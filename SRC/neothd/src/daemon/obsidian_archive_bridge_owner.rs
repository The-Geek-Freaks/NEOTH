//! Daemon-owned authority for the local Obsidian Archive Bridge.
//!
//! The plugin is deliberately only a bounded change notifier.  This owner
//! authenticates the paired plugin, rechecks the accepted configuration and
//! calls the existing managed-note reader; it never accepts note text, paths,
//! SQL, or WAL authority from Obsidian.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const RECORD_FILE: &str = "obsidian_archive_bridge_pairing.v1.json";
const SCHEMA_VERSION: u8 = 3;
const MAX_RECEIPTS: usize = 1024;
const PAIRING_PROTOCOL: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingRecord {
    schema_version: u8,
    pairing_id: String,
    pairing_generation: u64,
    secret_verifier_sha256: String,
    /// Opaque policy namespace, never a path.
    stable_policy_vault_id: String,
    /// Opaque digest of the paired physical vault root, never a canonical path.
    vault_root_binding: String,
    enabled: bool,
    receipts: VecDeque<Receipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    event_id: String,
    source_id: String,
    source_revision: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PairingPayload {
    pub protocol: u8,
    pub endpoint: String,
    pub pairing_secret: String,
    pub pairing_generation: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BridgeStatus {
    pub paired: bool,
    pub enabled: bool,
    pub pairing_generation: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SyncRequest {
    pub protocol: u8,
    #[serde(rename = "pairingSecret")]
    pub pairing_secret: String,
    #[serde(rename = "generation", alias = "pairing_generation")]
    pub pairing_generation: u64,
    pub event_id: String,
    pub source_id: String,
    pub source_revision: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SyncResponse {
    pub status: &'static str,
    pub generation: Option<u64>,
}

/// A live owner is created only by `neoth serve`.  The mutex serializes the
/// final pairing/configuration check with receipt persistence, so an unpair
/// cannot race a successful notification into a second transport receipt.
pub(crate) struct ArchiveBridgeOwner {
    home: PathBuf,
    vault: PathBuf,
    configuration: crate::connectors::ConnectorConfiguration,
    identity_key: [u8; 32],
    /// Installed only by the private CC RPC module, which owns the sealed
    /// daemon session.  An owner without it is deliberately inert.
    runtime: Mutex<Option<crate::connectors::control_plane::ContextImportRuntimeBinding>>,
    enabled: bool,
    /// Serializes pair/unpair publication and withdrawal.  It is deliberately
    /// distinct from `state`: an unpair must never wait for a listener drain
    /// while a handler is blocked waiting to authenticate against `state`.
    lifecycle: Mutex<Option<crate::daemon::obsidian_archive_bridge_ipc::ArchiveBridgeIpcBinding>>,
    state: Mutex<Option<PairingRecord>>,
}

impl ArchiveBridgeOwner {
    pub(crate) fn open(
        config: &crate::config::FreedomConfig,
        home: &Path,
    ) -> Result<Option<Arc<Self>>> {
        if !bridge_enabled(config) {
            return Ok(None);
        }
        let vault = configured_vault(config)?;
        let configuration = crate::connectors::obsidian::active_archive_bridge_configuration(
            &config.context_connectors,
        )
        .map_err(anyhow::Error::new)
        .context("select active Obsidian connector authority for Archive Bridge")?;
        let master = crate::wal::master_key::load_existing_master_key_at(home)?;
        let identity_key = *crate::wal::crypto::derive_subkey(
            &master,
            b"neoth/obsidian-archive-bridge/policy-identity/v1\0",
        )?
        .expose();
        let record = load_record(home)?;
        Ok(Some(Arc::new(Self {
            home: home.to_path_buf(),
            vault,
            configuration,
            identity_key,
            runtime: Mutex::new(None),
            enabled: true,
            lifecycle: Mutex::new(None),
            state: Mutex::new(record),
        })))
    }

    /// The sealed RPC module attaches exactly one CC runtime before any
    /// persisted pairing endpoint can be published.
    pub(crate) fn attach_context_import_runtime(
        &self,
        runtime: crate::connectors::control_plane::ContextImportRuntimeBinding,
    ) -> Result<()> {
        ensure!(
            runtime.instance_id()
                == &crate::connectors::ConnectorInstanceId::accountless(
                    crate::connectors::ConnectorId::Obsidian
                )
                && runtime.subject_id() == &self.configuration.subject_id
                && runtime.policy_revision() == self.configuration.policy.revision,
            "Archive Bridge runtime binding does not match its admitted Obsidian configuration"
        );
        let mut slot = self
            .runtime
            .lock()
            .map_err(|_| anyhow::anyhow!("Archive Bridge runtime controller poisoned"))?;
        ensure!(
            slot.is_none(),
            "Archive Bridge runtime binding already attached"
        );
        *slot = Some(runtime);
        Ok(())
    }

    fn acquire_operation_lease(
        &self,
    ) -> Result<crate::connectors::control_plane::ContextImportOperationLease> {
        self.runtime
            .lock()
            .map_err(|_| anyhow::anyhow!("Archive Bridge runtime controller poisoned"))?
            .as_ref()
            .context("Archive Bridge has no live connector-control runtime binding")?
            .acquire_context_import_operation_lease()
            .map_err(anyhow::Error::new)
    }

    fn runtime_is_live(&self) -> bool {
        self.acquire_operation_lease().is_ok()
    }

    /// Publish the persisted paired generation when the daemon starts.  The
    /// owner remains valid without a record, so a later CC `pair` can create
    /// its first listener without restarting the daemon.
    pub(crate) fn start_if_paired(self: &Arc<Self>) -> Result<()> {
        self.acquire_operation_lease()?;
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| anyhow::anyhow!("Archive Bridge lifecycle controller poisoned"))?;
        if lifecycle.is_some() || self.endpoint_name().is_none() {
            return Ok(());
        }
        *lifecycle = Some(crate::daemon::obsidian_archive_bridge_ipc::bind_and_serve(
            &self.home,
            Arc::clone(self),
        )?);
        Ok(())
    }

    /// Controller-owned pair mutation.  The durable/in-memory pairing becomes
    /// authoritative before the private endpoint is published.  If binding
    /// fails, both copies are restored before the caller receives failure.
    pub(crate) fn pair(self: &Arc<Self>) -> Result<PairingPayload> {
        let lease = self.acquire_operation_lease()?;
        lease.with_context_import_commit_permit(|| self.pair_under_live_lease())
    }

    fn pair_under_live_lease(self: &Arc<Self>) -> Result<PairingPayload> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| anyhow::anyhow!("Archive Bridge lifecycle controller poisoned"))?;
        ensure!(
            lifecycle.is_none(),
            "Obsidian Archive Bridge is already paired; unpair before rotating the listener"
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Archive Bridge controller poisoned"))?;
        let prior = state.clone();
        let pairing_id = uuid::Uuid::now_v7().simple().to_string();
        let pairing_secret =
            uuid::Uuid::new_v4().simple().to_string() + &uuid::Uuid::new_v4().simple().to_string();
        let generation = state
            .as_ref()
            .map_or(1, |record| record.pairing_generation.saturating_add(1));
        let stable_policy_vault_id = vault_identity(&self.vault)?;
        let vault_root_binding = crate::connectors::obsidian::archive_bridge_vault_binding(
            &self.configuration,
            self.vault.clone(),
            &stable_policy_vault_id,
            self.identity_key,
        )
        .map_err(anyhow::Error::new)
        .context("bind paired physical Obsidian vault root")?
        .encoded();
        let record = PairingRecord {
            schema_version: SCHEMA_VERSION,
            pairing_id,
            pairing_generation: generation,
            secret_verifier_sha256: secret_verifier(&pairing_secret),
            stable_policy_vault_id,
            vault_root_binding,
            enabled: true,
            receipts: VecDeque::new(),
        };
        persist_record(&self.home, &record)?;
        let payload = PairingPayload {
            protocol: PAIRING_PROTOCOL,
            endpoint: endpoint_for(&self.home, &record),
            pairing_secret,
            pairing_generation: generation,
        };
        *state = Some(record);
        drop(state);
        match crate::daemon::obsidian_archive_bridge_ipc::bind_and_serve(
            &self.home,
            Arc::clone(self),
        ) {
            Ok(binding) => *lifecycle = Some(binding),
            Err(error) => {
                let mut state = self.state.lock().map_err(|_| {
                    anyhow::anyhow!("Archive Bridge controller poisoned during pair rollback")
                })?;
                match prior.as_ref() {
                    Some(record) => persist_record(&self.home, record)?,
                    None => remove_record(&self.home)?,
                }
                *state = prior;
                return Err(error).context("publish paired Obsidian Archive Bridge listener");
            }
        }
        Ok(payload)
    }

    pub(crate) fn unpair(&self) -> Result<BridgeStatus> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| anyhow::anyhow!("Archive Bridge lifecycle controller poisoned"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Archive Bridge controller poisoned"))?;
        let Some(record) = state.as_mut() else {
            return Ok(BridgeStatus {
                paired: false,
                enabled: false,
                pairing_generation: None,
            });
        };
        record.enabled = false;
        record.pairing_generation = record.pairing_generation.saturating_add(1);
        record.receipts.clear();
        persist_record(&self.home, record)?;
        let response = BridgeStatus {
            paired: true,
            enabled: false,
            pairing_generation: Some(record.pairing_generation),
        };
        // Release state before draining.  An admitted IPC request may be in
        // `spawn_blocking` and needs this mutex to observe the durable revoke.
        drop(state);
        if let Some(binding) = lifecycle.take() {
            binding.withdraw_and_drain()?;
        }
        Ok(response)
    }

    pub(crate) fn endpoint_name(&self) -> Option<String> {
        self.state.lock().ok().and_then(|state| {
            state
                .as_ref()
                .filter(|record| record.enabled)
                .map(|record| endpoint_for(&self.home, record))
        })
    }

    pub(crate) fn endpoint_nonce(&self) -> Option<String> {
        self.state.lock().ok().and_then(|state| {
            state
                .as_ref()
                .filter(|record| record.enabled)
                .map(|record| record.pairing_id.clone())
        })
    }

    pub(crate) fn status(&self) -> BridgeStatus {
        let state = self.state.lock().ok();
        let record = state.as_ref().and_then(|state| state.as_ref());
        BridgeStatus {
            paired: record.is_some(),
            enabled: self.enabled
                && self.runtime_is_live()
                && record.is_some_and(|record| record.enabled),
            pairing_generation: record.map(|record| record.pairing_generation),
        }
    }

    pub(crate) fn matches_vault(&self, requested: &Path) -> Result<()> {
        ensure!(
            same_vault(&self.vault, requested)?,
            "requested vault does not match the configured Obsidian vault"
        );
        Ok(())
    }

    pub(crate) fn authorize_status(
        &self,
        protocol: u8,
        pairing_secret: &str,
        pairing_generation: u64,
    ) -> SyncResponse {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return SyncResponse {
                    status: "error",
                    generation: None,
                };
            }
        };
        let Some(record) = state.as_ref() else {
            return SyncResponse {
                status: "unpaired",
                generation: None,
            };
        };
        if protocol != PAIRING_PROTOCOL
            || !self.enabled
            || !record.enabled
            || !self.runtime_is_live()
        {
            return SyncResponse {
                status: "revoked",
                generation: Some(record.pairing_generation),
            };
        }
        if pairing_generation != record.pairing_generation {
            return SyncResponse {
                status: "generation_mismatch",
                generation: Some(record.pairing_generation),
            };
        }
        if !constant_time_hex_eq(
            &record.secret_verifier_sha256,
            &secret_verifier(pairing_secret),
        ) {
            return SyncResponse {
                status: "unpaired",
                generation: Some(record.pairing_generation),
            };
        }
        SyncResponse {
            status: "ok",
            generation: Some(record.pairing_generation),
        }
    }

    /// This is invoked only from the bridge IPC's bounded blocking task.  Keep
    /// the controller mutex across descriptor authentication, fresh vault
    /// selection, GroundTruth commit, state update, and receipt persistence.
    pub(crate) fn sync(&self, request: SyncRequest) -> SyncResponse {
        if request.protocol != PAIRING_PROTOCOL
            || !valid_event_component(&request.event_id)
            || !valid_event_component(&request.source_id)
            || !valid_event_component(&request.source_revision)
        {
            return SyncResponse {
                status: "invalid_request",
                generation: None,
            };
        }
        // Keep the configuration/pairing decision and state receipt serial. The
        // existing reader owns the only ingestion state map and DB dedup path.
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return SyncResponse {
                    status: "error",
                    generation: None,
                };
            }
        };
        let Some(record) = state.as_mut() else {
            return SyncResponse {
                status: "unpaired",
                generation: None,
            };
        };
        if !self.enabled || !record.enabled {
            return SyncResponse {
                status: "revoked",
                generation: Some(record.pairing_generation),
            };
        }
        if request.pairing_generation != record.pairing_generation {
            return SyncResponse {
                status: "generation_mismatch",
                generation: Some(record.pairing_generation),
            };
        }
        if !constant_time_hex_eq(
            &record.secret_verifier_sha256,
            &secret_verifier(&request.pairing_secret),
        ) {
            return SyncResponse {
                status: "unpaired",
                generation: Some(record.pairing_generation),
            };
        }
        let root_binding = match crate::connectors::obsidian::ArchiveBridgeVaultBinding::parse(
            &record.vault_root_binding,
        ) {
            Ok(binding) => binding,
            Err(_) => {
                return SyncResponse {
                    status: "vault_mismatch",
                    generation: Some(record.pairing_generation),
                };
            }
        };
        let receipt = Receipt {
            event_id: request.event_id,
            source_id: request.source_id,
            source_revision: request.source_revision,
        };
        if record.receipts.iter().any(|known| known == &receipt) {
            return SyncResponse {
                status: "already_current",
                generation: Some(record.pairing_generation),
            };
        }
        if record
            .receipts
            .iter()
            .any(|known| known.event_id == receipt.event_id)
        {
            return SyncResponse {
                status: "event_reuse_conflict",
                generation: Some(record.pairing_generation),
            };
        }
        let generation = record.pairing_generation;
        let lease = match self.acquire_operation_lease() {
            Ok(lease) => lease,
            Err(_) => {
                return SyncResponse {
                    status: "revoked",
                    generation: Some(generation),
                };
            }
        };
        // No raw plugin value is used below. The reader freshly opens and
        // selects the configured current note by its HMAC descriptor before
        // applying the existing frontmatter/symlink/sanitizer/DB gates.
        let outcome = lease.with_context_import_commit_permit(|| {
            let outcome = crate::daemon::obsidian_vault_reader_cron::run_one_archive_bridge_note(
                &self.configuration,
                &self.vault,
                &self.home,
                &record.stable_policy_vault_id,
                self.identity_key,
                root_binding,
                &request.pairing_secret,
                &receipt.source_id,
                &receipt.source_revision,
            )?;
            if matches!(
                outcome,
                crate::daemon::obsidian_vault_reader_cron::BridgeReaderOutcome::AlreadyCurrent
                    | crate::daemon::obsidian_vault_reader_cron::BridgeReaderOutcome::Accepted
            ) {
                record.receipts.push_back(receipt);
                while record.receipts.len() > MAX_RECEIPTS {
                    record.receipts.pop_front();
                }
                persist_record(&self.home, record)?;
            }
            Ok(outcome)
        });
        match outcome {
            Ok(crate::daemon::obsidian_vault_reader_cron::BridgeReaderOutcome::StaleRevision) => {
                SyncResponse {
                    status: "stale_revision",
                    generation: Some(generation),
                }
            }
            Ok(crate::daemon::obsidian_vault_reader_cron::BridgeReaderOutcome::AlreadyCurrent)
            | Ok(crate::daemon::obsidian_vault_reader_cron::BridgeReaderOutcome::Accepted) => {
                SyncResponse {
                    status: "accepted",
                    generation: Some(record.pairing_generation),
                }
            }
            Err(_) => SyncResponse {
                status: "error",
                generation: Some(generation),
            },
        }
    }

    /// Daemon shutdown uses the same withdraw-before-drain ordering as CC
    /// unpair.  It must run after connector-control admission is closed.
    pub(crate) fn shutdown(&self) -> Result<()> {
        let binding = self
            .lifecycle
            .lock()
            .map_err(|_| anyhow::anyhow!("Archive Bridge lifecycle controller poisoned"))?
            .take();
        if let Some(binding) = binding {
            binding.withdraw_and_drain()?;
        }
        Ok(())
    }
}

fn bridge_enabled(config: &crate::config::FreedomConfig) -> bool {
    config.obsidian_archive_bridge_enabled
        && config.obsidian_vault_reader_enabled
        && crate::connectors::obsidian::active_archive_bridge_configuration(
            &config.context_connectors,
        )
        .is_ok()
}
fn configured_vault(config: &crate::config::FreedomConfig) -> Result<PathBuf> {
    config
        .obsidian_vault
        .as_ref()
        .map(PathBuf::from)
        .context("obsidian_vault is required")
}
fn same_vault(left: &Path, right: &Path) -> Result<bool> {
    Ok(
        std::fs::canonicalize(left).context("canonicalize configured vault")?
            == std::fs::canonicalize(right).context("canonicalize requested vault")?,
    )
}
/// A persistable opaque binding to the physical vault root.  The actual
/// device/file identity never leaves the owner record; selector code receives
/// only this domain-separated digest.
fn vault_identity(vault: &Path) -> Result<String> {
    use cap_fs_ext::MetadataExt as _;
    let metadata = std::fs::metadata(vault)
        .with_context(|| format!("read configured vault metadata {}", vault.display()))?;
    ensure!(
        metadata.is_dir() && metadata.ino() != 0,
        "configured vault has no stable directory identity"
    );
    let mut digest = Sha256::new();
    digest.update(b"neoth/obsidian-archive-bridge/physical-root/v1\0");
    digest.update(metadata.dev().to_le_bytes());
    digest.update(metadata.ino().to_le_bytes());
    Ok(hex::encode(digest.finalize()))
}
fn secret_verifier(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}
#[cfg(windows)]
fn endpoint_for(home: &Path, record: &PairingRecord) -> String {
    let canonical = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let home_hash = hex::encode(Sha256::digest(canonical.as_os_str().as_encoded_bytes()));
    format!(
        r"\\.\pipe\neoth-obsidian-bridge-v1-{home_hash}-{}",
        record.pairing_id
    )
}

#[cfg(unix)]
fn endpoint_for(home: &Path, record: &PairingRecord) -> String {
    home.join(format!("obsidian-bridge-{}.sock", record.pairing_id))
        .display()
        .to_string()
}

#[cfg(not(any(unix, windows)))]
fn endpoint_for(_: &Path, record: &PairingRecord) -> String {
    format!("unsupported-{}", record.pairing_id)
}
fn valid_event_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}
fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .as_bytes()
            .iter()
            .zip(right.as_bytes())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}
fn record_path(home: &Path) -> PathBuf {
    home.join(RECORD_FILE)
}
fn load_record(home: &Path) -> Result<Option<PairingRecord>> {
    let path = record_path(home);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read bridge pairing record {}", path.display()))?;
    let record: PairingRecord =
        serde_json::from_slice(&bytes).context("parse bridge pairing record")?;
    ensure!(
        record.schema_version == SCHEMA_VERSION
            && !record.pairing_id.is_empty()
            && record.receipts.len() <= MAX_RECEIPTS,
        "invalid bridge pairing record"
    );
    Ok(Some(record))
}
fn persist_record(home: &Path, record: &PairingRecord) -> Result<()> {
    std::fs::create_dir_all(home).context("create NEOTH home for bridge pairing")?;
    let bytes = serde_json::to_vec(record).context("serialize bridge pairing record")?;
    crate::util::atomic_write::atomic_write_private(&record_path(home), &bytes)
        .context("persist bridge pairing record")
}
fn remove_record(home: &Path) -> Result<()> {
    let path = record_path(home);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("remove failed bridge pairing record {}", path.display()))?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn owner(home: &Path, vault: &Path) -> Arc<ArchiveBridgeOwner> {
        let subject = crate::connectors::SubjectId::new("bridge-test-operator").unwrap();
        let configuration = crate::connectors::ConnectorConfiguration {
            connector_id: crate::connectors::ConnectorId::Obsidian,
            account_id: None,
            subject_id: subject.clone(),
            credential_ref: None,
            policy: crate::connectors::ConnectorPolicySnapshot::local_read_only(7),
        };
        let runtime = crate::connectors::control_plane::test_context_import_runtime_fixture(
            crate::connectors::ConnectorInstanceId::accountless(
                crate::connectors::ConnectorId::Obsidian,
            ),
            subject,
            7,
            11,
        )
        .unwrap();
        let owner = Arc::new(ArchiveBridgeOwner {
            home: home.to_path_buf(),
            vault: vault.to_path_buf(),
            configuration,
            identity_key: [0x5a; 32],
            runtime: Mutex::new(None),
            enabled: true,
            lifecycle: Mutex::new(None),
            state: Mutex::new(None),
        });
        owner.attach_context_import_runtime(runtime).unwrap();
        owner
    }

    async fn status(endpoint: &str, secret: &str, generation: u64) -> String {
        let mut stream = tokio::net::UnixStream::connect(endpoint).await.unwrap();
        let frame = serde_json::json!({
            "op": "status",
            "protocol": PAIRING_PROTOCOL,
            "pairingSecret": secret,
            "generation": generation,
        });
        stream
            .write_all(serde_json::to_string(&frame).unwrap().as_bytes())
            .await
            .unwrap();
        stream.write_all(b"\n").await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resident_pair_listener_unpair_replay_denial_and_repair_generation() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let vault = crate::test_env::canonical_tempdir().unwrap();
        let owner = owner(home.path(), vault.path());
        assert!(!owner.status().paired, "resident owner starts unpaired");

        let first = owner.pair().unwrap();
        let first_reply = status(
            &first.endpoint,
            &first.pairing_secret,
            first.pairing_generation,
        )
        .await;
        assert!(
            first_reply.contains("\"ok\""),
            "paired endpoint accepts its scoped secret"
        );

        owner.unpair().unwrap();
        assert!(
            tokio::net::UnixStream::connect(&first.endpoint)
                .await
                .is_err(),
            "unpair withdraws the old endpoint before returning"
        );

        let second = owner.pair().unwrap();
        assert!(second.pairing_generation > first.pairing_generation);
        assert_ne!(second.endpoint, first.endpoint);
        let replay = status(
            &second.endpoint,
            &first.pairing_secret,
            first.pairing_generation,
        )
        .await;
        assert!(replay.contains("unpaired") || replay.contains("generation_mismatch"));
        let second_reply = status(
            &second.endpoint,
            &second.pairing_secret,
            second.pairing_generation,
        )
        .await;
        assert!(second_reply.contains("\"ok\""));
        owner.shutdown().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_listener_bind_restores_an_unpaired_record() {
        let base = crate::test_env::canonical_tempdir().unwrap();
        let home = base.path().join("a".repeat(96));
        std::fs::create_dir_all(&home).unwrap();
        let vault = crate::test_env::canonical_tempdir().unwrap();
        let owner = owner(&home, vault.path());

        assert!(
            owner.pair().is_err(),
            "AF_UNIX path cap must reject publication"
        );
        assert!(
            !record_path(&home).exists(),
            "failed bind rolls durable pairing state back"
        );
        assert!(
            !owner.status().paired,
            "failed bind rolls in-memory pairing state back"
        );
    }
}
