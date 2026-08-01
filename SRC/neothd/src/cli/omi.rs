//! Operator controls for the complete OMI conversation runtime.

use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use crate::cli::OutputFormat;
use crate::config::credentials::Credentials;
use crate::config::{FreedomConfig, OmiIngestMode, SecretsBackend};
use crate::secret::SecretString;
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::writer::WalWriterHandle;

#[derive(Args, Debug, Clone)]
pub struct OmiArgs {
    #[command(subcommand)]
    pub action: OmiAction,

    /// Override the NEOTH home containing freedom.yaml, credentials.yaml, and views.db.
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum OmiAction {
    /// Show configuration validity, credentials posture, ledger counts, and halt state.
    Status,
    /// Probe configured local OMI endpoints without contacting a public cloud API.
    Probe,
    /// Read a bounded JSON credential update from stdin. Secret values never enter argv.
    SetCredentials,
    /// Crash-recoverably configure the complete surfaced OMI settings and optional credentials from bounded JSON stdin.
    Configure,
    /// Permanently delete one conversation and every local derivative (privacy deletion wins over audit failure).
    Purge {
        conversation_id: String,
        /// Confirm the privacy deletion and durable anti-reimport tombstone.
        #[arg(long)]
        yes: bool,
    },
    /// Resume an SC-18-halted stream after a durable operator intent and documented review.
    Resume {
        /// Short review evidence retained with the last sanitizer finding set.
        #[arg(long, value_name = "NOTE")]
        review_note: String,
    },
    /// Apply the configured OMI retention window immediately (privacy deletion wins over audit failure).
    EnforceRetention,
    /// Remove stale recovery state and a purge tombstone after a durable operator intent.
    AllowReimport {
        conversation_id: String,
        /// Confirm that the remote source may restore previously deleted data.
        #[arg(long)]
        yes: bool,
    },
}

struct OmiContext {
    home: PathBuf,
    config: FreedomConfig,
    credentials: Credentials,
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OmiCredentialUpdate {
    #[serde(default)]
    pub(crate) developer_api_key: Option<SecretString>,
    #[serde(default)]
    pub(crate) native_ingest_token: Option<SecretString>,
}

impl OmiCredentialUpdate {
    fn is_empty(&self) -> bool {
        self.developer_api_key.is_none() && self.native_ingest_token.is_none()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.developer_api_key.is_none() && self.native_ingest_token.is_none() {
            bail!("OMI credential update contains no fields");
        }
        if let Some(key) = self
            .developer_api_key
            .as_ref()
            .map(SecretString::expose_secret)
            && (!key.starts_with("omi_dev_") || key.len() == "omi_dev_".len() || key.trim() != key)
        {
            bail!("OMI Developer key must be a trimmed non-empty omi_dev_* value");
        }
        if let Some(token) = self
            .native_ingest_token
            .as_ref()
            .map(SecretString::expose_secret)
            && (token.len() < 32 || token.trim() != token)
        {
            bail!("OMI native token must be trimmed and contain at least 32 bytes");
        }
        Ok(())
    }

    fn updated_field_names(&self) -> Vec<&'static str> {
        let mut fields = Vec::with_capacity(2);
        if self.developer_api_key.is_some() {
            fields.push("omi_developer_api_key");
        }
        if self.native_ingest_token.is_some() {
            fields.push("omi_ingest_token");
        }
        fields
    }
}

/// Secret-free settings owned by the OMI Privacy panel. Advanced OMI bounds
/// that are not surfaced there remain semantically present in freedom.yaml;
/// YAML comments and formatting are not preserved by parse/reserialize.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OmiConfigureSettings {
    enabled: bool,
    mode: OmiIngestMode,
    endpoint: String,
    listen_addr: String,
    retention_days: u64,
    retain_transcripts: bool,
    audio_enabled: bool,
    visual_enabled: bool,
    video_enabled: bool,
    allow_cloud_api: bool,
    allow_cloud_summary: bool,
    create_actions: bool,
    seed_groundtruth: bool,
    summary_enabled: bool,
}

impl OmiConfigureSettings {
    fn overlay_yaml(&self, root: &mut serde_yaml::Value) -> Result<()> {
        let root = root
            .as_mapping_mut()
            .context("freedom.yaml root must be a YAML mapping")?;
        let omi_key = serde_yaml::Value::String("omi".to_string());
        let mut omi = match root.remove(&omi_key) {
            Some(serde_yaml::Value::Mapping(omi)) => omi,
            Some(_) => bail!("freedom.yaml omi field must be a YAML mapping"),
            None => serde_yaml::Mapping::new(),
        };
        let surfaced = serde_yaml::to_value(self).context("serialize submitted OMI settings")?;
        let surfaced = surfaced
            .as_mapping()
            .context("submitted OMI settings did not serialize to a mapping")?;
        for (key, value) in surfaced {
            omi.insert(key.clone(), value.clone());
        }
        root.insert(omi_key, serde_yaml::Value::Mapping(omi));
        Ok(())
    }
}

impl From<&crate::config::OmiConfig> for OmiConfigureSettings {
    fn from(config: &crate::config::OmiConfig) -> Self {
        Self {
            enabled: config.enabled,
            mode: config.mode,
            endpoint: config.endpoint.clone(),
            listen_addr: config.listen_addr.clone(),
            retention_days: config.retention_days,
            retain_transcripts: config.retain_transcripts,
            audio_enabled: config.audio_enabled,
            visual_enabled: config.visual_enabled,
            video_enabled: config.video_enabled,
            allow_cloud_api: config.allow_cloud_api,
            allow_cloud_summary: config.allow_cloud_summary,
            create_actions: config.create_actions,
            seed_groundtruth: config.seed_groundtruth,
            summary_enabled: config.summary_enabled,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OmiConfigureRequest {
    settings: OmiConfigureSettings,
    #[serde(default)]
    credentials: OmiCredentialUpdate,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OmiConfigureCredentialReceipt {
    backend: String,
    updated_fields: Vec<String>,
    developer_api_key_present: bool,
    native_ingest_token_present: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OmiConfigureReceipt {
    operation: String,
    operation_id: String,
    path: String,
    settings_sha256: String,
    config_sha256: String,
    reload_requested: bool,
    reload_ts_unix: u64,
    settings: OmiConfigureSettings,
    credentials: OmiConfigureCredentialReceipt,
}

impl OmiContext {
    fn load(home: Option<PathBuf>) -> Result<Self> {
        let home = home.unwrap_or_else(FreedomConfig::default_neoth_home);
        let config_path = home.join("freedom.yaml");
        let pair =
            crate::config::load_runtime_config_pair_from_path(&config_path).with_context(|| {
                format!(
                    "load coherent OMI config and effective credentials from {}",
                    config_path.display()
                )
            })?;
        Ok(Self {
            home,
            config: pair.config,
            credentials: pair.credentials,
        })
    }

    fn db_path(&self) -> PathBuf {
        self.home.join("views.db")
    }
}

#[derive(Clone, Copy)]
enum OperatorAuditContract {
    /// Safety boundaries may not be lowered until the intent frame is durable.
    FailClosedBeforeMutation,
    /// Privacy deletion proceeds even when audit storage is unavailable. The
    /// command then returns an explicit "committed without complete audit"
    /// error rather than silently extending data retention.
    PrivacyDeletionWins,
}

impl OperatorAuditContract {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosedBeforeMutation => "fail_closed_before_mutation",
            Self::PrivacyDeletionWins => "privacy_deletion_wins",
        }
    }
}

struct OperatorAudit {
    writer: WalWriterHandle,
    join: tokio::task::JoinHandle<()>,
}

impl OperatorAudit {
    fn start(home: &Path) -> Result<Self> {
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir)
            .with_context(|| format!("create OMI operator WAL dir {}", wal_dir.display()))?;
        let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "omi-operator");
        let (writer, join) = crate::wal::writer::spawn_for_home(segment, home.to_path_buf())
            .context("spawn dedicated OMI operator WAL writer")?;
        Ok(Self { writer, join })
    }

    async fn emit(
        &self,
        phase: &'static str,
        operation: &'static str,
        contract: OperatorAuditContract,
        conversation_id: Option<&str>,
        review_note: Option<&str>,
        result: Option<serde_json::Value>,
    ) -> Result<()> {
        let payload = operator_audit_payload(
            phase,
            operation,
            contract,
            conversation_id,
            review_note,
            result,
        )?;
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
            .event_subtype(ExtendedSubtype::OmiLifecycleAudit as u8)
            .build();
        self.writer
            .append(header, payload)
            .await
            .context("durably append OMI operator audit frame")?;
        Ok(())
    }

    async fn finish(self) -> Result<()> {
        drop(self.writer);
        self.join.await.context("join OMI operator WAL writer")?;
        Ok(())
    }
}

fn operator_audit_payload(
    phase: &'static str,
    operation: &'static str,
    contract: OperatorAuditContract,
    conversation_id: Option<&str>,
    review_note: Option<&str>,
    result: Option<serde_json::Value>,
) -> Result<Vec<u8>> {
    let hash = |value: &str| hex::encode(Sha256::digest(value.as_bytes()));
    serde_json::to_vec(&serde_json::json!({
        "phase": phase,
        "operation": operation,
        "source": "omi_cli",
        "scope": "omi_operator",
        "audit_contract": contract.as_str(),
        "conversation_hash": conversation_id.map(hash),
        "review_note_hash": review_note.map(hash),
        "result": result,
        "ts_unix": crate::time::now_unix_secs(),
    }))
    .context("encode OMI operator audit frame")
}

struct PrivacyDeletionAudit {
    audit: Option<OperatorAudit>,
    failure: Option<String>,
}

impl PrivacyDeletionAudit {
    async fn begin(home: &Path, operation: &'static str, conversation_id: Option<&str>) -> Self {
        match OperatorAudit::start(home) {
            Ok(audit) => match audit
                .emit(
                    "operator_intent",
                    operation,
                    OperatorAuditContract::PrivacyDeletionWins,
                    conversation_id,
                    None,
                    None,
                )
                .await
            {
                Ok(()) => Self {
                    audit: Some(audit),
                    failure: None,
                },
                Err(error) => {
                    let _ = audit.finish().await;
                    Self {
                        audit: None,
                        failure: Some(error.to_string()),
                    }
                }
            },
            Err(error) => Self {
                audit: None,
                failure: Some(error.to_string()),
            },
        }
    }

    async fn complete(
        mut self,
        operation: &'static str,
        conversation_id: Option<&str>,
        result: serde_json::Value,
    ) -> Result<()> {
        if let Some(audit) = self.audit.take() {
            if let Err(error) = audit
                .emit(
                    "operator_result",
                    operation,
                    OperatorAuditContract::PrivacyDeletionWins,
                    conversation_id,
                    None,
                    Some(result),
                )
                .await
            {
                self.failure = Some(error.to_string());
            }
            if let Err(error) = audit.finish().await {
                self.failure.get_or_insert_with(|| error.to_string());
            }
        }
        if let Some(error) = self.failure {
            bail!(
                "OMI {operation} committed under privacy_deletion_wins, but its operator audit is incomplete: {error}"
            );
        }
        Ok(())
    }

    async fn record_failed_attempt(
        mut self,
        operation: &'static str,
        conversation_id: Option<&str>,
    ) {
        if let Some(audit) = self.audit.take() {
            let _ = audit
                .emit(
                    "operator_result",
                    operation,
                    OperatorAuditContract::PrivacyDeletionWins,
                    conversation_id,
                    None,
                    Some(serde_json::json!({ "success": false, "committed": false })),
                )
                .await;
            let _ = audit.finish().await;
        }
    }
}

fn native_daemon_pidfile(home: &Path) -> PathBuf {
    home.join("neothd.pid")
}

pub(crate) fn effective_omi_runtime_state(
    enabled: bool,
    status: &crate::memory::omi::OmiStatus,
    live_daemon_pid: Option<u32>,
) -> String {
    if !enabled {
        return "disabled".to_string();
    }
    let Some(live_pid) = live_daemon_pid else {
        return "inactive".to_string();
    };
    if status.runtime_pid != Some(live_pid) {
        return "unknown".to_string();
    }
    status
        .runtime_state
        .clone()
        .unwrap_or_else(|| "unknown".to_string())
}

fn native_mutation_requires_stopped_daemon(home: &Path, conversation_id: &str) -> Result<()> {
    if conversation_id.starts_with("native:") {
        let live = crate::daemon::pidfile::live_daemon_pid(&native_daemon_pidfile(home))
            .context("verify that the daemon is stopped before native OMI mutation")?;
        if live.is_some() {
            bail!(
                "native OMI mutation requires the daemon to be stopped so in-memory call data cannot recreate a removed receipt"
            );
        }
    }
    Ok(())
}

fn mode_name(mode: OmiIngestMode) -> &'static str {
    match mode {
        OmiIngestMode::DeveloperApi => "developer_api",
        OmiIngestMode::NativeIngest => "native_ingest",
        OmiIngestMode::Both => "both",
        OmiIngestMode::LegacyMemories => "legacy_memories",
    }
}

fn open_views(path: &Path) -> Result<rusqlite::Connection> {
    crate::memory::store::open(path)
        .with_context(|| format!("open OMI ledger at {}", path.display()))
}

fn read_status(path: &Path) -> Result<Option<crate::memory::omi::OmiStatus>> {
    if !path.exists() {
        return Ok(None);
    }
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = rusqlite::Connection::open_with_flags(path, flags)
        .with_context(|| format!("open OMI ledger read-only at {}", path.display()))?;
    crate::memory::omi::status(&conn)
        .map(Some)
        .context("read OMI ledger status; run `neoth migrate` or start the daemon")
}

fn read_private_json_stdin<T>(label: &str, max_bytes: u64) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut body = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(max_bytes + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("read {label} from stdin"))?;
    if body.len() as u64 > max_bytes {
        bail!("{label} exceeds {max_bytes} bytes");
    }
    serde_json::from_slice(&body).with_context(|| format!("parse {label} JSON from stdin"))
}

fn read_omi_credential_update() -> Result<OmiCredentialUpdate> {
    const MAX_STDIN_BYTES: u64 = 8 * 1024;
    let update: OmiCredentialUpdate =
        read_private_json_stdin("OMI credential update", MAX_STDIN_BYTES)?;
    update.validate()?;
    Ok(update)
}

fn read_omi_configure_request() -> Result<OmiConfigureRequest> {
    const MAX_STDIN_BYTES: u64 = 32 * 1024;
    let request: OmiConfigureRequest =
        read_private_json_stdin("OMI configure request", MAX_STDIN_BYTES)?;
    if !request.credentials.is_empty() {
        request.credentials.validate()?;
    }
    Ok(request)
}

pub(crate) fn rollback_omi_keychain_updates(
    store: &dyn crate::config::keychain::SecretStore,
    applied: &[(&'static str, Option<SecretString>)],
) -> Vec<String> {
    let mut failures = Vec::new();
    for (key, previous) in applied.iter().rev() {
        let result = match previous {
            Some(previous) => store.set(key, previous),
            None => store.delete(key),
        };
        if let Err(error) = result {
            failures.push(format!("{key}: {error:#}"));
        }
    }
    failures
}

pub(crate) fn stage_omi_keychain_update(
    store: &dyn crate::config::keychain::SecretStore,
    update: &OmiCredentialUpdate,
) -> Result<Vec<(&'static str, Option<SecretString>)>> {
    let mut requested = Vec::with_capacity(2);
    if let Some(value) = update.developer_api_key.as_ref() {
        requested.push(("omi_developer_api_key", value.clone()));
    }
    if let Some(value) = update.native_ingest_token.as_ref() {
        requested.push(("omi_ingest_token", value.clone()));
    }

    // Snapshot every prior value before the first write. Interleaving get/set
    // would leave an earlier key changed if reading a later key failed.
    let mut prior = Vec::with_capacity(requested.len());
    for (key, _) in &requested {
        let previous = store
            .get(key)
            .with_context(|| format!("read existing {key} from {}", store.backend_name()))?;
        prior.push((*key, previous));
    }

    let mut applied = Vec::with_capacity(requested.len());
    for ((key, value), (prior_key, previous)) in requested.iter().zip(prior) {
        debug_assert_eq!(*key, prior_key);
        // An OS credential API may publish a value and still report a later
        // durability error. Include the current key in the restoration set
        // before writing it; restoring an unchanged value is idempotent.
        applied.push((*key, previous));
        if let Err(error) = store.set(key, value) {
            let rollback = rollback_omi_keychain_updates(store, &applied);
            if rollback.is_empty() {
                return Err(error).with_context(|| {
                    format!(
                        "write {key} to {}; every requested keychain write was restored",
                        store.backend_name()
                    )
                });
            }
            bail!(
                "write {key} to {} failed ({error:#}); rollback also failed: {}",
                store.backend_name(),
                rollback.join("; ")
            );
        }
    }
    Ok(applied)
}

#[cfg(test)]
fn persist_omi_keychain_update(
    freedom_path: &Path,
    credentials_path: &Path,
    store: &dyn crate::config::keychain::SecretStore,
    update: &OmiCredentialUpdate,
) -> Result<()> {
    // Stage both values as file overrides in one durable pair transaction
    // before touching a non-transactional OS keychain. A process crash after
    // any later keychain write therefore leaves the complete new generation
    // reachable through the authoritative file overrides.
    let expected_source = Credentials::update_raw_freedom_with_credentials_at(
        freedom_path,
        credentials_path,
        |source, credentials| {
            if let Some(value) = update.developer_api_key.as_ref() {
                credentials.omi_developer_api_key = Some(value.clone());
            }
            if let Some(value) = update.native_ingest_token.as_ref() {
                credentials.omi_ingest_token = Some(value.clone());
            }
            Ok((None, source.map(|body| body.as_bytes().to_vec())))
        },
    )
    .context("stage OMI keychain values as crash-safe file overrides")?;
    finalize_staged_omi_keychain_update_if_source(
        freedom_path,
        credentials_path,
        store,
        update,
        expected_source.as_deref(),
    )
}

fn finalize_staged_omi_keychain_update_if_source(
    freedom_path: &Path,
    credentials_path: &Path,
    store: &dyn crate::config::keychain::SecretStore,
    update: &OmiCredentialUpdate,
    expected_freedom_source: Option<&[u8]>,
) -> Result<()> {
    let mut applied = None;
    let committed = Credentials::update_raw_freedom_with_credentials_at(
        freedom_path,
        credentials_path,
        |source, credentials| {
            anyhow::ensure!(
                source.map(str::as_bytes) == expected_freedom_source,
                "freedom.yaml changed before OMI keychain finalization"
            );
            if let Some(expected) = update.developer_api_key.as_ref() {
                anyhow::ensure!(
                    credentials
                        .omi_developer_api_key
                        .as_ref()
                        .is_some_and(|current| current.expose() == expected.expose()),
                    "staged OMI developer API key changed before keychain finalization"
                );
            }
            if let Some(expected) = update.native_ingest_token.as_ref() {
                anyhow::ensure!(
                    credentials
                        .omi_ingest_token
                        .as_ref()
                        .is_some_and(|current| current.expose() == expected.expose()),
                    "staged OMI ingest token changed before keychain finalization"
                );
            }

            // The exact config generation and both file receipts are checked
            // while every pair lock is held. Only then may keychain writes
            // begin; their prior values remain available for returned-error
            // rollback, while a hard crash is masked by the file overrides.
            applied = Some(stage_omi_keychain_update(store, update)?);
            if update.developer_api_key.is_some() {
                credentials.omi_developer_api_key = None;
            }
            if update.native_ingest_token.is_some() {
                credentials.omi_ingest_token = None;
            }
            Ok((None, ()))
        },
    );
    if let Err(error) = committed {
        return Err(staged_omi_finalization_error(
            error,
            store,
            applied.as_deref(),
        ));
    }
    Ok(())
}

fn staged_omi_finalization_error(
    error: anyhow::Error,
    store: &dyn crate::config::keychain::SecretStore,
    applied: Option<&[(&'static str, Option<SecretString>)]>,
) -> anyhow::Error {
    let Some(applied) = applied else {
        return error.context(
            "OMI keychain finalization failed before a complete keychain generation was staged; inspect the underlying keychain error and staged file values before retrying",
        );
    };

    if crate::config::credentials::dual_file_target_publication_crossed(&error) {
        return error.context(
            "OMI file target publication crossed its recovery boundary; the updated keychain generation was retained because the file target may already be committed; inspect recovery state and OMI status before retrying",
        );
    }

    let rollback = rollback_omi_keychain_updates(store, applied);
    if rollback.is_empty() {
        return error.context(
            "OMI file transaction did not retain the complete target generation; prior keychain values were restored",
        );
    }
    anyhow::anyhow!(
        "OMI file transaction failed ({error:#}); keychain rollback also failed: {}",
        rollback.join("; ")
    )
}

/// Finalize OMI values that were already committed as file overrides by the
/// init pair transaction. The exact current freedom generation is captured and
/// compare-and-swapped so a concurrent config writer wins loudly instead of
/// having its credentials silently cleared.
pub(crate) fn finalize_staged_omi_keychain_update(
    credentials_path: &Path,
    store: &dyn crate::config::keychain::SecretStore,
    update: &OmiCredentialUpdate,
) -> Result<()> {
    let freedom_path = credentials_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("freedom.yaml");
    let expected_source = match std::fs::read(&freedom_path) {
        Ok(source) => Some(source),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "read {} before OMI keychain finalization",
                    freedom_path.display()
                )
            });
        }
    };
    finalize_staged_omi_keychain_update_if_source(
        &freedom_path,
        credentials_path,
        store,
        update,
        expected_source.as_deref(),
    )
}

pub(crate) fn persist_omi_credential_update(
    home: &Path,
    update: &OmiCredentialUpdate,
) -> Result<SecretsBackend> {
    let freedom_path = home.join("freedom.yaml");
    let credentials_path = home.join("credentials.yaml");
    let (expected_source, backend) = Credentials::update_raw_freedom_with_credentials_at(
        &freedom_path,
        &credentials_path,
        |source, credentials| {
            let backend = source
                .map(serde_yaml::from_str::<FreedomConfig>)
                .transpose()
                .context("parse freedom.yaml before OMI credential update")?
                .map(|config| config.secrets_backend)
                .unwrap_or(SecretsBackend::File);
            if let Some(value) = update.developer_api_key.as_ref() {
                credentials.omi_developer_api_key = Some(value.clone());
            }
            if let Some(value) = update.native_ingest_token.as_ref() {
                credentials.omi_ingest_token = Some(value.clone());
            }
            Ok((None, (source.map(|body| body.as_bytes().to_vec()), backend)))
        },
    )
    .context("stage crash-safe OMI credential generation")?;
    match backend {
        SecretsBackend::File => {}
        SecretsBackend::Keychain => {
            let store = crate::config::keychain::open_store()
                .context("open configured OS keychain for OMI credential update")?;
            finalize_staged_omi_keychain_update_if_source(
                &freedom_path,
                &credentials_path,
                store.as_ref(),
                update,
                expected_source.as_deref(),
            )
            .context(
                "OMI keychain finalization did not complete cleanly; inspect the retained or restored generation in the underlying error",
            )?;
        }
    }
    Ok(backend)
}

fn print_credential_update(
    output: OutputFormat,
    backend: SecretsBackend,
    updated_fields: &[&str],
) -> Result<()> {
    let backend = match backend {
        SecretsBackend::File => "file",
        SecretsBackend::Keychain => "keychain",
    };
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "updated_fields": updated_fields,
                "backend": backend,
            }))?
        ),
        OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "updated_fields": updated_fields,
                "backend": backend,
            }))?
        ),
        OutputFormat::Table => println!(
            "Updated OMI credential field(s) in {backend}: {} (values hidden)",
            updated_fields.join(", ")
        ),
    }
    Ok(())
}

fn require_confirmation(confirmed: bool, operation: &str) -> Result<()> {
    if !confirmed {
        bail!("{operation} requires --yes");
    }
    Ok(())
}

fn print_outcome(
    output: OutputFormat,
    operation: &str,
    source_id: Option<&str>,
    outcome: crate::memory::omi::OmiPurgeOutcome,
) -> Result<()> {
    let value = serde_json::json!({
        "operation": operation,
        "conversation_id": source_id,
        "conversations": outcome.conversations,
        "segments": outcome.segments,
        "media": outcome.media,
        "actions": outcome.actions,
        "tasks": outcome.tasks,
        "groundtruth": outcome.groundtruth,
    });
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
        OutputFormat::Table => {
            if let Some(source_id) = source_id {
                println!("OMI {operation}: {source_id}");
            } else {
                println!("OMI {operation}");
            }
            println!(
                "conversations={} segments={} media={} actions={} tasks={} groundtruth={}",
                outcome.conversations,
                outcome.segments,
                outcome.media,
                outcome.actions,
                outcome.tasks,
                outcome.groundtruth,
            );
        }
    }
    Ok(())
}

fn print_status(context: &OmiContext, output: OutputFormat) -> Result<()> {
    let validation_error = context
        .config
        .omi
        .validate_with_credentials(&context.credentials)
        .err();
    let status = read_status(&context.db_path())?;
    let ledger_initialized = status.is_some();
    let status = status.unwrap_or_default();
    let daemon_pid = crate::daemon::pidfile::live_daemon_pid(&native_daemon_pidfile(&context.home))
        .context("read OMI daemon PID state")?;
    let effective_runtime_state =
        effective_omi_runtime_state(context.config.omi.enabled, &status, daemon_pid);
    let value = serde_json::json!({
        "enabled": context.config.omi.enabled,
        "mode": mode_name(context.config.omi.mode),
        "configuration_valid": validation_error.is_none(),
        "configuration_error": validation_error.as_deref(),
        "developer_api_credential_present": context.credentials.omi_developer_api_key.is_some(),
        "native_ingest_credential_present": context.credentials.omi_ingest_token.is_some(),
        "endpoint": context.config.omi.endpoint.as_str(),
        "listen_addr": context.config.omi.listen_addr.as_str(),
        "retention_days": context.config.omi.retention_days,
        "poll_interval_secs": context.config.omi.poll_interval_secs,
        "retain_transcripts": context.config.omi.retain_transcripts,
        "audio_enabled": context.config.omi.audio_enabled,
        "visual_enabled": context.config.omi.visual_enabled,
        "video_enabled": context.config.omi.video_enabled,
        "allow_cloud_api": context.config.omi.allow_cloud_api,
        "allow_cloud_summary": context.config.omi.allow_cloud_summary,
        "create_actions": context.config.omi.create_actions,
        "seed_groundtruth": context.config.omi.seed_groundtruth,
        "summary_enabled": context.config.omi.summary_enabled,
        "ledger_initialized": ledger_initialized,
        "conversations": status.conversations,
        "segments": status.segments,
        "media": status.media,
        "actions": status.actions,
        "tombstones": status.tombstones,
        "pending_audits": status.pending_audits,
        "runtime_state": effective_runtime_state,
        "runtime_persisted_state": status.runtime_state.as_deref(),
        "runtime_detail": status.runtime_detail.as_deref(),
        "runtime_pid": status.runtime_pid,
        "runtime_updated_ns": status.runtime_updated_ts,
        "daemon_pid": daemon_pid,
        "sanitizer_halted": status.sanitizer_halted,
        "last_success_ns": status.last_success_ts,
        "last_error": status.last_error.as_deref(),
        "last_retention_purge_ns": status.last_retention_purge_ts,
        "last_retention_error": status.last_retention_error.as_deref(),
    });

    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
        OutputFormat::Table => {
            println!(
                "OMI: {} / {} / config {}",
                if context.config.omi.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                mode_name(context.config.omi.mode),
                if validation_error.is_none() {
                    "valid"
                } else {
                    "INVALID"
                }
            );
            if let Some(error) = validation_error {
                println!("configuration error: {error}");
            }
            if ledger_initialized {
                println!(
                    "ledger: conversations={} segments={} media={} actions={} tombstones={} pending_audits={}",
                    status.conversations,
                    status.segments,
                    status.media,
                    status.actions,
                    status.tombstones,
                    status.pending_audits,
                );
            } else {
                println!("ledger: not initialized (start neoth serve)");
            }
            println!(
                "privacy: retention={}d retain_transcripts={} audio={} images={} video={}",
                context.config.omi.retention_days,
                context.config.omi.retain_transcripts,
                context.config.omi.audio_enabled,
                context.config.omi.visual_enabled,
                context.config.omi.video_enabled,
            );
            println!(
                "sanitizer: {}",
                if !ledger_initialized {
                    "not initialized"
                } else if status.sanitizer_halted {
                    "HALTED"
                } else {
                    "ready"
                }
            );
            println!(
                "runtime: {}{}",
                effective_runtime_state,
                status
                    .runtime_detail
                    .as_deref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default()
            );
            if let Some(error) = status.last_error {
                println!("last error: {error}");
            }
            if let Some(error) = status.last_retention_error {
                println!("retention error: {error}");
            }
        }
    }
    Ok(())
}

async fn print_probe(context: &OmiContext, output: OutputFormat) -> Result<()> {
    let local_endpoint = if context.config.omi.mode.polls()
        && crate::installers::omi::is_local_endpoint(&context.config.omi.endpoint).is_ok()
    {
        Some(
            crate::installers::omi::probe_endpoint(&context.config.omi.endpoint)
                .await
                .as_str(),
        )
    } else {
        None
    };
    let native_listener = if context.config.omi.mode.listens() {
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(&context.config.omi.listen_addr),
        )
        .await;
        Some(match outcome {
            Ok(Ok(_)) => "reachable",
            Ok(Err(_)) => "port_closed",
            Err(_) => "timeout",
        })
    } else {
        None
    };
    let public_api_probe = if context.config.omi.mode.polls()
        && crate::installers::omi::is_local_endpoint(&context.config.omi.endpoint).is_err()
    {
        Some("not_probed_auth_required")
    } else {
        None
    };
    let value = serde_json::json!({
        "mode": mode_name(context.config.omi.mode),
        "local_endpoint": local_endpoint,
        "native_listener": native_listener,
        "public_api": public_api_probe,
    });
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
        OutputFormat::Table => {
            println!("OMI probe ({})", mode_name(context.config.omi.mode));
            if let Some(outcome) = local_endpoint {
                println!("local endpoint: {outcome}");
            }
            if let Some(outcome) = native_listener {
                println!("native listener: {outcome}");
            }
            if let Some(outcome) = public_api_probe {
                println!("public Developer API: {outcome}");
            }
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn submitted_secret_matches(submitted: &SecretString, readback: Option<&SecretString>) -> bool {
    readback.is_some_and(|readback| {
        bool::from(
            submitted
                .expose_secret()
                .as_bytes()
                .ct_eq(readback.expose_secret().as_bytes()),
        )
    })
}

fn new_omi_operation_id() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| anyhow::anyhow!("OS RNG unavailable for OMI operation id: {error}"))?;
    Ok(hex::encode(random))
}

fn render_omi_configure_target(
    source: &str,
    settings: &OmiConfigureSettings,
) -> Result<(String, FreedomConfig)> {
    anyhow::ensure!(
        !source.trim().is_empty(),
        "freedom.yaml is empty. Run `neoth init` first to generate it."
    );
    let mut persisted: serde_yaml::Value =
        serde_yaml::from_str(source).context("parse freedom.yaml for OMI configure")?;
    settings.overlay_yaml(&mut persisted)?;
    let body = serde_yaml::to_string(&persisted)
        .context("serialize semantically merged OMI configuration")?;
    let candidate: FreedomConfig =
        serde_yaml::from_str(&body).context("validate merged OMI configuration")?;
    anyhow::ensure!(
        OmiConfigureSettings::from(&candidate.omi) == *settings,
        "merged OMI settings do not match the submitted snapshot"
    );
    let _ = candidate.public_yaml()?;
    Ok((body, candidate))
}

fn configure_omi_at_with_reload<R>(
    home: &Path,
    request: OmiConfigureRequest,
    request_reload: R,
) -> Result<OmiConfigureReceipt>
where
    R: FnOnce(&Path) -> Result<(PathBuf, u64)>,
{
    configure_omi_at_with_reload_and_validation_hook(home, request, request_reload, || {})
}

fn configure_omi_at_with_reload_and_validation_hook<R, H>(
    home: &Path,
    request: OmiConfigureRequest,
    request_reload: R,
    after_validation: H,
) -> Result<OmiConfigureReceipt>
where
    R: FnOnce(&Path) -> Result<(PathBuf, u64)>,
    H: FnOnce(),
{
    configure_omi_at_with_reload_and_hooks(home, request, request_reload, after_validation, || {})
}

fn configure_omi_at_with_reload_and_hooks<R, H, B>(
    home: &Path,
    request: OmiConfigureRequest,
    request_reload: R,
    after_validation: H,
    before_verified_readback: B,
) -> Result<OmiConfigureReceipt>
where
    R: FnOnce(&Path) -> Result<(PathBuf, u64)>,
    H: FnOnce(),
    B: FnOnce(),
{
    let freedom_path = home.join("freedom.yaml");
    let credentials_path = home.join("credentials.yaml");
    anyhow::ensure!(
        freedom_path
            .try_exists()
            .with_context(|| format!("check {}", freedom_path.display()))?,
        "freedom.yaml not found at {}. Run `neoth init` first to generate it.",
        freedom_path.display()
    );
    if !request.credentials.is_empty() {
        request.credentials.validate()?;
    }

    let operation_id = new_omi_operation_id()?;
    let settings_body =
        serde_json::to_vec(&request.settings).context("encode OMI settings binding")?;
    let settings_sha256 = sha256_hex(&settings_body);
    let updated_fields = request
        .credentials
        .updated_field_names()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let settings = request.settings;
    let credential_update = request.credentials;
    let mut keychain_store: Option<Box<dyn crate::config::keychain::SecretStore>> = None;

    // One recovery journal binds the exact before/after bytes for both files.
    // The closure executes while the transaction lock plus both legacy locks
    // are held, so neither an older CLI nor a concurrent daemon writer can
    // publish between validation and the two durable renames.
    let (expected_config, backend) = Credentials::update_raw_freedom_with_credentials_at(
        &freedom_path,
        &credentials_path,
        |source, credentials| {
            let source = source
                .with_context(|| format!("freedom.yaml not found at {}", freedom_path.display()))?;
            let (body, candidate) = render_omi_configure_target(source, &settings)?;

            if let Some(value) = credential_update.developer_api_key.as_ref() {
                credentials.omi_developer_api_key = Some(value.clone());
            }
            if let Some(value) = credential_update.native_ingest_token.as_ref() {
                credentials.omi_ingest_token = Some(value.clone());
            }

            let backend = candidate.secrets_backend;
            let mut effective_credentials = credentials.clone();
            if backend == SecretsBackend::Keychain {
                let store = crate::config::keychain::open_store()
                    .context("open configured OS keychain for OMI configure")?;
                crate::config::keychain::supplement_from_store(
                    &mut effective_credentials,
                    store.as_ref(),
                )
                .context("load coherent OMI credentials from the OS keychain")?;
                keychain_store = Some(store);
            }
            candidate
                .omi
                .validate_with_credentials(&effective_credentials)
                .map_err(anyhow::Error::msg)
                .context("validate submitted OMI settings and effective credentials")?;
            after_validation();
            let expected = body.as_bytes().to_vec();
            Ok((Some(body), (expected, backend)))
        },
    )
    .context("commit crash-recoverable OMI settings/credential transaction")?;

    if backend == SecretsBackend::Keychain && !credential_update.is_empty() {
        let store = keychain_store
            .as_deref()
            .context("OMI keychain store was not retained for finalization")?;
        finalize_staged_omi_keychain_update_if_source(
            &freedom_path,
            &credentials_path,
            store,
            &credential_update,
            Some(&expected_config),
        )
        .context(
            "OMI config committed, but keychain finalization did not complete cleanly; inspect the retained or restored generation before retrying",
        )?;
    }

    before_verified_readback();

    // Read back and reload while the exact pair generation is locked. A newer
    // writer in either inter-transaction gap wins loudly; no stale GUI success
    // receipt is emitted. The committed generation hash lets operators and the
    // GUI identify precisely what was verified.
    crate::config::with_config_credential_migration_lock(&freedom_path, || {
        let current_config = std::fs::read(&freedom_path)
            .with_context(|| format!("read back committed {}", freedom_path.display()))?;
        anyhow::ensure!(
            current_config == expected_config,
            "OMI configuration committed, but freedom.yaml changed before verified readback; refresh and retry"
        );
        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path)
            .context("reload committed OMI config/credential generation")?;
        let readback_settings = OmiConfigureSettings::from(&pair.config.omi);
        anyhow::ensure!(
            readback_settings == settings,
            "OMI configuration readback does not match the submitted settings"
        );
        pair.config
            .omi
            .validate_with_credentials(&pair.credentials)
            .map_err(anyhow::Error::msg)
            .context("validate committed OMI readback")?;
        let developer_present = pair.credentials.omi_developer_api_key.is_some();
        let native_present = pair.credentials.omi_ingest_token.is_some();
        if let Some(submitted) = credential_update.developer_api_key.as_ref() {
            anyhow::ensure!(
                submitted_secret_matches(
                    submitted,
                    pair.credentials.omi_developer_api_key.as_ref()
                ),
                "OMI Developer key changed before verified readback; refresh and retry"
            );
        }
        if let Some(submitted) = credential_update.native_ingest_token.as_ref() {
            anyhow::ensure!(
                submitted_secret_matches(submitted, pair.credentials.omi_ingest_token.as_ref()),
                "OMI native token changed before verified readback; refresh and retry"
            );
        }
        anyhow::ensure!(
            pair.config.secrets_backend == backend,
            "OMI secrets backend changed before verified readback"
        );
        let (_, reload_ts_unix) = request_reload(home).context(
            "OMI configuration committed and verified, but its reload request failed; run `neoth reload` and refresh OMI status",
        )?;
        Ok(OmiConfigureReceipt {
            operation: "omi.configure".to_string(),
            operation_id,
            path: freedom_path.display().to_string(),
            settings_sha256,
            config_sha256: sha256_hex(&current_config),
            reload_requested: true,
            reload_ts_unix,
            settings: readback_settings,
            credentials: OmiConfigureCredentialReceipt {
                // Keep this exhaustive literal mapping inline. Besides making
                // the closed public vocabulary obvious, it prevents generic
                // sensitive-data heuristics from treating a helper named for
                // the credential backend as a secret-producing source.
                backend: match backend {
                    SecretsBackend::File => "file",
                    SecretsBackend::Keychain => "keychain",
                }
                .to_string(),
                updated_fields,
                developer_api_key_present: developer_present,
                native_ingest_token_present: native_present,
            },
        })
    })
}

fn print_configure_receipt(output: OutputFormat, receipt: &OmiConfigureReceipt) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(receipt)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(receipt)?),
        OutputFormat::Table => {
            println!("OMI configuration committed and verified: {}", receipt.path);
            println!("  operation id    : {}", receipt.operation_id);
            println!("  config sha256   : {}", receipt.config_sha256);
            // Do not echo config-derived credential metadata to terminal logs.
            // The typed JSON receipt retains the non-secret backend for callers
            // that explicitly request structured output.
            println!("  credentials     : committed and verified");
            println!("  reload requested: {}", receipt.reload_requested);
        }
    }
    Ok(())
}

pub async fn run_omi(args: OmiArgs) -> Result<()> {
    if matches!(&args.action, OmiAction::SetCredentials) {
        let home = args
            .home
            .clone()
            .unwrap_or_else(FreedomConfig::default_neoth_home);
        let update = read_omi_credential_update()?;
        let updated_fields = update.updated_field_names();
        let backend = persist_omi_credential_update(&home, &update)?;
        return print_credential_update(args.output, backend, &updated_fields);
    }
    if matches!(&args.action, OmiAction::Configure) {
        let home = args
            .home
            .clone()
            .unwrap_or_else(FreedomConfig::default_neoth_home);
        let request = read_omi_configure_request()?;
        let receipt = configure_omi_at_with_reload(&home, request, |home| {
            crate::cli::reload::request_reload_at(home)
        })?;
        return print_configure_receipt(args.output, &receipt);
    }
    let context = OmiContext::load(args.home)?;
    match args.action {
        OmiAction::Status => print_status(&context, args.output),
        OmiAction::Probe => print_probe(&context, args.output).await,
        OmiAction::SetCredentials => unreachable!("handled before OMI context load"),
        OmiAction::Configure => unreachable!("handled before OMI context load"),
        OmiAction::Purge {
            conversation_id,
            yes,
        } => {
            require_confirmation(yes, "OMI purge")?;
            native_mutation_requires_stopped_daemon(&context.home, &conversation_id)?;
            let audit =
                PrivacyDeletionAudit::begin(&context.home, "purge", Some(&conversation_id)).await;
            let mut conn = match open_views(&context.db_path()) {
                Ok(conn) => conn,
                Err(error) => {
                    audit
                        .record_failed_attempt("purge", Some(&conversation_id))
                        .await;
                    return Err(error);
                }
            };
            let outcome = match crate::memory::omi::purge_conversation(
                &mut conn,
                &conversation_id,
                crate::time::now_unix_ns(),
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    audit
                        .record_failed_attempt("purge", Some(&conversation_id))
                        .await;
                    return Err(error);
                }
            };
            let journal_cleanup = crate::daemon::omi_native_ingest::purge_native_journal_for_source(
                &context.home,
                &conversation_id,
            );
            let audit_result = audit
                .complete(
                    "purge",
                    Some(&conversation_id),
                    serde_json::json!({
                        "success": journal_cleanup.is_ok(),
                        "committed": true,
                        "journal_removed": journal_cleanup.as_ref().copied().ok(),
                        "conversations": outcome.conversations,
                        "segments": outcome.segments,
                        "media": outcome.media,
                        "actions": outcome.actions,
                        "tasks": outcome.tasks,
                        "groundtruth": outcome.groundtruth,
                    }),
                )
                .await;
            if let Err(error) = journal_cleanup {
                if let Err(audit_error) = audit_result {
                    bail!(
                        "OMI purge database deletion committed, but native receipt cleanup failed: {error:#}; {audit_error:#}"
                    );
                }
                return Err(error).context(
                    "OMI purge database deletion committed, but native receipt cleanup failed",
                );
            }
            audit_result?;
            print_outcome(args.output, "purge", Some(&conversation_id), outcome)
        }
        OmiAction::Resume { review_note } => {
            let audit = OperatorAudit::start(&context.home)?;
            audit
                .emit(
                    "operator_intent",
                    "resume",
                    OperatorAuditContract::FailClosedBeforeMutation,
                    None,
                    Some(&review_note),
                    None,
                )
                .await?;
            let resumed = match crate::daemon::omi_ingest_task::resume_sanitizer(
                &context.db_path(),
                &review_note,
            )
            .await
            {
                Ok(resumed) => resumed,
                Err(error) => {
                    let _ = audit
                        .emit(
                            "operator_result",
                            "resume",
                            OperatorAuditContract::FailClosedBeforeMutation,
                            None,
                            Some(&review_note),
                            Some(serde_json::json!({ "success": false, "committed": false })),
                        )
                        .await;
                    let _ = audit.finish().await;
                    return Err(error);
                }
            };
            if let Err(error) = audit
                .emit(
                    "operator_result",
                    "resume",
                    OperatorAuditContract::FailClosedBeforeMutation,
                    None,
                    Some(&review_note),
                    Some(serde_json::json!({ "success": true, "resumed": resumed })),
                )
                .await
            {
                let _ = audit.finish().await;
                bail!("OMI resume committed, but its result audit failed: {error:#}");
            }
            audit.finish().await?;
            let value = serde_json::json!({
                "operation": "resume",
                "resumed": resumed,
                "review_evidence_retained": resumed,
            });
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
                OutputFormat::Table => println!(
                    "OMI sanitizer: {}",
                    if resumed { "resumed" } else { "not halted" }
                ),
            }
            Ok(())
        }
        OmiAction::EnforceRetention => {
            let audit = PrivacyDeletionAudit::begin(&context.home, "enforce_retention", None).await;
            let outcome = match crate::daemon::omi_ingest_task::enforce_retention_once(
                &context.db_path(),
                context.config.omi.retention_days,
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    // `enforce_retention_once` commits its SQLite deletion before
                    // removing filesystem receipts. Report that partial boundary
                    // explicitly; never imply that a retry can restore data.
                    let audit_result = audit
                        .complete(
                            "enforce_retention",
                            None,
                            serde_json::json!({
                                "success": false,
                                "database_deletion_may_be_committed": true,
                            }),
                        )
                        .await;
                    if let Err(audit_error) = audit_result {
                        bail!(
                            "OMI retention may have committed its database deletion before failing: {error:#}; {audit_error:#}"
                        );
                    }
                    return Err(error).context(
                        "OMI retention may have committed its database deletion before receipt cleanup failed",
                    );
                }
            };
            audit
                .complete(
                    "enforce_retention",
                    None,
                    serde_json::json!({
                        "success": true,
                        "committed": true,
                        "conversations": outcome.conversations,
                        "segments": outcome.segments,
                        "media": outcome.media,
                        "actions": outcome.actions,
                        "tasks": outcome.tasks,
                        "groundtruth": outcome.groundtruth,
                    }),
                )
                .await?;
            print_outcome(args.output, "retention", None, outcome)
        }
        OmiAction::AllowReimport {
            conversation_id,
            yes,
        } => {
            require_confirmation(yes, "OMI allow-reimport")?;
            native_mutation_requires_stopped_daemon(&context.home, &conversation_id)?;
            let audit = OperatorAudit::start(&context.home)?;
            audit
                .emit(
                    "operator_intent",
                    "allow_reimport",
                    OperatorAuditContract::FailClosedBeforeMutation,
                    Some(&conversation_id),
                    None,
                    None,
                )
                .await?;
            let journal_removed =
                match crate::daemon::omi_native_ingest::purge_native_journal_for_source(
                    &context.home,
                    &conversation_id,
                ) {
                    Ok(removed) => removed,
                    Err(error) => {
                        let _ = audit
                            .emit(
                                "operator_result",
                                "allow_reimport",
                                OperatorAuditContract::FailClosedBeforeMutation,
                                Some(&conversation_id),
                                None,
                                Some(serde_json::json!({ "success": false, "committed": false })),
                            )
                            .await;
                        let _ = audit.finish().await;
                        return Err(error).context(
                            "remove stale native OMI receipt before clearing the tombstone",
                        );
                    }
                };
            let conn = match open_views(&context.db_path()) {
                Ok(conn) => conn,
                Err(error) => {
                    let _ = audit
                        .emit(
                            "operator_result",
                            "allow_reimport",
                            OperatorAuditContract::FailClosedBeforeMutation,
                            Some(&conversation_id),
                            None,
                            Some(serde_json::json!({
                                "success": false,
                                "stale_native_receipt_removed": journal_removed,
                                "tombstone_cleared": false,
                            })),
                        )
                        .await;
                    let _ = audit.finish().await;
                    return Err(error);
                }
            };
            let cleared = match crate::memory::omi::clear_tombstone(&conn, &conversation_id) {
                Ok(cleared) => cleared,
                Err(error) => {
                    let _ = audit
                        .emit(
                            "operator_result",
                            "allow_reimport",
                            OperatorAuditContract::FailClosedBeforeMutation,
                            Some(&conversation_id),
                            None,
                            Some(serde_json::json!({
                                "success": false,
                                "stale_native_receipt_removed": journal_removed,
                                "tombstone_cleared": false,
                            })),
                        )
                        .await;
                    let _ = audit.finish().await;
                    return Err(error);
                }
            };
            if let Err(error) = audit
                .emit(
                    "operator_result",
                    "allow_reimport",
                    OperatorAuditContract::FailClosedBeforeMutation,
                    Some(&conversation_id),
                    None,
                    Some(serde_json::json!({
                        "success": true,
                        "tombstone_cleared": cleared,
                        "stale_native_receipt_removed": journal_removed,
                        "reconciliation_state_cleared": true,
                    })),
                )
                .await
            {
                let _ = audit.finish().await;
                bail!("OMI allow-reimport committed, but its result audit failed: {error:#}");
            }
            audit.finish().await?;
            let value = serde_json::json!({
                "operation": "allow_reimport",
                "conversation_id": conversation_id.as_str(),
                "tombstone_cleared": cleared,
                "stale_native_receipt_removed": journal_removed,
                "reconciliation_state_cleared": true,
            });
            match args.output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&value)?),
                OutputFormat::Table => println!(
                    "OMI allow-reimport: {} ({})",
                    conversation_id,
                    if cleared {
                        "tombstone cleared"
                    } else {
                        "no tombstone"
                    }
                ),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::keychain::SecretStore as _;

    fn credential_update(developer: Option<&str>, native: Option<&str>) -> OmiCredentialUpdate {
        OmiCredentialUpdate {
            developer_api_key: developer.map(SecretString::from),
            native_ingest_token: native.map(SecretString::from),
        }
    }

    #[test]
    fn credential_update_validation_is_strict_and_names_only() {
        assert!(credential_update(None, None).validate().is_err());
        assert!(
            credential_update(Some("omi_dev_"), None)
                .validate()
                .is_err()
        );
        assert!(credential_update(None, Some("short")).validate().is_err());
        let valid = credential_update(
            Some("omi_dev_replacement"),
            Some("0123456789abcdef0123456789abcdef"),
        );
        valid.validate().unwrap();
        assert_eq!(
            valid.updated_field_names(),
            vec!["omi_developer_api_key", "omi_ingest_token"]
        );
    }

    #[test]
    fn file_credential_update_preserves_every_unrelated_secret() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("credentials.yaml");
        let existing = Credentials {
            provider_key: Some(SecretString::from("provider-stays")),
            telegram_token: Some(SecretString::from("telegram-stays")),
            omi_developer_api_key: Some(SecretString::from("omi_dev_old")),
            ..Default::default()
        };
        existing.write(&path).unwrap();
        let update = credential_update(
            Some("omi_dev_replacement"),
            Some("0123456789abcdef0123456789abcdef"),
        );
        assert_eq!(
            persist_omi_credential_update(home.path(), &update).unwrap(),
            SecretsBackend::File
        );

        let loaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            loaded.provider_key.as_ref().unwrap().expose(),
            "provider-stays"
        );
        assert_eq!(
            loaded.telegram_token.as_ref().unwrap().expose(),
            "telegram-stays"
        );
        assert_eq!(
            loaded.omi_developer_api_key.as_ref().unwrap().expose(),
            "omi_dev_replacement"
        );
        assert_eq!(
            loaded.omi_ingest_token.as_ref().unwrap().expose(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn keychain_update_clears_masking_file_values_and_preserves_other_fields() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("credentials.yaml");
        let existing = Credentials {
            provider_key: Some(SecretString::from("provider-stays")),
            omi_developer_api_key: Some(SecretString::from("omi_dev_file_override")),
            omi_ingest_token: Some(SecretString::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
            ..Default::default()
        };
        existing.write(&path).unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        store
            .set(
                "omi_developer_api_key",
                &SecretString::from("omi_dev_old_store"),
            )
            .unwrap();
        let update = credential_update(
            Some("omi_dev_new_store"),
            Some("0123456789abcdef0123456789abcdef"),
        );

        persist_omi_keychain_update(&home.path().join("freedom.yaml"), &path, &store, &update)
            .unwrap();

        let file = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            file.provider_key.as_ref().unwrap().expose(),
            "provider-stays"
        );
        assert!(file.omi_developer_api_key.is_none());
        assert!(file.omi_ingest_token.is_none());
        assert_eq!(
            store
                .get("omi_developer_api_key")
                .unwrap()
                .unwrap()
                .expose(),
            "omi_dev_new_store"
        );
        assert_eq!(
            store.get("omi_ingest_token").unwrap().unwrap().expose(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn target_publication_error_retains_updated_keychain_generation() {
        let store = crate::config::keychain::InMemorySecretStore::default();
        store
            .set(
                "omi_developer_api_key",
                &SecretString::from("omi_dev_old_store"),
            )
            .unwrap();
        let update = credential_update(Some("omi_dev_new_store"), None);
        let applied = stage_omi_keychain_update(&store, &update).unwrap();
        let error = staged_omi_finalization_error(
            crate::config::credentials::test_target_publication_crossed_error(anyhow::anyhow!(
                "injected post-publication failure"
            )),
            &store,
            Some(&applied),
        );

        assert!(crate::config::credentials::dual_file_target_publication_crossed(&error));
        let error = format!("{error:#}");
        assert!(error.contains("updated keychain generation was retained"));
        assert!(error.contains("injected post-publication failure"));
        assert_eq!(
            store
                .get("omi_developer_api_key")
                .unwrap()
                .unwrap()
                .expose(),
            "omi_dev_new_store"
        );
    }

    #[test]
    fn keychain_stage_reads_every_prior_value_before_first_write() {
        struct SecondReadFailureStore {
            get_calls: std::sync::atomic::AtomicUsize,
            set_calls: std::sync::atomic::AtomicUsize,
        }

        impl crate::config::keychain::SecretStore for SecondReadFailureStore {
            fn get(&self, _key: &str) -> Result<Option<SecretString>> {
                let call = self
                    .get_calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if call == 1 {
                    bail!("injected second keychain read failure")
                }
                Ok(Some(SecretString::from("prior-value")))
            }

            fn set(&self, _key: &str, _value: &SecretString) -> Result<()> {
                self.set_calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }

            fn delete(&self, _key: &str) -> Result<()> {
                bail!("unexpected keychain delete")
            }

            fn backend_name(&self) -> &'static str {
                "second-read-failure-test"
            }
        }

        let store = SecondReadFailureStore {
            get_calls: std::sync::atomic::AtomicUsize::new(0),
            set_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let update = credential_update(
            Some("omi_dev_new_store"),
            Some("0123456789abcdef0123456789abcdef"),
        );

        let error = stage_omi_keychain_update(&store, &update).unwrap_err();
        assert!(format!("{error:#}").contains("injected second keychain read failure"));
        assert_eq!(
            store.set_calls.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "no keychain write may occur until every prior value is readable"
        );
    }

    #[test]
    fn keychain_stage_restores_current_key_when_write_reports_after_side_effect() {
        struct CommittedThenErrorStore {
            data: std::sync::Mutex<std::collections::HashMap<String, String>>,
            set_calls: std::sync::atomic::AtomicUsize,
        }

        impl crate::config::keychain::SecretStore for CommittedThenErrorStore {
            fn get(&self, key: &str) -> Result<Option<SecretString>> {
                let data = self.data.lock().unwrap();
                Ok(data.get(key).cloned().map(SecretString::from))
            }

            fn set(&self, key: &str, value: &SecretString) -> Result<()> {
                let call = self
                    .set_calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.data
                    .lock()
                    .unwrap()
                    .insert(key.to_string(), value.expose().to_string());
                if call == 1 {
                    bail!("injected error after keychain side effect")
                }
                Ok(())
            }

            fn delete(&self, key: &str) -> Result<()> {
                self.data.lock().unwrap().remove(key);
                Ok(())
            }

            fn backend_name(&self) -> &'static str {
                "post-side-effect-failure-test"
            }
        }

        let store = CommittedThenErrorStore {
            data: std::sync::Mutex::new(std::collections::HashMap::from([
                ("omi_developer_api_key".into(), "old-developer-key".into()),
                ("omi_ingest_token".into(), "old-ingest-token".into()),
            ])),
            set_calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let update = credential_update(
            Some("omi_dev_new_store"),
            Some("0123456789abcdef0123456789abcdef"),
        );

        let error = stage_omi_keychain_update(&store, &update).unwrap_err();
        assert!(format!("{error:#}").contains("every requested keychain write was restored"));
        assert_eq!(
            store
                .get("omi_developer_api_key")
                .unwrap()
                .unwrap()
                .expose(),
            "old-developer-key"
        );
        assert_eq!(
            store.get("omi_ingest_token").unwrap().unwrap().expose(),
            "old-ingest-token"
        );
        assert_eq!(
            store.set_calls.load(std::sync::atomic::Ordering::Relaxed),
            4
        );
    }

    #[test]
    fn pre_publication_error_restores_prior_keychain_generation() {
        let store = crate::config::keychain::InMemorySecretStore::default();
        store
            .set(
                "omi_developer_api_key",
                &SecretString::from("omi_dev_old_store"),
            )
            .unwrap();
        let update = credential_update(Some("omi_dev_new_store"), None);
        let applied = stage_omi_keychain_update(&store, &update).unwrap();
        let error = staged_omi_finalization_error(
            anyhow::anyhow!("injected pre-publication failure"),
            &store,
            Some(&applied),
        );

        assert!(!crate::config::credentials::dual_file_target_publication_crossed(&error));
        assert!(format!("{error:#}").contains("prior keychain values were restored"));
        assert_eq!(
            store
                .get("omi_developer_api_key")
                .unwrap()
                .unwrap()
                .expose(),
            "omi_dev_old_store"
        );
    }

    #[test]
    fn staged_keychain_finalization_rejects_changed_file_receipt_before_keychain_write() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("credentials.yaml");
        let staged = credential_update(Some("omi_dev_staged"), None);
        Credentials {
            omi_developer_api_key: staged.developer_api_key.clone(),
            ..Default::default()
        }
        .write(&path)
        .unwrap();
        let store = crate::config::keychain::InMemorySecretStore::default();
        store
            .set(
                "omi_developer_api_key",
                &SecretString::from("preexisting-keychain"),
            )
            .unwrap();

        Credentials::update_at(&path, |credentials| {
            credentials.omi_developer_api_key = Some(SecretString::from("concurrent-file-writer"));
            Ok(())
        })
        .unwrap();

        let error = finalize_staged_omi_keychain_update(&path, &store, &staged).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("before a complete keychain generation was staged"));
        assert!(
            error.contains("staged OMI developer API key changed before keychain finalization")
        );
        assert!(!error.contains("keychain values were restored"));
        assert_eq!(
            store
                .get("omi_developer_api_key")
                .unwrap()
                .unwrap()
                .expose(),
            "preexisting-keychain"
        );
        assert_eq!(
            Credentials::load_or_default(&path)
                .unwrap()
                .omi_developer_api_key
                .as_ref()
                .unwrap()
                .expose(),
            "concurrent-file-writer"
        );
    }

    #[test]
    fn failed_keychain_stage_never_claims_restore_when_rollback_failed() {
        struct RollbackFailureStore {
            set_calls: std::sync::atomic::AtomicUsize,
        }

        impl crate::config::keychain::SecretStore for RollbackFailureStore {
            fn get(&self, _key: &str) -> Result<Option<SecretString>> {
                Ok(Some(SecretString::from("prior-value")))
            }

            fn set(&self, _key: &str, _value: &SecretString) -> Result<()> {
                let call = self
                    .set_calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if call == 0 {
                    Ok(())
                } else {
                    bail!("injected keychain write failure")
                }
            }

            fn delete(&self, _key: &str) -> Result<()> {
                bail!("unexpected keychain delete")
            }

            fn backend_name(&self) -> &'static str {
                "rollback-failure-test"
            }
        }

        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("credentials.yaml");
        let staged = credential_update(
            Some("omi_dev_staged"),
            Some("0123456789abcdef0123456789abcdef"),
        );
        Credentials {
            omi_developer_api_key: staged.developer_api_key.clone(),
            omi_ingest_token: staged.native_ingest_token.clone(),
            ..Default::default()
        }
        .write(&path)
        .unwrap();
        let store = RollbackFailureStore {
            set_calls: std::sync::atomic::AtomicUsize::new(0),
        };

        let error = finalize_staged_omi_keychain_update(&path, &store, &staged).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("before a complete keychain generation was staged"));
        assert!(error.contains("rollback also failed"));
        assert!(!error.contains("keychain values were restored"));
        assert_eq!(
            store.set_calls.load(std::sync::atomic::Ordering::Relaxed),
            4
        );
    }

    fn configure_settings() -> OmiConfigureSettings {
        OmiConfigureSettings {
            enabled: true,
            mode: OmiIngestMode::Both,
            endpoint: "https://api.omi.me".to_string(),
            listen_addr: "127.0.0.1:8003".to_string(),
            retention_days: 14,
            retain_transcripts: true,
            audio_enabled: true,
            visual_enabled: true,
            video_enabled: false,
            allow_cloud_api: true,
            allow_cloud_summary: false,
            create_actions: true,
            seed_groundtruth: false,
            summary_enabled: true,
        }
    }

    fn configure_request() -> OmiConfigureRequest {
        OmiConfigureRequest {
            settings: configure_settings(),
            credentials: credential_update(
                Some("omi_dev_configure"),
                Some("0123456789abcdef0123456789abcdef"),
            ),
        }
    }

    fn write_configure_fixture(home: &Path) {
        std::fs::write(
            home.join("freedom.yaml"),
            concat!(
                "operator_id: alice\n",
                "future_extension: keep-me\n",
                "omi:\n",
                "  poll_interval_secs: 45\n",
                "  confidence_threshold: 0.8\n",
            ),
        )
        .unwrap();
        Credentials {
            provider_key: Some(SecretString::from("provider-stays")),
            ..Default::default()
        }
        .write(&home.join("credentials.yaml"))
        .unwrap();
    }

    #[test]
    fn configure_commits_one_verified_pair_and_secret_free_receipt() {
        let home = tempfile::tempdir().unwrap();
        write_configure_fixture(home.path());
        let receipt = configure_omi_at_with_reload(home.path(), configure_request(), |home| {
            let sentinel = home.join(".reload-requested-test");
            std::fs::write(&sentinel, b"reload\n")?;
            Ok((sentinel, 42))
        })
        .unwrap();

        assert_eq!(receipt.operation, "omi.configure");
        assert_eq!(receipt.operation_id.len(), 32);
        assert_eq!(
            receipt.settings_sha256,
            sha256_hex(&serde_json::to_vec(&configure_settings()).unwrap())
        );
        assert_eq!(
            receipt.config_sha256,
            sha256_hex(&std::fs::read(home.path().join("freedom.yaml")).unwrap())
        );
        assert_eq!(receipt.reload_ts_unix, 42);
        assert_eq!(receipt.settings, configure_settings());
        assert_eq!(receipt.credentials.backend, "file");
        assert_eq!(
            receipt.credentials.updated_fields,
            vec!["omi_developer_api_key", "omi_ingest_token"]
        );
        assert!(receipt.credentials.developer_api_key_present);
        assert!(receipt.credentials.native_ingest_token_present);

        let public = std::fs::read_to_string(home.path().join("freedom.yaml")).unwrap();
        assert!(public.contains("future_extension: keep-me"));
        assert!(public.contains("poll_interval_secs: 45"));
        assert!(public.contains("confidence_threshold: 0.8"));
        assert!(!public.contains("omi_dev_configure"));
        let pair =
            crate::config::load_runtime_config_pair_from_path(&home.path().join("freedom.yaml"))
                .unwrap();
        assert_eq!(
            OmiConfigureSettings::from(&pair.config.omi),
            configure_settings()
        );
        assert_eq!(
            pair.credentials.provider_key.as_ref().unwrap().expose(),
            "provider-stays"
        );
        assert_eq!(
            pair.credentials
                .omi_developer_api_key
                .as_ref()
                .unwrap()
                .expose(),
            "omi_dev_configure"
        );

        let wire = serde_json::to_string(&receipt).unwrap();
        assert!(!wire.contains("omi_dev_configure"));
        assert!(!wire.contains("0123456789abcdef"));
        let mut unknown: serde_json::Value = serde_json::from_str(&wire).unwrap();
        unknown["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<OmiConfigureReceipt>(unknown).is_err());
    }

    #[test]
    fn configure_validation_failure_preserves_both_files_exactly() {
        let home = tempfile::tempdir().unwrap();
        write_configure_fixture(home.path());
        let freedom_path = home.path().join("freedom.yaml");
        let credentials_path = home.path().join("credentials.yaml");
        let freedom_before = std::fs::read(&freedom_path).unwrap();
        let credentials_before = std::fs::read(&credentials_path).unwrap();
        let mut request = configure_request();
        request.settings.visual_enabled = false;
        request.settings.video_enabled = true;
        let reload_called = std::cell::Cell::new(false);

        let error = configure_omi_at_with_reload(home.path(), request, |_| {
            reload_called.set(true);
            anyhow::bail!("must not reload")
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("video_enabled"));
        assert!(!reload_called.get());
        assert_eq!(std::fs::read(&freedom_path).unwrap(), freedom_before);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_before
        );
    }

    #[test]
    fn configure_reload_failure_reports_committed_state_without_success_receipt() {
        let home = tempfile::tempdir().unwrap();
        write_configure_fixture(home.path());
        let error = configure_omi_at_with_reload(home.path(), configure_request(), |_| {
            anyhow::bail!("injected reload failure")
        })
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("configuration committed and verified"));
        assert!(error.contains("injected reload failure"));

        let pair =
            crate::config::load_runtime_config_pair_from_path(&home.path().join("freedom.yaml"))
                .unwrap();
        assert_eq!(
            OmiConfigureSettings::from(&pair.config.omi),
            configure_settings()
        );
        pair.config
            .omi
            .validate_with_credentials(&pair.credentials)
            .unwrap();
    }

    #[test]
    fn configure_serializes_concurrent_config_writer_without_lost_update() {
        use std::sync::mpsc;
        use std::time::Duration;

        let home = tempfile::tempdir().unwrap();
        write_configure_fixture(home.path());
        let configure_home = home.path().to_path_buf();
        let writer_path = home.path().join("freedom.yaml");
        let (validated_tx, validated_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let configure = std::thread::spawn(move || {
            configure_omi_at_with_reload_and_validation_hook(
                &configure_home,
                configure_request(),
                |home| Ok((home.join(".reload-requested-test"), 7)),
                || {
                    validated_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                },
            )
        });
        validated_rx.recv().unwrap();

        let (writer_done_tx, writer_done_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            FreedomConfig::update_at(&writer_path, |config| {
                config.operator_id = Some("concurrent-writer".to_string());
                Ok(())
            })
            .unwrap();
            writer_done_tx.send(()).unwrap();
        });
        assert!(
            writer_done_rx
                .recv_timeout(Duration::from_millis(150))
                .is_err(),
            "concurrent writer must wait through OMI validation and pair publication"
        );
        release_tx.send(()).unwrap();
        let configure_result = configure.join().unwrap();
        writer_done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        writer.join().unwrap();
        if let Err(error) = configure_result {
            assert!(
                format!("{error:#}").contains("changed before verified readback"),
                "a concurrent winner must produce the explicit CAS conflict"
            );
        }

        let pair =
            crate::config::load_runtime_config_pair_from_path(&home.path().join("freedom.yaml"))
                .unwrap();
        assert_eq!(
            pair.config.operator_id.as_deref(),
            Some("concurrent-writer")
        );
        assert_eq!(
            OmiConfigureSettings::from(&pair.config.omi),
            configure_settings()
        );
        assert_eq!(
            pair.credentials
                .omi_developer_api_key
                .as_ref()
                .unwrap()
                .expose(),
            "omi_dev_configure"
        );
    }

    #[test]
    fn configure_rejects_concurrent_credential_generation_before_receipt() {
        use std::sync::{Arc, mpsc};

        let home = tempfile::tempdir().unwrap();
        write_configure_fixture(home.path());
        let configure_home = home.path().to_path_buf();
        let writer_home = home.path().to_path_buf();
        let (published_tx, published_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let reload_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let configure_reload_called = Arc::clone(&reload_called);
        let configure = std::thread::spawn(move || {
            configure_omi_at_with_reload_and_hooks(
                &configure_home,
                configure_request(),
                move |home| {
                    configure_reload_called.store(true, Ordering::SeqCst);
                    Ok((home.join(".reload-requested-test"), 7))
                },
                || {},
                || {
                    published_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                },
            )
        });
        published_rx.recv().unwrap();

        let writer = std::thread::spawn(move || {
            persist_omi_credential_update(
                &writer_home,
                &credential_update(Some("omi_dev_concurrent"), None),
            )
        });
        assert_eq!(writer.join().unwrap().unwrap(), SecretsBackend::File);
        release_tx.send(()).unwrap();

        let error = configure.join().unwrap().unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("Developer key changed before verified readback"));
        assert!(!error.contains("omi_dev_configure"));
        assert!(!error.contains("omi_dev_concurrent"));
        assert!(!reload_called.load(Ordering::SeqCst));

        let pair =
            crate::config::load_runtime_config_pair_from_path(&home.path().join("freedom.yaml"))
                .unwrap();
        assert_eq!(
            pair.credentials
                .omi_developer_api_key
                .as_ref()
                .unwrap()
                .expose(),
            "omi_dev_concurrent"
        );
        assert_eq!(
            pair.credentials.omi_ingest_token.as_ref().unwrap().expose(),
            "0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn confirmation_is_fail_closed() {
        assert!(require_confirmation(false, "OMI purge").is_err());
        assert!(require_confirmation(true, "OMI purge").is_ok());
    }

    #[test]
    fn every_ingest_mode_has_a_stable_operator_name() {
        assert_eq!(mode_name(OmiIngestMode::DeveloperApi), "developer_api");
        assert_eq!(mode_name(OmiIngestMode::NativeIngest), "native_ingest");
        assert_eq!(mode_name(OmiIngestMode::Both), "both");
        assert_eq!(mode_name(OmiIngestMode::LegacyMemories), "legacy_memories");
    }

    #[test]
    fn status_does_not_create_a_missing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.db");

        assert_eq!(read_status(&path).unwrap(), None);
        assert!(!path.exists());
    }

    #[test]
    fn effective_runtime_health_rejects_stale_or_missing_daemon_state() {
        let mut status = crate::memory::omi::OmiStatus {
            runtime_state: Some("healthy".to_string()),
            runtime_pid: Some(42),
            ..Default::default()
        };
        assert_eq!(
            effective_omi_runtime_state(false, &status, None),
            "disabled"
        );
        assert_eq!(effective_omi_runtime_state(true, &status, None), "inactive");
        assert_eq!(
            effective_omi_runtime_state(true, &status, Some(41)),
            "unknown"
        );
        assert_eq!(
            effective_omi_runtime_state(true, &status, Some(42)),
            "healthy"
        );
        status.runtime_state = Some("failed".to_string());
        assert_eq!(
            effective_omi_runtime_state(true, &status, Some(42)),
            "failed"
        );
    }

    #[test]
    fn native_mutation_uses_the_explicit_home_pidfile() {
        let custom_home = tempfile::tempdir().unwrap();
        let custom_pidfile = native_daemon_pidfile(custom_home.path());
        assert_eq!(custom_pidfile, custom_home.path().join("neothd.pid"));
        assert_ne!(
            custom_pidfile,
            crate::daemon::pidfile::default_pidfile(),
            "--home must never fall back to the default daemon lock"
        );

        // Daemon liveness is a HELD advisory lock on the pidfile, not a live
        // pid written into it — a stale pidfile from a crashed daemon must not
        // block anything. Simulating a running daemon therefore means holding
        // the lock, exactly as the daemon does.
        let guard = crate::daemon::pidfile::acquire(&custom_pidfile)
            .expect("hold the custom-home daemon lock");
        assert!(
            native_mutation_requires_stopped_daemon(custom_home.path(), "native:call-1").is_err(),
            "a daemon holding the lock in the custom home must block native mutation"
        );
        drop(guard);
        assert!(
            native_mutation_requires_stopped_daemon(custom_home.path(), "developer-call-1").is_ok(),
            "non-native sources do not own a local recovery receipt"
        );
    }

    #[test]
    fn operator_audit_hashes_external_identifiers_and_documents_contract() {
        let payload = operator_audit_payload(
            "operator_intent",
            "allow_reimport",
            OperatorAuditContract::FailClosedBeforeMutation,
            Some("native:private-call"),
            Some("review contains private details"),
            None,
        )
        .unwrap();
        let payload = String::from_utf8(payload).unwrap();
        assert!(payload.contains("fail_closed_before_mutation"));
        assert!(payload.contains("conversation_hash"));
        assert!(payload.contains("review_note_hash"));
        assert!(!payload.contains("private-call"));
        assert!(!payload.contains("review contains private details"));
    }

    #[tokio::test]
    async fn operator_audit_uses_a_dedicated_durable_wal_segment() {
        let home = tempfile::tempdir().unwrap();
        let audit = OperatorAudit::start(home.path()).unwrap();
        audit
            .emit(
                "operator_intent",
                "resume",
                OperatorAuditContract::FailClosedBeforeMutation,
                None,
                Some("reviewed"),
                None,
            )
            .await
            .unwrap();
        audit.finish().await.unwrap();

        let segments: Vec<_> = std::fs::read_dir(home.path().join("wal"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("wal"))
            .collect();
        assert_eq!(segments.len(), 1);
        let segment_name = segments[0].file_name().unwrap();
        assert!(crate::wal::scan::canonical_segment_name(segment_name));
        assert!(segment_name.to_string_lossy().contains("-omi-operator-"));
        let bytes = std::fs::read(&segments[0]).unwrap();
        let segment_header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let frame = crate::wal::frame::decode_frame(&bytes[segment_header.header_len()..]).unwrap();
        assert_eq!(frame.header.event_type, EVENT_TYPE_EXTENDED);
        assert_eq!(
            frame.header.event_subtype,
            ExtendedSubtype::OmiLifecycleAudit as u8
        );
        assert!(home.path().join("wal").join("hmac.key").exists());
    }
}
