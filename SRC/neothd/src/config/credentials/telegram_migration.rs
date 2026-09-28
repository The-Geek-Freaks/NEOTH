//! Durable, file-backed custody for one OpenClaw Telegram migration.
//!
//! This is deliberately a narrow participant, rather than a generic migration
//! framework.  It owns the exact raw config/credential pair which the normal
//! Telegram writer would publish, and can therefore resume or reverse only that
//! immutable generation.  The coordinator owns source-set inspection, the
//! asynchronous `getMe` probe, operation phase, and reload requests.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

use super::{
    Credentials, FileSnapshot, JournalFileSnapshot,
    PreparedTelegramAccountUpsert, publish_prepared_file_pair, sibling_credentials_path,
    transaction_directory, validate_exact_pair_target, with_config_writer_guard,
    with_dual_file_transaction_lock, with_legacy_pair_locks,
};
use crate::channels::registry::ChannelAccountId;
use crate::secret::SecretString;

const CUSTODY_VERSION: u8 = 1;
const CUSTODY_PREFIX: &str = ".openclaw-telegram-migration-";
const CUSTODY_SUFFIX: &str = ".custody.yaml";

/// Opaque candidate which contains the selected Telegram secrets until it is
/// turned into durable custody.  It has no Debug implementation by design.
pub(crate) struct PreparedTelegramMigration {
    prepared: PreparedTelegramAccountUpsert,
    operation_id: String,
    request_commitment: String,
}

/// Private custody handle.  Its on-disk representation contains raw file
/// snapshots and must never be copied to status JSON or diagnostic output.
pub(crate) struct TelegramMigrationCustody {
    path: PathBuf,
    freedom_path: PathBuf,
    credentials_path: PathBuf,
    record: TelegramMigrationCustodyRecord,
}

/// Optional custody lookup. Only the exact derived capability path being
/// absent is `Absent`; malformed, unreadable or substituted files are errors.
pub(crate) enum TelegramMigrationCustodyLoad {
    Absent,
    Present(Box<TelegramMigrationCustody>),
}

/// Observable raw-pair state, deliberately independent of the coordinator's
/// phase.  `Mixed` always requires a hold; it is never a recovery direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TelegramMigrationState {
    Before,
    After,
    Mixed,
}

/// Opaque successful commit information suitable for a private coordinator
/// receipt.  It contains commitments only, never pair bytes or tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TelegramMigrationCommit {
    pub(crate) before_sha256: String,
    pub(crate) after_sha256: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TelegramMigrationCustodyRecord {
    version: u8,
    operation_id: String,
    request_commitment: String,
    account_id: String,
    allowed_user_id: u64,
    freedom_file: String,
    credentials_file: String,
    freedom_before: JournalFileSnapshot,
    credentials_before: JournalFileSnapshot,
    freedom_after: JournalFileSnapshot,
    credentials_after: JournalFileSnapshot,
    before_sha256: String,
    after_sha256: String,
}

impl Credentials {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_telegram_migration_upsert_at(
        freedom_path: &Path, credentials_path: &Path, account_id: ChannelAccountId,
        allowed_user_id: u64, token: SecretString, operation_id: &str, request_commitment: &str,
    ) -> Result<PreparedTelegramMigration> {
        validate_operation_binding(operation_id, request_commitment)?;
        super::with_coherent_pair_transaction_at(freedom_path, || {
            let config = crate::config::FreedomConfig::load_public_from_path_unlocked(freedom_path)?;
            anyhow::ensure!(config.secrets_backend != crate::config::SecretsBackend::Keychain, "Telegram OpenClaw migration requires a file-backed secrets backend");
            let prepared = Self::prepare_telegram_account_upsert_at(freedom_path, credentials_path, account_id, allowed_user_id, token)?;
            Ok(PreparedTelegramMigration { prepared, operation_id: operation_id.to_owned(), request_commitment: request_commitment.to_owned() })
        })
    }
}
impl PreparedTelegramMigration {
    pub(crate) fn candidate_pair(&self) -> &crate::config::RuntimeConfigPair { self.prepared.candidate_pair() }
    pub(crate) fn account_id(&self) -> &ChannelAccountId { self.prepared.account_id() }
    pub(crate) fn persist_telegram_migration_custody_at(self) -> Result<TelegramMigrationCustody> { TelegramMigrationCustody::persist(self.prepared, self.operation_id, self.request_commitment) }
}
impl TelegramMigrationCustody {
    fn persist(prepared: PreparedTelegramAccountUpsert, operation_id: String, request_commitment: String) -> Result<Self> {
        validate_operation_binding(&operation_id, &request_commitment)?;
        let directory = transaction_directory(&prepared.freedom_path);
        anyhow::ensure!(
            directory == transaction_directory(&prepared.credentials_path),
            "Telegram migration pair paths are not siblings"
        );
        let path = custody_path(&prepared.freedom_path, &operation_id)?;
        with_dual_file_transaction_lock(&prepared.freedom_path, || {
            with_config_writer_guard(&prepared.freedom_path, || {
                with_legacy_pair_locks(&prepared.freedom_path, &prepared.credentials_path, || {
                    validate_pair_targets(&prepared.freedom_path, &prepared.credentials_path)?;
                    let actual_freedom = FileSnapshot::capture(&prepared.freedom_path)?;
                    let actual_credentials = FileSnapshot::capture(&prepared.credentials_path)?;
                    anyhow::ensure!(
                        actual_freedom.same_as(&prepared.freedom_before)
                            && actual_credentials.same_as(&prepared.credentials_before),
                        "Telegram migration pair changed before custody could be persisted"
                    );
                    let before_sha256 =
                        pair_commitment(&prepared.freedom_before, &prepared.credentials_before);
                    let after_sha256 =
                        pair_commitment(&prepared.freedom_after, &prepared.credentials_after);
                    let record = TelegramMigrationCustodyRecord {
                        version: CUSTODY_VERSION,
                        operation_id,
                        request_commitment,
                        account_id: prepared.account_id.to_string(),
                        allowed_user_id: prepared.candidate.config.channel_accounts.telegram.get(&prepared.account_id).context("prepared Telegram policy is missing")?.allowed_user_id,
                        freedom_file: transaction_file_name_exact(
                            &prepared.freedom_path,
                            "freedom.yaml",
                        )?,
                        credentials_file: transaction_file_name_exact(
                            &prepared.credentials_path,
                            "credentials.yaml",
                        )?,
                        freedom_before: JournalFileSnapshot::from_file_snapshot(
                            &prepared.freedom_before,
                        ),
                        credentials_before: JournalFileSnapshot::from_file_snapshot(
                            &prepared.credentials_before,
                        ),
                        freedom_after: JournalFileSnapshot::from_file_snapshot(
                            &prepared.freedom_after,
                        ),
                        credentials_after: JournalFileSnapshot::from_file_snapshot(
                            &prepared.credentials_after,
                        ),
                        before_sha256,
                        after_sha256,
                    };
                    persist_record_create_new(&path, &record)?;
                    Ok(Self {
                        path,
                        freedom_path: prepared.freedom_path.clone(),
                        credentials_path: prepared.credentials_path.clone(),
                        record,
                    })
                })
            })
        })
    }

    /// Load immutable private custody and verify its operation binding before
    /// examining raw snapshots.  This rejects replacement sidecars, malformed
    /// schema/checksums and any path other than the expected sibling leaf.
    pub(crate) fn load_at(
        freedom_path: &Path,
        operation_id: &str,
        request_commitment: &str,
    ) -> Result<Self> {
        validate_operation_binding(operation_id, request_commitment)?;
        validate_freedom_path(freedom_path)?;
        let credentials_path = sibling_credentials_path(freedom_path);
        validate_exact_pair_target(&credentials_path, "Telegram migration credentials")?;
        let path = custody_path(freedom_path, operation_id)?;
        validate_exact_pair_target(&path, "Telegram migration custody")?;
        let body = read_custody_bounded(&path)?
            .with_context(|| format!("Telegram migration custody {} is missing", path.display()))?;
        let record: TelegramMigrationCustodyRecord = serde_yaml::from_slice(&body)
            .with_context(|| format!("parse Telegram migration custody {}", path.display()))?;
        validate_record(&record, operation_id, request_commitment)?;
        validate_record_paths(&record, freedom_path, &credentials_path)?;
        Ok(Self {
            path,
            freedom_path: freedom_path.to_path_buf(),
            credentials_path,
            record,
        })
    }

    pub(crate) fn load_optional_at(
        freedom_path: &Path,
        operation_id: &str,
        request_commitment: &str,
    ) -> Result<TelegramMigrationCustodyLoad> {
        validate_operation_binding(operation_id, request_commitment)?;
        validate_freedom_path(freedom_path)?;
        let path = custody_path(freedom_path, operation_id)?;
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(TelegramMigrationCustodyLoad::Absent)
            }
            Err(error) => Err(error)
                .with_context(|| format!("inspect Telegram migration custody {}", path.display())),
            Ok(_) => Self::load_at(freedom_path, operation_id, request_commitment)
                .map(Box::new)
                .map(TelegramMigrationCustodyLoad::Present),
        }
    }

    pub(crate) fn before_sha256(&self) -> &str {
        &self.record.before_sha256
    }
    pub(crate) fn after_sha256(&self) -> &str {
        &self.record.after_sha256
    }
    pub(crate) fn allowed_user_id(&self) -> u64 { self.record.allowed_user_id }
    pub(crate) fn account_id(&self) -> &str {
        &self.record.account_id
    }
    /// Stable public identifier for the immutable private custody record.
    pub(crate) fn custody_sha256(&self) -> String {
        custody_digest(&self.record)
    }

    /// Classify the full raw pair under the normal writer authority.  A mixed
    /// member state is intentionally returned as `Mixed`, never repaired.
    pub(crate) fn inspect_at(
        &self,
        freedom_path: &Path,
        credentials_path: &Path,
        operation_id: &str,
        request_commitment: &str,
    ) -> Result<TelegramMigrationState> {
        self.require_binding(operation_id, request_commitment)?;
        self.require_paths(freedom_path, credentials_path)?;
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    self.ensure_persisted_unchanged()?;
                    classify_pair(freedom_path, credentials_path, &self.record)
                })
            })
        })
    }

    /// Publish the immutable stored postimage only while the exact raw
    /// preimage remains current.  It never renders credentials/incarnations a
    /// second time and never requests reload.
    pub(crate) fn commit_if_before_at(
        &self,
        freedom_path: &Path,
        credentials_path: &Path,
        operation_id: &str,
        request_commitment: &str,
    ) -> Result<TelegramMigrationCommit> {
        self.commit_if_before_at_using_fault(
            freedom_path,
            credentials_path,
            operation_id,
            request_commitment,
            |_| Ok(()),
        )
    }

    fn commit_if_before_at_using_fault<F>(
        &self,
        freedom_path: &Path,
        credentials_path: &Path,
        operation_id: &str,
        request_commitment: &str,
        fault: F,
    ) -> Result<TelegramMigrationCommit>
    where
        F: FnMut(super::DualFileFaultPoint) -> Result<()>,
    {
        self.require_binding(operation_id, request_commitment)?;
        self.require_paths(freedom_path, credentials_path)?;
        let (before_freedom, before_credentials, after_freedom, after_credentials) =
            self.snapshots()?;
        let directory = transaction_directory(freedom_path);
        anyhow::ensure!(
            directory == transaction_directory(credentials_path),
            "Telegram migration pair paths are not siblings"
        );
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    self.ensure_persisted_unchanged()?;
                    match classify_snapshots(
                        freedom_path,
                        credentials_path,
                        &before_freedom,
                        &before_credentials,
                        &after_freedom,
                        &after_credentials,
                    )? {
                        TelegramMigrationState::After => Ok(TelegramMigrationCommit {
                            before_sha256: self.record.before_sha256.clone(),
                            after_sha256: self.record.after_sha256.clone(),
                        }),
                        TelegramMigrationState::Mixed => anyhow::bail!(
                            "Telegram migration pair is neither its immutable before nor after generation; operation is held"
                        ),
                        TelegramMigrationState::Before => publish_prepared_file_pair(
                            freedom_path,
                            credentials_path,
                            &directory,
                            &before_freedom,
                            &after_freedom,
                            &before_credentials,
                            &after_credentials,
                            TelegramMigrationCommit {
                                before_sha256: self.record.before_sha256.clone(),
                                after_sha256: self.record.after_sha256.clone(),
                            },
                            Some(|path: &Path, body: &[u8]| {
                                crate::util::atomic_write::atomic_write_private(path, body)
                                    .with_context(|| format!("atomically write {}", path.display()))
                            }),
                            fault,
                        ),
                    }
                })
            })
        })
    }

    #[cfg(test)]
    pub(crate) fn commit_if_before_at_using_test_fault<F>(
        &self,
        freedom_path: &Path,
        credentials_path: &Path,
        operation_id: &str,
        request_commitment: &str,
        fault: F,
    ) -> Result<TelegramMigrationCommit>
    where
        F: FnMut(super::DualFileFaultPoint) -> Result<()>,
    {
        self.commit_if_before_at_using_fault(
            freedom_path,
            credentials_path,
            operation_id,
            request_commitment,
            fault,
        )
    }

    /// Reverse only the immutable postimage, using the same dual-file journal
    /// as forward publication.  The caller records its reverse direction
    /// before calling this; `Before` is not treated as proof that a reverse
    /// write happened.
    pub(crate) fn rollback_if_exact_at(
        &self,
        freedom_path: &Path,
        credentials_path: &Path,
        operation_id: &str,
        request_commitment: &str,
    ) -> Result<TelegramMigrationState> {
        self.rollback_if_exact_at_using_fault(
            freedom_path,
            credentials_path,
            operation_id,
            request_commitment,
            |_| Ok(()),
        )
    }

    fn rollback_if_exact_at_using_fault<F>(
        &self,
        freedom_path: &Path,
        credentials_path: &Path,
        operation_id: &str,
        request_commitment: &str,
        fault: F,
    ) -> Result<TelegramMigrationState>
    where
        F: FnMut(super::DualFileFaultPoint) -> Result<()>,
    {
        self.require_binding(operation_id, request_commitment)?;
        self.require_paths(freedom_path, credentials_path)?;
        let (before_freedom, before_credentials, after_freedom, after_credentials) =
            self.snapshots()?;
        let directory = transaction_directory(freedom_path);
        with_dual_file_transaction_lock(freedom_path, || {
            with_config_writer_guard(freedom_path, || {
                with_legacy_pair_locks(freedom_path, credentials_path, || {
                    self.ensure_persisted_unchanged()?;
                    match classify_snapshots(
                        freedom_path,
                        credentials_path,
                        &before_freedom,
                        &before_credentials,
                        &after_freedom,
                        &after_credentials,
                    )? {
                        TelegramMigrationState::Before => Ok(TelegramMigrationState::Before),
                        TelegramMigrationState::Mixed => anyhow::bail!(
                            "Telegram migration pair drifted from its immutable postimage; rollback is held"
                        ),
                        TelegramMigrationState::After => publish_prepared_file_pair(
                            freedom_path,
                            credentials_path,
                            &directory,
                            &after_freedom,
                            &before_freedom,
                            &after_credentials,
                            &before_credentials,
                            TelegramMigrationState::Before,
                            Some(|path: &Path, body: &[u8]| {
                                crate::util::atomic_write::atomic_write_private(path, body)
                                    .with_context(|| format!("atomically write {}", path.display()))
                            }),
                            fault,
                        ),
                    }
                })
            })
        })
    }

    #[cfg(test)]
    pub(crate) fn rollback_if_exact_at_using_test_fault<F>(
        &self,
        freedom_path: &Path,
        credentials_path: &Path,
        operation_id: &str,
        request_commitment: &str,
        fault: F,
    ) -> Result<TelegramMigrationState>
    where
        F: FnMut(super::DualFileFaultPoint) -> Result<()>,
    {
        self.rollback_if_exact_at_using_fault(
            freedom_path,
            credentials_path,
            operation_id,
            request_commitment,
            fault,
        )
    }

    fn require_binding(&self, operation_id: &str, request_commitment: &str) -> Result<()> {
        validate_record(&self.record, operation_id, request_commitment)
    }

    fn require_paths(&self, freedom_path: &Path, credentials_path: &Path) -> Result<()> {
        anyhow::ensure!(
            freedom_path == self.freedom_path && credentials_path == self.credentials_path,
            "Telegram migration custody is bound to a different configuration home"
        );
        validate_record_paths(&self.record, freedom_path, credentials_path)
    }

    /// A handle is not authority to ignore later sidecar replacement.  Re-read
    /// the no-follow private leaf before every observation or write and demand
    /// byte-for-byte decoded-record equality with the custody that was loaded.
    fn ensure_persisted_unchanged(&self) -> Result<()> {
        validate_exact_pair_target(&self.path, "Telegram migration custody")?;
        let body = read_custody_bounded(&self.path)?.with_context(|| {
            format!(
                "Telegram migration custody {} disappeared",
                self.path.display()
            )
        })?;
        let observed: TelegramMigrationCustodyRecord = serde_yaml::from_slice(&body)
            .with_context(|| format!("parse Telegram migration custody {}", self.path.display()))?;
        validate_record(
            &observed,
            &self.record.operation_id,
            &self.record.request_commitment,
        )?;
        validate_record_paths(&observed, &self.freedom_path, &self.credentials_path)?;
        anyhow::ensure!(
            observed == self.record,
            "Telegram migration custody changed after it was loaded; operation is held"
        );
        Ok(())
    }

    fn snapshots(&self) -> Result<(FileSnapshot, FileSnapshot, FileSnapshot, FileSnapshot)> {
        Ok((
            self.record
                .freedom_before
                .decode("Telegram migration freedom_before")?,
            self.record
                .credentials_before
                .decode("Telegram migration credentials_before")?,
            self.record
                .freedom_after
                .decode("Telegram migration freedom_after")?,
            self.record
                .credentials_after
                .decode("Telegram migration credentials_after")?,
        ))
    }
}

fn classify_pair(
    freedom: &Path,
    credentials: &Path,
    record: &TelegramMigrationCustodyRecord,
) -> Result<TelegramMigrationState> {
    let (before_freedom, before_credentials, after_freedom, after_credentials) = (
        record
            .freedom_before
            .decode("Telegram migration freedom_before")?,
        record
            .credentials_before
            .decode("Telegram migration credentials_before")?,
        record
            .freedom_after
            .decode("Telegram migration freedom_after")?,
        record
            .credentials_after
            .decode("Telegram migration credentials_after")?,
    );
    classify_snapshots(
        freedom,
        credentials,
        &before_freedom,
        &before_credentials,
        &after_freedom,
        &after_credentials,
    )
}

fn classify_snapshots(
    freedom_path: &Path,
    credentials_path: &Path,
    freedom_before: &FileSnapshot,
    credentials_before: &FileSnapshot,
    freedom_after: &FileSnapshot,
    credentials_after: &FileSnapshot,
) -> Result<TelegramMigrationState> {
    validate_pair_targets(freedom_path, credentials_path)?;
    let freedom = FileSnapshot::capture(freedom_path)?;
    let credentials = FileSnapshot::capture(credentials_path)?;
    if freedom.same_as(freedom_before) && credentials.same_as(credentials_before) {
        Ok(TelegramMigrationState::Before)
    } else if freedom.same_as(freedom_after) && credentials.same_as(credentials_after) {
        Ok(TelegramMigrationState::After)
    } else {
        Ok(TelegramMigrationState::Mixed)
    }
}

fn validate_pair_targets(freedom_path: &Path, credentials_path: &Path) -> Result<()> {
    validate_freedom_path(freedom_path)?;
    validate_exact_pair_target(credentials_path, "Telegram migration credentials")
}

fn validate_freedom_path(freedom_path: &Path) -> Result<()> {
    anyhow::ensure!(
        freedom_path
            .file_name()
            .is_some_and(|name| name == "freedom.yaml"),
        "Telegram migration custody requires the canonical freedom.yaml target"
    );
    validate_exact_pair_target(freedom_path, "Telegram migration freedom config")
}

fn transaction_file_name_exact(path: &Path, expected: &str) -> Result<String> {
    anyhow::ensure!(
        path.file_name().is_some_and(|name| name == expected),
        "Telegram migration custody requires canonical {expected} target"
    );
    Ok(expected.to_owned())
}

fn validate_record_paths(
    record: &TelegramMigrationCustodyRecord,
    freedom_path: &Path,
    credentials_path: &Path,
) -> Result<()> {
    validate_freedom_path(freedom_path)?;
    anyhow::ensure!(
        credentials_path == sibling_credentials_path(freedom_path),
        "Telegram migration custody credentials target is not the original freedom.yaml sibling"
    );
    anyhow::ensure!(
        record.freedom_file == "freedom.yaml" && record.credentials_file == "credentials.yaml",
        "Telegram migration custody targets are not canonical pair filenames"
    );
    validate_exact_pair_target(credentials_path, "Telegram migration credentials")
}

fn custody_path(freedom_path: &Path, operation_id: &str) -> Result<PathBuf> {
    let parsed = uuid::Uuid::parse_str(operation_id)
        .context("Telegram migration operation id must be a UUID")?;
    anyhow::ensure!(
        parsed.hyphenated().to_string() == operation_id,
        "Telegram migration operation id must be canonical lowercase hyphenated UUID"
    );
    Ok(transaction_directory(freedom_path)
        .join(format!("{CUSTODY_PREFIX}{operation_id}{CUSTODY_SUFFIX}")))
}

fn validate_operation_binding(operation_id: &str, request_commitment: &str) -> Result<()> {
    let _ = custody_path(Path::new("."), operation_id)?;
    anyhow::ensure!(
        request_commitment.len() == 64
            && request_commitment
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "Telegram migration request commitment must be lowercase SHA-256 hex"
    );
    Ok(())
}

fn validate_record(
    record: &TelegramMigrationCustodyRecord,
    operation_id: &str,
    request_commitment: &str,
) -> Result<()> {
    anyhow::ensure!(
        record.version == CUSTODY_VERSION,
        "unsupported Telegram migration custody version"
    );
    validate_operation_binding(&record.operation_id, &record.request_commitment)?;
    anyhow::ensure!(
        record.operation_id == operation_id && record.request_commitment == request_commitment,
        "Telegram migration custody binding does not match this operation/request"
    );
    let account = ChannelAccountId::new(record.account_id.clone())
        .context("invalid Telegram migration custody account id")?;
    anyhow::ensure!(
        account.to_string() == record.account_id,
        "noncanonical Telegram migration custody account id"
    );
    anyhow::ensure!(record.allowed_user_id != 0, "Telegram migration custody allowed user id is zero");
    let (before_freedom, before_credentials, after_freedom, after_credentials) = (
        record
            .freedom_before
            .decode("Telegram migration freedom_before")?,
        record
            .credentials_before
            .decode("Telegram migration credentials_before")?,
        record
            .freedom_after
            .decode("Telegram migration freedom_after")?,
        record
            .credentials_after
            .decode("Telegram migration credentials_after")?,
    );
    anyhow::ensure!(
        record.before_sha256 == pair_commitment(&before_freedom, &before_credentials)
            && record.after_sha256 == pair_commitment(&after_freedom, &after_credentials),
        "Telegram migration custody pair commitment mismatch"
    );
    Ok(())
}

fn persist_record_create_new(path: &Path, record: &TelegramMigrationCustodyRecord) -> Result<()> {
    let mut body = zeroize::Zeroizing::new(
        serde_yaml::to_string(record).context("serialize private Telegram migration custody")?,
    );
    anyhow::ensure!(
        body.len() as u64 <= super::MAX_DUAL_FILE_JOURNAL_BYTES,
        "Telegram migration custody exceeds the private recovery limit"
    );
    let result = crate::util::atomic_write::write_private_create_new_durable(path, body.as_bytes())
        .with_context(|| format!("create private Telegram migration custody {}", path.display()));
    body.zeroize();
    result
}

fn custody_digest(record: &TelegramMigrationCustodyRecord) -> String {
    let mut body = zeroize::Zeroizing::new(
        serde_yaml::to_string(record)
            .expect("Telegram migration custody serialization was validated before persistence"),
    );
    let mut digest = Sha256::new();
    digest.update(b"neoth-openclaw-telegram-migration-custody-v1\0");
    digest.update(body.as_bytes());
    let digest = format!("{:x}", digest.finalize());
    body.zeroize();
    digest
}

/// Read custody through a bound parent and a bounded no-follow regular-child
/// handle.  Permission checks remain explicit because custody carries raw
/// credential snapshots, while the opened child protects the read itself from
/// a leaf symlink/junction replacement.
fn read_custody_bounded(path: &Path) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("Telegram migration custody path has no parent")?;
    let parent = if parent == Path::new(".") {
        std::path::absolute(parent).context("resolve relative Telegram migration custody parent")?
    } else {
        parent.to_path_buf()
    };
    let name = path
        .file_name()
        .context("Telegram migration custody path has no file name")?;
    let bound = crate::skills::store::open_bound_directory(
        &parent,
        false,
        "Telegram migration custody parent",
    )?
    .with_context(|| {
        format!(
            "Telegram migration custody parent {} is absent",
            parent.display()
        )
    })?;
    match bound.dir.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("inspect Telegram migration custody {}", path.display())),
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file(),
                "Telegram migration custody {} is not a regular file",
                path.display()
            );
            #[cfg(unix)]
            {
                use cap_std::fs::PermissionsExt as _;
                anyhow::ensure!(
                    metadata.permissions().mode() & 0o077 == 0,
                    "Telegram migration custody {} is readable outside its owner",
                    path.display()
                );
            }
            #[cfg(windows)]
            crate::wal::win_native::verify_private_dacl(path).with_context(|| {
                format!(
                    "verify private Telegram migration custody DACL {}",
                    path.display()
                )
            })?;
            let bytes = crate::skills::store::read_regular_file_bounded(
                &bound.dir,
                name,
                &bound.physical_display_path.join(name),
                super::MAX_DUAL_FILE_JOURNAL_BYTES as usize,
            )
            .with_context(|| {
                format!(
                    "read bounded no-follow Telegram migration custody {}",
                    path.display()
                )
            })?;
            Ok(Some(zeroize::Zeroizing::new(bytes)))
        }
    }
}

fn pair_commitment(freedom: &FileSnapshot, credentials: &FileSnapshot) -> String {
    let mut hash = Sha256::new();
    hash.update(b"neoth-openclaw-telegram-migration-pair-v1\0");
    for (name, snapshot) in [("freedom.yaml", freedom), ("credentials.yaml", credentials)] {
        hash.update(name.as_bytes());
        hash.update([0]);
        match snapshot {
            FileSnapshot::Present(bytes) => {
                hash.update([1]);
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes.as_slice());
            }
            FileSnapshot::Missing => hash.update([0]),
        }
    }
    format!("{:x}", hash.finalize())
}

#[cfg(test)]
mod tests;
