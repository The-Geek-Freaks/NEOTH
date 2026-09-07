//! Managed lifecycle for one physical native code-map root.
//!
//! Inspection is deliberately read-only. Refresh is the only path that may
//! create/migrate a database, and corruption repair requires an explicit flag
//! so the original database remains available for forensic recovery.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::root_identity::CanonicalRepoRoot;
use super::snapshot::{
    RebuildOptions, rebuild_snapshot_delta_cancellable, stable_source_fingerprint,
};
use super::walker::ScanCancellation;

const MAX_LIFECYCLE_TEXT_BYTES: i64 = 64 * 1024;
const MAX_FAILURE_DIAGNOSTIC_BYTES: usize = 4 * 1024;
const REFRESH_LEASE_SUFFIX: &str = ".lifecycle-refresh-lease";
type LifecycleRootRow = (Option<String>, i64, i64, bool);

static LOCAL_REFRESH_LEASES: OnceLock<Mutex<BTreeMap<PathBuf, String>>> = OnceLock::new();

#[derive(Clone, Debug, Default)]
pub struct LifecycleCancellation {
    scan: ScanCancellation,
    cancelled: Arc<AtomicBool>,
}

impl LifecycleCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.scan.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleGeneration {
    pub root: String,
    pub root_identity_sha256: String,
    pub index_generation: i64,
    pub graph_generation: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeMapLifecycleState {
    Disabled,
    Absent,
    Unmapped,
    Incomplete {
        snapshot: LifecycleGeneration,
    },
    Fresh {
        snapshot: LifecycleGeneration,
    },
    Stale {
        snapshot: LifecycleGeneration,
    },
    Refreshing {
        attempt_id: String,
        owner_id: String,
        prior: Option<LifecycleGeneration>,
    },
    Recovering {
        attempt_id: String,
        prior: Option<LifecycleGeneration>,
    },
    Corrupt {
        diagnostic: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeMapLifecycleStatus {
    pub database_path: PathBuf,
    pub root: Option<String>,
    pub root_identity_sha256: Option<String>,
    pub state: CodeMapLifecycleState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshCause {
    ManualIfNeeded,
    ManualForce,
    FilesystemInvalidation,
    PeriodicReconciliation,
    StartupRecovery,
    ExplicitCorruptStoreRepair,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshOutcome {
    ReusedFresh,
    IndexedFirstTime,
    RefreshedStale,
    RebuiltForced,
    RecoveredPublishedAttempt,
    Cancelled,
    CommittedAfterCancellation,
    CorruptRepairRequired,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleRefreshOptions {
    pub force: bool,
    pub repair_corrupt: bool,
    pub cause: RefreshCause,
}

impl Default for LifecycleRefreshOptions {
    fn default() -> Self {
        Self {
            force: false,
            repair_corrupt: false,
            cause: RefreshCause::ManualIfNeeded,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeMapLifecycleReceipt {
    pub root: String,
    pub root_identity_sha256: String,
    pub database_path: PathBuf,
    pub cause: RefreshCause,
    pub outcome: RefreshOutcome,
    pub prior_generation: Option<LifecycleGeneration>,
    pub published_generation: Option<LifecycleGeneration>,
    pub source_fingerprint_sha256: Option<String>,
    pub journal_attempt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_diagnostic: Option<String>,
}

/// Inspect one root without creating a database, running migrations, or
/// repairing corrupt evidence. A root that cannot be canonicalized is unmapped.
pub fn inspect(database_path: &Path, root: &Path) -> CodeMapLifecycleStatus {
    let root = match CanonicalRepoRoot::discover(root) {
        Ok(root) => root,
        Err(_) => {
            return CodeMapLifecycleStatus {
                database_path: database_path.to_path_buf(),
                root: None,
                root_identity_sha256: None,
                state: CodeMapLifecycleState::Unmapped,
            };
        }
    };
    let root_identity_sha256 = root_identity_sha256(&root);
    if let Err(error) = super::lifecycle_repair::inspection_error(database_path) {
        return status(&root, database_path, corrupt(error));
    }
    if !database_path.exists() {
        return status(&root, database_path, CodeMapLifecycleState::Absent);
    }
    let connection = match super::persist::open_read_only(database_path) {
        Ok(connection) => connection,
        Err(error) => return status(&root, database_path, corrupt(error)),
    };
    let row: Result<Option<LifecycleRootRow>> = connection
        .query_row(
            "SELECT root_identity, index_generation, graph_generation, \
                    oversize_skipped = 0 AND truncated_at IS NULL \
             FROM code_map_roots WHERE root = ?1 \
               AND (root_identity IS NULL OR length(CAST(root_identity AS BLOB)) <= ?2)",
            rusqlite::params![root.display(), MAX_LIFECYCLE_TEXT_BYTES],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .context("read code-map lifecycle root status");
    let row = match row {
        Ok(row) => row,
        Err(error) => return status(&root, database_path, corrupt(error)),
    };
    let Some((stored_identity, index, graph, complete)) = row else {
        let oversized: bool = match connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM code_map_roots WHERE root = ?1 \
                AND root_identity IS NOT NULL \
                AND length(CAST(root_identity AS BLOB)) > ?2)",
            rusqlite::params![root.display(), MAX_LIFECYCLE_TEXT_BYTES],
            |row| row.get(0),
        ) {
            Ok(value) => value,
            Err(error) => return status(&root, database_path, corrupt(error)),
        };
        if oversized {
            return status(
                &root,
                database_path,
                corrupt("stored root identity exceeds lifecycle read bound"),
            );
        }
        match journal_phase(&connection, root.identity().as_str()) {
            Ok(Some((attempt_id, phase, journal_owner))) if phase == "running" => {
                let state = match refresh_lease_owner(database_path) {
                    Ok(Some(owner_id)) if journal_owner.as_deref() == Some(owner_id.as_str()) => {
                        CodeMapLifecycleState::Refreshing {
                            attempt_id,
                            owner_id,
                            prior: None,
                        }
                    }
                    Ok(Some(_)) => {
                        return status(
                            &root,
                            database_path,
                            corrupt("lifecycle lease owner does not match running journal attempt"),
                        );
                    }
                    Ok(None) => CodeMapLifecycleState::Recovering {
                        attempt_id,
                        prior: None,
                    },
                    Err(error) => return status(&root, database_path, corrupt(error)),
                };
                return status(&root, database_path, state);
            }
            Err(error) => return status(&root, database_path, corrupt(error)),
            _ => {}
        }
        return status(&root, database_path, CodeMapLifecycleState::Unmapped);
    };
    if stored_identity.as_deref() != Some(root.identity().as_str()) {
        return status(&root, database_path, CodeMapLifecycleState::Unmapped);
    }
    let snapshot = LifecycleGeneration {
        root: root.display().to_owned(),
        root_identity_sha256,
        index_generation: index,
        graph_generation: graph,
    };
    if !complete || index <= 0 || index != graph {
        return status(
            &root,
            database_path,
            CodeMapLifecycleState::Incomplete { snapshot },
        );
    }
    match journal_phase(&connection, root.identity().as_str()) {
        Ok(Some((attempt_id, phase, journal_owner))) if phase == "running" => {
            let state = match refresh_lease_owner(database_path) {
                Ok(Some(owner_id)) if journal_owner.as_deref() == Some(owner_id.as_str()) => {
                    CodeMapLifecycleState::Refreshing {
                        attempt_id,
                        owner_id,
                        prior: Some(snapshot),
                    }
                }
                Ok(Some(_)) => {
                    return status(
                        &root,
                        database_path,
                        corrupt("lifecycle lease owner does not match running journal attempt"),
                    );
                }
                Ok(None) => CodeMapLifecycleState::Recovering {
                    attempt_id,
                    prior: Some(snapshot),
                },
                Err(error) => return status(&root, database_path, corrupt(error)),
            };
            return status(&root, database_path, state);
        }
        Err(error) => return status(&root, database_path, corrupt(error)),
        _ => {}
    }
    match super::persist::is_index_stale(&connection, root.display()) {
        Ok(true) => status(
            &root,
            database_path,
            CodeMapLifecycleState::Stale { snapshot },
        ),
        Ok(false) => status(
            &root,
            database_path,
            CodeMapLifecycleState::Fresh { snapshot },
        ),
        Err(error) => status(&root, database_path, corrupt(error)),
    }
}

/// Refresh exactly one canonical physical root. The previous generation stays
/// queryable until the atomic snapshot publisher commits. A cancellation before
/// that commit returns `Cancelled`; after commit it returns the committed
/// generation as `CommittedAfterCancellation`.
pub fn refresh(
    database_path: &Path,
    root_path: &Path,
    options: LifecycleRefreshOptions,
    cancellation: &LifecycleCancellation,
) -> Result<CodeMapLifecycleReceipt> {
    refresh_with_repair_checkpoint(database_path, root_path, options, cancellation, || {})
}

fn refresh_with_repair_checkpoint(
    database_path: &Path,
    root_path: &Path,
    options: LifecycleRefreshOptions,
    cancellation: &LifecycleCancellation,
    mut repair_checkpoint: impl FnMut(),
) -> Result<CodeMapLifecycleReceipt> {
    let root = CanonicalRepoRoot::discover(root_path)?;
    let inspected = inspect(database_path, root.path());
    let prior = state_snapshot(&inspected.state);
    if cancellation.is_cancelled() {
        return Ok(receipt(
            &root,
            database_path,
            options.cause,
            RefreshOutcome::Cancelled,
            prior,
            None,
            None,
            String::new(),
        ));
    }
    if matches!(&inspected.state, CodeMapLifecycleState::Corrupt { .. }) && !options.repair_corrupt
    {
        return Ok(receipt(
            &root,
            database_path,
            options.cause,
            RefreshOutcome::CorruptRepairRequired,
            prior,
            None,
            None,
            String::new(),
        ));
    }
    let lease = if matches!(&inspected.state, CodeMapLifecycleState::Fresh { .. }) && !options.force
    {
        None
    } else {
        Some(RefreshLease::acquire(database_path)?)
    };
    if matches!(&inspected.state, CodeMapLifecycleState::Corrupt { .. }) {
        if cancellation.is_cancelled() {
            return Ok(receipt(
                &root,
                database_path,
                options.cause,
                RefreshOutcome::Cancelled,
                prior,
                None,
                None,
                String::new(),
            ));
        }
        let repair_result = super::lifecycle_repair::preserve_explicitly(database_path, || {
            repair_checkpoint();
            anyhow::ensure!(
                !cancellation.is_cancelled(),
                "code-map lifecycle refresh cancelled"
            );
            Ok(())
        });
        if repair_result.is_err() && cancellation.is_cancelled() {
            return Ok(receipt(
                &root,
                database_path,
                options.cause,
                RefreshOutcome::Cancelled,
                prior,
                None,
                None,
                String::new(),
            ));
        }
        repair_result?;
    }
    if matches!(&inspected.state, CodeMapLifecycleState::Fresh { .. }) && !options.force {
        return Ok(receipt(
            &root,
            database_path,
            options.cause,
            RefreshOutcome::ReusedFresh,
            prior.clone(),
            prior,
            None,
            String::new(),
        ));
    }
    if let CodeMapLifecycleState::Recovering {
        attempt_id,
        prior: Some(published),
    } = &inspected.state
        && !options.force
    {
        if cancellation.is_cancelled() {
            return Ok(receipt(
                &root,
                database_path,
                options.cause,
                RefreshOutcome::Cancelled,
                prior,
                None,
                None,
                String::new(),
            ));
        }
        let connection = super::persist::open_read_only(database_path)?;
        if !super::persist::is_index_stale(&connection, root.display())? {
            let fingerprint = stable_source_fingerprint(&root, RebuildOptions::default())?;
            if cancellation.is_cancelled() {
                return Ok(receipt(
                    &root,
                    database_path,
                    options.cause,
                    RefreshOutcome::Cancelled,
                    prior,
                    None,
                    None,
                    String::new(),
                ));
            }
            let journal = super::persist::open(database_path)?;
            journal_claim_owner(
                &journal,
                &root,
                attempt_id,
                &lease.as_ref().unwrap().owner_id,
            )?;
            journal_finish(
                &journal,
                &root,
                attempt_id,
                &lease.as_ref().unwrap().owner_id,
                "recovered",
                Some(published),
                Some(&fingerprint),
            )?;
            return Ok(receipt(
                &root,
                database_path,
                options.cause,
                RefreshOutcome::RecoveredPublishedAttempt,
                prior,
                Some(published.clone()),
                Some(fingerprint),
                attempt_id.clone(),
            ));
        }
    }
    if let CodeMapLifecycleState::Recovering {
        attempt_id,
        prior: None,
    } = &inspected.state
    {
        if cancellation.is_cancelled() {
            return Ok(receipt(
                &root,
                database_path,
                options.cause,
                RefreshOutcome::Cancelled,
                prior,
                None,
                None,
                String::new(),
            ));
        }
        let journal = super::persist::open(database_path)?;
        journal_claim_owner(
            &journal,
            &root,
            attempt_id,
            &lease.as_ref().unwrap().owner_id,
        )?;
        journal_finish(
            &journal,
            &root,
            attempt_id,
            &lease.as_ref().unwrap().owner_id,
            "interrupted",
            None,
            None,
        )?;
    }
    if cancellation.is_cancelled() {
        return Ok(receipt(
            &root,
            database_path,
            options.cause,
            RefreshOutcome::Cancelled,
            prior,
            None,
            None,
            String::new(),
        ));
    }
    let attempt_id = uuid::Uuid::now_v7().to_string();
    let journal = super::persist::open(database_path)?;
    let _lease = lease;
    journal_start(
        &journal,
        &root,
        &attempt_id,
        &_lease
            .as_ref()
            .expect("mutating refresh must hold a lease")
            .owner_id,
        prior.as_ref(),
    )?;
    let snapshot = match rebuild_snapshot_delta_cancellable(
        &root,
        database_path,
        RebuildOptions::default(),
        &cancellation.scan,
    ) {
        Ok(snapshot) => snapshot,
        Err(_) if cancellation.is_cancelled() => {
            journal_finish(
                &journal,
                &root,
                &attempt_id,
                &_lease.as_ref().expect("active refresh lease").owner_id,
                "cancelled",
                None,
                None,
            )?;
            return Ok(receipt(
                &root,
                database_path,
                options.cause,
                RefreshOutcome::Cancelled,
                prior,
                None,
                None,
                attempt_id,
            ));
        }
        Err(error) => {
            journal_finish(
                &journal,
                &root,
                &attempt_id,
                &_lease.as_ref().expect("active refresh lease").owner_id,
                "failed",
                None,
                None,
            )?;
            let mut failed = receipt(
                &root,
                database_path,
                options.cause,
                RefreshOutcome::Failed,
                prior,
                None,
                None,
                attempt_id,
            );
            failed.failure_diagnostic = Some(bounded_diagnostic(
                &crate::security::redact::sanitize_tool_output(&format!(
                    "refresh native code-map lifecycle snapshot: {error:#}"
                )),
            ));
            return Ok(failed);
        }
    };
    let published = LifecycleGeneration {
        root: snapshot.root.display().to_owned(),
        root_identity_sha256: snapshot.root_identity_sha256,
        index_generation: snapshot.index_generation,
        graph_generation: snapshot.graph_generation,
    };
    journal_finish(
        &journal,
        &root,
        &attempt_id,
        &_lease.as_ref().expect("active refresh lease").owner_id,
        "committed",
        Some(&published),
        Some(&snapshot.source_fingerprint_sha256),
    )?;
    let outcome = if cancellation.is_cancelled() {
        RefreshOutcome::CommittedAfterCancellation
    } else if options.force {
        RefreshOutcome::RebuiltForced
    } else if prior.is_some() {
        RefreshOutcome::RefreshedStale
    } else {
        RefreshOutcome::IndexedFirstTime
    };
    Ok(receipt(
        &root,
        database_path,
        options.cause,
        outcome,
        prior,
        Some(published),
        Some(snapshot.source_fingerprint_sha256),
        attempt_id,
    ))
}

pub fn reconcile(
    database_path: &Path,
    root: &Path,
    cancellation: &LifecycleCancellation,
) -> Result<CodeMapLifecycleReceipt> {
    refresh(
        database_path,
        root,
        LifecycleRefreshOptions {
            cause: RefreshCause::StartupRecovery,
            ..LifecycleRefreshOptions::default()
        },
        cancellation,
    )
}

fn status(
    root: &CanonicalRepoRoot,
    database_path: &Path,
    state: CodeMapLifecycleState,
) -> CodeMapLifecycleStatus {
    CodeMapLifecycleStatus {
        database_path: database_path.to_path_buf(),
        root: Some(root.display().to_owned()),
        root_identity_sha256: Some(root_identity_sha256(root)),
        state,
    }
}

fn corrupt(error: impl std::fmt::Display) -> CodeMapLifecycleState {
    CodeMapLifecycleState::Corrupt {
        diagnostic: error.to_string(),
    }
}

fn state_snapshot(state: &CodeMapLifecycleState) -> Option<LifecycleGeneration> {
    match state {
        CodeMapLifecycleState::Incomplete { snapshot }
        | CodeMapLifecycleState::Fresh { snapshot }
        | CodeMapLifecycleState::Stale { snapshot } => Some(snapshot.clone()),
        CodeMapLifecycleState::Refreshing { prior, .. }
        | CodeMapLifecycleState::Recovering { prior, .. } => prior.clone(),
        _ => None,
    }
}

fn receipt(
    root: &CanonicalRepoRoot,
    database_path: &Path,
    cause: RefreshCause,
    outcome: RefreshOutcome,
    prior_generation: Option<LifecycleGeneration>,
    published_generation: Option<LifecycleGeneration>,
    source_fingerprint_sha256: Option<String>,
    journal_attempt_id: String,
) -> CodeMapLifecycleReceipt {
    CodeMapLifecycleReceipt {
        root: root.display().to_owned(),
        root_identity_sha256: root_identity_sha256(root),
        database_path: database_path.to_path_buf(),
        cause,
        outcome,
        prior_generation,
        published_generation,
        source_fingerprint_sha256,
        journal_attempt_id,
        failure_diagnostic: None,
    }
}

fn root_identity_sha256(root: &CanonicalRepoRoot) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.code-map.root-identity.v1\0");
    digest.update(root.identity().as_str().as_bytes());
    hex::encode(digest.finalize())
}

fn now_ms() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn journal_phase(
    connection: &rusqlite::Connection,
    identity: &str,
) -> Result<Option<(String, String, Option<String>)>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'code_map_lifecycle_attempts')",
        [], |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let mut statement = connection.prepare(
        "SELECT attempt_id, phase, owner_id FROM code_map_lifecycle_attempts \
         WHERE root_identity = ?1 \
           AND length(CAST(attempt_id AS BLOB)) <= ?2 \
           AND length(CAST(phase AS BLOB)) <= ?2 \
           AND (owner_id IS NULL OR length(CAST(owner_id AS BLOB)) <= ?2)",
    )?;
    let mut rows = statement.query(rusqlite::params![identity, MAX_LIFECYCLE_TEXT_BYTES])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let attempt_id = bounded_row_text(row, 0, "lifecycle journal attempt")?;
    let phase = bounded_row_text(row, 1, "lifecycle journal phase")?;
    let owner_id = match row.get_ref(2)? {
        rusqlite::types::ValueRef::Null => None,
        rusqlite::types::ValueRef::Text(bytes) => {
            Some(bounded_text(bytes, "lifecycle journal owner")?)
        }
        _ => anyhow::bail!("lifecycle journal owner is not text"),
    };
    Ok(Some((attempt_id, phase, owner_id)))
}

fn bounded_row_text(row: &rusqlite::Row<'_>, index: usize, label: &str) -> Result<String> {
    match row.get_ref(index)? {
        rusqlite::types::ValueRef::Text(bytes) => bounded_text(bytes, label),
        _ => anyhow::bail!("{label} is not text"),
    }
}

fn bounded_text(bytes: &[u8], label: &str) -> Result<String> {
    anyhow::ensure!(
        bytes.len() <= MAX_LIFECYCLE_TEXT_BYTES as usize,
        "{label} exceeds lifecycle read bound"
    );
    Ok(std::str::from_utf8(bytes)
        .with_context(|| format!("{label} is not UTF-8"))?
        .to_owned())
}

struct RefreshLease {
    _file: std::fs::File,
    path: PathBuf,
    owner_id: String,
}

impl RefreshLease {
    fn acquire(database_path: &Path) -> Result<Self> {
        let path = refresh_lease_path(database_path)?;
        let parent = path
            .parent()
            .context("lifecycle refresh lease has no parent")?;
        if !parent.exists() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("create lifecycle refresh lease parent {}", parent.display())
            })?;
        }
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        anyhow::ensure!(
            parent_metadata.is_dir() && !parent_metadata.file_type().is_symlink(),
            "lifecycle refresh lease parent is not a regular directory"
        );
        if path.exists() {
            ensure_regular_non_symlink_file(&path, "lifecycle refresh lease")?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("open lifecycle refresh lease {}", path.display()))?;
        ensure_regular_non_symlink_file(&path, "lifecycle refresh lease")?;
        let owner_id = uuid::Uuid::now_v7().to_string();
        {
            let mut local = local_refresh_leases()
                .lock()
                .expect("lifecycle lease mutex poisoned");
            anyhow::ensure!(
                !local.contains_key(&path),
                "a lifecycle refresh already owns this physical root"
            );
            local.insert(path.clone(), owner_id.clone());
        }
        let write_owner = (|| -> Result<()> {
            file.try_lock()
                .with_context(|| "a lifecycle refresh already owns this physical root")?;
            file.set_len(0)?;
            (&file).write_all(owner_id.as_bytes())?;
            (&file).write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_owner {
            remove_local_refresh_lease(&path, &owner_id);
            return Err(error);
        }
        Ok(Self {
            _file: file,
            path,
            owner_id,
        })
    }
}

impl Drop for RefreshLease {
    fn drop(&mut self) {
        remove_local_refresh_lease(&self.path, &self.owner_id);
    }
}

fn local_refresh_leases() -> &'static Mutex<BTreeMap<PathBuf, String>> {
    LOCAL_REFRESH_LEASES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn remove_local_refresh_lease(path: &Path, owner_id: &str) {
    if let Ok(mut local) = local_refresh_leases().lock()
        && local.get(path).is_some_and(|owner| owner == owner_id)
    {
        local.remove(path);
    }
}

fn refresh_lease_owner(database_path: &Path) -> Result<Option<String>> {
    let path = refresh_lease_path(database_path)?;
    if let Some(owner) = local_refresh_leases()
        .lock()
        .expect("lifecycle lease mutex poisoned")
        .get(&path)
        .cloned()
    {
        return Ok(Some(owner));
    }
    if !path.exists() {
        return Ok(None);
    }
    ensure_regular_non_symlink_file(&path, "lifecycle refresh lease")?;
    let metadata = std::fs::metadata(&path)?;
    anyhow::ensure!(
        metadata.len() <= 128,
        "lifecycle refresh lease owner exceeds bound"
    );
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)?;
    match file.try_lock() {
        Ok(()) => {
            file.unlock()?;
            Ok(None)
        }
        Err(std::fs::TryLockError::WouldBlock) => {
            let owner = std::fs::read_to_string(&path)?;
            let owner = owner.trim();
            anyhow::ensure!(
                uuid::Uuid::parse_str(owner).is_ok(),
                "invalid lifecycle refresh lease owner"
            );
            Ok(Some(owner.to_owned()))
        }
        Err(std::fs::TryLockError::Error(error)) => {
            Err(error).context("probe lifecycle refresh lease")
        }
    }
}

fn refresh_lease_path(database_path: &Path) -> Result<PathBuf> {
    let parent = database_path
        .parent()
        .context("code-map database path has no parent")?;
    let name = database_path
        .file_name()
        .context("code-map database path has no file name")?;
    anyhow::ensure!(
        name != "." && name != "..",
        "invalid code-map database file name"
    );
    if parent.exists() {
        let metadata = std::fs::symlink_metadata(parent)
            .with_context(|| format!("inspect code-map database parent {}", parent.display()))?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "code-map database parent is not a regular directory"
        );
    }
    Ok(parent.join(format!(
        "{}{}",
        name.to_string_lossy(),
        REFRESH_LEASE_SUFFIX
    )))
}

fn ensure_regular_non_symlink_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} is not a regular non-symlink file: {}",
        path.display()
    );
    Ok(())
}

fn bounded_diagnostic(value: &str) -> String {
    if value.len() <= MAX_FAILURE_DIAGNOSTIC_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_FAILURE_DIAGNOSTIC_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

fn journal_start(
    connection: &rusqlite::Connection,
    root: &CanonicalRepoRoot,
    attempt_id: &str,
    owner_id: &str,
    prior: Option<&LifecycleGeneration>,
) -> Result<()> {
    let changed = connection.execute(
        "INSERT INTO code_map_lifecycle_attempts \
         (root_identity, root_display, attempt_id, phase, prior_index_generation, prior_graph_generation, owner_id, started_at_ms, completed_at_ms) \
         VALUES (?1, ?2, ?3, 'running', ?4, ?5, ?6, ?7, NULL) \
         ON CONFLICT(root_identity) DO UPDATE SET root_display=excluded.root_display, attempt_id=excluded.attempt_id, phase='running', prior_index_generation=excluded.prior_index_generation, prior_graph_generation=excluded.prior_graph_generation, published_index_generation=NULL, published_graph_generation=NULL, source_fingerprint_sha256=NULL, owner_id=excluded.owner_id, started_at_ms=excluded.started_at_ms, completed_at_ms=NULL \
         WHERE code_map_lifecycle_attempts.phase <> 'running'",
        rusqlite::params![root.identity().as_str(), root.display(), attempt_id, prior.map(|p| p.index_generation), prior.map(|p| p.graph_generation), owner_id, now_ms()?],
    )?;
    anyhow::ensure!(
        changed == 1,
        "a lifecycle refresh already owns this physical root"
    );
    Ok(())
}

fn journal_claim_owner(
    connection: &rusqlite::Connection,
    root: &CanonicalRepoRoot,
    attempt_id: &str,
    owner_id: &str,
) -> Result<()> {
    let changed = connection.execute(
        "UPDATE code_map_lifecycle_attempts SET owner_id = ?3 \
         WHERE root_identity = ?1 AND attempt_id = ?2 AND phase = 'running'",
        rusqlite::params![root.identity().as_str(), attempt_id, owner_id],
    )?;
    anyhow::ensure!(
        changed == 1,
        "lifecycle journal recovery ownership could not be claimed"
    );
    Ok(())
}

fn journal_finish(
    connection: &rusqlite::Connection,
    root: &CanonicalRepoRoot,
    attempt_id: &str,
    owner_id: &str,
    phase: &str,
    published: Option<&LifecycleGeneration>,
    fingerprint: Option<&str>,
) -> Result<()> {
    let changed = connection.execute(
        "UPDATE code_map_lifecycle_attempts SET phase=?4, published_index_generation=?5, published_graph_generation=?6, source_fingerprint_sha256=?7, completed_at_ms=?8 WHERE root_identity=?1 AND attempt_id=?2 AND owner_id=?3",
        rusqlite::params![root.identity().as_str(), attempt_id, owner_id, phase, published.map(|p| p.index_generation), published.map(|p| p.graph_generation), fingerprint, now_ms()?],
    )?;
    anyhow::ensure!(
        changed == 1,
        "lifecycle journal ownership was lost before terminal update"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_source(repo: &Path, name: &str, body: &str) {
        std::fs::write(repo.join(name), body).unwrap();
    }

    fn normal_refresh(database: &Path, repo: &Path) -> CodeMapLifecycleReceipt {
        refresh(
            database,
            repo,
            LifecycleRefreshOptions::default(),
            &LifecycleCancellation::new(),
        )
        .unwrap()
    }

    fn published(receipt: &CodeMapLifecycleReceipt) -> LifecycleGeneration {
        receipt.published_generation.clone().unwrap()
    }

    #[test]
    fn absent_inspection_is_non_mutating() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let database = workspace.path().join("missing").join("code_map.db");

        let status = inspect(&database, &repo);
        assert!(matches!(status.state, CodeMapLifecycleState::Absent));
        assert!(!database.exists());
        assert!(!database.parent().unwrap().exists());
    }

    #[test]
    fn already_cancelled_refresh_does_not_create_a_database() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let database = workspace.path().join("missing").join("code_map.db");
        let cancellation = LifecycleCancellation::new();
        cancellation.cancel();

        let receipt = refresh(
            &database,
            &repo,
            LifecycleRefreshOptions::default(),
            &cancellation,
        )
        .unwrap();
        assert_eq!(receipt.outcome, RefreshOutcome::Cancelled);
        assert!(!database.exists());
        assert!(!database.parent().unwrap().exists());
    }

    #[test]
    fn corrupt_inspection_preserves_the_database_until_explicit_repair() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let database = workspace.path().join("code_map.db");
        let original = b"not a sqlite database";
        std::fs::write(&database, original).unwrap();

        let status = inspect(&database, &repo);
        assert!(matches!(
            status.state,
            CodeMapLifecycleState::Corrupt { .. }
        ));
        assert_eq!(std::fs::read(&database).unwrap(), original);
    }

    #[test]
    fn refresh_reuses_fresh_then_advances_for_edit_add_remove_and_rename() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let database = workspace.path().join("code_map.db");
        write_source(&repo, "one.rs", "pub fn one() {}\n");

        let first = normal_refresh(&database, &repo);
        assert_eq!(first.outcome, RefreshOutcome::IndexedFirstTime);
        let mut prior = published(&first);

        let fresh = normal_refresh(&database, &repo);
        assert_eq!(fresh.outcome, RefreshOutcome::ReusedFresh);
        assert_eq!(published(&fresh), prior);

        write_source(&repo, "one.rs", "pub fn one() { let _ = 1; }\n");
        let edited = normal_refresh(&database, &repo);
        assert_eq!(edited.outcome, RefreshOutcome::RefreshedStale);
        prior = published(&edited);
        assert!(prior.index_generation > first.published_generation.unwrap().index_generation);

        write_source(&repo, "two.rs", "pub fn two() {}\n");
        let added = normal_refresh(&database, &repo);
        prior = published(&added);
        assert!(prior.index_generation > edited.published_generation.unwrap().index_generation);
        let canonical = CanonicalRepoRoot::discover(&repo).unwrap();
        let connection = super::super::persist::open_read_only(&database).unwrap();
        assert_eq!(
            super::super::persist::load_map(&connection, canonical.display())
                .unwrap()
                .unwrap()
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            vec!["one.rs", "two.rs"]
        );
        drop(connection);

        std::fs::remove_file(repo.join("two.rs")).unwrap();
        let removed = normal_refresh(&database, &repo);
        prior = published(&removed);
        assert!(prior.index_generation > added.published_generation.unwrap().index_generation);
        let connection = super::super::persist::open_read_only(&database).unwrap();
        assert_eq!(
            super::super::persist::load_map(&connection, canonical.display())
                .unwrap()
                .unwrap()
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            vec!["one.rs"]
        );
        drop(connection);

        std::fs::rename(repo.join("one.rs"), repo.join("renamed.rs")).unwrap();
        let renamed = normal_refresh(&database, &repo);
        assert!(published(&renamed).index_generation > prior.index_generation);
        let connection = super::super::persist::open_read_only(&database).unwrap();
        assert_eq!(
            super::super::persist::load_map(&connection, canonical.display())
                .unwrap()
                .unwrap()
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            vec!["renamed.rs"]
        );
    }

    #[test]
    fn roots_are_isolated_in_one_database() {
        let workspace = tempdir().unwrap();
        let one = workspace.path().join("one");
        let two = workspace.path().join("two");
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();
        write_source(&one, "one.rs", "pub fn one() {}\n");
        write_source(&two, "two.rs", "pub fn two() {}\n");
        let database = workspace.path().join("code_map.db");

        let one_first = normal_refresh(&database, &one);
        let two_first = normal_refresh(&database, &two);
        write_source(&one, "one.rs", "pub fn one() { let _ = 1; }\n");
        let one_second = normal_refresh(&database, &one);

        assert!(published(&one_second).index_generation > published(&one_first).index_generation);
        let two_status = inspect(&database, &two);
        assert!(matches!(
            two_status.state,
            CodeMapLifecycleState::Fresh { .. }
        ));
        assert_eq!(
            state_snapshot(&two_status.state),
            Some(published(&two_first))
        );
    }

    #[test]
    fn completed_receipt_and_status_report_the_same_committed_generation() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_source(&repo, "lib.rs", "pub fn committed() {}\n");
        let database = workspace.path().join("code_map.db");

        let receipt = normal_refresh(&database, &repo);
        let committed = published(&receipt);
        let status = inspect(&database, &repo);
        assert!(matches!(status.state, CodeMapLifecycleState::Fresh { .. }));
        assert_eq!(state_snapshot(&status.state), Some(committed));
        assert!(receipt.failure_diagnostic.is_none());
    }

    #[test]
    fn interrupted_before_publish_is_reconciled_by_a_new_attempt() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_source(&repo, "lib.rs", "pub fn ready() {}\n");
        let database = workspace.path().join("code_map.db");
        let root = CanonicalRepoRoot::discover(&repo).unwrap();
        let attempt = "018f36e7-42d3-7000-8000-000000000001";
        let journal = super::super::persist::open(&database).unwrap();
        journal_start(&journal, &root, attempt, "orphan-owner", None).unwrap();
        drop(journal);

        assert!(matches!(
            inspect(&database, &repo).state,
            CodeMapLifecycleState::Recovering { prior: None, .. }
        ));
        let receipt = reconcile(&database, &repo, &LifecycleCancellation::new()).unwrap();
        assert_eq!(receipt.outcome, RefreshOutcome::IndexedFirstTime);
        assert!(receipt.published_generation.is_some());
    }

    #[test]
    fn published_before_journal_finish_recovers_without_duplicate_generation() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_source(&repo, "lib.rs", "pub fn ready() {}\n");
        let database = workspace.path().join("code_map.db");
        let root = CanonicalRepoRoot::discover(&repo).unwrap();
        let attempt = "018f36e7-42d3-7000-8000-000000000002";
        let journal = super::super::persist::open(&database).unwrap();
        journal_start(&journal, &root, attempt, "orphan-owner", None).unwrap();
        drop(journal);
        let snapshot =
            super::super::snapshot::rebuild_snapshot(&root, &database, RebuildOptions::default())
                .unwrap();

        let receipt = reconcile(&database, &repo, &LifecycleCancellation::new()).unwrap();
        assert_eq!(receipt.outcome, RefreshOutcome::RecoveredPublishedAttempt);
        assert_eq!(
            published(&receipt).index_generation,
            snapshot.index_generation
        );
        assert_eq!(
            published(&receipt).graph_generation,
            snapshot.graph_generation
        );
    }

    #[test]
    fn live_lease_reports_refreshing_and_orphan_lease_reports_recovering() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_source(&repo, "lib.rs", "pub fn ready() {}\n");
        let database = workspace.path().join("code_map.db");
        let first = normal_refresh(&database, &repo);
        let root = CanonicalRepoRoot::discover(&repo).unwrap();
        let attempt = "018f36e7-42d3-7000-8000-000000000003";
        let lease = RefreshLease::acquire(&database).unwrap();
        let journal = super::super::persist::open(&database).unwrap();
        journal_start(
            &journal,
            &root,
            attempt,
            &lease.owner_id,
            first.published_generation.as_ref(),
        )
        .unwrap();
        drop(journal);

        assert!(matches!(
            inspect(&database, &repo).state,
            CodeMapLifecycleState::Refreshing { ref attempt_id, .. } if attempt_id == attempt
        ));
        let concurrent = refresh(
            &database,
            &repo,
            LifecycleRefreshOptions::default(),
            &LifecycleCancellation::new(),
        )
        .unwrap_err();
        assert!(concurrent.to_string().contains("already owns"));
        drop(lease);
        assert!(matches!(
            inspect(&database, &repo).state,
            CodeMapLifecycleState::Recovering { ref attempt_id, .. } if attempt_id == attempt
        ));
    }

    #[test]
    fn cancelled_repair_preserves_corrupt_evidence_without_renaming_it() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let database = workspace.path().join("code_map.db");
        let original = b"not a sqlite database";
        std::fs::write(&database, original).unwrap();
        let cancellation = LifecycleCancellation::new();
        cancellation.cancel();

        let receipt = refresh(
            &database,
            &repo,
            LifecycleRefreshOptions {
                repair_corrupt: true,
                cause: RefreshCause::ExplicitCorruptStoreRepair,
                ..LifecycleRefreshOptions::default()
            },
            &cancellation,
        )
        .unwrap();
        assert_eq!(receipt.outcome, RefreshOutcome::Cancelled);
        assert_eq!(std::fs::read(&database).unwrap(), original);
    }

    #[test]
    fn normal_refresh_of_corrupt_store_does_not_create_a_lease_or_repair_state() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let database = workspace.path().join("code_map.db");
        let original = b"not a sqlite database";
        std::fs::write(&database, original).unwrap();
        let entries = || {
            let mut names = std::fs::read_dir(workspace.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let before = entries();
        let result = normal_refresh(&database, &repo);
        assert_eq!(result.outcome, RefreshOutcome::CorruptRepairRequired);
        assert_eq!(entries(), before);
        assert_eq!(std::fs::read(database).unwrap(), original);
    }

    #[test]
    fn cancellation_during_repair_returns_a_receipt_and_retains_resumable_evidence() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_source(&repo, "lib.rs", "pub fn ready() {}\n");
        let database = workspace.path().join("code_map.db");
        std::fs::write(&database, b"corrupt sqlite database").unwrap();
        std::fs::write(workspace.path().join("code_map.db-wal"), b"corrupt wal").unwrap();
        let cancellation = LifecycleCancellation::new();
        let options = LifecycleRefreshOptions {
            repair_corrupt: true,
            cause: RefreshCause::ExplicitCorruptStoreRepair,
            ..LifecycleRefreshOptions::default()
        };
        let mut checkpoints = 0;
        let result = refresh_with_repair_checkpoint(
            &database,
            &repo,
            options.clone(),
            &cancellation,
            || {
                checkpoints += 1;
                if checkpoints == 3 {
                    cancellation.cancel();
                }
            },
        )
        .unwrap();
        assert_eq!(result.outcome, RefreshOutcome::Cancelled);
        assert!(result.published_generation.is_none());
        assert!(matches!(
            inspect(&database, &repo).state,
            CodeMapLifecycleState::Corrupt { .. }
        ));
        let resumed = refresh(&database, &repo, options, &LifecycleCancellation::new()).unwrap();
        assert_eq!(resumed.outcome, RefreshOutcome::IndexedFirstTime);
        assert!(matches!(
            inspect(&database, &repo).state,
            CodeMapLifecycleState::Fresh { .. }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn repaired_fresh_open_wal_set_is_fresh_and_not_repaired_again() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        write_source(&repo, "lib.rs", "pub fn ready() {}\n");
        let database = workspace.path().join("code_map.db");
        std::fs::write(&database, b"corrupt sqlite database").unwrap();
        let options = LifecycleRefreshOptions {
            repair_corrupt: true,
            cause: RefreshCause::ExplicitCorruptStoreRepair,
            ..LifecycleRefreshOptions::default()
        };

        let repaired = refresh(
            &database,
            &repo,
            options.clone(),
            &LifecycleCancellation::new(),
        )
        .unwrap();
        assert_eq!(repaired.outcome, RefreshOutcome::IndexedFirstTime);

        let fresh_connection = rusqlite::Connection::open(&database).unwrap();
        let journal_mode: String = fresh_connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        fresh_connection
            .execute_batch(
                "CREATE TABLE repair_wal_probe (id INTEGER); INSERT INTO repair_wal_probe VALUES (1);",
            )
            .unwrap();
        let wal = PathBuf::from(format!("{}-wal", database.display()));
        let shm = PathBuf::from(format!("{}-shm", database.display()));
        assert!(wal.is_file());
        assert!(shm.is_file());

        assert!(matches!(
            inspect(&database, &repo).state,
            CodeMapLifecycleState::Fresh { .. }
        ));
        let reused = refresh(&database, &repo, options, &LifecycleCancellation::new()).unwrap();
        assert_eq!(reused.outcome, RefreshOutcome::ReusedFresh);
        drop(fresh_connection);
    }

    #[test]
    fn failed_rebuild_returns_a_terminal_receipt_with_a_bounded_diagnostic() {
        let workspace = tempdir().unwrap();
        let repo = workspace.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let oversized = vec![b'x'; super::super::walker::DEFAULT_MAX_FILE_BYTES as usize + 1];
        std::fs::write(repo.join("oversized.rs"), oversized).unwrap();
        let database = workspace.path().join("code_map.db");

        let receipt = normal_refresh(&database, &repo);
        assert_eq!(receipt.outcome, RefreshOutcome::Failed);
        assert!(receipt.published_generation.is_none());
        assert!(
            receipt
                .failure_diagnostic
                .as_deref()
                .is_some_and(|value| value.len() <= MAX_FAILURE_DIAGNOSTIC_BYTES + 4)
        );
        let root = CanonicalRepoRoot::discover(&repo).unwrap();
        let connection = super::super::persist::open_read_only(&database).unwrap();
        assert!(matches!(
            journal_phase(&connection, root.identity().as_str()).unwrap(),
            Some((_, phase, _)) if phase == "failed"
        ));
    }
}
