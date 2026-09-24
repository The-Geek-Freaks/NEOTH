//! ADOPT31-B8 — bounded, default-off document discovery.
//!
//! This is deliberately a notice producer only. It never extracts, distills,
//! stages, activates, sends, or persists document bodies.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::task::JoinHandle;

use crate::config::DocIngestConfig;
use crate::skills::store::{
    BoundDirectory, PrivateChildCommit, PrivateChildDurabilityUnknown,
    atomic_write_private_child_reported, open_absolute_bound_directory,
    open_bound_regular_file_snapshot, open_or_create_bound_lockfile, read_regular_file_bounded,
};

pub const POLL_INTERVAL: Duration = Duration::from_secs(60);
const STATE_FILE: &str = "doc_ingest_state.v1.json";
const LOCK_FILE: &str = "doc_ingest_state.v1.lock";
const SCHEMA_VERSION: u8 = 1;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 4_096;
const MAX_ROOTS: usize = 32;
const MAX_DIRECTORIES_PER_SCAN: usize = 2_048;
const MAX_ENTRIES_PER_DIRECTORY: usize = 4_096;
const MAX_VISITED_ENTRIES_PER_SCAN: usize = 65_536;
const MAX_QUEUED_DIRECTORIES_PER_SCAN: usize = 4_096;
const MAX_INVENTORY_CANDIDATES_PER_SCAN: usize = 4_096;
const MAX_CANDIDATES_PER_SCAN: usize = 64;
const MAX_SOURCE_BYTES_PER_SCAN: u64 = 256 * 1024 * 1024;
const MAX_QUOTA_TIMESTAMPS: usize = 4_096;

/// Operator-visible metadata only. `source_path` is deliberately available to
/// the local CLI, while document content never leaves the bounded hash read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentNotice {
    pub revision_id: String,
    pub source_path: String,
    pub source_kind: String,
    pub source_bytes: u64,
    pub source_sha256: String,
    pub first_seen_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NoticeStatus {
    Pending,
    Deferred,
    Superseded,
    Dismissed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateEntry {
    notice: DocumentNotice,
    root_id: String,
    relative_path: String,
    status: NoticeStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocIngestState {
    schema_version: u8,
    entries: BTreeMap<String, StateEntry>,
    admitted_notice_timestamps_unix: Vec<i64>,
    #[serde(default)]
    scan_after_source_path: Option<String>,
}

impl Default for DocIngestState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            entries: BTreeMap::new(),
            admitted_notice_timestamps_unix: Vec::new(),
            scan_after_source_path: None,
        }
    }
}

struct ScanRoot {
    directory: BoundDirectory,
    directory_identity: String,
    root_id: String,
    physical_path: String,
}

#[derive(Default)]
struct ScanControl {
    cancelled: AtomicBool,
    commit: Mutex<()>,
    #[cfg(test)]
    before_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(test)]
    after_scan: Mutex<Option<tokio::sync::oneshot::Sender<bool>>>,
}

impl ScanControl {
    fn check(&self) -> Result<()> {
        anyhow::ensure!(
            !self.cancelled.load(Ordering::Acquire),
            "document discovery scan was cancelled"
        );
        Ok(())
    }

    fn cancel_and_fence(&self) {
        self.cancelled.store(true, Ordering::Release);
        // A retiring worker may finish an already-started atomic state write.
        // Waiting on this short commit section makes task-join completion the
        // boundary after which its blocking scan cannot publish more notices.
        drop(
            self.commit
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        );
    }
}

struct CancelScanOnDrop(Arc<ScanControl>);

impl Drop for CancelScanOnDrop {
    fn drop(&mut self) {
        self.0.cancel_and_fence();
    }
}

/// Bounded outcome of one provider-free discovery pass. It contains counts
/// only, so callers cannot accidentally obtain document bodies from the cron.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ScanReport {
    pub(crate) discovered: usize,
    pub(crate) pending: usize,
    pub(crate) deferred: usize,
}

/// Spawn a local-only poller after the daemon's default-off admission gate.
/// Blocking filesystem work cooperates with the retiring task's commit fence.
pub fn spawn(
    home: PathBuf,
    config: DocIngestConfig,
    vault_root: Option<PathBuf>,
) -> JoinHandle<Result<()>> {
    spawn_controlled(home, config, vault_root, Arc::new(ScanControl::default()))
}

fn spawn_controlled(
    home: PathBuf,
    config: DocIngestConfig,
    vault_root: Option<PathBuf>,
    control: Arc<ScanControl>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        if !config.enabled {
            return Ok(());
        }
        let _cancel_on_retirement = CancelScanOnDrop(control.clone());
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let scan_home = home.clone();
            let scan_config = config.clone();
            let scan_vault = vault_root.clone();
            let scan_control = control.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let result = scan_once_controlled(
                    &scan_home,
                    &scan_config,
                    scan_vault.as_deref(),
                    crate::time::now_unix_i64(),
                    &scan_control,
                );
                #[cfg(test)]
                if let Some(sender) = scan_control.after_scan.lock().unwrap().take() {
                    let _ = sender.send(result.is_ok());
                }
                result
            })
            .await
            .context("join bounded document discovery scan")?;
            match outcome {
                Ok(report) => tracing::debug!(
                    discovered = report.discovered,
                    pending = report.pending,
                    deferred = report.deferred,
                    "document discovery scan completed"
                ),
                Err(error) => tracing::warn!(
                    error = %error,
                    "document discovery scan refused; retained state will be retried next interval"
                ),
            }
        }
    })
}

/// Run one bounded discovery pass. This is the connected CLI/test seam; it
/// uses the production no-follow scanner and real durable state, not fixtures.
#[cfg(test)]
pub(crate) fn scan_once(
    home: &Path,
    config: &DocIngestConfig,
    vault_root: Option<&Path>,
    now_unix: i64,
) -> Result<ScanReport> {
    scan_once_controlled(home, config, vault_root, now_unix, &ScanControl::default())
}

fn scan_once_controlled(
    home: &Path,
    config: &DocIngestConfig,
    vault_root: Option<&Path>,
    now_unix: i64,
    control: &ScanControl,
) -> Result<ScanReport> {
    if !config.enabled {
        return Ok(ScanReport::default());
    }
    control.check()?;
    config
        .validate(vault_root.is_some())
        .map_err(anyhow::Error::msg)?;
    let roots = resolve_roots(config, vault_root.map(Path::to_path_buf))?;
    control.check()?;
    scan_roots(home, config, &roots, now_unix, control)
}

/// List only notices still requiring an operator decision.
pub fn list_pending(home: &Path) -> Result<Vec<DocumentNotice>> {
    let Some(home) = open_absolute_bound_directory(home, false, "document ingest home")? else {
        return Ok(Vec::new());
    };
    let state = load_state(&home)?;
    let mut notices = state
        .entries
        .values()
        .filter(|entry| matches!(entry.status, NoticeStatus::Pending))
        .map(|entry| entry.notice.clone())
        .collect::<Vec<_>>();
    notices.sort_by(|left, right| {
        left.first_seen_unix
            .cmp(&right.first_seen_unix)
            .then_with(|| left.revision_id.cmp(&right.revision_id))
    });
    Ok(notices)
}

/// Dismiss one exact pending revision. Unknown, deferred, superseded, and
/// already dismissed revisions remain unchanged.
pub fn dismiss_pending(home: &Path, revision_id: &str) -> Result<bool> {
    validate_revision_id(revision_id)?;
    with_locked_state(home, &ScanControl::default(), |state, _| {
        let changed = state.entries.get_mut(revision_id).is_some_and(|entry| {
            if matches!(entry.status, NoticeStatus::Pending) {
                entry.status = NoticeStatus::Dismissed;
                true
            } else {
                false
            }
        });
        Ok((changed, changed))
    })
}

fn scan_roots(
    home: &Path,
    config: &DocIngestConfig,
    roots: &[ScanRoot],
    now_unix: i64,
    control: &ScanControl,
) -> Result<ScanReport> {
    with_locked_state(home, control, |state, _root| {
        control.check()?;
        let old_quota_len = state.admitted_notice_timestamps_unix.len();
        prune_quota(state, now_unix);
        let mut inventory = inventory_roots(roots, control)?;
        inventory.sort_by(|left, right| {
            left.selection_key
                .cmp(&right.selection_key)
                .then_with(|| left.file_identity.cmp(&right.file_identity))
        });

        let mut candidates = Vec::new();
        let mut source_bytes_budget = MAX_SOURCE_BYTES_PER_SCAN;
        let scan_after = state.scan_after_source_path.clone();
        let (hashed, last_attempted) = hash_inventory_range(
            &inventory,
            scan_after.as_deref(),
            &mut source_bytes_budget,
            now_unix,
            control,
        )?;
        candidates.extend(hashed);
        candidates.sort_by(|left, right| left.revision_id.cmp(&right.revision_id));
        let discovered = candidates.len();
        let mut dirty = state.admitted_notice_timestamps_unix.len() != old_quota_len;
        for candidate in candidates {
            supersede_prior_revision(
                state,
                &candidate.root_id,
                &candidate.relative_path,
                &candidate.revision_id,
                &mut dirty,
            );
            if let Some(existing) = state.entries.get_mut(&candidate.revision_id) {
                // A deferred revision can become visible only after a fresh
                // snapshot from a currently selected root confirms its bytes.
                if matches!(existing.status, NoticeStatus::Deferred)
                    && state.admitted_notice_timestamps_unix.len() < config.max_per_day
                {
                    existing.status = NoticeStatus::Pending;
                    state.admitted_notice_timestamps_unix.push(now_unix);
                    dirty = true;
                }
                continue;
            }
            let status = if state.admitted_notice_timestamps_unix.len() < config.max_per_day {
                state.admitted_notice_timestamps_unix.push(now_unix);
                NoticeStatus::Pending
            } else {
                NoticeStatus::Deferred
            };
            state.entries.insert(
                candidate.revision_id.clone(),
                StateEntry {
                    notice: candidate.notice,
                    root_id: candidate.root_id,
                    relative_path: candidate.relative_path,
                    status,
                },
            );
            dirty = true;
        }
        if state.entries.len() > MAX_ENTRIES {
            anyhow::bail!("document-ingest state entry limit exceeded");
        }
        let next_cursor = last_attempted;
        if state.scan_after_source_path != next_cursor {
            state.scan_after_source_path = next_cursor;
            dirty = true;
        }
        let report = ScanReport {
            discovered,
            pending: state
                .entries
                .values()
                .filter(|entry| matches!(entry.status, NoticeStatus::Pending))
                .count(),
            deferred: state
                .entries
                .values()
                .filter(|entry| matches!(entry.status, NoticeStatus::Deferred))
                .count(),
        };
        Ok((report, dirty))
    })
}

struct Candidate {
    revision_id: String,
    root_id: String,
    relative_path: String,
    notice: DocumentNotice,
}

/// A metadata-only inventory item. The stored parent capability and child
/// identity are used to re-open the exact candidate for the later bounded
/// hash attempt; no document body is captured during inventory.
struct InventoryCandidate {
    selection_key: String,
    file_identity: String,
    parent: Dir,
    name: OsString,
    path: PathBuf,
    root_id: String,
    relative_path: String,
    kind: &'static str,
    source_bytes: u64,
}

struct DirectoryWork {
    directory: Dir,
    display: PathBuf,
    relative: PathBuf,
}

enum HashCandidateResult {
    Accepted(Candidate),
    Rejected,
    ByteBudgetDeferred,
}

fn resolve_roots(config: &DocIngestConfig, vault_root: Option<PathBuf>) -> Result<Vec<ScanRoot>> {
    if !config.enabled {
        return Ok(Vec::new());
    }
    anyhow::ensure!(
        config.max_per_day > 0,
        "document ingest max_per_day must be positive"
    );
    let mut paths = config
        .watch_paths
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if let Some(vault) = vault_root {
        paths.push(vault);
    }
    anyhow::ensure!(
        !paths.is_empty(),
        "enabled document ingest needs at least one operator-selected root"
    );
    anyhow::ensure!(
        paths.len() <= MAX_ROOTS,
        "document ingest root limit exceeded"
    );
    let mut roots = paths
        .iter()
        .map(|path| open_scan_root(path))
        .collect::<Result<Vec<_>>>()?;
    // Descendants are inventoried first. The later global directory/file
    // identities then make an overlapping parent skip the exact same object.
    // Ties use a verified physical representation only for deterministic
    // ownership; aliases are collapsed by the opened directory identity.
    roots.sort_by(|left, right| {
        right
            .directory
            .physical_display_path
            .components()
            .count()
            .cmp(&left.directory.physical_display_path.components().count())
            .then_with(|| left.physical_path.cmp(&right.physical_path))
            .then_with(|| left.directory_identity.cmp(&right.directory_identity))
    });
    let mut selected = BTreeSet::new();
    roots.retain(|root| selected.insert(root.directory_identity.clone()));
    Ok(roots)
}

fn open_scan_root(path: &Path) -> Result<ScanRoot> {
    anyhow::ensure!(
        path.is_absolute(),
        "document ingest root must be absolute: {}",
        path.display()
    );
    let directory = open_absolute_bound_directory(path, false, "document ingest root")?
        .context("document ingest root is missing")?;
    let physical_path = directory
        .physical_display_path
        .to_str()
        .context("document-ingest physical root path is not valid UTF-8")?
        .to_owned();
    let directory_identity = crate::skills::store::directory_identity_token(&directory.dir)?;
    let root_id = hash_domain(b"doc-ingest-root-v1", directory_identity.as_bytes());
    Ok(ScanRoot {
        directory,
        directory_identity,
        root_id,
        physical_path,
    })
}

fn inventory_roots(roots: &[ScanRoot], control: &ScanControl) -> Result<Vec<InventoryCandidate>> {
    let mut queue = Vec::new();
    let mut queued_directory_identities = BTreeSet::new();
    // `Vec::pop` is LIFO, so seed roots in reverse stable-priority order.
    // This ensures an explicitly nested root claims its file identities before
    // an overlapping parent can encounter the same descendants.
    for root in roots.iter().rev() {
        control.check()?;
        if queued_directory_identities.insert(root.directory_identity.clone()) {
            anyhow::ensure!(
                queued_directory_identities.len() <= MAX_QUEUED_DIRECTORIES_PER_SCAN,
                "document-ingest queued-directory inventory limit exceeded"
            );
            queue.push((
                DirectoryWork {
                    directory: root.directory.dir.try_clone()?,
                    display: root.directory.display_path.clone(),
                    relative: PathBuf::new(),
                },
                root,
            ));
        }
    }

    let mut directories = 0usize;
    let mut visited_entries = 0usize;
    let mut file_identities = BTreeSet::new();
    let mut candidates = Vec::new();
    while let Some((work, root)) = queue.pop() {
        control.check()?;
        directories += 1;
        anyhow::ensure!(
            directories <= MAX_DIRECTORIES_PER_SCAN,
            "document-ingest directory inventory limit exceeded"
        );
        let DirectoryWork {
            directory,
            display,
            relative,
        } = work;
        let mut entries = Vec::new();
        for entry in directory
            .read_dir(".")
            .with_context(|| format!("enumerate bound document root {}", display.display()))?
        {
            control.check()?;
            entries.push(entry?);
        }
        anyhow::ensure!(
            entries.len() <= MAX_ENTRIES_PER_DIRECTORY,
            "document-ingest directory entry limit exceeded: {}",
            display.display()
        );
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            control.check()?;
            visited_entries += 1;
            anyhow::ensure!(
                visited_entries <= MAX_VISITED_ENTRIES_PER_SCAN,
                "document-ingest visited-entry inventory limit exceeded"
            );
            let name = entry.file_name();
            if name.is_empty() || name == OsStr::new(".") || name == OsStr::new("..") {
                continue;
            }
            name.to_str()
                .context("document-ingest entry name is not valid UTF-8")?;
            let path = display.join(&name);
            let relative_path = relative.join(&name);
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                let child = crate::skills::store::open_real_child_dir(&directory, &name, &path)?;
                let child_identity = crate::skills::store::directory_identity_token(&child)?;
                if queued_directory_identities.insert(child_identity) {
                    anyhow::ensure!(
                        queued_directory_identities.len() <= MAX_QUEUED_DIRECTORIES_PER_SCAN,
                        "document-ingest queued-directory inventory limit exceeded"
                    );
                    queue.push((
                        DirectoryWork {
                            directory: child,
                            display: path,
                            relative: relative_path,
                        },
                        root,
                    ));
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(kind) = document_kind(&name) else {
                continue;
            };
            let source_path = path
                .to_str()
                .context("document-ingest source path is not valid UTF-8")?
                .to_owned();
            let relative_path = relative_path
                .to_str()
                .context("document-ingest relative source path is not valid UTF-8")?
                .to_owned();
            let (file, binding) = open_bound_regular_file_snapshot(&directory, &name, &path)?;
            let source_bytes = file.metadata()?.len();
            let file_identity = binding.identity_token().to_owned();
            if !file_identities.insert(file_identity.clone()) {
                continue;
            }
            anyhow::ensure!(
                candidates.len() < MAX_INVENTORY_CANDIDATES_PER_SCAN,
                "document-ingest candidate inventory limit exceeded"
            );
            candidates.push(InventoryCandidate {
                selection_key: format!(
                    "doc-ingest-path-v1\0{}\0{relative_path}",
                    root.directory_identity
                ),
                file_identity,
                parent: directory.try_clone()?,
                name,
                path: PathBuf::from(source_path),
                root_id: root.root_id.clone(),
                relative_path,
                kind,
                source_bytes,
            });
        }
    }
    Ok(candidates)
}

/// Hash a stable rotating range from a complete metadata inventory. A source
/// which exceeds the remaining byte budget is deliberately left as the next
/// cursor item: advancing past it would make a set of large documents starve
/// forever. An individually oversized source has no possible admissible read,
/// so it is an attempted rejection and may advance the cursor.
fn hash_inventory_range(
    inventory: &[InventoryCandidate],
    scan_after: Option<&str>,
    source_bytes_budget: &mut u64,
    first_seen_unix: i64,
    control: &ScanControl,
) -> Result<(Vec<Candidate>, Option<String>)> {
    if inventory.is_empty() {
        return Ok((Vec::new(), None));
    }
    let start = scan_after.map_or(0, |cursor| {
        inventory.partition_point(|candidate| candidate.selection_key.as_str() <= cursor)
    });
    let attempts = inventory.len().min(MAX_CANDIDATES_PER_SCAN);
    let mut candidates = Vec::new();
    let mut last_attempted = None;
    for offset in 0..attempts {
        control.check()?;
        let candidate = &inventory[(start + offset) % inventory.len()];
        if candidate.source_bytes <= crate::skills::doc_distill::MAX_DOCUMENT_SOURCE_BYTES
            && candidate.source_bytes > *source_bytes_budget
        {
            break;
        }
        let selection_key = candidate.selection_key.clone();
        match hash_candidate(candidate, source_bytes_budget, first_seen_unix, control)? {
            HashCandidateResult::Accepted(candidate) => {
                last_attempted = Some(selection_key);
                candidates.push(candidate);
            }
            HashCandidateResult::Rejected => {
                last_attempted = Some(selection_key);
            }
            HashCandidateResult::ByteBudgetDeferred => break,
        }
    }
    Ok((candidates, last_attempted))
}

fn hash_candidate(
    candidate: &InventoryCandidate,
    source_bytes_budget: &mut u64,
    first_seen_unix: i64,
    control: &ScanControl,
) -> Result<HashCandidateResult> {
    control.check()?;
    let (mut file, binding) =
        open_bound_regular_file_snapshot(&candidate.parent, &candidate.name, &candidate.path)?;
    if binding.identity_token() != candidate.file_identity {
        return Ok(HashCandidateResult::Rejected);
    }
    let before = file.metadata()?;
    if !before.is_file() || before.len() > crate::skills::doc_distill::MAX_DOCUMENT_SOURCE_BYTES {
        return Ok(HashCandidateResult::Rejected);
    }
    if before.len() > *source_bytes_budget {
        return Ok(HashCandidateResult::ByteBudgetDeferred);
    }
    // Deduct before the first read. A short, changed, or rejected read attempt
    // therefore still consumes its whole reserved portion of this pass's cap.
    *source_bytes_budget -= before.len();
    let mut hasher = Sha256::new();
    let mut remaining = before.len();
    let mut buffer = [0u8; 64 * 1024];
    let buffer_len = buffer.len() as u64;
    while remaining > 0 {
        control.check()?;
        let count = file.read(&mut buffer[..remaining.min(buffer_len) as usize])?;
        if count == 0 {
            // The pre-read metadata promised more bytes. Treat a concurrent
            // truncation as this pass's rejected attempt after preserving its
            // prior byte reservation, then let a later rotation retry it.
            return Ok(HashCandidateResult::Rejected);
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let after = file.metadata()?;
    if after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
        || !binding.matches_regular_file_snapshot(
            &candidate.parent,
            &candidate.name,
            &candidate.path,
        )?
    {
        return Ok(HashCandidateResult::Rejected);
    }
    let source_sha256 = hex::encode(hasher.finalize());
    let revision_id = hash_domain(
        b"doc-ingest-revision-v1",
        format!(
            "{}\0{}\0{}\0{source_sha256}",
            candidate.root_id, candidate.relative_path, candidate.kind
        )
        .as_bytes(),
    );
    Ok(HashCandidateResult::Accepted(Candidate {
        revision_id: revision_id.clone(),
        root_id: candidate.root_id.clone(),
        relative_path: candidate.relative_path.clone(),
        notice: DocumentNotice {
            revision_id,
            source_path: candidate
                .path
                .to_str()
                .context("document-ingest source path is not valid UTF-8")?
                .to_owned(),
            source_kind: candidate.kind.to_owned(),
            source_bytes: before.len(),
            source_sha256,
            first_seen_unix,
        },
    }))
}

fn document_kind(name: &OsStr) -> Option<&'static str> {
    let extension = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    Some(match extension.as_str() {
        "pdf" => "pdf",
        "docx" | "pptx" | "xlsx" | "odt" | "ods" | "odp" | "epub" | "rtf" => "office_or_book",
        "txt" | "md" | "markdown" => "plain_text",
        _ => return None,
    })
}

fn with_locked_state<T>(
    home: &Path,
    control: &ScanControl,
    operation: impl FnOnce(&mut DocIngestState, &BoundDirectory) -> Result<(T, bool)>,
) -> Result<T> {
    control.check()?;
    let home = open_absolute_bound_directory(home, true, "document ingest home")?
        .context("document ingest home missing")?;
    let lock_path = home.display_path.join(LOCK_FILE);
    let (lock, lock_binding) =
        open_or_create_bound_lockfile(&home.dir, OsStr::new(LOCK_FILE), &lock_path)?;
    lock.try_lock()
        .context("document discovery state is busy; retry the command or scan")?;
    control.check()?;
    let state = load_state(&home)?;
    let mut state = state;
    let (value, dirty) = operation(&mut state, &home)?;
    if dirty {
        #[cfg(test)]
        if let Some(hook) = control.before_commit.lock().unwrap().take() {
            hook();
        }
        let _commit = control
            .commit
            .lock()
            .map_err(|_| anyhow::anyhow!("document discovery commit fence is poisoned"))?;
        control.check()?;
        anyhow::ensure!(
            lock_binding.matches_regular_file_child_readonly(
                &home.dir,
                OsStr::new(LOCK_FILE),
                &lock_path,
            )?,
            "document-ingest state lock binding changed before commit"
        );
        save_state(&home, &state)?;
    }
    lock.unlock().context("unlock document-ingest state")?;
    Ok(value)
}

fn load_state(home: &BoundDirectory) -> Result<DocIngestState> {
    let path = home.display_path.join(STATE_FILE);
    let bytes = match read_regular_file_bounded(
        &home.dir,
        OsStr::new(STATE_FILE),
        &path,
        MAX_STATE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(DocIngestState::default());
        }
        Err(error) => return Err(error).context("read document-ingest state fail closed"),
    };
    let state: DocIngestState =
        serde_json::from_slice(&bytes).context("parse document-ingest state fail closed")?;
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &DocIngestState) -> Result<()> {
    anyhow::ensure!(
        state.schema_version == SCHEMA_VERSION
            && state.entries.len() <= MAX_ENTRIES
            && state.admitted_notice_timestamps_unix.len() <= MAX_QUOTA_TIMESTAMPS,
        "invalid document-ingest state bounds"
    );
    anyhow::ensure!(
        state
            .scan_after_source_path
            .as_ref()
            .is_none_or(|cursor| !cursor.is_empty() && cursor.len() <= 8192),
        "invalid document-ingest scan cursor"
    );
    for (revision_id, entry) in &state.entries {
        anyhow::ensure!(
            revision_id == &entry.notice.revision_id,
            "document-ingest state map key disagrees with notice revision id"
        );
        validate_revision_id(revision_id)?;
        validate_revision_id(&entry.root_id)?;
        anyhow::ensure!(
            !entry.relative_path.is_empty()
                && entry.relative_path.len() <= 4096
                && entry.notice.source_path.len() <= 8192
                && entry.notice.first_seen_unix >= 0
                && entry.notice.source_bytes
                    <= crate::skills::doc_distill::MAX_DOCUMENT_SOURCE_BYTES,
            "invalid document-ingest notice bounds"
        );
        validate_revision_id(&entry.notice.source_sha256)?;
        anyhow::ensure!(
            matches!(
                entry.notice.source_kind.as_str(),
                "pdf" | "office_or_book" | "plain_text"
            ),
            "invalid document-ingest source kind"
        );
        let expected_revision = hash_domain(
            b"doc-ingest-revision-v1",
            format!(
                "{}\0{}\0{}\0{}",
                entry.root_id,
                entry.relative_path,
                entry.notice.source_kind,
                entry.notice.source_sha256,
            )
            .as_bytes(),
        );
        anyhow::ensure!(
            expected_revision == *revision_id,
            "document-ingest revision digest does not bind its stored metadata"
        );
    }
    Ok(())
}

fn save_state(home: &BoundDirectory, state: &DocIngestState) -> Result<()> {
    let bytes = serde_json::to_vec(state).context("serialize document-ingest state")?;
    anyhow::ensure!(
        bytes.len() <= MAX_STATE_BYTES,
        "document-ingest state exceeds bounded maximum"
    );
    let path = home.display_path.join(STATE_FILE);
    match atomic_write_private_child_reported(&home.dir, OsStr::new(STATE_FILE), &path, &bytes)? {
        PrivateChildCommit::PublishedAndSynced => Ok(()),
        PrivateChildCommit::PublishedDurabilityUnknown(
            PrivateChildDurabilityUnknown::ParentSyncUnsupported,
        ) => {
            // Windows cannot confirm a parent-directory fsync. The exact
            // capability-relative bytes are nevertheless live-verified before
            // treating this state transition as committed; callers must not
            // misreport it as power-loss durable.
            let actual =
                read_regular_file_bounded(&home.dir, OsStr::new(STATE_FILE), &path, bytes.len())
                    .context("live-verify Windows document-ingest state")?;
            anyhow::ensure!(
                actual == bytes,
                "document-ingest state changed after unsupported durability publication"
            );
            home.dir
                .dir_metadata()
                .context("revalidate document-ingest state parent")?;
            Ok(())
        }
        PrivateChildCommit::PublishedDurabilityUnknown(reason) => anyhow::bail!(
            "document-ingest state may already be published but post-commit durability is unknown: {reason}"
        ),
    }
}

fn prune_quota(state: &mut DocIngestState, now: i64) {
    state
        .admitted_notice_timestamps_unix
        .retain(|stamp| *stamp > now.saturating_sub(86_400));
}
fn supersede_prior_revision(
    state: &mut DocIngestState,
    root_id: &str,
    relative: &str,
    current_revision: &str,
    dirty: &mut bool,
) {
    for entry in state.entries.values_mut().filter(|entry| {
        entry.root_id == root_id
            && entry.relative_path == relative
            && entry.notice.revision_id != current_revision
            && matches!(entry.status, NoticeStatus::Pending | NoticeStatus::Deferred)
    }) {
        entry.status = NoticeStatus::Superseded;
        *dirty = true;
    }
}
fn validate_revision_id(value: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "invalid document revision id"
    );
    Ok(())
}
fn hash_domain(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(b"\0");
    hash.update(bytes);
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_scan_refuses_before_creating_home() {
        let parent = tempfile::tempdir().unwrap();
        let home = parent.path().join("not-created");
        let control = ScanControl::default();
        control.cancel_and_fence();
        assert!(
            scan_once_controlled(&home, &config(parent.path(), 3), None, 100, &control,).is_err()
        );
        assert!(!home.exists());
    }

    #[tokio::test]
    async fn retiring_worker_fences_late_blocking_state_publication() {
        let home = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("review.md"), "# Read after approval\n").unwrap();
        let control = Arc::new(ScanControl::default());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        *control.before_commit.lock().unwrap() = Some(Box::new(move || {
            let _ = entered_tx.send(());
            release_rx.recv_timeout(Duration::from_secs(15)).unwrap();
        }));
        *control.after_scan.lock().unwrap() = Some(finished_tx);
        let worker = spawn_controlled(
            home.path().to_path_buf(),
            config(root.path(), 3),
            None,
            control,
        );
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .expect("filesystem scan must run outside the Tokio worker")
            .unwrap();
        worker.abort();
        let retired = tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("worker retirement must not wait for the blocked scan")
            .unwrap_err();
        assert!(retired.is_cancelled());
        release_tx.send(()).unwrap();
        assert!(
            !tokio::time::timeout(Duration::from_secs(5), finished_rx)
                .await
                .unwrap()
                .unwrap(),
            "retired scan must refuse its pending state publication"
        );
        assert!(!home.path().join(STATE_FILE).exists());
        assert!(list_pending(home.path()).unwrap().is_empty());
        scan_once(home.path(), &config(root.path(), 3), None, 101).unwrap();
        assert_eq!(list_pending(home.path()).unwrap().len(), 1);
    }

    #[test]
    fn cancellation_before_commit_preserves_existing_state_bytes() {
        let home = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("guide.txt"), "retained source").unwrap();
        scan_once(home.path(), &config(root.path(), 3), None, 100).unwrap();
        let before = std::fs::read(home.path().join(STATE_FILE)).unwrap();
        let control = ScanControl::default();
        let result = with_locked_state(home.path(), &control, |state, _| {
            state.entries.values_mut().next().unwrap().status = NoticeStatus::Dismissed;
            control.cancel_and_fence();
            Ok(((), true))
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(home.path().join(STATE_FILE)).unwrap(), before);
        assert_eq!(list_pending(home.path()).unwrap().len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn locked_state_commit_revalidates_held_lock_with_readonly_identity_probe() {
        let home = tempfile::tempdir().expect("home");
        let control = ScanControl::default();

        with_locked_state(home.path(), &control, |_, _| Ok(((), true)))
            .expect("held lock permits its read-only no-follow identity revalidation");

        assert!(home.path().join(STATE_FILE).is_file());
    }

    #[test]
    fn valid_hex_digest_tampering_refuses_state_mutation() {
        let home = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("guide.txt"), "retained source").unwrap();
        scan_once(home.path(), &config(root.path(), 3), None, 100).unwrap();
        let pending = list_pending(home.path()).unwrap();
        let state_path = home.path().join(STATE_FILE);
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state["entries"][&pending[0].revision_id]["notice"]["source_sha256"] =
            serde_json::Value::String("f".repeat(64));
        let tampered = serde_json::to_vec(&state).unwrap();
        std::fs::write(&state_path, &tampered).unwrap();
        assert!(dismiss_pending(home.path(), &pending[0].revision_id).is_err());
        assert_eq!(std::fs::read(&state_path).unwrap(), tampered);
    }

    fn config(root: &Path, max_per_day: usize) -> DocIngestConfig {
        DocIngestConfig {
            enabled: true,
            watch_paths: vec![root.to_string_lossy().into_owned()],
            max_per_day,
        }
    }

    #[test]
    fn real_file_scan_reopens_state_and_deduplicates_revision() {
        let home = tempfile::tempdir().expect("home");
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("guide.rtf"), b"{\\rtf1 test}").expect("document");
        let first = scan_once(home.path(), &config(root.path(), 3), None, 100).expect("first scan");
        let second =
            scan_once(home.path(), &config(root.path(), 3), None, 101).expect("restart scan");
        assert_eq!(first.pending, 1);
        assert_eq!(second.discovered, 1);
        assert_eq!(list_pending(home.path()).expect("pending").len(), 1);
    }

    #[test]
    fn listing_a_missing_home_is_read_only() {
        let parent = tempfile::tempdir().expect("parent");
        let absent = parent.path().join("missing-home");
        assert!(list_pending(&absent).expect("empty list").is_empty());
        assert!(
            !absent.exists(),
            "read-only pending list must not create state or a lock"
        );
    }

    #[test]
    fn real_change_supersedes_pending_and_quota_defers_next_revision() {
        let home = tempfile::tempdir().expect("home");
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("guide.txt");
        std::fs::write(&path, b"first").expect("first document");
        scan_once(home.path(), &config(root.path(), 1), None, 100).expect("first scan");
        std::fs::write(&path, b"second").expect("changed document");
        let report =
            scan_once(home.path(), &config(root.path(), 1), None, 101).expect("changed scan");
        assert_eq!(report.pending, 0);
        assert_eq!(report.deferred, 1);
        assert!(list_pending(home.path()).expect("pending").is_empty());
        let reopened = scan_once(home.path(), &config(root.path(), 1), None, 86_501)
            .expect("expired quota permits the freshly revalidated revision");
        assert_eq!(reopened.pending, 1);
        assert_eq!(reopened.deferred, 0);
    }

    #[test]
    fn deferred_revision_requires_current_root_snapshot_before_promotion() {
        let home = tempfile::tempdir().unwrap();
        let original_root = tempfile::tempdir().unwrap();
        let replacement_root = tempfile::tempdir().unwrap();
        let source = original_root.path().join("guide.txt");
        std::fs::write(&source, "first").unwrap();
        scan_once(home.path(), &config(original_root.path(), 1), None, 100).unwrap();
        std::fs::write(&source, "second").unwrap();
        scan_once(home.path(), &config(original_root.path(), 1), None, 101).unwrap();
        scan_once(
            home.path(),
            &config(replacement_root.path(), 1),
            None,
            86_500,
        )
        .unwrap();
        assert!(
            list_pending(home.path()).unwrap().is_empty(),
            "quota expiry must not publish a deferred notice from a removed root"
        );
        scan_once(home.path(), &config(original_root.path(), 1), None, 86_501).unwrap();
        let pending = list_pending(home.path()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].source_sha256,
            hex::encode(Sha256::digest(b"second"))
        );
    }

    #[test]
    fn bounded_inventory_rotates_after_reopen_and_revisits_a_changed_later_file() {
        let home = tempfile::tempdir().expect("home");
        let root = tempfile::tempdir().expect("root");
        for number in 0..65 {
            std::fs::write(
                root.path().join(format!("{number:03}.txt")),
                format!("{number}"),
            )
            .expect("document");
        }
        let first = scan_once(home.path(), &config(root.path(), 100), None, 100)
            .expect("first bounded scan");
        let original = list_pending(home.path())
            .expect("first pending")
            .into_iter()
            .find(|notice| notice.source_path.ends_with("063.txt"))
            .expect("last first-range document");
        std::fs::write(root.path().join("063.txt"), "changed after its first hash")
            .expect("changed document");
        let second = scan_once(home.path(), &config(root.path(), 100), None, 101)
            .expect("reopened cursor scan");
        let third = scan_once(home.path(), &config(root.path(), 100), None, 102)
            .expect("wrapped cursor scan");
        assert_eq!(first.discovered, MAX_CANDIDATES_PER_SCAN);
        assert_eq!(second.discovered, MAX_CANDIDATES_PER_SCAN);
        assert_eq!(third.discovered, MAX_CANDIDATES_PER_SCAN);
        let changed = list_pending(home.path())
            .expect("rotated pending")
            .into_iter()
            .find(|notice| notice.source_path.ends_with("063.txt"))
            .expect("revisited document");
        assert_ne!(changed.source_sha256, original.source_sha256);
        assert_eq!(list_pending(home.path()).expect("pending").len(), 65);
    }

    #[test]
    fn byte_budget_defers_the_next_item_and_rotates_a_full_64_file_inventory() {
        let root = tempfile::tempdir().expect("root");
        for number in 0..MAX_CANDIDATES_PER_SCAN {
            std::fs::write(root.path().join(format!("{number:03}.txt")), b"aa").expect("document");
        }
        let roots = resolve_roots(&config(root.path(), 10), None).expect("roots");
        let control = ScanControl::default();
        let mut inventory = inventory_roots(&roots, &control).expect("metadata-only inventory");
        inventory.sort_by(|left, right| left.selection_key.cmp(&right.selection_key));
        assert_eq!(inventory.len(), MAX_CANDIDATES_PER_SCAN);

        let mut first_budget = 3;
        let (first, first_cursor) =
            hash_inventory_range(&inventory, None, &mut first_budget, 100, &control)
                .expect("first bounded range");
        assert_eq!(first.len(), 1);
        assert_eq!(first_budget, 1);
        let first_cursor = first_cursor.expect("cursor stops before byte-deferred item");

        let mut second_budget = 3;
        let (second, second_cursor) = hash_inventory_range(
            &inventory,
            Some(&first_cursor),
            &mut second_budget,
            101,
            &control,
        )
        .expect("reopened bounded range");
        assert_eq!(second.len(), 1);
        assert_eq!(second_budget, 1);
        assert_ne!(second[0].notice.source_path, first[0].notice.source_path);
        assert_ne!(second_cursor.expect("advanced cursor"), first_cursor);
    }

    #[test]
    fn overlapping_roots_attribute_the_shared_file_to_the_longest_root_once() {
        let home = tempfile::tempdir().expect("home");
        let parent = tempfile::tempdir().expect("parent root");
        let child = parent.path().join("nested");
        std::fs::create_dir(&child).expect("nested root");
        std::fs::write(child.join("guide.txt"), b"one shared physical file").expect("document");
        let config = DocIngestConfig {
            enabled: true,
            watch_paths: vec![
                parent.path().to_string_lossy().into_owned(),
                child.to_string_lossy().into_owned(),
            ],
            max_per_day: 10,
        };
        let roots = resolve_roots(&config, None).expect("overlapping roots");
        assert_eq!(roots[0].directory.display_path, child);
        let child_root_id = roots[0].root_id.clone();
        scan_once(home.path(), &config, None, 100).expect("scan overlapping roots");
        let state_home = open_absolute_bound_directory(home.path(), false, "test home")
            .expect("open home")
            .expect("home");
        let state = load_state(&state_home).expect("state");
        assert_eq!(state.entries.len(), 1);
        assert_eq!(
            state.entries.values().next().expect("entry").root_id,
            child_root_id
        );
    }

    #[cfg(windows)]
    #[test]
    fn drive_case_aliases_share_one_physical_root_inventory() {
        let home = tempfile::tempdir().expect("home");
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("guide.txt"), b"one physical file").expect("document");
        let root_path = root.path().to_str().expect("UTF-8 temporary root");
        let alias = format!("{}{}", root_path[..1].to_ascii_lowercase(), &root_path[1..]);
        let config = DocIngestConfig {
            enabled: true,
            watch_paths: vec![root_path.to_owned(), alias],
            max_per_day: 10,
        };
        let roots = resolve_roots(&config, None).expect("resolve aliases");
        assert_eq!(
            roots.len(),
            1,
            "case aliases must collapse by opened directory identity"
        );
        let report = scan_once(home.path(), &config, None, 100).expect("scan aliases");
        assert_eq!(report.discovered, 1);
        assert_eq!(list_pending(home.path()).expect("pending").len(), 1);
    }

    #[test]
    fn corrupt_state_fails_closed_without_overwrite() {
        let home = tempfile::tempdir().expect("home");
        let root = tempfile::tempdir().expect("root");
        let state = home.path().join(STATE_FILE);
        let corrupt = b"{broken-json";
        std::fs::write(&state, corrupt).expect("corrupt state");
        assert!(scan_once(home.path(), &config(root.path(), 1), None, 100).is_err());
        assert_eq!(std::fs::read(&state).expect("state retained"), corrupt);
    }

    #[test]
    fn nested_unknown_state_field_fails_closed_without_overwrite() {
        let home = tempfile::tempdir().expect("home");
        let revision = "a".repeat(64);
        let state = format!(
            r#"{{"schema_version":1,"entries":{{"{revision}":{{"notice":{{"revision_id":"{revision}","source_path":"C:/operator/guide.txt","source_kind":"plain_text","source_bytes":1,"source_sha256":"{revision}","first_seen_unix":1}},"root_id":"{revision}","relative_path":"guide.txt","status":"pending","unexpected":true}}}},"admitted_notice_timestamps_unix":[]}}"#
        );
        let path = home.path().join(STATE_FILE);
        std::fs::write(&path, &state).expect("state");
        assert!(list_pending(home.path()).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).expect("state retained"),
            state
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_leaf_is_never_discovered() {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir().expect("home");
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        let outside_file = outside.path().join("outside.txt");
        std::fs::write(&outside_file, b"outside").expect("outside file");
        symlink(&outside_file, root.path().join("linked.txt")).expect("link");
        scan_once(home.path(), &config(root.path(), 1), None, 100).expect("scan");
        assert!(list_pending(home.path()).expect("pending").is_empty());
    }
}
