//! Daemon-owned filesystem invalidation for explicitly managed code-map roots.
//!
//! `notify` is an optimization that marks a root dirty. It is never a
//! freshness authority: every refresh still uses the lifecycle service's
//! bounded strong inspection before a receipt says a generation is reusable.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use notify::{Event, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::code_map::lifecycle::{
    LifecycleCancellation, LifecycleRefreshOptions, RefreshCause, reconcile, refresh,
};
use crate::config::CodeMapLifecycleConfig;

const MAX_REFRESH_FAILURE_RETRIES: u32 = 3;
const RETRY_BACKOFF: Duration = Duration::from_secs(5);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(60);
const STATUS_SCHEMA_VERSION: u32 = 1;
const STATUS_MAX_BYTES: u64 = 64 * 1024;
const STATUS_MAX_ERROR_CHARS: usize = 1_024;

/// The durable filename is instance-scoped rather than process-CWD scoped.
pub(crate) const CODE_MAP_LIFECYCLE_STATUS_FILE: &str = "code_map_lifecycle_status.json";

/// The runtime state deliberately reports observed ownership, not merely the
/// configuration that requested it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CodeMapLifecycleRuntimeState {
    Running,
    Stopping,
    Stopped,
}

/// Cross-process, read-only lifecycle status. `requested_*` is the accepted
/// configuration generation; `active_roots` proves only roots whose watcher
/// construction and startup reconciliation completed in this daemon boot.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CodeMapLifecycleRuntimeStatus {
    pub schema_version: u32,
    pub instance_home: PathBuf,
    pub boot_id: String,
    pub daemon_pid: u32,
    /// Accepted requested generation. It may advance while a prior active
    /// generation is being cancelled and joined during a root replacement.
    pub config_generation: u64,
    /// Generation that owns `active_roots` and worker-originated diagnostics.
    pub active_config_generation: Option<u64>,
    pub observed_unix_millis: u64,
    pub state: CodeMapLifecycleRuntimeState,
    pub requested_enabled: bool,
    pub requested_roots: Vec<PathBuf>,
    pub requested_config_fingerprint_sha256: String,
    /// A requested enabled generation can be persisted while its roots are
    /// temporarily unavailable. The supervisor retains any prior active set
    /// and records that activation boundary here rather than claiming success.
    #[serde(default)]
    pub requested_activation_diagnostic: Option<String>,
    pub active_roots: Vec<PathBuf>,
    pub active_config_fingerprint_sha256: Option<String>,
    pub active_refresh_attempts: u32,
    pub last_error: Option<String>,
    pub last_reconcile_unix_millis: Option<u64>,
    pub last_reconcile_root: Option<PathBuf>,
}

/// Serializes same-process writers before atomically replacing the status
/// file, so concurrent root workers cannot publish torn or mixed snapshots.
#[derive(Clone)]
pub(crate) struct CodeMapLifecycleStatusWriter {
    path: PathBuf,
    snapshot: Arc<Mutex<CodeMapLifecycleRuntimeStatus>>,
}

fn read_status_body(reader: impl Read) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    reader.take(STATUS_MAX_BYTES + 1).read_to_end(&mut body)?;
    anyhow::ensure!(
        body.len() as u64 <= STATUS_MAX_BYTES,
        "code-map lifecycle status exceeds {} bytes",
        STATUS_MAX_BYTES
    );
    Ok(body)
}

impl CodeMapLifecycleStatusWriter {
    pub(crate) fn new(
        instance_home: &Path,
        config: &CodeMapLifecycleConfig,
        generation: u64,
    ) -> Self {
        Self {
            path: instance_home.join(CODE_MAP_LIFECYCLE_STATUS_FILE),
            snapshot: Arc::new(Mutex::new(CodeMapLifecycleRuntimeStatus {
                schema_version: STATUS_SCHEMA_VERSION,
                instance_home: instance_home.to_path_buf(),
                boot_id: uuid::Uuid::now_v7().to_string(),
                daemon_pid: std::process::id(),
                config_generation: generation,
                active_config_generation: None,
                observed_unix_millis: now_unix_millis(),
                state: CodeMapLifecycleRuntimeState::Running,
                requested_enabled: config.enabled,
                requested_roots: config.managed_roots.clone(),
                requested_config_fingerprint_sha256: lifecycle_config_fingerprint(config),
                requested_activation_diagnostic: None,
                active_roots: Vec::new(),
                active_config_fingerprint_sha256: None,
                active_refresh_attempts: 0,
                last_error: None,
                last_reconcile_unix_millis: None,
                last_reconcile_root: None,
            })),
        }
    }

    /// Reads only a currently lock-proven daemon status for this exact
    /// instance. A retained status from a crashed process is rejected even
    /// when its JSON is otherwise well formed.
    pub(crate) fn read_active(
        instance_home: &Path,
    ) -> Result<Option<CodeMapLifecycleRuntimeStatus>> {
        let path = instance_home.join(CODE_MAP_LIFECYCLE_STATUS_FILE);
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("stat {}", path.display()))?;
        if metadata.len() > STATUS_MAX_BYTES {
            anyhow::bail!(
                "code-map lifecycle status {} exceeds {} bytes",
                path.display(),
                STATUS_MAX_BYTES
            );
        }
        let body = read_status_body(file).with_context(|| format!("read {}", path.display()))?;
        let status: CodeMapLifecycleRuntimeStatus =
            serde_json::from_slice(&body).with_context(|| format!("parse {}", path.display()))?;
        if status.schema_version != STATUS_SCHEMA_VERSION
            || status.instance_home != instance_home
            || uuid::Uuid::parse_str(&status.boot_id).is_err()
            || status.state != CodeMapLifecycleRuntimeState::Running
        {
            return Ok(None);
        }
        let pidfile = instance_home.join("neothd.pid");
        if crate::daemon::pidfile::live_daemon_pid(&pidfile)? != Some(status.daemon_pid) {
            return Ok(None);
        }
        Ok(Some(status))
    }

    pub(crate) fn publish_requested(&self, config: &CodeMapLifecycleConfig, generation: u64) {
        self.update(|status| {
            status.config_generation = generation;
            status.requested_enabled = config.enabled;
            status.requested_roots = config.managed_roots.clone();
            status.requested_config_fingerprint_sha256 = lifecycle_config_fingerprint(config);
            status.requested_activation_diagnostic = None;
        });
    }

    /// Promote a requested generation only after the prior worker set joined.
    /// All worker-originated updates carry this token, preventing a removed
    /// root from writing stale refresh state into a replacement generation.
    pub(crate) fn activate_generation(&self, generation: u64) {
        self.update(|status| {
            status.active_config_generation = Some(generation);
            status.active_config_fingerprint_sha256 =
                Some(status.requested_config_fingerprint_sha256.clone());
            status.active_roots.clear();
            status.active_refresh_attempts = 0;
            status.last_error = None;
            status.last_reconcile_unix_millis = None;
            status.last_reconcile_root = None;
            status.requested_activation_diagnostic = None;
            status.state = CodeMapLifecycleRuntimeState::Running;
        });
    }

    pub(crate) fn publish_active_roots(&self, generation: u64, roots: Vec<PathBuf>) {
        self.update_for_active_generation(generation, |status| status.active_roots = roots);
    }

    pub(crate) fn record_error_for(&self, generation: u64, error: impl std::fmt::Display) {
        let error = bounded_error(error.to_string());
        self.update_for_active_generation(generation, |status| status.last_error = Some(error));
    }

    pub(crate) fn record_requested_activation_diagnostic(&self, error: impl std::fmt::Display) {
        let error = bounded_error(error.to_string());
        self.update(|status| status.requested_activation_diagnostic = Some(error));
    }

    pub(crate) fn record_reconcile_for(&self, generation: u64, root: &Path) {
        let root = root.to_path_buf();
        self.update_for_active_generation(generation, |status| {
            status.last_reconcile_unix_millis = Some(now_unix_millis());
            status.last_reconcile_root = Some(root);
        });
    }

    pub(crate) fn refresh_started_for(&self, generation: u64) {
        self.update_for_active_generation(generation, |status| {
            status.active_refresh_attempts = status.active_refresh_attempts.saturating_add(1)
        });
    }

    pub(crate) fn refresh_finished_for(&self, generation: u64) {
        self.update_for_active_generation(generation, |status| {
            status.active_refresh_attempts = status.active_refresh_attempts.saturating_sub(1)
        });
    }

    pub(crate) fn publish_stopping(&self) {
        self.update(|status| status.state = CodeMapLifecycleRuntimeState::Stopping);
    }

    pub(crate) fn publish_stopped(&self) {
        self.update(|status| {
            status.state = CodeMapLifecycleRuntimeState::Stopped;
            status.active_roots.clear();
            status.active_refresh_attempts = 0;
            status.active_config_generation = None;
            status.active_config_fingerprint_sha256 = None;
        });
    }

    fn update_for_active_generation(
        &self,
        generation: u64,
        mutate: impl FnOnce(&mut CodeMapLifecycleRuntimeStatus),
    ) {
        self.update_if(
            |status| status.active_config_generation == Some(generation),
            mutate,
        );
    }

    fn update(&self, mutate: impl FnOnce(&mut CodeMapLifecycleRuntimeStatus)) {
        self.update_if(|_| true, mutate);
    }

    fn update_if(
        &self,
        should_update: impl FnOnce(&CodeMapLifecycleRuntimeStatus) -> bool,
        mutate: impl FnOnce(&mut CodeMapLifecycleRuntimeStatus),
    ) {
        // Keep the process-local status lock through the atomic replacement.
        // Releasing it after serialization would allow a later state to land
        // first and then be overwritten by this older payload.
        let mut status = self
            .snapshot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !should_update(&status) {
            return;
        }
        mutate(&mut status);
        status.observed_unix_millis = now_unix_millis();
        let body = match serde_json::to_vec(&*status) {
            Ok(body) => body,
            Err(error) => {
                warn!(error = %error, "serialize code-map lifecycle status failed");
                return;
            }
        };
        if let Err(error) = crate::util::atomic_write::atomic_write_private(&self.path, &body) {
            warn!(path = %self.path.display(), error = %error, "persist code-map lifecycle status failed");
        }
    }
}

/// Read the lifecycle status only when it is still owned by the live daemon
/// for this exact instance home. Stale, stopped, malformed, and foreign-home
/// snapshots return `Ok(None)` rather than claiming an active watcher.
pub fn read_active_code_map_lifecycle_status(
    instance_home: &Path,
) -> Result<Option<CodeMapLifecycleRuntimeStatus>> {
    CodeMapLifecycleStatusWriter::read_active(instance_home)
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn bounded_error(error: String) -> String {
    error.chars().take(STATUS_MAX_ERROR_CHARS).collect()
}

fn lifecycle_config_fingerprint(config: &CodeMapLifecycleConfig) -> String {
    let mut hasher = Sha256::new();
    hasher.update([u8::from(config.enabled)]);
    hasher.update(config.debounce_millis.to_le_bytes());
    hasher.update(config.reconciliation_interval_secs.to_le_bytes());
    for root in &config.managed_roots {
        hasher.update(root.to_string_lossy().as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

enum WatchSignal {
    Event(Event),
    BackendError(notify::Error),
}

/// One recursive watcher and its real synchronous lifecycle-refresh worker.
/// The worker owns every refresh call; [`Self::shutdown`] signals the shared
/// cancellation token and joins that worker before returning.
pub(crate) struct CodeMapLifecycleWatcher {
    root: PathBuf,
    cancellation: LifecycleCancellation,
    stop_tx: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
    // Kept alive for the same lifetime as the worker. Dropping a
    // RecommendedWatcher first would silently stop invalidations while the
    // worker continued to report periodic reconciliation only.
    watcher: notify::RecommendedWatcher,
}

impl CodeMapLifecycleWatcher {
    pub(crate) fn start(
        database_path: PathBuf,
        root: PathBuf,
        debounce: Duration,
        reconciliation_interval: Duration,
        status: Option<CodeMapLifecycleStatusWriter>,
        status_generation: u64,
    ) -> Result<Self> {
        let cancellation = LifecycleCancellation::new();

        // Reconcile an abandoned durable attempt before the callback can mark
        // the root dirty. A startup failure is visible and retried through the
        // bounded worker policy after the watch is registered; it does not
        // create a detached refresh or claim a fresh snapshot.
        let retry_startup = match reconcile(&database_path, &root, &cancellation) {
            Ok(receipt) => {
                if let Some(status) = &status {
                    status.record_reconcile_for(status_generation, &root);
                }
                info!(
                    root = %root.display(),
                    outcome = ?receipt.outcome,
                    "code-map lifecycle startup reconciliation completed"
                );
                false
            }
            Err(error) => {
                if let Some(status) = &status {
                    status.record_error_for(status_generation, &error);
                }
                warn!(
                    root = %root.display(),
                    error = %error,
                    "code-map lifecycle startup reconciliation failed; watcher will retry"
                );
                true
            }
        };

        // Filesystem notifications are only dirty hints. Bound the callback
        // queue and drop excess duplicates while a slow refresh owns the
        // worker; the periodic strong reconciliation still detects misses.
        let (event_tx, event_rx) = mpsc::sync_channel(256);
        let mut watcher = notify::recommended_watcher(move |result| {
            let signal = match result {
                Ok(event) => WatchSignal::Event(event),
                Err(error) => WatchSignal::BackendError(error),
            };
            // The receiver ends only after shutdown; callbacks cannot perform
            // refresh IO or retain authority once the worker has joined.
            let _ = event_tx.try_send(signal);
        })
        .context("construct code-map lifecycle filesystem watcher")?;
        watcher
            .watch(&root, RecursiveMode::Recursive)
            .with_context(|| format!("watch managed code-map root {}", root.display()))?;

        let (stop_tx, stop_rx) = mpsc::channel();
        let worker_cancellation = cancellation.clone();
        let worker_root = root.clone();
        let worker = thread::Builder::new()
            .name("neoth-code-map-lifecycle".to_string())
            .spawn(move || {
                run_worker(WorkerInputs {
                    database_path,
                    root: worker_root,
                    debounce,
                    reconciliation_interval,
                    retry_startup,
                    event_rx,
                    stop_rx,
                    cancellation: worker_cancellation,
                    status,
                    status_generation,
                });
            })
            .context("start code-map lifecycle worker")?;

        Ok(Self {
            root,
            cancellation,
            stop_tx,
            worker: Some(worker),
            watcher,
        })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Cancel the actual scan/build/publish path and wait for that worker. This
    /// is intentionally stronger than aborting an async wrapper around a
    /// blocking refresh, which could otherwise leave a detached publisher.
    pub(crate) fn shutdown(&mut self) -> Result<()> {
        self.cancellation.cancel();
        let _ = self.stop_tx.send(());
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("code-map lifecycle worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for CodeMapLifecycleWatcher {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.cancellation.cancel();
            let _ = self.stop_tx.send(());
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
        // Make the retained ownership explicit for Clippy and readers.
        let _ = &self.watcher;
    }
}

/// Bounded set of daemon watchers derived from one accepted config snapshot.
/// Construction validates and canonicalizes every configured root before any
/// watcher is retained; a partial start is shut down before its error returns.
pub(crate) struct CodeMapLifecycleWatchers {
    watchers: Vec<CodeMapLifecycleWatcher>,
}

impl CodeMapLifecycleWatchers {
    pub(crate) fn disabled() -> Self {
        Self {
            watchers: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn start(database_path: &Path, config: &CodeMapLifecycleConfig) -> Result<Self> {
        Self::start_with_status(database_path, config, None, 0)
    }

    pub(crate) fn start_with_status(
        database_path: &Path,
        config: &CodeMapLifecycleConfig,
        status: Option<CodeMapLifecycleStatusWriter>,
        status_generation: u64,
    ) -> Result<Self> {
        if !config.enabled {
            return Ok(Self::disabled());
        }
        let roots = config.canonical_managed_roots()?;
        let debounce = Duration::from_millis(config.debounce_millis);
        let reconciliation_interval = Duration::from_secs(config.reconciliation_interval_secs);
        let mut watchers = Vec::with_capacity(roots.len());
        for root in roots {
            match CodeMapLifecycleWatcher::start(
                database_path.to_path_buf(),
                root.path().to_path_buf(),
                debounce,
                reconciliation_interval,
                status.clone(),
                status_generation,
            ) {
                Ok(watcher) => watchers.push(watcher),
                Err(error) => {
                    let mut partial = Self { watchers };
                    let _ = partial.shutdown();
                    return Err(error);
                }
            }
        }
        Ok(Self { watchers })
    }

    pub(crate) fn is_disabled(&self) -> bool {
        self.watchers.is_empty()
    }

    pub(crate) fn roots(&self) -> impl Iterator<Item = &Path> {
        self.watchers.iter().map(CodeMapLifecycleWatcher::root)
    }

    pub(crate) fn shutdown(&mut self) -> Result<()> {
        let mut first_error = None;
        for watcher in &mut self.watchers {
            if let Err(error) = watcher.shutdown() {
                warn!(root = %watcher.root().display(), error = %error, "code-map lifecycle watcher shutdown failed");
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        self.watchers.clear();
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }
}

/// Every owned input transferred from the watcher constructor to exactly one
/// synchronous worker. Grouping them makes the ownership/cancellation
/// boundary explicit without splitting status from the refresh it describes.
struct WorkerInputs {
    database_path: PathBuf,
    root: PathBuf,
    debounce: Duration,
    reconciliation_interval: Duration,
    retry_startup: bool,
    event_rx: mpsc::Receiver<WatchSignal>,
    stop_rx: mpsc::Receiver<()>,
    cancellation: LifecycleCancellation,
    status: Option<CodeMapLifecycleStatusWriter>,
    status_generation: u64,
}

fn run_worker(inputs: WorkerInputs) {
    let WorkerInputs {
        database_path,
        root,
        debounce,
        reconciliation_interval,
        retry_startup,
        event_rx,
        stop_rx,
        cancellation,
        status,
        status_generation,
    } = inputs;
    let mut dirty_after: Option<Instant> = retry_startup.then(Instant::now);
    let mut retry_after: Option<Instant> = None;
    let mut next_reconciliation = Instant::now() + reconciliation_interval;
    let mut failures: u32 = 0;

    loop {
        if cancellation.is_cancelled() || stop_rx.try_recv().is_ok() {
            debug!(root = %root.display(), "code-map lifecycle worker stopping");
            break;
        }

        let now = Instant::now();
        let deadline = [dirty_after, retry_after, Some(next_reconciliation)]
            .into_iter()
            .flatten()
            .min()
            .expect("reconciliation deadline is always present");
        // The notify callback queue carries only dirty hints, while `stop_rx`
        // is a distinct control channel. Bound this wait so cancellation and
        // reload removal are observed promptly even when no filesystem event
        // arrives and reconciliation is configured for its longest interval.
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(100));
        match event_rx.recv_timeout(wait) {
            Ok(WatchSignal::Event(event)) => {
                if event_is_root_relevant(&event, &root) {
                    dirty_after = Some(debounce_deadline(Instant::now(), debounce));
                    // A new source event supersedes a failed retry schedule.
                    retry_after = None;
                    failures = 0;
                }
            }
            Ok(WatchSignal::BackendError(error)) => {
                warn!(
                    root = %root.display(),
                    error = %error,
                    "code-map lifecycle watcher backend error; scheduling bounded refresh retry"
                );
                dirty_after = Some(debounce_deadline(Instant::now(), debounce));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                warn!(root = %root.display(), "code-map lifecycle watcher callback channel closed");
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }

        if cancellation.is_cancelled() || stop_rx.try_recv().is_ok() {
            break;
        }
        let now = Instant::now();
        let cause = if dirty_after.is_some_and(|deadline| deadline <= now) {
            dirty_after = None;
            Some(RefreshCause::FilesystemInvalidation)
        } else if retry_after.is_some_and(|deadline| deadline <= now) {
            retry_after = None;
            Some(RefreshCause::FilesystemInvalidation)
        } else if next_reconciliation <= now {
            next_reconciliation = now + reconciliation_interval;
            Some(RefreshCause::PeriodicReconciliation)
        } else {
            None
        };
        let Some(cause) = cause else {
            continue;
        };

        if let Some(status) = &status {
            status.refresh_started_for(status_generation);
        }
        let result = refresh(
            &database_path,
            &root,
            LifecycleRefreshOptions {
                force: false,
                repair_corrupt: false,
                cause,
            },
            &cancellation,
        );
        if let Some(status) = &status {
            status.refresh_finished_for(status_generation);
        }
        match result {
            Ok(receipt) => {
                failures = 0;
                if let Some(status) = &status {
                    status.record_reconcile_for(status_generation, &root);
                }
                info!(
                    root = %root.display(),
                    cause = ?receipt.cause,
                    outcome = ?receipt.outcome,
                    "code-map lifecycle refresh completed"
                );
            }
            Err(error) if cancellation.is_cancelled() => {
                debug!(root = %root.display(), error = %error, "code-map lifecycle refresh cancelled");
                break;
            }
            Err(error) => {
                failures = failures.saturating_add(1);
                if let Some(status) = &status {
                    status.record_error_for(status_generation, &error);
                }
                warn!(
                    root = %root.display(),
                    failures,
                    max_failures = MAX_REFRESH_FAILURE_RETRIES,
                    error = %error,
                    "code-map lifecycle refresh failed"
                );
                if failures <= MAX_REFRESH_FAILURE_RETRIES {
                    let multiplier = u64::from(failures);
                    retry_after = Some(
                        Instant::now()
                            + RETRY_BACKOFF
                                .checked_mul(multiplier as u32)
                                .unwrap_or(MAX_RETRY_BACKOFF)
                                .min(MAX_RETRY_BACKOFF),
                    );
                } else {
                    warn!(
                        root = %root.display(),
                        "code-map lifecycle retry budget exhausted; waiting for the next strong reconciliation or a new dirty event"
                    );
                }
            }
        }
    }
}

fn event_is_root_relevant(_event: &Event, _root: &Path) -> bool {
    // This callback belongs to exactly one already-canonical root watcher.
    // `notify` may spell a delivered in-root path through a lexical alias or
    // platform-specific case without allowing canonicalization of deleted
    // files. Every callback therefore safely marks only this watcher's root
    // dirty; strong refresh is still the sole freshness proof.
    true
}

fn debounce_deadline(now: Instant, debounce: Duration) -> Instant {
    now + debounce
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use notify::{Event, EventKind, event::ModifyKind};

    use super::{CodeMapLifecycleStatusWriter, debounce_deadline, event_is_root_relevant};
    use crate::config::CodeMapLifecycleConfig;

    #[test]
    fn status_stream_read_is_bounded_even_without_a_stable_reported_length() {
        let error = super::read_status_body(std::io::repeat(b' ')).unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        assert_eq!(super::read_status_body(&b"{}"[..]).unwrap(), b"{}");
    }

    #[test]
    fn root_owned_watcher_marks_its_delivered_events_dirty() {
        let root_a = tempfile::tempdir().unwrap();
        let event = Event::new(EventKind::Modify(ModifyKind::Any))
            .add_path(root_a.path().join("src/lib.rs"));
        assert!(event_is_root_relevant(&event, root_a.path()));
    }

    #[test]
    fn root_owned_watcher_accepts_lexically_aliased_in_root_events() {
        let root = tempfile::tempdir().unwrap();
        let event = Event::new(EventKind::Modify(ModifyKind::Any))
            .add_path(root.path().join("nested/../file.rs"));
        assert!(event_is_root_relevant(&event, root.path()));
    }

    #[test]
    fn later_dirty_event_replaces_the_pending_debounce_deadline() {
        let first = Instant::now();
        let first_deadline = debounce_deadline(first, Duration::from_millis(50));
        let second_deadline = debounce_deadline(first_deadline, Duration::from_millis(50));
        assert!(second_deadline > first_deadline);
    }

    #[test]
    fn durable_status_requires_the_live_instance_pid_lock() {
        let home = tempfile::tempdir().unwrap();
        let config = CodeMapLifecycleConfig::default();
        let status = CodeMapLifecycleStatusWriter::new(home.path(), &config, 7);
        let guard = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        status.publish_requested(&config, 7);
        let live = CodeMapLifecycleStatusWriter::read_active(home.path()).unwrap();
        assert_eq!(live.unwrap().config_generation, 7);
        drop(guard);
        assert!(
            CodeMapLifecycleStatusWriter::read_active(home.path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn stale_worker_generation_cannot_roll_back_replaced_status() {
        let home = tempfile::tempdir().unwrap();
        let config = CodeMapLifecycleConfig::default();
        let status = CodeMapLifecycleStatusWriter::new(home.path(), &config, 7);
        let _guard = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        let old_root = home.path().join("old-root");
        let new_root = home.path().join("new-root");

        status.publish_requested(&config, 7);
        status.activate_generation(7);
        status.publish_active_roots(7, vec![old_root]);
        status.publish_requested(&config, 8);
        status.record_error_for(7, "old worker is still joining");
        status.activate_generation(8);
        status.record_error_for(7, "stale worker must be ignored");
        status.publish_active_roots(8, vec![new_root.clone()]);

        let observed = CodeMapLifecycleStatusWriter::read_active(home.path())
            .unwrap()
            .unwrap();
        assert_eq!(observed.config_generation, 8);
        assert_eq!(observed.active_config_generation, Some(8));
        assert_eq!(observed.active_roots, vec![new_root]);
        assert!(observed.last_error.is_none());
    }
}
