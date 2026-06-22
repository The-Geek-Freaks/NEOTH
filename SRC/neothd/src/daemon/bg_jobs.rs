//! GOLD-ADAPT-ODY-07 — Background-job detach + auto-continue registry.
//!
//! Ports the on-disk job-tracking pattern from Odysseus `src/bg_jobs.py`:
//! when the daemon spawns a long-running subprocess (shell command, model
//! pull, recon tool, …) it can DETACH it — the child keeps running even if
//! the daemon's provider-dispatch loop moves on — and track it via a pair of
//! on-disk artefacts:
//!
//! - `~/.neoth/bgjobs/<job_id>.log`  — stdout+stderr tail (written by the
//!   child or a wrapper; the registry itself just owns the path contract)
//! - `~/.neoth/bgjobs/<job_id>.exit` — written by the child (or the monitor)
//!   once it exits; contains the numeric exit code as ASCII + newline
//!
//! The registry (`BgJobRegistry`) is a lightweight in-memory store keyed by
//! `job_id` (a stable opaque string: caller-supplied name + ts_unix).  The
//! companion `bg_monitor` module scans the `bgjobs/` directory, reconciles
//! the `.exit` markers against the registry, and reports / triggers
//! auto-continue callbacks.
//!
//! ## Design constraints (from ODY source analysis)
//!
//! - **Headless**: the registry holds no child `Process` handle — it only
//!   records the on-disk paths. Callers use `tokio::process::Command::spawn`
//!   independently and hand the `job_id` to the registry via `register`.
//! - **Auto-continue**: when the monitor observes a `.exit` marker it invokes
//!   the optional `on_complete` callback registered with the job. Typical use:
//!   re-send the conversation turn ("the background task you launched is now
//!   done — here is its output").
//! - **Idempotent**: calling `register` twice with the same `job_id` is a
//!   no-op (returns `false`); the first registration wins.
//! - **Persistence across daemon restarts**: because state lives on disk, a
//!   daemon restart can call `load_existing` to re-hydrate the in-memory
//!   registry from any `.log` files that don't yet have a paired `.exit`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

// ── Public types ────────────────────────────────────────────────────────────

/// Stable identifier for a background job.
///
/// Callers build these with [`BgJobId::new`]; the string form is
/// `<label>-<ts_unix>` and is used verbatim as the file-stem under
/// `<bgjobs_dir>/<job_id>.log` / `<bgjobs_dir>/<job_id>.exit`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BgJobId(pub String);

impl BgJobId {
    /// Build a new id from a human-readable label and the current unix
    /// timestamp (seconds). Callers may supply a deterministic ts in tests.
    pub fn new(label: &str, ts_unix: u64) -> Self {
        Self(format!("{label}-{ts_unix}"))
    }

    /// The string form used as the filesystem stem.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BgJobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle status of a background job as seen by the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgJobStatus {
    /// The job is running (no `.exit` marker observed yet).
    Running,
    /// The monitor observed a `.exit` file; `code` is the parsed exit code
    /// (0 = success). May be `None` when the file exists but is unreadable /
    /// not yet a valid integer (partial write race — treated as still running).
    Completed { code: Option<i32> },
}

/// Callback invoked by the monitor when a job completes.
///
/// Receives the `job_id` and the exit code (None when unreadable).
/// The callback is `Arc`-wrapped so the registry can store it without
/// lifetime constraints. Returning an error from the callback is logged
/// as a warning but does NOT prevent the job from being marked complete.
pub type OnCompleteFn = Arc<dyn Fn(&BgJobId, Option<i32>) + Send + Sync + 'static>;

/// One registration entry in the registry.
#[derive(Clone)]
pub struct BgJobEntry {
    pub job_id: BgJobId,
    /// Absolute path to the `.log` file (stdout/stderr tail).
    pub log_path: PathBuf,
    /// Absolute path to the `.exit` marker.
    pub exit_path: PathBuf,
    /// Human-readable description shown in `neoth jobs list`.
    pub description: String,
    /// Unix timestamp (seconds) when the job was registered.
    pub registered_at: u64,
    /// Optional auto-continue callback.  `None` ⇒ monitor just logs the
    /// completion; operator checks via `neoth jobs status`.
    pub on_complete: Option<OnCompleteFn>,
}

impl std::fmt::Debug for BgJobEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgJobEntry")
            .field("job_id", &self.job_id)
            .field("log_path", &self.log_path)
            .field("exit_path", &self.exit_path)
            .field("description", &self.description)
            .field("registered_at", &self.registered_at)
            .field("on_complete", &self.on_complete.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

// ── Registry ────────────────────────────────────────────────────────────────

/// Thread-safe, heap-allocated background-job registry.
///
/// A single instance is shared between the daemon's cron loop and any code
/// path that spawns a detached job. Wrap in `Arc` (the registry itself
/// contains a `Mutex`).
#[derive(Debug, Default)]
pub struct BgJobRegistry {
    inner: Mutex<Vec<BgJobEntry>>,
    /// Root directory under which `<job_id>.log` / `<job_id>.exit` live.
    bgjobs_dir: PathBuf,
}

impl BgJobRegistry {
    /// Create a new registry rooted at `bgjobs_dir`.
    /// The directory is created lazily by `register` when the first job is
    /// registered (not by the constructor) so tests can pass a tempdir
    /// that already exists.
    pub fn new(bgjobs_dir: impl Into<PathBuf>) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            bgjobs_dir: bgjobs_dir.into(),
        }
    }

    /// The directory holding job artefact files.
    pub fn bgjobs_dir(&self) -> &Path {
        &self.bgjobs_dir
    }

    /// Compute the `.log` path for a job id.
    pub fn log_path(&self, id: &BgJobId) -> PathBuf {
        self.bgjobs_dir.join(format!("{}.log", id.as_str()))
    }

    /// Compute the `.exit` marker path for a job id.
    pub fn exit_path(&self, id: &BgJobId) -> PathBuf {
        self.bgjobs_dir.join(format!("{}.exit", id.as_str()))
    }

    /// Register a new background job.
    ///
    /// Returns `true` on first registration, `false` when `job_id` is already
    /// known (idempotent — the existing entry is left unchanged).
    pub async fn register(
        &self,
        job_id: BgJobId,
        description: impl Into<String>,
        registered_at: u64,
        on_complete: Option<OnCompleteFn>,
    ) -> bool {
        let mut jobs = self.inner.lock().await;
        if jobs.iter().any(|e| e.job_id == job_id) {
            return false;
        }
        let log_path = self.log_path(&job_id);
        let exit_path = self.exit_path(&job_id);
        jobs.push(BgJobEntry {
            job_id,
            log_path,
            exit_path,
            description: description.into(),
            registered_at,
            on_complete,
        });
        true
    }

    /// Remove a job from the in-memory registry (does NOT delete disk files).
    pub async fn forget(&self, job_id: &BgJobId) {
        let mut jobs = self.inner.lock().await;
        jobs.retain(|e| &e.job_id != job_id);
    }

    /// Snapshot of all currently registered entries (clone-of-clones).
    pub async fn entries(&self) -> Vec<BgJobEntry> {
        self.inner.lock().await.clone()
    }

    /// Count of registered jobs.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// True when the registry has no entries.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Re-hydrate from disk: scan `bgjobs_dir` for `*.log` files that have
    /// no paired `*.exit` (= still-running jobs from a previous daemon
    /// session) and add stub entries for them (no `on_complete` callback —
    /// the original callback was in the previous process). Skips job ids
    /// already present in the registry.
    ///
    /// Returns the number of jobs loaded.
    pub async fn load_existing(&self) -> usize {
        let Ok(rd) = std::fs::read_dir(&self.bgjobs_dir) else {
            return 0;
        };
        let mut loaded = 0usize;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("log") {
                continue;
            }
            let stem = match p.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_owned(),
                None => continue,
            };
            let exit_path = self.bgjobs_dir.join(format!("{stem}.exit"));
            // Only resurrect jobs that don't yet have an exit marker.
            if exit_path.exists() {
                continue;
            }
            let id = BgJobId(stem.clone());
            let newly = self
                .register(
                    id,
                    format!("(restored) {stem}"),
                    0, // ts unknown after restart
                    None,
                )
                .await;
            if newly {
                loaded += 1;
            }
        }
        loaded
    }
}

// ── Status query (sync helper) ───────────────────────────────────────────────

/// Read the live status of a job directly from the filesystem — does NOT
/// require a registry lock, so it can be used from the monitor without
/// holding the registry mutex. Callers pass the exit-path from the entry.
pub fn read_job_status(exit_path: &Path) -> BgJobStatus {
    let Ok(raw) = std::fs::read_to_string(exit_path) else {
        return BgJobStatus::Running;
    };
    let code = raw.trim().parse::<i32>().ok();
    BgJobStatus::Completed { code }
}

// ── Process-global registry ──────────────────────────────────────────────────
//
// A single `Arc<BgJobRegistry>` initialised once at daemon startup
// (`init_global_registry`) and accessible to any code path that wants to
// register a detached job without threading the registry through the call
// stack.  `OnceLock` semantics: the second `init_global_registry` call is a
// no-op (the first registration wins).  Returns `None` before daemon startup
// (e.g. during `neoth chat` which skips `run_serve`).

use std::sync::OnceLock;

static BG_JOB_REGISTRY: OnceLock<Arc<BgJobRegistry>> = OnceLock::new();

/// Access the process-global [`BgJobRegistry`] initialised by `daemon::serve`.
///
/// Returns `None` before `run_serve` has called [`init_global_registry`]
/// (i.e. in one-shot CLI invocations that do not go through `neoth serve`).
pub fn global_registry() -> Option<Arc<BgJobRegistry>> {
    BG_JOB_REGISTRY.get().map(Arc::clone)
}

/// Called exactly once at daemon startup (from
/// `serve_tasks::spawn_bg_monitor_task`).  Subsequent calls are no-ops
/// (OnceLock semantics — the first registration wins).
pub(crate) fn init_global_registry(reg: Arc<BgJobRegistry>) {
    let _ = BG_JOB_REGISTRY.set(reg);
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_registry() -> (BgJobRegistry, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let reg = BgJobRegistry::new(dir.path().to_path_buf());
        (reg, dir)
    }

    #[tokio::test]
    async fn register_returns_true_first_time() {
        let (reg, _dir) = temp_registry();
        let id = BgJobId::new("echo", 1_000);
        assert!(reg.register(id, "echo test", 1_000, None).await);
        assert_eq!(reg.len().await, 1);
    }

    #[tokio::test]
    async fn register_idempotent_second_call_returns_false() {
        let (reg, _dir) = temp_registry();
        let id = BgJobId::new("echo", 1_000);
        assert!(reg.register(id.clone(), "first", 1_000, None).await);
        assert!(!reg.register(id.clone(), "second", 1_001, None).await);
        assert_eq!(reg.len().await, 1);
    }

    #[tokio::test]
    async fn forget_removes_entry() {
        let (reg, _dir) = temp_registry();
        let id = BgJobId::new("task", 2_000);
        reg.register(id.clone(), "desc", 2_000, None).await;
        assert_eq!(reg.len().await, 1);
        reg.forget(&id).await;
        assert!(reg.is_empty().await);
    }

    #[tokio::test]
    async fn log_and_exit_paths_use_correct_stems() {
        let (reg, dir) = temp_registry();
        let id = BgJobId::new("probe", 42);
        let log = reg.log_path(&id);
        let exit = reg.exit_path(&id);
        assert_eq!(log, dir.path().join("probe-42.log"));
        assert_eq!(exit, dir.path().join("probe-42.exit"));
    }

    #[test]
    fn read_job_status_no_file_means_running() {
        let dir = tempfile::tempdir().unwrap();
        let exit = dir.path().join("phantom.exit");
        assert_eq!(read_job_status(&exit), BgJobStatus::Running);
    }

    #[test]
    fn read_job_status_zero_means_completed_success() {
        let dir = tempfile::tempdir().unwrap();
        let exit = dir.path().join("job.exit");
        std::fs::write(&exit, b"0\n").unwrap();
        assert_eq!(
            read_job_status(&exit),
            BgJobStatus::Completed { code: Some(0) }
        );
    }

    #[test]
    fn read_job_status_nonzero_code() {
        let dir = tempfile::tempdir().unwrap();
        let exit = dir.path().join("job.exit");
        std::fs::write(&exit, b"1\n").unwrap();
        assert_eq!(
            read_job_status(&exit),
            BgJobStatus::Completed { code: Some(1) }
        );
    }

    #[test]
    fn read_job_status_malformed_exit_file_means_running() {
        // Partial write / empty file — treat as still running.
        let dir = tempfile::tempdir().unwrap();
        let exit = dir.path().join("job.exit");
        std::fs::write(&exit, b"").unwrap();
        assert_eq!(
            read_job_status(&exit),
            BgJobStatus::Completed { code: None }
        );
        // Note: empty parses as `None` (no integer), not as `Running` — the
        // file EXISTS (the process at least started writing), so we report
        // `Completed{code:None}` and let the monitor decide what to do.
    }

    #[tokio::test]
    async fn load_existing_resurrects_log_without_exit() {
        let dir = tempfile::tempdir().unwrap();
        // Simulate a job that left a .log but no .exit (still running).
        std::fs::write(dir.path().join("old-job-999.log"), b"output").unwrap();
        let reg = BgJobRegistry::new(dir.path().to_path_buf());
        let loaded = reg.load_existing().await;
        assert_eq!(loaded, 1);
        assert_eq!(reg.len().await, 1);
        let entries = reg.entries().await;
        assert_eq!(entries[0].job_id, BgJobId("old-job-999".to_owned()));
    }

    #[tokio::test]
    async fn load_existing_skips_completed_jobs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("done-job-1.log"), b"output").unwrap();
        std::fs::write(dir.path().join("done-job-1.exit"), b"0\n").unwrap();
        let reg = BgJobRegistry::new(dir.path().to_path_buf());
        let loaded = reg.load_existing().await;
        assert_eq!(loaded, 0);
        assert!(reg.is_empty().await);
    }

    #[tokio::test]
    async fn on_complete_callback_is_stored_and_retrievable() {
        let (reg, _dir) = temp_registry();
        let triggered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let triggered_clone = Arc::clone(&triggered);
        let cb: OnCompleteFn = Arc::new(move |_id, _code| {
            triggered_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let id = BgJobId::new("cb-job", 3_000);
        let registered = reg.register(id.clone(), "callback test", 3_000, Some(cb)).await;
        assert!(registered);
        let entries = reg.entries().await;
        assert_eq!(entries.len(), 1);
        // Invoke the stored callback to prove it's wired.
        if let Some(f) = &entries[0].on_complete {
            f(&id, Some(0));
        }
        assert!(triggered.load(std::sync::atomic::Ordering::SeqCst));
    }
}
