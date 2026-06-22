//! GOLD-ADAPT-ODY-07 — Background-job monitor (scan + auto-continue).
//!
//! Pairs with [`super::bg_jobs`]. The monitor runs a periodic scan over the
//! [`super::bg_jobs::BgJobRegistry`] and, for every job that transitioned to
//! `Completed` since the last scan:
//!
//! 1. Calls the job's `on_complete` callback (if registered) — the
//!    "auto-continue" trigger (e.g. re-enter the conversation with the job's
//!    output).
//! 2. Logs the completion at `tracing::info` level so operators see it in
//!    `neoth serve` output without enabling verbose tracing.
//! 3. Removes the entry from the in-memory registry (the on-disk `.log` /
//!    `.exit` files are LEFT in place for operator inspection; a future
//!    `neoth jobs clean` command should GC them).
//!
//! ## Usage
//!
//! ```text
//! let registry = Arc::new(BgJobRegistry::new(home.join("bgjobs")));
//! let handle = spawn_bg_monitor(registry, 5 /* secs */);
//! // … daemon runs …
//! handle.abort();
//! ```
//!
//! ## Testing strategy
//!
//! The `scan_once` function is extracted as a pure (well — async, async is
//! fine) unit so tests can drive it without the timing loop:
//!
//! - write a `.exit` file for a job → `scan_once` observes it, fires
//!   the callback, removes the entry from the registry.
//! - no `.exit` file → `scan_once` leaves the entry in the registry.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use super::bg_jobs::{BgJobRegistry, BgJobStatus, read_job_status};

/// Minimum monitor interval — prevents a misconfigured zero-second loop.
const MONITOR_FLOOR_SECS: u64 = 1;

/// Completion report produced by [`scan_once`] for each job that exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobCompleteReport {
    pub job_id: String,
    pub exit_code: Option<i32>,
    /// True when the `on_complete` callback was present and invoked.
    pub callback_invoked: bool,
}

/// Spawn the background-job monitor loop.
///
/// Every `interval_secs` the loop calls [`scan_once`] against `registry`.
/// Jobs that completed have their callbacks invoked and are removed from the
/// registry. The returned [`JoinHandle`] should be aborted during daemon
/// shutdown.
///
/// Returns `None` when `interval_secs` is 0 (no idle task for unconfigured
/// operator setups — mirrors the pattern of [`super::worker_watch`]).
pub fn spawn_bg_monitor(
    registry: Arc<BgJobRegistry>,
    interval_secs: u64,
) -> Option<JoinHandle<()>> {
    if interval_secs == 0 {
        return None;
    }
    let secs = interval_secs.max(MONITOR_FLOOR_SECS);
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let reports = scan_once(&registry).await;
            for r in &reports {
                tracing::info!(
                    job_id = %r.job_id,
                    exit_code = ?r.exit_code,
                    callback_invoked = r.callback_invoked,
                    "bg_monitor: job completed"
                );
            }
        }
    }))
}

/// Single scan pass over the registry.
///
/// For each registered job:
/// - If the `.exit` marker exists, fires `on_complete` (if present),
///   emits a log line, removes the entry from the registry, and records
///   a [`JobCompleteReport`].
/// - If `.exit` is absent, the job is still running — no action.
///
/// Extracted from the loop so it is independently testable without wall-
/// clock sleeps.
pub async fn scan_once(registry: &BgJobRegistry) -> Vec<JobCompleteReport> {
    let entries = registry.entries().await;
    let mut reports = Vec::new();
    for entry in &entries {
        match read_job_status(&entry.exit_path) {
            BgJobStatus::Running => {
                // Still running — nothing to do.
                tracing::debug!(
                    job_id = %entry.job_id,
                    "bg_monitor: job still running"
                );
            }
            BgJobStatus::Completed { code } => {
                let callback_invoked = if let Some(cb) = &entry.on_complete {
                    cb(&entry.job_id, code);
                    true
                } else {
                    false
                };
                registry.forget(&entry.job_id).await;
                reports.push(JobCompleteReport {
                    job_id: entry.job_id.to_string(),
                    exit_code: code,
                    callback_invoked,
                });
            }
        }
    }
    reports
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::daemon::bg_jobs::{BgJobId, OnCompleteFn};

    /// Helper: build a registry with a temp dir and register one job.
    async fn one_job_registry(
        on_complete: Option<OnCompleteFn>,
    ) -> (Arc<BgJobRegistry>, tempfile::TempDir, BgJobId) {
        let dir = tempfile::tempdir().unwrap();
        let reg = Arc::new(BgJobRegistry::new(dir.path().to_path_buf()));
        let id = BgJobId::new("test-job", 100);
        reg.register(id.clone(), "a test job", 100, on_complete).await;
        (reg, dir, id)
    }

    // ── Core scenario: register + complete ────────────────────────────────

    #[tokio::test]
    async fn completed_job_is_removed_from_registry_after_scan() {
        let (reg, dir, id) = one_job_registry(None).await;
        // Write the .exit marker (exit code 0).
        let exit_path = dir.path().join(format!("{}.exit", id.as_str()));
        std::fs::write(&exit_path, b"0\n").unwrap();

        let reports = scan_once(&reg).await;

        assert_eq!(reports.len(), 1, "one completed job must yield one report");
        assert_eq!(reports[0].job_id, id.to_string());
        assert_eq!(reports[0].exit_code, Some(0));
        assert!(!reports[0].callback_invoked, "no callback was registered");
        // Entry must have been removed.
        assert!(reg.is_empty().await, "registry must be empty after completion");
    }

    #[tokio::test]
    async fn running_job_stays_in_registry() {
        let (reg, _dir, _id) = one_job_registry(None).await;
        // No .exit file written → job is still running.
        let reports = scan_once(&reg).await;
        assert!(reports.is_empty(), "no reports for a running job");
        assert_eq!(reg.len().await, 1, "entry must remain in registry");
    }

    // ── Auto-continue callback ─────────────────────────────────────────────

    #[tokio::test]
    async fn auto_continue_callback_is_invoked_on_completion() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        let cb: OnCompleteFn = Arc::new(move |_id, code| {
            assert_eq!(code, Some(0));
            fired_clone.store(true, Ordering::SeqCst);
        });

        let (reg, dir, id) = one_job_registry(Some(cb)).await;
        std::fs::write(dir.path().join(format!("{}.exit", id.as_str())), b"0\n").unwrap();

        let reports = scan_once(&reg).await;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].callback_invoked);
        assert!(fired.load(Ordering::SeqCst), "callback must have been called");
    }

    #[tokio::test]
    async fn callback_receives_non_zero_exit_code() {
        let received_code: Arc<std::sync::Mutex<Option<i32>>> =
            Arc::new(std::sync::Mutex::new(None));
        let rc_clone = Arc::clone(&received_code);
        let cb: OnCompleteFn = Arc::new(move |_id, code| {
            *rc_clone.lock().unwrap() = code;
        });

        let (reg, dir, id) = one_job_registry(Some(cb)).await;
        std::fs::write(dir.path().join(format!("{}.exit", id.as_str())), b"127\n").unwrap();

        scan_once(&reg).await;
        assert_eq!(*received_code.lock().unwrap(), Some(127));
    }

    // ── Multi-job mixed state ──────────────────────────────────────────────

    #[tokio::test]
    async fn mixed_running_and_done_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Arc::new(BgJobRegistry::new(dir.path().to_path_buf()));

        let done_id = BgJobId::new("done", 200);
        let running_id = BgJobId::new("running", 201);

        reg.register(done_id.clone(), "will finish", 200, None).await;
        reg.register(running_id.clone(), "still going", 201, None).await;

        // Only write exit marker for `done`.
        std::fs::write(
            dir.path().join(format!("{}.exit", done_id.as_str())),
            b"0\n",
        )
        .unwrap();

        let reports = scan_once(&reg).await;

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].job_id, done_id.to_string());

        // `running` must still be in the registry.
        let remaining = reg.entries().await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].job_id, running_id);
    }

    // ── spawn_bg_monitor interface ─────────────────────────────────────────

    #[test]
    fn zero_interval_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Arc::new(BgJobRegistry::new(dir.path()));
        assert!(
            spawn_bg_monitor(reg, 0).is_none(),
            "interval=0 must produce no task"
        );
    }

    #[tokio::test]
    async fn nonzero_interval_spawns_task() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Arc::new(BgJobRegistry::new(dir.path()));
        let handle = spawn_bg_monitor(Arc::clone(&reg), 3600);
        assert!(handle.is_some(), "interval > 0 must spawn a task");
        handle.unwrap().abort();
    }

    // ── Report completeness check ──────────────────────────────────────────

    #[tokio::test]
    async fn report_fields_are_populated() {
        let (reg, dir, id) = one_job_registry(None).await;
        std::fs::write(dir.path().join(format!("{}.exit", id.as_str())), b"2\n").unwrap();
        let reports = scan_once(&reg).await;
        let r = &reports[0];
        assert_eq!(r.job_id, "test-job-100");
        assert_eq!(r.exit_code, Some(2));
        assert!(!r.callback_invoked);
    }
}
