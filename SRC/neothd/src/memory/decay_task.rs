//! Hebbian-decay background task — Q-8 adoption.
//!
//! Runs `memory::consolidate::run_consolidation_pass` every `interval` on
//! a long-lived tokio task. Cadence default 2h matches Jarvis'
//! `hippocampus-preprocess.timer` from the Q-8 audit row — frequent enough
//! that importance scores stay current within a day, infrequent enough
//! that the writer never competes for the SQLite lock on a hot loop.
//!
//! Errors are logged but **never** propagate out — a transient SQLite
//! error must not crash the daemon. The next tick retries.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinHandle;

use crate::memory::{consolidate, store};

/// 2 hours. Matches the Jarvis hippocampus-preprocess.timer pattern.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(2 * 60 * 60);

/// Spawn the decay task. Returns a `JoinHandle` the caller aborts on shutdown.
///
/// `db_path` lets tests inject a tempdir db; production callers pass
/// `store::default_path()`. Same for `interval` — tests use a short tick.
pub fn spawn(db_path: PathBuf, interval: Duration) -> JoinHandle<Result<()>> {
    tokio::spawn(async move { run(db_path, interval).await })
}

async fn run(db_path: PathBuf, interval: Duration) -> Result<()> {
    let mut ticker = tokio::time::interval(interval);
    // First tick fires immediately. Skip the initial fire on the assumption
    // that fresh boot already has a recent consolidation state — gives
    // operators a clean log on `neoth serve` startup without an immediate
    // SQLite write.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if let Err(e) = run_once(&db_path).await {
            tracing::warn!(
                db = %db_path.display(),
                error = %e,
                "Hebbian decay pass failed (will retry next tick)"
            );
        }
    }
}

/// One-shot decay pass — useful for `neoth memory --decay` style CLIs +
/// for unit tests.
pub async fn run_once(db_path: &std::path::Path) -> Result<consolidate::PassReport> {
    let db = db_path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<consolidate::PassReport> {
        let mut conn = store::open(&db)?;
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        consolidate::run_consolidation_pass(&mut conn, now_ns)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn run_once_returns_a_pass_report_against_empty_db() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let report = run_once(&db).await.expect("run once");
        // Empty db: nothing to decay, nothing to promote, nothing to forget.
        assert_eq!(report.hot_decayed, 0);
        assert_eq!(report.hot_archived, 0);
        assert_eq!(report.consolidated, 0);
    }

    #[tokio::test]
    async fn spawn_aborts_cleanly_on_handle_drop() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        // 10ms interval — task ticks fast enough to be in `interval.tick()`
        // when we abort.
        let task = spawn(db, Duration::from_millis(10));
        // Give it a moment to enter the loop.
        tokio::time::sleep(Duration::from_millis(25)).await;
        task.abort();
        // JoinError on aborted tasks is expected — we just want the
        // abort to not hang the test.
        let _ = task.await;
    }
}
