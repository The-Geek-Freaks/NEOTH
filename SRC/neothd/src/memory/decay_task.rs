//! Hebbian-decay background task — Q-8 adoption.
//!
//! Runs `memory::consolidate::run_consolidation_pass` every `interval` on
//! a long-lived tokio task. Cadence default 2h matches the
//! `hippocampus-preprocess.timer` cadence from the Q-8 audit row — frequent enough
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

/// 2 hours. Matches the hippocampus-preprocess.timer cadence pattern.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(2 * 60 * 60);

/// Spawn the decay task. Returns a `JoinHandle` the caller aborts on shutdown.
///
/// `db_path` lets tests inject a tempdir db; production callers pass
/// `store::default_path()`. Same for `interval` — tests use a short tick.
pub fn spawn(db_path: PathBuf, interval: Duration, vault: Option<PathBuf>) -> JoinHandle<()> {
    tokio::spawn(async move { run(db_path, interval, vault).await })
}

/// M-04 (Session 24): infinite-loop body never returns Ok(()), so
/// the pre-fix `Result<()>` signature was misleading — every per-
/// tick failure stays inside the body (logged + retried on next
/// tick), and the only way the function exits is via task abort or
/// panic. Return-unit makes the never-returns semantics honest +
/// matches the JoinHandle<()> the caller actually observes.
async fn run(db_path: PathBuf, interval: Duration, vault: Option<PathBuf>) {
    let mut ticker = tokio::time::interval(interval);
    // Skip missed ticks rather than bursting (the codebase-wide default for
    // every periodic task — auto_update / doctor_cron / drift_alert_cron /
    // cron::scheduler all set this). Without it, a consolidation pass that
    // outran the interval would let tokio fire the next tick(s) immediately
    // on completion, running two decay passes back-to-back with no spacing —
    // a second pass can forget rows that only just crossed FORGET_FLOOR
    // during the first pass's own decay UPDATE, WITHOUT a pre-decay draft.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick fires immediately. Skip the initial fire on the assumption
    // that fresh boot already has a recent consolidation state — gives
    // operators a clean log on `neoth serve` startup without an immediate
    // SQLite write.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if let Err(e) = run_once(&db_path, vault.clone()).await {
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
pub async fn run_once(
    db_path: &std::path::Path,
    vault: Option<PathBuf>,
) -> Result<consolidate::PassReport> {
    let db = db_path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<consolidate::PassReport> {
        let mut conn = store::open(&db)?;
        // M-03 (Session 24): SystemTime::now().duration_since(UNIX_EPOCH)
        // can fail when the host clock has rolled BEFORE 1970 (broken
        // BIOS battery, mis-initialised VM, NTP regression). Pre-fix
        // used `unwrap_or(0)` which made every stored event look
        // maximally old — the consolidation pass mass-migrated hot →
        // warm and trimmed importance to floor on retentive rows. The
        // operator's working memory tier evaporated silently across
        // the next decay tick.
        //
        // Fix: skip the pass entirely on clock failure. Return an
        // empty PassReport so the caller sees "ran, did nothing"
        // rather than "ran, blew away the hot tier". Emit a
        // tracing::error! so operators see the cause in NEOTH_LOG.
        //
        // BOTH clock-failure modes must skip identically — the pre-epoch
        // Err arm AND the far-future nanosecond-overflow arm. The earlier
        // `unwrap_or(i64::MAX)` re-introduced the M-03 hazard under a
        // different trigger: a host clock reporting a time whose ns count
        // exceeds i64 (~year 2262) would set now_ns = i64::MAX, making
        // EVERY stored event look >7d old → the whole hot tier consolidates
        // + below-floor rows are deleted in one pass (and, with a vault,
        // pre-decay-drafted en masse). Refuse the pass instead.
        let now_ns = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => match i64::try_from(d.as_nanos()) {
                Ok(ns) => ns,
                Err(_) => {
                    tracing::error!(
                        nanos = d.as_nanos(),
                        "memory::decay_task::run_once: host clock nanosecond count \
                         overflows i64 (year >= 2262?) — refusing to run consolidation \
                         (would mass-migrate the entire hot tier). Check NTP / VM / \
                         hypervisor clock; rerun decay after fix."
                    );
                    return Ok(consolidate::PassReport::default());
                }
            },
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "memory::decay_task::run_once: host clock is before UNIX epoch — \
                     refusing to run consolidation (would mass-migrate hot tier). \
                     Check BIOS battery / NTP / VM clock; rerun decay after fix."
                );
                return Ok(consolidate::PassReport::default());
            }
        };
        consolidate::run_consolidation_pass(&mut conn, now_ns, vault.as_deref())
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
        let report = run_once(&db, None).await.expect("run once");
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
        let task = spawn(db, Duration::from_millis(10), None);
        // Give it a moment to enter the loop.
        tokio::time::sleep(Duration::from_millis(25)).await;
        task.abort();
        // JoinError on aborted tasks is expected — we just want the
        // abort to not hang the test.
        let _ = task.await;
    }
}
