//! Sources-table GC scheduler — wires `memory::gc::run_pass` into the
//! daemon loop. Default cadence 24 h: source rows older than the TTL are
//! relatively rare and full-walk SQLite work doesn't earn an aggressive
//! tick rate.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::memory::{gc, store};

/// 24 h. Matches the daily Hebbian decay cadence so operators only see
/// one daemon-side maintenance pulse per day in `neoth status`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Spawn the GC task. Returns the JoinHandle so the caller aborts on
/// shutdown. `db_path = None` resolves to `store::default_path()`.
pub fn spawn(db_path: Option<PathBuf>, interval: Duration) -> JoinHandle<Result<()>> {
    let db = db_path.unwrap_or_else(store::default_path);
    tokio::spawn(async move { run(db, interval).await })
}

async fn run(db: PathBuf, interval: Duration) -> Result<()> {
    info!(
        db = %db.display(),
        interval_secs = interval.as_secs(),
        "sources GC task started",
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — fresh boot already has a clean state.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match run_once(&db).await {
            Ok(report) => {
                if report.sources_dropped > 0 {
                    info!(
                        sources = report.sources_dropped,
                        chunks = report.chunks_dropped,
                        chunks_trigram = report.chunks_trigram_dropped,
                        "sources GC pass swept transient rows",
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "sources GC pass failed (retry next tick)");
            }
        }
    }
}

/// One-shot pass — useful for `neoth gc --run` CLI surface + unit tests.
pub async fn run_once(db_path: &std::path::Path) -> Result<gc::GcReport> {
    let db = db_path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<gc::GcReport> {
        let mut conn = store::open(&db)?;
        // Fail-safe skip on clock failure (mirrors M-03 in decay_task): a
        // `now_ns = 0` default makes `cutoff = now - TTL` nonsensical, so the
        // GC pass would operate on a garbage window. Surface the error instead
        // — the periodic loop logs a warning and retries on the next tick.
        let now_ns = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "system clock is before UNIX_EPOCH ({e}); skipping GC pass — \
                     check BIOS battery / NTP / VM clock"
                ));
            }
        };
        let report = gc::run_pass(&mut conn, now_ns, gc::DEFAULT_TTL_NS)?;
        // MEM-13 — after TTL aging, enforce the total-size cap so a busy ctx
        // store can't grow without bound.
        match gc::enforce_size_cap(&mut conn, gc::DEFAULT_MAX_SOURCES) {
            Ok(capped) if capped > 0 => {
                tracing::info!(capped, "gc: size cap evicted oldest ctx sources")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "gc: size-cap pass failed (non-fatal)"),
        }
        Ok(report)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn run_once_on_empty_db_returns_zero_report() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let report = run_once(&db).await.expect("run_once");
        assert_eq!(report.sources_dropped, 0);
    }

    #[tokio::test]
    async fn spawn_aborts_cleanly() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let task = spawn(Some(db), Duration::from_millis(25));
        tokio::time::sleep(Duration::from_millis(15)).await;
        task.abort();
        let _ = task.await;
    }
}
