//! Round-3 v0.4 G-01 cron-wiring — daemon-side glue between the
//! `crate::reflection` producer (G-01-mini) + the
//! `crate::proactive::ProactiveQueue` substrate (G-01a).
//!
//! G-01-mini (Session 24) shipped the reflection builder: pure-fn
//! `top_topics_last_7_days` + `build_reflection_item`. G-01a shipped
//! the bounded daily-budget queue. What was missing — the operator-
//! visible piece — was the cron registration that actually fires
//! the builder periodically + persists the item into the queue. This
//! module closes that gap.
//!
//! ## Cadence
//!
//! Default tick interval **24h** even though reflection is weekly:
//! the per-week dedup_key (`"reflection:weekly:<iso-week>"`) in
//! `build_reflection_item` means daily ticks are idempotent — only
//! one item per ISO week ever lands in the queue regardless of how
//! often the cron fires. The daily tick gives us recovery: if a
//! daemon restart misses Sunday's tick, Monday's still picks up the
//! week's reflection.
//!
//! Operators tune via `freedom.yaml::reflection.cron_interval_secs`.
//!
//! ## Shared queue lifecycle
//!
//! `ProactiveQueue` is single-writer per documentation. The cron
//! loop OWNS the in-memory copy for the daemon's lifetime; on each
//! tick it (1) reads the persisted file (in case the GUI / CLI
//! drained items between ticks), (2) enqueues the fresh reflection
//! (dedup may reject — that's fine), (3) writes back via the
//! atomic `.tmp` + rename path.
//!
//! ## Why "drain" is NOT this module's job
//!
//! Draining (popping items out + delivering them via the operator's
//! preferred channel) is the consumer half — a separate cron / GUI
//! reader. This module is the PRODUCER. Splitting keeps the
//! delivery-channel choice (chat / Telegram / Slack / GUI banner)
//! orthogonal to the "what should we surface" decision.

use std::path::PathBuf;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Default tick interval — 24 hours in seconds.
pub const DEFAULT_CRON_INTERVAL_SECS: u64 = 24 * 3600;

/// One reflection-cron tick: opens views.db, asks `reflection` for
/// the week's top topics, builds a [`ProactiveItem`], enqueues into
/// the on-disk queue. Pure-fn (no async) so tests can call it
/// directly without the executor.
///
/// `now_unix` lets tests inject a stable time. Production calls
/// pass `chrono::Utc::now().timestamp()`.
///
/// Returns `Ok(true)` when a new item was enqueued (week wasn't
/// already represented); `Ok(false)` when the dedup rejected it
/// (idempotent re-tick). Errors propagate from views.db open /
/// queue load/save.
pub fn run_reflection_tick_once(home: &std::path::Path, now_unix: i64) -> Result<bool, String> {
    use crate::proactive::ProactiveQueue;
    use crate::reflection::{build_reflection_item, top_topics_last_7_days};

    let views_path = home.join("views.db");
    if !views_path.exists() {
        // Fresh install — no episodes yet, nothing to reflect on.
        // Quiet no-op so the cron doesn't spam the log every tick
        // during the wizard's first week.
        return Ok(false);
    }
    let conn = crate::memory::store::open(&views_path)
        .map_err(|e| format!("views.db open failed: {e}"))?;
    let now_ns = now_unix.saturating_mul(1_000_000_000);
    let topics = top_topics_last_7_days(&conn, now_ns, 3)
        .map_err(|e| format!("top_topics query failed: {e}"))?;

    let iso_week_tag = iso_week_tag_from_unix(now_unix);
    let item = match build_reflection_item(&iso_week_tag, &topics, now_unix) {
        Some(i) => i,
        None => {
            // Empty topics → no vacuous nudge. Return cleanly.
            return Ok(false);
        }
    };

    let queue_path = home.join("proactive_queue.json");
    let mut queue =
        ProactiveQueue::load_from(&queue_path).map_err(|e| format!("queue load failed: {e}"))?;
    let enqueued = queue.enqueue(item);
    queue
        .save_to(&queue_path)
        .map_err(|e| format!("queue save failed: {e}"))?;
    Ok(enqueued)
}

/// Spawn the reflection cron loop. Matches the doctor_cron /
/// updater_cron pattern in `daemon/`: returns a `JoinHandle<()>`
/// the daemon's shutdown path can `.abort()` on signal.
///
/// Loop body: every `interval_secs`, call [`run_reflection_tick_once`]
/// + log Ok/Err outcome. Per-tick failures NEVER abort the loop —
/// transient views.db lock, queue rewrite race, etc. should heal on
/// the next tick.
pub fn spawn_reflection_cron_loop(home: PathBuf, interval_secs: u64) -> JoinHandle<()> {
    let interval = Duration::from_secs(interval_secs.max(60));
    tokio::spawn(async move {
        info!(
            interval_secs = interval.as_secs(),
            home = %home.display(),
            "reflection cron loop spawned (G-01-mini producer + G-01a queue)"
        );
        let mut ticker = tokio::time::interval(interval);
        // First tick fires immediately; subsequent ticks at `interval`.
        // The interval-tick contract guarantees we don't pile up if
        // the body is slow.
        loop {
            ticker.tick().await;
            let now_unix = chrono::Utc::now().timestamp();
            match run_reflection_tick_once(&home, now_unix) {
                Ok(true) => info!(
                    "reflection cron: new weekly item enqueued (ISO week {})",
                    iso_week_tag_from_unix(now_unix)
                ),
                Ok(false) => {
                    tracing::debug!("reflection cron: tick produced no new item (dedup or empty)")
                }
                Err(e) => {
                    warn!(error = %e, "reflection cron tick failed; will retry next interval")
                }
            }
        }
    })
}

/// Compute the ISO-8601 week tag (e.g. `"2026-W22"`) from a unix
/// timestamp. Used as the dedup discriminator so the same week
/// can't double-fire across cron retries.
pub fn iso_week_tag_from_unix(ts_unix: i64) -> String {
    use chrono::Datelike;
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(ts_unix, 0)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap());
    let iso = dt.iso_week();
    format!("{:04}-W{:02}", iso.year(), iso.week())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn iso_week_tag_format_is_yyyy_wxx() {
        // 2026-01-01 → ISO week 1 of 2026.
        let ts = 1_767_225_600; // 2026-01-01 00:00:00 UTC
        let tag = iso_week_tag_from_unix(ts);
        assert!(
            tag.starts_with("2026-W") || tag.starts_with("2025-W"),
            "{} should look like YYYY-WXX",
            tag
        );
        assert_eq!(tag.len(), 8, "format is YYYY-WXX = 8 chars");
    }

    #[test]
    fn iso_week_tag_distinct_across_weeks() {
        let ts_a = 1_767_225_600; // 2026-01-01
        let ts_b = ts_a + 14 * 24 * 3600; // 2 weeks later
        assert_ne!(
            iso_week_tag_from_unix(ts_a),
            iso_week_tag_from_unix(ts_b),
            "two-week gap must produce distinct ISO week tags"
        );
    }

    #[test]
    fn iso_week_tag_same_within_one_week() {
        // Same Monday + same Friday should land on the same ISO week.
        let monday = 1_767_398_400; // 2026-01-05 00:00:00 UTC (Mon)
        let friday = monday + 4 * 24 * 3600;
        assert_eq!(
            iso_week_tag_from_unix(monday),
            iso_week_tag_from_unix(friday),
            "Mon + Fri of same week must share ISO tag"
        );
    }

    #[test]
    fn iso_week_tag_handles_epoch_zero() {
        // 1970-01-01 — Thursday, ISO week 1 of 1970.
        let tag = iso_week_tag_from_unix(0);
        assert_eq!(tag, "1970-W01");
    }

    #[test]
    fn run_reflection_tick_once_no_views_db_returns_ok_false() {
        let tmp = TempDir::new().unwrap();
        let result = run_reflection_tick_once(tmp.path(), 1_700_000_000).unwrap();
        assert!(
            !result,
            "fresh install (no views.db) must surface as Ok(false) not error"
        );
    }

    #[test]
    fn run_reflection_tick_once_empty_db_returns_ok_false() {
        let tmp = TempDir::new().unwrap();
        let views_path = tmp.path().join("views.db");
        // Create the schema but no rows.
        let _conn = crate::memory::store::open(&views_path).unwrap();
        let result = run_reflection_tick_once(tmp.path(), 1_700_000_000).unwrap();
        assert!(
            !result,
            "empty idx_episode → no topics → Ok(false) not error"
        );
    }

    #[test]
    fn default_cron_interval_is_24h() {
        assert_eq!(DEFAULT_CRON_INTERVAL_SECS, 24 * 3600);
    }
}
