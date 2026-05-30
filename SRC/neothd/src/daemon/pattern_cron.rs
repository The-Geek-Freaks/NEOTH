//! G-01 (first slice) — self-initiated message engine: the inactivity
//! detector.
//!
//! G-01's full vision is a "smart pattern engine" that watches the
//! operator's behaviour and proactively surfaces "I noticed X, want me to
//! do Y?" nudges. The channel-delivery substrate it needs is already
//! shipped: `proactive::ProactiveQueue` (the bounded daily-budget queue),
//! `daemon::reflection_cron` + `daemon::g02_surfacing_cron` (sibling
//! producers), and `daemon::proactive_dispatcher` (the drain+send loop
//! that actually delivers enqueued items to the operator's channel).
//!
//! This module lands the FIRST detector on that substrate: an
//! **inactivity gap** check. When the most recent `idx_episode` event is
//! older than `inactivity_gap_secs`, it enqueues ONE proactive nudge
//! ("haven't heard from you — all good?"), deduped per UTC day so a
//! continued silence produces at most one nudge per day, not one per
//! tick. This is a distinct signal from reflection's weekly "here's what
//! you worked on" summary — it prompts RE-ENGAGEMENT after a cold period.
//!
//! Default OFF (`freedom.yaml::pattern_cron.enabled`): a proactive ping is
//! intrusive, so it stays opt-in (matching `drift_alert`/`profile_adapt`).
//! Further detectors (topic-burst, time-of-day shift, query-repeat) layer
//! onto the same `detect_*` + enqueue shape in follow-on slices.

use std::path::PathBuf;

use crate::config::PatternCronConfig;
use crate::proactive::ProactiveItem;

/// Pure inactivity detector: returns a nudge item when the newest
/// `idx_episode` row is older than `gap_secs` relative to `now_ns`.
/// `None` when the operator is active, the DB is empty (fresh install —
/// nothing to miss), or the clock looks bogus (last event in the future).
///
/// The `dedup_key` carries the UTC day (`now_unix / 86400`) so a
/// persistent silence enqueues at most one nudge per day — the queue's
/// dedup drops same-day re-ticks.
pub fn detect_inactivity_gap(
    conn: &rusqlite::Connection,
    now_ns: i64,
    gap_secs: u64,
) -> Option<ProactiveItem> {
    // Newest episode timestamp, or None when idx_episode is empty.
    let last_ns: Option<i64> = conn
        .query_row("SELECT MAX(ts_ns) FROM idx_episode", [], |r| r.get(0))
        .ok()
        .flatten();
    let last_ns = last_ns?;
    if last_ns <= 0 || last_ns > now_ns {
        // No real activity yet, or a clock fault (last event "in the
        // future") — never nudge on a bogus gap.
        return None;
    }
    let gap_ns = now_ns - last_ns;
    let threshold_ns = (gap_secs as i64).saturating_mul(1_000_000_000);
    if gap_ns < threshold_ns {
        return None;
    }
    let now_unix = now_ns / 1_000_000_000;
    let gap_days = gap_ns / (24 * 3600 * 1_000_000_000);
    let day_bucket = now_unix / 86_400;
    Some(ProactiveItem {
        priority: 60, // useful unprompted nudge, below operator-urgent (100)
        dedup_key: format!("pattern:inactivity:{day_bucket}"),
        channel: String::new(), // operator default channel
        source: "pattern_cron".to_string(),
        body: format!(
            "Ich habe seit ~{gap_days} Tag(en) nichts von dir gehört — alles gut? \
             (`neoth status` zeigt, woran wir zuletzt waren.)"
        ),
        scheduled_for_unix: 0,
    })
}

/// One pattern-cron tick: open views.db, run the inactivity detector,
/// enqueue any nudge into the on-disk proactive queue. Mirrors
/// `reflection_cron::run_reflection_tick_once`. Returns `Ok(true)` when a
/// new nudge was enqueued, `Ok(false)` on no-op (active operator / empty
/// DB / dedup). `now_unix` is injected so tests can pin the clock.
pub fn run_pattern_tick_once(
    home: &std::path::Path,
    now_unix: i64,
    gap_secs: u64,
) -> Result<bool, String> {
    use crate::proactive::ProactiveQueue;

    let views_path = home.join("views.db");
    if !views_path.exists() {
        // Fresh install — no episodes yet; quiet no-op (don't log-spam
        // during the wizard's first run).
        return Ok(false);
    }
    let conn = crate::memory::store::open(&views_path)
        .map_err(|e| format!("views.db open failed: {e}"))?;
    let now_ns = now_unix.saturating_mul(1_000_000_000);
    let Some(item) = detect_inactivity_gap(&conn, now_ns, gap_secs) else {
        return Ok(false);
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

/// Spawn the pattern-cron loop. Returns `None` when
/// `config.enabled == false` (the default) so opt-out operators carry no
/// idle tokio task; otherwise a `JoinHandle` the daemon shutdown path
/// aborts. Per-tick failures never abort the loop (heal next tick).
pub fn spawn_pattern_cron_loop(
    config: PatternCronConfig,
    home: PathBuf,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("pattern cron disabled in config (pattern_cron.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    let gap_secs = config.inactivity_gap_secs;
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            inactivity_gap_secs = gap_secs,
            "pattern cron loop online (G-01 inactivity detector)",
        );
        loop {
            ticker.tick().await;
            let now_unix = chrono::Utc::now().timestamp();
            match run_pattern_tick_once(&home, now_unix, gap_secs) {
                Ok(true) => tracing::info!("pattern cron: inactivity nudge enqueued"),
                Ok(false) => tracing::debug!("pattern cron: no nudge this tick"),
                Err(e) => {
                    tracing::warn!(error = %e, "pattern cron tick failed; retrying next interval")
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_NS: i64 = 24 * 3600 * 1_000_000_000;

    fn seed_episode(conn: &rusqlite::Connection, ts_ns: i64) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, 1, ?2, 'e', 'h', 0.5, ?2)",
            rusqlite::params![ts_ns, ts_ns],
        )
        .unwrap();
    }

    fn fresh_db() -> (tempfile::TempDir, rusqlite::Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        (dir, conn)
    }

    #[test]
    fn no_nudge_when_idx_episode_empty() {
        let (_d, conn) = fresh_db();
        assert!(detect_inactivity_gap(&conn, 100 * DAY_NS, 3 * 24 * 3600).is_none());
    }

    #[test]
    fn no_nudge_when_operator_active_within_gap() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        seed_episode(&conn, now - DAY_NS); // active 1 day ago, gap = 3d
        assert!(detect_inactivity_gap(&conn, now, 3 * 24 * 3600).is_none());
    }

    #[test]
    fn nudges_when_gap_exceeds_threshold() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        seed_episode(&conn, now - 5 * DAY_NS); // quiet for 5 days, gap = 3d
        let item = detect_inactivity_gap(&conn, now, 3 * 24 * 3600).expect("nudge");
        assert_eq!(item.source, "pattern_cron");
        assert_eq!(item.priority, 60);
        assert!(item.dedup_key.starts_with("pattern:inactivity:"));
        assert!(
            item.body.contains("5 Tag"),
            "gap days in body: {}",
            item.body
        );
    }

    #[test]
    fn no_nudge_on_future_last_event_clock_fault() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        seed_episode(&conn, now + DAY_NS); // last event in the future
        assert!(detect_inactivity_gap(&conn, now, 3 * 24 * 3600).is_none());
    }

    #[test]
    fn dedup_key_is_per_utc_day() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        seed_episode(&conn, now - 5 * DAY_NS);
        let a = detect_inactivity_gap(&conn, now, 3 * 24 * 3600).unwrap();
        // +12h same UTC day → same dedup key (the queue collapses re-ticks).
        let b =
            detect_inactivity_gap(&conn, now + 12 * 3600 * 1_000_000_000, 3 * 24 * 3600).unwrap();
        assert_eq!(a.dedup_key, b.dedup_key);
    }

    #[test]
    fn run_tick_no_views_db_is_ok_false() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!run_pattern_tick_once(dir.path(), 1_700_000_000, 3 * 24 * 3600).unwrap());
    }

    #[test]
    fn run_tick_enqueues_then_dedups_same_day() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let now_unix = 100 * 24 * 3600;
        seed_episode(&conn, (now_unix - 5 * 24 * 3600) * 1_000_000_000);
        drop(conn);
        // First tick enqueues; second same-day tick dedups (Ok(false)).
        assert!(run_pattern_tick_once(dir.path(), now_unix, 3 * 24 * 3600).unwrap());
        assert!(!run_pattern_tick_once(dir.path(), now_unix, 3 * 24 * 3600).unwrap());
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = PatternCronConfig::default(); // enabled = false
        assert!(spawn_pattern_cron_loop(cfg, dir.path().to_path_buf()).is_none());
    }

    #[tokio::test]
    async fn spawn_returns_some_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = PatternCronConfig {
            enabled: true,
            ..PatternCronConfig::default()
        };
        let h = spawn_pattern_cron_loop(cfg, dir.path().to_path_buf()).expect("handle");
        h.abort();
    }
}
