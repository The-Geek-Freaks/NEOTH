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

/// Weekly tech-currency refresh (OPT-IN). Once per ISO week — gated by a marker
/// file so the daily cron tick never refetches — it pulls trending Hacker News
/// topics, computes the gap vs the operator's skills/memory + ignore/pin lists,
/// and enqueues a reflection. OFF by default
/// (`reflect_topics.yaml::weekly_refresh`, set via `neoth reflect weekly`) and
/// refused under Strict autonomy. This is the ONLY network egress in the
/// reflection cron; the offline G-01-mini weekly reflection stays free +
/// quota-safe. Returns `Ok(true)` when a fresh item was enqueued.
async fn run_tech_currency_tick_once(
    home: &std::path::Path,
    now_unix: i64,
) -> Result<bool, String> {
    use crate::cli::reflect::{ReflectTopics, collect_covered};
    use crate::proactive::ProactiveQueue;
    use crate::sources::hackernews::{
        GapFilter, build_tech_currency_item, tech_currency_gaps, top_stories,
    };

    let cfg = ReflectTopics::load(home);
    if !cfg.weekly_refresh {
        return Ok(false); // opt-in; off by default (no network unless enabled)
    }
    let autonomy = crate::config::FreedomConfig::load_from_default_path()
        .map(|c| c.autonomy)
        .unwrap_or_default();
    if autonomy == crate::permissions::AutonomyLevel::Strict {
        return Ok(false); // no external egress under Strict autonomy
    }
    // Once per ISO week: the marker makes the daily tick idempotent WITHOUT a
    // redundant HN fetch (queue dedup is a second safety net).
    let week = iso_week_tag_from_unix(now_unix);
    let marker = home.join("reflections").join("tech-currency-week.txt");
    if std::fs::read_to_string(&marker)
        .ok()
        .map(|s| s.trim() == week)
        .unwrap_or(false)
    {
        return Ok(false);
    }

    let stories = top_stories(50)
        .await
        .map_err(|e| format!("HN fetch failed: {e}"))?;
    let filter = GapFilter {
        covered: collect_covered(home),
        ignore: cfg.ignore,
        pin: cfg.pin,
    };
    let gaps = tech_currency_gaps(&stories, &filter, 7);

    // Mark the week done even when there are no gaps, so we don't refetch HN
    // every night for an empty result.
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, &week);

    let item = match build_tech_currency_item(&week, &gaps, now_unix) {
        Some(i) => i,
        None => return Ok(false), // no gaps → no vacuous nudge
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

/// Resolve the Obsidian sync target (`vault_root`, `subdir`) from freedom.yaml,
/// or `None` when no vault is configured. Re-read each tick so toggling the
/// vault doesn't need a daemon restart.
fn obsidian_target() -> Option<(PathBuf, String)> {
    let cfg = crate::config::FreedomConfig::load_from_default_path().ok()?;
    let vault = cfg.obsidian_vault.clone()?;
    let subdir = cfg
        .obsidian_subdir
        .clone()
        .unwrap_or_else(|| "NEOTH".to_string());
    Some((PathBuf::from(vault), subdir))
}

/// Generic offline daily/yearly reflection tick (OPT-IN). Composes a
/// [`PeriodReflection`] from the period's top operator topics, archives it as
/// JSONL, and — when an Obsidian vault is configured — writes the daily-note /
/// yearly-summary. Idempotent per tag via a marker file so the daily cron tick
/// fires each cadence at most once. Deterministic + offline (no LLM, no
/// network), so it runs unattended even with the cloud quota exhausted.
/// `enabled` is the operator opt-in; `window_days` + `topic_n` scale the summary.
#[allow(clippy::too_many_arguments)]
fn run_period_reflection_tick_once(
    home: &std::path::Path,
    now_unix: i64,
    kind: crate::reflection::periodic::PeriodKind,
    enabled: bool,
    tag: &str,
    marker_name: &str,
    window_days: i64,
    topic_n: usize,
    obsidian: Option<(&std::path::Path, &str)>,
) -> Result<bool, String> {
    use crate::reflection::periodic;
    use crate::reflection::top_topics_in_days;

    if !enabled {
        return Ok(false); // opt-in; off by default
    }
    let marker = home.join("reflections").join(marker_name);
    if std::fs::read_to_string(&marker)
        .ok()
        .map(|s| s.trim() == tag)
        .unwrap_or(false)
    {
        return Ok(false); // already done this period
    }
    let views_path = home.join("views.db");
    if !views_path.exists() {
        return Ok(false); // fresh install — nothing to summarise
    }
    let conn = crate::memory::store::open(&views_path)
        .map_err(|e| format!("views.db open failed: {e}"))?;
    let now_ns = now_unix.saturating_mul(1_000_000_000);
    let topics = top_topics_in_days(&conn, now_ns, window_days, topic_n)
        .map_err(|e| format!("topic query failed: {e}"))?;

    let write_marker = |marker: &std::path::Path, tag: &str| {
        if let Some(p) = marker.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let _ = std::fs::write(marker, tag);
    };

    match periodic::build_reflection(kind, tag, &topics, now_unix) {
        Some(refl) => {
            // Archive FIRST — only mark the period done once it's persisted, so
            // a transient IO error retries next tick instead of silently
            // dropping the day's reflection.
            periodic::append(home, &refl).map_err(|e| format!("archive append failed: {e}"))?;
            write_marker(&marker, tag);
            if let Some((vault, subdir)) = obsidian {
                match periodic::sync_to_obsidian(home, vault, subdir, kind, tag) {
                    Ok(o) if o.written => info!(
                        path = %o.target_path.display(),
                        "reflection cron: {} Obsidian note written",
                        kind.as_str()
                    ),
                    Ok(_) => {}
                    Err(e) => {
                        warn!(error = %e, "reflection cron: Obsidian {} sync failed", kind.as_str())
                    }
                }
            }
            Ok(true)
        }
        None => {
            // Empty period → no vacuous note, but still mark done so we don't
            // recompute the topic query every tick for the rest of the period.
            write_marker(&marker, tag);
            Ok(false)
        }
    }
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
            // Opt-in weekly tech-currency refresh (network; idempotent per ISO
            // week). A failure here NEVER aborts the loop or the offline tick.
            match run_tech_currency_tick_once(&home, now_unix).await {
                Ok(true) => info!(
                    "reflection cron: weekly tech-currency reflection enqueued (ISO week {})",
                    iso_week_tag_from_unix(now_unix)
                ),
                Ok(false) => {}
                Err(e) => {
                    warn!(error = %e, "tech-currency tick failed; will retry next interval")
                }
            }
            // Opt-in offline daily + yearly self-reflections → archive + Obsidian
            // notes. Read the opt-in flags + Obsidian target fresh each tick.
            let cfg = crate::cli::reflect::ReflectTopics::load(&home);
            let obsidian = obsidian_target();
            let obs_ref = obsidian.as_ref().map(|(p, s)| (p.as_path(), s.as_str()));
            use crate::reflection::periodic::{PeriodKind, date_tag_from_unix, year_tag_from_unix};
            let daily_tag = date_tag_from_unix(now_unix);
            if let Err(e) = run_period_reflection_tick_once(
                &home,
                now_unix,
                PeriodKind::Daily,
                cfg.daily_notes,
                &daily_tag,
                "daily-last.txt",
                1,
                5,
                obs_ref,
            ) {
                warn!(error = %e, "daily reflection tick failed; will retry next interval");
            }
            let yearly_tag = year_tag_from_unix(now_unix);
            if let Err(e) = run_period_reflection_tick_once(
                &home,
                now_unix,
                PeriodKind::Yearly,
                cfg.yearly_summary,
                &yearly_tag,
                "yearly-last.txt",
                365,
                10,
                obs_ref,
            ) {
                warn!(error = %e, "yearly reflection tick failed; will retry next interval");
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

    #[tokio::test]
    async fn tech_currency_tick_is_noop_when_weekly_refresh_disabled() {
        // Default reflect_topics.yaml (absent) → weekly_refresh = false → the
        // tick returns Ok(false) BEFORE any network call. Hermetic: no HN fetch,
        // no marker written.
        let tmp = TempDir::new().unwrap();
        let r = run_tech_currency_tick_once(tmp.path(), 1_767_225_600).await;
        assert_eq!(r, Ok(false), "disabled weekly refresh is a clean no-op");
        assert!(
            !tmp.path()
                .join("reflections/tech-currency-week.txt")
                .exists(),
            "no marker is written when the feature is off"
        );
    }

    #[test]
    fn iso_week_tag_same_within_one_week() {
        // Same Monday + same Friday should land on the same ISO week.
        // 2026-01-05 is the first Monday of ISO week 2026-W02
        // (2026-01-01 is a Thursday → Jan 1 itself is in W01, and W02
        // runs Mon Jan 5 – Sun Jan 11). The prior literal here was
        // 1_767_398_400 = Sat 2026-01-03, which is still in W01 and
        // whose +4-day Friday crossed into W02 — a wrong fixture, not
        // a code bug.
        let monday = 1_767_571_200; // 2026-01-05 00:00:00 UTC (Mon)
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

    #[test]
    fn period_tick_disabled_is_a_clean_noop() {
        use crate::reflection::periodic::PeriodKind;
        let tmp = TempDir::new().unwrap();
        let r = run_period_reflection_tick_once(
            tmp.path(),
            1_700_000_000,
            PeriodKind::Daily,
            false, // opt-in OFF
            "2026-06-16",
            "daily-last.txt",
            1,
            5,
            None,
        );
        assert_eq!(r, Ok(false), "disabled cadence is a clean no-op");
        assert!(
            !tmp.path().join("reflections/daily-last.txt").exists(),
            "no marker written when off"
        );
    }

    #[test]
    fn period_tick_archives_and_is_idempotent_per_tag() {
        use crate::reflection::periodic::{self, PeriodKind};
        let tmp = TempDir::new().unwrap();
        let views = tmp.path().join("views.db");
        let conn = crate::memory::store::open(&views).unwrap();
        let now_unix = 1_700_000_000i64;
        let now_ns = now_unix * 1_000_000_000;
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                1i64,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                now_ns - 3_600_000_000_000i64, // 1h ago, inside the 1-day window
                "kubernetes networking deep dive",
                "hash1",
            ],
        )
        .unwrap();
        let tag = "2026-test-day";
        let r = run_period_reflection_tick_once(
            tmp.path(),
            now_unix,
            PeriodKind::Daily,
            true,
            tag,
            "daily-last.txt",
            1,
            5,
            None, // no Obsidian (hermetic — never reads the operator's real config)
        )
        .unwrap();
        assert!(r, "enabled + topics present → archived");
        assert!(
            periodic::jsonl_file(tmp.path(), PeriodKind::Daily, tag).exists(),
            "reflection archived as JSONL"
        );
        assert!(tmp.path().join("reflections/daily-last.txt").exists());

        // Second call, same tag → idempotent no-op (marker hit).
        let r2 = run_period_reflection_tick_once(
            tmp.path(),
            now_unix,
            PeriodKind::Daily,
            true,
            tag,
            "daily-last.txt",
            1,
            5,
            None,
        )
        .unwrap();
        assert!(!r2, "marker makes the tick idempotent per tag");
    }
}
