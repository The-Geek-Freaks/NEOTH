//! G-01 — self-initiated message engine: the behaviour-pattern detectors.
//!
//! G-01's vision is a "smart pattern engine" that watches the operator's
//! behaviour and proactively surfaces "I noticed X, want me to do Y?"
//! nudges. The channel-delivery substrate it needs is already shipped:
//! `proactive::ProactiveQueue` (the bounded daily-budget queue),
//! `daemon::reflection_cron` + `daemon::g02_surfacing_cron` (sibling
//! producers), and `daemon::proactive_dispatcher` (the drain+send loop
//! that actually delivers enqueued items to the operator's channel).
//!
//! Each detector is a pure fn over `idx_episode` returning
//! `Option<ProactiveItem>`, run once per tick by `run_pattern_tick_once`
//! and enqueued behind a per-UTC-day `dedup_key` (so a persistent
//! condition produces at most one nudge per day, not one per tick):
//!
//!   - [`detect_inactivity_gap`] — silence longer than the gap threshold
//!     ("haven't heard from you — all good?"); prompts RE-ENGAGEMENT after
//!     a cold period (distinct from reflection's weekly summary).
//!   - [`detect_query_repeat`] — the same message asked N+ times in a
//!     window (candidate for a saved note/shortcut/skill).
//!   - [`detect_topic_burst`] — a topic whose recent mention-rate spikes
//!     over its baseline (focus shift), via the shared
//!     `reflection::topic_counts` tokeniser.
//!   - [`detect_time_of_day_shift`] — the peak active hour moved by N+
//!     hours (so timed briefings/reminders can follow the operator).
//!
//! Default OFF (`freedom.yaml::pattern_cron.enabled`): a proactive ping is
//! intrusive, so the whole engine stays opt-in (matching `drift_alert`/
//! `profile_adapt`); once opted in, each detector has its own toggle.

use std::path::PathBuf;

use crate::config::PatternCronConfig;
use crate::proactive::ProactiveItem;

/// Operator-authored natural-language text lands in `idx_episode` as
/// `EVENT_TYPE_RAW_TEXT` (0x01) — both the CLI prompt path
/// (`cli/chat.rs`) and the sanitised channel-inbound path
/// (`cli/serve.rs`) emit it. Assistant replies (`CHANNEL_EGRESS`), the
/// `[INGRESS] N bytes` placeholder rows (`CHANNEL_INGRESS`), and
/// dreaming/skill rows carry OTHER event types. Every detector filters
/// to RAW_TEXT so it reasons over what the OPERATOR actually wrote, not
/// NEOTH's own output (otherwise query-repeat fires on the byte-identical
/// `[INGRESS]` placeholder, and topic-burst counts NEOTH's verbose
/// replies as the operator's focus).
const RAW_TEXT_EVENT_TYPE: i64 = crate::wal::events::EVENT_TYPE_RAW_TEXT as i64;

/// Convert `u64` seconds to `i64` nanoseconds, CLAMPING absurd values
/// (> ~292 years) instead of letting the `u64 -> i64` cast wrap to a
/// negative threshold — a wrapped threshold reads as "always exceeded"
/// and would silently make a detector fire every tick.
fn secs_to_ns(secs: u64) -> i64 {
    let clamped = secs.min(i64::MAX as u64 / 1_000_000_000);
    (clamped as i64) * 1_000_000_000
}

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
    if gap_secs == 0 {
        // A zero gap would nudge on every tick — treat as "off".
        return None;
    }
    // Newest OPERATOR episode timestamp, or None when there is no operator
    // text yet (fresh install). RAW_TEXT-only so an assistant reply /
    // `[INGRESS]` placeholder doesn't count as the operator being active.
    let last_ns: Option<i64> = conn
        .query_row(
            "SELECT MAX(ts_ns) FROM idx_episode WHERE event_type = ?1",
            [RAW_TEXT_EVENT_TYPE],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    let last_ns = last_ns?;
    if last_ns <= 0 || last_ns > now_ns {
        // No real activity yet, or a clock fault (last event "in the
        // future") — never nudge on a bogus gap.
        return None;
    }
    let gap_ns = now_ns - last_ns;
    let threshold_ns = secs_to_ns(gap_secs);
    if gap_ns < threshold_ns {
        return None;
    }
    let now_unix = now_ns / 1_000_000_000;
    let day_ns: i64 = 24 * 3600 * 1_000_000_000;
    let gap_days = gap_ns / day_ns;
    let day_bucket = now_unix / 86_400;
    // Sub-day thresholds (operator lowered the gap) read better in hours
    // than as "~0 Tag(en)".
    let elapsed = if gap_days >= 1 {
        format!("~{gap_days} Tag(en)")
    } else {
        let gap_hours = gap_ns / (3600 * 1_000_000_000);
        format!("~{gap_hours} Stunde(n)")
    };
    Some(ProactiveItem {
        priority: 60, // useful unprompted nudge, below operator-urgent (100)
        dedup_key: format!("pattern:inactivity:{day_bucket}"),
        channel: String::new(), // operator default channel
        source: "pattern_cron".to_string(),
        body: format!(
            "Ich habe seit {elapsed} nichts von dir gehört — alles gut? \
             (`neoth status` zeigt, woran wir zuletzt waren.)"
        ),
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: 0,
    })
}

/// Collapse whitespace to single spaces and char-boundary-safe truncate
/// to `max` chars (appending `…` when clipped) so an excerpt of operator
/// text renders cleanly on one line in a chat nudge.
fn excerpt(text: &str, max: usize) -> String {
    let one_line: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= max {
        one_line
    } else {
        let head: String = one_line.chars().take(max).collect();
        format!("{head}…")
    }
}

/// Operator-text episodes whose `ts_ns` is in `(from_ns, to_ns]`
/// (RAW_TEXT-only). `None` only on a SQL error — an empty window is
/// `Some(vec![])`.
fn fetch_episode_texts(
    conn: &rusqlite::Connection,
    from_ns: i64,
    to_ns: i64,
) -> Option<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT text FROM idx_episode \
             WHERE ts_ns > ?1 AND ts_ns <= ?2 AND event_type = ?3",
        )
        .ok()?;
    let rows = stmt
        .query_map(
            rusqlite::params![from_ns, to_ns, RAW_TEXT_EVENT_TYPE],
            |r| r.get::<_, String>(0),
        )
        .ok()?;
    rows.collect::<rusqlite::Result<Vec<_>>>().ok()
}

/// Operator-text episode timestamps (ns) in `(from_ns, to_ns]`
/// (RAW_TEXT-only).
fn fetch_episode_ts(conn: &rusqlite::Connection, from_ns: i64, to_ns: i64) -> Option<Vec<i64>> {
    let mut stmt = conn
        .prepare(
            "SELECT ts_ns FROM idx_episode \
             WHERE ts_ns > ?1 AND ts_ns <= ?2 AND event_type = ?3",
        )
        .ok()?;
    let rows = stmt
        .query_map(
            rusqlite::params![from_ns, to_ns, RAW_TEXT_EVENT_TYPE],
            |r| r.get::<_, i64>(0),
        )
        .ok()?;
    rows.collect::<rusqlite::Result<Vec<_>>>().ok()
}

/// UTC hour (0..=23) with the most episodes; ties break to the smaller
/// hour for determinism. `None` when the slice is empty / all bogus.
fn peak_hour(ts_ns: &[i64]) -> Option<u32> {
    let mut hist = [0u32; 24];
    for &t in ts_ns {
        if t <= 0 {
            continue;
        }
        let hour = ((t / 1_000_000_000) % 86_400) / 3_600;
        hist[hour as usize] += 1;
    }
    let mut best_h = 0usize;
    let mut best_c = 0u32;
    for (h, &c) in hist.iter().enumerate() {
        if c > best_c {
            best_c = c;
            best_h = h;
        }
    }
    (best_c > 0).then_some(best_h as u32)
}

/// Shortest distance between two clock hours, wrapping at 24
/// (23→1 is 2 hours, not 22).
fn circular_hour_distance(a: u32, b: u32) -> u32 {
    let d = (a as i32 - b as i32).unsigned_abs();
    d.min(24 - d)
}

/// Query-repeat detector: when the operator has sent byte-identical
/// (same `text_hash`) non-trivial text `min_count`+ times within the
/// last `window_secs`, nudge once — a recurring ask is a candidate for a
/// saved note / shortcut / skill. Picks the single most-repeated text;
/// the `length(text) >= 8` floor drops "ok"/"hi"/"ja" chatter. `None`
/// when nothing qualifies, the clock is bogus, or `min_count == 0`.
///
/// `dedup_key` carries `text_hash` + the UTC day so one recurring query
/// nudges at most once per day, and two different recurring queries can
/// each fire.
pub fn detect_query_repeat(
    conn: &rusqlite::Connection,
    now_ns: i64,
    window_secs: u64,
    min_count: u32,
) -> Option<ProactiveItem> {
    if now_ns <= 0 || min_count == 0 || window_secs == 0 {
        return None;
    }
    let window_ns = secs_to_ns(window_secs);
    let from_ns = now_ns.saturating_sub(window_ns);
    // RAW_TEXT-only + length>=8. MAX(text) is a determinism tie-break
    // within a `text_hash` group; the 64-bit `text_hash` (indexer writes
    // `{:016x}`) makes intra-group text divergence a ~2^-64 collision,
    // so MAX(text) is the group's actual text in practice.
    let row: Option<(String, String, i64)> = conn
        .query_row(
            "SELECT text_hash, MAX(text) t, COUNT(*) c FROM idx_episode \
             WHERE ts_ns > ?1 AND ts_ns <= ?2 AND event_type = ?3 AND length(text) >= 8 \
             GROUP BY text_hash HAVING c >= ?4 \
             ORDER BY c DESC, MAX(ts_ns) DESC LIMIT 1",
            rusqlite::params![from_ns, now_ns, RAW_TEXT_EVENT_TYPE, min_count as i64],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .ok();
    let (text_hash, text, count) = row?;
    let day_bucket = (now_ns / 1_000_000_000) / 86_400;
    Some(ProactiveItem {
        priority: 55,
        dedup_key: format!("pattern:query-repeat:{text_hash}:{day_bucket}"),
        channel: String::new(),
        source: "pattern_cron".to_string(),
        body: format!(
            "Du hast in letzter Zeit ~{count}× das Gleiche gefragt (»{ex}«) — \
             soll ich mir das merken oder eine Notiz/Shortcut dafür anlegen?",
            ex = excerpt(&text, 80),
        ),
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: 0,
    })
}

/// Topic-burst detector: a topic whose mention-rate in the recent window
/// `(now - recent_secs, now]` spikes by `factor`× over its rate in the
/// baseline period `(now - baseline_secs, now - recent_secs]` — a sign
/// the operator is suddenly focused on something. Uses the SAME tokeniser
/// as the weekly reflection (`reflection::topic_counts`) so "topic" means
/// one thing across the daemon. A topic must clear `min_count` recent
/// mentions before it can burst (drops one-off noise); a brand-new topic
/// with zero baseline always bursts once over the floor. Picks the
/// highest recent count, ties broken alphabetically for determinism.
/// `None` when nothing bursts, the windows are degenerate, or the clock
/// is bogus.
pub fn detect_topic_burst(
    conn: &rusqlite::Connection,
    now_ns: i64,
    recent_secs: u64,
    baseline_secs: u64,
    min_count: u32,
    factor: f64,
) -> Option<ProactiveItem> {
    if now_ns <= 0 || min_count == 0 || baseline_secs <= recent_secs || factor <= 0.0 {
        return None;
    }
    let recent_from = now_ns.saturating_sub(secs_to_ns(recent_secs));
    let baseline_from = now_ns.saturating_sub(secs_to_ns(baseline_secs));
    let recent_texts = fetch_episode_texts(conn, recent_from, now_ns)?;
    let baseline_texts = fetch_episode_texts(conn, baseline_from, recent_from)?;
    let recent_counts = crate::reflection::topic_counts(&recent_texts);
    let baseline_counts = crate::reflection::topic_counts(&baseline_texts);

    let recent_days = (recent_secs as f64 / 86_400.0).max(1e-9);
    let baseline_days = ((baseline_secs - recent_secs) as f64 / 86_400.0).max(1e-9);

    let mut best: Option<(String, usize)> = None;
    for (topic, &rc) in &recent_counts {
        if (rc as u32) < min_count {
            continue;
        }
        let bc = baseline_counts.get(topic).copied().unwrap_or(0);
        let recent_rate = rc as f64 / recent_days;
        let baseline_rate = bc as f64 / baseline_days;
        let is_burst = baseline_rate <= 0.0 || recent_rate >= factor * baseline_rate;
        if !is_burst {
            continue;
        }
        let better = match &best {
            None => true,
            Some((bt, bcount)) => rc > *bcount || (rc == *bcount && topic < bt),
        };
        if better {
            best = Some((topic.clone(), rc));
        }
    }
    let (topic, count) = best?;
    // WEEK bucket (not day): a brand-new topic has zero baseline for the
    // first ~recent_secs, so a day bucket would re-nudge daily until the
    // baseline catches up. One nudge per topic per ISO-week is enough.
    let week_bucket = (now_ns / 1_000_000_000) / 86_400 / 7;
    Some(ProactiveItem {
        priority: 55,
        dedup_key: format!("pattern:topic-burst:{topic}:{week_bucket}"),
        channel: String::new(),
        source: "pattern_cron".to_string(),
        body: format!(
            "Du beschäftigst dich gerade viel mit »{topic}« (~{count} Erwähnungen in \
             den letzten Tagen) — soll ich dazu was sammeln oder eine Notiz/Skill anlegen?"
        ),
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: 0,
    })
}

/// Time-of-day-shift detector: the operator's peak active hour in the
/// recent window moved by `min_hours`+ hours (circular distance) from the
/// baseline window. Both windows need `min_episodes`+ rows — a sparse
/// histogram gives a noisy peak we shouldn't act on. `None` when data is
/// thin, the peak is stable, the windows are degenerate, or the clock is
/// bogus.
pub fn detect_time_of_day_shift(
    conn: &rusqlite::Connection,
    now_ns: i64,
    recent_secs: u64,
    baseline_secs: u64,
    min_hours: u32,
    min_episodes: u32,
) -> Option<ProactiveItem> {
    if now_ns <= 0 || baseline_secs <= recent_secs || min_hours == 0 || min_episodes == 0 {
        return None;
    }
    let recent_from = now_ns.saturating_sub(secs_to_ns(recent_secs));
    let baseline_from = now_ns.saturating_sub(secs_to_ns(baseline_secs));
    let recent_ts = fetch_episode_ts(conn, recent_from, now_ns)?;
    let baseline_ts = fetch_episode_ts(conn, baseline_from, recent_from)?;
    if (recent_ts.len() as u32) < min_episodes || (baseline_ts.len() as u32) < min_episodes {
        return None;
    }
    let recent_peak = peak_hour(&recent_ts)?;
    let baseline_peak = peak_hour(&baseline_ts)?;
    if circular_hour_distance(recent_peak, baseline_peak) < min_hours {
        return None;
    }
    // WEEK bucket: a real lifestyle shift stays "shifted" for weeks while
    // the 30-day baseline slowly absorbs it — a day bucket would nudge
    // daily the whole time. One nudge per week is the right cadence.
    let week_bucket = (now_ns / 1_000_000_000) / 86_400 / 7;
    Some(ProactiveItem {
        priority: 50,
        dedup_key: format!("pattern:tod-shift:{week_bucket}"),
        channel: String::new(),
        source: "pattern_cron".to_string(),
        body: format!(
            "Deine aktivsten Stunden haben sich verschoben (~{baseline_peak:02}:00 → \
             ~{recent_peak:02}:00 UTC) — soll ich Briefings/Reminders entsprechend timen?"
        ),
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: 0,
    })
}

/// One pattern-cron tick: open views.db, run every ENABLED detector, and
/// enqueue each nudge into the on-disk proactive queue. Mirrors
/// `reflection_cron::run_reflection_tick_once`. Returns the number of NEW
/// items enqueued this tick (0 on a no-op: active operator / empty DB /
/// every nudge already deduped). The inactivity detector is always run
/// (it is the engine's core signal); the other three are gated by their
/// per-detector flags. `now_unix` is injected so tests can pin the clock.
pub fn run_pattern_tick_once(
    home: &std::path::Path,
    now_unix: i64,
    config: &PatternCronConfig,
) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;

    let views_path = home.join("views.db");
    if !views_path.exists() {
        // Fresh install — no episodes yet; quiet no-op (don't log-spam
        // during the wizard's first run).
        return Ok(0);
    }
    let conn = crate::memory::store::open(&views_path)
        .map_err(|e| format!("views.db open failed: {e}"))?;
    let now_ns = now_unix.saturating_mul(1_000_000_000);

    let mut items: Vec<ProactiveItem> = Vec::new();
    if let Some(i) = detect_inactivity_gap(&conn, now_ns, config.inactivity_gap_secs) {
        items.push(i);
    }
    if config.query_repeat_enabled {
        if let Some(i) = detect_query_repeat(
            &conn,
            now_ns,
            config.query_repeat_window_secs,
            config.query_repeat_min_count,
        ) {
            items.push(i);
        }
    }
    if config.topic_burst_enabled {
        if let Some(i) = detect_topic_burst(
            &conn,
            now_ns,
            config.topic_burst_recent_secs,
            config.topic_burst_baseline_secs,
            config.topic_burst_min_count,
            config.topic_burst_factor,
        ) {
            items.push(i);
        }
    }
    if config.tod_shift_enabled {
        if let Some(i) = detect_time_of_day_shift(
            &conn,
            now_ns,
            config.tod_shift_recent_secs,
            config.tod_shift_baseline_secs,
            config.tod_shift_min_hours,
            config.tod_shift_min_episodes,
        ) {
            items.push(i);
        }
    }
    if items.is_empty() {
        return Ok(0);
    }
    // Highest-priority first so the per-tick cap keeps the MOST important
    // nudge when several detectors fire at once; the cap (default 1)
    // bounds how much of the shared 3/day ProactiveQueue budget the
    // pattern engine can consume in a single tick, leaving room for the
    // reflection + g02 producers.
    items.sort_by_key(|i| std::cmp::Reverse(i.priority));
    let cap = config.max_nudges_per_tick.max(1) as usize;

    let queue_path = home.join("proactive_queue.json");
    ProactiveQueue::modify(&queue_path, |queue| {
        let mut enqueued = 0usize;
        for item in items {
            if enqueued >= cap {
                break;
            }
            if queue.enqueue(item) {
                enqueued += 1;
            }
        }
        // Always persist — same as the old unconditional save_to call.
        (true, enqueued)
    })
    .map_err(|e| format!("queue load/save failed: {e}"))
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
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            inactivity_gap_secs = config.inactivity_gap_secs,
            query_repeat = config.query_repeat_enabled,
            topic_burst = config.topic_burst_enabled,
            tod_shift = config.tod_shift_enabled,
            "pattern cron loop online (G-01 behaviour detectors)",
        );
        loop {
            ticker.tick().await;
            let now_unix = crate::time::utc_now().timestamp();
            match run_pattern_tick_once(&home, now_unix, &config) {
                Ok(0) => tracing::debug!("pattern cron: no nudge this tick"),
                Ok(n) => tracing::info!(nudges = n, "pattern cron: proactive nudges enqueued"),
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

    fn seed_text(
        conn: &rusqlite::Connection,
        event_id: i64,
        ts_ns: i64,
        text: &str,
        text_hash: &str,
    ) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, 1, ?2, ?3, ?4, 0.5, ?2)",
            rusqlite::params![event_id, ts_ns, text, text_hash],
        )
        .unwrap();
    }

    /// Like [`seed_text`] but with an explicit `event_type` — for the
    /// RAW_TEXT-filter guard tests.
    fn seed_typed(
        conn: &rusqlite::Connection,
        event_id: i64,
        ts_ns: i64,
        text: &str,
        text_hash: &str,
        event_type: i64,
    ) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, ?5, ?2, ?3, ?4, 0.5, ?2)",
            rusqlite::params![event_id, ts_ns, text, text_hash, event_type],
        )
        .unwrap();
    }

    /// Episode timestamp (ns) at a given UTC day index + hour + `k`-second
    /// offset — for deterministic time-of-day histogram tests.
    fn ts_at_hour(day_idx: i64, hour: i64, k: i64) -> i64 {
        ((day_idx * 86_400) + hour * 3_600 + k) * 1_000_000_000
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
    fn run_tick_no_views_db_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            run_pattern_tick_once(dir.path(), 1_700_000_000, &PatternCronConfig::default())
                .unwrap(),
            0
        );
    }

    #[test]
    fn run_tick_enqueues_then_dedups_same_day() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let now_unix = 100 * 24 * 3600;
        // One short episode 5 days ago: only the inactivity detector fires
        // (text 'e' is too short for query-repeat/topic-burst, one row is
        // too sparse for the tod histogram).
        seed_episode(&conn, (now_unix - 5 * 24 * 3600) * 1_000_000_000);
        drop(conn);
        let cfg = PatternCronConfig::default();
        // First tick enqueues 1; second same-day tick dedups → 0.
        assert_eq!(
            run_pattern_tick_once(dir.path(), now_unix, &cfg).unwrap(),
            1
        );
        assert_eq!(
            run_pattern_tick_once(dir.path(), now_unix, &cfg).unwrap(),
            0
        );
    }

    // --- query-repeat detector ---

    #[test]
    fn query_repeat_none_below_min_count() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        seed_text(
            &conn,
            1,
            now - DAY_NS,
            "what is the deployment status",
            "qh",
        );
        seed_text(
            &conn,
            2,
            now - DAY_NS + 1_000_000_000,
            "what is the deployment status",
            "qh",
        );
        assert!(detect_query_repeat(&conn, now, 7 * 24 * 3600, 3).is_none());
    }

    #[test]
    fn query_repeat_fires_at_min_count() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        for k in 0..3 {
            seed_text(
                &conn,
                10 + k,
                now - DAY_NS + k * 1_000_000_000,
                "what is the deployment status",
                "qh",
            );
        }
        let item = detect_query_repeat(&conn, now, 7 * 24 * 3600, 3).expect("nudge");
        assert_eq!(item.source, "pattern_cron");
        assert_eq!(item.priority, 55);
        assert!(item.dedup_key.starts_with("pattern:query-repeat:qh:"));
        assert!(item.body.contains("3×"), "count in body: {}", item.body);
    }

    #[test]
    fn query_repeat_ignores_short_text() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        for k in 0..5 {
            seed_text(&conn, 20 + k, now - DAY_NS + k * 1_000_000_000, "hi", "sh");
        }
        assert!(detect_query_repeat(&conn, now, 7 * 24 * 3600, 3).is_none());
    }

    #[test]
    fn query_repeat_respects_window() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        // 3 identical asks 10 days ago — outside the 7-day window.
        for k in 0..3 {
            seed_text(
                &conn,
                30 + k,
                now - 10 * DAY_NS + k * 1_000_000_000,
                "what is the deployment status",
                "qh",
            );
        }
        assert!(detect_query_repeat(&conn, now, 7 * 24 * 3600, 3).is_none());
    }

    // --- topic-burst detector ---

    #[test]
    fn topic_burst_none_on_empty_db() {
        let (_d, conn) = fresh_db();
        assert!(
            detect_topic_burst(&conn, 100 * DAY_NS, 2 * 24 * 3600, 14 * 24 * 3600, 4, 3.0)
                .is_none()
        );
    }

    #[test]
    fn topic_burst_none_when_topic_stable() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        // "database tuning notes" 4× recent (rate 2/d) AND 20× across the
        // baseline (rate ~1.7/d) → not a 3× spike.
        for k in 0..4 {
            seed_text(
                &conn,
                100 + k,
                now - DAY_NS + k * 1_000_000_000,
                "database tuning notes",
                &format!("rb{k}"),
            );
        }
        for k in 0..20 {
            seed_text(
                &conn,
                200 + k,
                now - 6 * DAY_NS - k * 3600 * 1_000_000_000,
                "database tuning notes",
                &format!("bb{k}"),
            );
        }
        assert!(detect_topic_burst(&conn, now, 2 * 24 * 3600, 14 * 24 * 3600, 4, 3.0).is_none());
    }

    #[test]
    fn topic_burst_fires_on_spike() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        for k in 0..5 {
            seed_text(
                &conn,
                300 + k,
                now - DAY_NS + k * 1_000_000_000,
                "kubernetes migration plan",
                &format!("kr{k}"),
            );
        }
        seed_text(
            &conn,
            400,
            now - 8 * DAY_NS,
            "kubernetes notes earlier",
            "kb0",
        );
        let item =
            detect_topic_burst(&conn, now, 2 * 24 * 3600, 14 * 24 * 3600, 4, 3.0).expect("nudge");
        assert_eq!(item.priority, 55);
        assert_eq!(item.source, "pattern_cron");
        assert!(item.dedup_key.starts_with("pattern:topic-burst:"));
    }

    #[test]
    fn topic_burst_brand_new_topic_fires() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        // "rustlang async runtime" 4× recent, ZERO baseline.
        for k in 0..4 {
            seed_text(
                &conn,
                500 + k,
                now - DAY_NS + k * 1_000_000_000,
                "rustlang async runtime",
                &format!("nr{k}"),
            );
        }
        let item =
            detect_topic_burst(&conn, now, 2 * 24 * 3600, 14 * 24 * 3600, 4, 3.0).expect("nudge");
        assert!(item.dedup_key.contains("topic-burst"));
    }

    // --- time-of-day-shift detector ---

    #[test]
    fn tod_shift_none_when_data_sparse() {
        let (_d, conn) = fresh_db();
        let now = ts_at_hour(100, 0, 0);
        for k in 0..5 {
            seed_text(
                &conn,
                600 + k,
                ts_at_hour(98, 8, k),
                "x msg",
                &format!("r{k}"),
            );
            seed_text(
                &conn,
                700 + k,
                ts_at_hour(80, 20, k),
                "x msg",
                &format!("b{k}"),
            );
        }
        assert!(
            detect_time_of_day_shift(&conn, now, 7 * 24 * 3600, 30 * 24 * 3600, 4, 10).is_none()
        );
    }

    #[test]
    fn tod_shift_none_when_peak_stable() {
        let (_d, conn) = fresh_db();
        let now = ts_at_hour(100, 0, 0);
        for k in 0..12 {
            seed_text(
                &conn,
                600 + k,
                ts_at_hour(98, 20, k),
                "x msg",
                &format!("r{k}"),
            );
            seed_text(
                &conn,
                700 + k,
                ts_at_hour(80, 20, k),
                "x msg",
                &format!("b{k}"),
            );
        }
        assert!(
            detect_time_of_day_shift(&conn, now, 7 * 24 * 3600, 30 * 24 * 3600, 4, 10).is_none()
        );
    }

    #[test]
    fn tod_shift_fires_on_peak_move() {
        let (_d, conn) = fresh_db();
        let now = ts_at_hour(100, 0, 0);
        // recent peak hour 8, baseline peak hour 20 → circular distance 12.
        for k in 0..12 {
            seed_text(
                &conn,
                600 + k,
                ts_at_hour(98, 8, k),
                "x msg",
                &format!("r{k}"),
            );
            seed_text(
                &conn,
                700 + k,
                ts_at_hour(80, 20, k),
                "x msg",
                &format!("b{k}"),
            );
        }
        let item = detect_time_of_day_shift(&conn, now, 7 * 24 * 3600, 30 * 24 * 3600, 4, 10)
            .expect("nudge");
        assert_eq!(item.priority, 50);
        assert!(item.dedup_key.starts_with("pattern:tod-shift:"));
        assert!(item.body.contains("08:00"), "peak in body: {}", item.body);
    }

    // --- pure helpers ---

    #[test]
    fn circular_hour_distance_wraps() {
        assert_eq!(circular_hour_distance(23, 1), 2);
        assert_eq!(circular_hour_distance(1, 23), 2);
        assert_eq!(circular_hour_distance(8, 20), 12);
        assert_eq!(circular_hour_distance(10, 10), 0);
        assert_eq!(circular_hour_distance(0, 12), 12);
    }

    #[test]
    fn peak_hour_picks_modal_hour() {
        let base = 9 * 3600 * 1_000_000_000;
        let ts: Vec<i64> = vec![base, base + 1, base + 2, 14 * 3600 * 1_000_000_000];
        assert_eq!(peak_hour(&ts), Some(9));
        assert_eq!(peak_hour(&[]), None);
    }

    #[test]
    fn excerpt_collapses_and_truncates() {
        assert_eq!(excerpt("hello   world\n\nfoo", 100), "hello world foo");
        let long = "a".repeat(200);
        let ex = excerpt(&long, 80);
        assert_eq!(ex.chars().count(), 81, "80 chars + ellipsis");
        assert!(ex.ends_with('…'));
    }

    // --- review-hardening guards ---

    #[test]
    fn secs_to_ns_clamps_absurd_values() {
        assert_eq!(secs_to_ns(0), 0);
        assert_eq!(secs_to_ns(3), 3_000_000_000);
        // A naive `as i64` cast of a huge u64 would wrap negative; the
        // clamp keeps it a large POSITIVE threshold.
        let huge = secs_to_ns(u64::MAX);
        assert!(huge > 0);
        assert_eq!(huge, (i64::MAX / 1_000_000_000) * 1_000_000_000);
    }

    #[test]
    fn inactivity_zero_gap_never_nudges() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        seed_episode(&conn, now - 5 * DAY_NS);
        assert!(detect_inactivity_gap(&conn, now, 0).is_none());
    }

    #[test]
    fn inactivity_subday_gap_reads_in_hours() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        seed_episode(&conn, now - 6 * 3600 * 1_000_000_000); // 6h ago
        let item = detect_inactivity_gap(&conn, now, 5 * 3600).expect("nudge"); // gap 5h
        assert!(item.body.contains("Stunde"), "body: {}", item.body);
    }

    #[test]
    fn detectors_ignore_non_raw_text_events() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        // 4 identical assistant/INGRESS rows (event_type 0x33) — NOT
        // operator text, so query-repeat + inactivity must ignore them.
        for k in 0..4 {
            seed_typed(
                &conn,
                800 + k,
                now - DAY_NS + k * 1_000_000_000,
                "[INGRESS] 42 bytes here",
                "egr",
                0x33,
            );
        }
        assert!(detect_query_repeat(&conn, now, 7 * 24 * 3600, 3).is_none());
        assert!(detect_inactivity_gap(&conn, now, 3 * 24 * 3600).is_none());
    }

    #[test]
    fn query_repeat_zero_window_none() {
        let (_d, conn) = fresh_db();
        assert!(detect_query_repeat(&conn, 100 * DAY_NS, 0, 3).is_none());
    }

    #[test]
    fn topic_burst_zero_or_negative_factor_none() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        for k in 0..5 {
            seed_text(
                &conn,
                900 + k,
                now - DAY_NS + k * 1_000_000_000,
                "kubernetes migration plan",
                &format!("z{k}"),
            );
        }
        assert!(detect_topic_burst(&conn, now, 2 * 24 * 3600, 14 * 24 * 3600, 4, 0.0).is_none());
        assert!(detect_topic_burst(&conn, now, 2 * 24 * 3600, 14 * 24 * 3600, 4, -1.0).is_none());
    }

    #[test]
    fn topic_burst_dedup_key_is_per_week() {
        let (_d, conn) = fresh_db();
        let now = 100 * DAY_NS;
        // Seed 12h ago so the events stay inside the recent window at BOTH
        // `now` and `now + 1 day` (an event exactly on the window's
        // exclusive lower bound would drop out at now+1d).
        let twelve_h = 43_200 * 1_000_000_000;
        for k in 0..4 {
            seed_text(
                &conn,
                950 + k,
                now - twelve_h + k * 1_000_000_000,
                "rustlang async runtime",
                &format!("w{k}"),
            );
        }
        let a = detect_topic_burst(&conn, now, 2 * 24 * 3600, 14 * 24 * 3600, 4, 3.0).unwrap();
        // +1 day, same ISO-week bucket → same dedup key (no daily re-nudge).
        let b =
            detect_topic_burst(&conn, now + DAY_NS, 2 * 24 * 3600, 14 * 24 * 3600, 4, 3.0).unwrap();
        assert_eq!(a.dedup_key, b.dedup_key);
    }

    #[test]
    fn tod_shift_zero_thresholds_none() {
        let (_d, conn) = fresh_db();
        let now = ts_at_hour(100, 0, 0);
        for k in 0..12 {
            seed_text(
                &conn,
                600 + k,
                ts_at_hour(98, 8, k),
                "x msg",
                &format!("r{k}"),
            );
            seed_text(
                &conn,
                700 + k,
                ts_at_hour(80, 20, k),
                "x msg",
                &format!("b{k}"),
            );
        }
        assert!(
            detect_time_of_day_shift(&conn, now, 7 * 24 * 3600, 30 * 24 * 3600, 0, 10).is_none()
        );
        assert!(
            detect_time_of_day_shift(&conn, now, 7 * 24 * 3600, 30 * 24 * 3600, 4, 0).is_none()
        );
    }

    #[test]
    fn run_tick_caps_nudges_per_tick() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let now_unix = 100 * 24 * 3600;
        let now_ns = now_unix * 1_000_000_000;
        // Same query 3× five days ago → BOTH inactivity (silence) AND
        // query-repeat fire. Default cap of 1 keeps only the higher-
        // priority one (inactivity, 60 > 55).
        for k in 0..3 {
            seed_text(
                &conn,
                1000 + k,
                now_ns - 5 * DAY_NS + k * 1_000_000_000,
                "what is the deployment status",
                "qh",
            );
        }
        drop(conn);
        let cfg = PatternCronConfig::default();
        assert_eq!(
            run_pattern_tick_once(dir.path(), now_unix, &cfg).unwrap(),
            1
        );
    }

    #[test]
    fn config_back_compat_partial_deserialize() {
        // An old freedom.yaml that only knows the original 3 fields must
        // still deserialize — the new detector fields fall back to Default
        // (serde(default) on the struct).
        let json = r#"{"enabled":true,"interval_secs":3600,"inactivity_gap_secs":86400}"#;
        let cfg: PatternCronConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.interval_secs, 3600);
        assert!(cfg.query_repeat_enabled);
        assert_eq!(cfg.query_repeat_min_count, 3);
        assert!(cfg.topic_burst_enabled);
        assert_eq!(cfg.topic_burst_factor, 3.0);
        assert!(cfg.tod_shift_enabled);
        assert_eq!(cfg.tod_shift_min_episodes, 10);
        assert_eq!(cfg.max_nudges_per_tick, 1);
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
