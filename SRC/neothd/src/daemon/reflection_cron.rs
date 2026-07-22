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
//!
//! ## GOLD-ADAPT-OH-07 — Subconscious anti-double-emit
//!
//! The second dedup layer (complementing the per-ISO-week queue
//! `dedup_key`) is a persisted `SubconsciousTickState` stored in
//! `<home>/reflections/subconscious_state.json`. It records
//! `last_emitted_unix` — the wall-clock of the last successful
//! weekly reflection emit. Any `run_reflection_tick_once` call that
//! occurs within `min_window_secs` of `last_emitted_unix` returns
//! `Ok(false)` immediately (suppressed), preventing double-emit
//! across rapid cron ticks, daemon restarts, or manual triggers.
//!
//! `recent_reflections_sitrep` exposes the operator-visible view:
//! the last N daily reflections + the most recent weekly emit, so
//! the subconscious "what have I been saying" state is auditable
//! without inspecting raw JSONL.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Default tick interval — 24 hours in seconds.
pub const DEFAULT_CRON_INTERVAL_SECS: u64 = 24 * 3600;
const MAX_TICK_STATE_BYTES: usize = 64 * 1024;
const MAX_MARKER_BYTES: usize = 256;

fn read_bounded_state_file(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Option<Vec<u8>>, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent: {}", path.display()))?;
    let Some(name) = path.file_name() else {
        return Err(format!("{label} path has no file name: {}", path.display()));
    };
    let Some(directory) = crate::skills::store::open_bound_directory(parent, false, label)
        .map_err(|error| format!("open {label} parent {}: {error:#}", parent.display()))?
    else {
        return Ok(None);
    };
    match crate::skills::store::read_regular_file_bounded(&directory.dir, name, path, max_bytes) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(format!("read {label} {}: {error:#}", path.display())),
    }
}

// ── GOLD-ADAPT-OH-07: SubconsciousTickState ──────────────────────────────────

/// Persisted state for the subconscious weekly-reflection emitter.
/// Written to `<home>/reflections/subconscious_state.json` after every
/// successful emit so the daemon survives restarts without re-emitting.
///
/// All fields carry `#[serde(default)]` so files written before any
/// field existed deserialise cleanly.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubconsciousTickState {
    /// Unix-seconds of the last successful weekly reflection emit.
    /// `0` means "never emitted" (fresh install).
    #[serde(default)]
    pub last_emitted_unix: i64,
}

/// Path of the tick-state file relative to `home`.
fn tick_state_path(home: &std::path::Path) -> PathBuf {
    home.join("reflections").join("subconscious_state.json")
}

/// Load the tick state. A missing file is a fresh install; an existing
/// unreadable, empty, or malformed file is evidence of broken persisted state
/// and must stop the anti-double-emit gate rather than resetting it.
pub fn load_tick_state(home: &std::path::Path) -> Result<SubconsciousTickState, String> {
    let path = tick_state_path(home);
    let bytes = match read_bounded_state_file(&path, MAX_TICK_STATE_BYTES, "reflection tick state")?
    {
        Some(bytes) => bytes,
        None => return Ok(SubconsciousTickState::default()),
    };
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse reflection tick state {}: {error}", path.display()))
}

/// Persist the tick state privately, atomically, and durably. A successful
/// enqueue is not reported as fully committed unless its replay-suppression
/// state also reaches disk.
pub fn save_tick_state(
    home: &std::path::Path,
    state: &SubconsciousTickState,
) -> Result<(), String> {
    let path = tick_state_path(home);
    let bytes = serde_json::to_vec_pretty(state)
        .expect("SubconsciousTickState contains only infallibly serializable fields");
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .map_err(|error| format!("persist reflection tick state {}: {error}", path.display()))
}

/// Read a cadence marker. Only absence means "not committed"; every other
/// read failure is surfaced so a broken marker cannot silently reopen work.
fn marker_matches(path: &Path, expected: &str) -> Result<bool, String> {
    let Some(bytes) = read_bounded_state_file(path, MAX_MARKER_BYTES, "reflection marker")? else {
        return Ok(false);
    };
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| format!("reflection marker is not UTF-8: {}", path.display()))?;
    Ok(value.trim() == expected)
}

/// Atomically persist a cadence marker. Marker durability is part of the tick
/// commit: callers must return this error so the next cron tick retries.
fn persist_marker(path: &Path, value: &str) -> Result<(), String> {
    crate::util::atomic_write::atomic_write_private(path, value.as_bytes())
        .map_err(|error| format!("persist reflection marker {}: {error}", path.display()))
}

// ── GOLD-ADAPT-OH-07: ReflectionSitrep ──────────────────────────────────────

/// One entry in the recent-reflections sitrep (a compact summary of
/// what the subconscious has surfaced recently). Covers both weekly
/// reflections (source `"weekly"`) and period reflections
/// (`"daily"` / `"yearly"`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SitrepEntry {
    /// `"weekly"` | `"daily"` | `"yearly"`.
    pub kind: String,
    /// ISO-week tag (`"YYYY-WXX"`) for weekly; `"YYYY-MM-DD"` for daily;
    /// `"YYYY"` for yearly.
    pub tag: String,
    /// Unix-seconds when the reflection was generated / emitted.
    pub generated_ts_unix: i64,
    /// Top topics extracted for this period (empty for weekly when none
    /// were surfaced yet).
    pub topics: Vec<String>,
    /// One-line body text the operator would have seen as a nudge.
    pub body: String,
}

/// Compact operator-facing view of recent subconscious activity.
/// Returned by [`recent_reflections_sitrep`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReflectionSitrep {
    /// Unix-seconds of the last successful weekly emit (`0` = never).
    pub last_emitted_unix: i64,
    /// Recent reflections, newest first.
    pub recent: Vec<SitrepEntry>,
}

/// Build a `ReflectionSitrep` by reading:
/// 1. The persisted `SubconsciousTickState` (for `last_emitted_unix`).
/// 2. Daily period-reflection JSONL files for the last `lookback_days`.
///
/// At most `max_entries` entries are returned, newest first.
/// Missing daily reflection files are naturally absent. A broken tick-state
/// file is surfaced so the operator is not shown a false "never emitted"
/// status while the autonomous gate is fail-closed.
pub fn recent_reflections_sitrep(
    home: &std::path::Path,
    lookback_days: u32,
    max_entries: usize,
) -> Result<ReflectionSitrep, String> {
    use crate::reflection::periodic::{PeriodKind, date_tag_from_unix, load_for_tag};

    let state = load_tick_state(home)?;
    let now = crate::time::now_unix_i64();
    let mut entries: Vec<SitrepEntry> = Vec::new();

    for back in 0..lookback_days as i64 {
        let ts = now - back * 86_400;
        let tag = date_tag_from_unix(ts);
        for r in load_for_tag(home, PeriodKind::Daily, &tag) {
            entries.push(SitrepEntry {
                kind: "daily".to_string(),
                tag: r.tag.clone(),
                generated_ts_unix: r.generated_ts_unix,
                topics: r.topics.clone(),
                body: r.body.clone(),
            });
        }
    }

    // Sort newest first, then cap.
    entries.sort_by_key(|e| std::cmp::Reverse(e.generated_ts_unix));
    entries.truncate(max_entries);

    Ok(ReflectionSitrep {
        last_emitted_unix: state.last_emitted_unix,
        recent: entries,
    })
}

// ── Weekly reflection tick (extended with OH-07 window gate) ─────────────────

/// One reflection-cron tick: opens views.db, asks `reflection` for
/// the week's top topics, builds a [`ProactiveItem`], enqueues into
/// the on-disk queue. Pure-fn (no async) so tests can call it
/// directly without the executor.
///
/// `now_unix` lets tests inject a stable time. Production calls
/// pass `chrono::Utc::now().timestamp()`.
///
/// `min_window_secs` — GOLD-ADAPT-OH-07 anti-double-emit gate.
/// If `now_unix - last_emitted_unix < min_window_secs`, the tick
/// returns `Ok(false)` immediately (suppressed) so rapid re-ticks
/// or daemon restarts within the same window never double-emit the
/// same reflection. Pass `0` to disable the gate (tests that
/// exercise other paths do this). The cron loop passes
/// `DEFAULT_CRON_INTERVAL_SECS`.
///
/// Returns `Ok(true)` when a new item was enqueued (week wasn't
/// already represented); `Ok(false)` when the window gate or queue
/// dedup rejected it (idempotent re-tick). Errors propagate from
/// views.db open / queue load/save.
pub fn run_reflection_tick_once(
    home: &std::path::Path,
    now_unix: i64,
    min_window_secs: u64,
) -> Result<bool, String> {
    use crate::proactive::ProactiveQueue;
    use crate::reflection::{build_reflection_item, top_topics_last_7_days};

    // GOLD-ADAPT-OH-07: window gate — suppress if we emitted recently.
    if min_window_secs > 0 {
        let state = load_tick_state(home)?;
        if state.last_emitted_unix > 0 {
            let elapsed = now_unix.saturating_sub(state.last_emitted_unix) as u64;
            if elapsed < min_window_secs {
                return Ok(false); // suppressed — within anti-double-emit window
            }
        }
    }

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
    // Always persist (dirty=true) — same as the old code which called save_to
    // unconditionally regardless of whether enqueue deduped the item.
    let enqueued = ProactiveQueue::modify(&queue_path, |queue| {
        let inserted = queue.enqueue(item);
        (true, inserted)
    })
    .map_err(|e| format!("queue load/save failed: {e}"))?;

    // Queue persistence is the delivery commit. Persist the replay gate even
    // when enqueue deduped: that is the recovery path after a crash/error
    // between the prior queue save and tick-state save. Requiring a fresh
    // insertion here would leave state missing forever and recompute every tick.
    save_tick_state(
        home,
        &SubconsciousTickState {
            last_emitted_unix: now_unix,
        },
    )?;

    // GOLD-ADAPT-OH-08 — stage the observation for the Intelligence view.
    // Written every time topics are present and the window gate passed, even
    // when the queue dedup already has this week's item (the observation is
    // an independent surface-only record, not a delivery-queue item). The
    // operator reads staged observations via `neoth proactive intelligence`.
    if let Some(obs) =
        crate::reflection::build_reflection_observation(&iso_week_tag, &topics, now_unix)
        && let Err(e) = crate::reflection::append_staged_observation(home, &obs)
    {
        warn!(
            error = %e,
            "reflection cron: staged observation write failed (non-fatal)"
        );
    }

    Ok(enqueued)
}

#[derive(Debug)]
struct TechCurrencyPreflight {
    week: String,
    marker: PathBuf,
    ignore: Vec<String>,
    pin: Vec<String>,
}

/// Blocking phase before network: load opt-in state and validate the durable
/// marker. Network authority is deliberately not decided here: every concrete
/// HN URL is gated immediately at its transport sink by ExternalHttpAuthorizer.
/// `None` means clean no-op without opening a socket.
fn tech_currency_preflight(
    home: &Path,
    now_unix: i64,
) -> Result<Option<TechCurrencyPreflight>, String> {
    let cfg = crate::cli::reflect::ReflectTopics::load(home);
    if !cfg.weekly_refresh {
        return Ok(None);
    }

    let week = iso_week_tag_from_unix(now_unix);
    let marker = home.join("reflections").join("tech-currency-week.txt");
    if marker_matches(&marker, &week)? {
        return Ok(None);
    }

    Ok(Some(TechCurrencyPreflight {
        week,
        marker,
        ignore: cfg.ignore,
        pin: cfg.pin,
    }))
}

/// Blocking phase after fetch: derive gaps, persist queue mutation, then
/// atomically commit the marker. The marker is checked again because another
/// process may have completed the same week while the async fetch was in flight.
fn commit_tech_currency_tick(
    home: &Path,
    now_unix: i64,
    preflight: TechCurrencyPreflight,
    stories: Vec<crate::sources::hackernews::HnStory>,
) -> Result<bool, String> {
    use crate::cli::reflect::collect_covered;
    use crate::proactive::ProactiveQueue;
    use crate::sources::hackernews::{GapFilter, build_tech_currency_item, tech_currency_gaps};

    if marker_matches(&preflight.marker, &preflight.week)? {
        return Ok(false);
    }

    let filter = GapFilter {
        covered: collect_covered(home),
        ignore: preflight.ignore,
        pin: preflight.pin,
    };
    let gaps = tech_currency_gaps(&stories, &filter, 7);
    let Some(item) = build_tech_currency_item(&preflight.week, &gaps, now_unix) else {
        persist_marker(&preflight.marker, &preflight.week)?;
        return Ok(false);
    };

    let queue_path = home.join("proactive_queue.json");
    let enqueued = ProactiveQueue::modify(&queue_path, |queue| {
        let inserted = queue.enqueue(item);
        (true, inserted)
    })
    .map_err(|error| format!("queue load/save failed: {error}"))?;

    // Queue must reach disk first. If marker persistence fails, return Err;
    // queue dedup makes the retry safe and the marker then converges.
    persist_marker(&preflight.marker, &preflight.week)?;
    Ok(enqueued)
}

/// Weekly tech-currency refresh (OPT-IN). Blocking filesystem/policy work is
/// split from the async HN fetch and the blocking queue/marker commit. Returns
/// `Ok(true)` only when a fresh queue item was inserted.
async fn run_tech_currency_tick_once(
    home: &Path,
    now_unix: i64,
    http: &crate::tools::external_http::ExternalHttpAuthorizer,
) -> Result<bool, String> {
    let preflight_home = home.to_path_buf();
    let Some(preflight) =
        tokio::task::spawn_blocking(move || tech_currency_preflight(&preflight_home, now_unix))
            .await
            .map_err(|error| format!("tech-currency preflight worker failed: {error}"))??
    else {
        return Ok(false);
    };

    let stories = crate::sources::hackernews::top_stories(http, 50)
        .await
        .map_err(|error| format!("HN fetch failed: {error}"))?;

    let commit_home = home.to_path_buf();
    tokio::task::spawn_blocking(move || {
        commit_tech_currency_tick(&commit_home, now_unix, preflight, stories)
    })
    .await
    .map_err(|error| format!("tech-currency commit worker failed: {error}"))?
}

/// Resolve the Obsidian sync target (`vault_root`, `subdir`) from the exact
/// immutable config generation obtained from the daemon ReloadController.
fn obsidian_target(cfg: &crate::config::FreedomConfig) -> Option<(PathBuf, String)> {
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
    if marker_matches(&marker, tag)? {
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

    match periodic::build_reflection(kind, tag, &topics, now_unix) {
        Some(refl) => {
            // Archive FIRST — only mark the period done once it's persisted, so
            // a transient IO error retries next tick instead of silently
            // dropping the day's reflection.
            periodic::append(home, &refl).map_err(|e| format!("archive append failed: {e}"))?;
            persist_marker(&marker, tag)?;
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
            persist_marker(&marker, tag)?;
            Ok(false)
        }
    }
}

struct PeriodTickResults {
    daily: Result<bool, String>,
    yearly: Result<bool, String>,
}

/// Run both offline period cadences in one blocking worker. Configuration,
/// SQLite, archive, marker, and optional Obsidian I/O all stay off Tokio's
/// async scheduler; an individual cadence failure does not suppress the other.
fn run_period_reflection_ticks_once(
    home: &Path,
    now_unix: i64,
    config: &crate::config::FreedomConfig,
) -> Result<PeriodTickResults, String> {
    use crate::reflection::periodic::{PeriodKind, date_tag_from_unix, year_tag_from_unix};

    let cfg = crate::cli::reflect::ReflectTopics::load(home);
    let obsidian = obsidian_target(config);
    let obs_ref = obsidian.as_ref().map(|(p, s)| (p.as_path(), s.as_str()));
    let daily_tag = date_tag_from_unix(now_unix);
    let daily = run_period_reflection_tick_once(
        home,
        now_unix,
        PeriodKind::Daily,
        cfg.daily_notes,
        &daily_tag,
        "daily-last.txt",
        1,
        5,
        obs_ref,
    );
    let yearly_tag = year_tag_from_unix(now_unix);
    let yearly = run_period_reflection_tick_once(
        home,
        now_unix,
        PeriodKind::Yearly,
        cfg.yearly_summary,
        &yearly_tag,
        "yearly-last.txt",
        365,
        10,
        obs_ref,
    );
    Ok(PeriodTickResults { daily, yearly })
}

/// Spawn the reflection cron loop. Matches the doctor_cron /
/// updater_cron pattern in `daemon/`: returns a `JoinHandle<()>`
/// the daemon's shutdown path can `.abort()` on signal.
///
/// Loop body: every `interval_secs`, call [`run_reflection_tick_once`]
/// + log Ok/Err outcome. Per-tick failures NEVER abort the loop —
/// transient views.db lock, queue rewrite race, etc. should heal on
/// the next tick.
pub fn spawn_reflection_cron_loop(
    home: PathBuf,
    interval_secs: u64,
    reload_controller: std::sync::Arc<crate::config::reload::ReloadController>,
    http: std::sync::Arc<crate::tools::external_http::ExternalHttpAuthorizer>,
) -> JoinHandle<()> {
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
            let now_unix = crate::time::utc_now().timestamp();
            let weekly_home = home.clone();
            match tokio::task::spawn_blocking(move || {
                run_reflection_tick_once(&weekly_home, now_unix, DEFAULT_CRON_INTERVAL_SECS)
            })
            .await
            {
                Ok(Ok(true)) => info!(
                    "reflection cron: new weekly item enqueued (ISO week {})",
                    iso_week_tag_from_unix(now_unix)
                ),
                Ok(Ok(false)) => {
                    tracing::debug!("reflection cron: tick produced no new item (dedup or empty)")
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "reflection cron tick failed; will retry next interval")
                }
                Err(e) => warn!(
                    error = %e,
                    "reflection cron filesystem worker failed; will retry next interval"
                ),
            }
            // Opt-in weekly tech-currency refresh (network; idempotent per ISO
            // week). A failure here NEVER aborts the loop or the offline tick.
            match run_tech_currency_tick_once(&home, now_unix, http.as_ref()).await {
                Ok(true) => info!(
                    "reflection cron: weekly tech-currency reflection enqueued (ISO week {})",
                    iso_week_tag_from_unix(now_unix)
                ),
                Ok(false) => {}
                Err(e) => {
                    warn!(error = %e, "tech-currency tick failed; will retry next interval")
                }
            }
            // Opt-in offline daily + yearly self-reflections. All config,
            // SQLite, archive, marker, and Obsidian I/O runs off the Tokio loop.
            let period_home = home.clone();
            let period_config = reload_controller.latest();
            match tokio::task::spawn_blocking(move || {
                run_period_reflection_ticks_once(&period_home, now_unix, &period_config)
            })
            .await
            {
                Ok(Ok(results)) => {
                    if let Err(e) = results.daily {
                        warn!(error = %e, "daily reflection tick failed; will retry next interval");
                    }
                    if let Err(e) = results.yearly {
                        warn!(error = %e, "yearly reflection tick failed; will retry next interval");
                    }
                }
                Ok(Err(e)) => warn!(
                    error = %e,
                    "reflection cron: config invalid; daily/yearly sync blocked fail-closed"
                ),
                Err(e) => warn!(
                    error = %e,
                    "period reflection filesystem worker failed; will retry next interval"
                ),
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
            "{tag} should look like YYYY-WXX"
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
        let r = run_tech_currency_tick_once(
            tmp.path(),
            1_767_225_600,
            &crate::tools::external_http::ExternalHttpAuthorizer::test_allow(),
        )
        .await;
        assert_eq!(r, Ok(false), "disabled weekly refresh is a clean no-op");
        assert!(
            !tmp.path()
                .join("reflections/tech-currency-week.txt")
                .exists(),
            "no marker is written when the feature is off"
        );
    }

    #[test]
    fn tech_currency_preflight_only_resolves_opt_in_and_marker() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("reflect_topics.yaml"),
            "weekly_refresh: true\n",
        )
        .unwrap();

        let preflight = tech_currency_preflight(tmp.path(), 1_767_225_600).unwrap();
        assert!(
            preflight.is_some(),
            "permission is intentionally deferred to each exact HTTP sink"
        );
    }

    #[test]
    fn obsidian_target_uses_the_passed_active_config_snapshot() {
        let config = crate::config::FreedomConfig {
            obsidian_vault: Some("C:/active-vault".to_string()),
            obsidian_subdir: Some("Active-NEOTH".to_string()),
            ..Default::default()
        };
        assert_eq!(
            obsidian_target(&config),
            Some((PathBuf::from("C:/active-vault"), "Active-NEOTH".to_string()))
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
        // min_window_secs = 0 → gate disabled; exercises the "no views.db" path.
        let result = run_reflection_tick_once(tmp.path(), 1_700_000_000, 0).unwrap();
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
        let result = run_reflection_tick_once(tmp.path(), 1_700_000_000, 0).unwrap();
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
    fn reflection_markers_are_atomic_and_persistence_errors_surface() {
        let tmp = TempDir::new().unwrap();
        let marker = tmp.path().join("reflections").join("daily-last.txt");
        persist_marker(&marker, "2026-07-21").unwrap();
        persist_marker(&marker, "2026-07-22").unwrap();
        assert!(marker_matches(&marker, "2026-07-22").unwrap());
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "2026-07-22");

        let blocked = tmp.path().join("blocked-marker");
        std::fs::create_dir(&blocked).unwrap();
        let error = persist_marker(&blocked, "must-fail").unwrap_err();
        assert!(error.contains("persist reflection marker"));
    }

    #[test]
    fn marker_read_errors_do_not_reopen_completed_work() {
        let tmp = TempDir::new().unwrap();
        let marker = tmp.path().join("marker-as-directory");
        std::fs::create_dir(&marker).unwrap();

        let error = marker_matches(&marker, "2026-W30").unwrap_err();
        assert!(error.contains("read reflection marker"));
    }

    #[test]
    fn oversized_marker_is_rejected_instead_of_reading_unbounded_state() {
        let tmp = TempDir::new().unwrap();
        let marker = tmp.path().join("oversized-marker.txt");
        std::fs::write(&marker, vec![b'x'; MAX_MARKER_BYTES + 1]).unwrap();

        let error = marker_matches(&marker, "2026-W30").unwrap_err();
        assert!(error.contains("read reflection marker"));
        assert!(error.contains("exceeds"));
    }

    #[test]
    fn tech_currency_queue_dedup_repairs_missing_marker_on_retry() {
        use crate::sources::hackernews::HnStory;

        let tmp = TempDir::new().unwrap();
        let week = "2026-W30";
        let marker = tmp
            .path()
            .join("reflections")
            .join("tech-currency-week.txt");
        let stories = vec![
            HnStory {
                id: 1,
                title: "WebGPU rendering lands in production".to_string(),
                url: None,
                score: 100,
                by: "a".to_string(),
            },
            HnStory {
                id: 2,
                title: "WebGPU rendering patterns explained".to_string(),
                url: None,
                score: 90,
                by: "b".to_string(),
            },
        ];
        let preflight = || TechCurrencyPreflight {
            week: week.to_string(),
            marker: marker.clone(),
            ignore: Vec::new(),
            pin: Vec::new(),
        };

        assert!(
            commit_tech_currency_tick(tmp.path(), 1_700_000_000, preflight(), stories.clone())
                .unwrap()
        );
        std::fs::remove_file(&marker).unwrap();
        assert!(
            !commit_tech_currency_tick(tmp.path(), 1_700_000_001, preflight(), stories).unwrap(),
            "persisted queue item must dedup the retry"
        );
        assert!(marker_matches(&marker, week).unwrap());
        let queue =
            crate::proactive::ProactiveQueue::load_from(&tmp.path().join("proactive_queue.json"))
                .unwrap();
        assert_eq!(queue.len(), 1);
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

    // ── GOLD-ADAPT-OH-07: SubconsciousTickState persistence ─────────────────

    #[test]
    fn tick_state_default_is_zero_last_emitted() {
        let state = SubconsciousTickState::default();
        assert_eq!(state.last_emitted_unix, 0, "fresh install = never emitted");
    }

    #[test]
    fn tick_state_roundtrip_save_load() {
        let tmp = TempDir::new().unwrap();
        let state = SubconsciousTickState {
            last_emitted_unix: 1_700_000_000,
        };
        save_tick_state(tmp.path(), &state).unwrap();
        let loaded = load_tick_state(tmp.path()).unwrap();
        assert_eq!(loaded, state, "save + load must produce identical state");
    }

    #[test]
    fn load_tick_state_returns_default_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        let state = load_tick_state(tmp.path()).unwrap();
        assert_eq!(
            state.last_emitted_unix, 0,
            "missing file → default (never emitted)"
        );
    }

    #[test]
    fn load_tick_state_rejects_empty_existing_file() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("reflections");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("subconscious_state.json"), b"").unwrap();
        let state_path = dir.join("subconscious_state.json");
        let error = load_tick_state(tmp.path()).unwrap_err();
        assert!(error.contains("parse reflection tick state"));
        assert_eq!(
            std::fs::read(state_path).unwrap(),
            b"",
            "invalid state must remain available as forensic evidence"
        );
    }

    #[test]
    fn load_tick_state_rejects_oversized_existing_file() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("reflections");
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("subconscious_state.json");
        std::fs::write(&state_path, vec![b' '; MAX_TICK_STATE_BYTES + 1]).unwrap();

        let error = load_tick_state(tmp.path()).unwrap_err();
        assert!(error.contains("read reflection tick state"));
        assert!(error.contains("exceeds"));
        assert_eq!(
            std::fs::metadata(&state_path).unwrap().len(),
            (MAX_TICK_STATE_BYTES + 1) as u64,
            "oversized state must remain available as forensic evidence"
        );
    }

    #[test]
    fn queue_dedup_retry_repairs_missing_tick_state() {
        let tmp = TempDir::new().unwrap();
        let views = tmp.path().join("views.db");
        let conn = crate::memory::store::open(&views).unwrap();
        let now_unix = 1_700_000_000i64;
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                1i64,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                now_unix * 1_000_000_000 - 3_600_000_000_000i64,
                "rust async runtime diagnostics",
                "queue-state-retry",
            ],
        )
        .unwrap();

        assert!(run_reflection_tick_once(tmp.path(), now_unix, 0).unwrap());
        std::fs::remove_file(tick_state_path(tmp.path())).unwrap();

        assert!(
            !run_reflection_tick_once(tmp.path(), now_unix + 1, 0).unwrap(),
            "queue dedup must reject replay after state-loss window"
        );
        assert_eq!(
            load_tick_state(tmp.path()).unwrap().last_emitted_unix,
            now_unix + 1,
            "dedup retry must converge the missing tick state"
        );
        let queue =
            crate::proactive::ProactiveQueue::load_from(&tmp.path().join("proactive_queue.json"))
                .unwrap();
        assert_eq!(queue.len(), 1, "retry must not duplicate queue item");
    }

    // ── GOLD-ADAPT-OH-07: anti-double-emit window gate ───────────────────────

    #[test]
    fn window_gate_suppresses_second_tick_within_window() {
        // Two ticks within the window: second must be suppressed.
        let tmp = TempDir::new().unwrap();
        let t0: i64 = 1_700_000_000;
        let window: u64 = 3600; // 1h window
        let t1 = t0 + 60; // 60s later — still inside window

        // Manually plant a tick state as if the first tick already fired.
        save_tick_state(
            tmp.path(),
            &SubconsciousTickState {
                last_emitted_unix: t0,
            },
        )
        .unwrap();

        // Second tick within window → suppressed.
        let result = run_reflection_tick_once(tmp.path(), t1, window);
        assert_eq!(
            result,
            Ok(false),
            "second tick within window must be suppressed by window gate"
        );
    }

    #[test]
    fn window_gate_allows_tick_after_window_expires() {
        // Tick after the window expires: gate must pass through (no views.db
        // → Ok(false) from the "no episodes" path, NOT from the gate).
        let tmp = TempDir::new().unwrap();
        let t0: i64 = 1_700_000_000;
        let window: u64 = 3600; // 1h window
        let t_after = t0 + window as i64 + 1; // 1 second after window

        save_tick_state(
            tmp.path(),
            &SubconsciousTickState {
                last_emitted_unix: t0,
            },
        )
        .unwrap();

        // Tick after window expiry. No views.db → Ok(false) from that path,
        // NOT from the gate. We verify the gate was NOT the cause by checking
        // that the state file is still the original (gate would have exited
        // before the views.db check, and the code only updates state on enqueue).
        let result = run_reflection_tick_once(tmp.path(), t_after, window);
        // Should be Ok(false) because there's no views.db, not because of the gate.
        assert_eq!(
            result,
            Ok(false),
            "after window: no views.db gives Ok(false) from no-views-db path"
        );
        // State unchanged (no successful enqueue happened).
        let state = load_tick_state(tmp.path()).unwrap();
        assert_eq!(
            state.last_emitted_unix, t0,
            "last_emitted_unix must not change when no enqueue happened"
        );
    }

    #[test]
    fn window_gate_zero_means_disabled() {
        // min_window_secs = 0 → gate entirely disabled; even a very recent
        // last_emitted_unix must not suppress the tick.
        let tmp = TempDir::new().unwrap();
        let t0: i64 = 1_700_000_000;
        save_tick_state(
            tmp.path(),
            &SubconsciousTickState {
                last_emitted_unix: t0,
            },
        )
        .unwrap();

        // Tick at t0 + 1s with gate disabled → falls through to no-views-db path.
        let result = run_reflection_tick_once(tmp.path(), t0 + 1, 0);
        assert_eq!(
            result,
            Ok(false),
            "gate=0 must not suppress; Ok(false) from no-views-db, not gate"
        );
    }

    #[test]
    fn second_tick_within_window_does_not_update_state() {
        let tmp = TempDir::new().unwrap();
        let t0: i64 = 1_700_000_000;
        let window: u64 = 86_400; // 24h

        save_tick_state(
            tmp.path(),
            &SubconsciousTickState {
                last_emitted_unix: t0,
            },
        )
        .unwrap();

        // Tick 1h later — within window → suppressed.
        let r = run_reflection_tick_once(tmp.path(), t0 + 3600, window);
        assert_eq!(r, Ok(false));

        // State must NOT have been updated (save only happens on successful enqueue).
        let state = load_tick_state(tmp.path()).unwrap();
        assert_eq!(
            state.last_emitted_unix, t0,
            "suppressed tick must not overwrite last_emitted_unix"
        );
    }

    // ── GOLD-ADAPT-OH-07: ReflectionSitrep ──────────────────────────────────

    #[test]
    fn sitrep_empty_home_returns_zero_last_emitted_and_no_entries() {
        let tmp = TempDir::new().unwrap();
        let sitrep = recent_reflections_sitrep(tmp.path(), 7, 10).unwrap();
        assert_eq!(sitrep.last_emitted_unix, 0, "fresh install = never emitted");
        assert!(sitrep.recent.is_empty(), "no daily reflections yet");
    }

    #[test]
    fn sitrep_reflects_persisted_last_emitted() {
        let tmp = TempDir::new().unwrap();
        let t0: i64 = 1_700_000_000;
        save_tick_state(
            tmp.path(),
            &SubconsciousTickState {
                last_emitted_unix: t0,
            },
        )
        .unwrap();

        let sitrep = recent_reflections_sitrep(tmp.path(), 7, 10).unwrap();
        assert_eq!(
            sitrep.last_emitted_unix, t0,
            "sitrep must carry the persisted last_emitted_unix"
        );
    }

    #[test]
    fn sitrep_includes_recent_daily_reflections_newest_first() {
        use crate::reflection::periodic::{
            PeriodKind, append, build_reflection, date_tag_from_unix,
        };
        let tmp = TempDir::new().unwrap();

        // Write two daily reflections with different generated_ts_unix values.
        let now: i64 = crate::time::now_unix_i64();
        let today_tag = date_tag_from_unix(now);
        let yesterday_tag = date_tag_from_unix(now - 86_400);

        let r1 = build_reflection(
            PeriodKind::Daily,
            &yesterday_tag,
            &["kubernetes".into()],
            now - 86_400,
        )
        .unwrap();
        let r2 =
            build_reflection(PeriodKind::Daily, &today_tag, &["terraform".into()], now).unwrap();

        append(tmp.path(), &r1).unwrap();
        append(tmp.path(), &r2).unwrap();

        let sitrep = recent_reflections_sitrep(tmp.path(), 7, 10).unwrap();
        assert_eq!(sitrep.recent.len(), 2, "both daily reflections must appear");
        // Newest first.
        assert_eq!(
            sitrep.recent[0].tag, today_tag,
            "today's reflection must be first"
        );
        assert_eq!(
            sitrep.recent[1].tag, yesterday_tag,
            "yesterday's reflection must be second"
        );
        assert!(sitrep.recent[0].body.contains("terraform"));
        assert!(sitrep.recent[1].body.contains("kubernetes"));
    }

    #[test]
    fn sitrep_respects_max_entries_cap() {
        use crate::reflection::periodic::{
            PeriodKind, append, build_reflection, date_tag_from_unix,
        };
        let tmp = TempDir::new().unwrap();

        let now: i64 = crate::time::now_unix_i64();
        // Write 5 daily reflections across 5 days (today + 4 days back).
        for back in 0..5i64 {
            let ts = now - back * 86_400;
            let tag = date_tag_from_unix(ts);
            let r = build_reflection(PeriodKind::Daily, &tag, &["rust".into()], ts).unwrap();
            append(tmp.path(), &r).unwrap();
        }

        // Request at most 3.
        let sitrep = recent_reflections_sitrep(tmp.path(), 7, 3).unwrap();
        assert_eq!(sitrep.recent.len(), 3, "max_entries cap must be honoured");
    }

    // ── GOLD-ADAPT-OH-08: staged-observation write from run_reflection_tick_once ─

    #[test]
    fn oh08_run_reflection_tick_writes_staged_observation_when_topics_present() {
        let tmp = TempDir::new().unwrap();
        let views = tmp.path().join("views.db");
        let conn = crate::memory::store::open(&views).unwrap();
        let now_unix: i64 = 1_700_000_000;
        let now_ns = now_unix * 1_000_000_000;
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                1i64,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                now_ns - 3_600_000_000_000i64, // 1h ago, inside the 7-day window
                "kubernetes deployment rollout testing",
                "hash1",
            ],
        )
        .unwrap();
        // min_window_secs = 0 → gate disabled so we reach the staging write.
        let enqueued = run_reflection_tick_once(tmp.path(), now_unix, 0).unwrap();
        // Whether or not the queue dedup accepted the item, the staged observation
        // must exist (the observation is independent of the queue dedup result).
        let staged = crate::reflection::load_staged_observations(tmp.path());
        assert_eq!(staged.len(), 1, "one staged observation must be written");
        assert!(
            staged[0].body.contains("kubernetes"),
            "observation body must include the extracted topic; got: {}",
            staged[0].body
        );
        assert!(staged[0].surface_only, "surface_only flag must be true");
        let _ = enqueued;
    }

    #[test]
    fn oh08_staged_observation_not_written_when_no_topics() {
        // Empty views.db → no topics → build_reflection_observation returns None
        // → no staging write.
        let tmp = TempDir::new().unwrap();
        let views = tmp.path().join("views.db");
        let _conn = crate::memory::store::open(&views).unwrap();
        // No rows → topics empty.
        run_reflection_tick_once(tmp.path(), 1_700_000_000, 0).unwrap();
        assert!(
            crate::reflection::load_staged_observations(tmp.path()).is_empty(),
            "no topics → no staged observation"
        );
    }

    #[test]
    fn sitrep_lookback_days_bounds_how_far_back_we_read() {
        use crate::reflection::periodic::{
            PeriodKind, append, build_reflection, date_tag_from_unix,
        };
        let tmp = TempDir::new().unwrap();

        let now: i64 = crate::time::now_unix_i64();
        // Write a reflection 10 days back (outside a 7-day window).
        let old_ts = now - 10 * 86_400;
        let old_tag = date_tag_from_unix(old_ts);
        let r = build_reflection(PeriodKind::Daily, &old_tag, &["ancient".into()], old_ts).unwrap();
        append(tmp.path(), &r).unwrap();

        // With lookback_days=7, the 10-day-old entry must not appear.
        let sitrep = recent_reflections_sitrep(tmp.path(), 7, 10).unwrap();
        assert!(
            sitrep.recent.is_empty(),
            "reflection outside lookback window must not appear in sitrep"
        );
    }
}
