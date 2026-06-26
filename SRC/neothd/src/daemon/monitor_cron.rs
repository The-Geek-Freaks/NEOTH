//! HO-07 — neoth-monitor alerting daemon cron.
//!
//! Scans the WAL + `~/.neoth/crash.log` every `monitor.interval_secs` and
//! emits advisory WAL frames when anomalies are detected:
//!
//!   - `0x48 WAL_CRC_ALERT` — one or more `0x50 RECOVERY_TRUNCATED` /
//!     `0x51 COMPACTION_AUTH_FAILED` frames found in the rolling
//!     `wal_crc_window_secs` look-back. Immediate-sync.
//!   - `0x49 CRASH_LOG_ALERT` — new `[neoth panic]` lines appeared in
//!     `crash.log` since the last tick. Immediate-sync.
//!   - `0x4A CHANNEL_SILENCE_ALERT` — no `0x32 CHANNEL_INGRESS` /
//!     `0x33 CHANNEL_EGRESS` frames in the last `channel_silence_secs`
//!     while the UTC clock is inside the active window. Batchable.
//!
//! ## Design
//!
//! Mirrors [`super::resource_watch`] / [`super::drift_alert_cron`]:
//!   - Pure, injectable-input tick functions (testable without live I/O).
//!   - [`spawn_monitor_cron_loop`] returns `None` when `monitor.enabled ==
//!     false` so opt-out operators carry no idle tokio task (default OFF).
//!   - WAL frame scanner uses the same `decode_frame` /
//!     `parse_segment_header` pattern as `resource_watch.rs` tests.

use std::path::{Path, PathBuf};

use crate::config::MonitorConfig;
use crate::memory::scorecard::{
    PipelineHistory, ScorecardHistory, compute_quality_scorecard, HEALTHY_THRESHOLD,
};
use crate::wal::{
    events::{
        EVENT_TYPE_CHANNEL_EGRESS, EVENT_TYPE_CHANNEL_INGRESS, EVENT_TYPE_CHANNEL_SILENCE_ALERT,
        EVENT_TYPE_COMPACTION_AUTH_FAILED, EVENT_TYPE_CRASH_LOG_ALERT,
        EVENT_TYPE_MEMORY_PIPELINE_SCORECARD_TICK, EVENT_TYPE_RECOVERY_TRUNCATED,
        EVENT_TYPE_WAL_CRC_ALERT,
    },
    writer::WalWriterHandle,
};

// ---------------------------------------------------------------------------
// Data types

/// Result of a WAL CRC scan pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalCrcScanResult {
    /// Frames of type 0x50 RECOVERY_TRUNCATED found in the window.
    pub recovery_truncated_count: u32,
    /// Frames of type 0x51 COMPACTION_AUTH_FAILED found in the window.
    pub compaction_auth_failed_count: u32,
    /// Look-back window in seconds.
    pub window_secs: u64,
}

impl WalCrcScanResult {
    /// True when any integrity anomaly was found.
    pub fn has_anomalies(&self) -> bool {
        self.recovery_truncated_count > 0 || self.compaction_auth_failed_count > 0
    }
}

/// Result of a crash-log check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashLogResult {
    /// Path that was checked.
    pub crash_log_path: PathBuf,
    /// New `[neoth panic]` lines since the last known byte offset.
    pub new_crashes: u32,
    /// Unix timestamp from the most recent panic line, 0 when unparseable.
    pub last_crash_ts_unix: i64,
}

/// Result of a channel-silence check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSilenceResult {
    /// Unix timestamp of the last CHANNEL_INGRESS/EGRESS frame, 0 = none found.
    pub last_activity_ts_unix: i64,
    /// Seconds elapsed since last activity (or since look-back start when 0).
    pub silence_duration_secs: u64,
    /// Whether we are currently in the active UTC window.
    pub in_active_window: bool,
    /// Should an alert be emitted? (silence exceeded threshold AND in window)
    pub should_alert: bool,
}

// ---------------------------------------------------------------------------
// Pure WAL frame scanner

/// Count `0x50 RECOVERY_TRUNCATED` and `0x51 COMPACTION_AUTH_FAILED` frames
/// in a WAL segment file whose `ts_unix` payload field (JSON `"ts_unix"`)
/// falls within `[now_unix - window_secs, now_unix]`.
///
/// Parsing is best-effort: corrupt / truncated frames stop the scan for that
/// segment but don't propagate an error — the monitor is advisory.
pub fn count_crc_frames_in_segment(
    seg_bytes: &[u8],
    now_unix: i64,
    window_secs: u64,
) -> (u32, u32) {
    let cutoff = now_unix.saturating_sub(window_secs as i64);
    let mut truncated = 0u32;
    let mut auth_failed = 0u32;
    // GOLD-ARCH-03: for_each_frame so CRC-anomaly frames inside a v2/zstd-
    // compressed segment are counted, not silently skipped (the prior walk
    // parsed the header but ran decode_frame over the raw zstd blob).
    if let Err(e) = crate::wal::scan::for_each_frame(seg_bytes, |_, dec| {
        if dec.header.event_type == EVENT_TYPE_RECOVERY_TRUNCATED
            || dec.header.event_type == EVENT_TYPE_COMPACTION_AUTH_FAILED
        {
            // Parse ts_unix from JSON payload for window filtering.
            let ts = serde_json::from_slice::<serde_json::Value>(dec.payload)
                .ok()
                .and_then(|v| v.get("ts_unix")?.as_i64())
                .unwrap_or(now_unix); // conservative: include when unparseable
            if ts >= cutoff {
                if dec.header.event_type == EVENT_TYPE_RECOVERY_TRUNCATED {
                    truncated += 1;
                } else {
                    auth_failed += 1;
                }
            }
        }
        Ok(())
    }) {
        // GR-133 — surface a tamper-suspect segment instead of silently dropping
        // the error (its CRC-anomaly frames won't be counted). The monitor is
        // advisory, but it must not HIDE an integrity failure.
        tracing::warn!(error = %e, "monitor CRC scan: skipping a tamper-suspect WAL segment");
    }
    (truncated, auth_failed)
}

/// Scan all `*.wal` segment files in `wal_dir` and aggregate CRC anomaly
/// counts for the rolling `window_secs` window ending at `now_unix`.
pub fn scan_wal_dir_for_crc_anomalies(
    wal_dir: &Path,
    now_unix: i64,
    window_secs: u64,
) -> WalCrcScanResult {
    let mut truncated_total = 0u32;
    let mut auth_failed_total = 0u32;
    if let Ok(rd) = std::fs::read_dir(wal_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("wal") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&p) else {
                continue;
            };
            let (t, a) = count_crc_frames_in_segment(&bytes, now_unix, window_secs);
            truncated_total = truncated_total.saturating_add(t);
            auth_failed_total = auth_failed_total.saturating_add(a);
        }
    }
    WalCrcScanResult {
        recovery_truncated_count: truncated_total,
        compaction_auth_failed_count: auth_failed_total,
        window_secs,
    }
}

// ---------------------------------------------------------------------------
// Crash-log checker

/// Parse a `[neoth panic] ts_unix=NNN ...` line and extract the timestamp.
pub fn parse_panic_ts(line: &str) -> Option<i64> {
    let prefix = "ts_unix=";
    let start = line.find(prefix)?;
    let after = &line[start + prefix.len()..];
    after
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<i64>().ok())
}

/// Check `crash_log_path` for new `[neoth panic]` lines. `known_byte_offset`
/// is the byte count seen on the last tick — new lines are those in the file
/// tail beyond this offset. Returns `(result, new_offset)`.
pub fn check_crash_log(crash_log_path: &Path, known_byte_offset: u64) -> (CrashLogResult, u64) {
    let content = match std::fs::read(crash_log_path) {
        Ok(b) => b,
        Err(_) => {
            return (
                CrashLogResult {
                    crash_log_path: crash_log_path.to_path_buf(),
                    new_crashes: 0,
                    last_crash_ts_unix: 0,
                },
                known_byte_offset,
            );
        }
    };
    let new_offset = content.len() as u64;
    let tail = if known_byte_offset as usize <= content.len() {
        &content[known_byte_offset as usize..]
    } else {
        // File was truncated/rotated — scan from start.
        &content[..]
    };
    let tail_str = String::from_utf8_lossy(tail);
    let mut count = 0u32;
    let mut last_ts = 0i64;
    for line in tail_str.lines() {
        if line.contains("[neoth panic]") {
            count += 1;
            if let Some(ts) = parse_panic_ts(line) {
                last_ts = last_ts.max(ts);
            }
        }
    }
    (
        CrashLogResult {
            crash_log_path: crash_log_path.to_path_buf(),
            new_crashes: count,
            last_crash_ts_unix: last_ts,
        },
        new_offset,
    )
}

// ---------------------------------------------------------------------------
// Channel-silence checker

/// Scan WAL segment for the most recent CHANNEL_INGRESS / CHANNEL_EGRESS
/// `ts_unix` field.
pub fn latest_channel_activity_in_segment(seg_bytes: &[u8]) -> Option<i64> {
    let mut latest: Option<i64> = None;
    // GOLD-ARCH-03: for_each_frame so channel activity inside a v2/zstd-
    // compressed segment is seen, not silently skipped.
    if let Err(e) = crate::wal::scan::for_each_frame(seg_bytes, |_, dec| {
        if dec.header.event_type == EVENT_TYPE_CHANNEL_INGRESS
            || dec.header.event_type == EVENT_TYPE_CHANNEL_EGRESS
        {
            let ts = serde_json::from_slice::<serde_json::Value>(dec.payload)
                .ok()
                .and_then(|v| v.get("ts_unix")?.as_i64());
            if let Some(t) = ts {
                latest = Some(latest.map_or(t, |prev| prev.max(t)));
            }
        }
        Ok(())
    }) {
        // GR-133 — surface a tamper-suspect segment rather than silently dropping
        // the error (its channel-activity frames won't be seen).
        tracing::warn!(error = %e, "monitor channel-activity scan: skipping a tamper-suspect WAL segment");
    }
    latest
}

/// Scan all `*.wal` files in `wal_dir` for the latest CHANNEL_INGRESS /
/// CHANNEL_EGRESS timestamp.
pub fn scan_wal_dir_for_channel_activity(wal_dir: &Path) -> Option<i64> {
    let mut latest: Option<i64> = None;
    if let Ok(rd) = std::fs::read_dir(wal_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("wal") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&p) else {
                continue;
            };
            if let Some(t) = latest_channel_activity_in_segment(&bytes) {
                latest = Some(latest.map_or(t, |prev| prev.max(t)));
            }
        }
    }
    latest
}

/// Check whether the current UTC hour is inside the active window
/// `[start, end)` (exclusive end). Wraps midnight correctly.
pub fn is_in_active_window(utc_hour: u8, start: u8, end: u8) -> bool {
    if start <= end {
        utc_hour >= start && utc_hour < end
    } else {
        // Window wraps midnight, e.g. 22..=06
        utc_hour >= start || utc_hour < end
    }
}

/// Evaluate channel silence. `now_unix` is the current wall-clock second.
pub fn evaluate_channel_silence(
    last_activity: Option<i64>,
    now_unix: i64,
    config: &MonitorConfig,
) -> ChannelSilenceResult {
    let utc_hour = {
        // Compute UTC hour from unix timestamp (simple modulo arithmetic).
        let secs_in_day = now_unix.rem_euclid(86400);
        (secs_in_day / 3600) as u8
    };
    let in_window = is_in_active_window(
        utc_hour,
        config.channel_silence_active_utc_start,
        config.channel_silence_active_utc_end,
    );
    let (last_ts, silence_secs, should_alert) = match last_activity {
        Some(t) => {
            let silence = (now_unix - t).max(0) as u64;
            (
                t,
                silence,
                in_window && silence >= config.channel_silence_secs,
            )
        }
        // MONITOR-05: never saw a CHANNEL_INGRESS/EGRESS frame → we cannot claim
        // "silence" (silence = was-active-now-quiet). A host with NO channels
        // configured (or a channel that has never been live) produces no frames
        // and must NOT trip a false-positive silence alert.
        None => (0i64, 0u64, false),
    };
    ChannelSilenceResult {
        last_activity_ts_unix: last_ts,
        silence_duration_secs: silence_secs,
        in_active_window: in_window,
        should_alert,
    }
}

/// MONITOR-04 — cross-tick dedup memory: the last wall-clock second each alert
/// KIND was emitted, so the live loop suppresses re-emitting the same kind
/// within `monitor.min_repeat_alert_secs`. Lives in the spawn loop (like the
/// crash-log offset). Crash alerts are already edge-triggered (crash.log
/// byte-offset delta) so they need no entry here.
#[derive(Debug, Default, Clone, Copy)]
pub struct MonitorEmitState {
    pub last_wal_crc_emit: i64,
    pub last_silence_emit: i64,
}

/// True when `now` is at least `window_secs` past `last_emit` (or there was no
/// prior emit — `last_emit == 0`). `window_secs == 0` disables dedup.
pub fn alert_due(last_emit: i64, now: i64, window_secs: u64) -> bool {
    last_emit == 0 || now.saturating_sub(last_emit) >= window_secs as i64
}

// ---------------------------------------------------------------------------
// Tick functions (injectable, unit-testable)

/// One monitor tick. Accepts pre-computed inputs so the function is
/// testable without live WAL I/O. Emits WAL frames as appropriate.
///
/// Returns `(wal_crc_alerted, crash_alerted, silence_alerted)`.
pub async fn run_monitor_tick(
    config: &MonitorConfig,
    writer: &WalWriterHandle,
    wal_scan: WalCrcScanResult,
    crash: Option<CrashLogResult>,
    channel: ChannelSilenceResult,
) -> Result<(bool, bool, bool), String> {
    let ts_unix = crate::time::now_unix_i64();

    let mut wal_alerted = false;
    let mut crash_alerted = false;
    let mut silence_alerted = false;

    // ── 0x48 WAL_CRC_ALERT ──────────────────────────────────────────────────
    if wal_scan.has_anomalies() {
        let payload = serde_json::to_vec(&serde_json::json!({
            "recovery_truncated_count": wal_scan.recovery_truncated_count,
            "compaction_auth_failed_count": wal_scan.compaction_auth_failed_count,
            "window_secs": wal_scan.window_secs,
            "ts_unix": ts_unix,
        }))
        .map_err(|e| format!("serialize wal_crc payload: {e}"))?;
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_WAL_CRC_ALERT, &payload)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
        writer
            .append(header, payload)
            .await
            .map_err(|e| format!("wal append WAL_CRC_ALERT: {e}"))?;
        tracing::warn!(
            recovery_truncated = wal_scan.recovery_truncated_count,
            compaction_auth_failed = wal_scan.compaction_auth_failed_count,
            window_secs = wal_scan.window_secs,
            "monitor: WAL integrity anomalies detected — `neoth wal show --type recovery_truncated`",
        );
        wal_alerted = true;
    }

    // ── 0x49 CRASH_LOG_ALERT ────────────────────────────────────────────────
    if let Some(ref c) = crash {
        if c.new_crashes > 0 {
            let payload = serde_json::to_vec(&serde_json::json!({
                "crash_log_path": c.crash_log_path.to_string_lossy(),
                "new_crashes_since_last_check": c.new_crashes,
                "last_crash_ts_unix": c.last_crash_ts_unix,
                "ts_unix": ts_unix,
            }))
            .map_err(|e| format!("serialize crash_log payload: {e}"))?;
            let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_CRASH_LOG_ALERT, &payload)
                .flags(crate::wal::EventFlags::SYNTHETIC)
                .build();
            writer
                .append(header, payload)
                .await
                .map_err(|e| format!("wal append CRASH_LOG_ALERT: {e}"))?;
            tracing::warn!(
                new_crashes = c.new_crashes,
                last_crash_ts = c.last_crash_ts_unix,
                path = %c.crash_log_path.display(),
                "monitor: new daemon panics in crash.log — inspect and report",
            );
            crash_alerted = true;

            // GOLD-ADAPT-HERMES-07b — categorise the NEW panic lines into
            // staged, operator-reviewable PatchProposals. Advisory only: nothing
            // is auto-applied (`neoth self-heal list` surfaces them). Best-effort.
            if let Ok(content) = std::fs::read_to_string(&c.crash_log_path) {
                let panic_lines: Vec<&str> = content
                    .lines()
                    .filter(|l| l.contains("[neoth panic]") || l.contains("panicked at"))
                    .collect();
                // The newly-appeared panics are the tail of the file.
                let take = (c.new_crashes as usize).min(panic_lines.len());
                let new_lines = &panic_lines[panic_lines.len() - take..];
                let proposals = crate::daemon::self_heal::analyse_panic_lines(new_lines, ts_unix);
                if let Some(home) = c.crash_log_path.parent() {
                    match crate::daemon::self_heal::stage_proposals(home, &proposals) {
                        Ok(()) if !proposals.is_empty() => tracing::info!(
                            staged = proposals.len(),
                            "HERMES-07b: staged self-heal patch proposals for operator review",
                        ),
                        Ok(()) => {}
                        Err(e) => tracing::warn!(error = %e, "self-heal: stage proposals failed"),
                    }
                }
            }
        }
    }

    // ── 0x4A CHANNEL_SILENCE_ALERT ──────────────────────────────────────────
    if channel.should_alert {
        let payload = serde_json::to_vec(&serde_json::json!({
            "last_activity_ts_unix": channel.last_activity_ts_unix,
            "silence_duration_secs": channel.silence_duration_secs,
            "active_window_utc_start": config.channel_silence_active_utc_start,
            "active_window_utc_end": config.channel_silence_active_utc_end,
            "ts_unix": ts_unix,
        }))
        .map_err(|e| format!("serialize channel_silence payload: {e}"))?;
        let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_CHANNEL_SILENCE_ALERT, &payload)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
        writer
            .append(header, payload)
            .await
            .map_err(|e| format!("wal append CHANNEL_SILENCE_ALERT: {e}"))?;
        tracing::warn!(
            silence_secs = channel.silence_duration_secs,
            last_activity = channel.last_activity_ts_unix,
            "monitor: channel has been silent — check messenger adapter connectivity",
        );
        silence_alerted = true;
    }

    Ok((wal_alerted, crash_alerted, silence_alerted))
}

/// Live tick wrapper — reads the WAL dir + crash log then calls
/// [`run_monitor_tick`]. Accepts `home` + `wal_dir` so the daemon can
/// pass the real paths; tests substitute tempdirs.
pub async fn run_monitor_tick_live(
    config: &MonitorConfig,
    writer: &WalWriterHandle,
    home: &Path,
    wal_dir: &Path,
    crash_log_offset: &mut u64,
    emit_state: &mut MonitorEmitState,
) -> Result<(bool, bool, bool), String> {
    let now_unix = crate::time::now_unix_i64();

    // WAL CRC scan
    let mut wal_scan =
        scan_wal_dir_for_crc_anomalies(wal_dir, now_unix, config.wal_crc_window_secs);
    // MONITOR-04 dedup: the same corruption frames linger in the look-back
    // window for many ticks — suppress re-emit within `min_repeat_alert_secs`
    // by zeroing the counts (so `run_monitor_tick` sees no anomaly this tick).
    if wal_scan.has_anomalies()
        && !alert_due(
            emit_state.last_wal_crc_emit,
            now_unix,
            config.min_repeat_alert_secs,
        )
    {
        wal_scan.recovery_truncated_count = 0;
        wal_scan.compaction_auth_failed_count = 0;
    }

    // Crash log check (already edge-triggered via the byte offset → no dedup).
    let crash_log_path = home.join("crash.log");
    let (crash_result, new_offset) = check_crash_log(&crash_log_path, *crash_log_offset);
    *crash_log_offset = new_offset;
    let crash = if crash_log_path.exists() {
        Some(crash_result)
    } else {
        None
    };

    // Channel silence check
    let last_activity = scan_wal_dir_for_channel_activity(wal_dir);
    let mut channel = evaluate_channel_silence(last_activity, now_unix, config);
    // MONITOR-04 dedup: silence is level-triggered (stays true while quiet) —
    // suppress re-emit within the window.
    if channel.should_alert
        && !alert_due(
            emit_state.last_silence_emit,
            now_unix,
            config.min_repeat_alert_secs,
        )
    {
        channel.should_alert = false;
    }

    let (wal, crash_alerted, silence) =
        run_monitor_tick(config, writer, wal_scan, crash, channel).await?;
    // Record the emits so the next tick can dedup against them.
    if wal {
        emit_state.last_wal_crc_emit = now_unix;
    }
    if silence {
        emit_state.last_silence_emit = now_unix;
    }
    Ok((wal, crash_alerted, silence))
}

// ---------------------------------------------------------------------------
// Spawn loop

/// Spawn the monitor cron loop. Returns `None` when `config.enabled ==
/// false` (default) so opt-out operators carry no idle tokio task.
// ---------------------------------------------------------------------------
// JV-MEM-15 — quality scorecard integration

/// One scorecard tick: open the store read-only, compute the 5-dim scorecard,
/// append to history, and log. All failures are warn-logged — the main monitor
/// loop must not be disrupted by a missing or locked store.
pub fn run_scorecard_tick(home: &Path, now_unix: i64, history: &mut ScorecardHistory) {
    let store_path = home.join(".neoth").join("views.db");
    let conn = match crate::memory::store::open(&store_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "scorecard tick: cannot open memory store");
            return;
        }
    };
    match compute_quality_scorecard(&conn, now_unix, 200) {
        Ok(sc) => {
            let grade = sc.grade;
            let composite = sc.composite;
            let is_healthy = sc.is_healthy;
            history.push(sc);
            if is_healthy {
                tracing::debug!(
                    grade = grade.as_str(),
                    composite,
                    "memory scorecard: healthy (JV-MEM-15)",
                );
            } else {
                tracing::warn!(
                    grade = grade.as_str(),
                    composite,
                    threshold = HEALTHY_THRESHOLD,
                    persistently_unhealthy = history.is_persistently_unhealthy(),
                    "memory scorecard: below healthy threshold (JV-MEM-15)",
                );
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "scorecard tick: query failed");
        }
    }
}

/// GOLD-ADAPT-MEM-11 — 15-point per-subsystem pipeline scorecard tick.
///
/// Opens the memory store read-only in a synchronous scope (the connection is
/// dropped before any `.await` — SEND SAFETY for rusqlite::Connection which is
/// `!Send`), runs `read_and_compute_pipeline_scorecard`, pushes to `history`,
/// and emits a `0x9F MEMORY_PIPELINE_SCORECARD_TICK` WAL frame unconditionally
/// every tick so the operator gets a time-series audit trail via
/// `neoth wal show --type memory_pipeline_scorecard_tick`.
///
/// All failures are warn-logged; the monitor loop must not be disrupted by a
/// missing or locked store, a serialize error, or a WAL write error.
pub async fn run_pipeline_scorecard_tick(
    home: &std::path::Path,
    now_unix: i64,
    writer: &WalWriterHandle,
    history: &mut PipelineHistory,
) {
    use crate::memory::scorecard::read_and_compute_pipeline_scorecard;

    // ── 1. Open DB, compute scorecard, drop connection — all sync ────────────
    let store_path = home.join(".neoth").join("views.db");
    let result = {
        // Tight sync scope: open, query, drop.
        match crate::memory::store::open(&store_path) {
            Ok(conn) => {
                let r = read_and_compute_pipeline_scorecard(&conn, now_unix);
                // conn is dropped here (end of block)
                r
            }
            Err(e) => {
                tracing::warn!(error = %e, "pipeline scorecard tick: cannot open memory store");
                return;
            }
        }
    };

    let sc = match result {
        Ok(sc) => sc,
        Err(e) => {
            tracing::warn!(error = %e, "pipeline scorecard tick: query failed");
            return;
        }
    };

    // ── 2. Log + push to history ──────────────────────────────────────────────
    let overall_grade = sc.overall_grade;
    let overall_composite = sc.overall_composite;
    let is_healthy = sc.is_healthy;

    if is_healthy {
        tracing::debug!(
            grade = overall_grade.as_str(),
            composite = overall_composite,
            "memory pipeline scorecard: healthy (MEM-11)",
        );
    } else {
        // Warn on each subsystem that is below grade C.
        for sub in &sc.subsystems {
            if !sub.grade.is_healthy() {
                tracing::warn!(
                    subsystem = sub.name,
                    grade = sub.grade.as_str(),
                    score = sub.score,
                    "memory pipeline scorecard: subsystem below healthy threshold (MEM-11)",
                );
            }
        }
        tracing::warn!(
            grade = overall_grade.as_str(),
            composite = overall_composite,
            threshold = crate::memory::scorecard::HEALTHY_THRESHOLD,
            "memory pipeline scorecard: overall below healthy threshold (MEM-11)",
        );
    }

    history.push(sc.clone());

    // ── 3. Emit 0x9F WAL frame (best-effort, unconditional) ──────────────────
    let payload_value = serde_json::json!({
        "ts_unix": now_unix,
        "overall_grade": overall_grade.as_str(),
        "overall_composite": overall_composite,
        "subsystems": sc.subsystems.iter().map(|s| serde_json::json!({
            "name": s.name,
            "score": s.score,
            "grade": s.grade.as_str(),
        })).collect::<Vec<_>>(),
    });
    let payload = match serde_json::to_vec(&payload_value) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "pipeline scorecard tick: failed to serialize WAL payload");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_MEMORY_PIPELINE_SCORECARD_TICK, &payload)
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(
            error = %e,
            "pipeline scorecard tick: WAL append failed (advisory — not fatal)"
        );
    }
}

/// GOLD-ADOPT-27 — at monitor start, probe every channel's config-completeness
/// and `warn!` any that are actively misconfigured (e.g. one of a required
/// token pair). Best-effort: a missing config/creds file → no warning. The full
/// per-channel table lives in `neoth status`.
fn warn_misconfigured_channels(home: &Path) {
    let cfg = crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml")).ok();
    let creds =
        crate::config::credentials::Credentials::load_or_default(&home.join("credentials.yaml"))
            .unwrap_or_default();
    let view = crate::channels::probe::ChannelCredsView::from_config(cfg.as_ref(), &creds);
    for h in crate::channels::probe::misconfigured(&view) {
        tracing::warn!(
            channel = h.channel,
            status = h.status.as_str(),
            "channel misconfigured: {} (see `neoth status`)",
            h.message
        );
    }
}

pub fn spawn_monitor_cron_loop(
    config: MonitorConfig,
    home: PathBuf,
    wal_dir: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("monitor cron disabled (monitor.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut crash_log_offset = 0u64;
        let mut emit_state = MonitorEmitState::default();
        // JV-MEM-15 — 7-day scorecard history ring buffer (headless, no DB writes).
        let mut scorecard_history = ScorecardHistory::default();
        // GOLD-ADAPT-MEM-11 — 15-point pipeline scorecard history ring buffer.
        let mut pipeline_history = PipelineHistory::default();
        tracing::info!(
            interval_secs = interval.as_secs(),
            min_repeat_alert_secs = config.min_repeat_alert_secs,
            "monitor cron loop online (HO-07)",
        );
        // GOLD-ADOPT-27 — channel health probe. A channel misconfig is STATIC
        // config state (changes only on reload), so warn ONCE at monitor start
        // rather than every tick. The rich per-channel table is `neoth status`.
        warn_misconfigured_channels(&home);
        loop {
            ticker.tick().await;
            match run_monitor_tick_live(
                &config,
                &writer,
                &home,
                &wal_dir,
                &mut crash_log_offset,
                &mut emit_state,
            )
            .await
            {
                Ok((wal, crash, silence)) => {
                    if wal || crash || silence {
                        tracing::info!(wal, crash, silence, "monitor tick: alerts emitted");
                    } else {
                        tracing::debug!("monitor tick: clean");
                    }
                }
                Err(e) => tracing::error!(error = %e, "monitor tick failed"),
            }

            // JV-MEM-15 — quality scorecard tick (best-effort; never fails the loop).
            run_scorecard_tick(&home, crate::time::now_unix_i64(), &mut scorecard_history);
            // GOLD-ADAPT-MEM-11 — 15-point pipeline scorecard tick.
            run_pipeline_scorecard_tick(
                &home,
                crate::time::now_unix_i64(),
                &writer,
                &mut pipeline_history,
            )
            .await;
        }
    }))
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::{
        EVENT_TYPE_CHANNEL_SILENCE_ALERT, EVENT_TYPE_CRASH_LOG_ALERT, EVENT_TYPE_WAL_CRC_ALERT,
    };

    fn default_config() -> MonitorConfig {
        MonitorConfig {
            enabled: true,
            interval_secs: 300,
            wal_crc_window_secs: 3600,
            channel_silence_secs: 1800,
            channel_silence_active_utc_start: 7,
            channel_silence_active_utc_end: 21,
            min_repeat_alert_secs: 3600,
        }
    }

    #[test]
    fn monitor_05_no_silence_alert_when_never_any_channel_activity() {
        // MONITOR-05: last_activity = None (no channel frame ever) during the
        // ACTIVE window must NOT alert — a no-channel host can't be "silent".
        let cfg = default_config();
        let now_at_10am = 36000i64; // 10:00 UTC, inside 07..21
        let r = evaluate_channel_silence(None, now_at_10am, &cfg);
        assert!(r.in_active_window, "10:00 is inside the active window");
        assert!(
            !r.should_alert,
            "no channel activity ever seen → no silence false-positive",
        );
    }

    #[test]
    fn monitor_04_alert_due_window() {
        // First emit (last==0) always due; within window not due; past window due;
        // window 0 disables dedup (always due).
        let now = 1_700_000_000i64;
        assert!(
            alert_due(0, now, 3600),
            "first emit (no prior) is always due"
        );
        assert!(
            !alert_due(now - 100, now, 3600),
            "100s < 3600s window → suppressed"
        );
        assert!(
            alert_due(now - 4000, now, 3600),
            "4000s >= 3600s → due again"
        );
        assert!(alert_due(now - 1, now, 0), "window 0 disables dedup");
    }

    /// Count frames of a given event_type in an uncompressed WAL segment.
    fn count_frames(seg: &std::path::Path, event_type: u8) -> usize {
        let Ok(bytes) = std::fs::read(seg) else {
            return 0;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            return 0;
        };
        let mut cursor = hdr.header_len();
        let mut count = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == event_type {
                count += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        count
    }

    // ── Test 1: WAL CRC — no anomalies ──────────────────────────────────────

    #[tokio::test]
    async fn wal_crc_no_alert_when_no_anomaly_frames() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("monitor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let cfg = default_config();
        let scan = WalCrcScanResult {
            recovery_truncated_count: 0,
            compaction_auth_failed_count: 0,
            window_secs: 3600,
        };
        let channel = ChannelSilenceResult {
            last_activity_ts_unix: 0,
            silence_duration_secs: 0,
            in_active_window: false,
            should_alert: false,
        };
        let (wal_alerted, _, _) = run_monitor_tick(&cfg, &writer, scan, None, channel)
            .await
            .unwrap();
        assert!(!wal_alerted, "no anomalies → no alert");
        assert_eq!(count_frames(&seg, EVENT_TYPE_WAL_CRC_ALERT), 0);
    }

    // ── Test 2: WAL CRC — anomaly emits 0x48 ────────────────────────────────

    #[tokio::test]
    async fn wal_crc_alert_when_recovery_truncated_present() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("monitor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let cfg = default_config();
        let scan = WalCrcScanResult {
            recovery_truncated_count: 2,
            compaction_auth_failed_count: 1,
            window_secs: 3600,
        };
        let channel = ChannelSilenceResult {
            last_activity_ts_unix: 0,
            silence_duration_secs: 0,
            in_active_window: false,
            should_alert: false,
        };
        let (wal_alerted, _, _) = run_monitor_tick(&cfg, &writer, scan, None, channel)
            .await
            .unwrap();
        assert!(wal_alerted);
        assert_eq!(count_frames(&seg, EVENT_TYPE_WAL_CRC_ALERT), 1);
    }

    // ── Test 3: crash-log — no new content ──────────────────────────────────

    #[tokio::test]
    async fn crash_log_no_alert_when_no_new_content() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("monitor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let cfg = default_config();
        let crash = CrashLogResult {
            crash_log_path: dir.path().join("crash.log"),
            new_crashes: 0,
            last_crash_ts_unix: 0,
        };
        let scan = WalCrcScanResult {
            recovery_truncated_count: 0,
            compaction_auth_failed_count: 0,
            window_secs: 3600,
        };
        let channel = ChannelSilenceResult {
            last_activity_ts_unix: 0,
            silence_duration_secs: 0,
            in_active_window: false,
            should_alert: false,
        };
        let (_, crash_alerted, _) = run_monitor_tick(&cfg, &writer, scan, Some(crash), channel)
            .await
            .unwrap();
        assert!(!crash_alerted);
        assert_eq!(count_frames(&seg, EVENT_TYPE_CRASH_LOG_ALERT), 0);
    }

    // ── Test 4: crash-log — new panic line emits 0x49 ───────────────────────

    #[tokio::test]
    async fn crash_log_alert_when_new_panic_line() {
        let dir = tempfile::tempdir().unwrap();
        let crash_log = dir.path().join("crash.log");
        std::fs::write(
            &crash_log,
            "[neoth panic] ts_unix=1700000100 at src/lib.rs:42: intentional test panic (version=0.3.0)\n",
        )
        .unwrap();
        let (result, _new_offset) = check_crash_log(&crash_log, 0);
        assert_eq!(result.new_crashes, 1);
        assert_eq!(result.last_crash_ts_unix, 1700000100);

        let seg = dir.path().join("monitor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let cfg = default_config();
        let scan = WalCrcScanResult {
            recovery_truncated_count: 0,
            compaction_auth_failed_count: 0,
            window_secs: 3600,
        };
        let channel = ChannelSilenceResult {
            last_activity_ts_unix: 0,
            silence_duration_secs: 0,
            in_active_window: false,
            should_alert: false,
        };
        let (_, crash_alerted, _) = run_monitor_tick(&cfg, &writer, scan, Some(result), channel)
            .await
            .unwrap();
        assert!(crash_alerted);
        assert_eq!(count_frames(&seg, EVENT_TYPE_CRASH_LOG_ALERT), 1);
    }

    // ── Test 5: channel silence — recent activity → no alert ────────────────

    #[tokio::test]
    async fn channel_silence_no_alert_when_recent_activity() {
        let cfg = default_config();
        let now = 1_700_000_000i64;
        // Activity 10 seconds ago — well within 1800s threshold.
        let result = evaluate_channel_silence(Some(now - 10), now, &cfg);
        assert!(!result.should_alert, "recent activity → no alert");
    }

    // ── Test 6: channel silence — outside active window → no alert ──────────

    #[tokio::test]
    async fn channel_silence_no_alert_outside_active_window() {
        let cfg = default_config();
        // now_unix at 02:00 UTC — outside 07..21 window.
        // Unix 0 = Thu 1970-01-01 00:00:00 UTC. 2*3600 = 7200 → utc_hour=2.
        let now_at_2am = 7200i64; // 02:00:00 UTC on 1970-01-01
        let result = evaluate_channel_silence(None, now_at_2am, &cfg);
        assert!(!result.should_alert, "outside active window → no alert");
        assert!(!result.in_active_window);
    }

    // ── Test 7: channel silence — long silence during window → alert ─────────

    #[tokio::test]
    async fn channel_silence_alert_when_stale_during_active_window() {
        let cfg = default_config();
        // 10:00 UTC = hour 10 → inside 07..21 window.
        let now_at_10am = 36000i64; // 10 * 3600
        // last activity was 2000s ago → > 1800s threshold
        let last_activity = now_at_10am - 2000;
        let result = evaluate_channel_silence(Some(last_activity), now_at_10am, &cfg);
        assert!(result.should_alert);
        assert!(result.in_active_window);
        assert_eq!(result.silence_duration_secs, 2000);

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("monitor.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let scan = WalCrcScanResult {
            recovery_truncated_count: 0,
            compaction_auth_failed_count: 0,
            window_secs: 3600,
        };
        let (_, _, silence_alerted) = run_monitor_tick(&cfg, &writer, scan, None, result)
            .await
            .unwrap();
        assert!(silence_alerted);
        drop(writer);
        join.await.unwrap();
        assert_eq!(count_frames(&seg, EVENT_TYPE_CHANNEL_SILENCE_ALERT), 1);
    }

    // ── Test 8: spawn returns None when disabled ─────────────────────────────

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("monitor.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = MonitorConfig {
            enabled: false,
            ..MonitorConfig::default()
        };
        assert!(
            spawn_monitor_cron_loop(
                cfg,
                dir.path().to_path_buf(),
                dir.path().to_path_buf(),
                writer
            )
            .is_none()
        );
    }

    // ── GOLD-ADAPT-MEM-11: pipeline scorecard tick emits 0x9F frame ──────────

    #[tokio::test]
    async fn pipeline_scorecard_tick_emits_0x9f_wal_frame() {
        use crate::memory::scorecard::PipelineHistory;
        use crate::wal::events::EVENT_TYPE_MEMORY_PIPELINE_SCORECARD_TICK;

        // 1. Set up tempdir with a real views.db (empty store is fine — probes
        //    return 0-counts and map to neutral fallbacks).
        let dir = tempfile::tempdir().unwrap();
        // The store path is home/.neoth/views.db
        let neoth_home = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_home).unwrap();
        let store_path = neoth_home.join("views.db");
        let _conn = crate::memory::store::open(&store_path).unwrap();
        drop(_conn); // close so the tick can re-open it

        // 2. Spin up a real WAL writer.
        let seg = dir.path().join("pipeline-scorecard.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        // 3. Call the tick.
        let now_unix = crate::time::now_unix_i64();
        let mut history = PipelineHistory::default();
        run_pipeline_scorecard_tick(dir.path(), now_unix, &writer, &mut history).await;

        // 4. Assert exactly ONE 0x9F frame was written.
        assert_eq!(
            count_frames(&seg, EVENT_TYPE_MEMORY_PIPELINE_SCORECARD_TICK),
            1,
            "pipeline scorecard tick must emit exactly one 0x9F WAL frame"
        );

        // 5. Decode the frame payload and verify structure.
        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == EVENT_TYPE_MEMORY_PIPELINE_SCORECARD_TICK {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                let subs = v.get("subsystems").unwrap().as_array().unwrap();
                assert_eq!(
                    subs.len(),
                    15,
                    "payload must carry exactly 15 subsystem entries"
                );
                assert!(
                    v.get("overall_grade").is_some(),
                    "payload must contain overall_grade"
                );
                assert!(
                    v.get("overall_composite").is_some(),
                    "payload must contain overall_composite"
                );
                break;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }

        // 6. Assert history received the entry.
        assert_eq!(history.len(), 1, "history must hold one entry after the tick");
        assert!(
            history.latest().unwrap().is_healthy,
            "empty store must produce a healthy scorecard"
        );
    }

    // ── Extra: is_in_active_window boundary cases ────────────────────────────

    #[test]
    fn active_window_boundary_cases() {
        // Standard window 07..21
        assert!(is_in_active_window(7, 7, 21)); // exactly at start
        assert!(is_in_active_window(20, 7, 21)); // one before end
        assert!(!is_in_active_window(21, 7, 21)); // at end (exclusive)
        assert!(!is_in_active_window(6, 7, 21)); // just before start
        // Wrapping window 22..06
        assert!(is_in_active_window(23, 22, 6));
        assert!(is_in_active_window(0, 22, 6));
        assert!(is_in_active_window(5, 22, 6));
        assert!(!is_in_active_window(6, 22, 6));
        assert!(!is_in_active_window(21, 22, 6));
    }

    // ── Extra: parse_panic_ts ────────────────────────────────────────────────

    #[test]
    fn parse_panic_ts_extracts_timestamp() {
        let line = "[neoth panic] ts_unix=1700000100 at src/lib.rs:42: boom (version=0.3.0)";
        assert_eq!(parse_panic_ts(line), Some(1700000100));
        assert_eq!(parse_panic_ts("[no ts here]"), None);
        assert_eq!(parse_panic_ts("ts_unix=abc rest"), None);
    }
}
