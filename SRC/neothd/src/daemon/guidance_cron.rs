//! GOLD-ADAPT-JV-MEM-16 — Guidance-block snapshot refresh cron.
//!
//! Periodically writes `~/.neoth/guidance_snapshot.json` from the WAL +
//! scorecard so the synchronous `maybe_guidance_block_at` (which runs inside
//! `spawn_blocking` on every chat turn) can read richer context without
//! repeating expensive WAL scans per turn.
//!
//! ## Design
//!
//! - **WAL-free**: the cron only reads WAL segments; it writes a single JSON
//!   snapshot file via atomic tmp-rename. No WAL events emitted → shutdown
//!   order is irrelevant (can abort adjacent to other WAL-free tasks like
//!   `snapshot_refresh_handle`).
//! - **Best-effort**: a missing store / absent WAL dir / absent snapshot →
//!   graceful degradation. The guidance block still renders cards + pending
//!   from the existing MEM-12 lanes.
//! - **Independent**: runs its own rusqlite read-only connection, separate
//!   from the monitor-cron loop, to avoid shared-state coupling.
//!
//! ## Snapshot staleness
//!
//! With the default 3h interval the snapshot may be up to 3h old. That is
//! acceptable for advisory context. The `ts_unix` field lets a future version
//! reject a snapshot older than e.g. 12h; not done now (YAGNI, feature is
//! opt-in).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public types

/// Cross-process snapshot cached to disk for `maybe_guidance_block_at` reads.
///
/// Serialised to `~/.neoth/guidance_snapshot.json` by the daemon cron;
/// deserialised by the CLI chat path on every `build_prompt_bundle` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidanceSnapshot {
    /// Unix timestamp when this snapshot was written.
    pub ts_unix: i64,
    /// Memory freshness score from the scorecard (0.0–1.0).
    pub scorecard_freshness: f64,
    /// Letter grade ("A"–"F").
    pub scorecard_grade: String,
    /// True when composite ≥ HEALTHY_THRESHOLD.
    pub scorecard_healthy: bool,
    /// 0x49 CRASH_LOG_ALERT frames in the last `signal_window_secs`.
    pub crash_alerts_24h: u32,
    /// 0x4A CHANNEL_SILENCE_ALERT frames in the last `signal_window_secs`.
    pub silence_alerts_24h: u32,
    /// 0x6E TOKEN_ANOMALY_DETECTED frames in the last `signal_window_secs`.
    pub token_anomaly_24h: u32,
    /// 0x6F SESSION_HEALTH_DEGRADED frames in the last `signal_window_secs`.
    pub session_degraded_24h: u32,
    /// 0x42 JOB_FAILED frames in the last `signal_window_secs`.
    pub cron_errors_24h: u32,
}

// ---------------------------------------------------------------------------
// Path helpers

/// Canonical path for the guidance snapshot file.
///
/// `neoth_home` is `~/.neoth/` (the value returned by
/// [`crate::config::FreedomConfig::default_neoth_home`]).
pub fn guidance_snapshot_path(neoth_home: &Path) -> PathBuf {
    neoth_home.join("guidance_snapshot.json")
}

/// Best-effort load of the guidance snapshot. Returns `None` when the file
/// is absent, unreadable, or contains invalid JSON — callers degrade
/// gracefully to the existing MEM-12 lanes.
pub fn load_guidance_snapshot(neoth_home: &Path) -> Option<GuidanceSnapshot> {
    let path = guidance_snapshot_path(neoth_home);
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

// ---------------------------------------------------------------------------
// WAL signal scanner

/// Scan every `*.wal` file in `wal_dir` and count notable event types fired
/// within the last `window_secs` seconds ending at `now_unix`.
///
/// Returns `(crash_alerts, silence_alerts, token_anomaly, session_degraded,
/// cron_errors)`.
///
/// Uses `crate::wal::scan::for_each_frame` so v2/zstd-compressed segments
/// are handled transparently (GOLD-ARCH-03 pattern).
///
/// Best-effort: an unreadable segment or corrupt frame stops the scan for
/// that segment only; the function never propagates errors.
pub fn scan_signals_24h(
    wal_dir: &Path,
    now_unix: i64,
    window_secs: u64,
) -> (u32, u32, u32, u32, u32) {
    use crate::wal::events::{
        EVENT_TYPE_CHANNEL_SILENCE_ALERT, EVENT_TYPE_CRASH_LOG_ALERT, EVENT_TYPE_JOB_FAILED,
        EVENT_TYPE_SESSION_HEALTH_DEGRADED, EVENT_TYPE_TOKEN_ANOMALY_DETECTED,
    };

    let cutoff = now_unix.saturating_sub(window_secs as i64);
    let (mut crash, mut silence, mut anomaly, mut degraded, mut cron_err) =
        (0u32, 0u32, 0u32, 0u32, 0u32);

    let Ok(rd) = std::fs::read_dir(wal_dir) else {
        return (0, 0, 0, 0, 0);
    };

    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        let _ = crate::wal::scan::for_each_frame(&bytes, |_, dec| {
            let et = dec.header.event_type;
            if et == EVENT_TYPE_CRASH_LOG_ALERT
                || et == EVENT_TYPE_CHANNEL_SILENCE_ALERT
                || et == EVENT_TYPE_TOKEN_ANOMALY_DETECTED
                || et == EVENT_TYPE_SESSION_HEALTH_DEGRADED
                || et == EVENT_TYPE_JOB_FAILED
            {
                // Extract ts_unix from JSON payload for window filtering.
                // Conservative fallback: include when unparseable (same
                // pattern as monitor_cron::count_crc_frames_in_segment).
                let ts = serde_json::from_slice::<serde_json::Value>(dec.payload)
                    .ok()
                    .and_then(|v| v.get("ts_unix")?.as_i64())
                    .unwrap_or(now_unix);
                if ts >= cutoff {
                    if et == EVENT_TYPE_CRASH_LOG_ALERT {
                        crash += 1;
                    } else if et == EVENT_TYPE_CHANNEL_SILENCE_ALERT {
                        silence += 1;
                    } else if et == EVENT_TYPE_TOKEN_ANOMALY_DETECTED {
                        anomaly += 1;
                    } else if et == EVENT_TYPE_SESSION_HEALTH_DEGRADED {
                        degraded += 1;
                    } else {
                        // EVENT_TYPE_JOB_FAILED
                        cron_err += 1;
                    }
                }
            }
            Ok(())
        });
    }
    (crash, silence, anomaly, degraded, cron_err)
}

// ---------------------------------------------------------------------------
// Tick function

/// One refresh tick: read the scorecard + scan WAL signals, then atomically
/// write the snapshot JSON.
///
/// `neoth_home` is `~/.neoth/` (the value from
/// [`crate::config::FreedomConfig::default_neoth_home`]).
/// `wal_dir` is typically `~/.neoth/wal/`.
///
/// Pure + synchronous — intended to be called inside `spawn_blocking`.
pub fn run_guidance_snapshot_tick(
    neoth_home: &Path,
    wal_dir: &Path,
    now_unix: i64,
    signal_window_secs: u64,
) {
    // ── Scorecard ────────────────────────────────────────────────────────────
    let store_path = neoth_home.join("views.db");
    let (freshness, grade, healthy) = if store_path.exists() {
        match crate::memory::store::open(&store_path).and_then(|c| {
            crate::memory::scorecard::compute_quality_scorecard(&c, now_unix, 200)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }) {
            Ok(sc) => (sc.freshness, sc.grade.as_str().to_string(), sc.is_healthy),
            Err(e) => {
                tracing::warn!(error = %e, "guidance cron: scorecard query failed");
                (0.5, "?".to_string(), true)
            }
        }
    } else {
        // No store yet (fresh install) — treat as fully healthy.
        (1.0, "?".to_string(), true)
    };

    // ── WAL signal scan ──────────────────────────────────────────────────────
    let (crash, silence, anomaly, degraded, cron_err) =
        scan_signals_24h(wal_dir, now_unix, signal_window_secs);

    // ── Serialise + atomic write ─────────────────────────────────────────────
    let snap = GuidanceSnapshot {
        ts_unix: now_unix,
        scorecard_freshness: freshness,
        scorecard_grade: grade,
        scorecard_healthy: healthy,
        crash_alerts_24h: crash,
        silence_alerts_24h: silence,
        token_anomaly_24h: anomaly,
        session_degraded_24h: degraded,
        cron_errors_24h: cron_err,
    };

    let path = guidance_snapshot_path(neoth_home);
    let tmp = path.with_extension("json.tmp");
    match serde_json::to_vec(&snap) {
        Ok(bytes) => {
            // Ensure the parent exists (it always should, but be defensive).
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(&tmp, &bytes).is_ok() {
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    tracing::warn!(error = %e, "guidance cron: snapshot rename failed");
                }
            } else {
                tracing::warn!("guidance cron: snapshot write to tmp failed");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "guidance cron: snapshot serialisation failed");
        }
    }

    tracing::debug!(
        freshness,
        cron_errors = cron_err,
        crash_alerts = crash,
        "JV-MEM-16: guidance snapshot refreshed"
    );
}

// ---------------------------------------------------------------------------
// Spawn helper

/// Spawn the guidance-block snapshot refresh cron loop.
///
/// Returns `None` when `config.enabled == false` so opt-out operators carry
/// no idle tokio task. Mirrors [`super::monitor_cron::spawn_monitor_cron_loop`].
pub fn spawn_guidance_cron_loop(
    config: crate::config::automation::GuidanceCronConfig,
    neoth_home: PathBuf,
    wal_dir: PathBuf,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            signal_window_secs = config.signal_window_secs,
            "guidance-block snapshot cron online (JV-MEM-16)",
        );
        loop {
            ticker.tick().await;
            let home2 = neoth_home.clone();
            let wal2 = wal_dir.clone();
            let sw = config.signal_window_secs;
            let _ = tokio::task::spawn_blocking(move || {
                run_guidance_snapshot_tick(&home2, &wal2, crate::time::now_unix_i64(), sw)
            })
            .await;
        }
    }))
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unit: run_guidance_snapshot_tick writes a readable snapshot ───────────

    /// JV-MEM-16: verify that run_guidance_snapshot_tick writes a parseable
    /// guidance_snapshot.json under the given neoth_home.
    #[test]
    fn run_guidance_snapshot_tick_writes_readable_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_home = dir.path();
        let wal_dir = neoth_home.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        // No views.db → scorecard falls back to defaults.
        // No WAL → signals all 0.
        run_guidance_snapshot_tick(neoth_home, &wal_dir, 1_700_000_000, 86_400);
        let snap = load_guidance_snapshot(neoth_home)
            .expect("snapshot must be written even with empty neoth_home");
        assert_eq!(snap.ts_unix, 1_700_000_000);
        assert_eq!(snap.cron_errors_24h, 0, "empty WAL = 0 cron errors");
        // No views.db → healthy fallback
        assert!(snap.scorecard_healthy, "empty store defaults to healthy");
    }

    // ── Unit: scan_signals_24h returns zeros on empty dir ───────────────────

    #[test]
    fn scan_signals_24h_empty_dir_returns_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let (c, s, a, d, e) = scan_signals_24h(dir.path(), 1_700_000_000, 86_400);
        assert_eq!((c, s, a, d, e), (0, 0, 0, 0, 0));
    }

    // ── Unit: scan_signals_24h returns zeros on missing dir ─────────────────

    #[test]
    fn scan_signals_24h_missing_dir_returns_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent");
        let (c, s, a, d, e) = scan_signals_24h(&missing, 1_700_000_000, 86_400);
        assert_eq!((c, s, a, d, e), (0, 0, 0, 0, 0));
    }

    // ── Unit: load_guidance_snapshot returns None on missing file ────────────

    #[test]
    fn load_guidance_snapshot_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_guidance_snapshot(dir.path()).is_none());
    }

    // ── Unit: spawn_guidance_cron_loop returns None when disabled ────────────

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = crate::config::automation::GuidanceCronConfig {
            enabled: false,
            ..Default::default()
        };
        let handle =
            spawn_guidance_cron_loop(cfg, dir.path().to_path_buf(), dir.path().to_path_buf());
        assert!(handle.is_none());
    }
}
