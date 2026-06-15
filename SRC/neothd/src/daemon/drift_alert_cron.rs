//! HO-09b — profile drift-alert daemon cron.
//!
//! HO-09 shipped the pure-fn drift primitives (`profile::baseline_diff`),
//! the `freedom.yaml::drift_alert` config, and the `neoth profile drift
//! {report,baseline,reset}` CLI. This module is the 4th deliverable: the
//! daemon cron that runs the same drift evaluation on a schedule and
//! emits a `0xBA PROFILE_DRIFT_ALERT` WAL frame when the operator's
//! profile has drifted past `drift_alert.threshold`.
//!
//! ## Design
//!
//! Mirrors [`super::doctor_cron`]: a pure-fn [`run_drift_alert_tick`]
//! (unit-testable against a tempdir) + a [`spawn_drift_alert_cron_loop`]
//! that returns `None` when `drift_alert.enabled == false` (no idle tokio
//! task for opt-out operators — and the master switch defaults OFF).
//!
//! The baseline resolution is shared with the CLI report path via
//! `crate::cli::profile::compute_drift_against_baseline` (operator working
//! baseline first, else the immutable `0xB3` migration anchor), so the
//! cron and `neoth profile drift report` can never disagree on what the
//! baseline is.
//!
//! Unlike `neoth profile drift report` (which fires every tick clean or
//! not), this cron emits a WAL frame ONLY when the drift ratio strictly
//! exceeds the threshold — every `0xBA` frame is operator-actionable, so
//! `neoth wal show --type profile_drift_alert` is a clean signal, not
//! hourly "still fine" noise.

use std::path::PathBuf;

use crate::config::DriftAlertConfig;
use crate::profile::baseline_diff::DriftReport;
use crate::wal::writer::WalWriterHandle;

/// One drift-alert cron pass. Resolves the baseline + current claim set
/// (shared seam with the CLI report path), and — when the drift ratio
/// strictly exceeds `config.threshold` — emits a `0xBA
/// PROFILE_DRIFT_ALERT` WAL frame and returns `Ok(Some(report))`.
///
/// Returns `Ok(None)` (no frame) when:
///   - no baseline exists yet (fresh install — operator hasn't captured a
///     working baseline and there's no `0xB3` migration anchor), or
///   - the drift is at-or-below the threshold (informational, not
///     actionable).
///
/// `home` locates `views.db` (`home/views.db`) + the working baseline
/// file + the WAL dir (`home/wal`) for the anchor scan — matching the
/// daemon's real layout (`FreedomConfig::default_wal_dir() == home/wal`).
pub async fn run_drift_alert_tick(
    home: &std::path::Path,
    config: &DriftAlertConfig,
    writer: &WalWriterHandle,
) -> Result<Option<DriftReport>, String> {
    let db_path = home.join("views.db");
    let wal_dir = home.join("wal");

    let (report, source) =
        match crate::cli::profile::compute_drift_against_baseline(home, &db_path, &wal_dir) {
            Ok(Some(x)) => x,
            Ok(None) => {
                tracing::debug!("drift-alert cron: no baseline yet, skipping tick");
                return Ok(None);
            }
            Err(e) => return Err(format!("drift evaluation: {e}")),
        };

    if !report.is_over(config.threshold) {
        tracing::debug!(
            drift_ratio = report.drift_ratio(),
            threshold = config.threshold,
            "drift-alert cron: under threshold, no alert",
        );
        return Ok(None);
    }

    let ts_unix = crate::time::now_unix_i64();
    let payload = serde_json::to_vec(&serde_json::json!({
        "drift_ratio": report.drift_ratio(),
        "threshold": config.threshold,
        "added_count": report.added.len(),
        "removed_count": report.removed.len(),
        "baseline_source": source,
        "ts_unix": ts_unix,
    }))
    .map_err(|e| format!("serialize drift payload: {e}"))?;

    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_PROFILE_DRIFT_ALERT,
        &payload,
    )
    .flags(crate::wal::EventFlags::SYNTHETIC)
    .build();
    writer
        .append(header, payload)
        .await
        .map_err(|e| format!("wal append: {e}"))?;

    tracing::warn!(
        drift_ratio = report.drift_ratio(),
        threshold = config.threshold,
        baseline_source = %source,
        added = report.added.len(),
        removed = report.removed.len(),
        "profile drift alert: profile drifted past threshold — review `neoth profile show`, \
         then re-anchor via `neoth profile drift baseline`",
    );
    Ok(Some(report))
}

/// Spawn the drift-alert cron loop. Returns the `JoinHandle` so the daemon
/// tracks it alongside the other background tasks; `None` when
/// `config.enabled == false` so opt-out operators (the default) carry no
/// idle tokio task. The interval comes from `config.interval_secs`, clamped
/// to a 60s floor by `DriftAlertConfig::interval_duration` so an
/// operator-supplied `interval_secs: 0` can't tight-loop.
pub fn spawn_drift_alert_cron_loop(
    config: DriftAlertConfig,
    home: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("drift-alert cron disabled in config (drift_alert.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            threshold = config.threshold,
            "drift-alert cron loop online (HO-09b)",
        );
        loop {
            ticker.tick().await;
            match run_drift_alert_tick(&home, &config, &writer).await {
                Ok(Some(report)) => tracing::info!(
                    drift_ratio = report.drift_ratio(),
                    "drift-alert cron: 0xBA emitted",
                ),
                Ok(None) => tracing::debug!("drift-alert cron: no alert this tick"),
                Err(e) => tracing::error!(error = %e, "drift-alert tick failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use crate::profile::baseline_diff::{DriftBaseline, save_drift_baseline};
    use crate::wal::events::EVENT_TYPE_PROFILE_DRIFT_ALERT;

    /// Seed one active idx_profile claim into a fresh views.db under `home`.
    fn seed_claim(home: &std::path::Path, field: &str, value_json: &str) {
        let conn = store::open(&home.join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_profile (extraction_id, event_id, field, value_json, confidence, \
             evidence_event_ids, guard_version, applied_at, superseded_at) \
             VALUES (?1, 0, ?2, ?3, 0.9, '[]', '0.1.0', 100, NULL)",
            rusqlite::params![format!("ext-{field}"), field, value_json],
        )
        .unwrap();
    }

    /// Count `0xBA PROFILE_DRIFT_ALERT` frames in an uncompressed WAL
    /// segment (test writer uses the plain `spawn`).
    fn count_drift_frames(seg: &std::path::Path) -> usize {
        // The writer creates the segment file lazily on first append, so a
        // tick that emits NO alert leaves no file at all — that trivially
        // has zero drift frames.
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
            if dec.header.event_type == EVENT_TYPE_PROFILE_DRIFT_ALERT {
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

    /// Return the first `0xBA` frame's JSON payload from an uncompressed
    /// WAL segment, so a test can assert the on-disk payload contract (the
    /// operator-facing `neoth wal show --type profile_drift_alert` output)
    /// — not just that a frame exists.
    fn first_drift_payload(seg: &std::path::Path) -> Option<serde_json::Value> {
        let bytes = std::fs::read(seg).ok()?;
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).ok()?;
        let mut cursor = hdr.header_len();
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => return None,
            };
            if dec.header.event_type == EVENT_TYPE_PROFILE_DRIFT_ALERT {
                return serde_json::from_slice(dec.payload).ok();
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        None
    }

    fn enabled_config(threshold: f64) -> DriftAlertConfig {
        DriftAlertConfig {
            enabled: true,
            threshold,
            interval_secs: crate::config::DEFAULT_DRIFT_ALERT_INTERVAL_SECS,
        }
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("drift.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = DriftAlertConfig {
            enabled: false,
            threshold: 0.25,
            interval_secs: crate::config::DEFAULT_DRIFT_ALERT_INTERVAL_SECS,
        };
        let handle = spawn_drift_alert_cron_loop(cfg, home.path().to_path_buf(), writer);
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn spawn_returns_some_when_enabled() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("drift.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let handle =
            spawn_drift_alert_cron_loop(enabled_config(0.25), home.path().to_path_buf(), writer);
        let handle = handle.expect("expected join handle when enabled");
        handle.abort(); // immediate cancel; ticker has not fired
    }

    #[tokio::test]
    async fn tick_skips_when_no_baseline_exists() {
        // views.db with a claim but NO working baseline + empty wal dir
        // (no 0xB3 anchor) → compute returns None → tick Ok(None), no frame.
        let home = tempfile::tempdir().unwrap();
        seed_claim(home.path(), "identity.location", "\"berlin\"");
        std::fs::create_dir_all(home.path().join("wal")).unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("drift.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let out = run_drift_alert_tick(home.path(), &enabled_config(0.25), &writer)
            .await
            .unwrap();
        assert!(out.is_none(), "no baseline → no alert");
        assert_eq!(
            count_drift_frames(&seg),
            0,
            "no 0xBA frame without baseline"
        );
    }

    #[tokio::test]
    async fn tick_emits_alert_when_drift_over_threshold() {
        // ASYMMETRIC setup so added_count != removed_count are individually
        // meaningful (a 1↔1 setup makes a count-swap invisible): TWO current
        // claims vs a ONE-hash working baseline → added=2 (both current
        // hashes absent from baseline), removed=1 (the zeros hash absent
        // from current), drift_ratio = (2+1)/max(1,2) = 1.5 > 0.25.
        let home = tempfile::tempdir().unwrap();
        seed_claim(home.path(), "identity.location", "\"berlin\"");
        seed_claim(home.path(), "identity.role", "\"operator\"");
        save_drift_baseline(
            home.path(),
            &DriftBaseline::new(
                "manual",
                vec!["0000000000000000000000000000000000000000000000000000000000000000".into()],
                "0.2.1",
                100,
            ),
        )
        .unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("drift.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let report = run_drift_alert_tick(home.path(), &enabled_config(0.25), &writer)
            .await
            .unwrap()
            .expect("drift over threshold must alert");
        assert!(report.is_over(0.25));
        assert_eq!(report.added.len(), 2);
        assert_eq!(report.removed.len(), 1);
        assert_eq!(
            count_drift_frames(&seg),
            1,
            "exactly one 0xBA frame emitted"
        );
        // Pin the on-disk payload contract (the operator-facing WAL signal),
        // not just frame presence — guards against a silent serialization
        // regression in baseline_source / counts / ratio.
        let payload = first_drift_payload(&seg).expect("0xBA payload must decode");
        assert_eq!(payload["baseline_source"], "working/manual");
        assert_eq!(payload["added_count"], 2);
        assert_eq!(payload["removed_count"], 1);
        assert_eq!(payload["threshold"], 0.25);
        let ratio = payload["drift_ratio"].as_f64().expect("drift_ratio is f64");
        assert!((ratio - report.drift_ratio()).abs() < 1e-9);
        assert!(ratio > 0.25);
    }

    #[tokio::test]
    async fn tick_no_alert_when_drift_under_threshold() {
        // Working baseline == current claim hashes → drift ratio 0.0 →
        // Ok(None), no frame even though a baseline exists.
        let home = tempfile::tempdir().unwrap();
        seed_claim(home.path(), "identity.location", "\"berlin\"");
        let current =
            crate::cli::profile::current_active_claim_hashes(&home.path().join("views.db"))
                .unwrap();
        save_drift_baseline(
            home.path(),
            &DriftBaseline::new("manual", current, "0.2.1", 100),
        )
        .unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("drift.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let out = run_drift_alert_tick(home.path(), &enabled_config(0.25), &writer)
            .await
            .unwrap();
        assert!(out.is_none(), "identical baseline → no drift → no alert");
        assert_eq!(count_drift_frames(&seg), 0);
    }

    #[test]
    fn default_interval_is_six_hours() {
        assert_eq!(
            crate::config::DriftAlertConfig::default().interval_secs,
            6 * 3600
        );
        assert_eq!(crate::config::DEFAULT_DRIFT_ALERT_INTERVAL_SECS, 6 * 3600);
    }

    #[test]
    fn interval_duration_clamps_zero_to_sixty_seconds() {
        // The HO-09b review (MEDIUM) flagged that the old `.max(60)` on
        // the compile-time constant was vacuous. The clamp now applies to
        // the operator-supplied config value — pin that contract.
        let cfg = DriftAlertConfig {
            enabled: true,
            threshold: 0.25,
            interval_secs: 0,
        };
        assert_eq!(cfg.interval_duration(), std::time::Duration::from_secs(60));
        let cfg2 = DriftAlertConfig {
            enabled: true,
            threshold: 0.25,
            interval_secs: 7200,
        };
        assert_eq!(
            cfg2.interval_duration(),
            std::time::Duration::from_secs(7200)
        );
    }
}
