//! MONITOR-03 / RECALL-METER-01 — recall-p95 latency alert daemon cron.
//!
//! Each one-shot `neoth recall` records its query latency into the
//! `idx_recall_latency` table (RECALL-METER-01, see `memory::store`). This cron
//! — when `freedom.yaml::recall_latency.enabled` — reads the recent window,
//! computes the p95, and emits a `0x4B RECALL_LATENCY_ALERT` WAL frame when p95
//! exceeds `p95_threshold_ms` (and at least `min_samples` samples exist). It is
//! the cross-process bridge the runbook's "recall p95" trigger rule needs:
//! recall runs in a separate process from the daemon, so the durable table — not
//! an in-memory meter — is the only thing both sides can see.
//!
//! ## Design (grooved cron recipe — mirrors [`super::drift_alert_cron`] /
//! [`super::regression_cron`])
//! Pure [`evaluate_recall_p95`] (unit-testable) + [`run_recall_latency_tick`]
//! (reads views.db, emits) + [`spawn_recall_latency_cron_loop`] (None when
//! disabled). A frame is emitted ONLY when p95 is over threshold, so
//! `neoth wal show --type recall_latency_alert` stays actionable.

use std::path::{Path, PathBuf};

use crate::config::RecallLatencyConfig;
use crate::wal::writer::WalWriterHandle;

/// Nearest-rank p95 over the samples. Empty → 0.0. Pure + allocation-light
/// (sorts a copy). Returned in the same unit as the input (ms).
fn p95(latencies: &[f64]) -> f64 {
    if latencies.is_empty() {
        return 0.0;
    }
    let mut sorted = latencies.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (((sorted.len() - 1) as f64) * 0.95).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// PURE core: compute p95 over `latencies` and return `Some((p95_ms, count))`
/// when it STRICTLY exceeds `threshold_ms` AND there are at least `min_samples`
/// samples. `None` when under threshold or too few samples (a handful of
/// queries doesn't make a trustworthy p95 — never cry wolf on cold start).
pub fn evaluate_recall_p95(
    latencies: &[f64],
    threshold_ms: f64,
    min_samples: usize,
) -> Option<(f64, usize)> {
    if latencies.len() < min_samples {
        return None;
    }
    let p = p95(latencies);
    (p > threshold_ms).then_some((p, latencies.len()))
}

/// One recall-latency cron pass. Reads the recent `idx_recall_latency` window
/// from `home/views.db`, evaluates p95, and on a breach emits a `0x4B
/// RECALL_LATENCY_ALERT` frame. Returns `Some(p95_ms)` when it alerted.
pub async fn run_recall_latency_tick(
    home: &Path,
    config: &RecallLatencyConfig,
    writer: &WalWriterHandle,
) -> Result<Option<f64>, String> {
    let db_path = home.join("views.db");
    // Read + DROP the (!Send) sqlite Connection in a tight scope BEFORE any
    // await, so this tick's future stays Send for `tokio::spawn`.
    let latencies = {
        let conn =
            crate::memory::store::open(&db_path).map_err(|e| format!("open views.db: {e}"))?;
        crate::memory::store::recent_recall_latencies_ms(&conn, config.window)
            .map_err(|e| format!("read recall latencies: {e}"))?
    };

    let Some((p95_ms, sample_count)) =
        evaluate_recall_p95(&latencies, config.p95_threshold_ms, config.min_samples)
    else {
        tracing::debug!(
            samples = latencies.len(),
            "recall-latency cron: under threshold or too few samples, no alert"
        );
        return Ok(None);
    };

    let ts_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let payload = serde_json::to_vec(&serde_json::json!({
        "p95_ms": p95_ms,
        "threshold_ms": config.p95_threshold_ms,
        "sample_count": sample_count,
        "ts_unix": ts_unix,
    }))
    .map_err(|e| format!("serialize recall-latency payload: {e}"))?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_RECALL_LATENCY_ALERT,
        &payload,
    )
    .flags(crate::wal::EventFlags::SYNTHETIC)
    .build();
    writer
        .append(header, payload)
        .await
        .map_err(|e| format!("wal append: {e}"))?;
    tracing::warn!(
        p95_ms,
        threshold_ms = config.p95_threshold_ms,
        sample_count,
        "recall latency alert: p95 over threshold — recall is degrading (cold cache / disk / index)",
    );
    Ok(Some(p95_ms))
}

/// Spawn the recall-latency cron loop. `None` when disabled (default) so opt-out
/// operators carry no idle task. 6h by default; interval clamped to a 60s floor.
pub fn spawn_recall_latency_cron_loop(
    config: RecallLatencyConfig,
    home: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("recall-latency cron disabled in config (recall_latency.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            p95_threshold_ms = config.p95_threshold_ms,
            "recall-latency cron loop online (MONITOR-03)",
        );
        loop {
            ticker.tick().await;
            match run_recall_latency_tick(&home, &config, &writer).await {
                Ok(Some(p95_ms)) => {
                    tracing::warn!(p95_ms, "recall-latency cron: 0x4B emitted")
                }
                Ok(None) => tracing::debug!("recall-latency cron: no alert this tick"),
                Err(e) => tracing::error!(error = %e, "recall-latency tick failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::EVENT_TYPE_RECALL_LATENCY_ALERT;

    #[test]
    fn p95_picks_the_high_tail() {
        // 1..=100 ⇒ nearest-rank p95 at idx round(99*0.95)=94 ⇒ value 95.
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        assert_eq!(p95(&v), 95.0);
        assert_eq!(p95(&[]), 0.0);
        assert_eq!(p95(&[42.0]), 42.0);
    }

    #[test]
    fn evaluate_flags_only_over_threshold_with_enough_samples() {
        // Fast window with enough samples → no alert.
        let fast = vec![5.0; 50];
        assert!(evaluate_recall_p95(&fast, 750.0, 20).is_none());
        // Slow window with enough samples → alert with p95 + count.
        let slow = vec![900.0; 50];
        let hit = evaluate_recall_p95(&slow, 750.0, 20).expect("over threshold");
        assert_eq!(hit.0, 900.0);
        assert_eq!(hit.1, 50);
    }

    #[test]
    fn evaluate_returns_none_when_too_few_samples() {
        // Even a clearly-slow window doesn't alert below min_samples.
        let slow = vec![5000.0; 5];
        assert!(evaluate_recall_p95(&slow, 750.0, 20).is_none());
    }

    fn count_alert_frames(seg: &std::path::Path) -> usize {
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
            if dec.header.event_type == EVENT_TYPE_RECALL_LATENCY_ALERT {
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

    fn enabled_cfg(threshold: f64, min_samples: usize) -> RecallLatencyConfig {
        RecallLatencyConfig {
            enabled: true,
            p95_threshold_ms: threshold,
            min_samples,
            window: 200,
            interval_secs: crate::config::DEFAULT_RECALL_LATENCY_INTERVAL_SECS,
        }
    }

    #[tokio::test]
    async fn tick_emits_when_recorded_latencies_are_slow() {
        let home = tempfile::tempdir().unwrap();
        // Seed slow samples through the real store recorder (also exercises the
        // schema + INSERT path).
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        for _ in 0..30 {
            crate::memory::store::record_recall_latency(&conn, 100, 1200.0).unwrap();
        }
        drop(conn);

        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let out = run_recall_latency_tick(home.path(), &enabled_cfg(750.0, 20), &writer)
            .await
            .unwrap();
        assert_eq!(out, Some(1200.0), "p95 of all-1200ms is 1200 > 750");
        drop(writer);
        join.await.ok();
        assert_eq!(count_alert_frames(&seg), 1, "exactly one 0x4B frame");
    }

    #[tokio::test]
    async fn tick_no_alert_when_fast() {
        let home = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&home.path().join("views.db")).unwrap();
        for _ in 0..30 {
            crate::memory::store::record_recall_latency(&conn, 100, 4.0).unwrap();
        }
        drop(conn);
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let out = run_recall_latency_tick(home.path(), &enabled_cfg(750.0, 20), &writer)
            .await
            .unwrap();
        assert!(out.is_none(), "fast recall ⇒ no alert");
        drop(writer);
        join.await.ok();
        assert_eq!(count_alert_frames(&seg), 0);
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let home = tempfile::tempdir().unwrap();
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = RecallLatencyConfig {
            enabled: false,
            ..Default::default()
        };
        let handle =
            spawn_recall_latency_cron_loop(cfg, home.path().to_path_buf(), writer);
        assert!(handle.is_none());
    }

    #[test]
    fn default_interval_is_six_hours() {
        assert_eq!(RecallLatencyConfig::default().interval_secs, 6 * 3600);
    }
}
