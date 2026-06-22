//! JV-SELF-02 — AMEM4Rec consolidation-sweep cron (async wrapper).
//!
//! Wraps [`crate::memory::consolidation_sweep::run_sweep`] — the pure, sync
//! sweep logic — in the standard `run_X_tick` + `spawn_X_cron_loop` async
//! pattern used by [`super::contradiction_resolve_cron`] and
//! [`super::token_anomaly_cron`].
//!
//! ## WAL frames
//!
//! - `0x9D CONSOLIDATION_SWEEP_STARTED` — emitted BEFORE `spawn_blocking`.
//! - `0x9E CONSOLIDATION_SWEEP_DONE` — emitted AFTER `spawn_blocking` returns.
//!
//! Both are written in async context, NOT inside `spawn_blocking`, because
//! [`crate::wal::writer::WalWriterHandle::append`] is async and tokio channel
//! sends require an async executor — calling from inside `spawn_blocking` would
//! trigger a "no current runtime" panic on some builds.
//!
//! ## Opt-in
//!
//! Disabled by default (`freedom.yaml::consolidation_sweep.enabled: false`).
//! The cron loop never spawns when disabled → `None` is returned.

use std::path::{Path, PathBuf};

use crate::config::automation::ConsolidationSweepConfig;
use crate::memory::{consolidation_sweep::run_sweep, store};
use crate::wal::{
    EventFlags, HeaderBuilder,
    events::{EVENT_TYPE_CONSOLIDATION_SWEEP_DONE, EVENT_TYPE_CONSOLIDATION_SWEEP_STARTED},
    writer::WalWriterHandle,
};

/// Emit one WAL frame (best-effort — a write failure is logged at error level
/// but never propagates: audit loss is visible via `neoth monitor`, and the
/// sweep result has already been computed; failing loud here would only abort
/// a completed pass).
async fn emit(
    writer: &WalWriterHandle,
    event_type: u8,
    payload: serde_json::Value,
    label: &'static str,
) {
    let bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "consolidation_sweep_cron: serialize WAL payload failed");
            return;
        }
    };
    let header = HeaderBuilder::new(event_type, &bytes)
        .flags(EventFlags::SYNTHETIC)
        .build();
    if let Err(e) = writer.append(header, bytes).await {
        tracing::error!(
            audit_loss = true,
            event = label,
            error = %e,
            "consolidation_sweep_cron: WAL frame lost"
        );
    }
}

/// One consolidation-sweep tick:
/// 1. Emits `0x9D CONSOLIDATION_SWEEP_STARTED`.
/// 2. Runs [`run_sweep`] inside `spawn_blocking` (rusqlite `Connection` is `!Send`).
/// 3. Emits `0x9E CONSOLIDATION_SWEEP_DONE` with the counts.
///
/// Returns the [`SweepReport`] for logging; always succeeds (errors are
/// logged and reflected as a zero-count report to the cron loop).
pub async fn run_consolidation_sweep_tick(
    db_path: &Path,
    cfg: ConsolidationSweepConfig,
    writer: &WalWriterHandle,
) -> crate::memory::consolidation_sweep::SweepReport {
    let ts_unix = crate::time::now_unix_i64();

    // Emit STARTED before blocking.
    emit(
        writer,
        EVENT_TYPE_CONSOLIDATION_SWEEP_STARTED,
        serde_json::json!({
            "cosine_threshold": cfg.cosine_threshold,
            "min_cluster_size": cfg.min_cluster_size,
            "importance_boost_cap": cfg.importance_boost_cap,
            "ts_unix": ts_unix,
        }),
        "CONSOLIDATION_SWEEP_STARTED",
    )
    .await;

    let path = db_path.to_path_buf();
    let now_ns = crate::time::now_unix_ns_i64();

    let report = tokio::task::spawn_blocking(move || -> crate::memory::consolidation_sweep::SweepReport {
        match store::open(&path) {
            Err(e) => {
                tracing::error!(error = %e, "consolidation_sweep_cron: open db failed");
                crate::memory::consolidation_sweep::SweepReport::default()
            }
            Ok(conn) => {
                match run_sweep(&conn, now_ns, &cfg) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, "consolidation_sweep_cron: sweep failed");
                        crate::memory::consolidation_sweep::SweepReport::default()
                    }
                }
            }
        }
    })
    .await
    .unwrap_or_else(|e| {
        tracing::error!(error = %e, "consolidation_sweep_cron: spawn_blocking panicked");
        crate::memory::consolidation_sweep::SweepReport::default()
    });

    // Emit DONE after blocking returns.
    let ts_unix_done = crate::time::now_unix_i64();
    emit(
        writer,
        EVENT_TYPE_CONSOLIDATION_SWEEP_DONE,
        serde_json::json!({
            "clusters_found": report.clusters_found,
            "members_boosted": report.members_boosted,
            "merged_to_groundtruth": report.merged_to_groundtruth,
            "ts_unix": ts_unix_done,
        }),
        "CONSOLIDATION_SWEEP_DONE",
    )
    .await;

    report
}

/// Spawn the consolidation-sweep cron loop as a background tokio task.
/// Returns `None` when `config.enabled == false` — opt-out operators carry
/// no idle task.
pub fn spawn_consolidation_sweep_cron_loop(
    config: ConsolidationSweepConfig,
    db_path: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!(
            "consolidation-sweep cron disabled \
             (consolidation_sweep.enabled = false)"
        );
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            cosine_threshold = config.cosine_threshold,
            min_cluster_size = config.min_cluster_size,
            "consolidation-sweep cron loop online (JV-SELF-02)",
        );
        loop {
            ticker.tick().await;
            let report = run_consolidation_sweep_tick(
                &db_path,
                config,
                &writer,
            )
            .await;
            tracing::info!(
                clusters_found = report.clusters_found,
                members_boosted = report.members_boosted,
                merged_to_groundtruth = report.merged_to_groundtruth,
                "consolidation-sweep cron tick complete",
            );
        }
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;

    #[test]
    fn config_defaults() {
        let cfg = ConsolidationSweepConfig::default();
        assert!(!cfg.enabled, "disabled by default");
        assert_eq!(
            cfg.interval_secs,
            crate::config::automation::DEFAULT_CONSOLIDATION_SWEEP_INTERVAL_SECS
        );
        assert_eq!(
            cfg.interval_duration(),
            std::time::Duration::from_secs(
                crate::config::automation::DEFAULT_CONSOLIDATION_SWEEP_INTERVAL_SECS
            )
        );
    }

    #[test]
    fn interval_floor_clamps_zero() {
        let cfg = ConsolidationSweepConfig {
            interval_secs: 0,
            ..Default::default()
        };
        assert_eq!(cfg.interval_duration(), std::time::Duration::from_secs(60));
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let cfg = ConsolidationSweepConfig { enabled: false, ..Default::default() };
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        let handle = spawn_consolidation_sweep_cron_loop(cfg, "/nonexistent".into(), writer.clone());
        assert!(handle.is_none(), "disabled config must return None");
        drop(writer);
        join.await.ok();
    }

    #[tokio::test]
    async fn spawn_returns_some_when_enabled() {
        let cfg = ConsolidationSweepConfig {
            enabled: true,
            interval_secs: 999_999, // long — won't fire in test
            ..Default::default()
        };
        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        let handle =
            spawn_consolidation_sweep_cron_loop(cfg, "/nonexistent".into(), writer.clone());
        assert!(handle.is_some(), "enabled=true must return a JoinHandle");
        handle.unwrap().abort();
        drop(writer);
        join.await.ok();
    }

    #[tokio::test]
    async fn tick_on_empty_db_emits_no_panic_and_zero_report() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        // Create schema.
        drop(store::open(&db_path).unwrap());

        let seg_dir = tempfile::tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();

        let report = run_consolidation_sweep_tick(
            &db_path,
            ConsolidationSweepConfig::default(),
            &writer,
        )
        .await;

        assert_eq!(report.clusters_found, 0);
        assert_eq!(report.members_boosted, 0);
        assert_eq!(report.merged_to_groundtruth, 0);

        drop(writer);
        join.await.ok();
    }

}
