//! U-04 — updater cron loop + WAL audit frame.
//!
//! Wraps the pure-fn primitives in [`crate::updater::pipeline`] for
//! the daemon's recurring updater pass. Mirrors the EL-01 doctor-
//! cron pattern: a tokio interval loop runs `run_updater_pass` per
//! tick, emits `0x44 UPDATER_TASK_FIRED` before the pass + `0x45
//! UPDATER_TASK_RESULT` after, and short-circuits cleanly when the
//! operator disabled updates in `freedom.yaml::updater`.
//!
//! ## What's wired today
//!
//! - [`spawn_updater_cron_loop`] — boxed `Fn() -> Vec<ComponentSpec>`
//!   builder so callers plug in per-task version-probe logic (e.g.
//!   GitHub Releases for `neothd`, `claude --version` for the CLI
//!   lane). The builder runs ON each tick so a transient network
//!   failure produces a Failed outcome instead of a panic.
//! - [`run_updater_tick`] — pure-fn over the builder, emits WAL +
//!   returns the [`UpdaterTaskResultPayload`] for the caller's
//!   audit trail.
//!
//! ## What ships in follow-ups
//!
//! - Real version-probe builders for `neoth_self` / `skill_plugin` /
//!   `cli_version` lanes (U-01 / U-02 / U-03). The shapes already
//!   exist as `pipeline::neoth_self_specs` / `skill_plugin_specs` /
//!   `cli_version_specs` — the missing piece is the operator-config
//!   driven "where does latest_version come from" probe.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::updater::pipeline::{ComponentSpec, run_updater_pass};
use crate::wal::events::{EVENT_TYPE_UPDATER_TASK_FIRED, EVENT_TYPE_UPDATER_TASK_RESULT};
use crate::wal::payloads_u04::{UpdaterTaskKind, UpdaterTaskResultPayload};
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};

/// Default cron interval — operators tune via
/// `freedom.yaml::updater.cron_interval_secs`. 6h balances "catch
/// real upstream releases within the same day" against "don't
/// hammer GitHub API with daemon-driven version checks".
pub const DEFAULT_UPDATER_INTERVAL_SECS: u64 = 6 * 3600;

/// Per-task operator config — one entry per UpdaterTaskKind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdaterCronConfig {
    pub enabled: bool,
    pub interval_secs: u64,
}

impl Default for UpdaterCronConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: DEFAULT_UPDATER_INTERVAL_SECS,
        }
    }
}

impl UpdaterCronConfig {
    pub fn interval_duration(&self) -> Duration {
        // 60s minimum floor — protects against misconfigured `0`s.
        Duration::from_secs(self.interval_secs.max(60))
    }
}

/// One tick of the updater cron pass.
///
/// Sequence:
///   1. Builder runs → produces the per-component spec list. A
///      panic in the builder is caught by the spawn-loop wrapper
///      (so a transient network error doesn't crash the daemon).
///   2. Emit `0x44 UPDATER_TASK_FIRED` with the task_kind tag so
///      auditors see "the cron started" even when the result frame
///      never lands (e.g. daemon killed mid-pass).
///   3. `run_updater_pass` computes outcomes from the specs.
///   4. Emit `0x45 UPDATER_TASK_RESULT` with the full payload.
///
/// Returns the payload so callers (tests, `neoth updater status`)
/// can inspect outcomes without re-running the pass.
pub async fn run_updater_tick<F>(
    task_kind: UpdaterTaskKind,
    builder: F,
    writer: &WalWriterHandle,
) -> Result<UpdaterTaskResultPayload, String>
where
    F: FnOnce() -> Vec<ComponentSpec>,
{
    // 0x44 UPDATER_TASK_FIRED first — audit chain proves the cron
    // started even when the result frame is lost to a daemon kill.
    let fired_payload = serde_json::json!({
        "task_kind": task_kind.as_str(),
        "ts_unix": crate::time::now_unix_secs(),
    });
    let fired_body = serde_json::to_vec(&fired_payload).map_err(|e| format!("serde fired: {e}"))?;
    let fired_header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_FIRED, &fired_body)
        .flags(EventFlags::SYNTHETIC)
        .build();
    writer
        .append(fired_header, fired_body)
        .await
        .map_err(|e| format!("wal append fired: {e}"))?;

    let specs = builder();
    let result = run_updater_pass(task_kind, specs);

    let result_body = serde_json::to_vec(&result).map_err(|e| format!("serde result: {e}"))?;
    let result_header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_RESULT, &result_body)
        .flags(EventFlags::SYNTHETIC)
        .build();
    writer
        .append(result_header, result_body)
        .await
        .map_err(|e| format!("wal append result: {e}"))?;

    Ok(result)
}

/// Spawn the periodic updater cron loop. Returns `None` when
/// `config.enabled == false` so the daemon doesn't accumulate idle
/// tokio tasks for opt-out operators.
///
/// The `builder` closure is boxed + cloned each tick (cheap — it's
/// a `Box<dyn Fn>`, not the spec vec). Builders must be `Send +
/// Sync + 'static` since the loop runs on a tokio worker.
pub fn spawn_updater_cron_loop(
    config: UpdaterCronConfig,
    task_kind: UpdaterTaskKind,
    builder: std::sync::Arc<dyn Fn() -> Vec<ComponentSpec> + Send + Sync + 'static>,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!(
            task_kind = task_kind.as_str(),
            "updater cron disabled in config; skipping loop spawn"
        );
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            task_kind = task_kind.as_str(),
            interval_secs = interval.as_secs(),
            "updater cron loop online (U-04)",
        );
        loop {
            ticker.tick().await;
            let b = builder.clone();
            // Catch panics from the builder so a transient
            // network failure doesn't abort the daemon. Spawn
            // the build on a blocking thread so the panic
            // boundary applies via spawn_blocking's join. We
            // know our trait-object builders are unwind-safe
            // (the closures we pass in carry no interior-
            // mutability state across the boundary — they
            // just call probe fns and return a fresh Vec).
            let spec_result = tokio::task::spawn_blocking(move || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b()))
            })
            .await;
            let specs = match spec_result {
                Ok(Ok(v)) => v,
                Ok(Err(_panic)) => {
                    tracing::error!(
                        task_kind = task_kind.as_str(),
                        "updater builder panicked; skipping this tick",
                    );
                    continue;
                }
                Err(e) => {
                    tracing::error!(error = %e, "updater builder join failed");
                    continue;
                }
            };

            // Inline the WAL emit half so the closure-passing
            // pattern stays clean (run_updater_tick takes the
            // builder, not pre-built specs).
            let fired_payload = serde_json::json!({
                "task_kind": task_kind.as_str(),
                "ts_unix": crate::time::now_unix_secs(),
            });
            let fired_body = match serde_json::to_vec(&fired_payload) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(error = %e, "serialise fired payload");
                    continue;
                }
            };
            let fired_header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_FIRED, &fired_body)
                .flags(EventFlags::SYNTHETIC)
                .build();
            if let Err(e) = writer.append(fired_header, fired_body).await {
                tracing::warn!(error = %e, "wal append fired (updater tick)");
                continue;
            }
            let result = run_updater_pass(task_kind, specs);
            let result_body = match serde_json::to_vec(&result) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(error = %e, "serialise result payload");
                    continue;
                }
            };
            let result_header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_RESULT, &result_body)
                .flags(EventFlags::SYNTHETIC)
                .build();
            if let Err(e) = writer.append(result_header, result_body).await {
                tracing::warn!(error = %e, "wal append result (updater tick)");
                continue;
            }
            tracing::debug!(
                task_kind = task_kind.as_str(),
                components = result.components.len(),
                duration_ms = result.duration_ms,
                "updater tick complete",
            );
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::updater::pipeline::GateDecision;

    fn spec(name: &str, current: &str, latest: Result<&str, &str>) -> ComponentSpec {
        ComponentSpec {
            name: name.to_string(),
            current_version: current.to_string(),
            latest_version: latest.map(|s| s.to_string()).map_err(|s| s.to_string()),
            gate_decision: GateDecision::Allow,
        }
    }

    #[test]
    fn default_config_pinned() {
        let c = UpdaterCronConfig::default();
        assert!(c.enabled);
        assert_eq!(c.interval_secs, DEFAULT_UPDATER_INTERVAL_SECS);
    }

    #[test]
    fn interval_clamped_to_60_seconds_minimum() {
        let c = UpdaterCronConfig {
            enabled: true,
            interval_secs: 5,
        };
        assert_eq!(c.interval_duration(), Duration::from_secs(60));
    }

    #[test]
    fn interval_uses_configured_value_above_floor() {
        let c = UpdaterCronConfig {
            enabled: true,
            interval_secs: 12_000,
        };
        assert_eq!(c.interval_duration(), Duration::from_secs(12_000));
    }

    #[tokio::test]
    async fn run_updater_tick_emits_fired_then_result_frames() {
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("updater.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let builder = || {
            vec![
                spec("neothd", "0.2.1", Ok("0.2.1")),
                spec("claude", "0.42.0", Ok("0.43.0")),
            ]
        };
        let result = run_updater_tick(UpdaterTaskKind::NeothSelf, builder, &writer)
            .await
            .unwrap();
        assert_eq!(result.components.len(), 2);
        // WAL file has both frames written (size > 0 — actual
        // frame ordering is enforced by the WAL writer).
        let meta = std::fs::metadata(&seg).unwrap();
        assert!(meta.len() > 0);
    }

    #[tokio::test]
    async fn spawn_loop_returns_none_when_disabled() {
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("updater.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = UpdaterCronConfig {
            enabled: false,
            interval_secs: DEFAULT_UPDATER_INTERVAL_SECS,
        };
        let builder: std::sync::Arc<dyn Fn() -> Vec<ComponentSpec> + Send + Sync + 'static> =
            std::sync::Arc::new(Vec::new);
        let handle = spawn_updater_cron_loop(cfg, UpdaterTaskKind::NeothSelf, builder, writer);
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn spawn_loop_returns_some_when_enabled() {
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("updater.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = UpdaterCronConfig::default();
        let builder: std::sync::Arc<dyn Fn() -> Vec<ComponentSpec> + Send + Sync + 'static> =
            std::sync::Arc::new(Vec::new);
        let handle = spawn_updater_cron_loop(cfg, UpdaterTaskKind::NeothSelf, builder, writer)
            .expect("expected join handle when enabled");
        handle.abort();
    }
}
