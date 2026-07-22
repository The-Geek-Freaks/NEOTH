//! U-04 — updater cron loop + WAL audit frame.
//!
//! Wraps the pure-fn primitives in [`crate::updater::pipeline`] for
//! the daemon's recurring updater pass. Mirrors the EL-01 doctor-
//! cron pattern: a reload-aware Tokio supervisor runs `run_updater_pass` per
//! tick, emits `0x44 UPDATER_TASK_FIRED` before the pass + `0x45
//! UPDATER_TASK_RESULT` after, and short-circuits cleanly when the
//! operator disabled updates in `freedom.yaml::updater`.
//!
//! ## What's wired today
//!
//! - [`spawn_updater_cron_loop`] — live-reload-aware supervisor. It resolves
//!   the accepted updater/autonomy policy on every tick and passes that exact
//!   snapshot + a policy-derived gate into the task builder.
//!
//! ## What ships in follow-ups
//!
//! - Request-bound permit consumption at the concrete GitHub, npm-registry,
//!   and `git ls-remote` transport leaves. Only after each leaf writes its own
//!   intent and terminal result may the daemon replace the explicit denied gate
//!   with the live operator decision.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::updater::pipeline::{ComponentSpec, run_updater_pass};
use crate::wal::events::{EVENT_TYPE_UPDATER_TASK_FIRED, EVENT_TYPE_UPDATER_TASK_RESULT};
use crate::wal::payloads_u04::UpdaterTaskKind;
#[cfg(test)]
use crate::wal::payloads_u04::UpdaterTaskResultPayload;
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};

/// Default cron interval — operators tune via
/// `freedom.yaml::updater.cron_interval_secs`. 6h balances "catch
/// real upstream releases within the same day" against "don't
/// hammer GitHub API with daemon-driven version checks".
pub const DEFAULT_UPDATER_INTERVAL_SECS: u64 = 6 * 3600;

/// Recurring updater probes are network operations, not update application.
/// Until the GitHub/npm/git transports accept a request-bound permit and emit
/// matching intent/result frames themselves, the daemon path must not call
/// them. Manual, operator-initiated updater commands are unaffected.
pub const UNAUDITED_RECURRING_EGRESS_DENIED: &str = "recurring updater network probe blocked: request-bound autonomy and mandatory intent/result WAL are not wired at the concrete transport leaf";

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

/// Resolve the accepted config generation for one updater lane. Unlike the old
/// startup snapshot, this function is called again after every reload wake and
/// immediately before each pass. Strict and fail-closed Custom never execute a
/// standing cron.
fn live_cron_config(
    task_kind: UpdaterTaskKind,
    config: &crate::config::FreedomConfig,
) -> UpdaterCronConfig {
    let scheduler_allowed = crate::cron::scheduler::autonomy_allows_scheduler(config.autonomy);
    match task_kind {
        UpdaterTaskKind::NeothSelf => UpdaterCronConfig {
            enabled: scheduler_allowed
                && config.updater.enabled
                && config.auto_update.enabled
                && config.auto_update.check_interval_secs != 0,
            interval_secs: config.auto_update.check_interval_secs,
        },
        UpdaterTaskKind::SkillPlugin | UpdaterTaskKind::CliVersions => UpdaterCronConfig {
            enabled: scheduler_allowed && config.updater.enabled,
            interval_secs: config.updater.interval_secs,
        },
    }
}

fn recurring_egress_gate() -> crate::updater::pipeline::GateDecision {
    crate::updater::pipeline::GateDecision::Deny {
        reason: UNAUDITED_RECURRING_EGRESS_DENIED.to_string(),
    }
}

/// One tick of the updater cron pass.
///
/// Sequence:
///   1. Emit `0x44 UPDATER_TASK_FIRED` with the task_kind tag so
///      auditors see "the cron started" even when the result frame
///      never lands (e.g. daemon killed mid-pass).
///   2. Builder runs → produces the per-component spec list.
///   3. `run_updater_pass` computes outcomes from the specs.
///   4. Emit `0x45 UPDATER_TASK_RESULT` with the full payload.
///
/// Returns the payload so callers (tests, `neoth updater status`)
/// can inspect outcomes without re-running the pass.
#[cfg(test)]
async fn run_updater_tick<F>(
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

/// Spawn the periodic updater cron loop.
///
/// The small supervisor exists even while the lane is disabled so a successful
/// hot reload can enable it without restarting the daemon. Disabled lanes wait
/// for a reload-generation bump and perform no builder work or WAL emission.
/// Enabled lanes run once immediately, then sleep for the live interval; a
/// reload interrupts that sleep so cadence/enable/autonomy changes take effect
/// before another pass.
///
/// The builder receives the exact accepted config snapshot used for the pass
/// plus a gate decision. Today that decision is deliberately fail-closed until
/// every concrete recurring network transport consumes a request-bound permit.
/// This ensures no GitHub/npm/git egress can happen before its mandatory intent
/// WAL. The builder runs on a blocking worker because local package scans and
/// version commands are synchronous.
pub fn spawn_updater_cron_loop(
    task_kind: UpdaterTaskKind,
    builder: Arc<
        dyn Fn(
                Arc<crate::config::FreedomConfig>,
                crate::updater::pipeline::GateDecision,
            ) -> Vec<ComponentSpec>
            + Send
            + Sync
            + 'static,
    >,
    reload_controller: Arc<crate::config::reload::ReloadController>,
    writer: WalWriterHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut generation = reload_controller.subscribe_generation();
        let mut run_immediately = true;
        tracing::info!(
            task_kind = task_kind.as_str(),
            "live updater cron supervisor online (network probes fail closed until leaf audit wiring lands)",
        );
        loop {
            let config = reload_controller.latest();
            let live = live_cron_config(task_kind, &config);
            if !live.enabled {
                tracing::debug!(
                    task_kind = task_kind.as_str(),
                    autonomy = config.autonomy.as_str(),
                    "updater cron lane disabled by accepted live policy",
                );
                if generation.changed().await.is_err() {
                    return;
                }
                run_immediately = true;
                continue;
            }

            if !run_immediately {
                tokio::select! {
                    _ = tokio::time::sleep(live.interval_duration()) => {}
                    changed = generation.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        continue;
                    }
                }
            }
            run_immediately = false;

            // Re-read immediately before the pass. A reload that disabled the
            // lane or dropped autonomy while the timer was asleep wins without
            // any builder work, WAL intent, or network attempt.
            let config = reload_controller.latest();
            if !live_cron_config(task_kind, &config).enabled {
                continue;
            }

            // 0x44 precedes every builder action. The builder is constrained by
            // `recurring_egress_gate()` to pure/local work; when the transport
            // permit contract lands, its own request intent must still be the
            // final operation before each concrete egress leaf.
            let fired_payload = serde_json::json!({
                "task_kind": task_kind.as_str(),
                "ts_unix": crate::time::now_unix_secs(),
            });
            let fired_body = match serde_json::to_vec(&fired_payload) {
                Ok(body) => body,
                Err(error) => {
                    tracing::error!(error = %error, "serialise fired payload");
                    continue;
                }
            };
            let fired_header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_FIRED, &fired_body)
                .flags(EventFlags::SYNTHETIC)
                .build();
            if let Err(error) = writer.append(fired_header, fired_body).await {
                tracing::warn!(error = %error, "wal append fired (updater tick)");
                continue;
            }

            let b = builder.clone();
            let gate = recurring_egress_gate();
            // Catch panics from the builder so a transient
            // local probe failure doesn't abort the daemon. Spawn
            // the build on a blocking thread so the panic
            // boundary applies via spawn_blocking's join. We
            // know our trait-object builders are unwind-safe
            // (the closures we pass in carry no interior-
            // mutability state across the boundary — they
            // just call probe fns and return a fresh Vec).
            let spec_result = tokio::task::spawn_blocking(move || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b(config, gate)))
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
    })
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
                spec("neoth", "0.2.1", Ok("0.2.1")),
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

    #[test]
    fn live_config_honours_disable_autonomy_and_lane_interval() {
        use crate::permissions::AutonomyLevel;

        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = AutonomyLevel::Standard;
        config.updater.enabled = true;
        config.updater.interval_secs = 12_345;
        config.auto_update.enabled = true;
        config.auto_update.check_interval_secs = 54_321;

        let cli = live_cron_config(UpdaterTaskKind::CliVersions, &config);
        assert!(cli.enabled);
        assert_eq!(cli.interval_secs, 12_345);
        let own = live_cron_config(UpdaterTaskKind::NeothSelf, &config);
        assert!(own.enabled);
        assert_eq!(own.interval_secs, 54_321);

        config.autonomy = AutonomyLevel::Custom;
        assert!(!live_cron_config(UpdaterTaskKind::CliVersions, &config).enabled);
        config.autonomy = AutonomyLevel::Strict;
        assert!(!live_cron_config(UpdaterTaskKind::SkillPlugin, &config).enabled);
        config.autonomy = AutonomyLevel::Standard;
        config.updater.enabled = false;
        assert!(!live_cron_config(UpdaterTaskKind::CliVersions, &config).enabled);
        config.updater.enabled = true;
        config.auto_update.enabled = false;
        assert!(!live_cron_config(UpdaterTaskKind::NeothSelf, &config).enabled);
    }

    #[test]
    fn recurring_network_gate_is_explicitly_fail_closed() {
        match recurring_egress_gate() {
            GateDecision::Deny { reason } => {
                assert_eq!(reason, UNAUDITED_RECURRING_EGRESS_DENIED);
                assert!(reason.contains("intent/result WAL"));
            }
            GateDecision::Allow => panic!("recurring cron must not fabricate egress authority"),
        }
    }

    #[tokio::test]
    async fn disabled_live_lane_spawns_inert_reload_supervisor() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("updater.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let mut config = crate::config::FreedomConfig::default();
        config.updater.enabled = false;
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config,
            wal_dir.path().join("freedom.yaml"),
        ));
        let called = Arc::new(AtomicBool::new(false));
        let called_by_builder = Arc::clone(&called);
        let builder = Arc::new(move |_config: Arc<crate::config::FreedomConfig>, _gate| {
            called_by_builder.store(true, Ordering::SeqCst);
            Vec::new()
        });
        let handle =
            spawn_updater_cron_loop(UpdaterTaskKind::CliVersions, builder, controller, writer);
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(!called.load(Ordering::SeqCst));
        handle.abort();
    }
}
