//! U-04 / GOLD-R3-18 — reload-owned recurring update supervisor.
//!
//! Wraps the pure-fn primitives in [`crate::updater::pipeline`] for
//! the daemon's recurring updater passes. One reload-owned supervisor is the
//! sole lifecycle owner for the three probe lanes, CLI auto-apply and
//! neoth-self staging. Every accepted generation change cancels and joins the
//! old generation before deriving the replacement lane set.
//!
//! ## What's wired today
//!
//! - [`spawn_updater_supervisor`] — exact accepted-generation supervisor.
//! - Every probe and mutation lane emits `0x44 UPDATER_TASK_FIRED` before work
//!   and a typed `0x45 UPDATER_TASK_RESULT` terminal receipt.
//! - Lanes that share a historical `UpdaterTaskKind` are serialized across the
//!   complete FIRED/RESULT pair, so audit frames cannot interleave ambiguously.
//! - NEOTH self-probe and self-stage have request-bound leaf authority, but
//!   remain explicitly denied until absolute operation/effect/quiesce/terminal
//!   deadlines and owned cancellation/reaping are complete.
//! - CLI version probes, skill/plugin probes and CLI auto-apply remain denied
//!   until their process, registry, Git and install leaves enforce the same
//!   exact authority contract.
//!
//! ## What ships in follow-ups
//!
//! - Request-bound permit consumption at the concrete npm-registry,
//!   `git ls-remote` and installer process leaves. Only after each leaf writes
//!   its own intent and terminal result may that lane replace its explicit
//!   denied gate with the live operator decision.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use crate::updater::pipeline::ComponentSpec;
use crate::updater::pipeline::run_updater_pass;
use crate::wal::events::{EVENT_TYPE_UPDATER_TASK_FIRED, EVENT_TYPE_UPDATER_TASK_RESULT};
use crate::wal::payloads_u04::{
    ComponentOutcome, UpdaterPassIdentity, UpdaterPassLane, UpdaterTaskFiredPayload,
    UpdaterTaskKind, UpdaterTaskResultPayload,
};
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};
use futures_util::FutureExt;

/// Legacy recurring lanes are denied until their concrete network/process
/// leaves consume request-bound authority. Manual, operator-initiated updater
/// commands are unaffected.
pub const UNAUDITED_RECURRING_EGRESS_DENIED: &str = "recurring updater network probe blocked: request-bound autonomy and mandatory intent/result WAL are not wired at the concrete transport leaf";
pub const UNBOUNDED_RECURRING_LIFECYCLE_DENIED: &str = "recurring NEOTH self-update blocked: absolute operation/effect/quiesce/terminal deadlines and owned cancellation/kill/reap are not wired";
const REQUEST_BOUND_POLICY_REFUSED: &str =
    "accepted updater policy refused this exact recurring leaf";
const ACCEPTED_GENERATION_RETIRED: &str =
    "accepted updater generation retired before this recurring leaf started";

#[derive(Debug)]
enum TerminalizedPassFailure {
    /// The concrete effect failed after its request-bound terminal leaf audit
    /// was acknowledged. The outer updater RESULT is therefore the durable
    /// terminal state and the lane may retry on its next cadence.
    RetryNextCadence(String),
    /// Authority, lifecycle or audit persistence could not prove a safe
    /// terminal boundary. The accepted generation must fail closed.
    CloseSupervisor(String),
}

fn mutation_failure_disposition(error: String) -> TerminalizedPassFailure {
    // `run_self_stage_pass` currently returns String, so retain a deliberately
    // narrow classification at this boundary. Every typed updater-leaf error
    // is authority-fatal except a durably terminalized ordinary Effect.
    const EFFECT_MARKER: &str = "updater leaf effect failed (";
    if let Some(effect) = error.split_once(EFFECT_MARKER).map(|(_, effect)| effect) {
        return if effect.starts_with("panic;")
            || effect.starts_with("cancelled;")
            || effect.starts_with("policy;")
        {
            TerminalizedPassFailure::CloseSupervisor(error)
        } else {
            TerminalizedPassFailure::RetryNextCadence(error)
        };
    }
    if error.contains("updater leaf ")
        || error.contains("accepted updater generation retired")
        || error.contains("mandatory staged self-update WAL append failed")
        || error.contains("self-update notification sidecar write failed")
        || error.contains("neoth-self staging rejected the configured release target")
    {
        TerminalizedPassFailure::CloseSupervisor(error)
    } else {
        TerminalizedPassFailure::RetryNextCadence(error)
    }
}

fn authorized_probe_failure_disposition(error: anyhow::Error) -> TerminalizedPassFailure {
    match error.downcast_ref::<crate::updater::authority::UpdaterLeafExecutionError>() {
        Some(crate::updater::authority::UpdaterLeafExecutionError::Effect {
            kind: "panic" | "cancelled" | "policy",
            ..
        }) => TerminalizedPassFailure::CloseSupervisor(format!(
            "authorized self-update probe failed: {error}"
        )),
        Some(crate::updater::authority::UpdaterLeafExecutionError::Effect { .. }) | None => {
            TerminalizedPassFailure::RetryNextCadence(format!(
                "authorized self-update probe failed: {error}"
            ))
        }
        Some(_) => TerminalizedPassFailure::CloseSupervisor(format!(
            "authorized self-update probe failed: {error}"
        )),
    }
}

/// Every recurring update lane owned by the generation supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RecurringUpdateLane {
    NeothSelfProbe,
    CliVersionProbe,
    SkillPluginProbe,
    CliAutoApply,
    SelfStage,
}

impl RecurringUpdateLane {
    fn as_str(self) -> &'static str {
        match self {
            Self::NeothSelfProbe => "neoth_self_probe",
            Self::CliVersionProbe => "cli_version_probe",
            Self::SkillPluginProbe => "skill_plugin_probe",
            Self::CliAutoApply => "cli_auto_apply",
            Self::SelfStage => "self_stage",
        }
    }

    fn task_kind(self) -> Option<UpdaterTaskKind> {
        match self {
            Self::NeothSelfProbe => Some(UpdaterTaskKind::NeothSelf),
            Self::CliVersionProbe => Some(UpdaterTaskKind::CliVersions),
            Self::SkillPluginProbe => Some(UpdaterTaskKind::SkillPlugin),
            Self::CliAutoApply | Self::SelfStage => None,
        }
    }

    fn audit_task_kind(self) -> UpdaterTaskKind {
        match self {
            Self::NeothSelfProbe | Self::SelfStage => UpdaterTaskKind::NeothSelf,
            Self::CliVersionProbe | Self::CliAutoApply => UpdaterTaskKind::CliVersions,
            Self::SkillPluginProbe => UpdaterTaskKind::SkillPlugin,
        }
    }

    fn audit_lane(self) -> UpdaterPassLane {
        match self {
            Self::NeothSelfProbe => UpdaterPassLane::NeothSelfProbe,
            Self::CliVersionProbe => UpdaterPassLane::CliVersionProbe,
            Self::SkillPluginProbe => UpdaterPassLane::SkillPluginProbe,
            Self::CliAutoApply => UpdaterPassLane::CliAutoApply,
            Self::SelfStage => UpdaterPassLane::SelfStage,
        }
    }

    fn runs_immediately_on_enable(self) -> bool {
        self.task_kind().is_some()
    }
}

#[derive(Default)]
struct UpdaterAuditLocks {
    neoth_self: tokio::sync::Mutex<()>,
    cli_versions: tokio::sync::Mutex<()>,
    skill_plugin: tokio::sync::Mutex<()>,
}

impl UpdaterAuditLocks {
    async fn lock(&self, task_kind: UpdaterTaskKind) -> tokio::sync::MutexGuard<'_, ()> {
        match task_kind {
            UpdaterTaskKind::NeothSelf => self.neoth_self.lock().await,
            UpdaterTaskKind::CliVersions => self.cli_versions.lock().await,
            UpdaterTaskKind::SkillPlugin => self.skill_plugin.lock().await,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LaneSchedule {
    lane: RecurringUpdateLane,
    interval_secs: u64,
}

impl LaneSchedule {
    fn interval_duration(self) -> Duration {
        Duration::from_secs(self.interval_secs.max(60))
    }
}

#[derive(Debug, Clone, Copy)]
struct LaneCadence {
    schedule: LaneSchedule,
    next_due: tokio::time::Instant,
}

impl LaneCadence {
    fn newly_enabled(schedule: LaneSchedule, now: tokio::time::Instant) -> Self {
        let next_due = if schedule.lane.runs_immediately_on_enable() {
            now
        } else {
            now + schedule.interval_duration()
        };
        Self { schedule, next_due }
    }

    /// Apply a live cadence change without creating an unrelated reload storm.
    /// A shorter interval may pull a deadline closer; a longer interval never
    /// postpones work that was already due under the accepted prior policy.
    fn rescheduled(self, schedule: LaneSchedule, now: tokio::time::Instant) -> Self {
        let next_due = if schedule.interval_duration() < self.schedule.interval_duration() {
            self.next_due.min(now + schedule.interval_duration())
        } else {
            self.next_due
        };
        Self { schedule, next_due }
    }

    /// MissedTickBehavior::Skip expressed over an absolute deadline. Runtime
    /// duration and reload churn never move the cadence anchor forward by an
    /// additional full interval.
    fn advance_after_run(&mut self, now: tokio::time::Instant) {
        let interval = self.schedule.interval_duration();
        while self.next_due <= now {
            self.next_due += interval;
        }
    }
}

/// Derive one complete lane set from one accepted config snapshot.
///
/// `updater.enabled` is the global recurring-update master. The GUI-facing
/// `auto_update.enabled` and `auto_update.auto_apply` switches additionally
/// gate both mutating lanes, closing the legacy state where CLI auto-apply
/// remained active while both GUI update switches were off.
fn effective_lane_schedules(config: &crate::config::FreedomConfig) -> Vec<LaneSchedule> {
    if !config.updater.enabled
        || !crate::cron::scheduler::autonomy_allows_scheduler(config.autonomy)
    {
        return Vec::new();
    }

    let mut schedules = vec![
        LaneSchedule {
            lane: RecurringUpdateLane::CliVersionProbe,
            interval_secs: config.updater.interval_secs,
        },
        LaneSchedule {
            lane: RecurringUpdateLane::SkillPluginProbe,
            interval_secs: config.updater.interval_secs,
        },
    ];

    if config.auto_update.enabled && config.auto_update.check_interval_secs != 0 {
        schedules.push(LaneSchedule {
            lane: RecurringUpdateLane::NeothSelfProbe,
            interval_secs: config.auto_update.check_interval_secs,
        });
    }

    if config.auto_update.enabled
        && config.auto_update.auto_apply
        && crate::daemon::auto_update::auto_apply_enabled(config.autonomy)
    {
        schedules.push(LaneSchedule {
            lane: RecurringUpdateLane::CliAutoApply,
            interval_secs: config.updater.interval_secs,
        });
        if config.auto_update.check_interval_secs != 0 {
            schedules.push(LaneSchedule {
                lane: RecurringUpdateLane::SelfStage,
                interval_secs: config.auto_update.check_interval_secs,
            });
        }
    }

    schedules
}

fn recurring_egress_gate(lane: RecurringUpdateLane) -> crate::updater::pipeline::GateDecision {
    match lane {
        // Their exact request-bound authority is wired, but admitting either
        // lane before R3-18B would let a stalled transport, filesystem effect,
        // blocking stage helper or terminal append hold reload/shutdown
        // forever. Keep them inert until the owned lifecycle is bounded.
        RecurringUpdateLane::NeothSelfProbe | RecurringUpdateLane::SelfStage => {
            crate::updater::pipeline::GateDecision::Deny {
                reason: UNBOUNDED_RECURRING_LIFECYCLE_DENIED.to_string(),
            }
        }
        // CLI/npm/Git/OSV/install leaves remain inert until their own exact
        // request-bound authority wrappers land.
        RecurringUpdateLane::CliVersionProbe
        | RecurringUpdateLane::SkillPluginProbe
        | RecurringUpdateLane::CliAutoApply => crate::updater::pipeline::GateDecision::Deny {
            reason: UNAUDITED_RECURRING_EGRESS_DENIED.to_string(),
        },
    }
}

type LaneFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;
type LaneExecutor = Arc<
    dyn Fn(
            RecurringUpdateLane,
            Arc<crate::config::reload::AcceptedConfigSnapshot>,
            crate::updater::pipeline::GateDecision,
        ) -> LaneFuture
        + Send
        + Sync
        + 'static,
>;

/// Sole daemon owner for all recurring update work.
pub(crate) struct UpdaterSupervisorHandle {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
    failure: Option<tokio::sync::oneshot::Receiver<String>>,
}

impl UpdaterSupervisorHandle {
    pub(crate) fn abort_handle(&self) -> tokio::task::AbortHandle {
        self.join
            .as_ref()
            .expect("live updater supervisor handle")
            .abort_handle()
    }

    /// Required daemon-boundary signal. It resolves only when the supervisor
    /// exits unexpectedly or panics; ordinary shutdown is initiated after the
    /// daemon's main boundary select has already completed.
    pub(crate) async fn wait_for_failure(&mut self) -> String {
        match self
            .failure
            .as_mut()
            .expect("live updater supervisor failure receiver")
            .await
        {
            Ok(reason) => reason,
            Err(_) => "updater supervisor task panicked or was aborted".to_string(),
        }
    }

    /// Stop the current accepted generation, cancel and join any active lane,
    /// then join the supervisor itself.
    pub(crate) async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take()
            && let Err(error) = join.await
        {
            tracing::warn!(%error, "updater supervisor join failed during shutdown");
        }
    }
}

impl Drop for UpdaterSupervisorHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        // Drop cannot await. Detach after signalling shutdown so the
        // supervisor can still cancel and join admitted work and emit its
        // terminal result. Aborting here manufactured an audit orphan during
        // otherwise graceful owner teardown. Normal daemon shutdown calls
        // `shutdown()` and awaits this same task.
        let _ = self.join.take();
    }
}

/// Spawn one reload-owned supervisor for probe, CLI auto-apply and self-stage
/// work. Even a fully disabled configuration keeps this one inert supervisor
/// so a later accepted generation can enable lanes without a daemon restart.
pub(crate) fn spawn_updater_supervisor(
    home: PathBuf,
    reload_controller: Arc<crate::config::reload::ReloadController>,
    writer: WalWriterHandle,
) -> UpdaterSupervisorHandle {
    let executor: LaneExecutor = Arc::new(move |lane, snapshot, gate| {
        let home = home.clone();
        let writer = writer.clone();
        Box::pin(run_production_lane_once(lane, snapshot, home, writer, gate))
    });
    spawn_updater_supervisor_with_executor(reload_controller, executor)
}

fn spawn_updater_supervisor_with_executor(
    reload_controller: Arc<crate::config::reload::ReloadController>,
    executor: LaneExecutor,
) -> UpdaterSupervisorHandle {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (failure_tx, failure_rx) = tokio::sync::oneshot::channel();
    let audit_locks = Arc::new(UpdaterAuditLocks::default());
    let join = tokio::spawn(async move {
        if let Err(reason) =
            run_updater_supervisor(reload_controller, executor, audit_locks, shutdown_rx).await
        {
            let _ = failure_tx.send(reason);
        }
    });
    UpdaterSupervisorHandle {
        shutdown: Some(shutdown_tx),
        join: Some(join),
        failure: Some(failure_rx),
    }
}

enum SupervisorWake {
    Reload,
    Shutdown,
    LaneExited(String),
}

async fn run_updater_supervisor(
    reload_controller: Arc<crate::config::reload::ReloadController>,
    executor: LaneExecutor,
    audit_locks: Arc<UpdaterAuditLocks>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String> {
    let mut generation = reload_controller.subscribe_generation();
    let mut cadence_by_lane = std::collections::HashMap::<RecurringUpdateLane, LaneCadence>::new();
    tracing::info!("reload-owned updater supervisor online (recurring egress remains fail-closed)");

    loop {
        // Config + epoch come from one ArcSwap object. The watch receiver is
        // notification only and never paired with a separate `latest()` read.
        let snapshot = reload_controller.accepted_snapshot();
        let epoch = snapshot.epoch();
        let schedules = effective_lane_schedules(&snapshot.config());
        let active_lanes: std::collections::HashSet<_> =
            schedules.iter().map(|schedule| schedule.lane).collect();
        cadence_by_lane.retain(|lane, _| active_lanes.contains(lane));
        let now = tokio::time::Instant::now();
        let (cancel_generation, _) = tokio::sync::watch::channel(false);
        let mut lanes = tokio::task::JoinSet::new();

        for schedule in schedules {
            let cadence = cadence_by_lane
                .remove(&schedule.lane)
                .map(|prior| prior.rescheduled(schedule, now))
                .unwrap_or_else(|| LaneCadence::newly_enabled(schedule, now));
            lanes.spawn(run_lane_loop(
                cadence,
                Arc::clone(&snapshot),
                executor.clone(),
                Arc::clone(&audit_locks),
                cancel_generation.subscribe(),
            ));
        }
        tracing::debug!(
            epoch,
            lanes = lanes.len(),
            "accepted updater generation active"
        );

        let wake = tokio::select! {
            biased;
            _ = &mut shutdown => SupervisorWake::Shutdown,
            changed = generation.changed() => {
                if changed.is_ok() {
                    SupervisorWake::Reload
                } else {
                    SupervisorWake::Shutdown
                }
            }
            lane = lanes.join_next(), if !lanes.is_empty() => {
                let reason = match lane {
                    Some(Ok(Ok((lane, _)))) => format!(
                        "recurring update lane `{}` exited outside generation cancellation",
                        lane.as_str()
                    ),
                    Some(Ok(Err(reason))) => reason,
                    Some(Err(error)) => {
                        format!("recurring update lane task failed: {error}")
                    }
                    None => "recurring update lane set ended unexpectedly".to_string(),
                };
                tracing::error!(epoch, %reason, "recurring updater supervisor is failing closed");
                SupervisorWake::LaneExited(reason)
            }
        };

        cancel_generation.send_replace(true);
        let mut drain_failure = None;
        while let Some(result) = lanes.join_next().await {
            match result {
                Ok(Ok((lane, cadence))) => {
                    cadence_by_lane.insert(lane, cadence);
                }
                Ok(Err(reason)) => {
                    tracing::error!(
                        epoch,
                        %reason,
                        "recurring update lane failed while draining accepted work"
                    );
                    drain_failure.get_or_insert(reason);
                }
                Err(error) => {
                    let reason = format!("recurring update lane join failed: {error}");
                    tracing::error!(epoch, %reason);
                    drain_failure.get_or_insert(reason);
                }
            }
        }
        if let Some(reason) = drain_failure {
            return Err(format!(
                "recurring updater failed while draining epoch {epoch}: {reason}"
            ));
        }

        match wake {
            SupervisorWake::Reload => {
                tracing::debug!(epoch, "retired updater generation after accepted reload");
            }
            SupervisorWake::Shutdown => {
                tracing::debug!(epoch, "updater supervisor shut down cleanly");
                return Ok(());
            }
            SupervisorWake::LaneExited(reason) => {
                return Err(format!(
                    "recurring updater lane failed at epoch {epoch}: {reason}"
                ));
            }
        }
    }
}

async fn run_lane_loop(
    mut cadence: LaneCadence,
    snapshot: Arc<crate::config::reload::AcceptedConfigSnapshot>,
    executor: LaneExecutor,
    audit_locks: Arc<UpdaterAuditLocks>,
    mut cancel_generation: tokio::sync::watch::Receiver<bool>,
) -> Result<(RecurringUpdateLane, LaneCadence), String> {
    let lane = cadence.schedule.lane;
    loop {
        tokio::select! {
            biased;
            changed = cancel_generation.changed() => {
                let _ = changed;
                return Ok((lane, cadence));
            }
            _ = tokio::time::sleep_until(cadence.next_due) => {}
        }

        if *cancel_generation.borrow() {
            return Ok((lane, cadence));
        }

        // Admission is the same-kind audit lock. A cancelled generation that
        // was only queued here must retire without constructing or polling its
        // executor, so revoked snapshots cannot begin work after cancellation.
        let _audit_pair = tokio::select! {
            biased;
            changed = cancel_generation.changed() => {
                let _ = changed;
                return Ok((lane, cadence));
            }
            guard = audit_locks.lock(lane.audit_task_kind()) => guard,
        };
        if *cancel_generation.borrow() {
            return Ok((lane, cadence));
        }

        let gate = recurring_egress_gate(lane);
        let work = std::panic::AssertUnwindSafe(executor(lane, Arc::clone(&snapshot), gate))
            .catch_unwind();
        tokio::pin!(work);
        let (cancellation_requested, execution) = tokio::select! {
            biased;
            changed = cancel_generation.changed() => {
                let _ = changed;
                // Never drop admitted work: a probe may already have written
                // FIRED, and a future authorized executor may own a blocking
                // worker or child process. Join it to its terminal RESULT before
                // replacing the accepted generation.
                (true, (&mut work).await)
            }
            result = &mut work => {
                (false, result)
            }
        };
        require_successful_lane_execution(lane, execution)?;
        cadence.advance_after_run(tokio::time::Instant::now());
        if cancellation_requested || *cancel_generation.borrow() {
            return Ok((lane, cadence));
        }
    }
}

fn require_successful_lane_execution(
    lane: RecurringUpdateLane,
    result: Result<Result<(), String>, Box<dyn std::any::Any + Send>>,
) -> Result<(), String> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            tracing::error!(
                lane = lane.as_str(),
                %error,
                "recurring update work failed; closing supervisor"
            );
            Err(format!(
                "recurring update lane `{}` failed: {error}",
                lane.as_str()
            ))
        }
        Err(_) => {
            tracing::error!(
                lane = lane.as_str(),
                "recurring update work panicked; closing supervisor"
            );
            Err(format!(
                "recurring update lane `{}` panicked",
                lane.as_str()
            ))
        }
    }
}

async fn run_production_lane_once(
    lane: RecurringUpdateLane,
    snapshot: Arc<crate::config::reload::AcceptedConfigSnapshot>,
    home: PathBuf,
    writer: WalWriterHandle,
    gate: crate::updater::pipeline::GateDecision,
) -> Result<(), String> {
    let config = snapshot.config();
    let pass_identity = UpdaterPassIdentity::new(lane.audit_lane(), snapshot.epoch());
    match lane {
        RecurringUpdateLane::CliAutoApply => {
            let deny_reason = match &gate {
                crate::updater::pipeline::GateDecision::Deny { reason } => reason.clone(),
                crate::updater::pipeline::GateDecision::Allow => {
                    return Err("CLI auto-apply was enabled before its process/HTTP/install leaves consumed request-bound authority".to_string());
                }
            };
            run_mutation_pass_at(
                pass_identity,
                UpdaterTaskKind::CliVersions,
                "cli_auto_apply",
                "not_run",
                &deny_reason,
                &writer,
                crate::daemon::auto_update::run_cli_auto_apply_pass(
                    gate,
                    &writer,
                    &config.security,
                ),
            )
            .await?;
            Ok(())
        }
        RecurringUpdateLane::SelfStage => {
            let skipped_reason = match &gate {
                crate::updater::pipeline::GateDecision::Deny { reason } => reason.clone(),
                crate::updater::pipeline::GateDecision::Allow => {
                    REQUEST_BOUND_POLICY_REFUSED.to_string()
                }
            };
            run_mutation_pass_at(
                pass_identity,
                UpdaterTaskKind::NeothSelf,
                "self_stage",
                crate::updater::self_update::current_version(),
                &skipped_reason,
                &writer,
                crate::daemon::auto_update::run_self_stage_pass(
                    gate,
                    &home,
                    Arc::clone(&snapshot),
                    &writer,
                ),
            )
            .await?;
            Ok(())
        }
        RecurringUpdateLane::NeothSelfProbe => {
            if let crate::updater::pipeline::GateDecision::Deny { reason } = &gate {
                let result = run_probe_pass_with_builder_at(
                    pass_identity,
                    UpdaterTaskKind::NeothSelf,
                    &writer,
                    || async { Ok(denied_probe_specs(UpdaterTaskKind::NeothSelf, reason)) },
                )
                .await?;
                tracing::debug!(
                    components = result.components.len(),
                    duration_ms = result.duration_ms,
                    epoch = snapshot.epoch(),
                    "self-update probe blocked before leaf authority",
                );
                return Ok(());
            }
            let result =
                run_authorized_self_probe(pass_identity, Arc::clone(&snapshot), &writer).await?;
            tracing::debug!(
                components = result.components.len(),
                duration_ms = result.duration_ms,
                epoch = snapshot.epoch(),
                "authorized self-update probe complete",
            );
            Ok(())
        }
        probe_lane => {
            let deny_reason = match &gate {
                crate::updater::pipeline::GateDecision::Deny { reason } => reason.clone(),
                crate::updater::pipeline::GateDecision::Allow => {
                    return Err(format!(
                        "recurring updater lane `{}` was enabled before all concrete leaves consumed request-bound authority",
                        probe_lane.as_str()
                    ));
                }
            };
            let task_kind = probe_lane
                .task_kind()
                .expect("probe lane must map to updater task kind");
            let result =
                run_probe_pass_with_builder_at(pass_identity, task_kind, &writer, || async {
                    Ok(denied_probe_specs(task_kind, &deny_reason))
                })
                .await?;
            tracing::debug!(
                task_kind = task_kind.as_str(),
                components = result.components.len(),
                duration_ms = result.duration_ms,
                epoch = snapshot.epoch(),
                "updater tick complete",
            );
            Ok(())
        }
    }
}

#[cfg(test)]
async fn run_mutation_pass<F>(
    task_kind: UpdaterTaskKind,
    component_name: &str,
    current_version: &str,
    deny_reason: &str,
    writer: &WalWriterHandle,
    work: F,
) -> Result<UpdaterTaskResultPayload, String>
where
    F: Future<Output = Result<crate::daemon::auto_update::RecurringMutationOutcome, String>>,
{
    run_mutation_pass_at(
        UpdaterPassIdentity::new(test_lane_for_task(task_kind), 0),
        task_kind,
        component_name,
        current_version,
        deny_reason,
        writer,
        work,
    )
    .await
}

async fn run_mutation_pass_at<F>(
    identity: UpdaterPassIdentity,
    task_kind: UpdaterTaskKind,
    component_name: &str,
    current_version: &str,
    deny_reason: &str,
    writer: &WalWriterHandle,
    work: F,
) -> Result<UpdaterTaskResultPayload, String>
where
    F: Future<Output = Result<crate::daemon::auto_update::RecurringMutationOutcome, String>>,
{
    append_updater_fired(&identity, task_kind, writer).await?;
    let started = std::time::Instant::now();
    let outcome = std::panic::AssertUnwindSafe(work).catch_unwind().await;
    let (component, terminalized_failure) = match outcome {
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::BlockedByGate)) => (
            ComponentOutcome::skipped_by_gate(component_name, current_version, deny_reason),
            None,
        ),
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::SkippedByPolicy)) => (
            ComponentOutcome::skipped_by_gate(
                component_name,
                current_version,
                REQUEST_BOUND_POLICY_REFUSED,
            ),
            None,
        ),
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::GenerationRetired)) => (
            ComponentOutcome::skipped_by_gate(
                component_name,
                current_version,
                ACCEPTED_GENERATION_RETIRED,
            ),
            None,
        ),
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::Completed)) => (
            ComponentOutcome::up_to_date(component_name, current_version),
            None,
        ),
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::Staged {
            prior_version,
            staged_version,
        })) => (
            ComponentOutcome::staged(component_name, prior_version, staged_version),
            None,
        ),
        Ok(Err(error)) => (
            ComponentOutcome::failed(component_name, current_version, error.clone()),
            Some(mutation_failure_disposition(error)),
        ),
        Err(_) => {
            let error = format!("{component_name} executor panicked");
            (
                ComponentOutcome::failed(component_name, current_version, &error),
                Some(TerminalizedPassFailure::CloseSupervisor(error)),
            )
        }
    };
    let result = UpdaterTaskResultPayload {
        identity,
        task_kind,
        ts_unix: crate::time::now_unix_secs(),
        duration_ms: started.elapsed().as_millis().min(u32::MAX as u128) as u32,
        components: vec![component],
    };
    append_updater_result(&result, writer).await?;
    match terminalized_failure {
        Some(TerminalizedPassFailure::RetryNextCadence(error)) => {
            tracing::warn!(
                task_kind = task_kind.as_str(),
                component = component_name,
                %error,
                "recurring updater leaf failed; durable Failed RESULT recorded; retrying next cadence"
            );
        }
        Some(TerminalizedPassFailure::CloseSupervisor(error)) => return Err(error),
        None => {}
    }
    Ok(result)
}

async fn run_authorized_self_probe(
    identity: UpdaterPassIdentity,
    snapshot: Arc<crate::config::reload::AcceptedConfigSnapshot>,
    writer: &WalWriterHandle,
) -> Result<UpdaterTaskResultPayload, String> {
    let task_kind = UpdaterTaskKind::NeothSelf;
    append_updater_fired(&identity, task_kind, writer).await?;
    let started = std::time::Instant::now();
    let current = crate::updater::self_update::current_version();
    let checked = std::panic::AssertUnwindSafe(async {
        let authority = crate::updater::self_update::RecurringSelfUpdateAuthority::for_probe(
            writer.clone(),
            Arc::clone(&snapshot),
        );
        let config = &snapshot.config().auto_update;
        crate::updater::self_update::check_for_update_channel_authorized(
            &authority,
            &config.repo,
            config.channel,
        )
        .await
    })
    .catch_unwind()
    .await;
    let (component, terminalized_failure) = match checked {
        Ok(Ok(check)) if check.needs_update => (
            ComponentOutcome::update_available("neoth", check.current, check.latest),
            None,
        ),
        Ok(Ok(check)) => (ComponentOutcome::up_to_date("neoth", check.current), None),
        Ok(Err(error)) if crate::updater::authority::error_is_policy_refusal(&error) => (
            ComponentOutcome::skipped_by_gate("neoth", current, REQUEST_BOUND_POLICY_REFUSED),
            None,
        ),
        Ok(Err(error)) if crate::updater::authority::error_is_generation_retired(&error) => (
            ComponentOutcome::skipped_by_gate("neoth", current, ACCEPTED_GENERATION_RETIRED),
            None,
        ),
        Ok(Err(error)) => {
            let failure = authorized_probe_failure_disposition(error);
            let diagnostic = match &failure {
                TerminalizedPassFailure::RetryNextCadence(error)
                | TerminalizedPassFailure::CloseSupervisor(error) => error,
            };
            (
                ComponentOutcome::failed("neoth", current, diagnostic),
                Some(failure),
            )
        }
        Err(_) => {
            let diagnostic = "authorized self-update probe executor panicked".to_string();
            (
                ComponentOutcome::failed("neoth", current, &diagnostic),
                Some(TerminalizedPassFailure::CloseSupervisor(diagnostic)),
            )
        }
    };
    let result = UpdaterTaskResultPayload {
        identity,
        task_kind,
        ts_unix: crate::time::now_unix_secs(),
        duration_ms: started.elapsed().as_millis().min(u32::MAX as u128) as u32,
        components: vec![component],
    };
    append_updater_result(&result, writer).await?;
    match terminalized_failure {
        Some(TerminalizedPassFailure::RetryNextCadence(error)) => {
            tracing::warn!(
                task_kind = task_kind.as_str(),
                %error,
                "recurring updater probe failed; durable Failed RESULT recorded; retrying next cadence"
            );
        }
        Some(TerminalizedPassFailure::CloseSupervisor(error)) => return Err(error),
        None => {}
    }
    Ok(result)
}

/// Build auditable denied rows without package scans, subprocesses or network.
/// The inventory sentinel for Skill/Plugin is intentional: enumerating the
/// installed tree is blocking work and must not happen before this generation's
/// standing authority is sufficient to run the concrete leaf chain.
fn denied_probe_specs(
    task_kind: UpdaterTaskKind,
    reason: &str,
) -> Vec<crate::updater::pipeline::ComponentSpec> {
    let names: Vec<(&str, String)> = match task_kind {
        UpdaterTaskKind::NeothSelf => vec![(
            "neoth",
            crate::updater::self_update::current_version().to_string(),
        )],
        UpdaterTaskKind::CliVersions => crate::updater::Component::ALL
            .iter()
            .map(|component| (component.name(), "unprobed".to_string()))
            .collect(),
        UpdaterTaskKind::SkillPlugin => {
            vec![("skill_plugin_inventory", "unscanned".to_string())]
        }
    };
    names
        .into_iter()
        .map(
            |(name, current_version)| crate::updater::pipeline::ComponentSpec {
                name: name.to_string(),
                current_version,
                latest_version: Err(reason.to_string()),
                gate_decision: crate::updater::pipeline::GateDecision::Deny {
                    reason: reason.to_string(),
                },
            },
        )
        .collect()
}

/// Production probe sequence shared by tests: FIRED is durable before the
/// builder/executor runs, and every contained builder error or panic becomes a
/// terminal RESULT with a typed Failed component.
#[cfg(test)]
async fn run_probe_pass_with_builder<F, B>(
    task_kind: UpdaterTaskKind,
    writer: &WalWriterHandle,
    builder: F,
) -> Result<UpdaterTaskResultPayload, String>
where
    F: FnOnce() -> B,
    B: Future<Output = Result<Vec<crate::updater::pipeline::ComponentSpec>, String>>,
{
    run_probe_pass_with_builder_at(
        UpdaterPassIdentity::new(test_lane_for_task(task_kind), 0),
        task_kind,
        writer,
        builder,
    )
    .await
}

async fn run_probe_pass_with_builder_at<F, B>(
    identity: UpdaterPassIdentity,
    task_kind: UpdaterTaskKind,
    writer: &WalWriterHandle,
    builder: F,
) -> Result<UpdaterTaskResultPayload, String>
where
    F: FnOnce() -> B,
    B: Future<Output = Result<Vec<crate::updater::pipeline::ComponentSpec>, String>>,
{
    append_updater_fired(&identity, task_kind, writer).await?;
    let computed = std::panic::AssertUnwindSafe(async move {
        builder()
            .await
            .map(|specs| run_updater_pass(task_kind, specs))
    })
    .catch_unwind()
    .await;
    let mut result = match computed {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => failed_probe_result(task_kind, error),
        Err(_) => failed_probe_result(task_kind, "updater builder/executor panicked"),
    };
    result.identity = identity;
    append_updater_result(&result, writer).await?;
    Ok(result)
}

fn failed_probe_result(
    task_kind: UpdaterTaskKind,
    error: impl Into<String>,
) -> UpdaterTaskResultPayload {
    UpdaterTaskResultPayload {
        identity: UpdaterPassIdentity::legacy(),
        task_kind,
        ts_unix: crate::time::now_unix_secs(),
        duration_ms: 0,
        components: vec![ComponentOutcome::failed(
            format!("{}_pass", task_kind.as_str()),
            "unknown",
            error,
        )],
    }
}

async fn append_updater_fired(
    identity: &UpdaterPassIdentity,
    task_kind: UpdaterTaskKind,
    writer: &WalWriterHandle,
) -> Result<(), String> {
    let payload = UpdaterTaskFiredPayload {
        identity: identity.clone(),
        task_kind,
        ts_unix: crate::time::now_unix_secs(),
    };
    let body = serde_json::to_vec(&payload).map_err(|error| format!("serde fired: {error}"))?;
    let header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_FIRED, &body)
        .flags(EventFlags::SYNTHETIC)
        .build();
    writer
        .append(header, body)
        .await
        .map(|_| ())
        .map_err(|error| format!("wal append fired: {error}"))
}

async fn append_updater_result(
    result: &crate::wal::payloads_u04::UpdaterTaskResultPayload,
    writer: &WalWriterHandle,
) -> Result<(), String> {
    let body = serde_json::to_vec(result).map_err(|error| format!("serde result: {error}"))?;
    let header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_RESULT, &body)
        .flags(EventFlags::SYNTHETIC)
        .build();
    writer
        .append(header, body)
        .await
        .map(|_| ())
        .map_err(|error| format!("wal append result: {error}"))
}

#[cfg(test)]
fn test_lane_for_task(task_kind: UpdaterTaskKind) -> UpdaterPassLane {
    match task_kind {
        UpdaterTaskKind::NeothSelf => UpdaterPassLane::NeothSelfProbe,
        UpdaterTaskKind::SkillPlugin => UpdaterPassLane::SkillPluginProbe,
        UpdaterTaskKind::CliVersions => UpdaterPassLane::CliVersionProbe,
    }
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
    fn interval_clamped_to_60_seconds_minimum() {
        let schedule = LaneSchedule {
            lane: RecurringUpdateLane::CliVersionProbe,
            interval_secs: 5,
        };
        assert_eq!(schedule.interval_duration(), Duration::from_secs(60));
    }

    #[test]
    fn interval_uses_configured_value_above_floor() {
        let schedule = LaneSchedule {
            lane: RecurringUpdateLane::CliVersionProbe,
            interval_secs: 12_000,
        };
        assert_eq!(schedule.interval_duration(), Duration::from_secs(12_000));
    }

    #[tokio::test(start_paused = true)]
    async fn cadence_skips_missed_ticks_without_runtime_drift() {
        let anchor = tokio::time::Instant::now();
        let mut cadence = LaneCadence::newly_enabled(
            LaneSchedule {
                lane: RecurringUpdateLane::CliAutoApply,
                interval_secs: 60,
            },
            anchor,
        );
        assert_eq!(cadence.next_due, anchor + Duration::from_secs(60));
        cadence.advance_after_run(anchor + Duration::from_secs(185));
        assert_eq!(
            cadence.next_due,
            anchor + Duration::from_secs(240),
            "deadline stays on the original 60-second grid"
        );
    }

    #[tokio::test]
    async fn production_probe_path_emits_exact_fired_then_result_frames() {
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;

        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("updater-000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let result = run_probe_pass_with_builder(UpdaterTaskKind::NeothSelf, &writer, || async {
            Ok(vec![
                spec("neoth", "0.2.1", Ok("0.2.1")),
                spec("claude", "0.42.0", Ok("0.43.0")),
            ])
        })
        .await
        .unwrap();
        assert_eq!(result.components.len(), 2);
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let first = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(first.header.event_type, EVENT_TYPE_UPDATER_TASK_FIRED);
        let fired: UpdaterTaskFiredPayload = serde_json::from_slice(first.payload).unwrap();
        let second_offset = SEGMENT_HEADER_LEN + first.header.total_len as usize;
        let second = decode_frame(&bytes[second_offset..]).unwrap();
        assert_eq!(second.header.event_type, EVENT_TYPE_UPDATER_TASK_RESULT);
        let marker_offset = second_offset + second.header.total_len as usize;
        let marker = decode_frame(&bytes[marker_offset..]).unwrap();
        assert_eq!(
            marker.header.event_type,
            crate::wal::events::EVENT_TYPE_COMPACTION_MARKER
        );
        assert_eq!(
            marker_offset + marker.header.total_len as usize,
            bytes.len(),
            "exactly one FIRED/RESULT pair followed by its shutdown HMAC marker"
        );
        let decoded: UpdaterTaskResultPayload = serde_json::from_slice(second.payload).unwrap();
        assert_eq!(decoded, result);
        assert_eq!(fired.identity, decoded.identity);
        assert!(decoded.identity.correlatable_pass_id().is_some());
    }

    #[tokio::test]
    async fn retired_generation_is_terminally_skipped_without_failing_the_supervisor() {
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("retired-generation-000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();

        let result = run_mutation_pass(
            UpdaterTaskKind::NeothSelf,
            "neoth",
            "1.0.0",
            "unused",
            &writer,
            async { Ok(crate::daemon::auto_update::RecurringMutationOutcome::GenerationRetired) },
        )
        .await
        .expect("reload retirement is a clean skipped pass");
        assert_eq!(result.components.len(), 1);
        assert_eq!(
            result.components[0].status,
            crate::wal::payloads_u04::ComponentStatus::SkippedByGate
        );
        assert_eq!(result.components[0].note, ACCEPTED_GENERATION_RETIRED);

        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn terminalized_leaf_failure_retries_on_the_next_lane_cadence() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("retryable-leaf-000001.wal");
        let (writer, writer_join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let controller = crate::config::reload::ReloadController::new(
            crate::config::FreedomConfig::default(),
            wal_dir.path().join("freedom.yaml"),
        );
        let snapshot = controller.accepted_snapshot();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::unbounded_channel();
        let executor: LaneExecutor = {
            let attempts = Arc::clone(&attempts);
            let writer = writer.clone();
            Arc::new(move |lane, snapshot, _gate| {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                let writer = writer.clone();
                let observed_tx = observed_tx.clone();
                Box::pin(async move {
                    let outcome = async move {
                        if attempt == 0 {
                            Err(
                                "neoth-self staging leaf failed: updater leaf effect failed \
                                 (transport; digest deadbeef)"
                                    .to_string(),
                            )
                        } else {
                            Ok(crate::daemon::auto_update::RecurringMutationOutcome::Completed)
                        }
                    };
                    let result = run_mutation_pass_at(
                        UpdaterPassIdentity::new(lane.audit_lane(), snapshot.epoch()),
                        UpdaterTaskKind::NeothSelf,
                        "self_stage",
                        "1.0.0",
                        "unused",
                        &writer,
                        outcome,
                    )
                    .await?;
                    observed_tx
                        .send((attempt, result.components[0].status))
                        .map_err(|_| "test observation receiver closed".to_string())?;
                    Ok(())
                })
            })
        };
        let (cancel, _) = tokio::sync::watch::channel(false);
        let loop_task = tokio::spawn(run_lane_loop(
            LaneCadence {
                schedule: LaneSchedule {
                    lane: RecurringUpdateLane::SelfStage,
                    interval_secs: 60,
                },
                next_due: tokio::time::Instant::now(),
            },
            snapshot,
            executor,
            Arc::new(UpdaterAuditLocks::default()),
            cancel.subscribe(),
        ));

        assert_eq!(
            observed_rx.recv().await.unwrap(),
            (0, crate::wal::payloads_u04::ComponentStatus::Failed),
            "the transient leaf failure must first become a durable Failed result"
        );
        assert_eq!(
            observed_rx.recv().await.unwrap(),
            (1, crate::wal::payloads_u04::ComponentStatus::UpToDate),
            "the same lane must remain alive and execute its next cadence"
        );
        cancel.send_replace(true);
        let (lane, cadence) = loop_task.await.unwrap().unwrap();
        assert_eq!(lane, RecurringUpdateLane::SelfStage);
        assert!(
            cadence.next_due > tokio::time::Instant::now(),
            "the successful retry must advance the cadence"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        drop(writer);
        writer_join.await.unwrap();
        let bytes = std::fs::read(seg).unwrap();
        let mut offset = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut terminal_statuses = Vec::new();
        while offset < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[offset..]).unwrap();
            if frame.header.event_type == EVENT_TYPE_UPDATER_TASK_RESULT {
                let result: UpdaterTaskResultPayload =
                    serde_json::from_slice(frame.payload).unwrap();
                terminal_statuses.push(result.components[0].status);
            }
            offset += frame.header.total_len as usize;
        }
        assert_eq!(
            terminal_statuses,
            [
                crate::wal::payloads_u04::ComponentStatus::Failed,
                crate::wal::payloads_u04::ComponentStatus::UpToDate,
            ],
            "both cadences must retain their own terminal audit result"
        );
    }

    #[tokio::test]
    async fn terminalized_authority_or_audit_failure_still_closes_the_lane() {
        for error in [
            "mandatory updater leaf result audit failed",
            "updater leaf permit/request mismatch",
            "updater leaf effect failed (panic; digest abc)",
            "mandatory staged self-update WAL append failed",
        ] {
            let wal_dir = tempfile::tempdir().unwrap();
            let seg = wal_dir.path().join("fatal-000001.wal");
            let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
            let result = run_mutation_pass(
                UpdaterTaskKind::NeothSelf,
                "self_stage",
                "1.0.0",
                "unused",
                &writer,
                async { Err(error.to_string()) },
            )
            .await;
            assert_eq!(result.unwrap_err(), error);
            drop(writer);
            join.await.unwrap();
        }
    }

    #[tokio::test]
    async fn builder_error_and_panic_each_emit_terminal_failed_result() {
        for (name, panic_builder) in [("error", false), ("panic", true)] {
            let wal_dir = tempfile::tempdir().unwrap();
            let seg = wal_dir.path().join(format!("{name}-000001.wal"));
            let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
            let result =
                run_probe_pass_with_builder(UpdaterTaskKind::SkillPlugin, &writer, || async move {
                    if panic_builder {
                        panic!("contained test panic");
                    }
                    Err("contained builder error".to_string())
                })
                .await
                .unwrap();
            assert_eq!(result.components.len(), 1);
            assert_eq!(
                result.components[0].status,
                crate::wal::payloads_u04::ComponentStatus::Failed
            );
            assert!(result.components[0].note.contains(if panic_builder {
                "panicked"
            } else {
                "builder error"
            }));
            drop(writer);
            join.await.unwrap();

            let bytes = tokio::fs::read(&seg).await.unwrap();
            let first = crate::wal::frame::decode_frame(
                &bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..],
            )
            .unwrap();
            let second_offset =
                crate::wal::segment_header::SEGMENT_HEADER_LEN + first.header.total_len as usize;
            let second = crate::wal::frame::decode_frame(&bytes[second_offset..]).unwrap();
            assert_eq!(first.header.event_type, EVENT_TYPE_UPDATER_TASK_FIRED);
            assert_eq!(second.header.event_type, EVENT_TYPE_UPDATER_TASK_RESULT);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_result_append_failure_closes_the_supervisor() {
        use crate::permissions::AutonomyLevel;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("freedom.yaml");
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = AutonomyLevel::Standard;
        config.updater.enabled = true;
        config.updater.interval_secs = 3_600;
        config.auto_update.enabled = false;
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config,
            config_path,
        ));

        let segment = dir.path().join("terminal-append-failure-000001.wal");
        let (writer, writer_join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let writer_join = Arc::new(tokio::sync::Mutex::new(Some(writer_join)));
        let executor: LaneExecutor = {
            let writer = writer.clone();
            let writer_join = Arc::clone(&writer_join);
            Arc::new(move |lane, _snapshot, _gate| {
                if lane != RecurringUpdateLane::CliVersionProbe {
                    return Box::pin(async { Ok(()) });
                }
                let writer = writer.clone();
                let writer_join = Arc::clone(&writer_join);
                Box::pin(async move {
                    run_probe_pass_with_builder(
                        UpdaterTaskKind::CliVersions,
                        &writer,
                        || async move {
                            // The builder runs only after FIRED has a durable
                            // ACK. Closing the writer here deterministically
                            // makes only the terminal RESULT append fail.
                            let join = writer_join
                                .lock()
                                .await
                                .take()
                                .expect("test WAL writer must still be live");
                            join.abort();
                            let _ = join.await;
                            Ok(denied_probe_specs(
                                UpdaterTaskKind::CliVersions,
                                UNAUDITED_RECURRING_EGRESS_DENIED,
                            ))
                        },
                    )
                    .await?;
                    Ok(())
                })
            })
        };
        let mut handle = spawn_updater_supervisor_with_executor(Arc::clone(&controller), executor);

        let failure = tokio::time::timeout(Duration::from_secs(2), handle.wait_for_failure())
            .await
            .expect("supervisor continued after a missing terminal RESULT");
        assert!(
            failure.contains("wal append result") && failure.contains("cli_version_probe"),
            "unexpected fail-closed reason: {failure}"
        );
        handle.shutdown().await;
        drop(writer);

        let bytes = tokio::fs::read(&segment).await.unwrap();
        let fired = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(fired.header.event_type, EVENT_TYPE_UPDATER_TASK_FIRED);
        assert_eq!(
            SEGMENT_HEADER_LEN + fired.header.total_len as usize,
            bytes.len(),
            "fault injection must leave exactly the durable FIRED whose missing RESULT closed serve"
        );
    }

    #[tokio::test]
    async fn blocked_mutation_lane_emits_typed_fired_and_terminal_result() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("mutation-000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let controller = crate::config::reload::ReloadController::new(
            crate::config::FreedomConfig::default(),
            dir.path().join("freedom.yaml"),
        );
        run_production_lane_once(
            RecurringUpdateLane::CliAutoApply,
            controller.accepted_snapshot(),
            dir.path().to_path_buf(),
            writer.clone(),
            recurring_egress_gate(RecurringUpdateLane::CliAutoApply),
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let first = crate::wal::frame::decode_frame(
            &bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..],
        )
        .unwrap();
        let second_offset =
            crate::wal::segment_header::SEGMENT_HEADER_LEN + first.header.total_len as usize;
        let second = crate::wal::frame::decode_frame(&bytes[second_offset..]).unwrap();
        assert_eq!(first.header.event_type, EVENT_TYPE_UPDATER_TASK_FIRED);
        assert_eq!(second.header.event_type, EVENT_TYPE_UPDATER_TASK_RESULT);
        let result: UpdaterTaskResultPayload = serde_json::from_slice(second.payload).unwrap();
        assert_eq!(result.task_kind, UpdaterTaskKind::CliVersions);
        assert_eq!(result.components.len(), 1);
        assert_eq!(result.components[0].name, "cli_auto_apply");
        assert_eq!(
            result.components[0].status,
            crate::wal::payloads_u04::ComponentStatus::SkippedByGate
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_kind_lanes_cannot_interleave_fired_result_pairs() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("serialized-pairs-000001.wal");
        let (writer, writer_join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        let locks = Arc::new(UpdaterAuditLocks::default());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let (first_entered_tx, first_entered_rx) = tokio::sync::oneshot::channel();

        let first = {
            let locks = Arc::clone(&locks);
            let writer = writer.clone();
            let release_first = Arc::clone(&release_first);
            tokio::spawn(async move {
                let _pair = locks.lock(UpdaterTaskKind::CliVersions).await;
                run_probe_pass_with_builder(UpdaterTaskKind::CliVersions, &writer, || async move {
                    let _ = first_entered_tx.send(());
                    release_first.notified().await;
                    Ok(vec![spec("first", "1.0", Ok("1.0"))])
                })
                .await
            })
        };
        first_entered_rx.await.unwrap();

        let (second_entered_tx, mut second_entered_rx) = tokio::sync::oneshot::channel();
        let second = {
            let locks = Arc::clone(&locks);
            let writer = writer.clone();
            tokio::spawn(async move {
                let _pair = locks.lock(UpdaterTaskKind::CliVersions).await;
                let _ = second_entered_tx.send(());
                run_probe_pass_with_builder(UpdaterTaskKind::CliVersions, &writer, || async {
                    Ok(vec![spec("second", "1.0", Ok("1.0"))])
                })
                .await
            })
        };

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            matches!(
                second_entered_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "second same-kind lane entered before the first terminal RESULT"
        );
        release_first.notify_one();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        assert_eq!(second_entered_rx.try_recv(), Ok(()));
        drop(writer);
        writer_join.await.unwrap();

        let bytes = tokio::fs::read(&seg).await.unwrap();
        let mut offset = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut event_types = Vec::new();
        while offset < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[offset..]).unwrap();
            event_types.push(frame.header.event_type);
            offset += frame.header.total_len as usize;
        }
        assert_eq!(
            event_types,
            [
                EVENT_TYPE_UPDATER_TASK_FIRED,
                EVENT_TYPE_UPDATER_TASK_RESULT,
                EVENT_TYPE_UPDATER_TASK_FIRED,
                EVENT_TYPE_UPDATER_TASK_RESULT,
                crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
            ],
            "same-kind audit pairs must remain contiguous before the shutdown HMAC marker"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_same_kind_waiter_never_admits_revoked_generation_work() {
        let dir = tempfile::tempdir().unwrap();
        let controller = crate::config::reload::ReloadController::new(
            crate::config::FreedomConfig::default(),
            dir.path().join("freedom.yaml"),
        );
        let snapshot = controller.accepted_snapshot();
        let locks = Arc::new(UpdaterAuditLocks::default());
        let (cancel, _) = tokio::sync::watch::channel(false);
        let release_first = Arc::new(tokio::sync::Notify::new());
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let release_for_executor = Arc::clone(&release_first);
        let executor: LaneExecutor = Arc::new(move |lane, _snapshot, _gate| {
            let release_first = Arc::clone(&release_for_executor);
            let events = events_tx.clone();
            Box::pin(async move {
                events.send(("started", lane)).unwrap();
                if lane == RecurringUpdateLane::CliVersionProbe {
                    release_first.notified().await;
                }
                events.send(("finished", lane)).unwrap();
                Ok(())
            })
        });
        let due = tokio::time::Instant::now();

        let first = tokio::spawn(run_lane_loop(
            LaneCadence {
                schedule: LaneSchedule {
                    lane: RecurringUpdateLane::CliVersionProbe,
                    interval_secs: 3_600,
                },
                next_due: due,
            },
            Arc::clone(&snapshot),
            Arc::clone(&executor),
            Arc::clone(&locks),
            cancel.subscribe(),
        ));
        assert_eq!(
            events_rx.recv().await.unwrap(),
            ("started", RecurringUpdateLane::CliVersionProbe)
        );

        let second = tokio::spawn(run_lane_loop(
            LaneCadence {
                schedule: LaneSchedule {
                    lane: RecurringUpdateLane::CliAutoApply,
                    interval_secs: 3_600,
                },
                next_due: due,
            },
            snapshot,
            executor,
            locks,
            cancel.subscribe(),
        ));
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            events_rx.try_recv().is_err(),
            "same-kind waiter executed before audit admission"
        );

        cancel.send_replace(true);
        let (second_lane, second_cadence) = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("cancelled lock waiter did not retire")
            .unwrap()
            .unwrap();
        assert_eq!(second_lane, RecurringUpdateLane::CliAutoApply);
        assert_eq!(
            second_cadence.next_due, due,
            "unadmitted work must retain its due deadline for policy-safe replacement"
        );
        assert!(
            events_rx.try_recv().is_err(),
            "revoked old-generation waiter emitted work after cancellation"
        );

        release_first.notify_one();
        let (first_lane, first_cadence) = first.await.unwrap().unwrap();
        assert_eq!(first_lane, RecurringUpdateLane::CliVersionProbe);
        assert!(
            first_cadence.next_due > due,
            "admitted work must advance cadence after its terminal result"
        );
        assert_eq!(
            events_rx.recv().await.unwrap(),
            ("finished", RecurringUpdateLane::CliVersionProbe)
        );
        assert!(
            events_rx.try_recv().is_err(),
            "only the admitted lane may execute in the retired generation"
        );
    }

    fn lane_set(
        config: &crate::config::FreedomConfig,
    ) -> std::collections::HashSet<RecurringUpdateLane> {
        effective_lane_schedules(config)
            .into_iter()
            .map(|schedule| schedule.lane)
            .collect()
    }

    #[test]
    fn effective_lanes_fail_closed_on_contradictory_update_switches() {
        use crate::permissions::AutonomyLevel;

        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = AutonomyLevel::Elevated;
        config.updater.enabled = true;
        config.updater.interval_secs = 12_345;
        config.auto_update.enabled = false;
        config.auto_update.auto_apply = true;
        config.auto_update.check_interval_secs = 54_321;

        let schedules = effective_lane_schedules(&config);
        let lanes = lane_set(&config);
        assert_eq!(schedules.len(), lanes.len(), "one owner per lane");
        assert_eq!(
            lanes,
            [
                RecurringUpdateLane::CliVersionProbe,
                RecurringUpdateLane::SkillPluginProbe,
            ]
            .into_iter()
            .collect(),
            "auto_update disabled must suppress self probe and both mutating lanes"
        );

        config.auto_update.enabled = true;
        config.auto_update.auto_apply = false;
        assert_eq!(
            lane_set(&config),
            [
                RecurringUpdateLane::CliVersionProbe,
                RecurringUpdateLane::SkillPluginProbe,
                RecurringUpdateLane::NeothSelfProbe,
            ]
            .into_iter()
            .collect(),
            "check-only config must not retain a mutating lane"
        );

        config.auto_update.auto_apply = true;
        assert_eq!(lane_set(&config).len(), 5);
        config.updater.enabled = false;
        assert!(lane_set(&config).is_empty(), "global updater switch wins");

        config.updater.enabled = true;
        for autonomy in [AutonomyLevel::Strict, AutonomyLevel::Custom] {
            config.autonomy = autonomy;
            assert!(
                lane_set(&config).is_empty(),
                "{autonomy:?} autonomy cannot own standing updater work"
            );
        }
    }

    #[test]
    fn recurring_network_gate_keeps_unbounded_self_leaves_fail_closed() {
        for lane in [
            RecurringUpdateLane::NeothSelfProbe,
            RecurringUpdateLane::SelfStage,
        ] {
            match recurring_egress_gate(lane) {
                GateDecision::Deny { reason } => {
                    assert_eq!(reason, UNBOUNDED_RECURRING_LIFECYCLE_DENIED);
                    assert!(reason.contains("kill/reap"));
                }
                GateDecision::Allow => {
                    panic!("{lane:?} must remain denied until R3-18B is complete")
                }
            }
        }
        for lane in [
            RecurringUpdateLane::CliVersionProbe,
            RecurringUpdateLane::SkillPluginProbe,
            RecurringUpdateLane::CliAutoApply,
        ] {
            match recurring_egress_gate(lane) {
                GateDecision::Deny { reason } => {
                    assert_eq!(reason, UNAUDITED_RECURRING_EGRESS_DENIED);
                    assert!(reason.contains("intent/result WAL"));
                }
                GateDecision::Allow => {
                    panic!("{lane:?} must remain denied until all concrete leaves are wired")
                }
            }
        }
    }

    #[test]
    fn denied_probe_rows_require_no_inventory_and_are_all_gate_skips() {
        for (kind, expected_rows) in [
            (UpdaterTaskKind::NeothSelf, 1usize),
            (
                UpdaterTaskKind::CliVersions,
                crate::updater::Component::ALL.len(),
            ),
            (UpdaterTaskKind::SkillPlugin, 1usize),
        ] {
            let specs = denied_probe_specs(kind, UNAUDITED_RECURRING_EGRESS_DENIED);
            assert_eq!(specs.len(), expected_rows);
            assert!(specs.iter().all(|spec| {
                matches!(spec.gate_decision, GateDecision::Deny { .. })
                    && spec
                        .latest_version
                        .as_ref()
                        .is_err_and(|error| error == UNAUDITED_RECURRING_EGRESS_DENIED)
            }));
        }
    }

    fn write_reload(
        path: &std::path::Path,
        controller: &crate::config::reload::ReloadController,
        config: &crate::config::FreedomConfig,
    ) {
        std::fs::write(path, serde_yaml::to_string(config).unwrap()).unwrap();
        assert!(matches!(
            controller.try_reload().unwrap(),
            crate::config::reload::ReloadResult::Reloaded { .. }
        ));
    }

    #[derive(Debug, PartialEq, Eq)]
    enum WorkEvent {
        Started { epoch: u64, deny_unknown: bool },
        Finished { epoch: u64 },
    }

    async fn next_work_event(
        events: &mut tokio::sync::mpsc::UnboundedReceiver<WorkEvent>,
    ) -> WorkEvent {
        tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("timed out waiting for fake updater work event")
            .expect("fake updater event stream closed")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_owner_signals_and_drains_admitted_work() {
        use crate::permissions::AutonomyLevel;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("freedom.yaml");
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = AutonomyLevel::Standard;
        config.updater.enabled = true;
        config.updater.interval_secs = 3_600;
        config.auto_update.enabled = false;
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config,
            config_path,
        ));

        let release = Arc::new(std::sync::Barrier::new(2));
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let executor: LaneExecutor = {
            let release = Arc::clone(&release);
            Arc::new(move |lane, snapshot, _gate| {
                if lane != RecurringUpdateLane::CliVersionProbe {
                    return Box::pin(async { Ok(()) });
                }
                let release = Arc::clone(&release);
                let events = events_tx.clone();
                Box::pin(async move {
                    let epoch = snapshot.epoch();
                    events
                        .send(WorkEvent::Started {
                            epoch,
                            deny_unknown: false,
                        })
                        .unwrap();
                    tokio::task::spawn_blocking(move || release.wait())
                        .await
                        .map_err(|error| error.to_string())?;
                    events.send(WorkEvent::Finished { epoch }).unwrap();
                    Ok(())
                })
            })
        };

        let handle = spawn_updater_supervisor_with_executor(controller, executor);
        assert!(matches!(
            next_work_event(&mut events_rx).await,
            WorkEvent::Started { epoch: 0, .. }
        ));

        drop(handle);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), events_rx.recv())
                .await
                .is_err(),
            "owner drop must signal cancellation without aborting admitted work"
        );

        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();
        assert_eq!(
            next_work_event(&mut events_rx).await,
            WorkEvent::Finished { epoch: 0 },
            "the detached supervisor must drain the admitted leaf to completion"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_joins_real_blocking_work_before_replacement() {
        use crate::config::EgressMode;
        use crate::permissions::AutonomyLevel;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("freedom.yaml");
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = AutonomyLevel::Standard;
        config.updater.enabled = true;
        config.updater.interval_secs = 3_600;
        config.auto_update.enabled = false;
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config.clone(),
            config_path.clone(),
        ));

        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let release_epoch_zero = Arc::new(std::sync::Barrier::new(2));
        let wal_path = dir.path().join("reload-blocking-000001.wal");
        let (writer, writer_join) = crate::wal::writer::spawn(wal_path.clone()).unwrap();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let executor: LaneExecutor = {
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            let release_epoch_zero = Arc::clone(&release_epoch_zero);
            let writer = writer.clone();
            Arc::new(move |lane, snapshot, gate| {
                assert!(matches!(gate, GateDecision::Deny { .. }));
                if lane != RecurringUpdateLane::CliVersionProbe {
                    return Box::pin(async { Ok(()) });
                }
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                let release_epoch_zero = Arc::clone(&release_epoch_zero);
                let events = events_tx.clone();
                let writer = writer.clone();
                Box::pin(async move {
                    let epoch = snapshot.epoch();
                    let deny_unknown =
                        snapshot.config().security.egress.mode == EgressMode::DenyUnknown;
                    run_probe_pass_with_builder(
                        UpdaterTaskKind::CliVersions,
                        &writer,
                        || async move {
                            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                            max_active.fetch_max(current, Ordering::SeqCst);
                            events
                                .send(WorkEvent::Started {
                                    epoch,
                                    deny_unknown,
                                })
                                .unwrap();
                            if epoch == 0 {
                                // Model a real synchronous probe owned through
                                // an awaited JoinHandle. Reload must not drop
                                // that handle (which would detach the closure).
                                tokio::task::spawn_blocking(move || release_epoch_zero.wait())
                                    .await
                                    .map_err(|error| error.to_string())?;
                            }
                            active.fetch_sub(1, Ordering::SeqCst);
                            events.send(WorkEvent::Finished { epoch }).unwrap();
                            Ok(denied_probe_specs(
                                UpdaterTaskKind::CliVersions,
                                UNAUDITED_RECURRING_EGRESS_DENIED,
                            ))
                        },
                    )
                    .await?;
                    Ok(())
                })
            })
        };
        let handle = spawn_updater_supervisor_with_executor(Arc::clone(&controller), executor);

        assert_eq!(
            next_work_event(&mut events_rx).await,
            WorkEvent::Started {
                epoch: 0,
                deny_unknown: false
            }
        );

        // Tightening security cancels + joins generation 0 before generation 1
        // can start the same lane.
        config.security.egress.mode = EgressMode::DenyUnknown;
        write_reload(&config_path, &controller, &config);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), events_rx.recv())
                .await
                .is_err(),
            "replacement must wait while prior generation is still blocking"
        );
        release_epoch_zero.wait();
        assert_eq!(
            next_work_event(&mut events_rx).await,
            WorkEvent::Finished { epoch: 0 }
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), events_rx.recv())
                .await
                .is_err(),
            "joined pass must advance cadence instead of duplicating immediately"
        );

        handle.shutdown().await;
        drop(writer);
        writer_join.await.unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(
            max_active.load(Ordering::SeqCst),
            1,
            "old and new accepted generations must never own one lane concurrently"
        );

        let bytes = tokio::fs::read(&wal_path).await.unwrap();
        let first = crate::wal::frame::decode_frame(
            &bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..],
        )
        .unwrap();
        let second_offset =
            crate::wal::segment_header::SEGMENT_HEADER_LEN + first.header.total_len as usize;
        let second = crate::wal::frame::decode_frame(&bytes[second_offset..]).unwrap();
        let marker_offset = second_offset + second.header.total_len as usize;
        let marker = crate::wal::frame::decode_frame(&bytes[marker_offset..]).unwrap();
        assert_eq!(first.header.event_type, EVENT_TYPE_UPDATER_TASK_FIRED);
        assert_eq!(second.header.event_type, EVENT_TYPE_UPDATER_TASK_RESULT);
        assert_eq!(
            marker.header.event_type,
            crate::wal::events::EVENT_TYPE_COMPACTION_MARKER
        );
        assert_eq!(
            marker_offset + marker.header.total_len as usize,
            bytes.len(),
            "reload during admitted work leaves one terminal pair, no duplicate pass, and a shutdown HMAC marker"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reloads_preserve_absolute_cadence_and_do_not_starve_mutations() {
        use crate::permissions::AutonomyLevel;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("freedom.yaml");
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = AutonomyLevel::Elevated;
        config.updater.enabled = true;
        config.updater.interval_secs = 60;
        config.auto_update.enabled = true;
        config.auto_update.auto_apply = true;
        config.auto_update.check_interval_secs = 60;
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config.clone(),
            config_path.clone(),
        ));

        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let executor: LaneExecutor = Arc::new(move |lane, snapshot, gate| {
            assert_eq!(
                gate,
                recurring_egress_gate(lane),
                "executor received a gate that does not match the concrete lane"
            );
            let events = events_tx.clone();
            Box::pin(async move {
                events.send((lane, snapshot.epoch())).unwrap();
                Ok(())
            })
        });
        let handle = spawn_updater_supervisor_with_executor(Arc::clone(&controller), executor);

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let mut counts = std::collections::HashMap::<(RecurringUpdateLane, u64), usize>::new();
        while let Ok(event) = events_rx.try_recv() {
            *counts.entry(event).or_default() += 1;
        }
        assert_eq!(
            counts,
            [
                ((RecurringUpdateLane::NeothSelfProbe, 0), 1),
                ((RecurringUpdateLane::CliVersionProbe, 0), 1),
                ((RecurringUpdateLane::SkillPluginProbe, 0), 1),
            ]
            .into_iter()
            .collect(),
            "only the three probes run once at first enable"
        );

        // Five unrelated accepted reloads must neither duplicate immediate
        // probes nor reset the mutating lanes' original t=60 deadline.
        for reload_index in 1..=5 {
            tokio::time::advance(Duration::from_secs(10)).await;
            config.monitor.interval_secs += 1;
            write_reload(&config_path, &controller, &config);
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            assert!(
                events_rx.try_recv().is_err(),
                "reload {reload_index} created an early or duplicate pass"
            );
        }

        tokio::time::advance(Duration::from_secs(10)).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let mut at_deadline = std::collections::HashMap::new();
        while let Ok((lane, epoch)) = events_rx.try_recv() {
            assert_eq!(epoch, 5, "pass must bind the latest accepted snapshot");
            *at_deadline.entry(lane).or_insert(0usize) += 1;
        }
        assert_eq!(
            at_deadline,
            [
                (RecurringUpdateLane::NeothSelfProbe, 1),
                (RecurringUpdateLane::CliVersionProbe, 1),
                (RecurringUpdateLane::SkillPluginProbe, 1),
                (RecurringUpdateLane::CliAutoApply, 1),
                (RecurringUpdateLane::SelfStage, 1),
            ]
            .into_iter()
            .collect(),
            "every lane fires exactly once at its preserved absolute deadline"
        );

        handle.shutdown().await;
    }
}
