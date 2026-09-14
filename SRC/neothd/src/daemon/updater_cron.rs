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
//! - NEOTH self-probe has request-bound leaf authority, one inherited pass
//!   deadline, cooperative HTTP cancellation, and retained deadline ownership.
//!   Self-stage remains explicitly denied because its blocking preparation and
//!   publication work cannot yet be cooperatively cancelled.
//! - CLI version probes, skill/plugin probes and CLI auto-apply remain denied
//!   until their process, registry, Git and install leaves enforce the same
//!   exact authority contract. In particular, the binary-version child has no
//!   timeout; npm has a local timeout but no owned descendant process tree;
//!   Git kills/reaps its direct child but not a descendant tree; and installer
//!   leaves have no shared pass deadline/cancellation token.
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

use crate::updater::budget::{UpdaterDeadlinePhase, UpdaterRunClock, UpdaterRunLimits};
#[cfg(test)]
use crate::updater::pipeline::ComponentSpec;
use crate::updater::pipeline::run_updater_pass;
use crate::wal::events::{EVENT_TYPE_UPDATER_TASK_FIRED, EVENT_TYPE_UPDATER_TASK_RESULT};
use crate::wal::payloads_u04::{
    ComponentOutcome, UPDATER_LEAF_RECEIPT_BINDING_SCHEMA_VERSION, UpdaterLeafReceiptBinding,
    UpdaterPassIdentity, UpdaterPassLane, UpdaterTaskFiredPayload, UpdaterTaskKind,
    UpdaterTaskResultPayload, UpdaterTerminalOutcome, updater_fired_receipt_sha256,
};
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};
use futures_util::FutureExt;
use sha2::{Digest as _, Sha256};

/// Legacy recurring lanes are denied until their concrete network/process
/// leaves consume request-bound authority. Manual, operator-initiated updater
/// commands are unaffected.
pub const UNAUDITED_RECURRING_EGRESS_DENIED: &str = "recurring updater network probe blocked: request-bound autonomy and mandatory intent/result WAL are not wired at every concrete transport/process leaf; binary probe lacks a timeout, npm/Git do not own descendant process trees, and installers lack one inherited deadline/cancellation token";
pub const UNBOUNDED_RECURRING_LIFECYCLE_DENIED: &str = "recurring NEOTH self-stage blocked: HTTP has leaf-local timeouts but no inherited absolute pass deadline covers blocking stage prepare/publish, terminal WAL acknowledgement, or generation quiescence; spawn_blocking work cannot be cooperatively cancelled";
const REQUEST_BOUND_POLICY_REFUSED: &str =
    "accepted updater policy refused this exact recurring leaf";
const ACCEPTED_GENERATION_RETIRED: &str =
    "accepted updater generation retired before this recurring leaf started";
const ACCEPTED_UPDATER_POLICY_DOMAIN: &[u8] = b"neoth/updater-accepted-policy/v1\0";

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

fn authorized_probe_failure_disposition(
    error: anyhow::Error,
    cancellation_requested: bool,
) -> (TerminalizedPassFailure, UpdaterTerminalOutcome) {
    match error.downcast_ref::<crate::updater::authority::UpdaterLeafExecutionError>() {
        Some(crate::updater::authority::UpdaterLeafExecutionError::Effect {
            kind: "cancelled",
            ..
        }) if cancellation_requested => (
            TerminalizedPassFailure::RetryNextCadence(format!(
                "authorized self-update probe cancelled by its owning generation: {error}"
            )),
            UpdaterTerminalOutcome::Cancelled,
        ),
        Some(crate::updater::authority::UpdaterLeafExecutionError::Effect {
            kind: "panic" | "cancelled" | "policy",
            ..
        }) => (
            TerminalizedPassFailure::CloseSupervisor(format!(
                "authorized self-update probe failed: {error}"
            )),
            UpdaterTerminalOutcome::Failed,
        ),
        Some(crate::updater::authority::UpdaterLeafExecutionError::Effect {
            kind: "timeout",
            ..
        }) => (
            TerminalizedPassFailure::RetryNextCadence(format!(
                "authorized self-update probe failed: {error}"
            )),
            UpdaterTerminalOutcome::TimedOut,
        ),
        Some(crate::updater::authority::UpdaterLeafExecutionError::Effect { .. }) | None => (
            TerminalizedPassFailure::RetryNextCadence(format!(
                "authorized self-update probe failed: {error}"
            )),
            UpdaterTerminalOutcome::Failed,
        ),
        Some(_) => (
            TerminalizedPassFailure::CloseSupervisor(format!(
                "authorized self-update probe failed: {error}"
            )),
            UpdaterTerminalOutcome::Failed,
        ),
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
        // Wave 25 admits only the concrete HTTP self-probe.  It now consumes
        // request-bound authority, the pass clock/control, and ordered leaf
        // receipts; it does not stage or publish an update.
        RecurringUpdateLane::NeothSelfProbe => crate::updater::pipeline::GateDecision::Allow,
        RecurringUpdateLane::SelfStage => crate::updater::pipeline::GateDecision::Deny {
            reason: UNBOUNDED_RECURRING_LIFECYCLE_DENIED.to_string(),
        },
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
/// One admitted pass owns its cancellation edge and the single run clock which
/// bound its durable leaf requests.  A deadline is observable only after
/// admission, so denied lanes cannot manufacture a lifecycle owner.
#[derive(Clone)]
pub(crate) struct UpdaterPassControl {
    cancelled: tokio::sync::watch::Sender<bool>,
    clock: Arc<std::sync::Mutex<Option<UpdaterRunClock>>>,
    // The real writer clone remains with this control from admission until a
    // joined terminal result, including an escalated deadline drain.
    wal_root_guard: Option<WalWriterHandle>,
}

impl UpdaterPassControl {
    fn new(wal_root_guard: Option<WalWriterHandle>) -> Self {
        let (cancelled, _) = tokio::sync::watch::channel(false);
        Self {
            cancelled,
            clock: Arc::new(std::sync::Mutex::new(None)),
            wal_root_guard,
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.send_replace(true);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }

    pub(crate) fn admit(&self, clock: UpdaterRunClock) -> anyhow::Result<()> {
        let mut admitted = self
            .clock
            .lock()
            .map_err(|_| anyhow::anyhow!("updater pass admission clock is poisoned"))?;
        anyhow::ensure!(admitted.is_none(), "updater pass clock was admitted twice");
        *admitted = Some(clock);
        Ok(())
    }

    pub(crate) fn deadline(&self, phase: UpdaterDeadlinePhase) -> Option<tokio::time::Instant> {
        let clock = self
            .clock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clock.as_ref().map(|clock| clock.deadline(phase))
    }

    pub(crate) async fn cancelled(&self) {
        let mut cancelled = self.cancelled.subscribe();
        if *cancelled.borrow() {
            return;
        }
        let _ = cancelled.changed().await;
    }
}

/// A deadline-expired admitted pass whose task, cancellation control, and
/// writer root are still owned by the daemon boundary.  It must be joined
/// before any writer-close or clean shutdown continuation.
pub(crate) struct RetainedUpdaterPass {
    lane: RecurringUpdateLane,
    control: UpdaterPassControl,
    pass: tokio::task::JoinHandle<Result<(), String>>,
}

impl RetainedUpdaterPass {
    pub(crate) async fn join(self) -> Result<(), String> {
        let Self {
            lane,
            control,
            pass,
        } = self;
        // Keep both the cancellation control and its WAL root guard alive
        // until the child has acknowledged its terminal state.
        let _root_guard = &control.wal_root_guard;
        match pass.await {
            Ok(result) => result.map_err(|error| {
                format!(
                    "retained updater pass `{}` completed late: {error}",
                    lane.as_str()
                )
            }),
            Err(error) => Err(format!(
                "retained updater pass `{}` join failed: {error}",
                lane.as_str()
            )),
        }
    }
}

pub(crate) enum UpdaterSupervisorFailure {
    Failed(String),
    DeadlineExceeded(Vec<RetainedUpdaterPass>),
}

enum UpdaterSupervisorExit {
    Clean,
    Failed(UpdaterSupervisorFailure),
}

impl std::fmt::Display for UpdaterSupervisorFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(reason) => formatter.write_str(reason),
            Self::DeadlineExceeded(passes) => write!(
                formatter,
                "fatal updater operation deadline exceeded for {} retained pass(es); late join is required",
                passes.len()
            ),
        }
    }
}

type LaneExecutor = Arc<
    dyn Fn(
            RecurringUpdateLane,
            Arc<crate::config::reload::AcceptedConfigSnapshot>,
            crate::updater::pipeline::GateDecision,
            UpdaterPassControl,
        ) -> LaneFuture
        + Send
        + Sync
        + 'static,
>;

/// Sole daemon owner for all recurring update work.
pub(crate) struct UpdaterSupervisorHandle {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<UpdaterSupervisorExit>>,
    // Notification only: ownership is always retained in `join`'s output.
    failure: Option<tokio::sync::oneshot::Receiver<()>>,
    failure_notified: bool,
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
    pub(crate) async fn wait_for_failure(&mut self) -> UpdaterSupervisorFailure {
        if !self.failure_notified {
            let notification = {
                let receiver = self
                    .failure
                    .as_mut()
                    .expect("live updater supervisor failure receiver");
                receiver.await
            };
            match notification {
                Ok(()) => {
                    // There is no await between receipt and this state write.
                    // A select cancellation during the following join can
                    // therefore retry without awaiting a consumed oneshot.
                    self.failure_notified = true;
                    let _ = self.failure.take();
                }
                Err(_) => {
                    return UpdaterSupervisorFailure::Failed(
                        "updater supervisor failure notification closed".to_string(),
                    );
                }
            }
        }
        {
            // `wait_for_failure` is polled inside Serve's `select!`.
            // Await the owned handle by mutable borrow so another ready
            // branch may cancel this future without moving/detaching it.
            let completion = {
                let join = self.join.as_mut().expect("live updater supervisor join");
                join.await
            };
            let _ = self.join.take();
            match completion {
                Ok(UpdaterSupervisorExit::Failed(reason)) => reason,
                Ok(UpdaterSupervisorExit::Clean) => UpdaterSupervisorFailure::Failed(
                    "updater supervisor ended cleanly without a shutdown request".to_string(),
                ),
                Err(error) => UpdaterSupervisorFailure::Failed(format!(
                    "updater supervisor task panicked or was aborted: {error}"
                )),
            }
        }
    }

    /// Stop the current generation and return any deadline-expired pass still
    /// owned by its supervisor.  This is finite: the caller, not this method,
    /// must hold the returned ownership in its fail-stopped late-join branch.
    pub(crate) async fn shutdown(mut self) -> Option<UpdaterSupervisorFailure> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take() {
            match join.await {
                Ok(UpdaterSupervisorExit::Clean) => return None,
                Ok(UpdaterSupervisorExit::Failed(reason)) => return Some(reason),
                Err(error) => {
                    return Some(UpdaterSupervisorFailure::Failed(format!(
                        "updater supervisor join failed during shutdown: {error}"
                    )));
                }
            }
        }
        None
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
    let wal_root_guard = writer.clone();
    let executor: LaneExecutor = Arc::new(move |lane, snapshot, gate, control| {
        let home = home.clone();
        let writer = writer.clone();
        Box::pin(run_production_lane_once(
            lane, snapshot, home, writer, gate, control,
        ))
    });
    spawn_updater_supervisor_with_executor(reload_controller, executor, Some(wal_root_guard))
}

fn spawn_updater_supervisor_with_executor(
    reload_controller: Arc<crate::config::reload::ReloadController>,
    executor: LaneExecutor,
    wal_root_guard: Option<WalWriterHandle>,
) -> UpdaterSupervisorHandle {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (failure_tx, failure_rx) = tokio::sync::oneshot::channel();
    let audit_locks = Arc::new(UpdaterAuditLocks::default());
    let join = tokio::spawn(async move {
        match run_updater_supervisor(
            reload_controller,
            executor,
            audit_locks,
            shutdown_rx,
            wal_root_guard,
        )
        .await
        {
            Ok(()) => UpdaterSupervisorExit::Clean,
            Err(reason) => {
                // This carries no owned future.  A failed send cannot detach
                // a pass because the `JoinHandle` output below retains it.
                let _ = failure_tx.send(());
                UpdaterSupervisorExit::Failed(reason)
            }
        }
    });
    UpdaterSupervisorHandle {
        shutdown: Some(shutdown_tx),
        join: Some(join),
        failure: Some(failure_rx),
        failure_notified: false,
    }
}

enum SupervisorWake {
    Reload,
    Shutdown,
    LaneExited(String),
    DeadlineExceeded(RetainedUpdaterPass),
}

enum UpdaterLaneFailure {
    Failed(String),
    DeadlineExceeded(RetainedUpdaterPass),
}

impl std::fmt::Debug for UpdaterLaneFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(reason) => formatter.debug_tuple("Failed").field(reason).finish(),
            Self::DeadlineExceeded(pass) => formatter
                .debug_struct("DeadlineExceeded")
                .field("lane", &pass.lane.as_str())
                .finish(),
        }
    }
}

async fn run_updater_supervisor(
    reload_controller: Arc<crate::config::reload::ReloadController>,
    executor: LaneExecutor,
    audit_locks: Arc<UpdaterAuditLocks>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    wal_root_guard: Option<WalWriterHandle>,
) -> Result<(), UpdaterSupervisorFailure> {
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
                wal_root_guard.clone(),
            ));
        }
        tracing::debug!(
            epoch,
            lanes = lanes.len(),
            "accepted updater generation active"
        );

        let wake = Some(tokio::select! {
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
                match lane {
                    Some(Ok(Err(UpdaterLaneFailure::DeadlineExceeded(pass)))) => {
                        tracing::error!(epoch, lane = pass.lane.as_str(), "updater operation deadline exceeded; retaining pass at serve boundary");
                        SupervisorWake::DeadlineExceeded(pass)
                    }
                    Some(Ok(Ok((lane, _)))) => {
                        let reason = format!("recurring update lane `{}` exited outside generation cancellation", lane.as_str());
                        tracing::error!(epoch, %reason, "recurring updater supervisor is failing closed");
                        SupervisorWake::LaneExited(reason)
                    }
                    Some(Ok(Err(UpdaterLaneFailure::Failed(reason)))) => {
                        tracing::error!(epoch, %reason, "recurring updater supervisor is failing closed");
                        SupervisorWake::LaneExited(reason)
                    }
                    Some(Err(error)) => {
                        let reason = format!("recurring update lane task failed: {error}");
                        tracing::error!(epoch, %reason, "recurring updater supervisor is failing closed");
                        SupervisorWake::LaneExited(reason)
                    }
                    None => {
                        let reason = "recurring update lane set ended unexpectedly".to_string();
                        tracing::error!(epoch, %reason, "recurring updater supervisor is failing closed");
                        SupervisorWake::LaneExited(reason)
                    }
                }
            }
        });

        cancel_generation.send_replace(true);
        let mut drain_failure = None;
        let mut retained_passes = Vec::new();
        while let Some(result) = lanes.join_next().await {
            match result {
                Ok(Ok((lane, cadence))) => {
                    cadence_by_lane.insert(lane, cadence);
                }
                Ok(Err(UpdaterLaneFailure::Failed(reason))) => {
                    tracing::error!(
                        epoch,
                        %reason,
                        "recurring update lane failed while draining accepted work"
                    );
                    drain_failure.get_or_insert(reason);
                }
                Ok(Err(UpdaterLaneFailure::DeadlineExceeded(pass))) => {
                    tracing::error!(
                        epoch,
                        lane = pass.lane.as_str(),
                        "additional updater deadline pass retained at serve boundary"
                    );
                    retained_passes.push(pass);
                }
                Err(error) => {
                    let reason = format!("recurring update lane join failed: {error}");
                    tracing::error!(epoch, %reason);
                    drain_failure.get_or_insert(reason);
                }
            }
        }
        // Only a deadline wake transfers its owned pass out of `wake`.
        // Reload, shutdown, and ordinary lane-failure wakes must remain
        // available after every child has joined so their exact lifecycle
        // decision can be made below.
        let wake = match wake {
            Some(SupervisorWake::DeadlineExceeded(pass)) => {
                retained_passes.push(pass);
                None
            }
            wake => wake,
        };
        if !retained_passes.is_empty() {
            return Err(UpdaterSupervisorFailure::DeadlineExceeded(retained_passes));
        }
        if let Some(reason) = drain_failure {
            return Err(UpdaterSupervisorFailure::Failed(format!(
                "recurring updater failed while draining epoch {epoch}: {reason}"
            )));
        }

        let wake = match wake {
            Some(wake) => wake,
            None => {
                return Err(UpdaterSupervisorFailure::Failed(
                    "updater supervisor lost its non-deadline wake state".to_string(),
                ));
            }
        };
        match wake {
            SupervisorWake::Reload => {
                tracing::debug!(epoch, "retired updater generation after accepted reload");
            }
            SupervisorWake::Shutdown => {
                tracing::debug!(epoch, "updater supervisor shut down cleanly");
                return Ok(());
            }
            SupervisorWake::LaneExited(reason) => {
                return Err(UpdaterSupervisorFailure::Failed(format!(
                    "recurring updater lane failed at epoch {epoch}: {reason}"
                )));
            }
            SupervisorWake::DeadlineExceeded(pass) => {
                return Err(UpdaterSupervisorFailure::DeadlineExceeded(vec![pass]));
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
    wal_root_guard: Option<WalWriterHandle>,
) -> Result<(RecurringUpdateLane, LaneCadence), UpdaterLaneFailure> {
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
        let control = UpdaterPassControl::new(wal_root_guard.clone());
        let lane_control = control.clone();
        let lane_snapshot = Arc::clone(&snapshot);
        let lane_executor = Arc::clone(&executor);
        // `JoinHandle` is deliberately retained through every branch below.
        // Dropping it would detach a future which may already own a durable
        // updater Intent and its generation/WAL lease.
        let mut work = tokio::spawn(async move {
            let execution = std::panic::AssertUnwindSafe(lane_executor(
                lane,
                lane_snapshot,
                gate,
                lane_control,
            ))
            .catch_unwind()
            .await;
            require_successful_lane_execution(lane, execution)
        });
        let (cancellation_requested, execution) = tokio::select! {
            biased;
            changed = cancel_generation.changed() => {
                let _ = changed;
                control.cancel();
                let joined = match control.deadline(UpdaterDeadlinePhase::Operation) {
                    Some(deadline) => match tokio::time::timeout_at(deadline, &mut work).await {
                        Ok(joined) => joined,
                        Err(_) => {
                            // This is a fatal lifecycle state, but it is not a
                            // return path: retain the actual task ownership and
                            // WAL clone until the late terminal join finishes.
                            // Return the owned drain object, rather than an
                            // ordinary error.  Serve keeps this exact task,
                            // control and writer guard through its explicit
                            // fail-stopped late-join branch.
                            tracing::error!(lane = lane.as_str(), "updater operation deadline expired while draining an admitted pass; retaining owner until late join");
                            return Err(UpdaterLaneFailure::DeadlineExceeded(
                                RetainedUpdaterPass {
                                    lane,
                                    control,
                                    pass: work,
                                },
                            ));
                        }
                    },
                    None => work.await,
                };
                (true, joined)
            }
            result = &mut work => {
                (false, result)
            }
        };
        match execution {
            Ok(result) => result.map_err(UpdaterLaneFailure::Failed)?,
            Err(error) => {
                return Err(UpdaterLaneFailure::Failed(format!(
                    "recurring update lane task join failed: {error}"
                )));
            }
        }
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

fn accepted_updater_policy_sha256(
    config: &crate::config::FreedomConfig,
) -> Result<[u8; 32], String> {
    // Serialize through `Value`: serde_json's default object map is ordered,
    // so nested HashMap-backed policy fields do not inherit process-random
    // iteration order into the durable binding.
    let value = serde_json::to_value(config)
        .map_err(|error| format!("materialize accepted updater policy snapshot: {error}"))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("serialize accepted updater policy snapshot: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(ACCEPTED_UPDATER_POLICY_DOMAIN);
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

async fn run_production_lane_once(
    lane: RecurringUpdateLane,
    snapshot: Arc<crate::config::reload::AcceptedConfigSnapshot>,
    home: PathBuf,
    writer: WalWriterHandle,
    gate: crate::updater::pipeline::GateDecision,
    control: UpdaterPassControl,
) -> Result<(), String> {
    let config = snapshot.config();
    let pass_identity = UpdaterPassIdentity::bound(
        lane.audit_lane(),
        snapshot.epoch(),
        accepted_updater_policy_sha256(&config)?,
    );
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
                run_authorized_self_probe(pass_identity, Arc::clone(&snapshot), &writer, control)
                    .await?;
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
    let fired_receipt_sha256 = append_updater_fired(&identity, task_kind, writer).await?;
    let started = std::time::Instant::now();
    let outcome = std::panic::AssertUnwindSafe(work).catch_unwind().await;
    let (component, terminalized_failure, terminal_outcome) = match outcome {
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::BlockedByGate)) => (
            ComponentOutcome::skipped_by_gate(component_name, current_version, deny_reason),
            None,
            UpdaterTerminalOutcome::SkippedByGate,
        ),
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::SkippedByPolicy)) => (
            ComponentOutcome::skipped_by_gate(
                component_name,
                current_version,
                REQUEST_BOUND_POLICY_REFUSED,
            ),
            None,
            UpdaterTerminalOutcome::SkippedByGate,
        ),
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::GenerationRetired)) => (
            ComponentOutcome::skipped_by_gate(
                component_name,
                current_version,
                ACCEPTED_GENERATION_RETIRED,
            ),
            None,
            UpdaterTerminalOutcome::Cancelled,
        ),
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::Completed)) => (
            ComponentOutcome::up_to_date(component_name, current_version),
            None,
            UpdaterTerminalOutcome::Completed,
        ),
        Ok(Ok(crate::daemon::auto_update::RecurringMutationOutcome::Staged {
            prior_version,
            staged_version,
        })) => (
            ComponentOutcome::staged(component_name, prior_version, staged_version),
            None,
            UpdaterTerminalOutcome::Completed,
        ),
        Ok(Err(error)) => (
            ComponentOutcome::failed(component_name, current_version, error.clone()),
            Some(mutation_failure_disposition(error)),
            UpdaterTerminalOutcome::Failed,
        ),
        Err(_) => {
            let error = format!("{component_name} executor panicked");
            (
                ComponentOutcome::failed(component_name, current_version, &error),
                Some(TerminalizedPassFailure::CloseSupervisor(error)),
                UpdaterTerminalOutcome::Failed,
            )
        }
    };
    let result = UpdaterTaskResultPayload {
        identity,
        task_kind,
        ts_unix: crate::time::now_unix_secs(),
        duration_ms: started.elapsed().as_millis().min(u32::MAX as u128) as u32,
        terminal_outcome: Some(terminal_outcome),
        fired_receipt_sha256: Some(fired_receipt_sha256),
        leaf_receipt_binding: None,
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
    control: UpdaterPassControl,
) -> Result<UpdaterTaskResultPayload, String> {
    let config = snapshot.config().auto_update.clone();
    run_authorized_self_probe_with_check(identity, snapshot, writer, control, move |authority| {
        Box::pin(async move {
            crate::updater::self_update::check_for_update_channel_authorized(
                authority,
                &config.repo,
                config.channel,
            )
            .await
        })
    })
    .await
}

async fn run_authorized_self_probe_with_check<F>(
    identity: UpdaterPassIdentity,
    snapshot: Arc<crate::config::reload::AcceptedConfigSnapshot>,
    writer: &WalWriterHandle,
    control: UpdaterPassControl,
    check: F,
) -> Result<UpdaterTaskResultPayload, String>
where
    F: for<'a> FnOnce(
        &'a crate::updater::self_update::RecurringSelfUpdateAuthority,
    ) -> futures_util::future::BoxFuture<
        'a,
        anyhow::Result<crate::updater::self_update::UpdateCheck>,
    >,
{
    let task_kind = UpdaterTaskKind::NeothSelf;
    let fired_receipt_sha256 = append_updater_fired(&identity, task_kind, writer).await?;
    let pass_id = identity
        .correlatable_pass_id_for(task_kind)
        .ok_or_else(|| "authorized updater probe requires a bound outer pass identity".to_string())?
        .to_string();
    // Admission happens only after FIRED is durable.  Every leaf receives a
    // clone of this one monotonic clock; no request can restart its budget.
    let run_clock = UpdaterRunLimits::default_http_probe()
        .and_then(UpdaterRunClock::start)
        .map_err(|error| format!("admit bounded updater probe pass: {error}"))?;
    control
        .admit(run_clock.clone())
        .map_err(|error| format!("record admitted updater probe clock: {error:#}"))?;
    let cancellation = control.clone();
    let authority = crate::updater::self_update::RecurringSelfUpdateAuthority::for_probe(
        writer.clone(),
        Arc::clone(&snapshot),
        pass_id,
        run_clock.clone(),
        control,
    );
    let started = std::time::Instant::now();
    let current = crate::updater::self_update::current_version();
    let checked = std::panic::AssertUnwindSafe(check(&authority))
        .catch_unwind()
        .await;
    let terminal_receipts = authority
        .terminal_receipts()
        .map_err(|error| format!("collect acknowledged updater leaf receipts: {error}"))?;
    if authority.outer_terminal_indeterminate() {
        // An intent may be durable while its terminal WAL acknowledgement is
        // unknown.  Do not manufacture an outer RESULT around that gap; leave
        // the FIRED/intent for strict recovery to synthesize an interrupted
        // terminal and its matching outer pass closure.
        return Err(
            "updater leaf terminal acknowledgement is indeterminate; outer RESULT withheld for recovery"
                .to_string(),
        );
    }
    let leaf_receipt_binding =
        (!terminal_receipts.is_empty()).then_some(UpdaterLeafReceiptBinding {
            schema_version: UPDATER_LEAF_RECEIPT_BINDING_SCHEMA_VERSION,
            budgets: run_clock.budgets().clone(),
            terminal_receipts,
        });
    let (component, mut terminalized_failure, mut terminal_outcome) = match checked {
        Ok(Ok(check)) if check.needs_update => (
            ComponentOutcome::update_available("neoth", check.current, check.latest),
            None,
            UpdaterTerminalOutcome::Completed,
        ),
        Ok(Ok(check)) => (
            ComponentOutcome::up_to_date("neoth", check.current),
            None,
            UpdaterTerminalOutcome::Completed,
        ),
        Ok(Err(error)) if crate::updater::authority::error_is_policy_refusal(&error) => (
            ComponentOutcome::skipped_by_gate("neoth", current, REQUEST_BOUND_POLICY_REFUSED),
            None,
            UpdaterTerminalOutcome::SkippedByGate,
        ),
        Ok(Err(error)) if crate::updater::authority::error_is_generation_retired(&error) => (
            ComponentOutcome::skipped_by_gate("neoth", current, ACCEPTED_GENERATION_RETIRED),
            None,
            UpdaterTerminalOutcome::Cancelled,
        ),
        Ok(Err(error)) => {
            let (failure, terminal_outcome) =
                authorized_probe_failure_disposition(error, cancellation.is_cancelled());
            let diagnostic = match &failure {
                TerminalizedPassFailure::RetryNextCadence(error)
                | TerminalizedPassFailure::CloseSupervisor(error) => error.to_string(),
            };
            (
                ComponentOutcome::failed("neoth", current, diagnostic),
                Some(failure),
                terminal_outcome,
            )
        }
        Err(_) => {
            let diagnostic = "authorized self-update probe executor panicked".to_string();
            (
                ComponentOutcome::failed("neoth", current, &diagnostic),
                Some(TerminalizedPassFailure::CloseSupervisor(diagnostic)),
                UpdaterTerminalOutcome::Failed,
            )
        }
    };
    if run_clock
        .remaining(UpdaterDeadlinePhase::Terminal)
        .is_zero()
    {
        terminal_outcome = UpdaterTerminalOutcome::TimedOut;
        terminalized_failure = Some(TerminalizedPassFailure::RetryNextCadence(
            "updater pass terminal acknowledgement exceeded its inherited absolute deadline"
                .to_string(),
        ));
    }
    let result = UpdaterTaskResultPayload {
        identity,
        task_kind,
        ts_unix: crate::time::now_unix_secs(),
        duration_ms: started.elapsed().as_millis().min(u32::MAX as u128) as u32,
        terminal_outcome: Some(terminal_outcome),
        fired_receipt_sha256: Some(fired_receipt_sha256),
        leaf_receipt_binding,
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
    let fired_receipt_sha256 = append_updater_fired(&identity, task_kind, writer).await?;
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
    result.terminal_outcome = Some(terminal_outcome_for_components(&result.components));
    result.fired_receipt_sha256 = Some(fired_receipt_sha256);
    append_updater_result(&result, writer).await?;
    Ok(result)
}

fn terminal_outcome_for_components(components: &[ComponentOutcome]) -> UpdaterTerminalOutcome {
    if components
        .iter()
        .any(|component| component.status == crate::wal::payloads_u04::ComponentStatus::Failed)
    {
        UpdaterTerminalOutcome::Failed
    } else if !components.is_empty()
        && components.iter().all(|component| {
            component.status == crate::wal::payloads_u04::ComponentStatus::SkippedByGate
        })
    {
        UpdaterTerminalOutcome::SkippedByGate
    } else {
        UpdaterTerminalOutcome::Completed
    }
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
        terminal_outcome: None,
        fired_receipt_sha256: None,
        leaf_receipt_binding: None,
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
) -> Result<String, String> {
    let payload = UpdaterTaskFiredPayload {
        identity: identity.clone(),
        task_kind,
        ts_unix: crate::time::now_unix_secs(),
    };
    let body = serde_json::to_vec(&payload).map_err(|error| format!("serde fired: {error}"))?;
    let fired_receipt_sha256 = updater_fired_receipt_sha256(&body);
    let header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_FIRED, &body)
        .flags(EventFlags::SYNTHETIC)
        .build();
    writer
        .append(header, body)
        .await
        .map_err(|error| format!("wal append fired: {error}"))?;
    Ok(fired_receipt_sha256)
}

async fn append_updater_result(
    result: &crate::wal::payloads_u04::UpdaterTaskResultPayload,
    writer: &WalWriterHandle,
) -> Result<(), String> {
    result
        .validate_leaf_receipt_binding()
        .map_err(|error| format!("validate outer updater leaf receipt binding: {error}"))?;
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        assert_eq!(
            decoded.terminal_outcome,
            Some(UpdaterTerminalOutcome::Completed)
        );
        let expected_fired_receipt = updater_fired_receipt_sha256(first.payload);
        assert_eq!(
            decoded.fired_receipt_sha256.as_deref(),
            Some(expected_fired_receipt.as_str())
        );
        assert_eq!(
            decoded.correlatable_fired_receipt(),
            decoded.fired_receipt_sha256.as_deref()
        );
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
        assert_eq!(
            result.terminal_outcome,
            Some(UpdaterTerminalOutcome::Cancelled)
        );

        drop(writer);
        join.await.unwrap();
    }

    #[test]
    fn accepted_policy_digest_is_stable_and_changes_with_the_snapshot() {
        let first = crate::config::FreedomConfig::default();
        let second = crate::config::FreedomConfig::default();
        assert_eq!(
            accepted_updater_policy_sha256(&first).unwrap(),
            accepted_updater_policy_sha256(&second).unwrap()
        );

        let mut changed = first.clone();
        changed.monitor.interval_secs = changed.monitor.interval_secs.saturating_add(1);
        assert_ne!(
            accepted_updater_policy_sha256(&first).unwrap(),
            accepted_updater_policy_sha256(&changed).unwrap()
        );
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
            Arc::new(move |lane, snapshot, _gate, _control| {
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
            None,
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
            Arc::new(move |lane, _snapshot, _gate, _control| {
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
        let mut handle =
            spawn_updater_supervisor_with_executor(Arc::clone(&controller), executor, None);

        let failure = tokio::time::timeout(Duration::from_secs(2), handle.wait_for_failure())
            .await
            .expect("supervisor continued after a missing terminal RESULT");
        let failure = failure.to_string();
        assert!(
            failure.contains("wal append result") && failure.contains("cli_version_probe"),
            "unexpected fail-closed reason: {failure}"
        );
        let _ = handle.shutdown().await;
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
            UpdaterPassControl::new(None),
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
        let executor: LaneExecutor = Arc::new(move |lane, _snapshot, _gate, _control| {
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
            None,
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
            None,
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
    fn recurring_network_gate_admits_only_bounded_self_probe() {
        assert!(matches!(
            recurring_egress_gate(RecurringUpdateLane::NeothSelfProbe),
            GateDecision::Allow
        ));
        match recurring_egress_gate(RecurringUpdateLane::SelfStage) {
            GateDecision::Deny { reason } => {
                assert_eq!(reason, UNBOUNDED_RECURRING_LIFECYCLE_DENIED);
                assert!(reason.contains("absolute pass deadline"));
                assert!(reason.contains("spawn_blocking"));
            }
            GateDecision::Allow => panic!("SelfStage must remain denied in Wave 25"),
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
                    assert!(reason.contains("descendant process trees"));
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
            Arc::new(move |lane, snapshot, _gate, _control| {
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

        let handle = spawn_updater_supervisor_with_executor(controller, executor, None);
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
            Arc::new(move |lane, snapshot, gate, _control| {
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
        let handle =
            spawn_updater_supervisor_with_executor(Arc::clone(&controller), executor, None);

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

        let _ = handle.shutdown().await;
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
        let executor: LaneExecutor = Arc::new(move |lane, snapshot, gate, _control| {
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
        let handle =
            spawn_updater_supervisor_with_executor(Arc::clone(&controller), executor, None);

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

        let _ = handle.shutdown().await;
    }

    #[tokio::test]
    async fn admitted_operation_deadline_reports_fatal_but_retains_join_until_late_release() {
        let home = tempfile::tempdir().unwrap();
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            crate::config::FreedomConfig::default(),
            home.path().join("freedom.yaml"),
        ));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let release = Arc::new(tokio::sync::Notify::new());
        let executor: LaneExecutor = {
            let release = Arc::clone(&release);
            let started_tx = Arc::clone(&started_tx);
            Arc::new(move |_lane, _snapshot, _gate, control| {
                let release = Arc::clone(&release);
                let started_tx = Arc::clone(&started_tx);
                Box::pin(async move {
                    let clock = UpdaterRunClock::start(
                        UpdaterRunLimits::new(
                            Duration::from_millis(5),
                            Duration::from_millis(10),
                            Duration::from_millis(15),
                            Duration::from_millis(20),
                        )
                        .map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                    control.admit(clock).map_err(|error| error.to_string())?;
                    if let Ok(mut started) = started_tx.lock()
                        && let Some(started) = started.take()
                    {
                        let _ = started.send(());
                    }
                    // Models a terminal-WAL acknowledgement that cannot yet
                    // complete. It intentionally ignores cancellation until
                    // the test grants the late join.
                    release.notified().await;
                    Ok(())
                })
            })
        };
        let (cancel, _) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run_lane_loop(
            LaneCadence {
                schedule: LaneSchedule {
                    lane: RecurringUpdateLane::NeothSelfProbe,
                    interval_secs: 60,
                },
                next_due: tokio::time::Instant::now(),
            },
            controller.accepted_snapshot(),
            executor,
            Arc::new(UpdaterAuditLocks::default()),
            cancel.subscribe(),
            None,
        ));
        started_rx.await.expect("admitted pass started");
        cancel.send_replace(true);
        let retained = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("operation deadline must return its owned retained outcome")
            .expect("lane loop task completed");
        let retained = match retained {
            Err(UpdaterLaneFailure::DeadlineExceeded(retained)) => retained,
            Err(UpdaterLaneFailure::Failed(reason)) => {
                panic!("unexpected ordinary failure: {reason}")
            }
            Ok(_) => panic!("deadline drain unexpectedly completed cleanly"),
        };
        assert!(
            !retained.pass.is_finished(),
            "deadline outcome must retain, not drop or detach, the admitted JoinHandle"
        );
        release.notify_waiters();
        retained
            .join()
            .await
            .expect("retained lane task joins after release");
    }

    #[tokio::test]
    async fn dropped_failure_notification_does_not_drop_retained_pass_ownership() {
        let release = Arc::new(tokio::sync::Notify::new());
        let pass_release = Arc::clone(&release);
        let pass = tokio::spawn(async move {
            pass_release.notified().await;
            Ok(())
        });
        let retained = RetainedUpdaterPass {
            lane: RecurringUpdateLane::NeothSelfProbe,
            control: UpdaterPassControl::new(None),
            pass,
        };
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
        let (failure_tx, failure_rx) = tokio::sync::oneshot::channel();
        drop(failure_tx);
        let join = tokio::spawn(async move {
            UpdaterSupervisorExit::Failed(UpdaterSupervisorFailure::DeadlineExceeded(vec![
                retained,
            ]))
        });
        let mut handle = UpdaterSupervisorHandle {
            shutdown: Some(shutdown_tx),
            join: Some(join),
            failure: Some(failure_rx),
            failure_notified: false,
        };
        assert!(matches!(
            handle.wait_for_failure().await,
            UpdaterSupervisorFailure::Failed(reason)
                if reason.contains("notification closed")
        ));
        let retained = tokio::time::timeout(Duration::from_secs(1), handle.shutdown())
            .await
            .expect("shutdown must return a finite retained ownership outcome")
            .expect("shutdown must return the deadline outcome");
        let mut retained = match retained {
            UpdaterSupervisorFailure::DeadlineExceeded(passes) => passes,
            UpdaterSupervisorFailure::Failed(reason) => panic!("unexpected failure: {reason}"),
        };
        let retained = retained.pop().expect("one retained pass");
        assert!(
            !retained.pass.is_finished(),
            "finite shutdown outcome must still own the live pass for Serve"
        );
        let late_join = tokio::spawn(async move { retained.join().await });
        tokio::task::yield_now().await;
        assert!(
            !late_join.is_finished(),
            "Serve late join must retain ownership until the terminal release"
        );
        release.notify_waiters();
        tokio::time::timeout(Duration::from_secs(1), late_join)
            .await
            .expect("serve late join completed")
            .expect("late join task completed")
            .expect("retained pass completed");
    }

    #[tokio::test]
    async fn cancelling_pending_wait_for_failure_leaves_shutdown_ownership_intact() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (failure_tx, failure_rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            UpdaterSupervisorExit::Clean
        });
        let mut handle = UpdaterSupervisorHandle {
            shutdown: Some(shutdown_tx),
            join: Some(join),
            failure: Some(failure_rx),
            failure_notified: false,
        };
        {
            let pending = handle.wait_for_failure();
            tokio::pin!(pending);
            tokio::select! {
                biased;
                _ = &mut pending => panic!("failure notification was not sent"),
                _ = tokio::task::yield_now() => {}
            }
        }
        // Keep the sender live: cancellation of the `select!` branch, rather
        // than receiver closure, is the condition under test.
        let _keep_failure_sender = failure_tx;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), handle.shutdown())
                .await
                .expect("ordinary shutdown still owns its supervisor")
                .is_none(),
            "cancelling a pending wait must not move or detach the join handle"
        );
    }

    #[tokio::test]
    async fn cancelling_wait_after_notification_retries_the_borrowed_supervisor_join() {
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
        let (failure_tx, failure_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let join_release = Arc::clone(&release);
        let join = tokio::spawn(async move {
            join_release.notified().await;
            UpdaterSupervisorExit::Failed(UpdaterSupervisorFailure::Failed(
                "expected failure".to_string(),
            ))
        });
        let mut handle = UpdaterSupervisorHandle {
            shutdown: Some(shutdown_tx),
            join: Some(join),
            failure: Some(failure_rx),
            failure_notified: false,
        };
        failure_tx.send(()).unwrap();
        {
            let pending = handle.wait_for_failure();
            tokio::pin!(pending);
            tokio::select! {
                biased;
                _ = &mut pending => panic!("supervisor join was intentionally held"),
                _ = tokio::task::yield_now() => {}
            }
        }
        release.notify_one();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), handle.wait_for_failure())
                .await
                .expect("retry must await the still-owned join"),
            UpdaterSupervisorFailure::Failed(reason) if reason == "expected failure"
        ));
    }

    #[tokio::test]
    async fn cancelled_loopback_http_writes_leaf_receipt_before_outer_cancelled_result() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("000001.wal");
        let (writer, writer_join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), home.clone()).unwrap();
        ready.wait().await.unwrap();
        // The production probe uses FailClosed confirmation.  External HTTP
        // becomes autonomous at Elevated, so this fixture reaches the real
        // request-bound effect instead of returning before the loopback
        // transport can signal its header boundary.
        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Elevated;
        let reload =
            crate::config::reload::ReloadController::new(config, home.join("freedom.yaml"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (headers_tx, headers_rx) = tokio::sync::oneshot::channel();
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0u8; 512];
            let read = stream.read(&mut bytes).await.unwrap();
            assert!(read > 0 && bytes[..read].starts_with(b"GET "));
            let _ = headers_tx.send(());
            while stream.read(&mut bytes).await.unwrap() != 0 {}
            let _ = eof_tx.send(());
        });
        let control = UpdaterPassControl::new(Some(writer.clone()));
        let cancel = control.clone();
        let task_writer = writer.clone();
        let task_identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 0);
        let mut task = tokio::spawn(async move {
            run_authorized_self_probe_with_check(
                task_identity,
                reload.accepted_snapshot(),
                &task_writer,
                control,
                move |authority| {
                    Box::pin(async move {
                        authority
                            .execute_http_for_probe_test(
                                "loopback-cancel",
                                "https://loopback.invalid/",
                                move || async move {
                                    let mut stream = tokio::net::TcpStream::connect(address)
                                        .await
                                        .map_err(|error| {
                                            crate::updater::authority::UpdaterLeafFailure::new(
                                    crate::updater::authority::UpdaterLeafFailureKind::Protocol,
                                    error.into(),
                                )
                                        })?;
                                    stream
                                        .write_all(b"GET / HTTP/1.1\r\nHost: loopback\r\n\r\n")
                                        .await
                                        .map_err(|error| {
                                            crate::updater::authority::UpdaterLeafFailure::new(
                                    crate::updater::authority::UpdaterLeafFailureKind::Protocol,
                                    error.into(),
                                )
                                        })?;
                                    let mut byte = [0u8; 1];
                                    let _ = stream.read(&mut byte).await.map_err(|error| {
                                        crate::updater::authority::UpdaterLeafFailure::new(
                                    crate::updater::authority::UpdaterLeafFailureKind::Protocol,
                                    error.into(),
                                )
                                    })?;
                                    Ok(crate::updater::authority::UpdaterLeafSuccess::new(
                                (),
                                crate::updater::authority::UpdaterLeafOutcomeCode::Completed,
                            ))
                                },
                            )
                            .await?;
                        Ok(crate::updater::self_update::UpdateCheck {
                            current: "0.0.0".to_string(),
                            latest: "0.0.0".to_string(),
                            needs_update: false,
                            release_url: String::new(),
                            published_at: String::new(),
                        })
                    })
                },
            )
            .await
        });
        {
            let headers = tokio::time::timeout(Duration::from_secs(1), headers_rx);
            tokio::pin!(headers);
            tokio::select! {
                header = &mut headers => {
                    header
                        .expect("authorized loopback effect did not write request headers in time")
                        .expect("loopback server dropped its header signal");
                }
                outcome = &mut task => {
                    panic!(
                        "authorized updater probe returned before its injected loopback HTTP effect connected: {outcome:?}"
                    );
                }
            }
        }
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), eof_rx)
            .await
            .unwrap()
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .expect("owning generation cancellation must finish the pass normally");
        assert_eq!(
            result.terminal_outcome,
            Some(UpdaterTerminalOutcome::Cancelled)
        );
        result.validate_leaf_receipt_binding().unwrap();
        let receipt = &result
            .leaf_receipt_binding
            .as_ref()
            .unwrap()
            .terminal_receipts[0];
        assert!(receipt.request_id.contains("loopback-cancel"));
        drop(cancel);
        drop(writer);
        writer_join.await.unwrap().unwrap();
        server.await.unwrap();
        let bytes = tokio::fs::read(segment).await.unwrap();
        let mut offset = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut leaf_result_payload = None;
        let mut leaf_result_offset = None;
        let mut outer_result = None;
        let mut outer_result_offset = None;
        while offset < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[offset..]).unwrap();
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                && frame.header.event_subtype
                    == crate::wal::events::ExtendedSubtype::UpdaterLeafResult as u8
            {
                let leaf: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                assert_eq!(leaf["status"], "failure");
                assert_eq!(leaf["error_kind"], "cancelled");
                leaf_result_payload = Some(frame.payload.to_vec());
                leaf_result_offset = Some(offset);
            }
            if frame.header.event_type == EVENT_TYPE_UPDATER_TASK_RESULT {
                let decoded: UpdaterTaskResultPayload =
                    serde_json::from_slice(frame.payload).unwrap();
                if decoded.identity == result.identity {
                    outer_result = Some(decoded);
                    outer_result_offset = Some(offset);
                }
            }
            offset += frame.header.total_len as usize;
        }
        let leaf_result_payload = leaf_result_payload.expect("durable cancelled leaf result");
        let outer_result = outer_result.expect("durable outer result after leaf terminal");
        assert_eq!(
            outer_result.terminal_outcome,
            Some(UpdaterTerminalOutcome::Cancelled)
        );
        outer_result.validate_leaf_receipt_binding().unwrap();
        let receipt = &outer_result
            .leaf_receipt_binding
            .as_ref()
            .unwrap()
            .terminal_receipts[0];
        assert!(receipt.request_id.contains("loopback-cancel"));
        assert!(
            leaf_result_offset.expect("leaf result offset")
                < outer_result_offset.expect("outer result offset"),
            "the outer receipt binding must follow the acknowledged leaf terminal"
        );
        let bound = &outer_result.leaf_receipt_binding.unwrap().terminal_receipts[0];
        assert_eq!(
            bound.result_receipt_sha256,
            crate::wal::payloads_u04::updater_leaf_result_receipt_sha256(&leaf_result_payload)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn generation_cancelled_loopback_leaf_joins_before_lane_replacement() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("000001.wal");
        let (writer, writer_join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), home.clone()).unwrap();
        ready.wait().await.unwrap();

        let mut config = crate::config::FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Elevated;
        let controller =
            crate::config::reload::ReloadController::new(config, home.join("freedom.yaml"));
        let snapshot = controller.accepted_snapshot();
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 0);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (headers_tx, headers_rx) = tokio::sync::oneshot::channel();
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0u8; 512];
            let read = stream.read(&mut bytes).await.unwrap();
            assert!(read > 0 && bytes[..read].starts_with(b"GET "));
            let _ = headers_tx.send(());
            while stream.read(&mut bytes).await.unwrap() != 0 {}
            let _ = eof_tx.send(());
        });

        let starts = Arc::new(AtomicUsize::new(0));
        let executor: LaneExecutor = {
            let writer = writer.clone();
            let identity = identity.clone();
            let starts = Arc::clone(&starts);
            Arc::new(move |lane, snapshot, _gate, control| {
                assert_eq!(lane, RecurringUpdateLane::NeothSelfProbe);
                let writer = writer.clone();
                let identity = identity.clone();
                let starts = Arc::clone(&starts);
                Box::pin(async move {
                    starts.fetch_add(1, Ordering::SeqCst);
                    run_authorized_self_probe_with_check(
                        identity,
                        snapshot,
                        &writer,
                        control,
                        move |authority| {
                            Box::pin(async move {
                                authority
                                    .execute_http_for_probe_test(
                                        "generation-loopback-cancel",
                                        "https://loopback.invalid/",
                                        move || async move {
                                            let mut stream = tokio::net::TcpStream::connect(address)
                                                .await
                                                .map_err(|error| {
                                                    crate::updater::authority::UpdaterLeafFailure::new(
                                                        crate::updater::authority::UpdaterLeafFailureKind::Protocol,
                                                        error.into(),
                                                    )
                                                })?;
                                            stream
                                                .write_all(b"GET / HTTP/1.1\r\nHost: loopback\r\n\r\n")
                                                .await
                                                .map_err(|error| {
                                                    crate::updater::authority::UpdaterLeafFailure::new(
                                                        crate::updater::authority::UpdaterLeafFailureKind::Protocol,
                                                        error.into(),
                                                    )
                                                })?;
                                            let mut byte = [0u8; 1];
                                            let _ = stream.read(&mut byte).await.map_err(|error| {
                                                crate::updater::authority::UpdaterLeafFailure::new(
                                                    crate::updater::authority::UpdaterLeafFailureKind::Protocol,
                                                    error.into(),
                                                )
                                            })?;
                                            Ok(crate::updater::authority::UpdaterLeafSuccess::new(
                                                (),
                                                crate::updater::authority::UpdaterLeafOutcomeCode::Completed,
                                            ))
                                        },
                                    )
                                    .await?;
                                Ok(crate::updater::self_update::UpdateCheck {
                                    current: "0.0.0".to_string(),
                                    latest: "0.0.0".to_string(),
                                    needs_update: false,
                                    release_url: String::new(),
                                    published_at: String::new(),
                                })
                            })
                        },
                    )
                    .await
                    .map(|_| ())
                })
            })
        };
        let (generation_cancel, _) = tokio::sync::watch::channel(false);
        let mut lane = tokio::spawn(run_lane_loop(
            LaneCadence {
                schedule: LaneSchedule {
                    lane: RecurringUpdateLane::NeothSelfProbe,
                    interval_secs: 60,
                },
                next_due: tokio::time::Instant::now(),
            },
            snapshot,
            executor,
            Arc::new(UpdaterAuditLocks::default()),
            generation_cancel.subscribe(),
            Some(writer.clone()),
        ));
        {
            let headers = tokio::time::timeout(Duration::from_secs(1), headers_rx);
            tokio::pin!(headers);
            tokio::select! {
                header = &mut headers => {
                    header
                        .expect("generation-owned loopback effect did not write request headers in time")
                        .expect("loopback server dropped its header signal");
                }
                outcome = &mut lane => {
                    panic!(
                        "generation lane returned before its injected loopback HTTP effect connected: {outcome:?}"
                    );
                }
            }
        }
        generation_cancel.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), eof_rx)
            .await
            .unwrap()
            .unwrap();
        let (joined_lane, cadence) = tokio::time::timeout(Duration::from_secs(1), lane)
            .await
            .unwrap()
            .unwrap()
            .expect("generation cancellation must join the admitted loopback pass cleanly");
        assert_eq!(joined_lane, RecurringUpdateLane::NeothSelfProbe);
        assert!(
            cadence.next_due > tokio::time::Instant::now(),
            "the joined pass must carry its advanced cadence into normal replacement"
        );
        assert_eq!(
            starts.load(Ordering::SeqCst),
            1,
            "the retired generation cannot start a successor before its admitted pass joins"
        );

        drop(writer);
        writer_join.await.unwrap().unwrap();
        server.await.unwrap();
        let bytes = tokio::fs::read(segment).await.unwrap();
        let mut offset = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut leaf_result_payload = None;
        let mut leaf_result_offset = None;
        let mut outer_result = None;
        let mut outer_result_offset = None;
        while offset < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[offset..]).unwrap();
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                && frame.header.event_subtype
                    == crate::wal::events::ExtendedSubtype::UpdaterLeafResult as u8
            {
                let leaf: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                assert_eq!(leaf["status"], "failure");
                assert_eq!(leaf["error_kind"], "cancelled");
                leaf_result_payload = Some(frame.payload.to_vec());
                leaf_result_offset = Some(offset);
            }
            if frame.header.event_type == EVENT_TYPE_UPDATER_TASK_RESULT {
                let decoded: UpdaterTaskResultPayload =
                    serde_json::from_slice(frame.payload).unwrap();
                if decoded.identity == identity {
                    outer_result = Some(decoded);
                    outer_result_offset = Some(offset);
                }
            }
            offset += frame.header.total_len as usize;
        }
        let leaf_result_payload = leaf_result_payload.expect("durable cancelled leaf result");
        let outer_result = outer_result.expect("durable outer result after leaf terminal");
        assert_eq!(
            outer_result.terminal_outcome,
            Some(UpdaterTerminalOutcome::Cancelled)
        );
        outer_result.validate_leaf_receipt_binding().unwrap();
        assert!(
            leaf_result_offset.expect("leaf result offset")
                < outer_result_offset.expect("outer result offset"),
            "the outer receipt binding must follow the acknowledged leaf terminal"
        );
        let bound = &outer_result.leaf_receipt_binding.unwrap().terminal_receipts[0];
        assert_eq!(
            bound.result_receipt_sha256,
            crate::wal::payloads_u04::updater_leaf_result_receipt_sha256(&leaf_result_payload)
        );
    }
}
