//! `dispatch_session()` production orchestrator.
//!
//! Per `PLAN/CHORUS_dispatcher_design.md` (2026-05-20). This module
//! Picks BACKLOG tasks, transitions them through `InProgress → Review` (or
//! `Blocked`), executes the bound worker, applies verified patches through the
//! guarded worktree path, and persists/audits the outcome. The ratified
//! decisions are:
//!
//!   Q1 patch safety → guarded worktree apply + verification
//!   Q2 progress → lifecycle and heartbeat updates through WAL 0x77
//!   Q3 review gating → policy-driven review/promotion
//!   Q4 cycle prevention → time + count budget enforced (both)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::coding::retry::WorkerRetryPolicy;
use crate::coding::store;
use crate::coding::types::{
    Hemisphere, KanbanComment, KanbanSessionId, KanbanTask, KanbanTaskId, TaskStatus, TestSummary,
};
use crate::coding::worker::{
    AcceptedWorkerOutcome, Worker, WorkerContract, WorkerOutcome, WorkerPatchState,
};
use crate::security::redact::sanitize_tool_output;

/// Map of hemisphere → bound worker. The dispatcher consults this for
/// every BACKLOG task; if no worker is bound for the task's
/// hemisphere, the task is moved to `Blocked` with a reason.
pub struct HemisphereWorkerSet {
    workers: HashMap<Hemisphere, Box<dyn Worker>>,
}

impl HemisphereWorkerSet {
    pub fn new() -> Self {
        Self {
            workers: HashMap::new(),
        }
    }

    /// Bind a worker to a hemisphere. Subsequent calls for the same
    /// hemisphere replace the previous binding (last-write-wins,
    /// matches the YAML-config reload contract).
    pub fn bind(&mut self, hemisphere: Hemisphere, worker: Box<dyn Worker>) -> &mut Self {
        self.workers.insert(hemisphere, worker);
        self
    }

    /// `true` when at least one worker is bound. Operator-friendly
    /// pre-check before `dispatch_session` runs.
    pub fn has_any(&self) -> bool {
        !self.workers.is_empty()
    }

    /// Look up the worker bound to the given hemisphere. None means
    /// the dispatcher will mark every task on that hemisphere as
    /// Blocked.
    pub fn get(&self, hemisphere: Hemisphere) -> Option<&dyn Worker> {
        self.workers.get(&hemisphere).map(|b| b.as_ref())
    }
}

impl Default for HemisphereWorkerSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Budget caps that bound a dispatch run. Pick #6 Q4 — defense in
/// depth, both caps fire whichever hits first.
#[derive(Debug, Clone, Copy)]
pub struct DispatchBudget {
    /// Wall-clock budget for the entire session. Default 30 min.
    pub max_duration: Duration,
    /// Maximum tasks the dispatcher will run in one session. Default
    /// 20. Hard cap regardless of time remaining.
    pub max_tasks: usize,
}

impl Default for DispatchBudget {
    fn default() -> Self {
        Self {
            max_duration: Duration::from_secs(30 * 60),
            max_tasks: 20,
        }
    }
}

/// WAL writer handle plumbed through `DispatchApplyConfig`. The
/// daemon's `cli::serve` path holds a live handle and threads it
/// in so Phase 4 emits `0xD3 PATCH_APPLIED` / `0xD4
/// PATCH_APPLY_FAILED` frames. CLI one-shot (`neoth code --apply`)
/// runs without the daemon's WAL writer; `None` skips the emit
/// (the operator-driven invocation is its own visible audit).
pub type WalWriterRef = Option<std::sync::Arc<crate::wal::writer::WalWriterHandle>>;

/// ADV review-D (Session 30) — the ORIGIN of an apply request, so the
/// per-task permission gate stays context-sensitive. The dispatcher
/// degrades a `Decision::Confirm` to Allow ONLY for `CliConfirmed` (the
/// operator already confirmed by typing `neoth code --apply` at a local
/// TTY). A daemon-scheduled or channel-requested apply MUST NOT inherit
/// that trust — there is no operator at the keyboard — so those origins
/// keep `Confirm` as a hard gate (fail-closed: the apply is refused until
/// a real confirmation channel exists). Deliberately NO `Default` impl:
/// the origin must be chosen explicitly at every construction site, so a
/// future caller can't silently get the trusted `CliConfirmed` behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOrigin {
    /// Local CLI `neoth code --apply` — the operator confirmed at a TTY.
    /// The only origin permitted to degrade `Confirm` → Allow.
    CliConfirmed,
    /// A daemon cron / scheduler-initiated apply. No operator present →
    /// `Confirm` is NOT degraded.
    DaemonScheduled,
    /// An apply requested over a messaging channel. No local auth →
    /// `Confirm` is NOT degraded.
    ChannelRequested,
    /// A native GUI/Buddy run reached a concrete patch boundary. This remains
    /// provenance only; an opaque per-run approval is still required.
    GuiRequested,
}

/// Proof that the actual local CLI entry point parsed an `--apply` flag.
///
/// This is deliberately separate from [`ApplyOrigin`], which remains useful
/// observable provenance but can be supplied by non-CLI callers.  No display
/// label or origin value is authority to preconfirm a mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApplyConfirmation {
    LocalCliFlag,
    GuiInteractive,
    Unattended,
}

impl ApplyOrigin {
    /// Stable wire/log name.
    pub fn as_str(self) -> &'static str {
        match self {
            ApplyOrigin::CliConfirmed => "cli_confirmed",
            ApplyOrigin::DaemonScheduled => "daemon_scheduled",
            ApplyOrigin::ChannelRequested => "channel_requested",
            ApplyOrigin::GuiRequested => "gui_requested",
        }
    }
}

/// Pick #6 Phase 4 — opt-in patch-apply config. When passed to
/// `dispatch_session`, every worker-produced patch is applied
/// inside a task-scoped git worktree per the Chorus verdict
/// (Strategy B). When `None`, dispatcher behaves as Phase 3:
/// store the dispatcher-owned task artifact under the live views.db parent
/// (`<audit-root>/coding-sessions/<session>/task-<id>-<nonce>.patch`) but
/// never apply.
///
/// The `repo_root` MUST be a valid git working tree (the
/// dispatcher does NOT auto-detect via walk-up; the operator's
/// `neoth code --apply <repo_root>` provides it explicitly).
///
/// `test_cmd` + `test_timeout` come from
/// `freedom.yaml::coding.{test_cmd,test_timeout_secs}` when the
/// CLI wires them. When `test_cmd` is `Some` and the apply
/// succeeds, the dispatcher runs the command inside the
/// worktree; non-zero exit routes through the retry-policy
/// path the same way a `git apply --check` rejection does.
///
/// `autonomy_policy` flows through
/// `permissions::evaluate(PatchApplyToRepo, &policy_snapshot)`; combined with
/// `origin` it gates whether a `Confirm`
/// decision may degrade to Allow (see [`ApplyOrigin`]). Strict
/// denies outright; other levels yield Confirm, degraded to Allow
/// only when the origin is `CliConfirmed`.
#[derive(Clone)]
pub struct DispatchApplyConfig {
    pub repo_root: std::path::PathBuf,
    /// Origin of this apply request — gates whether `Confirm` may degrade
    /// to Allow (only `CliConfirmed`). See [`ApplyOrigin`].
    pub origin: ApplyOrigin,
    confirmation: ApplyConfirmation,
    /// Installed only by the service after a real RunState exists. It is
    /// private so UI labels and external callers cannot mint admission.
    gui_patch_approval: Option<super::service::GuiPatchApprovalBroker>,
    pub test_cmd: Option<String>,
    pub test_timeout: std::time::Duration,
    pub wal_writer: WalWriterRef,
    /// Pick #6 Phase 4 defense-in-depth (Chorus Q1a) —
    /// per-task `permissions::evaluate(PatchApplyToRepo, &policy_snapshot)`
    /// gate. When `Some`, the dispatcher consults the policy
    /// BEFORE creating the worktree. Strict → Deny (task
    /// blocks); Standard/Elevated/Full → Confirm. The Confirm
    /// degrades to Allow ONLY when `origin` is `CliConfirmed`
    /// (operator opted in by passing `--apply` at a TTY);
    /// `DaemonScheduled` / `ChannelRequested` keep Confirm as a
    /// hard gate (fail-closed). When `None`, the gate is skipped
    /// (CLI one-shot operator-already-confirmed).
    pub autonomy_policy: Option<crate::permissions::AutonomyPolicySnapshot>,
    /// Optional, explicitly rooted read-only code-map advisory.  This is
    /// evidence for the operator only; it has no authority over admission or
    /// the existing ownership/churn risk gate.
    pub pre_apply_impact_advisory: Option<PreApplyImpactAdvisoryConfig>,
    #[cfg(test)]
    test_pause: Option<std::sync::Arc<PatchApplyPause>>,
}

impl std::fmt::Debug for DispatchApplyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchApplyConfig")
            .field("repo_root", &self.repo_root)
            .field("origin", &self.origin)
            .field("test_cmd", &self.test_cmd)
            .field("test_timeout", &self.test_timeout)
            .field("wal_writer", &self.wal_writer.as_ref().map(|_| "<live>"))
            .field("autonomy_policy", &self.autonomy_policy)
            .field("pre_apply_impact_advisory", &self.pre_apply_impact_advisory)
            .finish()
    }
}

impl DispatchApplyConfig {
    /// `origin` is REQUIRED (not a builder) so every construction site
    /// makes an explicit trust decision — see [`ApplyOrigin`]. CLI
    /// one-shots pass `ApplyOrigin::CliConfirmed`; daemon/channel apply
    /// paths must pass their own origin so the `Confirm` gate is NOT
    /// silently degraded for an unattended apply.
    pub fn new(repo_root: impl Into<std::path::PathBuf>, origin: ApplyOrigin) -> Self {
        Self {
            repo_root: repo_root.into(),
            origin,
            confirmation: ApplyConfirmation::Unattended,
            gui_patch_approval: None,
            test_cmd: None,
            test_timeout: std::time::Duration::from_secs(5 * 60),
            wal_writer: None,
            autonomy_policy: None,
            pre_apply_impact_advisory: None,
            #[cfg(test)]
            test_pause: None,
        }
    }

    /// Only the local CLI command boundary may set this marker.  It is
    /// crate-private so source-channel strings and external request payloads
    /// cannot manufacture it.
    pub(crate) fn with_local_cli_confirmation(mut self) -> Self {
        self.confirmation = ApplyConfirmation::LocalCliFlag;
        self
    }

    /// Set only by the service's native GUI route. This still requires the
    /// per-run broker to yield an exact one-use grant at admission time.
    pub(crate) fn with_gui_interactive_confirmation(mut self) -> Self {
        self.confirmation = ApplyConfirmation::GuiInteractive;
        self
    }

    pub(crate) fn attach_gui_patch_approval_broker(
        &mut self,
        broker: super::service::GuiPatchApprovalBroker,
    ) {
        debug_assert_eq!(self.confirmation, ApplyConfirmation::GuiInteractive);
        self.gui_patch_approval = Some(broker);
    }

    #[cfg(test)]
    fn with_test_pause(mut self, pause: std::sync::Arc<PatchApplyPause>) -> Self {
        self.test_pause = Some(pause);
        self
    }

    #[cfg(test)]
    async fn pause_for_test(&self, point: PatchApplyPausePoint) {
        let pause = self
            .test_pause
            .as_ref()
            .filter(|pause| pause.point == point)
            .cloned();
        if let Some(pause) = pause {
            pause
                .entered
                .store(true, std::sync::atomic::Ordering::Release);
            // One waiter only. `notify_one` retains a permit when the test
            // has observed `entered` but has not yet subscribed, avoiding a
            // lost wake-up between the atomic load and `notified().await`.
            pause.entered_notify.notify_one();
            pause.release.notified().await;
        }
    }

    /// Attach the operator's autonomy level so the dispatcher runs
    /// `permissions::evaluate(PatchApplyToRepo, &policy_snapshot)` per task. Strict
    /// denies the task before any IO. For `ApplyOrigin::CliConfirmed` a
    /// `Confirm` decision degrades to Allow (the operator already
    /// confirmed by passing `--apply` at a TTY); for `DaemonScheduled` /
    /// `ChannelRequested` a `Confirm` is a HARD gate (apply refused until
    /// a real confirmation channel exists) — see the gate in
    /// `apply_patch_via_worktree`.
    pub fn with_policy(mut self, policy: crate::permissions::AutonomyPolicySnapshot) -> Self {
        self.autonomy_policy = Some(policy);
        self
    }

    #[cfg(test)]
    pub fn with_autonomy(self, level: crate::permissions::AutonomyLevel) -> Self {
        self.with_policy(crate::permissions::AutonomyPolicySnapshot::test_level(
            level,
        ))
    }

    /// Builder-style — flip the operator's test command on
    /// the config.
    pub fn with_test_cmd(mut self, cmd: impl Into<String>) -> Self {
        self.test_cmd = Some(cmd.into());
        self
    }

    /// Override the default 5-minute test timeout.
    pub fn with_test_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.test_timeout = timeout;
        self
    }

    /// Attach a live `WalWriterHandle` so Phase 4 emits
    /// `0xD3 PATCH_APPLIED` / `0xD4 PATCH_APPLY_FAILED`
    /// frames per task. The daemon's `cli::serve` path threads
    /// this in; CLI one-shot leaves it None.
    pub fn with_wal_writer(
        mut self,
        writer: std::sync::Arc<crate::wal::writer::WalWriterHandle>,
    ) -> Self {
        self.wal_writer = Some(writer);
        self
    }

    /// Attach an already-selected code-map database and the canonical root it
    /// was indexed for. This never discovers a database from CWD and is read
    /// only when an admitted patch is about to be applied.
    pub fn with_pre_apply_impact_advisory(
        mut self,
        database_path: impl Into<std::path::PathBuf>,
        root: crate::code_map::CanonicalRepoRoot,
        impact_options: crate::code_map::ImpactOptions,
    ) -> Self {
        self.pre_apply_impact_advisory = Some(PreApplyImpactAdvisoryConfig {
            database_path: database_path.into(),
            root,
            impact_options,
            coverage_options: crate::code_map::test_coverage::TestCoverageOptions::default(),
        });
        self
    }
}

/// Explicit dependency for the pre-worktree advisory.  Patch bytes, provider
/// data and worktree paths are deliberately absent: analysis consumes only the
/// already verified in-memory patch passed to the dispatcher.
#[derive(Clone, Debug)]
pub struct PreApplyImpactAdvisoryConfig {
    pub database_path: std::path::PathBuf,
    pub root: crate::code_map::CanonicalRepoRoot,
    pub impact_options: crate::code_map::ImpactOptions,
    pub coverage_options: crate::code_map::test_coverage::TestCoverageOptions,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PreApplyImpactAdvisoryState {
    Available,
    Unavailable(PreApplyImpactAdvisoryUnavailable),
}

/// Typed degradation is retained for operator audit, never converted into a
/// coverage claim. The state cannot affect permission, risk scoring or apply.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PreApplyImpactAdvisoryUnavailable {
    DatabaseUnavailable,
    RootOrGenerationUnavailable,
    Stale,
    CappedOrPartial,
    MalformedOrUnmappableInput,
    AnalysisFailed,
    ReceiptTooLarge,
}

#[derive(Clone, Debug)]
struct PreApplyImpactAdvisory {
    state: PreApplyImpactAdvisoryState,
    citation: Option<super::code_map_receipt::ImpactTestGapCitation>,
    diagnostic: Option<String>,
}

/// Per-dispatch aggregated outcome. Returned so the caller (likely
/// `neoth code`) can render a one-line operator summary.
#[derive(Debug, Default, Clone)]
pub struct DispatchOutcome {
    pub tasks_attempted: usize,
    pub tasks_completed: usize,
    pub tasks_blocked: usize,
    pub tasks_unassigned: usize,
    pub budget_exhausted: bool,
    /// Appended only after the dispatcher's durable success transition for a
    /// task. These identifiers make a joined cancellation result inspectable
    /// without inferring effects from an aggregate count.
    pub completed_task_ids: Vec<i64>,
    /// Subset whose task-scoped worktree apply and receipt attachment both
    /// succeeded. An empty patch deliberately does not enter this list.
    pub applied_task_ids: Vec<i64>,
    /// Tasks durably transitioned to Blocked during this pass.
    pub blocked_task_ids: Vec<i64>,
    /// Subset blocked because no worker was bound for their hemisphere.
    pub unassigned_task_ids: Vec<i64>,
}

/// Cooperative service cancellation. The dispatcher never drops an in-flight
/// batch: a caller that requests cancellation waits for its controlled worker
/// futures and receives every durable task effect that completed first.
pub trait DispatchCancellation {
    fn is_cancelled(&self) -> bool;

    /// A thread-safe live probe for the narrow admitted-effect interval. The
    /// async dispatcher still owns cancellation reporting; the blocking
    /// worktree helper receives only this boolean capability so it can refuse
    /// at its final pre-effect linearization point.
    fn effect_cancellation_probe(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchEffectReceipt {
    pub completed_task_ids: Vec<i64>,
    pub applied_task_ids: Vec<i64>,
    pub blocked_task_ids: Vec<i64>,
    pub unassigned_task_ids: Vec<i64>,
}

#[derive(Debug, Clone)]
pub enum CancellableDispatchOutcome {
    Completed(DispatchOutcome),
    Cancelled(DispatchEffectReceipt),
}

/// TASK-02 — hard wall-clock ceiling for a single `worker.execute()`
/// call. A provider that never returns (network hang, wedged local
/// model, deadlocked CLI subprocess) would otherwise pin its hemisphere
/// slot for the entire dispatch — and a `neoth code` ONE-SHOT has no
/// daemon `worker_watch` to reap it. Past this budget the dispatcher
/// abandons the call (dropping the future cancels the in-flight
/// request), marks the task `Blocked`, and emits `0x4D WORKER_DIED`.
/// 300s tracks the default test-timeout ballpark; exposing it as
/// `freedom.yaml::coding.task_timeout_secs` is a `config/mod.rs`
/// follow-up (ARCH-04 lane) — kept a const here to stay MY-LANE.
const WORKER_EXECUTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Run one dispatch pass over the session's BACKLOG tasks. Picks
/// BACKLOG tasks whose hemisphere has a bound worker, transitions
/// them to `InProgress`, fires the worker, transitions to `Review`
/// (or `Blocked` on `WorkerOutcome.failed()`). Stops at the first
/// budget breach. Returns the aggregated outcome.
///
/// Concurrency (COR-19): each loop iteration picks a BATCH of up to one
/// Backlog task per bound hemisphere and runs their `worker.execute()`
/// calls concurrently via `join_all` on this task (no `spawn` — `conn` is
/// !Sync but execute() is conn-free, so the connection never crosses a task
/// boundary). All DB writes + the per-session early-stop state stay serial:
/// task pick/transition before the batch, result processing after it.
pub async fn dispatch_session(
    conn: &Connection,
    session_id: KanbanSessionId,
    workers: &HemisphereWorkerSet,
    budget: DispatchBudget,
) -> Result<DispatchOutcome> {
    dispatch_session_with_apply(conn, session_id, workers, budget, None).await
}

/// Pick #6 Phase 4 — variant that also applies worker patches
/// inside a task-scoped git worktree when `apply_config` is
/// `Some`. The simple `dispatch_session` calls this with `None`
/// for backward-compat. New CLI surfaces (`neoth code --apply`)
/// call this directly.
pub async fn dispatch_session_with_apply(
    conn: &Connection,
    session_id: KanbanSessionId,
    workers: &HemisphereWorkerSet,
    budget: DispatchBudget,
    apply_config: Option<&DispatchApplyConfig>,
) -> Result<DispatchOutcome> {
    dispatch_session_with_apply_inner(conn, session_id, workers, budget, apply_config, None).await
}

/// Shared serial dispatcher body. The cancellable service path supplies its
/// token so cancellation is observed before every new batch and before each
/// durable completion/apply write; legacy callers retain the exact previous
/// behaviour by passing `None`.
async fn dispatch_session_with_apply_inner(
    conn: &Connection,
    session_id: KanbanSessionId,
    workers: &HemisphereWorkerSet,
    budget: DispatchBudget,
    apply_config: Option<&DispatchApplyConfig>,
    cancellation: Option<&dyn DispatchCancellation>,
) -> Result<DispatchOutcome> {
    let started = Instant::now();
    let mut outcome = DispatchOutcome::default();
    let mut retry_policy = WorkerRetryPolicy::new();
    // QU-01 (Session 28): per-session patch-spiral tracker. Composed
    // with retry_policy — retry rotates strategy hints, spiral
    // detector bails out of the rotation entirely when the worker
    // has produced N consecutive failing patches for the same task.
    // Greeting-regression detection is per-call inside
    // `handle_retryable_failure` so it doesn't need session state.
    let mut patch_spiral = crate::coding::early_stop::PatchSpiralTracker::new();
    // QU-01 Phase 3 (Session 28): per-task recent-output ring for the
    // repetition-loop detector. Each failed attempt pushes the
    // worker's reply text; `is_repetition_loop` checks the tail of
    // REPETITION_LOOP_MIN_SAMPLES for an identical-after-whitespace
    // wedge. Capped at REPETITION_RING_CAP entries per task so a
    // long-churning session doesn't grow the map unbounded.
    let mut recent_outputs: HashMap<KanbanTaskId, Vec<String>> = HashMap::new();

    if !workers.has_any() {
        warn!(
            session_id = session_id.raw(),
            "dispatch_session: no workers bound; nothing to do"
        );
        return Ok(outcome);
    }

    // C10a provenance: derive the durable patch namespace from the live
    // database selected by this dispatcher, not from a worker response. The
    // default views.db lives under ~/.neoth, while tests/custom instances get
    // an equally task-local audit root next to their explicit database.
    let audit_root = dispatch_audit_root(conn)?;

    // SD-02 (Round-3 v0.4) — best-effort WAL progress writer; no-op when
    // wal_writer is None (CLI one-shot without --apply). Computed once.
    let writer_for_progress = apply_config.and_then(|cfg| cfg.wal_writer.as_deref());
    'dispatch: loop {
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            break;
        }
        // Cycle-prevention Q4 — time + count budget. Defense in depth:
        // either cap stops the loop. Bail out before touching DB to
        // keep the metric accurate.
        if outcome.tasks_attempted >= budget.max_tasks {
            info!(
                session_id = session_id.raw(),
                tasks_attempted = outcome.tasks_attempted,
                "dispatch budget exhausted: task count cap"
            );
            outcome.budget_exhausted = true;
            break;
        }
        if started.elapsed() >= budget.max_duration {
            info!(
                session_id = session_id.raw(),
                elapsed_secs = started.elapsed().as_secs(),
                "dispatch budget exhausted: wall-clock cap"
            );
            outcome.budget_exhausted = true;
            break;
        }

        // COR-19: pick a BATCH of up to one Backlog task per bound
        // hemisphere (unbound-hemisphere tasks are Blocked inline by
        // pick_batch). The slow worker.execute() calls then run
        // CONCURRENTLY across hemispheres while everything that touches
        // `conn` or the per-session early-stop state stays serial.
        // `conn` is !Sync but execute() is conn-free, so the connection
        // never crosses a task boundary — no Arc<Mutex<Connection>> needed.
        let batch = pick_batch(conn, session_id, workers, &mut outcome)?;
        if batch.is_empty() {
            break;
        }
        // `pick_batch` can durably block unbound work, but cancellation must
        // stop before selected tasks enter InProgress or any provider starts.
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            break;
        }

        // Trim to the remaining task budget so a multi-hemisphere batch
        // can't overshoot max_tasks; untaken tasks stay Backlog and the
        // next iteration's top-of-loop check then trips the cap.
        let remaining = budget.max_tasks.saturating_sub(outcome.tasks_attempted);
        let mut batch: Vec<KanbanTask> = batch.into_iter().take(remaining).collect();
        if batch.is_empty() {
            outcome.budget_exhausted = true;
            break;
        }

        // Task comments → worker prompt. Notes ride the IN-MEMORY task
        // description (rendered verbatim by build_task_prompt) so the
        // conn-free Worker trait stays untouched; the stored row is never
        // rewritten. A failed comment read degrades to a plain dispatch.
        for task in &mut batch {
            match store::list_comments_for_task(conn, task.task_id) {
                Ok(comments) => append_task_notes(task, &comments),
                Err(e) => warn!(
                    task_id = task.task_id.raw(),
                    error = %e,
                    "list_comments_for_task failed; dispatching without notes"
                ),
            }
        }

        // Transition every batch task Backlog → InProgress + emit the
        // 0x77 KANBAN_TASK_PROGRESS(0,"dispatched") frame BEFORE any
        // execute() starts (serial DB; mirrors the per-task pre-fix
        // behaviour even if a worker later crashes).
        let now_ns = now_unix_ns();
        for task in &batch {
            store::patch_task_status(conn, task.task_id, TaskStatus::InProgress, now_ns)
                .context("transition Backlog → InProgress (batch)")?;
            emit_kanban_task_progress_wal(writer_for_progress, task, 0, "dispatched");
        }
        outcome.tasks_attempted += batch.len();

        // Run the batch's worker.execute() calls CONCURRENTLY on THIS
        // task via join_all (no tokio::spawn → no Send/'static bound;
        // `conn` stays put). pick_batch guarantees one task per
        // hemisphere, so no worker is invoked concurrently with itself.
        let exec_futures: Vec<_> = batch
            .iter()
            .map(|task| {
                let worker = workers
                    .get(task.hemisphere)
                    .expect("pick_batch only returns tasks whose hemisphere has a bound worker");
                // ADOPT31-C10a: bind this exact selected task and worker
                // BEFORE execute. The context is dispatcher-owned (not a
                // provider-returned string) and accompanies the result until
                // the post-execute contract gate below.
                let contract = WorkerContract::for_dispatch(task, worker, &audit_root);
                // TASK-02: hard per-worker timeout. Dropping the timeout
                // future on Elapsed cancels the in-flight provider call, so
                // a hung hemisphere can't stall the whole join_all batch.
                async move {
                    (
                        contract,
                        tokio::time::timeout(WORKER_EXECUTE_TIMEOUT, worker.execute(task)).await,
                    )
                }
            })
            .collect();
        let exec_results = futures_util::future::join_all(exec_futures).await;

        // Process each (task, result) SERIALLY — the per-session
        // early-stop state (retry_policy / patch_spiral / recent_outputs)
        // and all `conn` writes happen here, one task at a time, so the
        // match arms below are byte-identical to the pre-COR-19 serial loop.
        let mut completed_batch = batch.into_iter().zip(exec_results);
        while let Some((task, (contract, timed_result))) = completed_batch.next() {
            if cancellation.is_some_and(|token| token.is_cancelled()) {
                // The provider futures above have all settled. Their outputs
                // have not yet crossed a durable result/apply boundary, so
                // restore every untouched task to Backlog and acknowledge the
                // cancellation with only effects that completed earlier.
                let now_ns = now_unix_ns();
                store::patch_task_status(conn, task.task_id, TaskStatus::Backlog, now_ns)
                    .context("restore cancelled dispatch task to Backlog")?;
                for (pending, _) in completed_batch {
                    store::patch_task_status(conn, pending.task_id, TaskStatus::Backlog, now_ns)
                        .context("restore cancelled dispatch batch task to Backlog")?;
                }
                break 'dispatch;
            }
            // TASK-02: unwrap the per-worker timeout layer first. A hung
            // worker (Elapsed) is a HARD block — a wall-clock hang is not a
            // transient retryable error, so it goes straight to Blocked +
            // 0x4D WORKER_DIED rather than burning the retry rotation. A
            // worker that finished within budget yields its own Result,
            // handled byte-identically by the arms below.
            let exec_result = match timed_result {
                Ok(r) => r,
                Err(_elapsed) => {
                    let now_ns = now_unix_ns();
                    if let Err(e) =
                        store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns)
                    {
                        tracing::warn!(
                            task_id = task.task_id.raw(),
                            error = %e,
                            "transition InProgress → Blocked (worker timeout) failed"
                        );
                    }
                    outcome.tasks_blocked += 1;
                    outcome.blocked_task_ids.push(task.task_id.raw());
                    patch_spiral.record(task.task_id, false);
                    warn!(
                        task_id = task.task_id.raw(),
                        timeout_secs = WORKER_EXECUTE_TIMEOUT.as_secs(),
                        "worker.execute() exceeded per-task timeout; Blocked + 0x4D WORKER_DIED"
                    );
                    emit_worker_died_wal(writer_for_progress, &task, WORKER_EXECUTE_TIMEOUT);
                    continue;
                }
            };
            // ADOPT31-C10a: this is the sole untrusted WorkerOutcome gate,
            // immediately after Worker::execute returns and before refusal/
            // review classification, retry artifact attachment, SQLite
            // artifact storage, or a worktree apply can observe its content.
            // A violation intentionally supplies NO partial outcome and only
            // a fixed diagnostic to the existing retry/blocked machinery;
            // otherwise that machinery would persist the rejected patch/path
            // during its retry rotation.
            let exec_result = match exec_result {
                Ok(o) => {
                    let worker = workers
                        .get(task.hemisphere)
                        .expect("selected task's bound worker remains available during dispatch");
                    let accepted = match contract.validate_and_materialize(&task, worker, o) {
                        Ok(accepted) => accepted,
                        Err(violation) => {
                            patch_spiral.record(task.task_id, false);
                            record_recent_output(
                                &mut recent_outputs,
                                task.task_id,
                                "worker contract violation",
                            );
                            let recent = recent_output_refs(&recent_outputs, task.task_id);
                            warn!(
                                task_id = task.task_id.raw(),
                                violation = violation.as_str(),
                                "worker result rejected by central contract; retrying or blocking without result content"
                            );
                            handle_retryable_failure(
                                conn,
                                &task,
                                &mut retry_policy,
                                &mut patch_spiral,
                                &recent,
                                &mut outcome,
                                "worker result rejected by central contract",
                                None,
                            )?;
                            continue;
                        }
                    };
                    Ok(accepted)
                }
                Err(e) => Err(e),
            };
            match exec_result {
                // QU-01 harte-Kritik fix (Session 28): a refusal can
                // arrive STRUCTURALLY review-ready — the worker emits
                // "Sorry, I can't help with that" as non-empty
                // patch_text, so `review_ready()` is true even though
                // the content is a refusal. Without this arm, the
                // no-`--apply` path below promotes it straight to Review
                // (the apply path would catch it on `git apply` rejection,
                // but the no-apply path never looked at content). Route
                // any review-ready-but-refusal outcome into the failure
                // path so `handle_retryable_failure`'s greeting-regression
                // check fires + the task lands Blocked instead of landing
                // a refusal as Review material.
                Ok(o)
                    if o.review_ready()
                        && (crate::coding::early_stop::is_refusal_or_capability_disclaimer(
                            &o.patch_text,
                        )
                            || crate::coding::early_stop::is_refusal_or_capability_disclaimer(
                                &o.summary,
                            )) =>
                {
                    patch_spiral.record(task.task_id, false);
                    record_recent_output(
                        &mut recent_outputs,
                        task.task_id,
                        &worker_output_text(&o),
                    );
                    let recent = recent_output_refs(&recent_outputs, task.task_id);
                    handle_retryable_failure(
                        conn,
                        &task,
                        &mut retry_policy,
                        &mut patch_spiral,
                        &recent,
                        &mut outcome,
                        "worker reply was a refusal disguised as patch output",
                        Some(&o),
                    )?;
                }
                Ok(o) if o.review_ready() => {
                    // Q2 streaming: batched — one TASK_COMPLETED frame at
                    // end. SD-02 (Round-3 v0.4) added 0x77 KANBAN_TASK_PROGRESS
                    // heartbeats at task pick-up (above) + review-ready
                    // (below) so `neoth kanban watch` shows progress
                    // between status changes. 30s background heartbeat
                    // (mid-execute) lands in a future sprint.
                    emit_kanban_task_progress_wal(writer_for_progress, &task, 100, "review_ready");
                    // GR-021: route the original apply-outcome persistence error
                    // through the normal retry path, so a recoverable failure
                    // can land Backlog/Blocked. If that recovery's own durable
                    // mutation fails, its Result is intentionally propagated
                    // rather than silently stranding this InProgress task.
                    if let Err(e) = apply_outcome(conn, &task, &o) {
                        patch_spiral.record(task.task_id, false);
                        record_recent_output(
                            &mut recent_outputs,
                            task.task_id,
                            &worker_output_text(&o),
                        );
                        let recent = recent_output_refs(&recent_outputs, task.task_id);
                        let diagnosis =
                            format!("apply_outcome DB write failed (task-stranding guard): {e}");
                        handle_retryable_failure(
                            conn,
                            &task,
                            &mut retry_policy,
                            &mut patch_spiral,
                            &recent,
                            &mut outcome,
                            &diagnosis,
                            Some(&o),
                        )?;
                        continue;
                    }

                    // Pick #6 Phase 4: opt-in real-apply path. When the
                    // operator passed `--apply` the dispatcher creates a
                    // task-scoped git worktree, runs git apply, and only
                    // promotes to Review when both succeed. On apply
                    // rejection the task is treated as a retryable
                    // failure with git's stderr as the diagnosis hint.
                    if let Some(cfg) = apply_config {
                        #[cfg(test)]
                        cfg.pause_for_test(PatchApplyPausePoint::BeforeGate).await;
                        // This is the cancellation linearization point before
                        // any final PatchApplyToRepo decision. The accepted
                        // worker result has not yet been authorized for a
                        // worktree effect, so restore it to Backlog without
                        // creating a new permission decision.
                        if cancellation.is_some_and(|token| token.is_cancelled()) {
                            let now_ns = now_unix_ns();
                            store::patch_task_status(
                                conn,
                                task.task_id,
                                TaskStatus::Backlog,
                                now_ns,
                            )
                            .context("restore cancelled task before patch authorization")?;
                            for (pending, _) in completed_batch {
                                store::patch_task_status(
                                    conn,
                                    pending.task_id,
                                    TaskStatus::Backlog,
                                    now_ns,
                                )
                                .context("restore cancelled dispatch batch task to Backlog")?;
                            }
                            break 'dispatch;
                        }
                        // Offload the blocking apply (git subprocesses +
                        // run_worktree_tests' process-poll loop with
                        // std::thread::sleep) to a blocking thread so it never
                        // stalls the async worker / serialises concurrent
                        // sessions on the runtime (GOLD-SEC-05 / A-05). The
                        // dispatcher stays async; only this sync sub-call moves
                        // off the executor. All three args are Clone, so the
                        // 'static + Send closure clones them rather than
                        // borrowing `conn` (which is !Send).
                        let admission = authorize_patch_apply_before_worktree(&task, &o, cfg).await;
                        #[cfg(test)]
                        cfg.pause_for_test(PatchApplyPausePoint::AfterAdmission)
                            .await;
                        // Gate admission is durable history. A cancellation
                        // that arrives after that await consumes no worktree
                        // capability: preserve the decision, restore Backlog,
                        // and do not start a blocking effect.
                        if cancellation.is_some_and(|token| token.is_cancelled()) {
                            let now_ns = now_unix_ns();
                            store::patch_task_status(
                                conn,
                                task.task_id,
                                TaskStatus::Backlog,
                                now_ns,
                            )
                            .context("restore cancelled task after patch authorization")?;
                            for (pending, _) in completed_batch {
                                store::patch_task_status(
                                    conn,
                                    pending.task_id,
                                    TaskStatus::Backlog,
                                    now_ns,
                                )
                                .context("restore cancelled dispatch batch task to Backlog")?;
                            }
                            break 'dispatch;
                        }
                        let cancellation_probe =
                            cancellation.and_then(|token| token.effect_cancellation_probe());
                        let apply_res = match admission {
                            // A NoPatch outcome has no worktree effect and therefore no
                            // PatchApplyToRepo decision.
                            Ok(None) => Ok(()),
                            Ok(Some(admission)) => {
                                let task_c = task.clone();
                                let outcome_c = o.clone();
                                let cfg_c = cfg.clone();
                                tokio::task::spawn_blocking(move || {
                                    apply_admitted_patch_in_worktree(
                                        admission,
                                        &task_c,
                                        &outcome_c,
                                        &cfg_c,
                                        cancellation_probe,
                                    )
                                })
                                .await
                                .unwrap_or_else(|e| Err(format!("apply task panicked: {e}")))
                            }
                            Err(error) => Err(error),
                        };
                        match apply_res {
                            Ok(()) => {
                                outcome.tasks_completed += 1;
                                retry_policy.reset(task.task_id);
                                patch_spiral.record(task.task_id, true);
                                // GOLD-COR-03 / A-10: the patch really landed in a
                                // worktree and — when a test command was configured —
                                // its suite ran green there. Do NOT copy the provider's
                                // claimed per-test counts and merely stamp them trusted:
                                // the only directly observed fact is one successful
                                // command receipt. Without a `test_cmd` no suite ran,
                                // so the self-reported summary remains unverified.
                                // GR-002: an EMPTY patch is a no-op — apply_patch_via_worktree
                                // returned Ok WITHOUT applying anything or running the
                                // worktree suite, so the worker's self-reported green
                                // summary has NO verification behind it. `applied` stays
                                // false for an empty patch so it can't auto-promote.
                                let verified = if apply_is_test_verified(
                                    cfg.test_cmd.is_some(),
                                    &o.patch_text,
                                ) {
                                    TestSummary::verified_command_passed()
                                } else {
                                    o.tests
                                };
                                store::attach_task_artifact(
                                    conn,
                                    task.task_id,
                                    o.patch_path(),
                                    Some(verified),
                                )
                                .context("attach dispatcher-verified test receipt")?;
                                // Both worktree apply and the durable task
                                // receipt succeeded. Only now may a joined
                                // cancellation report this task as applied.
                                if !o.patch_text.trim().is_empty() {
                                    outcome.applied_task_ids.push(task.task_id.raw());
                                }
                                outcome.completed_task_ids.push(task.task_id.raw());
                            }
                            Err(diagnosis) if diagnosis == APPLY_CANCELLED_BEFORE_WORKTREE => {
                                // The blocking helper was joined but observed cancellation
                                // immediately before `create_task_worktree`; no effect was
                                // started, so this task resumes as Backlog rather than entering
                                // retry/block accounting.
                                let now_ns = now_unix_ns();
                                store::patch_task_status(
                                    conn,
                                    task.task_id,
                                    TaskStatus::Backlog,
                                    now_ns,
                                )
                                .context("restore cancelled admitted task to Backlog")?;
                                for (pending, _) in completed_batch {
                                    store::patch_task_status(
                                        conn,
                                        pending.task_id,
                                        TaskStatus::Backlog,
                                        now_ns,
                                    )
                                    .context("restore cancelled dispatch batch task to Backlog")?;
                                }
                                break 'dispatch;
                            }
                            Err(diagnosis) => {
                                patch_spiral.record(task.task_id, false);
                                record_recent_output(
                                    &mut recent_outputs,
                                    task.task_id,
                                    &worker_output_text(&o),
                                );
                                let recent = recent_output_refs(&recent_outputs, task.task_id);
                                handle_retryable_failure(
                                    conn,
                                    &task,
                                    &mut retry_policy,
                                    &mut patch_spiral,
                                    &recent,
                                    &mut outcome,
                                    &diagnosis,
                                    Some(&o),
                                )?;
                            }
                        }
                    } else {
                        outcome.tasks_completed += 1;
                        retry_policy.reset(task.task_id);
                        patch_spiral.record(task.task_id, true);
                        // Productive completion resets the repetition ring
                        // so a later unrelated failure on the same task id
                        // (rare, but possible after re-queue) starts fresh.
                        recent_outputs.remove(&task.task_id);
                        outcome.completed_task_ids.push(task.task_id.raw());
                    }
                }
                Ok(o) => {
                    // Outcome reached us but `failed()` (empty patch +
                    // zero tests) — treat as a retryable failure +
                    // count toward the patch-spiral + repetition ring.
                    patch_spiral.record(task.task_id, false);
                    record_recent_output(
                        &mut recent_outputs,
                        task.task_id,
                        &worker_output_text(&o),
                    );
                    let recent = recent_output_refs(&recent_outputs, task.task_id);
                    handle_retryable_failure(
                        conn,
                        &task,
                        &mut retry_policy,
                        &mut patch_spiral,
                        &recent,
                        &mut outcome,
                        "worker returned empty outcome",
                        Some(&o),
                    )?;
                }
                Err(e) => {
                    // Worker-execute error counts as a patch failure
                    // (no usable patch was produced this attempt). The
                    // error string is the "output" for repetition-loop
                    // purposes — a worker that keeps erroring identically
                    // is wedged just as surely as one that re-emits the
                    // same patch.
                    patch_spiral.record(task.task_id, false);
                    let err_text = format!("worker execute failed: {e}");
                    record_recent_output(&mut recent_outputs, task.task_id, &err_text);
                    let recent = recent_output_refs(&recent_outputs, task.task_id);
                    handle_retryable_failure(
                        conn,
                        &task,
                        &mut retry_policy,
                        &mut patch_spiral,
                        &recent,
                        &mut outcome,
                        &err_text,
                        None,
                    )?;
                }
            }
        }
    }

    info!(
        session_id = session_id.raw(),
        attempted = outcome.tasks_attempted,
        completed = outcome.tasks_completed,
        blocked = outcome.tasks_blocked,
        unassigned = outcome.tasks_unassigned,
        budget_exhausted = outcome.budget_exhausted,
        "dispatch session complete"
    );
    Ok(outcome)
}

/// Cancellation-aware service entry point. The existing dispatcher keeps its
/// serial SQLite ownership and joins every started worker/apply future. A
/// cancellation observed before entry has no dispatch effects; one observed
/// while it is running is acknowledged only after the full pass settles and
/// returns the exact durable IDs accumulated by that pass.
pub async fn dispatch_session_with_apply_cancellable(
    conn: &Connection,
    session_id: KanbanSessionId,
    workers: &HemisphereWorkerSet,
    budget: DispatchBudget,
    apply_config: Option<&DispatchApplyConfig>,
    cancellation: &dyn DispatchCancellation,
) -> Result<CancellableDispatchOutcome> {
    if cancellation.is_cancelled() {
        return Ok(CancellableDispatchOutcome::Cancelled(
            DispatchEffectReceipt {
                completed_task_ids: Vec::new(),
                applied_task_ids: Vec::new(),
                blocked_task_ids: Vec::new(),
                unassigned_task_ids: Vec::new(),
            },
        ));
    }
    let outcome = dispatch_session_with_apply_inner(
        conn,
        session_id,
        workers,
        budget,
        apply_config,
        Some(cancellation),
    )
    .await?;
    if cancellation.is_cancelled() {
        return Ok(CancellableDispatchOutcome::Cancelled(
            DispatchEffectReceipt {
                completed_task_ids: outcome.completed_task_ids.clone(),
                applied_task_ids: outcome.applied_task_ids.clone(),
                blocked_task_ids: outcome.blocked_task_ids.clone(),
                unassigned_task_ids: outcome.unassigned_task_ids.clone(),
            },
        ));
    }
    Ok(CancellableDispatchOutcome::Completed(outcome))
}

/// Resolve the dispatcher-owned audit root from the *live* main SQLite
/// database. This is deliberately independent of worker/provider settings:
/// the same database that owns the task/session rows owns their patch
/// artifacts. Production in-memory databases have no durable parent and fail
/// closed rather than accepting a worker-selected fallback path; `cfg(test)`
/// uses an isolated temporary namespace solely for focused unit coverage.
fn dispatch_audit_root(conn: &Connection) -> Result<std::path::PathBuf> {
    let mut statement = conn
        .prepare("PRAGMA database_list")
        .context("inspect main database for coding artifact root")?;
    let mut rows = statement
        .query([])
        .context("query main database for coding artifact root")?;
    while let Some(row) = rows
        .next()
        .context("read main database for coding artifact root")?
    {
        let name: String = row
            .get(1)
            .context("read database name for coding artifact root")?;
        if name != "main" {
            continue;
        }
        let db_path: String = row
            .get(2)
            .context("read main database path for coding artifact root")?;
        if db_path.is_empty() {
            #[cfg(test)]
            {
                // Focused in-memory unit tests have no on-disk database
                // parent. Keep their artifacts in a named test-only temporary
                // namespace; production has no such fallback and fails closed
                // below.
                let root = std::env::temp_dir().join("neoth-dispatch-in-memory-tests");
                std::fs::create_dir_all(&root).context("create test-only coding artifact root")?;
                return Ok(root);
            }
            #[cfg(not(test))]
            anyhow::bail!("main database has no durable parent for coding artifacts");
        }
        let path = std::path::PathBuf::from(db_path);
        let path = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .context("resolve relative main database for coding artifacts")?
                .join(path)
        };
        if let Some(root) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
        {
            return Ok(root);
        }
        anyhow::bail!("main database has no durable parent for coding artifacts");
    }
    anyhow::bail!("main database is unavailable for coding artifact root")
}

/// COR-19: pick one Backlog task per BOUND hemisphere in a single pass.
///
/// Unbound-hemisphere Backlog tasks are transitioned Backlog → Blocked
/// inline (serial DB) and counted in `outcome.tasks_unassigned` — the
/// same action the pre-COR-19 serial loop took per task. For each
/// hemisphere that HAS a bound worker, at most one Backlog task is
/// selected (the first in `list_tasks_for_session` order); additional
/// same-hemisphere tasks stay Backlog and are picked in a later batch.
/// The returned batch therefore has at most one task per hemisphere, so
/// the concurrent execute() phase never invokes a worker concurrently
/// with itself. An empty return means no runnable Backlog tasks remain.
fn pick_batch(
    conn: &Connection,
    session_id: KanbanSessionId,
    workers: &HemisphereWorkerSet,
    outcome: &mut DispatchOutcome,
) -> Result<Vec<KanbanTask>> {
    // GOLD-HON-18: SQL filters to Backlog (no fetch-all + Rust status scan).
    let tasks = store::list_backlog_tasks_for_session(conn, session_id)
        .context("list_backlog_tasks_for_session for pick_batch")?;
    let mut claimed: std::collections::HashSet<Hemisphere> = std::collections::HashSet::new();
    let mut batch: Vec<KanbanTask> = Vec::new();
    let now_ns = now_unix_ns();
    for t in tasks {
        if workers.get(t.hemisphere).is_none() {
            // No worker bound for this hemisphere — Block it (mirrors the
            // pre-COR-19 serial path's no-worker arm).
            outcome.tasks_unassigned += 1;
            store::patch_task_status(conn, t.task_id, TaskStatus::Blocked, now_ns)
                .context("transition Backlog → Blocked (no worker)")?;
            outcome.blocked_task_ids.push(t.task_id.raw());
            outcome.unassigned_task_ids.push(t.task_id.raw());
            continue;
        }
        // `insert` returns false when the hemisphere is already claimed
        // for this batch — leave that task Backlog for a future iteration.
        if claimed.insert(t.hemisphere) {
            batch.push(t);
        }
    }
    Ok(batch)
}

/// Persist the worker outcome to the task row + transition status.
/// `Review` when the outcome is review-ready, `Blocked` when the
/// worker bailed out with both an empty patch + zero tests.
/// Pick #6 Phase 4 (2026-05-21): create a task-scoped git
/// worktree, refuse if it's dirty, apply the patch. Returns Ok
/// on success, Err with an operator-readable diagnosis string
/// (suitable for `handle_retryable_failure`'s `diagnosis` arg)
/// on any apply or worktree failure.
///
/// The worktree is intentionally LEFT in place on success so
/// the operator can inspect / cherry-pick the applied diff
/// against their main checkout. Cleanup is operator-driven via
/// `neoth code --cleanup-worktree <task_id>` (lands as a CLI
/// follow-up). Tests + GUI surfaces in v0.3 add automatic
/// cleanup on successful Review → Done transitions.
/// Private capability created only after the authoritative Gate has appended
/// its authenticated decision.  There is intentionally no public constructor
/// and no raw-input worktree helper.
struct AdmittedPatchApply {
    target: crate::code_map::CanonicalRepoRoot,
    task_id: KanbanTaskId,
    accepted_patch_sha256: [u8; 32],
    request_binding_sha256: String,
}

/// Internal outcome used only to distinguish a joined, pre-effect
/// cancellation from an actual apply failure. It is never persisted or exposed
/// as a worker diagnostic.
const APPLY_CANCELLED_BEFORE_WORKTREE: &str = "patch apply cancelled before worktree creation";

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PatchApplyPausePoint {
    BeforeGate,
    AfterAdmission,
    AfterGuiApprovalBeforeFreshDescriptor,
}

#[cfg(test)]
struct PatchApplyPause {
    point: PatchApplyPausePoint,
    entered: std::sync::atomic::AtomicBool,
    entered_notify: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

/// Perform the sole final decision immediately before the first worktree
/// effect.  The Gate owns the legacy permission pair and typed HMAC-backed
/// TrustDecision; this dispatcher must not append a second decision.
async fn authorize_patch_apply_before_worktree(
    task: &KanbanTask,
    outcome: &AcceptedWorkerOutcome,
    cfg: &DispatchApplyConfig,
) -> std::result::Result<Option<AdmittedPatchApply>, String> {
    if outcome.patch_state() == WorkerPatchState::NoPatch {
        return Ok(None);
    }
    let patch = outcome
        .patch_text()
        .ok_or_else(|| "accepted patch outcome has no immutable patch bytes".to_string())?;
    let initial_target = crate::code_map::CanonicalRepoRoot::discover(&cfg.repo_root)
        .map_err(|error| format!("canonical repository validation failed before apply: {error}"))?;
    let policy = cfg.autonomy_policy.as_ref().ok_or_else(|| {
        "patch apply requires an immutable autonomy policy before worktree creation".to_string()
    })?;
    let writer = cfg.wal_writer.as_deref().ok_or_else(|| {
        "patch apply requires a home-backed permission audit writer before worktree creation"
            .to_string()
    })?;
    let initial_patch_sha256: [u8; 32] = Sha256::digest(patch.as_bytes()).into();
    let initial_binding = patch_apply_request_binding(
        initial_target.identity().as_str(),
        task.task_id,
        &initial_patch_sha256,
        cfg.origin,
    );
    let (target, accepted_patch_sha256, binding, confirmation_source) = match cfg.confirmation {
        ApplyConfirmation::LocalCliFlag => (
            initial_target,
            initial_patch_sha256,
            initial_binding,
            Some("local_cli_code_apply_flag"),
        ),
        ApplyConfirmation::GuiInteractive => {
            let broker = cfg.gui_patch_approval.as_ref().ok_or_else(|| {
                "native GUI patch apply is missing its run-owned approval broker".to_owned()
            })?;
            let grant = broker
                .request_exact(
                    initial_target.identity().as_str(),
                    initial_target.path().display().to_string(),
                    task.task_id,
                    patch,
                    initial_binding,
                )
                .await?;
            #[cfg(test)]
            cfg.pause_for_test(PatchApplyPausePoint::AfterGuiApprovalBeforeFreshDescriptor)
                .await;
            // The GUI could wait for up to the approval TTL. Reconstruct the
            // physical target and exact descriptor only after that wait; a
            // replaced root must fail before it creates Gate history.
            let target =
                crate::code_map::CanonicalRepoRoot::discover(&cfg.repo_root).map_err(|error| {
                    format!("canonical repository changed during native patch approval: {error}")
                })?;
            let accepted_patch_sha256: [u8; 32] = Sha256::digest(patch.as_bytes()).into();
            let binding = patch_apply_request_binding(
                target.identity().as_str(),
                task.task_id,
                &accepted_patch_sha256,
                cfg.origin,
            );
            if !grant.matches(
                target.identity().as_str(),
                task.task_id,
                &accepted_patch_sha256,
                &binding,
            ) {
                return Err(
                    "native GUI approval grant did not bind this exact patch apply".to_owned(),
                );
            }
            grant.ensure_active()?;
            // The broker grant is private and one-use. This source is written
            // only after it matched the canonical root, task, patch digest,
            // and existing request binding above.
            (
                target,
                accepted_patch_sha256,
                binding,
                Some("native_gui_patch_approval"),
            )
        }
        ApplyConfirmation::Unattended => {
            (initial_target, initial_patch_sha256, initial_binding, None)
        }
    };
    let action = crate::permissions::Action::PatchApplyToRepo {
        repo_root: target.path().to_path_buf(),
        task_id: task.task_id.raw() as u64,
    };
    let mut gate = crate::permissions::Gate::for_policy(policy.clone())
        .with_confirm(crate::permissions::ConfirmStrategy::FailClosed);
    if let Some(confirmation_source) = confirmation_source {
        gate = gate.with_preconfirmed_confirmation(confirmation_source);
    }
    gate.check_with_audit_sink(
        &action,
        crate::permissions::PermissionAuditSink::Writer(writer),
        true,
        Some(&binding),
    )
    .await
    .map_err(|error| {
        format!(
            "permission gate blocked apply for task {}: {error}",
            task.task_id.raw()
        )
    })?;
    Ok(Some(AdmittedPatchApply {
        target,
        task_id: task.task_id,
        accepted_patch_sha256,
        request_binding_sha256: binding,
    }))
}

/// Stable, unambiguous binding for the physical repository, exact accepted
/// patch bytes, task, and observable apply origin.  It deliberately excludes
/// raw paths, titles, source labels, and provider content.
fn patch_apply_request_binding(
    repo_identity: &str,
    task_id: KanbanTaskId,
    accepted_patch_sha256: &[u8; 32],
    origin: ApplyOrigin,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth.permissions.patch-apply.v1\0");
    let identity = repo_identity.as_bytes();
    digest.update(
        u32::try_from(identity.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    digest.update(identity);
    digest.update((task_id.raw() as u64).to_be_bytes());
    digest.update(accepted_patch_sha256);
    digest.update([match origin {
        ApplyOrigin::CliConfirmed => 1,
        ApplyOrigin::DaemonScheduled => 2,
        ApplyOrigin::ChannelRequested => 3,
        ApplyOrigin::GuiRequested => 4,
    }]);
    hex::encode(digest.finalize())
}

const MAX_PRE_APPLY_IMPACT_ADVISORY_WAL_BYTES: usize = 24 * 1024;
const MAX_PRE_APPLY_IMPACT_DIAGNOSTIC_BYTES: usize = 512;

/// Analyze the already admitted in-memory patch before a worktree exists.
/// Every failure deliberately degrades to a typed informational state; this
/// function must never change the risk gate or the apply decision.
fn pre_apply_impact_advisory(
    config: Option<&PreApplyImpactAdvisoryConfig>,
    current_target: &crate::code_map::CanonicalRepoRoot,
    patch_text: &str,
) -> Option<PreApplyImpactAdvisory> {
    let config = config?;
    if config.root != *current_target {
        return Some(PreApplyImpactAdvisory {
            state: PreApplyImpactAdvisoryState::Unavailable(
                PreApplyImpactAdvisoryUnavailable::RootOrGenerationUnavailable,
            ),
            citation: None,
            diagnostic: Some(
                "configured code-map root differs from admitted repository".to_owned(),
            ),
        });
    }
    let conn = match crate::code_map::persist::open_read_only(&config.database_path) {
        Ok(conn) => conn,
        Err(error) => {
            return Some(unavailable_pre_apply_impact_advisory(
                PreApplyImpactAdvisoryUnavailable::DatabaseUnavailable,
                error,
            ));
        }
    };
    let request = crate::code_map::DiffImpactRequest {
        repo_root: current_target.path().to_path_buf(),
        input: crate::code_map::DiffImpactInput::stdin(patch_text.to_owned()),
        options: config.impact_options,
    };
    let impact = match crate::code_map::analyze_diff_impact(&conn, &request) {
        Ok(impact) => impact,
        Err(error) => {
            return Some(unavailable_pre_apply_impact_advisory(
                classify_pre_apply_impact_error(&error.to_string()),
                error,
            ));
        }
    };
    let diff = match super::code_map_receipt::DiffImpactCitation::from_receipt(&impact) {
        Ok((citation, _metadata_redacted)) => citation,
        Err(error) => {
            return Some(unavailable_pre_apply_impact_advisory(
                classify_pre_apply_impact_error(&error.to_string()),
                error,
            ));
        }
    };
    let gap = match crate::code_map::test_coverage::test_gap_for_impact(
        &conn,
        &impact.impact,
        config.coverage_options.clone(),
    ) {
        Ok(gap) => gap,
        Err(error) => {
            return Some(unavailable_pre_apply_impact_advisory(
                PreApplyImpactAdvisoryUnavailable::AnalysisFailed,
                error,
            ));
        }
    };
    match super::code_map_receipt::ImpactTestGapCitation::from_result(
        &diff,
        current_target.identity().as_str(),
        &gap,
    ) {
        Ok(citation) => Some(PreApplyImpactAdvisory {
            state: PreApplyImpactAdvisoryState::Available,
            citation: Some(citation),
            diagnostic: None,
        }),
        Err(error) => Some(unavailable_pre_apply_impact_advisory(
            classify_pre_apply_impact_error(&error.to_string()),
            error,
        )),
    }
}

fn unavailable_pre_apply_impact_advisory(
    state: PreApplyImpactAdvisoryUnavailable,
    error: impl std::fmt::Display,
) -> PreApplyImpactAdvisory {
    let diagnostic = crate::security::redact::sanitize_tool_output(&error.to_string());
    PreApplyImpactAdvisory {
        state: PreApplyImpactAdvisoryState::Unavailable(state),
        citation: None,
        diagnostic: Some(
            diagnostic
                .chars()
                .take(MAX_PRE_APPLY_IMPACT_DIAGNOSTIC_BYTES)
                .collect(),
        ),
    }
}

fn classify_pre_apply_impact_error(error: &str) -> PreApplyImpactAdvisoryUnavailable {
    if error.contains("stale") {
        PreApplyImpactAdvisoryUnavailable::Stale
    } else if error.contains("truncated") || error.contains("capped") || error.contains("partial") {
        PreApplyImpactAdvisoryUnavailable::CappedOrPartial
    } else if error.contains("no persisted")
        || error.contains("generation")
        || error.contains("root identity")
    {
        PreApplyImpactAdvisoryUnavailable::RootOrGenerationUnavailable
    } else if error.contains("stdin") || error.contains("mappable") || error.contains("diff") {
        PreApplyImpactAdvisoryUnavailable::MalformedOrUnmappableInput
    } else {
        PreApplyImpactAdvisoryUnavailable::AnalysisFailed
    }
}

/// Produce a bounded audit value that intentionally has no patch, source,
/// prompt, provider, or worktree content. W48 citations have already
/// sanitized their metadata; unavailable diagnostics are redacted above.
fn pre_apply_impact_advisory_wal_value(
    advisory: Option<&PreApplyImpactAdvisory>,
) -> serde_json::Value {
    let Some(advisory) = advisory else {
        return serde_json::json!({ "state": "not_configured" });
    };
    let value = serde_json::json!({
        "state": &advisory.state,
        "citation": &advisory.citation,
        "diagnostic": &advisory.diagnostic,
    });
    match serde_json::to_vec(&value) {
        Ok(serialized) if serialized.len() <= MAX_PRE_APPLY_IMPACT_ADVISORY_WAL_BYTES => value,
        _ => serde_json::json!({
            "state": PreApplyImpactAdvisoryState::Unavailable(
                PreApplyImpactAdvisoryUnavailable::ReceiptTooLarge,
            ),
        }),
    }
}

fn log_pre_apply_impact_advisory(task: &KanbanTask, advisory: Option<&PreApplyImpactAdvisory>) {
    let Some(advisory) = advisory else {
        return;
    };
    match (&advisory.state, &advisory.citation) {
        (PreApplyImpactAdvisoryState::Available, Some(citation)) => {
            for node in &citation.nodes {
                if node.coverage_unknown {
                    info!(task_id = task.task_id.raw(), path = %node.impact_node.path, symbol = %node.impact_node.symbol, "pre-apply code-map test evidence is unresolved or partial; advisory only");
                } else if node.no_observed_test_in_indexed_map {
                    info!(task_id = task.task_id.raw(), path = %node.impact_node.path, symbol = %node.impact_node.symbol, "no observed test in complete indexed map; this is not proof of no tests");
                } else {
                    info!(task_id = task.task_id.raw(), path = %node.impact_node.path, symbol = %node.impact_node.symbol, observed_tests = node.observed_tests.len(), "pre-apply code-map observed test evidence; advisory only");
                }
            }
        }
        (state, _) => {
            info!(task_id = task.task_id.raw(), state = ?state, "pre-apply code-map advisory unavailable; existing risk/apply behavior retained")
        }
    }
}

fn apply_admitted_patch_in_worktree(
    admission: AdmittedPatchApply,
    task: &KanbanTask,
    outcome: &AcceptedWorkerOutcome,
    cfg: &DispatchApplyConfig,
    cancellation_probe: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> std::result::Result<(), String> {
    let current_target = crate::code_map::CanonicalRepoRoot::discover(admission.target.path())
        .map_err(|error| format!("repository changed after permission admission: {error}"))?;
    if current_target != admission.target {
        return Err("repository physical identity changed after permission admission".to_string());
    }
    if task.task_id != admission.task_id {
        return Err("task changed after permission admission".to_string());
    }
    let patch = outcome
        .patch_text()
        .ok_or_else(|| "accepted patch outcome has no immutable patch bytes".to_string())?;
    let patch_sha256: [u8; 32] = Sha256::digest(patch.as_bytes()).into();
    if patch_sha256 != admission.accepted_patch_sha256 {
        return Err("accepted patch changed after permission admission".to_string());
    }
    let binding = patch_apply_request_binding(
        current_target.identity().as_str(),
        task.task_id,
        &patch_sha256,
        cfg.origin,
    );
    if binding != admission.request_binding_sha256 {
        return Err("patch apply request binding changed after permission admission".to_string());
    }

    if cancellation_probe.is_some_and(|probe| probe.load(std::sync::atomic::Ordering::Acquire)) {
        return Err(APPLY_CANCELLED_BEFORE_WORKTREE.to_string());
    }

    // The accepted patch bytes are immutable and authenticated at this point.
    // Analyse them before a worktree exists; an unavailable advisory is kept
    // as typed audit evidence and cannot alter the existing risk/apply path.
    let impact_advisory = pre_apply_impact_advisory(
        cfg.pre_apply_impact_advisory.as_ref(),
        &current_target,
        patch,
    );
    log_pre_apply_impact_advisory(task, impact_advisory.as_ref());

    let wt_path =
        crate::coding::worktree::create_task_worktree(current_target.path(), task.task_id)
            .map_err(|e| {
                format!(
                    "worktree create failed for task {}: {e}",
                    task.task_id.raw()
                )
            })?;

    // WS-BUG P1: the worktree path is deterministic per task_id, so leaking it
    // on ANY error path below made every retry fail at git "already checked
    // out", permanently blocking --apply for that task. Wrap the post-creation
    // body so a single cleanup covers all six failure returns; success keeps
    // the worktree (documented — the operator inspects the applied diff there).
    let apply_result: std::result::Result<(), String> = (|| {
        let patch_text = outcome
            .patch_text()
            .ok_or_else(|| "accepted patch outcome has no immutable patch bytes".to_string())?;
        // Per Chorus verdict Q1b: refuse on dirty. The worktree was
        // just created from HEAD so it should be clean — this is a
        // defensive check against an operator that pre-populated
        // the .neoth-task-N/ dir.
        match crate::coding::worktree::is_worktree_dirty(&wt_path) {
            Ok(true) => {
                return Err(format!(
                    "task {} worktree {} is dirty — refusing apply (Chorus Q1b)",
                    task.task_id.raw(),
                    wt_path.display()
                ));
            }
            Err(e) => {
                return Err(format!("worktree dirty-check failed: {e}"));
            }
            Ok(false) => {}
        }

        // REPOW pre-edit risk gate — autonomy-tiered: Warn / RequireConfirm / Block.
        // Standard → warn only.  Elevated → confirm for risk ≥ 0.85.
        // Full → block for risk ≥ HIGH_RISK_THRESHOLD unless an override lease covers it.
        // Block / RequireConfirm: skip the apply (return Err) — NO interactive prompt.
        // The has_override check reads the lease store from default_neoth_home; a store
        // load failure is treated as no-override (fail-closed for elevated/full paths).
        // Git failures inside assess_edit_risk degrade to no-warning (existing behaviour).
        {
            use crate::code_map::risk::{RiskGateAction, risk_gate_action};
            use crate::permissions::AutonomyLevel;

            let changed = crate::code_map::risk::patch_changed_files_from_text(patch_text);
            let warnings = crate::code_map::risk::assess_edit_risk(current_target.path(), &changed);

            // Determine override-lease status once (shared across all files in this patch).
            // Only consulted when autonomy is Elevated or Full — skip the I/O otherwise.
            let autonomy_level = cfg
                .autonomy_policy
                .as_ref()
                .map(crate::permissions::AutonomyPolicySnapshot::level)
                .unwrap_or(AutonomyLevel::Standard);
            let has_override = match autonomy_level {
                AutonomyLevel::Elevated | AutonomyLevel::Full => {
                    // neoth: override token = a DangerousCommand lease granted to "operator".
                    // Operator runs: `neoth lease grant operator dangerous_command --ttl 300`
                    let home = crate::config::FreedomConfig::default_neoth_home();
                    let path = crate::permissions::lease::LeaseStore::default_path(&home);
                    let now = crate::time::now_unix_i64();
                    crate::permissions::lease::LeaseStore::load(&path)
                        .ok()
                        .and_then(|store| {
                            store
                                .find_covering(
                                    crate::security::risk_gate::RISK_LEASE_SUBJECT,
                                    &crate::permissions::lease::LeaseScope::DangerousCommand,
                                    now,
                                )
                                .map(|_| true)
                        })
                        .unwrap_or(false)
                }
                _ => false,
            };

            for w in &warnings {
                let action = risk_gate_action(autonomy_level, w.risk_score, has_override);
                match action {
                    RiskGateAction::Warn => {
                        warn!(
                            task_id = task.task_id.raw(),
                            file = %w.file,
                            risk_score = w.risk_score,
                            bus_factor = w.bus_factor,
                            reason = %w.reason,
                            autonomy = ?autonomy_level,
                            "⚠ editing high-risk file — review carefully",
                        );
                    }
                    RiskGateAction::RequireConfirm | RiskGateAction::Block => {
                        warn!(
                            task_id = task.task_id.raw(),
                            file = %w.file,
                            risk_score = w.risk_score,
                            bus_factor = w.bus_factor,
                            reason = %w.reason,
                            autonomy = ?autonomy_level,
                            has_override = has_override,
                            "⛔ BLOCKED high-risk edit — grant an override lease to allow \
                             (`neoth lease grant operator dangerous_command --ttl 300`)",
                        );
                        let msg = format!(
                            "risk gate blocked edit of `{}` for task {} \
                         (risk={:.2}, autonomy={autonomy_level:?}) — \
                         grant an override lease to allow: \
                         `neoth lease grant operator dangerous_command --ttl 300`",
                            w.file,
                            task.task_id.raw(),
                            w.risk_score,
                        );
                        // The immutable admitted patch was analyzed before this
                        // structural-risk decision. Persist that bounded advisory
                        // with the refusal; it remains evidence only and does not
                        // change risk score, override authority, or this error.
                        emit_patch_apply_failed_wal(
                            cfg.wal_writer.as_deref(),
                            task,
                            &wt_path,
                            "risk",
                            &msg,
                            impact_advisory.as_ref(),
                        );
                        return Err(msg);
                    }
                }
            }
        }

        let patch_hash = crate::coding::worktree::patch_hash_bytes(patch_text.as_bytes());

        match crate::coding::worktree::apply_patch_bytes_in_worktree(
            &wt_path,
            patch_text.as_bytes(),
        ) {
            Ok(crate::coding::worktree::PatchApplyOutcome::Applied { worktree_path }) => {
                info!(
                    task_id = task.task_id.raw(),
                    worktree = %worktree_path.display(),
                    "patch applied"
                );
                // Phase 4 test-loop: when the operator configured a
                // test command, run it inside the worktree. A
                // non-zero exit routes through the retry-policy
                // path the same way a git apply rejection does.
                let result = if let Some(cmd) = cfg.test_cmd.as_deref() {
                    run_worktree_tests(&worktree_path, cmd, cfg.test_timeout, task)
                } else {
                    Ok(())
                };

                match result {
                    Ok(()) => {
                        emit_patch_applied_wal(
                            cfg.wal_writer.as_deref(),
                            task,
                            &worktree_path,
                            &patch_hash,
                            impact_advisory.as_ref(),
                        );
                        Ok(())
                    }
                    Err((stage, msg)) => {
                        emit_patch_apply_failed_wal(
                            cfg.wal_writer.as_deref(),
                            task,
                            &worktree_path,
                            stage,
                            &msg,
                            impact_advisory.as_ref(),
                        );
                        Err(msg)
                    }
                }
            }
            Ok(crate::coding::worktree::PatchApplyOutcome::Rejected { stderr }) => {
                let msg = format!(
                    "git apply rejected patch for task {}: {stderr}",
                    task.task_id.raw()
                );
                emit_patch_apply_failed_wal(
                    cfg.wal_writer.as_deref(),
                    task,
                    &wt_path,
                    "apply",
                    &msg,
                    impact_advisory.as_ref(),
                );
                Err(msg)
            }
            Err(e) => {
                let msg = format!(
                    "apply_patch_in_worktree IO error for task {}: {e}",
                    task.task_id.raw()
                );
                emit_patch_apply_failed_wal(
                    cfg.wal_writer.as_deref(),
                    task,
                    &wt_path,
                    "apply_check",
                    &msg,
                    impact_advisory.as_ref(),
                );
                Err(msg)
            }
        }
    })();

    // WS-BUG P1: clean the scratch worktree on any failure so a retry can
    // recreate it. Success intentionally keeps it (see fn doc). Best-effort —
    // a cleanup failure is logged, not surfaced (the apply outcome is authoritative).
    if apply_result.is_err()
        && let Err(e) =
            crate::coding::worktree::cleanup_worktree(current_target.path(), &wt_path, true)
    {
        tracing::warn!(
            task_id = task.task_id.raw(),
            error = %e,
            "worktree cleanup after failed apply failed"
        );
    }
    apply_result
}

/// Emit `0xD3 PATCH_APPLIED` into the WAL when a writer is wired.
/// Best-effort — backpressure / closed-channel errors log at
/// warn level but never bubble up; the apply already landed on
/// disk and the operator-visible task transition is the
/// authoritative signal.
fn emit_patch_applied_wal(
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    task: &KanbanTask,
    worktree_path: &std::path::Path,
    patch_hash: &str,
    impact_advisory: Option<&PreApplyImpactAdvisory>,
) {
    let Some(writer) = writer else {
        return;
    };
    let payload = serde_json::json!({
        "task_id": task.task_id.raw(),
        "session_id": task.session_id.raw(),
        "worktree_path": worktree_path.display().to_string(),
        "patch_hash": patch_hash,
        "pre_apply_impact_advisory": pre_apply_impact_advisory_wal_value(impact_advisory),
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_PATCH_APPLIED, &payload);
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(
            task_id = task.task_id.raw(),
            error = %e,
            "WAL emit for PATCH_APPLIED failed; apply already landed"
        );
    }
}

/// Emit `0xD4 PATCH_APPLY_FAILED` into the WAL when a writer is
/// wired. `stage` is `"risk"`, `"apply_check"`, `"apply"`, or `"tests"` per
/// the event-code doc-comment.
fn emit_patch_apply_failed_wal(
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    task: &KanbanTask,
    worktree_path: &std::path::Path,
    stage: &str,
    reason: &str,
    impact_advisory: Option<&PreApplyImpactAdvisory>,
) {
    let Some(writer) = writer else {
        return;
    };
    let redacted = crate::security::redact::sanitize_tool_output(reason);
    let worktree_path =
        crate::security::redact::sanitize_tool_output(&worktree_path.display().to_string());
    let payload = serde_json::json!({
        "task_id": task.task_id.raw(),
        "session_id": task.session_id.raw(),
        "worktree_path": worktree_path,
        "stage": stage,
        "reason": redacted,
        "pre_apply_impact_advisory": pre_apply_impact_advisory_wal_value(impact_advisory),
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    let header =
        crate::wal::make_header(crate::wal::events::EVENT_TYPE_PATCH_APPLY_FAILED, &payload);
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(
            task_id = task.task_id.raw(),
            error = %e,
            "WAL emit for PATCH_APPLY_FAILED failed"
        );
    }
}

/// SD-02 (Round-3 v0.4) — emit `0x77 KANBAN_TASK_PROGRESS` into the
/// WAL at task-lifecycle progress points. Best-effort — emission
/// failures log at warn level but never abort the dispatcher;
/// progress frames are operator-visible signal, not load-bearing
/// state.
///
/// `progress_pct` is the operator-readable completion estimate
/// (0 = picked up, 100 = review-ready). `message` is a free-form
/// one-liner the kanban watch surface renders ("dispatching" /
/// "review_ready" / "tests_running"). Bilingual messages welcome.
/// Caps for the injected notes block so a comment-heavy task cannot
/// blow a small-context worker's window. Newest comments win under the
/// caps; the surviving set renders oldest-first.
const NOTES_MAX_COMMENTS: usize = 20;
const NOTES_MAX_BYTES: usize = 4096;

/// Append the task's comment thread to the in-memory description as a
/// "Task notes" block that `build_task_prompt` renders verbatim. The
/// stored row is untouched — enrichment lives only for one dispatch.
fn append_task_notes(task: &mut KanbanTask, comments: &[KanbanComment]) {
    if comments.is_empty() {
        return;
    }
    let mut picked: Vec<&KanbanComment> = Vec::new();
    let mut used = 0usize;
    for c in comments.iter().rev().take(NOTES_MAX_COMMENTS) {
        let line_len = c.author.len() + c.body.len() + 8;
        if used + line_len > NOTES_MAX_BYTES {
            break;
        }
        used += line_len;
        picked.push(c);
    }
    if picked.is_empty() {
        return;
    }
    picked.reverse();
    let mut block = String::with_capacity(used + 64);
    block.push_str("Task notes (operator + workers, oldest first — follow these):");
    for c in picked {
        block.push_str("\n- [");
        block.push_str(&c.author);
        block.push_str("] ");
        // Single-line body keeps the prompt's TASK block shape intact.
        block.push_str(&c.body.replace('\n', " "));
    }
    match task.description.as_mut() {
        Some(d) => {
            d.push_str("\n\n");
            d.push_str(&block);
        }
        None => task.description = Some(block),
    }
}

fn emit_kanban_task_progress_wal(
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    task: &KanbanTask,
    progress_pct: u8,
    message: &str,
) {
    let Some(writer) = writer else {
        return;
    };
    let payload = serde_json::json!({
        "task_id": task.task_id.raw(),
        "session_id": task.session_id.raw(),
        "hemisphere": task.hemisphere.as_str(),
        "progress_pct": progress_pct,
        "message": message,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    let header = crate::wal::make_header(
        crate::wal::events::EVENT_TYPE_KANBAN_TASK_PROGRESS,
        &payload,
    );
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(
            task_id = task.task_id.raw(),
            error = %e,
            "WAL emit for KANBAN_TASK_PROGRESS failed (non-fatal)"
        );
    }
}

/// TASK-02 — emit `0x4D WORKER_DIED` when a `worker.execute()` is
/// abandoned at the per-task hard timeout. The daemon `worker_watch`
/// reaps worker deaths in the long-running serve path, but a `neoth
/// code` one-shot has no watcher — so the dispatcher emits the same
/// frame inline when it kills a hung worker. Best-effort, mirroring the
/// progress emit (sync `try_append_sync`): a failed append logs at warn
/// and never aborts the dispatch. The payload is a superset of
/// `worker_watch::emit_worker_died`'s (`worker` + `ts_unix`) so both
/// emit sites produce frames a `worker_died` consumer can read.
fn emit_worker_died_wal(
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    task: &KanbanTask,
    timeout: std::time::Duration,
) {
    let Some(writer) = writer else {
        return;
    };
    let payload = serde_json::json!({
        "worker": task.hemisphere.as_str(),
        "task_id": task.task_id.raw(),
        "session_id": task.session_id.raw(),
        "reason": "worker_execute_timeout",
        "timeout_secs": timeout.as_secs(),
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_WORKER_DIED, &payload);
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(
            task_id = task.task_id.raw(),
            error = %e,
            "WAL emit for WORKER_DIED (timeout) failed (non-fatal)"
        );
    }
}

fn now_unix_secs() -> u64 {
    crate::time::now_unix_secs()
}

fn apply_outcome(
    conn: &Connection,
    task: &KanbanTask,
    outcome: &AcceptedWorkerOutcome,
) -> Result<()> {
    let target = if outcome.review_ready() {
        TaskStatus::Review
    } else {
        TaskStatus::Blocked
    };
    let now_ns = now_unix_ns();
    store::persist_task_result(
        conn,
        task.task_id,
        outcome.patch_path(),
        Some(outcome.tests),
        outcome.result_context_commitment.as_ref(),
        target,
        now_ns,
    )
    .context("persist accepted worker result boundary")?;
    Ok(())
}

/// Pick #6 Phase 4-pre (2026-05-21): one failed attempt — either
/// the worker errored or returned an empty outcome. Decide whether
/// to re-queue with a strategy hint (more retry budget) or
/// transition to Blocked (ceiling hit).
///
/// Smallcode equivalent: `checkAndEnforceHardFail` +
/// `pickDecomposeStrategy` from `bin/governor.js`. Per
/// `PLAN/SMALLCODE_INTEGRATION_PLAN_2026-05-21.md`.
fn handle_retryable_failure(
    conn: &Connection,
    task: &KanbanTask,
    retry_policy: &mut WorkerRetryPolicy,
    patch_spiral: &mut crate::coding::early_stop::PatchSpiralTracker,
    recent_outputs: &[&str],
    outcome: &mut DispatchOutcome,
    diagnosis: &str,
    partial_outcome: Option<&AcceptedWorkerOutcome>,
) -> Result<()> {
    let attempt = retry_policy.record_attempt(task.task_id);
    let now_ns = now_unix_ns();

    // Diagnosis strings ride into `tracing::info!`/`warn!` which the
    // WAL subscriber persists durably. Provider-error messages can
    // carry an API key in a URL query string, a Bearer header, or a
    // leaked .env line; cargo/test output arrives ANSI-colourised.
    // sanitize_tool_output strips the escape bytes THEN redacts secret
    // shapes (QU-04) — see `security::redact`. One canonical pass here
    // covers every downstream consumer of `diagnosis` (early-stop log
    // markers, the re-injection hint, the Blocked-reason emit).
    let diagnosis = sanitize_tool_output(diagnosis);

    // ── QU-01 (Session 28) — early-stop detectors before retry ────────────
    //
    // Two bail-out signals skip the retry-strategy rotation entirely
    // + transition straight to Blocked. Both write a distinct log
    // marker so the operator running `neoth kanban watch` sees WHY
    // the task didn't get its full retry budget.
    //
    // 1. Greeting-regression — the worker reply degenerated to
    //    `"Sorry, I can't help with that"`-style refusal. Rotating
    //    SplitFile → OneErrorAtATime → RewriteSection on the same
    //    prompt just burns budget producing more refusals. The
    //    operator needs to rephrase the prompt; mark Blocked +
    //    surface in the activity feed.
    //
    // 2. Patch-spiral — N consecutive failing patches for the same
    //    task (default ceiling 4 per smallcode's original spec).
    //    Past this point retry-strategy hints have already been
    //    rotated through, and continuing burns operator API quota
    //    for no net signal. Bail.
    let greeting_regression =
        crate::coding::early_stop::is_refusal_or_capability_disclaimer(&diagnosis)
            || partial_outcome
                .map(|o| {
                    // Check both surfaces an LLM refusal could land on:
                    // the operator-facing summary (one-line) AND the patch
                    // body (where a refusal-as-prose ended up if the worker
                    // didn't even produce a diff header).
                    crate::coding::early_stop::is_refusal_or_capability_disclaimer(&o.summary)
                        || crate::coding::early_stop::is_refusal_or_capability_disclaimer(
                            &o.patch_text,
                        )
                })
                .unwrap_or(false);
    if greeting_regression {
        warn!(
            task_id = task.task_id.raw(),
            attempt = attempt,
            early_stop = "greeting_regression",
            diagnosis = %diagnosis,
            "worker greeting-regression detected; bypassing retry rotation + marking Blocked"
        );
        store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns)
            .context("block greeting-regression worker result")?;
        outcome.tasks_blocked += 1;
        outcome.blocked_task_ids.push(task.task_id.raw());
        return Ok(());
    }
    if patch_spiral.is_spiraling(task.task_id) {
        let failure_count = patch_spiral.failure_count(task.task_id);
        warn!(
            task_id = task.task_id.raw(),
            attempt = attempt,
            early_stop = "patch_spiral",
            consecutive_failures = failure_count,
            diagnosis = %diagnosis,
            "patch-spiral ceiling hit ({failure_count} consecutive failures); marking Blocked"
        );
        store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns)
            .context("block patch-spiral worker result")?;
        outcome.tasks_blocked += 1;
        outcome.blocked_task_ids.push(task.task_id.raw());
        return Ok(());
    }
    // 3. Repetition-loop (QU-01 Phase 3) — the worker re-emitted the
    //    same reply (whitespace-normalised) for the last
    //    REPETITION_LOOP_MIN_SAMPLES attempts. A wedged model that
    //    keeps producing byte-identical output won't escape via a
    //    strategy-hint rotation; bail rather than burn the rest of
    //    the retry budget on guaranteed-identical attempts.
    if crate::coding::early_stop::is_repetition_loop(recent_outputs) {
        warn!(
            task_id = task.task_id.raw(),
            attempt = attempt,
            early_stop = "repetition_loop",
            samples = recent_outputs.len(),
            diagnosis = %diagnosis,
            "repetition-loop detected (identical worker output tail); marking Blocked"
        );
        store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns)
            .context("block repeated worker result")?;
        outcome.tasks_blocked += 1;
        outcome.blocked_task_ids.push(task.task_id.raw());
        return Ok(());
    }

    if retry_policy.should_retry(task.task_id) {
        // Re-queue with a strategy hint appended to the description.
        // The dispatcher's next loop pass will pick the task up
        // again from Backlog with the hint visible to the worker.
        let strategy = retry_policy.pick_strategy(task.task_id);
        // QU-05 — re-inject the actual failure diagnosis (compiler /
        // test output) alongside the generic strategy nudge. Before
        // this, the worker only saw "[retry hint: split the file]"
        // and never its own error, so it kept reproducing the same
        // break. `diagnosis` is already redacted (line above) so a
        // leaked secret in an error string never reaches the task
        // description (which `neoth kanban` renders + the WAL anchors).
        let hint = reinjection_hint(strategy.hint(), &diagnosis);
        info!(
            task_id = task.task_id.raw(),
            attempt = attempt,
            strategy = strategy.as_str(),
            diagnosis = %diagnosis,
            "worker attempt failed; retrying with strategy hint + diagnosis"
        );
        store::append_task_description_hint(conn, task.task_id, &hint)
            .context("persist retry hint before re-queue")?;
        // Re-record any partial artefacts (patch path, tests) so
        // the operator sees what the failed attempt produced even
        // before the next try.
        if let Some(o) = partial_outcome {
            store::attach_task_artifact(conn, task.task_id, o.patch_path(), Some(o.tests))
                .context("attach accepted partial worker artifact before retry")?;
        }
        // Back to Backlog for the next dispatch loop iteration.
        store::patch_task_status(conn, task.task_id, TaskStatus::Backlog, now_ns)
            .context("re-queue retryable worker failure")?;
        // Don't count as blocked or completed yet — the dispatcher's
        // budget cap will end the loop if we churn too long.
    } else if task.hemisphere == Hemisphere::Left {
        // QU-05 ESCALATE — a Left (fast) worker exhausted its retry
        // budget. Hand the task to the Right (deep) hemisphere ONCE
        // with a fresh budget before giving up. The hemisphere field
        // itself doubles as the escalation marker: a task already on
        // Right/Cerebellum falls through to the Blocked arm below, so
        // there's no Left⇄Right ping-pong. (WorkerOutcome is a struct,
        // not the enum the spec assumed, so escalate rides this
        // hemisphere-reassign path, not a `WorkerOutcome::Escalate`
        // variant.)
        match store::patch_task_hemisphere(conn, task.task_id, Hemisphere::Right, None, None) {
            Ok(()) => {
                warn!(
                    task_id = task.task_id.raw(),
                    attempt = attempt,
                    escalate = "left_to_right",
                    diagnosis = %diagnosis,
                    "Left worker retry ceiling hit; escalating task to Right hemisphere"
                );
                // Fresh retry budget on the new hemisphere + re-inject
                // the last diagnosis so the deep worker sees what the
                // fast one could not converge on.
                retry_policy.reset(task.task_id);
                let hint = reinjection_hint(
                    "[escalated to the deep worker — the fast worker could not converge]",
                    &diagnosis,
                );
                store::append_task_description_hint(conn, task.task_id, &hint)
                    .context("persist escalation retry hint")?;
                if let Some(o) = partial_outcome {
                    store::attach_task_artifact(conn, task.task_id, o.patch_path(), Some(o.tests))
                        .context("attach accepted partial worker artifact before escalation")?;
                }
                // Re-queue; the next loop pass re-reads the task with
                // hemisphere=Right and binds the Right worker. Not
                // counted blocked/completed — it gets another shot.
                store::patch_task_status(conn, task.task_id, TaskStatus::Backlog, now_ns)
                    .context("re-queue escalated worker failure")?;
            }
            Err(e) => {
                // Reassign failed — fall back to Blocked rather than
                // re-queueing onto a stale hemisphere.
                tracing::warn!(
                    task_id = task.task_id.raw(),
                    error = %e,
                    "escalate hemisphere reassign failed; blocking task"
                );
                store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns)
                    .context("block task after escalation reassignment failure")?;
                outcome.tasks_blocked += 1;
                outcome.blocked_task_ids.push(task.task_id.raw());
            }
        }
    } else {
        // Ceiling hit on Right/Cerebellum — no deeper hemisphere to
        // escalate to. Give up + transition to Blocked.
        let strategy = retry_policy.pick_strategy(task.task_id);
        warn!(
            task_id = task.task_id.raw(),
            attempt = attempt,
            final_strategy = strategy.as_str(),
            diagnosis = %diagnosis,
            "worker retry ceiling hit (no deeper hemisphere); task transitioned to Blocked"
        );
        store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns)
            .context("block exhausted worker retry")?;
        outcome.tasks_blocked += 1;
        outcome.blocked_task_ids.push(task.task_id.raw());
    }
    Ok(())
}

fn now_unix_ns() -> u64 {
    crate::time::now_unix_ns()
}

/// QU-05 — true when the operator's test command is a `cargo check`
/// invocation, so the dispatcher routes through the structured-JSON
/// diagnostic path (rustc's parsed errors re-injected into the next
/// attempt) instead of the generic stderr-tail path. Matches `cargo
/// check [flags…]`; not `cargo test` / `cargo build` / a wrapper
/// script.
fn is_cargo_check_cmd(cmd: &str) -> bool {
    let mut it = cmd.split_whitespace();
    matches!((it.next(), it.next()), (Some("cargo"), Some("check")))
}

/// QU-05 — run the post-apply test command inside the task worktree.
/// A `cargo check` routes through `run_cargo_check_json` so a failing
/// check re-injects rustc's parsed, capped diagnostics as the
/// `diagnosis` that `handle_retryable_failure` appends to the next
/// attempt's prompt; any other command runs generically (stderr tail).
/// `Ok(())` = pass; `Err((stage, diagnosis))` = fail / spawn error,
/// routed through `emit_patch_apply_failed_wal` + the retry path.
fn run_worktree_tests(
    worktree: &std::path::Path,
    cmd: &str,
    timeout: Duration,
    task: &KanbanTask,
) -> std::result::Result<(), (&'static str, String)> {
    use crate::coding::{cargo_check, worktree};
    let tid = task.task_id.raw();
    if is_cargo_check_cmd(cmd) {
        match worktree::run_cargo_check_json(worktree, cmd, timeout) {
            Ok(run) if run.passed => {
                info!(task_id = tid, cmd = cmd, "cargo check passed in worktree");
                Ok(())
            }
            Ok(run) => {
                let detail = if cargo_check::has_errors(&run.diagnostics) {
                    cargo_check::format_for_retry(&run.diagnostics)
                } else if run.timed_out {
                    format!(
                        "cargo check timed out — full log: {}",
                        run.log_path.display()
                    )
                } else {
                    format!(
                        "cargo check failed without parseable errors — full log: {}",
                        run.log_path.display()
                    )
                };
                Err((
                    "tests",
                    format!("cargo check failed for task {tid}:\n{detail}"),
                ))
            }
            Err(e) => Err((
                "tests",
                format!("cargo check spawn failed for task {tid}: {e}"),
            )),
        }
    } else {
        match worktree::run_test_cmd(worktree, cmd, timeout) {
            Ok(worktree::TestOutcome::Passed) => {
                info!(task_id = tid, cmd = cmd, "tests passed in worktree");
                Ok(())
            }
            Ok(worktree::TestOutcome::Failed { reason }) => Err((
                "tests",
                format!("tests failed in worktree for task {tid} ({cmd}): {reason}"),
            )),
            Err(e) => Err((
                "tests",
                format!("test-command spawn failed for task {tid} ({cmd}): {e}"),
            )),
        }
    }
}

/// QU-05 — cap on the failure diagnostic re-injected into the next
/// attempt's task description. A `cargo check` / test failure can dump
/// kilobytes; the worker only needs the head to know what to fix, and
/// the description also renders in `neoth kanban` views + anchors in
/// the WAL, so an unbounded dump would bloat both.
const REINJECTED_DIAGNOSIS_CAP: usize = 1_500;

/// QU-05 — build the retry hint appended to the task description before
/// the next attempt. Combines the generic strategy nudge ("split the
/// file" / "rewrite the section") with the actual failure diagnosis so
/// the worker sees *what* broke, not just *how* to retry. `diagnosis`
/// MUST already be redacted by the caller; this only bounds its length
/// at a UTF-8 char boundary so a multi-byte rustc arrow (`-->`) or a
/// German error message can't panic the slice.
fn reinjection_hint(strategy_hint: &str, diagnosis: &str) -> String {
    let diag = diagnosis.trim();
    if diag.is_empty() {
        return strategy_hint.to_string();
    }
    let bounded = if diag.len() > REINJECTED_DIAGNOSIS_CAP {
        // Walk back to the nearest UTF-8 char boundary at/below the cap
        // so a multi-byte char straddling it can't panic the slice.
        let end = diag.floor_char_boundary(REINJECTED_DIAGNOSIS_CAP);
        format!("{}\n…(diagnostic truncated)", &diag[..end])
    } else {
        diag.to_string()
    };
    format!("{strategy_hint}\n[previous attempt failed]:\n{bounded}")
}

/// QU-01 Phase 3 — cap on the per-task recent-output ring. Only the
/// most-recent N matter to `is_repetition_loop` (which inspects the
/// last REPETITION_LOOP_MIN_SAMPLES), so keep the ring small + drop
/// the oldest beyond this. 8 gives comfortable headroom over the
/// 3-sample detector window without unbounded growth on a wedged
/// task that re-queues many times.
const REPETITION_RING_CAP: usize = 8;

/// Collapse a worker outcome into the single text the repetition-loop
/// detector compares. Joins the operator-facing summary + the patch
/// body so two attempts that differ only in one surface still count
/// as distinct (and two byte-identical attempts collapse to the same
/// string regardless of which surface carried the content).
fn worker_output_text(o: &WorkerOutcome) -> String {
    // Newline-join keeps the two surfaces distinguishable to
    // `collapse_ws` without introducing a separator that could
    // appear inside either field.
    format!("{}\n{}", o.summary, o.patch_text)
}

/// Push `text` onto the task's recent-output ring, dropping the
/// oldest entry past [`REPETITION_RING_CAP`]. Creates the ring lazily
/// on first failure for a task.
fn record_recent_output(
    map: &mut HashMap<KanbanTaskId, Vec<String>>,
    task_id: KanbanTaskId,
    text: &str,
) {
    let ring = map.entry(task_id).or_default();
    ring.push(text.to_string());
    if ring.len() > REPETITION_RING_CAP {
        let overflow = ring.len() - REPETITION_RING_CAP;
        ring.drain(0..overflow);
    }
}

/// Borrow the task's recent-output ring as a `Vec<&str>` for
/// [`is_repetition_loop`]. Empty vec when the task has no recorded
/// outputs yet (first failure) — the detector returns false below
/// its minimum-sample floor, so this is the correct no-op.
fn recent_output_refs(
    map: &HashMap<KanbanTaskId, Vec<String>>,
    task_id: KanbanTaskId,
) -> Vec<&str> {
    map.get(&task_id)
        .map(|ring| ring.iter().map(String::as_str).collect())
        .unwrap_or_default()
}

/// GR-002 — whether a worktree apply has observed enough to replace an
/// unverified worker test claim with the dispatcher's one-command verified
/// receipt (which `check_auto_promotable` may use). Requires BOTH a configured
/// test command (a suite actually ran in the worktree) AND a non-empty patch.
/// An empty patch is a no-op: `apply_patch_via_worktree` returns Ok without
/// applying or running any suite, so its self-reported "tests green" claim has
/// no verification behind it and must never auto-promote. Pure → unit-testable.
fn apply_is_test_verified(test_cmd_present: bool, patch_text: &str) -> bool {
    test_cmd_present && !patch_text.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;

    #[test]
    fn empty_patch_is_never_test_verified() {
        // GR-002: an empty patch (a no-op that ran no worktree suite) must NOT be
        // stamped `applied`, even when a test_cmd is configured and the worker
        // self-reports green — otherwise it would auto-promote to DONE with no
        // change + no test evidence.
        assert!(
            !apply_is_test_verified(true, ""),
            "empty patch + test_cmd must NOT be verified"
        );
        assert!(
            !apply_is_test_verified(false, ""),
            "empty patch, no test_cmd"
        );
        // A real (non-empty) patch with a configured suite IS verified; without a
        // suite it is not (apply alone is not test evidence).
        assert!(
            apply_is_test_verified(true, "diff --git a/x b/x\n"),
            "non-empty patch + test_cmd must be verified"
        );
        assert!(
            !apply_is_test_verified(false, "diff --git a/x b/x\n"),
            "non-empty patch without a test_cmd is not test-verified"
        );
    }

    /// A canned worker — returns the same outcome every call.
    /// Sufficient to pin the dispatch path's contract.
    struct CannedWorker {
        outcome: WorkerOutcome,
        name: &'static str,
    }

    #[async_trait]
    impl Worker for CannedWorker {
        async fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            Ok(self.outcome.clone())
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    #[derive(Clone)]
    struct AtomicCancellation {
        cancelled: Arc<std::sync::atomic::AtomicBool>,
    }

    impl AtomicCancellation {
        fn new() -> Self {
            Self {
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }

        fn request(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    impl DispatchCancellation for AtomicCancellation {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::Acquire)
        }

        fn effect_cancellation_probe(&self) -> Option<Arc<std::sync::atomic::AtomicBool>> {
            Some(Arc::clone(&self.cancelled))
        }
    }

    fn patch_apply_pause(point: PatchApplyPausePoint) -> Arc<PatchApplyPause> {
        Arc::new(PatchApplyPause {
            point,
            entered: std::sync::atomic::AtomicBool::new(false),
            entered_notify: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }

    async fn wait_for_patch_apply_pause(pause: &PatchApplyPause) {
        loop {
            if pause.entered.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            pause.entered_notify.notified().await;
        }
    }

    /// A worker that always errors. Lets us test the bail-out path
    /// without touching real provider code.
    struct FailingWorker;

    #[async_trait]
    impl Worker for FailingWorker {
        async fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            anyhow::bail!("simulated worker failure")
        }
        fn name(&self) -> &'static str {
            "failing-worker"
        }
    }

    /// A worker that fails with a DISTINCT message each call. Reaching
    /// the retry ceiling this way exercises the ceiling/escalate path
    /// without tripping the QU-01 repetition-loop early-stop (which
    /// needs byte-identical output across attempts and would otherwise
    /// Block first).
    struct VaryingFailWorker {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Worker for VaryingFailWorker {
        async fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            anyhow::bail!("distinct failure #{n}")
        }
        fn name(&self) -> &'static str {
            "varying-fail-worker"
        }
    }

    /// A worker that never returns within the dispatcher's per-task
    /// timeout. Under `#[tokio::test(start_paused = true)]` tokio
    /// auto-advances virtual time, so the dispatcher's
    /// `timeout(WORKER_EXECUTE_TIMEOUT, …)` fires long before this
    /// 1-hour sleep would — no real wall-clock wait. Exercises TASK-02.
    struct HangingWorker;

    #[async_trait]
    impl Worker for HangingWorker {
        async fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            Ok(green_outcome())
        }
        fn name(&self) -> &'static str {
            "hanging-worker"
        }
    }

    fn fresh_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = crate::memory::store::open(&path).expect("open views.db");
        store::ensure_schema(&conn).expect("ensure schema");
        (dir, conn)
    }

    fn green_outcome() -> WorkerOutcome {
        WorkerOutcome {
            patch_text: "diff --git a/x b/x\n+ok\n".into(),
            patch_path: std::path::PathBuf::new(),
            tests: TestSummary {
                added: 1,
                total: 1,
                passing: 1,
                failing: 0,
                skipped: 0,
                applied: false,
            },
            summary: "ok".into(),
            result_context_commitment: None,
        }
    }

    fn notes_task(description: Option<&str>) -> KanbanTask {
        KanbanTask {
            task_id: KanbanTaskId(1),
            session_id: KanbanSessionId(1),
            status: TaskStatus::Backlog,
            title: "t".into(),
            description: description.map(str::to_string),
            task_type: "ui".into(),
            hemisphere: Hemisphere::Left,
            worker: None,
            parent_task_id: None,
            created_ns: 0,
            started_ns: None,
            eta_ns: None,
            completed_ns: None,
            patch_path: None,
            test_summary: None,
            worker_result_provenance: None,
        }
    }

    fn note(author: &str, body: &str) -> KanbanComment {
        KanbanComment {
            comment_id: 0,
            task_id: KanbanTaskId(1),
            author: author.into(),
            body: body.into(),
            created_ns: 0,
        }
    }

    #[test]
    fn append_task_notes_rides_description_with_author_tags() {
        // The worker prompt renders description verbatim, so the notes
        // block must land there, oldest-first, author-tagged, and with
        // multi-line bodies flattened to one line.
        let mut t = notes_task(Some("base description"));
        append_task_notes(
            &mut t,
            &[
                note("operator", "use the\nexisting helper"),
                note("left", "ack"),
            ],
        );
        let d = t.description.unwrap();
        assert!(d.starts_with("base description\n\n"));
        assert!(d.contains("Task notes"));
        assert!(d.contains("- [operator] use the existing helper"));
        assert!(d.contains("- [left] ack"));
        assert!(
            d.find("[operator]").unwrap() < d.find("[left]").unwrap(),
            "oldest comment must render first"
        );
    }

    #[test]
    fn append_task_notes_handles_missing_description_and_empty_thread() {
        let mut none_desc = notes_task(None);
        append_task_notes(&mut none_desc, &[note("operator", "note")]);
        assert!(none_desc.description.unwrap().contains("- [operator] note"));

        let mut untouched = notes_task(Some("keep"));
        append_task_notes(&mut untouched, &[]);
        assert_eq!(untouched.description.as_deref(), Some("keep"));
    }

    #[test]
    fn append_task_notes_caps_keep_newest_comments() {
        // Over-cap threads must keep the NEWEST comments (they carry the
        // operator's latest steering) and stay under the byte ceiling.
        let comments: Vec<KanbanComment> = (0..NOTES_MAX_COMMENTS + 5)
            .map(|i| note("operator", &format!("note-{i}")))
            .collect();
        let mut t = notes_task(None);
        append_task_notes(&mut t, &comments);
        let d = t.description.unwrap();
        assert!(!d.contains("note-0"), "oldest overflow comment must drop");
        assert!(d.contains(&format!("note-{}", NOTES_MAX_COMMENTS + 4)));
        assert!(d.len() <= NOTES_MAX_BYTES + 128);

        // Byte cap: one giant comment younger than many small ones —
        // the giant one fits first (newest), the rest drop.
        let big = "x".repeat(NOTES_MAX_BYTES);
        let mut thread: Vec<KanbanComment> = (0..5)
            .map(|i| note("operator", &format!("small-{i}")))
            .collect();
        thread.push(note("operator", &big));
        let mut t2 = notes_task(None);
        append_task_notes(&mut t2, &thread);
        assert!(t2.description.is_none() || !t2.description.as_ref().unwrap().contains("small-0"));
    }

    /// Captures the description the dispatcher hands the worker so the
    /// comment-injection contract is pinned end-to-end (store → batch
    /// enrichment → execute).
    struct RecordingWorker {
        seen: std::sync::Arc<std::sync::Mutex<Option<String>>>,
        outcome: WorkerOutcome,
    }

    #[async_trait]
    impl Worker for RecordingWorker {
        async fn execute(&self, task: &KanbanTask) -> Result<WorkerOutcome> {
            *self.seen.lock().unwrap() = task.description.clone();
            Ok(self.outcome.clone())
        }
        fn name(&self) -> &'static str {
            "recording-worker"
        }
    }

    #[tokio::test]
    async fn dispatch_injects_task_comments_into_worker_view() {
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id =
            store::insert_task(&conn, session_id, 10, "t", Some("desc"), "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        store::insert_comment(&conn, task_id, 11, "operator", "prefer the small fix").unwrap();

        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(RecordingWorker {
                seen: seen.clone(),
                outcome: green_outcome(),
            }),
        );
        dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();

        let got = seen.lock().unwrap().clone().expect("worker ran");
        assert!(got.starts_with("desc"), "original description preserved");
        assert!(
            got.contains("- [operator] prefer the small fix"),
            "comment must reach the worker prompt view: {got}"
        );
    }

    #[tokio::test]
    async fn dispatch_with_no_workers_returns_zero_outcome() {
        // Pre-condition: dispatch with empty worker set MUST bail out
        // cleanly without touching the session. Operators can run
        // `neoth code` against a hemisphere-less freedom.yaml without
        // hitting an assertion.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let workers = HemisphereWorkerSet::new();
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();
        assert_eq!(outcome.tasks_attempted, 0);
        assert_eq!(outcome.tasks_completed, 0);
        assert!(!outcome.budget_exhausted);
    }

    #[tokio::test]
    async fn dispatch_runs_one_left_task_end_to_end() {
        // Pin the happy path: one BACKLOG task on Left, one CannedWorker
        // bound, dispatch ends with task in Review + outcome.completed=1.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "test-left",
            }),
        );
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();
        assert_eq!(outcome.tasks_attempted, 1);
        assert_eq!(outcome.tasks_completed, 1);
        assert_eq!(outcome.tasks_blocked, 0);

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.task_id, task_id);
        assert_eq!(task.status, TaskStatus::Review);
    }

    #[tokio::test]
    async fn dispatch_preserves_a_coherent_test_only_outcome() {
        // ADOPT31-C10a must not turn the explicit NoPatch state into a
        // failure when the worker has supplied a coherent, unverified test
        // result. The review gate still decides later whether an operator may
        // promote it; this only pins the dispatcher result contract.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut test_only = green_outcome();
        test_only.patch_text.clear();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: test_only,
                name: "test-only-worker",
            }),
        );
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();

        assert_eq!(outcome.tasks_completed, 1);
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Review);
        assert_eq!(task.test_summary, Some(green_outcome().tests));
    }

    #[tokio::test(start_paused = true)]
    async fn worker_timeout_blocks_task_and_does_not_hang() {
        // TASK-02: a worker.execute() that never returns within
        // WORKER_EXECUTE_TIMEOUT must NOT pin the dispatch forever — the
        // dispatcher abandons it, marks the task Blocked, and the run
        // completes (the one-shot path has no daemon worker_watch to reap
        // the hang). start_paused lets tokio auto-advance past the 300s
        // budget with zero real wall-clock wait.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(Hemisphere::Left, Box::new(HangingWorker));

        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();

        assert_eq!(outcome.tasks_attempted, 1);
        assert_eq!(
            outcome.tasks_completed, 0,
            "a hung worker completes nothing"
        );
        assert_eq!(outcome.tasks_blocked, 1, "the timed-out task lands Blocked");

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            task.status,
            TaskStatus::Blocked,
            "timed-out task must be Blocked, not left InProgress"
        );
    }

    #[tokio::test]
    async fn left_ceiling_escalates_to_right_then_completes() {
        // QU-05 escalate: a Left worker that always fails exhausts its
        // retry budget; the dispatcher hands the task to the Right
        // hemisphere with a fresh budget. A green Right worker then
        // completes it → Review, never Blocked.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(VaryingFailWorker {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }),
        );
        workers.bind(
            Hemisphere::Right,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "test-right",
            }),
        );
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.hemisphere, Hemisphere::Right, "escalated Left → Right");
        assert_eq!(task.status, TaskStatus::Review, "Right worker completed it");
        assert_eq!(outcome.tasks_completed, 1);
        assert_eq!(
            outcome.tasks_blocked, 0,
            "never blocked — escalation rescued it"
        );
    }

    #[tokio::test]
    async fn right_ceiling_blocks_without_further_escalation() {
        // A task that fails on the Right (deepest) hemisphere has
        // nowhere to escalate → Blocked after the ceiling, with no
        // ping-pong back to Left.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Right, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Right,
            Box::new(VaryingFailWorker {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }),
        );
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.hemisphere, Hemisphere::Right, "stays Right");
        assert_eq!(task.status, TaskStatus::Blocked);
        assert_eq!(outcome.tasks_blocked, 1);
    }

    #[tokio::test]
    async fn dispatch_blocks_unassigned_hemisphere() {
        // A task with hemisphere Right but no Right worker bound MUST
        // surface as `tasks_unassigned` and the row MUST land in
        // Blocked, not in InProgress (otherwise the audit chain shows
        // a task starting that never actually started).
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Right, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "test-left",
            }),
        );
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();
        assert_eq!(outcome.tasks_unassigned, 1);
        assert_eq!(outcome.tasks_completed, 0);

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    #[tokio::test]
    async fn dispatch_blocks_when_worker_errors() {
        // Worker.execute returning Err must transition the task to
        // Blocked, NOT InProgress, so an audit consumer never sees a
        // task stuck in InProgress without a worker producing output.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(Hemisphere::Left, Box::new(FailingWorker));
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();
        assert_eq!(outcome.tasks_blocked, 1);
        assert_eq!(outcome.tasks_completed, 0);

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    #[tokio::test]
    async fn dispatch_respects_max_tasks_budget() {
        // 3 backlog tasks, budget capped at 2 → dispatcher attempts
        // exactly 2 and surfaces budget_exhausted=true. The third
        // task stays in Backlog.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        for i in 0..3 {
            let t = store::insert_task(&conn, session_id, 10 + i, "t", None, "ui", None).unwrap();
            store::patch_task_hemisphere(&conn, t, Hemisphere::Left, None, None).unwrap();
        }

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "test",
            }),
        );
        let budget = DispatchBudget {
            max_tasks: 2,
            max_duration: Duration::from_secs(60),
        };
        let outcome = dispatch_session(&conn, session_id, &workers, budget)
            .await
            .unwrap();
        assert_eq!(outcome.tasks_attempted, 2);
        assert!(outcome.budget_exhausted);

        let backlog_count = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .into_iter()
            .filter(|t| t.status == TaskStatus::Backlog)
            .count();
        assert_eq!(backlog_count, 1);
    }

    #[tokio::test]
    async fn dispatch_two_hemisphere_workers_run_concurrently() {
        // COR-19: the Left and Right workers' execute() calls must OVERLAP.
        // Each BarrierWorker bumps `entered` then blocks on a 2-party
        // tokio::sync::Barrier — both must enter execute() before either is
        // released. Under the pre-COR-19 serial loop, worker A blocks at the
        // barrier forever (worker B is never executed) → the dispatch hangs
        // and the timeout below makes that a clean FAIL. Under the concurrent
        // batch loop both enter, the barrier releases, and both complete.
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct BarrierWorker {
            barrier: Arc<tokio::sync::Barrier>,
            entered: Arc<AtomicUsize>,
            name: &'static str,
        }
        #[async_trait]
        impl Worker for BarrierWorker {
            async fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
                self.entered.fetch_add(1, Ordering::SeqCst);
                self.barrier.wait().await;
                Ok(green_outcome())
            }
            fn name(&self) -> &'static str {
                self.name
            }
        }

        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let left = store::insert_task(&conn, session_id, 10, "left", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, left, Hemisphere::Left, None, None).unwrap();
        let right = store::insert_task(&conn, session_id, 11, "right", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, right, Hemisphere::Right, None, None).unwrap();

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let entered = Arc::new(AtomicUsize::new(0));
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(BarrierWorker {
                barrier: Arc::clone(&barrier),
                entered: Arc::clone(&entered),
                name: "barrier-left",
            }),
        );
        workers.bind(
            Hemisphere::Right,
            Box::new(BarrierWorker {
                barrier: Arc::clone(&barrier),
                entered: Arc::clone(&entered),
                name: "barrier-right",
            }),
        );

        let budget = DispatchBudget {
            max_tasks: 2,
            max_duration: Duration::from_secs(30),
        };
        // A serial dispatcher deadlocks here (worker B never runs while A
        // blocks at the barrier); the timeout turns that into a clean FAIL
        // instead of a hung CI job.
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            dispatch_session(&conn, session_id, &workers, budget),
        )
        .await;
        let outcome = result
            .expect("dispatch deadlocked — the two hemisphere workers were NOT run concurrently")
            .expect("dispatch failed");

        assert_eq!(
            entered.load(Ordering::SeqCst),
            2,
            "both workers must have entered execute()"
        );
        assert_eq!(outcome.tasks_completed, 2, "both tasks must complete");
        assert_eq!(outcome.tasks_blocked, 0);
        let tasks = store::list_tasks_for_session(&conn, session_id).unwrap();
        for t in &tasks {
            assert_eq!(
                t.status,
                TaskStatus::Review,
                "task {} must be Review after concurrent dispatch",
                t.task_id.raw()
            );
        }
    }

    #[tokio::test]
    async fn dispatch_is_reentrant() {
        // Calling dispatch twice on the same session is a no-op the
        // second time — the first run drained the Backlog, the second
        // finds nothing to do and returns zero outcome.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "test",
            }),
        );

        let first = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();
        assert_eq!(first.tasks_attempted, 1);

        let second = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();
        assert_eq!(second.tasks_attempted, 0);
        assert_eq!(second.tasks_completed, 0);
    }

    #[tokio::test]
    async fn worker_set_bind_replaces_existing() {
        // Last-write-wins matches the YAML-config reload contract.
        // An operator who re-binds a hemisphere via /reload should see
        // the new worker take over on the next dispatch tick.
        let mut set = HemisphereWorkerSet::new();
        set.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "first",
            }),
        );
        set.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "second",
            }),
        );
        assert_eq!(set.get(Hemisphere::Left).unwrap().name(), "second");
    }

    #[tokio::test]
    async fn dispatch_budget_default_is_30_minutes_and_20_tasks() {
        let b = DispatchBudget::default();
        assert_eq!(b.max_duration.as_secs(), 30 * 60);
        assert_eq!(b.max_tasks, 20);
    }

    // ── Pick #6 Phase 4 apply-via-worktree integration ─────────────

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Live git fixture: tempdir + init + initial commit so HEAD
    /// points somewhere apply_patch_in_worktree can branch off.
    fn init_repo(dir: &std::path::Path) -> std::io::Result<()> {
        use std::process::Command;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["init", "-q"])
            .status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "user.email", "ph4-test@example.com"])
            .status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "user.name", "ph4-test"])
            .status()?;
        std::fs::write(dir.join("README.md"), "initial\n")?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["add", "README.md"])
            .status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["commit", "-q", "-m", "init"])
            .status()?;
        Ok(())
    }

    fn green_outcome_with_real_patch() -> WorkerOutcome {
        // Real patch body (line-by-line so leading-space context
        // lines survive). Mirrors the smoke test in worktree::tests.
        let patch_lines = [
            "diff --git a/README.md b/README.md",
            "--- a/README.md",
            "+++ b/README.md",
            "@@ -1 +1,2 @@",
            " initial",
            "+second line",
            "",
        ];
        WorkerOutcome {
            patch_text: patch_lines.join("\n"),
            patch_path: std::path::PathBuf::new(),
            tests: TestSummary {
                added: 1,
                total: 1,
                passing: 1,
                failing: 0,
                skipped: 0,
                applied: false,
            },
            summary: "applied".into(),
            result_context_commitment: None,
        }
    }

    #[tokio::test]
    async fn dispatch_session_with_apply_creates_worktree_and_applies_patch() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        // Build a sibling git repo so worktree_path_for lands at
        // <tempdir>/.neoth-task-N (parent of repo dir).
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();

        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let outcome_template = green_outcome_with_real_patch();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "phase4-test",
            }),
        );

        let (writer, _writer_join) = authenticated_apply_writer(&dir.path().join("neoth-home"));
        let cfg = local_test_apply_config(&repo, &writer);
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&cfg),
        )
        .await
        .expect("dispatch with apply");

        assert_eq!(outcome.tasks_completed, 1);

        // Worktree must exist as sibling of repo + contain the
        // applied content.
        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        assert!(wt.exists(), "worktree exists at {}", wt.display());
        let readme = std::fs::read_to_string(wt.join("README.md")).unwrap();
        assert!(readme.contains("second line"), "patch applied: {readme}");

        // Cleanup so we don't leak (force=true because the apply
        // produced a dirty worktree by design).
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &wt, true);
    }

    #[tokio::test]
    async fn dispatch_session_with_apply_marks_task_blocked_on_conflict() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();

        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        // Patch references a file that doesn't exist — git apply
        // --check rejects. Phase 4 must re-queue, then Block at
        // ceiling.
        let patch_lines = [
            "diff --git a/nonexistent.txt b/nonexistent.txt",
            "--- a/nonexistent.txt",
            "+++ b/nonexistent.txt",
            "@@ -1 +1,2 @@",
            " line that does not exist",
            "+new line",
            "",
        ];
        let mut bad_outcome = green_outcome();
        bad_outcome.patch_text = patch_lines.join("\n");

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: bad_outcome,
                name: "phase4-bad",
            }),
        );

        let (writer, _writer_join) = authenticated_apply_writer(&dir.path().join("neoth-home"));
        let cfg = local_test_apply_config(&repo, &writer);
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&cfg),
        )
        .await
        .expect("dispatch with apply");

        // Task transitions through retries and finally lands in
        // Blocked once the retry ceiling fires.
        assert_eq!(outcome.tasks_completed, 0);
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .into_iter()
            .find(|t| t.task_id == task_id)
            .unwrap();
        assert!(
            matches!(task.status, TaskStatus::Blocked | TaskStatus::Backlog),
            "task ended in {:?} after apply rejection",
            task.status
        );

        // Best-effort cleanup of any worktree left behind.
        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        if wt.exists() {
            let _ = crate::coding::worktree::cleanup_worktree(&repo, &wt, true);
        }
    }

    fn always_pass_cmd_str() -> &'static str {
        if cfg!(windows) {
            "cmd /C exit 0"
        } else {
            "true"
        }
    }

    fn always_fail_cmd_str() -> &'static str {
        if cfg!(windows) {
            "cmd /C exit 1"
        } else {
            "false"
        }
    }

    fn authenticated_apply_writer(
        home: &std::path::Path,
    ) -> (
        std::sync::Arc<crate::wal::writer::WalWriterHandle>,
        tokio::task::JoinHandle<()>,
    ) {
        let wal = home.join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = crate::wal::writer::unique_standalone_segment_path(&wal, "dispatch-test");
        let (writer, join) = crate::wal::writer::spawn_for_home(segment, home.to_path_buf())
            .expect("home-backed test audit writer");
        (std::sync::Arc::new(writer), join)
    }

    fn local_test_apply_config(
        repo: &std::path::Path,
        writer: &std::sync::Arc<crate::wal::writer::WalWriterHandle>,
    ) -> DispatchApplyConfig {
        DispatchApplyConfig::new(repo, ApplyOrigin::CliConfirmed)
            .with_autonomy(crate::permissions::AutonomyLevel::Full)
            .with_local_cli_confirmation()
            .with_wal_writer(std::sync::Arc::clone(writer))
    }

    fn indexed_pre_apply_advisory(
        repo: &std::path::Path,
        database_path: std::path::PathBuf,
        impact_options: crate::code_map::ImpactOptions,
    ) -> PreApplyImpactAdvisoryConfig {
        let root = crate::code_map::CanonicalRepoRoot::discover(repo).unwrap();
        crate::code_map::rebuild_snapshot(&root, &database_path, Default::default()).unwrap();
        PreApplyImpactAdvisoryConfig {
            database_path,
            root,
            impact_options,
            coverage_options: crate::code_map::test_coverage::TestCoverageOptions::default(),
        }
    }

    fn decoded_wal_payloads(home: &std::path::Path, event_type: u8) -> Vec<serde_json::Value> {
        let mut payloads = Vec::new();
        crate::wal::scan::for_each_frame_at_home(
            home,
            crate::wal::scan::HomeWalScanLimits::default(),
            |_, frame| {
                if frame.header.event_type == event_type {
                    payloads.push(serde_json::from_slice(frame.payload).unwrap());
                }
                Ok(())
            },
        )
        .unwrap();
        payloads
    }

    fn accepted_patch_with_sentinel() -> WorkerOutcome {
        let mut outcome = green_outcome_with_real_patch();
        outcome.patch_text = [
            "diff --git a/src/lib.rs b/src/lib.rs",
            "--- a/src/lib.rs",
            "+++ b/src/lib.rs",
            "@@ -1,3 +1,3 @@",
            " pub fn target() {",
            "-    let _ = 0;",
            "+    let _ = \"W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL\";",
            " }",
            "",
        ]
        .join("\n");
        outcome
    }

    fn accepted_patch_that_git_rejects() -> WorkerOutcome {
        let mut outcome = accepted_patch_with_sentinel();
        outcome.patch_text = [
            "diff --git a/src/lib.rs b/src/lib.rs",
            "--- a/src/lib.rs",
            "+++ b/src/lib.rs",
            "@@ -1 +1 @@",
            "-different-base-line",
            "+W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL",
            "",
        ]
        .join("\n");
        outcome
    }

    fn add_rust_impact_edge_fixture(repo: &std::path::Path) {
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(
            repo.join("src/lib.rs"),
            "pub fn target() {\n    let _ = 0;\n}\n\npub fn caller_one() {\n    target();\n}\n\npub fn caller_two() {\n    target();\n}\n",
        ).unwrap();
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["add", "src/lib.rs"])
            .status()
            .unwrap();
        assert!(status.success());
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["commit", "-q", "-m", "impact fixture"])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Create enough real, multi-author history on the exact file changed by
    /// `accepted_patch_with_sentinel` to cross the production Full-autonomy
    /// structural-risk threshold. The risk gate reads `git log` itself; this
    /// is deliberately not a mocked warning or a test-only authority seam.
    fn add_real_high_risk_history(repo: &std::path::Path) -> crate::code_map::risk::RiskWarning {
        const AUTHORS: [(&str, &str); 3] = [
            ("Ada", "ada@example.com"),
            ("Blaise", "blaise@example.com"),
            ("Chien", "chien@example.com"),
        ];
        // `assess_edit_risk` reads actual `git log` ownership and churn, so
        // the fixture still needs 200 real revisions. Build them through one
        // bounded fast-import stream instead of 400 add/commit child starts;
        // `head_ref` is the initialized repository's actual branch, never a
        // guessed `main`/`master` name.
        let head_ref = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["rev-parse", "--symbolic-full-name", "HEAD"])
            .output()
            .unwrap();
        assert!(head_ref.status.success());
        let head_ref = String::from_utf8(head_ref.stdout)
            .unwrap()
            .trim()
            .to_owned();
        assert!(
            head_ref.starts_with("refs/heads/"),
            "fixture must update the initialized branch, got {head_ref:?}"
        );

        let mut source = std::fs::read_to_string(repo.join("src/lib.rs")).unwrap();
        let mut stream = Vec::new();
        let first_timestamp = crate::time::now_unix_i64();
        for revision in 0..200 {
            let (name, email) = AUTHORS[revision % AUTHORS.len()];
            source.push_str(&format!("// W88 structural-risk history {revision}\n"));
            let parent = if revision == 0 {
                head_ref.as_str().to_owned()
            } else {
                format!(":{revision}")
            };
            let timestamp = first_timestamp + revision as i64;
            stream.extend_from_slice(
                format!(
                    "commit {head_ref}\nmark :{}\nauthor {name} <{email}> {timestamp} +0000\ncommitter {name} <{email}> {timestamp} +0000\ndata 12\nrisk history\nfrom {parent}\nM 100644 inline src/lib.rs\ndata {}\n",
                    revision + 1,
                    source.len(),
                )
                .as_bytes(),
            );
            stream.extend_from_slice(source.as_bytes());
        }
        stream.extend_from_slice(b"done\n");
        let mut import = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("fast-import")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write as _;
            import.stdin.as_mut().unwrap().write_all(&stream).unwrap();
        }
        let import = import.wait_with_output().unwrap();
        assert!(
            import.status.success(),
            "git fast-import must create the real risk history: {}",
            String::from_utf8_lossy(&import.stderr)
        );
        // fast-import updates the branch ref but does not update the primary
        // worktree/index. The advisory snapshots the filesystem while the
        // dispatcher later creates a worktree from HEAD, so synchronize them.
        let reset = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["reset", "--hard", "HEAD"])
            .output()
            .unwrap();
        assert!(
            reset.status.success(),
            "git reset must synchronize the imported fixture history: {}",
            String::from_utf8_lossy(&reset.stderr)
        );
        let warnings = crate::code_map::risk::assess_edit_risk(repo, &["src/lib.rs".to_owned()]);
        let warning = warnings
            .iter()
            .find(|warning| warning.file == "src/lib.rs")
            .expect("real indexed fixture must produce a structural-risk warning");
        assert!(
            warning.risk_score >= crate::code_map::risk::HIGH_RISK_THRESHOLD,
            "history must reach the production Full-autonomy block threshold: {warning:?}"
        );
        assert_eq!(
            crate::code_map::risk::risk_gate_action(
                crate::permissions::AutonomyLevel::Full,
                warning.risk_score,
                false,
            ),
            crate::code_map::risk::RiskGateAction::Block,
            "fixture must take the real no-override structural-risk branch"
        );
        warning.clone()
    }

    async fn apply_direct_risk_refusal(
        conn: &Connection,
        session_id: KanbanSessionId,
        audit_root: &std::path::Path,
        cfg: &DispatchApplyConfig,
        provider_sentinel: &str,
    ) -> (KanbanTaskId, String) {
        let task_id = store::insert_task(conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(conn, task_id, Hemisphere::Left, None, None).unwrap();
        let task = store::list_tasks_for_session(conn, session_id)
            .unwrap()
            .into_iter()
            .find(|task| task.task_id == task_id)
            .unwrap();
        let mut worker_outcome = accepted_patch_with_sentinel();
        worker_outcome.summary = provider_sentinel.to_owned();
        let worker = CannedWorker {
            outcome: worker_outcome,
            name: "w88-real-risk-refusal",
        };
        let accepted = WorkerContract::for_dispatch(&task, &worker, audit_root)
            .validate_and_materialize(&task, &worker, worker.outcome.clone())
            .expect("fixture outcome crosses the immutable accepted-patch boundary");
        let admission = authorize_patch_apply_before_worktree(&task, &accepted, cfg)
            .await
            .expect("permission gate admits the exact local CLI request")
            .expect("fixture has a patch to apply");
        let error = apply_admitted_patch_in_worktree(admission, &task, &accepted, cfg, None)
            .expect_err("real structural-risk gate must refuse the accepted patch");
        let worktree = cfg
            .repo_root
            .parent()
            .unwrap()
            .join(format!(".neoth-task-{}", task_id.raw()));
        assert!(
            !worktree.exists(),
            "risk refusal must clean its pre-edit worktree without applying a patch"
        );
        (task_id, error)
    }

    fn accepted_patch_with_capped_impact() -> WorkerOutcome {
        accepted_patch_with_sentinel()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn risk_block_emits_preapply_advisory_receipt_without_changing_risk_authority() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        // The production risk gate reads the process-default NEOTH_HOME for
        // override leases. Serialize and isolate it so this fixture proves the
        // no-override Block branch without inheriting an ambient lease.
        let _env = crate::test_env::lock();
        let previous_home = std::env::var_os("NEOTH_HOME");
        struct RestoreNeothHome(Option<std::ffi::OsString>);
        impl Drop for RestoreNeothHome {
            fn drop(&mut self) {
                unsafe {
                    match self.0.take() {
                        Some(home) => std::env::set_var("NEOTH_HOME", home),
                        None => std::env::remove_var("NEOTH_HOME"),
                    }
                }
            }
        }

        let (dir, conn) = fresh_db();
        let home = dir.path().join("neoth-home");
        unsafe { std::env::set_var("NEOTH_HOME", &home) };
        let _restore_home = RestoreNeothHome(previous_home);
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();
        add_rust_impact_edge_fixture(&repo);
        let risk_warning = add_real_high_risk_history(&repo);
        let root = crate::code_map::CanonicalRepoRoot::discover(&repo).unwrap();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let (writer, writer_join) = authenticated_apply_writer(&home);
        let available = indexed_pre_apply_advisory(
            &repo,
            dir.path().join("available-code-map.db"),
            crate::code_map::ImpactOptions::default(),
        );
        let expected_patch = accepted_patch_with_sentinel().patch_text;
        let read_only = crate::code_map::persist::open_read_only(&available.database_path).unwrap();
        let expected_impact = crate::code_map::analyze_diff_impact(
            &read_only,
            &crate::code_map::DiffImpactRequest {
                repo_root: available.root.path().to_path_buf(),
                input: crate::code_map::DiffImpactInput::stdin(expected_patch),
                options: available.impact_options,
            },
        )
        .unwrap();
        let expected_gap = crate::code_map::test_coverage::test_gap_for_impact(
            &read_only,
            &expected_impact.impact,
            crate::code_map::test_coverage::TestCoverageOptions::default(),
        )
        .unwrap();

        let available_cfg = local_test_apply_config(&repo, &writer).with_pre_apply_impact_advisory(
            available.database_path.clone(),
            available.root.clone(),
            available.impact_options,
        );
        let (available_task, available_error) = apply_direct_risk_refusal(
            &conn,
            session_id,
            dir.path(),
            &available_cfg,
            "W88_PROVIDER_TEXT_MUST_NOT_REACH_WAL_AVAILABLE",
        )
        .await;
        drop(available_cfg);

        let stale_database = dir.path().join("stale-code-map.db");
        crate::code_map::rebuild_snapshot(&root, &stale_database, Default::default()).unwrap();
        std::fs::write(repo.join("README.md"), "initial\nmake advisory stale\n").unwrap();
        let stale_cfg = local_test_apply_config(&repo, &writer).with_pre_apply_impact_advisory(
            stale_database,
            root.clone(),
            crate::code_map::ImpactOptions::default(),
        );
        let (stale_task, stale_error) = apply_direct_risk_refusal(
            &conn,
            session_id,
            dir.path(),
            &stale_cfg,
            "W88_PROVIDER_TEXT_MUST_NOT_REACH_WAL_STALE",
        )
        .await;
        drop(stale_cfg);

        let missing_cfg = local_test_apply_config(&repo, &writer).with_pre_apply_impact_advisory(
            dir.path().join("missing-code-map.db"),
            root,
            crate::code_map::ImpactOptions::default(),
        );
        let (missing_task, missing_error) = apply_direct_risk_refusal(
            &conn,
            session_id,
            dir.path(),
            &missing_cfg,
            "W88_PROVIDER_TEXT_MUST_NOT_REACH_WAL_MISSING",
        )
        .await;
        drop(missing_cfg);

        let expected_risk_error = |task_id: KanbanTaskId| {
            format!(
                "risk gate blocked edit of `src/lib.rs` for task {} \
                 (risk={:.2}, autonomy=Full) — \
                 grant an override lease to allow: \
                 `neoth lease grant operator dangerous_command --ttl 300`",
                task_id.raw(),
                risk_warning.risk_score,
            )
        };
        assert_eq!(available_error, expected_risk_error(available_task));
        assert_eq!(stale_error, expected_risk_error(stale_task));
        assert_eq!(missing_error, expected_risk_error(missing_task));
        assert!(
            !std::fs::read_to_string(repo.join("src/lib.rs"))
                .unwrap()
                .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL"),
            "risk refusal must not apply the immutable accepted patch to the repository"
        );

        drop(writer);
        writer_join.await.unwrap();
        let payloads =
            decoded_wal_payloads(&home, crate::wal::events::EVENT_TYPE_PATCH_APPLY_FAILED);
        for task_id in [available_task, stale_task, missing_task] {
            assert_eq!(
                payloads
                    .iter()
                    .filter(|payload| payload["task_id"].as_i64() == Some(task_id.raw()))
                    .count(),
                1,
                "one actual refusal must write exactly one PATCH_APPLY_FAILED receipt"
            );
        }
        let by_task = |task_id: KanbanTaskId| {
            payloads
                .iter()
                .find(|payload| payload["task_id"].as_i64() == Some(task_id.raw()))
                .unwrap()
        };
        let available_payload = by_task(available_task);
        assert_eq!(available_payload["stage"].as_str(), Some("risk"));
        let receipt = &available_payload["pre_apply_impact_advisory"];
        assert_eq!(receipt["state"].as_str(), Some("available"));
        let citation = &receipt["citation"];
        assert_eq!(
            citation["root_identity"].as_str(),
            Some(available.root.identity().as_str())
        );
        assert!(citation["index_generation"].as_i64().unwrap() > 0);
        assert_eq!(citation["index_generation"], citation["graph_generation"]);
        assert_eq!(
            citation["impact_digest"].as_str(),
            Some(expected_impact.impact.digest.as_str())
        );
        assert_eq!(
            citation["outcome"],
            serde_json::to_value(&expected_gap.outcome).unwrap()
        );
        assert_eq!(
            citation["no_observed_test_is_not_absence"].as_bool(),
            Some(expected_gap.no_observed_test_is_not_absence)
        );

        let stale_payload = by_task(stale_task);
        let stale_receipt = &stale_payload["pre_apply_impact_advisory"];
        assert_eq!(stale_payload["stage"].as_str(), Some("risk"));
        assert_eq!(receipt_unavailable_reason(stale_receipt), "stale");
        assert!(stale_receipt["citation"].is_null());
        let missing_payload = by_task(missing_task);
        let missing_receipt = &missing_payload["pre_apply_impact_advisory"];
        assert_eq!(missing_payload["stage"].as_str(), Some("risk"));
        assert_eq!(
            receipt_unavailable_reason(missing_receipt),
            "database_unavailable"
        );
        assert!(missing_receipt["citation"].is_null());

        let serialized = serde_json::to_string(&payloads).unwrap();
        assert!(!serialized.contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL"));
        assert!(!serialized.contains("W88_PROVIDER_TEXT_MUST_NOT_REACH_WAL"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_worker_patch_applies_with_preworktree_advisory_and_decoded_wal_citation() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();
        add_rust_impact_edge_fixture(&repo);
        let advisory = indexed_pre_apply_advisory(
            &repo,
            dir.path().join("code-map.db"),
            crate::code_map::ImpactOptions::default(),
        );
        let root = advisory.root.clone();
        let patch = accepted_patch_with_sentinel();
        let accepted_patch_bytes = patch.patch_text.clone();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: patch,
                name: "w49-advisory-applied",
            }),
        );
        let home = dir.path().join("neoth-home");
        let (writer, writer_join) = authenticated_apply_writer(&home);
        let apply_cfg = local_test_apply_config(&repo, &writer)
            .with_autonomy(crate::permissions::AutonomyLevel::Standard)
            .with_pre_apply_impact_advisory(
                advisory.database_path.clone(),
                advisory.root.clone(),
                advisory.impact_options,
            );

        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.tasks_completed, 1,
            "advisory cannot block admitted apply; outcome={outcome:?}"
        );
        let worktree = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        assert!(
            std::fs::read_to_string(worktree.join("src/lib.rs"))
                .unwrap()
                .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL"),
            "accepted mapped patch reached a real worktree"
        );
        drop(apply_cfg);
        drop(workers);
        drop(writer);
        writer_join.await.unwrap();

        let payloads = decoded_wal_payloads(&home, crate::wal::events::EVENT_TYPE_PATCH_APPLIED);
        let payload = payloads
            .iter()
            .find(|payload| payload["task_id"].as_i64() == Some(task_id.raw()))
            .expect("PATCH_APPLIED WAL receipt");
        let receipt = &payload["pre_apply_impact_advisory"];
        assert_eq!(receipt["state"].as_str(), Some("available"));
        let citation = &receipt["citation"];
        assert_eq!(
            citation["root_identity"].as_str(),
            Some(root.identity().as_str())
        );
        assert!(citation["index_generation"].as_i64().unwrap() > 0);
        assert_eq!(citation["index_generation"], citation["graph_generation"]);
        let read_only = crate::code_map::persist::open_read_only(&advisory.database_path).unwrap();
        let expected = crate::code_map::analyze_diff_impact(
            &read_only,
            &crate::code_map::DiffImpactRequest {
                repo_root: root.path().to_path_buf(),
                input: crate::code_map::DiffImpactInput::stdin(accepted_patch_bytes.clone()),
                options: crate::code_map::ImpactOptions::default(),
            },
        )
        .unwrap();
        assert_eq!(
            citation["impact_digest"].as_str(),
            Some(expected.impact.digest.as_str())
        );
        assert!(
            !serde_json::to_string(payload)
                .unwrap()
                .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL")
        );
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &worktree, true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_worker_rejected_patch_keeps_preworktree_advisory_in_decoded_failed_wal() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();
        add_rust_impact_edge_fixture(&repo);
        let advisory = indexed_pre_apply_advisory(
            &repo,
            dir.path().join("code-map.db"),
            crate::code_map::ImpactOptions::default(),
        );
        let patch = accepted_patch_that_git_rejects();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: patch,
                name: "w49-advisory-rejected",
            }),
        );
        let home = dir.path().join("neoth-home");
        let (writer, writer_join) = authenticated_apply_writer(&home);
        let apply_cfg = local_test_apply_config(&repo, &writer)
            .with_autonomy(crate::permissions::AutonomyLevel::Standard)
            .with_pre_apply_impact_advisory(
                advisory.database_path.clone(),
                advisory.root.clone(),
                advisory.impact_options,
            );

        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.tasks_completed, 0,
            "real git rejection remains a normal failed apply"
        );
        drop(apply_cfg);
        drop(workers);
        drop(writer);
        writer_join.await.unwrap();

        let payloads =
            decoded_wal_payloads(&home, crate::wal::events::EVENT_TYPE_PATCH_APPLY_FAILED);
        let payload = payloads
            .iter()
            .find(|payload| payload["task_id"].as_i64() == Some(task_id.raw()))
            .expect("PATCH_APPLY_FAILED WAL receipt");
        let receipt = &payload["pre_apply_impact_advisory"];
        assert_eq!(receipt["state"].as_str(), Some("available"));
        assert_eq!(
            receipt["citation"]["root_identity"].as_str(),
            Some(advisory.root.identity().as_str())
        );
        assert!(receipt["citation"]["index_generation"].as_i64().unwrap() > 0);
        assert!(
            !serde_json::to_string(payload)
                .unwrap()
                .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_or_stale_preapply_advisory_cannot_change_admission_or_real_apply() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        for stale in [false, true] {
            let (dir, conn) = fresh_db();
            let repo = dir.path().join("repo");
            std::fs::create_dir_all(&repo).unwrap();
            init_repo(&repo).unwrap();
            add_rust_impact_edge_fixture(&repo);
            let root = crate::code_map::CanonicalRepoRoot::discover(&repo).unwrap();
            let database_path = dir.path().join("code-map.db");
            if stale {
                crate::code_map::rebuild_snapshot(&root, &database_path, Default::default())
                    .unwrap();
                std::fs::write(repo.join("README.md"), "initial\nexternal stale change\n").unwrap();
            }
            let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
            let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
            store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
            let mut workers = HemisphereWorkerSet::new();
            workers.bind(
                Hemisphere::Left,
                Box::new(CannedWorker {
                    outcome: accepted_patch_with_sentinel(),
                    name: "w49-unavailable-advisory",
                }),
            );
            let home = dir.path().join("neoth-home");
            let (writer, writer_join) = authenticated_apply_writer(&home);
            let advisory = PreApplyImpactAdvisoryConfig {
                database_path,
                root,
                impact_options: crate::code_map::ImpactOptions::default(),
                coverage_options: crate::code_map::test_coverage::TestCoverageOptions::default(),
            };
            let apply_cfg = local_test_apply_config(&repo, &writer)
                .with_autonomy(crate::permissions::AutonomyLevel::Standard)
                .with_pre_apply_impact_advisory(
                    advisory.database_path.clone(),
                    advisory.root.clone(),
                    advisory.impact_options,
                );

            let outcome = dispatch_session_with_apply(
                &conn,
                session_id,
                &workers,
                DispatchBudget::default(),
                Some(&apply_cfg),
            )
            .await
            .unwrap();
            assert_eq!(
                outcome.tasks_completed, 1,
                "unavailable advisory cannot change apply; outcome={outcome:?}"
            );
            assert_eq!(
                outcome.applied_task_ids,
                vec![task_id.raw()],
                "unavailable advisory must retain the exact real apply receipt; outcome={outcome:?}"
            );
            let worktree = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
            assert!(
                std::fs::read_to_string(worktree.join("src/lib.rs"))
                    .unwrap()
                    .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL"),
                "unavailable advisory must not skip the admitted worktree patch"
            );
            drop(apply_cfg);
            drop(workers);
            drop(writer);
            writer_join.await.unwrap();
            let payloads =
                decoded_wal_payloads(&home, crate::wal::events::EVENT_TYPE_PATCH_APPLIED);
            let payload = payloads
                .iter()
                .find(|payload| payload["task_id"].as_i64() == Some(task_id.raw()))
                .unwrap();
            let reason = receipt_unavailable_reason(&payload["pre_apply_impact_advisory"]);
            assert_eq!(
                reason,
                if stale {
                    "stale"
                } else {
                    "database_unavailable"
                }
            );
            assert!(
                !serde_json::to_string(payload)
                    .unwrap()
                    .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL")
            );
            let _ = crate::coding::worktree::cleanup_worktree(&repo, &worktree, true);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capped_preapply_impact_is_typed_but_cannot_change_admission_or_real_apply() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();
        add_rust_impact_edge_fixture(&repo);
        let mut impact_options = crate::code_map::ImpactOptions::default();
        impact_options.max_nodes = 1;
        let advisory =
            indexed_pre_apply_advisory(&repo, dir.path().join("code-map.db"), impact_options);
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: accepted_patch_with_capped_impact(),
                name: "w49-capped-advisory",
            }),
        );
        let home = dir.path().join("neoth-home");
        let (writer, writer_join) = authenticated_apply_writer(&home);
        let mut apply_cfg = local_test_apply_config(&repo, &writer)
            .with_autonomy(crate::permissions::AutonomyLevel::Standard);
        apply_cfg.pre_apply_impact_advisory = Some(advisory);

        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.tasks_completed, 1,
            "capped evidence is informational only; outcome={outcome:?}"
        );
        assert_eq!(
            outcome.applied_task_ids,
            vec![task_id.raw()],
            "capped advisory must retain the exact real apply receipt; outcome={outcome:?}"
        );
        let worktree = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        assert!(
            std::fs::read_to_string(worktree.join("src/lib.rs"))
                .unwrap()
                .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL"),
            "capped advisory must not skip the admitted worktree patch"
        );
        drop(apply_cfg);
        drop(workers);
        drop(writer);
        writer_join.await.unwrap();
        let payloads = decoded_wal_payloads(&home, crate::wal::events::EVENT_TYPE_PATCH_APPLIED);
        let payload = payloads
            .iter()
            .find(|payload| payload["task_id"].as_i64() == Some(task_id.raw()))
            .unwrap();
        let receipt = &payload["pre_apply_impact_advisory"];
        assert_eq!(
            receipt["state"].as_str(),
            Some("available"),
            "capped impact receipt state: receipt={receipt:?}; outcome={outcome:?}"
        );
        assert_eq!(
            receipt["citation"]["outcome"]["rejected_input"].as_str(),
            Some("truncated"),
            "capped impact receipt must retain typed truncation: receipt={receipt:?}; outcome={outcome:?}"
        );
        assert!(
            receipt["citation"]["impact_partial"].as_bool().unwrap(),
            "capped impact receipt must mark partial evidence: receipt={receipt:?}; outcome={outcome:?}"
        );
        assert!(
            !serde_json::to_string(payload)
                .unwrap()
                .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL")
        );
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &worktree, true);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn apply_wal_advisory_uses_narrow_and_wide_configured_impact_policies() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }

        let mut citations = Vec::new();
        for (label, max_nodes) in [("narrow", 1), ("wide", 8)] {
            let (dir, conn) = fresh_db();
            let repo = dir.path().join("repo");
            std::fs::create_dir_all(&repo).unwrap();
            init_repo(&repo).unwrap();
            add_rust_impact_edge_fixture(&repo);

            let policy = crate::config::CodeMapImpactPolicy {
                max_depth: crate::config::CodeMapImpactPolicy::default().max_depth,
                max_nodes,
                allow_stale: false,
            };
            policy.validate().unwrap();
            let advisory = indexed_pre_apply_advisory(
                &repo,
                dir.path().join("code-map.db"),
                policy.impact_options(),
            );
            let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
            let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
            store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
            let mut workers = HemisphereWorkerSet::new();
            workers.bind(
                Hemisphere::Left,
                Box::new(CannedWorker {
                    outcome: accepted_patch_with_capped_impact(),
                    name: label,
                }),
            );
            let home = dir.path().join("neoth-home");
            let (writer, writer_join) = authenticated_apply_writer(&home);
            let apply_cfg = local_test_apply_config(&repo, &writer)
                .with_autonomy(crate::permissions::AutonomyLevel::Standard)
                .with_pre_apply_impact_advisory(
                    advisory.database_path.clone(),
                    advisory.root.clone(),
                    advisory.impact_options,
                );

            let outcome = dispatch_session_with_apply(
                &conn,
                session_id,
                &workers,
                DispatchBudget::default(),
                Some(&apply_cfg),
            )
            .await
            .unwrap();
            assert_eq!(outcome.applied_task_ids, vec![task_id.raw()]);
            let worktree = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
            assert!(worktree.join("src/lib.rs").is_file());

            drop(apply_cfg);
            drop(workers);
            drop(writer);
            writer_join.await.unwrap();
            let payloads =
                decoded_wal_payloads(&home, crate::wal::events::EVENT_TYPE_PATCH_APPLIED);
            let payload = payloads
                .iter()
                .find(|payload| payload["task_id"].as_i64() == Some(task_id.raw()))
                .expect("PATCH_APPLIED WAL receipt");
            let citation = payload["pre_apply_impact_advisory"]["citation"].clone();
            assert_eq!(
                citation["root_identity"].as_str(),
                Some(advisory.root.identity().as_str())
            );
            assert!(citation["index_generation"].as_i64().unwrap() > 0);
            assert_eq!(citation["index_generation"], citation["graph_generation"]);
            assert!(
                !serde_json::to_string(payload)
                    .unwrap()
                    .contains("W49_RAW_PATCH_SENTINEL_MUST_NOT_REACH_WAL")
            );
            citations.push(citation);
            let _ = crate::coding::worktree::cleanup_worktree(&repo, &worktree, true);
        }

        let narrow = &citations[0];
        let wide = &citations[1];
        assert_eq!(
            narrow["outcome"]["rejected_input"].as_str(),
            Some("truncated")
        );
        assert_eq!(narrow["impact_partial"].as_bool(), Some(true));
        assert_eq!(wide["impact_partial"].as_bool(), Some(false));
        assert!(
            wide["nodes"].as_array().unwrap().len() > narrow["nodes"].as_array().unwrap().len(),
            "wide configured policy must reach the real Apply WAL advisory"
        );
    }

    fn receipt_unavailable_reason(receipt: &serde_json::Value) -> &str {
        receipt["state"]["unavailable"]
            .as_str()
            .expect("typed unavailable advisory state")
    }

    #[test]
    fn pre_apply_impact_missing_database_is_typed_and_never_retains_patch_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let root = crate::code_map::CanonicalRepoRoot::discover(&repo).unwrap();
        let raw_sentinel = "RAW_PRE_APPLY_PATCH_SENTINEL_DO_NOT_PERSIST";
        let config = PreApplyImpactAdvisoryConfig {
            database_path: dir.path().join("absent-code-map.db"),
            root: root.clone(),
            impact_options: crate::code_map::ImpactOptions::default(),
            coverage_options: crate::code_map::test_coverage::TestCoverageOptions::default(),
        };

        let advisory = pre_apply_impact_advisory(Some(&config), &root, raw_sentinel)
            .expect("configured advisory returns typed degradation");
        assert!(matches!(
            advisory.state,
            PreApplyImpactAdvisoryState::Unavailable(
                PreApplyImpactAdvisoryUnavailable::DatabaseUnavailable
            )
        ));
        let serialized =
            serde_json::to_string(&pre_apply_impact_advisory_wal_value(Some(&advisory))).unwrap();
        assert!(!serialized.contains(raw_sentinel));
        assert!(serialized.len() <= MAX_PRE_APPLY_IMPACT_ADVISORY_WAL_BYTES);
    }

    #[test]
    fn pre_apply_impact_indexed_accepted_patch_has_root_generation_and_digest_citation() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();
        add_rust_impact_edge_fixture(&repo);
        let root = crate::code_map::CanonicalRepoRoot::discover(&repo).unwrap();
        let db = dir.path().join("code-map.db");
        crate::code_map::rebuild_snapshot(&root, &db, Default::default()).unwrap();
        let patch = accepted_patch_with_sentinel();
        let config = PreApplyImpactAdvisoryConfig {
            database_path: db,
            root: root.clone(),
            impact_options: crate::code_map::ImpactOptions::default(),
            coverage_options: crate::code_map::test_coverage::TestCoverageOptions::default(),
        };

        let advisory = pre_apply_impact_advisory(Some(&config), &root, &patch.patch_text)
            .expect("configured advisory returns a receipt");
        let citation = advisory
            .citation
            .as_ref()
            .expect("indexed accepted patch has bounded citation");
        assert!(matches!(
            advisory.state,
            PreApplyImpactAdvisoryState::Available
        ));
        assert_eq!(citation.root_identity, root.identity().as_str());
        assert!(citation.index_generation > 0);
        assert_eq!(citation.index_generation, citation.graph_generation);
        assert_eq!(citation.impact_digest.len(), 64);
        let serialized = serde_json::to_string(&pre_apply_impact_advisory_wal_value(Some(
            &PreApplyImpactAdvisory {
                state: PreApplyImpactAdvisoryState::Available,
                citation: Some(citation.clone()),
                diagnostic: None,
            },
        )))
        .unwrap();
        assert!(!serialized.contains(&patch.patch_text));
        assert!(serialized.len() <= MAX_PRE_APPLY_IMPACT_ADVISORY_WAL_BYTES);
    }

    fn gui_test_apply_config(
        repo: &std::path::Path,
        writer: &std::sync::Arc<crate::wal::writer::WalWriterHandle>,
        broker: crate::coding::service::GuiPatchApprovalBroker,
    ) -> DispatchApplyConfig {
        let mut config = DispatchApplyConfig::new(repo, ApplyOrigin::GuiRequested)
            .with_autonomy(crate::permissions::AutonomyLevel::Full)
            .with_gui_interactive_confirmation()
            .with_wal_writer(std::sync::Arc::clone(writer));
        config.attach_gui_patch_approval_broker(broker);
        config
    }

    #[test]
    fn patch_apply_binding_uses_physical_root_patch_task_and_origin() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let canonical = crate::code_map::CanonicalRepoRoot::discover(&first).unwrap();
        let alias = crate::code_map::CanonicalRepoRoot::discover(&first.join(".")).unwrap();
        let other = crate::code_map::CanonicalRepoRoot::discover(&second).unwrap();
        let task = KanbanTaskId(42);
        let patch: [u8; 32] = Sha256::digest(b"accepted patch").into();
        let changed_patch: [u8; 32] = Sha256::digest(b"accepted patch changed").into();
        let binding = patch_apply_request_binding(
            canonical.identity().as_str(),
            task,
            &patch,
            ApplyOrigin::CliConfirmed,
        );
        assert_eq!(
            binding,
            patch_apply_request_binding(
                alias.identity().as_str(),
                task,
                &patch,
                ApplyOrigin::CliConfirmed,
            ),
            "canonical spelling aliases bind identically"
        );
        assert_ne!(
            binding,
            patch_apply_request_binding(
                other.identity().as_str(),
                task,
                &patch,
                ApplyOrigin::CliConfirmed,
            )
        );
        assert_ne!(
            binding,
            patch_apply_request_binding(
                canonical.identity().as_str(),
                task,
                &changed_patch,
                ApplyOrigin::CliConfirmed,
            )
        );
        assert_ne!(
            binding,
            patch_apply_request_binding(
                canonical.identity().as_str(),
                KanbanTaskId(43),
                &patch,
                ApplyOrigin::CliConfirmed,
            )
        );
        assert_ne!(
            binding,
            patch_apply_request_binding(
                canonical.identity().as_str(),
                task,
                &patch,
                ApplyOrigin::DaemonScheduled,
            )
        );
    }

    #[tokio::test]
    async fn dispatch_session_with_apply_records_command_receipt_on_zero_exit() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();

        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut outcome_template = green_outcome_with_real_patch();
        // Deliberately distinct from the trusted command receipt below. A
        // successful configured command proves that one command passed; it
        // does not prove these provider-claimed per-test counts.
        outcome_template.tests = TestSummary {
            added: 7,
            total: 7,
            passing: 7,
            failing: 0,
            skipped: 0,
            applied: false,
        };

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "phase4-test-pass",
            }),
        );

        let (writer, _writer_join) = authenticated_apply_writer(&dir.path().join("neoth-home"));
        let apply_cfg = local_test_apply_config(&repo, &writer)
            .with_test_cmd(always_pass_cmd_str())
            .with_test_timeout(std::time::Duration::from_secs(10));
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .expect("dispatch with test_cmd");

        assert_eq!(outcome.tasks_completed, 1, "passing tests must complete");
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            task.test_summary,
            Some(TestSummary::verified_command_passed()),
            "a passing configured command records only its truthful receipt, not provider counts"
        );

        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &wt, true);
    }

    #[tokio::test]
    async fn dispatch_session_with_apply_routes_test_failure_to_retry_path() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();

        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let outcome_template = green_outcome_with_real_patch();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "phase4-test-fail",
            }),
        );

        let (writer, _writer_join) = authenticated_apply_writer(&dir.path().join("neoth-home"));
        let apply_cfg = local_test_apply_config(&repo, &writer)
            .with_test_cmd(always_fail_cmd_str())
            .with_test_timeout(std::time::Duration::from_secs(10));
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .expect("dispatch with failing test_cmd");

        // Failing tests must NOT mark complete + must route the
        // task through the retry-policy path → Blocked at the
        // ceiling (3 attempts for the default WorkerRetryPolicy).
        assert_eq!(outcome.tasks_completed, 0);

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .into_iter()
            .find(|t| t.task_id == task_id)
            .unwrap();
        // The retry path leaves the task in Backlog (re-queue)
        // OR Blocked (ceiling hit) — both are acceptable end
        // states; we just must NOT see Review/Done from a
        // failing test.
        assert!(
            matches!(task.status, TaskStatus::Blocked | TaskStatus::Backlog),
            "failing tests must NOT promote; got {:?}",
            task.status
        );

        // Cleanup any worktree the apply created before the
        // test-fail bounce.
        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        if wt.exists() {
            let _ = crate::coding::worktree::cleanup_worktree(&repo, &wt, true);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatch_session_with_apply_emits_patch_applied_wal_frame() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();

        // Home-backed writer so the final Gate decision has its mandatory
        // HMAC marker before the historical PATCH_APPLIED frame is emitted.
        let home = dir.path().join("neoth-home");
        let (writer, _wal_join) = authenticated_apply_writer(&home);
        let wal_seg = home.join("wal");

        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let outcome_template = green_outcome_with_real_patch();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "ph4-wal-emit",
            }),
        );

        let apply_cfg = local_test_apply_config(&repo, &writer);

        // QU-10d: the dispatcher is now async — await it directly. The
        // prior spawn_blocking + Arc<Mutex<conn>> wrapper (needed when the
        // dispatcher was sync) is obsolete; the WAL writer task still
        // flushes concurrently on the multi-thread runtime.
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .expect("dispatch");

        assert_eq!(outcome.tasks_completed, 1);

        // Give the writer task a beat to flush the frame.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Read the segment back via the WAL reader + assert a
        // PATCH_APPLIED frame appears.
        let bytes = std::fs::read_dir(&wal_seg)
            .expect("read home WAL directory")
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| std::fs::read(entry.path()).ok())
            .flatten()
            .collect::<Vec<_>>();
        // The 0xD3 byte appears in every PATCH_APPLIED frame's
        // event_type field. A more rigorous check would walk
        // the frames via the proper reader; this byte-presence
        // smoke is sufficient to pin the emit lands.
        assert!(
            bytes.contains(&crate::wal::events::EVENT_TYPE_PATCH_APPLIED),
            "WAL segment must contain a 0xD3 byte from PATCH_APPLIED frame"
        );

        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &wt, true);
    }

    #[tokio::test]
    async fn lf_p1_03_patch_apply_failed_wal_sanitizes_ansi_split_secret() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("failed.wal");
        let (writer, writer_join) =
            crate::wal::writer::spawn(wal_path.clone()).expect("spawn WAL writer");
        let task = notes_task(Some("WAL redaction fixture"));
        let secret = concat!("sk-", "FAKE_TEST_PATCH_FAILURE_AAAAAAAAAAAAA");
        let reason = format!("rustc: \x1b[31m{secret}\x1b[0m at ../src/lib.rs");
        let worktree =
            std::path::PathBuf::from(format!("workspace/\x1b[35m{secret}\x1b[0m/task-worktree"));

        emit_patch_apply_failed_wal(Some(&writer), &task, &worktree, "tests", &reason, None);
        drop(writer);
        writer_join.await.expect("WAL writer join");

        let bytes = std::fs::read(&wal_path).unwrap();
        let segment = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let frame = crate::wal::frame::decode_frame(&bytes[segment.header_len()..]).unwrap();
        assert_eq!(
            frame.header.event_type,
            crate::wal::events::EVENT_TYPE_PATCH_APPLY_FAILED
        );
        let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        let persisted_reason = payload["reason"].as_str().unwrap();
        assert!(!persisted_reason.contains(secret));
        assert!(!persisted_reason.contains('\x1b'));
        assert!(persisted_reason.contains("REDACTED"));
        assert!(persisted_reason.contains("../src/lib.rs"));
        let persisted_path = payload["worktree_path"].as_str().unwrap();
        assert!(!persisted_path.contains(secret));
        assert!(!persisted_path.contains('\x1b'));
        assert!(persisted_path.contains("REDACTED"));
        assert!(persisted_path.contains("task-worktree"));
        assert_eq!(payload["stage"], "tests");
        assert_eq!(payload["task_id"], task.task_id.raw());
    }

    #[tokio::test]
    async fn dispatch_session_with_apply_strict_autonomy_denies_before_any_io() {
        // Strict autonomy MUST refuse the apply BEFORE creating
        // the worktree. The task ends in Blocked/Backlog via the
        // retry path; no `.neoth-task-N/` directory is created.
        let (dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "phase4-strict",
            }),
        );

        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let home = dir.path().join("neoth-home");
        let (writer, _writer_join) = authenticated_apply_writer(&home);
        let apply_cfg = DispatchApplyConfig::new(&repo, ApplyOrigin::CliConfirmed)
            .with_autonomy(crate::permissions::AutonomyLevel::Strict)
            .with_local_cli_confirmation()
            .with_wal_writer(std::sync::Arc::clone(&writer));
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .expect("dispatch with strict autonomy");

        assert_eq!(outcome.tasks_completed, 0, "strict must NOT complete");
        // No worktree created — the gate denied before
        // worktree::create_task_worktree ran.
        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        assert!(!wt.exists(), "strict gate must run BEFORE worktree IO");
        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
            .expect("strict denial is authenticated before the no-effect return");
        assert!(matches!(
            ledger.completeness,
            crate::permissions::TrustLedgerCompleteness::Complete
        ));
        assert!(
            !ledger.entries.is_empty(),
            "each strict retry must retain a typed final decision"
        );
        assert!(ledger.entries.iter().all(|entry| {
            entry.event.action == crate::permissions::ActionKind::PatchApplyToRepo
                && entry.event.outcome == crate::permissions::TrustOutcome::Denied
        }));
    }

    #[tokio::test]
    async fn dispatch_session_with_apply_full_autonomy_still_applies_under_confirm() {
        // Full autonomy yields Decision::Confirm for
        // PatchApplyToRepo (v0.2-conservative). The CLI
        // pre-confirmed via --apply, so the dispatcher
        // degrades Confirm → Allow and the apply lands.
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();

        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let outcome_template = green_outcome_with_real_patch();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "phase4-full-autonomy",
            }),
        );

        let (writer, _writer_join) = authenticated_apply_writer(&dir.path().join("neoth-home"));
        let apply_cfg = local_test_apply_config(&repo, &writer);
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .expect("dispatch full");

        assert_eq!(
            outcome.tasks_completed, 1,
            "full → confirm → allow → complete"
        );
        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(
            &dir.path().join("neoth-home"),
            "local",
        )
        .expect("the allowed decision is HMAC-complete while the worktree exists");
        assert_eq!(ledger.entries.len(), 1, "one final Gate decision per apply");
        assert!(matches!(
            ledger.entries[0].event.outcome,
            crate::permissions::TrustOutcome::Allowed
        ));

        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &wt, true);
    }

    #[tokio::test]
    async fn native_gui_grant_records_one_bound_decision_before_worktree_effect() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();
        let home = dir.path().join("neoth-home");
        let (writer, _writer_join) = authenticated_apply_writer(&home);
        let session_id = store::insert_session(&conn, 1, "p", "h", "gui", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let accepted_patch = green_outcome_with_real_patch();
        let canonical = crate::code_map::CanonicalRepoRoot::discover(&repo).unwrap();
        let accepted_patch_sha256: [u8; 32] =
            Sha256::digest(accepted_patch.patch_text.as_bytes()).into();
        let expected_binding = patch_apply_request_binding(
            canonical.identity().as_str(),
            task_id,
            &accepted_patch_sha256,
            ApplyOrigin::GuiRequested,
        );
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: accepted_patch,
                name: "native-gui-approved",
            }),
        );
        let (broker, _cancellation) =
            crate::coding::service::GuiPatchApprovalBroker::for_dispatch_test();
        let pause = patch_apply_pause(PatchApplyPausePoint::AfterAdmission);
        let cfg = gui_test_apply_config(&repo, &writer, broker.clone())
            .with_test_pause(Arc::clone(&pause));
        let dispatch = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&cfg),
        );
        let approve = async {
            let metadata = broker.wait_for_pending_metadata_for_test().await;
            assert_eq!(metadata.task_id, task_id);
            assert_eq!(metadata.request_binding_sha256, expected_binding);
            let response = broker.respond_for_test(metadata.approval_id, true).await;
            wait_for_patch_apply_pause(&pause).await;
            let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
                .expect("the required GUI decision is durable before any worktree effect");
            assert_eq!(ledger.entries.len(), 1);
            assert_eq!(
                ledger.entries[0].event.request_binding_sha256.as_deref(),
                Some(expected_binding.as_str())
            );
            assert!(
                !dir.path()
                    .join(format!(".neoth-task-{}", task_id.raw()))
                    .exists(),
                "the after-admission pause precedes worktree creation"
            );
            pause.release.notify_one();
            response
        };
        let (outcome, response) = tokio::join!(dispatch, approve);
        assert_eq!(response, crate::coding::PatchApprovalResponse::Accepted);
        assert_eq!(outcome.unwrap().tasks_completed, 1);
        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
            .expect("native GUI Gate decision must be HMAC complete before worktree apply");
        assert_eq!(ledger.entries.len(), 1);
        let event = &ledger.entries[0].event;
        assert_eq!(
            event.action,
            crate::permissions::ActionKind::PatchApplyToRepo
        );
        assert_eq!(
            event.confirmation_source.as_deref(),
            Some("native_gui_patch_approval")
        );
        assert_eq!(
            event.request_binding_sha256.as_deref(),
            Some(expected_binding.as_str())
        );
        assert!(matches!(
            event.outcome,
            crate::permissions::TrustOutcome::Allowed
        ));
        let worktree = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        assert!(
            worktree.exists(),
            "admitted GUI patch must create its worktree"
        );
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &worktree, true);
    }

    #[tokio::test]
    async fn native_gui_route_without_run_broker_has_no_gate_or_worktree_authority() {
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let home = dir.path().join("neoth-home");
        let (writer, _writer_join) = authenticated_apply_writer(&home);
        let session_id = store::insert_session(&conn, 1, "p", "h", "gui", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "native-gui-missing-broker",
            }),
        );
        let cfg = DispatchApplyConfig::new(&repo, ApplyOrigin::GuiRequested)
            .with_autonomy(crate::permissions::AutonomyLevel::Full)
            .with_gui_interactive_confirmation()
            .with_wal_writer(writer);
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&cfg),
        )
        .await
        .expect("missing GUI broker follows ordinary retry handling");
        assert_eq!(outcome.tasks_completed, 0);
        assert!(
            !dir.path()
                .join(format!(".neoth-task-{}", task_id.raw()))
                .exists()
        );
        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
            .expect("missing broker must not create a final decision");
        assert!(ledger.entries.is_empty());
    }

    #[tokio::test]
    async fn native_gui_rejection_and_cancel_before_response_create_no_gate_history() {
        for cancel_first in [false, true] {
            let (dir, conn) = fresh_db();
            let repo = dir.path().join("repo");
            std::fs::create_dir_all(&repo).unwrap();
            let home = dir.path().join("neoth-home");
            let (writer, _writer_join) = authenticated_apply_writer(&home);
            let session_id = store::insert_session(&conn, 1, "p", "h", "gui", None).unwrap();
            let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
            let task = store::list_tasks_for_session(&conn, session_id)
                .unwrap()
                .pop()
                .unwrap();
            let worker = CannedWorker {
                outcome: green_outcome(),
                name: "native-gui-reject-cancel",
            };
            let accepted = WorkerContract::for_dispatch(&task, &worker, dir.path())
                .validate_and_materialize(&task, &worker, green_outcome())
                .unwrap();
            let (broker, cancellation) =
                crate::coding::service::GuiPatchApprovalBroker::for_dispatch_test();
            let cfg = gui_test_apply_config(&repo, &writer, broker.clone());
            let authorize = authorize_patch_apply_before_worktree(&task, &accepted, &cfg);
            let answer = async {
                let metadata = broker.wait_for_pending_metadata_for_test().await;
                if cancel_first {
                    cancellation.request();
                }
                broker.respond_for_test(metadata.approval_id, false).await
            };
            let (admission, response) = tokio::join!(authorize, answer);
            assert!(admission.is_err());
            assert_eq!(
                response,
                if cancel_first {
                    crate::coding::PatchApprovalResponse::StaleOrUnknown
                } else {
                    crate::coding::PatchApprovalResponse::Rejected
                }
            );
            assert!(
                !dir.path()
                    .join(format!(".neoth-task-{}", task_id.raw()))
                    .exists(),
                "reject/cancel must return before a worktree capability exists"
            );
            let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
                .expect("reject/cancel has no Gate history");
            assert!(ledger.entries.is_empty());
        }
    }

    #[tokio::test]
    async fn native_gui_root_replacement_during_approval_refuses_before_gate() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();
        let home = dir.path().join("neoth-home");
        let (writer, _writer_join) = authenticated_apply_writer(&home);
        let session_id = store::insert_session(&conn, 1, "p", "h", "gui", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        let worker = CannedWorker {
            outcome: green_outcome_with_real_patch(),
            name: "native-gui-root-replacement",
        };
        let accepted = WorkerContract::for_dispatch(&task, &worker, dir.path())
            .validate_and_materialize(&task, &worker, green_outcome_with_real_patch())
            .unwrap();
        let (broker, _cancellation) =
            crate::coding::service::GuiPatchApprovalBroker::for_dispatch_test();
        let pause = patch_apply_pause(PatchApplyPausePoint::AfterGuiApprovalBeforeFreshDescriptor);
        let cfg = gui_test_apply_config(&repo, &writer, broker.clone())
            .with_test_pause(Arc::clone(&pause));
        let authorize = authorize_patch_apply_before_worktree(&task, &accepted, &cfg);
        let answer_and_replace = async {
            let metadata = broker.wait_for_pending_metadata_for_test().await;
            assert_eq!(
                broker.respond_for_test(metadata.approval_id, true).await,
                crate::coding::PatchApprovalResponse::Accepted
            );
            wait_for_patch_apply_pause(&pause).await;
            let displaced = dir.path().join("repo-displaced");
            std::fs::rename(&repo, &displaced).unwrap();
            std::fs::create_dir_all(&repo).unwrap();
            init_repo(&repo).unwrap();
            pause.release.notify_one();
        };
        let (admission, ()) = tokio::join!(authorize, answer_and_replace);
        assert!(
            admission.is_err(),
            "fresh descriptor must reject replaced root"
        );
        assert!(
            !dir.path()
                .join(format!(".neoth-task-{}", task_id.raw()))
                .exists(),
            "fresh descriptor failure occurs before worktree creation"
        );
        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
            .expect("replaced root must not write an old-root decision");
        assert!(ledger.entries.is_empty());
    }

    #[tokio::test]
    async fn allowed_hmac_decision_is_complete_before_first_worktree_effect() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_repo(&repo).unwrap();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        let worker = CannedWorker {
            outcome: green_outcome_with_real_patch(),
            name: "pre-effect-ledger",
        };
        let accepted = WorkerContract::for_dispatch(&task, &worker, dir.path())
            .validate_and_materialize(&task, &worker, green_outcome_with_real_patch())
            .expect("fixture outcome crosses the normal accepted-patch boundary");
        let home = dir.path().join("neoth-home");
        let (writer, _writer_join) = authenticated_apply_writer(&home);
        let cfg = local_test_apply_config(&repo, &writer);

        let admission = authorize_patch_apply_before_worktree(&task, &accepted, &cfg)
            .await
            .expect("final Gate decision")
            .expect("fixture has a patch");
        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
            .expect("forced marker makes allowed evidence complete before apply");
        assert!(matches!(
            ledger.completeness,
            crate::permissions::TrustLedgerCompleteness::Complete
        ));
        assert_eq!(ledger.entries.len(), 1);
        assert!(matches!(
            ledger.entries[0].event.outcome,
            crate::permissions::TrustOutcome::Allowed
        ));
        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        assert!(!wt.exists(), "Gate admission itself has no worktree effect");

        apply_admitted_patch_in_worktree(admission, &task, &accepted, &cfg, None)
            .expect("only the admitted capability can create the worktree");
        assert!(wt.exists());
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &wt, true);
    }

    #[tokio::test]
    async fn patch_apply_missing_required_writer_blocks_before_worktree() {
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "missing-required-writer",
            }),
        );
        let cfg = DispatchApplyConfig::new(&repo, ApplyOrigin::CliConfirmed)
            .with_autonomy(crate::permissions::AutonomyLevel::Full)
            .with_local_cli_confirmation();
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&cfg),
        )
        .await
        .expect("missing audit writer becomes a task failure, not a dispatcher failure");
        assert_eq!(outcome.tasks_completed, 0);
        assert!(
            !dir.path()
                .join(format!(".neoth-task-{}", task_id.raw()))
                .exists(),
            "required audit absence must prevent the first worktree effect"
        );
    }

    #[tokio::test]
    async fn cancellation_after_worker_result_before_gate_restores_backlog_without_decision() {
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "cancel-before-gate",
            }),
        );
        let home = dir.path().join("neoth-home");
        let (writer, _writer_join) = authenticated_apply_writer(&home);
        let pause = patch_apply_pause(PatchApplyPausePoint::BeforeGate);
        let cfg = local_test_apply_config(&repo, &writer).with_test_pause(Arc::clone(&pause));
        let cancellation = AtomicCancellation::new();

        let dispatch = dispatch_session_with_apply_cancellable(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&cfg),
            &cancellation,
        );
        let request_cancel = async {
            wait_for_patch_apply_pause(&pause).await;
            cancellation.request();
            pause.release.notify_one();
        };
        let (result, ()) = tokio::join!(dispatch, request_cancel);

        let CancellableDispatchOutcome::Cancelled(receipt) = result.unwrap() else {
            panic!("cancellation must return its joined effect receipt");
        };
        assert!(receipt.completed_task_ids.is_empty());
        assert!(receipt.applied_task_ids.is_empty());
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Backlog);
        assert!(
            !dir.path()
                .join(format!(".neoth-task-{}", task_id.raw()))
                .exists()
        );
        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
            .expect("pre-Gate cancellation must leave no final permission decision");
        assert!(ledger.entries.is_empty());
    }

    #[tokio::test]
    async fn cancellation_after_admission_preserves_history_but_consumes_no_worktree_effect() {
        let (dir, conn) = fresh_db();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "cancel-after-admission",
            }),
        );
        let home = dir.path().join("neoth-home");
        let (writer, _writer_join) = authenticated_apply_writer(&home);
        let pause = patch_apply_pause(PatchApplyPausePoint::AfterAdmission);
        let cfg = local_test_apply_config(&repo, &writer).with_test_pause(Arc::clone(&pause));
        let cancellation = AtomicCancellation::new();

        let dispatch = dispatch_session_with_apply_cancellable(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&cfg),
            &cancellation,
        );
        let request_cancel = async {
            wait_for_patch_apply_pause(&pause).await;
            cancellation.request();
            pause.release.notify_one();
        };
        let (result, ()) = tokio::join!(dispatch, request_cancel);

        let CancellableDispatchOutcome::Cancelled(receipt) = result.unwrap() else {
            panic!("cancellation must return its joined effect receipt");
        };
        assert!(receipt.completed_task_ids.is_empty());
        assert!(receipt.applied_task_ids.is_empty());
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Backlog);
        assert!(
            !dir.path()
                .join(format!(".neoth-task-{}", task_id.raw()))
                .exists()
        );
        let ledger = crate::permissions::TrustLedger::replay_subject_at_home(&home, "local")
            .expect("post-admission cancellation keeps the final decision as history");
        assert_eq!(ledger.entries.len(), 1);
        assert!(matches!(
            ledger.entries[0].event.outcome,
            crate::permissions::TrustOutcome::Allowed
        ));
    }

    #[tokio::test]
    async fn daemon_scheduled_origin_blocks_on_confirm() {
        // ADV review-D (Session 30): SAME autonomy + SAME provider
        // outcome as `full_autonomy_still_applies_under_confirm`, the
        // ONLY difference is the apply origin. Full autonomy yields
        // Decision::Confirm for PatchApplyToRepo; with a
        // `DaemonScheduled` origin there is NO operator at a TTY, so the
        // Confirm is a HARD gate (fail-closed) — the apply is refused and
        // the task does NOT complete. The gate fires BEFORE any worktree
        // IO, so no git repo is needed.
        let (dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome_with_real_patch(),
                name: "phase4-daemon-origin",
            }),
        );

        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let (writer, _writer_join) = authenticated_apply_writer(&dir.path().join("neoth-home"));
        let apply_cfg = DispatchApplyConfig::new(&repo, ApplyOrigin::DaemonScheduled)
            .with_autonomy(crate::permissions::AutonomyLevel::Full)
            .with_wal_writer(std::sync::Arc::clone(&writer));
        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .await
        .expect("dispatch with daemon-scheduled origin");

        assert_eq!(
            outcome.tasks_completed, 0,
            "daemon-scheduled origin must NOT degrade Confirm → apply"
        );
        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        assert!(
            !wt.exists(),
            "origin gate must refuse BEFORE any worktree IO"
        );
    }

    #[test]
    fn apply_origin_is_observable_provenance_only() {
        // Stable wire/log names — these land in WAL diagnostics + Err
        // strings, so a rename is a breaking change worth a test.
        assert_eq!(ApplyOrigin::CliConfirmed.as_str(), "cli_confirmed");
        assert_eq!(ApplyOrigin::DaemonScheduled.as_str(), "daemon_scheduled");
        assert_eq!(ApplyOrigin::ChannelRequested.as_str(), "channel_requested");
        assert_eq!(ApplyOrigin::GuiRequested.as_str(), "gui_requested");
    }

    #[tokio::test]
    async fn dispatch_session_with_apply_none_behaves_like_phase_3() {
        // Passing None preserves the review-only behaviour: the dispatcher
        // records its derived task artifact but never applies it.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "phase3-compat",
            }),
        );

        let outcome = dispatch_session_with_apply(
            &conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            None,
        )
        .await
        .expect("dispatch without apply");
        assert_eq!(outcome.tasks_completed, 1);
    }

    #[tokio::test]
    async fn invalid_worker_contract_never_stores_or_applies_in_direct_or_apply_modes() {
        // ADOPT31-C10a: exercise both caller modes with a worker outcome that
        // nominates a real foreign file whose bytes differ from patch_text.
        // The contract must reject it before `apply_outcome` can attach any
        // artifact and before --apply can create a worktree. The worker keeps
        // returning the same invalid result, so the retry ceiling eventually
        // routes the task to Blocked without ever counting a completion.
        for with_apply in [false, true] {
            let (dir, conn) = fresh_db();
            let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
            let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
            store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

            let mut invalid = green_outcome();
            let worker_selected_foreign = dir.path().join("foreign-mismatched.patch");
            std::fs::write(
                &worker_selected_foreign,
                b"different file selected by worker",
            )
            .unwrap();
            invalid.patch_path = worker_selected_foreign;
            let mut workers = HemisphereWorkerSet::new();
            workers.bind(
                Hemisphere::Left,
                Box::new(CannedWorker {
                    outcome: invalid,
                    name: "forged-applied-receipt",
                }),
            );

            let repo = dir.path().join("never-created-repo");
            let apply_cfg = DispatchApplyConfig::new(&repo, ApplyOrigin::CliConfirmed);
            let result = (if with_apply {
                dispatch_session_with_apply(
                    &conn,
                    session_id,
                    &workers,
                    DispatchBudget::default(),
                    Some(&apply_cfg),
                )
                .await
            } else {
                dispatch_session(&conn, session_id, &workers, DispatchBudget::default()).await
            })
            .expect("contract rejection is handled as retry/blocked, not a dispatch error");

            assert_eq!(
                result.tasks_completed, 0,
                "invalid worker output must never count completed (with_apply={with_apply})"
            );
            let task = store::list_tasks_for_session(&conn, session_id)
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(
                task.status,
                TaskStatus::Blocked,
                "retry ceiling/unassigned fallback must leave invalid output Blocked"
            );
            assert!(
                task.patch_path.is_none() && task.test_summary.is_none(),
                "contract-rejected output must not attach an artifact (with_apply={with_apply})"
            );
            assert!(
                !dir.path()
                    .join(format!(".neoth-task-{}", task_id.raw()))
                    .exists(),
                "contract rejection must occur before worktree creation (with_apply={with_apply})"
            );
        }
    }

    // Helper: silence dead-code on the Arc import in case the test
    // tree shrinks.
    #[allow(dead_code)]
    fn _arc_alive() -> Arc<()> {
        Arc::new(())
    }

    // ── QU-01 dispatcher wire-in (Session 28) ──────────────────────────

    /// Worker that returns a refusal-summary outcome on every call.
    /// Drives the greeting-regression bypass through the dispatcher.
    struct RefusalWorker;

    #[async_trait]
    impl Worker for RefusalWorker {
        async fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            Ok(WorkerOutcome {
                // Worker "succeeded" structurally (non-empty
                // patch_text) so the Ok branch hits the apply path —
                // but the patch is just a refusal in prose form,
                // which is what greeting-regression detects on the
                // patch_text surface.
                patch_text: "Sorry, I can't help with that request.".into(),
                patch_path: std::path::PathBuf::new(),
                tests: TestSummary::ZERO,
                summary: "refused".into(),
                result_context_commitment: None,
            })
        }
        fn name(&self) -> &'static str {
            "refusal-worker"
        }
    }

    #[tokio::test]
    async fn refusal_disguised_as_patch_blocks_even_without_apply() {
        // QU-01 harte-Kritik fix (Session 28): a refusal that arrives
        // as non-empty patch_text is STRUCTURALLY review-ready, so the
        // pre-fix dispatcher promoted it to Review on the no-`--apply`
        // path (the apply path would have caught it on git-apply
        // rejection, but no-apply never inspected content). The new
        // pre-check routes any review-ready-but-refusal outcome into
        // the failure path so greeting-regression fires + the task
        // lands Blocked — NOT Review — even with apply_config = None.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(Hemisphere::Left, Box::new(RefusalWorker));
        // NO apply path (apply_config = None) — this is the exact
        // edge flagged in review.
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .expect("dispatch");
        assert_eq!(outcome.tasks_attempted, 1);
        assert_eq!(
            outcome.tasks_completed, 0,
            "a refusal-as-patch must NOT count as completed"
        );
        assert_eq!(
            outcome.tasks_blocked, 1,
            "refusal-as-patch must land Blocked via greeting-regression"
        );
        // Task ends Blocked, not Review.
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    #[tokio::test]
    async fn legacy_worker_outcome_keeps_nullable_result_provenance_empty() {
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: green_outcome(),
                name: "legacy-none",
            }),
        );
        dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();
        assert_eq!(
            store::load_task_worker_result_provenance(&conn, task_id).unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn privileged_internal_forged_output_binding_never_materializes_or_persists() {
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut forged = green_outcome();
        forged.result_context_commitment =
            Some(crate::coding::worker::WorkerResultContextCommitment {
                schema: crate::coding::worker::WorkerResultContextCommitment::SCHEMA.to_owned(),
                task_id: task_id.raw(),
                submitted_context_sha256: "a".repeat(64),
                submitted_context_bytes: 1,
                context_truncated: false,
                sources: vec![crate::coding::worker::WorkerResultContextSource {
                    root_identity: "forged-root-identity".to_owned(),
                    index_generation: 1,
                    graph_generation: 1,
                }],
                accepted_output_sha256: "b".repeat(64),
                accepted_output_bytes: 1,
            });
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: forged,
                name: "forged-context",
            }),
        );
        dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .unwrap();
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
        assert_eq!(
            task.patch_path, None,
            "forged claim cannot materialize an artifact"
        );
        assert_eq!(
            task.test_summary, None,
            "forged claim cannot persist a task result"
        );
        assert_eq!(
            store::load_task_worker_result_provenance(&conn, task_id).unwrap(),
            None
        );
    }

    /// Worker that returns an empty outcome (no patch, no tests) but
    /// stashes a refusal in the summary field. Drives the
    /// failed-outcome → handle_retryable_failure → greeting-regression
    /// detection path.
    struct EmptyRefusalWorker;

    #[async_trait]
    impl Worker for EmptyRefusalWorker {
        async fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            Ok(WorkerOutcome {
                patch_text: String::new(),
                patch_path: std::path::PathBuf::new(),
                tests: TestSummary::ZERO,
                summary: "Sorry, I can't help with that request.".into(),
                result_context_commitment: None,
            })
        }
        fn name(&self) -> &'static str {
            "empty-refusal-worker"
        }
    }

    #[tokio::test]
    async fn empty_refusal_outcome_triggers_greeting_regression_bypass() {
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(Hemisphere::Left, Box::new(EmptyRefusalWorker));
        let outcome = dispatch_session(&conn, session_id, &workers, DispatchBudget::default())
            .await
            .expect("dispatch");
        // Greeting-regression on the summary surface → straight to
        // Blocked, not Retry-Backlog. Only one attempt counted.
        assert_eq!(outcome.tasks_attempted, 1);
        assert_eq!(outcome.tasks_blocked, 1);
        assert_eq!(outcome.tasks_completed, 0);
        // Task ends in Blocked (not Backlog — the bypass writes
        // Blocked immediately).
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    /// Worker that always returns a structurally-failed outcome
    /// (empty patch + zero tests) WITHOUT a refusal marker, so the
    /// greeting-regression detector stays quiet and we exercise the
    /// patch-spiral ceiling.
    struct EmptyOutcomeWorker;

    #[async_trait]
    impl Worker for EmptyOutcomeWorker {
        async fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            Ok(WorkerOutcome {
                patch_text: String::new(),
                patch_path: std::path::PathBuf::new(),
                tests: TestSummary::ZERO,
                summary: "no diff produced".into(),
                result_context_commitment: None,
            })
        }
        fn name(&self) -> &'static str {
            "empty-outcome-worker"
        }
    }

    #[tokio::test]
    async fn repeated_empty_outcome_lands_blocked_via_retry_ceiling() {
        // EmptyOutcomeWorker keeps producing failed outcomes. With
        // QU-01 wire-in, the patch-spiral tracker counts each one;
        // when retry_policy's ceiling fires first (default 3
        // attempts) the task lands Blocked via the ceiling path,
        // not via the spiral path. Either way the test asserts
        // Blocked + at most one task touched per attempt budget.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();
        let mut workers = HemisphereWorkerSet::new();
        workers.bind(Hemisphere::Left, Box::new(EmptyOutcomeWorker));
        // Lift the default tasks cap so the same task can recycle
        // through the retry rotation a few times before Blocked.
        let budget = DispatchBudget {
            max_tasks: 50,
            ..DispatchBudget::default()
        };
        let outcome = dispatch_session(&conn, session_id, &workers, budget)
            .await
            .expect("dispatch");
        // Eventually Blocked. With identical failing outputs the
        // repetition-loop detector (3-sample tail) fires at attempt 3,
        // one before the patch-spiral ceiling (4) — either way the
        // task lands Blocked. Outcome counter for Blocked is 1.
        assert_eq!(outcome.tasks_blocked, 1);
        assert_eq!(outcome.tasks_completed, 0);
        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    // ── QU-01 Phase 3 repetition-ring helpers ──────────────────────

    #[tokio::test]
    async fn worker_output_text_joins_summary_and_patch() {
        let o = WorkerOutcome {
            patch_text: "diff body".into(),
            patch_path: std::path::PathBuf::new(),
            tests: TestSummary::ZERO,
            summary: "one-liner".into(),
            result_context_commitment: None,
        };
        let text = worker_output_text(&o);
        assert!(text.contains("one-liner"));
        assert!(text.contains("diff body"));
    }

    #[tokio::test]
    async fn record_recent_output_caps_ring_at_capacity() {
        let mut map: HashMap<KanbanTaskId, Vec<String>> = HashMap::new();
        let tid = KanbanTaskId(1);
        // Push more than the cap; oldest must drop, newest survive.
        for i in 0..(REPETITION_RING_CAP + 3) {
            record_recent_output(&mut map, tid, &format!("out{i}"));
        }
        let ring = map.get(&tid).unwrap();
        assert_eq!(ring.len(), REPETITION_RING_CAP, "ring must cap at capacity");
        // Oldest three (out0..out2) dropped; newest is the last push.
        assert_eq!(
            ring.last().unwrap(),
            &format!("out{}", REPETITION_RING_CAP + 2)
        );
        assert!(
            !ring.iter().any(|s| s == "out0"),
            "oldest entry must be evicted"
        );
    }

    #[tokio::test]
    async fn recent_output_refs_empty_for_unknown_task() {
        let map: HashMap<KanbanTaskId, Vec<String>> = HashMap::new();
        let refs = recent_output_refs(&map, KanbanTaskId(99));
        assert!(refs.is_empty());
    }

    #[tokio::test]
    async fn recent_output_refs_round_trips_into_repetition_detector() {
        // The whole point: a per-task ring of identical outputs must
        // make `is_repetition_loop` fire once it reaches the sample
        // floor. Proves the wire-in glue produces a slice the
        // detector accepts.
        let mut map: HashMap<KanbanTaskId, Vec<String>> = HashMap::new();
        let tid = KanbanTaskId(7);
        record_recent_output(&mut map, tid, "stuck output");
        record_recent_output(&mut map, tid, "stuck output");
        let refs2 = recent_output_refs(&map, tid);
        assert!(
            !crate::coding::early_stop::is_repetition_loop(&refs2),
            "2 samples is below the min-sample floor"
        );
        record_recent_output(&mut map, tid, "stuck output");
        let refs3 = recent_output_refs(&map, tid);
        assert!(
            crate::coding::early_stop::is_repetition_loop(&refs3),
            "3 identical samples must trip the repetition-loop detector"
        );
    }

    // ── QU-05 reinjection_hint ─────────────────────────────────────

    #[tokio::test]
    async fn reinjection_hint_combines_strategy_and_diagnosis() {
        let h = reinjection_hint(
            "[retry hint: split the file]",
            "error[E0425]: cannot find value `x`",
        );
        assert!(h.contains("[retry hint: split the file]"));
        assert!(h.contains("[previous attempt failed]:"));
        assert!(h.contains("E0425"));
    }

    #[tokio::test]
    async fn reinjection_hint_falls_back_to_strategy_when_diagnosis_empty() {
        // An empty / whitespace-only diagnosis must not produce a
        // dangling "[previous attempt failed]:" header with no body.
        assert_eq!(reinjection_hint("[hint]", ""), "[hint]");
        assert_eq!(reinjection_hint("[hint]", "   \n\t "), "[hint]");
    }

    #[tokio::test]
    async fn reinjection_hint_truncates_long_diagnosis_at_char_boundary() {
        // A multi-byte char straddling the cap must not panic the
        // byte slice. Build a diagnosis well past the cap of
        // multi-byte arrows + umlauts (rustc emits `-->`, German
        // error text emits ä/ö/ü).
        let diag = "ü-->".repeat(2000); // ~10 KB, all multi-byte heavy
        let h = reinjection_hint("[hint]", &diag);
        assert!(h.contains("(diagnostic truncated)"));
        // Bounded: strategy hint + header + cap + truncation marker.
        assert!(h.len() < REINJECTED_DIAGNOSIS_CAP + 200);
    }

    #[tokio::test]
    async fn reinjection_hint_short_diagnosis_not_truncated() {
        let h = reinjection_hint("[hint]", "boom");
        assert!(h.contains("boom"));
        assert!(!h.contains("truncated"));
    }

    // ── QU-05 is_cargo_check_cmd routing ───────────────────────────

    #[tokio::test]
    async fn is_cargo_check_cmd_matches_check_with_and_without_flags() {
        assert!(is_cargo_check_cmd("cargo check"));
        assert!(is_cargo_check_cmd("cargo check --workspace"));
        assert!(is_cargo_check_cmd("  cargo   check   --all-targets "));
    }

    #[tokio::test]
    async fn is_cargo_check_cmd_rejects_other_commands() {
        assert!(!is_cargo_check_cmd("cargo test"));
        assert!(!is_cargo_check_cmd("cargo build"));
        assert!(!is_cargo_check_cmd("pytest -q"));
        assert!(!is_cargo_check_cmd("cargo"));
        assert!(!is_cargo_check_cmd(""));
        // A wrapper script named "cargo-check" must NOT match — it's a
        // single token, not `cargo` + `check`.
        assert!(!is_cargo_check_cmd("cargo-check"));
    }
}
