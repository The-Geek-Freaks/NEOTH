//! Pick #6 Phase 2 — `dispatch_session()` orchestrator skeleton.
//!
//! Per `PLAN/CHORUS_dispatcher_design.md` (2026-05-20). This module
//! lands the orchestration glue: pick BACKLOG tasks, transition them
//! through `InProgress → Review` (or `Blocked`), capture the worker
//! outcome. The four Chorus-gated decisions are placeholder-default:
//!
//!   Q1 patch safety → currently "trust the worker output path"
//!     (the dispatcher just stores `WorkerOutcome.patch_path`; safe
//!     because no actual git-apply happens yet)
//!   Q2 streaming → currently batched (one COMPLETED frame at end);
//!     30s heartbeat hook reserved via WAL 0x77 but not yet emitted
//!   Q3 review gating → currently always operator-in-loop (the
//!     dispatcher never auto-promotes; Pick #10's review CLI does)
//!   Q4 cycle prevention → time + count budget enforced (both)
//!
//! Concrete worker impls (LeftWorker against local_qwen,
//! RightWorker against claude_cli/openai_compat) wire in Phase 3.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rusqlite::Connection;
use tracing::{info, warn};

use crate::coding::retry::WorkerRetryPolicy;
use crate::coding::store;
use crate::coding::types::{Hemisphere, KanbanSessionId, KanbanTask, KanbanTaskId, TaskStatus};
use crate::coding::worker::{Worker, WorkerOutcome};
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

/// Pick #6 Phase 4 — opt-in patch-apply config. When passed to
/// `dispatch_session`, every worker-produced patch is applied
/// inside a task-scoped git worktree per the Chorus verdict
/// (Strategy B). When `None`, dispatcher behaves as Phase 3:
/// store the patch under `<patch_root>/...` but never apply.
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
/// `autonomy` flows through `permissions::evaluate(WriteToRepo,
/// level)` in a follow-up commit — today the dispatcher applies
/// unconditionally when `apply_config` is `Some`. The CLI's
/// `neoth code --apply` operator-prompt gate happens before
/// `dispatch_session` is called, so the in-loop gate is a
/// defense-in-depth check that lands once the permissions
/// surface adds the `WriteToRepo` action.
#[derive(Clone)]
pub struct DispatchApplyConfig {
    pub repo_root: std::path::PathBuf,
    pub test_cmd: Option<String>,
    pub test_timeout: std::time::Duration,
    pub wal_writer: WalWriterRef,
    /// Pick #6 Phase 4 defense-in-depth (Chorus Q1a) —
    /// per-task `permissions::evaluate(PatchApplyToRepo, level)`
    /// gate. When `Some`, the dispatcher consults the policy
    /// BEFORE creating the worktree. Strict → Deny (task
    /// blocks); Standard/Elevated/Full → Confirm via the
    /// CLI's pre-flight prompt (operator already opted in by
    /// passing `--apply` in `neoth code`, so the in-loop
    /// Confirm degrades to Allow). When `None`, the gate is
    /// skipped (CLI one-shot operator-already-confirmed).
    pub autonomy: Option<crate::permissions::AutonomyLevel>,
}

impl std::fmt::Debug for DispatchApplyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchApplyConfig")
            .field("repo_root", &self.repo_root)
            .field("test_cmd", &self.test_cmd)
            .field("test_timeout", &self.test_timeout)
            .field("wal_writer", &self.wal_writer.as_ref().map(|_| "<live>"))
            .field("autonomy", &self.autonomy)
            .finish()
    }
}

impl DispatchApplyConfig {
    pub fn new(repo_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
            test_cmd: None,
            test_timeout: std::time::Duration::from_secs(5 * 60),
            wal_writer: None,
            autonomy: None,
        }
    }

    /// Attach the operator's autonomy level so the dispatcher
    /// runs `permissions::evaluate(PatchApplyToRepo, level)`
    /// per task. Strict denies the task before any IO; other
    /// levels Confirm but the caller (CLI) has already
    /// confirmed by passing `--apply` so the in-loop Confirm
    /// degrades to Allow.
    pub fn with_autonomy(mut self, level: crate::permissions::AutonomyLevel) -> Self {
        self.autonomy = Some(level);
        self
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
}

/// Run one dispatch pass over the session's BACKLOG tasks. Picks
/// BACKLOG tasks whose hemisphere has a bound worker, transitions
/// them to `InProgress`, fires the worker, transitions to `Review`
/// (or `Blocked` on `WorkerOutcome.failed()`). Stops at the first
/// budget breach. Returns the aggregated outcome.
///
/// Concurrency: serial for now — one task at a time. The hemisphere
/// loop is a single thread; if a future pick wants concurrent
/// hemispheres, refactor to `spawn` per hemisphere with a shared
/// budget gate.
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

    loop {
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

        let Some(task) = pick_next_backlog_task(conn, session_id, workers)? else {
            break;
        };
        outcome.tasks_attempted += 1;

        let Some(worker) = workers.get(task.hemisphere) else {
            // No worker bound for this task's hemisphere — Block it.
            outcome.tasks_unassigned += 1;
            let now_ns = now_unix_ns();
            store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns)
                .context("transition Backlog → Blocked (no worker)")?;
            continue;
        };

        // Transition to InProgress before invoking the worker so the
        // activity feed shows the task lifecycle correctly even if
        // the worker crashes.
        let now_ns = now_unix_ns();
        store::patch_task_status(conn, task.task_id, TaskStatus::InProgress, now_ns)
            .context("transition Backlog → InProgress")?;

        // SD-02 (Round-3 v0.4) — emit 0x77 KANBAN_TASK_PROGRESS at
        // pick-up. progress_pct=0, message="dispatched". Best-
        // effort; no-op when wal_writer is None (CLI one-shot
        // without --apply doesn't thread a writer through).
        let writer_for_progress = apply_config.and_then(|cfg| cfg.wal_writer.as_deref());
        emit_kanban_task_progress_wal(writer_for_progress, &task, 0, "dispatched");

        let exec_result = worker.execute(&task).await;
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
                    && (crate::coding::early_stop::is_greeting_regression(&o.patch_text)
                        || crate::coding::early_stop::is_greeting_regression(&o.summary)) =>
            {
                patch_spiral.record(task.task_id, false);
                record_recent_output(&mut recent_outputs, task.task_id, &worker_output_text(&o));
                let recent = recent_output_refs(&recent_outputs, task.task_id);
                let _ = handle_retryable_failure(
                    conn,
                    &task,
                    &mut retry_policy,
                    &mut patch_spiral,
                    &recent,
                    &mut outcome,
                    "worker reply was a refusal disguised as patch output",
                    Some(&o),
                );
            }
            Ok(o) if o.review_ready() => {
                // Q2 streaming: batched — one TASK_COMPLETED frame at
                // end. SD-02 (Round-3 v0.4) added 0x77 KANBAN_TASK_PROGRESS
                // heartbeats at task pick-up (above) + review-ready
                // (below) so `neoth kanban watch` shows progress
                // between status changes. 30s background heartbeat
                // (mid-execute) lands in a future sprint.
                emit_kanban_task_progress_wal(writer_for_progress, &task, 100, "review_ready");
                apply_outcome(conn, &task, &o)?;

                // Pick #6 Phase 4: opt-in real-apply path. When the
                // operator passed `--apply` the dispatcher creates a
                // task-scoped git worktree, runs git apply, and only
                // promotes to Review when both succeed. On apply
                // rejection the task is treated as a retryable
                // failure with git's stderr as the diagnosis hint.
                if let Some(cfg) = apply_config {
                    match apply_patch_via_worktree(&task, &o, cfg) {
                        Ok(()) => {
                            outcome.tasks_completed += 1;
                            retry_policy.reset(task.task_id);
                            patch_spiral.record(task.task_id, true);
                        }
                        Err(diagnosis) => {
                            patch_spiral.record(task.task_id, false);
                            record_recent_output(
                                &mut recent_outputs,
                                task.task_id,
                                &worker_output_text(&o),
                            );
                            let recent = recent_output_refs(&recent_outputs, task.task_id);
                            let _ = handle_retryable_failure(
                                conn,
                                &task,
                                &mut retry_policy,
                                &mut patch_spiral,
                                &recent,
                                &mut outcome,
                                &diagnosis,
                                Some(&o),
                            );
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
                }
            }
            Ok(o) => {
                // Outcome reached us but `failed()` (empty patch +
                // zero tests) — treat as a retryable failure +
                // count toward the patch-spiral + repetition ring.
                patch_spiral.record(task.task_id, false);
                record_recent_output(&mut recent_outputs, task.task_id, &worker_output_text(&o));
                let recent = recent_output_refs(&recent_outputs, task.task_id);
                let _ = handle_retryable_failure(
                    conn,
                    &task,
                    &mut retry_policy,
                    &mut patch_spiral,
                    &recent,
                    &mut outcome,
                    "worker returned empty outcome",
                    Some(&o),
                );
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
                let _ = handle_retryable_failure(
                    conn,
                    &task,
                    &mut retry_policy,
                    &mut patch_spiral,
                    &recent,
                    &mut outcome,
                    &err_text,
                    None,
                );
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

/// Pull the next Backlog task whose hemisphere has a bound worker.
/// Tasks on un-bound hemispheres still surface — caller decides what
/// to do (we Block them in the orchestrator). None means "no more
/// Backlog tasks for this session".
fn pick_next_backlog_task(
    conn: &Connection,
    session_id: KanbanSessionId,
    _workers: &HemisphereWorkerSet,
) -> Result<Option<KanbanTask>> {
    // Newest-first within Backlog. The actual sort key is per
    // store::list_tasks_for_session; we filter here to keep the
    // dispatcher path testable in isolation.
    let tasks = store::list_tasks_for_session(conn, session_id)
        .context("list_tasks_for_session for dispatch")?;
    for t in tasks {
        if t.status == TaskStatus::Backlog {
            return Ok(Some(t));
        }
    }
    Ok(None)
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
fn apply_patch_via_worktree(
    task: &KanbanTask,
    outcome: &WorkerOutcome,
    cfg: &DispatchApplyConfig,
) -> std::result::Result<(), String> {
    if outcome.patch_text.is_empty() {
        // Worker produced no patch — nothing to apply. Caller
        // already promoted to Review based on the test summary.
        return Ok(());
    }

    // Pick #6 Phase 4 defense-in-depth (Chorus Q1a). When the
    // caller passed an autonomy level, run the permission gate
    // BEFORE any IO. Strict denies outright; other levels are
    // Confirm — degraded to Allow because the CLI already
    // prompted via `--apply` (operator-confirmed once,
    // dispatcher trusts that signal for the session).
    if let Some(level) = cfg.autonomy {
        use crate::permissions::{Action, Decision, evaluate};
        let action = Action::PatchApplyToRepo {
            repo_root: cfg.repo_root.clone(),
            task_id: task.task_id.raw() as u64,
        };
        match evaluate(&action, level) {
            Decision::Allow => {}
            Decision::Confirm(_) => {
                // CLI-driven runs: operator already confirmed
                // by passing `--apply`. Future unattended-
                // scheduled-apply path (lives in cli::serve,
                // not the CLI one-shot) will surface this
                // Confirm to the operator via the existing
                // PermissionConfirm channel.
            }
            Decision::Deny(reason) => {
                return Err(format!(
                    "permission gate denied apply for task {}: {reason}",
                    task.task_id.raw()
                ));
            }
        }
    }

    let wt_path = crate::coding::worktree::create_task_worktree(&cfg.repo_root, task.task_id)
        .map_err(|e| {
            format!(
                "worktree create failed for task {}: {e}",
                task.task_id.raw()
            )
        })?;

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

    let patch_hash = crate::coding::worktree::patch_hash(&outcome.patch_path)
        .unwrap_or_else(|_| "(unhashable)".to_string());

    match crate::coding::worktree::apply_patch_in_worktree(&wt_path, &outcome.patch_path) {
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
            emit_patch_apply_failed_wal(cfg.wal_writer.as_deref(), task, &wt_path, "apply", &msg);
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
            );
            Err(msg)
        }
    }
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
) {
    let Some(writer) = writer else {
        return;
    };
    let payload = serde_json::json!({
        "task_id": task.task_id.raw(),
        "session_id": task.session_id.raw(),
        "worktree_path": worktree_path.display().to_string(),
        "patch_hash": patch_hash,
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
/// wired. `stage` is `"apply_check"`, `"apply"`, or `"tests"` per
/// the event-code doc-comment.
fn emit_patch_apply_failed_wal(
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    task: &KanbanTask,
    worktree_path: &std::path::Path,
    stage: &str,
    reason: &str,
) {
    let Some(writer) = writer else {
        return;
    };
    let redacted = crate::security::redact::redact_text(reason);
    let payload = serde_json::json!({
        "task_id": task.task_id.raw(),
        "session_id": task.session_id.raw(),
        "worktree_path": worktree_path.display().to_string(),
        "stage": stage,
        "reason": redacted,
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

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn apply_outcome(conn: &Connection, task: &KanbanTask, outcome: &WorkerOutcome) -> Result<()> {
    let target = if outcome.review_ready() {
        TaskStatus::Review
    } else {
        TaskStatus::Blocked
    };
    store::attach_task_artifact(
        conn,
        task.task_id,
        Some(&outcome.patch_path),
        Some(outcome.tests),
    )
    .context("attach_task_artifact on worker outcome")?;
    let now_ns = now_unix_ns();
    store::patch_task_status(conn, task.task_id, target, now_ns)
        .context("transition InProgress → Review/Blocked")?;
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
    partial_outcome: Option<&WorkerOutcome>,
) -> anyhow::Result<()> {
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
    let greeting_regression = crate::coding::early_stop::is_greeting_regression(&diagnosis)
        || partial_outcome
            .map(|o| {
                // Check both surfaces an LLM refusal could land on:
                // the operator-facing summary (one-line) AND the patch
                // body (where a refusal-as-prose ended up if the worker
                // didn't even produce a diff header).
                crate::coding::early_stop::is_greeting_regression(&o.summary)
                    || crate::coding::early_stop::is_greeting_regression(&o.patch_text)
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
        outcome.tasks_blocked += 1;
        let _ = store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns);
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
        outcome.tasks_blocked += 1;
        let _ = store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns);
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
        outcome.tasks_blocked += 1;
        let _ = store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns);
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
        // Best-effort hint persistence — failure to append doesn't
        // block the retry, just means the next attempt runs without
        // the hint.
        if let Err(e) = store::append_task_description_hint(conn, task.task_id, &hint) {
            tracing::warn!(
                task_id = task.task_id.raw(),
                error = %e,
                "could not append retry hint to task description"
            );
        }
        // Re-record any partial artefacts (patch path, tests) so
        // the operator sees what the failed attempt produced even
        // before the next try.
        if let Some(o) = partial_outcome {
            let _ =
                store::attach_task_artifact(conn, task.task_id, Some(&o.patch_path), Some(o.tests));
        }
        // Back to Backlog for the next dispatch loop iteration.
        store::patch_task_status(conn, task.task_id, TaskStatus::Backlog, now_ns)
            .context("re-queue task to Backlog for retry")?;
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
                let _ = store::append_task_description_hint(conn, task.task_id, &hint);
                if let Some(o) = partial_outcome {
                    let _ = store::attach_task_artifact(
                        conn,
                        task.task_id,
                        Some(&o.patch_path),
                        Some(o.tests),
                    );
                }
                // Re-queue; the next loop pass re-reads the task with
                // hemisphere=Right and binds the Right worker. Not
                // counted blocked/completed — it gets another shot.
                let _ = store::patch_task_status(conn, task.task_id, TaskStatus::Backlog, now_ns);
            }
            Err(e) => {
                // Reassign failed — fall back to Blocked rather than
                // re-queueing onto a stale hemisphere.
                tracing::warn!(
                    task_id = task.task_id.raw(),
                    error = %e,
                    "escalate hemisphere reassign failed; blocking task"
                );
                outcome.tasks_blocked += 1;
                let _ = store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns);
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
        outcome.tasks_blocked += 1;
        let _ = store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_ns);
    }
    Ok(())
}

fn now_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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
        // (`str::floor_char_boundary` would be cleaner but is only
        // stable since 1.91; MSRV is 1.86.)
        let mut end = REINJECTED_DIAGNOSIS_CAP;
        while end > 0 && !diag.is_char_boundary(end) {
            end -= 1;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::types::TestSummary;
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::Arc;

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
            patch_path: PathBuf::from("/tmp/x.patch"),
            tests: TestSummary {
                added: 1,
                total: 1,
                passing: 1,
                failing: 0,
                skipped: 0,
            },
            summary: "ok".into(),
        }
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

    fn green_outcome_with_real_patch(patch_path: PathBuf) -> WorkerOutcome {
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
        std::fs::write(&patch_path, patch_lines.join("\n")).unwrap();
        WorkerOutcome {
            patch_text: "<set>".into(),
            patch_path,
            tests: TestSummary {
                added: 1,
                total: 1,
                passing: 1,
                failing: 0,
                skipped: 0,
            },
            summary: "applied".into(),
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

        let patch_path = dir.path().join("change.patch");
        let outcome_template = green_outcome_with_real_patch(patch_path.clone());

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "phase4-test",
            }),
        );

        let cfg = DispatchApplyConfig::new(&repo);
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
        let patch_path = dir.path().join("bad.patch");
        let patch_lines = [
            "diff --git a/nonexistent.txt b/nonexistent.txt",
            "--- a/nonexistent.txt",
            "+++ b/nonexistent.txt",
            "@@ -1 +1,2 @@",
            " line that does not exist",
            "+new line",
            "",
        ];
        std::fs::write(&patch_path, patch_lines.join("\n")).unwrap();
        let mut bad_outcome = green_outcome();
        bad_outcome.patch_path = patch_path;

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: bad_outcome,
                name: "phase4-bad",
            }),
        );

        let cfg = DispatchApplyConfig::new(&repo);
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

    #[tokio::test]
    async fn dispatch_session_with_apply_runs_test_cmd_and_marks_completed_on_zero_exit() {
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

        let patch_path = dir.path().join("change.patch");
        let outcome_template = green_outcome_with_real_patch(patch_path.clone());

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "phase4-test-pass",
            }),
        );

        let apply_cfg = DispatchApplyConfig::new(&repo)
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

        let patch_path = dir.path().join("change.patch");
        let outcome_template = green_outcome_with_real_patch(patch_path.clone());

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "phase4-test-fail",
            }),
        );

        let apply_cfg = DispatchApplyConfig::new(&repo)
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

        // Live WAL writer against a tempfile so we can verify
        // the 0xD3 frame actually lands.
        let wal_seg = dir.path().join("000001.wal");
        let (writer, _wal_join) =
            crate::wal::writer::spawn(wal_seg.clone()).expect("spawn wal writer");
        let writer = std::sync::Arc::new(writer);

        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let patch_path = dir.path().join("change.patch");
        let outcome_template = green_outcome_with_real_patch(patch_path.clone());

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "ph4-wal-emit",
            }),
        );

        let apply_cfg =
            DispatchApplyConfig::new(&repo).with_wal_writer(std::sync::Arc::clone(&writer));

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
        let bytes = std::fs::read(&wal_seg).expect("read wal segment");
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

        // Use a path that does NOT need to exist — the gate
        // fires before we ever touch the filesystem.
        let fake_repo = dir.path().join("never-exists");
        let apply_cfg = DispatchApplyConfig::new(&fake_repo)
            .with_autonomy(crate::permissions::AutonomyLevel::Strict);
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

        let patch_path = dir.path().join("change.patch");
        let outcome_template = green_outcome_with_real_patch(patch_path.clone());

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(
            Hemisphere::Left,
            Box::new(CannedWorker {
                outcome: outcome_template,
                name: "phase4-full-autonomy",
            }),
        );

        let apply_cfg =
            DispatchApplyConfig::new(&repo).with_autonomy(crate::permissions::AutonomyLevel::Full);
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

        let wt = dir.path().join(format!(".neoth-task-{}", task_id.raw()));
        let _ = crate::coding::worktree::cleanup_worktree(&repo, &wt, true);
    }

    #[tokio::test]
    async fn dispatch_session_with_apply_none_behaves_like_phase_3() {
        // Backward compat: passing None for apply_config preserves
        // the Phase-3 behaviour where the dispatcher records the
        // patch_path but never actually applies anything.
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
                patch_path: PathBuf::from("/tmp/refusal.patch"),
                tests: TestSummary::ZERO,
                summary: "refused".into(),
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
        // edge Alex flagged.
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
                patch_path: PathBuf::from("/tmp/empty.patch"),
                tests: TestSummary::ZERO,
                summary: "Sorry, I can't help with that request.".into(),
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
                patch_path: PathBuf::from("/tmp/empty.patch"),
                tests: TestSummary::ZERO,
                summary: "no diff produced".into(),
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
            patch_path: PathBuf::from("/tmp/x.patch"),
            tests: TestSummary::ZERO,
            summary: "one-liner".into(),
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
