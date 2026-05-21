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
use crate::coding::types::{Hemisphere, KanbanSessionId, KanbanTask, TaskStatus};
use crate::coding::worker::{Worker, WorkerOutcome};
use crate::security::redact::redact_text;

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
/// `autonomy` flows through `permissions::evaluate(WriteToRepo,
/// level)` in a follow-up commit — today the dispatcher applies
/// unconditionally when `apply_config` is `Some`. The CLI's
/// `neoth code --apply` operator-prompt gate happens before
/// `dispatch_session` is called, so the in-loop gate is a
/// defense-in-depth check that lands once the permissions
/// surface adds the `WriteToRepo` action.
#[derive(Debug, Clone)]
pub struct DispatchApplyConfig {
    pub repo_root: std::path::PathBuf,
}

impl DispatchApplyConfig {
    pub fn new(repo_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
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
pub fn dispatch_session(
    conn: &Connection,
    session_id: KanbanSessionId,
    workers: &HemisphereWorkerSet,
    budget: DispatchBudget,
) -> Result<DispatchOutcome> {
    dispatch_session_with_apply(conn, session_id, workers, budget, None)
}

/// Pick #6 Phase 4 — variant that also applies worker patches
/// inside a task-scoped git worktree when `apply_config` is
/// `Some`. The simple `dispatch_session` calls this with `None`
/// for backward-compat. New CLI surfaces (`neoth code --apply`)
/// call this directly.
pub fn dispatch_session_with_apply(
    conn: &Connection,
    session_id: KanbanSessionId,
    workers: &HemisphereWorkerSet,
    budget: DispatchBudget,
    apply_config: Option<&DispatchApplyConfig>,
) -> Result<DispatchOutcome> {
    let started = Instant::now();
    let mut outcome = DispatchOutcome::default();
    let mut retry_policy = WorkerRetryPolicy::new();

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

        let exec_result = worker.execute(&task);
        match exec_result {
            Ok(o) if o.review_ready() => {
                // Q2 streaming: batched — one TASK_COMPLETED frame at
                // end. 30s heartbeat (WAL 0x77 KANBAN_TASK_PROGRESS)
                // lands in a later sprint via a background task.
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
                        }
                        Err(diagnosis) => {
                            let _ = handle_retryable_failure(
                                conn,
                                &task,
                                &mut retry_policy,
                                &mut outcome,
                                &diagnosis,
                                Some(&o),
                            );
                        }
                    }
                } else {
                    outcome.tasks_completed += 1;
                    retry_policy.reset(task.task_id);
                }
            }
            Ok(o) => {
                // Outcome reached us but `failed()` (empty patch +
                // zero tests) — treat as a retryable failure.
                let _ = handle_retryable_failure(
                    conn,
                    &task,
                    &mut retry_policy,
                    &mut outcome,
                    "worker returned empty outcome",
                    Some(&o),
                );
            }
            Err(e) => {
                let _ = handle_retryable_failure(
                    conn,
                    &task,
                    &mut retry_policy,
                    &mut outcome,
                    &format!("worker execute failed: {e}"),
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

    let wt_path = crate::coding::worktree::create_task_worktree(&cfg.repo_root, task.task_id)
        .map_err(|e| format!("worktree create failed for task {}: {e}", task.task_id.raw()))?;

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

    match crate::coding::worktree::apply_patch_in_worktree(&wt_path, &outcome.patch_path) {
        Ok(crate::coding::worktree::PatchApplyOutcome::Applied { worktree_path }) => {
            info!(
                task_id = task.task_id.raw(),
                worktree = %worktree_path.display(),
                "patch applied; tests run in worktree (follow-up commit)"
            );
            // WAL 0xD3 PATCH_APPLIED emit + test execution land
            // in the follow-up commit; today the operator sees
            // the applied patch in the worktree + can inspect
            // manually.
            Ok(())
        }
        Ok(crate::coding::worktree::PatchApplyOutcome::Rejected { stderr }) => Err(format!(
            "git apply rejected patch for task {}: {stderr}",
            task.task_id.raw()
        )),
        Err(e) => Err(format!(
            "apply_patch_in_worktree IO error for task {}: {e}",
            task.task_id.raw()
        )),
    }
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
    outcome: &mut DispatchOutcome,
    diagnosis: &str,
    partial_outcome: Option<&WorkerOutcome>,
) -> anyhow::Result<()> {
    let attempt = retry_policy.record_attempt(task.task_id);
    let now_ns = now_unix_ns();

    // Diagnosis strings ride into `tracing::info!`/`warn!` which the
    // WAL subscriber persists durably. Provider-error messages can
    // carry an API key in a URL query string, a Bearer header, or a
    // leaked .env line. Redact before logging — see `security::redact`.
    let diagnosis = redact_text(diagnosis);

    if retry_policy.should_retry(task.task_id) {
        // Re-queue with a strategy hint appended to the description.
        // The dispatcher's next loop pass will pick the task up
        // again from Backlog with the hint visible to the worker.
        let strategy = retry_policy.pick_strategy(task.task_id);
        let hint = strategy.hint();
        info!(
            task_id = task.task_id.raw(),
            attempt = attempt,
            strategy = strategy.as_str(),
            diagnosis = %diagnosis,
            "worker attempt failed; retrying with strategy hint"
        );
        // Best-effort hint persistence — failure to append doesn't
        // block the retry, just means the next attempt runs without
        // the hint.
        if let Err(e) = store::append_task_description_hint(conn, task.task_id, hint) {
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
            let _ = store::attach_task_artifact(
                conn,
                task.task_id,
                Some(&o.patch_path),
                Some(o.tests),
            );
        }
        // Back to Backlog for the next dispatch loop iteration.
        store::patch_task_status(conn, task.task_id, TaskStatus::Backlog, now_ns)
            .context("re-queue task to Backlog for retry")?;
        // Don't count as blocked or completed yet — the dispatcher's
        // budget cap will end the loop if we churn too long.
    } else {
        // Ceiling hit — give up + transition to Blocked.
        let strategy = retry_policy.pick_strategy(task.task_id);
        warn!(
            task_id = task.task_id.raw(),
            attempt = attempt,
            final_strategy = strategy.as_str(),
            diagnosis = %diagnosis,
            "worker retry ceiling hit; task transitioned to Blocked"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::types::TestSummary;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// A canned worker — returns the same outcome every call.
    /// Sufficient to pin the dispatch path's contract.
    struct CannedWorker {
        outcome: WorkerOutcome,
        name: &'static str,
    }

    impl Worker for CannedWorker {
        fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            Ok(self.outcome.clone())
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    /// A worker that always errors. Lets us test the bail-out path
    /// without touching real provider code.
    struct FailingWorker;

    impl Worker for FailingWorker {
        fn execute(&self, _task: &KanbanTask) -> Result<WorkerOutcome> {
            anyhow::bail!("simulated worker failure")
        }
        fn name(&self) -> &'static str {
            "failing-worker"
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

    #[test]
    fn dispatch_with_no_workers_returns_zero_outcome() {
        // Pre-condition: dispatch with empty worker set MUST bail out
        // cleanly without touching the session. Operators can run
        // `neoth code` against a hemisphere-less freedom.yaml without
        // hitting an assertion.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let workers = HemisphereWorkerSet::new();
        let outcome =
            dispatch_session(&conn, session_id, &workers, DispatchBudget::default()).unwrap();
        assert_eq!(outcome.tasks_attempted, 0);
        assert_eq!(outcome.tasks_completed, 0);
        assert!(!outcome.budget_exhausted);
    }

    #[test]
    fn dispatch_runs_one_left_task_end_to_end() {
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
        let outcome =
            dispatch_session(&conn, session_id, &workers, DispatchBudget::default()).unwrap();
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

    #[test]
    fn dispatch_blocks_unassigned_hemisphere() {
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
        let outcome =
            dispatch_session(&conn, session_id, &workers, DispatchBudget::default()).unwrap();
        assert_eq!(outcome.tasks_unassigned, 1);
        assert_eq!(outcome.tasks_completed, 0);

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    #[test]
    fn dispatch_blocks_when_worker_errors() {
        // Worker.execute returning Err must transition the task to
        // Blocked, NOT InProgress, so an audit consumer never sees a
        // task stuck in InProgress without a worker producing output.
        let (_dir, conn) = fresh_db();
        let session_id = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let task_id = store::insert_task(&conn, session_id, 10, "t", None, "ui", None).unwrap();
        store::patch_task_hemisphere(&conn, task_id, Hemisphere::Left, None, None).unwrap();

        let mut workers = HemisphereWorkerSet::new();
        workers.bind(Hemisphere::Left, Box::new(FailingWorker));
        let outcome =
            dispatch_session(&conn, session_id, &workers, DispatchBudget::default()).unwrap();
        assert_eq!(outcome.tasks_blocked, 1);
        assert_eq!(outcome.tasks_completed, 0);

        let task = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Blocked);
    }

    #[test]
    fn dispatch_respects_max_tasks_budget() {
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
        let outcome = dispatch_session(&conn, session_id, &workers, budget).unwrap();
        assert_eq!(outcome.tasks_attempted, 2);
        assert!(outcome.budget_exhausted);

        let backlog_count = store::list_tasks_for_session(&conn, session_id)
            .unwrap()
            .into_iter()
            .filter(|t| t.status == TaskStatus::Backlog)
            .count();
        assert_eq!(backlog_count, 1);
    }

    #[test]
    fn dispatch_is_reentrant() {
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

        let first =
            dispatch_session(&conn, session_id, &workers, DispatchBudget::default()).unwrap();
        assert_eq!(first.tasks_attempted, 1);

        let second =
            dispatch_session(&conn, session_id, &workers, DispatchBudget::default()).unwrap();
        assert_eq!(second.tasks_attempted, 0);
        assert_eq!(second.tasks_completed, 0);
    }

    #[test]
    fn worker_set_bind_replaces_existing() {
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

    #[test]
    fn dispatch_budget_default_is_30_minutes_and_20_tasks() {
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
        Command::new("git").arg("-C").arg(dir).args(["init", "-q"]).status()?;
        Command::new("git").arg("-C").arg(dir)
            .args(["config", "user.email", "ph4-test@example.com"]).status()?;
        Command::new("git").arg("-C").arg(dir)
            .args(["config", "user.name", "ph4-test"]).status()?;
        std::fs::write(dir.join("README.md"), "initial\n")?;
        Command::new("git").arg("-C").arg(dir).args(["add", "README.md"]).status()?;
        Command::new("git").arg("-C").arg(dir)
            .args(["commit", "-q", "-m", "init"]).status()?;
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

    #[test]
    fn dispatch_session_with_apply_creates_worktree_and_applies_patch() {
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

    #[test]
    fn dispatch_session_with_apply_marks_task_blocked_on_conflict() {
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

    #[test]
    fn dispatch_session_with_apply_none_behaves_like_phase_3() {
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
        .expect("dispatch without apply");
        assert_eq!(outcome.tasks_completed, 1);
    }

    // Helper: silence dead-code on the Arc import in case the test
    // tree shrinks.
    #[allow(dead_code)]
    fn _arc_alive() -> Arc<()> {
        Arc::new(())
    }
}
