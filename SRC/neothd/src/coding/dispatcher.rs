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
                outcome.tasks_completed += 1;
                // Worker succeeded — clear retry state so a future
                // re-run of the same task starts fresh.
                retry_policy.reset(task.task_id);
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

    // Helper: silence dead-code on the Arc import in case the test
    // tree shrinks.
    #[allow(dead_code)]
    fn _arc_alive() -> Arc<()> {
        Arc::new(())
    }
}
