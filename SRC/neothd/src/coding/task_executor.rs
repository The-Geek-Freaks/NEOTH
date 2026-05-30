//! QU-10b / SP-A1 — pending-task controller loop.
//!
//! `cli::code::run_code` decomposes a prompt into a kanban session and
//! runs [`dispatcher::dispatch_session_with_apply`] ONCE against that one
//! freshly-created session. Pending work created any other way — a
//! deferred dispatch, tasks added to an existing session, or a session
//! whose `--dispatch` was skipped — sits in the kanban Backlog with
//! nothing driving it. This module is the controller that closes that
//! gap: it scans `idx_kanban_task` for every session with a Backlog task
//! and runs the dispatcher over each, aggregating the per-session
//! outcomes into one [`ExecutorReport`].
//!
//! **Operator-driven, not autonomous.** The coding workflow is explicitly
//! operator-gated (see `cli::code` — the operator drives dispatch). This
//! controller is invoked by `neoth code --run-pending`, NOT a daemon
//! loop: autonomously dispatching code workers in the background is an
//! autonomy/safety decision out of scope here. Each session gets the full
//! `DispatchBudget` (the per-session cycle caps still bound each run).

use anyhow::{Context, Result};
use rusqlite::Connection;

use super::dispatcher::{
    DispatchApplyConfig, DispatchBudget, DispatchOutcome, HemisphereWorkerSet,
    dispatch_session_with_apply,
};
use super::store;
use super::types::KanbanSessionId;

/// Aggregate of one `run_pending_sessions` pass across every session that
/// had Backlog work. `sessions_seen` is the count discovered up front;
/// `sessions_dispatched` is how many the loop actually drove (equal unless
/// a dispatch errored — which aborts the pass with the error context).
#[derive(Debug, Clone, Default)]
pub struct ExecutorReport {
    pub sessions_seen: usize,
    pub sessions_dispatched: usize,
    pub tasks_attempted: usize,
    pub tasks_completed: usize,
    pub tasks_blocked: usize,
    pub tasks_unassigned: usize,
    /// Number of sessions whose per-session budget was exhausted.
    pub budget_exhausted_sessions: usize,
    /// Per-session (id, outcome) in dispatch order, for the CLI render.
    pub per_session: Vec<(KanbanSessionId, DispatchOutcome)>,
}

/// Drive the dispatcher across every session that still has a Backlog
/// task (ascending session id, deterministic). Each session gets the
/// full `budget`; `apply_config` is threaded verbatim (so `--apply`
/// applies in the worktree just like the single-session path). A
/// dispatch error aborts the pass with context — the already-driven
/// sessions stay committed (the dispatcher writes per-task as it goes),
/// so a re-run resumes the remaining Backlog.
pub fn run_pending_sessions(
    conn: &Connection,
    workers: &HemisphereWorkerSet,
    budget: DispatchBudget,
    apply_config: Option<&DispatchApplyConfig>,
) -> Result<ExecutorReport> {
    let sessions =
        store::sessions_with_backlog_tasks(conn).context("list sessions with backlog tasks")?;
    let mut report = ExecutorReport {
        sessions_seen: sessions.len(),
        ..Default::default()
    };
    for session_id in sessions {
        let outcome = dispatch_session_with_apply(conn, session_id, workers, budget, apply_config)
            .with_context(|| format!("dispatch pending session {}", session_id.raw()))?;
        report.sessions_dispatched += 1;
        report.tasks_attempted += outcome.tasks_attempted;
        report.tasks_completed += outcome.tasks_completed;
        report.tasks_blocked += outcome.tasks_blocked;
        report.tasks_unassigned += outcome.tasks_unassigned;
        if outcome.budget_exhausted {
            report.budget_exhausted_sessions += 1;
        }
        report.per_session.push((session_id, outcome));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::types::{Hemisphere, KanbanTask, TestSummary};
    use crate::coding::worker::{Worker, WorkerOutcome};

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        store::ensure_schema(&conn).unwrap();
        conn
    }

    /// Seed one session with a single Left-assigned Backlog task. Returns
    /// the session id.
    fn seed_left_backlog(conn: &Connection, title: &str) -> KanbanSessionId {
        let sid = store::insert_session(conn, 1000, "prompt", "deadbeef", "cli", None).unwrap();
        let tid = store::insert_task(conn, sid, 1000, title, None, "feature", None).unwrap();
        store::patch_task_hemisphere(conn, tid, Hemisphere::Left, Some("left/mock"), None).unwrap();
        sid
    }

    struct MockWorker;
    impl Worker for MockWorker {
        fn execute(&self, _task: &KanbanTask) -> anyhow::Result<WorkerOutcome> {
            Ok(WorkerOutcome {
                patch_text: "diff --git a/x b/x\n@@\n+ok\n".into(),
                patch_path: std::path::PathBuf::from("mock.patch"),
                tests: TestSummary {
                    added: 1,
                    total: 1,
                    passing: 1,
                    failing: 0,
                    skipped: 0,
                },
                summary: "mock worker did the work".into(),
            })
        }
        fn name(&self) -> &'static str {
            "left/mock"
        }
    }

    fn left_workers() -> HemisphereWorkerSet {
        let mut w = HemisphereWorkerSet::new();
        w.bind(Hemisphere::Left, Box::new(MockWorker));
        w
    }

    #[test]
    fn sessions_with_backlog_returns_only_sessions_that_have_backlog() {
        let conn = open();
        let s1 = seed_left_backlog(&conn, "t1");
        let s2 = seed_left_backlog(&conn, "t2");
        // A third session with NO tasks must not appear.
        let _empty = store::insert_session(&conn, 1000, "p", "feed", "cli", None).unwrap();
        let pending = store::sessions_with_backlog_tasks(&conn).unwrap();
        assert_eq!(pending, vec![s1, s2]);
    }

    #[test]
    fn run_pending_empty_when_no_backlog() {
        let conn = open();
        let report =
            run_pending_sessions(&conn, &left_workers(), DispatchBudget::default(), None).unwrap();
        assert_eq!(report.sessions_seen, 0);
        assert_eq!(report.sessions_dispatched, 0);
        assert_eq!(report.tasks_attempted, 0);
    }

    #[test]
    fn run_pending_drains_backlog_across_sessions() {
        let conn = open();
        seed_left_backlog(&conn, "t1");
        seed_left_backlog(&conn, "t2");
        let report =
            run_pending_sessions(&conn, &left_workers(), DispatchBudget::default(), None).unwrap();
        assert_eq!(report.sessions_seen, 2);
        assert_eq!(report.sessions_dispatched, 2);
        assert_eq!(report.tasks_attempted, 2, "one task per session attempted");
        // Pin the cross-session accumulation (`+=`, not `=`): MockWorker
        // returns review-ready (patch + 1 passing test, apply_config=None),
        // so each session completes its one task → 2 total. A regression to
        // `=` would silently report 1 here.
        assert_eq!(
            report.tasks_completed, 2,
            "tasks_completed must accumulate across both sessions"
        );
        assert_eq!(report.per_session.len(), 2);
        // The controller drained every Backlog task — a second pass finds
        // nothing pending.
        assert!(
            store::sessions_with_backlog_tasks(&conn)
                .unwrap()
                .is_empty(),
            "backlog must be drained after the executor pass"
        );
    }

    #[test]
    fn run_pending_with_no_workers_attempts_nothing_and_leaves_backlog() {
        let conn = open();
        let sid = seed_left_backlog(&conn, "t1");
        // Empty worker set: dispatch_session short-circuits (no worker
        // bound), so the task is never attempted and stays in Backlog.
        let empty = HemisphereWorkerSet::new();
        let report = run_pending_sessions(&conn, &empty, DispatchBudget::default(), None).unwrap();
        assert_eq!(report.sessions_seen, 1);
        assert_eq!(report.tasks_attempted, 0);
        assert_eq!(
            store::sessions_with_backlog_tasks(&conn).unwrap(),
            vec![sid],
            "no worker → backlog untouched"
        );
    }
}
