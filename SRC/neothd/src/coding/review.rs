//! Review + auto-promote flow — Pick #10 per
//! `PLAN/SPEC_coding_workflow.md` build order.
//!
//! After a worker completes a task and lands a patch + `TestSummary`
//! into REVIEW, NEOTH can auto-promote to DONE when the test outcome
//! is `all_green` (i.e. at least one test, zero failing). Operators
//! who want a manual gate run `neoth kanban review <task> --promote`
//! to do the same check + transition explicitly.
//!
//! Inter-hemisphere comments are already shipped via Pick #2
//! `store::insert_comment` — this module wires the auto-promote
//! decision + provides a session-wide sweep so the dispatcher can
//! ask "which REVIEW tasks are ready to land?" in one call.
//!
//! Pure decision functions stay testable without the dispatcher.

use anyhow::{Context, Result};
use rusqlite::Connection;

use super::store;
use super::types::{KanbanSessionId, KanbanTask, KanbanTaskId, TaskStatus};

/// Why a REVIEW task was NOT auto-promoted. Used by the CLI surface
/// (`neoth kanban review <task>`) to tell the operator what's
/// missing — "no patch", "tests not green", "wrong status", etc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReviewBlocker {
    /// Task is not in REVIEW (might be still IN_PROGRESS or already DONE).
    NotInReview,
    /// Worker did not attach a `TestSummary` JSON to the row.
    NoTestSummary,
    /// `TestSummary::all_green()` is false: zero tests OR ≥1 failing.
    TestsNotGreen,
}

impl ReviewBlocker {
    pub const fn as_str(self) -> &'static str {
        match self {
            ReviewBlocker::NotInReview => "task is not in REVIEW status",
            ReviewBlocker::NoTestSummary => "worker did not attach test summary",
            ReviewBlocker::TestsNotGreen => "tests are not green (zero or failing)",
        }
    }
}

/// Decision-only check — pure function over a `KanbanTask`. Returns
/// `Ok(())` when the task is auto-promotable, `Err(ReviewBlocker)`
/// otherwise. The dispatcher (Pick #6) calls this BEFORE issuing a
/// status patch + the CLI's `--promote --check` flag prints the
/// blocker without touching state.
pub fn check_auto_promotable(task: &KanbanTask) -> Result<(), ReviewBlocker> {
    if task.status != TaskStatus::Review {
        return Err(ReviewBlocker::NotInReview);
    }
    let Some(summary) = task.test_summary else {
        return Err(ReviewBlocker::NoTestSummary);
    };
    if !summary.all_green() {
        return Err(ReviewBlocker::TestsNotGreen);
    }
    Ok(())
}

/// Look up the task, check via `check_auto_promotable`, and (when
/// allowed) transition to DONE via `store::patch_task_status`. Returns
/// `Ok(true)` when the promotion landed; `Ok(false)` when the task was
/// in REVIEW but blocked by a missing summary or failing tests (caller
/// inspects via a separate `check_auto_promotable` if they need the
/// blocker reason); `Err(...)` for IO/store errors.
///
/// `Err(ReviewBlocker::NotInReview)` is NOT bubbled — a task that
/// wasn't in REVIEW silently returns `Ok(false)` so the sweep variant
/// can run over every task without per-task error noise.
pub fn auto_promote_if_green(
    conn: &Connection,
    task_id: KanbanTaskId,
    now_ns: u64,
) -> Result<bool> {
    let task = fetch_task(conn, task_id)?;
    match check_auto_promotable(&task) {
        Ok(()) => {
            store::patch_task_status(conn, task_id, TaskStatus::Done, now_ns)
                .with_context(|| format!("auto-promote task #{} REVIEW → DONE", task_id.raw()))?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Sweep every task in a session, auto-promoting each REVIEW row
/// that passes `check_auto_promotable`. Returns the number that
/// transitioned. The dispatcher (Pick #6) calls this after a batch
/// of worker completions to land the green ones in one pass.
pub fn auto_promote_session(
    conn: &Connection,
    session_id: KanbanSessionId,
    now_ns: u64,
) -> Result<usize> {
    let tasks = store::list_tasks_for_session(conn, session_id)
        .context("list tasks for session in review sweep")?;
    let mut promoted = 0usize;
    for task in &tasks {
        if check_auto_promotable(task).is_ok() {
            store::patch_task_status(conn, task.task_id, TaskStatus::Done, now_ns).with_context(
                || {
                    format!(
                        "sweep auto-promote task #{} REVIEW → DONE",
                        task.task_id.raw()
                    )
                },
            )?;
            promoted += 1;
        }
    }
    Ok(promoted)
}

/// Diagnostic helper — load one task by id. Returns an anyhow error
/// when the row is missing; the auto-promote path treats absence as
/// fatal because the caller asked for a specific id.
fn fetch_task(conn: &Connection, task_id: KanbanTaskId) -> Result<KanbanTask> {
    let tasks = store::list_tasks_for_session(conn, lookup_session(conn, task_id)?)?;
    tasks
        .into_iter()
        .find(|t| t.task_id == task_id)
        .ok_or_else(|| anyhow::anyhow!("task #{} not found", task_id.raw()))
}

/// Sqlite roundtrip to find which session owns a task. Single-row,
/// index-backed via `idx_kanban_task` PK. Keeps the fetch path simple
/// — no new SELECT helper needed in `store.rs` just for review.
fn lookup_session(conn: &Connection, task_id: KanbanTaskId) -> Result<KanbanSessionId> {
    let session_id: i64 = conn
        .query_row(
            "SELECT session_id FROM idx_kanban_task WHERE task_id = ?1",
            [task_id.raw()],
            |row| row.get(0),
        )
        .with_context(|| format!("look up session for task #{}", task_id.raw()))?;
    Ok(KanbanSessionId(session_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::types::{Hemisphere, TestSummary};
    use tempfile::tempdir;

    fn fresh_db() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = crate::memory::store::open(&path).unwrap();
        store::ensure_schema(&conn).unwrap();
        (dir, conn)
    }

    fn task_with(
        status: TaskStatus,
        hemisphere: Hemisphere,
        summary: Option<TestSummary>,
    ) -> KanbanTask {
        KanbanTask {
            task_id: KanbanTaskId(1),
            session_id: KanbanSessionId(1),
            status,
            title: "title".to_string(),
            description: None,
            task_type: "ui".to_string(),
            hemisphere,
            worker: None,
            parent_task_id: None,
            created_ns: 0,
            started_ns: None,
            eta_ns: None,
            completed_ns: None,
            patch_path: None,
            test_summary: summary,
        }
    }

    // ── Pure decision check ────────────────────────────────────────────────

    #[test]
    fn check_rejects_non_review_status() {
        for status in [
            TaskStatus::Backlog,
            TaskStatus::Todo,
            TaskStatus::InProgress,
            TaskStatus::Done,
            TaskStatus::Blocked,
            TaskStatus::Archived,
        ] {
            let task = task_with(
                status,
                Hemisphere::Left,
                Some(TestSummary {
                    added: 5,
                    total: 5,
                    passing: 5,
                    failing: 0,
                    skipped: 0,
                }),
            );
            assert_eq!(
                check_auto_promotable(&task),
                Err(ReviewBlocker::NotInReview),
                "status {status:?} must NOT auto-promote — only Review"
            );
        }
    }

    #[test]
    fn check_rejects_review_without_test_summary() {
        let task = task_with(TaskStatus::Review, Hemisphere::Left, None);
        assert_eq!(
            check_auto_promotable(&task),
            Err(ReviewBlocker::NoTestSummary)
        );
    }

    #[test]
    fn check_rejects_review_with_zero_tests() {
        // Per `TestSummary::all_green` contract: zero tests does NOT
        // count as green — blocks worker patches that skip tests.
        let task = task_with(
            TaskStatus::Review,
            Hemisphere::Left,
            Some(TestSummary::ZERO),
        );
        assert_eq!(
            check_auto_promotable(&task),
            Err(ReviewBlocker::TestsNotGreen),
            "zero-test summary must block auto-promote"
        );
    }

    #[test]
    fn check_rejects_review_with_failing_tests() {
        let task = task_with(
            TaskStatus::Review,
            Hemisphere::Left,
            Some(TestSummary {
                added: 5,
                total: 5,
                passing: 3,
                failing: 2,
                skipped: 0,
            }),
        );
        assert_eq!(
            check_auto_promotable(&task),
            Err(ReviewBlocker::TestsNotGreen)
        );
    }

    #[test]
    fn check_accepts_review_with_all_green() {
        let task = task_with(
            TaskStatus::Review,
            Hemisphere::Left,
            Some(TestSummary {
                added: 5,
                total: 5,
                passing: 5,
                failing: 0,
                skipped: 0,
            }),
        );
        assert!(check_auto_promotable(&task).is_ok());
    }

    #[test]
    fn check_accepts_review_with_skipped_tests_if_rest_pass() {
        // Skipped is tolerated — operator might gate a flaky test
        // behind `#[ignore]` while the rest of the suite passes.
        let task = task_with(
            TaskStatus::Review,
            Hemisphere::Left,
            Some(TestSummary {
                added: 5,
                total: 5,
                passing: 4,
                failing: 0,
                skipped: 1,
            }),
        );
        assert!(check_auto_promotable(&task).is_ok());
    }

    #[test]
    fn review_blocker_strings_are_operator_actionable() {
        // Pin the operator-readable strings — `neoth kanban review
        // <task>` surfaces them, runbook references them verbatim.
        assert_eq!(
            ReviewBlocker::NotInReview.as_str(),
            "task is not in REVIEW status"
        );
        assert_eq!(
            ReviewBlocker::NoTestSummary.as_str(),
            "worker did not attach test summary"
        );
        assert_eq!(
            ReviewBlocker::TestsNotGreen.as_str(),
            "tests are not green (zero or failing)"
        );
    }

    // ── Integration with the store ─────────────────────────────────────────

    #[test]
    fn auto_promote_if_green_lands_in_done_with_completed_ns() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();
        store::patch_task_status(&conn, t, TaskStatus::InProgress, 100).unwrap();
        store::patch_task_status(&conn, t, TaskStatus::Review, 200).unwrap();
        store::attach_task_artifact(
            &conn,
            t,
            None,
            Some(TestSummary {
                added: 3,
                total: 3,
                passing: 3,
                failing: 0,
                skipped: 0,
            }),
        )
        .unwrap();

        let promoted = auto_promote_if_green(&conn, t, 300).expect("promote");
        assert!(promoted, "all-green REVIEW task must auto-promote");

        let tasks = store::list_tasks_for_session(&conn, s).unwrap();
        let task = tasks.into_iter().find(|x| x.task_id == t).unwrap();
        assert_eq!(task.status, TaskStatus::Done);
        assert_eq!(task.completed_ns, Some(300));
    }

    #[test]
    fn auto_promote_if_green_silently_skips_blocked_tasks() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "title", None, "ui", None).unwrap();
        // Move to REVIEW but DON'T attach a test summary.
        store::patch_task_status(&conn, t, TaskStatus::Review, 100).unwrap();

        let promoted = auto_promote_if_green(&conn, t, 200).expect("no error");
        assert!(!promoted, "task without test summary must NOT promote");

        let tasks = store::list_tasks_for_session(&conn, s).unwrap();
        let task = tasks.into_iter().find(|x| x.task_id == t).unwrap();
        assert_eq!(task.status, TaskStatus::Review, "status must stay Review");
    }

    #[test]
    fn auto_promote_session_counts_only_green_review_tasks() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();

        // Three tasks in REVIEW:
        //   t1: all-green → should promote
        //   t2: zero tests → should NOT promote
        //   t3: 1 failing → should NOT promote
        let t1 = store::insert_task(&conn, s, 10, "green", None, "ui", None).unwrap();
        let t2 = store::insert_task(&conn, s, 11, "no-tests", None, "ui", None).unwrap();
        let t3 = store::insert_task(&conn, s, 12, "failing", None, "ui", None).unwrap();
        // Plus one in IN_PROGRESS that should be untouched.
        let t4 = store::insert_task(&conn, s, 13, "in-progress", None, "ui", None).unwrap();

        for t in [t1, t2, t3] {
            store::patch_task_status(&conn, t, TaskStatus::Review, 100).unwrap();
        }
        store::patch_task_status(&conn, t4, TaskStatus::InProgress, 100).unwrap();

        store::attach_task_artifact(
            &conn,
            t1,
            None,
            Some(TestSummary {
                added: 1,
                total: 1,
                passing: 1,
                failing: 0,
                skipped: 0,
            }),
        )
        .unwrap();
        // t2 gets NO summary.
        store::attach_task_artifact(
            &conn,
            t3,
            None,
            Some(TestSummary {
                added: 2,
                total: 2,
                passing: 1,
                failing: 1,
                skipped: 0,
            }),
        )
        .unwrap();

        let promoted = auto_promote_session(&conn, s, 300).expect("sweep");
        assert_eq!(promoted, 1, "only t1 must auto-promote");

        let tasks = store::list_tasks_for_session(&conn, s).unwrap();
        let by_id = |id: KanbanTaskId| tasks.iter().find(|x| x.task_id == id).unwrap().status;
        assert_eq!(by_id(t1), TaskStatus::Done);
        assert_eq!(by_id(t2), TaskStatus::Review);
        assert_eq!(by_id(t3), TaskStatus::Review);
        assert_eq!(by_id(t4), TaskStatus::InProgress);
    }

    #[test]
    fn auto_promote_session_handles_empty_session() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let promoted = auto_promote_session(&conn, s, 100).expect("empty");
        assert_eq!(promoted, 0);
    }
}
