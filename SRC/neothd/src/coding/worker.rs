//! Pick #6 Phase 1 — `Worker` trait + `WorkerOutcome` types.
//!
//! Per `PLAN/CHORUS_dispatcher_design.md` (2026-05-20). This module
//! lands the dispatcher's type surface only: the trait every
//! hemisphere-bound worker must implement, and the outcome struct
//! a worker reports back. Concrete impls (LeftWorker against local
//! Qwen / RightWorker against claude_cli or openai_compat) land in
//! Phase 2 once the Chorus verdict on patch safety (Q1) settles.
//!
//! QU-10d (Session 30): the trait is now `async` (via `async_trait`) —
//! the prerequisite picked for parallel dispatch. Provider-backed
//! workers `.await` their `provider.complete` directly instead of the
//! prior `runtime.block_on` hack, and `task_executor` can drive several
//! sessions concurrently (`run_pending_sessions_parallel`).

use std::path::PathBuf;

use async_trait::async_trait;

use crate::coding::types::{KanbanTask, TestSummary};

/// One worker run against a single kanban task. Each hemisphere has
/// its own concrete impl wired through `HemisphereWorkerSet`. The
/// dispatcher invokes `execute` after transitioning the task into
/// `InProgress` and applies the returned outcome via
/// `store::patch_task_result` + status transition to `Review` (or
/// `Blocked` on `WorkerOutcome.failed()`).
#[async_trait]
pub trait Worker: Send + Sync {
    /// Execute the worker against the given task. `async` (QU-10d) so a
    /// provider-backed worker awaits `provider.complete` on the ambient
    /// runtime instead of holding a `block_on` handle, and the executor
    /// can drive multiple sessions concurrently. The hemisphere wiring
    /// still guarantees one task at a time per hemisphere within a
    /// session; `WorkerOutcome.summary` lands in the activity feed
    /// regardless of success.
    async fn execute(&self, task: &KanbanTask) -> anyhow::Result<WorkerOutcome>;

    /// Operator-readable name of this worker, e.g. `"left/local_qwen"`,
    /// `"right/claude_cli"`. Used in WAL frames + the activity feed +
    /// `neoth kanban task <id>` output. Stable across releases — a
    /// rename invalidates audit chain readability.
    fn name(&self) -> &'static str;
}

/// What a worker reports back after one task run. Stored in
/// `idx_kanban_task.test_summary` (JSON-encoded `TestSummary` only)
/// + the patch text/path columns. The `summary` field surfaces in
///   the activity-feed-right-rail one-line.
#[derive(Debug, Clone)]
pub struct WorkerOutcome {
    /// The patch text the worker produced. Unified-diff format ready
    /// for `git apply`. Empty string means "worker had nothing to
    /// change" — that's a successful no-op outcome, not a failure.
    pub patch_text: String,
    /// Where the patch was saved on disk. The dispatcher writes it to
    /// `<wal_dir>/coding-sessions/<session-id>/task-<id>.patch` so
    /// audit consumers can re-apply / re-review without re-running
    /// the worker.
    pub patch_path: PathBuf,
    /// Test outcome. `TestSummary::ZERO` means the worker ran no
    /// tests; the auto-promote check (`coding::review::check_auto_promotable`)
    /// already gates DONE on `total > 0 && failing == 0`.
    pub tests: TestSummary,
    /// One-line operator-facing summary. Shows up in `neoth kanban
    /// watch` + the GUI activity-feed-rail. Pin to ≤120 chars so the
    /// feed rendering stays clean; longer worker prose belongs in a
    /// `KANBAN_TASK_COMMENT` frame.
    pub summary: String,
}

impl WorkerOutcome {
    /// `true` when the outcome carries no patch + no tests. The
    /// dispatcher treats this as a `Blocked` transition instead of
    /// `Review` so the operator notices a worker that bailed out.
    pub fn failed(&self) -> bool {
        self.patch_text.is_empty() && self.tests == TestSummary::ZERO
    }

    /// `true` when the outcome is review-ready: at least one of patch
    /// or tests is non-empty. Used by the dispatcher to decide
    /// `InProgress → Review` vs `InProgress → Blocked`.
    pub fn review_ready(&self) -> bool {
        !self.failed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::types::{Hemisphere, KanbanSessionId, KanbanTaskId, TaskStatus};

    fn sample_task() -> KanbanTask {
        KanbanTask {
            task_id: KanbanTaskId(42),
            session_id: KanbanSessionId(1),
            status: TaskStatus::Todo,
            title: "Sample".into(),
            description: None,
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
        }
    }

    /// A test-only worker that returns whatever outcome the test
    /// hands it. Sufficient to pin the dispatch path's contract
    /// without booting a real provider.
    struct CannedWorker {
        name_: &'static str,
        outcome: WorkerOutcome,
    }

    #[async_trait]
    impl Worker for CannedWorker {
        async fn execute(&self, _task: &KanbanTask) -> anyhow::Result<WorkerOutcome> {
            Ok(self.outcome.clone())
        }
        fn name(&self) -> &'static str {
            self.name_
        }
    }

    #[test]
    fn worker_outcome_failed_when_both_empty() {
        // A worker that bails out with no patch + no tests must be
        // visible to the dispatcher as `failed()` so the task can
        // surface as Blocked rather than silently slipping into Review.
        let o = WorkerOutcome {
            patch_text: "".into(),
            patch_path: PathBuf::from("/tmp/empty.patch"),
            tests: TestSummary::ZERO,
            summary: "worker had nothing to add".into(),
        };
        assert!(o.failed());
        assert!(!o.review_ready());
    }

    #[test]
    fn worker_outcome_review_ready_with_just_patch() {
        // A patch-only outcome (no tests added) is still review-ready
        // — the operator may have manually validated, the auto-
        // promote check separately gates DONE on tests being green.
        let o = WorkerOutcome {
            patch_text: "diff --git a/x b/x\n+new line\n".into(),
            patch_path: PathBuf::from("/tmp/x.patch"),
            tests: TestSummary::ZERO,
            summary: "added a line".into(),
        };
        assert!(o.review_ready());
        assert!(!o.failed());
    }

    #[test]
    fn worker_outcome_review_ready_with_just_tests() {
        // A tests-only outcome (worker added regression coverage but
        // no code change) is still review-ready. Niche but legal.
        let o = WorkerOutcome {
            patch_text: "".into(),
            patch_path: PathBuf::from("/tmp/x.patch"),
            tests: TestSummary {
                added: 3,
                total: 3,
                passing: 3,
                failing: 0,
                skipped: 0,
            },
            summary: "added 3 regression tests".into(),
        };
        assert!(o.review_ready());
    }

    #[tokio::test]
    async fn canned_worker_returns_outcome_unchanged() {
        // The test harness contract: a CannedWorker echoes its outcome
        // through `execute` so test bodies can exercise dispatch
        // logic without provider plumbing.
        let outcome = WorkerOutcome {
            patch_text: "x".into(),
            patch_path: PathBuf::from("/tmp/x.patch"),
            tests: TestSummary::ZERO,
            summary: "test".into(),
        };
        let w = CannedWorker {
            name_: "test-worker",
            outcome: outcome.clone(),
        };
        let result = w.execute(&sample_task()).await.expect("canned worker ok");
        assert_eq!(result.patch_text, outcome.patch_text);
        assert_eq!(w.name(), "test-worker");
    }
}
