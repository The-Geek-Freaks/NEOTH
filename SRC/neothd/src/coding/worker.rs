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

use std::{ffi::OsString, path::PathBuf};

use async_trait::async_trait;

use crate::coding::types::{KanbanTask, TestSummary};

/// Maximum byte envelope accepted for one worker result. This mirrors the
/// provider completion cap, but sits at the dispatcher boundary as well so a
/// custom/test worker cannot bypass the provider parser and make the retry
/// ring, SQLite artifact columns, or apply path allocate unbounded output.
pub const MAX_WORKER_RESULT_BYTES: usize = 128 * 1024;

/// `WorkerOutcome::summary` is an operator-facing one-line field. The parser
/// already truncates at this character count; the central contract rejects
/// instead of truncating so callers cannot silently alter an audited result.
pub const MAX_WORKER_SUMMARY_CHARS: usize = 120;

/// A UTF-8 scalar is at most four bytes, so this bounds the raw summary bytes
/// independently of its character-count presentation contract.
pub const MAX_WORKER_SUMMARY_BYTES: usize = MAX_WORKER_SUMMARY_CHARS * 4;

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

/// Explicit state of the patch surface in a validated worker result. Only
/// [`Patch`](Self::Patch) gets a dispatcher-derived task artifact and may reach
/// the worktree apply path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerPatchState {
    NoPatch,
    Patch,
}

/// Address identity of the boxed worker bound by `HemisphereWorkerSet` for the
/// duration of one dispatch pass. It is captured only in the private,
/// in-memory contract and never serialized or logged. The boxed worker stays
/// allocated for the whole dispatcher borrow, so comparing this value catches
/// an accidental result/worker re-association even when two workers advertise
/// the same stable `Worker::name()` label.
fn dispatch_worker_identity(worker: &dyn Worker) -> usize {
    (worker as *const dyn Worker as *const ()) as usize
}

/// Content-free reason a [`WorkerContract`] rejected an untrusted result.
///
/// This type deliberately carries no returned worker text, patch bytes, or
/// path. The dispatcher uses only the stable code for logging/retry state, so
/// an invalid response is never copied into SQLite, WAL-facing diagnostics, or
/// a retry prompt before the contract boundary has accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerContractViolation {
    InvocationContext,
    ClaimedAppliedTests,
    IncoherentTestCounts,
    SummaryTooLong,
    SummaryTooLarge,
    SummaryContainsControl,
    PatchTooLarge,
    OutputTooLarge,
    PatchContainsControl,
    PatchUnsafe,
    ClaimedPatchPath,
    ArtifactPathUnsafe,
    ArtifactWriteFailed,
}

impl WorkerContractViolation {
    /// Stable, content-free diagnostic code suitable for a retry reason or
    /// structured log field. Never include provider-controlled strings here.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvocationContext => "invocation_context",
            Self::ClaimedAppliedTests => "claimed_applied_tests",
            Self::IncoherentTestCounts => "incoherent_test_counts",
            Self::SummaryTooLong => "summary_too_long",
            Self::SummaryTooLarge => "summary_too_large",
            Self::SummaryContainsControl => "summary_contains_control",
            Self::PatchTooLarge => "patch_too_large",
            Self::OutputTooLarge => "output_too_large",
            Self::PatchContainsControl => "patch_contains_control",
            Self::PatchUnsafe => "patch_unsafe",
            Self::ClaimedPatchPath => "claimed_patch_path",
            Self::ArtifactPathUnsafe => "artifact_path_unsafe",
            Self::ArtifactWriteFailed => "artifact_write_failed",
        }
    }
}

/// Dispatcher-owned, non-serializable binding for exactly one `Worker::execute`
/// call. It is created from the task selected by the dispatcher and the bound
/// worker object before execution, then checked again before any classification,
/// artifact persistence, retry-output storage, or worktree apply can inspect
/// the returned [`WorkerOutcome`].
///
/// The fields intentionally remain private and there is no serde form: a
/// provider response cannot forge a task/session/hemisphere/worker association
/// by echoing strings. Task and session ids are typed values from the actual
/// dispatcher selection, not caller-supplied text.
#[derive(Debug, Clone)]
pub(crate) struct WorkerContract {
    task_id: crate::coding::types::KanbanTaskId,
    session_id: crate::coding::types::KanbanSessionId,
    hemisphere: crate::coding::types::Hemisphere,
    worker_name: &'static str,
    worker_identity: usize,
    /// This comes from the dispatcher's live database/audit context, never
    /// from a worker. It is deliberately captured alongside the task identity
    /// before `execute` starts so the result cannot choose where it lands.
    audit_root: PathBuf,
    /// A dispatcher-generated, one-shot leaf name. It is not a retry counter
    /// or a worker value: the entropy means an older artifact for this task
    /// can never be replaced or selected by a later result.
    artifact_name: OsString,
}

impl WorkerContract {
    /// Capture the exact dispatch identity before invoking the worker.
    pub(crate) fn for_dispatch(
        task: &KanbanTask,
        worker: &dyn Worker,
        audit_root: &std::path::Path,
    ) -> Self {
        Self {
            task_id: task.task_id,
            session_id: task.session_id,
            hemisphere: task.hemisphere,
            worker_name: worker.name(),
            worker_identity: dispatch_worker_identity(worker),
            audit_root: audit_root.to_path_buf(),
            artifact_name: OsString::from(format!(
                "task-{}-{}.patch",
                task.task_id.raw(),
                uuid::Uuid::new_v4().simple()
            )),
        }
    }

    /// Validate the returned outcome against the dispatcher-owned invocation.
    /// The caller must pass the same task and bound worker that created this
    /// contract; any mismatch fails before the outcome is otherwise observed.
    pub(crate) fn validate_and_materialize(
        self,
        task: &KanbanTask,
        worker: &dyn Worker,
        outcome: WorkerOutcome,
    ) -> Result<AcceptedWorkerOutcome, WorkerContractViolation> {
        if self.task_id != task.task_id
            || self.session_id != task.session_id
            || self.hemisphere != task.hemisphere
            || self.worker_name != worker.name()
            || self.worker_identity != dispatch_worker_identity(worker)
        {
            return Err(WorkerContractViolation::InvocationContext);
        }
        if outcome.tests.applied {
            return Err(WorkerContractViolation::ClaimedAppliedTests);
        }
        if !outcome.tests.is_coherent() {
            return Err(WorkerContractViolation::IncoherentTestCounts);
        }
        if outcome.summary.chars().count() > MAX_WORKER_SUMMARY_CHARS {
            return Err(WorkerContractViolation::SummaryTooLong);
        }
        if outcome.summary.len() > MAX_WORKER_SUMMARY_BYTES {
            return Err(WorkerContractViolation::SummaryTooLarge);
        }
        if outcome.summary.chars().any(char::is_control) {
            return Err(WorkerContractViolation::SummaryContainsControl);
        }

        let patch_state = outcome.patch_state();
        if outcome.patch_text.len() > MAX_WORKER_RESULT_BYTES {
            return Err(WorkerContractViolation::PatchTooLarge);
        }
        if outcome
            .patch_text
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
        {
            return Err(WorkerContractViolation::PatchContainsControl);
        }
        if crate::coding::provider_worker::validate_worker_patch_text(&outcome.patch_text).is_err()
        {
            return Err(WorkerContractViolation::PatchUnsafe);
        }
        let output_bytes = outcome
            .summary
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(outcome.patch_text.len()));
        if !matches!(output_bytes, Some(n) if n <= MAX_WORKER_RESULT_BYTES) {
            return Err(WorkerContractViolation::OutputTooLarge);
        }

        // A WorkerOutcome is an untrusted message. In particular it is NOT
        // allowed to nominate a host path that an operator-approved --apply
        // will later read. Reject the legacy field instead of trying to
        // sanitize or compare it: the dispatcher writes only `patch_text` to
        // its task/session-bound artifact below.
        if !outcome.patch_path.as_os_str().is_empty() {
            return Err(WorkerContractViolation::ClaimedPatchPath);
        }

        let patch_path = match patch_state {
            WorkerPatchState::NoPatch => None,
            WorkerPatchState::Patch => Some(dispatch_patch_path(
                &self.audit_root,
                task,
                &self.artifact_name,
                outcome.patch_text.as_bytes(),
            )?),
        };
        Ok(AcceptedWorkerOutcome {
            outcome,
            patch_path,
        })
    }
}

/// A worker result that crossed the dispatcher-owned contract boundary. The
/// raw worker result cannot supply the artifact path: only
/// [`WorkerContract::validate_and_materialize`] can create this type and its
/// patch path is derived from the exact dispatched task/session context.
#[derive(Debug, Clone)]
pub(crate) struct AcceptedWorkerOutcome {
    outcome: WorkerOutcome,
    patch_path: Option<PathBuf>,
}

impl AcceptedWorkerOutcome {
    /// The dispatcher-created patch artifact. `None` honestly represents a
    /// coherent no-patch/test-only result and must never be persisted as a
    /// made-up patch path.
    pub(crate) fn patch_path(&self) -> Option<&PathBuf> {
        self.patch_path.as_ref()
    }

    /// The immutable text that crossed the central contract. This, rather
    /// than the audit artifact path, is the sole source for risk, hash, and
    /// worktree apply.
    pub(crate) fn patch_text(&self) -> Option<&str> {
        (self.outcome.patch_state() == WorkerPatchState::Patch)
            .then_some(self.outcome.patch_text.as_str())
    }
}

impl std::ops::Deref for AcceptedWorkerOutcome {
    type Target = WorkerOutcome;

    fn deref(&self) -> &Self::Target {
        &self.outcome
    }
}

/// Materialize the only patch source that can reach persistence or --apply.
/// The location is dispatcher-derived and exact: a one-shot, random leaf sits
/// under the selected task/session directory. The capability-relative helper
/// opens every ancestor without following links and publishes the final leaf
/// exclusively, so a symlink, junction, pre-existing file, or cross-task leaf
/// cannot redirect or replace the accepted bytes.
fn dispatch_patch_path(
    audit_root: &std::path::Path,
    task: &KanbanTask,
    artifact_name: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<PathBuf, WorkerContractViolation> {
    let session_path = audit_root
        .join("coding-sessions")
        .join(task.session_id.raw().to_string());
    let session = crate::skills::store::open_bound_directory_from_trusted_anchor(
        audit_root,
        &session_path,
        true,
        "coding worker patch artifact directory",
    )
    .map_err(|_| WorkerContractViolation::ArtifactPathUnsafe)?
    .ok_or(WorkerContractViolation::ArtifactPathUnsafe)?;
    let patch_path = session.display_path.join(artifact_name);
    crate::skills::store::atomic_write_private_child_create_new(
        &session.dir,
        artifact_name,
        &patch_path,
        bytes,
    )
    .map_err(|_| WorkerContractViolation::ArtifactWriteFailed)?;
    Ok(patch_path)
}

/// What a worker reports back after one task run. The worker can report text,
/// tests, and an operator summary; it cannot choose the durable patch
/// artifact. The dispatcher creates that route only after this value passes
/// [`WorkerContract`].
#[derive(Debug, Clone)]
pub struct WorkerOutcome {
    /// The patch text the worker produced. Unified-diff format ready
    /// for `git apply`. Empty string means "worker had nothing to
    /// change" — that's a successful no-op outcome, not a failure.
    pub patch_text: String,
    /// Deprecated compatibility surface for historical custom workers. It
    /// must remain an empty `PathBuf`: the central contract rejects every
    /// non-empty value so a worker can never pick the file that audit/risk/
    /// `--apply` later consumes. The accepted artifact route lives privately
    /// in [`AcceptedWorkerOutcome`].
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
    /// Explicitly classify the patch payload before a dispatcher decides
    /// whether there is any worktree material to apply.
    pub fn patch_state(&self) -> WorkerPatchState {
        if self.patch_text.is_empty() {
            WorkerPatchState::NoPatch
        } else {
            WorkerPatchState::Patch
        }
    }

    /// `true` when the outcome carries no patch + no tests. The
    /// dispatcher treats this as a `Blocked` transition instead of
    /// `Review` so the operator notices a worker that bailed out.
    pub fn failed(&self) -> bool {
        self.patch_state() == WorkerPatchState::NoPatch && self.tests == TestSummary::ZERO
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

    fn contract_result(
        expected_task: &KanbanTask,
        actual_task: &KanbanTask,
        expected_worker: &CannedWorker,
        actual_worker: &dyn Worker,
        outcome: &WorkerOutcome,
    ) -> Result<WorkerPatchState, WorkerContractViolation> {
        let audit = tempfile::tempdir().expect("contract audit root");
        WorkerContract::for_dispatch(expected_task, expected_worker, audit.path())
            .validate_and_materialize(actual_task, actual_worker, outcome.clone())
            .map(|accepted| accepted.patch_state())
    }

    fn valid_outcome() -> WorkerOutcome {
        WorkerOutcome {
            patch_text: "diff --git a/x b/x\n+safe\n".into(),
            patch_path: PathBuf::new(),
            tests: TestSummary {
                added: 1,
                total: 1,
                passing: 1,
                failing: 0,
                skipped: 0,
                applied: false,
            },
            summary: "safe change".into(),
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
            patch_path: PathBuf::new(),
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
            patch_path: PathBuf::new(),
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
            patch_path: PathBuf::new(),
            tests: TestSummary {
                added: 3,
                total: 3,
                passing: 3,
                failing: 0,
                skipped: 0,
                applied: false,
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
            patch_path: PathBuf::new(),
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

    #[test]
    fn worker_contract_accepts_normal_patch_and_test_only_outcomes() {
        let task = sample_task();
        let worker = CannedWorker {
            name_: "test-worker",
            outcome: valid_outcome(),
        };
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &valid_outcome()),
            Ok(WorkerPatchState::Patch)
        );

        let mut test_only = valid_outcome();
        test_only.patch_text.clear();
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &test_only),
            Ok(WorkerPatchState::NoPatch),
            "a coherent tests-only result remains a valid no-patch outcome"
        );
    }

    #[test]
    fn worker_contract_rejects_claimed_or_malformed_test_receipts() {
        let task = sample_task();
        let worker = CannedWorker {
            name_: "test-worker",
            outcome: valid_outcome(),
        };
        let mut claimed = valid_outcome();
        claimed.tests.applied = true;
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &claimed),
            Err(WorkerContractViolation::ClaimedAppliedTests)
        );

        for malformed in [
            TestSummary {
                added: 0,
                total: 1,
                passing: 0,
                failing: 0,
                skipped: 2,
                applied: false,
            },
            TestSummary {
                added: 0,
                total: 1,
                passing: 1,
                failing: 1,
                skipped: 0,
                applied: false,
            },
            TestSummary {
                added: 0,
                total: u32::MAX,
                passing: u32::MAX,
                failing: 1,
                skipped: 0,
                applied: false,
            },
        ] {
            let mut outcome = valid_outcome();
            outcome.tests = malformed;
            assert_eq!(
                contract_result(&task, &task, &worker, &worker, &outcome),
                Err(WorkerContractViolation::IncoherentTestCounts),
                "must reject malformed counts without arithmetic overflow"
            );
        }
    }

    #[test]
    fn worker_contract_rejects_controls_and_oversized_result_surfaces() {
        let task = sample_task();
        let worker = CannedWorker {
            name_: "test-worker",
            outcome: valid_outcome(),
        };

        let mut control_summary = valid_outcome();
        control_summary.summary = "unsafe\u{1b}[31m".into();
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &control_summary),
            Err(WorkerContractViolation::SummaryContainsControl)
        );

        let mut long_summary = valid_outcome();
        long_summary.summary = "x".repeat(MAX_WORKER_SUMMARY_CHARS + 1);
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &long_summary),
            Err(WorkerContractViolation::SummaryTooLong)
        );

        let mut control_patch = valid_outcome();
        control_patch.patch_text.push('\u{1b}');
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &control_patch),
            Err(WorkerContractViolation::PatchContainsControl)
        );

        let mut c1_control_patch = valid_outcome();
        c1_control_patch.patch_text.push('\u{0085}');
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &c1_control_patch),
            Err(WorkerContractViolation::PatchContainsControl),
            "all Unicode controls are rejected at the central boundary"
        );

        let mut credential_patch = valid_outcome();
        credential_patch.patch_text = concat!(
            "diff --git a/.env b/.env\n",
            "--- a/.env\n",
            "+++ b/.env\n",
            "@@ -0,0 +1 @@\n",
            "+token=sk-FAKE_TEST_CODING_AAAAAAAAAAAAAAAAAAA\n"
        )
        .into();
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &credential_patch),
            Err(WorkerContractViolation::PatchUnsafe),
            "a custom Worker cannot bypass the provider diff-secret gate"
        );

        let mut oversized_patch = valid_outcome();
        oversized_patch.patch_text = "x".repeat(MAX_WORKER_RESULT_BYTES + 1);
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &oversized_patch),
            Err(WorkerContractViolation::PatchTooLarge)
        );

        let mut oversized_output = valid_outcome();
        oversized_output.patch_text = "x".repeat(MAX_WORKER_RESULT_BYTES);
        assert_eq!(
            contract_result(&task, &task, &worker, &worker, &oversized_output),
            Err(WorkerContractViolation::OutputTooLarge)
        );

        // C10a provenance regression: route-looking, absolute Windows, UNC,
        // sibling, symlink-shaped, and mismatched paths are all rejected
        // without being opened. A worker cannot nominate the source that a
        // later direct review or --apply would persist/read.
        for claimed_path in [
            PathBuf::from("C:\\foreign\\absolute.patch"),
            PathBuf::from("\\\\host\\share\\unc.patch"),
            PathBuf::from("coding-sessions\\sibling\\task-42.patch"),
            PathBuf::from("linked\\task-42.patch"),
            PathBuf::from("mismatched.patch"),
        ] {
            let mut claimed_path_outcome = valid_outcome();
            claimed_path_outcome.patch_path = claimed_path;
            assert_eq!(
                contract_result(&task, &task, &worker, &worker, &claimed_path_outcome,),
                Err(WorkerContractViolation::ClaimedPatchPath),
                "a worker path can never select a dispatcher artifact"
            );
        }
    }

    #[test]
    fn worker_contract_materializes_only_exact_task_bound_patch_bytes() {
        let task = sample_task();
        let worker = CannedWorker {
            name_: "test-worker",
            outcome: valid_outcome(),
        };
        let audit = tempfile::tempdir().expect("audit root");
        let outcome = valid_outcome();
        let accepted = WorkerContract::for_dispatch(&task, &worker, audit.path())
            .validate_and_materialize(&task, &worker, outcome.clone())
            .expect("valid outcome crosses contract");
        let expected_parent = audit
            .path()
            .join("coding-sessions")
            .join(task.session_id.raw().to_string());
        let expected = accepted.patch_path().expect("patch outcome has artifact");
        assert_eq!(expected.parent(), Some(expected_parent.as_path()));
        assert!(
            expected
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("task-42-")),
            "only the dispatcher chooses the task-bound artifact leaf"
        );
        assert_eq!(
            expected.extension().and_then(|ext| ext.to_str()),
            Some("patch")
        );
        assert_eq!(
            std::fs::read(expected).unwrap(),
            outcome.patch_text.as_bytes()
        );
        std::fs::write(expected, b"artifact substitution after acceptance").unwrap();
        assert_eq!(
            accepted.patch_text(),
            Some(outcome.patch_text.as_str()),
            "the accepted execution bytes remain in-memory and never reopen the audit artifact"
        );

        let no_patch_audit = tempfile::tempdir().expect("no-patch audit root");
        let mut tests_only = valid_outcome();
        tests_only.patch_text.clear();
        let accepted = WorkerContract::for_dispatch(&task, &worker, no_patch_audit.path())
            .validate_and_materialize(&task, &worker, tests_only)
            .expect("coherent test-only outcome crosses contract");
        assert_eq!(accepted.patch_path(), None);
        assert!(
            !no_patch_audit.path().join("coding-sessions").exists(),
            "NoPatch must not create a durable patch namespace or artifact"
        );
    }

    #[test]
    fn worker_contract_refuses_a_preexisting_artifact_leaf_without_overwriting_it() {
        let task = sample_task();
        let audit = tempfile::tempdir().expect("audit root");
        let session = audit
            .path()
            .join("coding-sessions")
            .join(task.session_id.raw().to_string());
        std::fs::create_dir_all(&session).expect("session directory");
        let leaf = std::ffi::OsStr::new("task-42-preexisting.patch");
        let existing = session.join(leaf);
        std::fs::write(&existing, b"do not replace").expect("preexisting artifact");

        assert_eq!(
            dispatch_patch_path(audit.path(), &task, leaf, b"replacement"),
            Err(WorkerContractViolation::ArtifactWriteFailed),
            "the exclusive capability-relative commit rejects a preexisting leaf"
        );
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            b"do not replace",
            "a previous artifact must never be overwritten by another worker result"
        );
    }

    #[cfg(unix)]
    #[test]
    fn worker_contract_rejects_symlinked_artifact_directory() {
        use std::os::unix::fs::symlink;

        let task = sample_task();
        let worker = CannedWorker {
            name_: "test-worker",
            outcome: valid_outcome(),
        };
        let audit = tempfile::tempdir().expect("audit root");
        let foreign = tempfile::tempdir().expect("foreign root");
        let foreign_sessions = foreign.path().join("coding-sessions");
        std::fs::create_dir(&foreign_sessions).unwrap();
        symlink(&foreign_sessions, audit.path().join("coding-sessions")).unwrap();

        assert_eq!(
            WorkerContract::for_dispatch(&task, &worker, audit.path())
                .validate_and_materialize(&task, &worker, valid_outcome())
                .map(|_| ()),
            Err(WorkerContractViolation::ArtifactPathUnsafe),
            "a symlinked artifact namespace must never redirect dispatcher bytes"
        );
    }

    #[test]
    fn worker_contract_binds_the_exact_dispatch_task_and_worker() {
        let expected_task = sample_task();
        let mut other_task = sample_task();
        other_task.session_id = KanbanSessionId(2);
        let expected_worker = CannedWorker {
            name_: "test-worker",
            outcome: valid_outcome(),
        };
        let other_worker = CannedWorker {
            name_: "test-worker",
            outcome: valid_outcome(),
        };

        assert_eq!(
            contract_result(
                &expected_task,
                &other_task,
                &expected_worker,
                &expected_worker,
                &valid_outcome(),
            ),
            Err(WorkerContractViolation::InvocationContext),
            "a result cannot be re-associated with a different session task"
        );
        assert_eq!(
            contract_result(
                &expected_task,
                &expected_task,
                &expected_worker,
                &other_worker,
                &valid_outcome(),
            ),
            Err(WorkerContractViolation::InvocationContext),
            "the result is also bound to the actual worker object, not just its label"
        );
    }
}
