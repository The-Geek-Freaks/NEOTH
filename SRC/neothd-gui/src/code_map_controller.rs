//! Typed GUI ownership for code-map lifecycle operations.
//!
//! The controller contains no Slint state and never shells out.  Its small
//! ownership model makes a cancellation request and a worker completion refer
//! to the same canonical root and operation revision.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};

use neothd::code_map::{
    CodeMapLifecycleReceipt, CodeMapLifecycleStatus, LifecycleCancellation,
    LifecycleRefreshOptions, inspect, refresh,
};

#[derive(Clone, Debug)]
pub struct CodeMapOperation {
    revision: u64,
    root: PathBuf,
    cancellation: LifecycleCancellation,
}

impl CodeMapOperation {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    #[cfg(test)]
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

#[derive(Default)]
struct ControllerState {
    next_revision: u64,
    current_view: Option<(u64, PathBuf)>,
    active: Option<ActiveOperation>,
}

/// The controller records the execution claim separately from its public
/// operation handle.  A clone of a handle may be held by a UI callback, but
/// it cannot start a second core refresh once one worker claimed this slot.
struct ActiveOperation {
    operation: CodeMapOperation,
    execution: RefreshExecution,
}

/// A core refresh is the only path that may settle an execution claim.  The
/// terminal UI worker may then release that settled operation; neither a
/// stale handle nor a premature completion callback may release `Running`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefreshExecution {
    NotStarted,
    Running,
    Settled,
}

/// One GUI process owns at most one lifecycle refresh at a time.  The core
/// database lease remains the cross-process authority; this prevents a stale
/// local completion from replacing newer UI state.
pub struct CodeMapLifecycleController {
    database_path: PathBuf,
    state: Mutex<ControllerState>,
}

impl CodeMapLifecycleController {
    pub fn new(database_path: PathBuf) -> Self {
        Self {
            database_path,
            state: Mutex::new(ControllerState::default()),
        }
    }

    pub fn inspect(&self, root: &Path) -> Result<(u64, PathBuf, CodeMapLifecycleStatus)> {
        // Inspection owns no filesystem mutation. Preserve the exact root
        // request so core can return its typed `Unmapped` status instead of a
        // GUI-side canonicalization error.
        let root = root.to_path_buf();
        let revision = self.claim_revision(&root)?;
        let status = inspect(&self.database_path, &root);
        Ok((revision, root, status))
    }

    pub fn begin_refresh(&self, root: &Path) -> Result<CodeMapOperation> {
        let root = canonical_root(root)?;
        let mut state = self
            .state
            .lock()
            .expect("code-map controller lock poisoned");
        if let Some(active) = &state.active {
            bail!(
                "A repository index operation is already running for {}.",
                active.operation.root.display()
            );
        }
        state.next_revision = state
            .next_revision
            .checked_add(1)
            .context("code-map operation revision overflow")?;
        let operation = CodeMapOperation {
            revision: state.next_revision,
            root,
            cancellation: LifecycleCancellation::new(),
        };
        state.current_view = Some((operation.revision, operation.root.clone()));
        state.active = Some(ActiveOperation {
            operation: operation.clone(),
            execution: RefreshExecution::NotStarted,
        });
        Ok(operation)
    }

    pub fn refresh(
        &self,
        operation: &CodeMapOperation,
        options: LifecycleRefreshOptions,
    ) -> Result<CodeMapLifecycleReceipt> {
        // Claiming under the same mutex that owns `active` closes both stale
        // handle and duplicate-clone races before the core can touch disk.
        // We intentionally release the mutex before the blocking core call so
        // cancellation can still reach the active operation while it runs.
        self.claim_refresh_execution(operation)?;
        let result = refresh(
            &self.database_path,
            operation.root(),
            options,
            &operation.cancellation,
        );
        self.mark_refresh_settled(operation);
        result
    }

    /// Signals the owned core cancellation token.  The active slot remains
    /// occupied until [`Self::finish`] observes the worker's terminal receipt.
    pub fn request_cancel(&self) -> Option<CodeMapOperation> {
        let operation = self
            .state
            .lock()
            .expect("code-map controller lock poisoned")
            .active
            .as_ref()
            .map(|active| active.operation.clone());
        if let Some(operation) = &operation {
            operation.cancel();
        }
        operation
    }

    /// Clears an operation only when it is still the current root/revision.
    /// Returns whether its completion may update the view.
    pub(super) fn finish(&self, operation: &CodeMapOperation) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("code-map controller lock poisoned");
        let current = state.active.as_ref().is_some_and(|active| {
            active.operation.revision == operation.revision
                && active.operation.root == operation.root
                && active.execution == RefreshExecution::Settled
        });
        if current {
            state.active = None;
        }
        current
            && state.current_view.as_ref().is_some_and(|(revision, root)| {
                *revision == operation.revision && root == operation.root()
            })
    }

    #[cfg(test)]
    pub fn is_current(&self, revision: u64, root: &Path) -> bool {
        self.state
            .lock()
            .expect("code-map controller lock poisoned")
            .active
            .as_ref()
            .is_some_and(|active| {
                active.operation.revision == revision && active.operation.root == root
            })
    }

    pub fn has_active_refresh(&self) -> bool {
        self.state
            .lock()
            .expect("code-map controller lock poisoned")
            .active
            .is_some()
    }

    pub fn is_current_view(&self, revision: u64, root: &Path) -> bool {
        self.state
            .lock()
            .expect("code-map controller lock poisoned")
            .current_view
            .as_ref()
            .is_some_and(|(current_revision, current_root)| {
                *current_revision == revision && current_root == root
            })
    }

    fn claim_revision(&self, root: &Path) -> Result<u64> {
        let mut state = self
            .state
            .lock()
            .expect("code-map controller lock poisoned");
        if state.active.is_some() {
            bail!("A repository index operation is already running.");
        }
        state.next_revision = state
            .next_revision
            .checked_add(1)
            .context("code-map operation revision overflow")?;
        state.current_view = Some((state.next_revision, root.to_path_buf()));
        Ok(state.next_revision)
    }

    /// Authoritatively reserves this exact active operation for one core
    /// refresh.  This guard runs before the database path is passed to core,
    /// so a stale handle or a second clone cannot mutate any repository.
    fn claim_refresh_execution(&self, operation: &CodeMapOperation) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .expect("code-map controller lock poisoned");
        let active = state
            .active
            .as_mut()
            .context("repository index operation is no longer active")?;
        anyhow::ensure!(
            active.operation.revision == operation.revision
                && active.operation.root == operation.root,
            "repository index operation is stale for {}",
            operation.root.display()
        );
        anyhow::ensure!(
            active.execution == RefreshExecution::NotStarted,
            "repository index operation {} is already executing",
            operation.root.display()
        );
        active.execution = RefreshExecution::Running;
        Ok(())
    }

    /// Marks a claimed core invocation as terminal before its caller posts the
    /// receipt. A premature `finish` call sees `Running` and cannot release
    /// the operation slot while core still owns the repository work.
    fn mark_refresh_settled(&self, operation: &CodeMapOperation) {
        let mut state = self
            .state
            .lock()
            .expect("code-map controller lock poisoned");
        if let Some(active) = state.active.as_mut()
            && active.operation.revision == operation.revision
            && active.operation.root == operation.root
            && active.execution == RefreshExecution::Running
        {
            active.execution = RefreshExecution::Settled;
        }
    }

    /// Explicitly releases an operation whose worker was never started. The
    /// normal UI path does not need this because it starts the worker directly
    /// after `begin_refresh`; it is kept separate from `finish` so a clone
    /// cannot masquerade as a terminal core worker.
    #[cfg(test)]
    fn abandon_unstarted(&self, operation: &CodeMapOperation) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("code-map controller lock poisoned");
        let unstarted = state.active.as_ref().is_some_and(|active| {
            active.operation.revision == operation.revision
                && active.operation.root == operation.root
                && active.execution == RefreshExecution::NotStarted
        });
        if unstarted {
            state.active = None;
        }
        unstarted
    }
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize repository root {}", root.display()))?;
    anyhow::ensure!(
        root.is_dir(),
        "repository root is not a directory: {}",
        root.display()
    );
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::CodeMapLifecycleController;

    #[test]
    fn cancellation_keeps_the_operation_owned_until_its_worker_finishes() {
        let root = tempfile::tempdir().unwrap();
        let controller = CodeMapLifecycleController::new(root.path().join("code_map.db"));
        let operation = controller.begin_refresh(root.path()).unwrap();

        controller.claim_refresh_execution(&operation).unwrap();
        let cancelled = controller.request_cancel().expect("active operation");
        assert_eq!(cancelled.revision(), operation.revision());
        assert!(operation.is_cancelled());
        assert!(controller.has_active_refresh());
        assert!(controller.is_current(operation.revision(), operation.root()));
        assert!(
            !controller.finish(&operation),
            "only a settled core worker can release a running operation"
        );
        controller.mark_refresh_settled(&operation);
        assert!(controller.finish(&operation));
        assert!(!controller.is_current(operation.revision(), operation.root()));
        assert!(!controller.has_active_refresh());
    }

    #[test]
    fn old_completion_cannot_clear_a_newer_operation() {
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        let controller = CodeMapLifecycleController::new(first_root.path().join("code_map.db"));
        let first = controller.begin_refresh(first_root.path()).unwrap();
        assert!(controller.abandon_unstarted(&first));
        let second = controller.begin_refresh(second_root.path()).unwrap();

        assert!(!controller.finish(&first));
        assert!(controller.is_current(second.revision(), second.root()));
    }

    #[test]
    fn stale_operation_is_rejected_before_it_can_create_or_mutate_the_database() {
        let state = tempfile::tempdir().unwrap();
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        let database = state.path().join("code_map.db");
        let controller = CodeMapLifecycleController::new(database.clone());
        let stale = controller.begin_refresh(first_root.path()).unwrap();
        assert!(controller.abandon_unstarted(&stale));
        let current = controller.begin_refresh(second_root.path()).unwrap();

        let error = controller
            .refresh(&stale, neothd::code_map::LifecycleRefreshOptions::default())
            .expect_err("a finished operation must not reach core refresh");
        assert!(error.to_string().contains("stale"));
        assert!(
            !database.exists(),
            "the stale handle was rejected before core could create its database"
        );
        assert!(controller.is_current(current.revision(), current.root()));
    }

    #[test]
    fn only_one_clone_can_claim_execution_and_cancel_still_targets_the_current_operation() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("code_map.db");
        let controller = CodeMapLifecycleController::new(database.clone());
        let operation = controller.begin_refresh(root.path()).unwrap();
        let duplicate = operation.clone();

        controller.claim_refresh_execution(&operation).unwrap();
        let error = controller
            .refresh(
                &duplicate,
                neothd::code_map::LifecycleRefreshOptions::default(),
            )
            .expect_err("a second handle clone must not start another core refresh");
        assert!(error.to_string().contains("already executing"));
        assert!(
            !database.exists(),
            "the duplicate handle was rejected before core could create its database"
        );

        let cancelled = controller
            .request_cancel()
            .expect("current active operation");
        assert_eq!(cancelled.revision(), operation.revision());
        assert!(operation.is_cancelled());
        controller.mark_refresh_settled(&operation);
        assert!(controller.finish(&operation));
    }

    #[test]
    fn inspection_preserves_core_unmapped_state_for_an_unresolvable_root() {
        let home = tempfile::tempdir().unwrap();
        let controller = CodeMapLifecycleController::new(home.path().join("code_map.db"));
        let missing = home.path().join("does-not-exist");

        let (_, _, status) = controller.inspect(&missing).unwrap();
        assert!(matches!(
            status.state,
            neothd::code_map::CodeMapLifecycleState::Unmapped
        ));
    }

    #[test]
    fn later_inspection_invalidates_a_queued_refresh_receipt_view() {
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        let controller = CodeMapLifecycleController::new(first_root.path().join("code_map.db"));
        let refresh = controller.begin_refresh(first_root.path()).unwrap();
        assert!(controller.abandon_unstarted(&refresh));

        let (inspection_revision, inspection_root, _) =
            controller.inspect(second_root.path()).unwrap();
        assert!(controller.is_current_view(inspection_revision, &inspection_root));
        assert!(
            !controller.is_current_view(refresh.revision(), refresh.root()),
            "a queued older receipt must lose to the newer inspection view"
        );
    }
}
