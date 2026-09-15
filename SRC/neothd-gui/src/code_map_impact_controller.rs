//! Read-only GUI ownership for explicit Git diff impact and observed test evidence.
//!
//! This controller contains no Slint state, lifecycle refresh, or provider
//! call. It opens an existing code-map database read-only, binds one explicit
//! root and Git source to a revision, and fences late worker completion.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use neothd::code_map::{
    DiffImpactInput, DiffImpactReceipt, DiffImpactRequest, ImpactOptions, ImpactTestGapResult,
    TestCoverageOptions, analyze_diff_impact, test_gap_for_impact,
};

/// GUI-selectable Git source. No raw stdin diff is accepted by this surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeMapImpactSource {
    WorkingTree,
    Staged,
    Committed { base: String, target: String },
}

impl CodeMapImpactSource {
    pub fn from_form(kind: i32, base: &str, target: &str) -> Result<Self> {
        match kind {
            0 => Ok(Self::WorkingTree),
            1 => Ok(Self::Staged),
            2 => {
                let base = base.trim();
                let target = target.trim();
                ensure!(
                    !base.is_empty(),
                    "committed comparison requires a base revision"
                );
                ensure!(
                    !target.is_empty(),
                    "committed comparison requires a target revision"
                );
                Ok(Self::Committed {
                    base: base.to_owned(),
                    target: target.to_owned(),
                })
            }
            _ => bail!("unknown Git source selection"),
        }
    }

    fn to_core_input(&self) -> DiffImpactInput {
        match self {
            Self::WorkingTree => DiffImpactInput::working_tree(),
            Self::Staged => DiffImpactInput::staged(),
            Self::Committed { base, target } => {
                DiffImpactInput::committed(base.clone(), target.clone())
            }
        }
    }
}

/// One exact UI operation. requested_root is part of the view fence, while
/// root is the physical path passed to the typed core API.
#[derive(Clone, Debug)]
pub struct CodeMapImpactOperation {
    revision: u64,
    requested_root: PathBuf,
    root: PathBuf,
    source: CodeMapImpactSource,
}

impl CodeMapImpactOperation {
    pub fn source(&self) -> &CodeMapImpactSource {
        &self.source
    }
}

/// Typed core receipts are retained without text parsing so uncertainty, cap,
/// and no-absence facts remain available to the presentation layer.
#[derive(Clone, Debug)]
pub struct CodeMapImpactAnalysis {
    pub operation: CodeMapImpactOperation,
    pub impact: DiffImpactReceipt,
    pub test_gap: ImpactTestGapResult,
}

#[derive(Default)]
struct ControllerState {
    next_revision: u64,
    active: Option<ActiveOperation>,
    current_view: Option<CodeMapImpactOperation>,
}

struct ActiveOperation {
    operation: CodeMapImpactOperation,
    execution: ImpactExecution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImpactExecution {
    NotStarted,
    Running,
    Settled,
}

/// Terminal ownership outcome. A discarded worker was real work for the old
/// selection, but it is forbidden from repainting the current selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeMapImpactCompletion {
    Render,
    Discarded,
    Ignored,
}

/// Atomic result of a selected-root or Git-source mutation. Presentation
/// ownership and execution ownership are intentionally separate: a second
/// delayed picker can find no visible view while the first worker still owns
/// the read-only core request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeMapImpactViewInvalidation {
    pub view_invalidated: bool,
    pub analysis_active: bool,
}

/// One GUI process owns one read-only impact request at a time. There is no
/// cancellation control because the current core API has no cancellation token.
pub struct CodeMapImpactController {
    database_path: PathBuf,
    state: Mutex<ControllerState>,
}

impl CodeMapImpactController {
    pub fn new(database_path: PathBuf) -> Self {
        Self {
            database_path,
            state: Mutex::new(ControllerState::default()),
        }
    }

    pub fn begin(
        &self,
        requested_root: &Path,
        source: CodeMapImpactSource,
    ) -> Result<CodeMapImpactOperation> {
        let requested_root = requested_root.to_path_buf();
        let root = requested_root.canonicalize().with_context(|| {
            format!("canonicalize repository root {}", requested_root.display())
        })?;
        ensure!(
            root.is_dir(),
            "repository root is not a directory: {}",
            root.display()
        );

        let mut state = self.state.lock().expect("code-map impact lock poisoned");
        if let Some(active) = &state.active {
            bail!(
                "A change-impact analysis is already running for {}.",
                active.operation.root.display()
            );
        }
        state.next_revision = state
            .next_revision
            .checked_add(1)
            .context("code-map impact revision overflow")?;
        let operation = CodeMapImpactOperation {
            revision: state.next_revision,
            requested_root,
            root,
            source,
        };
        state.current_view = Some(operation.clone());
        state.active = Some(ActiveOperation {
            operation: operation.clone(),
            execution: ImpactExecution::NotStarted,
        });
        Ok(operation)
    }

    /// Executes public W43/W48 APIs through an ordinary SQLite read-only
    /// handle. It never creates a database, schema, migration, lifecycle
    /// refresh, or provider request. SQLite coordination may create sidecars.
    pub fn analyze(&self, operation: &CodeMapImpactOperation) -> Result<CodeMapImpactAnalysis> {
        self.claim_execution(operation)?;
        let result = (|| {
            ensure!(
                self.database_path.exists(),
                "code-map database is absent; inspect or set up the repository index first"
            );
            let metadata = std::fs::symlink_metadata(&self.database_path).with_context(|| {
                format!("inspect code-map database {}", self.database_path.display())
            })?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "code-map database is not a regular file"
            );
            let connection = rusqlite::Connection::open_with_flags(
                &self.database_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .with_context(|| {
                format!(
                    "open code-map database read-only {}",
                    self.database_path.display()
                )
            })?;
            connection
                .busy_timeout(Duration::from_millis(5_000))
                .context("set read-only code-map SQLite busy timeout")?;
            connection
                .pragma_update(None, "query_only", "ON")
                .context("enforce read-only code-map SQLite queries")?;

            let request = DiffImpactRequest {
                repo_root: operation.root.clone(),
                input: operation.source.to_core_input(),
                options: ImpactOptions::default(),
            };
            let impact = analyze_diff_impact(&connection, &request)?;
            ensure!(
                !impact.impact.stale,
                "repository index is stale; refresh it before analyzing change impact"
            );
            let test_gap =
                test_gap_for_impact(&connection, &impact.impact, TestCoverageOptions::default())?;
            Ok(CodeMapImpactAnalysis {
                operation: operation.clone(),
                impact,
                test_gap,
            })
        })();
        self.mark_settled(operation);
        result
    }

    /// Invalidates presentation ownership for every actual selected-root or
    /// source mutation. The currently running core read remains owned until it
    /// settles, but its terminal receipt becomes display-ineligible. Both
    /// facts are sampled under the same mutex so UI interlocks remain active
    /// across repeated delayed picker completions.
    pub fn invalidate_view(&self) -> CodeMapImpactViewInvalidation {
        let mut state = self.state.lock().expect("code-map impact lock poisoned");
        let view_invalidated = state.current_view.take().is_some();
        CodeMapImpactViewInvalidation {
            view_invalidated,
            analysis_active: state.active.is_some(),
        }
    }

    /// Releases only the exact settled worker and reports whether it may paint
    /// the current selection. An older completion cannot clear a newer worker.
    pub fn finish(&self, operation: &CodeMapImpactOperation) -> CodeMapImpactCompletion {
        let mut state = self.state.lock().expect("code-map impact lock poisoned");
        let owned = state.active.as_ref().is_some_and(|active| {
            same_operation(&active.operation, operation)
                && active.execution == ImpactExecution::Settled
        });
        if !owned {
            return CodeMapImpactCompletion::Ignored;
        }
        state.active = None;
        if state
            .current_view
            .as_ref()
            .is_some_and(|current| same_operation(current, operation))
        {
            CodeMapImpactCompletion::Render
        } else {
            CodeMapImpactCompletion::Discarded
        }
    }

    pub fn has_active_analysis(&self) -> bool {
        self.state
            .lock()
            .expect("code-map impact lock poisoned")
            .active
            .is_some()
    }

    /// Fences a queued receipt against the exact visible root and source.
    #[cfg(test)]
    pub fn is_current_view(
        &self,
        operation: &CodeMapImpactOperation,
        requested_root: &Path,
        source: &CodeMapImpactSource,
    ) -> bool {
        self.state
            .lock()
            .expect("code-map impact lock poisoned")
            .current_view
            .as_ref()
            .is_some_and(|current| {
                same_operation(current, operation)
                    && current.requested_root == requested_root
                    && &current.source == source
            })
    }

    fn claim_execution(&self, operation: &CodeMapImpactOperation) -> Result<()> {
        let mut state = self.state.lock().expect("code-map impact lock poisoned");
        let active = state
            .active
            .as_mut()
            .context("change-impact analysis is no longer active")?;
        ensure!(
            same_operation(&active.operation, operation)
                && active.execution == ImpactExecution::NotStarted,
            "change-impact analysis is already executing"
        );
        active.execution = ImpactExecution::Running;
        Ok(())
    }

    fn mark_settled(&self, operation: &CodeMapImpactOperation) {
        let mut state = self.state.lock().expect("code-map impact lock poisoned");
        if let Some(active) = state.active.as_mut()
            && same_operation(&active.operation, operation)
            && active.execution == ImpactExecution::Running
        {
            active.execution = ImpactExecution::Settled;
        }
    }
}

fn same_operation(left: &CodeMapImpactOperation, right: &CodeMapImpactOperation) -> bool {
    left.revision == right.revision
        && left.requested_root == right.requested_root
        && left.root == right.root
        && left.source == right.source
}

#[cfg(test)]
mod tests {
    use super::{
        CodeMapImpactCompletion, CodeMapImpactController, CodeMapImpactSource,
        CodeMapImpactViewInvalidation,
    };

    #[test]
    fn source_and_root_draft_changes_fence_a_late_completion() {
        let database_home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let controller = CodeMapImpactController::new(database_home.path().join("code_map.db"));
        let operation = controller
            .begin(repository.path(), CodeMapImpactSource::WorkingTree)
            .unwrap();

        assert!(controller.analyze(&operation).is_err());
        assert_eq!(
            controller.finish(&operation),
            CodeMapImpactCompletion::Render
        );
        assert!(!controller.is_current_view(
            &operation,
            repository.path(),
            &CodeMapImpactSource::Staged,
        ));
        assert!(!controller.is_current_view(
            &operation,
            &repository.path().join("changed-draft"),
            &CodeMapImpactSource::WorkingTree,
        ));
    }

    #[test]
    fn second_analysis_is_rejected_before_a_read_only_database_open() {
        let database_home = tempfile::tempdir().unwrap();
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        let database = database_home.path().join("code_map.db");
        let controller = CodeMapImpactController::new(database.clone());
        let first = controller
            .begin(first_root.path(), CodeMapImpactSource::WorkingTree)
            .unwrap();

        let error = controller
            .begin(second_root.path(), CodeMapImpactSource::Staged)
            .expect_err("second analysis must not enter core");
        assert!(error.to_string().contains("already running"));
        assert!(
            !database.exists(),
            "the controller did not create a database"
        );
        assert!(controller.analyze(&first).is_err());
        assert_eq!(controller.finish(&first), CodeMapImpactCompletion::Render);
    }

    #[test]
    fn committed_source_requires_both_explicit_revisions() {
        assert!(CodeMapImpactSource::from_form(2, "", "HEAD").is_err());
        assert!(CodeMapImpactSource::from_form(2, "HEAD~1", "").is_err());
        assert!(matches!(
            CodeMapImpactSource::from_form(2, "HEAD~1", "HEAD"),
            Ok(CodeMapImpactSource::Committed { .. })
        ));
    }

    #[test]
    fn root_picker_invalidation_discards_only_the_old_settled_completion() {
        let database_home = tempfile::tempdir().unwrap();
        let repository = tempfile::tempdir().unwrap();
        let controller = CodeMapImpactController::new(database_home.path().join("code_map.db"));
        let operation = controller
            .begin(repository.path(), CodeMapImpactSource::WorkingTree)
            .unwrap();

        assert_eq!(
            controller.invalidate_view(),
            CodeMapImpactViewInvalidation {
                view_invalidated: true,
                analysis_active: true,
            }
        );
        assert!(controller.analyze(&operation).is_err());
        assert_eq!(
            controller.finish(&operation),
            CodeMapImpactCompletion::Discarded
        );
        assert!(!controller.has_active_analysis());
    }
}
