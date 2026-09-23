//! Shared, process-local controller for one coding run.
//!
//! The CLI, desktop UI, and Buddy are consumers of this service rather than
//! independent orchestration paths.  This module deliberately owns run
//! lifetime, cancellation acknowledgement, progress delivery, and terminal
//! retention.  It never treats archive state as a cancellation result.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, broadcast, oneshot, watch};

use super::classifier::{Complexity, classify_heuristic};
use super::code_map_receipt::{CodingCodeMapResultEvidence, PreparedCodeMapContext};
use super::decomposer::{
    DecomposerLlm, DecompositionCancellation, DecompositionCancelled,
    decompose_with_code_map_context_cancellable,
};
use super::dispatcher::{ApplyConfirmation, ApplyOrigin, DispatchApplyConfig, HemisphereWorkerSet};
use super::store;
use super::types::{Hemisphere, KanbanSessionId, KanbanTaskId, SessionStatus};

const EVENT_SUBSCRIBER_CAPACITY: usize = 64;
const RETAINED_TERMINAL_RUNS: usize = 64;
const GUI_PATCH_APPROVAL_TTL: std::time::Duration = std::time::Duration::from_secs(120);
const GUI_PATCH_APPROVAL_MAX_CHANGED_FILES: usize = 64;
const GUI_PATCH_APPROVAL_MAX_FILE_LABEL_BYTES: usize = 512;

#[cfg(test)]
struct ApprovalPublicationPause {
    entered: AtomicBool,
    entered_notify: Notify,
    release: Notify,
    approval_id: std::sync::Mutex<Option<CodingPatchApprovalId>>,
}

#[cfg(test)]
impl ApprovalPublicationPause {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            entered_notify: Notify::new(),
            release: Notify::new(),
            approval_id: std::sync::Mutex::new(None),
        }
    }

    async fn wait_until_entered(&self) {
        loop {
            let notified = self.entered_notify.notified();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn approval_id(&self) -> CodingPatchApprovalId {
        self.approval_id
            .lock()
            .expect("test publication pause mutex poisoned")
            .expect("publication pause must receive an approval id before entering")
    }
}

/// Opaque identity for one local coding run. It is not a database row id and
/// must never be substituted for a [`KanbanSessionId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CodingRunId(u64);

impl CodingRunId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Opaque native-GUI identifier for one pending exact-patch decision.
///
/// This alias avoids giving the GUI crate a direct `uuid` dependency. It is
/// only an identifier: a matching live service-side broker entry remains the
/// authority for a response.
pub type CodingPatchApprovalId = uuid::Uuid;

/// Bounded display data for one pending native patch approval. This contains
/// no raw diff, prompt, provider output, or caller-supplied path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingPatchApprovalMetadata {
    pub approval_id: CodingPatchApprovalId,
    pub task_id: KanbanTaskId,
    pub repository_display: String,
    pub patch_sha256: String,
    pub request_binding_sha256: String,
    pub changed_files: Vec<String>,
    pub expires_unix: i64,
}

/// Result of consuming one native patch-approval response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchApprovalResponse {
    Accepted,
    Rejected,
    StaleOrUnknown,
    Expired,
}

/// Exact accepted diff available only while the matching approval remains
/// pending. Deliberately has no `Debug` or `Serialize` implementation.
pub struct CodingPatchApprovalPreview {
    pub metadata: CodingPatchApprovalMetadata,
    pub patch_text: String,
}

/// Read-only preview result. Deliberately has no `Debug` or `Serialize`
/// implementation because its available form contains raw accepted diff bytes.
pub enum PatchApprovalPreviewResult {
    Available(CodingPatchApprovalPreview),
    StaleOrUnknown,
    Expired,
}

/// Stable externally visible phase. A terminal result is carried separately so
/// a cancelled operation cannot be confused with an archived session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodingRunPhase {
    Queued,
    PreparingContext,
    PersistingReceipt,
    Decomposing,
    InsertingTasks,
    Assigning,
    Dispatching,
    Applying,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

impl CodingRunPhase {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// The durable/effectful boundary reached before a cancellation settled.
/// `NoEffect` is valid only when no provider dispatch was attempted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationEffect {
    NoEffect,
    SessionCreatedNoProvider,
    ProviderAttemptedUnknown,
    ProviderCompletedNoTasks,
    TasksInsertedUndispatched,
    DispatchEffects {
        completed_task_ids: Vec<i64>,
        applied_task_ids: Vec<i64>,
        blocked_task_ids: Vec<i64>,
        unassigned_task_ids: Vec<i64>,
    },
}

/// Provider observation retained for conservative cancellation reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCallState {
    NotAttempted,
    AttemptedUnknown,
    Completed,
}

/// Counts from a completed dispatch pass. Unlike prompt/provider material,
/// these are safe to show in every frontend's terminal status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingDispatchSummary {
    pub tasks_attempted: usize,
    pub tasks_completed: usize,
    pub tasks_blocked: usize,
    pub tasks_unassigned: usize,
    pub budget_exhausted: bool,
}

/// Immutable terminal receipt returned only after the owned worker settles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodingRunResult {
    Completed {
        run_id: CodingRunId,
        session_id: KanbanSessionId,
        task_count: usize,
        task_ids: Vec<KanbanTaskId>,
        clarifying_question: Option<String>,
        session_complexity: String,
        input_truncated: bool,
        /// Present only for an accepted decomposition that retained the exact
        /// prepared provider-input attempt used for that result.
        code_map_result_evidence: Option<CodingCodeMapResultEvidence>,
        dispatch: Option<CodingDispatchSummary>,
    },
    Cancelled {
        run_id: CodingRunId,
        session_id: Option<KanbanSessionId>,
        provider_state: ProviderCallState,
        effect: CancellationEffect,
    },
    Failed {
        run_id: CodingRunId,
        session_id: Option<KanbanSessionId>,
        message: String,
    },
}

impl CodingRunResult {
    pub const fn run_id(&self) -> CodingRunId {
        match self {
            Self::Completed { run_id, .. }
            | Self::Cancelled { run_id, .. }
            | Self::Failed { run_id, .. } => *run_id,
        }
    }
}

/// One snapshot is enough for a GUI/Buddy to render a stable operation card.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingRunSnapshot {
    pub run_id: CodingRunId,
    pub phase: CodingRunPhase,
    pub repository_root: PathBuf,
    pub session_id: Option<KanbanSessionId>,
    pub cancel_requested: bool,
    pub provider_state: ProviderCallState,
    pub task_count: usize,
    /// Authoritative recovery for a GUI that subscribes after the advisory
    /// event or whose bounded receiver lagged. It is metadata only.
    pub pending_patch_approval: Option<CodingPatchApprovalMetadata>,
    pub terminal: Option<CodingRunResult>,
}

/// Bounded progress stream. Every payload is local metadata/counts only; raw
/// prompts, assembled context, provider prompts, and provider replies do not
/// enter the event stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodingRunEvent {
    Phase(CodingRunPhase),
    SessionCreated {
        session_id: KanbanSessionId,
    },
    CodeMapContextPrepared,
    ReceiptRecorded {
        attempt: u8,
    },
    /// Advisory plan review could not complete; decomposition continues.
    PlanReviewUnavailable,
    TasksInserted {
        count: usize,
    },
    /// Advisory metadata-only notification for a pending exact-patch approval.
    /// The full patch is available only through `patch_approval_preview`.
    PatchApplyApprovalRequested(CodingPatchApprovalMetadata),
    CancelRequested,
    CancelAcknowledged {
        effect: CancellationEffect,
    },
    Terminal(CodingRunResult),
}

/// Cooperative cancellation shared with all service stages. Cancellation is a
/// request; callers must await the terminal receipt before claiming the run
/// stopped. The worker is responsible for joining an in-flight provider call
/// before publishing an `AttemptedUnknown` terminal state.
#[derive(Clone, Debug)]
pub struct CodingCancellation {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CodingCancellation {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn request(&self) -> bool {
        let changed = !self.cancelled.swap(true, Ordering::AcqRel);
        if changed {
            self.notify.notify_waiters();
        }
        changed
    }

    pub fn is_requested(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn ensure_not_requested(&self) -> Result<()> {
        ensure!(!self.is_requested(), "coding run cancellation requested");
        Ok(())
    }

    pub async fn cancelled(&self) {
        loop {
            if self.is_requested() {
                return;
            }
            self.notify.notified().await;
        }
    }
}

impl Default for CodingCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl DecompositionCancellation for CodingCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_requested()
    }
}

impl super::dispatcher::DispatchCancellation for CodingCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_requested()
    }

    fn effect_cancellation_probe(&self) -> Option<Arc<AtomicBool>> {
        Some(Arc::clone(&self.cancelled))
    }
}

/// Executor implemented by the real coding pipeline. It owns the provider and
/// opens any SQLite connection inside its task; a `rusqlite::Connection` never
/// crosses a spawned-thread boundary.
#[async_trait::async_trait(?Send)]
pub(crate) trait CodingRunWorker: 'static {
    async fn run(
        &self,
        request: CodingStartRequest,
        progress: CodingRunProgress,
        cancellation: CodingCancellation,
    ) -> CodingRunResult;
}

/// Common front-end request. A caller must choose a repository explicitly;
/// service code never consults process CWD for code-map or apply authority.
#[derive(Clone, Debug)]
pub struct CodingStartRequest {
    pub prompt: String,
    pub repository_root: PathBuf,
    pub source_channel: String,
    pub no_assign: bool,
    pub dispatch: bool,
    pub apply: bool,
    /// Set only by the local CLI command boundary after Clap parsed `--apply`.
    /// `source_channel` is display provenance and is never converted to this.
    apply_confirmation: ApplyConfirmation,
    /// Service-private immutable selection. The runtime constructs it from
    /// the explicit root immediately before session/provider work and retains
    /// it only until the decomposer records hash-only evidence.
    prepared_code_map_context: Option<PreparedCodeMapContext>,
    /// Optional CLI-selected diff source. It remains transient until the
    /// shared code-map preparation path validates and receipts it.
    diff_impact_input: Option<crate::code_map::diff_impact::DiffImpactInput>,
    brainstorm_spec: Option<crate::coding::brainstorm::BrainstormSpec>,
}

impl CodingStartRequest {
    /// Public, Send-safe frontend input. Context evidence is deliberately not
    /// caller-supplied: the service binds it to `repository_root` itself.
    pub fn new(
        prompt: String,
        repository_root: PathBuf,
        source_channel: String,
        no_assign: bool,
        dispatch: bool,
        apply: bool,
    ) -> Result<Self> {
        let request = Self {
            prompt,
            repository_root,
            source_channel,
            no_assign,
            dispatch,
            apply,
            apply_confirmation: ApplyConfirmation::Unattended,
            prepared_code_map_context: None,
            diff_impact_input: None,
            brainstorm_spec: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn with_local_cli_apply_confirmation(mut self) -> Self {
        self.apply_confirmation = ApplyConfirmation::LocalCliFlag;
        self
    }

    /// Route this run through the native interactive patch-approval flow.
    ///
    /// This is public because `neothd-gui` is a separate crate. It grants no
    /// authority: every accepted patch still requires a matching, live opaque
    /// approval from this run's broker immediately before the existing Gate.
    pub fn with_gui_apply_route(mut self) -> Self {
        self.apply_confirmation = ApplyConfirmation::GuiInteractive;
        self
    }

    pub(crate) fn with_prepared_code_map_context(
        mut self,
        prepared_code_map_context: Option<PreparedCodeMapContext>,
    ) -> Self {
        self.prepared_code_map_context = prepared_code_map_context;
        self
    }

    pub(crate) fn with_diff_impact_input(
        mut self,
        diff_impact_input: Option<crate::code_map::diff_impact::DiffImpactInput>,
    ) -> Self {
        self.diff_impact_input = diff_impact_input;
        self
    }

    pub(crate) fn with_brainstorm_spec(
        mut self,
        brainstorm_spec: Option<crate::coding::brainstorm::BrainstormSpec>,
    ) -> Self {
        self.brainstorm_spec = brainstorm_spec;
        self
    }
}

/// Real worker bindings and optional worktree apply authority for one run.
/// They are constructed and finalized only by the shared service runtime, so
/// CLI, GUI, and Buddy cannot create competing dispatch lifecycles.
pub(crate) struct CodingDispatchPlan {
    workers: HemisphereWorkerSet,
    apply_config: Option<DispatchApplyConfig>,
    audit: Option<(
        Arc<crate::wal::writer::WalWriterHandle>,
        tokio::task::JoinHandle<()>,
    )>,
}

impl CodingDispatchPlan {
    pub(crate) fn new(
        workers: HemisphereWorkerSet,
        apply_config: Option<DispatchApplyConfig>,
        audit: Option<(
            Arc<crate::wal::writer::WalWriterHandle>,
            tokio::task::JoinHandle<()>,
        )>,
    ) -> Self {
        Self {
            workers,
            apply_config,
            audit,
        }
    }

    async fn finalize(mut self) -> Result<()> {
        drop(self.apply_config.take());
        drop(self.workers);
        if let Some((writer, join)) = self.audit.take() {
            drop(writer);
            join.await
                .map_err(|error| anyhow::anyhow!("coding dispatch audit task panicked: {error}"))?;
        }
        Ok(())
    }
}

/// Build the real worker and audit bindings for one dispatching run.  This is
/// intentionally service-owned: the CLI is just another frontend and must not
/// retain a second provider/dispatch loop after starting a run.
async fn build_dispatch_plan(
    config: &crate::config::FreedomConfig,
    neoth_home: &std::path::Path,
    request: &CodingStartRequest,
    code_map_database_path: &std::path::Path,
) -> Result<CodingDispatchPlan> {
    use crate::coding::provider_worker::ProviderWorker;
    use crate::config::inference::HemisphereRole;

    // Establish the explicit physical root before starting provider/WAL
    // resources, so a bad apply root cannot leave a partial dispatch plan.
    let advisory_root = request
        .apply
        .then(|| crate::code_map::CanonicalRepoRoot::discover(&request.repository_root))
        .transpose()?;
    let audit = coding_audit_writer_for_home(neoth_home);
    let writer = audit.as_ref().map(|(writer, _)| Arc::clone(writer));
    // This snapshot was prepared from the canonical request root before any
    // worker/provider exists. Clone only the immutable value into each
    // hemisphere worker; no worker reopens the DB or consults process CWD.
    let prepared_worker_context = prepared_worker_context_for_dispatch(request);
    let mut workers = HemisphereWorkerSet::new();
    for (role, hemisphere, role_name) in [
        (HemisphereRole::Left, Hemisphere::Left, "left"),
        (HemisphereRole::Right, Hemisphere::Right, "right"),
        (
            HemisphereRole::Cerebellum,
            Hemisphere::Cerebellum,
            "cerebellum",
        ),
    ] {
        match crate::providers::from_config_for_role_at(config, role, neoth_home).await {
            Ok(provider) => {
                let provider_name = provider.name();
                let label = intern_worker_label(&format!("{role_name}/{provider_name}"));
                let default_model =
                    crate::providers::provider_default_wire_model(provider.as_ref());
                let model_name = default_model.clone().unwrap_or_default();
                let authorizer =
                    crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
                        config.autonomy_policy(),
                        writer.as_ref().map(|writer| writer.as_ref().clone()),
                        config.tokens.max_per_request,
                    )
                    .with_usage_home(neoth_home.to_path_buf());
                let authorizer = coding_role_authorizer(authorizer, config, role)?;
                let provider = Arc::new(
                    crate::providers::cost_authorization::AuthorizedProvider::from_box(
                        provider,
                        authorizer,
                        default_model,
                        "coding.worker",
                    ),
                );
                workers.bind(
                    hemisphere,
                    Box::new(ProviderWorker::new(
                        label,
                        provider,
                        model_name,
                        prepared_worker_context.clone(),
                        neoth_home.to_path_buf(),
                    )),
                );
            }
            Err(error) => {
                tracing::warn!(
                    hemisphere = hemisphere.as_str(),
                    error = %error,
                    "coding dispatch hemisphere is unbound; its tasks will block"
                );
            }
        }
    }

    let apply_config = if request.apply {
        let origin = match request.apply_confirmation {
            ApplyConfirmation::LocalCliFlag => ApplyOrigin::CliConfirmed,
            ApplyConfirmation::GuiInteractive => ApplyOrigin::GuiRequested,
            // This value is only provenance.  A free-form source label never
            // becomes local authority or a trust-ledger subject.
            ApplyConfirmation::Unattended => ApplyOrigin::ChannelRequested,
        };
        let mut apply = DispatchApplyConfig::new(&request.repository_root, origin)
            .with_policy(config.autonomy_policy());
        // This is an explicit service dependency, not a dispatcher default or
        // CWD lookup. The read-only open happens only after patch admission;
        // an absent/stale DB becomes an advisory receipt, never an apply gate.
        apply = apply.with_pre_apply_impact_advisory(
            code_map_database_path,
            advisory_root.expect("apply dispatch has an advisory root"),
            config.code_map.impact_policy.impact_options(),
        );
        if request.apply_confirmation == ApplyConfirmation::LocalCliFlag {
            apply = apply.with_local_cli_confirmation();
        } else if request.apply_confirmation == ApplyConfirmation::GuiInteractive {
            apply = apply.with_gui_interactive_confirmation();
        }
        if let Some(writer) = writer.as_ref() {
            apply = apply.with_wal_writer(Arc::clone(writer));
        }
        if let Some(command) = config.coding.test_cmd.as_deref() {
            apply = apply
                .with_test_cmd(command)
                .with_test_timeout(std::time::Duration::from_secs(
                    config.coding.test_timeout_secs,
                ));
        }
        Some(apply)
    } else {
        None
    };
    Ok(CodingDispatchPlan::new(workers, apply_config, audit))
}

fn prepared_worker_context_for_dispatch(
    request: &CodingStartRequest,
) -> Option<PreparedCodeMapContext> {
    request.prepared_code_map_context.clone()
}

fn coding_audit_writer_for_home(
    neoth_home: &std::path::Path,
) -> Option<(
    Arc<crate::wal::writer::WalWriterHandle>,
    tokio::task::JoinHandle<()>,
)> {
    let wal_dir = neoth_home.join("wal");
    std::fs::create_dir_all(&wal_dir).ok()?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "code");
    match crate::wal::writer::spawn_for_home(segment, neoth_home.to_path_buf()) {
        Ok((writer, join)) => Some((Arc::new(writer), join)),
        Err(error) => {
            tracing::warn!(error = %error, "coding dispatch audit writer could not start");
            None
        }
    }
}

/// A prepared, counts-only summary that cannot become durable until the outer
/// provider audit has also finalized the run as completed.
struct DispatchSummaryCandidate {
    queue_path: PathBuf,
    item: crate::proactive::ProactiveItem,
}

fn prepare_dispatch_summary(
    queue_path: &std::path::Path,
    outcome: &super::dispatcher::DispatchOutcome,
    session_id: KanbanSessionId,
) -> DispatchSummaryCandidate {
    DispatchSummaryCandidate {
        queue_path: queue_path.to_path_buf(),
        item: super::feed::build_session_summary_item(outcome, session_id.raw()),
    }
}

/// Commit a summary only after every relevant finalizer reports the same
/// completed result. This remains best-effort: durable task effects are
/// authoritative when the notification queue is unavailable.
fn commit_dispatch_summary(candidate: DispatchSummaryCandidate) {
    if let Err(error) =
        crate::proactive::ProactiveQueue::enqueue_at(&candidate.queue_path, candidate.item)
    {
        tracing::warn!(error = %error, "session-summary: proactive queue transaction failed");
    }
}

fn commit_dispatch_summary_for_terminal(
    result: &CodingRunResult,
    candidate: Option<DispatchSummaryCandidate>,
) {
    if matches!(result, CodingRunResult::Completed { .. })
        && let Some(candidate) = candidate
    {
        commit_dispatch_summary(candidate);
    }
}

fn intern_worker_label(label: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex as StdMutex, OnceLock};

    static LABELS: OnceLock<StdMutex<HashSet<&'static str>>> = OnceLock::new();
    let labels = LABELS.get_or_init(|| StdMutex::new(HashSet::new()));
    let mut labels = labels
        .lock()
        .expect("coding worker label interner poisoned");
    if let Some(existing) = labels.get(label) {
        return existing;
    }
    let leaked = Box::leak(label.to_owned().into_boxed_str());
    labels.insert(leaked);
    leaked
}

/// The durable, provider-facing half of the native coding runtime.
///
/// It opens its SQLite connection inside the LocalSet worker, creates the
/// session, records code-map evidence through the existing decomposer before
/// the provider call, classifies tasks, and owns optional dispatch/apply until
/// a terminal outcome. The caller only supplies real provider bindings; it
/// does not run a second orchestration loop after this worker returns.
pub(crate) struct StoredDecompositionWorker {
    db_path: PathBuf,
    operator_id: Option<String>,
    llm: Arc<dyn DecomposerLlm>,
    dispatch_plan: std::sync::Mutex<Option<CodingDispatchPlan>>,
    plan_review: Option<PathBuf>,
    proactive_queue_path: Option<PathBuf>,
    proactive_summary: std::sync::Mutex<Option<DispatchSummaryCandidate>>,
}

impl StoredDecompositionWorker {
    pub(crate) fn new(
        db_path: PathBuf,
        operator_id: Option<String>,
        llm: Arc<dyn DecomposerLlm>,
    ) -> Self {
        Self {
            db_path,
            operator_id,
            llm,
            dispatch_plan: std::sync::Mutex::new(None),
            plan_review: None,
            proactive_queue_path: None,
            proactive_summary: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn with_dispatch_plan(self, dispatch_plan: CodingDispatchPlan) -> Self {
        *self
            .dispatch_plan
            .lock()
            .expect("coding dispatch plan mutex poisoned") = Some(dispatch_plan);
        self
    }

    pub(crate) fn with_plan_review(mut self, neoth_home: PathBuf) -> Self {
        self.plan_review = Some(neoth_home);
        self
    }

    pub(crate) fn with_proactive_queue(mut self, queue_path: PathBuf) -> Self {
        self.proactive_queue_path = Some(queue_path);
        self
    }

    fn take_proactive_summary(&self) -> Option<DispatchSummaryCandidate> {
        self.proactive_summary
            .lock()
            .expect("coding proactive summary mutex poisoned")
            .take()
    }

    /// A run cancelled before dispatch still owns a one-shot worker/audit
    /// graph. Drain it here rather than dropping the JoinHandle, so terminal
    /// cancellation never races detached audit writes.
    async fn finalize_unused_dispatch_plan(&self) -> Result<()> {
        let plan = self
            .dispatch_plan
            .lock()
            .expect("coding dispatch plan mutex poisoned")
            .take();
        if let Some(plan) = plan {
            plan.finalize().await?;
        }
        Ok(())
    }

    async fn cancelled(
        &self,
        progress: &CodingRunProgress,
        session_id: Option<KanbanSessionId>,
        provider_state: ProviderCallState,
        effect: CancellationEffect,
    ) -> CodingRunResult {
        CodingRunResult::Cancelled {
            run_id: progress.run_id().await,
            session_id,
            provider_state,
            effect,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl CodingRunWorker for StoredDecompositionWorker {
    async fn run(
        &self,
        request: CodingStartRequest,
        progress: CodingRunProgress,
        cancellation: CodingCancellation,
    ) -> CodingRunResult {
        progress.set_phase(CodingRunPhase::PreparingContext).await;
        if cancellation.is_requested() {
            return self
                .cancelled(
                    &progress,
                    None,
                    ProviderCallState::NotAttempted,
                    CancellationEffect::NoEffect,
                )
                .await;
        }

        let conn = match crate::memory::store::open(&self.db_path)
            .and_then(|conn| store::ensure_schema(&conn).map(|()| conn))
        {
            Ok(conn) => conn,
            Err(error) => {
                return CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: None,
                    message: redact_error(&error),
                };
            }
        };
        let prompt_hash = format!(
            "{:016x}",
            xxhash_rust::xxh3::xxh3_64(request.prompt.as_bytes())
        );
        let session_id = match store::insert_session(
            &conn,
            crate::time::now_unix_ns(),
            &request.prompt,
            &prompt_hash,
            &request.source_channel,
            self.operator_id.as_deref(),
        ) {
            Ok(session_id) => session_id,
            Err(error) => {
                return CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: None,
                    message: redact_error(&error),
                };
            }
        };
        progress.session_created(session_id).await;
        progress.context_prepared().await;
        if cancellation.is_requested() {
            return self
                .cancelled(
                    &progress,
                    Some(session_id),
                    ProviderCallState::NotAttempted,
                    CancellationEffect::SessionCreatedNoProvider,
                )
                .await;
        }

        // `decompose_with_code_map_context` performs prompt validation and
        // receipt persistence synchronously before its first provider await.
        // A cancellation waits for this LocalSet future to settle instead of
        // dropping a live provider future.  Do not pre-label the snapshot as
        // attempted here: receipt persistence and the explicit pre-provider
        // checkpoint can still return a truthful no-provider cancellation.
        progress.set_phase(CodingRunPhase::PersistingReceipt).await;
        progress.set_phase(CodingRunPhase::Decomposing).await;
        let decomposed = decompose_with_code_map_context_cancellable(
            self.llm.as_ref(),
            &conn,
            session_id,
            &request.prompt,
            request.prepared_code_map_context.as_ref(),
            crate::time::now_unix_ns(),
            &cancellation,
        )
        .await;
        let result = match decomposed {
            Ok(result) => result,
            Err(error) if cancellation.is_requested() => {
                let (provider_state, effect) = match error.downcast_ref::<DecompositionCancelled>()
                {
                    Some(DecompositionCancelled::BeforeProvider) => (
                        ProviderCallState::NotAttempted,
                        CancellationEffect::SessionCreatedNoProvider,
                    ),
                    Some(DecompositionCancelled::BeforeTaskInsertion) => (
                        ProviderCallState::Completed,
                        CancellationEffect::ProviderCompletedNoTasks,
                    ),
                    None => (
                        ProviderCallState::AttemptedUnknown,
                        CancellationEffect::ProviderAttemptedUnknown,
                    ),
                };
                return self
                    .cancelled(&progress, Some(session_id), provider_state, effect)
                    .await;
            }
            Err(error) => {
                return CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: Some(session_id),
                    message: redact_error(&error),
                };
            }
        };
        progress.provider_state(ProviderCallState::Completed).await;
        if cancellation.is_requested() {
            return self
                .cancelled(
                    &progress,
                    Some(session_id),
                    ProviderCallState::Completed,
                    CancellationEffect::ProviderCompletedNoTasks,
                )
                .await;
        }
        progress.set_phase(CodingRunPhase::InsertingTasks).await;
        progress.tasks_inserted(result.task_ids.len()).await;
        if result.task_ids.is_empty() {
            // Match the established CLI lifecycle: a provider request that
            // yields only a clarifying question remains inspectable but does
            // not strand a Planning session or enter assignment/dispatch.
            if let Err(error) = store::archive_session(
                &conn,
                session_id,
                SessionStatus::Abandoned,
                result
                    .clarifying_question
                    .as_deref()
                    .or(Some("decomposer produced no tasks")),
                None,
            ) {
                return CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: Some(session_id),
                    message: redact_error(&error),
                };
            }
            return CodingRunResult::Completed {
                run_id: progress.run_id().await,
                session_id,
                task_count: 0,
                task_ids: Vec::new(),
                clarifying_question: result.clarifying_question,
                session_complexity: result.session_complexity.as_str().to_owned(),
                input_truncated: result.input_truncated,
                code_map_result_evidence: result.code_map_result_evidence,
                dispatch: None,
            };
        }
        if cancellation.is_requested() {
            return self
                .cancelled(
                    &progress,
                    Some(session_id),
                    ProviderCallState::Completed,
                    CancellationEffect::TasksInsertedUndispatched,
                )
                .await;
        }
        if let Some(neoth_home) = self.plan_review.as_ref()
            && let Err(error) = review_plan_for_service(
                &conn,
                session_id,
                &result,
                &request.prompt,
                request.brainstorm_spec.as_ref(),
                self.llm.as_ref(),
                neoth_home,
                &cancellation,
            )
            .await
        {
            if cancellation.is_requested() {
                return self
                    .cancelled(
                        &progress,
                        Some(session_id),
                        ProviderCallState::AttemptedUnknown,
                        CancellationEffect::TasksInsertedUndispatched,
                    )
                    .await;
            }
            tracing::warn!(error = %error, "coding plan review unavailable; continuing");
            let _ = progress
                .state
                .events
                .send(CodingRunEvent::PlanReviewUnavailable);
        }
        if !request.no_assign {
            progress.set_phase(CodingRunPhase::Assigning).await;
            if let Err(error) =
                classify_and_assign(&conn, &result.task_ids, self.llm.as_ref(), &cancellation).await
            {
                if cancellation.is_requested() {
                    return self
                        .cancelled(
                            &progress,
                            Some(session_id),
                            ProviderCallState::Completed,
                            CancellationEffect::TasksInsertedUndispatched,
                        )
                        .await;
                }
                return CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: Some(session_id),
                    message: redact_error(&error),
                };
            }
        }
        if cancellation.is_requested() {
            return self
                .cancelled(
                    &progress,
                    Some(session_id),
                    ProviderCallState::Completed,
                    CancellationEffect::TasksInsertedUndispatched,
                )
                .await;
        }

        let dispatch = if request.dispatch {
            let Some(mut dispatch_plan) = self
                .dispatch_plan
                .lock()
                .expect("coding dispatch plan mutex poisoned")
                .take()
            else {
                return CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: Some(session_id),
                    message: "coding dispatch bindings were not prepared".to_owned(),
                };
            };
            progress.set_phase(CodingRunPhase::Dispatching).await;
            if dispatch_plan.apply_config.is_some() {
                progress.set_phase(CodingRunPhase::Applying).await;
            }
            if request.apply_confirmation == ApplyConfirmation::GuiInteractive
                && let Some(apply_config) = dispatch_plan.apply_config.as_mut()
            {
                // A dispatch plan is prepared before a RunState exists. Attach
                // this run's private broker only at the final service-owned
                // dispatch boundary; route metadata alone never authorizes it.
                apply_config.attach_gui_patch_approval_broker(progress.gui_patch_approval_broker());
            }
            // This checked call is added by the companion integration patch.
            // It returns a durable per-task effect receipt on cancellation,
            // rather than leaking an aggregate-only DispatchOutcome.
            let dispatch_result = super::dispatcher::dispatch_session_with_apply_cancellable(
                &conn,
                session_id,
                &dispatch_plan.workers,
                super::dispatcher::DispatchBudget::default(),
                dispatch_plan.apply_config.as_ref(),
                &cancellation,
            )
            .await;
            // The WAL task is part of the durable dispatch boundary.  Drain it
            // before publishing either success or cancellation, so a returned
            // effect receipt cannot race a still-writing audit task.
            let audit_result = dispatch_plan.finalize().await;
            if let Err(error) = audit_result {
                return CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: Some(session_id),
                    message: redact_error(&error),
                };
            }
            match dispatch_result {
                Ok(super::dispatcher::CancellableDispatchOutcome::Completed(outcome)) => {
                    if let Some(queue_path) = self.proactive_queue_path.as_deref() {
                        *self
                            .proactive_summary
                            .lock()
                            .expect("coding proactive summary mutex poisoned") =
                            Some(prepare_dispatch_summary(queue_path, &outcome, session_id));
                    }
                    Some(CodingDispatchSummary {
                        tasks_attempted: outcome.tasks_attempted,
                        tasks_completed: outcome.tasks_completed,
                        tasks_blocked: outcome.tasks_blocked,
                        tasks_unassigned: outcome.tasks_unassigned,
                        budget_exhausted: outcome.budget_exhausted,
                    })
                }
                Ok(super::dispatcher::CancellableDispatchOutcome::Cancelled(effect)) => {
                    return self
                        .cancelled(
                            &progress,
                            Some(session_id),
                            ProviderCallState::Completed,
                            CancellationEffect::DispatchEffects {
                                completed_task_ids: effect.completed_task_ids,
                                applied_task_ids: effect.applied_task_ids,
                                blocked_task_ids: effect.blocked_task_ids,
                                unassigned_task_ids: effect.unassigned_task_ids,
                            },
                        )
                        .await;
                }
                Err(error) => {
                    return CodingRunResult::Failed {
                        run_id: progress.run_id().await,
                        session_id: Some(session_id),
                        message: redact_error(&error),
                    };
                }
            }
        } else {
            None
        };
        CodingRunResult::Completed {
            run_id: progress.run_id().await,
            session_id,
            task_count: result.task_ids.len(),
            task_ids: result.task_ids,
            clarifying_question: result.clarifying_question,
            session_complexity: result.session_complexity.as_str().to_owned(),
            input_truncated: result.input_truncated,
            code_map_result_evidence: result.code_map_result_evidence,
            dispatch,
        }
    }
}

/// Owns the one-shot provider audit and its exact provider graph until every
/// decomposer/classifier request has settled. This wrapper is the runtime
/// controller's production worker; its terminal result is not published until
/// the audit writer has been finalized.
pub(crate) struct AuditedCodingWorker {
    inner: std::sync::Mutex<Option<StoredDecompositionWorker>>,
    audit: std::sync::Mutex<Option<crate::providers::cost_authorization::ProviderCallOneShot>>,
    provider_owner:
        std::sync::Mutex<Option<Arc<crate::coding::cerebellum_provider::CerebellumDecomposer>>>,
}

impl AuditedCodingWorker {
    pub(crate) fn new(
        inner: StoredDecompositionWorker,
        audit: crate::providers::cost_authorization::ProviderCallOneShot,
        provider_owner: Arc<crate::coding::cerebellum_provider::CerebellumDecomposer>,
    ) -> Self {
        Self {
            inner: std::sync::Mutex::new(Some(inner)),
            audit: std::sync::Mutex::new(Some(audit)),
            provider_owner: std::sync::Mutex::new(Some(provider_owner)),
        }
    }
}

/// Construct the real Cerebellum provider/audit graph on the controller's
/// owned runtime thread. The returned worker owns the graph through terminal
/// audit finalization; no frontend ever receives either value.
pub(crate) async fn build_audited_worker(
    config: &crate::config::FreedomConfig,
    neoth_home: &std::path::Path,
    db_path: PathBuf,
    dispatch_plan: Option<CodingDispatchPlan>,
) -> Result<AuditedCodingWorker> {
    let provider = crate::providers::from_config_for_role_at(
        config,
        crate::config::inference::HemisphereRole::Cerebellum,
        neoth_home,
    )
    .await?;
    let default_model = crate::providers::provider_default_wire_model(provider.as_ref());
    let audit =
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot_at_home(
            config.autonomy_policy(),
            neoth_home,
            config.tokens.max_per_request,
        )
        .await?;
    let authorizer = coding_role_authorizer(
        audit.authorizer(),
        config,
        crate::config::inference::HemisphereRole::Cerebellum,
    )?;
    let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
        provider,
        authorizer,
        default_model,
        "coding.decomposer",
    );
    let owner = Arc::new(crate::coding::cerebellum_provider::CerebellumDecomposer::new(provider));
    let llm: Arc<dyn DecomposerLlm> = owner.clone();
    let worker = StoredDecompositionWorker::new(db_path, config.operator_id.clone(), llm);
    let worker = if config.coding.plan_review {
        worker.with_plan_review(neoth_home.to_path_buf())
    } else {
        worker
    };
    let worker = if config.proactive.enabled {
        worker.with_proactive_queue(neoth_home.join("proactive_queue.json"))
    } else {
        worker
    };
    let worker = match dispatch_plan {
        Some(dispatch_plan) => worker.with_dispatch_plan(dispatch_plan),
        None => worker,
    };
    Ok(AuditedCodingWorker::new(worker, audit, owner))
}

/// Bind the role already selected by a coding worker factory.  The fixed
/// config snapshot deliberately matches the provider topology for this run;
/// coding workers are not daemon-live provider routes.
fn coding_role_authorizer(
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    config: &crate::config::FreedomConfig,
    role: crate::config::inference::HemisphereRole,
) -> Result<crate::providers::cost_authorization::ProviderCallAuthorizer> {
    let provider = config
        .inference
        .slot_for(role)
        .provider
        .or_else(|| config.provider_kind.map(|kind| kind.to_inference()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "coding role `{}` has no configured provider identity",
                role.as_str()
            )
        })?;
    Ok(authorizer.with_role_dispatch(role, provider, Arc::new(config.clone())))
}

#[async_trait::async_trait(?Send)]
impl CodingRunWorker for AuditedCodingWorker {
    async fn run(
        &self,
        request: CodingStartRequest,
        progress: CodingRunProgress,
        cancellation: CodingCancellation,
    ) -> CodingRunResult {
        let inner = {
            self.inner
                .lock()
                .expect("audited coding worker mutex poisoned")
                .take()
        };
        let inner = match inner {
            Some(inner) => inner,
            None => {
                return CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: progress.snapshot().await.session_id,
                    message: "coding worker was started more than once".to_owned(),
                };
            }
        };
        let result = match futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(
            inner.run(request, progress.clone(), cancellation),
        ))
        .await
        {
            Ok(result) => result,
            Err(_) => CodingRunResult::Failed {
                run_id: progress.run_id().await,
                session_id: progress.snapshot().await.session_id,
                message: "coding worker panicked; inspect scoped local diagnostics".to_owned(),
            },
        };
        let dispatch_audit = inner.finalize_unused_dispatch_plan().await;
        let proactive_summary = inner.take_proactive_summary();
        drop(inner);
        let audit = self
            .audit
            .lock()
            .expect("coding provider audit mutex poisoned")
            .take();
        let owner = self
            .provider_owner
            .lock()
            .expect("coding provider owner mutex poisoned")
            .take();
        match (audit, owner) {
            (Some(audit), Some(owner)) => match audit.finish(owner).await {
                Ok(()) => match dispatch_audit {
                    Ok(()) => {
                        commit_dispatch_summary_for_terminal(&result, proactive_summary);
                        result
                    }
                    Err(error) => CodingRunResult::Failed {
                        run_id: progress.run_id().await,
                        session_id: progress.snapshot().await.session_id,
                        message: redact_error(&error),
                    },
                },
                Err(error) => CodingRunResult::Failed {
                    run_id: progress.run_id().await,
                    session_id: progress.snapshot().await.session_id,
                    message: redact_error(&error),
                },
            },
            _ => CodingRunResult::Failed {
                run_id: progress.run_id().await,
                session_id: progress.snapshot().await.session_id,
                message: "coding provider audit ownership was lost".to_owned(),
            },
        }
    }
}

async fn classify_and_assign(
    conn: &rusqlite::Connection,
    task_ids: &[KanbanTaskId],
    llm: &dyn DecomposerLlm,
    cancellation: &CodingCancellation,
) -> Result<()> {
    let wanted = task_ids
        .iter()
        .map(|id| id.raw())
        .collect::<std::collections::HashSet<_>>();
    let session_id = conn
        .query_row(
            "SELECT session_id FROM idx_kanban_task WHERE task_id = ?1",
            [task_ids.first().map_or(0, |task_id| task_id.raw())],
            |row| row.get::<_, i64>(0),
        )
        .map(KanbanSessionId)?;
    for task in store::list_tasks_for_session(conn, session_id)?
        .into_iter()
        .filter(|task| wanted.contains(&task.task_id.raw()))
    {
        cancellation.ensure_not_requested()?;
        let complexity = match classify_heuristic(&task) {
            complexity @ (Complexity::Fast | Complexity::Deep) => complexity,
            Complexity::Ambiguous => {
                let verdict =
                    crate::coding::second_opinion::second_opinion_classify(llm, &task).await;
                cancellation.ensure_not_requested()?;
                verdict
            }
        };
        cancellation.ensure_not_requested()?;
        store::patch_task_hemisphere(conn, task.task_id, complexity.to_hemisphere(), None, None)?;
    }
    Ok(())
}

async fn review_plan_for_service(
    conn: &rusqlite::Connection,
    session_id: KanbanSessionId,
    result: &super::decomposer::DecompositionResult,
    prompt: &str,
    spec: Option<&crate::coding::brainstorm::BrainstormSpec>,
    llm: &dyn DecomposerLlm,
    neoth_home: &std::path::Path,
    cancellation: &CodingCancellation,
) -> Result<()> {
    cancellation.ensure_not_requested()?;
    use std::fmt::Write as _;
    let mut plan = format!("# Plan under review\n\n## Operator request\n{prompt}\n");
    if let Some(spec) = spec {
        let _ = writeln!(plan, "## Problem\n{}\n", spec.problem);
        let _ = writeln!(plan, "## Solution\n{}\n", spec.solution);
        let _ = writeln!(plan, "## Out-of-Scope\n{}\n", spec.out_of_scope.join("\n"));
    }
    plan.push_str("## Decomposed tasks\n");
    for task in store::list_tasks_for_session(conn, session_id)?
        .into_iter()
        .filter(|task| result.task_ids.contains(&task.task_id))
    {
        let _ = writeln!(
            plan,
            "- [{}] {} ({})",
            task.task_id.raw(),
            task.title,
            task.task_type
        );
        if let Some(description) = task.description {
            let _ = writeln!(plan, "  {description}");
        }
    }
    let receipts = store::load_code_map_receipts(conn, session_id)?;
    if let Some(receipt) = receipts.last() {
        let _ = writeln!(
            plan,
            "\n## Code-map input evidence\nPrepared input attempt {}; context SHA-256 {}; context truncated: {}.",
            receipt.attempt, receipt.submitted_context_sha256, receipt.context_truncated
        );
        for source in &receipt.sources {
            let _ = writeln!(
                plan,
                "- {:?}: index/graph generation {}/{}; {} selected files, {} caller edges (selection before input truncation).",
                source.kind,
                source.index_generation,
                source.graph_generation,
                source.selected_files.len(),
                source.callers.len()
            );
        }
    }
    // Keep the same delimiter hardening as the legacy renderer before the
    // plan-review envelope performs its own sanitisation.
    let plan = plan.replace("</", "<\u{200B}/");
    let outcome = crate::coding::plan_review::review_plan(llm, &plan).await?;
    cancellation.ensure_not_requested()?;
    let path = neoth_home.join(format!("plan_review_log_{}.json", session_id.raw()));
    if let Ok(json) = outcome.log().to_json() {
        let _ = std::fs::write(path, json);
    }
    Ok(())
}

fn redact_error(_error: &anyhow::Error) -> String {
    // Provider and SQLite errors can embed request URLs, provider replies, or
    // operator-derived input. The service event/result stream is observable by
    // every front end, so keep it deliberately diagnostic-free; the durable
    // provider audit and scoped database inspection retain the authorized
    // failure evidence.
    "coding operation failed; inspect scoped local diagnostics".to_owned()
}

impl CodingStartRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.prompt.trim().is_empty(),
            "coding prompt must not be empty"
        );
        ensure!(
            self.repository_root.is_absolute(),
            "coding repository root must be absolute"
        );
        ensure!(
            !self.source_channel.trim().is_empty() && self.source_channel.len() <= 64,
            "coding source channel must be a bounded non-empty label"
        );
        ensure!(
            !self.apply || self.dispatch,
            "apply requires dispatch in a fresh coding run"
        );
        Ok(())
    }
}

enum GuiPatchApprovalDecision {
    Approved(GuiPatchApprovalGrant),
    Rejected,
    Expired,
    Cancelled,
}

struct PendingGuiPatchApproval {
    metadata: CodingPatchApprovalMetadata,
    repository_identity: String,
    patch_sha256: [u8; 32],
    patch_text: String,
    expires_at: tokio::time::Instant,
    response: oneshot::Sender<GuiPatchApprovalDecision>,
}

/// Private per-run capability installed into the dispatcher only for a native
/// GUI-routed run. A caller cannot construct a grant from an approval id or a
/// display label.
#[derive(Clone)]
pub(crate) struct GuiPatchApprovalBroker {
    state: std::sync::Weak<RunState>,
    pending: Arc<Mutex<Option<PendingGuiPatchApproval>>>,
    #[cfg(test)]
    publication_pause: Option<Arc<ApprovalPublicationPause>>,
    #[cfg(test)]
    test_keepalive: Option<Arc<RunState>>,
}

/// Private, non-cloneable proof returned only after the broker consumed a
/// matching accepted response. It is checked again at the Gate boundary.
pub(crate) struct GuiPatchApprovalGrant {
    repository_identity: String,
    task_id: KanbanTaskId,
    patch_sha256: [u8; 32],
    request_binding_sha256: String,
    state: std::sync::Weak<RunState>,
}

impl GuiPatchApprovalGrant {
    pub(crate) fn matches(
        &self,
        repository_identity: &str,
        task_id: KanbanTaskId,
        patch_sha256: &[u8; 32],
        request_binding_sha256: &str,
    ) -> bool {
        self.repository_identity == repository_identity
            && self.task_id == task_id
            && self.patch_sha256 == *patch_sha256
            && self.request_binding_sha256 == request_binding_sha256
    }

    /// Recheck cancellation immediately before the dispatcher enters the
    /// durable Gate. This closes the accept/cancel handoff without trying to
    /// erase a decision that the Gate has already admitted.
    pub(crate) fn ensure_active(&self) -> std::result::Result<(), String> {
        let state = self
            .state
            .upgrade()
            .ok_or_else(|| "native patch approval run is no longer live".to_owned())?;
        if state.cancellation.is_requested() {
            return Err("native patch approval cancelled".to_owned());
        }
        Ok(())
    }
}

impl GuiPatchApprovalBroker {
    fn new(state: std::sync::Weak<RunState>) -> Self {
        Self {
            state,
            pending: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            publication_pause: None,
            #[cfg(test)]
            test_keepalive: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_dispatch_test() -> (Self, CodingCancellation) {
        let cancellation = CodingCancellation::new();
        let (events, _) = broadcast::channel(EVENT_SUBSCRIBER_CAPACITY);
        let (terminal, _) = watch::channel(None);
        let state = Arc::new_cyclic(|weak| RunState {
            snapshot: Mutex::new(CodingRunSnapshot {
                run_id: CodingRunId(92),
                phase: CodingRunPhase::Applying,
                repository_root: std::env::temp_dir(),
                session_id: None,
                cancel_requested: false,
                provider_state: ProviderCallState::Completed,
                task_count: 1,
                pending_patch_approval: None,
                terminal: None,
            }),
            cancellation: cancellation.clone(),
            events,
            terminal,
            gui_patch_approval: Self::new(weak.clone()),
        });
        let mut broker = state.gui_patch_approval.clone();
        broker.test_keepalive = Some(state);
        (broker, cancellation)
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_pending_metadata_for_test(&self) -> CodingPatchApprovalMetadata {
        let _keepalive = self.test_keepalive.as_ref();
        let state = self
            .state
            .upgrade()
            .expect("test broker must retain its run state");
        for _ in 0..128 {
            if let Some(metadata) = state.snapshot.lock().await.pending_patch_approval.clone() {
                return metadata;
            }
            tokio::task::yield_now().await;
        }
        panic!("dispatcher did not publish a native patch approval");
    }

    #[cfg(test)]
    pub(crate) async fn respond_for_test(
        &self,
        approval_id: CodingPatchApprovalId,
        approved: bool,
    ) -> PatchApprovalResponse {
        self.respond(approval_id, approved).await
    }

    #[cfg(test)]
    fn with_publication_pause_for_test(mut self, pause: Arc<ApprovalPublicationPause>) -> Self {
        self.publication_pause = Some(pause);
        self
    }

    #[cfg(test)]
    async fn pause_before_snapshot_for_test(&self) {
        if let Some(pause) = self.publication_pause.as_ref() {
            pause.entered.store(true, Ordering::Release);
            pause.entered_notify.notify_waiters();
            pause.release.notified().await;
        }
    }

    pub(crate) async fn request_exact(
        &self,
        repository_identity: &str,
        repository_display: String,
        task_id: KanbanTaskId,
        patch_text: &str,
        request_binding_sha256: String,
    ) -> std::result::Result<GuiPatchApprovalGrant, String> {
        if patch_text.is_empty() || patch_text.len() > super::worker::MAX_WORKER_RESULT_BYTES {
            return Err(
                "native patch approval requires bounded non-empty accepted patch bytes".to_owned(),
            );
        }
        let state = self
            .state
            .upgrade()
            .ok_or_else(|| "native patch approval run is no longer live".to_owned())?;
        if state.cancellation.is_requested() {
            return Err("native patch approval cancelled".to_owned());
        }

        let patch_sha256: [u8; 32] = Sha256::digest(patch_text.as_bytes()).into();
        let expires_at = tokio::time::Instant::now() + GUI_PATCH_APPROVAL_TTL;
        let metadata = CodingPatchApprovalMetadata {
            approval_id: uuid::Uuid::now_v7(),
            task_id,
            repository_display,
            patch_sha256: hex::encode(patch_sha256),
            request_binding_sha256: request_binding_sha256.clone(),
            changed_files: bounded_changed_files(patch_text),
            expires_unix: crate::time::now_unix_i64()
                .saturating_add(GUI_PATCH_APPROVAL_TTL.as_secs() as i64),
        };
        let (response, receiver) = oneshot::channel();
        let cancelled_before_publish = {
            let mut pending = self.pending.lock().await;
            if pending.is_some() {
                return Err("native patch approval already pending for this run".to_owned());
            }
            *pending = Some(PendingGuiPatchApproval {
                metadata: metadata.clone(),
                repository_identity: repository_identity.to_owned(),
                patch_sha256,
                patch_text: patch_text.to_owned(),
                expires_at,
                response,
            });
            #[cfg(test)]
            if let Some(pause) = self.publication_pause.as_ref() {
                *pause
                    .approval_id
                    .lock()
                    .expect("test publication pause mutex poisoned") = Some(metadata.approval_id);
            }
            #[cfg(test)]
            self.pause_before_snapshot_for_test().await;
            let mut snapshot = state.snapshot.lock().await;
            if snapshot.terminal.is_some() || state.cancellation.is_requested() {
                snapshot.pending_patch_approval = None;
                pending.take()
            } else {
                snapshot.pending_patch_approval = Some(metadata.clone());
                None
            }
        };
        if let Some(current) = cancelled_before_publish {
            let _ = current.response.send(GuiPatchApprovalDecision::Cancelled);
            return Err("native patch approval cancelled".to_owned());
        }
        let _ = state
            .events
            .send(CodingRunEvent::PatchApplyApprovalRequested(
                metadata.clone(),
            ));

        let decision = tokio::select! {
            biased;
            decision = receiver => decision.unwrap_or(GuiPatchApprovalDecision::Cancelled),
            _ = state.cancellation.cancelled() => {
                self.remove(metadata.approval_id, GuiPatchApprovalDecision::Cancelled).await;
                GuiPatchApprovalDecision::Cancelled
            }
            _ = tokio::time::sleep_until(expires_at) => {
                self.remove(metadata.approval_id, GuiPatchApprovalDecision::Expired).await;
                GuiPatchApprovalDecision::Expired
            }
        };
        match decision {
            GuiPatchApprovalDecision::Approved(grant) => {
                grant.ensure_active()?;
                Ok(grant)
            }
            GuiPatchApprovalDecision::Rejected => Err("native patch approval rejected".to_owned()),
            GuiPatchApprovalDecision::Expired => Err("native patch approval expired".to_owned()),
            GuiPatchApprovalDecision::Cancelled => {
                Err("native patch approval cancelled".to_owned())
            }
        }
    }

    async fn respond(
        &self,
        approval_id: CodingPatchApprovalId,
        approved: bool,
    ) -> PatchApprovalResponse {
        let Some(state) = self.state.upgrade() else {
            return PatchApprovalResponse::StaleOrUnknown;
        };
        let (current, result) = {
            let mut pending = self.pending.lock().await;
            let Some(current) = pending.as_ref() else {
                return PatchApprovalResponse::StaleOrUnknown;
            };
            if current.metadata.approval_id != approval_id {
                return PatchApprovalResponse::StaleOrUnknown;
            }
            let expired = tokio::time::Instant::now() >= current.expires_at;
            let cancelled = state.cancellation.is_requested();
            let current = pending.take().expect("pending approval checked above");
            Self::clear_snapshot_while_pending(&state, approval_id).await;
            if cancelled {
                (current, PatchApprovalResponse::StaleOrUnknown)
            } else if expired {
                (current, PatchApprovalResponse::Expired)
            } else {
                let result = if approved {
                    PatchApprovalResponse::Accepted
                } else {
                    PatchApprovalResponse::Rejected
                };
                (current, result)
            }
        };
        let decision = match result {
            PatchApprovalResponse::Accepted => {
                GuiPatchApprovalDecision::Approved(GuiPatchApprovalGrant {
                    repository_identity: current.repository_identity,
                    task_id: current.metadata.task_id,
                    patch_sha256: current.patch_sha256,
                    request_binding_sha256: current.metadata.request_binding_sha256.clone(),
                    state: Arc::downgrade(&state),
                })
            }
            PatchApprovalResponse::Rejected => GuiPatchApprovalDecision::Rejected,
            PatchApprovalResponse::Expired => GuiPatchApprovalDecision::Expired,
            PatchApprovalResponse::StaleOrUnknown => GuiPatchApprovalDecision::Cancelled,
        };
        let _ = current.response.send(decision);
        result
    }

    async fn preview(&self, approval_id: CodingPatchApprovalId) -> PatchApprovalPreviewResult {
        let Some(state) = self.state.upgrade() else {
            return PatchApprovalPreviewResult::StaleOrUnknown;
        };
        let expired_or_cancelled = {
            let mut pending = self.pending.lock().await;
            let Some(current) = pending.as_ref() else {
                return PatchApprovalPreviewResult::StaleOrUnknown;
            };
            if current.metadata.approval_id != approval_id {
                return PatchApprovalPreviewResult::StaleOrUnknown;
            }
            if tokio::time::Instant::now() >= current.expires_at
                || state.cancellation.is_requested()
            {
                let current = pending.take();
                Self::clear_snapshot_while_pending(&state, approval_id).await;
                current
            } else {
                let digest: [u8; 32] = Sha256::digest(current.patch_text.as_bytes()).into();
                if digest != current.patch_sha256
                    || hex::encode(digest) != current.metadata.patch_sha256
                {
                    return PatchApprovalPreviewResult::StaleOrUnknown;
                }
                return PatchApprovalPreviewResult::Available(CodingPatchApprovalPreview {
                    metadata: current.metadata.clone(),
                    patch_text: current.patch_text.clone(),
                });
            }
        };
        if let Some(current) = expired_or_cancelled {
            let cancelled = state.cancellation.is_requested();
            let _ = current.response.send(if cancelled {
                GuiPatchApprovalDecision::Cancelled
            } else {
                GuiPatchApprovalDecision::Expired
            });
            if cancelled {
                PatchApprovalPreviewResult::StaleOrUnknown
            } else {
                PatchApprovalPreviewResult::Expired
            }
        } else {
            PatchApprovalPreviewResult::StaleOrUnknown
        }
    }

    async fn invalidate(&self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let current = {
            let mut pending = self.pending.lock().await;
            let current = pending.take();
            if let Some(current) = current.as_ref() {
                Self::clear_snapshot_while_pending(&state, current.metadata.approval_id).await;
            }
            current
        };
        if let Some(current) = current {
            let _ = current.response.send(GuiPatchApprovalDecision::Cancelled);
        }
    }

    async fn remove(&self, approval_id: CodingPatchApprovalId, decision: GuiPatchApprovalDecision) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        let current = {
            let mut pending = self.pending.lock().await;
            if pending
                .as_ref()
                .is_some_and(|current| current.metadata.approval_id == approval_id)
            {
                let current = pending.take();
                Self::clear_snapshot_while_pending(&state, approval_id).await;
                current
            } else {
                None
            }
        };
        if let Some(current) = current {
            let _ = current.response.send(decision);
        }
    }

    /// Every mirrored-state mutation locks `pending` before `snapshot`.
    /// Callers hold the pending lock, making a consumed entry and the recovery
    /// snapshot one linearizable state transition.
    async fn clear_snapshot_while_pending(state: &RunState, approval_id: CodingPatchApprovalId) {
        let mut snapshot = state.snapshot.lock().await;
        if snapshot
            .pending_patch_approval
            .as_ref()
            .is_some_and(|metadata| metadata.approval_id == approval_id)
        {
            snapshot.pending_patch_approval = None;
        }
    }
}

fn bounded_changed_files(patch_text: &str) -> Vec<String> {
    let mut files = crate::code_map::risk::patch_changed_files_from_text(patch_text);
    files.sort_unstable();
    files
        .into_iter()
        .filter_map(|file| safe_relative_display_file(&file))
        .take(GUI_PATCH_APPROVAL_MAX_CHANGED_FILES)
        .collect()
}

/// Provider-supplied diff headers are useful only as bounded display labels.
/// Do not let control bytes, roots, path traversal, or malformed components
/// escape the raw preview boundary through serializable event metadata.
fn safe_relative_display_file(file: &str) -> Option<String> {
    if file.is_empty()
        || file.len() > GUI_PATCH_APPROVAL_MAX_FILE_LABEL_BYTES
        || file.chars().any(char::is_control)
        || file.starts_with(['/', '\\'])
    {
        return None;
    }
    let components = file.split(['/', '\\']).collect::<Vec<_>>();
    if components.is_empty()
        || components.iter().any(|component| {
            component.is_empty() || matches!(*component, "." | "..") || component.contains(':')
        })
    {
        return None;
    }
    Some(components.join("/"))
}

/// Worker-owned capability for emitting a canonical state transition.
#[derive(Clone)]
pub struct CodingRunProgress {
    state: Arc<RunState>,
}

impl CodingRunProgress {
    async fn run_id(&self) -> CodingRunId {
        self.state.snapshot.lock().await.run_id
    }

    async fn snapshot(&self) -> CodingRunSnapshot {
        self.state.snapshot.lock().await.clone()
    }

    pub async fn set_phase(&self, phase: CodingRunPhase) {
        let mut snapshot = self.state.snapshot.lock().await;
        if snapshot.terminal.is_some() || snapshot.phase.is_terminal() {
            return;
        }
        snapshot.phase = phase;
        let _ = self.state.events.send(CodingRunEvent::Phase(phase));
    }

    pub async fn session_created(&self, session_id: KanbanSessionId) {
        let mut snapshot = self.state.snapshot.lock().await;
        if snapshot.terminal.is_some() {
            return;
        }
        snapshot.session_id = Some(session_id);
        let _ = self
            .state
            .events
            .send(CodingRunEvent::SessionCreated { session_id });
    }

    pub async fn context_prepared(&self) {
        let _ = self
            .state
            .events
            .send(CodingRunEvent::CodeMapContextPrepared);
    }

    pub async fn receipt_recorded(&self, attempt: u8) {
        let _ = self
            .state
            .events
            .send(CodingRunEvent::ReceiptRecorded { attempt });
    }

    pub async fn provider_state(&self, provider_state: ProviderCallState) {
        self.state.snapshot.lock().await.provider_state = provider_state;
    }

    pub async fn tasks_inserted(&self, count: usize) {
        let mut snapshot = self.state.snapshot.lock().await;
        snapshot.task_count = count;
        let _ = self
            .state
            .events
            .send(CodingRunEvent::TasksInserted { count });
    }

    pub fn cancellation(&self) -> CodingCancellation {
        self.state.cancellation.clone()
    }

    fn gui_patch_approval_broker(&self) -> GuiPatchApprovalBroker {
        self.state.gui_patch_approval.clone()
    }
}

struct RunState {
    snapshot: Mutex<CodingRunSnapshot>,
    cancellation: CodingCancellation,
    events: broadcast::Sender<CodingRunEvent>,
    terminal: watch::Sender<Option<CodingRunResult>>,
    gui_patch_approval: GuiPatchApprovalBroker,
}

struct ActiveRun {
    state: Arc<RunState>,
    /// The registry is the sole owner of this handle.  A caller can take it
    /// only through `cancel_and_join`, which transfers that one ownership
    /// temporarily in order to await the worker.  The public run handle never
    /// receives a JoinHandle.
    join: Option<tokio::task::JoinHandle<()>>,
}

struct RegistryState {
    next_run_id: AtomicU64,
    active: Mutex<HashMap<CodingRunId, ActiveRun>>,
    terminal: Mutex<VecDeque<CodingRunSnapshot>>,
}

/// Process-local coding controller. It owns the only join path for every
/// worker; callers receive a watch channel and cannot detach or double-join it.
#[derive(Clone)]
struct LocalCodingService {
    registry: Arc<RegistryState>,
}

impl Default for LocalCodingService {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalCodingService {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(RegistryState {
                next_run_id: AtomicU64::new(1),
                active: Mutex::new(HashMap::new()),
                terminal: Mutex::new(VecDeque::new()),
            }),
        }
    }

    pub(crate) async fn start_local(
        &self,
        request: CodingStartRequest,
        worker: Arc<dyn CodingRunWorker>,
    ) -> Result<LocalCodingRunHandle> {
        request.validate()?;
        let root = std::fs::canonicalize(&request.repository_root).map_err(|error| {
            anyhow::anyhow!(
                "canonicalize coding repository root {}: {error}",
                request.repository_root.display()
            )
        })?;
        ensure!(root.is_dir(), "coding repository root must be a directory");

        let run_id = CodingRunId(self.registry.next_run_id.fetch_add(1, Ordering::Relaxed));
        let cancellation = CodingCancellation::new();
        let (events, _) = broadcast::channel(EVENT_SUBSCRIBER_CAPACITY);
        let initial = CodingRunSnapshot {
            run_id,
            phase: CodingRunPhase::Queued,
            repository_root: root.clone(),
            session_id: None,
            cancel_requested: false,
            provider_state: ProviderCallState::NotAttempted,
            task_count: 0,
            pending_patch_approval: None,
            terminal: None,
        };
        let (terminal, terminal_rx) = watch::channel(None);
        let state = Arc::new_cyclic(|weak| RunState {
            snapshot: Mutex::new(initial),
            cancellation: cancellation.clone(),
            events,
            terminal,
            gui_patch_approval: GuiPatchApprovalBroker::new(weak.clone()),
        });
        // Publish the active row before allowing the worker to run. Without
        // this gate a very fast failure could remove a row that has not been
        // inserted yet and leave an immortal, already-terminal active entry.
        self.registry.active.lock().await.insert(
            run_id,
            ActiveRun {
                state: Arc::clone(&state),
                join: None,
            },
        );
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let registry = Arc::clone(&self.registry);
        let task_state = Arc::clone(&state);
        let task_request = CodingStartRequest {
            repository_root: root,
            ..request
        };
        // The registry owns this one JoinHandle. The worker itself publishes
        // its terminal state and removes its active row, so ordinary
        // completion needs no detached supervisor task.
        // Coding owns a rusqlite connection through provider awaits. It is
        // therefore deliberately a Tokio LocalSet task: no Connection is ever
        // marked Send or smuggled to a blocking thread. All front ends enter
        // this shared controller from the application's LocalSet.
        let join = tokio::task::spawn_local(async move {
            // The sender is dropped only if setup itself failed, in which
            // case this task has no externally reachable run handle.
            if started_rx.await.is_err() {
                return;
            }
            let progress = CodingRunProgress {
                state: Arc::clone(&task_state),
            };
            let result = match futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(
                worker.run(task_request, progress.clone(), cancellation),
            ))
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    // A temporary MutexGuard in the first field of a struct
                    // literal lives while its sibling fields are evaluated.
                    // Read this snapshot once so the second identifier cannot
                    // try to re-lock the same non-reentrant Tokio mutex.
                    let (run_id, session_id) = {
                        let snapshot = task_state.snapshot.lock().await;
                        (snapshot.run_id, snapshot.session_id)
                    };
                    CodingRunResult::Failed {
                        run_id,
                        session_id,
                        message: "coding worker panicked; inspect scoped local diagnostics"
                            .to_owned(),
                    }
                }
            };
            finish_run(&task_state, result).await;
            let snapshot = task_state.snapshot.lock().await.clone();
            registry.active.lock().await.remove(&snapshot.run_id);
            let mut retained = registry.terminal.lock().await;
            retained.push_back(snapshot);
            while retained.len() > RETAINED_TERMINAL_RUNS {
                retained.pop_front();
            }
        });
        let installed = self
            .registry
            .active
            .lock()
            .await
            .get_mut(&run_id)
            .map(|active| active.join = Some(join));
        debug_assert!(
            installed.is_some(),
            "new coding run disappeared before start gate"
        );
        let _ = started_tx.send(());

        Ok(LocalCodingRunHandle {
            run_id,
            state,
            terminal: terminal_rx,
            registry: Arc::clone(&self.registry),
        })
    }

    pub async fn snapshot(&self, run_id: CodingRunId) -> Option<CodingRunSnapshot> {
        if let Some(active) = self.registry.active.lock().await.get(&run_id) {
            return Some(active.state.snapshot.lock().await.clone());
        }
        self.registry
            .terminal
            .lock()
            .await
            .iter()
            .find(|snapshot| snapshot.run_id == run_id)
            .cloned()
    }

    async fn respond_patch_approval(
        &self,
        run_id: CodingRunId,
        approval_id: CodingPatchApprovalId,
        approved: bool,
    ) -> PatchApprovalResponse {
        let state = self
            .registry
            .active
            .lock()
            .await
            .get(&run_id)
            .map(|active| Arc::clone(&active.state));
        match state {
            Some(state) => {
                state
                    .gui_patch_approval
                    .respond(approval_id, approved)
                    .await
            }
            None => PatchApprovalResponse::StaleOrUnknown,
        }
    }

    async fn patch_approval_preview(
        &self,
        run_id: CodingRunId,
        approval_id: CodingPatchApprovalId,
    ) -> PatchApprovalPreviewResult {
        let state = self
            .registry
            .active
            .lock()
            .await
            .get(&run_id)
            .map(|active| Arc::clone(&active.state));
        match state {
            Some(state) => state.gui_patch_approval.preview(approval_id).await,
            None => PatchApprovalPreviewResult::StaleOrUnknown,
        }
    }

    /// Request cancellation without claiming completion. Frontends that need a
    /// final effect receipt must then call `cancel_and_join` or await their
    /// handle's terminal watcher.
    pub async fn request_cancel(&self, run_id: CodingRunId) -> Result<()> {
        let state = self
            .registry
            .active
            .lock()
            .await
            .get(&run_id)
            .map(|active| Arc::clone(&active.state));
        let Some(state) = state else {
            return self
                .snapshot(run_id)
                .await
                .and_then(|snapshot| snapshot.terminal)
                .map(|_| ())
                .ok_or_else(|| anyhow::anyhow!("unknown coding run {}", run_id.raw()));
        };
        request_cancellation(&state).await;
        Ok(())
    }

    /// Request cancellation and wait for a joined terminal result. A returned
    /// `Cancelled` value is therefore an acknowledgement, not a mere signal.
    pub async fn cancel_and_join(&self, run_id: CodingRunId) -> Result<CodingRunResult> {
        let handle = {
            let active = self.registry.active.lock().await;
            active.get(&run_id).map(|active| LocalCodingRunHandle {
                run_id,
                state: Arc::clone(&active.state),
                terminal: active.state.terminal.subscribe(),
                registry: Arc::clone(&self.registry),
            })
        };
        match handle {
            Some(handle) => handle.cancel_and_join().await,
            None => self
                .snapshot(run_id)
                .await
                .and_then(|snapshot| snapshot.terminal)
                .ok_or_else(|| anyhow::anyhow!("unknown coding run {}", run_id.raw())),
        }
    }

    async fn shutdown_and_join_all(&self) -> Result<()> {
        // Snapshot identities before awaiting any join. New Start commands are
        // no longer admitted once RuntimeCommand::Shutdown is being handled.
        let run_ids = self
            .registry
            .active
            .lock()
            .await
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut failures = Vec::new();
        for run_id in run_ids {
            if let Err(error) = self.cancel_and_join(run_id).await {
                // Continue draining all other workers even when one task
                // panicked or finalization failed. Shutdown may report the
                // aggregate only after no owned provider future remains.
                failures.push(format!("run {}: {error}", run_id.raw()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "coding service shutdown drained all runs with failures: {}",
                failures.join("; ")
            );
        }
    }
}

/// Runtime configuration captured once when the process-local controller is
/// started. It is never exposed through snapshots, events, or terminal
/// receipts. Desktop callers create the controller during application setup;
/// individual GUI/Buddy requests carry no provider, SQLite, or secret state.
#[derive(Clone)]
pub struct CodingServiceConfig {
    pub database_path: PathBuf,
    /// The code-map snapshot selected by this service instance. Keeping it in
    /// the instance config avoids consulting a process-global home at run time.
    pub code_map_database_path: PathBuf,
    pub neoth_home: PathBuf,
    /// Exact config file reloaded before every fresh coding run.
    pub freedom_config_path: PathBuf,
    pub freedom_config: crate::config::FreedomConfig,
}

/// Send-capable frontend controller. Its private OS thread owns a current
/// thread Tokio Runtime plus LocalSet; every rusqlite connection and local
/// JoinHandle remains there for its entire lifetime.
#[derive(Clone)]
pub struct CodingService {
    control: Arc<ServiceControl>,
}

struct ServiceControl {
    commands: tokio::sync::mpsc::UnboundedSender<RuntimeCommand>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    shutting_down: AtomicBool,
    shutdown_drained: AtomicBool,
    shutdown_guard_started: AtomicBool,
    shutdown_finished: AtomicBool,
    shutdown_notify: Notify,
    shutdown_error: std::sync::Mutex<Option<String>>,
}

enum RuntimeCommand {
    Start {
        request: Box<CodingStartRequest>,
        reply: tokio::sync::oneshot::Sender<Result<CodingRunHandle>>,
    },
    Snapshot {
        run_id: CodingRunId,
        reply: tokio::sync::oneshot::Sender<Option<CodingRunSnapshot>>,
    },
    RespondPatchApproval {
        run_id: CodingRunId,
        approval_id: CodingPatchApprovalId,
        approved: bool,
        reply: tokio::sync::oneshot::Sender<PatchApprovalResponse>,
    },
    ReadPatchApprovalPreview {
        run_id: CodingRunId,
        approval_id: CodingPatchApprovalId,
        reply: tokio::sync::oneshot::Sender<PatchApprovalPreviewResult>,
    },
    RequestCancel {
        run_id: CodingRunId,
        reply: tokio::sync::oneshot::Sender<Result<()>>,
    },
    CancelAndJoin {
        run_id: CodingRunId,
        reply: tokio::sync::oneshot::Sender<Result<CodingRunResult>>,
    },
    Shutdown {
        reply: tokio::sync::oneshot::Sender<Result<()>>,
    },
}

/// Send-capable run observation handle. It is deliberately separate from the
/// LocalSet handle that owns the task JoinHandle.
pub struct CodingRunHandle {
    run_id: CodingRunId,
    events: broadcast::Sender<CodingRunEvent>,
    terminal: watch::Receiver<Option<CodingRunResult>>,
    service: CodingService,
}

impl CodingService {
    pub fn spawn(config: CodingServiceConfig) -> Result<Self> {
        let (commands, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let control = Arc::new(ServiceControl {
            commands: commands.clone(),
            thread: std::sync::Mutex::new(None),
            shutting_down: AtomicBool::new(false),
            shutdown_drained: AtomicBool::new(false),
            shutdown_guard_started: AtomicBool::new(false),
            shutdown_finished: AtomicBool::new(false),
            shutdown_notify: Notify::new(),
            shutdown_error: std::sync::Mutex::new(None),
        });
        let runtime_control = Arc::clone(&control);
        let thread = std::thread::Builder::new()
            .name("neoth-coding-service".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(anyhow::anyhow!(
                            "build coding service runtime: {error}"
                        )));
                        return;
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    return;
                }
                tokio::task::LocalSet::new().block_on(
                    &runtime,
                    runtime_command_loop(config, receiver, runtime_control),
                );
            })
            .map_err(|error| anyhow::anyhow!("start coding service runtime thread: {error}"))?;
        ready_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("coding service runtime exited during startup"))??;
        *control
            .thread
            .lock()
            .expect("coding service thread mutex poisoned") = Some(thread);
        Ok(Self { control })
    }

    pub async fn start(&self, request: CodingStartRequest) -> Result<CodingRunHandle> {
        ensure!(
            !self.control.shutting_down.load(Ordering::Acquire),
            "coding service is shutting down"
        );
        let (reply, result) = tokio::sync::oneshot::channel();
        self.control
            .commands
            .send(RuntimeCommand::Start {
                request: Box::new(request),
                reply,
            })
            .map_err(|_| anyhow::anyhow!("coding service runtime is unavailable"))?;
        result
            .await
            .map_err(|_| anyhow::anyhow!("coding service start reply dropped"))?
    }

    pub async fn snapshot(&self, run_id: CodingRunId) -> Option<CodingRunSnapshot> {
        let (reply, result) = tokio::sync::oneshot::channel();
        if self
            .control
            .commands
            .send(RuntimeCommand::Snapshot { run_id, reply })
            .is_err()
        {
            return None;
        }
        result.await.ok().flatten()
    }

    /// Consume an opaque pending native patch approval. A stale id is a normal
    /// typed result, while a stopped controller remains an operational error.
    pub async fn respond_patch_approval(
        &self,
        run_id: CodingRunId,
        approval_id: CodingPatchApprovalId,
        approved: bool,
    ) -> Result<PatchApprovalResponse> {
        let (reply, result) = tokio::sync::oneshot::channel();
        self.control
            .commands
            .send(RuntimeCommand::RespondPatchApproval {
                run_id,
                approval_id,
                approved,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("coding service runtime is unavailable"))?;
        result
            .await
            .map_err(|_| anyhow::anyhow!("coding service approval reply dropped"))
    }

    /// Read the full accepted patch only while the exact approval is pending.
    /// This does not consume or extend the one-use approval.
    pub async fn patch_approval_preview(
        &self,
        run_id: CodingRunId,
        approval_id: CodingPatchApprovalId,
    ) -> Result<PatchApprovalPreviewResult> {
        let (reply, result) = tokio::sync::oneshot::channel();
        self.control
            .commands
            .send(RuntimeCommand::ReadPatchApprovalPreview {
                run_id,
                approval_id,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("coding service runtime is unavailable"))?;
        result
            .await
            .map_err(|_| anyhow::anyhow!("coding service preview reply dropped"))
    }

    pub async fn request_cancel(&self, run_id: CodingRunId) -> Result<()> {
        let (reply, result) = tokio::sync::oneshot::channel();
        self.control
            .commands
            .send(RuntimeCommand::RequestCancel { run_id, reply })
            .map_err(|_| anyhow::anyhow!("coding service runtime is unavailable"))?;
        result
            .await
            .map_err(|_| anyhow::anyhow!("coding service cancel reply dropped"))?
    }

    pub async fn cancel_and_join(&self, run_id: CodingRunId) -> Result<CodingRunResult> {
        let (reply, result) = tokio::sync::oneshot::channel();
        self.control
            .commands
            .send(RuntimeCommand::CancelAndJoin { run_id, reply })
            .map_err(|_| anyhow::anyhow!("coding service runtime is unavailable"))?;
        result
            .await
            .map_err(|_| anyhow::anyhow!("coding service terminal reply dropped"))?
    }

    /// Reject future starts, cancel every owned run, wait for their terminal
    /// finalizers, then join the runtime thread. Dropping a controller is not
    /// a shutdown acknowledgement.
    pub async fn shutdown_and_join(&self) -> Result<()> {
        if !self.control.shutting_down.swap(true, Ordering::AcqRel) {
            let (reply, _result) = tokio::sync::oneshot::channel();
            if let Err(_error) = self
                .control
                .commands
                .send(RuntimeCommand::Shutdown { reply })
            {
                *self
                    .control
                    .shutdown_error
                    .lock()
                    .expect("coding service shutdown mutex poisoned") =
                    Some("coding service runtime is unavailable".to_owned());
                self.control.shutdown_drained.store(true, Ordering::Release);
            }
            self.start_shutdown_guard();
        }
        loop {
            // Register before observing the predicate so completion between
            // observation and await cannot lose the only wakeup.
            let notified = self.control.shutdown_notify.notified();
            if self.control.shutdown_finished.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
        if let Some(error) = self
            .control
            .shutdown_error
            .lock()
            .expect("coding service shutdown mutex poisoned")
            .clone()
        {
            anyhow::bail!("coding service shutdown failed: {error}");
        }
        let thread = self
            .control
            .thread
            .lock()
            .expect("coding service thread mutex poisoned")
            .take();
        if let Some(thread) = thread {
            tokio::task::spawn_blocking(move || thread.join())
                .await
                .map_err(|error| anyhow::anyhow!("join coding service runtime task: {error}"))?
                .map_err(|_| anyhow::anyhow!("coding service runtime thread panicked"))?;
        }
        Ok(())
    }

    fn start_shutdown_guard(&self) {
        if self
            .control
            .shutdown_guard_started
            .swap(true, Ordering::AcqRel)
        {
            return;
        }
        let control = Arc::clone(&self.control);
        std::thread::spawn(move || {
            while !control.shutdown_drained.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let thread = control
                .thread
                .lock()
                .expect("coding service thread mutex poisoned")
                .take();
            if let Some(thread) = thread
                && thread.join().is_err()
            {
                let mut error = control
                    .shutdown_error
                    .lock()
                    .expect("coding service shutdown mutex poisoned");
                if error.is_none() {
                    *error = Some("coding service runtime thread panicked".to_owned());
                }
            }
            control.shutdown_finished.store(true, Ordering::Release);
            control.shutdown_notify.notify_waiters();
        });
    }
}

impl CodingRunHandle {
    pub const fn run_id(&self) -> CodingRunId {
        self.run_id
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CodingRunEvent> {
        self.events.subscribe()
    }

    pub async fn snapshot(&self) -> Option<CodingRunSnapshot> {
        self.service.snapshot(self.run_id).await
    }

    pub async fn respond_patch_approval(
        &self,
        approval_id: CodingPatchApprovalId,
        approved: bool,
    ) -> Result<PatchApprovalResponse> {
        self.service
            .respond_patch_approval(self.run_id, approval_id, approved)
            .await
    }

    pub async fn patch_approval_preview(
        &self,
        approval_id: CodingPatchApprovalId,
    ) -> Result<PatchApprovalPreviewResult> {
        self.service
            .patch_approval_preview(self.run_id, approval_id)
            .await
    }

    pub async fn request_cancel(&self) -> Result<()> {
        self.service.request_cancel(self.run_id).await
    }

    pub async fn cancel_and_join(&self) -> Result<CodingRunResult> {
        self.service.cancel_and_join(self.run_id).await
    }

    pub async fn wait_terminal(&mut self) -> Result<CodingRunResult> {
        loop {
            if let Some(result) = self.terminal.borrow().clone() {
                return Ok(result);
            }
            self.terminal
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("coding service terminal channel closed"))?;
        }
    }
}

async fn runtime_command_loop(
    config: CodingServiceConfig,
    mut commands: tokio::sync::mpsc::UnboundedReceiver<RuntimeCommand>,
    control: Arc<ServiceControl>,
) {
    let service = LocalCodingService::new();
    while let Some(command) = commands.recv().await {
        match command {
            RuntimeCommand::Start { request, reply } => {
                let result =
                    start_runtime_run(&service, &config, *request, Arc::clone(&control)).await;
                let _ = reply.send(result);
            }
            RuntimeCommand::Snapshot { run_id, reply } => {
                let _ = reply.send(service.snapshot(run_id).await);
            }
            RuntimeCommand::RespondPatchApproval {
                run_id,
                approval_id,
                approved,
                reply,
            } => {
                let _ = reply.send(
                    service
                        .respond_patch_approval(run_id, approval_id, approved)
                        .await,
                );
            }
            RuntimeCommand::ReadPatchApprovalPreview {
                run_id,
                approval_id,
                reply,
            } => {
                let _ = reply.send(service.patch_approval_preview(run_id, approval_id).await);
            }
            RuntimeCommand::RequestCancel { run_id, reply } => {
                let _ = reply.send(service.request_cancel(run_id).await);
            }
            RuntimeCommand::CancelAndJoin { run_id, reply } => {
                // Joining can wait on an already-started provider call. Keep
                // the sole controller receiver free so other active runs can
                // still be observed or cancelled during that wait.
                let service = service.clone();
                tokio::task::spawn_local(async move {
                    let _ = reply.send(service.cancel_and_join(run_id).await);
                });
            }
            RuntimeCommand::Shutdown { reply } => {
                let result = service.shutdown_and_join_all().await;
                if let Err(error) = &result {
                    *control
                        .shutdown_error
                        .lock()
                        .expect("coding service shutdown mutex poisoned") = Some(error.to_string());
                }
                let _ = reply.send(result);
                control.shutdown_drained.store(true, Ordering::Release);
                break;
            }
        }
    }
}

async fn start_runtime_run(
    service: &LocalCodingService,
    config: &CodingServiceConfig,
    request: CodingStartRequest,
    control: Arc<ServiceControl>,
) -> Result<CodingRunHandle> {
    let code_map_database_path = config.code_map_database_path.clone();
    let neoth_home = config.neoth_home.clone();
    let database_path = config.database_path.clone();
    let local = start_runtime_run_with_worker_factory(
        service,
        config,
        request,
        &code_map_database_path,
        move |run_config, dispatch_plan| async move {
            let worker =
                build_audited_worker(&run_config, &neoth_home, database_path, dispatch_plan)
                    .await?;
            Ok(Arc::new(worker) as Arc<dyn CodingRunWorker>)
        },
    )
    .await?;
    Ok(CodingRunHandle {
        run_id: local.run_id,
        events: local.state.events.clone(),
        terminal: local.terminal.clone(),
        service: CodingService { control },
    })
}

/// One service admission order shared by the production provider factory and
/// isolated-database fixtures. Preparation must finish before dispatch or any
/// worker/provider factory is invoked.
async fn start_runtime_run_with_worker_factory<F, Fut>(
    service: &LocalCodingService,
    config: &CodingServiceConfig,
    mut request: CodingStartRequest,
    code_map_database_path: &std::path::Path,
    worker_factory: F,
) -> Result<LocalCodingRunHandle>
where
    F: FnOnce(crate::config::FreedomConfig, Option<CodingDispatchPlan>) -> Fut,
    Fut: std::future::Future<Output = Result<Arc<dyn CodingRunWorker>>>,
{
    request.validate()?;
    // A service can live longer than a GUI settings view. Reload precisely at
    // this admission boundary and fail closed on unreadable/invalid changes;
    // no run may inherit a stale provider, autonomy, cap, or apply policy.
    let run_config = crate::config::FreedomConfig::load_from_path(&config.freedom_config_path)
        .with_context(|| {
            format!(
                "reload coding configuration from {}",
                config.freedom_config_path.display()
            )
        })?;
    let repository_root = std::fs::canonicalize(&request.repository_root).with_context(|| {
        format!(
            "canonicalize coding repository root {}",
            request.repository_root.display()
        )
    })?;
    ensure!(
        repository_root.is_dir(),
        "coding repository root must be a directory"
    );
    // Freeze the typed original selection before a session, provider audit, or
    // dispatch worker exists.  It uses this explicit root, never process CWD.
    let prepared_context = prepare_runtime_code_map_context_at_database(
        &request.prompt,
        &repository_root,
        &run_config.code_map,
        request.diff_impact_input.as_ref(),
        code_map_database_path,
    )?;
    request.repository_root = repository_root;
    request = request.with_prepared_code_map_context(prepared_context);
    let dispatch_plan = if request.dispatch {
        Some(
            build_dispatch_plan(
                &run_config,
                &config.neoth_home,
                &request,
                code_map_database_path,
            )
            .await?,
        )
    } else {
        None
    };
    let worker = worker_factory(run_config, dispatch_plan).await?;
    service.start_local(request, worker).await
}

fn prepare_runtime_code_map_context_at_database(
    prompt: &str,
    repository_root: &std::path::Path,
    config: &crate::config::CodeMapConfig,
    diff_impact_input: Option<&crate::code_map::diff_impact::DiffImpactInput>,
    database_path: &std::path::Path,
) -> Result<Option<PreparedCodeMapContext>> {
    crate::cli::code::prepare_code_map_context_for_root_at_database(
        prompt,
        repository_root,
        config,
        diff_impact_input,
        database_path,
    )
}

/// Observer handle. It contains no JoinHandle and cannot detach the run.
struct LocalCodingRunHandle {
    run_id: CodingRunId,
    state: Arc<RunState>,
    terminal: watch::Receiver<Option<CodingRunResult>>,
    registry: Arc<RegistryState>,
}

impl LocalCodingRunHandle {
    #[cfg(test)]
    pub const fn run_id(&self) -> CodingRunId {
        self.run_id
    }

    pub async fn request_cancel(&self) {
        request_cancellation(&self.state).await;
    }

    /// Wait for normal completion without changing cancellation state. This
    /// still joins the registry-owned task before returning its terminal
    /// receipt, so callers never observe a partially unwound run.
    #[cfg(test)]
    pub async fn wait_terminal(mut self) -> Result<CodingRunResult> {
        self.join_terminal().await
    }

    pub async fn cancel_and_join(mut self) -> Result<CodingRunResult> {
        self.request_cancel().await;
        self.join_terminal().await
    }

    async fn join_terminal(&mut self) -> Result<CodingRunResult> {
        // Take the sole owned join handle if the active entry still exists.
        // Concurrent cancellers merely wait on the terminal watch channel.
        let join = self
            .registry
            .active
            .lock()
            .await
            .get_mut(&self.run_id)
            .and_then(|active| active.join.take());
        if let Some(join) = join {
            join.await
                .map_err(|error| anyhow::anyhow!("coding run worker panicked: {error}"))?;
        }
        loop {
            if let Some(result) = self.terminal.borrow().clone() {
                return Ok(result);
            }
            self.terminal.changed().await.map_err(|_| {
                anyhow::anyhow!("coding run terminal channel closed before publishing a result")
            })?;
        }
    }
}

async fn request_cancellation(state: &RunState) {
    if state.cancellation.request() {
        state.gui_patch_approval.invalidate().await;
        let mut snapshot = state.snapshot.lock().await;
        if snapshot.terminal.is_none() {
            snapshot.cancel_requested = true;
            snapshot.phase = CodingRunPhase::Cancelling;
            let _ = state.events.send(CodingRunEvent::CancelRequested);
            let _ = state
                .events
                .send(CodingRunEvent::Phase(CodingRunPhase::Cancelling));
        }
    }
}

async fn finish_run(state: &RunState, mut result: CodingRunResult) {
    state.gui_patch_approval.invalidate().await;
    let mut snapshot = state.snapshot.lock().await;
    if snapshot.terminal.is_some() {
        return;
    }
    // Never publish the dangerous claim that cancellation had no effects once
    // a provider request was even attempted. A worker can be interrupted at
    // an HTTP boundary where remote billing/completion is unknowable, so the
    // conservative terminal receipt wins over an optimistic worker value.
    if let CodingRunResult::Cancelled {
        provider_state,
        effect,
        ..
    } = &mut result
    {
        let observed = match (*provider_state, snapshot.provider_state) {
            (ProviderCallState::Completed, _) | (_, ProviderCallState::Completed) => {
                ProviderCallState::Completed
            }
            (ProviderCallState::AttemptedUnknown, _) | (_, ProviderCallState::AttemptedUnknown) => {
                ProviderCallState::AttemptedUnknown
            }
            _ => ProviderCallState::NotAttempted,
        };
        *provider_state = observed;
        if matches!(effect, CancellationEffect::NoEffect)
            && observed != ProviderCallState::NotAttempted
        {
            *effect = match observed {
                ProviderCallState::Completed => CancellationEffect::ProviderCompletedNoTasks,
                ProviderCallState::AttemptedUnknown => CancellationEffect::ProviderAttemptedUnknown,
                ProviderCallState::NotAttempted => CancellationEffect::NoEffect,
            };
        }
    }
    snapshot.session_id = match &result {
        CodingRunResult::Completed { session_id, .. } => Some(*session_id),
        CodingRunResult::Cancelled { session_id, .. }
        | CodingRunResult::Failed { session_id, .. } => *session_id,
    };
    snapshot.provider_state = match &result {
        CodingRunResult::Cancelled { provider_state, .. } => *provider_state,
        _ => snapshot.provider_state,
    };
    snapshot.phase = match &result {
        CodingRunResult::Completed { .. } => CodingRunPhase::Completed,
        CodingRunResult::Cancelled { effect, .. } => {
            let _ = state.events.send(CodingRunEvent::CancelAcknowledged {
                effect: effect.clone(),
            });
            CodingRunPhase::Cancelled
        }
        CodingRunResult::Failed { .. } => CodingRunPhase::Failed,
    };
    snapshot.terminal = Some(result.clone());
    let _ = state.events.send(CodingRunEvent::Terminal(result.clone()));
    let _ = state.terminal.send(Some(result));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::code_map_receipt::{
        CodeMapContextKind, CodeMapContextSource, CodeMapSelectedFile,
    };
    use crate::config::inference::{HemisphereRole, InferenceProvider, TopologyMode};
    use crate::config::role_policy::{RolePolicyConfig, RolePolicyRule};
    use crate::permissions::AutonomyLevel;
    use crate::providers::{Completion, Provider, Request};
    use std::sync::atomic::AtomicUsize;

    struct RoleCountingProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Provider for RoleCountingProvider {
        fn name(&self) -> &'static str {
            "local_ollama"
        }

        fn default_model(&self) -> Option<&str> {
            Some("w300-cerebellum")
        }

        fn output_token_ceiling(&self, _: &Request) -> Option<u32> {
            Some(64)
        }

        async fn complete(&self, request: Request) -> Result<Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Completion {
                text: "decomposition".to_owned(),
                model: request.model.unwrap_or_default(),
                ..Completion::default()
            })
        }
    }

    fn w300_role_config(policy_provider: InferenceProvider) -> crate::config::FreedomConfig {
        let mut config = crate::config::FreedomConfig::default();
        config.inference.mode = TopologyMode::Custom;
        config.inference.cerebellum.provider = Some(InferenceProvider::LocalOllama);
        config.inference.role_policy = Some(RolePolicyConfig {
            rules: vec![RolePolicyRule {
                role: HemisphereRole::Cerebellum,
                provider: policy_provider,
                model: Some("w300-cerebellum".to_owned()),
            }],
        });
        config
    }

    fn w300_provider_request_payload(segment: &std::path::Path) -> serde_json::Value {
        let bytes = std::fs::read(segment).unwrap();
        let header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = header.header_len();
        while cursor < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[cursor..]).unwrap();
            cursor += frame.header.total_len as usize;
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST {
                return serde_json::from_slice(&frame.payload).unwrap();
            }
        }
        panic!("allowed Cerebellum call must write a provider-request lifecycle frame");
    }

    #[tokio::test]
    async fn cerebellum_decomposer_role_binding_allows_one_leaf_and_audits_then_denies_before_transport()
     {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("w300-cerebellum-role.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let allowed_config = w300_role_config(InferenceProvider::LocalOllama);
        let allowed_calls = Arc::new(AtomicUsize::new(0));
        let allowed_authorizer = coding_role_authorizer(
            crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
                AutonomyLevel::Full,
                Some(writer.clone()),
                allowed_config.tokens.max_per_request,
            ),
            &allowed_config,
            HemisphereRole::Cerebellum,
        )
        .unwrap();
        let allowed = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            Box::new(RoleCountingProvider {
                calls: Arc::clone(&allowed_calls),
            }),
            allowed_authorizer,
            Some("w300-cerebellum".to_owned()),
            "coding.decomposer.w300",
        );
        let decomposer = crate::coding::cerebellum_provider::CerebellumDecomposer::new(allowed);
        assert_eq!(decomposer.complete("plan").await.unwrap(), "decomposition");
        assert_eq!(allowed_calls.load(Ordering::SeqCst), 1);
        drop(decomposer);
        drop(writer);
        join.await.unwrap();
        let request = w300_provider_request_payload(&segment);
        assert_eq!(request["hemisphere_role"], "cerebellum");
        assert_eq!(request["hemisphere_provider"], "local_ollama");
        assert_eq!(request["hemisphere_model"], "w300-cerebellum");

        let denied_config = w300_role_config(InferenceProvider::OpenAi);
        let denied_calls = Arc::new(AtomicUsize::new(0));
        let denied_authorizer = coding_role_authorizer(
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                AutonomyLevel::Full,
            ),
            &denied_config,
            HemisphereRole::Cerebellum,
        )
        .unwrap();
        let denied = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            Box::new(RoleCountingProvider {
                calls: Arc::clone(&denied_calls),
            }),
            denied_authorizer,
            Some("w300-cerebellum".to_owned()),
            "coding.decomposer.w300",
        );
        let error = crate::coding::cerebellum_provider::CerebellumDecomposer::new(denied)
            .complete("plan")
            .await
            .expect_err("configured Cerebellum provider mismatch must stop before transport");
        assert!(
            format!("{error:#}").contains("role dispatch denied"),
            "{error:#}"
        );
        assert_eq!(denied_calls.load(Ordering::SeqCst), 0);
    }

    fn service_code_map_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, CodingServiceConfig) {
        let dir = tempfile::tempdir().unwrap();
        let repository_root = dir.path().join("repo");
        std::fs::create_dir_all(repository_root.join("src")).unwrap();
        std::fs::write(
            repository_root.join("src/auth.rs"),
            "pub fn verify_token() -> bool { true }\n",
        )
        .unwrap();
        let root = crate::code_map::CanonicalRepoRoot::discover(&repository_root).unwrap();
        let code_map_database_path = dir.path().join("code-map.db");
        crate::code_map::rebuild_snapshot(&root, &code_map_database_path, Default::default())
            .unwrap();
        let freedom_config_path = dir.path().join("freedom.yaml");
        std::fs::write(&freedom_config_path, "operator_id: fixture\n").unwrap();
        let neoth_home = dir.path().join("neoth-home");
        std::fs::create_dir_all(&neoth_home).unwrap();
        let config = CodingServiceConfig {
            database_path: dir.path().join("views.db"),
            code_map_database_path: code_map_database_path.clone(),
            neoth_home,
            freedom_config_path,
            freedom_config: crate::config::FreedomConfig::default(),
        };
        (dir, repository_root, code_map_database_path, config)
    }

    fn explicit_auth_stdin_diff() -> crate::code_map::diff_impact::DiffImpactInput {
        crate::code_map::diff_impact::DiffImpactInput::stdin(
            concat!(
                "diff --git a/src/auth.rs b/src/auth.rs\n",
                "--- a/src/auth.rs\n",
                "+++ b/src/auth.rs\n",
                "@@ -1 +1 @@\n",
                "-pub fn verify_token() -> bool { true }\n",
                "+pub fn verify_token() -> bool { false }\n",
            )
            .to_owned(),
        )
    }

    struct RuntimeCountingDecomposer(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl DecomposerLlm for RuntimeCountingDecomposer {
        async fn complete(&self, _: &str) -> Result<String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(
                    r#"{"tasks":[{"title":"Add tests for token verification","task_type":"tests","depends_on":[]}],"clarifying_question":null,"estimated_session_complexity":"fast"}"#
                    .to_owned(),
            )
        }
    }

    async fn start_fixture_runtime(
        service: &LocalCodingService,
        config: &CodingServiceConfig,
        repository_root: &std::path::Path,
        code_map_database_path: &std::path::Path,
        factory_calls: Arc<AtomicUsize>,
        llm_calls: Arc<AtomicUsize>,
    ) -> Result<LocalCodingRunHandle> {
        let views_database_path = config.database_path.clone();
        let request =
            request(repository_root).with_diff_impact_input(Some(explicit_auth_stdin_diff()));
        start_runtime_run_with_worker_factory(
            service,
            config,
            request,
            code_map_database_path,
            move |_run_config, dispatch_plan| async move {
                assert!(dispatch_plan.is_none(), "fixture does not dispatch tasks");
                factory_calls.fetch_add(1, Ordering::SeqCst);
                let worker: Arc<dyn CodingRunWorker> = Arc::new(StoredDecompositionWorker::new(
                    views_database_path,
                    Some("fixture-operator".to_owned()),
                    Arc::new(RuntimeCountingDecomposer(llm_calls)),
                ));
                Ok(worker)
            },
        )
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_runtime_start_rejects_untrusted_maps_before_real_worker_factory_and_provider() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let service = LocalCodingService::new();
                let (valid_dir, valid_root, valid_database, valid_config) =
                    service_code_map_fixture();
                let valid_factory_calls = Arc::new(AtomicUsize::new(0));
                let valid_llm_calls = Arc::new(AtomicUsize::new(0));
                let valid = start_fixture_runtime(
                    &service,
                    &valid_config,
                    &valid_root,
                    &valid_database,
                    Arc::clone(&valid_factory_calls),
                    Arc::clone(&valid_llm_calls),
                )
                .await
                .expect("trusted fixture must reach the real worker factory");
                let valid_terminal = valid.wait_terminal().await.unwrap();
                assert!(matches!(valid_terminal, CodingRunResult::Completed { .. }));
                assert_eq!(valid_factory_calls.load(Ordering::SeqCst), 1);
                assert_eq!(valid_llm_calls.load(Ordering::SeqCst), 1);
                drop(valid_dir);

                let (_dir, repository_root, database_path, config) = service_code_map_fixture();
                std::fs::write(
                    repository_root.join("src/auth.rs"),
                    "pub fn changed_token() -> bool { false }\n",
                )
                .unwrap();
                let factory_calls = Arc::new(AtomicUsize::new(0));
                let llm_calls = Arc::new(AtomicUsize::new(0));
                let stale = start_fixture_runtime(
                    &service,
                    &config,
                    &repository_root,
                    &database_path,
                    Arc::clone(&factory_calls),
                    Arc::clone(&llm_calls),
                )
                .await
                .err()
                .expect("stale snapshot must reject runtime start");
                assert!(
                    !stale.to_string().is_empty(),
                    "stale rejection remains visible"
                );
                assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
                assert_eq!(llm_calls.load(Ordering::SeqCst), 0);

                let (_dir, repository_root, database_path, config) = service_code_map_fixture();
                let root = crate::code_map::CanonicalRepoRoot::discover(&repository_root).unwrap();
                let conn = crate::code_map::persist::open(&database_path).unwrap();
                conn.execute(
                    "UPDATE code_map_roots SET oversize_skipped = 1 WHERE root = ?1",
                    rusqlite::params![root.display()],
                )
                .unwrap();
                drop(conn);
                let factory_calls = Arc::new(AtomicUsize::new(0));
                let llm_calls = Arc::new(AtomicUsize::new(0));
                let partial = start_fixture_runtime(
                    &service,
                    &config,
                    &repository_root,
                    &database_path,
                    Arc::clone(&factory_calls),
                    Arc::clone(&llm_calls),
                )
                .await
                .err()
                .expect("partial snapshot must reject runtime start");
                let partial_text = format!("{partial:#}");
                assert!(
                    partial_text.contains("partial") || partial_text.contains("incomplete"),
                    "partial capture rejection remains visible: {partial_text}"
                );
                assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
                assert_eq!(llm_calls.load(Ordering::SeqCst), 0);

                let (dir, repository_root, database_path, config) = service_code_map_fixture();
                std::fs::rename(&repository_root, dir.path().join("replaced-original")).unwrap();
                std::fs::create_dir_all(repository_root.join("src")).unwrap();
                std::fs::write(
                    repository_root.join("src/auth.rs"),
                    "pub fn verify_token() -> bool { true }\n",
                )
                .unwrap();
                let factory_calls = Arc::new(AtomicUsize::new(0));
                let llm_calls = Arc::new(AtomicUsize::new(0));
                let replaced = start_fixture_runtime(
                    &service,
                    &config,
                    &repository_root,
                    &database_path,
                    Arc::clone(&factory_calls),
                    Arc::clone(&llm_calls),
                )
                .await
                .err()
                .expect("physical root replacement must reject runtime start");
                let replaced_text = format!("{replaced:#}");
                assert!(
                    replaced_text.contains("no longer identifies the indexed directory"),
                    "physical-root replacement rejection remains visible: {replaced_text}"
                );
                assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
                assert_eq!(llm_calls.load(Ordering::SeqCst), 0);
            })
            .await;
    }

    fn approval_test_state() -> Arc<RunState> {
        let (events, _) = broadcast::channel(EVENT_SUBSCRIBER_CAPACITY);
        let (terminal, _) = watch::channel(None);
        let cancellation = CodingCancellation::new();
        Arc::new_cyclic(|weak| RunState {
            snapshot: Mutex::new(CodingRunSnapshot {
                run_id: CodingRunId(91),
                phase: CodingRunPhase::Applying,
                repository_root: std::env::temp_dir(),
                session_id: None,
                cancel_requested: false,
                provider_state: ProviderCallState::Completed,
                task_count: 1,
                pending_patch_approval: None,
                terminal: None,
            }),
            cancellation,
            events,
            terminal,
            gui_patch_approval: GuiPatchApprovalBroker::new(weak.clone()),
        })
    }

    async fn wait_for_pending_metadata(state: &RunState) -> CodingPatchApprovalMetadata {
        for _ in 0..64 {
            if let Some(metadata) = state.snapshot.lock().await.pending_patch_approval.clone() {
                return metadata;
            }
            tokio::task::yield_now().await;
        }
        panic!("native patch approval was not published");
    }

    #[tokio::test]
    async fn native_patch_approval_preview_is_exact_and_response_is_one_use() {
        let state = approval_test_state();
        let broker = state.gui_patch_approval.clone();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            async move {
                broker
                    .request_exact(
                        "canonical:test-repository",
                        "canonical-test-repository".to_owned(),
                        KanbanTaskId(7),
                        "diff --git a/a.rs b/a.rs\n+++ b/a.rs\n+new bytes\n",
                        "binding-7".to_owned(),
                    )
                    .await
            }
        });
        let metadata = wait_for_pending_metadata(&state).await;
        assert_eq!(
            state
                .snapshot
                .lock()
                .await
                .pending_patch_approval
                .as_ref()
                .map(|pending| pending.approval_id),
            Some(metadata.approval_id),
            "snapshot is the recovery source before the advisory event is consumed"
        );
        match broker.preview(metadata.approval_id).await {
            PatchApprovalPreviewResult::Available(preview) => {
                assert_eq!(preview.metadata.request_binding_sha256, "binding-7");
                assert_eq!(
                    preview.patch_text,
                    "diff --git a/a.rs b/a.rs\n+++ b/a.rs\n+new bytes\n"
                );
            }
            PatchApprovalPreviewResult::StaleOrUnknown | PatchApprovalPreviewResult::Expired => {
                panic!("live approval must return its exact preview")
            }
        }
        assert_eq!(
            broker.respond(metadata.approval_id, true).await,
            PatchApprovalResponse::Accepted
        );
        assert_eq!(
            broker.respond(metadata.approval_id, true).await,
            PatchApprovalResponse::StaleOrUnknown
        );
        assert!(
            state.snapshot.lock().await.pending_patch_approval.is_none(),
            "consuming a response clears snapshot recovery with the pending slot"
        );
        let grant = waiter.await.unwrap().unwrap();
        let digest: [u8; 32] =
            Sha256::digest(b"diff --git a/a.rs b/a.rs\n+++ b/a.rs\n+new bytes\n").into();
        assert!(grant.matches(
            "canonical:test-repository",
            KanbanTaskId(7),
            &digest,
            "binding-7",
        ));
        assert!(matches!(
            broker.preview(metadata.approval_id).await,
            PatchApprovalPreviewResult::StaleOrUnknown
        ));
    }

    #[tokio::test]
    async fn native_patch_approval_cancel_and_expiry_remove_raw_preview() {
        let state = approval_test_state();
        let broker = state.gui_patch_approval.clone();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            async move {
                broker
                    .request_exact(
                        "canonical:test-repository",
                        "canonical-test-repository".to_owned(),
                        KanbanTaskId(8),
                        "diff --git a/b.rs b/b.rs\n+++ b/b.rs\n+new bytes\n",
                        "binding-8".to_owned(),
                    )
                    .await
            }
        });
        let metadata = wait_for_pending_metadata(&state).await;
        {
            let mut pending = broker.pending.lock().await;
            pending.as_mut().unwrap().expires_at = tokio::time::Instant::now();
        }
        assert_eq!(
            broker.respond(metadata.approval_id, true).await,
            PatchApprovalResponse::Expired
        );
        assert!(waiter.await.unwrap().is_err());
        assert!(matches!(
            broker.preview(metadata.approval_id).await,
            PatchApprovalPreviewResult::StaleOrUnknown
        ));

        let waiter = tokio::spawn({
            let broker = broker.clone();
            async move {
                broker
                    .request_exact(
                        "canonical:test-repository",
                        "canonical-test-repository".to_owned(),
                        KanbanTaskId(9),
                        "diff --git a/c.rs b/c.rs\n+++ b/c.rs\n+new bytes\n",
                        "binding-9".to_owned(),
                    )
                    .await
            }
        });
        let metadata = wait_for_pending_metadata(&state).await;
        state.cancellation.request();
        assert_eq!(
            broker.respond(metadata.approval_id, true).await,
            PatchApprovalResponse::StaleOrUnknown
        );
        assert!(waiter.await.unwrap().is_err());
        assert!(state.snapshot.lock().await.pending_patch_approval.is_none());
    }

    #[tokio::test]
    async fn consume_during_publication_cannot_leave_stale_snapshot_metadata() {
        let state = approval_test_state();
        let pause = Arc::new(ApprovalPublicationPause::new());
        let broker = state
            .gui_patch_approval
            .clone()
            .with_publication_pause_for_test(Arc::clone(&pause));
        let waiter = tokio::spawn({
            let broker = broker.clone();
            async move {
                broker
                    .request_exact(
                        "canonical:test-repository",
                        "canonical-test-repository".to_owned(),
                        KanbanTaskId(10),
                        "diff --git a/d.rs b/d.rs\n+++ b/d.rs\n+new bytes\n",
                        "binding-10".to_owned(),
                    )
                    .await
            }
        });
        pause.wait_until_entered().await;
        assert!(
            state.snapshot.lock().await.pending_patch_approval.is_none(),
            "the slot is not externally visible until snapshot recovery is installed"
        );
        let approval_id = pause.approval_id();
        let consumer = tokio::spawn({
            let broker = broker.clone();
            async move { broker.respond(approval_id, false).await }
        });
        pause.release.notify_one();
        assert_eq!(consumer.await.unwrap(), PatchApprovalResponse::Rejected);
        assert!(waiter.await.unwrap().is_err());
        assert!(
            state.snapshot.lock().await.pending_patch_approval.is_none(),
            "response removes the slot and mirrored metadata in one ordered transition"
        );
    }

    #[test]
    fn approval_metadata_omits_hostile_diff_header_suffixes() {
        let files = bounded_changed_files(
            "+++ b/src/lib.rs\n+++ b/../secret\n+++ b//absolute\n+++ b/a/./b\n+++ b/a/../../b\n+++ b/a\\b\n+++ b/a\u{7f}b\n+++ b/C:drive\n+++ b/src/main.rs\n",
        );
        assert_eq!(files, vec!["a/b", "src/lib.rs", "src/main.rs"]);
    }

    struct FixtureWorker {
        effects: Arc<AtomicUsize>,
        wait_for_cancel: bool,
    }

    struct PanicWorker;

    #[async_trait::async_trait(?Send)]
    impl CodingRunWorker for PanicWorker {
        async fn run(
            &self,
            _request: CodingStartRequest,
            _progress: CodingRunProgress,
            _cancellation: CodingCancellation,
        ) -> CodingRunResult {
            panic!("fixture worker panic")
        }
    }

    #[async_trait::async_trait(?Send)]
    impl CodingRunWorker for FixtureWorker {
        async fn run(
            &self,
            _request: CodingStartRequest,
            progress: CodingRunProgress,
            cancellation: CodingCancellation,
        ) -> CodingRunResult {
            progress.set_phase(CodingRunPhase::PreparingContext).await;
            if self.wait_for_cancel {
                cancellation.cancelled().await;
                return CodingRunResult::Cancelled {
                    run_id: (progress.state.snapshot.lock().await).run_id,
                    session_id: None,
                    provider_state: ProviderCallState::NotAttempted,
                    effect: CancellationEffect::NoEffect,
                };
            }
            self.effects.fetch_add(1, Ordering::AcqRel);
            let run_id = progress.state.snapshot.lock().await.run_id;
            CodingRunResult::Failed {
                run_id,
                session_id: None,
                message: "fixture failure".to_owned(),
            }
        }
    }

    fn request(root: &std::path::Path) -> CodingStartRequest {
        CodingStartRequest {
            prompt: "implement fixture".to_owned(),
            repository_root: root.to_path_buf(),
            source_channel: "test".to_owned(),
            no_assign: false,
            dispatch: false,
            apply: false,
            apply_confirmation: ApplyConfirmation::Unattended,
            prepared_code_map_context: None,
            diff_impact_input: None,
            brainstorm_spec: None,
        }
    }

    #[test]
    fn source_channel_never_mints_local_apply_confirmation() {
        let root = std::env::current_dir().unwrap();
        let spoofed = CodingStartRequest::new(
            "fixture".to_owned(),
            root.clone(),
            "cli".to_owned(),
            false,
            true,
            true,
        )
        .unwrap();
        assert_eq!(spoofed.apply_confirmation, ApplyConfirmation::Unattended);

        let explicitly_local = CodingStartRequest::new(
            "fixture".to_owned(),
            root.clone(),
            "not-a-cli-label".to_owned(),
            false,
            true,
            true,
        )
        .unwrap()
        .with_local_cli_apply_confirmation();
        assert_eq!(
            explicitly_local.apply_confirmation,
            ApplyConfirmation::LocalCliFlag
        );

        let gui_route = CodingStartRequest::new(
            "fixture".to_owned(),
            root,
            "cli".to_owned(),
            false,
            true,
            true,
        )
        .unwrap()
        .with_gui_apply_route();
        assert_eq!(
            gui_route.apply_confirmation,
            ApplyConfirmation::GuiInteractive
        );
    }

    fn prepared_context() -> PreparedCodeMapContext {
        PreparedCodeMapContext::new(
            "selected source summary".to_owned(),
            vec![CodeMapContextSource {
                kind: CodeMapContextKind::TargetedRecall,
                root: "/fixture/repository".to_owned(),
                root_identity: "fixture-root-identity".to_owned(),
                index_generation: 1,
                graph_generation: 1,
                stale: false,
                selection_truncated: false,
                metadata_redacted: false,
                diff_impact: None,
                selected_files: vec![CodeMapSelectedFile {
                    path: "src/lib.rs".to_owned(),
                    symbols: vec!["fixture".to_owned()],
                }],
                callers: Vec::new(),
            }],
        )
        .unwrap()
    }

    #[test]
    fn dispatch_workers_receive_the_same_prepared_context_snapshot_as_the_request() {
        let root = tempfile::tempdir().unwrap();
        let mut start = request(root.path());
        let prepared = prepared_context();
        start.prepared_code_map_context = Some(prepared.clone());

        let worker_context = prepared_worker_context_for_dispatch(&start)
            .expect("prepared request context must reach the dispatch plan");
        assert_eq!(worker_context.text(), prepared.text());
        assert_eq!(worker_context.sources(), prepared.sources());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_waits_for_joined_no_effect_terminal_result() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir().unwrap();
                let service = LocalCodingService::new();
                let effects = Arc::new(AtomicUsize::new(0));
                let handle = service
                    .start_local(
                        request(root.path()),
                        Arc::new(FixtureWorker {
                            effects: Arc::clone(&effects),
                            wait_for_cancel: true,
                        }),
                    )
                    .await
                    .unwrap();
                let run_id = handle.run_id();
                let result = handle.cancel_and_join().await.unwrap();
                assert!(matches!(
                    result,
                    CodingRunResult::Cancelled {
                        provider_state: ProviderCallState::NotAttempted,
                        effect: CancellationEffect::NoEffect,
                        ..
                    }
                ));
                assert_eq!(effects.load(Ordering::Acquire), 0);
                assert!(matches!(
                    service.snapshot(run_id).await.unwrap().terminal,
                    Some(CodingRunResult::Cancelled { .. })
                ));
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_failure_is_retained_without_being_relabelled_cancelled() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir().unwrap();
                let service = LocalCodingService::new();
                let handle = service
                    .start_local(
                        request(root.path()),
                        Arc::new(FixtureWorker {
                            effects: Arc::new(AtomicUsize::new(0)),
                            wait_for_cancel: false,
                        }),
                    )
                    .await
                    .unwrap();
                let run_id = handle.run_id();
                let result = handle.wait_terminal().await.unwrap();
                assert!(matches!(result, CodingRunResult::Failed { .. }));
                assert!(matches!(
                    service.snapshot(run_id).await.unwrap().terminal,
                    Some(CodingRunResult::Failed { .. })
                ));
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_shutdown_cancels_and_joins_every_active_run() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir().unwrap();
                let service = LocalCodingService::new();
                let handle = service
                    .start_local(
                        request(root.path()),
                        Arc::new(FixtureWorker {
                            effects: Arc::new(AtomicUsize::new(0)),
                            wait_for_cancel: true,
                        }),
                    )
                    .await
                    .unwrap();
                let run_id = handle.run_id();
                service.shutdown_and_join_all().await.unwrap();
                assert!(matches!(
                    service.snapshot(run_id).await.unwrap().terminal,
                    Some(CodingRunResult::Cancelled { .. })
                ));
                assert!(service.registry.active.lock().await.is_empty());
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn panicked_worker_publishes_failed_terminal_and_retires_run() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir().unwrap();
                let service = LocalCodingService::new();
                let handle = service
                    .start_local(request(root.path()), Arc::new(PanicWorker))
                    .await
                    .unwrap();
                let run_id = handle.run_id();
                assert!(matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        handle.wait_terminal(),
                    )
                    .await
                    .expect("panic fallback must publish a terminal result")
                    .unwrap(),
                    CodingRunResult::Failed { .. }
                ));
                assert!(service.registry.active.lock().await.is_empty());
                assert!(matches!(
                    service.snapshot(run_id).await.unwrap().terminal,
                    Some(CodingRunResult::Failed { .. })
                ));
            })
            .await;
    }

    struct DeterministicDecomposer;

    #[async_trait::async_trait]
    impl DecomposerLlm for DeterministicDecomposer {
        async fn complete(&self, _prompt: &str) -> Result<String> {
            Ok(r#"{"tasks":[{"title":"Persist one task","task_type":"tests"}]}"#.to_owned())
        }
    }

    struct GateDecomposer {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl DecomposerLlm for GateDecomposer {
        async fn complete(&self, _prompt: &str) -> Result<String> {
            self.started.notify_one();
            self.release.notified().await;
            Ok(r#"{"tasks":[{"title":"must not persist","task_type":"tests"}]}"#.to_owned())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_worker_records_context_before_fixture_provider_and_inserts_atomically() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir().unwrap();
                let db_path = root.path().join("views.db");
                let service = LocalCodingService::new();
                let mut request = request(root.path());
                request.prompt = "operator secret sk-provenance-must-not-leak".to_owned();
                request.prepared_code_map_context = Some(prepared_context());
                let handle = service
                    .start_local(
                        request,
                        Arc::new(StoredDecompositionWorker::new(
                            db_path.clone(),
                            Some("fixture-operator".to_owned()),
                            Arc::new(DeterministicDecomposer),
                        )),
                    )
                    .await
                    .unwrap();
                let result = handle.wait_terminal().await.unwrap();
                let session_id = match result {
                    CodingRunResult::Completed {
                        session_id,
                        task_count,
                        ..
                    } => {
                        assert_eq!(task_count, 1);
                        session_id
                    }
                    other => panic!("expected deterministic completion, got {other:?}"),
                };
                let conn = crate::memory::store::open(&db_path).unwrap();
                let receipts = store::load_code_map_receipts(&conn, session_id).unwrap();
                assert_eq!(receipts.len(), 1);
                assert_eq!(receipts[0].attempt, 1);
                let persisted = serde_json::to_string(&receipts).unwrap();
                assert!(!persisted.contains("sk-provenance-must-not-leak"));
                assert_eq!(
                    store::list_tasks_for_session(&conn, session_id)
                        .unwrap()
                        .len(),
                    1
                );
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_worker_without_diff_keeps_legacy_provider_path_and_writes_no_code_map_receipt()
    {
        struct CountingDecomposer(Arc<AtomicUsize>);

        #[async_trait::async_trait]
        impl DecomposerLlm for CountingDecomposer {
            async fn complete(&self, _: &str) -> Result<String> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(
                    r#"{"tasks":[{"title":"Add tests to preserve legacy request","task_type":"tests","depends_on":[]}],"clarifying_question":null,"estimated_session_complexity":"fast"}"#
                        .to_owned(),
                )
            }
        }

        tokio::task::LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir().unwrap();
                let db_path = root.path().join("views.db");
                let calls = Arc::new(AtomicUsize::new(0));
                let service = LocalCodingService::new();
                let handle = service
                    .start_local(
                        request(root.path()),
                        Arc::new(StoredDecompositionWorker::new(
                            db_path.clone(),
                            None,
                            Arc::new(CountingDecomposer(Arc::clone(&calls))),
                        )),
                    )
                    .await
                    .unwrap();
                let result = handle.wait_terminal().await.unwrap();
                let session_id = match result {
                    CodingRunResult::Completed {
                        session_id,
                        task_count,
                        ..
                    } => {
                        assert_eq!(task_count, 1);
                        session_id
                    }
                    other => panic!("expected legacy completion, got {other:?}"),
                };
                assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
                let conn = crate::memory::store::open(&db_path).unwrap();
                assert!(
                    store::load_code_map_receipts(&conn, session_id)
                        .unwrap()
                        .is_empty(),
                    "the no-diff service path must retain its legacy no-receipt behavior"
                );
                let tasks = store::list_tasks_for_session(&conn, session_id).unwrap();
                assert_eq!(tasks.len(), 1);
                assert_eq!(tasks[0].hemisphere, crate::coding::types::Hemisphere::Left);
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn successful_service_dispatch_enqueues_one_counts_only_session_summary() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir().unwrap();
                let db_path = root.path().join("views.db");
                let queue_path = root.path().join("proactive_queue.json");
                let mut queue = crate::proactive::ProactiveQueue::new();
                queue
                    .enqueue(crate::proactive::ProactiveItem {
                        priority: 10,
                        dedup_key: "retained".to_owned(),
                        channel: String::new(),
                        account_id: None,
                        account_binding: None,
                        source: "test".to_owned(),
                        body: "keep me".to_owned(),
                        scheduled_for_unix: 0,
                        is_failure: false,
                        expires_unix: 0,
                    })
                    .unwrap();
                queue.save_to(&queue_path).unwrap();

                let service = LocalCodingService::new();
                let mut request = request(root.path());
                request.dispatch = true;
                let worker = Arc::new(
                    StoredDecompositionWorker::new(
                        db_path,
                        None,
                        Arc::new(DeterministicDecomposer),
                    )
                    .with_dispatch_plan(CodingDispatchPlan::new(
                        HemisphereWorkerSet::new(),
                        None,
                        None,
                    ))
                    .with_proactive_queue(queue_path.clone()),
                );
                let handle = service.start_local(request, worker.clone()).await.unwrap();
                let result = handle.wait_terminal().await.unwrap();
                let session_id = match &result {
                    CodingRunResult::Completed {
                        session_id,
                        dispatch: Some(_),
                        ..
                    } => *session_id,
                    other => panic!("expected completed dispatched run, got {other:?}"),
                };
                let summary = worker
                    .take_proactive_summary()
                    .expect("successful dispatched worker must stage a summary candidate");
                commit_dispatch_summary_for_terminal(&result, Some(summary));

                let loaded = crate::proactive::ProactiveQueue::load_from(&queue_path).unwrap();
                let items = loaded.peek();
                assert!(items.iter().any(|item| item.dedup_key == "retained"));
                let summary = items
                    .iter()
                    .find(|item| {
                        item.dedup_key == format!("coding:session-summary:{}", session_id.raw())
                    })
                    .expect("successful dispatch must enqueue exactly its session summary");
                assert_eq!(summary.source, "coding_session");
                assert!(!summary.body.contains("Persist one task"));
            })
            .await;
    }

    #[test]
    fn provider_audit_failure_terminal_does_not_commit_staged_summary() {
        let root = tempfile::tempdir().unwrap();
        let queue_path = root.path().join("proactive_queue.json");
        let mut queue = crate::proactive::ProactiveQueue::new();
        queue
            .enqueue(crate::proactive::ProactiveItem {
                priority: 10,
                dedup_key: "retained".to_owned(),
                channel: String::new(),
                account_id: None,
                account_binding: None,
                source: "test".to_owned(),
                body: "keep me".to_owned(),
                scheduled_for_unix: 0,
                is_failure: false,
                expires_unix: 0,
            })
            .unwrap();
        queue.save_to(&queue_path).unwrap();
        let staged = prepare_dispatch_summary(
            &queue_path,
            &crate::coding::dispatcher::DispatchOutcome::default(),
            KanbanSessionId(42),
        );
        let audit_failure = CodingRunResult::Failed {
            run_id: CodingRunId(1),
            session_id: Some(KanbanSessionId(42)),
            message: "coding operation failed; inspect scoped local diagnostics".to_owned(),
        };

        commit_dispatch_summary_for_terminal(&audit_failure, Some(staged));

        let loaded = crate::proactive::ProactiveQueue::load_from(&queue_path).unwrap();
        assert_eq!(loaded.peek().len(), 1);
        assert_eq!(loaded.peek()[0].dedup_key, "retained");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_after_provider_completion_skips_atomic_task_insertion() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let root = tempfile::tempdir().unwrap();
                let db_path = root.path().join("views.db");
                let service = LocalCodingService::new();
                let started = Arc::new(tokio::sync::Notify::new());
                let release = Arc::new(tokio::sync::Notify::new());
                let handle = service
                    .start_local(
                        request(root.path()),
                        Arc::new(StoredDecompositionWorker::new(
                            db_path.clone(),
                            None,
                            Arc::new(GateDecomposer {
                                started: Arc::clone(&started),
                                release: Arc::clone(&release),
                            }),
                        )),
                    )
                    .await
                    .unwrap();
                started.notified().await;
                handle.request_cancel().await;
                release.notify_one();
                let result = handle.wait_terminal().await.unwrap();
                assert!(matches!(
                    &result,
                    CodingRunResult::Cancelled {
                        provider_state: ProviderCallState::Completed,
                        effect: CancellationEffect::ProviderCompletedNoTasks,
                        ..
                    }
                ));
                let conn = crate::memory::store::open(&db_path).unwrap();
                assert!(
                    store::list_tasks_for_session(
                        &conn,
                        match result {
                            CodingRunResult::Cancelled {
                                session_id: Some(session_id),
                                ..
                            } => session_id,
                            _ => unreachable!(),
                        },
                    )
                    .unwrap()
                    .is_empty()
                );
            })
            .await;
    }

    #[test]
    fn public_controller_and_observer_handles_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CodingServiceConfig>();
        assert_send::<CodingService>();
        assert_send::<CodingRunHandle>();
        assert_send::<CodingStartRequest>();
        assert_send::<CodingRunSnapshot>();
        assert_send::<CodingRunResult>();
    }
}

#[cfg(test)]
#[path = "service_runtime_tests.rs"]
mod runtime_tests;
