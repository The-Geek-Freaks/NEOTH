//! Typed GUI ownership for native coding runs.
//!
//! The controller deliberately owns only GUI operation identity, revision, and
//! cancellation routing. [`neothd::coding::CodingService`] owns the runtime,
//! provider bindings, SQLite connections, repository context, worker task, and
//! terminal receipt.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};

use neothd::coding::{
    CodingPatchApprovalId, CodingPatchApprovalMetadata, CodingRunHandle, CodingRunId,
    CodingRunResult, CodingService, CodingServiceConfig, CodingStartRequest,
    PatchApprovalPreviewResult, PatchApprovalResponse,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodingCancelState {
    /// A start command has been reserved. The command bridge requests core
    /// cancellation immediately after the run id becomes available.
    DeferredStart { revision: u64 },
    /// Core has accepted a run id and received the cancellation request.
    Requested { revision: u64, run_id: CodingRunId },
}

#[derive(Debug)]
enum ActiveCodingRun {
    Starting {
        revision: u64,
        cancel_requested: bool,
    },
    Running {
        revision: u64,
        run_id: CodingRunId,
        cancel_requested: bool,
    },
}

#[derive(Default)]
struct ControllerState {
    next_revision: u64,
    active: Option<ActiveCodingRun>,
    // Only bounded metadata reaches this controller state. The exact diff is
    // requested from Core only while this matching live entry remains pending.
    pending_patch_approval: Option<CodingPatchApprovalMetadata>,
    // UI double-clicks and delayed callbacks cannot send a second response for
    // an approval that this GUI revision has already handed to Core.
    submitted_patch_approvals: HashSet<String>,
    shutting_down: bool,
}

/// A started run keeps the service's observation handle with the bridge
/// worker. UI consumers may subscribe and wait, but cannot obtain a worker or
/// provider handle from it.
pub struct StartedCodingRun {
    revision: u64,
    run_id: CodingRunId,
    handle: CodingRunHandle,
    deferred_cancel_error: Option<String>,
}

impl StartedCodingRun {
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn run_id(&self) -> CodingRunId {
        self.run_id
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<neothd::coding::CodingRunEvent> {
        self.handle.subscribe()
    }

    /// A cancellation that arrived while `start` was awaiting a run id is
    /// replayed immediately. Retain a delivery error so the GUI keeps the run
    /// visible and lets the operator retry cancellation instead of falsely
    /// reporting that startup failed.
    pub fn deferred_cancel_error(&self) -> Option<&str> {
        self.deferred_cancel_error.as_deref()
    }

    /// Wait for the terminal receipt, then take the service's bounded join
    /// path. Calling `cancel_and_join` after the watch already observed a
    /// terminal result cannot retroactively cancel completed work; it joins a
    /// still-active worker or reads the retained terminal receipt.
    pub async fn wait_terminal_and_join(&mut self) -> Result<CodingRunResult> {
        let observed = self.handle.wait_terminal().await?;
        let joined = self.handle.cancel_and_join().await?;
        anyhow::ensure!(
            observed == joined,
            "coding service terminal receipt changed while joining"
        );
        Ok(joined)
    }
}

/// One GUI process owns at most one native Coding service run at a time.
/// The service remains the authority for worker joining and terminal results;
/// this layer only prevents stale GUI completion/cancel actions crossing runs.
pub struct CodingController {
    service: Mutex<Option<CodingService>>,
    state: Mutex<ControllerState>,
    // Serializes the point where a GUI reservation becomes a service-owned
    // run with shutdown admission. It intentionally spans `service.start` so
    // a close cannot observe "no service" and then let a late start escape.
    admission: tokio::sync::Mutex<()>,
}

impl Default for CodingController {
    fn default() -> Self {
        Self::new()
    }
}

impl CodingController {
    pub fn new() -> Self {
        Self {
            service: Mutex::new(None),
            state: Mutex::new(ControllerState::default()),
            admission: tokio::sync::Mutex::new(()),
        }
    }

    /// Reserves the one GUI operation slot before a background bridge starts.
    pub fn begin_start(&self) -> Result<u64> {
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        anyhow::ensure!(
            !state.shutting_down,
            "native coding service is shutting down"
        );
        if state.active.is_some() {
            bail!("A native coding run is already active.");
        }
        state.next_revision = state
            .next_revision
            .checked_add(1)
            .context("coding operation revision overflow")?;
        let revision = state.next_revision;
        state.pending_patch_approval = None;
        state.submitted_patch_approvals.clear();
        state.active = Some(ActiveCodingRun::Starting {
            revision,
            cancel_requested: false,
        });
        Ok(revision)
    }

    /// Sends an explicit operator request to the shared service. A cancellation
    /// that arrived during `Starting` is forwarded as soon as the service
    /// returns the opaque run id.
    pub async fn start_reserved(
        &self,
        revision: u64,
        request: CodingStartRequest,
    ) -> Result<StartedCodingRun> {
        let _admission = self.admission.lock().await;
        self.ensure_start_reservation(revision)?;
        if self.is_shutting_down() {
            self.clear_start_reservation(revision);
            bail!("native coding service is shutting down");
        }
        let service = match self.service() {
            Ok(service) => service,
            Err(error) => {
                self.clear_start_reservation(revision);
                return Err(error);
            }
        };
        let handle = match service.start(request).await {
            Ok(handle) => handle,
            Err(error) => {
                self.clear_start_reservation(revision);
                return Err(error);
            }
        };
        let run_id = handle.run_id();
        let cancel_requested = match self.activate(revision, run_id) {
            Ok(cancel_requested) => cancel_requested,
            Err(error) => {
                // A service-accepted run must never be orphaned merely
                // because its GUI reservation can no longer own it.
                let cleanup = handle.cancel_and_join().await;
                return match cleanup {
                    Ok(_) => Err(error),
                    Err(cleanup_error) => Err(error.context(format!(
                        "also could not cancel and join unowned coding run {}: {cleanup_error:#}",
                        run_id.raw()
                    ))),
                };
            }
        };
        let deferred_cancel_error = if cancel_requested {
            service.request_cancel(run_id).await.err().map(|error| {
                format!(
                    "forward deferred cancellation for run {}: {error:#}",
                    run_id.raw()
                )
            })
        } else {
            None
        };
        Ok(StartedCodingRun {
            revision,
            run_id,
            handle,
            deferred_cancel_error,
        })
    }

    /// Rejects future GUI starts, carries a cancellation request across a
    /// still-reserved start, and waits for Core to join every active worker and
    /// its owned runtime thread. Dropping the controller is never a shutdown
    /// substitute.
    pub async fn shutdown_and_join(&self) -> Result<()> {
        let _admission = self.admission.lock().await;
        let service = {
            let mut state = self.state.lock().expect("coding controller lock poisoned");
            state.shutting_down = true;
            match state.active.as_mut() {
                Some(ActiveCodingRun::Starting {
                    cancel_requested, ..
                })
                | Some(ActiveCodingRun::Running {
                    cancel_requested, ..
                }) => *cancel_requested = true,
                None => {}
            }
            // A service shutdown invalidates its in-memory broker. Clear the
            // GUI copy before awaiting Core so a queued event or preview
            // cannot repopulate the closing window.
            state.pending_patch_approval = None;
            state.submitted_patch_approvals.clear();
            self.service
                .lock()
                .expect("coding service lock poisoned")
                .clone()
        };

        if let Some(service) = service {
            service.shutdown_and_join().await?;
        }

        self.state
            .lock()
            .expect("coding controller lock poisoned")
            .active = None;
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        state.pending_patch_approval = None;
        state.submitted_patch_approvals.clear();
        Ok(())
    }

    /// Signals cancellation for this exact GUI revision without claiming
    /// completion. A queued stale Cancel click is a no-op, so it can never
    /// target a run started later by Settings or Buddy. The terminal bridge
    /// must still await the service receipt and then call [`Self::finish`].
    pub async fn request_cancel(
        &self,
        expected_revision: u64,
    ) -> Result<Option<CodingCancelState>> {
        let Some(target) = self.prepare_cancel(expected_revision) else {
            return Ok(None);
        };
        self.dispatch_prepared_cancel(target).await?;
        Ok(Some(target))
    }

    /// Synchronously fences the exact GUI revision against further preview or
    /// approval work. Call this on the UI callback thread before clearing the
    /// modal or spawning the asynchronous Core cancellation delivery.
    pub fn prepare_cancel(&self, expected_revision: u64) -> Option<CodingCancelState> {
        self.mark_cancel_requested(expected_revision)
    }

    /// Delivers a cancellation that [`Self::prepare_cancel`] has already
    /// fenced locally. Keeping the delivery separate prevents the UI from
    /// leaving the approval window live while a background runtime starts.
    pub async fn dispatch_prepared_cancel(&self, target: CodingCancelState) -> Result<()> {
        if let CodingCancelState::Requested { run_id, .. } = target {
            self.service()?.request_cancel(run_id).await?;
        }
        Ok(())
    }

    /// Releases only the exact run/revision after the service supplied its
    /// terminal result. Older UI workers cannot clear a newer run.
    pub fn finish(&self, revision: u64, run_id: CodingRunId) -> bool {
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        let matches = state.active.as_ref().is_some_and(|active| {
            matches!(
                active,
                ActiveCodingRun::Running {
                    revision: active_revision,
                    run_id: active_run_id,
                    ..
                } if *active_revision == revision && *active_run_id == run_id
            )
        });
        if matches {
            state.active = None;
            state.pending_patch_approval = None;
            state.submitted_patch_approvals.clear();
        }
        matches
    }

    /// Records bounded Core metadata for the current UI operation. Repeating
    /// the same event/snapshot is harmless; a later patch replaces only the
    /// displayed pending identity, never a response already sent to Core.
    pub fn observe_patch_approval(
        &self,
        revision: u64,
        run_id: CodingRunId,
        metadata: CodingPatchApprovalMetadata,
    ) -> bool {
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        if !self.approval_admission_open(&state, revision, run_id) {
            return false;
        }
        if state
            .pending_patch_approval
            .as_ref()
            .is_some_and(|pending| pending.approval_id == metadata.approval_id)
        {
            return true;
        }
        state.pending_patch_approval = Some(metadata);
        true
    }

    /// Recovers the service-owned pending metadata after the initial event
    /// subscription or a bounded broadcast lag. It never reconstructs an
    /// approval from disk and never fetches raw patch text.
    pub async fn recover_patch_approval(
        &self,
        revision: u64,
        run_id: CodingRunId,
    ) -> Option<CodingPatchApprovalMetadata> {
        if !self.is_approval_admission_open(revision, run_id) {
            return None;
        }
        let metadata = self
            .service()
            .ok()?
            .snapshot(run_id)
            .await?
            .pending_patch_approval?;
        if self.observe_patch_approval(revision, run_id, metadata.clone()) {
            Some(metadata)
        } else {
            None
        }
    }

    /// Obtains the exact accepted text only for the current pending metadata.
    /// The second fence prevents a delayed preview for patch A from painting a
    /// newer patch B in the same run.
    pub async fn patch_approval_preview(
        &self,
        revision: u64,
        run_id: CodingRunId,
        approval_id: &str,
    ) -> Result<Option<PatchApprovalPreviewResult>> {
        let approval_id = {
            let state = self.state.lock().expect("coding controller lock poisoned");
            let pending = state.pending_patch_approval.as_ref().filter(|pending| {
                self.approval_admission_open(&state, revision, run_id)
                    && pending.approval_id.to_string() == approval_id
            });
            let Some(pending) = pending else {
                return Ok(None);
            };
            pending.approval_id
        };
        let preview = self
            .service()?
            .patch_approval_preview(run_id, approval_id)
            .await?;
        if self.is_patch_approval_current(revision, run_id, &approval_id.to_string()) {
            Ok(Some(preview))
        } else {
            Ok(None)
        }
    }

    /// Sends one explicit decision for the exact visible approval. The
    /// submitted-id fence is local UI ownership only; Core still consumes the
    /// opaque one-use broker entry before any authority is created.
    pub async fn respond_patch_approval(
        &self,
        revision: u64,
        run_id: CodingRunId,
        approval_id: &str,
        approved: bool,
    ) -> Result<Option<PatchApprovalResponse>> {
        let Some(core_approval_id) =
            self.reserve_patch_approval_response(revision, run_id, approval_id)
        else {
            return Ok(None);
        };
        // Cancellation/shutdown may have won after the local reservation but
        // before this task reaches the service command edge.
        if !self.is_patch_approval_current(revision, run_id, approval_id) {
            return Ok(None);
        }
        let response = self
            .service()?
            .respond_patch_approval(run_id, core_approval_id, approved)
            .await?;
        Ok(Some(response))
    }

    fn reserve_patch_approval_response(
        &self,
        revision: u64,
        run_id: CodingRunId,
        approval_id: &str,
    ) -> Option<CodingPatchApprovalId> {
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        if !self.approval_admission_open(&state, revision, run_id)
            || state
                .pending_patch_approval
                .as_ref()
                .is_none_or(|pending| pending.approval_id.to_string() != approval_id)
            || !state
                .submitted_patch_approvals
                .insert(approval_id.to_owned())
        {
            return None;
        }
        Some(
            state
                .pending_patch_approval
                .as_ref()
                .expect("matching pending approval")
                .approval_id,
        )
    }

    /// Clears only the exact completed/stale approval. A late completion for
    /// patch A cannot close patch B when both belong to the same run.
    pub fn clear_patch_approval(
        &self,
        revision: u64,
        run_id: CodingRunId,
        approval_id: &str,
    ) -> bool {
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        if !self.approval_admission_open(&state, revision, run_id)
            || state
                .pending_patch_approval
                .as_ref()
                .is_none_or(|pending| pending.approval_id.to_string() != approval_id)
        {
            return false;
        }
        state.pending_patch_approval = None;
        true
    }

    pub fn has_active_run(&self) -> bool {
        self.state
            .lock()
            .expect("coding controller lock poisoned")
            .active
            .is_some()
    }

    pub fn current_run_id(&self, revision: u64) -> Option<CodingRunId> {
        self.state
            .lock()
            .expect("coding controller lock poisoned")
            .active
            .as_ref()
            .and_then(|active| match active {
                ActiveCodingRun::Running {
                    revision: active_revision,
                    run_id,
                    ..
                } if *active_revision == revision => Some(*run_id),
                ActiveCodingRun::Starting { .. } | ActiveCodingRun::Running { .. } => None,
            })
    }

    fn is_shutting_down(&self) -> bool {
        self.state
            .lock()
            .expect("coding controller lock poisoned")
            .shutting_down
    }

    pub fn is_current(&self, revision: u64, run_id: CodingRunId) -> bool {
        self.state
            .lock()
            .expect("coding controller lock poisoned")
            .active
            .as_ref()
            .is_some_and(|active| {
                matches!(
                    active,
                    ActiveCodingRun::Running {
                        revision: active_revision,
                        run_id: active_run_id,
                        ..
                    } if *active_revision == revision && *active_run_id == run_id
                )
            })
    }

    pub fn is_patch_approval_current(
        &self,
        revision: u64,
        run_id: CodingRunId,
        approval_id: &str,
    ) -> bool {
        let state = self.state.lock().expect("coding controller lock poisoned");
        self.approval_admission_open(&state, revision, run_id)
            && state
                .pending_patch_approval
                .as_ref()
                .is_some_and(|pending| pending.approval_id.to_string() == approval_id)
    }

    fn is_approval_admission_open(&self, revision: u64, run_id: CodingRunId) -> bool {
        let state = self.state.lock().expect("coding controller lock poisoned");
        self.approval_admission_open(&state, revision, run_id)
    }

    fn approval_admission_open(
        &self,
        state: &ControllerState,
        revision: u64,
        run_id: CodingRunId,
    ) -> bool {
        if state.shutting_down {
            return false;
        }
        state.active.as_ref().is_some_and(|active| {
            matches!(
                active,
                ActiveCodingRun::Running {
                    revision: active_revision,
                    run_id: active_run_id,
                    cancel_requested,
                } if *active_revision == revision
                    && *active_run_id == run_id
                    && !*cancel_requested
            )
        })
    }

    /// Marks cancellation and revokes the GUI's ephemeral patch view in one
    /// mutex acquisition, before the asynchronous service command starts.
    fn mark_cancel_requested(&self, expected_revision: u64) -> Option<CodingCancelState> {
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        let target = match state.active.as_mut() {
            None => return None,
            Some(ActiveCodingRun::Starting {
                revision,
                cancel_requested,
            }) if *revision == expected_revision => {
                *cancel_requested = true;
                CodingCancelState::DeferredStart {
                    revision: *revision,
                }
            }
            Some(ActiveCodingRun::Running {
                revision,
                run_id,
                cancel_requested,
            }) if *revision == expected_revision => {
                *cancel_requested = true;
                CodingCancelState::Requested {
                    revision: *revision,
                    run_id: *run_id,
                }
            }
            Some(_) => return None,
        };
        state.pending_patch_approval = None;
        state.submitted_patch_approvals.clear();
        Some(target)
    }

    /// Checks both `Starting` and `Running` ownership for a queued UI
    /// cancellation response. A terminal worker clears the slot before its
    /// UI receipt is posted, so those late responses must be discarded.
    pub fn is_active_revision(&self, revision: u64) -> bool {
        self.state
            .lock()
            .expect("coding controller lock poisoned")
            .active
            .as_ref()
            .is_some_and(|active| match active {
                ActiveCodingRun::Starting {
                    revision: active_revision,
                    ..
                }
                | ActiveCodingRun::Running {
                    revision: active_revision,
                    ..
                } => *active_revision == revision,
            })
    }

    fn ensure_start_reservation(&self, revision: u64) -> Result<()> {
        let state = self.state.lock().expect("coding controller lock poisoned");
        anyhow::ensure!(
            matches!(
                state.active.as_ref(),
                Some(ActiveCodingRun::Starting {
                    revision: active_revision,
                    ..
                }) if *active_revision == revision
            ),
            "native coding start reservation is stale"
        );
        Ok(())
    }

    fn activate(&self, revision: u64, run_id: CodingRunId) -> Result<bool> {
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        let (active_revision, cancel_requested) = match state.active.as_ref() {
            Some(ActiveCodingRun::Starting {
                revision: active_revision,
                cancel_requested,
            }) => (*active_revision, *cancel_requested),
            _ => bail!("native coding start reservation is no longer active"),
        };
        anyhow::ensure!(
            active_revision == revision,
            "native coding start reservation is stale"
        );
        state.active = Some(ActiveCodingRun::Running {
            revision,
            run_id,
            cancel_requested,
        });
        Ok(cancel_requested)
    }

    fn clear_start_reservation(&self, revision: u64) {
        let mut state = self.state.lock().expect("coding controller lock poisoned");
        if matches!(
            state.active.as_ref(),
            Some(ActiveCodingRun::Starting {
                revision: active_revision,
                ..
            }) if *active_revision == revision
        ) {
            state.active = None;
        }
    }

    fn service(&self) -> Result<CodingService> {
        let mut service = self.service.lock().expect("coding service lock poisoned");
        if let Some(service) = service.as_ref() {
            return Ok(service.clone());
        }
        let neoth_home = neothd::config::FreedomConfig::default_neoth_home();
        let freedom_config = neothd::config::FreedomConfig::load_from_default_path()
            .context("load freedom configuration for native coding service")?;
        let started = CodingService::spawn(CodingServiceConfig {
            database_path: neothd::memory::store::default_path(),
            neoth_home,
            freedom_config_path: neothd::config::FreedomConfig::default_path(),
            freedom_config,
        })?;
        *service = Some(started.clone());
        Ok(started)
    }
}

/// Constructs only the service's public request DTO. The GUI never creates
/// provider bindings, database connections, or code-map context objects.
pub fn native_coding_request(
    prompt: String,
    repository_root: PathBuf,
    source_channel: String,
    no_assign: bool,
    dispatch: bool,
    apply: bool,
) -> Result<CodingStartRequest> {
    CodingStartRequest::new(
        prompt,
        repository_root,
        source_channel,
        no_assign,
        dispatch,
        apply,
    )
    // This only routes an apply-capable GUI/Buddy run to Core's later
    // interactive request. It does not preconfirm a patch or weaken Gate.
    .map(CodingStartRequest::with_gui_apply_route)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use neothd::coding::{
        CodingPatchApprovalId, CodingPatchApprovalMetadata, CodingRunId, KanbanTaskId,
    };

    use super::{CodingCancelState, CodingController, native_coding_request};

    fn test_run_id(raw: u64) -> CodingRunId {
        serde_json::from_str(&raw.to_string()).expect("test CodingRunId json")
    }

    fn approval_metadata(id: &str) -> CodingPatchApprovalMetadata {
        CodingPatchApprovalMetadata {
            approval_id: id
                .parse::<CodingPatchApprovalId>()
                .expect("test approval id"),
            task_id: serde_json::from_str::<KanbanTaskId>("42").expect("test task id"),
            repository_display: "C:/canonical/repository".into(),
            patch_sha256: "a".repeat(64),
            request_binding_sha256: "b".repeat(64),
            changed_files: vec!["src/example.rs".into()],
            expires_unix: i64::MAX,
        }
    }

    fn active_controller() -> (CodingController, u64, CodingRunId) {
        let controller = CodingController::new();
        let revision = controller.begin_start().expect("reserve test run");
        let run_id = test_run_id(9);
        controller
            .activate(revision, run_id)
            .expect("activate test run");
        (controller, revision, run_id)
    }

    #[test]
    fn only_one_gui_start_reservation_can_be_active() {
        let controller = CodingController::new();
        let revision = controller.begin_start().unwrap();
        assert_eq!(revision, 1);
        assert!(controller.has_active_run());
        assert!(controller.begin_start().is_err());
    }

    #[test]
    fn cancellation_during_start_is_deferred_without_claiming_completion() {
        let controller = CodingController::new();
        let revision = controller.begin_start().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let cancelled = runtime
            .block_on(controller.request_cancel(revision))
            .unwrap();

        assert_eq!(
            cancelled,
            Some(CodingCancelState::DeferredStart { revision })
        );
        assert!(controller.has_active_run());
        // A late startup failure may release only its own reservation, after
        // which a fresh GUI action receives a new revision.
        controller.clear_start_reservation(revision);
        assert!(!controller.has_active_run());
        assert_eq!(controller.begin_start().unwrap(), revision + 1);
    }

    #[test]
    fn stale_cancel_revision_cannot_mutate_the_active_reservation() {
        let controller = CodingController::new();
        let revision = controller.begin_start().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let cancelled = runtime
            .block_on(controller.request_cancel(revision + 1))
            .unwrap();

        assert_eq!(cancelled, None);
        assert!(controller.ensure_start_reservation(revision).is_ok());
        assert_eq!(
            runtime
                .block_on(controller.request_cancel(revision))
                .unwrap(),
            Some(CodingCancelState::DeferredStart { revision })
        );
    }

    #[test]
    fn stale_start_cleanup_cannot_release_a_newer_reservation() {
        let controller = CodingController::new();
        let stale_revision = controller.begin_start().unwrap();
        controller.clear_start_reservation(stale_revision);
        let current_revision = controller.begin_start().unwrap();

        controller.clear_start_reservation(stale_revision);

        assert!(controller.has_active_run());
        assert!(
            controller
                .ensure_start_reservation(current_revision)
                .is_ok()
        );
    }

    #[test]
    fn shutdown_without_a_started_service_rejects_future_gui_starts() {
        let controller = CodingController::new();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        runtime.block_on(controller.shutdown_and_join()).unwrap();

        assert!(!controller.has_active_run());
        assert!(controller.begin_start().is_err());
    }

    #[test]
    fn public_request_constructor_enforces_explicit_safe_intent() {
        assert!(
            native_coding_request(
                "implement it".into(),
                PathBuf::from("relative-root"),
                "gui".into(),
                false,
                false,
                false,
            )
            .is_err()
        );
        assert!(
            native_coding_request(
                "implement it".into(),
                std::env::temp_dir().join("explicit-root"),
                "gui".into(),
                false,
                false,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn patch_approval_ui_fence_rejects_delayed_previous_patch_clear() {
        let (controller, revision, run_id) = active_controller();
        let first = approval_metadata("00000000-0000-0000-0000-000000000001");
        let second = approval_metadata("00000000-0000-0000-0000-000000000002");
        let first_id = first.approval_id.to_string();
        let second_id = second.approval_id.to_string();

        assert!(controller.observe_patch_approval(revision, run_id, first));
        assert!(controller.observe_patch_approval(revision, run_id, second));
        assert!(!controller.clear_patch_approval(revision, run_id, &first_id));
        assert!(controller.is_patch_approval_current(revision, run_id, &second_id));
        assert!(controller.clear_patch_approval(revision, run_id, &second_id));
    }

    #[test]
    fn patch_approval_response_is_reserved_only_once_per_visible_id() {
        let (controller, revision, run_id) = active_controller();
        let metadata = approval_metadata("00000000-0000-0000-0000-000000000003");
        let approval_id = metadata.approval_id.to_string();
        assert!(controller.observe_patch_approval(revision, run_id, metadata));

        assert!(
            controller
                .reserve_patch_approval_response(revision, run_id, &approval_id)
                .is_some()
        );
        assert!(
            controller
                .reserve_patch_approval_response(revision, run_id, &approval_id)
                .is_none()
        );
    }

    #[test]
    fn cancellation_synchronously_revokes_pending_approval_before_core_cancel() {
        let (controller, revision, run_id) = active_controller();
        let metadata = approval_metadata("00000000-0000-0000-0000-000000000004");
        let approval_id = metadata.approval_id.to_string();
        assert!(controller.observe_patch_approval(revision, run_id, metadata.clone()));

        assert_eq!(
            controller.prepare_cancel(revision),
            Some(CodingCancelState::Requested { revision, run_id })
        );
        assert!(!controller.is_patch_approval_current(revision, run_id, &approval_id));
        assert!(!controller.observe_patch_approval(revision, run_id, metadata));
        assert!(
            controller
                .reserve_patch_approval_response(revision, run_id, &approval_id)
                .is_none()
        );
    }

    #[test]
    fn shutdown_synchronously_rejects_delayed_patch_approval_observation() {
        let (controller, revision, run_id) = active_controller();
        let metadata = approval_metadata("00000000-0000-0000-0000-000000000005");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");

        runtime
            .block_on(controller.shutdown_and_join())
            .expect("shutdown without a started service");

        assert!(!controller.observe_patch_approval(revision, run_id, metadata));
        assert!(!controller.is_current(revision, run_id));
    }
}
