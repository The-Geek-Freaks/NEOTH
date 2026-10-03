//! Retained live-audio owner for the A2 registry.
//!
//! This is deliberately a concrete adapter over the reviewed W2274 session:
//! microphone authority is kept here until `ConversationSession::open` consumes
//! it, while provider decisions are forwarded only to the running session.

#[cfg(feature = "live-audio")]
use std::sync::Arc;
#[cfg(feature = "live-audio")]
use tokio::sync::Mutex;

#[cfg(feature = "live-audio")]
use super::conversation_protocol::*;
#[cfg(feature = "live-audio")]
use super::conversation_registry::RetainedConversationOwner;

/// All configuration/WAL/credential inputs are copied from the active daemon
/// incarnation by `serve`; this owner accepts no GUI-selected home, provider,
/// device, or credential value.
#[cfg(feature = "live-audio")]
pub(crate) struct LiveConversationOwnerInputs {
    pub(crate) dependencies: crate::media::conversation_loop::ConversationDependencies,
    pub(crate) capture: crate::media::live_capture::CpalCaptureConfig,
    pub(crate) microphone: crate::permissions::microphone::MicConsentStore,
    pub(crate) bridge: Arc<dyn crate::daemon::gui_chat_bridge::GuiChatBridge>,
}

#[cfg(feature = "live-audio")]
struct ActiveRun {
    request_id: ConversationRequestId,
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    generation: u64,
    control: tokio::sync::mpsc::Sender<crate::media::conversation_loop::A2Control>,
    task: tokio::task::JoinHandle<Result<(), &'static str>>,
    pump: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "live-audio")]
struct OpeningRun {
    request_id: ConversationRequestId,
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    generation: u64,
    scope: crate::media::conversation_scope::CancelScope,
    task: tokio::task::JoinHandle<OpeningCompletion>,
}

#[cfg(feature = "live-audio")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RetainedOwnerTaskKind {
    Reap,
    Settlement,
}

#[cfg(feature = "live-audio")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RetainedSettlementIntent {
    Stop,
    Revoke,
    Close,
    ReapActive,
}

#[cfg(feature = "live-audio")]
struct RetainedOwnerTask {
    request_id: ConversationRequestId,
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    generation: u64,
    kind: RetainedOwnerTaskKind,
    intent: RetainedSettlementIntent,
    completed: tokio::sync::watch::Receiver<Option<ConversationResult<()>>>,
    join: Arc<Mutex<RetainedOwnerJoin>>,
}

#[cfg(feature = "live-audio")]
enum RetainedOwnerJoin {
    Pending(tokio::task::JoinHandle<()>),
    Done(ConversationResult<()>),
}

#[cfg(feature = "live-audio")]
#[derive(Clone)]
struct RetainedOwnerWait {
    completed: tokio::sync::watch::Receiver<Option<ConversationResult<()>>>,
    join: Arc<Mutex<RetainedOwnerJoin>>,
}

#[cfg(feature = "live-audio")]
enum OpeningCompletion {
    Active(ActiveRun),
    Cancelled,
    Failed(ConversationError),
}

#[cfg(feature = "live-audio")]
fn opening_error_code(error: &'static str) -> ConversationErrorCode {
    match error {
        "microphone_open_intent_not_durable" | "microphone_open_result_not_durable" => {
            ConversationErrorCode::WalFailed
        }
        "opening_cancelled_before_capture" | "opening_cancelled_after_capture_ready" => {
            ConversationErrorCode::CancelIndeterminate
        }
        _ => ConversationErrorCode::MicrophoneOpenFailed,
    }
}

#[cfg(feature = "live-audio")]
fn publish_opening_terminal(
    projection: &tokio::sync::broadcast::Sender<(ConversationRequestId, ConversationEvent)>,
    request_id: ConversationRequestId,
    code: ConversationErrorCode,
    retryable: bool,
) {
    let _ = projection.send((
        request_id,
        ConversationEvent::Terminal {
            terminal: ConversationTerminal { code, retryable },
        },
    ));
}

#[cfg(feature = "live-audio")]
async fn settle_active_run(active: ActiveRun) -> ConversationResult<()> {
    // A completed task has already dropped this receiver; that is a normal
    // completion path, not a substitute for joining both retained children.
    let _ = active
        .control
        .send(crate::media::conversation_loop::A2Control::Shutdown)
        .await;
    let task_result = active
        .task
        .await
        .map_err(|_| {
            ConversationError::new(
                ConversationErrorCode::StreamSettlementIndeterminate,
                false,
                "conversation_task_join_failed",
            )
        })
        .and_then(|result| {
            result.map_err(|_| {
                ConversationError::new(
                    ConversationErrorCode::StreamSettlementIndeterminate,
                    false,
                    "conversation_task_failed",
                )
            })
        });
    let pump_result = active.pump.await.map_err(|_| {
        ConversationError::new(
            ConversationErrorCode::StreamSettlementIndeterminate,
            false,
            "conversation_event_pump_join_failed",
        )
    });
    // Do not use `?` before the second join: the retained pump must always be
    // settled, while the first failure remains the externally visible cause.
    task_result.and(pump_result)
}

#[cfg(feature = "live-audio")]
async fn join_opening_run(opening: OpeningRun) -> ConversationResult<OpeningCompletion> {
    opening.task.await.map_err(|_| {
        ConversationError::new(
            ConversationErrorCode::StreamSettlementIndeterminate,
            false,
            "conversation_opening_join_failed",
        )
    })
}

#[cfg(feature = "live-audio")]
async fn cancel_and_settle_opening(opening: OpeningRun) -> ConversationResult<()> {
    let _ = opening.scope.invalidate();
    match join_opening_run(opening).await? {
        OpeningCompletion::Active(active) => settle_active_run(active).await,
        OpeningCompletion::Cancelled => Ok(()),
        OpeningCompletion::Failed(error) => Err(error),
    }
}

#[cfg(feature = "live-audio")]
async fn wait_for_retained_owner_task(
    mut completed: tokio::sync::watch::Receiver<Option<ConversationResult<()>>>,
) -> ConversationResult<()> {
    loop {
        if let Some(result) = completed.borrow().clone() {
            return result;
        }
        completed.changed().await.map_err(|_| {
            ConversationError::new(
                ConversationErrorCode::StreamSettlementIndeterminate,
                false,
                "retained_conversation_settlement_lost",
            )
        })?;
    }
}

#[cfg(feature = "live-audio")]
async fn join_retained_owner_task(join: Arc<Mutex<RetainedOwnerJoin>>) -> ConversationResult<()> {
    // This is a task-local custody mutex, never OwnerState.  The handle stays
    // in Pending while it is awaited; cancellation merely releases this guard
    // and leaves the next waiter owning the same handle.
    let mut join = join.lock().await;
    match &mut *join {
        RetainedOwnerJoin::Pending(worker) => {
            let result = worker.await.map_err(|_| {
                ConversationError::new(
                    ConversationErrorCode::StreamSettlementIndeterminate,
                    false,
                    "retained_conversation_settlement_join_failed",
                )
            });
            *join = RetainedOwnerJoin::Done(result.clone());
            result
        }
        RetainedOwnerJoin::Done(result) => result.clone(),
    }
}

#[cfg(feature = "live-audio")]
fn retained_join_succeeded(join: &Arc<Mutex<RetainedOwnerJoin>>) -> bool {
    matches!(join.try_lock(), Ok(join) if matches!(&*join, RetainedOwnerJoin::Done(Ok(()))))
}

#[cfg(feature = "live-audio")]
fn take_finished_active(active: &mut Option<ActiveRun>) -> Option<ActiveRun> {
    if active
        .as_ref()
        .is_some_and(|run| run.task.is_finished() || run.pump.is_finished())
    {
        active.take()
    } else {
        None
    }
}

#[cfg(feature = "live-audio")]
struct OwnerState {
    microphone: crate::permissions::microphone::MicConsentStore,
    challenge: Option<crate::permissions::microphone::MicChallenge>,
    capability: Option<crate::permissions::microphone::MicStartCapability>,
    pending_request: Option<ConversationRequestId>,
    opening: Option<OpeningRun>,
    active: Option<ActiveRun>,
    retained: Option<RetainedOwnerTask>,
}

#[cfg(feature = "live-audio")]
pub(crate) struct LiveConversationOwner {
    dependencies: crate::media::conversation_loop::ConversationDependencies,
    capture: crate::media::live_capture::CpalCaptureConfig,
    bridge: Arc<dyn crate::daemon::gui_chat_bridge::GuiChatBridge>,
    state: Arc<Mutex<OwnerState>>,
    /// Bounded output feeds the registry projection pump.  It transports only
    /// state/prompt/terminal facts, never transcript, PCM or provider text.
    events: tokio::sync::broadcast::Sender<(ConversationRequestId, ConversationEvent)>,
}

#[cfg(feature = "live-audio")]
impl LiveConversationOwner {
    pub(crate) fn new(inputs: LiveConversationOwnerInputs) -> Self {
        let (events, _) = tokio::sync::broadcast::channel(CONVERSATION_REPLAY_MAX_FRAMES);
        Self {
            dependencies: inputs.dependencies,
            capture: inputs.capture,
            bridge: inputs.bridge,
            state: Arc::new(Mutex::new(OwnerState {
                microphone: inputs.microphone,
                challenge: None,
                capability: None,
                pending_request: None,
                opening: None,
                active: None,
                retained: None,
            })),
            events,
        }
    }

    pub(crate) fn subscribe_events(
        &self,
    ) -> tokio::sync::broadcast::Receiver<(ConversationRequestId, ConversationEvent)> {
        self.events.subscribe()
    }
    fn emit(&self, request_id: ConversationRequestId, event: ConversationEvent) {
        let _ = self.events.send((request_id, event));
    }
    fn map_mic(decision: MicConsentDecision) -> crate::permissions::microphone::MicDecision {
        match decision {
            MicConsentDecision::AllowOnce => crate::permissions::microphone::MicDecision::AllowOnce,
            MicConsentDecision::AllowAlways => {
                crate::permissions::microphone::MicDecision::AllowAlways
            }
            MicConsentDecision::Deny => crate::permissions::microphone::MicDecision::Deny,
        }
    }
    fn map_provider(
        decision: crate::daemon::gui_chat_protocol::GuiChatConsentDecision,
    ) -> crate::daemon::gui_chat_bridge::GuiChatConsentDecision {
        match decision {
            crate::daemon::gui_chat_protocol::GuiChatConsentDecision::Deny => {
                crate::daemon::gui_chat_bridge::GuiChatConsentDecision::Deny
            }
            crate::daemon::gui_chat_protocol::GuiChatConsentDecision::AllowOnce => {
                crate::daemon::gui_chat_bridge::GuiChatConsentDecision::AllowOnce
            }
            crate::daemon::gui_chat_protocol::GuiChatConsentDecision::AllowAlways => {
                crate::daemon::gui_chat_bridge::GuiChatConsentDecision::AllowAlways
            }
        }
    }
    fn matches_active(
        active: &ActiveRun,
        request_id: ConversationRequestId,
        subscription_id: &ConversationSubscriptionId,
        session_id: &str,
        origin_surface: ConversationSurface,
        generation: u64,
    ) -> bool {
        active.request_id == request_id
            && active.subscription_id == *subscription_id
            && active.session_id == session_id
            && active.origin_surface == origin_surface
            && active.generation == generation
    }
    fn matches_opening(
        opening: &OpeningRun,
        request_id: ConversationRequestId,
        subscription_id: &ConversationSubscriptionId,
        session_id: &str,
        origin_surface: ConversationSurface,
        generation: u64,
    ) -> bool {
        opening.request_id == request_id
            && opening.subscription_id == *subscription_id
            && opening.session_id == session_id
            && opening.origin_surface == origin_surface
            && opening.generation == generation
    }
    fn matches_retained(
        retained: &RetainedOwnerTask,
        request_id: ConversationRequestId,
        subscription_id: &ConversationSubscriptionId,
        session_id: &str,
        origin_surface: ConversationSurface,
        generation: u64,
    ) -> bool {
        retained.request_id == request_id
            && retained.subscription_id == *subscription_id
            && retained.session_id == session_id
            && retained.origin_surface == origin_surface
            && retained.generation == generation
    }
    fn retain_settlement(
        state: &mut OwnerState,
        opening: Option<OpeningRun>,
        active: Option<ActiveRun>,
        intent: RetainedSettlementIntent,
    ) -> RetainedOwnerWait {
        let (request_id, subscription_id, session_id, origin_surface, generation) =
            match (opening.as_ref(), active.as_ref()) {
                (Some(opening), _) => (
                    opening.request_id,
                    opening.subscription_id.clone(),
                    opening.session_id.clone(),
                    opening.origin_surface,
                    opening.generation,
                ),
                (_, Some(active)) => (
                    active.request_id,
                    active.subscription_id.clone(),
                    active.session_id.clone(),
                    active.origin_surface,
                    active.generation,
                ),
                (None, None) => unreachable!("retained settlement requires conversation ownership"),
            };
        let (finished, completed) = tokio::sync::watch::channel(None);
        let worker = tokio::spawn(async move {
            let opening_result = match opening {
                Some(opening) => cancel_and_settle_opening(opening).await,
                None => Ok(()),
            };
            let active_result = match active {
                Some(active) => settle_active_run(active).await,
                None => Ok(()),
            };
            let _ = finished.send(Some(opening_result.and(active_result)));
        });
        let join = Arc::new(Mutex::new(RetainedOwnerJoin::Pending(worker)));
        let waiter = RetainedOwnerWait {
            completed: completed.clone(),
            join: Arc::clone(&join),
        };
        state.retained = Some(RetainedOwnerTask {
            request_id,
            subscription_id,
            session_id,
            origin_surface,
            generation,
            kind: RetainedOwnerTaskKind::Settlement,
            intent,
            completed,
            join,
        });
        waiter
    }
    fn retain_reap_opening(
        state: &mut OwnerState,
        owner_state: Arc<Mutex<OwnerState>>,
        opening: OpeningRun,
    ) -> RetainedOwnerWait {
        let (finished, completed) = tokio::sync::watch::channel(None);
        let binding = (
            opening.request_id,
            opening.subscription_id.clone(),
            opening.session_id.clone(),
            opening.origin_surface,
            opening.generation,
        );
        let worker = tokio::spawn(async move {
            let result = match join_opening_run(opening).await {
                Ok(OpeningCompletion::Active(active)) => {
                    owner_state.lock().await.active = Some(active);
                    Ok(())
                }
                Ok(OpeningCompletion::Cancelled) | Ok(OpeningCompletion::Failed(_)) => Ok(()),
                Err(error) => Err(error),
            };
            let _ = finished.send(Some(result));
        });
        let join = Arc::new(Mutex::new(RetainedOwnerJoin::Pending(worker)));
        let waiter = RetainedOwnerWait {
            completed: completed.clone(),
            join: Arc::clone(&join),
        };
        state.retained = Some(RetainedOwnerTask {
            request_id: binding.0,
            subscription_id: binding.1,
            session_id: binding.2,
            origin_surface: binding.3,
            generation: binding.4,
            kind: RetainedOwnerTaskKind::Reap,
            intent: RetainedSettlementIntent::ReapActive,
            completed,
            join,
        });
        waiter
    }
    async fn await_matching_retained(
        &self,
        request_id: ConversationRequestId,
        subscription_id: &ConversationSubscriptionId,
        session_id: &str,
        origin_surface: ConversationSurface,
        generation: u64,
    ) -> ConversationResult<Option<(RetainedOwnerTaskKind, RetainedSettlementIntent)>> {
        let retained = {
            let state = self.state.lock().await;
            match state.retained.as_ref() {
                Some(retained)
                    if Self::matches_retained(
                        retained,
                        request_id,
                        subscription_id,
                        session_id,
                        origin_surface,
                        generation,
                    ) =>
                {
                    Some((
                        retained.kind,
                        retained.intent,
                        RetainedOwnerWait {
                            completed: retained.completed.clone(),
                            join: Arc::clone(&retained.join),
                        },
                    ))
                }
                Some(_) => {
                    return Err(ConversationError::new(
                        ConversationErrorCode::Forbidden,
                        false,
                        "conversation_control_binding_mismatch",
                    ));
                }
                None => None,
            }
        };
        match retained {
            Some((kind, intent, waiter)) => {
                self.await_retained_owner_task(waiter).await?;
                Ok(Some((kind, intent)))
            }
            None => Ok(None),
        }
    }
    async fn await_retained_owner_task(&self, waiter: RetainedOwnerWait) -> ConversationResult<()> {
        let result = wait_for_retained_owner_task(waiter.completed).await;
        let join_result = join_retained_owner_task(waiter.join).await;
        result.and(join_result)
    }
    async fn reap_finished(&self) -> ConversationResult<()> {
        loop {
            let retained = {
                let mut state = self.state.lock().await;
                if let Some(retained) = state.retained.as_ref() {
                    let completed = retained.completed.borrow().clone();
                    if let Some(result) = completed {
                        // An abandoned RPC may be the first observer.  Never
                        // discard its typed terminal failure and turn a later
                        // close into a false success; only a genuine success
                        // can release the retained owner slot here.
                        if result.is_err() {
                            Some(RetainedOwnerWait {
                                completed: retained.completed.clone(),
                                join: Arc::clone(&retained.join),
                            })
                        } else {
                            let joined = retained_join_succeeded(&retained.join);
                            if joined {
                                state.retained.take();
                                None
                            } else {
                                Some(RetainedOwnerWait {
                                    completed: retained.completed.clone(),
                                    join: Arc::clone(&retained.join),
                                })
                            }
                        }
                    } else {
                        Some(RetainedOwnerWait {
                            completed: retained.completed.clone(),
                            join: Arc::clone(&retained.join),
                        })
                    }
                } else if state
                    .opening
                    .as_ref()
                    .is_some_and(|opening| opening.task.is_finished())
                {
                    let opening = state.opening.take().expect("finished opening retained");
                    Some(Self::retain_reap_opening(
                        &mut state,
                        Arc::clone(&self.state),
                        opening,
                    ))
                } else if let Some(active) = take_finished_active(&mut state.active) {
                    Some(Self::retain_settlement(
                        &mut state,
                        None,
                        Some(active),
                        RetainedSettlementIntent::ReapActive,
                    ))
                } else {
                    None
                }
            };
            match retained {
                Some(waiter) => self.await_retained_owner_task(waiter).await?,
                None => return Ok(()),
            }
        }
    }
}

#[cfg(feature = "live-audio")]
#[async_trait::async_trait]
impl RetainedConversationOwner for LiveConversationOwner {
    fn subscribe_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<(ConversationRequestId, ConversationEvent)>> {
        Some(LiveConversationOwner::subscribe_events(self))
    }
    async fn preflight(
        &self,
        request: ConversationPreflightRequest,
    ) -> ConversationResult<ConversationEvent> {
        self.reap_finished().await?;
        let mut state = self.state.lock().await;
        if state.active.is_some() || state.opening.is_some() || state.pending_request.is_some() {
            return Err(ConversationError::new(
                ConversationErrorCode::Busy,
                true,
                "conversation_slot_occupied",
            ));
        }
        match crate::media::conversation_loop::ConversationSession::microphone_preflight(
            &mut state.microphone,
            &self.dependencies.config_digest,
        )
        .map_err(|_| {
            ConversationError::new(
                ConversationErrorCode::Unavailable,
                false,
                "microphone_preflight_failed",
            )
        })? {
            crate::media::conversation_loop::ConversationStart::ConfirmationRequired {
                challenge,
            } => {
                state.challenge = Some(challenge);
                state.pending_request = Some(request.request_id);
                Ok(ConversationEvent::MicrophoneConfirmationRequired {
                    request_id: request.request_id,
                    prompt: SafeMicPrompt {
                        expires_at_unix_ms: crate::time::now_unix_secs()
                            .saturating_add(120)
                            .saturating_mul(1000),
                    },
                })
            }
            crate::media::conversation_loop::ConversationStart::Capability(capability) => {
                state.capability = Some(capability);
                state.pending_request = Some(request.request_id);
                Ok(ConversationEvent::State {
                    state: ConversationState::Ready,
                })
            }
        }
    }
    async fn decide_microphone(
        &self,
        request: ConversationMicrophoneDecisionRequest,
    ) -> ConversationResult<ConversationEvent> {
        let mut state = self.state.lock().await;
        if state.pending_request != Some(request.request_id) {
            return Err(ConversationError::new(
                ConversationErrorCode::Forbidden,
                false,
                "microphone_decision_request_mismatch",
            ));
        }
        let challenge = state.challenge.take().ok_or_else(|| {
            ConversationError::new(
                ConversationErrorCode::ConsentRequired,
                false,
                "microphone_challenge_missing",
            )
        })?;
        match crate::media::conversation_loop::ConversationSession::microphone_decide(
            &mut state.microphone,
            challenge,
            Self::map_mic(request.decision),
        )
        .map_err(|_| {
            ConversationError::new(
                ConversationErrorCode::MicrophoneDenied,
                false,
                "microphone_decision_failed",
            )
        })? {
            Some(capability) => {
                state.capability = Some(capability);
                Ok(ConversationEvent::State {
                    state: ConversationState::Ready,
                })
            }
            None => {
                state.pending_request = None;
                Ok(ConversationEvent::Terminal {
                    terminal: ConversationTerminal {
                        code: ConversationErrorCode::MicrophoneDenied,
                        retryable: false,
                    },
                })
            }
        }
    }
    async fn start(
        &self,
        request: ConversationStartRequest,
    ) -> ConversationResult<ConversationEvent> {
        self.reap_finished().await?;
        let mut state = self.state.lock().await;
        if state.pending_request != Some(request.request_id)
            || state.active.is_some()
            || state.opening.is_some()
        {
            return Err(ConversationError::new(
                ConversationErrorCode::Busy,
                true,
                "conversation_start_not_ready",
            ));
        }
        // Construct a replacement before consuming the one-shot capability.
        // A local store-open failure leaves this ready preflight retryable.
        let replacement_microphone =
            crate::permissions::microphone::MicConsentStore::open(&self.dependencies.home)
                .map_err(|_| {
                    ConversationError::new(
                        ConversationErrorCode::WalFailed,
                        false,
                        "microphone_store_reopen_failed",
                    )
                })?;
        let capability = state.capability.take().ok_or_else(|| {
            ConversationError::new(
                ConversationErrorCode::ConsentRequired,
                false,
                "microphone_capability_missing",
            )
        })?;
        let microphone = std::mem::replace(&mut state.microphone, replacement_microphone);
        let dependencies = self.dependencies.clone();
        let capture = self.capture.clone();
        let bridge = Arc::clone(&self.bridge);
        let projection = self.events.clone();
        let scope = crate::media::conversation_scope::CancelScope::new();
        let token = scope.snapshot().map_err(|_| {
            ConversationError::new(
                ConversationErrorCode::GenerationExhausted,
                false,
                "conversation_opening_scope_exhausted",
            )
        })?;
        let request_id = request.request_id;
        let subscription_id = request.subscription_id.clone();
        let session_id = request.session_id.clone();
        let origin_surface = request.origin_surface;
        let generation = request.expected_generation;
        let opening_scope = scope.clone();
        // The OpeningRun is placed in state below without another await.  The
        // task owns every later await, including supervisor construction and the
        // potentially 120-second permit wait.
        let task = tokio::spawn(async move {
            let supervisor =
                match crate::daemon::authorized_text_turn::AuthorizedTextTurnSupervisor::new(
                    bridge,
                    dependencies.task_registry.clone(),
                )
                .await
                {
                    Ok(supervisor) => supervisor,
                    Err(_) => {
                        publish_opening_terminal(
                            &projection,
                            request_id,
                            ConversationErrorCode::Unavailable,
                            false,
                        );
                        return OpeningCompletion::Failed(ConversationError::new(
                            ConversationErrorCode::Unavailable,
                            false,
                            "authorized_text_turn_supervisor_failed",
                        ));
                    }
                };
            let open = crate::media::conversation_loop::ConversationSession::open(
                microphone,
                capability,
                dependencies,
                supervisor,
                capture,
                opening_scope,
                token,
            )
            .await;
            let session = match open {
                Ok(session) => session,
                Err((error, supervisor)) => {
                    // `open` did not consume the supervisor.  The worker it
                    // registered owns bridge state and must acknowledge shutdown
                    // before this opening can publish its terminal state.
                    let cleanup = supervisor.shutdown_and_join().await;
                    if cleanup.is_err() {
                        publish_opening_terminal(
                            &projection,
                            request_id,
                            ConversationErrorCode::StreamSettlementIndeterminate,
                            false,
                        );
                        return OpeningCompletion::Failed(ConversationError::new(
                            ConversationErrorCode::StreamSettlementIndeterminate,
                            false,
                            "authorized_turn_supervisor_unsettled",
                        ));
                    }
                    let code = opening_error_code(error);
                    publish_opening_terminal(
                        &projection,
                        request_id,
                        code,
                        !matches!(code, ConversationErrorCode::CancelIndeterminate),
                    );
                    return if matches!(code, ConversationErrorCode::CancelIndeterminate) {
                        OpeningCompletion::Cancelled
                    } else {
                        OpeningCompletion::Failed(ConversationError::new(
                            code,
                            true,
                            "conversation_microphone_open_failed",
                        ))
                    };
                }
            };
            let (control, control_rx) = tokio::sync::mpsc::channel(8);
            let (events, mut event_rx) = tokio::sync::mpsc::channel(32);
            let task = tokio::spawn(async move { session.run(control_rx, events).await });
            let pump = tokio::spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    let mapped = match event {
                        crate::media::conversation_loop::ConversationEvent::Listening => ConversationEvent::State { state: ConversationState::Listening },
                        crate::media::conversation_loop::ConversationEvent::ProviderConfirmationRequired(prompt) => ConversationEvent::ProviderConfirmationRequired { provider_request_id: ConversationRequestId(prompt.request_id.as_uuid()), prompt: crate::daemon::gui_chat_protocol::GuiChatConsentPromptWire { request_id: crate::daemon::gui_chat_protocol::GuiChatRequestId(prompt.request_id.as_uuid()), routes: prompt.routes.into_iter().map(|route| crate::daemon::gui_chat_protocol::GuiChatConsentRouteWire { provider: route.provider, endpoint_origin: route.endpoint_origin }).collect(), expires_at_unix_ms: prompt.expires_at_unix_ms } },
                        crate::media::conversation_loop::ConversationEvent::Cancelled => ConversationEvent::Terminal { terminal: ConversationTerminal { code: ConversationErrorCode::CancelIndeterminate, retryable: false } },
                        crate::media::conversation_loop::ConversationEvent::Failed(_) => ConversationEvent::Terminal { terminal: ConversationTerminal { code: ConversationErrorCode::StreamSettlementIndeterminate, retryable: true } },
                        _ => continue,
                    };
                    let _ = projection.send((request_id, mapped));
                }
            });
            OpeningCompletion::Active(ActiveRun {
                request_id,
                subscription_id,
                session_id,
                origin_surface,
                generation,
                control,
                task,
                pump,
            })
        });
        state.pending_request = None;
        state.capability = None;
        state.challenge = None;
        state.opening = Some(OpeningRun {
            request_id,
            subscription_id: request.subscription_id,
            session_id: request.session_id,
            origin_surface: request.origin_surface,
            generation: request.expected_generation,
            scope,
            task,
        });
        Ok(ConversationEvent::State {
            state: ConversationState::Ready,
        })
    }
    async fn abort_start(
        &self,
        request: ConversationAbortStartRequest,
    ) -> ConversationResult<ConversationEvent> {
        self.control(ConversationControlRequest {
            schema_version: request.schema_version,
            expected_boot_id: request.expected_boot_id,
            request_id: request.request_id,
            subscription_id: request.subscription_id,
            session_id: request.session_id,
            origin_surface: request.origin_surface,
            expected_generation: request.expected_generation,
            control: ConversationControl::Stop,
        })
        .await
    }
    async fn decide_provider(
        &self,
        request: ConversationProviderDecisionRequest,
    ) -> ConversationResult<ConversationEvent> {
        self.reap_finished().await?;
        let control = {
            let state = self.state.lock().await;
            let active = state.active.as_ref().ok_or_else(|| {
                ConversationError::new(
                    ConversationErrorCode::ConsentRequired,
                    false,
                    "provider_decision_without_active_session",
                )
            })?;
            if !Self::matches_active(
                active,
                request.request_id,
                &request.subscription_id,
                &request.session_id,
                request.origin_surface,
                request.expected_generation,
            ) {
                return Err(ConversationError::new(
                    ConversationErrorCode::Forbidden,
                    false,
                    "provider_decision_binding_mismatch",
                ));
            }
            active.control.clone()
        };
        control
            .send(
                crate::media::conversation_loop::A2Control::ProviderDecision(
                    crate::daemon::gui_chat_bridge::GuiChatRequestId(request.provider_request_id.0),
                    Self::map_provider(request.decision),
                ),
            )
            .await
            .map_err(|_| {
                ConversationError::new(
                    ConversationErrorCode::CancelIndeterminate,
                    true,
                    "conversation_control_closed",
                )
            })?;
        Ok(ConversationEvent::State {
            state: ConversationState::Thinking,
        })
    }
    async fn control(
        &self,
        request: ConversationControlRequest,
    ) -> ConversationResult<ConversationEvent> {
        if let Some((kind, intent)) = self
            .await_matching_retained(
                request.request_id,
                &request.subscription_id,
                &request.session_id,
                request.origin_surface,
                request.expected_generation,
            )
            .await?
        {
            if kind == RetainedOwnerTaskKind::Settlement && intent == RetainedSettlementIntent::Stop
            {
                return Ok(ConversationEvent::State {
                    state: ConversationState::Stopped,
                });
            }
        }
        self.reap_finished().await?;
        let waiter = {
            let mut state = self.state.lock().await;
            if let Some(retained) = state.retained.as_ref() {
                if !Self::matches_retained(
                    retained,
                    request.request_id,
                    &request.subscription_id,
                    &request.session_id,
                    request.origin_surface,
                    request.expected_generation,
                ) {
                    return Err(ConversationError::new(
                        ConversationErrorCode::Forbidden,
                        false,
                        "conversation_control_binding_mismatch",
                    ));
                }
                RetainedOwnerWait {
                    completed: retained.completed.clone(),
                    join: Arc::clone(&retained.join),
                }
            } else {
                if let Some(opening) = state.opening.as_ref() {
                    if !Self::matches_opening(
                        opening,
                        request.request_id,
                        &request.subscription_id,
                        &request.session_id,
                        request.origin_surface,
                        request.expected_generation,
                    ) {
                        return Err(ConversationError::new(
                            ConversationErrorCode::Forbidden,
                            false,
                            "conversation_control_binding_mismatch",
                        ));
                    }
                    let opening = state.opening.take();
                    Self::retain_settlement(
                        &mut state,
                        opening,
                        None,
                        RetainedSettlementIntent::Stop,
                    )
                } else if let Some(active) = state.active.as_ref() {
                    if !Self::matches_active(
                        active,
                        request.request_id,
                        &request.subscription_id,
                        &request.session_id,
                        request.origin_surface,
                        request.expected_generation,
                    ) {
                        return Err(ConversationError::new(
                            ConversationErrorCode::Forbidden,
                            false,
                            "conversation_control_binding_mismatch",
                        ));
                    }
                    let active = state.active.take();
                    Self::retain_settlement(
                        &mut state,
                        None,
                        active,
                        RetainedSettlementIntent::Stop,
                    )
                } else {
                    return Err(ConversationError::new(
                        ConversationErrorCode::Unauthorized,
                        false,
                        "conversation_not_active",
                    ));
                }
            }
        };
        self.await_retained_owner_task(waiter).await?;
        Ok(ConversationEvent::State {
            state: ConversationState::Stopped,
        })
    }
    async fn revoke_microphone(
        &self,
        request: ConversationRevokeMicrophoneRequest,
    ) -> ConversationResult<ConversationEvent> {
        if let Some((kind, intent)) = self
            .await_matching_retained(
                request.request_id,
                &request.subscription_id,
                &request.session_id,
                request.origin_surface,
                request.expected_generation,
            )
            .await?
        {
            if kind == RetainedOwnerTaskKind::Settlement
                && intent == RetainedSettlementIntent::Revoke
            {
                return Ok(ConversationEvent::Terminal {
                    terminal: ConversationTerminal {
                        code: ConversationErrorCode::MicrophoneRevoked,
                        retryable: false,
                    },
                });
            }
        }
        self.reap_finished().await?;
        let waiter = {
            let mut state = self.state.lock().await;
            if let Some(retained) = state.retained.as_ref() {
                if !Self::matches_retained(
                    retained,
                    request.request_id,
                    &request.subscription_id,
                    &request.session_id,
                    request.origin_surface,
                    request.expected_generation,
                ) {
                    return Err(ConversationError::new(
                        ConversationErrorCode::Forbidden,
                        false,
                        "microphone_revoke_binding_mismatch",
                    ));
                }
                RetainedOwnerWait {
                    completed: retained.completed.clone(),
                    join: Arc::clone(&retained.join),
                }
            } else {
                let binding_matches = state
                    .opening
                    .as_ref()
                    .map(|opening| {
                        Self::matches_opening(
                            opening,
                            request.request_id,
                            &request.subscription_id,
                            &request.session_id,
                            request.origin_surface,
                            request.expected_generation,
                        )
                    })
                    .or_else(|| {
                        state.active.as_ref().map(|active| {
                            Self::matches_active(
                                active,
                                request.request_id,
                                &request.subscription_id,
                                &request.session_id,
                                request.origin_surface,
                                request.expected_generation,
                            )
                        })
                    });
                match binding_matches {
                    Some(true) => {}
                    Some(false) => {
                        return Err(ConversationError::new(
                            ConversationErrorCode::Forbidden,
                            false,
                            "microphone_revoke_binding_mismatch",
                        ));
                    }
                    None => {
                        return Err(ConversationError::new(
                            ConversationErrorCode::Unauthorized,
                            false,
                            "conversation_not_active",
                        ));
                    }
                }
                state.microphone.revoke().map_err(|_| {
                    ConversationError::new(
                        ConversationErrorCode::MicrophoneRevoked,
                        false,
                        "microphone_revoke_failed",
                    )
                })?;
                let opening = state.opening.take();
                let active = state.active.take();
                Self::retain_settlement(
                    &mut state,
                    opening,
                    active,
                    RetainedSettlementIntent::Revoke,
                )
            }
        };
        self.await_retained_owner_task(waiter).await?;
        Ok(ConversationEvent::Terminal {
            terminal: ConversationTerminal {
                code: ConversationErrorCode::MicrophoneRevoked,
                retryable: false,
            },
        })
    }
    async fn close_and_drain(&self) -> ConversationResult<()> {
        loop {
            let (kind, waiter) = {
                let mut state = self.state.lock().await;
                if let Some(retained) = state.retained.as_ref() {
                    (
                        retained.kind,
                        RetainedOwnerWait {
                            completed: retained.completed.clone(),
                            join: Arc::clone(&retained.join),
                        },
                    )
                } else {
                    let opening = state.opening.take();
                    let active = state.active.take();
                    match (opening, active) {
                        (None, None) => return Ok(()),
                        (opening, active) => (
                            RetainedOwnerTaskKind::Settlement,
                            Self::retain_settlement(
                                &mut state,
                                opening,
                                active,
                                RetainedSettlementIntent::Close,
                            ),
                        ),
                    }
                }
            };
            let captured_join = Arc::clone(&waiter.join);
            self.await_retained_owner_task(waiter).await?;
            if kind == RetainedOwnerTaskKind::Settlement {
                return Ok(());
            }
            let mut state = self.state.lock().await;
            if state.retained.as_ref().is_some_and(|retained| {
                retained.kind == RetainedOwnerTaskKind::Reap
                    && Arc::ptr_eq(&retained.join, &captured_join)
                    && retained_join_succeeded(&retained.join)
            }) {
                state.retained.take();
            }
        }
    }
}

#[cfg(all(test, feature = "live-audio"))]
mod tests {
    use super::*;

    fn binding(
        request: u128,
        generation: u64,
    ) -> (
        ConversationRequestId,
        ConversationSubscriptionId,
        String,
        ConversationSurface,
        u64,
    ) {
        (
            ConversationRequestId(uuid::Uuid::from_u128(request)),
            ConversationSubscriptionId("sub".into()),
            "session".into(),
            ConversationSurface::Buddy,
            generation,
        )
    }

    #[tokio::test]
    async fn aborted_fake_stage_is_joined_before_stop_ack_and_leaves_no_active_slot() {
        let (request_id, subscription_id, session_id, surface, generation) = binding(1, 7);
        let (control, mut receive) = tokio::sync::mpsc::channel(1);
        let (joined_tx, joined_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            assert!(matches!(
                receive.recv().await,
                Some(crate::media::conversation_loop::A2Control::Shutdown)
            ));
            let _ = joined_tx.send(());
            Ok(())
        });
        let pump = tokio::spawn(async {});
        let active = ActiveRun {
            request_id,
            subscription_id,
            session_id,
            origin_surface: surface,
            generation,
            control,
            task,
            pump,
        };
        settle_active_run(active).await.unwrap();
        joined_rx.await.unwrap();
    }

    #[tokio::test]
    async fn foreign_request_or_generation_never_matches_active_control_binding() {
        let (request_id, subscription_id, session_id, surface, generation) = binding(2, 3);
        let (control, _) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async { Ok(()) });
        let pump = tokio::spawn(async {});
        let active = ActiveRun {
            request_id,
            subscription_id: subscription_id.clone(),
            session_id: session_id.clone(),
            origin_surface: surface,
            generation,
            control,
            task,
            pump,
        };
        assert!(!LiveConversationOwner::matches_active(
            &active,
            ConversationRequestId(uuid::Uuid::from_u128(9)),
            &subscription_id,
            &session_id,
            surface,
            generation
        ));
        assert!(!LiveConversationOwner::matches_active(
            &active,
            request_id,
            &subscription_id,
            &session_id,
            surface,
            generation + 1
        ));
        settle_active_run(active).await.unwrap();
    }

    #[tokio::test]
    async fn task_error_still_drains_the_event_pump() {
        let (request_id, subscription_id, session_id, surface, generation) = binding(3, 4);
        let (control, _) = tokio::sync::mpsc::channel(1);
        let (release_pump, pump_release) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async { Err("fake_stage_failure") });
        let pump = tokio::spawn(async move {
            let _ = pump_release.await;
        });
        let active = ActiveRun {
            request_id,
            subscription_id,
            session_id,
            origin_surface: surface,
            generation,
            control,
            task,
            pump,
        };
        let settlement = tokio::spawn(settle_active_run(active));
        tokio::task::yield_now().await;
        assert!(
            !settlement.is_finished(),
            "task failure must not skip the retained pump join"
        );
        release_pump.send(()).expect("release the retained pump");
        assert!(
            settlement
                .await
                .expect("settlement task must join")
                .is_err()
        );
    }

    #[tokio::test]
    async fn timed_out_abort_waiter_leaves_retained_settlement_busy_until_inner_cleanup_joins() {
        use std::time::Duration;

        let (release_cleanup, cleanup_release) = tokio::sync::oneshot::channel();
        let (finished, completed) = tokio::sync::watch::channel(None);
        let cleanup = tokio::spawn(async move {
            let _ = cleanup_release.await;
            let _ = finished.send(Some(Ok(())));
        });

        // This models the five-second audit/HTTP timeout dropping its
        // `abort_start` future.  It only drops a watcher; the retained worker
        // still owns the cleanup task and the slot remains occupied.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(0),
                wait_for_retained_owner_task(completed.clone())
            )
            .await
            .is_err()
        );
        assert!(
            completed.borrow().is_none(),
            "timed-out caller must not free the retained slot"
        );

        let later_close = tokio::spawn(wait_for_retained_owner_task(completed.clone()));
        tokio::task::yield_now().await;
        assert!(
            !later_close.is_finished(),
            "a later close must join the same unfinished settlement"
        );
        release_cleanup
            .send(())
            .expect("release fake inner cleanup once");
        later_close
            .await
            .expect("later close waiter must join")
            .expect("joined cleanup is a genuine settlement");
        cleanup
            .await
            .expect("retained cleanup worker must not detach");
        assert!(
            completed.borrow().is_some(),
            "slot becomes reusable only after the retained worker reports completion"
        );
    }

    #[tokio::test]
    async fn old_waiter_cannot_join_a_later_retained_worker() {
        let (release_old, old_release) = tokio::sync::oneshot::channel();
        let old_join = Arc::new(Mutex::new(RetainedOwnerJoin::Pending(tokio::spawn(
            async move {
                let _ = old_release.await;
            },
        ))));
        let (release_new, new_release) = tokio::sync::oneshot::channel();
        let new_join = Arc::new(Mutex::new(RetainedOwnerJoin::Pending(tokio::spawn(
            async move {
                let _ = new_release.await;
            },
        ))));

        let old_waiter = tokio::spawn(join_retained_owner_task(Arc::clone(&old_join)));
        tokio::task::yield_now().await;
        assert!(matches!(
            &*new_join
                .try_lock()
                .expect("later token remains independently owned"),
            RetainedOwnerJoin::Pending(_)
        ));
        release_old.send(()).expect("release only the old worker");
        old_waiter
            .await
            .expect("old waiter must join")
            .expect("old worker completed");
        assert!(matches!(
            &*new_join
                .try_lock()
                .expect("old waiter must not consume later token"),
            RetainedOwnerJoin::Pending(_)
        ));
        release_new
            .send(())
            .expect("release later worker separately");
        join_retained_owner_task(new_join)
            .await
            .expect("later worker remains joinable by its own waiter");
    }

    #[tokio::test]
    async fn cancelled_join_waiter_leaves_pending_handle_owned_for_the_next_waiter() {
        let (release, worker_release) = tokio::sync::oneshot::channel();
        let join = Arc::new(Mutex::new(RetainedOwnerJoin::Pending(tokio::spawn(
            async move {
                let _ = worker_release.await;
            },
        ))));
        let cancelled_waiter = tokio::spawn(join_retained_owner_task(Arc::clone(&join)));
        tokio::task::yield_now().await;
        cancelled_waiter.abort();
        let _ = cancelled_waiter.await;
        assert!(matches!(
            &*join
                .try_lock()
                .expect("cancellation must release custody lock"),
            RetainedOwnerJoin::Pending(_)
        ));
        release
            .send(())
            .expect("release owned worker after cancelled caller");
        join_retained_owner_task(join)
            .await
            .expect("next waiter must join the still-owned handle");
    }

    #[tokio::test]
    async fn captured_reap_token_cannot_clear_later_or_failed_retained_join() {
        let old_join = Arc::new(Mutex::new(RetainedOwnerJoin::Done(Ok(()))));
        let later_join = Arc::new(Mutex::new(RetainedOwnerJoin::Done(Ok(()))));
        let failed_join = Arc::new(Mutex::new(RetainedOwnerJoin::Done(Err(
            ConversationError::new(
                ConversationErrorCode::StreamSettlementIndeterminate,
                false,
                "fake_retained_join_failure",
            ),
        ))));

        assert!(retained_join_succeeded(&old_join));
        assert!(
            !Arc::ptr_eq(&old_join, &later_join),
            "a completed old close token must not identify a later reap"
        );
        assert!(retained_join_succeeded(&later_join));
        assert!(
            !retained_join_succeeded(&failed_join),
            "a cached join failure must retain the slot and propagate"
        );
    }

    #[tokio::test]
    async fn completed_active_is_removed_before_the_next_preflight() {
        let (request_id, subscription_id, session_id, surface, generation) = binding(4, 5);
        let (control, _) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async { Ok(()) });
        let pump = tokio::spawn(async {});
        tokio::task::yield_now().await;
        let mut active = Some(ActiveRun {
            request_id,
            subscription_id,
            session_id,
            origin_surface: surface,
            generation,
            control,
            task,
            pump,
        });
        let completed = take_finished_active(&mut active)
            .expect("completed active must leave the occupied slot");
        assert!(active.is_none());
        settle_active_run(completed).await.unwrap();
    }

    #[tokio::test]
    async fn settled_opening_failure_projects_a_terminal_before_slot_reuse() {
        let (projection, mut events) = tokio::sync::broadcast::channel(1);
        let (request_id, _, _, _, _) = binding(5, 6);
        publish_opening_terminal(
            &projection,
            request_id,
            ConversationErrorCode::WalFailed,
            true,
        );
        assert!(
            matches!(events.recv().await, Ok((id, ConversationEvent::Terminal { terminal: ConversationTerminal { code: ConversationErrorCode::WalFailed, retryable: true } })) if id == request_id)
        );
        assert_eq!(
            opening_error_code("microphone_open_result_not_durable"),
            ConversationErrorCode::WalFailed
        );
    }

    #[test]
    fn replacement_store_must_be_opened_before_consuming_start_capability() {
        // `start` opens the replacement store before `capability.take()`: an
        // open failure leaves the existing ready preflight retriable.
        let source = include_str!("conversation_owner.rs");
        let reopen = source
            .find("let replacement_microphone")
            .expect("replacement store open");
        let consume = source
            .find("let capability = state.capability.take()")
            .expect("capability consumption");
        assert!(reopen < consume);
    }
}
