//! Daemon-owned capacity-one A2 conversation registry.
//!
//! The audit boundary retains exactly one conversation owner.  The registry
//! contains only safe projections, bounded idempotency records and explicit
//! caller bindings; PCM, transcripts, receipts, permits and credentials never
//! cross this module.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use super::conversation_protocol::*;
use super::conversation_session::ConversationTaskRegistry;

#[async_trait]
pub(crate) trait ConversationRuntime: Send + Sync {
    async fn availability(&self, request: ConversationAvailabilityRequest) -> ConversationResult<ConversationAvailabilityResponse>;
    async fn preflight(&self, request: ConversationPreflightRequest) -> ConversationResult<ConversationProgressResponse>;
    async fn decide_microphone(&self, request: ConversationMicrophoneDecisionRequest) -> ConversationResult<ConversationProgressResponse>;
    async fn decide_provider(&self, request: ConversationProviderDecisionRequest) -> ConversationResult<ConversationProgressResponse>;
    async fn start(&self, request: ConversationStartRequest) -> ConversationResult<ConversationProgressResponse>;
    async fn abort_start(&self, request: ConversationAbortStartRequest) -> ConversationResult<ConversationProgressResponse>;
    async fn control(&self, request: ConversationControlRequest) -> ConversationResult<ConversationProgressResponse>;
    async fn revoke_microphone(&self, request: ConversationRevokeMicrophoneRequest) -> ConversationResult<ConversationProgressResponse>;
    async fn replay(&self, request: ConversationAttachRequest) -> ConversationResult<Vec<ConversationStreamFrame>>;
    async fn attach(&self, request: ConversationAttachRequest, sink: &mut dyn ConversationProjectionSink) -> ConversationResult<()>;
    async fn close_and_drain(&self) -> ConversationResult<()>;
}

#[async_trait]
pub(crate) trait RetainedConversationOwner: Send + Sync {
    #[cfg(any(test, feature = "live-audio"))]
    fn subscribe_events(&self) -> Option<tokio::sync::broadcast::Receiver<(ConversationRequestId, ConversationEvent)>> { None }
    async fn preflight(&self, request: ConversationPreflightRequest) -> ConversationResult<ConversationEvent>;
    async fn decide_microphone(&self, request: ConversationMicrophoneDecisionRequest) -> ConversationResult<ConversationEvent>;
    async fn decide_provider(&self, request: ConversationProviderDecisionRequest) -> ConversationResult<ConversationEvent>;
    async fn start(&self, request: ConversationStartRequest) -> ConversationResult<ConversationEvent>;
    async fn abort_start(&self, request: ConversationAbortStartRequest) -> ConversationResult<ConversationEvent>;
    async fn control(&self, request: ConversationControlRequest) -> ConversationResult<ConversationEvent>;
    async fn revoke_microphone(&self, request: ConversationRevokeMicrophoneRequest) -> ConversationResult<ConversationEvent>;
    async fn close_and_drain(&self) -> ConversationResult<()>;
}

struct RegistryState {
    availability: ConversationAvailability,
    owner: Option<Arc<dyn RetainedConversationOwner>>,
    subscriptions: HashMap<ConversationSubscriptionId, SubscriptionBinding>,
    preflight_replies: HashMap<ConversationRequestId, ConversationProgressResponse>,
    preflight_inputs: HashMap<ConversationRequestId, (String, ConversationSurface)>,
    start_replies: HashMap<ConversationSubscriptionId, ConversationProgressResponse>,
    // A subscription enters this FIFO only after a real terminal projection.
    // It is the sole eviction source: active or not-yet-settled idempotency
    // records are never discarded to make room for another admission.
    settled: VecDeque<ConversationSubscriptionId>,
    frames: VecDeque<ConversationStreamFrame>,
    next_sequence: u64,
}

#[derive(Clone)]
struct SubscriptionBinding {
    session_id: String,
    surface: ConversationSurface,
    request_id: ConversationRequestId,
    generation: u64,
}

pub(crate) struct ConversationRegistry {
    boot_id: String,
    tasks: ConversationTaskRegistry,
    state: Arc<Mutex<RegistryState>>,
    projections: tokio::sync::broadcast::Sender<ConversationStreamFrame>,
    // The owner-event relay outlives an individual conversation session.  It
    // is deliberately not registered in ConversationTaskRegistry: that
    // registry is drained by the session during owner shutdown.
    relay_shutdown: watch::Sender<bool>,
    // Relay failure is retained in the JoinHandle result.  In particular, a
    // fail-closed lag settlement must not hide an owner close failure merely
    // because it took the owner out of RegistryState first.
    relay: Mutex<Option<JoinHandle<ConversationResult<()>>>>,
    // These are keyed operation locks, never the retained state lock.  Thus a
    // 120-second AudioWorkPermit wait cannot block availability/replay/drain.
    preflight_gates: Mutex<HashMap<ConversationRequestId, Arc<Mutex<()>>>>,
    preflight_serial: Mutex<()>,
    start_gates: Mutex<HashMap<ConversationSubscriptionId, Arc<Mutex<()>>>>,
}

impl ConversationRegistry {
    fn base(boot_id: String, tasks: ConversationTaskRegistry, availability: ConversationAvailability, owner: Option<Arc<dyn RetainedConversationOwner>>) -> Self {
        let (projections, _) = tokio::sync::broadcast::channel(CONVERSATION_REPLAY_MAX_FRAMES);
        let (relay_shutdown, _) = watch::channel(false);
        Self {
            boot_id, tasks, projections, relay_shutdown, relay: Mutex::new(None),
            state: Arc::new(Mutex::new(RegistryState { availability, owner, subscriptions: HashMap::new(), preflight_replies: HashMap::new(), preflight_inputs: HashMap::new(), start_replies: HashMap::new(), settled: VecDeque::new(), frames: VecDeque::new(), next_sequence: 0 })),
            preflight_gates: Mutex::new(HashMap::new()), preflight_serial: Mutex::new(()), start_gates: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn unavailable(boot_id: String) -> Self {
        Self::base(boot_id, ConversationTaskRegistry::default(), ConversationAvailability { feature: ConversationFeature::LiveAudioDisabled, microphone: MicrophonePermissionState::Unknown, busy: false, last_device_open: None }, None)
    }

    /// The owner event projection is registry-owned, rather than a session
    /// cleanup task.  Session teardown drains ConversationTaskRegistry before
    /// `run` returns, so registering this long-lived receiver there would
    /// deadlock owner-close on its still-open broadcast channel.
    #[cfg(any(test, feature = "live-audio"))]
    pub(crate) async fn new(boot_id: String, owner: Arc<dyn RetainedConversationOwner>, tasks: ConversationTaskRegistry) -> ConversationResult<Self> {
        let registry = Self::base(boot_id.clone(), tasks, ConversationAvailability { feature: ConversationFeature::Available, microphone: MicrophonePermissionState::Unknown, busy: false, last_device_open: None }, Some(Arc::clone(&owner)));
        if let Some(mut events) = owner.subscribe_events() {
            let state = Arc::clone(&registry.state);
            let projections = registry.projections.clone();
            let mut shutdown = registry.relay_shutdown.subscribe();
            let relay = tokio::spawn(async move {
                loop {
                    let received = tokio::select! {
                        event = events.recv() => Some(event),
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                // owner.close_and_drain has already settled the
                                // session. Drain any final queued projections
                                // before joining; an empty queue is the normal
                                // final-owner-close case.
                                loop {
                                    match events.try_recv() {
                                        Ok((request_id, event)) => Self::relay_event(&state, &projections, &boot_id, request_id, event).await,
                                        Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {
                                            Self::settle_relay_lag(&state, &projections, &boot_id).await?;
                                            break;
                                        }
                                        Err(tokio::sync::broadcast::error::TryRecvError::Empty | tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                                    }
                                }
                                None
                            } else { continue }
                        }
                    };
                    let Some(received) = received else { break; };
                    let (request_id, event) = match received {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            Self::settle_relay_lag(&state, &projections, &boot_id).await?;
                            break;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    };
                    Self::relay_event(&state, &projections, &boot_id, request_id, event).await;
                }
                Ok(())
            });
            *registry.relay.lock().await = Some(relay);
        }
        Ok(registry)
    }

    #[cfg(any(test, feature = "live-audio"))]
    async fn relay_event(state: &Arc<Mutex<RegistryState>>, projections: &tokio::sync::broadcast::Sender<ConversationStreamFrame>, boot_id: &str, request_id: ConversationRequestId, event: ConversationEvent) {
        let mut state = state.lock().await;
        let Some((subscription_id, binding)) = state.subscriptions.iter().find(|(_, candidate)| candidate.request_id == request_id).map(|(id, binding)| (id.clone(), binding.clone())) else { return; };
        state.next_sequence = state.next_sequence.saturating_add(1);
        let sequence = state.next_sequence;
        Self::apply_availability(&mut state, &event);
        Self::mark_settled(&mut state, &subscription_id, &event);
        let frame = ConversationStreamFrame { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: boot_id.into(), subscription_id, generation: binding.generation, sequence, event };
        state.frames.push_back(frame.clone());
        while state.frames.len() > CONVERSATION_REPLAY_MAX_FRAMES { state.frames.pop_front(); }
        let _ = projections.send(frame);
    }

    #[cfg(any(test, feature = "live-audio"))]
    async fn settle_relay_lag(state: &Arc<Mutex<RegistryState>>, projections: &tokio::sync::broadcast::Sender<ConversationStreamFrame>, boot_id: &str) -> ConversationResult<()> {
        let (frames, owner) = {
            let mut state = state.lock().await;
            let active: Vec<_> = state.subscriptions.iter()
                .filter(|(id, _)| !state.settled.iter().any(|settled| settled == *id))
                .map(|(id, binding)| (id.clone(), binding.clone()))
                .collect();
            let mut frames = Vec::with_capacity(active.len());
            for (subscription_id, binding) in active {
                state.next_sequence = state.next_sequence.saturating_add(1);
                let terminal = ConversationEvent::Terminal { terminal: ConversationTerminal { code: ConversationErrorCode::StreamSettlementIndeterminate, retryable: false } };
                Self::apply_availability(&mut state, &terminal);
                Self::mark_settled(&mut state, &subscription_id, &terminal);
                let frame = ConversationStreamFrame { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: boot_id.into(), subscription_id, generation: binding.generation, sequence: state.next_sequence, event: terminal };
                state.frames.push_back(frame.clone());
                while state.frames.len() > CONVERSATION_REPLAY_MAX_FRAMES { state.frames.pop_front(); }
                frames.push(frame);
            }
            state.availability.busy = false;
            (frames, state.owner.take())
        };
        for frame in frames { let _ = projections.send(frame); }
        match owner {
            Some(owner) => owner.close_and_drain().await,
            None => Ok(()),
        }
    }

    fn apply_availability(state: &mut RegistryState, event: &ConversationEvent) {
        match event {
            ConversationEvent::Availability { availability } => state.availability = availability.clone(),
            ConversationEvent::MicrophoneConfirmationRequired { .. } => state.availability.microphone = MicrophonePermissionState::Required,
            ConversationEvent::State { state: ConversationState::Listening } => state.availability.microphone = MicrophonePermissionState::Granted,
            ConversationEvent::Terminal { terminal } => {
                state.availability.busy = false;
                match terminal.code {
                    ConversationErrorCode::MicrophoneDenied => state.availability.microphone = MicrophonePermissionState::Unknown,
                    ConversationErrorCode::MicrophoneRevoked => state.availability.microphone = MicrophonePermissionState::Revoked,
                    ConversationErrorCode::MicrophoneOpenFailed | ConversationErrorCode::DeviceLost => state.availability.last_device_open = Some(MicOpenOutcome::Failed),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn mark_settled(state: &mut RegistryState, subscription_id: &ConversationSubscriptionId, event: &ConversationEvent) {
        if matches!(event, ConversationEvent::Terminal { .. })
            && !state.settled.iter().any(|settled| settled == subscription_id) {
            state.settled.push_back(subscription_id.clone());
        }
    }

    /// Releases only records with an observed terminal projection.  The state
    /// mutation deliberately precedes gate removal: a concurrent duplicate may
    /// still hold its old gate, but can never observe a partially retained
    /// idempotency record.
    async fn evict_settled_records(&self) {
        let mut preflight_ids = Vec::new();
        let mut subscription_ids = Vec::new();
        {
            let mut state = self.state.lock().await;
            while state.preflight_inputs.len() >= CONVERSATION_REPLAY_MAX_FRAMES {
                let Some(subscription_id) = state.settled.pop_front() else { break; };
                if let Some(binding) = state.subscriptions.remove(&subscription_id) {
                    state.preflight_inputs.remove(&binding.request_id);
                    state.preflight_replies.remove(&binding.request_id);
                    state.start_replies.remove(&subscription_id);
                    preflight_ids.push(binding.request_id);
                    subscription_ids.push(subscription_id);
                }
            }
        }
        if !preflight_ids.is_empty() {
            let mut gates = self.preflight_gates.lock().await;
            for request_id in preflight_ids { gates.remove(&request_id); }
        }
        if !subscription_ids.is_empty() {
            let mut gates = self.start_gates.lock().await;
            for subscription_id in subscription_ids { gates.remove(&subscription_id); }
        }
    }

    fn header(&self, schema: u16, expected_boot_id: &str) -> ConversationResult<()> { validate_request_header(schema, expected_boot_id, &self.boot_id) }
    fn response(&self, request_id: ConversationRequestId, subscription_id: Option<ConversationSubscriptionId>, generation: u64, latest_sequence: u64, event: ConversationEvent) -> ConversationProgressResponse {
        ConversationProgressResponse { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id, subscription_id, generation, latest_sequence, event }
    }
    async fn owner(&self) -> ConversationResult<Arc<dyn RetainedConversationOwner>> {
        self.state.lock().await.owner.clone().ok_or_else(|| ConversationError::unavailable("conversation_runtime_unavailable"))
    }
    async fn preflight_gate(&self, request_id: ConversationRequestId) -> ConversationResult<Arc<Mutex<()>>> {
        let mut gates = self.preflight_gates.lock().await;
        if let Some(gate) = gates.get(&request_id) { return Ok(Arc::clone(gate)); }
        if gates.len() >= CONVERSATION_REPLAY_MAX_FRAMES { return Err(ConversationError::new(ConversationErrorCode::Busy, true, "conversation_preflight_idempotency_full")); }
        let gate = Arc::new(Mutex::new(())); gates.insert(request_id, Arc::clone(&gate)); Ok(gate)
    }
    async fn start_gate(&self, subscription_id: &ConversationSubscriptionId) -> ConversationResult<Arc<Mutex<()>>> {
        let mut gates = self.start_gates.lock().await;
        if let Some(gate) = gates.get(subscription_id) { return Ok(Arc::clone(gate)); }
        if gates.len() >= CONVERSATION_REPLAY_MAX_FRAMES { return Err(ConversationError::new(ConversationErrorCode::Busy, true, "conversation_start_idempotency_full")); }
        let gate = Arc::new(Mutex::new(())); gates.insert(subscription_id.clone(), Arc::clone(&gate)); Ok(gate)
    }
    async fn publish_new(&self, session_id: String, surface: ConversationSurface, request_id: ConversationRequestId, event: ConversationEvent) -> ConversationProgressResponse {
        let mut state = self.state.lock().await;
        state.next_sequence = state.next_sequence.saturating_add(1);
        let sequence = state.next_sequence;
        let id = ConversationSubscriptionId(format!("{}:{}", request_id.0.simple(), sequence));
        state.subscriptions.insert(id.clone(), SubscriptionBinding { session_id, surface, request_id, generation: sequence });
        let frame = ConversationStreamFrame { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), subscription_id: id.clone(), generation: sequence, sequence, event: event.clone() };
        state.frames.push_back(frame.clone()); while state.frames.len() > CONVERSATION_REPLAY_MAX_FRAMES { state.frames.pop_front(); }
        Self::mark_settled(&mut state, &id, &event);
        let _ = self.projections.send(frame);
        self.response(request_id, Some(id), sequence, sequence, event)
    }
    async fn binding(&self, subscription_id: &ConversationSubscriptionId, request_id: ConversationRequestId, session_id: &str, surface: ConversationSurface, expected_generation: u64) -> ConversationResult<SubscriptionBinding> {
        validate_id(&subscription_id.0)?;
        let binding = self.state.lock().await.subscriptions.get(subscription_id).cloned().ok_or_else(|| ConversationError::new(ConversationErrorCode::Unauthorized, false, "conversation_subscription_unknown"))?;
        if binding.request_id != request_id { return Err(ConversationError::new(ConversationErrorCode::Forbidden, false, "conversation_subscription_request_mismatch")); }
        if binding.session_id != session_id || binding.surface != surface { return Err(ConversationError::new(ConversationErrorCode::Forbidden, false, "conversation_subscription_owner_mismatch")); }
        if binding.generation != expected_generation { return Err(ConversationError::new(ConversationErrorCode::BootChanged, true, "conversation_subscription_generation_mismatch")); }
        Ok(binding)
    }
    async fn publish_existing(&self, subscription_id: ConversationSubscriptionId, binding: SubscriptionBinding, event: ConversationEvent) -> ConversationProgressResponse {
        let mut state = self.state.lock().await;
        state.next_sequence = state.next_sequence.saturating_add(1); let sequence = state.next_sequence;
        Self::apply_availability(&mut state, &event);
        Self::mark_settled(&mut state, &subscription_id, &event);
        let frame = ConversationStreamFrame { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), subscription_id: subscription_id.clone(), generation: binding.generation, sequence, event: event.clone() };
        state.frames.push_back(frame.clone()); while state.frames.len() > CONVERSATION_REPLAY_MAX_FRAMES { state.frames.pop_front(); }
        let _ = self.projections.send(frame);
        self.response(binding.request_id, Some(subscription_id), binding.generation, sequence, event)
    }
}

#[async_trait]
impl ConversationRuntime for ConversationRegistry {
    async fn availability(&self, request: ConversationAvailabilityRequest) -> ConversationResult<ConversationAvailabilityResponse> {
        self.header(request.schema_version, &request.expected_boot_id)?;
        Ok(ConversationAvailabilityResponse { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), availability: self.state.lock().await.availability.clone() })
    }

    async fn preflight(&self, request: ConversationPreflightRequest) -> ConversationResult<ConversationProgressResponse> {
        self.header(request.schema_version, &request.expected_boot_id)?; validate_id(&request.session_id)?;
        let canonical = (request.session_id.clone(), request.origin_surface);
        // A retained replay must win over maintenance eviction.  Once a
        // terminal record has naturally aged out it may be admitted anew, but
        // cache pressure may not erase a still-retained duplicate on arrival.
        {
            let state = self.state.lock().await;
            if let Some(previous) = state.preflight_inputs.get(&request.request_id) {
                if previous != &canonical { return Err(ConversationError::new(ConversationErrorCode::Conflict, false, "conversation_preflight_body_conflict")); }
                return state.preflight_replies.get(&request.request_id).cloned().ok_or_else(|| ConversationError::new(ConversationErrorCode::StreamSettlementIndeterminate, false, "conversation_preflight_replay_missing"));
            }
        }
        self.evict_settled_records().await;
        let gate = self.preflight_gate(request.request_id).await?;
        let _flight = gate.lock().await;
        let _capacity = self.preflight_serial.lock().await;
        {
            let state = self.state.lock().await;
            if let Some(previous) = state.preflight_inputs.get(&request.request_id) {
                if previous != &canonical { return Err(ConversationError::new(ConversationErrorCode::Conflict, false, "conversation_preflight_body_conflict")); }
                return state.preflight_replies.get(&request.request_id).cloned().ok_or_else(|| ConversationError::new(ConversationErrorCode::StreamSettlementIndeterminate, false, "conversation_preflight_replay_missing"));
            }
            if state.availability.busy { return Err(ConversationError::new(ConversationErrorCode::Busy, true, "conversation_active_request_busy")); }
            if state.preflight_inputs.len() >= CONVERSATION_REPLAY_MAX_FRAMES { return Err(ConversationError::new(ConversationErrorCode::Busy, true, "conversation_preflight_cache_full")); }
        }
        let event = self.owner().await?.preflight(request.clone()).await?;
        let response = self.publish_new(request.session_id, request.origin_surface, request.request_id, event).await;
        let mut state = self.state.lock().await;
        state.availability.busy = true;
        Self::apply_availability(&mut state, &response.event);
        state.preflight_inputs.insert(request.request_id, canonical);
        state.preflight_replies.insert(request.request_id, response.clone());
        Ok(response)
    }
    async fn decide_microphone(&self, request: ConversationMicrophoneDecisionRequest) -> ConversationResult<ConversationProgressResponse> {
        self.header(request.schema_version, &request.expected_boot_id)?;
        let binding = self.binding(&request.subscription_id, request.request_id, &request.session_id, request.origin_surface, request.expected_generation).await?;
        let event = self.owner().await?.decide_microphone(request.clone()).await?;
        Ok(self.publish_existing(request.subscription_id, binding, event).await)
    }
    async fn decide_provider(&self, request: ConversationProviderDecisionRequest) -> ConversationResult<ConversationProgressResponse> {
        self.header(request.schema_version, &request.expected_boot_id)?;
        let binding = self.binding(&request.subscription_id, request.request_id, &request.session_id, request.origin_surface, request.expected_generation).await?;
        let event = self.owner().await?.decide_provider(request.clone()).await?;
        Ok(self.publish_existing(request.subscription_id, binding, event).await)
    }
    async fn start(&self, request: ConversationStartRequest) -> ConversationResult<ConversationProgressResponse> {
        self.header(request.schema_version, &request.expected_boot_id)?;
        let binding = self.binding(&request.subscription_id, request.request_id, &request.session_id, request.origin_surface, request.expected_generation).await?;
        if let Some(replay) = self.state.lock().await.start_replies.get(&request.subscription_id).cloned() { return Ok(replay); }
        self.evict_settled_records().await;
        let gate = self.start_gate(&request.subscription_id).await?;
        let _flight = gate.lock().await;
        {
            let state = self.state.lock().await;
            if let Some(replay) = state.start_replies.get(&request.subscription_id).cloned() { return Ok(replay); }
            // Reserve the cache admission before consuming start authority.
            // A full cache therefore fails before owner.start, never after.
            if state.start_replies.len() >= CONVERSATION_REPLAY_MAX_FRAMES {
                return Err(ConversationError::new(ConversationErrorCode::Busy, true, "conversation_start_cache_full"));
            }
        }
        let event = self.owner().await?.start(request.clone()).await?;
        let response = self.publish_existing(request.subscription_id.clone(), binding, event).await;
        let mut state = self.state.lock().await;
        state.start_replies.insert(request.subscription_id, response.clone());
        Ok(response)
    }
    async fn abort_start(&self, request: ConversationAbortStartRequest) -> ConversationResult<ConversationProgressResponse> {
        self.header(request.schema_version, &request.expected_boot_id)?;
        let binding = self.binding(&request.subscription_id, request.request_id, &request.session_id, request.origin_surface, request.expected_generation).await?;
        let event = self.owner().await?.abort_start(request.clone()).await?;
        Ok(self.publish_existing(request.subscription_id, binding, event).await)
    }
    async fn control(&self, request: ConversationControlRequest) -> ConversationResult<ConversationProgressResponse> {
        self.header(request.schema_version, &request.expected_boot_id)?;
        let binding = self.binding(&request.subscription_id, request.request_id, &request.session_id, request.origin_surface, request.expected_generation).await?;
        let event = self.owner().await?.control(request.clone()).await?;
        Ok(self.publish_existing(request.subscription_id, binding, event).await)
    }
    async fn revoke_microphone(&self, request: ConversationRevokeMicrophoneRequest) -> ConversationResult<ConversationProgressResponse> {
        self.header(request.schema_version, &request.expected_boot_id)?;
        let binding = self.binding(&request.subscription_id, request.request_id, &request.session_id, request.origin_surface, request.expected_generation).await?;
        let event = self.owner().await?.revoke_microphone(request.clone()).await?;
        Ok(self.publish_existing(request.subscription_id, binding, event).await)
    }
    async fn replay(&self, request: ConversationAttachRequest) -> ConversationResult<Vec<ConversationStreamFrame>> {
        self.header(request.schema_version, &request.expected_boot_id)?; validate_id(&request.subscription_id.0)?;
        let state = self.state.lock().await;
        let binding = state.subscriptions.get(&request.subscription_id).ok_or_else(|| ConversationError::new(ConversationErrorCode::Unauthorized, false, "conversation_subscription_unknown"))?;
        if binding.request_id != request.request_id || binding.generation != request.expected_generation || binding.session_id != request.session_id || binding.surface != request.origin_surface { return Err(ConversationError::new(ConversationErrorCode::Forbidden, false, "conversation_attach_binding_mismatch")); }
        if let Some(first) = state.frames.front() { if request.after_sequence.saturating_add(1) < first.sequence { return Err(ConversationError::new(ConversationErrorCode::ReplayGap, true, "conversation_replay_gap")); } }
        Ok(state.frames.iter().filter(|frame| frame.subscription_id == request.subscription_id && frame.sequence > request.after_sequence).cloned().take(CONVERSATION_REPLAY_MAX_FRAMES).collect())
    }
    async fn attach(&self, request: ConversationAttachRequest, sink: &mut dyn ConversationProjectionSink) -> ConversationResult<()> {
        let mut live = self.projections.subscribe(); let mut cursor = request.after_sequence;
        for frame in self.replay(request.clone()).await? { cursor = cursor.max(frame.sequence); sink.on_frame(frame).await?; }
        loop { match live.recv().await {
            Ok(frame) if frame.subscription_id == request.subscription_id && frame.sequence > cursor => { cursor = frame.sequence; sink.on_frame(frame).await?; }
            Ok(_) => {}, Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => return Err(ConversationError::new(ConversationErrorCode::ReplayGap, true, "conversation_attach_lagged")),
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        }}
    }
    async fn close_and_drain(&self) -> ConversationResult<()> {
        // Do not clear bindings before the owner settles: the dedicated relay
        // must still be able to project final owner events while close waits.
        let owner = { let mut state = self.state.lock().await; state.availability.busy = false; state.owner.take() };
        let owner_result = match owner { Some(owner) => owner.close_and_drain().await, None => Ok(()) };
        let _ = self.relay_shutdown.send(true);
        let relay_result = match self.relay.lock().await.take() {
            Some(relay) => match relay.await {
                Ok(result) => result,
                Err(_) => Err(ConversationError::new(ConversationErrorCode::StreamSettlementIndeterminate, false, "conversation_event_relay_failed")),
            },
            None => Ok(()),
        };
        { let mut state = self.state.lock().await; state.subscriptions.clear(); state.preflight_replies.clear(); state.preflight_inputs.clear(); state.start_replies.clear(); state.settled.clear(); }
        let task_result = self.tasks.drain().await.map_err(|_| ConversationError::new(ConversationErrorCode::StreamSettlementIndeterminate, false, "conversation_task_drain_failed"));
        owner_result.and(relay_result).and(task_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::{broadcast, Notify};

    struct FakeOwner { preflights: AtomicUsize, starts: AtomicUsize, fail_start_once: AtomicBool, block_first_preflight: bool, entered: Notify, release: Notify }
    impl FakeOwner { fn new(block_preflight: bool) -> Self { Self { preflights: AtomicUsize::new(0), starts: AtomicUsize::new(0), fail_start_once: AtomicBool::new(false), block_first_preflight: block_preflight, entered: Notify::new(), release: Notify::new() } } }
    fn ready() -> ConversationEvent { ConversationEvent::State { state: ConversationState::Ready } }
    #[async_trait]
    impl RetainedConversationOwner for FakeOwner {
        async fn preflight(&self, _request: ConversationPreflightRequest) -> ConversationResult<ConversationEvent> { self.preflights.fetch_add(1, Ordering::SeqCst); self.entered.notify_waiters(); if self.block_first_preflight && self.preflights.load(Ordering::SeqCst) == 1 { self.release.notified().await; } Ok(ready()) }
        async fn decide_microphone(&self, _request: ConversationMicrophoneDecisionRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn decide_provider(&self, _request: ConversationProviderDecisionRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn start(&self, _request: ConversationStartRequest) -> ConversationResult<ConversationEvent> { self.starts.fetch_add(1, Ordering::SeqCst); if self.fail_start_once.swap(false, Ordering::SeqCst) { Err(ConversationError::new(ConversationErrorCode::MicrophoneOpenFailed, true, "fake_start_failure")) } else { Ok(ConversationEvent::State { state: ConversationState::Listening }) } }
        async fn abort_start(&self, _request: ConversationAbortStartRequest) -> ConversationResult<ConversationEvent> { Ok(ConversationEvent::Terminal { terminal: ConversationTerminal { code: ConversationErrorCode::CancelIndeterminate, retryable: false } }) }
        async fn control(&self, _request: ConversationControlRequest) -> ConversationResult<ConversationEvent> { Ok(ConversationEvent::Terminal { terminal: ConversationTerminal { code: ConversationErrorCode::CancelIndeterminate, retryable: false } }) }
        async fn revoke_microphone(&self, _request: ConversationRevokeMicrophoneRequest) -> ConversationResult<ConversationEvent> { Ok(ConversationEvent::Terminal { terminal: ConversationTerminal { code: ConversationErrorCode::MicrophoneRevoked, retryable: false } }) }
        async fn close_and_drain(&self) -> ConversationResult<()> { Ok(()) }
    }

    struct RelayOwner {
        events: broadcast::Sender<(ConversationRequestId, ConversationEvent)>,
        closes: AtomicUsize,
        fail_close: AtomicBool,
        closed: Notify,
    }
    impl RelayOwner {
        fn new() -> Self {
            let (events, _) = broadcast::channel(1);
            Self { events, closes: AtomicUsize::new(0), fail_close: AtomicBool::new(false), closed: Notify::new() }
        }
    }
    #[async_trait]
    impl RetainedConversationOwner for RelayOwner {
        fn subscribe_events(&self) -> Option<broadcast::Receiver<(ConversationRequestId, ConversationEvent)>> { Some(self.events.subscribe()) }
        async fn preflight(&self, _request: ConversationPreflightRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn decide_microphone(&self, _request: ConversationMicrophoneDecisionRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn decide_provider(&self, _request: ConversationProviderDecisionRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn start(&self, _request: ConversationStartRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn abort_start(&self, _request: ConversationAbortStartRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn control(&self, _request: ConversationControlRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn revoke_microphone(&self, _request: ConversationRevokeMicrophoneRequest) -> ConversationResult<ConversationEvent> { Ok(ready()) }
        async fn close_and_drain(&self) -> ConversationResult<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            self.closed.notify_one();
            if self.fail_close.load(Ordering::SeqCst) {
                Err(ConversationError::new(ConversationErrorCode::WalFailed, false, "fake_relay_owner_close_failed"))
            } else { Ok(()) }
        }
    }
    fn preflight(id: ConversationRequestId, session: &str) -> ConversationPreflightRequest { ConversationPreflightRequest { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: "boot".into(), request_id: id, session_id: session.into(), origin_surface: ConversationSurface::Buddy } }
    fn start(id: ConversationRequestId, subscription_id: ConversationSubscriptionId, generation: u64) -> ConversationStartRequest { ConversationStartRequest { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: "boot".into(), request_id: id, subscription_id, session_id: "session".into(), origin_surface: ConversationSurface::Buddy, expected_generation: generation } }

    #[tokio::test]
    async fn concurrent_duplicate_preflight_mints_one_owner_call_and_one_subscription() {
        let owner = Arc::new(FakeOwner::new(true));
        let registry = Arc::new(ConversationRegistry::new("boot".into(), owner.clone(), ConversationTaskRegistry::default()).await.unwrap());
        let request_id = ConversationRequestId(uuid::Uuid::new_v4());
        let entered = owner.entered.notified();
        let first = { let registry = registry.clone(); tokio::spawn(async move { registry.preflight(preflight(request_id, "session")).await.unwrap() }) };
        entered.await;
        let second = { let registry = registry.clone(); tokio::spawn(async move { registry.preflight(preflight(request_id, "session")).await.unwrap() }) };
        owner.release.notify_waiters();
        let first = first.await.unwrap(); let second = second.await.unwrap();
        assert_eq!(owner.preflights.load(Ordering::SeqCst), 1);
        assert_eq!(first.subscription_id, second.subscription_id);
    }

    #[tokio::test]
    async fn changed_preflight_body_for_same_request_is_a_conflict() {
        let owner = Arc::new(FakeOwner::new(false));
        let registry = ConversationRegistry::new("boot".into(), owner, ConversationTaskRegistry::default()).await.unwrap();
        let request_id = ConversationRequestId(uuid::Uuid::new_v4());
        registry.preflight(preflight(request_id, "session")).await.unwrap();
        let error = registry.preflight(preflight(request_id, "other-session")).await.unwrap_err();
        assert_eq!(error.code, ConversationErrorCode::Conflict);
    }

    #[tokio::test]
    async fn foreign_session_cannot_control_bound_subscription() {
        let owner = Arc::new(FakeOwner::new(false));
        let registry = ConversationRegistry::new("boot".into(), owner, ConversationTaskRegistry::default()).await.unwrap();
        let request_id = ConversationRequestId(uuid::Uuid::new_v4());
        let response = registry.preflight(preflight(request_id, "session")).await.unwrap();
        let error = registry.control(ConversationControlRequest { schema_version: CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: "boot".into(), request_id, subscription_id: response.subscription_id.unwrap(), session_id: "foreign".into(), origin_surface: ConversationSurface::Buddy, expected_generation: response.generation, control: ConversationControl::Stop }).await.unwrap_err();
        assert_eq!(error.code, ConversationErrorCode::Forbidden);
    }

    #[tokio::test]
    async fn failed_start_is_not_cached_and_retry_reaches_owner() {
        let owner = Arc::new(FakeOwner::new(false)); owner.fail_start_once.store(true, Ordering::SeqCst);
        let registry = Arc::new(ConversationRegistry::new("boot".into(), owner.clone(), ConversationTaskRegistry::default()).await.unwrap());
        let request_id = ConversationRequestId(uuid::Uuid::new_v4());
        let admission = { let registry = registry.clone(); let task = tokio::spawn(async move { registry.preflight(preflight(request_id, "session")).await.unwrap() }); task.await.unwrap() };
        let request = start(request_id, admission.subscription_id.unwrap(), admission.generation);
        assert_eq!(registry.start(request.clone()).await.unwrap_err().code, ConversationErrorCode::MicrophoneOpenFailed);
        assert!(matches!(registry.start(request).await.unwrap().event, ConversationEvent::State { state: ConversationState::Listening }));
        assert_eq!(owner.starts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn more_than_the_retention_limit_of_settled_lifecycles_admits_the_next_request() {
        let owner = Arc::new(FakeOwner::new(false));
        let registry = ConversationRegistry::new("boot".into(), owner.clone(), ConversationTaskRegistry::default()).await.unwrap();
        for _ in 0..=CONVERSATION_REPLAY_MAX_FRAMES {
            let request_id = ConversationRequestId(uuid::Uuid::new_v4());
            let admission = registry.preflight(preflight(request_id, "session")).await.unwrap();
            registry.control(ConversationControlRequest {
                schema_version: CONVERSATION_V1_SCHEMA_VERSION,
                expected_boot_id: "boot".into(), request_id,
                subscription_id: admission.subscription_id.unwrap(),
                session_id: "session".into(), origin_surface: ConversationSurface::Buddy,
                expected_generation: admission.generation, control: ConversationControl::Stop,
            }).await.unwrap();
        }
        assert_eq!(owner.preflights.load(Ordering::SeqCst), CONVERSATION_REPLAY_MAX_FRAMES + 1);
    }

    #[tokio::test]
    async fn relay_lag_publishes_indeterminate_terminal_and_closes_its_owner() {
        let owner = Arc::new(RelayOwner::new());
        let registry = ConversationRegistry::new("boot".into(), owner.clone(), ConversationTaskRegistry::default()).await.unwrap();
        let request_id = ConversationRequestId(uuid::Uuid::new_v4());
        let admission = registry.preflight(preflight(request_id, "session")).await.unwrap();
        // Holding registry state makes the relay retain one event while the
        // one-slot owner bus advances beyond it, deterministically producing
        // RecvError::Lagged when the relay resumes.
        let held = registry.state.lock().await;
        owner.events.send((request_id, ready())).unwrap();
        owner.events.send((request_id, ready())).unwrap();
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), owner.closed.notified()).await.unwrap();
        assert_eq!(owner.closes.load(Ordering::SeqCst), 1);
        let frames = registry.replay(ConversationAttachRequest {
            schema_version: CONVERSATION_V1_SCHEMA_VERSION,
            expected_boot_id: "boot".into(), request_id,
            subscription_id: admission.subscription_id.unwrap(),
            session_id: "session".into(), origin_surface: ConversationSurface::Buddy,
            expected_generation: admission.generation, after_sequence: 0,
        }).await.unwrap();
        assert!(frames.iter().any(|frame| matches!(&frame.event, ConversationEvent::Terminal {
            terminal: ConversationTerminal { code: ConversationErrorCode::StreamSettlementIndeterminate, retryable: false }
        })));
    }

    #[tokio::test]
    async fn relay_lag_owner_close_failure_is_returned_by_runtime_close() {
        let owner = Arc::new(RelayOwner::new());
        owner.fail_close.store(true, Ordering::SeqCst);
        let registry = ConversationRegistry::new("boot".into(), owner.clone(), ConversationTaskRegistry::default()).await.unwrap();
        let request_id = ConversationRequestId(uuid::Uuid::new_v4());
        registry.preflight(preflight(request_id, "session")).await.unwrap();
        let held = registry.state.lock().await;
        owner.events.send((request_id, ready())).unwrap();
        owner.events.send((request_id, ready())).unwrap();
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), owner.closed.notified()).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), registry.close_and_drain()).await.unwrap().unwrap_err();
        assert_eq!(owner.closes.load(Ordering::SeqCst), 1);
        assert_eq!(error.code, ConversationErrorCode::WalFailed);
    }

    #[tokio::test]
    async fn runtime_close_joins_a_long_lived_relay_after_session_cleanup() {
        // RelayOwner retains its broadcast sender after close.  A relay placed
        // in the shared session cleanup registry would wait forever here when
        // owner teardown drains that registry; the registry-owned signal and
        // handle must make the complete runtime close return instead.
        let owner = Arc::new(RelayOwner::new());
        let session_tasks = ConversationTaskRegistry::default();
        let registry = ConversationRegistry::new("boot".into(), owner.clone(), session_tasks.clone()).await.unwrap();
        session_tasks.spawn_cleanup(Box::pin(async {})).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), session_tasks.drain_cleanup()).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(1), registry.close_and_drain()).await.unwrap().unwrap();
        assert_eq!(owner.closes.load(Ordering::SeqCst), 1);
        assert!(registry.relay.lock().await.is_none());
    }
}
