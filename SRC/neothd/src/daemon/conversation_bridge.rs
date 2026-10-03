//! Public, projection-only A2 conversation facade for `neothd-gui`.
//!
//! The GUI gets this facade only through the attested current daemon instance.
//! It never obtains a session, microphone/provider authority, WAL, permit, raw
//! audio, transcript, credentials, model configuration, or response text.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use crate::daemon::conversation_protocol as wire;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConversationRequestId(Uuid);
impl ConversationRequestId {
    pub fn new() -> Self { Self(Uuid::new_v4()) }
    pub fn parse(value: &str) -> Result<Self, ConversationBridgeError> {
        Uuid::parse_str(value).map(Self).map_err(|_| ConversationBridgeError::invalid())
    }
    fn wire(self) -> wire::ConversationRequestId { wire::ConversationRequestId(self.0) }
}

impl Default for ConversationRequestId {
    fn default() -> Self { Self::new() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationSubscription { id: String, request_id: ConversationRequestId, generation: u64, session_id: String }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicDecision { AllowOnce, AllowAlways, Deny }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDecision { AllowOnce, AllowAlways, Deny }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationState { Ready, Listening, Recognizing, Thinking, Speaking, Cancelling, Stopped }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationErrorCode { Conflict, InvalidRequest, Unauthorized, Forbidden, BootChanged, Busy, Unavailable, ConsentRequired, ReplayGap, CancelIndeterminate, MicrophoneDenied, MicrophoneRevoked, MicrophoneOpenFailed, DeviceLost, WalFailed, SttFailed, TtsFailed, QueueOverflow, GenerationExhausted, StreamSettlementIndeterminate }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationFeature { Available, LiveAudioDisabled, ComponentsUnavailable }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicrophonePermission { Unknown, Required, Granted, Revoked }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicOpenOutcome { Opened, Failed }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationAvailability { pub feature: ConversationFeature, pub microphone: MicrophonePermission, pub busy: bool, pub last_device_open: Option<MicOpenOutcome> }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConsentRoute {
    pub provider: String,
    pub endpoint_origin: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversationEvent {
    Availability(ConversationAvailability),
    MicrophoneConfirmationRequired { request_id: ConversationRequestId, expires_at_unix_ms: u64 },
    /// Safe route names and origins explain the pending consent; sealed proof and transcript remain private.
    ProviderConfirmationRequired { provider_request_id: ConversationRequestId, expires_at_unix_ms: u64, routes: Vec<ProviderConsentRoute> },
    State(ConversationState),
    Terminal { code: ConversationErrorCode, retryable: bool },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationProgress { pub subscription: Option<ConversationSubscription>, pub latest_sequence: u64, pub event: ConversationEvent }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationFrame { pub sequence: u64, pub event: ConversationEvent }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationBridgeErrorCode { InvalidRequest, Unavailable, BootChanged, Refused, Indeterminate }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationBridgeError { pub code: ConversationBridgeErrorCode, pub retryable: bool }
impl ConversationBridgeError { fn invalid() -> Self { Self { code: ConversationBridgeErrorCode::InvalidRequest, retryable: false } } fn unavailable() -> Self { Self { code: ConversationBridgeErrorCode::Unavailable, retryable: true } } }
pub type ConversationBridgeResult<T> = Result<T, ConversationBridgeError>;

#[async_trait]
pub trait ConversationBridge: Send + Sync {
    async fn availability(&self, request_id: ConversationRequestId) -> ConversationBridgeResult<ConversationAvailability>;
    async fn preflight(&self, request_id: ConversationRequestId, session_id: String) -> ConversationBridgeResult<ConversationProgress>;
    async fn decide_microphone(&self, subscription: ConversationSubscription, decision: MicDecision) -> ConversationBridgeResult<ConversationProgress>;
    async fn decide_provider(&self, subscription: ConversationSubscription, provider_request_id: ConversationRequestId, decision: ProviderDecision) -> ConversationBridgeResult<ConversationProgress>;
    /// This request is cancellation-coupled in the daemon: a post-write timeout
    /// must settle the retained start before a microphone can outlive it.
    async fn start(&self, subscription: ConversationSubscription) -> ConversationBridgeResult<ConversationProgress>;
    async fn stop(&self, subscription: ConversationSubscription) -> ConversationBridgeResult<ConversationProgress>;
    async fn revoke_microphone(&self, subscription: ConversationSubscription) -> ConversationBridgeResult<ConversationProgress>;
    async fn attach(&self, subscription: ConversationSubscription, after_sequence: u64, sink: &mut dyn ConversationEventSink) -> ConversationBridgeResult<()>;
}
pub trait ConversationEventSink: Send { fn on_event(&mut self, frame: ConversationFrame) -> ConversationBridgeResult<()>; }

struct CoreConversationBridge { home: PathBuf, boot_id: String }

/// The factory resolves the default home and attests the live daemon before any
/// wire request. The GUI cannot choose an endpoint, sidecar, token or boot ID.
pub fn bridge_for_attested_current_instance() -> ConversationBridgeResult<Arc<dyn ConversationBridge>> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let boot_id = crate::daemon::audit_rpc::attested_conversation_boot_id(&home).map_err(|_| ConversationBridgeError::unavailable())?;
    Ok(Arc::new(CoreConversationBridge { home, boot_id }))
}

fn client<T>(result: Result<T, crate::daemon::audit_rpc::ConversationClientError>) -> ConversationBridgeResult<T> {
    use crate::daemon::audit_rpc::ConversationClientError;
    result.map_err(|error| match error {
        ConversationClientError::PreWriteUnavailable(_) => ConversationBridgeError::unavailable(),
        ConversationClientError::Indeterminate(_) => ConversationBridgeError { code: ConversationBridgeErrorCode::Indeterminate, retryable: false },
        ConversationClientError::Refused(_, _) => ConversationBridgeError { code: ConversationBridgeErrorCode::Refused, retryable: false },
    })
}
fn subscription(id: wire::ConversationSubscriptionId, request_id: ConversationRequestId, generation: u64, session_id: String) -> ConversationSubscription { ConversationSubscription { id: id.0, request_id, generation, session_id } }
fn require_response(response: &wire::ConversationProgressResponse, boot: &str, request_id: ConversationRequestId) -> ConversationBridgeResult<()> {
    if response.schema_version != wire::CONVERSATION_V1_SCHEMA_VERSION || response.expected_boot_id != boot || response.request_id != request_id.wire() { return Err(ConversationBridgeError { code: ConversationBridgeErrorCode::BootChanged, retryable: true }); }
    Ok(())
}
fn map_event(value: wire::ConversationEvent) -> ConversationEvent { match value {
    wire::ConversationEvent::Availability { availability } => ConversationEvent::Availability(map_availability(availability)),
    wire::ConversationEvent::MicrophoneConfirmationRequired { request_id, prompt } => ConversationEvent::MicrophoneConfirmationRequired { request_id: ConversationRequestId(request_id.0), expires_at_unix_ms: prompt.expires_at_unix_ms },
    wire::ConversationEvent::ProviderConfirmationRequired { provider_request_id, prompt } => ConversationEvent::ProviderConfirmationRequired { provider_request_id: ConversationRequestId(provider_request_id.0), expires_at_unix_ms: prompt.expires_at_unix_ms, routes: prompt.routes.into_iter().map(|route| ProviderConsentRoute { provider: route.provider, endpoint_origin: route.endpoint_origin }).collect() },
    wire::ConversationEvent::State { state } => ConversationEvent::State(match state { wire::ConversationState::Ready => ConversationState::Ready, wire::ConversationState::Listening => ConversationState::Listening, wire::ConversationState::Recognizing => ConversationState::Recognizing, wire::ConversationState::Thinking => ConversationState::Thinking, wire::ConversationState::Speaking => ConversationState::Speaking, wire::ConversationState::Cancelling => ConversationState::Cancelling, wire::ConversationState::Stopped => ConversationState::Stopped }),
    wire::ConversationEvent::Terminal { terminal } => ConversationEvent::Terminal { code: map_code(terminal.code), retryable: terminal.retryable },
} }
fn map_availability(value: wire::ConversationAvailability) -> ConversationAvailability { ConversationAvailability { feature: match value.feature { wire::ConversationFeature::Available => ConversationFeature::Available, wire::ConversationFeature::LiveAudioDisabled => ConversationFeature::LiveAudioDisabled, wire::ConversationFeature::ComponentsUnavailable => ConversationFeature::ComponentsUnavailable }, microphone: match value.microphone { wire::MicrophonePermissionState::Unknown => MicrophonePermission::Unknown, wire::MicrophonePermissionState::Required => MicrophonePermission::Required, wire::MicrophonePermissionState::Granted => MicrophonePermission::Granted, wire::MicrophonePermissionState::Revoked => MicrophonePermission::Revoked }, busy: value.busy, last_device_open: value.last_device_open.map(|outcome| match outcome { wire::MicOpenOutcome::Opened => MicOpenOutcome::Opened, wire::MicOpenOutcome::Failed => MicOpenOutcome::Failed }) } }
fn map_code(value: wire::ConversationErrorCode) -> ConversationErrorCode { match value { wire::ConversationErrorCode::Conflict => ConversationErrorCode::Conflict, wire::ConversationErrorCode::InvalidRequest => ConversationErrorCode::InvalidRequest, wire::ConversationErrorCode::Unauthorized => ConversationErrorCode::Unauthorized, wire::ConversationErrorCode::Forbidden => ConversationErrorCode::Forbidden, wire::ConversationErrorCode::BootChanged => ConversationErrorCode::BootChanged, wire::ConversationErrorCode::Busy => ConversationErrorCode::Busy, wire::ConversationErrorCode::Unavailable => ConversationErrorCode::Unavailable, wire::ConversationErrorCode::ConsentRequired => ConversationErrorCode::ConsentRequired, wire::ConversationErrorCode::ReplayGap => ConversationErrorCode::ReplayGap, wire::ConversationErrorCode::CancelIndeterminate => ConversationErrorCode::CancelIndeterminate, wire::ConversationErrorCode::MicrophoneDenied => ConversationErrorCode::MicrophoneDenied, wire::ConversationErrorCode::MicrophoneRevoked => ConversationErrorCode::MicrophoneRevoked, wire::ConversationErrorCode::MicrophoneOpenFailed => ConversationErrorCode::MicrophoneOpenFailed, wire::ConversationErrorCode::DeviceLost => ConversationErrorCode::DeviceLost, wire::ConversationErrorCode::WalFailed => ConversationErrorCode::WalFailed, wire::ConversationErrorCode::SttFailed => ConversationErrorCode::SttFailed, wire::ConversationErrorCode::TtsFailed => ConversationErrorCode::TtsFailed, wire::ConversationErrorCode::QueueOverflow => ConversationErrorCode::QueueOverflow, wire::ConversationErrorCode::GenerationExhausted => ConversationErrorCode::GenerationExhausted, wire::ConversationErrorCode::StreamSettlementIndeterminate => ConversationErrorCode::StreamSettlementIndeterminate } }
fn map_progress(
    response: wire::ConversationProgressResponse,
    boot: &str,
    request_id: ConversationRequestId,
    session_id: &str,
    expected: Option<&ConversationSubscription>,
) -> ConversationBridgeResult<ConversationProgress> {
    require_response(&response, boot, request_id)?;
    if let Some(id) = &response.subscription_id {
        wire::validate_id(&id.0).map_err(|_| ConversationBridgeError::invalid())?;
        if response.generation == 0 { return Err(ConversationBridgeError::invalid()); }
    }
    if let Some(expected) = expected {
        if response.subscription_id.as_ref().map(|id| id.0.as_str()) != Some(expected.id.as_str())
            || response.generation != expected.generation
            || session_id != expected.session_id
        {
            return Err(ConversationBridgeError::invalid());
        }
    }
    Ok(ConversationProgress {
        subscription: response.subscription_id.map(|id| subscription(id, request_id, response.generation, session_id.to_string())),
        latest_sequence: response.latest_sequence,
        event: map_event(response.event),
    })
}
fn wire_subscription(value: &ConversationSubscription) -> wire::ConversationSubscriptionId { wire::ConversationSubscriptionId(value.id.clone()) }

#[async_trait]
impl ConversationBridge for CoreConversationBridge {
    async fn availability(&self, request_id: ConversationRequestId) -> ConversationBridgeResult<ConversationAvailability> {
        let request = wire::ConversationAvailabilityRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: request_id.wire() };
        let response: wire::ConversationAvailabilityResponse = client(crate::daemon::audit_rpc::conversation_post(&self.home, wire::CONVERSATION_V1_AVAILABILITY_PATH, &request).await)?;
        if response.schema_version != wire::CONVERSATION_V1_SCHEMA_VERSION || response.expected_boot_id != self.boot_id { return Err(ConversationBridgeError { code: ConversationBridgeErrorCode::BootChanged, retryable: true }); } Ok(map_availability(response.availability))
    }
    async fn preflight(&self, request_id: ConversationRequestId, session_id: String) -> ConversationBridgeResult<ConversationProgress> { let request = wire::ConversationPreflightRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: request_id.wire(), session_id: session_id.clone(), origin_surface: wire::ConversationSurface::Buddy }; let response = client(crate::daemon::audit_rpc::conversation_post(&self.home, wire::CONVERSATION_V1_PREFLIGHT_PATH, &request).await)?; map_progress(response, &self.boot_id, request_id, &session_id, None) }
    async fn decide_microphone(&self, value: ConversationSubscription, decision: MicDecision) -> ConversationBridgeResult<ConversationProgress> { let request = wire::ConversationMicrophoneDecisionRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: value.request_id.wire(), subscription_id: wire_subscription(&value), session_id: value.session_id.clone(), origin_surface: wire::ConversationSurface::Buddy, expected_generation: value.generation, decision: match decision { MicDecision::AllowOnce => wire::MicConsentDecision::AllowOnce, MicDecision::AllowAlways => wire::MicConsentDecision::AllowAlways, MicDecision::Deny => wire::MicConsentDecision::Deny } }; let response = client(crate::daemon::audit_rpc::conversation_post(&self.home, wire::CONVERSATION_V1_MICROPHONE_DECIDE_PATH, &request).await)?; map_progress(response, &self.boot_id, value.request_id, &value.session_id, Some(&value)) }
    async fn decide_provider(&self, value: ConversationSubscription, provider_request_id: ConversationRequestId, decision: ProviderDecision) -> ConversationBridgeResult<ConversationProgress> { let request = wire::ConversationProviderDecisionRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: value.request_id.wire(), subscription_id: wire_subscription(&value), session_id: value.session_id.clone(), origin_surface: wire::ConversationSurface::Buddy, expected_generation: value.generation, provider_request_id: provider_request_id.wire(), decision: match decision { ProviderDecision::AllowOnce => crate::daemon::gui_chat_protocol::GuiChatConsentDecision::AllowOnce, ProviderDecision::AllowAlways => crate::daemon::gui_chat_protocol::GuiChatConsentDecision::AllowAlways, ProviderDecision::Deny => crate::daemon::gui_chat_protocol::GuiChatConsentDecision::Deny } }; let response = client(crate::daemon::audit_rpc::conversation_post(&self.home, wire::CONVERSATION_V1_PROVIDER_DECIDE_PATH, &request).await)?; map_progress(response, &self.boot_id, value.request_id, &value.session_id, Some(&value)) }
    async fn start(&self, value: ConversationSubscription) -> ConversationBridgeResult<ConversationProgress> { let request = wire::ConversationStartRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: value.request_id.wire(), subscription_id: wire_subscription(&value), session_id: value.session_id.clone(), origin_surface: wire::ConversationSurface::Buddy, expected_generation: value.generation }; let abort = wire::ConversationAbortStartRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: value.request_id.wire(), subscription_id: wire_subscription(&value), session_id: value.session_id.clone(), origin_surface: wire::ConversationSurface::Buddy, expected_generation: value.generation }; let response = client(crate::daemon::audit_rpc::conversation_post_cancellable(&self.home, wire::CONVERSATION_V1_START_PATH, &request, &abort).await)?; map_progress(response, &self.boot_id, value.request_id, &value.session_id, Some(&value)) }
    async fn stop(&self, value: ConversationSubscription) -> ConversationBridgeResult<ConversationProgress> { let request = wire::ConversationControlRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: value.request_id.wire(), subscription_id: wire_subscription(&value), session_id: value.session_id.clone(), origin_surface: wire::ConversationSurface::Buddy, expected_generation: value.generation, control: wire::ConversationControl::Stop }; let response = client(crate::daemon::audit_rpc::conversation_post(&self.home, wire::CONVERSATION_V1_CONTROL_PATH, &request).await)?; map_progress(response, &self.boot_id, value.request_id, &value.session_id, Some(&value)) }
    async fn revoke_microphone(&self, value: ConversationSubscription) -> ConversationBridgeResult<ConversationProgress> { let request = wire::ConversationRevokeMicrophoneRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: value.request_id.wire(), subscription_id: wire_subscription(&value), session_id: value.session_id.clone(), origin_surface: wire::ConversationSurface::Buddy, expected_generation: value.generation }; let response = client(crate::daemon::audit_rpc::conversation_post(&self.home, wire::CONVERSATION_V1_REVOKE_MICROPHONE_PATH, &request).await)?; map_progress(response, &self.boot_id, value.request_id, &value.session_id, Some(&value)) }
    async fn attach(&self, value: ConversationSubscription, after_sequence: u64, sink: &mut dyn ConversationEventSink) -> ConversationBridgeResult<()> { let request = wire::ConversationAttachRequest { schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION, expected_boot_id: self.boot_id.clone(), request_id: value.request_id.wire(), subscription_id: wire_subscription(&value), session_id: value.session_id.clone(), origin_surface: wire::ConversationSurface::Buddy, expected_generation: value.generation, after_sequence }; let boot = self.boot_id.clone(); let id = value.id.clone(); let generation = value.generation; client(crate::daemon::audit_rpc::conversation_attach(&self.home, &request, &mut |frame| { if frame.expected_boot_id != boot || frame.subscription_id.0 != id || frame.generation != generation { return Err(crate::daemon::audit_rpc::ConversationClientError::Indeterminate("conversation attach binding mismatch".into())); } sink.on_event(ConversationFrame { sequence: frame.sequence, event: map_event(frame.event) }).map_err(|_| crate::daemon::audit_rpc::ConversationClientError::Indeterminate("conversation sink rejected frame".into())) }).await) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indeterminate_start_failure_is_not_projected_as_retryable_unavailability() {
        let error = client::<()>(Err(crate::daemon::audit_rpc::ConversationClientError::Indeterminate("unconfirmed start abort".into()))).unwrap_err();
        assert_eq!(error.code, ConversationBridgeErrorCode::Indeterminate);
        assert!(!error.retryable);
    }

    #[test]
    fn stateful_reply_cannot_replace_its_subscription_or_generation() {
        let request_id = ConversationRequestId::new();
        let expected = ConversationSubscription { id: "owned".into(), request_id, generation: 4, session_id: "session".into() };
        let response = wire::ConversationProgressResponse {
            schema_version: wire::CONVERSATION_V1_SCHEMA_VERSION,
            expected_boot_id: "boot".into(),
            request_id: request_id.wire(),
            subscription_id: Some(wire::ConversationSubscriptionId("foreign".into())),
            generation: 4,
            latest_sequence: 1,
            event: wire::ConversationEvent::State { state: wire::ConversationState::Listening },
        };
        assert!(map_progress(response.clone(), "boot", request_id, "session", Some(&expected)).is_err());
        let mut stale = response;
        stale.subscription_id = Some(wire::ConversationSubscriptionId("owned".into()));
        stale.generation = 3;
        assert!(map_progress(stale, "boot", request_id, "session", Some(&expected)).is_err());
    }
}
