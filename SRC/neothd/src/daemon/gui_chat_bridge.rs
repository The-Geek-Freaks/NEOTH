//! W41 public GUI facade amendment. Wire DTOs, daemon grants, local consent
//! proofs, audit transport, provider handles, WAL, and runtime traits remain
//! crate-private in `neothd`.

use std::fmt;
use std::path::PathBuf;

use async_trait::async_trait;
use uuid::Uuid;

pub const GUI_CHAT_MESSAGE_MAX_BYTES: usize = 3 * 1024;
pub const GUI_CHAT_SESSION_ID_MAX_BYTES: usize = 128;
pub const GUI_CHAT_BOOT_ID_MAX_BYTES: usize = 128;
pub const GUI_CHAT_MODEL_MAX_BYTES: usize = 256;
pub const GUI_CHAT_SKILL_MAX_BYTES: usize = 256;
pub const GUI_CHAT_ATTACHMENT_MAX_COUNT: usize = 8;
pub const GUI_CHAT_ATTACHMENT_PATH_MAX_BYTES: usize = 4096;
pub const GUI_CHAT_FRAME_MAX_BYTES: usize = 64 * 1024;
pub const GUI_CHAT_CONSENT_ROUTE_MAX_COUNT: usize = 8;
pub const GUI_CHAT_CONSENT_ROUTE_PROVIDER_MAX_BYTES: usize = 128;
pub const GUI_CHAT_CONSENT_ROUTE_ORIGIN_MAX_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuiChatRequestId(Uuid);
impl GuiChatRequestId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
    pub fn parse(value: &str) -> Result<Self, GuiChatBridgeError> {
        let id = Uuid::parse_str(value).map_err(|_| GuiChatBridgeError::invalid("request_id"))?;
        if id.get_version_num() != 7 {
            return Err(GuiChatBridgeError::invalid("request_id"));
        }
        Ok(Self(id))
    }
    /// Request correlation only; this identifier carries no turn authority.
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}
impl Default for GuiChatRequestId {
    fn default() -> Self {
        Self::new()
    }
}

/// Daemon-minted correlation only. It cannot authorize status, attach, cancel,
/// or provider work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuiChatTurnId(pub(crate) Uuid);
impl GuiChatTurnId {
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiChatSurface {
    Main,
    Buddy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiChatPhase {
    Waiting,
    Receiving,
    Finalizing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiChatTerminalState {
    Complete,
    Cancelled,
    Failed,
    CrashUnknown,
    Indeterminate,
}

/// Local-only input. Paths reach the daemon only after authenticated bridge
/// staging. No GUI API accepts selected-home, endpoint, or credential input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuiChatBridgePreflightInput {
    pub request_id: GuiChatRequestId,
    pub session_id: String,
    pub origin_surface: GuiChatSurface,
    pub message: String,
    pub model: Option<String>,
    pub skill_id: Option<String>,
    pub incognito: bool,
    /// Captured next-turn display grant. The attested preflight descriptor
    /// commits this value; the daemon never reads a later preference.
    pub reasoning_display: bool,
    pub attachment_paths: Vec<PathBuf>,
}

/// Presentation-only egress summary. The optional origin is canonical core
/// display data; it never contains a path, query, fragment, user-info, or bearer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuiChatConsentRoute {
    pub provider: String,
    pub endpoint_origin: Option<String>,
}

/// Exact request-bound UI prompt. No prompt/model/skill/attachment/session,
/// capability, grant, bearer, or proof appears here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuiChatConsentPrompt {
    pub request_id: GuiChatRequestId,
    pub routes: Vec<GuiChatConsentRoute>,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiChatConsentDecision {
    Deny,
    AllowOnce,
    AllowAlways,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuiChatTurnMetadata {
    pub boot_id: String,
    pub turn_id: GuiChatTurnId,
    pub origin_surface: GuiChatSurface,
    pub phase: GuiChatPhase,
    pub latest_sequence: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuiChatSubscriptionMetadata {
    pub boot_id: String,
    pub turn_id: GuiChatTurnId,
    pub surface: GuiChatSurface,
    pub generation: u64,
    pub latest_sequence: u64,
}

#[derive(Clone, PartialEq, Eq)]
enum GuiChatSealedHandle {
    Live(Vec<u8>),
    #[cfg(feature = "gui-bridge-test-support")]
    Fixture,
}
impl GuiChatSealedHandle {
    fn live(bytes: Vec<u8>) -> Self {
        Self::Live(bytes)
    }
    /// A real adapter rejects `None` before it serializes or writes audit-RPC.
    pub(crate) fn live_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Live(bytes) => Some(bytes),
            #[cfg(feature = "gui-bridge-test-support")]
            Self::Fixture => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct GuiChatBridgePreflightReceipt {
    sealed: GuiChatSealedHandle,
}
#[derive(Clone, PartialEq, Eq)]
pub struct GuiChatBridgeDecisionReceipt {
    sealed: GuiChatSealedHandle,
}
#[derive(Clone, PartialEq, Eq)]
pub struct GuiChatBridgeTurn {
    pub metadata: GuiChatTurnMetadata,
    sealed: GuiChatSealedHandle,
}
#[derive(Clone, PartialEq, Eq)]
pub struct GuiChatBridgeSubscription {
    pub metadata: GuiChatSubscriptionMetadata,
    sealed: GuiChatSealedHandle,
}
impl GuiChatBridgePreflightReceipt {
    pub(crate) fn from_live(bytes: Vec<u8>) -> Self {
        Self {
            sealed: GuiChatSealedHandle::live(bytes),
        }
    }
}
impl GuiChatBridgeDecisionReceipt {
    pub(crate) fn from_live(bytes: Vec<u8>) -> Self {
        Self {
            sealed: GuiChatSealedHandle::live(bytes),
        }
    }
}
impl GuiChatBridgeTurn {
    pub(crate) fn from_live(metadata: GuiChatTurnMetadata, bytes: Vec<u8>) -> Self {
        Self {
            metadata,
            sealed: GuiChatSealedHandle::live(bytes),
        }
    }
}
impl GuiChatBridgeSubscription {
    pub(crate) fn from_live(metadata: GuiChatSubscriptionMetadata, bytes: Vec<u8>) -> Self {
        Self {
            metadata,
            sealed: GuiChatSealedHandle::live(bytes),
        }
    }
}

macro_rules! redacted_debug {
    ($type_name:ident) => {
        impl fmt::Debug for $type_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($type_name), "(<sealed>)"))
            }
        }
    };
}
redacted_debug!(GuiChatBridgePreflightReceipt);
redacted_debug!(GuiChatBridgeDecisionReceipt);
impl fmt::Debug for GuiChatBridgeTurn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiChatBridgeTurn")
            .field("metadata", &self.metadata)
            .field("sealed", &"<redacted>")
            .finish()
    }
}
impl fmt::Debug for GuiChatBridgeSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiChatBridgeSubscription")
            .field("metadata", &self.metadata)
            .field("sealed", &"<redacted>")
            .finish()
    }
}

/// `Ready` is modal-free only after core has already verified the existing
/// request-bound authorization for this sealed descriptor. It carries the
/// resulting decision receipt, so GUI starts it directly and cannot invent a
/// policy. Every other descriptor must show its exact prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuiChatBridgePreflight {
    Ready {
        decision: GuiChatBridgeDecisionReceipt,
    },
    ConfirmationRequired {
        receipt: GuiChatBridgePreflightReceipt,
        prompt: GuiChatConsentPrompt,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuiChatBridgeDecisionOutcome {
    Denied,
    Approved(GuiChatBridgeDecisionReceipt),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuiChatBridgeEvent {
    Accepted {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
    },
    PhaseChanged {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
        phase: GuiChatPhase,
    },
    Notice {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
        code: String,
    },
    Delta {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
        text: String,
    },
    /// Ephemeral reasoning for the sole currently attached subscription.
    /// A reconnect receives a redacted state/counter projection instead.
    ReasoningDelta {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
        reasoning_sequence: u32,
        delta: crate::providers::ReasoningText,
    },
    /// A reconnect-safe cursor checkpoint for omitted live reasoning. It is
    /// deliberately non-terminal and has no text field.
    ReasoningCheckpoint {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
        reasoning_sequence: u32,
        event_count: u64,
        byte_count: u64,
    },
    /// Reasoning lifecycle/counters. This frame contains no provider text and
    /// is strictly terminal for the reasoning plane.
    ReasoningState {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
        reasoning_sequence: u32,
        state: crate::providers::ReasoningTerminalState,
        event_count: u64,
        byte_count: u64,
    },
    ProviderDone {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
    },
    CancelRequested {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
    },
    Terminal {
        subscription: GuiChatSubscriptionMetadata,
        sequence: u64,
        state: GuiChatTerminalState,
        provider: String,
        model: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiChatBridgeErrorCode {
    InvalidRequest,
    BootChanged,
    Unauthorized,
    Forbidden,
    Unavailable,
    Busy,
    Conflict,
    ConsentRequired,
    AttachmentRejected,
    ReplayGap,
    CancelIndeterminate,
    Internal,
}
#[derive(Clone, PartialEq, Eq)]
pub struct GuiChatBridgeError {
    pub code: GuiChatBridgeErrorCode,
    pub retryable: bool,
    detail: &'static str,
}
impl GuiChatBridgeError {
    pub const fn invalid(detail: &'static str) -> Self {
        Self {
            code: GuiChatBridgeErrorCode::InvalidRequest,
            retryable: false,
            detail,
        }
    }
}
impl fmt::Debug for GuiChatBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuiChatBridgeError")
            .field("code", &self.code)
            .field("retryable", &self.retryable)
            .finish()
    }
}
impl fmt::Display for GuiChatBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail)
    }
}
impl std::error::Error for GuiChatBridgeError {}
pub type GuiChatBridgeResult<T> = Result<T, GuiChatBridgeError>;

pub trait GuiChatBridgeEventSink: Send {
    fn on_event(&mut self, event: GuiChatBridgeEvent) -> GuiChatBridgeResult<()>;
}

/// The later core-owned adapter binds an attested home and existing authenticated
/// audit-RPC endpoint. It alone maps the explicit UI policy to the existing
/// request-bound verifier and opaque proof.
#[async_trait]
pub trait GuiChatBridge: Send + Sync {
    async fn preflight(
        &self,
        input: GuiChatBridgePreflightInput,
    ) -> GuiChatBridgeResult<GuiChatBridgePreflight>;
    async fn decide(
        &self,
        preflight: GuiChatBridgePreflightReceipt,
        decision: GuiChatConsentDecision,
    ) -> GuiChatBridgeResult<GuiChatBridgeDecisionOutcome>;
    async fn start(
        &self,
        decision: GuiChatBridgeDecisionReceipt,
    ) -> GuiChatBridgeResult<GuiChatBridgeTurn>;
    async fn active(&self) -> GuiChatBridgeResult<Option<GuiChatBridgeTurn>>;
    async fn exchange_same_session_attach(
        &self,
        turn: &GuiChatBridgeTurn,
        surface: GuiChatSurface,
    ) -> GuiChatBridgeResult<GuiChatBridgeSubscription>;
    async fn attach(
        &self,
        subscription: GuiChatBridgeSubscription,
        after_sequence: u64,
        sink: &mut dyn GuiChatBridgeEventSink,
    ) -> GuiChatBridgeResult<()>;
    async fn cancel(&self, turn: &GuiChatBridgeTurn) -> GuiChatBridgeResult<()>;
    async fn status(&self, turn: &GuiChatBridgeTurn) -> GuiChatBridgeResult<GuiChatTurnMetadata>;
}

/// Explicitly feature-gated integration support. Fixtures carry no proof,
/// capability, grant, or wire DTO; a real adapter rejects them before any write.
#[cfg(feature = "gui-bridge-test-support")]
pub mod gui_bridge_test_support {
    use super::*;
    fn fixture() -> GuiChatSealedHandle {
        GuiChatSealedHandle::Fixture
    }
    pub fn new_turn_id() -> GuiChatTurnId {
        GuiChatTurnId(Uuid::now_v7())
    }
    pub fn preflight_receipt() -> GuiChatBridgePreflightReceipt {
        GuiChatBridgePreflightReceipt { sealed: fixture() }
    }
    pub fn decision_receipt() -> GuiChatBridgeDecisionReceipt {
        GuiChatBridgeDecisionReceipt { sealed: fixture() }
    }
    pub fn turn(metadata: GuiChatTurnMetadata) -> GuiChatBridgeTurn {
        GuiChatBridgeTurn {
            metadata,
            sealed: fixture(),
        }
    }
    pub fn subscription(metadata: GuiChatSubscriptionMetadata) -> GuiChatBridgeSubscription {
        GuiChatBridgeSubscription {
            metadata,
            sealed: fixture(),
        }
    }
}

struct CoreGuiChatBridge {
    home: PathBuf,
    boot_id: String,
    active: std::sync::Mutex<Option<ActiveGrant>>,
}
struct ActiveGrant {
    origin_surface: GuiChatSurface,
    session_id: String,
    grant: crate::daemon::gui_chat_protocol::GuiChatOpaqueCapability,
    start: crate::daemon::gui_chat_protocol::GuiChatStartResponse,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct PreflightSealed {
    request: crate::daemon::gui_chat_protocol::GuiChatPreflightRequest,
    response: crate::daemon::gui_chat_protocol::GuiChatPreflightResponse,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct DecisionSealed {
    request: crate::daemon::gui_chat_protocol::GuiChatPreflightRequest,
    turn_intent_digest: crate::daemon::gui_chat_protocol::GuiChatDigest,
    start_capability: crate::daemon::gui_chat_protocol::GuiChatOpaqueCapability,
    attachment_tickets: Vec<crate::daemon::gui_chat_protocol::GuiChatAttachmentTicket>,
}

fn seal_approved_decision(
    request: crate::daemon::gui_chat_protocol::GuiChatPreflightRequest,
    response: crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse,
) -> GuiChatBridgeResult<DecisionSealed> {
    match response {
        crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse::Approved {
            turn_intent_digest,
            start_capability,
            attachment_tickets,
            ..
        } => Ok(DecisionSealed {
            request,
            turn_intent_digest,
            start_capability,
            attachment_tickets,
        }),
        crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse::Denied { .. } => {
            Err(bridge_error("consent decision denied"))
        }
    }
}

fn bridge_error(detail: &'static str) -> GuiChatBridgeError {
    GuiChatBridgeError {
        code: GuiChatBridgeErrorCode::Unavailable,
        retryable: true,
        detail,
    }
}
fn seal<T: serde::Serialize>(value: &T) -> GuiChatBridgeResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| bridge_error("seal GUI bridge receipt"))
}
fn unseal<T: serde::de::DeserializeOwned>(value: &[u8]) -> GuiChatBridgeResult<T> {
    serde_json::from_slice(value).map_err(|_| bridge_error("invalid sealed GUI bridge receipt"))
}
fn unseal_handle<T: serde::de::DeserializeOwned>(
    handle: &GuiChatSealedHandle,
) -> GuiChatBridgeResult<T> {
    unseal(
        handle
            .live_bytes()
            .ok_or_else(|| bridge_error("fixture handle rejected before audit-RPC write"))?,
    )
}
fn bridge_client<T>(
    result: Result<T, crate::daemon::audit_rpc::GuiChatClientError>,
) -> GuiChatBridgeResult<T> {
    result.map_err(|_| bridge_error("authenticated GUI chat RPC unavailable or indeterminate"))
}

/// Real core-owned acquisition. The GUI supplies no home/endpoint/token: the
/// default process instance home is resolved here and its live daemon proof
/// becomes the exact `expected_boot_id` commitment for every wire request.
pub fn bridge_for_attested_current_instance()
-> GuiChatBridgeResult<std::sync::Arc<dyn GuiChatBridge>> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let boot_id = crate::daemon::audit_rpc::attested_gui_chat_boot_id(&home)
        .map_err(|_| bridge_error("no attested live GUI chat daemon"))?;
    Ok(std::sync::Arc::new(CoreGuiChatBridge {
        home,
        boot_id,
        active: std::sync::Mutex::new(None),
    }))
}

#[async_trait]
impl GuiChatBridge for CoreGuiChatBridge {
    async fn preflight(
        &self,
        input: GuiChatBridgePreflightInput,
    ) -> GuiChatBridgeResult<GuiChatBridgePreflight> {
        let request = crate::daemon::gui_chat_protocol::GuiChatPreflightRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            request_id: crate::daemon::gui_chat_protocol::GuiChatRequestId(
                input.request_id.as_uuid(),
            ),
            session_id: input.session_id,
            origin_surface: match input.origin_surface {
                GuiChatSurface::Main => crate::daemon::gui_chat_protocol::GuiChatSurface::Main,
                GuiChatSurface::Buddy => crate::daemon::gui_chat_protocol::GuiChatSurface::Buddy,
            },
            message: input.message,
            model: input.model,
            skill_id: input.skill_id,
            incognito: input.incognito,
            reasoning_display: input.reasoning_display,
            attachments: input
                .attachment_paths
                .into_iter()
                .map(
                    |path| crate::daemon::gui_chat_protocol::GuiChatAttachmentCandidate {
                        path: path.to_string_lossy().into_owned(),
                    },
                )
                .collect(),
        };
        crate::daemon::gui_chat_protocol::validate_preflight_request(&request)
            .map_err(|_| GuiChatBridgeError::invalid("preflight"))?;
        let response = bridge_client(
            crate::daemon::audit_rpc::gui_chat_post(
                &self.home,
                crate::daemon::gui_chat_protocol::GUI_CHAT_V1_CONSENT_PREFLIGHT_PATH,
                &request,
            )
            .await,
        )?;
        crate::daemon::gui_chat_protocol::validate_preflight_response(&response)
            .map_err(|_| bridge_error("invalid preflight response"))?;
        match response.consent.clone() {
            crate::daemon::gui_chat_protocol::GuiChatConsentPreflightState::Ready => {
                let proof=crate::cli::consent_challenge::mint_ready_request_bound_gui_chat_consent(&self.home, &response.preflight_descriptor_digest.0, &response.consent_challenge.0, &request.session_id, crate::time::now_unix_secs()).map_err(|_|bridge_error("ready existing-grant verification failed"))?;
                let decide=crate::daemon::gui_chat_protocol::GuiChatConsentDecisionRequest { schema_version:1, expected_boot_id:self.boot_id.clone(), preflight_id:response.preflight_id.clone(), preflight_descriptor_digest:response.preflight_descriptor_digest.clone(), consent_challenge:response.consent_challenge.clone(), decision:crate::daemon::gui_chat_protocol::GuiChatConsentDecision::AllowOnce, consent_proof:Some(crate::daemon::gui_chat_protocol::GuiChatConsentProof(proof.to_string())) };
                crate::daemon::gui_chat_protocol::validate_decide_request(&decide).map_err(|_|bridge_error("invalid ready proof"))?;
                let reply:crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse=bridge_client(crate::daemon::audit_rpc::gui_chat_post(&self.home,crate::daemon::gui_chat_protocol::GUI_CHAT_V1_CONSENT_DECIDE_PATH,&decide).await)?;
                crate::daemon::gui_chat_protocol::validate_decide_response(&reply).map_err(|_|bridge_error("invalid ready decision response"))?;
                match &reply { crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse::Denied { expected_boot_id, .. } | crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse::Approved { expected_boot_id, .. } if expected_boot_id != &self.boot_id => return Err(bridge_error("daemon boot changed during ready decision")), _ => {} }
                let sealed=seal_approved_decision(request,reply)?;
                Ok(GuiChatBridgePreflight::Ready { decision: GuiChatBridgeDecisionReceipt::from_live(seal(&sealed)?) })
            }
            crate::daemon::gui_chat_protocol::GuiChatConsentPreflightState::ConfirmationRequired { prompt } => {
                if prompt.request_id != request.request_id { return Err(bridge_error("consent prompt request binding mismatch")); }
                let receipt=GuiChatBridgePreflightReceipt::from_live(seal(&PreflightSealed { request, response })?);
                Ok(GuiChatBridgePreflight::ConfirmationRequired {
                    receipt,
                    prompt: GuiChatConsentPrompt {
                        request_id: input.request_id,
                        routes: prompt
                            .routes
                            .into_iter()
                            .map(|route| GuiChatConsentRoute {
                                provider: route.provider,
                                endpoint_origin: route.endpoint_origin,
                            })
                            .collect(),
                        expires_at_unix_ms: prompt.expires_at_unix_ms,
                    },
                })
            }
        }
    }
    async fn decide(
        &self,
        preflight: GuiChatBridgePreflightReceipt,
        decision: GuiChatConsentDecision,
    ) -> GuiChatBridgeResult<GuiChatBridgeDecisionOutcome> {
        let sealed: PreflightSealed = unseal_handle(&preflight.sealed)?;
        let proof = match decision {
            GuiChatConsentDecision::Deny => None,
            GuiChatConsentDecision::AllowOnce | GuiChatConsentDecision::AllowAlways => {
                crate::cli::consent_challenge::decide_request_bound_gui_chat_consent(
                    &self.home,
                    &sealed.response.consent_challenge.0,
                    &sealed.response.preflight_descriptor_digest.0,
                    &sealed.request.session_id,
                    match decision {
                        GuiChatConsentDecision::AllowOnce => {
                            crate::cli::consent_challenge::ChatConsentDecision::AllowOnce
                        }
                        GuiChatConsentDecision::AllowAlways => {
                            crate::cli::consent_challenge::ChatConsentDecision::AllowAlways
                        }
                        GuiChatConsentDecision::Deny => unreachable!(),
                    },
                )
                .await
                .map_err(|_| bridge_error("verified local consent unavailable"))?
                .map(|proof| {
                    crate::daemon::gui_chat_protocol::GuiChatConsentProof(proof.to_string())
                })
            }
        };
        let request = crate::daemon::gui_chat_protocol::GuiChatConsentDecisionRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            preflight_id: sealed.response.preflight_id,
            preflight_descriptor_digest: sealed.response.preflight_descriptor_digest,
            consent_challenge: sealed.response.consent_challenge,
            decision: map_decision(decision),
            consent_proof: proof,
        };
        crate::daemon::gui_chat_protocol::validate_decide_request(&request)
            .map_err(|_| bridge_error("invalid core consent proof"))?;
        let response = bridge_client(
            crate::daemon::audit_rpc::gui_chat_post(
                &self.home,
                crate::daemon::gui_chat_protocol::GUI_CHAT_V1_CONSENT_DECIDE_PATH,
                &request,
            )
            .await,
        )?;
        crate::daemon::gui_chat_protocol::validate_decide_response(&response)
            .map_err(|_| bridge_error("invalid consent response"))?;
        match &response {
            crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse::Denied {
                expected_boot_id,
                ..
            }
            | crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse::Approved {
                expected_boot_id,
                ..
            } if expected_boot_id != &self.boot_id => {
                return Err(bridge_error("daemon boot changed during consent"));
            }
            _ => {}
        }
        match response { crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse::Denied { .. } => Ok(GuiChatBridgeDecisionOutcome::Denied), approved @ crate::daemon::gui_chat_protocol::GuiChatConsentDecisionResponse::Approved { .. } => { let sealed=seal_approved_decision(sealed.request,approved)?; Ok(GuiChatBridgeDecisionOutcome::Approved(GuiChatBridgeDecisionReceipt::from_live(seal(&sealed)?))) } }
    }
    async fn start(
        &self,
        decision: GuiChatBridgeDecisionReceipt,
    ) -> GuiChatBridgeResult<GuiChatBridgeTurn> {
        let sealed: DecisionSealed = unseal_handle(&decision.sealed)?;
        let request = crate::daemon::gui_chat_protocol::GuiChatStartRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            request_id: sealed.request.request_id,
            session_id: sealed.request.session_id.clone(),
            origin_surface: sealed.request.origin_surface,
            turn_intent_digest: sealed.turn_intent_digest,
            start_capability: sealed.start_capability,
            attachment_tickets: sealed.attachment_tickets,
        };
        crate::daemon::gui_chat_protocol::validate_start_request(&request)
            .map_err(|_| bridge_error("invalid start receipt"))?;
        let response = bridge_client(
            crate::daemon::audit_rpc::gui_chat_post(
                &self.home,
                crate::daemon::gui_chat_protocol::GUI_CHAT_V1_START_PATH,
                &request,
            )
            .await,
        )?;
        crate::daemon::gui_chat_protocol::validate_start_response(&response)
            .map_err(|_| bridge_error("invalid start response"))?;
        if response.expected_boot_id != self.boot_id {
            return Err(bridge_error("daemon boot changed during start"));
        }
        let grant = response.same_session_attach_grant.grant.clone();
        self.active
            .lock()
            .map_err(|_| bridge_error("GUI bridge state poisoned"))?
            .replace(ActiveGrant {
                origin_surface: input_surface(request.origin_surface),
                session_id: sealed.request.session_id,
                grant,
                start: response.clone(),
            });
        Ok(GuiChatBridgeTurn::from_live(
            GuiChatTurnMetadata {
                boot_id: self.boot_id.clone(),
                turn_id: GuiChatTurnId(response.turn_id.0),
                origin_surface: input_surface(request.origin_surface),
                phase: GuiChatPhase::Waiting,
                latest_sequence: response.initial_sequence,
            },
            seal(&response)?,
        ))
    }
    async fn active(&self) -> GuiChatBridgeResult<Option<GuiChatBridgeTurn>> {
        let Some(active) = self
            .active
            .lock()
            .map_err(|_| bridge_error("GUI bridge state poisoned"))?
            .as_ref()
            .map(|a| {
                (
                    a.origin_surface,
                    a.session_id.clone(),
                    a.grant.clone(),
                    a.start.clone(),
                )
            })
        else {
            return Ok(None);
        };
        let request = crate::daemon::gui_chat_protocol::GuiChatActiveRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            session_id: active.1,
            same_session_attach_grant: active.2,
        };
        let response = bridge_client(
            crate::daemon::audit_rpc::gui_chat_post(
                &self.home,
                crate::daemon::gui_chat_protocol::GUI_CHAT_V1_ACTIVE_PATH,
                &request,
            )
            .await,
        )?;
        crate::daemon::gui_chat_protocol::validate_active_response(&response)
            .map_err(|_| bridge_error("invalid active response"))?;
        if response.expected_boot_id != self.boot_id {
            return Err(bridge_error("daemon boot changed during active"));
        }
        let Some(turn) = response.active_turn else {
            self.active
                .lock()
                .map_err(|_| bridge_error("GUI bridge state poisoned"))?
                .take();
            return Ok(None);
        };
        Ok(Some(GuiChatBridgeTurn::from_live(
            GuiChatTurnMetadata {
                boot_id: self.boot_id.clone(),
                turn_id: GuiChatTurnId(turn.turn_id.0),
                origin_surface: active.0,
                phase: map_phase(turn.phase),
                latest_sequence: turn.latest_sequence,
            },
            seal(&active.3)?,
        )))
    }
    async fn exchange_same_session_attach(
        &self,
        turn: &GuiChatBridgeTurn,
        surface: GuiChatSurface,
    ) -> GuiChatBridgeResult<GuiChatBridgeSubscription> {
        if turn.metadata.boot_id != self.boot_id {
            return Err(bridge_error("turn boot changed"));
        }
        let start: crate::daemon::gui_chat_protocol::GuiChatStartResponse =
            unseal_handle(&turn.sealed)?;
        let request = crate::daemon::gui_chat_protocol::GuiChatAttachExchangeRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            turn_id: start.turn_id,
            session_id: start.same_session_attach_grant.session_id.clone(),
            desired_surface: map_surface(surface),
            grant: start.same_session_attach_grant.grant,
        };
        crate::daemon::gui_chat_protocol::validate_attach_exchange_request(&request)
            .map_err(|_| bridge_error("invalid attach exchange receipt"))?;
        let response: crate::daemon::gui_chat_protocol::GuiChatAttachExchangeResponse =
            bridge_client(
                crate::daemon::audit_rpc::gui_chat_post(
                    &self.home,
                    crate::daemon::gui_chat_protocol::GUI_CHAT_V1_ATTACH_EXCHANGE_PATH,
                    &request,
                )
                .await,
            )?;
        crate::daemon::gui_chat_protocol::validate_attach_exchange_response(&response)
            .map_err(|_| bridge_error("invalid attach exchange response"))?;
        if response.expected_boot_id != self.boot_id || response.surface != map_surface(surface) {
            return Err(bridge_error("attach exchange binding mismatch"));
        }
        Ok(GuiChatBridgeSubscription::from_live(
            GuiChatSubscriptionMetadata {
                boot_id: self.boot_id.clone(),
                turn_id: GuiChatTurnId(response.turn_id.0),
                surface,
                generation: response.subscription_generation,
                latest_sequence: response.initial_sequence,
            },
            seal(&response)?,
        ))
    }
    async fn attach(
        &self,
        subscription: GuiChatBridgeSubscription,
        after_sequence: u64,
        sink: &mut dyn GuiChatBridgeEventSink,
    ) -> GuiChatBridgeResult<()> {
        if subscription.metadata.boot_id != self.boot_id {
            return Err(bridge_error("subscription boot changed"));
        }
        let sealed: crate::daemon::gui_chat_protocol::GuiChatAttachExchangeResponse =
            unseal_handle(&subscription.sealed)?;
        let request = crate::daemon::gui_chat_protocol::GuiChatAttachRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            turn_id: sealed.turn_id,
            session_id: sealed.session_id,
            surface: sealed.surface,
            subscription_generation: sealed.subscription_generation,
            attach_capability: sealed.attach_capability,
            after_sequence,
        };
        let metadata = subscription.metadata.clone();
        let expected_boot = self.boot_id.clone();
        let mut terminal = false;
        let mut deliver=|frame:crate::daemon::gui_chat_protocol::GuiChatStreamFrame| -> Result<(),crate::daemon::audit_rpc::GuiChatClientError> {
            if frame.boot_id != expected_boot { return Err(crate::daemon::audit_rpc::GuiChatClientError::Indeterminate("frame boot changed".into())); }
            terminal=matches!(&frame.payload,crate::daemon::gui_chat_protocol::GuiChatFramePayload::Terminal{..});
            sink.on_event(map_frame(frame,metadata.clone())).map_err(|_|crate::daemon::audit_rpc::GuiChatClientError::Indeterminate("GUI sink rejected frame".into()))
        };
        bridge_client(
            crate::daemon::audit_rpc::gui_chat_attach(&self.home, &request, &mut deliver).await,
        )?;
        if terminal {
            self.active
                .lock()
                .map_err(|_| bridge_error("GUI bridge state poisoned"))?
                .take();
        }
        Ok(())
    }
    async fn cancel(&self, turn: &GuiChatBridgeTurn) -> GuiChatBridgeResult<()> {
        let start: crate::daemon::gui_chat_protocol::GuiChatStartResponse =
            unseal_handle(&turn.sealed)?;
        let request = crate::daemon::gui_chat_protocol::GuiChatCancelRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            turn_id: start.turn_id,
            session_id: start.same_session_attach_grant.session_id,
            cancel_capability: start.cancel_capability,
        };
        let _: crate::daemon::gui_chat_protocol::GuiChatCancelResponse = bridge_client(
            crate::daemon::audit_rpc::gui_chat_post(
                &self.home,
                crate::daemon::gui_chat_protocol::GUI_CHAT_V1_CANCEL_PATH,
                &request,
            )
            .await,
        )?;
        Ok(())
    }
    async fn status(&self, turn: &GuiChatBridgeTurn) -> GuiChatBridgeResult<GuiChatTurnMetadata> {
        if turn.metadata.boot_id != self.boot_id {
            return Err(bridge_error("turn boot changed"));
        }
        let start: crate::daemon::gui_chat_protocol::GuiChatStartResponse =
            unseal_handle(&turn.sealed)?;
        let request = crate::daemon::gui_chat_protocol::GuiChatStatusRequest {
            schema_version: 1,
            expected_boot_id: self.boot_id.clone(),
            turn_id: start.turn_id,
            session_id: start.same_session_attach_grant.session_id,
            attach_capability: start.origin_attach_capability,
        };
        let response: crate::daemon::gui_chat_protocol::GuiChatStatusResponse = bridge_client(
            crate::daemon::audit_rpc::gui_chat_post(
                &self.home,
                crate::daemon::gui_chat_protocol::GUI_CHAT_V1_STATUS_PATH,
                &request,
            )
            .await,
        )?;
        crate::daemon::gui_chat_protocol::validate_status_response(&response)
            .map_err(|_| bridge_error("invalid status response"))?;
        if response.expected_boot_id != self.boot_id {
            return Err(bridge_error("daemon boot changed during status"));
        }
        Ok(GuiChatTurnMetadata {
            boot_id: self.boot_id.clone(),
            turn_id: GuiChatTurnId(response.turn_id.0),
            origin_surface: turn.metadata.origin_surface,
            phase: map_phase(response.phase),
            latest_sequence: response.latest_sequence,
        })
    }
}
fn map_decision(
    decision: GuiChatConsentDecision,
) -> crate::daemon::gui_chat_protocol::GuiChatConsentDecision {
    match decision {
        GuiChatConsentDecision::Deny => {
            crate::daemon::gui_chat_protocol::GuiChatConsentDecision::Deny
        }
        GuiChatConsentDecision::AllowOnce => {
            crate::daemon::gui_chat_protocol::GuiChatConsentDecision::AllowOnce
        }
        GuiChatConsentDecision::AllowAlways => {
            crate::daemon::gui_chat_protocol::GuiChatConsentDecision::AllowAlways
        }
    }
}
fn map_surface(surface: GuiChatSurface) -> crate::daemon::gui_chat_protocol::GuiChatSurface {
    match surface {
        GuiChatSurface::Main => crate::daemon::gui_chat_protocol::GuiChatSurface::Main,
        GuiChatSurface::Buddy => crate::daemon::gui_chat_protocol::GuiChatSurface::Buddy,
    }
}
fn input_surface(surface: crate::daemon::gui_chat_protocol::GuiChatSurface) -> GuiChatSurface {
    match surface {
        crate::daemon::gui_chat_protocol::GuiChatSurface::Main => GuiChatSurface::Main,
        crate::daemon::gui_chat_protocol::GuiChatSurface::Buddy => GuiChatSurface::Buddy,
    }
}
fn map_phase(phase: crate::daemon::gui_chat_protocol::GuiChatPhase) -> GuiChatPhase {
    match phase {
        crate::daemon::gui_chat_protocol::GuiChatPhase::Waiting => GuiChatPhase::Waiting,
        crate::daemon::gui_chat_protocol::GuiChatPhase::Receiving => GuiChatPhase::Receiving,
        crate::daemon::gui_chat_protocol::GuiChatPhase::Finalizing => GuiChatPhase::Finalizing,
    }
}
fn map_frame(
    frame: crate::daemon::gui_chat_protocol::GuiChatStreamFrame,
    subscription: GuiChatSubscriptionMetadata,
) -> GuiChatBridgeEvent {
    let sequence = frame.sequence;
    match frame.payload {
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::Accepted => {
            GuiChatBridgeEvent::Accepted {
                subscription,
                sequence,
            }
        }
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::PhaseChanged { phase } => {
            GuiChatBridgeEvent::PhaseChanged {
                subscription,
                sequence,
                phase: map_phase(phase),
            }
        }
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::Notice { code } => {
            GuiChatBridgeEvent::Notice {
                subscription,
                sequence,
                code,
            }
        }
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::Delta { text } => {
            GuiChatBridgeEvent::Delta {
                subscription,
                sequence,
                text,
            }
        }
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::ReasoningDelta {
            reasoning_sequence,
            delta,
        } => GuiChatBridgeEvent::ReasoningDelta {
            subscription,
            sequence,
            reasoning_sequence,
            delta: crate::providers::ReasoningText::new(delta),
        },
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::ReasoningCheckpoint {
            reasoning_sequence,
            event_count,
            byte_count,
        } => GuiChatBridgeEvent::ReasoningCheckpoint {
            subscription,
            sequence,
            reasoning_sequence,
            event_count,
            byte_count,
        },
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::ReasoningState {
            reasoning_sequence,
            state,
            event_count,
            byte_count,
        } => GuiChatBridgeEvent::ReasoningState {
            subscription,
            sequence,
            reasoning_sequence,
            state,
            event_count,
            byte_count,
        },
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::ProviderDone => {
            GuiChatBridgeEvent::ProviderDone {
                subscription,
                sequence,
            }
        }
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::CancelRequested => {
            GuiChatBridgeEvent::CancelRequested {
                subscription,
                sequence,
            }
        }
        crate::daemon::gui_chat_protocol::GuiChatFramePayload::Terminal { terminal } => {
            GuiChatBridgeEvent::Terminal {
                subscription,
                sequence,
                state: match terminal.state {
                    crate::daemon::gui_chat_protocol::GuiChatTerminalState::Complete => {
                        GuiChatTerminalState::Complete
                    }
                    crate::daemon::gui_chat_protocol::GuiChatTerminalState::Cancelled => {
                        GuiChatTerminalState::Cancelled
                    }
                    crate::daemon::gui_chat_protocol::GuiChatTerminalState::Failed => {
                        GuiChatTerminalState::Failed
                    }
                    crate::daemon::gui_chat_protocol::GuiChatTerminalState::CrashUnknown => {
                        GuiChatTerminalState::CrashUnknown
                    }
                    crate::daemon::gui_chat_protocol::GuiChatTerminalState::Indeterminate => {
                        GuiChatTerminalState::Indeterminate
                    }
                },
                provider: terminal.provider,
                model: terminal.model,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_handles_redact_live_bytes() {
        let receipt = GuiChatBridgePreflightReceipt::from_live(b"daemon-capability-raw".to_vec());
        assert!(!format!("{receipt:?}").contains("daemon-capability-raw"));
    }
    #[test]
    fn public_request_id_requires_v7() {
        assert!(GuiChatRequestId::parse("550e8400-e29b-41d4-a716-446655440000").is_err());
    }
    #[cfg(feature = "gui-bridge-test-support")]
    #[tokio::test]
    async fn fixture_decision_is_rejected_before_any_audit_rpc_write() {
        let bridge = CoreGuiChatBridge {
            home: PathBuf::from("fixture-does-not-connect"),
            boot_id: "boot".into(),
            active: std::sync::Mutex::new(None),
        };
        let error = bridge
            .start(gui_bridge_test_support::decision_receipt())
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fixture handle rejected before audit-RPC write")
        );
    }
}
