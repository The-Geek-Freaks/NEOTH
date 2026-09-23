//! W41 proposal-only sealed v1 GUI chat protocol contract, revision 03.
//!
//! This file is deliberately not declared from daemon/mod.rs yet.  It freezes
//! the DTO, digest and handoff boundary that later runtime, RPC and GUI owners
//! will adopt together.  It does not create a listener, scheduler or provider.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::daemon::audit_rpc::AuditStream;

// Proposal-02 keeps this wire module crate-private. The public GUI facade is
// gui_chat_bridge and never exposes this stream or engine event type.

pub(crate) const GUI_CHAT_V1_SCHEMA_VERSION: u8 = 1;
pub(crate) const GUI_CHAT_V1_CONSENT_PREFLIGHT_PATH: &str = "/chat/v1/consent/preflight";
pub(crate) const GUI_CHAT_V1_CONSENT_DECIDE_PATH: &str = "/chat/v1/consent/decide";
pub(crate) const GUI_CHAT_V1_START_PATH: &str = "/chat/v1/start";
pub(crate) const GUI_CHAT_V1_ATTACH_EXCHANGE_PATH: &str = "/chat/v1/attach/exchange";
pub(crate) const GUI_CHAT_V1_ATTACH_PATH: &str = "/chat/v1/attach";
pub(crate) const GUI_CHAT_V1_CANCEL_PATH: &str = "/chat/v1/cancel";
pub(crate) const GUI_CHAT_V1_STATUS_PATH: &str = "/chat/v1/status";
pub(crate) const GUI_CHAT_V1_ACTIVE_PATH: &str = "/chat/v1/active";

pub(crate) const GUI_CHAT_MESSAGE_MAX_BYTES: usize = 3 * 1024;
pub(crate) const GUI_CHAT_SESSION_ID_MAX_BYTES: usize = 128;
pub(crate) const GUI_CHAT_MODEL_MAX_BYTES: usize = 256;
pub(crate) const GUI_CHAT_SKILL_MAX_BYTES: usize = 256;
pub(crate) const GUI_CHAT_ATTACHMENT_MAX_COUNT: usize = 8;
pub(crate) const GUI_CHAT_ATTACHMENT_PATH_MAX_BYTES: usize = 4096;
pub(crate) const GUI_CHAT_ATTACHMENT_MEDIA_KIND_MAX_BYTES: usize = 96;
pub(crate) const GUI_CHAT_OPAQUE_CAPABILITY_MAX_BYTES: usize = 512;
pub(crate) const GUI_CHAT_BOOT_ID_MAX_BYTES: usize = 128;
pub(crate) const GUI_CHAT_FRAME_MAX_BYTES: usize = 64 * 1024;
pub(crate) const GUI_CHAT_REASONING_EVENT_MAX: u64 = 256;
pub(crate) const GUI_CHAT_REASONING_BYTE_MAX: u64 = 64 * 1024;
pub(crate) const GUI_CHAT_REPLAY_MAX_BYTES: usize = 1024 * 1024;
pub(crate) const GUI_CHAT_NOTICE_MAX_BYTES: usize = 512;
pub(crate) const GUI_CHAT_PROVIDER_MAX_BYTES: usize = 128;
pub(crate) const GUI_CHAT_CONSENT_ROUTE_MAX_COUNT: usize = 8;
pub(crate) const GUI_CHAT_CONSENT_ROUTE_PROVIDER_MAX_BYTES: usize = 128;
pub(crate) const GUI_CHAT_CONSENT_ROUTE_ORIGIN_MAX_BYTES: usize = 256;
pub(crate) const GUI_CHAT_RESPONSE_HASH_BYTES: usize = 32;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct GuiChatDigest(pub(crate) String);

impl fmt::Debug for GuiChatDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GuiChatDigest(<sha256>)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct GuiChatOpaqueCapability(pub(crate) String);

impl fmt::Debug for GuiChatOpaqueCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GuiChatOpaqueCapability(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct GuiChatRequestId(pub(crate) Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct GuiChatTurnId(pub(crate) Uuid);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatSurface {
    Main,
    Buddy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatPhase {
    Waiting,
    Receiving,
    Finalizing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatTerminalState {
    Complete,
    Cancelled,
    Failed,
    CrashUnknown,
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatAttachmentCandidate {
    pub(crate) path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatPreflightRequest {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) request_id: GuiChatRequestId,
    pub(crate) session_id: String,
    pub(crate) origin_surface: GuiChatSurface,
    pub(crate) message: String,
    pub(crate) model: Option<String>,
    pub(crate) skill_id: Option<String>,
    pub(crate) incognito: bool,
    /// Per-turn presentation consent. Historical preflights and callers that
    /// do not know this field are always denied display rather than inheriting
    /// a preference from configuration or process state.
    #[serde(default)]
    pub(crate) reasoning_display: bool,
    pub(crate) attachments: Vec<GuiChatAttachmentCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatAttachmentManifestEntry {
    pub(crate) ordinal: u16,
    pub(crate) content_digest: GuiChatDigest,
    pub(crate) byte_len: u64,
    pub(crate) media_kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatConsentRouteWire {
    pub(crate) provider: String,
    pub(crate) endpoint_origin: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatConsentPromptWire {
    pub(crate) request_id: GuiChatRequestId,
    pub(crate) routes: Vec<GuiChatConsentRouteWire>,
    pub(crate) expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
pub(crate) enum GuiChatConsentPreflightState {
    Ready,
    ConfirmationRequired { prompt: GuiChatConsentPromptWire },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatPreflightResponse {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) preflight_id: GuiChatOpaqueCapability,
    pub(crate) preflight_descriptor_digest: GuiChatDigest,
    pub(crate) consent_challenge: GuiChatOpaqueCapability,
    pub(crate) attachment_manifest: Vec<GuiChatAttachmentManifestEntry>,
    pub(crate) consent: GuiChatConsentPreflightState,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct GuiChatConsentProof(pub(crate) String);

impl fmt::Debug for GuiChatConsentProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GuiChatConsentProof(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatConsentDecision {
    Deny,
    AllowOnce,
    AllowAlways,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatConsentDecisionRequest {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) preflight_id: GuiChatOpaqueCapability,
    pub(crate) preflight_descriptor_digest: GuiChatDigest,
    pub(crate) consent_challenge: GuiChatOpaqueCapability,
    pub(crate) decision: GuiChatConsentDecision,
    /// `None` is valid only for Deny. Allow decisions receive this only from
    /// the core-owned existing request-bound verifier.
    pub(crate) consent_proof: Option<GuiChatConsentProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatAttachmentTicket {
    pub(crate) ordinal: u16,
    pub(crate) ticket: GuiChatOpaqueCapability,
}

/// Denial is a normal terminal consent result. It contains no proof, ticket,
/// start capability, or provider admission authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "outcome", rename_all = "snake_case")]
pub(crate) enum GuiChatConsentDecisionResponse {
    Denied {
        schema_version: u8,
        expected_boot_id: String,
    },
    Approved {
        schema_version: u8,
        expected_boot_id: String,
        turn_intent_digest: GuiChatDigest,
        start_capability: GuiChatOpaqueCapability,
        attachment_tickets: Vec<GuiChatAttachmentTicket>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatStartRequest {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) request_id: GuiChatRequestId,
    pub(crate) session_id: String,
    pub(crate) origin_surface: GuiChatSurface,
    pub(crate) turn_intent_digest: GuiChatDigest,
    pub(crate) start_capability: GuiChatOpaqueCapability,
    pub(crate) attachment_tickets: Vec<GuiChatAttachmentTicket>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatSameSessionAttachGrant {
    pub(crate) grant: GuiChatOpaqueCapability,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) session_id: String,
    pub(crate) allowed_surfaces: Vec<GuiChatSurface>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatStartResponse {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) turn_intent_digest: GuiChatDigest,
    pub(crate) origin_attach_capability: GuiChatOpaqueCapability,
    pub(crate) cancel_capability: GuiChatOpaqueCapability,
    pub(crate) same_session_attach_grant: GuiChatSameSessionAttachGrant,
    pub(crate) initial_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatAttachExchangeRequest {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) session_id: String,
    pub(crate) desired_surface: GuiChatSurface,
    pub(crate) grant: GuiChatOpaqueCapability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatAttachExchangeResponse {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) session_id: String,
    pub(crate) surface: GuiChatSurface,
    pub(crate) subscription_generation: u64,
    pub(crate) attach_capability: GuiChatOpaqueCapability,
    pub(crate) initial_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatAttachRequest {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) session_id: String,
    pub(crate) surface: GuiChatSurface,
    pub(crate) subscription_generation: u64,
    pub(crate) attach_capability: GuiChatOpaqueCapability,
    pub(crate) after_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatCancelRequest {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) session_id: String,
    pub(crate) cancel_capability: GuiChatOpaqueCapability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatCancelOutcome {
    Accepted,
    AlreadyRequested,
    AlreadyTerminal,
    UnknownRequest,
    BootChanged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatCancelResponse {
    pub(crate) schema_version: u8,
    pub(crate) outcome: GuiChatCancelOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatStatusRequest {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) session_id: String,
    pub(crate) attach_capability: GuiChatOpaqueCapability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatStatusResponse {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) phase: GuiChatPhase,
    pub(crate) latest_sequence: u64,
    pub(crate) terminal: Option<GuiChatTerminal>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatActiveRequest {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) session_id: String,
    pub(crate) same_session_attach_grant: GuiChatOpaqueCapability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatActiveResponse {
    pub(crate) schema_version: u8,
    pub(crate) expected_boot_id: String,
    pub(crate) active_turn: Option<GuiChatActiveTurn>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatActiveTurn {
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) phase: GuiChatPhase,
    pub(crate) latest_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatSubscription {
    pub(crate) session_id: String,
    pub(crate) surface: GuiChatSurface,
    pub(crate) generation: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub(crate) enum GuiChatFramePayload {
    Accepted,
    PhaseChanged {
        phase: GuiChatPhase,
    },
    Notice {
        code: String,
    },
    /// Provider dispatch made no meaningful progress before the core-owned
    /// silence watchdog elapsed. This is a failed turn, never a completion.
    TurnSilenceTimeout {
        timeout_seconds: u64,
        retryable: bool,
    },
    Delta {
        text: String,
    },
    /// Live-only provider reasoning. The runtime never places this payload in
    /// a reconnectable replay record.
    ReasoningDelta {
        reasoning_sequence: u32,
        delta: String,
    },
    /// Metadata-only replay checkpoint. It contains no provider text and
    /// preserves the authenticated stream cursor when an earlier live-only
    /// delta is unavailable to a new attachment.
    ReasoningCheckpoint {
        reasoning_sequence: u32,
        event_count: u64,
        byte_count: u64,
    },
    /// Reasoning terminal state. This is never used as a replay placeholder:
    /// every one of its closed states terminates the reasoning plane.
    ReasoningState {
        reasoning_sequence: u32,
        state: crate::providers::ReasoningTerminalState,
        event_count: u64,
        byte_count: u64,
    },
    /// The already-reduced same-query projection. It has no recall text,
    /// request token, session, provider, or storage value; W246 may include
    /// passive typed source provenance for an available exact binding.
    RecallChipBatch {
        batch: GuiChatRecallChipBatch,
    },
    /// W162's producer-owned inner sequence and closed live state. This
    /// carries neither a CLI control token nor provider text or usage totals.
    ThroughputState {
        throughput_sequence: u64,
        state: GuiChatThroughputState,
    },
    ProviderDone,
    CancelRequested,
    Terminal {
        terminal: GuiChatTerminal,
    },
}

impl fmt::Debug for GuiChatFramePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReasoningDelta {
                reasoning_sequence, ..
            } => formatter
                .debug_struct("ReasoningDelta")
                .field("reasoning_sequence", reasoning_sequence)
                .field("delta", &"<redacted>")
                .finish(),
            Self::Accepted => formatter.write_str("Accepted"),
            Self::PhaseChanged { phase } => formatter
                .debug_struct("PhaseChanged")
                .field("phase", phase)
                .finish(),
            Self::Notice { code } => formatter
                .debug_struct("Notice")
                .field("code", code)
                .finish(),
            Self::TurnSilenceTimeout {
                timeout_seconds,
                retryable,
            } => formatter
                .debug_struct("TurnSilenceTimeout")
                .field("timeout_seconds", timeout_seconds)
                .field("retryable", retryable)
                .finish(),
            Self::Delta { text } => formatter.debug_struct("Delta").field("text", text).finish(),
            Self::ReasoningState {
                reasoning_sequence,
                state,
                event_count,
                byte_count,
            } => formatter
                .debug_struct("ReasoningState")
                .field("reasoning_sequence", reasoning_sequence)
                .field("state", state)
                .field("event_count", event_count)
                .field("byte_count", byte_count)
                .finish(),
            Self::ReasoningCheckpoint {
                reasoning_sequence,
                event_count,
                byte_count,
            } => formatter
                .debug_struct("ReasoningCheckpoint")
                .field("reasoning_sequence", reasoning_sequence)
                .field("event_count", event_count)
                .field("byte_count", byte_count)
                .finish(),
            Self::RecallChipBatch { batch } => formatter
                .debug_struct("RecallChipBatch")
                .field("batch", batch)
                .finish(),
            Self::ThroughputState {
                throughput_sequence,
                state,
            } => formatter
                .debug_struct("ThroughputState")
                .field("throughput_sequence", throughput_sequence)
                .field("state", state)
                .finish(),
            Self::ProviderDone => formatter.write_str("ProviderDone"),
            Self::CancelRequested => formatter.write_str("CancelRequested"),
            Self::Terminal { terminal } => formatter
                .debug_struct("Terminal")
                .field("terminal", terminal)
                .finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatStreamFrame {
    pub(crate) schema_version: u8,
    pub(crate) boot_id: String,
    pub(crate) turn_id: GuiChatTurnId,
    pub(crate) subscription: GuiChatSubscription,
    pub(crate) sequence: u64,
    pub(crate) payload: GuiChatFramePayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatUsage {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) elapsed_ms: u64,
}

/// W163's closed, content-free presentation status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatRecallChipStatus {
    Ready,
    NoRecall,
    Missing,
    Stale,
    Failed,
    Incognito,
}

/// W163's closed recall tier vocabulary. These values carry no source name or
/// recalled content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatRecallChipTier {
    Canonical,
    Hot,
    Warm,
    Cold,
    Unknown,
}

/// W163's closed source-trust projection. It is informational only and never
/// authorizes source lookup or navigation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatRecallChipSourceState {
    Available,
    Missing,
    Revoked,
    Untrusted,
}

/// The W246 closed warm-source kind. A summary citation carries the positive
/// consolidated snapshot identity; it never carries the negative event
/// sentinel used internally by legacy warm retrieval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatRecallWarmKind {
    Retained,
    Summary,
}

/// Content-free W246 Recall-chip provenance. This is a passive identity
/// projection only; it grants no lookup, navigation, or authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub(crate) enum GuiChatRecallChipCitation {
    Event {
        event_id: i64,
        event_type: u8,
    },
    WarmSnapshot {
        consolidated_id: i64,
        warm_kind: GuiChatRecallWarmKind,
        original_event_id: Option<i64>,
    },
    GroundTruth {
        fact_id: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatRecallChipRow {
    pub(crate) tier: GuiChatRecallChipTier,
    /// The already-computed Stage-3 score, present only for valid available
    /// warm rows. W167 does not recompute or normalize it.
    pub(crate) score: Option<f64>,
    pub(crate) source_state: GuiChatRecallChipSourceState,
    /// Omission is accepted only to decode a legacy W163 batch. A W246
    /// producer emits it solely for an available, exact typed source binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) citation: Option<GuiChatRecallChipCitation>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatRecallChipBatch {
    pub(crate) status: GuiChatRecallChipStatus,
    pub(crate) rows: Vec<GuiChatRecallChipRow>,
}

/// W162's closed measurement unit. This states the producer basis only; it
/// never exposes a provider token total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatThroughputBasis {
    VisibleEvent,
    TokenDelta,
}

/// Closed lifecycle reasons for an unavailable live rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatThroughputUnavailable {
    NoVisibleEvents,
    NoUsageReported,
    Cancelled,
    StreamError,
}

/// W162's already-produced current rate state. The daemon transport only maps
/// this closed value; it never derives a rate from text or usage totals.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum GuiChatThroughputState {
    Measuring {
        basis: GuiChatThroughputBasis,
        per_second: f64,
    },
    Paused {
        basis: GuiChatThroughputBasis,
    },
    Unavailable {
        reason: GuiChatThroughputUnavailable,
    },
}

/// An issuer-created response-feedback target. GUI transport carries this
/// opaque identity verbatim; it neither derives nor registers a target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatResponseFeedbackTarget {
    pub(crate) response_id: String,
    pub(crate) session_id: String,
    pub(crate) revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatTerminal {
    pub(crate) state: GuiChatTerminalState,
    pub(crate) response_digest: GuiChatDigest,
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) usage: GuiChatUsage,
    pub(crate) lifecycle_receipt_id: GuiChatDigest,
    /// Present only when the daemon producer issued this exact target after
    /// its terminal durability barrier. Omission remains wire-compatible.
    #[serde(default)]
    pub(crate) response_feedback_target: Option<GuiChatResponseFeedbackTarget>,
    /// A completed non-incognito response could not be issued as a feedback
    /// target. This never authorizes fallback creation by a GUI consumer.
    #[serde(default)]
    pub(crate) response_feedback_unavailable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuiChatErrorCode {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuiChatErrorResponse {
    pub(crate) schema_version: u8,
    pub(crate) code: GuiChatErrorCode,
    pub(crate) retryable: bool,
    pub(crate) detail: String,
}

#[derive(Debug, Error)]
pub(crate) enum GuiChatProtocolError {
    #[error("invalid GUI chat v1 request: {0}")]
    Invalid(&'static str),
    #[error("GUI chat v1 runtime error: {0:?}")]
    Runtime(GuiChatErrorResponse),
}

pub(crate) type GuiChatResult<T> = std::result::Result<T, GuiChatProtocolError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuiChatStagedAttachmentBinding {
    pub(crate) ordinal: u16,
    pub(crate) content_digest: GuiChatDigest,
    pub(crate) ticket_binding_digest: GuiChatDigest,
}

#[async_trait]
pub(crate) trait GuiChatRuntime: Send + Sync {
    async fn preflight(
        &self,
        request: GuiChatPreflightRequest,
    ) -> GuiChatResult<GuiChatPreflightResponse>;

    async fn decide(
        &self,
        request: GuiChatConsentDecisionRequest,
    ) -> GuiChatResult<GuiChatConsentDecisionResponse>;

    async fn start(&self, request: GuiChatStartRequest) -> GuiChatResult<GuiChatStartResponse>;

    async fn exchange_attach(
        &self,
        request: GuiChatAttachExchangeRequest,
    ) -> GuiChatResult<GuiChatAttachExchangeResponse>;

    async fn attach(&self, stream: AuditStream, request: GuiChatAttachRequest)
    -> GuiChatResult<()>;

    async fn cancel(&self, request: GuiChatCancelRequest) -> GuiChatResult<GuiChatCancelResponse>;

    async fn status(&self, request: GuiChatStatusRequest) -> GuiChatResult<GuiChatStatusResponse>;

    async fn active(&self, request: GuiChatActiveRequest) -> GuiChatResult<GuiChatActiveResponse>;

    async fn close_and_drain(&self);
}

pub(crate) fn preflight_descriptor_digest(
    request: &GuiChatPreflightRequest,
    manifest: &[GuiChatAttachmentManifestEntry],
    accepted_config_generation: u64,
    incognito_message_key: Option<&[u8]>,
) -> GuiChatResult<GuiChatDigest> {
    validate_preflight_request(request)?;
    validate_manifest(manifest)?;
    let mut encoder = DigestEncoder::new("neoth/gui-chat/preflight/v1");
    encoder.field(request.request_id.0.as_bytes());
    encoder.field(surface_discriminant(request.origin_surface));
    if request.incognito {
        let key = incognito_message_key.filter(|key| !key.is_empty()).ok_or(
            GuiChatProtocolError::Invalid("incognito_message_key_missing"),
        )?;
        encoder.field(
            keyed_incognito_message_digest(key, &request.message)
                .0
                .as_bytes(),
        );
    } else {
        encoder.field(request.message.as_bytes());
    }
    encoder.option_field(request.model.as_deref());
    encoder.option_field(request.skill_id.as_deref());
    encoder.field(&[u8::from(request.incognito)]);
    encoder.field(&[u8::from(request.reasoning_display)]);
    encoder.field(request.session_id.as_bytes());
    encoder.field(request.expected_boot_id.as_bytes());
    encoder.field(&accepted_config_generation.to_be_bytes());
    for entry in manifest {
        encoder.field(&entry.ordinal.to_be_bytes());
        encoder.field(entry.content_digest.0.as_bytes());
        encoder.field(&entry.byte_len.to_be_bytes());
        encoder.field(entry.media_kind.as_bytes());
    }
    Ok(encoder.finish())
}

fn keyed_incognito_message_digest(key: &[u8], message: &str) -> GuiChatDigest {
    let mut encoder = DigestEncoder::new("neoth/gui-chat/incognito-message/v1");
    encoder.field(key);
    encoder.field(message.as_bytes());
    encoder.finish()
}

pub(crate) fn ticket_binding_digest(
    preflight_digest: &GuiChatDigest,
    ordinal: u16,
    content_digest: &GuiChatDigest,
    ticket_nonce_digest: &GuiChatDigest,
) -> GuiChatResult<GuiChatDigest> {
    validate_digest(preflight_digest)?;
    validate_digest(content_digest)?;
    validate_digest(ticket_nonce_digest)?;
    let mut encoder = DigestEncoder::new("neoth/gui-chat/ticket-binding/v1");
    encoder.field(preflight_digest.0.as_bytes());
    encoder.field(&ordinal.to_be_bytes());
    encoder.field(content_digest.0.as_bytes());
    encoder.field(ticket_nonce_digest.0.as_bytes());
    Ok(encoder.finish())
}

pub(crate) fn turn_intent_digest(
    preflight_digest: &GuiChatDigest,
    bindings: &[GuiChatStagedAttachmentBinding],
) -> GuiChatResult<GuiChatDigest> {
    validate_digest(preflight_digest)?;
    if bindings.len() > GUI_CHAT_ATTACHMENT_MAX_COUNT {
        return Err(GuiChatProtocolError::Invalid(
            "too_many_attachment_bindings",
        ));
    }
    let mut encoder = DigestEncoder::new("neoth/gui-chat/turn-intent/v1");
    encoder.field(preflight_digest.0.as_bytes());
    for (expected, binding) in bindings.iter().enumerate() {
        if binding.ordinal != expected as u16 {
            return Err(GuiChatProtocolError::Invalid("attachment_binding_order"));
        }
        validate_digest(&binding.content_digest)?;
        validate_digest(&binding.ticket_binding_digest)?;
        encoder.field(&binding.ordinal.to_be_bytes());
        encoder.field(binding.content_digest.0.as_bytes());
        encoder.field(binding.ticket_binding_digest.0.as_bytes());
    }
    Ok(encoder.finish())
}

pub(crate) fn validate_preflight_request(request: &GuiChatPreflightRequest) -> GuiChatResult<()> {
    validate_schema(request.schema_version)?;
    validate_nonempty(
        "expected_boot_id",
        &request.expected_boot_id,
        GUI_CHAT_BOOT_ID_MAX_BYTES,
    )?;
    validate_request_id(request.request_id)?;
    validate_nonempty(
        "session_id",
        &request.session_id,
        GUI_CHAT_SESSION_ID_MAX_BYTES,
    )?;
    validate_nonempty("message", &request.message, GUI_CHAT_MESSAGE_MAX_BYTES)?;
    validate_optional("model", request.model.as_deref(), GUI_CHAT_MODEL_MAX_BYTES)?;
    validate_optional(
        "skill_id",
        request.skill_id.as_deref(),
        GUI_CHAT_SKILL_MAX_BYTES,
    )?;
    if request.attachments.len() > GUI_CHAT_ATTACHMENT_MAX_COUNT {
        return Err(GuiChatProtocolError::Invalid(
            "too_many_attachment_candidates",
        ));
    }
    for attachment in &request.attachments {
        validate_nonempty(
            "attachment_path",
            &attachment.path,
            GUI_CHAT_ATTACHMENT_PATH_MAX_BYTES,
        )?;
    }
    Ok(())
}

pub(crate) fn validate_stream_frame(frame: &GuiChatStreamFrame) -> GuiChatResult<()> {
    validate_schema(frame.schema_version)?;
    validate_nonempty("boot_id", &frame.boot_id, GUI_CHAT_BOOT_ID_MAX_BYTES)?;
    validate_turn_id(&frame.turn_id)?;
    validate_nonempty(
        "subscription_session",
        &frame.subscription.session_id,
        GUI_CHAT_SESSION_ID_MAX_BYTES,
    )?;
    validate_nonzero("subscription_generation", frame.subscription.generation)?;
    validate_nonzero("stream_sequence", frame.sequence)?;
    match &frame.payload {
        GuiChatFramePayload::Notice { code } => {
            validate_nonempty("notice_code", code, GUI_CHAT_NOTICE_MAX_BYTES)?;
        }
        GuiChatFramePayload::TurnSilenceTimeout {
            timeout_seconds,
            retryable,
        } => {
            if *timeout_seconds != crate::cli::chat_turn_watchdog::TURN_SILENCE_TIMEOUT.as_secs()
                || !retryable
            {
                return Err(GuiChatProtocolError::Invalid("turn_silence_timeout_fields"));
            }
        }
        GuiChatFramePayload::Delta { text } => {
            validate_nonempty("delta", text, GUI_CHAT_FRAME_MAX_BYTES)?;
        }
        GuiChatFramePayload::ReasoningDelta {
            reasoning_sequence,
            delta,
        } => {
            validate_nonzero("reasoning_sequence", u64::from(*reasoning_sequence))?;
            validate_nonempty("reasoning_delta", delta, GUI_CHAT_FRAME_MAX_BYTES)?;
        }
        GuiChatFramePayload::ReasoningState {
            reasoning_sequence,
            event_count,
            byte_count,
            ..
        } => {
            validate_nonzero("reasoning_sequence", u64::from(*reasoning_sequence))?;
            if *event_count > GUI_CHAT_REASONING_EVENT_MAX
                || *byte_count > GUI_CHAT_REASONING_BYTE_MAX
                || *byte_count > (GUI_CHAT_FRAME_MAX_BYTES as u64).saturating_mul(*event_count)
            {
                return Err(GuiChatProtocolError::Invalid("reasoning_counter_bounds"));
            }
        }
        GuiChatFramePayload::ReasoningCheckpoint {
            reasoning_sequence,
            event_count,
            byte_count,
        } => {
            validate_nonzero("reasoning_sequence", u64::from(*reasoning_sequence))?;
            if *event_count > GUI_CHAT_REASONING_EVENT_MAX
                || *byte_count > GUI_CHAT_REASONING_BYTE_MAX
                || *byte_count > (GUI_CHAT_FRAME_MAX_BYTES as u64).saturating_mul(*event_count)
            {
                return Err(GuiChatProtocolError::Invalid("reasoning_counter_bounds"));
            }
        }
        GuiChatFramePayload::RecallChipBatch { batch } => {
            validate_recall_chip_batch(batch)?;
        }
        GuiChatFramePayload::ThroughputState {
            throughput_sequence,
            state,
        } => {
            validate_nonzero("throughput_sequence", *throughput_sequence)?;
            validate_throughput_state(state)?;
        }
        GuiChatFramePayload::Terminal { terminal } => {
            validate_terminal(terminal)?;
        }
        GuiChatFramePayload::Accepted
        | GuiChatFramePayload::PhaseChanged { .. }
        | GuiChatFramePayload::ProviderDone
        | GuiChatFramePayload::CancelRequested => {}
    }
    let encoded_len = serde_json::to_vec(frame)
        .map_err(|_| GuiChatProtocolError::Invalid("frame_encoding"))?
        .len();
    if encoded_len > GUI_CHAT_FRAME_MAX_BYTES {
        return Err(GuiChatProtocolError::Invalid("frame_too_large"));
    }
    Ok(())
}

fn validate_manifest(manifest: &[GuiChatAttachmentManifestEntry]) -> GuiChatResult<()> {
    if manifest.len() > GUI_CHAT_ATTACHMENT_MAX_COUNT {
        return Err(GuiChatProtocolError::Invalid("too_many_manifest_entries"));
    }
    for (expected, entry) in manifest.iter().enumerate() {
        if entry.ordinal != expected as u16 {
            return Err(GuiChatProtocolError::Invalid("manifest_order"));
        }
        validate_digest(&entry.content_digest)?;
        validate_nonempty(
            "media_kind",
            &entry.media_kind,
            GUI_CHAT_ATTACHMENT_MEDIA_KIND_MAX_BYTES,
        )?;
    }
    Ok(())
}

pub(crate) fn validate_recall_chip_batch(batch: &GuiChatRecallChipBatch) -> GuiChatResult<()> {
    if batch.rows.len() > crate::memory::recall_presentation::MAX_RECALL_CHIP_ROWS {
        return Err(GuiChatProtocolError::Invalid("recall_chip_rows"));
    }
    if batch.status != GuiChatRecallChipStatus::Ready && !batch.rows.is_empty() {
        return Err(GuiChatProtocolError::Invalid(
            "recall_chip_unavailable_rows",
        ));
    }
    for row in &batch.rows {
        if row.tier == GuiChatRecallChipTier::Unknown
            && row.source_state != GuiChatRecallChipSourceState::Untrusted
        {
            return Err(GuiChatProtocolError::Invalid("recall_chip_unknown_trust"));
        }
        match row.score {
            Some(score)
                if row.tier == GuiChatRecallChipTier::Warm
                    && row.source_state == GuiChatRecallChipSourceState::Available
                    && score.is_finite()
                    && (0.0..=1.0).contains(&score) => {}
            Some(_) => return Err(GuiChatProtocolError::Invalid("recall_chip_score")),
            None => {}
        }
        match (&row.citation, row.tier, row.source_state) {
            (None, _, _) => {}
            (
                Some(GuiChatRecallChipCitation::Event {
                    event_id,
                    event_type: _,
                }),
                GuiChatRecallChipTier::Hot
                | GuiChatRecallChipTier::Warm
                | GuiChatRecallChipTier::Cold,
                GuiChatRecallChipSourceState::Available,
            ) if *event_id > 0 => {}
            (
                Some(GuiChatRecallChipCitation::WarmSnapshot {
                    consolidated_id,
                    warm_kind: GuiChatRecallWarmKind::Retained,
                    original_event_id,
                }),
                GuiChatRecallChipTier::Warm,
                GuiChatRecallChipSourceState::Available,
            ) if *consolidated_id > 0 && original_event_id.is_none_or(|event_id| event_id > 0) => {}
            (
                Some(GuiChatRecallChipCitation::WarmSnapshot {
                    consolidated_id,
                    warm_kind: GuiChatRecallWarmKind::Summary,
                    original_event_id: None,
                }),
                GuiChatRecallChipTier::Warm,
                GuiChatRecallChipSourceState::Available,
            ) if *consolidated_id > 0 => {}
            (
                Some(GuiChatRecallChipCitation::GroundTruth { fact_id }),
                GuiChatRecallChipTier::Canonical,
                GuiChatRecallChipSourceState::Available,
            ) if *fact_id > 0 => {}
            _ => return Err(GuiChatProtocolError::Invalid("recall_chip_citation")),
        }
    }
    Ok(())
}

pub(crate) fn validate_throughput_state(state: &GuiChatThroughputState) -> GuiChatResult<()> {
    match state {
        GuiChatThroughputState::Measuring { per_second, .. }
            if per_second.is_finite()
                && (0.0..=crate::cli::chat::LIVE_THROUGHPUT_PROTOCOL_MAX_PER_SECOND)
                    .contains(per_second) =>
        {
            Ok(())
        }
        GuiChatThroughputState::Measuring { .. } => {
            Err(GuiChatProtocolError::Invalid("throughput_rate"))
        }
        GuiChatThroughputState::Paused { .. } | GuiChatThroughputState::Unavailable { .. } => {
            Ok(())
        }
    }
}

fn validate_terminal(terminal: &GuiChatTerminal) -> GuiChatResult<()> {
    validate_digest(&terminal.response_digest)?;
    validate_digest(&terminal.lifecycle_receipt_id)?;
    validate_nonempty("provider", &terminal.provider, GUI_CHAT_PROVIDER_MAX_BYTES)?;
    validate_nonempty("model", &terminal.model, GUI_CHAT_MODEL_MAX_BYTES)?;

    match (
        terminal.response_feedback_target.as_ref(),
        terminal.response_feedback_unavailable,
    ) {
        (Some(_), true) => Err(GuiChatProtocolError::Invalid(
            "response_feedback_target_unavailable_conflict",
        )),
        (Some(target), false) => {
            if terminal.state != GuiChatTerminalState::Complete {
                return Err(GuiChatProtocolError::Invalid(
                    "response_feedback_target_not_complete",
                ));
            }
            if target.response_id.len() != 32
                || !target
                    .response_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(GuiChatProtocolError::Invalid(
                    "response_feedback_response_id",
                ));
            }
            validate_nonempty(
                "response_feedback_session",
                &target.session_id,
                GUI_CHAT_SESSION_ID_MAX_BYTES,
            )?;
            Ok(())
        }
        (None, true) if terminal.state == GuiChatTerminalState::Complete => Ok(()),
        (None, true) => Err(GuiChatProtocolError::Invalid(
            "response_feedback_unavailable_not_complete",
        )),
        (None, false) => Ok(()),
    }
}

fn validate_schema(schema_version: u8) -> GuiChatResult<()> {
    if schema_version == GUI_CHAT_V1_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(GuiChatProtocolError::Invalid("unsupported_schema_version"))
    }
}

fn validate_optional(name: &'static str, value: Option<&str>, limit: usize) -> GuiChatResult<()> {
    if let Some(value) = value {
        validate_nonempty(name, value, limit)?;
    }
    Ok(())
}

fn validate_nonempty(name: &'static str, value: &str, limit: usize) -> GuiChatResult<()> {
    if value.is_empty() {
        return Err(GuiChatProtocolError::Invalid(match name {
            "message" => "message_empty",
            _ => "required_field_empty",
        }));
    }
    if value.len() > limit {
        return Err(GuiChatProtocolError::Invalid("field_too_large"));
    }
    Ok(())
}

fn validate_digest(digest: &GuiChatDigest) -> GuiChatResult<()> {
    if digest.0.len() == GUI_CHAT_RESPONSE_HASH_BYTES * 2
        && digest.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(GuiChatProtocolError::Invalid("invalid_digest"))
    }
}

struct DigestEncoder(Sha256);

impl DigestEncoder {
    fn new(domain: &str) -> Self {
        let mut encoder = Self(Sha256::new());
        encoder.field(domain.as_bytes());
        encoder
    }

    fn field(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
    }

    fn option_field(&mut self, value: Option<&str>) {
        match value {
            Some(value) => {
                self.field(&[1]);
                self.field(value.as_bytes());
            }
            None => self.field(&[0]),
        }
    }

    fn finish(self) -> GuiChatDigest {
        GuiChatDigest(hex::encode(self.0.finalize()))
    }
}

// Each audit-RPC handler calls the route-specific validator after sealed serde
// decoding and before runtime dispatch. Responses are validated before bridge
// presentation. Cursor upper bound is recovered from the authenticated attach
// capability record, never supplied by the GUI.
pub(crate) fn validate_decide_request(r: &GuiChatConsentDecisionRequest) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_capability(&r.preflight_id)?;
    validate_digest(&r.preflight_descriptor_digest)?;
    validate_capability(&r.consent_challenge)?;
    match (r.decision, r.consent_proof.as_ref()) {
        (GuiChatConsentDecision::Deny, None) => Ok(()),
        (GuiChatConsentDecision::Deny, Some(_)) => {
            Err(GuiChatProtocolError::Invalid("deny_must_not_supply_proof"))
        }
        (GuiChatConsentDecision::AllowOnce | GuiChatConsentDecision::AllowAlways, Some(proof)) => {
            validate_consent_proof(proof)
        }
        (GuiChatConsentDecision::AllowOnce | GuiChatConsentDecision::AllowAlways, None) => Err(
            GuiChatProtocolError::Invalid("allow_requires_verified_proof"),
        ),
    }
}
pub(crate) fn validate_decide_response(r: &GuiChatConsentDecisionResponse) -> GuiChatResult<()> {
    match r {
        GuiChatConsentDecisionResponse::Denied {
            schema_version,
            expected_boot_id,
        } => {
            validate_schema(*schema_version)?;
            validate_boot(expected_boot_id)
        }
        GuiChatConsentDecisionResponse::Approved {
            schema_version,
            expected_boot_id,
            turn_intent_digest,
            start_capability,
            attachment_tickets,
        } => {
            validate_schema(*schema_version)?;
            validate_boot(expected_boot_id)?;
            validate_digest(turn_intent_digest)?;
            validate_capability(start_capability)?;
            validate_tickets(attachment_tickets)
        }
    }
}
pub(crate) fn validate_start_request(r: &GuiChatStartRequest) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_request_id(r.request_id)?;
    validate_nonempty("session", &r.session_id, GUI_CHAT_SESSION_ID_MAX_BYTES)?;
    validate_digest(&r.turn_intent_digest)?;
    validate_capability(&r.start_capability)?;
    validate_tickets(&r.attachment_tickets)
}
pub(crate) fn validate_start_response(r: &GuiChatStartResponse) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_turn_id(&r.turn_id)?;
    validate_digest(&r.turn_intent_digest)?;
    validate_capability(&r.origin_attach_capability)?;
    validate_capability(&r.cancel_capability)?;
    validate_same_session_grant(&r.same_session_attach_grant)
}
pub(crate) fn validate_attach_exchange_request(
    r: &GuiChatAttachExchangeRequest,
) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_turn_id(&r.turn_id)?;
    validate_nonempty("session", &r.session_id, GUI_CHAT_SESSION_ID_MAX_BYTES)?;
    validate_capability(&r.grant)
}
pub(crate) fn validate_attach_exchange_response(
    r: &GuiChatAttachExchangeResponse,
) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_turn_id(&r.turn_id)?;
    validate_nonempty("session", &r.session_id, GUI_CHAT_SESSION_ID_MAX_BYTES)?;
    validate_nonzero("subscription_generation", r.subscription_generation)?;
    validate_capability(&r.attach_capability)
}
pub(crate) fn validate_attach_request(
    r: &GuiChatAttachRequest,
    cursor_upper_bound: u64,
) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_turn_id(&r.turn_id)?;
    validate_nonempty("session", &r.session_id, GUI_CHAT_SESSION_ID_MAX_BYTES)?;
    validate_nonzero("subscription_generation", r.subscription_generation)?;
    validate_capability(&r.attach_capability)?;
    if r.after_sequence > cursor_upper_bound {
        return Err(GuiChatProtocolError::Invalid("attach_cursor_ahead"));
    }
    Ok(())
}
pub(crate) fn validate_cancel_request(r: &GuiChatCancelRequest) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_turn_id(&r.turn_id)?;
    validate_nonempty("session", &r.session_id, GUI_CHAT_SESSION_ID_MAX_BYTES)?;
    validate_capability(&r.cancel_capability)
}
pub(crate) fn validate_cancel_response(r: &GuiChatCancelResponse) -> GuiChatResult<()> {
    validate_schema(r.schema_version)
}
pub(crate) fn validate_status_request(r: &GuiChatStatusRequest) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_turn_id(&r.turn_id)?;
    validate_nonempty("session", &r.session_id, GUI_CHAT_SESSION_ID_MAX_BYTES)?;
    validate_capability(&r.attach_capability)
}
pub(crate) fn validate_status_response(r: &GuiChatStatusResponse) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_turn_id(&r.turn_id)?;
    if let Some(terminal) = &r.terminal {
        if r.latest_sequence == 0 {
            return Err(GuiChatProtocolError::Invalid("terminal_without_sequence"));
        }
        validate_terminal(terminal)?;
    }
    Ok(())
}
pub(crate) fn validate_active_request(r: &GuiChatActiveRequest) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_nonempty("session", &r.session_id, GUI_CHAT_SESSION_ID_MAX_BYTES)?;
    validate_capability(&r.same_session_attach_grant)
}
pub(crate) fn validate_active_response(r: &GuiChatActiveResponse) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    if let Some(turn) = &r.active_turn {
        validate_turn_id(&turn.turn_id)?;
    }
    Ok(())
}
pub(crate) fn validate_preflight_response(r: &GuiChatPreflightResponse) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_boot(&r.expected_boot_id)?;
    validate_capability(&r.preflight_id)?;
    validate_digest(&r.preflight_descriptor_digest)?;
    validate_capability(&r.consent_challenge)?;
    validate_manifest(&r.attachment_manifest)?;
    validate_consent_preflight_state(&r.consent)
}
#[allow(dead_code)] // Production wire validator; non-200 responses are currently mapped to GuiChatClientError.
pub(crate) fn validate_error_response(r: &GuiChatErrorResponse) -> GuiChatResult<()> {
    validate_schema(r.schema_version)?;
    validate_nonempty("detail", &r.detail, GUI_CHAT_NOTICE_MAX_BYTES)
}

fn validate_consent_preflight_state(state: &GuiChatConsentPreflightState) -> GuiChatResult<()> {
    match state {
        GuiChatConsentPreflightState::Ready => Ok(()),
        GuiChatConsentPreflightState::ConfirmationRequired { prompt } => {
            validate_request_id(prompt.request_id)?;
            if prompt.expires_at_unix_ms == 0 {
                return Err(GuiChatProtocolError::Invalid("consent_prompt_expiry_zero"));
            }
            validate_consent_routes(&prompt.routes)
        }
    }
}

fn validate_consent_routes(routes: &[GuiChatConsentRouteWire]) -> GuiChatResult<()> {
    if routes.is_empty() || routes.len() > GUI_CHAT_CONSENT_ROUTE_MAX_COUNT {
        return Err(GuiChatProtocolError::Invalid("consent_route_count"));
    }
    for (index, route) in routes.iter().enumerate() {
        validate_nonempty(
            "consent_provider",
            &route.provider,
            GUI_CHAT_CONSENT_ROUTE_PROVIDER_MAX_BYTES,
        )?;
        if let Some(origin) = &route.endpoint_origin {
            validate_canonical_endpoint_origin(origin)?;
        }
        if routes[..index].iter().any(|prior| {
            prior.provider == route.provider && prior.endpoint_origin == route.endpoint_origin
        }) {
            return Err(GuiChatProtocolError::Invalid("duplicate_consent_route"));
        }
    }
    Ok(())
}

fn validate_canonical_endpoint_origin(origin: &str) -> GuiChatResult<()> {
    validate_nonempty(
        "consent_endpoint_origin",
        origin,
        GUI_CHAT_CONSENT_ROUTE_ORIGIN_MAX_BYTES,
    )?;
    let parsed = url::Url::parse(origin)
        .map_err(|_| GuiChatProtocolError::Invalid("consent_endpoint_origin"))?;
    if parsed.origin().ascii_serialization() != origin
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(GuiChatProtocolError::Invalid("consent_endpoint_origin"));
    }
    Ok(())
}
fn validate_boot(v: &str) -> GuiChatResult<()> {
    validate_nonempty("boot", v, GUI_CHAT_BOOT_ID_MAX_BYTES)
}
fn validate_request_id(id: GuiChatRequestId) -> GuiChatResult<()> {
    if id.0.get_version_num() == 7 {
        Ok(())
    } else {
        Err(GuiChatProtocolError::Invalid("request_id_not_v7"))
    }
}
fn validate_turn_id(id: &GuiChatTurnId) -> GuiChatResult<()> {
    if id.0.get_version_num() == 7 {
        Ok(())
    } else {
        Err(GuiChatProtocolError::Invalid("turn_id_not_v7"))
    }
}
fn validate_nonzero(name: &'static str, value: u64) -> GuiChatResult<()> {
    if value == 0 {
        Err(GuiChatProtocolError::Invalid(
            if name == "subscription_generation" {
                "subscription_generation_zero"
            } else {
                "sequence_zero"
            },
        ))
    } else {
        Ok(())
    }
}
fn validate_capability(value: &GuiChatOpaqueCapability) -> GuiChatResult<()> {
    validate_opaque("capability", &value.0, GUI_CHAT_OPAQUE_CAPABILITY_MAX_BYTES)
}
fn validate_consent_proof(value: &GuiChatConsentProof) -> GuiChatResult<()> {
    validate_nonempty(
        "consent_proof",
        &value.0,
        GUI_CHAT_OPAQUE_CAPABILITY_MAX_BYTES,
    )?;
    // Request-bound proofs are minted by consent_challenge as
    // `<canonical-lowercase-uuid>.<64-lowercase-hex-secret>`. They are not
    // GUI capabilities, so do not relax the strict opaque-capability grammar.
    let (token_id, secret) = value
        .0
        .split_once('.')
        .ok_or(GuiChatProtocolError::Invalid("consent_proof_shape"))?;
    let parsed = Uuid::parse_str(token_id)
        .map_err(|_| GuiChatProtocolError::Invalid("consent_proof_shape"))?;
    if parsed.to_string() != token_id
        || secret.len() != 64
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GuiChatProtocolError::Invalid("consent_proof_shape"));
    }
    Ok(())
}
fn validate_opaque(name: &'static str, value: &str, limit: usize) -> GuiChatResult<()> {
    validate_nonempty(name, value, limit)?;
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(())
    } else {
        Err(GuiChatProtocolError::Invalid("opaque_token_shape"))
    }
}
fn validate_tickets(tickets: &[GuiChatAttachmentTicket]) -> GuiChatResult<()> {
    if tickets.len() > GUI_CHAT_ATTACHMENT_MAX_COUNT {
        return Err(GuiChatProtocolError::Invalid("too_many_tickets"));
    }
    for (index, ticket) in tickets.iter().enumerate() {
        if ticket.ordinal != index as u16 {
            return Err(GuiChatProtocolError::Invalid("ticket_order_or_duplicate"));
        }
        validate_capability(&ticket.ticket)?;
    }
    Ok(())
}
fn validate_same_session_grant(grant: &GuiChatSameSessionAttachGrant) -> GuiChatResult<()> {
    validate_capability(&grant.grant)?;
    validate_turn_id(&grant.turn_id)?;
    validate_nonempty("session", &grant.session_id, GUI_CHAT_SESSION_ID_MAX_BYTES)?;
    if grant.allowed_surfaces.is_empty()
        || grant.allowed_surfaces.len() > 2
        || grant
            .allowed_surfaces
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err(GuiChatProtocolError::Invalid("allowed_surface_set"));
    }
    Ok(())
}
fn surface_discriminant(surface: GuiChatSurface) -> &'static [u8] {
    match surface {
        GuiChatSurface::Main => b"main",
        GuiChatSurface::Buddy => b"buddy",
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> GuiChatDigest {
        GuiChatDigest(std::iter::repeat_n(byte, 64).collect())
    }

    fn preflight() -> GuiChatPreflightRequest {
        GuiChatPreflightRequest {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: "boot-a".into(),
            request_id: GuiChatRequestId(Uuid::now_v7()),
            session_id: "session-a".into(),
            origin_surface: GuiChatSurface::Main,
            message: "hello".into(),
            model: Some("model-a".into()),
            skill_id: None,
            incognito: false,
            reasoning_display: false,
            attachments: vec![GuiChatAttachmentCandidate {
                path: "C:/safe/input.txt".into(),
            }],
        }
    }

    fn manifest() -> Vec<GuiChatAttachmentManifestEntry> {
        vec![GuiChatAttachmentManifestEntry {
            ordinal: 0,
            content_digest: digest('a'),
            byte_len: 3,
            media_kind: "text/plain".into(),
        }]
    }

    fn write_consent_fixture_config(home: &std::path::Path) {
        let mut config = crate::config::FreedomConfig {
            provider_kind: Some(crate::cli::init::ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_model: Some("consent-proof-fixture".into()),
            autonomy: crate::permissions::AutonomyLevel::Full,
            review_gate_enabled: false,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            ..Default::default()
        };
        config.council.disabled = Some(true);
        config.memory.recall_shortcut = false;
        std::fs::write(
            home.join("freedom.yaml"),
            serde_yaml::to_string(&config).expect("serialize consent fixture config"),
        )
        .expect("write consent fixture config");
    }

    #[tokio::test]
    async fn request_bound_consent_proofs_accept_real_ready_and_interactive_mints() {
        let descriptor_digest = "a".repeat(64);

        let ready_home = tempfile::tempdir().expect("ready fixture home");
        write_consent_fixture_config(ready_home.path());
        crate::consent::prepare_grant_routes(
            ready_home.path(),
            &[crate::consent::ConsentRoute::new(
                crate::cli::init::ProviderKind::ClaudeCli,
                None,
            )],
        )
        .expect("prepare ready consent")
        .commit()
        .expect("commit ready consent");
        let ready_proof =
            crate::cli::consent_challenge::mint_ready_request_bound_gui_chat_consent(
                ready_home.path(),
                &descriptor_digest,
                "ready-daemon-challenge",
                "ready-session",
                crate::time::now_unix_secs(),
            )
            .expect("mint ready request-bound proof");
        validate_consent_proof(&GuiChatConsentProof(ready_proof.to_string()))
            .expect("ready producer proof matches the wire grammar");

        let interactive_home = tempfile::tempdir().expect("interactive fixture home");
        write_consent_fixture_config(interactive_home.path());
        let challenge = match crate::cli::consent_challenge::create_core_gui_chat_consent_preflight(
            interactive_home.path(),
            crate::time::now_unix_secs(),
        )
        .expect("create interactive consent preflight")
        {
            crate::cli::consent_challenge::CoreGuiChatConsentPreflight::ConfirmationRequired {
                challenge_token,
                ..
            } => challenge_token,
            crate::cli::consent_challenge::CoreGuiChatConsentPreflight::Ready => {
                panic!("ungranted fixture unexpectedly ready")
            }
        };
        let interactive_proof =
            crate::cli::consent_challenge::decide_request_bound_gui_chat_consent(
                interactive_home.path(),
                challenge.as_str(),
                &descriptor_digest,
                "interactive-session",
                crate::cli::consent_challenge::ChatConsentDecision::AllowOnce,
            )
            .await
            .expect("decide interactive request-bound consent")
            .expect("allow-once produces a request-bound proof");
        validate_consent_proof(&GuiChatConsentProof(interactive_proof.to_string()))
            .expect("interactive producer proof matches the wire grammar");
    }

    #[test]
    fn request_bound_consent_proof_rejects_noncanonical_and_oversized_shapes() {
        let canonical =
            "018f1234-5678-7abc-8def-0123456789ab.".to_owned() + &"a".repeat(64);
        validate_consent_proof(&GuiChatConsentProof(canonical.clone()))
            .expect("canonical request-bound proof");

        for malformed in [
            canonical.to_uppercase(),
            canonical.replacen('.', "", 1),
            format!("{canonical}.extra"),
            format!("{}g", &canonical[..canonical.len() - 1]),
            canonical[..canonical.len() - 1].to_owned(),
            "x".repeat(GUI_CHAT_OPAQUE_CAPABILITY_MAX_BYTES + 1),
        ] {
            assert!(validate_consent_proof(&GuiChatConsentProof(malformed)).is_err());
        }

        let deny_with_proof = GuiChatConsentDecisionRequest {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: "boot-a".into(),
            preflight_id: GuiChatOpaqueCapability("preflight-capability".into()),
            preflight_descriptor_digest: digest('a'),
            consent_challenge: GuiChatOpaqueCapability("challenge-capability".into()),
            decision: GuiChatConsentDecision::Deny,
            consent_proof: Some(GuiChatConsentProof(canonical)),
        };
        assert!(matches!(
            validate_decide_request(&deny_with_proof),
            Err(GuiChatProtocolError::Invalid("deny_must_not_supply_proof"))
        ));
    }

    #[test]
    fn sealed_requests_and_frames_reject_unknown_fields() {
        assert!(serde_json::from_str::<GuiChatPreflightRequest>(
            r#"{"schema_version":1,"expected_boot_id":"boot","request_id":"00000000-0000-0000-0000-000000000000","session_id":"s","origin_surface":"main","message":"m","model":null,"skill_id":null,"incognito":false,"attachments":[],"extra":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<GuiChatStreamFrame>(
            r#"{"schema_version":1,"boot_id":"boot","turn_id":"00000000-0000-0000-0000-000000000000","subscription":{"session_id":"s","surface":"main","generation":1},"sequence":1,"type":"accepted","extra":true}"#
        )
        .is_err());
    }

    #[test]
    fn request_and_frame_caps_are_enforced() {
        let mut request = preflight();
        request.message = "x".repeat(GUI_CHAT_MESSAGE_MAX_BYTES + 1);
        assert!(matches!(
            validate_preflight_request(&request),
            Err(GuiChatProtocolError::Invalid("field_too_large"))
        ));

        let frame = GuiChatStreamFrame {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            boot_id: "boot-a".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            subscription: GuiChatSubscription {
                session_id: "session-a".into(),
                surface: GuiChatSurface::Main,
                generation: 1,
            },
            sequence: 1,
            payload: GuiChatFramePayload::Delta {
                text: "x".repeat(GUI_CHAT_FRAME_MAX_BYTES),
            },
        };
        assert!(matches!(
            validate_stream_frame(&frame),
            Err(GuiChatProtocolError::Invalid("frame_too_large"))
        ));
    }

    #[test]
    fn digest_stages_are_non_circular_and_path_free() {
        let request = preflight();
        let manifest = manifest();
        let preflight_digest =
            preflight_descriptor_digest(&request, &manifest, 7, Some(b"per-boot-key")).unwrap();
        let ticket_binding = ticket_binding_digest(
            &preflight_digest,
            0,
            &manifest[0].content_digest,
            &digest('b'),
        )
        .unwrap();
        let turn_digest = turn_intent_digest(
            &preflight_digest,
            &[GuiChatStagedAttachmentBinding {
                ordinal: 0,
                content_digest: manifest[0].content_digest.clone(),
                ticket_binding_digest: ticket_binding,
            }],
        )
        .unwrap();

        assert_ne!(preflight_digest, turn_digest);
        assert_ne!(turn_digest.0, request.attachments[0].path);
        assert_ne!(preflight_digest.0, request.attachments[0].path);
    }

    #[test]
    fn lifecycle_and_terminal_are_content_free_by_shape() {
        let terminal = GuiChatTerminal {
            state: GuiChatTerminalState::Complete,
            response_digest: digest('c'),
            provider: "provider".into(),
            model: "model".into(),
            usage: GuiChatUsage {
                input_tokens: 1,
                output_tokens: 2,
                elapsed_ms: 3,
            },
            lifecycle_receipt_id: digest('d'),
            response_feedback_target: None,
            response_feedback_unavailable: false,
        };
        let lifecycle = serde_json::to_string(&GuiChatFramePayload::Terminal { terminal }).unwrap();
        assert!(!lifecycle.contains("response_text"));
        assert!(!lifecycle.contains("prompt"));
        assert!(!lifecycle.contains("Delta"));

        let delta = serde_json::to_string(&GuiChatFramePayload::Delta {
            text: "visible response".into(),
        })
        .unwrap();
        assert!(delta.contains("visible response"));
    }

    #[test]
    fn ingress_rejects_ids_caps_tickets_generations_and_cursor() {
        let mut request = preflight();
        request.request_id = GuiChatRequestId(Uuid::nil());
        assert!(validate_preflight_request(&request).is_err());
        let attach = GuiChatAttachRequest {
            schema_version: 1,
            expected_boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::nil()),
            session_id: "session".into(),
            surface: GuiChatSurface::Main,
            subscription_generation: 0,
            attach_capability: GuiChatOpaqueCapability("good_token".into()),
            after_sequence: 2,
        };
        assert!(validate_attach_request(&attach, 1).is_err());
        assert!(validate_capability(&GuiChatOpaqueCapability(String::new())).is_err());
        assert!(
            validate_consent_proof(&GuiChatConsentProof(
                "x".repeat(GUI_CHAT_OPAQUE_CAPABILITY_MAX_BYTES + 1)
            ))
            .is_err()
        );
        let tickets = vec![
            GuiChatAttachmentTicket {
                ordinal: 1,
                ticket: GuiChatOpaqueCapability("one".into()),
            },
            GuiChatAttachmentTicket {
                ordinal: 1,
                ticket: GuiChatOpaqueCapability("two".into()),
            },
        ];
        assert!(validate_tickets(&tickets).is_err());
    }

    #[test]
    fn request_and_origin_surface_change_digest_but_subscriber_does_not() {
        let request = preflight();
        let entries = manifest();
        let first = preflight_descriptor_digest(&request, &entries, 7, Some(b"key-one")).unwrap();
        let mut changed_id = request.clone();
        changed_id.request_id = GuiChatRequestId(Uuid::now_v7());
        let mut changed_surface = request.clone();
        changed_surface.origin_surface = GuiChatSurface::Buddy;
        assert_ne!(
            first,
            preflight_descriptor_digest(&changed_id, &entries, 7, Some(b"key-one")).unwrap()
        );
        assert_ne!(
            first,
            preflight_descriptor_digest(&changed_surface, &entries, 7, Some(b"key-one")).unwrap()
        );
        let binding =
            ticket_binding_digest(&first, 0, &entries[0].content_digest, &digest('b')).unwrap();
        let final_one = turn_intent_digest(
            &first,
            &[GuiChatStagedAttachmentBinding {
                ordinal: 0,
                content_digest: entries[0].content_digest.clone(),
                ticket_binding_digest: binding.clone(),
            }],
        )
        .unwrap();
        let final_two = turn_intent_digest(
            &first,
            &[GuiChatStagedAttachmentBinding {
                ordinal: 0,
                content_digest: entries[0].content_digest.clone(),
                ticket_binding_digest: binding,
            }],
        )
        .unwrap();
        let main_attach = GuiChatAttachExchangeRequest {
            schema_version: 1,
            expected_boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            session_id: "session".into(),
            desired_surface: GuiChatSurface::Main,
            grant: GuiChatOpaqueCapability("grant".into()),
        };
        let buddy_attach = GuiChatAttachExchangeRequest {
            desired_surface: GuiChatSurface::Buddy,
            ..main_attach.clone()
        };
        validate_attach_exchange_request(&main_attach).unwrap();
        validate_attach_exchange_request(&buddy_attach).unwrap();
        assert_ne!(main_attach.desired_surface, buddy_attach.desired_surface);
        assert_eq!(final_one, final_two);
    }

    #[test]
    fn incognito_key_is_required_and_never_serialized_or_debugged() {
        let mut request = preflight();
        request.incognito = true;
        assert!(preflight_descriptor_digest(&request, &[], 7, None).is_err());
        let one = preflight_descriptor_digest(&request, &[], 7, Some(b"private-key-one")).unwrap();
        let two = preflight_descriptor_digest(&request, &[], 7, Some(b"private-key-two")).unwrap();
        assert_ne!(one, two);
        assert!(
            !serde_json::to_string(&request)
                .unwrap()
                .contains("incognito_message_key")
        );
        assert!(!format!("{one:?}").contains("private-key-one"));
    }

    #[test]
    fn actual_lifecycle_and_delta_frames_validate_as_envelopes() {
        let terminal = GuiChatTerminal {
            state: GuiChatTerminalState::Complete,
            response_digest: digest('c'),
            provider: "provider".into(),
            model: "model".into(),
            usage: GuiChatUsage {
                input_tokens: 1,
                output_tokens: 2,
                elapsed_ms: 3,
            },
            lifecycle_receipt_id: digest('d'),
            response_feedback_target: None,
            response_feedback_unavailable: false,
        };
        let lifecycle = GuiChatStreamFrame {
            schema_version: 1,
            boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            subscription: GuiChatSubscription {
                session_id: "session".into(),
                surface: GuiChatSurface::Main,
                generation: 1,
            },
            sequence: 1,
            payload: GuiChatFramePayload::Terminal { terminal },
        };
        validate_stream_frame(&lifecycle).unwrap();
        assert!(
            !serde_json::to_string(&lifecycle)
                .unwrap()
                .contains("response_text")
        );
        let delta = GuiChatStreamFrame {
            payload: GuiChatFramePayload::Delta {
                text: "visible".into(),
            },
            sequence: 2,
            ..lifecycle
        };
        validate_stream_frame(&delta).unwrap();
    }

    #[test]
    fn recall_chip_batch_is_typed_bounded_and_content_free() {
        let row = GuiChatRecallChipRow {
            tier: GuiChatRecallChipTier::Warm,
            score: Some(0.42),
            source_state: GuiChatRecallChipSourceState::Available,
            citation: None,
        };
        let frame = |batch| GuiChatStreamFrame {
            schema_version: 1,
            boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            subscription: GuiChatSubscription {
                session_id: "gui-subscription".into(),
                surface: GuiChatSurface::Main,
                generation: 1,
            },
            sequence: 1,
            payload: GuiChatFramePayload::RecallChipBatch { batch },
        };
        let valid = frame(GuiChatRecallChipBatch {
            status: GuiChatRecallChipStatus::Ready,
            rows: vec![row.clone()],
        });
        validate_stream_frame(&valid).unwrap();
        let encoded = serde_json::to_string(&valid).unwrap();
        for forbidden in ["recall_text", "source_id", "request_id", "control_token"] {
            assert!(
                !encoded.contains(forbidden),
                "recall-chip GUI frame must not expose {forbidden}"
            );
        }

        let unavailable_with_row = frame(GuiChatRecallChipBatch {
            status: GuiChatRecallChipStatus::Incognito,
            rows: vec![row.clone()],
        });
        assert!(matches!(
            validate_stream_frame(&unavailable_with_row),
            Err(GuiChatProtocolError::Invalid(
                "recall_chip_unavailable_rows"
            ))
        ));

        let too_many = frame(GuiChatRecallChipBatch {
            status: GuiChatRecallChipStatus::Ready,
            rows: vec![row.clone(); crate::memory::recall_presentation::MAX_RECALL_CHIP_ROWS + 1],
        });
        assert!(matches!(
            validate_stream_frame(&too_many),
            Err(GuiChatProtocolError::Invalid("recall_chip_rows"))
        ));

        let untrusted_unknown = frame(GuiChatRecallChipBatch {
            status: GuiChatRecallChipStatus::Ready,
            rows: vec![GuiChatRecallChipRow {
                tier: GuiChatRecallChipTier::Unknown,
                score: None,
                source_state: GuiChatRecallChipSourceState::Available,
                citation: None,
            }],
        });
        assert!(matches!(
            validate_stream_frame(&untrusted_unknown),
            Err(GuiChatProtocolError::Invalid("recall_chip_unknown_trust"))
        ));

        let invalid_score = frame(GuiChatRecallChipBatch {
            status: GuiChatRecallChipStatus::Ready,
            rows: vec![GuiChatRecallChipRow {
                tier: GuiChatRecallChipTier::Hot,
                score: Some(0.42),
                source_state: GuiChatRecallChipSourceState::Available,
                citation: None,
            }],
        });
        assert!(matches!(
            validate_stream_frame(&invalid_score),
            Err(GuiChatProtocolError::Invalid("recall_chip_score"))
        ));
    }

    #[test]
    fn recall_chip_citation_requires_exact_available_tier_and_positive_binding() {
        let frame = |row| GuiChatStreamFrame {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            subscription: GuiChatSubscription {
                session_id: "gui-subscription".into(),
                surface: GuiChatSurface::Main,
                generation: 1,
            },
            sequence: 1,
            payload: GuiChatFramePayload::RecallChipBatch {
                batch: GuiChatRecallChipBatch {
                    status: GuiChatRecallChipStatus::Ready,
                    rows: vec![row],
                },
            },
        };
        let summary = GuiChatRecallChipRow {
            tier: GuiChatRecallChipTier::Warm,
            score: Some(0.42),
            source_state: GuiChatRecallChipSourceState::Available,
            citation: Some(GuiChatRecallChipCitation::WarmSnapshot {
                consolidated_id: 12,
                warm_kind: GuiChatRecallWarmKind::Summary,
                original_event_id: None,
            }),
        };
        validate_stream_frame(&frame(summary)).unwrap();

        let forged = GuiChatRecallChipRow {
            tier: GuiChatRecallChipTier::Warm,
            score: None,
            source_state: GuiChatRecallChipSourceState::Untrusted,
            citation: Some(GuiChatRecallChipCitation::Event {
                event_id: 1,
                event_type: 7,
            }),
        };
        assert!(matches!(
            validate_stream_frame(&frame(forged)),
            Err(GuiChatProtocolError::Invalid("recall_chip_citation"))
        ));

        let sentinel = GuiChatRecallChipRow {
            tier: GuiChatRecallChipTier::Warm,
            score: None,
            source_state: GuiChatRecallChipSourceState::Available,
            citation: Some(GuiChatRecallChipCitation::Event {
                event_id: -12,
                event_type: 7,
            }),
        };
        assert!(matches!(
            validate_stream_frame(&frame(sentinel)),
            Err(GuiChatProtocolError::Invalid("recall_chip_citation"))
        ));

        let legacy = GuiChatRecallChipRow {
            tier: GuiChatRecallChipTier::Warm,
            score: Some(0.42),
            source_state: GuiChatRecallChipSourceState::Available,
            citation: None,
        };
        validate_stream_frame(&frame(legacy)).unwrap();

        let legacy_wire: GuiChatRecallChipRow =
            serde_json::from_str(r#"{"tier":"warm","score":0.42,"source_state":"available"}"#)
                .unwrap();
        assert_eq!(legacy_wire.citation, None);
        assert!(serde_json::from_str::<GuiChatRecallChipRow>(
            r#"{"tier":"warm","score":0.42,"source_state":"available","citation":{"kind":"event","event_id":1,"event_type":7,"extra":true}}"#,
        )
        .is_err());
    }

    #[test]
    fn throughput_state_is_typed_bounded_and_content_free() {
        let frame = |throughput_sequence, state| GuiChatStreamFrame {
            schema_version: 1,
            boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            subscription: GuiChatSubscription {
                session_id: "gui-subscription".into(),
                surface: GuiChatSurface::Main,
                generation: 1,
            },
            sequence: 1,
            payload: GuiChatFramePayload::ThroughputState {
                throughput_sequence,
                state,
            },
        };
        let valid = frame(
            7,
            GuiChatThroughputState::Measuring {
                basis: GuiChatThroughputBasis::VisibleEvent,
                per_second: 42.0,
            },
        );
        validate_stream_frame(&valid).unwrap();
        let encoded = serde_json::to_string(&valid).unwrap();
        for forbidden in ["control_token", "provider_text", "usage_total", "prompt"] {
            assert!(
                !encoded.contains(forbidden),
                "throughput GUI frame must not expose {forbidden}"
            );
        }
        assert!(matches!(
            validate_stream_frame(&frame(
                0,
                GuiChatThroughputState::Unavailable {
                    reason: GuiChatThroughputUnavailable::NoVisibleEvents,
                },
            )),
            Err(GuiChatProtocolError::Invalid("sequence_zero"))
        ));
        assert!(matches!(
            validate_stream_frame(&frame(
                1,
                GuiChatThroughputState::Measuring {
                    basis: GuiChatThroughputBasis::VisibleEvent,
                    per_second: f64::INFINITY,
                },
            )),
            Err(GuiChatProtocolError::Invalid("throughput_rate"))
        ));
    }

    #[test]
    fn terminal_response_feedback_target_is_strict_and_complete_only() {
        let valid_target = GuiChatResponseFeedbackTarget {
            response_id: "a".repeat(32),
            session_id: "core-session".into(),
            revision: 7,
        };
        let terminal = GuiChatTerminal {
            state: GuiChatTerminalState::Complete,
            response_digest: digest('c'),
            provider: "provider".into(),
            model: "model".into(),
            usage: GuiChatUsage {
                input_tokens: 1,
                output_tokens: 2,
                elapsed_ms: 3,
            },
            lifecycle_receipt_id: digest('d'),
            response_feedback_target: Some(valid_target.clone()),
            response_feedback_unavailable: false,
        };
        let frame = |terminal| GuiChatStreamFrame {
            schema_version: 1,
            boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            subscription: GuiChatSubscription {
                session_id: "session".into(),
                surface: GuiChatSurface::Main,
                generation: 1,
            },
            sequence: 1,
            payload: GuiChatFramePayload::Terminal { terminal },
        };

        validate_stream_frame(&frame(terminal.clone())).unwrap();

        let mut malformed_response_id = terminal.clone();
        malformed_response_id
            .response_feedback_target
            .as_mut()
            .expect("target")
            .response_id = "g".repeat(32);
        assert!(matches!(
            validate_stream_frame(&frame(malformed_response_id)),
            Err(GuiChatProtocolError::Invalid(
                "response_feedback_response_id"
            ))
        ));

        let mut empty_session = terminal.clone();
        empty_session
            .response_feedback_target
            .as_mut()
            .expect("target")
            .session_id = String::new();
        assert!(matches!(
            validate_stream_frame(&frame(empty_session)),
            Err(GuiChatProtocolError::Invalid("required_field_empty"))
        ));

        let mut oversized_session = terminal.clone();
        oversized_session
            .response_feedback_target
            .as_mut()
            .expect("target")
            .session_id = "s".repeat(GUI_CHAT_SESSION_ID_MAX_BYTES + 1);
        assert!(matches!(
            validate_stream_frame(&frame(oversized_session)),
            Err(GuiChatProtocolError::Invalid("field_too_large"))
        ));

        let mut conflicting_target = terminal.clone();
        conflicting_target.response_feedback_unavailable = true;
        assert!(matches!(
            validate_stream_frame(&frame(conflicting_target)),
            Err(GuiChatProtocolError::Invalid(
                "response_feedback_target_unavailable_conflict"
            ))
        ));

        let mut target_on_failed_terminal = terminal.clone();
        target_on_failed_terminal.state = GuiChatTerminalState::Failed;
        assert!(matches!(
            validate_stream_frame(&frame(target_on_failed_terminal)),
            Err(GuiChatProtocolError::Invalid(
                "response_feedback_target_not_complete"
            ))
        ));

        let mut unavailable_on_failed_terminal = terminal.clone();
        unavailable_on_failed_terminal.state = GuiChatTerminalState::Failed;
        unavailable_on_failed_terminal.response_feedback_target = None;
        unavailable_on_failed_terminal.response_feedback_unavailable = true;
        assert!(matches!(
            validate_stream_frame(&frame(unavailable_on_failed_terminal)),
            Err(GuiChatProtocolError::Invalid(
                "response_feedback_unavailable_not_complete"
            ))
        ));
    }

    #[test]
    fn missing_reasoning_display_decodes_false_and_digest_commits_grant() {
        let request = preflight();
        let mut historical = serde_json::to_value(&request).unwrap();
        historical
            .as_object_mut()
            .expect("preflight object")
            .remove("reasoning_display");
        let decoded: GuiChatPreflightRequest = serde_json::from_value(historical).unwrap();
        assert!(!decoded.reasoning_display);
        let mut shown = decoded.clone();
        shown.reasoning_display = true;
        assert_ne!(
            preflight_descriptor_digest(&decoded, &[], 7, None).unwrap(),
            preflight_descriptor_digest(&shown, &[], 7, None).unwrap(),
        );
    }

    #[test]
    fn reasoning_wire_frames_are_bounded_and_text_free_state_is_valid() {
        let lifecycle = GuiChatStreamFrame {
            schema_version: 1,
            boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            subscription: GuiChatSubscription {
                session_id: "session".into(),
                surface: GuiChatSurface::Main,
                generation: 1,
            },
            sequence: 1,
            payload: GuiChatFramePayload::ReasoningDelta {
                reasoning_sequence: 1,
                delta: "ephemeral".into(),
            },
        };
        validate_stream_frame(&lifecycle).unwrap();
        assert!(!format!("{lifecycle:?}").contains("ephemeral"));
        let state = GuiChatStreamFrame {
            sequence: 2,
            payload: GuiChatFramePayload::ReasoningState {
                reasoning_sequence: 2,
                state: crate::providers::ReasoningTerminalState::Complete,
                event_count: 1,
                byte_count: 9,
            },
            ..lifecycle
        };
        validate_stream_frame(&state).unwrap();
        let serialized = serde_json::to_string(&state).unwrap();
        assert!(!serialized.contains("ephemeral"));
        let checkpoint = GuiChatStreamFrame {
            sequence: 3,
            payload: GuiChatFramePayload::ReasoningCheckpoint {
                reasoning_sequence: 1,
                event_count: 1,
                byte_count: 9,
            },
            ..state
        };
        validate_stream_frame(&checkpoint).unwrap();
        assert!(
            !serde_json::to_string(&checkpoint)
                .unwrap()
                .contains("ephemeral")
        );
    }

    #[test]
    fn silence_timeout_frame_is_typed_and_cannot_be_misreported_as_completion() {
        let frame = GuiChatStreamFrame {
            schema_version: GUI_CHAT_V1_SCHEMA_VERSION,
            boot_id: "boot".into(),
            turn_id: GuiChatTurnId(Uuid::now_v7()),
            subscription: GuiChatSubscription {
                session_id: "session".into(),
                surface: GuiChatSurface::Main,
                generation: 1,
            },
            sequence: 1,
            payload: GuiChatFramePayload::TurnSilenceTimeout {
                timeout_seconds: crate::cli::chat_turn_watchdog::TURN_SILENCE_TIMEOUT.as_secs(),
                retryable: true,
            },
        };
        validate_stream_frame(&frame).expect("typed silence timeout frame validates");
        let encoded = serde_json::to_string(&frame).expect("encode silence timeout frame");
        assert!(encoded.contains("turn_silence_timeout"));
        assert!(encoded.contains("retryable"));
        assert!(!encoded.contains("provider_done"));
        assert!(!encoded.contains("complete"));

        let invalid = GuiChatStreamFrame {
            payload: GuiChatFramePayload::TurnSilenceTimeout {
                timeout_seconds: 1,
                retryable: false,
            },
            ..frame
        };
        assert!(matches!(
            validate_stream_frame(&invalid),
            Err(GuiChatProtocolError::Invalid("turn_silence_timeout_fields"))
        ));
    }
}
