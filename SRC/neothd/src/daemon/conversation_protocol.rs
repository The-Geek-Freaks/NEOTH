//! Closed, projection-only A2 audit-RPC contract.
//!
//! This module deliberately contains no provider, PCM, transcript, capability,
//! receipt, WAL, or permit value.  The retained registry is its sole consumer.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::gui_chat_protocol::{GuiChatConsentDecision, GuiChatConsentPromptWire};

pub(crate) const CONVERSATION_V1_SCHEMA_VERSION: u16 = 1;
pub(crate) const CONVERSATION_V1_AVAILABILITY_PATH: &str = "/conversation/v1/availability";
pub(crate) const CONVERSATION_V1_PREFLIGHT_PATH: &str = "/conversation/v1/preflight";
pub(crate) const CONVERSATION_V1_MICROPHONE_DECIDE_PATH: &str =
    "/conversation/v1/microphone/decide";
pub(crate) const CONVERSATION_V1_PROVIDER_DECIDE_PATH: &str = "/conversation/v1/provider/decide";
pub(crate) const CONVERSATION_V1_START_PATH: &str = "/conversation/v1/start";
pub(crate) const CONVERSATION_V1_ABORT_START_PATH: &str = "/conversation/v1/start/abort";
pub(crate) const CONVERSATION_V1_CONTROL_PATH: &str = "/conversation/v1/control";
pub(crate) const CONVERSATION_V1_REVOKE_MICROPHONE_PATH: &str =
    "/conversation/v1/revoke-microphone";
pub(crate) const CONVERSATION_V1_ATTACH_PATH: &str = "/conversation/v1/attach";
pub(crate) const CONVERSATION_BOOT_ID_MAX_BYTES: usize = 128;
pub(crate) const CONVERSATION_ID_MAX_BYTES: usize = 128;
pub(crate) const CONVERSATION_REPLAY_MAX_FRAMES: usize = 256;
pub(crate) const CONVERSATION_FRAME_MAX_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct ConversationRequestId(pub(crate) Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct ConversationSubscriptionId(pub(crate) String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConversationSurface {
    Buddy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MicConsentDecision {
    AllowOnce,
    AllowAlways,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConversationControl {
    Stop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConversationState {
    Ready,
    Listening,
    Recognizing,
    Thinking,
    Speaking,
    Cancelling,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConversationErrorCode {
    InvalidRequest,
    Conflict,
    Unauthorized,
    Forbidden,
    BootChanged,
    Busy,
    Unavailable,
    ConsentRequired,
    ReplayGap,
    CancelIndeterminate,
    MicrophoneDenied,
    MicrophoneRevoked,
    MicrophoneOpenFailed,
    DeviceLost,
    WalFailed,
    SttFailed,
    TtsFailed,
    QueueOverflow,
    GenerationExhausted,
    StreamSettlementIndeterminate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConversationTerminal {
    pub(crate) code: ConversationErrorCode,
    pub(crate) retryable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SafeMicPrompt {
    pub(crate) expires_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConversationFeature {
    Available,
    LiveAudioDisabled,
    ComponentsUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MicrophonePermissionState {
    Unknown,
    Required,
    Granted,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MicOpenOutcome {
    Opened,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConversationAvailability {
    pub(crate) feature: ConversationFeature,
    pub(crate) microphone: MicrophonePermissionState,
    pub(crate) busy: bool,
    pub(crate) last_device_open: Option<MicOpenOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub(crate) enum ConversationEvent {
    Availability {
        availability: ConversationAvailability,
    },
    MicrophoneConfirmationRequired {
        request_id: ConversationRequestId,
        prompt: SafeMicPrompt,
    },
    ProviderConfirmationRequired {
        provider_request_id: ConversationRequestId,
        prompt: GuiChatConsentPromptWire,
    },
    State {
        state: ConversationState,
    },
    Terminal {
        terminal: ConversationTerminal,
    },
}

macro_rules! request {
    ($name:ident { $($field:ident : $kind:ty),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct $name {
            pub(crate) schema_version: u16,
            pub(crate) expected_boot_id: String,
            pub(crate) request_id: ConversationRequestId,
            $(pub(crate) $field: $kind,)*
        }
    };
}
request!(ConversationAvailabilityRequest {});
request!(ConversationPreflightRequest {
    session_id: String,
    origin_surface: ConversationSurface
});
request!(ConversationMicrophoneDecisionRequest {
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    expected_generation: u64,
    decision: MicConsentDecision
});
request!(ConversationProviderDecisionRequest {
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    expected_generation: u64,
    provider_request_id: ConversationRequestId,
    decision: GuiChatConsentDecision
});
request!(ConversationStartRequest {
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    expected_generation: u64
});
request!(ConversationAbortStartRequest {
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    expected_generation: u64
});
request!(ConversationControlRequest {
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    expected_generation: u64,
    control: ConversationControl
});
request!(ConversationRevokeMicrophoneRequest {
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    expected_generation: u64
});
request!(ConversationAttachRequest {
    subscription_id: ConversationSubscriptionId,
    session_id: String,
    origin_surface: ConversationSurface,
    expected_generation: u64,
    after_sequence: u64
});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConversationAvailabilityResponse {
    pub(crate) schema_version: u16,
    pub(crate) expected_boot_id: String,
    pub(crate) availability: ConversationAvailability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConversationProgressResponse {
    pub(crate) schema_version: u16,
    pub(crate) expected_boot_id: String,
    pub(crate) request_id: ConversationRequestId,
    pub(crate) subscription_id: Option<ConversationSubscriptionId>,
    pub(crate) generation: u64,
    pub(crate) latest_sequence: u64,
    pub(crate) event: ConversationEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConversationStreamFrame {
    pub(crate) schema_version: u16,
    pub(crate) expected_boot_id: String,
    pub(crate) subscription_id: ConversationSubscriptionId,
    pub(crate) generation: u64,
    pub(crate) sequence: u64,
    pub(crate) event: ConversationEvent,
}

#[async_trait::async_trait]
pub(crate) trait ConversationProjectionSink: Send {
    async fn on_frame(&mut self, frame: ConversationStreamFrame) -> ConversationResult<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConversationError {
    pub(crate) code: ConversationErrorCode,
    pub(crate) retryable: bool,
    detail: &'static str,
}
impl ConversationError {
    pub(crate) const fn new(
        code: ConversationErrorCode,
        retryable: bool,
        detail: &'static str,
    ) -> Self {
        Self {
            code,
            retryable,
            detail,
        }
    }
    pub(crate) const fn unavailable(detail: &'static str) -> Self {
        Self::new(ConversationErrorCode::Unavailable, false, detail)
    }
    pub(crate) const fn invalid(detail: &'static str) -> Self {
        Self::new(ConversationErrorCode::InvalidRequest, false, detail)
    }
}
impl std::fmt::Display for ConversationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail)
    }
}
impl std::error::Error for ConversationError {}
pub(crate) type ConversationResult<T> = Result<T, ConversationError>;

pub(crate) fn validate_request_header(
    schema_version: u16,
    expected_boot_id: &str,
    boot_id: &str,
) -> ConversationResult<()> {
    if schema_version != CONVERSATION_V1_SCHEMA_VERSION {
        return Err(ConversationError::invalid("conversation_schema_version"));
    }
    if expected_boot_id.is_empty() || expected_boot_id.len() > CONVERSATION_BOOT_ID_MAX_BYTES {
        return Err(ConversationError::invalid("conversation_boot_id"));
    }
    if expected_boot_id != boot_id {
        return Err(ConversationError::new(
            ConversationErrorCode::BootChanged,
            true,
            "conversation_boot_changed",
        ));
    }
    Ok(())
}
pub(crate) fn validate_id(value: &str) -> ConversationResult<()> {
    if value.is_empty()
        || value.len() > CONVERSATION_ID_MAX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
    {
        Err(ConversationError::invalid("conversation_id"))
    } else {
        Ok(())
    }
}
