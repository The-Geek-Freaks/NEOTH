//! Stable v3 authenticated mobile-companion wire contract.
//!
//! This standalone module deliberately defines application bytes independently
//! of serde's map ordering. Peeroxide provides the encrypted message carrier;
//! this module binds a durable device signing key to that carrier without
//! treating the per-invite Noise key as a durable identity.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const COMPANION_V3_SCHEMA_VERSION: u8 = 3;
pub const COMPANION_V3_MAX_FRAME_BYTES: usize = 8 * 1024;
pub const COMPANION_V3_MAX_CHAT_TERMINAL_BYTES: usize = 80 * 1024;
pub const COMPANION_V3_MAX_CHAT_MESSAGE_BYTES: usize = 640;
pub const COMPANION_V3_MAX_CHAT_RECORDS: usize = 64;
pub const COMPANION_ACTIVITY_SCHEMA_VERSION: u8 = 1;
pub const COMPANION_ACTIVITY_MAX_EVENTS: usize = 16;
pub const COMPANION_ACTIVITY_MAX_LABEL_BYTES: usize = 96;
pub const COMPANION_V3_MAX_LABEL_BYTES: usize = 64;
pub const COMPANION_V3_MAX_ACTIVE_TURNS: usize = 8;
pub const COMPANION_V3_STATUS_SCOPE: &str = "companion.status.read";
pub const COMPANION_V3_CHAT_SCOPE: &str = "companion.chat.send";
const ENROLL_DOMAIN: &[u8] = b"NEOTH/companion/v3/enroll";
const STATUS_DOMAIN: &[u8] = b"NEOTH/companion/v3/status";
const CHAT_DOMAIN: &[u8] = b"NEOTH/companion/v3/chat";

/// Schema v1 carries only these producer-owned presentation labels. Any new
/// label requires a coordinated schema revision instead of projecting tool
/// names, paths, arguments, or error text through the companion boundary.
pub fn is_companion_activity_label_v1(label: &str) -> bool {
    matches!(label, "Read file" | "Write file" | "List files" | "Search code" | "Tool call")
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionScope {
    StatusRead,
    ChatSend,
}

impl CompanionScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatusRead => COMPANION_V3_STATUS_SCOPE,
            Self::ChatSend => COMPANION_V3_CHAT_SCOPE,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceGrantState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionDeviceId(pub Uuid);

impl fmt::Display for CompanionDeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Public reconnect material only.  Neither this descriptor nor its durable
/// registry record contains a bearer, PSK, client private key, prompt, or
/// WebChat capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconnectDescriptor {
    pub schema_version: u8,
    pub carrier: String,
    pub rendezvous_topic: [u8; 32],
    pub daemon_noise_public_key: [u8; 32],
    pub descriptor_generation: u64,
}

/// First application message inside an already authenticated v2 bootstrap
/// connection.  `transport_peer_key` is the Noise peer key admitted from the
/// one-time invite; `device_signing_public_key` is deliberately independent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentProof {
    pub schema_version: u8,
    pub invite_topic: [u8; 32],
    pub transport_peer_key: [u8; 32],
    /// Long-lived Peeroxide static public key used only for v3 reconnect.
    /// It differs from the invite-derived v2 transport key above and is bound
    /// by this device-signing-key signature before the daemon persists it.
    pub client_noise_public_key: [u8; 32],
    pub device_signing_public_key: [u8; 32],
    pub client_nonce: [u8; 32],
    pub requested_scope: CompanionScope,
    pub label: String,
    /// Exact 64-byte Ed25519 signature. A Vec avoids depending on serde's
    /// fixed-array support while validation keeps the wire representation
    /// equally strict.
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentAccepted {
    pub schema_version: u8,
    pub device_id: CompanionDeviceId,
    pub revision: u64,
    pub granted_scope: CompanionScope,
    pub reconnect: ReconnectDescriptor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChatChallenge {
    pub schema_version: u8,
    pub device_id: CompanionDeviceId,
    pub revision: u64,
    pub listener_generation: u64,
    pub daemon_boot_id: String,
    pub challenge_nonce: [u8; 32],
    pub issued_at_unix: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionChatRequest {
    pub schema_version: u8,
    pub device_id: CompanionDeviceId,
    pub revision: u64,
    pub listener_generation: u64,
    pub daemon_boot_id: String,
    pub challenge_nonce: [u8; 32],
    pub request_id: Uuid,
    pub message: String,
    /// Deliberately request-scoped.  Absent preserves the exact v3 request
    /// encoding and signing transcript, so an installed v3 bridge can only
    /// ever receive its single terminal frame.
    #[serde(default, skip_serializing_if = "CompanionChatCapabilities::is_empty")]
    pub capabilities: CompanionChatCapabilities,
    pub signature: Vec<u8>,
}

/// Explicit client opt-in for server-to-client frames which are not part of
/// the original v3 one-terminal conversation.  New flags require their own
/// signed transcript extension; an empty value is omitted for wire- and
/// signature-compatibility with already paired v3 clients.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionChatCapabilities {
    #[serde(default)]
    pub tool_activity_v1: bool,
}

impl CompanionChatCapabilities {
    pub const fn is_empty(&self) -> bool {
        !self.tool_activity_v1
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionChatRecordKind {
    Stdout,
    Stderr,
    Notice,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionChatRecord {
    pub kind: CompanionChatRecordKind,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionChatOutcome {
    Accepted,
    Denied,
    Busy,
    Unavailable,
    Timeout,
    Indeterminate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionChatTerminal {
    pub schema_version: u8,
    pub request_id: Uuid,
    pub outcome: CompanionChatOutcome,
    pub records: Vec<CompanionChatRecord>,
    pub provider: Option<String>,
    pub model: Option<String>,
}

/// A bounded redacted snapshot for a capability-negotiated companion chat.
/// It is intentionally separate from the v3 terminal record contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionToolActivityPhase {
    Started,
    Succeeded,
    Failed,
    Rejected,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionToolActivityEvent {
    pub event_seq: u64,
    pub ordinal: u32,
    pub phase: CompanionToolActivityPhase,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionChatActivitySnapshot {
    pub activity_schema_version: u8,
    pub request_id: Uuid,
    pub max_event_seq: u64,
    pub incomplete: bool,
    pub events: Vec<CompanionToolActivityEvent>,
}

/// A server-minted, in-memory, one-use challenge.  It is bound to the exact
/// daemon listener generation and intentionally dies across a daemon restart;
/// a reconnect obtains a fresh challenge after the durable grant reloads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusChallenge {
    pub schema_version: u8,
    pub device_id: CompanionDeviceId,
    pub revision: u64,
    pub listener_generation: u64,
    pub daemon_boot_id: String,
    pub challenge_nonce: [u8; 32],
    pub issued_at_unix: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusProof {
    pub schema_version: u8,
    pub device_id: CompanionDeviceId,
    pub revision: u64,
    pub listener_generation: u64,
    pub daemon_boot_id: String,
    pub challenge_nonce: [u8; 32],
    /// Exact 64-byte Ed25519 signature.
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionStatusSnapshot {
    pub schema_version: u8,
    pub device_id: CompanionDeviceId,
    pub daemon_boot_id: String,
    pub readiness: CompanionReadiness,
    pub observed_at_unix: i64,
    /// `None` means this narrow vertical did not observe a turn inventory;
    /// it never fabricates an empty list as a readiness claim.
    pub active_turns: Option<Vec<CompanionActiveTurn>>,
}

/// Every server response uses this one adjacent-tagged envelope.  The body
/// remains versioned even though the envelope is not, so a client must reject
/// a stale body before it acts on an accepted enrollment, challenge, snapshot,
/// or denial.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum ServerFrame {
    EnrollmentAccepted(EnrollmentAccepted),
    StatusChallenge(StatusChallenge),
    StatusSnapshot(CompanionStatusSnapshot),
    ChatChallenge(ChatChallenge),
    ChatActivitySnapshot(CompanionChatActivitySnapshot),
    ChatTerminal(CompanionChatTerminal),
    Denied(CompanionDenied),
}

/// A deliberately small public denial.  Details stay in daemon logs and the
/// durable audit path; peers receive one bounded stable code only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionDenied {
    pub schema_version: u8,
    pub code: CompanionDeniedCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionDeniedCode {
    DeviceDenied,
    InvalidFrame,
    RetryLater,
    Unavailable,
}

impl CompanionDenied {
    pub fn new(code: CompanionDeniedCode) -> Result<Self, ProtocolError> {
        let value = Self {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            code: code.to_owned(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionReadiness {
    Ready,
    Starting,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionActiveTurn {
    pub phase: String,
    pub latest_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    UnsupportedVersion,
    InvalidLabel,
    InvalidBootId,
    InvalidDescriptor,
    InvalidSignature,
    InvalidFrame,
    TooManyActiveTurns,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedVersion => "unsupported companion v3 schema version",
            Self::InvalidLabel => "invalid companion device label",
            Self::InvalidBootId => "invalid daemon boot identity",
            Self::InvalidDescriptor => "invalid companion reconnect descriptor",
            Self::InvalidSignature => "invalid companion device signature",
            Self::InvalidFrame => "invalid or oversized companion frame",
            Self::TooManyActiveTurns => "companion status contains too many active turns",
        })
    }
}

impl std::error::Error for ProtocolError {}

impl EnrollmentProof {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        if self.label.is_empty() || self.label.len() > COMPANION_V3_MAX_LABEL_BYTES {
            return Err(ProtocolError::InvalidLabel);
        }
        if self.label.chars().any(char::is_control) {
            return Err(ProtocolError::InvalidLabel);
        }
        Ok(())
    }

    /// Stable length-delimited bytes, not serialized JSON.  The v2 Noise
    /// carrier authenticates possession of the invite PSK; this signature
    /// additionally binds durable client identity to that admitted carrier.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(ENROLL_DOMAIN.len() + 2 * 32 + 64 + self.label.len());
        push_field(&mut out, ENROLL_DOMAIN);
        push_field(&mut out, &[self.schema_version]);
        push_field(&mut out, &self.invite_topic);
        push_field(&mut out, &self.transport_peer_key);
        push_field(&mut out, &self.client_noise_public_key);
        push_field(&mut out, &self.device_signing_public_key);
        push_field(&mut out, &self.client_nonce);
        push_field(&mut out, self.requested_scope.as_str().as_bytes());
        push_field(&mut out, self.label.as_bytes());
        Ok(out)
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        let key = VerifyingKey::from_bytes(&self.device_signing_public_key)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        key.verify(&self.signing_bytes()?, &signature_bytes(&self.signature)?)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    pub fn signed(
        invite_topic: [u8; 32],
        transport_peer_key: [u8; 32],
        client_noise_public_key: [u8; 32],
        client_nonce: [u8; 32],
        requested_scope: CompanionScope,
        label: String,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let mut result = Self {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            invite_topic,
            transport_peer_key,
            client_noise_public_key,
            device_signing_public_key: signing_key.verifying_key().to_bytes(),
            client_nonce,
            requested_scope,
            label,
            signature: Vec::new(),
        };
        result.signature = signing_key
            .sign(&result.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(result)
    }
}

impl ChatChallenge {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        if self.daemon_boot_id.is_empty() || self.daemon_boot_id.len() > 128 {
            return Err(ProtocolError::InvalidBootId);
        }
        Ok(())
    }
}

impl CompanionChatRequest {
    pub const fn requests_tool_activity_v1(&self) -> bool {
        self.capabilities.tool_activity_v1
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        if self.daemon_boot_id.is_empty() || self.daemon_boot_id.len() > 128
            || self.message.is_empty()
            || self.message.len() > COMPANION_V3_MAX_CHAT_MESSAGE_BYTES
            // Match the daemon's sealed plain-chat boundary exactly: only a
            // slash after leading whitespace selects a local CLI action.
            // Embedded path separators and URLs remain ordinary text and are
            // signed/preserved as supplied.
            || self.message.trim_start().starts_with('/')
        {
            return Err(ProtocolError::InvalidFrame);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(
            CHAT_DOMAIN.len() + 192 + self.daemon_boot_id.len() + self.message.len(),
        );
        push_field(&mut out, CHAT_DOMAIN);
        push_field(&mut out, &[self.schema_version]);
        push_field(&mut out, self.device_id.0.as_bytes());
        push_field(&mut out, &self.revision.to_be_bytes());
        push_field(&mut out, &self.listener_generation.to_be_bytes());
        push_field(&mut out, self.daemon_boot_id.as_bytes());
        push_field(&mut out, &self.challenge_nonce);
        push_field(&mut out, self.request_id.as_bytes());
        push_field(&mut out, self.message.as_bytes());
        // Do not append an empty capability field: those exact bytes are the
        // already-deployed v3 signing transcript.  A requested capability is
        // bound to the request and cannot be introduced by a relay.
        if self.requests_tool_activity_v1() {
            push_field(&mut out, b"tool_activity_v1");
        }
        Ok(out)
    }

    pub fn signed(
        challenge: &ChatChallenge,
        request_id: Uuid,
        message: String,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        challenge.validate()?;
        let mut result = Self {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: challenge.device_id.clone(),
            revision: challenge.revision,
            listener_generation: challenge.listener_generation,
            daemon_boot_id: challenge.daemon_boot_id.clone(),
            challenge_nonce: challenge.challenge_nonce,
            request_id,
            message,
            capabilities: CompanionChatCapabilities::default(),
            signature: Vec::new(),
        };
        result.signature = signing_key
            .sign(&result.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(result)
    }

    pub fn signed_with_tool_activity_v1(
        challenge: &ChatChallenge,
        request_id: Uuid,
        message: String,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let mut result = Self::signed(challenge, request_id, message, signing_key)?;
        result.capabilities.tool_activity_v1 = true;
        result.signature = signing_key
            .sign(&result.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(result)
    }

    pub fn verify_with(&self, device_public_key: &[u8; 32]) -> Result<(), ProtocolError> {
        let key = VerifyingKey::from_bytes(device_public_key)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        key.verify(&self.signing_bytes()?, &signature_bytes(&self.signature)?)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

impl StatusChallenge {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        if self.daemon_boot_id.is_empty() || self.daemon_boot_id.len() > 128 {
            return Err(ProtocolError::InvalidBootId);
        }
        Ok(())
    }
}

impl StatusProof {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        if self.daemon_boot_id.is_empty() || self.daemon_boot_id.len() > 128 {
            return Err(ProtocolError::InvalidBootId);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut out = Vec::with_capacity(STATUS_DOMAIN.len() + 160 + self.daemon_boot_id.len());
        push_field(&mut out, STATUS_DOMAIN);
        push_field(&mut out, &[self.schema_version]);
        push_field(&mut out, self.device_id.0.as_bytes());
        push_field(&mut out, &self.revision.to_be_bytes());
        push_field(&mut out, &self.listener_generation.to_be_bytes());
        push_field(&mut out, self.daemon_boot_id.as_bytes());
        push_field(&mut out, &self.challenge_nonce);
        Ok(out)
    }

    pub fn signed(
        challenge: &StatusChallenge,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        challenge.validate()?;
        let mut result = Self {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: challenge.device_id.clone(),
            revision: challenge.revision,
            listener_generation: challenge.listener_generation,
            daemon_boot_id: challenge.daemon_boot_id.clone(),
            challenge_nonce: challenge.challenge_nonce,
            signature: Vec::new(),
        };
        result.signature = signing_key
            .sign(&result.signing_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(result)
    }

    pub fn verify_with(&self, device_public_key: &[u8; 32]) -> Result<(), ProtocolError> {
        let key = VerifyingKey::from_bytes(device_public_key)
            .map_err(|_| ProtocolError::InvalidSignature)?;
        key.verify(&self.signing_bytes()?, &signature_bytes(&self.signature)?)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

impl ReconnectDescriptor {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        if self.carrier != "peeroxide-hyperswarm-v3" || self.descriptor_generation == 0 {
            return Err(ProtocolError::InvalidDescriptor);
        }
        Ok(())
    }
}

impl CompanionStatusSnapshot {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        if self.daemon_boot_id.is_empty() || self.daemon_boot_id.len() > 128 {
            return Err(ProtocolError::InvalidBootId);
        }
        if self
            .active_turns
            .as_ref()
            .is_some_and(|turns| turns.len() > COMPANION_V3_MAX_ACTIVE_TURNS)
        {
            return Err(ProtocolError::TooManyActiveTurns);
        }
        if self
            .active_turns
            .as_ref()
            .into_iter()
            .flatten()
            .any(|turn| {
                turn.phase.is_empty()
                    || turn.phase.len() > 32
                    || turn.phase.chars().any(char::is_control)
            })
        {
            return Err(ProtocolError::InvalidFrame);
        }
        Ok(())
    }
}

impl CompanionChatTerminal {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        require_version(self.schema_version)?;
        if self.records.len() > COMPANION_V3_MAX_CHAT_RECORDS {
            return Err(ProtocolError::InvalidFrame);
        }
        match self.outcome {
            CompanionChatOutcome::Accepted => {
                if self.provider.as_deref().is_none_or(str::is_empty)
                    || self.model.as_deref().is_none_or(str::is_empty)
                {
                    return Err(ProtocolError::InvalidFrame);
                }
            }
            _ if !self.records.is_empty() || self.provider.is_some() || self.model.is_some() => {
                return Err(ProtocolError::InvalidFrame);
            }
            _ => {}
        }
        Ok(())
    }
}

impl CompanionChatActivitySnapshot {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.activity_schema_version != COMPANION_ACTIVITY_SCHEMA_VERSION
            || self.events.len() > COMPANION_ACTIVITY_MAX_EVENTS
        {
            return Err(ProtocolError::InvalidFrame);
        }
        let mut previous = 0u64;
        for event in &self.events {
            if event.event_seq == 0
                || event.event_seq <= previous
                || event.ordinal == 0
                || event.label.is_empty()
                || event.label.len() > COMPANION_ACTIVITY_MAX_LABEL_BYTES
                || event.label.chars().any(char::is_control)
                || !is_companion_activity_label_v1(&event.label)
            {
                return Err(ProtocolError::InvalidFrame);
            }
            previous = event.event_seq;
        }
        if self.max_event_seq != previous {
            return Err(ProtocolError::InvalidFrame);
        }
        Ok(())
    }
}

impl ServerFrame {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::EnrollmentAccepted(value) => {
                require_version(value.schema_version)?;
                value.reconnect.validate()
            }
            Self::StatusChallenge(value) => value.validate(),
            Self::StatusSnapshot(value) => value.validate(),
            Self::ChatChallenge(value) => value.validate(),
            Self::ChatActivitySnapshot(value) => value.validate(),
            Self::ChatTerminal(value) => value.validate(),
            Self::Denied(value) => value.validate(),
        }
    }
}

pub fn device_key_fingerprint(public_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public_key))
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let frame = serde_json::to_vec(value).map_err(|_| ProtocolError::InvalidFrame)?;
    (frame.len() <= COMPANION_V3_MAX_FRAME_BYTES)
        .then_some(frame)
        .ok_or(ProtocolError::InvalidFrame)
}

pub fn encode_server_frame(frame: &ServerFrame) -> Result<Vec<u8>, ProtocolError> {
    frame.validate()?;
    match frame {
        ServerFrame::ChatTerminal(_) => encode_chat_terminal(frame),
        _ => encode_frame(frame),
    }
}

/// Advertise optional activity support without changing the frozen
/// `ChatChallenge` body. Older adjacent-tag enum decoders ignore this
/// top-level sibling and retain their existing challenge/terminal exchange.
pub fn encode_chat_challenge_with_activity_advertisement(
    challenge: &ChatChallenge,
    tool_activity_v1: bool,
) -> Result<Vec<u8>, ProtocolError> {
    challenge.validate()?;
    let mut envelope = serde_json::Map::new();
    envelope.insert("type".into(), serde_json::Value::String("chat_challenge".into()));
    envelope.insert(
        "body".into(),
        serde_json::to_value(challenge).map_err(|_| ProtocolError::InvalidFrame)?,
    );
    if tool_activity_v1 {
        envelope.insert(
            "capabilities".into(),
            serde_json::json!({"tool_activity_v1": true}),
        );
    }
    encode_frame(&serde_json::Value::Object(envelope))
}

/// Decode the frozen challenge body plus the optional envelope advertisement.
/// Absent, unknown, false, or malformed capability values deliberately fall
/// back to legacy request signing. A malformed challenge itself remains an
/// error rather than being mistaken for legacy support.
pub fn decode_chat_challenge_with_activity_advertisement(
    bytes: &[u8],
) -> Result<(ChatChallenge, bool), ProtocolError> {
    if bytes.is_empty() || bytes.len() > COMPANION_V3_MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrame);
    }
    let envelope: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidFrame)?;
    let frame: ServerFrame =
        serde_json::from_value(envelope.clone()).map_err(|_| ProtocolError::InvalidFrame)?;
    let ServerFrame::ChatChallenge(challenge) = frame else {
        return Err(ProtocolError::InvalidFrame);
    };
    challenge.validate()?;
    let advertised = envelope
        .get("capabilities")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|capabilities| {
            capabilities.len() == 1
                && capabilities.get("tool_activity_v1") == Some(&serde_json::Value::Bool(true))
        });
    Ok((challenge, advertised))
}

pub fn encode_chat_terminal(frame: &ServerFrame) -> Result<Vec<u8>, ProtocolError> {
    let ServerFrame::ChatTerminal(value) = frame else {
        return Err(ProtocolError::InvalidFrame);
    };
    value.validate()?;
    let bytes = serde_json::to_vec(frame).map_err(|_| ProtocolError::InvalidFrame)?;
    (bytes.len() <= COMPANION_V3_MAX_CHAT_TERMINAL_BYTES)
        .then_some(bytes)
        .ok_or(ProtocolError::InvalidFrame)
}

pub fn decode_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, ProtocolError> {
    if frame.is_empty() || frame.len() > COMPANION_V3_MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrame);
    }
    serde_json::from_slice(frame).map_err(|_| ProtocolError::InvalidFrame)
}

pub fn decode_server_frame(frame: &[u8]) -> Result<ServerFrame, ProtocolError> {
    if frame.is_empty() || frame.len() > COMPANION_V3_MAX_CHAT_TERMINAL_BYTES {
        return Err(ProtocolError::InvalidFrame);
    }
    let value: ServerFrame =
        serde_json::from_slice(frame).map_err(|_| ProtocolError::InvalidFrame)?;
    value.validate()?;
    if !matches!(value, ServerFrame::ChatTerminal(_)) && frame.len() > COMPANION_V3_MAX_FRAME_BYTES
    {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(value)
}

fn require_version(version: u8) -> Result<(), ProtocolError> {
    (version == COMPANION_V3_SCHEMA_VERSION)
        .then_some(())
        .ok_or(ProtocolError::UnsupportedVersion)
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn signature_bytes(bytes: &[u8]) -> Result<Signature, ProtocolError> {
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidSignature)?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jm03_activity_snapshot_accepts_only_bounded_monotonic_redacted_events() {
        let snapshot = CompanionChatActivitySnapshot {
            activity_schema_version: COMPANION_ACTIVITY_SCHEMA_VERSION,
            request_id: Uuid::nil(),
            max_event_seq: 2,
            incomplete: false,
            events: vec![
                CompanionToolActivityEvent {
                    event_seq: 1,
                    ordinal: 1,
                    phase: CompanionToolActivityPhase::Started,
                    label: "Read file".to_owned(),
                },
                CompanionToolActivityEvent {
                    event_seq: 2,
                    ordinal: 1,
                    phase: CompanionToolActivityPhase::Succeeded,
                    label: "Read file".to_owned(),
                },
            ],
        };
        assert_eq!(snapshot.validate(), Ok(()));
    }

    #[test]
    fn jm04_activity_snapshot_rejects_sequence_and_label_boundary_breaks() {
        let mut snapshot = CompanionChatActivitySnapshot {
            activity_schema_version: COMPANION_ACTIVITY_SCHEMA_VERSION,
            request_id: Uuid::nil(),
            max_event_seq: 1,
            incomplete: true,
            events: vec![CompanionToolActivityEvent {
                event_seq: 1,
                ordinal: 1,
                phase: CompanionToolActivityPhase::Unknown,
                label: "Tool call".to_owned(),
            }],
        };
        snapshot.events[0].label = "x".repeat(COMPANION_ACTIVITY_MAX_LABEL_BYTES + 1);
        assert!(snapshot.validate().is_err());
        snapshot.events[0].label = "Tool call".to_owned();
        snapshot.events.push(snapshot.events[0].clone());
        snapshot.max_event_seq = 1;
        assert!(snapshot.validate().is_err());
        snapshot.events.truncate(1);
        snapshot.events[0].label = "C:\\private\\secret-token".to_owned();
        assert!(snapshot.validate().is_err());
    }

    #[test]
    fn jm03_capability_opt_in_is_signed_while_legacy_chat_request_bytes_stay_v3() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let challenge = ChatChallenge {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: CompanionDeviceId(Uuid::nil()),
            revision: 1,
            listener_generation: 2,
            daemon_boot_id: "boot".to_owned(),
            challenge_nonce: [3; 32],
            issued_at_unix: 4,
        };
        let legacy = CompanionChatRequest::signed(
            &challenge, Uuid::new_v4(), "hello".to_owned(), &signing,
        ).unwrap();
        let opted_in = CompanionChatRequest::signed_with_tool_activity_v1(
            &challenge, Uuid::new_v4(), "hello".to_owned(), &signing,
        ).unwrap();

        assert!(!legacy.requests_tool_activity_v1());
        assert!(!serde_json::to_string(&legacy).unwrap().contains("capabilities"));
        assert!(opted_in.requests_tool_activity_v1());
        assert!(serde_json::to_string(&opted_in).unwrap().contains("tool_activity_v1"));
        legacy.verify_with(&signing.verifying_key().to_bytes()).unwrap();
        opted_in.verify_with(&signing.verifying_key().to_bytes()).unwrap();
        assert_ne!(legacy.signing_bytes().unwrap(), opted_in.signing_bytes().unwrap());
    }

    #[test]
    fn jm03_envelope_sibling_advertisement_preserves_frozen_challenge_body() {
        #[derive(Deserialize)]
        #[serde(tag = "type", content = "body", rename_all = "snake_case")]
        enum FrozenLegacyServerFrame {
            ChatChallenge(ChatChallenge),
        }
        let challenge = ChatChallenge {
            schema_version: COMPANION_V3_SCHEMA_VERSION,
            device_id: CompanionDeviceId(Uuid::nil()),
            revision: 1,
            listener_generation: 2,
            daemon_boot_id: "boot".to_owned(),
            challenge_nonce: [4; 32],
            issued_at_unix: 5,
        };
        let bytes = encode_chat_challenge_with_activity_advertisement(&challenge, true).unwrap();
        let legacy: FrozenLegacyServerFrame = serde_json::from_slice(&bytes).unwrap();
        let FrozenLegacyServerFrame::ChatChallenge(legacy_body) = legacy;
        assert_eq!(legacy_body, challenge);
        let (decoded, advertised) = decode_chat_challenge_with_activity_advertisement(&bytes).unwrap();
        assert_eq!(decoded, challenge);
        assert!(advertised);
    }

    #[test]
    fn jm03_absent_unknown_or_malformed_advertisement_falls_back_to_legacy() {
        let body = r#"{"schema_version":3,"device_id":"00000000-0000-0000-0000-000000000000","revision":1,"listener_generation":2,"daemon_boot_id":"boot","challenge_nonce":[4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],"issued_at_unix":5}"#;
        for suffix in [
            "".to_owned(),
            ",\"capabilities\":{\"unknown\":true}".to_owned(),
            ",\"capabilities\":{\"tool_activity_v1\":\"yes\"}".to_owned(),
        ] {
            let bytes = format!("{{\"type\":\"chat_challenge\",\"body\":{body}{suffix}}}");
            assert!(!decode_chat_challenge_with_activity_advertisement(bytes.as_bytes()).unwrap().1);
        }
        assert!(decode_chat_challenge_with_activity_advertisement(
            br#"{"type":"chat_challenge","body":{"schema_version":2}}"#
        ).is_err());
    }

    #[test]
    fn chat_request_is_signed_to_a_fresh_challenge_and_rejects_slashes_or_overlong_text() {
        let signing = SigningKey::from_bytes(&[9; 32]);
        let challenge = ChatChallenge {
            schema_version: 3,
            device_id: CompanionDeviceId(Uuid::nil()),
            revision: 2,
            listener_generation: 3,
            daemon_boot_id: "boot".into(),
            challenge_nonce: [4; 32],
            issued_at_unix: 1,
        };
        let request = CompanionChatRequest::signed(
            &challenge,
            Uuid::now_v7(),
            "ordinary text".into(),
            &signing,
        )
        .unwrap();
        assert!(
            request
                .verify_with(&signing.verifying_key().to_bytes())
                .is_ok()
        );
        let mut path = request.clone();
        path.message = "ordinary / path".into();
        assert!(path.validate().is_ok());
        let mut url = request.clone();
        url.message = "https://example.test/a/b".into();
        assert!(url.validate().is_ok());
        let mut slash = request.clone();
        slash.message = "\n \t /help".into();
        assert!(slash.validate().is_err());
        let exact_limit = CompanionChatRequest::signed(
            &challenge,
            Uuid::now_v7(),
            "x".repeat(COMPANION_V3_MAX_CHAT_MESSAGE_BYTES),
            &signing,
        )
        .unwrap();
        assert!(exact_limit.validate().is_ok());
        let mut overlong = request;
        overlong.message = "x".repeat(COMPANION_V3_MAX_CHAT_MESSAGE_BYTES + 1);
        assert!(overlong.validate().is_err());
    }

    #[test]
    fn chat_terminal_never_exposes_records_for_nonaccepted_outcomes() {
        let terminal = CompanionChatTerminal {
            schema_version: 3,
            request_id: Uuid::nil(),
            outcome: CompanionChatOutcome::Busy,
            records: vec![CompanionChatRecord {
                kind: CompanionChatRecordKind::Stdout,
                text: "private".into(),
            }],
            provider: None,
            model: None,
        };
        assert!(terminal.validate().is_err());
    }

    #[test]
    fn server_frames_use_only_stable_adjacent_tags_and_bounded_denials() {
        let denied =
            ServerFrame::Denied(CompanionDenied::new(CompanionDeniedCode::DeviceDenied).unwrap());
        let encoded = encode_server_frame(&denied).unwrap();
        let decoded: ServerFrame = decode_frame(&encoded).unwrap();
        assert_eq!(decoded, denied);
        assert!(
            serde_json::from_slice::<ServerFrame>(
                br#"{"type":"denied","body":{"schema_version":3,"code":"detail_private_path"}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_slice::<ServerFrame>(
                br#"{"type":"denied","body":{"schema_version":3,"code":"ok","extra":true}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn validated_server_decode_rejects_bad_version_and_descriptor_in_every_body() {
        for frame in [
            br#"{"type":"enrollment_accepted","body":{"schema_version":2,"device_id":"00000000-0000-0000-0000-000000000001","revision":1,"granted_scope":"status_read","reconnect":{"schema_version":3,"carrier":"peeroxide-hyperswarm-v3","rendezvous_topic":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"daemon_noise_public_key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"descriptor_generation":1}}"# as &[u8],
            br#"{"type":"status_challenge","body":{"schema_version":2,"device_id":"00000000-0000-0000-0000-000000000001","revision":1,"listener_generation":1,"daemon_boot_id":"boot","challenge_nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"issued_at_unix":1}}"#,
            br#"{"type":"status_snapshot","body":{"schema_version":2,"device_id":"00000000-0000-0000-0000-000000000001","daemon_boot_id":"boot","readiness":"ready","observed_at_unix":1,"active_turns":null}}"#,
            br#"{"type":"denied","body":{"schema_version":2,"code":"device_denied"}}"#,
        ] { assert!(decode_server_frame(frame).is_err()); }
        assert!(decode_server_frame(br#"{"type":"enrollment_accepted","body":{"schema_version":3,"device_id":"00000000-0000-0000-0000-000000000001","revision":1,"granted_scope":"status_read","reconnect":{"schema_version":3,"carrier":"wrong","rendezvous_topic":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"daemon_noise_public_key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"descriptor_generation":1}}"#).is_err());
    }
}
