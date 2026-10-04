//! W2306 candidate: v3 authenticated mobile-companion wire contract.
//!
//! This is an isolated candidate, not compiled or integrated.  It deliberately
//! defines application bytes independently of serde's map ordering.  Peeroxide
//! provides the encrypted message carrier; this module binds a durable device
//! signing key to that carrier without treating the per-invite Noise key as a
//! durable identity.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const COMPANION_V3_SCHEMA_VERSION: u8 = 3;
pub const COMPANION_V3_MAX_FRAME_BYTES: usize = 8 * 1024;
pub const COMPANION_V3_MAX_LABEL_BYTES: usize = 64;
pub const COMPANION_V3_MAX_ACTIVE_TURNS: usize = 8;
pub const COMPANION_V3_STATUS_SCOPE: &str = "companion.status.read";
const ENROLL_DOMAIN: &[u8] = b"NEOTH/companion/v3/enroll";
const STATUS_DOMAIN: &[u8] = b"NEOTH/companion/v3/status";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionScope {
    StatusRead,
}

impl CompanionScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StatusRead => COMPANION_V3_STATUS_SCOPE,
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

impl ServerFrame {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::EnrollmentAccepted(value) => {
                require_version(value.schema_version)?;
                value.reconnect.validate()
            }
            Self::StatusChallenge(value) => value.validate(),
            Self::StatusSnapshot(value) => value.validate(),
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
    encode_frame(frame)
}

pub fn decode_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, ProtocolError> {
    if frame.is_empty() || frame.len() > COMPANION_V3_MAX_FRAME_BYTES {
        return Err(ProtocolError::InvalidFrame);
    }
    serde_json::from_slice(frame).map_err(|_| ProtocolError::InvalidFrame)
}

pub fn decode_server_frame(frame: &[u8]) -> Result<ServerFrame, ProtocolError> {
    let value: ServerFrame = decode_frame(frame)?;
    value.validate()?;
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
