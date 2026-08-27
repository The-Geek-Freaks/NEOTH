//! Sealed, metadata-only transcript-mining provenance contracts.
//!
//! This module intentionally has no database mutation or WAL append API. It
//! defines the closed payload shapes a later authenticated producer may use;
//! raw text, platform identifiers, labels, paths, and secrets are not
//! representable here.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, Serializer};

// These contracts are intentionally compiled ahead of the P1-08 authenticated
// Rust-payload producer/reader. Root-level non-test expectations keep the
// dormant release artifacts explicit without weakening their test vectors.
pub(crate) const TRANSCRIPT_MINING_PAYLOAD_SCHEMA_VERSION: u8 = 1;
pub(crate) const MAX_TRANSCRIPT_MINING_PAYLOAD_BYTES: usize = 1024;
const SHA256_HEX_LEN: usize = 64;

macro_rules! opaque_id {
    ($name:ident) => {
        #[cfg_attr(not(test), expect(
            dead_code,
            reason = "GOLD-LF-P1-08 stages 1-2 reserve opaque lifecycle and provenance identifiers before an authenticated Rust payload producer or reader exists"
        ))]
        #[derive(Clone, PartialEq, Eq, Serialize)]
        #[serde(transparent)]
        pub(crate) struct $name(String);

        impl $name {
            fn parse(value: String) -> Result<Self> {
                ensure!(
                    !value.is_empty()
                        && value.len() <= 64
                        && value.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'-' | b'_')
                        }),
                    "invalid opaque identifier"
                );
                Ok(Self(value))
            }

            fn validate(&self) -> Result<()> {
                Self::parse(self.0.clone()).map(|_| ())
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("[opaque-id]")
            }
        }
    };
}

opaque_id!(MiningLifecycleId);
opaque_id!(MiningProvenanceId);

/// Stable SQLite raw-turn row identity. Zero is never a valid AUTOINCREMENT
/// row and is rejected even when the payload was deserialized from WAL bytes.
#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve validated raw-turn identity before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct RawTurnRowId(i64);

impl RawTurnRowId {
    fn parse(value: i64) -> Result<Self> {
        ensure!(value > 0, "invalid raw turn row identifier");
        Ok(Self(value))
    }

    fn validate(&self) -> Result<()> {
        Self::parse(self.0).map(|_| ())
    }
}

/// A full SHA-256 digest, rendered only as canonical lower-case hex on disk.
#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve canonical digest bindings before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    fn parse_lower_hex(value: &str) -> Result<Self> {
        ensure!(
            value.len() == SHA256_HEX_LEN
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid sha256 digest"
        );
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0]).unwrap_or_default() << 4)
                | hex_nibble(pair[1]).unwrap_or_default();
        }
        Ok(Self(bytes))
    }

    fn lower_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.lower_hex())
    }
}

impl std::fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[sha256]")
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// An authenticated subject digest. Its field and constructor are private so
/// no caller can turn a raw platform subject identifier into mining authority.
#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve a sealed authenticated subject before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct AuthenticatedMiningSubject(Sha256Digest);

impl AuthenticatedMiningSubject {
    fn from_verified_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

impl std::fmt::Debug for AuthenticatedMiningSubject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthenticatedMiningSubject([redacted])")
    }
}

#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve the closed transcript source-kind vocabulary before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TranscriptMiningSourceKind {
    OperatorRawTextV1,
}

#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve finite retention values before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FiniteRetention {
    Minutes15,
    Hours24,
    Days30,
}

#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve closed privacy dispositions before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivacyDisposition {
    MiningPermitted,
    Revoked,
    LegacyUnbound,
}

#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve closed mining lifecycle states before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MiningLifecycle {
    Pending,
    Active,
    Revoked,
    Cancelled,
    LegacyUnbound,
}

#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve closed mining revocation reasons before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MiningRevocation {
    RawTurnDeleted,
    OperatorRevoked,
    RetentionExpired,
}

/// Metadata-only reference to the raw row and the corresponding WAL frame.
#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve raw-frame bindings before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RawFrameReference {
    raw_turn_row_id: RawTurnRowId,
    raw_frame_sha256: Sha256Digest,
}

impl RawFrameReference {
    fn validate(&self) -> Result<()> {
        self.raw_turn_row_id.validate()
    }
}

/// Canonical `ExtendedSubtype::TranscriptMiningBound` payload. Fields are in
/// canonical serialization order and exclude raw content and source identity.
#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve the sealed bound-payload contract before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TranscriptMiningBoundV1 {
    schema_version: u8,
    lifecycle_id: MiningLifecycleId,
    provenance_id: MiningProvenanceId,
    subject: AuthenticatedMiningSubject,
    raw_frame: RawFrameReference,
    raw_text_sha256: Sha256Digest,
    source_kind: TranscriptMiningSourceKind,
    retention: FiniteRetention,
    privacy_disposition: PrivacyDisposition,
    lifecycle: MiningLifecycle,
    issued_at_unix: i64,
    expires_at_unix: i64,
}

/// Canonical `ExtendedSubtype::TranscriptMiningRevoked` payload. It carries a
/// closed reason and digest bindings only; no text survives revocation.
#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve the sealed revocation-payload contract before an authenticated Rust payload producer or reader exists"
))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TranscriptMiningRevokedV1 {
    schema_version: u8,
    lifecycle_id: MiningLifecycleId,
    provenance_id: MiningProvenanceId,
    subject: AuthenticatedMiningSubject,
    raw_frame: RawFrameReference,
    bound_payload_sha256: Sha256Digest,
    revocation: MiningRevocation,
    privacy_disposition: PrivacyDisposition,
    lifecycle: MiningLifecycle,
    revoked_at_unix: i64,
}

impl TranscriptMiningBoundV1 {
    fn validate(&self) -> Result<()> {
        self.lifecycle_id.validate()?;
        self.provenance_id.validate()?;
        self.raw_frame.validate()?;
        ensure!(
            self.schema_version == TRANSCRIPT_MINING_PAYLOAD_SCHEMA_VERSION,
            "unsupported transcript mining payload version"
        );
        ensure!(
            self.privacy_disposition == PrivacyDisposition::MiningPermitted
                && self.lifecycle == MiningLifecycle::Active
                && self.expires_at_unix > self.issued_at_unix,
            "invalid transcript mining binding state"
        );
        Ok(())
    }

    #[cfg_attr(not(test), expect(
        dead_code,
        reason = "GOLD-LF-P1-08 stages 1-2 reserve bound-payload encoding before an authenticated Rust payload producer or reader exists"
    ))]
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_canonical(self)
    }

    #[cfg_attr(not(test), expect(
        dead_code,
        reason = "GOLD-LF-P1-08 stages 1-2 reserve bound-payload decoding before an authenticated Rust payload producer or reader exists"
    ))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let wire: TranscriptMiningBoundWire = decode_wire(bytes)?;
        let value = Self::from_wire(wire)?;
        ensure!(
            encode_canonical(&value)? == bytes,
            "transcript mining payload is not canonical"
        );
        value.validate()?;
        Ok(value)
    }

    fn from_wire(wire: TranscriptMiningBoundWire) -> Result<Self> {
        Ok(Self {
            schema_version: wire.schema_version,
            lifecycle_id: MiningLifecycleId::parse(wire.lifecycle_id)?,
            provenance_id: MiningProvenanceId::parse(wire.provenance_id)?,
            subject: AuthenticatedMiningSubject::from_verified_digest(
                Sha256Digest::parse_lower_hex(&wire.subject)?,
            ),
            raw_frame: RawFrameReference {
                raw_turn_row_id: RawTurnRowId::parse(wire.raw_frame.raw_turn_row_id)?,
                raw_frame_sha256: Sha256Digest::parse_lower_hex(&wire.raw_frame.raw_frame_sha256)?,
            },
            raw_text_sha256: Sha256Digest::parse_lower_hex(&wire.raw_text_sha256)?,
            source_kind: wire.source_kind,
            retention: wire.retention,
            privacy_disposition: wire.privacy_disposition,
            lifecycle: wire.lifecycle,
            issued_at_unix: wire.issued_at_unix,
            expires_at_unix: wire.expires_at_unix,
        })
    }
}

impl TranscriptMiningRevokedV1 {
    fn validate(&self) -> Result<()> {
        self.lifecycle_id.validate()?;
        self.provenance_id.validate()?;
        self.raw_frame.validate()?;
        ensure!(
            self.schema_version == TRANSCRIPT_MINING_PAYLOAD_SCHEMA_VERSION,
            "unsupported transcript mining payload version"
        );
        ensure!(
            self.privacy_disposition == PrivacyDisposition::Revoked
                && matches!(
                    self.lifecycle,
                    MiningLifecycle::Revoked | MiningLifecycle::Cancelled
                ),
            "invalid transcript mining revocation state"
        );
        Ok(())
    }

    #[cfg_attr(not(test), expect(
        dead_code,
        reason = "GOLD-LF-P1-08 stages 1-2 reserve revocation-payload encoding before an authenticated Rust payload producer or reader exists"
    ))]
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_canonical(self)
    }

    #[cfg_attr(not(test), expect(
        dead_code,
        reason = "GOLD-LF-P1-08 stages 1-2 reserve revocation-payload decoding before an authenticated Rust payload producer or reader exists"
    ))]
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let wire: TranscriptMiningRevokedWire = decode_wire(bytes)?;
        let value = Self::from_wire(wire)?;
        ensure!(
            encode_canonical(&value)? == bytes,
            "transcript mining payload is not canonical"
        );
        value.validate()?;
        Ok(value)
    }

    fn from_wire(wire: TranscriptMiningRevokedWire) -> Result<Self> {
        Ok(Self {
            schema_version: wire.schema_version,
            lifecycle_id: MiningLifecycleId::parse(wire.lifecycle_id)?,
            provenance_id: MiningProvenanceId::parse(wire.provenance_id)?,
            subject: AuthenticatedMiningSubject::from_verified_digest(
                Sha256Digest::parse_lower_hex(&wire.subject)?,
            ),
            raw_frame: RawFrameReference {
                raw_turn_row_id: RawTurnRowId::parse(wire.raw_frame.raw_turn_row_id)?,
                raw_frame_sha256: Sha256Digest::parse_lower_hex(&wire.raw_frame.raw_frame_sha256)?,
            },
            bound_payload_sha256: Sha256Digest::parse_lower_hex(&wire.bound_payload_sha256)?,
            revocation: wire.revocation,
            privacy_disposition: wire.privacy_disposition,
            lifecycle: wire.lifecycle,
            revoked_at_unix: wire.revoked_at_unix,
        })
    }
}

#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve raw-frame wire decoding before an authenticated Rust payload producer or reader exists"
))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFrameReferenceWire {
    raw_turn_row_id: i64,
    raw_frame_sha256: String,
}

#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve bound-payload wire decoding before an authenticated Rust payload producer or reader exists"
))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptMiningBoundWire {
    schema_version: u8,
    lifecycle_id: String,
    provenance_id: String,
    subject: String,
    raw_frame: RawFrameReferenceWire,
    raw_text_sha256: String,
    source_kind: TranscriptMiningSourceKind,
    retention: FiniteRetention,
    privacy_disposition: PrivacyDisposition,
    lifecycle: MiningLifecycle,
    issued_at_unix: i64,
    expires_at_unix: i64,
}

#[cfg_attr(not(test), expect(
    dead_code,
    reason = "GOLD-LF-P1-08 stages 1-2 reserve revocation-payload wire decoding before an authenticated Rust payload producer or reader exists"
))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptMiningRevokedWire {
    schema_version: u8,
    lifecycle_id: String,
    provenance_id: String,
    subject: String,
    raw_frame: RawFrameReferenceWire,
    bound_payload_sha256: String,
    revocation: MiningRevocation,
    privacy_disposition: PrivacyDisposition,
    lifecycle: MiningLifecycle,
    revoked_at_unix: i64,
}

fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| anyhow::anyhow!("encode transcript mining payload"))?;
    ensure!(
        bytes.len() <= MAX_TRANSCRIPT_MINING_PAYLOAD_BYTES,
        "transcript mining payload exceeds size limit"
    );
    Ok(bytes)
}

fn decode_wire<T>(bytes: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    ensure!(
        bytes.len() <= MAX_TRANSCRIPT_MINING_PAYLOAD_BYTES,
        "transcript mining payload exceeds size limit"
    );
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("decode transcript mining payload"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> Sha256Digest {
        Sha256Digest::parse_lower_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap()
    }

    fn bound() -> TranscriptMiningBoundV1 {
        TranscriptMiningBoundV1 {
            schema_version: 1,
            lifecycle_id: MiningLifecycleId::parse("lifecycle-01".into()).unwrap(),
            provenance_id: MiningProvenanceId::parse("provenance-01".into()).unwrap(),
            subject: AuthenticatedMiningSubject::from_verified_digest(digest()),
            raw_frame: RawFrameReference {
                raw_turn_row_id: RawTurnRowId::parse(7).unwrap(),
                raw_frame_sha256: digest(),
            },
            raw_text_sha256: digest(),
            source_kind: TranscriptMiningSourceKind::OperatorRawTextV1,
            retention: FiniteRetention::Hours24,
            privacy_disposition: PrivacyDisposition::MiningPermitted,
            lifecycle: MiningLifecycle::Active,
            issued_at_unix: 100,
            expires_at_unix: 101,
        }
    }

    #[test]
    fn bound_payload_is_fixed_canonical_metadata_only_vector() {
        let encoded = bound().encode().unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            "{\"schema_version\":1,\"lifecycle_id\":\"lifecycle-01\",\"provenance_id\":\"provenance-01\",\"subject\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"raw_frame\":{\"raw_turn_row_id\":7,\"raw_frame_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"},\"raw_text_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"source_kind\":\"operator_raw_text_v1\",\"retention\":\"hours24\",\"privacy_disposition\":\"mining_permitted\",\"lifecycle\":\"active\",\"issued_at_unix\":100,\"expires_at_unix\":101}"
        );
        assert_eq!(TranscriptMiningBoundV1::decode(&encoded).unwrap(), bound());
    }

    #[test]
    fn revoked_payload_is_fixed_canonical_metadata_only_vector() {
        let revoked = TranscriptMiningRevokedV1 {
            schema_version: 1,
            lifecycle_id: MiningLifecycleId::parse("lifecycle-01".into()).unwrap(),
            provenance_id: MiningProvenanceId::parse("provenance-01".into()).unwrap(),
            subject: AuthenticatedMiningSubject::from_verified_digest(digest()),
            raw_frame: RawFrameReference {
                raw_turn_row_id: RawTurnRowId::parse(7).unwrap(),
                raw_frame_sha256: digest(),
            },
            bound_payload_sha256: digest(),
            revocation: MiningRevocation::RawTurnDeleted,
            privacy_disposition: PrivacyDisposition::Revoked,
            lifecycle: MiningLifecycle::Cancelled,
            revoked_at_unix: 102,
        };
        let encoded = revoked.encode().unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            "{\"schema_version\":1,\"lifecycle_id\":\"lifecycle-01\",\"provenance_id\":\"provenance-01\",\"subject\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"raw_frame\":{\"raw_turn_row_id\":7,\"raw_frame_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"},\"bound_payload_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"revocation\":\"raw_turn_deleted\",\"privacy_disposition\":\"revoked\",\"lifecycle\":\"cancelled\",\"revoked_at_unix\":102}"
        );
        assert_eq!(
            TranscriptMiningRevokedV1::decode(&encoded).unwrap(),
            revoked
        );
    }

    #[test]
    fn decoder_rejects_unknown_noncanonical_digest_and_expiry() {
        assert!(TranscriptMiningBoundV1::decode(br#"{"schema_version":1,"extra":true}"#).is_err());
        assert!(TranscriptMiningBoundV1::decode(b"{} ").is_err());
        let mut invalid = bound();
        invalid.expires_at_unix = invalid.issued_at_unix;
        assert!(invalid.encode().is_err());
        assert!(Sha256Digest::parse_lower_hex("not-a-digest").is_err());
    }

    #[test]
    fn payload_type_surface_has_no_raw_or_path_fields() {
        let encoded = String::from_utf8(bound().encode().unwrap()).unwrap();
        for prohibited in ["text", "platform", "label", "path", "secret"] {
            assert!(!encoded.contains(&format!("\"{prohibited}\"")));
        }
    }
}
