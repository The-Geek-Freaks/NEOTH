//! W153 terminal-only metadata codec for ephemeral provider reasoning streams.
//!
//! A reasoning delta is presentation-only data. This codec accepts exactly one
//! bounded terminal receipt and has no field capable of carrying reasoning
//! text, a content-derived hash, prompt/session identity, or replay cursor.

use serde::{Deserialize, Deserializer, Serialize};

/// The only schema version accepted for a `ReasoningStreamAuditV1` payload.
pub const REASONING_STREAM_AUDIT_SCHEMA_VERSION: u8 = 1;

/// Bounded decode and encode ceiling for the complete JSON receipt.
pub const MAX_REASONING_STREAM_AUDIT_BYTES: usize = 2 * 1024;

/// A request digest is the fixed-width, domain-separated SHA-256 identity
/// supplied by the request boundary, never the request id itself.
pub const REQUEST_ID_DIGEST_HEX_LEN: usize = 64;

/// Provider/model identities are copied exactly from the authenticated leaf.
/// These ceilings leave room for ordinary opaque local paths and explicit wire
/// model identifiers without turning the terminal receipt into an open blob.
pub const MAX_PROVIDER_ID_BYTES: usize = 256;
pub const MAX_MODEL_ID_BYTES: usize = 1024;

/// Bound terminal aggregate counters independently of the JSON byte ceiling.
pub const MAX_REASONING_EVENT_COUNT: u64 = 1_000_000;
pub const MAX_REASONING_BYTE_COUNT: u64 = 16 * 1024 * 1024;

/// Closed final disposition for the reasoning event plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningAuditTerminalState {
    Unsupported,
    Hidden,
    Redacted,
    Complete,
    Cancelled,
}

/// Closed terminal reason. Stream failures are represented here because the
/// terminal state vocabulary intentionally has no generic `error` variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningAuditReasonCode {
    Unsupported,
    DisplayDisabled,
    PolicyRedacted,
    Cancelled,
    Complete,
    StreamError,
}

/// Identity state for a terminal reasoning audit.
///
/// `Unobserved` says only that this audit path did not observe an authenticated
/// provider leaf. It makes no claim about whether a transport effect occurred.
/// In particular, stream-open and breaker failures must use this variant rather
/// than inventing a provider default or model alias.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReasoningAuditIdentity {
    AuthenticatedLeaf { provider: String, model: String },
    Unobserved,
}

/// One terminal metadata-only receipt for a reasoning stream.
///
/// Construction and deserialization both validate the complete closed shape.
/// Fields remain private so future append paths cannot create an unchecked
/// payload by struct literal; use [`ReasoningStreamAuditV1::new`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReasoningStreamAuditV1 {
    schema_version: u8,
    request_id_digest: String,
    identity: ReasoningAuditIdentity,
    display_granted: bool,
    event_count: u64,
    byte_count: u64,
    terminal_state: ReasoningAuditTerminalState,
    reason_code: ReasoningAuditReasonCode,
}

/// Strict wire-only shape. It is deliberately not public: `Deserialize` below
/// routes every externally shaped value through `TryFrom` and validation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasoningStreamAuditV1Wire {
    schema_version: u8,
    request_id_digest: String,
    identity: ReasoningAuditIdentity,
    display_granted: bool,
    event_count: u64,
    byte_count: u64,
    terminal_state: ReasoningAuditTerminalState,
    reason_code: ReasoningAuditReasonCode,
}

impl TryFrom<ReasoningStreamAuditV1Wire> for ReasoningStreamAuditV1 {
    type Error = anyhow::Error;

    fn try_from(value: ReasoningStreamAuditV1Wire) -> Result<Self, Self::Error> {
        let audit = Self {
            schema_version: value.schema_version,
            request_id_digest: value.request_id_digest,
            identity: value.identity,
            display_granted: value.display_granted,
            event_count: value.event_count,
            byte_count: value.byte_count,
            terminal_state: value.terminal_state,
            reason_code: value.reason_code,
        };
        audit.validate()?;
        Ok(audit)
    }
}

impl<'de> Deserialize<'de> for ReasoningStreamAuditV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ReasoningStreamAuditV1Wire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl ReasoningStreamAuditV1 {
    /// Construct the sole supported metadata-only audit shape.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id_digest: String,
        provider: String,
        model: String,
        display_granted: bool,
        event_count: u64,
        byte_count: u64,
        terminal_state: ReasoningAuditTerminalState,
        reason_code: ReasoningAuditReasonCode,
    ) -> anyhow::Result<Self> {
        let audit = Self {
            schema_version: REASONING_STREAM_AUDIT_SCHEMA_VERSION,
            request_id_digest,
            identity: ReasoningAuditIdentity::AuthenticatedLeaf { provider, model },
            display_granted,
            event_count,
            byte_count,
            terminal_state,
            reason_code,
        };
        audit.validate()?;
        Ok(audit)
    }

    /// Construct a terminal receipt when the stream failed or was cancelled
    /// before an authenticated leaf identity was observed. Observed counters
    /// are always zero for this state.
    pub fn without_observed_leaf(
        request_id_digest: String,
        display_granted: bool,
        terminal_state: ReasoningAuditTerminalState,
        reason_code: ReasoningAuditReasonCode,
    ) -> anyhow::Result<Self> {
        let audit = Self {
            schema_version: REASONING_STREAM_AUDIT_SCHEMA_VERSION,
            request_id_digest,
            identity: ReasoningAuditIdentity::Unobserved,
            display_granted,
            event_count: 0,
            byte_count: 0,
            terminal_state,
            reason_code,
        };
        audit.validate()?;
        Ok(audit)
    }

    /// Strict bounded serialization for the future immediate WAL append path.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        let encoded = serde_json::to_vec(self)
            .map_err(|error| anyhow::anyhow!("encode reasoning stream audit: {error}"))?;
        anyhow::ensure!(
            encoded.len() <= MAX_REASONING_STREAM_AUDIT_BYTES,
            "reasoning stream audit exceeds {MAX_REASONING_STREAM_AUDIT_BYTES} bytes"
        );
        Ok(encoded)
    }

    /// Strict bounded decoding for WAL inspection and recovery.
    pub fn decode(encoded: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            encoded.len() <= MAX_REASONING_STREAM_AUDIT_BYTES,
            "reasoning stream audit exceeds {MAX_REASONING_STREAM_AUDIT_BYTES} bytes"
        );
        let audit: Self = serde_json::from_slice(encoded)
            .map_err(|error| anyhow::anyhow!("decode reasoning stream audit: {error}"))?;
        audit.validate()?;
        Ok(audit)
    }

    /// The audited display grant, retained as a terminal lifecycle fact only.
    #[must_use]
    pub const fn display_granted(&self) -> bool {
        self.display_granted
    }

    /// The closed final reasoning disposition.
    #[must_use]
    pub const fn terminal_state(&self) -> ReasoningAuditTerminalState {
        self.terminal_state
    }

    /// The closed terminal reason, including stream errors.
    #[must_use]
    pub const fn reason_code(&self) -> ReasoningAuditReasonCode {
        self.reason_code
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == REASONING_STREAM_AUDIT_SCHEMA_VERSION,
            "unsupported reasoning stream audit schema version {}",
            self.schema_version
        );
        anyhow::ensure!(
            is_lower_sha256_hex(&self.request_id_digest),
            "reasoning stream audit request_id_digest must be a {REQUEST_ID_DIGEST_HEX_LEN}-character lower-case SHA-256 hex digest"
        );
        match &self.identity {
            ReasoningAuditIdentity::AuthenticatedLeaf { provider, model } => {
                ensure_authenticated_identity("provider", provider, MAX_PROVIDER_ID_BYTES)?;
                ensure_authenticated_identity("model", model, MAX_MODEL_ID_BYTES)?;
            }
            ReasoningAuditIdentity::Unobserved => {
                anyhow::ensure!(
                    self.event_count == 0 && self.byte_count == 0,
                    "unobserved reasoning audit identity cannot claim observed counters"
                );
                anyhow::ensure!(
                    self.terminal_state != ReasoningAuditTerminalState::Complete,
                    "unobserved reasoning audit identity cannot claim complete"
                );
                anyhow::ensure!(
                    matches!(
                        self.reason_code,
                        ReasoningAuditReasonCode::StreamError | ReasoningAuditReasonCode::Cancelled
                    ),
                    "unobserved reasoning audit identity requires stream_error or cancelled"
                );
            }
        }
        anyhow::ensure!(
            self.event_count <= MAX_REASONING_EVENT_COUNT,
            "reasoning stream audit event_count exceeds {MAX_REASONING_EVENT_COUNT}"
        );
        anyhow::ensure!(
            self.byte_count <= MAX_REASONING_BYTE_COUNT,
            "reasoning stream audit byte_count exceeds {MAX_REASONING_BYTE_COUNT}"
        );
        Ok(())
    }
}

/// Serializer entry point for append paths that need a free function instead
/// of a method. It carries the same validation as [`ReasoningStreamAuditV1`].
pub fn encode_reasoning_stream_audit_v1(
    audit: &ReasoningStreamAuditV1,
) -> anyhow::Result<Vec<u8>> {
    audit.encode()
}

fn is_lower_sha256_hex(value: &str) -> bool {
    value.len() == REQUEST_ID_DIGEST_HEX_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
        })
}

fn ensure_authenticated_identity(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.trim().is_empty() && value.len() <= max_bytes,
        "reasoning stream audit {label} must contain 1..={max_bytes} bytes"
    );
    anyhow::ensure!(
        value.chars().all(|character| !character.is_control()),
        "reasoning stream audit {label} contains a control character"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_audit() -> ReasoningStreamAuditV1 {
        ReasoningStreamAuditV1::new(
            "ab".repeat(32),
            "claude_cli".to_owned(),
            "claude-sonnet-4.5".to_owned(),
            true,
            3,
            144,
            ReasoningAuditTerminalState::Complete,
            ReasoningAuditReasonCode::Complete,
        )
        .expect("closed v1 audit fixture")
    }

    #[test]
    fn v1_schema_has_only_metadata_fields() {
        let value = serde_json::to_value(valid_audit()).expect("serialize v1 audit");
        let object = value.as_object().expect("v1 object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "schema_version",
                "request_id_digest",
                "identity",
                "display_granted",
                "event_count",
                "byte_count",
                "terminal_state",
                "reason_code",
            ])
        );
        assert_eq!(
            object
                .get("identity")
                .and_then(serde_json::Value::as_object)
                .expect("authenticated identity object")
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["kind", "provider", "model"])
        );
        assert!(
            !object.keys().any(|key| {
                matches!(key.as_str(), "reasoning" | "content_hash" | "prompt" | "session" | "replay")
            }),
            "metadata-only v1 must never grow a raw or replayable reasoning field"
        );
    }

    #[test]
    fn v1_rejects_unknown_schema_unbounded_and_control_values() {
        let unknown = br#"{"schema_version":1,"request_id_digest":"abababababababababababababababababababababababababababababababab","identity":{"kind":"authenticated_leaf","provider":"claude_cli","model":"claude-sonnet-4.5"},"display_granted":false,"event_count":0,"byte_count":0,"terminal_state":"hidden","reason_code":"display_disabled","reasoning":"never"}"#;
        assert!(ReasoningStreamAuditV1::decode(unknown).is_err());

        let unsupported_schema = br#"{"schema_version":2,"request_id_digest":"abababababababababababababababababababababababababababababababab","identity":{"kind":"authenticated_leaf","provider":"claude_cli","model":"claude-sonnet-4.5"},"display_granted":false,"event_count":0,"byte_count":0,"terminal_state":"hidden","reason_code":"display_disabled"}"#;
        assert!(ReasoningStreamAuditV1::decode(unsupported_schema).is_err());

        let unknown_reason = br#"{"schema_version":1,"request_id_digest":"abababababababababababababababababababababababababababababababab","identity":{"kind":"authenticated_leaf","provider":"claude_cli","model":"claude-sonnet-4.5"},"display_granted":false,"event_count":0,"byte_count":0,"terminal_state":"hidden","reason_code":"diagnostic_text"}"#;
        assert!(ReasoningStreamAuditV1::decode(unknown_reason).is_err());

        let bad_digest = ReasoningStreamAuditV1::new(
            "ABC".repeat(22),
            "claude_cli".to_owned(),
            "claude-sonnet-4.5".to_owned(),
            false,
            0,
            0,
            ReasoningAuditTerminalState::Hidden,
            ReasoningAuditReasonCode::DisplayDisabled,
        );
        assert!(bad_digest.is_err());

        let control_identity = ReasoningStreamAuditV1::new(
            "ab".repeat(32),
            "claude\ncli".to_owned(),
            "claude-sonnet-4.5".to_owned(),
            false,
            0,
            0,
            ReasoningAuditTerminalState::Hidden,
            ReasoningAuditReasonCode::DisplayDisabled,
        );
        assert!(control_identity.is_err());

        let unbounded = ReasoningStreamAuditV1::new(
            "ab".repeat(32),
            "claude_cli".to_owned(),
            "claude-sonnet-4.5".to_owned(),
            false,
            MAX_REASONING_EVENT_COUNT + 1,
            0,
            ReasoningAuditTerminalState::Hidden,
            ReasoningAuditReasonCode::DisplayDisabled,
        );
        assert!(unbounded.is_err());
    }

    #[test]
    fn v1_preserves_a_long_windows_local_wire_model_identity() {
        let model = format!(
            r"C:\Models\community\quantized\{}.gguf",
            "local-model_".repeat(16)
        );
        assert!(model.len() > 96);
        let audit = ReasoningStreamAuditV1::new(
            "ab".repeat(32),
            "local_qwen".to_owned(),
            model.clone(),
            false,
            0,
            0,
            ReasoningAuditTerminalState::Unsupported,
            ReasoningAuditReasonCode::Unsupported,
        )
        .expect("authenticated wire identity stays exact");
        let encoded = audit.encode().expect("encode exact wire identity");
        let decoded = ReasoningStreamAuditV1::decode(&encoded).expect("decode exact wire identity");
        let decoded_json = serde_json::to_value(decoded).expect("serialize decoded audit");
        assert_eq!(
            decoded_json
                .get("identity")
                .and_then(serde_json::Value::as_object)
                .and_then(|identity| identity.get("model"))
                .and_then(serde_json::Value::as_str),
            Some(model.as_str())
        );
    }

    #[test]
    fn v1_unobserved_identity_is_closed_and_zero_accounted() {
        let audit = ReasoningStreamAuditV1::without_observed_leaf(
            "ab".repeat(32),
            false,
            ReasoningAuditTerminalState::Hidden,
            ReasoningAuditReasonCode::StreamError,
        )
        .expect("pre-identity stream failure is representable");
        let value = serde_json::to_value(&audit).expect("serialize unobserved audit");
        assert_eq!(value["identity"], serde_json::json!({ "kind": "unobserved" }));
        assert_eq!(value["event_count"], 0);
        assert_eq!(value["byte_count"], 0);
        assert!(
            ReasoningStreamAuditV1::without_observed_leaf(
                "ab".repeat(32),
                false,
                ReasoningAuditTerminalState::Complete,
                ReasoningAuditReasonCode::StreamError,
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ReasoningStreamAuditV1>(serde_json::json!({
                "schema_version": 1,
                "request_id_digest": "ab".repeat(32),
                "identity": { "kind": "unobserved" },
                "display_granted": false,
                "event_count": 1,
                "byte_count": 0,
                "terminal_state": "hidden",
                "reason_code": "stream_error",
            }))
            .is_err()
        );
    }

    #[test]
    fn v1_round_trips_through_the_bounded_serializer() {
        let audit = valid_audit();
        let encoded = encode_reasoning_stream_audit_v1(&audit).expect("encode v1 audit");
        assert!(encoded.len() <= MAX_REASONING_STREAM_AUDIT_BYTES);
        assert_eq!(ReasoningStreamAuditV1::decode(&encoded).unwrap(), audit);
    }
}
