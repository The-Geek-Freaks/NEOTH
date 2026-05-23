//! K-5 — Keet-specific WAL payload shapes.
//!
//! The K-1 spec originally reserved `0x35 KEET_INGRESS` + `0x36
//! KEET_EGRESS` but those event-code slots were already claimed by
//! `INGRESS_QUARANTINED` + `INGRESS_SANITIZED` (the sanitizer
//! pipeline). The right ship is to reuse the generic
//! `EVENT_TYPE_CHANNEL_INGRESS` (0x32) + `EVENT_TYPE_CHANNEL_EGRESS`
//! (0x33) with a Keet-specific PAYLOAD shape that carries the
//! peer-public-key + device-id + seed-fingerprint fields a generic
//! channel payload doesn't have.
//!
//! This module ships the typed payload structs + helpers that
//! build the JSON byte vec the WAL writer consumes. Pure-fn so
//! tests pin the wire shape without touching disk.

use serde::{Deserialize, Serialize};

/// Canonical channel slug for Keet ingress/egress payloads. Pin
/// drift-guarded — a future rename needs operator migration since
/// the WAL replay matches by this string.
pub const KEET_CHANNEL_SLUG: &str = "keet";

/// Ingress payload — message coming FROM Keet INTO NEOTH.
/// `peer_pubkey` is the Hyperswarm noise-protocol public key
/// (32-byte hex); `device_id` is operator-assigned to disambiguate
/// the same identity across phone + laptop + tablet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeetIngressPayload {
    /// Always `"keet"` — drift-guarded by serde-round-trip test.
    pub channel: String,
    /// Hyperswarm noise-protocol public key (32-byte hex).
    pub peer_pubkey: String,
    /// Operator-assigned device tag (e.g. `"phone"`, `"laptop"`).
    pub device_id: String,
    /// Inbound message body — already sanitised (the sanitizer
    /// runs upstream of WAL append).
    pub text: String,
    /// ISO-8601 timestamp at ingress (operator-local).
    pub ts_iso: String,
    /// Optional reply-to-message-id when this is a thread reply.
    pub reply_to: Option<String>,
}

impl KeetIngressPayload {
    /// Construct with the channel slug pre-filled so callers can't
    /// forget. Operator-visible failure if they pass the wrong slug
    /// would surface as orphaned events in a doctor scan.
    pub fn new(
        peer_pubkey: impl Into<String>,
        device_id: impl Into<String>,
        text: impl Into<String>,
        ts_iso: impl Into<String>,
    ) -> Self {
        Self {
            channel: KEET_CHANNEL_SLUG.to_string(),
            peer_pubkey: peer_pubkey.into(),
            device_id: device_id.into(),
            text: text.into(),
            ts_iso: ts_iso.into(),
            reply_to: None,
        }
    }

    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }

    /// Serialise to the JSON bytes the WAL writer appends.
    /// Returns an empty Vec on serialisation failure — the
    /// Serialize impl can't fail in practice (no Result-returning
    /// fields) so the empty path is dead code defended against.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Egress payload — message going FROM NEOTH OUT to Keet. Mirrors
/// the ingress shape but carries the `message_id` Keet returns
/// after a successful send (used to anchor `CHANNEL_ACK`/EDIT
/// events 0x37/0x38).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeetEgressPayload {
    pub channel: String,
    pub peer_pubkey: String,
    pub device_id: String,
    pub text: String,
    pub ts_iso: String,
    /// Keet-assigned message id (returned by `send_message`).
    /// Empty when the send is fire-and-forget.
    pub message_id: String,
}

impl KeetEgressPayload {
    pub fn new(
        peer_pubkey: impl Into<String>,
        device_id: impl Into<String>,
        text: impl Into<String>,
        ts_iso: impl Into<String>,
    ) -> Self {
        Self {
            channel: KEET_CHANNEL_SLUG.to_string(),
            peer_pubkey: peer_pubkey.into(),
            device_id: device_id.into(),
            text: text.into(),
            ts_iso: ts_iso.into(),
            message_id: String::new(),
        }
    }

    pub fn with_message_id(mut self, id: impl Into<String>) -> Self {
        self.message_id = id.into();
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// True ⇔ `slug` is the Keet channel identifier. Case-sensitive —
/// the WAL replay matches verbatim.
pub fn is_keet_channel(slug: &str) -> bool {
    slug == KEET_CHANNEL_SLUG
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_ingress() -> KeetIngressPayload {
        KeetIngressPayload::new(
            "0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd",
            "phone",
            "hello from keet",
            "2026-05-23T10:00:00+02:00",
        )
    }

    fn fixture_egress() -> KeetEgressPayload {
        KeetEgressPayload::new(
            "0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd",
            "laptop",
            "reply text",
            "2026-05-23T10:01:00+02:00",
        )
        .with_message_id("msg-7f3a")
    }

    // ── KEET_CHANNEL_SLUG drift guard ───────────────────────────

    #[test]
    fn keet_channel_slug_pinned() {
        assert_eq!(KEET_CHANNEL_SLUG, "keet");
    }

    #[test]
    fn is_keet_channel_matches_canonical_only() {
        assert!(is_keet_channel("keet"));
        assert!(!is_keet_channel("Keet"));
        assert!(!is_keet_channel("KEET"));
        assert!(!is_keet_channel(""));
        assert!(!is_keet_channel("telegram"));
    }

    // ── KeetIngressPayload ──────────────────────────────────────

    #[test]
    fn ingress_constructor_fills_canonical_slug() {
        let p = fixture_ingress();
        assert_eq!(p.channel, "keet");
    }

    #[test]
    fn ingress_reply_to_defaults_to_none() {
        let p = fixture_ingress();
        assert!(p.reply_to.is_none());
    }

    #[test]
    fn ingress_with_reply_to_sets_field() {
        let p = fixture_ingress().with_reply_to("parent-id-7f3a");
        assert_eq!(p.reply_to.as_deref(), Some("parent-id-7f3a"));
    }

    #[test]
    fn ingress_to_bytes_emits_valid_json_with_required_fields() {
        let bytes = fixture_ingress().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["channel"], "keet");
        assert!(v["peer_pubkey"].is_string());
        assert!(v["device_id"].is_string());
        assert!(v["text"].is_string());
        assert!(v["ts_iso"].is_string());
    }

    #[test]
    fn ingress_serde_round_trips() {
        let original = fixture_ingress().with_reply_to("p-7f3a");
        let bytes = original.to_bytes();
        let back: KeetIngressPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, original);
    }

    // ── KeetEgressPayload ───────────────────────────────────────

    #[test]
    fn egress_constructor_fills_canonical_slug() {
        let p = fixture_egress();
        assert_eq!(p.channel, "keet");
    }

    #[test]
    fn egress_message_id_defaults_to_empty() {
        let p = KeetEgressPayload::new("pk", "phone", "t", "ts");
        assert!(p.message_id.is_empty());
    }

    #[test]
    fn egress_with_message_id_sets_field() {
        let p = fixture_egress();
        assert_eq!(p.message_id, "msg-7f3a");
    }

    #[test]
    fn egress_to_bytes_emits_valid_json_with_message_id() {
        let bytes = fixture_egress().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["channel"], "keet");
        assert_eq!(v["message_id"], "msg-7f3a");
    }

    #[test]
    fn egress_serde_round_trips() {
        let original = fixture_egress();
        let bytes = original.to_bytes();
        let back: KeetEgressPayload = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, original);
    }

    // ── Cross-shape parity ──────────────────────────────────────

    #[test]
    fn ingress_and_egress_share_core_field_names() {
        // A future schema-drift between ingress/egress (different
        // field names for the same operator concept) would surface
        // as broken WAL replays. Pin field-name parity.
        let i_bytes = fixture_ingress().to_bytes();
        let e_bytes = fixture_egress().to_bytes();
        let i: serde_json::Value = serde_json::from_slice(&i_bytes).unwrap();
        let e: serde_json::Value = serde_json::from_slice(&e_bytes).unwrap();
        for shared in ["channel", "peer_pubkey", "device_id", "text", "ts_iso"] {
            assert!(i.get(shared).is_some(), "ingress missing {shared}");
            assert!(e.get(shared).is_some(), "egress missing {shared}");
        }
    }
}
