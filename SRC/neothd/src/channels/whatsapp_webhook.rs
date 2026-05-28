//! WhatsApp Cloud API webhook payload decoder — the parsing layer that
//! the Phase-2 HTTP server will feed.
//!
//! Meta POSTs webhook events as nested JSON to the operator's configured
//! callback URL. The envelope shape:
//!
//! ```json
//! {
//!   "object": "whatsapp_business_account",
//!   "entry": [{
//!     "id": "<WABA_ID>",
//!     "changes": [{
//!       "field": "messages",
//!       "value": {
//!         "metadata": { "phone_number_id": "<PNID>", ... },
//!         "contacts": [{ "profile": {"name": "Alex"}, "wa_id": "49151..." }],
//!         "messages": [{
//!           "from": "49151...",
//!           "id": "wamid....",
//!           "timestamp": "1700000000",
//!           "type": "text",
//!           "text": { "body": "hello" }
//!         }]
//!       }
//!     }]
//!   }]
//! }
//! ```
//!
//! This module parses every text message in the payload into
//! `InboundMessage`s. Non-message event types (delivery status,
//! template reply, button click) flow through `Other` so the
//! webhook handler still ACKs them and Meta stops re-delivering.
//!
//! The HTTP verify-token round-trip + the listener itself are
//! deferred to Phase 2 — once hyper lands the route becomes:
//! `POST /webhook` → `verify_signature` → `decode_payload` →
//! dispatch each `InboundMessage` to the `PipelineHandler`.

use serde::Deserialize;

use super::{ChannelKind, InboundMessage};

/// Top-level webhook envelope. Meta wraps every dispatched event in
/// `object: "whatsapp_business_account"` plus an `entry` array. v0.1
/// handles the first entry only — multi-WABA support arrives with the
/// real listener.
#[derive(Debug, Deserialize)]
pub struct WebhookEnvelope {
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub entry: Vec<EntryNode>,
}

#[derive(Debug, Deserialize)]
pub struct EntryNode {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub changes: Vec<ChangeNode>,
}

#[derive(Debug, Deserialize)]
pub struct ChangeNode {
    #[serde(default)]
    pub field: String,
    #[serde(default)]
    pub value: ChangeValue,
}

#[derive(Debug, Deserialize, Default)]
pub struct ChangeValue {
    #[serde(default)]
    pub metadata: Option<Metadata>,
    #[serde(default)]
    pub contacts: Vec<ContactProfile>,
    #[serde(default)]
    pub messages: Vec<TextMessage>,
}

#[derive(Debug, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub phone_number_id: String,
    #[serde(default)]
    pub display_phone_number: String,
}

#[derive(Debug, Deserialize)]
pub struct ContactProfile {
    #[serde(default)]
    pub wa_id: String,
    #[serde(default)]
    pub profile: ProfileNode,
}

#[derive(Debug, Deserialize, Default)]
pub struct ProfileNode {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct TextMessage {
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub timestamp: String,
    /// Message type — `"text"`, `"image"`, `"audio"`, `"button"`,
    /// `"interactive"`, etc. We currently process only `"text"`; other
    /// types yield `Inbound::Skipped`.
    #[serde(rename = "type", default)]
    pub msg_type: String,
    #[serde(default)]
    pub text: Option<TextBody>,
}

#[derive(Debug, Deserialize)]
pub struct TextBody {
    #[serde(default)]
    pub body: String,
}

/// Outcome of decoding a webhook POST body.
#[derive(Debug)]
pub enum DecodedWebhook {
    /// Decoded successfully — one entry per processable text message.
    Messages(Vec<InboundMessage>),
    /// Decoded successfully but no user-message content (delivery
    /// status update, non-text media we don't yet handle). Caller
    /// still returns HTTP 200 so Meta stops re-delivering.
    NoMessages { reason: String },
    /// Malformed JSON or unrecognised envelope shape. Caller logs
    /// + returns 400 so Meta surfaces the operator's misconfiguration.
    ParseError { reason: String },
}

/// Parse one webhook POST body into a `DecodedWebhook`. Pure function;
/// no I/O. The Phase-2 HTTP listener calls this on every received
/// request after the X-Hub-Signature-256 verify step.
pub fn decode_payload(raw: &str) -> DecodedWebhook {
    let envelope: WebhookEnvelope = match serde_json::from_str(raw) {
        Ok(e) => e,
        Err(e) => {
            return DecodedWebhook::ParseError {
                reason: format!("envelope parse: {e}"),
            };
        }
    };

    if envelope.object != "whatsapp_business_account" {
        return DecodedWebhook::ParseError {
            reason: format!(
                "unexpected envelope.object `{}` (expected `whatsapp_business_account`)",
                envelope.object,
            ),
        };
    }

    let mut messages = Vec::new();
    for entry in &envelope.entry {
        for change in &entry.changes {
            // Build a lookup from wa_id → display name so we can
            // populate `sender_display` on outbound InboundMessage.
            let mut name_lookup: std::collections::HashMap<&str, &str> =
                std::collections::HashMap::new();
            for c in &change.value.contacts {
                if !c.wa_id.is_empty() && !c.profile.name.is_empty() {
                    name_lookup.insert(c.wa_id.as_str(), c.profile.name.as_str());
                }
            }
            for m in &change.value.messages {
                if m.msg_type != "text" {
                    continue; // Skipped — media/interactive in a later iteration.
                }
                let Some(text) = &m.text else { continue };
                if text.body.is_empty() {
                    continue;
                }
                let ts_unix: u64 = m.timestamp.parse().unwrap_or(0);
                let display = name_lookup.get(m.from.as_str()).map(|s| s.to_string());
                messages.push(InboundMessage {
                    channel: ChannelKind::WhatsAppBusiness,
                    chat_id: m.from.clone(),
                    thread_id: None,
                    sender_id: m.from.clone(),
                    sender_display: display,
                    text: Some(text.body.clone()),
                    media: None,
                    reply_to: None,
                    message_id: None,
                    edit_unix: None,
                    mention_kind: None,
                    channel_ts_unix: ts_unix,
                    raw_ts_ms: Some((ts_unix as i64) * 1000),
                    human_uuid: None,
                });
            }
        }
    }

    if messages.is_empty() {
        return DecodedWebhook::NoMessages {
            reason: "no processable text messages (status update or non-text content)".into(),
        };
    }
    DecodedWebhook::Messages(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real Meta payload (trimmed) — one text message from a known user.
    const FIXTURE_TEXT: &str = r#"{
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "WABA_ID",
            "changes": [{
                "field": "messages",
                "value": {
                    "metadata": {
                        "phone_number_id": "PN_ID",
                        "display_phone_number": "+4915112345678"
                    },
                    "contacts": [{
                        "profile": {"name": "Alex"},
                        "wa_id": "4915112345678"
                    }],
                    "messages": [{
                        "from": "4915112345678",
                        "id": "wamid.HBgL",
                        "timestamp": "1700000000",
                        "type": "text",
                        "text": {"body": "hello neoth"}
                    }]
                }
            }]
        }]
    }"#;

    #[test]
    fn decode_extracts_text_message_into_inbound() {
        match decode_payload(FIXTURE_TEXT) {
            DecodedWebhook::Messages(msgs) => {
                assert_eq!(msgs.len(), 1);
                let m = &msgs[0];
                assert!(matches!(m.channel, ChannelKind::WhatsAppBusiness));
                assert_eq!(m.chat_id, "4915112345678");
                assert_eq!(m.sender_id, "4915112345678");
                assert_eq!(m.sender_display.as_deref(), Some("Alex"));
                assert_eq!(m.text.as_deref(), Some("hello neoth"));
                assert_eq!(m.channel_ts_unix, 1_700_000_000);
                assert_eq!(m.raw_ts_ms, Some(1_700_000_000_000));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn decode_skips_non_text_message_types() {
        // Image messages currently aren't processed — the media track
        // ships them later. Webhook still ACKed via NoMessages.
        let raw = r#"{
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "W",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messages": [{
                            "from": "4915",
                            "id": "wamid.IMG",
                            "timestamp": "1700",
                            "type": "image",
                            "image": {"id": "media-1"}
                        }]
                    }
                }]
            }]
        }"#;
        match decode_payload(raw) {
            DecodedWebhook::NoMessages { reason } => {
                assert!(reason.contains("no processable"));
            }
            other => panic!("expected NoMessages, got {other:?}"),
        }
    }

    #[test]
    fn decode_skips_status_only_payloads() {
        // Meta sends delivery-status updates with the same envelope
        // but no `messages` array. Decoder yields NoMessages so the
        // webhook returns 200 + Meta stops re-delivering.
        let raw = r#"{
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "W",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "statuses": [{
                            "id": "wamid.X",
                            "status": "delivered",
                            "timestamp": "1700",
                            "recipient_id": "4915"
                        }]
                    }
                }]
            }]
        }"#;
        match decode_payload(raw) {
            DecodedWebhook::NoMessages { .. } => {}
            other => panic!("expected NoMessages, got {other:?}"),
        }
    }

    #[test]
    fn decode_handles_multiple_messages_in_one_payload() {
        // Meta occasionally batches messages from the same chat in a
        // single webhook delivery. The decoder must surface all of
        // them in order.
        let raw = r#"{
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "W",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messages": [
                            {"from": "1", "id": "a", "timestamp": "1700", "type": "text",
                             "text": {"body": "first"}},
                            {"from": "1", "id": "b", "timestamp": "1701", "type": "text",
                             "text": {"body": "second"}}
                        ]
                    }
                }]
            }]
        }"#;
        match decode_payload(raw) {
            DecodedWebhook::Messages(m) => {
                assert_eq!(m.len(), 2);
                assert_eq!(m[0].text.as_deref(), Some("first"));
                assert_eq!(m[1].text.as_deref(), Some("second"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_wrong_envelope_object() {
        // A Page webhook (object="page") landing on our endpoint MUST
        // be rejected — we only handle whatsapp_business_account.
        let raw = r#"{"object": "page", "entry": []}"#;
        match decode_payload(raw) {
            DecodedWebhook::ParseError { reason } => {
                assert!(reason.contains("whatsapp_business_account"));
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn decode_malformed_json_yields_parse_error() {
        match decode_payload("{not json") {
            DecodedWebhook::ParseError { reason } => assert!(reason.contains("envelope parse")),
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn decode_empty_text_body_skipped() {
        let raw = r#"{
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "W",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messages": [{
                            "from": "1", "id": "a", "timestamp": "1700",
                            "type": "text", "text": {"body": ""}
                        }]
                    }
                }]
            }]
        }"#;
        match decode_payload(raw) {
            DecodedWebhook::NoMessages { .. } => {}
            other => panic!("expected NoMessages, got {other:?}"),
        }
    }

    #[test]
    fn decode_populates_sender_display_from_contacts() {
        // Operator-facing detail: the `contacts` block carries human
        // names. Match by wa_id + populate sender_display so log
        // messages show "Alex" rather than just the phone number.
        match decode_payload(FIXTURE_TEXT) {
            DecodedWebhook::Messages(m) => {
                assert_eq!(m[0].sender_display.as_deref(), Some("Alex"));
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn decode_missing_contact_name_leaves_display_none() {
        // No `contacts` block → sender_display stays None. The pipeline
        // works without it; it's a convenience for log readability.
        let raw = r#"{
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "W",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messages": [{
                            "from": "1", "id": "a", "timestamp": "1700",
                            "type": "text", "text": {"body": "hi"}
                        }]
                    }
                }]
            }]
        }"#;
        match decode_payload(raw) {
            DecodedWebhook::Messages(m) => {
                assert!(m[0].sender_display.is_none());
            }
            other => panic!("expected Messages, got {other:?}"),
        }
    }
}
