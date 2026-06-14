//! GOLD-FEAT-10 — LINE Messaging API protocol layer: the typed inbound wire
//! structs + the `InboundMessage` decoder + the outbound push REST helper. The
//! [`super::line::LineChannel`] adapter and the webhook listener's `handle_line`
//! path are thin orchestrators over these pure-ish functions so the parse +
//! request-build logic is unit-testable without a live LINE channel.
//!
//! ## Transport: webhook in, REST push out (zero extra deps)
//!
//! LINE *pushes* events to the operator's public webhook URL (there is no
//! inbound poll API), so inbound rides the shared [`super::webhook_listener`]
//! (hyper) exactly like WhatsApp: the listener verifies the `X-Line-Signature`
//! (base64 HMAC-SHA256 over the RAW body — see
//! [`super::webhook_verify::verify_line_signature`]), then `decode_line_payload`
//! turns the JSON into `InboundMessage`s. Outbound replies + proactive sends go
//! through the push endpoint (`POST /v2/bot/message/push`) keyed by the source
//! id, so a send works at any time. The per-event `replyToken` (valid ~1 min,
//! single-use) is a documented latency follow-up, not the base path — push is
//! the uniform route for both solicited replies and daemon-initiated proactive.
//!
//! ## Inbound wire shape (`POST <webhook>` body)
//!
//! ```json
//! { "destination": "Uxxxx",
//!   "events": [{ "type": "message", "mode": "active",
//!     "timestamp": 1625665242211,
//!     "source": { "type": "user", "userId": "Uyyyy" },
//!     "replyToken": "abc", "webhookEventId": "01FZ74A0TDDPYRVKNK77XKC3ZR",
//!     "deliveryContext": { "isRedelivery": false },
//!     "message": { "id": "1435...", "type": "text", "text": "hello" } }] }
//! ```
//! Non-message events (follow / join / postback) + non-text messages carry no
//! actionable text → `decode_line_payload` skips them (the listener still 200s
//! so LINE stops re-delivering). The "Verify" button in the LINE console POSTs
//! `events: []` with a valid signature → an empty, ACKed `NoMessages`.

use serde::{Deserialize, Serialize};

use super::{ChannelError, ChannelKind, InboundMessage, MessageId};

/// LINE push endpoint base. The send helper appends `/v2/bot/message/push`.
/// Overridable for tests so the send path can point at a mock server.
pub const LINE_API_BASE: &str = "https://api.line.me";

/// `User-Agent` sent on every LINE request (matches the other adapters'
/// convention for cross-channel grep consistency).
const USER_AGENT: &str = "NEOTH/0.1 (+https://neoth.dev)";

/// LINE caps a single text message at 5000 characters. Longer text is rejected
/// by the API (400) rather than truncated server-side — surfaced as a
/// `Transport` error by [`send_line_push`]. The [`super::formatter`] splits at
/// this boundary on the `send_canonical` path.
pub const LINE_MAX_TEXT_CHARS: usize = 5000;

// ── Inbound wire types ───────────────────────────────────────────────────

/// Top-level webhook body LINE POSTs to the bot's callback URL. Every field is
/// `serde(default)`-tolerant so an unusual event in the array can't fail the
/// whole parse — `decode_line_payload` decides what is actionable.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LineWebhookBody {
    /// The bot's own user id (the channel that received the event). Optional;
    /// informational only.
    #[serde(default)]
    pub destination: String,
    #[serde(default)]
    pub events: Vec<LineEvent>,
}

/// One webhook event. Only `type == "message"` with a `text` message is
/// actionable; everything else (follow, join, postback, sticker, image, …)
/// decodes cleanly but maps to `None`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LineEvent {
    #[serde(default, rename = "type")]
    pub event_type: String,
    /// `"active"` for a real event, `"standby"` in a LINE module multi-bot
    /// setup (a standby event is handled by another module → skipped).
    #[serde(default)]
    pub mode: String,
    /// Event time in **milliseconds** since the unix epoch.
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub source: Option<LineSource>,
    /// Token to call the reply API. Valid ~1 min, single-use. Carried for a
    /// future low-latency reply path; the base adapter sends via push.
    #[serde(default, rename = "replyToken")]
    pub reply_token: Option<String>,
    /// Stable per-delivery id (ULID). Identical across the original event and
    /// any redelivery → the dedup key (NOT `message.id`, which is the content
    /// id and differs per message but is shared on redelivery anyway).
    #[serde(default, rename = "webhookEventId")]
    pub webhook_event_id: Option<String>,
    #[serde(default, rename = "deliveryContext")]
    pub delivery_context: Option<LineDeliveryContext>,
    #[serde(default)]
    pub message: Option<LineMessage>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LineSource {
    /// `"user"`, `"group"`, or `"room"`.
    #[serde(default, rename = "type")]
    pub source_type: String,
    /// The sending user's id. Present for `user` sources; usually present for
    /// `group`/`room` members too (absent only when the member hasn't added
    /// the bot as a friend).
    #[serde(default, rename = "userId")]
    pub user_id: Option<String>,
    #[serde(default, rename = "groupId")]
    pub group_id: Option<String>,
    #[serde(default, rename = "roomId")]
    pub room_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LineDeliveryContext {
    #[serde(default, rename = "isRedelivery")]
    pub is_redelivery: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LineMessage {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "type")]
    pub message_type: String,
    #[serde(default)]
    pub text: Option<String>,
}

/// Outcome of decoding a LINE webhook POST body. Mirrors WhatsApp's
/// [`super::whatsapp_webhook::DecodedWebhook`] so the listener path is uniform.
#[derive(Debug)]
pub enum DecodedLineWebhook {
    /// One entry per actionable text message event.
    Messages(Vec<InboundMessage>),
    /// Parsed fine, but no actionable text (a follow/postback event, a sticker,
    /// or the empty `events` array from the console "Verify" button). Caller
    /// returns 200 so LINE stops re-delivering.
    NoMessages { reason: String },
    /// Malformed JSON. Caller logs + returns 200 (LINE re-delivers 4xx/5xx; a
    /// parse failure after a verified signature is the operator's bug, not a
    /// reason to make LINE hammer the endpoint).
    ParseError { reason: String },
}

// ── Mapping ──────────────────────────────────────────────────────────────

/// Resolve the conversation id a reply should route back to. A group event
/// replies to the `groupId`, a room event to the `roomId`, a DM to the
/// `userId` — so the push `to` lands in the same conversation. A KNOWN source
/// type with its primary id absent returns `None` (the message is dropped, not
/// cross-routed to a different recipient — e.g. a room event with no `roomId`
/// must NOT be answered in the sender's DM). The cross-id fallback applies only
/// to an UNKNOWN/future source type so a spec addition still routes somewhere.
fn chat_id_of(src: &LineSource) -> Option<String> {
    let primary = match src.source_type.as_str() {
        "group" => src.group_id.clone(),
        "room" => src.room_id.clone(),
        "user" => src.user_id.clone(),
        _ => src
            .user_id
            .clone()
            .or_else(|| src.group_id.clone())
            .or_else(|| src.room_id.clone()),
    };
    primary.filter(|s| !s.is_empty())
}

/// Parse one verified webhook POST body into a [`DecodedLineWebhook`]. Pure;
/// no I/O. The listener calls this after the `X-Line-Signature` verify step.
pub fn decode_line_payload(raw: &str) -> DecodedLineWebhook {
    let body: LineWebhookBody = match serde_json::from_str(raw) {
        Ok(b) => b,
        Err(e) => {
            return DecodedLineWebhook::ParseError {
                reason: format!("line webhook parse: {e}"),
            };
        }
    };

    let mut messages = Vec::new();
    for ev in &body.events {
        // Only real (non-standby) message events with text are actionable.
        if ev.event_type != "message" {
            continue;
        }
        if !ev.mode.is_empty() && ev.mode != "active" {
            continue; // standby event — another LINE module owns it
        }
        let Some(msg) = ev.message.as_ref() else {
            continue;
        };
        if msg.message_type != "text" {
            continue; // sticker / image / audio — media track handles later
        }
        let Some(text) = msg.text.as_ref() else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        let Some(src) = ev.source.as_ref() else {
            continue; // sourceless event — cannot route a reply
        };
        let Some(chat_id) = chat_id_of(src) else {
            continue;
        };
        // sender_id is the member's user id when known; in a group where the
        // member hasn't friended the bot it can be absent → fall back to the
        // chat id so downstream identity has a stable, non-empty value.
        let sender_id = src
            .user_id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| chat_id.clone());
        // Dedup key: the webhookEventId is stable across redeliveries. Fall
        // back to the message content id when (improbably) absent.
        let dedup_id = ev
            .webhook_event_id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| msg.id.clone());
        messages.push(InboundMessage {
            channel: ChannelKind::Line,
            chat_id,
            thread_id: None,
            sender_id,
            sender_display: None,
            text: Some(text.clone()),
            media: None,
            reply_to: None,
            message_id: if dedup_id.is_empty() {
                None
            } else {
                Some(dedup_id)
            },
            edit_unix: None,
            mention_kind: None,
            // LINE timestamps are ms since epoch; clamp negatives to 0.
            channel_ts_unix: ev.timestamp.max(0) as u64 / 1000,
            raw_ts_ms: Some(ev.timestamp),
            human_uuid: None,
        });
    }

    if messages.is_empty() {
        return DecodedLineWebhook::NoMessages {
            reason: "no actionable text events (follow/postback/sticker, standby, or empty verify ping)".into(),
        };
    }
    DecodedLineWebhook::Messages(messages)
}

// ── Outbound push types ──────────────────────────────────────────────────

/// `POST /v2/bot/message/push` body. `messages` is a single-element vec — one
/// text bubble per send (LINE allows up to 5 objects per call; the adapter
/// sends one and lets the formatter split path handle multi-chunk replies).
#[derive(Serialize)]
struct PushRequest<'a> {
    to: &'a str,
    messages: Vec<TextMessage<'a>>,
}

#[derive(Serialize)]
struct TextMessage<'a> {
    #[serde(rename = "type")]
    message_type: &'static str,
    text: &'a str,
}

/// `POST /v2/bot/message/push` 200 response (`{ "sentMessages": [{ "id": ".." }] }`).
/// Tolerant: a 2xx with an unexpected body still counts as sent (`MessageId("sent")`).
#[derive(Debug, Clone, Deserialize, Default)]
struct PushResponse {
    #[serde(default, rename = "sentMessages")]
    sent_messages: Vec<SentMessage>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct SentMessage {
    #[serde(default)]
    id: String,
}

// ── REST helper ──────────────────────────────────────────────────────────

/// `POST {base_url}/v2/bot/message/push` — send `text` to `to` (a `userId`,
/// `groupId`, or `roomId`). `access_token` is the long-lived channel access
/// token (Bearer). Mirrors the Signal adapter's status-code → [`ChannelError`]
/// mapping (429 → RateLimited, 401/403 → Auth, other non-2xx → Transport).
pub async fn send_line_push(
    http: &reqwest::Client,
    base_url: &str,
    access_token: &crate::secret::SecretString,
    to: &str,
    text: &str,
) -> std::result::Result<MessageId, ChannelError> {
    // Pre-flight the LINE 5000-char-per-text-message cap: a longer body would be
    // rejected by the API with a 400 that maps to an opaque transport error.
    // Surface a clear, distinct error here instead — protects both the webhook
    // reply path AND the proactive `send_text` path (the formatter only splits
    // on the `send_canonical` path).
    let char_count = text.chars().count();
    if char_count > LINE_MAX_TEXT_CHARS {
        return Err(ChannelError::Transport(format!(
            "line push: text is {char_count} chars, exceeds the {LINE_MAX_TEXT_CHARS}-char per-message limit"
        )));
    }
    let url = format!("{}/v2/bot/message/push", base_url.trim_end_matches('/'));
    let body = PushRequest {
        to,
        messages: vec![TextMessage {
            message_type: "text",
            text,
        }],
    };
    let response = http
        .post(&url)
        .bearer_auth(access_token.expose())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .json(&body)
        .send()
        .await
        .map_err(|e| ChannelError::Transport(format!("line POST {url}: {e}")))?;
    map_status(&response, "line push")?;
    let parsed: PushResponse = response.json().await.unwrap_or_default();
    Ok(MessageId(
        parsed
            .sent_messages
            .into_iter()
            .map(|m| m.id)
            .find(|id| !id.is_empty())
            .unwrap_or_else(|| "sent".to_string()),
    ))
}

/// Shared non-2xx → [`ChannelError`] mapping. LINE does NOT document a
/// `Retry-After` header on 429, so the retry hint defaults to a short backoff.
fn map_status(response: &reqwest::Response, ctx: &str) -> std::result::Result<(), ChannelError> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    if status.as_u16() == 429 {
        let retry_after_secs = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|n| n.ceil() as u64)
            .unwrap_or(2);
        return Err(ChannelError::RateLimited { retry_after_secs });
    }
    if matches!(status.as_u16(), 401 | 403) {
        return Err(ChannelError::Auth(format!("{ctx} HTTP {}", status.as_u16())));
    }
    Err(ChannelError::Transport(format!(
        "{ctx} HTTP {}",
        status.as_u16()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_one(body: &str) -> Vec<InboundMessage> {
        match decode_line_payload(body) {
            DecodedLineWebhook::Messages(m) => m,
            other => panic!("expected Messages, got {other:?}"),
        }
    }

    #[test]
    fn maps_dm_text_event_to_inbound() {
        let msgs = decode_one(
            r#"{"destination":"Ubot","events":[{
                "type":"message","mode":"active","timestamp":1625665242211,
                "source":{"type":"user","userId":"Ualice"},
                "replyToken":"rt","webhookEventId":"01FZ","deliveryContext":{"isRedelivery":false},
                "message":{"id":"14353798921116","type":"text","text":"hello"}}]}"#,
        );
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(m.channel, ChannelKind::Line);
        assert_eq!(m.sender_id, "Ualice");
        assert_eq!(m.chat_id, "Ualice", "DM chat_id = sender user id");
        assert_eq!(m.text.as_deref(), Some("hello"));
        assert_eq!(m.channel_ts_unix, 1_625_665_242, "ms → s");
        assert_eq!(m.raw_ts_ms, Some(1625665242211));
        assert_eq!(
            m.message_id.as_deref(),
            Some("01FZ"),
            "dedup key is the stable webhookEventId, not message.id"
        );
    }

    #[test]
    fn group_event_routes_reply_to_group_id() {
        let msgs = decode_one(
            r#"{"events":[{"type":"message","mode":"active","timestamp":1,
                "source":{"type":"group","groupId":"Cgroup","userId":"Umember"},
                "webhookEventId":"e1","message":{"id":"m1","type":"text","text":"hi team"}}]}"#,
        );
        assert_eq!(msgs[0].chat_id, "Cgroup", "group → chat_id is the group id");
        assert_eq!(msgs[0].sender_id, "Umember", "sender stays the member user id");
    }

    #[test]
    fn room_event_routes_reply_to_room_id() {
        let msgs = decode_one(
            r#"{"events":[{"type":"message","mode":"active","timestamp":1,
                "source":{"type":"room","roomId":"Rroom","userId":"Umember"},
                "webhookEventId":"e2","message":{"id":"m2","type":"text","text":"yo"}}]}"#,
        );
        assert_eq!(msgs[0].chat_id, "Rroom");
        assert_eq!(msgs[0].sender_id, "Umember");
    }

    #[test]
    fn room_event_without_room_id_is_dropped_not_misrouted_to_dm() {
        // A known `room` source with no roomId must NOT be answered in the
        // sender's DM — it is dropped (decode skips it → NoMessages).
        let raw = r#"{"events":[{"type":"message","mode":"active","timestamp":1,
            "source":{"type":"room","userId":"Umember"},
            "webhookEventId":"e","message":{"id":"m","type":"text","text":"hi"}}]}"#;
        assert!(
            matches!(decode_line_payload(raw), DecodedLineWebhook::NoMessages { .. }),
            "a room event with no roomId must be dropped, not cross-routed to the user's DM"
        );
    }

    #[tokio::test]
    async fn over_length_text_is_rejected_before_send() {
        // The 5000-char pre-flight guard surfaces a clear error rather than an
        // opaque LINE 400. A >5000-char string makes send_line_push bail with
        // the length-guard Transport error before any network call (the
        // unroutable base proves the guard fires first — a routing failure would
        // instead report "line POST http://... :").
        let http = reqwest::Client::new();
        let secret = crate::secret::SecretString::from("t");
        let long = "x".repeat(LINE_MAX_TEXT_CHARS + 1);
        let err = send_line_push(&http, "http://127.0.0.1:1", &secret, "Ualice", &long)
            .await
            .unwrap_err();
        match err {
            ChannelError::Transport(m) => assert!(
                m.contains("exceeds the") && m.contains("per-message limit"),
                "expected the length-guard message, got: {m}"
            ),
            other => panic!("expected the length-guard Transport error, got {other:?}"),
        }
    }

    #[test]
    fn group_member_without_user_id_falls_back_to_group_chat_id() {
        // A group member who hasn't friended the bot arrives with no userId.
        let msgs = decode_one(
            r#"{"events":[{"type":"message","mode":"active","timestamp":1,
                "source":{"type":"group","groupId":"Cg"},
                "webhookEventId":"e3","message":{"id":"m3","type":"text","text":"x"}}]}"#,
        );
        assert_eq!(msgs[0].chat_id, "Cg");
        assert_eq!(msgs[0].sender_id, "Cg", "no userId → sender falls back to chat id");
    }

    #[test]
    fn empty_events_verify_ping_maps_to_no_messages() {
        // The LINE console "Verify" button POSTs an empty events array.
        match decode_line_payload(r#"{"destination":"Ubot","events":[]}"#) {
            DecodedLineWebhook::NoMessages { .. } => {}
            other => panic!("expected NoMessages for verify ping, got {other:?}"),
        }
    }

    #[test]
    fn non_text_and_non_message_events_are_skipped() {
        let sticker = r#"{"events":[{"type":"message","mode":"active","timestamp":1,
            "source":{"type":"user","userId":"U"},"webhookEventId":"e",
            "message":{"id":"m","type":"sticker","packageId":"1"}}]}"#;
        let follow = r#"{"events":[{"type":"follow","mode":"active","timestamp":1,
            "source":{"type":"user","userId":"U"},"webhookEventId":"e"}]}"#;
        assert!(matches!(
            decode_line_payload(sticker),
            DecodedLineWebhook::NoMessages { .. }
        ));
        assert!(matches!(
            decode_line_payload(follow),
            DecodedLineWebhook::NoMessages { .. }
        ));
    }

    #[test]
    fn standby_mode_event_is_skipped() {
        let standby = r#"{"events":[{"type":"message","mode":"standby","timestamp":1,
            "source":{"type":"user","userId":"U"},"webhookEventId":"e",
            "message":{"id":"m","type":"text","text":"owned by another module"}}]}"#;
        assert!(matches!(
            decode_line_payload(standby),
            DecodedLineWebhook::NoMessages { .. }
        ));
    }

    #[test]
    fn blank_text_event_is_skipped() {
        let blank = r#"{"events":[{"type":"message","mode":"active","timestamp":1,
            "source":{"type":"user","userId":"U"},"webhookEventId":"e",
            "message":{"id":"m","type":"text","text":"   "}}]}"#;
        assert!(matches!(
            decode_line_payload(blank),
            DecodedLineWebhook::NoMessages { .. }
        ));
    }

    #[test]
    fn malformed_json_yields_parse_error() {
        match decode_line_payload("{not json") {
            DecodedLineWebhook::ParseError { reason } => assert!(reason.contains("parse")),
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn multiple_events_in_one_body_all_decode_in_order() {
        let msgs = decode_one(
            r#"{"events":[
                {"type":"message","mode":"active","timestamp":1,"source":{"type":"user","userId":"U"},
                 "webhookEventId":"a","message":{"id":"1","type":"text","text":"first"}},
                {"type":"follow","mode":"active","timestamp":2,"source":{"type":"user","userId":"U"},
                 "webhookEventId":"b"},
                {"type":"message","mode":"active","timestamp":3,"source":{"type":"user","userId":"U"},
                 "webhookEventId":"c","message":{"id":"2","type":"text","text":"second"}}]}"#,
        );
        assert_eq!(msgs.len(), 2, "only the two text events are actionable");
        assert_eq!(msgs[0].text.as_deref(), Some("first"));
        assert_eq!(msgs[1].text.as_deref(), Some("second"));
    }

    #[test]
    fn push_request_serializes_to_line_shape() {
        let body = PushRequest {
            to: "Ualice",
            messages: vec![TextMessage {
                message_type: "text",
                text: "hi",
            }],
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["to"], "Ualice");
        assert_eq!(json["messages"][0]["type"], "text");
        assert_eq!(json["messages"][0]["text"], "hi");
    }

    #[test]
    fn push_response_extracts_first_sent_message_id() {
        let parsed: PushResponse = serde_json::from_str(
            r#"{"sentMessages":[{"id":"4611...","quoteToken":"q"}]}"#,
        )
        .unwrap();
        assert_eq!(parsed.sent_messages[0].id, "4611...");
    }
}
