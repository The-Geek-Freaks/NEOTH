//! B9 — Google Chat wire types + pure mapping (always compiled; the
//! network adapter in [`super::gchat`] is behind the `gchat-channel`
//! feature and consumes these).
//!
//! Google Chat app events arrive through a **GCP Pub/Sub PULL
//! subscription** (Hermes pattern — no public URL, NEOTH dials out):
//! the Chat app is configured with a Pub/Sub topic, NEOTH pulls
//! `projects/<p>/subscriptions/<s>` and each message's `data` is the
//! base64-encoded Chat event JSON. Only `MESSAGE` events from human
//! senders map to an [`InboundMessage`]; everything else (bot echoes,
//! `ADDED_TO_SPACE`, …) is ack'd + dropped.
//!
//! ## Spoofing characteristics
//!
//! `sender_id` is the Google-asserted resource name (`users/<id>`)
//! from the Chat event — authenticated by Google's infrastructure and
//! delivered over an authenticated Pub/Sub pull, so it is LOW
//! spoof-risk (comparable to iMessage handles, unlike raw IRC nicks).

use serde::Deserialize;

use super::{ChannelKind, InboundMessage};

/// `POST {sub}:pull` response.
#[derive(Debug, Deserialize)]
pub struct PullResponse {
    #[serde(default, rename = "receivedMessages")]
    pub received_messages: Vec<ReceivedMessage>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivedMessage {
    #[serde(rename = "ackId")]
    pub ack_id: String,
    pub message: Option<PubsubMessage>,
}

#[derive(Debug, Deserialize)]
pub struct PubsubMessage {
    /// base64 (standard alphabet) of the Chat event JSON.
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default, rename = "messageId")]
    pub message_id: Option<String>,
}

/// The Chat event payload (subset NEOTH consumes).
#[derive(Debug, Deserialize)]
pub struct ChatEvent {
    #[serde(default, rename = "type")]
    pub event_type: Option<String>,
    #[serde(default)]
    pub message: Option<ChatMessage>,
}

#[derive(Debug, Deserialize)]
pub struct ChatMessage {
    /// Resource name `spaces/<s>/messages/<m>` — WAL correlation id.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub sender: Option<ChatUser>,
    #[serde(default)]
    pub space: Option<ChatSpace>,
    #[serde(default)]
    pub thread: Option<ChatThread>,
}

#[derive(Debug, Deserialize)]
pub struct ChatUser {
    /// `users/<numeric id>` — the Google-asserted sender identity.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    /// `HUMAN` | `BOT`.
    #[serde(default, rename = "type")]
    pub user_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChatSpace {
    /// `spaces/<id>` — the reply destination.
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChatThread {
    #[serde(default)]
    pub name: Option<String>,
}

/// Decode a Pub/Sub `data` blob (standard base64 of Chat event JSON).
/// `None` on bad base64 / bad JSON — the caller acks + skips (a poison
/// message must never wedge the pull loop).
pub fn decode_chat_event(data_b64: &str) -> Option<ChatEvent> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_b64.trim())
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Map a Chat event to the pipeline's [`InboundMessage`]. `None` for
/// anything that must not reach the pipeline: non-`MESSAGE` events,
/// bot senders (loop guard), empty text, or a payload missing the
/// space/sender identifiers the reply + audit paths need.
pub fn event_to_inbound(event: &ChatEvent, ts_unix: u64) -> Option<InboundMessage> {
    if event.event_type.as_deref() != Some("MESSAGE") {
        return None;
    }
    let msg = event.message.as_ref()?;
    let sender = msg.sender.as_ref()?;
    // Loop guard — never feed our own (or any) bot's messages back in.
    if sender.user_type.as_deref() == Some("BOT") {
        return None;
    }
    let sender_id = sender.name.as_deref()?.trim();
    if sender_id.is_empty() {
        return None;
    }
    let space = msg.space.as_ref()?.name.as_deref()?.trim();
    if space.is_empty() {
        return None;
    }
    let text = msg.text.as_deref().map(str::trim).filter(|t| !t.is_empty())?;
    Some(InboundMessage {
        channel: ChannelKind::GoogleChat,
        chat_id: space.to_string(),
        thread_id: msg
            .thread
            .as_ref()
            .and_then(|t| t.name.clone())
            .filter(|s| !s.is_empty()),
        sender_id: sender_id.to_string(),
        sender_display: sender.display_name.clone(),
        text: Some(text.to_string()),
        media: None,
        reply_to: None,
        message_id: msg.name.clone().filter(|s| !s.is_empty()),
        edit_unix: None,
        mention_kind: None,
        channel_ts_unix: ts_unix,
        raw_ts_ms: None,
        human_uuid: None,
    })
}

/// Service-account JWT claims JSON for the Google OAuth2 token grant
/// (`urn:ietf:params:oauth:grant-type:jwt-bearer`). Pure so the shape
/// is unit-testable without the signing dep.
pub fn sa_jwt_claims(client_email: &str, scope: &str, token_uri: &str, iat_unix: u64) -> String {
    serde_json::json!({
        "iss": client_email,
        "scope": scope,
        "aud": token_uri,
        "iat": iat_unix,
        "exp": iat_unix + 3600,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(json: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(json)
    }

    const HUMAN_MSG: &str = r#"{
        "type": "MESSAGE",
        "message": {
            "name": "spaces/AAA/messages/BBB",
            "text": "  hallo neoth  ",
            "sender": {"name": "users/12345", "displayName": "Alex", "type": "HUMAN"},
            "space": {"name": "spaces/AAA"},
            "thread": {"name": "spaces/AAA/threads/TTT"}
        }
    }"#;

    #[test]
    fn human_message_maps_to_inbound() {
        let ev = decode_chat_event(&b64(HUMAN_MSG)).expect("decodes");
        let inbound = event_to_inbound(&ev, 1_700_000_000).expect("maps");
        assert_eq!(inbound.channel, ChannelKind::GoogleChat);
        assert_eq!(inbound.chat_id, "spaces/AAA");
        assert_eq!(inbound.sender_id, "users/12345");
        assert_eq!(inbound.sender_display.as_deref(), Some("Alex"));
        assert_eq!(inbound.text.as_deref(), Some("hallo neoth"), "trimmed");
        assert_eq!(
            inbound.message_id.as_deref(),
            Some("spaces/AAA/messages/BBB")
        );
        assert_eq!(
            inbound.thread_id.as_deref(),
            Some("spaces/AAA/threads/TTT")
        );
    }

    #[test]
    fn bot_sender_and_non_message_events_are_dropped() {
        let bot = HUMAN_MSG.replace("\"HUMAN\"", "\"BOT\"");
        let ev = decode_chat_event(&b64(&bot)).unwrap();
        assert!(event_to_inbound(&ev, 0).is_none(), "bot loop guard");
        let added = HUMAN_MSG.replace("\"MESSAGE\"", "\"ADDED_TO_SPACE\"");
        let ev = decode_chat_event(&b64(&added)).unwrap();
        assert!(event_to_inbound(&ev, 0).is_none(), "non-MESSAGE dropped");
    }

    #[test]
    fn missing_fields_and_poison_payloads_are_none() {
        // bad base64 / bad JSON → None, never a panic
        assert!(decode_chat_event("!!!not-base64!!!").is_none());
        assert!(decode_chat_event(&b64("{not json")).is_none());
        // empty text → None
        let empty = HUMAN_MSG.replace("  hallo neoth  ", "   ");
        let ev = decode_chat_event(&b64(&empty)).unwrap();
        assert!(event_to_inbound(&ev, 0).is_none());
        // no sender → None
        let ev = decode_chat_event(&b64(
            r#"{"type":"MESSAGE","message":{"text":"x","space":{"name":"spaces/A"}}}"#,
        ))
        .unwrap();
        assert!(event_to_inbound(&ev, 0).is_none());
    }

    #[test]
    fn sa_jwt_claims_shape_is_google_token_grant() {
        let c = sa_jwt_claims(
            "bot@proj.iam.gserviceaccount.com",
            "https://www.googleapis.com/auth/pubsub",
            "https://oauth2.googleapis.com/token",
            1_700_000_000,
        );
        let v: serde_json::Value = serde_json::from_str(&c).unwrap();
        assert_eq!(v["iss"], "bot@proj.iam.gserviceaccount.com");
        assert_eq!(v["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(v["exp"].as_u64().unwrap() - v["iat"].as_u64().unwrap(), 3600);
    }
}
