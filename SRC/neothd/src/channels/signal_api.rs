//! GOLD-FEAT-10 — Signal protocol layer (typed wire structs + the REST
//! helpers + the `InboundMessage` mapping). The [`super::signal::SignalChannel`]
//! adapter is a thin orchestrator over these pure-ish functions so the
//! parsing + request-building logic is unit-testable without a live
//! `signal-cli` daemon.
//!
//! ## Transport: subprocess-as-service, not in-process libsignal
//!
//! NEOTH never embeds Java / libsignal-client. It talks to a locally
//! running `signal-cli` over its HTTP API (the bbernhard
//! `signal-cli-rest-api` container, or `signal-cli --http` native). The
//! v1 path is the simplest possible: poll `GET /v1/receive/{number}` for
//! inbound + `POST /v2/send` for outbound. A WebSocket/SSE upgrade for
//! lower-latency receive is a documented follow-up (Hermes uses SSE; the
//! poll path is correct, just chattier).
//!
//! ## Inbound wire shape (bbernhard `GET /v1/receive/{number}` → array of)
//!
//! ```json
//! { "envelope": { "source": "+4412345", "sourceName": "Alice",
//!     "timestamp": 1718000000000,
//!     "dataMessage": { "message": "hello",
//!       "groupInfo": { "groupId": "abc==", "type": "DELIVER" } } } }
//! ```
//! Receipts / typing / sync messages arrive as envelopes with NO
//! `dataMessage.message` — they map to `None` (observed + dropped).

use serde::{Deserialize, Serialize};

use super::{ChannelError, ChannelKind, InboundMessage, MessageId};

/// `User-Agent` sent on every signal-cli request (matches the discord
/// adapter's convention for cross-channel grep consistency).
const USER_AGENT: &str = "NEOTH/0.1 (+https://neoth.dev)";

// ── Inbound wire types ───────────────────────────────────────────────────

/// One element of the `GET /v1/receive/{number}` JSON array.
#[derive(Debug, Clone, Deserialize)]
pub struct ReceiveEnvelope {
    pub envelope: Envelope,
    /// The account that received it (our own number). Optional; informational.
    #[serde(default)]
    pub account: Option<String>,
}

/// The signal-cli envelope. Every field is `serde(default)`-tolerant so a
/// single odd envelope (sync message, receipt) can't fail the whole
/// array-parse — `envelope_to_inbound` decides what is actionable.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Envelope {
    /// Sender's E.164 number. Empty for some system envelopes → skipped.
    #[serde(default)]
    pub source: String,
    #[serde(default, rename = "sourceName")]
    pub source_name: Option<String>,
    /// signal-cli millisecond timestamp.
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default, rename = "dataMessage")]
    pub data_message: Option<DataMessage>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DataMessage {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default, rename = "groupInfo")]
    pub group_info: Option<GroupInfo>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GroupInfo {
    #[serde(default, rename = "groupId")]
    pub group_id: Option<String>,
}

// ── Outbound wire types ──────────────────────────────────────────────────

/// `POST /v2/send` body. `recipients` is a single-element vec — a number
/// (`+E.164`) for a DM or a base64 `group.<id>` for a group.
#[derive(Serialize)]
struct SendRequest<'a> {
    message: &'a str,
    number: &'a str,
    recipients: Vec<String>,
}

/// `POST /v2/send` response (`{ "timestamp": 1718... }`). Tolerant: a 2xx
/// with an unexpected body still counts as sent (`MessageId("sent")`).
#[derive(Debug, Clone, Deserialize, Default)]
struct SendResponse {
    #[serde(default)]
    timestamp: Option<i64>,
}

// ── Mapping ──────────────────────────────────────────────────────────────

/// Map a received envelope to a normalized [`InboundMessage`], or `None`
/// when the envelope carries no actionable text (a receipt / typing /
/// sync event, or an empty/source-less envelope). `chat_id` is the group
/// id when the message is a group message, else the sender's number — so a
/// reply routes back to the same conversation.
pub fn envelope_to_inbound(env: &ReceiveEnvelope) -> Option<InboundMessage> {
    let e = &env.envelope;
    if e.source.trim().is_empty() {
        return None;
    }
    let data = e.data_message.as_ref()?;
    let text = data.message.clone()?;
    if text.trim().is_empty() {
        return None;
    }
    let chat_id = data
        .group_info
        .as_ref()
        .and_then(|g| g.group_id.clone())
        .filter(|g| !g.is_empty())
        .unwrap_or_else(|| e.source.clone());
    Some(InboundMessage {
        channel: ChannelKind::Signal,
        chat_id,
        thread_id: None,
        sender_id: e.source.clone(),
        sender_display: e.source_name.clone(),
        text: Some(text),
        media: None,
        reply_to: None,
        message_id: Some(e.timestamp.to_string()),
        edit_unix: None,
        mention_kind: None,
        // signal-cli timestamps are ms since epoch; clamp negatives to 0.
        channel_ts_unix: e.timestamp.max(0) as u64 / 1000,
        raw_ts_ms: Some(e.timestamp),
        human_uuid: None,
    })
}

// ── REST helpers ─────────────────────────────────────────────────────────

/// `POST {base_url}/v2/send` — send `text` from `our_number` to `recipient`
/// (a number or `group.<id>`). Mirrors the discord adapter's status-code
/// → [`ChannelError`] mapping (429 → RateLimited, 401/403 → Auth, other
/// non-2xx → Transport).
pub async fn send_signal_message(
    http: &reqwest::Client,
    base_url: &str,
    our_number: &str,
    recipient: &str,
    text: &str,
) -> std::result::Result<MessageId, ChannelError> {
    let url = format!("{}/v2/send", base_url.trim_end_matches('/'));
    let body = SendRequest {
        message: text,
        number: our_number,
        recipients: vec![recipient.to_string()],
    };
    let response = http
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .json(&body)
        .send()
        .await
        .map_err(|e| ChannelError::Transport(format!("signal POST {url}: {e}")))?;
    map_status(&response, "signal send")?;
    let parsed: SendResponse = response.json().await.unwrap_or_default();
    Ok(MessageId(
        parsed
            .timestamp
            .map(|t| t.to_string())
            .unwrap_or_else(|| "sent".to_string()),
    ))
}

/// `GET {base_url}/v1/receive/{number}` — drain pending inbound envelopes.
/// signal-cli returns them as a JSON array (possibly empty). An empty array
/// is `Ok(vec![])`, not an error.
pub async fn receive_messages(
    http: &reqwest::Client,
    base_url: &str,
    our_number: &str,
) -> std::result::Result<Vec<ReceiveEnvelope>, ChannelError> {
    let url = format!(
        "{}/v1/receive/{}",
        base_url.trim_end_matches('/'),
        our_number
    );
    let response = http
        .get(&url)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .send()
        .await
        .map_err(|e| ChannelError::Transport(format!("signal GET {url}: {e}")))?;
    map_status(&response, "signal receive")?;
    let envelopes: Vec<ReceiveEnvelope> = response
        .json()
        .await
        .map_err(|e| ChannelError::Transport(format!("signal receive parse: {e}")))?;
    Ok(envelopes)
}

/// Shared non-2xx → [`ChannelError`] mapping (consumes nothing on success).
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
            .unwrap_or(1);
        return Err(ChannelError::RateLimited { retry_after_secs });
    }
    if matches!(status.as_u16(), 401 | 403) {
        return Err(ChannelError::Auth(format!(
            "{ctx} HTTP {}",
            status.as_u16()
        )));
    }
    Err(ChannelError::Transport(format!(
        "{ctx} HTTP {}",
        status.as_u16()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_json(body: &str) -> ReceiveEnvelope {
        serde_json::from_str(body).expect("fixture parses")
    }

    #[test]
    fn maps_dm_envelope_to_inbound() {
        let env = envelope_json(
            r#"{"envelope":{"source":"+4412345","sourceName":"Alice",
                "timestamp":1718000000000,
                "dataMessage":{"message":"hello"}}}"#,
        );
        let msg = envelope_to_inbound(&env).expect("dm with text maps");
        assert_eq!(msg.channel, ChannelKind::Signal);
        assert_eq!(msg.sender_id, "+4412345");
        assert_eq!(msg.chat_id, "+4412345", "DM chat_id = sender number");
        assert_eq!(msg.sender_display.as_deref(), Some("Alice"));
        assert_eq!(msg.text.as_deref(), Some("hello"));
        assert_eq!(msg.channel_ts_unix, 1_718_000_000, "ms → s");
        assert_eq!(msg.raw_ts_ms, Some(1718000000000));
    }

    #[test]
    fn group_message_uses_group_id_as_chat_id() {
        let env = envelope_json(
            r#"{"envelope":{"source":"+4499","timestamp":1718000000000,
                "dataMessage":{"message":"hi team",
                  "groupInfo":{"groupId":"GROUP_BASE64==","type":"DELIVER"}}}}"#,
        );
        let msg = envelope_to_inbound(&env).expect("group msg maps");
        assert_eq!(msg.chat_id, "GROUP_BASE64==", "group → chat_id is the group id");
        assert_eq!(msg.sender_id, "+4499", "sender stays the member number");
    }

    #[test]
    fn receipt_envelope_without_datamessage_maps_to_none() {
        let env = envelope_json(r#"{"envelope":{"source":"+4412345","timestamp":1718000000001}}"#);
        assert!(
            envelope_to_inbound(&env).is_none(),
            "a receipt / typing envelope (no dataMessage) is not actionable"
        );
    }

    #[test]
    fn empty_text_and_sourceless_envelopes_map_to_none() {
        let empty_text = envelope_json(
            r#"{"envelope":{"source":"+44","timestamp":1,"dataMessage":{"message":"   "}}}"#,
        );
        assert!(envelope_to_inbound(&empty_text).is_none(), "blank text dropped");
        let no_source = envelope_json(
            r#"{"envelope":{"source":"","timestamp":1,"dataMessage":{"message":"x"}}}"#,
        );
        assert!(envelope_to_inbound(&no_source).is_none(), "source-less envelope dropped");
    }

    #[test]
    fn send_request_serializes_to_signal_cli_shape() {
        let body = SendRequest {
            message: "hi",
            number: "+4400",
            recipients: vec!["+4411".to_string()],
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["message"], "hi");
        assert_eq!(json["number"], "+4400");
        assert_eq!(json["recipients"][0], "+4411");
    }

    #[test]
    fn array_parse_tolerates_mixed_envelope_kinds() {
        // A real /v1/receive payload mixes a data message + a receipt; the
        // array must parse + only the data message becomes an InboundMessage.
        let arr: Vec<ReceiveEnvelope> = serde_json::from_str(
            r#"[
              {"envelope":{"source":"+44","timestamp":2,"dataMessage":{"message":"real"}}},
              {"envelope":{"source":"+44","timestamp":3}}
            ]"#,
        )
        .expect("mixed array parses");
        let inbound: Vec<_> = arr.iter().filter_map(envelope_to_inbound).collect();
        assert_eq!(inbound.len(), 1, "only the data message is actionable");
        assert_eq!(inbound[0].text.as_deref(), Some("real"));
    }
}
