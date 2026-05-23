//! Slack events_api envelope decoder — the parsing layer that the
//! Phase-2 socket-mode WebSocket loop will feed.
//!
//! Slack socket mode delivers messages as JSON envelopes over a WSS
//! connection. Each envelope carries an `envelope_id` (NEOTH ACKs it
//! back to Slack to confirm receipt) plus a `payload.event` block
//! with the actual message data. This module parses both — the
//! transport (tokio-tungstenite) is the only piece left to wire when
//! the operator opts in.
//!
//! Shipping the decoder before the transport means:
//!   - The conversion from Slack JSON → NEOTH `InboundMessage` is
//!     unit-tested against real Slack event fixtures.
//!   - The Phase-2 WS loop becomes a thin glue layer (dial → read →
//!     parse → emit → ACK) rather than a from-scratch port.
//!   - Format drift between Slack API revisions surfaces in the
//!     parser tests, not in production at 3am.

use serde::Deserialize;

use super::{ChannelKind, InboundMessage};

/// Top-level socket-mode envelope. Slack wraps every dispatched event
/// in this shape. Operators ACK by emitting an `acknowledge` message
/// carrying the same `envelope_id`.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct SocketEnvelope {
    /// Envelope category — `events_api` carries normal message events;
    /// `disconnect` / `hello` / `slash_commands` / `interactive` are
    /// other paths the WS loop may receive. We only act on `events_api`
    /// today; the rest become `OtherEnvelope`.
    #[serde(rename = "type")]
    pub envelope_type: String,
    /// Slack's unique id for this delivery. The WS loop ACKs by echoing
    /// this id back so Slack stops re-delivering the same event.
    pub envelope_id: String,
    /// Inner payload — present for `events_api`; absent for `hello`.
    #[serde(default)]
    pub payload: Option<EventsApiPayload>,
}

/// Inside an `events_api` envelope: `event` carries the actual content.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct EventsApiPayload {
    /// Workspace id (`T...`). Useful for multi-team operator deployments.
    #[serde(default)]
    pub team_id: Option<String>,
    /// The actual message/event.
    pub event: SlackEvent,
}

/// One Slack event. We only model the shapes NEOTH operates on; future
/// event types parse through `Other`.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SlackEvent {
    /// A user posted a message in a channel or DM.
    Message {
        /// Channel id (`C...` / `D...` / `G...`).
        channel: String,
        /// User id who sent it (`U...`).
        #[serde(default)]
        user: Option<String>,
        /// Plain-text body. Slack's mrkdwn formatting stays as-is.
        #[serde(default)]
        text: Option<String>,
        /// Slack's message timestamp — a numeric string like
        /// `"1700000000.000100"`. Doubles as the message id.
        ts: String,
        /// `bot_id` is set when a bot wrote the message; NEOTH
        /// typically wants to skip these to avoid echo loops.
        #[serde(default)]
        bot_id: Option<String>,
        /// `subtype` distinguishes joins/leaves/edits from real
        /// messages; absent = normal user message.
        #[serde(default)]
        subtype: Option<String>,
    },
    /// Catch-all for events we don't yet handle (app_mention,
    /// reaction_added, etc). Keeps the parser forward-compatible.
    #[serde(other)]
    Other,
}

/// Outcome of decoding a raw WS frame.
///
/// `InboundMessage` is `Box`ed to keep the enum's stack footprint
/// uniform across variants (clippy::large_enum_variant).
#[derive(Debug)]
pub enum DecodedFrame {
    /// `events_api` envelope carrying an actionable message event.
    Message {
        envelope_id: String,
        inbound: Box<InboundMessage>,
    },
    /// `events_api` envelope but the event is not a user message
    /// (bot echo, subtype like `channel_join`, or unsupported event
    /// type). Caller ACKs but skips dispatch.
    NonMessage { envelope_id: String },
    /// Non-`events_api` envelope (hello / disconnect / slash command).
    /// Caller handles per-envelope-type logic separately.
    OtherEnvelope {
        envelope_type: String,
        envelope_id: String,
    },
    /// Malformed JSON or missing fields. Caller logs + skips ACK so
    /// Slack re-delivers (the WS loop can retry parsing after a
    /// format drift is patched).
    ParseError { reason: String },
}

/// Parse one raw WS-text payload into a `DecodedFrame`. Pure function;
/// no I/O. The Phase-2 WS loop calls this on every received frame.
pub fn decode_frame(raw: &str) -> DecodedFrame {
    let envelope: SocketEnvelope = match serde_json::from_str(raw) {
        Ok(e) => e,
        Err(e) => {
            return DecodedFrame::ParseError {
                reason: format!("envelope parse: {e}"),
            };
        }
    };

    if envelope.envelope_type != "events_api" {
        return DecodedFrame::OtherEnvelope {
            envelope_type: envelope.envelope_type,
            envelope_id: envelope.envelope_id,
        };
    }

    let Some(payload) = envelope.payload else {
        return DecodedFrame::ParseError {
            reason: "events_api envelope missing payload".into(),
        };
    };

    match payload.event {
        SlackEvent::Message {
            channel,
            user,
            text,
            ts,
            bot_id,
            subtype,
        } => {
            // Skip bot-authored messages (echo loops) and message-
            // subtypes that aren't real user posts (joins, edits).
            if bot_id.is_some() || subtype.is_some() {
                return DecodedFrame::NonMessage {
                    envelope_id: envelope.envelope_id,
                };
            }
            let body = text.unwrap_or_default();
            if body.is_empty() {
                return DecodedFrame::NonMessage {
                    envelope_id: envelope.envelope_id,
                };
            }
            // Slack `ts` is a numeric string like "1700000000.000100"
            // (seconds.microseconds). Convert to (u64 secs, i64 ms).
            let (secs, ms) = parse_slack_ts(&ts);
            let inbound = InboundMessage {
                channel: ChannelKind::Slack,
                chat_id: channel,
                thread_id: None,
                sender_id: user.unwrap_or_default(),
                sender_display: None,
                text: Some(body),
                media: None,
                reply_to: None,
                mention_kind: None,
                channel_ts_unix: secs,
                raw_ts_ms: Some(ms),
                human_uuid: None,
            };
            DecodedFrame::Message {
                envelope_id: envelope.envelope_id,
                inbound: Box::new(inbound),
            }
        }
        SlackEvent::Other => DecodedFrame::NonMessage {
            envelope_id: envelope.envelope_id,
        },
    }
}

/// Parse a Slack `ts` string (`"<seconds>.<microseconds>"`) into both
/// a `u64` epoch-seconds value (for `channel_ts_unix`) and an `i64`
/// milliseconds value (for `raw_ts_ms`). Defensive: malformed `ts`
/// strings yield `(0, 0)` rather than panicking — the WAL frame still
/// lands, just without a usable timestamp.
fn parse_slack_ts(ts: &str) -> (u64, i64) {
    let mut parts = ts.splitn(2, '.');
    let secs_str = parts.next().unwrap_or("0");
    let micros_str = parts.next().unwrap_or("0");
    let secs: u64 = secs_str.parse().unwrap_or(0);
    let micros: u64 = micros_str.parse().unwrap_or(0);
    let ms = (secs as i64) * 1000 + (micros / 1000) as i64;
    (secs, ms)
}

/// Build the ACK JSON the WS loop sends back to Slack after handling
/// an envelope. Format pinned by Slack docs: `{"envelope_id": "..."}`.
pub fn build_ack(envelope_id: &str) -> String {
    serde_json::json!({ "envelope_id": envelope_id }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real-shape fixture from Slack's socket-mode docs (trimmed).
    const FIXTURE_MESSAGE: &str = r#"{
        "type": "events_api",
        "envelope_id": "abc-123",
        "payload": {
            "team_id": "T12345",
            "event": {
                "type": "message",
                "channel": "C67890",
                "user": "U11111",
                "text": "hello neoth",
                "ts": "1700000000.000100"
            }
        }
    }"#;

    #[test]
    fn decode_extracts_message_into_inbound() {
        let r = decode_frame(FIXTURE_MESSAGE);
        match r {
            DecodedFrame::Message {
                envelope_id,
                inbound,
            } => {
                assert_eq!(envelope_id, "abc-123");
                assert_eq!(inbound.chat_id, "C67890");
                assert_eq!(inbound.sender_id, "U11111");
                assert_eq!(inbound.text.as_deref(), Some("hello neoth"));
                assert_eq!(inbound.channel_ts_unix, 1_700_000_000);
                assert_eq!(inbound.raw_ts_ms, Some(1_700_000_000_000));
                assert!(matches!(inbound.channel, ChannelKind::Slack));
                assert!(inbound.thread_id.is_none());
                assert!(inbound.media.is_none());
                assert!(inbound.reply_to.is_none());
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn parse_slack_ts_extracts_seconds_and_ms() {
        let (s, ms) = parse_slack_ts("1700000000.000100");
        assert_eq!(s, 1_700_000_000);
        // 0.000100 = 100 microseconds = 0 milliseconds (integer math).
        assert_eq!(ms, 1_700_000_000_000);
        // Non-zero ms portion.
        let (s, ms) = parse_slack_ts("1700000000.123456");
        assert_eq!(s, 1_700_000_000);
        assert_eq!(ms, 1_700_000_000_000 + 123);
    }

    #[test]
    fn parse_slack_ts_defensive_on_garbage() {
        // Malformed input must not panic — pipeline already lost the
        // timestamp, no need to crash the receive loop too.
        assert_eq!(parse_slack_ts("not-a-ts"), (0, 0));
        assert_eq!(parse_slack_ts(""), (0, 0));
        assert_eq!(parse_slack_ts("garbage.also-garbage"), (0, 0));
    }

    #[test]
    fn decode_skips_bot_messages_as_non_message() {
        let raw = r#"{
            "type": "events_api",
            "envelope_id": "bot-1",
            "payload": {
                "event": {
                    "type": "message",
                    "channel": "C1",
                    "user": "U1",
                    "text": "from a bot",
                    "ts": "1700000000.000100",
                    "bot_id": "B12345"
                }
            }
        }"#;
        match decode_frame(raw) {
            DecodedFrame::NonMessage { envelope_id } => assert_eq!(envelope_id, "bot-1"),
            other => panic!("expected NonMessage, got {other:?}"),
        }
    }

    #[test]
    fn decode_skips_subtype_messages_like_channel_join() {
        let raw = r#"{
            "type": "events_api",
            "envelope_id": "join-1",
            "payload": {
                "event": {
                    "type": "message",
                    "channel": "C1",
                    "user": "U1",
                    "ts": "1700000000.000100",
                    "subtype": "channel_join",
                    "text": "<@U1> has joined the channel"
                }
            }
        }"#;
        match decode_frame(raw) {
            DecodedFrame::NonMessage { envelope_id } => assert_eq!(envelope_id, "join-1"),
            other => panic!("expected NonMessage, got {other:?}"),
        }
    }

    #[test]
    fn decode_skips_empty_text_as_non_message() {
        // Slack occasionally delivers messages with empty body (file
        // upload only, etc). NEOTH skips these for v0.1 — the file
        // path lands when the media-handling track ships.
        let raw = r#"{
            "type": "events_api",
            "envelope_id": "empty-1",
            "payload": {
                "event": {
                    "type": "message",
                    "channel": "C1",
                    "user": "U1",
                    "ts": "1700000000.000100"
                }
            }
        }"#;
        match decode_frame(raw) {
            DecodedFrame::NonMessage { .. } => {}
            other => panic!("expected NonMessage, got {other:?}"),
        }
    }

    #[test]
    fn decode_hello_envelope_classified_as_other() {
        let raw = r#"{
            "type": "hello",
            "envelope_id": "hello-1",
            "num_connections": 1
        }"#;
        match decode_frame(raw) {
            DecodedFrame::OtherEnvelope {
                envelope_type,
                envelope_id,
            } => {
                assert_eq!(envelope_type, "hello");
                assert_eq!(envelope_id, "hello-1");
            }
            other => panic!("expected OtherEnvelope, got {other:?}"),
        }
    }

    #[test]
    fn decode_disconnect_envelope_classified_as_other() {
        let raw = r#"{
            "type": "disconnect",
            "envelope_id": "disc-1",
            "reason": "warning"
        }"#;
        match decode_frame(raw) {
            DecodedFrame::OtherEnvelope { envelope_type, .. } => {
                assert_eq!(envelope_type, "disconnect");
            }
            other => panic!("expected OtherEnvelope, got {other:?}"),
        }
    }

    #[test]
    fn decode_unknown_event_type_classified_as_non_message() {
        // app_mention / reaction_added / member_joined_channel etc
        // fall through to the catch-all `Other` variant and are
        // reported as NonMessage so the WS loop still ACKs.
        let raw = r#"{
            "type": "events_api",
            "envelope_id": "mention-1",
            "payload": {
                "event": {
                    "type": "app_mention",
                    "channel": "C1",
                    "user": "U1",
                    "text": "<@U_BOT> hi",
                    "ts": "1700000000.000100"
                }
            }
        }"#;
        match decode_frame(raw) {
            DecodedFrame::NonMessage { envelope_id } => assert_eq!(envelope_id, "mention-1"),
            other => panic!("expected NonMessage, got {other:?}"),
        }
    }

    #[test]
    fn decode_malformed_json_yields_parse_error() {
        match decode_frame("{this is not json}") {
            DecodedFrame::ParseError { reason } => assert!(reason.contains("envelope parse")),
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn decode_events_api_without_payload_yields_parse_error() {
        let raw = r#"{"type": "events_api", "envelope_id": "no-payload-1"}"#;
        match decode_frame(raw) {
            DecodedFrame::ParseError { reason } => assert!(reason.contains("missing payload")),
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn build_ack_emits_required_field() {
        let ack = build_ack("env-42");
        let v: serde_json::Value = serde_json::from_str(&ack).unwrap();
        assert_eq!(v["envelope_id"], "env-42");
    }

    #[test]
    fn build_ack_is_minimal_no_extra_fields() {
        // Slack rejects ACKs with extra fields — keep the wire tight.
        let ack = build_ack("env-1");
        let v: serde_json::Value = serde_json::from_str(&ack).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 1);
    }
}
