//! Discord Gateway live WSS dial loop.
//!
//! Per `PLAN/PROGRESS.md` post-v0.1 backlog: closes the
//! "Live Discord WSS dial (`connect_async` + heartbeat task
//! + reconnect loop using the now-shipped helpers)" item.
//!
//! ## Architecture
//!
//! Two layers, mirroring `channels::slack_socket`:
//!
//!   - [`run_gateway_loop`] — outer reconnect loop. Owns the
//!     [`ReconnectTracker`] and the session-id state across
//!     reconnects. Terminates only on a terminal close code
//!     (4004 bad token, 4013 invalid intents, …) or operator
//!     SIGTERM.
//!   - [`run_one_session`] — one dial → READY → DISPATCH
//!     loop → close cycle. Spawns the heartbeat task, sends
//!     IDENTIFY or RESUME based on whether we have a session
//!     id from a prior connection, forwards every relevant
//!     DISPATCH frame to the `PipelineHandler`.
//!
//! Pure-function helpers in this file (no IO):
//!
//!   - [`build_identify_frame`] / [`build_resume_frame`] —
//!     frame JSON construction with secret-in-payload pinned
//!     to one site so the SecretString never lands in a
//!     `tracing::*!` macro.
//!   - [`parse_hello_interval`] — extracts the heartbeat
//!     interval from a HELLO `d` payload; returns the
//!     default 41 250 ms when the field is missing (matches
//!     Discord's documented baseline so an early reconnect
//!     keeps heartbeating even if the parser sees a malformed
//!     frame).
//!   - [`parse_session_id_from_ready`] — extracts
//!     `session_id` from a READY dispatch.
//!   - [`parse_message_create`] — extracts the small subset
//!     of MESSAGE_CREATE fields NEOTH cares about
//!     (channel_id, author username, content). Bot messages
//!     are filtered here so the handler does not echo replies
//!     back to itself.
//!
//! ## Security
//!
//!   - `bot_token: SecretString` flows through one site
//!     (`build_identify_frame` / `build_resume_frame`).
//!     `expose()` is called once per frame; the resulting
//!     `String` is sent to the WSS sink + dropped.
//!   - `tracing::*!` macros NEVER receive the raw token —
//!     diagnostic logs receive only the op code + sequence
//!     number + close code.
//!
//! ## What this module does NOT do
//!
//!   - Send a reply back to Discord. The handler returns an
//!     `OutboundMessage` but routing that back to a Discord
//!     channel needs the REST `chat.create-message` path
//!     that already exists in `channels::discord::send_text`.
//!     Wiring that in requires the upstream daemon to give
//!     this loop a `DiscordChannel` reference. Today the
//!     handler's reply is logged + dropped — same shape
//!     `discord::run` had during Phase 1.
//!   - Voice / presence updates / typing indicators. Out of
//!     scope for chat receive.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, protocol::CloseFrame},
};
use tracing::{debug, info, warn};

use crate::channels::discord_gateway::{
    GATEWAY_WSS_URL, GatewayAction, GatewayEnvelope, GatewayPhase, IdentifyProperties,
    ReconnectTracker, build_heartbeat_payload, classify_envelope, current_seq, current_session_id,
    intents as intent_flags, is_terminal_close, opcode, record_seq, record_session_id, reset_seq,
    reset_session_id, should_resume_after_close,
};
use crate::channels::{OutboundMessage, PipelineHandler};
use crate::secret::SecretString;

/// Type-erased outbound reply sender. The gateway loop accepts
/// one when the caller wants pipeline handler replies routed
/// back to Discord; passing `None` keeps the Phase-1 shape
/// where replies are logged + dropped.
///
/// Matches the [`channels::slack_socket::OutboundSender`] shape
/// so a future cross-channel reply orchestrator can hold both
/// behind a common type if it grows.
pub type OutboundSender = Arc<
    dyn Fn(OutboundMessage) -> futures_util::future::BoxFuture<'static, anyhow::Result<()>>
        + Send
        + Sync,
>;

/// Default heartbeat interval when the HELLO payload is
/// malformed. Per Discord docs, real intervals are typically
/// 41 250 ms — pinning a sane fallback keeps the heartbeat
/// task alive long enough to read the next frame, which is
/// usually the corrective frame.
const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 41_250;

/// Minimal subset of a MESSAGE_CREATE payload NEOTH consumes.
/// Discord's full schema is rich (embeds, attachments, mentions,
/// stickers); v0.3 chat receive surfaces only what the pipeline
/// handler needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMessageCreate {
    pub channel_id: String,
    /// Immutable, platform-assigned Discord user id (the "snowflake"). This
    /// is the STABLE identity — used as `sender_id` for rate-limiting,
    /// audit, and capability-lease subject matching. A user can rename their
    /// account freely, so the username must NEVER be used as an identity.
    pub author_id: String,
    /// Mutable display name. Surfaced via `sender_display` for humans only.
    pub author_username: String,
    pub author_is_bot: bool,
    pub content: String,
    pub message_id: String,
}

/// Outer reconnect loop. Returns only on a terminal close code
/// or a fatal serialisation error; transient WS / IO errors
/// trigger an exponential-backoff reconnect via
/// [`ReconnectTracker`].
pub async fn run_gateway_loop(
    bot_token: SecretString,
    intents: u32,
    handler: PipelineHandler,
    sender: Option<OutboundSender>,
) -> Result<()> {
    let handler = Arc::new(handler);
    let mut tracker = ReconnectTracker::new();
    loop {
        match run_one_session(
            &bot_token,
            intents,
            Arc::clone(&handler),
            sender.as_ref().map(Arc::clone),
        )
        .await
        {
            Ok(SessionEnd::CleanClose) => {
                info!("discord gateway session ended cleanly — reconnecting");
                tracker.record_success();
            }
            Ok(SessionEnd::TerminalClose { code }) => {
                tracing::error!(
                    close_code = code,
                    "discord gateway terminal close — operator config required (bad token / invalid intents)"
                );
                return Ok(());
            }
            Err(e) => {
                let delay = tracker.next_delay();
                warn!(
                    error = %e,
                    attempt = tracker.attempts(),
                    delay_secs = delay.as_secs(),
                    "discord gateway session errored — backing off"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// What ended the inner session. The outer loop reads this to
/// decide between "reconnect now" + "bail permanently".
#[derive(Debug)]
enum SessionEnd {
    /// Server closed with a resume-eligible code, or the stream
    /// ended without a frame. Outer loop reconnects.
    CleanClose,
    /// Server closed with a terminal code (4004 / 4013 / …).
    /// Outer loop returns.
    TerminalClose { code: u16 },
}

async fn run_one_session(
    bot_token: &SecretString,
    intents: u32,
    handler: Arc<PipelineHandler>,
    sender: Option<OutboundSender>,
) -> Result<SessionEnd> {
    info!(url = GATEWAY_WSS_URL, "discord gateway dialing");
    log_phase(GatewayPhase::Connecting);

    let (ws, _resp) = connect_async(GATEWAY_WSS_URL)
        .await
        .context("dial discord gateway WSS endpoint")?;
    let (mut sink, mut stream) = ws.split();
    log_phase(GatewayPhase::WaitingForHello);

    // Heartbeat ticker — set after HELLO arrives so we know the
    // operator-supplied interval. Until then, the select arm
    // below pends forever, so only stream.next() fires.
    let mut heartbeat: Option<tokio::time::Interval> = None;
    let mut identified = false;

    loop {
        let frame = tokio::select! {
            biased;
            msg = stream.next() => {
                let Some(msg) = msg else { break; };
                match msg {
                    Ok(Message::Text(t)) => t,
                    Ok(Message::Binary(b)) => {
                        debug!(len = b.len(), "ignoring binary frame from discord");
                        continue;
                    }
                    Ok(Message::Ping(p)) => {
                        if let Err(e) = sink.send(Message::Pong(p)).await {
                            anyhow::bail!("WS pong write failed: {e}");
                        }
                        continue;
                    }
                    Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => continue,
                    Ok(Message::Close(frame)) => {
                        let code = frame
                            .as_ref()
                            .map(|f: &CloseFrame| u16::from(f.code))
                            .unwrap_or(1006);
                        let reason = frame
                            .as_ref()
                            .map(|f| f.reason.to_string())
                            .unwrap_or_default();
                        info!(close_code = code, reason = %reason, "discord gateway peer closed");
                        if is_terminal_close(code) {
                            return Ok(SessionEnd::TerminalClose { code });
                        }
                        if !should_resume_after_close(code) {
                            reset_seq();
                            reset_session_id();
                        }
                        return Ok(SessionEnd::CleanClose);
                    }
                    Err(e) => anyhow::bail!("WS read error: {e}"),
                }
            }
            _ = tick_or_pending(&mut heartbeat) => {
                // Periodic heartbeat send. Discord drops the
                // connection if no heartbeat arrives within the
                // grace window after one heartbeat_interval, so
                // a write failure here is a fatal session
                // condition.
                let payload = build_heartbeat_payload(current_seq());
                if let Err(e) = sink.send(Message::Text(payload)).await {
                    anyhow::bail!("heartbeat send failed: {e}");
                }
                debug!("discord heartbeat sent");
                continue;
            }
        };

        let envelope = match serde_json::from_str::<GatewayEnvelope>(&frame) {
            Ok(env) => env,
            Err(e) => {
                warn!(error = %e, "discord frame missing op field — ignoring");
                continue;
            }
        };

        match classify_envelope(&envelope) {
            GatewayAction::DispatchEvent { seq, event_type } => {
                record_seq(seq);
                // Re-parse to reach the `d` field. The envelope
                // shape ignored it because typed-payload extraction
                // varies per event; the live loop pulls just the
                // events it dispatches.
                let parsed: Value = match serde_json::from_str(&frame) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, event = %event_type, "discord dispatch JSON parse failed");
                        continue;
                    }
                };
                let d = parsed.get("d").cloned().unwrap_or(Value::Null);

                match event_type.as_str() {
                    "READY" => {
                        if let Some(sid) = parse_session_id_from_ready(&d) {
                            record_session_id(sid);
                        }
                        identified = true;
                        log_phase(GatewayPhase::Streaming);
                    }
                    "MESSAGE_CREATE" => {
                        if let Some(parsed_msg) = parse_message_create(&d) {
                            forward_message(
                                &parsed_msg,
                                Arc::clone(&handler),
                                sender.as_ref().map(Arc::clone),
                            )
                            .await;
                        }
                    }
                    _ => {
                        debug!(event = %event_type, "discord dispatch ignored");
                    }
                }
            }
            GatewayAction::SendIdentify => {
                let interval_ms = parse_hello_interval(&parsed_d_from_frame(&frame));
                heartbeat = Some(make_heartbeat_interval(interval_ms));

                // Decide IDENTIFY vs RESUME based on session
                // state from a prior connection.
                let payload = if let Some(sid) = current_session_id() {
                    log_phase(GatewayPhase::Identifying);
                    build_resume_frame(bot_token, &sid, current_seq())
                } else {
                    log_phase(GatewayPhase::Identifying);
                    build_identify_frame(bot_token, intents)
                };
                if let Err(e) = sink.send(Message::Text(payload)).await {
                    anyhow::bail!("IDENTIFY/RESUME write failed: {e}");
                }
            }
            GatewayAction::HeartbeatAcked => {
                debug!("discord heartbeat ack");
            }
            GatewayAction::ReconnectAndResume => {
                info!("discord server requested reconnect — closing for resume");
                return Ok(SessionEnd::CleanClose);
            }
            GatewayAction::InvalidSessionResetAndIdentify => {
                info!("discord invalid session — full reset");
                reset_seq();
                reset_session_id();
                return Ok(SessionEnd::CleanClose);
            }
            GatewayAction::UnknownOpcode { op } => {
                debug!(op = op, "discord unknown opcode — ignoring");
            }
        }
    }

    if identified {
        Ok(SessionEnd::CleanClose)
    } else {
        anyhow::bail!("discord WSS stream ended before identify");
    }
}

fn log_phase(phase: GatewayPhase) {
    info!(phase = phase.as_str(), "discord gateway phase");
}

/// Construct the periodic heartbeat ticker. The first tick
/// fires after one full interval — Discord's spec actually
/// wants a jittered first-heartbeat in [0, heartbeat_interval),
/// but a single-full-interval delay still respects the
/// server's grace window + keeps the code straightforward.
/// Operator-tunable jitter can land later if a real Gateway
/// disconnect proves the spec-strict form matters.
fn make_heartbeat_interval(interval_ms: u64) -> tokio::time::Interval {
    let mut int = tokio::time::interval(Duration::from_millis(interval_ms));
    // Skip the immediate tick that tokio::time::interval fires
    // at construction — we don't want a heartbeat before
    // IDENTIFY/RESUME.
    int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires after `interval_ms`; that is the
    // first heartbeat we send.
    int.reset();
    int
}

/// Await the next heartbeat tick, or pend forever when no
/// interval has been installed yet (pre-HELLO). The select
/// arm in `run_one_session` polls this so a missing interval
/// simply never fires that branch.
async fn tick_or_pending(interval: &mut Option<tokio::time::Interval>) {
    match interval.as_mut() {
        Some(int) => {
            int.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

fn parsed_d_from_frame(frame: &str) -> Value {
    serde_json::from_str::<Value>(frame)
        .ok()
        .and_then(|v| v.get("d").cloned())
        .unwrap_or(Value::Null)
}

async fn forward_message(
    msg: &ParsedMessageCreate,
    handler: Arc<PipelineHandler>,
    sender: Option<OutboundSender>,
) {
    if msg.author_is_bot {
        // Don't echo bot messages back into the pipeline.
        return;
    }
    let inbound = crate::channels::InboundMessage {
        channel: crate::channels::ChannelKind::Discord,
        chat_id: msg.channel_id.clone(),
        thread_id: None,
        sender_id: msg.author_id.clone(),
        sender_display: Some(msg.author_username.clone()),
        text: Some(msg.content.clone()),
        media: None,
        reply_to: None,
        message_id: Some(msg.message_id.clone()),
        edit_unix: None,
        mention_kind: None,
        channel_ts_unix: now_unix_secs(),
        raw_ts_ms: None,
        human_uuid: None,
    };
    match handler(inbound).await {
        Ok(Some(out)) => match sender {
            Some(sender) => {
                let chars = out.text.len();
                if let Err(e) = sender(out).await {
                    warn!(
                        error = %e,
                        channel_id = %msg.channel_id,
                        "discord reply send failed"
                    );
                } else {
                    debug!(
                        reply_chars = chars,
                        channel_id = %msg.channel_id,
                        "discord reply sent"
                    );
                }
            }
            None => {
                info!(
                    reply_chars = out.text.len(),
                    channel_id = %msg.channel_id,
                    "discord handler produced reply (no sender wired — dropped)"
                );
            }
        },
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "discord pipeline handler failed");
        }
    }
}

fn now_unix_secs() -> u64 {
    crate::time::now_unix_secs()
}

// ── Pure-function helpers (testable) ──────────────────────────────────────

/// Build an IDENTIFY frame. The bot token surfaces here once
/// per session; the resulting String is sent to the sink + the
/// SecretString is never stored or logged.
pub fn build_identify_frame(bot_token: &SecretString, intents: u32) -> String {
    let props = IdentifyProperties::neoth_default();
    // Build the d object manually to keep the secret in one
    // expose() site. serde_json::to_string with serde derive
    // would also work, but the manual form makes the
    // expose-and-immediately-format pattern obvious to reviewers.
    let token = bot_token.expose();
    let body = serde_json::json!({
        "op": opcode::IDENTIFY,
        "d": {
            "token": token,
            "intents": intents,
            "properties": {
                "$os": props.os,
                "$browser": props.browser,
                "$device": props.device,
            }
        }
    });
    serde_json::to_string(&body).expect("Discord IDENTIFY frame is infallible JSON")
}

/// Build a RESUME frame. Same security shape as
/// [`build_identify_frame`] — token expose() lives at exactly
/// one site.
pub fn build_resume_frame(bot_token: &SecretString, session_id: &str, seq: i64) -> String {
    let token = bot_token.expose();
    let seq_value: Value = if seq < 0 {
        Value::Null
    } else {
        Value::from(seq)
    };
    let body = serde_json::json!({
        "op": opcode::RESUME,
        "d": {
            "token": token,
            "session_id": session_id,
            "seq": seq_value,
        }
    });
    serde_json::to_string(&body).expect("Discord RESUME frame is infallible JSON")
}

/// Extract the `heartbeat_interval` from a HELLO `d` payload.
/// Falls back to [`DEFAULT_HEARTBEAT_INTERVAL_MS`] on malformed
/// input so a broken HELLO does not kill the connection.
pub fn parse_hello_interval(d: &Value) -> u64 {
    d.get("heartbeat_interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_MS)
}

/// Extract `session_id` from a READY dispatch `d` payload.
pub fn parse_session_id_from_ready(d: &Value) -> Option<String> {
    d.get("session_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Extract the MESSAGE_CREATE subset NEOTH consumes. Returns
/// `None` for malformed payloads or messages with no content.
pub fn parse_message_create(d: &Value) -> Option<ParsedMessageCreate> {
    let channel_id = d.get("channel_id")?.as_str()?.to_string();
    let message_id = d.get("id")?.as_str()?.to_string();
    let author = d.get("author")?;
    // The numeric snowflake is the canonical identity. A message with no
    // author id is malformed — reject it rather than fall back to a
    // spoofable display name (would let a renamed account match a lease).
    let author_id = author.get("id")?.as_str()?.to_string();
    let author_username = author.get("username")?.as_str().unwrap_or("").to_string();
    let author_is_bot = author.get("bot").and_then(|v| v.as_bool()).unwrap_or(false);
    let content = d
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if content.is_empty() {
        return None;
    }
    Some(ParsedMessageCreate {
        channel_id,
        author_id,
        author_username,
        author_is_bot,
        content,
        message_id,
    })
}

/// Default intents NEOTH requests when no per-channel override
/// is configured. Mirrors `discord_gateway::intents::NEOTH_DEFAULT`.
pub const fn default_intents() -> u32 {
    intent_flags::NEOTH_DEFAULT
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn token() -> SecretString {
        SecretString::new("bot-token-secret-do-not-log".to_string())
    }

    #[test]
    fn build_identify_frame_carries_token_intents_and_properties() {
        let frame = build_identify_frame(&token(), intent_flags::NEOTH_DEFAULT);
        let parsed: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(parsed["op"], opcode::IDENTIFY);
        assert_eq!(parsed["d"]["token"], "bot-token-secret-do-not-log");
        assert_eq!(
            parsed["d"]["intents"].as_u64().unwrap() as u32,
            intent_flags::NEOTH_DEFAULT
        );
        assert!(
            parsed["d"]["properties"]["$browser"]
                .as_str()
                .unwrap()
                .contains("neoth")
        );
    }

    #[test]
    fn build_resume_frame_carries_token_session_id_and_seq() {
        let frame = build_resume_frame(&token(), "S-42", 17);
        let parsed: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(parsed["op"], opcode::RESUME);
        assert_eq!(parsed["d"]["session_id"], "S-42");
        assert_eq!(parsed["d"]["seq"], 17);
    }

    #[test]
    fn build_resume_frame_nulls_negative_seq() {
        // seq < 0 means we never saw a DISPATCH; per Discord
        // docs the resume MUST send `null` so the server knows
        // to replay from the start.
        let frame = build_resume_frame(&token(), "S-1", -1);
        let parsed: Value = serde_json::from_str(&frame).unwrap();
        assert!(parsed["d"]["seq"].is_null());
    }

    #[test]
    fn parse_hello_interval_extracts_value() {
        let d = json!({ "heartbeat_interval": 12_500 });
        assert_eq!(parse_hello_interval(&d), 12_500);
    }

    #[test]
    fn parse_hello_interval_falls_back_on_missing_field() {
        let d = json!({});
        assert_eq!(parse_hello_interval(&d), DEFAULT_HEARTBEAT_INTERVAL_MS);
    }

    #[test]
    fn parse_hello_interval_falls_back_on_non_numeric() {
        let d = json!({ "heartbeat_interval": "fast" });
        assert_eq!(parse_hello_interval(&d), DEFAULT_HEARTBEAT_INTERVAL_MS);
    }

    #[test]
    fn parse_session_id_from_ready_extracts() {
        let d = json!({ "session_id": "abc-123", "user": {} });
        assert_eq!(parse_session_id_from_ready(&d), Some("abc-123".to_string()));
    }

    #[test]
    fn parse_session_id_returns_none_when_missing() {
        let d = json!({});
        assert_eq!(parse_session_id_from_ready(&d), None);
    }

    #[test]
    fn parse_message_create_extracts_canonical_subset() {
        let d = json!({
            "id": "M1",
            "channel_id": "C1",
            "content": "hello",
            "author": { "id": "1234567890", "username": "alice", "bot": false }
        });
        let parsed = parse_message_create(&d).unwrap();
        assert_eq!(parsed.channel_id, "C1");
        // sender identity is the immutable snowflake, NOT the username
        assert_eq!(parsed.author_id, "1234567890");
        assert_eq!(parsed.author_username, "alice");
        assert_eq!(parsed.content, "hello");
        assert!(!parsed.author_is_bot);
        assert_eq!(parsed.message_id, "M1");
    }

    #[test]
    fn parse_message_create_rejects_author_without_id() {
        // A spoofable display name must never become the identity: a
        // message whose author carries no snowflake id is rejected outright
        // rather than falling back to the username.
        let d = json!({
            "id": "M9",
            "channel_id": "C1",
            "content": "hi",
            "author": { "username": "alice" }
        });
        assert!(
            parse_message_create(&d).is_none(),
            "missing author.id must be rejected, not username-fallback"
        );
    }

    #[test]
    fn parse_message_create_flags_bot_messages() {
        let d = json!({
            "id": "M2",
            "channel_id": "C1",
            "content": "ping",
            "author": { "id": "999", "username": "neoth-bot", "bot": true }
        });
        let parsed = parse_message_create(&d).unwrap();
        assert!(parsed.author_is_bot);
    }

    #[test]
    fn parse_message_create_returns_none_for_empty_content() {
        // Discord delivers MESSAGE_CREATE for system events
        // (channel joins) with empty content. NEOTH skips
        // those — pipeline handlers expect non-empty text.
        let d = json!({
            "id": "M3",
            "channel_id": "C1",
            "content": "",
            "author": { "id": "1234567890", "username": "alice" }
        });
        assert!(parse_message_create(&d).is_none());
    }

    #[test]
    fn parse_message_create_returns_none_for_malformed_input() {
        let d = json!({ "channel_id": "C1" });
        assert!(parse_message_create(&d).is_none());
    }

    #[test]
    fn default_intents_match_gateway_module_default() {
        assert_eq!(default_intents(), intent_flags::NEOTH_DEFAULT);
    }
}
