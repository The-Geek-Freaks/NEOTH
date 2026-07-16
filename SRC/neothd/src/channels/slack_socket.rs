//! Slack Socket-Mode WebSocket loop (CDX-06).
//!
//! Slack Socket Mode delivers events over a single WSS connection
//! rather than a public HTTP webhook — the operator doesn't need to
//! expose a port, terminate TLS, or run a reverse proxy. Workflow:
//!
//!   1. Call `apps.connections.open` with the `xapp-` app-level token →
//!      Slack returns a one-shot `wss://wss-primary.slack.com/link/?ticket=...`
//!      URL valid for a short window.
//!   2. Dial that URL via TLS-WebSocket.
//!   3. Read JSON frames; each one is a `SocketEnvelope`.
//!   4. For every `events_api` frame, ACK by sending
//!      `{"envelope_id": "..."}` back on the same socket within ~3s
//!      (otherwise Slack assumes delivery failed + retries).
//!   5. Decode the inner `SlackEvent` into `InboundMessage`; pass to the
//!      operator's `PipelineHandler`.
//!   6. Handle `disconnect` envelopes (re-fetch URL + dial again) and
//!      transport errors (backoff + reconnect).
//!
//! This module ships the dialer + per-frame loop + reconnect harness.
//! The pure-function envelope decoder lives in `slack_events.rs` so
//! tests can exercise it without spinning up a WebSocket.

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, protocol::CloseFrame},
};
use tracing::{debug, info, warn};

use super::slack_api::{post_message, socket_mode_open};
use super::slack_events::{DecodedFrame, decode_frame};
use super::{InboundMessage, OutboundMessage, PipelineHandler};
use crate::secret::SecretString;

/// Outbound dispatch callback. Production wires this to
/// [`super::slack_api::post_message`]; tests inject a recording
/// closure so the receive→reply contract is testable without a live
/// WSS server.
pub(crate) type OutboundSender = Arc<
    dyn Fn(OutboundMessage) -> futures_util::future::BoxFuture<'static, Result<()>> + Send + Sync,
>;

/// Maximum back-off between reconnect attempts. Slack's disconnect
/// signal usually means "you've been idle, please re-dial" — typical
/// reconnect cycle is under a second. We cap at 60s so a sustained
/// outage on Slack's side doesn't pound the API.
const MAX_RECONNECT_BACKOFF_SECS: u64 = 60;

/// Time we give the ACK write before considering the frame lost. Slack
/// retries unacked frames after ~3s; we keep our own write timeout
/// short so a hung socket gets dropped + reconnected promptly.
const ACK_TIMEOUT_SECS: u64 = 2;

/// Run the Slack socket-mode receive loop. Long-running — returns only
/// when the `handler` future drops or a fatal error occurs (auth
/// failure, malformed credentials). Transient WS errors trigger
/// exponential-backoff reconnect.
///
/// Pick #28 (Session 14) — closes the receive→reply loop. The
/// `bot_token` is now required because every pipeline `Ok(Some(out))`
/// gets posted back via `chat.postMessage` instead of being logged
/// + dropped (the prior shape).
pub async fn run_socket_loop(
    app_token: &SecretString,
    bot_token: SecretString,
    allowed_user_id: String,
    gate_writer: crate::wal::writer::WalWriterHandle,
    handler: PipelineHandler,
) -> Result<()> {
    let handler = Arc::new(handler);
    let bot_token = Arc::new(bot_token);
    // Production OutboundSender wires `OutboundMessage` straight into
    // `chat.postMessage`. The intermediate closure keeps the bot_token
    // out of the per-message hot path's signature — the only
    // arguments dispatch_inbound needs are msg + handler + sender.
    let sender: OutboundSender = {
        let bot_token = Arc::clone(&bot_token);
        Arc::new(move |outbound: OutboundMessage| {
            let bot_token = Arc::clone(&bot_token);
            Box::pin(async move {
                let result = post_message(&bot_token, &outbound.recipient_id, &outbound.text)
                    .await
                    .context("slack chat.postMessage")?;
                if !result.ok {
                    anyhow::bail!(
                        "slack chat.postMessage ok=false: {}",
                        result.error.unwrap_or_else(|| "unknown".into())
                    );
                }
                Ok(())
            })
        })
    };
    let mut backoff_secs: u64 = 1;
    loop {
        match run_one_session(
            app_token,
            &allowed_user_id,
            &gate_writer,
            Arc::clone(&handler),
            Arc::clone(&sender),
        )
        .await
        {
            Ok(()) => {
                info!("slack socket-mode session ended cleanly — reconnecting");
                backoff_secs = 1;
            }
            Err(e) => {
                warn!(
                    error = %e,
                    backoff_secs,
                    "slack socket-mode session errored — backing off before reconnect"
                );
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(MAX_RECONNECT_BACKOFF_SECS);
            }
        }
    }
}

/// One full connect → read → ACK loop cycle. Returns Ok when Slack
/// sends a clean `disconnect` envelope (caller reconnects); Err when
/// the transport breaks or credentials are rejected.
async fn run_one_session(
    app_token: &SecretString,
    allowed_user_id: &str,
    gate_writer: &crate::wal::writer::WalWriterHandle,
    handler: Arc<PipelineHandler>,
    sender: OutboundSender,
) -> Result<()> {
    let opened = socket_mode_open(app_token)
        .await
        .context("apps.connections.open")?;
    if !opened.ok {
        anyhow::bail!(
            "apps.connections.open failed: {}",
            opened.error.unwrap_or_else(|| "unknown error".into())
        );
    }
    let url = opened
        .url
        .ok_or_else(|| anyhow::anyhow!("apps.connections.open ok=true but no url returned"))?;
    let dial_url = if url.ends_with("&debug_reconnects=true") || url.contains("?debug_reconnects=")
    {
        url
    } else if url.contains('?') {
        format!("{url}&debug_reconnects=true")
    } else {
        format!("{url}?debug_reconnects=true")
    };
    info!(
        url_host = %dial_url.split('/').nth(2).unwrap_or("?"),
        "slack socket-mode dialing"
    );
    let (ws, _resp) = connect_async(&dial_url)
        .await
        .context("dial slack socket-mode WSS endpoint")?;
    let (mut sink, mut stream) = ws.split();

    while let Some(msg) = stream.next().await {
        let frame = match msg {
            Ok(Message::Text(t)) => t,
            Ok(Message::Binary(b)) => {
                // Slack uses JSON text frames. Binary is unexpected;
                // log + ignore.
                debug!(len = b.len(), "ignoring binary frame from slack");
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
                if let Some(CloseFrame { code, reason }) = frame {
                    info!(code = %code, reason = %reason, "slack socket-mode peer closed");
                } else {
                    info!("slack socket-mode peer closed without frame");
                }
                return Ok(());
            }
            Err(e) => anyhow::bail!("WS read error: {e}"),
        };

        match decode_frame(&frame) {
            DecodedFrame::Message {
                envelope_id,
                inbound,
            } => {
                ack(&mut sink, &envelope_id).await?;
                dispatch_inbound(
                    *inbound,
                    allowed_user_id,
                    Some(gate_writer),
                    Arc::clone(&handler),
                    Arc::clone(&sender),
                )
                .await;
            }
            DecodedFrame::NonMessage { envelope_id } => {
                ack(&mut sink, &envelope_id).await?;
            }
            DecodedFrame::OtherEnvelope {
                envelope_type,
                envelope_id,
            } => {
                // Slack's `disconnect` envelope means "rotate the URL +
                // reconnect promptly". Other envelope types (`hello`,
                // `slash_commands`, `interactive`) get ACKed; per-type
                // dispatch is a follow-up once the operator opts into
                // those event sources.
                ack(&mut sink, &envelope_id).await?;
                if envelope_type == "disconnect" {
                    info!("slack socket-mode received disconnect — reconnecting");
                    return Ok(());
                }
                debug!(envelope_type = %envelope_type, "slack envelope ACKed without dispatch");
            }
            DecodedFrame::ParseError { reason } => {
                // Don't ACK on parse errors — Slack will redeliver. Log
                // so the operator sees the drift.
                warn!(reason = %reason, frame_len = frame.len(), "slack frame parse error");
            }
        }
    }
    Ok(())
}

async fn ack(
    sink: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    envelope_id: &str,
) -> Result<()> {
    let payload = serde_json::json!({ "envelope_id": envelope_id });
    let text = serde_json::to_string(&payload).context("serialize ACK")?;
    tokio::time::timeout(
        Duration::from_secs(ACK_TIMEOUT_SECS),
        sink.send(Message::Text(text)),
    )
    .await
    .context("ACK write timeout")?
    .context("ACK write")?;
    Ok(())
}

/// Run the operator's `PipelineHandler` on one inbound message and, on
/// `Ok(Some(outbound))`, send the reply back to Slack via the
/// supplied `OutboundSender`. Sender failures are logged but never
/// propagated — the receive loop must keep running even if one reply
/// fails to land (transient Slack 5xx, rate-limit, network blip).
///
/// Pick #28 (Session 14) — replaces the prior log-and-drop placeholder
/// that just emitted a debug line. The receive→reply loop is now
/// closed end-to-end.
pub(crate) async fn dispatch_inbound(
    msg: InboundMessage,
    allowed_user_id: &str,
    gate_writer: Option<&crate::wal::writer::WalWriterHandle>,
    handler: Arc<PipelineHandler>,
    sender: OutboundSender,
) {
    if crate::channels::sender_blocked_by_allowlist(
        Some(allowed_user_id),
        &msg.sender_id,
        gate_writer,
        "slack",
    )
    .await
    {
        return;
    }
    let chat_id = msg.chat_id.clone();
    match handler(msg).await {
        Ok(Some(outbound)) => {
            let recipient = outbound.recipient_id.clone();
            match sender(outbound).await {
                Ok(()) => {
                    debug!(recipient = %recipient, "slack reply posted via chat.postMessage");
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        recipient = %recipient,
                        "slack chat.postMessage failed — receive loop continues",
                    );
                }
            }
        }
        Ok(None) => {
            debug!(chat_id = %chat_id, "pipeline returned no outbound");
        }
        Err(e) => {
            warn!(error = %e, chat_id = %chat_id, "slack pipeline handler errored");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::channels::ChannelKind;
    use crate::channels::slack_events::{DecodedFrame, decode_frame};

    /// Sanity-check: the ACK shape Slack expects is a single JSON
    /// object with `envelope_id`. Drift would break ACK silently —
    /// Slack would re-deliver, NEOTH would re-process. Pin the shape.
    #[test]
    fn ack_payload_matches_slack_protocol_shape() {
        let payload = serde_json::json!({ "envelope_id": "Ev123" });
        let text = serde_json::to_string(&payload).unwrap();
        assert_eq!(text, r#"{"envelope_id":"Ev123"}"#);
    }

    /// The decoder + dispatcher contract: a real Slack message frame
    /// produces a `DecodedFrame::Message` with an InboundMessage shaped
    /// for the pipeline. Together with the ACK shape pin above, this
    /// covers the loop's invariants without spinning up a WSS server.
    #[test]
    fn message_frame_decodes_to_inbound_for_dispatch() {
        let raw = r#"{
            "type": "events_api",
            "envelope_id": "Ev42",
            "payload": {
                "team_id": "T1",
                "event": {
                    "type": "message",
                    "channel": "C1",
                    "user": "U1",
                    "text": "hi neoth",
                    "ts": "1700000000.000100"
                }
            }
        }"#;
        match decode_frame(raw) {
            DecodedFrame::Message {
                envelope_id,
                inbound,
            } => {
                assert_eq!(envelope_id, "Ev42");
                assert!(matches!(inbound.channel, ChannelKind::Slack));
                assert_eq!(inbound.chat_id, "C1");
                assert_eq!(inbound.text.as_deref(), Some("hi neoth"));
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    /// Disconnect envelopes must round-trip into a category the loop
    /// can act on (reconnect path). Pin the envelope_type string Slack
    /// uses since the loop branches on it verbatim.
    #[test]
    fn disconnect_envelope_decodes_to_other_envelope_with_type_disconnect() {
        let raw = r#"{
            "type": "disconnect",
            "envelope_id": "Ev9",
            "reason": "warning"
        }"#;
        match decode_frame(raw) {
            DecodedFrame::OtherEnvelope {
                envelope_type,
                envelope_id,
            } => {
                assert_eq!(envelope_type, "disconnect");
                assert_eq!(envelope_id, "Ev9");
            }
            other => panic!("expected OtherEnvelope, got {other:?}"),
        }
    }

    /// Bot-authored messages must NOT reach the pipeline (echo-loop
    /// prevention). Decoded as NonMessage so the loop still ACKs but
    /// doesn't call the handler.
    #[test]
    fn bot_id_message_decodes_to_non_message() {
        let raw = r#"{
            "type": "events_api",
            "envelope_id": "EvBot",
            "payload": {
                "event": {
                    "type": "message",
                    "channel": "C1",
                    "user": "U1",
                    "text": "from a bot",
                    "ts": "1700000000.001",
                    "bot_id": "B777"
                }
            }
        }"#;
        match decode_frame(raw) {
            DecodedFrame::NonMessage { envelope_id } => {
                assert_eq!(envelope_id, "EvBot");
            }
            other => panic!("expected NonMessage, got {other:?}"),
        }
    }

    // ── Pick #28 (Session 14) — receive→reply loop closure ───────────

    use super::{OutboundSender, dispatch_inbound};
    use crate::channels::{InboundMessage, OutboundMessage, PipelineHandler};
    use std::sync::{Arc, Mutex};

    fn build_inbound(text: &str) -> InboundMessage {
        InboundMessage {
            channel: ChannelKind::Slack,
            chat_id: "C123".into(),
            thread_id: None,
            sender_id: "U999".into(),
            sender_display: Some("sam".into()),
            text: Some(text.into()),
            media: None,
            reply_to: None,
            message_id: None,
            edit_unix: None,
            mention_kind: None,
            channel_ts_unix: 1_700_000_000,
            raw_ts_ms: None,
            human_uuid: None,
        }
    }

    /// Test sender that records every outbound call into a shared Vec.
    fn recording_sender() -> (OutboundSender, Arc<Mutex<Vec<OutboundMessage>>>) {
        let calls: Arc<Mutex<Vec<OutboundMessage>>> = Arc::new(Mutex::new(Vec::new()));
        let calls_c = Arc::clone(&calls);
        let sender: OutboundSender = Arc::new(move |outbound: OutboundMessage| {
            let calls_c = Arc::clone(&calls_c);
            Box::pin(async move {
                calls_c.lock().unwrap().push(outbound);
                Ok(())
            })
        });
        (sender, calls)
    }

    #[tokio::test]
    async fn dispatch_inbound_posts_reply_when_handler_returns_some() {
        let (sender, calls) = recording_sender();
        let handler: PipelineHandler = Box::new(|inbound: InboundMessage| {
            Box::pin(async move {
                let text = inbound.text.clone().unwrap_or_default();
                Ok(Some(OutboundMessage {
                    recipient_id: inbound.chat_id.clone(),
                    text: format!("echo: {text}"),
                }))
            })
        });
        let handler = Arc::new(handler);
        dispatch_inbound(build_inbound("hi neoth"), "U999", None, handler, sender).await;
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "exactly one outbound must be sent");
        assert_eq!(calls[0].recipient_id, "C123");
        assert_eq!(calls[0].text, "echo: hi neoth");
    }

    #[tokio::test]
    async fn dispatch_inbound_skips_send_when_handler_returns_none() {
        let (sender, calls) = recording_sender();
        let handler: PipelineHandler =
            Box::new(|_: InboundMessage| Box::pin(async move { Ok(None) }));
        let handler = Arc::new(handler);
        dispatch_inbound(build_inbound("ignored"), "U999", None, handler, sender).await;
        assert!(
            calls.lock().unwrap().is_empty(),
            "None must NOT trigger a post"
        );
    }

    #[tokio::test]
    async fn dispatch_inbound_swallows_handler_error_without_send() {
        let (sender, calls) = recording_sender();
        let handler: PipelineHandler = Box::new(|_: InboundMessage| {
            Box::pin(async move { Err(anyhow::anyhow!("pipeline blew up")) })
        });
        let handler = Arc::new(handler);
        dispatch_inbound(
            build_inbound("trigger error"),
            "U999",
            None,
            handler,
            sender,
        )
        .await;
        // Handler error → no outbound; receive loop continues.
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dispatch_inbound_continues_after_sender_failure() {
        // Sender failure (e.g. Slack 5xx, rate-limit) must NOT
        // propagate — the receive loop has to keep running.
        let failing: OutboundSender = Arc::new(|_: OutboundMessage| {
            Box::pin(async move { Err(anyhow::anyhow!("slack 503")) })
        });
        let handler: PipelineHandler = Box::new(|inbound: InboundMessage| {
            Box::pin(async move {
                Ok(Some(OutboundMessage {
                    recipient_id: inbound.chat_id,
                    text: "reply".into(),
                }))
            })
        });
        let handler = Arc::new(handler);
        // No panic, no propagation — the function returns ().
        dispatch_inbound(build_inbound("ping"), "U999", None, handler, failing).await;
    }

    #[tokio::test]
    async fn dispatch_inbound_blocks_non_allowlisted_user_before_pipeline() {
        let (sender, sends) = recording_sender();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&calls);
        let handler: PipelineHandler = Box::new(move |_: InboundMessage| {
            let calls = Arc::clone(&calls_for_handler);
            Box::pin(async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(None)
            })
        });
        dispatch_inbound(
            build_inbound("blocked"),
            "U111",
            None,
            Arc::new(handler),
            sender,
        )
        .await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(sends.lock().unwrap().is_empty());
    }
}
