//! GOLD-FEAT-10 — Mattermost channel adapter (WebSocket receive + REST send).
//!
//! Mattermost is self-hosted, Slack-style team chat. Like Slack socket-mode (and
//! unlike the webhook channels) NEOTH dials OUT to the server's WebSocket API
//! (`/api/v4/websocket`) — no public URL, no reverse proxy. The adapter reuses
//! the always-present `tokio-tungstenite` + `reqwest` deps, so it carries no new
//! crate and needs no feature gate (always compiled, like Slack/Signal/LINE).
//!
//! Flow:
//!   1. `GET /api/v4/users/me` once → our own user id (to drop self-echo).
//!   2. Dial `wss://…/api/v4/websocket`, send the `authentication_challenge`
//!      frame (Mattermost streams nothing until it sees a valid token).
//!   3. Read frames; decode each `posted` event ([`mattermost_api::decode_frame`])
//!      into an [`InboundMessage`] + run it through the pipeline `handler`.
//!   4. Post any reply back via `POST /api/v4/posts`.
//!   5. Reconnect with exponential backoff on transport error / clean close.
//!
//! The pure frame decode + URL/auth builders live in [`super::mattermost_api`]
//! so they're unit-testable without a live server; the receive→reply dispatch
//! reuses the channel-agnostic [`super::slack_socket::dispatch_inbound`].

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{info, warn};

use super::mattermost_api::{
    MmFrame, auth_challenge_frame, decode_frame, fetch_me_user_id, mm_ws_url, send_post,
};
use super::slack_socket::{OutboundSender, dispatch_inbound};
use super::{Channel, ChannelError, MessageId, OutboundMessage, PipelineHandler};
use crate::secret::SecretString;

/// Cap on reconnect backoff. A Mattermost WS drop is usually a server restart or
/// a network blip; cap at 60s so a sustained outage doesn't pound the server.
const MAX_RECONNECT_BACKOFF_SECS: u64 = 60;

/// Mattermost adapter. Holds the server base URL (`https://mm.example.com`) + a
/// personal-access / bot token. Construction does no I/O.
pub struct MattermostChannel {
    base_url: String,
    token: SecretString,
}

impl MattermostChannel {
    pub fn new(base_url: impl Into<String>, token: SecretString) -> Self {
        Self {
            base_url: base_url.into(),
            token,
        }
    }
}

#[async_trait]
impl Channel for MattermostChannel {
    fn name(&self) -> &'static str {
        "mattermost"
    }

    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        // Identify ourselves once so the receive loop can drop our own echo. A
        // failure here means bad creds / unreachable server — fatal, surfaced to
        // the spawn harness rather than spinning a doomed reconnect loop.
        let bot_user_id = fetch_me_user_id(&self.base_url, &self.token)
            .await
            .context("mattermost identify (GET /users/me)")?;
        let handler = Arc::new(handler);
        // Outbound dispatch wires `OutboundMessage` straight into POST /posts.
        let sender: OutboundSender = {
            let base = self.base_url.clone();
            let token = self.token.clone();
            Arc::new(move |outbound: OutboundMessage| {
                let base = base.clone();
                let token = token.clone();
                Box::pin(async move {
                    send_post(&base, &token, &outbound.recipient_id, &outbound.text)
                        .await
                        .map(|_id| ())
                        .map_err(|e| anyhow::anyhow!(e.to_string()))
                })
            })
        };
        let mut backoff_secs: u64 = 1;
        loop {
            match run_one_session(
                &self.base_url,
                &self.token,
                &bot_user_id,
                Arc::clone(&handler),
                Arc::clone(&sender),
            )
            .await
            {
                Ok(()) => {
                    info!("mattermost WS session ended cleanly — reconnecting");
                    backoff_secs = 1;
                }
                Err(e) => {
                    warn!(error = %e, backoff_secs, "mattermost WS session errored — backing off");
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(MAX_RECONNECT_BACKOFF_SECS);
                }
            }
        }
    }

    /// Post a message to a Mattermost channel id via `POST /api/v4/posts`.
    /// Returns the created post id as the [`MessageId`].
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let id = send_post(&self.base_url, &self.token, chat_id, text).await?;
        Ok(MessageId(id))
    }

    /// Proactive send is identical to a reply (POST /posts). The operator
    /// proactive gate is the caller's responsibility per the C-11 contract.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.send_text(chat_id, text).await
    }
}

/// One connect → authenticate → read loop cycle. Returns `Ok` on a clean peer
/// close (caller reconnects) and `Err` on a transport failure.
async fn run_one_session(
    base_url: &str,
    token: &SecretString,
    bot_user_id: &str,
    handler: Arc<PipelineHandler>,
    sender: OutboundSender,
) -> Result<()> {
    let ws_url = mm_ws_url(base_url);
    let host = ws_url.split('/').nth(2).unwrap_or("?").to_string();
    let (ws, _resp) = connect_async(&ws_url)
        .await
        .context("dial mattermost WS endpoint")?;
    let (mut sink, mut stream) = ws.split();
    // Mattermost streams no events until authenticated.
    sink.send(Message::Text(auth_challenge_frame(token.expose())))
        .await
        .context("send mattermost auth challenge")?;
    info!(host = %host, "mattermost WS connected + authenticated");

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(frame)) => match decode_frame(&frame, bot_user_id) {
                MmFrame::Posted(inbound) => {
                    dispatch_inbound(*inbound, Arc::clone(&handler), Arc::clone(&sender)).await;
                }
                MmFrame::Ignored => {}
                MmFrame::ParseError(reason) => {
                    warn!(reason = %reason, "mattermost frame parse error")
                }
            },
            Ok(Message::Ping(p)) => {
                sink.send(Message::Pong(p))
                    .await
                    .context("mattermost WS pong")?;
            }
            Ok(Message::Close(_)) => {
                info!("mattermost WS peer closed — reconnecting");
                return Ok(());
            }
            Ok(_) => {} // binary / pong / frame — ignore
            Err(e) => anyhow::bail!("mattermost WS read error: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_reports_mattermost_name() {
        let c = MattermostChannel::new("https://mm.example.com", SecretString::from("tok"));
        assert_eq!(c.name(), "mattermost");
    }

    #[tokio::test]
    async fn send_text_surfaces_transport_error_on_unreachable_host() {
        // A bogus host → DNS/connect failure → Transport (not Auth/RateLimited),
        // proving send_text routes through POST /posts rather than the
        // NotSupported default.
        let c = MattermostChannel::new(
            "https://definitely-not-a-real-mm-host.invalid",
            SecretString::from("tok"),
        );
        let err = c.send_text("chan123", "hi").await.unwrap_err();
        assert!(
            matches!(err, ChannelError::Transport(_)),
            "expected Transport, got {err:?}"
        );
    }

    #[tokio::test]
    async fn send_proactive_delegates_to_send_text() {
        let c = MattermostChannel::new(
            "https://definitely-not-a-real-mm-host.invalid",
            SecretString::from("tok"),
        );
        let err = c.send_proactive("chan123", "hi").await.unwrap_err();
        assert!(
            matches!(err, ChannelError::Transport(_)),
            "expected Transport (delegate path), got {err:?}"
        );
        let msg = format!("{err}");
        assert!(!msg.contains("not supported"), "leaked default impl: {msg}");
    }
}
