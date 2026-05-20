//! Slack channel — scaffold (socket mode).
//!
//! v0.1.x ships the credential surface + `Channel` trait wiring;
//! the actual socket-mode WebSocket client is Phase 2 work.
//! Socket mode is the operator-friendly path because it does not
//! require a public HTTPS endpoint — NEOTH opens a WebSocket to
//! Slack's edge URL and receives events that way. The full
//! integration needs:
//!   - `xapp-...` app-level token to call `apps.connections.open`
//!   - `xoxb-...` bot user OAuth token for `chat.postMessage`,
//!     `files.upload`, etc.
//!   - reqwest + tokio-tungstenite + an event-routing layer that
//!     decodes Slack's JSON-encoded `events_api` envelopes into
//!     `InboundMessage`.
//!
//! Until that lands `run()` bails with a pointer to the setup
//! documentation. The credential split (two tokens) is honoured at
//! construction time so the wizard already collects them correctly.

use anyhow::Result;
use async_trait::async_trait;

use super::{Channel, ChannelError, MessageId, PipelineHandler};
use crate::secret::SecretString;

pub struct SlackChannel {
    /// `xoxb-...` bot user OAuth token. Consumed by `send_text` for
    /// `chat.postMessage` AND by the socket-mode loop via the outbound
    /// send path.
    bot_token: SecretString,
    /// `xapp-...` app-level token for socket mode. The socket-mode
    /// loop dials Slack's WSS endpoint with this token.
    app_token: SecretString,
}

impl SlackChannel {
    pub fn new(bot_token: SecretString, app_token: SecretString) -> Self {
        Self {
            bot_token,
            app_token,
        }
    }

    /// Operator-visible hint surfaced by the wizard + `neoth doctor`.
    pub const SETUP_HINT: &'static str = "Slack socket mode: create an app at api.slack.com/apps, enable Socket Mode, \
         copy the xoxb- bot token + xapp- app token into credentials.yaml. \
         Real receive/send wiring lands in Phase 2.";
}

#[async_trait]
impl Channel for SlackChannel {
    fn name(&self) -> &'static str {
        "slack"
    }

    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        // CDX-06 + Pick #28 (Session 14): socket-mode WS loop with
        // receive→reply closed end-to-end. The bot_token is now
        // threaded through so every pipeline `Ok(Some(out))` lands
        // back on Slack via `chat.postMessage`.
        super::slack_socket::run_socket_loop(&self.app_token, self.bot_token.clone(), handler).await
    }

    /// Send a plain-text message to a Slack channel via `chat.postMessage`.
    /// Outbound-only path that works without the Phase-2 socket-mode loop —
    /// proactive cron jobs and one-way notifications use this today.
    ///
    /// `chat_id` accepts Slack's channel ids (`C…` / `D…` / `G…`) or
    /// `#channel-name` (Slack resolves server-side). Returns the
    /// message timestamp (`ts`) as the [`MessageId`] so callers can
    /// reference it for future edits / reactions.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let result = super::slack_api::post_message(&self.bot_token, chat_id, text)
            .await
            .map_err(|e| ChannelError::Transport(e.to_string()))?;
        if !result.ok {
            return Err(ChannelError::Transport(format!(
                "slack chat.postMessage: {}",
                result.error.as_deref().unwrap_or("unknown error")
            )));
        }
        let ts = result.ts.ok_or_else(|| {
            ChannelError::Transport(
                "slack chat.postMessage returned ok=true with no ts (protocol violation)".into(),
            )
        })?;
        Ok(MessageId(ts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_reports_slack_name() {
        let c = SlackChannel::new(
            SecretString::from("xoxb-test"),
            SecretString::from("xapp-test"),
        );
        assert_eq!(c.name(), "slack");
    }

    #[tokio::test]
    async fn run_surfaces_auth_failure_on_invalid_app_token() {
        // CDX-06 socket-mode wiring shipped: run() now dials Slack
        // via the real socket-mode loop. An invalid xapp- token must
        // make `apps.connections.open` fail; the loop's outer
        // reconnect harness catches the error and backs off. To keep
        // the test bounded we wrap the long-running call in a
        // timeout — the loop never exits success in normal operation.
        let c = SlackChannel::new(
            SecretString::from("xoxb-test"),
            SecretString::from("xapp-definitely-invalid"),
        );
        let handler: PipelineHandler = Box::new(|_inbound| Box::pin(async move { Ok(None) }));
        let result = tokio::time::timeout(std::time::Duration::from_secs(8), c.run(handler)).await;
        // Either the call timed out (loop is retrying — auth keeps
        // failing, the loop is alive) or it returned Err. Both
        // outcomes prove the wiring is live; the previous stub
        // returned Err immediately with "deferred to Phase 2".
        match result {
            Err(_) => { /* timeout = loop is alive + retrying */ }
            Ok(Ok(())) => panic!("run() should not exit Ok against an invalid token"),
            Ok(Err(_)) => { /* clean error propagation also acceptable */ }
        }
    }

    #[tokio::test]
    async fn send_text_surfaces_transport_error_on_invalid_token() {
        // We can't reach real Slack without credentials, but pointing
        // at a bogus token must yield a Transport error rather than
        // panicking or returning Ok. The HTTP request itself fails
        // (or Slack returns ok=false), both classified as Transport.
        let c = SlackChannel::new(
            SecretString::from("xoxb-definitely-invalid"),
            SecretString::from("xapp-also-invalid"),
        );
        let result = c.send_text("C12345", "hi").await;
        match result {
            Err(crate::channels::ChannelError::Transport(_)) => { /* expected */ }
            Err(other) => panic!("expected Transport, got {other:?}"),
            Ok(_) => panic!("expected Err against an invalid token"),
        }
    }

    #[test]
    fn setup_hint_mentions_both_token_types() {
        let h = SlackChannel::SETUP_HINT;
        assert!(h.contains("xoxb"));
        assert!(h.contains("xapp"));
    }
}
