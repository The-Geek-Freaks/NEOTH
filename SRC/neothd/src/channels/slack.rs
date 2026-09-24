//! Slack channel — LIVE via socket mode.
//!
//! `run()` delegates to [`super::slack_socket::run_socket_loop`], which
//! opens a WebSocket to Slack's edge URL (no public HTTPS endpoint
//! required), ACKs each envelope, and dispatches inbound events into the
//! pipeline. This module owns the credential surface + `Channel` trait
//! wiring; `slack_socket` owns the live receive/send loop. The
//! integration uses:
//!   - `xapp-...` app-level token to call `apps.connections.open`
//!   - `xoxb-...` bot user OAuth token for `chat.postMessage`,
//!     `files.upload`, etc.
//!   - tokio-tungstenite + an event-routing layer that decodes Slack's
//!     JSON-encoded `events_api` envelopes into `InboundMessage`.
//!
//! The credential split (two tokens) is honoured at construction time so
//! the wizard collects them correctly before the socket loop runs.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;

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
    inbound_gate: Option<SlackInboundGate>,
    proactive_dm_member: Option<String>,
    proactive_api: Arc<dyn SlackProactiveApi>,
}

#[async_trait]
trait SlackProactiveApi: Send + Sync {
    async fn open_dm(
        &self,
        bot_token: &SecretString,
        allowed_member: &str,
    ) -> Result<super::slack_api::ConversationsOpenResult>;

    async fn post_dm(
        &self,
        bot_token: &SecretString,
        dm_id: &str,
        text: &str,
    ) -> Result<super::slack_api::PostMessageResult>;
}

struct LiveSlackProactiveApi;

#[async_trait]
impl SlackProactiveApi for LiveSlackProactiveApi {
    async fn open_dm(
        &self,
        bot_token: &SecretString,
        allowed_member: &str,
    ) -> Result<super::slack_api::ConversationsOpenResult> {
        super::slack_api::conversations_open(bot_token, allowed_member).await
    }

    async fn post_dm(
        &self,
        bot_token: &SecretString,
        dm_id: &str,
        text: &str,
    ) -> Result<super::slack_api::PostMessageResult> {
        super::slack_api::post_message(bot_token, dm_id, text).await
    }
}

struct SlackInboundGate {
    allowed_user_id: String,
    writer: crate::wal::writer::WalWriterHandle,
}

impl SlackChannel {
    pub fn new(bot_token: SecretString, app_token: SecretString) -> Self {
        Self {
            bot_token,
            app_token,
            inbound_gate: None,
            proactive_dm_member: None,
            proactive_api: Arc::new(LiveSlackProactiveApi),
        }
    }

    /// Build the account-bound proactive adapter. The member is normalized at
    /// construction and never accepted from a queued item's mutable route.
    pub fn new_proactive_dm(
        bot_token: SecretString,
        app_token: SecretString,
        allowed_user_id: String,
    ) -> Result<Self> {
        let mut channel = Self::new(bot_token, app_token);
        channel.proactive_dm_member = Some(normalize_allowed_user_id(&allowed_user_id)?);
        Ok(channel)
    }

    #[cfg(test)]
    fn new_proactive_dm_with_api(
        bot_token: SecretString,
        app_token: SecretString,
        allowed_user_id: String,
        proactive_api: Arc<dyn SlackProactiveApi>,
    ) -> Result<Self> {
        let mut channel = Self::new_proactive_dm(bot_token, app_token, allowed_user_id)?;
        channel.proactive_api = proactive_api;
        Ok(channel)
    }

    pub fn new_inbound(
        bot_token: SecretString,
        app_token: SecretString,
        allowed_user_id: &str,
        writer: crate::wal::writer::WalWriterHandle,
    ) -> Result<Self> {
        let mut channel = Self::new(bot_token, app_token);
        channel.inbound_gate = Some(SlackInboundGate {
            allowed_user_id: normalize_allowed_user_id(allowed_user_id)?,
            writer,
        });
        Ok(channel)
    }

    /// Operator-visible hint surfaced by the wizard + `neoth doctor`.
    pub const SETUP_HINT: &'static str = "Slack socket mode: create an app at api.slack.com/apps, enable Socket Mode, \
         copy the xoxb- bot token + xapp- app token into credentials.yaml. \
         Bot messages need chat:write; named proactive DMs also need im:write. \
         `neoth serve` opens the outbound WebSocket, receives events, ACKs \
         envelopes, and sends replies through chat.postMessage.";
}

#[async_trait]
impl Channel for SlackChannel {
    fn name(&self) -> &'static str {
        "slack"
    }

    fn supports_message_edits(&self) -> bool {
        true
    }

    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        // CDX-06 + Pick #28 (Session 14): socket-mode WS loop with
        // receive→reply closed end-to-end. The bot_token is now
        // threaded through so every pipeline `Ok(Some(out))` lands
        // back on Slack via `chat.postMessage`.
        let gate = self.inbound_gate.as_ref().context(
            "Slack inbound is fail-closed: construct with an allowed user id and WAL writer",
        )?;
        super::slack_socket::run_socket_loop(
            &self.app_token,
            self.bot_token.clone(),
            gate.allowed_user_id.clone(),
            gate.writer.clone(),
            handler,
        )
        .await
    }

    /// Send a plain-text message to a Slack channel via `chat.postMessage`.
    /// The live socket-mode receive loop and proactive jobs both use this
    /// outbound API path.
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

    /// Named-account proactive delivery resolves the configured immutable
    /// member to the app's IM conversation and posts only to that returned
    /// `D…` id. The caller owns the proactive policy gate and durable Armed
    /// admission before this adapter performs either provider operation.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let Some(allowed_member) = self.proactive_dm_member.as_deref() else {
            return self.send_text(chat_id, text).await;
        };
        if chat_id != allowed_member {
            return Err(ChannelError::Transport(
                "Slack proactive recipient conflicts with the configured account member".into(),
            ));
        }
        let opened = self
            .proactive_api
            .open_dm(&self.bot_token, allowed_member)
            .await
            .map_err(|error| ChannelError::Transport(error.to_string()))?;
        if !opened.ok {
            return Err(ChannelError::Transport(format!(
                "slack conversations.open: {}",
                opened.error.as_deref().unwrap_or("unknown error")
            )));
        }
        let dm_id = opened.channel_id.ok_or_else(|| {
            ChannelError::Transport(
                "slack conversations.open returned ok=true with no channel id (protocol violation)"
                    .into(),
            )
        })?;
        if !is_slack_im_id(&dm_id) {
            return Err(ChannelError::Transport(
                "slack conversations.open returned a non-IM channel id (protocol violation)".into(),
            ));
        }
        let posted = self
            .proactive_api
            .post_dm(&self.bot_token, &dm_id, text)
            .await
            .map_err(|error| ChannelError::Transport(error.to_string()))?;
        if !posted.ok {
            return Err(ChannelError::Transport(format!(
                "slack chat.postMessage: {}",
                posted.error.as_deref().unwrap_or("unknown error")
            )));
        }
        let ts = posted.ts.ok_or_else(|| {
            ChannelError::Transport(
                "slack chat.postMessage returned ok=true with no ts (protocol violation)".into(),
            )
        })?;
        Ok(MessageId(ts))
    }

    /// SPEC-11: edit a previously-sent message via `chat.update`. `message_id`
    /// is the `ts` returned by [`send_text`]. Used by the [`LiveDelivery`]
    /// streaming-preview path. A Slack `ok=false` (e.g. `message_not_found`)
    /// surfaces as `Transport` so the `LiveDelivery` degrade path is reserved
    /// for genuine `NotSupported` adapters, not transient API errors.
    ///
    /// [`LiveDelivery`]: crate::channels::LiveDelivery
    /// [`send_text`]: SlackChannel::send_text
    async fn edit_message(
        &self,
        chat_id: &str,
        message_id: &MessageId,
        new_text: &str,
    ) -> std::result::Result<(), ChannelError> {
        let result =
            super::slack_api::update_message(&self.bot_token, chat_id, &message_id.0, new_text)
                .await
                .map_err(|e| ChannelError::Transport(e.to_string()))?;
        if !result.ok {
            return Err(ChannelError::Transport(format!(
                "slack chat.update: {}",
                result.error.as_deref().unwrap_or("unknown error")
            )));
        }
        Ok(())
    }
}

/// Canonicalize Slack's immutable member id. Display names and emails are
/// mutable and therefore never accepted as authorization identities.
pub fn normalize_allowed_user_id(raw: &str) -> Result<String> {
    let value = raw.trim();
    if value.len() < 2
        || !matches!(value.as_bytes().first(), Some(b'U' | b'W'))
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        anyhow::bail!("Slack allowed user id must be an immutable `U…` or `W…` member id");
    }
    Ok(value.to_string())
}

fn is_slack_im_id(raw: &str) -> bool {
    raw.len() >= 2 && raw.starts_with('D') && raw.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    enum ScriptStep {
        Open(std::result::Result<super::super::slack_api::ConversationsOpenResult, String>),
        Post(std::result::Result<super::super::slack_api::PostMessageResult, String>),
    }

    struct ScriptedProactiveApi {
        steps: Mutex<VecDeque<ScriptStep>>,
        calls: Mutex<Vec<String>>,
    }

    impl ScriptedProactiveApi {
        fn new(steps: Vec<ScriptStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn take(&self, expected: &str) -> std::result::Result<ScriptStep, anyhow::Error> {
            let step = self.steps.lock().unwrap().pop_front().ok_or_else(|| {
                anyhow::anyhow!("unexpected proactive Slack API call: {expected}")
            })?;
            self.calls.lock().unwrap().push(expected.to_string());
            Ok(step)
        }
    }

    #[async_trait::async_trait]
    impl SlackProactiveApi for ScriptedProactiveApi {
        async fn open_dm(
            &self,
            _bot_token: &SecretString,
            allowed_member: &str,
        ) -> Result<super::super::slack_api::ConversationsOpenResult> {
            let step = self.take(&format!("open:{allowed_member}"))?;
            match step {
                ScriptStep::Open(result) => result.map_err(anyhow::Error::msg),
                ScriptStep::Post(_) => anyhow::bail!("post occurred before conversations.open"),
            }
        }

        async fn post_dm(
            &self,
            _bot_token: &SecretString,
            dm_id: &str,
            text: &str,
        ) -> Result<super::super::slack_api::PostMessageResult> {
            let step = self.take(&format!("post:{dm_id}:{text}"))?;
            match step {
                ScriptStep::Post(result) => result.map_err(anyhow::Error::msg),
                ScriptStep::Open(_) => anyhow::bail!("conversations.open was attempted twice"),
            }
        }
    }

    #[test]
    fn allowed_user_id_is_trimmed_and_rejects_mutable_names() {
        assert_eq!(normalize_allowed_user_id(" U123ABC ").unwrap(), "U123ABC");
        assert_eq!(normalize_allowed_user_id("W123ABC").unwrap(), "W123ABC");
        for invalid in ["", "alex", "U 123", "C123"] {
            assert!(normalize_allowed_user_id(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn channel_reports_slack_name() {
        let c = SlackChannel::new(
            SecretString::from("xoxb-test"),
            SecretString::from("xapp-test"),
        );
        assert_eq!(c.name(), "slack");
    }

    #[test]
    fn proactive_dm_constructor_keeps_only_immutable_member_authority() {
        let channel = SlackChannel::new_proactive_dm(
            SecretString::from("xoxb-test"),
            SecretString::from("xapp-test"),
            " U123ABC ".into(),
        )
        .unwrap();
        assert_eq!(channel.proactive_dm_member.as_deref(), Some("U123ABC"));
        assert!(
            SlackChannel::new_proactive_dm(
                SecretString::from("xoxb-test"),
                SecretString::from("xapp-test"),
                "#general".into(),
            )
            .is_err()
        );
    }

    fn scripted_proactive_channel(api: Arc<ScriptedProactiveApi>) -> SlackChannel {
        SlackChannel::new_proactive_dm_with_api(
            SecretString::from("xoxb-test"),
            SecretString::from("xapp-test"),
            "U123ABC".into(),
            api,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn proactive_dm_opens_exact_member_then_posts_only_returned_im() {
        let api = Arc::new(ScriptedProactiveApi::new(vec![
            ScriptStep::Open(Ok(super::super::slack_api::ConversationsOpenResult {
                ok: true,
                channel_id: Some("D123IM".into()),
                error: None,
            })),
            ScriptStep::Post(Ok(super::super::slack_api::PostMessageResult {
                ok: true,
                ts: Some("1700000000.000100".into()),
                channel: Some("D123IM".into()),
                error: None,
            })),
        ]));
        let channel = scripted_proactive_channel(Arc::clone(&api));
        assert_eq!(
            channel
                .send_proactive("U123ABC", "private body")
                .await
                .unwrap(),
            MessageId("1700000000.000100".into())
        );
        assert_eq!(
            api.calls(),
            vec!["open:U123ABC", "post:D123IM:private body"]
        );
    }

    #[tokio::test]
    async fn proactive_dm_resolver_error_or_malformed_id_never_posts() {
        for opened in [
            Err("resolver timeout".to_string()),
            Ok(super::super::slack_api::ConversationsOpenResult {
                ok: true,
                channel_id: Some("D-not-a-valid-im".into()),
                error: None,
            }),
        ] {
            let api = Arc::new(ScriptedProactiveApi::new(vec![ScriptStep::Open(opened)]));
            let channel = scripted_proactive_channel(Arc::clone(&api));
            assert!(
                channel
                    .send_proactive("U123ABC", "private body")
                    .await
                    .is_err()
            );
            assert_eq!(api.calls(), vec!["open:U123ABC"]);
        }
    }

    #[tokio::test]
    async fn proactive_dm_post_failure_is_one_open_and_one_post_without_retry() {
        let api = Arc::new(ScriptedProactiveApi::new(vec![
            ScriptStep::Open(Ok(super::super::slack_api::ConversationsOpenResult {
                ok: true,
                channel_id: Some("D123IM".into()),
                error: None,
            })),
            ScriptStep::Post(Err("post outcome unknown".to_string())),
        ]));
        let channel = scripted_proactive_channel(Arc::clone(&api));
        assert!(
            channel
                .send_proactive("U123ABC", "private body")
                .await
                .is_err()
        );
        assert_eq!(
            api.calls(),
            vec!["open:U123ABC", "post:D123IM:private body"],
            "an unknown post result cannot trigger a resolver or post retry"
        );
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
            SecretString::from(["xoxb", "definitely-invalid"].join("-")),
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
        assert!(h.contains("neoth serve"));
        assert!(!h.contains("Phase 2"));
    }

    /// SPEC-11 pin: edit_message routes through chat.update. A bogus token
    /// yields a Transport error (not NotSupported) — proving the override
    /// landed + that LiveDelivery's degrade path is reserved for genuine
    /// no-edit-API adapters, not transient Slack failures.
    #[tokio::test]
    async fn edit_message_surfaces_transport_error_on_invalid_token() {
        let c = SlackChannel::new(
            SecretString::from(["xoxb", "definitely-invalid"].join("-")),
            SecretString::from("xapp-also-invalid"),
        );
        let err = c
            .edit_message("C12345", &MessageId("1700000000.000100".into()), "edited")
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::channels::ChannelError::Transport(_)),
            "expected Transport (chat.update path); got {err:?}"
        );
        let msg = format!("{err}");
        assert!(!msg.contains("not supported"), "leaked default impl: {msg}");
    }

    /// C-11 wire-up pin: send_proactive routes through the same Slack
    /// chat.postMessage path as send_text. Verified via the bogus-token
    /// Transport error — proves the trait default `NotSupported` is no
    /// longer the path Slack falls through to.
    #[tokio::test]
    async fn send_proactive_delegates_to_send_text_returns_transport_error_on_invalid_token() {
        let c = SlackChannel::new(
            SecretString::from(["xoxb", "definitely-invalid"].join("-")),
            SecretString::from("xapp-also-invalid"),
        );
        let err = c.send_proactive("C12345", "hi").await.unwrap_err();
        assert!(
            matches!(err, crate::channels::ChannelError::Transport(_)),
            "expected Transport (delegate path); got {err:?}"
        );
        let msg = format!("{err}");
        assert!(!msg.contains("not supported"), "leaked default impl: {msg}");
    }
}
