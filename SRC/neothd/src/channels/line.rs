//! GOLD-FEAT-10 — LINE Messaging API channel adapter.
//!
//! **Outbound is LIVE:** [`LineChannel::send_text`] (and proactive) POST to the
//! `/v2/bot/message/push` endpoint keyed by the source id — so cron jobs /
//! proactive sends reach LINE today.
//!
//! **Inbound is LIVE via the shared webhook path, not this module's `run()`:**
//! LINE delivers events by POSTing to the daemon's [`super::webhook_listener`]
//! (hyper HTTP server), which runs [`super::webhook_verify::verify_line_signature`]
//! and [`super::line_api::decode_line_payload`] to turn the JSON into
//! `InboundMessage`s, then routes any reply back through the push API. Because
//! LINE pushes (there is no per-channel long-poll), this module's standalone
//! `Channel::run()` deliberately bails with a pointer to that webhook flow — it
//! is not the receive path. This mirrors the WhatsApp adapter exactly.
//!
//! ## Operator prerequisite (not automatable)
//!
//! The operator creates a Messaging API channel in the LINE Developers console,
//! copies the **channel secret** (Basic Settings — signature verification) and
//! the **long-lived channel access token** (Messaging API tab — sending) into
//! `credentials.yaml`, and points their LINE webhook URL at the reverse proxy
//! fronting NEOTH's `/line/webhook` listener.

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::line_api::{LINE_API_BASE, send_line_push};
use super::{Channel, ChannelError, MessageId, PipelineHandler};
use crate::secret::SecretString;

/// LINE adapter. Holds the channel access token, a shared HTTP client, and the
/// API base URL (overridable for tests). Stateless beyond that — every send is
/// one HTTPS round trip to the push endpoint.
pub struct LineChannel {
    access_token: SecretString,
    http: reqwest::Client,
    base_url: String,
}

impl LineChannel {
    /// Build with the operator's long-lived channel access token. Uses the
    /// shared hardened HTTP client (TLS + no-redirect + timeouts).
    pub fn new(access_token: SecretString) -> Result<Self> {
        let http = crate::providers::http_client::build_client()
            .context("build reqwest client for LINE adapter")?;
        Ok(Self {
            access_token,
            http,
            base_url: LINE_API_BASE.to_string(),
        })
    }

    /// Override the API base URL (tests point this at a mock server).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
    }

    /// Operator-visible hint surfaced by the wizard + `neoth doctor`.
    pub const SETUP_HINT: &'static str = "LINE Messaging API: create a Messaging API channel at developers.line.biz, \
         copy the channel secret (Basic Settings) + long-lived channel access token \
         (Messaging API tab) into credentials.yaml, and point your LINE webhook URL \
         at the reverse proxy fronting NEOTH's /line/webhook listener.";
}

#[async_trait]
impl Channel for LineChannel {
    fn name(&self) -> &'static str {
        "line"
    }

    /// LINE pushes inbound events to the webhook listener — there is no poll
    /// loop. Bail with an actionable pointer to that flow (mirrors the WhatsApp
    /// adapter). The daemon's channel-spawn loop never calls this for LINE; it
    /// wires the webhook listener instead.
    async fn run(&self, _handler: PipelineHandler) -> Result<()> {
        anyhow::bail!(
            "line channel: inbound is served by the webhook listener (POST /line/webhook), \
             not Channel::run — LINE pushes events to a public HTTPS endpoint the operator \
             fronts with a reverse proxy. Outbound send_text works today via the push API, \
             so cron jobs / proactive paths can message LINE even without the receive wiring."
        )
    }

    /// Send a plain-text message via the LINE push API. `chat_id` is the
    /// `userId` / `groupId` / `roomId` carried as the inbound `chat_id`, so
    /// replies route back to the same conversation. Returns the LINE sent-
    /// message id as the [`MessageId`].
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        send_line_push(
            &self.http,
            &self.base_url,
            &self.access_token,
            chat_id,
            text,
        )
        .await
    }

    /// Proactive send delegates to `send_text` — the push POST is identical for
    /// replies vs daemon-initiated sends. The operator gate
    /// (`FreedomConfig::proactive.enabled`) is the CALLER's responsibility per
    /// the C-11 trait contract.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.send_text(chat_id, text).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> LineChannel {
        LineChannel::new(SecretString::from("channel-access-token")).unwrap()
    }

    #[test]
    fn adapter_reports_line_name() {
        assert_eq!(adapter().name(), "line");
    }

    #[test]
    fn with_base_url_trims_trailing_slash() {
        let a = adapter().with_base_url("http://127.0.0.1:9/");
        assert_eq!(a.base_url, "http://127.0.0.1:9");
    }

    #[test]
    fn setup_hint_has_actionable_single_paragraph_contract() {
        assert!(LineChannel::SETUP_HINT.contains("LINE Messaging API"));
        assert!(LineChannel::SETUP_HINT.contains("credentials.yaml"));
        assert_eq!(LineChannel::SETUP_HINT.matches('\n').count(), 0);
    }

    #[tokio::test]
    async fn run_bails_with_actionable_webhook_pointer() {
        let handler: PipelineHandler = Box::new(|_inbound| Box::pin(async move { Ok(None) }));
        let err = adapter().run(handler).await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("webhook listener"), "msg: {msg}");
        assert!(
            msg.contains("send_text") || msg.contains("push API"),
            "bail must reference the outbound capability: {msg}"
        );
    }

    #[tokio::test]
    async fn send_text_surfaces_transport_error_against_unroutable_base() {
        // Point the base at an unroutable port so the send fails fast with a
        // Transport error rather than hitting the real LINE API.
        let a = adapter().with_base_url("http://127.0.0.1:1");
        let err = a.send_text("Ualice", "hi").await.unwrap_err();
        assert!(
            matches!(err, ChannelError::Transport(_)),
            "expected Transport, got {err:?}"
        );
    }

    #[tokio::test]
    async fn send_proactive_delegates_to_push_path() {
        let a = adapter().with_base_url("http://127.0.0.1:1");
        let err = a.send_proactive("Ualice", "hi").await.unwrap_err();
        // Delegates to send_text → same Transport failure, never the trait
        // default NotSupported.
        assert!(matches!(err, ChannelError::Transport(_)), "got {err:?}");
        assert!(!format!("{err}").contains("not supported"));
    }
}
