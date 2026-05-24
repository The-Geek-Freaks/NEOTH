//! WhatsApp Business Cloud API channel — scaffold.
//!
//! v0.1.x ships the credential surface + the `Channel` trait wiring
//! so operators can configure WhatsApp via `neoth init` and the
//! daemon serialises the config without panicking. The actual
//! webhook receiver / send pipeline is deferred — WhatsApp requires
//! a public HTTPS endpoint (or an ngrok-style tunnel) for the
//! webhook callback, which is a meaningful infra commitment that
//! operators should opt into per deployment rather than have NEOTH
//! bind a public port silently.
//!
//! What lands later (Phase 2):
//!   - hyper-based HTTP server bound to the operator's configured
//!     interface + a TLS termination story (operator picks: terminate
//!     inside NEOTH via rustls or front it with Caddy/nginx).
//!   - `POST /webhook` handler that verifies Meta's `hub.verify_token`
//!     and decodes message JSON into `InboundMessage`.
//!   - `send_text` / `send_media` via the `/messages` Graph API
//!     endpoint, scoped to the operator's phone-number id.
//!
//! Until that lands `run()` bails fast with a clear message that
//! points operators at the right setup steps.

use anyhow::Result;
use async_trait::async_trait;

use super::{Channel, ChannelError, MessageId, PipelineHandler};
use crate::secret::SecretString;

pub struct WhatsAppChannel {
    /// Meta Cloud API access token (long-lived system-user token).
    /// Consumed by `send_text` today via the Graph API; the Phase-2
    /// webhook receiver will also use it.
    access_token: SecretString,
    /// Numeric phone-number id from the Meta console.
    phone_number_id: String,
    /// Verify token used during webhook handshake. Receive-only;
    /// `send_text` does not need it.
    #[allow(dead_code)]
    verify_token: SecretString,
}

impl WhatsAppChannel {
    pub fn new(
        access_token: SecretString,
        phone_number_id: String,
        verify_token: SecretString,
    ) -> Self {
        Self {
            access_token,
            phone_number_id,
            verify_token,
        }
    }

    /// Operator-visible hint surfaced by the wizard + `neoth doctor`.
    pub const SETUP_HINT: &'static str = "WhatsApp Business Cloud API: create an app at developers.facebook.com, \
         attach a phone number, copy the access token + phone-number id into \
         credentials.yaml. Webhook target lands in Phase 2.";
}

#[async_trait]
impl Channel for WhatsAppChannel {
    fn name(&self) -> &'static str {
        "whatsapp"
    }

    async fn run(&self, _handler: PipelineHandler) -> Result<()> {
        anyhow::bail!(
            "whatsapp channel: webhook receiver deferred to Phase 2 — needs an \
             HTTPS endpoint operator-side. Credentials accepted + serialised \
             so the next release can wire the receiver without re-pairing. \
             Outbound `send_text` works today via the Graph API — operators \
             can use NEOTH to push WhatsApp messages from cron jobs / \
             proactive paths even before the receive loop lands."
        )
    }

    /// Send a plain-text WhatsApp message via the Cloud Graph API.
    /// Outbound-only path that works without the Phase-2 webhook
    /// receiver — proactive cron jobs + one-way notifications use it
    /// today. `chat_id` is the recipient's phone number in E.164
    /// (e.g. `"+4915112345678"`); Meta normalises country prefixes
    /// server-side. Returns the WhatsApp wamid (`wamid....`) as the
    /// [`MessageId`] for future correlation with delivery webhooks.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let result = super::whatsapp_api::send_text_message(
            &self.access_token,
            &self.phone_number_id,
            chat_id,
            text,
        )
        .await
        .map_err(|e| ChannelError::Transport(e.to_string()))?;
        if !result.ok {
            return Err(ChannelError::Transport(format!(
                "whatsapp send: {}",
                result.error.as_deref().unwrap_or("unknown error")
            )));
        }
        let id = result.message_id.ok_or_else(|| {
            ChannelError::Transport(
                "whatsapp send returned ok=true with no message id (protocol violation)".into(),
            )
        })?;
        Ok(MessageId(id))
    }

    /// C-11 wire-up (Session 21): proactive send delegates to `send_text`.
    /// WhatsApp's outbound API is identical for solicited replies vs
    /// daemon-initiated proactive (the Meta-side "24h template-only"
    /// constraint is a higher-level concern that callers handle via
    /// template selection — this trait method just ships the bytes).
    /// The operator-gate (`FreedomConfig::proactive.enabled`) is the
    /// CALLER's responsibility per the C-11 trait contract.
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

    #[test]
    fn channel_reports_whatsapp_name() {
        let c = WhatsAppChannel::new(
            SecretString::from("token"),
            "1234567890".to_string(),
            SecretString::from("verify"),
        );
        assert_eq!(c.name(), "whatsapp");
    }

    #[tokio::test]
    async fn run_bails_with_actionable_message() {
        let c = WhatsAppChannel::new(
            SecretString::from("token"),
            "12345".to_string(),
            SecretString::from("verify"),
        );
        let handler: PipelineHandler = Box::new(|_inbound| Box::pin(async move { Ok(None) }));
        let err = c.run(handler).await.unwrap_err();
        let msg = format!("{err}");
        // Bail must say WHY (receive deferred) AND point at the
        // current outbound capability so the operator knows what's
        // usable today.
        assert!(msg.contains("deferred"), "msg: {msg}");
        assert!(
            msg.contains("send_text") || msg.contains("Graph API"),
            "bail must reference the outbound capability: {msg}"
        );
    }

    #[tokio::test]
    async fn send_text_surfaces_transport_error_on_invalid_token() {
        use crate::channels::ChannelError;
        // Live network call against Meta's Graph API with a bogus
        // token MUST yield a Transport error rather than panicking
        // or returning Ok. Either DNS/transport fails OR Meta returns
        // an OAuth error envelope — both classified as Transport.
        let c = WhatsAppChannel::new(
            SecretString::from("definitely-invalid-token"),
            "1234567890".to_string(),
            SecretString::from("v"),
        );
        let result = c.send_text("+15551234567", "hi").await;
        match result {
            Err(ChannelError::Transport(_)) => { /* expected */ }
            Err(other) => panic!("expected Transport, got {other:?}"),
            Ok(_) => panic!("expected Err against an invalid token"),
        }
    }

    #[test]
    fn setup_hint_is_non_empty_and_single_paragraph() {
        assert!(!WhatsAppChannel::SETUP_HINT.is_empty());
        // No mid-line newlines — wizard renders it as one block.
        let nl_count = WhatsAppChannel::SETUP_HINT.matches('\n').count();
        assert!(nl_count <= 1);
    }

    /// C-11 wire-up pin: send_proactive routes through the same Graph
    /// API path as send_text. Verified via the bogus-token Transport
    /// error — proves the trait default `NotSupported` is no longer
    /// the path WhatsApp falls through to.
    #[tokio::test]
    async fn send_proactive_delegates_to_send_text_returns_transport_error_on_invalid_token() {
        use crate::channels::ChannelError;
        let c = WhatsAppChannel::new(
            SecretString::from("definitely-invalid-token"),
            "1234567890".to_string(),
            SecretString::from("v"),
        );
        let err = c.send_proactive("+15551234567", "hi").await.unwrap_err();
        assert!(
            matches!(err, ChannelError::Transport(_)),
            "expected Transport (delegate path); got {err:?}"
        );
        let msg = format!("{err}");
        assert!(!msg.contains("not supported"), "leaked default impl: {msg}");
    }
}
