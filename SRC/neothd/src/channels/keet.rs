//! Keet channel adapter — R-2 stub.
//!
//! Keet rides on Holepunch's Hyperswarm + Hypercore stack (JS / Node).
//! A native-Rust port is multi-week work — see the research note
//! `QUELLEN/research/` (Phase 11 R-A1, pending). v0.1.x ships this
//! stub so the wizard's per-hemisphere picker + `freedom.yaml`
//! configuration round-trip cleanly without a "dispatching to a
//! nonexistent adapter" panic.
//!
//! What the stub provides:
//!   - `KeetChannel::new(seed_phrase)` — accepts the 24-word seed the
//!     operator paired with on their phone.
//!   - `Channel::name()` → `"keet"`.
//!   - `Channel::run(handler)` → returns a clear "deferred" error.
//!   - `send_text` / `send_media` inherit the trait's `NotSupported`
//!     default.
//!
//! Why this shape: the channel adapter trait + dispatch path are already
//! solid (`SP-5 C-prime`). What's missing is the Hyperswarm transport,
//! and that decision is captured separately. When the transport lands,
//! only `run()` + `send_text` + `send_media` need to be filled in.

use anyhow::Result;
use async_trait::async_trait;

use super::{Channel, PipelineHandler};
use crate::secret::SecretString;

pub struct KeetChannel {
    /// Operator's 24-word pairing phrase. Stored as `SecretString` so
    /// mlock + zeroize protect it the same way provider keys do.
    seed_phrase: SecretString,
}

impl KeetChannel {
    pub fn new(seed_phrase: SecretString) -> Self {
        Self { seed_phrase }
    }

    /// Operator-visible hint for the pairing flow. Exposed so the wizard
    /// can render the same line in both the seed-prompt and the post-
    /// install confirmation.
    pub const PAIRING_HINT: &'static str =
        "Paste the 24-word seed phrase Keet generated on your phone.";
}

#[async_trait]
impl Channel for KeetChannel {
    fn name(&self) -> &'static str {
        "keet"
    }

    async fn run(&self, _handler: PipelineHandler) -> Result<()> {
        // Hyperswarm + Hypercore transport is multi-week work. The trait
        // path stays clean — when the transport lands, replace this body
        // with the actual swarm join + topic subscription. Until then,
        // dispatching to Keet bails fast with an actionable message.
        anyhow::bail!(
            "keet channel: receive loop is deferred until the Hyperswarm \
             transport lands. Use Telegram for v0.1.x. The seed phrase \
             you configured ({} chars) is persisted unchanged so the \
             upgrade requires no re-pairing.",
            self.seed_phrase.expose().len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_reports_keet_name() {
        let c = KeetChannel::new(SecretString::from(
            "word ".repeat(24).trim_end().to_string(),
        ));
        assert_eq!(c.name(), "keet");
    }

    #[tokio::test]
    async fn run_bails_with_actionable_message() {
        let c = KeetChannel::new(SecretString::from("seed".to_string()));
        let handler: PipelineHandler = Box::new(|_inbound| Box::pin(async move { Ok(None) }));
        let err = c.run(handler).await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("deferred"), "msg: {msg}");
        assert!(msg.contains("Telegram"), "msg: {msg}");
    }

    /// Trait defaults must surface as `NotSupported` so callers can
    /// distinguish "stub, will land later" from "transport error".
    #[tokio::test]
    async fn send_text_inherits_not_supported_default() {
        use crate::channels::ChannelError;
        let c = KeetChannel::new(SecretString::from("x".to_string()));
        let err = c.send_text("chat", "hi").await.unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "send_text"
            }
        ));
    }

    #[test]
    fn pairing_hint_is_non_empty_and_single_line() {
        assert!(!KeetChannel::PAIRING_HINT.is_empty());
        assert!(!KeetChannel::PAIRING_HINT.contains('\n'));
    }
}
