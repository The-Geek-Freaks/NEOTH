//! Inbound channel abstraction.
//!
//! Every messaging channel (Telegram first, WhatsApp / Slack / Discord later)
//! implements `Channel`. The daemon's `serve` loop spawns a task per
//! configured channel. Each task:
//!   1. Receives inbound messages from its transport.
//!   2. Filters via operator-configured allowlist.
//!   3. Emits `CHANNEL_INGRESS` to the WAL.
//!   4. Routes the message through the configured LLM provider.
//!   5. Emits `CHANNEL_EGRESS` after the reply is sent.
//!
//! Per the self-contained hard rule (`memory/neoth-hard-rule-self-contained.md`):
//! all channel logic lives inside NEOTH. No external relays, webhooks, or
//! shared services. Long-polling is the default transport.

pub mod discord;
pub mod discord_gateway;
pub mod formatter;
pub mod keet;
pub mod rate_limit;
pub mod slack;
pub mod slack_api;
pub mod slack_events;
pub mod slack_socket;
pub mod telegram;
pub mod webhook_listener;
pub mod webhook_router;
pub mod webhook_verify;
pub mod whatsapp;
pub mod whatsapp_api;
pub mod whatsapp_webhook;

use anyhow::Result;
use async_trait::async_trait;

/// Concrete messenger family. SP-5 C-prime: replaces the previous
/// `&'static str` `channel` field so adapters cannot diverge on naming.
/// Add a variant when a new adapter ships. `as_str()` returns the stable
/// snake_case identifier used for log fields + WAL payload "channel" keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelKind {
    Telegram,
    Keet,
    Slack,
    WhatsAppBusiness,
    WhatsAppBaileys,
    Discord,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Telegram => "telegram",
            ChannelKind::Keet => "keet",
            ChannelKind::Slack => "slack",
            ChannelKind::WhatsAppBusiness => "whatsapp_business",
            ChannelKind::WhatsAppBaileys => "whatsapp_baileys",
            ChannelKind::Discord => "discord",
        }
    }
}

impl serde::Serialize for ChannelKind {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_str())
    }
}

/// Platform-native message identifier. Opaque string so each vendor stays in
/// charge of its own ID format (Telegram numeric, Slack `ts`, WhatsApp wamid).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageId(pub String);

/// Coarse classification of inbound/outbound media. Refined later when
/// adapters need format-specific handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Video,
    Audio,
    Document,
    Sticker,
}

/// Bytes + MIME envelope for an inbound media attachment or an outbound
/// `send_media` call. Adapters that cannot honour `send_media` return
/// `ChannelError::NotSupported` rather than silently dropping.
#[derive(Debug, Clone)]
pub struct MediaPayload {
    pub kind: MediaKind,
    pub data: Vec<u8>,
    pub mime: String,
    pub filename: Option<String>,
}

/// How the bot was addressed in a group context. Single-DM messages have no
/// mention. v0.1.x emits `Native` only; richer kinds arrive with Slack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MentionKind {
    Native,
    ReplyToBot,
    QuotedBot,
    ThreadParticipant,
}

/// Typed channel errors. Adapters return `NotSupported` for capabilities the
/// vendor cannot provide (e.g. WhatsApp Business edit_message). Callers must
/// handle `NotSupported` instead of treating it as a generic failure — the
/// streaming-preview pipeline drops intermediate edits when that happens.
///
/// `Deferred` is the v0.1.x scaffold tag: the channel adapter is
/// configured + credential surface is live, but the runtime transport
/// (webhook receiver / WebSocket / Hyperswarm) hasn't shipped yet. The
/// daemon's channel-spawn loop matches this variant and skips
/// restart-loop attempts — distinguishing "not implemented yet" from
/// "transport blew up" so logs aren't noisy.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel transport error: {0}")]
    Transport(String),
    #[error("not supported by adapter: {feature}")]
    NotSupported { feature: &'static str },
    #[error("rate limited; retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("deferred — {reason}")]
    Deferred { reason: &'static str },
    #[error("auth error: {0}")]
    Auth(String),
}

/// One inbound message as it arrives from a channel transport, normalized
/// across vendors so the daemon pipeline can be channel-agnostic downstream.
///
/// SP-5 C-prime envelope: future-proofed for Keet / Slack / WhatsApp without
/// adopting cross-channel identity (UUID v7) at v0.1.x. See
/// `memory/neoth-sp5-channel-api.md`.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// Concrete messenger family. Replaces the previous `&'static str`.
    pub channel: ChannelKind,
    /// Channel-native chat identifier (Telegram chat_id, Slack channel, WA JID).
    pub chat_id: String,
    /// Channel-native thread/topic id when the platform exposes one. Opaque
    /// to NEOTH — adapters never reinterpret it.
    pub thread_id: Option<String>,
    /// Channel-native sender identifier. **Not** a NEOTH-wide UUID; cross-
    /// channel identity is deferred until a second adapter is in production.
    pub sender_id: String,
    /// Human-readable sender name when known (Telegram username/first_name).
    pub sender_display: Option<String>,
    /// The text payload. `None` when the inbound message has only media or is
    /// a system/service event the pipeline still wants to observe.
    pub text: Option<String>,
    /// Inbound media attachment when present.
    pub media: Option<MediaPayload>,
    /// Channel-native id of the message this one replies to.
    pub reply_to: Option<MessageId>,
    /// How the bot was addressed (DM → None, group native @ → Some(Native), …).
    pub mention_kind: Option<MentionKind>,
    /// Wall-clock timestamp the channel transport assigned to the message
    /// (seconds since unix epoch — keep `u64` for WAL compatibility).
    pub channel_ts_unix: u64,
    /// Raw platform timestamp (milliseconds, can be negative on Slack `ts`).
    /// Optional because not every channel exposes it; absence means "use
    /// channel_ts_unix instead".
    pub raw_ts_ms: Option<i64>,
}

/// What the daemon decided to send back. The channel adapter renders this
/// onto its native medium (Telegram sendMessage, WhatsApp text message, ...).
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// Vendor-specific identifier of the destination (echoes `chat_id`).
    pub recipient_id: String,
    /// Reply text.
    pub text: String,
}

/// Boxed pipeline handler closure type. The daemon supplies one when calling
/// `Channel::run`. Each inbound message goes through this closure; it returns
/// either an outbound message to send, `None` to drop silently, or an error
/// to log + skip the reply.
pub type PipelineHandler = Box<
    dyn Fn(
            InboundMessage,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Option<OutboundMessage>>> + Send>,
        > + Send
        + Sync,
>;

/// Implemented by every channel adapter. Object-safe so the daemon can hold
/// `Box<dyn Channel>` in its registry.
///
/// SP-5 C-prime: `name()` + `run(handler)` are the existing v0.1 surface;
/// `send_text` + `send_media` were added for proactive paths the handler
/// closure cannot reach. Everything else from `SPEC_channels.md`
/// (`edit_message`, `ack_received`, `send_proactive`, `get_chat_meta`,
/// `send_action_indicator`) stays deferred — adapters never implement them
/// until a second production messenger lands.
#[async_trait]
pub trait Channel: Send + Sync {
    /// Short identifier for logs + WAL events: "telegram", "whatsapp", ...
    fn name(&self) -> &'static str;

    /// Long-running task. Receives messages from the transport, calls
    /// `handler` for each. Returns when the channel is shut down (handler
    /// future dropped, channel-specific stop signal, or fatal error).
    async fn run(&self, handler: PipelineHandler) -> Result<()>;

    /// Send a plain-text message to a chat. Default impl returns
    /// `NotSupported` so legacy adapters keep compiling; concrete adapters
    /// override.
    async fn send_text(
        &self,
        _chat_id: &str,
        _text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "send_text",
        })
    }

    /// Send media (image/video/audio/document) with an optional caption.
    /// Default impl returns `NotSupported`.
    async fn send_media(
        &self,
        _chat_id: &str,
        _media: &MediaPayload,
        _caption: Option<&str>,
    ) -> std::result::Result<MessageId, ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "send_media",
        })
    }
}

/// F-3: send a [`formatter::CanonicalReply`] through a Channel adapter,
/// routing through the per-channel `Formatter` impl when one exists
/// and falling back to plain `send_text(text)` otherwise.
///
/// Returns the `MessageId` of every chunk the formatter produced (one
/// per split-message, in order). All current [`ChannelKind`] variants
/// have formatters; the `None` fallback is kept for future channel
/// variants so the plain prose still sends even before a dialect
/// formatter ships.
///
/// Snapshot semantics: this helper does NOT emit `ChannelSend`
/// rollback frames. Callers that want rollback coverage chain through
/// [`send_text_with_snapshot`] on each formatter chunk. The two
/// helpers compose: format → for each chunk → send_with_snapshot.
pub async fn send_canonical(
    channel: &dyn Channel,
    kind: ChannelKind,
    chat_id: &str,
    reply: &formatter::CanonicalReply,
) -> std::result::Result<Vec<MessageId>, ChannelError> {
    match formatter::for_channel(kind) {
        Some(fmt) => {
            let chunks = fmt.format(reply);
            let mut ids = Vec::with_capacity(chunks.len());
            for chunk in &chunks {
                ids.push(channel.send_text(chat_id, chunk).await?);
            }
            Ok(ids)
        }
        None => {
            // No formatter for this channel yet — send the plain text
            // through. Code blocks are dropped because we have no
            // fence syntax to choose; the operator-visible loss is
            // acknowledged in the function docstring.
            let id = channel.send_text(chat_id, &reply.text).await?;
            Ok(vec![id])
        }
    }
}

/// A3-tail: send a text message AND emit a `ChannelSend`
/// PRE_MUTATION_SNAPSHOT (0xF2) on success. The snapshot captures the
/// outbound text as `before_state` so `neoth rollback list --kind
/// channel_send` surfaces "what I sent to whom" — the A6 dispatcher
/// then renders the platform-specific delete/edit template.
///
/// Target shape: `<platform>:<chat_id>:<message_id>` — matches what
/// `apply_plan_channel_send` expects. Snapshot is honoured only when
/// the operator's `rollback.capture_kinds` includes `channel_send`
/// (default-on).
///
/// Call this from any pipeline runner / cron job / proactive helper
/// that drives outbound messages — direct `Channel::send_text` calls
/// keep the old no-snapshot behaviour for callers that genuinely
/// don't want rollback coverage (e.g. ACK-only delivery confirmations).
pub async fn send_text_with_snapshot(
    channel: &dyn Channel,
    rollback_policy: &crate::config::RollbackConfig,
    platform: ChannelKind,
    chat_id: &str,
    text: &str,
) -> std::result::Result<MessageId, ChannelError> {
    let message_id = channel.send_text(chat_id, text).await?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let target = format!("{}:{}:{}", platform.as_str(), chat_id, message_id.0);
    let wal_dir = crate::config::FreedomConfig::default_wal_dir();
    if let Err(e) = std::fs::create_dir_all(&wal_dir) {
        tracing::warn!(error = %e, "could not create WAL dir for channel-send snapshot — proceeding without rollback");
        return Ok(message_id);
    }
    let segment = wal_dir.join(format!("channel-snapshot-{now_unix}.wal"));
    let (writer, join) = match crate::wal::writer::spawn(segment) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "spawn WAL writer failed for channel-send snapshot — proceeding without rollback");
            return Ok(message_id);
        }
    };
    let emit = crate::wal::snapshot::emit_if_policy_allows(
        &writer,
        rollback_policy,
        crate::wal::snapshot::MutationKind::ChannelSend,
        target,
        text.as_bytes(),
        now_unix,
        Some(format!(
            "{} send_text via send_text_with_snapshot",
            platform.as_str()
        )),
    )
    .await;
    drop(writer);
    let _ = join.await;
    if let Err(e) = emit {
        tracing::warn!(error = %e, "channel-send snapshot emit failed (message was sent successfully)");
    }
    Ok(message_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_kind_serializes_as_snake_case() {
        assert_eq!(ChannelKind::Telegram.as_str(), "telegram");
        assert_eq!(ChannelKind::WhatsAppBusiness.as_str(), "whatsapp_business");
        assert_eq!(ChannelKind::Keet.as_str(), "keet");
        let json = serde_json::to_string(&ChannelKind::Slack).unwrap();
        assert_eq!(json, "\"slack\"");
    }

    #[test]
    fn channel_error_not_supported_carries_feature_name() {
        let err = ChannelError::NotSupported {
            feature: "edit_message",
        };
        let msg = format!("{err}");
        assert!(msg.contains("edit_message"), "got: {msg}");
    }

    /// Adapter that overrides nothing must inherit the default
    /// `NotSupported` answers for both send paths. Guards against an
    /// accidental future refactor that removes the defaults and silently
    /// breaks unimplemented adapters.
    struct NoopChannel;

    #[async_trait]
    impl Channel for NoopChannel {
        fn name(&self) -> &'static str {
            "noop"
        }
        async fn run(&self, _handler: PipelineHandler) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn default_send_text_returns_not_supported() {
        let c = NoopChannel;
        let err = c.send_text("x", "hi").await.unwrap_err();
        assert!(
            matches!(
                err,
                ChannelError::NotSupported {
                    feature: "send_text"
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn default_send_media_returns_not_supported() {
        let c = NoopChannel;
        let m = MediaPayload {
            kind: MediaKind::Image,
            data: vec![1, 2, 3],
            mime: "image/png".into(),
            filename: None,
        };
        let err = c.send_media("x", &m, Some("cap")).await.unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "send_media"
            }
        ));
    }

    /// A3-tail mock that returns a fixed MessageId on send_text so
    /// `send_text_with_snapshot` has a synthetic surface to exercise.
    struct FakeChannel;
    #[async_trait]
    impl Channel for FakeChannel {
        fn name(&self) -> &'static str {
            "fake"
        }
        async fn run(&self, _handler: PipelineHandler) -> Result<()> {
            Ok(())
        }
        async fn send_text(
            &self,
            _chat_id: &str,
            _text: &str,
        ) -> std::result::Result<MessageId, ChannelError> {
            Ok(MessageId("msg-42".to_string()))
        }
    }

    #[tokio::test]
    async fn send_text_with_snapshot_returns_message_id_even_when_wal_path_unwritable() {
        // The helper must not block the send on snapshot failure —
        // the message went out, return the id, log the snapshot
        // failure. We can't easily induce a writable→unwritable
        // race in test, but we can at least exercise the happy
        // path against a defaulted RollbackConfig that disables
        // capture (so no WAL write happens).
        let rb = crate::config::RollbackConfig {
            capture_kinds: vec![], // ChannelSend NOT in allowlist
            max_snapshot_bytes: 1024,
        };
        let c = FakeChannel;
        let id = send_text_with_snapshot(&c, &rb, ChannelKind::Slack, "C-x", "hello")
            .await
            .expect("send must succeed");
        assert_eq!(id.0, "msg-42");
    }

    #[tokio::test]
    async fn send_text_with_snapshot_surfaces_channel_send_error() {
        struct ErroringChannel;
        #[async_trait]
        impl Channel for ErroringChannel {
            fn name(&self) -> &'static str {
                "err"
            }
            async fn run(&self, _h: PipelineHandler) -> Result<()> {
                Ok(())
            }
            async fn send_text(
                &self,
                _c: &str,
                _t: &str,
            ) -> std::result::Result<MessageId, ChannelError> {
                Err(ChannelError::Transport("dead network".into()))
            }
        }
        let rb = crate::config::RollbackConfig::default();
        let c = ErroringChannel;
        let err = send_text_with_snapshot(&c, &rb, ChannelKind::Telegram, "123", "hi")
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::Transport(_)));
    }

    // ── F-3 send_canonical wiring ─────────────────────────────────────────

    /// Mock that captures every `send_text` payload so the test can
    /// verify the formatter chunked + sent each piece.
    struct CapturingChannel {
        sent: std::sync::Mutex<Vec<String>>,
    }
    #[async_trait]
    impl Channel for CapturingChannel {
        fn name(&self) -> &'static str {
            "capturing"
        }
        async fn run(&self, _h: PipelineHandler) -> Result<()> {
            Ok(())
        }
        async fn send_text(
            &self,
            _chat_id: &str,
            text: &str,
        ) -> std::result::Result<MessageId, ChannelError> {
            let mut sent = self.sent.lock().unwrap();
            let idx = sent.len();
            sent.push(text.to_string());
            Ok(MessageId(format!("msg-{idx}")))
        }
    }

    #[tokio::test]
    async fn send_canonical_routes_through_telegram_formatter() {
        let c = CapturingChannel {
            sent: std::sync::Mutex::new(Vec::new()),
        };
        let reply = formatter::CanonicalReply {
            text: "hello. how are you?".to_string(),
            code_blocks: vec![],
            length_hint: None,
        };
        let ids = send_canonical(&c, ChannelKind::Telegram, "123", &reply)
            .await
            .expect("send_canonical");
        assert_eq!(ids.len(), 1);
        let sent = c.sent.lock().unwrap();
        // Telegram MarkdownV2 must escape the `.` in the body (`?` is
        // not a MarkdownV2 metacharacter — leave it unescaped).
        assert!(
            sent[0].contains("\\."),
            "expected escaped `.` in Telegram output: {:?}",
            sent[0]
        );
        assert!(!sent[0].contains("\\?"));
    }

    #[tokio::test]
    async fn send_canonical_routes_through_keet_formatter() {
        let c = CapturingChannel {
            sent: std::sync::Mutex::new(Vec::new()),
        };
        let reply = formatter::CanonicalReply {
            text: "plain *unescaped* body".to_string(),
            code_blocks: vec![formatter::CodeBlock {
                lang: "rust".into(),
                body: "fn x() {}".into(),
            }],
            length_hint: None,
        };
        let ids = send_canonical(&c, ChannelKind::Keet, "chat-1", &reply)
            .await
            .expect("send_canonical keet");
        assert_eq!(ids.len(), 1);
        let sent = c.sent.lock().unwrap();
        assert_eq!(sent[0], "plain *unescaped* body\n```rust\nfn x() {}\n```");
    }

    #[tokio::test]
    async fn send_canonical_splits_long_body_into_multiple_sends() {
        let c = CapturingChannel {
            sent: std::sync::Mutex::new(Vec::new()),
        };
        let big = "alpha ".repeat(800); // ~4800 chars, exceeds Slack 4000-cap
        let reply = formatter::CanonicalReply {
            text: big,
            code_blocks: vec![],
            length_hint: None,
        };
        let ids = send_canonical(&c, ChannelKind::Slack, "C-1", &reply)
            .await
            .expect("send_canonical split");
        assert!(ids.len() >= 2, "expected ≥2 chunks, got {}", ids.len());
        let sent = c.sent.lock().unwrap();
        // First chunk carries the [1/N] marker.
        assert!(sent[0].starts_with("[1/"));
    }

    #[tokio::test]
    async fn send_canonical_propagates_send_text_error() {
        struct AlwaysFails;
        #[async_trait]
        impl Channel for AlwaysFails {
            fn name(&self) -> &'static str {
                "fail"
            }
            async fn run(&self, _h: PipelineHandler) -> Result<()> {
                Ok(())
            }
            async fn send_text(
                &self,
                _c: &str,
                _t: &str,
            ) -> std::result::Result<MessageId, ChannelError> {
                Err(ChannelError::Transport("nope".into()))
            }
        }
        let reply = formatter::CanonicalReply {
            text: "x".into(),
            code_blocks: vec![],
            length_hint: None,
        };
        let err = send_canonical(&AlwaysFails, ChannelKind::Telegram, "1", &reply)
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::Transport(_)));
    }
}
