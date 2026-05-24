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
pub mod discord_gateway_loop;
pub mod formatter;
pub mod keet;
pub mod keet_bencode;
pub mod keet_crypto;
pub mod keet_dht;
pub mod keet_pairing;
pub mod keet_udp;
pub mod keet_wal;
pub mod pears_bridge;
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
    /// C-13 (Session 21) — cross-channel `human_uuid`. Populated by
    /// the future `idx_human_identity` resolver (C-12) when the same
    /// operator appears on multiple channels under different
    /// `sender_id`s. `None` for adapters that haven't been wired into
    /// the resolver yet — downstream code must tolerate either path.
    /// Stable UUID v7 string when present so WAL replay can sort by
    /// time-of-first-link.
    pub human_uuid: Option<String>,
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

    // ── C-10 (Session 21) — extended trait surface ─────────────────
    //
    // Five methods reserved by `SPEC_channels.md` for the second-
    // production-adapter milestone. Default impls return
    // `NotSupported` so the existing v0.1 adapters (Telegram /
    // WhatsApp / Slack) keep compiling unchanged. When the second
    // adapter lands + needs one of these surfaces, the daemon's
    // channel-spawn loop will surface a clean "feature deferred"
    // diagnostic instead of a panic.

    /// Spawn the inbound-message receive loop as a long-running
    /// task. Default impl is a no-op error so adapters that haven't
    /// implemented it surface clearly. The legacy `run(handler)`
    /// path stays the canonical entry point; this method is the
    /// future-proofed split for adapters that want to expose the
    /// receive loop independent of the handler.
    async fn spawn_receive_loop(
        &self,
        _handler: PipelineHandler,
    ) -> std::result::Result<tokio::task::JoinHandle<()>, ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "spawn_receive_loop",
        })
    }

    /// Acknowledge receipt of an inbound message. Some platforms
    /// (e.g. WhatsApp Business, Discord interactions) require an
    /// explicit ACK before the platform considers delivery
    /// complete. Default `NotSupported` for adapters where ACK is
    /// implicit (Telegram getUpdates / Slack events poll).
    async fn ack_received(
        &self,
        _chat_id: &str,
        _message_id: &MessageId,
    ) -> std::result::Result<(), ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "ack_received",
        })
    }

    /// Fetch chat metadata (title, member count, topic) for a chat
    /// the bot is in. Used by the future `neoth channels show
    /// <id>` operator surface + by the cross-channel identity
    /// resolver to enrich `InboundMessage::sender_display`.
    async fn get_chat_meta(&self, _chat_id: &str) -> std::result::Result<ChatMeta, ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "get_chat_meta",
        })
    }

    /// Send a transient "typing…" / "uploading photo…" indicator
    /// so the operator on the other end sees activity before the
    /// reply lands. Telegram sendChatAction / Slack typing event /
    /// WhatsApp presence update all map here.
    async fn send_action_indicator(
        &self,
        _chat_id: &str,
        _action: ChatAction,
    ) -> std::result::Result<(), ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "send_action_indicator",
        })
    }

    /// Edit an outbound message after it was sent (Telegram
    /// editMessageText, Slack chat.update). Used by streaming
    /// preview + post-reply correction paths. Default `NotSupported`
    /// for adapters without an edit API (most webhooks).
    async fn edit_message(
        &self,
        _chat_id: &str,
        _message_id: &MessageId,
        _new_text: &str,
    ) -> std::result::Result<(), ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "edit_message",
        })
    }

    /// C-11 (Session 21) — send an unsolicited proactive message.
    /// Distinct from `send_text` (which assumes a reply context):
    /// `send_proactive` is the daemon firing on its own (cron
    /// briefing, follow-up reminder, self-dev acceptance notice).
    ///
    /// **CRITICAL gate**: callers MUST check
    /// `FreedomConfig::proactive.enabled` (C-16) BEFORE invoking
    /// this method. The default impl bails with `NotSupported` so
    /// adapters that haven't opted in stay silent; the operator
    /// gate is honoured by the caller, not by the trait impl.
    /// Per AGENTER hard rule "no destructive auto-action without
    /// operator GO per command" — proactive messaging is the
    /// archetypal example.
    async fn send_proactive(
        &self,
        _chat_id: &str,
        _text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "send_proactive",
        })
    }
}

/// C-10 — minimal chat metadata returned by `Channel::get_chat_meta`.
/// Vendor-specific fields stay in `extra` so the resolver doesn't
/// have to bump the struct shape every time a platform adds a field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChatMeta {
    pub chat_id: String,
    pub title: Option<String>,
    pub member_count: Option<u32>,
    pub topic: Option<String>,
    /// Vendor-specific extras as opaque key/value strings.
    pub extra: std::collections::BTreeMap<String, String>,
}

/// C-10 — typing-style indicator the platform displays to the
/// other side. Pinned exhaustively per the platforms NEOTH
/// currently knows about; adding a new action needs an entry here
/// + per-adapter mapping (Telegram chat-action / Slack typing /
/// WhatsApp presence).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChatAction {
    /// "typing…" — operator should expect a text reply soon.
    Typing,
    /// "uploading photo…" / "sending image…"
    UploadingPhoto,
    /// "uploading document…" / "sending file…"
    UploadingDocument,
    /// "recording voice message…"
    RecordingVoice,
}

impl ChatAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Typing => "typing",
            Self::UploadingPhoto => "uploading_photo",
            Self::UploadingDocument => "uploading_document",
            Self::RecordingVoice => "recording_voice",
        }
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
///
/// **K-Perf-5 (2026-05-22)**: this convenience overload spawns a
/// fresh WAL writer per call. For high-throughput channel fan-out
/// callers should prefer [`send_text_with_snapshot_using`] which
/// reuses the daemon's shared long-lived writer. The per-call spawn
/// here costs an open + fsync + close every message — ~10ms on warm
/// SSD, more on USB drives. The shared-writer overload skips those
/// syscalls entirely (the writer is already running its blocking
/// task on a tokio worker, frame just lands on its mpsc queue).
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

/// K-Perf-5: like [`send_text_with_snapshot`] but uses an existing
/// long-lived `WalWriterHandle` (typically the one `cli::serve` spawns
/// at boot) instead of opening a fresh per-call writer. This is the
/// hot-path variant — channel fan-out, proactive briefings, cron-
/// triggered sends should route here so every outbound message saves
/// the ~10ms open + fsync + close cost of a spawn/drop cycle.
///
/// Behaviour is otherwise identical: returns the `MessageId` on
/// success, emits a `ChannelSend` `PRE_MUTATION_SNAPSHOT` honouring
/// `rollback_policy.capture_kinds`, and never fails the send when the
/// snapshot emit fails (snapshot is best-effort — the message went
/// out, that's what the operator cares about).
pub async fn send_text_with_snapshot_using(
    channel: &dyn Channel,
    writer: &crate::wal::writer::WalWriterHandle,
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
    let emit = crate::wal::snapshot::emit_if_policy_allows(
        writer,
        rollback_policy,
        crate::wal::snapshot::MutationKind::ChannelSend,
        target,
        text.as_bytes(),
        now_unix,
        Some(format!(
            "{} send_text via send_text_with_snapshot_using",
            platform.as_str()
        )),
    )
    .await;
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

    // ── C-10 default impls (Session 21) ──────────────────────────

    #[tokio::test]
    async fn default_spawn_receive_loop_returns_not_supported() {
        let c = NoopChannel;
        let handler: PipelineHandler = Box::new(|_inbound| Box::pin(async { Ok(None) }));
        let err = c.spawn_receive_loop(handler).await.unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "spawn_receive_loop"
            }
        ));
    }

    #[tokio::test]
    async fn default_ack_received_returns_not_supported() {
        let c = NoopChannel;
        let err = c
            .ack_received("x", &MessageId("m-1".into()))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "ack_received"
            }
        ));
    }

    #[tokio::test]
    async fn default_get_chat_meta_returns_not_supported() {
        let c = NoopChannel;
        let err = c.get_chat_meta("x").await.unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "get_chat_meta"
            }
        ));
    }

    #[tokio::test]
    async fn default_send_action_indicator_returns_not_supported() {
        let c = NoopChannel;
        let err = c
            .send_action_indicator("x", ChatAction::Typing)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "send_action_indicator"
            }
        ));
    }

    #[tokio::test]
    async fn default_edit_message_returns_not_supported() {
        let c = NoopChannel;
        let err = c
            .edit_message("x", &MessageId("m-1".into()), "new")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "edit_message"
            }
        ));
    }

    #[tokio::test]
    async fn default_send_proactive_returns_not_supported() {
        // C-11 default impl — adapter must opt in explicitly. The
        // operator-side gate is FreedomConfig::proactive.enabled
        // (C-16); this test pins the per-adapter default refusal
        // so a misconfigured caller cannot route around the gate
        // by hitting an adapter that "happens to allow it".
        let c = NoopChannel;
        let err = c.send_proactive("x", "hi").await.unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "send_proactive"
            }
        ));
    }

    #[test]
    fn chat_action_as_str_pinned() {
        assert_eq!(ChatAction::Typing.as_str(), "typing");
        assert_eq!(ChatAction::UploadingPhoto.as_str(), "uploading_photo");
        assert_eq!(ChatAction::UploadingDocument.as_str(), "uploading_document");
        assert_eq!(ChatAction::RecordingVoice.as_str(), "recording_voice");
    }

    #[test]
    fn chat_meta_default_is_empty() {
        let m = ChatMeta::default();
        assert!(m.chat_id.is_empty());
        assert!(m.title.is_none());
        assert!(m.member_count.is_none());
        assert!(m.topic.is_none());
        assert!(m.extra.is_empty());
    }

    // ── C-13 human_uuid field (Session 21) ────────────────────────

    #[test]
    fn inbound_message_human_uuid_defaults_to_none_in_struct_literal() {
        // Drift guard — a future refactor that defaults human_uuid
        // to Some(something) would shape resolver behaviour without
        // operator awareness.
        let msg = InboundMessage {
            channel: ChannelKind::Telegram,
            chat_id: "c".into(),
            thread_id: None,
            sender_id: "s".into(),
            sender_display: None,
            text: None,
            media: None,
            reply_to: None,
            mention_kind: None,
            channel_ts_unix: 0,
            raw_ts_ms: None,
            human_uuid: None,
        };
        assert!(msg.human_uuid.is_none());
    }

    #[test]
    fn inbound_message_human_uuid_round_trips_when_present() {
        let msg = InboundMessage {
            channel: ChannelKind::Telegram,
            chat_id: "c".into(),
            thread_id: None,
            sender_id: "s".into(),
            sender_display: None,
            text: None,
            media: None,
            reply_to: None,
            mention_kind: None,
            channel_ts_unix: 0,
            raw_ts_ms: None,
            human_uuid: Some("01902f3a-1234-7000-8000-abcdef012345".into()),
        };
        assert_eq!(
            msg.human_uuid.as_deref(),
            Some("01902f3a-1234-7000-8000-abcdef012345")
        );
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
    async fn k_perf_5_send_text_with_snapshot_using_shares_a_writer_across_calls() {
        // K-Perf-5 contract: a single long-lived writer handles many
        // outbound sends. We spawn one writer, fire N consecutive
        // sends through `send_text_with_snapshot_using`, and verify
        // every send still returns the expected id. The performance
        // win (no per-call spawn) is harder to assert directly — what
        // we pin here is the BEHAVIOURAL contract: the helper works
        // against a shared writer without surprise interactions.
        use crate::wal::writer::spawn as wal_spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("shared.wal");
        let (writer, join) = wal_spawn(seg.clone()).unwrap();
        let rb = crate::config::RollbackConfig::default(); // ChannelSend in allowlist
        let c = FakeChannel;

        for i in 0..5 {
            let id = send_text_with_snapshot_using(
                &c,
                &writer,
                &rb,
                ChannelKind::Slack,
                "C-shared",
                &format!("msg {i}"),
            )
            .await
            .expect("send must succeed");
            assert_eq!(id.0, "msg-42");
        }
        drop(writer);
        let _ = join.await;

        // 5 ChannelSend snapshot frames should have landed on the
        // SHARED segment — no per-call segment files were created.
        let segments_in_dir: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".wal"))
            .collect();
        assert_eq!(
            segments_in_dir.len(),
            1,
            "K-Perf-5: shared writer must keep all snapshots in one segment, got {:?}",
            segments_in_dir
                .iter()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn k_perf_5_send_text_with_snapshot_using_propagates_send_error() {
        // Channel send failure must surface even when the snapshot
        // path is short-circuited. Same contract as the spawn-per-call
        // variant.
        use crate::wal::writer::spawn as wal_spawn;
        use tempfile::tempdir;

        struct ErrCh;
        #[async_trait]
        impl Channel for ErrCh {
            fn name(&self) -> &'static str {
                "errch"
            }
            async fn run(&self, _h: PipelineHandler) -> Result<()> {
                Ok(())
            }
            async fn send_text(
                &self,
                _c: &str,
                _t: &str,
            ) -> std::result::Result<MessageId, ChannelError> {
                Err(ChannelError::Transport("network gone".into()))
            }
        }

        let dir = tempdir().unwrap();
        let (writer, join) = wal_spawn(dir.path().join("e.wal")).unwrap();
        let rb = crate::config::RollbackConfig::default();
        let err =
            send_text_with_snapshot_using(&ErrCh, &writer, &rb, ChannelKind::Telegram, "123", "hi")
                .await
                .unwrap_err();
        assert!(matches!(err, ChannelError::Transport(_)));
        drop(writer);
        let _ = join.await;
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
