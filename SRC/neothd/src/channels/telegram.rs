//! Telegram channel adapter.
//!
//! Long-polling via teloxide. No webhooks (operator does not need a public
//! HTTPS endpoint). Optional allowlist locks the bot to a single Telegram
//! user-id, matching the wizard's "restrict to a single user" prompt.
//!
//! Per the self-contained hard rule: only thing the operator supplies is the
//! bot token from @BotFather and (optionally) their own Telegram user-id.
//! Everything else — polling, sendMessage, error backoff — lives in NEOTH.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::{FileId, ParseMode, PhotoSize};

use super::{
    Channel, ChannelError, ChannelKind, InboundMessage, MediaKind, MediaPayload, MessageId,
    PipelineHandler,
};
use crate::secret::SecretString;

/// Hard ceiling on inbound attachment size. Matches the vision +
/// WAL writer 16 MiB ceiling so a Telegram-side bypass cannot
/// exceed downstream payload budgets.
const MAX_INBOUND_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;

pub struct TelegramChannel {
    token: SecretString,
    /// Optional allowlist. `None` = open to anyone (DO NOT do this in
    /// production). `Some(id)` = only that single Telegram user_id may
    /// interact. Group chats are rejected unless the bot is explicitly
    /// mentioned (deferred to V2).
    allowed_user_id: Option<u64>,
}

impl TelegramChannel {
    pub fn new(token: SecretString, allowed_user_id: Option<u64>) -> Self {
        Self {
            token,
            allowed_user_id,
        }
    }
}

#[async_trait]
impl Channel for TelegramChannel {
    fn name(&self) -> &'static str {
        "telegram"
    }

    /// SP-5 C-prime: send a plain text message via Telegram `sendMessage`.
    /// `chat_id` is the numeric chat id rendered as a decimal string (matches
    /// how `InboundMessage::chat_id` is populated). Markdown rendering uses
    /// MarkdownV2 with a plain-text fallback on parse error.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        use teloxide::types::ChatId;

        let id: i64 = chat_id.parse().map_err(|e: std::num::ParseIntError| {
            ChannelError::Transport(format!("chat_id parse: {e}"))
        })?;
        let bot = Bot::new(self.token.expose());

        let send = bot
            .send_message(ChatId(id), text)
            .parse_mode(ParseMode::MarkdownV2)
            .await;
        let msg = match send {
            Ok(m) => m,
            Err(_) => bot
                .send_message(ChatId(id), text)
                .await
                .map_err(|e| ChannelError::Transport(format!("telegram sendMessage: {e}")))?,
        };
        Ok(MessageId(msg.id.0.to_string()))
    }

    /// C-11 wire-up (Session 21): proactive send delegates to `send_text`.
    /// The wire-level Telegram sendMessage call is identical for solicited
    /// replies vs daemon-initiated proactive — the operator-gate
    /// (`FreedomConfig::proactive.enabled`) is the CALLER's
    /// responsibility per the C-11 trait contract, NOT this adapter's.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.send_text(chat_id, text).await
    }

    /// SP-5 C-prime: media send. Not wired through teloxide yet (no operator
    /// pressure for proactive media at v0.1.x); explicit `NotSupported` keeps
    /// the pipeline honest until R-9 multimodal lands.
    async fn send_media(
        &self,
        _chat_id: &str,
        _media: &MediaPayload,
        _caption: Option<&str>,
    ) -> std::result::Result<MessageId, ChannelError> {
        Err(ChannelError::NotSupported {
            feature: "telegram.send_media",
        })
    }

    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        let bot = Bot::new(self.token.expose());
        // Verify the bot token before starting the long-poll loop. Helpful
        // failure mode: clear error on bad token instead of silent retry.
        let me = bot
            .get_me()
            .await
            .context("Telegram getMe failed. Bad bot token, or no network?")?;
        tracing::info!(
            bot = me.username.as_deref().unwrap_or("(unknown)"),
            "Telegram bot connected"
        );

        let handler = Arc::new(handler);
        let allowed = self.allowed_user_id;

        teloxide::repl(bot.clone(), move |bot: Bot, msg: Message| {
            let handler = Arc::clone(&handler);
            async move {
                let result = handle_one_message(bot, msg, handler, allowed).await;
                if let Err(e) = result {
                    tracing::warn!(error = %e, "Telegram message handler error");
                }
                respond(())
            }
        })
        .await;
        Ok(())
    }
}

async fn handle_one_message(
    bot: Bot,
    msg: Message,
    handler: Arc<PipelineHandler>,
    allowed_user_id: Option<u64>,
) -> Result<()> {
    let Some(from) = msg.from.as_ref() else {
        // Non-user message (channel post, service message). Ignore.
        return Ok(());
    };

    // Allowlist check FIRST — before we read the text, before we touch the
    // WAL, before any provider call. Rejected messages get logged + dropped;
    // we do NOT send a "you are not allowed" reply (information leak).
    if let Some(allowed) = allowed_user_id {
        if from.id.0 != allowed {
            tracing::warn!(
                from_id = from.id.0,
                allowed_id = allowed,
                "Telegram message dropped: sender not on allowlist"
            );
            return Ok(());
        }
    }

    // Detect message kind. Order matters: photo/voice/audio/document
    // populate `media`; bare text falls through to the existing path.
    let media = match download_attachment_if_any(&bot, &msg).await {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(error = %e, "Telegram attachment download failed");
            let _ = bot
                .send_message(
                    msg.chat.id,
                    format!("[NEOTH] could not download attachment: {e}"),
                )
                .await;
            return Ok(());
        }
    };

    let text = msg
        .text()
        .map(|s| s.to_string())
        .or_else(|| msg.caption().map(|s| s.to_string()));

    if text.is_none() && media.is_none() {
        // Sticker / location / poll / service event. Acknowledge so
        // the operator knows their message hit NEOTH but the type
        // isn't supported in v0.1.x.
        bot.send_message(
            msg.chat.id,
            "[NEOTH] message kind not supported in v0.1.x (no text, no photo/voice/audio).",
        )
        .await
        .context("Telegram sendMessage (unsupported-kind reply)")?;
        return Ok(());
    }

    let inbound = InboundMessage {
        channel: ChannelKind::Telegram,
        chat_id: msg.chat.id.to_string(),
        thread_id: msg.thread_id.map(|t| t.0.to_string()),
        sender_id: from.id.0.to_string(),
        sender_display: from
            .username
            .clone()
            .or_else(|| Some(from.first_name.clone())),
        text,
        media,
        reply_to: None,
        mention_kind: None,
        channel_ts_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        raw_ts_ms: Some(msg.date.timestamp() * 1000),
        human_uuid: None,
    };

    match handler(inbound).await {
        Ok(Some(out)) => {
            // Reply via Markdown so basic code blocks render. teloxide may
            // reject malformed Markdown — fall back to plain text on error.
            let send_result = bot
                .send_message(msg.chat.id, &out.text)
                .parse_mode(ParseMode::MarkdownV2)
                .await;
            if send_result.is_err() {
                // Markdown parser is strict; retry as plain.
                bot.send_message(msg.chat.id, &out.text)
                    .await
                    .context("Telegram sendMessage (plain retry)")?;
            }
        }
        Ok(None) => {
            // Pipeline chose to drop silently. No reply, no error.
        }
        Err(e) => {
            // Provider failure or WAL failure. Tell the operator something
            // went wrong without leaking internals.
            tracing::warn!(error = %e, "pipeline error for Telegram message");
            bot.send_message(msg.chat.id, "[NEOTH] internal error; see daemon logs.")
                .await
                .context("Telegram sendMessage (error notice)")?;
        }
    }

    Ok(())
}

/// Detect + download the first eligible attachment on `msg`. Returns
/// `Ok(None)` when the message is text-only or carries an unsupported
/// attachment type (sticker, location, …). On real download failures
/// returns `Err` so the handler can surface the issue to the operator.
///
/// Supported today: `photo` (largest variant), `voice`, `audio`.
/// Documents are deferred — we'd need to honor mime + extension
/// detection before routing them.
async fn download_attachment_if_any(bot: &Bot, msg: &Message) -> Result<Option<MediaPayload>> {
    if let Some(photos) = msg.photo() {
        let Some(largest) = pick_largest_photo(photos) else {
            return Ok(None);
        };
        let bytes = download_telegram_file(bot, &largest.file.id.0).await?;
        return Ok(Some(MediaPayload {
            kind: MediaKind::Image,
            mime: "image/jpeg".to_string(), // Telegram converts photos to JPEG.
            filename: None,
            data: bytes,
        }));
    }
    if let Some(voice) = msg.voice() {
        let bytes = download_telegram_file(bot, &voice.file.id.0).await?;
        return Ok(Some(MediaPayload {
            kind: MediaKind::Audio,
            mime: voice
                .mime_type
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "audio/ogg".to_string()),
            filename: None,
            data: bytes,
        }));
    }
    if let Some(audio) = msg.audio() {
        let bytes = download_telegram_file(bot, &audio.file.id.0).await?;
        return Ok(Some(MediaPayload {
            kind: MediaKind::Audio,
            mime: audio
                .mime_type
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "audio/mpeg".to_string()),
            filename: audio.file_name.clone(),
            data: bytes,
        }));
    }
    Ok(None)
}

fn pick_largest_photo(photos: &[PhotoSize]) -> Option<&PhotoSize> {
    photos
        .iter()
        .max_by_key(|p| (p.width as u64) * (p.height as u64))
}

async fn download_telegram_file(bot: &Bot, file_id: &str) -> Result<Vec<u8>> {
    // teloxide 0.17 wraps file_id in a newtype.
    let file = bot
        .get_file(FileId(file_id.to_string()))
        .await
        .context("Telegram getFile")?;
    // Pre-download gate: if Telegram reports a non-zero size and it's
    // already over the ceiling, refuse without paying the network cost.
    // file.size == 0 happens for some voice messages where the API
    // omits the field; treat that as "unknown size" and rely on the
    // post-download buffer-length check below.
    if file.size > 0 && (file.size as usize) > MAX_INBOUND_ATTACHMENT_BYTES {
        anyhow::bail!(
            "attachment {} bytes exceeds {} ceiling",
            file.size,
            MAX_INBOUND_ATTACHMENT_BYTES
        );
    }
    let capacity_hint = if file.size > 0 {
        (file.size as usize).min(MAX_INBOUND_ATTACHMENT_BYTES)
    } else {
        // Conservative initial allocation — `Vec::extend_from_slice`
        // will grow if the actual transfer is bigger, and the post-
        // download check enforces the real ceiling.
        64 * 1024
    };
    let mut buf: Vec<u8> = Vec::with_capacity(capacity_hint);
    bot.download_file(&file.path, &mut buf)
        .await
        .context("Telegram download_file")?;
    // Post-download gate: covers the unknown-size case + a server that
    // reports a bogus size in the metadata response.
    if buf.len() > MAX_INBOUND_ATTACHMENT_BYTES {
        anyhow::bail!(
            "downloaded {} bytes exceeds {} ceiling (metadata reported size={})",
            buf.len(),
            MAX_INBOUND_ATTACHMENT_BYTES,
            file.size,
        );
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_reports_name() {
        let t = TelegramChannel::new(SecretString::from("dummy"), Some(123));
        assert_eq!(t.name(), "telegram");
    }

    #[test]
    fn pick_largest_photo_returns_max_area_variant() {
        let mk = |w: u32, h: u32| PhotoSize {
            file: teloxide::types::FileMeta {
                id: teloxide::types::FileId(format!("{w}x{h}")),
                unique_id: teloxide::types::FileUniqueId(format!("u-{w}x{h}")),
                size: w * h,
            },
            width: w,
            height: h,
        };
        let photos = vec![mk(64, 64), mk(320, 240), mk(800, 600), mk(640, 480)];
        let largest = pick_largest_photo(&photos).expect("non-empty");
        assert_eq!(largest.width, 800);
        assert_eq!(largest.height, 600);
    }

    #[test]
    fn pick_largest_photo_returns_none_for_empty() {
        let photos: Vec<PhotoSize> = vec![];
        assert!(pick_largest_photo(&photos).is_none());
    }

    /// C-11 wire-up pin: with a bogus token, both send_text +
    /// send_proactive surface a Transport error (not NotSupported).
    /// Proves the wire-up landed: the trait default would have
    /// returned NotSupported for send_proactive. Network call shape
    /// is identical to send_text — the test forces the chat_id parse
    /// failure path so no actual Telegram HTTP request happens.
    #[tokio::test]
    async fn send_proactive_delegates_to_send_text_returns_transport_error_on_bad_chat_id() {
        let t = TelegramChannel::new(SecretString::from("dummy-token"), None);
        let err = t.send_proactive("not-a-number", "hi").await.unwrap_err();
        assert!(
            matches!(err, ChannelError::Transport(_)),
            "expected Transport (delegate to send_text path); got {err:?}"
        );
        // Belt-and-suspenders: ensure we did NOT fall through to
        // the trait default `NotSupported { feature: "send_proactive" }`.
        let msg = format!("{err}");
        assert!(!msg.contains("not supported"), "leaked default impl: {msg}");
    }
}
