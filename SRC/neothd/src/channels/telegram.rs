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
use std::future::Future;
use std::sync::Arc;

use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::{FileId, InputFile, ParseMode, PhotoSize};

use super::{
    Channel, ChannelError, ChannelKind, InboundMessage, MediaKind, MediaPayload, MessageId,
    PipelineHandler,
};
use crate::secret::SecretString;

/// Hard ceiling on inbound attachment size. Matches the vision +
/// WAL writer 16 MiB ceiling so a Telegram-side bypass cannot
/// exceed downstream payload budgets.
const MAX_INBOUND_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;

/// Outbound media is held in memory by `InputFile::memory`, so keep the
/// project-wide 16 MiB ceiling even though some Telegram endpoints currently
/// accept larger uploads. Photos and stickers have stricter Bot API limits.
const MAX_OUTBOUND_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTBOUND_PHOTO_BYTES: usize = 10 * 1024 * 1024;
const MAX_OUTBOUND_STICKER_BYTES: usize = 512 * 1024;
const MAX_TELEGRAM_CAPTION_CHARS: usize = 1024;
const MAX_INLINE_RETRY_AFTER_SECS: u32 = 5;

pub struct TelegramChannel {
    token: SecretString,
    /// Optional allowlist. `None` = open to anyone (DO NOT do this in
    /// production). `Some(id)` = only that single Telegram user_id may
    /// interact, including in group chats. There is currently no separate
    /// mention-only group mode; the sender allowlist remains authoritative.
    allowed_user_id: Option<u64>,
    /// SF-03: optional daemon WAL writer so the allowlist gate can emit a
    /// `0x3B CHANNEL_GATE_REJECTED` audit frame when it drops a
    /// non-allowlisted sender. The daemon owns the single WAL writer; the
    /// adapter borrows a clone purely for this gate audit. `None` (the
    /// default, e.g. in tests) keeps the pre-SF-03 tracing-only drop.
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
}

impl TelegramChannel {
    pub fn new(token: SecretString, allowed_user_id: Option<u64>) -> Self {
        Self {
            token,
            allowed_user_id,
            gate_writer: None,
        }
    }

    /// SF-03: attach the daemon's WAL writer so allowlist-rejected senders
    /// are audited via `0x3B CHANNEL_GATE_REJECTED` instead of being
    /// dropped tracing-only. The daemon is the single writer; this is a
    /// cheap `WalWriterHandle` clone (an `mpsc` sender), so there is no
    /// second-writer/single-writer-invariant conflict.
    pub fn with_gate_writer(mut self, writer: crate::wal::writer::WalWriterHandle) -> Self {
        self.gate_writer = Some(writer);
        self
    }

    /// Validate the bot token WITHOUT starting the long-poll loop — calls
    /// Telegram `getMe` and returns the bot's `@username` on success. This is
    /// the live pre-flight behind `neoth channel test telegram`: a bad token
    /// surfaces here as a clear error instead of a silent retry at daemon
    /// startup (the same `get_me()` the `run` loop does, hoisted to a check).
    pub async fn validate(&self) -> std::result::Result<String, ChannelError> {
        let bot = Bot::new(self.token.expose());
        let me = bot
            .get_me()
            .await
            .map_err(|e| self.map_request_error("getMe", e))?;
        Ok(me
            .username
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string()))
    }

    fn map_request_error(
        &self,
        operation: &'static str,
        error: teloxide::RequestError,
    ) -> ChannelError {
        map_request_error(self.token.expose(), operation, error)
    }
}

fn map_request_error(
    token: &str,
    operation: &'static str,
    error: teloxide::RequestError,
) -> ChannelError {
    match error {
        teloxide::RequestError::RetryAfter(wait) => ChannelError::RateLimited {
            retry_after_secs: u64::from(wait.seconds()),
        },
        error => ChannelError::Transport(format!(
            "telegram {operation}: {}",
            redact_token(&error.to_string(), token)
        )),
    }
}

/// Retry exactly once only when Telegram explicitly says the request was
/// rejected for a short flood-control interval. Network failures are not
/// retried here because the server may already have accepted the upload and a
/// blind retry could duplicate operator-visible media.
async fn request_with_short_rate_limit_retry<F, Fut, T>(
    mut request: F,
) -> std::result::Result<T, teloxide::RequestError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, teloxide::RequestError>>,
{
    match request().await {
        Err(teloxide::RequestError::RetryAfter(wait))
            if wait.seconds() <= MAX_INLINE_RETRY_AFTER_SECS =>
        {
            tokio::time::sleep(wait.duration()).await;
            request().await
        }
        result => result,
    }
}

async fn send_bot_text(
    bot: &Bot,
    chat_id: teloxide::types::ChatId,
    text: &str,
) -> std::result::Result<teloxide::types::Message, ChannelError> {
    let send = request_with_short_rate_limit_retry(|| {
        let request = bot
            .send_message(chat_id, text.to_string())
            .parse_mode(ParseMode::MarkdownV2);
        async move { request.await }
    })
    .await;
    match send {
        Ok(message) => Ok(message),
        Err(teloxide::RequestError::Api(teloxide::ApiError::CantParseEntities(_))) => {
            request_with_short_rate_limit_retry(|| {
                let request = bot.send_message(chat_id, text.to_string());
                async move { request.await }
            })
            .await
            .map_err(|error| map_request_error(bot.token(), "sendMessage", error))
        }
        Err(error) => Err(map_request_error(bot.token(), "sendMessage", error)),
    }
}

fn redact_token(message: &str, token: &str) -> String {
    if token.is_empty() {
        return message.to_string();
    }
    message.replace(token, "[REDACTED]")
}

fn default_outbound_filename(media: &MediaPayload) -> &'static str {
    match (media.kind, media.mime.trim().to_ascii_lowercase().as_str()) {
        (MediaKind::Image, "image/png") => "image.png",
        (MediaKind::Image, _) => "image.jpg",
        (MediaKind::Video, _) => "video.mp4",
        (MediaKind::Audio, "audio/mp4" | "audio/m4a" | "audio/x-m4a") => "audio.m4a",
        (MediaKind::Audio, _) => "audio.mp3",
        (MediaKind::Document, _) => "document.bin",
        (MediaKind::Sticker, "video/webm") => "sticker.webm",
        (MediaKind::Sticker, "application/x-tgsticker") => "sticker.tgs",
        (MediaKind::Sticker, _) => "sticker.webp",
    }
}

fn safe_outbound_filename(media: &MediaPayload) -> std::result::Result<String, ChannelError> {
    let raw = media
        .filename
        .as_deref()
        .unwrap_or_else(|| default_outbound_filename(media));
    let name = raw.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    if name.is_empty() || name.chars().count() > 255 || name.chars().any(|ch| ch.is_control()) {
        return Err(ChannelError::Transport(
            "telegram outbound media has an invalid filename".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn valid_document_mime(mime: &str) -> bool {
    mime.len() <= 127
        && mime.is_ascii()
        && !mime.chars().any(char::is_whitespace)
        && mime
            .split_once('/')
            .is_some_and(|(top, sub)| !top.is_empty() && !sub.is_empty())
}

fn validate_outbound_media(media: &MediaPayload) -> std::result::Result<String, ChannelError> {
    if media.data.is_empty() {
        return Err(ChannelError::Transport(
            "telegram outbound media payload is empty".to_string(),
        ));
    }
    let size_cap = match media.kind {
        MediaKind::Image => MAX_OUTBOUND_PHOTO_BYTES,
        MediaKind::Sticker => MAX_OUTBOUND_STICKER_BYTES,
        MediaKind::Video | MediaKind::Audio | MediaKind::Document => MAX_OUTBOUND_ATTACHMENT_BYTES,
    };
    if media.data.len() > size_cap {
        return Err(ChannelError::Transport(format!(
            "telegram outbound media is {} bytes; limit for {:?} is {size_cap}",
            media.data.len(),
            media.kind
        )));
    }

    let mime = media.mime.trim().to_ascii_lowercase();
    let mime_ok = match media.kind {
        MediaKind::Image => matches!(mime.as_str(), "image/jpeg" | "image/png"),
        MediaKind::Video => mime == "video/mp4",
        MediaKind::Audio => matches!(
            mime.as_str(),
            "audio/mpeg" | "audio/mp4" | "audio/m4a" | "audio/x-m4a"
        ),
        MediaKind::Document => valid_document_mime(&mime),
        MediaKind::Sticker => matches!(
            mime.as_str(),
            "image/webp" | "application/x-tgsticker" | "video/webm"
        ),
    };
    if !mime_ok {
        return Err(ChannelError::Transport(format!(
            "telegram outbound {:?} rejects MIME type {mime:?}",
            media.kind
        )));
    }
    safe_outbound_filename(media)
}

fn plan_caption(kind: MediaKind, caption: Option<&str>) -> (Option<String>, Option<String>) {
    let caption = caption.filter(|value| !value.is_empty());
    let attached = caption
        .filter(|value| {
            kind != MediaKind::Sticker && value.chars().count() <= MAX_TELEGRAM_CAPTION_CHARS
        })
        .map(str::to_string);
    let follow_up = caption.filter(|_| attached.is_none()).map(str::to_string);
    (attached, follow_up)
}

#[async_trait]
impl Channel for TelegramChannel {
    fn name(&self) -> &'static str {
        "telegram"
    }

    fn supports_message_edits(&self) -> bool {
        true
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
        let msg = send_bot_text(&bot, ChatId(id), text).await?;
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

    /// Outbound Telegram media is uploaded from bounded in-memory bytes. Every
    /// `MediaKind` maps to its native Bot API method; MIME, filename and size
    /// are validated before the first network byte. Captions that do not fit
    /// Telegram's 1024-character media limit (and sticker captions, which the
    /// API does not support) are delivered as formatted follow-up messages.
    async fn send_media(
        &self,
        chat_id: &str,
        media: &MediaPayload,
        caption: Option<&str>,
    ) -> std::result::Result<MessageId, ChannelError> {
        use teloxide::types::ChatId;

        let id: i64 = chat_id.parse().map_err(|e: std::num::ParseIntError| {
            ChannelError::Transport(format!("chat_id parse: {e}"))
        })?;
        let filename = validate_outbound_media(media)?;
        let (attach_caption, follow_up_caption) = plan_caption(media.kind, caption);
        let bot = Bot::new(self.token.expose());

        let message = match media.kind {
            MediaKind::Image => {
                request_with_short_rate_limit_retry(|| {
                    let request = bot.send_photo(
                        ChatId(id),
                        InputFile::memory(media.data.clone()).file_name(filename.clone()),
                    );
                    let caption = attach_caption.clone();
                    async move {
                        match caption {
                            Some(caption) => request.caption(caption).await,
                            None => request.await,
                        }
                    }
                })
                .await
            }
            MediaKind::Video => {
                request_with_short_rate_limit_retry(|| {
                    let request = bot.send_video(
                        ChatId(id),
                        InputFile::memory(media.data.clone()).file_name(filename.clone()),
                    );
                    let caption = attach_caption.clone();
                    async move {
                        match caption {
                            Some(caption) => request.caption(caption).await,
                            None => request.await,
                        }
                    }
                })
                .await
            }
            MediaKind::Audio => {
                request_with_short_rate_limit_retry(|| {
                    let request = bot.send_audio(
                        ChatId(id),
                        InputFile::memory(media.data.clone()).file_name(filename.clone()),
                    );
                    let caption = attach_caption.clone();
                    async move {
                        match caption {
                            Some(caption) => request.caption(caption).await,
                            None => request.await,
                        }
                    }
                })
                .await
            }
            MediaKind::Document => {
                request_with_short_rate_limit_retry(|| {
                    let request = bot.send_document(
                        ChatId(id),
                        InputFile::memory(media.data.clone()).file_name(filename.clone()),
                    );
                    let caption = attach_caption.clone();
                    async move {
                        match caption {
                            Some(caption) => request.caption(caption).await,
                            None => request.await,
                        }
                    }
                })
                .await
            }
            MediaKind::Sticker => {
                request_with_short_rate_limit_retry(|| {
                    let request = bot.send_sticker(
                        ChatId(id),
                        InputFile::memory(media.data.clone()).file_name(filename.clone()),
                    );
                    async move { request.await }
                })
                .await
            }
        }
        .map_err(|e| self.map_request_error("sendMedia", e))?;

        if let Some(caption) = follow_up_caption {
            let reply = super::formatter::CanonicalReply {
                text: caption,
                code_blocks: Vec::new(),
                length_hint: Some(super::formatter::LengthHint::Long),
            };
            // Build every chunk before the first await. `Formatter` is a
            // synchronous trait object and deliberately need not be `Send`;
            // retaining it across the network await would make this
            // `async_trait` future non-Send.
            let chunks = super::formatter::for_channel(ChannelKind::Telegram)
                .map(|formatter| formatter.format(&reply))
                .unwrap_or_else(|| vec![reply.text]);
            for chunk in chunks {
                // The media is already delivered. Surfacing a caption error
                // would make callers retry and duplicate the attachment.
                if let Err(error) = self.send_text(chat_id, &chunk).await {
                    tracing::warn!(
                        error = %error,
                        "telegram caption follow-up failed after media delivery (dropped)"
                    );
                    break;
                }
            }
        }

        Ok(MessageId(message.id.0.to_string()))
    }

    /// SPEC-11: edit a previously-sent message via Telegram `editMessageText`.
    /// `message_id` is the numeric id returned by [`TelegramChannel::send_text`]
    /// (Telegram message ids are stable across edits). Drives the
    /// [`LiveDelivery`](crate::channels::LiveDelivery) streaming-preview path.
    /// A bad chat_id / message_id or a Telegram-side failure surfaces as
    /// `Transport` so the `LiveDelivery` degrade path stays reserved for true
    /// `NotSupported` adapters.
    async fn edit_message(
        &self,
        chat_id: &str,
        message_id: &MessageId,
        new_text: &str,
    ) -> std::result::Result<(), ChannelError> {
        use teloxide::types::{ChatId, MessageId as TgMessageId};

        let id: i64 = chat_id.parse().map_err(|e: std::num::ParseIntError| {
            ChannelError::Transport(format!("chat_id parse: {e}"))
        })?;
        let mid: i32 = message_id.0.parse().map_err(|e: std::num::ParseIntError| {
            ChannelError::Transport(format!("message_id parse: {e}"))
        })?;
        let bot = Bot::new(self.token.expose());
        // Try MarkdownV2 first (matches send_text), fall back to plain text on a
        // parse rejection so a strict-markdown body still lands the edit.
        let edit = request_with_short_rate_limit_retry(|| {
            let request = bot
                .edit_message_text(ChatId(id), TgMessageId(mid), new_text.to_string())
                .parse_mode(ParseMode::MarkdownV2);
            async move { request.await }
        })
        .await;
        match edit {
            Ok(_) => {}
            Err(teloxide::RequestError::Api(teloxide::ApiError::CantParseEntities(_))) => {
                request_with_short_rate_limit_retry(|| {
                    let request =
                        bot.edit_message_text(ChatId(id), TgMessageId(mid), new_text.to_string());
                    async move { request.await }
                })
                .await
                .map_err(|e| self.map_request_error("editMessageText", e))?;
            }
            Err(e) => return Err(self.map_request_error("editMessageText", e)),
        }
        Ok(())
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
        // SF-03: one writer clone per dptree branch (each `move` endpoint
        // closure owns its own; cloned again per inbound for the audit).
        let gate_writer_msg = self.gate_writer.clone();
        let gate_writer_edit = self.gate_writer.clone();
        // SD-03: bounded dedup so a repeated edited-message delivery (Telegram
        // can re-send the same edit across poll cycles) emits 0x38 only once.
        let dedup = Arc::new(std::sync::Mutex::new(EditDedup::new(EDIT_DEDUP_CAP)));

        // SD-03: teloxide::repl only delivers *new* Messages. Edited messages
        // arrive as `UpdateKind::EditedMessage` and are dropped by repl. A
        // Dispatcher with explicit `filter_message` + `filter_edited_message`
        // branches handles both — and the handler-tree description makes the
        // long-poll listener opt into `allowed_updates = [..,edited_message]`
        // automatically (teloxide derives it from the branch set).
        let h_msg = Arc::clone(&handler);
        let h_edit = Arc::clone(&handler);
        let dedup_edit = Arc::clone(&dedup);

        let schema = dptree::entry()
            .branch(
                Update::filter_message().endpoint(move |bot: Bot, msg: Message| {
                    let handler = Arc::clone(&h_msg);
                    let gate_writer = gate_writer_msg.clone();
                    async move {
                        if let Err(e) =
                            handle_one_message(bot, msg, handler, allowed, gate_writer).await
                        {
                            tracing::warn!(error = %e, "Telegram message handler error");
                        }
                        respond(())
                    }
                }),
            )
            .branch(
                Update::filter_edited_message().endpoint(move |bot: Bot, msg: Message| {
                    let handler = Arc::clone(&h_edit);
                    let dedup = Arc::clone(&dedup_edit);
                    let gate_writer = gate_writer_edit.clone();
                    async move {
                        if let Err(e) =
                            handle_edited_message(bot, msg, handler, allowed, dedup, gate_writer)
                                .await
                        {
                            tracing::warn!(error = %e, "Telegram edited-message handler error");
                        }
                        respond(())
                    }
                }),
            );

        Dispatcher::builder(bot, schema)
            .enable_ctrlc_handler()
            .build()
            .dispatch()
            .await;
        Ok(())
    }
}

/// SD-03 edit-dedup capacity. Telegram rarely redelivers an edit, but a
/// long-running daemon must bound the memory: oldest key evicted at capacity.
const EDIT_DEDUP_CAP: usize = 512;

/// Bounded FIFO set of `(message_id, edit_ts_unix)` keys. A *new* edit to the
/// same message (later `edit_date`) is a distinct key, so it is recorded again.
struct EditDedup {
    seen: std::collections::HashSet<(i64, i64)>,
    order: std::collections::VecDeque<(i64, i64)>,
    cap: usize,
}

impl EditDedup {
    fn new(cap: usize) -> Self {
        Self {
            seen: std::collections::HashSet::with_capacity(cap),
            order: std::collections::VecDeque::with_capacity(cap),
            cap,
        }
    }

    /// `true` when `key` is newly recorded (caller should emit 0x38); `false`
    /// when it was already seen (duplicate delivery → skip the audit frame).
    fn check_and_insert(&mut self, key: (i64, i64)) -> bool {
        if self.seen.contains(&key) {
            return false;
        }
        if self.order.len() >= self.cap
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        self.seen.insert(key);
        self.order.push_back(key);
        true
    }
}

/// SF-03: best-effort `0x3B CHANNEL_GATE_REJECTED` audit frame for an
/// allowlist-rejected sender. No-op when no writer is attached (tests /
/// open-allowlist installs). Never fails the caller — a WAL write error
/// logs `warn!` and is dropped; the rejection already happened, the audit
/// frame is the nicety. Carries only the numeric sender id + reason — no
/// message text (the gate fires before the text is read).
async fn emit_gate_rejected(writer: Option<&crate::wal::writer::WalWriterHandle>, sender_id: u64) {
    let Some(w) = writer else {
        return;
    };
    let ts_unix = crate::time::now_unix_i64();
    let payload = match serde_json::to_vec(&serde_json::json!({
        "channel": "telegram",
        "sender_id": sender_id,
        "reason": "not_on_allowlist",
        "ts_unix": ts_unix,
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialize CHANNEL_GATE_REJECTED failed");
            return;
        }
    };
    let header = crate::wal::make_header(
        crate::wal::events::EVENT_TYPE_CHANNEL_GATE_REJECTED,
        &payload,
    );
    if let Err(e) = w.append(header, payload).await {
        tracing::warn!(error = %e, "CHANNEL_GATE_REJECTED append failed (non-fatal)");
    }
}

/// SF-03 allowlist gate, shared by the new-message + edited-message paths
/// so both enforce the identical drop-and-audit contract from one tested
/// seam. Returns `true` when the sender is blocked (caller drops the
/// update) and, as a side effect, emits the `0x3B CHANNEL_GATE_REJECTED`
/// audit frame. `site` ("message"/"edit") only labels the two call sites in
/// the warn log. An open allowlist (`None`) never blocks; a rejected sender
/// is never sent a reply (information-leak avoidance).
async fn sender_blocked_by_allowlist(
    allowed_user_id: Option<u64>,
    from_id: u64,
    gate_writer: Option<&crate::wal::writer::WalWriterHandle>,
    site: &'static str,
) -> bool {
    let Some(allowed) = allowed_user_id else {
        return false;
    };
    if from_id == allowed {
        return false;
    }
    tracing::warn!(
        from_id,
        allowed_id = allowed,
        site,
        "Telegram sender not on allowlist — dropped"
    );
    emit_gate_rejected(gate_writer, from_id).await;
    true
}

async fn handle_one_message(
    bot: Bot,
    msg: Message,
    handler: Arc<PipelineHandler>,
    allowed_user_id: Option<u64>,
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
) -> Result<()> {
    let Some(from) = msg.from.as_ref() else {
        // Non-user message (channel post, service message). Ignore.
        return Ok(());
    };

    // Allowlist check FIRST — before we read the text, before we touch the
    // WAL, before any provider call. Rejected messages get logged + dropped
    // (+ a 0x3B audit frame); we do NOT send a "you are not allowed" reply
    // (information leak).
    if sender_blocked_by_allowlist(allowed_user_id, from.id.0, gate_writer.as_ref(), "message")
        .await
    {
        return Ok(());
    }

    // Detect message kind. Order matters: photo/voice/audio/document
    // populate `media`; bare text falls through to the existing path.
    let media = match download_attachment_if_any(&bot, &msg).await {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(error = %e, "Telegram attachment download failed");
            let notice = format!("[NEOTH] could not download attachment: {e}");
            let _ = send_bot_text(&bot, msg.chat.id, &notice).await;
            audit_notice_egress(gate_writer.as_ref(), &msg.chat.id.to_string(), &notice).await;
            return Ok(());
        }
    };

    let text = msg
        .text()
        .map(|s| s.to_string())
        .or_else(|| msg.caption().map(|s| s.to_string()));

    if text.is_none() && media.is_none() {
        // Location / poll / service event. Acknowledge so
        // the operator knows their message hit NEOTH but the type
        // is not silently discarded.
        let notice = "[NEOTH] message kind not supported (no text or supported media).";
        send_bot_text(&bot, msg.chat.id, notice).await?;
        audit_notice_egress(gate_writer.as_ref(), &msg.chat.id.to_string(), notice).await;
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
        message_id: Some(msg.id.0.to_string()),
        edit_unix: None,
        mention_kind: None,
        // GOLD-COR-11 / A-38/E-08: use the PROVIDER timestamp (msg.date), not
        // the daemon's local receive time, so retention/ordering consumers see
        // a consistent time axis across channels (Slack/WhatsApp already do).
        channel_ts_unix: msg.date.timestamp().max(0) as u64,
        raw_ts_ms: Some(msg.date.timestamp() * 1000),
        human_uuid: None,
    };

    match handler(inbound).await {
        Ok(Some(out)) => {
            // Reply via Markdown. Plain fallback is restricted to Telegram's
            // explicit parse rejection; ambiguous transport errors are never
            // retried because the first send may already have landed.
            send_bot_text(&bot, msg.chat.id, &out.text).await?;
        }
        Ok(None) => {
            // Pipeline chose to drop silently. No reply, no error.
        }
        Err(e) => {
            // Provider failure or WAL failure. Tell the operator something
            // went wrong without leaking internals.
            tracing::warn!(error = %e, "pipeline error for Telegram message");
            let notice = "[NEOTH] internal error; see daemon logs.";
            send_bot_text(&bot, msg.chat.id, notice).await?;
            audit_notice_egress(gate_writer.as_ref(), &msg.chat.id.to_string(), notice).await;
        }
    }

    Ok(())
}

/// Audit an out-of-pipeline error-notice send (attachment-failed /
/// unsupported-kind / internal-error notices) so every external Telegram
/// mutation leaves a metadata-only `CHANNEL_EGRESS` trail — even the ones that
/// don't flow through the pipeline's `ChannelSend` gate. Recipient + body are
/// HASHED (never the chat id or the text in the clear). Audit-only: these
/// operator-facing notices are intentionally NOT gate-suppressed, so the
/// operator still learns their message failed even at Strict autonomy.
async fn audit_notice_egress(
    gate_writer: Option<&crate::wal::writer::WalWriterHandle>,
    chat_id: &str,
    body: &str,
) {
    let Some(w) = gate_writer else {
        return;
    };
    let now = crate::time::now_unix_secs();
    let payload = crate::channels::send_gate::channel_egress_payload(
        "telegram", chat_id, body, None, false, false, now,
    );
    let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_CHANNEL_SEND, &payload);
    if let Err(e) = w.append(header, payload).await {
        tracing::warn!(error = %e, "Telegram notice-egress WAL append failed (non-fatal)");
    }
}

/// SD-03: handle a Telegram *edited* message. Audit-only — builds an
/// `InboundMessage` flagged with `edit_unix` and hands it to the pipeline,
/// which records a hashed WAL `0x38 CHANNEL_EDIT` frame and returns `Ok(None)`
/// (no provider re-run, no reply). Allowlist is enforced first, identical to
/// new messages; duplicate edit deliveries are dropped via `dedup`.
async fn handle_edited_message(
    _bot: Bot,
    msg: Message,
    handler: Arc<PipelineHandler>,
    allowed_user_id: Option<u64>,
    dedup: Arc<std::sync::Mutex<EditDedup>>,
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
) -> Result<()> {
    let Some(from) = msg.from.as_ref() else {
        return Ok(());
    };

    // Allowlist FIRST — same contract as new messages: rejected edits are
    // logged + dropped (+ a 0x3B audit frame), never acknowledged.
    if sender_blocked_by_allowlist(allowed_user_id, from.id.0, gate_writer.as_ref(), "edit").await {
        return Ok(());
    }

    // A genuine `EditedMessage` always carries `edit_date`. If Telegram omits
    // it (malformed/unexpected update), drop rather than emit a degenerate
    // `edit_ts_unix: 0` audit frame — audit hygiene over best-effort logging.
    let Some(edit_unix) = msg.edit_date().map(|d| d.timestamp()) else {
        tracing::warn!(
            message_id = msg.id.0,
            "Telegram edit dropped: update had no edit_date"
        );
        return Ok(());
    };
    let key = (i64::from(msg.id.0), edit_unix);
    {
        // Poison-tolerant: dedup is best-effort audit hygiene, never a
        // correctness gate. Recover the inner set on a poisoned lock.
        let mut guard = dedup.lock().unwrap_or_else(|p| p.into_inner());
        if !guard.check_and_insert(key) {
            // Duplicate delivery of an already-audited edit. Drop silently.
            return Ok(());
        }
    }

    let text = msg
        .text()
        .map(|s| s.to_string())
        .or_else(|| msg.caption().map(|s| s.to_string()));

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
        // Edits are audited by text-hash only; we do not re-download media.
        media: None,
        reply_to: None,
        message_id: Some(msg.id.0.to_string()),
        edit_unix: Some(edit_unix),
        mention_kind: None,
        // GOLD-COR-11 / A-38/E-08: use the PROVIDER timestamp (msg.date), not
        // the daemon's local receive time, so retention/ordering consumers see
        // a consistent time axis across channels (Slack/WhatsApp already do).
        channel_ts_unix: msg.date.timestamp().max(0) as u64,
        raw_ts_ms: Some(msg.date.timestamp() * 1000),
        human_uuid: None,
    };

    // Audit-only: the pipeline emits 0x38 and returns Ok(None). No reply is
    // sent for an edit — surfacing one would be noise + a side channel.
    if let Err(e) = handler(inbound).await {
        tracing::warn!(error = %e, "pipeline error for Telegram edited message");
    }
    Ok(())
}

/// Detect + download the first eligible attachment on `msg`. Returns
/// `Ok(None)` when the message is text-only or carries an unsupported
/// attachment type (sticker, location, …). On real download failures
/// returns `Err` so the handler can surface the issue to the operator.
///
/// Supported today: `photo` (largest variant), `voice`, `audio`, `video`,
/// `document`, and `sticker`.
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
    if let Some(video) = msg.video() {
        let bytes = download_telegram_file(bot, &video.file.id.0).await?;
        return Ok(Some(MediaPayload {
            kind: MediaKind::Video,
            mime: video
                .mime_type
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "video/mp4".to_string()),
            filename: video.file_name.clone(),
            data: bytes,
        }));
    }
    if let Some(document) = msg.document() {
        let bytes = download_telegram_file(bot, &document.file.id.0).await?;
        return Ok(Some(MediaPayload {
            kind: MediaKind::Document,
            mime: document
                .mime_type
                .as_ref()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "application/octet-stream".to_string()),
            filename: document.file_name.clone(),
            data: bytes,
        }));
    }
    if let Some(sticker) = msg.sticker() {
        let bytes = download_telegram_file(bot, &sticker.file.id.0).await?;
        let (mime, filename) = if sticker.flags.is_video {
            ("video/webm", "sticker.webm")
        } else if sticker.flags.is_animated {
            ("application/x-tgsticker", "sticker.tgs")
        } else {
            ("image/webp", "sticker.webp")
        };
        return Ok(Some(MediaPayload {
            kind: MediaKind::Sticker,
            mime: mime.to_string(),
            filename: Some(filename.to_string()),
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
    fn outbound_media_validation_covers_every_native_mapping() {
        let cases = [
            (MediaKind::Image, "image/jpeg", "image.jpg"),
            (MediaKind::Video, "video/mp4", "video.mp4"),
            (MediaKind::Audio, "audio/m4a", "audio.m4a"),
            (
                MediaKind::Document,
                "application/octet-stream",
                "document.bin",
            ),
            (MediaKind::Sticker, "video/webm", "sticker.webm"),
        ];
        for (kind, mime, expected_name) in cases {
            let media = MediaPayload {
                kind,
                data: vec![1, 2, 3],
                mime: mime.to_string(),
                filename: None,
            };
            assert_eq!(validate_outbound_media(&media).unwrap(), expected_name);
        }

        let named = MediaPayload {
            kind: MediaKind::Image,
            data: vec![1],
            mime: "image/png".to_string(),
            filename: Some("../../safe-name.png".to_string()),
        };
        assert_eq!(validate_outbound_media(&named).unwrap(), "safe-name.png");
    }

    #[test]
    fn outbound_media_validation_rejects_empty_oversized_and_mismatched_payloads() {
        let empty = MediaPayload {
            kind: MediaKind::Image,
            data: Vec::new(),
            mime: "image/jpeg".to_string(),
            filename: None,
        };
        assert!(validate_outbound_media(&empty).is_err());

        let oversized_sticker = MediaPayload {
            kind: MediaKind::Sticker,
            data: vec![0; MAX_OUTBOUND_STICKER_BYTES + 1],
            mime: "image/webp".to_string(),
            filename: None,
        };
        assert!(validate_outbound_media(&oversized_sticker).is_err());

        let mismatched = MediaPayload {
            kind: MediaKind::Audio,
            data: vec![1],
            mime: "image/jpeg".to_string(),
            filename: None,
        };
        assert!(validate_outbound_media(&mismatched).is_err());

        let control_filename = MediaPayload {
            kind: MediaKind::Document,
            data: vec![1],
            mime: "application/pdf".to_string(),
            filename: Some("invoice\nsecret.pdf".to_string()),
        };
        assert!(validate_outbound_media(&control_filename).is_err());
    }

    #[test]
    fn caption_plan_attaches_short_text_and_falls_back_losslessly() {
        let short = "hello";
        assert_eq!(
            plan_caption(MediaKind::Image, Some(short)),
            (Some(short.to_string()), None)
        );

        let long = "ü".repeat(MAX_TELEGRAM_CAPTION_CHARS + 1);
        assert_eq!(
            plan_caption(MediaKind::Document, Some(&long)),
            (None, Some(long))
        );
        assert_eq!(
            plan_caption(MediaKind::Sticker, Some(short)),
            (None, Some(short.to_string()))
        );
        assert_eq!(plan_caption(MediaKind::Audio, Some("")), (None, None));
    }

    #[test]
    fn telegram_transport_errors_redact_the_bot_token() {
        let token = "123456:super-secret-token";
        let message =
            format!("request https://api.telegram.org/bot{token}/sendDocument failed: {token}");
        let redacted = redact_token(&message, token);
        assert!(!redacted.contains(token));
        assert_eq!(redacted.matches("[REDACTED]").count(), 2);
    }

    #[tokio::test]
    async fn short_retry_after_is_retried_once_and_long_delay_is_surfaced() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&attempts);
        let result = request_with_short_rate_limit_retry(|| {
            let attempt = seen.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    Err(teloxide::RequestError::RetryAfter(
                        teloxide::types::Seconds::from_seconds(0),
                    ))
                } else {
                    Ok(7_u8)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&attempts);
        let result: std::result::Result<(), _> = request_with_short_rate_limit_retry(|| {
            seen.fetch_add(1, Ordering::SeqCst);
            async {
                Err(teloxide::RequestError::RetryAfter(
                    teloxide::types::Seconds::from_seconds(MAX_INLINE_RETRY_AFTER_SECS + 1),
                ))
            }
        })
        .await;
        assert!(matches!(result, Err(teloxide::RequestError::RetryAfter(_))));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn with_gate_writer_attaches_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, _join) = crate::wal::writer::spawn(dir.path().join("g.wal")).unwrap();
        let t = TelegramChannel::new(SecretString::from("dummy"), Some(1)).with_gate_writer(writer);
        assert!(t.gate_writer.is_some());
    }

    #[tokio::test]
    async fn emit_gate_rejected_writes_0x3b_frame_and_none_is_noop() {
        // SF-03: None writer (tests / open-allowlist) → no-op, no panic.
        emit_gate_rejected(None, 999).await;

        // Some writer → exactly one 0x3B frame carrying the numeric sender
        // id + reason, NO message text.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("gate.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        emit_gate_rejected(Some(&writer), 4242).await;

        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut found = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_CHANNEL_GATE_REJECTED {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                assert_eq!(v["sender_id"], 4242);
                assert_eq!(v["reason"], "not_on_allowlist");
                assert_eq!(v["channel"], "telegram");
                assert!(
                    v.get("text").is_none(),
                    "gate-reject frame must carry no text"
                );
                found += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert_eq!(found, 1, "expected exactly one CHANNEL_GATE_REJECTED frame");
    }

    #[tokio::test]
    async fn sender_blocked_by_allowlist_gates_both_paths() {
        // Open allowlist → nobody is blocked (no writer needed).
        assert!(
            !sender_blocked_by_allowlist(None, 999, None, "message").await,
            "open allowlist must let every sender through"
        );
        // Listed sender → not blocked.
        assert!(
            !sender_blocked_by_allowlist(Some(7), 7, None, "edit").await,
            "the allowed sender must pass"
        );

        // Unlisted sender → blocked AND a single 0x3B frame for that id is
        // written. This is the seam both handle_one_message ("message") and
        // handle_edited_message ("edit") route through, so it guards both.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("gate.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        assert!(
            sender_blocked_by_allowlist(Some(7), 13, Some(&writer), "edit").await,
            "a sender not on the allowlist must be blocked"
        );

        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut found = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_CHANNEL_GATE_REJECTED {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                assert_eq!(v["sender_id"], 13);
                assert_eq!(v["reason"], "not_on_allowlist");
                found += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert_eq!(
            found, 1,
            "blocked sender must produce exactly one 0x3B frame"
        );
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

    /// SPEC-11 pin: edit_message surfaces a Transport error on a bad chat_id
    /// (forces the parse-failure branch so no real Telegram HTTP request is
    /// made) — proving the override landed (the trait default would return
    /// NotSupported) without needing network access.
    #[tokio::test]
    async fn edit_message_returns_transport_error_on_bad_chat_id() {
        let t = TelegramChannel::new(SecretString::from("dummy-token"), None);
        let err = t
            .edit_message("not-a-number", &MessageId("42".into()), "edited")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChannelError::Transport(_)),
            "expected Transport (parse-failure branch); got {err:?}"
        );
        let msg = format!("{err}");
        assert!(!msg.contains("not supported"), "leaked default impl: {msg}");
    }

    /// SPEC-11 pin: a bad message_id (non-numeric) also surfaces Transport
    /// via the message_id parse branch.
    #[tokio::test]
    async fn edit_message_returns_transport_error_on_bad_message_id() {
        let t = TelegramChannel::new(SecretString::from("dummy-token"), None);
        let err = t
            .edit_message("123", &MessageId("not-numeric".into()), "edited")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ChannelError::Transport(_)),
            "expected Transport (message_id parse branch); got {err:?}"
        );
    }

    // ── SD-03 EditDedup ────────────────────────────────────────────────────
    #[test]
    fn edit_dedup_first_sight_is_new_repeat_is_dup() {
        let mut d = EditDedup::new(8);
        assert!(
            d.check_and_insert((100, 1_700_000_000)),
            "first sight = new"
        );
        assert!(
            !d.check_and_insert((100, 1_700_000_000)),
            "same (msg_id, edit_ts) = duplicate"
        );
    }

    #[test]
    fn edit_dedup_later_edit_to_same_message_is_new() {
        let mut d = EditDedup::new(8);
        assert!(d.check_and_insert((100, 1_700_000_000)));
        // A *new* edit to the same message carries a later edit_date → fresh.
        assert!(
            d.check_and_insert((100, 1_700_000_050)),
            "later edit_date on same message must be a distinct event"
        );
    }

    #[test]
    fn edit_dedup_evicts_oldest_at_capacity() {
        let mut d = EditDedup::new(2);
        assert!(d.check_and_insert((1, 0)));
        assert!(d.check_and_insert((2, 0)));
        // Inserting a third evicts the oldest (1, 0).
        assert!(d.check_and_insert((3, 0)));
        // (1, 0) was evicted → seen as new again.
        assert!(
            d.check_and_insert((1, 0)),
            "evicted key must be treated as new on re-sight"
        );
        // (3, 0) still present → duplicate.
        assert!(!d.check_and_insert((3, 0)), "recent key still deduped");
    }
}
