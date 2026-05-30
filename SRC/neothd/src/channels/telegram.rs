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
        if self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
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
    let ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
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
    // WAL, before any provider call. Rejected messages get logged + dropped;
    // we do NOT send a "you are not allowed" reply (information leak).
    if let Some(allowed) = allowed_user_id {
        if from.id.0 != allowed {
            tracing::warn!(
                from_id = from.id.0,
                allowed_id = allowed,
                "Telegram message dropped: sender not on allowlist"
            );
            // SF-03: audit the rejected sender so it shows in
            // `neoth wal show --type channel_gate_rejected` (the drop was
            // previously tracing-only — invisible at the default log level).
            emit_gate_rejected(gate_writer.as_ref(), from.id.0).await;
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
        message_id: Some(msg.id.0.to_string()),
        edit_unix: None,
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
    // logged + dropped, never acknowledged (information leak).
    if let Some(allowed) = allowed_user_id {
        if from.id.0 != allowed {
            tracing::warn!(
                from_id = from.id.0,
                allowed_id = allowed,
                "Telegram edit dropped: sender not on allowlist"
            );
            // SF-03: audit the rejected sender (edit path).
            emit_gate_rejected(gate_writer.as_ref(), from.id.0).await;
            return Ok(());
        }
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
        channel_ts_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
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
