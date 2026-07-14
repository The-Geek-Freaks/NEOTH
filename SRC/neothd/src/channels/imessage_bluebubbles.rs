//! GOLD-FEAT-10b — iMessage adapter via a local BlueBubbles server.
//!
//! BlueBubbles is an open-source Mac app that exposes iMessage as a REST
//! API + optional webhook (<https://bluebubblestatus.com>). NEOTH uses the
//! **polling** transport (`POST /api/v1/message/query`) so the
//! operator needs NO public URL — NEOTH dials out to the BlueBubbles server
//! on the local Mac (or LAN/Tailscale).
//!
//! ## Operator prerequisites
//!
//! 1. BlueBubbles running on a Mac with an active iCloud/iMessage account.
//! 2. In BB → Settings → Server, note the **server URL** and set a
//!    **server password**.
//! 3. In `credentials.yaml`, supply:
//!    - `bluebubbles_url`:      e.g. `http://192.168.1.5:1234`  (non-secret)
//!    - `bluebubbles_password`: the BB server password             (secret)
//!    - `bluebubbles_chat_guid`: (optional) comma-separated BB chat GUIDs to
//!      accept; omit to accept all chats NEOTH can see.
//!    - `imessage_allowed_sender`: (optional) single iMessage handle that may
//!      reach the pipeline; omit for open-to-all-watched-chats.
//!
//! ## Spoofing characteristics
//!
//! iMessage sender handles (`source`) are verified by Apple end-to-end:
//! they are either a real phone number or an Apple-ID email, tied to an
//! iCloud account. This makes them **LOW spoof-risk** — significantly harder
//! to fake than IRC nicks or Nostr aliases, and comparable to WhatsApp phone
//! numbers. Still enforce the operator allowlist for defence-in-depth.
//!
//! ## Polling cursor
//!
//! The inbound poll uses `POST /api/v1/message/query` with `after`, `limit`,
//! `offset`, and ascending sort. All pages are drained before the cursor is
//! advanced. On each
//! tick the cursor advances to `max(returned message timestamps) + 1 ms`.
//! On the first tick, `after = now_unix_ms - poll_interval_ms` so only
//! "very recent" messages are fetched at startup (avoids replaying history
//! into the pipeline on first boot).
//!
//! ## send_media
//!
//! Outbound attachments go through `POST /api/v1/message/attachment`
//! (multipart: `chatGuid` + `name` required, file part `attachment` —
//! verified against the BB server source, `MessageRouter.sendAttachment`).
//! BB has no caption field on attachment sends; a non-empty caption is
//! delivered as a follow-up `message/text` call.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{info, warn};

use super::{
    Channel, ChannelError, ChannelKind, InboundMessage, MediaPayload, MessageId, PipelineHandler,
    sender_blocked_by_allowlist,
};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default polling cadence. 3 s gives a responsive feel while keeping the BB
/// server load negligible (it is a personal Mac app, not a cloud service).
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// BlueBubbles accepts up to 1000 rows per message-query page.
const POLL_PAGE_SIZE: usize = 1000;

/// Fail the poll without advancing its cursor if a broken server ignores
/// `offset` forever. One million rows per 3-second window is already far above
/// a personal iMessage workload; returning an error preserves retryability.
const MAX_POLL_PAGES: usize = 1000;

/// `User-Agent` sent on every BlueBubbles HTTP request.
const USER_AGENT: &str = "NEOTH/0.1 (+https://neoth.dev)";

// ── Wire types ─────────────────────────────────────────────────────────────

/// Top-level response of `POST /api/v1/message/query`.
/// BB wraps the array in `{ "status": 200, "data": [...], "metadata": ... }`.
#[derive(Debug, Deserialize)]
struct MessageListResponse {
    #[serde(default)]
    data: Vec<BbMessage>,
    #[serde(default)]
    metadata: Option<MessageListMetadata>,
}

#[derive(Debug, Deserialize)]
struct MessageListMetadata {
    #[serde(default)]
    total: Option<usize>,
}

/// One inbound message from the BlueBubbles REST API.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct BbMessage {
    /// BB internal GUID — used as `message_id` so the WAL can correlate.
    #[serde(default)]
    pub guid: String,
    /// The iMessage handle of the sender (E.164 phone or `@email`).
    /// Populated for incoming messages; our own messages have `is_from_me: true`.
    #[serde(default, rename = "handle")]
    pub handle: Option<BbHandle>,
    /// The chat this message belongs to. Needed for routing replies back.
    #[serde(default, rename = "chats")]
    pub chats: Vec<BbChat>,
    /// Plain-text body (may be empty for tapback/reactions/system messages).
    #[serde(default)]
    pub text: Option<String>,
    /// Unix milliseconds. BlueBubbles serializes its internal `Date` with
    /// JavaScript `Date::getTime()` before sending the REST response.
    #[serde(default, rename = "dateCreated")]
    pub date_created: i64,
    /// True if NEOTH sent this message (via our own Apple ID). We NEVER
    /// re-ingest outbound messages — they would echo back into the pipeline.
    #[serde(default, rename = "isFromMe")]
    pub is_from_me: bool,
}

/// The iMessage sender handle.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct BbHandle {
    /// The handle's address: E.164 phone number or Apple-ID email.
    #[serde(default)]
    pub address: String,
}

/// The chat a message belongs to.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct BbChat {
    /// BB chat GUID, e.g. `iMessage;-;+14155551234` for a DM or
    /// `iMessage;+;group-uuid` for a group.
    #[serde(default)]
    pub guid: String,
}

/// Clamp a BlueBubbles Unix-millisecond timestamp to zero for corrupt negative
/// values. The server already converts its macOS database epoch to `Date` and
/// serializes `Date::getTime()`; adding the 2001 epoch delta again would move
/// the cursor roughly 31 years into the future.
pub(crate) fn bb_date_to_unix_ms(date_created: i64) -> i64 {
    date_created.max(0)
}

// ── Mapping ───────────────────────────────────────────────────────────────

/// Map one raw BB message to a normalised [`InboundMessage`], returning
/// `None` when:
/// - it is our own outbound message (`is_from_me`)
/// - the sender handle is missing or empty (system/tapback/reaction)
/// - the text body is absent or blank (attachment-only, tapback)
///
/// `chat_guid_allowlist` is an optional operator-supplied set of BB chat
/// GUIDs to watch; if `Some` and the message's chat GUID is not in the
/// list the message is silently dropped here (pre-allowlist filter so the
/// WAL gate is never reached for unrelated chats).
pub(crate) fn bb_message_to_inbound(
    msg: &BbMessage,
    chat_guid_allowlist: Option<&[String]>,
) -> Option<InboundMessage> {
    if msg.is_from_me {
        return None;
    }
    let handle = msg.handle.as_ref()?;
    if handle.address.trim().is_empty() {
        return None;
    }
    let text = msg.text.as_deref()?;
    if text.trim().is_empty() {
        return None;
    }

    // Use the first chat GUID as chat_id; if there is none, fall back to the
    // sender's handle address (DM-only fallback).
    let chat_id = msg
        .chats
        .first()
        .map(|c| c.guid.clone())
        .filter(|g| !g.is_empty())
        .unwrap_or_else(|| handle.address.clone());

    // Chat GUID allowlist filter (optional operator-supplied, checked here
    // so the WAL gate only fires for configured chats).
    if let Some(allowed) = chat_guid_allowlist {
        if !allowed.iter().any(|a| a == &chat_id) {
            return None;
        }
    }

    let unix_ms = bb_date_to_unix_ms(msg.date_created);
    let channel_ts_unix = (unix_ms / 1000) as u64;

    Some(InboundMessage {
        channel: ChannelKind::IMessageBlueBubbles,
        chat_id,
        thread_id: None,
        sender_id: handle.address.clone(),
        sender_display: None, // BB handle struct carries no display name
        text: Some(text.to_string()),
        media: None,
        reply_to: None,
        message_id: if msg.guid.is_empty() {
            None
        } else {
            Some(msg.guid.clone())
        },
        edit_unix: None,
        mention_kind: None,
        channel_ts_unix,
        raw_ts_ms: Some(unix_ms),
        human_uuid: None,
    })
}

// ── Adapter ───────────────────────────────────────────────────────────────

/// BlueBubbles iMessage adapter. All state is immutable after construction
/// (password never re-read from disk at runtime).
pub struct BlueBubblesChannel {
    /// Base URL of the BlueBubbles server, trailing slash stripped.
    server_url: String,
    /// BB server password — appended as `?password=…` query param.
    /// NEVER logged, never appears in tracing fields.
    password: crate::secret::SecretString,
    /// Optional comma-separated chat GUIDs to watch. `None` = all chats.
    chat_guid_allowlist: Option<Vec<String>>,
    /// Optional single iMessage handle that may reach the pipeline.
    /// Checked via [`sender_blocked_by_allowlist`] after chat filtering.
    allowed_sender: Option<String>,
    /// Shared HTTP client (keep-alive, rustls TLS).
    http: reqwest::Client,
    /// Polling cadence.
    poll_interval: Duration,
    /// WAL writer for `0x3B CHANNEL_GATE_REJECTED` audit frames.
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
}

impl BlueBubblesChannel {
    /// Construct from credentials. Fails only if the reqwest client cannot
    /// be built (which is essentially unreachable in practice).
    pub fn new(
        server_url: impl Into<String>,
        password: crate::secret::SecretString,
        chat_guid_allowlist: Option<Vec<String>>,
        allowed_sender: Option<String>,
    ) -> Result<Self> {
        // Security review: never follow redirects — a redirect would
        // forward the password query param to the redirect target.
        let http = crate::providers::http_client::build_client_no_redirect()
            .context("build reqwest client for BlueBubbles adapter")?;
        Ok(Self {
            server_url: server_url.into().trim_end_matches('/').to_string(),
            password,
            chat_guid_allowlist,
            allowed_sender,
            http,
            poll_interval: DEFAULT_POLL_INTERVAL,
            gate_writer: None,
        })
    }

    /// Override poll cadence (tuning / tests).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Attach a WAL writer so allowlist-rejected senders are audited via
    /// `0x3B CHANNEL_GATE_REJECTED`. Mirrors the IRC/Signal pattern.
    pub fn with_gate_writer(mut self, writer: crate::wal::writer::WalWriterHandle) -> Self {
        self.gate_writer = Some(writer);
        self
    }

    /// Construct the full API URL with the password query parameter.
    /// The password is embedded in the URL per the BB API design; we
    /// deliberately never log URLs from this adapter (see tests).
    /// Security review: reqwest connection errors embed the full request URL
    /// (which carries `?password=…`). Every error string passes through here
    /// before it can reach logs or callers.
    fn scrub(&self, msg: String) -> String {
        msg.replace(self.password.expose(), "***")
    }

    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/api/v1/{}?password={}",
            self.server_url,
            path.trim_start_matches('/'),
            self.password.expose()
        )
    }

    /// Drain every `POST /api/v1/message/query` page for one fixed cursor.
    /// Advancing the cursor remains the caller's job and happens only after
    /// this returns the complete window.
    async fn poll_messages(
        &self,
        cursor_ms: i64,
    ) -> std::result::Result<Vec<BbMessage>, ChannelError> {
        self.poll_messages_with_page_size(cursor_ms, POLL_PAGE_SIZE)
            .await
    }

    async fn poll_messages_with_page_size(
        &self,
        cursor_ms: i64,
        page_size: usize,
    ) -> std::result::Result<Vec<BbMessage>, ChannelError> {
        let page_size = page_size.clamp(1, 1000);
        let url = self.api_url("message/query");
        let mut messages = Vec::new();
        let mut offset = 0usize;

        for _ in 0..MAX_POLL_PAGES {
            let body = serde_json::json!({
                "after": cursor_ms,
                "limit": page_size,
                "offset": offset,
                "sort": "ASC",
                "with": ["chats"],
            });
            let resp = self
                .http
                .post(&url)
                .header(reqwest::header::USER_AGENT, USER_AGENT)
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    ChannelError::Transport(
                        self.scrub(format!("BlueBubbles POST /message/query: {e}")),
                    )
                })?;
            map_bb_status(&resp)?;
            let parsed: MessageListResponse = resp.json().await.map_err(|e| {
                ChannelError::Transport(
                    self.scrub(format!("BlueBubbles /message/query parse: {e}")),
                )
            })?;
            let page_len = parsed.data.len();
            let total = parsed.metadata.and_then(|metadata| metadata.total);
            messages.extend(parsed.data);
            offset = offset.saturating_add(page_len);

            if page_len == 0 || page_len < page_size || total.is_some_and(|total| offset >= total) {
                return Ok(messages);
            }
        }

        Err(ChannelError::Transport(format!(
            "BlueBubbles /message/query exceeded {MAX_POLL_PAGES} pages without completing; cursor preserved for retry"
        )))
    }

    /// `POST /api/v1/message/text` — send `text` to `chat_guid`.
    /// BlueBubbles returns `{ "status": 200, "message": { "guid": "…" } }`.
    async fn post_text(
        &self,
        chat_guid: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let url = self.api_url("message/text");
        let body = serde_json::json!({
            "chatGuid": chat_guid,
            "message": text,
            "tempGuid": format!("neoth-{}", uuid::Uuid::new_v4()),
        });
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                ChannelError::Transport(self.scrub(format!("BlueBubbles POST /message/text: {e}")))
            })?;
        map_bb_status(&resp)?;
        // Parse the returned message GUID if available; fall back to "sent".
        // BB wraps responses as `{status, message: "<string>", data: {guid}}`
        // (verified against MessageRouter.sendText upstream) — the guid lives
        // at `/data/guid`; `/message/guid` kept as a legacy fallback.
        let val: serde_json::Value = resp.json().await.map_err(|error| {
            ChannelError::Transport(self.scrub(format!(
                "BlueBubbles POST /message/text response JSON: {error}"
            )))
        })?;
        let guid = val
            .pointer("/data/guid")
            .or_else(|| val.pointer("/message/guid"))
            .and_then(|v| v.as_str())
            .unwrap_or("sent")
            .to_string();
        Ok(MessageId(guid))
    }
}

/// Map BlueBubbles HTTP status → [`ChannelError`]. BB uses standard HTTP
/// status codes: 401 = bad password, 429 = rate-limit (rare for a local
/// server but handle it), other 4xx/5xx = transport error.
fn map_bb_status(resp: &reqwest::Response) -> std::result::Result<(), ChannelError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    if status.as_u16() == 429 {
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|n| n.ceil() as u64)
            .unwrap_or(1);
        return Err(ChannelError::RateLimited {
            retry_after_secs: retry_after,
        });
    }
    if matches!(status.as_u16(), 401 | 403) {
        return Err(ChannelError::Auth(format!(
            "BlueBubbles HTTP {} — bad password?",
            status.as_u16()
        )));
    }
    Err(ChannelError::Transport(format!(
        "BlueBubbles HTTP {}",
        status.as_u16()
    )))
}

#[async_trait]
impl Channel for BlueBubblesChannel {
    fn name(&self) -> &'static str {
        "imessage_bluebubbles"
    }

    /// Long-running poll loop. Initialises the cursor to `now - poll_interval`
    /// so only messages that arrived in the last tick window are ingested on
    /// first boot (no historical replay). Advances the cursor after every
    /// successful poll. Auth failures are fatal; transient transport errors
    /// are logged and retried on the next tick.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        info!(
            url = %self.server_url,
            poll_secs = self.poll_interval.as_secs(),
            "bluebubbles imessage poll loop starting"
        );

        // Seed the cursor at "now minus one poll window" so we don't replay
        // the entire message history on startup.
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let mut cursor_ms = now_unix_ms.saturating_sub(self.poll_interval.as_millis() as i64);

        let allowed_sender = self.allowed_sender.as_deref();
        let chat_guid_allowlist = self.chat_guid_allowlist.as_deref();

        loop {
            match self.poll_messages(cursor_ms).await {
                Ok(messages) => {
                    let mut new_cursor = cursor_ms;
                    for msg in &messages {
                        // Advance cursor to max(ts) + 1 ms so the next poll
                        // doesn't re-deliver the same messages.
                        let unix_ms = bb_date_to_unix_ms(msg.date_created);
                        if unix_ms >= new_cursor {
                            new_cursor = unix_ms + 1;
                        }

                        let Some(inbound) = bb_message_to_inbound(msg, chat_guid_allowlist) else {
                            continue; // is_from_me / tapback / blank — skip
                        };

                        // D2 sender allowlist gate (post-chat filter).
                        if sender_blocked_by_allowlist(
                            allowed_sender,
                            &inbound.sender_id,
                            self.gate_writer.as_ref(),
                            "imessage_bluebubbles",
                        )
                        .await
                        {
                            continue;
                        }

                        match handler(inbound).await {
                            Ok(Some(out)) => {
                                if let Err(e) = self.post_text(&out.recipient_id, &out.text).await {
                                    warn!(error = %e, "bluebubbles reply send failed (dropped)");
                                }
                            }
                            Ok(None) => {} // pipeline chose silence
                            Err(e) => {
                                warn!(error = %e, "bluebubbles pipeline handler errored; skipping message");
                            }
                        }
                    }
                    cursor_ms = new_cursor;
                }
                Err(ChannelError::Auth(msg)) => {
                    tracing::error!(
                        error = %msg,
                        "bluebubbles auth failed — stopping adapter (check server URL / password)"
                    );
                    return Err(anyhow::anyhow!("bluebubbles auth: {msg}"));
                }
                Err(ChannelError::RateLimited { retry_after_secs }) => {
                    // Local BB server rate-limiting is unusual but handle it
                    // gracefully: wait the requested period, then resume.
                    // Security review: cap a server/MITM-supplied Retry-After
                    // so a hostile value can never park the adapter forever.
                    let capped = retry_after_secs.min(300);
                    warn!(
                        retry_after_secs,
                        capped, "bluebubbles rate-limited; backing off"
                    );
                    tokio::time::sleep(Duration::from_secs(capped)).await;
                }
                Err(e) => {
                    warn!(error = %e, "bluebubbles poll failed; retrying next tick");
                }
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// Send a reply via `POST /api/v1/message/text`. `chat_id` is the BB
    /// chat GUID as stored in `InboundMessage::chat_id`.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.post_text(chat_id, text).await
    }

    /// Proactive send delegates to `send_text` — the BB REST call is
    /// identical. The operator gate (`FreedomConfig::proactive.enabled`)
    /// is the CALLER's responsibility per the C-11 trait contract.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.send_text(chat_id, text).await
    }

    /// Outbound attachment via `POST /api/v1/message/attachment` (verified
    /// against the BB server source: `MessageRouter.sendAttachment`, form
    /// fields `chatGuid` + `name` required, file part named `attachment`,
    /// optional `tempGuid`). BB has no caption field on attachment sends —
    /// a non-empty caption goes out as a follow-up text message.
    async fn send_media(
        &self,
        chat_id: &str,
        media: &MediaPayload,
        caption: Option<&str>,
    ) -> std::result::Result<MessageId, ChannelError> {
        let filename = media
            .filename
            .clone()
            .unwrap_or_else(|| default_attachment_name(media.kind).to_string());
        let part = reqwest::multipart::Part::bytes(media.data.clone())
            .file_name(filename.clone())
            .mime_str(&media.mime)
            .map_err(|e| {
                ChannelError::Transport(self.scrub(format!("BlueBubbles attachment mime: {e}")))
            })?;
        let form = reqwest::multipart::Form::new()
            .text("chatGuid", chat_id.to_string())
            .text("tempGuid", format!("neoth-{}", uuid::Uuid::new_v4()))
            .text("name", filename)
            .part("attachment", part);
        let url = self.api_url("message/attachment");
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .multipart(form)
            .send()
            .await
            .map_err(|e| {
                ChannelError::Transport(
                    self.scrub(format!("BlueBubbles POST /message/attachment: {e}")),
                )
            })?;
        map_bb_status(&resp)?;
        let val: serde_json::Value = resp.json().await.map_err(|error| {
            ChannelError::Transport(self.scrub(format!(
                "BlueBubbles POST /message/attachment response JSON: {error}"
            )))
        })?;
        let guid = val
            .pointer("/data/guid")
            .and_then(|v| v.as_str())
            .unwrap_or("sent")
            .to_string();
        if let Some(c) = caption {
            if !c.trim().is_empty() {
                // The attachment is already delivered — a caption failure must
                // NOT surface as Err, or the proactive tick would mark the item
                // Failed and a retry would deliver the attachment twice.
                if let Err(e) = self.post_text(chat_id, c).await {
                    tracing::warn!(
                        error = %e,
                        "bluebubbles caption send failed after attachment delivery (dropped)"
                    );
                }
            }
        }
        Ok(MessageId(guid))
    }
}

/// Fallback filename when the payload carries none — BB requires `name`.
fn default_attachment_name(kind: crate::channels::MediaKind) -> &'static str {
    use crate::channels::MediaKind;
    match kind {
        MediaKind::Image | MediaKind::Sticker => "image.png",
        MediaKind::Video => "video.mp4",
        MediaKind::Audio => "audio.m4a",
        MediaKind::Document => "file.bin",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    fn make_msg(
        guid: &str,
        address: &str,
        text: Option<&str>,
        chat_guid: &str,
        date_created: i64,
        is_from_me: bool,
    ) -> BbMessage {
        BbMessage {
            guid: guid.to_string(),
            handle: if address.is_empty() {
                None
            } else {
                Some(BbHandle {
                    address: address.to_string(),
                })
            },
            chats: if chat_guid.is_empty() {
                vec![]
            } else {
                vec![BbChat {
                    guid: chat_guid.to_string(),
                }]
            },
            text: text.map(|t| t.to_string()),
            date_created,
            is_from_me,
        }
    }

    // ── Message mapping ───────────────────────────────────────────────────

    #[test]
    fn maps_dm_message_to_inbound() {
        let msg = make_msg(
            "iMessage;-;+14155551234;abc",
            "+14155551234",
            Some("hello"),
            "iMessage;-;+14155551234",
            1_700_000_000_123,
            false,
        );
        let inbound = bb_message_to_inbound(&msg, None).expect("valid DM maps");
        assert_eq!(inbound.channel, ChannelKind::IMessageBlueBubbles);
        assert_eq!(inbound.sender_id, "+14155551234");
        assert_eq!(inbound.chat_id, "iMessage;-;+14155551234");
        assert_eq!(inbound.text.as_deref(), Some("hello"));
        assert_eq!(inbound.channel_ts_unix, 1_700_000_000_u64);
        assert_eq!(inbound.raw_ts_ms, Some(1_700_000_000_123));
    }

    #[test]
    fn outbound_messages_are_dropped() {
        let msg = make_msg("g1", "+1999", Some("my own reply"), "chat1", 0, true);
        assert!(
            bb_message_to_inbound(&msg, None).is_none(),
            "is_from_me must be dropped"
        );
    }

    #[test]
    fn blank_text_maps_to_none() {
        let msg = make_msg("g2", "+1999", Some("   "), "chat1", 0, false);
        assert!(
            bb_message_to_inbound(&msg, None).is_none(),
            "blank text dropped"
        );
    }

    #[test]
    fn missing_handle_maps_to_none() {
        let msg = make_msg("g3", "", Some("hi"), "chat1", 0, false);
        assert!(
            bb_message_to_inbound(&msg, None).is_none(),
            "missing handle dropped"
        );
    }

    #[test]
    fn missing_text_maps_to_none() {
        let msg = make_msg("g4", "+1999", None, "chat1", 0, false);
        assert!(
            bb_message_to_inbound(&msg, None).is_none(),
            "tapback/attachment-only dropped"
        );
    }

    // ── Cursor advance ────────────────────────────────────────────────────

    #[test]
    fn bb_date_to_unix_ms_preserves_server_unix_timestamp() {
        // BlueBubbles already serializes Date::getTime() (Unix ms).
        assert_eq!(bb_date_to_unix_ms(1_700_000_000_123), 1_700_000_000_123);
        // Negative clamped to 0 (paranoia against corrupted BB data)
        assert_eq!(bb_date_to_unix_ms(i64::MIN), 0);
    }

    // ── Chat GUID allowlist ───────────────────────────────────────────────

    #[test]
    fn chat_guid_allowlist_filters_unknown_chats() {
        let msg = make_msg("g5", "+1999", Some("hi"), "iMessage;-;+1999", 0, false);
        let allowed = vec!["iMessage;-;+1234".to_string()];
        assert!(
            bb_message_to_inbound(&msg, Some(&allowed)).is_none(),
            "chat not in allowlist dropped"
        );
        let allowed_match = vec!["iMessage;-;+1999".to_string()];
        assert!(
            bb_message_to_inbound(&msg, Some(&allowed_match)).is_some(),
            "chat in allowlist passes"
        );
    }

    #[test]
    fn no_chat_guid_uses_sender_address() {
        // No chats array → falls back to sender address as chat_id.
        let msg = BbMessage {
            guid: "g6".to_string(),
            handle: Some(BbHandle {
                address: "+14155551234".to_string(),
            }),
            chats: vec![], // no chats
            text: Some("fallback".to_string()),
            date_created: 0,
            is_from_me: false,
        };
        let inbound = bb_message_to_inbound(&msg, None).expect("maps");
        assert_eq!(
            inbound.chat_id, "+14155551234",
            "sender address used as fallback chat_id"
        );
    }

    // ── Adapter construction ──────────────────────────────────────────────

    #[test]
    fn new_trims_trailing_slash() {
        let pw = SecretString::from("pw");
        let ch = BlueBubblesChannel::new("http://localhost:1234/", pw, None, None).expect("builds");
        assert_eq!(
            ch.server_url, "http://localhost:1234",
            "trailing slash stripped"
        );
    }

    #[tokio::test]
    async fn poll_drains_all_message_query_pages_before_returning() {
        use wiremock::matchers::{body_json, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let common = |offset| {
            serde_json::json!({
                "after": 1_700_000_000_000_i64,
                "limit": 2,
                "offset": offset,
                "sort": "ASC",
                "with": ["chats"],
            })
        };
        Mock::given(method("POST"))
            .and(path("/api/v1/message/query"))
            .and(query_param("password", "pw"))
            .and(body_json(common(0)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": 200,
                "message": "Successfully fetched messages!",
                "data": [{"guid": "g1"}, {"guid": "g2"}],
                "metadata": {"offset": 0, "limit": 2, "total": 3, "count": 2}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/message/query"))
            .and(query_param("password", "pw"))
            .and(body_json(common(2)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": 200,
                "message": "Successfully fetched messages!",
                "data": [{"guid": "g3"}],
                "metadata": {"offset": 2, "limit": 2, "total": 3, "count": 1}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let channel = BlueBubblesChannel::new(server.uri(), SecretString::from("pw"), None, None)
            .expect("channel builds");
        let messages = channel
            .poll_messages_with_page_size(1_700_000_000_000, 2)
            .await
            .expect("all pages load");
        assert_eq!(
            messages
                .iter()
                .map(|message| message.guid.as_str())
                .collect::<Vec<_>>(),
            vec!["g1", "g2", "g3"]
        );
    }

    #[tokio::test]
    async fn malformed_send_success_response_is_not_reported_as_sent() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/message/text"))
            .and(query_param("password", "pw"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
            .mount(&server)
            .await;
        let channel =
            BlueBubblesChannel::new(server.uri(), SecretString::from("pw"), None, None).unwrap();
        let error = channel
            .post_text("iMessage;-;+1234", "hello")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("response JSON"), "got: {error}");
    }

    #[test]
    fn send_before_connect_returns_transport_error_shape() {
        // Verify that calling post_text against a non-existent URL produces
        // a Transport error, not a panic.  We can't hit a real server in unit
        // tests, so we verify the error KIND only (no live network).
        //
        // This is a compile+shape test — the actual network call will fail
        // with a connection-refused Transport error.
        let pw = SecretString::from("pw");
        let ch = BlueBubblesChannel::new("http://127.0.0.1:19999", pw, None, None).expect("builds");
        // The error MUST be ChannelError::Transport (not Auth, not panics).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(ch.post_text("iMessage;-;+1234", "test"));
        match result {
            Err(ChannelError::Transport(_)) => {}
            Err(other) => panic!("expected Transport, got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    // ── Password never logged ─────────────────────────────────────────────

    #[test]
    fn api_url_contains_password_but_struct_debug_does_not_expose_it() {
        // Confirm the Debug impl on SecretString does NOT print the raw secret.
        let pw = SecretString::from("super_secret_pw");
        let ch = BlueBubblesChannel::new("http://localhost:1234", pw, None, None).expect("builds");
        let debug_str = format!("{:?}", ch.password);
        assert!(
            !debug_str.contains("super_secret_pw"),
            "SecretString debug must not reveal the raw password: {debug_str}"
        );
    }

    #[test]
    fn default_poll_interval_is_3s() {
        let pw = SecretString::from("pw");
        let ch = BlueBubblesChannel::new("http://localhost:1234", pw, None, None).expect("builds");
        assert_eq!(ch.poll_interval, DEFAULT_POLL_INTERVAL);
        assert_eq!(ch.poll_interval.as_secs(), 3);
    }

    #[test]
    fn default_attachment_names_cover_every_media_kind() {
        use crate::channels::MediaKind;
        // BB requires a non-empty `name` form field — every kind must map.
        for (kind, expect) in [
            (MediaKind::Image, "image.png"),
            (MediaKind::Sticker, "image.png"),
            (MediaKind::Video, "video.mp4"),
            (MediaKind::Audio, "audio.m4a"),
            (MediaKind::Document, "file.bin"),
        ] {
            assert_eq!(default_attachment_name(kind), expect);
            assert!(!default_attachment_name(kind).is_empty());
        }
    }

    #[test]
    fn with_poll_interval_overrides_default() {
        let pw = SecretString::from("pw");
        let ch = BlueBubblesChannel::new("http://localhost:1234", pw, None, None)
            .expect("builds")
            .with_poll_interval(Duration::from_millis(500));
        assert_eq!(ch.poll_interval, Duration::from_millis(500));
    }
}
