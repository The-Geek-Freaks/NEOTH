//! Operator-opt-in WhatsApp Web via the repository-owned Baileys sidecar.
//!
//! The Node sidecar in `bridges/whatsapp-baileys/` owns QR pairing, Baileys
//! reconnects, encrypted auth state, durable inbound buffering, media download,
//! and outbound idempotency. This Rust adapter owns NEOTH policy: dedicated
//! credentials (never Meta Cloud credentials), mandatory sender allowlisting,
//! deny-by-default group allowlisting, WAL gate audits, a durable restart
//! cursor, pipeline dispatch, and reply delivery.
//!
//! HTTP is accepted only for loopback bridges. Remote bridges must use HTTPS
//! (normally Tailscale Serve or an authenticated TLS reverse proxy). Every
//! request carries a dedicated bearer token and redirects are disabled.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use base64::Engine as _;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tracing::{info, warn};

use crate::secret::SecretString;

use super::{
    Channel, ChannelError, ChannelKind, InboundMessage, MediaKind, MediaPayload, MessageId,
    PipelineHandler, PipelineHandlerWithActivity,
};

const CURSOR_VERSION: u8 = 1;
const MAX_PROCESSED_IDS: usize = 20_000;
const MAX_MEDIA_BYTES: usize = 10 * 1024 * 1024;
const MAX_HEALTH_BODY: usize = 64 * 1024;
const MAX_POLL_BODY: usize = 16 * 1024 * 1024;
const MAX_ERROR_BODY: usize = 4 * 1024;
const LONG_POLL_MS: u64 = 25_000;
const MAX_RECONNECT_BACKOFF_SECS: u64 = 30;
const SEND_ATTEMPTS: usize = 3;
/// The sidecar's opt-in alone is deliberately insufficient: the daemon owner
/// must independently opt in before an admitted inbound may create a status.
const STATUS_DAEMON_OPT_IN_ENV: &str = "NEOTH_WA_STATUS_EDIT_DAEMON_V1";
const MAX_STATUS_REVISIONS: u64 = 16;
static OUTBOUND_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, thiserror::Error)]
enum BridgeError {
    #[error("invalid Baileys bridge configuration: {0}")]
    Config(String),
    #[error("Baileys bridge authentication failed: {0}")]
    Auth(String),
    #[error("Baileys bridge cursor cannot continue safely: {0}")]
    Cursor(String),
    #[error("Baileys bridge outbound outcome is unknown; refusing to resend: {0}")]
    Ambiguous(String),
    #[error("Baileys bridge rate limited the request; retry after {0}s")]
    RateLimited(u64),
    #[error("Baileys bridge transport failed: {0}")]
    Transport(String),
}

impl BridgeError {
    fn into_channel(self) -> ChannelError {
        match self {
            Self::Auth(message) => ChannelError::Auth(message),
            Self::RateLimited(retry_after_secs) => ChannelError::RateLimited { retry_after_secs },
            Self::Config(message)
            | Self::Cursor(message)
            | Self::Ambiguous(message)
            | Self::Transport(message) => ChannelError::Transport(message),
        }
    }

    fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::Auth(_) | Self::Config(_) | Self::Cursor(_) | Self::Ambiguous(_)
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BridgeHealth {
    pub status: String,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub linked: bool,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub latest_cursor: String,
    #[serde(default)]
    capabilities: BridgeCapabilities,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct BridgeCapabilities {
    #[serde(default)]
    text: bool,
    #[serde(default)]
    media: bool,
    #[serde(default)]
    cursor: bool,
    #[serde(default)]
    status_edit_v1: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct PollResponse {
    cursor: String,
    messages: Vec<BridgeInbound>,
}

#[derive(Debug, Clone, Deserialize)]
struct BridgeInbound {
    id: String,
    chat_id: String,
    sender_id: String,
    #[serde(default)]
    sender_display: Option<String>,
    timestamp_ms: i64,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    reply_to: Option<String>,
    #[serde(default)]
    is_group: bool,
    #[serde(default)]
    media: Option<BridgeInboundMedia>,
}

#[derive(Debug, Clone, Deserialize)]
struct BridgeInboundMedia {
    kind: String,
    mime: String,
    #[serde(default)]
    filename: Option<String>,
    data_b64: String,
}

#[derive(Debug, Serialize)]
struct BridgeSendRequest<'a> {
    to: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    idempotency_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    media: Option<BridgeSendMedia>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_turn: Option<BridgeStatusTurn<'a>>,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct BridgeStatusTurn<'a> {
    account_id: &'a str,
    chat_id: &'a str,
    inbound_id: &'a str,
}

#[derive(Debug, Serialize)]
struct BridgeSendMedia {
    kind: &'static str,
    mime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    data_b64: String,
    ptt: bool,
}

#[derive(Debug, Deserialize)]
struct BridgeSendResponse {
    message_id: String,
}

/// Closed, redacted wire projection accepted by W2492. It deliberately has no
/// tool arguments, model prompt, output, error string, or arbitrary detail.
#[derive(Debug, Serialize)]
struct BridgeStatusRequest<'a> {
    op: &'static str,
    account_id: &'a str,
    chat_id: &'a str,
    inbound_id: &'a str,
    idempotency_key: String,
    revision: u64,
    activity: BridgeStatusActivity<'a>,
}

#[derive(Debug, Serialize)]
struct BridgeStatusActivity<'a> {
    phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct BridgeApiError {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    earliest_cursor: Option<String>,
    #[serde(default)]
    latest_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorState {
    version: u8,
    account_id: String,
    cursor: String,
    /// Message id -> provider timestamp. The timestamp makes bounded pruning
    /// deterministic; ids are claimed before policy/pipeline side effects.
    processed_ids: BTreeMap<String, i64>,
}

impl CursorState {
    fn load_or_initialize(path: &Path, account_id: &str, latest_cursor: &str) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let state = Self::new(account_id, latest_cursor);
                state.persist(path)?;
                return Ok(state);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read Baileys cursor {}", path.display()));
            }
        };
        let state: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse Baileys cursor {}", path.display()))?;
        if state.version != CURSOR_VERSION {
            anyhow::bail!(
                "unsupported Baileys cursor version {} in {} (expected {})",
                state.version,
                path.display(),
                CURSOR_VERSION
            );
        }
        if state.account_id != account_id {
            // A QR re-pair changed the inbox. Reusing the prior account's
            // cursor or ids can suppress unrelated messages, so start at the
            // new bridge's explicit live boundary.
            let state = Self::new(account_id, latest_cursor);
            state.persist(path)?;
            return Ok(state);
        }
        Ok(state)
    }

    fn new(account_id: &str, latest_cursor: &str) -> Self {
        Self {
            version: CURSOR_VERSION,
            account_id: account_id.to_string(),
            cursor: latest_cursor.to_string(),
            processed_ids: BTreeMap::new(),
        }
    }

    fn persist(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("serialize Baileys cursor")?;
        crate::util::atomic_write::atomic_write(path, &bytes)
            .with_context(|| format!("persist Baileys cursor {}", path.display()))
    }

    /// At-most-once claim, matching Nostr's restart policy: duplicate agent
    /// turns are more dangerous than a visible failed reply. The sidecar also
    /// idempotently keys replies, so in-process transport retries stay safe.
    fn claim(&mut self, path: &Path, id: &str, timestamp_ms: i64) -> Result<bool> {
        if self.processed_ids.contains_key(id) {
            return Ok(false);
        }
        self.processed_ids.insert(id.to_string(), timestamp_ms);
        self.prune();
        if let Err(error) = self.persist(path) {
            self.processed_ids.remove(id);
            return Err(error);
        }
        Ok(true)
    }

    fn advance(&mut self, path: &Path, cursor: String) -> Result<()> {
        self.cursor = cursor;
        self.persist(path)
    }

    fn prune(&mut self) {
        if self.processed_ids.len() <= MAX_PROCESSED_IDS {
            return;
        }
        let mut by_age: Vec<(String, i64)> = self
            .processed_ids
            .iter()
            .map(|(id, timestamp)| (id.clone(), *timestamp))
            .collect();
        by_age.sort_unstable_by_key(|(_, timestamp)| *timestamp);
        for (id, _) in by_age
            .into_iter()
            .take(self.processed_ids.len() - MAX_PROCESSED_IDS)
        {
            self.processed_ids.remove(&id);
        }
    }
}

#[derive(Clone)]
struct BridgeClient {
    base_url: String,
    token: SecretString,
    http: reqwest::Client,
}

impl BridgeClient {
    fn new(base_url: impl AsRef<str>, token: SecretString) -> Result<Self, BridgeError> {
        let base_url = validate_bridge_url(base_url.as_ref())?;
        if token.expose().len() < 32
            || !token.expose().bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
            })
        {
            return Err(BridgeError::Config(
                "whatsapp_baileys_token must be 32+ URL-safe ASCII characters".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(40))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| BridgeError::Config(format!("build HTTP client: {error}")))?;
        Ok(Self {
            base_url,
            token,
            http,
        })
    }

    async fn health(&self) -> Result<BridgeHealth, BridgeError> {
        let response = self
            .http
            .get(format!("{}/v1/health", self.base_url))
            .bearer_auth(self.token.expose())
            .send()
            .await
            .map_err(|error| BridgeError::Transport(format!("GET /v1/health: {error}")))?;
        let health: BridgeHealth = decode_response(response, MAX_HEALTH_BODY).await?;
        if health.status != "ok" {
            return Err(BridgeError::Transport(format!(
                "health status was `{}`",
                health.status
            )));
        }
        if !health.capabilities.text || !health.capabilities.cursor {
            return Err(BridgeError::Config(
                "bridge lacks required text/cursor capabilities".to_string(),
            ));
        }
        if health.latest_cursor.parse::<u64>().is_err() {
            return Err(BridgeError::Config(
                "bridge returned a non-numeric latest_cursor".to_string(),
            ));
        }
        Ok(health)
    }

    async fn poll(&self, cursor: &str) -> Result<PollResponse, BridgeError> {
        let timeout_ms = LONG_POLL_MS.to_string();
        let response = self
            .http
            .get(format!("{}/v1/messages", self.base_url))
            .bearer_auth(self.token.expose())
            // One event keeps the response beneath the 16 MiB trust-boundary
            // cap even when it carries the maximum 10 MiB base64 media.
            .query(&[
                ("cursor", cursor),
                ("limit", "1"),
                ("timeout_ms", timeout_ms.as_str()),
            ])
            .send()
            .await
            .map_err(|error| BridgeError::Transport(format!("GET /v1/messages: {error}")))?;
        let batch: PollResponse = decode_response(response, MAX_POLL_BODY).await?;
        if batch.cursor.parse::<u64>().is_err() {
            return Err(BridgeError::Config(
                "bridge returned a non-numeric cursor".to_string(),
            ));
        }
        if batch.messages.len() > 1 {
            return Err(BridgeError::Config(
                "bridge ignored limit=1 and returned multiple messages".to_string(),
            ));
        }
        Ok(batch)
    }

    async fn send(
        &self,
        recipient: &str,
        text: Option<&str>,
        media: Option<BridgeSendMedia>,
        idempotency_key: &str,
    ) -> Result<MessageId, BridgeError> {
        self.send_with_status(recipient, text, media, idempotency_key, None).await
    }

    async fn send_with_status(
        &self,
        recipient: &str,
        text: Option<&str>,
        media: Option<BridgeSendMedia>,
        idempotency_key: &str,
        status_turn: Option<BridgeStatusTurn<'_>>,
    ) -> Result<MessageId, BridgeError> {
        let body = BridgeSendRequest {
            to: recipient,
            text,
            idempotency_key,
            media,
            status_turn,
        };
        let response = self
            .http
            .post(format!("{}/v1/messages", self.base_url))
            .bearer_auth(self.token.expose())
            .json(&body)
            .send()
            .await
            .map_err(|error| BridgeError::Transport(format!("POST /v1/messages: {error}")))?;
        let sent: BridgeSendResponse = decode_response(response, MAX_HEALTH_BODY).await?;
        if sent.message_id.trim().is_empty() {
            return Err(BridgeError::Transport(
                "bridge returned an empty outbound message_id".to_string(),
            ));
        }
        Ok(MessageId(sent.message_id))
    }

    async fn status(&self, request: &BridgeStatusRequest<'_>) -> Result<(), BridgeError> {
        let response = self
            .http
            .post(format!("{}/v1/status", self.base_url))
            .bearer_auth(self.token.expose())
            .json(request)
            .send()
            .await
            .map_err(|error| BridgeError::Transport(format!("POST /v1/status: {error}")))?;
        let sent: BridgeSendResponse = decode_response(response, MAX_HEALTH_BODY).await?;
        if sent.message_id.trim().is_empty() {
            return Err(BridgeError::Transport(
                "bridge returned an empty status message_id".to_string(),
            ));
        }
        Ok(())
    }
}

async fn response_bytes_limited(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, Vec<u8>), BridgeError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(BridgeError::Transport(format!(
            "bridge response exceeds {max_bytes} bytes"
        )));
    }
    let status = response.status();
    let headers = response.headers().clone();
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| BridgeError::Transport(error.to_string()))?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(BridgeError::Transport(format!(
                "bridge response exceeds {max_bytes} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, headers, body))
}

async fn decode_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<T, BridgeError> {
    let (status, headers, body) = response_bytes_limited(response, max_bytes).await?;
    if status.is_success() {
        return serde_json::from_slice(&body)
            .map_err(|error| BridgeError::Transport(format!("decode bridge JSON: {error}")));
    }
    let parsed: BridgeApiError = serde_json::from_slice(&body).unwrap_or(BridgeApiError {
        error: String::new(),
        message: String::from_utf8_lossy(&body[..body.len().min(MAX_ERROR_BODY)]).to_string(),
        earliest_cursor: None,
        latest_cursor: None,
    });
    match status.as_u16() {
        401 | 403 => Err(BridgeError::Auth(if parsed.message.is_empty() {
            format!("HTTP {status}")
        } else {
            parsed.message
        })),
        409 if matches!(parsed.error.as_str(), "cursor_expired" | "future_cursor") => {
            Err(BridgeError::Cursor(format!(
                "{} (earliest={}, latest={}); inspect the sidecar journal, then remove only the NEOTH cursor file to establish a new explicit live boundary",
                if parsed.message.is_empty() {
                    parsed.error
                } else {
                    parsed.message
                },
                parsed.earliest_cursor.as_deref().unwrap_or("?"),
                parsed.latest_cursor.as_deref().unwrap_or("?")
            )))
        }
        409 if matches!(
            parsed.error.as_str(),
            "outbound_outcome_unknown" | "idempotency_payload_mismatch"
        ) =>
        {
            Err(BridgeError::Ambiguous(parsed.message))
        }
        429 => {
            let retry_after_secs = headers
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
                .unwrap_or(5);
            Err(BridgeError::RateLimited(retry_after_secs))
        }
        _ => Err(BridgeError::Transport(format!(
            "HTTP {status}: {}",
            if parsed.message.is_empty() {
                parsed.error
            } else {
                parsed.message
            }
        ))),
    }
}

fn validate_bridge_url(raw: &str) -> Result<String, BridgeError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|error| BridgeError::Config(format!("malformed URL: {error}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BridgeError::Config(
            "URL userinfo is forbidden; use whatsapp_baileys_token".to_string(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(BridgeError::Config(
            "bridge URL must not contain a query or fragment".to_string(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| BridgeError::Config("URL has no host".to_string()))?;
    let loopback = is_loopback_host(host);
    match parsed.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => {
            return Err(BridgeError::Config(
                "remote bridge URLs must use HTTPS; HTTP is loopback-only".to_string(),
            ));
        }
        scheme => {
            return Err(BridgeError::Config(format!(
                "unsupported bridge URL scheme `{scheme}`"
            )));
        }
    }
    Ok(trimmed.to_string())
}

/// Shared by CLI staging and the live bridge constructor so both surfaces
/// apply the exact same loopback-only HTTP exception (including IPv6 forms).
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let literal = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    literal.eq_ignore_ascii_case("localhost")
        || literal
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn normalize_sender_id(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    if let Some(local) = value.strip_suffix("@s.whatsapp.net") {
        let phone = local.split(':').next().unwrap_or(local);
        if !phone.is_empty() && phone.chars().all(|character| character.is_ascii_digit()) {
            return format!("+{phone}");
        }
    }
    value
}

fn parse_allowlist(raw: &str, required: bool, label: &str) -> Result<BTreeSet<String>> {
    let values: BTreeSet<String> = raw
        .split(',')
        .map(normalize_sender_id)
        .filter(|value| !value.is_empty())
        .collect();
    if required && values.is_empty() {
        anyhow::bail!("{label} must contain at least one exact sender id");
    }
    Ok(values)
}

fn decode_inbound(raw: &BridgeInbound) -> Result<InboundMessage> {
    if raw.id.trim().is_empty() || raw.chat_id.trim().is_empty() || raw.sender_id.trim().is_empty()
    {
        anyhow::bail!("bridge event id/chat_id/sender_id must be non-empty");
    }
    let media = raw.media.as_ref().map(decode_media).transpose()?;
    let text = raw
        .text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    if text.is_none() && media.is_none() {
        anyhow::bail!("bridge event has neither text nor media");
    }
    if raw.is_group != raw.chat_id.ends_with("@g.us") {
        anyhow::bail!("bridge event group flag disagrees with chat_id");
    }
    Ok(InboundMessage {
        channel: ChannelKind::WhatsAppBaileys,
        chat_id: raw.chat_id.clone(),
        thread_id: None,
        sender_id: normalize_sender_id(&raw.sender_id),
        sender_display: raw.sender_display.clone(),
        text,
        media,
        reply_to: raw.reply_to.clone().map(MessageId),
        message_id: Some(raw.id.clone()),
        edit_unix: None,
        mention_kind: None,
        channel_ts_unix: (raw.timestamp_ms / 1000).max(0) as u64,
        raw_ts_ms: Some(raw.timestamp_ms),
        human_uuid: None,
    })
}

fn decode_media(raw: &BridgeInboundMedia) -> Result<MediaPayload> {
    if raw.data_b64.len() > (MAX_MEDIA_BYTES * 4 / 3) + 8 {
        anyhow::bail!("bridge media base64 exceeds 10 MiB decoded bound");
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(&raw.data_b64)
        .context("decode bridge media base64")?;
    if data.is_empty() || data.len() > MAX_MEDIA_BYTES {
        anyhow::bail!("bridge media must contain 1 byte..10 MiB");
    }
    let kind = match raw.kind.as_str() {
        "image" => MediaKind::Image,
        "video" => MediaKind::Video,
        "audio" => MediaKind::Audio,
        "document" => MediaKind::Document,
        "sticker" => MediaKind::Sticker,
        other => anyhow::bail!("unsupported bridge media kind `{other}`"),
    };
    if raw.mime.trim().is_empty() || raw.mime.contains('\r') || raw.mime.contains('\n') {
        anyhow::bail!("bridge media MIME is empty or contains a newline");
    }
    Ok(MediaPayload {
        kind,
        data,
        mime: raw.mime.clone(),
        filename: raw.filename.clone(),
    })
}

fn media_for_send(media: &MediaPayload) -> Result<BridgeSendMedia, ChannelError> {
    if media.data.is_empty() || media.data.len() > MAX_MEDIA_BYTES {
        return Err(ChannelError::Transport(
            "WhatsApp Baileys media must contain 1 byte..10 MiB".to_string(),
        ));
    }
    let kind = match media.kind {
        MediaKind::Image => "image",
        MediaKind::Video => "video",
        MediaKind::Audio => "audio",
        MediaKind::Document => "document",
        MediaKind::Sticker => "sticker",
    };
    Ok(BridgeSendMedia {
        kind,
        mime: media.mime.clone(),
        filename: media.filename.clone(),
        data_b64: base64::engine::general_purpose::STANDARD.encode(&media.data),
        ptt: false,
    })
}

fn idempotency_key(prefix: &str, parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    format!("neoth-{prefix}-{:x}", hasher.finalize())
}

fn one_shot_idempotency_key(prefix: &str, recipient: &str, payload: &[u8]) -> String {
    let nonce = OUTBOUND_NONCE.fetch_add(1, Ordering::Relaxed);
    idempotency_key(
        prefix,
        &[
            recipient.as_bytes(),
            payload,
            &crate::time::now_unix_ns().to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

/// Read-only live probe used by `neoth channel test whatsapp_baileys`.
pub async fn probe_bridge(
    base_url: &str,
    token: SecretString,
) -> std::result::Result<BridgeHealth, ChannelError> {
    BridgeClient::new(base_url, token)
        .map_err(BridgeError::into_channel)?
        .health()
        .await
        .map_err(BridgeError::into_channel)
}

/// NEOTH's live adapter to the repository-owned Baileys sidecar.
pub struct WhatsAppBaileysChannel {
    bridge: BridgeClient,
    allowed_senders: BTreeSet<String>,
    allowed_groups: BTreeSet<String>,
    cursor_path: PathBuf,
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
}

impl WhatsAppBaileysChannel {
    pub fn new(
        base_url: impl AsRef<str>,
        token: SecretString,
        allowed_senders_csv: impl AsRef<str>,
        allowed_groups_csv: Option<&str>,
        cursor_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        Ok(Self {
            bridge: BridgeClient::new(base_url, token).map_err(anyhow::Error::new)?,
            allowed_senders: parse_allowlist(
                allowed_senders_csv.as_ref(),
                true,
                "whatsapp_baileys_allowed_senders",
            )?,
            allowed_groups: parse_allowlist(
                allowed_groups_csv.unwrap_or_default(),
                false,
                "whatsapp_baileys_allowed_groups",
            )?,
            cursor_path: cursor_path.into(),
            gate_writer: None,
        })
    }

    pub fn with_gate_writer(mut self, writer: crate::wal::writer::WalWriterHandle) -> Self {
        self.gate_writer = Some(writer);
        self
    }

    async fn send_reply_with_retry(
        &self,
        recipient: &str,
        text: &str,
        inbound_id: &str,
        status_turn: Option<BridgeStatusTurn<'_>>,
    ) -> std::result::Result<MessageId, BridgeError> {
        let key = idempotency_key("wa-reply", &[inbound_id.as_bytes()]);
        let mut backoff = 1u64;
        let mut last_error = None;
        for attempt in 0..SEND_ATTEMPTS {
            match self.bridge.send_with_status(recipient, Some(text), None, &key, status_turn).await {
                Ok(id) => return Ok(id),
                Err(error) if error.is_fatal() => return Err(error),
                Err(BridgeError::RateLimited(seconds)) if attempt + 1 < SEND_ATTEMPTS => {
                    tokio::time::sleep(Duration::from_secs(seconds.min(30))).await;
                    last_error = Some(BridgeError::RateLimited(seconds));
                }
                Err(error) if attempt + 1 < SEND_ATTEMPTS => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(4);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| BridgeError::Transport("send attempts exhausted".into())))
    }

    async fn wait_until_connected(&self) -> Result<BridgeHealth> {
        let mut backoff = 1u64;
        loop {
            match self.bridge.health().await {
                Ok(health)
                    if health.connected
                        && health.linked
                        && health
                            .account_id
                            .as_deref()
                            .is_some_and(|id| !id.is_empty()) =>
                {
                    return Ok(health);
                }
                Ok(_) => {
                    warn!(
                        channel = "whatsapp_baileys",
                        "Baileys bridge reachable but not paired/connected; waiting for QR pairing"
                    );
                }
                Err(error) if error.is_fatal() => return Err(anyhow::Error::new(error)),
                Err(error) => warn!(error = %error, "Baileys bridge health probe failed; retrying"),
            }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF_SECS);
        }
    }

    async fn audit_rejection(&self, sender: &str, reason: &'static str) {
        super::emit_gate_rejected_reason(
            self.gate_writer.as_ref(),
            sender,
            "whatsapp_baileys",
            reason,
        )
        .await;
    }

    /// The activity-aware path is intentionally Baileys-specific. It owns the
    /// sidecar status publisher for exactly one durable, admitted inbound turn
    /// and joins it before the ordinary final `wa-reply` path is reached.
    pub async fn run_with_activity(
        &self,
        handler: PipelineHandlerWithActivity,
        daemon_status_opt_in: bool,
    ) -> Result<()> {
        let health = self.wait_until_connected().await?;
        let account_id = health
            .account_id
            .context("bridge connected without account_id")?;
        let status_enabled = daemon_status_opt_in && health.capabilities.status_edit_v1;
        let mut state =
            CursorState::load_or_initialize(&self.cursor_path, &account_id, &health.latest_cursor)?;
        info!(
            channel = "whatsapp_baileys",
            account = %account_id,
            media = health.capabilities.media,
            status_edit_v1 = status_enabled,
            cursor = %state.cursor,
            "Baileys bridge adapter live"
        );
        let mut backoff = 1u64;
        loop {
            let batch = match self.bridge.poll(&state.cursor).await {
                Ok(batch) => {
                    backoff = 1;
                    batch
                }
                Err(error) if error.is_fatal() => return Err(anyhow::Error::new(error)),
                Err(error) => {
                    warn!(error = %error, backoff, "Baileys poll failed; reconnecting");
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF_SECS);
                    continue;
                }
            };
            for raw in &batch.messages {
                if !state.claim(&self.cursor_path, &raw.id, raw.timestamp_ms)? {
                    continue;
                }
                let inbound = match decode_inbound(raw) {
                    Ok(inbound) => inbound,
                    Err(error) => {
                        warn!(message_id = %raw.id, error = %error, "malformed authenticated Baileys event dropped");
                        self.audit_rejection(&raw.sender_id, "malformed_bridge_event").await;
                        continue;
                    }
                };
                if !self.allowed_senders.contains(&inbound.sender_id) {
                    self.audit_rejection(&inbound.sender_id, "not_on_allowlist").await;
                    continue;
                }
                if raw.is_group
                    && !self.allowed_groups.contains(&normalize_sender_id(&raw.chat_id))
                {
                    self.audit_rejection(&inbound.sender_id, "group_not_on_allowlist").await;
                    continue;
                }

                // Mint only after claim and both admissions. The sink identity
                // never selects a recipient; the sidecar independently binds
                // account/chat/inbound to its retained journal tuple.
                let (activity_sink, status_owner) = if status_enabled {
                    match crate::mcp::dispatch_loop::ToolActivitySink::new_authenticated(
                        status_turn_identity(&account_id, &raw.id),
                    ) {
                        Ok(sink) => {
                            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
                            let publisher = publish_turn_status(
                                self.bridge.clone(),
                                sink.clone(),
                                account_id.clone(),
                                raw.chat_id.clone(),
                                raw.id.clone(),
                                cancel_rx,
                            );
                            (Some(sink), Some((cancel_tx, publisher)))
                        }
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                };

                let pipeline = handler(inbound, activity_sink);
                let pipeline_result = if let Some((cancel_tx, publisher)) = status_owner {
                    run_status_owned_pipeline(pipeline, publisher, cancel_tx).await
                } else {
                    pipeline.await
                };
                match pipeline_result {
                    Ok(Some(outbound)) => {
                        if let Err(error) = self
                            .send_reply_with_retry(
                                &outbound.recipient_id,
                                &outbound.text,
                                &raw.id,
                                status_enabled.then_some(BridgeStatusTurn {
                                    account_id: &account_id,
                                    chat_id: &raw.chat_id,
                                    inbound_id: &raw.id,
                                }),
                            )
                            .await
                        {
                            warn!(message_id = %raw.id, error = %error, "Baileys reply failed after idempotent retries");
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(message_id = %raw.id, error = %error, "Baileys pipeline rejected inbound")
                    }
                }
            }
            state.advance(&self.cursor_path, batch.cursor)?;
        }
    }
}

pub(crate) fn status_daemon_opted_in() -> bool {
    status_daemon_opted_in_from(std::env::var(STATUS_DAEMON_OPT_IN_ENV).ok().as_deref())
}

fn status_daemon_opted_in_from(value: Option<&str>) -> bool {
    value == Some("1")
}

fn status_turn_identity(account_id: &str, inbound_id: &str) -> String {
    // ToolActivitySink rejects overlong identities. Hashing preserves a stable
    // authenticated local identity without injecting raw message ids into it.
    let mut digest = Sha256::new();
    digest.update(account_id.as_bytes());
    digest.update([0]);
    digest.update(inbound_id.as_bytes());
    format!("wa-status:{}", hex::encode(digest.finalize()))
}

fn status_idempotency_key(account_id: &str, chat_id: &str, inbound_id: &str, revision: u64) -> String {
    let mut digest = Sha256::new();
    for part in [account_id.as_bytes(), chat_id.as_bytes(), inbound_id.as_bytes()] {
        digest.update(part);
        digest.update([0]);
    }
    digest.update(revision.to_le_bytes());
    format!("neoth-wa-status-{}", hex::encode(digest.finalize()))
}

fn status_activity(event: &crate::mcp::dispatch_loop::ToolActivity) -> Option<BridgeStatusActivity<'_>> {
    use crate::mcp::dispatch_loop::ToolActivityPhase;
    match event.phase {
        ToolActivityPhase::Started => Some(BridgeStatusActivity {
            phase: "tool_start",
            label: Some(event.label.as_str()),
        }),
        ToolActivityPhase::Succeeded => Some(BridgeStatusActivity {
            phase: "tool_finish",
            label: Some(event.label.as_str()),
        }),
        ToolActivityPhase::Rejected => Some(BridgeStatusActivity {
            phase: "tool_rejected",
            label: Some(event.label.as_str()),
        }),
        ToolActivityPhase::Failed => Some(BridgeStatusActivity { phase: "error", label: None }),
        // Report uncertainty explicitly, without suggesting completion.
        ToolActivityPhase::Unknown => Some(BridgeStatusActivity { phase: "unknown", label: None }),
    }
}

// Both futures remain children of the inbound turn. Dropping that turn drops
// the publisher too; no detached task can keep posting after channel teardown.
async fn run_status_owned_pipeline<P, S>(
    pipeline: P,
    publisher: S,
    cancel: tokio::sync::watch::Sender<bool>,
) -> P::Output
where
    P: std::future::Future,
    S: std::future::Future<Output = ()>,
{
    tokio::pin!(pipeline, publisher);
    tokio::select! {
        result = &mut pipeline => {
            let _ = cancel.send(true);
            publisher.await;
            result
        }
        () = &mut publisher => pipeline.await,
    }
}

async fn publish_turn_status(
    bridge: BridgeClient,
    sink: crate::mcp::dispatch_loop::ToolActivitySink,
    account_id: String,
    chat_id: String,
    inbound_id: String,
    mut cancelled: tokio::sync::watch::Receiver<bool>,
) {
    // Activity may precede the first publisher poll; consume it from revision zero.
    let mut observed = 0;
    let mut last_event_seq = 0;
    let mut revision = 0;
    loop {
        let changed = sink.changed_after(observed);
        tokio::pin!(changed);
        let next = tokio::select! {
            biased;
            _ = cancelled.changed() => return,
            next = &mut changed => next,
        };
        observed = next;
        let (events, incomplete) = sink.snapshot();
        if incomplete || revision >= MAX_STATUS_REVISIONS {
            return;
        }
        let Some(event) = events.into_iter().rev().find(|event| event.event_seq > last_event_seq) else {
            continue;
        };
        last_event_seq = event.event_seq;
        let Some(activity) = status_activity(&event) else {
            return;
        };
        let request = BridgeStatusRequest {
            op: if revision == 0 { "create" } else { "edit" },
            account_id: &account_id,
            chat_id: &chat_id,
            inbound_id: &inbound_id,
            idempotency_key: status_idempotency_key(&account_id, &chat_id, &inbound_id, revision),
            revision,
            activity,
        };
        let sent = bridge.status(&request);
        tokio::pin!(sent);
        let result = tokio::select! {
            biased;
            _ = cancelled.changed() => return,
            result = &mut sent => result,
        };
        // Any response failure, including unknown 409/5xx outcomes, closes the
        // publisher without retrying or perturbing the ordinary final reply.
        if result.is_err() {
            return;
        }
        revision = revision.saturating_add(1);
        if matches!(event.phase, crate::mcp::dispatch_loop::ToolActivityPhase::Failed | crate::mcp::dispatch_loop::ToolActivityPhase::Unknown) {
            return;
        }
    }
}

#[async_trait]
impl Channel for WhatsAppBaileysChannel {
    fn name(&self) -> &'static str {
        "whatsapp_baileys"
    }

    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        let handler = std::sync::Arc::new(handler);
        self.run_with_activity(
            Box::new(move |inbound, _| handler(inbound)),
            false,
        )
        .await
    }

    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let key = one_shot_idempotency_key("wa-text", chat_id, text.as_bytes());
        self.bridge
            .send(chat_id, Some(text), None, &key)
            .await
            .map_err(BridgeError::into_channel)
    }

    async fn send_media(
        &self,
        chat_id: &str,
        media: &MediaPayload,
        caption: Option<&str>,
    ) -> std::result::Result<MessageId, ChannelError> {
        let body = media_for_send(media)?;
        let key = one_shot_idempotency_key("wa-media", chat_id, &media.data);
        self.bridge
            .send(chat_id, caption, Some(body), &key)
            .await
            .map_err(BridgeError::into_channel)
    }

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

    fn token() -> SecretString {
        SecretString::from("x".repeat(32))
    }

    #[test]
    fn url_policy_requires_tls_off_host() {
        assert!(validate_bridge_url("http://127.0.0.1:9120").is_ok());
        assert!(validate_bridge_url("http://127.42.0.9:9120").is_ok());
        assert!(validate_bridge_url("http://[::1]:9120/").is_ok());
        assert!(validate_bridge_url("https://wa-bridge.example.test").is_ok());
        assert!(validate_bridge_url("http://wa-bridge.example.test").is_err());
        assert!(validate_bridge_url("file:///tmp/socket").is_err());
        assert!(validate_bridge_url("https://user:pw@example.test").is_err());
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("example.test"));
    }

    #[test]
    fn constructor_requires_sender_allowlist_and_strong_token() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            WhatsAppBaileysChannel::new(
                "http://127.0.0.1:9120",
                SecretString::from("short"),
                "+49123",
                None,
                temp.path().join("cursor.json")
            )
            .is_err()
        );
        assert!(
            WhatsAppBaileysChannel::new(
                "http://127.0.0.1:9120",
                token(),
                "",
                None,
                temp.path().join("cursor.json")
            )
            .is_err()
        );
    }

    #[test]
    fn sender_ids_normalize_phone_jids_but_keep_lids_and_groups_exact() {
        assert_eq!(
            normalize_sender_id("49170123:4@s.whatsapp.net"),
            "+49170123"
        );
        assert_eq!(normalize_sender_id("ABC@lid"), "abc@lid");
        assert_eq!(
            normalize_sender_id("120363000000000000@g.us"),
            "120363000000000000@g.us"
        );
    }

    #[test]
    fn inbound_text_and_media_map_to_canonical_envelope() {
        let raw = BridgeInbound {
            id: "group:m1".into(),
            chat_id: "120363000000000000@g.us".into(),
            sender_id: "49170123@s.whatsapp.net".into(),
            sender_display: Some("Alex".into()),
            timestamp_ms: 1_700_000_000_123,
            text: Some("caption".into()),
            reply_to: Some("quoted".into()),
            is_group: true,
            media: Some(BridgeInboundMedia {
                kind: "image".into(),
                mime: "image/png".into(),
                filename: Some("x.png".into()),
                data_b64: base64::engine::general_purpose::STANDARD.encode(b"png"),
            }),
        };
        let inbound = decode_inbound(&raw).unwrap();
        assert_eq!(inbound.channel, ChannelKind::WhatsAppBaileys);
        assert_eq!(inbound.sender_id, "+49170123");
        assert_eq!(inbound.message_id.as_deref(), Some("group:m1"));
        assert_eq!(inbound.reply_to, Some(MessageId("quoted".into())));
        assert_eq!(inbound.channel_ts_unix, 1_700_000_000);
        assert_eq!(inbound.raw_ts_ms, Some(1_700_000_000_123));
        assert_eq!(inbound.media.unwrap().data, b"png");
    }

    #[test]
    fn group_flag_mismatch_and_oversize_media_fail_closed() {
        let mut raw = BridgeInbound {
            id: "m1".into(),
            chat_id: "49123@s.whatsapp.net".into(),
            sender_id: "+49123".into(),
            sender_display: None,
            timestamp_ms: 1,
            text: Some("x".into()),
            reply_to: None,
            is_group: true,
            media: None,
        };
        assert!(decode_inbound(&raw).is_err());
        raw.is_group = false;
        raw.media = Some(BridgeInboundMedia {
            kind: "image".into(),
            mime: "image/png".into(),
            filename: None,
            data_b64: "A".repeat((MAX_MEDIA_BYTES * 4 / 3) + 9),
        });
        assert!(decode_inbound(&raw).is_err());
    }

    #[test]
    fn cursor_claim_and_identity_rotation_are_restart_safe() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state/cursor.json");
        let mut state = CursorState::load_or_initialize(&path, "+491", "7").unwrap();
        assert_eq!(state.cursor, "7");
        assert!(state.claim(&path, "m1", 10).unwrap());
        assert!(!state.claim(&path, "m1", 10).unwrap());
        state.advance(&path, "8".into()).unwrap();
        let restored = CursorState::load_or_initialize(&path, "+491", "99").unwrap();
        assert_eq!(restored.cursor, "8");
        assert!(restored.processed_ids.contains_key("m1"));
        let rotated = CursorState::load_or_initialize(&path, "+492", "42").unwrap();
        assert_eq!(rotated.cursor, "42");
        assert!(rotated.processed_ids.is_empty());
    }

    #[tokio::test]
    async fn client_sends_bearer_and_idempotency_body() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header(
                "authorization",
                format!("Bearer {}", token().expose()),
            ))
            .and(body_json(serde_json::json!({
                "to": "+49123",
                "text": "hi",
                "idempotency_key": "reply:m1"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message_id": "out-1",
                "deduplicated": false
            })))
            .mount(&server)
            .await;
        let client = BridgeClient::new(server.uri(), token()).unwrap();
        let id = client
            .send("+49123", Some("hi"), None, "reply:m1")
            .await
            .unwrap();
        assert_eq!(id, MessageId("out-1".into()));
    }

    #[tokio::test]
    async fn health_and_poll_contract_are_live_and_cursor_bound() {
        use wiremock::matchers::{header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let auth = format!("Bearer {}", token().expose());
        Mock::given(method("GET"))
            .and(path("/v1/health"))
            .and(header("authorization", auth.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status":"ok", "connected":true, "linked":true,
                "account_id":"+491", "latest_cursor":"5",
                "capabilities":{"text":true,"media":true,"cursor":true}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .and(header("authorization", auth))
            .and(query_param("cursor", "5"))
            .and(query_param("limit", "1"))
            .and(query_param("timeout_ms", LONG_POLL_MS.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cursor":"6",
                "messages":[{
                    "id":"chat:m1", "chat_id":"491@s.whatsapp.net",
                    "sender_id":"+491", "timestamp_ms":1, "text":"hi",
                    "is_group":false
                }]
            })))
            .mount(&server)
            .await;
        let client = BridgeClient::new(server.uri(), token()).unwrap();
        let health = client.health().await.unwrap();
        assert_eq!(health.account_id.as_deref(), Some("+491"));
        let batch = client.poll("5").await.unwrap();
        assert_eq!(batch.cursor, "6");
        assert_eq!(batch.messages[0].id, "chat:m1");
    }

    #[tokio::test]
    async fn status_actual_channel_owner_gates_activity_and_binds_final_after_status() {
        use crate::mcp::tool_call_parser::ParsedToolCall;
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use wiremock::matchers::{header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (daemon, capability, sender_allowed, group_allowed) in [
            (true, true, true, true),
            (false, true, true, true),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, false),
        ] {
            let server = Arc::new(MockServer::start().await);
            let auth = format!("Bearer {}", token().expose());
            Mock::given(method("GET")).and(path("/v1/health"))
                .and(header("authorization", auth.clone()))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "status": "ok", "connected": true, "linked": true,
                    "account_id": "+491701234567", "latest_cursor": "0",
                    "capabilities": { "text": true, "cursor": true, "status_edit_v1": capability }
                }))).mount(&server).await;
            Mock::given(method("GET")).and(path("/v1/messages")).and(query_param("cursor", "0"))
                .and(header("authorization", auth.clone()))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "cursor": "1", "messages": [{ "id": "120@g.us:in-1", "chat_id": "120@g.us",
                        "sender_id": "+491701234567", "timestamp_ms": 1000, "is_group": true,
                        "text": "private-inbound-canary" }]
                }))).expect(1).mount(&server).await;
            // End the real adapter only after it has completed the first turn
            // and advanced the durable cursor; no dropped detached test task.
            Mock::given(method("GET")).and(path("/v1/messages")).and(query_param("cursor", "1"))
                .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                    "error": "cursor_expired", "message": "test terminal", "earliest_cursor": "2", "latest_cursor": "2"
                }))).expect(1).mount(&server).await;
            for route in ["/v1/status", "/v1/messages"] {
                Mock::given(method("POST")).and(path(route)).and(header("authorization", auth.clone()))
                    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "message_id": "reply" })))
                    .mount(&server).await;
            }
            let count = Arc::new(AtomicUsize::new(0));
            let handler_count = Arc::clone(&count);
            let handler_server = Arc::clone(&server);
            let handler: PipelineHandlerWithActivity = Box::new(move |inbound, sink| {
                let count = Arc::clone(&handler_count);
                let server = Arc::clone(&handler_server);
                Box::pin(async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(sink.is_some(), daemon && capability);
                    if let Some(sink) = sink {
                        let call = sink.try_observe(&ParsedToolCall {
                            server: "filesystem".into(), tool: "read_file".into(),
                            arguments: serde_json::json!({ "path": "private-argument-canary" }),
                        }).unwrap();
                        call.started_at_write_edge();
                        for expected in [1, 2] {
                            loop {
                                let seen = server.received_requests().await.unwrap().iter()
                                    .filter(|request| request.url.path() == "/v1/status").count();
                                if seen >= expected { break; }
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                            if expected == 1 { call.settled_from_result(false); }
                        }
                    }
                    Ok(Some(crate::channels::OutboundMessage { recipient_id: inbound.chat_id, text: "final".into() }))
                })
            });
            let home = tempfile::tempdir().unwrap();
            let channel = WhatsAppBaileysChannel::new(
                server.uri(), token(),
                if sender_allowed { "+491701234567" } else { "+491709999999" },
                Some(if group_allowed { "120@g.us" } else { "999@g.us" }),
                home.path().join("cursor.json"),
            ).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), channel.run_with_activity(handler, daemon))
                .await.expect("bounded real adapter turn");
            assert!(matches!(result.unwrap_err().downcast_ref::<BridgeError>(), Some(BridgeError::Cursor(_))));
            let admitted = sender_allowed && group_allowed;
            assert_eq!(count.load(Ordering::SeqCst), usize::from(admitted));
            let requests = server.received_requests().await.unwrap();
            let posts = requests.iter().filter(|request| request.method.as_str() == "POST").collect::<Vec<_>>();
            let active = admitted && daemon && capability;
            assert_eq!(posts.len(), if active { 3 } else { usize::from(admitted) });
            if admitted {
                let final_request = posts.last().unwrap();
                assert_eq!(final_request.url.path(), "/v1/messages");
                let body: serde_json::Value = serde_json::from_slice(&final_request.body).unwrap();
                assert_eq!(body["idempotency_key"], idempotency_key("wa-reply", &[b"120@g.us:in-1"]));
                if active {
                    assert_eq!(posts[0].url.path(), "/v1/status");
                    assert_eq!(posts[1].url.path(), "/v1/status");
                    assert_eq!(body["status_turn"], serde_json::json!({
                        "account_id": "+491701234567", "chat_id": "120@g.us", "inbound_id": "120@g.us:in-1"
                    }));
                } else {
                    assert!(body.get("status_turn").is_none());
                }
            }
            for request in posts { assert!(!String::from_utf8_lossy(&request.body).contains("private-")); }
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn status_final_reply_carries_turn_binding_and_preserves_legacy_wire() {
        assert_eq!(idempotency_key("wa-reply", &[b"120@g.us:in-1"]), "neoth-wa-reply-c578494e4757bea8f44d9d22c8ec9a314c99b594f97880d423a66bfb6d82e007");
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        for body in [
            serde_json::json!({
                "to": "120@g.us", "text": "final", "idempotency_key": "neoth-wa-reply-bound",
                "status_turn": { "account_id": "+491", "chat_id": "120@g.us", "inbound_id": "inbound" }
            }),
            serde_json::json!({ "to": "120@g.us", "text": "legacy", "idempotency_key": "legacy-key" }),
        ] {
            Mock::given(method("POST"))
                .and(path("/v1/messages"))
                .and(header("authorization", format!("Bearer {}", token().expose())))
                .and(body_json(body))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "message_id": "reply" })))
                .expect(1)
                .mount(&server)
                .await;
        }
        let client = BridgeClient::new(server.uri(), token()).unwrap();
        client.send_with_status("120@g.us", Some("final"), None, "neoth-wa-reply-bound", Some(BridgeStatusTurn {
            account_id: "+491", chat_id: "120@g.us", inbound_id: "inbound",
        })).await.unwrap();
        client.send("120@g.us", Some("legacy"), None, "legacy-key").await.unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn status_owner_publishes_preexisting_activity_then_edit_from_real_observer() {
        use crate::mcp::{dispatch_loop::ToolActivitySink, tool_call_parser::ParsedToolCall};
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        for (revision, op, phase) in [(0, "create", "tool_start"), (1, "edit", "tool_finish")] {
            Mock::given(method("POST"))
                .and(path("/v1/status"))
                .and(header("authorization", format!("Bearer {}", token().expose())))
                .and(body_json(serde_json::json!({
                    "op": op, "account_id": "+491", "chat_id": "491@s.whatsapp.net",
                    "inbound_id": "held-inbound", "revision": revision,
                    "idempotency_key": status_idempotency_key("+491", "491@s.whatsapp.net", "held-inbound", revision),
                    "activity": {"phase": phase, "label": "Read file"}
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"message_id": "status-one"})))
                .expect(1)
                .mount(&server)
                .await;
        }
        let sink = ToolActivitySink::new_authenticated("held-turn".into()).unwrap();
        let call = sink.try_observe(&ParsedToolCall {
            server: "filesystem".into(), tool: "read_file".into(),
            arguments: serde_json::json!({"path": "private-canary-not-projected"}),
        }).unwrap();
        // Deliberately emit before the owner/publisher is ever polled.
        call.started_at_write_edge();
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel::<()>();
        let publisher = publish_turn_status(
            BridgeClient::new(server.uri(), token()).unwrap(), sink,
            "+491".into(), "491@s.whatsapp.net".into(), "held-inbound".into(), cancel_rx,
        );
        let mut owner = Box::pin(run_status_owned_pipeline(
            async { finish_rx.await.expect("pipeline release") }, publisher, cancel_tx,
        ));
        let progress = async {
            for expected in [1, 2] {
                loop {
                    if server.received_requests().await.unwrap().len() >= expected { break; }
                    tokio::task::yield_now().await;
                }
                if expected == 1 { call.settled_from_result(false); }
            }
            finish_tx.send(()).unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(&mut owner, progress);
        }).await.expect("actual status HTTP create/edit and owned shutdown");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert!(!String::from_utf8_lossy(&request.body).contains("private-canary"));
        }
    }

    #[tokio::test]
    async fn status_owner_drop_retires_pipeline_and_publisher_without_detached_task() {
        use std::future::Future as _;
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

        struct DropWitness(Arc<AtomicBool>);
        impl Drop for DropWitness {
            fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
        }
        let pipeline_dropped = Arc::new(AtomicBool::new(false));
        let publisher_dropped = Arc::new(AtomicBool::new(false));
        let pipeline_witness = DropWitness(Arc::clone(&pipeline_dropped));
        let publisher_witness = DropWitness(Arc::clone(&publisher_dropped));
        let pipeline = async move {
            let _retained = pipeline_witness;
            std::future::pending::<()>().await;
        };
        let publisher = async move {
            let _retained = publisher_witness;
            std::future::pending::<()>().await;
        };
        let (cancel_tx, _cancel_rx) = tokio::sync::watch::channel(false);
        let mut owner = Box::pin(run_status_owned_pipeline(pipeline, publisher, cancel_tx));
        std::future::poll_fn(|cx| {
            assert!(owner.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        }).await;
        drop(owner);
        assert!(pipeline_dropped.load(Ordering::SeqCst));
        assert!(publisher_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn status_owner_uncertain_http_failure_stops_without_revision_retry() {
        use crate::mcp::{dispatch_loop::ToolActivitySink, tool_call_parser::ParsedToolCall};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/status"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        let sink = ToolActivitySink::new_authenticated("uncertain-turn".into()).unwrap();
        let call = sink.try_observe(&ParsedToolCall {
            server: "filesystem".into(), tool: "read_file".into(),
            arguments: serde_json::json!({}),
        }).unwrap();
        call.started_at_write_edge();
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        tokio::time::timeout(Duration::from_secs(5), publish_turn_status(
            BridgeClient::new(server.uri(), token()).unwrap(), sink,
            "+491".into(), "491@s.whatsapp.net".into(), "in-uncertain".into(), cancel_rx,
        )).await.expect("failed HTTP terminates the publisher without retry");
        call.settled_from_result(false);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[test]
    fn status_daemon_opt_in_requires_the_exact_separate_value() {
        assert!(status_daemon_opted_in_from(Some("1")));
        assert!(!status_daemon_opted_in_from(None));
        assert!(!status_daemon_opted_in_from(Some("true")));
        assert!(!status_daemon_opted_in_from(Some("1 ")));
    }

    #[test]
    fn status_writer_keeps_the_admitted_tuple_and_revision_in_its_key() {
        let first = status_idempotency_key("+491", "491@s.whatsapp.net", "in-1", 0);
        let next = status_idempotency_key("+491", "491@s.whatsapp.net", "in-1", 1);
        let other_chat = status_idempotency_key("+491", "492@s.whatsapp.net", "in-1", 0);
        assert!(first.starts_with("neoth-wa-status-"));
        assert_ne!(first, next);
        assert_ne!(first, other_chat);
        assert!(status_turn_identity("+491", "in-1").starts_with("wa-status:"));
    }

    #[test]
    fn status_projection_distinguishes_rejection_and_unknown_without_private_details() {
        use crate::mcp::dispatch_loop::{ToolActivity, ToolActivityPhase};
        let started = ToolActivity {
            turn_id: "turn".into(), event_seq: 1, ordinal: 1,
            phase: ToolActivityPhase::Started, label: "Read file".into(), detail: None,
        };
        let failed = ToolActivity { phase: ToolActivityPhase::Failed, ..started.clone() };
        let unknown = ToolActivity { phase: ToolActivityPhase::Unknown, ..started.clone() };
        let start = status_activity(&started).unwrap();
        assert_eq!(start.phase, "tool_start");
        assert_eq!(start.label, Some("Read file"));
        assert_eq!(status_activity(&failed).unwrap().phase, "error");
        let rejected = ToolActivity { phase: ToolActivityPhase::Rejected, ..started.clone() };
        assert_eq!(status_activity(&rejected).unwrap().phase, "tool_rejected");
        let uncertainty = status_activity(&unknown).unwrap();
        assert_eq!(uncertainty.phase, "unknown");
        assert_eq!(uncertainty.label, None);
    }

    #[tokio::test]
    async fn status_owner_cancellation_joins_without_an_http_status_send() {
        let sink = crate::mcp::dispatch_loop::ToolActivitySink::new_authenticated("turn".into())
            .expect("authenticated local turn identity");
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let server = wiremock::MockServer::start().await;
        let client = BridgeClient::new(server.uri(), token()).unwrap();
        let call = sink.try_observe(&crate::mcp::tool_call_parser::ParsedToolCall {
            server: "filesystem".into(), tool: "read_file".into(),
            arguments: serde_json::json!({}),
        }).unwrap();
        call.started_at_write_edge();
        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), publish_turn_status(
            client, sink, "+491".into(), "491@s.whatsapp.net".into(), "in-1".into(), cancel_rx,
        )).await.expect("cancellation beats ready activity without HTTP");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn status_client_posts_only_the_closed_v1_activity_body() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/status"))
            .and(header("authorization", format!("Bearer {}", token().expose())))
            .and(body_json(serde_json::json!({
                "op":"create", "account_id":"+491", "chat_id":"491@s.whatsapp.net",
                "inbound_id":"in-1", "idempotency_key":"neoth-wa-status-test",
                "revision":0, "activity":{"phase":"tool_start","label":"Read file"}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"message_id":"status-1"})))
            .mount(&server).await;
        let request = BridgeStatusRequest {
            op: "create", account_id: "+491", chat_id: "491@s.whatsapp.net", inbound_id: "in-1",
            idempotency_key: "neoth-wa-status-test".into(), revision: 0,
            activity: BridgeStatusActivity { phase: "tool_start", label: Some("Read file") },
        };
        BridgeClient::new(server.uri(), token()).unwrap().status(&request).await.unwrap();
    }

    #[tokio::test]
    async fn cursor_expiry_is_fatal_not_silent_skip() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error":"cursor_expired", "message":"cursor predates retained events",
                "earliest_cursor":"10", "latest_cursor":"20"
            })))
            .mount(&server)
            .await;
        let client = BridgeClient::new(server.uri(), token()).unwrap();
        let error = client.poll("1").await.unwrap_err();
        assert!(matches!(error, BridgeError::Cursor(_)));
        assert!(error.to_string().contains("earliest=10"));
    }
}
