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
    PipelineHandler,
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
        let body = BridgeSendRequest {
            to: recipient,
            text,
            idempotency_key,
            media,
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
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
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
    ) -> std::result::Result<MessageId, BridgeError> {
        let key = idempotency_key("wa-reply", &[inbound_id.as_bytes()]);
        let mut backoff = 1u64;
        let mut last_error = None;
        for attempt in 0..SEND_ATTEMPTS {
            match self.bridge.send(recipient, Some(text), None, &key).await {
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
}

#[async_trait]
impl Channel for WhatsAppBaileysChannel {
    fn name(&self) -> &'static str {
        "whatsapp_baileys"
    }

    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        let health = self.wait_until_connected().await?;
        let account_id = health
            .account_id
            .context("bridge connected without account_id")?;
        let mut state =
            CursorState::load_or_initialize(&self.cursor_path, &account_id, &health.latest_cursor)?;
        info!(
            channel = "whatsapp_baileys",
            account = %account_id,
            media = health.capabilities.media,
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
                        self.audit_rejection(&raw.sender_id, "malformed_bridge_event")
                            .await;
                        continue;
                    }
                };
                if !self.allowed_senders.contains(&inbound.sender_id) {
                    self.audit_rejection(&inbound.sender_id, "not_on_allowlist")
                        .await;
                    continue;
                }
                if raw.is_group
                    && !self
                        .allowed_groups
                        .contains(&normalize_sender_id(&raw.chat_id))
                {
                    self.audit_rejection(&inbound.sender_id, "group_not_on_allowlist")
                        .await;
                    continue;
                }
                match handler(inbound).await {
                    Ok(Some(outbound)) => {
                        if let Err(error) = self
                            .send_reply_with_retry(&outbound.recipient_id, &outbound.text, &raw.id)
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
        assert!(validate_bridge_url("http://[::1]:9120/").is_ok());
        assert!(validate_bridge_url("https://wa-bridge.example.test").is_ok());
        assert!(validate_bridge_url("http://wa-bridge.example.test").is_err());
        assert!(validate_bridge_url("file:///tmp/socket").is_err());
        assert!(validate_bridge_url("https://user:pw@example.test").is_err());
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
