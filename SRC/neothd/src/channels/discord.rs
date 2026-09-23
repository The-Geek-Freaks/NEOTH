//! Discord channel adapter — live Gateway receive + REST send.
//!
//! `DiscordChannel::run` maintains the authenticated Gateway WebSocket loop
//! (heartbeats, resume sequence, reconnect backoff, intents) and routes
//! `MESSAGE_CREATE` envelopes into the shared channel pipeline. Replies and
//! proactive messages use Discord's v10 REST API. `validate_bot` performs the
//! read-only identity probe used by `neoth channel test discord`.
//!
//! ## Wire shape
//!
//! ```text
//! POST https://discord.com/api/v10/channels/{channel_id}/messages
//! Authorization: Bot <token>
//! Content-Type: application/json
//!
//! { "content": "<text up to 2000 chars>" }
//! ```
//!
//! Returns 200/201 with the created message envelope. NEOTH consumes
//! the `id` field as `MessageId`.
//!
//! ## Hard limits enforced
//!
//! - Discord's hard `content` limit is 2000 characters. Longer
//!   messages get split into ≤2000-char chunks; the adapter returns
//!   the LAST chunk's `MessageId` (matches Telegram's behaviour for
//!   the same overflow).
//! - Rate-limit headers (`X-RateLimit-Remaining` / `Retry-After`)
//!   are honoured: 429 maps to `ChannelError::RateLimited`.
//!
//! ## Deliberately out of scope
//!
//! - Multi-shard coordination for very large guild deployments
//! - Slash command + interaction handling
//! - Embed objects + file attachments (`multipart/form-data`)
//! - Voice channel signalling (probably never — out of NEOTH scope)

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};

use super::{Channel, ChannelError, MessageId, PipelineHandler};
use crate::secret::SecretString;

/// Hard cap on a single Discord message body. Anything longer gets
/// chunked into multiple requests.
pub const DISCORD_MAX_CONTENT_CHARS: usize = 2000;

/// Discord API base URL pinned to v10. v9 is still operational but
/// v10 is the long-term-stable contract per Discord's docs.
pub const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

/// Discord responses used here are tiny JSON envelopes. Bound them so a
/// compromised/misbehaving upstream cannot turn an identity probe or send
/// acknowledgement into an unbounded allocation.
const DISCORD_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const DISCORD_USER_AGENT: &str =
    concat!("NEOTH/", env!("CARGO_PKG_VERSION"), " (+https://neoth.dev)");

/// Discord adapter. `new` creates the outbound/probe surface; daemon inbound
/// must use [`DiscordChannel::new_inbound`] so `Channel::run` cannot ever start
/// with an open sender policy or without a WAL gate-audit writer.
pub struct DiscordChannel {
    bot_token: SecretString,
    http: reqwest::Client,
    inbound_gate: Option<DiscordInboundGate>,
}

struct DiscordInboundGate {
    allowed_sender_id: String,
    writer: crate::wal::writer::WalWriterHandle,
    live_egress: crate::cli::serve_tasks::LegacyLiveEgressProvenance,
}

type DiscordGatewayReplyPoster = std::sync::Arc<
    dyn Fn(
            String,
            String,
        )
            -> futures_util::future::BoxFuture<'static, std::result::Result<MessageId, ChannelError>>
        + Send
        + Sync,
>;

/// Build the one default-Discord Gateway reply path. Its opaque startup
/// provenance must record an authenticated intent before the adapter call and
/// a terminal result after it; an unrecordable intent refuses the call.
fn authenticated_gateway_reply_sender(
    writer: crate::wal::writer::WalWriterHandle,
    live_egress: crate::cli::serve_tasks::LegacyLiveEgressProvenance,
    post: DiscordGatewayReplyPoster,
) -> crate::channels::discord_gateway_loop::OutboundSender {
    std::sync::Arc::new(move |out: crate::channels::OutboundMessage| {
        let writer = writer.clone();
        let live_egress = live_egress.clone();
        let post = std::sync::Arc::clone(&post);
        Box::pin(async move {
            let Some(intent_id) = crate::channels::send_gate::emit_legacy_live_egress_intent(
                &writer,
                "discord",
                &out.recipient_id,
                &out.text,
                crate::time::now_unix_secs(),
                &live_egress,
            )
            .await
            else {
                anyhow::bail!(
                    "mandatory authenticated Discord egress intent could not be recorded"
                );
            };

            match post(out.recipient_id, out.text).await {
                Ok(message_id) => {
                    crate::channels::send_gate::emit_legacy_live_egress_result(
                        &writer,
                        &intent_id,
                        "delivered",
                        Some(&message_id.0),
                        crate::time::now_unix_secs(),
                        &live_egress,
                    )
                    .await
                    .map_err(|()| {
                        anyhow::anyhow!(
                            "mandatory authenticated Discord egress receipt could not be recorded"
                        )
                    })?;
                    Ok(())
                }
                Err(error) => {
                    let outcome = match &error {
                        ChannelError::Transport(_) => "transport",
                        ChannelError::NotSupported { .. } => "not_supported",
                        ChannelError::RateLimited { .. } => "rate_limited",
                        ChannelError::Auth(_) => "auth",
                    };
                    crate::channels::send_gate::emit_legacy_live_egress_result(
                        &writer,
                        &intent_id,
                        outcome,
                        None,
                        crate::time::now_unix_secs(),
                        &live_egress,
                    )
                    .await
                    .map_err(|()| {
                        anyhow::anyhow!(
                            "mandatory authenticated Discord egress receipt could not be recorded"
                        )
                    })?;
                    Err(anyhow::anyhow!("discord reply send: {error}"))
                }
            }
        })
    })
}

impl DiscordChannel {
    pub fn new(bot_token: SecretString) -> Result<Self> {
        let http = crate::providers::http_client::build_client_no_redirect()
            .context("build reqwest client for Discord adapter")?;
        Ok(Self {
            bot_token,
            http,
            inbound_gate: None,
        })
    }

    /// Construct the receive-capable adapter with its mandatory exact-user
    /// authorization policy and audit sink bound for the whole gateway life.
    pub fn new_inbound(
        bot_token: SecretString,
        allowed_sender_id: &str,
        writer: crate::wal::writer::WalWriterHandle,
        live_egress: crate::cli::serve_tasks::LegacyLiveEgressProvenance,
    ) -> Result<Self> {
        let mut channel = Self::new(bot_token)?;
        channel.inbound_gate = Some(DiscordInboundGate {
            allowed_sender_id: normalize_allowed_sender_id(allowed_sender_id)?,
            writer,
            live_egress,
        });
        Ok(channel)
    }

    /// Validate the configured bot token without sending a message.
    ///
    /// Discord's `GET /users/@me` returns the immutable bot snowflake and
    /// display identity. Redirects are disabled by the shared client so the
    /// authorization header cannot be redirected away from Discord's origin.
    pub async fn validate_bot(&self) -> std::result::Result<DiscordBotIdentity, ChannelError> {
        validate_bot_at(&self.http, DISCORD_API_BASE, &self.bot_token).await
    }
}

/// Validate and canonicalize an immutable Discord user snowflake. Usernames
/// are mutable and therefore never accepted as authorization identities.
pub fn normalize_allowed_sender_id(raw: &str) -> Result<String> {
    let value = raw.trim();
    if value.is_empty() {
        anyhow::bail!("Discord allowed sender id is required");
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("Discord allowed sender id must be a numeric user snowflake");
    }
    let parsed = value
        .parse::<u64>()
        .context("Discord allowed sender id exceeds the snowflake range")?;
    if parsed == 0 || parsed.to_string() != value {
        anyhow::bail!("Discord allowed sender id must be a canonical positive user snowflake");
    }
    Ok(value.to_string())
}

/// The Discord REST `Authorization` header value — single source of the
/// `Bot <token>` format (contract-pinned by test).
fn auth_header_value(bot_token: &SecretString) -> String {
    format!("Bot {}", bot_token.expose())
}

/// Public, secret-free result of Discord's authenticated identity probe.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct DiscordBotIdentity {
    /// Immutable Discord snowflake. This is the identity key; usernames can
    /// change and must never be used for authorization.
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub global_name: Option<String>,
}

/// Base-URL-injectable core of [`DiscordChannel::validate_bot`]. Keeping the
/// HTTP client injectable lets the wire contract be tested against loopback
/// without weakening the production endpoint or leaking a real credential.
pub(crate) async fn validate_bot_at(
    http: &reqwest::Client,
    base_url: &str,
    bot_token: &SecretString,
) -> std::result::Result<DiscordBotIdentity, ChannelError> {
    let url = format!("{}/users/@me", base_url.trim_end_matches('/'));
    let response = http
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, auth_header_value(bot_token))
        .header(reqwest::header::USER_AGENT, DISCORD_USER_AGENT)
        .send()
        .await
        .map_err(|e| ChannelError::Transport(format!("discord GET /users/@me: {e}")))?;

    let status = response.status();
    if status.as_u16() == 429 {
        let retry_after_secs = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|n| n.ceil() as u64)
            .unwrap_or(1);
        return Err(ChannelError::RateLimited { retry_after_secs });
    }

    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(ChannelError::Auth(format!(
            "discord GET /users/@me returned HTTP {}",
            status.as_u16()
        )));
    }
    if !status.is_success() {
        return Err(ChannelError::Transport(format!(
            "discord GET /users/@me returned HTTP {}",
            status.as_u16()
        )));
    }

    let body = response_bytes_limited(response, DISCORD_MAX_RESPONSE_BYTES).await?;
    let identity: DiscordBotIdentity = serde_json::from_slice(&body)
        .map_err(|e| ChannelError::Transport(format!("discord identity response parse: {e}")))?;
    if identity.id.trim().is_empty() || identity.username.trim().is_empty() {
        return Err(ChannelError::Transport(
            "discord identity response omitted id or username".into(),
        ));
    }
    Ok(identity)
}

#[async_trait]
impl Channel for DiscordChannel {
    fn name(&self) -> &'static str {
        "discord"
    }

    /// Receive path: dial the Gateway via `discord_gateway_loop`,
    /// forward `MESSAGE_CREATE` events through `handler`, post the
    /// handler's reply back to the channel via the REST
    /// `chat.create-message` path the send-only Phase-1 build
    /// already shipped. `Deferred` flag from Phase 1 is gone —
    /// the receive loop is live as of 2026-05-21.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        use crate::channels::discord_gateway_loop::{default_intents, run_gateway_loop};

        let inbound_gate = self.inbound_gate.as_ref().context(
            "Discord inbound is fail-closed: construct with an allowed sender id and WAL writer",
        )?;
        let http = self.http.clone();
        let token = std::sync::Arc::new(self.bot_token.clone());
        let sender = {
            let http = http.clone();
            let token = std::sync::Arc::clone(&token);
            let post: DiscordGatewayReplyPoster = std::sync::Arc::new(move |recipient, text| {
                let http = http.clone();
                let token = std::sync::Arc::clone(&token);
                Box::pin(async move { post_to_discord(&http, &token, &recipient, &text).await })
            });
            authenticated_gateway_reply_sender(
                inbound_gate.writer.clone(),
                inbound_gate.live_egress.clone(),
                post,
            )
        };
        run_gateway_loop(
            self.bot_token.clone(),
            default_intents(),
            inbound_gate.allowed_sender_id.clone(),
            inbound_gate.writer.clone(),
            handler,
            Some(sender),
        )
        .await
    }

    /// Send a text message. Chunked at `DISCORD_MAX_CONTENT_CHARS`.
    /// Returns the LAST chunk's `MessageId`.
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let chunks = chunk_message(text, DISCORD_MAX_CONTENT_CHARS);
        let mut last_id: Option<MessageId> = None;
        for chunk in chunks {
            let id = self.post_one(chat_id, &chunk).await?;
            last_id = Some(id);
        }
        last_id.ok_or_else(|| ChannelError::Transport("empty text after chunking".into()))
    }

    /// C-11 wire-up (Session 21): proactive send delegates to `send_text`.
    /// Discord's REST POST is identical for solicited replies vs
    /// daemon-initiated proactive — the operator-gate
    /// (`FreedomConfig::proactive.enabled`) is the CALLER's
    /// responsibility per the C-11 trait contract.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.send_text(chat_id, text).await
    }
}

impl DiscordChannel {
    /// One single REST POST. Caller chunked appropriately.
    async fn post_one(
        &self,
        channel_id: &str,
        content: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        post_to_discord(&self.http, &self.bot_token, channel_id, content).await
    }
}

/// Free-function counterpart to `DiscordChannel::post_one`. The
/// receive loop (`channels::discord_gateway_loop`) builds its
/// reply-sender closure against this, capturing only an
/// `Arc<reqwest::Client>` plus `Arc<SecretString>` instead of an
/// `Arc<DiscordChannel>` (the adapter doesn't impl Clone, and
/// would need a layered Arc to share across the WSS read-loop
/// and the heartbeat tick). The shape mirrors
/// `slack_api::post_message` so cross-channel reviewers see the
/// same pattern.
pub async fn post_to_discord(
    http: &reqwest::Client,
    bot_token: &SecretString,
    channel_id: &str,
    content: &str,
) -> std::result::Result<MessageId, ChannelError> {
    let chunks = chunk_message(content, DISCORD_MAX_CONTENT_CHARS);
    let mut last_id: Option<MessageId> = None;
    for chunk in chunks {
        let id = post_one_chunk(http, bot_token, channel_id, &chunk).await?;
        last_id = Some(id);
    }
    last_id.ok_or_else(|| ChannelError::Transport("empty text after chunking".into()))
}

async fn post_one_chunk(
    http: &reqwest::Client,
    bot_token: &SecretString,
    channel_id: &str,
    content: &str,
) -> std::result::Result<MessageId, ChannelError> {
    let url = format!("{DISCORD_API_BASE}/channels/{channel_id}/messages");
    let body = MessageCreateRequest { content };
    let response = http
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, auth_header_value(bot_token))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::USER_AGENT, DISCORD_USER_AGENT)
        .json(&body)
        .send()
        .await
        .map_err(|e| ChannelError::Transport(format!("discord POST {url}: {e}")))?;

    let status = response.status();
    if status.as_u16() == 429 {
        let retry_after_secs = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|n| n.ceil() as u64)
            .unwrap_or(1);
        return Err(ChannelError::RateLimited { retry_after_secs });
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(ChannelError::Auth(format!(
            "discord message create returned HTTP {}",
            status.as_u16()
        )));
    }
    if !status.is_success() {
        return Err(ChannelError::Transport(format!(
            "discord message create returned HTTP {}",
            status.as_u16()
        )));
    }
    let body = response_bytes_limited(response, DISCORD_MAX_RESPONSE_BYTES).await?;
    let parsed: MessageCreateResponse = serde_json::from_slice(&body)
        .map_err(|e| ChannelError::Transport(format!("discord response parse: {e}")))?;
    Ok(MessageId(parsed.id))
}

async fn response_bytes_limited(
    response: reqwest::Response,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, ChannelError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(ChannelError::Transport(format!(
            "discord response exceeds {max_bytes}-byte limit"
        )));
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| ChannelError::Transport(format!("discord response body: {e}")))?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ChannelError::Transport(format!(
                "discord response exceeds {max_bytes}-byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Split a text payload into ≤max-char chunks. Boundary preference:
/// last newline before the cap; falling back to a hard char-split.
/// Char counts are UTF-8 codepoint counts to match Discord's spec.
pub fn chunk_message(text: &str, max_chars: usize) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut cursor = 0;
    while cursor < chars.len() {
        let remaining = chars.len() - cursor;
        if remaining <= max_chars {
            out.push(chars[cursor..].iter().collect::<String>());
            break;
        }
        // Look for last newline within the window for a clean break.
        let window_end = cursor + max_chars;
        let split = chars[cursor..window_end]
            .iter()
            .rposition(|c| *c == '\n')
            .map(|p| cursor + p + 1)
            .unwrap_or(window_end);
        out.push(chars[cursor..split].iter().collect::<String>());
        cursor = split;
    }
    out
}

// ── Wire types ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct MessageCreateRequest<'a> {
    content: &'a str,
}

#[derive(Deserialize)]
struct MessageCreateResponse {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn adapter_reports_discord_name() {
        let a = DiscordChannel::new(SecretString::new("token".into())).unwrap();
        assert_eq!(a.name(), "discord");
    }

    #[test]
    fn adapter_builds_authorization_header_with_bot_prefix() {
        let header = auth_header_value(&SecretString::new("abc123".into()));
        assert!(header.starts_with("Bot "));
        assert!(header.ends_with("abc123"));
    }

    #[tokio::test]
    async fn validate_bot_at_gets_identity_without_sending_message() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .and(header("authorization", "Bot fake-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"id":"123456789","username":"neoth","global_name":"NEOTH Bot"}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;

        let http = crate::providers::http_client::build_client_no_redirect().unwrap();
        let identity = validate_bot_at(&http, &server.uri(), &SecretString::from("fake-token"))
            .await
            .unwrap();
        assert_eq!(identity.id, "123456789");
        assert_eq!(identity.username, "neoth");
        assert_eq!(identity.global_name.as_deref(), Some("NEOTH Bot"));
    }

    #[tokio::test]
    async fn validate_bot_at_rejects_auth_and_incomplete_identity() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let unauthorized = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&unauthorized)
            .await;
        let http = crate::providers::http_client::build_client_no_redirect().unwrap();
        let err = validate_bot_at(&http, &unauthorized.uri(), &SecretString::from("bad-token"))
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::Auth(_)));

        let incomplete = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/users/@me"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"id":"","username":"neoth"}"#),
            )
            .mount(&incomplete)
            .await;
        let err = validate_bot_at(&http, &incomplete.uri(), &SecretString::from("token"))
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::Transport(_)));
    }

    #[tokio::test]
    async fn gateway_reply_sender_refuses_missing_intent_and_never_retries_adapter_error() {
        let provenance = crate::cli::serve_tasks::legacy_live_egress_provenance_for_test(
            crate::channels::ChannelKind::Discord,
        )
        .expect("Discord has sealed default live provenance");
        let refused_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let refused_post: DiscordGatewayReplyPoster = {
            let refused_calls = std::sync::Arc::clone(&refused_calls);
            std::sync::Arc::new(move |_recipient, _text| {
                refused_calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(MessageId("must-not-send".to_string())) })
            })
        };
        let refused = authenticated_gateway_reply_sender(
            crate::wal::writer::closed_test_writer(),
            provenance.clone(),
            refused_post,
        );
        assert!(
            refused(crate::channels::OutboundMessage {
                recipient_id: "private-channel".to_string(),
                text: "private-reply".to_string(),
            })
            .await
            .is_err()
        );
        assert_eq!(
            refused_calls.load(Ordering::SeqCst),
            0,
            "an unrecordable authenticated intent refuses the adapter call"
        );

        let home = tempfile::tempdir().expect("create gateway sender WAL home");
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).expect("create gateway sender WAL");
        let segment = wal.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), home.path().to_path_buf())
                .expect("spawn gateway sender WAL writer");
        ready
            .wait()
            .await
            .expect("initialize gateway sender WAL writer");
        let failed_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let failed_post: DiscordGatewayReplyPoster = {
            let failed_calls = std::sync::Arc::clone(&failed_calls);
            std::sync::Arc::new(move |_recipient, _text| {
                failed_calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Err(ChannelError::Transport("fixture failure".to_string())) })
            })
        };
        let failed = authenticated_gateway_reply_sender(writer.clone(), provenance, failed_post);
        assert!(
            failed(crate::channels::OutboundMessage {
                recipient_id: "private-channel".to_string(),
                text: "private-reply".to_string(),
            })
            .await
            .is_err()
        );
        assert_eq!(
            failed_calls.load(Ordering::SeqCst),
            1,
            "a terminal adapter error is recorded without a retry"
        );
        drop(failed);
        drop(writer);
        join.await
            .expect("join gateway sender WAL writer")
            .expect("close gateway sender WAL writer");

        let bytes = tokio::fs::read(segment)
            .await
            .expect("read gateway sender WAL");
        let mut cursor = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut outcome = None;
        while cursor < bytes.len() {
            let frame = crate::wal::frame::decode_frame(&bytes[cursor..])
                .expect("complete gateway sender evidence frame");
            if frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::ChannelEgressResult as u8
            {
                let payload: serde_json::Value =
                    serde_json::from_slice(frame.payload).expect("gateway terminal JSON");
                outcome = payload["outcome"].as_str().map(str::to_string);
            }
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(outcome.as_deref(), Some("transport"));
    }

    #[tokio::test]
    async fn gateway_reply_sender_records_delivery_and_leaves_one_effect_unsettled_when_receipt_writer_stops()
     {
        let provenance = crate::cli::serve_tasks::legacy_live_egress_provenance_for_test(
            crate::channels::ChannelKind::Discord,
        )
        .expect("Discord has sealed default live provenance");

        let delivered_home = tempfile::tempdir().expect("create delivered gateway sender WAL home");
        let delivered_wal = delivered_home.path().join("wal");
        std::fs::create_dir_all(&delivered_wal).expect("create delivered gateway sender WAL");
        let delivered_segment = delivered_wal.join("000001.wal");
        let (delivered_writer, delivered_join, delivered_ready) =
            crate::wal::writer::spawn_for_home_ready(
                delivered_segment.clone(),
                delivered_home.path().to_path_buf(),
            )
            .expect("spawn delivered gateway sender WAL writer");
        delivered_ready
            .wait()
            .await
            .expect("initialize delivered gateway sender WAL writer");
        let delivered_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let delivered_post: DiscordGatewayReplyPoster = {
            let delivered_calls = std::sync::Arc::clone(&delivered_calls);
            std::sync::Arc::new(move |_recipient, _text| {
                delivered_calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(MessageId("accepted-message".to_string())) })
            })
        };
        let delivered = authenticated_gateway_reply_sender(
            delivered_writer.clone(),
            provenance.clone(),
            delivered_post,
        );
        delivered(crate::channels::OutboundMessage {
            recipient_id: "private-channel".to_string(),
            text: "private-reply".to_string(),
        })
        .await
        .expect("accepted Discord post records a delivered terminal");
        assert_eq!(delivered_calls.load(Ordering::SeqCst), 1);
        drop(delivered);
        drop(delivered_writer);
        delivered_join
            .await
            .expect("join delivered gateway sender WAL writer")
            .expect("close delivered gateway sender WAL writer");

        let delivered_bytes = tokio::fs::read(&delivered_segment)
            .await
            .expect("read delivered gateway sender WAL");
        let mut cursor = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut delivered_intent = None;
        let mut delivered_outcome = None;
        while cursor < delivered_bytes.len() {
            let frame = crate::wal::frame::decode_frame(&delivered_bytes[cursor..])
                .expect("complete delivered gateway sender evidence frame");
            let payload: serde_json::Value =
                serde_json::from_slice(frame.payload).expect("delivered gateway sender JSON");
            if frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::ChannelEgressIntent as u8
            {
                delivered_intent = payload["intent_id"].as_str().map(str::to_string);
            }
            if frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::ChannelEgressResult as u8
            {
                delivered_outcome = Some((
                    payload["intent_id"].as_str().map(str::to_string),
                    payload["outcome"].as_str().map(str::to_string),
                ));
            }
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(
            delivered_outcome,
            Some((delivered_intent, Some("delivered".to_string())))
        );

        let unsettled_home = tempfile::tempdir().expect("create unsettled gateway sender WAL home");
        let unsettled_wal = unsettled_home.path().join("wal");
        std::fs::create_dir_all(&unsettled_wal).expect("create unsettled gateway sender WAL");
        let unsettled_segment = unsettled_wal.join("000001.wal");
        let (unsettled_writer, unsettled_completion, unsettled_ready) =
            crate::wal::writer::spawn_for_home_ready_with_completion(
                unsettled_segment.clone(),
                unsettled_home.path().to_path_buf(),
            )
            .expect("spawn unsettled gateway sender WAL writer");
        unsettled_ready
            .wait()
            .await
            .expect("initialize unsettled gateway sender WAL writer");
        let (post_started_tx, post_started_rx) = tokio::sync::oneshot::channel();
        let (post_release_tx, post_release_rx) = tokio::sync::oneshot::channel();
        let post_started_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(post_started_tx)));
        let post_release_rx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(post_release_rx)));
        let unsettled_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let unsettled_post: DiscordGatewayReplyPoster = {
            let post_started_tx = std::sync::Arc::clone(&post_started_tx);
            let post_release_rx = std::sync::Arc::clone(&post_release_rx);
            let unsettled_calls = std::sync::Arc::clone(&unsettled_calls);
            std::sync::Arc::new(move |_recipient, _text| {
                unsettled_calls.fetch_add(1, Ordering::SeqCst);
                post_started_tx
                    .lock()
                    .expect("lock post-start sender")
                    .take()
                    .expect("one production adapter call")
                    .send(())
                    .expect("test observes production adapter call");
                let post_release_rx = std::sync::Arc::clone(&post_release_rx);
                Box::pin(async move {
                    post_release_rx
                        .lock()
                        .await
                        .take()
                        .expect("one production adapter result")
                        .await
                        .expect("test releases accepted adapter result");
                    Ok(MessageId("accepted-before-receipt-failure".to_string()))
                })
            })
        };
        let unsettled = authenticated_gateway_reply_sender(
            unsettled_writer.clone(),
            provenance,
            unsettled_post,
        );
        let in_flight = {
            let unsettled = unsettled.clone();
            tokio::spawn(async move {
                unsettled(crate::channels::OutboundMessage {
                    recipient_id: "private-channel".to_string(),
                    text: "private-reply".to_string(),
                })
                .await
            })
        };
        post_started_rx
            .await
            .expect("intent persisted before adapter call is observed");
        unsettled_completion.abort_handle().abort();
        assert!(
            unsettled_completion.wait().await.is_err(),
            "the result writer stops before the accepted adapter result"
        );
        post_release_tx
            .send(())
            .expect("release accepted adapter result after writer stops");
        assert!(
            in_flight
                .await
                .expect("join unsettled production sender")
                .is_err(),
            "receipt write failure is visible to the caller after one adapter effect"
        );
        assert_eq!(
            unsettled_calls.load(Ordering::SeqCst),
            1,
            "a receipt failure never replays the accepted adapter effect"
        );
        drop(unsettled);
        drop(unsettled_writer);

        let unsettled_bytes = tokio::fs::read(unsettled_segment)
            .await
            .expect("read unsettled gateway sender WAL");
        let mut cursor = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut intent_count = 0;
        let mut result_count = 0;
        while cursor < unsettled_bytes.len() {
            let frame = crate::wal::frame::decode_frame(&unsettled_bytes[cursor..])
                .expect("complete unsettled gateway sender evidence frame");
            if frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::ChannelEgressIntent as u8
            {
                intent_count += 1;
            }
            if frame.header.event_subtype
                == crate::wal::events::ExtendedSubtype::ChannelEgressResult as u8
            {
                result_count += 1;
            }
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(intent_count, 1, "the accepted effect retains its intent");
        assert_eq!(
            result_count, 0,
            "the stopped writer leaves the intent unsettled"
        );
    }

    #[test]
    fn chunk_message_empty_returns_empty() {
        let chunks = chunk_message("", 100);
        assert!(chunks.is_empty());
    }

    #[test]
    fn chunk_message_under_limit_one_chunk() {
        let chunks = chunk_message("hello", 2000);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "hello");
    }

    #[test]
    fn chunk_message_prefers_newline_boundary() {
        let text = "line one\nline two\nline three";
        let chunks = chunk_message(text, 18);
        // First chunk should end after a newline (clean break).
        assert!(
            chunks[0].ends_with('\n'),
            "first chunk should end at a newline: {:?}",
            chunks[0]
        );
    }

    #[test]
    fn chunk_message_falls_back_to_hard_split_without_newlines() {
        let text = "x".repeat(2050);
        let chunks = chunk_message(&text, 2000);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].chars().count() <= 2000);
        assert!(chunks[1].chars().count() <= 2000);
        // No content loss.
        let total: usize = chunks.iter().map(|c| c.chars().count()).sum();
        assert_eq!(total, 2050);
    }

    #[test]
    fn chunk_message_respects_unicode_codepoints() {
        // Emoji + multi-byte chars should be measured by codepoint,
        // not byte length.
        let text = "🦀".repeat(2050);
        let chunks = chunk_message(&text, 2000);
        for c in &chunks {
            assert!(
                c.chars().count() <= 2000,
                "chunk over limit: {}",
                c.chars().count()
            );
        }
    }

    #[test]
    fn chunk_message_caps_long_message_into_multiple() {
        let text = "z".repeat(7000);
        let chunks = chunk_message(&text, 2000);
        assert!(
            chunks.len() >= 4,
            "expected ≥4 chunks, got {}",
            chunks.len()
        );
        for c in &chunks {
            assert!(c.chars().count() <= 2000);
        }
    }

    // Pick #29 deferral test removed 2026-05-21 — the receive path
    // is no longer Deferred. `DiscordChannel::run` dials the
    // Gateway via `discord_gateway_loop::run_gateway_loop`. A live
    // receive integration test against a real bot token belongs in
    // a `#[ignore]`d e2e suite, not the offline unit module.

    #[test]
    fn api_base_pinned_to_v10() {
        assert_eq!(DISCORD_API_BASE, "https://discord.com/api/v10");
    }

    #[test]
    fn discord_max_content_chars_matches_spec() {
        // Hard rule from Discord docs — bumping this requires platform
        // confirmation.
        assert_eq!(DISCORD_MAX_CONTENT_CHARS, 2000);
    }

    /// C-11 wire-up pin: send_proactive routes through the same
    /// Discord REST POST path as send_text. Verified via the
    /// bogus-token Transport error — proves the trait default
    /// `NotSupported` is no longer the path Discord falls through to.
    #[tokio::test]
    async fn send_proactive_delegates_to_send_text_returns_transport_error_on_invalid_token() {
        use crate::channels::ChannelError;
        let c = DiscordChannel::new(SecretString::from("invalid-bot-token")).unwrap();
        let err = c.send_proactive("12345", "hi").await.unwrap_err();
        // Discord classifies 401 as Auth (not Transport); both prove
        // the delegate landed. The trait default would have surfaced
        // NotSupported { feature: "send_proactive" } — we pin that
        // explicit negative below.
        assert!(
            matches!(err, ChannelError::Transport(_) | ChannelError::Auth(_)),
            "expected Transport or Auth (delegate path); got {err:?}"
        );
        let msg = format!("{err}");
        assert!(!msg.contains("not supported"), "leaked default impl: {msg}");
    }
}
