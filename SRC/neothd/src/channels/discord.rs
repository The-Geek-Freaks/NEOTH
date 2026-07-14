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

/// Send-only Discord adapter. Holds the bot token + a shared HTTP
/// client. Stateless — every send call is one HTTP round trip.
pub struct DiscordChannel {
    bot_token: SecretString,
    http: reqwest::Client,
}

impl DiscordChannel {
    pub fn new(bot_token: SecretString) -> Result<Self> {
        let http = crate::providers::http_client::build_client_no_redirect()
            .context("build reqwest client for Discord adapter")?;
        Ok(Self { bot_token, http })
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
        use crate::channels::discord_gateway_loop::{
            OutboundSender, default_intents, run_gateway_loop,
        };

        let http = self.http.clone();
        let token = std::sync::Arc::new(self.bot_token.clone());
        let sender: OutboundSender = {
            let http = http.clone();
            let token = std::sync::Arc::clone(&token);
            std::sync::Arc::new(move |out: crate::channels::OutboundMessage| {
                let http = http.clone();
                let token = std::sync::Arc::clone(&token);
                Box::pin(async move {
                    post_to_discord(&http, &token, &out.recipient_id, &out.text)
                        .await
                        .map(|_| ())
                        .map_err(|e| anyhow::anyhow!("discord reply send: {e}"))
                })
            })
        };
        run_gateway_loop(
            self.bot_token.clone(),
            default_intents(),
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
