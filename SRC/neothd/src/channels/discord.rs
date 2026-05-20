//! Discord channel adapter (Session 14 Pick #15) — Phase 1: SEND-ONLY.
//!
//! NEOTH can POST messages to a Discord channel via the bot REST API.
//! Receiving messages requires Discord's Gateway WebSocket protocol
//! (heartbeats, sequence resumes, sharding, intents) which is a
//! multi-hundred-LOC endeavour — that's Phase 2. Send-only is
//! immediately useful for "NEOTH posts cron-driven briefings to my
//! Discord channel" + "NEOTH echoes channel-EGRESS into Discord
//! when the operator wants to mirror conversation state across
//! channels".
//!
//! ## Status: SEND-ONLY in v0.1 / v0.2 / v0.3 (Codex feedback Pick #29)
//!
//! Receive (Gateway WSS) is **explicitly deferred to v0.3+** so the
//! channel-status surface stays honest. Operator running `neoth
//! channels list` (or reading freedom.yaml + `neoth doctor`) sees
//! Discord as send-capable + receive-deferred — there is no silent
//! "it should work but doesn't" gap. Path to receive: Slack
//! Socket-Mode is the reference template (`channels/slack_socket.rs`
//! ships an analogous reconnect-with-backoff WSS loop + ACK
//! contract + JSON envelope decoder). When Discord receive lands it
//! follows the same shape against `wss://gateway.discord.gg`.
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
//! ## Phase 2 follow-up
//!
//! - Gateway WebSocket connection + sharding for receive path
//! - Slash command + interaction handling
//! - Embed objects + file attachments (`multipart/form-data`)
//! - Voice channel signalling (probably never — out of NEOTH scope)

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{Channel, ChannelError, MessageId, PipelineHandler};
use crate::secret::SecretString;

/// Hard cap on a single Discord message body. Anything longer gets
/// chunked into multiple requests.
pub const DISCORD_MAX_CONTENT_CHARS: usize = 2000;

/// Discord API base URL pinned to v10. v9 is still operational but
/// v10 is the long-term-stable contract per Discord's docs.
pub const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

/// Send-only Discord adapter. Holds the bot token + a shared HTTP
/// client. Stateless — every send call is one HTTP round trip.
pub struct DiscordChannel {
    bot_token: SecretString,
    http: reqwest::Client,
}

impl DiscordChannel {
    pub fn new(bot_token: SecretString) -> Result<Self> {
        let http = crate::providers::http_client::build_client()
            .context("build reqwest client for Discord adapter")?;
        Ok(Self { bot_token, http })
    }

    fn auth_header_value(&self) -> String {
        format!("Bot {}", self.bot_token.expose())
    }
}

#[async_trait]
impl Channel for DiscordChannel {
    fn name(&self) -> &'static str {
        "discord"
    }

    /// Phase 1: receive-path not implemented — **explicitly deferred
    /// to v0.3+** per Codex 2026-05-19. Returns `Deferred` so the
    /// daemon's channel-spawn loop logs once + skips the restart
    /// loop, matching the existing Keet behaviour. The error string
    /// names v0.3+ so operators reading `neoth doctor` / channel logs
    /// know exactly where to look for the receive ETA.
    async fn run(&self, _handler: PipelineHandler) -> Result<()> {
        Err(anyhow::Error::from(ChannelError::Deferred {
            reason: "Discord Gateway WebSocket receive path is deferred to v0.3+ — \
                     Phase 1 (this build) is send-only. See channels/discord.rs module \
                     doc for the receive-implementation plan + reference template.",
        }))
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
}

impl DiscordChannel {
    /// One single REST POST. Caller chunked appropriately.
    async fn post_one(
        &self,
        channel_id: &str,
        content: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        let url = format!("{DISCORD_API_BASE}/channels/{channel_id}/messages");
        let body = MessageCreateRequest { content };
        let response = self
            .http
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, self.auth_header_value())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::USER_AGENT,
                "NEOTH/0.1 (+https://neoth.dev)",
            )
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
            let body_text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Auth(format!(
                "discord HTTP {}: {}",
                status.as_u16(),
                body_text.trim()
            )));
        }
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            return Err(ChannelError::Transport(format!(
                "discord HTTP {}: {}",
                status.as_u16(),
                body_text.trim()
            )));
        }
        let parsed: MessageCreateResponse = response
            .json()
            .await
            .map_err(|e| ChannelError::Transport(format!("discord response parse: {e}")))?;
        Ok(MessageId(parsed.id))
    }
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
        let a = DiscordChannel::new(SecretString::new("abc123".into())).unwrap();
        let header = a.auth_header_value();
        assert!(header.starts_with("Bot "));
        assert!(header.ends_with("abc123"));
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

    #[tokio::test]
    async fn run_returns_deferred_v03_marker() {
        // Pick #29 (Session 14, Codex feedback): the error string MUST
        // surface "v0.3" so operators reading `neoth doctor` or channel
        // status logs see the explicit deferral target. Without this
        // pin a future refactor could quietly drop the version, leaving
        // operators wondering "is receive coming or not?".
        let a = DiscordChannel::new(SecretString::new("token".into())).unwrap();
        let handler: PipelineHandler = Box::new(|_msg| Box::pin(async { Ok(None) }));
        let err = a.run(handler).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("v0.3"),
            "Discord receive deferral must name v0.3 explicitly; got: {msg}"
        );
        assert!(
            msg.contains("send-only"),
            "deferral message must mention Phase-1 send-only capability; got: {msg}"
        );
    }

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
}
