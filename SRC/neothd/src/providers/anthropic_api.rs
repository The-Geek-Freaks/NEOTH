//! Anthropic Messages REST adapter (`api.anthropic.com/v1/messages`).
//!
//! PF-02 — the one provider that CANNOT ride the OpenAI-compat path
//! (`OpenaiCompat` against an OAI-shim) because the Anthropic wire format
//! diverges: the `system` prompt is a TOP-LEVEL field (not a `messages[]`
//! entry), `max_tokens` is REQUIRED, auth is the `x-api-key` header (not
//! `Authorization: Bearer`), a pinned `anthropic-version` header is
//! mandatory, and the response carries `content[].text` (not
//! `choices[].message.content`). Lets an operator use a key-based
//! Anthropic provider WITHOUT the `claude` CLI binary (the `ClaudeCli`
//! path), which `InferenceProvider::AnthropicApi` previously collapsed to.
//!
//! Non-streaming (one POST, full response) — mirrors `openai_api`; the
//! `Provider::stream` default impl wraps `complete` in a single done-chunk,
//! so `neoth chat --stream` still works (emitting one chunk at the end).
//!
//! ## ⚠ Cost — this path BILLS per-token
//!
//! Operator directive (2026-05-31): this adapter calls the metered
//! Anthropic API. For a Claude subscription (Claude Pro/Max or Claude Code
//! OAuth) the `ClaudeCli` provider — the `claude` CLI driven via tmux — is
//! the cost-free path (OAuth, NO per-token metering) and stays the wizard
//! default + the recommended Anthropic route. `anthropic_api` exists for
//! operators who only have an API key (no subscription); the wizard warns
//! loudly before selection so nobody bills themselves by accident.

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::quota::{QuotaError, parse_retry_after};
use super::{Completion, Provider, Request};
use crate::secret::SecretString;

/// Pinned Anthropic API version. Required on every request; bumping it is
/// a deliberate, reviewed change (a new version can alter the wire shape).
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Anthropic's `max_tokens` is REQUIRED (unlike OpenAI). 4096 output tokens
/// (~3000 words) covers a chat reply comfortably and is supported by every
/// current Claude model; operators tuning longer outputs is a follow-on.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Adapter for the native Anthropic Messages API.
pub struct AnthropicAdapter {
    /// e.g. `https://api.anthropic.com/v1` — no trailing slash.
    endpoint: String,
    /// `x-api-key: <key>`. SecretString so Debug stays redacted.
    api_key: SecretString,
    /// Default model when the per-request override is None.
    default_model: String,
    /// Output-token cap sent as the required `max_tokens` field.
    max_tokens: u32,
    /// Shared HTTP client.
    http: reqwest::Client,
}

impl AnthropicAdapter {
    pub fn new(api_key: SecretString, default_model: String) -> Result<Self> {
        Self::build(
            "https://api.anthropic.com/v1".to_string(),
            api_key,
            default_model,
            DEFAULT_MAX_TOKENS,
        )
    }

    fn build(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
        max_tokens: u32,
    ) -> Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let http = crate::providers::http_client::build_client()?;
        Ok(Self {
            endpoint,
            api_key,
            default_model,
            max_tokens,
            http,
        })
    }
}

#[async_trait]
impl Provider for AnthropicAdapter {
    fn name(&self) -> &'static str {
        "anthropic_api"
    }

    async fn complete(&self, req: Request) -> Result<Completion> {
        // GR-04: same circuit-breaker wrap as the other cloud adapters so a
        // persistent Anthropic outage trips to a fast local error.
        crate::providers::circuit_breaker::run_with_breaker("anthropic_api", async {
            let started = Instant::now();
            let model = req
                .model
                .clone()
                .unwrap_or_else(|| self.default_model.clone());

            // Anthropic: `system` is a TOP-LEVEL field, NOT a messages[]
            // entry; messages carry only user/assistant turns.
            let body = MessagesRequest {
                model: model.clone(),
                max_tokens: self.max_tokens,
                system: req.system.clone().filter(|s| !s.is_empty()),
                messages: vec![AnthropicMessage {
                    role: "user",
                    content: req.prompt.clone(),
                }],
            };

            let url = format!("{}/messages", self.endpoint);
            let response = self
                .http
                .post(&url)
                .header("x-api-key", self.api_key.expose())
                .header("anthropic-version", ANTHROPIC_VERSION)
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {url}"))?;

            let status = response.status();
            if !status.is_success() {
                // 429 carries Retry-After the quota tracker needs — extract
                // BEFORE consuming the body (same contract as openai_api).
                if status.as_u16() == 429 {
                    let retry_after = parse_retry_after(response.headers());
                    let body = response.text().await.unwrap_or_default();
                    return Err(anyhow::Error::new(QuotaError {
                        provider: "anthropic_api",
                        retry_after,
                        body: body.trim().to_string(),
                    }));
                }
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".into());
                anyhow::bail!(
                    "anthropic_api returned HTTP {}: {}",
                    status.as_u16(),
                    body.trim()
                );
            }

            let parsed: MessagesResponse = response
                .json()
                .await
                .context("parse anthropic_api response JSON")?;

            // Concatenate every text block (a normal reply is a single text
            // block; tool-use / multi-block replies still yield the prose).
            // Empty/absent text → error (CDX-07 silent-fail-to-empty guard):
            // a 200 with no text is a refusal / stop-reason oddity the
            // operator should SEE, not a blank reply.
            let text: String = parsed
                .content
                .iter()
                .filter(|b| b.block_type == "text")
                .filter_map(|b| b.text.as_deref())
                .collect::<Vec<_>>()
                .join("");
            if text.is_empty() {
                anyhow::bail!(
                    "anthropic_api returned 200 OK but no text content block (stop_reason \
                     {:?}) — likely a refusal or a non-text reply. Inspect the raw body via \
                     NEOTH_LOG=debug.",
                    parsed.stop_reason
                );
            }

            let latency = started.elapsed();
            debug!(
                adapter = "anthropic_api",
                model = %model,
                response_bytes = text.len(),
                latency_ms = latency.as_millis(),
                "anthropic completion"
            );

            Ok(Completion {
                text,
                model,
                latency,
                input_tokens: parsed.usage.as_ref().map(|u| u.input_tokens),
                output_tokens: parsed.usage.as_ref().map(|u| u.output_tokens),
            })
        })
        .await
    }
}

// ── Wire types ─────────────────────────────────────────────────────────────
//
// Minimal shapes — only the fields we send or read. serde ignores the rest.

#[derive(Serialize)]
struct MessagesRequest {
    model: String,
    max_tokens: u32,
    /// Top-level system prompt; omitted entirely when absent/empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<AnthropicMessage>,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    content: Vec<ContentBlock>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn adapter_constructs_and_names_itself() {
        let a = AnthropicAdapter::new(
            SecretString::from("sk-ant-test"),
            "claude-sonnet-4-6".to_string(),
        )
        .expect("construct");
        assert_eq!(a.name(), "anthropic_api");
        assert_eq!(a.endpoint, "https://api.anthropic.com/v1");
        assert_eq!(a.max_tokens, DEFAULT_MAX_TOKENS);
    }

    fn build_adapter_against(server_uri: &str) -> AnthropicAdapter {
        AnthropicAdapter::build(
            server_uri.to_string(),
            SecretString::from("sk-ant-mock-key"),
            "claude-mock".to_string(),
            DEFAULT_MAX_TOKENS,
        )
        .expect("adapter constructs against mock URI")
    }

    #[tokio::test]
    async fn mock_200_ok_returns_completion_with_token_counts() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .and(header("x-api-key", "sk-ant-mock-key"))
            .and(header("anthropic-version", ANTHROPIC_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_mock_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-mock",
                "content": [{ "type": "text", "text": "hello from anthropic" }],
                "stop_reason": "end_turn",
                "usage": { "input_tokens": 9, "output_tokens": 4 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let completion = adapter
            .complete(Request {
                prompt: "say hi".into(),
                ..Default::default()
            })
            .await
            .expect("200 OK must succeed");
        assert_eq!(completion.text, "hello from anthropic");
        assert_eq!(completion.input_tokens, Some(9));
        assert_eq!(completion.output_tokens, Some(4));
        assert_eq!(completion.model, "claude-mock");
    }

    #[tokio::test]
    async fn mock_request_has_system_top_level_max_tokens_and_user_message() {
        // Pins the Anthropic-specific envelope: system is a TOP-LEVEL field
        // (not in messages[]), max_tokens is present, the prompt is a single
        // user message, model comes from the per-request override.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .and(body_json(serde_json::json!({
                "model": "claude-override",
                "max_tokens": DEFAULT_MAX_TOKENS,
                "system": "you are NEOTH",
                "messages": [ { "role": "user", "content": "ping" } ],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{ "type": "text", "text": "pong" }],
                "usage": { "input_tokens": 3, "output_tokens": 1 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let completion = adapter
            .complete(Request {
                prompt: "ping".into(),
                system: Some("you are NEOTH".into()),
                model: Some("claude-override".into()),
                ..Default::default()
            })
            .await
            .expect("envelope mock must match");
        assert_eq!(completion.text, "pong");
        assert_eq!(completion.model, "claude-override");
    }

    #[tokio::test]
    async fn mock_no_system_omits_the_field() {
        // With no system prompt the `system` key must be ABSENT (not null) —
        // `skip_serializing_if`. body_json asserts exact shape.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .and(body_json(serde_json::json!({
                "model": "claude-mock",
                "max_tokens": DEFAULT_MAX_TOKENS,
                "messages": [ { "role": "user", "content": "hi" } ],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [{ "type": "text", "text": "yo" }]
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let completion = adapter
            .complete(Request {
                prompt: "hi".into(),
                ..Default::default()
            })
            .await
            .expect("no-system envelope must match");
        assert_eq!(completion.text, "yo");
        // missing usage → None token counts, no error.
        assert_eq!(completion.input_tokens, None);
        assert_eq!(completion.output_tokens, None);
    }

    #[tokio::test]
    async fn mock_429_returns_quota_error_with_retry_after() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "14")
                    .set_body_raw(
                        r#"{"error":{"type":"rate_limit_error"}}"#,
                        "application/json",
                    ),
            )
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let err = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect_err("429 must surface as QuotaError");
        let quota = err
            .downcast_ref::<QuotaError>()
            .expect("downcast to QuotaError");
        assert_eq!(quota.provider, "anthropic_api");
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(14)));
        assert!(quota.body.contains("rate_limit_error"));
    }

    #[tokio::test]
    async fn mock_401_auth_fail_names_status_and_provider() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .respond_with(ResponseTemplate::new(401).set_body_raw(
                r#"{"error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
                "application/json",
            ))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let err = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect_err("401 must surface as error");
        let msg = err.to_string();
        assert!(msg.contains("401"), "must name status; got: {msg}");
        assert!(
            msg.contains("anthropic_api"),
            "must name provider; got: {msg}"
        );
    }

    #[tokio::test]
    async fn mock_200_with_no_text_block_errors_not_empty() {
        // CDX-07 silent-fail guard: a 200 whose content has no text block
        // must error (showing stop_reason), never Ok(text="").
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": [],
                "stop_reason": "max_tokens",
                "usage": { "input_tokens": 5, "output_tokens": 0 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let err = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect_err("no text block must error, not return Ok(\"\")");
        let msg = err.to_string();
        assert!(
            msg.contains("no text content") || msg.contains("max_tokens"),
            "error must explain WHY; got: {msg}"
        );
    }
}
