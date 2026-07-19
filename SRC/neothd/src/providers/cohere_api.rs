//! Cohere v2 Messages REST adapter (`api.cohere.com/v2/chat`).
//!
//! PF-02 — the second provider (after `anthropic_api`) that cannot ride
//! the OpenAI-compat path: the Cohere v2 wire format is a HYBRID —
//! OpenAI-like REQUEST (a `messages` array that DOES carry a `system`
//! role, a `stream` bool, Bearer auth) but an Anthropic-like RESPONSE
//! (`message.content[].text` blocks) with NESTED token usage
//! (`usage.tokens.input_tokens`). Verified against docs.cohere.com/
//! reference/chat (2026-05). Uses a plain API key (Bearer) — no OAuth,
//! no token expiry.
//!
//! Non-streaming (one POST, full response) — mirrors `openai_api` /
//! `anthropic_api`; the `Provider::stream` default impl wraps `complete`
//! in a single done-chunk, so `neoth chat --stream` still works.
//!
//! ## ⚠ Cost — this path BILLS per-token
//!
//! Cohere is a metered API (no subscription path). The wizard flags this
//! at selection. Operators on a Claude subscription should prefer
//! `claude_cli` (OAuth, no metering) — see
//! [[feedback_claude_cli_is_the_cost_free_path]].

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::quota::{QuotaError, parse_retry_after};
use super::{Completion, Provider, ProviderDispatchPermit, ProviderRequestControls, Request};
use crate::secret::SecretString;

/// Output-token cap sent as `max_tokens` (Cohere makes it optional, but a
/// cap bounds runaway output + cost). 4096 covers a chat reply.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Adapter for the native Cohere v2 Chat API.
pub struct CohereAdapter {
    /// e.g. `https://api.cohere.com/v2` — no trailing slash.
    endpoint: String,
    /// `Authorization: Bearer <key>`. SecretString so Debug stays redacted.
    api_key: SecretString,
    /// Default model when the per-request override is None.
    default_model: String,
    /// Output-token cap sent as `max_tokens`.
    max_tokens: u32,
    /// Shared HTTP client.
    http: reqwest::Client,
}

impl CohereAdapter {
    pub fn new(api_key: SecretString, default_model: String) -> Result<Self> {
        Self::build(
            "https://api.cohere.com/v2".to_string(),
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
        let http = crate::providers::http_client::build_client_no_redirect()?;
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
impl Provider for CohereAdapter {
    fn name(&self) -> &'static str {
        "cohere_api"
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::SAMPLING_MAX_ONE
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.default_model)
    }

    fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
        Some(self.max_tokens)
    }

    async fn complete_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        crate::providers::circuit_breaker::run_with_breaker("cohere_api", async {
            let started = Instant::now();
            let model = req
                .model
                .clone()
                .unwrap_or_else(|| self.default_model.clone());

            // Cohere v2: `system` is a messages[] ROLE (OpenAI-like), NOT a
            // top-level field (unlike Anthropic).
            let mut messages = Vec::new();
            if let Some(sys) = req.system.as_ref().filter(|s| !s.is_empty()) {
                messages.push(CohereMessage {
                    role: "system",
                    content: sys.clone(),
                });
            }
            messages.push(CohereMessage {
                role: "user",
                content: req.prompt.clone(),
            });

            let body = CohereRequest {
                stream: false,
                model: model.clone(),
                messages,
                max_tokens: Some(self.max_tokens),
                temperature: req.temperature,
                p: req.top_p,
                seed: req.sampling_seed,
                stop_sequences: (!req.stop_sequences.is_empty())
                    .then(|| req.stop_sequences.clone()),
            };

            let url = format!("{}/chat", self.endpoint);
            let response = self
                .http
                .post(&url)
                .bearer_auth(self.api_key.expose())
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {url}"))?;

            let status = response.status();
            if !status.is_success() {
                if status.as_u16() == 429 {
                    let retry_after = parse_retry_after(response.headers());
                    let body = response
                        .text()
                        .await
                        .unwrap_or_default()
                        .replace(self.api_key.expose(), "[REDACTED]");
                    return Err(anyhow::Error::new(QuotaError {
                        provider: "cohere_api",
                        retry_after,
                        body: body.trim().to_string(),
                    }));
                }
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".into())
                    .replace(self.api_key.expose(), "[REDACTED]");
                anyhow::bail!(
                    "cohere_api returned HTTP {}: {}",
                    status.as_u16(),
                    body.trim()
                );
            }

            let parsed: CohereResponse = response
                .json()
                .await
                .context("parse cohere_api response JSON")?;

            // Concatenate every text block (Anthropic-like content[] array).
            // Empty → error (CDX-07 silent-fail-to-empty guard).
            let text: String = parsed
                .message
                .as_ref()
                .map(|m| {
                    m.content
                        .iter()
                        .filter(|b| b.block_type == "text")
                        .filter_map(|b| b.text.as_deref())
                        .collect::<Vec<_>>()
                        .join("")
                })
                .unwrap_or_default();
            if text.is_empty() {
                anyhow::bail!(
                    "cohere_api returned 200 OK but no text content (finish_reason {:?}) — \
                     likely a refusal or non-text reply. Inspect the raw body via NEOTH_LOG=debug.",
                    parsed.finish_reason
                );
            }

            let (input_tokens, output_tokens) = parsed
                .usage
                .as_ref()
                .and_then(|u| u.tokens.as_ref())
                .map(|t| (Some(t.input_tokens), Some(t.output_tokens)))
                .unwrap_or((None, None));

            let latency = started.elapsed();
            debug!(
                adapter = "cohere_api",
                model = %model,
                response_bytes = text.len(),
                latency_ms = latency.as_millis(),
                "cohere completion"
            );

            Ok(Completion {
                text,
                identity: Default::default(),
                model,
                latency,
                input_tokens,
                output_tokens,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        })
        .await
    }
}

// ── Wire types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CohereRequest {
    stream: bool,
    model: String,
    messages: Vec<CohereMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
}

#[derive(Serialize)]
struct CohereMessage {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct CohereResponse {
    #[serde(default)]
    message: Option<CohereRespMessage>,
    #[serde(default)]
    usage: Option<CohereUsage>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct CohereRespMessage {
    #[serde(default)]
    content: Vec<CohereContentBlock>,
}

#[derive(Deserialize)]
struct CohereContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    #[serde(default)]
    text: Option<String>,
}

#[derive(Deserialize)]
struct CohereUsage {
    #[serde(default)]
    tokens: Option<CohereTokens>,
}

#[derive(Deserialize)]
struct CohereTokens {
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
        let a = CohereAdapter::new(
            SecretString::from("co-test"),
            "command-a-plus-05-2026".to_string(),
        )
        .expect("construct");
        assert_eq!(a.name(), "cohere_api");
        assert_eq!(a.endpoint, "https://api.cohere.com/v2");
    }

    #[test]
    fn request_controls_use_cohere_v2_wire_names_and_omit_absent_values() {
        let base = || CohereRequest {
            stream: false,
            model: "command-a".into(),
            messages: vec![CohereMessage {
                role: "user",
                content: "ping".into(),
            }],
            max_tokens: Some(4096),
            temperature: None,
            p: None,
            seed: None,
            stop_sequences: None,
        };
        let empty = serde_json::to_value(base()).unwrap();
        for field in ["temperature", "p", "seed", "stop_sequences"] {
            assert!(empty.get(field).is_none());
        }

        let controlled = serde_json::to_value(CohereRequest {
            temperature: Some(0.5),
            p: Some(0.85),
            seed: Some(11),
            stop_sequences: Some(vec!["END".into()]),
            ..base()
        })
        .unwrap();
        assert_eq!(controlled["temperature"].as_f64(), Some(f64::from(0.5_f32)));
        assert_eq!(controlled["p"].as_f64(), Some(f64::from(0.85_f32)));
        assert_eq!(controlled["seed"], 11);
        assert_eq!(controlled["stop_sequences"], serde_json::json!(["END"]));
    }

    fn build_adapter_against(server_uri: &str) -> CohereAdapter {
        CohereAdapter::build(
            server_uri.to_string(),
            SecretString::from("co-mock-key"),
            "command-mock".to_string(),
            DEFAULT_MAX_TOKENS,
        )
        .expect("adapter constructs against mock URI")
    }

    #[tokio::test]
    async fn mock_200_ok_returns_completion_with_nested_token_counts() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat"))
            .and(header("authorization", "Bearer co-mock-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "co-resp-1",
                "finish_reason": "COMPLETE",
                "message": {
                    "role": "assistant",
                    "content": [{ "type": "text", "text": "hello from cohere" }]
                },
                "usage": { "tokens": { "input_tokens": 11, "output_tokens": 6 } }
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
            .expect("200 OK must succeed");
        assert_eq!(completion.text, "hello from cohere");
        assert_eq!(completion.input_tokens, Some(11));
        assert_eq!(completion.output_tokens, Some(6));
        assert_eq!(completion.model, "command-mock");
    }

    #[tokio::test]
    async fn mock_request_has_system_as_message_role_stream_false_and_max_tokens() {
        // Pins the Cohere envelope: system is a messages[] ROLE (NOT a
        // top-level field), stream=false, max_tokens present, model from
        // the per-request override.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat"))
            .and(body_json(serde_json::json!({
                "stream": false,
                "model": "command-override",
                "messages": [
                    { "role": "system", "content": "you are NEOTH" },
                    { "role": "user", "content": "ping" }
                ],
                "max_tokens": DEFAULT_MAX_TOKENS,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": { "content": [{ "type": "text", "text": "pong" }] }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let completion = adapter
            .complete(Request {
                prompt: "ping".into(),
                system: Some("you are NEOTH".into()),
                model: Some("command-override".into()),
                ..Default::default()
            })
            .await
            .expect("envelope mock must match");
        assert_eq!(completion.text, "pong");
        // missing usage → None token counts, no error.
        assert_eq!(completion.input_tokens, None);
    }

    #[tokio::test]
    async fn mock_429_returns_quota_error_with_retry_after() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "9")
                    .set_body_raw(r#"{"message":"rate limited"}"#, "application/json"),
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
        assert_eq!(quota.provider, "cohere_api");
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(9)));
    }

    #[tokio::test]
    async fn mock_401_names_status_and_provider() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_raw(r#"{"message":"invalid api token"}"#, "application/json"),
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
            .expect_err("401 must surface as error");
        let msg = err.to_string();
        assert!(msg.contains("401"), "must name status; got: {msg}");
        assert!(msg.contains("cohere_api"), "must name provider; got: {msg}");
    }

    #[tokio::test]
    async fn mock_200_with_no_text_block_errors_not_empty() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "finish_reason": "MAX_TOKENS",
                "message": { "content": [] }
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
            msg.contains("no text content") || msg.contains("MAX_TOKENS"),
            "error must explain WHY; got: {msg}"
        );
    }
}
