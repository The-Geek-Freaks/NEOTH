//! OpenAI REST adapter (`api.openai.com` and OpenAI-compatible endpoints).
//!
//! POST {endpoint}/chat/completions with a Bearer token. Supports both the
//! upstream OpenAI service and any OpenAI-compatible endpoint
//! (LM Studio, vLLM, Anthropic via OAI-shim, etc.) by overriding `endpoint`.
//!
//! Streaming arrives in Phase 5C. Day-5b is non-streaming (one POST, full
//! response back).

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::quota::{QuotaError, parse_retry_after};
use super::{Completion, Provider, Request};
use crate::secret::SecretString;

/// Adapter for OpenAI REST + compatibles.
pub struct OpenAiAdapter {
    /// e.g. `https://api.openai.com/v1` — no trailing slash.
    endpoint: String,
    /// `Authorization: Bearer <key>`. SecretString so Debug stays redacted.
    api_key: SecretString,
    /// Default model when the per-request override is None.
    default_model: String,
    /// Shared HTTP client.
    http: reqwest::Client,
    /// Adapter name surfaced in logs + WAL events. Allows the OpenAI-compat
    /// alias to identify itself differently from upstream OpenAI even though
    /// the wire protocol is identical.
    name: &'static str,
}

impl OpenAiAdapter {
    pub fn new_openai(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
    ) -> Result<Self> {
        Self::build(endpoint, api_key, default_model, "openai_api")
    }

    pub fn new_compat(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
    ) -> Result<Self> {
        Self::build(endpoint, api_key, default_model, "openai_compat")
    }

    fn build(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
        name: &'static str,
    ) -> Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let http = crate::providers::http_client::build_client()?;
        Ok(Self {
            endpoint,
            api_key,
            default_model,
            http,
            name,
        })
    }
}

#[async_trait]
impl Provider for OpenAiAdapter {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn complete(&self, req: Request) -> Result<Completion> {
        // GR-04: wrap in circuit breaker so persistent provider
        // outages stop hammering the upstream + surface as a fast
        // local error after the failure threshold trips.
        crate::providers::circuit_breaker::run_with_breaker(self.name, async {
        let started = Instant::now();
        let model = req
            .model
            .clone()
            .unwrap_or_else(|| self.default_model.clone());

        let mut messages = Vec::new();
        if let Some(sys) = &req.system {
            messages.push(ChatMessage {
                role: "system",
                content: sys.clone(),
            });
        }
        messages.push(ChatMessage {
            role: "user",
            content: req.prompt.clone(),
        });

        let body = ChatRequest {
            model: model.clone(),
            messages,
            stream: false,
        };

        let url = format!("{}/chat/completions", self.endpoint);
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
            // 429 carries a Retry-After header that the quota tracker needs.
            // We extract it BEFORE consuming the body so the caller can
            // downcast the error to `QuotaError` and update the tracker
            // without re-parsing the response. Body is still shown to the
            // operator for diagnostics.
            if status.as_u16() == 429 {
                let retry_after = parse_retry_after(response.headers());
                let body = response.text().await.unwrap_or_default();
                return Err(anyhow::Error::new(QuotaError {
                    provider: self.name,
                    retry_after,
                    body: body.trim().to_string(),
                }));
            }
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".into());
            anyhow::bail!(
                "{} returned HTTP {}: {}",
                self.name,
                status.as_u16(),
                body.trim()
            );
        }

        let parsed: ChatResponse = response
            .json()
            .await
            .with_context(|| format!("parse {} response JSON", self.name))?;

        // CDX-07 silent-fail-to-empty fix: surface the malformed shape
        // as an error instead of silently returning "". An OpenAI-compat
        // response without choices is almost always a content-filter
        // refusal or a backend error envelope mistakenly returned as
        // 200 — operator wants to see WHY, not a blank reply.
        let text = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} returned 200 OK but the response has no choices[].message.content — \
                     likely a content-filter refusal or upstream error envelope. \
                     Inspect the raw HTTP body via NEOTH_LOG_LEVEL=debug.",
                    self.name
                )
            })?;

        let latency = started.elapsed();
        debug!(
            adapter = self.name,
            model = %model,
            response_bytes = text.len(),
            latency_ms = latency.as_millis(),
            "openai completion"
        );

        Ok(Completion {
            text,
            model,
            latency,
            input_tokens: parsed.usage.as_ref().map(|u| u.prompt_tokens),
            output_tokens: parsed.usage.as_ref().map(|u| u.completion_tokens),
        })
        }).await
    }
}

// ── Wire types ─────────────────────────────────────────────────────────────
//
// Minimal shapes — only the fields we read or send. The remote may include
// many more; serde tolerates that with `#[serde(default)]` + ignoring unknown.

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
}

#[derive(Serialize, Deserialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    content: String,
}

#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;

    /// We don't run a live HTTP server in unit tests — that lives in an
    /// integration test once mockito/wiremock is added. Here we just verify
    /// the adapter constructs and reports its name. The actual HTTP round
    /// trip is covered by mocking-based tests in `tests/openai_mock.rs`
    /// (Phase 5A-6).
    #[test]
    fn adapter_constructs_with_endpoint_and_key() {
        let a = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-4o".to_string(),
        )
        .expect("construct");
        assert_eq!(a.name(), "openai_api");

        let b = OpenAiAdapter::new_compat(
            "http://localhost:8080/v1".to_string(),
            SecretString::from(""),
            "local-llama".to_string(),
        )
        .expect("construct compat");
        assert_eq!(b.name(), "openai_compat");
    }

    #[test]
    fn trailing_slash_in_endpoint_is_stripped() {
        let a = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1/".to_string(),
            SecretString::from("sk-test"),
            "gpt-4o".to_string(),
        )
        .expect("construct");
        assert_eq!(a.endpoint, "https://api.openai.com/v1");
    }

    // ── Pick #31 (Session 14) — wiremock-backed e2e shape tests ──────
    //
    // Codex feedback #4 asked for live provider/council e2e. The
    // CI-runnable half lives here: wiremock spins up a local HTTP
    // server, the adapter dials it as if it were OpenAI, we assert
    // the request shape + response handling for the four classes
    // (200 OK / 429 rate-limited / 401 auth-fail / 500 server-error)
    // without burning real tokens. The live half (real OpenAI key)
    // is on Alex to run + post results — flagged in PROGRESS.md.

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_adapter_against(server_uri: &str) -> OpenAiAdapter {
        OpenAiAdapter::new_openai(
            server_uri.to_string(),
            SecretString::from("sk-test-mock-key"),
            "gpt-4o-mock".to_string(),
        )
        .expect("adapter constructs against mock URI")
    }

    #[tokio::test]
    async fn mock_200_ok_returns_completion_with_token_counts() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer sk-test-mock-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-mock-1",
                "object": "chat.completion",
                "created": 1_700_000_000_u64,
                "model": "gpt-4o-mock",
                "choices": [{
                    "index": 0,
                    "message": { "role": "assistant", "content": "hello from mock" },
                    "finish_reason": "stop"
                }],
                "usage": { "prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "say hi".into(),
            ..Default::default()
        };
        let completion = adapter.complete(req).await.expect("200 OK must succeed");
        assert_eq!(completion.text, "hello from mock");
        assert_eq!(completion.input_tokens, Some(7));
        assert_eq!(completion.output_tokens, Some(3));
        assert_eq!(completion.model, "gpt-4o-mock");
    }

    #[tokio::test]
    async fn mock_429_rate_limited_returns_quota_error_with_retry_after() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "12")
                    .set_body_raw(
                        r#"{"error":{"message":"rate_limit_exceeded"}}"#,
                        "application/json",
                    ),
            )
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "should rate-limit".into(),
            ..Default::default()
        };
        let err = adapter
            .complete(req)
            .await
            .expect_err("429 must surface as QuotaError");
        // QuotaError carries Retry-After + body. Downcast to inspect.
        let quota = err
            .downcast_ref::<QuotaError>()
            .expect("downcast to QuotaError");
        assert_eq!(quota.provider, "openai_api");
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(12)));
        assert!(quota.body.contains("rate_limit_exceeded"));
    }

    #[tokio::test]
    async fn mock_401_auth_fail_returns_descriptive_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_raw(
                r#"{"error":{"message":"Incorrect API key provided"}}"#,
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
        assert!(msg.contains("401"), "error must name status; got: {msg}");
        assert!(
            msg.contains("openai_api"),
            "error must name provider; got: {msg}"
        );
    }

    #[tokio::test]
    async fn mock_500_transient_returns_status_in_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(500).set_body_raw(
                r#"{"error":{"message":"backend timeout"}}"#,
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
            .expect_err("500 must surface as error");
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("backend timeout"));
    }

    #[tokio::test]
    async fn mock_200_with_no_choices_surfaces_cdx07_silent_fail_guard() {
        // CDX-07 silent-fail-to-empty: a 200 with no choices[] must
        // NOT return Ok(text=""). The provider explicitly errors so
        // the operator sees the content-filter / refusal signal.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-filtered",
                "model": "gpt-4o-mock",
                "choices": [],
                "usage": { "prompt_tokens": 5, "completion_tokens": 0, "total_tokens": 5 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let err = adapter
            .complete(Request {
                prompt: "filtered".into(),
                ..Default::default()
            })
            .await
            .expect_err("empty choices[] must error, not return Ok(\"\")");
        let msg = err.to_string();
        assert!(
            msg.contains("no choices") || msg.contains("content-filter"),
            "error must explain WHY; got: {msg}"
        );
    }

    #[tokio::test]
    async fn mock_200_with_missing_usage_returns_none_token_counts() {
        // Pick #34 (Session 14, test-gap audit-fix): OpenAI-compat
        // endpoints (vLLM, LM Studio, some Ollama versions) routinely
        // omit the `usage` field. Prior tests always supplied `usage`
        // so the `Option<u32>` fall-through path was never pinned —
        // a future refactor changing `input_tokens` to non-optional
        // would silently break those endpoints. This pins the
        // contract: missing usage → `None` token counts, no error.
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "chatcmpl-no-usage",
                "model": "gpt-4o-mock",
                "choices": [{
                    "message": { "role": "assistant", "content": "fine" }
                }]
                // NOTE: no `usage` key — endpoint dropped it
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let completion = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect("missing usage must not cause an error");
        assert_eq!(completion.text, "fine");
        assert_eq!(completion.input_tokens, None);
        assert_eq!(completion.output_tokens, None);
    }

    #[tokio::test]
    async fn mock_request_carries_correct_bearer_and_payload() {
        // The 200-success test already verifies the bearer header
        // matches via `wiremock::matchers::header`. This test
        // additionally asserts the JSON body shape (system + user
        // messages in `messages[]`, model from override, stream=false).
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "gpt-5.5-override",
                "messages": [
                    { "role": "system", "content": "you are NEOTH" },
                    { "role": "user", "content": "ping" }
                ],
                "stream": false,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": { "role": "assistant", "content": "pong" }
                }],
                "usage": { "prompt_tokens": 4, "completion_tokens": 1, "total_tokens": 5 }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "ping".into(),
            system: Some("you are NEOTH".into()),
            model: Some("gpt-5.5-override".into()),
            ..Default::default()
        };
        let completion = adapter
            .complete(req)
            .await
            .expect("body-shape mock must match");
        assert_eq!(completion.text, "pong");
        assert_eq!(completion.model, "gpt-5.5-override");
    }
}
