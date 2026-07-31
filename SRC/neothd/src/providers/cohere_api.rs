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
use super::response_bounds;
use super::termination::ProviderTermination;
use super::{Completion, Provider, ProviderDispatchPermit, ProviderRequestControls, Request};
use crate::secret::SecretString;

/// The Cohere endpoint is an untrusted byte source even on 2xx. These caps
/// bound allocation before any parse; error envelopes keep digest evidence
/// only, which also removes the substring key-scrub the endpoint could defeat
/// with any other encoding.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_SUCCESS_BODY_BYTES: usize = response_bounds::MAX_SUCCESS_JSON_BODY_BYTES;
const ERROR_BODY_EVIDENCE_DOMAIN: &[u8] = b"cohere-http-error-body/v1";
const SUCCESS_BODY_EVIDENCE_DOMAIN: &[u8] = b"cohere-success-body/v1";

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
                    let evidence = response_bounds::error_body_evidence(
                        response,
                        ERROR_BODY_EVIDENCE_DOMAIN,
                        MAX_ERROR_BODY_BYTES,
                    )
                    .await;
                    return Err(anyhow::Error::new(QuotaError {
                        provider: "cohere_api",
                        retry_after,
                        body: evidence,
                    }));
                }
                let evidence = response_bounds::error_body_evidence(
                    response,
                    ERROR_BODY_EVIDENCE_DOMAIN,
                    MAX_ERROR_BODY_BYTES,
                )
                .await;
                anyhow::bail!("cohere_api returned HTTP {} ({evidence})", status.as_u16());
            }

            let parsed: CohereResponse = response_bounds::decode_json(
                response,
                "cohere_api",
                SUCCESS_BODY_EVIDENCE_DOMAIN,
                MAX_SUCCESS_BODY_BYTES,
            )
            .await?;
            let termination = cohere_termination(parsed.finish_reason.clone())?;

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
                termination,
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

fn cohere_termination(finish_reason: Option<String>) -> Result<ProviderTermination> {
    if let Some(reason) = finish_reason.as_deref()
        && matches!(reason.to_ascii_uppercase().as_str(), "ERROR" | "TIMEOUT")
    {
        anyhow::bail!("cohere_api returned 200 OK with non-success finish_reason `{reason}`");
    }
    Ok(ProviderTermination::finished(finish_reason))
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
        // Bounds fixtures deliberately fail provider calls and the breaker
        // registry is process-global per adapter identity.
        crate::providers::circuit_breaker::reset_for_test("cohere_api");
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
        assert_eq!(
            completion.termination.finish_reason.as_deref(),
            Some("COMPLETE")
        );
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

    #[test]
    fn finish_reason_table_preserves_success_and_rejects_terminal_errors() {
        for reason in ["COMPLETE", "MAX_TOKENS", "STOP_SEQUENCE", "TOOL_CALL"] {
            let termination =
                cohere_termination(Some(reason.into())).expect("successful finish reason");
            assert_eq!(termination.finish_reason.as_deref(), Some(reason));
            assert!(!termination.is_refusal());
        }
        for reason in ["ERROR", "TIMEOUT", "error", "timeout"] {
            let error = cohere_termination(Some(reason.into())).expect_err("must be non-success");
            assert!(error.to_string().contains(reason));
        }
    }

    #[tokio::test]
    async fn mock_200_error_finish_reason_is_not_returned_as_completion() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "finish_reason": "ERROR",
                "message": {
                    "content": [{"type": "text", "text": "partial transport failure"}]
                }
            })))
            .mount(&mock)
            .await;
        let adapter = build_adapter_against(&mock.uri());
        let error = adapter
            .complete(Request {
                prompt: "x".into(),
                ..Default::default()
            })
            .await
            .expect_err("ERROR finish reason must fail");
        assert!(error.to_string().contains("finish_reason `ERROR`"));
    }

    // ── Response envelope bounds (GOLD-R4-15k1) ──────────────────────────────

    async fn mount_chat(mock: &MockServer, status: u16, body: impl Into<Vec<u8>>) {
        Mock::given(method("POST"))
            .and(path("/chat"))
            .respond_with(
                ResponseTemplate::new(status).set_body_raw(body.into(), "application/json"),
            )
            .mount(mock)
            .await;
    }

    async fn complete_error_against(mock: &MockServer) -> String {
        build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect_err("bounded fixture must fail")
            .to_string()
    }

    #[tokio::test]
    async fn oversized_success_body_fails_before_json_allocation() {
        let secret = "cohere-never-persist-oversized-success";
        let body = format!(
            r#"{{"message":{{"content":[{{"type":"text","text":"{secret}{}"}}]}}}}"#,
            "x".repeat(MAX_SUCCESS_BODY_BYTES)
        );
        let mock = MockServer::start().await;
        mount_chat(&mock, 200, body).await;

        let message = complete_error_against(&mock).await;
        assert!(message.contains("successful response body exceeded"));
        assert!(message.contains("body_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn malformed_success_body_reports_only_digest_evidence() {
        let secret = "cohere-never-persist-malformed-success";
        let mock = MockServer::start().await;
        mount_chat(&mock, 200, format!(r#"{{"message":"{secret}""#)).await;

        let message = complete_error_against(&mock).await;
        assert!(message.contains("malformed successful JSON response"));
        assert!(message.contains("body_sha256="));
        assert!(!message.contains(secret));
    }

    #[tokio::test]
    async fn oversized_http_error_body_reports_status_and_digest_only() {
        let secret = "cohere-never-persist-http-error";
        let mock = MockServer::start().await;
        mount_chat(
            &mock,
            500,
            format!("{secret}{}", "x".repeat(MAX_ERROR_BODY_BYTES * 2)),
        )
        .await;

        let message = complete_error_against(&mock).await;
        assert!(message.contains("HTTP 500"), "got: {message}");
        assert!(message.contains("body_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn quota_body_retains_digest_evidence_only() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "5")
                    .set_body_raw(
                        r#"{"message":"co-mock-key over quota"}"#,
                        "application/json",
                    ),
            )
            .mount(&mock)
            .await;

        let error = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect_err("429 must surface as QuotaError");
        let quota = error
            .downcast_ref::<QuotaError>()
            .expect("429 remains a typed QuotaError");
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(5)));
        assert!(quota.body.starts_with("body_sha256="));
        assert!(!quota.body.contains("co-mock-key"));
        assert!(!quota.body.contains("over quota"));
    }
}
