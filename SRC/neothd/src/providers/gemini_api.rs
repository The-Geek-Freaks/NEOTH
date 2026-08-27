//! Google Gemini REST adapter (`generativelanguage.googleapis.com`).
//!
//! Different wire format from OpenAI: model goes in the URL path, key as a
//! query parameter, messages are `contents` with `parts`. Token usage is
//! reported in `usageMetadata`.
//!
//! Streaming arrives in Phase 5C. Day-5b is non-streaming.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::quota::{QuotaError, parse_retry_after};
use super::response_bounds;
use super::termination::{ProviderTermination, RefusalOrigin};
use super::{
    Completion, CompletionUsageMeasurements, Provider, ProviderDispatchPermit,
    ProviderRequestControls, Request,
};
use crate::secret::SecretString;

/// `generativelanguage.googleapis.com` is an untrusted byte source even on
/// 2xx. These caps bound allocation before any parse; error envelopes keep
/// digest evidence only, which also removes the need to string-scrub a key
/// the endpoint may have echoed in an encoding the scrubber would miss.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_SUCCESS_BODY_BYTES: usize = response_bounds::MAX_SUCCESS_JSON_BODY_BYTES;
const ERROR_BODY_EVIDENCE_DOMAIN: &[u8] = b"gemini-http-error-body/v1";
const SUCCESS_BODY_EVIDENCE_DOMAIN: &[u8] = b"gemini-success-body/v1";

/// Official Gemini REST base. The only public constructor pins it; `build`
/// exists so bounds/wire fixtures can point the same production code path at a
/// local mock, the way `anthropic_api` and `openai_api` already do.
const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";

pub struct GeminiAdapter {
    base_url: String,
    api_key: SecretString,
    default_model: String,
    http: reqwest::Client,
}

impl GeminiAdapter {
    pub fn new(api_key: SecretString, default_model: String) -> Result<Self> {
        Self::build(DEFAULT_BASE_URL.to_string(), api_key, default_model)
    }

    fn build(base_url: String, api_key: SecretString, default_model: String) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let http = crate::providers::http_client::build_client_no_redirect()?;
        Ok(Self {
            base_url,
            api_key,
            default_model,
            http,
        })
    }
}

#[async_trait]
impl Provider for GeminiAdapter {
    fn name(&self) -> &'static str {
        "gemini_api"
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::SAMPLING.with_output_token_limit()
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.default_model)
    }

    fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
        Some(effective_output_token_cap(req))
    }

    async fn complete_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        // GR-04: circuit breaker — same pattern as openai_api.
        crate::providers::circuit_breaker::run_with_breaker("gemini_api", async {
            let started = Instant::now();
            let model = req
                .model
                .clone()
                .unwrap_or_else(|| self.default_model.clone());

            let mut contents = Vec::new();
            contents.push(GeminiContent {
                role: "user".into(),
                parts: vec![GeminiPart {
                    text: req.prompt.clone(),
                }],
            });

            let body = GeminiRequest {
                contents,
                system_instruction: req.system.as_ref().map(|s| GeminiContent {
                    role: "system".into(),
                    parts: vec![GeminiPart { text: s.clone() }],
                }),
                generation_config: GeminiGenerationConfig {
                    max_output_tokens: effective_output_token_cap(&req),
                    temperature: req.temperature,
                    top_p: req.top_p,
                    seed: req.sampling_seed,
                    stop_sequences: (!req.stop_sequences.is_empty())
                        .then(|| req.stop_sequences.clone()),
                },
            };

            // Pick #33 (Session 14, security audit-fix Security#2): Gemini
            // accepts the API key either as `?key=...` URL parameter OR as
            // the `x-goog-api-key` header. The URL form exposes the key to
            // every layer that observes the request URL: reqwest's debug
            // logs (`RUST_LOG=reqwest=debug`), transparent HTTP proxies,
            // SOCKS5 access logs, and any tracing instrumentation that
            // captures the request URI. The header form leaks only on
            // mTLS-terminating proxies (a tighter trust boundary). Switch
            // to the header — the model still goes in the path because
            // Gemini's URL routing keys off it.
            let url = format!("{}/models/{model}:generateContent", self.base_url);

            let response = self
                .http
                .post(&url)
                .header("x-goog-api-key", self.api_key.expose())
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST gemini model={model}"))?;

            let status = response.status();
            if !status.is_success() {
                // 429 → typed QuotaError so the dispatcher can update the
                // quota tracker without re-parsing the response. See
                // openai_api.rs for the symmetric handling.
                if status.as_u16() == 429 {
                    let retry_after = parse_retry_after(response.headers());
                    let evidence = response_bounds::error_body_evidence(
                        response,
                        ERROR_BODY_EVIDENCE_DOMAIN,
                        MAX_ERROR_BODY_BYTES,
                    )
                    .await;
                    return Err(anyhow::Error::new(QuotaError {
                        provider: "gemini_api",
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
                anyhow::bail!("gemini_api returned HTTP {} ({evidence})", status.as_u16());
            }

            let parsed: GeminiResponse = response_bounds::decode_json(
                response,
                "gemini_api",
                SUCCESS_BODY_EVIDENCE_DOMAIN,
                MAX_SUCCESS_BODY_BYTES,
            )
            .await?;

            let latency = started.elapsed();
            completion_from_response(parsed, model, latency)
        })
        .await
    }
}

/// This exact value is bound by authorization and serialized to Gemini's
/// `generationConfig.maxOutputTokens` field. A request may narrow the
/// reviewed default but never widen it; request validation bounds malformed
/// values before the adapter reaches transport.
fn effective_output_token_cap(req: &Request) -> u32 {
    req.max_output_tokens
        .map(|requested| requested.min(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING))
        .unwrap_or(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
}

fn completion_from_response(
    parsed: GeminiResponse,
    model: String,
    latency: Duration,
) -> Result<Completion> {
    let candidate = parsed.candidates.first();
    let finish_reason = candidate.and_then(|value| value.finish_reason.clone());
    let prompt_block_reason = parsed
        .prompt_feedback
        .as_ref()
        .and_then(|feedback| feedback.block_reason.clone());
    let candidate_filter_reason = finish_reason
        .as_deref()
        .filter(|reason| is_candidate_filter_reason(reason))
        .map(str::to_owned);

    let mut termination = if let Some(reason) = prompt_block_reason.as_ref() {
        ProviderTermination::refused(
            finish_reason.clone(),
            RefusalOrigin::PromptFilter,
            reason.clone(),
            parsed
                .prompt_feedback
                .as_ref()
                .and_then(|feedback| feedback.block_reason_message.clone()),
        )
    } else if let Some(reason) = candidate_filter_reason {
        ProviderTermination::refused(
            finish_reason.clone(),
            RefusalOrigin::CandidateFilter,
            reason,
            candidate.and_then(|value| value.finish_message.clone()),
        )
    } else {
        ProviderTermination::finished(finish_reason)
    };

    if let Some(feedback) = parsed.prompt_feedback.as_ref() {
        if !feedback.safety_ratings.is_empty() {
            termination = termination.with_native_detail(
                "prompt_feedback_safety_ratings",
                serde_json::Value::Array(feedback.safety_ratings.clone()),
            );
        }
        if let Some(message) = feedback.block_reason_message.as_ref() {
            termination = termination
                .with_native_detail("prompt_block_reason_message", message.clone().into());
        }
    }
    if let Some(candidate) = candidate {
        if !candidate.safety_ratings.is_empty() {
            termination = termination.with_native_detail(
                "candidate_safety_ratings",
                serde_json::Value::Array(candidate.safety_ratings.clone()),
            );
        }
        if let Some(message) = candidate.finish_message.as_ref() {
            termination = termination.with_native_detail("finish_message", message.clone().into());
        }
    }

    // CDX-07: a malformed ordinary 200 remains an error. A native prompt or
    // candidate filter is a valid provider outcome even when Gemini omits all
    // candidate text.
    let text = candidate
        .and_then(|value| value.content.as_ref())
        .and_then(|content| content.parts.first())
        .map(|part| part.text.clone());
    let text = match text {
        Some(text) => text,
        None if termination.is_refusal() => String::new(),
        None => {
            anyhow::bail!(
                "Gemini returned 200 OK but no candidates[].content.parts[].text and no \
                 native prompt/candidate filter metadata"
            )
        }
    };
    let input_tokens = parsed
        .usage_metadata
        .as_ref()
        .and_then(|usage| usage.prompt_token_count);
    let output_tokens = parsed
        .usage_metadata
        .as_ref()
        .and_then(|usage| usage.candidates_token_count);
    let usage_measurements = match (input_tokens, output_tokens) {
        (None, None) => None,
        (input_tokens, output_tokens) => Some(CompletionUsageMeasurements::provider_reported(
            input_tokens,
            output_tokens,
            None,
            None,
            None,
            None,
        )?),
    };

    debug!(
        model = %model,
        response_bytes = text.len(),
        latency_ms = latency.as_millis(),
        "gemini completion"
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
        usage_measurements,
    })
}

fn is_candidate_filter_reason(reason: &str) -> bool {
    matches!(
        reason,
        "SAFETY"
            | "RECITATION"
            | "BLOCKLIST"
            | "PROHIBITED_CONTENT"
            | "SPII"
            | "IMAGE_SAFETY"
            | "MODEL_ARMOR"
            | "IMAGE_PROHIBITED_CONTENT"
            | "IMAGE_RECITATION"
            | "ESCALATION"
    )
}

// ── Wire types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(rename = "systemInstruction", skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GeminiContent>,
    #[serde(rename = "generationConfig")]
    generation_config: GeminiGenerationConfig,
}

#[derive(Serialize)]
struct GeminiGenerationConfig {
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(rename = "topP", skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(rename = "stopSequences", skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Serialize, Deserialize)]
struct GeminiPart {
    text: String,
}

#[derive(Deserialize)]
struct GeminiResponse {
    #[serde(default)]
    candidates: Vec<GeminiCandidate>,
    #[serde(rename = "promptFeedback", default)]
    prompt_feedback: Option<GeminiPromptFeedback>,
    #[serde(rename = "usageMetadata", default)]
    usage_metadata: Option<GeminiUsage>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    #[serde(default)]
    content: Option<GeminiContent>,
    #[serde(rename = "finishReason", default)]
    finish_reason: Option<String>,
    #[serde(rename = "safetyRatings", default)]
    safety_ratings: Vec<serde_json::Value>,
    #[serde(rename = "finishMessage", default)]
    finish_message: Option<String>,
}

#[derive(Deserialize)]
struct GeminiPromptFeedback {
    #[serde(rename = "blockReason", default)]
    block_reason: Option<String>,
    #[serde(rename = "blockReasonMessage", default)]
    block_reason_message: Option<String>,
    #[serde(rename = "safetyRatings", default)]
    safety_ratings: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct GeminiUsage {
    #[serde(rename = "promptTokenCount", default)]
    prompt_token_count: Option<u32>,
    #[serde(rename = "candidatesTokenCount", default)]
    candidates_token_count: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_filter_reasons_are_distinct_from_structural_failures() {
        for reason in [
            "SAFETY",
            "RECITATION",
            "BLOCKLIST",
            "PROHIBITED_CONTENT",
            "SPII",
            "IMAGE_SAFETY",
            "MODEL_ARMOR",
            "IMAGE_PROHIBITED_CONTENT",
            "IMAGE_RECITATION",
            "ESCALATION",
        ] {
            assert!(is_candidate_filter_reason(reason), "{reason}");
        }
        for reason in [
            "MALFORMED_FUNCTION_CALL",
            "UNEXPECTED_TOOL_CALL",
            "NO_IMAGE",
            "MAX_TOKENS",
            "STOP",
            "OTHER",
        ] {
            assert!(!is_candidate_filter_reason(reason), "{reason}");
        }
    }
    use crate::providers::Provider;

    #[test]
    fn adapter_constructs() {
        let a = GeminiAdapter::new(
            SecretString::from("AIza-test"),
            "gemini-2.5-pro".to_string(),
        )
        .expect("construct");
        assert_eq!(a.name(), "gemini_api");
    }

    #[test]
    fn request_serializes_bounded_generation_config() {
        let body = GeminiRequest {
            contents: vec![GeminiContent {
                role: "user".into(),
                parts: vec![GeminiPart {
                    text: "ping".into(),
                }],
            }],
            system_instruction: None,
            generation_config: GeminiGenerationConfig {
                max_output_tokens: crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING,
                temperature: None,
                top_p: None,
                seed: None,
                stop_sequences: None,
            },
        };
        let json = serde_json::to_value(body).unwrap();
        assert_eq!(json["generationConfig"]["maxOutputTokens"], 4096);
        for field in ["temperature", "topP", "seed", "stopSequences"] {
            assert!(json["generationConfig"].get(field).is_none());
        }
    }

    #[test]
    fn requested_output_cap_is_authorized_and_serialized_verbatim() {
        let req = Request {
            max_output_tokens: Some(88),
            ..Request::default()
        };
        let adapter = GeminiAdapter::new(SecretString::from("AIza-test"), "gemini-test".into())
            .expect("adapter constructs");
        assert!(adapter.request_controls().supports_max_output_tokens());
        assert_eq!(adapter.output_token_ceiling(&req), Some(88));

        let json = serde_json::to_value(GeminiGenerationConfig {
            max_output_tokens: effective_output_token_cap(&req),
            temperature: None,
            top_p: None,
            seed: None,
            stop_sequences: None,
        })
        .expect("generation config serializes");
        assert_eq!(json["maxOutputTokens"], 88);
    }

    #[test]
    fn requested_output_cap_cannot_widen_the_reviewed_gemini_ceiling() {
        let req = Request {
            max_output_tokens: Some(crate::providers::MAX_REQUEST_OUTPUT_TOKENS),
            ..Request::default()
        };
        let adapter = GeminiAdapter::new(SecretString::from("AIza-test"), "gemini-test".into())
            .expect("adapter constructs");
        assert_eq!(
            adapter.output_token_ceiling(&req),
            Some(crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
        );
        let json = serde_json::to_value(GeminiGenerationConfig {
            max_output_tokens: effective_output_token_cap(&req),
            temperature: None,
            top_p: None,
            seed: None,
            stop_sequences: None,
        })
        .expect("generation config serializes");
        assert_eq!(
            json["maxOutputTokens"],
            crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING
        );
    }

    #[test]
    fn request_serializes_sampling_controls() {
        let config = GeminiGenerationConfig {
            max_output_tokens: 4096,
            temperature: Some(0.6),
            top_p: Some(0.75),
            seed: Some(17),
            stop_sequences: Some(vec!["END".into()]),
        };
        let json = serde_json::to_value(config).unwrap();
        assert_eq!(json["temperature"].as_f64(), Some(f64::from(0.6_f32)));
        assert_eq!(json["topP"].as_f64(), Some(f64::from(0.75_f32)));
        assert_eq!(json["seed"], 17);
        assert_eq!(json["stopSequences"], serde_json::json!(["END"]));
    }

    #[test]
    fn normal_fixture_retains_finish_reason_and_usage() {
        let parsed: GeminiResponse = serde_json::from_value(serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{ "text": "hello from gemini" }]
                },
                "finishReason": "STOP",
                "safetyRatings": [{
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "probability": "NEGLIGIBLE"
                }]
            }],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": 3
            }
        }))
        .expect("normal fixture");

        let completion = completion_from_response(parsed, "gemini-fixture".into(), Duration::ZERO)
            .expect("normal completion");
        assert_eq!(completion.text, "hello from gemini");
        assert_eq!(
            completion.termination.finish_reason.as_deref(),
            Some("STOP")
        );
        assert!(!completion.termination.is_refusal());
        assert_eq!(completion.input_tokens, Some(5));
        assert_eq!(completion.output_tokens, Some(3));
        assert!(
            completion
                .termination
                .native_details
                .contains_key("candidate_safety_ratings")
        );
    }

    #[test]
    fn prompt_feedback_block_with_partial_usage_metadata_is_retained() {
        let parsed: GeminiResponse = serde_json::from_value(serde_json::json!({
            "promptFeedback": {
                "blockReason": "SAFETY",
                "blockReasonMessage": "Prompt was blocked by safety policy.",
                "safetyRatings": [{
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "probability": "HIGH",
                    "blocked": true
                }]
            },
            "usageMetadata": {
                "promptTokenCount": 5,
                "totalTokenCount": 5
            }
        }))
        .expect("prompt block fixture");

        let completion = completion_from_response(parsed, "gemini-fixture".into(), Duration::ZERO)
            .expect("prompt block is a typed provider outcome");
        assert!(completion.text.is_empty());
        let refusal = completion
            .termination
            .refusal
            .expect("promptFeedback.blockReason must be retained");
        assert_eq!(refusal.origin, RefusalOrigin::PromptFilter);
        assert_eq!(refusal.reason, "SAFETY");
        assert_eq!(
            refusal.message.as_deref(),
            Some("Prompt was blocked by safety policy.")
        );
        assert_eq!(completion.input_tokens, Some(5));
        assert_eq!(
            completion.output_tokens, None,
            "an omitted candidatesTokenCount must remain unknown"
        );
        assert!(
            completion
                .termination
                .native_details
                .contains_key("prompt_feedback_safety_ratings")
        );
    }

    #[test]
    fn candidate_filter_without_content_retains_ratings_and_message() {
        let parsed: GeminiResponse = serde_json::from_value(serde_json::json!({
            "candidates": [{
                "finishReason": "PROHIBITED_CONTENT",
                "finishMessage": "Candidate was blocked.",
                "safetyRatings": [{
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "probability": "MEDIUM",
                    "blocked": true
                }]
            }]
        }))
        .expect("candidate block fixture");

        let completion = completion_from_response(parsed, "gemini-fixture".into(), Duration::ZERO)
            .expect("candidate filter is a typed provider outcome");
        assert!(completion.text.is_empty());
        assert_eq!(
            completion.termination.finish_reason.as_deref(),
            Some("PROHIBITED_CONTENT")
        );
        let refusal = completion
            .termination
            .refusal
            .expect("candidate finishReason must be retained");
        assert_eq!(refusal.origin, RefusalOrigin::CandidateFilter);
        assert_eq!(refusal.reason, "PROHIBITED_CONTENT");
        assert_eq!(refusal.message.as_deref(), Some("Candidate was blocked."));
        assert_eq!(
            completion.termination.native_details.get("finish_message"),
            Some(&serde_json::json!("Candidate was blocked."))
        );
        assert!(
            completion
                .termination
                .native_details
                .contains_key("candidate_safety_ratings")
        );
    }

    // ── Response envelope bounds (GOLD-R4-15k1) ──────────────────────────────

    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_adapter_against(base_url: &str) -> GeminiAdapter {
        // Bounds fixtures deliberately fail provider calls and the breaker
        // registry is process-global per adapter identity, so without this
        // reset the fifth deliberate failure would open the breaker and later
        // tests would observe that instead of their own fixture.
        crate::providers::circuit_breaker::reset_for_test("gemini_api");
        GeminiAdapter::build(
            base_url.to_string(),
            SecretString::from("gemini-mock-key"),
            "gemini-mock".to_string(),
        )
        .expect("adapter constructs against mock URL")
    }

    async fn mount_generate(mock: &MockServer, status: u16, body: impl Into<Vec<u8>>) {
        Mock::given(method("POST"))
            .and(path_regex(r"^/models/.*:generateContent$"))
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
    async fn mock_200_completes_through_the_bounded_reader() {
        let mock = MockServer::start().await;
        mount_generate(
            &mock,
            200,
            serde_json::json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "hello from gemini"}]},
                    "finishReason": "STOP"
                }],
                "usageMetadata": {"promptTokenCount": 6, "candidatesTokenCount": 2}
            })
            .to_string(),
        )
        .await;

        let completion = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "say hi".into(),
                ..Default::default()
            })
            .await
            .expect("200 must succeed");
        assert_eq!(completion.text, "hello from gemini");
        assert_eq!(completion.input_tokens, Some(6));
        assert_eq!(completion.output_tokens, Some(2));
        assert_eq!(
            completion.termination.finish_reason.as_deref(),
            Some("STOP")
        );
    }

    #[tokio::test]
    async fn oversized_success_body_fails_before_json_allocation() {
        let secret = "gemini-never-persist-oversized-success";
        let body = format!(
            r#"{{"candidates":[{{"content":{{"parts":[{{"text":"{secret}{}"}}]}}}}]}}"#,
            "x".repeat(MAX_SUCCESS_BODY_BYTES)
        );
        let mock = MockServer::start().await;
        mount_generate(&mock, 200, body).await;

        let message = complete_error_against(&mock).await;
        assert!(message.contains("successful response body exceeded"));
        assert!(message.contains("body_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn malformed_success_body_reports_only_digest_evidence() {
        let secret = "gemini-never-persist-malformed-success";
        let mock = MockServer::start().await;
        mount_generate(&mock, 200, format!(r#"{{"candidates":"{secret}""#)).await;

        let message = complete_error_against(&mock).await;
        assert!(message.contains("malformed successful JSON response"));
        assert!(message.contains("body_sha256="));
        assert!(!message.contains(secret));
    }

    #[tokio::test]
    async fn oversized_http_error_body_reports_status_and_digest_only() {
        let secret = "gemini-never-persist-http-error";
        let mock = MockServer::start().await;
        mount_generate(
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

    /// The endpoint may echo the API key into its own error envelope. The
    /// digest keeps that out of the retained quota evidence without relying on
    /// a substring scrub that any encoding would defeat.
    #[tokio::test]
    async fn quota_body_keeps_typed_retry_after_without_raw_bytes_or_key() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/models/.*:generateContent$"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "11")
                    .set_body_raw(
                        r#"{"error":{"message":"quota exceeded for gemini-mock-key"}}"#,
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
        assert_eq!(quota.provider, "gemini_api");
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(11)));
        assert!(quota.body.starts_with("body_sha256="));
        assert!(quota.body.ends_with(" truncated=false"));
        assert!(!quota.body.contains("gemini-mock-key"));
        assert!(!quota.body.contains("quota exceeded"));
    }

    #[tokio::test]
    async fn public_constructor_pins_the_official_endpoint() {
        let adapter = GeminiAdapter::new(
            SecretString::from("gemini-mock-key"),
            "gemini-mock".to_string(),
        )
        .expect("official constructor");
        assert_eq!(
            adapter.base_url,
            "https://generativelanguage.googleapis.com/v1beta"
        );
    }
}
