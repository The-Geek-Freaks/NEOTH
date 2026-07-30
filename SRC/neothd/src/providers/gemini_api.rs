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
use super::termination::{ProviderTermination, RefusalOrigin};
use super::{Completion, Provider, ProviderDispatchPermit, ProviderRequestControls, Request};
use crate::secret::SecretString;

pub struct GeminiAdapter {
    api_key: SecretString,
    default_model: String,
    http: reqwest::Client,
}

impl GeminiAdapter {
    pub fn new(api_key: SecretString, default_model: String) -> Result<Self> {
        let http = crate::providers::http_client::build_client_no_redirect()?;
        Ok(Self {
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
        ProviderRequestControls::SAMPLING
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.default_model)
    }

    fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
        Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
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
                    max_output_tokens: super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING,
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
            let url = format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            );

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
                    let body = response.text().await.unwrap_or_default();
                    let scrubbed = body.replace(self.api_key.expose(), "[REDACTED]");
                    return Err(anyhow::Error::new(QuotaError {
                        provider: "gemini_api",
                        retry_after,
                        body: scrubbed.trim().to_string(),
                    }));
                }
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".into());
                // Strip API key from URL if it leaks into the error string.
                let scrubbed = body.replace(self.api_key.expose(), "[REDACTED]");
                anyhow::bail!(
                    "gemini_api returned HTTP {}: {}",
                    status.as_u16(),
                    scrubbed.trim()
                );
            }

            let parsed: GeminiResponse = response
                .json()
                .await
                .context("parse gemini response JSON")?;

            let latency = started.elapsed();
            completion_from_response(parsed, model, latency)
        })
        .await
    }
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
        input_tokens: parsed
            .usage_metadata
            .as_ref()
            .and_then(|usage| usage.prompt_token_count),
        output_tokens: parsed
            .usage_metadata
            .as_ref()
            .and_then(|usage| usage.candidates_token_count),
        cache_creation_tokens: None,
        cache_read_tokens: None,
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
}
