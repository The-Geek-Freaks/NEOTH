//! Google Gemini REST adapter (`generativelanguage.googleapis.com`).
//!
//! Different wire format from OpenAI: model goes in the URL path, key as a
//! query parameter, messages are `contents` with `parts`. Token usage is
//! reported in `usageMetadata`.
//!
//! Streaming arrives in Phase 5C. Day-5b is non-streaming.

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::quota::{QuotaError, parse_retry_after};
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

            let text = parsed
                // CDX-07 silent-fail-to-empty fix: a Gemini 200 response
                // with no candidates / no parts is a safety-block / quota
                // edge case operators want to see surfaced, not silently
                // collapsed to "". Force an error so the chat dispatch
                // logs the failure cause instead of emitting a blank reply.
                .candidates
                .into_iter()
                .next()
                .and_then(|c| c.content.parts.into_iter().next())
                .map(|p| p.text)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Gemini returned 200 OK but no candidates[].content.parts[].text — \
                     likely a safety filter block or quota exhaustion envelope. \
                     Inspect the raw HTTP body via NEOTH_LOG_LEVEL=debug."
                    )
                })?;

            let latency = started.elapsed();
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
                latency,
                input_tokens: parsed.usage_metadata.as_ref().map(|u| u.prompt_token_count),
                output_tokens: parsed
                    .usage_metadata
                    .as_ref()
                    .map(|u| u.candidates_token_count),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        })
        .await
    }
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
    candidates: Vec<GeminiCandidate>,
    #[serde(rename = "usageMetadata", default)]
    usage_metadata: Option<GeminiUsage>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    content: GeminiContent,
}

#[derive(Deserialize)]
struct GeminiUsage {
    #[serde(rename = "promptTokenCount")]
    prompt_token_count: u32,
    #[serde(rename = "candidatesTokenCount")]
    candidates_token_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(json["temperature"], 0.6);
        assert_eq!(json["topP"], 0.75);
        assert_eq!(json["seed"], 17);
        assert_eq!(json["stopSequences"], serde_json::json!(["END"]));
    }
}
