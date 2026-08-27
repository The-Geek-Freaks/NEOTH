//! Azure OpenAI Service adapter (C-4 Phase 2, Session 14).
//!
//! Talks to Azure's classic deployment-based endpoint:
//!
//! ```text
//! POST https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<ver>
//! Content-Type: application/json
//! api-key: <api_key>       ← NOT `Authorization: Bearer`
//! ```
//!
//! Differs from upstream OpenAI in three ways the adapter has to
//! handle:
//!
//!   1. **Header scheme** — `api-key` instead of `Authorization: Bearer`.
//!   2. **Deployment name** — the operator creates named deployments
//!      inside their Azure resource (e.g. `gpt-5-prod`) which proxy
//!      to a specific underlying model. `provider_model` in NEOTH
//!      config encodes the deployment name; the actual chat model
//!      lives behind it on Azure's side.
//!   3. **API version query** — every classic endpoint call requires
//!      `?api-version=<YYYY-MM-DD[-preview]>`. Defaults to the latest
//!      GA release.
//!
//! Reference:
//! <https://learn.microsoft.com/en-us/azure/foundry/openai/reference>
//!
//! Request + response body shapes match OpenAI's chat-completions API,
//! so the wire types are intentionally identical to those in
//! `providers::openai_api`. Streaming is out of scope for Phase 2 —
//! falls through to the Provider trait's default impl.

use std::time::Instant;

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

/// An Azure OpenAI resource is an untrusted byte source even on 2xx. These
/// caps bound allocation before any parse. The error body is still classified
/// (policy envelope, typed failure) but never printed: only the classification
/// and digest evidence reach an operator.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_SUCCESS_BODY_BYTES: usize = response_bounds::MAX_SUCCESS_JSON_BODY_BYTES;
const ERROR_BODY_EVIDENCE_DOMAIN: &[u8] = b"azure-openai-http-error-body/v1";
const SUCCESS_BODY_EVIDENCE_DOMAIN: &[u8] = b"azure-openai-success-body/v1";

/// Latest GA api-version as of 2026-05-18. Operators wanting newer
/// (`2025-04-01-preview`) override via `freedom.yaml::provider_api_version`
/// or per-slot `inference.<role>.api_version`.
pub const DEFAULT_API_VERSION: &str = "2024-10-21";

/// Adapter for Azure OpenAI Service (classic deployment endpoint).
pub struct AzureOpenAiAdapter {
    /// Resource base URL: `https://<name>.openai.azure.com`. Adapter
    /// trims trailing slashes + a trailing `/openai/...` path on
    /// construction so operator paste-errors don't deform the
    /// canonical URL.
    endpoint: String,
    /// `api-key` header value.
    api_key: SecretString,
    /// Deployment name configured by the operator inside their Azure
    /// resource. Doubles as the `model` field on the request body —
    /// Azure routes by deployment, not by underlying model name.
    deployment_name: String,
    /// `?api-version=<ver>` query parameter.
    api_version: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for AzureOpenAiAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureOpenAiAdapter")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"[REDACTED]")
            .field("deployment_name", &self.deployment_name)
            .field("api_version", &self.api_version)
            .finish_non_exhaustive()
    }
}

impl AzureOpenAiAdapter {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: SecretString,
        deployment_name: impl Into<String>,
        api_version: Option<String>,
    ) -> Result<Self> {
        let endpoint = normalise_endpoint(endpoint.into());
        if endpoint.is_empty() {
            anyhow::bail!(
                "azure_openai: empty endpoint — set `provider_endpoint: https://<resource>.openai.azure.com` \
                 in freedom.yaml before selecting the azure_openai provider"
            );
        }
        let deployment_name = deployment_name.into();
        validate_deployment_name(&deployment_name)?;
        let api_version = api_version
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_API_VERSION.to_string());
        let http = super::http_client::build_client_no_redirect()?;
        Ok(Self {
            endpoint,
            api_key,
            deployment_name,
            api_version,
            http,
        })
    }

    fn url(&self, deployment: &str) -> String {
        format!(
            "{}/openai/deployments/{deployment}/chat/completions?api-version={ver}",
            self.endpoint,
            ver = self.api_version,
        )
    }
}

/// Validate an Azure deployment name. Azure routes by a deployment name
/// embedded directly in the URL path
/// (`/openai/deployments/<name>/chat/completions`), so restrict it to a
/// conservative `[A-Za-z0-9._-]+` (COR-15 / A-37): a name carrying `/`,
/// `?`, `#`, or `..` could otherwise inject extra path segments, a query
/// string, or path traversal into the request URL. Real Azure deployment
/// names are alphanumeric with dashes, so this rejects nothing legitimate.
fn validate_deployment_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!(
            "azure_openai: empty deployment name — set `provider_model: <your-deployment-name>` \
             in freedom.yaml. Deployments are created in the Azure portal under \
             your OpenAI resource → Deployments."
        );
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        anyhow::bail!(
            "azure_openai: deployment name `{name}` contains characters outside [A-Za-z0-9._-]. \
             A name with '/', '?', '#', or '..' could rewrite the request URL path; use the exact \
             deployment name shown in the Azure portal (OpenAI resource → Deployments)."
        );
    }
    // `..` is the one traversal sequence still expressible within the
    // charset above (both bytes are '.'); a `..` segment in the URL path
    // normalises UP a level. Reject it explicitly.
    if name.contains("..") {
        anyhow::bail!(
            "azure_openai: deployment name `{name}` contains `..` (path traversal). Use the exact \
             deployment name shown in the Azure portal (OpenAI resource → Deployments)."
        );
    }
    Ok(())
}

#[async_trait]
impl Provider for AzureOpenAiAdapter {
    fn name(&self) -> &'static str {
        "azure_openai"
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::SAMPLING.with_output_token_limit()
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.deployment_name)
    }

    fn consent_route(&self) -> Option<crate::consent::ConsentRoute> {
        Some(crate::consent::ConsentRoute::new(
            crate::cli::init::ProviderKind::AzureOpenAi,
            Some(&self.endpoint),
        ))
    }

    fn output_token_ceiling(&self, req: &Request) -> Option<u32> {
        Some(effective_output_token_limit(req))
    }

    async fn complete_raw(
        &self,
        req: Request,
        _permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
        // GR-04: circuit breaker — same pattern as openai_api.
        crate::providers::circuit_breaker::run_with_breaker("azure_openai", async {
            let started = Instant::now();
            // Azure's `model` field on the request body is overloaded with
            // the deployment name; per-request override lets advanced
            // operators target a different deployment from the same chat
            // call (rare but supported by Azure).
            let deployment = req
                .model
                .clone()
                .unwrap_or_else(|| self.deployment_name.clone());
            // COR-15: the per-request override (req.model) bypasses the
            // constructor's check and lands directly in the URL path —
            // re-validate so a crafted model name can't inject path
            // segments / query / traversal into the Azure endpoint URL.
            validate_deployment_name(&deployment)?;

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
                // Azure's docs mark `model` as optional when the deployment
                // already encodes it; include it anyway for the v1-compat
                // path where Azure expects the underlying model name.
                model: deployment.clone(),
                messages,
                stream: false,
                max_completion_tokens: effective_output_token_limit(&req),
                temperature: req.temperature,
                top_p: req.top_p,
                seed: req.sampling_seed,
                stop: (!req.stop_sequences.is_empty()).then(|| req.stop_sequences.clone()),
            };

            let url = self.url(&deployment);
            let response = self
                .http
                .post(&url)
                .header("content-type", "application/json")
                .header("api-key", self.api_key.expose())
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
                        provider: "azure_openai",
                        retry_after,
                        body: evidence,
                    }));
                }
                // The body is read under a cap and kept only to classify the
                // envelope (policy refusal, typed Azure failure). What reaches
                // an operator is the classification plus digest evidence.
                let bounded = response_bounds::error_body_with_evidence(
                    response,
                    ERROR_BODY_EVIDENCE_DOMAIN,
                    MAX_ERROR_BODY_BYTES,
                )
                .await;
                // A recognised policy envelope becomes visible refusal text, so
                // this one classified string still gets the key scrub the
                // OpenAI-compatible leaf applies. The scrub is not the bound —
                // the cap and the digest are — it only keeps our own key out of
                // text an endpoint can make visible.
                let body_text = bounded
                    .classification_text
                    .replace(self.api_key.expose(), "[REDACTED]");
                if let Some((reason, message)) = parse_azure_policy_error(&body_text) {
                    return Ok(Completion {
                        text: message.clone().unwrap_or_default(),
                        identity: Default::default(),
                        model: deployment,
                        termination: ProviderTermination::refused(
                            None,
                            RefusalOrigin::PromptFilter,
                            reason,
                            message,
                        ),
                        latency: started.elapsed(),
                        input_tokens: None,
                        output_tokens: None,
                        cache_creation_tokens: None,
                        cache_read_tokens: None,
                        usage_measurements: None,
                    });
                }
                return Err(map_azure_error(
                    status,
                    &body_text,
                    &deployment,
                    &bounded.evidence,
                ));
            }

            let parsed: ChatResponse = response_bounds::decode_json(
                response,
                "azure_openai",
                SUCCESS_BODY_EVIDENCE_DOMAIN,
                MAX_SUCCESS_BODY_BYTES,
            )
            .await?;

            let choice = parsed.choices.into_iter().next().ok_or_else(|| {
                anyhow::anyhow!(
                    "azure_openai returned 200 OK but the response has no choices[] — \
                     likely an upstream error envelope. Inspect NEOTH_LOG_LEVEL=debug."
                )
            })?;
            let (text, termination) = parse_azure_choice(choice)?;

            let latency = started.elapsed();
            debug!(
                adapter = "azure_openai",
                deployment = %deployment,
                api_version = %self.api_version,
                response_bytes = text.len(),
                latency_ms = latency.as_millis(),
                "azure openai completion"
            );

            Ok(Completion {
                text,
                identity: Default::default(),
                model: deployment,
                termination,
                latency,
                input_tokens: parsed.usage.as_ref().map(|u| u.prompt_tokens),
                output_tokens: parsed.usage.as_ref().map(|u| u.completion_tokens),
                cache_creation_tokens: None,
                cache_read_tokens: None,
                usage_measurements: parsed
                    .usage
                    .as_ref()
                    .map(|usage| {
                        CompletionUsageMeasurements::provider_reported(
                            Some(usage.prompt_tokens),
                            Some(usage.completion_tokens),
                            None,
                            None,
                            None,
                            None,
                        )
                    })
                    .transpose()?,
            })
        })
        .await
    }
}

fn parse_azure_choice(choice: ChatChoice) -> Result<(String, ProviderTermination)> {
    let ChatChoice {
        message,
        finish_reason,
    } = choice;
    let ChatChoiceMessage { content, refusal } = message;
    let refusal_present = refusal.is_some();
    let refusal_message = refusal.filter(|value| !value.trim().is_empty());
    let content_filtered = finish_reason.as_deref() == Some("content_filter");
    let termination = if refusal_present {
        ProviderTermination::refused(
            finish_reason.clone(),
            RefusalOrigin::ProviderMessage,
            "message.refusal",
            refusal_message.clone(),
        )
    } else if content_filtered {
        ProviderTermination::refused(
            finish_reason.clone(),
            RefusalOrigin::FinishReason,
            "content_filter",
            None,
        )
    } else {
        ProviderTermination::finished(finish_reason)
    };
    let text = content
        .or_else(|| refusal_message.clone())
        .or_else(|| termination.is_refusal().then(String::new))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "azure_openai returned 200 OK but choices[0].message.content is null \
                 without a native refusal or content_filter finish reason"
            )
        })?;
    Ok((text, termination))
}

fn parse_azure_policy_error(body: &str) -> Option<(String, Option<String>)> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let envelope = parsed.get("error").unwrap_or(&parsed);
    let reason = [
        envelope.get("code"),
        envelope.pointer("/innererror/code"),
        envelope.pointer("/inner_error/code"),
        parsed.get("code"),
    ]
    .into_iter()
    .flatten()
    .filter_map(serde_json::Value::as_str)
    .find(|value| {
        matches!(
            value
                .trim()
                .to_ascii_lowercase()
                .replace(['_', '-'], "")
                .as_str(),
            "contentfilter"
                | "contentpolicyviolation"
                | "responsibleaipolicyviolation"
                | "safetyviolation"
        )
    })?
    .trim()
    .to_string();
    let message = envelope
        .get("message")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Some((reason, message))
}

/// Strip trailing slashes + an accidental path suffix from the
/// operator-supplied endpoint. Accepts:
///   - `https://foo.openai.azure.com`
///   - `https://foo.openai.azure.com/`
///   - `https://foo.openai.azure.com/openai`
///   - `https://foo.openai.azure.com/openai/`
///   - `https://foo.openai.azure.com/openai/deployments/...` (rarely
///     pasted but normalise just in case)
///
/// and produces the canonical `https://foo.openai.azure.com` form.
fn normalise_endpoint(raw: String) -> String {
    let mut ep = raw.trim().trim_end_matches('/').to_string();
    // Strip any trailing /openai[/...] path segment so the URL builder
    // can re-append cleanly.
    if let Some(idx) = ep.find("/openai") {
        ep.truncate(idx);
    }
    ep.trim_end_matches('/').to_string()
}

/// Map non-success Azure responses to actionable error messages.
/// Classifies a bounded error body into operator guidance.
///
/// `body` is read under a cap and used only for classification; `evidence` is
/// the digest that ships instead of the bytes. An Azure error envelope is
/// gateway-authored and has echoed request material, so the raw body never
/// reaches the message.
fn map_azure_error(
    status: reqwest::StatusCode,
    body: &str,
    deployment: &str,
    evidence: &str,
) -> anyhow::Error {
    let lower = body.trim().to_ascii_lowercase();
    let code = status.as_u16();
    if code == 401 || lower.contains("unauthorized") || lower.contains("invalid api key") {
        anyhow::anyhow!(
            "azure_openai HTTP {code}: api-key rejected. Confirm the key matches the resource \
             at the configured endpoint, and that the key hasn't been rotated. ({evidence})"
        )
    } else if code == 404 && lower.contains("deployment") {
        anyhow::anyhow!(
            "azure_openai HTTP 404: deployment `{deployment}` not found at the configured endpoint. \
             Check the deployment name against the Azure portal → OpenAI resource → Deployments. \
             ({evidence})"
        )
    } else if code == 400 && (lower.contains("api-version") || lower.contains("apiversion")) {
        anyhow::anyhow!(
            "azure_openai HTTP 400: api-version rejected. Set `provider_api_version` in freedom.yaml \
             (current default: 2024-10-21; preview: 2025-04-01-preview). ({evidence})"
        )
    } else if code == 400 && lower.contains("content_filter") {
        anyhow::anyhow!(
            "azure_openai HTTP 400: content filter triggered. Azure applies its own content \
             policy on top of the underlying model. ({evidence})"
        )
    } else {
        anyhow::anyhow!("azure_openai returned HTTP {code} ({evidence})")
    }
}

// ── Wire types ─────────────────────────────────────────────────────────
//
// Identical to `providers::openai_api`'s shapes — Azure mirrors OpenAI's
// request/response envelope, only the auth + URL differ.

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    max_completion_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
}

/// Azure's reviewed per-call maximum is both its cost ceiling and the exact
/// `max_completion_tokens` field written to the request body.
fn effective_output_token_limit(req: &Request) -> u32 {
    req.max_output_tokens
        .unwrap_or(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
        .min(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
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
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
}

#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_key() -> SecretString {
        SecretString::new("test-azure-key".into())
    }

    #[test]
    fn adapter_constructs_with_endpoint_and_deployment() {
        let a = AzureOpenAiAdapter::new(
            "https://my-resource.openai.azure.com",
            dummy_key(),
            "gpt-5-prod",
            None,
        )
        .expect("construct");
        assert_eq!(a.name(), "azure_openai");
        assert_eq!(a.api_version, DEFAULT_API_VERSION);
        assert_eq!(
            a.consent_route(),
            Some(crate::consent::ConsentRoute::new(
                crate::cli::init::ProviderKind::AzureOpenAi,
                Some("https://my-resource.openai.azure.com"),
            ))
        );
    }

    #[test]
    fn requested_output_cap_is_the_exact_azure_wire_ceiling() {
        let adapter = AzureOpenAiAdapter::new(
            "https://my-resource.openai.azure.com",
            dummy_key(),
            "gpt-5-prod",
            None,
        )
        .expect("construct");
        let req = Request {
            max_output_tokens: Some(88),
            ..Request::default()
        };
        assert!(adapter.request_controls().supports_max_output_tokens());
        assert_eq!(adapter.output_token_ceiling(&req), Some(88));
        assert_eq!(effective_output_token_limit(&req), 88);
        let body = ChatRequest {
            model: "gpt-5-prod".into(),
            messages: vec![],
            stream: false,
            max_completion_tokens: effective_output_token_limit(&req),
            temperature: None,
            top_p: None,
            seed: None,
            stop: None,
        };
        assert_eq!(
            serde_json::to_value(body).unwrap()["max_completion_tokens"],
            88
        );
    }

    #[test]
    fn chat_request_serializes_bounded_output_ceiling() {
        let body = ChatRequest {
            model: "gpt-5-prod".into(),
            messages: vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }],
            stream: false,
            max_completion_tokens: crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING,
            temperature: None,
            top_p: None,
            seed: None,
            stop: None,
        };
        let json = serde_json::to_value(body).unwrap();
        assert_eq!(json["max_completion_tokens"], 4096);
        for field in ["temperature", "top_p", "seed", "stop"] {
            assert!(json.get(field).is_none());
        }
    }

    #[test]
    fn chat_request_serializes_sampling_controls() {
        let body = ChatRequest {
            model: "gpt-5-prod".into(),
            messages: vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }],
            stream: false,
            max_completion_tokens: crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING,
            temperature: Some(0.3),
            top_p: Some(0.8),
            seed: Some(9),
            stop: Some(vec!["END".into()]),
        };
        let json = serde_json::to_value(body).unwrap();
        assert_eq!(json["temperature"].as_f64(), Some(f64::from(0.3_f32)));
        assert_eq!(json["top_p"].as_f64(), Some(f64::from(0.8_f32)));
        assert_eq!(json["seed"], 9);
        assert_eq!(json["stop"], serde_json::json!(["END"]));
    }

    #[test]
    fn empty_endpoint_is_rejected() {
        let err =
            AzureOpenAiAdapter::new("", dummy_key(), "gpt-5-prod", None).expect_err("must reject");
        assert!(err.to_string().contains("empty endpoint"));
    }

    #[test]
    fn empty_deployment_is_rejected() {
        let err = AzureOpenAiAdapter::new(
            "https://my-resource.openai.azure.com",
            dummy_key(),
            "",
            None,
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("empty deployment"));
    }

    #[test]
    fn deployment_name_with_url_unsafe_chars_is_rejected_at_construction() {
        // COR-15: names that could inject path segments / query / traversal
        // into the Azure URL must be refused by new().
        for bad in [
            "../../admin",
            "prod/chat/completions",
            "prod?api-version=evil",
            "prod#frag",
            "prod name",
            "prod%2e%2e",
        ] {
            let res = AzureOpenAiAdapter::new(
                "https://my-resource.openai.azure.com",
                dummy_key(),
                bad,
                None,
            );
            assert!(res.is_err(), "new() must reject deployment `{bad}`");
        }
    }

    #[test]
    fn deployment_name_charset_validator_accepts_real_and_rejects_unsafe() {
        // Real Azure deployment names (alphanumeric + . _ -) pass.
        for ok in ["gpt-5-prod", "gpt.4o", "my_deploy-1", "GPT5"] {
            assert!(validate_deployment_name(ok).is_ok(), "should accept `{ok}`");
        }
        // Anything with path/query/traversal metacharacters is refused.
        for bad in ["", "a/b", "a?b", "a#b", "a b", "..", "a:b"] {
            let err = validate_deployment_name(bad).expect_err("must reject");
            let msg = err.to_string();
            assert!(
                msg.contains("empty deployment")
                    || msg.contains("outside [A-Za-z0-9._-]")
                    || msg.contains("path traversal"),
                "`{bad}` got: {msg}"
            );
        }
    }

    #[test]
    fn api_version_override_threads_through() {
        let a = AzureOpenAiAdapter::new(
            "https://my-resource.openai.azure.com",
            dummy_key(),
            "gpt-5-prod",
            Some("2025-04-01-preview".to_string()),
        )
        .expect("construct");
        assert_eq!(a.api_version, "2025-04-01-preview");
    }

    #[test]
    fn api_version_empty_string_falls_back_to_default() {
        let a = AzureOpenAiAdapter::new(
            "https://my-resource.openai.azure.com",
            dummy_key(),
            "gpt-5-prod",
            Some("   ".to_string()),
        )
        .expect("construct");
        assert_eq!(a.api_version, DEFAULT_API_VERSION);
    }

    #[test]
    fn endpoint_strips_trailing_slash() {
        let a = AzureOpenAiAdapter::new(
            "https://my-resource.openai.azure.com/",
            dummy_key(),
            "gpt-5-prod",
            None,
        )
        .expect("construct");
        assert_eq!(a.endpoint, "https://my-resource.openai.azure.com");
    }

    #[test]
    fn endpoint_strips_trailing_openai_segment() {
        // Common operator paste-error: copy the URL with `/openai/`
        // already attached.
        let a = AzureOpenAiAdapter::new(
            "https://my-resource.openai.azure.com/openai/",
            dummy_key(),
            "gpt-5-prod",
            None,
        )
        .expect("construct");
        assert_eq!(a.endpoint, "https://my-resource.openai.azure.com");
    }

    #[test]
    fn endpoint_strips_full_deployments_path() {
        let a = AzureOpenAiAdapter::new(
            "https://my-resource.openai.azure.com/openai/deployments/old-deployment",
            dummy_key(),
            "gpt-5-prod",
            None,
        )
        .expect("construct");
        assert_eq!(a.endpoint, "https://my-resource.openai.azure.com");
    }

    #[test]
    fn url_assembles_canonical_form() {
        let a = AzureOpenAiAdapter::new(
            "https://foo.openai.azure.com",
            dummy_key(),
            "gpt-5-prod",
            None,
        )
        .expect("construct");
        let url = a.url("gpt-5-prod");
        assert_eq!(
            url,
            format!(
                "https://foo.openai.azure.com/openai/deployments/gpt-5-prod/chat/completions?api-version={DEFAULT_API_VERSION}"
            )
        );
    }

    #[test]
    fn url_threads_per_request_deployment_override() {
        let a = AzureOpenAiAdapter::new(
            "https://foo.openai.azure.com",
            dummy_key(),
            "default-deployment",
            None,
        )
        .expect("construct");
        let url = a.url("override-deployment");
        assert!(url.contains("/deployments/override-deployment/"));
    }

    #[test]
    fn map_error_recognises_401_invalid_key() {
        let err = map_azure_error(
            reqwest::StatusCode::UNAUTHORIZED,
            "{\"error\":{\"code\":\"401\",\"message\":\"Invalid API key\"}}",
            "gpt-5-prod",
            "body_sha256=fixture truncated=false",
        );
        let s = err.to_string();
        assert!(s.contains("api-key rejected"));
    }

    #[test]
    fn map_error_recognises_404_missing_deployment() {
        let err = map_azure_error(
            reqwest::StatusCode::NOT_FOUND,
            "{\"error\":{\"message\":\"The API deployment for this resource does not exist.\"}}",
            "gpt-5-prod",
            "body_sha256=fixture truncated=false",
        );
        let s = err.to_string();
        assert!(s.contains("deployment"));
        assert!(s.contains("gpt-5-prod"));
        assert!(s.contains("Azure portal"));
    }

    #[test]
    fn map_error_recognises_400_bad_api_version() {
        let err = map_azure_error(
            reqwest::StatusCode::BAD_REQUEST,
            "{\"error\":{\"message\":\"api-version 2020-01-01 is not supported\"}}",
            "gpt-5-prod",
            "body_sha256=fixture truncated=false",
        );
        let s = err.to_string();
        assert!(s.contains("api-version"));
        assert!(s.contains("provider_api_version"));
    }

    #[test]
    fn map_error_recognises_content_filter() {
        let err = map_azure_error(
            reqwest::StatusCode::BAD_REQUEST,
            "{\"error\":{\"innererror\":{\"code\":\"content_filter\"}}}",
            "gpt-5-prod",
            "body_sha256=fixture truncated=false",
        );
        let s = err.to_string();
        assert!(s.contains("content filter"));
    }

    #[test]
    fn map_error_falls_through_for_unknown_codes() {
        let err = map_azure_error(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "gpt-5-prod",
            "body_sha256=fixture truncated=false",
        );
        assert!(err.to_string().contains("HTTP 500"));
    }

    #[test]
    fn native_200_refusal_fixtures_preserve_authoritative_signal() {
        for (fixture, expected_origin, expected_reason, expected_text) in [
            (
                serde_json::json!({
                    "message": {"content": null, "refusal": "I cannot help with that."},
                    "finish_reason": "stop"
                }),
                RefusalOrigin::ProviderMessage,
                "message.refusal",
                "I cannot help with that.",
            ),
            (
                serde_json::json!({
                    "message": {"content": null},
                    "finish_reason": "content_filter"
                }),
                RefusalOrigin::FinishReason,
                "content_filter",
                "",
            ),
        ] {
            let choice: ChatChoice = serde_json::from_value(fixture).expect("valid fixture");
            let (text, termination) = parse_azure_choice(choice).expect("native refusal");
            let refusal = termination.refusal.expect("typed refusal");
            assert_eq!(refusal.origin, expected_origin);
            assert_eq!(refusal.reason, expected_reason);
            assert_eq!(text, expected_text);
        }
    }

    #[test]
    fn blank_message_refusal_is_authoritative_and_not_a_malformed_success() {
        let choice: ChatChoice = serde_json::from_value(serde_json::json!({
            "message": {"content": null, "refusal": ""},
            "finish_reason": "stop"
        }))
        .unwrap();
        let (text, termination) = parse_azure_choice(choice).expect("blank native refusal");
        assert!(text.is_empty());
        assert_eq!(
            termination.refusal.expect("typed refusal").origin,
            RefusalOrigin::ProviderMessage
        );
    }

    #[test]
    fn http_policy_envelope_is_recognised_without_message_substring_guessing() {
        let (reason, message) = parse_azure_policy_error(
            r#"{"error":{"code":"content_filter","message":"Prompt blocked.","innererror":{"code":"ResponsibleAIPolicyViolation"}}}"#,
        )
        .expect("policy envelope");
        assert_eq!(reason, "content_filter");
        assert_eq!(message.as_deref(), Some("Prompt blocked."));
        assert!(parse_azure_policy_error(r#"{"error":{"code":"BadRequest"}}"#).is_none());
    }

    // ── Response envelope bounds (GOLD-R4-15k1) ──────────────────────────────

    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_adapter_against(endpoint: &str) -> AzureOpenAiAdapter {
        // Bounds fixtures deliberately fail provider calls and the breaker
        // registry is process-global per adapter identity.
        crate::providers::circuit_breaker::reset_for_test("azure_openai");
        AzureOpenAiAdapter::new(
            endpoint.to_string(),
            SecretString::from("azure-mock-key"),
            "gpt-mock",
            None,
        )
        .expect("adapter constructs against mock endpoint")
    }

    async fn mount_completions(mock: &MockServer, status: u16, body: impl Into<Vec<u8>>) {
        Mock::given(method("POST"))
            .and(path_regex(r"^/openai/deployments/.*/chat/completions$"))
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
        let secret = "azure-never-persist-oversized-success";
        let body = format!(
            r#"{{"choices":[{{"message":{{"role":"assistant","content":"{secret}{}"}}}}]}}"#,
            "x".repeat(MAX_SUCCESS_BODY_BYTES)
        );
        let mock = MockServer::start().await;
        mount_completions(&mock, 200, body).await;

        let message = complete_error_against(&mock).await;
        assert!(message.contains("successful response body exceeded"));
        assert!(message.contains("body_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }

    /// The classification still works on a bounded body — an oversized 400
    /// policy envelope must not silently become a generic failure — while the
    /// bytes themselves never reach the operator-facing message.
    #[tokio::test]
    async fn error_classification_survives_bounding_without_echoing_the_body() {
        let secret = "azure-never-persist-http-error";
        let mock = MockServer::start().await;
        mount_completions(
            &mock,
            404,
            format!(
                r#"{{"error":{{"message":"The API deployment for this resource does not exist. {secret}{}"}}}}"#,
                "x".repeat(MAX_ERROR_BODY_BYTES * 2)
            ),
        )
        .await;

        let message = complete_error_against(&mock).await;
        assert!(message.contains("HTTP 404"), "got: {message}");
        assert!(message.contains("gpt-mock"), "keeps the deployment name");
        assert!(message.contains("Azure portal"), "keeps operator guidance");
        assert!(message.contains("body_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn http_policy_refusal_stays_a_typed_completion_on_a_bounded_body() {
        let mock = MockServer::start().await;
        mount_completions(
            &mock,
            400,
            r#"{"error":{"code":"content_filter","message":"Prompt blocked."}}"#,
        )
        .await;

        let completion = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("a policy envelope is an authoritative response, not a transport failure");
        let refusal = completion
            .termination
            .refusal
            .expect("policy envelope must stay a typed refusal");
        assert_eq!(refusal.origin, RefusalOrigin::PromptFilter);
        assert_eq!(refusal.reason, "content_filter");
        assert_eq!(completion.text, "Prompt blocked.");
    }

    /// A policy message becomes visible text, so an endpoint echoing our own
    /// key back inside it must not put that key in the completion.
    #[tokio::test]
    async fn policy_refusal_text_never_carries_our_own_key() {
        let mock = MockServer::start().await;
        mount_completions(
            &mock,
            400,
            r#"{"error":{"code":"content_filter","message":"blocked for key azure-mock-key"}}"#,
        )
        .await;

        let completion = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("policy envelope stays an authoritative response");
        assert!(!completion.text.contains("azure-mock-key"));
        assert!(completion.text.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn quota_body_retains_digest_evidence_only() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/openai/deployments/.*/chat/completions$"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "13")
                    .set_body_raw(
                        r#"{"error":{"message":"azure-mock-key exceeded quota"}}"#,
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
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(13)));
        assert!(quota.body.starts_with("body_sha256="));
        assert!(!quota.body.contains("azure-mock-key"));
        assert!(!quota.body.contains("exceeded quota"));
    }
}
