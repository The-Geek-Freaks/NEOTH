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
use super::{Completion, Provider, Request};
use crate::secret::SecretString;

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
        let http = super::http_client::build_client()?;
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

    async fn complete(&self, req: Request) -> Result<Completion> {
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
                    let body_text = response
                        .text()
                        .await
                        .unwrap_or_default()
                        .replace(self.api_key.expose(), "[REDACTED]");
                    return Err(anyhow::Error::new(QuotaError {
                        provider: "azure_openai",
                        retry_after,
                        body: body_text.trim().to_string(),
                    }));
                }
                let body_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".into())
                    .replace(self.api_key.expose(), "[REDACTED]");
                return Err(map_azure_error(status, &body_text, &deployment));
            }

            let parsed: ChatResponse = response
                .json()
                .await
                .with_context(|| "parse azure_openai response JSON".to_string())?;

            let text = parsed
                .choices
                .into_iter()
                .next()
                .map(|c| c.message.content)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "azure_openai returned 200 OK but no choices[].message.content — \
                     likely a content-filter refusal. Inspect NEOTH_LOG_LEVEL=debug."
                    )
                })?;

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
                model: deployment,
                latency,
                input_tokens: parsed.usage.as_ref().map(|u| u.prompt_tokens),
                output_tokens: parsed.usage.as_ref().map(|u| u.completion_tokens),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        })
        .await
    }
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
fn map_azure_error(status: reqwest::StatusCode, body: &str, deployment: &str) -> anyhow::Error {
    let trimmed = body.trim();
    let lower = trimmed.to_ascii_lowercase();
    let code = status.as_u16();
    if code == 401 || lower.contains("unauthorized") || lower.contains("invalid api key") {
        anyhow::anyhow!(
            "azure_openai HTTP {code}: api-key rejected. Confirm the key matches the resource \
             at the configured endpoint, and that the key hasn't been rotated. Raw body: {trimmed}"
        )
    } else if code == 404 && lower.contains("deployment") {
        anyhow::anyhow!(
            "azure_openai HTTP 404: deployment `{deployment}` not found at the configured endpoint. \
             Check the deployment name against the Azure portal → OpenAI resource → Deployments. \
             Raw body: {trimmed}"
        )
    } else if code == 400 && (lower.contains("api-version") || lower.contains("apiversion")) {
        anyhow::anyhow!(
            "azure_openai HTTP 400: api-version rejected. Set `provider_api_version` in freedom.yaml \
             (current default: 2024-10-21; preview: 2025-04-01-preview). Raw body: {trimmed}"
        )
    } else if code == 400 && lower.contains("content_filter") {
        anyhow::anyhow!(
            "azure_openai HTTP 400: content filter triggered. Azure applies its own content \
             policy on top of the underlying model. Raw body: {trimmed}"
        )
    } else {
        anyhow::anyhow!("azure_openai returned HTTP {code}: {trimmed}")
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
        );
        assert!(err.to_string().contains("HTTP 500"));
    }
}
