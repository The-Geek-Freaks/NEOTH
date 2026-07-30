//! OpenAI REST adapter (`api.openai.com` and OpenAI-compatible endpoints).
//!
//! POST {endpoint}/chat/completions with a Bearer token. Supports both the
//! upstream OpenAI service and OpenAI-compatible endpoints (LM Studio, vLLM,
//! Ollama /v1, Anthropic via OAI-shim, etc.). A non-official endpoint supplied
//! through the OpenAI constructor is deliberately reclassified as
//! `openai_api_custom`: it cannot inherit the reviewed official price table.
//!
//! Streaming: `stream()` sends `stream: true` and reads the response body as
//! Server-Sent Events (SSE), parsing each `data: {...}` line as an OpenAI
//! streaming chunk and mapping it to `CompletionChunk`. Works with any
//! OpenAI-compat endpoint including Ollama's `/v1/chat/completions` path.

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::quota::{QuotaError, parse_retry_after};
use super::termination::{ObservedUpstreamEvidence, ProviderTermination, RefusalOrigin};
use super::{
    ChunkStream, Completion, CompletionChunk, Provider, ProviderDispatchPermit,
    ProviderRequestControls, Request,
};
use crate::config::inference::OpenAiCompatibleProfile;
use crate::secret::SecretString;

const MAX_PROVIDER_ERROR_BODY_BYTES: usize = 64 * 1024;

struct BoundedProviderErrorBody {
    text: String,
    evidence: String,
}

fn redacted_response_evidence(
    domain: &'static [u8],
    arguments: std::fmt::Arguments<'_>,
    input_truncated: bool,
) -> String {
    let evidence = crate::security::redact::bounded_audit_digest_with_truncation(
        domain,
        arguments,
        input_truncated,
    );
    format!(
        "body_sha256={} truncated={}",
        evidence.sha256, evidence.truncated
    )
}

async fn read_bounded_provider_error_body(
    response: reqwest::Response,
    api_key: &str,
) -> BoundedProviderErrorBody {
    let mut body = Vec::with_capacity(MAX_PROVIDER_ERROR_BODY_BYTES.min(8 * 1024));
    let mut input_truncated = false;
    let mut read_failed = false;
    let mut chunks = response.bytes_stream();
    while let Some(next) = chunks.next().await {
        let chunk = match next {
            Ok(chunk) => chunk,
            Err(_) => {
                read_failed = true;
                break;
            }
        };
        let remaining = MAX_PROVIDER_ERROR_BODY_BYTES.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            input_truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let raw = String::from_utf8_lossy(&body);
    let evidence = redacted_response_evidence(
        b"openai-compatible-http-error-body/v1",
        format_args!("{raw}"),
        input_truncated || read_failed,
    );
    let mut text = if read_failed && raw.is_empty() {
        "<unreadable body>".to_owned()
    } else {
        raw.into_owned()
    };
    if !api_key.is_empty() {
        text = text.replace(api_key, "[REDACTED]");
    }
    BoundedProviderErrorBody { text, evidence }
}

fn is_official_openai_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("api.openai.com")
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().trim_end_matches('/') == "/v1"
}

fn is_openrouter_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("openrouter.ai")
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path().trim_end_matches('/') == "/api/v1"
}

fn parse_openai_compatible_policy_error(body: &str) -> Option<(String, Option<String>)> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    parse_openai_compatible_policy_error_value(&parsed)
}

fn parse_openai_compatible_policy_error_value(
    parsed: &serde_json::Value,
) -> Option<(String, Option<String>)> {
    let envelope = parsed.get("error").unwrap_or(parsed);
    let metadata = envelope.get("metadata");
    let native_reason = metadata
        .and_then(|value| value.get("error_type"))
        .and_then(serde_json::Value::as_str)
        .into_iter()
        .chain(
            ["error_type", "code", "type", "reason"]
                .into_iter()
                .filter_map(|key| envelope.get(key).and_then(serde_json::Value::as_str)),
        )
        .chain(parsed.get("error_type").and_then(serde_json::Value::as_str))
        .map(|value| value.trim().to_ascii_lowercase())
        .find(|value| {
            matches!(
                value.as_str(),
                "content_filter"
                    | "content_policy_violation"
                    | "data_inspection_failed"
                    | "moderation_blocked"
                    | "policy_violation"
                    | "refusal"
                    | "safety_violation"
            )
        });
    let router_guardrail = parsed
        .pointer("/openrouter_metadata/pipeline")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|pipeline| {
            pipeline.iter().any(|stage| {
                stage.get("type").and_then(serde_json::Value::as_str) == Some("guardrail")
                    && stage
                        .pointer("/data/action")
                        .and_then(serde_json::Value::as_str)
                        == Some("blocked")
            })
        });
    let reason =
        native_reason.or_else(|| router_guardrail.then(|| "router_guardrail".to_string()))?;
    let message = match reason.as_str() {
        "router_guardrail" => "The configured router guardrail blocked this request.",
        "data_inspection_failed" => "The provider blocked this request during data inspection.",
        "refusal" => "The provider refused this request.",
        _ => "The provider blocked this request under its content policy.",
    };
    Some((reason, Some(message.to_owned())))
}

fn merge_openrouter_observed_fields(
    accumulated: &mut Option<ObservedUpstreamEvidence>,
    provider: Option<&str>,
    model: Option<&str>,
) -> Result<()> {
    ObservedUpstreamEvidence::merge_into(
        accumulated,
        ObservedUpstreamEvidence::from_wire(provider, model)?,
    )?;
    Ok(())
}

fn merge_openrouter_error_provider(
    accumulated: &mut Option<ObservedUpstreamEvidence>,
    error: &serde_json::Value,
) -> Result<()> {
    merge_openrouter_observed_fields(
        accumulated,
        error
            .pointer("/metadata/provider_name")
            .and_then(serde_json::Value::as_str),
        None,
    )
}

fn merge_openrouter_observed_value(
    accumulated: &mut Option<ObservedUpstreamEvidence>,
    value: &serde_json::Value,
) -> Result<()> {
    merge_openrouter_observed_fields(
        accumulated,
        value.get("provider").and_then(serde_json::Value::as_str),
        value.get("model").and_then(serde_json::Value::as_str),
    )?;
    if let Some(error) = value.get("error") {
        merge_openrouter_error_provider(accumulated, error)?;
    } else {
        merge_openrouter_error_provider(accumulated, value)?;
    }
    Ok(())
}

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
    /// Exact compatible wire/vendor profile. `None` denotes native OpenAI or
    /// Copilot rather than an OpenAI-compatible binding.
    compat_profile: Option<OpenAiCompatibleProfile>,
    /// OpenRouter routing/guardrail metadata is opt-in. This flag is derived
    /// only from the exact HTTPS service endpoint, never an arbitrary suffix.
    openrouter_metadata: bool,
}

impl OpenAiAdapter {
    pub fn new_openai(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
    ) -> Result<Self> {
        let name = if is_official_openai_endpoint(&endpoint) {
            "openai_api"
        } else {
            "openai_api_custom"
        };
        Self::build(endpoint, api_key, default_model, name, None)
    }

    /// Backward-compatible arbitrary endpoint constructor. New config wiring
    /// uses [`Self::new_compat_profiled`] so reviewed vendor identities survive
    /// through authorization and completion attribution.
    pub fn new_compat(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
    ) -> Result<Self> {
        Self::new_compat_profiled(
            OpenAiCompatibleProfile::Generic,
            endpoint,
            api_key,
            default_model,
        )
    }

    pub fn new_compat_profiled(
        profile: OpenAiCompatibleProfile,
        endpoint: String,
        api_key: SecretString,
        default_model: String,
    ) -> Result<Self> {
        super::known_endpoints::validate_profile_endpoint(profile, &endpoint)?;
        Self::build(
            endpoint,
            api_key,
            default_model,
            profile.adapter_name(),
            Some(profile),
        )
    }

    /// GOLD-ADAPT-ODY-15 — Copilot-endpoint variant. Identical wire format to
    /// `new_openai` but names itself `"copilot_api"` so `Provider::name()`
    /// returns the correct cost-table key. The session token is a short-lived
    /// credential managed by `CopilotAdapter::fetch_or_refresh_token`; this
    /// constructor just records it as the bearer key for the one call.
    pub fn new_copilot(
        endpoint: String,
        session_token: SecretString,
        default_model: String,
    ) -> Result<Self> {
        Self::build(endpoint, session_token, default_model, "copilot_api", None)
    }

    fn build(
        endpoint: String,
        api_key: SecretString,
        default_model: String,
        name: &'static str,
        compat_profile: Option<OpenAiCompatibleProfile>,
    ) -> Result<Self> {
        let openrouter_metadata = is_openrouter_endpoint(&endpoint);
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let http = crate::providers::http_client::build_client_no_redirect()?;
        Ok(Self {
            endpoint,
            api_key,
            default_model,
            http,
            name,
            compat_profile,
            openrouter_metadata,
        })
    }

    #[cfg(test)]
    fn chat_request(
        &self,
        model: String,
        messages: Vec<ChatMessage>,
        stream: bool,
        req: &Request,
    ) -> ChatRequest {
        self.chat_request_with_subject(model, messages, stream, req, None)
    }

    fn chat_request_with_subject(
        &self,
        model: String,
        messages: Vec<ChatMessage>,
        stream: bool,
        req: &Request,
        provider_subject: Option<&crate::security::provider_subject::ProviderSubjectIdentifier>,
    ) -> ChatRequest {
        let (max_completion_tokens, max_tokens) =
            if self.compat_profile.is_some() || self.name == "openai_api_custom" {
                // Generic OpenAI-compatible servers (vLLM, LM Studio, Ollama,
                // OpenRouter) consistently implement the legacy `max_tokens`
                // field, while `max_completion_tokens` is an OpenAI/Azure-era
                // extension that several of them reject as unknown.
                (None, Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING))
            } else {
                (Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING), None)
            };
        ChatRequest {
            model,
            messages,
            stream,
            max_completion_tokens,
            max_tokens,
            temperature: req.temperature,
            top_p: req.top_p,
            seed: req.sampling_seed,
            stop: (!req.stop_sequences.is_empty()).then(|| req.stop_sequences.clone()),
            safety_identifier: provider_subject
                .and_then(|subject| subject.wire_value_for(self.name))
                .map(ToOwned::to_owned),
        }
    }

    fn authorized_chat_request(
        &self,
        model: String,
        messages: Vec<ChatMessage>,
        stream: bool,
        req: &Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<ChatRequest> {
        let provider_subject = permit.provider_subject()?;
        Ok(self.chat_request_with_subject(model, messages, stream, req, provider_subject.as_ref()))
    }

    fn instruction_role(&self) -> &'static str {
        if self.name == "openai_api" {
            "developer"
        } else {
            "system"
        }
    }
}

#[async_trait]
impl Provider for OpenAiAdapter {
    fn name(&self) -> &'static str {
        self.name
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::SAMPLING
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.default_model)
    }

    fn consent_route(&self) -> Option<crate::consent::ConsentRoute> {
        let kind = match (self.compat_profile, self.name) {
            (Some(_), _) => crate::cli::init::ProviderKind::OpenaiCompat,
            (None, "copilot_api") => crate::cli::init::ProviderKind::GitHubCopilot,
            (None, _) => crate::cli::init::ProviderKind::OpenaiApi,
        };
        Some(crate::consent::ConsentRoute::new(
            kind,
            Some(&self.endpoint),
        ))
    }

    fn output_token_ceiling(&self, _req: &Request) -> Option<u32> {
        Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
    }

    fn streams_on_wire(&self) -> bool {
        true
    }

    async fn complete_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<Completion> {
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
                    // OpenAI's current contract gives the developer role
                    // precedence over user messages. Compatible endpoints are
                    // intentionally kept on the broadly supported system role.
                    role: self.instruction_role(),
                    content: sys.clone(),
                });
            }
            messages.push(ChatMessage {
                role: "user",
                content: req.prompt.clone(),
            });

            let body =
                self.authorized_chat_request(model.clone(), messages, false, &req, permit)?;

            let url = format!("{}/chat/completions", self.endpoint);
            let mut request = self.http.post(&url).bearer_auth(self.api_key.expose());
            if self.openrouter_metadata {
                request = request.header("X-OpenRouter-Metadata", "enabled");
            }
            let response = request
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {url}"))?;

            let status = response.status();
            if !status.is_success() {
                // 429 carries a Retry-After header that the quota tracker needs.
                // We extract it BEFORE consuming the body so the caller can
                // downcast the error to `QuotaError` and update the tracker
                // without re-parsing the response. Only domain-separated body
                // evidence is retained; gateways may echo request secrets.
                let retry_after =
                    (status.as_u16() == 429).then(|| parse_retry_after(response.headers()));
                let bounded =
                    read_bounded_provider_error_body(response, self.api_key.expose()).await;
                if let Some(retry_after) = retry_after {
                    return Err(anyhow::Error::new(QuotaError {
                        provider: self.name,
                        retry_after,
                        body: bounded.evidence,
                    }));
                }
                let body = bounded.text;
                if let Some((reason, message)) = parse_openai_compatible_policy_error(body.trim()) {
                    let mut observed_upstream = None;
                    if self.openrouter_metadata
                        && let Ok(parsed) = serde_json::from_str(body.trim())
                    {
                        merge_openrouter_observed_value(&mut observed_upstream, &parsed)?;
                    }
                    let mut termination = ProviderTermination::refused(
                        None,
                        if reason == "router_guardrail" {
                            RefusalOrigin::RouterGuardrail
                        } else {
                            RefusalOrigin::PromptFilter
                        },
                        reason,
                        message.clone(),
                    )
                    .with_native_detail("policy_error_sha256", serde_json::json!(bounded.evidence));
                    termination.observed_upstream = observed_upstream;
                    return Ok(Completion {
                        text: message.clone().unwrap_or_default(),
                        identity: Default::default(),
                        model,
                        termination,
                        latency: started.elapsed(),
                        input_tokens: None,
                        output_tokens: None,
                        cache_creation_tokens: None,
                        cache_read_tokens: None,
                    });
                }
                anyhow::bail!(
                    "{} returned HTTP {} ({})",
                    self.name,
                    status.as_u16(),
                    bounded.evidence
                );
            }

            let parsed: ChatResponse = response
                .json()
                .await
                .with_context(|| format!("parse {} response JSON", self.name))?;
            let ChatResponse {
                choices,
                usage,
                model: observed_model,
                provider: observed_provider,
            } = parsed;
            let mut observed_upstream = None;
            if self.openrouter_metadata {
                merge_openrouter_observed_fields(
                    &mut observed_upstream,
                    observed_provider.as_deref(),
                    observed_model.as_deref(),
                )?;
            }

            // CDX-07 silent-fail-to-empty fix: surface the malformed shape
            // as an error instead of silently returning "". A native
            // `message.refusal` or `finish_reason=content_filter`, however,
            // is an authoritative successful response envelope and must be
            // returned as typed termination metadata rather than discarded.
            let choice = choices.into_iter().next().ok_or_else(|| {
                anyhow::anyhow!(
                    "{} returned 200 OK but the response has no choices[] — \
                     likely an upstream error envelope. \
                     Inspect the raw HTTP body via NEOTH_LOG_LEVEL=debug.",
                    self.name
                )
            })?;
            let finish_reason = choice.finish_reason;
            let choice_policy_error = choice
                .error
                .as_ref()
                .and_then(parse_openai_compatible_policy_error_value);
            let choice_error_evidence = choice.error.as_ref().map(|error| {
                redacted_response_evidence(
                    b"openai-compatible-choice-error/v1",
                    format_args!("{error}"),
                    false,
                )
            });
            if self.openrouter_metadata
                && let Some(error) = choice.error.as_ref()
            {
                merge_openrouter_error_provider(&mut observed_upstream, error)?;
            }
            let ChatChoiceMessage { content, refusal } = choice.message;
            let parsed_content = content
                .map(ChatChoiceContent::into_text_and_refusal)
                .unwrap_or_default();
            let direct_refusal_present = refusal.is_some();
            let direct_refusal_message = refusal.filter(|value| !value.trim().is_empty());
            let (refusal_present, refusal_message, refusal_reason) = if direct_refusal_present {
                (true, direct_refusal_message, "message.refusal")
            } else {
                (
                    parsed_content.refusal_present,
                    parsed_content.refusal_message,
                    "content.refusal",
                )
            };
            let content_filtered = finish_reason.as_deref() == Some("content_filter");
            let mut termination = if refusal_present {
                ProviderTermination::refused(
                    finish_reason.clone(),
                    RefusalOrigin::ProviderMessage,
                    refusal_reason,
                    refusal_message.clone(),
                )
            } else if let Some((reason, message)) = choice_policy_error.as_ref() {
                ProviderTermination::refused(
                    finish_reason.clone(),
                    match reason.as_str() {
                        "refusal" => RefusalOrigin::ProviderMessage,
                        "router_guardrail" => RefusalOrigin::RouterGuardrail,
                        _ => RefusalOrigin::CandidateFilter,
                    },
                    reason.clone(),
                    message.clone(),
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
            if choice_policy_error.is_some()
                && let Some(evidence) = choice_error_evidence
            {
                termination = termination
                    .with_native_detail("choice_error_sha256", serde_json::json!(evidence));
            }
            termination.observed_upstream = observed_upstream;
            let text = parsed_content
                .text
                .filter(|value| !value.is_empty())
                .or_else(|| refusal_message.clone())
                .or_else(|| {
                    choice_policy_error
                        .as_ref()
                        .and_then(|(_, message)| message.clone())
                })
                .or_else(|| termination.is_refusal().then(String::new))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} returned 200 OK but choices[0].message has neither content nor a \
                         native refusal and finish_reason is not content_filter",
                        self.name
                    )
                })
                .or_else(|error| {
                    if termination.is_refusal() {
                        Ok(String::new())
                    } else {
                        Err(error)
                    }
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
                identity: Default::default(),
                model,
                termination,
                latency,
                input_tokens: usage.as_ref().map(|u| u.prompt_tokens),
                output_tokens: usage.as_ref().map(|u| u.completion_tokens),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        })
        .await
    }

    /// SSE streaming completion. Sends `stream: true` and parses the response
    /// body as Server-Sent Events. Each `data: {...}` line is decoded as an
    /// `OpenAI streaming chunk`; `data: [DONE]` terminates the stream.
    ///
    /// Works with any OpenAI-compat endpoint that honours `stream: true`,
    /// including Ollama's `/v1/chat/completions` path and LM Studio.
    async fn stream_raw(
        &self,
        req: Request,
        permit: &ProviderDispatchPermit,
    ) -> Result<ChunkStream> {
        crate::providers::circuit_breaker_stream::run_stream_with_breaker(self.name, async {
            let model = req
                .model
                .clone()
                .unwrap_or_else(|| self.default_model.clone());

            let mut messages = Vec::new();
            if let Some(sys) = &req.system {
                messages.push(ChatMessage {
                    role: self.instruction_role(),
                    content: sys.clone(),
                });
            }
            messages.push(ChatMessage {
                role: "user",
                content: req.prompt.clone(),
            });

            let body = self.authorized_chat_request(model.clone(), messages, true, &req, permit)?;

            let url = format!("{}/chat/completions", self.endpoint);
            let mut request = self.http.post(&url).bearer_auth(self.api_key.expose());
            if self.openrouter_metadata {
                request = request.header("X-OpenRouter-Metadata", "enabled");
            }
            let response = request
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {url} (stream)"))?;

            let status = response.status();
            if !status.is_success() {
                let retry_after =
                    (status.as_u16() == 429).then(|| parse_retry_after(response.headers()));
                let bounded =
                    read_bounded_provider_error_body(response, self.api_key.expose()).await;
                if let Some(retry_after) = retry_after {
                    return Err(anyhow::Error::new(QuotaError {
                        provider: self.name,
                        retry_after,
                        body: bounded.evidence,
                    }));
                }
                let body_text = bounded.text;
                if let Some((reason, message)) =
                    parse_openai_compatible_policy_error(body_text.trim())
                {
                    let mut observed_upstream = None;
                    if self.openrouter_metadata
                        && let Ok(parsed) = serde_json::from_str(body_text.trim())
                    {
                        merge_openrouter_observed_value(&mut observed_upstream, &parsed)?;
                    }
                    let origin = if reason == "router_guardrail" {
                        RefusalOrigin::RouterGuardrail
                    } else {
                        RefusalOrigin::PromptFilter
                    };
                    let mut termination =
                        ProviderTermination::refused(None, origin, reason, message.clone())
                            .with_native_detail(
                                "policy_error_sha256",
                                serde_json::json!(bounded.evidence),
                            );
                    termination.observed_upstream = observed_upstream;
                    let chunk = CompletionChunk {
                        delta: message.clone().unwrap_or_default(),
                        done: true,
                        identity: Default::default(),
                        termination,
                        input_tokens: None,
                        output_tokens: None,
                        cache_creation_tokens: None,
                        cache_read_tokens: None,
                    };
                    return Ok(Box::pin(futures_util::stream::iter(vec![Ok(chunk)])) as ChunkStream);
                }
                anyhow::bail!(
                    "{} stream returned HTTP {} ({})",
                    self.name,
                    status.as_u16(),
                    bounded.evidence
                );
            }

            let name = self.name;
            let observe_openrouter = self.openrouter_metadata;
            let byte_stream = response.bytes_stream();
            // Buffer partial lines across byte chunks (SSE lines may be split
            // across reqwest byte chunks on slow connections).
            let inner: ChunkStream = Box::pin(async_stream::try_stream! {
                let mut buf = String::new();
                let mut input_tokens: Option<u32> = None;
                let mut output_tokens: Option<u32> = None;
                let mut termination = ProviderTermination::default();
                let mut observed_upstream = None;
                let mut saw_authoritative_terminal = false;

                tokio::pin!(byte_stream);
                while let Some(chunk_result) = byte_stream.next().await {
                    let bytes = chunk_result
                        .with_context(|| format!("{name}: SSE byte read error"))?;
                    let text = std::str::from_utf8(&bytes)
                        .with_context(|| format!("{name}: SSE chunk not valid UTF-8"))?;
                    buf.push_str(text);

                    // Process all complete lines (\n-terminated SSE lines).
                    while let Some(newline_pos) = buf.find('\n') {
                        let line = buf[..newline_pos].trim_end_matches('\r').to_string();
                        buf.drain(..=newline_pos);

                        if line.is_empty() || line.starts_with(':') {
                            // SSE comment or blank separator — skip.
                            continue;
                        }
                        let Some(data) = sse_data(&line) else {
                            continue;
                        };
                        if data == "[DONE]" {
                            // Emit the final done-chunk with token counts.
                            termination.observed_upstream = observed_upstream;
                            yield CompletionChunk {
                                delta: String::new(),
                                done: true,
                                identity: Default::default(),
                                termination,
                                input_tokens,
                                output_tokens,
                                cache_creation_tokens: None,
                                cache_read_tokens: None,
                            };
                            return;
                        }
                        // Decode every JSON frame. A malformed frame or a
                        // non-policy error envelope is a stream error, never
                        // an empty successful completion.
                        let decoded = decode_sse_chunk(
                            data,
                            name,
                            &mut termination,
                            observe_openrouter,
                            &mut observed_upstream,
                        )?;
                        saw_authoritative_terminal |= decoded.authoritative_terminal;
                        // Capture token counts from any usage block the endpoint
                        // injects (Ollama compat includes them on the last data
                        // line, OpenAI includes them only with stream_options).
                        if let Some(u) = decoded.usage {
                            input_tokens = Some(u.prompt_tokens);
                            output_tokens = Some(u.completion_tokens);
                        }
                        if !decoded.delta.is_empty() {
                            yield CompletionChunk {
                                delta: decoded.delta,
                                done: false,
                                identity: Default::default(),
                                termination: Default::default(),
                                input_tokens: None,
                                output_tokens: None,
                                cache_creation_tokens: None,
                                cache_read_tokens: None,
                            };
                        }
                    }
                }
                // EOF residual: parse a final `data:` line the endpoint ended
                // WITHOUT a trailing newline (the line-loop never consumed it), so
                // a newline-less last delta or usage block isn't dropped before the
                // terminator. A newline-less terminal frame must still authorize
                // successful EOF completion.
                let tail = buf.trim();
                if let Some(data) = sse_data(tail) {
                    let data = data.trim();
                    if data == "[DONE]" {
                        saw_authoritative_terminal = true;
                    } else if !data.is_empty() {
                        let decoded = decode_sse_chunk(
                            data,
                            name,
                            &mut termination,
                            observe_openrouter,
                            &mut observed_upstream,
                        )?;
                        saw_authoritative_terminal |= decoded.authoritative_terminal;
                        if let Some(u) = decoded.usage {
                            input_tokens = Some(u.prompt_tokens);
                            output_tokens = Some(u.completion_tokens);
                        }
                        if !decoded.delta.is_empty() {
                            yield CompletionChunk {
                                delta: decoded.delta,
                                done: false,
                                identity: Default::default(),
                                termination: Default::default(),
                                input_tokens: None,
                                output_tokens: None,
                                cache_creation_tokens: None,
                                cache_read_tokens: None,
                            };
                        }
                    }
                }
                if !saw_authoritative_terminal {
                    Err(anyhow::anyhow!(
                        "{name}: SSE stream ended before an authoritative terminal signal \
                         ([DONE], finish_reason, or recognized policy envelope)"
                    ))?;
                }
                termination.observed_upstream = observed_upstream;
                yield CompletionChunk {
                    delta: String::new(),
                    done: true,
                    identity: Default::default(),
                    termination,
                    input_tokens,
                    output_tokens,
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                };
            });

            debug!(adapter = name, model = %model, "openai SSE stream started");
            Ok(inner)
        })
        .await
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
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safety_identifier: Option<String>,
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
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
    #[serde(default)]
    finish_reason: Option<String>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    #[serde(default)]
    content: Option<ChatChoiceContent>,
    #[serde(default)]
    refusal: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ChatChoiceContent {
    Text(String),
    Parts(Vec<ChatChoiceContentPart>),
}

#[derive(Default)]
struct ParsedChatChoiceContent {
    text: Option<String>,
    refusal_present: bool,
    refusal_message: Option<String>,
}

impl ChatChoiceContent {
    fn into_text_and_refusal(self) -> ParsedChatChoiceContent {
        match self {
            Self::Text(text) => ParsedChatChoiceContent {
                text: (!text.is_empty()).then_some(text),
                ..Default::default()
            },
            Self::Parts(parts) => {
                let mut text = String::new();
                let mut refusal_present = false;
                let mut refusal_message = String::new();
                for part in parts {
                    match part.kind.as_str() {
                        "text" => {
                            if let Some(fragment) = part.text {
                                text.push_str(&fragment);
                            }
                        }
                        "refusal" => {
                            refusal_present = true;
                            if let Some(fragment) =
                                part.refusal.or(part.text).filter(|value| !value.is_empty())
                            {
                                refusal_message.push_str(&fragment);
                            }
                        }
                        _ => {}
                    }
                }
                ParsedChatChoiceContent {
                    text: (!text.is_empty()).then_some(text),
                    refusal_present,
                    refusal_message: (!refusal_message.is_empty()).then_some(refusal_message),
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct ChatChoiceContentPart {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
}

#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

// ── SSE streaming wire types ────────────────────────────────────────────────
//
// OpenAI streaming format: each `data:` line is a JSON object with a
// `choices[].delta.content` field.  The final line is `data: [DONE]`.
// Usage is only present when the endpoint opts in (stream_options or
// Ollama's own done-chunk injection); it is always optional here.

#[derive(Deserialize)]
struct SseChunk {
    #[serde(default)]
    choices: Vec<SseChoice>,
    #[serde(default)]
    usage: Option<SseUsage>,
    #[serde(default)]
    error: Option<serde_json::Value>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    provider: Option<String>,
}

/// Return the payload of an SSE `data` field. The single space after `:` is
/// optional per the wire format, so `data:{...}` and `data: {...}` must take
/// the same parser path in both the line loop and the EOF residual handler.
fn sse_data(line: &str) -> Option<&str> {
    line.strip_prefix("data:")
        .map(|data| data.strip_prefix(' ').unwrap_or(data))
}

fn decode_sse_chunk(
    data: &str,
    adapter_name: &str,
    termination: &mut ProviderTermination,
    observe_openrouter: bool,
    observed_upstream: &mut Option<ObservedUpstreamEvidence>,
) -> Result<DecodedSseChunk> {
    let parsed: SseChunk = serde_json::from_str(data)
        .with_context(|| format!("{adapter_name}: malformed SSE data frame"))?;
    let SseChunk {
        choices,
        usage,
        error,
        model,
        provider,
    } = parsed;

    if observe_openrouter {
        merge_openrouter_observed_fields(observed_upstream, provider.as_deref(), model.as_deref())?;
        if let Some(error) = error.as_ref() {
            merge_openrouter_error_provider(observed_upstream, error)?;
        }
    }

    if let Some(error) = error {
        let error_evidence = redacted_response_evidence(
            b"openai-compatible-sse-error/v1",
            format_args!("{error}"),
            false,
        );
        let Some((reason, message)) = parse_openai_compatible_policy_error_value(&error) else {
            anyhow::bail!("{adapter_name}: SSE error envelope ({error_evidence})");
        };
        let finish_reason = termination.finish_reason.clone();
        *termination = ProviderTermination::refused(
            finish_reason,
            if reason == "router_guardrail" {
                RefusalOrigin::RouterGuardrail
            } else {
                RefusalOrigin::PromptFilter
            },
            reason,
            message.clone(),
        )
        .with_native_detail("stream_error_sha256", serde_json::json!(error_evidence));
        return Ok(DecodedSseChunk {
            usage,
            delta: message.unwrap_or_default(),
            authoritative_terminal: true,
        });
    }

    let Some(choice) = choices.into_iter().next() else {
        return Ok(DecodedSseChunk {
            usage,
            delta: String::new(),
            authoritative_terminal: false,
        });
    };
    if observe_openrouter && let Some(error) = choice.error.as_ref() {
        merge_openrouter_error_provider(observed_upstream, error)?;
    }
    let authoritative_terminal = choice.finish_reason.is_some()
        || choice
            .error
            .as_ref()
            .and_then(parse_openai_compatible_policy_error_value)
            .is_some();
    let delta = choice.into_delta(termination);
    Ok(DecodedSseChunk {
        usage,
        delta,
        authoritative_terminal,
    })
}

struct DecodedSseChunk {
    usage: Option<SseUsage>,
    delta: String,
    authoritative_terminal: bool,
}

#[derive(Deserialize)]
struct SseChoice {
    #[serde(default)]
    delta: SseDelta,
    #[serde(default)]
    finish_reason: Option<String>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

impl SseChoice {
    fn into_delta(self, termination: &mut ProviderTermination) -> String {
        let Self {
            delta,
            finish_reason,
            error,
        } = self;
        let SseDelta { content, refusal } = delta;
        let refusal_present = refusal.is_some();
        let refusal_fragment = refusal.filter(|message| !message.is_empty());
        let policy_error = error
            .as_ref()
            .and_then(parse_openai_compatible_policy_error_value);

        if refusal_present {
            match termination.refusal.as_mut() {
                Some(existing)
                    if existing.origin == RefusalOrigin::ProviderMessage
                        && existing.reason == "message.refusal" =>
                {
                    if let Some(fragment) = refusal_fragment.as_ref() {
                        existing
                            .message
                            .get_or_insert_with(String::new)
                            .push_str(fragment);
                    }
                    if finish_reason.is_some() {
                        termination.finish_reason = finish_reason.clone();
                    }
                }
                _ => {
                    *termination = ProviderTermination::refused(
                        finish_reason.clone(),
                        RefusalOrigin::ProviderMessage,
                        "message.refusal",
                        refusal_fragment.clone(),
                    );
                }
            }
        } else if termination.is_refusal() {
            if finish_reason.is_some() {
                termination.finish_reason = finish_reason.clone();
            }
        } else if let Some((reason, message)) = policy_error.as_ref() {
            *termination = ProviderTermination::refused(
                finish_reason.clone(),
                match reason.as_str() {
                    "refusal" => RefusalOrigin::ProviderMessage,
                    "router_guardrail" => RefusalOrigin::RouterGuardrail,
                    _ => RefusalOrigin::CandidateFilter,
                },
                reason.clone(),
                message.clone(),
            );
            if let Some(error) = error {
                let evidence = redacted_response_evidence(
                    b"openai-compatible-sse-choice-error/v1",
                    format_args!("{error}"),
                    false,
                );
                *termination = std::mem::take(termination)
                    .with_native_detail("choice_error_sha256", serde_json::json!(evidence));
            }
        } else if finish_reason.as_deref() == Some("content_filter") {
            *termination = ProviderTermination::refused(
                finish_reason.clone(),
                RefusalOrigin::FinishReason,
                "content_filter",
                None,
            );
        } else if finish_reason.is_some() {
            *termination = ProviderTermination::finished(finish_reason);
        }

        content
            .filter(|text| !text.is_empty())
            .or(refusal_fragment)
            .or_else(|| policy_error.and_then(|(_, message)| message))
            .unwrap_or_default()
    }
}

#[derive(Default, Deserialize)]
struct SseDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
}

#[derive(Deserialize)]
struct SseUsage {
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
    fn profiled_compat_adapters_retain_vendor_identity_and_compat_consent() {
        for (profile, endpoint, expected_name) in [
            (
                OpenAiCompatibleProfile::OpenRouter,
                "https://openrouter.ai/api/v1",
                "openrouter_api",
            ),
            (
                OpenAiCompatibleProfile::DeepSeek,
                "https://api.deepseek.com",
                "deepseek_api",
            ),
            (
                OpenAiCompatibleProfile::MoonshotKimi,
                "https://api.moonshot.ai/v1",
                "moonshot_kimi_api",
            ),
            (
                OpenAiCompatibleProfile::QwenChat,
                "https://workspace.eu-central-1.maas.aliyuncs.com/compatible-mode/v1",
                "qwen_chat_api",
            ),
        ] {
            let adapter = OpenAiAdapter::new_compat_profiled(
                profile,
                endpoint.into(),
                SecretString::from("sk-test"),
                "model".into(),
            )
            .unwrap();
            assert_eq!(adapter.name(), expected_name);
            assert_eq!(adapter.compat_profile, Some(profile));
            assert_eq!(
                adapter.consent_route().unwrap().kind,
                crate::cli::init::ProviderKind::OpenaiCompat
            );
        }
    }

    #[test]
    fn profiled_compat_rejects_endpoint_drift_and_unimplemented_qwen_surfaces() {
        let mismatch = OpenAiAdapter::new_compat_profiled(
            OpenAiCompatibleProfile::OpenRouter,
            "https://openrouter.ai.evil.example/api/v1".into(),
            SecretString::from("sk-test"),
            "model".into(),
        )
        .err()
        .expect("profile mismatch must fail")
        .to_string();
        assert!(mismatch.contains("openrouter"));
        assert!(mismatch.contains("does not match"));

        for profile in [
            OpenAiCompatibleProfile::QwenResponses,
            OpenAiCompatibleProfile::QwenAnthropicCompat,
            OpenAiCompatibleProfile::QwenDashScope,
        ] {
            let error = OpenAiAdapter::new_compat_profiled(
                profile,
                "https://dashscope-us.aliyuncs.com/compatible-mode/v1".into(),
                SecretString::from("sk-test"),
                "qwen3.7-plus".into(),
            )
            .err()
            .expect("unimplemented surface must fail")
            .to_string();
            assert!(error.contains("not implemented"), "{profile:?}: {error}");
        }
    }

    #[test]
    fn custom_openai_endpoint_has_a_distinct_unknown_pricing_identity() {
        let custom = OpenAiAdapter::new_openai(
            "https://gateway.example.test/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        assert_eq!(custom.name(), "openai_api_custom");
        assert!(crate::providers::cost::lookup_price(custom.name(), "gpt-5").is_none());
        let request = serde_json::to_value(custom.chat_request(
            "gpt-5".into(),
            vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }],
            false,
            &Request::default(),
        ))
        .unwrap();
        assert_eq!(request["max_tokens"], 4096);
        assert!(request.get("max_completion_tokens").is_none());
    }

    #[test]
    fn only_the_exact_official_openai_origin_and_v1_path_keep_official_identity() {
        for endpoint in [
            "https://api.openai.com/v1",
            "https://api.openai.com:443/v1/",
        ] {
            let adapter = OpenAiAdapter::new_openai(
                endpoint.into(),
                SecretString::from("sk-test"),
                "gpt-5".into(),
            )
            .unwrap();
            assert_eq!(adapter.name(), "openai_api", "endpoint={endpoint}");
        }

        for endpoint in [
            "http://api.openai.com/v1",
            "https://api.openai.com.evil.example/v1",
            "https://api.openai.com/v1/extra",
            "https://api.openai.com/v1?route=other",
            "https://user@api.openai.com/v1",
        ] {
            let adapter = OpenAiAdapter::new_openai(
                endpoint.into(),
                SecretString::from("sk-test"),
                "gpt-5".into(),
            )
            .unwrap();
            assert_eq!(adapter.name(), "openai_api_custom", "endpoint={endpoint}");
        }
    }

    #[test]
    fn official_openai_wires_typed_subject_for_nonstream_and_stream_only() {
        let home = tempfile::tempdir().unwrap();
        let raw_principal = "raw-alice@example.test";
        let subject =
            crate::security::provider_subject::derive(home.path(), "openai_api", raw_principal)
                .unwrap();
        let official = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1".into(),
            SecretString::from("sk-test"),
            "gpt-5".into(),
        )
        .unwrap();
        let custom = OpenAiAdapter::new_openai(
            "https://gateway.example.test/v1".into(),
            SecretString::from("sk-test"),
            "gpt-5".into(),
        )
        .unwrap();
        let compat = OpenAiAdapter::new_compat(
            "http://127.0.0.1:8080/v1".into(),
            SecretString::from(""),
            "local-model".into(),
        )
        .unwrap();
        let message = || {
            vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }]
        };

        for streaming in [false, true] {
            let official_json = serde_json::to_value(official.chat_request_with_subject(
                "gpt-5".into(),
                message(),
                streaming,
                &Request::default(),
                Some(&subject),
            ))
            .unwrap();
            let identifier = official_json["safety_identifier"].as_str().unwrap();
            assert_eq!(identifier.len(), 64);
            assert!(!identifier.contains(raw_principal));
            assert_eq!(official_json["stream"], streaming);

            for adapter in [&custom, &compat] {
                let body = serde_json::to_value(adapter.chat_request_with_subject(
                    "model".into(),
                    message(),
                    streaming,
                    &Request::default(),
                    Some(&subject),
                ))
                .unwrap();
                assert!(
                    body.get("safety_identifier").is_none(),
                    "{} must not inherit native OpenAI metadata",
                    adapter.name()
                );
            }
        }

        let serialized_request = serde_json::to_string(&Request::default()).unwrap();
        assert!(!serialized_request.contains("safety_identifier"));
        assert!(
            serde_json::from_value::<Request>(serde_json::json!({
                "safety_identifier": "caller-controlled"
            }))
            .is_err(),
            "callers cannot inject native OpenAI wire metadata through Request"
        );
    }

    #[test]
    fn only_the_exact_openrouter_service_origin_enables_router_metadata() {
        for endpoint in [
            "https://openrouter.ai/api/v1",
            "https://openrouter.ai:443/api/v1/",
        ] {
            assert!(is_openrouter_endpoint(endpoint), "endpoint={endpoint}");
            let adapter = OpenAiAdapter::new_compat(
                endpoint.into(),
                SecretString::from("sk-test"),
                "openai/gpt-5".into(),
            )
            .unwrap();
            assert!(adapter.openrouter_metadata, "endpoint={endpoint}");
        }

        for endpoint in [
            "http://openrouter.ai/api/v1",
            "https://openrouter.ai.evil.example/api/v1",
            "https://openrouter.ai/api/v1/extra",
            "https://openrouter.ai/api/v1?route=other",
            "https://user@openrouter.ai/api/v1",
        ] {
            assert!(!is_openrouter_endpoint(endpoint), "endpoint={endpoint}");
        }
    }

    #[test]
    fn native_copilot_and_compat_requests_use_supported_output_cap_fields() {
        let native = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        let copilot = OpenAiAdapter::new_copilot(
            "https://api.githubcopilot.com".to_string(),
            SecretString::from("copilot-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        let compat = OpenAiAdapter::new_compat(
            "http://localhost:8080/v1".to_string(),
            SecretString::from(""),
            "local-llama".to_string(),
        )
        .unwrap();
        let message = || {
            vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }]
        };

        for streaming in [false, true] {
            let native_json = serde_json::to_value(native.chat_request(
                "gpt-5".into(),
                message(),
                streaming,
                &Request::default(),
            ))
            .unwrap();
            assert_eq!(native_json["stream"], streaming);
            assert_eq!(native_json["max_completion_tokens"], 4096);
            assert!(native_json.get("max_tokens").is_none());

            let copilot_json = serde_json::to_value(copilot.chat_request(
                "gpt-5".into(),
                message(),
                streaming,
                &Request::default(),
            ))
            .unwrap();
            assert_eq!(copilot_json["stream"], streaming);
            assert_eq!(copilot_json["max_completion_tokens"], 4096);
            assert!(copilot_json.get("max_tokens").is_none());

            let compat_json = serde_json::to_value(compat.chat_request(
                "local-llama".into(),
                message(),
                streaming,
                &Request::default(),
            ))
            .unwrap();
            assert_eq!(compat_json["stream"], streaming);
            assert_eq!(compat_json["max_tokens"], 4096);
            assert!(compat_json.get("max_completion_tokens").is_none());
        }
    }

    #[test]
    fn request_controls_are_serialized_and_absent_controls_are_omitted() {
        let adapter = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        let message = || {
            vec![ChatMessage {
                role: "user",
                content: "ping".into(),
            }]
        };
        let empty = serde_json::to_value(adapter.chat_request(
            "gpt-5".into(),
            message(),
            false,
            &Request::default(),
        ))
        .unwrap();
        for field in ["temperature", "top_p", "seed", "stop"] {
            assert!(empty.get(field).is_none(), "unexpected {field}: {empty}");
        }

        let controlled = serde_json::to_value(adapter.chat_request(
            "gpt-5".into(),
            message(),
            false,
            &Request {
                temperature: Some(0.4),
                top_p: Some(0.8),
                sampling_seed: Some(42),
                stop_sequences: vec!["END".into()],
                ..Request::default()
            },
        ))
        .unwrap();
        assert_eq!(controlled["temperature"].as_f64(), Some(f64::from(0.4_f32)));
        assert_eq!(controlled["top_p"].as_f64(), Some(f64::from(0.8_f32)));
        assert_eq!(controlled["seed"], 42);
        assert_eq!(controlled["stop"], serde_json::json!(["END"]));
    }

    #[test]
    fn policy_error_parser_covers_kimi_qwen_and_openai_compatible_codes() {
        for (body, expected) in [
            (
                r#"{"error":{"code":"content_filter","message":"blocked"}}"#,
                "content_filter",
            ),
            (
                r#"{"code":"data_inspection_failed","message":"inspection blocked"}"#,
                "data_inspection_failed",
            ),
            (
                r#"{"error":{"type":"content_policy_violation"}}"#,
                "content_policy_violation",
            ),
            (r#"{"error":{"error_type":"refusal"}}"#, "refusal"),
            (
                r#"{"error":{"metadata":{"error_type":"content_policy_violation","provider_name":"Anthropic"}}}"#,
                "content_policy_violation",
            ),
            (
                r#"{
                    "error": {"code": 403, "message": "Request blocked"},
                    "openrouter_metadata": {
                        "pipeline": [{
                            "type": "guardrail",
                            "data": {"action": "blocked"}
                        }]
                    }
                }"#,
                "router_guardrail",
            ),
        ] {
            let (reason, _) =
                parse_openai_compatible_policy_error(body).expect("known policy code");
            assert_eq!(reason, expected);
        }
        assert!(
            parse_openai_compatible_policy_error(
                r#"{"error":{"code":"invalid_api_key","message":"bad key"}}"#
            )
            .is_none()
        );
    }

    #[test]
    fn openrouter_observation_projects_only_provider_and_model_identifiers() {
        let secret = "sk-must-not-survive";
        let prompt = "private prompt must not survive";
        let response = serde_json::json!({
            "model": "anthropic/claude-sonnet-4",
            "provider": "Anthropic",
            "error": {
                "metadata": {
                    "provider_name": "Anthropic",
                    "api_key": secret,
                    "prompt": prompt
                }
            },
            "openrouter_metadata": {
                "prompt": prompt,
                "secret": secret
            }
        });
        let mut observed = None;
        merge_openrouter_observed_value(&mut observed, &response).unwrap();

        let encoded = serde_json::to_string(&observed).unwrap();
        assert_eq!(
            observed,
            Some(ObservedUpstreamEvidence {
                provider: Some("Anthropic".into()),
                model: Some("anthropic/claude-sonnet-4".into()),
            })
        );
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains(prompt));
    }

    #[test]
    fn official_openai_uses_developer_role_but_compat_keeps_system_role() {
        let official = OpenAiAdapter::new_openai(
            "https://api.openai.com/v1".to_string(),
            SecretString::from("sk-test"),
            "gpt-5".to_string(),
        )
        .unwrap();
        let compat = OpenAiAdapter::new_compat(
            "https://openrouter.ai/api/v1".to_string(),
            SecretString::from("sk-test"),
            "openai/gpt-5".to_string(),
        )
        .unwrap();

        assert_eq!(official.instruction_role(), "developer");
        assert_eq!(compat.instruction_role(), "system");
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
    // is on the operator to run + post results — flagged in PROGRESS.md.

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_adapter_against(server_uri: &str) -> OpenAiAdapter {
        OpenAiAdapter::build(
            server_uri.to_string(),
            SecretString::from("sk-test-mock-key"),
            "gpt-4o-mock".to_string(),
            "openai_api",
            None,
        )
        .expect("adapter constructs against mock URI")
    }

    fn build_compat_adapter_against(server_uri: &str) -> OpenAiAdapter {
        OpenAiAdapter::new_compat(
            server_uri.to_string(),
            SecretString::from("compat-test-key"),
            "local-llama".to_string(),
        )
        .expect("compat adapter constructs against mock URI")
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
        assert_eq!(
            completion.termination.finish_reason.as_deref(),
            Some("stop")
        );
        assert!(!completion.termination.is_refusal());
    }

    #[tokio::test]
    async fn mock_200_message_refusal_is_retained_as_typed_termination() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "gpt-4o-mock",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "refusal": "I cannot help with that request."
                    },
                    "finish_reason": "stop"
                }],
                "usage": { "prompt_tokens": 5, "completion_tokens": 8 }
            })))
            .mount(&mock)
            .await;

        let completion = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("native refusal is a valid 200 completion envelope");
        let refusal = completion
            .termination
            .refusal
            .expect("message.refusal must be retained");
        assert_eq!(refusal.origin, RefusalOrigin::ProviderMessage);
        assert_eq!(refusal.reason, "message.refusal");
        assert_eq!(
            refusal.message.as_deref(),
            Some("I cannot help with that request.")
        );
        assert_eq!(completion.text, "I cannot help with that request.");
    }

    #[tokio::test]
    async fn mock_200_content_part_refusal_is_retained_as_typed_termination() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "gpt-4o-mock",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": [{
                            "type": "refusal",
                            "refusal": "I cannot help with that request."
                        }]
                    },
                    "finish_reason": "stop"
                }]
            })))
            .mount(&mock)
            .await;

        let completion = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("content-part refusal is a valid 200 completion envelope");
        let refusal = completion
            .termination
            .refusal
            .expect("content.refusal must be retained");
        assert_eq!(refusal.origin, RefusalOrigin::ProviderMessage);
        assert_eq!(refusal.reason, "content.refusal");
        assert_eq!(
            refusal.message.as_deref(),
            Some("I cannot help with that request.")
        );
        assert_eq!(completion.text, "I cannot help with that request.");
    }

    #[tokio::test]
    async fn mock_200_content_filter_without_text_is_retained() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "gpt-4o-mock",
                "choices": [{
                    "index": 0,
                    "message": { "role": "assistant", "content": null },
                    "finish_reason": "content_filter"
                }]
            })))
            .mount(&mock)
            .await;

        let completion = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("content_filter is a typed provider outcome");
        assert!(completion.text.is_empty());
        assert_eq!(
            completion.termination.finish_reason.as_deref(),
            Some("content_filter")
        );
        let refusal = completion
            .termination
            .refusal
            .expect("content_filter must be retained");
        assert_eq!(refusal.origin, RefusalOrigin::FinishReason);
        assert_eq!(refusal.reason, "content_filter");
    }

    #[tokio::test]
    async fn mock_openrouter_embedded_policy_error_retains_partial_output_and_native_reason() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("x-openrouter-metadata", "enabled"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "openai/gpt-5",
                "provider": "OpenAI",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "partial output"
                    },
                    "finish_reason": "error",
                    "error": {
                        "code": 400,
                        "message": "Output blocked by provider policy",
                        "metadata": {
                            "error_type": "content_policy_violation",
                            "provider_code": "content_filter",
                            "provider_name": "OpenAI"
                        }
                    }
                }]
            })))
            .mount(&mock)
            .await;

        let mut adapter = build_compat_adapter_against(&mock.uri());
        adapter.openrouter_metadata = true;
        let completion = adapter
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("embedded OpenRouter policy error is a typed completion");
        assert_eq!(completion.text, "partial output");
        assert_eq!(completion.identity.provider, "openai_compat");
        assert_eq!(completion.identity.wire_model, "local-llama");
        assert_eq!(completion.model, "local-llama");
        assert_eq!(
            completion.termination.finish_reason.as_deref(),
            Some("error")
        );
        assert_eq!(
            completion.termination.observed_upstream.as_ref(),
            Some(&ObservedUpstreamEvidence {
                provider: Some("OpenAI".into()),
                model: Some("openai/gpt-5".into()),
            })
        );
        let refusal = completion
            .termination
            .refusal
            .expect("embedded policy error must be retained");
        assert_eq!(refusal.origin, RefusalOrigin::CandidateFilter);
        assert_eq!(refusal.reason, "content_policy_violation");
        assert_eq!(
            refusal.message.as_deref(),
            Some("The provider blocked this request under its content policy.")
        );
        assert!(
            completion
                .termination
                .native_details
                .contains_key("choice_error_sha256")
        );
    }

    #[tokio::test]
    async fn mock_openrouter_guardrail_403_is_attributed_to_router() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("x-openrouter-metadata", "enabled"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": {
                    "code": 403,
                    "message": "Request blocked: prompt injection patterns detected",
                    "metadata": {
                        "patterns": ["ignore all previous instructions"]
                    }
                },
                "openrouter_metadata": {
                    "requested": "openai/gpt-5",
                    "pipeline": [{
                        "type": "guardrail",
                        "name": "regex_pi_detection",
                        "data": {
                            "action": "blocked",
                            "detected": true
                        }
                    }]
                }
            })))
            .mount(&mock)
            .await;

        let mut adapter = build_compat_adapter_against(&mock.uri());
        adapter.openrouter_metadata = true;
        let completion = adapter
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("router guardrail is a typed provider outcome");
        let refusal = completion
            .termination
            .refusal
            .expect("router guardrail must be retained");
        assert_eq!(refusal.origin, RefusalOrigin::RouterGuardrail);
        assert_eq!(refusal.reason, "router_guardrail");
        assert_eq!(
            refusal.message.as_deref(),
            Some("The configured router guardrail blocked this request.")
        );
    }

    #[tokio::test]
    async fn mock_compat_policy_error_envelope_becomes_typed_refusal_completion() {
        let secret = "sk-never-persist-http-policy-error";
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {
                    "code": "data_inspection_failed",
                    "message": "request blocked by provider inspection",
                    "debug_echo": secret
                }
            })))
            .mount(&mock)
            .await;

        let completion = build_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("documented compatible policy code is a typed outcome");
        let refusal = completion
            .termination
            .refusal
            .as_ref()
            .expect("policy error must be retained");
        assert_eq!(refusal.origin, RefusalOrigin::PromptFilter);
        assert_eq!(refusal.reason, "data_inspection_failed");
        assert_eq!(
            refusal.message.as_deref(),
            Some("The provider blocked this request during data inspection.")
        );
        let persisted =
            serde_json::to_string(&completion.termination).expect("serialize termination");
        assert!(!persisted.contains(secret));
        assert!(!persisted.contains("debug_echo"));
        assert!(!persisted.contains("request blocked by provider inspection"));
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
        // QuotaError carries Retry-After plus redacted body evidence.
        let quota = err
            .downcast_ref::<QuotaError>()
            .expect("downcast to QuotaError");
        assert_eq!(quota.provider, "openai_api");
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(12)));
        assert!(quota.body.starts_with("body_sha256="));
        assert!(quota.body.ends_with(" truncated=false"));
        assert!(!quota.body.contains("rate_limit_exceeded"));
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
        assert!(!msg.contains("Incorrect API key provided"));
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
        assert!(msg.contains("body_sha256="));
        assert!(!msg.contains("backend timeout"));
    }

    #[tokio::test]
    async fn mock_stream_429_preserves_retry_after_without_raw_body() {
        let secret = "sk-never-persist-stream-quota-body";
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "17")
                    .set_body_raw(
                        format!(r#"{{"error":{{"message":"{secret}"}}}}"#),
                        "application/json",
                    ),
            )
            .mount(&mock)
            .await;

        let error = match build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
        {
            Ok(_) => panic!("streaming 429 must fail before yielding chunks"),
            Err(error) => error,
        };
        let quota = error
            .downcast_ref::<QuotaError>()
            .expect("streaming 429 remains a typed QuotaError");
        assert_eq!(quota.retry_after, Some(std::time::Duration::from_secs(17)));
        assert!(quota.body.starts_with("body_sha256="));
        assert!(quota.body.ends_with(" truncated=false"));
        assert!(!quota.body.contains(secret));
    }

    #[tokio::test]
    async fn mock_stream_500_caps_and_redacts_oversized_body() {
        let secret = "sk-never-persist-stream-http-body";
        let body = format!("{secret}{}", "x".repeat(MAX_PROVIDER_ERROR_BODY_BYTES * 2));
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(500).set_body_raw(body, "text/plain"))
            .mount(&mock)
            .await;

        let error = match build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
        {
            Ok(_) => panic!("streaming 500 must fail before yielding chunks"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("HTTP 500"));
        assert!(message.contains("body_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains(secret));
        assert!(!message.contains(&"x".repeat(128)));
    }

    #[tokio::test]
    async fn custom_endpoint_does_not_follow_cross_origin_redirects() {
        let redirect_target = MockServer::start().await;
        let source = MockServer::start().await;
        let location = format!("{}/capture", redirect_target.uri());
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", location))
            .mount(&source)
            .await;

        let adapter =
            OpenAiAdapter::new_openai(source.uri(), SecretString::from("sk-test"), "gpt-5".into())
                .unwrap();
        let error = adapter
            .complete(Request {
                prompt: "must stay on source origin".into(),
                ..Default::default()
            })
            .await
            .expect_err("307 must surface instead of being followed");
        assert!(error.to_string().contains("307"));
        assert!(
            redirect_target
                .received_requests()
                .await
                .expect("request recording enabled")
                .is_empty(),
            "the redirected origin must receive no request"
        );
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
        // additionally asserts the JSON body shape (developer + user
        // messages in `messages[]`, model from override, stream=false).
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "gpt-5.5-override",
                "messages": [
                    { "role": "developer", "content": "you are NEOTH" },
                    { "role": "user", "content": "ping" }
                ],
                "stream": false,
                "max_completion_tokens": 4096,
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

    #[tokio::test]
    async fn mock_compat_complete_uses_only_legacy_max_tokens() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "local-llama",
                "messages": [{ "role": "user", "content": "ping" }],
                "stream": false,
                "max_tokens": 4096,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{
                    "message": { "role": "assistant", "content": "pong" }
                }]
            })))
            .mount(&mock)
            .await;

        let completion = build_compat_adapter_against(&mock.uri())
            .complete(Request {
                prompt: "ping".into(),
                ..Default::default()
            })
            .await
            .expect("compat complete body must use max_tokens");
        assert_eq!(completion.text, "pong");
    }

    // ── SSE streaming tests ────────────────────────────────────────────

    /// Proves the SSE stream() override accepts both legal `data:` forms:
    /// with and without the optional space after the colon.
    #[tokio::test]
    async fn mock_sse_stream_delivers_progressive_chunks() {
        use futures_util::StreamExt;

        let sse_body = concat!(
            "data:{\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}\n\n",
            "data: [DONE]\n\n",
        );

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer sk-test-mock-key"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "say hi".into(),
            ..Default::default()
        };

        let mut stream = adapter.stream(req).await.expect("stream must start");
        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.expect("chunk must be Ok"));
        }

        // Must have received at least 2 content chunks + 1 done chunk.
        assert!(
            chunks.len() >= 3,
            "expected ≥3 chunks (2 content + 1 done), got {}",
            chunks.len()
        );

        // Last chunk must be done.
        let last = chunks.last().unwrap();
        assert!(last.done, "last chunk must have done=true");

        // Content chunks must NOT have done=true.
        let content_chunks: Vec<_> = chunks.iter().filter(|c| !c.done).collect();
        assert!(
            !content_chunks.is_empty(),
            "must have at least one non-done content chunk"
        );

        // Accumulated text must equal "Hello world".
        let accumulated: String = content_chunks.iter().map(|c| c.delta.as_str()).collect();
        assert_eq!(accumulated, "Hello world");
    }

    #[tokio::test]
    async fn mock_openrouter_sse_retains_observed_upstream_on_terminal_chunk_only() {
        use futures_util::StreamExt;

        let sse_body = concat!(
            "data: {\"model\":\"anthropic/claude-sonnet-4\",\"provider\":\"Anthropic\",",
            "\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"model\":\"anthropic/claude-sonnet-4\",\"choices\":[{\"delta\":{},",
            "\"finish_reason\":\"stop\",\"error\":{\"metadata\":{\"provider_name\":\"Anthropic\"}}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("x-openrouter-metadata", "enabled"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let mut adapter = build_compat_adapter_against(&mock.uri());
        adapter.openrouter_metadata = true;
        let mut stream = adapter
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("OpenRouter SSE stream starts");

        let content = stream
            .next()
            .await
            .expect("content chunk")
            .expect("content chunk succeeds");
        assert_eq!(content.delta, "hello");
        assert!(!content.done);
        assert_eq!(content.identity.provider, "openai_compat");
        assert_eq!(content.identity.wire_model, "local-llama");
        assert!(content.termination.observed_upstream.is_none());

        let terminal = stream
            .next()
            .await
            .expect("terminal chunk")
            .expect("terminal chunk succeeds");
        assert!(terminal.done);
        assert_eq!(terminal.identity.provider, "openai_compat");
        assert_eq!(terminal.identity.wire_model, "local-llama");
        assert_eq!(
            terminal.termination.observed_upstream,
            Some(ObservedUpstreamEvidence {
                provider: Some("Anthropic".into()),
                model: Some("anthropic/claude-sonnet-4".into()),
            })
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn mock_openrouter_sse_conflicting_observed_provider_fails_explicitly() {
        use futures_util::StreamExt;

        let sse_body = concat!(
            "data: {\"model\":\"anthropic/claude-sonnet-4\",\"provider\":\"Anthropic\",",
            "\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n",
            "data: {\"model\":\"anthropic/claude-sonnet-4\",\"provider\":\"OpenAI\",",
            "\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let mut adapter = build_compat_adapter_against(&mock.uri());
        adapter.openrouter_metadata = true;
        let mut stream = adapter
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("OpenRouter SSE stream starts");

        let partial = stream
            .next()
            .await
            .expect("partial chunk")
            .expect("partial chunk succeeds");
        assert_eq!(partial.delta, "partial");

        let error = stream
            .next()
            .await
            .expect("conflict error")
            .expect_err("conflicting observations must fail");
        assert!(
            error
                .to_string()
                .contains("conflicting observed upstream provider values")
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn mock_sse_eof_after_partial_delta_returns_stream_error() {
        use futures_util::StreamExt;

        let sse_body = "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n";
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let mut stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("truncated SSE stream starts");
        let partial = stream
            .next()
            .await
            .expect("partial content chunk")
            .expect("partial content succeeds");
        assert_eq!(partial.delta, "partial");
        assert!(!partial.done);

        let error = stream
            .next()
            .await
            .expect("EOF error follows partial content")
            .expect_err("EOF without a terminal signal must fail");
        let message = error.to_string();
        assert!(
            message.contains("authoritative terminal signal"),
            "{message}"
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn mock_sse_eof_after_newline_less_finish_reason_completes() {
        use futures_util::StreamExt;

        let sse_body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"complete\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}"
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let mut stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("SSE stream starts");
        let content = stream
            .next()
            .await
            .expect("content chunk")
            .expect("content succeeds");
        assert_eq!(content.delta, "complete");
        assert!(!content.done);

        let final_chunk = stream
            .next()
            .await
            .expect("terminal chunk")
            .expect("terminal chunk succeeds");
        assert!(final_chunk.done);
        assert_eq!(
            final_chunk.termination.finish_reason.as_deref(),
            Some("stop")
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn mock_stream_policy_handshake_returns_final_typed_refusal() {
        use futures_util::StreamExt;

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {
                    "code": "content_filter",
                    "message": "Prompt blocked."
                }
            })))
            .mount(&mock)
            .await;

        let mut stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("policy handshake is a typed stream outcome");
        let chunk = stream
            .next()
            .await
            .expect("policy handshake yields a final chunk")
            .expect("policy handshake chunk succeeds");

        assert!(chunk.done);
        assert_eq!(
            chunk.delta,
            "The provider blocked this request under its content policy."
        );
        let refusal = chunk
            .termination
            .refusal
            .expect("policy handshake retains refusal");
        assert_eq!(refusal.origin, RefusalOrigin::PromptFilter);
        assert_eq!(refusal.reason, "content_filter");
        assert_eq!(
            refusal.message.as_deref(),
            Some("The provider blocked this request under its content policy.")
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn mock_sse_stream_retains_native_refusal_on_final_chunk() {
        use futures_util::StreamExt;

        let sse_body = concat!(
            "data: {\"choices\":[{\"delta\":{\"refusal\":\"I cannot help \"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"refusal\":\"with that request.\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let mut stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("native-refusal stream starts");
        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.expect("native-refusal chunk succeeds"));
        }

        let visible: String = chunks
            .iter()
            .filter(|chunk| !chunk.done)
            .map(|chunk| chunk.delta.as_str())
            .collect();
        assert_eq!(visible, "I cannot help with that request.");
        let termination = &chunks.last().expect("final chunk").termination;
        assert_eq!(termination.finish_reason.as_deref(), Some("stop"));
        let refusal = termination
            .refusal
            .as_ref()
            .expect("final chunk retains native refusal");
        assert_eq!(refusal.origin, RefusalOrigin::ProviderMessage);
        assert_eq!(refusal.reason, "message.refusal");
        assert_eq!(
            refusal.message.as_deref(),
            Some("I cannot help with that request.")
        );
    }

    #[tokio::test]
    async fn mock_sse_blank_native_refusal_is_authoritative() {
        use futures_util::StreamExt;

        let sse_body = concat!(
            "data: {\"choices\":[{\"delta\":{\"refusal\":\"\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let mut stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("blank native-refusal stream starts");
        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.expect("blank native-refusal chunk succeeds"));
        }

        assert_eq!(chunks.len(), 1, "blank refusal emits only the terminator");
        let termination = &chunks[0].termination;
        assert_eq!(termination.finish_reason.as_deref(), Some("stop"));
        let refusal = termination
            .refusal
            .as_ref()
            .expect("blank refusal field remains authoritative");
        assert_eq!(refusal.origin, RefusalOrigin::ProviderMessage);
        assert_eq!(refusal.reason, "message.refusal");
        assert_eq!(refusal.message, None);
    }

    #[tokio::test]
    async fn mock_sse_top_level_policy_error_becomes_typed_refusal() {
        use futures_util::StreamExt;

        let secret = "sk-never-persist-top-level-sse-error";
        let sse_body = concat!(
            "data: {\"error\":{\"code\":\"content_filter\",\"message\":\"Prompt blocked.\",\"debug_echo\":\"sk-never-persist-top-level-sse-error\"}}\n\n",
            "data: [DONE]\n\n",
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let mut stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("policy-error SSE stream starts");
        let first = stream
            .next()
            .await
            .expect("policy message chunk")
            .expect("policy message succeeds");
        assert!(!first.done);
        assert_eq!(
            first.delta,
            "The provider blocked this request under its content policy."
        );
        let persisted_chunk =
            serde_json::to_string(&crate::recovery::turn_journal::TurnEvent::ProviderChunk {
                ts_unix: 1,
                text: first.delta.clone(),
            })
            .expect("serialize provider chunk journal event");
        assert!(!persisted_chunk.contains(secret));
        assert!(!persisted_chunk.contains("debug_echo"));
        assert!(!persisted_chunk.contains("Prompt blocked."));
        let final_chunk = stream
            .next()
            .await
            .expect("policy terminator")
            .expect("policy terminator succeeds");
        assert!(final_chunk.done);
        let refusal = final_chunk
            .termination
            .refusal
            .as_ref()
            .expect("top-level policy error remains typed");
        assert_eq!(refusal.origin, RefusalOrigin::PromptFilter);
        assert_eq!(refusal.reason, "content_filter");
        assert_eq!(
            refusal.message.as_deref(),
            Some("The provider blocked this request under its content policy.")
        );
        assert!(
            final_chunk
                .termination
                .native_details
                .contains_key("stream_error_sha256")
        );
        let persisted =
            serde_json::to_string(&final_chunk.termination).expect("serialize termination");
        assert!(!persisted.contains(secret));
        assert!(!persisted.contains("debug_echo"));
        assert!(!persisted.contains("Prompt blocked."));
        let persisted_response = serde_json::to_string(
            &crate::recovery::turn_journal::TurnEvent::ProviderResponse {
                ts_unix: 2,
                provider: "openai_compat".into(),
                model: "local-llama".into(),
                termination: final_chunk.termination.clone(),
                latency_ms: 0,
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            },
        )
        .expect("serialize provider response journal event");
        assert!(!persisted_response.contains(secret));
        assert!(!persisted_response.contains("debug_echo"));
        assert!(!persisted_response.contains("Prompt blocked."));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn mock_sse_top_level_non_policy_error_fails_after_partial_content() {
        use futures_util::StreamExt;

        let sse_body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n",
            "data: {\"error\":{\"code\":\"server_error\",\"message\":\"upstream crashed\"}}\n\n",
        );
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let mut stream = build_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "fixture".into(),
                ..Default::default()
            })
            .await
            .expect("non-policy error stream starts");
        let partial = stream
            .next()
            .await
            .expect("partial content chunk")
            .expect("partial content succeeds");
        assert_eq!(partial.delta, "partial");
        assert!(!partial.done);

        let error = stream
            .next()
            .await
            .expect("error item follows partial content")
            .expect_err("non-policy SSE error must not become empty success");
        let message = error.to_string();
        assert!(message.contains("SSE error envelope"), "{message}");
        assert!(message.contains("body_sha256="), "{message}");
        assert!(!message.contains("server_error"), "{message}");
        assert!(!message.contains("upstream crashed"), "{message}");
    }

    #[test]
    fn sse_choice_parses_finish_filter_and_embedded_policy_error() {
        let secret = "sk-never-persist-choice-error";
        let finish_filter: SseChoice = serde_json::from_value(serde_json::json!({
            "delta": {},
            "finish_reason": "content_filter"
        }))
        .expect("content-filter choice");
        let mut termination = ProviderTermination::default();
        assert!(finish_filter.into_delta(&mut termination).is_empty());
        let refusal = termination.refusal.expect("finish filter retained");
        assert_eq!(refusal.origin, RefusalOrigin::FinishReason);
        assert_eq!(refusal.reason, "content_filter");

        let embedded_error: SseChoice = serde_json::from_value(serde_json::json!({
            "delta": {},
            "finish_reason": null,
            "error": {
                "code": "content_policy_violation",
                "message": "Candidate blocked.",
                "debug_echo": secret
            }
        }))
        .expect("embedded policy error choice");
        let mut termination = ProviderTermination::default();
        assert_eq!(
            embedded_error.into_delta(&mut termination),
            "The provider blocked this request under its content policy."
        );
        let refusal = termination
            .refusal
            .as_ref()
            .expect("embedded policy error retained");
        assert_eq!(refusal.origin, RefusalOrigin::CandidateFilter);
        assert_eq!(refusal.reason, "content_policy_violation");
        assert_eq!(
            refusal.message.as_deref(),
            Some("The provider blocked this request under its content policy.")
        );
        assert!(
            termination
                .native_details
                .contains_key("choice_error_sha256")
        );
        let persisted = serde_json::to_string(&termination).expect("serialize termination");
        assert!(!persisted.contains(secret));
        assert!(!persisted.contains("debug_echo"));
        assert!(!persisted.contains("Candidate blocked."));
    }

    /// Proves that stream:true and the official developer instruction role are
    /// sent on the same wire path.
    #[tokio::test]
    async fn mock_official_sse_stream_uses_developer_role_and_stream_true() {
        use futures_util::StreamExt;

        let sse_body = "data: [DONE]\n\n";

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "gpt-4o-mock",
                "messages": [
                    {"role": "developer", "content": "trusted instruction"},
                    {"role": "user", "content": "ping"}
                ],
                "stream": true,
                "max_completion_tokens": 4096,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_raw(sse_body, "text/event-stream"))
            .mount(&mock)
            .await;

        let adapter = build_adapter_against(&mock.uri());
        let req = Request {
            prompt: "ping".into(),
            system: Some("trusted instruction".into()),
            ..Default::default()
        };

        let mut stream = adapter.stream(req).await.expect("stream must start");
        // Drain — we only care that the mock matched (body_json assertion verifies stream:true).
        while stream.next().await.is_some() {}
    }

    #[tokio::test]
    async fn mock_compat_stream_uses_only_legacy_max_tokens() {
        use futures_util::StreamExt;

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "model": "local-llama",
                "messages": [{ "role": "user", "content": "ping" }],
                "stream": true,
                "max_tokens": 4096,
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw("data: [DONE]\n\n", "text/event-stream"),
            )
            .mount(&mock)
            .await;

        let mut stream = build_compat_adapter_against(&mock.uri())
            .stream(Request {
                prompt: "ping".into(),
                ..Default::default()
            })
            .await
            .expect("compat stream body must use max_tokens");
        while stream.next().await.is_some() {}
    }
}
