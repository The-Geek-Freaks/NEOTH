//! AWS Bedrock Runtime adapter (C-3 Phase 2, Session 14).
//!
//! Talks to `bedrock-runtime.<region>.amazonaws.com` via the modern
//! **Converse** API. The Converse shape is provider-agnostic — the
//! same request envelope works for Anthropic Claude, Amazon Titan,
//! Meta Llama, Mistral, etc. — so NEOTH ships one adapter rather
//! than per-family JSON dispatchers (as was the alternative considered
//! during the Session-14 4-agent design review).
//!
//! Wire shape (subset NEOTH consumes):
//!
//! ```text
//! POST /model/{modelId}/converse
//! Host:                  bedrock-runtime.<region>.amazonaws.com
//! Content-Type:          application/json
//! Authorization:         AWS4-HMAC-SHA256 …  (hand-rolled SigV4)
//! X-Amz-Date:            YYYYMMDDTHHmmssZ
//! X-Amz-Content-Sha256:  hex(SHA256(body))
//! X-Amz-Security-Token:  <when temporary credentials>
//!
//! Body: { messages: [...], system: [...], inferenceConfig: {...} }
//! ```
//!
//! Streaming via the binary event-stream framing is intentionally
//! out-of-scope for Phase 2 — Bedrock uses
//! `application/vnd.amazon.eventstream`, which needs a CRC-validated
//! frame parser. Phase 3 work. Today `stream()` falls through to the
//! Provider-trait default impl that wraps the full completion in one
//! `done` chunk.

use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::aws_credentials::{AwsCredentials, ResolvedCredentials, env_var_getter, resolve_chain};
use super::aws_sigv4::sign;
use super::quota::{QuotaError, parse_retry_after};
use super::{Completion, Provider, ProviderDispatchPermit, ProviderRequestControls, Request};

/// AWS service name used in the SigV4 credential scope. **Not**
/// `bedrock-runtime` — the runtime data plane signs under `bedrock`.
const SERVICE_NAME: &str = "bedrock";
pub(crate) const DEFAULT_REGION: &str = "us-east-1";
pub(crate) const DEFAULT_ENDPOINT_ORIGIN: &str = "https://bedrock-runtime.us-east-1.amazonaws.com";

/// Adapter for Bedrock Runtime.
pub struct AwsBedrockAdapter {
    region: String,
    credentials: AwsCredentials,
    default_model: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for AwsBedrockAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsBedrockAdapter")
            .field("region", &self.region)
            .field("credentials", &self.credentials)
            .field("default_model", &self.default_model)
            .finish_non_exhaustive()
    }
}

impl AwsBedrockAdapter {
    /// Construct an adapter against a specific region + model. Caller
    /// passes already-resolved [`AwsCredentials`] — typically from
    /// [`resolve_credentials_for_adapter`]. The HTTP client honours
    /// `NEOTH_HTTP_PROXY` via the shared `http_client::build_client`.
    pub fn new(
        region: impl Into<String>,
        credentials: AwsCredentials,
        default_model: impl Into<String>,
    ) -> Result<Self> {
        let region = region.into();
        let region = canonical_region(&region)?;
        let default_model = default_model.into();
        if default_model.is_empty() {
            anyhow::bail!(
                "aws_bedrock: empty model — set `provider_model: anthropic.claude-3-5-sonnet-20241022-v2:0` \
                 (or another Bedrock model id) in freedom.yaml"
            );
        }
        let http = super::http_client::build_client_no_redirect()?;
        Ok(Self {
            region,
            credentials,
            default_model,
            http,
        })
    }

    /// Resolve credentials via the closed-enum chain in [`super::aws_credentials`].
    /// Production entry point; test code can construct an adapter directly
    /// with hand-built `AwsCredentials` via [`AwsBedrockAdapter::new`].
    pub fn resolve_credentials_via_chain() -> Result<ResolvedCredentials> {
        resolve_chain(None, &env_var_getter, None)
    }

    fn endpoint_host(&self) -> String {
        format!("bedrock-runtime.{}.amazonaws.com", self.region)
    }

    fn endpoint_url(&self, model: &str) -> String {
        // Foundation-model ids contain `:` (e.g.
        // `anthropic.claude-3-5-sonnet-20241022-v2:0`). reqwest::Url
        // accepts the colon in path segments without further encoding,
        // and AWS canonicalises it the same way. For full ARN model ids
        // (containing `/`), operators must use the inference-profile
        // form Bedrock expects — that path normalises through Url::parse
        // identically on both sign + send.
        format!(
            "https://{host}/model/{model}/converse",
            host = self.endpoint_host(),
        )
    }
}

/// Resolve the exact region the runtime will put on the wire.
///
/// A configured value wins even when it is invalid; validation then fails
/// closed instead of silently falling through to an environment variable.
/// This mirrors the synthetic-config precedence used by hemisphere and
/// fallback slots (`slot.region` is copied into `provider_region` first).
pub(crate) fn effective_region(configured: Option<&str>) -> Result<String> {
    let env_region = std::env::var("AWS_REGION").ok();
    let env_default_region = std::env::var("AWS_DEFAULT_REGION").ok();
    effective_region_from_candidates(
        configured,
        env_region.as_deref(),
        env_default_region.as_deref(),
    )
}

pub(crate) fn effective_region_from_candidates(
    configured: Option<&str>,
    env_region: Option<&str>,
    env_default_region: Option<&str>,
) -> Result<String> {
    canonical_region(
        configured
            .or(env_region)
            .or(env_default_region)
            .unwrap_or(DEFAULT_REGION),
    )
}

pub(crate) fn endpoint_origin_for_region(region: &str) -> Result<String> {
    let region = canonical_region(region)?;
    Ok(format!("https://bedrock-runtime.{region}.amazonaws.com"))
}

pub(crate) fn effective_endpoint_origin(configured_region: Option<&str>) -> Result<String> {
    endpoint_origin_for_region(&effective_region(configured_region)?)
}

/// Accept only the AWS Bedrock Runtime hostname shape and return its canonical
/// HTTPS origin. Raw input is deliberately absent from every error because a
/// malformed config value can contain credential material.
pub(crate) fn canonical_endpoint_origin(endpoint: &str) -> Result<String> {
    let url = url::Url::parse(endpoint)
        .map_err(|_| anyhow::anyhow!("aws_bedrock: invalid Bedrock Runtime endpoint"))?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        anyhow::bail!("aws_bedrock: invalid Bedrock Runtime endpoint");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("aws_bedrock: invalid Bedrock Runtime endpoint"))?;
    let region = host
        .strip_prefix("bedrock-runtime.")
        .and_then(|value| value.strip_suffix(".amazonaws.com"))
        .ok_or_else(|| anyhow::anyhow!("aws_bedrock: invalid Bedrock Runtime endpoint"))?;
    let canonical = endpoint_origin_for_region(region)?;
    if url.origin().ascii_serialization() != canonical
        || (endpoint != canonical && endpoint != format!("{canonical}/"))
    {
        anyhow::bail!("aws_bedrock: non-canonical Bedrock Runtime endpoint");
    }
    Ok(canonical)
}

#[async_trait]
impl Provider for AwsBedrockAdapter {
    fn name(&self) -> &'static str {
        "aws_bedrock"
    }

    fn request_controls(&self) -> ProviderRequestControls {
        ProviderRequestControls::SAMPLING_WITHOUT_SEED
    }

    fn default_model(&self) -> Option<&str> {
        Some(&self.default_model)
    }

    fn consent_route(&self) -> Option<crate::consent::ConsentRoute> {
        Some(crate::consent::ConsentRoute::new(
            crate::cli::init::ProviderKind::AwsBedrock,
            Some(&format!("https://{}", self.endpoint_host())),
        ))
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
        crate::providers::circuit_breaker::run_with_breaker("aws_bedrock", async {
            let started = Instant::now();
            let model = req
                .model
                .clone()
                .unwrap_or_else(|| self.default_model.clone());

            let body = build_converse_body(&req);
            let body_bytes =
                serde_json::to_vec(&body).context("serialise Bedrock Converse body")?;

            let url_str = self.endpoint_url(&model);
            let parsed_url =
                reqwest::Url::parse(&url_str).with_context(|| format!("parse URL {url_str}"))?;
            let host = parsed_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Bedrock URL has no host: {url_str}"))?
                .to_string();
            let path = parsed_url.path().to_string();
            let query = parsed_url.query().unwrap_or("").to_string();

            let signed = sign(
                "POST",
                &host,
                &path,
                &query,
                &body_bytes,
                &self.region,
                SERVICE_NAME,
                &self.credentials,
                crate::time::utc_now(),
            );

            let response = self
                .http
                .post(parsed_url.clone())
                .header("content-type", "application/json")
                .header("host", &host)
                .header("authorization", signed.authorization.clone())
                .header("x-amz-date", &signed.x_amz_date)
                .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
                .pipe_if(signed.x_amz_security_token.as_ref(), |req, token| {
                    req.header("x-amz-security-token", token)
                })
                .body(body_bytes)
                .send()
                .await
                .with_context(|| format!("POST {url_str}"))?;

            let status = response.status();
            if !status.is_success() {
                // 429 lands as ThrottlingException — feed the per-provider
                // quota tracker like every other adapter.
                if status.as_u16() == 429 {
                    let retry_after = parse_retry_after(response.headers());
                    let body_text = response.text().await.unwrap_or_default();
                    return Err(anyhow::Error::new(QuotaError {
                        provider: "aws_bedrock",
                        retry_after,
                        body: body_text.trim().to_string(),
                    }));
                }
                let body_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable body>".into());
                return Err(map_bedrock_error(status, &body_text, &self.region));
            }

            let parsed: ConverseResponse = response
                .json()
                .await
                .with_context(|| "parse aws_bedrock Converse response JSON".to_string())?;

            let text = parsed
                .output
                .and_then(|o| o.message)
                .and_then(|m| m.content.into_iter().next())
                .map(|c| c.text)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "aws_bedrock returned 200 OK but the response has no \
                     output.message.content[].text — likely a content-filter \
                     refusal or guardrail block. Inspect the raw HTTP body via \
                     NEOTH_LOG_LEVEL=debug."
                    )
                })?;

            let latency = started.elapsed();
            debug!(
                adapter = "aws_bedrock",
                model = %model,
                region = %self.region,
                response_bytes = text.len(),
                latency_ms = latency.as_millis(),
                "bedrock converse completion"
            );

            Ok(Completion {
                text,
                identity: Default::default(),
                model,
                latency,
                input_tokens: parsed.usage.as_ref().map(|u| u.input_tokens),
                output_tokens: parsed.usage.as_ref().map(|u| u.output_tokens),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        })
        .await
    }
}

/// Map a non-success Bedrock response into a tighter, actionable
/// error message rather than the raw JSON. Surfaces region + status
/// hints that the operator can act on.
fn map_bedrock_error(status: reqwest::StatusCode, body: &str, region: &str) -> anyhow::Error {
    let trimmed = body.trim();
    let lower = trimmed.to_ascii_lowercase();
    let code = status.as_u16();

    // Bedrock returns `__type` or `message` fields in the body for most
    // errors. We inspect for the common operator-actionable codes
    // before falling through to the raw envelope.
    // Order matters: more specific causes (token expiry, signature
    // mismatch) must match BEFORE the generic-403 "credentials rejected"
    // catch — otherwise an `ExpiredTokenException` body with a 403
    // status surfaces as a generic credentials error instead of the
    // actionable "refresh SSO" hint.
    if lower.contains("resourcenotfound") || lower.contains("model not found") {
        anyhow::anyhow!(
            "aws_bedrock HTTP {code}: model id not found in region `{region}`. \
             Bedrock model availability is per-region — confirm the model is \
             enabled in your AWS account for this region (Bedrock console → \
             Model access). Raw body: {trimmed}"
        )
    } else if lower.contains("expiredtokenexception")
        || lower.contains("invalidclienttokenid")
        || code == 401
    {
        anyhow::anyhow!(
            "aws_bedrock HTTP {code}: temporary credentials expired or invalid. \
             Refresh AWS_SESSION_TOKEN or re-run your SSO/identity-center session. \
             Raw body: {trimmed}"
        )
    } else if code == 403
        && (lower.contains("invalidsignature")
            || lower.contains("invalid signature")
            || lower.contains("signaturedoesnotmatch"))
    {
        anyhow::anyhow!(
            "aws_bedrock HTTP 403: SigV4 signature rejected. Most common cause: \
             credentials are bound to a different region than `{region}`, or the \
             local system clock is more than 5 minutes off UTC. Raw body: {trimmed}"
        )
    } else if code == 403 {
        anyhow::anyhow!(
            "aws_bedrock HTTP 403: credentials rejected. Check that the IAM \
             principal has `bedrock:InvokeModel` permission for the configured \
             model in region `{region}`. Raw body: {trimmed}"
        )
    } else if code == 400 && lower.contains("validationexception") {
        anyhow::anyhow!(
            "aws_bedrock HTTP 400 ValidationException: request body shape \
             rejected by Converse API. This usually means the model id does \
             not support the Converse API (Bedrock's older `InvokeModel` is \
             not used by NEOTH). Raw body: {trimmed}"
        )
    } else {
        anyhow::anyhow!("aws_bedrock returned HTTP {code}: {trimmed}")
    }
}

/// Trim trailing slashes + whitespace + any path suffix an operator
/// might have pasted accidentally (e.g. they paste a Bedrock console
/// URL instead of the region code).
fn canonical_region(raw: &str) -> Result<String> {
    let region = normalise_region(raw);
    if region.is_empty() {
        anyhow::bail!(
            "aws_bedrock: empty region — set `provider_region: us-east-1` in freedom.yaml \
             (or AWS_REGION env var) before selecting the aws_bedrock provider"
        );
    }
    validate_region(&region)?;
    Ok(region)
}

fn normalise_region(raw: &str) -> String {
    raw.trim()
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches(".amazonaws.com")
        .trim_start_matches("bedrock-runtime.")
        .to_string()
}

fn validate_region(region: &str) -> Result<()> {
    if region.len() > 63
        || region.starts_with('-')
        || region.ends_with('-')
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !region.contains('-')
    {
        anyhow::bail!(
            "aws_bedrock: invalid region; expected a lowercase AWS region id such as `us-east-1`"
        );
    }
    Ok(())
}

fn build_converse_body(req: &Request) -> ConverseRequest {
    let mut inference_config = InferenceConfig {
        max_tokens: Some(super::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING),
        ..InferenceConfig::default()
    };
    if let Some(t) = req.temperature {
        inference_config.temperature = Some(t);
    }
    if let Some(p) = req.top_p {
        inference_config.top_p = Some(p);
    }
    if !req.stop_sequences.is_empty() {
        inference_config.stop_sequences = Some(req.stop_sequences.clone());
    }

    let system_text = req
        .system
        .as_ref()
        .map(|s| vec![ConverseSystemBlock { text: s.clone() }]);

    ConverseRequest {
        messages: vec![ConverseMessage {
            role: "user",
            content: vec![ConverseContentBlock {
                text: req.prompt.clone(),
            }],
        }],
        system: system_text,
        inference_config: Some(inference_config),
    }
}

// ── Wire types ─────────────────────────────────────────────────────────
//
// Minimal Converse-API shape — only the fields NEOTH sends/reads. Bedrock
// will accept and ignore additional fields, and serde tolerates missing
// optional fields on response.

#[derive(Serialize)]
struct ConverseRequest {
    messages: Vec<ConverseMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<Vec<ConverseSystemBlock>>,
    #[serde(rename = "inferenceConfig", skip_serializing_if = "Option::is_none")]
    inference_config: Option<InferenceConfig>,
}

#[derive(Serialize)]
struct ConverseMessage {
    role: &'static str,
    content: Vec<ConverseContentBlock>,
}

#[derive(Serialize)]
struct ConverseContentBlock {
    text: String,
}

#[derive(Serialize)]
struct ConverseSystemBlock {
    text: String,
}

#[derive(Serialize, Default)]
struct InferenceConfig {
    #[serde(rename = "maxTokens", skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(rename = "topP", skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(rename = "stopSequences", skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ConverseResponse {
    #[serde(default)]
    output: Option<ConverseOutput>,
    #[serde(default)]
    usage: Option<ConverseUsage>,
}

#[derive(Deserialize)]
struct ConverseOutput {
    #[serde(default)]
    message: Option<ConverseRespMessage>,
}

#[derive(Deserialize)]
struct ConverseRespMessage {
    #[serde(default)]
    content: Vec<ConverseRespContent>,
}

#[derive(Deserialize)]
struct ConverseRespContent {
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct ConverseUsage {
    #[serde(rename = "inputTokens", default)]
    input_tokens: u32,
    #[serde(rename = "outputTokens", default)]
    output_tokens: u32,
}

// ── Small reqwest::RequestBuilder extension ────────────────────────────

/// Conditional-pipe helper to keep the header-chain readable when an
/// optional header may or may not be added. Internal to this module.
trait RequestBuilderExt {
    fn pipe_if<T>(
        self,
        value: Option<T>,
        f: impl FnOnce(reqwest::RequestBuilder, T) -> reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder;
}

impl RequestBuilderExt for reqwest::RequestBuilder {
    fn pipe_if<T>(
        self,
        value: Option<T>,
        f: impl FnOnce(reqwest::RequestBuilder, T) -> reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        match value {
            Some(v) => f(self, v),
            None => self,
        }
    }
}

/// Public helper for the WAL header sanitiser. Strips every header
/// the SigV4 stack could leak credential material through. Used on
/// the `cli::chat` request path around the PROVIDER_REQUEST (0x20)
/// WAL frame (B22: emitted post-model-resolution, pre-network-call)
/// — guardrail #5 from the Session-14 security review.
///
/// Headers stripped:
///   - `authorization` (SigV4 signature carries credential scope)
///   - `x-amz-security-token` (raw temporary credentials)
///
/// Other `X-Amz-*` headers (date, content-sha256) are derived
/// signatures themselves — safe to log.
pub fn strip_sensitive_headers(headers: &reqwest::header::HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "authorization" || lower == "x-amz-security-token" {
            continue;
        }
        out.insert(name.clone(), value.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    fn dummy_creds() -> AwsCredentials {
        AwsCredentials {
            access_key_id: SecretString::new("AKIATEST".into()),
            secret_access_key: SecretString::new("dummy-secret".into()),
            session_token: None,
        }
    }

    #[test]
    fn adapter_constructs_with_region_and_model() {
        let a = AwsBedrockAdapter::new(
            "us-east-1",
            dummy_creds(),
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
        )
        .expect("construct");
        assert_eq!(a.name(), "aws_bedrock");
        assert_eq!(a.region, "us-east-1");
        assert_eq!(
            a.consent_route(),
            Some(crate::consent::ConsentRoute::new(
                crate::cli::init::ProviderKind::AwsBedrock,
                Some("https://bedrock-runtime.us-east-1.amazonaws.com"),
            ))
        );
    }

    #[test]
    fn empty_region_is_rejected() {
        let err = AwsBedrockAdapter::new("", dummy_creds(), "amazon.titan-text-express-v1")
            .expect_err("must reject");
        assert!(err.to_string().contains("empty region"));
    }

    #[test]
    fn region_cannot_rewrite_the_bedrock_host() {
        for region in [
            "us-east-1.evil.example",
            "us-east-1/path",
            "US-EAST-1",
            "-us-east-1",
        ] {
            let error = AwsBedrockAdapter::new(region, dummy_creds(), "test-model").unwrap_err();
            assert!(error.to_string().contains("invalid region"));
        }
    }

    #[test]
    fn empty_model_is_rejected() {
        let err = AwsBedrockAdapter::new("us-east-1", dummy_creds(), "").expect_err("must reject");
        assert!(err.to_string().contains("empty model"));
    }

    #[test]
    fn normalise_region_strips_url_prefixes() {
        // Operator paste-error: full hostname instead of region code.
        assert_eq!(
            normalise_region("https://bedrock-runtime.eu-central-1.amazonaws.com"),
            "eu-central-1"
        );
        assert_eq!(normalise_region("us-east-1/"), "us-east-1");
        assert_eq!(normalise_region(" eu-west-2 "), "eu-west-2");
    }

    #[test]
    fn effective_region_precedence_is_config_then_environment_then_default() {
        assert_eq!(
            effective_region_from_candidates(
                Some("eu-central-1"),
                Some("ap-southeast-2"),
                Some("us-west-2"),
            )
            .unwrap(),
            "eu-central-1"
        );
        assert_eq!(
            effective_region_from_candidates(None, Some("ap-southeast-2"), Some("us-west-2"),)
                .unwrap(),
            "ap-southeast-2"
        );
        assert_eq!(
            effective_region_from_candidates(None, None, Some("us-west-2")).unwrap(),
            "us-west-2"
        );
        assert_eq!(
            effective_region_from_candidates(None, None, None).unwrap(),
            DEFAULT_REGION
        );
        assert!(effective_region_from_candidates(Some(""), Some("us-east-1"), None).is_err());
    }

    #[test]
    fn bedrock_endpoint_origins_are_region_bound_and_fail_closed() {
        assert_eq!(
            endpoint_origin_for_region("eu-central-1").unwrap(),
            "https://bedrock-runtime.eu-central-1.amazonaws.com"
        );
        assert_eq!(
            canonical_endpoint_origin("https://bedrock-runtime.eu-central-1.amazonaws.com/")
                .unwrap(),
            "https://bedrock-runtime.eu-central-1.amazonaws.com"
        );
        for endpoint in [
            "http://bedrock-runtime.us-east-1.amazonaws.com",
            "https://bedrock-runtime.US-EAST-1.amazonaws.com",
            "https://bedrock-runtime.us-east-1.amazonaws.com:443",
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/x",
            "https://bedrock-runtime.us-east-1.amazonaws.com.evil.example",
            "https://operator:secret@bedrock-runtime.us-east-1.amazonaws.com",
        ] {
            let error = canonical_endpoint_origin(endpoint).unwrap_err();
            assert!(!format!("{error:#}").contains("secret"));
        }
    }

    #[test]
    fn endpoint_url_includes_region_and_model() {
        let a = AwsBedrockAdapter::new(
            "eu-central-1",
            dummy_creds(),
            "amazon.titan-text-express-v1",
        )
        .unwrap();
        let url = a.endpoint_url("anthropic.claude-3-5-sonnet-20241022-v2:0");
        assert!(url.starts_with("https://bedrock-runtime.eu-central-1.amazonaws.com/model/"));
        assert!(url.ends_with("/converse"));
    }

    #[test]
    fn build_converse_body_includes_user_message() {
        let req = Request {
            prompt: "Hello".into(),
            ..Default::default()
        };
        let body = build_converse_body(&req);
        assert_eq!(body.messages.len(), 1);
        assert_eq!(body.messages[0].role, "user");
        assert_eq!(body.messages[0].content[0].text, "Hello");
        assert!(body.system.is_none());
        assert_eq!(
            body.inference_config.unwrap().max_tokens,
            Some(crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
        );
    }

    #[test]
    fn build_converse_body_threads_system_prompt() {
        let req = Request {
            prompt: "User question".into(),
            system: Some("You are a helpful assistant.".into()),
            ..Default::default()
        };
        let body = build_converse_body(&req);
        let system = body.system.expect("system block present");
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].text, "You are a helpful assistant.");
    }

    #[test]
    fn build_converse_body_threads_inference_config_when_set() {
        let req = Request {
            prompt: "hi".into(),
            temperature: Some(0.5),
            top_p: Some(0.95),
            ..Default::default()
        };
        let body = build_converse_body(&req);
        let cfg = body.inference_config.expect("inference config present");
        assert_eq!(
            cfg.max_tokens,
            Some(crate::providers::DEFAULT_CLOUD_OUTPUT_TOKEN_CEILING)
        );
        assert_eq!(cfg.temperature, Some(0.5));
        assert_eq!(cfg.top_p, Some(0.95));
        assert!(cfg.stop_sequences.is_none());
    }

    #[test]
    fn build_converse_body_serialises_to_json_camel_case() {
        let req = Request {
            prompt: "hi".into(),
            temperature: Some(0.5),
            stop_sequences: vec!["END".into()],
            ..Default::default()
        };
        let body = build_converse_body(&req);
        let json = serde_json::to_string(&body).unwrap();
        // Converse API uses camelCase wire fields.
        assert!(json.contains("\"inferenceConfig\""), "got: {json}");
        assert!(json.contains("\"maxTokens\":4096"), "got: {json}");
        assert!(json.contains("\"stopSequences\":[\"END\"]"), "got: {json}");
    }

    #[test]
    fn strip_sensitive_headers_drops_authorization_and_token() {
        let mut hdrs = reqwest::header::HeaderMap::new();
        hdrs.insert("Authorization", "AWS4-HMAC-SHA256 …".parse().unwrap());
        hdrs.insert(
            "X-Amz-Security-Token",
            "session-token-blob".parse().unwrap(),
        );
        hdrs.insert("X-Amz-Date", "20260518T120000Z".parse().unwrap());
        hdrs.insert("Content-Type", "application/json".parse().unwrap());

        let stripped = strip_sensitive_headers(&hdrs);
        assert!(stripped.get("authorization").is_none());
        assert!(stripped.get("x-amz-security-token").is_none());
        assert!(stripped.get("x-amz-date").is_some());
        assert!(stripped.get("content-type").is_some());
    }

    #[test]
    fn map_bedrock_error_recognises_resource_not_found() {
        let err = map_bedrock_error(
            reqwest::StatusCode::BAD_REQUEST,
            "{\"__type\":\"ResourceNotFoundException\",\"message\":\"unknown model\"}",
            "us-east-1",
        );
        let s = err.to_string();
        assert!(s.contains("model id not found"));
        assert!(s.contains("us-east-1"));
    }

    #[test]
    fn map_bedrock_error_recognises_invalid_signature() {
        let err = map_bedrock_error(
            reqwest::StatusCode::FORBIDDEN,
            "{\"__type\":\"InvalidSignatureException\"}",
            "eu-central-1",
        );
        let s = err.to_string();
        assert!(s.contains("SigV4 signature rejected"));
        assert!(s.contains("eu-central-1"));
    }

    #[test]
    fn map_bedrock_error_recognises_expired_token() {
        let err = map_bedrock_error(
            reqwest::StatusCode::FORBIDDEN,
            "{\"__type\":\"ExpiredTokenException\"}",
            "us-east-1",
        );
        let s = err.to_string();
        assert!(s.contains("expired or invalid"));
    }

    #[test]
    fn map_bedrock_error_recognises_validation_exception() {
        let err = map_bedrock_error(
            reqwest::StatusCode::BAD_REQUEST,
            "{\"__type\":\"ValidationException\",\"message\":\"bad shape\"}",
            "us-east-1",
        );
        let s = err.to_string();
        assert!(s.contains("ValidationException"));
        assert!(s.contains("Converse API"));
    }

    #[test]
    fn map_bedrock_error_falls_through_for_unknown_codes() {
        let err = map_bedrock_error(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error",
            "us-east-1",
        );
        assert!(err.to_string().contains("HTTP 500"));
    }
}
