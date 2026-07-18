//! OpenAI model-list source.
//!
//! Endpoint: `GET https://api.openai.com/v1/models` with
//! `Authorization: Bearer <api_key>`. Returns
//! `{ "object": "list", "data": [ { "id": "...", "object": "model",
//! "created": 0, "owned_by": "..." }, ... ] }`. Works against
//! OpenAI-compat endpoints too (LM Studio, vLLM, Ollama, OpenRouter).
//!
//! Reference: <https://platform.openai.com/docs/api-reference/models/list>

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use crate::models::catalog::{ModelEntry, SourceOrigin};
use crate::models::sources::{FetchResult, ModelSource};
use crate::secret::SecretString;

const PROVIDER_KEY: &str = "openai_api";
const DEFAULT_ENDPOINT: &str = "https://api.openai.com/v1/models";
const MAX_LIST_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub struct OpenAiSource {
    api_key: Option<SecretString>,
    endpoint: String,
    /// Override `provider()` when the source talks to an OpenAI-
    /// compatible endpoint instead of upstream OpenAI. The catalog
    /// then indexes the result under e.g. `openai_compat` instead of
    /// `openai_api`.
    provider_override: Option<&'static str>,
}

impl OpenAiSource {
    pub fn new_openai(api_key: Option<SecretString>) -> Self {
        Self {
            api_key,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            provider_override: None,
        }
    }

    pub fn new_compat(api_key: Option<SecretString>, endpoint: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            api_key,
            endpoint: canonical_models_endpoint(endpoint.as_ref())?,
            provider_override: Some("openai_compat"),
        })
    }

    /// Internal helper used by tests.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
}

/// Canonical, request-ready model-list URL for OpenAI-compatible APIs.
///
/// Query parameters are preserved, fragments are removed, and only HTTP(S)
/// endpoints are accepted. This avoids the old `...?token=x/models` suffix
/// corruption and gives discovery one exact endpoint identity to compare.
pub(crate) fn canonical_models_endpoint(endpoint: &str) -> Result<String> {
    let mut endpoint = url::Url::parse(endpoint.trim()).context("parse model-list endpoint URL")?;
    anyhow::ensure!(
        matches!(endpoint.scheme(), "http" | "https"),
        "model-list endpoint URL must use http or https"
    );
    endpoint.set_fragment(None);
    let path = endpoint.path().trim_end_matches('/').to_owned();
    if !path.ends_with("/models") {
        let path = if path.is_empty() {
            "/models".to_string()
        } else {
            format!("{path}/models")
        };
        endpoint.set_path(&path);
    } else if endpoint.path().ends_with('/') {
        endpoint.set_path(&path);
    }
    Ok(endpoint.into())
}

#[async_trait]
impl ModelSource for OpenAiSource {
    fn provider(&self) -> &'static str {
        self.provider_override.unwrap_or(PROVIDER_KEY)
    }

    async fn fetch(&self) -> Result<FetchResult> {
        let key_str = self
            .api_key
            .as_ref()
            .map(|k| k.expose().to_string())
            .unwrap_or_default();
        if key_str.is_empty() && self.provider_override.is_none() {
            anyhow::bail!(
                "openai_api: API key not configured. Set `provider_key` for the \
                 openai_api hemisphere in freedom.yaml to enable model discovery."
            );
        }
        let models = fetch_models_via_rest(&self.endpoint, &key_str).await?;
        Ok(FetchResult {
            provider: self.provider(),
            origin: SourceOrigin::Api,
            models,
        })
    }
}

async fn fetch_models_via_rest(endpoint: &str, api_key: &str) -> Result<Vec<ModelEntry>> {
    let client = crate::providers::http_client::build_client()?;
    let mut request = client.get(endpoint).timeout(Duration::from_secs(30));
    if !api_key.is_empty() {
        request = request.bearer_auth(api_key);
    }
    let mut response = request
        .send()
        .await
        .context("request OpenAI-compatible model list")?;
    let status = response.status();
    if !status.is_success() {
        // A provider-controlled body can be arbitrarily large and can echo
        // request credentials or signed query parameters. It must never cross
        // the durable/public catalog error boundary.
        anyhow::bail!("openai list-models returned HTTP {}", status.as_u16());
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_LIST_RESPONSE_BYTES as u64)
    {
        anyhow::bail!("openai list-models response exceeds {MAX_LIST_RESPONSE_BYTES} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read openai list-models response")?
    {
        if body.len().saturating_add(chunk.len()) > MAX_LIST_RESPONSE_BYTES {
            anyhow::bail!("openai list-models response exceeds {MAX_LIST_RESPONSE_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    let parsed: ListResponse =
        serde_json::from_slice(&body).context("parse openai list-models JSON")?;
    let mut entries: Vec<ModelEntry> = parsed
        .data
        .into_iter()
        .map(|m| {
            let mut e = ModelEntry::new(m.id);
            if let Some(owner) = m.owned_by {
                e = e.with_summary(format!("owned_by={owner}"));
            }
            e
        })
        .collect();
    // OpenAI's /v1/models returns models in an opaque order; sort
    // alphabetically for stable catalog diffs across refreshes.
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(entries)
}

// ── Wire types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ListResponse {
    #[serde(default)]
    data: Vec<ModelRow>,
}

#[derive(Deserialize)]
struct ModelRow {
    id: String,
    #[serde(default)]
    owned_by: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn openai_source_reports_default_provider_key() {
        let s = OpenAiSource::new_openai(Some(SecretString::new("sk-test".into())));
        assert_eq!(s.provider(), "openai_api");
    }

    #[test]
    fn compat_source_reports_compat_provider_key() {
        let s = OpenAiSource::new_compat(None, "http://localhost:8080/v1").unwrap();
        assert_eq!(s.provider(), "openai_compat");
    }

    #[test]
    fn compat_normalises_endpoint_when_models_suffix_missing() {
        let s = OpenAiSource::new_compat(None, "http://localhost:8080/v1").unwrap();
        assert_eq!(s.endpoint, "http://localhost:8080/v1/models");
    }

    #[test]
    fn compat_passes_through_endpoint_when_models_suffix_present() {
        let s = OpenAiSource::new_compat(None, "http://localhost:8080/v1/models").unwrap();
        assert_eq!(s.endpoint, "http://localhost:8080/v1/models");
    }

    #[test]
    fn compat_canonicalization_preserves_query_and_drops_fragment() {
        let s = OpenAiSource::new_compat(
            None,
            "https://models.example/v1/?tenant=alpha#operator-note",
        )
        .unwrap();
        assert_eq!(s.endpoint, "https://models.example/v1/models?tenant=alpha");
        assert!(OpenAiSource::new_compat(None, "file:///tmp/models").is_err());
    }

    #[tokio::test]
    async fn openai_missing_key_bails() {
        let s = OpenAiSource::new_openai(None);
        let err = s.fetch().await.expect_err("must bail");
        assert!(err.to_string().contains("API key"));
    }

    #[tokio::test]
    async fn compat_without_key_still_attempts_call() {
        // OpenAI-compat endpoints (LM Studio, Ollama, vLLM) typically
        // run unauthenticated on localhost. The source must NOT require
        // a key in that mode — it just sends the request without the
        // Authorization header.
        let s = OpenAiSource::new_compat(None, "http://127.0.0.1:1/v1").unwrap();
        // The actual call will fail (no server) but the bail path
        // must be the connect-error path, not the missing-key path.
        let err = s.fetch().await.expect_err("must error on connect");
        assert!(
            !err.to_string().contains("API key"),
            "compat must not bail on missing key; got: {err}"
        );
    }

    #[tokio::test]
    async fn successful_response_body_is_hard_bounded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
                b'x';
                MAX_LIST_RESPONSE_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;
        let source = OpenAiSource::new_compat(None, format!("{}/v1", server.uri())).unwrap();
        let error = source.fetch().await.expect_err("oversized body must fail");
        assert!(error.to_string().contains("response exceeds"));
    }
}
