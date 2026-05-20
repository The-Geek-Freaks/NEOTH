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

    pub fn new_compat(api_key: Option<SecretString>, endpoint: impl Into<String>) -> Self {
        let mut ep = endpoint.into();
        // Caller may pass either `https://host/v1` or `https://host/v1/models`;
        // normalise to the models path.
        if !ep.trim_end_matches('/').ends_with("/models") {
            ep = format!("{}/models", ep.trim_end_matches('/'));
        }
        Self {
            api_key,
            endpoint: ep,
            provider_override: Some("openai_compat"),
        }
    }

    /// Internal helper used by tests.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
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
    let response = request
        .send()
        .await
        .with_context(|| format!("GET {endpoint}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "openai list-models returned HTTP {}: {}",
            status.as_u16(),
            body.trim()
        );
    }
    let parsed: ListResponse = response
        .json()
        .await
        .context("parse openai list-models JSON")?;
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

    #[test]
    fn openai_source_reports_default_provider_key() {
        let s = OpenAiSource::new_openai(Some(SecretString::new("sk-test".into())));
        assert_eq!(s.provider(), "openai_api");
    }

    #[test]
    fn compat_source_reports_compat_provider_key() {
        let s = OpenAiSource::new_compat(None, "http://localhost:8080/v1");
        assert_eq!(s.provider(), "openai_compat");
    }

    #[test]
    fn compat_normalises_endpoint_when_models_suffix_missing() {
        let s = OpenAiSource::new_compat(None, "http://localhost:8080/v1");
        assert_eq!(s.endpoint, "http://localhost:8080/v1/models");
    }

    #[test]
    fn compat_passes_through_endpoint_when_models_suffix_present() {
        let s = OpenAiSource::new_compat(None, "http://localhost:8080/v1/models");
        assert_eq!(s.endpoint, "http://localhost:8080/v1/models");
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
        let s = OpenAiSource::new_compat(None, "http://127.0.0.1:1/v1");
        // The actual call will fail (no server) but the bail path
        // must be the connect-error path, not the missing-key path.
        let err = s.fetch().await.expect_err("must error on connect");
        assert!(
            !err.to_string().contains("API key"),
            "compat must not bail on missing key; got: {err}"
        );
    }
}
