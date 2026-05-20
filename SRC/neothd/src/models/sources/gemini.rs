//! Google Gemini model-list source.
//!
//! Endpoint: `GET https://generativelanguage.googleapis.com/v1beta/models?key=<api_key>`.
//! Key is passed as a query parameter (Google's auth scheme for the
//! Generative AI REST surface), NOT as a Bearer header. Returns
//! `{ "models": [ { "name": "models/gemini-3.1-pro-preview",
//! "supportedGenerationMethods": [...], ... }, ... ] }`.
//!
//! Reference: <https://ai.google.dev/api/models#method:-models.list>

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use crate::models::catalog::{ModelEntry, SourceOrigin};
use crate::models::cli_detect::{bundled_cli_models, probe_cli_version};
use crate::models::sources::{FetchResult, ModelSource};
use crate::secret::SecretString;

const PROVIDER_KEY: &str = "gemini_api";
const DEFAULT_ENDPOINT: &str = "https://generativelanguage.googleapis.com/v1beta/models";
const DEFAULT_CLI_BINARY: &str = "gemini";

pub struct GeminiSource {
    api_key: Option<SecretString>,
    endpoint: String,
    cli_binary: Option<String>,
    cli_probe_enabled: bool,
}

impl GeminiSource {
    pub fn new(api_key: Option<SecretString>) -> Self {
        Self {
            api_key,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            cli_binary: None,
            cli_probe_enabled: true,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_cli_binary(mut self, binary: impl Into<String>) -> Self {
        self.cli_binary = Some(binary.into());
        self
    }

    pub fn without_cli_probe(mut self) -> Self {
        self.cli_probe_enabled = false;
        self
    }
}

#[async_trait]
impl ModelSource for GeminiSource {
    fn provider(&self) -> &'static str {
        PROVIDER_KEY
    }

    async fn fetch(&self) -> Result<FetchResult> {
        // Same strategy as `anthropic.rs`: REST wins when a key is
        // available; CLI-presence falls back to bundled aliases;
        // otherwise bail with actionable hint.
        if let Some(key) = self.api_key.as_ref() {
            let models = fetch_models_via_rest(&self.endpoint, key.expose()).await?;
            return Ok(FetchResult {
                provider: PROVIDER_KEY,
                origin: SourceOrigin::Api,
                models,
            });
        }
        if self.cli_probe_enabled {
            let binary = self.cli_binary.as_deref().unwrap_or(DEFAULT_CLI_BINARY);
            if let Ok(presence) = probe_cli_version(binary) {
                tracing::info!(
                    binary = %presence.binary,
                    version = %presence.version,
                    "gemini_api catalog: REST key absent — falling back to CLI-detected bundled aliases"
                );
                return Ok(FetchResult {
                    provider: PROVIDER_KEY,
                    origin: SourceOrigin::Cli,
                    models: bundled_gemini_entries(),
                });
            }
        }
        anyhow::bail!(
            "gemini_api: API key not configured AND `gemini` CLI not detected on PATH. \
             Set `provider_key` in freedom.yaml OR install Google's Gemini CLI (npm i -g @google/gemini-cli)."
        )
    }
}

fn bundled_gemini_entries() -> Vec<ModelEntry> {
    bundled_cli_models::GEMINI
        .iter()
        .map(|(id, summary)| ModelEntry::new(*id).with_summary(*summary))
        .collect()
}

async fn fetch_models_via_rest(endpoint: &str, api_key: &str) -> Result<Vec<ModelEntry>> {
    let client = crate::providers::http_client::build_client()?;
    let url = format!("{endpoint}?key={api_key}");
    let response = client
        .get(&url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        // The url contains the key — strip it from any context surface.
        .with_context(|| format!("GET {endpoint} (key redacted)"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "gemini_api list-models returned HTTP {}: {}",
            status.as_u16(),
            body.trim()
        );
    }
    let parsed: ListResponse = response
        .json()
        .await
        .context("parse gemini_api list-models JSON")?;
    Ok(parsed
        .models
        .into_iter()
        // Filter to chat-capable models; embeddings + tuning models
        // are out of scope for the LLM chat provider selector.
        .filter(|m| supports_generate_content(&m.supported_generation_methods))
        .map(|m| {
            // Gemini's REST API returns IDs as `models/gemini-3.1-pro-preview`;
            // strip the prefix so the catalog entry matches the form the
            // operator types into freedom.yaml.
            let bare_id = m
                .name
                .strip_prefix("models/")
                .unwrap_or(&m.name)
                .to_string();
            let mut e = ModelEntry::new(bare_id);
            if let Some(display) = m.display_name {
                e = e.with_display_name(display);
            }
            if let Some(desc) = m.description {
                e = e.with_summary(desc);
            }
            e
        })
        .collect())
}

fn supports_generate_content(methods: &[String]) -> bool {
    // Gemini exposes `generateContent` for text chat and
    // `embedContent` for embeddings. We only catalog the chat path.
    methods.iter().any(|m| m == "generateContent")
}

// ── Wire types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ListResponse {
    #[serde(default)]
    models: Vec<ModelRow>,
}

#[derive(Deserialize)]
struct ModelRow {
    name: String,
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "supportedGenerationMethods")]
    supported_generation_methods: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_reports_provider_key() {
        let s = GeminiSource::new(None);
        assert_eq!(s.provider(), "gemini_api");
    }

    #[tokio::test]
    async fn missing_key_without_cli_bails_actionably() {
        let s = GeminiSource::new(None).without_cli_probe();
        let err = s.fetch().await.expect_err("must bail");
        assert!(err.to_string().contains("API key"));
        assert!(err.to_string().contains("gemini_api"));
    }

    #[tokio::test]
    async fn missing_key_with_unresolvable_cli_binary_still_bails() {
        let s =
            GeminiSource::new(None).with_cli_binary("this-binary-cannot-exist-on-any-real-system");
        let err = s.fetch().await.expect_err("must bail");
        assert!(err.to_string().contains("API key"));
    }

    #[test]
    fn bundled_gemini_entries_carry_summaries() {
        let entries = bundled_gemini_entries();
        assert!(!entries.is_empty());
        for e in &entries {
            assert!(
                e.summary.is_some(),
                "bundled entry {} missing summary",
                e.id
            );
        }
    }

    #[test]
    fn bundled_gemini_entries_include_pro_preview() {
        let entries = bundled_gemini_entries();
        assert!(entries.iter().any(|e| e.id == "gemini-3.1-pro-preview"));
    }

    #[test]
    fn supports_generate_content_recognises_chat_method() {
        assert!(supports_generate_content(&[
            "generateContent".to_string(),
            "countTokens".to_string(),
        ]));
    }

    #[test]
    fn supports_generate_content_filters_embedding_only_models() {
        assert!(!supports_generate_content(&["embedContent".to_string()]));
    }

    #[test]
    fn endpoint_override_threads_through() {
        let s = GeminiSource::new(None).with_endpoint("http://localhost:9999/v1beta/models");
        assert_eq!(s.endpoint, "http://localhost:9999/v1beta/models");
    }
}
