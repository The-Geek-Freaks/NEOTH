//! Google Gemini model-list source.
//!
//! Endpoint: `GET https://generativelanguage.googleapis.com/v1beta/models`
//! with the key in the `x-goog-api-key` header (NOT the query string, so it
//! never leaks into logs/proxies — GOLD-SEC-22). Google's auth scheme for the
//! Generative AI REST surface), NOT as a Bearer header. Returns
//! `{ "models": [ { "name": "models/gemini-3.1-pro-preview",
//! "supportedGenerationMethods": [...], ... }, ... ] }`.
//!
//! Reference: <https://ai.google.dev/api/models#method:-models.list>

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use crate::models::catalog::{MAX_MODELS_PER_PROVIDER, ModelEntry, SourceOrigin};
use crate::models::cli_detect::{bundled_cli_models, probe_cli_version};
use crate::models::sources::{FetchResult, MAX_LIST_PAGES, ModelSource, read_bounded_list_page};
use crate::secret::SecretString;

const PROVIDER_KEY: &str = "gemini_api";

// Antigravity CLI (`agy`) is the post-2026-05-19 Google CLI that
// authenticates against the same backend. Used as the CLI probe for
// the gemini_api catalog's no-API-key fallback.
const DEFAULT_ENDPOINT: &str = "https://generativelanguage.googleapis.com/v1beta/models";
const DEFAULT_CLI_BINARY: &str = "agy";

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
            "gemini_api: API key not configured AND no Google CLI (`agy`) detected on PATH. \
             Set `provider_key` in freedom.yaml OR install Antigravity CLI \
             (curl -fsSL https://antigravity.google/cli/install.sh | sh). The legacy \
             gemini-cli stops serving API requests on 2026-06-18."
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
    let base_url = url::Url::parse(endpoint).context("parse gemini_api models endpoint")?;
    let mut page_token: Option<String> = None;
    let mut seen_tokens = HashSet::new();
    let mut total_bytes = 0usize;
    let mut model_rows = 0usize;
    let mut entries = Vec::new();

    // GOLD-SEC-22 / A-60: key in the `x-goog-api-key` header, not the
    // `?key=` query param (URLs leak into logs/proxies; headers do not).
    for _ in 0..MAX_LIST_PAGES {
        let mut url = base_url.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("pageSize", "1000");
            if let Some(token) = page_token.as_deref() {
                query.append_pair("pageToken", token);
            }
        }
        let response = client
            .get(url)
            .header("x-goog-api-key", api_key)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .context("request gemini_api model list")?;
        let parsed: ListResponse =
            read_bounded_list_page(response, "gemini_api", &mut total_bytes).await?;
        anyhow::ensure!(
            model_rows.saturating_add(parsed.models.len()) <= MAX_MODELS_PER_PROVIDER,
            "gemini_api model list exceeds {MAX_MODELS_PER_PROVIDER} entries"
        );
        model_rows += parsed.models.len();
        entries.extend(
            parsed
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
                }),
        );

        let Some(token) = parsed.next_page_token.filter(|token| !token.is_empty()) else {
            return Ok(entries);
        };
        anyhow::ensure!(
            seen_tokens.insert(token.clone()),
            "gemini_api pagination repeated token"
        );
        page_token = Some(token);
    }

    anyhow::bail!("gemini_api pagination exceeds {MAX_LIST_PAGES} pages")
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
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
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
    use crate::models::sources::MAX_LIST_PAGE_BYTES;
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    #[tokio::test]
    async fn rest_catalog_follows_all_pages_and_filters_non_chat_models() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .and(query_param("pageSize", "1000"))
            .and(query_param_is_missing("pageToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [
                    {"name": "models/gemini-first", "supportedGenerationMethods": ["generateContent"]},
                    {"name": "models/embed-only", "supportedGenerationMethods": ["embedContent"]}
                ],
                "nextPageToken": "page-two"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .and(query_param("pageSize", "1000"))
            .and(query_param("pageToken", "page-two"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [
                    {"name": "models/gemini-second", "supportedGenerationMethods": ["generateContent"]}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let models = fetch_models_via_rest(&format!("{}/v1beta/models", server.uri()), "test-key")
            .await
            .unwrap();
        assert_eq!(
            models
                .iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>(),
            vec!["gemini-first", "gemini-second"]
        );
    }

    #[tokio::test]
    async fn rest_catalog_rejects_repeated_pagination_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .and(query_param_is_missing("pageToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [],
                "nextPageToken": "same-token"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .and(query_param("pageToken", "same-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "models": [],
                "nextPageToken": "same-token"
            })))
            .mount(&server)
            .await;

        let error = fetch_models_via_rest(&format!("{}/v1beta/models", server.uri()), "test-key")
            .await
            .expect_err("repeated token must fail closed");
        assert!(error.to_string().contains("repeated token"));
    }

    #[tokio::test]
    async fn rest_catalog_response_is_hard_bounded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_LIST_PAGE_BYTES + 1]),
            )
            .mount(&server)
            .await;

        let error = fetch_models_via_rest(&format!("{}/v1beta/models", server.uri()), "test-key")
            .await
            .expect_err("oversized page must fail closed");
        assert!(error.to_string().contains("page exceeds"));
    }

    #[tokio::test]
    async fn rest_catalog_never_surfaces_provider_error_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .respond_with(ResponseTemplate::new(429).set_body_string("echoed-secret-test-key"))
            .mount(&server)
            .await;

        let error = fetch_models_via_rest(&format!("{}/v1beta/models", server.uri()), "test-key")
            .await
            .expect_err("HTTP failure must fail closed");
        assert!(error.to_string().contains("HTTP 429"));
        assert!(!error.to_string().contains("echoed-secret"));
    }
}
