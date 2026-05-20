//! Anthropic model-list source.
//!
//! Tries the `claude` CLI first (`claude /model list` — the slash-
//! command list on Claude Code surfaces the catalog without an API
//! key). Falls back to `GET https://api.anthropic.com/v1/models`
//! with the operator's `x-api-key` header.
//!
//! Reference:
//! <https://platform.claude.com/docs/en/api-reference/models/list>

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use crate::models::catalog::{ModelEntry, SourceOrigin};
use crate::models::cli_detect::{bundled_cli_models, probe_cli_version};
use crate::models::sources::{FetchResult, ModelSource};
use crate::secret::SecretString;

const PROVIDER_KEY: &str = "anthropic_api";
const ANTHROPIC_VERSION_HEADER: &str = "2023-06-01";
const DEFAULT_ENDPOINT: &str = "https://api.anthropic.com/v1/models";
const DEFAULT_CLI_BINARY: &str = "claude";

/// Anthropic source. Tries CLI-presence detection first (so operators
/// running NEOTH with only the OAuth-authed `claude` CLI installed
/// still get a populated catalog), then REST as the authoritative
/// fallback when an API key is configured.
pub struct AnthropicSource {
    api_key: Option<SecretString>,
    endpoint: String,
    /// Optional CLI binary override (for tests + advanced operators
    /// with custom installs). Defaults to `"claude"` discovered via
    /// `$PATH`.
    cli_binary: Option<String>,
    /// When `false`, skip the CLI-presence detection path entirely.
    /// Tests in air-gapped CI use this to keep results deterministic.
    cli_probe_enabled: bool,
}

impl AnthropicSource {
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

    /// Disable CLI-presence probing. Used by tests + by orchestration
    /// paths that explicitly want REST-only discovery.
    pub fn without_cli_probe(mut self) -> Self {
        self.cli_probe_enabled = false;
        self
    }
}

#[async_trait]
impl ModelSource for AnthropicSource {
    fn provider(&self) -> &'static str {
        PROVIDER_KEY
    }

    async fn fetch(&self) -> Result<FetchResult> {
        // Strategy:
        //   1. If we have a REST key, REST wins — it's the most
        //      authoritative source (Anthropic's own list-models
        //      endpoint).
        //   2. Else, if the `claude` CLI is on PATH, fall through to
        //      the bundled canonical-aliases path with
        //      SourceOrigin::Cli. The catalog is informational only —
        //      the actual chat path uses `provider_kind: claude_cli`
        //      with OAuth.
        //   3. Else, bail with an actionable hint.
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
                    "anthropic_api catalog: REST key absent — falling back to CLI-detected bundled aliases"
                );
                return Ok(FetchResult {
                    provider: PROVIDER_KEY,
                    origin: SourceOrigin::Cli,
                    models: bundled_anthropic_entries(),
                });
            }
        }
        anyhow::bail!(
            "anthropic_api: API key not configured AND `claude` CLI not detected on PATH. \
             Set `provider_key` in freedom.yaml OR install `claude` (npm i -g @anthropic-ai/claude-code)."
        )
    }
}

fn bundled_anthropic_entries() -> Vec<ModelEntry> {
    bundled_cli_models::ANTHROPIC
        .iter()
        .map(|(id, summary)| ModelEntry::new(*id).with_summary(*summary))
        .collect()
}

async fn fetch_models_via_rest(endpoint: &str, api_key: &str) -> Result<Vec<ModelEntry>> {
    let client = crate::providers::http_client::build_client()?;
    let response = client
        .get(endpoint)
        .header("x-api-key", api_key)
        .header("anthropic-version", ANTHROPIC_VERSION_HEADER)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .with_context(|| format!("GET {endpoint}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "anthropic_api list-models returned HTTP {}: {}",
            status.as_u16(),
            body.trim()
        );
    }
    let parsed: ListResponse = response
        .json()
        .await
        .context("parse anthropic_api list-models JSON")?;
    Ok(parsed
        .data
        .into_iter()
        .map(|m| {
            let mut e = ModelEntry::new(m.id);
            if let Some(name) = m.display_name {
                e = e.with_display_name(name);
            }
            e
        })
        .collect())
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
    display_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_constructs_without_key() {
        let s = AnthropicSource::new(None);
        assert_eq!(s.provider(), "anthropic_api");
    }

    #[test]
    fn source_constructs_with_key_and_endpoint_override() {
        let s = AnthropicSource::new(Some(SecretString::new("sk-ant-test".into())))
            .with_endpoint("https://internal.proxy/v1/models");
        assert_eq!(s.endpoint, "https://internal.proxy/v1/models");
    }

    #[tokio::test]
    async fn missing_key_without_cli_bails_with_actionable_message() {
        // CLI-probe explicitly disabled so the test stays deterministic
        // on dev machines that have `claude` installed.
        let s = AnthropicSource::new(None).without_cli_probe();
        let err = s.fetch().await.expect_err("must bail");
        let msg = err.to_string();
        assert!(msg.contains("API key"), "got: {msg}");
        assert!(msg.contains("anthropic_api"), "got: {msg}");
    }

    #[tokio::test]
    async fn missing_key_with_unresolvable_cli_binary_still_bails() {
        // CLI probe is enabled but points at a binary that can't exist.
        let s = AnthropicSource::new(None)
            .with_cli_binary("this-binary-will-never-exist-anywhere-ever");
        let err = s.fetch().await.expect_err("must bail");
        let msg = err.to_string();
        // Error must reference both the missing key + the absent CLI.
        assert!(msg.contains("API key"), "got: {msg}");
        assert!(msg.contains("CLI") || msg.contains("claude"), "got: {msg}");
    }

    #[test]
    fn bundled_anthropic_entries_carry_summaries() {
        let entries = bundled_anthropic_entries();
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
    fn bundled_anthropic_entries_include_opus_flagship() {
        let entries = bundled_anthropic_entries();
        assert!(entries.iter().any(|e| e.id == "claude-opus-4-7"));
    }
}
