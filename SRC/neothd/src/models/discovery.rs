//! Discovery orchestrator — fan-out across all configured model
//! sources and merge results into the catalog.
//!
//! Entry points:
//!
//!   - [`discover_all`] — runs every source the operator has
//!     configured credentials for (driven by `FreedomConfig`),
//!     updates the catalog on disk. Used by the daily cron task
//!     + the `neoth models refresh` CLI subcommand.
//!   - [`build_sources_from_config`] — pure helper that translates
//!     `FreedomConfig` into a `Vec<Box<dyn ModelSource>>`. Surfaced
//!     publicly so the CLI subcommand can list "what would be
//!     queried" without firing the actual HTTPS calls.
//!
//! Concurrency: sources are independent — one provider's failure
//! does NOT halt the others. `futures::join_all` collects results
//! in parallel; each source's error is recorded under its
//! `ProviderCatalog::last_error` so the operator sees the cause
//! in `neoth models show <provider>`.

use std::path::Path;

use anyhow::Result;
use futures_util::future::join_all;

use super::catalog::ModelsCatalog;
use super::sources::ModelSource;
use super::sources::anthropic::AnthropicSource;
use super::sources::bedrock::BedrockSource;
use super::sources::gemini::GeminiSource;
use super::sources::openai::OpenAiSource;
use crate::config::FreedomConfig;
use crate::providers::aws_credentials;

/// Summary of one discovery run — returned to the CLI subcommand
/// so the operator sees `refreshed: 3, failed: 1` rather than just
/// "done".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryReport {
    /// Provider keys that successfully refreshed.
    pub refreshed: Vec<String>,
    /// Provider keys where the fetch raised an error.
    pub failed: Vec<String>,
    /// Provider keys that were skipped because no credentials were
    /// configured (typical for an operator who only uses one cloud).
    pub skipped_no_creds: Vec<String>,
}

impl DiscoveryReport {
    pub fn summary_line(&self) -> String {
        format!(
            "{} refreshed, {} failed, {} skipped (no creds)",
            self.refreshed.len(),
            self.failed.len(),
            self.skipped_no_creds.len()
        )
    }
}

/// Translate the operator's `FreedomConfig` into the set of sources
/// to query. Each source corresponds to one provider kind for which
/// the operator has surfaced credentials. The list is order-stable
/// (anthropic → openai → gemini → bedrock) so test diffs stay
/// deterministic.
pub fn build_sources_from_config(config: &FreedomConfig) -> Vec<Box<dyn ModelSource>> {
    let mut sources: Vec<Box<dyn ModelSource>> = Vec::new();

    // Anthropic API — only when a key is set + provider_kind hints
    // direct API usage (or per-hemisphere AnthropicApi is selected).
    if let Some(key) = config.provider_key.as_ref() {
        if uses_anthropic_api(config) {
            sources.push(Box::new(AnthropicSource::new(Some(key.clone()))));
        }
        // OpenAI / OpenAi-compat key paths.
        if uses_openai_api(config) {
            sources.push(Box::new(OpenAiSource::new_openai(Some(key.clone()))));
        }
        if uses_gemini_api(config) {
            sources.push(Box::new(GeminiSource::new(Some(key.clone()))));
        }
    }

    // OpenAI-compat endpoints typically don't need keys (LM Studio,
    // Ollama, vLLM on localhost). The source itself tolerates an
    // empty key.
    if uses_openai_compat(config) {
        if let Some(endpoint) = config.provider_endpoint.as_ref() {
            sources.push(Box::new(OpenAiSource::new_compat(
                config.provider_key.clone(),
                endpoint,
            )));
        }
    }

    // Bedrock — uses its own closed-enum credential chain, not the
    // freedom.yaml provider_key. The discovery path attempts the
    // same resolution as the chat adapter.
    if uses_bedrock(config) {
        match resolve_bedrock_credentials_for_discovery(config) {
            Ok(bedrock) => sources.push(bedrock),
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "aws_bedrock model discovery skipped — credentials not resolvable"
                );
            }
        }
    }

    sources
}

fn uses_anthropic_api(config: &FreedomConfig) -> bool {
    matches_any_kind(config, |k| {
        // PF-02 — BOTH the `claude` CLI path AND the native key-based
        // AnthropicApi adapter consume the same Anthropic model catalog, so
        // both must trigger the Anthropic discovery source (model-version-
        // agnostic HARD RULE — neither needs a code patch for a new Claude).
        matches!(
            k,
            crate::cli::init::ProviderKind::ClaudeCli
                | crate::cli::init::ProviderKind::AnthropicApi
        )
    })
}

fn uses_openai_api(config: &FreedomConfig) -> bool {
    matches_any_kind(config, |k| {
        matches!(k, crate::cli::init::ProviderKind::OpenaiApi)
    })
}

fn uses_openai_compat(config: &FreedomConfig) -> bool {
    matches_any_kind(config, |k| {
        matches!(k, crate::cli::init::ProviderKind::OpenaiCompat)
    })
}

fn uses_gemini_api(config: &FreedomConfig) -> bool {
    matches_any_kind(config, |k| {
        matches!(k, crate::cli::init::ProviderKind::GeminiApi)
    })
}

fn uses_bedrock(config: &FreedomConfig) -> bool {
    matches_any_kind(config, |k| {
        matches!(k, crate::cli::init::ProviderKind::AwsBedrock)
    })
}

/// Returns true when the top-level `provider_kind` OR any per-
/// hemisphere slot's provider matches the predicate. Mirrors the
/// consent gate's "is this kind anywhere in the topology" check.
fn matches_any_kind(
    config: &FreedomConfig,
    pred: impl Fn(crate::cli::init::ProviderKind) -> bool,
) -> bool {
    if let Some(kind) = config.provider_kind
        && pred(kind)
    {
        return true;
    }
    for slot in [
        &config.inference.default_slot,
        &config.inference.left,
        &config.inference.right,
        &config.inference.cerebellum,
    ] {
        if let Some(inf_provider) = slot.provider
            && pred(inf_provider.to_provider_kind())
        {
            return true;
        }
    }
    false
}

fn resolve_bedrock_credentials_for_discovery(
    config: &FreedomConfig,
) -> Result<Box<dyn ModelSource>> {
    let region = config
        .provider_region
        .clone()
        .or_else(|| std::env::var("AWS_REGION").ok())
        .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
        .unwrap_or_else(|| "us-east-1".to_string());
    let resolved = aws_credentials::resolve_chain(None, &aws_credentials::env_var_getter, None)?;
    Ok(Box::new(BedrockSource::new(region, resolved.credentials)))
}

/// Run every source concurrently, update the catalog at `path` with
/// the results. Failures are recorded per-provider but do not abort
/// the run.
pub async fn discover_all(catalog_path: &Path, config: &FreedomConfig) -> Result<DiscoveryReport> {
    let sources = build_sources_from_config(config);
    discover_with_sources(catalog_path, sources).await
}

/// Lower-level entry point — accepts pre-built sources so tests can
/// inject a deterministic mix. Production callers use [`discover_all`].
pub async fn discover_with_sources(
    catalog_path: &Path,
    sources: Vec<Box<dyn ModelSource>>,
) -> Result<DiscoveryReport> {
    let mut catalog = ModelsCatalog::load_from(catalog_path);
    let mut report = DiscoveryReport::default();

    if sources.is_empty() {
        // Empty config — no sources to run. The operator's `neoth
        // models refresh` should still succeed (no work), but the
        // catalog is not rewritten.
        return Ok(report);
    }

    let provider_names: Vec<&'static str> = sources.iter().map(|s| s.provider()).collect();
    let futures = sources.iter().map(|s| s.fetch());
    let results = join_all(futures).await;

    for (provider, result) in provider_names.into_iter().zip(results) {
        match result {
            Ok(fr) => {
                catalog.upsert(fr.provider, fr.origin, fr.models);
                report.refreshed.push(provider.to_string());
            }
            Err(e) => {
                catalog.record_error(provider, e.to_string());
                report.failed.push(provider.to_string());
            }
        }
    }

    catalog.save()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::init::ProviderKind;
    use crate::config::FreedomConfig;
    use crate::config::inference::{HemisphereSlot, InferenceProvider, InferenceTopology};
    use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
    use crate::models::sources::FetchResult;
    use async_trait::async_trait;
    use tempfile::tempdir;

    fn base_config() -> FreedomConfig {
        FreedomConfig {
            operator_id: Some("test".into()),
            ..Default::default()
        }
    }

    /// Drop-in mock source used by orchestrator tests — never touches
    /// the network.
    struct MockSource {
        name: &'static str,
        result: std::sync::Mutex<Option<Result<FetchResult>>>,
    }

    impl MockSource {
        fn ok(name: &'static str, ids: Vec<&'static str>) -> Self {
            let models = ids.into_iter().map(ModelEntry::new).collect();
            Self {
                name,
                result: std::sync::Mutex::new(Some(Ok(FetchResult {
                    provider: name,
                    origin: SourceOrigin::Api,
                    models,
                }))),
            }
        }

        fn err(name: &'static str, msg: &str) -> Self {
            Self {
                name,
                result: std::sync::Mutex::new(Some(Err(anyhow::anyhow!(msg.to_string())))),
            }
        }
    }

    #[async_trait]
    impl ModelSource for MockSource {
        fn provider(&self) -> &'static str {
            self.name
        }

        async fn fetch(&self) -> Result<FetchResult> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow::anyhow!("already consumed")))
        }
    }

    #[tokio::test]
    async fn empty_sources_returns_empty_report_no_file_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let report = discover_with_sources(&path, vec![]).await.unwrap();
        assert!(report.refreshed.is_empty());
        assert!(report.failed.is_empty());
        // Catalog file should NOT have been created.
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn all_sources_succeed_populates_catalog() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let sources: Vec<Box<dyn ModelSource>> = vec![
            Box::new(MockSource::ok("anthropic_api", vec!["claude-opus-4-7"])),
            Box::new(MockSource::ok("openai_api", vec!["gpt-5.5", "gpt-5.4"])),
        ];
        let report = discover_with_sources(&path, sources).await.unwrap();
        assert_eq!(report.refreshed.len(), 2);
        assert!(report.failed.is_empty());

        let reloaded = ModelsCatalog::load_from(&path);
        assert_eq!(reloaded.provider("anthropic_api").unwrap().models.len(), 1);
        assert_eq!(reloaded.provider("openai_api").unwrap().models.len(), 2);
    }

    #[tokio::test]
    async fn one_failure_does_not_block_other_sources() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let sources: Vec<Box<dyn ModelSource>> = vec![
            Box::new(MockSource::err("anthropic_api", "401 unauthorized")),
            Box::new(MockSource::ok("openai_api", vec!["gpt-5.5"])),
        ];
        let report = discover_with_sources(&path, sources).await.unwrap();
        assert_eq!(report.failed, vec!["anthropic_api".to_string()]);
        assert_eq!(report.refreshed, vec!["openai_api".to_string()]);

        let reloaded = ModelsCatalog::load_from(&path);
        let failed = reloaded.provider("anthropic_api").unwrap();
        assert!(failed.models.is_empty());
        assert_eq!(failed.last_error.as_deref(), Some("401 unauthorized"));
    }

    #[tokio::test]
    async fn prior_models_preserved_when_refresh_fails() {
        // Operator's wizard select must keep working through a
        // transient API outage. Refresh failures stamp last_error
        // but never wipe the previous catalog.
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");

        // Seed: one good refresh.
        let sources_good: Vec<Box<dyn ModelSource>> = vec![Box::new(MockSource::ok(
            "openai_api",
            vec!["gpt-5.5", "gpt-5.4"],
        ))];
        discover_with_sources(&path, sources_good).await.unwrap();

        // Second pass: transient failure on the same provider.
        let sources_fail: Vec<Box<dyn ModelSource>> = vec![Box::new(MockSource::err(
            "openai_api",
            "503 service unavailable",
        ))];
        discover_with_sources(&path, sources_fail).await.unwrap();

        let reloaded = ModelsCatalog::load_from(&path);
        let p = reloaded.provider("openai_api").unwrap();
        assert_eq!(p.models.len(), 2, "prior models preserved through failure");
        assert!(p.last_error.is_some(), "last_error stamped");
    }

    #[test]
    fn build_sources_empty_config_returns_no_sources() {
        let config = FreedomConfig::default();
        let sources = build_sources_from_config(&config);
        assert!(sources.is_empty());
    }

    #[test]
    fn build_sources_recognises_claude_cli_top_level() {
        let mut config = base_config();
        config.provider_kind = Some(ProviderKind::ClaudeCli);
        config.provider_key = Some(crate::secret::SecretString::new("sk-ant".into()));
        let sources = build_sources_from_config(&config);
        let names: Vec<_> = sources.iter().map(|s| s.provider()).collect();
        assert!(names.contains(&"anthropic_api"));
    }

    #[test]
    fn build_sources_recognises_openai_per_hemisphere() {
        let mut config = base_config();
        config.provider_key = Some(crate::secret::SecretString::new("sk-test".into()));
        config.inference = InferenceTopology {
            mode: crate::config::inference::TopologyMode::Custom,
            left: HemisphereSlot {
                provider: Some(InferenceProvider::OpenAi),
                ..Default::default()
            },
            ..Default::default()
        };
        let sources = build_sources_from_config(&config);
        let names: Vec<_> = sources.iter().map(|s| s.provider()).collect();
        assert!(names.contains(&"openai_api"));
    }

    #[test]
    fn build_sources_recognises_gemini_per_hemisphere() {
        let mut config = base_config();
        config.provider_key = Some(crate::secret::SecretString::new("AIza-test".into()));
        config.inference = InferenceTopology {
            mode: crate::config::inference::TopologyMode::Custom,
            right: HemisphereSlot {
                provider: Some(InferenceProvider::Gemini),
                ..Default::default()
            },
            ..Default::default()
        };
        let sources = build_sources_from_config(&config);
        let names: Vec<_> = sources.iter().map(|s| s.provider()).collect();
        assert!(names.contains(&"gemini_api"));
    }

    #[test]
    fn summary_line_renders_counts() {
        let mut report = DiscoveryReport::default();
        report.refreshed = vec!["a".into(), "b".into()];
        report.failed = vec!["c".into()];
        report.skipped_no_creds = vec!["d".into()];
        let line = report.summary_line();
        assert!(line.contains("2 refreshed"));
        assert!(line.contains("1 failed"));
        assert!(line.contains("1 skipped"));
    }
}
