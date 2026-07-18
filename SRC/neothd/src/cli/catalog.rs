//! `neoth catalog` — operator-facing LLM-provider model-catalog
//! management (Session 14 Pick #3, K-Models-Discovery).
//!
//! Distinct from `neoth models` which manages local artifact caches
//! (CLIP, Whisper, etc.) — `neoth catalog` is about the LLM model
//! IDs each provider currently exposes (`gpt-5.5`,
//! `gemini-3.1-pro-preview`, `anthropic.claude-opus-4-7`, …) and
//! whether NEOTH's wizard selects + freedom.yaml defaults are
//! pointing at the right ones.
//!
//! Subcommands:
//!
//!   - `refresh`  Run discovery against every configured provider +
//!                rewrite `~/.neoth/models_catalog.json`.
//!   - `list`     Print all cached models, grouped by provider.
//!   - `show`     Print one provider's catalog with metadata.
//!   - `defaults` Print the recommended-default model per provider.
//!   - `clear`    Wipe the cached catalog.
//!
//! Honours the global `--output {table, json, jsonl}` flag.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::json;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::models::catalog::{
    CATALOG_VERSION, ModelEntry, ModelsCatalog, ProviderCatalog, SourceOrigin, now_unix,
};
use crate::models::discovery;

const CATALOG_REFRESH_OPERATION: &str = "catalog.refresh";
const CATALOG_LIST_OPERATION: &str = "catalog.list";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CatalogRefreshResult {
    Fresh,
    Refreshed,
    Partial,
    NoDiscoverableSources,
    NoSources,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct CatalogRefreshReceipt {
    operation: &'static str,
    path: String,
    catalog_version: u32,
    catalog_generation: Option<u64>,
    catalog_hash: Option<String>,
    catalog_changed: bool,
    result: CatalogRefreshResult,
    stale_only: bool,
    configured: Vec<String>,
    fresh: Vec<String>,
    refreshed: Vec<String>,
    failed: Vec<String>,
    superseded: Vec<String>,
    skipped_no_creds: Vec<String>,
    credential_failures: Vec<String>,
    configuration_failures: Vec<String>,
    unsupported: Vec<String>,
    blocked_no_consent: Vec<String>,
}

impl CatalogRefreshReceipt {
    fn from_report(
        path: &std::path::Path,
        stale_only: bool,
        report: &discovery::DiscoveryReport,
    ) -> Result<Self> {
        validate_report_partition(report, stale_only)?;
        validate_snapshot_receipt(report.catalog_generation, report.catalog_hash.as_deref())?;
        if !report.fresh.is_empty() || !report.refreshed.is_empty() || !report.failed.is_empty() {
            anyhow::ensure!(
                report.catalog_generation.is_some(),
                "catalog refresh outcome references stored providers without a committed snapshot"
            );
        }
        if report.catalog_changed {
            anyhow::ensure!(
                report.catalog_generation.is_some(),
                "catalog refresh reported a durable change without a committed snapshot"
            );
        }
        if (!report.refreshed.is_empty() || !report.failed.is_empty()) && !report.catalog_changed {
            anyhow::bail!(
                "catalog refresh persisted provider outcomes without marking the catalog changed"
            );
        }
        let result = if !report.failed.is_empty()
            || !report.superseded.is_empty()
            || !report.skipped_no_creds.is_empty()
            || !report.credential_failures.is_empty()
            || !report.configuration_failures.is_empty()
            || !report.blocked_no_consent.is_empty()
        {
            CatalogRefreshResult::Partial
        } else if !report.refreshed.is_empty() {
            CatalogRefreshResult::Refreshed
        } else if stale_only && !report.fresh.is_empty() {
            CatalogRefreshResult::Fresh
        } else if !report.configured.is_empty()
            && report.unsupported.len() == report.configured.len()
        {
            CatalogRefreshResult::NoDiscoverableSources
        } else {
            CatalogRefreshResult::NoSources
        };
        Ok(Self {
            operation: CATALOG_REFRESH_OPERATION,
            path: path.display().to_string(),
            catalog_version: CATALOG_VERSION,
            catalog_generation: report.catalog_generation,
            catalog_hash: report.catalog_hash.clone(),
            catalog_changed: report.catalog_changed,
            result,
            stale_only,
            configured: report.configured.clone(),
            fresh: report.fresh.clone(),
            refreshed: report.refreshed.clone(),
            failed: report.failed.clone(),
            superseded: report.superseded.clone(),
            skipped_no_creds: report.skipped_no_creds.clone(),
            credential_failures: report.credential_failures.clone(),
            configuration_failures: report.configuration_failures.clone(),
            unsupported: report.unsupported.clone(),
            blocked_no_consent: report.blocked_no_consent.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CatalogListState {
    Present,
    Missing,
}

#[derive(Debug, Serialize)]
struct CatalogListReceipt {
    operation: &'static str,
    path: String,
    state: CatalogListState,
    catalog_version: u32,
    catalog_generation: Option<u64>,
    catalog_hash: Option<String>,
    providers: std::collections::BTreeMap<String, CatalogListProviderReceipt>,
}

#[derive(Debug, Serialize)]
struct CatalogListProviderReceipt {
    fetched_at_unix: u64,
    source: SourceOrigin,
    last_error: Option<String>,
    models: Vec<ModelEntry>,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_snapshot_receipt(generation: Option<u64>, hash: Option<&str>) -> Result<()> {
    anyhow::ensure!(
        generation.is_some() == hash.is_some(),
        "catalog snapshot generation and hash must either both be present or both be absent"
    );
    if let Some(hash) = hash {
        anyhow::ensure!(
            valid_sha256(hash),
            "catalog snapshot hash is not lowercase SHA-256"
        );
    }
    Ok(())
}

fn validate_catalog_snapshot(catalog: &ModelsCatalog) -> Result<()> {
    catalog.validate_semantics()?;
    for (provider, entry) in &catalog.providers {
        anyhow::ensure!(
            matches!(
                provider.as_str(),
                discovery::ANTHROPIC_CATALOG_PROVIDER
                    | discovery::OPENAI_CATALOG_PROVIDER
                    | discovery::GEMINI_CATALOG_PROVIDER
                    | discovery::OPENAI_COMPAT_CATALOG_PROVIDER
                    | discovery::BEDROCK_CATALOG_PROVIDER
            ),
            "catalog snapshot contains unknown provider key `{provider}`"
        );
        if !entry.models.is_empty() {
            anyhow::ensure!(
                entry.fetched_at_unix > 0,
                "catalog provider `{provider}` has models without a fetch timestamp"
            );
        }
        if let Some(binding_hash) = entry.binding_hash.as_deref() {
            anyhow::ensure!(
                valid_sha256(binding_hash),
                "catalog provider `{provider}` has an invalid binding hash"
            );
        }
        let mut model_ids = std::collections::HashSet::new();
        for model in &entry.models {
            anyhow::ensure!(
                !model.id.trim().is_empty() && model.id.trim() == model.id,
                "catalog provider `{provider}` contains an invalid model id"
            );
            anyhow::ensure!(
                model_ids.insert(model.id.as_str()),
                "catalog provider `{provider}` repeats model id `{}`",
                model.id
            );
            anyhow::ensure!(
                model
                    .summary
                    .as_deref()
                    .is_none_or(|summary| summary.chars().count() <= 200),
                "catalog provider `{provider}` contains an overlong model summary"
            );
        }
    }
    Ok(())
}

impl CatalogRefreshResult {
    fn is_success(self) -> bool {
        matches!(
            self,
            Self::Fresh | Self::Refreshed | Self::NoDiscoverableSources
        )
    }
}

fn validate_report_partition(report: &discovery::DiscoveryReport, stale_only: bool) -> Result<()> {
    let canonical_provider = |provider: &str| {
        matches!(
            provider,
            discovery::ANTHROPIC_CATALOG_PROVIDER
                | discovery::OPENAI_CATALOG_PROVIDER
                | discovery::GEMINI_CATALOG_PROVIDER
                | discovery::OPENAI_COMPAT_CATALOG_PROVIDER
                | discovery::BEDROCK_CATALOG_PROVIDER
                | discovery::INVALID_CATALOG_PROVIDER
                | "local_qwen"
                | "local_ouro"
                | "local_ollama"
                | "recursive_mas"
                | "azure_openai"
                | "cohere_api"
                | "copilot_api"
                | "none"
        )
    };
    let mut configured = std::collections::HashSet::new();
    for provider in &report.configured {
        anyhow::ensure!(
            canonical_provider(provider) && configured.insert(provider.as_str()),
            "catalog discovery produced an invalid configured-provider partition"
        );
    }
    let mut outcomes = std::collections::HashSet::new();
    for providers in [
        &report.fresh,
        &report.refreshed,
        &report.failed,
        &report.superseded,
        &report.skipped_no_creds,
        &report.credential_failures,
        &report.configuration_failures,
        &report.unsupported,
        &report.blocked_no_consent,
    ] {
        for provider in providers {
            anyhow::ensure!(
                canonical_provider(provider) && outcomes.insert(provider.as_str()),
                "catalog discovery produced overlapping or invalid provider outcomes"
            );
        }
    }
    anyhow::ensure!(
        configured == outcomes,
        "catalog discovery outcomes do not cover the configured provider scope"
    );
    anyhow::ensure!(
        stale_only || report.fresh.is_empty(),
        "full catalog refresh unexpectedly reported a provider as already fresh"
    );
    Ok(())
}

#[derive(Args, Debug, Clone)]
pub struct CatalogArgs {
    #[command(subcommand)]
    pub action: CatalogAction,

    /// Output format (inherited from global --output flag).
    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CatalogAction {
    /// Run discovery against every configured provider + persist the
    /// updated catalog. Idempotent — running twice in a row hits each
    /// provider's list-models endpoint once per run.
    Refresh {
        /// Only refresh providers whose cache entry is older than the
        /// TTL. Useful when running the daily cron job.
        #[arg(long)]
        stale_only: bool,
    },
    /// Print every cached model, grouped by provider.
    List {
        /// Include models the provider has flagged as deprecated /
        /// scheduled for sunset. Off by default — the wizard never
        /// surfaces deprecated entries either.
        #[arg(long)]
        include_deprecated: bool,
        /// Show only this provider's models (e.g. `anthropic_api`). Omit to
        /// list every cached provider. The JSON shape is identical — just
        /// narrowed to the one key — which drives the GUI per-role model
        /// picker via a clean `--output json` subprocess call (MV-01c).
        #[arg(long)]
        provider: Option<String>,
    },
    /// Print one provider's full catalog with metadata.
    Show {
        /// Provider key (`anthropic_api`, `openai_api`, `gemini_api`,
        /// `aws_bedrock`, `openai_compat`, …).
        provider: String,
    },
    /// Print the recommended-default model per provider — what the
    /// wizard / `freedom.yaml::provider_model` resolves to when the
    /// operator never types an explicit id.
    Defaults,
    /// Wipe the cached catalog. Next `refresh` rebuilds from scratch.
    Clear,
}

pub async fn run_catalog(args: CatalogArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let path = ModelsCatalog::default_path(&home);
    match args.action {
        CatalogAction::Refresh { stale_only } => {
            run_refresh(&home, &path, stale_only, args.output).await
        }
        CatalogAction::List {
            include_deprecated,
            provider,
        } => run_list(&path, include_deprecated, provider.as_deref(), args.output),
        CatalogAction::Show { provider } => run_show(&path, &provider, args.output),
        CatalogAction::Defaults => run_defaults(&path, args.output),
        CatalogAction::Clear => run_clear(&path, args.output),
    }
}

async fn run_refresh(
    home: &std::path::Path,
    path: &std::path::Path,
    stale_only: bool,
    output: OutputFormat,
) -> Result<()> {
    let config = FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))?;
    let plan = discovery::build_sources_from_config_at(&config, home)?;
    let plan = if stale_only {
        let existing = ModelsCatalog::load_snapshot_strict_from(path)?
            .map(|snapshot| snapshot.catalog)
            .unwrap_or_default();
        plan.stale_only(&existing, now_unix())
    } else {
        plan
    };
    let report = discovery::discover_with_plan(path, plan).await?;
    let receipt = CatalogRefreshReceipt::from_report(path, stale_only, &report)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&receipt)?);
        }
        _ => {
            println!("[neoth catalog refresh] {}", report.summary_line());
            if !report.fresh.is_empty() {
                println!("  fresh:     {}", report.fresh.join(", "));
            }
            if !report.refreshed.is_empty() {
                println!("  refreshed: {}", report.refreshed.join(", "));
            }
            if !report.failed.is_empty() {
                println!("  failed:    {}", report.failed.join(", "));
                println!("    → see `neoth catalog show <provider>` for the underlying error");
            }
            if !report.superseded.is_empty() {
                println!(
                    "  superseded by newer refresh/clear: {}",
                    report.superseded.join(", ")
                );
            }
            if !report.skipped_no_creds.is_empty() {
                println!(
                    "  skipped (no credentials): {}",
                    report.skipped_no_creds.join(", ")
                );
            }
            if !report.credential_failures.is_empty() {
                println!(
                    "  credential resolution failed: {}",
                    report.credential_failures.join(", ")
                );
            }
            if !report.configuration_failures.is_empty() {
                println!(
                    "  required configuration missing: {}",
                    report.configuration_failures.join(", ")
                );
            }
            if !report.unsupported.is_empty() {
                println!(
                    "  adapter has no model-list source: {}",
                    report.unsupported.join(", ")
                );
            }
            if !report.blocked_no_consent.is_empty() {
                println!(
                    "  blocked (instance consent missing): {}",
                    report.blocked_no_consent.join(", ")
                );
            }
        }
    }
    // JSON/JSONL callers must receive the typed receipt even for an incomplete
    // logical outcome. Flush it before returning a non-zero process status.
    use std::io::Write as _;
    std::io::stdout().flush()?;
    match receipt.result {
        CatalogRefreshResult::Partial => {
            anyhow::bail!("catalog refresh incomplete; inspect the provider outcome sets and retry")
        }
        CatalogRefreshResult::NoSources => anyhow::bail!(
            "catalog refresh has no configured provider source; configure a provider and retry"
        ),
        result if result.is_success() => Ok(()),
        _ => unreachable!("catalog refresh result enum is exhaustively classified"),
    }
}

/// PURE provider selection: `None` returns every cached provider; `Some(p)`
/// narrows to the single matching key (empty when `p` is absent). Split out so
/// the `--provider` filter is unit-testable without capturing stdout, and so
/// the JSON + table render paths share one source of truth.
fn select_providers<'a>(
    catalog: &'a ModelsCatalog,
    provider: Option<&str>,
) -> Vec<(&'a str, &'a ProviderCatalog)> {
    catalog
        .providers
        .iter()
        .filter(|(name, _)| provider.is_none() || provider == Some(name.as_str()))
        .map(|(name, pc)| (name.as_str(), pc))
        .collect()
}

fn run_list(
    path: &std::path::Path,
    include_deprecated: bool,
    provider: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let Some(snapshot) = ModelsCatalog::load_snapshot_strict_from(path)? else {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let receipt = CatalogListReceipt {
                    operation: CATALOG_LIST_OPERATION,
                    path: path.display().to_string(),
                    state: CatalogListState::Missing,
                    catalog_version: CATALOG_VERSION,
                    catalog_generation: None,
                    catalog_hash: None,
                    providers: std::collections::BTreeMap::new(),
                };
                println!("{}", serde_json::to_string(&receipt)?);
            }
            _ => {
                println!("[neoth catalog list] catalog empty — run `neoth catalog refresh` first");
            }
        }
        return Ok(());
    };
    let catalog = snapshot.catalog;
    validate_catalog_snapshot(&catalog)?;
    let content_hash = snapshot.content_hash;
    validate_snapshot_receipt(Some(catalog.generation), Some(&content_hash))?;
    let selected = select_providers(&catalog, provider);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let providers = selected
                .iter()
                .map(|&(name, pc)| {
                    let models = pc
                        .models
                        .iter()
                        .filter(|m| include_deprecated || !m.deprecated)
                        .cloned()
                        .collect();
                    (
                        name.to_string(),
                        CatalogListProviderReceipt {
                            fetched_at_unix: pc.fetched_at_unix,
                            source: pc.source,
                            last_error: pc.last_error.clone(),
                            models,
                        },
                    )
                })
                .collect();
            let receipt = CatalogListReceipt {
                operation: CATALOG_LIST_OPERATION,
                path: path.display().to_string(),
                state: CatalogListState::Present,
                catalog_version: CATALOG_VERSION,
                catalog_generation: Some(catalog.generation),
                catalog_hash: Some(content_hash),
                providers,
            };
            println!("{}", serde_json::to_string(&receipt)?);
        }
        _ => {
            if selected.is_empty() {
                println!("[neoth catalog list] no matching cached provider");
                return Ok(());
            }
            for &(name, pc) in &selected {
                let fresh_marker = if pc.is_fresh(now_unix(), catalog.effective_ttl_secs()) {
                    "fresh"
                } else {
                    "stale"
                };
                println!(
                    "── {name}  [{fresh_marker}, source={}, {} models]",
                    source_origin_str(pc.source),
                    pc.models.len()
                );
                for m in &pc.models {
                    if !include_deprecated && m.deprecated {
                        continue;
                    }
                    let dep_marker = if m.deprecated { " [deprecated]" } else { "" };
                    let display = m.display_name.as_deref().unwrap_or("");
                    if display.is_empty() {
                        println!("    {}{}", m.id, dep_marker);
                    } else {
                        println!("    {}{}  — {}", m.id, dep_marker, display);
                    }
                }
                if let Some(err) = &pc.last_error {
                    println!("    last_error: {err}");
                }
            }
        }
    }
    Ok(())
}

fn run_show(path: &std::path::Path, provider: &str, output: OutputFormat) -> Result<()> {
    let catalog = ModelsCatalog::load_strict_from(path)?.unwrap_or_default();
    validate_catalog_snapshot(&catalog)?;
    let Some(pc) = catalog.provider(provider) else {
        anyhow::bail!(
            "provider `{provider}` not in cached catalog. Run `neoth catalog refresh` first, \
             or `neoth catalog list` to see what's known."
        );
    };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&json!({ provider: pc }))?);
        }
        _ => render_provider_detail(provider, pc, &catalog),
    }
    Ok(())
}

fn render_provider_detail(name: &str, pc: &ProviderCatalog, catalog: &ModelsCatalog) {
    let fresh_marker = if pc.is_fresh(now_unix(), catalog.effective_ttl_secs()) {
        "fresh"
    } else {
        "stale"
    };
    let age_secs = now_unix().saturating_sub(pc.fetched_at_unix);
    let age_h = age_secs / 3600;
    let age_m = (age_secs % 3600) / 60;
    println!("Provider: {name}");
    println!("  Source:        {}", source_origin_str(pc.source));
    println!("  Fetched:       {age_h}h {age_m}m ago  [{fresh_marker}]");
    if let Some(err) = &pc.last_error {
        println!("  Last error:    {err}");
    }
    println!("  Models: {}", pc.models.len());
    for m in &pc.models {
        let dep = if m.deprecated { " [deprecated]" } else { "" };
        println!("    {}{}", m.id, dep);
        if let Some(d) = m.display_name.as_deref() {
            println!("      display: {d}");
        }
        if let Some(s) = m.summary.as_deref() {
            println!("      summary: {s}");
        }
    }
}

fn run_defaults(path: &std::path::Path, output: OutputFormat) -> Result<()> {
    let catalog = ModelsCatalog::load_strict_from(path)?.unwrap_or_default();
    validate_catalog_snapshot(&catalog)?;
    let defaults: Vec<(String, Option<String>)> = catalog
        .providers
        .iter()
        .map(|(name, pc)| (name.clone(), pc.recommended_default().map(|m| m.id.clone())))
        .collect();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let map: serde_json::Map<String, serde_json::Value> =
                defaults.into_iter().map(|(k, v)| (k, json!(v))).collect();
            println!("{}", serde_json::to_string(&json!({ "defaults": map }))?);
        }
        _ => {
            if defaults.is_empty() {
                println!(
                    "[neoth catalog defaults] catalog empty — run `neoth catalog refresh` first"
                );
                return Ok(());
            }
            for (name, default) in defaults {
                match default {
                    Some(id) => println!("  {name:<20} → {id}"),
                    None => println!("  {name:<20} → (none — catalog empty or all deprecated)"),
                }
            }
        }
    }
    Ok(())
}

fn run_clear(path: &std::path::Path, output: OutputFormat) -> Result<()> {
    if !ModelsCatalog::clear_at(path)? {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{{\"status\":\"already_empty\"}}");
            }
            _ => println!("[neoth catalog clear] catalog already empty"),
        }
        return Ok(());
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{{\"status\":\"cleared\"}}");
        }
        _ => println!("[neoth catalog clear] catalog wiped"),
    }
    Ok(())
}

fn source_origin_str(origin: SourceOrigin) -> &'static str {
    match origin {
        SourceOrigin::Cli => "cli",
        SourceOrigin::Api => "api",
        SourceOrigin::Bundled => "bundled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::catalog::{ModelEntry, ModelsCatalog};
    use tempfile::tempdir;

    fn test_catalog_hash() -> String {
        "0".repeat(64)
    }

    #[test]
    fn source_origin_str_round_trips() {
        assert_eq!(source_origin_str(SourceOrigin::Cli), "cli");
        assert_eq!(source_origin_str(SourceOrigin::Api), "api");
        assert_eq!(source_origin_str(SourceOrigin::Bundled), "bundled");
    }

    #[test]
    fn refresh_receipt_binds_operation_path_result_and_provider_sets() {
        let path = std::path::Path::new("state/models_catalog.json");
        let fresh = serde_json::to_value(
            CatalogRefreshReceipt::from_report(
                path,
                true,
                &discovery::DiscoveryReport {
                    catalog_generation: Some(7),
                    catalog_hash: Some(test_catalog_hash()),
                    configured: vec!["openai_api".into()],
                    fresh: vec!["openai_api".into()],
                    ..Default::default()
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            fresh,
            json!({
                "operation": "catalog.refresh",
                "path": path.display().to_string(),
                "catalog_version": CATALOG_VERSION,
                "catalog_generation": 7,
                "catalog_hash": test_catalog_hash(),
                "catalog_changed": false,
                "result": "fresh",
                "stale_only": true,
                "configured": ["openai_api"],
                "fresh": ["openai_api"],
                "refreshed": [],
                "failed": [],
                "superseded": [],
                "skipped_no_creds": [],
                "credential_failures": [],
                "configuration_failures": [],
                "unsupported": [],
                "blocked_no_consent": [],
            })
        );

        let report = discovery::DiscoveryReport {
            catalog_changed: true,
            catalog_generation: Some(8),
            catalog_hash: Some(test_catalog_hash()),
            configured: vec![
                "openai_api".into(),
                "anthropic_api".into(),
                "gemini_api".into(),
                "aws_bedrock".into(),
                "openai_compat".into(),
            ],
            refreshed: vec!["openai_api".into()],
            failed: vec!["anthropic_api".into()],
            skipped_no_creds: vec!["gemini_api".into()],
            credential_failures: vec!["aws_bedrock".into()],
            configuration_failures: vec!["openai_compat".into()],
            ..Default::default()
        };
        let partial =
            serde_json::to_value(CatalogRefreshReceipt::from_report(path, false, &report).unwrap())
                .unwrap();
        assert_eq!(partial["operation"], json!("catalog.refresh"));
        assert_eq!(partial["path"], json!(path.display().to_string()));
        assert_eq!(partial["catalog_version"], json!(CATALOG_VERSION));
        assert_eq!(partial["catalog_generation"], json!(8));
        assert_eq!(partial["catalog_hash"], json!(test_catalog_hash()));
        assert_eq!(partial["catalog_changed"], json!(true));
        assert_eq!(partial["result"], json!("partial"));
        assert_eq!(partial["stale_only"], json!(false));
        assert_eq!(
            partial["configured"],
            json!([
                "openai_api",
                "anthropic_api",
                "gemini_api",
                "aws_bedrock",
                "openai_compat"
            ])
        );
        assert_eq!(partial["refreshed"], json!(["openai_api"]));
        assert_eq!(partial["failed"], json!(["anthropic_api"]));
        assert_eq!(partial["superseded"], json!([]));
        assert_eq!(partial["skipped_no_creds"], json!(["gemini_api"]));
        assert_eq!(partial["credential_failures"], json!(["aws_bedrock"]));
        assert_eq!(partial["configuration_failures"], json!(["openai_compat"]));
        assert_eq!(partial["unsupported"], json!([]));
        assert_eq!(partial["blocked_no_consent"], json!([]));

        let refreshed = CatalogRefreshReceipt::from_report(
            path,
            false,
            &discovery::DiscoveryReport {
                catalog_changed: true,
                catalog_generation: Some(9),
                catalog_hash: Some(test_catalog_hash()),
                configured: vec!["openai_api".into()],
                refreshed: vec!["openai_api".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(refreshed.result, CatalogRefreshResult::Refreshed);

        let no_sources =
            CatalogRefreshReceipt::from_report(path, false, &discovery::DiscoveryReport::default())
                .unwrap();
        assert_eq!(no_sources.result, CatalogRefreshResult::NoSources);
        assert!(!no_sources.result.is_success());

        let superseded_after_clear = CatalogRefreshReceipt::from_report(
            path,
            false,
            &discovery::DiscoveryReport {
                configured: vec!["openai_api".into()],
                superseded: vec!["openai_api".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(superseded_after_clear.result, CatalogRefreshResult::Partial);
        assert!(!superseded_after_clear.catalog_changed);
        assert_eq!(superseded_after_clear.catalog_generation, None);
        assert_eq!(superseded_after_clear.catalog_hash, None);

        let unsupported = CatalogRefreshReceipt::from_report(
            path,
            false,
            &discovery::DiscoveryReport {
                configured: vec!["local_ollama".into()],
                unsupported: vec!["local_ollama".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            unsupported.result,
            CatalogRefreshResult::NoDiscoverableSources
        );
        assert!(unsupported.result.is_success());
    }

    #[test]
    fn refresh_receipt_rejects_incomplete_or_overlapping_provider_partitions() {
        let path = std::path::Path::new("state/models_catalog.json");
        for report in [
            discovery::DiscoveryReport {
                configured: vec!["openai_api".into(), "anthropic_api".into()],
                refreshed: vec!["openai_api".into()],
                ..Default::default()
            },
            discovery::DiscoveryReport {
                configured: vec!["openai_api".into()],
                fresh: vec!["openai_api".into()],
                refreshed: vec!["openai_api".into()],
                ..Default::default()
            },
            discovery::DiscoveryReport {
                configured: vec!["unknown_provider".into()],
                failed: vec!["unknown_provider".into()],
                ..Default::default()
            },
        ] {
            assert!(CatalogRefreshReceipt::from_report(path, true, &report).is_err());
        }
    }

    #[tokio::test]
    async fn refresh_without_configured_sources_returns_nonzero_after_receipt_creation() {
        let home = tempdir().unwrap();
        let path = home.path().join("models_catalog.json");
        let error = run_refresh(home.path(), &path, false, OutputFormat::Json)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no configured provider source"));
        assert!(!path.exists());
    }

    #[test]
    fn clear_handles_missing_file_gracefully() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        run_clear(&path, OutputFormat::Table).expect("must succeed on missing file");
    }

    #[test]
    fn clear_removes_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        std::fs::write(&path, b"{}").unwrap();
        assert!(path.exists());
        run_clear(&path, OutputFormat::Table).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn list_on_empty_catalog_does_not_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        run_list(&path, false, None, OutputFormat::Json).expect("must succeed on empty catalog");
    }

    #[test]
    fn list_rejects_malformed_or_semantically_invalid_catalogs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        assert!(run_list(&path, false, None, OutputFormat::Json).is_err());

        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.providers.insert(
            "future_provider".into(),
            ProviderCatalog {
                fetched_at_unix: 1,
                source: SourceOrigin::Api,
                models: vec![ModelEntry::new("model")],
                ..Default::default()
            },
        );
        catalog.save().unwrap();
        assert!(run_list(&path, false, None, OutputFormat::Json).is_err());

        catalog.providers.clear();
        catalog.providers.insert(
            "openai_api".into(),
            ProviderCatalog {
                fetched_at_unix: 1,
                source: SourceOrigin::Api,
                models: vec![ModelEntry::new("same"), ModelEntry::new("same")],
                ..Default::default()
            },
        );
        catalog.save().unwrap();
        assert!(run_list(&path, false, None, OutputFormat::Json).is_err());
    }

    #[test]
    fn select_providers_filters_to_one_or_returns_all() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut cat = ModelsCatalog::default().with_path(path);
        cat.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![ModelEntry::new("claude-opus-4-7")],
        );
        cat.upsert(
            "gemini_api",
            SourceOrigin::Api,
            vec![ModelEntry::new("gemini-3.1-pro")],
        );
        // None → every cached provider.
        assert_eq!(select_providers(&cat, None).len(), 2);
        // Some(match) → exactly that one key.
        let one = select_providers(&cat, Some("anthropic_api"));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].0, "anthropic_api");
        // Some(no-match) → empty (run_list then prints the empty envelope).
        assert!(select_providers(&cat, Some("does_not_exist")).is_empty());
    }

    #[test]
    fn list_with_provider_filter_does_not_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut cat = ModelsCatalog::default().with_path(path.clone());
        cat.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![ModelEntry::new("claude-opus-4-7")],
        );
        cat.save().unwrap();
        run_list(&path, false, Some("anthropic_api"), OutputFormat::Json)
            .expect("filtered list ok");
        run_list(&path, false, Some("absent"), OutputFormat::Json)
            .expect("absent provider → empty ok");
    }

    #[test]
    fn defaults_on_empty_catalog_does_not_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        run_defaults(&path, OutputFormat::Json).expect("must succeed on empty catalog");
    }

    #[test]
    fn show_errors_when_provider_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let err = run_show(&path, "anthropic_api", OutputFormat::Table)
            .expect_err("must bail on missing provider");
        assert!(err.to_string().contains("not in cached catalog"));
    }

    #[test]
    fn show_renders_provider_present_in_catalog() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut cat = ModelsCatalog::default().with_path(path.clone());
        cat.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![ModelEntry::new("claude-opus-4-7")],
        );
        cat.save().unwrap();
        run_show(&path, "anthropic_api", OutputFormat::Json).expect("must succeed");
    }
}
