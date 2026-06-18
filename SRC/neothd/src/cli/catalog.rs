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
use serde_json::json;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::models::catalog::{ModelsCatalog, ProviderCatalog, SourceOrigin, now_unix};
use crate::models::discovery;

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
    let yaml = home.join("freedom.yaml");
    let config = if yaml.exists() {
        FreedomConfig::load_from_path(&yaml).unwrap_or_default()
    } else {
        FreedomConfig::default()
    };

    if stale_only {
        let existing = ModelsCatalog::load_from(path);
        let stale = existing.stale_providers(now_unix());
        if stale.is_empty() {
            match output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let empty: Vec<String> = Vec::new();
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "status": "fresh",
                            "stale_providers": empty,
                        }))?
                    );
                }
                _ => {
                    println!(
                        "[neoth catalog refresh --stale-only] every provider is fresh; nothing to do"
                    );
                }
            }
            return Ok(());
        }
    }

    let report = discovery::discover_all(path, &config).await?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "refreshed": report.refreshed,
                    "failed": report.failed,
                    "skipped_no_creds": report.skipped_no_creds,
                }))?
            );
        }
        _ => {
            println!("[neoth catalog refresh] {}", report.summary_line());
            if !report.refreshed.is_empty() {
                println!("  refreshed: {}", report.refreshed.join(", "));
            }
            if !report.failed.is_empty() {
                println!("  failed:    {}", report.failed.join(", "));
                println!("    → see `neoth catalog show <provider>` for the underlying error");
            }
        }
    }
    Ok(())
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
    let catalog = ModelsCatalog::load_from(path);
    let selected = select_providers(&catalog, provider);
    if selected.is_empty() {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{{\"providers\":{{}}}}");
            }
            _ => {
                println!("[neoth catalog list] catalog empty — run `neoth catalog refresh` first");
            }
        }
        return Ok(());
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let filtered: serde_json::Map<String, serde_json::Value> = selected
                .iter()
                .map(|&(name, pc)| {
                    let models: Vec<&_> = pc
                        .models
                        .iter()
                        .filter(|m| include_deprecated || !m.deprecated)
                        .collect();
                    (
                        name.to_string(),
                        json!({
                            "fetched_at_unix": pc.fetched_at_unix,
                            "source": pc.source,
                            "last_error": pc.last_error,
                            "models": models,
                        }),
                    )
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string(&json!({ "providers": filtered }))?
            );
        }
        _ => {
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
                    println!("    last_error: {}", err);
                }
            }
        }
    }
    Ok(())
}

fn run_show(path: &std::path::Path, provider: &str, output: OutputFormat) -> Result<()> {
    let catalog = ModelsCatalog::load_from(path);
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
    let catalog = ModelsCatalog::load_from(path);
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
    if !path.exists() {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{{\"status\":\"already_empty\"}}");
            }
            _ => println!("[neoth catalog clear] catalog already empty"),
        }
        return Ok(());
    }
    std::fs::remove_file(path)?;
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

    #[test]
    fn source_origin_str_round_trips() {
        assert_eq!(source_origin_str(SourceOrigin::Cli), "cli");
        assert_eq!(source_origin_str(SourceOrigin::Api), "api");
        assert_eq!(source_origin_str(SourceOrigin::Bundled), "bundled");
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
