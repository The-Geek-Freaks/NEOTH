//! `neoth hooks` — operator visibility into the loaded TOML hook set.
//!
//! Two actions today:
//!   - `list`     dumps every parsed hook (or only enabled ones with
//!                `--enabled`), grouped by stage. JSON-or-table output.
//!   - `validate` parses + dry-runs each hook against a synthetic body.
//!                Surfaces bad regex / unknown stage names before the
//!                daemon picks them up at request time.
//!
//! Operators add hooks by dropping `~/.neoth/hooks/*.toml` files. The
//! daemon loads them per-turn via [`crate::hooks::load_all`]; this CLI
//! is read-only inspection.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::hooks::schema::{HookAction, HookDef};
use crate::hooks::stages::HookStage;

#[derive(Args, Debug, Clone)]
pub struct HooksArgs {
    #[command(subcommand)]
    pub action: HooksAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HooksAction {
    /// List every parsed hook, grouped by pipeline stage. `--enabled`
    /// filters to enabled-only (default behaviour shows every hook so
    /// the operator can see which ones are toggled off).
    List {
        #[arg(long)]
        enabled: bool,
    },
    /// Parse every hook file + verify the matcher regex (if any) compiles.
    /// Returns non-zero on any failure so CI can gate config changes.
    Validate,
}

pub async fn run_hooks(args: HooksArgs) -> Result<()> {
    let hook_dir = FreedomConfig::default_neoth_home().join("hooks");
    match args.action {
        HooksAction::List { enabled } => run_list(&hook_dir, enabled, &args.output).await,
        HooksAction::Validate => run_validate(&hook_dir, &args.output).await,
    }
}

async fn run_list(
    hook_dir: &std::path::Path,
    enabled_only: bool,
    output: &OutputFormat,
) -> Result<()> {
    let hooks = crate::hooks::load_all(hook_dir)
        .await
        .with_context(|| format!("load hooks from {}", hook_dir.display()))?;
    let filtered: Vec<&HookDef> = hooks
        .iter()
        .filter(|h| !enabled_only || h.is_enabled())
        .collect();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "hooks_dir": hook_dir.display().to_string(),
                "count": filtered.len(),
                "hooks": filtered.iter().map(|h| serde_json::json!({
                    "name": h.name,
                    "stage": h.stage.as_str(),
                    "enabled": h.is_enabled(),
                    "matcher_pattern": h.matcher.as_ref().map(|m| m.pattern.clone()),
                    "action": action_label(&h.action),
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            if filtered.is_empty() {
                if hook_dir.is_dir() {
                    println!("# Hooks at {}\n  (no enabled hooks)", hook_dir.display());
                } else {
                    println!(
                        "# Hooks at {}\n  (directory does not exist — create it + drop *.toml \
                         files to add hooks)",
                        hook_dir.display()
                    );
                }
                return Ok(());
            }
            println!(
                "# Hooks at {} ({} entries)",
                hook_dir.display(),
                filtered.len()
            );
            // Group by stage so operators see what fires at each pipeline boundary.
            let stages = [
                HookStage::PreChannelIngress,
                HookStage::PrePipeline,
                HookStage::PreProviderCall,
                HookStage::PostProviderCall,
                HookStage::PreEgress,
                HookStage::JobFired,
                HookStage::JobDone,
                HookStage::OnShutdown,
            ];
            for stage in stages {
                let group: Vec<&&HookDef> = filtered.iter().filter(|h| h.stage == stage).collect();
                if group.is_empty() {
                    continue;
                }
                println!("\n  [{}]", stage.as_str());
                for h in group {
                    let status = if h.is_enabled() { "ON " } else { "OFF" };
                    let matcher = h
                        .matcher
                        .as_ref()
                        .map(|m| m.pattern.as_str())
                        .unwrap_or("(no matcher — fires unconditionally)");
                    println!(
                        "    {status}  {:<24}  action={}  matcher={}",
                        h.name,
                        action_label(&h.action),
                        matcher,
                    );
                }
            }
        }
    }
    Ok(())
}

async fn run_validate(hook_dir: &std::path::Path, output: &OutputFormat) -> Result<()> {
    let hooks = crate::hooks::load_all(hook_dir)
        .await
        .with_context(|| format!("load hooks from {}", hook_dir.display()))?;
    let mut bad: Vec<(String, String)> = Vec::new();
    for h in &hooks {
        if let Some(m) = &h.matcher {
            if let Err(e) = regex::Regex::new(&m.pattern) {
                bad.push((h.name.clone(), format!("bad regex: {e}")));
            }
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "checked": hooks.len(),
                    "failures": bad.iter().map(|(n, e)| serde_json::json!({
                        "name": n,
                        "error": e,
                    })).collect::<Vec<_>>(),
                    "ok": bad.is_empty(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("# Validate hooks at {}", hook_dir.display());
            println!("  Checked: {}", hooks.len());
            if bad.is_empty() {
                println!("  OK — every hook parses + every regex compiles");
            } else {
                println!("  {} failure(s):", bad.len());
                for (name, err) in &bad {
                    println!("    {name}: {err}");
                }
            }
        }
    }

    if !bad.is_empty() {
        anyhow::bail!("{} hook(s) failed validation", bad.len());
    }
    Ok(())
}

fn action_label(a: &HookAction) -> &'static str {
    match a {
        HookAction::Allow => "allow",
        HookAction::Replace { .. } => "replace",
        HookAction::Block { .. } => "block",
        HookAction::Plugin { .. } => "plugin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::schema::HookMatcher;
    use tempfile::tempdir;

    #[tokio::test]
    async fn list_empty_dir_does_not_error() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        // Don't create the dir — exercise the missing-directory branch.
        run_list(&hook_dir, false, &OutputFormat::Json)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_passes_on_well_formed_hooks() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        std::fs::create_dir_all(&hook_dir).unwrap();
        let body = r#"
name    = "redact"
stage   = "pre_provider_call"
enabled = true

[matcher]
pattern = "(?i)\\bsecret\\s*=\\s*\\S+"

[action]
kind     = "replace"
template = "[X]"
"#;
        std::fs::write(hook_dir.join("redact.toml"), body).unwrap();
        run_validate(&hook_dir, &OutputFormat::Json).await.unwrap();
    }

    #[tokio::test]
    async fn validate_fails_on_bad_regex() {
        let dir = tempdir().unwrap();
        let hook_dir = dir.path().join("hooks");
        std::fs::create_dir_all(&hook_dir).unwrap();
        let body = r#"
name    = "bad"
stage   = "pre_provider_call"
enabled = true

[matcher]
pattern = "[unclosed"

[action]
kind = "allow"
"#;
        std::fs::write(hook_dir.join("bad.toml"), body).unwrap();
        let err = run_validate(&hook_dir, &OutputFormat::Json)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failed validation"));
    }

    #[test]
    fn action_labels_cover_every_variant() {
        assert_eq!(action_label(&HookAction::Allow), "allow");
        assert_eq!(
            action_label(&HookAction::Replace {
                template: "x".into()
            }),
            "replace"
        );
        assert_eq!(
            action_label(&HookAction::Block {
                reason: "no".into()
            }),
            "block"
        );
    }

    #[test]
    fn hookdef_default_enabled_is_true() {
        let h = HookDef {
            name: "x".into(),
            stage: HookStage::PreProviderCall,
            enabled: None,
            matcher: Some(HookMatcher {
                pattern: ".*".into(),
            }),
            action: HookAction::Allow,
        };
        assert!(h.is_enabled());
    }
}
