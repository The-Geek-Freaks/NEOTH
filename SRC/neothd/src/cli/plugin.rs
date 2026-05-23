//! `neoth plugin` — D-102 (Session 21, 2026-05-23) operator-facing
//! activation management for WASM plugins.
//!
//! The 6/6 agent panel verdict: default-inactive. The daemon never
//! instantiates a discovered `.wasm` until the operator runs `neoth
//! plugin enable <id>` (or accepts it via the first-run wizard
//! multiselect step).
//!
//! Subcommands:
//!   - `list`    every discovered plugin + its activation state
//!   - `pending` only the discovered-but-unconfirmed plugins
//!   - `enable <id>`  flip Pending|Disabled → Active
//!   - `disable <id>` flip Pending|Active   → Disabled
//!
//! Activation state lives in `freedom.yaml::plugins.wasm.activations`
//! keyed by plugin manifest id. Mutations go through
//! [`FreedomConfig::save_public_to_default_path`] so the on-disk
//! representation is the authoritative source for the next daemon
//! boot.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::wasm_plugin::discovery::{PluginActivation, discover};

#[derive(Args, Debug, Clone)]
pub struct PluginArgs {
    #[command(subcommand)]
    pub action: PluginAction,

    /// Output format (inherited from global --output flag).
    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PluginAction {
    /// List every discovered plugin + its operator activation state.
    /// Plugins NOT yet listed in freedom.yaml::plugins.wasm.activations
    /// show as `pending` (the default for any newly discovered id).
    List,
    /// Show only the discovered-but-not-yet-decided plugins. Operator
    /// review queue.
    Pending,
    /// Flip a plugin to `active`. Idempotent — already-active plugins
    /// return success without rewriting freedom.yaml.
    Enable {
        /// Plugin manifest id (matches the directory name under
        /// `~/.neoth/plugins/<id>/`).
        id: String,
    },
    /// Flip a plugin to `disabled`. Idempotent.
    Disable { id: String },
}

pub async fn run_plugin(args: PluginArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        PluginAction::List => render_list(&home, args.output, false),
        PluginAction::Pending => render_list(&home, args.output, true),
        PluginAction::Enable { id } => set_activation(&home, &id, PluginActivation::Active, args.output),
        PluginAction::Disable { id } => set_activation(&home, &id, PluginActivation::Disabled, args.output),
    }
}

fn render_list(home: &std::path::Path, output: OutputFormat, only_pending: bool) -> Result<()> {
    let plugins_root = home.join("plugins");
    let report = discover(&plugins_root);
    let activations = load_activations()?;

    let mut rows: Vec<(String, PluginActivation, String)> = report
        .loaded
        .iter()
        .map(|p| {
            let state = activations
                .get(&p.manifest.id)
                .copied()
                .unwrap_or_default();
            (p.manifest.id.clone(), state, p.manifest.name.clone())
        })
        .collect();
    if only_pending {
        rows.retain(|(_, s, _)| *s == PluginActivation::Pending);
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload: Vec<serde_json::Value> = rows
                .iter()
                .map(|(id, state, name)| {
                    json!({
                        "id": id,
                        "name": name,
                        "activation": state.as_str(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                if only_pending {
                    println!("No plugins awaiting activation.");
                } else {
                    println!("No plugins discovered under ~/.neoth/plugins/");
                    println!();
                    println!("Drop a `<plugins-dir>/<id>/{{plugin.toml, plugin.wasm}}` pair");
                    println!("to surface entries here. They default to PENDING; run");
                    println!("`neoth plugin enable <id>` to opt them in.");
                }
                return Ok(());
            }
            println!("{:<24}  {:<10}  NAME", "ID", "STATE");
            println!("{:<24}  {:<10}  ----", "--", "-----");
            for (id, state, name) in &rows {
                println!("{:<24}  {:<10}  {}", id, state.as_str(), name);
            }
            if only_pending {
                println!();
                println!("Run `neoth plugin enable <id>` to activate.");
            }
        }
    }
    Ok(())
}

fn set_activation(
    home: &std::path::Path,
    id: &str,
    new_state: PluginActivation,
    output: OutputFormat,
) -> Result<()> {
    // Validate the id actually corresponds to a discovered plugin —
    // typo'd ids should fail loudly rather than silently writing a
    // stranded activation entry to freedom.yaml.
    let plugins_root = home.join("plugins");
    let report = discover(&plugins_root);
    let id_known = report.loaded.iter().any(|p| p.manifest.id == id);
    if !id_known {
        let discovered: Vec<&str> = report
            .loaded
            .iter()
            .map(|p| p.manifest.id.as_str())
            .collect();
        anyhow::bail!(
            "no plugin with id `{id}` discovered under {}. Found: {:?}. \
             Check the directory name matches the manifest `id`.",
            plugins_root.display(),
            discovered
        );
    }

    let mut cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml to update plugin activation")?;
    let prev = cfg
        .plugins
        .wasm
        .activations
        .get(id)
        .copied()
        .unwrap_or_default();
    if prev == new_state {
        emit_unchanged(id, new_state, output);
        return Ok(());
    }
    cfg.plugins.wasm.activations.insert(id.to_string(), new_state);
    cfg.save_public_to_default_path()
        .context("save freedom.yaml after plugin activation change")?;

    emit_changed(id, prev, new_state, output);
    Ok(())
}

fn emit_changed(
    id: &str,
    prev: PluginActivation,
    new: PluginActivation,
    output: OutputFormat,
) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload = json!({
                "id": id,
                "previous": prev.as_str(),
                "new": new.as_str(),
                "changed": true,
            });
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        }
        OutputFormat::Table => {
            println!(
                "Plugin `{id}` activation: {} → {}",
                prev.as_str(),
                new.as_str()
            );
            if matches!(new, PluginActivation::Active) {
                println!(
                    "The plugin will instantiate on the next `neoth serve` boot."
                );
            }
        }
    }
}

fn emit_unchanged(id: &str, state: PluginActivation, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload = json!({
                "id": id,
                "previous": state.as_str(),
                "new": state.as_str(),
                "changed": false,
            });
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        }
        OutputFormat::Table => {
            println!("Plugin `{id}` already {} — no change.", state.as_str());
        }
    }
}

fn load_activations() -> Result<BTreeMap<String, PluginActivation>> {
    match FreedomConfig::load_from_default_path() {
        Ok(cfg) => Ok(cfg.plugins.wasm.activations.clone()),
        Err(_) => Ok(BTreeMap::new()),
    }
}

#[cfg(test)]
mod tests {
    use crate::wasm_plugin::discovery::PluginActivation;

    #[test]
    fn activation_default_is_pending() {
        assert_eq!(PluginActivation::default(), PluginActivation::Pending);
    }

    #[test]
    fn activation_is_active_only_for_active() {
        assert!(PluginActivation::Active.is_active());
        assert!(!PluginActivation::Pending.is_active());
        assert!(!PluginActivation::Disabled.is_active());
    }

    #[test]
    fn activation_as_str_round_trips_via_serde() {
        for s in [
            PluginActivation::Pending,
            PluginActivation::Active,
            PluginActivation::Disabled,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: PluginActivation = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
            assert_eq!(s.as_str(), json.trim_matches('"'));
        }
    }
}
