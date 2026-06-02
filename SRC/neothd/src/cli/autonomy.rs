//! `neoth autonomy` — view + set the operator autonomy level in freedom.yaml.
//!
//! Autonomy (`strict | standard | elevated | full | custom`) gates EVERY tool
//! and provider call via [`crate::permissions::evaluate`]. It is picked at
//! onboarding (`neoth init --autonomy <level>`) and inspected by
//! `neoth permissions show`; this command is the post-onboarding setter/getter
//! so operators retune WITHOUT re-running the wizard or hand-editing YAML.
//!
//! `set` persists through [`crate::config::FreedomConfig::save_public_to_default_path`]
//! — the same atomic, 0600, secrets-stripped write `neoth hemispheres set`
//! already uses, so it never leaks keys into freedom.yaml.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::permissions::AutonomyLevel;

#[derive(Args, Debug, Clone)]
pub struct AutonomyArgs {
    #[command(subcommand)]
    pub action: AutonomyAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AutonomyAction {
    /// Print the current autonomy level (read from freedom.yaml).
    Show,
    /// Set the autonomy level in freedom.yaml. Persists immediately; takes
    /// effect on the next command / daemon config reload.
    Set {
        /// One of: `strict` | `standard` | `elevated` | `full` | `custom`.
        level: String,
    },
}

/// Pure core of `set`: validate `level`, return the config with the new
/// autonomy applied plus the PREVIOUS level. Separated from disk I/O so the
/// validation + mutation are hermetically testable. Rejects unknown levels
/// with the canonical list in the message.
fn apply_level(cfg: FreedomConfig, level: &str) -> Result<(FreedomConfig, AutonomyLevel)> {
    let parsed = AutonomyLevel::from_str(&level.trim().to_ascii_lowercase()).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid autonomy level `{level}` — expected one of: strict, standard, elevated, full, custom"
        )
    })?;
    let previous = cfg.autonomy;
    let mut next = cfg;
    next.autonomy = parsed;
    Ok((next, previous))
}

pub fn run_autonomy(args: AutonomyArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        AutonomyAction::Show => run_show(output),
        AutonomyAction::Set { level } => run_set(&level, output),
    }
}

fn run_show(output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().context(
        "load freedom.yaml (run `neoth init` first if this is a fresh install)",
    )?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({ "autonomy": cfg.autonomy.as_str() })
        ),
        OutputFormat::Table => println!("autonomy: {}", cfg.autonomy.as_str()),
    }
    Ok(())
}

fn run_set(level: &str, output: OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().context(
        "load freedom.yaml (run `neoth init` first if this is a fresh install)",
    )?;
    let (next, previous) = apply_level(cfg, level)?;
    let applied = next.autonomy;
    next.save_public_to_default_path()
        .context("persist the new autonomy level to freedom.yaml")?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "autonomy": applied.as_str(),
                "previous": previous.as_str(),
                "changed": applied != previous,
            })
        ),
        OutputFormat::Table => {
            if applied == previous {
                println!("autonomy unchanged: {} (already set)", applied.as_str());
            } else {
                println!(
                    "autonomy: {} -> {} (saved to freedom.yaml)",
                    previous.as_str(),
                    applied.as_str()
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_level_accepts_every_level_and_reports_previous() {
        for (s, expected) in [
            ("strict", AutonomyLevel::Strict),
            ("standard", AutonomyLevel::Standard),
            ("elevated", AutonomyLevel::Elevated),
            ("full", AutonomyLevel::Full),
            ("custom", AutonomyLevel::Custom),
        ] {
            let cfg = FreedomConfig::default(); // default autonomy = Standard
            let (next, prev) = apply_level(cfg, s).expect("valid level");
            assert_eq!(next.autonomy, expected, "level {s} must apply");
            assert_eq!(prev, AutonomyLevel::Standard, "previous is the default");
        }
    }

    #[test]
    fn apply_level_is_case_and_whitespace_insensitive() {
        let (next, _) = apply_level(FreedomConfig::default(), "  ELEVATED  ").expect("normalized");
        assert_eq!(next.autonomy, AutonomyLevel::Elevated);
    }

    #[test]
    fn apply_level_rejects_unknown_with_canonical_list() {
        let err = apply_level(FreedomConfig::default(), "yolo").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid autonomy level"), "got: {msg}");
        assert!(msg.contains("strict") && msg.contains("full"), "lists valid levels: {msg}");
    }

    #[test]
    fn apply_level_does_not_touch_other_fields() {
        // Only `autonomy` changes — a regression here would silently reset
        // operator config on every `autonomy set`.
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Strict;
        let baseline = cfg.clone();
        let (next, _) = apply_level(cfg, "full").expect("valid");
        assert_eq!(next.autonomy, AutonomyLevel::Full);
        // Everything except autonomy is identical.
        let mut next_normalized = next.clone();
        next_normalized.autonomy = baseline.autonomy;
        assert_eq!(
            serde_yaml::to_string(&next_normalized).unwrap(),
            serde_yaml::to_string(&baseline).unwrap(),
            "no field other than autonomy may change"
        );
    }
}
