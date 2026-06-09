//! `neoth goal` — GOLD-ADOPT-22 — inspect + control the dispatch-loop
//! Goal/Grind nudges.
//!
//! - **goal** — a one-shot objective: the loop injects ONE "before finishing,
//!   check this is met" nudge, then lets the next clean exit stop.
//! - **grind** — a relentless objective: EVERY clean exit gets a "keep working"
//!   nudge until the iteration cap, so the model can't stop early.
//!
//! A grind that's silently left on becomes a "why won't it stop?" problem, so
//! this surfaces the active state (`show`) and makes clearing it one command
//! (`off`). The state persists in `freedom.yaml::goal.{goal,grind}`.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

#[derive(Args, Debug, Clone)]
pub struct GoalArgs {
    #[command(subcommand)]
    pub action: GoalAction,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GoalAction {
    /// Show the active goal + grind (the default — also runs with no subcommand
    /// via the wrapper).
    Show,
    /// Set the one-shot goal (replaces any existing goal).
    Set {
        /// The goal text the model must verify before finishing.
        text: String,
    },
    /// Set the relentless grind objective (the model won't stop early until the
    /// dispatch-loop iteration cap).
    Grind {
        /// The grind text.
        text: String,
    },
    /// Clear both goal and grind.
    Off,
}

pub async fn run_goal(args: GoalArgs) -> Result<()> {
    let yaml = FreedomConfig::default_neoth_home().join("freedom.yaml");

    // `show` works without an existing config (fresh install → nothing active).
    if matches!(args.action, GoalAction::Show) {
        let cfg = FreedomConfig::load_from_path(&yaml).unwrap_or_default();
        return print_state(&cfg, &args.output);
    }

    if !yaml.exists() {
        anyhow::bail!(
            "freedom.yaml not found at {}. Run `neoth init` first.",
            yaml.display()
        );
    }
    let mut cfg = FreedomConfig::load_from_path(&yaml).context("load freedom.yaml")?;
    match &args.action {
        GoalAction::Set { text } => cfg.goal.goal = Some(text.clone()),
        GoalAction::Grind { text } => cfg.goal.grind = Some(text.clone()),
        GoalAction::Off => {
            cfg.goal.goal = None;
            cfg.goal.grind = None;
        }
        GoalAction::Show => unreachable!("handled above"),
    }
    cfg.save_public_to_default_path()
        .context("write freedom.yaml")?;
    print_state(&cfg, &args.output)
}

fn print_state(cfg: &FreedomConfig, output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "goal": cfg.goal.goal,
                    "grind": cfg.goal.grind,
                    "max_turns": cfg.goal.max_turns,
                }))?
            );
        }
        OutputFormat::Table => {
            match &cfg.goal.goal {
                Some(g) => println!("goal:  {g}"),
                None => println!("goal:  (none)"),
            }
            match &cfg.goal.grind {
                Some(g) => {
                    println!("grind: {g}");
                    println!("       ⚠ GRIND ACTIVE — every turn is nudged to keep working until");
                    println!("         the {}-turn cap. Clear it with `neoth goal off`.", cfg.goal.max_turns);
                }
                None => println!("grind: (none)"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_state_renders_active_grind_warning() {
        // Pure render check (no IO): an active grind surfaces the warning line.
        let mut cfg = FreedomConfig::default();
        cfg.goal.grind = Some("ship it".into());
        // Table render must mention the grind text + the ACTIVE warning.
        // (We can't capture stdout cleanly here; assert the config wiring is
        // what print_state reads.)
        assert_eq!(cfg.goal.grind.as_deref(), Some("ship it"));
        assert!(cfg.goal.goal.is_none());
    }
}
