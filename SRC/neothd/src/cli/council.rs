//! `neoth council` — operator UI for the Pick #8 smartest-wins
//! features (Session 14 Pick #14).
//!
//! The Pick #8 stack shipped behind opt-in flags: `selection_mode`,
//! `self_reflect_enabled`, `refine_threshold`, etc. Editing
//! `freedom.yaml` by hand is error-prone (typos in enum variants,
//! missing fields silently default-off). This CLI surfaces the
//! controls + the memory-routing observability so operators see
//! what NEOTH has learned about their workload.
//!
//! Subcommands:
//!
//!   - `tune`        Toggle smartest-wins / self-reflect / refine
//!                   threshold in freedom.yaml atomically.
//!   - `weights`     Inspect `~/.neoth/routing_weights.json` —
//!                   per-(topic, role) Hebbian acceptance signals.
//!   - `show`        Print the current `council` config block.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::inference::SelectionMode;
use crate::memory::routing_weights::{RoutingWeights, now_unix};

#[derive(Args, Debug, Clone)]
pub struct CouncilArgs {
    #[command(subcommand)]
    pub action: CouncilAction,

    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CouncilAction {
    /// Print the active `council` config block from freedom.yaml.
    Show,

    /// Atomically modify the `council` config block in freedom.yaml.
    /// Each flag is optional; only the ones you pass get updated.
    Tune {
        /// Set selection mode. Values: `legacy_majority` (default;
        /// v0.1 behaviour), `consensus_or_best` (Verdict::Consensus
        /// wins on agreement, else quality-score), `best_always`
        /// (always pick by quality score).
        #[arg(long, value_name = "MODE")]
        selection_mode: Option<String>,

        /// Toggle self-reflect refinement pass. `true` enables the
        /// threshold-gated, depth=0-only second-call refinement.
        #[arg(long)]
        self_reflect: Option<bool>,

        /// Composite quality score threshold below which the
        /// refinement pass fires (range [0.0, 1.0]; default 0.90).
        #[arg(long, value_name = "T")]
        refine_threshold: Option<f32>,

        /// Hard cap on LLM calls per user message (BudgetToken
        /// schema field; default 15).
        #[arg(long, value_name = "N")]
        max_calls: Option<u32>,

        /// Daily USD budget cap (set to 0 to disable).
        #[arg(long, value_name = "USD")]
        daily_usd_cap: Option<f32>,

        /// Print what would change without writing freedom.yaml.
        #[arg(long)]
        dry_run: bool,
    },

    /// Inspect the memory-routing weights. Each row records a
    /// `(topic_hash, hemisphere_role)` pair's Hebbian-decayed
    /// acceptance count. Read-only.
    Weights {
        /// Operator-readable cap on rows printed. Defaults to 20.
        #[arg(long, value_name = "N")]
        top_n: Option<usize>,

        /// Filter to one hemisphere role: `left`, `right`,
        /// `cerebellum`. Default: all three.
        #[arg(long, value_name = "ROLE")]
        role: Option<String>,
    },
}

pub async fn run_council(args: CouncilArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        CouncilAction::Show => run_show(&home, args.output),
        CouncilAction::Tune {
            selection_mode,
            self_reflect,
            refine_threshold,
            max_calls,
            daily_usd_cap,
            dry_run,
        } => run_tune(
            &home,
            selection_mode,
            self_reflect,
            refine_threshold,
            max_calls,
            daily_usd_cap,
            dry_run,
            args.output,
        ),
        CouncilAction::Weights { top_n, role } => {
            run_weights(&home, top_n, role.as_deref(), args.output)
        }
    }
}

fn run_show(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let yaml = home.join("freedom.yaml");
    let cfg = if yaml.exists() {
        FreedomConfig::load_from_path(&yaml).unwrap_or_default()
    } else {
        FreedomConfig::default()
    };
    let council = &cfg.council;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let j = json!({
                "selection_mode": selection_mode_as_str(council.selection_mode),
                "self_reflect_enabled": council.self_reflect_enabled,
                "refine_threshold": council.effective_refine_threshold(),
                "max_calls_per_user_message": council.effective_max_calls(),
                "daily_usd_cap": council.daily_usd_cap,
                "max_background_connections": council.effective_max_background_connections(),
                "diversity_bonus_weight": council.effective_diversity_bonus_weight(),
                "max_recursion_depth": council.effective_max_recursion_depth(),
            });
            println!("{}", serde_json::to_string_pretty(&j)?);
        }
        OutputFormat::Table => {
            println!("# council config (~/.neoth/freedom.yaml)");
            println!(
                "  selection_mode:           {}",
                selection_mode_as_str(council.selection_mode)
            );
            println!(
                "  self_reflect_enabled:     {}",
                council.self_reflect_enabled
            );
            println!(
                "  refine_threshold:         {:.2} (effective)",
                council.effective_refine_threshold()
            );
            println!(
                "  max_calls_per_user_msg:   {}",
                council.effective_max_calls()
            );
            println!(
                "  daily_usd_cap:            {}",
                council
                    .daily_usd_cap
                    .map(|n| format!("${n:.2}"))
                    .unwrap_or_else(|| "(none)".into())
            );
            println!(
                "  max_background_connect:   {}",
                council.effective_max_background_connections()
            );
            println!(
                "  diversity_bonus_weight:   {:.2}",
                council.effective_diversity_bonus_weight()
            );
            println!(
                "  max_recursion_depth:      {}",
                council.effective_max_recursion_depth()
            );
            println!();
            println!("(use `neoth council tune --selection-mode X --self-reflect true` to change)");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_tune(
    home: &std::path::Path,
    selection_mode: Option<String>,
    self_reflect: Option<bool>,
    refine_threshold: Option<f32>,
    max_calls: Option<u32>,
    daily_usd_cap: Option<f32>,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let yaml = home.join("freedom.yaml");
    if !yaml.exists() {
        anyhow::bail!(
            "freedom.yaml not found at {}. Run `neoth init` first.",
            yaml.display()
        );
    }
    let mut cfg = FreedomConfig::load_from_path(&yaml).context("load freedom.yaml")?;
    let mut changes: Vec<(&'static str, String, String)> = Vec::new();

    if let Some(mode_str) = selection_mode {
        let parsed = parse_selection_mode(&mode_str)?;
        let before = selection_mode_as_str(cfg.council.selection_mode).to_string();
        let after = selection_mode_as_str(parsed).to_string();
        if before != after {
            cfg.council.selection_mode = parsed;
            changes.push(("selection_mode", before, after));
        }
    }
    if let Some(sr) = self_reflect {
        let before = cfg.council.self_reflect_enabled;
        if before != sr {
            cfg.council.self_reflect_enabled = sr;
            changes.push(("self_reflect_enabled", before.to_string(), sr.to_string()));
        }
    }
    if let Some(t) = refine_threshold {
        if !(0.0..=1.0).contains(&t) {
            anyhow::bail!("refine_threshold {t} out of [0.0, 1.0]");
        }
        let before = cfg.council.refine_threshold.unwrap_or(0.9);
        cfg.council.refine_threshold = Some(t);
        changes.push((
            "refine_threshold",
            format!("{before:.2}"),
            format!("{t:.2}"),
        ));
    }
    if let Some(n) = max_calls {
        if n == 0 {
            anyhow::bail!("max_calls must be >= 1");
        }
        let before = cfg.council.effective_max_calls();
        cfg.council.max_calls_per_user_message = Some(n);
        changes.push((
            "max_calls_per_user_message",
            before.to_string(),
            n.to_string(),
        ));
    }
    if let Some(usd) = daily_usd_cap {
        let before = cfg
            .council
            .daily_usd_cap
            .map(|n| format!("${n:.2}"))
            .unwrap_or_else(|| "(none)".into());
        cfg.council.daily_usd_cap = if usd <= 0.0 { None } else { Some(usd) };
        let after = cfg
            .council
            .daily_usd_cap
            .map(|n| format!("${n:.2}"))
            .unwrap_or_else(|| "(none)".into());
        changes.push(("daily_usd_cap", before, after));
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let j = json!({
                "dry_run": dry_run,
                "changes": changes.iter()
                    .map(|(field, before, after)| json!({
                        "field": field,
                        "before": before,
                        "after": after,
                    }))
                    .collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&j)?);
        }
        OutputFormat::Table => {
            if changes.is_empty() {
                println!(
                    "[neoth council tune] no changes — every requested value already matched the current config"
                );
            } else {
                println!(
                    "# tune changes ({}{})",
                    changes.len(),
                    if dry_run { " — DRY RUN" } else { "" }
                );
                for (field, before, after) in &changes {
                    println!("  {field:<28} {before:>14} → {after}");
                }
            }
        }
    }

    if !dry_run && !changes.is_empty() {
        write_freedom_yaml(&yaml, &cfg)?;
    }
    Ok(())
}

fn run_weights(
    home: &std::path::Path,
    top_n: Option<usize>,
    role_filter: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let path = RoutingWeights::default_path(home);
    let weights = RoutingWeights::load_from(&path);
    let role_filter = role_filter.map(parse_role).transpose()?;

    let now = now_unix();
    let mut rows: Vec<_> = weights
        .rows
        .iter()
        .filter(|r| match role_filter {
            None => true,
            Some(r2) => r.hemisphere_role == r2,
        })
        .map(|r| {
            let memw = weights.load_memory_weight(r.topic_hash, r.hemisphere_role, now);
            (r, memw)
        })
        .collect();
    rows.sort_by(|(_, w_a), (_, w_b)| w_b.partial_cmp(w_a).unwrap_or(std::cmp::Ordering::Equal));
    let cap = top_n.unwrap_or(20);
    rows.truncate(cap);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let j: Vec<_> = rows
                .iter()
                .map(|(r, w)| {
                    json!({
                        "topic_hash": format!("{:016x}", r.topic_hash),
                        "hemisphere_role": role_to_str(r.hemisphere_role),
                        "success_count": r.success_count,
                        "decay_anchor_unix": r.decay_anchor_unix,
                        "memory_weight": w,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&j)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("# routing weights — empty");
                println!(
                    "  (no acceptance signals yet; weights accumulate when council selection_mode is non-legacy)"
                );
                return Ok(());
            }
            println!(
                "# routing weights (top {}, sorted by memory_weight DESC)",
                rows.len()
            );
            println!(
                "  {:<18} {:<12} {:>14} {:>10}",
                "topic_hash", "role", "success_count", "mem_weight"
            );
            println!(
                "  {:<18} {:<12} {:>14} {:>10}",
                "-".repeat(18),
                "-".repeat(12),
                "-".repeat(14),
                "-".repeat(10)
            );
            for (r, w) in rows {
                println!(
                    "  {:<18x} {:<12} {:>14.2} {:>10.3}",
                    r.topic_hash,
                    role_to_str(r.hemisphere_role),
                    r.success_count,
                    w
                );
            }
            println!();
            println!(
                "(weights decay via Hebbian factor per elapsed day; MAX_WEIGHT_DELTA = 0.05 const)"
            );
        }
    }
    Ok(())
}

fn parse_selection_mode(s: &str) -> Result<SelectionMode> {
    match s.to_ascii_lowercase().replace('-', "_").as_str() {
        "legacy_majority" | "legacy" => Ok(SelectionMode::LegacyMajority),
        "consensus_or_best" | "consensus" | "or_best" => Ok(SelectionMode::ConsensusOrBest),
        "best_always" | "best" | "always" => Ok(SelectionMode::BestAlways),
        other => anyhow::bail!(
            "invalid selection_mode `{other}`. Values: legacy_majority | consensus_or_best | best_always"
        ),
    }
}

fn parse_role(s: &str) -> Result<crate::config::inference::HemisphereRole> {
    use crate::config::inference::HemisphereRole;
    match s.to_ascii_lowercase().as_str() {
        "left" | "l" => Ok(HemisphereRole::Left),
        "right" | "r" => Ok(HemisphereRole::Right),
        "cerebellum" | "c" | "cere" => Ok(HemisphereRole::Cerebellum),
        other => anyhow::bail!("invalid role `{other}`. Values: left | right | cerebellum"),
    }
}

fn selection_mode_as_str(mode: SelectionMode) -> &'static str {
    match mode {
        SelectionMode::LegacyMajority => "legacy_majority",
        SelectionMode::ConsensusOrBest => "consensus_or_best",
        SelectionMode::BestAlways => "best_always",
    }
}

fn role_to_str(role: crate::config::inference::HemisphereRole) -> &'static str {
    use crate::config::inference::HemisphereRole;
    match role {
        HemisphereRole::Left => "left",
        HemisphereRole::Right => "right",
        HemisphereRole::Cerebellum => "cerebellum",
    }
}

fn write_freedom_yaml(path: &PathBuf, cfg: &FreedomConfig) -> Result<()> {
    let yaml = serde_yaml::to_string(cfg).context("serialize freedom.yaml")?;
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, yaml).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_selection_mode_accepts_all_aliases() {
        assert!(matches!(
            parse_selection_mode("legacy_majority").unwrap(),
            SelectionMode::LegacyMajority
        ));
        assert!(matches!(
            parse_selection_mode("legacy").unwrap(),
            SelectionMode::LegacyMajority
        ));
        assert!(matches!(
            parse_selection_mode("CONSENSUS_OR_BEST").unwrap(),
            SelectionMode::ConsensusOrBest
        ));
        assert!(matches!(
            parse_selection_mode("consensus-or-best").unwrap(),
            SelectionMode::ConsensusOrBest
        ));
        assert!(matches!(
            parse_selection_mode("best_always").unwrap(),
            SelectionMode::BestAlways
        ));
        assert!(matches!(
            parse_selection_mode("BEST").unwrap(),
            SelectionMode::BestAlways
        ));
    }

    #[test]
    fn parse_selection_mode_rejects_unknown() {
        let err = parse_selection_mode("nope").unwrap_err();
        assert!(err.to_string().contains("invalid selection_mode"));
    }

    #[test]
    fn parse_role_accepts_full_and_short() {
        use crate::config::inference::HemisphereRole;
        assert_eq!(parse_role("left").unwrap(), HemisphereRole::Left);
        assert_eq!(parse_role("L").unwrap(), HemisphereRole::Left);
        assert_eq!(parse_role("right").unwrap(), HemisphereRole::Right);
        assert_eq!(parse_role("r").unwrap(), HemisphereRole::Right);
        assert_eq!(
            parse_role("cerebellum").unwrap(),
            HemisphereRole::Cerebellum
        );
        assert_eq!(parse_role("c").unwrap(), HemisphereRole::Cerebellum);
    }

    #[test]
    fn parse_role_rejects_unknown() {
        let err = parse_role("hippocampus").unwrap_err();
        assert!(err.to_string().contains("invalid role"));
    }

    #[test]
    fn role_to_str_mirrors_parse_role() {
        use crate::config::inference::HemisphereRole;
        for r in [
            HemisphereRole::Left,
            HemisphereRole::Right,
            HemisphereRole::Cerebellum,
        ] {
            let s = role_to_str(r);
            assert_eq!(parse_role(s).unwrap(), r);
        }
    }

    #[test]
    fn selection_mode_as_str_round_trips() {
        for mode in [
            SelectionMode::LegacyMajority,
            SelectionMode::ConsensusOrBest,
            SelectionMode::BestAlways,
        ] {
            let s = selection_mode_as_str(mode);
            assert!(parse_selection_mode(s).is_ok());
        }
    }
}
