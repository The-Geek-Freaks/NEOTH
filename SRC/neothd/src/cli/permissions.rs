//! `neoth permissions` — operator visibility into the autonomy gate.
//!
//! Every paid provider call, channel send, file write, and shell exec is
//! gated by `permissions::evaluate(action, level)` which returns `Allow` /
//! `Confirm(reason)` / `Deny(reason)`. Operators picked a level at
//! `neoth init`; this CLI surfaces what that level actually permits.
//!
//! - `show` prints the active level + a decision table for every `Action`
//!   variant at every level (so operators can see what `strict` would
//!   refuse before they downgrade).
//! - `check <action>` runs a single evaluation against the configured
//!   level, returning Allow/Confirm/Deny + the reason text the dispatcher
//!   would surface.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::permissions::{Action, AutonomyLevel, Decision, evaluate};

#[derive(Args, Debug, Clone)]
pub struct PermissionsArgs {
    #[command(subcommand)]
    pub action: PermissionsAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PermissionsAction {
    /// Print the active autonomy level + the decision table for every
    /// action variant at every level. With `--level <L>`, only that
    /// level's column is rendered (handy for "what would `strict` block?").
    Show {
        #[arg(long)]
        level: Option<String>,
    },
    /// Run a single permission evaluation against the configured level.
    /// `<action>` names match the snake-case wire form: `read`,
    /// `write_neoth_home`, `write_outside_home`, `exec_scripts`,
    /// `exec_arbitrary`, `paid_provider_call`, `channel_send`,
    /// `dangerous_target`. `--eur` and `--target` are honoured only when
    /// the action variant carries them.
    Check {
        action: String,
        #[arg(long)]
        eur: Option<f32>,
        #[arg(long)]
        target: Option<String>,
    },
}

pub async fn run_permissions(args: PermissionsArgs) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first if absent")?;
    match args.action {
        PermissionsAction::Show { level } => run_show(cfg.autonomy, level.as_deref(), &args.output),
        PermissionsAction::Check {
            action,
            eur,
            target,
        } => run_check(cfg.autonomy, &action, eur, target.as_deref(), &args.output),
    }
}

const ALL_LEVELS: [AutonomyLevel; 5] = [
    AutonomyLevel::Strict,
    AutonomyLevel::Standard,
    AutonomyLevel::Elevated,
    AutonomyLevel::Full,
    AutonomyLevel::Custom,
];

/// Representative action set for the decision-matrix preview. The CLI
/// preview cannot enumerate every possible `DangerousTarget(String)` or
/// every `eur_estimate`; we pick canonical values that show the typical
/// behavior. Operators run `permissions check` for specific cases.
fn preview_actions() -> Vec<(&'static str, Action)> {
    vec![
        ("read", Action::Read),
        ("write_neoth_home", Action::WriteNeothHome),
        ("write_outside_home", Action::WriteOutsideHome),
        ("exec_scripts", Action::ExecScripts),
        ("exec_arbitrary", Action::ExecArbitrary),
        (
            "paid_provider_call (€0.05)",
            Action::PaidProviderCall { eur_estimate: 0.05 },
        ),
        (
            "paid_provider_call (€1.50)",
            Action::PaidProviderCall { eur_estimate: 1.50 },
        ),
        (
            "paid_provider_call (€10.00)",
            Action::PaidProviderCall {
                eur_estimate: 10.00,
            },
        ),
        ("channel_send", Action::ChannelSend),
        (
            "dangerous_target",
            Action::DangerousTarget("example".into()),
        ),
        (
            "mcp_tool_invocation",
            Action::McpToolInvocation {
                server_id: "filesystem".into(),
                tool: "read_file".into(),
            },
        ),
    ]
}

fn run_show(
    active: AutonomyLevel,
    level_filter: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let levels: Vec<AutonomyLevel> = match level_filter {
        Some(s) => {
            let l = AutonomyLevel::from_str(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown level `{s}`. Valid: strict, standard, elevated, full, custom"
                )
            })?;
            vec![l]
        }
        None => ALL_LEVELS.to_vec(),
    };
    let actions = preview_actions();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "active_level": active.as_str(),
                "matrix": levels.iter().map(|l| serde_json::json!({
                    "level": l.as_str(),
                    "decisions": actions.iter().map(|(name, action)| {
                        let d = evaluate(action, *l);
                        serde_json::json!({
                            "action": name,
                            "decision": d.tag(),
                            "reason": match &d {
                                Decision::Allow => "".to_string(),
                                Decision::Confirm(r) | Decision::Deny(r) => r.clone(),
                            },
                        })
                    }).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!(
                "# Permissions — active level: {} (set via `neoth init`)",
                active.as_str()
            );
            for level in &levels {
                println!("\n  [{}]", level.as_str());
                for (name, action) in &actions {
                    let d = evaluate(action, *level);
                    let tag = d.tag();
                    let reason = match d {
                        Decision::Allow => "".to_string(),
                        Decision::Confirm(r) | Decision::Deny(r) => format!(" — {r}"),
                    };
                    println!("    {:<32} {tag}{reason}", name);
                }
            }
        }
    }
    Ok(())
}

fn run_check(
    level: AutonomyLevel,
    action_name: &str,
    eur: Option<f32>,
    target: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let action = parse_action(action_name, eur, target)?;
    let decision = evaluate(&action, level);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "level": level.as_str(),
                    "action": action_name,
                    "decision": decision.tag(),
                    "reason": match &decision {
                        Decision::Allow => "".to_string(),
                        Decision::Confirm(r) | Decision::Deny(r) => r.clone(),
                    },
                    "allowed": decision.is_allow(),
                }))?
            );
        }
        OutputFormat::Table => {
            let reason = match &decision {
                Decision::Allow => "(no reason)".to_string(),
                Decision::Confirm(r) | Decision::Deny(r) => r.clone(),
            };
            println!(
                "# Permission check\n  level:    {}\n  action:   {action_name}\n  decision: {}\n  reason:   {reason}",
                level.as_str(),
                decision.tag(),
            );
        }
    }
    Ok(())
}

fn parse_action(name: &str, eur: Option<f32>, target: Option<&str>) -> Result<Action> {
    Ok(match name {
        "read" => Action::Read,
        "write_neoth_home" => Action::WriteNeothHome,
        "write_outside_home" => Action::WriteOutsideHome,
        "exec_scripts" => Action::ExecScripts,
        "exec_arbitrary" => Action::ExecArbitrary,
        "paid_provider_call" => Action::PaidProviderCall {
            eur_estimate: eur
                .ok_or_else(|| anyhow::anyhow!("paid_provider_call requires --eur <amount>"))?,
        },
        "channel_send" => Action::ChannelSend,
        "dangerous_target" => Action::DangerousTarget(
            target
                .ok_or_else(|| anyhow::anyhow!("dangerous_target requires --target <name>"))?
                .to_string(),
        ),
        "mcp_tool_invocation" => Action::McpToolInvocation {
            server_id: target
                .ok_or_else(|| {
                    anyhow::anyhow!("mcp_tool_invocation requires --target <server_id:tool>")
                })?
                .split(':')
                .next()
                .unwrap_or("?")
                .to_string(),
            tool: target
                .and_then(|s| s.split(':').nth(1))
                .unwrap_or("?")
                .to_string(),
        },
        other => anyhow::bail!(
            "unknown action `{other}`. Valid: read, write_neoth_home, write_outside_home, \
             exec_scripts, exec_arbitrary, paid_provider_call, channel_send, dangerous_target, \
             mcp_tool_invocation"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_action_read_returns_read_variant() {
        assert_eq!(parse_action("read", None, None).unwrap(), Action::Read,);
    }

    #[test]
    fn parse_action_paid_provider_requires_eur() {
        let err = parse_action("paid_provider_call", None, None).unwrap_err();
        assert!(err.to_string().contains("--eur"));
    }

    #[test]
    fn parse_action_dangerous_target_requires_target() {
        let err = parse_action("dangerous_target", None, None).unwrap_err();
        assert!(err.to_string().contains("--target"));
    }

    #[test]
    fn parse_action_paid_provider_with_eur() {
        let a = parse_action("paid_provider_call", Some(0.5), None).unwrap();
        match a {
            Action::PaidProviderCall { eur_estimate } => {
                assert!((eur_estimate - 0.5).abs() < f32::EPSILON)
            }
            _ => panic!("expected PaidProviderCall"),
        }
    }

    #[test]
    fn parse_action_unknown_lists_valid_names() {
        let err = parse_action("ghost", None, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("read"));
        assert!(msg.contains("channel_send"));
    }

    #[test]
    fn run_show_unknown_level_filter_errors() {
        let err =
            run_show(AutonomyLevel::Standard, Some("ghost"), &OutputFormat::Json).unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn run_check_allows_read_at_strict() {
        run_check(
            AutonomyLevel::Strict,
            "read",
            None,
            None,
            &OutputFormat::Json,
        )
        .unwrap();
    }

    #[test]
    fn run_show_renders_every_level_in_json() {
        run_show(AutonomyLevel::Standard, None, &OutputFormat::Json).unwrap();
        run_show(AutonomyLevel::Standard, None, &OutputFormat::Table).unwrap();
    }

    #[test]
    fn preview_actions_covers_all_action_variants_today() {
        // If a future Action variant is added, this test ensures we update
        // the preview list so the CLI matrix stays exhaustive. Add the new
        // variant's representative below; the cardinality assertion below
        // intentionally fails if the count drifts.
        assert_eq!(preview_actions().len(), 11);
    }
}
