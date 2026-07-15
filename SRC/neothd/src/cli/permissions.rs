//! `neoth permissions` — operator visibility into the autonomy gate.
//!
//! Every paid provider call, channel send, file write, and shell exec is
//! gated by an immutable autonomy-policy snapshot which returns `Allow` /
//! `Confirm(reason)` / `Deny(reason)`. Operators picked a level at
//! `neoth init`; this CLI surfaces what that level actually permits.
//!
//! - `show` prints the active policy + a decision table for every `Action`
//!   variant at every level (so operators can see what `strict` would
//!   refuse before they downgrade).
//! - `check <action>` runs a single evaluation against the active policy,
//!   returning Allow/Confirm/Deny + the reason text the dispatcher
//!   would surface.
//! - `set` / `clear` atomically edit per-action Custom overrides.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::permissions::lease::{LeaseScope, LeaseStore};
use crate::permissions::{
    Action, ActionKind, AutonomyLevel, AutonomyPolicySnapshot, CustomDecision, Decision, evaluate,
    lease_scope_for,
};

#[derive(Args, Debug, Clone)]
pub struct PermissionsArgs {
    #[command(subcommand)]
    pub action: PermissionsAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PermissionsAction {
    /// Print the active autonomy level, typed Custom override map, and the
    /// exhaustive decision table. With `--level <L>`, only that level is
    /// rendered.
    Show {
        #[arg(long)]
        level: Option<String>,
    },
    /// Run a single permission evaluation against the active policy. Action
    /// names are the snake-case names emitted by `permissions show`.
    /// `paid_provider_call` requires `--eur`; `dangerous_target` requires
    /// `--target <name>`; `mcp_tool_invocation` requires
    /// `--target <server:tool>`.
    Check {
        action: String,
        #[arg(long)]
        eur: Option<f32>,
        #[arg(long)]
        target: Option<String>,
        /// SL-01a-b: evaluate as this subject (a peer pub-key-hex or a
        /// plugin id). When set, an active capability lease in
        /// `~/.neoth/leases.json` that covers the action upgrades a
        /// `Confirm` decision to `Allow` — exactly as the autonomy gate
        /// would at runtime. Lets the operator verify "does peerX's lease
        /// let them do this right now?" before trusting it.
        #[arg(long)]
        subject: Option<String>,
    },
    /// Atomically set a Custom per-action override in freedom.yaml. The
    /// override is active when autonomy is `custom`.
    Set {
        /// Stable snake-case action name from `permissions show`.
        action: ActionKind,
        /// `allow` | `confirm` | `deny`.
        decision: CustomDecision,
    },
    /// Atomically remove a Custom override. The action then inherits its
    /// Standard decision.
    Clear {
        /// Stable snake-case action name from `permissions show`.
        action: ActionKind,
    },
}

pub async fn run_permissions(args: PermissionsArgs) -> Result<()> {
    match args.action {
        PermissionsAction::Show { level } => {
            let cfg = load_config()?;
            run_show(&cfg, level.as_deref(), &args.output)
        }
        PermissionsAction::Check {
            action,
            eur,
            target,
            subject,
        } => {
            let cfg = load_config()?;
            run_check(
                &cfg,
                &action,
                eur,
                target.as_deref(),
                subject.as_deref(),
                &args.output,
            )
        }
        PermissionsAction::Set { action, decision } => {
            set_override_at(&FreedomConfig::default_path(), action, decision)?;
            print_override_change("set", action, Some(decision), &args.output)
        }
        PermissionsAction::Clear { action } => {
            clear_override_at(&FreedomConfig::default_path(), action)?;
            print_override_change("cleared", action, None, &args.output)
        }
    }
}

fn load_config() -> Result<FreedomConfig> {
    FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first if absent")
}

const ALL_LEVELS: [AutonomyLevel; 5] = [
    AutonomyLevel::Strict,
    AutonomyLevel::Standard,
    AutonomyLevel::Elevated,
    AutonomyLevel::Full,
    AutonomyLevel::Custom,
];

/// Exactly one representative for every stable action kind. Payload-bearing
/// actions use visibly synthetic values and never become dispatch grants.
fn preview_actions() -> Vec<(ActionKind, Action)> {
    ActionKind::ALL
        .into_iter()
        .map(|kind| (kind, Action::representative(kind)))
        .collect()
}

fn run_show(cfg: &FreedomConfig, level_filter: Option<&str>, output: &OutputFormat) -> Result<()> {
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
    let policy_for = |level| {
        if level == AutonomyLevel::Custom {
            AutonomyPolicySnapshot::new(level, &cfg.custom_autonomy)
        } else {
            AutonomyPolicySnapshot::builtin(level).expect("non-Custom built-in level")
        }
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "active_level": cfg.autonomy.as_str(),
                "active_custom_overrides": &cfg.custom_autonomy.overrides,
                "matrix": levels.iter().map(|l| serde_json::json!({
                    "level": l.as_str(),
                    "decisions": actions.iter().map(|(kind, action)| {
                        let policy = policy_for(*l);
                        let d = evaluate(action, &policy);
                        serde_json::json!({
                            "action": kind.as_str(),
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
                cfg.autonomy.as_str()
            );
            if cfg.custom_autonomy.overrides.is_empty() {
                println!("  custom overrides: none (all actions inherit Standard)");
            } else {
                println!("  custom overrides:");
                for (kind, decision) in &cfg.custom_autonomy.overrides {
                    println!("    {kind}: {decision}");
                }
            }
            for level in &levels {
                println!("\n  [{}]", level.as_str());
                let policy = policy_for(*level);
                for (kind, action) in &actions {
                    let d = evaluate(action, &policy);
                    let tag = d.tag();
                    let reason = match d {
                        Decision::Allow => "".to_string(),
                        Decision::Confirm(r) | Decision::Deny(r) => format!(" — {r}"),
                    };
                    println!("    {:<32} {tag}{reason}", kind.as_str());
                }
            }
        }
    }
    Ok(())
}

fn run_check(
    cfg: &FreedomConfig,
    action_name: &str,
    eur: Option<f32>,
    target: Option<&str>,
    subject: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let action = parse_action(action_name, eur, target)?;
    let policy = cfg.autonomy_policy();
    let base = evaluate(&action, &policy);

    // SL-01a-b: mirror the autonomy gate's lease upgrade so the operator can
    // probe "does this subject's lease let them do this right now?". Only a
    // `Confirm` is upgradeable (never a `Deny` — the hard floor); only when a
    // subject is given AND an active lease covers the action's scope. This is
    // a READ-ONLY probe: it computes the same decision the gate would, but
    // emits no WAL frame (a check must not pollute the audit log).
    // An empty/whitespace `--subject` is treated as no subject (fail-closed:
    // never probe against a possible `granted_to == ""` match-all lease).
    let subject = subject.map(str::trim).filter(|s| !s.is_empty());
    // Probe the lease store only on a `Confirm` with a real subject whose
    // action maps to a scope. `(lease_id, scope)` when a lease covers it.
    let via_lease: Option<(String, LeaseScope)> =
        if let (Some(subj), Decision::Confirm(_)) = (subject, &base) {
            match lease_scope_for(&action) {
                Some(scope) => {
                    let path = LeaseStore::default_path(&FreedomConfig::default_neoth_home());
                    let store = LeaseStore::load(&path)
                        .with_context(|| format!("load leases at {}", path.display()))?;
                    store
                        .find_covering(subj, &scope, now_unix())
                        .map(|lease| (lease.lease_id.clone(), scope))
                }
                None => None,
            }
        } else {
            None
        };
    // A covering lease upgrades the decision to Allow; otherwise it is the
    // base decision unchanged.
    let effective = if via_lease.is_some() {
        Decision::Allow
    } else {
        base.clone()
    };

    // McpTool carries an inner tool id that `as_str()` drops; render the
    // qualified `mcp_tool:<id>` form so the probe identifies WHICH tool the
    // lease covered (an operator may hold several MCP-tool leases).
    let scope_display = |s: &LeaseScope| match s {
        LeaseScope::McpTool(id) => format!("mcp_tool:{id}"),
        other => other.as_str().to_string(),
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "level": policy.level().as_str(),
                    "action": action_name,
                    "subject": subject,
                    "base_decision": base.tag(),
                    "decision": effective.tag(),
                    "reason": match &effective {
                        Decision::Allow => "".to_string(),
                        Decision::Confirm(r) | Decision::Deny(r) => r.clone(),
                    },
                    "lease_id": via_lease.as_ref().map(|(id, _)| id.clone()),
                    "lease_scope": via_lease.as_ref().map(|(_, s)| scope_display(s)),
                    "allowed": effective.is_allow(),
                }))?
            );
        }
        OutputFormat::Table => {
            let reason = match &effective {
                Decision::Allow => "(no reason)".to_string(),
                Decision::Confirm(r) | Decision::Deny(r) => r.clone(),
            };
            println!(
                "# Permission check\n  level:    {}\n  action:   {action_name}\n  subject:  {}\n  decision: {}\n  reason:   {reason}",
                policy.level().as_str(),
                subject.unwrap_or("(none)"),
                effective.tag(),
            );
            if let Some((id, scope)) = &via_lease {
                println!(
                    "  ⮑ upgraded confirm → allow via lease {} (scope {})",
                    id.chars().take(12).collect::<String>(),
                    scope_display(scope),
                );
            }
        }
    }
    Ok(())
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}

fn parse_action(name: &str, eur: Option<f32>, target: Option<&str>) -> Result<Action> {
    let kind: ActionKind = name.parse().map_err(anyhow::Error::msg)?;
    Ok(match kind {
        ActionKind::PaidProviderCall => {
            let mut action = Action::representative(kind);
            if let Action::PaidProviderCall { eur_estimate, .. } = &mut action {
                *eur_estimate = eur
                    .ok_or_else(|| anyhow::anyhow!("paid_provider_call requires --eur <amount>"))?;
            }
            action
        }
        ActionKind::DangerousTarget => Action::DangerousTarget(
            target
                .ok_or_else(|| anyhow::anyhow!("dangerous_target requires --target <name>"))?
                .to_string(),
        ),
        ActionKind::McpToolInvocation => {
            let target = target.ok_or_else(|| {
                anyhow::anyhow!("mcp_tool_invocation requires --target <server_id:tool>")
            })?;
            let (server_id, tool) = target.split_once(':').ok_or_else(|| {
                anyhow::anyhow!("mcp_tool_invocation --target must be <server_id:tool>")
            })?;
            if server_id.is_empty() || tool.is_empty() {
                anyhow::bail!("mcp_tool_invocation --target must be <server_id:tool>");
            }
            Action::McpToolInvocation {
                server_id: server_id.to_string(),
                tool: tool.to_string(),
            }
        }
        _ => Action::representative(kind),
    })
}

fn set_override_at(
    path: &std::path::Path,
    action: ActionKind,
    decision: CustomDecision,
) -> Result<()> {
    FreedomConfig::update_at(path, |cfg| {
        cfg.custom_autonomy.overrides.insert(action, decision);
        Ok(())
    })
}

fn clear_override_at(path: &std::path::Path, action: ActionKind) -> Result<()> {
    FreedomConfig::update_at(path, |cfg| {
        cfg.custom_autonomy.overrides.remove(&action);
        Ok(())
    })
}

fn print_override_change(
    operation: &str,
    action: ActionKind,
    decision: Option<CustomDecision>,
    output: &OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "operation": operation,
                "action": action,
                "decision": decision,
                "path": FreedomConfig::default_path(),
            }))?
        ),
        OutputFormat::Table => match decision {
            Some(decision) => println!(
                "Custom override set: {action} = {decision}. It is active when autonomy is `custom`."
            ),
            None => println!(
                "Custom override cleared: {action}. It now inherits the Standard decision."
            ),
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(level: AutonomyLevel) -> FreedomConfig {
        FreedomConfig {
            autonomy: level,
            ..FreedomConfig::default()
        }
    }

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
            Action::PaidProviderCall { eur_estimate, .. } => {
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
        let err = run_show(
            &config(AutonomyLevel::Standard),
            Some("ghost"),
            &OutputFormat::Json,
        )
        .unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[test]
    fn run_check_allows_read_at_strict() {
        run_check(
            &config(AutonomyLevel::Strict),
            "read",
            None,
            None,
            None,
            &OutputFormat::Json,
        )
        .unwrap();
    }

    #[test]
    fn run_check_without_subject_does_not_consult_leases() {
        // No subject ⇒ the probe never touches leases.json; a Confirm stays
        // a Confirm (here WriteOutsideHome at Standard).
        run_check(
            &config(AutonomyLevel::Standard),
            "write_outside_home",
            None,
            None,
            None,
            &OutputFormat::Json,
        )
        .unwrap();
    }

    #[test]
    fn run_check_deny_is_never_lease_upgradable_even_with_subject() {
        // dangerous_target is Deny at Standard. Passing a subject must NOT
        // flip it — the probe only upgrades Confirm, never Deny. (No real
        // lease store is needed: the base decision is Deny so the lease
        // branch is never entered.)
        run_check(
            &config(AutonomyLevel::Standard),
            "dangerous_target",
            None,
            Some("nodeA"),
            Some("peerA"),
            &OutputFormat::Json,
        )
        .unwrap();
    }

    #[test]
    fn run_show_renders_every_level_in_json() {
        let cfg = config(AutonomyLevel::Standard);
        run_show(&cfg, None, &OutputFormat::Json).unwrap();
        run_show(&cfg, None, &OutputFormat::Table).unwrap();
    }

    #[test]
    fn preview_actions_covers_all_action_variants_today() {
        // ActionKind::ALL + the exhaustive representative match make a future
        // Action variant fail compilation until the CLI matrix can show it.
        assert_eq!(preview_actions().len(), ActionKind::ALL.len());
        for (kind, action) in preview_actions() {
            assert_eq!(action.kind(), kind);
        }
    }

    #[test]
    fn parse_action_supports_every_stable_action_kind() {
        for kind in ActionKind::ALL {
            let eur = (kind == ActionKind::PaidProviderCall).then_some(0.10);
            let target = match kind {
                ActionKind::DangerousTarget => Some("example"),
                ActionKind::McpToolInvocation => Some("server:tool"),
                _ => None,
            };
            assert_eq!(
                parse_action(kind.as_str(), eur, target).unwrap().kind(),
                kind
            );
        }
    }

    #[test]
    fn set_and_clear_override_round_trip_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            serde_yaml::to_string(&config(AutonomyLevel::Custom)).unwrap(),
        )
        .unwrap();

        set_override_at(&path, ActionKind::ExternalHttpRequest, CustomDecision::Deny).unwrap();
        let loaded = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(
            loaded
                .custom_autonomy
                .overrides
                .get(&ActionKind::ExternalHttpRequest),
            Some(&CustomDecision::Deny)
        );

        clear_override_at(&path, ActionKind::ExternalHttpRequest).unwrap();
        let loaded = FreedomConfig::load_from_path(&path).unwrap();
        assert!(
            !loaded
                .custom_autonomy
                .overrides
                .contains_key(&ActionKind::ExternalHttpRequest)
        );
    }
}
