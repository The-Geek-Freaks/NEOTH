//! `neoth consent` — manage first-run outbound-LLM consent (V03-08).
//!
//! Subcommands: `list`, `grant <provider>`, `revoke <provider>`. The chat +
//! serve paths gate cloud-bound provider calls behind a recorded consent
//! marker so the operator's text never reaches a third-party until they
//! explicitly opt in.
//!
//! Consent state lives under `~/.neoth/consent/<provider_kind>.granted`.
//! Operators can audit by hand (`ls ~/.neoth/consent/`) or via this CLI.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::json;

use crate::cli::OutputFormat;
use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::consent;

#[derive(Args, Debug, Clone)]
pub struct ConsentArgs {
    #[command(subcommand)]
    pub action: ConsentAction,

    /// Output format (inherited from global --output flag).
    #[clap(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConsentAction {
    /// List recorded consent grants under `~/.neoth/consent/`.
    List,
    /// Show consent state for a single provider.
    Show {
        #[arg(value_enum)]
        provider: ProviderKind,
    },
    /// Record consent for sending operator text to a cloud provider.
    Grant {
        #[arg(value_enum)]
        provider: ProviderKind,
    },
    /// Remove a previously recorded consent grant.
    Revoke {
        #[arg(value_enum)]
        provider: ProviderKind,
    },
}

pub async fn run_consent(args: ConsentArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        ConsentAction::List => render_list(&home, args.output),
        ConsentAction::Show { provider } => render_show(&home, provider, args.output),
        ConsentAction::Grant { provider } => render_grant(&home, provider, args.output),
        ConsentAction::Revoke { provider } => render_revoke(&home, provider, args.output),
    }
}

fn render_list(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let grants = consent::list_grants(home)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload: Vec<serde_json::Value> = grants
                .iter()
                .map(|(k, ts)| {
                    json!({
                        "provider": consent::slug(*k),
                        "granted_unix_ts": ts,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Table => {
            if grants.is_empty() {
                println!("No consent grants recorded.");
                println!();
                println!("Cloud providers require one-time consent before NEOTH routes");
                println!("any text to them. Run `neoth consent grant <provider>` to grant.");
                return Ok(());
            }
            println!("{:<18}  granted_unix_ts", "provider");
            println!("{}  {}", "-".repeat(18), "-".repeat(20));
            for (kind, ts) in grants {
                println!("{:<18}  {}", consent::slug(kind), ts);
            }
        }
    }
    Ok(())
}

fn render_show(home: &std::path::Path, provider: ProviderKind, output: OutputFormat) -> Result<()> {
    let slug_s = consent::slug(provider);
    let granted = consent::is_granted(home, provider);
    let is_cloud = consent::is_cloud(provider);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "is_cloud": is_cloud,
                    "granted": granted,
                    "marker_path": consent::marker_path(home, provider).display().to_string(),
                }))?
            );
        }
        OutputFormat::Table => {
            if !is_cloud {
                println!("{slug_s}: not a cloud provider — no consent required.");
                return Ok(());
            }
            if granted {
                println!("{slug_s}: GRANTED");
                println!("marker: {}", consent::marker_path(home, provider).display());
            } else {
                println!("{slug_s}: NOT GRANTED");
                println!("run `neoth consent grant {slug_s}` to record consent.");
            }
        }
    }
    Ok(())
}

fn render_grant(
    home: &std::path::Path,
    provider: ProviderKind,
    output: OutputFormat,
) -> Result<()> {
    if !consent::is_cloud(provider) {
        anyhow::bail!(
            "provider `{}` is not a cloud provider — no consent required",
            consent::slug(provider)
        );
    }
    consent::grant(home, provider)?;
    let slug_s = consent::slug(provider);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "action": "granted",
                    "marker_path": consent::marker_path(home, provider).display().to_string(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("✓ consent granted for `{slug_s}`.");
            println!("marker: {}", consent::marker_path(home, provider).display());
        }
    }
    Ok(())
}

fn render_revoke(
    home: &std::path::Path,
    provider: ProviderKind,
    output: OutputFormat,
) -> Result<()> {
    let slug_s = consent::slug(provider);
    let was_granted = consent::is_granted(home, provider);
    consent::revoke(home, provider)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": slug_s,
                    "action": if was_granted { "revoked" } else { "noop" },
                }))?
            );
        }
        OutputFormat::Table => {
            if was_granted {
                println!("✓ consent revoked for `{slug_s}`.");
                println!(
                    "next chat against `{slug_s}` will re-prompt (or bail in non-interactive contexts)."
                );
            } else {
                println!("`{slug_s}` had no consent grant — nothing to revoke.");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn grant_then_show_then_revoke_round_trip_via_render_helpers() {
        let tmp = TempDir::new().unwrap();
        // Direct module calls — render_* uses default_neoth_home() which we
        // can't override per call without env shimming. These tests pin the
        // underlying consent module behaviour the CLI dispatches to.
        assert!(!consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
        consent::grant(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
        consent::revoke(tmp.path(), ProviderKind::OpenaiApi).unwrap();
        assert!(!consent::is_granted(tmp.path(), ProviderKind::OpenaiApi));
    }
}
