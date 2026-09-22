//! GOLD-ADAPT-JV-MODE-03 (consumer) — `neoth capabilities`.
//!
//! The first real CONSUMER of the [`crate::memory::self_wiki`] capability map:
//! surfaces every feature the binary ships (bundled skills, daemon crons, CLI
//! commands, slash commands) so the operator — and, via `--output json`, a
//! downstream agent — can query "what can NEOTH do?" without re-parsing YAML.
//! The self-wiki list plus quality current/history reads are read-only.
//! `capabilities quality snapshot` alone persists a local private snapshot.

use anyhow::Result;
use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::memory::self_wiki::{self, CapabilityEntry, CapabilityKind};

#[derive(Debug, Args)]
pub struct CapabilitiesArgs {
    #[command(subcommand)]
    pub action: Option<CapabilitiesAction>,
    /// Filter to one kind: `skill` | `cron` | `cli` | `slash`. Omit for all.
    #[arg(long, value_name = "KIND")]
    pub kind: Option<String>,
    /// Case-insensitive substring search across capability descriptions.
    #[arg(long, value_name = "KEYWORD")]
    pub search: Option<String>,
    /// Override the NEOTH home for `capabilities quality` only.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Debug, Subcommand)]
pub enum CapabilitiesAction {
    /// Inspect or explicitly persist content-free provider capability health.
    Quality(QualityArgs),
}

#[derive(Debug, Args)]
pub struct QualityArgs {
    #[command(subcommand)]
    pub action: Option<QualityAction>,
}

#[derive(Debug, Subcommand)]
pub enum QualityAction {
    /// Capture a new authenticated-WAL-derived local snapshot.
    Snapshot,
    /// Read bounded persisted snapshots without creating or repairing state.
    History,
}

/// Map the operator-facing `--kind` token to a [`CapabilityKind`].
fn parse_kind(token: &str) -> Option<CapabilityKind> {
    match token.trim().to_ascii_lowercase().as_str() {
        "skill" | "skills" => Some(CapabilityKind::Skill),
        "cron" | "crons" => Some(CapabilityKind::Cron),
        "cli" | "command" | "commands" | "cli-command" => Some(CapabilityKind::CliCommand),
        "slash" | "slash-command" => Some(CapabilityKind::SlashCommand),
        _ => None,
    }
}

/// Pure selection so the filtering is unit-testable without stdout capture.
/// Returns the entries matching the optional kind + optional description search
/// (both applied; search is case-insensitive substring).
pub fn select<'a>(
    wiki: &'a self_wiki::SelfWiki,
    kind: Option<CapabilityKind>,
    search: Option<&str>,
) -> Vec<&'a CapabilityEntry> {
    let needle = search.map(|s| s.to_ascii_lowercase());
    wiki.all()
        .filter(|e| kind.is_none_or(|k| e.kind == k))
        .filter(|e| {
            needle
                .as_deref()
                .is_none_or(|n| e.description.to_ascii_lowercase().contains(n))
        })
        .collect()
}

pub fn run_capabilities(args: CapabilitiesArgs) -> Result<()> {
    if let Some(CapabilitiesAction::Quality(quality)) = args.action {
        return run_quality(args.home.as_deref(), quality, args.output);
    }
    anyhow::ensure!(
        args.home.is_none(),
        "--home is only valid with `neoth capabilities quality`"
    );
    let kind = match args.kind.as_deref() {
        Some(tok) => match parse_kind(tok) {
            Some(k) => Some(k),
            None => anyhow::bail!("unknown --kind `{tok}` (expected: skill | cron | cli | slash)"),
        },
        None => None,
    };
    let wiki = self_wiki::build();
    let entries = select(&wiki, kind, args.search.as_deref());

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "kind": e.kind.as_str(),
                        "description": e.description,
                        "feature_gate": e.feature_gate,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({ "total": entries.len(), "capabilities": rows })
            );
        }
        _ => {
            if kind.is_none() && args.search.is_none() {
                // Bare invocation → the wiki's own per-kind summary first.
                println!("{}", wiki.summary());
                println!();
            }
            println!(
                "{} capabilit{} listed:",
                entries.len(),
                if entries.len() == 1 { "y" } else { "ies" }
            );
            for e in &entries {
                let gate = e
                    .feature_gate
                    .map(|g| format!("  [feature: {g}]"))
                    .unwrap_or_default();
                println!(
                    "  [{}] {}{} — {}",
                    e.kind.as_str(),
                    e.id,
                    gate,
                    e.description
                );
            }
        }
    }
    Ok(())
}

fn run_quality(
    home: Option<&std::path::Path>,
    quality: QualityArgs,
    output: OutputFormat,
) -> Result<()> {
    let home = home
        .map(PathBuf::from)
        .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home);
    match quality.action {
        None => render_current(&home, output),
        Some(QualityAction::Snapshot) => {
            let snapshot = crate::daemon::capability_decay::history::capture(
                &home,
                crate::time::now_unix_i64(),
            )?;
            render_snapshots(&[snapshot], output, "captured")
        }
        Some(QualityAction::History) => {
            let snapshots = crate::daemon::capability_decay::history::read(&home)?;
            render_snapshots(&snapshots, output, "history")
        }
    }
}

fn render_current(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let report = crate::daemon::capability_decay::inspect_authenticated_terminal_history(
        home,
        crate::time::now_unix_i64(),
    )?;
    let value = serde_json::json!({
        "source": "authenticated_terminal_wal_prefix",
        "as_of_unix": report.as_of_unix,
        "recent_since_unix": report.recent_since_unix,
        "baseline_since_unix": report.baseline_since_unix,
        "input_receipt_sha256": report.input_receipt_sha256,
        "authenticated_terminal_sample_count": report.authenticated_terminal_sample_count,
        "unattributed_terminal_rows": report.unattributed_terminal_rows,
        "legacy_terminal_rows": report.legacy_terminal_rows,
        "observations": report.observations.iter().map(|row| serde_json::json!({
            "provider": row.identity.provider,
            "model": row.identity.model,
            "workflow": row.identity.workflow.as_str(),
            "trend": trend_label(row.trend),
            "recent_samples": row.recent_samples,
            "baseline_samples": row.baseline_samples,
            "recent_failures": row.recent_failures,
            "baseline_failures": row.baseline_failures,
            "recent_p90_latency_ms": row.recent_p90_latency_ms,
            "baseline_p90_latency_ms": row.baseline_p90_latency_ms,
        })).collect::<Vec<_>>(),
        "limits": "operational failure/latency only; no reasoning-quality, routing, disable, or retry decision",
    });
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{value}"),
        _ => {
            println!(
                "Capability quality as of {} (authenticated terminal WAL; {} accepted samples)",
                report.as_of_unix, report.authenticated_terminal_sample_count
            );
            println!("Shows call failures and response times; it does not measure answer quality.");
            for row in &report.observations {
                println!(
                    "  {}/{}/{}: {} (failures recent {}/{}, baseline {}/{}; p90 {} ms vs {} ms)",
                    row.identity.provider,
                    row.identity.model,
                    row.identity.workflow.as_str(),
                    trend_label(row.trend),
                    row.recent_failures,
                    row.recent_samples,
                    row.baseline_failures,
                    row.baseline_samples,
                    row.recent_p90_latency_ms,
                    row.baseline_p90_latency_ms
                );
            }
        }
    }
    Ok(())
}

fn trend_label(trend: crate::daemon::capability_decay::CapabilityTrend) -> &'static str {
    match trend {
        crate::daemon::capability_decay::CapabilityTrend::Stable => "stable",
        crate::daemon::capability_decay::CapabilityTrend::Degrading => "degrading",
        crate::daemon::capability_decay::CapabilityTrend::Recovering => "recovering",
        crate::daemon::capability_decay::CapabilityTrend::InsufficientSamples => {
            "insufficient_samples"
        }
    }
}

fn render_snapshots(
    snapshots: &[crate::daemon::capability_decay::history::CapabilitySnapshot],
    output: OutputFormat,
    mode: &str,
) -> Result<()> {
    let value = serde_json::json!({ "mode": mode, "provenance": "saved_local_observations", "reauthenticated": false, "snapshots": snapshots });
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{value}"),
        _ => {
            println!(
                "Capability quality {mode}: {} local snapshot(s)",
                snapshots.len()
            );
            println!("Saved observations, not a fresh check. Capture times are Unix seconds.");
            for snapshot in snapshots {
                println!(
                    "  captured {}: {} accepted samples",
                    snapshot.captured_at_unix, snapshot.authenticated_terminal_sample_count
                );
                for row in &snapshot.observations {
                    println!(
                        "    {}/{}/{}: {} (failures recent {}/{}, baseline {}/{}; p90 {} ms vs {} ms)",
                        row.provider,
                        row.model,
                        row.workflow.as_str(),
                        trend_label(row.trend),
                        row.recent_failures,
                        row.recent_samples,
                        row.baseline_failures,
                        row.baseline_samples,
                        row.recent_p90_latency_ms,
                        row.baseline_p90_latency_ms
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    use crate::cli::{Cli, Commands};

    #[test]
    fn parse_kind_accepts_aliases_and_rejects_junk() {
        assert_eq!(parse_kind("skill"), Some(CapabilityKind::Skill));
        assert_eq!(parse_kind("CRONS"), Some(CapabilityKind::Cron));
        assert_eq!(parse_kind("cli"), Some(CapabilityKind::CliCommand));
        assert_eq!(parse_kind("slash"), Some(CapabilityKind::SlashCommand));
        assert!(parse_kind("nonsense").is_none());
    }

    #[test]
    fn select_filters_by_kind_and_search() {
        let wiki = self_wiki::build();
        let all = select(&wiki, None, None);
        assert!(!all.is_empty(), "the binary ships capabilities");

        let skills = select(&wiki, Some(CapabilityKind::Skill), None);
        assert!(skills.iter().all(|e| e.kind == CapabilityKind::Skill));
        assert!(skills.len() < all.len(), "skills are a subset of all");

        // Search is a description substring filter (case-insensitive).
        let hits = select(&wiki, None, Some("memory"));
        assert!(
            hits.iter()
                .all(|e| e.description.to_ascii_lowercase().contains("memory")),
            "every search hit must contain the needle"
        );
    }

    #[test]
    fn clap_keeps_plain_list_and_quality_actions_separate() {
        let plain = Cli::try_parse_from([
            "neoth",
            "capabilities",
            "--kind",
            "skill",
            "--search",
            "memory",
        ])
        .unwrap();
        let Commands::Capabilities(plain) = plain.command else {
            panic!("plain capabilities must dispatch to its command");
        };
        assert!(plain.action.is_none());
        assert_eq!(plain.kind.as_deref(), Some("skill"));
        assert_eq!(plain.search.as_deref(), Some("memory"));
        assert!(plain.home.is_none());

        let snapshot = Cli::try_parse_from([
            "neoth",
            "--output",
            "json",
            "capabilities",
            "--home",
            "C:/capability-home",
            "quality",
            "snapshot",
        ])
        .unwrap();
        assert_eq!(snapshot.effective_output(), OutputFormat::Json);
        let Commands::Capabilities(snapshot) = snapshot.command else {
            panic!("quality snapshot must dispatch to capabilities");
        };
        assert_eq!(
            snapshot.home.as_deref(),
            Some(std::path::Path::new("C:/capability-home"))
        );
        assert!(matches!(
            snapshot.action,
            Some(CapabilitiesAction::Quality(QualityArgs {
                action: Some(QualityAction::Snapshot)
            }))
        ));

        let history = Cli::try_parse_from([
            "neoth",
            "capabilities",
            "--home",
            "C:/capability-home",
            "quality",
            "history",
        ])
        .unwrap();
        let Commands::Capabilities(history) = history.command else {
            panic!("quality history must dispatch to capabilities");
        };
        assert!(matches!(
            history.action,
            Some(CapabilitiesAction::Quality(QualityArgs {
                action: Some(QualityAction::History)
            }))
        ));
    }
}
