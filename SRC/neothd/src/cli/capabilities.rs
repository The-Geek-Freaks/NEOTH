//! GOLD-ADAPT-JV-MODE-03 (consumer) — `neoth capabilities`.
//!
//! The first real CONSUMER of the [`crate::memory::self_wiki`] capability map:
//! surfaces every feature the binary ships (bundled skills, daemon crons, CLI
//! commands, slash commands) so the operator — and, via `--output json`, a
//! downstream agent — can query "what can NEOTH do?" without re-parsing YAML.
//! The map itself is pure/read-only; this command just renders it.

use anyhow::Result;
use clap::Args;

use crate::cli::OutputFormat;
use crate::memory::self_wiki::{self, CapabilityEntry, CapabilityKind};

#[derive(Debug, Args)]
pub struct CapabilitiesArgs {
    /// Filter to one kind: `skill` | `cron` | `cli` | `slash`. Omit for all.
    #[arg(long, value_name = "KIND")]
    pub kind: Option<String>,
    /// Case-insensitive substring search across capability descriptions.
    #[arg(long, value_name = "KEYWORD")]
    pub search: Option<String>,
    #[arg(skip)]
    pub output: OutputFormat,
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
    let kind = match args.kind.as_deref() {
        Some(tok) => match parse_kind(tok) {
            Some(k) => Some(k),
            None => anyhow::bail!(
                "unknown --kind `{tok}` (expected: skill | cron | cli | slash)"
            ),
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
            println!("{} capabilit{} listed:", entries.len(), if entries.len() == 1 { "y" } else { "ies" });
            for e in &entries {
                let gate = e
                    .feature_gate
                    .map(|g| format!("  [feature: {g}]"))
                    .unwrap_or_default();
                println!("  [{}] {}{} — {}", e.kind.as_str(), e.id, gate, e.description);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
