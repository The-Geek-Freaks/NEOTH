//! `neoth mode` — operator-facing surface for the QM-3 ModeRegistry.
//!
//! Subcommands:
//!   `list` — enumerate every mode the bundled + user-installed
//!            skills ship. Sorted by mode id.
//!   `show <id>` — render one mode's full shape (spectrum, oversight,
//!                 output contract, trigger phrases, system_prompt_delta).
//!   `match "<text>"` — run the registry's trigger matcher against an
//!                      arbitrary message and report which mode (if any)
//!                      would activate.
//!
//! Output respects the global `--output` flag.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::skills::mode_registry::ModeRegistry;

#[derive(Args, Debug, Clone)]
pub struct ModeArgs {
    #[command(subcommand)]
    pub action: ModeAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ModeAction {
    /// List every registered mode (sorted by id).
    List,
    /// Show one mode's full shape.
    Show {
        /// Mode id (e.g. `research_lit_review`, `paper_full`).
        id: String,
    },
    /// Match an arbitrary message against the registry's trigger
    /// phrases and report which mode would activate.
    Match {
        /// The message to match.
        text: String,
    },
}

pub async fn run_mode(args: ModeArgs) -> Result<()> {
    let skills_dir = FreedomConfig::default_neoth_home().join("skills");
    let skills = crate::skills::load_all(&skills_dir).await?;
    let registry = ModeRegistry::from_skills(&skills)?;

    match args.action {
        ModeAction::List => list_modes(&registry, args.output),
        ModeAction::Show { id } => show_mode(&registry, &id, args.output),
        ModeAction::Match { text } => match_mode(&registry, &text, args.output),
    }
    Ok(())
}

fn list_modes(registry: &ModeRegistry, output: OutputFormat) {
    let mut rows: Vec<_> = registry.iter().collect();
    rows.sort_by(|a, b| a.mode.id.cmp(&b.mode.id));
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            for r in &rows {
                let v = serde_json::json!({
                    "id": r.mode.id,
                    "skill_id": r.skill_id,
                    "description": r.mode.description,
                    "spectrum": r.mode.spectrum.as_str(),
                    "oversight": r.mode.oversight.as_str(),
                });
                println!("{}", serde_json::to_string(&v).unwrap_or_default());
            }
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("no modes registered (no bundled or user-installed skill ships any)");
                return;
            }
            println!(
                "{:<32} {:<22} {:<11} {:<10} description",
                "mode id", "skill", "spectrum", "oversight"
            );
            println!("{}", "-".repeat(92));
            for r in &rows {
                let desc = char_truncate(&r.mode.description, 28);
                println!(
                    "{:<32} {:<22} {:<11} {:<10} {}",
                    truncate(&r.mode.id, 32),
                    truncate(&r.skill_id, 22),
                    r.mode.spectrum.as_str(),
                    r.mode.oversight.as_str(),
                    desc
                );
            }
        }
    }
}

fn show_mode(registry: &ModeRegistry, id: &str, output: OutputFormat) {
    let Some(resolved) = registry.get(id) else {
        eprintln!("no mode with id `{id}` in the registry");
        eprintln!("run `neoth mode list` to see registered modes");
        return;
    };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let v = serde_json::json!({
                "id": resolved.mode.id,
                "skill_id": resolved.skill_id,
                "description": resolved.mode.description,
                "spectrum": resolved.mode.spectrum.as_str(),
                "oversight": resolved.mode.oversight.as_str(),
                "output_format": resolved.mode.output.format,
                "output_length_hint": resolved.mode.output.length_hint,
                "trigger_phrases": resolved.mode.trigger_phrases,
                "system_prompt_delta": resolved.mode.system_prompt_delta,
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        }
        OutputFormat::Table => {
            println!("mode:               {}", resolved.mode.id);
            println!("parent skill:       {}", resolved.skill_id);
            println!("description:        {}", resolved.mode.description);
            println!("spectrum:           {}", resolved.mode.spectrum.as_str());
            println!("oversight:          {}", resolved.mode.oversight.as_str());
            println!("output format:      {}", resolved.mode.output.format);
            if let Some(hint) = &resolved.mode.output.length_hint {
                println!("output length hint: {hint}");
            }
            println!("trigger phrases:");
            for p in &resolved.mode.trigger_phrases {
                println!("  - {p}");
            }
            if !resolved.mode.system_prompt_delta.is_empty() {
                println!("system prompt delta:");
                for line in resolved.mode.system_prompt_delta.lines() {
                    println!("  {line}");
                }
            }
        }
    }
}

fn match_mode(registry: &ModeRegistry, text: &str, output: OutputFormat) {
    match registry.match_trigger(text) {
        Some(resolved) => match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let v = serde_json::json!({
                    "matched_mode": resolved.mode.id,
                    "skill_id": resolved.skill_id,
                    "description": resolved.mode.description,
                    "spectrum": resolved.mode.spectrum.as_str(),
                    "oversight": resolved.mode.oversight.as_str(),
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            }
            OutputFormat::Table => {
                println!(
                    "match: {} (skill: {})",
                    resolved.mode.id, resolved.skill_id
                );
                println!("  spectrum:  {}", resolved.mode.spectrum.as_str());
                println!("  oversight: {}", resolved.mode.oversight.as_str());
            }
        },
        None => match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"matched_mode": serde_json::Value::Null})
                    )
                    .unwrap_or_default()
                );
            }
            OutputFormat::Table => {
                println!("no mode activated for this message");
            }
        },
    }
}

fn truncate(s: &str, n: usize) -> String {
    char_truncate(s, n)
}

/// UTF-8 char-boundary-safe truncation. `n` is the max character
/// count (not byte count) so multi-byte characters like `—` don't
/// land mid-byte. Appends `…` when truncated.
fn char_truncate(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= n {
        return s.to_string();
    }
    let prefix: String = chars.iter().take(n.saturating_sub(1)).collect();
    format!("{prefix}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_mode_list_does_not_error_on_empty_skills_dir() {
        // No user-installed skills + bundled set still loads via R3-P0.
        // List subcommand prints without panicking.
        let args = ModeArgs {
            action: ModeAction::List,
            output: OutputFormat::Table,
        };
        // Run inside a tempdir env so we don't touch the real ~/.neoth
        let dir = tempfile::tempdir().unwrap();
        let prior = std::env::var_os("NEOTH_HOME");
        // SAFETY: tests are single-threaded per default. We restore prior.
        unsafe {
            std::env::set_var("NEOTH_HOME", dir.path());
        }
        let result = run_mode(args).await;
        unsafe {
            match prior {
                Some(v) => std::env::set_var("NEOTH_HOME", v),
                None => std::env::remove_var("NEOTH_HOME"),
            }
        }
        assert!(result.is_ok(), "list must not error on empty dir: {result:?}");
    }

    #[tokio::test]
    async fn run_mode_match_returns_ok_for_unmatched_text() {
        let args = ModeArgs {
            action: ModeAction::Match {
                text: "completely unrelated prompt".into(),
            },
            output: OutputFormat::Table,
        };
        let dir = tempfile::tempdir().unwrap();
        let prior = std::env::var_os("NEOTH_HOME");
        unsafe {
            std::env::set_var("NEOTH_HOME", dir.path());
        }
        let result = run_mode(args).await;
        unsafe {
            match prior {
                Some(v) => std::env::set_var("NEOTH_HOME", v),
                None => std::env::remove_var("NEOTH_HOME"),
            }
        }
        assert!(result.is_ok());
    }
}
