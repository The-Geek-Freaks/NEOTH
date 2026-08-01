//! `neoth mode` — operator-facing surface for the QM-3 ModeRegistry.
//!
//! Subcommands:
//!   `list` — enumerate every mode the bundled + user-installed
//!            skills ship. Sorted by mode id.
//!   `show <id>` — render one mode's full shape (spectrum, oversight,
//!                 output contract, trigger phrases, system_prompt_delta).
//!   `match "<text>"` — run the same authority-bound resolver used by chat,
//!                      channels, and `skills --test`, then emit its typed
//!                      route report.
//!
//! Output respects the global `--output` flag.

use anyhow::{Context, Result};
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
    let skills = crate::skills::SkillRegistry::load(&skills_dir).await?;
    let snapshot = skills
        .authority_bound_snapshot()
        .context("acquire authority-bound Mode CLI Skill snapshot")?;
    let registry = ModeRegistry::from_skills(snapshot.skills())?;

    match args.action {
        ModeAction::List => list_modes(&registry, args.output),
        ModeAction::Show { id } => show_mode(&registry, &id, args.output),
        ModeAction::Match { text } => match_mode(snapshot, &text, args.output).await?,
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
                println!(
                    "{}",
                    serde_json::to_string(&v).expect("mode row is infallible JSON")
                );
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
            println!(
                "{}",
                serde_json::to_string_pretty(&v).expect("mode detail is infallible JSON")
            );
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

async fn match_mode(
    snapshot: crate::skills::registry::SkillSnapshot,
    text: &str,
    output: OutputFormat,
) -> Result<()> {
    let config = FreedomConfig::load_from_default_path_or_default()
        .context("load Skill routing policy for mode match")?;
    let mut blocked_skill_ids = std::collections::BTreeSet::<String>::new();
    if !config.skills.pinned_hashes.is_empty() {
        let verdicts = crate::skills::versioning::check_pinned_hashes(
            snapshot
                .skills()
                .iter()
                .map(|skill| (skill.id(), skill.content_hash.as_str())),
            &config.skills.pinned_hashes,
        );
        for (skill, verdict) in snapshot.skills().iter().zip(verdicts) {
            if verdict.verdict == crate::skills::versioning::PinnedHashOutcome::Mismatch {
                blocked_skill_ids.insert(skill.id().to_owned());
            }
        }
    }
    let eval_suppress = config.skills.should_suppress_for_eval();
    let resolver = crate::skills::resolver::SkillRouteResolver::new(snapshot.clone())
        .retaining(|skill| !eval_suppress && !blocked_skill_ids.contains(skill.id()));
    let explicit_skill_id = match crate::slash::parse_invocation(text) {
        crate::slash::Invocation::Command { name, .. }
            if snapshot
                .skills()
                .iter()
                .any(|skill| skill.id().eq_ignore_ascii_case(&name)) =>
        {
            Some(name.to_lowercase())
        }
        _ => None,
    };
    let literal_floor = if config.skills.enable_all_bundled {
        crate::skills::router::FULL_AUTO_MIN_WEIGHT
    } else {
        crate::skills::router::DEFAULT_MIN_WEIGHT
    };
    let embed_provider = if !eval_suppress && config.skills.always_embed_route {
        crate::providers::embed_provider_from_config(&config).await
    } else {
        None
    };
    let active_files = crate::skills::resolver::active_files_from_env();
    let decision = resolver
        .resolve(
            crate::skills::resolver::SkillRouteRequest::automatic(
                text,
                literal_floor,
                &active_files,
            )
            .with_explicit_skill(explicit_skill_id.as_deref()),
            embed_provider.as_deref(),
        )
        .await;
    let report = decision.report().clone();

    match decision {
        crate::skills::resolver::SkillRouteDecision::Match(route) => match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let v = serde_json::json!({
                    "matched_skill": route.skill().id(),
                    "matched_mode": route.mode().map(|mode| mode.id.as_str()),
                    "route_report": report,
                });
                println!("{}", serde_json::to_string_pretty(&v)?);
            }
            OutputFormat::Table => {
                println!(
                    "match: {}{} (stage: {:?})",
                    route.skill().id(),
                    route
                        .mode()
                        .map(|mode| format!("/{}", mode.id))
                        .unwrap_or_default(),
                    report.stage,
                );
                println!("  snapshot: {}", report.snapshot_sha256);
            }
        },
        crate::skills::resolver::SkillRouteDecision::NoMatch(_)
        | crate::skills::resolver::SkillRouteDecision::Conflict(_)
        | crate::skills::resolver::SkillRouteDecision::Rejected(_) => match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "matched_skill": serde_json::Value::Null,
                        "matched_mode": serde_json::Value::Null,
                        "route_report": report,
                    }))?
                );
            }
            OutputFormat::Table => {
                println!("skill route: {:?}", report.outcome);
                if !report.candidates.is_empty() {
                    println!(
                        "  candidates: {}",
                        report
                            .candidates
                            .iter()
                            .map(|candidate| candidate.skill_id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                if let Some(rejection) = report.rejection {
                    println!("  rejection: {rejection:?}");
                }
                println!("  snapshot: {}", report.snapshot_sha256);
            }
        },
    }
    Ok(())
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

    // These two mutate the process-global `NEOTH_HOME`, so they take
    // the crate-wide env lock (see `crate::test_env`) to serialize
    // against any other env-touching test (e.g. `daemon::pidfile`).
    // Plain `#[test]` + a manually-driven current-thread runtime, NOT
    // `#[tokio::test]`: holding a `std::sync::MutexGuard` across an
    // `.await` trips `clippy::await_holding_lock` under `-D warnings`,
    // so we keep the await inside a synchronous `block_on`.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    #[test]
    fn run_mode_list_does_not_error_on_empty_skills_dir() {
        // No user-installed skills + bundled set still loads via R3-P0.
        // List subcommand prints without panicking.
        let _env = crate::test_env::lock();
        let args = ModeArgs {
            action: ModeAction::List,
            output: OutputFormat::Table,
        };
        // Run inside a tempdir env so we don't touch the real ~/.neoth
        let dir = tempfile::tempdir().unwrap();
        let prior = std::env::var_os("NEOTH_HOME");
        // SAFETY: env lock held for the whole body; we restore prior.
        unsafe {
            std::env::set_var("NEOTH_HOME", dir.path());
        }
        let result = block_on(run_mode(args));
        unsafe {
            match prior {
                Some(v) => std::env::set_var("NEOTH_HOME", v),
                None => std::env::remove_var("NEOTH_HOME"),
            }
        }
        assert!(
            result.is_ok(),
            "list must not error on empty dir: {result:?}"
        );
    }

    #[test]
    fn run_mode_match_returns_ok_for_unmatched_text() {
        let _env = crate::test_env::lock();
        let args = ModeArgs {
            action: ModeAction::Match {
                text: "completely unrelated prompt".into(),
            },
            output: OutputFormat::Table,
        };
        let dir = tempfile::tempdir().unwrap();
        let prior = std::env::var_os("NEOTH_HOME");
        // SAFETY: env lock held for the whole body; we restore prior.
        unsafe {
            std::env::set_var("NEOTH_HOME", dir.path());
        }
        let result = block_on(run_mode(args));
        unsafe {
            match prior {
                Some(v) => std::env::set_var("NEOTH_HOME", v),
                None => std::env::remove_var("NEOTH_HOME"),
            }
        }
        assert!(result.is_ok());
    }
}
