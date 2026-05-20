//! `neoth skills` — operator-facing view of installed skills + router probe.
//!
//! Modes:
//!   `--list`        load all manifests, show id / description / enabled / keywords
//!   `--test "<msg>"` route the message through the keyword scan, print which
//!                   skill (if any) would activate plus the matched keywords
//!
//! Output respects the global `--output` flag.

use anyhow::Result;
use clap::Args;
use tracing::info;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::skills::{load_all, route};

#[derive(Args, Debug, Clone)]
pub struct SkillsArgs {
    /// Print the table of installed skills.
    #[arg(long, conflicts_with_all = ["test", "run_tests"])]
    pub list: bool,

    /// Run the router against an arbitrary message and report the match.
    #[arg(long, value_name = "MESSAGE", conflicts_with_all = ["list", "run_tests"])]
    pub test: Option<String>,

    /// Run the RED/GREEN scenario suite for a skill. Loads
    /// `~/.neoth/skills/<id>/tests/*.yaml`, runs each scenario twice
    /// (without and with the skill's system prompt), reports pass/fail.
    /// Requires a working provider in `freedom.yaml`. Phase 33+ (obra/
    /// superpowers Item #3 port).
    #[arg(long = "run-tests", value_name = "SKILL_ID", conflicts_with_all = ["list", "test"])]
    pub run_tests: Option<String>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_skills(args: SkillsArgs) -> Result<()> {
    let skills_dir = FreedomConfig::default_neoth_home().join("skills");
    let skills = load_all(&skills_dir).await?;
    info!(
        path = %skills_dir.display(),
        count = skills.len(),
        "skills loaded"
    );

    if let Some(skill_id) = &args.run_tests {
        let skill = skills.iter().find(|s| s.id() == skill_id).ok_or_else(|| {
            anyhow::anyhow!(
                "no skill with id '{skill_id}' loaded from {}",
                skills_dir.display(),
            )
        })?;
        let config = FreedomConfig::load_from_default_path()?;
        let provider = crate::providers::from_config(&config).await?;
        let outcomes =
            crate::skills::test_harness::run_all_scenarios_for(provider.as_ref(), skill).await?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                for o in &outcomes {
                    let v = serde_json::json!({
                        "scenario": o.scenario_id,
                        "passed": o.passed(),
                        "red_violated": o.red_violated,
                        "green_complied": o.green_complied,
                        "forbid_respected": o.forbid_respected,
                    });
                    println!("{}", serde_json::to_string(&v)?);
                }
            }
            OutputFormat::Table => {
                if outcomes.is_empty() {
                    println!("no scenarios for skill '{skill_id}'");
                    println!(
                        "  create one: mkdir -p {dir}/{id}/tests && \\\n  \
                         $EDITOR {dir}/{id}/tests/<scenario>.yaml",
                        dir = skills_dir.display(),
                        id = skill_id,
                    );
                } else {
                    let total = outcomes.len();
                    let passed = outcomes.iter().filter(|o| o.passed()).count();
                    println!(
                        "# {} scenarios — {} passed / {} failed",
                        total,
                        passed,
                        total - passed
                    );
                    for o in &outcomes {
                        let mark = if o.passed() { "PASS" } else { "FAIL" };
                        println!("  {mark}  {}", o.scenario_id);
                        if !o.passed() {
                            if let Some(red) = o.red_violated {
                                println!("    RED-violated:    {red}");
                            }
                            if let Some(g) = o.green_complied {
                                println!("    GREEN-complied:  {g}");
                            }
                            if let Some(f) = o.forbid_respected {
                                println!("    forbid-respected: {f}");
                            }
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    if let Some(msg) = &args.test {
        match route(msg, &skills) {
            Some(m) => match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let v = serde_json::json!({
                        "matched_skill": m.skill.id(),
                        "description": m.skill.description(),
                        "matched_keywords": m.matched_keywords,
                    });
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                OutputFormat::Table => {
                    println!(
                        "match: {} — keywords: {}",
                        m.skill.id(),
                        m.matched_keywords.join(", ")
                    );
                    println!("  description: {}", m.skill.description());
                }
            },
            None => match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"matched_skill": serde_json::Value::Null})
                        )?
                    );
                }
                OutputFormat::Table => {
                    println!("no skill activated for this message");
                }
            },
        }
        return Ok(());
    }

    // Default + --list.
    match args.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&skills.iter().map(|s| &s.manifest).collect::<Vec<_>>())?
        ),
        OutputFormat::Jsonl => {
            for s in &skills {
                println!("{}", serde_json::to_string(&s.manifest)?);
            }
        }
        OutputFormat::Table => {
            if skills.is_empty() {
                println!("no skills installed in {}", skills_dir.display());
                println!("create one with:");
                println!(
                    "  mkdir -p {0}/<skill-id> && $EDITOR {0}/<skill-id>/skill.yaml",
                    skills_dir.display()
                );
            } else {
                println!("{:<24} {:<7} {:<5} description", "id", "enabled", "kw#");
                println!("{}", "-".repeat(78));
                for s in &skills {
                    let enabled = if s.is_enabled() { "yes" } else { "no" };
                    let desc = if s.description().len() > 40 {
                        format!("{}…", &s.description()[..39])
                    } else {
                        s.description().to_string()
                    };
                    println!(
                        "{:<24} {:<7} {:<5} {}",
                        truncate(s.id(), 24),
                        enabled,
                        s.trigger_keywords().len(),
                        desc
                    );
                }
            }
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}
