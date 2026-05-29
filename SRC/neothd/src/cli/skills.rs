//! `neoth skills` — operator-facing view of installed skills + router probe.
//!
//! Modes:
//!   `--list`        load all manifests, show id / description / enabled / keywords
//!   `--test "<msg>"` route the message through the keyword scan, print which
//!                   skill (if any) would activate plus the matched keywords
//!
//! Output respects the global `--output` flag.

use std::path::PathBuf;

use std::io::IsTerminal;

use anyhow::Result;
use clap::Args;
use tracing::info;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::skills::{installer, load_all, route};

#[derive(Args, Debug, Clone)]
pub struct SkillsArgs {
    /// Print the table of installed skills.
    #[arg(long, conflicts_with_all = ["test", "run_tests", "install", "uninstall"])]
    pub list: bool,

    /// Run the router against an arbitrary message and report the match.
    #[arg(long, value_name = "MESSAGE", conflicts_with_all = ["list", "run_tests", "install", "uninstall"])]
    pub test: Option<String>,

    /// Run the RED/GREEN scenario suite for a skill. Loads
    /// `~/.neoth/skills/<id>/tests/*.yaml`, runs each scenario twice
    /// (without and with the skill's system prompt), reports pass/fail.
    /// Requires a working provider in `freedom.yaml`. Phase 33+ (obra/
    /// superpowers Item #3 port).
    #[arg(long = "run-tests", value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "install", "uninstall"])]
    pub run_tests: Option<String>,

    /// QM-11 install a skill from a local directory containing `skill.yaml`.
    /// Validates the manifest BEFORE copying; refuses to replace an
    /// existing install unless `--force` is set.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["list", "test", "run_tests", "uninstall"])]
    pub install: Option<PathBuf>,

    /// QM-11 uninstall the named skill from `~/.neoth/skills/<id>/`.
    /// Idempotent — missing id is reported as such, not an error.
    #[arg(long, value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install"])]
    pub uninstall: Option<String>,

    /// QM-11: force replacement when `--install` would overwrite an
    /// existing skill of the same id.
    #[arg(long, requires = "install")]
    pub force: bool,

    /// UX-06 — create a new skill manifest via an interactive wizard (or
    /// `--create-*` flags / `--non-interactive`). Writes a validated
    /// `~/.neoth/skills/<id>/skill.yaml` — no Rust required.
    #[arg(long, conflicts_with_all = ["list", "test", "run_tests", "install", "uninstall"])]
    pub create: bool,

    /// UX-06 non-interactive: skill id (kebab-case, `[a-zA-Z0-9_-]`).
    #[arg(long = "create-id", value_name = "ID", requires = "create")]
    pub create_id: Option<String>,

    /// UX-06 non-interactive: one-line description.
    #[arg(long = "create-description", value_name = "DESC", requires = "create")]
    pub create_description: Option<String>,

    /// UX-06 non-interactive: comma-separated trigger keywords.
    #[arg(long = "create-keywords", value_name = "KW,...", requires = "create")]
    pub create_keywords: Option<String>,

    /// UX-06 non-interactive: system prompt text.
    #[arg(
        long = "create-system-prompt",
        value_name = "PROMPT",
        requires = "create"
    )]
    pub create_system_prompt: Option<String>,

    /// UX-06: skip interactive prompts even on a TTY (drives `--create`
    /// from the `--create-*` flags only).
    #[arg(long = "non-interactive", requires = "create")]
    pub create_non_interactive: bool,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_skills(args: SkillsArgs) -> Result<()> {
    let skills_dir = FreedomConfig::default_neoth_home().join("skills");

    // QM-11 install — happens BEFORE the load so the operator sees
    // their just-installed skill in the post-install list.
    if let Some(source) = &args.install {
        let report = installer::install_from_local(source, &skills_dir, args.force)?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let v = serde_json::json!({
                    "id": report.id,
                    "installed_at": report.installed_at.display().to_string(),
                    "replaced_existing": report.replaced_existing,
                });
                println!("{}", serde_json::to_string(&v)?);
            }
            OutputFormat::Table => {
                let verb = if report.replaced_existing {
                    "Reinstalled"
                } else {
                    "Installed"
                };
                println!(
                    "{verb} `{}` at {}",
                    report.id,
                    report.installed_at.display()
                );
            }
        }
        return Ok(());
    }

    // QM-11 uninstall.
    if let Some(id) = &args.uninstall {
        let removed = installer::uninstall(&skills_dir, id)?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let v = serde_json::json!({
                    "id": id,
                    "removed": removed,
                });
                println!("{}", serde_json::to_string(&v)?);
            }
            OutputFormat::Table => {
                if removed {
                    println!("Uninstalled `{id}`");
                } else {
                    println!(
                        "Skill `{id}` was not installed under {} — nothing to remove.",
                        skills_dir.display()
                    );
                }
            }
        }
        return Ok(());
    }

    // UX-06 create — happens BEFORE the load so a missing skills dir
    // (fresh install) doesn't block creating the operator's first skill.
    if args.create {
        let interactive = !args.create_non_interactive && std::io::stdin().is_terminal();
        let params = crate::skills::creator::collect_create_params(&args, interactive)?;
        let report = crate::skills::creator::create_skill(&skills_dir, params)?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let v = serde_json::json!({
                    "id": report.id,
                    "path": report.path.display().to_string(),
                });
                println!("{}", serde_json::to_string(&v)?);
            }
            OutputFormat::Table => {
                println!("Created skill `{}` at {}", report.id, report.path.display());
                println!("Try it: neoth skills --test \"<a message that should trigger it>\"");
            }
        }
        return Ok(());
    }

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
