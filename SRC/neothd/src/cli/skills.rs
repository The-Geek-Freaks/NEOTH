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

    /// GOLD-ADOPT-14 — activate a skill that ships disabled (e.g. the imported
    /// `pm-*` skills): adds it to `freedom.yaml::skills.enabled` (clearing any
    /// disable). Persists across restarts + binary upgrades.
    #[arg(long, value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install", "uninstall", "create", "disable"])]
    pub enable: Option<String>,

    /// GOLD-ADOPT-14 — deactivate a bundled skill: adds it to
    /// `freedom.yaml::skills.disabled` (clearing any enable). `disabled` always
    /// wins, so this also overrides a prior `--enable`.
    #[arg(long, value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install", "uninstall", "create", "enable"])]
    pub disable: Option<String>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// GOLD-ADOPT-14 — pure enable/disable mutation on the skills config: lowercase
/// the id, drop it from BOTH lists (dedup + idempotent), then add it to the
/// chosen list. `disabled`-wins is enforced by the loader, not here.
fn apply_skill_toggle(skills: &mut crate::config::SkillsConfig, id_lc: &str, turn_on: bool) {
    skills.enabled.retain(|s| s.trim().to_lowercase() != id_lc);
    skills.disabled.retain(|s| s.trim().to_lowercase() != id_lc);
    if turn_on {
        skills.enabled.push(id_lc.to_string());
    } else {
        skills.disabled.push(id_lc.to_string());
    }
}

/// Canonical skill-toggle mutation for CLI, slash actions, and future GUI
/// callers. Validation happens before the locked config RMW; malformed
/// freedom.yaml bytes are preserved by [`FreedomConfig::update_at`].
pub(crate) async fn set_skill_enabled_at(
    home: &std::path::Path,
    id: &str,
    turn_on: bool,
) -> Result<String> {
    let id_lc = id.trim().to_lowercase();
    if id_lc.is_empty() {
        anyhow::bail!("skill id must not be empty");
    }
    let skills = load_all(&home.join("skills")).await?;
    if !skills
        .iter()
        .any(|skill| skill.id().to_lowercase() == id_lc)
    {
        anyhow::bail!("no skill with id '{id}' — run `neoth skills --list` to see installed ids");
    }

    FreedomConfig::update_at(&home.join("freedom.yaml"), |cfg| {
        apply_skill_toggle(&mut cfg.skills, &id_lc, turn_on);
        Ok(())
    })
    .map_err(|error| anyhow::anyhow!("update freedom.yaml: {error}"))?;
    Ok(id_lc)
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

    // GOLD-ADOPT-14 — enable/disable toggle, persisted to freedom.yaml.
    if args.enable.is_some() || args.disable.is_some() {
        return run_skill_toggle(&args, &skills).await;
    }

    if let Some(skill_id) = &args.run_tests {
        let skill = skills.iter().find(|s| s.id() == skill_id).ok_or_else(|| {
            anyhow::anyhow!(
                "no skill with id '{skill_id}' loaded from {}",
                skills_dir.display(),
            )
        })?;
        let config = FreedomConfig::load_from_default_path()?;
        let provider =
            crate::providers::from_config_at(&config, &FreedomConfig::default_neoth_home()).await?;
        let default_model = crate::providers::provider_default_wire_model(provider.as_ref());
        let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            provider,
            crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot(
                config.autonomy_policy(),
                config.tokens.max_per_request,
            )?,
            default_model,
            "skills.test_harness",
        );
        let outcomes = crate::skills::test_harness::run_all_scenarios_for(&provider, skill).await?;
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
                    let desc = truncate(s.description(), 40);
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

/// GOLD-ADOPT-14 — `neoth skill {--enable,--disable} <id>`: validate the id is a
/// real loaded skill, then persist the toggle to `freedom.yaml::skills.{enabled,
/// disabled}` (atomic, secret-stripped). Mirrors the `neoth council suppress`
/// load→mutate→write pattern. Bails when no freedom.yaml exists (init first).
async fn run_skill_toggle(
    args: &SkillsArgs,
    skills: &[crate::skills::schema::Skill],
) -> Result<()> {
    let (id, turn_on) = match (&args.enable, &args.disable) {
        (Some(id), _) => (id.as_str(), true),
        (_, Some(id)) => (id.as_str(), false),
        // The dispatcher only calls this when one of the two is Some.
        _ => unreachable!("run_skill_toggle requires --enable or --disable"),
    };
    // `skills` was already loaded by the caller; keep the invariant explicit
    // while routing the mutation through the shared locked helper.
    debug_assert!(
        skills
            .iter()
            .any(|skill| skill.id().eq_ignore_ascii_case(id))
    );
    let id_lc = set_skill_enabled_at(&FreedomConfig::default_neoth_home(), id, turn_on).await?;

    let state = if turn_on { "enabled" } else { "disabled" };
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({ "id": id_lc, "state": state }))?
            );
        }
        OutputFormat::Table => {
            println!("Skill `{id_lc}` {state} (freedom.yaml::skills.{state}).");
            println!("  Applies on the next skill load (daemon reload / next CLI turn).");
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!(
            "{}…",
            s.chars().take(n.saturating_sub(1)).collect::<String>()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SkillsConfig;

    #[test]
    fn truncate_is_unicode_boundary_safe() {
        let description = format!("{}🌍tail", "a".repeat(38));
        assert_eq!(truncate(&description, 40), format!("{}🌍…", "a".repeat(38)));
    }

    #[test]
    fn toggle_enable_moves_id_from_disabled_to_enabled() {
        let mut s = SkillsConfig {
            disabled: vec!["pm-create-prd".into(), "raskal".into()],
            ..SkillsConfig::default()
        };
        apply_skill_toggle(&mut s, "pm-create-prd", true);
        assert!(s.enabled.contains(&"pm-create-prd".to_string()));
        assert!(
            !s.disabled.contains(&"pm-create-prd".to_string()),
            "enable must clear a prior disable"
        );
        // Unrelated entries are left untouched.
        assert!(s.disabled.contains(&"raskal".to_string()));
    }

    #[test]
    fn toggle_disable_moves_id_from_enabled_to_disabled() {
        let mut s = SkillsConfig {
            enabled: vec!["pm-swot-analysis".into()],
            ..SkillsConfig::default()
        };
        apply_skill_toggle(&mut s, "pm-swot-analysis", false);
        assert!(s.disabled.contains(&"pm-swot-analysis".to_string()));
        assert!(!s.enabled.contains(&"pm-swot-analysis".to_string()));
    }

    #[test]
    fn toggle_is_idempotent_no_duplicates() {
        let mut s = SkillsConfig::default();
        apply_skill_toggle(&mut s, "pm-lean-canvas", true);
        apply_skill_toggle(&mut s, "pm-lean-canvas", true);
        assert_eq!(
            s.enabled.iter().filter(|x| *x == "pm-lean-canvas").count(),
            1,
            "re-enabling must not duplicate the id"
        );
        assert!(s.disabled.is_empty());
    }

    #[test]
    fn toggle_dedups_case_insensitively() {
        // A pre-existing mixed-case entry must not survive a re-toggle.
        let mut s = SkillsConfig {
            enabled: vec!["PM-Retro".into()],
            ..SkillsConfig::default()
        };
        apply_skill_toggle(&mut s, "pm-retro", false);
        assert!(
            s.enabled.is_empty(),
            "mixed-case enable entry must be cleared"
        );
        assert_eq!(s.disabled, vec!["pm-retro".to_string()]);
    }
}
