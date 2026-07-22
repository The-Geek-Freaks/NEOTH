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
use serde::Serialize;
use tracing::info;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::skills::loader::{SkillInventoryOrigin, SkillInventoryRow, diagnostic_inventory};
use crate::skills::{installer, load_all, route};

/// Stable machine-readable acknowledgement shared with the GUI. Keep this
/// explicit rather than serialising `InstallReport` directly: the report owns
/// filesystem types while the wire contract intentionally contains strings.
#[derive(Serialize)]
struct SkillInstallReceipt<'a> {
    id: &'a str,
    installed_at: String,
    replaced_existing: bool,
    source_manifest_sha256: &'a str,
    source_generation_sha256: &'a str,
    replaced_generation_sha256: Option<&'a str>,
    warnings: &'a [String],
}

fn skill_install_receipt(report: &installer::InstallReport) -> SkillInstallReceipt<'_> {
    SkillInstallReceipt {
        id: &report.id,
        installed_at: report.installed_at.display().to_string(),
        replaced_existing: report.replaced_existing,
        source_manifest_sha256: &report.source_manifest_sha256,
        source_generation_sha256: &report.source_generation_sha256,
        replaced_generation_sha256: report.replaced_generation_sha256.as_deref(),
        warnings: &report.warnings,
    }
}

#[derive(Serialize)]
struct SkillInstallPreflightReceipt<'a> {
    id: &'a str,
    source_manifest_sha256: &'a str,
    source_generation_sha256: &'a str,
    replacing_existing: bool,
    target_generation_sha256: Option<&'a str>,
}

fn skill_install_preflight_receipt(
    report: &installer::InstallPreflight,
) -> SkillInstallPreflightReceipt<'_> {
    SkillInstallPreflightReceipt {
        id: &report.id,
        source_manifest_sha256: &report.source_manifest_sha256,
        source_generation_sha256: &report.source_generation_sha256,
        replacing_existing: report.replacing_existing,
        target_generation_sha256: report.target_generation_sha256.as_deref(),
    }
}

#[derive(Serialize)]
struct SkillTargetPreflightReceipt<'a> {
    id: &'a str,
    target_generation_sha256: Option<&'a str>,
}

fn skill_target_preflight_receipt(
    report: &installer::SkillTargetPreflight,
) -> SkillTargetPreflightReceipt<'_> {
    SkillTargetPreflightReceipt {
        id: &report.id,
        target_generation_sha256: report.target_generation_sha256.as_deref(),
    }
}

#[derive(Serialize)]
struct SkillUninstallReceipt<'a> {
    id: &'a str,
    removed: bool,
    removed_generation_sha256: Option<&'a str>,
    warnings: &'a [String],
}

fn skill_uninstall_receipt(report: &installer::UninstallReport) -> SkillUninstallReceipt<'_> {
    SkillUninstallReceipt {
        id: &report.id,
        removed: report.removed,
        removed_generation_sha256: report.removed_generation_sha256.as_deref(),
        warnings: &report.warnings,
    }
}

/// Stable machine-readable create acknowledgement. `replaced_existing` is
/// part of the receipt so GUI/operator surfaces never infer replacement from
/// diagnostics or preflight state.
#[derive(Serialize)]
struct SkillCreateReceipt<'a> {
    id: &'a str,
    path: String,
    manifest_sha256: &'a str,
    target_generation_sha256: &'a str,
    replaced_generation_sha256: Option<&'a str>,
    replaced_existing: bool,
    warnings: &'a [String],
}

fn skill_create_receipt(report: &crate::skills::creator::CreateReport) -> SkillCreateReceipt<'_> {
    SkillCreateReceipt {
        id: &report.id,
        path: report.path.display().to_string(),
        manifest_sha256: &report.manifest_sha256,
        target_generation_sha256: &report.target_generation_sha256,
        replaced_generation_sha256: report.replaced_generation_sha256.as_deref(),
        replaced_existing: report.replaced_existing,
        warnings: &report.warnings,
    }
}

#[derive(Args, Debug, Clone)]
#[command(group(
    clap::ArgGroup::new("force_target")
        .args(["install", "create"])
        .multiple(false)
))]
pub struct SkillsArgs {
    /// Print the table of installed skills.
    #[arg(long, conflicts_with_all = ["test", "run_tests", "install", "inspect_install", "inspect_target", "uninstall", "create", "enable", "disable"])]
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

    /// Validate a local skill source and report the exact manifest generation
    /// plus whether its id already exists. Read-only except crash recovery.
    #[arg(long = "inspect-install", value_name = "PATH", conflicts_with_all = ["list", "test", "run_tests", "install", "uninstall", "create", "enable", "disable"])]
    pub inspect_install: Option<PathBuf>,

    /// Inspect the exact currently-live public entry (healthy or broken)
    /// without following links/reparse points. Read-only except crash recovery.
    #[arg(long = "inspect-target", value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install", "inspect_install", "uninstall", "create", "enable", "disable"])]
    pub inspect_target: Option<String>,

    /// Bind an install to the id returned by `--inspect-install`.
    #[arg(long = "expected-id", value_name = "ID", requires_all = ["install", "expected_generation_sha256", "expected_target_generation_sha256"])]
    pub expected_id: Option<String>,

    /// Bind an install to every path/type/byte in the package inspected before
    /// GUI replacement confirmation.
    #[arg(long = "expected-generation-sha256", value_name = "SHA256", requires_all = ["install", "expected_id", "expected_target_generation_sha256"])]
    pub expected_generation_sha256: Option<String>,

    /// Bind replacement consent to the exact installed generation seen during
    /// preflight. Use `absent` when preflight observed no destination.
    #[arg(long = "expected-target-generation-sha256", value_name = "SHA256_OR_ABSENT", requires_all = ["install", "expected_id", "expected_generation_sha256"])]
    pub expected_target_generation_sha256: Option<String>,

    /// Bind GUI create/repair to the exact id returned by `--inspect-target`.
    #[arg(long = "expected-create-id", value_name = "ID", requires_all = ["create", "expected_create_target_generation_sha256"])]
    pub expected_create_id: Option<String>,

    /// Bind create/repair to the exact destination generation, or to explicit
    /// absence with the literal `absent`.
    #[arg(long = "expected-create-target-generation-sha256", value_name = "SHA256_OR_ABSENT", requires_all = ["create", "expected_create_id"])]
    pub expected_create_target_generation_sha256: Option<String>,

    /// QM-11 uninstall the named skill from `~/.neoth/skills/<id>/`.
    /// Idempotent — missing id is reported as such, not an error.
    #[arg(long, value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install"])]
    pub uninstall: Option<String>,

    /// Bind GUI uninstall to the exact id returned by `--inspect-target`.
    #[arg(long = "expected-uninstall-id", value_name = "ID", requires_all = ["uninstall", "expected_uninstall_generation_sha256"])]
    pub expected_uninstall_id: Option<String>,

    /// Bind GUI uninstall to the exact healthy or broken destination
    /// generation returned by `--inspect-target`.
    #[arg(long = "expected-uninstall-generation-sha256", value_name = "SHA256", requires_all = ["uninstall", "expected_uninstall_id"])]
    pub expected_uninstall_generation_sha256: Option<String>,

    /// Explicitly replace an existing skill for `--install` or replace its
    /// manifest for `--create`. Both operations refuse replacement by default.
    #[arg(
        long,
        requires = "force_target",
        conflicts_with_all = ["list", "test", "run_tests", "uninstall", "enable", "disable"]
    )]
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
    if args.force && args.install.is_none() && !args.create {
        anyhow::bail!("--force requires --install or --create");
    }

    if let Some(source) = &args.inspect_install {
        let report = installer::inspect_local_install(source, &skills_dir)?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::to_string(&skill_install_preflight_receipt(&report))?
            ),
            OutputFormat::Table => {
                println!(
                    "Skill `{}` validated (replacement: {}).",
                    report.id,
                    if report.replacing_existing {
                        "required"
                    } else {
                        "no"
                    }
                );
                println!("Manifest SHA-256:   {}", report.source_manifest_sha256);
                println!("Generation SHA-256: {}", report.source_generation_sha256);
            }
        }
        return Ok(());
    }

    if let Some(id) = &args.inspect_target {
        let report = installer::inspect_installed_target(&skills_dir, id)?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::to_string(&skill_target_preflight_receipt(&report))?
            ),
            OutputFormat::Table => match &report.target_generation_sha256 {
                Some(generation) => {
                    println!("Skill `{id}` target generation SHA-256: {generation}")
                }
                None => println!("Skill `{id}` is absent under {}", skills_dir.display()),
            },
        }
        return Ok(());
    }

    // QM-11 install — happens BEFORE the load so the operator sees
    // their just-installed skill in the post-install list.
    if let Some(source) = &args.install {
        let expectation = match (
            &args.expected_id,
            &args.expected_generation_sha256,
            &args.expected_target_generation_sha256,
        ) {
            (Some(id), Some(source_generation_sha256), Some(target_generation)) => {
                let target_generation_sha256 = if target_generation == "absent" {
                    None
                } else {
                    Some(target_generation.clone())
                };
                Some(installer::InstallExpectation {
                    id: id.clone(),
                    source_generation_sha256: source_generation_sha256.clone(),
                    target_generation_sha256,
                })
            }
            (None, None, None) => None,
            _ => anyhow::bail!(
                "--expected-id, --expected-generation-sha256, and --expected-target-generation-sha256 must be supplied together"
            ),
        };
        let report = installer::install_from_local_with_expectation(
            source,
            &skills_dir,
            args.force,
            expectation.as_ref(),
        )?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string(&skill_install_receipt(&report))?
                );
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
                for warning in &report.warnings {
                    eprintln!("Warning: {warning}");
                }
            }
        }
        return Ok(());
    }

    // QM-11 uninstall.
    if let Some(id) = &args.uninstall {
        let expectation = match (
            &args.expected_uninstall_id,
            &args.expected_uninstall_generation_sha256,
        ) {
            (Some(expected_id), Some(target_generation_sha256)) => {
                Some(installer::UninstallExpectation {
                    id: expected_id.clone(),
                    target_generation_sha256: target_generation_sha256.clone(),
                })
            }
            (None, None) => None,
            _ => anyhow::bail!(
                "--expected-uninstall-id and --expected-uninstall-generation-sha256 must be supplied together"
            ),
        };
        let report = installer::uninstall_with_report_and_expectation(
            &skills_dir,
            id,
            expectation.as_ref(),
        )?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string(&skill_uninstall_receipt(&report))?
                );
            }
            OutputFormat::Table => {
                if report.removed {
                    println!("Uninstalled `{id}`");
                } else {
                    println!(
                        "Skill `{id}` was not installed under {} — nothing to remove.",
                        skills_dir.display()
                    );
                }
                for warning in &report.warnings {
                    eprintln!("Warning: {warning}");
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
        let existing = if args.force {
            crate::skills::creator::ExistingSkillPolicy::Replace
        } else {
            crate::skills::creator::ExistingSkillPolicy::Refuse
        };
        let expectation = match (
            &args.expected_create_id,
            &args.expected_create_target_generation_sha256,
        ) {
            (Some(expected_id), Some(target_generation)) => {
                let target_generation_sha256 = if target_generation == "absent" {
                    None
                } else {
                    Some(target_generation.clone())
                };
                Some(crate::skills::creator::CreateExpectation {
                    id: expected_id.clone(),
                    target_generation_sha256,
                })
            }
            (None, None) => None,
            _ => anyhow::bail!(
                "--expected-create-id and --expected-create-target-generation-sha256 must be supplied together"
            ),
        };
        let report = crate::skills::creator::create_skill_with_expectation(
            &skills_dir,
            params,
            existing,
            expectation.as_ref(),
        )?;
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!("{}", serde_json::to_string(&skill_create_receipt(&report))?);
            }
            OutputFormat::Table => {
                let verb = if report.replaced_existing {
                    "Replaced"
                } else {
                    "Created"
                };
                println!("{verb} skill `{}` at {}", report.id, report.path.display());
                for warning in &report.warnings {
                    eprintln!("Warning: {warning}");
                }
                println!("Try it: neoth skills --test \"<a message that should trigger it>\"");
            }
        }
        return Ok(());
    }

    if args.list
        || (args.test.is_none()
            && args.run_tests.is_none()
            && args.enable.is_none()
            && args.disable.is_none())
    {
        let inventory = diagnostic_inventory(&skills_dir).await?;
        print_skill_inventory(&inventory, args.output, &skills_dir)?;
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

    unreachable!("every skills command mode returns before the strict runtime load falls through")
}

fn print_skill_inventory(
    inventory: &[SkillInventoryRow],
    output: OutputFormat,
    skills_dir: &std::path::Path,
) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(inventory)?),
        OutputFormat::Jsonl => {
            for row in inventory {
                println!("{}", serde_json::to_string(row)?);
            }
        }
        OutputFormat::Table => {
            if inventory.is_empty() {
                println!("no skills available in {}", skills_dir.display());
                return Ok(());
            }
            println!(
                "{:<9} {:<24} {:<8} {:<7} description",
                "status", "id", "origin", "enabled"
            );
            println!("{}", "-".repeat(92));
            for row in inventory {
                match row {
                    SkillInventoryRow::Healthy {
                        manifest, origin, ..
                    } => println!(
                        "{:<9} {:<24} {:<8} {:<7} {}",
                        "healthy",
                        truncate(&manifest.id, 24),
                        match origin {
                            SkillInventoryOrigin::Bundled => "bundled",
                            SkillInventoryOrigin::User => "user",
                        },
                        if manifest.enabled { "yes" } else { "no" },
                        truncate(&manifest.description, 40),
                    ),
                    SkillInventoryRow::Broken {
                        id, error, path, ..
                    } => {
                        println!(
                            "{:<9} {:<24} {:<8} {:<7} {}",
                            "BROKEN",
                            truncate(id, 24),
                            "user",
                            "n/a",
                            truncate(error, 40),
                        );
                        println!("  reason: {error}");
                        println!("  path:   {}", path.display());
                    }
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
    use clap::Parser as _;

    #[test]
    fn force_parses_for_create_and_install_but_not_by_itself() {
        let create = crate::cli::Cli::try_parse_from([
            "neoth",
            "skills",
            "--create",
            "--force",
            "--non-interactive",
            "--create-id",
            "alpha",
            "--create-description",
            "Alpha skill",
        ])
        .unwrap();
        let crate::cli::Commands::Skills(create) = create.command else {
            panic!("expected skills command");
        };
        assert!(create.create);
        assert!(create.force);

        let install =
            crate::cli::Cli::try_parse_from(["neoth", "skills", "--install", "./alpha", "--force"])
                .unwrap();
        let crate::cli::Commands::Skills(install) = install.command else {
            panic!("expected skills command");
        };
        assert!(install.install.is_some());
        assert!(install.force);

        assert!(crate::cli::Cli::try_parse_from(["neoth", "skills", "--force"]).is_err());
    }

    #[test]
    fn install_expectation_flags_are_typed_and_must_be_supplied_together() {
        let hash = "a".repeat(64);
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "skills",
            "--install",
            "./alpha",
            "--expected-id",
            "alpha",
            "--expected-generation-sha256",
            hash.as_str(),
            "--expected-target-generation-sha256",
            "absent",
        ])
        .unwrap();
        let crate::cli::Commands::Skills(args) = cli.command else {
            panic!("expected skills command");
        };
        assert_eq!(args.expected_id.as_deref(), Some("alpha"));
        assert_eq!(
            args.expected_generation_sha256.as_deref(),
            Some(hash.as_str())
        );
        assert_eq!(
            args.expected_target_generation_sha256.as_deref(),
            Some("absent")
        );

        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "skills",
                "--install",
                "./alpha",
                "--expected-id",
                "alpha",
            ])
            .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "skills",
                "--inspect-install",
                "./alpha",
                "--install",
                "./alpha",
            ])
            .is_err()
        );
    }

    #[test]
    fn create_and_uninstall_expectations_are_typed_and_all_or_none() {
        let hash = "a".repeat(64);
        let create = crate::cli::Cli::try_parse_from([
            "neoth",
            "skills",
            "--create",
            "--non-interactive",
            "--create-id",
            "alpha",
            "--create-description",
            "Alpha skill",
            "--expected-create-id",
            "alpha",
            "--expected-create-target-generation-sha256",
            "absent",
        ])
        .unwrap();
        let crate::cli::Commands::Skills(create) = create.command else {
            panic!("expected skills command");
        };
        assert_eq!(create.expected_create_id.as_deref(), Some("alpha"));
        assert_eq!(
            create.expected_create_target_generation_sha256.as_deref(),
            Some("absent")
        );

        let uninstall = crate::cli::Cli::try_parse_from([
            "neoth",
            "skills",
            "--uninstall",
            "alpha",
            "--expected-uninstall-id",
            "alpha",
            "--expected-uninstall-generation-sha256",
            hash.as_str(),
        ])
        .unwrap();
        let crate::cli::Commands::Skills(uninstall) = uninstall.command else {
            panic!("expected skills command");
        };
        assert_eq!(uninstall.expected_uninstall_id.as_deref(), Some("alpha"));
        assert_eq!(
            uninstall.expected_uninstall_generation_sha256.as_deref(),
            Some(hash.as_str())
        );

        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "skills",
                "--create",
                "--expected-create-id",
                "alpha",
            ])
            .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "skills",
                "--uninstall",
                "alpha",
                "--expected-uninstall-id",
                "alpha",
            ])
            .is_err()
        );
    }

    #[test]
    fn truncate_is_unicode_boundary_safe() {
        let description = format!("{}🌍tail", "a".repeat(38));
        assert_eq!(truncate(&description, 40), format!("{}🌍…", "a".repeat(38)));
    }

    #[test]
    fn install_receipt_keeps_warning_array_in_the_json_contract() {
        let report = installer::InstallReport {
            id: "my-skill".to_string(),
            installed_at: PathBuf::from("skills").join("my-skill"),
            replaced_existing: true,
            source_manifest_sha256: "a".repeat(64),
            source_generation_sha256: "b".repeat(64),
            replaced_generation_sha256: Some("c".repeat(64)),
            warnings: vec!["old backup could not be removed".to_string()],
        };

        let value = serde_json::to_value(skill_install_receipt(&report)).unwrap();
        assert_eq!(value["id"], "my-skill");
        assert_eq!(
            value["installed_at"],
            report.installed_at.display().to_string()
        );
        assert_eq!(value["replaced_existing"], true);
        assert_eq!(value["source_manifest_sha256"], "a".repeat(64));
        assert_eq!(value["source_generation_sha256"], "b".repeat(64));
        assert_eq!(value["replaced_generation_sha256"], "c".repeat(64));
        assert_eq!(
            value["warnings"],
            serde_json::json!(["old backup could not be removed"])
        );
        assert_eq!(value.as_object().unwrap().len(), 7);
    }

    #[test]
    fn install_receipt_keeps_a_stable_empty_warning_array() {
        let report = installer::InstallReport {
            id: "new-skill".to_string(),
            installed_at: PathBuf::from("new-skill"),
            replaced_existing: false,
            source_manifest_sha256: "c".repeat(64),
            source_generation_sha256: "d".repeat(64),
            replaced_generation_sha256: None,
            warnings: Vec::new(),
        };

        let json = serde_json::to_string(&skill_install_receipt(&report)).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"id":"new-skill","installed_at":"new-skill","replaced_existing":false,"source_manifest_sha256":"{}","source_generation_sha256":"{}","replaced_generation_sha256":null,"warnings":[]}}"#,
                "c".repeat(64),
                "d".repeat(64)
            )
        );
    }

    #[test]
    fn install_preflight_receipt_is_exact_for_new_and_replacement_targets() {
        for replacing_existing in [false, true] {
            let target_generation_sha256 = replacing_existing.then(|| "a".repeat(64));
            let report = installer::InstallPreflight {
                id: "my-skill".to_string(),
                source_manifest_sha256: "e".repeat(64),
                source_generation_sha256: "f".repeat(64),
                replacing_existing,
                target_generation_sha256: target_generation_sha256.clone(),
            };

            let value = serde_json::to_value(skill_install_preflight_receipt(&report)).unwrap();
            assert_eq!(
                value,
                serde_json::json!({
                    "id": "my-skill",
                    "source_manifest_sha256": "e".repeat(64),
                    "source_generation_sha256": "f".repeat(64),
                    "replacing_existing": replacing_existing,
                    "target_generation_sha256": target_generation_sha256,
                })
            );
            assert_eq!(value.as_object().unwrap().len(), 5);
        }
    }

    #[test]
    fn target_preflight_receipt_is_exact_for_absent_and_present_entries() {
        for target_generation_sha256 in [None, Some("a".repeat(64))] {
            let report = installer::SkillTargetPreflight {
                id: "my-skill".to_string(),
                target_generation_sha256: target_generation_sha256.clone(),
            };
            let value = serde_json::to_value(skill_target_preflight_receipt(&report)).unwrap();
            assert_eq!(
                value,
                serde_json::json!({
                    "id": "my-skill",
                    "target_generation_sha256": target_generation_sha256,
                })
            );
            assert_eq!(value.as_object().unwrap().len(), 2);
        }
    }

    #[test]
    fn diagnostic_inventory_json_keeps_healthy_and_broken_rows_structural() {
        let manifest: crate::skills::schema::SkillManifest = serde_yaml::from_str(
            "id: alpha\ndescription: Alpha skill\ntrigger_keywords: [one, two]\n",
        )
        .unwrap();
        let rows = vec![
            SkillInventoryRow::Healthy {
                manifest: Box::new(manifest),
                origin: SkillInventoryOrigin::User,
                path: Some(PathBuf::from("skills").join("alpha")),
            },
            SkillInventoryRow::Broken {
                id: "broken-skill".to_string(),
                error: "missing skill.yaml".to_string(),
                path: PathBuf::from("skills").join("broken-skill"),
                repairability: installer::SkillRepairability::ManifestReplaceable,
            },
        ];

        let value = serde_json::to_value(&rows).unwrap();
        let healthy = value[0].as_object().unwrap();
        assert_eq!(healthy["status"], "healthy");
        assert_eq!(healthy["origin"], "user");
        let expected_path = PathBuf::from("skills").join("alpha");
        let expected_path = expected_path.to_string_lossy();
        assert_eq!(healthy["path"].as_str(), Some(expected_path.as_ref()));
        assert_eq!(healthy["manifest"]["id"], "alpha");
        assert_eq!(healthy.len(), 4);

        let broken = value[1].as_object().unwrap();
        assert_eq!(broken["status"], "broken");
        assert_eq!(broken["id"], "broken-skill");
        assert_eq!(broken["error"], "missing skill.yaml");
        assert_eq!(broken["repairability"], "manifest_replaceable");
        assert_eq!(broken.len(), 5);
    }

    #[test]
    fn uninstall_receipt_keeps_idempotence_and_warnings_exact() {
        for removed in [false, true] {
            let report = installer::UninstallReport {
                id: "my-skill".to_string(),
                removed,
                removed_generation_sha256: removed.then(|| "b".repeat(64)),
                warnings: vec!["private cleanup remains pending".to_string()],
            };
            let value = serde_json::to_value(skill_uninstall_receipt(&report)).unwrap();
            assert_eq!(
                value,
                serde_json::json!({
                    "id": "my-skill",
                    "removed": removed,
                    "removed_generation_sha256": removed.then(|| "b".repeat(64)),
                    "warnings": ["private cleanup remains pending"],
                })
            );
            assert_eq!(value.as_object().unwrap().len(), 4);
        }
    }

    #[test]
    fn create_receipt_reports_new_and_replaced_generations_structurally() {
        for replaced_existing in [false, true] {
            let report = crate::skills::creator::CreateReport {
                id: "my-skill".to_string(),
                path: PathBuf::from("skills").join("my-skill").join("skill.yaml"),
                manifest_sha256: "a".repeat(64),
                target_generation_sha256: "b".repeat(64),
                replaced_generation_sha256: replaced_existing.then(|| "c".repeat(64)),
                replaced_existing,
                warnings: vec!["directory sync warning".to_string()],
            };

            let value = serde_json::to_value(skill_create_receipt(&report)).unwrap();
            assert_eq!(value["id"], "my-skill");
            assert_eq!(value["path"], report.path.display().to_string());
            assert_eq!(value["manifest_sha256"], "a".repeat(64));
            assert_eq!(value["target_generation_sha256"], "b".repeat(64));
            assert_eq!(
                value["replaced_generation_sha256"],
                replaced_existing
                    .then(|| serde_json::Value::String("c".repeat(64)))
                    .unwrap_or(serde_json::Value::Null)
            );
            assert_eq!(value["replaced_existing"], replaced_existing);
            assert_eq!(
                value["warnings"],
                serde_json::json!(["directory sync warning"])
            );
            assert_eq!(value.as_object().unwrap().len(), 7);
        }
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
