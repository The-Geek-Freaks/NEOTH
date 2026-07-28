//! `neoth skills` — operator-facing view of installed skills + router probe.
//!
//! Modes:
//!   `--list`        load all manifests, show id / description / enabled / keywords
//!   `--test "<msg>"` route the message through the keyword scan, print which
//!                   skill (if any) would activate plus the matched keywords
//!
//! Output respects the global `--output` flag.

use std::path::{Path, PathBuf};

use std::io::IsTerminal;

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;
use tracing::info;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::skills::loader::{SkillInventoryOrigin, SkillInventoryRow, diagnostic_inventory};
use crate::skills::mutation_lifecycle::{self, IntentDelivery as SkillIntentDelivery};
use crate::skills::{installer, load_all, operator_skill_warnings, route};

fn print_operator_skill_warnings(warnings: &[String]) {
    for warning in operator_skill_warnings(warnings) {
        eprintln!("Warning: {warning}");
    }
}

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
    warnings: Vec<&'static str>,
}

fn skill_install_receipt(report: &installer::InstallReport) -> SkillInstallReceipt<'_> {
    SkillInstallReceipt {
        id: &report.id,
        installed_at: report.installed_at.display().to_string(),
        replaced_existing: report.replaced_existing,
        source_manifest_sha256: &report.source_manifest_sha256,
        source_generation_sha256: &report.source_generation_sha256,
        replaced_generation_sha256: report.replaced_generation_sha256.as_deref(),
        warnings: operator_skill_warnings(&report.warnings),
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
    warnings: Vec<&'static str>,
}

fn skill_uninstall_receipt(report: &installer::UninstallReport) -> SkillUninstallReceipt<'_> {
    SkillUninstallReceipt {
        id: &report.id,
        removed: report.removed,
        removed_generation_sha256: report.removed_generation_sha256.as_deref(),
        warnings: operator_skill_warnings(&report.warnings),
    }
}

fn print_skill_uninstall_report(
    report: &installer::UninstallReport,
    skills_dir: &Path,
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(&skill_uninstall_receipt(report))?
            );
        }
        OutputFormat::Table => {
            if report.removed {
                println!("Uninstalled `{}`", report.id);
            } else {
                println!(
                    "Skill `{}` was not installed under {} — nothing to remove.",
                    report.id,
                    skills_dir.display()
                );
            }
            print_operator_skill_warnings(&report.warnings);
        }
    }
    Ok(())
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
    warnings: Vec<&'static str>,
}

fn skill_create_receipt(report: &crate::skills::creator::CreateReport) -> SkillCreateReceipt<'_> {
    SkillCreateReceipt {
        id: &report.id,
        path: report.path.display().to_string(),
        manifest_sha256: &report.manifest_sha256,
        target_generation_sha256: &report.target_generation_sha256,
        replaced_generation_sha256: report.replaced_generation_sha256.as_deref(),
        replaced_existing: report.replaced_existing,
        warnings: operator_skill_warnings(&report.warnings),
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
    let home = FreedomConfig::default_neoth_home();
    let skills_dir = home.join("skills");
    if args.force && args.install.is_none() && !args.create {
        anyhow::bail!("--force requires --install or --create");
    }
    reconcile_pending_skill_mutation(&home, &skills_dir)
        .await
        .context("reconcile pending audited Skill mutation")?;

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
        // R3-17: prepare privately under the shared cross-process lock, ACK the
        // exact prepared binding, then publish under that SAME lock. No second
        // preflight can race the intent's source/destination anchor identity.
        let operation_id = uuid::Uuid::now_v7().simple().to_string();
        let mut prepared = installer::prepare_install_from_local_with_expectation(
            source,
            &skills_dir,
            args.force,
            expectation.as_ref(),
            &operation_id,
        )?;
        prepared
            .mark_intent_submitting()
            .context("persist skill install intent-delivery ownership")?;
        let audit_binding = prepared.audit_binding();
        let intent_receipt = match deliver_skill_mutation_intent(&home, &audit_binding).await? {
            SkillIntentDelivery::Durable(receipt) => receipt,
            SkillIntentDelivery::DefinitelyNotRecorded(audit_error) => {
                prepared.abort_without_intent().with_context(|| {
                    format!(
                        "skill install intent was not durable and private preparation cleanup failed: {audit_error:#}"
                    )
                })?;
                return Err(audit_error.context(
                    "skill install intent was not durable; no public Skill was installed",
                ));
            }
            SkillIntentDelivery::Pending(audit_error) => {
                drop(prepared);
                return Err(audit_error.context(
                    "skill install intent delivery may still complete; private journal retained \
                     for same-operation recovery",
                ));
            }
        };
        if let Err(error) = prepared.mark_intent_durable_authenticated(intent_receipt) {
            drop(prepared);
            let recovery = reconcile_pending_skill_mutation(&home, &skills_dir).await;
            return Err(match recovery {
                Ok(()) => error.context(
                    "skill install intent was durable, but its local phase transition failed; \
                     the same operation was reconciled without committing",
                ),
                Err(recovery_error) => error.context(format!(
                    "skill install intent was durable, its local phase transition failed, and \
                     same-operation recovery remains pending: {recovery_error:#}"
                )),
            });
        }

        let report = match prepared.commit() {
            Ok(report) => report,
            Err(commit_error) => {
                let status = commit_error.state().as_str();
                let error = commit_error.into_inner();
                if let Err(recovery_error) =
                    reconcile_pending_skill_mutation(&home, &skills_dir).await
                {
                    return Err(error.context(format!(
                        "skill install failed with `{status}`, and its same-operation terminal \
                         reconciliation remains pending: {recovery_error:#}"
                    )));
                }
                return Err(error);
            }
        };
        reconcile_pending_skill_mutation(&home, &skills_dir)
            .await
            .context("skill was installed, but its committed audit remains pending")?;

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
                print_operator_skill_warnings(&report.warnings);
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
        let operation_id = uuid::Uuid::now_v7().simple().to_string();
        let preparation = installer::prepare_uninstall_with_expectation(
            &skills_dir,
            id,
            expectation.as_ref(),
            &operation_id,
        )?;
        let mut prepared = match preparation {
            installer::PreparedSkillRemovalOutcome::Unchanged(report) => {
                print_skill_uninstall_report(&report, &skills_dir, args.output)?;
                return Ok(());
            }
            installer::PreparedSkillRemovalOutcome::Prepared(prepared) => prepared,
        };
        prepared
            .mark_intent_submitting()
            .context("persist skill removal intent-delivery ownership")?;
        let audit_binding = prepared.audit_binding();
        let intent_receipt = match deliver_skill_mutation_intent(&home, &audit_binding).await? {
            SkillIntentDelivery::Durable(receipt) => receipt,
            SkillIntentDelivery::DefinitelyNotRecorded(audit_error) => {
                prepared.abort_without_intent().with_context(|| {
                    format!(
                        "skill removal intent was not durable and its journal cleanup failed: {audit_error:#}"
                    )
                })?;
                return Err(audit_error
                    .context("skill removal intent was not durable; no public Skill was removed"));
            }
            SkillIntentDelivery::Pending(audit_error) => {
                drop(prepared);
                return Err(audit_error.context(
                    "skill removal intent delivery may still complete; private journal retained \
                     for same-operation recovery",
                ));
            }
        };
        if let Err(error) = prepared.mark_intent_durable_authenticated(intent_receipt) {
            drop(prepared);
            let recovery = reconcile_pending_skill_mutation(&home, &skills_dir).await;
            return Err(match recovery {
                Ok(()) => error.context(
                    "skill removal intent was durable, but its local phase transition failed; \
                     the same operation was reconciled without committing",
                ),
                Err(recovery_error) => error.context(format!(
                    "skill removal intent was durable, its local phase transition failed, and \
                     same-operation recovery remains pending: {recovery_error:#}"
                )),
            });
        }

        let report = match prepared.commit() {
            Ok(report) => report,
            Err(commit_error) => {
                let status = commit_error.state().as_str();
                let error = commit_error.into_inner();
                if let Err(recovery_error) =
                    reconcile_pending_skill_mutation(&home, &skills_dir).await
                {
                    return Err(error.context(format!(
                        "skill removal failed with `{status}`, and its same-operation terminal \
                         reconciliation remains pending: {recovery_error:#}"
                    )));
                }
                return Err(error);
            }
        };
        reconcile_pending_skill_mutation(&home, &skills_dir)
            .await
            .context("skill removal committed, but its correlated audit remains pending")?;
        print_skill_uninstall_report(&report, &skills_dir, args.output)?;
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
        let report = crate::skills::creator::create_skill_with_expectation_audited(
            &home,
            &skills_dir,
            params,
            existing,
            expectation.as_ref(),
            installer::SkillMutationOrigin::CliCreate,
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
                print_operator_skill_warnings(&report.warnings);
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

#[cfg(test)]
fn fail_next_skill_audit_deliveries(count: usize) {
    mutation_lifecycle::fail_next_skill_audit_deliveries(count);
}

async fn deliver_skill_mutation_intent(
    home: &Path,
    binding: &installer::SkillMutationAuditBinding,
) -> Result<SkillIntentDelivery> {
    mutation_lifecycle::deliver_intent(home, None, binding).await
}

#[cfg(test)]
async fn deliver_skill_mutation_terminal_once(
    home: &Path,
    binding: &installer::SkillMutationAuditBinding,
) -> Result<()> {
    mutation_lifecycle::deliver_terminal_once(home, None, binding)
        .await
        .map(|_| ())
}

async fn reconcile_pending_skill_mutation(home: &Path, skills_dir: &Path) -> Result<()> {
    mutation_lifecycle::reconcile_pending(home, skills_dir, None).await
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
    fn install_receipt_redacts_private_warning_details_in_the_json_contract() {
        let private_warning = format!(
            "skill is installed, but cleanup of prior tree `C:\\Users\\alice\\.neoth\\skills\\.neoth-install-backup-{}` failed: access token secret",
            "deadbeef".repeat(4)
        );
        let report = installer::InstallReport {
            id: "my-skill".to_string(),
            installed_at: PathBuf::from("skills").join("my-skill"),
            replaced_existing: true,
            source_manifest_sha256: "a".repeat(64),
            source_generation_sha256: "b".repeat(64),
            replaced_generation_sha256: Some("c".repeat(64)),
            warnings: vec![private_warning.clone()],
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
            serde_json::json!([crate::skills::WARNING_CLEANUP_PENDING])
        );
        let encoded = value.to_string();
        assert!(!encoded.contains("alice"));
        assert!(!encoded.contains("access token secret"));
        assert!(!encoded.contains(&"deadbeef".repeat(4)));
        assert!(!encoded.contains(&private_warning));
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
    fn uninstall_receipt_keeps_idempotence_and_redacted_warning_class() {
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
                    "warnings": [crate::skills::WARNING_CLEANUP_PENDING],
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
                if replaced_existing {
                    serde_json::Value::String("c".repeat(64))
                } else {
                    serde_json::Value::Null
                }
            );
            assert_eq!(value["replaced_existing"], replaced_existing);
            assert_eq!(
                value["warnings"],
                serde_json::json!([crate::skills::WARNING_DURABILITY_UNCONFIRMED])
            );
            assert_eq!(value.as_object().unwrap().len(), 7);
        }
    }

    #[test]
    fn operator_warning_redaction_preserves_count_and_recovery_classes() {
        let raw = vec![
            "prior generation `C:\\private\\.neoth-install-backup-secret` was retained for crash recovery".to_string(),
            "private cleanup remains pending: bearer-token-secret".to_string(),
            "namespace transition was not durably synced: /home/alice/private".to_string(),
            "unexpected private detail: password-secret".to_string(),
        ];

        let redacted = operator_skill_warnings(&raw);
        assert_eq!(
            redacted,
            vec![
                crate::skills::WARNING_RECOVERY_RETAINED,
                crate::skills::WARNING_CLEANUP_PENDING,
                crate::skills::WARNING_DURABILITY_UNCONFIRMED,
                crate::skills::WARNING_POST_COMMIT_REDACTED,
            ]
        );
        let encoded = serde_json::to_string(&redacted).unwrap();
        for secret in [
            "private\\",
            "bearer-token",
            "/home/alice",
            "password-secret",
        ] {
            assert!(!encoded.contains(secret));
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

    /// Decode every authenticated-home WAL frame to `{event_type, payload}`
    /// JSON through the same bounded, encrypted, no-follow scanner production
    /// reconciliation uses.
    fn decode_wal_frames(home: &std::path::Path) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        crate::wal::scan::for_each_frame_at_home(
            home,
            crate::wal::scan::HomeWalScanLimits::default(),
            |_, dec| {
                let payload = serde_json::from_slice::<serde_json::Value>(dec.payload).ok();
                out.push(serde_json::json!({
                    "event_type": format!("0x{:02X}", dec.header.event_type),
                    "event_subtype": format!("0x{:02X}", dec.header.event_subtype),
                    "payload": payload,
                }));
                Ok(())
            },
        )
        .unwrap();
        out
    }

    #[tokio::test]
    async fn skill_install_emits_correlated_intent_and_committed_wal() {
        // R3-17: a skill install leaves a durable, correlated intent→committed
        // audit trail. No daemon here → the direct home-bound WAL writer (append
        // mode), so both frames must persist in order with skill-specific keys.
        let home = tempfile::TempDir::new().unwrap();
        let op = "0123456789abcdef0123456789abcdef";
        let source = "7".repeat(64);
        let prior = "1".repeat(64);
        let binding = installer::SkillMutationAuditBinding {
            operation_id: op.into(),
            kind: installer::SkillMutationKind::Replace,
            origin: installer::SkillMutationOrigin::CliInstall,
            skill_id: "demo_skill".into(),
            source_generation_sha256: Some(source.clone()),
            prior_generation_sha256: Some(prior.clone()),
            prior_object_identity_sha256: Some("4".repeat(64)),
            intent_receipt: None,
            commit_boundary_sha256: None,
            phase: installer::SkillMutationPhase::Prepared,
            observed_generation_sha256: None,
            error_sha256: None,
            created_at_unix: 1,
        };
        let super::SkillIntentDelivery::Durable(receipt) =
            super::deliver_skill_mutation_intent(home.path(), &binding)
                .await
                .unwrap()
        else {
            panic!("intent must be durable");
        };
        let mut terminal = binding.clone();
        terminal.intent_receipt = Some(receipt);
        terminal.commit_boundary_sha256 = Some("6".repeat(64));
        terminal.phase = installer::SkillMutationPhase::Committed;
        terminal.observed_generation_sha256 = Some(source.clone());
        super::deliver_skill_mutation_terminal_once(home.path(), &terminal)
            .await
            .unwrap();
        // Simulate cancellation after the first fsynced result but before the
        // outbox acknowledgement: retry must observe, not append, that result.
        super::deliver_skill_mutation_terminal_once(home.path(), &terminal)
            .await
            .unwrap();

        let frames = decode_wal_frames(home.path());
        assert_eq!(frames.len(), 2, "intent + result frames must both persist");
        assert_eq!(frames[0]["event_type"], "0x00");
        assert_eq!(frames[1]["event_type"], "0x00");
        assert_eq!(frames[0]["event_subtype"], "0x14");
        assert_eq!(frames[1]["event_subtype"], "0x15");
        let intent = &frames[0]["payload"];
        assert_eq!(intent["phase"], "intent");
        assert_eq!(intent["operation_id"], op);
        assert_eq!(intent["skill_id"], "demo_skill");
        assert_eq!(intent["source_generation_sha256"], source);
        assert_eq!(intent["replacing_existing"], true);
        assert_eq!(intent["target_generation_sha256"], prior);
        assert_eq!(intent["prior_anchor_state"], "present");
        let result = &frames[1]["payload"];
        assert_eq!(result["status"], "committed");
        assert_eq!(
            result["operation_id"], op,
            "the terminal outcome must correlate to its intent"
        );
        assert_eq!(result["skill_id"], "demo_skill");
        assert_eq!(result["replaced_existing"], true);
        assert_eq!(result["installed_generation_sha256"], source);
    }

    #[tokio::test]
    async fn skill_removal_emits_correlated_intent_and_committed_wal() {
        let home = tempfile::TempDir::new().unwrap();
        let op = "fedcba9876543210fedcba9876543210";
        let prior = "1".repeat(64);
        let binding = installer::SkillMutationAuditBinding {
            operation_id: op.into(),
            kind: installer::SkillMutationKind::Remove,
            origin: installer::SkillMutationOrigin::CliUninstall,
            skill_id: "demo_skill".into(),
            source_generation_sha256: None,
            prior_generation_sha256: Some(prior.clone()),
            prior_object_identity_sha256: Some("5".repeat(64)),
            intent_receipt: None,
            commit_boundary_sha256: None,
            phase: installer::SkillMutationPhase::Prepared,
            observed_generation_sha256: None,
            error_sha256: None,
            created_at_unix: 2,
        };
        let super::SkillIntentDelivery::Durable(receipt) =
            super::deliver_skill_mutation_intent(home.path(), &binding)
                .await
                .unwrap()
        else {
            panic!("intent must be durable");
        };
        let mut terminal = binding.clone();
        terminal.intent_receipt = Some(receipt);
        terminal.commit_boundary_sha256 = Some("6".repeat(64));
        terminal.phase = installer::SkillMutationPhase::Committed;
        super::deliver_skill_mutation_terminal_once(home.path(), &terminal)
            .await
            .unwrap();

        let frames = decode_wal_frames(home.path());
        assert_eq!(frames.len(), 2, "intent + result frames must both persist");
        assert_eq!(frames[0]["event_type"], "0x00");
        assert_eq!(frames[1]["event_type"], "0x00");
        assert_eq!(frames[0]["event_subtype"], "0x17");
        assert_eq!(frames[1]["event_subtype"], "0x18");
        let intent = &frames[0]["payload"];
        assert_eq!(intent["phase"], "intent");
        assert_eq!(intent["operation_id"], op);
        assert_eq!(intent["skill_id"], "demo_skill");
        assert_eq!(intent["target_generation_sha256"], prior);
        assert_eq!(intent["prior_anchor_state"], "present");
        let result = &frames[1]["payload"];
        assert_eq!(result["status"], "committed");
        assert_eq!(result["operation_id"], op);
        assert_eq!(result["skill_id"], "demo_skill");
        assert_eq!(result["removed"], true);
        assert_eq!(result["removed_generation_sha256"], prior);
    }

    #[tokio::test]
    async fn failed_skill_install_keeps_the_prepared_operation_id_in_terminal_audit() {
        let home = tempfile::TempDir::new().unwrap();
        let op = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let source = "2".repeat(64);
        let error_sha256 = "3".repeat(64);
        let binding = installer::SkillMutationAuditBinding {
            operation_id: op.into(),
            kind: installer::SkillMutationKind::Install,
            origin: installer::SkillMutationOrigin::CliInstall,
            skill_id: "failed_skill".into(),
            source_generation_sha256: Some(source),
            prior_generation_sha256: None,
            prior_object_identity_sha256: None,
            intent_receipt: None,
            commit_boundary_sha256: None,
            phase: installer::SkillMutationPhase::Prepared,
            observed_generation_sha256: None,
            error_sha256: None,
            created_at_unix: 3,
        };
        let super::SkillIntentDelivery::Durable(receipt) =
            super::deliver_skill_mutation_intent(home.path(), &binding)
                .await
                .unwrap()
        else {
            panic!("intent must be durable");
        };
        let mut terminal = binding.clone();
        terminal.intent_receipt = Some(receipt);
        terminal.commit_boundary_sha256 = Some("6".repeat(64));
        terminal.phase = installer::SkillMutationPhase::Aborted;
        terminal.error_sha256 = Some(error_sha256.clone());
        super::deliver_skill_mutation_terminal_once(home.path(), &terminal)
            .await
            .unwrap();

        let frames = decode_wal_frames(home.path());
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["payload"]["operation_id"], op);
        assert_eq!(frames[1]["payload"]["operation_id"], op);
        assert_eq!(frames[1]["payload"]["status"], "aborted");
        assert_eq!(frames[1]["payload"]["error_sha256"], error_sha256);
    }

    #[tokio::test]
    async fn failed_intent_delivery_aborts_only_after_wal_proves_it_was_not_recorded() {
        let home = tempfile::TempDir::new().unwrap();
        let source_root = tempfile::TempDir::new().unwrap();
        let source = source_root.path().join("intent_failure_source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(
            source.join("skill.yaml"),
            "id: intent_failure\n\
             description: failed intent delivery\n\
             trigger_keywords: [failure]\n\
             system_prompt: fail closed\n",
        )
        .unwrap();
        let skills_dir = home.path().join("skills");
        let prepared = installer::prepare_install_from_local_with_expectation(
            &source,
            &skills_dir,
            false,
            None,
            "67676767676767676767676767676767",
        )
        .unwrap();
        let binding = prepared.audit_binding();

        super::fail_next_skill_audit_deliveries(1);
        let delivery = super::deliver_skill_mutation_intent(home.path(), &binding)
            .await
            .unwrap();
        let super::SkillIntentDelivery::DefinitelyNotRecorded(error) = delivery else {
            panic!("injected pre-append failure must be proven not recorded");
        };
        assert!(format!("{error:#}").contains("injected Skill mutation WAL delivery failure"));
        prepared.abort_without_intent().unwrap();

        assert!(!skills_dir.join("intent_failure").exists());
        assert!(!skills_dir.join(".neoth-skill-mutation.json").exists());
        assert!(std::fs::read_dir(&skills_dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".neoth-install-intent_failure-")
        }));
    }

    #[tokio::test]
    async fn result_cancel_recovery_reuses_operation_and_never_duplicates_terminal() {
        let home = tempfile::TempDir::new().unwrap();
        let source_root = tempfile::TempDir::new().unwrap();
        let source = source_root.path().join("cancel_source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(
            source.join("skill.yaml"),
            "id: cancel_recovery\n\
             description: cancellation recovery\n\
             trigger_keywords: [cancel]\n\
             system_prompt: recover\n",
        )
        .unwrap();
        let skills_dir = home.path().join("skills");
        let operation_id = "34343434343434343434343434343434";
        let mut prepared = installer::prepare_install_from_local_with_expectation(
            &source,
            &skills_dir,
            false,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_submitting().unwrap();
        let intent = prepared.audit_binding();
        let super::SkillIntentDelivery::Durable(intent_receipt) =
            super::deliver_skill_mutation_intent(home.path(), &intent)
                .await
                .unwrap()
        else {
            panic!("test intent must be durable");
        };
        prepared
            .mark_intent_durable_authenticated(intent_receipt)
            .unwrap();
        prepared.commit().unwrap();

        // Simulate cancellation after the fsynced terminal append but before
        // the local outbox acknowledgement/cleanup.
        let mut pending = installer::open_pending_skill_mutation_reconciliation(&skills_dir)
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        super::fail_next_skill_audit_deliveries(1);
        let failure = super::deliver_skill_mutation_terminal_once(home.path(), &terminal)
            .await
            .unwrap_err();
        assert!(format!("{failure:#}").contains("injected Skill mutation WAL delivery failure"));
        assert!(
            skills_dir.join(".neoth-skill-mutation.json").exists(),
            "failed terminal delivery must retain the exact outbox"
        );
        super::deliver_skill_mutation_terminal_once(home.path(), &terminal)
            .await
            .unwrap();
        drop(pending);

        super::reconcile_pending_skill_mutation(home.path(), &skills_dir)
            .await
            .unwrap();
        assert!(
            !skills_dir.join(".neoth-skill-mutation.json").exists(),
            "existing terminal WAL evidence must allow durable outbox cleanup"
        );
        let frames = decode_wal_frames(home.path());
        let results = frames
            .iter()
            .filter(|frame| {
                frame["event_subtype"] == "0x15" && frame["payload"]["operation_id"] == operation_id
            })
            .count();
        assert_eq!(results, 1, "terminal result must be exactly once");
    }
}
