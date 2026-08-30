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

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::media::MediaExtractor;
use crate::skills::loader::{
    SkillInventoryOrigin, SkillInventoryRow, SkillInventoryRuntimeState, diagnostic_inventory,
};
use crate::skills::mutation_lifecycle::{self, IntentDelivery as SkillIntentDelivery};
use crate::skills::{installer, operator_skill_warnings};

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

/// Stable read-only receipt for ADOPT31-B1.  The source path deliberately
/// never crosses this boundary, and the embedded text was defanged by the
/// document distillation module before it became review output.
#[derive(Serialize)]
struct DocumentReviewReceipt<'a> {
    review_only: bool,
    skill_written: bool,
    skill_activated: bool,
    provider_dispatched: bool,
    document: &'a crate::skills::doc_distill::DistilledDoc,
}

/// Human-readable mutation status deliberately omits skill identifiers and
/// filesystem locations. Structured output retains the explicit receipt for
/// callers that require those fields.
fn skill_install_status_message(report: &installer::InstallReport) -> &'static str {
    if report.replaced_existing {
        "Reinstalled skill."
    } else {
        "Installed skill."
    }
}

/// Human-readable mutation status deliberately omits skill identifiers and
/// filesystem locations. Structured output retains the explicit receipt for
/// callers that require those fields.
fn skill_uninstall_status_message(report: &installer::UninstallReport) -> &'static str {
    if report.removed {
        "Uninstalled skill."
    } else {
        "Skill was not installed; nothing to remove."
    }
}

fn print_skill_uninstall_report(
    report: &installer::UninstallReport,
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
            println!("{}", skill_uninstall_status_message(report));
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
), group(
    clap::ArgGroup::new("authority_toggle")
        .args(["enable", "disable", "revoke"])
        .multiple(false)
))]
pub struct SkillsArgs {
    /// Extract one PDF, office document, or EPUB into a sanitized operator
    /// review draft. This is read-only: it never writes, installs, activates,
    /// routes, or provider-dispatches a skill.
    #[arg(
        long = "from-doc",
        value_name = "PATH",
        conflicts_with_all = [
            "list", "check_routing", "test", "run_tests", "install", "inspect_install",
            "inspect_target", "uninstall", "create", "enable", "disable", "revoke", "force"
        ]
    )]
    pub from_doc: Option<PathBuf>,

    /// Print the table of installed skills.
    #[arg(long, conflicts_with_all = ["test", "run_tests", "install", "inspect_install", "inspect_target", "uninstall", "create", "enable", "disable", "revoke"])]
    pub list: bool,

    /// Validate catalogue-wide parent/mode alias ownership and emit every
    /// cross-owner collision. Exits non-zero when the hot-reload gate would
    /// reject the current catalogue.
    #[arg(long = "check-routing", conflicts_with_all = ["list", "test", "run_tests", "install", "inspect_install", "inspect_target", "uninstall", "create", "enable", "disable", "revoke"])]
    pub check_routing: bool,

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
    #[arg(long = "inspect-install", value_name = "PATH", conflicts_with_all = ["list", "test", "run_tests", "install", "uninstall", "create", "enable", "disable", "revoke"])]
    pub inspect_install: Option<PathBuf>,

    /// Inspect the exact currently-live public entry (healthy or broken)
    /// without following links/reparse points. Read-only except crash recovery.
    #[arg(long = "inspect-target", value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install", "inspect_install", "uninstall", "create", "enable", "disable", "revoke"])]
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
        conflicts_with_all = ["list", "test", "run_tests", "uninstall", "enable", "disable", "revoke"]
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
    #[arg(long, value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install", "uninstall", "create", "disable", "revoke"])]
    pub enable: Option<String>,

    /// GOLD-ADOPT-14 — deactivate a bundled skill: adds it to
    /// `freedom.yaml::skills.disabled` (clearing any enable). `disabled` always
    /// wins, so this also overrides a prior `--enable`.
    #[arg(long, value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install", "uninstall", "create", "enable", "revoke"])]
    pub disable: Option<String>,

    /// Revoke the exact current installed-Skill generation. Revocation writes
    /// an authenticated authority record and also disables the Skill in
    /// freedom.yaml. Bundled Skills use `--disable` instead.
    #[arg(long, value_name = "SKILL_ID", conflicts_with_all = ["list", "test", "run_tests", "install", "uninstall", "create", "enable", "disable"])]
    pub revoke: Option<String>,

    /// Bind a GUI/Buddy authority action to the exact package generation shown
    /// before consent.
    #[arg(
        long = "expected-authority-generation-sha256",
        value_name = "SHA256",
        requires_all = ["authority_toggle", "expected_authority_incarnation", "expected_authority_install_receipt_sha256"]
    )]
    pub expected_authority_generation_sha256: Option<String>,

    /// Bind authority consent across identical-byte reinstall (ABA).
    #[arg(
        long = "expected-authority-incarnation",
        value_name = "N",
        requires_all = ["authority_toggle", "expected_authority_generation_sha256", "expected_authority_install_receipt_sha256"]
    )]
    pub expected_authority_incarnation: Option<u64>,

    /// Bind authority consent to the authenticated terminal install receipt.
    #[arg(
        long = "expected-authority-install-receipt-sha256",
        value_name = "SHA256",
        requires_all = ["authority_toggle", "expected_authority_generation_sha256", "expected_authority_incarnation"]
    )]
    pub expected_authority_install_receipt_sha256: Option<String>,

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SkillAuthorityTarget {
    Enabled,
    Disabled,
    Revoked,
}

impl SkillAuthorityTarget {
    fn state_label(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
        }
    }

    fn turns_policy_on(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct SkillToggleOutcome {
    pub(crate) id: String,
    pub(crate) state: &'static str,
    pub(crate) origin: &'static str,
    pub(crate) authority: Option<crate::skills::authority::SkillAuthorityReceipt>,
    pub(crate) reload_requested: bool,
    pub(crate) reload_sentinel: String,
    pub(crate) reload_ts_unix: u64,
}

fn update_skill_policy_at(config_path: &Path, id_lc: &str, turn_on: bool) -> Result<()> {
    FreedomConfig::update_at(config_path, |cfg| {
        apply_skill_toggle(&mut cfg.skills, id_lc, turn_on);
        Ok(())
    })
    .map_err(|error| anyhow::anyhow!("update freedom.yaml: {error}"))
}

async fn activate_installed_skill(
    home: &Path,
    config_path: &Path,
    id: &str,
    decision_source: crate::skills::authority::SkillAuthorityDecisionSource,
    expectation: Option<crate::skills::authority::InstalledSkillDecisionExpectation>,
) -> Result<crate::skills::authority::SkillAuthorityReceipt> {
    let id_for_plan = id.to_string();
    let (prepared, prospective_config) = FreedomConfig::prepare_update_at(config_path, |config| {
        apply_skill_toggle(&mut config.skills, &id_for_plan, true);
        Ok(config.clone())
    })
    .context("prepare exact Skill enable policy generation")?;
    let prospective_reload =
        crate::config::reload::ReloadController::new(prospective_config, config_path.to_path_buf());
    let home = home.to_path_buf();
    let config_path = config_path.to_path_buf();
    let id = id.to_string();
    tokio::task::spawn_blocking(move || {
        let rollback_path = config_path.clone();
        let rollback_id = id.clone();
        crate::skills::authority::publish_installed_activation_transaction(
            &home,
            &id,
            &prospective_reload,
            decision_source,
            expectation.as_ref(),
            move || prepared.commit(),
            move || update_skill_policy_at(&rollback_path, &rollback_id, false),
        )
    })
    .await
    .context("installed-Skill activation transaction worker failed")?
}

async fn reduce_installed_skill(
    home: &Path,
    config_path: &Path,
    id: &str,
    decision: crate::skills::authority::SkillAuthorityDecision,
    expectation: Option<crate::skills::authority::InstalledSkillDecisionExpectation>,
) -> Result<crate::skills::authority::SkillAuthorityReceipt> {
    let id_for_plan = id.to_string();
    let (prepared, prospective_config) = FreedomConfig::prepare_update_at(config_path, |config| {
        apply_skill_toggle(&mut config.skills, &id_for_plan, false);
        Ok(config.clone())
    })
    .context("prepare exact Skill disable policy generation")?;
    let prospective_reload =
        crate::config::reload::ReloadController::new(prospective_config, config_path.to_path_buf());
    let home = home.to_path_buf();
    let id = id.to_string();
    tokio::task::spawn_blocking(move || {
        crate::skills::authority::publish_installed_reduction_transaction(
            &home,
            &id,
            &prospective_reload,
            decision,
            expectation.as_ref(),
            move || prepared.commit(),
        )
    })
    .await
    .context("installed-Skill authority reduction worker failed")?
}

async fn verify_skill_decision_commit(
    home: &Path,
    config_path: &Path,
    id: &str,
    target: SkillAuthorityTarget,
    origin: SkillInventoryOrigin,
    receipt: Option<&crate::skills::authority::SkillAuthorityReceipt>,
) -> Result<()> {
    let home = home.to_path_buf();
    let config_path = config_path.to_path_buf();
    let id = id.to_string();
    let receipt = receipt.cloned();
    tokio::task::spawn_blocking(move || {
        let config = FreedomConfig::load_from_path(&config_path)
            .context("re-read Skill policy after authority decision")?;
        let policy_enabled = config
            .skills
            .enabled
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(&id));
        let policy_disabled = config
            .skills
            .disabled
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(&id));
        match origin {
            SkillInventoryOrigin::Bundled => {
                anyhow::ensure!(
                    receipt.is_none(),
                    "bundled Skill decision unexpectedly minted installed authority"
                );
                anyhow::ensure!(
                    (target == SkillAuthorityTarget::Enabled
                        && policy_enabled
                        && !policy_disabled)
                        || (target == SkillAuthorityTarget::Disabled && policy_disabled),
                    "bundled Skill policy changed before decision confirmation"
                );
            }
            SkillInventoryOrigin::User => {
                let receipt =
                    receipt.context("installed Skill decision has no authority receipt")?;
                let status = crate::skills::authority::inspect_current_authority(&home, &id)?
                    .context("installed Skill decision has no authenticated current readback")?;
                anyhow::ensure!(
                    status.record_sha256() == receipt.record_sha256()
                        && status.current_anchor_sha256() == receipt.current_anchor_sha256()
                        && status.record().decision_id == receipt.decision_id()
                        && status.record().state == receipt.state(),
                    "installed Skill authority changed before decision confirmation"
                );
                match target {
                    SkillAuthorityTarget::Enabled => {
                        anyhow::ensure!(
                            policy_enabled && !policy_disabled,
                            "installed Skill policy changed before activation confirmation"
                        );
                        let reload = crate::config::reload::ReloadController::new(
                            config,
                            config_path,
                        );
                        match crate::skills::authority::validate_installed_authority(
                            &home, &id, &reload,
                        ) {
                            crate::skills::authority::InstalledSkillAuthorityValidation::Active(
                                authority,
                            ) if authority.record_sha256() == receipt.record_sha256()
                                && authority.package_generation_sha256()
                                    == receipt.package_generation_sha256() => {}
                            _ => anyhow::bail!(
                                "installed Skill activation is not executable at exact-generation readback"
                            ),
                        }
                    }
                    SkillAuthorityTarget::Disabled | SkillAuthorityTarget::Revoked => {
                        anyhow::ensure!(
                            policy_disabled,
                            "installed Skill authority reduction lacks its policy disable"
                        );
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("Skill decision confirmation worker failed")?
}

/// Canonical bundled-policy / installed-authority mutation shared by CLI, GUI,
/// Buddy slash actions and authenticated proposal adoption.
///
/// Installed activation commits a prospective-policy inactive guard, the exact
/// config CAS, and final Active authority under one package mutation lock.
/// Disable/revoke commit policy denial before reducing authority. Same-id
/// bundled fallback therefore cannot appear at an intermediate boundary.
#[cfg(test)]
pub(crate) async fn set_skill_authority_at(
    home: &Path,
    id: &str,
    target: SkillAuthorityTarget,
    decision_source: crate::skills::authority::SkillAuthorityDecisionSource,
) -> Result<SkillToggleOutcome> {
    set_skill_authority_at_config(
        home,
        &home.join("freedom.yaml"),
        id,
        target,
        decision_source,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn set_skill_authority_at_config(
    home: &Path,
    config_path: &Path,
    id: &str,
    target: SkillAuthorityTarget,
    decision_source: crate::skills::authority::SkillAuthorityDecisionSource,
) -> Result<SkillToggleOutcome> {
    set_skill_authority_at_config_with_expectation(
        home,
        config_path,
        id,
        target,
        decision_source,
        None,
    )
    .await
}

pub(crate) async fn set_skill_authority_at_config_with_expectation(
    home: &Path,
    config_path: &Path,
    id: &str,
    target: SkillAuthorityTarget,
    decision_source: crate::skills::authority::SkillAuthorityDecisionSource,
    expectation: Option<crate::skills::authority::InstalledSkillDecisionExpectation>,
) -> Result<SkillToggleOutcome> {
    let id_lc = id.trim().to_lowercase();
    crate::skills::creator::validate_skill_id(&id_lc).context("validate skill id")?;
    let skills_dir = home.join("skills");
    let accepted_config = FreedomConfig::load_from_path(config_path)
        .with_context(|| format!("load Skill policy from {}", config_path.display()))?;
    let inventory = crate::skills::loader::diagnostic_inventory_for_accepted_config(
        &skills_dir,
        accepted_config,
        config_path.to_path_buf(),
    )
    .await?;
    if target == SkillAuthorityTarget::Enabled {
        let ownership_inventory =
            crate::skills::loader::load_all_from_config_path(&skills_dir, config_path)
                .await
                .context("load Skill catalogue for enable route-owner preflight")?;
        crate::skills::route_ownership::validate_inventory(&ownership_inventory)
            .context("Skill enable rejected by route-owner preflight")?;
    }
    let origin = match inventory
        .iter()
        .find(|row| row.id().eq_ignore_ascii_case(&id_lc))
    {
        Some(SkillInventoryRow::Healthy { origin, .. }) => *origin,
        Some(SkillInventoryRow::Broken {
            runtime_state: SkillInventoryRuntimeState::BundledFallbackActive,
            ..
        }) if target == SkillAuthorityTarget::Disabled => SkillInventoryOrigin::Bundled,
        Some(SkillInventoryRow::Broken { error, .. }) => {
            anyhow::bail!(
                "installed Skill `{id_lc}` is broken and cannot change authority; disable remains available only while a bundled fallback is active: {error}"
            )
        }
        None => {
            anyhow::bail!(
                "no skill with id '{id}' — run `neoth skills --list` to see installed ids"
            )
        }
    };
    let authority = match origin {
        SkillInventoryOrigin::Bundled => {
            anyhow::ensure!(
                expectation.is_none(),
                "bundled Skill `{id_lc}` does not accept an installed-generation expectation"
            );
            anyhow::ensure!(
                target != SkillAuthorityTarget::Revoked,
                "bundled Skill `{id_lc}` has compile-time trust; use --disable to deny it by policy"
            );
            update_skill_policy_at(config_path, &id_lc, target.turns_policy_on())?;
            None
        }
        SkillInventoryOrigin::User => {
            anyhow::ensure!(
                expectation.is_some()
                    || decision_source
                        == crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
                "GUI/Buddy installed-Skill authority requires an exact generation, incarnation, and install-receipt expectation"
            );
            let receipt = if target == SkillAuthorityTarget::Enabled {
                activate_installed_skill(home, config_path, &id_lc, decision_source, expectation)
                    .await?
            } else {
                let (state, reason) = match target {
                    SkillAuthorityTarget::Disabled => (
                        crate::skills::authority::SkillAuthorityState::Inactive,
                        Some("operator disabled installed Skill".to_string()),
                    ),
                    SkillAuthorityTarget::Revoked => (
                        crate::skills::authority::SkillAuthorityState::Revoked,
                        Some("operator revoked installed Skill".to_string()),
                    ),
                    SkillAuthorityTarget::Enabled => unreachable!("handled above"),
                };
                let decision = crate::skills::authority::SkillAuthorityDecision::new(
                    decision_source,
                    state,
                    reason,
                )?;
                reduce_installed_skill(home, config_path, &id_lc, decision, expectation).await?
            };
            Some(receipt)
        }
    };
    verify_skill_decision_commit(
        home,
        config_path,
        &id_lc,
        target,
        origin,
        authority.as_ref(),
    )
    .await?;
    let (reload_sentinel, reload_ts_unix) = crate::cli::reload::request_reload_at(home)
        .context("Skill decision committed, but requesting the daemon reload failed")?;
    Ok(SkillToggleOutcome {
        id: id_lc,
        state: target.state_label(),
        origin: match origin {
            SkillInventoryOrigin::Bundled => "bundled",
            SkillInventoryOrigin::User => "installed",
        },
        authority,
        reload_requested: true,
        reload_sentinel: reload_sentinel.display().to_string(),
        reload_ts_unix,
    })
}

pub async fn run_skills(args: SkillsArgs) -> Result<()> {
    // ADOPT31-B1 is deliberately before skill-mutation reconciliation: a
    // document-review request must not write, install, activate, or recover a
    // skill as an incidental side effect.
    if let Some(source) = &args.from_doc {
        return run_document_review(source, args.output).await;
    }

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
                println!("{}", skill_install_status_message(&report));
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
                print_skill_uninstall_report(&report, args.output)?;
                return Ok(());
            }
            installer::PreparedSkillRemovalOutcome::Prepared(prepared) => *prepared,
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
        print_skill_uninstall_report(&report, args.output)?;
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
                println!(
                    "Installed inactive; explicit activation is required before routing or tests."
                );
            }
        }
        return Ok(());
    }

    if args.check_routing {
        let config_path = home.join("freedom.yaml");
        let inventory = crate::skills::loader::load_all_from_config_path(&skills_dir, &config_path)
            .await
            .with_context(|| {
                format!(
                    "load prospective Skill catalogue for route-owner probe from {}",
                    skills_dir.display()
                )
            })?;
        let collisions = crate::skills::route_ownership::inventory_collisions(&inventory);
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": collisions.is_empty(),
                        "collision_count": collisions.len(),
                        "collisions": collisions,
                    }))?
                );
            }
            OutputFormat::Table => {
                if collisions.is_empty() {
                    println!("Skill routing ownership: valid (no cross-owner aliases)");
                } else {
                    println!(
                        "Skill routing ownership: {} cross-owner collision(s)",
                        collisions.len()
                    );
                    for collision in &collisions {
                        println!("  `{}`", collision.normalized_alias);
                        for claim in &collision.claims {
                            match &claim.mode_id {
                                Some(mode) => println!(
                                    "    - {}/{} ({:?}): {:?}",
                                    claim.skill_id, mode, claim.kind, claim.raw_alias
                                ),
                                None => println!(
                                    "    - {} ({:?}): {:?}",
                                    claim.skill_id, claim.kind, claim.raw_alias
                                ),
                            }
                        }
                    }
                }
            }
        }
        anyhow::ensure!(
            collisions.is_empty(),
            "Skill route-owner probe found {} collision(s)",
            collisions.len()
        );
        return Ok(());
    }

    if args.list
        || (args.test.is_none()
            && args.run_tests.is_none()
            && args.enable.is_none()
            && args.disable.is_none()
            && args.revoke.is_none())
    {
        let inventory = diagnostic_inventory(&skills_dir).await?;
        print_skill_inventory(&inventory, args.output, &skills_dir)?;
        return Ok(());
    }

    // GOLD-ADOPT-14 — enable/disable toggle, persisted to freedom.yaml.
    if args.enable.is_some() || args.disable.is_some() || args.revoke.is_some() {
        return run_skill_toggle(&args).await;
    }

    if let Some(skill_id) = &args.run_tests {
        let config = FreedomConfig::load_from_default_path()?;
        let accepted = std::sync::Arc::new(crate::config::reload::ReloadController::new(
            config.clone(),
            FreedomConfig::default_path(),
        ));
        let config_epoch = accepted.accepted_snapshot().epoch();
        let runtime_registry =
            crate::skills::SkillRegistry::load_with_reload_controller(&skills_dir, accepted)
                .await
                .with_context(|| {
                    format!(
                        "load authority-admitted Skill registry for test execution from {}",
                        skills_dir.display()
                    )
                })?;
        let runtime_skills = runtime_registry.snapshot_owned_for_epoch(config_epoch);
        let skill = runtime_skills
            .iter()
            .find(|skill| skill.id() == skill_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no active authority-admitted skill with id '{skill_id}' loaded from {}; \
                     activate the exact installed generation before running provider tests",
                    skills_dir.display(),
                )
            })?;
        let provider =
            crate::providers::from_config_at(&config, &FreedomConfig::default_neoth_home()).await?;
        let default_model = crate::providers::provider_default_wire_model(provider.as_ref());
        let provider_audit =
            crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot(
                config.autonomy_policy(),
                config.tokens.max_per_request,
            )
            .await?;
        let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
            provider,
            provider_audit.authorizer(),
            default_model,
            "skills.test_harness",
        );
        let outcomes =
            crate::skills::test_harness::run_all_scenarios_for_authorized(&provider, skill).await;
        provider_audit
            .finish(provider)
            .await
            .context("finalize skill-test provider-call audit WAL")?;
        let outcomes = outcomes?;
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
        let config_path = home.join("freedom.yaml");
        let config = FreedomConfig::load_from_path_or_default(&config_path)
            .with_context(|| format!("load Skill routing policy from {}", config_path.display()))?;
        let runtime_registry = crate::skills::SkillRegistry::load(&skills_dir)
            .await
            .with_context(|| {
                format!(
                    "load authority-admitted Skill registry for routing test from {}",
                    skills_dir.display()
                )
            })?;
        let snapshot = runtime_registry
            .authority_bound_snapshot()
            .context("acquire authority-bound Skill probe snapshot")?;
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
        let explicit_skill_id = match crate::slash::parse_invocation(msg) {
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
        let floor = if config.skills.enable_all_bundled {
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
                crate::skills::resolver::SkillRouteRequest::automatic(msg, floor, &active_files)
                    .with_explicit_skill(explicit_skill_id.as_deref()),
                embed_provider.as_deref(),
            )
            .await;
        let report = decision.report().clone();
        match decision {
            crate::skills::resolver::SkillRouteDecision::Match(route) => match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let v = serde_json::json!({
                        "matched_skill": route.skill().id(),
                        "matched_mode": route.mode().map(|mode| mode.id.as_str()),
                        "description": route.skill().description(),
                        "matched_keywords": report.candidates.first().map(|candidate| &candidate.matched_terms),
                        "route_report": report,
                    });
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                OutputFormat::Table => {
                    let evidence = report
                        .candidates
                        .first()
                        .map(|candidate| candidate.matched_terms.join(", "))
                        .unwrap_or_default();
                    println!(
                        "match: {}{} — stage: {:?} — evidence: {}",
                        route.skill().id(),
                        route
                            .mode()
                            .map(|mode| format!("/{}", mode.id))
                            .unwrap_or_default(),
                        report.stage,
                        evidence,
                    );
                    println!("  description: {}", route.skill().description());
                    println!("  snapshot: {}", report.snapshot_sha256);
                }
            },
            crate::skills::resolver::SkillRouteDecision::NoMatch(_)
            | crate::skills::resolver::SkillRouteDecision::Conflict(_)
            | crate::skills::resolver::SkillRouteDecision::Rejected(_) => match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "matched_skill": serde_json::Value::Null,
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
        return Ok(());
    }

    unreachable!("every skills command mode returns before the strict runtime load falls through")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentReviewDoclingPolicy {
    Disabled,
}

impl DocumentReviewDoclingPolicy {
    const fn enabled(self) -> bool {
        match self {
            Self::Disabled => false,
        }
    }
}

const DOCUMENT_REVIEW_DOCLING_POLICY: DocumentReviewDoclingPolicy =
    DocumentReviewDoclingPolicy::Disabled;

// Security: this pre-runtime review entry point intentionally does not load
// `FreedomConfig`; the fixed disabled policy keeps Docling typed `Unsupported`.
// The shared router falls through only `Unsupported`; every other extraction
// error fails review.
fn document_review_backends() -> Vec<std::sync::Arc<dyn MediaExtractor>> {
    vec![
        std::sync::Arc::new(crate::media::docling::DoclingExtractor::new(
            DOCUMENT_REVIEW_DOCLING_POLICY.enabled(),
        )),
        std::sync::Arc::new(crate::media::pdf::PdfExtractor),
        std::sync::Arc::new(crate::media::document::DocumentExtractor),
    ]
}

async fn extract_document_for_review_with_backends(
    backends: &[std::sync::Arc<dyn MediaExtractor>],
    asset: &crate::media::Asset,
) -> std::result::Result<crate::media::Extraction, crate::media::ExtractionError> {
    crate::media::route_to_first_match(backends, asset).await
}

async fn extract_document_for_review(
    asset: &crate::media::Asset,
) -> std::result::Result<crate::media::Extraction, crate::media::ExtractionError> {
    let backends = document_review_backends();
    extract_document_for_review_with_backends(&backends, asset).await
}

/// The shared CLI/chat handler for `/skill-from-doc <path>` and the secondary
/// `neoth skills --from-doc <path>` surface. It reads one bounded file and
/// prints a review draft; it has no skill filesystem, config, WAL, router, or
/// provider dependency.
pub async fn run_document_review(path: &Path, output: OutputFormat) -> Result<()> {
    let source = path.to_path_buf();
    let admitted = tokio::task::spawn_blocking(move || {
        crate::skills::doc_distill::admit_operator_document(&source)
    })
    .await
    .map_err(|_| anyhow::anyhow!("document source admission worker failed"))??;
    let extraction = extract_document_for_review(admitted.asset())
        .await
        .map_err(|_| anyhow::anyhow!("document extraction failed; no review draft was produced"))?;
    let document = crate::skills::doc_distill::distill_doc(
        extraction,
        admitted.source_kind(),
        admitted.source_bytes(),
        admitted.source_bytes_sha256().to_owned(),
    )?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string(&DocumentReviewReceipt {
                review_only: true,
                skill_written: false,
                skill_activated: false,
                provider_dispatched: false,
                document: &document,
            })?
        ),
        OutputFormat::Table => println!("{}", document.render_operator_review()),
    }
    Ok(())
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
                "{:<9} {:<24} {:<8} {:<25} description",
                "status", "id", "origin", "runtime"
            );
            println!("{}", "-".repeat(112));
            for row in inventory {
                match row {
                    SkillInventoryRow::Healthy {
                        manifest,
                        origin,
                        runtime_state,
                        ..
                    } => println!(
                        "{:<9} {:<24} {:<8} {:<25} {}",
                        "healthy",
                        truncate(&manifest.id, 24),
                        match origin {
                            SkillInventoryOrigin::Bundled => "bundled",
                            SkillInventoryOrigin::User => "user",
                        },
                        match runtime_state {
                            SkillInventoryRuntimeState::TrustedBundledActive => "bundled-active",
                            SkillInventoryRuntimeState::InstalledActive => "installed-active",
                            SkillInventoryRuntimeState::BundledFallbackActive =>
                                "bundled-fallback-active",
                            SkillInventoryRuntimeState::Disabled => "disabled/quarantined",
                        },
                        truncate(&manifest.description, 40),
                    ),
                    SkillInventoryRow::Broken {
                        id,
                        error,
                        path,
                        runtime_state,
                        ..
                    } => {
                        println!(
                            "{:<9} {:<24} {:<8} {:<25} {}",
                            "BROKEN",
                            truncate(id, 24),
                            "user",
                            match runtime_state {
                                SkillInventoryRuntimeState::BundledFallbackActive => {
                                    "bundled-fallback-active"
                                }
                                SkillInventoryRuntimeState::Disabled => "disabled/quarantined",
                                SkillInventoryRuntimeState::TrustedBundledActive => {
                                    "bundled-active"
                                }
                                SkillInventoryRuntimeState::InstalledActive => {
                                    "invalid-installed-active"
                                }
                            },
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

/// Apply one typed enable/disable/revoke action and emit the complete authority
/// plus reload acknowledgement consumed by GUI automation.
async fn run_skill_toggle(args: &SkillsArgs) -> Result<()> {
    let (id, target) = match (&args.enable, &args.disable, &args.revoke) {
        (Some(id), _, _) => (id.as_str(), SkillAuthorityTarget::Enabled),
        (_, Some(id), _) => (id.as_str(), SkillAuthorityTarget::Disabled),
        (_, _, Some(id)) => (id.as_str(), SkillAuthorityTarget::Revoked),
        // The dispatcher only calls this when one authority action is present.
        _ => unreachable!("run_skill_toggle requires --enable, --disable, or --revoke"),
    };
    // The GUI currently invokes this executable as a subprocess. Record the
    // trusted mutation boundary, not a caller-asserted presentation surface.
    // A future authenticated GUI IPC endpoint may derive OperatorGui
    // server-side; a public CLI flag must never mint that attribution.
    let source = crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli;
    let expectation = match (
        &args.expected_authority_generation_sha256,
        args.expected_authority_incarnation,
        &args.expected_authority_install_receipt_sha256,
    ) {
        (Some(generation), Some(incarnation), Some(receipt)) => Some(
            crate::skills::authority::InstalledSkillDecisionExpectation::new(
                generation.clone(),
                incarnation,
                receipt.clone(),
            )?,
        ),
        (None, None, None) => None,
        _ => anyhow::bail!(
            "--expected-authority-generation-sha256, --expected-authority-incarnation, and --expected-authority-install-receipt-sha256 must be supplied together"
        ),
    };
    let home = FreedomConfig::default_neoth_home();
    let outcome = set_skill_authority_at_config_with_expectation(
        &home,
        &home.join("freedom.yaml"),
        id,
        target,
        source,
        expectation,
    )
    .await?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&outcome)?);
        }
        OutputFormat::Table => {
            println!(
                "Skill `{}` {} (origin: {}).",
                outcome.id, outcome.state, outcome.origin
            );
            if let Some(receipt) = outcome.authority.as_ref() {
                println!(
                    "  Authority sequence {} for generation {} ({}).",
                    receipt.authority_sequence(),
                    receipt.package_generation_sha256(),
                    match receipt.durability() {
                        crate::skills::authority::SkillAuthorityDurability::Confirmed => "durable",
                        crate::skills::authority::SkillAuthorityDurability::NamespaceDurabilityUnsupported =>
                            "live-verified; namespace power-loss durability unsupported",
                        crate::skills::authority::SkillAuthorityDurability::Unconfirmed =>
                            "visible; durability unconfirmed",
                        crate::skills::authority::SkillAuthorityDurability::StateUncertain =>
                            "state uncertain",
                    }
                );
            }
            println!("  Live reload requested: {}", outcome.reload_sentinel);
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

    #[derive(Clone, Copy)]
    enum InjectedReviewFailure {
        Backend,
        Io,
    }

    struct FatalReviewExtractor {
        failure: InjectedReviewFailure,
    }

    #[async_trait::async_trait]
    impl MediaExtractor for FatalReviewExtractor {
        fn name(&self) -> &'static str {
            "injected-fatal"
        }

        async fn extract(
            &self,
            _asset: &crate::media::Asset,
        ) -> std::result::Result<crate::media::Extraction, crate::media::ExtractionError> {
            Err(match self.failure {
                InjectedReviewFailure::Backend => crate::media::ExtractionError::Backend {
                    backend: "injected-fatal",
                    reason: "injected backend failure".into(),
                },
                InjectedReviewFailure::Io => {
                    crate::media::ExtractionError::Io("injected IO failure".into())
                }
            })
        }
    }

    struct NativeFallbackProbe {
        reached: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl MediaExtractor for NativeFallbackProbe {
        fn name(&self) -> &'static str {
            "native-fallback-probe"
        }

        async fn extract(
            &self,
            _asset: &crate::media::Asset,
        ) -> std::result::Result<crate::media::Extraction, crate::media::ExtractionError> {
            self.reached.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::media::Extraction::default())
        }
    }

    #[test]
    fn routing_collision_probe_is_typed_and_exclusive() {
        let cli = crate::cli::Cli::try_parse_from(["neoth", "skills", "--check-routing"])
            .expect("parse route-owner probe");
        let crate::cli::Commands::Skills(args) = cli.command else {
            panic!("expected skills command");
        };
        assert!(args.check_routing);

        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "skills",
                "--check-routing",
                "--test",
                "deploy now",
            ])
            .is_err()
        );
    }

    #[test]
    fn from_doc_is_a_typed_read_only_cli_mode_and_rejects_mutator_combinations() {
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "skills",
            "--from-doc",
            "operator-guide.pdf",
        ])
        .expect("parse read-only document review mode");
        let crate::cli::Commands::Skills(args) = cli.command else {
            panic!("expected skills command");
        };
        assert_eq!(args.from_doc, Some(PathBuf::from("operator-guide.pdf")));
        assert!(args.install.is_none());
        assert!(!args.create);
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "skills",
                "--from-doc",
                "operator-guide.pdf",
                "--install",
                "untrusted-skill",
            ])
            .is_err()
        );
    }

    #[test]
    fn document_review_backends_keep_disabled_docling_before_native_fallbacks() {
        assert_eq!(
            DOCUMENT_REVIEW_DOCLING_POLICY,
            DocumentReviewDoclingPolicy::Disabled
        );
        assert!(!DOCUMENT_REVIEW_DOCLING_POLICY.enabled());

        let backends = document_review_backends();
        let names: Vec<_> = backends.iter().map(|backend| backend.name()).collect();

        assert_eq!(names.as_slice(), &["docling", "pdf", "document"]);
    }

    #[tokio::test]
    async fn document_review_rtf_falls_back_from_disabled_docling_to_native_metadata() {
        let asset = crate::media::Asset::Bytes {
            kind: crate::media::AssetKind::Document,
            mime: "application/rtf".into(),
            data: br"{\rtf1\ansi Operator review\par}".to_vec(),
        };

        let docling_error = document_review_backends()[0]
            .extract(&asset)
            .await
            .expect_err("disabled Docling must fail with a typed fallback signal");
        assert!(matches!(
            docling_error,
            crate::media::ExtractionError::Unsupported {
                backend: "docling",
                got: crate::media::AssetKind::Document,
            }
        ));

        let extraction = extract_document_for_review(&asset)
            .await
            .expect("typed Unsupported must fall through to the native RTF extractor");
        assert_eq!(extraction.text, "Operator review");
        assert_eq!(extraction.metadata["extractor"], "document");
        assert_eq!(extraction.metadata["format"], "rtf");
    }

    #[tokio::test]
    async fn document_review_fatal_errors_stop_before_native_fallbacks() {
        let asset = crate::media::Asset::Bytes {
            kind: crate::media::AssetKind::Document,
            mime: "application/rtf".into(),
            data: br"{\rtf1\ansi Operator review\par}".to_vec(),
        };

        for failure in [InjectedReviewFailure::Backend, InjectedReviewFailure::Io] {
            let fallback_reached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let backends: Vec<std::sync::Arc<dyn MediaExtractor>> = vec![
                std::sync::Arc::new(FatalReviewExtractor { failure }),
                std::sync::Arc::new(NativeFallbackProbe {
                    reached: std::sync::Arc::clone(&fallback_reached),
                }),
            ];

            let error = extract_document_for_review_with_backends(&backends, &asset)
                .await
                .expect_err("fatal extraction errors must not fall through");
            match (failure, error) {
                (
                    InjectedReviewFailure::Backend,
                    crate::media::ExtractionError::Backend {
                        backend: "injected-fatal",
                        ..
                    },
                )
                | (InjectedReviewFailure::Io, crate::media::ExtractionError::Io(_)) => {}
                (_, unexpected) => panic!("unexpected extraction error: {unexpected:?}"),
            }
            assert!(
                !fallback_reached.load(std::sync::atomic::Ordering::SeqCst),
                "native fallback must not receive a fatal extraction error"
            );
        }
    }

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
    fn authority_actions_are_exclusive_and_decision_source_is_not_caller_controlled() {
        let generation = "a".repeat(64);
        let receipt = "b".repeat(64);
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "skills",
            "--revoke",
            "alpha",
            "--expected-authority-generation-sha256",
            generation.as_str(),
            "--expected-authority-incarnation",
            "1",
            "--expected-authority-install-receipt-sha256",
            receipt.as_str(),
        ])
        .unwrap();
        let crate::cli::Commands::Skills(args) = cli.command else {
            panic!("expected skills command");
        };
        assert_eq!(args.revoke.as_deref(), Some("alpha"));

        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "skills",
                "--enable",
                "alpha",
                "--disable",
                "alpha",
            ])
            .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from([
                "neoth",
                "skills",
                "--revoke",
                "alpha",
                "--decision-source",
                "gui",
            ])
            .is_err()
        );
        assert!(
            crate::cli::Cli::try_parse_from(["neoth", "skills", "--revoke", "alpha", "--list",])
                .is_err()
        );
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
    fn human_mutation_statuses_are_static_and_do_not_disclose_skill_details() {
        let skill_id = "private-finance-forecast";
        let installed_at = PathBuf::from("C:\\Users\\alice\\.neoth\\skills").join(skill_id);
        let install = installer::InstallReport {
            id: skill_id.to_string(),
            installed_at: installed_at.clone(),
            replaced_existing: false,
            source_manifest_sha256: "a".repeat(64),
            source_generation_sha256: "b".repeat(64),
            replaced_generation_sha256: None,
            warnings: Vec::new(),
        };
        let reinstall = installer::InstallReport {
            replaced_existing: true,
            ..install.clone()
        };
        let removed = installer::UninstallReport {
            id: skill_id.to_string(),
            removed: true,
            removed_generation_sha256: Some("c".repeat(64)),
            warnings: Vec::new(),
        };
        let unchanged = installer::UninstallReport {
            removed: false,
            removed_generation_sha256: None,
            ..removed.clone()
        };

        let statuses = [
            skill_install_status_message(&install),
            skill_install_status_message(&reinstall),
            skill_uninstall_status_message(&removed),
            skill_uninstall_status_message(&unchanged),
        ];
        assert_eq!(
            statuses,
            [
                "Installed skill.",
                "Reinstalled skill.",
                "Uninstalled skill.",
                "Skill was not installed; nothing to remove.",
            ]
        );
        for status in statuses {
            assert!(!status.contains(skill_id));
            assert!(!status.contains(installed_at.to_string_lossy().as_ref()));
        }
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
                runtime_state: SkillInventoryRuntimeState::InstalledActive,
                package_generation_sha256: Some("a".repeat(64)),
                install_incarnation: Some(1),
                install_terminal_receipt_sha256: Some("b".repeat(64)),
            },
            SkillInventoryRow::Broken {
                id: "broken-skill".to_string(),
                error: "missing skill.yaml".to_string(),
                path: PathBuf::from("skills").join("broken-skill"),
                repairability: installer::SkillRepairability::ManifestReplaceable,
                runtime_state: SkillInventoryRuntimeState::Disabled,
                package_generation_sha256: None,
                install_incarnation: None,
                install_terminal_receipt_sha256: None,
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
        assert_eq!(healthy["runtime_state"], "installed_active");
        assert_eq!(healthy["package_generation_sha256"], "a".repeat(64));
        assert_eq!(healthy["install_incarnation"], 1);
        assert_eq!(healthy["install_terminal_receipt_sha256"], "b".repeat(64));
        assert_eq!(healthy.len(), 8);

        let broken = value[1].as_object().unwrap();
        assert_eq!(broken["status"], "broken");
        assert_eq!(broken["id"], "broken-skill");
        assert_eq!(broken["error"], "missing skill.yaml");
        assert_eq!(broken["repairability"], "manifest_replaceable");
        assert_eq!(broken["runtime_state"], "disabled");
        assert!(broken["package_generation_sha256"].is_null());
        assert!(broken["install_incarnation"].is_null());
        assert!(broken["install_terminal_receipt_sha256"].is_null());
        assert_eq!(broken.len(), 9);
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

    fn install_authority_test_wal_key(home: &Path) {
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&wal_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_directory_dacl(&wal_dir).unwrap();
        crate::wal::compaction::load_or_init_key(&wal_dir.join("hmac.key")).unwrap();
    }

    fn record_authority_test_install(home: &Path, id: &str) {
        let current = installer::inspect_current_install(&home.join("skills"), id)
            .expect("installed Skill fixture");
        mutation_lifecycle::record_committed_install_incarnation_for_test(
            home,
            id,
            &current.generation_sha256,
            installer::SkillMutationOrigin::CliInstall,
        )
        .unwrap();
    }

    fn installed_authority_expectation(
        home: &Path,
        id: &str,
    ) -> crate::skills::authority::InstalledSkillDecisionExpectation {
        let generation = installer::inspect_current_install(&home.join("skills"), id)
            .expect("installed Skill fixture")
            .generation_sha256;
        let install_proof =
            mutation_lifecycle::authenticate_current_install_incarnation(home, id, &generation)
                .expect("installed Skill fixture has a durable incarnation receipt");
        crate::skills::authority::InstalledSkillDecisionExpectation::new(
            generation,
            install_proof.install_incarnation(),
            install_proof.terminal_receipt_sha256().to_string(),
        )
        .expect("installed Skill fixture has a valid decision expectation")
    }

    fn authority_fixture_manifest(
        id: &str,
        system_prompt: &str,
        tool: &str,
        delegate_to: &str,
        model: &str,
        source: &str,
    ) -> String {
        format!(
            "id: {id}\n\
             description: installed authority lifecycle fixture\n\
             enabled: true\n\
             system_prompt: {system_prompt:?}\n\
             trigger_keywords: [authority-lifecycle]\n\
             tool_allowlist: [{tool:?}]\n\
             delegate_to: {delegate_to:?}\n\
             model: {model:?}\n\
             source: {source:?}\n"
        )
    }

    #[tokio::test]
    async fn installed_toggle_roundtrip_publishes_exact_authority_before_runtime_success() {
        let home = tempfile::tempdir().unwrap();
        let id = "authority-roundtrip";
        let skill_dir = home.path().join("skills").join(id);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("skill.yaml"),
            "id: authority-roundtrip\n\
             description: CLI GUI Buddy authority roundtrip\n\
             enabled: true\n",
        )
        .unwrap();
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        install_authority_test_wal_key(home.path());
        record_authority_test_install(home.path(), id);
        let generation = installer::inspect_current_install(&home.path().join("skills"), id)
            .unwrap()
            .generation_sha256;
        let install_proof = mutation_lifecycle::authenticate_current_install_incarnation(
            home.path(),
            id,
            &generation,
        )
        .unwrap();
        let expectation = crate::skills::authority::InstalledSkillDecisionExpectation::new(
            generation,
            install_proof.install_incarnation(),
            install_proof.terminal_receipt_sha256().to_string(),
        )
        .unwrap();

        let active = set_skill_authority_at_config_with_expectation(
            home.path(),
            &home.path().join("freedom.yaml"),
            id,
            SkillAuthorityTarget::Enabled,
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorGui,
            Some(expectation.clone()),
        )
        .await
        .unwrap();
        let active_receipt = active.authority.as_ref().expect("installed receipt");
        assert_eq!(
            active_receipt.state(),
            crate::skills::authority::SkillAuthorityState::Active
        );
        assert_eq!(
            active_receipt.decision_source(),
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorGui
        );
        let config = FreedomConfig::load_from_path(&home.path().join("freedom.yaml")).unwrap();
        let reload =
            crate::config::reload::ReloadController::new(config, home.path().join("freedom.yaml"));
        assert!(matches!(
            crate::skills::authority::validate_installed_authority(home.path(), id, &reload),
            crate::skills::authority::InstalledSkillAuthorityValidation::Active(_)
        ));

        let disabled = set_skill_authority_at_config_with_expectation(
            home.path(),
            &home.path().join("freedom.yaml"),
            id,
            SkillAuthorityTarget::Disabled,
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorBuddy,
            Some(expectation),
        )
        .await
        .unwrap();
        assert_eq!(
            disabled.authority.as_ref().unwrap().state(),
            crate::skills::authority::SkillAuthorityState::Inactive
        );
        let config = FreedomConfig::load_from_path(&home.path().join("freedom.yaml")).unwrap();
        assert!(config.skills.disabled.iter().any(|value| value == id));
        let reload =
            crate::config::reload::ReloadController::new(config, home.path().join("freedom.yaml"));
        let runtime = crate::skills::loader::load_authorized_reload_from_reload_controller(
            &home.path().join("skills"),
            &reload,
        )
        .await
        .unwrap();
        crate::skills::route_ownership::validate_runtime(&runtime.skills).unwrap();
        let current = crate::skills::authority::inspect_current_authority(home.path(), id)
            .unwrap()
            .unwrap();
        assert_eq!(
            current.record().state,
            crate::skills::authority::SkillAuthorityState::Inactive
        );

        let revoked = set_skill_authority_at(
            home.path(),
            id,
            SkillAuthorityTarget::Revoked,
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
        )
        .await
        .unwrap();
        assert_eq!(
            revoked.authority.as_ref().unwrap().state(),
            crate::skills::authority::SkillAuthorityState::Revoked
        );
        assert!(revoked.reload_requested);
        assert!(Path::new(&revoked.reload_sentinel).is_file());
    }

    #[tokio::test]
    async fn buddy_rejects_stale_authority_after_replace_claim_drift_and_rollback() {
        // GUI/Buddy consent is a three-part capability (package generation,
        // install incarnation, terminal install receipt), not a mutable Skill
        // id or a UI selection. Exercise a real on-disk package lifecycle:
        // v1 activates through Buddy, replacements change every behavior
        // claim one at a time, then an exact-byte rollback returns to v1 under
        // a new incarnation. In all cases a stale Buddy revoke must be a
        // no-op before policy or authority mutation.
        let home = tempfile::tempdir().unwrap();
        let id = "buddy-stale-authority";
        let skill_dir = home.path().join("skills").join(id);
        std::fs::create_dir_all(&skill_dir).unwrap();
        let config_path = home.path().join("freedom.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        install_authority_test_wal_key(home.path());

        let generation_n_manifest = authority_fixture_manifest(
            id,
            "AUTHORITY-N",
            "fetch",
            "research-helper",
            "provider/model-n",
            "https://example.test/skills/n",
        );
        std::fs::write(skill_dir.join("skill.yaml"), &generation_n_manifest).unwrap();
        record_authority_test_install(home.path(), id);
        let stale_n = installed_authority_expectation(home.path(), id);

        let active = set_skill_authority_at_config_with_expectation(
            home.path(),
            &config_path,
            id,
            SkillAuthorityTarget::Enabled,
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorBuddy,
            Some(stale_n.clone()),
        )
        .await
        .expect("Buddy uses the same exact-generation activation path as GUI");
        let active_receipt = active.authority.expect("installed active receipt");
        assert_eq!(
            active_receipt.decision_source(),
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorBuddy
        );
        let original_authority = active_receipt.record_sha256().to_string();
        let original_generation = active_receipt.package_generation_sha256().to_string();

        let variants = [
            (
                "manifest",
                authority_fixture_manifest(
                    id,
                    "AUTHORITY-N-CHANGED-MANIFEST",
                    "fetch",
                    "research-helper",
                    "provider/model-n",
                    "https://example.test/skills/n",
                ),
            ),
            (
                "source",
                authority_fixture_manifest(
                    id,
                    "AUTHORITY-N",
                    "fetch",
                    "research-helper",
                    "provider/model-n",
                    "https://example.test/skills/n-plus-one",
                ),
            ),
            (
                "model",
                authority_fixture_manifest(
                    id,
                    "AUTHORITY-N",
                    "fetch",
                    "research-helper",
                    "provider/model-n-plus-one",
                    "https://example.test/skills/n",
                ),
            ),
            (
                "delegation",
                authority_fixture_manifest(
                    id,
                    "AUTHORITY-N",
                    "fetch",
                    "research-helper-plus-one",
                    "provider/model-n",
                    "https://example.test/skills/n",
                ),
            ),
            (
                "allowlist",
                authority_fixture_manifest(
                    id,
                    "AUTHORITY-N",
                    "channel-send",
                    "research-helper",
                    "provider/model-n",
                    "https://example.test/skills/n",
                ),
            ),
        ];

        for (claim, replacement) in variants {
            std::fs::write(skill_dir.join("skill.yaml"), replacement).unwrap();
            record_authority_test_install(home.path(), id);
            let current_generation =
                installer::inspect_current_install(&home.path().join("skills"), id)
                    .expect("replaced installed Skill fixture")
                    .generation_sha256;
            assert_ne!(
                current_generation, original_generation,
                "{claim} replacement must change the package generation"
            );
            let replacement_reload = crate::config::reload::ReloadController::new(
                FreedomConfig::load_from_path(&config_path).unwrap(),
                config_path.clone(),
            );
            assert_eq!(
                crate::skills::authority::validate_installed_authority(
                    home.path(),
                    id,
                    &replacement_reload,
                )
                .inactive_reason(),
                Some(crate::skills::authority::SkillAuthorityInactiveReason::PackageGenerationMismatch),
                "{claim} replacement must remove the old runtime authority before Buddy acts"
            );

            let config_before = std::fs::read(&config_path).unwrap();
            let error = set_skill_authority_at_config_with_expectation(
                home.path(),
                &config_path,
                id,
                SkillAuthorityTarget::Revoked,
                crate::skills::authority::SkillAuthorityDecisionSource::OperatorBuddy,
                Some(stale_n.clone()),
            )
            .await
            .expect_err("Buddy must not revoke a different generation than the one it showed");
            assert!(
                format!("{error:#}").contains("changed after operator consent"),
                "{claim} replacement returned an unrelated error: {error:#}"
            );
            assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
            assert_eq!(
                crate::skills::authority::inspect_current_authority(home.path(), id)
                    .unwrap()
                    .expect("original authority remains readable after rejected stale action")
                    .record_sha256(),
                original_authority,
                "{claim} stale Buddy action must not publish a replacement authority"
            );
        }

        // Restore the exact v1 bytes. The generation matches N again, but the
        // durable mutation lifecycle mints a new incarnation (the ABA case).
        std::fs::write(skill_dir.join("skill.yaml"), &generation_n_manifest).unwrap();
        record_authority_test_install(home.path(), id);
        let rolled_back_generation =
            installer::inspect_current_install(&home.path().join("skills"), id)
                .expect("rolled-back installed Skill fixture")
                .generation_sha256;
        let rolled_back_proof = mutation_lifecycle::authenticate_current_install_incarnation(
            home.path(),
            id,
            &rolled_back_generation,
        )
        .expect("rolled-back installed Skill fixture has a durable incarnation receipt");
        assert_eq!(
            rolled_back_generation, original_generation,
            "rollback fixture must restore byte-identical package generation"
        );
        assert_ne!(
            rolled_back_proof.install_incarnation(),
            active_receipt.install_incarnation(),
            "byte-identical rollback must still receive a fresh incarnation"
        );
        let rollback_reload = crate::config::reload::ReloadController::new(
            FreedomConfig::load_from_path(&config_path).unwrap(),
            config_path.clone(),
        );
        assert_eq!(
            crate::skills::authority::validate_installed_authority(
                home.path(),
                id,
                &rollback_reload
            )
            .inactive_reason(),
            Some(
                crate::skills::authority::SkillAuthorityInactiveReason::InstallIncarnationMismatch
            ),
            "byte-identical rollback must not resurrect N authority before a fresh decision"
        );
        let config_before_rollback_revoke = std::fs::read(&config_path).unwrap();
        let error = set_skill_authority_at_config_with_expectation(
            home.path(),
            &config_path,
            id,
            SkillAuthorityTarget::Revoked,
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorBuddy,
            Some(stale_n),
        )
        .await
        .expect_err("Buddy must reject an ABA rollback under the stale installation receipt");
        assert!(
            format!("{error:#}").contains("changed after operator consent"),
            "rollback returned an unrelated error: {error:#}"
        );
        assert_eq!(
            std::fs::read(&config_path).unwrap(),
            config_before_rollback_revoke
        );
        assert_eq!(
            crate::skills::authority::inspect_current_authority(home.path(), id)
                .unwrap()
                .expect("original authority remains readable after rejected rollback action")
                .record_sha256(),
            original_authority
        );
    }

    #[tokio::test]
    async fn revoke_rejects_reexposed_bundled_alias_without_mutating_state() {
        let home = tempfile::tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let bundled_override = skills_dir.join("academic_research");
        let custom_collision = skills_dir.join("custom_collision");
        std::fs::create_dir_all(&bundled_override).unwrap();
        std::fs::create_dir_all(&custom_collision).unwrap();
        std::fs::write(
            bundled_override.join("skill.yaml"),
            "id: academic_research\n\
             description: Active installed override\n\
             trigger_keywords: [installed-override-only]\n\
             system_prompt: override fixture\n",
        )
        .unwrap();
        std::fs::write(
            custom_collision.join("skill.yaml"),
            "id: custom_collision\n\
             description: Claims the bundled fallback alias\n\
             trigger_keywords: [research]\n\
             system_prompt: collision fixture\n",
        )
        .unwrap();
        let config_path = home.path().join("freedom.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        install_authority_test_wal_key(home.path());
        record_authority_test_install(home.path(), "academic_research");
        record_authority_test_install(home.path(), "custom_collision");

        // Reconstruct a legacy/upgraded state that predates the public enable
        // preflight. New operator activations must never be able to create it.
        let reload = crate::config::reload::ReloadController::new(
            FreedomConfig::load_from_path(&config_path).unwrap(),
            config_path.clone(),
        );
        for id in ["academic_research", "custom_collision"] {
            let decision = crate::skills::authority::SkillAuthorityDecision::new(
                crate::skills::authority::SkillAuthorityDecisionSource::Migration,
                crate::skills::authority::SkillAuthorityState::Active,
                None,
            )
            .unwrap();
            crate::skills::authority::publish_installed_authority_decision(
                home.path(),
                id,
                &reload,
                decision,
            )
            .unwrap();
        }
        let policy_before = std::fs::read(&config_path).unwrap();
        let target_before = installer::inspect_current_install(&skills_dir, "academic_research")
            .unwrap()
            .generation_sha256;
        let collision_before = installer::inspect_current_install(&skills_dir, "custom_collision")
            .unwrap()
            .generation_sha256;
        let authority_before =
            crate::skills::authority::inspect_current_authority(home.path(), "academic_research")
                .unwrap()
                .unwrap()
                .record_sha256()
                .to_string();
        let collision_authority_before =
            crate::skills::authority::inspect_current_authority(home.path(), "custom_collision")
                .unwrap()
                .unwrap()
                .record_sha256()
                .to_string();

        let error = set_skill_authority_at_config(
            home.path(),
            &config_path,
            "academic_research",
            SkillAuthorityTarget::Revoked,
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
        )
        .await
        .unwrap_err();
        let detail = format!("{error:#}");
        assert!(
            detail.contains("route-owner reduction preflight"),
            "{detail}"
        );
        assert!(detail.contains("academic_research"), "{detail}");
        assert!(detail.contains("custom_collision"), "{detail}");
        assert_eq!(std::fs::read(&config_path).unwrap(), policy_before);
        assert_eq!(
            installer::inspect_current_install(&skills_dir, "academic_research")
                .unwrap()
                .generation_sha256,
            target_before
        );
        assert_eq!(
            installer::inspect_current_install(&skills_dir, "custom_collision")
                .unwrap()
                .generation_sha256,
            collision_before
        );
        assert_eq!(
            crate::skills::authority::inspect_current_authority(home.path(), "academic_research")
                .unwrap()
                .unwrap()
                .record_sha256(),
            authority_before
        );
        assert_eq!(
            crate::skills::authority::inspect_current_authority(home.path(), "custom_collision")
                .unwrap()
                .unwrap()
                .record_sha256(),
            collision_authority_before
        );
    }

    #[tokio::test]
    async fn enable_rejects_alias_hidden_by_unauthorized_bundled_shadow_without_mutation() {
        let home = tempfile::tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let bundled_shadow = skills_dir.join("academic_research");
        let target = skills_dir.join("custom_collision");
        std::fs::create_dir_all(&bundled_shadow).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(
            bundled_shadow.join("skill.yaml"),
            "id: academic_research\n\
             description: Installed shadow without authority\n\
             trigger_keywords: [installed-shadow-only]\n\
             system_prompt: shadow fixture\n",
        )
        .unwrap();
        std::fs::write(
            target.join("skill.yaml"),
            "id: custom_collision\n\
             description: Claims the bundled fallback alias\n\
             trigger_keywords: [research]\n\
             system_prompt: collision fixture\n",
        )
        .unwrap();
        let config_path = home.path().join("freedom.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        install_authority_test_wal_key(home.path());
        record_authority_test_install(home.path(), "academic_research");
        record_authority_test_install(home.path(), "custom_collision");
        let policy_before = std::fs::read(&config_path).unwrap();
        let shadow_before = installer::inspect_current_install(&skills_dir, "academic_research")
            .unwrap()
            .generation_sha256;
        let target_before = installer::inspect_current_install(&skills_dir, "custom_collision")
            .unwrap()
            .generation_sha256;
        assert!(
            crate::skills::authority::inspect_current_authority(home.path(), "academic_research")
                .unwrap()
                .is_none()
        );
        assert!(
            crate::skills::authority::inspect_current_authority(home.path(), "custom_collision")
                .unwrap()
                .is_none()
        );

        let error = set_skill_authority_at_config(
            home.path(),
            &config_path,
            "custom_collision",
            SkillAuthorityTarget::Enabled,
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
        )
        .await
        .unwrap_err();
        let detail = format!("{error:#}");
        assert!(
            detail.contains("Skill activation route-owner preflight failed"),
            "{detail}"
        );
        assert!(detail.contains("academic_research"), "{detail}");
        assert!(detail.contains("custom_collision"), "{detail}");
        assert_eq!(std::fs::read(&config_path).unwrap(), policy_before);
        assert_eq!(
            installer::inspect_current_install(&skills_dir, "academic_research")
                .unwrap()
                .generation_sha256,
            shadow_before
        );
        assert_eq!(
            installer::inspect_current_install(&skills_dir, "custom_collision")
                .unwrap()
                .generation_sha256,
            target_before
        );
        assert!(
            crate::skills::authority::inspect_current_authority(home.path(), "academic_research")
                .unwrap()
                .is_none()
        );
        assert!(
            crate::skills::authority::inspect_current_authority(home.path(), "custom_collision")
                .unwrap()
                .is_none()
        );
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
                // Skip WAL chain-integrity frames: the authenticated rotation
                // contract publishes a compaction marker, which is not part of
                // any skill's audit trail.
                if dec.header.event_type == crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
                    return Ok(());
                }
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
            mutation_sequence: None,
            previous_terminal_receipt_sha256: None,
            prior_install_incarnation: None,
            resulting_install_incarnation: None,
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
            mutation_sequence: None,
            previous_terminal_receipt_sha256: None,
            prior_install_incarnation: None,
            resulting_install_incarnation: None,
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
            mutation_sequence: None,
            previous_terminal_receipt_sha256: None,
            prior_install_incarnation: None,
            resulting_install_incarnation: None,
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
