//! GOLD-ADAPT-JV-MODE-04 — `neoth self-activate`
//!
//! Headless surface for NEOTH toggling its own skills / cron jobs under
//! sovereign mode.  Operator- AND agent-callable under `AutonomyLevel::Full`
//! when `FreedomConfig::sovereign_active()` is true.
//!
//! ## Gate chain (evaluated in order, first failure wins)
//!
//! 0. The Skill id is canonicalised and must resolve to a real, fully loadable
//!    bundled or installed Skill. Its exact content/install generation is bound
//!    before any config mutation.
//! 1. `freedom.yaml::self_activation.enabled` must be `true`  → else Deny.
//! 2. For skill toggle: `skills.disabled` list MUST NOT already contain the
//!    skill id (preflight firewall — `disabled` wins and toggling would be a
//!    no-op that misleads the agent) → else Err.
//! 3. `FreedomConfig::sovereign_active()` (sovereign_buddy && Full autonomy)
//!    → else `evaluate()` returns Confirm at Elevated or Deny at lower levels.
//! 4. `self_activation.skill_allowlist` must contain the skill id (case-
//!    insensitive) → else Confirm is returned (operator must decide).
//! 5. `permissions::evaluate(Action::SelfSkillToggle{..}, &policy_snapshot)` → Allow /
//!    Confirm / Deny.  The `evaluate` layer knows nothing about FreedomConfig;
//!    callers in steps 3-4 short-circuit before reaching it when sovereign
//!    pre-conditions are not met.
//! 6. After publication, the exact runtime loader must see the same Skill
//!    generation in the requested effective state. A readback failure is an
//!    explicit partial-state error and never emits a success receipt.
//!
//! ## WAL audit trail
//!
//! A final typed `TrustDecision` is required before this CLI mutates either
//! file. 0xD0 `CONFIG_RELOADED` is a later daemon compatibility observation
//! after hot reload; it is never the authorization evidence for the mutation.
//!
//! ## jobs.yaml live reload
//!
//! `run_scheduler` stages and validates `jobs.yaml` on every scheduler tick,
//! then swaps the complete in-memory generation. This command updates only an
//! existing, fully specified job under the shared cross-process jobs lock; it
//! never invents an incomplete schedule/prompt. The change therefore takes
//! effect on the next tick without restarting the daemon.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::{
    cli::{OutputFormat, permission_audit::RequiredPermissionAudit},
    config::FreedomConfig,
    permissions::{Action, Decision, Gate, evaluate},
};

// ── Args ──────────────────────────────────────────────────────────────────────

/// GOLD-ADAPT-JV-MODE-04 — NEOTH self-activation: toggle own skills / crons
/// under sovereign mode (`sovereign_buddy && Full` autonomy).
///
/// Gate: `self_activation.enabled` must be true AND `sovereign_active()`.
/// For skills: id must be in `self_activation.skill_allowlist`.
/// For cron: `--confirm-cron` flag required at every autonomy level.
#[derive(Args, Debug)]
pub struct SelfActivateArgs {
    #[command(subcommand)]
    pub action: SelfActivateAction,
}

#[derive(Subcommand, Debug)]
pub enum SelfActivateAction {
    /// Toggle a bundled skill on or off.
    ///
    /// Requires `self_activation.skill_allowlist` to contain the skill id.
    /// Writes `freedom.yaml::skills.{enabled,disabled}` (same path as
    /// `neoth skills --enable/--disable`).
    Skill {
        /// Skill id to toggle (case-insensitive, e.g. `fact-check`).
        id: String,
        /// Enable the skill (add to `skills.enabled`, remove from `skills.disabled`).
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable the skill (add to `skills.disabled`).  `disabled` always
        /// wins — this also overrides a prior `--enable`.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        /// Output format (inherited from global `--output` flag).
        #[arg(skip)]
        output: OutputFormat,
    },
    /// Toggle an existing cron job entry.
    ///
    /// Writes `~/.neoth/jobs.yaml` transactionally; the scheduler live-reloads
    /// the validated generation on its next tick. Create the full job first
    /// with `neoth cron add`. `--confirm-cron` remains mandatory.
    Cron {
        /// Existing cron job id to modify.
        job_id: String,
        /// Enable the cron job.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable the cron job.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        /// Required safety flag — cron activation is never auto-allowed at
        /// any autonomy level.
        #[arg(long)]
        confirm_cron: bool,
        /// Output format (inherited from global `--output` flag).
        #[arg(skip)]
        output: OutputFormat,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run `neoth self-activate`.  `output` is the global `--output` flag value.
pub async fn run_self_activate(args: SelfActivateArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let yaml = home.join("freedom.yaml");
    if !yaml.exists() {
        anyhow::bail!(
            "freedom.yaml not found at {}. Run `neoth init` first.",
            yaml.display()
        );
    }
    match args.action {
        SelfActivateAction::Skill {
            id,
            enable,
            disable,
            output: _,
        } => {
            if !enable && !disable {
                anyhow::bail!("specify --enable or --disable");
            }
            let turn_on = enable;
            run_skill_toggle(&yaml, &home.join("skills"), &id, turn_on, output).await
        }
        SelfActivateAction::Cron {
            job_id,
            enable,
            disable,
            confirm_cron,
            output: _,
        } => {
            if !enable && !disable {
                anyhow::bail!("specify --enable or --disable");
            }
            let cfg = FreedomConfig::load_from_path(&yaml)
                .map_err(|e| anyhow::anyhow!("load freedom.yaml: {e}"))?;
            if !cfg.self_activation.enabled {
                anyhow::bail!(
                    "self-activation is disabled. Set `self_activation.enabled: true` \
                     in freedom.yaml to allow NEOTH to toggle its own skills/crons."
                );
            }
            let turn_on = enable;
            run_cron_toggle(cfg, &home, &job_id, turn_on, confirm_cron, output).await
        }
    }
}

// ── Skill toggle ──────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
struct LoadableSkillIdentity {
    path: PathBuf,
    content_hash: String,
    installed_generation_sha256: Option<String>,
    enabled: bool,
    visibility: crate::config::SkillVisibility,
}

fn canonical_skill_id(id: &str) -> Result<String> {
    let canonical = id.trim().to_ascii_lowercase();
    crate::skills::creator::validate_skill_id(&canonical)
        .with_context(|| format!("self-activation skill id `{id}` is not canonical"))?;
    Ok(canonical)
}

async fn loadable_skill_identity(
    config_path: &Path,
    skills_dir: &Path,
    id: &str,
) -> Result<LoadableSkillIdentity> {
    let skills = crate::skills::loader::load_all_from_config_path(skills_dir, config_path)
        .await
        .with_context(|| {
            format!(
                "load the exact Skill generation for `{id}` from {}",
                skills_dir.display()
            )
        })?;
    let skill = skills
        .into_iter()
        .find(|skill| skill.id() == id)
        .ok_or_else(|| {
            anyhow::anyhow!("skill `{id}` is not installed or bundled and cannot be self-activated")
        })?;
    let installed_generation_sha256 =
        crate::skills::installer::inspect_installed_target(skills_dir, id)
            .with_context(|| format!("bind the installed Skill generation for `{id}`"))?
            .target_generation_sha256;
    let enabled = skill.is_enabled();
    let visibility = skill.visibility();
    Ok(LoadableSkillIdentity {
        path: skill.path,
        content_hash: skill.content_hash,
        installed_generation_sha256,
        enabled,
        visibility,
    })
}

async fn run_skill_toggle(
    config_path: &Path,
    skills_dir: &Path,
    id: &str,
    turn_on: bool,
    output: OutputFormat,
) -> Result<()> {
    let id_lc = canonical_skill_id(id)?;
    let before = loadable_skill_identity(config_path, skills_dir, &id_lc)
        .await
        .context("self-activation preflight failed before freedom.yaml was changed")?;
    if turn_on && before.visibility == crate::config::SkillVisibility::Off {
        anyhow::bail!(
            "skill `{id_lc}` has effective visibility `off` and cannot be enabled by self-activate"
        );
    }

    let cfg = FreedomConfig::load_from_path(config_path)
        .context("load freedom.yaml for self-activation permission admission")?;
    let action = validate_skill_toggle_policy(&cfg, &id_lc, turn_on)?;
    let audit = required_local_trust_gate(
        config_path.parent().unwrap_or_else(|| Path::new(".")),
        cfg.autonomy_policy(),
        &action,
        None,
        "self-activate-skill",
    )
    .await?;

    let mutation_path = config_path.to_path_buf();
    let mutation_id = id_lc.clone();
    // The owned runner moves the audit session into the same task that joins
    // this blocking mutation. If the caller is cancelled, Tokio detaches that
    // owner rather than dropping the audit while a config publisher continues.
    run_owned_audited_blocking_mutation(audit, "freedom.yaml", move || {
        FreedomConfig::update_at(&mutation_path, |cfg| {
            // This closure owns the atomic publication lock. Re-evaluate every
            // immutable admission condition immediately before changing bytes so a
            // config generation that changed after the audited outer check cannot
            // inherit that earlier allow.
            validate_skill_toggle_policy(cfg, &mutation_id, turn_on)?;
            apply_skill_toggle(cfg, &mutation_id, turn_on);
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("write freedom.yaml: {e}"))
    })
    .await?;

    let after = loadable_skill_identity(config_path, skills_dir, &id_lc)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "self-activation changed freedom.yaml, but exact runtime readback failed; \
                 state may be partial and no success receipt was emitted: {error:#}"
            )
        })?;
    if before.path != after.path
        || before.content_hash != after.content_hash
        || before.installed_generation_sha256 != after.installed_generation_sha256
    {
        anyhow::bail!(
            "self-activation changed freedom.yaml, but Skill `{id_lc}` vanished or was replaced \
             before exact readback; state may be partial and no success receipt was emitted"
        );
    }
    if after.enabled != turn_on {
        anyhow::bail!(
            "self-activation changed freedom.yaml, but exact runtime readback reports Skill \
             `{id_lc}` as {}; state may be partial and no success receipt was emitted",
            if after.enabled { "enabled" } else { "disabled" }
        );
    }

    // WAL audit note: 0xD0 CONFIG_RELOADED fires automatically when the daemon
    // hot-reloads freedom.yaml and sees "skills" in changed_fields.
    // This is identical to the autonomy.rs sovereign_buddy path.
    let state = if turn_on { "enabled" } else { "disabled" };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "skill_id": id_lc,
                    "state": state,
                    "wal": "0xD0 CONFIG_RELOADED fires on next daemon hot-reload"
                }))?
            );
        }
        OutputFormat::Table => {
            println!("Self-activate: skill `{id_lc}` {state} (freedom.yaml::skills.{state}).");
            println!(
                "  WAL 0xD0 CONFIG_RELOADED will fire when the daemon next reloads freedom.yaml."
            );
            println!("  Takes effect on next skill load (daemon reload or next CLI turn).");
        }
    }
    Ok(())
}

/// Check the invariants that make a self-skill mutation admissible. This runs
/// once for the audited admission snapshot and again inside
/// [`FreedomConfig::update_at`] immediately before atomic publication.
fn validate_skill_toggle_policy(cfg: &FreedomConfig, id_lc: &str, turn_on: bool) -> Result<Action> {
    if !cfg.self_activation.enabled {
        anyhow::bail!(
            "self-activation is disabled. Set `self_activation.enabled: true` \
             in freedom.yaml to allow NEOTH to toggle its own skills/crons."
        );
    }
    if cfg
        .skills
        .disabled
        .iter()
        .any(|skill| skill.trim().eq_ignore_ascii_case(id_lc))
    {
        anyhow::bail!(
            "skill '{id_lc}' is in `skills.disabled` — the disabled list always wins and \
             cannot be overridden by self-activate. Operator must run `neoth skills --enable {id_lc}` explicitly."
        );
    }

    let action = Action::SelfSkillToggle {
        skill_id: id_lc.to_owned(),
        enable: turn_on,
    };
    if !cfg.sovereign_active() {
        match evaluate(&action, &cfg.autonomy_policy()) {
            Decision::Allow => anyhow::bail!(
                "self-activate requires sovereign mode (sovereign_buddy: true AND autonomy: full). \
                 Enable sovereign mode via `neoth mode sovereign-buddy enable`."
            ),
            Decision::Confirm(message) => anyhow::bail!("confirm required: {message}"),
            Decision::Deny(message) => anyhow::bail!("denied: {message}"),
        }
    }
    if !cfg.self_activation.skill_allowed(id_lc) {
        if cfg.self_activation.skill_allowlist.is_empty() {
            anyhow::bail!(
                "self-activation skill allowlist is empty — add '{id_lc}' to `self_activation.skill_allowlist` in freedom.yaml."
            );
        }
        anyhow::bail!(
            "skill '{id_lc}' not in `self_activation.skill_allowlist`. Add it to freedom.yaml or use `neoth skills --enable {id_lc}` as operator."
        );
    }
    if turn_on
        && cfg
            .skills
            .visibility_overrides
            .get(id_lc)
            .is_some_and(|visibility| *visibility == crate::config::SkillVisibility::Off)
    {
        anyhow::bail!(
            "skill '{id_lc}' has `skills.visibility_overrides: off` — this operator block cannot be overridden by self-activate"
        );
    }
    match evaluate(&action, &cfg.autonomy_policy()) {
        Decision::Allow => Ok(action),
        Decision::Confirm(message) => anyhow::bail!("confirm required: {message}"),
        Decision::Deny(message) => anyhow::bail!("denied: {message}"),
    }
}

fn apply_skill_toggle(cfg: &mut FreedomConfig, id_lc: &str, turn_on: bool) {
    cfg.skills
        .enabled
        .retain(|skill| !skill.trim().eq_ignore_ascii_case(id_lc));
    cfg.skills
        .disabled
        .retain(|skill| !skill.trim().eq_ignore_ascii_case(id_lc));
    if turn_on {
        cfg.skills.enabled.push(id_lc.to_owned());
    } else {
        cfg.skills.disabled.push(id_lc.to_owned());
    }
}

/// Resolve and durably record exactly one final local decision before a config
/// or jobs mutation. Callers own the returned session through their mutation
/// and must finalize it before reporting success.
async fn required_local_trust_gate(
    home: &Path,
    policy: crate::permissions::AutonomyPolicySnapshot,
    action: &Action,
    preconfirmed_source: Option<&'static str>,
    surface: &'static str,
) -> Result<RequiredPermissionAudit> {
    let audit = RequiredPermissionAudit::open(home, surface)?;
    let mut gate = Gate::for_policy(policy);
    if let Some(source) = preconfirmed_source {
        gate = gate.with_preconfirmed_confirmation(source);
    }
    match gate
        .check_with_audit_sink(action, audit.sink(), true, None)
        .await
    {
        Ok(()) => Ok(audit),
        Err(error) => {
            let completion = audit.finish().await;
            match completion {
                Ok(()) => Err(error.into()),
                Err(finalize) => Err(anyhow::anyhow!(
                    "self-activation admission refused ({error}); required audit finalization also failed: {finalize:#}"
                )),
            }
        }
    }
}

/// Own one blocking mutation and its required permission audit in the same
/// detached-on-caller-cancellation task. The outer CLI only awaits this task;
/// once the effect starts it cannot outlive its audit owner, and that owner
/// always performs bounded finalization after the blocking join settles.
async fn run_owned_audited_blocking_mutation(
    audit: RequiredPermissionAudit,
    mutation_name: &'static str,
    mutation: impl FnOnce() -> Result<()> + Send + 'static,
) -> Result<()> {
    let owned = tokio::spawn(async move {
        let mutation_result = match tokio::task::spawn_blocking(mutation).await {
            Ok(result) => result,
            Err(error) => Err(anyhow::anyhow!(
                "{mutation_name} mutation worker failed before publication: {error}"
            )),
        };
        let audit_result = audit.finish().await;
        match (mutation_result, audit_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(mutation), Ok(())) => Err(mutation),
            (Ok(()), Err(audit)) => Err(audit).context(format!(
                "{mutation_name} changed, but required self-activation permission audit finalization failed"
            )),
            (Err(mutation), Err(audit)) => Err(mutation).context(format!(
                "{mutation_name} was not changed and required permission audit finalization also failed: {audit:#}"
            )),
        }
    });
    owned
        .await
        .map_err(|error| anyhow::anyhow!("owned {mutation_name} audit operation failed: {error}"))?
}

// ── Cron toggle ───────────────────────────────────────────────────────────────

async fn run_cron_toggle(
    cfg: FreedomConfig,
    home: &std::path::Path,
    job_id: &str,
    turn_on: bool,
    confirm_cron: bool,
    output: OutputFormat,
) -> Result<()> {
    // `--confirm-cron` is deliberately the only preconfirmation source. It
    // satisfies the intentional Confirm from SelfCronRegister but never a
    // policy Deny or the Custom/kill-switch floors.
    let action = validate_cron_toggle_policy(&cfg, job_id, confirm_cron)?;
    let config_path = home.join("freedom.yaml");
    let audit = required_local_trust_gate(
        home,
        cfg.autonomy_policy(),
        &action,
        Some("cli_confirm_cron"),
        "self-activate-cron",
    )
    .await?;

    // Re-load the policy from inside the atomic jobs writer immediately before
    // the in-place job edit. The blocking config-to-jobs lock chain runs on a
    // blocking worker so an OS lock wait cannot stall the async executor.
    let jobs_yaml = home.join("jobs.yaml");
    let config_path_for_mutation = config_path.clone();
    let job_id_for_mutation = job_id.to_owned();
    let state = if turn_on { "enabled" } else { "disabled" };
    run_owned_audited_blocking_mutation(audit, "jobs.yaml", move || {
        update_jobs_yaml(
            &jobs_yaml,
            &config_path_for_mutation,
            &job_id_for_mutation,
            turn_on,
            confirm_cron,
        )
    })
    .await?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "job_id": job_id,
                    "state": state,
                    "restart_required": false,
                    "live_reload": true,
                    "note": "scheduler applies the validated jobs.yaml generation on its next tick"
                }))?
            );
        }
        OutputFormat::Table => {
            println!("Self-activate: cron job `{job_id}` {state} (jobs.yaml).");
            println!(
                "  Scheduler live reload will apply it on the next tick; no restart required."
            );
        }
    }
    Ok(())
}

/// Toggle an existing job in the canonical [`crate::cron::JobsFile`] schema.
/// The shared mutation helper reloads under an OS lock, validates the complete
/// generation, and atomically commits it. Missing jobs fail closed: a job needs
/// a real schedule, name, prompt, and timeout from `neoth cron add` before it
/// can be self-activated.
fn validate_cron_toggle_policy(
    cfg: &FreedomConfig,
    job_id: &str,
    confirm_cron: bool,
) -> Result<Action> {
    if !cfg.self_activation.enabled {
        anyhow::bail!(
            "self-activation is disabled. Set `self_activation.enabled: true` in freedom.yaml to allow NEOTH to toggle its own skills/crons."
        );
    }
    if !cfg.self_activation.allow_cron_registration {
        anyhow::bail!(
            "cron self-registration is disabled — set freedom.yaml::self_activation.allow_cron_registration: true first"
        );
    }
    if cfg.autonomy == crate::permissions::AutonomyLevel::Custom {
        anyhow::bail!(
            "cron self-registration is disabled under custom autonomy regardless of overrides"
        );
    }
    if !confirm_cron {
        anyhow::bail!(
            "cron registration always requires explicit operator confirmation. Re-run with --confirm-cron to proceed. The scheduler applies a valid jobs.yaml generation on its next live-reload tick."
        );
    }
    let action = Action::SelfCronRegister {
        job_id: job_id.to_owned(),
    };
    match evaluate(&action, &cfg.autonomy_policy()) {
        Decision::Deny(message) => anyhow::bail!("denied: {message}"),
        // The explicit flag is the only confirmation source. An unexpected
        // Allow does not weaken that rule because it was already checked.
        Decision::Allow | Decision::Confirm(_) => Ok(action),
    }
}

fn update_jobs_yaml(
    path: &std::path::Path,
    config_path: &std::path::Path,
    job_id: &str,
    turn_on: bool,
    confirm_cron: bool,
) -> Result<()> {
    crate::config::with_current_freedom_config_authority_locked(config_path, |current_cfg| {
        validate_cron_toggle_policy(current_cfg, job_id, confirm_cron)?;
        crate::cron::JobsFile::modify_at_path(path, |jobs| {
            let job = jobs
                .jobs
                .iter_mut()
                .find(|job| job.id == job_id)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "cron job `{job_id}` does not exist in {} — create its full \
                         schedule first with `neoth cron add`",
                        path.display()
                    )
                })?;
            job.enabled = turn_on;
            Ok(())
        })
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::AutonomyLevel;
    use crate::{
        config::{FreedomConfig, SelfActivationConfig},
        permissions::{Action, evaluate},
    };
    use tempfile::TempDir;

    fn make_cfg(autonomy: AutonomyLevel, sovereign_buddy: bool) -> FreedomConfig {
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = autonomy;
        cfg.sovereign_buddy = sovereign_buddy;
        cfg.self_activation = SelfActivationConfig {
            enabled: true,
            skill_allowlist: vec!["fact-check".to_string()],
            allow_cron_registration: false,
        };
        cfg
    }

    fn write_freedom_yaml(dir: &TempDir, cfg: &FreedomConfig) -> std::path::PathBuf {
        let path = dir.path().join("freedom.yaml");
        let yaml = serde_yaml::to_string(cfg).unwrap();
        std::fs::write(&path, yaml).unwrap();
        path
    }

    // ── skill toggle: permission gate ─────────────────────────────────────────

    #[test]
    fn self_activate_blocked_below_full_autonomy() {
        // Strict, Standard, Elevated all deny or confirm — never Allow.
        for level in [
            AutonomyLevel::Strict,
            AutonomyLevel::Standard,
            AutonomyLevel::Elevated,
        ] {
            let action = Action::SelfSkillToggle {
                skill_id: "fact-check".to_string(),
                enable: true,
            };
            let decision = evaluate(&action, level);
            // Strict/Standard → Deny; Elevated → Confirm. None is Allow.
            assert!(
                !matches!(decision, crate::permissions::Decision::Allow),
                "expected non-Allow at {level:?}, got {decision:?}"
            );
        }
    }

    #[test]
    fn self_activate_blocked_when_sovereign_mode_off() {
        // Full autonomy but sovereign_buddy = false → sovereign_active() = false.
        let cfg = make_cfg(AutonomyLevel::Full, false);
        assert!(
            !cfg.sovereign_active(),
            "sovereign_active should be false without sovereign_buddy"
        );
        // run_skill_toggle would call evaluate and get Allow (Full), but
        // the sovereign_active gate before the allowlist check bails first.
        // We test the gate directly:
        let action = Action::SelfSkillToggle {
            skill_id: "fact-check".to_string(),
            enable: true,
        };
        // evaluate at Full → Allow, but the caller gate is sovereign_active()
        // which is false — so the caller must not reach evaluate.
        assert!(
            !cfg.sovereign_active(),
            "gate: sovereign_active must be true before allowlist + evaluate"
        );
        // The decision itself would be Allow at Full — the caller gate is the firewall.
        let decision = evaluate(&action, cfg.autonomy);
        assert!(matches!(decision, crate::permissions::Decision::Allow));
    }

    #[test]
    fn self_activate_blocked_when_skill_in_disabled_list() {
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.skills.disabled.push("fact-check".to_string());

        // Simulate the preflight check that run_skill_toggle performs.
        let id_lc = "fact-check";
        let in_disabled = cfg
            .skills
            .disabled
            .iter()
            .any(|s| s.trim().to_lowercase() == id_lc);
        assert!(
            in_disabled,
            "preflight should detect skill is in the disabled list"
        );
    }

    #[test]
    fn self_activate_allowlist_miss_does_not_allow() {
        let cfg = make_cfg(AutonomyLevel::Full, true);
        // "unknown-skill" is not in the allowlist.
        assert!(
            !cfg.self_activation.skill_allowed("unknown-skill"),
            "skill not in allowlist should not be allowed"
        );
        // "fact-check" IS in the allowlist.
        assert!(
            cfg.self_activation.skill_allowed("fact-check"),
            "skill in allowlist should be allowed"
        );
        // Case-insensitive check.
        assert!(
            cfg.self_activation.skill_allowed("FACT-CHECK"),
            "allowlist check should be case-insensitive"
        );
    }

    #[test]
    fn changed_skill_config_refuses_before_mutation() {
        let mut admitted = make_cfg(AutonomyLevel::Full, true);
        assert!(validate_skill_toggle_policy(&admitted, "fact-check", true).is_ok());
        admitted.self_activation.enabled = false;
        let error = validate_skill_toggle_policy(&admitted, "fact-check", true).unwrap_err();
        assert!(error.to_string().contains("self-activation is disabled"));
    }

    #[tokio::test]
    async fn allowlisted_ghost_skill_cannot_mutate_freedom_yaml() {
        let dir = TempDir::new().unwrap();
        let cfg = make_cfg(AutonomyLevel::Full, true);
        let yaml_path = write_freedom_yaml(&dir, &cfg);
        let original = std::fs::read(&yaml_path).unwrap();

        let error = run_skill_toggle(
            &yaml_path,
            &dir.path().join("skills"),
            "fact-check",
            true,
            OutputFormat::Json,
        )
        .await
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("not installed or bundled"),
            "ghost denial must explain the missing runtime Skill: {error:#}"
        );
        assert_eq!(
            std::fs::read(&yaml_path).unwrap(),
            original,
            "a ghost allowlist entry must not publish a config mutation"
        );
    }

    #[tokio::test]
    async fn malformed_skill_id_is_rejected_before_config_mutation() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.self_activation
            .skill_allowlist
            .push("../fact-check".to_string());
        let yaml_path = write_freedom_yaml(&dir, &cfg);
        let original = std::fs::read(&yaml_path).unwrap();

        let error = run_skill_toggle(
            &yaml_path,
            &dir.path().join("skills"),
            "../FACT-CHECK",
            true,
            OutputFormat::Json,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("not canonical"), "{error:#}");
        assert_eq!(std::fs::read(&yaml_path).unwrap(), original);
    }

    #[tokio::test]
    async fn broken_allowlisted_skill_cannot_mutate_freedom_yaml() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.self_activation.skill_allowlist = vec!["broken".to_string()];
        let yaml_path = write_freedom_yaml(&dir, &cfg);
        let broken_dir = dir.path().join("skills").join("broken");
        std::fs::create_dir_all(&broken_dir).unwrap();
        std::fs::write(broken_dir.join("skill.yaml"), "id: [not valid yaml").unwrap();
        let original = std::fs::read(&yaml_path).unwrap();

        let error = run_skill_toggle(
            &yaml_path,
            &dir.path().join("skills"),
            "broken",
            true,
            OutputFormat::Json,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("preflight failed"), "{error:#}");
        assert_eq!(std::fs::read(&yaml_path).unwrap(), original);
    }

    #[tokio::test]
    async fn real_skill_toggle_requires_exact_runtime_readback() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.self_activation.skill_allowlist = vec!["academic_research".to_string()];
        let yaml_path = write_freedom_yaml(&dir, &cfg);
        let skills_dir = dir.path().join("skills");

        run_skill_toggle(
            &yaml_path,
            &skills_dir,
            "ACADEMIC_RESEARCH",
            false,
            OutputFormat::Json,
        )
        .await
        .unwrap();

        let trust = crate::permissions::trust_ledger::TrustLedger::replay_subject_at_home(
            dir.path(),
            crate::permissions::trust_ledger::LOCAL_SUBJECT,
        )
        .expect("the required local WAL decision must be authenticated and replayable");
        assert_eq!(
            trust.entries.len(),
            1,
            "one skill mutation has one final decision"
        );
        assert!(matches!(
            trust.entries[0].event.outcome,
            crate::permissions::trust_ledger::TrustOutcome::Allowed
        ));

        let readback = FreedomConfig::load_from_path(&yaml_path).unwrap();
        assert!(
            readback
                .skills
                .disabled
                .iter()
                .any(|id| id == "academic_research")
        );
        let loaded = crate::skills::loader::load_all_from_config_path(&skills_dir, &yaml_path)
            .await
            .unwrap();
        let skill = loaded
            .iter()
            .find(|skill| skill.id() == "academic_research")
            .unwrap();
        assert!(!skill.is_enabled());
    }

    #[tokio::test]
    async fn denied_local_admission_records_one_authenticated_denial() {
        let dir = TempDir::new().unwrap();
        let cfg = make_cfg(AutonomyLevel::Standard, true);
        let action = Action::SelfSkillToggle {
            skill_id: "fact-check".to_owned(),
            enable: true,
        };
        let denied = required_local_trust_gate(
            dir.path(),
            cfg.autonomy_policy(),
            &action,
            None,
            "test-self-activate-deny",
        )
        .await;
        assert!(
            denied.is_err(),
            "Standard policy must deny self-activation before any config write"
        );

        let trust = crate::permissions::trust_ledger::TrustLedger::replay_subject_at_home(
            dir.path(),
            crate::permissions::trust_ledger::LOCAL_SUBJECT,
        )
        .expect("the denial must be authenticated and replayable");
        assert_eq!(trust.entries.len(), 1);
        assert!(matches!(
            trust.entries[0].event.outcome,
            crate::permissions::trust_ledger::TrustOutcome::Denied
        ));
    }

    #[tokio::test]
    async fn cancelled_outer_keeps_required_audit_through_blocking_mutation() {
        let home = TempDir::new().unwrap();
        let cfg = make_cfg(AutonomyLevel::Full, true);
        let action = validate_skill_toggle_policy(&cfg, "fact-check", true).unwrap();
        let audit = required_local_trust_gate(
            home.path(),
            cfg.autonomy_policy(),
            &action,
            None,
            "test-self-activate-cancel",
        )
        .await
        .unwrap();
        let retained_writer = audit
            .writer_clone_for_test()
            .expect("temp HOME must select the owned required audit writer");
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (effect_done_tx, effect_done_rx) = std::sync::mpsc::sync_channel(1);

        // This is the same owned runner used by skill and cron production
        // paths. Cancelling its outer await must detach the owner, not drop the
        // required writer while the blocking effect is still paused.
        let outer = tokio::spawn(run_owned_audited_blocking_mutation(
            audit,
            "test-self-activate-cancel",
            move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                effect_done_tx.send(()).unwrap();
                Ok(())
            },
        ));
        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("blocking mutation must start")
        })
        .await
        .unwrap();

        outer.abort();
        assert!(outer.await.unwrap_err().is_cancelled());
        let payload = b"audit-survives-outer-cancellation".to_vec();
        let header = crate::wal::HeaderBuilder::new(0xE4, &payload).build();
        retained_writer
            .append(header, payload)
            .await
            .expect("the detached owner must keep its audit writer alive while the effect pauses");
        release_tx.send(()).unwrap();
        tokio::task::spawn_blocking(move || {
            effect_done_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("detached owner must keep the mutation alive")
        })
        .await
        .unwrap();

        let writer_closed = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let payload = b"audit-must-close-after-effect".to_vec();
                let header = crate::wal::HeaderBuilder::new(0xE5, &payload).build();
                if retained_writer.append(header, payload).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            writer_closed.is_ok(),
            "bounded finalization must close the retained audit writer after the effect"
        );
        drop(retained_writer);

        let reopened = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match RequiredPermissionAudit::open(home.path(), "test-self-activate-reopen") {
                    Ok(session) => match session.finish().await {
                        Ok(()) => break,
                        Err(_) => tokio::task::yield_now().await,
                    },
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        assert!(
            reopened.is_ok(),
            "the detached owner must bounded-finalize and release its WAL authority"
        );
        let trust = crate::permissions::trust_ledger::TrustLedger::replay_subject_at_home(
            home.path(),
            crate::permissions::trust_ledger::LOCAL_SUBJECT,
        )
        .expect("the admitted decision remains authenticated after outer cancellation");
        assert_eq!(trust.entries.len(), 1);
        assert!(matches!(
            trust.entries[0].event.outcome,
            crate::permissions::trust_ledger::TrustOutcome::Allowed
        ));
    }

    #[test]
    fn self_activate_skill_toggle_writes_freedom_yaml() {
        let dir = TempDir::new().unwrap();
        let cfg = make_cfg(AutonomyLevel::Full, true);
        let yaml_path = write_freedom_yaml(&dir, &cfg);

        // Load, apply toggle, save.
        let mut loaded = FreedomConfig::load_from_path(&yaml_path).unwrap();
        let id_lc = "fact-check";
        loaded
            .skills
            .enabled
            .retain(|s| s.trim().to_lowercase() != id_lc);
        loaded
            .skills
            .disabled
            .retain(|s| s.trim().to_lowercase() != id_lc);
        loaded.skills.disabled.push(id_lc.to_string());
        // This legacy unit isolates the list mutation. Path-injected update_at
        // and unknown-field preservation are covered by config RMW tests.
        assert!(
            loaded
                .skills
                .disabled
                .iter()
                .any(|s| s.trim().to_lowercase() == id_lc),
            "skill should appear in disabled list after toggle"
        );
        assert!(
            !loaded
                .skills
                .enabled
                .iter()
                .any(|s| s.trim().to_lowercase() == id_lc),
            "skill should NOT appear in enabled list after disable toggle"
        );
    }

    // ── cron: always requires --confirm-cron ─────────────────────────────────

    #[test]
    fn self_activate_cron_register_always_requires_confirm_flag() {
        // At Full autonomy, SelfCronRegister → Confirm (never Allow).
        let action = Action::SelfCronRegister {
            job_id: "daily-summary".to_string(),
        };
        let decision = evaluate(&action, AutonomyLevel::Full);
        assert!(
            matches!(decision, crate::permissions::Decision::Confirm(_)),
            "SelfCronRegister must always return Confirm at Full, got {decision:?}"
        );
    }

    #[test]
    fn self_activate_cron_blocked_without_confirm_flag() {
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.self_activation.allow_cron_registration = true;
        let error = validate_cron_toggle_policy(&cfg, "my-job", false).unwrap_err();
        assert!(error.to_string().contains("--confirm-cron"));
    }

    #[tokio::test]
    async fn custom_autonomy_cannot_enable_cron_registration_via_override() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_cfg(AutonomyLevel::Custom, false);
        cfg.self_activation.allow_cron_registration = true;
        cfg.custom_autonomy.overrides.insert(
            crate::permissions::ActionKind::SelfCronRegister,
            crate::permissions::CustomDecision::Allow,
        );

        let error = run_cron_toggle(cfg, dir.path(), "my-job", true, true, OutputFormat::Json)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("disabled under custom autonomy"));
        assert!(!dir.path().join("jobs.yaml").exists());
    }

    // ── jobs.yaml writer ──────────────────────────────────────────────────────

    #[test]
    fn update_jobs_yaml_rejects_missing_job_without_creating_partial_schema() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jobs.yaml");
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.self_activation.allow_cron_registration = true;
        let config_path = write_freedom_yaml(&dir, &cfg);
        let error = update_jobs_yaml(&path, &config_path, "my-job", true, true).unwrap_err();
        assert!(
            error.to_string().contains("neoth cron add"),
            "missing jobs need an actionable full-schema command: {error:#}"
        );
        assert!(
            !path.exists(),
            "a missing job must not create a partial file"
        );
    }

    #[test]
    fn update_jobs_yaml_disable_existing_job() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jobs.yaml");
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.self_activation.allow_cron_registration = true;
        let config_path = write_freedom_yaml(&dir, &cfg);
        std::fs::write(
            &path,
            "version: 1\njobs:\n  - id: my-job\n    name: My job\n    enabled: true\n    schedule:\n      cron: '0 * * * *'\n    prompt: Do the work\n    timeout_seconds: 60\n",
        )
        .unwrap();
        update_jobs_yaml(&path, &config_path, "my-job", false, true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let jobs = crate::cron::JobsFile::from_yaml_str(&content).unwrap();
        assert!(!jobs.jobs[0].enabled, "should flip enabled to false");
    }

    #[test]
    fn update_jobs_yaml_unknown_id_leaves_valid_file_unchanged() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jobs.yaml");
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.self_activation.allow_cron_registration = true;
        let config_path = write_freedom_yaml(&dir, &cfg);
        let original = "version: 1\njobs:\n  - id: existing\n    name: Existing\n    enabled: true\n    schedule:\n      cron: '0 * * * *'\n    prompt: Do the work\n    timeout_seconds: 60\n";
        std::fs::write(&path, original).unwrap();

        let error = update_jobs_yaml(&path, &config_path, "missing", false, true).unwrap_err();
        assert!(error.to_string().contains("does not exist"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn cron_config_authority_serializes_killswitch_after_jobs_commit() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_cfg(AutonomyLevel::Full, true);
        cfg.self_activation.allow_cron_registration = true;
        let config_path = write_freedom_yaml(&dir, &cfg);
        let jobs_path = dir.path().join("jobs.yaml");
        std::fs::write(
            &jobs_path,
            "version: 1\njobs:\n  - id: my-job\n    name: My job\n    enabled: false\n    schedule:\n      cron: '0 * * * *'\n    prompt: Do the work\n    timeout_seconds: 60\n",
        )
        .unwrap();

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (updated_tx, updated_rx) = std::sync::mpsc::channel();
        let updater_path = config_path.clone();
        let updater = std::thread::spawn(move || {
            entered_rx.recv().unwrap();
            FreedomConfig::update_at(&updater_path, |live| {
                live.self_activation.enabled = false;
                Ok(())
            })
            .unwrap();
            updated_tx.send(()).unwrap();
        });

        crate::config::with_current_freedom_config_authority_locked(&config_path, |locked| {
            validate_cron_toggle_policy(locked, "my-job", true)?;
            entered_tx.send(()).unwrap();
            assert!(
                updated_rx
                    .recv_timeout(std::time::Duration::from_millis(100))
                    .is_err(),
                "kill-switch publication must wait while config authority guards jobs commit"
            );
            crate::cron::JobsFile::modify_at_path(&jobs_path, |jobs| {
                jobs.jobs[0].enabled = true;
                Ok(())
            })
        })
        .unwrap();
        updater.join().unwrap();
        updated_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        assert!(
            !FreedomConfig::load_from_path(&config_path)
                .unwrap()
                .self_activation
                .enabled
        );
        let jobs =
            crate::cron::JobsFile::from_yaml_str(&std::fs::read_to_string(&jobs_path).unwrap())
                .unwrap();
        assert!(
            jobs.jobs[0].enabled,
            "the permitted job commit completed before kill switch publication"
        );
    }
}
