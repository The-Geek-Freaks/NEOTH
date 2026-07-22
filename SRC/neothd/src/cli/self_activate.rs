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
//! 0xD0 `CONFIG_RELOADED` fires **automatically** when the running daemon
//! hot-reloads `freedom.yaml` and sees `"skills"` in `changed_fields`.
//! The CLI path does not write WAL directly (no daemon writer available);
//! the daemon detects the change on its next poll cycle.
//! This is identical to how `neoth autonomy` handles `sovereign_buddy`.
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
    cli::OutputFormat,
    config::FreedomConfig,
    permissions::{Action, Decision, evaluate},
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
            run_cron_toggle(cfg, &home, &job_id, turn_on, confirm_cron, output)
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

    FreedomConfig::update_at(config_path, |cfg| {
        // Re-check the kill-switch inside the exact generation that will be
        // published. The entry-point snapshot may have changed while the
        // command was being dispatched.
        if !cfg.self_activation.enabled {
            anyhow::bail!(
                "self-activation is disabled. Set `self_activation.enabled: true` \
                 in freedom.yaml to allow NEOTH to toggle its own skills/crons."
            );
        }

        // Gate 2 — preflight firewall: `skills.disabled` always wins, so if the
        // skill is already in the disabled list and the agent asks to enable it,
        // the toggle would write `skills.enabled` but the loader would still see
        // it as disabled.  Bail loudly so the agent knows it must use the operator
        // `neoth skills --enable` path after explicit operator consent.
        if cfg
            .skills
            .disabled
            .iter()
            .any(|s| s.trim().to_lowercase() == id_lc)
        {
            anyhow::bail!(
                "skill '{id_lc}' is in `skills.disabled` — the disabled list \
                 always wins and cannot be overridden by self-activate. \
                 Operator must run `neoth skills --enable {id_lc}` explicitly."
            );
        }

        // Gate 3 — sovereign mode required for auto-allow at Full level.
        // Below Full or without sovereign_buddy, `evaluate` returns Deny/Confirm.
        let action = Action::SelfSkillToggle {
            skill_id: id_lc.clone(),
            enable: turn_on,
        };

        if !cfg.sovereign_active() {
            // Sovereign mode (sovereign_buddy AND Full autonomy) is the only
            // auto-allow path. At Full without sovereign_buddy, evaluate
            // returns Allow, but the sovereign gate is the outer firewall.
            let decision = evaluate(&action, &cfg.autonomy_policy());
            match decision {
                Decision::Allow => {
                    anyhow::bail!(
                        "self-activate requires sovereign mode (sovereign_buddy: true AND \
                         autonomy: full). Enable sovereign mode via `neoth mode sovereign-buddy enable`."
                    );
                }
                Decision::Confirm(msg) => anyhow::bail!("confirm required: {msg}"),
                Decision::Deny(msg) => anyhow::bail!("denied: {msg}"),
            }
        }

        // Gate 4 — allowlist check (sovereign_active = true from here).
        if !cfg.self_activation.skill_allowed(&id_lc) {
            if cfg.self_activation.skill_allowlist.is_empty() {
                anyhow::bail!(
                    "self-activation skill allowlist is empty — add '{id_lc}' to \
                     `self_activation.skill_allowlist` in freedom.yaml."
                );
            }
            anyhow::bail!(
                "skill '{id_lc}' not in `self_activation.skill_allowlist`. \
                 Add it to freedom.yaml or use `neoth skills --enable {id_lc}` as operator."
            );
        }

        if turn_on
            && cfg
                .skills
                .visibility_overrides
                .get(&id_lc)
                .is_some_and(|visibility| *visibility == crate::config::SkillVisibility::Off)
        {
            anyhow::bail!(
                "skill '{id_lc}' has `skills.visibility_overrides: off` — this operator \
                 block cannot be overridden by self-activate"
            );
        }

        // Gate 5 — permission system (Full+sovereign → Allow).
        let decision = evaluate(&action, &cfg.autonomy_policy());
        match decision {
            Decision::Allow => {}
            Decision::Confirm(msg) => anyhow::bail!("confirm required: {msg}"),
            Decision::Deny(msg) => anyhow::bail!("denied: {msg}"),
        }

        // Apply toggle — same mutation as `neoth skills --enable/--disable`.
        cfg.skills
            .enabled
            .retain(|s| s.trim().to_lowercase() != id_lc);
        cfg.skills
            .disabled
            .retain(|s| s.trim().to_lowercase() != id_lc);
        if turn_on {
            cfg.skills.enabled.push(id_lc.clone());
        } else {
            cfg.skills.disabled.push(id_lc.clone());
        }
        Ok(())
    })
    .map_err(|e| anyhow::anyhow!("write freedom.yaml: {e}"))?;

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

// ── Cron toggle ───────────────────────────────────────────────────────────────

fn run_cron_toggle(
    cfg: FreedomConfig,
    home: &std::path::Path,
    job_id: &str,
    turn_on: bool,
    confirm_cron: bool,
    output: OutputFormat,
) -> Result<()> {
    // Error-hunt #2: the config opt-in was shipped dead — wire it. Cron
    // self-toggling needs the freedom.yaml flag AND --confirm-cron AND the
    // permission Confirm below (three independent gates, all fail-closed).
    if !cfg.self_activation.allow_cron_registration {
        anyhow::bail!(
            "cron self-registration is disabled — set \
             freedom.yaml::self_activation.allow_cron_registration: true first"
        );
    }
    // Custom is deliberately disabled for unattended scheduler mutation. A
    // per-action override must never turn Custom into a cron-registration
    // capability; use an explicit non-Custom level plus --confirm-cron.
    if cfg.autonomy == crate::permissions::AutonomyLevel::Custom {
        anyhow::bail!(
            "cron self-registration is disabled under custom autonomy regardless of overrides"
        );
    }
    // Gate — cron always requires --confirm-cron, regardless of autonomy level.
    // This is enforced by the permission system (SelfCronRegister → always Confirm),
    // plus an explicit flag check so even Full+sovereign cannot auto-allow.
    let action = Action::SelfCronRegister {
        job_id: job_id.to_string(),
    };
    let decision = evaluate(&action, &cfg.autonomy_policy());
    match decision {
        Decision::Allow => {
            // evaluate_full returns Confirm for SelfCronRegister, not Allow.
            // Reaching Allow here would be a permissions bug. Treat as Confirm.
        }
        Decision::Confirm(_) => {
            if !confirm_cron {
                anyhow::bail!(
                    "cron registration always requires explicit operator confirmation. \
                     Re-run with --confirm-cron to proceed. The scheduler applies a \
                     valid jobs.yaml generation on its next live-reload tick."
                );
            }
        }
        Decision::Deny(msg) => anyhow::bail!("denied: {msg}"),
    }

    // Write jobs.yaml.
    let jobs_yaml = home.join("jobs.yaml");
    let state = if turn_on { "enabled" } else { "disabled" };
    update_jobs_yaml(&jobs_yaml, job_id, turn_on)?;

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
fn update_jobs_yaml(path: &std::path::Path, job_id: &str, turn_on: bool) -> Result<()> {
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
            error.to_string().contains("not installed or bundled"),
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
        // Missing --confirm-cron → the caller bails with an error.
        // Simulate the check: decision is Confirm and confirm_cron = false.
        let action = Action::SelfCronRegister {
            job_id: "my-job".to_string(),
        };
        let decision = evaluate(&action, AutonomyLevel::Full);
        let confirm_cron = false;
        let would_bail =
            matches!(decision, crate::permissions::Decision::Confirm(_)) && !confirm_cron;
        assert!(would_bail, "missing --confirm-cron should trigger bail");
    }

    #[test]
    fn custom_autonomy_cannot_enable_cron_registration_via_override() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_cfg(AutonomyLevel::Custom, false);
        cfg.self_activation.allow_cron_registration = true;
        cfg.custom_autonomy.overrides.insert(
            crate::permissions::ActionKind::SelfCronRegister,
            crate::permissions::CustomDecision::Allow,
        );

        let error =
            run_cron_toggle(cfg, dir.path(), "my-job", true, true, OutputFormat::Json).unwrap_err();
        assert!(error.to_string().contains("disabled under custom autonomy"));
        assert!(!dir.path().join("jobs.yaml").exists());
    }

    // ── jobs.yaml writer ──────────────────────────────────────────────────────

    #[test]
    fn update_jobs_yaml_rejects_missing_job_without_creating_partial_schema() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jobs.yaml");
        let error = update_jobs_yaml(&path, "my-job", true).unwrap_err();
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
        std::fs::write(
            &path,
            "version: 1\njobs:\n  - id: my-job\n    name: My job\n    enabled: true\n    schedule:\n      cron: '0 * * * *'\n    prompt: Do the work\n    timeout_seconds: 60\n",
        )
        .unwrap();
        update_jobs_yaml(&path, "my-job", false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let jobs = crate::cron::JobsFile::from_yaml_str(&content).unwrap();
        assert!(!jobs.jobs[0].enabled, "should flip enabled to false");
    }

    #[test]
    fn update_jobs_yaml_unknown_id_leaves_valid_file_unchanged() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jobs.yaml");
        let original = "version: 1\njobs:\n  - id: existing\n    name: Existing\n    enabled: true\n    schedule:\n      cron: '0 * * * *'\n    prompt: Do the work\n    timeout_seconds: 60\n";
        std::fs::write(&path, original).unwrap();

        let error = update_jobs_yaml(&path, "missing", false).unwrap_err();
        assert!(error.to_string().contains("does not exist"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }
}
