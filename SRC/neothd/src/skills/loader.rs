//! Skill loader — bundled-in-binary defaults + `~/.neoth/skills/<id>/skill.yaml`
//! user overrides. Existing malformed or unreadable manifests fail the load;
//! only genuinely absent optional files are ignored.
//!
//! ## Two layers
//!
//! 1. **Bundled**: every skill under `SRC/neothd/assets/skills/<id>/skill.yaml`
//!    is `include_str!`-baked into the binary at compile time (see
//!    [`super::bundled::BUNDLED_SKILLS`]). Fresh operator boot has the full
//!    library active — no install step required. R3 P0 fix.
//! 2. **User inventory**: anything under
//!    `~/.neoth/skills/<id>/skill.yaml` appears as an installed candidate.
//!    Raw inventory views layer a same-id candidate over the bundled row for
//!    diagnostics and mutation workflows only. Executable runtime snapshots
//!    never inherit bundled trust: the exact installed package must consume a
//!    current [`super::authority::ValidatedInstalledSkillAuthority`] before it
//!    can replace the bundled Skill or route at all.
//!
//! Layout convention for user-installed skills:
//! ```text
//! ~/.neoth/skills/
//!   morning-news/
//!     skill.yaml           ← parsed
//!     extras.md            ← ignored by loader, can be referenced from system_prompt
//!   recall-helper/
//!     skill.yaml
//! ```

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::schema::{RuntimeSkill, Skill, SkillManifest};
use super::store::{open_bound_directory, open_real_child_dir, read_regular_file_bounded};

const MAX_SKILL_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_INSTALLED_SKILL_ROOT_ENTRIES: usize = 512;
const MAX_INSTALLED_SKILL_MANIFEST_WORK_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct AuthorizedRuntimeSkillSnapshot {
    pub(crate) skills: Vec<RuntimeSkill>,
    pub(crate) accepted_config_epoch: u64,
}

/// Load every available skill into a raw diagnostic/mutation inventory —
/// bundled-in-binary defaults plus user-installed candidates from
/// `<skills_dir>` if it exists.
///
/// This function does **not** grant runtime authority and its output must not
/// route, inject prompts, select models, or execute tests. Runtime consumers
/// use [`load_authorized_from_reload_controller`]. In this inventory only,
/// user candidates override bundled ids so operators can inspect or repair the
/// candidate they actually installed. A missing user dir is a normal
/// fresh-install state; an existing unreadable user dir is an error.
///
/// A missing user directory is the normal fresh-install state. Once the
/// directory or an individual `skill.yaml` exists, read/parse/schema failures
/// are fatal so startup cannot silently lose operator-installed behaviour.
///
/// The output is sorted by id for deterministic ordering downstream
/// (router picks the first keyword match in declaration order; sorting
/// the inputs keeps that order reproducible across processes).
pub async fn load_all(skills_dir: &Path) -> Result<Vec<Skill>> {
    let config_path = skills_dir.parent().map(|home| home.join("freedom.yaml"));
    load_all_from_policy_source(skills_dir, config_path.as_deref(), None).await
}

/// Load the full skill set against an exact operator config path.
///
/// Daemon instances with a custom `--config` filename must never reconstruct
/// `<home>/freedom.yaml`: that can publish a routing policy from a different
/// file than the one accepted by the runtime reload controller.
pub(crate) async fn load_all_from_config_path(
    skills_dir: &Path,
    config_path: &Path,
) -> Result<Vec<Skill>> {
    load_all_from_policy_source(skills_dir, Some(config_path), None).await
}

/// Load the full skill set from an already accepted runtime policy snapshot.
/// This is the daemon hot-reload path: a rejected freedom.yaml generation can
/// never leak its skill enable/disable decisions into the routing registry.
pub(crate) async fn load_all_from_skills_config(
    skills_dir: &Path,
    skills_config: &crate::config::SkillsConfig,
) -> Result<Vec<Skill>> {
    load_all_from_policy_source(
        skills_dir,
        None,
        Some(SkillPolicy::from_config(skills_config)),
    )
    .await
}

/// Build the routing snapshot from the exact config generation accepted by
/// the runtime reload controller.
///
/// Bundled Skills have an explicit compile-time trust origin. Installed
/// packages are candidates only: each one must consume a
/// [`super::authority::ValidatedInstalledSkillAuthority`] for its exact live
/// generation before it can replace a bundled Skill or enter the returned
/// registry. Missing, stale, revoked, mismatched, or policy-disabled authority
/// leaves the candidate absent; an installed same-id package never inherits
/// the bundled package's trust.
pub(crate) async fn load_authorized_from_reload_controller(
    skills_dir: &Path,
    reload: &crate::config::reload::ReloadController,
) -> Result<AuthorizedRuntimeSkillSnapshot> {
    load_authorized_with_budget_override(skills_dir, reload, None).await
}

async fn load_authorized_with_budget_override(
    skills_dir: &Path,
    reload: &crate::config::reload::ReloadController,
    authority_budget_override: Option<(usize, u64)>,
) -> Result<AuthorizedRuntimeSkillSnapshot> {
    let installed_store_ready = match super::mutation_lifecycle::reconcile_for_runtime(skills_dir)
        .await
    {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(
                dir = %skills_dir.display(),
                error = %error,
                "installed Skill store reconciliation failed; publishing trusted bundled-only runtime snapshot"
            );
            false
        }
    };

    let home = skills_dir.parent().map(Path::to_path_buf);
    if home.is_none() {
        tracing::warn!(
            dir = %skills_dir.display(),
            "authorized Skill directory has no NEOTH home parent; publishing trusted bundled-only runtime snapshot"
        );
    }
    let skills_dir = skills_dir.to_path_buf();
    let skills_dir_display = skills_dir.display().to_string();
    let reload = reload.clone();
    let accepted = reload.accepted_snapshot();
    let accepted_epoch = accepted.epoch();
    let accepted_config = accepted.config();
    let policy = SkillPolicy::from_config(&accepted_config.skills);

    tokio::task::spawn_blocking(move || {
        let bundled_only = load_trusted_bundled_with_policy(&policy)?;
        let mut by_id: HashMap<String, RuntimeSkill> = bundled_only
            .iter()
            .cloned()
            .map(|skill| (skill.id().to_string(), skill))
            .collect();

        let candidates = if installed_store_ready {
            match load_user_skills_with_mode(&skills_dir, UserSkillLoadMode::Quarantine) {
                Ok(candidates) => candidates,
                Err(error) => {
                    tracing::warn!(
                        dir = %skills_dir.display(),
                        error = %error,
                        "installed Skill store is unavailable; publishing trusted bundled-only runtime snapshot"
                    );
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        let Some(home) = home.as_deref() else {
            return finish_authorized_snapshot(&reload, accepted_epoch, bundled_only);
        };
        let mut authority_batch = if candidates.is_empty() {
            None
        } else {
            match super::authority::begin_installed_authority_validation_batch(home, &reload) {
                Ok(batch) => {
                    #[cfg(test)]
                    let batch = {
                        let mut batch = batch;
                        if let Some((max_entries, max_bytes)) = authority_budget_override {
                            batch.set_traversal_limits_for_test(max_entries, max_bytes);
                        }
                        batch
                    };
                    #[cfg(not(test))]
                    debug_assert!(
                        authority_budget_override.is_none(),
                        "runtime authority budget overrides are test-only"
                    );
                    Some(batch)
                }
                Err(error) => {
                    tracing::warn!(
                        dir = %skills_dir.display(),
                        error = %error,
                        "installed Skill authority batch is unavailable; publishing trusted bundled-only runtime snapshot"
                    );
                    return finish_authorized_snapshot(&reload, accepted_epoch, bundled_only);
                }
            }
        };
        for candidate in candidates {
            let id = candidate.skill.id().to_string();
            let Some(authority_batch) = authority_batch.as_mut() else {
                break;
            };
            match authority_batch.validate(&id, &reload) {
                Ok(super::authority::InstalledSkillAuthorityValidation::Active(authority)) => {
                    let skill = match RuntimeSkill::from_validated_installed(
                        authority,
                        candidate.skill.path,
                        candidate.skill.content_hash,
                        &candidate.manifest_sha256,
                    )
                    .with_context(|| format!("materialize authorized installed Skill `{id}`"))
                    {
                        Ok(skill) => skill,
                        Err(error) => {
                            tracing::warn!(
                                id = %id,
                                error = %error,
                                "quarantining installed Skill whose authority and loaded bytes do not match"
                            );
                            continue;
                        }
                    };
                    let overrode_bundled = by_id.contains_key(&id);
                    debug!(
                        id = %id,
                        overrode_bundled,
                        content_hash = %skill.content_hash,
                        "admitted installed Skill with validated runtime authority"
                    );
                    by_id.insert(id, skill);
                }
                Ok(super::authority::InstalledSkillAuthorityValidation::Inactive(reason)) => {
                    if matches!(
                        reason,
                        super::authority::SkillAuthorityInactiveReason::DecisionInactive
                            | super::authority::SkillAuthorityInactiveReason::DecisionRevoked
                    ) {
                        by_id.remove(&id);
                    }
                    debug!(
                        id = %id,
                        authority_reason = reason.as_str(),
                        "installed Skill is inactive at the runtime authority boundary"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        dir = %skills_dir.display(),
                        id = %id,
                        error = %error,
                        "installed Skill authority batch exceeded its aggregate validation boundary; publishing trusted bundled-only runtime snapshot"
                    );
                    return finish_authorized_snapshot(&reload, accepted_epoch, bundled_only);
                }
            }
        }

        anyhow::ensure!(
            reload.accepted_snapshot().epoch() == accepted_epoch,
            "accepted Skill policy changed while building authorized runtime registry"
        );
        let mut out: Vec<RuntimeSkill> = by_id.into_values().collect();
        out.sort_by(|left, right| left.id().cmp(right.id()));
        if let Err(error) = super::mode_registry::ModeRegistry::from_skills(&out) {
            tracing::warn!(
                error = %error,
                "authorized installed Skill modes conflict; publishing trusted bundled-only runtime snapshot"
            );
            return Ok(AuthorizedRuntimeSkillSnapshot {
                skills: bundled_only,
                accepted_config_epoch: accepted_epoch,
            });
        }
        Ok(AuthorizedRuntimeSkillSnapshot {
            skills: out,
            accepted_config_epoch: accepted_epoch,
        })
    })
    .await
    .with_context(|| format!("authorized Skill loader worker failed for {skills_dir_display}"))?
}

/// Build a complete bundled-only runtime layer from one stable accepted policy
/// epoch. Used by the registry's last-resort fail-closed path: filtering an old
/// mixed snapshot would both preserve stale enablement and lose bundled ids
/// that an installed package had replaced.
pub(crate) async fn load_trusted_bundled_from_reload_controller(
    reload: &crate::config::reload::ReloadController,
) -> Result<AuthorizedRuntimeSkillSnapshot> {
    const MAX_ACCEPTED_EPOCH_RETRIES: usize = 8;

    let reload = reload.clone();
    for attempt in 1..=MAX_ACCEPTED_EPOCH_RETRIES {
        let accepted = reload.accepted_snapshot();
        let accepted_epoch = accepted.epoch();
        let policy = SkillPolicy::from_config(&accepted.config().skills);
        let bundled =
            tokio::task::spawn_blocking(move || load_trusted_bundled_with_policy(&policy))
                .await
                .context("trusted bundled Skill fallback worker failed")??;
        if reload.accepted_snapshot().epoch() == accepted_epoch {
            return Ok(AuthorizedRuntimeSkillSnapshot {
                skills: bundled,
                accepted_config_epoch: accepted_epoch,
            });
        }
        debug!(
            attempt,
            accepted_epoch,
            "accepted Skill policy changed while building bundled-only fallback; retrying"
        );
        tokio::task::yield_now().await;
    }
    anyhow::bail!(
        "accepted Skill policy did not stabilize across {MAX_ACCEPTED_EPOCH_RETRIES} bundled fallback attempts"
    )
}

fn load_trusted_bundled_with_policy(policy: &SkillPolicy) -> Result<Vec<RuntimeSkill>> {
    let mut bundled = parse_bundled_skills()?;
    for skill in bundled.values_mut() {
        policy.apply_to_bundled_manifest(&mut skill.manifest);
    }
    let mut runtime = bundled
        .into_values()
        .map(RuntimeSkill::from_trusted_bundled)
        .collect::<Result<Vec<_>>>()?;
    runtime.sort_by(|left, right| left.id().cmp(right.id()));
    super::mode_registry::ModeRegistry::from_skills(&runtime)
        .context("validate trusted bundled Skill modes")?;
    Ok(runtime)
}

fn finish_authorized_snapshot(
    reload: &crate::config::reload::ReloadController,
    accepted_epoch: u64,
    skills: Vec<RuntimeSkill>,
) -> Result<AuthorizedRuntimeSkillSnapshot> {
    anyhow::ensure!(
        reload.accepted_snapshot().epoch() == accepted_epoch,
        "accepted Skill policy changed while building authorized runtime registry"
    );
    Ok(AuthorizedRuntimeSkillSnapshot {
        skills,
        accepted_config_epoch: accepted_epoch,
    })
}

async fn load_all_from_policy_source(
    skills_dir: &Path,
    config_path: Option<&Path>,
    accepted_policy: Option<SkillPolicy>,
) -> Result<Vec<Skill>> {
    // Installed bytes are never observable while their correlated mutation
    // intent/result lifecycle is unresolved. This chokepoint covers CLI chat,
    // mode/ecology routing, Doctor, hot reload, and direct registry bootstrap.
    super::mutation_lifecycle::reconcile_for_runtime(skills_dir)
        .await
        .with_context(|| {
            format!(
                "reconcile audited Skill mutation before loading {}",
                skills_dir.display()
            )
        })?;

    // ── Layer 1: bundled skills (always present) ────────────────────────
    let mut by_id = parse_bundled_skills()?;

    // ── Layer 2: user skills (override by id) ───────────────────────────
    // cap-std exposes synchronous handle-relative I/O. Keep directory walks
    // and config snapshots off Tokio's async worker so hot reloads cannot
    // stall unrelated channel/provider tasks when many manifests are present.
    let skills_dir_owned = skills_dir.to_path_buf();
    let config_path = config_path.map(Path::to_path_buf);
    let (policy, user_skills) = tokio::task::spawn_blocking(move || {
        let policy = match (accepted_policy, config_path) {
            (Some(policy), _) => policy,
            (None, Some(config_path)) => load_skill_policy_from_config_path(&config_path)?,
            (None, None) => SkillPolicy::default(),
        };
        let user_skills = load_user_skills(&skills_dir_owned)?;
        Ok::<_, anyhow::Error>((policy, user_skills))
    })
    .await
    .with_context(|| format!("skill loader worker failed for {}", skills_dir.display()))??;
    for skill in by_id.values_mut() {
        policy.apply_to_bundled_manifest(&mut skill.manifest);
    }
    for mut candidate in user_skills {
        policy.apply_to_manifest(&mut candidate.skill.manifest);
        let skill = candidate.skill;
        let overrode = by_id.contains_key(&skill.manifest.id);
        debug!(
            id = %skill.manifest.id,
            keywords = skill.manifest.trigger_keywords.len(),
            enabled = skill.manifest.enabled,
            overrode_bundled = overrode,
            content_hash = %skill.content_hash,
            "loaded user skill"
        );
        by_id.insert(skill.manifest.id.clone(), skill);
    }

    let mut out: Vec<Skill> = by_id.into_values().collect();
    out.sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    Ok(out)
}

/// Diagnostic operator inventory. Runtime loading remains strict and aborts
/// on the first broken user generation; this separate surface preserves every
/// healthy row while making the broken directory visible and removable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SkillInventoryRow {
    Healthy {
        manifest: Box<SkillManifest>,
        origin: SkillInventoryOrigin,
        path: Option<PathBuf>,
        runtime_state: SkillInventoryRuntimeState,
        package_generation_sha256: Option<String>,
        install_incarnation: Option<u64>,
        install_terminal_receipt_sha256: Option<String>,
    },
    Broken {
        id: String,
        error: String,
        path: PathBuf,
        repairability: super::installer::SkillRepairability,
        runtime_state: SkillInventoryRuntimeState,
        package_generation_sha256: Option<String>,
        install_incarnation: Option<u64>,
        install_terminal_receipt_sha256: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillInventoryOrigin {
    Bundled,
    User,
}

/// Execution truth for an inventory row. `manifest.enabled` is only the
/// effective policy bit and must never be presented as installed-Skill
/// authority. A same-id installed candidate can be quarantined while the
/// trusted bundled implementation remains active.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillInventoryRuntimeState {
    TrustedBundledActive,
    InstalledActive,
    BundledFallbackActive,
    Disabled,
}

impl SkillInventoryRuntimeState {
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub const fn installed_candidate_is_active(self) -> bool {
        matches!(self, Self::InstalledActive)
    }
}

#[derive(Clone, Debug)]
struct InventoryRuntimeEvidence {
    state: SkillInventoryRuntimeState,
    package_generation_sha256: Option<String>,
    install_incarnation: Option<u64>,
    install_terminal_receipt_sha256: Option<String>,
}

fn installed_candidate_runtime_state(
    evidence: Option<&InventoryRuntimeEvidence>,
    package_generation_sha256: Option<&str>,
    install_incarnation: Option<u64>,
    install_terminal_receipt_sha256: Option<&str>,
) -> SkillInventoryRuntimeState {
    match evidence {
        Some(InventoryRuntimeEvidence {
            state: SkillInventoryRuntimeState::InstalledActive,
            package_generation_sha256: Some(runtime_generation),
            install_incarnation: Some(runtime_incarnation),
            install_terminal_receipt_sha256: Some(runtime_receipt),
        }) if package_generation_sha256 == Some(runtime_generation.as_str())
            && install_incarnation == Some(*runtime_incarnation)
            && install_terminal_receipt_sha256 == Some(runtime_receipt.as_str()) =>
        {
            SkillInventoryRuntimeState::InstalledActive
        }
        Some(InventoryRuntimeEvidence {
            state: SkillInventoryRuntimeState::TrustedBundledActive,
            ..
        }) => SkillInventoryRuntimeState::BundledFallbackActive,
        _ => SkillInventoryRuntimeState::Disabled,
    }
}

impl SkillInventoryRow {
    pub fn id(&self) -> &str {
        match self {
            Self::Healthy { manifest, .. } => &manifest.id,
            Self::Broken { id, .. } => id,
        }
    }
}

pub async fn diagnostic_inventory(skills_dir: &Path) -> Result<Vec<SkillInventoryRow>> {
    let home = skills_dir
        .parent()
        .context("Skill inventory directory has no NEOTH home parent")?;
    let config_path = home.join("freedom.yaml");
    let config = crate::config::FreedomConfig::load_from_path_or_default(&config_path)
        .with_context(|| format!("load Skill inventory policy from {}", config_path.display()))?;
    diagnostic_inventory_for_accepted_config(skills_dir, config, config_path).await
}

/// Instance-bound inventory using the exact config generation already accepted
/// by the caller. Daemons with a custom config filename must use this entry
/// point; reconstructing `<home>/freedom.yaml` would render authority from a
/// different policy generation.
pub(crate) async fn diagnostic_inventory_for_accepted_config(
    skills_dir: &Path,
    config: crate::config::FreedomConfig,
    config_path: PathBuf,
) -> Result<Vec<SkillInventoryRow>> {
    let policy = SkillPolicy::from_config(&config.skills);
    let reload = crate::config::reload::ReloadController::new(config, config_path);
    let runtime = load_authorized_from_reload_controller(skills_dir, &reload)
        .await
        .with_context(|| {
            format!(
                "build authority-admitted Skill inventory from {}",
                skills_dir.display()
            )
        })?;
    let runtime_states = runtime
        .skills
        .into_iter()
        .map(|skill| {
            let state = if !skill.is_enabled() {
                SkillInventoryRuntimeState::Disabled
            } else if skill.is_trusted_bundled() {
                SkillInventoryRuntimeState::TrustedBundledActive
            } else {
                SkillInventoryRuntimeState::InstalledActive
            };
            (
                skill.id().to_lowercase(),
                InventoryRuntimeEvidence {
                    state,
                    package_generation_sha256: skill
                        .package_generation_sha256()
                        .map(str::to_string),
                    install_incarnation: skill.install_incarnation(),
                    install_terminal_receipt_sha256: skill
                        .install_terminal_receipt_sha256()
                        .map(str::to_string),
                },
            )
        })
        .collect();
    let skills_dir = skills_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        diagnostic_inventory_blocking(&skills_dir, &policy, &runtime_states)
    })
    .await
    .context("skill diagnostic inventory worker failed")?
}

fn diagnostic_inventory_blocking(
    skills_dir: &Path,
    policy: &SkillPolicy,
    runtime_states: &HashMap<String, InventoryRuntimeEvidence>,
) -> Result<Vec<SkillInventoryRow>> {
    let (installed_entries, install_incarnations) =
        super::installer::list_installed_with_incarnation_index(skills_dir)
            .context("capture installed Skill inventory and incarnations atomically")?;
    let mut rows = std::collections::BTreeMap::<String, SkillInventoryRow>::new();
    for (_, mut skill) in parse_bundled_skills()? {
        policy.apply_to_bundled_manifest(&mut skill.manifest);
        let runtime_state = runtime_states
            .get(&skill.manifest.id.to_lowercase())
            .map(|evidence| evidence.state)
            .unwrap_or(SkillInventoryRuntimeState::Disabled);
        rows.insert(
            skill.manifest.id.to_lowercase(),
            SkillInventoryRow::Healthy {
                manifest: Box::new(skill.manifest),
                origin: SkillInventoryOrigin::Bundled,
                path: None,
                runtime_state,
                package_generation_sha256: None,
                install_incarnation: None,
                install_terminal_receipt_sha256: None,
            },
        );
    }

    for entry in installed_entries {
        let key = entry.dir_name.to_lowercase();
        let repairability = entry
            .repairability
            .unwrap_or(super::installer::SkillRepairability::RemoveOnly);
        match (entry.manifest, entry.error) {
            (Some(mut manifest), None) => {
                policy.apply_to_manifest(&mut manifest);
                let install_proof = entry.generation_sha256.as_deref().and_then(|generation| {
                    install_incarnations
                        .authenticate_current(&key, generation)
                        .ok()
                });
                let runtime_state = installed_candidate_runtime_state(
                    runtime_states.get(&key),
                    entry.generation_sha256.as_deref(),
                    install_proof
                        .as_ref()
                        .map(|proof| proof.install_incarnation()),
                    install_proof
                        .as_ref()
                        .map(|proof| proof.terminal_receipt_sha256()),
                );
                rows.insert(
                    key,
                    SkillInventoryRow::Healthy {
                        manifest: Box::new(manifest),
                        origin: SkillInventoryOrigin::User,
                        path: Some(entry.path),
                        runtime_state,
                        package_generation_sha256: entry.generation_sha256,
                        install_incarnation: install_proof
                            .as_ref()
                            .map(|proof| proof.install_incarnation()),
                        install_terminal_receipt_sha256: install_proof
                            .as_ref()
                            .map(|proof| proof.terminal_receipt_sha256().to_string()),
                    },
                );
            }
            (_, error) => {
                let runtime_state = installed_candidate_runtime_state(
                    runtime_states.get(&key),
                    entry.generation_sha256.as_deref(),
                    None,
                    None,
                );
                rows.insert(
                    key,
                    SkillInventoryRow::Broken {
                        id: entry.dir_name,
                        error: sanitize_inventory_error(
                            error.as_deref().unwrap_or("unknown inventory error"),
                        ),
                        path: entry.path,
                        repairability,
                        runtime_state,
                        package_generation_sha256: entry.generation_sha256,
                        install_incarnation: None,
                        install_terminal_receipt_sha256: None,
                    },
                );
            }
        }
    }

    let mut rows: Vec<_> = rows.into_values().collect();
    rows.sort_by(|left, right| left.id().cmp(right.id()));
    Ok(rows)
}

fn sanitize_inventory_error(error: &str) -> String {
    let mut clean = String::with_capacity(error.len().min(512));
    for character in error.chars() {
        if clean.len() >= 512 {
            break;
        }
        match character {
            '\r' | '\n' | '\t' => clean.push(' '),
            value if value.is_control() => clean.push('�'),
            value => clean.push(value),
        }
    }
    if error.len() > clean.len() {
        clean.push('…');
    }
    clean
}

struct LoadedUserSkill {
    skill: Skill,
    manifest_sha256: String,
}

fn load_user_skills(skills_dir: &Path) -> Result<Vec<LoadedUserSkill>> {
    load_user_skills_with_mode(skills_dir, UserSkillLoadMode::Strict)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserSkillLoadMode {
    /// Inventory and operator-facing validation must expose a broken package
    /// as an error instead of silently pretending it is absent.
    Strict,
    /// Runtime authority reloads quarantine each broken candidate so one
    /// poisoned package cannot retain an older, already-revoked routing
    /// snapshot by aborting the complete ArcSwap replacement.
    Quarantine,
}

fn load_user_skills_with_mode(
    skills_dir: &Path,
    mode: UserSkillLoadMode,
) -> Result<Vec<LoadedUserSkill>> {
    load_user_skills_with_limits(
        skills_dir,
        mode,
        MAX_INSTALLED_SKILL_ROOT_ENTRIES,
        MAX_INSTALLED_SKILL_MANIFEST_WORK_BYTES,
    )
}

fn charge_manifest_work(
    total: &mut usize,
    charge: usize,
    max_manifest_work_bytes: usize,
    skills_dir: &Path,
) -> Result<()> {
    let next = total
        .checked_add(charge)
        .context("installed Skill manifest-work counter overflow")?;
    anyhow::ensure!(
        next <= max_manifest_work_bytes,
        "installed Skill manifests under {} exceed the \
         {max_manifest_work_bytes}-byte runtime work limit",
        skills_dir.display()
    );
    *total = next;
    Ok(())
}

fn load_user_skills_with_limits(
    skills_dir: &Path,
    mode: UserSkillLoadMode,
    max_root_entries: usize,
    max_manifest_work_bytes: usize,
) -> Result<Vec<LoadedUserSkill>> {
    let mut out = Vec::new();
    let root = open_bound_directory(skills_dir, false, "skills root")
        .with_context(|| format!("read skills directory {}", skills_dir.display()))?;
    if let Some(root) = root {
        let _mutation_guard = super::installer::lock_skill_mutations(&root)
            .context("lock skill store for a consistent runtime snapshot")?;
        super::installer::recover_pending_transactions_locked(&root)
            .context("recover interrupted skill transaction before runtime load")?;
        let entries = root
            .dir
            .entries()
            .with_context(|| format!("enumerate skills directory {}", skills_dir.display()))?;
        let mut root_entry_count = 0usize;
        let mut manifest_work_bytes = 0usize;
        for entry in entries {
            root_entry_count = root_entry_count
                .checked_add(1)
                .context("installed Skill root-entry counter overflow")?;
            anyhow::ensure!(
                root_entry_count <= max_root_entries,
                "installed Skill root under {} exceeds the {max_root_entries}-entry runtime limit",
                skills_dir.display()
            );
            let mut load_budget_failed = false;
            let loaded = (|| -> Result<Option<LoadedUserSkill>> {
                let entry = entry.with_context(|| {
                    format!("enumerate skills directory {}", skills_dir.display())
                })?;
                let name = entry.file_name();
                let path = root.display_path.join(&name);
                if name.as_encoded_bytes().first() == Some(&b'.') {
                    return Ok(None);
                }
                // A directory whose NAME cannot be a skill id is not loaded — but it
                // must not take the other skills down with it. `validate_skill_id`
                // was tightened to lowercase-only after installs already existed, so
                // one legacy `MySkill/` would otherwise fail the whole registry
                // build and with it `neoth serve` and `neoth chat`. Skipping is
                // equally fail-closed for authority (the skill is never loaded) and
                // the entry still surfaces as a Broken row in `diagnostic_inventory`,
                // which is the operator's repair path.
                let Some(dir_name) = name.to_str() else {
                    tracing::warn!(
                        path = %path.display(),
                        "skipping installed skill: directory name is not valid UTF-8"
                    );
                    return Ok(None);
                };
                if let Err(error) = super::creator::validate_skill_id(dir_name) {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "skipping installed skill: directory id is not canonical \
                         (see `neoth skills --list` for the repair path)"
                    );
                    return Ok(None);
                }
                let file_type = entry
                    .file_type()
                    .with_context(|| format!("inspect skill entry {}", path.display()))?;
                if file_type.is_symlink() {
                    anyhow::bail!(
                        "installed skill must be a real directory, not a symlink or reparse point: {}",
                        path.display()
                    );
                }
                if !file_type.is_dir() {
                    anyhow::bail!(
                        "installed skill entry must be a real directory: {}",
                        path.display()
                    );
                }
                let skill_dir = open_real_child_dir(&root.dir, &name, &path)?;
                let yaml_path = path.join("skill.yaml");
                let raw = match read_regular_file_bounded(
                    &skill_dir,
                    OsStr::new("skill.yaml"),
                    &yaml_path,
                    MAX_SKILL_MANIFEST_BYTES,
                ) {
                    Ok(raw) => raw,
                    Err(error) if error_is_not_found(&error) => {
                        anyhow::bail!(
                            "no skill.yaml in installed skill directory {}",
                            path.display()
                        );
                    }
                    Err(error) => {
                        // A bounded read can consume MAX+1 bytes before proving
                        // that a hostile file is oversized. Charge that worst
                        // case even though no Vec is returned, otherwise many
                        // oversized candidates bypass the aggregate work cap.
                        if let Err(budget_error) = charge_manifest_work(
                            &mut manifest_work_bytes,
                            MAX_SKILL_MANIFEST_BYTES.saturating_add(1),
                            max_manifest_work_bytes,
                            skills_dir,
                        ) {
                            load_budget_failed = true;
                            return Err(budget_error);
                        }
                        return Err(error).with_context(|| format!("read {}", yaml_path.display()));
                    }
                };
                if let Err(error) = charge_manifest_work(
                    &mut manifest_work_bytes,
                    raw.len(),
                    max_manifest_work_bytes,
                    skills_dir,
                ) {
                    load_budget_failed = true;
                    return Err(error);
                }

                let manifest_sha256 = super::authority::manifest_sha256(&raw);
                let (manifest, raw_yaml) = parse_one(&yaml_path, raw)?;
                super::creator::validate_skill_id(&manifest.id).with_context(|| {
                    format!(
                        "skill manifest id is not canonical at {}",
                        yaml_path.display()
                    )
                })?;
                if manifest.id != dir_name {
                    anyhow::bail!(
                        "skill id mismatch at {}: directory `{dir_name}` contains manifest id `{}`",
                        yaml_path.display(),
                        manifest.id
                    );
                }
                // ARCH-07 — content_hash = SHA-256(yaml || template).
                let content_hash = crate::skills::versioning::skill_content_hash_hex(
                    &raw_yaml,
                    &manifest.system_prompt,
                );
                Ok(Some(LoadedUserSkill {
                    skill: Skill {
                        manifest,
                        path: yaml_path,
                        content_hash,
                    },
                    manifest_sha256,
                }))
            })();

            match loaded {
                Ok(Some(skill)) => out.push(skill),
                Ok(None) => {}
                Err(error) if load_budget_failed => return Err(error),
                Err(error) if mode == UserSkillLoadMode::Quarantine => {
                    tracing::warn!(
                        error = %error,
                        "quarantining invalid installed Skill during authorized runtime reload"
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }
    out.sort_by(|left, right| left.skill.id().cmp(right.skill.id()));
    Ok(out)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SkillPolicyFile {
    skills: SkillPolicy,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct SkillPolicy {
    enabled: HashSet<String>,
    disabled: HashSet<String>,
    enable_all_bundled: bool,
    visibility_overrides: HashMap<String, crate::config::SkillVisibility>,
}

impl SkillPolicy {
    pub(crate) fn from_config(config: &crate::config::SkillsConfig) -> Self {
        Self {
            enabled: config
                .enabled
                .iter()
                .map(|id| id.trim().to_lowercase())
                .filter(|id| !id.is_empty())
                .collect(),
            disabled: config
                .disabled
                .iter()
                .map(|id| id.trim().to_lowercase())
                .filter(|id| !id.is_empty())
                .collect(),
            enable_all_bundled: config.enable_all_bundled,
            visibility_overrides: config
                .visibility_overrides
                .iter()
                .filter_map(|(id, &visibility)| {
                    let id = id.trim().to_lowercase();
                    (!id.is_empty()).then_some((id, visibility))
                })
                .collect(),
        }
    }

    /// Apply installed-Skill policy without granting bundled-only full-auto
    /// trust. A positive allowlist controls effective behavior but never
    /// creates installed authority; runtime admission still requires the
    /// exact authenticated package decision.
    pub(crate) fn apply_to_manifest(&self, manifest: &mut SkillManifest) {
        let id = manifest.id.to_lowercase();
        if self.enabled.contains(&id) {
            manifest.enabled = true;
        }
        if self.disabled.contains(&id) {
            manifest.enabled = false;
        }
        if let Some(&visibility) = self.visibility_overrides.get(&id) {
            manifest.visibility = visibility;
        }
        if manifest.visibility == crate::config::SkillVisibility::Off {
            manifest.enabled = false;
        }
    }

    /// Apply policy to a compile-time bundled Skill. Only this explicit origin
    /// may inherit `enable_all_bundled`.
    pub(crate) fn apply_to_bundled_manifest(&self, manifest: &mut SkillManifest) {
        if self.enable_all_bundled {
            manifest.enabled = true;
        }
        self.apply_to_manifest(manifest);
    }
}

/// Read the skill-specific operator policy adjacent to `<skills_dir>` without
/// coupling the loader to provider credentials or unrelated config sections.
/// Missing `freedom.yaml` is optional; any error after the file exists is
/// propagated so policy cannot silently relax to defaults.
pub(crate) fn load_skill_policy(skills_dir: &Path) -> Result<SkillPolicy> {
    let Some(home) = skills_dir.parent() else {
        return Ok(SkillPolicy::default());
    };
    load_skill_policy_from_config_path(&home.join("freedom.yaml"))
}

/// Load only the Skill policy from the daemon's exact active config path.
/// Background update probes must use this entry point: reconstructing
/// `<home>/freedom.yaml` would let a Custom instance inherit the wrong
/// enabled/disabled decision at the network-egress boundary.
pub(crate) fn load_skill_policy_from_config_path(freedom_path: &Path) -> Result<SkillPolicy> {
    // Recover any interrupted config/credential publication and capture the
    // exact public-policy generation under the canonical transaction boundary.
    // Parse only the skill section afterwards so this loader stays independent
    // of provider credentials and unrelated runtime validation.
    let snapshot = crate::config::snapshot_raw_config_pair(freedom_path)
        .with_context(|| format!("read skill policy from {}", freedom_path.display()))?;
    let Some(body) = snapshot.freedom.as_deref() else {
        return Ok(SkillPolicy::default());
    };
    let body = std::str::from_utf8(body)
        .with_context(|| format!("skill policy is not UTF-8 at {}", freedom_path.display()))?;
    let mut policy = serde_yaml::from_str::<SkillPolicyFile>(body)
        .with_context(|| format!("parse skill policy at {}", freedom_path.display()))?
        .skills;
    policy.enabled = policy
        .enabled
        .into_iter()
        .map(|id| id.trim().to_lowercase())
        .filter(|id| !id.is_empty())
        .collect();
    policy.disabled = policy
        .disabled
        .into_iter()
        .map(|id| id.trim().to_lowercase())
        .filter(|id| !id.is_empty())
        .collect();
    policy.visibility_overrides = policy
        .visibility_overrides
        .into_iter()
        .filter_map(|(id, visibility)| {
            let id = id.trim().to_lowercase();
            (!id.is_empty()).then_some((id, visibility))
        })
        .collect();
    Ok(policy)
}

/// Decode every entry in [`super::bundled::BUNDLED_SKILLS`] into a `Skill`.
/// A bundled YAML that fails to parse is a build error (the bundled tests
/// in `super::bundled` pin every YAML at compile time), so a failure here
/// would only fire on a corrupted compile-time asset. Propagating that error
/// prevents a partially populated built-in registry from reaching callers.
fn parse_bundled_skills() -> Result<HashMap<String, Skill>> {
    let mut out = HashMap::new();
    for (expected_id, yaml_body) in super::bundled::BUNDLED_SKILLS {
        let mut manifest = serde_yaml::from_str::<SkillManifest>(yaml_body)
            .with_context(|| format!("parse bundled skill `{expected_id}`"))?;
        if manifest.id != *expected_id {
            anyhow::bail!(
                "bundled skill id mismatch: table id `{expected_id}` contains manifest id `{}`",
                manifest.id
            );
        }
        super::creator::validate_skill_id(&manifest.id)
            .with_context(|| format!("bundled skill id `{expected_id}` is not canonical"))?;
        manifest.trigger_keywords = manifest
            .trigger_keywords
            .into_iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        // ARCH-07 — bundled skill content_hash uses the
        // already-in-memory yaml body (no re-read needed).
        let content_hash =
            crate::skills::versioning::skill_content_hash_hex(yaml_body, &manifest.system_prompt);
        out.insert(
            manifest.id.clone(),
            Skill::from_trusted_bundled(
                manifest,
                PathBuf::from(format!("<bundled>/{expected_id}/skill.yaml")),
                content_hash,
            ),
        );
    }
    Ok(out)
}

/// Returns the parsed manifest AND the raw yaml body. The body is
/// needed by [`load_all`] to compute the ARCH-07 `content_hash =
/// SHA-256(yaml || template)` at load time.
fn parse_one(yaml_path: &Path, body: Vec<u8>) -> Result<(SkillManifest, String)> {
    let body = String::from_utf8(body)
        .with_context(|| format!("skill manifest is not UTF-8 at {}", yaml_path.display()))?;
    let mut manifest: SkillManifest = serde_yaml::from_str(&body)
        .with_context(|| format!("parse YAML at {}", yaml_path.display()))?;
    if manifest.id.is_empty() {
        anyhow::bail!("skill id must not be empty: {}", yaml_path.display());
    }
    if manifest.description.trim().is_empty() {
        anyhow::bail!(
            "skill description must not be empty: {}",
            yaml_path.display()
        );
    }
    // Normalise trigger keywords: lowercase + trim, drop empties.
    manifest.trigger_keywords = manifest
        .trigger_keywords
        .into_iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    Ok((manifest, body))
}

fn error_is_not_found(error: &anyhow::Error) -> bool {
    error
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs::{create_dir_all, write};

    #[cfg(unix)]
    fn try_symlink_dir(source: &Path, target: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(source, target)
    }

    #[cfg(windows)]
    fn try_symlink_dir(source: &Path, target: &Path) -> std::io::Result<()> {
        match std::os::windows::fs::symlink_dir(source, target) {
            Ok(()) => Ok(()),
            Err(_) => {
                let status = std::process::Command::new("cmd.exe")
                    .args(["/D", "/C", "mklink", "/J"])
                    .arg(target)
                    .arg(source)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()?;
                if status.success() {
                    Ok(())
                } else {
                    Err(std::io::Error::other(format!(
                        "mklink /J failed with {status}"
                    )))
                }
            }
        }
    }

    async fn write_manifest(dir: &Path, id: &str, body: &str) {
        let sd = dir.join(id);
        create_dir_all(&sd).await.unwrap();
        write(sd.join("skill.yaml"), body).await.unwrap();
    }

    fn install_test_wal_key(home: &Path) {
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

    fn record_test_install_incarnation(home: &Path, id: &str) {
        let current = super::super::installer::inspect_current_install(&home.join("skills"), id)
            .unwrap()
            .expect("installed Skill fixture exists");
        super::super::mutation_lifecycle::record_committed_install_incarnation_for_test(
            home,
            id,
            &current.generation_sha256,
            super::super::installer::SkillMutationOrigin::CliInstall,
        )
        .unwrap();
    }

    fn test_reload_controller(home: &Path) -> crate::config::reload::ReloadController {
        let config = crate::config::FreedomConfig::default();
        let config_path = home.join("freedom.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        crate::config::reload::ReloadController::new(config, config_path)
    }

    fn activate_test_skill(
        home: &Path,
        id: &str,
        reload: &crate::config::reload::ReloadController,
    ) {
        let decision = super::super::authority::SkillAuthorityDecision::new(
            super::super::authority::SkillAuthorityDecisionSource::OperatorCli,
            super::super::authority::SkillAuthorityState::Active,
            None,
        )
        .unwrap();
        super::super::authority::publish_installed_authority_decision(home, id, reload, decision)
            .unwrap();
    }

    #[tokio::test]
    async fn empty_dir_returns_only_bundled_skills() {
        // R3 P0: a fresh operator boot with no user-installed skills
        // must still light up the bundled library. Pre-fix this
        // returned an empty Vec.
        let dir = tempdir().unwrap();
        let skills = load_all(dir.path()).await.unwrap();
        assert_eq!(
            skills.len(),
            super::super::bundled::BUNDLED_SKILLS.len(),
            "fresh-install must surface every bundled skill"
        );
        // Pin one specific bundled id so a future drift surfaces
        // (verification_before_completion has shipped since 2026-05-14).
        assert!(
            skills
                .iter()
                .any(|s| s.manifest.id == "verification_before_completion"),
            "verification_before_completion must be in the bundled set"
        );
    }

    #[tokio::test]
    async fn missing_dir_returns_only_bundled_skills() {
        // Same contract as empty_dir, but the user dir doesn't exist
        // at all (most-fresh-install state).
        let dir = tempdir().unwrap();
        let nope = dir.path().join("does-not-exist");
        let skills = load_all(&nope).await.unwrap();
        assert_eq!(skills.len(), super::super::bundled::BUNDLED_SKILLS.len());
    }

    #[tokio::test]
    async fn qm_21_ported_superpowers_skills_all_parse_clean() {
        // QM-21 (2026-05-22 Session 20): the 5 shipped P1 skill YAMLs
        // in SRC/neothd/assets/skills/ must round-trip the loader
        // without warning. A typo'd YAML field (e.g. wrong indentation
        // on system_prompt:) would silently drop the skill at runtime
        // because parse_one logs warn + continues. This smoke test
        // makes such a regression surface at build time instead.
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source_skills_dir = manifest_dir.join("assets").join("skills");
        if !source_skills_dir.exists() {
            // Some CI shapes (cargo publish --dry-run, source-only
            // builds) may not carry the assets dir. Skip gracefully.
            return;
        }
        // Never point the runtime loader at the immutable source tree. The
        // loader intentionally takes skill/config transaction locks; doing so
        // under `assets/` polluted release checkouts with lock artifacts.
        let fixture = tempdir().unwrap();
        let skills_dir = fixture.path().join("skills");
        create_dir_all(&skills_dir).await.unwrap();
        for entry in std::fs::read_dir(&source_skills_dir).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_type().unwrap().is_dir() {
                continue;
            }
            let source_manifest = entry.path().join("skill.yaml");
            if !source_manifest.is_file() {
                continue;
            }
            let target_dir = skills_dir.join(entry.file_name());
            create_dir_all(&target_dir).await.unwrap();
            std::fs::copy(source_manifest, target_dir.join("skill.yaml")).unwrap();
        }
        let skills = load_all(&skills_dir).await.unwrap();
        let expected = [
            // QM-21 (superpowers P1) — 6 skills
            "receiving_code_review",
            "requesting_code_review",
            "systematic_debugging",
            "test_driven_development",
            "verification_before_completion",
            "writing_skills",
            // QM-22 batch A (mattpocock engineering, 4 skills)
            "diagnose",
            "grill_with_docs",
            "triage",
            "zoom_out",
            // QM-22 batch B (mattpocock engineering, 5 skills)
            "improve_codebase_architecture",
            "to_prd",
            "to_issues",
            "prototype",
            "grill_me",
            // QM-24 (superpowers P4 skills, 6 of 8 — using-superpowers
            // + subagent-driven-development intentionally skipped per
            // QUELLEN audit overlap analysis)
            "brainstorming",
            "writing_plans",
            "executing_plans",
            "dispatching_parallel_agents",
            "using_git_worktrees",
            "finishing_a_development_branch",
            // QM-23 (academic-research-skills, 15 modes in one skill)
            "academic_research",
            // ARCH-03 / QU-06 — three-layer context conductor
            "conductor",
            // GOLD-ADAPT-PT-06/07 — ponytail lazy-dev + over-engineering audit
            "lazy_dev",
            "lazy_review",
            // GOLD-ADAPT-JV-SEC-REST (2026-07-03) — 4 Jarvis security skills
            "nmap_recon",
            "ops_network",
            "pentagi",
            "security_audit",
        ];
        for id in expected {
            assert!(
                skills.iter().any(|s| s.id() == id),
                "QM-21: expected shipped skill `{id}` to parse cleanly; got: {:?}",
                skills.iter().map(|s| s.id()).collect::<Vec<_>>(),
            );
        }
        // Every skill must carry trigger_keywords (a manifest with an
        // empty list is a router miss waiting to happen) + a non-empty
        // system_prompt (the whole point of the skill).
        // Exception: persona-mode skills (e.g. `loyal_buddy`) are hard-wired
        // via PersonaMode, not the keyword router — their trigger_keywords are
        // intentionally empty so the router never picks them up accidentally.
        const PERSONA_MODE_SKILLS: &[&str] = &["loyal_buddy"];
        for s in &skills {
            if !PERSONA_MODE_SKILLS.contains(&s.id()) {
                assert!(
                    !s.trigger_keywords().is_empty(),
                    "skill `{}` has no trigger_keywords",
                    s.id()
                );
            }
            assert!(
                !s.manifest.system_prompt.trim().is_empty(),
                "skill `{}` has empty system_prompt",
                s.id()
            );
        }
    }

    #[tokio::test]
    async fn loads_well_formed_manifest() {
        let dir = tempdir().unwrap();
        write_manifest(
            dir.path(),
            "morning-news",
            r#"
id: morning-news
description: Fetch + summarise today's headlines.
trigger_keywords: [news, briefing, headlines]
system_prompt: |
  You are a news briefing agent.
tool_allowlist: [fetch, channel-send]
"#,
        )
        .await;
        let skills = load_all(dir.path()).await.unwrap();
        // Bundled set + 1 new user skill.
        assert_eq!(
            skills.len(),
            super::super::bundled::BUNDLED_SKILLS.len() + 1
        );
        let s = skills
            .iter()
            .find(|s| s.id() == "morning-news")
            .expect("user skill morning-news must load");
        assert_eq!(s.trigger_keywords().len(), 3);
        assert_eq!(s.manifest.tool_allowlist, vec!["fetch", "channel-send"]);
        assert!(s.is_enabled());
    }

    #[tokio::test]
    async fn user_skill_overrides_bundled_with_same_id() {
        // R3 P0 contract: operator who drops a custom
        // ~/.neoth/skills/verification_before_completion/skill.yaml
        // sees their version win over the bundled default.
        let dir = tempdir().unwrap();
        write_manifest(
            dir.path(),
            "verification_before_completion",
            r#"
id: verification_before_completion
description: OPERATOR OVERRIDE — looser verification gate for spike work.
trigger_keywords: [done, finished]
system_prompt: |
  You are the operator's customised verification gate.
"#,
        )
        .await;
        let skills = load_all(dir.path()).await.unwrap();
        let s = skills
            .iter()
            .find(|s| s.id() == "verification_before_completion")
            .unwrap();
        assert!(
            s.manifest.description.contains("OPERATOR OVERRIDE"),
            "user-installed skill must override the bundled default"
        );
        // The override REPLACES the bundled entry — count stays at
        // the bundled total, not bundled + 1.
        assert_eq!(skills.len(), super::super::bundled::BUNDLED_SKILLS.len());
    }

    #[tokio::test]
    async fn id_mismatch_rejects_the_registry_load() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "expected-id", "id: wrong-id\ndescription: x\n").await;
        let error = load_all(dir.path()).await.unwrap_err();
        assert!(format!("{error:#}").contains("skill id mismatch"));
        assert!(format!("{error:#}").contains("expected-id"));
    }

    #[tokio::test]
    async fn authorized_quarantine_never_swallows_root_entry_budget_exhaustion() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "alpha", "id: alpha\ndescription: alpha\n").await;
        write_manifest(dir.path(), "beta", "id: beta\ndescription: beta\n").await;

        let error =
            load_user_skills_with_limits(dir.path(), UserSkillLoadMode::Quarantine, 1, usize::MAX)
                .unwrap_err();
        assert!(
            format!("{error:#}").contains("1-entry runtime limit"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn authorized_quarantine_never_swallows_manifest_work_budget_exhaustion() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "alpha", "id: alpha\ndescription: alpha\n").await;

        let error = load_user_skills_with_limits(dir.path(), UserSkillLoadMode::Quarantine, 1, 1)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("1-byte runtime work limit"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn oversized_read_errors_are_charged_to_authorized_work_budget() {
        let dir = tempdir().unwrap();
        let skill_dir = dir.path().join("alpha");
        create_dir_all(&skill_dir).await.unwrap();
        write(
            skill_dir.join("skill.yaml"),
            vec![b'x'; MAX_SKILL_MANIFEST_BYTES + 1],
        )
        .await
        .unwrap();

        let error = load_user_skills_with_limits(
            dir.path(),
            UserSkillLoadMode::Quarantine,
            1,
            MAX_SKILL_MANIFEST_BYTES,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("runtime work limit"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn aggregate_authority_overflow_discards_partially_admitted_snapshot() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "alpha",
            "id: alpha\n\
             description: authorized first candidate\n\
             system_prompt: AUTHORIZED-ALPHA\n\
             trigger_keywords: [alpha]\n",
        )
        .await;
        write_manifest(
            &skills_dir,
            "beta",
            "id: beta\n\
             description: rejected second candidate\n\
             system_prompt: INACTIVE-BETA\n\
             trigger_keywords: [beta]\n",
        )
        .await;
        install_test_wal_key(home.path());
        record_test_install_incarnation(home.path(), "alpha");
        record_test_install_incarnation(home.path(), "beta");
        let reload = test_reload_controller(home.path());
        activate_test_skill(home.path(), "alpha", &reload);

        // Candidate order is canonical by id. Alpha consumes one package
        // entry plus its one authority-record entry and is admitted. Beta's
        // first package entry then crosses the shared limit. The loader must
        // discard that partial map and return the complete bundled-only layer.
        let snapshot =
            load_authorized_with_budget_override(&skills_dir, &reload, Some((2, u64::MAX)))
                .await
                .unwrap();

        assert_eq!(
            snapshot.skills.len(),
            super::super::bundled::BUNDLED_SKILLS.len()
        );
        assert!(
            snapshot.skills.iter().all(RuntimeSkill::is_trusted_bundled),
            "an aggregate traversal failure must discard every installed candidate"
        );
        assert!(
            snapshot
                .skills
                .iter()
                .all(|skill| skill.id() != "alpha" && skill.id() != "beta"),
            "no partially admitted installed Skill may survive aggregate overflow"
        );
        assert_eq!(
            snapshot.accepted_config_epoch,
            reload.accepted_snapshot().epoch()
        );
    }

    #[tokio::test]
    async fn physical_topic_forget_cannot_destroy_installed_authority_proofs() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "physical-proof";
        write_manifest(
            &skills_dir,
            id,
            "id: physical-proof\n\
             description: physical redaction proof fixture\n\
             system_prompt: AUTHORITY-SURVIVES-PHYSICAL-FORGET\n\
             trigger_keywords: [physical]\n",
        )
        .await;
        install_test_wal_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path());
        activate_test_skill(home.path(), id, &reload);

        let before = load_authorized_from_reload_controller(&skills_dir, &reload)
            .await
            .unwrap();
        assert!(
            before
                .skills
                .iter()
                .any(|skill| skill.id() == id && !skill.is_trusted_bundled())
        );

        let mut protected_refusals = 0usize;
        for entry in std::fs::read_dir(home.path().join("wal")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(OsStr::to_str) != Some("wal") {
                continue;
            }
            match crate::wal::redact::scan_and_redact(
                &path,
                crate::wal::redact::payload_contains_topic(id),
            ) {
                Ok(report) => assert!(
                    report.frames_redacted.is_empty(),
                    "physical forget redacted an unexpected frame in {}",
                    path.display()
                ),
                Err(error)
                    if format!("{error:#}").contains("protected installed-Skill runtime proof") =>
                {
                    protected_refusals += 1;
                }
                Err(error) => panic!(
                    "physical forget returned an unrelated error for {}: {error:#}",
                    path.display()
                ),
            }
        }
        assert!(
            protected_refusals >= 2,
            "both mutation and authority proof segments must reject topic redaction"
        );

        let after = load_authorized_from_reload_controller(&skills_dir, &reload)
            .await
            .unwrap();
        assert!(
            after
                .skills
                .iter()
                .any(|skill| skill.id() == id && !skill.is_trusted_bundled()),
            "authenticated installed authority must remain valid after physical forget refusal"
        );
    }

    #[tokio::test]
    async fn missing_description_rejected() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "broke", "id: broke\ndescription: \"\"\n").await;
        let error = load_all(dir.path()).await.unwrap_err();
        assert!(format!("{error:#}").contains("description must not be empty"));
    }

    #[tokio::test]
    async fn malformed_existing_manifest_rejects_the_registry_load() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "broken", "id: [not-valid\n").await;
        let error = load_all(dir.path()).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("parse YAML"));
        assert!(detail.contains("broken"));
    }

    #[tokio::test]
    async fn diagnostic_inventory_preserves_healthy_rows_and_surfaces_broken_rows() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "healthy-user",
            "id: healthy-user\ndescription: Healthy user skill\ntrigger_keywords: [healthy]\n",
        )
        .await;
        create_dir_all(skills_dir.join("broken-user"))
            .await
            .unwrap();

        let runtime_error = load_all(&skills_dir)
            .await
            .expect_err("runtime routing must remain fail-closed");
        assert!(format!("{runtime_error:#}").contains("no skill.yaml"));

        let rows = diagnostic_inventory(&skills_dir).await.unwrap();
        assert!(rows.iter().any(|row| matches!(
            row,
            SkillInventoryRow::Healthy { manifest, origin: SkillInventoryOrigin::User, .. }
                if manifest.id == "healthy-user"
        )));
        assert!(rows.iter().any(|row| matches!(
            row,
            SkillInventoryRow::Broken { id, error, .. }
                if id == "broken-user" && error.contains("no skill.yaml")
        )));
        assert!(rows.iter().any(|row| matches!(
            row,
            SkillInventoryRow::Healthy {
                origin: SkillInventoryOrigin::Bundled,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn diagnostic_inventory_applies_operator_policy_to_healthy_rows() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "policy-user",
            "id: policy-user\ndescription: Policy user skill\nenabled: true\n",
        )
        .await;
        write(
            home.path().join("freedom.yaml"),
            "skills:\n  disabled: [policy-user]\n",
        )
        .await
        .unwrap();

        let rows = diagnostic_inventory(&skills_dir).await.unwrap();
        let row = rows
            .iter()
            .find(|row| row.id() == "policy-user")
            .expect("policy row");
        assert!(matches!(
            row,
            SkillInventoryRow::Healthy { manifest, .. } if !manifest.enabled
        ));
    }

    #[tokio::test]
    async fn diagnostic_inventory_reports_authority_and_bundled_fallback_truth() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "standalone-candidate",
            "id: standalone-candidate\n\
             description: manifest enablement is not runtime authority\n\
             enabled: true\n",
        )
        .await;
        write_manifest(
            &skills_dir,
            "systematic_debugging",
            "id: systematic_debugging\n\
             description: installed same-id candidate without authority\n\
             enabled: true\n",
        )
        .await;

        let rows = diagnostic_inventory(&skills_dir).await.unwrap();
        let standalone = rows
            .iter()
            .find(|row| row.id() == "standalone-candidate")
            .unwrap();
        assert!(matches!(
            standalone,
            SkillInventoryRow::Healthy {
                runtime_state: SkillInventoryRuntimeState::Disabled,
                ..
            }
        ));
        let override_row = rows
            .iter()
            .find(|row| row.id() == "systematic_debugging")
            .unwrap();
        assert!(matches!(
            override_row,
            SkillInventoryRow::Healthy {
                origin: SkillInventoryOrigin::User,
                runtime_state: SkillInventoryRuntimeState::BundledFallbackActive,
                ..
            }
        ));

        install_test_wal_key(home.path());
        record_test_install_incarnation(home.path(), "standalone-candidate");
        let reload = test_reload_controller(home.path());
        activate_test_skill(home.path(), "standalone-candidate", &reload);
        let rows = diagnostic_inventory(&skills_dir).await.unwrap();
        assert!(matches!(
            rows.iter()
                .find(|row| row.id() == "standalone-candidate")
                .unwrap(),
            SkillInventoryRow::Healthy {
                runtime_state: SkillInventoryRuntimeState::InstalledActive,
                ..
            }
        ));
    }

    #[test]
    fn diagnostic_runtime_truth_rejects_identical_bytes_from_a_new_incarnation() {
        let generation = "a".repeat(64);
        let prior_receipt = "b".repeat(64);
        let replacement_receipt = "c".repeat(64);
        let evidence = InventoryRuntimeEvidence {
            state: SkillInventoryRuntimeState::InstalledActive,
            package_generation_sha256: Some(generation.clone()),
            install_incarnation: Some(7),
            install_terminal_receipt_sha256: Some(prior_receipt.clone()),
        };

        assert_eq!(
            installed_candidate_runtime_state(
                Some(&evidence),
                Some(&generation),
                Some(7),
                Some(&prior_receipt),
            ),
            SkillInventoryRuntimeState::InstalledActive
        );
        assert_eq!(
            installed_candidate_runtime_state(
                Some(&evidence),
                Some(&generation),
                Some(8),
                Some(&replacement_receipt),
            ),
            SkillInventoryRuntimeState::Disabled,
            "an identical-byte reinstall is a new authority incarnation"
        );
    }

    #[tokio::test]
    async fn exact_custom_config_filename_owns_skill_policy() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        create_dir_all(&skills_dir).await.unwrap();
        write(
            home.path().join("freedom.yaml"),
            "skills:\n  disabled: [systematic_debugging]\n",
        )
        .await
        .unwrap();
        let custom_config = home.path().join("operator-instance.yaml");
        write(&custom_config, "skills: {}\n").await.unwrap();

        let adjacent = load_all(&skills_dir).await.unwrap();
        assert!(
            !adjacent
                .iter()
                .find(|skill| skill.id() == "systematic_debugging")
                .unwrap()
                .is_enabled(),
            "the compatibility loader should still use adjacent freedom.yaml"
        );

        let exact = load_all_from_config_path(&skills_dir, &custom_config)
            .await
            .unwrap();
        assert!(
            exact
                .iter()
                .find(|skill| skill.id() == "systematic_debugging")
                .unwrap()
                .is_enabled(),
            "a custom config filename must not inherit adjacent freedom.yaml policy"
        );

        let exact_config = crate::config::FreedomConfig::load_from_path(&custom_config).unwrap();
        let inventory = diagnostic_inventory_for_accepted_config(
            &skills_dir,
            exact_config,
            custom_config.clone(),
        )
        .await
        .unwrap();
        assert!(matches!(
            inventory
                .iter()
                .find(|row| row.id() == "systematic_debugging")
                .unwrap(),
            SkillInventoryRow::Healthy {
                manifest,
                runtime_state: SkillInventoryRuntimeState::TrustedBundledActive,
                ..
            } if manifest.enabled
        ));
    }

    #[tokio::test]
    async fn existing_non_directory_skills_path_is_not_treated_as_missing() {
        let dir = tempdir().unwrap();
        let skills_path = dir.path().join("skills");
        write(&skills_path, "not a directory").await.unwrap();
        let error = load_all(&skills_path).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("reconcile audited Skill mutation"));
        assert!(detail.contains("real directory"));
    }

    #[tokio::test]
    async fn existing_skill_manifest_directory_is_not_treated_as_missing() {
        let dir = tempdir().unwrap();
        let manifest_path = dir.path().join("broken").join("skill.yaml");
        create_dir_all(&manifest_path).await.unwrap();
        let error = load_all(dir.path()).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("read"));
        assert!(detail.contains("skill.yaml"));
    }

    #[tokio::test]
    async fn non_hidden_skill_directory_without_manifest_rejects_runtime_load() {
        let dir = tempdir().unwrap();
        create_dir_all(dir.path().join("partial-install"))
            .await
            .unwrap();

        let error = load_all(dir.path()).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("no skill.yaml"));
        assert!(detail.contains("partial-install"));
    }

    #[tokio::test]
    async fn non_hidden_file_entry_rejects_runtime_load_and_remains_diagnosable() {
        let dir = tempdir().unwrap();
        write(dir.path().join("broken-file"), "not a skill directory")
            .await
            .unwrap();

        let error = load_all(dir.path()).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("must be a real directory"));
        assert!(detail.contains("broken-file"));

        let rows = diagnostic_inventory(dir.path()).await.unwrap();
        assert!(rows.iter().any(|row| matches!(
            row,
            SkillInventoryRow::Broken { id, error, .. }
                if id == "broken-file" && error.contains("not a directory")
        )));
    }

    #[tokio::test]
    async fn linked_skill_directory_rejects_runtime_load_without_reading_outside() {
        let skills = tempdir().unwrap();
        let outside = tempdir().unwrap();
        write_manifest(
            outside.path(),
            "outside",
            "id: outside\ndescription: must not load\nsystem_prompt: no\n",
        )
        .await;
        let linked_source = outside.path().join("outside");
        let linked = skills.path().join("outside");
        try_symlink_dir(&linked_source, &linked).expect("create directory link fixture");

        let error = load_all(skills.path()).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("real directory") || detail.contains("symlink"));
        assert!(detail.contains("outside"));
    }

    #[tokio::test]
    async fn linked_skills_root_rejects_runtime_load() {
        let parent = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let linked = parent.path().join("skills");
        try_symlink_dir(outside.path(), &linked).expect("create linked skills root fixture");

        let error = load_all(&linked).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("reconcile audited Skill mutation"));
        assert!(detail.contains("real directory") || detail.contains("symlink"));
    }

    #[tokio::test]
    async fn oversized_skill_manifest_rejects_runtime_load() {
        let skills = tempdir().unwrap();
        let skill = skills.path().join("oversized");
        create_dir_all(&skill).await.unwrap();
        write(
            skill.join("skill.yaml"),
            vec![b'x'; MAX_SKILL_MANIFEST_BYTES + 1],
        )
        .await
        .unwrap();

        let error = load_all(skills.path()).await.unwrap_err();
        assert!(format!("{error:#}").contains("exceeds the"));
    }

    #[tokio::test]
    async fn malformed_existing_freedom_yaml_does_not_relax_skill_policy() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write(home.path().join("freedom.yaml"), "skills: [broken\n")
            .await
            .unwrap();
        let error = load_all(&skills_dir).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("parse skill policy"));
        assert!(detail.contains("freedom.yaml"));
    }

    #[tokio::test]
    async fn existing_unreadable_freedom_yaml_does_not_relax_skill_policy() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        create_dir_all(home.path().join("freedom.yaml"))
            .await
            .unwrap();
        let error = load_all(&skills_dir).await.unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("read skill policy"));
        assert!(detail.contains("freedom.yaml"));
    }

    #[tokio::test]
    async fn keywords_are_lowercased_and_trimmed() {
        let dir = tempdir().unwrap();
        write_manifest(
            dir.path(),
            "x",
            "id: x\ndescription: y\ntrigger_keywords: [\"  NEWS  \", \"\", BriEFing]\nsystem_prompt: ok\n",
        )
        .await;
        let skills = load_all(dir.path()).await.unwrap();
        let s = skills
            .iter()
            .find(|s| s.id() == "x")
            .expect("user skill loaded");
        assert_eq!(s.trigger_keywords(), &["news", "briefing"]);
    }

    #[tokio::test]
    async fn dot_prefixed_dirs_are_ignored() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), ".hidden", "id: .hidden\ndescription: x\n").await;
        let skills = load_all(dir.path()).await.unwrap();
        // No user entry surfaces from a dotfile dir; bundled-only.
        assert!(!skills.iter().any(|s| s.id() == ".hidden"));
        assert_eq!(skills.len(), super::super::bundled::BUNDLED_SKILLS.len());
    }

    #[tokio::test]
    async fn sorts_skills_by_id() {
        let dir = tempdir().unwrap();
        write_manifest(
            dir.path(),
            "zeta-user-test",
            "id: zeta-user-test\ndescription: z\nsystem_prompt: ok\n",
        )
        .await;
        write_manifest(
            dir.path(),
            "aaa-user-test",
            "id: aaa-user-test\ndescription: a\nsystem_prompt: ok\n",
        )
        .await;
        let skills = load_all(dir.path()).await.unwrap();
        // Bundled skills mix in; pin that aaa- comes before zeta- and
        // both surface in the merged set.
        let aaa_idx = skills
            .iter()
            .position(|s| s.id() == "aaa-user-test")
            .unwrap();
        let zeta_idx = skills
            .iter()
            .position(|s| s.id() == "zeta-user-test")
            .unwrap();
        assert!(aaa_idx < zeta_idx, "skills must be sorted by id");
    }

    #[tokio::test]
    async fn bundled_path_marker_is_distinguishable_from_user_path() {
        // The Skill::path field on bundled skills uses a `<bundled>/`
        // sentinel so downstream callers (e.g. `neoth skills list`) can
        // surface "bundled" vs "installed at <path>" honestly.
        let dir = tempdir().unwrap();
        let skills = load_all(dir.path()).await.unwrap();
        for s in &skills {
            let path_str = s.path.to_string_lossy();
            assert!(
                path_str.starts_with("<bundled>/"),
                "bundled skill `{}` must carry the <bundled>/ marker path; got {}",
                s.id(),
                path_str
            );
        }
    }

    #[tokio::test]
    async fn freedom_yaml_disabled_blocklist_turns_off_bundled_skill() {
        // GOLD-HON-11: a security-research register named in
        // freedom.yaml::skills.disabled loads but is marked disabled
        // (case-insensitive), while its siblings stay enabled.
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  disabled:\n    - RASKAL\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let raskal = skills
            .iter()
            .find(|s| s.id() == "raskal")
            .expect("raskal is bundled");
        let lowkey = skills
            .iter()
            .find(|s| s.id() == "lowkey_base")
            .expect("lowkey_base is bundled");
        assert!(
            !raskal.is_enabled(),
            "raskal must be disabled via freedom.yaml::skills.disabled"
        );
        assert!(
            lowkey.is_enabled(),
            "lowkey_base (not in the blocklist) must stay enabled"
        );
    }

    #[tokio::test]
    async fn freedom_yaml_enabled_allowlist_force_ons_a_ships_disabled_skill() {
        // GOLD-ADOPT-14: a skill shipping `enabled: false` is force-ON'd via
        // freedom.yaml::skills.enabled (the pm-* skills' activation path).
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "pm-off-skill",
            "id: pm-off-skill\ndescription: a ships-disabled skill\nversion: \"1.0.0\"\nsystem_prompt: hi\ntrigger_keywords: [\"x\"]\nenabled: false\n",
        )
        .await;
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  enabled:\n    - PM-OFF-SKILL\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let pm = skills
            .iter()
            .find(|s| s.id() == "pm-off-skill")
            .expect("pm-off-skill loaded");
        assert!(
            pm.is_enabled(),
            "pm-off-skill must be force-enabled via skills.enabled (case-insensitive)"
        );
    }

    #[tokio::test]
    async fn enable_all_bundled_force_ons_pm_skill_but_blocklist_still_wins() {
        // Full-auto mode (`skills.enable_all_bundled: true`) force-enables EVERY
        // bundled skill — including a `pm-*` skill that ships `enabled: false` —
        // yet a skill in `skills.disabled` stays OFF (the HON-11 guarantee must
        // survive full-auto: an operator force-OFF is never silently re-enabled).
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  enable_all_bundled: true\n  disabled:\n    - raskal\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let pm = skills
            .iter()
            .find(|s| s.id() == "pm-create-prd")
            .expect("pm-create-prd is bundled");
        assert!(
            pm.is_enabled(),
            "a ships-disabled pm-* skill must be force-enabled in full-auto mode"
        );
        let raskal = skills
            .iter()
            .find(|s| s.id() == "raskal")
            .expect("raskal is bundled");
        assert!(
            !raskal.is_enabled(),
            "the disabled blocklist must beat enable_all_bundled (no HON-11 bypass)"
        );
    }

    #[tokio::test]
    async fn enable_all_bundled_absent_keeps_pm_skill_disabled() {
        // Gated mode (default / key absent) leaves a ships-disabled pm-* skill
        // OFF — the curated set the keyword router stays clean against.
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        std::fs::write(home.path().join("freedom.yaml"), "skills: {}\n").unwrap();
        let skills = load_all(&skills_dir).await.unwrap();
        let pm = skills
            .iter()
            .find(|s| s.id() == "pm-create-prd")
            .expect("pm-create-prd is bundled");
        assert!(
            !pm.is_enabled(),
            "without enable_all_bundled a pm-* skill must stay disabled (gated default)"
        );
    }

    #[tokio::test]
    async fn enable_all_bundled_never_enables_an_installed_candidate() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "external-disabled",
            "id: external-disabled\n\
             description: installed authority fixture\n\
             system_prompt: never route without authority\n\
             trigger_keywords: [external]\n\
             enabled: false\n",
        )
        .await;
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  enable_all_bundled: true\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let external = skills
            .iter()
            .find(|skill| skill.id() == "external-disabled")
            .expect("raw inventory retains installed candidate");
        assert!(
            !external.is_enabled(),
            "bundled-only full-auto policy must not grant installed behavior"
        );
    }

    #[tokio::test]
    async fn freedom_yaml_disabled_beats_enabled_no_hon11_bypass() {
        // GOLD-ADOPT-14 security property: a skill in BOTH lists stays OFF —
        // a freedom.yaml write can never silently re-enable a force-disabled
        // security register (the HON-11 guarantee must hold).
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  enabled:\n    - raskal\n  disabled:\n    - raskal\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let raskal = skills
            .iter()
            .find(|s| s.id() == "raskal")
            .expect("raskal is bundled");
        assert!(
            !raskal.is_enabled(),
            "disabled must win over enabled — no HON-11 bypass"
        );
    }

    #[tokio::test]
    async fn no_freedom_yaml_leaves_security_skills_enabled() {
        // The honesty premise: these registers ship ENABLED by default.
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let skills = load_all(&skills_dir).await.unwrap();
        for id in ["lowkey_base", "raskal", "archon"] {
            let s = skills
                .iter()
                .find(|s| s.id() == id)
                .unwrap_or_else(|| panic!("{id} is bundled"));
            assert!(s.is_enabled(), "{id} must be enabled by default");
        }
    }

    // ── GOLD-CCPARITY-SKILLVIS-01 tests ───────────────────────────────────────

    /// Test 1: `visibility_overrides: { raskal: off }` disables the skill at
    /// load time (same effect as `disabled` blocklist), leaving siblings active.
    #[tokio::test]
    async fn ccparity_skillvis_off_via_freedom_yaml_disables_skill() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  visibility_overrides:\n    raskal: off\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let raskal = skills
            .iter()
            .find(|s| s.id() == "raskal")
            .expect("raskal is bundled");
        let lowkey = skills
            .iter()
            .find(|s| s.id() == "lowkey_base")
            .expect("lowkey_base is bundled");

        assert!(
            !raskal.is_enabled(),
            "raskal with visibility=off must be disabled at load time"
        );
        assert!(
            lowkey.is_enabled(),
            "lowkey_base (not overridden) must stay enabled"
        );
    }

    /// Test 2: `visibility_overrides: { my-skill: name_only }` stamps the
    /// `NameOnly` variant into the manifest without disabling the skill.
    #[tokio::test]
    async fn ccparity_skillvis_name_only_stamped_on_manifest() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "my-skill",
            "id: my-skill\ndescription: test skill\nversion: \"1.0.0\"\nsystem_prompt: hi\ntrigger_keywords: [\"x\"]\n",
        )
        .await;
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  visibility_overrides:\n    my-skill: name_only\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let s = skills
            .iter()
            .find(|s| s.id() == "my-skill")
            .expect("my-skill loaded");

        assert!(
            s.is_enabled(),
            "name_only skill must stay enabled (routing-time gate, not load-time disable)"
        );
        assert_eq!(
            s.visibility(),
            crate::config::SkillVisibility::NameOnly,
            "manifest must carry the stamped NameOnly override"
        );
    }

    /// Test 3: A skill with no `visibility:` in its YAML defaults to `On`.
    #[tokio::test]
    async fn ccparity_skillvis_manifest_default_is_on() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "plain-skill",
            "id: plain-skill\ndescription: no visibility field\nversion: \"1.0.0\"\nsystem_prompt: go\ntrigger_keywords: [\"go\"]\n",
        )
        .await;

        let skills = load_all(&skills_dir).await.unwrap();
        let s = skills
            .iter()
            .find(|s| s.id() == "plain-skill")
            .expect("plain-skill loaded");

        assert_eq!(
            s.visibility(),
            crate::config::SkillVisibility::On,
            "skill without explicit visibility must default to On"
        );
    }

    /// Test 4: `user_invocable_only` visibility is stamped correctly.
    #[tokio::test]
    async fn ccparity_skillvis_user_invocable_only_stamped() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_manifest(
            &skills_dir,
            "manual-skill",
            "id: manual-skill\ndescription: manual only\nversion: \"1.0.0\"\nsystem_prompt: manual\ntrigger_keywords: [\"manual\"]\n",
        )
        .await;
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  visibility_overrides:\n    manual-skill: user_invocable_only\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let s = skills
            .iter()
            .find(|s| s.id() == "manual-skill")
            .expect("manual-skill loaded");

        assert!(
            s.is_enabled(),
            "user_invocable_only skill must stay enabled"
        );
        assert_eq!(
            s.visibility(),
            crate::config::SkillVisibility::UserInvocableOnly,
            "manifest must carry the stamped UserInvocableOnly override"
        );
    }

    /// Test 5: `visibility_overrides` key is case-insensitive (matches the
    /// `disabled` blocklist contract).
    #[tokio::test]
    async fn ccparity_skillvis_override_is_case_insensitive() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  visibility_overrides:\n    RASKAL: off\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir).await.unwrap();
        let raskal = skills
            .iter()
            .find(|s| s.id() == "raskal")
            .expect("raskal is bundled");

        assert!(
            !raskal.is_enabled(),
            "visibility=off key match must be case-insensitive (RASKAL → raskal)"
        );
    }

    /// External review PR5-005: `validate_skill_id` was tightened to
    /// lowercase-only AFTER installs already existed, and the runtime loader
    /// propagated that failure — one legacy `MySkill/` directory then failed the
    /// WHOLE registry build, taking `neoth serve` and `neoth chat` down with it.
    /// A directory that cannot be a skill id is skipped, never loaded, and the
    /// healthy skills still load.
    #[tokio::test]
    async fn noncanonical_user_skill_directory_is_skipped_not_fatal() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        std::fs::create_dir_all(skills_dir.join("MySkill")).unwrap();
        std::fs::write(
            skills_dir.join("MySkill").join("skill.yaml"),
            "id: myskill\ndescription: legacy\ntrigger_keywords: [legacy]\n\
             system_prompt: legacy\n",
        )
        .unwrap();
        std::fs::create_dir_all(skills_dir.join("good_one")).unwrap();
        std::fs::write(
            skills_dir.join("good_one").join("skill.yaml"),
            "id: good_one\ndescription: fine\ntrigger_keywords: [fine]\n\
             system_prompt: fine\n",
        )
        .unwrap();

        let skills = load_all(&skills_dir)
            .await
            .expect("one non-canonical directory must not fail the whole load");
        assert!(
            skills.iter().any(|s| s.id() == "good_one"),
            "the healthy user skill must still load"
        );
        assert!(
            !skills.iter().any(|s| s.id() == "myskill"),
            "the non-canonical directory must NOT be loaded"
        );
    }
}
