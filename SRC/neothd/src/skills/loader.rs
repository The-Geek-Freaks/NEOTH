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
//! 2. **User**: anything under `~/.neoth/skills/<id>/skill.yaml` LAYERS on
//!    top. Same id as a bundled skill → user wins. New id → adds to the set.
//!    The user file's full directory becomes the canonical path (so
//!    multi-file skills referencing sibling assets work as expected).
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

use super::schema::{Skill, SkillManifest};
use super::store::{open_bound_directory, open_real_child_dir, read_regular_file_bounded};

const MAX_SKILL_MANIFEST_BYTES: usize = 1024 * 1024;

/// Load every available skill — bundled-in-binary defaults plus
/// user-installed overrides from `<skills_dir>` if it exists.
///
/// Bundled skills always load. User skills override bundled ids
/// (operator's customised version of `systematic_debugging` wins over
/// the shipped default). A missing user dir is a normal fresh-install
/// state; an existing unreadable user dir is an error.
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

async fn load_all_from_policy_source(
    skills_dir: &Path,
    config_path: Option<&Path>,
    accepted_policy: Option<SkillPolicy>,
) -> Result<Vec<Skill>> {
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
    for skill in user_skills {
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

    // Apply manifest defaults and every operator override at one chokepoint.
    // The updater calls the same method before any source probe, preventing
    // routing policy and network-egress policy from drifting apart.
    for skill in by_id.values_mut() {
        policy.apply_to_manifest(&mut skill.manifest);
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
    },
    Broken {
        id: String,
        error: String,
        path: PathBuf,
        repairability: super::installer::SkillRepairability,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillInventoryOrigin {
    Bundled,
    User,
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
    let skills_dir = skills_dir.to_path_buf();
    tokio::task::spawn_blocking(move || diagnostic_inventory_blocking(&skills_dir))
        .await
        .context("skill diagnostic inventory worker failed")?
}

fn diagnostic_inventory_blocking(skills_dir: &Path) -> Result<Vec<SkillInventoryRow>> {
    let policy = load_skill_policy(skills_dir)?;
    let mut rows = std::collections::BTreeMap::<String, SkillInventoryRow>::new();
    for (_, mut skill) in parse_bundled_skills()? {
        policy.apply_to_manifest(&mut skill.manifest);
        rows.insert(
            skill.manifest.id.to_lowercase(),
            SkillInventoryRow::Healthy {
                manifest: Box::new(skill.manifest),
                origin: SkillInventoryOrigin::Bundled,
                path: None,
            },
        );
    }

    for entry in super::installer::list_installed(skills_dir)? {
        let key = entry.dir_name.to_lowercase();
        let repairability = entry
            .repairability
            .unwrap_or(super::installer::SkillRepairability::RemoveOnly);
        match (entry.manifest, entry.error) {
            (Some(mut manifest), None) => {
                policy.apply_to_manifest(&mut manifest);
                rows.insert(
                    key,
                    SkillInventoryRow::Healthy {
                        manifest: Box::new(manifest),
                        origin: SkillInventoryOrigin::User,
                        path: Some(entry.path),
                    },
                );
            }
            (_, error) => {
                rows.insert(
                    key,
                    SkillInventoryRow::Broken {
                        id: entry.dir_name,
                        error: sanitize_inventory_error(
                            error.as_deref().unwrap_or("unknown inventory error"),
                        ),
                        path: entry.path,
                        repairability,
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

fn load_user_skills(skills_dir: &Path) -> Result<Vec<Skill>> {
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
        for entry in entries {
            let entry = entry
                .with_context(|| format!("enumerate skills directory {}", skills_dir.display()))?;
            let name = entry.file_name();
            let path = root.display_path.join(&name);
            if name.as_encoded_bytes().first() == Some(&b'.') {
                continue;
            }
            let dir_name = name.to_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "installed skill directory name is not valid UTF-8: {}",
                    path.display()
                )
            })?;
            super::creator::validate_skill_id(dir_name).with_context(|| {
                format!(
                    "installed skill directory id is not canonical at {}",
                    path.display()
                )
            })?;
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
                    return Err(error).with_context(|| format!("read {}", yaml_path.display()));
                }
            };

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
            out.push(Skill {
                manifest,
                path: yaml_path,
                content_hash,
            });
        }
    }
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
    fn from_config(config: &crate::config::SkillsConfig) -> Self {
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

    /// Apply the canonical effective-state precedence. Full-auto and the
    /// allowlist may enable a skill; the blocklist and `visibility: off` win.
    pub(crate) fn apply_to_manifest(&self, manifest: &mut SkillManifest) {
        let id = manifest.id.to_lowercase();
        if self.enable_all_bundled {
            manifest.enabled = true;
        }
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
            Skill {
                manifest,
                // Bundled skills have no on-disk path; use a
                // marker path so downstream consumers can tell
                // bundled from user-installed.
                path: PathBuf::from(format!("<bundled>/{expected_id}/skill.yaml")),
                content_hash,
            },
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
    }

    #[tokio::test]
    async fn existing_non_directory_skills_path_is_not_treated_as_missing() {
        let dir = tempdir().unwrap();
        let skills_path = dir.path().join("skills");
        write(&skills_path, "not a directory").await.unwrap();
        let error = load_all(&skills_path).await.unwrap_err();
        assert!(format!("{error:#}").contains("read skills directory"));
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
        assert!(detail.contains("read skills directory"));
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
}
