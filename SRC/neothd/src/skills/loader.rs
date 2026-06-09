//! Skill loader — bundled-in-binary defaults + `~/.neoth/skills/<id>/skill.yaml`
//! user overrides. Bad manifests are logged + skipped, never block startup.
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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs;
use tracing::{debug, warn};

use super::schema::{Skill, SkillManifest};

/// Load every available skill — bundled-in-binary defaults plus
/// user-installed overrides from `<skills_dir>` if it exists.
///
/// Bundled skills always load. User skills override bundled ids
/// (operator's customised version of `systematic_debugging` wins over
/// the shipped default). A missing or unreadable user dir is a normal
/// fresh-install state — the loader returns the bundled set without
/// error.
///
/// The output is sorted by id for deterministic ordering downstream
/// (router picks the first keyword match in declaration order; sorting
/// the inputs keeps that order reproducible across processes).
pub async fn load_all(skills_dir: &Path) -> Result<Vec<Skill>> {
    // ── Layer 1: bundled skills (always present) ────────────────────────
    let mut by_id: std::collections::HashMap<String, Skill> = parse_bundled_skills();

    // ── Layer 2: user skills (override by id) ───────────────────────────
    if skills_dir.exists() {
        if let Ok(mut entries) = fs::read_dir(skills_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let dir_name = match path.file_name().and_then(|s| s.to_str()) {
                    Some(n) if !n.starts_with('.') => n.to_string(),
                    _ => continue,
                };
                let yaml_path = path.join("skill.yaml");
                if !yaml_path.exists() {
                    continue;
                }

                match parse_one(&yaml_path).await {
                    Ok((manifest, raw_yaml)) => {
                        if manifest.id != dir_name {
                            warn!(
                                dir = %dir_name,
                                manifest_id = %manifest.id,
                                path = %yaml_path.display(),
                                "skill id mismatch — directory name and `id:` field differ; skipped"
                            );
                            continue;
                        }
                        let overrode = by_id.contains_key(&manifest.id);
                        // ARCH-07 — content_hash = SHA-256(yaml || template).
                        let content_hash = crate::skills::versioning::skill_content_hash_hex(
                            &raw_yaml,
                            &manifest.system_prompt,
                        );
                        debug!(
                            id = %manifest.id,
                            keywords = manifest.trigger_keywords.len(),
                            enabled = manifest.enabled,
                            overrode_bundled = overrode,
                            content_hash = %content_hash,
                            "loaded user skill"
                        );
                        by_id.insert(
                            manifest.id.clone(),
                            Skill {
                                manifest,
                                path: yaml_path,
                                content_hash,
                            },
                        );
                    }
                    Err(e) => {
                        warn!(path = %yaml_path.display(), error = %e, "skill load failed; skipped");
                    }
                }
            }
        }
    }

    // ── full-auto operating mode — freedom.yaml skills.enable_all_bundled ──
    // When the operator is in full-auto mode (`neoth autonomy full-auto` /
    // `neoth sudomode`), force EVERY bundled skill enabled so NEOTH proactively
    // routes the whole library — including the 68 `pm-*` skills that ship
    // `enabled: false`. Applied FIRST so the `disabled` blocklist below still
    // wins (an operator force-OFF, e.g. the RASKAL offensive register, is never
    // silently re-enabled — the GOLD-HON-11 guarantee holds even in full-auto).
    if read_enable_all_bundled(skills_dir) {
        for skill in by_id.values_mut() {
            skill.manifest.enabled = true;
        }
        debug!("full-auto mode: all bundled skills force-enabled (disabled blocklist still wins)");
    }

    // ── GOLD-ADOPT-14 — freedom.yaml skills.enabled allowlist (force-ON) ──
    // The complement of the blocklist: turns ON a skill that ships
    // `enabled: false` (the 68 imported `pm-*` skills ship DISABLED). Applied
    // BEFORE the disabled block below so `disabled` ALWAYS wins — a force-OFF
    // can never be silently re-enabled (preserves the GOLD-HON-11 guarantee).
    let enabled_allow = read_enabled_skill_ids(skills_dir);
    if !enabled_allow.is_empty() {
        for skill in by_id.values_mut() {
            if enabled_allow.contains(&skill.manifest.id.to_lowercase()) {
                skill.manifest.enabled = true;
                debug!(id = %skill.manifest.id, "skill force-enabled via freedom.yaml::skills.enabled");
            }
        }
    }

    // ── GOLD-HON-11 — freedom.yaml skills.disabled blocklist ────────────
    // Operators turn off a bundled skill (e.g. the RASKAL offensive-tooling
    // register, which ships ENABLED) via `freedom.yaml::skills.disabled`
    // rather than editing the shipped `skill.yaml` an upgrade overwrites.
    // Applied here at the single load chokepoint, so every downstream
    // `is_enabled()` consumer honours it with no call-site changes. Runs AFTER
    // the enabled allowlist so disabled wins on a conflicting id.
    let disabled = read_disabled_skill_ids(skills_dir);
    if !disabled.is_empty() {
        for skill in by_id.values_mut() {
            if disabled.contains(&skill.manifest.id.to_lowercase()) {
                skill.manifest.enabled = false;
                debug!(id = %skill.manifest.id, "skill disabled via freedom.yaml::skills.disabled");
            }
        }
    }

    let mut out: Vec<Skill> = by_id.into_values().collect();
    out.sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    Ok(out)
}

/// GOLD-HON-11 — read `skills.disabled: [<id>, …]` from the `freedom.yaml`
/// that sits next to `<skills_dir>` (i.e. `<home>/freedom.yaml`). Returns
/// lowercased ids. Missing / unreadable / unparseable freedom.yaml → empty
/// list (no skills disabled) — identical to the pre-HON-11 behaviour, so a
/// fresh install with no freedom.yaml is unaffected. Read as a raw
/// `serde_yaml::Value` (house style, mirrors `cluster::policy::
/// load_policy_from_freedom`) so the loader stays decoupled from the full
/// `FreedomConfig` type.
fn read_disabled_skill_ids(skills_dir: &Path) -> Vec<String> {
    let Some(home) = skills_dir.parent() else {
        return Vec::new();
    };
    let freedom_path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&freedom_path) else {
        return Vec::new();
    };
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return Vec::new();
    };
    value
        .get("skills")
        .and_then(|s| s.get("disabled"))
        .and_then(|d| d.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_lowercase()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// GOLD-ADOPT-14 — read `skills.enabled: [<id>, …]` (the force-ON allowlist)
/// from the `freedom.yaml` next to `<skills_dir>`. Same raw-`Value` walk +
/// lowercasing + empty-on-missing semantics as [`read_disabled_skill_ids`].
fn read_enabled_skill_ids(skills_dir: &Path) -> Vec<String> {
    let Some(home) = skills_dir.parent() else {
        return Vec::new();
    };
    let freedom_path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&freedom_path) else {
        return Vec::new();
    };
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return Vec::new();
    };
    value
        .get("skills")
        .and_then(|s| s.get("enabled"))
        .and_then(|d| d.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_lowercase()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Read `skills.enable_all_bundled: <bool>` (the full-auto force-ON-everything
/// switch) from the `freedom.yaml` next to `<skills_dir>`. Same raw-`Value`
/// walk + empty/missing-is-false semantics as [`read_disabled_skill_ids`], so a
/// fresh install (no freedom.yaml, or the key absent) is gated mode by default.
fn read_enable_all_bundled(skills_dir: &Path) -> bool {
    let Some(home) = skills_dir.parent() else {
        return false;
    };
    let freedom_path = home.join("freedom.yaml");
    let Ok(body) = std::fs::read_to_string(&freedom_path) else {
        return false;
    };
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return false;
    };
    value
        .get("skills")
        .and_then(|s| s.get("enable_all_bundled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Decode every entry in [`super::bundled::BUNDLED_SKILLS`] into a `Skill`.
/// A bundled YAML that fails to parse is a build error (the bundled tests
/// in `super::bundled` pin every YAML at compile time), so a failure here
/// would only fire on a manually corrupted include_str! — we log + skip
/// rather than panic so the daemon stays bootable even under that
/// degenerate state.
fn parse_bundled_skills() -> std::collections::HashMap<String, Skill> {
    let mut out = std::collections::HashMap::new();
    for (expected_id, yaml_body) in super::bundled::BUNDLED_SKILLS {
        match serde_yaml::from_str::<SkillManifest>(yaml_body) {
            Ok(mut manifest) => {
                if manifest.id != *expected_id {
                    warn!(
                        expected_id = %expected_id,
                        manifest_id = %manifest.id,
                        "bundled skill id mismatch — entry in BUNDLED_SKILLS disagrees with YAML; skipped"
                    );
                    continue;
                }
                manifest.trigger_keywords = manifest
                    .trigger_keywords
                    .into_iter()
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                // ARCH-07 — bundled skill content_hash uses the
                // already-in-memory yaml body (no re-read needed).
                let content_hash = crate::skills::versioning::skill_content_hash_hex(
                    yaml_body,
                    &manifest.system_prompt,
                );
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
            Err(e) => {
                warn!(
                    id = %expected_id,
                    error = %e,
                    "bundled skill YAML failed to parse — skipped"
                );
            }
        }
    }
    out
}

/// Returns the parsed manifest AND the raw yaml body. The body is
/// needed by [`load_all`] to compute the ARCH-07 `content_hash =
/// SHA-256(yaml || template)` at load time.
async fn parse_one(yaml_path: &Path) -> Result<(SkillManifest, String)> {
    let body = fs::read_to_string(yaml_path)
        .await
        .with_context(|| format!("read {}", yaml_path.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs::{create_dir_all, write};

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
        let skills_dir = manifest_dir.join("assets").join("skills");
        if !skills_dir.exists() {
            // Some CI shapes (cargo publish --dry-run, source-only
            // builds) may not carry the assets dir. Skip gracefully.
            return;
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
        for s in &skills {
            assert!(
                !s.trigger_keywords().is_empty(),
                "skill `{}` has no trigger_keywords",
                s.id()
            );
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
    async fn id_mismatch_is_skipped_with_warning() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "expected-id", "id: wrong-id\ndescription: x\n").await;
        let skills = load_all(dir.path()).await.unwrap();
        // Only the bundled set — the mismatched user entry was rejected.
        assert!(!skills.iter().any(|s| s.id() == "wrong-id"));
        assert!(!skills.iter().any(|s| s.id() == "expected-id"));
        assert_eq!(skills.len(), super::super::bundled::BUNDLED_SKILLS.len());
    }

    #[tokio::test]
    async fn missing_description_rejected() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "broke", "id: broke\ndescription: \"\"\n").await;
        let skills = load_all(dir.path()).await.unwrap();
        // Bundled set only — broken user entry skipped.
        assert!(!skills.iter().any(|s| s.id() == "broke"));
        assert_eq!(skills.len(), super::super::bundled::BUNDLED_SKILLS.len());
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
}
