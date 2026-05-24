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
                    Ok(manifest) => {
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
                        debug!(
                            id = %manifest.id,
                            keywords = manifest.trigger_keywords.len(),
                            enabled = manifest.enabled,
                            overrode_bundled = overrode,
                            "loaded user skill"
                        );
                        by_id.insert(
                            manifest.id.clone(),
                            Skill {
                                manifest,
                                path: yaml_path,
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

    let mut out: Vec<Skill> = by_id.into_values().collect();
    out.sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    Ok(out)
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
                out.insert(
                    manifest.id.clone(),
                    Skill {
                        manifest,
                        // Bundled skills have no on-disk path; use a
                        // marker path so downstream consumers can tell
                        // bundled from user-installed.
                        path: PathBuf::from(format!("<bundled>/{expected_id}/skill.yaml")),
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

async fn parse_one(yaml_path: &Path) -> Result<SkillManifest> {
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
    Ok(manifest)
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
}
