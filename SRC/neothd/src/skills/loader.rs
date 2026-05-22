//! Skill loader — walks `~/.neoth/skills/<id>/skill.yaml` and parses every
//! manifest. Bad manifests are logged + skipped, never block startup.
//!
//! Layout convention:
//! ```
//! ~/.neoth/skills/
//!   morning-news/
//!     skill.yaml           ← parsed
//!     extras.md            ← ignored by loader, can be referenced from system_prompt
//!   recall-helper/
//!     skill.yaml
//! ```

use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs;
use tracing::{debug, warn};

use super::schema::{Skill, SkillManifest};

/// Load every `<skills_dir>/<id>/skill.yaml`. Missing dir → empty vec, no error.
///
/// The directory name is the canonical skill id. If the YAML `id` field does
/// not match, the manifest is rejected with a warning and skipped — drift
/// here is almost always a copy-paste mistake worth surfacing.
pub async fn load_all(skills_dir: &Path) -> Result<Vec<Skill>> {
    if !skills_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = match fs::read_dir(skills_dir).await {
        Ok(e) => e,
        Err(_) => return Ok(Vec::new()),
    };

    let mut out = Vec::new();
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
                debug!(
                    id = %manifest.id,
                    keywords = manifest.trigger_keywords.len(),
                    enabled = manifest.enabled,
                    "loaded skill"
                );
                out.push(Skill {
                    manifest,
                    path: yaml_path,
                });
            }
            Err(e) => {
                warn!(path = %yaml_path.display(), error = %e, "skill load failed; skipped");
            }
        }
    }

    out.sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    Ok(out)
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
    async fn empty_dir_returns_empty_vec() {
        let dir = tempdir().unwrap();
        let skills = load_all(dir.path()).await.unwrap();
        assert!(skills.is_empty());
    }

    #[tokio::test]
    async fn missing_dir_returns_empty_vec() {
        let dir = tempdir().unwrap();
        let nope = dir.path().join("does-not-exist");
        let skills = load_all(&nope).await.unwrap();
        assert!(skills.is_empty());
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
        assert_eq!(skills.len(), 1);
        let s = &skills[0];
        assert_eq!(s.id(), "morning-news");
        assert_eq!(s.trigger_keywords().len(), 3);
        assert_eq!(s.manifest.tool_allowlist, vec!["fetch", "channel-send"]);
        assert!(s.is_enabled());
    }

    #[tokio::test]
    async fn id_mismatch_is_skipped_with_warning() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "expected-id", "id: wrong-id\ndescription: x\n").await;
        let skills = load_all(dir.path()).await.unwrap();
        assert!(skills.is_empty(), "mismatched id must not load");
    }

    #[tokio::test]
    async fn missing_description_rejected() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "broke", "id: broke\ndescription: \"\"\n").await;
        let skills = load_all(dir.path()).await.unwrap();
        assert!(skills.is_empty());
    }

    #[tokio::test]
    async fn keywords_are_lowercased_and_trimmed() {
        let dir = tempdir().unwrap();
        write_manifest(
            dir.path(),
            "x",
            "id: x\ndescription: y\ntrigger_keywords: [\"  NEWS  \", \"\", BriEFing]\n",
        )
        .await;
        let skills = load_all(dir.path()).await.unwrap();
        assert_eq!(skills[0].trigger_keywords(), &["news", "briefing"]);
    }

    #[tokio::test]
    async fn dot_prefixed_dirs_are_ignored() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), ".hidden", "id: .hidden\ndescription: x\n").await;
        let skills = load_all(dir.path()).await.unwrap();
        assert!(skills.is_empty());
    }

    #[tokio::test]
    async fn sorts_skills_by_id() {
        let dir = tempdir().unwrap();
        write_manifest(dir.path(), "zeta", "id: zeta\ndescription: z\n").await;
        write_manifest(dir.path(), "alpha", "id: alpha\ndescription: a\n").await;
        let skills = load_all(dir.path()).await.unwrap();
        assert_eq!(skills[0].id(), "alpha");
        assert_eq!(skills[1].id(), "zeta");
    }
}
