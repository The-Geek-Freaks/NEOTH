//! GOLD-FEAT-11 — skill curator cron.
//!
//! After a configurable minimum age (default 7 days), mature + accepted Skill
//! proposals are auto-promoted from `~/.neoth/proposals/` to
//! `~/.neoth/skills/` so they become live without operator surgery.
//!
//! Gated behind `SkillCuratorConfig.enabled = false` by default — only fires
//! when the operator explicitly enables it. Safe to spawn even when the
//! proposals directory is empty or absent.
//!
//! The `daemon/self_improvement_collector` and HERMES-06 write the proposals
//! this cron promotes. If those haven't run yet, the proposals directory is
//! empty and each tick is a fast no-op.

use std::path::Path;

use tracing::{debug, info, warn};

use crate::config::automation::SkillCuratorConfig;

/// One tick of the skill-curator cron.
///
/// Scans `~/.neoth/proposals/*.json`, finds entries that:
/// 1. Have `kind == "Skill"` (or equivalent serialised tag).
/// 2. Were created at least `cfg.min_age_days * 86400` seconds ago.
/// 3. Are operator-accepted (`is_verified_deployed == true` or
///    `accepted == true`).
///
/// For each qualifying entry, copies the YAML file referenced by the
/// `skill_path` field (or the raw `yaml_body` field) into
/// `~/.neoth/skills/<slug>.yaml` using an atomic write so the live skill
/// loader never sees a partial file.
pub async fn run_skill_curator_tick(home: &Path, cfg: &SkillCuratorConfig) -> anyhow::Result<()> {
    if !cfg.enabled {
        return Ok(());
    }

    let proposals_dir = home.join("proposals");
    if !proposals_dir.exists() {
        debug!("skill_curator: proposals dir absent — nothing to promote");
        return Ok(());
    }

    let skills_dir = home.join("skills");
    if !skills_dir.exists() {
        std::fs::create_dir_all(&skills_dir).map_err(|e| {
            anyhow::anyhow!("skill_curator: could not create skills dir: {e}")
        })?;
    }

    let now_unix = crate::time::now_unix_i64();
    let min_age_secs = (cfg.min_age_days * 86_400) as i64;

    let mut promoted = 0usize;

    let entries = match std::fs::read_dir(&proposals_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "skill_curator: could not read proposals dir — skipping tick");
            return Ok(());
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|x| x != "json").unwrap_or(true) {
            continue;
        }

        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skill_curator: could not read proposal");
                continue;
            }
        };

        let proposal: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skill_curator: could not parse proposal JSON");
                continue;
            }
        };

        // ── Filter ──────────────────────────────────────────────────────
        // kind must be "Skill" (case-insensitive)
        let kind = proposal
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if kind != "skill" {
            continue;
        }

        // Must be accepted
        let accepted = proposal
            .get("is_verified_deployed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || proposal
                .get("accepted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        if !accepted {
            continue;
        }

        // Must be old enough
        let created_at = proposal
            .get("created_at_unix")
            .and_then(|v| v.as_i64())
            .unwrap_or(now_unix); // default to now = never old enough
        if now_unix - created_at < min_age_secs {
            debug!(
                path = %path.display(),
                age_secs = now_unix - created_at,
                min_age_secs,
                "skill_curator: proposal not yet old enough"
            );
            continue;
        }

        // ── Promote ─────────────────────────────────────────────────────
        // Prefer `skill_path` (path to the generated YAML), fall back to
        // `yaml_body` (inlined YAML string).
        let slug = proposal
            .get("slug")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_skill")
            .to_string();

        let yaml_bytes: Vec<u8> = if let Some(skill_path) = proposal
            .get("skill_path")
            .and_then(|v| v.as_str())
        {
            let sp = Path::new(skill_path);
            match std::fs::read(sp) {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        skill_path = %sp.display(),
                        error = %e,
                        "skill_curator: could not read skill YAML file — skipping proposal"
                    );
                    continue;
                }
            }
        } else if let Some(body) = proposal.get("yaml_body").and_then(|v| v.as_str()) {
            body.as_bytes().to_vec()
        } else {
            warn!(
                path = %path.display(),
                "skill_curator: proposal has neither skill_path nor yaml_body — skipping"
            );
            continue;
        };

        let dest = skills_dir.join(format!("{slug}.yaml"));
        match crate::util::atomic_write::atomic_write(&dest, &yaml_bytes) {
            Ok(()) => {
                info!(
                    slug = %slug,
                    dest = %dest.display(),
                    "skill_curator: promoted skill to live skills dir"
                );
                promoted += 1;
            }
            Err(e) => {
                warn!(
                    slug = %slug,
                    dest = %dest.display(),
                    error = %e,
                    "skill_curator: atomic write failed — skipping"
                );
            }
        }
    }

    if promoted > 0 {
        info!(promoted, "skill_curator: tick complete");
    } else {
        debug!("skill_curator: no proposals promoted this tick");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn default_cfg() -> SkillCuratorConfig {
        SkillCuratorConfig {
            enabled: true,
            interval_secs: 7 * 86_400,
            min_age_days: 7,
        }
    }

    #[tokio::test]
    async fn no_op_when_proposals_dir_absent() {
        let dir = tempdir().unwrap();
        let cfg = default_cfg();
        run_skill_curator_tick(dir.path(), &cfg).await.unwrap();
        assert!(!dir.path().join("skills").exists());
    }

    #[tokio::test]
    async fn no_op_when_disabled() {
        let dir = tempdir().unwrap();
        let mut cfg = default_cfg();
        cfg.enabled = false;
        let proposals = dir.path().join("proposals");
        std::fs::create_dir(&proposals).unwrap();
        run_skill_curator_tick(dir.path(), &cfg).await.unwrap();
        assert!(!dir.path().join("skills").exists());
    }

    #[tokio::test]
    async fn skips_non_skill_proposals() {
        let dir = tempdir().unwrap();
        let proposals = dir.path().join("proposals");
        std::fs::create_dir(&proposals).unwrap();
        let now = crate::time::now_unix_i64() - 8 * 86_400;
        let proposal = serde_json::json!({
            "kind": "ConfigTweak",
            "accepted": true,
            "created_at_unix": now,
            "slug": "should_not_promote",
            "yaml_body": "name: should_not_promote\n"
        });
        std::fs::write(
            proposals.join("p1.json"),
            serde_json::to_string(&proposal).unwrap(),
        )
        .unwrap();
        let cfg = default_cfg();
        run_skill_curator_tick(dir.path(), &cfg).await.unwrap();
        assert!(!dir.path().join("skills").join("should_not_promote.yaml").exists());
    }

    #[tokio::test]
    async fn skips_too_young_proposals() {
        let dir = tempdir().unwrap();
        let proposals = dir.path().join("proposals");
        std::fs::create_dir(&proposals).unwrap();
        let now = crate::time::now_unix_i64() - 2 * 86_400; // only 2 days old
        let proposal = serde_json::json!({
            "kind": "Skill",
            "accepted": true,
            "created_at_unix": now,
            "slug": "young_skill",
            "yaml_body": "name: young_skill\n"
        });
        std::fs::write(
            proposals.join("p1.json"),
            serde_json::to_string(&proposal).unwrap(),
        )
        .unwrap();
        let cfg = default_cfg();
        run_skill_curator_tick(dir.path(), &cfg).await.unwrap();
        assert!(!dir.path().join("skills").join("young_skill.yaml").exists());
    }

    #[tokio::test]
    async fn promotes_mature_accepted_skill() {
        let dir = tempdir().unwrap();
        let proposals = dir.path().join("proposals");
        std::fs::create_dir(&proposals).unwrap();
        let now = crate::time::now_unix_i64() - 10 * 86_400; // 10 days old
        let yaml_body = "name: my_skill\ntrigger_keywords: [\"test\"]\n";
        let proposal = serde_json::json!({
            "kind": "Skill",
            "is_verified_deployed": true,
            "created_at_unix": now,
            "slug": "my_skill",
            "yaml_body": yaml_body
        });
        std::fs::write(
            proposals.join("p1.json"),
            serde_json::to_string(&proposal).unwrap(),
        )
        .unwrap();
        let cfg = default_cfg();
        run_skill_curator_tick(dir.path(), &cfg).await.unwrap();
        let dest = dir.path().join("skills").join("my_skill.yaml");
        assert!(dest.exists(), "skill should be promoted");
        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(content.contains("my_skill"));
    }
}
