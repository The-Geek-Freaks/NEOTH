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

/// Sanitise an untrusted proposal `slug` into a safe single-segment filename.
///
/// The slug comes straight from proposal JSON; without this it flows into
/// `skills_dir.join(format!("{slug}.yaml"))`, so a slug of `../../etc/cron.d/x`
/// (or `..\\..\\Windows\\...`) would let a crafted/corrupt proposal write YAML
/// anywhere the daemon can reach — an arbitrary-file-write primitive. We take
/// only the final path component (dropping any `dir/..` parts), whitelist to
/// `[A-Za-z0-9_-]`, trim separators, and cap the length, guaranteeing the
/// result is a single segment that cannot escape `skills_dir`.
fn sanitize_slug(raw: &str) -> String {
    let base = Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(128)
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '_' || c == '-');
    if trimmed.is_empty() {
        "unknown_skill".to_string()
    } else {
        trimmed.to_string()
    }
}

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

    // Resolve home once for the `skill_path` containment check below — a
    // crafted proposal must not turn the curator into an arbitrary-file reader.
    let home_canonical = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());

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
        let slug = sanitize_slug(
            proposal
                .get("slug")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown_skill"),
        );

        let yaml_bytes: Vec<u8> = if let Some(skill_path) = proposal
            .get("skill_path")
            .and_then(|v| v.as_str())
        {
            // Path hardening: only promote YAML that resolves INSIDE the
            // operator's ~/.neoth home. Without this a crafted proposal could
            // point `skill_path` at any file the daemon can read (e.g. a
            // secret) and have its contents copied into the live skills dir.
            let sp = Path::new(skill_path);
            match std::fs::canonicalize(sp) {
                Ok(real) if real.starts_with(&home_canonical) => match std::fs::read(&real) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(
                            skill_path = %real.display(),
                            error = %e,
                            "skill_curator: could not read skill YAML file — skipping proposal"
                        );
                        continue;
                    }
                },
                Ok(real) => {
                    warn!(
                        skill_path = %real.display(),
                        "skill_curator: skill_path escapes ~/.neoth — refusing to promote"
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        skill_path = %sp.display(),
                        error = %e,
                        "skill_curator: skill_path unresolvable — skipping proposal"
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
        // Backstop against a future slug-sanitiser regression: the sanitised
        // slug is a single segment, so dest MUST be a direct child of skills_dir.
        if dest.parent() != Some(skills_dir.as_path()) {
            warn!(slug = %slug, dest = %dest.display(), "skill_curator: dest escapes skills dir — refusing");
            continue;
        }
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

    #[test]
    fn sanitize_slug_strips_separators_and_traversal() {
        assert_eq!(sanitize_slug("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_slug("good_skill-1"), "good_skill-1");
        assert_eq!(sanitize_slug("with spaces!"), "with_spaces");
        assert_eq!(sanitize_slug(".."), "unknown_skill");
        assert_eq!(sanitize_slug(""), "unknown_skill");
    }

    #[tokio::test]
    async fn sanitizes_slug_traversal_no_arbitrary_write() {
        // A malicious/corrupt proposal slug must not let the curator write
        // outside the skills dir.
        let dir = tempdir().unwrap();
        let proposals = dir.path().join("proposals");
        std::fs::create_dir(&proposals).unwrap();
        let now = crate::time::now_unix_i64() - 10 * 86_400;
        let proposal = serde_json::json!({
            "kind": "Skill",
            "is_verified_deployed": true,
            "created_at_unix": now,
            "slug": "../../../pwned",
            "yaml_body": "name: pwned\n"
        });
        std::fs::write(proposals.join("p1.json"), serde_json::to_string(&proposal).unwrap()).unwrap();
        run_skill_curator_tick(dir.path(), &default_cfg()).await.unwrap();

        // The traversal target must NOT exist (no arbitrary write).
        assert!(!dir.path().join("pwned.yaml").exists(), "slug traversal must not escape skills dir");
        // It lands safely as skills/pwned.yaml (final component, sanitised).
        assert!(
            dir.path().join("skills").join("pwned.yaml").exists(),
            "slug promoted into skills dir under a safe filename"
        );
    }

    #[tokio::test]
    async fn refuses_skill_path_outside_home() {
        // skill_path pointing outside ~/.neoth must be refused (arbitrary-read
        // guard), not copied into the live skills dir.
        let home = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let proposals = home.path().join("proposals");
        std::fs::create_dir(&proposals).unwrap();
        let secret = outside.path().join("secret.yaml");
        std::fs::write(&secret, "name: exfiltrated\n").unwrap();
        let now = crate::time::now_unix_i64() - 10 * 86_400;
        let proposal = serde_json::json!({
            "kind": "Skill",
            "is_verified_deployed": true,
            "created_at_unix": now,
            "slug": "exfil",
            "skill_path": secret.display().to_string(),
        });
        std::fs::write(proposals.join("p1.json"), serde_json::to_string(&proposal).unwrap()).unwrap();
        run_skill_curator_tick(home.path(), &default_cfg()).await.unwrap();
        assert!(
            !home.path().join("skills").join("exfil.yaml").exists(),
            "skill_path outside home must be refused"
        );
    }

    #[tokio::test]
    async fn promotes_skill_path_inside_home() {
        // The legit producer convention writes skill_path under ~/.neoth — that
        // path must still promote (containment check must not break the flow).
        let home = tempdir().unwrap();
        let proposals = home.path().join("proposals");
        std::fs::create_dir(&proposals).unwrap();
        let staging = home.path().join("skills_staging");
        std::fs::create_dir(&staging).unwrap();
        let gen_path = staging.join("gen.yaml");
        std::fs::write(&gen_path, "name: legit_skill\n").unwrap();
        let now = crate::time::now_unix_i64() - 10 * 86_400;
        let proposal = serde_json::json!({
            "kind": "Skill",
            "is_verified_deployed": true,
            "created_at_unix": now,
            "slug": "legit_skill",
            "skill_path": gen_path.display().to_string(),
        });
        std::fs::write(proposals.join("p1.json"), serde_json::to_string(&proposal).unwrap()).unwrap();
        run_skill_curator_tick(home.path(), &default_cfg()).await.unwrap();
        let dest = home.path().join("skills").join("legit_skill.yaml");
        assert!(dest.exists(), "skill_path inside home must promote");
        assert!(std::fs::read_to_string(&dest).unwrap().contains("legit_skill"));
    }
}
