//! UX-06 — `neoth skills --create` skill-manifest wizard.
//!
//! A YAML-only path for non-Rust operators to author a skill: collect a
//! few fields (id / description / trigger keywords / system prompt),
//! build a validated [`SkillManifest`], and write
//! `~/.neoth/skills/<id>/skill.yaml` — the same shape the loader reads.
//!
//! The pure builder ([`build_manifest`] / [`write_skill_yaml`]) is fully
//! testable without a TTY; the interactive dialoguer wrapper is gated
//! behind `cfg(feature = "wizard")`, mirroring `cli/init.rs`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::skills::schema::SkillManifest;

/// Parameters gathered from CLI flags or interactive prompts.
#[derive(Debug, Clone)]
pub struct CreateParams {
    pub id: String,
    pub description: String,
    pub keywords: Vec<String>,
    pub system_prompt: String,
}

/// Report returned after a successful create.
#[derive(Debug, Clone)]
pub struct CreateReport {
    pub id: String,
    pub path: PathBuf,
}

// ── Pure builder (testable without dialoguer / filesystem) ────────────

/// Validate a skill id: non-empty, `[a-zA-Z0-9_-]`, ≤ 64 chars. Matches
/// the loader invariant that the on-disk directory name equals the id.
pub fn validate_skill_id(id: &str) -> Result<()> {
    if id.is_empty() {
        anyhow::bail!("skill id must not be empty");
    }
    if id.len() > 64 {
        anyhow::bail!("skill id must be <= 64 chars (got {})", id.len());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!("skill id may only contain [a-zA-Z0-9_-]: {id}");
    }
    Ok(())
}

/// Build a [`SkillManifest`] from raw params + round-trip it through
/// `serde_yaml` to prove the YAML we're about to write re-parses
/// cleanly. Returns `(manifest, yaml_string)`. Pure — no I/O.
pub fn build_manifest(params: &CreateParams) -> Result<(SkillManifest, String)> {
    validate_skill_id(&params.id)?;
    if params.description.trim().is_empty() {
        anyhow::bail!("description must not be empty");
    }
    // Normalise keywords: trim + lowercase + drop empties (matches the
    // loader's own normalisation so test/route behaviour is consistent).
    let keywords: Vec<String> = params
        .keywords
        .iter()
        .map(|k| k.trim().to_lowercase())
        .filter(|k| !k.is_empty())
        .collect();

    let manifest = SkillManifest {
        id: params.id.clone(),
        description: params.description.trim().to_string(),
        version: "1.0.0".to_string(),
        trigger_keywords: keywords,
        system_prompt: params.system_prompt.clone(),
        tool_allowlist: vec![],
        author: None,
        tags: vec![],
        homepage: None,
        source: None,
        modes: vec![],
        enabled: true,
        delegate_to: None,
    };

    let yaml = serde_yaml::to_string(&manifest).context("serialise SkillManifest to YAML")?;
    // Round-trip guard: the loader must be able to read what we write.
    let _back: SkillManifest = serde_yaml::from_str(&yaml)
        .context("round-trip parse failed — serde_yaml produced unreadable YAML")?;
    Ok((manifest, yaml))
}

/// Write `<skills_dir>/<id>/skill.yaml` atomically (tmp → rename),
/// creating the id directory. Overwrites an existing file (caller gates
/// any confirm). Returns the written path.
pub fn write_skill_yaml(skills_dir: &Path, id: &str, yaml: &str) -> Result<PathBuf> {
    let dir = skills_dir.join(id);
    std::fs::create_dir_all(&dir).with_context(|| format!("create skill dir {}", dir.display()))?;
    let target = dir.join("skill.yaml");
    let tmp = target.with_extension("yaml.tmp");
    std::fs::write(&tmp, yaml.as_bytes())
        .with_context(|| format!("write tmp {}", tmp.display()))?;
    if target.exists() {
        std::fs::remove_file(&target)
            .with_context(|| format!("remove existing {}", target.display()))?;
    }
    std::fs::rename(&tmp, &target)
        .with_context(|| format!("rename {} -> {}", tmp.display(), target.display()))?;
    Ok(target)
}

/// Top-level create: build + write + return the report.
pub fn create_skill(skills_dir: &Path, params: CreateParams) -> Result<CreateReport> {
    let (_, yaml) = build_manifest(&params)?;
    let path = write_skill_yaml(skills_dir, &params.id, &yaml)?;
    Ok(CreateReport {
        id: params.id,
        path,
    })
}

// ── Param collection: flags (non-interactive) or dialoguer prompts ───

/// Collect [`CreateParams`] from CLI flags (non-interactive) or via
/// dialoguer (interactive, `wizard` feature). `interactive` is computed
/// by the caller from `!--non-interactive && stdin().is_terminal()`.
pub fn collect_create_params(
    args: &crate::cli::skills::SkillsArgs,
    interactive: bool,
) -> Result<CreateParams> {
    if !interactive {
        let id = args
            .create_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--create-id is required in non-interactive mode"))?;
        let description = args.create_description.clone().ok_or_else(|| {
            anyhow::anyhow!("--create-description is required in non-interactive mode")
        })?;
        let keywords = split_keywords(args.create_keywords.as_deref());
        let system_prompt = args.create_system_prompt.clone().unwrap_or_default();
        return Ok(CreateParams {
            id,
            description,
            keywords,
            system_prompt,
        });
    }
    collect_create_params_interactive(args)
}

/// Split a comma-separated keyword flag into a trimmed, non-empty list.
fn split_keywords(raw: Option<&str>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}

#[cfg(feature = "wizard")]
fn collect_create_params_interactive(
    args: &crate::cli::skills::SkillsArgs,
) -> Result<CreateParams> {
    println!();
    println!("=== Create a new NEOTH skill =================================");
    println!();

    let id: String = loop {
        let default = args.create_id.clone().unwrap_or_default();
        let input: String =
            dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("Skill id (kebab-case, e.g. morning-news)")
                .default(default)
                .interact_text()
                .context("skill id input")?;
        match validate_skill_id(&input) {
            Ok(()) => break input,
            Err(e) => eprintln!("  invalid id: {e}"),
        }
    };

    let description: String =
        dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("One-line description")
            .default(args.create_description.clone().unwrap_or_default())
            .validate_with(|s: &String| {
                if s.trim().is_empty() {
                    Err("description is required".to_string())
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .context("description input")?;

    let kw_raw: String = dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Trigger keywords (comma-separated, e.g. news,briefing,headlines)")
        .default(args.create_keywords.clone().unwrap_or_default())
        .allow_empty(true)
        .interact_text()
        .context("keywords input")?;
    let keywords = split_keywords(Some(&kw_raw));

    let system_prompt: String =
        dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("System prompt (one line now; edit the YAML for multi-line)")
            .default(args.create_system_prompt.clone().unwrap_or_default())
            .allow_empty(true)
            .interact_text()
            .context("system_prompt input")?;

    Ok(CreateParams {
        id,
        description,
        keywords,
        system_prompt,
    })
}

#[cfg(not(feature = "wizard"))]
fn collect_create_params_interactive(
    args: &crate::cli::skills::SkillsArgs,
) -> Result<CreateParams> {
    // No dialoguer in this build — require the non-interactive flags.
    let id = args.create_id.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "interactive skill creation needs the `wizard` feature. Re-run with \
             --create-id / --create-description / --create-keywords / \
             --create-system-prompt --non-interactive."
        )
    })?;
    let description = args
        .create_description
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--create-description is required (no wizard feature)"))?;
    let keywords = split_keywords(args.create_keywords.as_deref());
    let system_prompt = args.create_system_prompt.clone().unwrap_or_default();
    Ok(CreateParams {
        id,
        description,
        keywords,
        system_prompt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_params() -> CreateParams {
        CreateParams {
            id: "morning-news".into(),
            description: "Fetch + summarise today's headlines.".into(),
            keywords: vec!["news".into(), "briefing".into(), "headlines".into()],
            system_prompt: "You are a news briefing agent.".into(),
        }
    }

    #[test]
    fn build_manifest_returns_loader_compatible_yaml() {
        let (m, yaml) = build_manifest(&good_params()).expect("build");
        assert_eq!(m.id, "morning-news");
        assert_eq!(m.trigger_keywords, vec!["news", "briefing", "headlines"]);
        assert!(m.enabled);
        let back: SkillManifest = serde_yaml::from_str(&yaml).expect("round-trip");
        assert_eq!(back.id, m.id);
        assert_eq!(back.trigger_keywords, m.trigger_keywords);
    }

    #[test]
    fn build_manifest_normalises_keywords() {
        let p = CreateParams {
            id: "x".into(),
            description: "d".into(),
            keywords: vec![" NEWS ".into(), "".into(), "BriEFing".into()],
            system_prompt: String::new(),
        };
        let (m, _) = build_manifest(&p).expect("build");
        assert_eq!(m.trigger_keywords, vec!["news", "briefing"]);
    }

    #[test]
    fn build_manifest_rejects_empty_id() {
        let mut p = good_params();
        p.id = String::new();
        assert!(build_manifest(&p).is_err());
    }

    #[test]
    fn build_manifest_rejects_empty_description() {
        let mut p = good_params();
        p.description = "   ".into();
        assert!(build_manifest(&p).is_err());
    }

    #[test]
    fn validate_skill_id_matrix() {
        assert!(validate_skill_id("morning-news").is_ok());
        assert!(validate_skill_id("x").is_ok());
        assert!(validate_skill_id(&"a".repeat(64)).is_ok());
        assert!(validate_skill_id("").is_err());
        assert!(validate_skill_id(&"a".repeat(65)).is_err());
        assert!(validate_skill_id("has space").is_err());
        assert!(validate_skill_id("has@sym").is_err());
    }

    #[test]
    fn create_skill_end_to_end_is_loader_compatible() {
        let dir = tempfile::tempdir().unwrap();
        let report = create_skill(dir.path(), good_params()).expect("create");
        assert_eq!(report.id, "morning-news");
        assert_eq!(
            report.path,
            dir.path().join("morning-news").join("skill.yaml")
        );
        let body = std::fs::read_to_string(&report.path).unwrap();
        let m: SkillManifest = serde_yaml::from_str(&body).expect("loader-parseable");
        assert_eq!(m.id, "morning-news");
        assert!(!m.trigger_keywords.is_empty());
    }

    #[test]
    fn write_skill_yaml_overwrite_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();
        write_skill_yaml(dir.path(), "morning-news", &yaml).unwrap();
        // Second write must succeed (overwrite), no tmp file lingering.
        write_skill_yaml(dir.path(), "morning-news", &yaml).unwrap();
        assert!(
            !dir.path()
                .join("morning-news")
                .join("skill.yaml.tmp")
                .exists()
        );
    }

    #[test]
    fn split_keywords_trims_and_drops_empties() {
        assert_eq!(
            split_keywords(Some("news, briefing , ,headlines")),
            vec!["news", "briefing", "headlines"]
        );
        assert!(split_keywords(None).is_empty());
        assert!(split_keywords(Some("")).is_empty());
    }
}
