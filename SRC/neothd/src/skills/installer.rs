//! QM-11 — Skills installer.
//!
//! Per `PLAN/QUELLEN_ADOPT_cc-switch_2026-05-21.md` §4 pick #4. NEOTH
//! ships a plugin SDK + WASM host + a skill loader (`skills::loader`)
//! that reads `~/.neoth/skills/<id>/skill.yaml`, but until QM-11
//! shipping there was no operator-facing surface for placing skill
//! directories there. Operators had to drop folders by hand.
//!
//! This module provides:
//!
//! - [`install_from_local`] — copy a local skill directory into
//!   `~/.neoth/skills/<id>/`. Validates the manifest before copy so
//!   broken YAML never lands in the skills dir.
//! - [`uninstall`] — remove `~/.neoth/skills/<id>/`, idempotent
//!   (missing is Ok, the operator wanted it gone either way).
//! - [`list_installed`] — return every skill currently present under
//!   `~/.neoth/skills/`. Mirrors `skills::loader::load_all` but
//!   surfaces broken installs (no skill.yaml, malformed YAML) so
//!   `neoth skills list` can report them honestly.
//!
//! ## What this module does NOT do (yet)
//!
//! - **GitHub fetch.** The cc-switch installer downloads a repo ZIP
//!   from `https://github.com/<owner>/<repo>/archive/<ref>.zip`,
//!   extracts, validates, then calls `install_from_local`. Adding
//!   that here means a new outbound HTTP surface; per the AIO hard
//!   rule (`[[neoth-aio-cross-platform]]`) that fetch belongs in
//!   `src/installers/` not in `src/skills/` (the providers/+installers/
//!   path is the only network-allowed band per `tests/no_outbound_network.rs`).
//!   Follow-up: `installers::skill_github::fetch` chains into this
//!   module's `install_from_local` after the ZIP is unpacked.
//! - **Symlinks.** cc-switch supports symlink installs for editable
//!   skill development; that's a power-user feature. Operators get
//!   copy-install in v0.1; symlink installs ship when there's an
//!   explicit operator ask.
//! - **Per-skill enable/disable from the installer.** That's a
//!   wizard / settings-panel concern; the manifest's `enabled: false`
//!   field already exists for the disable case.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::schema::SkillManifest;

/// Default skills dir: `~/.neoth/skills/`.
pub fn default_skills_dir() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("skills")
}

/// Report of one installation operation. Returned by [`install_from_local`]
/// so the CLI can surface what landed where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallReport {
    /// The skill id (matches the directory name + the manifest's `id`).
    pub id: String,
    /// Absolute path where the skill was placed.
    pub installed_at: PathBuf,
    /// True when the install REPLACED a prior install at the same id.
    /// Operators see "Reinstalled `xyz`" vs "Installed `xyz`" in CLI
    /// output.
    pub replaced_existing: bool,
}

/// Copy `<source_dir>/skill.yaml` (+ any sibling files) into
/// `<target_skills_dir>/<id>/`, where `<id>` is the manifest's id
/// field. Validates the manifest before the copy starts — a broken
/// YAML never lands in the operator's skills dir.
///
/// `replace_existing = false` errors when the target id already
/// exists; `true` removes the prior install first. Operators get the
/// safe behaviour by default; the CLI exposes `--force` to enable
/// replacement.
pub fn install_from_local(
    source_dir: &Path,
    target_skills_dir: &Path,
    replace_existing: bool,
) -> Result<InstallReport> {
    if !source_dir.is_dir() {
        anyhow::bail!(
            "source `{}` is not a directory — pass the skill folder, not the skill.yaml",
            source_dir.display()
        );
    }
    let manifest_path = source_dir.join("skill.yaml");
    if !manifest_path.exists() {
        anyhow::bail!(
            "no skill.yaml in `{}` — install source must contain a manifest",
            source_dir.display()
        );
    }

    // Parse + validate BEFORE touching the target dir. A broken
    // manifest aborts the install with the parse error verbatim;
    // the operator's existing skills stay untouched.
    let body = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read manifest at {}", manifest_path.display()))?;
    let manifest: SkillManifest = serde_yaml::from_str(&body)
        .with_context(|| format!("parse YAML at {}", manifest_path.display()))?;
    if manifest.id.trim().is_empty() {
        anyhow::bail!(
            "skill.yaml at `{}` has empty `id` — refuse to install",
            manifest_path.display()
        );
    }
    if manifest.description.trim().is_empty() {
        anyhow::bail!(
            "skill.yaml at `{}` has empty `description` — refuse to install",
            manifest_path.display()
        );
    }

    let target_dir = target_skills_dir.join(&manifest.id);
    let replacing = target_dir.exists();
    if replacing && !replace_existing {
        anyhow::bail!(
            "skill `{}` already installed at `{}`; pass --force to replace",
            manifest.id,
            target_dir.display()
        );
    }

    std::fs::create_dir_all(target_skills_dir)
        .with_context(|| format!("create skills dir at {}", target_skills_dir.display()))?;

    if replacing {
        std::fs::remove_dir_all(&target_dir)
            .with_context(|| format!("remove prior install at {}", target_dir.display()))?;
    }

    copy_dir_recursive(source_dir, &target_dir)
        .with_context(|| format!("copy {} → {}", source_dir.display(), target_dir.display()))?;

    Ok(InstallReport {
        id: manifest.id,
        installed_at: target_dir,
        replaced_existing: replacing,
    })
}

/// Remove `<target_skills_dir>/<id>/`. Idempotent — a missing id is
/// `Ok(false)` (the operator wanted it gone, it is gone). Returns
/// `Ok(true)` when bytes were actually removed.
pub fn uninstall(target_skills_dir: &Path, id: &str) -> Result<bool> {
    let path = target_skills_dir.join(id);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&path).with_context(|| format!("remove {}", path.display()))?;
    Ok(true)
}

/// One row in the operator-facing skills list. Distinct from
/// `super::Skill` because this surface includes BROKEN entries (no
/// skill.yaml / malformed YAML) so the operator can see + fix them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledEntry {
    /// Directory name under `~/.neoth/skills/`.
    pub dir_name: String,
    /// Absolute path to the skill directory.
    pub path: PathBuf,
    /// `Some(id)` when the manifest parsed cleanly; `None` when the
    /// directory exists but has no skill.yaml OR the YAML is broken.
    /// The CLI shows broken entries with a warn indicator so the
    /// operator notices.
    pub manifest_id: Option<String>,
    /// `Some(message)` when manifest load failed. Empty when the
    /// manifest is healthy.
    pub error: Option<String>,
}

/// List every entry under `<target_skills_dir>`. Includes broken ones.
/// Sorted by `dir_name` for stable output.
pub fn list_installed(target_skills_dir: &Path) -> Vec<InstalledEntry> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(target_skills_dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) if !n.starts_with('.') => n.to_string(),
            _ => continue,
        };
        let manifest_path = path.join("skill.yaml");
        let (manifest_id, error) = if !manifest_path.exists() {
            (None, Some("no skill.yaml in directory".to_string()))
        } else {
            match std::fs::read_to_string(&manifest_path) {
                Ok(body) => match serde_yaml::from_str::<SkillManifest>(&body) {
                    Ok(m) => (Some(m.id), None),
                    Err(e) => (None, Some(format!("YAML parse error: {e}"))),
                },
                Err(e) => (None, Some(format!("read error: {e}"))),
            }
        };
        out.push(InstalledEntry {
            dir_name,
            path,
            manifest_id,
            error,
        });
    }
    out.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
    out
}

/// Recursive directory copy. Pure-stdlib so no extra crate dep — the
/// install path doesn't need fancy progress / parallelism.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("create {}", dst.display()))?;
    for entry in std::fs::read_dir(src).with_context(|| format!("read_dir {}", src.display()))? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to)
                .with_context(|| format!("copy {} → {}", from.display(), to.display()))?;
        }
        // Symlinks intentionally skipped — installer is copy-install
        // only per the module-level note.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_skill(dir: &Path, id: &str, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("skill.yaml"), body).unwrap();
        let _ = id; // dir name supplies the id
    }

    fn good_yaml(id: &str) -> String {
        format!(
            "id: {id}\n\
             description: A test skill\n\
             trigger_keywords: [test, hello]\n\
             system_prompt: You are a test skill.\n"
        )
    }

    #[test]
    fn install_from_local_copies_skill_dir_into_target() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();

        let src = staging.path().join("my_skill_source");
        write_skill(&src, "my_skill", &good_yaml("my_skill"));

        let report = install_from_local(&src, dest.path(), false).expect("install must succeed");
        assert_eq!(report.id, "my_skill");
        assert!(!report.replaced_existing);
        assert!(report.installed_at.exists());
        assert!(report.installed_at.join("skill.yaml").exists());
    }

    #[test]
    fn install_from_local_copies_sibling_files() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();

        let src = staging.path().join("rich_skill_source");
        write_skill(&src, "rich_skill", &good_yaml("rich_skill"));
        // Drop an extra file alongside the manifest.
        std::fs::write(src.join("README.md"), b"# Rich skill").unwrap();

        let report = install_from_local(&src, dest.path(), false).unwrap();
        assert!(report.installed_at.join("README.md").exists());
    }

    #[test]
    fn install_from_local_refuses_when_target_exists_without_force() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();

        let src = staging.path().join("dup_source");
        write_skill(&src, "dup", &good_yaml("dup"));

        install_from_local(&src, dest.path(), false).unwrap();
        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(err.to_string().contains("already installed"));
        assert!(err.to_string().contains("--force"));
    }

    #[test]
    fn install_from_local_with_force_replaces_prior_install() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();

        let src_v1 = staging.path().join("replaceable_v1");
        write_skill(&src_v1, "replaceable", &good_yaml("replaceable"));
        std::fs::write(src_v1.join("VERSION"), b"v1").unwrap();
        install_from_local(&src_v1, dest.path(), false).unwrap();

        let src_v2 = staging.path().join("replaceable_v2");
        write_skill(&src_v2, "replaceable", &good_yaml("replaceable"));
        std::fs::write(src_v2.join("VERSION"), b"v2").unwrap();

        let report = install_from_local(&src_v2, dest.path(), true).unwrap();
        assert!(report.replaced_existing);
        let version = std::fs::read_to_string(report.installed_at.join("VERSION")).unwrap();
        assert_eq!(version, "v2");
    }

    #[test]
    fn install_from_local_rejects_missing_manifest() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();

        let src = staging.path().join("no_manifest");
        std::fs::create_dir_all(&src).unwrap();
        // No skill.yaml.
        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(err.to_string().contains("no skill.yaml"));
    }

    #[test]
    fn install_from_local_rejects_broken_yaml() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();

        let src = staging.path().join("broken");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("skill.yaml"), "this is = not [valid").unwrap();

        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(err.to_string().contains("parse YAML"));
        // Confirm the target dir was never created — atomic-fail.
        assert!(!dest.path().join("broken").exists());
    }

    #[test]
    fn install_from_local_rejects_empty_id() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();

        let src = staging.path().join("emptyid");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("skill.yaml"),
            "id: \"\"\ndescription: empty id\nsystem_prompt: x\n",
        )
        .unwrap();

        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(err.to_string().contains("empty `id`"));
    }

    #[test]
    fn uninstall_removes_skill_dir() {
        let dest = tempdir().unwrap();
        let target = dest.path().join("doomed");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("skill.yaml"), "id: doomed\n").unwrap();

        let removed = uninstall(dest.path(), "doomed").unwrap();
        assert!(removed);
        assert!(!target.exists());
    }

    #[test]
    fn uninstall_missing_id_is_ok_false() {
        let dest = tempdir().unwrap();
        let removed = uninstall(dest.path(), "never_installed").unwrap();
        assert!(!removed);
    }

    #[test]
    fn list_installed_surfaces_broken_entries() {
        let dest = tempdir().unwrap();

        let healthy = dest.path().join("healthy");
        std::fs::create_dir_all(&healthy).unwrap();
        std::fs::write(healthy.join("skill.yaml"), good_yaml("healthy")).unwrap();

        let no_manifest = dest.path().join("no_manifest");
        std::fs::create_dir_all(&no_manifest).unwrap();

        let broken_yaml = dest.path().join("broken_yaml");
        std::fs::create_dir_all(&broken_yaml).unwrap();
        std::fs::write(broken_yaml.join("skill.yaml"), "this is = not [valid").unwrap();

        let rows = list_installed(dest.path());
        assert_eq!(rows.len(), 3);

        let h = rows.iter().find(|r| r.dir_name == "healthy").unwrap();
        assert_eq!(h.manifest_id.as_deref(), Some("healthy"));
        assert!(h.error.is_none());

        let n = rows.iter().find(|r| r.dir_name == "no_manifest").unwrap();
        assert!(n.manifest_id.is_none());
        assert!(n.error.as_ref().unwrap().contains("no skill.yaml"));

        let b = rows.iter().find(|r| r.dir_name == "broken_yaml").unwrap();
        assert!(b.manifest_id.is_none());
        assert!(b.error.as_ref().unwrap().contains("YAML parse error"));
    }

    #[test]
    fn list_installed_returns_empty_for_missing_dir() {
        let dest = tempdir().unwrap();
        let rows = list_installed(&dest.path().join("nope"));
        assert!(rows.is_empty());
    }

    #[test]
    fn list_installed_skips_dotfiles_and_files() {
        let dest = tempdir().unwrap();
        // Hidden dir
        std::fs::create_dir_all(dest.path().join(".hidden")).unwrap();
        // Plain file
        std::fs::write(dest.path().join("loose.txt"), b"x").unwrap();
        let rows = list_installed(dest.path());
        assert!(rows.is_empty(), "expected no entries; got {rows:?}");
    }
}
