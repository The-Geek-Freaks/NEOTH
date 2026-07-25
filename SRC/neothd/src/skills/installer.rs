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

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
#[cfg(unix)]
use cap_std::fs::DirBuilder;
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::schema::SkillManifest;
use super::store::{
    BoundDirectory, cap_metadata_is_link_like, open_bound_directory, open_real_child_dir,
    open_regular_file, read_regular_file_bounded, remove_child_file, remove_real_directory_tree,
    rename_child,
};

const MAX_SKILL_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SKILL_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SKILL_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SKILL_ENTRIES: usize = 4096;
const MAX_SKILL_TREE_DEPTH: usize = 32;
const SKILL_MUTATION_LOCK_FILE: &str = ".neoth-skills.lock";
const INSTALL_TRANSACTION_PREFIX: &str = ".neoth-install-";
const BACKUP_TRANSACTION_PREFIX: &str = ".neoth-backup-";
const DELETE_TRANSACTION_PREFIX: &str = ".neoth-delete-";
const CREATOR_DIRECTORY_STAGE_PREFIX: &str = ".skill-create-stage-";
const CREATOR_MANIFEST_STAGE_PREFIX: &str = ".skill-yaml.stage-";
const FILE_REPLACEMENT_STAGE_PREFIX: &str = ".neoth-replace-";
static SKILL_MUTATION_LOCK: Mutex<()> = Mutex::new(());

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
    /// SHA-256 of the exact validated `skill.yaml` bytes copied into the
    /// committed generation. GUI callers bind their confirmation to it.
    pub source_manifest_sha256: String,
    /// Canonical SHA-256 over every package path, type, and file byte copied
    /// into the committed generation.
    pub source_generation_sha256: String,
    /// Exact generation replaced by this operation, or `None` for a new id.
    /// This binds the final receipt to the destination state the operator saw.
    pub replaced_generation_sha256: Option<String>,
    /// Non-fatal post-commit cleanup problems. The new skill is live when
    /// this is non-empty; CLI and GUI must surface every message.
    pub warnings: Vec<String>,
}

/// Read-only result used before a GUI asks whether an existing skill may be
/// replaced. The later install must present both fields as an expectation;
/// otherwise a changed source manifest cannot inherit the earlier consent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallPreflight {
    pub id: String,
    pub source_manifest_sha256: String,
    pub source_generation_sha256: String,
    pub replacing_existing: bool,
    pub target_generation_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallExpectation {
    pub id: String,
    pub source_generation_sha256: String,
    pub target_generation_sha256: Option<String>,
}

/// Read-only binding for one public entry below the skills root. The digest is
/// `None` only when the exact child name is absent. Directory generations are
/// content-addressed; broken file/link/reparse entries use the bounded,
/// no-follow identity described by [`installed_entry_generation_locked`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillTargetPreflight {
    pub id: String,
    pub target_generation_sha256: Option<String>,
}

/// A healthy canonical install read under the mutation lock. This is the
/// post-commit readback boundary used by GUI receipts: both hashes describe
/// the currently live `<skills>/<id>` entry, not an independently opened
/// source path which may already have been replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentSkillGeneration {
    pub id: String,
    pub manifest_sha256: String,
    pub generation_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallExpectation {
    pub id: String,
    pub target_generation_sha256: String,
}

struct ValidatedInstallSource {
    source: BoundDirectory,
    manifest: SkillManifest,
    manifest_bytes: Vec<u8>,
    manifest_sha256: String,
    generation_sha256: String,
}

fn validate_local_source(source_dir: &Path) -> Result<ValidatedInstallSource> {
    let Some(source) = open_bound_directory(source_dir, false, "skill source")? else {
        anyhow::bail!(
            "source `{}` is not a directory — pass the skill folder, not the skill.yaml",
            source_dir.display()
        );
    };
    let manifest_path = source.display_path.join("skill.yaml");
    let manifest_bytes = match read_regular_file_bounded(
        &source.dir,
        OsStr::new("skill.yaml"),
        &manifest_path,
        MAX_SKILL_MANIFEST_BYTES,
    ) {
        Ok(body) => body,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            anyhow::bail!(
                "no skill.yaml in `{}` — install source must contain a manifest",
                source.display_path.display()
            );
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read manifest at {}", manifest_path.display()));
        }
    };
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .with_context(|| format!("manifest is not UTF-8 at {}", manifest_path.display()))?;
    let manifest: SkillManifest = serde_yaml::from_str(manifest_text)
        .with_context(|| format!("parse YAML at {}", manifest_path.display()))?;
    super::creator::validate_skill_id(&manifest.id).with_context(|| {
        format!(
            "invalid skill id in {} (only lowercase [a-z0-9_-] allowed)",
            manifest_path.display()
        )
    })?;
    if manifest.description.trim().is_empty() {
        anyhow::bail!(
            "skill.yaml at `{}` has empty `description` — refuse to install",
            manifest_path.display()
        );
    }
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
    let generation_sha256 =
        skill_tree_generation_sha256(&source.dir, &source.display_path, Some(&manifest_bytes))?;
    Ok(ValidatedInstallSource {
        source,
        manifest,
        manifest_bytes,
        manifest_sha256,
        generation_sha256,
    })
}

pub(crate) fn target_generation_locked(root: &BoundDirectory, id: &str) -> Result<Option<String>> {
    let target = root.display_path.join(id);
    match root.dir.symlink_metadata(id) {
        Ok(_) => {
            let target_dir = open_real_child_dir(&root.dir, OsStr::new(id), &target)?;
            Ok(Some(skill_tree_generation_sha256(
                &target_dir,
                &target,
                None,
            )?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("inspect prior install at {}", target.display()))
        }
    }
}

fn valid_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Bind any direct public entry without following it. Healthy/repairable real
/// directories retain the canonical package-generation algorithm. If the
/// directory contains a link/special entry, or the public child itself is a
/// file/link/reparse point, a second bounded walker hashes names, entry kinds,
/// regular-file bytes, and link targets. It never opens a link target.
pub(crate) fn installed_entry_generation_locked(
    root: &BoundDirectory,
    id: &str,
) -> Result<Option<String>> {
    let display = root.display_path.join(id);
    let metadata = match root.dir.symlink_metadata(id) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect skill entry {}", display.display()));
        }
    };

    if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
        let directory = open_real_child_dir(&root.dir, OsStr::new(id), &display)?;
        if let Ok(generation) = skill_tree_generation_sha256(&directory, &display, None) {
            return Ok(Some(generation));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"NEOTH_INSTALLED_ENTRY_GENERATION\0v1\0");
        let mut budget = CopyBudget::default();
        hash_installed_entry_directory(
            &directory,
            &display,
            Path::new(""),
            0,
            &mut budget,
            &mut hasher,
        )?;
        return Ok(Some(hex::encode(hasher.finalize())));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"NEOTH_INSTALLED_ENTRY_GENERATION\0v1\0");
    hash_installed_leaf(
        &root.dir,
        OsStr::new(id),
        &display,
        Path::new(id),
        &metadata,
        &mut CopyBudget::default(),
        &mut hasher,
    )?;
    Ok(Some(hex::encode(hasher.finalize())))
}

/// Inspect one exact public target under the shared cross-process mutation
/// lock. This is intentionally separate from activation authority (R3-17).
pub fn inspect_installed_target(
    target_skills_dir: &Path,
    id: &str,
) -> Result<SkillTargetPreflight> {
    validate_installed_skill_dir_name(id)?;
    let target_generation_sha256 =
        match open_bound_directory(target_skills_dir, false, "skills root")? {
            None => None,
            Some(root) => {
                let _mutation_guard = lock_skill_mutations(&root)?;
                recover_pending_transactions_locked(&root)?;
                installed_entry_generation_locked(&root, id)?
            }
        };
    Ok(SkillTargetPreflight {
        id: id.to_string(),
        target_generation_sha256,
    })
}

/// Read the exact currently-live canonical install under the shared mutation
/// lock. Callers use this after a typed receipt to rule out accepting an old
/// source handle while a different destination generation is live.
pub fn inspect_current_install(
    target_skills_dir: &Path,
    id: &str,
) -> Result<CurrentSkillGeneration> {
    super::creator::validate_skill_id(id).context("validate installed skill id")?;
    let root = open_bound_directory(target_skills_dir, false, "skills root")?
        .with_context(|| format!("skills root is absent at {}", target_skills_dir.display()))?;
    let _mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)?;
    let display = root.display_path.join(id);
    let directory = open_real_child_dir(&root.dir, OsStr::new(id), &display)?;
    let manifest_path = display.join("skill.yaml");
    let manifest_bytes = read_regular_file_bounded(
        &directory,
        OsStr::new("skill.yaml"),
        &manifest_path,
        MAX_SKILL_MANIFEST_BYTES,
    )?;
    let manifest: SkillManifest = serde_yaml::from_slice(&manifest_bytes)
        .with_context(|| format!("parse installed manifest at {}", manifest_path.display()))?;
    if manifest.id != id {
        anyhow::bail!(
            "installed manifest id `{}` does not match canonical target `{id}`",
            manifest.id
        );
    }
    super::creator::validate_skill_id(&manifest.id).context("validate installed manifest id")?;
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
    let generation_sha256 = skill_tree_generation_sha256(&directory, &display, None)?;
    Ok(CurrentSkillGeneration {
        id: id.to_string(),
        manifest_sha256,
        generation_sha256,
    })
}

/// Validate a local source and inspect the recovered target namespace without
/// installing anything. This is the typed GUI confirmation boundary.
pub fn inspect_local_install(
    source_dir: &Path,
    target_skills_dir: &Path,
) -> Result<InstallPreflight> {
    let validated = validate_local_source(source_dir)?;
    let target_generation_sha256 =
        match open_bound_directory(target_skills_dir, false, "skills root")? {
            None => None,
            Some(root) => {
                let _mutation_guard = lock_skill_mutations(&root)?;
                recover_pending_transactions_locked(&root)?;
                target_generation_locked(&root, &validated.manifest.id)?
            }
        };
    Ok(InstallPreflight {
        id: validated.manifest.id,
        source_manifest_sha256: validated.manifest_sha256,
        source_generation_sha256: validated.generation_sha256,
        replacing_existing: target_generation_sha256.is_some(),
        target_generation_sha256,
    })
}

/// Copy `<source_dir>/skill.yaml` (+ any sibling files) into
/// `<target_skills_dir>/<id>/`, where `<id>` is the manifest's id
/// field. Validates the manifest before the copy starts — a broken
/// YAML never lands in the operator's skills dir.
///
/// `replace_existing = false` errors when the target id already exists;
/// `true` stages the replacement and keeps the prior tree available for
/// rollback until commit. Operators get the safe behaviour by default; the
/// CLI exposes `--force` to enable replacement.
pub fn install_from_local(
    source_dir: &Path,
    target_skills_dir: &Path,
    replace_existing: bool,
) -> Result<InstallReport> {
    install_from_local_with_expectation(source_dir, target_skills_dir, replace_existing, None)
}

pub fn install_from_local_with_expectation(
    source_dir: &Path,
    target_skills_dir: &Path,
    replace_existing: bool,
    expectation: Option<&InstallExpectation>,
) -> Result<InstallReport> {
    // Re-open and revalidate after any GUI confirmation. Consent is bound to
    // both the exact manifest bytes and their declared id before the target
    // namespace is opened or changed.
    let ValidatedInstallSource {
        source,
        manifest,
        manifest_bytes,
        manifest_sha256,
        generation_sha256,
    } = validate_local_source(source_dir)?;
    if let Some(expectation) = expectation {
        super::creator::validate_skill_id(&expectation.id).context("validate expected skill id")?;
        if expectation.source_generation_sha256.len() != 64
            || !expectation
                .source_generation_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            anyhow::bail!("expected generation SHA-256 must be 64 lowercase hex characters");
        }
        if expectation
            .target_generation_sha256
            .as_ref()
            .is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            anyhow::bail!("expected target generation SHA-256 must be 64 lowercase hex characters");
        }
        if expectation.id != manifest.id
            || expectation.source_generation_sha256 != generation_sha256
        {
            anyhow::bail!(
                "skill install source changed after preflight; inspect it again before installing"
            );
        }
    }

    let target_root = open_bound_directory(target_skills_dir, true, "skills root")?
        .context("created skills root is unexpectedly absent")?;
    let _mutation_guard = lock_skill_mutations(&target_root)?;
    recover_pending_transactions_locked(&target_root)?;
    let target_dir = target_root.display_path.join(&manifest.id);
    let replaced_generation_sha256 = target_generation_locked(&target_root, &manifest.id)?;
    let replacing = replaced_generation_sha256.is_some();
    if let Some(expectation) = expectation
        && expectation.target_generation_sha256 != replaced_generation_sha256
    {
        anyhow::bail!(
            "skill install destination changed after preflight; inspect it again before installing"
        );
    }
    if replacing && !replace_existing {
        anyhow::bail!(
            "skill `{}` already installed at `{}`; pass --force to replace",
            manifest.id,
            target_dir.display()
        );
    }

    // Copy into a private sibling first. A parse/read/copy failure never
    // exposes a partial skill directory and never destroys the prior install.
    let (stage_name, backup_candidate, stage_dir) =
        create_install_transaction(&target_root.dir, &manifest.id)?;
    let stage_display = target_root.display_path.join(&stage_name);
    let copy_result = copy_dir_recursive(
        &source.dir,
        &stage_dir,
        &source.display_path,
        &stage_display,
        Some(&manifest_bytes),
        0,
        &mut CopyBudget::default(),
    )
    .and_then(|()| {
        let staged = read_regular_file_bounded(
            &stage_dir,
            OsStr::new("skill.yaml"),
            &stage_display.join("skill.yaml"),
            MAX_SKILL_MANIFEST_BYTES,
        )?;
        if staged != manifest_bytes {
            anyhow::bail!("staged skill manifest differs from the validated generation");
        }
        let staged_generation = skill_tree_generation_sha256(&stage_dir, &stage_display, None)?;
        if staged_generation != generation_sha256 {
            anyhow::bail!("staged skill package differs from the preflight-validated generation");
        }
        Ok(())
    });
    drop(stage_dir);
    if let Err(copy_error) = copy_result {
        return Err(cleanup_after_failed_operation(
            copy_error,
            &target_root.dir,
            &stage_name,
            "partial skill staging directory",
        ));
    }
    sync_directory(&target_root.dir, &target_root.display_path)?;

    let mut backup_name = None;
    let mut warnings = Vec::new();
    if replacing {
        // Revalidate at the commit point, then move the prior tree aside. The
        // old install remains available for rollback until the staged tree is
        // atomically renamed into the public id.
        let prepare_backup = (|| -> Result<OsString> {
            if target_generation_locked(&target_root, &manifest.id)? != replaced_generation_sha256 {
                anyhow::bail!(
                    "skill `{}` destination changed while staging; refusing the stale replacement",
                    manifest.id
                );
            }
            drop(open_real_child_dir(
                &target_root.dir,
                OsStr::new(&manifest.id),
                &target_dir,
            )?);
            rename_child(
                &target_root.dir,
                OsStr::new(&manifest.id),
                &target_root.dir,
                &backup_candidate,
                false,
                &target_dir,
                &target_root.display_path.join(&backup_candidate),
            )
            .with_context(|| format!("stage prior install at {}", target_dir.display()))?;
            Ok(backup_candidate)
        })();
        match prepare_backup {
            Ok(candidate) => {
                backup_name = Some(candidate);
                if let Err(error) = sync_directory(&target_root.dir, &target_root.display_path) {
                    // The namespace rename already committed. Returning Err
                    // here would falsely report failure while hiding the live
                    // prior generation under its recoverable backup name.
                    warnings.push(format!(
                        "prior generation is in a recoverable backup, but that namespace transition was not durably synced: {error:#}"
                    ));
                }
            }
            Err(error) => {
                return Err(cleanup_after_failed_operation(
                    error,
                    &target_root.dir,
                    &stage_name,
                    "uncommitted skill staging directory",
                ));
            }
        }
    } else {
        match target_root.dir.symlink_metadata(&manifest.id) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                let error = anyhow::anyhow!(
                    "skill `{}` appeared at `{}` during install; refusing to replace it",
                    manifest.id,
                    target_dir.display()
                );
                return Err(cleanup_after_failed_operation(
                    error,
                    &target_root.dir,
                    &stage_name,
                    "uncommitted skill staging directory",
                ));
            }
            Err(error) => {
                let error = anyhow::Error::new(error).context(format!(
                    "recheck target before commit at {}",
                    target_dir.display()
                ));
                return Err(cleanup_after_failed_operation(
                    error,
                    &target_root.dir,
                    &stage_name,
                    "uncommitted skill staging directory",
                ));
            }
        }
    }

    if let Err(commit_error) = rename_child(
        &target_root.dir,
        &stage_name,
        &target_root.dir,
        OsStr::new(&manifest.id),
        false,
        &stage_display,
        &target_dir,
    ) {
        let mut error =
            commit_error.context(format!("commit staged skill at {}", target_dir.display()));
        if let Some(backup) = backup_name.as_ref()
            && let Err(rollback_error) = rename_child(
                &target_root.dir,
                backup,
                &target_root.dir,
                OsStr::new(&manifest.id),
                false,
                &target_root.display_path.join(backup),
                &target_dir,
            )
        {
            error = error.context(format!(
                "rollback also failed for prior install at {}: {rollback_error}",
                target_dir.display()
            ));
        } else if backup_name.is_some()
            && let Err(sync_error) = sync_directory(&target_root.dir, &target_root.display_path)
        {
            error = error.context(format!(
                "rollback restored the prior install, but syncing its directory entry failed: {sync_error:#}"
            ));
        }
        return Err(cleanup_after_failed_operation(
            error,
            &target_root.dir,
            &stage_name,
            "uncommitted skill staging directory",
        ));
    }
    let commit_namespace_durable = match sync_directory(&target_root.dir, &target_root.display_path)
    {
        Ok(()) => true,
        Err(sync_error) => {
            warnings.push(format!(
                "skill is committed and live, but its namespace durability could not be confirmed: {sync_error:#}"
            ));
            false
        }
    };
    if let Some(backup) = backup_name {
        if !commit_namespace_durable {
            // The public rename may disappear after a host interruption. Keep
            // the known-good prior generation until a later recovery pass can
            // prove which public namespace entry survived.
            warnings.push(format!(
                "prior generation `{}` was retained for crash recovery because the new namespace commit was not durably synced",
                target_root.display_path.join(&backup).display()
            ));
        } else if let Err(cleanup_error) = remove_transaction_directory(&target_root, &backup) {
            warnings.push(format!(
                "skill is installed, but cleanup of prior tree `{}` failed: {cleanup_error}",
                target_root.display_path.join(backup).display()
            ));
        } else if let Err(cleanup_error) =
            sync_directory(&target_root.dir, &target_root.display_path)
        {
            warnings.push(format!(
                "skill is installed, but transaction cleanup was not durably synced: {cleanup_error:#}"
            ));
        }
    }

    Ok(InstallReport {
        id: manifest.id,
        installed_at: target_dir,
        replaced_existing: replacing,
        source_manifest_sha256: manifest_sha256,
        source_generation_sha256: generation_sha256,
        replaced_generation_sha256,
        warnings,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallReport {
    pub id: String,
    pub removed: bool,
    /// Exact public generation removed by this operation, or `None` for an
    /// idempotent direct-CLI no-op on an already-absent id.
    pub removed_generation_sha256: Option<String>,
    /// Non-fatal durability/cleanup warnings after the public name is gone.
    pub warnings: Vec<String>,
}

/// Compatibility wrapper for internal callers that only need the desired-state
/// bit. Operator surfaces use [`uninstall_with_report`] and show warnings.
pub fn uninstall(target_skills_dir: &Path, id: &str) -> Result<bool> {
    Ok(uninstall_with_report(target_skills_dir, id)?.removed)
}

pub fn uninstall_with_report(target_skills_dir: &Path, id: &str) -> Result<UninstallReport> {
    uninstall_with_report_and_expectation(target_skills_dir, id, None)
}

pub fn uninstall_with_report_and_expectation(
    target_skills_dir: &Path,
    id: &str,
    expectation: Option<&UninstallExpectation>,
) -> Result<UninstallReport> {
    validate_installed_skill_dir_name(id)?;
    if let Some(expectation) = expectation {
        validate_installed_skill_dir_name(&expectation.id)?;
        if expectation.id != id {
            anyhow::bail!("skill uninstall expectation id does not match the requested id");
        }
        if !valid_sha256(&expectation.target_generation_sha256) {
            anyhow::bail!(
                "expected uninstall generation SHA-256 must be 64 lowercase hex characters"
            );
        }
    }

    let Some(root) = open_bound_directory(target_skills_dir, false, "skills root")? else {
        if expectation.is_some() {
            anyhow::bail!(
                "skill uninstall destination changed after preflight; inspect it again before uninstalling"
            );
        }
        return Ok(UninstallReport {
            id: id.to_string(),
            removed: false,
            removed_generation_sha256: None,
            warnings: Vec::new(),
        });
    };
    let _mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)?;
    let target = root.display_path.join(id);
    let removed_generation_sha256 = installed_entry_generation_locked(&root, id)?;
    if let Some(expectation) = expectation
        && removed_generation_sha256.as_deref()
            != Some(expectation.target_generation_sha256.as_str())
    {
        anyhow::bail!(
            "skill uninstall destination changed after preflight; inspect it again before uninstalling"
        );
    }
    let metadata = match root.dir.symlink_metadata(id) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(UninstallReport {
                id: id.to_string(),
                removed: false,
                removed_generation_sha256: None,
                warnings: Vec::new(),
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect installed skill {}", target.display()));
        }
    };

    let mut warnings = Vec::new();
    if cap_metadata_is_link_like(&metadata) || !metadata.is_dir() {
        // A broken link/reparse/file entry is itself the public object. Unlink
        // that handle-bound leaf atomically; never follow its target.
        remove_child_file(&root.dir, OsStr::new(id), &target)
            .with_context(|| format!("remove broken installed skill {}", target.display()))?;
        if let Err(error) = sync_directory(&root.dir, &root.display_path) {
            warnings.push(format!(
                "skill entry is removed, but its namespace durability could not be confirmed: {error:#}"
            ));
        }
    } else {
        // Public removal commits as one exclusive rename. Recursive cleanup is
        // performed only on the private tombstone, so a sharing/permission
        // failure can never expose a partially deleted live generation.
        let tombstone = allocate_delete_transaction_name(&root, id)?;
        let tombstone_path = root.display_path.join(&tombstone);
        rename_child(
            &root.dir,
            OsStr::new(id),
            &root.dir,
            &tombstone,
            false,
            &target,
            &tombstone_path,
        )
        .with_context(|| format!("commit uninstall of {}", target.display()))?;
        let namespace_durable = match sync_directory(&root.dir, &root.display_path) {
            Ok(()) => true,
            Err(error) => {
                warnings.push(format!(
                    "skill is removed, but its namespace durability could not be confirmed; private tombstone `{}` was retained for crash recovery: {error:#}",
                    tombstone_path.display()
                ));
                false
            }
        };
        if namespace_durable {
            if let Err(error) = remove_transaction_directory(&root, &tombstone) {
                warnings.push(format!(
                    "skill is removed, but private cleanup remains pending: {error:#}"
                ));
            } else if let Err(error) = sync_directory(&root.dir, &root.display_path) {
                warnings.push(format!(
                    "skill is removed, but tombstone cleanup was not durably synced: {error:#}"
                ));
            }
        }
    }
    Ok(UninstallReport {
        id: id.to_string(),
        removed: true,
        removed_generation_sha256,
        warnings,
    })
}

fn allocate_delete_transaction_name(root: &BoundDirectory, id: &str) -> Result<OsString> {
    for _ in 0..8 {
        let name = OsString::from(format!(
            "{DELETE_TRANSACTION_PREFIX}{id}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        match root.dir.symlink_metadata(&name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(name),
            Ok(_) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect private uninstall name `{}`",
                        name.to_string_lossy()
                    )
                });
            }
        }
    }
    anyhow::bail!("could not allocate a unique private uninstall tombstone after 8 attempts")
}

fn validate_installed_skill_dir_name(id: &str) -> Result<()> {
    if id.is_empty() || id.contains(['\0', '/', '\\', ':']) || matches!(id, "." | "..") {
        anyhow::bail!("invalid installed skill directory name `{id}`");
    }
    let mut components = Path::new(id).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        anyhow::bail!("invalid installed skill directory name `{id}`");
    }
    Ok(())
}

/// One row in the operator-facing skills list. Distinct from
/// `super::Skill` because this surface includes BROKEN entries (no
/// skill.yaml / malformed YAML) so the operator can see + fix them.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillRepairability {
    /// A real skill directory whose manifest is absent or a replaceable
    /// regular no-follow file. Creator repair can safely commit a new YAML.
    ManifestReplaceable,
    /// Files, links/reparse entries, unsafe directories, and linked/non-regular
    /// manifests can only be removed; creator repair would necessarily fail.
    RemoveOnly,
}

#[derive(Clone, Debug)]
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
    /// Parsed manifest for a healthy entry. Diagnostic inventory consumers
    /// use this without re-opening the path outside the mutation-locked
    /// snapshot.
    pub manifest: Option<SkillManifest>,
    /// `Some(message)` when manifest load failed. Empty when the
    /// manifest is healthy.
    pub error: Option<String>,
    /// Exact structural repair contract captured under the same mutation lock
    /// and no-follow directory capabilities as the rest of this snapshot.
    pub repairability: Option<SkillRepairability>,
}

/// List every entry under `<target_skills_dir>`. Includes broken ones.
/// Sorted by `dir_name` for stable output.
pub fn list_installed(target_skills_dir: &Path) -> Result<Vec<InstalledEntry>> {
    let mut out = Vec::new();
    let Some(root) = open_bound_directory(target_skills_dir, false, "skills root")? else {
        return Ok(out);
    };
    let _mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)?;
    let entries = root.dir.entries().with_context(|| {
        format!(
            "enumerate installed skills under {}",
            root.display_path.display()
        )
    })?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "read installed skill entry under {}",
                root.display_path.display()
            )
        })?;
        let name = entry.file_name();
        let dir_name = match name.to_str() {
            Some(value) if !value.starts_with('.') => value.to_string(),
            _ => continue,
        };
        let path = root.display_path.join(&name);
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                out.push(InstalledEntry {
                    dir_name,
                    path,
                    manifest_id: None,
                    manifest: None,
                    error: Some(format!("entry inspection error: {error}")),
                    repairability: Some(SkillRepairability::RemoveOnly),
                });
                continue;
            }
        };
        if file_type.is_symlink() {
            out.push(InstalledEntry {
                dir_name,
                path,
                manifest_id: None,
                manifest: None,
                error: Some("linked/reparse skill directories are not allowed".to_string()),
                repairability: Some(SkillRepairability::RemoveOnly),
            });
            continue;
        }
        if !file_type.is_dir() {
            out.push(InstalledEntry {
                dir_name,
                path,
                manifest_id: None,
                manifest: None,
                error: Some("skill entry is not a directory".to_string()),
                repairability: Some(SkillRepairability::RemoveOnly),
            });
            continue;
        }
        let skill_dir = match open_real_child_dir(&root.dir, &name, &path) {
            Ok(skill_dir) => skill_dir,
            Err(error) => {
                out.push(InstalledEntry {
                    dir_name,
                    path,
                    manifest_id: None,
                    manifest: None,
                    error: Some(format!("unsafe skill directory: {error:#}")),
                    repairability: Some(SkillRepairability::RemoveOnly),
                });
                continue;
            }
        };
        let structural_repairability = match skill_dir.symlink_metadata("skill.yaml") {
            Ok(metadata) if metadata.is_file() && !cap_metadata_is_link_like(&metadata) => {
                SkillRepairability::ManifestReplaceable
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                SkillRepairability::ManifestReplaceable
            }
            _ => SkillRepairability::RemoveOnly,
        };
        let manifest_path = path.join("skill.yaml");
        let (manifest, error) = match read_regular_file_bounded(
            &skill_dir,
            OsStr::new("skill.yaml"),
            &manifest_path,
            MAX_SKILL_MANIFEST_BYTES,
        ) {
            Ok(body) => match std::str::from_utf8(&body)
                .map_err(anyhow::Error::from)
                .and_then(|body| {
                    serde_yaml::from_str::<SkillManifest>(body).map_err(anyhow::Error::from)
                }) {
                Ok(manifest) if super::creator::validate_skill_id(&manifest.id).is_err() => (
                    None,
                    Some("manifest id is not canonical lowercase [a-z0-9_-]".to_string()),
                ),
                Ok(manifest) if manifest.id != dir_name => (
                    None,
                    Some(format!(
                        "manifest id `{}` does not match directory `{dir_name}`",
                        manifest.id
                    )),
                ),
                Ok(manifest) if manifest.description.trim().is_empty() => {
                    (None, Some("manifest description is empty".to_string()))
                }
                Ok(manifest) => (Some(manifest), None),
                Err(error) => (None, Some(format!("YAML parse error: {error}"))),
            },
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                (None, Some("no skill.yaml in directory".to_string()))
            }
            Err(error) => (None, Some(format!("read error: {error:#}"))),
        };
        let manifest_id = manifest.as_ref().map(|manifest| manifest.id.clone());
        let repairability = error.as_ref().map(|_| structural_repairability);
        out.push(InstalledEntry {
            dir_name,
            path,
            manifest_id,
            manifest,
            error,
            repairability,
        });
    }
    out.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
    Ok(out)
}

#[derive(Default)]
struct CopyBudget {
    entries: usize,
    bytes: u64,
}

pub(crate) fn skill_tree_generation_sha256(
    root: &Dir,
    display_root: &Path,
    validated_root_manifest: Option<&[u8]>,
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"NEOTH_SKILL_PACKAGE_GENERATION\0v1\0");
    let mut budget = CopyBudget::default();
    hash_skill_tree_directory(
        root,
        display_root,
        "",
        validated_root_manifest,
        0,
        &mut budget,
        &mut hasher,
    )?;
    Ok(hex::encode(hasher.finalize()))
}

fn hash_skill_tree_directory(
    directory: &Dir,
    display_directory: &Path,
    relative_prefix: &str,
    validated_root_manifest: Option<&[u8]>,
    depth: usize,
    budget: &mut CopyBudget,
    hasher: &mut Sha256,
) -> Result<()> {
    if depth > MAX_SKILL_TREE_DEPTH {
        anyhow::bail!(
            "skill tree exceeds maximum depth {MAX_SKILL_TREE_DEPTH} at {}",
            display_directory.display()
        );
    }
    let remaining_entry_budget = MAX_SKILL_ENTRIES
        .checked_sub(budget.entries)
        .context("skill package entry budget already exceeded")?;
    let entries = directory
        .entries()
        .with_context(|| format!("enumerate skill package {}", display_directory.display()))?;
    let mut names = Vec::with_capacity(remaining_entry_budget.min(64));
    for entry in entries {
        if names.len() >= remaining_entry_budget {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }
        names.push(
            entry.map(|entry| entry.file_name()).with_context(|| {
                format!("enumerate skill package {}", display_directory.display())
            })?,
        );
    }
    if validated_root_manifest.is_some()
        && !names.iter().any(|name| name == OsStr::new("skill.yaml"))
    {
        if names.len() >= remaining_entry_budget {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }
        names.push(OsString::from("skill.yaml"));
    }
    names.sort();

    for name in names {
        let name_text = name.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "skill package entry name is not UTF-8 under {}",
                display_directory.display()
            )
        })?;
        let relative = if relative_prefix.is_empty() {
            name_text.to_string()
        } else {
            format!("{relative_prefix}/{name_text}")
        };
        let display = display_directory.join(&name);
        budget.entries = budget
            .entries
            .checked_add(1)
            .context("skill package entry counter overflow")?;
        if budget.entries > MAX_SKILL_ENTRIES {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }

        if depth == 0
            && name == OsStr::new("skill.yaml")
            && let Some(bytes) = validated_root_manifest
        {
            hash_skill_file_record(hasher, &relative, bytes, budget)?;
            continue;
        }

        let file_type = directory
            .symlink_metadata(&name)
            .with_context(|| format!("inspect skill package entry {}", display.display()))?
            .file_type();
        if file_type.is_symlink() {
            anyhow::bail!(
                "skill package contains unsupported linked or reparse entry: {}",
                display.display()
            );
        }
        if file_type.is_dir() {
            hash_tree_record_header(hasher, b'D', &relative, 0)?;
            let child = open_real_child_dir(directory, &name, &display)?;
            hash_skill_tree_directory(
                &child,
                &display,
                &relative,
                None,
                depth + 1,
                budget,
                hasher,
            )?;
        } else if file_type.is_file() {
            let bytes = read_regular_file_bounded(
                directory,
                &name,
                &display,
                usize::try_from(MAX_SKILL_FILE_BYTES).expect("skill file limit fits usize"),
            )?;
            hash_skill_file_record(hasher, &relative, &bytes, budget)?;
        } else {
            anyhow::bail!(
                "skill package contains unsupported special entry: {}",
                display.display()
            );
        }
    }
    Ok(())
}

fn hash_skill_file_record(
    hasher: &mut Sha256,
    relative: &str,
    bytes: &[u8],
    budget: &mut CopyBudget,
) -> Result<()> {
    budget.bytes = budget
        .bytes
        .checked_add(bytes.len() as u64)
        .context("skill package byte counter overflow")?;
    if budget.bytes > MAX_SKILL_TOTAL_BYTES {
        anyhow::bail!("skill tree exceeds {MAX_SKILL_TOTAL_BYTES} total bytes");
    }
    hash_tree_record_header(hasher, b'F', relative, bytes.len() as u64)?;
    hasher.update(bytes);
    Ok(())
}

fn hash_tree_record_header(
    hasher: &mut Sha256,
    kind: u8,
    relative: &str,
    byte_len: u64,
) -> Result<()> {
    let path_len = u64::try_from(relative.len()).context("skill package path length overflow")?;
    hasher.update([kind]);
    hasher.update(path_len.to_le_bytes());
    hasher.update(relative.as_bytes());
    hasher.update(byte_len.to_le_bytes());
    Ok(())
}

fn hash_installed_entry_directory(
    directory: &Dir,
    display_directory: &Path,
    relative_prefix: &Path,
    depth: usize,
    budget: &mut CopyBudget,
    hasher: &mut Sha256,
) -> Result<()> {
    if depth > MAX_SKILL_TREE_DEPTH {
        anyhow::bail!(
            "installed skill entry exceeds maximum depth {MAX_SKILL_TREE_DEPTH} at {}",
            display_directory.display()
        );
    }
    let remaining = MAX_SKILL_ENTRIES
        .checked_sub(budget.entries)
        .context("installed skill entry budget already exceeded")?;
    let mut names = Vec::with_capacity(remaining.min(64));
    for entry in directory.entries().with_context(|| {
        format!(
            "enumerate installed skill entry {}",
            display_directory.display()
        )
    })? {
        if names.len() >= remaining {
            anyhow::bail!("installed skill entry exceeds {MAX_SKILL_ENTRIES} entries");
        }
        names.push(
            entry
                .with_context(|| {
                    format!(
                        "enumerate installed skill entry {}",
                        display_directory.display()
                    )
                })?
                .file_name(),
        );
    }
    names.sort();

    for name in names {
        budget.entries = budget
            .entries
            .checked_add(1)
            .context("installed skill entry counter overflow")?;
        if budget.entries > MAX_SKILL_ENTRIES {
            anyhow::bail!("installed skill entry exceeds {MAX_SKILL_ENTRIES} entries");
        }
        let display = display_directory.join(&name);
        let relative = relative_prefix.join(&name);
        let metadata = directory
            .symlink_metadata(&name)
            .with_context(|| format!("inspect installed skill entry {}", display.display()))?;
        if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
            hash_installed_record_header(hasher, b'D', &relative, 0)?;
            let child = open_real_child_dir(directory, &name, &display)?;
            hash_installed_entry_directory(&child, &display, &relative, depth + 1, budget, hasher)?;
        } else {
            hash_installed_leaf(
                directory, &name, &display, &relative, &metadata, budget, hasher,
            )?;
        }
    }
    Ok(())
}

fn hash_installed_leaf(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
    relative: &Path,
    metadata: &cap_std::fs::Metadata,
    budget: &mut CopyBudget,
    hasher: &mut Sha256,
) -> Result<()> {
    if metadata.is_file() && !cap_metadata_is_link_like(metadata) {
        let bytes = read_regular_file_bounded(
            parent,
            name,
            display,
            usize::try_from(MAX_SKILL_FILE_BYTES).expect("skill file limit fits usize"),
        )?;
        budget.bytes = budget
            .bytes
            .checked_add(bytes.len() as u64)
            .context("installed skill entry byte counter overflow")?;
        if budget.bytes > MAX_SKILL_TOTAL_BYTES {
            anyhow::bail!("installed skill entry exceeds {MAX_SKILL_TOTAL_BYTES} total bytes");
        }
        hash_installed_record_header(hasher, b'F', relative, bytes.len() as u64)?;
        hasher.update(&bytes);
        return Ok(());
    }

    if cap_metadata_is_link_like(metadata) || metadata.file_type().is_symlink() {
        match parent.read_link(name) {
            Ok(target) => {
                let target_bytes = os_string_bytes(target.as_os_str());
                hash_installed_record_header(hasher, b'L', relative, target_bytes.len() as u64)?;
                hasher.update(target_bytes);
            }
            Err(_) => {
                // Some Windows reparse kinds do not expose a symbolic-link
                // target. Bind the no-follow metadata instead of opening the
                // reparse target or pretending the entry is absent.
                hash_installed_record_header(hasher, b'R', relative, metadata.len())?;
                hash_metadata_fingerprint(hasher, metadata);
            }
        }
        return Ok(());
    }

    hash_installed_record_header(hasher, b'X', relative, metadata.len())?;
    hash_metadata_fingerprint(hasher, metadata);
    Ok(())
}

fn hash_installed_record_header(
    hasher: &mut Sha256,
    kind: u8,
    relative: &Path,
    byte_len: u64,
) -> Result<()> {
    let path_bytes = os_string_bytes(relative.as_os_str());
    let path_len =
        u64::try_from(path_bytes.len()).context("installed entry path length overflow")?;
    hasher.update([kind]);
    hasher.update(path_len.to_le_bytes());
    hasher.update(path_bytes);
    hasher.update(byte_len.to_le_bytes());
    Ok(())
}

fn hash_metadata_fingerprint(hasher: &mut Sha256, metadata: &cap_std::fs::Metadata) {
    hasher.update(metadata.len().to_le_bytes());
    hasher.update([u8::from(metadata.permissions().readonly())]);
    for timestamp in [metadata.modified(), metadata.created()] {
        match timestamp
            .ok()
            .and_then(|value| value.into_std().duration_since(std::time::UNIX_EPOCH).ok())
        {
            Some(value) => {
                hasher.update([1]);
                hasher.update(value.as_secs().to_le_bytes());
                hasher.update(value.subsec_nanos().to_le_bytes());
            }
            None => hasher.update([0]),
        }
    }
}

#[cfg(unix)]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, windows)))]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

/// Recursively copy one already-bound source directory into one already-bound
/// private stage. All opens are no-follow and handle-relative. At the root,
/// `skill.yaml` is written from the exact bytes that passed validation so a
/// concurrent source edit cannot install a different manifest generation.
fn copy_dir_recursive(
    source: &Dir,
    destination: &Dir,
    source_display: &Path,
    destination_display: &Path,
    validated_root_manifest: Option<&[u8]>,
    depth: usize,
    budget: &mut CopyBudget,
) -> Result<()> {
    if depth > MAX_SKILL_TREE_DEPTH {
        anyhow::bail!(
            "skill tree exceeds maximum depth {MAX_SKILL_TREE_DEPTH} at {}",
            source_display.display()
        );
    }

    if let Some(manifest) = validated_root_manifest {
        if manifest.len() > MAX_SKILL_MANIFEST_BYTES {
            anyhow::bail!(
                "skill manifest exceeds {MAX_SKILL_MANIFEST_BYTES} bytes at {}",
                source_display.join("skill.yaml").display()
            );
        }
        write_regular_file_create_new(
            destination,
            OsStr::new("skill.yaml"),
            manifest,
            &destination_display.join("skill.yaml"),
        )?;
        budget.entries = budget
            .entries
            .checked_add(1)
            .context("skill copy entry counter overflow")?;
        if budget.entries > MAX_SKILL_ENTRIES {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }
        budget.bytes = budget
            .bytes
            .checked_add(manifest.len() as u64)
            .context("skill copy byte counter overflow")?;
        if budget.bytes > MAX_SKILL_TOTAL_BYTES {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_TOTAL_BYTES} total bytes");
        }
    }

    let entries = source
        .entries()
        .with_context(|| format!("enumerate skill source {}", source_display.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("enumerate {}", source_display.display()))?;
        let name = entry.file_name();
        if validated_root_manifest.is_some() && name == OsStr::new("skill.yaml") {
            continue;
        }
        budget.entries = budget
            .entries
            .checked_add(1)
            .context("skill copy entry counter overflow")?;
        if budget.entries > MAX_SKILL_ENTRIES {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }

        let from_display = source_display.join(&name);
        let to_display = destination_display.join(&name);
        // The store's crash-recovery artifacts own these prefixes. A package
        // entry must never occupy that namespace.
        if let Some(entry_name) = name.to_str()
            && let Some(prefix) = RESERVED_SKILL_ENTRY_PREFIXES
                .iter()
                .find(|prefix| entry_name.starts_with(**prefix))
        {
            anyhow::bail!(
                "skill package entry uses the reserved private-artifact prefix `{prefix}`: {}",
                from_display.display()
            );
        }
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect skill source entry {}", from_display.display()))?;
        if file_type.is_symlink() {
            anyhow::bail!(
                "skill package contains unsupported linked or reparse entry: {}",
                from_display.display()
            );
        }
        if file_type.is_dir() {
            let source_child = source.open_dir_nofollow(&name).with_context(|| {
                format!(
                    "open source directory without following links {}",
                    from_display.display()
                )
            })?;
            ensure_real_cap_directory(&source_child, &from_display, "skill source directory")?;
            create_private_directory(destination, &name, &to_display)?;
            let destination_child = destination.open_dir_nofollow(&name).with_context(|| {
                format!(
                    "open destination directory without following links {}",
                    to_display.display()
                )
            })?;
            ensure_real_cap_directory(
                &destination_child,
                &to_display,
                "skill destination directory",
            )?;
            copy_dir_recursive(
                &source_child,
                &destination_child,
                &from_display,
                &to_display,
                None,
                depth + 1,
                budget,
            )?;
        } else if file_type.is_file() {
            copy_regular_file_create_new(
                source,
                destination,
                &name,
                &from_display,
                &to_display,
                budget,
            )?;
        } else {
            anyhow::bail!(
                "skill package contains unsupported special entry: {}",
                from_display.display()
            );
        }
    }
    sync_directory(destination, destination_display)
}

fn copy_regular_file_create_new(
    source: &Dir,
    destination: &Dir,
    name: &OsStr,
    source_display: &Path,
    target_display: &Path,
    budget: &mut CopyBudget,
) -> Result<()> {
    let input = open_regular_file(source, name, source_display)?;
    let metadata = input
        .metadata()
        .with_context(|| format!("inspect skill source {}", source_display.display()))?;
    if metadata.len() > MAX_SKILL_FILE_BYTES {
        anyhow::bail!(
            "skill file exceeds {MAX_SKILL_FILE_BYTES} bytes: {}",
            source_display.display()
        );
    }

    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut output = destination
        .open_with(name, &options)
        .with_context(|| format!("create skill target {}", target_display.display()))?;
    let mut limited = input.take(MAX_SKILL_FILE_BYTES.saturating_add(1));
    let copied = std::io::copy(&mut limited, &mut output).with_context(|| {
        format!(
            "copy {} → {}",
            source_display.display(),
            target_display.display()
        )
    })?;
    if copied > MAX_SKILL_FILE_BYTES {
        anyhow::bail!(
            "skill file grew beyond {MAX_SKILL_FILE_BYTES} bytes while copying: {}",
            source_display.display()
        );
    }
    budget.bytes = budget
        .bytes
        .checked_add(copied)
        .context("skill copy byte counter overflow")?;
    if budget.bytes > MAX_SKILL_TOTAL_BYTES {
        anyhow::bail!("skill tree exceeds {MAX_SKILL_TOTAL_BYTES} total bytes");
    }
    output
        .set_permissions(metadata.permissions())
        .with_context(|| {
            format!(
                "set permissions on skill target {}",
                target_display.display()
            )
        })?;
    output
        .sync_all()
        .with_context(|| format!("sync skill target {}", target_display.display()))?;
    Ok(())
}

fn write_regular_file_create_new(
    destination: &Dir,
    name: &OsStr,
    bytes: &[u8],
    target_display: &Path,
) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut output = destination
        .open_with(name, &options)
        .with_context(|| format!("create skill target {}", target_display.display()))?;
    std::io::Write::write_all(&mut output, bytes)
        .with_context(|| format!("write skill target {}", target_display.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync skill target {}", target_display.display()))?;
    Ok(())
}

fn create_private_directory(parent: &Dir, name: &OsStr, display_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt as _;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(name, &builder)
            .with_context(|| format!("create private directory {}", display_path.display()))?;
    }
    #[cfg(not(unix))]
    {
        parent
            .create_dir(name)
            .with_context(|| format!("create private directory {}", display_path.display()))?;
    }
    Ok(())
}

fn ensure_real_cap_directory(dir: &Dir, display_path: &Path, label: &str) -> Result<()> {
    let metadata = dir
        .dir_metadata()
        .with_context(|| format!("inspect {label} {}", display_path.display()))?;
    if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "{label} is linked or not a directory: {}",
            display_path.display()
        );
    }
    Ok(())
}

fn create_install_transaction(root: &Dir, id: &str) -> Result<(OsString, OsString, Dir)> {
    for _ in 0..8 {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let stage_name = OsString::from(format!("{INSTALL_TRANSACTION_PREFIX}{id}-{nonce}"));
        let backup_name = OsString::from(format!("{BACKUP_TRANSACTION_PREFIX}{id}-{nonce}"));
        match root.symlink_metadata(&backup_name) {
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect private skill backup name `{}`",
                        backup_name.to_string_lossy()
                    )
                });
            }
        }
        match create_private_directory(root, &stage_name, Path::new(&stage_name)) {
            Ok(()) => {
                let dir = root.open_dir_nofollow(&stage_name).with_context(|| {
                    format!(
                        "open private skill stage `{}`",
                        stage_name.to_string_lossy()
                    )
                })?;
                ensure_real_cap_directory(&dir, Path::new(&stage_name), "private skill stage")?;
                return Ok((stage_name, backup_name, dir));
            }
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error),
        }
    }
    anyhow::bail!("could not allocate a unique private skill stage after 8 attempts")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionArtifactKind {
    Stage,
    Backup,
}

#[derive(Default)]
struct PendingTransaction {
    stages: Vec<OsString>,
    backups: Vec<OsString>,
}

/// Recover interrupted skill installs without consulting ambient paths.
///
/// Recovery deliberately prefers a known-live backup over an uncommitted
/// stage. A stage can survive a crash during its recursive copy, whereas a
/// backup is only created after the staged tree and its directory entries have
/// been synced. If the public id already exists, it is the committed winner.
/// Ambiguous duplicate backups fail closed instead of selecting an arbitrary
/// prior generation.
pub fn recover_pending_transactions(target_skills_dir: &Path) -> Result<()> {
    let Some(root) = open_bound_directory(target_skills_dir, false, "skills root")? else {
        return Ok(());
    };
    let _mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)
}

pub(crate) fn recover_pending_transactions_locked(root: &BoundDirectory) -> Result<()> {
    let mut pending = BTreeMap::<String, PendingTransaction>::new();
    let mut delete_tombstones = Vec::<OsString>::new();
    let mut creator_directory_stages = Vec::<OsString>::new();
    let mut public_skill_directories = Vec::<OsString>::new();
    let entries = root.dir.entries().with_context(|| {
        format!(
            "enumerate pending skill transactions under {}",
            root.display_path.display()
        )
    })?;
    let mut root_entry_count = 0usize;
    for entry in entries {
        root_entry_count = root_entry_count
            .checked_add(1)
            .context("skill recovery entry counter overflow")?;
        if root_entry_count > MAX_SKILL_ENTRIES {
            anyhow::bail!(
                "skill recovery under {} exceeds the {MAX_SKILL_ENTRIES}-entry limit",
                root.display_path.display()
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "read pending skill transaction under {}",
                root.display_path.display()
            )
        })?;
        let name = entry.file_name();
        if matches_private_stage_marker(&name, CREATOR_DIRECTORY_STAGE_PREFIX, &root.display_path) {
            let display_path = root.display_path.join(&name);
            drop(
                open_real_child_dir(&root.dir, &name, &display_path).with_context(|| {
                    format!(
                        "creator stage must be a real directory: {}",
                        display_path.display()
                    )
                })?,
            );
            creator_directory_stages.push(name);
            continue;
        }
        if parse_delete_transaction_artifact(&name)?.is_some() {
            let display_path = root.display_path.join(&name);
            drop(
                open_real_child_dir(&root.dir, &name, &display_path).with_context(|| {
                    format!(
                        "pending uninstall tombstone must be a real directory: {}",
                        display_path.display()
                    )
                })?,
            );
            delete_tombstones.push(name);
            continue;
        }
        let Some((kind, id)) = parse_transaction_artifact(&name)? else {
            if name.as_encoded_bytes().first() != Some(&b'.')
                && entry.file_type().is_ok_and(|file_type| file_type.is_dir())
            {
                public_skill_directories.push(name);
            }
            continue;
        };
        let display_path = root.display_path.join(&name);
        drop(
            open_real_child_dir(&root.dir, &name, &display_path).with_context(|| {
                format!(
                    "pending skill transaction must be a real directory: {}",
                    display_path.display()
                )
            })?,
        );
        let transaction = pending.entry(id).or_default();
        match kind {
            TransactionArtifactKind::Stage => transaction.stages.push(name),
            TransactionArtifactKind::Backup => transaction.backups.push(name),
        }
    }

    // A tombstone is the only recoverable proof that the public uninstall
    // rename happened. Persist that rename before deleting the tombstone;
    // otherwise a crash can resurrect the public name after recovery already
    // discarded the only private generation.
    if !delete_tombstones.is_empty() {
        sync_directory(&root.dir, &root.display_path)?;
    }
    for stage in &creator_directory_stages {
        remove_transaction_directory(root, stage)?;
    }
    for tombstone in &delete_tombstones {
        remove_transaction_directory(root, tombstone)?;
    }
    if !creator_directory_stages.is_empty() || !delete_tombstones.is_empty() {
        sync_directory(&root.dir, &root.display_path)?;
    }

    for name in public_skill_directories {
        let display_path = root.display_path.join(&name);
        let Ok(directory) = open_real_child_dir(&root.dir, &name, &display_path) else {
            // Unsafe public entries remain visible as BROKEN and removable;
            // recovery must not follow them merely to search for private files.
            continue;
        };
        cleanup_private_file_stages(&directory, &display_path)?;
    }

    for (id, mut transaction) in pending {
        transaction.stages.sort();
        transaction.backups.sort();
        let public_path = root.display_path.join(&id);
        let public_exists = match root.dir.symlink_metadata(&id) {
            Ok(_) => {
                drop(open_real_child_dir(
                    &root.dir,
                    OsStr::new(&id),
                    &public_path,
                )?);
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect skill during recovery {}", public_path.display())
                });
            }
        };

        if !public_exists {
            match transaction.backups.as_slice() {
                [] => {}
                [backup] => {
                    rename_child(
                        &root.dir,
                        backup,
                        &root.dir,
                        OsStr::new(&id),
                        false,
                        &root.display_path.join(backup),
                        &public_path,
                    )
                    .with_context(|| {
                        format!(
                            "restore interrupted skill backup {} to {}",
                            root.display_path.join(backup).display(),
                            public_path.display()
                        )
                    })?;
                    sync_directory(&root.dir, &root.display_path)?;
                    transaction.backups.clear();
                }
                backups => {
                    anyhow::bail!(
                        "cannot recover skill `{id}`: {} backup generations are present under {}",
                        backups.len(),
                        root.display_path.display()
                    );
                }
            }
        }

        // When a public generation and a private rollback generation coexist,
        // first make the observed winner + rollback namespace durable. Only
        // then may recovery discard the rollback tree.
        if public_exists && (!transaction.stages.is_empty() || !transaction.backups.is_empty()) {
            sync_directory(&root.dir, &root.display_path)?;
        }
        for artifact in transaction.stages.iter().chain(transaction.backups.iter()) {
            remove_transaction_directory(root, artifact)?;
        }
        if !transaction.stages.is_empty() || !transaction.backups.is_empty() {
            sync_directory(&root.dir, &root.display_path)?;
        }
    }
    Ok(())
}

/// What one directory entry is, relative to a private stage-marker prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateStageMarker {
    /// Exactly one of ours — recover it.
    Ours,
    /// Carries the reserved prefix but not the 32-hex nonce. NOT one of ours:
    /// recovery must neither act on it nor guess what it was.
    Malformed,
    /// Unrelated entry.
    Foreign,
}

/// Classify a private crash-recovery artifact by its fixed-shape marker.
///
/// The marker prevents transaction-name collisions; it is not a credential.
/// Malformed names are untrusted filesystem input and are never copied into
/// diagnostics a caller may persist.
///
/// A malformed marker is reported, not fatal. Failing the store on it was a
/// self-inflicted denial of service: skill packages are externally sourced, the
/// install copy was name-agnostic, and recovery runs `?`-propagated ahead of
/// every store read — so a single package file named `.skill-yaml.stage-readme`
/// wedged `neoth serve`, `neoth chat`, the inventory AND the uninstall that
/// could have removed it, leaving no in-product repair path. Planting one is now
/// refused at install time (see [`RESERVED_SKILL_ENTRY_PREFIXES`]); an entry
/// that still appears is left untouched for the operator.
fn classify_private_stage_marker(name: &OsStr, prefix: &str) -> PrivateStageMarker {
    let Some(name) = name.to_str() else {
        return PrivateStageMarker::Foreign;
    };
    let Some(nonce) = name.strip_prefix(prefix) else {
        return PrivateStageMarker::Foreign;
    };
    if nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        PrivateStageMarker::Ours
    } else {
        PrivateStageMarker::Malformed
    }
}

/// True only for an artifact this store owns. A malformed marker is reported
/// once — WITHOUT echoing the untrusted name — and then ignored.
fn matches_private_stage_marker(name: &OsStr, prefix: &str, directory: &Path) -> bool {
    match classify_private_stage_marker(name, prefix) {
        PrivateStageMarker::Ours => true,
        PrivateStageMarker::Malformed => {
            tracing::warn!(
                directory = %directory.display(),
                prefix,
                "ignoring a foreign entry that carries a reserved private skill stage prefix \
                 with a malformed nonce; it is not a recoverable transaction"
            );
            false
        }
        PrivateStageMarker::Foreign => false,
    }
}

/// Reserved private-artifact prefixes that a skill package may never carry.
///
/// Rejected at install time so a foreign file can never occupy the namespace
/// this store's crash recovery owns.
const RESERVED_SKILL_ENTRY_PREFIXES: [&str; 3] = [
    CREATOR_DIRECTORY_STAGE_PREFIX,
    CREATOR_MANIFEST_STAGE_PREFIX,
    FILE_REPLACEMENT_STAGE_PREFIX,
];

fn cleanup_private_file_stages(directory: &Dir, display_directory: &Path) -> Result<()> {
    let entries = directory.entries().with_context(|| {
        format!(
            "enumerate private skill stages under {}",
            display_directory.display()
        )
    })?;
    let mut stages = Vec::new();
    let mut entry_count = 0usize;
    for entry in entries {
        entry_count = entry_count
            .checked_add(1)
            .context("private skill stage entry counter overflow")?;
        if entry_count > MAX_SKILL_ENTRIES {
            anyhow::bail!(
                "private stage recovery under {} exceeds the {MAX_SKILL_ENTRIES}-entry limit",
                display_directory.display()
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "read private skill stage under {}",
                display_directory.display()
            )
        })?;
        let name = entry.file_name();
        if matches_private_stage_marker(&name, CREATOR_MANIFEST_STAGE_PREFIX, display_directory)
            || matches_private_stage_marker(&name, FILE_REPLACEMENT_STAGE_PREFIX, display_directory)
        {
            let metadata = directory.symlink_metadata(&name).with_context(|| {
                format!(
                    "inspect private skill stage {}",
                    display_directory.join(&name).display()
                )
            })?;
            if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "private skill file stage is unexpectedly a directory: {}",
                    display_directory.join(&name).display()
                );
            }
            stages.push(name);
        }
    }
    for stage in stages.iter() {
        remove_child_file(directory, stage, &display_directory.join(stage))?;
    }
    if !stages.is_empty() {
        sync_directory(directory, display_directory)?;
    }
    Ok(())
}

fn parse_delete_transaction_artifact(name: &OsStr) -> Result<Option<String>> {
    let Some(name) = name.to_str() else {
        return Ok(None);
    };
    let Some(body) = name.strip_prefix(DELETE_TRANSACTION_PREFIX) else {
        return Ok(None);
    };
    let Some((id, nonce)) = body.rsplit_once('-') else {
        anyhow::bail!("malformed pending skill uninstall name `{name}`");
    };
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("malformed pending skill uninstall nonce in `{name}`");
    }
    validate_installed_skill_dir_name(id)
        .with_context(|| format!("malformed pending skill uninstall id in `{name}`"))?;
    Ok(Some(id.to_string()))
}

fn parse_transaction_artifact(name: &OsStr) -> Result<Option<(TransactionArtifactKind, String)>> {
    let Some(name) = name.to_str() else {
        return Ok(None);
    };
    let (kind, body) = if let Some(body) = name.strip_prefix(INSTALL_TRANSACTION_PREFIX) {
        (TransactionArtifactKind::Stage, body)
    } else if let Some(body) = name.strip_prefix(BACKUP_TRANSACTION_PREFIX) {
        (TransactionArtifactKind::Backup, body)
    } else {
        return Ok(None);
    };
    let Some((id, nonce)) = body.rsplit_once('-') else {
        anyhow::bail!("malformed pending skill transaction name `{name}`");
    };
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("malformed pending skill transaction nonce in `{name}`");
    }
    super::creator::validate_skill_id(id)
        .with_context(|| format!("malformed pending skill transaction id in `{name}`"))?;
    Ok(Some((kind, id.to_string())))
}

fn remove_transaction_directory(root: &BoundDirectory, name: &OsStr) -> Result<()> {
    let display_path = root.display_path.join(name);
    drop(
        open_real_child_dir(&root.dir, name, &display_path).with_context(|| {
            format!(
                "refuse to remove unsafe pending skill transaction {}",
                display_path.display()
            )
        })?,
    );
    remove_real_directory_tree(&root.dir, name, &display_path).with_context(|| {
        format!(
            "remove pending skill transaction {}",
            display_path.display()
        )
    })
}

fn sync_directory(directory: &Dir, display_path: &Path) -> Result<()> {
    #[cfg(test)]
    TEST_SYNC_FAILURES.with(|remaining| {
        let count = remaining.get();
        if count > 0 {
            remaining.set(count - 1);
            anyhow::bail!(
                "injected skill directory sync failure for {}",
                display_path.display()
            );
        }
        Ok(())
    })?;
    #[cfg(unix)]
    {
        directory
            .open(".")
            .and_then(|file| file.sync_all())
            .with_context(|| format!("sync skill directory {}", display_path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (directory, display_path);
    Ok(())
}

#[cfg(test)]
thread_local! {
    static TEST_SYNC_FAILURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn fail_next_directory_syncs(count: usize) {
    TEST_SYNC_FAILURES.with(|remaining| remaining.set(count));
}

fn cleanup_after_failed_operation(
    error: anyhow::Error,
    root: &Dir,
    child: &OsStr,
    label: &str,
) -> anyhow::Error {
    match remove_real_directory_tree(root, child, Path::new(child)) {
        Ok(()) => error,
        Err(cleanup_error)
            if cleanup_error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            error
        }
        Err(cleanup_error) => error.context(format!(
            "cleanup of {label} `{}` also failed: {cleanup_error}",
            child.to_string_lossy()
        )),
    }
}

pub(crate) struct SkillMutationGuard {
    _process: MutexGuard<'static, ()>,
    _file: std::fs::File,
}

pub(crate) fn lock_skill_mutations(root: &BoundDirectory) -> Result<SkillMutationGuard> {
    let process = SKILL_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let started = std::time::Instant::now();
    loop {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            options.share_mode(FILE_SHARE_READ);
        }
        let file = match root.dir.open_with(SKILL_MUTATION_LOCK_FILE, &options) {
            Ok(file) => file,
            #[cfg(windows)]
            Err(error) if error.raw_os_error() == Some(32) => {
                if started.elapsed() >= std::time::Duration::from_secs(5) {
                    anyhow::bail!(
                        "skills mutation lock held for >5s at {}",
                        root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "open skills mutation lock {}",
                        root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
                    )
                });
            }
        };
        let metadata = file.metadata().context("inspect skills mutation lock")?;
        if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "skills mutation lock is not a real regular file: {}",
                root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
            );
        }
        let file = file.into_std();
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            // SAFETY: flock is called on a live owned regular-file descriptor.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < std::time::Duration::from_secs(5)
                {
                    drop(file);
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    anyhow::bail!(
                        "skills mutation lock held for >5s at {}",
                        root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
                    );
                }
                return Err(error).with_context(|| {
                    format!(
                        "lock skills mutation file {}",
                        root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
                    )
                });
            }
        }
        return Ok(SkillMutationGuard {
            _process: process,
            _file: file,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

    fn transaction_names(id: &str) -> (String, String) {
        let nonce = "0123456789abcdef0123456789abcdef";
        (
            format!("{INSTALL_TRANSACTION_PREFIX}{id}-{nonce}"),
            format!("{BACKUP_TRANSACTION_PREFIX}{id}-{nonce}"),
        )
    }

    #[test]
    fn second_os_process_is_blocked_by_the_held_skill_mutation_lock() {
        // GOLD-R3-11 cross-process regression: prove the capability-bound store
        // mutation lock serialises SEPARATE OS PROCESSES (the Unix flock /
        // Windows share-mode open), not merely threads sharing the in-process
        // mutex — thread-only evidence does not establish the Windows/macOS/
        // Linux release claim.
        //
        // Child mode: this same test is re-execed by the parent with the shared
        // directory in the environment; it attempts the lock and exits 0 when it
        // acquires, 3 when it is blocked.
        const CHILD_ENV: &str = "NEOTH_SKILL_LOCK_CHILD";
        const TEST_PATH: &str = "skills::installer::tests::second_os_process_is_blocked_by_the_held_skill_mutation_lock";

        if let Ok(shared) = std::env::var(CHILD_ENV) {
            let root = open_bound_directory(Path::new(&shared), true, "skills")
                .expect("child: open bound dir")
                .expect("child: bound dir present");
            match lock_skill_mutations(&root) {
                Ok(_guard) => std::process::exit(0),
                Err(_) => std::process::exit(3),
            }
        }

        let dir = tempdir().unwrap();
        let shared = dir.path();
        let root = open_bound_directory(shared, true, "skills")
            .unwrap()
            .expect("parent: bound dir present");

        // Parent holds the lock across the child's entire attempt.
        let guard = lock_skill_mutations(&root).expect("parent acquires the lock");
        let blocked = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_PATH])
            .env(CHILD_ENV, shared)
            .output()
            .expect("spawn blocked child");
        assert_eq!(
            blocked.status.code(),
            Some(3),
            "a second OS process must NOT acquire the lock while it is held (stderr: {})",
            String::from_utf8_lossy(&blocked.stderr)
        );
        drop(guard);

        // Lock released → a second OS process can now acquire it.
        let acquired = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_PATH])
            .env(CHILD_ENV, shared)
            .output()
            .expect("spawn acquiring child");
        assert_eq!(
            acquired.status.code(),
            Some(0),
            "once released a second OS process must acquire the lock (stderr: {})",
            String::from_utf8_lossy(&acquired.stderr)
        );
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
    fn install_from_local_rejects_a_linked_source_root() {
        let parent = tempdir().unwrap();
        let outside = tempdir().unwrap();
        write_skill(outside.path(), "linked-source", &good_yaml("linked-source"));
        let linked_source = parent.path().join("source");
        try_symlink_dir(outside.path(), &linked_source)
            .expect("create linked source-root test fixture");
        let dest = tempdir().unwrap();

        let error = install_from_local(&linked_source, dest.path(), false).unwrap_err();
        assert!(format!("{error:#}").contains("skill source must be a real directory"));
        assert!(!dest.path().join("linked-source").exists());
    }

    #[test]
    fn install_from_local_rejects_linked_sibling_directories() {
        let staging = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let source = staging.path().join("source");
        write_skill(&source, "linked-child", &good_yaml("linked-child"));
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        try_symlink_dir(outside.path(), &source.join("linked-assets"))
            .expect("create linked child test fixture");

        let error = install_from_local(&source, dest.path(), false).unwrap_err();

        assert!(format!("{error:#}").contains("unsupported linked or reparse entry"));
        assert!(!dest.path().join("linked-child").exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn install_expectation_binds_every_package_file() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let source = staging.path().join("source");
        write_skill(&source, "bound-package", &good_yaml("bound-package"));
        std::fs::write(source.join("README.md"), b"generation one").unwrap();

        let preflight = inspect_local_install(&source, dest.path()).unwrap();
        assert_eq!(preflight.id, "bound-package");
        assert_eq!(preflight.source_manifest_sha256.len(), 64);
        assert_eq!(preflight.source_generation_sha256.len(), 64);
        std::fs::write(source.join("README.md"), b"generation two").unwrap();

        let error = install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            Some(&InstallExpectation {
                id: preflight.id,
                source_generation_sha256: preflight.source_generation_sha256,
                target_generation_sha256: preflight.target_generation_sha256,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("source changed after preflight"));
        assert!(!dest.path().join("bound-package").exists());
    }

    #[test]
    fn install_report_matches_the_preflight_generation() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let source = staging.path().join("source");
        write_skill(&source, "bound-package", &good_yaml("bound-package"));
        std::fs::create_dir(source.join("assets")).unwrap();
        std::fs::write(source.join("assets").join("payload.bin"), b"payload").unwrap();

        let preflight = inspect_local_install(&source, dest.path()).unwrap();
        let report = install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            Some(&InstallExpectation {
                id: preflight.id.clone(),
                source_generation_sha256: preflight.source_generation_sha256.clone(),
                target_generation_sha256: preflight.target_generation_sha256.clone(),
            }),
        )
        .unwrap();

        assert_eq!(report.id, preflight.id);
        assert_eq!(
            report.source_manifest_sha256,
            preflight.source_manifest_sha256
        );
        assert_eq!(
            report.source_generation_sha256,
            preflight.source_generation_sha256
        );
        assert_eq!(
            report.replaced_generation_sha256,
            preflight.target_generation_sha256
        );
    }

    #[test]
    fn replacement_expectation_rejects_a_destination_generation_that_changed() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let source = staging.path().join("source");
        write_skill(&source, "bound-target", &good_yaml("bound-target"));
        std::fs::write(source.join("asset.txt"), b"new generation").unwrap();
        let installed = dest.path().join("bound-target");
        write_skill(&installed, "bound-target", &good_yaml("bound-target"));
        std::fs::write(installed.join("asset.txt"), b"old generation").unwrap();

        let preflight = inspect_local_install(&source, dest.path()).unwrap();
        assert!(preflight.replacing_existing);
        assert!(preflight.target_generation_sha256.is_some());
        std::fs::write(installed.join("asset.txt"), b"concurrent generation").unwrap();

        let error = install_from_local_with_expectation(
            &source,
            dest.path(),
            true,
            Some(&InstallExpectation {
                id: preflight.id,
                source_generation_sha256: preflight.source_generation_sha256,
                target_generation_sha256: preflight.target_generation_sha256,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("destination changed after preflight"));
        assert_eq!(
            std::fs::read(installed.join("asset.txt")).unwrap(),
            b"concurrent generation"
        );
    }

    #[test]
    fn generation_walk_rejects_an_entry_before_exceeding_its_collection_budget() {
        let source = tempdir().unwrap();
        std::fs::write(source.path().join("one-more-entry"), b"payload").unwrap();
        let bound = open_bound_directory(source.path(), false, "generation budget fixture")
            .unwrap()
            .unwrap();
        let mut budget = CopyBudget {
            entries: MAX_SKILL_ENTRIES,
            bytes: 0,
        };
        let mut hasher = Sha256::new();

        let error = hash_skill_tree_directory(
            &bound.dir,
            &bound.display_path,
            "",
            None,
            0,
            &mut budget,
            &mut hasher,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("exceeds 4096 entries"));
        assert_eq!(budget.entries, MAX_SKILL_ENTRIES);
    }

    #[test]
    fn failed_force_install_preserves_the_prior_tree_and_cleans_the_stage() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let original = staging.path().join("original");
        write_skill(&original, "bounded", &good_yaml("bounded"));
        std::fs::write(original.join("VERSION"), b"old").unwrap();
        install_from_local(&original, dest.path(), false).unwrap();

        let oversized = staging.path().join("oversized");
        write_skill(&oversized, "bounded", &good_yaml("bounded"));
        let oversized_file = std::fs::File::create(oversized.join("payload.bin")).unwrap();
        oversized_file.set_len(MAX_SKILL_FILE_BYTES + 1).unwrap();

        let error = install_from_local(&oversized, dest.path(), true).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds"));
        assert_eq!(
            std::fs::read(dest.path().join("bounded").join("VERSION")).unwrap(),
            b"old"
        );
        let leaked_stages = std::fs::read_dir(dest.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-install-bounded-")
            })
            .count();
        assert_eq!(leaked_stages, 0);
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_a_fifo_manifest_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let source = tempdir().unwrap();
        let manifest = source.path().join("skill.yaml");
        let manifest_c = CString::new(manifest.as_os_str().as_bytes()).unwrap();
        // SAFETY: `manifest_c` is a valid NUL-terminated path and mode is
        // limited to owner read/write for this private temporary directory.
        let result = unsafe { libc::mkfifo(manifest_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
        let dest = tempdir().unwrap();

        let error = install_from_local(source.path(), dest.path(), false).unwrap_err();
        assert!(format!("{error:#}").contains("expected a real regular file"));
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
    fn list_recovery_keeps_public_generation_and_cleans_committed_artifacts() {
        let dest = tempdir().unwrap();
        let (stage_name, backup_name) = transaction_names("recoverable");
        let public = dest.path().join("recoverable");
        write_skill(&public, "recoverable", &good_yaml("recoverable"));
        std::fs::write(public.join("VERSION"), b"new").unwrap();
        let backup = dest.path().join(&backup_name);
        write_skill(&backup, "recoverable", &good_yaml("recoverable"));
        std::fs::write(backup.join("VERSION"), b"old").unwrap();
        let stage = dest.path().join(&stage_name);
        write_skill(&stage, "recoverable", &good_yaml("recoverable"));

        let rows = list_installed(dest.path()).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dir_name, "recoverable");
        assert_eq!(std::fs::read(public.join("VERSION")).unwrap(), b"new");
        assert!(!backup.exists());
        assert!(!stage.exists());
    }

    #[test]
    fn recovery_retains_backup_until_public_namespace_sync_succeeds() {
        let dest = tempdir().unwrap();
        let (_, backup_name) = transaction_names("recoverable");
        let public = dest.path().join("recoverable");
        write_skill(&public, "recoverable", &good_yaml("recoverable"));
        std::fs::write(public.join("VERSION"), b"new").unwrap();
        let backup = dest.path().join(&backup_name);
        write_skill(&backup, "recoverable", &good_yaml("recoverable"));
        std::fs::write(backup.join("VERSION"), b"old").unwrap();

        fail_next_directory_syncs(1);
        let error = recover_pending_transactions(dest.path()).unwrap_err();

        assert!(format!("{error:#}").contains("injected skill directory sync failure"));
        assert!(public.exists(), "the observed public winner remains live");
        assert!(
            backup.exists(),
            "the only rollback generation must survive a failed parent sync"
        );

        recover_pending_transactions(dest.path()).unwrap();
        assert!(public.exists());
        assert!(!backup.exists());
    }

    #[test]
    fn list_recovery_restores_backup_when_crash_left_public_id_missing() {
        let dest = tempdir().unwrap();
        let (stage_name, backup_name) = transaction_names("recoverable");
        let backup = dest.path().join(&backup_name);
        write_skill(&backup, "recoverable", &good_yaml("recoverable"));
        std::fs::write(backup.join("VERSION"), b"old").unwrap();
        let stage = dest.path().join(&stage_name);
        write_skill(&stage, "recoverable", &good_yaml("recoverable"));
        std::fs::write(stage.join("VERSION"), b"new").unwrap();

        let rows = list_installed(dest.path()).unwrap();

        let public = dest.path().join("recoverable");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dir_name, "recoverable");
        assert_eq!(std::fs::read(public.join("VERSION")).unwrap(), b"old");
        assert!(!backup.exists());
        assert!(!stage.exists());
    }

    #[test]
    fn list_recovery_discards_stage_only_interrupted_copy() {
        let dest = tempdir().unwrap();
        let (stage_name, _) = transaction_names("incomplete");
        let stage = dest.path().join(&stage_name);
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("partial.bin"), b"partial").unwrap();

        let rows = list_installed(dest.path()).unwrap();

        assert!(rows.is_empty());
        assert!(!stage.exists());
        assert!(!dest.path().join("incomplete").exists());
    }

    #[test]
    fn install_recovers_backup_before_checking_replace_policy() {
        let source_root = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let source = source_root.path().join("source");
        write_skill(&source, "recoverable", &good_yaml("recoverable"));
        std::fs::write(source.join("VERSION"), b"new").unwrap();
        let (stage_name, backup_name) = transaction_names("recoverable");
        let backup = dest.path().join(&backup_name);
        write_skill(&backup, "recoverable", &good_yaml("recoverable"));
        std::fs::write(backup.join("VERSION"), b"old").unwrap();
        write_skill(
            &dest.path().join(&stage_name),
            "recoverable",
            &good_yaml("recoverable"),
        );

        let error = install_from_local(&source, dest.path(), false).unwrap_err();

        assert!(format!("{error:#}").contains("already installed"));
        assert_eq!(
            std::fs::read(dest.path().join("recoverable").join("VERSION")).unwrap(),
            b"old"
        );
        assert!(!backup.exists());
        assert!(!dest.path().join(stage_name).exists());
    }

    #[test]
    fn uninstall_recovers_backup_before_removal() {
        let dest = tempdir().unwrap();
        let (stage_name, backup_name) = transaction_names("recoverable");
        write_skill(
            &dest.path().join(&backup_name),
            "recoverable",
            &good_yaml("recoverable"),
        );
        write_skill(
            &dest.path().join(&stage_name),
            "recoverable",
            &good_yaml("recoverable"),
        );

        assert!(uninstall(dest.path(), "recoverable").unwrap());
        assert!(!dest.path().join("recoverable").exists());
        assert!(!dest.path().join(backup_name).exists());
        assert!(!dest.path().join(stage_name).exists());
    }

    #[test]
    fn uninstall_retains_tombstone_when_namespace_sync_fails() {
        let dest = tempdir().unwrap();
        let public = dest.path().join("doomed");
        write_skill(&public, "doomed", &good_yaml("doomed"));
        std::fs::write(public.join("sentinel"), b"recoverable").unwrap();

        fail_next_directory_syncs(1);
        let report = uninstall_with_report(dest.path(), "doomed").unwrap();

        assert!(report.removed);
        assert!(!public.exists());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("retained for crash recovery"))
        );
        let tombstones = std::fs::read_dir(dest.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with(DELETE_TRANSACTION_PREFIX)
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(
            std::fs::read(tombstones[0].join("sentinel")).unwrap(),
            b"recoverable"
        );

        recover_pending_transactions(dest.path()).unwrap();
        assert!(!tombstones[0].exists());
    }

    #[test]
    fn recovery_fails_closed_on_ambiguous_backup_generations() {
        let dest = tempdir().unwrap();
        for nonce in [
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        ] {
            write_skill(
                &dest
                    .path()
                    .join(format!("{BACKUP_TRANSACTION_PREFIX}ambiguous-{nonce}")),
                "ambiguous",
                &good_yaml("ambiguous"),
            );
        }

        let error = list_installed(dest.path()).unwrap_err();

        assert!(format!("{error:#}").contains("2 backup generations"));
        assert!(!dest.path().join("ambiguous").exists());
    }

    #[test]
    fn recovery_refuses_linked_transaction_artifacts() {
        let dest = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let (stage_name, _) = transaction_names("linked");
        try_symlink_dir(outside.path(), &dest.path().join(stage_name))
            .expect("create linked transaction fixture");

        let error = list_installed(dest.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("pending skill transaction must be a real directory")
        );
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
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
        let chain = format!("{err:#}");
        assert!(
            chain.contains("invalid skill id") && chain.contains("must not be empty"),
            "empty id must be rejected by validate_skill_id: {chain}"
        );
    }

    #[test]
    fn install_from_local_rejects_path_traversal_id() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let src = staging.path().join("evil_source");
        std::fs::create_dir_all(&src).unwrap();
        // Malicious manifest id that would escape the skills dir.
        std::fs::write(
            src.join("skill.yaml"),
            "id: \"../../pwned\"\ndescription: evil\nsystem_prompt: x\n",
        )
        .unwrap();
        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(
            err.to_string().contains("invalid skill id"),
            "traversal id must be rejected: {err}"
        );
        // Nothing was written outside the target skills dir.
        assert!(!dest.path().join("..").join("pwned").exists());
        assert!(!dest.path().join("pwned").exists());
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
    fn stale_uninstall_expectation_preserves_a_changed_healthy_generation() {
        let dest = tempdir().unwrap();
        let target = dest.path().join("healthy");
        write_skill(&target, "healthy", &good_yaml("healthy"));
        std::fs::write(target.join("asset.txt"), b"first").unwrap();
        let preflight = inspect_installed_target(dest.path(), "healthy").unwrap();
        let expected = preflight.target_generation_sha256.unwrap();

        std::fs::write(target.join("asset.txt"), b"changed after confirmation").unwrap();
        let error = uninstall_with_report_and_expectation(
            dest.path(),
            "healthy",
            Some(&UninstallExpectation {
                id: "healthy".to_string(),
                target_generation_sha256: expected,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("changed after preflight"));
        assert_eq!(
            std::fs::read(target.join("asset.txt")).unwrap(),
            b"changed after confirmation"
        );
    }

    #[test]
    fn stale_uninstall_expectation_preserves_a_changed_broken_entry() {
        let dest = tempdir().unwrap();
        let target = dest.path().join("broken");
        std::fs::write(&target, b"first broken generation").unwrap();
        let preflight = inspect_installed_target(dest.path(), "broken").unwrap();
        let expected = preflight.target_generation_sha256.unwrap();

        std::fs::write(&target, b"changed broken generation").unwrap();
        let error = uninstall_with_report_and_expectation(
            dest.path(),
            "broken",
            Some(&UninstallExpectation {
                id: "broken".to_string(),
                target_generation_sha256: expected,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("changed after preflight"));
        assert_eq!(std::fs::read(target).unwrap(), b"changed broken generation");
    }

    #[test]
    fn uninstall_rejects_ids_that_can_escape_the_skills_root() {
        let dest = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();

        for id in [
            "",
            "..",
            "../outside",
            "nested/skill",
            "nested\\skill",
            "skill:stream",
        ] {
            let error = uninstall(dest.path(), id).unwrap_err();
            assert!(
                format!("{error:#}").contains("invalid installed skill directory name"),
                "unexpected error for {id:?}: {error:#}"
            );
        }
        let absolute = outside.path().to_string_lossy();
        let error = uninstall(dest.path(), &absolute).unwrap_err();
        assert!(format!("{error:#}").contains("invalid installed skill directory name"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn uninstall_accepts_safe_legacy_directory_names() {
        let dest = tempdir().unwrap();
        let target = dest.path().join("legacy skill.β");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("skill.yaml"), "id: legacy skill.β\n").unwrap();

        assert!(uninstall(dest.path(), "legacy skill.β").unwrap());
        assert!(!target.exists());
    }

    #[test]
    fn uninstall_unlinks_broken_skill_directories_without_following_them() {
        let dest = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let linked = dest.path().join("linked-skill");
        try_symlink_dir(outside.path(), &linked).expect("create directory link test fixture");

        let report = uninstall_with_report(dest.path(), "linked-skill").unwrap();

        assert!(report.removed);
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
        assert!(std::fs::symlink_metadata(linked).is_err());
    }

    #[test]
    fn broken_file_entry_is_visible_and_removable() {
        let dest = tempdir().unwrap();
        let broken = dest.path().join("broken-file");
        std::fs::write(&broken, b"not a skill directory").unwrap();

        let rows = list_installed(dest.path()).unwrap();
        let row = rows
            .iter()
            .find(|row| row.dir_name == "broken-file")
            .expect("broken file must remain operator-visible");
        assert_eq!(row.error.as_deref(), Some("skill entry is not a directory"));
        assert_eq!(row.repairability, Some(SkillRepairability::RemoveOnly));

        let report = uninstall_with_report(dest.path(), "broken-file").unwrap();
        assert!(report.removed);
        assert!(!broken.exists());
    }

    #[test]
    fn uninstall_rejects_a_linked_skills_root() {
        let parent = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        let sentinel = victim.join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let linked_root = parent.path().join("skills");
        try_symlink_dir(outside.path(), &linked_root)
            .expect("create linked skills-root test fixture");

        let error = uninstall(&linked_root, "victim").unwrap_err();
        assert!(format!("{error:#}").contains("skills root must be a real directory"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn fresh_install_rejects_a_linked_skills_root() {
        let staging = tempdir().unwrap();
        let parent = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let linked_root = parent.path().join("skills");
        try_symlink_dir(outside.path(), &linked_root)
            .expect("create linked skills-root test fixture");
        let source = staging.path().join("source");
        write_skill(&source, "new-skill", &good_yaml("new-skill"));

        let error = install_from_local(&source, &linked_root, false).unwrap_err();
        assert!(format!("{error:#}").contains("skills root must be a real directory"));
        assert!(!outside.path().join("new-skill").exists());
    }

    #[test]
    fn recursive_remove_does_not_follow_a_swapped_target_link() {
        let dest = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let target = dest.path().join("victim");
        std::fs::create_dir(&target).unwrap();

        let root = open_bound_directory(dest.path(), false, "test skills root")
            .unwrap()
            .unwrap();
        drop(open_real_child_dir(&root.dir, OsStr::new("victim"), &target).unwrap());
        std::fs::remove_dir(&target).unwrap();
        try_symlink_dir(outside.path(), &target).expect("create swapped target test fixture");

        let _ = root.dir.remove_dir_all("victim");
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn file_copy_refuses_a_preexisting_target_alias() {
        let source_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let source = source_dir.path().join("source.txt");
        let target = target_dir.path().join("source.txt");
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&source, b"replacement").unwrap();
        std::fs::write(&sentinel, b"keep").unwrap();
        std::fs::hard_link(&sentinel, &target).unwrap();

        let source_root = open_bound_directory(source_dir.path(), false, "test source")
            .unwrap()
            .unwrap();
        let target_root = open_bound_directory(target_dir.path(), false, "test target")
            .unwrap()
            .unwrap();
        let error = copy_regular_file_create_new(
            &source_root.dir,
            &target_root.dir,
            OsStr::new("source.txt"),
            &source,
            &target,
            &mut CopyBudget::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("create skill target"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn forced_reinstall_rejects_linked_target_directories() {
        let staging = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let linked = dest.path().join("linked-skill");
        try_symlink_dir(outside.path(), &linked).expect("create directory link test fixture");
        let source = staging.path().join("source");
        write_skill(&source, "linked-skill", &good_yaml("linked-skill"));

        let error = install_from_local(&source, dest.path(), true).unwrap_err();
        assert!(format!("{error:#}").contains("real directory"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
        assert!(std::fs::symlink_metadata(linked).is_ok());
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

        let rows = list_installed(dest.path()).unwrap();
        assert_eq!(rows.len(), 3);

        let h = rows.iter().find(|r| r.dir_name == "healthy").unwrap();
        assert_eq!(h.manifest_id.as_deref(), Some("healthy"));
        assert!(h.error.is_none());

        let n = rows.iter().find(|r| r.dir_name == "no_manifest").unwrap();
        assert!(n.manifest_id.is_none());
        assert!(n.error.as_ref().unwrap().contains("no skill.yaml"));
        assert_eq!(
            n.repairability,
            Some(SkillRepairability::ManifestReplaceable)
        );

        let b = rows.iter().find(|r| r.dir_name == "broken_yaml").unwrap();
        assert!(b.manifest_id.is_none());
        assert!(b.error.as_ref().unwrap().contains("YAML parse error"));
        assert_eq!(
            b.repairability,
            Some(SkillRepairability::ManifestReplaceable)
        );
    }

    #[test]
    fn list_installed_returns_empty_for_missing_dir() {
        let dest = tempdir().unwrap();
        let rows = list_installed(&dest.path().join("nope")).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn list_installed_skips_private_dotfiles_but_surfaces_public_files() {
        let dest = tempdir().unwrap();
        // Hidden dir
        std::fs::create_dir_all(dest.path().join(".hidden")).unwrap();
        // Plain file
        std::fs::write(dest.path().join("loose.txt"), b"x").unwrap();
        let rows = list_installed(dest.path()).unwrap();
        assert_eq!(rows.len(), 1, "expected exactly one public broken entry");
        assert_eq!(rows[0].dir_name, "loose.txt");
        assert_eq!(
            rows[0].error.as_deref(),
            Some("skill entry is not a directory")
        );
    }

    #[test]
    fn recovery_cleans_creator_directory_and_private_file_stages() {
        let dest = tempdir().unwrap();
        let nonce = "0123456789abcdef0123456789abcdef";
        let creator_stage = dest
            .path()
            .join(format!("{CREATOR_DIRECTORY_STAGE_PREFIX}{nonce}"));
        std::fs::create_dir(&creator_stage).unwrap();
        std::fs::write(creator_stage.join("partial"), b"partial").unwrap();

        let public = dest.path().join("healthy");
        write_skill(&public, "healthy", &good_yaml("healthy"));
        let manifest_stage = public.join(format!("{CREATOR_MANIFEST_STAGE_PREFIX}{nonce}"));
        let replacement_stage = public.join(format!("{FILE_REPLACEMENT_STAGE_PREFIX}{nonce}"));
        std::fs::write(&manifest_stage, b"staged manifest").unwrap();
        std::fs::write(&replacement_stage, b"staged replacement").unwrap();

        let rows = list_installed(dest.path()).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dir_name, "healthy");
        assert!(!creator_stage.exists());
        assert!(!manifest_stage.exists());
        assert!(!replacement_stage.exists());
    }

    #[test]
    fn recovery_finishes_private_uninstall_tombstones() {
        let dest = tempdir().unwrap();
        let nonce = "0123456789abcdef0123456789abcdef";
        let tombstone = dest
            .path()
            .join(format!("{DELETE_TRANSACTION_PREFIX}doomed-{nonce}"));
        write_skill(&tombstone, "doomed", &good_yaml("doomed"));
        std::fs::write(tombstone.join("sentinel"), b"private").unwrap();

        let rows = list_installed(dest.path()).unwrap();

        assert!(rows.is_empty());
        assert!(!tombstone.exists());
    }

    #[test]
    fn recovery_accepts_the_same_safe_broken_names_as_uninstall() {
        let dest = tempdir().unwrap();
        let nonce = "0123456789abcdef0123456789abcdef";
        let tombstone = dest
            .path()
            .join(format!("{DELETE_TRANSACTION_PREFIX}Broken Skill-{nonce}"));
        std::fs::create_dir(&tombstone).unwrap();
        std::fs::write(tombstone.join("sentinel"), b"private").unwrap();

        recover_pending_transactions(dest.path()).unwrap();

        assert!(!tombstone.exists());
    }

    #[test]
    fn recovery_retains_uninstall_tombstone_until_parent_sync_succeeds() {
        let dest = tempdir().unwrap();
        let nonce = "0123456789abcdef0123456789abcdef";
        let tombstone = dest
            .path()
            .join(format!("{DELETE_TRANSACTION_PREFIX}doomed-{nonce}"));
        write_skill(&tombstone, "doomed", &good_yaml("doomed"));

        fail_next_directory_syncs(1);
        let error = recover_pending_transactions(dest.path()).unwrap_err();

        assert!(format!("{error:#}").contains("injected skill directory sync failure"));
        assert!(
            tombstone.exists(),
            "recovery must not discard the uninstall proof before a parent sync"
        );

        recover_pending_transactions(dest.path()).unwrap();
        assert!(!tombstone.exists());
    }

    #[test]
    fn recovery_ignores_noncanonical_private_transaction_nonces() {
        // A non-canonical nonce is NOT one of our transactions: recovery must
        // neither act on it nor guess. It must also not fail the store — that
        // turned one foreign entry into a permanent product-wide outage with no
        // in-product repair path (external review PR5-001).
        let dest = tempdir().unwrap();
        let uppercase = "0123456789ABCDEF0123456789ABCDEF";
        let stage = dest
            .path()
            .join(format!("{CREATOR_DIRECTORY_STAGE_PREFIX}{uppercase}"));
        std::fs::create_dir(&stage).unwrap();
        write_skill(
            &dest.path().join("healthy"),
            "healthy",
            &good_yaml("healthy"),
        );

        let rows = list_installed(dest.path()).expect("a foreign entry must not fail the store");
        assert!(
            rows.iter().any(|row| row.dir_name == "healthy"),
            "the healthy skill must still be inventoried: {rows:?}"
        );
        assert!(
            stage.exists(),
            "an entry we do not own must be left untouched for the operator"
        );
        assert_eq!(
            classify_private_stage_marker(
                std::ffi::OsStr::new(&format!("{CREATOR_DIRECTORY_STAGE_PREFIX}{uppercase}")),
                CREATOR_DIRECTORY_STAGE_PREFIX
            ),
            PrivateStageMarker::Malformed
        );
    }

    #[test]
    fn install_refuses_a_package_entry_with_a_reserved_private_prefix() {
        // The planting vector for PR5-001: the install copy was name-agnostic,
        // so a package could drop a file into the namespace the store's crash
        // recovery owns.
        for prefix in RESERVED_SKILL_ENTRY_PREFIXES {
            let staging = tempdir().unwrap();
            let dest = tempdir().unwrap();
            let source = staging.path().join("planted");
            write_skill(&source, "planted", &good_yaml("planted"));
            std::fs::write(source.join(format!("{prefix}readme")), b"x").unwrap();

            let error = install_from_local(&source, dest.path(), false)
                .expect_err("a reserved prefix must be refused at install time");
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("reserved private-artifact prefix"),
                "unexpected error for {prefix}: {rendered}"
            );
        }
    }
}
