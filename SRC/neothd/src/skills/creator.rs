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
//!
//! The store lock serializes cooperating NEOTH processes. It deliberately
//! does not claim to isolate the store from another hostile process already
//! running as the same OS user; that process can directly modify the user's
//! skill files outside NEOTH.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest as _, Sha256};

use crate::skills::schema::SkillManifest;
use crate::skills::store::{
    cap_metadata_is_link_like, open_bound_directory, open_real_child_dir, open_regular_file,
    read_regular_file_bounded, remove_child_file, remove_real_directory_tree, rename_child,
};

const MAX_SKILL_MANIFEST_BYTES: usize = 1024 * 1024;

/// Parameters gathered from CLI flags or interactive prompts.
#[derive(Debug, Clone)]
pub struct CreateParams {
    pub id: String,
    pub description: String,
    pub keywords: Vec<String>,
    pub system_prompt: String,
}

/// Existing-id policy for every skill-manifest writer. Callers must choose;
/// there is deliberately no implicit overwrite default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingSkillPolicy {
    /// Preserve an existing skill byte-for-byte and return an error.
    Refuse,
    /// Treat an already-identical manifest as an idempotent success, but
    /// preserve and reject every differing or broken existing generation.
    KeepIfIdentical,
    /// Atomically replace only the existing `skill.yaml`, preserving sibling
    /// assets in the skill directory.
    Replace,
}

/// Report returned after a successful create.
#[derive(Debug, Clone)]
pub struct CreateReport {
    pub id: String,
    pub path: PathBuf,
    /// Digest of the exact canonical YAML generation committed at `path`.
    pub manifest_sha256: String,
    /// Exact generation live at `<skills>/<id>` after the create/replace.
    pub target_generation_sha256: String,
    /// Exact public generation replaced by this operation, or `None` when the
    /// id was absent. This is an identity receipt, not activation authority.
    pub replaced_generation_sha256: Option<String>,
    pub replaced_existing: bool,
    /// Non-fatal durability warnings after the public rename committed.
    pub warnings: Vec<String>,
}

/// Typed destination expectation captured after the GUI click and before its
/// replacement confirmation. `None` binds an absent public child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateExpectation {
    pub id: String,
    pub target_generation_sha256: Option<String>,
}

// ── Pure builder (testable without dialoguer / filesystem) ────────────

/// Validate the canonical skill id: non-empty, `[a-z0-9_-]`, ≤ 64 chars. Matches
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
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        anyhow::bail!("skill id may only contain lowercase [a-z0-9_-]: {id}");
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
        model: None,
        paths: vec![],
        effort: None,
        loop_trigger: false,
        visibility: Default::default(),
    };

    let yaml = serde_yaml::to_string(&manifest).context("serialise SkillManifest to YAML")?;
    // Round-trip guard: the loader must be able to read what we write.
    let _back: SkillManifest = serde_yaml::from_str(&yaml)
        .context("round-trip parse failed — serde_yaml produced unreadable YAML")?;
    Ok((manifest, yaml))
}

/// Write `<skills_dir>/<id>/skill.yaml` transactionally, creating the id
/// directory when needed. Every namespace lookup below the bound skills root
/// is handle-relative and no-follow. Existing sibling assets are left in
/// place. Existing manifests follow the mandatory `existing` policy. Returns
/// a typed report recording whether this operation replaced one.
pub fn write_skill_yaml(
    skills_dir: &Path,
    id: &str,
    yaml: &str,
    existing: ExistingSkillPolicy,
) -> Result<CreateReport> {
    write_skill_yaml_with_expectation(skills_dir, id, yaml, existing, None)
}

pub fn write_skill_yaml_with_expectation(
    skills_dir: &Path,
    id: &str,
    yaml: &str,
    existing: ExistingSkillPolicy,
    expectation: Option<&CreateExpectation>,
) -> Result<CreateReport> {
    validate_skill_id(id)?;
    if yaml.len() > MAX_SKILL_MANIFEST_BYTES {
        anyhow::bail!("skill manifest exceeds the {MAX_SKILL_MANIFEST_BYTES}-byte limit");
    }
    let manifest: SkillManifest =
        serde_yaml::from_str(yaml).context("parse skill manifest before writing")?;
    if manifest.id != id {
        anyhow::bail!(
            "skill manifest id `{}` does not match target directory `{id}`",
            manifest.id
        );
    }
    if manifest.description.trim().is_empty() {
        anyhow::bail!("skill manifest description must not be empty");
    }
    let manifest_sha256 = hex::encode(Sha256::digest(yaml.as_bytes()));
    if let Some(expectation) = expectation {
        validate_skill_id(&expectation.id).context("validate expected create id")?;
        if expectation.id != id {
            anyhow::bail!("skill create expectation id does not match the requested id");
        }
        if expectation
            .target_generation_sha256
            .as_deref()
            .is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            anyhow::bail!(
                "expected create target generation SHA-256 must be 64 lowercase hex characters"
            );
        }
    }

    let root = open_bound_directory(skills_dir, true, "skills root")?
        .context("created skills root is unexpectedly absent")?;
    let _mutation_guard = super::installer::lock_skill_mutations(&root)?;
    // Installer and creator share one namespace and lock. Recover any
    // interrupted install before deciding whether this id exists or whether
    // replacement is permitted; otherwise a missing public id could make a
    // staged create overwrite the recoverable prior generation.
    super::installer::recover_pending_transactions_locked(&root)?;
    let skill_display = root.display_path.join(id);
    let replaced_generation_sha256 =
        super::installer::installed_entry_generation_locked(&root, id)?;
    if let Some(expectation) = expectation
        && expectation.target_generation_sha256 != replaced_generation_sha256
    {
        anyhow::bail!(
            "skill create destination changed after preflight; inspect it again before creating"
        );
    }

    let (replaced_existing, warnings) = match root.dir.symlink_metadata(id) {
        Ok(_) => {
            let skill_dir = open_real_child_dir(&root.dir, OsStr::new(id), &skill_display)?;
            match existing {
                ExistingSkillPolicy::Refuse => {
                    anyhow::bail!(
                        "skill `{id}` already exists at `{}`; pass --force to replace",
                        skill_display.display()
                    );
                }
                ExistingSkillPolicy::KeepIfIdentical => {
                    let manifest_display = skill_display.join("skill.yaml");
                    let current = read_regular_file_bounded(
                        &skill_dir,
                        OsStr::new("skill.yaml"),
                        &manifest_display,
                        MAX_SKILL_MANIFEST_BYTES,
                    )?;
                    if current != yaml.as_bytes() {
                        anyhow::bail!(
                            "skill `{id}` already exists with a different manifest at `{}`; explicit replacement preflight is required",
                            manifest_display.display()
                        );
                    }
                    return Ok(CreateReport {
                        id: id.to_string(),
                        path: manifest_display,
                        manifest_sha256,
                        target_generation_sha256: replaced_generation_sha256.clone().context(
                            "identical installed skill generation is unexpectedly absent",
                        )?,
                        replaced_generation_sha256: None,
                        replaced_existing: false,
                        warnings: Vec::new(),
                    });
                }
                ExistingSkillPolicy::Replace => {}
            }
            let warnings = replace_manifest_in_skill(&skill_dir, &skill_display, yaml.as_bytes())?;
            (true, warnings)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let warnings =
                create_skill_directory(&root.dir, &root.display_path, id, yaml.as_bytes())?;
            (false, warnings)
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect skill directory {}", skill_display.display()));
        }
    };

    let target_generation_sha256 = super::installer::installed_entry_generation_locked(&root, id)?
        .context("created skill generation is unexpectedly absent")?;

    Ok(CreateReport {
        id: id.to_string(),
        path: skill_display.join("skill.yaml"),
        manifest_sha256,
        target_generation_sha256,
        replaced_generation_sha256,
        replaced_existing,
        warnings,
    })
}

fn replace_manifest_in_skill(
    skill_dir: &Dir,
    display_dir: &Path,
    yaml: &[u8],
) -> Result<Vec<String>> {
    let target = OsStr::new("skill.yaml");
    let target_display = display_dir.join(target);
    let target_permissions = match skill_dir.symlink_metadata(target) {
        Ok(metadata) => {
            if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "existing skill manifest must be a real regular file: {}",
                    target_display.display()
                );
            }
            let opened = open_regular_file(skill_dir, target, &target_display)?;
            Some(
                opened
                    .metadata()
                    .with_context(|| format!("inspect {}", target_display.display()))?
                    .permissions(),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!(
                "inspect existing manifest {}",
                target_display.display()
            )));
        }
    };
    let replace_existing = target_permissions.is_some();
    let (stage_name, stage_display) =
        write_staged_manifest(skill_dir, display_dir, yaml, target_permissions)?;
    sync_directory(skill_dir, display_dir)?;

    // The fully-written stage becomes the public manifest in one filesystem
    // operation; a failed rename leaves the old manifest untouched. Windows
    // commits by the opened source handle rather than an ambient path.
    if let Err(error) = rename_child(
        skill_dir,
        &stage_name,
        skill_dir,
        target,
        replace_existing,
        &stage_display,
        &target_display,
    ) {
        return Err(cleanup_staged_file(
            error,
            skill_dir,
            &stage_name,
            &stage_display,
        ));
    }
    Ok(post_commit_sync_warnings(
        sync_directory(skill_dir, display_dir),
        "skill manifest is replaced, but its directory entry was not durably synced",
    ))
}

fn create_skill_directory(
    root: &Dir,
    display_root: &Path,
    id: &str,
    yaml: &[u8],
) -> Result<Vec<String>> {
    let (stage_name, stage_dir) = create_private_stage_directory(root, display_root)?;
    let stage_display = display_root.join(&stage_name);
    let prepare_result = write_manifest_create_new(&stage_dir, &stage_display, yaml)
        .and_then(|()| sync_directory(&stage_dir, &stage_display))
        .and_then(|()| sync_directory(root, display_root));
    // Windows will not rename or recursively remove a directory while this
    // no-follow capability handle remains open without delete sharing. Close
    // it before every commit and cleanup branch; the source generation is
    // reopened by rename_child through its bound parent capability.
    drop(stage_dir);
    if let Err(error) = prepare_result {
        return Err(cleanup_staged_directory(
            error,
            root,
            &stage_name,
            display_root,
        ));
    }
    // Even `Replace` only authorizes replacement of an id observed before
    // staging. If an unrelated process creates this previously-absent id in
    // the meantime, never let a directory rename replace it.
    match root.symlink_metadata(id) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            let error = anyhow::anyhow!(
                "skill `{id}` appeared at `{}` during create; refusing to replace it",
                display_root.join(id).display()
            );
            return Err(cleanup_staged_directory(
                error,
                root,
                &stage_name,
                display_root,
            ));
        }
        Err(error) => {
            let error = anyhow::Error::new(error).context(format!(
                "recheck skill directory before commit {}",
                display_root.join(id).display()
            ));
            return Err(cleanup_staged_directory(
                error,
                root,
                &stage_name,
                display_root,
            ));
        }
    }
    let target_display = display_root.join(id);
    if let Err(error) = rename_child(
        root,
        &stage_name,
        root,
        OsStr::new(id),
        false,
        &stage_display,
        &target_display,
    ) {
        return Err(cleanup_staged_directory(
            error,
            root,
            &stage_name,
            display_root,
        ));
    }
    Ok(post_commit_sync_warnings(
        sync_directory(root, display_root),
        "skill is created, but its public directory entry was not durably synced",
    ))
}

fn post_commit_sync_warnings(sync_result: Result<()>, context: &str) -> Vec<String> {
    match sync_result {
        Ok(()) => Vec::new(),
        Err(error) => vec![format!("{context}: {error:#}")],
    }
}

/// Persist directory-entry changes on Unix. Windows intentionally has no
/// claim here: Rust/cap-std exposes no supported equivalent of directory
/// `fsync`, and this code does not invent a `FlushFileBuffers` guarantee.
fn sync_directory(directory: &Dir, display_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        Dir::reopen_dir(directory)
            .and_then(|dir| dir.into_std_file().sync_all())
            .with_context(|| format!("sync skill directory {}", display_path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (directory, display_path);
    Ok(())
}

fn write_staged_manifest(
    skill_dir: &Dir,
    display_dir: &Path,
    yaml: &[u8],
    permissions: Option<cap_std::fs::Permissions>,
) -> Result<(OsString, PathBuf)> {
    for _ in 0..8 {
        let name = OsString::from(format!(
            ".skill-yaml.stage-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let display = display_dir.join(&name);
        match write_file_create_new(skill_dir, &name, &display, yaml, permissions.clone()) {
            Ok(()) => return Ok((name, display)),
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error),
        }
    }
    anyhow::bail!("could not allocate a unique staged skill manifest after 8 attempts")
}

fn write_manifest_create_new(skill_dir: &Dir, display_dir: &Path, yaml: &[u8]) -> Result<()> {
    let display = display_dir.join("skill.yaml");
    write_file_create_new(skill_dir, OsStr::new("skill.yaml"), &display, yaml, None)
}

fn write_file_create_new(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
    bytes: &[u8],
    permissions: Option<cap_std::fs::Permissions>,
) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = parent
        .open_with(name, &options)
        .with_context(|| format!("create staged skill manifest {}", display.display()))?;
    let write_result = std::io::Write::write_all(&mut file, bytes)
        .with_context(|| format!("write staged skill manifest {}", display.display()))
        .and_then(|()| {
            if let Some(permissions) = permissions {
                file.set_permissions(permissions)
                    .with_context(|| format!("preserve permissions for {}", display.display()))?;
            }
            Ok(())
        })
        .and_then(|()| {
            file.sync_all()
                .with_context(|| format!("sync staged skill manifest {}", display.display()))
        });
    drop(file);
    if let Err(error) = write_result {
        return Err(cleanup_staged_file(error, parent, name, display));
    }
    let written = match read_regular_file_bounded(parent, name, display, MAX_SKILL_MANIFEST_BYTES) {
        Ok(written) => written,
        Err(error) => return Err(cleanup_staged_file(error, parent, name, display)),
    };
    if written != bytes {
        return Err(cleanup_staged_file(
            anyhow::anyhow!(
                "staged skill manifest changed before commit: {}",
                display.display()
            ),
            parent,
            name,
            display,
        ));
    }
    Ok(())
}

fn create_private_stage_directory(root: &Dir, display_root: &Path) -> Result<(OsString, Dir)> {
    for _ in 0..8 {
        let name = OsString::from(format!(
            ".skill-create-stage-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let display = display_root.join(&name);
        let created = create_private_directory(root, &name, &display);
        match created {
            Ok(()) => {
                let dir = open_real_child_dir(root, &name, &display)?;
                return Ok((name, dir));
            }
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error),
        }
    }
    anyhow::bail!("could not allocate a unique staged skill directory after 8 attempts")
}

fn create_private_directory(parent: &Dir, name: &OsStr, display: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::{DirBuilder, DirBuilderExt as _};
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(name, &builder)
            .with_context(|| format!("create private skill directory {}", display.display()))?;
    }
    #[cfg(not(unix))]
    {
        parent
            .create_dir(name)
            .with_context(|| format!("create private skill directory {}", display.display()))?;
    }
    Ok(())
}

fn cleanup_staged_file(
    error: anyhow::Error,
    parent: &Dir,
    name: &OsStr,
    display: &Path,
) -> anyhow::Error {
    match remove_child_file(parent, name, display) {
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
            "cleanup of staged manifest `{}` also failed: {cleanup_error}",
            name.to_string_lossy()
        )),
    }
}

fn cleanup_staged_directory(
    error: anyhow::Error,
    root: &Dir,
    name: &OsStr,
    display_root: &Path,
) -> anyhow::Error {
    match remove_real_directory_tree(root, name, &display_root.join(name)) {
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
            "cleanup of staged skill directory `{}` also failed: {cleanup_error}",
            name.to_string_lossy()
        )),
    }
}

/// Top-level create: build + write + return the report.
pub fn create_skill(
    skills_dir: &Path,
    params: CreateParams,
    existing: ExistingSkillPolicy,
) -> Result<CreateReport> {
    create_skill_with_expectation(skills_dir, params, existing, None)
}

pub fn create_skill_with_expectation(
    skills_dir: &Path,
    params: CreateParams,
    existing: ExistingSkillPolicy,
    expectation: Option<&CreateExpectation>,
) -> Result<CreateReport> {
    let (_, yaml) = build_manifest(&params)?;
    write_skill_yaml_with_expectation(skills_dir, &params.id, &yaml, existing, expectation)
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
    fn post_commit_sync_failure_is_a_typed_warning_not_an_error() {
        let warnings = post_commit_sync_warnings(
            Err(anyhow::anyhow!("injected directory sync failure")),
            "skill is committed, but namespace durability is unconfirmed",
        );

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("skill is committed"));
        assert!(warnings[0].contains("injected directory sync failure"));
        assert!(post_commit_sync_warnings(Ok(()), "unused").is_empty());
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
        let report =
            create_skill(dir.path(), good_params(), ExistingSkillPolicy::Refuse).expect("create");
        assert_eq!(report.id, "morning-news");
        assert!(!report.replaced_existing);
        assert!(report.warnings.is_empty());
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
        write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap();
        // Explicit replacement succeeds and leaves no staged file behind.
        let report = write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Replace,
        )
        .unwrap();
        assert!(report.replaced_existing);
        assert!(report.warnings.is_empty());
        let names = std::fs::read_dir(dir.path().join("morning-news"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["skill.yaml"]);
    }

    #[test]
    fn stale_create_replacement_preserves_the_changed_generation() {
        let dir = tempfile::tempdir().unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();
        write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap();
        let preflight =
            super::super::installer::inspect_installed_target(dir.path(), "morning-news").unwrap();
        let expected = preflight.target_generation_sha256.unwrap();
        let manifest_path = dir.path().join("morning-news").join("skill.yaml");
        let changed = yaml.replace("today's headlines", "the operator's private headlines");
        std::fs::write(&manifest_path, changed.as_bytes()).unwrap();

        let error = write_skill_yaml_with_expectation(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Replace,
            Some(&CreateExpectation {
                id: "morning-news".to_string(),
                target_generation_sha256: Some(expected),
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("changed after preflight"));
        assert_eq!(std::fs::read(manifest_path).unwrap(), changed.as_bytes());
    }

    #[test]
    fn absent_create_expectation_rejects_an_appeared_target() {
        let dir = tempfile::tempdir().unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();
        let preflight =
            super::super::installer::inspect_installed_target(dir.path(), "morning-news").unwrap();
        assert!(preflight.target_generation_sha256.is_none());
        let appeared = dir.path().join("morning-news");
        std::fs::create_dir(&appeared).unwrap();
        std::fs::write(appeared.join("skill.yaml"), b"operator-owned bytes").unwrap();

        let error = write_skill_yaml_with_expectation(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Replace,
            Some(&CreateExpectation {
                id: "morning-news".to_string(),
                target_generation_sha256: None,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("changed after preflight"));
        assert_eq!(
            std::fs::read(appeared.join("skill.yaml")).unwrap(),
            b"operator-owned bytes"
        );
    }

    #[test]
    fn keep_if_identical_retries_without_overwriting_operator_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();
        write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap();

        let retry = write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::KeepIfIdentical,
        )
        .unwrap();
        assert!(!retry.replaced_existing);

        let manifest_path = dir.path().join("morning-news").join("skill.yaml");
        let operator_bytes = yaml.replace(
            "Fetch + summarise today's headlines.",
            "Operator-owned briefing",
        );
        assert_ne!(operator_bytes, yaml);
        std::fs::write(&manifest_path, operator_bytes.as_bytes()).unwrap();
        let error = write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::KeepIfIdentical,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("explicit replacement preflight is required"));
        assert_eq!(
            std::fs::read(&manifest_path).unwrap(),
            operator_bytes.as_bytes()
        );
    }

    #[test]
    fn refuse_existing_preserves_the_original_manifest_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();
        write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap();
        let manifest_path = dir.path().join("morning-news").join("skill.yaml");
        let original = std::fs::read(&manifest_path).unwrap();

        let mut changed = good_params();
        changed.description = "must not land".into();
        let (_, changed_yaml) = build_manifest(&changed).unwrap();
        let error = write_skill_yaml(
            dir.path(),
            "morning-news",
            &changed_yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("pass --force to replace"));
        assert_eq!(std::fs::read(manifest_path).unwrap(), original);
    }

    #[test]
    fn create_recovers_interrupted_install_before_refusing_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let nonce = "0123456789abcdef0123456789abcdef";
        let backup = dir
            .path()
            .join(format!(".neoth-backup-morning-news-{nonce}"));
        let stage = dir
            .path()
            .join(format!(".neoth-install-morning-news-{nonce}"));
        std::fs::create_dir(&backup).unwrap();
        std::fs::write(backup.join("skill.yaml"), b"old generation").unwrap();
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("partial.bin"), b"partial generation").unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();

        let error = write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("pass --force to replace"));
        assert_eq!(
            std::fs::read(dir.path().join("morning-news").join("skill.yaml")).unwrap(),
            b"old generation"
        );
        assert!(!backup.exists());
        assert!(!stage.exists());
    }

    #[test]
    fn create_recovers_stage_only_crash_before_deciding_id_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let nonce = "0123456789abcdef0123456789abcdef";
        let stage = dir
            .path()
            .join(format!(".neoth-install-morning-news-{nonce}"));
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("partial.bin"), b"partial generation").unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();

        let report = write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap();

        assert!(!report.replaced_existing);
        assert!(report.path.is_file());
        assert!(!stage.exists());
    }

    #[test]
    fn create_commit_refuses_an_id_that_appeared_during_staging() {
        let root_dir = tempfile::tempdir().unwrap();
        let root = open_bound_directory(root_dir.path(), false, "test skills root")
            .unwrap()
            .unwrap();
        let public = root_dir.path().join("morning-news");
        std::fs::create_dir(&public).unwrap();
        std::fs::write(public.join("sentinel"), b"keep").unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();

        let error = create_skill_directory(
            &root.dir,
            &root.display_path,
            "morning-news",
            yaml.as_bytes(),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("appeared"));
        assert_eq!(std::fs::read(public.join("sentinel")).unwrap(), b"keep");
        assert_eq!(
            std::fs::read_dir(root_dir.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".skill-create-stage-"))
                .count(),
            0
        );
    }

    #[test]
    fn overwrite_preserves_existing_skill_assets() {
        let dir = tempfile::tempdir().unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();
        write_skill_yaml(
            dir.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap();
        let asset = dir.path().join("morning-news").join("template.txt");
        std::fs::write(&asset, b"keep me").unwrap();

        let mut updated = good_params();
        updated.description = "Updated description".into();
        let (_, updated_yaml) = build_manifest(&updated).unwrap();
        write_skill_yaml(
            dir.path(),
            "morning-news",
            &updated_yaml,
            ExistingSkillPolicy::Replace,
        )
        .unwrap();

        assert_eq!(std::fs::read(asset).unwrap(), b"keep me");
        let installed =
            std::fs::read_to_string(dir.path().join("morning-news").join("skill.yaml")).unwrap();
        let manifest: SkillManifest = serde_yaml::from_str(&installed).unwrap();
        assert_eq!(manifest.description, "Updated description");
    }

    #[test]
    fn writer_rejects_manifest_id_mismatch_before_touching_store() {
        let dir = tempfile::tempdir().unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();
        let error = write_skill_yaml(
            dir.path(),
            "different-id",
            &yaml,
            ExistingSkillPolicy::Refuse,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("does not match target directory"));
        assert!(!dir.path().join("different-id").exists());
    }

    #[test]
    fn concurrent_writes_never_leave_a_torn_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = good_params();
        first.description = "first generation".into();
        let mut second = good_params();
        second.description = "second generation".into();
        let (_, first_yaml) = build_manifest(&first).unwrap();
        let (_, second_yaml) = build_manifest(&second).unwrap();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                write_skill_yaml(
                    dir.path(),
                    "morning-news",
                    &first_yaml,
                    ExistingSkillPolicy::Replace,
                )
                .unwrap();
            });
            scope.spawn(|| {
                write_skill_yaml(
                    dir.path(),
                    "morning-news",
                    &second_yaml,
                    ExistingSkillPolicy::Replace,
                )
                .unwrap();
            });
        });

        let body =
            std::fs::read_to_string(dir.path().join("morning-news").join("skill.yaml")).unwrap();
        let manifest: SkillManifest = serde_yaml::from_str(&body).unwrap();
        assert!(matches!(
            manifest.description.as_str(),
            "first generation" | "second generation"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn writer_rejects_linked_skill_directory_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("morning-news")).unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();

        let error = write_skill_yaml(
            root.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Replace,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("real directory"));
        assert!(!outside.path().join("skill.yaml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn writer_rejects_linked_manifest_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let skill_dir = root.path().join("morning-news");
        std::fs::create_dir(&skill_dir).unwrap();
        let sentinel = outside.path().join("sentinel.yaml");
        std::fs::write(&sentinel, b"keep me").unwrap();
        symlink(&sentinel, skill_dir.join("skill.yaml")).unwrap();
        let (_, yaml) = build_manifest(&good_params()).unwrap();

        let error = write_skill_yaml(
            root.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Replace,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("real regular file"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep me");
    }

    #[cfg(windows)]
    #[test]
    fn writer_rejects_reparse_skill_directory_without_touching_target() {
        use std::os::windows::fs::symlink_dir;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        if let Err(error) = symlink_dir(outside.path(), root.path().join("morning-news")) {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("create directory reparse fixture: {error}");
        }
        let (_, yaml) = build_manifest(&good_params()).unwrap();

        let error = write_skill_yaml(
            root.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Replace,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("real directory"));
        assert!(!outside.path().join("skill.yaml").exists());
    }

    #[cfg(windows)]
    #[test]
    fn writer_rejects_reparse_manifest_without_touching_target() {
        use std::os::windows::fs::symlink_file;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let skill_dir = root.path().join("morning-news");
        std::fs::create_dir(&skill_dir).unwrap();
        let sentinel = outside.path().join("sentinel.yaml");
        std::fs::write(&sentinel, b"keep me").unwrap();
        if let Err(error) = symlink_file(&sentinel, skill_dir.join("skill.yaml")) {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("create file reparse fixture: {error}");
        }
        let (_, yaml) = build_manifest(&good_params()).unwrap();

        let error = write_skill_yaml(
            root.path(),
            "morning-news",
            &yaml,
            ExistingSkillPolicy::Replace,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("real regular file"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep me");
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
