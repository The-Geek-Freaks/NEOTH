//! Capability-relative materialization of immutable bundled Skill resources.

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use cap_std::fs::Dir;
use sha2::{Digest as _, Sha256};

use super::store::{
    bind_retained_real_child_dir, create_private_regular_file_child_create_new,
    open_bound_directory, open_or_create_bound_lockfile, open_or_create_private_child_dir,
    open_real_child_dir_if_present, read_regular_file_bounded, remove_bound_real_directory_tree,
    rename_child,
};

pub struct BundledResource {
    pub relative_path: &'static str,
    pub bytes: &'static [u8],
}

const DRAWIO_RESOURCES: &[BundledResource] = &[
    BundledResource {
        relative_path: "skill.yaml",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/skill.yaml"),
    },
    BundledResource {
        relative_path: "data/lobe-icons.json",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/data/lobe-icons.json"),
    },
    BundledResource {
        relative_path: "data/SHAPE-INDEX-NOTICE.md",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/data/SHAPE-INDEX-NOTICE.md"),
    },
    BundledResource {
        relative_path: "data/shape-index.json.gz",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/data/shape-index.json.gz"),
    },
    BundledResource {
        relative_path: "scripts/aiicons.py",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/scripts/aiicons.py"),
    },
    BundledResource {
        relative_path: "scripts/autolayout.py",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/scripts/autolayout.py"),
    },
    BundledResource {
        relative_path: "scripts/encode_drawio_url.py",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/scripts/encode_drawio_url.py"),
    },
    BundledResource {
        relative_path: "scripts/rustimports.py",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/scripts/rustimports.py"),
    },
    BundledResource {
        relative_path: "scripts/shapesearch.py",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/scripts/shapesearch.py"),
    },
    BundledResource {
        relative_path: "scripts/validate.py",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/scripts/validate.py"),
    },
    BundledResource {
        relative_path: "styles/built-in/default.json",
        bytes: include_bytes!("../../assets/skills/drawio_diagram/styles/built-in/default.json"),
    },
];
const MAX_RESOURCE_FILES: usize = 16;
const MAX_RESOURCE_BYTES: usize = 2 * 1024 * 1024;

pub fn materialize_skill(home_path: &Path, skill_id: &str) -> Result<Option<PathBuf>> {
    let resources = match skill_id {
        "drawio_diagram" => DRAWIO_RESOURCES,
        _ => return Ok(None),
    };
    validate_resources(resources)?;
    let digest = package_digest(resources);
    let home = open_bound_directory(home_path, true, "bundled resource home")?
        .context("bundled resource home is unavailable")?;
    let namespace_path = home.physical_display_path.join("bundled-skill-resources");
    let namespace = open_or_create_private_child_dir(
        &home.dir,
        OsStr::new("bundled-skill-resources"),
        &namespace_path,
    )?;
    let skill_path = namespace_path.join(skill_id);
    let skill_dir =
        open_or_create_private_child_dir(&namespace, OsStr::new(skill_id), &skill_path)?;
    with_package_lock(&skill_dir, &skill_path, || {
        materialize_locked(&skill_dir, &skill_path, &digest, resources)
    })
    .map(Some)
}

fn materialize_locked(
    skill_dir: &Dir,
    skill_path: &Path,
    digest: &str,
    resources: &[BundledResource],
) -> Result<PathBuf> {
    let target_path = skill_path.join(digest);
    let rendered_target: String = target_path.to_string_lossy().escape_default().collect();
    anyhow::ensure!(
        rendered_target.chars().count() <= 4096,
        "bundled resource package path is too long to render safely: {}",
        target_path.display()
    );
    if let Some(target) =
        open_real_child_dir_if_present(skill_dir, OsStr::new(&digest), &target_path)?
    {
        verify_package(&target, &target_path, resources)?;
        return Ok(target_path.join("skill.yaml"));
    }

    // Interrupted stages are evidence. Refuse before allocating another one:
    // this gives crash recovery a fixed storage bound (one package maximum)
    // without deleting or consuming an object this invocation did not create.
    refuse_interrupted_stages(skill_dir, skill_path, digest)?;
    // UUID prevents a same-process collision and every directory operation
    // remains no-follow.
    let stage_name = format!(".{digest}.staging-{}", uuid::Uuid::new_v4().simple());
    let stage_path = skill_path.join(&stage_name);
    if open_real_child_dir_if_present(skill_dir, OsStr::new(&stage_name), &stage_path)?.is_some() {
        anyhow::bail!(
            "unexpected existing bundled resource stage: {}",
            stage_path.display()
        );
    }
    let stage = open_or_create_private_child_dir(skill_dir, OsStr::new(&stage_name), &stage_path)?;
    let (stage, stage_binding) =
        bind_retained_real_child_dir(skill_dir, OsStr::new(&stage_name), &stage_path, stage)?;
    #[cfg(test)]
    pause_after_stage_created_for_test(skill_path);
    write_package(&stage, &stage_path, resources)?;
    verify_package(&stage, &stage_path, resources)?;
    let stage_identity = stage_binding.identity_token().to_owned();
    drop(stage);
    if let Err(error) = rename_child(
        skill_dir,
        OsStr::new(&stage_name),
        skill_dir,
        OsStr::new(digest),
        false,
        &stage_path,
        &target_path,
    ) {
        if let Some(target) =
            open_real_child_dir_if_present(skill_dir, OsStr::new(digest), &target_path)?
        {
            verify_package(&target, &target_path, resources)?;
            remove_bound_real_directory_tree(skill_dir, OsStr::new(&stage_name), &stage_path, &stage_identity)
                .context("remove this invocation's unpublished bundled resource stage after concurrent publish")?;
        } else {
            return Err(error).with_context(|| {
                format!("publish bundled resource package {}", target_path.display())
            });
        }
    }
    let target = open_real_child_dir_if_present(skill_dir, OsStr::new(digest), &target_path)?
        .context("published bundled resource package disappeared")?;
    verify_package(&target, &target_path, resources)?;
    Ok(target_path.join("skill.yaml"))
}

fn with_package_lock<T>(
    skill_dir: &Dir,
    skill_path: &Path,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    const LOCK_FILE: &str = ".bundled-resource-materialize.lock";
    const WAIT: std::time::Duration = std::time::Duration::from_millis(25);
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
    let lock_path = skill_path.join(LOCK_FILE);
    let (lock, binding) =
        open_or_create_bound_lockfile(skill_dir, OsStr::new(LOCK_FILE), &lock_path)?;
    let deadline = std::time::Instant::now() + MAX_WAIT;
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                #[cfg(test)]
                report_lock_contention_for_test(skill_path);
                std::thread::sleep(WAIT)
            }
            Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
                "timed out waiting for bundled resource materialization lock: {}",
                lock_path.display()
            ),
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).context("lock bundled resource materialization");
            }
        }
    }
    let result = operation()?;
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(
            skill_dir,
            OsStr::new(LOCK_FILE),
            &lock_path
        )?,
        "bundled resource materialization lock changed during operation: {}",
        lock_path.display()
    );
    Ok(result)
}

fn validate_resources(resources: &[BundledResource]) -> Result<()> {
    anyhow::ensure!(
        resources.len() <= MAX_RESOURCE_FILES,
        "bundled resource file count exceeds bound"
    );
    let total = resources.iter().try_fold(0usize, |sum, resource| {
        validate_relative_path(resource.relative_path)?;
        sum.checked_add(resource.bytes.len())
            .ok_or_else(|| anyhow::anyhow!("bundled resource byte count overflow"))
    })?;
    anyhow::ensure!(
        total <= MAX_RESOURCE_BYTES,
        "bundled resource bytes exceed bound"
    );
    Ok(())
}

fn refuse_interrupted_stages(skill_dir: &Dir, skill_path: &Path, digest: &str) -> Result<()> {
    let prefix = format!(".{digest}.staging-");
    for entry in skill_dir
        .read_dir(".")
        .with_context(|| format!("enumerate bundled resource cache {}", skill_path.display()))?
    {
        let entry = entry.with_context(|| {
            format!("enumerate bundled resource cache {}", skill_path.display())
        })?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let display = skill_path.join(&name);
        // Opening capability-relatively is also a type/link check. A link-like
        // stage is an error, never an invitation to follow or remove it.
        open_real_child_dir_if_present(skill_dir, &name, &display)?
            .context("interrupted bundled resource stage disappeared during inspection")?;
        anyhow::bail!(
            "interrupted bundled resource stage requires operator inspection: {}",
            display.display()
        );
    }
    Ok(())
}

fn resource_parent(
    root: &Dir,
    root_path: &Path,
    relative: &Path,
    create: bool,
) -> Result<(Dir, PathBuf, std::ffi::OsString)> {
    let mut directory = root
        .try_clone()
        .context("clone bundled resource root capability")?;
    let mut display = root_path.to_path_buf();
    let parts: Vec<_> = relative.components().collect();
    for component in &parts[..parts.len() - 1] {
        let Component::Normal(name) = component else {
            anyhow::bail!("invalid bundled resource path")
        };
        display.push(name);
        directory = if create {
            open_or_create_private_child_dir(&directory, name, &display)?
        } else {
            open_real_child_dir_if_present(&directory, name, &display)?
                .context("bundled resource cache is missing a directory")?
        };
    }
    let Component::Normal(name) = parts[parts.len() - 1] else {
        anyhow::bail!("invalid bundled resource leaf")
    };
    Ok((directory, display, name.to_os_string()))
}

fn write_package(root: &Dir, root_path: &Path, resources: &[BundledResource]) -> Result<()> {
    for resource in resources {
        let (parent, display, name) =
            resource_parent(root, root_path, Path::new(resource.relative_path), true)?;
        let file_path = display.join(&name);
        let (mut file, _binding) =
            create_private_regular_file_child_create_new(&parent, &name, &file_path)?;
        file.write_all(resource.bytes)
            .with_context(|| format!("write bundled resource {}", file_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync bundled resource {}", file_path.display()))?;
    }
    Ok(())
}

fn verify_package(root: &Dir, root_path: &Path, resources: &[BundledResource]) -> Result<()> {
    for resource in resources {
        let (parent, display, name) =
            resource_parent(root, root_path, Path::new(resource.relative_path), false)?;
        let file_path = display.join(&name);
        let bytes = read_regular_file_bounded(&parent, &name, &file_path, resource.bytes.len())
            .with_context(|| format!("read bundled resource cache {}", file_path.display()))?;
        anyhow::ensure!(
            bytes == resource.bytes,
            "bundled resource cache hash mismatch: {}",
            file_path.display()
        );
    }
    Ok(())
}

fn package_digest(resources: &[BundledResource]) -> String {
    let mut digest = Sha256::new();
    for resource in resources {
        digest.update(resource.relative_path.as_bytes());
        digest.update([0]);
        digest.update((resource.bytes.len() as u64).to_be_bytes());
        digest.update(resource.bytes);
    }
    format!("{:x}", digest.finalize())
}

fn validate_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    anyhow::ensure!(
        !path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "bundled resource path escapes package: {value}"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn drawio_package_digest_for_test() -> String {
    package_digest(DRAWIO_RESOURCES)
}

#[cfg(test)]
static W192_STAGE_HOOK: std::sync::OnceLock<
    std::sync::Mutex<
        Option<(
            PathBuf,
            std::sync::mpsc::Sender<()>,
            std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        )>,
    >,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn set_stage_hook_for_test(
    value: Option<(
        PathBuf,
        std::sync::mpsc::Sender<()>,
        std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    )>,
) {
    *W192_STAGE_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("W192 stage hook lock") = value;
}

#[cfg(test)]
fn pause_after_stage_created_for_test(skill_path: &Path) {
    let hook = W192_STAGE_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("W192 stage hook lock")
        .clone()
        .filter(|(expected, _, _)| expected == skill_path);
    if let Some((_, ready, release)) = hook {
        let _ = ready.send(());
        let (state, wake) = &*release;
        let held = state.lock().expect("W192 stage release lock");
        let _ = wake
            .wait_timeout_while(held, std::time::Duration::from_secs(10), |held| !*held)
            .expect("W192 stage release wait");
    }
}

#[cfg(test)]
pub(crate) fn release_stage_hook_for_test(
    release: &std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
) {
    let (state, wake) = &**release;
    *state.lock().expect("W192 stage release lock") = true;
    wake.notify_all();
}

#[cfg(test)]
static W192_LOCK_CONTENTION_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<(PathBuf, std::sync::mpsc::Sender<()>)>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn set_lock_contention_hook_for_test(
    value: Option<(PathBuf, std::sync::mpsc::Sender<()>)>,
) {
    *W192_LOCK_CONTENTION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("W192 contention hook lock") = value;
}

#[cfg(test)]
fn report_lock_contention_for_test(skill_path: &Path) {
    let hook = W192_LOCK_CONTENTION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("W192 contention hook lock")
        .clone()
        .filter(|(expected, _)| expected == skill_path);
    if let Some((_, observed)) = hook {
        let _ = observed.send(());
    }
}
