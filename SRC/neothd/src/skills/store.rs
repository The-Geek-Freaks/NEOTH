//! Capability-bound filesystem boundary for user-installed skills.
//!
//! The ambient path is used only to select a trusted ancestor. Every
//! component below that ancestor is then created/opened relative to an owned
//! directory handle and without following links. Security-sensitive rename and
//! recursive-delete operations use native handle-relative primitives on Windows
//! instead of cap-std's ambient-path fallbacks. Once opened, a namespace swap
//! cannot redirect the operation to a different object.

use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
#[cfg(unix)]
use cap_std::fs::DirBuilder;
use cap_std::fs::{Dir, File, OpenOptions};

/// Open directory plus the operator-facing absolute namespace path. Security
/// decisions use `dir`; `display_path` is reporting-only.
pub(crate) struct BoundDirectory {
    pub(crate) dir: Dir,
    pub(crate) display_path: PathBuf,
}

/// Open `path` as a stable directory capability. The grandparent is the
/// explicit ambient trust boundary: for the production
/// `<user-home>/.neoth/skills` path this is the user home, matching the updater
/// trust model. Public callers that supply a custom path are responsible for
/// ensuring its grandparent (or nearest existing ancestor) is trusted. Every
/// component below that boundary is protected. If the anchor is absent, the
/// nearest existing ancestor is used and every missing descendant is created
/// handle-relatively.
pub(crate) fn open_bound_directory(
    path: &Path,
    create: bool,
    label: &str,
) -> Result<Option<BoundDirectory>> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("resolve absolute {label} path {}", path.display()))?;
    if absolute
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        anyhow::bail!(
            "{label} path must not contain `.` or `..` components: {}",
            path.display()
        );
    }

    let mut anchor = absolute.clone();
    for _ in 0..2 {
        if !anchor.pop() {
            break;
        }
    }
    loop {
        match std::fs::symlink_metadata(&anchor) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !anchor.pop() {
                    return Err(error).with_context(|| {
                        format!(
                            "find existing trusted ancestor for {label} {}",
                            path.display()
                        )
                    });
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect trusted ancestor for {label} {}", anchor.display())
                });
            }
        }
    }

    let relative = absolute
        .strip_prefix(&anchor)
        .with_context(|| {
            format!(
                "derive {label} path below trusted ancestor {}",
                anchor.display()
            )
        })?
        .to_path_buf();
    let canonical_anchor = std::fs::canonicalize(&anchor)
        .with_context(|| format!("canonicalize trusted {label} ancestor {}", anchor.display()))?;
    let mut current = open_ambient_directory_nofollow(&canonical_anchor, label)?;

    for component in relative.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!(
                "{label} path has a non-child component below its trusted ancestor: {}",
                absolute.display()
            );
        };
        match current.open_dir_nofollow(name) {
            Ok(next) => {
                ensure_cap_directory_is_real(&next, label, &absolute)?;
                current = next;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => {
                return Ok(None);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match create_private_child_directory(&current, name) {
                    Ok(()) => {}
                    Err(create_error)
                        if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => {
                        return Err(create_error).with_context(|| {
                            format!("create {label} component `{}`", name.to_string_lossy())
                        });
                    }
                }
                let next = current.open_dir_nofollow(name).with_context(|| {
                    format!(
                        "open newly-created {label} component `{}` without following links",
                        name.to_string_lossy()
                    )
                })?;
                ensure_cap_directory_is_real(&next, label, &absolute)?;
                current = next;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "{label} must be a real directory at every untrusted component: {}",
                        absolute.display()
                    )
                });
            }
        }
    }

    ensure_cap_directory_is_real(&current, label, &absolute)?;
    Ok(Some(BoundDirectory {
        dir: current,
        display_path: absolute,
    }))
}

fn create_private_child_directory(parent: &Dir, name: &OsStr) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt as _;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent.create_dir_with(name, &builder)
    }
    #[cfg(not(unix))]
    {
        parent.create_dir(name)
    }
}

/// Open one direct child directory without following a symlink, junction, or
/// other Windows reparse point.
pub(crate) fn open_real_child_dir(parent: &Dir, name: &OsStr, display_path: &Path) -> Result<Dir> {
    validate_child_name(name)?;
    let child = parent.open_dir_nofollow(name).with_context(|| {
        format!(
            "installed skill must be a real directory, not a file, symlink, or reparse point: {}",
            display_path.display()
        )
    })?;
    ensure_cap_directory_is_real(&child, "installed skill", display_path)?;
    Ok(child)
}

/// Read a direct regular-file child without following links and with a strict
/// byte ceiling. Returns `InvalidData` when the file is too large.
pub(crate) fn read_regular_file_bounded(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    validate_child_name(name)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent.open_with(name, &options).with_context(|| {
        format!(
            "open regular file without following links {}",
            display_path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened regular file {}", display_path.display()))?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!("expected a real regular file at {}", display_path.display());
    }
    read_bounded(file, display_path, max_bytes)
}

/// Same no-follow leaf open used by recursive copies. The caller streams from
/// the returned handle and therefore reads the exact object that was checked.
pub(crate) fn open_regular_file(parent: &Dir, name: &OsStr, display_path: &Path) -> Result<File> {
    validate_child_name(name)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent
        .open_with(name, &options)
        .with_context(|| format!("open skill source file {}", display_path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect skill source file {}", display_path.display()))?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "skill source is not a real regular file: {}",
            display_path.display()
        );
    }
    Ok(file)
}

/// Rename one already-bound direct child. On Windows this deliberately avoids
/// cap-std 4.0.2's ambient-path `std::fs::rename` fallback and commits the
/// namespace mutation through the opened source handle instead.
pub(crate) fn rename_child(
    source_parent: &Dir,
    source_name: &OsStr,
    target_parent: &Dir,
    target_name: &OsStr,
    replace_existing: bool,
    source_display: &Path,
    target_display: &Path,
) -> Result<()> {
    validate_child_name(source_name)?;
    validate_child_name(target_name)?;
    #[cfg(unix)]
    {
        if replace_existing {
            source_parent
                .rename(source_name, target_parent, target_name)
                .with_context(|| {
                    format!(
                        "rename capability-bound child {} to {}",
                        source_display.display(),
                        target_display.display()
                    )
                })?;
        } else {
            // `Dir::rename` has replace semantics. A fresh install/create must
            // instead commit with the kernel's exclusive rename primitive so
            // an uncooperative same-user writer cannot win the final lookup
            // race and have its directory replaced.
            #[cfg(any(
                target_vendor = "apple",
                target_os = "linux",
                target_os = "android",
                target_os = "redox"
            ))]
            rustix::fs::renameat_with(
                source_parent,
                source_name,
                target_parent,
                target_name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .with_context(|| {
                format!(
                    "exclusively rename capability-bound child {} to {}",
                    source_display.display(),
                    target_display.display()
                )
            })?;
            // A runtime bail here is unreachable-by-build: this is the commit
            // path of every skill install, uninstall tombstone and create, so a
            // target without `renameat2(RENAME_NOREPLACE)` would compile a
            // binary in which EVERY skill mutation fails at run time, with no
            // build-time signal. Fail at compile time instead — porting to such
            // a target is a deliberate act that needs a link+unlink fallback,
            // not a silent runtime dead end.
            #[cfg(not(any(
                target_vendor = "apple",
                target_os = "linux",
                target_os = "android",
                target_os = "redox",
                windows
            )))]
            compile_error!(
                "exclusive capability-bound rename needs renameat2(RENAME_NOREPLACE) or \
                 renamex_np(RENAME_EXCL); this Unix target has neither. Implement a \
                 linkat/unlinkat fallback in skills::store::rename_child before enabling it."
            );
        }
    }
    #[cfg(windows)]
    {
        let source = open_windows_mutation_handle(source_parent, source_name, source_display)?;
        let metadata = source
            .metadata()
            .with_context(|| format!("inspect rename source {}", source_display.display()))?;
        if cap_metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "refuse to rename linked or reparse source {}",
                source_display.display()
            );
        }
        windows_rename_open_handle(
            &source,
            target_parent,
            target_name,
            replace_existing,
            target_display,
        )?;
    }
    Ok(())
}

/// Remove one real direct-child directory without following a link or reparse
/// point. Both platforms use a bounded, handle-relative walk. Windows objects
/// are disposed by their opened handles because cap-std 4.0.2 closes its
/// validated handle before calling ambient `std::fs::remove_dir_all` there.
pub(crate) fn remove_real_directory_tree(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<()> {
    const MAX_DELETE_ENTRIES: usize = 4096;
    // One unit to enumerate the root, then at most one inspection, one child
    // enumeration, and one mutation per admitted entry.
    const MAX_DELETE_WORK_UNITS: usize = MAX_DELETE_ENTRIES * 3 + 1;

    let mut budget = DeleteBudget::new(MAX_DELETE_ENTRIES, MAX_DELETE_WORK_UNITS);
    remove_real_directory_tree_with_budget(parent, name, display_path, &mut budget)
}

#[derive(Debug)]
struct DeleteBudget {
    entries: usize,
    work_units: usize,
    max_entries: usize,
    max_work_units: usize,
}

impl DeleteBudget {
    fn new(max_entries: usize, max_work_units: usize) -> Self {
        Self {
            entries: 0,
            work_units: 0,
            max_entries,
            max_work_units,
        }
    }

    fn charge_entry(&mut self, display_path: &Path) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .context("skill deletion entry counter overflow")?;
        if self.entries > self.max_entries {
            anyhow::bail!(
                "refuse to remove skill tree exceeding the aggregate {}-entry limit at {}",
                self.max_entries,
                display_path.display()
            );
        }
        self.charge_work(display_path)
    }

    fn charge_work(&mut self, display_path: &Path) -> Result<()> {
        self.work_units = self
            .work_units
            .checked_add(1)
            .context("skill deletion work counter overflow")?;
        if self.work_units > self.max_work_units {
            anyhow::bail!(
                "refuse to remove skill tree exceeding the aggregate {}-unit work limit at {}",
                self.max_work_units,
                display_path.display()
            );
        }
        Ok(())
    }
}

fn remove_real_directory_tree_with_budget(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    budget: &mut DeleteBudget,
) -> Result<()> {
    validate_child_name(name)?;
    #[cfg(unix)]
    {
        let directory = open_real_child_dir(parent, name, display_path)?;
        remove_directory_contents(&directory, display_path, 0, budget)?;
        drop(directory);

        // The top-level tombstone/backup is deliberately removed only after
        // every descendant was admitted by the aggregate budget and deleted.
        // A budget or traversal failure therefore retains a retryable root.
        parent
            .remove_dir(name)
            .with_context(|| format!("remove capability-bound tree {}", display_path.display()))?;
    }
    #[cfg(windows)]
    {
        let handle = open_windows_mutation_handle(parent, name, display_path)?;
        let metadata = handle
            .metadata()
            .with_context(|| format!("inspect removal target {}", display_path.display()))?;
        if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "removal target must be a real directory: {}",
                display_path.display()
            );
        }
        let directory = Dir::from_std_file(
            handle
                .try_clone()
                .with_context(|| format!("clone removal handle {}", display_path.display()))?
                .into_std(),
        );
        remove_directory_contents(&directory, display_path, 0, budget)?;
        drop(directory);

        // Commit deletion through the same root handle that was validated
        // before traversal. Namespace swaps cannot redirect the commit.
        windows_mark_delete(&handle, display_path)?;
    }
    Ok(())
}

/// Remove one direct-child file/link stage by its already-bound object rather
/// than re-resolving an ambient Windows path.
pub(crate) fn remove_child_file(parent: &Dir, name: &OsStr, display_path: &Path) -> Result<()> {
    validate_child_name(name)?;
    #[cfg(unix)]
    parent
        .remove_file(name)
        .with_context(|| format!("remove capability-bound file {}", display_path.display()))?;
    #[cfg(windows)]
    {
        let handle = open_windows_mutation_handle(parent, name, display_path)?;
        let metadata = handle
            .metadata()
            .with_context(|| format!("inspect removal target {}", display_path.display()))?;
        if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
            anyhow::bail!("expected file removal target at {}", display_path.display());
        }
        windows_mark_delete(&handle, display_path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_mutation_handle(parent: &Dir, name: &OsStr, display_path: &Path) -> Result<File> {
    use cap_std::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .access_mode(FILE_GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
        );
    parent.open_with(name, &options).with_context(|| {
        format!(
            "open Windows mutation target without following links {}",
            display_path.display()
        )
    })
}

fn remove_directory_contents(
    directory: &Dir,
    display_path: &Path,
    depth: usize,
    budget: &mut DeleteBudget,
) -> Result<()> {
    const MAX_DELETE_DEPTH: usize = 128;
    if depth >= MAX_DELETE_DEPTH {
        anyhow::bail!(
            "refuse to remove skill tree deeper than {MAX_DELETE_DEPTH} levels at {}",
            display_path.display()
        );
    }
    budget.charge_work(display_path)?;
    let entries = directory
        .entries()
        .with_context(|| format!("enumerate removal tree {}", display_path.display()))?;
    for entry in entries {
        budget.charge_entry(display_path)?;
        let entry =
            entry.with_context(|| format!("read removal tree {}", display_path.display()))?;
        let name = entry.file_name();
        let child_display = display_path.join(&name);

        #[cfg(unix)]
        {
            let metadata = directory
                .symlink_metadata(&name)
                .with_context(|| format!("inspect removal child {}", child_display.display()))?;
            if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
                let child = open_real_child_dir(directory, &name, &child_display)?;
                remove_directory_contents(&child, &child_display, depth + 1, budget)?;
                drop(child);
                budget.charge_work(&child_display)?;
                directory.remove_dir(&name).with_context(|| {
                    format!(
                        "remove capability-bound directory {}",
                        child_display.display()
                    )
                })?;
            } else {
                budget.charge_work(&child_display)?;
                directory.remove_file(&name).with_context(|| {
                    format!("remove capability-bound leaf {}", child_display.display())
                })?;
            }
        }

        #[cfg(windows)]
        {
            let handle = open_windows_mutation_handle(directory, &name, &child_display)?;
            let metadata = handle
                .metadata()
                .with_context(|| format!("inspect removal child {}", child_display.display()))?;
            if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
                let child = Dir::from_std_file(
                    handle
                        .try_clone()
                        .with_context(|| {
                            format!("clone directory removal handle {}", child_display.display())
                        })?
                        .into_std(),
                );
                remove_directory_contents(&child, &child_display, depth + 1, budget)?;
                drop(child);
            }
            budget.charge_work(&child_display)?;
            windows_mark_delete(&handle, &child_display)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_mark_delete(handle: &File, display_path: &Path) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, GetLastError, HANDLE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
        FileDispositionInfo, FileDispositionInfoEx, SetFileInformationByHandle,
    };

    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: `handle` remains live for the call; `info` is a correctly sized
    // initialized FILE_DISPOSITION_INFO_EX value and the API does not retain it.
    let result = unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle() as HANDLE,
            FileDispositionInfoEx,
            std::ptr::addr_of!(info).cast::<std::ffi::c_void>(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO_EX>())
                .expect("FILE_DISPOSITION_INFO_EX size fits in u32"),
        )
    };
    if result == 0 {
        // SAFETY: no Win32 call intervened after SetFileInformationByHandle.
        let code = unsafe { GetLastError() };
        if matches!(
            code,
            ERROR_INVALID_FUNCTION | ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED
        ) {
            // Older Windows/filesystem combinations may not implement the Ex
            // disposition class. The legacy call operates on this same
            // no-follow handle, so it cannot redirect deletion through a
            // junction or symlink. Never fall back to an ambient path API.
            let legacy = FILE_DISPOSITION_INFO { DeleteFile: 1 };
            // SAFETY: `handle` remains live; `legacy` has the documented ABI
            // and the API does not retain the pointer.
            let legacy_result = unsafe {
                SetFileInformationByHandle(
                    handle.as_raw_handle() as HANDLE,
                    FileDispositionInfo,
                    std::ptr::addr_of!(legacy).cast::<std::ffi::c_void>(),
                    u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                        .expect("FILE_DISPOSITION_INFO size fits in u32"),
                )
            };
            if legacy_result != 0 {
                return Ok(());
            }
            // SAFETY: no Win32 call intervened after the legacy call.
            let legacy_code = unsafe { GetLastError() };
            anyhow::bail!(
                "delete capability-bound object {} failed: Ex disposition returned Win32 error {code:#010x}; handle-bound legacy disposition returned {legacy_code:#010x}",
                display_path.display()
            );
        }
        anyhow::bail!(
            "delete capability-bound object {} failed with Win32 error {code:#010x}",
            display_path.display()
        );
    }
    Ok(())
}

/// Atomically replace one existing regular-file child of `parent`.
///
/// The target is opened no-follow before any bytes are staged and revalidated
/// immediately before the commit. The temporary file and the final rename stay
/// relative to the supplied directory capability. Missing targets are never
/// created by a normal call: absence fails before staging. Callers serialize
/// same-store mutations; an unrelated process with write access to the same
/// directory remains outside that advisory-lock threat model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileReplaceReport {
    pub(crate) warnings: Vec<String>,
}

/// A conditional replacement proved that its authorized target generation is
/// no longer current before the namespace replacement committed.
///
/// Callers may use this marker to discard transaction state that exists only
/// to recover a possibly committed replacement. Every other replacement error
/// remains indeterminate and must preserve that recovery state.
#[derive(Debug)]
pub(crate) struct ConditionalReplacePreconditionFailed {
    display_path: PathBuf,
}

impl std::fmt::Display for ConditionalReplacePreconditionFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "replacement target {} no longer has the authorized byte generation",
            self.display_path.display()
        )
    }
}

impl std::error::Error for ConditionalReplacePreconditionFailed {}

#[cfg(test)]
pub(crate) fn replace_existing_regular_file(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    let report = replace_existing_regular_file_report(parent, name, display_path, bytes)?;
    for warning in crate::skills::operator_skill_warnings(&report.warnings) {
        tracing::warn!(path = %display_path.display(), %warning, "file replacement committed with warning");
    }
    Ok(())
}

pub(crate) fn replace_existing_regular_file_report(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> Result<FileReplaceReport> {
    replace_existing_regular_file_report_inner(parent, name, display_path, None, bytes)
}

/// Atomically replace an existing regular-file child only while it still has
/// the exact bytes authorized by the caller.
///
/// Both comparisons, the private stage, and the final rename are relative to
/// the same directory capability. The second comparison happens after the
/// replacement bytes are durable and immediately before the handle-relative
/// namespace commit, closing the cooperating-writer window covered by the
/// caller's mutation lock without ever re-resolving an ambient target path.
pub(crate) fn replace_existing_regular_file_if_matches_report(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    expected: &[u8],
    bytes: &[u8],
) -> Result<FileReplaceReport> {
    replace_existing_regular_file_report_inner(parent, name, display_path, Some(expected), bytes)
}

fn replace_existing_regular_file_report_inner(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    expected: Option<&[u8]>,
    bytes: &[u8],
) -> Result<FileReplaceReport> {
    validate_child_name(name)?;
    if let Some(expected) = expected {
        require_regular_file_bytes(parent, name, display_path, expected)
            .context("replacement target changed before staging")?;
    }
    let existing = open_regular_file(parent, name, display_path)?;
    let permissions = existing
        .metadata()
        .with_context(|| format!("inspect replacement target {}", display_path.display()))?
        .permissions();
    drop(existing);

    let mut stage_name = None;
    let mut stage = None;
    for _ in 0..8 {
        let candidate =
            std::ffi::OsString::from(format!(".neoth-replace-{}", uuid::Uuid::new_v4().simple()));
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
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            options
                .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_WRITE_THROUGH);
        }
        match parent.open_with(&candidate, &options) {
            Ok(file) => {
                stage_name = Some(candidate);
                stage = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "create capability-bound replacement for {}",
                        display_path.display()
                    )
                });
            }
        }
    }
    let stage_name = stage_name.context("could not allocate a private replacement file")?;
    let mut stage = stage.context("private replacement handle is unexpectedly absent")?;
    let mut committed = false;
    let mut warnings = Vec::new();
    let replace_result = (|| -> Result<()> {
        stage
            .write_all(bytes)
            .with_context(|| format!("write replacement for {}", display_path.display()))?;
        stage
            .set_permissions(permissions)
            .with_context(|| format!("preserve permissions for {}", display_path.display()))?;
        stage
            .sync_all()
            .with_context(|| format!("sync replacement for {}", display_path.display()))?;

        // Reject a target that changed or became a link/special file while the
        // stage was being written. The atomic commit replaces the leaf entry
        // itself and never follows it.
        if let Some(expected) = expected {
            require_regular_file_bytes(parent, name, display_path, expected)
                .context("replacement target changed before commit")?;
        } else {
            drop(open_regular_file(parent, name, display_path)?);
        }
        replace_staged_file(parent, &stage, &stage_name, name, display_path)?;
        committed = true;
        if let Err(error) =
            sync_parent_directory(parent, display_path.parent().unwrap_or(display_path))
        {
            warnings.push(format!(
                "replacement is committed, but parent-directory durability could not be confirmed: {error:#}"
            ));
        }
        Ok(())
    })();
    drop(stage);

    if let Err(error) = replace_result {
        if committed {
            return Err(error);
        }
        let stage_display = display_path
            .parent()
            .unwrap_or(display_path)
            .join(&stage_name);
        return match remove_child_file(parent, &stage_name, &stage_display) {
            Ok(()) => Err(error),
            Err(cleanup_error)
                if cleanup_error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                Err(error)
            }
            Err(cleanup_error) => Err(error.context(format!(
                "cleanup of staged replacement `{}` also failed: {cleanup_error}",
                stage_name.to_string_lossy()
            ))),
        };
    }
    Ok(FileReplaceReport { warnings })
}

fn require_regular_file_bytes(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    expected: &[u8],
) -> Result<()> {
    let actual = read_regular_file_bounded(parent, name, display_path, expected.len())
        .with_context(|| ConditionalReplacePreconditionFailed {
            display_path: display_path.to_path_buf(),
        })?;
    if actual != expected {
        return Err(ConditionalReplacePreconditionFailed {
            display_path: display_path.to_path_buf(),
        }
        .into());
    }
    Ok(())
}

#[cfg(unix)]
fn replace_staged_file(
    parent: &Dir,
    _stage: &File,
    stage_name: &OsStr,
    target_name: &OsStr,
    display_path: &Path,
) -> Result<()> {
    parent
        .rename(stage_name, parent, target_name)
        .with_context(|| format!("atomically replace {}", display_path.display()))
}

#[cfg(windows)]
fn replace_staged_file(
    parent: &Dir,
    stage: &File,
    _stage_name: &OsStr,
    target_name: &OsStr,
    display_path: &Path,
) -> Result<()> {
    windows_rename_open_handle(stage, parent, target_name, true, display_path)
}

#[cfg(windows)]
#[repr(C)]
struct NtIoStatusBlock {
    status_or_pointer: *mut std::ffi::c_void,
    information: usize,
}

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetInformationFile(
        file_handle: windows_sys::Win32::Foundation::HANDLE,
        io_status_block: *mut NtIoStatusBlock,
        file_information: *mut std::ffi::c_void,
        length: u32,
        file_information_class: i32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[cfg(windows)]
fn windows_rename_open_handle(
    source: &File,
    target_parent: &Dir,
    target_name: &OsStr,
    replace_existing: bool,
    display_path: &Path,
) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{FILE_RENAME_INFO, FILE_RENAME_INFO_0};

    let target_w: Vec<u16> = target_name.encode_wide().collect();
    let file_name_bytes = target_w
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .context("skill replacement target name is too long")?;
    let file_name_offset = u32::try_from(std::mem::offset_of!(FILE_RENAME_INFO, FileName))
        .expect("FILE_RENAME_INFO offset fits in u32");
    let buffer_size = file_name_offset
        .checked_add(file_name_bytes)
        .context("skill replacement target name is too long")?;
    let machine_words = (buffer_size as usize).div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0usize; machine_words];
    let rename_info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();

    // SAFETY: storage is aligned and sized through the variable-length UTF-16
    // FileName field. Both handles stay alive for the system call; the target
    // name is resolved relative to the already-bound parent handle.
    unsafe {
        std::ptr::addr_of_mut!((*rename_info).Anonymous).write(FILE_RENAME_INFO_0 {
            ReplaceIfExists: u8::from(replace_existing),
        });
        std::ptr::addr_of_mut!((*rename_info).RootDirectory)
            .write(target_parent.as_raw_handle() as HANDLE);
        std::ptr::addr_of_mut!((*rename_info).FileNameLength).write(file_name_bytes);
        target_w.as_ptr().copy_to_nonoverlapping(
            std::ptr::addr_of_mut!((*rename_info).FileName).cast::<u16>(),
            target_w.len(),
        );
    }
    let mut io_status = NtIoStatusBlock {
        status_or_pointer: std::ptr::null_mut(),
        information: 0,
    };
    const FILE_RENAME_INFORMATION_CLASS: i32 = 10;
    // SAFETY: both handles and rename_info remain live for the call; the
    // variable-length buffer is initialized through FileNameLength. The
    // native file-information API is required because the Win32
    // SetFileInformationByHandle wrapper rejects non-null RootDirectory even
    // though the underlying FILE_RENAME_INFORMATION contract supports it.
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut io_status,
            rename_info.cast::<std::ffi::c_void>(),
            buffer_size,
            FILE_RENAME_INFORMATION_CLASS,
        )
    };
    if status < 0 {
        // SAFETY: RtlNtStatusToDosError is a pure status-code conversion and
        // the immediately preceding NTSTATUS is preserved in `status`.
        let code = unsafe { RtlNtStatusToDosError(status) };
        anyhow::bail!(
            "atomically rename {} failed with NTSTATUS {status:#010x} / Win32 error {code:#010x}",
            display_path.display()
        );
    }
    Ok(())
}

pub(crate) fn sync_parent_directory(parent: &Dir, display_path: &Path) -> Result<()> {
    #[cfg(test)]
    if FORCE_PARENT_SYNC_FAILURE.with(std::cell::Cell::get) {
        anyhow::bail!("injected parent-directory sync failure")
    }
    #[cfg(unix)]
    {
        parent
            .open(".")
            .and_then(|file| file.sync_all())
            .with_context(|| format!("sync directory {}", display_path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (parent, display_path);
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FORCE_PARENT_SYNC_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn force_parent_sync_failure_for_test(enabled: bool) {
    FORCE_PARENT_SYNC_FAILURE.with(|forced| forced.set(enabled));
}

pub(crate) fn cap_metadata_is_link_like(metadata: &cap_std::fs::Metadata) -> bool {
    if metadata.is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn read_bounded(file: File, display_path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    file.take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", display_path.display()))?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} exceeds the {max_bytes}-byte skill file limit",
                display_path.display()
            ),
        )
        .into());
    }
    Ok(bytes)
}

fn open_ambient_directory_nofollow(path: &Path, label: &str) -> Result<Dir> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
        options
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ_WRITE);
    }

    let file = options.open(path).with_context(|| {
        format!(
            "open trusted {label} ancestor without following links {}",
            path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect trusted {label} ancestor {}", path.display()))?;
    if !metadata.is_dir() || std_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "trusted {label} ancestor is not a real directory: {}",
            path.display()
        );
    }
    Ok(Dir::from_std_file(file))
}

fn ensure_cap_directory_is_real(dir: &Dir, label: &str, display_path: &Path) -> Result<()> {
    let metadata = dir.dir_metadata().with_context(|| {
        format!(
            "inspect opened {label} directory {}",
            display_path.display()
        )
    })?;
    if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "{label} is not a real directory: {}",
            display_path.display()
        );
    }
    Ok(())
}

fn validate_child_name(name: &OsStr) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        anyhow::bail!("skill store child name must be exactly one normal path component");
    }
    if name.to_string_lossy().contains(['\0', '/', '\\', ':']) {
        anyhow::bail!("skill store child name contains a path separator, NUL, or stream marker");
    }
    Ok(())
}

fn std_metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn try_link_dir(source: &Path, target: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(source, target)
    }

    #[cfg(windows)]
    fn try_link_dir(source: &Path, target: &Path) -> std::io::Result<()> {
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

    #[test]
    fn replace_existing_regular_file_atomically_replaces_contents() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("skill.yaml");
        std::fs::write(&target, b"old").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        replace_existing_regular_file(&root.dir, OsStr::new("skill.yaml"), &target, b"replacement")
            .unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"replacement");
        assert_eq!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-replace-"))
                .count(),
            0
        );
    }

    #[test]
    fn replace_existing_regular_file_never_creates_a_missing_target() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("missing.yaml");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let error = replace_existing_regular_file(
            &root.dir,
            OsStr::new("missing.yaml"),
            &target,
            b"replacement",
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("open skill source file"));
        assert!(!target.exists());
    }

    #[test]
    fn conditional_file_replacement_preserves_a_changed_target_and_cleans_stage() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("skill.md");
        std::fs::write(&target, b"concurrent-generation").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let error = replace_existing_regular_file_if_matches_report(
            &root.dir,
            OsStr::new("skill.md"),
            &target,
            b"authorized-generation",
            b"replacement",
        )
        .expect_err("an unexpected byte generation must never be replaced");

        assert!(format!("{error:#}").contains("changed before staging"));
        assert_eq!(std::fs::read(&target).unwrap(), b"concurrent-generation");
        assert_eq!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-replace-"))
                .count(),
            0
        );
    }

    #[test]
    fn rename_child_commits_the_opened_directory_generation() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("sentinel"), b"generation").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        rename_child(
            &root.dir,
            OsStr::new("source"),
            &root.dir,
            OsStr::new("target"),
            false,
            &source,
            &target,
        )
        .unwrap();

        assert!(!source.exists());
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"generation"
        );
    }

    #[test]
    fn rename_child_without_replace_preserves_both_existing_entries() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::write(&source, b"source-generation").unwrap();
        std::fs::write(&target, b"target-sentinel").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let error = rename_child(
            &root.dir,
            OsStr::new("source"),
            &root.dir,
            OsStr::new("target"),
            false,
            &source,
            &target,
        )
        .unwrap_err();

        assert!(!format!("{error:#}").is_empty());
        assert_eq!(std::fs::read(&source).unwrap(), b"source-generation");
        assert_eq!(std::fs::read(&target).unwrap(), b"target-sentinel");
    }

    #[test]
    fn rename_child_with_replace_commits_source_over_existing_target() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::write(&source, b"source-generation").unwrap();
        std::fs::write(&target, b"target-sentinel").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        rename_child(
            &root.dir,
            OsStr::new("source"),
            &root.dir,
            OsStr::new("target"),
            true,
            &source,
            &target,
        )
        .unwrap();

        assert!(!source.exists());
        assert_eq!(std::fs::read(&target).unwrap(), b"source-generation");
    }

    #[test]
    fn remove_real_directory_tree_does_not_follow_nested_links() {
        let temp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_sentinel = outside.path().join("keep.txt");
        std::fs::write(&outside_sentinel, b"keep").unwrap();
        let victim = temp.path().join("victim");
        std::fs::create_dir_all(victim.join("nested")).unwrap();
        std::fs::write(victim.join("nested").join("inside.txt"), b"remove").unwrap();
        if try_link_dir(outside.path(), &victim.join("outside-link")).is_err() {
            return;
        }
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        remove_real_directory_tree(&root.dir, OsStr::new("victim"), &victim).unwrap();

        assert!(!victim.exists());
        assert_eq!(std::fs::read(&outside_sentinel).unwrap(), b"keep");
    }

    #[test]
    fn removal_budget_failure_retains_retryable_root() {
        let temp = tempdir().unwrap();
        let victim = temp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("one.txt"), b"one").unwrap();
        std::fs::write(victim.join("two.txt"), b"two").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        let mut budget = DeleteBudget::new(1, 16);

        let error = remove_real_directory_tree_with_budget(
            &root.dir,
            OsStr::new("victim"),
            &victim,
            &mut budget,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("aggregate 1-entry limit"));
        assert!(victim.is_dir(), "tombstone must remain available for retry");

        remove_real_directory_tree(&root.dir, OsStr::new("victim"), &victim).unwrap();
        assert!(!victim.exists());
    }

    #[test]
    fn removal_work_counter_fails_closed_on_overflow() {
        let mut budget = DeleteBudget {
            entries: 0,
            work_units: usize::MAX,
            max_entries: usize::MAX,
            max_work_units: usize::MAX,
        };

        let error = budget.charge_work(Path::new("victim")).unwrap_err();

        assert!(format!("{error:#}").contains("work counter overflow"));
    }

    #[test]
    fn removal_work_budget_failure_retains_retryable_root() {
        let temp = tempdir().unwrap();
        let victim = temp.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("keep.txt"), b"keep").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        // Root enumeration consumes the first unit. Inspecting the first entry
        // would consume the second and must fail before any mutation.
        let mut budget = DeleteBudget::new(8, 1);

        let error = remove_real_directory_tree_with_budget(
            &root.dir,
            OsStr::new("victim"),
            &victim,
            &mut budget,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("aggregate 1-unit work limit"));
        assert_eq!(std::fs::read(victim.join("keep.txt")).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn replace_existing_regular_file_rejects_a_linked_target() {
        let temp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let target = temp.path().join("skill.yaml");
        std::os::unix::fs::symlink(&sentinel, &target).unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        replace_existing_regular_file(&root.dir, OsStr::new("skill.yaml"), &target, b"replacement")
            .expect_err("a linked mutation target must be rejected");

        assert!(std::fs::symlink_metadata(&target).unwrap().is_symlink());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
    }
}
