//! Capability-bound filesystem boundary for user-installed skills.
//!
//! The ambient path is used only to select a trusted ancestor. Every
//! component below that ancestor is then created/opened relative to an owned
//! directory handle and without following links. Security-sensitive rename and
//! recursive-delete operations use native handle-relative primitives on Windows
//! instead of cap-std's ambient-path fallbacks. Bound traversal never follows a
//! swapped ancestor. Unix file publication additionally requires an
//! owner-private parent and verifies the exact open stage before and after its
//! unavoidable name-based rename; it does not claim isolation from a hostile
//! process running as the same OS identity.

use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
#[cfg(windows)]
use cap_fs_ext::MetadataExt as _;
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
#[cfg(unix)]
use cap_std::fs::DirBuilder;
use cap_std::fs::{Dir, File, OpenOptions};

#[cfg(test)]
thread_local! {
    static TEST_DELETE_WORK_BEFORE_FAILURE: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(test, unix))]
thread_local! {
    static TEST_BEFORE_EMPTY_DIRECTORY_RENAME:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static TEST_BEFORE_OPEN_FILE_RENAME:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static TEST_AFTER_BOUND_FILE_REVALIDATION:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, windows))]
thread_local! {
    static TEST_BEFORE_WINDOWS_RECURSIVE_LEAF_DELETE:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn fail_delete_after_work_units(units: usize) {
    TEST_DELETE_WORK_BEFORE_FAILURE.with(|remaining| remaining.set(Some(units)));
}

#[cfg(all(test, unix))]
fn set_before_empty_directory_rename_for_test(hook: impl FnOnce() + 'static) {
    TEST_BEFORE_EMPTY_DIRECTORY_RENAME.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(all(test, unix))]
fn run_before_empty_directory_rename_for_test() {
    TEST_BEFORE_EMPTY_DIRECTORY_RENAME.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(all(test, unix))]
fn set_before_open_file_rename_for_test(hook: impl FnOnce() + 'static) {
    TEST_BEFORE_OPEN_FILE_RENAME.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(all(test, unix))]
fn run_before_open_file_rename_for_test() {
    TEST_BEFORE_OPEN_FILE_RENAME.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(all(test, unix))]
fn set_after_bound_file_revalidation_for_test(hook: impl FnOnce() + 'static) {
    TEST_AFTER_BOUND_FILE_REVALIDATION.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(all(test, unix))]
fn run_after_bound_file_revalidation_for_test() {
    TEST_AFTER_BOUND_FILE_REVALIDATION.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(all(test, windows))]
fn set_before_windows_recursive_leaf_delete_for_test(hook: impl FnOnce() + 'static) {
    TEST_BEFORE_WINDOWS_RECURSIVE_LEAF_DELETE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(all(test, windows))]
fn run_before_windows_recursive_leaf_delete_for_test() {
    TEST_BEFORE_WINDOWS_RECURSIVE_LEAF_DELETE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
#[derive(Clone)]
struct TestPostCommitFailureRegistration {
    target: PathBuf,
    generation: u64,
}

#[cfg(test)]
static TEST_FAIL_PRIVATE_CHILD_POST_COMMIT_VALIDATION_AT: std::sync::Mutex<
    Vec<TestPostCommitFailureRegistration>,
> = std::sync::Mutex::new(Vec::new());
#[cfg(test)]
static TEST_POST_COMMIT_FAILURE_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

/// Inject a failure after a private regular-file stage has been atomically
/// renamed, but before the writer validates the committed target identity.
/// This is keyed by the operator-facing target path so parallel tests cannot
/// consume one another's failure.
#[cfg(test)]
pub(crate) fn fail_private_child_post_commit_validation_for_test(target: &Path) {
    let generation = TEST_POST_COMMIT_FAILURE_GENERATION
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut targets = TEST_FAIL_PRIVATE_CHILD_POST_COMMIT_VALIDATION_AT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    targets.retain(|candidate| candidate.target != target);
    targets.push(TestPostCommitFailureRegistration {
        target: target.to_path_buf(),
        generation,
    });
}

#[cfg(test)]
fn inject_private_child_post_commit_validation_failure(target: &Path) -> Result<()> {
    let mut targets = TEST_FAIL_PRIVATE_CHILD_POST_COMMIT_VALIDATION_AT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(index) = targets
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.target == target)
        .max_by_key(|(_, candidate)| candidate.generation)
        .map(|(index, _)| index)
    {
        targets.swap_remove(index);
        anyhow::bail!("injected private-child post-commit validation failure");
    }
    Ok(())
}

/// Open directory plus the operator-facing absolute namespace path. Security
/// decisions use `dir`; `display_path` is reporting-only.
pub(crate) struct BoundDirectory {
    pub(crate) dir: Dir,
    pub(crate) display_path: PathBuf,
}

/// Stable no-follow identity for one direct child. Real files/directories keep
/// their opened handle alive across the caller's commit window; Unix symlinks
/// cannot be opened portably without following them, so they retain the
/// equivalent `lstat` device/inode/type identity. The token is persisted only
/// in the private Skill-mutation journal and is never an ambient path.
pub(crate) struct BoundChildObject {
    identity_token: String,
    _handle: Option<File>,
}

/// Stable no-follow identity for one direct real-directory child.
///
/// Unlike [`BoundChildObject`], this intentionally retains no native mutation
/// handle. `cap_std::fs::Dir` requires its Windows handle to withhold
/// `FILE_SHARE_DELETE`; revalidating a retained directory through another
/// no-follow directory capability preserves that fence without ever requesting
/// directory `DELETE` access.
pub(crate) struct BoundDirectoryChild {
    identity_token: String,
}

impl BoundDirectoryChild {
    /// Re-check a direct real-directory child through a cap-std-compliant
    /// no-follow capability and compare its stable identity.
    pub(crate) fn matches_directory_child(
        &self,
        parent: &Dir,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<bool> {
        Ok(readonly_real_directory_identity(parent, name, display_path)? == self.identity_token)
    }
}

impl BoundChildObject {
    #[must_use]
    pub(crate) fn identity_token(&self) -> &str {
        &self.identity_token
    }

    pub(crate) fn matches_child(
        &self,
        parent: &Dir,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<bool> {
        Ok(bind_child_object(parent, name, display_path)?.identity_token == self.identity_token)
    }

    /// Re-check a regular-file namespace binding through a read-only handle.
    ///
    /// Windows mutation bindings deliberately request `DELETE` so a later
    /// handle-relative rename/delete cannot be redirected. A pure read/copy
    /// path must not require that capability: operator-owned credential files
    /// commonly grant read access while denying deletion. This variant opens
    /// the named child with `FILE_GENERIC_READ` only, retains no mutation
    /// authority, and compares the resulting file identity with this binding.
    pub(crate) fn matches_regular_file_child_readonly(
        &self,
        parent: &Dir,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<bool> {
        Ok(readonly_regular_file_identity(parent, name, display_path)? == self.identity_token)
    }

    /// Re-check a review byte capture's direct-child binding using the same
    /// no-follow open contract as its original handle.
    ///
    /// This must not reuse the ordinary read-only identity helper: on Windows
    /// that helper deliberately permits write/delete sharing for copy and
    /// mutation workflows, whereas the operator-review reader restricts
    /// future sharing where the platform exposes that facility.
    pub(crate) fn matches_regular_file_snapshot(
        &self,
        parent: &Dir,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<bool> {
        Ok(snapshot_regular_file_identity(parent, name, display_path)? == self.identity_token)
    }

    /// Remove the exact regular file retained by this binding.
    ///
    /// Windows commits through the retained `DELETE`-capable handle, so a
    /// same-name replacement cannot redirect the deletion. Unix has no
    /// portable unlink-by-handle primitive; it therefore quarantines the name,
    /// proves the atomic rename moved the retained inode, and only then unlinks
    /// the unpredictable capability-relative tombstone.
    pub(crate) fn remove_bound_file(
        self,
        _parent: &Dir,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<()> {
        validate_child_name(name)?;
        let handle = self._handle.with_context(|| {
            format!(
                "bound regular-file removal has no retained handle: {}",
                display_path.display()
            )
        })?;
        let metadata = handle.metadata().with_context(|| {
            format!(
                "inspect retained regular-file removal handle {}",
                display_path.display()
            )
        })?;
        anyhow::ensure!(
            metadata.is_file() && !cap_metadata_is_link_like(&metadata),
            "bound removal target is not a real regular file: {}",
            display_path.display()
        );
        anyhow::ensure!(
            child_identity_token(&metadata)? == self.identity_token,
            "retained regular-file removal identity changed: {}",
            display_path.display()
        );

        #[cfg(windows)]
        {
            windows_mark_delete(&handle, display_path)?;
            Ok(())
        }
        #[cfg(unix)]
        {
            anyhow::ensure!(
                readonly_regular_file_identity(_parent, name, display_path)? == self.identity_token,
                "regular-file removal target changed before commit: {}",
                display_path.display()
            );

            #[cfg(test)]
            run_after_bound_file_revalidation_for_test();

            // Unix has no portable unlink-by-handle operation. Move the
            // currently named entry to an unpredictable private tombstone
            // first, then prove which inode the atomic rename actually moved.
            // A replacement that wins the validation/rename race is restored
            // (or retained under the tombstone on a contested restore), never
            // unlinked as though it were the authorized file.
            let tombstone = std::ffi::OsString::from(format!(
                ".neoth-bound-delete-{}",
                uuid::Uuid::new_v4().simple()
            ));
            let tombstone_display = display_path
                .parent()
                .unwrap_or(display_path)
                .join(&tombstone);
            rename_child(
                _parent,
                name,
                _parent,
                &tombstone,
                false,
                display_path,
                &tombstone_display,
            )
            .with_context(|| {
                format!(
                    "quarantine exact regular-file removal target {}",
                    display_path.display()
                )
            })?;

            let moved_identity =
                readonly_regular_file_identity(_parent, &tombstone, &tombstone_display);
            match moved_identity {
                Ok(identity) if identity == self.identity_token => {}
                Ok(_) => {
                    let restore = rename_child(
                        _parent,
                        &tombstone,
                        _parent,
                        name,
                        false,
                        &tombstone_display,
                        display_path,
                    );
                    let sync = sync_parent_directory(
                        _parent,
                        display_path.parent().unwrap_or(display_path),
                    );
                    return match (restore, sync) {
                        (Ok(()), Ok(_)) => anyhow::bail!(
                            "regular-file removal race moved a replacement; it was restored without deletion: {}",
                            display_path.display()
                        ),
                        (Ok(()), Err(sync_error)) => Err(sync_error).with_context(|| {
                            format!(
                                "replacement was restored after a regular-file removal race, but parent durability is unconfirmed: {}",
                                display_path.display()
                            )
                        }),
                        (Err(restore_error), Ok(_)) => Err(restore_error).with_context(|| {
                            format!(
                                "regular-file removal race moved a replacement; it remains preserved at {} because restoring {} failed",
                                tombstone_display.display(),
                                display_path.display()
                            )
                        }),
                        (Err(restore_error), Err(sync_error)) => {
                            Err(restore_error).with_context(|| {
                                format!(
                                    "regular-file removal race moved a replacement; it remains preserved at {}; restoring {} failed and parent durability is also unconfirmed: {sync_error:#}",
                                    tombstone_display.display(),
                                    display_path.display()
                                )
                            })
                        }
                    };
                }
                Err(inspect_error) => {
                    let sync = sync_parent_directory(
                        _parent,
                        display_path.parent().unwrap_or(display_path),
                    );
                    return match sync {
                        Ok(_) => Err(inspect_error).with_context(|| {
                            format!(
                                "could not prove quarantined regular-file identity; object retained at {}",
                                tombstone_display.display()
                            )
                        }),
                        Err(sync_error) => Err(inspect_error).with_context(|| {
                            format!(
                                "could not prove quarantined regular-file identity; object retained at {} and parent durability is unconfirmed: {sync_error:#}",
                                tombstone_display.display()
                            )
                        }),
                    };
                }
            }

            _parent.remove_file(&tombstone).with_context(|| {
                format!(
                    "remove exact capability-bound regular file {}",
                    tombstone_display.display()
                )
            })?;
            sync_parent_directory(_parent, display_path.parent().unwrap_or(display_path))?;
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (_parent, handle);
            anyhow::bail!(
                "exact bound regular-file removal is unsupported on this platform: {}",
                display_path.display()
            )
        }
    }
}

fn child_kind(metadata: &cap_std::fs::Metadata) -> &'static str {
    if cap_metadata_is_link_like(metadata) {
        "link"
    } else if metadata.is_dir() {
        "dir"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    }
}

fn child_identity_token(metadata: &cap_std::fs::Metadata) -> Result<String> {
    let kind = child_kind(metadata);
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        Ok(format!(
            "unix:{:016x}:{:016x}:{kind}",
            metadata.dev(),
            metadata.ino()
        ))
    }
    #[cfg(windows)]
    {
        let volume = metadata.dev();
        let file_index = metadata.ino();
        Ok(format!("windows:{volume:08x}:{file_index:016x}:{kind}"))
    }
}

pub(crate) fn valid_child_identity_token(token: &str) -> bool {
    fn valid_hex(value: &str, width: usize) -> bool {
        value.len() == width
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    let mut fields = token.split(':');
    let Some(platform) = fields.next() else {
        return false;
    };
    let Some(first) = fields.next() else {
        return false;
    };
    let Some(second) = fields.next() else {
        return false;
    };
    let Some(kind) = fields.next() else {
        return false;
    };
    if fields.next().is_some() || !matches!(kind, "dir" | "file" | "link" | "other") {
        return false;
    }
    match platform {
        "unix" => valid_hex(first, 16) && valid_hex(second, 16),
        "windows" => valid_hex(first, 8) && valid_hex(second, 16),
        _ => false,
    }
}

/// Bind one direct child without following it. The returned identity can be
/// compared after a rename to prove the kernel moved the exact object that was
/// authorized, rather than a same-name replacement introduced in the final
/// lookup gap.
pub(crate) fn bind_child_object(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<BoundChildObject> {
    validate_child_name(name)?;
    #[cfg(windows)]
    {
        let handle = open_windows_mutation_handle(parent, name, display_path)?;
        let metadata = handle
            .metadata()
            .with_context(|| format!("inspect bound Skill object {}", display_path.display()))?;
        Ok(BoundChildObject {
            identity_token: child_identity_token(&metadata)?,
            _handle: Some(handle),
        })
    }
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
        match parent.open_with(name, &options) {
            Ok(handle) => {
                let metadata = handle.metadata().with_context(|| {
                    format!("inspect bound Skill object {}", display_path.display())
                })?;
                Ok(BoundChildObject {
                    identity_token: child_identity_token(&metadata)?,
                    _handle: Some(handle),
                })
            }
            Err(open_error) => {
                let metadata = parent.symlink_metadata(name).with_context(|| {
                    format!(
                        "inspect no-follow Skill object after open failure {}",
                        display_path.display()
                    )
                })?;
                if !cap_metadata_is_link_like(&metadata) {
                    return Err(open_error).with_context(|| {
                        format!("open bound Skill object {}", display_path.display())
                    });
                }
                Ok(BoundChildObject {
                    identity_token: child_identity_token(&metadata)?,
                    _handle: None,
                })
            }
        }
    }
}

/// Bind one direct real-directory child without acquiring directory mutation
/// authority. The identity is revalidated through `open_dir_nofollow`, whose
/// Windows handle honors cap-std's no-delete-share requirement.
fn bind_directory_child(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<BoundDirectoryChild> {
    Ok(BoundDirectoryChild {
        identity_token: readonly_real_directory_identity(parent, name, display_path)?,
    })
}

/// Open `path` as a stable directory capability. The grandparent is the
/// explicit ambient trust boundary: for the production
/// `<user-home>/.neoth/skills` path this is the user home, matching the updater
/// trust model. Public callers that supply a custom path are responsible for
/// ensuring its grandparent (or nearest existing ancestor) is trusted. Every
/// component below that boundary is protected. If the anchor is absent, the
/// nearest existing ancestor is used and every missing descendant is created
/// handle-relatively.
///
/// Production creation paths should use
/// [`open_bound_directory_from_trusted_anchor`] instead. This dynamic-anchor
/// variant remains for read-only discovery and its durability regression tests.
fn has_navigation_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

pub(crate) fn open_bound_directory(
    path: &Path,
    create: bool,
    label: &str,
) -> Result<Option<BoundDirectory>> {
    if has_navigation_component(path) {
        anyhow::bail!(
            "{label} path must not contain `.` or `..` components: {}",
            path.display()
        );
    }
    let absolute = std::path::absolute(path)
        .with_context(|| format!("resolve absolute {label} path {}", path.display()))?;
    if has_navigation_component(&absolute) {
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
    let designated_anchor = anchor.clone();
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
    if create && anchor == designated_anchor {
        // The designated grandparent may be the visible residue of this
        // function's earlier mkdir + failed parent-sync attempt. Confirm its
        // namespace publication before treating it as the trusted boundary;
        // otherwise a retry could descend into it and publish a child.
        if let Some(anchor_parent) = canonical_anchor.parent() {
            let parent = open_ambient_directory_nofollow(anchor_parent, label)?;
            sync_parent_directory(&parent, anchor_parent).with_context(|| {
                format!(
                    "sync parent before using existing trusted {label} boundary {}",
                    canonical_anchor.display()
                )
            })?;
        }
    }
    let current = open_ambient_directory_nofollow(&canonical_anchor, label)?;
    walk_bound_directory_descendants(
        current,
        canonical_anchor,
        &relative,
        &absolute,
        create,
        label,
    )
}

/// Open an operator-selected absolute path from a fixed filesystem root,
/// walking *every* descendant through no-follow directory capabilities.
///
/// Unlike [`open_bound_directory`], this function never derives or
/// canonicalizes a trust anchor from the supplied path. UNC and other
/// non-disk Windows namespaces are deliberately unsupported because their
/// root identity cannot be established by this local operator boundary.
pub(crate) fn open_absolute_bound_directory(
    path: &Path,
    create: bool,
    label: &str,
) -> Result<Option<BoundDirectory>> {
    if has_navigation_component(path) {
        anyhow::bail!(
            "{label} path must not contain `.` or `..` components: {}",
            path.display()
        );
    }
    let absolute = std::path::absolute(path)
        .with_context(|| format!("resolve absolute {label} path {}", path.display()))?;
    if has_navigation_component(&absolute) {
        anyhow::bail!(
            "{label} path must not contain `.` or `..` components: {}",
            path.display()
        );
    }

    #[cfg(unix)]
    let root = PathBuf::from("/");
    #[cfg(windows)]
    let root = {
        use std::path::Prefix;

        let mut components = absolute.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            anyhow::bail!(
                "{label} path has no supported disk root: {}",
                path.display()
            );
        };
        let Prefix::Disk(letter) = prefix.kind() else {
            anyhow::bail!(
                "{label} path has no supported disk root: {}",
                path.display()
            );
        };
        anyhow::ensure!(
            matches!(components.next(), Some(Component::RootDir)),
            "{label} path must be absolute beneath a disk root: {}",
            path.display()
        );
        PathBuf::from(format!("{}:\\", char::from(letter)))
    };
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (create, label, absolute);
        anyhow::bail!("{label} document review source is unsupported on this platform");
    }

    #[cfg(any(unix, windows))]
    {
        let relative = absolute.strip_prefix(&root).with_context(|| {
            format!(
                "derive {label} path below fixed filesystem root {}",
                root.display()
            )
        })?;
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            anyhow::bail!(
                "{label} path has a non-child component below its filesystem root: {}",
                path.display()
            );
        }
        let current = open_ambient_directory_nofollow(&root, label)?;
        walk_bound_directory_descendants(current, root, relative, &absolute, create, label)
    }

    #[cfg(not(any(unix, windows)))]
    unreachable!("unsupported platform returned above");
}

/// Open or create `path` below an explicit, already-existing trust anchor.
///
/// Unlike [`open_bound_directory`], this contract never re-selects the ambient
/// anchor from filesystem state. A directory left visible by a failed parent
/// sync therefore remains a guarded descendant on every retry. The anchor is
/// canonicalized and opened exactly once; every component below it is then
/// opened or created through directory capabilities without following links.
///
/// In create mode, the parent namespace of every existing or newly-created
/// descendant is synced before the walk can descend beneath it.
pub(crate) fn open_bound_directory_from_trusted_anchor(
    trusted_anchor: &Path,
    path: &Path,
    create: bool,
    label: &str,
) -> Result<Option<BoundDirectory>> {
    if has_navigation_component(trusted_anchor) {
        anyhow::bail!(
            "trusted {label} anchor must not contain `.` or `..` components: {}",
            trusted_anchor.display()
        );
    }
    let absolute_anchor = std::path::absolute(trusted_anchor).with_context(|| {
        format!(
            "resolve absolute trusted {label} anchor {}",
            trusted_anchor.display()
        )
    })?;
    if has_navigation_component(&absolute_anchor) {
        anyhow::bail!(
            "trusted {label} anchor must not contain `.` or `..` components: {}",
            trusted_anchor.display()
        );
    }

    if has_navigation_component(path) {
        anyhow::bail!(
            "{label} path must not contain `.` or `..` components: {}",
            path.display()
        );
    }
    let absolute = std::path::absolute(path)
        .with_context(|| format!("resolve absolute {label} path {}", path.display()))?;
    if has_navigation_component(&absolute) {
        anyhow::bail!(
            "{label} path must not contain `.` or `..` components: {}",
            path.display()
        );
    }

    let relative = absolute
        .strip_prefix(&absolute_anchor)
        .with_context(|| {
            format!(
                "{label} target {} is outside trusted anchor {}",
                absolute.display(),
                absolute_anchor.display()
            )
        })?
        .to_path_buf();
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        anyhow::bail!(
            "{label} target has a non-child component below trusted anchor {}: {}",
            absolute_anchor.display(),
            absolute.display()
        );
    }

    let canonical_anchor = std::fs::canonicalize(&absolute_anchor).with_context(|| {
        format!(
            "canonicalize existing trusted {label} anchor {}",
            absolute_anchor.display()
        )
    })?;
    let current = open_ambient_directory_nofollow(&canonical_anchor, label)?;
    walk_bound_directory_descendants(
        current,
        canonical_anchor,
        &relative,
        &absolute,
        create,
        label,
    )
}

fn walk_bound_directory_descendants(
    mut current: Dir,
    mut current_display: PathBuf,
    relative: &Path,
    absolute: &Path,
    create: bool,
    label: &str,
) -> Result<Option<BoundDirectory>> {
    for component in relative.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!(
                "{label} path has a non-child component below its trusted ancestor: {}",
                absolute.display()
            );
        };
        let next_display = current_display.join(name);
        match current.open_dir_nofollow(name) {
            Ok(next) => {
                ensure_cap_directory_is_real(&next, label, absolute)?;
                if create {
                    // A prior mkdir attempt may have published this child but
                    // failed its durability confirmation. Re-sync even an
                    // already-visible entry before any caller can descend and
                    // publish a marker beneath it.
                    sync_parent_directory(&current, &current_display).with_context(|| {
                        format!(
                            "sync parent before using existing {label} component `{}`",
                            name.to_string_lossy()
                        )
                    })?;
                }
                current = next;
                current_display = next_display;
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
                // `AlreadyExists` may be the visible residue of this process's
                // earlier mkdir + failed fsync attempt. Confirm the parent on
                // both creation outcomes before descending.
                sync_parent_directory(&current, &current_display).with_context(|| {
                    format!(
                        "sync parent after resolving new {label} component `{}`",
                        name.to_string_lossy()
                    )
                })?;
                let next = current.open_dir_nofollow(name).with_context(|| {
                    format!(
                        "open newly-created {label} component `{}` without following links",
                        name.to_string_lossy()
                    )
                })?;
                ensure_cap_directory_is_real(&next, label, absolute)?;
                current = next;
                current_display = next_display;
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

    ensure_cap_directory_is_real(&current, label, absolute)?;
    Ok(Some(BoundDirectory {
        dir: current,
        display_path: absolute.to_path_buf(),
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

/// Read a direct real-directory child's stable identity through cap-std's
/// no-follow directory open. No returned or temporary handle requests
/// directory `DELETE` access.
fn readonly_real_directory_identity(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<String> {
    let child = open_real_child_dir(parent, name, display_path)?;
    child_identity_token(&child.dir_metadata().with_context(|| {
        format!(
            "inspect real directory for read-only identity check {}",
            display_path.display()
        )
    })?)
}

/// Open one real child directory and bind the exact retained directory handle
/// to its current direct-child namespace entry.
///
/// This is the directory counterpart to [`open_bound_regular_file`].  The
/// handle identity is derived before the name binding, then compared to the
/// no-follow binding of that name.  Consequently an A-to-B-to-A namespace
/// swap cannot pair a capability for B with a binding for A.  Callers retain
/// both returned values and invoke
/// [`BoundDirectoryChild::matches_directory_child`] before their final
/// aggregate effect or return.
pub(crate) fn open_bound_real_child_dir(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(Dir, BoundDirectoryChild)> {
    let child = open_real_child_dir(parent, name, display_path)?;
    let opened_identity = child_identity_token(&child.dir_metadata().with_context(|| {
        format!(
            "inspect opened bound child directory {}",
            display_path.display()
        )
    })?)?;
    let binding = bind_directory_child(parent, name, display_path)?;
    anyhow::ensure!(
        opened_identity == binding.identity_token,
        "child directory changed while its capability was being bound: {}",
        display_path.display()
    );
    anyhow::ensure!(
        binding.matches_directory_child(parent, name, display_path)?,
        "child directory changed before its capability binding completed: {}",
        display_path.display()
    );
    Ok((child, binding))
}

/// Bind a caller-retained direct-child directory to the exact current namespace
/// object without converting a delete-sharing Windows handle into `Dir`.
pub(crate) fn bind_retained_real_child_dir(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    child: Dir,
) -> Result<(Dir, BoundDirectoryChild)> {
    validate_child_name(name)?;
    ensure_cap_directory_is_real(&child, "bound child", display_path)?;
    let opened_identity = child_identity_token(&child.dir_metadata().with_context(|| {
        format!(
            "inspect retained bound child directory {}",
            display_path.display()
        )
    })?)?;
    let binding = bind_directory_child(parent, name, display_path)?;
    anyhow::ensure!(
        opened_identity == binding.identity_token,
        "child directory changed while its retained capability was being bound: {}",
        display_path.display()
    );
    anyhow::ensure!(
        binding.matches_directory_child(parent, name, display_path)?,
        "child directory changed before its retained capability binding completed: {}",
        display_path.display()
    );
    Ok((child, binding))
}

/// Open one direct real-directory child if it exists. Absence is not an error;
/// a file, symlink, junction, or other reparse point remains a hard refusal.
///
/// This is the read/cleanup counterpart to [`open_or_create_private_child_dir`]:
/// callers can traverse an optional private generation without ever resolving
/// its ambient path.
pub(crate) fn open_real_child_dir_if_present(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<Option<Dir>> {
    validate_child_name(name)?;
    match parent.open_dir_nofollow(name) {
        Ok(child) => {
            ensure_cap_directory_is_real(&child, "private child", display_path)?;
            Ok(Some(child))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "open optional private child directory without following links {}",
                display_path.display()
            )
        }),
    }
}

/// Open or create one private direct-child directory without resolving any
/// descendant through an ambient path.
pub(crate) fn open_or_create_private_child_dir(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<Dir> {
    validate_child_name(name)?;
    match open_private_child_dir_nofollow(parent, name) {
        Ok(child) => {
            ensure_cap_directory_is_real(&child, "private child", display_path)?;
            // Existing may mean "mkdir succeeded, parent fsync failed" from a
            // prior serialized attempt. Confirm the namespace before returning
            // a capability that may publish a marker inside it.
            sync_parent_directory(parent, display_path.parent().unwrap_or(display_path))
                .with_context(|| {
                    format!(
                        "sync parent before using existing private child directory {}",
                        display_path.display()
                    )
                })?;
            Ok(child)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match create_private_child_directory(parent, name) {
                Ok(()) => {}
                Err(create_error) if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(create_error) => {
                    return Err(create_error).with_context(|| {
                        format!("create private child directory {}", display_path.display())
                    });
                }
            }
            // `AlreadyExists` is deliberately not a durability shortcut: it
            // can be the residue of a failed sync from an earlier attempt.
            sync_parent_directory(parent, display_path.parent().unwrap_or(display_path))
                .with_context(|| {
                    format!(
                        "sync parent after resolving private child directory {}",
                        display_path.display()
                    )
                })?;
            let child = open_private_child_dir_nofollow(parent, name).with_context(|| {
                format!(
                    "open private child directory without following links {}",
                    display_path.display()
                )
            })?;
            ensure_cap_directory_is_real(&child, "private child", display_path)?;
            Ok(child)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "open private child directory without following links {}",
                display_path.display()
            )
        }),
    }
}

/// Open a private directory child through cap-std's no-follow directory API.
///
/// On Windows this deliberately preserves cap-std's `FILE_SHARE_DELETE`
/// exclusion for every handle converted to [`Dir`]. Atomic publication needs
/// `DELETE` only on its staged regular-file handle; the retained parent
/// directory capability remains a namespace fence.
fn open_private_child_dir_nofollow(parent: &Dir, name: &OsStr) -> std::io::Result<Dir> {
    parent.open_dir_nofollow(name)
}

/// Read a direct regular-file child without following links and with a strict
/// byte ceiling. Returns `InvalidData` when the file is too large.
pub(crate) fn read_regular_file_bounded(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    read_regular_file_bounded_observed(parent, name, display_path, max_bytes, |_| Ok(()))
}

/// The same bounded no-follow read while reporting the exact number of bytes
/// consumed from the opened handle, including bytes read before an oversize or
/// I/O failure. Aggregate runtime budgets use this callback so rejected files
/// cannot make their read work disappear from accounting.
pub(crate) fn read_regular_file_bounded_observed(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    max_bytes: usize,
    observe: impl FnOnce(u64) -> Result<()>,
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
    read_bounded_observed(file, display_path, max_bytes, observe)
}

/// Same no-follow leaf open used by recursive copies. The caller streams from
/// the returned handle and therefore reads the exact object that was checked.
pub(crate) fn open_regular_file(parent: &Dir, name: &OsStr, display_path: &Path) -> Result<File> {
    open_bound_regular_file(parent, name, display_path).map(|(file, _binding)| file)
}

/// Open one real regular file and retain the identity of that exact handle.
///
/// The final namespace comparison closes the gap between opening the handle and
/// binding the direct-child name. Callers that keep both values can re-check the
/// name immediately before an effect without ever trusting an ambient path.
pub(crate) fn open_bound_regular_file(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, BoundChildObject)> {
    validate_child_name(name)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .access_mode(FILE_GENERIC_READ)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
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
    let binding = BoundChildObject {
        identity_token: child_identity_token(&metadata)?,
        _handle: Some(
            file.try_clone()
                .with_context(|| format!("retain file identity {}", display_path.display()))?,
        ),
    };
    if !binding.matches_regular_file_child_readonly(parent, name, display_path)? {
        anyhow::bail!(
            "regular file changed while its identity was being bound: {}",
            display_path.display()
        );
    }
    Ok((file, binding))
}

/// Open one real regular file through a retained directory capability for a
/// bounded, read-only operator review capture.
///
/// Every path component is expected to have been opened by
/// [`open_bound_directory`]; this leaf open never follows links. On Windows
/// its handle allows only other readers, preventing later writer/delete opens.
/// Existing writer handles can still influence bytes; Unix locks are likewise
/// advisory. Therefore the resulting bytes are always untrusted review data,
/// never authority for an install, activation, provider request, or write.
/// The caller's same-handle double-read and identity checks are detection
/// defenses, not an immutable-snapshot claim. Platforms without no-follow
/// opening fail closed rather than falling back to an ambient-path open.
pub(crate) fn open_bound_regular_file_snapshot(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, BoundChildObject)> {
    let file = open_regular_file_snapshot_handle(parent, name, display_path)?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspect document review snapshot {}",
            display_path.display()
        )
    })?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "document review snapshot is not a real regular file: {}",
            display_path.display()
        );
    }
    let binding = BoundChildObject {
        identity_token: child_identity_token(&metadata)?,
        _handle: Some(file.try_clone().with_context(|| {
            format!("retain document review snapshot {}", display_path.display())
        })?),
    };
    if !binding.matches_regular_file_snapshot(parent, name, display_path)? {
        anyhow::bail!(
            "document review snapshot changed while its identity was being bound: {}",
            display_path.display()
        );
    }
    Ok((file, binding))
}

fn open_regular_file_snapshot_handle(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<File> {
    validate_child_name(name)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
        };
        options
            .access_mode(FILE_GENERIC_READ)
            // Deny later write/delete opens while this review capture is held.
            // This does not retroactively constrain an already-open writer.
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name, display_path);
        anyhow::bail!("no no-follow document review capture primitive on this platform");
    }
    let file = parent
        .open_with(name, &options)
        .with_context(|| format!("open document review snapshot {}", display_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        // SAFETY: `file` owns a valid descriptor. This is deliberately
        // non-blocking so a concurrent cooperative writer is detected. This
        // lock is advisory and never upgrades untrusted review bytes into an
        // authority-bearing immutable snapshot.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "acquire shared document review snapshot lock {}",
                    display_path.display()
                )
            });
        }
    }
    Ok(file)
}

/// Open one regular file for reading and retain separate exact-object mutation
/// authority for its later removal.
///
/// The read handle is intentionally kept independent from the Windows
/// `DELETE`-capable binding. Comparing both kernel identities before return
/// prevents a namespace swap from pairing bytes from one file with deletion
/// authority over another.
#[cfg(test)]
pub(crate) fn open_bound_regular_file_for_removal(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, BoundChildObject)> {
    let (file, read_binding) = open_bound_regular_file(parent, name, display_path)?;
    let removal_binding = bind_regular_file_for_removal(parent, name, display_path, &read_binding)?;
    Ok((file, removal_binding))
}

/// Acquire exact-object removal authority for a regular file that is already
/// held through an identity-bound read handle.
///
/// Keeping this as a second phase lets callers finish non-destructive security
/// migration under a namespace-pinning handle before Windows `DELETE` access
/// exists. The identity comparison rejects a same-name replacement in the gap
/// instead of pairing old bytes with new removal authority.
pub(crate) fn bind_regular_file_for_removal(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    read_binding: &BoundChildObject,
) -> Result<BoundChildObject> {
    let removal_binding = bind_child_object(parent, name, display_path)?;
    anyhow::ensure!(
        removal_binding.identity_token() == read_binding.identity_token(),
        "regular file changed while its removal authority was being bound: {}",
        display_path.display()
    );
    Ok(removal_binding)
}

/// Bind exact-object removal authority to an already-open regular file.
///
/// Publication stages need to retain their original append-capable handle for
/// the eventual canonical writer while also owning a separate deletion handle
/// for fail-closed rollback. Comparing both kernel identities prevents cleanup
/// from targeting a same-name replacement introduced between creation and
/// binding.
pub(crate) fn bind_open_regular_file_for_removal(
    parent: &Dir,
    name: &OsStr,
    opened: &File,
    display_path: &Path,
) -> Result<BoundChildObject> {
    let opened_metadata = opened
        .metadata()
        .with_context(|| format!("inspect open regular file {}", display_path.display()))?;
    anyhow::ensure!(
        opened_metadata.is_file() && !cap_metadata_is_link_like(&opened_metadata),
        "open removal source is not a real regular file: {}",
        display_path.display()
    );
    let binding = bind_child_object(parent, name, display_path)?;
    anyhow::ensure!(
        child_identity_token(&opened_metadata)? == binding.identity_token(),
        "open regular file changed while its removal authority was being bound: {}",
        display_path.display()
    );
    Ok(binding)
}

/// Open and bind one regular file for a non-destructive durability operation.
///
/// This requests read/write data access but deliberately not Windows `DELETE`;
/// it is intended for `sync_all` on a copy destination, never namespace
/// mutation. The returned identity is derived from the same opened handle and
/// rechecked against the direct-child name before return.
pub(crate) fn open_bound_regular_file_readwrite(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, BoundChildObject)> {
    validate_child_name(name)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        options
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent.open_with(name, &options).with_context(|| {
        format!(
            "open regular file for non-destructive durability proof {}",
            display_path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspect regular file for non-destructive durability proof {}",
            display_path.display()
        )
    })?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "durability target is not a real regular file: {}",
            display_path.display()
        );
    }
    let binding = BoundChildObject {
        identity_token: child_identity_token(&metadata)?,
        _handle: Some(file.try_clone().with_context(|| {
            format!(
                "retain durability target identity {}",
                display_path.display()
            )
        })?),
    };
    if !binding.matches_regular_file_child_readonly(parent, name, display_path)? {
        anyhow::bail!(
            "regular file changed while its durability identity was being bound: {}",
            display_path.display()
        );
    }
    Ok((file, binding))
}

/// Open or create one direct private lockfile through an already-bound
/// directory. The returned OS file is suitable for a cross-process advisory
/// lock while `BoundChildObject` retains the no-follow child identity that a
/// caller must revalidate before every capability-relative publication.
///
/// This deliberately exposes no ambient path operation: both the create and
/// existing-file paths are direct-child capabilities and reject symlinks and
/// Windows reparse points.
pub(crate) fn open_or_create_bound_lockfile(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(std::fs::File, BoundChildObject)> {
    match parent.symlink_metadata(name) {
        Ok(metadata) => {
            if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "bound lockfile is not a real regular file: {}",
                    display_path.display()
                );
            }
            let (file, binding) = open_bound_lockfile_readwrite(parent, name, display_path)?;
            Ok((file.into_std(), binding))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Unlike the secret-file constructor, this empty lock leaf uses
            // the fully capability-relative atomic stage path on Windows too.
            // `display_path` remains error-only and is never opened.
            match atomic_write_private_child_create_new(parent, name, display_path, &[]) {
                Ok(()) => {}
                Err(error)
                    if error
                        .root_cause()
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) => {}
                Err(error) => return Err(error),
            }
            let (file, binding) = open_bound_lockfile_readwrite(parent, name, display_path)?;
            Ok((file.into_std(), binding))
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspect bound lockfile {}", display_path.display()))
        }
    }
}

/// Lock-specific no-follow open. On Windows it intentionally denies delete
/// sharing for the lifetime of the returned file lock, preventing a lock-leaf
/// rename/replacement from creating a second active namespace while a writer
/// holds this lease. Other durability reads keep their broader sharing policy.
fn open_bound_lockfile_readwrite(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, BoundChildObject)> {
    validate_child_name(name)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent.open_with(name, &options).with_context(|| {
        format!(
            "open bound lockfile without following links {}",
            display_path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect bound lockfile {}", display_path.display()))?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "bound lockfile is not a real regular file: {}",
            display_path.display()
        );
    }
    let binding = BoundChildObject {
        identity_token: child_identity_token(&metadata)?,
        _handle: Some(file.try_clone().with_context(|| {
            format!("retain bound lockfile identity {}", display_path.display())
        })?),
    };
    if !binding.matches_regular_file_child_readonly(parent, name, display_path)? {
        anyhow::bail!(
            "bound lockfile changed while its identity was being acquired: {}",
            display_path.display()
        );
    }
    Ok((file, binding))
}

/// Create the final private regular-file child directly and retain its exact
/// identity for a journaled secret write.
///
/// Unlike [`atomic_write_private_child_create_new`], this primitive never
/// places plaintext in a sibling stage file. On Windows an empty file is
/// created with its exact private DACL in the same directory and renamed
/// capability-relatively before this function returns; secret bytes are only
/// written through the returned handle after that rename. The final name may be
/// visible while bytes are written, so callers must first persist an Executing
/// journal, bind the returned identity into that journal before the first
/// secret byte, and treat every incomplete/mismatching result as indeterminate.
pub(crate) fn create_private_regular_file_child_create_new(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, BoundChildObject)> {
    validate_child_name(name)?;
    #[cfg(windows)]
    let file = {
        let stage_parent = display_path.parent().unwrap_or(display_path);
        let mut created = None;
        for _ in 0..8 {
            let stage_path = stage_parent.join(format!(
                ".neoth-private-empty-{}",
                uuid::Uuid::new_v4().simple()
            ));
            match crate::wal::win_native::create_private_shared_file_new(&stage_path) {
                Ok(file) => {
                    created = Some((File::from_std(file), stage_path));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "create atomically private empty destination stage for {}",
                            display_path.display()
                        )
                    });
                }
            }
        }
        let (file, stage_path) =
            created.context("could not allocate an atomically private empty destination stage")?;
        if let Err(error) = windows_rename_open_handle(&file, parent, name, false, display_path) {
            drop(file);
            return match std::fs::remove_file(&stage_path) {
                Ok(()) => Err(error),
                Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {
                    Err(error)
                }
                Err(cleanup_error) => Err(error.context(format!(
                    "cleanup of empty private destination stage also failed: {cleanup_error}"
                ))),
            };
        }
        file
    };
    #[cfg(not(windows))]
    let file = {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        parent.open_with(name, &options).with_context(|| {
            format!(
                "create final private regular-file child {}",
                display_path.display()
            )
        })?
    };
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        anyhow::ensure!(
            file.metadata()
                .context("inspect direct private destination mode")?
                .permissions()
                .mode()
                & 0o077
                == 0,
            "new private destination is accessible by group or other users"
        );
    }
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspect final private regular-file child {}",
            display_path.display()
        )
    })?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "new private destination is not a real regular file: {}",
            display_path.display()
        );
    }
    let binding = BoundChildObject {
        identity_token: child_identity_token(&metadata)?,
        _handle: Some(file.try_clone().with_context(|| {
            format!(
                "retain final private destination identity {}",
                display_path.display()
            )
        })?),
    };
    if !binding.matches_regular_file_child_readonly(parent, name, display_path)? {
        anyhow::bail!(
            "new private destination changed while its identity was being bound: {}",
            display_path.display()
        );
    }
    Ok((file, binding))
}

fn readonly_regular_file_identity(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<String> {
    validate_child_name(name)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .access_mode(FILE_GENERIC_READ)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent.open_with(name, &options).with_context(|| {
        format!(
            "open regular file for read-only identity check {}",
            display_path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspect regular file for read-only identity check {}",
            display_path.display()
        )
    })?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "expected a real regular file for read-only identity check: {}",
            display_path.display()
        );
    }
    child_identity_token(&metadata)
}

fn snapshot_regular_file_identity(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<String> {
    let file = open_regular_file_snapshot_handle(parent, name, display_path)?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspect document review snapshot identity {}",
            display_path.display()
        )
    })?;
    if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "expected a real regular file for document review snapshot: {}",
            display_path.display()
        );
    }
    child_identity_token(&metadata)
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
        // FILE_FLAG_OPEN_REPARSE_POINT binds a link/junction handle to the
        // namespace object itself. Renaming that handle is safe and is needed
        // for atomic leaf-removal tombstones; it never follows the target.
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

/// Publish an already-open regular-file stage and report the exact atomic
/// commit boundary to its owner.
///
/// `on_commit` runs exactly once after the kernel rename/handle-rename succeeds
/// and before any fallible post-commit target validation. It is never called on
/// a pre-commit error. This lets a caller transfer lock/quota ownership at the
/// only point where the new canonical object can begin consuming durable
/// resources, including when validation subsequently fails.
pub(crate) fn publish_open_regular_file_child_observed(
    source_parent: &Dir,
    source: &File,
    source_name: &OsStr,
    target_parent: &Dir,
    target_name: &OsStr,
    source_display: &Path,
    target_display: &Path,
    on_commit: impl FnOnce(),
) -> Result<()> {
    #[cfg(windows)]
    let _ = source_parent;
    validate_child_name(source_name)?;
    validate_child_name(target_name)?;
    let opened_metadata = source.metadata().with_context(|| {
        format!(
            "inspect open publication stage {}",
            source_display.display()
        )
    })?;
    anyhow::ensure!(
        opened_metadata.is_file() && !cap_metadata_is_link_like(&opened_metadata),
        "publication stage is not a real regular file: {}",
        source_display.display()
    );
    let opened_identity = child_identity_token(&opened_metadata)?;

    #[cfg(unix)]
    {
        let named_metadata = source_parent
            .symlink_metadata(source_name)
            .with_context(|| {
                format!(
                    "inspect named publication stage {}",
                    source_display.display()
                )
            })?;
        anyhow::ensure!(
            named_metadata.is_file()
                && !cap_metadata_is_link_like(&named_metadata)
                && opened_identity == child_identity_token(&named_metadata)?,
            "publication stage changed before commit: {}",
            source_display.display()
        );
        #[cfg(test)]
        run_before_open_file_rename_for_test();
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
                "exclusively publish capability-bound child {} as {}",
                source_display.display(),
                target_display.display()
            )
        })?;
        #[cfg(not(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox",
            windows
        )))]
        compile_error!(
            "exclusive WAL publication needs renameat2(RENAME_NOREPLACE) or \
             renamex_np(RENAME_EXCL); implement a linkat/unlinkat fallback before \
             enabling this Unix target."
        );
    }
    #[cfg(windows)]
    {
        windows_rename_open_handle(source, target_parent, target_name, false, target_display)?;
    }
    #[cfg(not(any(unix, windows)))]
    compile_error!(
        "observed regular-file publication requires an atomic Unix rename or Windows handle rename"
    );
    // Both supported platform branches reach this point only after their one
    // atomic namespace commit succeeded. Keep the callback before every
    // fallible post-commit lookup so callers cannot release ownership merely
    // because validation reports an error after the object became visible.
    on_commit();
    #[cfg(test)]
    inject_private_child_post_commit_validation_failure(target_display)?;
    let published_metadata = target_parent
        .symlink_metadata(target_name)
        .with_context(|| {
            format!(
                "inspect published regular file {}",
                target_display.display()
            )
        })?;
    anyhow::ensure!(
        published_metadata.is_file()
            && !cap_metadata_is_link_like(&published_metadata)
            && opened_identity == child_identity_token(&published_metadata)?,
        "published target is not the exact open stage object: {}",
        target_display.display()
    );
    Ok(())
}

fn named_regular_file_matches_open_object(
    parent: &Dir,
    name: &OsStr,
    opened: &File,
    display_path: &Path,
) -> Result<bool> {
    let opened_metadata = opened
        .metadata()
        .with_context(|| format!("inspect open file object {}", display_path.display()))?;
    let named_metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect named file object {}", display_path.display()));
        }
    };
    Ok(opened_metadata.is_file()
        && !cap_metadata_is_link_like(&opened_metadata)
        && named_metadata.is_file()
        && !cap_metadata_is_link_like(&named_metadata)
        && child_identity_token(&opened_metadata)? == child_identity_token(&named_metadata)?)
}

#[cfg(not(windows))]
fn remove_named_file_if_same_open_object(
    parent: &Dir,
    name: &OsStr,
    opened: &File,
    display_path: &Path,
) -> Result<()> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect cleanup candidate {}", display_path.display()));
        }
        Ok(_) => {}
    }
    if !named_regular_file_matches_open_object(parent, name, opened, display_path)? {
        anyhow::bail!(
            "refusing to clean up a file name that no longer identifies the open stage: {}",
            display_path.display()
        );
    }
    parent
        .remove_file(name)
        .with_context(|| format!("remove exact open stage {}", display_path.display()))
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
        #[cfg(test)]
        TEST_DELETE_WORK_BEFORE_FAILURE.with(|remaining| {
            if let Some(units) = remaining.get() {
                if units == 0 {
                    remaining.set(None);
                    return Err(anyhow::anyhow!(
                        "injected recursive Skill cleanup interruption at {}",
                        display_path.display()
                    ));
                }
                remaining.set(Some(units - 1));
            }
            Ok(())
        })?;
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
        let directory = open_real_child_dir(parent, name, display_path)?;
        let expected_identity = child_identity_token(
            &directory
                .dir_metadata()
                .with_context(|| format!("inspect removal target {}", display_path.display()))?,
        )?;
        remove_directory_contents(&directory, display_path, 0, budget)?;
        drop(directory);

        // `Dir` deliberately withholds delete sharing, so acquire native
        // DELETE authority only after the traversal capability closes. The
        // identity comparison below rejects a same-name replacement in that
        // hand-off window before the exact opened handle is marked deleted.
        let handle = open_windows_bound_real_directory_mutation_handle(
            parent,
            name,
            display_path,
            &expected_identity,
        )?;
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

/// Remove one optional direct-child file or link without following it.
///
/// Returns `true` only when this call removed an object. A real directory is
/// refused so cleanup code cannot recursively erase an unexpected generation.
pub(crate) fn remove_child_file_if_present(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<bool> {
    validate_child_name(name)?;
    #[cfg(unix)]
    {
        match parent.remove_file(name) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).with_context(|| {
                format!("remove capability-bound file {}", display_path.display())
            }),
        }
    }
    #[cfg(windows)]
    {
        match remove_child_file(parent, name, display_path) {
            Ok(()) => Ok(true),
            Err(error) if error_has_io_kind(&error, std::io::ErrorKind::NotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name);
        anyhow::bail!(
            "capability-bound leaf removal is unsupported on this platform: {}",
            display_path.display()
        );
    }
}

/// Remove one optional direct-child directory only when it is real and empty.
///
/// Unix first binds the opened object's device/inode identity, commits it to an
/// unpredictable private tombstone, and verifies that the rename moved exactly
/// that object before removal. Windows validates and deletes the exact no-follow
/// handle, avoiding cap-std's ambient `remove_dir` fallback. Links, junctions,
/// reparse points, files, and non-empty directories are refused.
pub(crate) fn remove_empty_real_child_dir_if_present(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<bool> {
    validate_child_name(name)?;
    #[cfg(unix)]
    {
        let Some(directory) = open_real_child_dir_if_present(parent, name, display_path)? else {
            return Ok(false);
        };
        ensure_directory_is_empty(&directory, display_path)?;
        let opened_identity =
            child_identity_token(&directory.dir_metadata().with_context(|| {
                format!("inspect opened directory {}", display_path.display())
            })?)?;
        let bound = bind_child_object(parent, name, display_path)?;
        anyhow::ensure!(
            bound.identity_token() == opened_identity,
            "empty-directory target changed while its handle was being bound: {}",
            display_path.display()
        );

        anyhow::ensure!(
            bound.matches_child(parent, name, display_path)?,
            "empty-directory target changed before its removal commit: {}",
            display_path.display()
        );
        #[cfg(test)]
        run_before_empty_directory_rename_for_test();

        let tombstone = std::ffi::OsString::from(format!(
            ".neoth-empty-delete-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let tombstone_display = display_path
            .parent()
            .unwrap_or(display_path)
            .join(&tombstone);
        rename_child(
            parent,
            name,
            parent,
            &tombstone,
            false,
            display_path,
            &tombstone_display,
        )
        .with_context(|| {
            format!(
                "commit exact-object empty-directory removal {}",
                display_path.display()
            )
        })?;
        anyhow::ensure!(
            bound.matches_child(parent, &tombstone, &tombstone_display)?,
            "empty-directory removal rename moved a different object; private tombstone retained: {}",
            tombstone_display.display()
        );
        ensure_directory_is_empty(&directory, &tombstone_display)?;
        anyhow::ensure!(
            bound.matches_child(parent, &tombstone, &tombstone_display)?,
            "empty-directory tombstone identity changed before unlink; retained: {}",
            tombstone_display.display()
        );
        match parent.remove_dir(&tombstone) {
            Ok(()) => Ok(true),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "remove exact-object empty-directory tombstone {}",
                    tombstone_display.display()
                )
            }),
        }
    }
    #[cfg(windows)]
    {
        let Some(directory) = open_real_child_dir_if_present(parent, name, display_path)? else {
            return Ok(false);
        };
        let expected_identity =
            child_identity_token(&directory.dir_metadata().with_context(|| {
                format!("inspect empty-directory target {}", display_path.display())
            })?)?;
        ensure_directory_is_empty(&directory, display_path)?;
        drop(directory);

        let handle = match open_windows_bound_real_directory_mutation_handle(
            parent,
            name,
            display_path,
            &expected_identity,
        ) {
            Ok(handle) => handle,
            Err(error) if error_has_io_kind(&error, std::io::ErrorKind::NotFound) => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        windows_mark_delete(&handle, display_path)?;
        Ok(true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name);
        anyhow::bail!(
            "capability-bound empty-directory removal is unsupported on this platform: {}",
            display_path.display()
        );
    }
}

fn ensure_directory_is_empty(directory: &Dir, display_path: &Path) -> Result<()> {
    let mut entries = directory
        .entries()
        .with_context(|| format!("enumerate directory {}", display_path.display()))?;
    match entries.next() {
        None => Ok(()),
        Some(Ok(_)) => anyhow::bail!(
            "refuse to remove non-empty capability-bound directory {}",
            display_path.display()
        ),
        Some(Err(error)) => Err(error)
            .with_context(|| format!("inspect directory entry {}", display_path.display())),
    }
}

#[cfg(windows)]
fn error_has_io_kind(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|source| source.kind() == kind)
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

/// Acquire exact-object directory deletion authority only after every
/// cap-std directory traversal handle for that object has closed. The caller
/// supplies the identity observed through the preceding no-follow traversal;
/// a same-name swap in the hand-off window fails before the raw native handle
/// can mark any directory for deletion.
#[cfg(windows)]
fn open_windows_bound_real_directory_mutation_handle(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    expected_identity: &str,
) -> Result<File> {
    let handle = open_windows_mutation_handle(parent, name, display_path)?;
    let metadata = handle
        .metadata()
        .with_context(|| format!("inspect bound removal target {}", display_path.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !cap_metadata_is_link_like(&metadata),
        "removal target must be a real directory: {}",
        display_path.display()
    );
    anyhow::ensure!(
        child_identity_token(&metadata)? == expected_identity,
        "directory changed before exact deletion authority was acquired: {}",
        display_path.display()
    );
    Ok(handle)
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
            let metadata = directory
                .symlink_metadata(&name)
                .with_context(|| format!("inspect removal child {}", child_display.display()))?;
            if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
                let child = open_real_child_dir(directory, &name, &child_display)?;
                let expected_identity =
                    child_identity_token(&child.dir_metadata().with_context(|| {
                        format!("inspect removal child {}", child_display.display())
                    })?)?;
                remove_directory_contents(&child, &child_display, depth + 1, budget)?;
                drop(child);
                budget.charge_work(&child_display)?;
                let handle = open_windows_bound_real_directory_mutation_handle(
                    directory,
                    &name,
                    &child_display,
                    &expected_identity,
                )?;
                windows_mark_delete(&handle, &child_display)?;
            } else {
                budget.charge_work(&child_display)?;
                #[cfg(test)]
                run_before_windows_recursive_leaf_delete_for_test();
                let handle = open_windows_mutation_handle(directory, &name, &child_display)?;
                let opened_metadata = handle.metadata().with_context(|| {
                    format!(
                        "inspect opened removal leaf before delete {}",
                        child_display.display()
                    )
                })?;
                anyhow::ensure!(
                    !opened_metadata.is_dir() || cap_metadata_is_link_like(&opened_metadata),
                    "removal leaf changed into a real directory before delete: {}",
                    child_display.display()
                );
                windows_mark_delete(&handle, &child_display)?;
            }
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

impl ConditionalReplacePreconditionFailed {
    pub(crate) fn at(display_path: impl Into<PathBuf>) -> Self {
        Self {
            display_path: display_path.into(),
        }
    }
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

/// Atomically publish private bytes as one direct regular-file child of an
/// already-bound directory. Creation, write, sync, rename and cleanup are all
/// capability-relative; a swapped ancestor cannot redirect the commit.
///
/// Compatibility wrapper: callers that do not need recovery metadata retain
/// the historical `Result<()>` contract. New state machines should use the
/// reported variant and treat either published outcome as revision-consuming.
pub(crate) fn atomic_write_private_child(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    atomic_write_private_child_legacy(parent, name, display_path, bytes, true)
}

/// Atomically create a new private direct-child file without replacing an
/// existing namespace entry.
///
/// This is the capability-relative commit primitive for replay tombstones and
/// operator-directed secret copies. The final rename is exclusive, so a
/// concurrent writer cannot be overwritten after the caller's absence check.
pub(crate) fn atomic_write_private_child_create_new(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    atomic_write_private_child_legacy(parent, name, display_path, bytes, false)
}

/// The only retry-safe failure from a reported private-child write.
///
/// Once the kernel rename succeeds, the reported API returns an `Ok` outcome
/// even if later identity validation or directory durability confirmation
/// fails. Callers must consume that revision rather than retrying it.
#[derive(Debug)]
pub(crate) struct PrivateChildPreCommitError {
    source: anyhow::Error,
}

impl std::fmt::Display for PrivateChildPreCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for PrivateChildPreCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl PrivateChildPreCommitError {
    pub(crate) fn root_cause(&self) -> &(dyn std::error::Error + 'static) {
        self.source.root_cause()
    }

    fn into_anyhow(self) -> anyhow::Error {
        self.source
    }
}

/// A committed private child write. `PublishedDurabilityUnknown` means the
/// atomic namespace change already happened; retrying would be unsafe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub(crate) enum PrivateChildCommit {
    PublishedAndSynced,
    PublishedDurabilityUnknown(PrivateChildDurabilityUnknown),
}

/// Why a published child cannot be reported power-loss durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateChildDurabilityUnknown {
    ParentSyncUnsupported,
    ParentSyncFailed,
    PostCommitValidationFailed,
}

impl std::fmt::Display for PrivateChildDurabilityUnknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ParentSyncUnsupported => "parent directory sync is unsupported",
            Self::ParentSyncFailed => "parent directory sync failed",
            Self::PostCommitValidationFailed => "post-commit validation failed",
        })
    }
}

impl std::error::Error for PrivateChildDurabilityUnknown {}

/// Atomic replacement with an exact pre-/post-publication outcome boundary.
pub(crate) fn atomic_write_private_child_reported(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> std::result::Result<PrivateChildCommit, PrivateChildPreCommitError> {
    atomic_write_private_child_reported_core(parent, name, display_path, bytes, true)
        .map(PrivateChildReportedCommit::into_commit)
        .map_err(|source| PrivateChildPreCommitError { source })
}

/// Exclusive atomic creation with the same recovery outcome as replacement.
pub(crate) fn atomic_write_private_child_create_new_reported(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> std::result::Result<PrivateChildCommit, PrivateChildPreCommitError> {
    atomic_write_private_child_reported_core(parent, name, display_path, bytes, false)
        .map(PrivateChildReportedCommit::into_commit)
        .map_err(|source| PrivateChildPreCommitError { source })
}

/// Internal carrier keeps the historical post-commit diagnostic available to
/// the source-compatible `Result<()>` wrappers without exposing it as a
/// retry-safe error to new callers.
struct PrivateChildReportedCommit {
    commit: PrivateChildCommit,
    legacy_post_commit_error: Option<anyhow::Error>,
}

impl PrivateChildReportedCommit {
    fn into_commit(self) -> PrivateChildCommit {
        self.commit
    }
}

fn atomic_write_private_child_legacy(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
    replace_existing: bool,
) -> Result<()> {
    let report = atomic_write_private_child_reported_core(
        parent,
        name,
        display_path,
        bytes,
        replace_existing,
    )
    .map_err(|source| PrivateChildPreCommitError { source }.into_anyhow())?;
    match report.legacy_post_commit_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn atomic_write_private_child_reported_core(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
    bytes: &[u8],
    replace_existing: bool,
) -> Result<PrivateChildReportedCommit> {
    validate_child_name(name)?;
    match parent.symlink_metadata(name) {
        Ok(_metadata) if !replace_existing => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "private atomic-write target already exists: {}",
                    display_path.display()
                ),
            )
            .into());
        }
        Ok(metadata) => {
            if cap_metadata_is_link_like(&metadata) || !metadata.is_file() {
                anyhow::bail!(
                    "private atomic-write target is not a real regular file: {}",
                    display_path.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect capability-bound atomic-write target {}",
                    display_path.display()
                )
            });
        }
    }

    let mut stage_name = None;
    let mut stage = None;
    for _ in 0..8 {
        let candidate =
            std::ffi::OsString::from(format!(".neoth-atomic-{}", uuid::Uuid::new_v4().simple()));
        #[cfg(windows)]
        let opened = windows_private_atomic_stage::Stage::create_private(
            parent,
            &candidate,
            display_path,
        );
        #[cfg(not(windows))]
        let opened = {
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
            parent.open_with(&candidate, &options)
        };
        match opened {
            Ok(file) => {
                stage_name = Some(candidate);
                stage = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "create capability-bound atomic stage for {}",
                        display_path.display()
                    )
                });
            }
        }
    }
    let stage_name = stage_name.context("could not allocate a private atomic stage file")?;
    let mut stage = stage.context("private atomic stage handle is unexpectedly absent")?;
    let mut committed = false;
    let result = (|| -> Result<PrivateChildReportedCommit> {
        stage.write_all(bytes).with_context(|| {
            format!("write private atomic stage for {}", display_path.display())
        })?;
        #[cfg(windows)]
        let synced_stage = stage
            .sync_all()
            .with_context(|| format!("sync private atomic stage for {}", display_path.display()))?;
        #[cfg(not(windows))]
        stage
            .sync_all()
            .with_context(|| format!("sync private atomic stage for {}", display_path.display()))?;
        #[cfg(windows)]
        let durability = windows_private_atomic_stage::durability_after_rename(
            synced_stage.rename_observed(
                parent,
                name,
                display_path,
                replace_existing,
                || committed = true,
            )?,
        );
        #[cfg(not(windows))]
        let durability = {
            replace_staged_file_observed(
                parent,
                &stage,
                &stage_name,
                name,
                display_path,
                replace_existing,
                || committed = true,
            )?;
            sync_parent_directory(parent, display_path.parent().unwrap_or(display_path))
        };
        match durability {
            Ok(DirectorySyncOutcome::Confirmed) => Ok(PrivateChildReportedCommit {
                commit: PrivateChildCommit::PublishedAndSynced,
                legacy_post_commit_error: None,
            }),
            Ok(DirectorySyncOutcome::Unsupported) => Ok(PrivateChildReportedCommit {
                commit: PrivateChildCommit::PublishedDurabilityUnknown(
                    PrivateChildDurabilityUnknown::ParentSyncUnsupported,
                ),
                legacy_post_commit_error: None,
            }),
            Err(error) => Ok(PrivateChildReportedCommit {
                commit: PrivateChildCommit::PublishedDurabilityUnknown(
                    PrivateChildDurabilityUnknown::ParentSyncFailed,
                ),
                legacy_post_commit_error: Some(error),
            }),
        }
    })();

    match result {
        Ok(commit) => {
            drop(stage);
            Ok(commit)
        }
        Err(error) if committed => {
            drop(stage);
            Ok(PrivateChildReportedCommit {
                commit: PrivateChildCommit::PublishedDurabilityUnknown(
                    PrivateChildDurabilityUnknown::PostCommitValidationFailed,
                ),
                legacy_post_commit_error: Some(error),
            })
        }
        Err(error) => {
            let stage_display = display_path
                .parent()
                .unwrap_or(display_path)
                .join(&stage_name);
            #[cfg(windows)]
            let cleanup = stage.cleanup(&stage_display);
            #[cfg(not(windows))]
            let cleanup = remove_named_file_if_same_open_object(
                parent,
                &stage_name,
                &stage,
                &stage_display,
            );
            drop(stage);
            match cleanup {
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
                    "cleanup of capability-bound atomic stage `{}` also failed: {cleanup_error}",
                    stage_name.to_string_lossy()
                ))),
            }
        }
    }
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
        #[cfg(windows)]
        let opened = windows_private_atomic_stage::Stage::create_replacement(
            parent,
            &candidate,
            display_path,
        );
        #[cfg(not(windows))]
        let opened = {
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
            parent.open_with(&candidate, &options)
        };
        match opened {
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
        #[cfg(windows)]
        let synced_stage = stage
            .sync_all()
            .with_context(|| format!("sync replacement for {}", display_path.display()))?;
        #[cfg(not(windows))]
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
        #[cfg(windows)]
        let durability = windows_private_atomic_stage::durability_after_rename(
            synced_stage.rename_observed(parent, name, display_path, true, || committed = true)?,
        );
        #[cfg(not(windows))]
        let durability = {
            replace_staged_file(parent, &stage, &stage_name, name, display_path, true)?;
            committed = true;
            sync_parent_directory(parent, display_path.parent().unwrap_or(display_path))
        };
        if matches!(durability, Ok(DirectorySyncOutcome::Unsupported)) {
            warnings.push(
                "replacement is committed, but parent-directory durability is unsupported"
                    .to_string(),
            );
        }
        if let Err(error) = durability {
            warnings.push(format!(
                "replacement is committed, but parent-directory durability could not be confirmed: {error:#}"
            ));
        }
        Ok(())
    })();
    if let Err(error) = replace_result {
        if committed {
            drop(stage);
            return Err(error);
        }
        let stage_display = display_path
            .parent()
            .unwrap_or(display_path)
            .join(&stage_name);
        #[cfg(windows)]
        let cleanup = stage.cleanup(&stage_display);
        #[cfg(not(windows))]
        let cleanup = remove_named_file_if_same_open_object(
            parent,
            &stage_name,
            &stage,
            &stage_display,
        );
        drop(stage);
        return match cleanup {
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
    drop(stage);
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
    stage: &File,
    stage_name: &OsStr,
    target_name: &OsStr,
    display_path: &Path,
    replace_existing: bool,
) -> Result<()> {
    replace_staged_file_observed(
        parent,
        stage,
        stage_name,
        target_name,
        display_path,
        replace_existing,
        || {},
    )
}

#[cfg(unix)]
fn replace_staged_file_observed(
    parent: &Dir,
    stage: &File,
    stage_name: &OsStr,
    target_name: &OsStr,
    display_path: &Path,
    replace_existing: bool,
    on_commit: impl FnOnce(),
) -> Result<()> {
    if replace_existing {
        anyhow::ensure!(
            named_regular_file_matches_open_object(parent, stage_name, stage, display_path)?,
            "replacement stage changed before commit: {}",
            display_path.display()
        );
        #[cfg(test)]
        run_before_open_file_rename_for_test();
        parent
            .rename(stage_name, parent, target_name)
            .with_context(|| format!("atomically replace {}", display_path.display()))?;
        on_commit();
        #[cfg(test)]
        inject_private_child_post_commit_validation_failure(display_path)?;
        anyhow::ensure!(
            named_regular_file_matches_open_object(parent, target_name, stage, display_path)?,
            "replacement target is not the exact open stage object: {}",
            display_path.display()
        );
        Ok(())
    } else {
        let stage_display = display_path
            .parent()
            .unwrap_or(display_path)
            .join(stage_name);
        publish_open_regular_file_child_observed(
            parent,
            stage,
            stage_name,
            parent,
            target_name,
            &stage_display,
            display_path,
            on_commit,
        )
        .with_context(|| format!("atomically create {}", display_path.display()))
    }
}

/// Owns the proof required to claim a durable Windows private-stage commit.
/// Keeping the stage and commit witness fields private prevents an arbitrary
/// `File` or a successful ambient-path rename from manufacturing `Confirmed`.
#[cfg(windows)]
mod windows_private_atomic_stage {
    use super::*;
    use std::marker::PhantomData;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum VolumeQualification {
        QualifiedLocalNtfs,
        Unsupported,
    }

    pub(super) struct Stage {
        file: File,
        volume: VolumeQualification,
    }

    pub(super) struct SyncedStage<'stage> {
        stage: &'stage Stage,
        _private: (),
    }

    pub(super) enum RenameCommit<'stage> {
        Qualified(QualifiedLocalNtfsRenameCommit<'stage>),
        Unsupported,
    }

    pub(super) struct QualifiedLocalNtfsRenameCommit<'stage> {
        _exact_stage: PhantomData<&'stage Stage>,
        _private: (),
    }

    impl Stage {
        pub(super) fn create_private(
            parent: &Dir,
            name: &OsStr,
            display_path: &Path,
        ) -> std::io::Result<Self> {
            Self::create(parent, name, display_path, true)
        }

        pub(super) fn create_replacement(
            parent: &Dir,
            name: &OsStr,
            display_path: &Path,
        ) -> std::io::Result<Self> {
            Self::create(parent, name, display_path, false)
        }

        fn create(
            parent: &Dir,
            name: &OsStr,
            display_path: &Path,
            protect_private_dacl: bool,
        ) -> std::io::Result<Self> {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
            };

            let mut options = OpenOptions::new();
            let access = if protect_private_dacl {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC
            } else {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE
            };
            options
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No)
                .access_mode(access)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_WRITE_THROUGH);
            let file = parent.open_with(name, &options)?;
            if protect_private_dacl {
                if let Err(error) = protect_private_dacl(&file) {
                    let stage_display = display_path
                        .parent()
                        .unwrap_or(display_path)
                        .join(name);
                    let cleanup = super::windows_mark_delete(&file, &stage_display);
                    return Err(std::io::Error::other(match cleanup {
                        Ok(()) => format!(
                            "protect capability-bound atomic stage for {}: {error:#}",
                            display_path.display()
                        ),
                        Err(cleanup_error) => format!(
                            "protect capability-bound atomic stage for {}: {error:#}; capability-relative cleanup of exact stage also failed: {cleanup_error:#}",
                            display_path.display()
                        ),
                    }));
                }
            }
            let volume = qualify_exact_handle(&file);
            Ok(Self { file, volume })
        }

        pub(super) fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.file.write_all(bytes)
        }

        pub(super) fn sync_all(&self) -> std::io::Result<SyncedStage<'_>> {
            self.file.sync_all()?;
            Ok(SyncedStage {
                stage: self,
                _private: (),
            })
        }

        pub(super) fn set_permissions(
            &mut self,
            permissions: cap_std::fs::Permissions,
        ) -> std::io::Result<()> {
            self.file.set_permissions(permissions)
        }

        pub(super) fn cleanup(&self, stage_display: &Path) -> Result<()> {
            #[cfg(test)]
            run_before_cleanup_for_test();
            super::windows_mark_delete(&self.file, stage_display)
        }
    }

    impl<'stage> SyncedStage<'stage> {
        pub(super) fn rename_observed(
            self,
            parent: &Dir,
            target_name: &OsStr,
            display_path: &Path,
            replace_existing: bool,
            on_commit: impl FnOnce(),
        ) -> Result<RenameCommit<'stage>> {
            #[cfg(test)]
            run_before_rename_for_test();
            super::windows_rename_open_handle(
                &self.stage.file,
                parent,
                target_name,
                replace_existing,
                display_path,
            )?;
            on_commit();
            #[cfg(test)]
            run_after_rename_for_test();
            #[cfg(test)]
            super::inject_private_child_post_commit_validation_failure(display_path)?;
            anyhow::ensure!(
                super::named_regular_file_matches_open_object(
                    parent,
                    target_name,
                    &self.stage.file,
                    display_path,
                )?,
                "committed private atomic target is not the exact open stage object: {}",
                display_path.display()
            );
            Ok(match self.stage.volume {
                VolumeQualification::QualifiedLocalNtfs => {
                    RenameCommit::Qualified(QualifiedLocalNtfsRenameCommit {
                        _exact_stage: PhantomData,
                        _private: (),
                    })
                }
                VolumeQualification::Unsupported => RenameCommit::Unsupported,
            })
        }

    }

    pub(super) fn durability_after_rename(
        commit: RenameCommit<'_>,
    ) -> Result<DirectorySyncOutcome> {
        Ok(match commit {
            RenameCommit::Qualified(witness) => {
                let QualifiedLocalNtfsRenameCommit {
                    _exact_stage: _,
                    _private: (),
                } = witness;
                DirectorySyncOutcome::Confirmed
            }
            RenameCommit::Unsupported => DirectorySyncOutcome::Unsupported,
        })
    }

    fn qualify_exact_handle(file: &File) -> VolumeQualification {
        #[cfg(test)]
        if let Some(qualification) = test_volume_qualification() {
            return qualification;
        }
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, VOLUME_NAME_NT,
        };

        let handle = file.as_raw_handle() as HANDLE;
        let mut filesystem = [0u16; 32];
        // SAFETY: `handle` is the live stage handle and every optional output
        // pointer is null. The filesystem buffer is valid for its stated size.
        let volume_ok = unsafe {
            GetVolumeInformationByHandleW(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        };
        if volume_ok == 0 {
            return VolumeQualification::Unsupported;
        }
        let fs_len = filesystem
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(filesystem.len());
        let filesystem = String::from_utf16_lossy(&filesystem[..fs_len]);

        let mut native_path = vec![0u16; 32_768];
        // SAFETY: the same live stage handle is queried and the writable UTF-16
        // buffer remains valid for the duration of the call.
        let path_len = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                native_path.as_mut_ptr(),
                native_path.len() as u32,
                VOLUME_NAME_NT,
            )
        } as usize;
        if path_len == 0 || path_len >= native_path.len() {
            return VolumeQualification::Unsupported;
        }
        let native_path = String::from_utf16_lossy(&native_path[..path_len]);
        classify_volume(&filesystem, &native_path)
    }

    fn classify_volume(filesystem: &str, native_path: &str) -> VolumeQualification {
        let native_path = native_path.to_ascii_lowercase();
        let suffix = native_path.strip_prefix(r"\device\harddiskvolume");
        let qualified_device = suffix.is_some_and(|suffix| {
            let digit_count = suffix.bytes().take_while(u8::is_ascii_digit).count();
            digit_count > 0 && suffix.as_bytes().get(digit_count) == Some(&b'\\')
        });
        if filesystem.eq_ignore_ascii_case("NTFS") && qualified_device {
            VolumeQualification::QualifiedLocalNtfs
        } else {
            VolumeQualification::Unsupported
        }
    }

    fn protect_private_dacl(file: &File) -> Result<()> {
        #[cfg(test)]
        if TEST_FORCE_DACL_FAILURE.with(std::cell::Cell::get) {
            anyhow::bail!("injected private-stage DACL failure");
        }
        crate::wal::win_native::set_private_current_user_file_handle_dacl(file)
            .map_err(anyhow::Error::from)
    }

    #[cfg(test)]
    thread_local! {
        static TEST_VOLUME_QUALIFICATION: std::cell::Cell<Option<VolumeQualification>> =
            const { std::cell::Cell::new(None) };
        static TEST_BEFORE_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        static TEST_AFTER_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        static TEST_BEFORE_CLEANUP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
        static TEST_FORCE_DACL_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[cfg(test)]
    fn test_volume_qualification() -> Option<VolumeQualification> {
        TEST_VOLUME_QUALIFICATION.with(std::cell::Cell::get)
    }

    #[cfg(test)]
    pub(super) struct TestScope {
        previous_volume: Option<VolumeQualification>,
    }

    #[cfg(test)]
    impl Drop for TestScope {
        fn drop(&mut self) {
            TEST_VOLUME_QUALIFICATION.with(|slot| slot.set(self.previous_volume));
            TEST_BEFORE_RENAME.with(|slot| slot.borrow_mut().take());
            TEST_AFTER_RENAME.with(|slot| slot.borrow_mut().take());
            TEST_BEFORE_CLEANUP.with(|slot| slot.borrow_mut().take());
        }
    }

    #[cfg(test)]
    pub(super) fn qualified_local_ntfs_for_test() -> TestScope {
        let previous_volume = TEST_VOLUME_QUALIFICATION
            .with(|slot| slot.replace(Some(VolumeQualification::QualifiedLocalNtfs)));
        TestScope { previous_volume }
    }

    #[cfg(test)]
    pub(super) fn unsupported_volume_for_test() -> TestScope {
        let previous_volume = TEST_VOLUME_QUALIFICATION
            .with(|slot| slot.replace(Some(VolumeQualification::Unsupported)));
        TestScope { previous_volume }
    }

    #[cfg(test)]
    pub(super) fn set_before_rename_for_test(hook: impl FnOnce() + 'static) {
        TEST_BEFORE_RENAME.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    pub(super) fn set_after_rename_for_test(hook: impl FnOnce() + 'static) {
        TEST_AFTER_RENAME.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    pub(super) fn set_before_cleanup_for_test(hook: impl FnOnce() + 'static) {
        TEST_BEFORE_CLEANUP.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(test)]
    struct DaclFailureScope;

    #[cfg(test)]
    impl Drop for DaclFailureScope {
        fn drop(&mut self) {
            TEST_FORCE_DACL_FAILURE.with(|slot| slot.set(false));
        }
    }

    #[cfg(test)]
    fn fail_dacl_for_test() -> DaclFailureScope {
        TEST_FORCE_DACL_FAILURE.with(|slot| slot.set(true));
        DaclFailureScope
    }

    #[cfg(test)]
    fn run_before_rename_for_test() {
        TEST_BEFORE_RENAME.with(|slot| {
            if let Some(hook) = slot.borrow_mut().take() {
                hook();
            }
        });
    }

    #[cfg(test)]
    fn run_after_rename_for_test() {
        TEST_AFTER_RENAME.with(|slot| {
            if let Some(hook) = slot.borrow_mut().take() {
                hook();
            }
        });
    }

    #[cfg(test)]
    fn run_before_cleanup_for_test() {
        TEST_BEFORE_CLEANUP.with(|slot| {
            if let Some(hook) = slot.borrow_mut().take() {
                hook();
            }
        });
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn only_local_ntfs_native_device_paths_are_qualified() {
            assert_eq!(
                classify_volume("NTFS", r"\Device\HarddiskVolume4\private.stage"),
                VolumeQualification::QualifiedLocalNtfs
            );
            for (filesystem, path) in [
                ("ReFS", r"\Device\HarddiskVolume4\private.stage"),
                ("FAT32", r"\Device\HarddiskVolume4\private.stage"),
                ("NTFS", r"\Device\Mup\server\share\private.stage"),
                ("NTFS", r"\Device\CustomRedirector\private.stage"),
                ("NTFS", r"\Device\HarddiskVolume\private.stage"),
                ("NTFS", r"\Device\HarddiskVolumeRedirector\private.stage"),
                ("NTFS", r"\Device\HarddiskVolumeShadow7\private.stage"),
                ("NTFS", r"\Device\HarddiskVolume7Shadow\private.stage"),
                ("NTFS", r"\Device\HarddiskVolume7"),
                ("", ""),
            ] {
                assert_eq!(
                    classify_volume(filesystem, path),
                    VolumeQualification::Unsupported,
                    "{filesystem} at {path} must remain fail-closed"
                );
            }
        }

        #[test]
        fn failed_dacl_hardening_cleans_up_the_exact_created_stage() {
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("state.json");
            let root = super::super::open_bound_directory(temp.path(), false, "test store")
                .unwrap()
                .unwrap();
            let candidate = OsStr::new(".neoth-atomic-dacl-failure");
            let _failure = fail_dacl_for_test();

            Stage::create_private(&root.dir, candidate, &target)
                .err()
                .expect("injected DACL failure must abort stage creation");

            assert!(!temp.path().join(".neoth-atomic-dacl-failure").exists());
        }
    }
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

/// Result of attempting to make a parent-directory namespace change durable.
///
/// Windows does not expose a supported equivalent of syncing an opened
/// directory handle, so generic directory mutations must preserve the
/// distinction instead of treating a successful no-op as confirmation. The
/// private Windows stage module can confirm only a same-handle write-through
/// rename whose exact handle was also qualified as residing on local NTFS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectorySyncOutcome {
    /// The platform accepted a real directory sync operation.
    #[cfg_attr(windows, allow(dead_code))]
    Confirmed,
    /// The platform cannot confirm parent-directory power-loss durability.
    #[cfg_attr(unix, allow(dead_code))]
    Unsupported,
}

/// Attempt to sync an already capability-bound parent directory.
pub(crate) fn sync_parent_directory(
    parent: &Dir,
    display_path: &Path,
) -> Result<DirectorySyncOutcome> {
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
        Ok(DirectorySyncOutcome::Confirmed)
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, display_path);
        Ok(DirectorySyncOutcome::Unsupported)
    }
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
        windows_file_attributes_are_link_like(metadata.file_attributes())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn windows_file_attributes_are_link_like(attributes: u32) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn read_bounded_observed(
    file: File,
    display_path: &Path,
    max_bytes: usize,
    observe: impl FnOnce(u64) -> Result<()>,
) -> Result<Vec<u8>> {
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    let read = file.take(limit).read_to_end(&mut bytes);
    observe(bytes.len() as u64)?;
    read.with_context(|| format!("read {}", display_path.display()))?;
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

    #[cfg(windows)]
    #[test]
    fn cap_std_directory_capability_fences_rename_delete_and_revalidates_identity() {
        let temp = tempdir().unwrap();
        let child_path = temp.path().join("stage");
        std::fs::create_dir(&child_path).unwrap();
        std::fs::write(child_path.join("skill.yaml"), b"id: stage").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let (child, bound) = open_bound_real_child_dir(&root.dir, OsStr::new("stage"), &child_path)
            .expect("cap-std directory capability and no-follow identity must bind together");

        assert!(child.entries().unwrap().next().is_some());
        assert!(
            bound
                .matches_directory_child(&root.dir, OsStr::new("stage"), &child_path)
                .unwrap()
        );

        let renamed = temp.path().join("stage-renamed");
        assert!(
            std::fs::rename(&child_path, &renamed).is_err(),
            "a retained cap-std directory capability must withhold delete sharing"
        );
        assert!(
            std::fs::remove_dir(&child_path).is_err(),
            "a retained cap-std directory capability must fence deletion"
        );
        drop(child);
        std::fs::rename(&child_path, &renamed)
            .expect("rename succeeds after the cap-std directory capability closes");
    }

    #[cfg(windows)]
    #[test]
    fn private_child_dacl_hardening_preserves_cap_std_atomic_publication() {
        let temp = tempdir().unwrap();
        let private_root = temp.path().join("private-root");
        crate::wal::win_native::create_private_directory_new(&private_root)
            .expect("create TokenUser-private test root");
        let child_path = private_root.join("private-state");
        let root = open_bound_directory(&private_root, false, "test store")
            .unwrap()
            .unwrap();
        let child =
            open_or_create_private_child_dir(&root.dir, OsStr::new("private-state"), &child_path)
                .expect("open private child with a DACL-migration-compatible capability");

        crate::wal::win_native::set_private_current_user_directory_dacl_bound(&child_path, &child)
            .expect("bound DACL hardening must preserve the cap-std directory capability");
        crate::wal::win_native::verify_private_directory_handle_dacl(&child)
            .expect("private child capability must retain the hardened DACL");

        let target = child_path.join("state.json");
        atomic_write_private_child(&child, OsStr::new("state.json"), &target, b"private state")
            .expect("hardened private child must support capability-relative atomic publication");
        assert_eq!(std::fs::read(&target).unwrap(), b"private state");
    }

    #[cfg(windows)]
    #[test]
    fn held_bound_lock_leaf_rejects_atomic_replacement() {
        let temp = tempdir().unwrap();
        let lock_path = temp.path().join("state-v1.lock");
        let root = open_bound_directory(temp.path(), false, "test SafeStore")
            .unwrap()
            .unwrap();
        let (_lock, _binding) =
            open_or_create_bound_lockfile(&root.dir, OsStr::new("state-v1.lock"), &lock_path)
                .expect("open and retain the SafeStore lock leaf");

        let error = atomic_write_private_child(
            &root.dir,
            OsStr::new("state-v1.lock"),
            &lock_path,
            b"replacement",
        )
        .expect_err("an open lock leaf must deny atomic replacement on Windows");

        assert!(
            format!("{error:#}").contains("Win32 error 0x00000020"),
            "expected ERROR_SHARING_VIOLATION, got {error:#}"
        );
        assert_eq!(std::fs::read(&lock_path).unwrap(), b"");
    }

    #[test]
    fn bound_regular_file_removal_deletes_the_exact_opened_file() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("claim.json");
        std::fs::write(&target, b"authenticated claim").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let (file, binding) =
            open_bound_regular_file_for_removal(&root.dir, OsStr::new("claim.json"), &target)
                .unwrap();
        binding
            .remove_bound_file(&root.dir, OsStr::new("claim.json"), &target)
            .unwrap();
        drop(file);

        assert!(!target.exists());
    }

    #[test]
    fn bound_regular_file_removal_never_deletes_a_same_name_replacement() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("claim.json");
        let displaced = temp.path().join("displaced-claim.json");
        std::fs::write(&target, b"authenticated claim").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let (file, binding) =
            open_bound_regular_file_for_removal(&root.dir, OsStr::new("claim.json"), &target)
                .unwrap();
        std::fs::rename(&target, &displaced).unwrap();
        std::fs::write(&target, b"same-name replacement sentinel").unwrap();

        let removal = binding.remove_bound_file(&root.dir, OsStr::new("claim.json"), &target);
        drop(file);

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"same-name replacement sentinel"
        );
        match removal {
            Ok(()) => assert!(
                !displaced.exists(),
                "successful removal must delete only the exact retained object"
            ),
            Err(_) => assert_eq!(
                std::fs::read(&displaced).unwrap(),
                b"authenticated claim",
                "fail-closed removal must retain the original object"
            ),
        }
    }

    #[cfg(unix)]
    #[test]
    fn bound_regular_file_removal_preserves_a_post_validation_replacement() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("claim.json");
        let displaced = temp.path().join("displaced-claim.json");
        std::fs::write(&target, b"authenticated claim").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        let (file, binding) =
            open_bound_regular_file_for_removal(&root.dir, OsStr::new("claim.json"), &target)
                .unwrap();

        let hook_target = target.clone();
        let hook_displaced = displaced.clone();
        set_after_bound_file_revalidation_for_test(move || {
            std::fs::rename(&hook_target, &hook_displaced).unwrap();
            std::fs::write(&hook_target, b"same-name replacement sentinel").unwrap();
        });
        let error = binding
            .remove_bound_file(&root.dir, OsStr::new("claim.json"), &target)
            .expect_err("a replacement introduced after validation must fail closed");
        drop(file);

        assert!(
            format!("{error:#}").contains("race moved a replacement"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"same-name replacement sentinel"
        );
        assert_eq!(std::fs::read(&displaced).unwrap(), b"authenticated claim");
        assert_eq!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-bound-delete-"))
                .count(),
            0
        );
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
    fn atomic_private_child_write_creates_and_replaces_through_bound_parent() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("pending.json");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        atomic_write_private_child(&root.dir, OsStr::new("pending.json"), &target, b"first")
            .unwrap();
        atomic_write_private_child(&root.dir, OsStr::new("pending.json"), &target, b"second")
            .unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"second");
        assert_eq!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-atomic-"))
                .count(),
            0
        );
    }

    #[cfg(unix)]
    fn swap_open_atomic_stage_name(directory: &Path, displaced_name: &str, replacement: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        let stage = std::fs::read_dir(directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-atomic-")
            })
            .expect("atomic stage must exist before commit")
            .path();
        std::fs::rename(&stage, directory.join(displaced_name)).unwrap();
        std::fs::write(&stage, replacement).unwrap();
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn open_file_publication_observer_runs_once_after_atomic_commit() {
        let temp = tempdir().unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        let stage_name = OsStr::new("stage.tmp");
        let target_name = OsStr::new("published.wal");
        let stage_display = temp.path().join(stage_name);
        let target_display = temp.path().join(target_name);
        let (mut stage, _binding) =
            create_private_regular_file_child_create_new(&root.dir, stage_name, &stage_display)
                .unwrap();
        use std::io::Write as _;
        stage.write_all(b"complete authenticated prefix").unwrap();
        stage.sync_all().unwrap();
        let mut commits = 0usize;

        publish_open_regular_file_child_observed(
            &root.dir,
            &stage,
            stage_name,
            &root.dir,
            target_name,
            &stage_display,
            &target_display,
            || {
                commits += 1;
                assert!(
                    !stage_display.exists(),
                    "commit observer must run after the source name is gone"
                );
                assert_eq!(
                    std::fs::read(&target_display).unwrap(),
                    b"complete authenticated prefix",
                    "commit observer must see the complete canonical object"
                );
            },
        )
        .unwrap();

        assert_eq!(commits, 1, "one rename must produce exactly one callback");
    }

    #[test]
    fn open_file_publication_observer_never_runs_before_commit() {
        let temp = tempdir().unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        let stage_name = OsStr::new("stage.tmp");
        let target_name = OsStr::new("published.wal");
        let stage_display = temp.path().join(stage_name);
        let target_display = temp.path().join(target_name);
        std::fs::write(&target_display, b"pre-existing target").unwrap();
        let (mut stage, _binding) =
            create_private_regular_file_child_create_new(&root.dir, stage_name, &stage_display)
                .unwrap();
        use std::io::Write as _;
        stage.write_all(b"uncommitted prefix").unwrap();
        stage.sync_all().unwrap();
        let mut commits = 0usize;

        publish_open_regular_file_child_observed(
            &root.dir,
            &stage,
            stage_name,
            &root.dir,
            target_name,
            &stage_display,
            &target_display,
            || commits += 1,
        )
        .expect_err("exclusive publication must refuse an existing target");

        assert_eq!(commits, 0, "a failed rename must not claim publication");
        assert_eq!(
            std::fs::read(&target_display).unwrap(),
            b"pre-existing target"
        );
        assert_eq!(
            std::fs::read(&stage_display).unwrap(),
            b"uncommitted prefix"
        );
    }

    #[test]
    fn open_file_publication_observer_precedes_post_commit_validation_failure() {
        let temp = tempdir().unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        let stage_name = OsStr::new("stage.tmp");
        let target_name = OsStr::new("published.wal");
        let stage_display = temp.path().join(stage_name);
        let target_display = temp.path().join(target_name);
        let (mut stage, _binding) =
            create_private_regular_file_child_create_new(&root.dir, stage_name, &stage_display)
                .unwrap();
        use std::io::Write as _;
        stage.write_all(b"committed prefix").unwrap();
        stage.sync_all().unwrap();
        fail_private_child_post_commit_validation_for_test(&target_display);
        let mut commits = 0usize;

        let error = publish_open_regular_file_child_observed(
            &root.dir,
            &stage,
            stage_name,
            &root.dir,
            target_name,
            &stage_display,
            &target_display,
            || commits += 1,
        )
        .expect_err("injected validation failure follows the atomic commit");

        assert!(
            format!("{error:#}").contains("post-commit validation failure"),
            "{error:#}"
        );
        assert_eq!(commits, 1, "the committed object must be reported once");
        assert!(!stage_display.exists());
        assert_eq!(std::fs::read(&target_display).unwrap(), b"committed prefix");
    }

    #[test]
    #[cfg(unix)]
    fn create_new_detects_source_name_substitution_and_never_claims_success() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("pending.json");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        let directory = temp.path().to_path_buf();
        set_before_open_file_rename_for_test(move || {
            swap_open_atomic_stage_name(&directory, "displaced-stage", b"attacker");
        });

        let error = atomic_write_private_child_create_new(
            &root.dir,
            OsStr::new("pending.json"),
            &target,
            b"authenticated",
        )
        .expect_err("source-name substitution must be detected after publication");

        assert!(
            format!("{error:#}").contains("not the exact open stage object"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"attacker");
        assert_eq!(
            std::fs::read(temp.path().join("displaced-stage")).unwrap(),
            b"authenticated"
        );
    }

    #[test]
    #[cfg(unix)]
    fn replacement_detects_source_name_substitution_and_never_claims_success() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("pending.json");
        std::fs::write(&target, b"old").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        let directory = temp.path().to_path_buf();
        set_before_open_file_rename_for_test(move || {
            swap_open_atomic_stage_name(&directory, "displaced-stage", b"attacker");
        });

        let error =
            atomic_write_private_child(&root.dir, OsStr::new("pending.json"), &target, b"new")
                .expect_err("replacement source-name substitution must be detected");

        assert!(
            format!("{error:#}").contains("not the exact open stage object"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"attacker");
        assert_eq!(
            std::fs::read(temp.path().join("displaced-stage")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn atomic_private_child_create_new_never_replaces_existing_target() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("consumed.used");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        atomic_write_private_child_create_new(
            &root.dir,
            OsStr::new("consumed.used"),
            &target,
            b"first",
        )
        .unwrap();
        let error = atomic_write_private_child_create_new(
            &root.dir,
            OsStr::new("consumed.used"),
            &target,
            b"second",
        )
        .expect_err("create-new must preserve the existing replay tombstone");

        assert!(format!("{error:#}").contains("already exists"));
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
    }

    #[test]
    fn new_private_child_syncs_its_parent_before_returning() {
        let temp = tempdir().unwrap();
        let child = temp.path().join("generations");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        force_parent_sync_failure_for_test(true);
        let error = open_or_create_private_child_dir(&root.dir, OsStr::new("generations"), &child)
            .expect_err("a newly published child must not escape a failed parent sync");
        assert!(format!("{error:#}").contains("injected parent-directory sync failure"));
        assert!(
            child.is_dir(),
            "the mkdir may have reached disk, but no caller capability was returned"
        );
        let retry_error =
            open_or_create_private_child_dir(&root.dir, OsStr::new("generations"), &child)
                .expect_err("a visible child must not bypass its failed durability confirmation");
        force_parent_sync_failure_for_test(false);

        assert!(format!("{retry_error:#}").contains("injected parent-directory sync failure"));
        open_or_create_private_child_dir(&root.dir, OsStr::new("generations"), &child)
            .expect("a retry returns only after the existing entry is durably re-synced");
    }

    #[test]
    fn bound_directory_creation_syncs_each_component_before_descending() {
        let temp = tempdir().unwrap();
        let requested = temp
            .path()
            .join("stage")
            .join("generations")
            .join("candidate");

        force_parent_sync_failure_for_test(true);
        let error = open_bound_directory(&requested, true, "test nested store")
            .err()
            .expect("creation must stop at the first unconfirmed namespace publication");
        assert!(format!("{error:#}").contains("injected parent-directory sync failure"));
        assert!(temp.path().join("stage").is_dir());
        assert!(
            !temp.path().join("stage").join("generations").exists(),
            "no descendant may be published after its parent sync failed"
        );
        let retry_error = open_bound_directory(&requested, true, "test nested store")
            .err()
            .expect("an existing first component must be re-synced before descending");
        force_parent_sync_failure_for_test(false);

        assert!(format!("{retry_error:#}").contains("injected parent-directory sync failure"));
        assert!(
            !temp.path().join("stage").join("generations").exists(),
            "failed retry sync still must not publish a descendant"
        );
        open_bound_directory(&requested, true, "test nested store")
            .expect("retry may descend after every parent namespace is durably confirmed");
        assert!(requested.is_dir());
    }

    #[test]
    fn explicit_trusted_anchor_retry_resyncs_first_of_multiple_missing_descendants() {
        let temp = tempdir().unwrap();
        let requested = temp
            .path()
            .join("stage")
            .join("generations")
            .join("candidate")
            .join("payload");

        force_parent_sync_failure_for_test(true);
        let error = open_bound_directory_from_trusted_anchor(
            temp.path(),
            &requested,
            true,
            "test explicit anchor",
        )
        .err()
        .expect("creation must stop after publishing the first missing descendant");
        assert!(format!("{error:#}").contains("injected parent-directory sync failure"));
        assert!(temp.path().join("stage").is_dir());
        assert!(!temp.path().join("stage").join("generations").exists());

        let retry_error = open_bound_directory_from_trusted_anchor(
            temp.path(),
            &requested,
            true,
            "test explicit anchor",
        )
        .err()
        .expect("retry must re-sync the visible descendant before descending");
        force_parent_sync_failure_for_test(false);

        assert!(format!("{retry_error:#}").contains("injected parent-directory sync failure"));
        assert!(
            !temp.path().join("stage").join("generations").exists(),
            "a failed retry must not publish a deeper descendant"
        );
        open_bound_directory_from_trusted_anchor(
            temp.path(),
            &requested,
            true,
            "test explicit anchor",
        )
        .expect("retry may descend after every namespace is durably confirmed");
        assert!(requested.is_dir());
    }

    #[test]
    fn explicit_trusted_anchor_rejects_target_escape_without_side_effects() {
        let temp = tempdir().unwrap();
        let trusted = temp.path().join("trusted");
        let outside = temp.path().join("trusted-neighbor").join("candidate");
        std::fs::create_dir(&trusted).unwrap();

        let error = open_bound_directory_from_trusted_anchor(
            &trusted,
            &outside,
            true,
            "test explicit anchor",
        )
        .err()
        .expect("a target outside the explicit anchor must fail closed");

        assert!(format!("{error:#}").contains("outside trusted anchor"));
        assert!(
            !outside.exists(),
            "an escaped target must not receive any filesystem side effects"
        );
    }

    #[test]
    fn explicit_trusted_anchor_rejects_navigation_before_normalization() {
        let temp = tempdir().unwrap();
        let trusted_with_parent = temp.path().join("anchor").join("..").join("trusted");
        let normalized_trusted = temp.path().join("trusted");
        let target = normalized_trusted.join("candidate");
        let anchor_error = open_bound_directory_from_trusted_anchor(
            &trusted_with_parent,
            &target,
            true,
            "test explicit anchor",
        )
        .err()
        .expect("a navigation-bearing trusted anchor must fail closed");
        assert!(format!("{anchor_error:#}").contains("must not contain"));
        assert!(!normalized_trusted.exists());

        let trusted = temp.path().join("stable");
        std::fs::create_dir(&trusted).unwrap();
        let target_with_parent = trusted.join("nested").join("..").join("candidate");
        let target_error = open_bound_directory_from_trusted_anchor(
            &trusted,
            &target_with_parent,
            true,
            "test explicit anchor",
        )
        .err()
        .expect("a navigation-bearing target must fail closed");
        assert!(format!("{target_error:#}").contains("must not contain"));
        assert!(!trusted.join("candidate").exists());
        assert!(!trusted.join("nested").exists());
    }

    #[test]
    fn optional_real_child_open_distinguishes_absence_from_invalid_objects() {
        let temp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let linked = temp.path().join("linked");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        assert!(
            open_real_child_dir_if_present(
                &root.dir,
                OsStr::new("missing"),
                &temp.path().join("missing"),
            )
            .unwrap()
            .is_none()
        );
        if try_link_dir(outside.path(), &linked).is_err() {
            return;
        }

        open_real_child_dir_if_present(&root.dir, OsStr::new("linked"), &linked)
            .expect_err("a symlink, junction, or reparse point must never be opened as real");
    }

    #[test]
    fn optional_child_file_removal_unlinks_links_without_following_them() {
        let temp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_sentinel = outside.path().join("keep.txt");
        std::fs::write(&outside_sentinel, b"keep").unwrap();
        let linked = temp.path().join("linked");
        if try_link_dir(outside.path(), &linked).is_err() {
            return;
        }
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        assert!(remove_child_file_if_present(&root.dir, OsStr::new("linked"), &linked).unwrap());
        assert!(std::fs::symlink_metadata(&linked).is_err());
        assert_eq!(std::fs::read(&outside_sentinel).unwrap(), b"keep");
        assert!(!remove_child_file_if_present(&root.dir, OsStr::new("linked"), &linked).unwrap());
    }

    #[test]
    fn optional_empty_directory_removal_is_bounded_and_link_safe() {
        let temp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_sentinel = outside.path().join("keep.txt");
        std::fs::write(&outside_sentinel, b"keep").unwrap();
        let empty = temp.path().join("empty");
        let non_empty = temp.path().join("non-empty");
        let linked = temp.path().join("linked");
        std::fs::create_dir(&empty).unwrap();
        std::fs::create_dir(&non_empty).unwrap();
        std::fs::write(non_empty.join("keep.txt"), b"keep").unwrap();
        let linked_created = try_link_dir(outside.path(), &linked).is_ok();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        assert!(
            remove_empty_real_child_dir_if_present(&root.dir, OsStr::new("empty"), &empty).unwrap()
        );
        assert!(!empty.exists());
        remove_empty_real_child_dir_if_present(&root.dir, OsStr::new("non-empty"), &non_empty)
            .expect_err("unexpected generation contents must be preserved");
        assert_eq!(std::fs::read(non_empty.join("keep.txt")).unwrap(), b"keep");
        assert!(
            !remove_empty_real_child_dir_if_present(
                &root.dir,
                OsStr::new("missing"),
                &temp.path().join("missing"),
            )
            .unwrap()
        );

        if linked_created {
            remove_empty_real_child_dir_if_present(&root.dir, OsStr::new("linked"), &linked)
                .expect_err("a link or reparse point must not be treated as an empty directory");
            assert_eq!(std::fs::read(&outside_sentinel).unwrap(), b"keep");
            assert!(
                std::fs::symlink_metadata(&linked).is_ok(),
                "refused link must remain for explicit leaf cleanup"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_deletion_traverses_before_acquiring_delete_authority() {
        let temp = tempdir().unwrap();
        let empty = temp.path().join("empty");
        let tree = temp.path().join("tree");
        std::fs::create_dir(&empty).unwrap();
        std::fs::create_dir_all(tree.join("nested")).unwrap();
        std::fs::write(tree.join("nested").join("entry.txt"), b"remove").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        assert!(
            remove_empty_real_child_dir_if_present(&root.dir, OsStr::new("empty"), &empty).unwrap()
        );
        assert!(!empty.exists());

        remove_real_directory_tree(&root.dir, OsStr::new("tree"), &tree).unwrap();
        assert!(!tree.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_recursive_delete_refuses_leaf_that_changes_to_real_directory() {
        let temp = tempdir().unwrap();
        let victim = temp.path().join("victim");
        let leaf = victim.join("stage");
        let displaced = victim.join("displaced-stage");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(&leaf, b"authorized leaf").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let hook_leaf = leaf.clone();
        let hook_displaced = displaced.clone();
        set_before_windows_recursive_leaf_delete_for_test(move || {
            std::fs::rename(&hook_leaf, &hook_displaced).unwrap();
            std::fs::create_dir(&hook_leaf).unwrap();
        });
        let error = remove_real_directory_tree(&root.dir, OsStr::new("victim"), &victim)
            .expect_err("a classified leaf that becomes a real directory must fail closed");

        assert!(
            format!("{error:#}").contains("changed into a real directory"),
            "{error:#}"
        );
        assert!(leaf.is_dir(), "replacement directory must never be deleted");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"authorized leaf");
    }

    #[cfg(unix)]
    #[test]
    fn empty_directory_removal_never_unlinks_a_final_lookup_replacement() {
        use std::os::unix::fs::MetadataExt as _;

        let temp = tempdir().unwrap();
        let target = temp.path().join("candidate");
        let moved_original = temp.path().join("concurrent-original");
        std::fs::create_dir(&target).unwrap();
        let original_inode = std::fs::metadata(&target).unwrap().ino();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let hook_target = target.clone();
        let hook_original = moved_original.clone();
        set_before_empty_directory_rename_for_test(move || {
            std::fs::rename(&hook_target, &hook_original).unwrap();
            std::fs::create_dir(&hook_target).unwrap();
        });
        let error =
            remove_empty_real_child_dir_if_present(&root.dir, OsStr::new("candidate"), &target)
                .expect_err(
                    "a concurrent same-name replacement must never inherit delete authority",
                );

        assert!(
            format!("{error:#}").contains("removal rename moved a different object"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::metadata(&moved_original).unwrap().ino(),
            original_inode,
            "the originally validated object must remain intact at its concurrent name"
        );
        assert!(
            !target.exists(),
            "replacement was isolated under a tombstone"
        );
        let tombstones = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-empty-delete-")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            tombstones.len(),
            1,
            "the unvalidated replacement must be retained, not deleted"
        );
        assert!(tombstones[0].path().is_dir());
        assert_ne!(
            std::fs::metadata(tombstones[0].path()).unwrap().ino(),
            original_inode
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

#[cfg(test)]
mod reported_commit_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn poisoned_post_commit_hook_recovers_without_cross_target_or_stale_state() {
        struct ScopedHookCleanup(Vec<PathBuf>);

        impl Drop for ScopedHookCleanup {
            fn drop(&mut self) {
                let mut targets = TEST_FAIL_PRIVATE_CHILD_POST_COMMIT_VALIDATION_AT
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                targets.retain(|registration| !self.0.contains(&registration.target));
                drop(targets);
                TEST_FAIL_PRIVATE_CHILD_POST_COMMIT_VALIDATION_AT.clear_poison();
            }
        }

        let unique = uuid::Uuid::new_v4().simple().to_string();
        let exact = PathBuf::from(format!("poison-exact-{unique}"));
        let second = PathBuf::from(format!("poison-second-{unique}"));
        let unrelated = PathBuf::from(format!("poison-unrelated-{unique}"));
        let never_registered = PathBuf::from(format!("poison-never-{unique}"));
        let _cleanup = ScopedHookCleanup(vec![
            exact.clone(),
            second.clone(),
            unrelated.clone(),
            never_registered.clone(),
        ]);

        {
            let mut targets = TEST_FAIL_PRIVATE_CHILD_POST_COMMIT_VALIDATION_AT
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            targets.push(TestPostCommitFailureRegistration {
                target: exact.clone(),
                generation: 0,
            });
            targets.push(TestPostCommitFailureRegistration {
                target: exact.clone(),
                generation: 0,
            });
        }
        fail_private_child_post_commit_validation_for_test(&unrelated);

        std::thread::spawn(|| {
            let _lock = TEST_FAIL_PRIVATE_CHILD_POST_COMMIT_VALIDATION_AT
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("deterministically poison the private-child test-hook mutex");
        })
        .join()
        .expect_err("the scoped poison worker must panic while holding the mutex");
        assert!(TEST_FAIL_PRIVATE_CHILD_POST_COMMIT_VALIDATION_AT.is_poisoned());

        fail_private_child_post_commit_validation_for_test(&exact);
        fail_private_child_post_commit_validation_for_test(&second);
        assert!(inject_private_child_post_commit_validation_failure(&never_registered).is_ok());
        assert!(inject_private_child_post_commit_validation_failure(&exact).is_err());
        assert!(inject_private_child_post_commit_validation_failure(&exact).is_ok());
        assert!(inject_private_child_post_commit_validation_failure(&second).is_err());
        assert!(inject_private_child_post_commit_validation_failure(&second).is_ok());
        assert!(inject_private_child_post_commit_validation_failure(&unrelated).is_err());
        assert!(inject_private_child_post_commit_validation_failure(&unrelated).is_ok());
    }

    #[test]
    fn reported_private_child_write_returns_a_published_commit() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let commit = atomic_write_private_child_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"private state",
        )
        .unwrap();
        assert!(matches!(
            commit,
            PrivateChildCommit::PublishedAndSynced
                | PrivateChildCommit::PublishedDurabilityUnknown(_)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"private state");
    }

    #[cfg(unix)]
    #[test]
    fn reported_private_child_sync_failure_is_published_not_retryable() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        force_parent_sync_failure_for_test(true);
        let commit = atomic_write_private_child_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"private state",
        )
        .unwrap();
        force_parent_sync_failure_for_test(false);
        assert_eq!(
            commit,
            PrivateChildCommit::PublishedDurabilityUnknown(
                PrivateChildDurabilityUnknown::ParentSyncFailed
            )
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"private state");
    }

    #[test]
    fn reported_create_new_observes_publication_before_post_commit_validation_failure() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        fail_private_child_post_commit_validation_for_test(&target);
        let commit = atomic_write_private_child_create_new_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"private state",
        )
        .expect("post-rename validation failure is a published outcome");

        assert_eq!(
            commit,
            PrivateChildCommit::PublishedDurabilityUnknown(
                PrivateChildDurabilityUnknown::PostCommitValidationFailed
            )
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"private state");
        assert_eq!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-atomic-"))
                .count(),
            0,
            "a committed stage is neither cleaned up nor retried"
        );
    }

    #[test]
    fn reported_replacement_observes_publication_before_post_commit_validation_failure() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        std::fs::write(&target, b"previous state").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        fail_private_child_post_commit_validation_for_test(&target);
        let commit = atomic_write_private_child_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"replacement state",
        )
        .expect("post-rename validation failure is a published outcome");

        assert_eq!(
            commit,
            PrivateChildCommit::PublishedDurabilityUnknown(
                PrivateChildDurabilityUnknown::PostCommitValidationFailed
            )
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement state");
        assert_eq!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-atomic-"))
                .count(),
            0,
            "a committed replacement stage is neither cleaned up nor retried"
        );
    }

    #[test]
    fn legacy_replacement_keeps_post_commit_validation_error() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        std::fs::write(&target, b"previous state").unwrap();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        fail_private_child_post_commit_validation_for_test(&target);
        let error = atomic_write_private_child(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"replacement state",
        )
        .expect_err("legacy callers must retain their historical error contract");

        assert!(
            format!("{error:#}").contains("injected private-child post-commit validation failure"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement state");
    }

    #[cfg(windows)]
    #[test]
    fn reported_private_child_write_confirms_windows_write_through_rename() {
        let _scope = windows_private_atomic_stage::qualified_local_ntfs_for_test();
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let commit = atomic_write_private_child_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"private state",
        )
        .unwrap();

        assert_eq!(commit, PrivateChildCommit::PublishedAndSynced);
        assert_eq!(std::fs::read(&target).unwrap(), b"private state");

        let error = atomic_write_private_child_create_new_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"must not replace the confirmed private record",
        )
        .expect_err("create-new must retain no-replace semantics after the durable rename");
        assert!(error
            .source
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists));
        assert_eq!(std::fs::read(&target).unwrap(), b"private state");
    }

    #[cfg(windows)]
    #[test]
    fn unsupported_windows_volume_publishes_without_claiming_durability() {
        let _scope = windows_private_atomic_stage::unsupported_volume_for_test();
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();

        let commit = atomic_write_private_child_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"private state",
        )
        .unwrap();

        assert_eq!(
            commit,
            PrivateChildCommit::PublishedDurabilityUnknown(
                PrivateChildDurabilityUnknown::ParentSyncUnsupported
            )
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"private state");

        std::fs::write(&target, b"old").unwrap();
        let report = replace_existing_regular_file_report(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"new",
        )
        .unwrap();
        assert!(report.warnings.iter().any(|warning| warning.contains("unsupported")));
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[cfg(windows)]
    #[test]
    fn failed_no_replace_rename_cannot_obtain_a_commit_witness() {
        let _scope = windows_private_atomic_stage::qualified_local_ntfs_for_test();
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        let injected_target = target.clone();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        windows_private_atomic_stage::set_before_rename_for_test(move || {
            std::fs::write(injected_target, b"racing writer").unwrap();
        });

        atomic_write_private_child_create_new_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"private state",
        )
        .expect_err("a colliding target must prevent the same-handle commit witness");

        assert_eq!(std::fs::read(&target).unwrap(), b"racing writer");
        assert_eq!(
            std::fs::read_dir(temp.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-atomic-"))
                .count(),
            0,
            "a failed rename must clean up only its exact open stage"
        );
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_disposes_exact_stage_handle_without_deleting_name_substitute() {
        let _scope = windows_private_atomic_stage::qualified_local_ntfs_for_test();
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        let injected_target = target.clone();
        let directory = temp.path().to_path_buf();
        let displaced = temp.path().join("displaced-exact-stage");
        let displaced_for_hook = displaced.clone();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        windows_private_atomic_stage::set_before_rename_for_test(move || {
            std::fs::write(injected_target, b"rename collision").unwrap();
        });
        windows_private_atomic_stage::set_before_cleanup_for_test(move || {
            let stage = std::fs::read_dir(&directory)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .find(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-atomic-"))
                .expect("exact open stage must still have its original name")
                .path();
            std::fs::rename(&stage, &displaced_for_hook).unwrap();
            std::fs::write(&stage, b"name substitute").unwrap();
        });

        atomic_write_private_child_create_new_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"private state",
        )
        .expect_err("the injected target must make the no-replace rename fail");

        assert_eq!(std::fs::read(&target).unwrap(), b"rename collision");
        assert!(!displaced.exists(), "the exact retained stage handle must be disposed");
        let substitutes: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".neoth-atomic-"))
            .collect();
        assert_eq!(substitutes.len(), 1, "only the deliberate substitute survives");
        assert_eq!(std::fs::read(substitutes[0].path()).unwrap(), b"name substitute");
    }

    #[cfg(windows)]
    #[test]
    fn post_rename_name_substitution_cannot_obtain_a_commit_witness() {
        let _scope = windows_private_atomic_stage::qualified_local_ntfs_for_test();
        let temp = tempdir().unwrap();
        let target = temp.path().join("state.json");
        let displaced = temp.path().join("displaced-stage.json");
        let swapped_target = target.clone();
        let swapped_displaced = displaced.clone();
        let root = open_bound_directory(temp.path(), false, "test store")
            .unwrap()
            .unwrap();
        windows_private_atomic_stage::set_after_rename_for_test(move || {
            std::fs::rename(&swapped_target, &swapped_displaced).unwrap();
            std::fs::write(&swapped_target, b"substituted target").unwrap();
        });

        let commit = atomic_write_private_child_create_new_reported(
            &root.dir,
            OsStr::new("state.json"),
            &target,
            b"private state",
        )
        .expect("a completed rename with failed identity validation is a published outcome");

        assert_eq!(
            commit,
            PrivateChildCommit::PublishedDurabilityUnknown(
                PrivateChildDurabilityUnknown::PostCommitValidationFailed
            )
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"substituted target");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"private state");
    }

    #[cfg(windows)]
    #[test]
    fn reparse_attribute_classification_is_deterministic_without_symlink_privilege() {
        assert!(windows_file_attributes_are_link_like(0x400));
        assert!(windows_file_attributes_are_link_like(0x400 | 0x20));
        assert!(!windows_file_attributes_are_link_like(0));
        assert!(!windows_file_attributes_are_link_like(0x20));
    }
}
