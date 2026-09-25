//! Capability-bound cross-process exclusion for Paperless lifecycle mutations.
//!
//! The lock file is opened only beneath the retained, already-owned `state`
//! directory. Dropping the guard releases the OS lock.

use std::ffi::OsStr;

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::OpenOptions;

use super::paperless_staging::OwnedPaperlessRoot;

pub(crate) struct PaperlessOperationLock {
    _file: std::fs::File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PaperlessOperationLockError {
    Busy,
    Unsafe,
    Io,
}

/// Acquire one nonblocking exclusive lock below the owned Paperless state
/// capability. `state` must already have been prepared by the launch guard.
pub(crate) fn acquire(
    root: &OwnedPaperlessRoot,
    lock_name: &OsStr,
) -> Result<PaperlessOperationLock, PaperlessOperationLockError> {
    let state = crate::skills::store::open_real_child_dir(
        &root.root,
        OsStr::new("state"),
        &root.display.join("state"),
    )
    .map_err(|_| PaperlessOperationLockError::Unsafe)?;
    match state.symlink_metadata(lock_name) {
        Ok(metadata) if !metadata.is_file() || metadata.is_symlink() => {
            return Err(PaperlessOperationLockError::Unsafe);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(PaperlessOperationLockError::Io),
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        };
        options
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = match state.open_with(lock_name, &options) {
        Ok(file) => file.into_std(),
        #[cfg(windows)]
        Err(error) if error.raw_os_error() == Some(32) => {
            return Err(PaperlessOperationLockError::Busy);
        }
        Err(_) => return Err(PaperlessOperationLockError::Io),
    };
    let metadata = file.metadata().map_err(|_| PaperlessOperationLockError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PaperlessOperationLockError::Unsafe);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PaperlessOperationLockError::Unsafe);
        }
    }
    match file.try_lock() {
        Ok(()) => Ok(PaperlessOperationLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(PaperlessOperationLockError::Busy),
        Err(std::fs::TryLockError::Error(_)) => Err(PaperlessOperationLockError::Io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged_owned_root() -> (tempfile::TempDir, OwnedPaperlessRoot) {
        let (home, _) = super::super::staged_paperless_home_for_test();
        let root_path = crate::config::InstancePaths::for_home(home.path()).paperless_root;
        let owned = super::super::paperless_staging::open_owned_root_at(&root_path).unwrap();
        (home, owned)
    }

    #[test]
    fn same_owned_root_is_busy_until_first_guard_drops() {
        let (_home, owned) = staged_owned_root();
        let first = acquire(&owned, OsStr::new(super::super::OPERATIONS_LOCK_NAME)).unwrap();
        assert!(matches!(
            acquire(&owned, OsStr::new(super::super::OPERATIONS_LOCK_NAME)),
            Err(PaperlessOperationLockError::Busy)
        ));
        drop(first);
        acquire(&owned, OsStr::new(super::super::OPERATIONS_LOCK_NAME)).unwrap();
    }

    #[test]
    fn independent_owned_roots_do_not_share_operation_lock() {
        let (_first_home, first_root) = staged_owned_root();
        let (_second_home, second_root) = staged_owned_root();
        let _first = acquire(
            &first_root,
            OsStr::new(super::super::OPERATIONS_LOCK_NAME),
        )
        .unwrap();
        let _second = acquire(
            &second_root,
            OsStr::new(super::super::OPERATIONS_LOCK_NAME),
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_lock_leaf_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let (home, owned) = staged_owned_root();
        let target = home.path().join("lock-target");
        std::fs::write(&target, b"retain").unwrap();
        let lock_path = owned.display.join("state").join(super::super::OPERATIONS_LOCK_NAME);
        symlink(&target, &lock_path).unwrap();

        assert!(matches!(
            acquire(&owned, OsStr::new(super::super::OPERATIONS_LOCK_NAME)),
            Err(PaperlessOperationLockError::Unsafe)
        ));
        assert_eq!(std::fs::read(target).unwrap(), b"retain");
    }

    #[test]
    fn malformed_state_entry_is_rejected() {
        let (_home, owned) = staged_owned_root();
        let state_path = owned.display.join("state");
        std::fs::remove_dir(&state_path).unwrap();
        std::fs::write(&state_path, b"not a directory").unwrap();

        assert!(matches!(
            acquire(&owned, OsStr::new(super::super::OPERATIONS_LOCK_NAME)),
            Err(PaperlessOperationLockError::Unsafe)
        ));
    }
}
