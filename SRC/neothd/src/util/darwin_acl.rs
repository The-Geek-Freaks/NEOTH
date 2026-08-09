//! macOS extended-ACL checks for security-sensitive directories.
//!
//! POSIX mode bits alone do not describe every principal that can access a
//! directory on macOS.  The verifier below uses the descriptor-relative ACL
//! API so the ACL inspected is the object opened with `O_NOFOLLOW`, rather
//! than a later path lookup.

use std::{io, path::Path};

/// Reject a directory that carries a macOS extended ACL.
///
/// On platforms without macOS extended ACLs this is deliberately a no-op, so
/// callers can apply the same hardening policy without platform conditionals.
#[cfg(not(target_os = "macos"))]
pub(crate) fn verify_directory_has_no_extended_acl(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_directory_has_no_extended_acl(path: &Path) -> io::Result<()> {
    use std::{
        fs::OpenOptions,
        os::unix::{fs::OpenOptionsExt, io::AsRawFd},
        ptr::NonNull,
    };

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;

    // `O_DIRECTORY` is the first guard; retain the descriptor-bound metadata
    // check so a platform or filesystem that does not honour that flag cannot
    // make this verifier inspect a non-directory object.
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", path.display()),
        ));
    }

    // SAFETY: `directory` remains live for this call, so `as_raw_fd()` is a
    // valid descriptor. `ACL_TYPE_EXTENDED` is Apple's documented selector for
    // the extended ACL associated with that descriptor.
    let raw_acl = unsafe { acl_get_fd_np(directory.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(raw_acl) = NonNull::new(raw_acl) else {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(os_error("acl_get_fd_np", path, error))
        };
    };

    let mut acl = OwnedAcl::new(raw_acl);
    let inspection = inspect_first_entry(acl.as_ptr(), path);
    // Call `acl_free` even when ACL inspection rejects or errors. A failed
    // release is itself fail-closed and is never retried.
    let release = acl.free_once(path);

    match (inspection, release) {
        (_, Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(target_os = "macos")]
const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
#[cfg(target_os = "macos")]
const ACL_FIRST_ENTRY: libc::c_int = 0;

#[cfg(target_os = "macos")]
type Acl = *mut libc::c_void;

#[cfg(target_os = "macos")]
#[link(name = "System")]
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
    fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut Acl) -> libc::c_int;
    fn acl_free(object: *mut libc::c_void) -> libc::c_int;
}

#[cfg(target_os = "macos")]
struct OwnedAcl(Option<std::ptr::NonNull<libc::c_void>>);

#[cfg(target_os = "macos")]
impl OwnedAcl {
    fn new(acl: std::ptr::NonNull<libc::c_void>) -> Self {
        Self(Some(acl))
    }

    fn as_ptr(&self) -> Acl {
        self.0
            .expect("owned ACL must be present until it is released")
            .as_ptr()
    }

    fn free_once(&mut self, path: &Path) -> io::Result<()> {
        let acl = self.0.take().expect("owned ACL must only be released once");
        // SAFETY: `acl` was returned non-null by `acl_get_fd_np` and has not
        // been passed to `acl_free` before; consuming it above prevents a
        // second explicit release or a Drop-path double free.
        let result = unsafe { acl_free(acl.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(os_error("acl_free", path, io::Error::last_os_error()))
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for OwnedAcl {
    fn drop(&mut self) {
        if let Some(acl) = self.0.take() {
            // SAFETY: this is only the unwind/early-drop fallback. `take()`
            // makes the allocation unreachable before the one permitted call.
            let _ = unsafe { acl_free(acl.as_ptr()) };
        }
    }
}

#[cfg(target_os = "macos")]
fn inspect_first_entry(acl: Acl, path: &Path) -> io::Result<()> {
    let mut entry = std::ptr::null_mut();
    // SAFETY: `acl` is a live allocation from `acl_get_fd_np`, and `entry`
    // points to writable storage for the ABI's out-parameter.
    let result = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };

    match result {
        0 if !entry.is_null() => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} has a macOS extended ACL", path.display()),
        )),
        0 => Err(io::Error::other(format!(
            "acl_get_entry returned success with a null entry for {}",
            path.display()
        ))),
        -1 => {
            let error = io::Error::last_os_error();
            if is_empty_acl_result(result, error.raw_os_error()) {
                Ok(())
            } else {
                Err(os_error("acl_get_entry", path, error))
            }
        }
        _ => Err(os_error("acl_get_entry", path, io::Error::last_os_error())),
    }
}

#[cfg(target_os = "macos")]
fn is_empty_acl_result(result: libc::c_int, errno: Option<libc::c_int>) -> bool {
    result == -1 && errno == Some(libc::EINVAL)
}

#[cfg(target_os = "macos")]
fn os_error(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} failed for {}: {error}", path.display()),
    )
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{is_empty_acl_result, verify_directory_has_no_extended_acl};

    #[test]
    fn fresh_directory_without_extended_acl_is_accepted() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        verify_directory_has_no_extended_acl(directory.path())
            .expect("a fresh temporary directory should not have an extended ACL");
    }

    #[test]
    fn only_the_documented_einval_marker_means_an_empty_acl() {
        assert!(is_empty_acl_result(-1, Some(libc::EINVAL)));
        assert!(!is_empty_acl_result(0, Some(libc::EINVAL)));
        assert!(!is_empty_acl_result(-1, Some(libc::ENOENT)));
        assert!(!is_empty_acl_result(-1, None));
    }
}
