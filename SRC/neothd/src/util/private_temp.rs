//! Private temporary storage for untrusted operator media.
//!
//! `tempfile` gives us unpredictable names and reliable cleanup, but a file in
//! the system temp directory otherwise inherits that directory's ACL on
//! Windows. Media snapshots can contain private documents, audio, or video, so
//! their access boundary must exist before the first byte is written.

use std::fs::File;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io;
use std::path::PathBuf;

const CREATE_ATTEMPTS: usize = 128;

/// Create a cleanup-guarded private file in the system temp directory.
///
/// Unix establishes mode `0600` through the creating `open(2)` call. Windows
/// supplies a protected, current-TokenUser-only DACL to `CreateFileW`; the
/// resulting handle allows an authorized same-token media subprocess to reopen
/// the random path while the parent retains the cleanup guard.
pub(crate) fn named_file(prefix: &str, suffix: &str) -> io::Result<tempfile::NamedTempFile> {
    validate_fragment(prefix)?;
    validate_fragment(suffix)?;
    let root = std::env::temp_dir();

    for _ in 0..CREATE_ATTEMPTS {
        let path = root.join(format!("{prefix}{}{suffix}", uuid::Uuid::new_v4()));
        match create_private_shared(&path) {
            Ok(file) => {
                let temp_path = match tempfile::TempPath::try_from_path(path.clone()) {
                    Ok(temp_path) => temp_path,
                    Err(error) => {
                        drop(file);
                        if let Err(cleanup_error) = std::fs::remove_file(&path) {
                            return Err(io::Error::new(
                                error.kind(),
                                format!(
                                    "construct temporary-path guard: {error}; cleanup of {} also failed: {cleanup_error}",
                                    path.display()
                                ),
                            ));
                        }
                        return Err(error);
                    }
                };
                return Ok(tempfile::NamedTempFile::from_parts(file, temp_path));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a collision-free private temporary file",
    ))
}

/// Create a cleanup-guarded private directory for a media tool work tree.
///
/// No payload is written until the freshly generated directory has been
/// narrowed and verified. Children inherit only the current TokenUser ACE on
/// Windows; Unix children are contained by a `0700` directory.
pub(crate) fn directory(prefix: &str) -> io::Result<PrivateTempDir> {
    validate_fragment(prefix)?;
    let root = std::env::temp_dir();
    for _ in 0..CREATE_ATTEMPTS {
        let path = root.join(format!("{prefix}{}", uuid::Uuid::new_v4()));
        match create_private_directory(&path) {
            Ok(()) => {
                let dir = PrivateTempDir { path };
                verify_private_directory(&dir)?;
                return Ok(dir);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a collision-free private temporary directory",
    ))
}

/// Cleanup guard for a directory created with a private descriptor/mode.
pub(crate) struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Remove the work tree now and surface cleanup failure to the caller.
    ///
    /// Security-sensitive supervisors should call this after every child and
    /// pipe has been reaped. `Drop` remains a last-resort cancellation guard,
    /// but cannot report an error.
    pub(crate) fn close(mut self) -> io::Result<()> {
        std::fs::remove_dir_all(&self.path)?;
        self.path.clear();
        Ok(())
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn validate_fragment(fragment: &str) -> io::Result<()> {
    if fragment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "temporary-file prefix/suffix contains a path separator or unsupported character",
        ))
    }
}

#[cfg(windows)]
fn create_private_shared(path: &std::path::Path) -> io::Result<File> {
    crate::wal::win_native::create_private_shared_file_new(path)
}

#[cfg(not(windows))]
fn create_private_shared(path: &std::path::Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[cfg(windows)]
fn create_private_directory(path: &std::path::Path) -> io::Result<()> {
    crate::wal::win_native::create_private_directory_new(path)
}

#[cfg(unix)]
fn create_private_directory(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

#[cfg(not(any(unix, windows)))]
fn create_private_directory(path: &std::path::Path) -> io::Result<()> {
    std::fs::create_dir(path)
}

fn verify_private_directory(dir: &PrivateTempDir) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::symlink_metadata(dir.path())?.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private temporary directory mode is {mode:#05o}, expected 0o700"),
            ));
        }
    }
    #[cfg(windows)]
    crate::wal::win_native::verify_private_directory_dacl(dir.path())?;
    #[cfg(not(any(unix, windows)))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn named_file_is_unique_writable_and_cleanup_guarded() {
        let mut first = named_file(".neoth-private-test-", ".bin").unwrap();
        let second = named_file(".neoth-private-test-", ".bin").unwrap();
        assert_ne!(first.path(), second.path());
        let first_path: PathBuf = first.path().to_owned();
        first.write_all(b"private").unwrap();
        assert_eq!(std::fs::read(&first_path).unwrap(), b"private");
        drop(first);
        assert!(!first_path.exists());
    }

    #[test]
    fn private_directory_is_cleanup_guarded() {
        let dir = directory(".neoth-private-cleanup-").unwrap();
        let path = dir.path().to_owned();
        std::fs::write(path.join("payload"), b"private").unwrap();
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn private_directory_explicit_close_reports_and_removes() {
        let dir = directory(".neoth-private-close-").unwrap();
        let path = dir.path().to_owned();
        std::fs::write(path.join("payload"), b"private").unwrap();
        dir.close().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn rejects_path_fragments() {
        assert!(named_file("../escape", ".bin").is_err());
        assert!(directory("nested/path").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_private_modes_are_exact() {
        use std::os::unix::fs::PermissionsExt as _;

        let file = named_file(".neoth-private-mode-", ".bin").unwrap();
        let dir = directory(".neoth-private-dir-").unwrap();
        assert_eq!(
            std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_dacls_are_verified() {
        let file = named_file(".neoth-private-dacl-", ".bin").unwrap();
        let dir = directory(".neoth-private-dir-").unwrap();
        crate::wal::win_native::verify_private_dacl(file.path()).unwrap();
        crate::wal::win_native::verify_private_directory_dacl(dir.path()).unwrap();
    }
}
