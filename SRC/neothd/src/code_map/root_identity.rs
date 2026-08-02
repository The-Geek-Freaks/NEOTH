//! Canonical, physical identity for one local repository root.
//!
//! Display paths are useful to operators but are not stable identities: aliases,
//! symlinks, junctions, and renames can all change the spelling without changing
//! the directory. Code-map receipts therefore bind both the canonical display
//! path and an OS-provided directory identity.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Stable local identity of a directory on the current machine.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RootIdentity(String);

impl RootIdentity {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A repository root resolved to one canonical display path and physical object.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalRepoRoot {
    path: PathBuf,
    display: String,
    identity: RootIdentity,
}

impl CanonicalRepoRoot {
    /// Resolve `path` without a raw-path fallback.
    pub fn discover(path: &Path) -> Result<Self> {
        let canonical = std::fs::canonicalize(path)
            .with_context(|| format!("canonicalize repository root {}", path.display()))?;
        let metadata = std::fs::metadata(&canonical)
            .with_context(|| format!("stat canonical repository root {}", canonical.display()))?;
        if !metadata.is_dir() {
            bail!("repository root {} is not a directory", canonical.display());
        }
        let display = canonical
            .to_str()
            .context("canonical repository root is not valid UTF-8")?
            .to_owned();
        let identity = physical_directory_identity(&canonical)?;
        Ok(Self {
            path: canonical,
            display,
            identity,
        })
    }

    /// Reconstitute and verify an identity stored in SQLite.
    pub fn from_persisted(display: &str, identity: &str) -> Result<Self> {
        let discovered = Self::discover(Path::new(display))?;
        if discovered.display != display {
            bail!(
                "persisted code-map root {display:?} is not its canonical display path {:?}",
                discovered.display
            );
        }
        if discovered.identity.as_str() != identity {
            bail!("persisted code-map root {display:?} no longer identifies the indexed directory");
        }
        Ok(discovered)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn display(&self) -> &str {
        &self.display
    }

    pub fn identity(&self) -> &RootIdentity {
        &self.identity
    }
}

#[cfg(unix)]
fn physical_directory_identity(path: &Path) -> Result<RootIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("read physical identity for {}", path.display()))?;
    Ok(RootIdentity(format!(
        "unix:{:016x}:{:016x}",
        metadata.dev(),
        metadata.ino()
    )))
}

#[cfg(windows)]
fn physical_directory_identity(path: &Path) -> Result<RootIdentity> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
    };

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        bail!("canonical repository root contains an interior NUL");
    }
    wide.push(0);
    // Desired access 0 is sufficient for metadata, cannot mutate the directory,
    // and BACKUP_SEMANTICS is required to open a directory handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open repository root identity handle {}", path.display()));
    }
    struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let handle = OwnedHandle(handle);
    let mut information = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
    let information_size = u32::try_from(std::mem::size_of::<FILE_ID_INFO>())
        .context("convert Windows FILE_ID_INFO size")?;
    if unsafe {
        GetFileInformationByHandleEx(
            handle.0,
            FileIdInfo,
            information.as_mut_ptr().cast(),
            information_size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "read repository root identity from handle {}",
                path.display()
            )
        });
    }
    let information = unsafe { information.assume_init() };
    let identifier = information.FileId.Identifier;
    if identifier.iter().all(|byte| *byte == 0) {
        bail!("file system did not provide a stable repository directory identity");
    }
    use std::fmt::Write as _;
    let mut file_id = String::with_capacity(32);
    for byte in identifier {
        write!(&mut file_id, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(RootIdentity(format!(
        "windows:{:016x}:{file_id}",
        information.VolumeSerialNumber
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn canonical_root_is_stable_for_relative_aliases() {
        let root = tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let direct = CanonicalRepoRoot::discover(&nested).unwrap();
        let aliased = CanonicalRepoRoot::discover(&root.path().join("nested").join(".")).unwrap();
        assert_eq!(direct, aliased);
        assert_eq!(direct.path(), std::fs::canonicalize(&nested).unwrap());
    }

    #[test]
    fn persisted_identity_rejects_another_directory() {
        let root = tempdir().unwrap();
        let a = root.path().join("a");
        let b = root.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let first = CanonicalRepoRoot::discover(&a).unwrap();
        let other = CanonicalRepoRoot::discover(&b).unwrap();
        assert!(
            CanonicalRepoRoot::from_persisted(other.display(), first.identity().as_str()).is_err()
        );
    }
}
