//! Crash-safe file writes (GOLD-ARCH-09).
//!
//! [`atomic_write`] is the canonical "write a file so a crash mid-write can't
//! leave a torn or empty target" primitive. It writes to a sibling temp file,
//! fsyncs it, then `rename`s over the target. The rename is atomic on both Unix
//! and Windows (std `rename` uses `MoveFileExW` with `REPLACE_EXISTING` /
//! `ReplaceFile` semantics on Windows), so **no explicit target-remove is
//! needed** — a remove-then-rename opens a window where a concurrent reader
//! sees no file at all, which is the exact bug this replaces in callers that
//! hand-rolled `if path.exists() { remove_file } ; rename`.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Atomically write `bytes` to `path`. Creates the parent directory if missing.
///
/// On success the file at `path` contains exactly `bytes`; on a crash mid-write
/// the previous contents (if any) survive intact. NOT a concurrency primitive:
/// two threads writing the same `path` should serialise externally (the temp
/// file is pid-scoped to avoid cross-process collisions, but same-process
/// racing writers can still clobber each other's rename — see the `*_LOCK`
/// patterns in `memory::channel_weights` / `cluster::registry` for that).
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_write_impl(path, bytes, false)
}

/// [`atomic_write`] for private operator data. On Unix the temporary file is
/// created with mode `0600` *before* any bytes are written, so the atomic
/// rename never exposes a wider-permission target even briefly. On Windows the
/// temporary file receives and verifies a protected current-user-only DACL
/// before any bytes are written; parent-directory ACLs are never inherited.
/// Its handle is `FILE_FLAG_WRITE_THROUGH`, so the subsequent handle-bound
/// rename durably commits Windows namespace metadata too.
pub fn atomic_write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_write_impl(path, bytes, true)
}

/// Create a new private file without replacing an existing path.
///
/// The security descriptor/mode is established before the first byte. Any
/// write, flush, sync, or verification failure closes and removes only the
/// file created by this call.
pub(crate) fn write_private_create_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_private_create_new_impl(path, bytes, false)
}

/// [`write_private_create_new`] with a durable directory-entry commit.
///
/// Use this for one-shot capabilities, claims, and replay tombstones whose
/// disappearance after power loss would reopen an already-authorized action.
pub(crate) fn write_private_create_new_durable(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_private_create_new_impl(path, bytes, true)
}

fn write_private_create_new_impl(
    path: &Path,
    bytes: &[u8],
    sync_parent: bool,
) -> std::io::Result<()> {
    #[cfg(windows)]
    let file = crate::wal::win_native::create_private_file_new(path)?;
    #[cfg(not(windows))]
    let file = {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options.open(path)?
    };

    let mut created = AtomicTemp::new(path.to_path_buf(), file);
    #[cfg(windows)]
    crate::wal::win_native::verify_private_file_handle(created.file())?;
    created.file_mut().write_all(bytes)?;
    created.file_mut().flush()?;
    created.file_mut().sync_all()?;
    created.close();
    if sync_parent {
        sync_create_new_parent(path)?;
    }
    created.disarm();
    Ok(())
}

/// Durably commit a successful `create_new` directory entry.
///
/// File data and metadata are synced by [`write_private_create_new`] before
/// this runs. POSIX additionally requires the containing directory to be
/// synced or a power loss may forget the new name, which would reopen a
/// one-shot control file or replay-tombstone window. Windows journals the
/// `CREATE_NEW` namespace operation; directory handles cannot be flushed via
/// `std::fs::File` there.
fn sync_create_new_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    CREATE_NEW_PARENT_SYNC_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    sync_parent_directory_required(path)
}

/// Durably commit the parent-directory entry containing `path`.
///
/// [`atomic_write_impl`] retains its historical best-effort parent sync because
/// cosmetic/cache callers cannot turn an otherwise successful replacement into
/// an error on filesystems that reject directory fsync. Transactions that
/// authorize an external effect call this helper after their atomic replacement
/// and before crossing the effect boundary.
///
/// Unix propagates every open/fsync error. Windows has no portable directory
/// fsync through `std`; private/capability atomic stages are opened with
/// `FILE_FLAG_WRITE_THROUGH`, so the handle-bound rename flushes namespace
/// metadata after the file bytes were explicitly committed.
pub(crate) fn sync_parent_directory_required(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    REQUIRED_PARENT_SYNC_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    #[cfg(unix)]
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
static REQUIRED_PARENT_SYNC_ATTEMPTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn required_parent_sync_attempts_for_test() -> usize {
    REQUIRED_PARENT_SYNC_ATTEMPTS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
static CREATE_NEW_PARENT_SYNC_ATTEMPTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn create_new_parent_sync_attempts_for_test() -> usize {
    CREATE_NEW_PARENT_SYNC_ATTEMPTS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Remove `path` and durably commit the directory-entry change. Absence is
/// already the requested state. This is the rollback counterpart to
/// [`atomic_write_private`] for transactions whose exact prior state was
/// "missing".
pub fn durable_remove_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            else {
                return Ok(());
            };
            match std::fs::symlink_metadata(parent) {
                Ok(_) => return sync_parent_directory_required(path),
                Err(parent_error) if parent_error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(());
                }
                Err(parent_error) => return Err(parent_error),
            }
        }
        Err(error) => return Err(error),
    }
    sync_parent_directory_required(path)
}

fn atomic_write_impl(path: &Path, bytes: &[u8], private: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(windows)]
    let tmp = if private {
        private_tmp_sibling(path)?
    } else {
        tmp_sibling(path)
    };
    #[cfg(not(windows))]
    let tmp = tmp_sibling(path);

    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        // `mode` applies only when this call creates the file. O_NOFOLLOW
        // also prevents a predictable stale temp name from being replaced
        // with a symlink to another operator file.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = private;

    #[cfg(windows)]
    let file = if private {
        crate::wal::win_native::create_private_file_new(&tmp)?
    } else {
        options.open(&tmp)?
    };
    #[cfg(not(windows))]
    let file = options.open(&tmp)?;
    let mut staged = AtomicTemp::new(tmp, file);

    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        // A temp file can survive a crash and later be reused after PID
        // reuse. Narrow an existing file before writing secrets; relying
        // on OpenOptionsExt::mode alone would leave its old mode intact.
        staged
            .file_mut()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    if private {
        crate::wal::win_native::verify_private_file_handle(staged.file())?;
    }
    staged.file_mut().write_all(bytes)?;
    staged.file_mut().flush()?;
    // Durability: the bytes must hit disk before the rename so a crash
    // between rename and the next fsync can't leave a renamed-but-empty file.
    staged.file_mut().sync_all()?;

    #[cfg(windows)]
    if private {
        crate::wal::win_native::replace_private_file_handle(staged.file(), path)?;
        staged.disarm();
        staged.close();
    } else {
        staged.close();
        std::fs::rename(staged.path(), path)?;
        staged.disarm();
    }
    #[cfg(not(windows))]
    {
        staged.close();
        std::fs::rename(staged.path(), path)?;
        staged.disarm();
    }
    // GR-088 — fsync the PARENT directory so the new directory entry created by
    // the rename is durable. The file's DATA was fsynced above, but on POSIX the
    // rename only updates the parent inode's metadata, which survives a power
    // loss only once the directory itself is fsynced. Best-effort + Unix-only
    // (on Windows the rename is journalled, and opening a directory as a File to
    // fsync it isn't valid).
    #[cfg(unix)]
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

struct AtomicTemp {
    path: Option<PathBuf>,
    file: Option<std::fs::File>,
}

impl AtomicTemp {
    fn new(path: PathBuf, file: std::fs::File) -> Self {
        Self {
            path: Some(path),
            file: Some(file),
        }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("atomic temp path is present")
    }

    #[cfg(windows)]
    fn file(&self) -> &std::fs::File {
        self.file.as_ref().expect("atomic temp file is present")
    }

    fn file_mut(&mut self) -> &mut std::fs::File {
        self.file.as_mut().expect("atomic temp file is present")
    }

    fn close(&mut self) {
        drop(self.file.take());
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for AtomicTemp {
    fn drop(&mut self) {
        // Secure Windows handles deny delete sharing; close first so every
        // write/flush/sync/commit error can remove its unpublished stage.
        self.close();
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(windows)]
fn private_tmp_sibling(path: &Path) -> std::io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| std::io::Error::other(format!("private temp RNG unavailable: {error}")))?;
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{}.tmp", hex::encode(nonce)));
    Ok(path.with_file_name(name))
}

/// The pid-scoped temp sibling for `path` (`<name>.<pid>.tmp` in the SAME
/// directory, so the rename stays on one filesystem and is therefore atomic).
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_bytes_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.txt");
        atomic_write(&target, b"hello world").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello world");
        // The temp sibling must be gone after a successful rename.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no .tmp file may survive a successful write"
        );
    }

    #[test]
    fn overwrites_existing_target_without_a_no_file_window() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.txt");
        std::fs::write(&target, b"old contents").unwrap();
        atomic_write(&target, b"new").unwrap();
        // The target file always existed (rename replaces in place); no
        // remove-then-rename gap. Content is the new bytes.
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested").join("deep").join("out.txt");
        atomic_write(&target, b"x").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"x");
    }

    #[test]
    fn durable_remove_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.txt");
        std::fs::write(&target, b"old").unwrap();

        durable_remove_file(&target).unwrap();
        assert!(!target.exists());
        let before_retry = required_parent_sync_attempts_for_test();
        durable_remove_file(&target).unwrap();
        assert!(
            required_parent_sync_attempts_for_test() > before_retry,
            "an absent target under an existing parent must retry the durability barrier"
        );
    }

    #[test]
    fn required_parent_sync_accepts_an_existing_parent() {
        let dir = tempfile::tempdir().unwrap();
        sync_parent_directory_required(&dir.path().join("transaction.json")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn required_parent_sync_propagates_a_missing_parent() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("missing-parent").join("transaction.json");
        assert!(
            sync_parent_directory_required(&target).is_err(),
            "a required durability boundary must not discard parent-open errors"
        );
    }

    #[test]
    fn private_write_cleans_stage_when_commit_fails() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("occupied");
        std::fs::create_dir(&target).unwrap();

        assert!(atomic_write_private(&target, b"must-not-land").is_err());
        assert!(
            target.is_dir(),
            "failed commit must preserve the old target"
        );
        assert!(
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp")),
            "failed private commit left a staged file behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_write_replaces_weak_target_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("private.json");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write_private(&target, b"new").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_write_narrows_a_reused_weak_temp_before_rename() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("private.json");
        let tmp = tmp_sibling(&target);
        std::fs::write(&tmp, b"stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write_private(&target, b"secret").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(windows)]
    #[test]
    fn private_write_sets_and_verifies_current_user_only_dacl() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("private.json");

        atomic_write_private(&target, b"secret").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
        crate::wal::win_native::verify_private_dacl(&target).unwrap();
    }
}
