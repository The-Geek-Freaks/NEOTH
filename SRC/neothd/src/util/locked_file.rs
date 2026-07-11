//! Cross-process advisory file locking (WAL-QUOTA / CREDENTIAL / MCP / COUNCIL
//! fail-closed RMW primitive — B17/B18/B25).
//!
//! Several config stores (`credentials.yaml`, `mcp_servers.yaml`, the council
//! day-counter log) are read-modify-written by BOTH the daemon and separate
//! `neoth …` CLI processes. Atomic `.tmp`+rename (see [`crate::util::atomic_write`])
//! prevents torn *reads*, but not a lost *update* when two processes each
//! `load → mutate → write` concurrently. This module provides the missing
//! cross-process tier: an OS advisory lock on a sibling `*.lock` file.
//!
//! The two-tier pattern (mutex-first, then this file lock) is documented on
//! `cluster::registry` — this is a generic, verbatim extraction of that
//! module's `lock_registry_file` / `try_lock_registry_file` so every store
//! shares one audited implementation instead of copy-pasting the unsafe
//! `flock`/`share_mode` code per module.
//!
//! No new dependencies: `libc` is already a `cfg(unix)` dep and
//! `std::os::windows::fs::OpenOptionsExt` is std. Built on the MSRV-1.86-safe
//! primitives used by `daemon::pidfile` (std `File::lock` needs 1.89):
//! non-blocking acquire retried every 50 ms, failing loudly after 5 s instead
//! of deadlocking on a stuck holder.
//!
//! Callers still keep their own process-local `static … : Mutex<()>` and take
//! it FIRST (mutex-first ordering) so same-process writers serialise by parking
//! on the mutex rather than all spinning on the file lock — see the
//! `cluster::registry` rationale for why file-first order flaked under load.

use std::path::Path;

use anyhow::{Context, Result};

const RETRY_EVERY: std::time::Duration = std::time::Duration::from_millis(50);
const GIVE_UP_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

/// Bounded-blocking exclusive OS lock on `lock_path`. Dropping the returned
/// handle releases the lock. `what` names the store for error messages.
///
/// Creates the parent directory if missing. Retries a non-blocking acquire
/// every 50 ms and fails loudly after 5 s (a stuck holder is a bug, not a
/// reason to deadlock). The lock is advisory — it only excludes other callers
/// that go through this same lock path, which every write path in a given store
/// does.
pub fn lock_file_blocking(lock_path: &Path, what: &str) -> Result<std::fs::File> {
    if let Some(parent) = lock_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {what} lock dir {}", parent.display()))?;
        }
    }
    let started = std::time::Instant::now();
    loop {
        if let Some(f) = try_lock_file_once(lock_path, what)? {
            return Ok(f);
        }
        if started.elapsed() >= GIVE_UP_AFTER {
            anyhow::bail!(
                "{what} lock {} held by another process for >5s — is a stuck \
                 `neoth` invocation or daemon write hanging?",
                lock_path.display()
            );
        }
        std::thread::sleep(RETRY_EVERY);
    }
}

/// One non-blocking exclusive-acquire attempt on `lock_path`.
/// `Ok(Some(file))` = acquired (drop releases); `Ok(None)` = currently held
/// elsewhere; `Err` = real I/O failure. Windows excludes via
/// `share_mode(FILE_SHARE_READ)` at open (a second write-open hits
/// ERROR_SHARING_VIOLATION); Unix via advisory `flock(LOCK_EX | LOCK_NB)`.
pub(crate) fn try_lock_file_once(lock_path: &Path, what: &str) -> Result<Option<std::fs::File>> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const ERROR_SHARING_VIOLATION: i32 = 32;
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ)
            .open(lock_path)
        {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(e) => Err(e).with_context(|| format!("open {what} lock file {}", lock_path.display())),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .with_context(|| format!("open {what} lock file {}", lock_path.display()))?;
        // SAFETY: plain flock syscall on a valid owned fd.
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            Ok(Some(f))
        } else {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e).with_context(|| format!("flock {}", lock_path.display()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquired_then_released_allows_second_acquire() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("thing.lock");
        {
            let _h = lock_file_blocking(&lock, "thing").unwrap();
            // While held, a non-blocking attempt from the same lock path must
            // report held-elsewhere OR acquired depending on OS reentrancy;
            // the contract we assert is that after drop, re-acquire succeeds.
        }
        // Handle dropped → lock released → re-acquire must succeed quickly.
        let _h2 = lock_file_blocking(&lock, "thing").unwrap();
    }

    #[test]
    fn lock_dir_is_created() {
        let dir = tempfile::tempdir().unwrap();
        // Nested, not-yet-existing parent.
        let lock = dir.path().join("sub").join("nested").join("x.lock");
        let _h = lock_file_blocking(&lock, "nested").unwrap();
        assert!(lock.exists(), "lock file (and its parent dir) must be created");
    }

    #[test]
    fn real_io_error_propagates() {
        // A lock path whose parent is a FILE (not a dir) cannot be created:
        // create_dir_all on it fails with a real I/O error, not Ok(None).
        let dir = tempfile::tempdir().unwrap();
        let file_as_parent = dir.path().join("iamafile");
        std::fs::write(&file_as_parent, b"x").unwrap();
        let lock = file_as_parent.join("child.lock");
        let r = lock_file_blocking(&lock, "bad");
        assert!(r.is_err(), "creating a lock under a file-parent must error, not spin");
    }
}
