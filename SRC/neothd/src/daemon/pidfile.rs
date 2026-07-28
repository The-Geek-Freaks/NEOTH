//! PID file — Phase 33c BS-12; TOCTOU-hardened in GOLD-COR-16.
//!
//! Single-instance lock. `neoth serve` takes an **exclusive OS-level lock**
//! on `~/.neoth/neothd.pid`, writes its PID into the file, and holds the
//! lock for the daemon's lifetime. A second `neoth serve` fails to take the
//! lock and refuses to start.
//!
//! ## Why a real lock (COR-16 / A-16)
//!
//! The old design did check-`exists` → read-PID → `pid_is_alive` → **then**
//! write — a TOCTOU window: two `neoth serve` started at the same instant
//! both saw "no live PID" and both wrote their PID, ending up with two
//! daemons writing the same WAL (frame corruption). The lock makes
//! acquisition atomic: only one process can hold it. It also removes the
//! PID-recycling false-positive (a stale PID reused by an unrelated live
//! process no longer blocks startup). The lock auto-releases when the holder
//! dies, even on a crash; Unix deliberately retains the stable lock inode so a
//! departing owner can never unlink a successor's newly acquired lock path.
//!
//! ## Cross-platform, dependency-free, readers stay un-blocked
//!
//! - **unix**: `flock(LOCK_EX | LOCK_NB)` on the open fd (advisory — does
//!   not block `read_to_string`, so [`live_daemon_pid`] readers still work).
//!   `libc` is already a dependency (see [`pid_is_alive`]).
//! - **windows**: open with `share_mode(FILE_SHARE_READ)` — a second daemon
//!   opening for WRITE hits `ERROR_SHARING_VIOLATION`, while read-only
//!   openers (readers) are still permitted by the shared read.
//!
//! The PID content is now informational (readers + a friendly "already
//! running" message); the lock, not the content, is the source of truth.

use std::fs::{File, OpenOptions};
use std::io::{Seek as _, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::FreedomConfig;

/// `~/.neoth/neothd.pid`.
pub fn default_pidfile() -> PathBuf {
    FreedomConfig::default_neoth_home().join("neothd.pid")
}

/// Result of an [`acquire`] attempt. Holds the locked file open for the
/// daemon's lifetime — dropping the guard releases the OS lock (also
/// automatic on process death, even a crash).
pub struct PidGuard {
    path: PathBuf,
    /// The locked PID file. `Option` lets [`Drop`] release the handle before
    /// Windows performs its best-effort cleanup. Unix retains the stable path
    /// and inode across owners to avoid an unlock-then-unlink race.
    lock: Option<File>,
    endpoint_published: bool,
}

impl PidGuard {
    /// Path of the PID file this guard owns.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Publish the discovery nonce for the daemon's mandatory internal RPC
    /// endpoint while this exact PID-file lock is still held. The endpoint
    /// sidecar is written first; this fsynced second line is the commit point
    /// that makes the sidecar usable by clients.
    pub(crate) fn publish_endpoint_nonce(&mut self, nonce: &str) -> Result<()> {
        if nonce.len() != 32
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            anyhow::bail!("daemon endpoint nonce must be 32 lowercase hex characters");
        }
        if self.endpoint_published {
            anyhow::bail!("daemon endpoint nonce was already published for this PID lock");
        }
        let file = self
            .lock
            .as_mut()
            .context("daemon PID lock is no longer held")?;
        // `acquire` leaves the file as exactly `PID\n`. Append the nonce
        // instead of truncating/re-writing: `live_daemon_pid` must never see
        // an empty first line and incorrectly conclude that no daemon owns the
        // WAL during endpoint publication. A reader may see a partial nonce,
        // which merely keeps endpoint discovery unavailable until sync.
        file.seek(SeekFrom::End(0))
            .with_context(|| format!("seek pidfile {}", self.path.display()))?;
        file.write_all(format!("{nonce}\n").as_bytes())
            .with_context(|| format!("publish daemon endpoint nonce {}", self.path.display()))?;
        file.flush()
            .with_context(|| format!("flush pidfile {}", self.path.display()))?;
        file.sync_data()
            .with_context(|| format!("sync pidfile {}", self.path.display()))?;
        self.endpoint_published = true;
        Ok(())
    }
}

impl Drop for PidGuard {
    /// Release the lock on clean shutdown.
    ///
    /// Unix must not unlink after releasing `flock`: a successor can acquire
    /// the same inode between unlock and unlink, after which deleting the path
    /// would make ownership probes miss that live daemon and let a third
    /// process create a second lock inode. The next owner safely re-locks and
    /// truncates the retained file. Windows may clean up after closing because
    /// a successor opens without share-delete, so `remove_file` cannot delete
    /// a live successor's path. Cleanup errors are harmless.
    fn drop(&mut self) {
        // Invalidate this incarnation's discovery tuple while its lock is
        // still authoritative. Without this ordering a cleanly-shutting-down
        // process can remain alive long enough for a successor to acquire the
        // stable inode, while readers still observe the predecessor's PID and
        // endpoint nonce.
        if let Some(file) = self.lock.as_mut()
            && let Err(error) = file
                .set_len(0)
                .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
                .and_then(|()| file.flush())
                .and_then(|()| file.sync_data())
        {
            tracing::warn!(
                path = %self.path.display(),
                error = %error,
                "failed to invalidate daemon pidfile before releasing its ownership lock"
            );
        }
        self.lock.take();
        #[cfg(windows)]
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Open `path` (creating it if absent) and take an exclusive, non-blocking
/// lock. Returns `Ok(Some(file))` when WE acquired the lock, `Ok(None)`
/// when another process already holds it, and `Err` on a real I/O failure.
/// The returned handle must stay open for as long as the lock is wanted.
fn open_exclusive(path: &Path) -> std::io::Result<Option<File>> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ only: deny other writers (a second daemon's
        // write-open fails) while still letting read-only openers in.
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const ERROR_SHARING_VIOLATION: i32 = 32;
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ)
            .open(path)
        {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(e) => Err(e),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        // Advisory flock: non-blocking exclusive. EWOULDBLOCK ⇒ held by
        // another open file description (another daemon).
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            Ok(Some(f))
        } else {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        // No lock primitive on this platform — plain create, no exclusion
        // (operator risk, same posture as `pid_is_alive`'s fallback).
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        Ok(Some(f))
    }
}

enum ExistingLockState {
    Missing,
    Held,
    Available(File),
}

/// Probe the existing PID-file lock without creating or modifying the file.
/// A successful `Available` handle owns the lock until dropped.
fn probe_existing_lock(path: &Path) -> std::io::Result<ExistingLockState> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const ERROR_SHARING_VIOLATION: i32 = 32;
        match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
        {
            Ok(file) => Ok(ExistingLockState::Available(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ExistingLockState::Missing)
            }
            Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
                Ok(ExistingLockState::Held)
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd as _;
        let file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ExistingLockState::Missing);
            }
            Err(error) => return Err(error),
        };
        // SAFETY: `file` is an owned live descriptor and remains open for the
        // entire non-blocking flock call.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            Ok(ExistingLockState::Available(file))
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                Ok(ExistingLockState::Held)
            } else {
                Err(error)
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => Ok(ExistingLockState::Available(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ExistingLockState::Missing)
            }
            Err(error) => Err(error),
        }
    }
}

/// Check whether a live daemon currently owns the lock at `path`.
/// Pure read/lock probe — no file creation or content mutation. Returns
/// `Ok(Some(pid))` only when the OS lock is held and its PID is valid and
/// alive. Missing and unlocked stale files return `Ok(None)`. A held but
/// unreadable, malformed, or dead-PID file fails closed.
pub fn live_daemon_pid(path: &Path) -> Result<Option<u32>> {
    live_daemon_pid_with_hook(path, || {})
}

fn live_daemon_pid_with_hook(path: &Path, after_initial_pid: impl FnOnce()) -> Result<Option<u32>> {
    match probe_existing_lock(path)
        .with_context(|| format!("probe daemon pidfile lock {}", path.display()))?
    {
        ExistingLockState::Missing => Ok(None),
        ExistingLockState::Available(lock) => {
            drop(lock);
            Ok(None)
        }
        ExistingLockState::Held => {
            let pid =
                read_pid(path).context("daemon PID lock is held but its owner is unreadable")?;
            if !pid_is_alive(pid) {
                anyhow::bail!(
                    "daemon PID lock is held, but recorded PID {pid} is not alive at {}",
                    path.display()
                );
            }
            after_initial_pid();
            match probe_existing_lock(path)
                .with_context(|| format!("revalidate daemon pidfile lock {}", path.display()))?
            {
                ExistingLockState::Held => {}
                ExistingLockState::Missing | ExistingLockState::Available(_) => return Ok(None),
            }
            let revalidated_pid =
                read_pid(path).context("re-read daemon PID after lock revalidation")?;
            if pid != revalidated_pid {
                return Ok(None);
            }
            match probe_existing_lock(path)
                .with_context(|| format!("finalize daemon pidfile lock proof {}", path.display()))?
            {
                // The prior owner can exit and a successor can acquire the
                // stable lock inode between probes. Require the same PID
                // sandwiched by Held observations, then recheck the recorded
                // process after the final observation. The endpoint nonce may
                // legitimately be appended while this PID remains the owner.
                ExistingLockState::Held if pid_is_alive(pid) => Ok(Some(pid)),
                ExistingLockState::Held => Ok(None),
                ExistingLockState::Missing | ExistingLockState::Available(_) => Ok(None),
            }
        }
    }
}

/// Verify the exact endpoint discovery tuple committed by the process that
/// currently holds the daemon PID-file lock.
pub(crate) fn live_daemon_endpoint(
    path: &Path,
    expected_pid: u32,
    expected_nonce: &str,
) -> Result<bool> {
    live_daemon_endpoint_with_hook(path, expected_pid, expected_nonce, || {})
}

fn live_daemon_endpoint_with_hook(
    path: &Path,
    expected_pid: u32,
    expected_nonce: &str,
    after_initial_snapshot: impl FnOnce(),
) -> Result<bool> {
    match probe_existing_lock(path)
        .with_context(|| format!("probe daemon pidfile lock {}", path.display()))?
    {
        ExistingLockState::Missing | ExistingLockState::Available(_) => return Ok(false),
        ExistingLockState::Held => {}
    }
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("read pidfile {}", path.display()));
        }
    };
    let mut lines = body.lines();
    let pid = lines
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .context("daemon pidfile has no valid PID")?;
    let nonce = lines
        .next()
        .context("daemon pidfile has no endpoint nonce")?;
    if lines.any(|line| !line.is_empty()) {
        anyhow::bail!("daemon pidfile has unexpected trailing content");
    }
    if pid != expected_pid || nonce != expected_nonce || !pid_is_alive(pid) {
        return Ok(false);
    }
    after_initial_snapshot();
    match probe_existing_lock(path)
        .with_context(|| format!("revalidate daemon pidfile lock {}", path.display()))?
    {
        ExistingLockState::Held => {}
        ExistingLockState::Missing | ExistingLockState::Available(_) => return Ok(false),
    }
    let revalidated_body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("re-read pidfile after lock proof {}", path.display()));
        }
    };
    if revalidated_body != body {
        return Ok(false);
    }
    match probe_existing_lock(path)
        .with_context(|| format!("finalize daemon endpoint lock proof {}", path.display()))?
    {
        ExistingLockState::Held => Ok(pid_is_alive(pid)),
        ExistingLockState::Missing | ExistingLockState::Available(_) => Ok(false),
    }
}

/// Acquire the daemon-singleton lock at `path`.
///
/// Takes an exclusive OS lock on the PID file (atomic — closes the
/// check-then-write TOCTOU), then writes the current PID into it. Returns
/// `Err` when another process already holds the lock (a daemon is running);
/// a stale file from a crashed daemon is re-locked and overwritten silently
/// because the OS released the dead process's lock.
pub fn acquire(path: &Path) -> Result<PidGuard> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create pidfile dir {}", parent.display()))?;
    }

    let mut file = match open_exclusive(path)
        .with_context(|| format!("open + lock pidfile {}", path.display()))?
    {
        Some(f) => f,
        None => {
            // Another daemon holds the lock. Best-effort read of the PID
            // for a helpful message (the lock, not the content, is truth).
            let who = read_pid(path)
                .map(|p| p.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            anyhow::bail!(
                "another neothd is already running (PID {who}, file {}). \
                 Stop it first or remove the PID file if you're sure.",
                path.display(),
            );
        }
    };

    // We hold the lock. Truncate any stale content from a prior owner and
    // write our PID (informational — readers + the message above).
    let pid = std::process::id();
    file.set_len(0)
        .with_context(|| format!("truncate pidfile {}", path.display()))?;
    file.write_all(format!("{pid}\n").as_bytes())
        .with_context(|| format!("write pidfile {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush pidfile {}", path.display()))?;

    Ok(PidGuard {
        path: path.to_path_buf(),
        lock: Some(file),
        endpoint_published: false,
    })
}

fn read_pid(path: &Path) -> Result<u32> {
    read_pid_snapshot(path).map(|(_, pid)| pid)
}

fn read_pid_snapshot(path: &Path) -> Result<(String, u32)> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read pidfile {}", path.display()))?;
    let first_line = body.lines().next().unwrap_or_default();
    let pid = first_line.parse::<u32>().with_context(|| {
        format!(
            "pidfile {} contains non-numeric PID line: {:?}",
            path.display(),
            first_line
        )
    })?;
    Ok((body, pid))
}

/// Is the process with this PID currently alive?
///
/// `unix`: `kill(pid, 0)` returns 0 if the process exists (errno ESRCH if not).
/// `windows`: `OpenProcess` + `GetExitCodeProcess`. Native Win32 avoids locale-
/// dependent `tasklist` output and restricted shells where spawning `tasklist`
/// is denied even for the current process.
///
/// `pub(crate)` so the AUDIT-RPC-01 client can reject a stale sidecar (a
/// crashed daemon's port may have been recycled by another local process —
/// sending the bearer token there would disclose it).
pub(crate) fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // libc::kill with signal 0 = existence check. Returns 0 on success.
        // EPERM (process exists but we lack permission) also means "alive".
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true;
        }
        // Treat anything other than ESRCH as "alive but inaccessible".
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, GetLastError, STILL_ACTIVE,
        };
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        if pid == 0 {
            return false;
        }

        // SAFETY: `pid` is a value read from a local sidecar/pidfile. The
        // returned handle is checked for null and closed exactly once below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            // Access denied still proves that a process owns the PID (for
            // example a protected system process), matching Unix EPERM.
            // Other errors are fail-closed for audit-RPC token disclosure.
            return unsafe { GetLastError() } == ERROR_ACCESS_DENIED;
        }

        let mut exit_code = 0u32;
        // SAFETY: `handle` is a live process handle and `exit_code` points to
        // writable storage for the duration of the call.
        let queried = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        // SAFETY: this function owns the successful `OpenProcess` handle.
        let _ = unsafe { CloseHandle(handle) };
        queried != 0 && exit_code == STILL_ACTIVE as u32
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Unknown platform: assume not alive (lets daemon start). Daemons
        // on platforms NEOTH doesn't officially support are operator-risk.
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn acquire_writes_current_pid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let _guard = acquire(&path).expect("acquire");
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.trim().parse::<u32>().unwrap(), std::process::id());
    }

    #[cfg(unix)]
    #[test]
    fn drop_retains_the_stable_unix_lock_inode() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let first_inode;
        {
            let _guard = acquire(&path).expect("acquire");
            assert!(path.exists());
            first_inode = std::fs::metadata(&path).unwrap().ino();
        }
        assert!(
            path.exists(),
            "Unix guard drop must retain the stable lock path"
        );
        let _next = acquire(&path).expect("the retained inode must be re-lockable");
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            first_inode,
            "a successor must lock the same path identity, not a replacement inode"
        );
    }

    #[cfg(windows)]
    #[test]
    fn drop_removes_pidfile_when_the_platform_cleanup_is_race_safe() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        {
            let _guard = acquire(&path).expect("acquire");
            assert!(path.exists());
        }
        assert!(!path.exists(), "guard drop must remove pidfile");
    }

    #[test]
    fn acquire_rejects_when_another_holds_the_lock() {
        // COR-16: a real running daemon HOLDS the OS lock — that, not the
        // PID content, is what a second acquire must trip over. (Within one
        // process, two separate opens still contend: distinct open file
        // descriptions on unix; a sharing violation on windows.)
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let _held = acquire(&path).expect("first acquire takes the lock");
        let second = acquire(&path);
        assert!(
            second.is_err(),
            "second acquire must be refused while the lock is held"
        );
        // The holder's pidfile must survive the failed second attempt.
        assert!(
            path.exists(),
            "failed acquire must not delete the holder's file"
        );
    }

    #[test]
    fn live_daemon_pid_reads_through_held_lock() {
        // COR-16 invariant: the lock must NOT block readers. While a guard
        // holds the file, `live_daemon_pid` (used by `neoth ingest` to avoid
        // racing WAL writes) must still read the PID — unix flock is
        // advisory; windows `share_mode(FILE_SHARE_READ)` permits read-only
        // openers.
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let _held = acquire(&path).expect("acquire");
        let live = live_daemon_pid(&path).expect("reader must not error on a locked file");
        assert_eq!(
            live,
            Some(std::process::id()),
            "reader must see the holder's PID through the lock"
        );
    }

    #[test]
    fn live_daemon_pid_tolerates_endpoint_publish_by_the_same_owner() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let mut held = acquire(&path).expect("acquire");
        let live = live_daemon_pid_with_hook(&path, || {
            held.publish_endpoint_nonce("00112233445566778899aabbccddeeff")
                .unwrap();
        })
        .unwrap();
        assert_eq!(
            live,
            Some(std::process::id()),
            "publishing the endpoint nonce must not look like a lock-owner transition"
        );
    }

    #[test]
    fn live_daemon_pid_rejects_an_unlocked_file_with_a_reused_live_pid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let body = format!("{}\n", std::process::id());
        std::fs::write(&path, &body).unwrap();

        assert_eq!(
            live_daemon_pid(&path).unwrap(),
            None,
            "live PID text without the OS lock is stale, not daemon ownership"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            body,
            "the ownership probe must not create, truncate, or rewrite pidfiles"
        );
    }

    #[test]
    fn live_daemon_pid_fails_closed_when_held_content_is_partial() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let mut held = open_exclusive(&path).unwrap().unwrap();
        held.set_len(0).unwrap();
        held.seek(SeekFrom::Start(0)).unwrap();
        held.write_all(b"partial").unwrap();
        held.sync_all().unwrap();

        let error =
            live_daemon_pid(&path).expect_err("a held malformed PID cannot mean no daemon writer");
        assert!(format!("{error:#}").contains("lock is held"));
    }

    #[test]
    fn endpoint_discovery_requires_the_exact_fsynced_nonce_and_locked_owner() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let mut held = acquire(&path).expect("acquire");
        let nonce = "00112233445566778899aabbccddeeff";
        assert!(
            !live_daemon_endpoint(&path, std::process::id(), nonce).unwrap_or(false),
            "the PID-only preparation state must not publish an endpoint"
        );
        assert_eq!(live_daemon_pid(&path).unwrap(), Some(std::process::id()));

        held.publish_endpoint_nonce(nonce).unwrap();
        assert_eq!(
            live_daemon_pid(&path).unwrap(),
            Some(std::process::id()),
            "endpoint publication must never hide the live WAL owner"
        );
        assert!(held.publish_endpoint_nonce(nonce).is_err());
        assert!(live_daemon_endpoint(&path, std::process::id(), nonce).unwrap());
        assert!(
            !live_daemon_endpoint(
                &path,
                std::process::id(),
                "ffeeddccbbaa99887766554433221100"
            )
            .unwrap(),
            "a sidecar from another daemon incarnation must not match"
        );
        assert!(
            !live_daemon_endpoint(&path, std::process::id().wrapping_add(1), nonce).unwrap(),
            "the endpoint nonce cannot authorize a different PID"
        );
    }

    #[test]
    fn endpoint_discovery_rejects_a_successor_lock_owner_transition() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let predecessor_nonce = "00112233445566778899aabbccddeeff";
        let successor_nonce = "ffeeddccbbaa99887766554433221100";
        let mut predecessor = acquire(&path).expect("acquire predecessor");
        predecessor
            .publish_endpoint_nonce(predecessor_nonce)
            .unwrap();
        let mut predecessor = Some(predecessor);
        let mut successor = None;

        let accepted =
            live_daemon_endpoint_with_hook(&path, std::process::id(), predecessor_nonce, || {
                drop(predecessor.take());
                let mut next = acquire(&path).expect("successor acquires stable lock inode");
                next.publish_endpoint_nonce(successor_nonce).unwrap();
                successor = Some(next);
            })
            .unwrap();

        assert!(
            !accepted,
            "a Held observation from a successor must not authorize the predecessor's tuple"
        );
        assert!(
            successor.is_some(),
            "successor lock remains held during proof"
        );
    }

    #[test]
    fn endpoint_discovery_rejects_an_unlocked_current_pid_and_nonce() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        let mut held = acquire(&path).expect("acquire");
        let nonce = "0123456789abcdeffedcba9876543210";
        held.publish_endpoint_nonce(nonce).unwrap();
        let stale_body = std::fs::read(&path).unwrap();
        drop(held);

        // Unix deliberately retains the stable inode after invalidating it.
        // Windows removes the released pidfile. Recreate the exact stale tuple
        // on both so the proof cannot pass on text equality alone.
        std::fs::write(&path, stale_body).unwrap();
        assert!(
            !live_daemon_endpoint(&path, std::process::id(), nonce).unwrap(),
            "an exact live PID + nonce without the OS lock is stale, not endpoint authority"
        );
    }

    #[test]
    fn lock_releases_on_drop_so_next_acquire_succeeds() {
        // Dropping the guard releases the OS lock; a fresh acquire then wins.
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        {
            let _g = acquire(&path).expect("first acquire");
        } // guard dropped → lock released; Unix intentionally retains the inode
        let _g2 = acquire(&path).expect("re-acquire after release must succeed");
        assert!(path.exists());
    }

    #[test]
    fn concurrent_acquire_only_one_holds_the_lock() {
        // The TOCTOU regression (A-16): N daemons racing to start must yield
        // exactly ONE lock holder, never two writing the same WAL.
        use std::sync::{Arc, Barrier};
        let dir = tempdir().unwrap();
        let path = Arc::new(dir.path().join("neothd.pid"));
        let n = 8;
        let start = Arc::new(Barrier::new(n));
        let attempted = Arc::new(Barrier::new(n));
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let path = Arc::clone(&path);
                let start = Arc::clone(&start);
                let attempted = Arc::clone(&attempted);
                std::thread::spawn(move || {
                    start.wait();
                    let res = acquire(&path); // winner keeps its guard in `res`
                    let won = res.is_ok();
                    // Hold the winner's lock until EVERY thread has attempted
                    // so contenders genuinely race a held lock.
                    attempted.wait();
                    drop(res);
                    won
                })
            })
            .collect();
        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&won| won)
            .count();
        assert_eq!(wins, 1, "exactly one concurrent acquire may hold the lock");
    }

    #[test]
    fn acquire_takes_over_stale_pidfile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        // PID 1 is unlikely to be unprivileged-user-killable, but we want a
        // PID that definitely isn't OUR process. Pick a clearly invalid
        // large PID — pid_is_alive should return false on most systems.
        let unlikely_pid = 999_999_999u32;
        std::fs::write(&path, format!("{unlikely_pid}\n")).unwrap();
        let _guard = acquire(&path).expect("must take over stale pid");
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.trim().parse::<u32>().unwrap(), std::process::id());
    }

    #[test]
    fn acquire_overwrites_garbage_pidfile() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        std::fs::write(&path, "not a number\n").unwrap();
        let _guard = acquire(&path).expect("must overwrite bad content");
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.trim().parse::<u32>().unwrap(), std::process::id());
    }

    #[test]
    fn default_pidfile_lives_under_neoth_home() {
        // `default_pidfile()` reads the process-global NEOTH_HOME. Taking the
        // env lock is not enough on its own: a sibling test that sets NEOTH_HOME
        // to a tempdir and then DROPS the lock across an `.await` (e.g.
        // `cron::runner`) leaves the var pointing at a tempdir with NO `.neoth`
        // substring while the lock is free — racing this read. So instead of
        // depending on ambient global state, set NEOTH_HOME ourselves under the
        // lock to a path that DOES contain `.neoth`, read, then restore the
        // prior value. Deterministic regardless of any concurrent env mutation.
        let _env = crate::test_env::lock();
        let home = tempdir().unwrap();
        let neoth_home = home.path().join(".neoth");
        let prior = std::env::var_os("NEOTH_HOME");
        // SAFETY: the crate env lock is held for the whole set→read→restore
        // critical section; this is a plain `#[test]` with no `.await`, so the
        // guard never crosses a suspension point.
        unsafe {
            std::env::set_var("NEOTH_HOME", &neoth_home);
        }
        let p = default_pidfile();
        unsafe {
            match prior {
                Some(v) => std::env::set_var("NEOTH_HOME", v),
                None => std::env::remove_var("NEOTH_HOME"),
            }
        }
        assert!(
            p.to_string_lossy().contains(".neoth"),
            "default_pidfile must live under a .neoth dir, got {}",
            p.display()
        );
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("neothd.pid"));
    }
}
