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
//! process no longer blocks startup) and the stale-file problem (the lock
//! auto-releases when the holder dies, even on a crash).
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
use std::io::Write;
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
    /// The locked PID file. `Option` so [`Drop`] can close the handle
    /// (releasing the lock) BEFORE removing the file — Windows refuses to
    /// delete a file that still has an open handle without share-delete.
    lock: Option<File>,
}

impl PidGuard {
    /// Path of the PID file this guard owns.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidGuard {
    /// Release the lock + remove the PID file on clean shutdown. The handle
    /// is dropped first so the unlink succeeds on Windows. Errors are
    /// swallowed — the process is going away anyway, and a leftover file is
    /// harmless (the next start re-locks it and overwrites).
    fn drop(&mut self) {
        self.lock.take();
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
            .open(path)?;
        Ok(Some(f))
    }
}

/// Check whether a live daemon currently owns the lock at `path`.
/// Pure read — no side effects. Returns `Ok(Some(pid))` when an alive
/// pid sits in the file, `Ok(None)` otherwise (missing / stale / un-
/// parseable). Callers like `neoth ingest` use this to avoid racing
/// WAL writes against a live daemon.
pub fn live_daemon_pid(path: &Path) -> Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }
    let pid = match read_pid(path) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    if pid_is_alive(pid) {
        Ok(Some(pid))
    } else {
        Ok(None)
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
    })
}

fn read_pid(path: &Path) -> Result<u32> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read pidfile {}", path.display()))?;
    let trimmed = body.trim();
    trimmed.parse::<u32>().with_context(|| {
        format!(
            "pidfile {} contains non-numeric body: {:?}",
            path.display(),
            trimmed
        )
    })
}

/// Is the process with this PID currently alive?
///
/// `unix`: `kill(pid, 0)` returns 0 if the process exists (errno ESRCH if not).
/// `windows`: OpenProcess + GetExitCodeProcess — but to avoid a `windows` crate
/// dependency we shell out to `tasklist /FI "PID eq <pid>"` and grep for the PID.
/// The subprocess approach is the same shape as `win_acl::icacls` (see D-008).
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
        use std::process::Command;
        let out = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output();
        match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                // tasklist returns "INFO: No tasks are running which match..." when not found.
                s.contains(&pid.to_string())
            }
            Err(_) => false,
        }
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

    #[test]
    fn drop_removes_pidfile() {
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
    fn lock_releases_on_drop_so_next_acquire_succeeds() {
        // Dropping the guard releases the OS lock; a fresh acquire then wins.
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        {
            let _g = acquire(&path).expect("first acquire");
        } // guard dropped → lock released + file removed
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
        // Reads the process-global NEOTH_HOME via default_pidfile();
        // take the env lock so a concurrent setter (cli::mode tests)
        // can't swap NEOTH_HOME to a tempdir mid-read. See
        // crate::test_env.
        let _env = crate::test_env::lock();
        let p = default_pidfile();
        assert!(p.to_string_lossy().contains(".neoth"));
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("neothd.pid"),);
    }
}
