//! PID file — Phase 33c BS-12.
//!
//! Single-instance lock. `neoth serve` writes `~/.neoth/neothd.pid` on
//! start and removes it on clean shutdown. A second `neoth serve` checks
//! for the file and refuses to start if the recorded PID is alive.
//!
//! Stale-PID handling: when the file exists but the process is gone (OS
//! killed it, crash, reboot), the new daemon takes over and overwrites
//! the file. We never refuse to start just because a stale file exists.
//!
//! Pattern matches the canonical UNIX daemon convention without the
//! `flock` syscall — Windows has no equivalent and we want one code path.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::FreedomConfig;

/// `~/.neoth/neothd.pid`.
pub fn default_pidfile() -> PathBuf {
    FreedomConfig::default_neoth_home().join("neothd.pid")
}

/// Result of an [`acquire`] attempt.
pub struct PidGuard {
    path: PathBuf,
}

impl PidGuard {
    /// Path of the PID file this guard owns.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidGuard {
    /// Remove the PID file on clean shutdown. Errors are swallowed — the
    /// process is going away anyway, and a leftover file would only cause
    /// a single warning at next start (stale-PID path).
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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

/// Acquire the daemon-singleton lock by writing the current PID to `path`.
///
/// Returns `Err` if a live PID is already recorded — the operator has a
/// running daemon they probably didn't mean to start a second copy of.
/// Stale-PID files (process gone) are overwritten silently.
pub fn acquire(path: &Path) -> Result<PidGuard> {
    if path.exists() {
        match read_pid(path) {
            Ok(other) => {
                if pid_is_alive(other) {
                    anyhow::bail!(
                        "another neothd is already running (PID {other}, file {}). \
                         Stop it first or remove the PID file if you're sure.",
                        path.display(),
                    );
                }
                tracing::warn!(
                    stale_pid = other,
                    path = %path.display(),
                    "stale neothd.pid found; taking over the lock",
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not parse existing PID file; overwriting");
            }
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create pidfile dir {}", parent.display()))?;
    }

    let pid = std::process::id();
    std::fs::write(path, format!("{pid}\n"))
        .with_context(|| format!("write pidfile {}", path.display()))?;
    Ok(PidGuard {
        path: path.to_path_buf(),
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
fn pid_is_alive(pid: u32) -> bool {
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
    fn acquire_rejects_when_live_pid_present() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neothd.pid");
        // Write the current process's PID — it's always alive.
        std::fs::write(&path, format!("{}\n", std::process::id())).unwrap();
        let r = acquire(&path);
        assert!(r.is_err(), "must refuse when our own PID is recorded");
        // File must NOT be removed when acquisition fails.
        assert!(
            path.exists(),
            "acquire failure must not delete the existing file"
        );
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
        let p = default_pidfile();
        assert!(p.to_string_lossy().contains(".neoth"));
        assert_eq!(p.file_name().and_then(|s| s.to_str()), Some("neothd.pid"),);
    }
}
