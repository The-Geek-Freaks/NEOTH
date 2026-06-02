//! PC-01 (app-launch slice): the thin spawn primitive behind the gated
//! [`crate::os_tools::gate::launch_os_app`].
//!
//! Deliberately minimal + dumb on purpose — ALL the security lives in the gate
//! (exec-allowlist + autonomy + audit) that runs BEFORE this is ever called:
//!   - **No shell.** `Command::new(program)` execs the binary directly via
//!     `argv[0]`; there is no `sh -c`, so shell metacharacters in a (future)
//!     argument can never be expanded into a different command.
//!   - **No arguments** in this slice. An allowlisted binary is launched bare;
//!     passing operator-supplied args (with a per-program arg policy) is a
//!     separate follow-on slice precisely because args can turn a benign binary
//!     into an arbitrary command.
//!   - **Detached stdio.** stdin/stdout/stderr are redirected to null so a
//!     launched program can neither read from nor write into NEOTH's own
//!     streams (critical: the daemon emits machine-readable JSON on stdout for
//!     the GUI bridge — an inherited child writing there would corrupt it).
//!
//! Fire-and-forget: the [`std::process::Child`] handle is dropped, so we do not
//! wait on or reap the launched process. For the one-shot `neoth os launch`
//! CLI this is correct (the CLI exits immediately and the OS reparents the
//! child). Daemon-side launch with proper child reaping is a follow-on.

use std::path::Path;
use std::process::{Command, Stdio};

/// Spawn `program` with no arguments, no shell, and detached stdio. Returns the
/// launched process id on success. The caller MUST have already cleared
/// `program` through the exec-allowlist + autonomy gate.
pub fn launch_program(program: &Path) -> std::io::Result<u32> {
    let child = Command::new(program)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = child.id();
    // TODO(daemon-launch): the Child is dropped without wait() — harmless for
    // the one-shot CLI (the process exits and init/parent reaps), but a
    // long-lived daemon launching many programs would accumulate zombies on
    // Unix. Before wiring a daemon-side launch path, switch to
    // tokio::process::Command and retain the handle for .try_wait() reaping.
    drop(child);
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test the spawn path against a real, argument-free, instantly
    /// exiting system binary. Platform-specific because there is no single
    /// cross-OS arg-free instant-exit executable.
    #[cfg(unix)]
    #[test]
    fn launches_true_and_returns_pid() {
        // `/bin/true` exists on every POSIX system, takes no args, exits 0,
        // and writes nothing — a clean spawn target.
        let pid = launch_program(Path::new("/bin/true")).expect("spawn /bin/true");
        assert!(pid > 0);
    }

    #[cfg(windows)]
    #[test]
    fn launches_whoami_and_returns_pid() {
        // `whoami.exe` lives in System32, takes no args, exits quickly, and
        // (with stdio nulled) writes nothing to our streams.
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let exe = std::path::PathBuf::from(sys)
            .join("System32")
            .join("whoami.exe");
        if exe.is_file() {
            let pid = launch_program(&exe).expect("spawn whoami.exe");
            assert!(pid > 0);
        }
    }

    #[test]
    fn launching_a_nonexistent_program_errors() {
        let r = launch_program(Path::new("/this/does/not/exist/neoth-ghost-binary"));
        assert!(r.is_err());
    }
}
