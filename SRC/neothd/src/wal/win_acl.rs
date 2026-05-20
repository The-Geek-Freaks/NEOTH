// Windows DACL restriction for NEOTH files (WAL segments, freedom.yaml, ...).
//
// Approach: invoke `icacls.exe` to grant the current user full control on the
// target file. We do NOT pass `/inheritance:r` — stripping inherited ACEs
// mid-write locks the daemon's own threads out of the file it just opened.
// Operators who need full sealing run `icacls "%USERPROFILE%\.neoth\" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"`
// once after `neoth init`. See SECURITY.md.
//
// icacls ships with every Windows install since XP and is significantly
// simpler than the equivalent unsafe Win32 wiring (OpenProcessToken +
// GetTokenInformation + InitializeAcl + AddAccessAllowedAce +
// SetNamedSecurityInfoW). The cost is one subprocess per restricted file,
// which is acceptable for WAL segments (rotated occasionally) and config
// files (written once).
//
// Security: USERNAME is validated against `[A-Za-z0-9._\- ]` before being
// passed to icacls. Without this, a hostile `USERNAME=foo" /grant Everyone:F`
// value could inject extra icacls arguments through CreateProcessW's
// command-line construction.
//
// Caveats:
//   - Race window: file exists briefly with inherited DACL between
//     OpenOptions::open() and this call. For freedom.yaml this is mitigated
//     by `umask`-equivalent OpenOptions on unix. On Windows the only fix is
//     CreateFileW with SECURITY_ATTRIBUTES — tracked for v0.5.
//   - %USERNAME% must be set. NEOTH startup ensures this; if missing or
//     malformed the call degrades gracefully to a logged warning.
//   - The subprocess call is wrapped in `tokio::task::spawn_blocking` when
//     called from async contexts (see `restrict_to_owner_async`).

#![cfg(windows)]

use std::io;
use std::path::Path;
use std::process::Command;

use tracing::warn;

/// Validate that a Windows USERNAME contains only the characters that can
/// safely be used as a single icacls argument component. Rejects values
/// containing quotes, backslashes, control chars, or anything outside the
/// expected `[A-Za-z0-9._\- ]` set.
fn safe_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '))
}

/// Restrict `path` so the current user (owner) has explicit Full Control.
/// Inherited ACEs are intentionally NOT stripped (see module doc + SECURITY.md).
///
/// On failure, emits a warning and returns Ok — callers must NOT rely on
/// this for security-critical guarantees on Windows.
///
/// This is the **sync** entry point. From async/tokio contexts, use
/// `restrict_to_owner_async` which wraps in `spawn_blocking` so the icacls
/// subprocess does not block a tokio worker thread.
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    let username = match std::env::var("USERNAME") {
        Ok(u) if safe_username(&u) => u,
        Ok(u) => {
            warn!(
                path = %path.display(),
                username_len = u.len(),
                "USERNAME contains unexpected characters; refusing to invoke icacls"
            );
            return Ok(());
        }
        Err(_) => {
            warn!(path = %path.display(), "USERNAME env var missing; cannot restrict DACL");
            return Ok(());
        }
    };

    let output = Command::new("icacls.exe")
        .arg(path)
        .arg("/grant:r")
        .arg(format!("{username}:(F)"))
        .output();

    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            warn!(
                path = %path.display(),
                stderr = %String::from_utf8_lossy(&out.stderr).trim_end(),
                stdout = %String::from_utf8_lossy(&out.stdout).trim_end(),
                code = out.status.code(),
                "icacls failed to restrict DACL"
            );
            Ok(())
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "icacls.exe could not be invoked");
            Ok(())
        }
    }
}

/// Async wrapper around `restrict_to_owner`. Runs the icacls subprocess on a
/// blocking thread pool so the calling tokio task isn't blocked. Same Ok-on-
/// failure semantics as the sync entry point.
pub async fn restrict_to_owner_async(path: &Path) -> io::Result<()> {
    let owned: std::path::PathBuf = path.to_path_buf();
    tokio::task::spawn_blocking(move || restrict_to_owner(&owned))
        .await
        .unwrap_or_else(|join_err| {
            warn!(error = %join_err, "icacls task panicked");
            Ok(())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn restrict_to_owner_does_not_panic_on_normal_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        File::create(&path).unwrap();
        // Smoke test: function runs to completion without panic.
        // Verifying the DACL semantically would require Win32 readback;
        // we trust icacls reporting its own exit status.
        restrict_to_owner(&path).expect("ok");
    }

    #[test]
    fn restrict_to_owner_handles_nonexistent_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.txt");
        // icacls will fail with exit 5 or 2; our wrapper logs and returns Ok.
        restrict_to_owner(&path).expect("graceful fallback");
    }
}
