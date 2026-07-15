// Windows DACL restriction for NEOTH files (WAL segments, freedom.yaml, ...).
//
// E-11: This module is the public entry point for DACL restriction on Windows.
//       It now delegates to `win_native::set_owner_dacl` which calls
//       `SetNamedSecurityInfoW` + `SetEntriesInAclW` directly, eliminating
//       the previous `icacls.exe` subprocess approach (D-008).
//
// Historical note (D-008): the original implementation shelled out to
// `icacls.exe /grant:r <USER>:(F)` which introduced one subprocess spawn per
// restricted file plus a command-line injection risk if USERNAME contained
// unexpected characters. The native API path in `win_native.rs` removes both
// concerns and reduces latency by ~50–200ms per WAL rotation.
//
// Policy unchanged from the icacls approach:
//   - Only the explicit DACL entry is set (no PROTECTED_DACL flag), so
//     inherited ACEs remain. This avoids locking out the daemon's open file
//     handles mid-write.
//   - %USERNAME% must be available. NEOTH startup ensures this. If missing or
//     invalid the call degrades to a logged warning (same behaviour as before).
//   - Async callers use `restrict_to_owner_async` which runs on a
//     `spawn_blocking` thread to avoid blocking a tokio worker.

use std::io;
use std::path::Path;

use tracing::warn;

use super::win_native;

/// Validate that a Windows USERNAME contains only the characters that can
/// safely be used as a trustee name. Rejects values containing quotes,
/// backslashes, control chars, or anything outside `[A-Za-z0-9._\- ]`.
///
/// This guard is kept here (even though we no longer pass USERNAME to a
/// subprocess command line) because an empty or wildly malformed USERNAME
/// indicates a broken environment and it is safer to skip the DACL call
/// entirely and emit a warning than to pass garbage to Win32 APIs.
fn safe_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '))
}

/// Restrict `path` so the current user (owner) has explicit Full Control via
/// a native `SetNamedSecurityInfoW` DACL entry.
///
/// On failure, emits a warning and returns `Ok` — callers must NOT rely on
/// this for security-critical guarantees on Windows (see SECURITY.md).
///
/// This is the **sync** entry point. From async/tokio contexts use
/// `restrict_to_owner_async`.
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    let username = match std::env::var("USERNAME") {
        Ok(u) if safe_username(&u) => u,
        Ok(u) => {
            warn!(
                path = %path.display(),
                username_len = u.len(),
                "USERNAME contains unexpected characters; skipping native DACL set"
            );
            return Ok(());
        }
        Err(_) => {
            warn!(path = %path.display(), "USERNAME env var missing; cannot restrict DACL");
            return Ok(());
        }
    };

    match win_native::set_owner_dacl(path, &username) {
        Ok(()) => Ok(()),
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "native SetNamedSecurityInfoW failed to restrict DACL"
            );
            Ok(())
        }
    }
}

/// Async wrapper around [`restrict_to_owner`]. Runs on a blocking thread
/// pool so the calling tokio task isn't blocked. Same `Ok`-on-failure
/// semantics as the sync entry point.
pub async fn restrict_to_owner_async(path: &Path) -> io::Result<()> {
    let owned: std::path::PathBuf = path.to_path_buf();
    tokio::task::spawn_blocking(move || restrict_to_owner(&owned))
        .await
        .unwrap_or_else(|join_err| {
            warn!(error = %join_err, "restrict_to_owner task panicked");
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
        let path = dir.path().join("test.wal");
        File::create(&path).unwrap();
        // Smoke test: runs to completion without panic.
        // DACL correctness is verified via round-trip tests in win_native::tests.
        restrict_to_owner(&path).expect("ok");
    }

    #[test]
    fn restrict_to_owner_handles_nonexistent_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.wal");
        // File does not exist — the native call will fail, which is logged
        // and swallowed (Ok-on-failure policy).
        restrict_to_owner(&path).expect("graceful fallback");
    }

    #[test]
    fn safe_username_accepts_valid_names() {
        assert!(safe_username("Alice"));
        assert!(safe_username("User-PC"));
        assert!(safe_username("john.doe"));
        assert!(safe_username("user_name"));
        // Backslash is NOT in the allowed set — domain prefixes are rejected.
        // `USERNAME` on Windows is the local user name without the domain.
        assert!(!safe_username("DOMAIN\\user"));
        assert!(!safe_username(""));
        assert!(!safe_username(&"x".repeat(65)));
    }

    #[test]
    fn safe_username_rejects_injection_attempts() {
        assert!(!safe_username("foo\" /grant Everyone:F"));
        assert!(!safe_username("foo\0bar"));
        assert!(!safe_username("foo\nbar"));
    }
}
