//! Multi-user isolation guard — Phase 33c BS-9.
//!
//! Refuse to start if `~/.neoth/` is world-readable (Unix) or has a
//! non-owner DACL entry (Windows). NEOTH stores operator-private state:
//! WAL frames, ground-truth facts, API keys (mode-0600 inside but in a
//! shared dir is still a leak via directory listing).
//!
//! The check runs in [`crate::cli::serve`] right after PID acquisition —
//! before the WAL writer opens any file under `~/.neoth/`. On Windows the
//! check is best-effort because the DACL parse path needs the `windows`
//! crate, which we deliberately avoid (see OPEN_DECISIONS D-008).

use std::path::Path;

use anyhow::Result;

/// Check the home directory's permissions. Returns `Err` with a
/// human-readable message when the dir is shared with other users on
/// the same host.
pub fn check_home_isolation(home: &Path) -> Result<()> {
    if !home.exists() {
        // Fresh install — wizard hasn't run yet. Caller will create the
        // dir with the right permissions.
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(home)?;
        let mode = meta.permissions().mode() & 0o777;
        // Mode 0700 is the target. Anything that grants read/exec to
        // group or other is a leak.
        let leaks_to_others = mode & 0o077 != 0;
        if leaks_to_others {
            anyhow::bail!(
                "{} is mode 0o{:o} — refusing to start (mode 0o700 required so other users on this host cannot list/read your NEOTH state). Fix: chmod 0700 {}",
                home.display(),
                mode,
                home.display(),
            );
        }
    }
    #[cfg(windows)]
    {
        // GOLD-SEC-29/33 / A-87: best-effort DACL check. A full parse would
        // need the `windows` crate (deliberately avoided), so we read the ACL
        // via `icacls` and WARN if it grants a broad principal (Everyone /
        // Users / Authenticated Users — localized names + well-known SIDs
        // covered). The wizard's `icacls /grant:r %USER%:(F)` (Phase 0 O-4)
        // is the actual enforcement; this surfaces a leak at daemon start
        // WITHOUT blocking — icacls output is locale-dependent, so a parse
        // miss must never lock the operator out of their own daemon.
        match std::process::Command::new("icacls.exe").arg(home).output() {
            Ok(out) if out.status.success() => {
                let acl = String::from_utf8_lossy(&out.stdout);
                const BROAD_PRINCIPALS: &[&str] = &[
                    "Everyone",
                    "Jeder",
                    "S-1-1-0", // Everyone
                    "\\Users",
                    "\\Benutzer",
                    "S-1-5-32-545", // BUILTIN\Users
                    "Authenticated Users",
                    "Authentifizierte Benutzer",
                    "S-1-5-11", // Authenticated Users
                ];
                if let Some(hit) = BROAD_PRINCIPALS
                    .iter()
                    .copied()
                    .find(|p| acl.contains(p))
                {
                    tracing::warn!(
                        home = %home.display(),
                        principal = %hit,
                        "NEOTH home directory ACL grants access to a broad principal — other \
                         users on this host may read your state (API keys, memory). Fix: \
                         icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:(OI)(CI)F\"",
                        home.display(),
                    );
                }
            }
            _ => {
                tracing::debug!(
                    home = %home.display(),
                    "icacls home-isolation check unavailable — relying on wizard-set ACL",
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_dir_passes_check() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("absent");
        assert!(check_home_isolation(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_dir_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("neoth-shared");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = check_home_isolation(&path);
        assert!(r.is_err(), "world-readable dir must be rejected");
        let msg = format!("{r:?}");
        assert!(msg.contains("0o700"), "error message must point to the fix");
    }

    #[cfg(unix)]
    #[test]
    fn mode_0700_passes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("neoth-private");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_home_isolation(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn mode_0750_is_still_rejected_for_group_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("group-readable");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(check_home_isolation(&path).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_no_panic() {
        // Best-effort on Windows; verify the function doesn't crash.
        let dir = tempdir().unwrap();
        check_home_isolation(dir.path()).unwrap();
    }
}
