//! Multi-user isolation guard — Phase 33c BS-9.
//!
//! Unix: REFUSE to start if `~/.neoth/` is world-readable (mode != 0700).
//! Windows: best-effort WARN (never blocks) on a broad-principal DACL entry —
//! the DACL parse without a windows-crate isn't reliable enough to hard-block,
//! and a shared `C:\Temp` etc. grants `Everyone` legitimately. NEOTH stores
//! operator-private state:
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
                // SEC-29/GR-022 — `icacls_broad_principal` anchors on the ACE form
                // `PRINCIPAL:(perms)` so the queried PATH icacls echoes as its
                // leading token (it contains `\Users` on every standard install)
                // is NOT false-matched — the warning now fires only on a REAL
                // broad grant. SEC-33 — the Windows path WARNS (never errors)
                // while the Unix path hard-fails: that asymmetry is INTENTIONAL,
                // not a bug. Windows directories routinely INHERIT broad ACEs
                // (e.g. `C:\Temp` grants `Jeder`/Everyone), so a hard-fail would
                // lock the operator out of a legitimate home; the wizard's
                // explicit `icacls /grant:r %USER%:(F)` is the actual enforcement
                // and this surfaces a leak loudly without blocking startup.
                if let Some(hit) = icacls_broad_principal(&acl) {
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

/// SEC-29/GR-022/SEC-33 — scan `icacls` output for a broad-principal ACE. Anchors
/// on the `PRINCIPAL:(perms)` ACE form so the queried PATH that icacls echoes as
/// the leading token (which contains `\Users` on every standard Windows install)
/// is NOT false-matched. Locale-robust: the `:(` separator + perms are icacls
/// syntax (not localized); a missed other-locale NAME is a false-NEGATIVE
/// (under-protection), never a false-positive lock-out. `None` when no broad
/// grant is present. Pure → unit-testable on any platform.
#[cfg_attr(not(windows), allow(dead_code))]
fn icacls_broad_principal(acl: &str) -> Option<&'static str> {
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
    BROAD_PRINCIPALS
        .iter()
        .copied()
        .find(|p| acl.contains(&format!("{p}:(")))
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

    #[test]
    fn icacls_broad_principal_ignores_echoed_path_but_catches_aces() {
        // SEC-29/GR-022: the queried path icacls echoes (contains \Users) must
        // NOT false-match; a genuine broad-principal ACE IS detected (→ on
        // Windows it surfaces a WARN, never blocks startup). Pure logic, runs on
        // every platform.
        assert_eq!(
            icacls_broad_principal("C:\\Users\\alex\\.neoth NEOTH-PC\\alex:(OI)(CI)(F)\r\n"),
            None,
            "the echoed \\Users path must not false-match"
        );
        assert_eq!(
            icacls_broad_principal("C:\\Users\\alex\\.neoth Everyone:(F)\r\n"),
            Some("Everyone")
        );
        assert_eq!(
            icacls_broad_principal("C:\\Users\\alex\\.neoth BUILTIN\\Users:(RX)\r\n"),
            Some("\\Users")
        );
        assert_eq!(
            icacls_broad_principal("C:\\Users\\alex\\.neoth S-1-1-0:(F)\r\n"),
            Some("S-1-1-0")
        );
        // A clean, user + SYSTEM only ACL → no broad principal.
        assert_eq!(
            icacls_broad_principal(
                "C:\\Users\\alex\\.neoth NEOTH-PC\\alex:(F)\r\nNT AUTHORITY\\SYSTEM:(F)\r\n"
            ),
            None
        );
    }
}
