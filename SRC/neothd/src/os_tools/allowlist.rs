//! PC-01 path allowlist + traversal defense. Fail-closed at every step.

use std::path::{Component, Path, PathBuf};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllowlistError {
    /// The target contains a `..` segment — rejected before any syscall.
    #[error("path traversal detected (a `..` segment is not allowed)")]
    TraversalDetected,
    /// `tools.os.allowed_paths` is empty — the default deny-all posture.
    #[error("OS file access denied: tools.os.allowed_paths is empty (default deny-all)")]
    DenyAll,
    /// The target could not be canonicalized (missing / unreadable / broken
    /// symlink). Fail-closed: an unresolvable path is never allowed.
    /// (`detail`, not `source`: a `source` field name makes thiserror treat
    /// it as a nested `std::error::Error`, which `String` is not.)
    #[error("cannot resolve path `{path}`: {detail}")]
    CanonicalizeFailed { path: String, detail: String },
    /// The canonical target is not under any allowed prefix.
    #[error("path `{0}` is not within any tools.os.allowed_paths prefix")]
    NotInAllowlist(String),
    /// Windows-only: the filename is a reserved device name (`NUL`, `CON`,
    /// `COM1`, …) or contains an NTFS Alternate Data Stream separator (`:`).
    /// Writes to these targets are silently discarded or hidden by the OS.
    #[error("filename `{0}` is a reserved Windows device name or ADS path")]
    WindowsReservedName(String),
}

/// Resolve `target` and confirm it falls under one of `allowed_paths`.
///
/// Canonicalizes BOTH the target and each allowed prefix with the same
/// [`std::fs::canonicalize`] so the comparison is consistent — symlinks and
/// `.`/`..` are resolved on both sides, and on Windows both acquire the same
/// `\\?\` verbatim prefix so [`Path::starts_with`] (a component-wise check,
/// not a string prefix) is sound. A non-existent / unreadable allowed prefix
/// simply can't match (fail-closed); it never widens the allowlist.
pub fn resolve_within_allowlist(
    target: &Path,
    allowed_paths: &[PathBuf],
) -> Result<PathBuf, AllowlistError> {
    // Reject `..` up-front: catches traversal even on a filesystem without
    // symlinks and gives a precise reason. (canonicalize would also defeat it
    // via the starts_with check below, but this is the explicit first guard.)
    if target
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(AllowlistError::TraversalDetected);
    }
    if allowed_paths.is_empty() {
        return Err(AllowlistError::DenyAll);
    }
    let canonical =
        std::fs::canonicalize(target).map_err(|e| AllowlistError::CanonicalizeFailed {
            path: target.display().to_string(),
            detail: e.to_string(),
        })?;
    let allowed = allowed_paths.iter().any(|prefix| {
        // A RELATIVE prefix would canonicalize against the daemon's CWD —
        // ambiguous and a footgun (the same config exposes different files
        // depending on where neothd was launched). Refuse to honour it.
        if !prefix.is_absolute() {
            tracing::warn!(
                prefix = %prefix.display(),
                "ignoring relative tools.os.allowed_paths entry — entries must be absolute"
            );
            return false;
        }
        match std::fs::canonicalize(prefix) {
            Ok(canon_prefix) => canonical.starts_with(&canon_prefix),
            Err(_) => false, // unresolvable prefix can't match — fail-closed
        }
    });
    if allowed {
        Ok(canonical)
    } else {
        Err(AllowlistError::NotInAllowlist(
            canonical.display().to_string(),
        ))
    }
}

/// Windows-only: reject filenames that are reserved device names or contain
/// NTFS Alternate Data Stream (ADS) separators.
///
/// Device names (`NUL`, `CON`, `PRN`, `AUX`, `COM1`…`COM9`, `LPT1`…`LPT9`)
/// are accepted by `file_name()` and pass the allowlist check, but writes to
/// them are silently discarded by the OS — the daemon would log a successful
/// write that persisted nothing. ADS paths (`file.txt:stream`) write hidden
/// data to a secondary stream that does not appear in directory listings and
/// is not counted against the file's reported size.
#[cfg(windows)]
fn reject_windows_reserved_filename(name: &std::ffi::OsStr) -> Result<(), AllowlistError> {
    let s = match name.to_str() {
        Some(s) => s,
        // Non-UTF-8 filenames can't be device names or ADS paths — allow them
        // to fall through; the subsequent write will surface its own error.
        None => return Ok(()),
    };

    // ADS separator: any `:` in the final filename component.
    if s.contains(':') {
        return Err(AllowlistError::WindowsReservedName(s.to_string()));
    }

    // Device name: strip an optional extension, then compare case-insensitively.
    let stem = s.split('.').next().unwrap_or(s);
    let upper = stem.to_ascii_uppercase();
    let reserved = matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if reserved {
        return Err(AllowlistError::WindowsReservedName(s.to_string()));
    }
    Ok(())
}

/// PC-01 (write slice): resolve a WRITE `target` under `allowed_write_paths`.
///
/// Unlike [`resolve_within_allowlist`] (which canonicalizes the existing
/// target), a write target often DOESN'T exist yet — so we canonicalize the
/// PARENT directory (which must exist + be allowlisted) and rebuild the target
/// as `canonical_parent / file_name`. Defenses, all fail-closed:
///   - reject any `..` segment up-front;
///   - deny-all on an empty write-allowlist;
///   - the target must have a plain final filename + a parent;
///   - the canonical parent must be under an allowed (canonical, absolute)
///     write prefix;
///   - if the target ALREADY exists and is a symlink pointing OUT of its own
///     directory, reject (a symlink can't be used to escape the allowlisted
///     dir on write).
pub fn resolve_write_target(
    target: &Path,
    allowed_write_paths: &[PathBuf],
) -> Result<PathBuf, AllowlistError> {
    if target
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(AllowlistError::TraversalDetected);
    }
    if allowed_write_paths.is_empty() {
        return Err(AllowlistError::DenyAll);
    }
    // The final component must be a plain filename (not `/`, `.`, `..`, or a
    // Windows prefix). `file_name()` returns None for all of those.
    let file_name = target
        .file_name()
        .ok_or_else(|| AllowlistError::NotInAllowlist(target.display().to_string()))?;

    // Windows: reject device names (NUL, CON, COM1, …) and ADS paths
    // (file.txt:stream). Both bypass normal file semantics — device names
    // silently discard written data; ADS paths write hidden secondary streams.
    #[cfg(windows)]
    reject_windows_reserved_filename(file_name)?;

    let parent = target
        .parent()
        .ok_or_else(|| AllowlistError::NotInAllowlist(target.display().to_string()))?;
    // The parent dir MUST exist (we don't create parent dirs) + canonicalize.
    let canon_parent =
        std::fs::canonicalize(parent).map_err(|e| AllowlistError::CanonicalizeFailed {
            path: parent.display().to_string(),
            detail: e.to_string(),
        })?;
    let resolved = canon_parent.join(file_name);

    // If the target already exists, resolve it through any symlink. Its real
    // location must still sit DIRECTLY in `canon_parent` — otherwise a symlink
    // at the target is being used to escape the allowlisted directory.
    if let Ok(canon_existing) = std::fs::canonicalize(&resolved) {
        if canon_existing.parent() != Some(canon_parent.as_path()) {
            return Err(AllowlistError::NotInAllowlist(
                canon_existing.display().to_string(),
            ));
        }
    }

    let allowed = allowed_write_paths.iter().any(|prefix| {
        if !prefix.is_absolute() {
            tracing::warn!(
                prefix = %prefix.display(),
                "ignoring relative tools.os.allowed_write_paths entry — entries must be absolute"
            );
            return false;
        }
        match std::fs::canonicalize(prefix) {
            Ok(canon_prefix) => canon_parent.starts_with(&canon_prefix),
            Err(_) => false,
        }
    });
    if allowed {
        Ok(resolved)
    } else {
        Err(AllowlistError::NotInAllowlist(
            resolved.display().to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn empty_allowlist_is_deny_all() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"x").unwrap();
        assert_eq!(
            resolve_within_allowlist(&f, &[]),
            Err(AllowlistError::DenyAll)
        );
    }

    #[test]
    fn allows_file_within_prefix() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"x").unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        let got = resolve_within_allowlist(&f, &allowed).unwrap();
        assert!(got.ends_with("a.txt"));
    }

    #[test]
    fn denies_file_outside_all_prefixes() {
        let allowed_dir = tempdir().unwrap();
        let other_dir = tempdir().unwrap();
        let f = other_dir.path().join("secret.txt");
        fs::write(&f, b"x").unwrap();
        let allowed = vec![allowed_dir.path().to_path_buf()];
        assert!(matches!(
            resolve_within_allowlist(&f, &allowed),
            Err(AllowlistError::NotInAllowlist(_))
        ));
    }

    #[test]
    fn dotdot_segment_is_rejected_before_fs() {
        // Even with a permissive allowlist, a literal `..` is refused.
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        let traversal = dir.path().join("..").join("etc").join("passwd");
        assert_eq!(
            resolve_within_allowlist(&traversal, &allowed),
            Err(AllowlistError::TraversalDetected)
        );
    }

    #[test]
    fn parent_of_prefix_is_denied() {
        // /tmp/work is allowed; /tmp itself (its parent) must NOT be readable.
        let parent = tempdir().unwrap();
        let work = parent.path().join("work");
        fs::create_dir(&work).unwrap();
        let marker = parent.path().join("outside.txt");
        fs::write(&marker, b"x").unwrap();
        let allowed = vec![work.clone()];
        assert!(matches!(
            resolve_within_allowlist(&marker, &allowed),
            Err(AllowlistError::NotInAllowlist(_))
        ));
    }

    #[test]
    fn relative_prefix_is_ignored_fail_closed() {
        // A relative allowed_paths entry must never authorise a read (it would
        // resolve against the daemon CWD). The file is real + inside the abs
        // dir, but the only allowed prefix is relative ⇒ NotInAllowlist.
        let dir = tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"x").unwrap();
        let allowed = vec![PathBuf::from("some/relative/dir")];
        assert!(matches!(
            resolve_within_allowlist(&f, &allowed),
            Err(AllowlistError::NotInAllowlist(_))
        ));
    }

    #[test]
    fn nonexistent_target_fails_closed() {
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        let ghost = dir.path().join("does-not-exist.txt");
        assert!(matches!(
            resolve_within_allowlist(&ghost, &allowed),
            Err(AllowlistError::CanonicalizeFailed { .. })
        ));
    }

    // ── write-target resolution ──────────────────────────────────────────

    #[test]
    fn write_allows_new_file_in_allowed_dir() {
        // The KEY difference vs read: the target does NOT exist yet, but its
        // parent does + is allowlisted ⇒ resolves (read would fail-closed here).
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        let new_file = dir.path().join("fresh.txt");
        let got = resolve_write_target(&new_file, &allowed).unwrap();
        assert!(got.ends_with("fresh.txt"));
    }

    #[test]
    fn write_empty_allowlist_is_deny_all() {
        let dir = tempdir().unwrap();
        assert_eq!(
            resolve_write_target(&dir.path().join("x.txt"), &[]),
            Err(AllowlistError::DenyAll)
        );
    }

    #[test]
    fn write_dotdot_rejected() {
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        let t = dir.path().join("..").join("escape.txt");
        assert_eq!(
            resolve_write_target(&t, &allowed),
            Err(AllowlistError::TraversalDetected)
        );
    }

    #[test]
    fn write_parent_outside_allowlist_denied() {
        let allowed_dir = tempdir().unwrap();
        let other = tempdir().unwrap();
        let allowed = vec![allowed_dir.path().to_path_buf()];
        let t = other.path().join("new.txt");
        assert!(matches!(
            resolve_write_target(&t, &allowed),
            Err(AllowlistError::NotInAllowlist(_))
        ));
    }

    #[test]
    fn write_nonexistent_parent_fails_closed() {
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        // parent dir doesn't exist ⇒ we never create parents ⇒ fail-closed.
        let t = dir.path().join("missing-subdir").join("f.txt");
        assert!(matches!(
            resolve_write_target(&t, &allowed),
            Err(AllowlistError::CanonicalizeFailed { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn write_symlink_target_escaping_dir_is_rejected() {
        // A symlink AT the target, pointing to a file OUTSIDE the allowed dir,
        // must not let a write escape — canonicalize resolves it + we reject.
        use std::os::unix::fs::symlink;
        let allowed_dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, b"x").unwrap();
        let link = allowed_dir.path().join("link.txt");
        symlink(&secret, &link).unwrap();
        let allowed = vec![allowed_dir.path().to_path_buf()];
        assert!(
            matches!(
                resolve_write_target(&link, &allowed),
                Err(AllowlistError::NotInAllowlist(_))
            ),
            "a symlink escaping its dir must be rejected on write"
        );
    }

    #[cfg(windows)]
    #[test]
    fn write_rejects_windows_device_names_and_ads() {
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        for bad in ["NUL", "con", "COM1", "lpt9", "nul.txt", "data.txt:hidden"] {
            let t = dir.path().join(bad);
            assert!(
                matches!(
                    resolve_write_target(&t, &allowed),
                    Err(AllowlistError::WindowsReservedName(_))
                ),
                "`{bad}` must be rejected as a reserved/ADS name"
            );
        }
        // A normal name with a digit that isn't a device (COM0 / LPT0 / COM10)
        // is allowed.
        assert!(resolve_write_target(&dir.path().join("com0.txt"), &allowed).is_ok());
    }

    #[test]
    fn write_relative_prefix_ignored_fail_closed() {
        let dir = tempdir().unwrap();
        let allowed = vec![PathBuf::from("some/rel/dir")];
        let t = dir.path().join("x.txt");
        assert!(matches!(
            resolve_write_target(&t, &allowed),
            Err(AllowlistError::NotInAllowlist(_))
        ));
    }

    // ── Windows-specific: device names + ADS paths ───────────────────────────

    #[cfg(windows)]
    #[test]
    fn write_nul_device_rejected() {
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        let t = dir.path().join("NUL");
        assert!(
            matches!(
                resolve_write_target(&t, &allowed),
                Err(AllowlistError::WindowsReservedName(_))
            ),
            "NUL device name must be rejected"
        );
    }

    #[cfg(windows)]
    #[test]
    fn write_con_device_rejected() {
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        // CON with extension (e.g. CON.txt) is also a device name on Windows.
        for name in &["CON", "con", "CON.txt", "PRN", "AUX", "COM1", "LPT9"] {
            let t = dir.path().join(name);
            assert!(
                matches!(
                    resolve_write_target(&t, &allowed),
                    Err(AllowlistError::WindowsReservedName(_))
                ),
                "{name} must be rejected as a Windows device name"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn write_ads_path_rejected() {
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        // ADS separator in the filename component.
        let t = dir.path().join("notes.txt:hidden");
        assert!(
            matches!(
                resolve_write_target(&t, &allowed),
                Err(AllowlistError::WindowsReservedName(_))
            ),
            "ADS filename (contains ':') must be rejected"
        );
    }

    #[cfg(windows)]
    #[test]
    fn write_normal_filename_still_allowed() {
        // Regression guard: the Windows checks must not reject legitimate names.
        let dir = tempdir().unwrap();
        let allowed = vec![dir.path().to_path_buf()];
        let t = dir.path().join("output.txt");
        // The parent exists, the name is clean — should resolve without error.
        let result = resolve_write_target(&t, &allowed);
        assert!(
            result.is_ok(),
            "normal filename must not be rejected by Windows checks: {result:?}"
        );
    }
}
