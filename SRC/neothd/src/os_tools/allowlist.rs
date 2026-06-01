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
}
