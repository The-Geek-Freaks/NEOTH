//! GOLD-FEAT-05 — self-source-edit engine.
//!
//! Provides the pure-function helpers consumed by the gate stack in
//! [`crate::coding::self_source_gate`]:
//!
//! - Source-root detection (walk up from binary path to workspace `Cargo.toml`)
//! - Unified-diff parsing — extract touched paths from `--- a/` / `+++ b/` headers
//! - SHA-256 diff hash for the WAL audit payload
//! - Changed-line counter (Layer-2 size cap)

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

// ── Source root detection ─────────────────────────────────────────────────────

/// Locate the NEOTH workspace root.
///
/// Resolution order:
/// 1. `source_root` override from `SelfEditConfig` (operator-set in
///    `freedom.yaml::coding.self_edit.source_root`).
/// 2. Walk up from the running binary path until a `Cargo.toml` containing
///    `[workspace]` is found.
///
/// Returns an error when neither yields a valid workspace directory.
pub fn neoth_source_root(
    cfg_root: &Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(root) = cfg_root {
        let root = root
            .canonicalize()
            .with_context(|| format!(
                "canonicalize source_root override {}",
                root.display()
            ))?;
        validate_source_root(&root)?;
        return Ok(root);
    }

    // Auto-detect: walk from the current exe up to the workspace root.
    let exe = std::env::current_exe()
        .context("determine path of running binary for source-root detection")?;

    for ancestor in exe.ancestors() {
        let cargo_toml = ancestor.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    let root = ancestor
                        .canonicalize()
                        .with_context(|| format!("canonicalize {}", ancestor.display()))?;
                    validate_source_root(&root)?;
                    return Ok(root);
                }
            }
        }
    }

    anyhow::bail!(
        "cannot auto-detect NEOTH source root from binary path {}; \
         set freedom.yaml::coding.self_edit.source_root explicitly",
        exe.display()
    )
}

/// Validate that `root` is a Rust workspace that lives inside a git repo.
///
/// Rejects paths that are not workspace roots (no `[workspace]` in
/// `Cargo.toml`) or that lack a `.git` directory — self-edit requires a
/// git repo for worktree isolation (Layer 4).
pub fn validate_source_root(root: &Path) -> Result<()> {
    let cargo_toml = root.join("Cargo.toml");
    if !cargo_toml.exists() {
        anyhow::bail!(
            "source root {} has no Cargo.toml",
            root.display()
        );
    }
    let content = std::fs::read_to_string(&cargo_toml)
        .with_context(|| format!("read {}", cargo_toml.display()))?;
    if !content.contains("[workspace]") {
        anyhow::bail!(
            "{} is not a Cargo workspace (no [workspace] section found)",
            cargo_toml.display()
        );
    }
    if !root.join(".git").exists() {
        anyhow::bail!(
            "source root {} has no .git directory — \
             self-edit requires a git repository for worktree isolation",
            root.display()
        );
    }
    Ok(())
}

// ── Diff parsing ──────────────────────────────────────────────────────────────

/// Reject any diff path that is not a clean repo-relative forward-slash path.
///
/// The hard-deny gate ([`super::self_source_gate`]) matches string *prefixes*
/// (`src/wal/`), but the live-tree sink (`git apply`) resolves the path on the
/// filesystem. A `..` traversal, an absolute path, a Windows drive prefix, or
/// backslash separators would let a diff evade the prefix deny while still
/// writing to a protected file. Reject them at parse time so no gate layer can
/// be fooled by a non-canonical path.
fn validate_diff_path(path: &str) -> Result<()> {
    if path.contains('\\') {
        anyhow::bail!(
            "diff path '{path}' contains a backslash — only forward-slash \
             repo-relative paths are allowed"
        );
    }
    if path.starts_with('/') {
        anyhow::bail!("diff path '{path}' is absolute — only repo-relative paths are allowed");
    }
    // Windows drive prefix, e.g. `C:` / `c:`.
    if path.as_bytes().get(1) == Some(&b':') {
        anyhow::bail!("diff path '{path}' has a drive prefix — only repo-relative paths are allowed");
    }
    if path.split('/').any(|component| component == "..") {
        anyhow::bail!("diff path '{path}' contains a '..' traversal component");
    }
    Ok(())
}

/// Parse a unified diff and return the set of file paths it touches.
///
/// Extracts paths from `--- a/<path>` and `+++ b/<path>` header lines,
/// stripping the `a/` / `b/` prefix so callers can compare against
/// project-relative paths.  `/dev/null` (new-file / deleted-file sentinel)
/// is excluded from the result.
pub fn diff_paths(diff: &str) -> Result<Vec<String>> {
    let mut paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for line in diff.lines() {
        // "+++ b/src/foo.rs"  →  "src/foo.rs"
        // "--- a/src/foo.rs"  →  "src/foo.rs"
        let maybe_path = line
            .strip_prefix("+++ b/")
            .or_else(|| line.strip_prefix("--- a/"));

        if let Some(path) = maybe_path {
            let path = path.trim();
            if !path.is_empty() && path != "/dev/null" {
                validate_diff_path(path)?;
                paths.insert(path.to_string());
            }
        }
    }

    if paths.is_empty() {
        anyhow::bail!(
            "diff contains no recognisable file path headers \
             (expected `--- a/<path>` / `+++ b/<path>` lines)"
        );
    }
    Ok(paths.into_iter().collect())
}

/// Compute the SHA-256 hex digest of `diff` bytes for WAL audit payload.
pub fn diff_sha256(diff: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(diff);
    hex::encode(hasher.finalize())
}

/// Count total changed lines in `diff`: additions (`+`) + removals (`-`),
/// excluding the `---`/`+++` header lines and `@@` hunk headers.
///
/// Used by Layer-2 `max_lines_changed` cap.
pub fn diff_line_count(diff: &str) -> usize {
    diff.lines()
        .filter(|l| {
            (l.starts_with('+') && !l.starts_with("+++"))
                || (l.starts_with('-') && !l.starts_with("---"))
        })
        .count()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal unified diff touching one file with one added comment line.
    const COMMENT_DIFF: &str = concat!(
        "diff --git a/src/cli/dummy.rs b/src/cli/dummy.rs\n",
        "--- a/src/cli/dummy.rs\n",
        "+++ b/src/cli/dummy.rs\n",
        "@@ -1,3 +1,4 @@\n",
        " // placeholder\n",
        "+// added comment\n",
        " fn main() {}\n",
    );

    // A diff touching a hard-deny path (src/wal/foo.rs).
    const WAL_DIFF: &str = concat!(
        "--- a/src/wal/foo.rs\n",
        "+++ b/src/wal/foo.rs\n",
        "@@ -1,1 +1,2 @@\n",
        " existing\n",
        "+new line\n",
    );

    #[test]
    fn diff_paths_extracts_correct_path() {
        let paths = diff_paths(COMMENT_DIFF).unwrap();
        assert_eq!(paths, vec!["src/cli/dummy.rs".to_string()]);
    }

    #[test]
    fn diff_paths_rejects_empty_diff() {
        let err = diff_paths("").unwrap_err();
        assert!(
            err.to_string().contains("no recognisable file path headers"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn diff_paths_excludes_dev_null() {
        let diff = concat!(
            "--- /dev/null\n",
            "+++ b/src/new.rs\n",
            "@@ -0,0 +1 @@\n",
            "+hello\n",
        );
        let paths = diff_paths(diff).unwrap();
        assert!(
            paths.contains(&"src/new.rs".to_string()),
            "expected src/new.rs in {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.contains("dev/null")),
            "dev/null leaked into paths: {paths:?}"
        );
    }

    #[test]
    fn diff_paths_wal_path_detected() {
        // Gate must see this path so it can hard-deny it (Layer 2).
        let paths = diff_paths(WAL_DIFF).unwrap();
        assert!(
            paths.iter().any(|p| p.starts_with("src/wal/")),
            "WAL path not detected: {paths:?}"
        );
    }

    #[test]
    fn diff_paths_rejects_traversal_component() {
        // `../` would let git apply escape the checked prefix to a denied path.
        let diff = concat!(
            "--- a/src/cli/../wal/foo.rs\n",
            "+++ b/src/cli/../wal/foo.rs\n",
            "@@ -1,1 +1,2 @@\n",
            " x\n",
            "+y\n",
        );
        let err = diff_paths(diff).unwrap_err();
        assert!(err.to_string().contains("traversal"), "got: {err}");
    }

    #[test]
    fn diff_paths_rejects_absolute_and_drive_and_backslash() {
        for bad in [
            "--- a//etc/passwd\n+++ b//etc/passwd\n@@ -1 +1 @@\n-x\n+y\n",
            "--- a/C:/Windows/x\n+++ b/C:/Windows/x\n@@ -1 +1 @@\n-x\n+y\n",
            "--- a/src\\wal\\foo.rs\n+++ b/src\\wal\\foo.rs\n@@ -1 +1 @@\n-x\n+y\n",
        ] {
            assert!(
                diff_paths(bad).is_err(),
                "expected rejection for malformed path in: {bad:?}"
            );
        }
    }

    #[test]
    fn diff_sha256_is_deterministic() {
        let h1 = diff_sha256(b"hello");
        let h2 = diff_sha256(b"hello");
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_eq!(h1.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn diff_sha256_differs_on_different_input() {
        assert_ne!(
            diff_sha256(b"hello"),
            diff_sha256(b"world"),
            "distinct inputs must produce distinct hashes"
        );
    }

    #[test]
    fn diff_line_count_counts_added_lines_only() {
        // COMMENT_DIFF has one `+` line (the added comment) and zero `-` lines.
        assert_eq!(diff_line_count(COMMENT_DIFF), 1);
    }

    #[test]
    fn diff_line_count_counts_removals() {
        let diff = concat!(
            "--- a/src/x.rs\n",
            "+++ b/src/x.rs\n",
            "@@ -1,2 +1,1 @@\n",
            "-removed\n",
            " kept\n",
        );
        assert_eq!(diff_line_count(diff), 1);
    }

    #[test]
    fn diff_line_count_excludes_header_lines() {
        // --- and +++ lines must NOT be counted.
        let diff = concat!(
            "--- a/src/x.rs\n",
            "+++ b/src/x.rs\n",
            "@@ -1,1 +1,1 @@\n",
            "-old\n",
            "+new\n",
        );
        // 1 removal + 1 addition = 2
        assert_eq!(diff_line_count(diff), 2);
    }
}
