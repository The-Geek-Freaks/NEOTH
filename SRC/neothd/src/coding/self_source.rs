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

/// The three distinct directories a self-edit needs. In NEOTH's real layout
/// they are NOT the same directory:
/// - `.git` lives at the repository root,
/// - the `[workspace]` Cargo.toml lives at `SRC/`,
/// - the `neothd` package (with `src/`) lives at `SRC/neothd/`.
///
/// The gate keeps its hard-deny / allowlist prefixes CRATE-relative
/// (`src/wal/`, `src/cli`), so `git apply` must run in [`SourceRoots::crate_dir`]
/// for those paths to resolve; the worktree lives in the git repo, and
/// `cargo check` runs in the workspace.
#[derive(Debug, Clone)]
pub struct SourceRoots {
    /// Directory containing `.git` — all `git worktree` operations run here.
    pub git_root: PathBuf,
    /// The crate directory (contains `src/` + a `[package]` Cargo.toml). Diff
    /// paths (`src/...`) are relative to THIS dir.
    pub crate_dir: PathBuf,
    /// The Cargo workspace directory (`[workspace]` Cargo.toml) — `cargo check`
    /// runs here so the whole workspace resolves.
    pub workspace_dir: PathBuf,
}

impl SourceRoots {
    /// `crate_dir` relative to `git_root` (e.g. `SRC/neothd`), or `.` when they
    /// are the same directory (a flat single-crate repo).
    pub fn crate_rel(&self) -> PathBuf {
        rel_or_dot(&self.git_root, &self.crate_dir)
    }

    /// `workspace_dir` relative to `git_root` (e.g. `SRC`), or `.` when equal.
    pub fn workspace_rel(&self) -> PathBuf {
        rel_or_dot(&self.git_root, &self.workspace_dir)
    }
}

/// `child` relative to `base`, collapsing an empty result (same dir) to `.`.
fn rel_or_dot(base: &Path, child: &Path) -> PathBuf {
    match child.strip_prefix(base) {
        Ok(r) if r.as_os_str().is_empty() => PathBuf::from("."),
        Ok(r) => r.to_path_buf(),
        Err(_) => PathBuf::from("."),
    }
}

/// Locate the three NEOTH source roots (git repo / crate / workspace).
///
/// Resolution:
/// 1. The CRATE dir is the `source_root` override from `SelfEditConfig`
///    (operator-set), else the compile-time crate dir (`CARGO_MANIFEST_DIR`) —
///    self-edit runs against the source it was built from.
/// 2. The git root and workspace dir are found by walking UP from the crate
///    dir (they are ancestors in NEOTH's `repo/SRC/neothd` layout, or the crate
///    dir itself in a flat single-crate repo).
///
/// Returns an error when the crate dir is invalid or no `.git` is found at or
/// above it (self-edit needs a git repo for worktree isolation, Layer 4).
pub fn neoth_source_root(cfg_root: &Option<PathBuf>) -> Result<SourceRoots> {
    let crate_dir = match cfg_root {
        Some(root) => strip_verbatim(
            root.canonicalize()
                .with_context(|| format!("canonicalize source_root override {}", root.display()))?,
        ),
        None => {
            // Auto-detect uses the COMPILE-TIME crate dir. This works for a
            // binary built from a local checkout, but a binary downloaded from
            // GitHub Releases carries the CI runner's build path, which does not
            // exist on the operator's machine → canonicalize fails here. That is
            // expected: a distributed binary MUST set an explicit source_root.
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            strip_verbatim(manifest.canonicalize().with_context(|| {
                format!(
                    "self-edit source-root auto-detect failed: the compile-time crate dir \
                     '{}' does not exist on this machine. This is normal for a downloaded \
                     release binary (the path points to the CI build machine). Set \
                     `coding.self_edit.source_root` in freedom.yaml to your local NEOTH \
                     crate checkout (the dir containing Cargo.toml + src/, e.g. \
                     C:\\path\\to\\NEOTH\\SRC\\neothd).",
                    manifest.display()
                )
            })?)
        }
    };
    validate_crate_dir(&crate_dir)?;

    let git_root = crate_dir
        .ancestors()
        .find(|a| a.join(".git").exists())
        .map(|p| p.to_path_buf())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no .git found at or above crate dir {} — self-edit requires a \
                 git repository for worktree isolation",
                crate_dir.display()
            )
        })?;

    // Workspace = nearest ancestor whose Cargo.toml declares [workspace]. Fall
    // back to the crate dir itself (flat single-crate repo).
    let workspace_dir = crate_dir
        .ancestors()
        .find(|a| dir_is_workspace(a))
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| crate_dir.clone());

    Ok(SourceRoots {
        git_root,
        crate_dir,
        workspace_dir,
    })
}

/// True when `dir/Cargo.toml` declares a `[workspace]`.
fn dir_is_workspace(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("Cargo.toml"))
        .map(|c| c.contains("[workspace]"))
        .unwrap_or(false)
}

/// Strip Windows' verbatim prefix (`\\?\C:\…` → `C:\…`) from a canonicalized
/// path. `std::fs::canonicalize` returns verbatim paths on Windows, which
/// `git` (MSYS-based) rejects with "could not create leading directories".
/// UNC verbatim paths (`\\?\UNC\…`) are left untouched.
fn strip_verbatim(p: PathBuf) -> PathBuf {
    if cfg!(windows) {
        let s = p.display().to_string();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            if !rest.starts_with("UNC") {
                return PathBuf::from(rest);
            }
        }
    }
    p
}

/// Validate that `dir` is the NEOTH crate root: a `[package]` Cargo.toml and a
/// `src/` directory. The git-repo and workspace requirements are checked
/// against ancestors by [`neoth_source_root`], not here.
pub fn validate_crate_dir(dir: &Path) -> Result<()> {
    let cargo_toml = dir.join("Cargo.toml");
    if !cargo_toml.exists() {
        anyhow::bail!("crate dir {} has no Cargo.toml", dir.display());
    }
    let content = std::fs::read_to_string(&cargo_toml)
        .with_context(|| format!("read {}", cargo_toml.display()))?;
    if !content.contains("[package]") {
        anyhow::bail!(
            "{} is not a Rust package (no [package] section found)",
            cargo_toml.display()
        );
    }
    if !dir.join("src").is_dir() {
        anyhow::bail!(
            "crate dir {} has no src/ directory — not a NEOTH source checkout",
            dir.display()
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
        anyhow::bail!(
            "diff path '{path}' has a drive prefix — only repo-relative paths are allowed"
        );
    }
    // Any other colon: NTFS alternate data streams (`mod.rs:stream`) attach to
    // an EXISTING file under a colon-suffixed name, bypassing prefix denies.
    if path.contains(':') {
        anyhow::bail!(
            "diff path '{path}' contains ':' — NTFS alternate data streams are not permitted"
        );
    }
    // `.` components survive the string-prefix deny check unchanged but the OS
    // resolves them away (`src/./wal/x` opens `src/wal/x`) — reject alongside
    // `..` so every gate layer sees the canonical spelling.
    if path
        .split('/')
        .any(|component| component == ".." || component == ".")
    {
        anyhow::bail!("diff path '{path}' contains a '.' or '..' traversal component");
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

    #[test]
    fn source_roots_resolve_for_nested_repo_layout() {
        // P0 regression: NEOTH's real layout has .git at the repo root,
        // [workspace] at SRC/, and the neothd package (with src/) at
        // SRC/neothd/ — three DIFFERENT dirs. Auto-detect must find all three
        // (the old validator required them in ONE dir → feature unreachable).
        let roots = neoth_source_root(&None).expect("source roots must resolve in-repo");
        assert!(
            roots.git_root.join(".git").exists(),
            "git_root has no .git: {}",
            roots.git_root.display()
        );
        assert!(
            roots.crate_dir.join("src").is_dir(),
            "crate_dir has no src/: {}",
            roots.crate_dir.display()
        );
        assert!(
            dir_is_workspace(&roots.workspace_dir),
            "workspace_dir is not a [workspace]: {}",
            roots.workspace_dir.display()
        );
        // Nesting: git_root ⊇ workspace_dir ⊇ crate_dir.
        assert!(roots.crate_dir.starts_with(&roots.workspace_dir));
        assert!(roots.workspace_dir.starts_with(&roots.git_root));
        // The crate is genuinely a subdir of the git root (not the flat case),
        // so git-apply-in-crate-dir vs worktree-at-git-root is exercised.
        assert_ne!(roots.crate_rel(), PathBuf::from("."));
    }

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
            err.to_string()
                .contains("no recognisable file path headers"),
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
    fn diff_paths_rejects_dot_component_and_ads_colon() {
        // `src/./wal/x` resolves to `src/wal/x` at the OS level but evades a
        // string-prefix deny; `mod.rs:stream` is an NTFS alternate data stream.
        for bad in [
            "--- a/src/./wal/mod.rs\n+++ b/src/./wal/mod.rs\n@@ -1 +1 @@\n-x\n+y\n",
            "--- a/src/cli/mod.rs:stream\n+++ b/src/cli/mod.rs:stream\n@@ -1 +1 @@\n-x\n+y\n",
        ] {
            assert!(
                diff_paths(bad).is_err(),
                "expected rejection for non-canonical path in: {bad:?}"
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
