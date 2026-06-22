//! REPOW-02 — Hidden coupling detector from `git log`.
//!
//! Pairs of files that change together frequently (co-change) but have
//! no import/call edge between them in the call graph are "hidden"
//! coupling — the most dangerous kind because no static tool surfaces
//! it. This module:
//!
//! 1. Runs `git -C <repo> log --name-only --pretty=format:COMMIT:%H` to get
//!    per-commit file-sets.
//! 2. Counts how many commits each unordered file-pair co-appears in.
//! 3. Filters out pairs below `min_co_changes` AND pairs that already
//!    have at least one `CodeEdge` linking the two files in `graph`.
//!
//! The edge filter is approximate: a pair is considered "already
//! connected" if any edge in `graph` has `from_file` equal to one of
//! the pair members AND `to_name` appears as a suffix of the other
//! member's path (e.g. edge to_name="config" matches file
//! "src/config.rs"). This avoids false-positives without needing full
//! symbol resolution.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::graph::CallGraph;

/// A pair of files that co-change without a known structural link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoupledPair {
    /// Lexicographically smaller file path.
    pub a: String,
    /// Lexicographically larger file path.
    pub b: String,
    /// Number of commits in which both `a` and `b` appear.
    pub co_changes: u32,
}

/// Detect hidden coupling in `repo`.
///
/// * `graph` — the call graph for the same repo; used to suppress pairs
///   that already have an explicit structural edge.
/// * `min_co_changes` — pairs with fewer co-changes are dropped.
///
/// Returns pairs sorted descending by `co_changes`, then by `(a, b)`.
pub fn hidden_coupling(
    repo: &Path,
    graph: &CallGraph,
    min_co_changes: u32,
) -> Result<Vec<CoupledPair>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["log", "--name-only", "--pretty=format:COMMIT:%H"])
        .output()
        .context("spawn git log for co-change")?;

    // Non-zero exit (e.g. no commits yet) → empty result.
    if !out.status.success() || out.stdout.is_empty() {
        return Ok(vec![]);
    }

    let raw = String::from_utf8_lossy(&out.stdout);
    let commit_file_sets = parse_commit_file_sets(&raw);

    // Count co-changes for every unordered pair.
    let mut pair_counts: HashMap<(String, String), u32> = HashMap::new();
    for files in &commit_file_sets {
        let mut sorted_files: Vec<&str> = files.iter().map(String::as_str).collect();
        sorted_files.sort();
        for i in 0..sorted_files.len() {
            for j in (i + 1)..sorted_files.len() {
                let key = (sorted_files[i].to_string(), sorted_files[j].to_string());
                *pair_counts.entry(key).or_insert(0) += 1;
            }
        }
    }

    // Build the edge set: (from_file, to_name) for quick lookup.
    let edges = graph.edges();

    let mut results: Vec<CoupledPair> = pair_counts
        .into_iter()
        .filter(|(_, count)| *count >= min_co_changes)
        .filter(|((a, b), _)| !pair_has_edge(a, b, edges))
        .map(|((a, b), co_changes)| CoupledPair { a, b, co_changes })
        .collect();

    // Sort desc by co_changes, then (a, b) for determinism.
    results.sort_by(|x, y| {
        y.co_changes
            .cmp(&x.co_changes)
            .then(x.a.cmp(&y.a))
            .then(x.b.cmp(&y.b))
    });

    Ok(results)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse the combined `git log --name-only --pretty=format:COMMIT:%H` output
/// into a list of per-commit file-sets.
///
/// Output format interleaves commit hash lines and file-path lines,
/// separated by blank lines:
///
/// ```text
/// <sha>
///
/// src/foo.rs
/// src/bar.rs
///
/// <sha>
///
/// src/baz.rs
/// ```
fn parse_commit_file_sets(raw: &str) -> Vec<Vec<String>> {
    let mut sets: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut in_files = false;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            if in_files && !current.is_empty() {
                sets.push(std::mem::take(&mut current));
                in_files = false;
            }
            continue;
        }
        // GR-fix: a commit boundary is the `COMMIT:` sentinel (git
        // --pretty=format:COMMIT:%H). A bare 40-hex check both MISSED SHA-256
        // (64-char) commit ids and FALSE-matched a tracked file literally named
        // with 40 hex chars. The colon can never appear in a tracked path.
        if line.starts_with("COMMIT:") {
            if in_files && !current.is_empty() {
                sets.push(std::mem::take(&mut current));
            }
            in_files = false;
            continue;
        }
        // Everything else is a file path.
        in_files = true;
        current.push(line.to_string());
    }
    if !current.is_empty() {
        sets.push(current);
    }
    sets
}

/// Returns `true` if any edge in `edges` links `a` and `b`.
///
/// An edge is considered to link two files when:
/// - `edge.from_file == a` and `edge.to_name` is a stem/suffix of `b`, OR
/// - `edge.from_file == b` and `edge.to_name` is a stem/suffix of `a`.
///
/// "stem" = the file path without extension and without leading path
/// components (e.g. `"src/config.rs"` → `"config"`).
fn pair_has_edge(a: &str, b: &str, edges: &[super::graph::CodeEdge]) -> bool {
    for edge in edges {
        // Determine which member is the `from_file` and which is `other`.
        let other = if edge.from_file == a {
            b
        } else if edge.from_file == b {
            a
        } else {
            continue;
        };
        if file_matches_name(other, &edge.to_name) {
            return true;
        }
    }
    false
}

/// Check whether `to_name` (a bare identifier from a call edge) could
/// correspond to `file_path`.
///
/// Matching strategy: compare `to_name` against the file stem (path
/// without directory components and without extension). This avoids
/// allocating format strings on every call and correctly handles both
/// POSIX and Windows separators because `file_stem()` is OS-agnostic.
fn file_matches_name(file_path: &str, to_name: &str) -> bool {
    // Primary: stem match (e.g. "src/config.rs" stem == "config").
    let stem = std::path::Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_path);
    if stem == to_name {
        return true;
    }
    // Fallback: exact path equality or path-suffix equality.
    if file_path == to_name {
        return true;
    }
    // Check for path component boundary using byte comparison to avoid
    // allocating a String just for the separator prefix.
    let sep_fwd = format!("/{to_name}");
    let sep_back = format!("\\{to_name}");
    file_path.ends_with(sep_fwd.as_str()) || file_path.ends_with(sep_back.as_str())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::graph::{CallGraph, CodeEdge, EdgeKind};
    use std::process::Command;
    use tempfile::tempdir;

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn init_repo(dir: &Path) -> std::io::Result<()> {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["init", "-q"])
            .status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "user.email", "ci@example.com"])
            .status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "user.name", "CI"])
            .status()?;
        Ok(())
    }

    fn commit_files(dir: &Path, files: &[(&str, &str)], msg: &str) {
        for (name, content) in files {
            if let Some(parent) = std::path::Path::new(name).parent() {
                if parent != std::path::Path::new("") {
                    std::fs::create_dir_all(dir.join(parent)).unwrap();
                }
            }
            std::fs::write(dir.join(name), content).unwrap();
            Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(["add", name])
                .env("GIT_AUTHOR_NAME", "CI")
                .env("GIT_AUTHOR_EMAIL", "ci@example.com")
                .env("GIT_COMMITTER_NAME", "CI")
                .env("GIT_COMMITTER_EMAIL", "ci@example.com")
                .status()
                .unwrap();
        }
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["commit", "-q", "-m", msg])
            .env("GIT_AUTHOR_NAME", "CI")
            .env("GIT_AUTHOR_EMAIL", "ci@example.com")
            .env("GIT_COMMITTER_NAME", "CI")
            .env("GIT_COMMITTER_EMAIL", "ci@example.com")
            .status()
            .unwrap();
    }

    fn empty_graph() -> CallGraph {
        CallGraph::from_edges(vec![])
    }

    fn graph_with_edge(from_file: &str, to_name: &str) -> CallGraph {
        CallGraph::from_edges(vec![CodeEdge {
            from_file: from_file.to_string(),
            from_symbol: "foo".to_string(),
            to_name: to_name.to_string(),
            kind: EdgeKind::Calls,
        }])
    }

    // --- pair changed together 3 times without edge → flagged -----------

    #[test]
    fn co_changed_pair_without_edge_is_flagged() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path();
        init_repo(repo).unwrap();

        commit_files(repo, &[("a.rs", "1"), ("b.rs", "1")], "both-1");
        commit_files(repo, &[("a.rs", "2"), ("b.rs", "2")], "both-2");
        commit_files(repo, &[("a.rs", "3"), ("b.rs", "3")], "both-3");

        let g = empty_graph();
        let pairs = hidden_coupling(repo, &g, 2).unwrap();

        assert!(
            pairs.iter().any(|p| {
                (p.a == "a.rs" && p.b == "b.rs") || (p.a == "b.rs" && p.b == "a.rs")
            }),
            "expected a.rs/b.rs pair, got {pairs:?}"
        );
        let pair = pairs
            .iter()
            .find(|p| p.a == "a.rs" || p.b == "a.rs")
            .unwrap();
        assert_eq!(pair.co_changes, 3);
    }

    // --- pair with an import edge → NOT flagged -------------------------

    #[test]
    fn pair_with_edge_is_suppressed() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path();
        init_repo(repo).unwrap();

        commit_files(repo, &[("mod_a.rs", "1"), ("mod_b.rs", "1")], "both-1");
        commit_files(repo, &[("mod_a.rs", "2"), ("mod_b.rs", "2")], "both-2");
        commit_files(repo, &[("mod_a.rs", "3"), ("mod_b.rs", "3")], "both-3");

        // Edge from mod_a.rs → "mod_b" (stem of mod_b.rs) → suppressed.
        let g = graph_with_edge("mod_a.rs", "mod_b");
        let pairs = hidden_coupling(repo, &g, 2).unwrap();

        assert!(
            !pairs.iter().any(|p| {
                (p.a == "mod_a.rs" || p.b == "mod_a.rs")
                    && (p.a == "mod_b.rs" || p.b == "mod_b.rs")
            }),
            "pair with edge should be suppressed, got {pairs:?}"
        );
    }

    // --- min_co_changes threshold filters low-frequency pairs -----------

    #[test]
    fn min_co_changes_threshold_respected() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path();
        init_repo(repo).unwrap();

        // x.rs and y.rs change together only once.
        commit_files(repo, &[("x.rs", "1"), ("y.rs", "1")], "once");

        let g = empty_graph();
        // Threshold = 2 → pair with 1 co-change should be absent.
        let pairs = hidden_coupling(repo, &g, 2).unwrap();
        assert!(
            !pairs
                .iter()
                .any(|p| (p.a == "x.rs" || p.b == "x.rs") && (p.a == "y.rs" || p.b == "y.rs")),
            "pair below threshold should be filtered, got {pairs:?}"
        );

        // Threshold = 1 → pair appears.
        let pairs_low = hidden_coupling(repo, &g, 1).unwrap();
        assert!(
            pairs_low
                .iter()
                .any(|p| (p.a == "x.rs" || p.b == "x.rs") && (p.a == "y.rs" || p.b == "y.rs")),
            "pair at threshold should appear, got {pairs_low:?}"
        );
    }
}
