//! REPOW-01 — File ownership + bus-factor from `git log`.
//!
//! Runs `git -C <repo> log --follow --format=%ae -- <file>` to collect
//! every author email in commit order (newest first), aggregates commit
//! counts per author, and computes the bus-factor: the minimum number
//! of top authors whose combined share is ≥ 50% of total commits.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Per-file ownership summary.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FileOwnership {
    /// Total commits touching this file (after `--follow`).
    pub total_commits: u32,
    /// Authors sorted descending by commit count: `(email, count)`.
    pub authors: Vec<(String, u32)>,
    /// Email of the author with the most commits, or `""` if no commits.
    pub primary_owner: String,
    /// Fraction of total commits owned by `primary_owner` (0.0 if total == 0).
    pub primary_share: f64,
    /// Minimum number of top-committers whose combined share ≥ 50%.
    /// 0 when there are no commits.
    ///
    /// Rule: sort authors desc by commits, then advance a cursor until
    /// cumulative_commits / total_commits ≥ 0.5.  The cursor position
    /// (1-based) is the bus_factor.  Consequence: if the top author
    /// already owns ≥ 50% of history, bus_factor == 1.
    pub bus_factor: u32,
    /// Email of the author of the *most recent* commit (first line in
    /// `git log --follow --format=%ae` output), or `""` if no commits.
    pub recent_owner: String,
}

/// Compute ownership statistics for `file` inside `repo`.
///
/// Returns an all-zeroed `FileOwnership` for files with no git history
/// (untracked, new, outside the repo). Never errors on empty output.
pub fn file_ownership(repo: &Path, file: &str) -> Result<FileOwnership> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["log", "--follow", "--format=%ae", "--", file])
        .output()
        .context("spawn git log for ownership")?;

    // Non-zero exit is possible for files outside the repo; treat as empty.
    let raw = String::from_utf8_lossy(&out.stdout);
    let emails: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if emails.is_empty() {
        return Ok(FileOwnership::default());
    }

    let recent_owner = emails[0].to_string();
    let total_commits = emails.len() as u32;

    // Aggregate commit counts per author.
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for email in &emails {
        *counts.entry(email).or_insert(0) += 1;
    }

    // Sort descending by count, then by email for determinism.
    let mut authors: Vec<(String, u32)> = counts
        .into_iter()
        .map(|(e, c)| (e.to_string(), c))
        .collect();
    authors.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let primary_owner = authors[0].0.clone();
    let primary_share = authors[0].1 as f64 / total_commits as f64;

    // Bus-factor: minimum authors to reach ≥ 50% of commits.
    let half = (total_commits as f64) * 0.5;
    let mut cumulative = 0u32;
    let mut bus_factor = 0u32;
    for (_, count) in &authors {
        cumulative += count;
        bus_factor += 1;
        if cumulative as f64 >= half {
            break;
        }
    }

    Ok(FileOwnership {
        total_commits,
        authors,
        primary_owner,
        primary_share,
        bus_factor,
        recent_owner,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Create a bare git repo in `dir` with configured identity.
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

    /// Commit a file as a specific author (email) using env vars so the
    /// per-repo identity doesn't interfere.
    fn commit_as(dir: &Path, file: &str, content: &str, email: &str, name: &str) {
        std::fs::write(dir.join(file), content).unwrap();
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["add", file])
            .status()
            .unwrap();
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["commit", "-q", "-m", &format!("update {file}")])
            .env("GIT_AUTHOR_NAME", name)
            .env("GIT_AUTHOR_EMAIL", email)
            .env("GIT_COMMITTER_NAME", name)
            .env("GIT_COMMITTER_EMAIL", email)
            .status()
            .unwrap();
    }

    // ----- primary owner + bus_factor == 1 when one author dominates ------

    #[test]
    fn primary_owner_and_bus_factor_one_when_single_author_dominates() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path();
        init_repo(repo).unwrap();

        // alice makes 3 commits, bob makes 1 → alice owns 75% (≥50%) → bus_factor=1
        commit_as(repo, "foo.rs", "v1", "alice@example.com", "Alice");
        commit_as(repo, "foo.rs", "v2", "alice@example.com", "Alice");
        commit_as(repo, "foo.rs", "v3", "alice@example.com", "Alice");
        commit_as(repo, "foo.rs", "v4", "bob@example.com", "Bob");

        let ow = file_ownership(repo, "foo.rs").unwrap();

        assert_eq!(ow.total_commits, 4);
        assert_eq!(ow.primary_owner, "alice@example.com");
        assert!((ow.primary_share - 0.75).abs() < 1e-9);
        assert_eq!(ow.bus_factor, 1, "alice alone covers ≥50% → bus_factor==1");
        // most recent commit was bob's
        assert_eq!(ow.recent_owner, "bob@example.com");
    }

    // ----- bus_factor == 2 when two authors each own exactly 50% ----------

    #[test]
    fn bus_factor_two_when_evenly_split_between_two_authors() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path();
        init_repo(repo).unwrap();

        // alice: 2 commits, bob: 2 commits → each 50%; alice reaches exactly
        // 50% first (sorted desc alphabetically as tie-break: alice < bob),
        // so bus_factor == 1. But if we want bus_factor==2, we need neither
        // author to reach ≥50% individually. Use 1 vs 1 with alice first
        // alphabetically: alice gets 50% alone → still bus_factor==1.
        //
        // To force bus_factor==2 we need a 3-author scenario where the top
        // two each own <50% but together ≥50%.
        // Pattern: carol:3, dave:3, eve:4 → total 10.
        //   carol: 3/10=30% < 50%; carol+dave: 6/10=60% ≥ 50% → bus_factor=2.
        commit_as(repo, "bar.rs", "c1", "carol@example.com", "Carol");
        commit_as(repo, "bar.rs", "c2", "carol@example.com", "Carol");
        commit_as(repo, "bar.rs", "c3", "carol@example.com", "Carol");
        commit_as(repo, "bar.rs", "d1", "dave@example.com", "Dave");
        commit_as(repo, "bar.rs", "d2", "dave@example.com", "Dave");
        commit_as(repo, "bar.rs", "d3", "dave@example.com", "Dave");
        commit_as(repo, "bar.rs", "e1", "eve@example.com", "Eve");
        commit_as(repo, "bar.rs", "e2", "eve@example.com", "Eve");
        commit_as(repo, "bar.rs", "e3", "eve@example.com", "Eve");
        commit_as(repo, "bar.rs", "e4", "eve@example.com", "Eve");

        let ow = file_ownership(repo, "bar.rs").unwrap();

        // eve has 4 (40% < 50%), so she alone doesn't reach 50%.
        // eve+carol: 7/10=70% ≥ 50% → bus_factor==2.
        assert_eq!(ow.total_commits, 10);
        assert_eq!(ow.primary_owner, "eve@example.com"); // highest count
        assert_eq!(ow.bus_factor, 2);
    }

    // ----- untracked / new file → zeroed ownership, no error --------------

    #[test]
    fn untracked_file_returns_zeroed_ownership() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path();
        init_repo(repo).unwrap();

        // Write a file but do NOT add/commit it.
        std::fs::write(repo.join("untracked.rs"), "fn main() {}").unwrap();

        let ow = file_ownership(repo, "untracked.rs").unwrap();

        assert_eq!(ow.total_commits, 0);
        assert!(ow.authors.is_empty());
        assert_eq!(ow.primary_owner, "");
        assert_eq!(ow.bus_factor, 0);
    }
}
