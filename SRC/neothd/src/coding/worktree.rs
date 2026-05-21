//! Pick #6 Phase 4 — task-scoped git worktree helpers.
//!
//! Per Chorus chat `019E49EAC4EACB805644D020B8F74A03` (codex-cli
//! + gemini-cli both picked Strategy B). Full verdict in
//! `PLAN/CHORUS_pick6_phase4_VERDICT.md`.
//!
//! ## Why per-task worktree (not direct apply, not stash)
//!
//! The worker produced a unified-diff patch + tests. Phase 4
//! actually applies it. Three strategies on the table:
//!
//!   A — `git apply` in the operator's checkout. Rejected: races
//!       with operator edits + parallel workers, no rollback.
//!   B — `git worktree add` per task. Adopted: isolation,
//!       deterministic cleanup, no operator-state pollution.
//!   C — `git stash` + apply + revert-on-fail. Rejected:
//!       stash is global-ish + brittle under concurrency.
//!
//! ## What this module owns
//!
//! Pure helpers:
//!   - [`worktree_path_for`] — deterministic path derivation
//!     given the repo root + task id.
//!   - [`PatchApplyOutcome`] — typed result of one apply attempt.
//!
//! Side-effect helpers (each shells out to `git`):
//!   - [`is_worktree_dirty`] — `git status --porcelain` against
//!     the worktree path.
//!   - [`create_task_worktree`] — `git worktree add` from
//!     `HEAD` of the operator's repo into the task path.
//!   - [`apply_patch_in_worktree`] — `git apply --check` then
//!     `git apply` against the patch file, inside the
//!     worktree. Returns the typed outcome.
//!   - [`cleanup_worktree`] — `git worktree remove` on success
//!     or operator-requested rollback.
//!
//! Side-effect helpers depend on the operator having `git` on
//! the PATH. The daemon's `cli::doctor` reports a clear
//! diagnostic when `which git` fails so the operator sees the
//! missing-tool root cause before reaching this module.
//!
//! ## What this module does NOT do
//!
//! - Test execution. Worker → patch → apply → tests is the full
//!   chain; the test command (`cargo check` / `pytest` / …) lives
//!   in `freedom.yaml::coding.test_cmd` and runs from the
//!   dispatcher, not here.
//!   `apply_patch_in_worktree` returns the path to the worktree
//!   so the dispatcher can spawn its test process there.
//! - WAL emission. The dispatcher records `0xD3 PATCH_APPLIED`
//!   (success) or `0xD4 PATCH_APPLY_FAILED` (apply or test fail)
//!   based on this module's outcome.
//! - Permission gating. The dispatcher consults
//!   `permissions::evaluate(WriteToRepo, level)` BEFORE calling
//!   into this module; the per-autonomy confirm prompt lives in
//!   the dispatcher's CLI surface (`neoth code` invocation),
//!   not the worktree helper.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::coding::types::KanbanTaskId;

/// Typed outcome of one `apply_patch_in_worktree` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchApplyOutcome {
    /// `git apply --check` AND `git apply` both succeeded.
    /// `worktree_path` is the path tests should run against;
    /// caller spawns the test command there.
    Applied { worktree_path: PathBuf },
    /// `git apply --check` (or the apply itself) rejected the
    /// patch. `stderr` carries git's diagnostic so the operator
    /// (or the retry-policy's hint generator) sees the conflict
    /// reason verbatim. The worktree was created but is left in
    /// whatever state `git apply` produced; cleanup is the
    /// caller's responsibility.
    Rejected { stderr: String },
}

impl PatchApplyOutcome {
    pub fn is_applied(&self) -> bool {
        matches!(self, PatchApplyOutcome::Applied { .. })
    }
}

/// Derive the task-scoped worktree path from the operator's
/// repo root + the task id. Pure function — separate so the
/// dispatcher can probe the path (for an existing-worktree
/// check) without doing IO.
///
/// Format: `<repo_parent>/.neoth-task-<task_id>/`.
///
/// We deliberately put the worktree as a SIBLING of the repo
/// (not inside it) so it doesn't appear in the operator's
/// `git status` of the main checkout + so `.gitignore` rules
/// don't have to know about it.
pub fn worktree_path_for(repo_root: &Path, task_id: KanbanTaskId) -> PathBuf {
    let parent = repo_root.parent().unwrap_or(repo_root);
    parent.join(format!(".neoth-task-{}", task_id.raw()))
}

/// Run `git status --porcelain` against `path` and return true
/// when the output is non-empty (i.e. the worktree has
/// uncommitted changes). Per the Chorus verdict, Phase 4 MUST
/// refuse to apply onto a dirty task worktree — the patch is
/// expected to land on a clean tree from HEAD.
pub fn is_worktree_dirty(path: &Path) -> Result<bool> {
    let out = Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("status")
        .arg("--porcelain")
        .output()
        .context("spawn git status --porcelain")?;
    if !out.status.success() {
        anyhow::bail!(
            "git status --porcelain failed (exit {}): {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(!out.stdout.is_empty())
}

/// Create the task-scoped worktree from `HEAD` of `repo_root`.
/// Returns the path so the caller can chain apply + test.
///
/// The worktree carries the operator's current HEAD — a future
/// follow-up adds a `from_ref: &str` parameter so the
/// dispatcher can pin against a specific branch / commit when
/// the operator has a multi-step session that builds on a prior
/// task's patch.
pub fn create_task_worktree(repo_root: &Path, task_id: KanbanTaskId) -> Result<PathBuf> {
    let path = worktree_path_for(repo_root, task_id);
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("worktree")
        .arg("add")
        .arg("--detach")
        .arg(&path)
        .arg("HEAD")
        .output()
        .context("spawn git worktree add")?;
    if !out.status.success() {
        anyhow::bail!(
            "git worktree add failed (exit {}): {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(path)
}

/// Apply a unified-diff patch file inside a task worktree.
/// Two-pass: `git apply --check` first (dry-run), then the
/// real `git apply` if check passed.
///
/// `worktree` MUST be clean before this call. Caller verifies
/// via [`is_worktree_dirty`] + refuses up-front.
pub fn apply_patch_in_worktree(worktree: &Path, patch: &Path) -> Result<PatchApplyOutcome> {
    let check = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .arg("apply")
        .arg("--check")
        .arg(patch)
        .output()
        .context("spawn git apply --check")?;
    if !check.status.success() {
        return Ok(PatchApplyOutcome::Rejected {
            stderr: String::from_utf8_lossy(&check.stderr).trim().to_string(),
        });
    }

    let apply = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .arg("apply")
        .arg(patch)
        .output()
        .context("spawn git apply (real)")?;
    if !apply.status.success() {
        return Ok(PatchApplyOutcome::Rejected {
            stderr: String::from_utf8_lossy(&apply.stderr).trim().to_string(),
        });
    }

    Ok(PatchApplyOutcome::Applied {
        worktree_path: worktree.to_path_buf(),
    })
}

/// Remove a task worktree. Mirrors `git worktree remove` —
/// fails when the worktree has uncommitted changes UNLESS
/// `force` is true.
pub fn cleanup_worktree(repo_root: &Path, worktree: &Path, force: bool) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo_root)
        .arg("worktree")
        .arg("remove");
    if force {
        cmd.arg("--force");
    }
    cmd.arg(worktree);
    let out = cmd.output().context("spawn git worktree remove")?;
    if !out.status.success() {
        anyhow::bail!(
            "git worktree remove failed (exit {}): {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Compute the SHA-256 of a patch file body. Used by the WAL
/// emit (0xD3 PATCH_APPLIED) so the audit anchor carries an
/// immutable reference to exactly which patch was applied;
/// helpful when the operator reviews the chain later or runs
/// `neoth rollback`. Returns lowercase hex.
pub fn patch_hash(patch: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(patch)
        .with_context(|| format!("read patch {} for hash", patch.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        hex.push(TABLE[(b >> 4) as usize] as char);
        hex.push(TABLE[(b & 0x0f) as usize] as char);
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_patch(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("change.patch");
        std::fs::write(&p, body).unwrap();
        p
    }

    fn init_git_repo(dir: &Path) -> Result<()> {
        // Init + identity + initial commit so HEAD points
        // somewhere. Tests skip when `git` isn't on PATH.
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["init", "-q"])
            .status()?;
        // Configure local identity so the commit succeeds in CI.
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "user.email", "neoth-test@example.com"])
            .status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "user.name", "neoth-test"])
            .status()?;
        std::fs::write(dir.join("README.md"), "initial\n")?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["add", "README.md"])
            .status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["commit", "-q", "-m", "init"])
            .status()?;
        Ok(())
    }

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn worktree_path_for_lives_next_to_repo_root() {
        let path =
            worktree_path_for(Path::new("/home/alice/code/proj"), KanbanTaskId(42));
        assert_eq!(path, PathBuf::from("/home/alice/code/.neoth-task-42"));
    }

    #[test]
    fn worktree_path_for_handles_root_without_parent() {
        // Edge case: repo root is `/`. Should still produce a
        // reasonable path rather than panic.
        let path = worktree_path_for(Path::new("/"), KanbanTaskId(7));
        // On Windows the join may differ; assert the suffix.
        assert!(path.to_string_lossy().contains(".neoth-task-7"));
    }

    #[test]
    fn apply_outcome_is_applied_flag_matches_variant() {
        let applied = PatchApplyOutcome::Applied {
            worktree_path: PathBuf::from("/tmp/wt"),
        };
        assert!(applied.is_applied());
        let rejected = PatchApplyOutcome::Rejected {
            stderr: "patch does not apply".to_string(),
        };
        assert!(!rejected.is_applied());
    }

    #[test]
    fn patch_hash_round_trips_known_text() {
        let dir = tempdir().unwrap();
        let p = write_patch(dir.path(), "diff --git a/x b/x\n");
        let h = patch_hash(&p).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Identical input → identical hash.
        let h2 = patch_hash(&p).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn patch_hash_differs_for_different_body() {
        let dir = tempdir().unwrap();
        let p1 = write_patch(dir.path(), "patch one");
        std::fs::write(dir.path().join("two.patch"), "patch two").unwrap();
        let h1 = patch_hash(&p1).unwrap();
        let h2 = patch_hash(&dir.path().join("two.patch")).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn create_and_remove_worktree_round_trip() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_git_repo(&repo).unwrap();

        let task = KanbanTaskId(101);
        let wt = create_task_worktree(&repo, task).expect("worktree add");
        assert!(wt.exists(), "worktree dir created at {}", wt.display());
        assert!(wt.join("README.md").exists(), "HEAD content present");

        // Clean worktree → not dirty.
        assert!(!is_worktree_dirty(&wt).unwrap());

        // Mutate a tracked file → dirty.
        std::fs::write(wt.join("README.md"), "modified\n").unwrap();
        assert!(is_worktree_dirty(&wt).unwrap());

        // Cleanup (force because we made it dirty).
        cleanup_worktree(&repo, &wt, true).expect("worktree remove");
        assert!(!wt.exists());
    }

    #[test]
    fn apply_patch_in_worktree_returns_applied_on_clean_patch() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_git_repo(&repo).unwrap();

        let task = KanbanTaskId(202);
        let wt = create_task_worktree(&repo, task).expect("worktree add");

        // Build a patch that adds a single line to README.md.
        // Use line-by-line vec push so leading spaces on context
        // lines are preserved (`\n\` line-continuation in a
        // string literal eats whitespace on the next line).
        let patch_lines = [
            "diff --git a/README.md b/README.md",
            "--- a/README.md",
            "+++ b/README.md",
            "@@ -1 +1,2 @@",
            " initial",
            "+second line",
            "",
        ];
        let patch_body = patch_lines.join("\n");
        let patch = dir.path().join("change.patch");
        std::fs::write(&patch, patch_body).unwrap();

        let outcome = apply_patch_in_worktree(&wt, &patch).expect("apply");
        match outcome {
            PatchApplyOutcome::Applied { worktree_path } => {
                assert_eq!(worktree_path, wt);
                let body = std::fs::read_to_string(wt.join("README.md")).unwrap();
                assert!(body.contains("second line"), "patch applied");
            }
            PatchApplyOutcome::Rejected { stderr } => {
                panic!("expected Applied, got Rejected: {stderr}");
            }
        }

        let _ = cleanup_worktree(&repo, &wt, true);
    }

    #[test]
    fn apply_patch_in_worktree_returns_rejected_on_conflict() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        init_git_repo(&repo).unwrap();

        let task = KanbanTaskId(303);
        let wt = create_task_worktree(&repo, task).expect("worktree add");

        // Patch references a file that doesn't exist + an
        // impossible context — git apply --check rejects.
        let patch_lines = [
            "diff --git a/nonexistent.txt b/nonexistent.txt",
            "--- a/nonexistent.txt",
            "+++ b/nonexistent.txt",
            "@@ -1 +1,2 @@",
            " line that does not exist",
            "+new line",
            "",
        ];
        let patch_body = patch_lines.join("\n");
        let patch = dir.path().join("bad.patch");
        std::fs::write(&patch, patch_body).unwrap();

        let outcome = apply_patch_in_worktree(&wt, &patch).expect("apply call");
        match outcome {
            PatchApplyOutcome::Rejected { stderr } => {
                assert!(!stderr.is_empty(), "rejection must carry git diagnostic");
            }
            PatchApplyOutcome::Applied { .. } => {
                panic!("expected Rejected, got Applied");
            }
        }

        let _ = cleanup_worktree(&repo, &wt, true);
    }
}
