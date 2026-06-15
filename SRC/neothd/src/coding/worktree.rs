//! Pick #6 Phase 4 — task-scoped git worktree helpers.
//!
//! Per Chorus chat `019E49EAC4EACB805644D020B8F74A03` (codex-cli +
//! gemini-cli both picked Strategy B). Full verdict in
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
    cmd.arg("-C").arg(repo_root).arg("worktree").arg("remove");
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

/// Outcome of one test-command invocation inside a worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    /// Command exited with status 0. Patch + tests are green;
    /// the dispatcher transitions the task to Review.
    Passed,
    /// Command exited non-zero OR the wall-clock timeout fired.
    /// `reason` carries the trimmed stderr (or "timed out
    /// after Ns") so the retry-policy hint generator surfaces
    /// the diagnostic.
    Failed { reason: String },
}

impl TestOutcome {
    pub fn is_passed(&self) -> bool {
        matches!(self, TestOutcome::Passed)
    }
}

/// Captured result of one child-process run: the exit status
/// (`None` == timed out + killed) plus the fully-drained stdout +
/// stderr byte streams.
struct CapturedRun {
    exit: Option<std::process::ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Drain a child pipe to completion on its own thread so a full pipe
/// buffer can't deadlock the parent's wait loop. Generic over
/// stdout/stderr (both are `Read + Send`).
fn drain_pipe<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
) -> Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>> {
    pipe.map(|mut p| {
        std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            p.read_to_end(&mut buf)?;
            Ok(buf)
        })
    })
}

/// Spawn `program args` in `cwd`, drain both pipes off threads, and
/// poll for completion with a wall-clock `timeout` (100 ms ticks).
/// A timed-out child is killed + reaped; `exit` is then `None`.
/// `Err` only on spawn failure — a non-zero exit is a normal
/// `CapturedRun`, not an error, so callers classify it themselves.
fn spawn_and_capture(
    program: &str,
    args: &[&str],
    cwd: &Path,
    timeout: std::time::Duration,
    ctx: &str,
) -> Result<CapturedRun> {
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {ctx} in {}", cwd.display()))?;

    let stdout_join = drain_pipe(child.stdout.take());
    let stderr_join = drain_pipe(child.stderr.take());

    let started = std::time::Instant::now();
    let exit = loop {
        match child.try_wait().context("child try_wait")? {
            Some(status) => break Some(status),
            None => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    };

    let stdout = stdout_join
        .and_then(|j| j.join().ok())
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let stderr = stderr_join
        .and_then(|j| j.join().ok())
        .and_then(|r| r.ok())
        .unwrap_or_default();

    Ok(CapturedRun {
        exit,
        stdout,
        stderr,
    })
}

/// Spawn the operator-configured test command inside a
/// worktree. `cmd` is split on whitespace into argv — operators
/// who need shell features wrap in a script. The wall-clock
/// `timeout` caps a hung test so the dispatcher loop stays
/// responsive.
///
/// Returns Err only for IO failures spawning the process;
/// non-zero exit + timeout are reported as `TestOutcome::Failed`
/// so the caller can route through the retry-policy path
/// without panicking.
pub fn run_test_cmd(
    worktree: &Path,
    cmd: &str,
    timeout: std::time::Duration,
) -> Result<TestOutcome> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        anyhow::bail!("empty test command — operator must set freedom.yaml::coding.test_cmd");
    }
    let (program, args) = parts.split_first().expect("non-empty by guard");

    let run = spawn_and_capture(
        program,
        args,
        worktree,
        timeout,
        &format!("test command `{cmd}`"),
    )?;
    let log_path = write_test_log(worktree, cmd, &run.stdout, &run.stderr, &run.exit);

    let Some(status) = run.exit else {
        return Ok(TestOutcome::Failed {
            reason: format!(
                "timed out after {}s — full log: {}",
                timeout.as_secs(),
                log_path.display()
            ),
        });
    };

    if status.success() {
        Ok(TestOutcome::Passed)
    } else {
        // Tail of stderr is the most operator-useful summary;
        // full streams sit in the log file for inspection.
        let tail = String::from_utf8_lossy(&run.stderr);
        let trimmed = tail.trim();
        let head = if trimmed.is_empty() {
            format!("exit code {}", status.code().unwrap_or(-1))
        } else {
            // Cap inline reason at ~400 chars — the WAL frame's
            // `reason` field passes through the dispatcher's
            // redact_text + we don't want a 64 KiB compiler dump
            // inline. Walk back to a UTF-8 char boundary so a
            // multibyte rustc arrow (`-->`) at the cut can't panic.
            let max = 400;
            if trimmed.len() > max {
                let mut end = max;
                while end > 0 && !trimmed.is_char_boundary(end) {
                    end -= 1;
                }
                let mut s = trimmed[..end].to_string();
                s.push_str(&format!(
                    "... ({} more bytes — see {})",
                    trimmed.len() - end,
                    log_path.display()
                ));
                s
            } else {
                trimmed.to_string()
            }
        };
        Ok(TestOutcome::Failed { reason: head })
    }
}

/// QU-05 — run `cargo check --message-format=json` inside a task
/// worktree and parse the structured diagnostics. The Rust analogue
/// of smallcode's `node --check` post-write pass: the dispatcher
/// feeds [`CargoCheckRun::diagnostics`] into
/// [`crate::coding::cargo_check::retry_hint_from_cargo_json`] so a
/// failing check re-injects rustc's own errors (capped, deduped) into
/// the next worker attempt.
///
/// `cmd` is the operator's configured cargo-check command (e.g.
/// `"cargo check"` or `"cargo check --workspace"`); its flags are
/// forwarded verbatim and `--message-format=json` is appended unless
/// the operator already set a `--message-format`.
///
/// `Err` only on spawn failure. A non-zero exit / timeout / compile
/// errors are reported in the returned `CargoCheckRun` (`passed =
/// false`) so the caller routes through the retry path without
/// panicking — same contract as [`run_test_cmd`].
pub fn run_cargo_check_json(
    worktree: &Path,
    cmd: &str,
    timeout: std::time::Duration,
) -> Result<CargoCheckRun> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        anyhow::bail!("empty cargo-check command");
    }
    let (program, op_args) = parts.split_first().expect("non-empty by guard");
    let mut args: Vec<&str> = op_args.to_vec();
    if !args.iter().any(|a| a.starts_with("--message-format")) {
        args.push("--message-format=json");
    }
    let run = spawn_and_capture(program, &args, worktree, timeout, cmd)?;
    let log_path = write_test_log(worktree, cmd, &run.stdout, &run.stderr, &run.exit);
    // rustc emits the JSON diagnostic objects on stdout; the final
    // "could not compile" line goes to stderr.
    let diagnostics =
        crate::coding::cargo_check::parse_cargo_check_json(&String::from_utf8_lossy(&run.stdout));
    let timed_out = run.exit.is_none();
    // passed = clean exit AND no hard errors in the JSON. A timeout
    // (exit None) is never a pass.
    let passed = run.exit.map(|s| s.success()).unwrap_or(false)
        && !crate::coding::cargo_check::has_errors(&diagnostics);
    Ok(CargoCheckRun {
        passed,
        timed_out,
        diagnostics,
        log_path,
    })
}

/// Outcome of one [`run_cargo_check_json`] invocation.
#[derive(Debug, Clone)]
pub struct CargoCheckRun {
    /// `cargo check` exited 0 AND no hard errors were parsed.
    pub passed: bool,
    /// The wall-clock timeout fired (child was killed). `passed` is
    /// always false in this case; `diagnostics` holds whatever was
    /// captured before the kill.
    pub timed_out: bool,
    /// Parsed compiler diagnostics (errors + warnings), in emit order.
    pub diagnostics: Vec<crate::coding::cargo_check::CargoDiagnostic>,
    /// Path to the persisted full-output log for operator inspection.
    pub log_path: PathBuf,
}

/// Persist the test command's full output streams under
/// `<worktree>/.neoth-test-output.log` so the operator can
/// inspect after a failed task without re-running. Always
/// writes (pass + fail) since `cargo test` success output is
/// useful too (which tests ran, timing). Best-effort — IO
/// failure here just degrades to "no log file"; the caller's
/// outcome is unaffected.
fn write_test_log(
    worktree: &Path,
    cmd: &str,
    stdout: &[u8],
    stderr: &[u8],
    exit: &Option<std::process::ExitStatus>,
) -> PathBuf {
    let log_path = worktree.join(".neoth-test-output.log");
    let exit_line = match exit {
        Some(s) => format!("exit_status: {}", s.code().unwrap_or(-1)),
        None => "exit_status: TIMEOUT".to_string(),
    };
    // GOLD-SEC-14 / A-33: test tooling can print tokens / paths / env, so
    // redact stdout+stderr before persisting them to disk.
    let stdout_lossy = String::from_utf8_lossy(stdout);
    let stderr_lossy = String::from_utf8_lossy(stderr);
    let stdout_red = crate::security::redact::redact_text(&stdout_lossy);
    let stderr_red = crate::security::redact::redact_text(&stderr_lossy);
    let body = format!(
        "# NEOTH Phase 4 test-output log\n\
         # cmd: {cmd}\n\
         # worktree: {}\n\
         # {exit_line}\n\
         # written_unix_ms: {}\n\
         \n\
         ## stdout ({} bytes)\n\n\
         {stdout_red}\n\
         ## stderr ({} bytes)\n\n\
         {stderr_red}\n",
        worktree.display(),
        crate::time::now_unix_ms_u128(),
        stdout.len(),
        stderr.len(),
    );
    // Write mode-0600 (A-33): the log may still hold redaction-missed
    // sensitive fragments; keep it owner-only rather than world-readable.
    let _ = crate::config::credentials::write_mode_0600(&log_path, body.as_bytes());
    log_path
}

/// Compute the SHA-256 of a patch file body. Used by the WAL
/// emit (0xD3 PATCH_APPLIED) so the audit anchor carries an
/// immutable reference to exactly which patch was applied;
/// helpful when the operator reviews the chain later or runs
/// `neoth rollback`. Returns lowercase hex.
pub fn patch_hash(patch: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes =
        std::fs::read(patch).with_context(|| format!("read patch {} for hash", patch.display()))?;
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
        let path = worktree_path_for(Path::new("/home/alice/code/proj"), KanbanTaskId(42));
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
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
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

    // ── run_test_cmd ───────────────────────────────────────────────

    /// Returns a command that always exits 0, cross-platform.
    /// Windows: `cmd /C exit 0`. Unix: `true`.
    fn always_pass_cmd() -> String {
        if cfg!(windows) {
            "cmd /C exit 0".to_string()
        } else {
            "true".to_string()
        }
    }

    /// Returns a command that always exits non-zero.
    fn always_fail_cmd() -> String {
        if cfg!(windows) {
            "cmd /C exit 1".to_string()
        } else {
            "false".to_string()
        }
    }

    #[test]
    fn run_test_cmd_reports_passed_on_zero_exit() {
        let dir = tempdir().unwrap();
        let outcome = run_test_cmd(
            dir.path(),
            &always_pass_cmd(),
            std::time::Duration::from_secs(10),
        )
        .expect("spawn");
        assert!(outcome.is_passed(), "got {outcome:?}");
    }

    #[test]
    fn run_test_cmd_reports_failed_on_nonzero_exit() {
        let dir = tempdir().unwrap();
        let outcome = run_test_cmd(
            dir.path(),
            &always_fail_cmd(),
            std::time::Duration::from_secs(10),
        )
        .expect("spawn");
        assert!(!outcome.is_passed());
        if let TestOutcome::Failed { reason } = outcome {
            assert!(!reason.is_empty(), "diagnostic must be non-empty");
        }
    }

    #[test]
    fn run_test_cmd_errors_on_empty_command() {
        let dir = tempdir().unwrap();
        let err = run_test_cmd(dir.path(), "   ", std::time::Duration::from_secs(1))
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"), "diagnostic: {err}");
    }

    #[test]
    fn run_test_cmd_writes_test_output_log_on_pass() {
        let dir = tempdir().unwrap();
        let outcome = run_test_cmd(
            dir.path(),
            &always_pass_cmd(),
            std::time::Duration::from_secs(10),
        )
        .expect("spawn");
        assert!(outcome.is_passed());
        let log = dir.path().join(".neoth-test-output.log");
        assert!(log.exists(), "test log must exist after pass");
        let body = std::fs::read_to_string(&log).unwrap();
        assert!(body.contains("## stdout"));
        assert!(body.contains("## stderr"));
        assert!(body.contains("exit_status: 0"));
    }

    #[test]
    fn run_test_cmd_writes_log_on_fail_with_nonzero_exit_status() {
        let dir = tempdir().unwrap();
        let outcome = run_test_cmd(
            dir.path(),
            &always_fail_cmd(),
            std::time::Duration::from_secs(10),
        )
        .expect("spawn");
        assert!(!outcome.is_passed());
        let log = dir.path().join(".neoth-test-output.log");
        assert!(log.exists(), "test log must exist after fail");
        let body = std::fs::read_to_string(&log).unwrap();
        assert!(body.contains("exit_status: 1"));
    }

    #[test]
    fn run_test_cmd_errors_when_program_missing() {
        // A binary that doesn't exist on PATH must surface as Err
        // (spawn failed), not as TestOutcome::Failed — the caller
        // distinguishes "your test runner is broken" from "tests
        // failed".
        let dir = tempdir().unwrap();
        let err = run_test_cmd(
            dir.path(),
            "neoth-totally-fictional-binary-9000",
            std::time::Duration::from_secs(1),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("spawn") || err.contains("not found"),
            "got: {err}"
        );
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

    // ── run_cargo_check_json ───────────────────────────────────────

    fn cargo_available() -> bool {
        Command::new("cargo")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn run_cargo_check_json_on_dir_without_manifest_is_not_passed() {
        if !cargo_available() {
            eprintln!("skipping: cargo not on PATH");
            return;
        }
        // A bare tempdir (under the system temp, no parent Cargo.toml)
        // → `cargo check` errors "could not find Cargo.toml": spawn
        // succeeds, exit is non-zero, so passed == false and the run
        // did not time out. Proves the glue without needing a full
        // crate fixture (the JSON parse + spawn capture are covered by
        // their own tests).
        let dir = tempdir().unwrap();
        let run = run_cargo_check_json(
            dir.path(),
            "cargo check",
            std::time::Duration::from_secs(60),
        )
        .expect("spawn cargo");
        assert!(!run.passed, "no-manifest check must not be a pass");
        assert!(!run.timed_out, "should error fast, not time out");
        assert!(run.log_path.exists(), "full-output log must be written");
    }
}
