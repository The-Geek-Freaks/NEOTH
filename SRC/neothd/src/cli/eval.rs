//! GOLD-ADAPT-HARNESS-05 — `neoth eval <suite.json>`: JSON EvalCase suite runner.
//!
//! Reads a JSON array of [`EvalCase`] from a file, executes each case through the
//! answer-check logic (headless, no live LLM — just the verifier), and produces an
//! [`EvalReport`] in JSON + a Markdown render.
//!
//! Design adapted from opencode-harness `eval.py`.  NEOTH's version is fully
//! self-contained: the verification step is deterministic (substring containment
//! check + optional shell command exit-code gate), so the suite runner is safe to
//! use in CI without network or provider keys.
//!
//! Output files are written to `<neoth_home>/eval-runs/<ts>/report.json` and
//! `report.md`.  A summary table is always printed to stdout.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A single eval case in the suite JSON.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvalCase {
    /// Unique identifier for the case (e.g. `"tc-01"`).
    pub id: String,
    /// Human-readable description shown in the Markdown report.
    pub description: String,
    /// The prompt / question to evaluate.
    pub prompt: String,
    /// The answer / model output to verify against.  In headless mode this is
    /// supplied directly in the suite; in live mode it would be the LLM reply.
    #[serde(default)]
    pub answer: Option<String>,
    /// The answer must contain this substring (case-insensitive) to pass.
    #[serde(default)]
    pub expect_contains: Option<String>,
    /// Shell command to run; passes if exit code is 0.
    #[serde(default)]
    pub verify_command: Option<String>,
    /// Maximum allowed steps for this case.  When the suite step budget
    /// (`EvalArgs::max_steps`) is exhausted, the case is not executed and
    /// receives a bounded [`CaseOutcome::Error`] verdict.
    #[serde(default)]
    pub max_steps: Option<u32>,
}

/// Outcome of a single case run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    Pass,
    Fail,
    Error,
}

/// Per-case result captured in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub id: String,
    pub description: String,
    pub outcome: CaseOutcome,
    /// One-line reason for the outcome (non-empty on Fail/Error).
    pub failure_reason: Option<String>,
    /// Wall-clock seconds the case took.
    pub elapsed_secs: f64,
    /// Number of "steps" consumed (always 1 in headless mode).
    pub steps: u32,
}

/// Aggregate report for the whole suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub suite_path: String,
    pub timestamp_unix: u64,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub errored: usize,
    pub elapsed_secs: f64,
    pub cases: Vec<CaseResult>,
}

impl EvalReport {
    /// Return true iff every case passed.
    pub fn all_passed(&self) -> bool {
        self.passed == self.total
    }

    /// Render a Markdown report string.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# NEOTH Eval Report\n\n");
        md.push_str(&format!("**Suite:** `{}`\n\n", self.suite_path));
        let ts = self.timestamp_unix;
        md.push_str(&format!("**Run at (unix):** {ts}\n\n"));
        md.push_str(&format!(
            "**Result:** {}/{} passed ({} failed, {} errored) in {:.2}s\n\n",
            self.passed, self.total, self.failed, self.errored, self.elapsed_secs
        ));
        md.push_str("## Cases\n\n");
        md.push_str("| # | ID | Description | Outcome | Elapsed | Reason |\n");
        md.push_str("|---|-----|-------------|---------|---------|--------|\n");
        for (i, c) in self.cases.iter().enumerate() {
            let icon = match c.outcome {
                CaseOutcome::Pass => "✅",
                CaseOutcome::Fail => "❌",
                CaseOutcome::Error => "⚠️",
            };
            let reason = c.failure_reason.as_deref().unwrap_or("-");
            md.push_str(&format!(
                "| {} | `{}` | {} | {} {} | {:.3}s | {} |\n",
                i + 1,
                c.id,
                c.description,
                icon,
                match c.outcome {
                    CaseOutcome::Pass => "Pass",
                    CaseOutcome::Fail => "Fail",
                    CaseOutcome::Error => "Error",
                },
                c.elapsed_secs,
                reason,
            ));
        }
        md.push('\n');
        if self.all_passed() {
            md.push_str("**Overall: PASS**\n");
        } else {
            md.push_str("**Overall: FAIL**\n");
        }
        md
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core evaluation logic (no LLM; deterministic verifiers)
// ─────────────────────────────────────────────────────────────────────────────

/// Run a single [`EvalCase`] and return its [`CaseResult`].
///
/// Verification order (first matching check wins):
/// 1. `expect_contains` — case-insensitive substring check on `answer`.
/// 2. `verify_command` — shell command; passes iff exit code is 0.
/// 3. No verifier present → auto-Pass (the case is a prompt-only smoke test).
pub fn run_case(case: &EvalCase) -> CaseResult {
    let start = Instant::now();

    let (outcome, failure_reason) = evaluate_case(case);

    CaseResult {
        id: case.id.clone(),
        description: case.description.clone(),
        outcome,
        failure_reason,
        elapsed_secs: start.elapsed().as_secs_f64(),
        steps: 1,
    }
}

fn evaluate_case(case: &EvalCase) -> (CaseOutcome, Option<String>) {
    // 1. Substring containment check.
    if let Some(ref needle) = case.expect_contains {
        let answer = case.answer.as_deref().unwrap_or("");
        let needle_lower = needle.to_lowercase();
        let answer_lower = answer.to_lowercase();
        if !answer_lower.contains(&needle_lower) {
            return (
                CaseOutcome::Fail,
                Some(format!(
                    "answer does not contain expected substring {:?} (answer: {:?})",
                    needle,
                    truncate(answer, 120),
                )),
            );
        }
        return (CaseOutcome::Pass, None);
    }

    // 2. Shell-command verifier.
    if let Some(ref cmd) = case.verify_command {
        match run_verify_command(cmd, VERIFY_COMMAND_TIMEOUT) {
            Ok(true) => return (CaseOutcome::Pass, None),
            Ok(false) => {
                return (
                    CaseOutcome::Fail,
                    Some(format!("verify_command exited non-zero: {cmd}")),
                )
            }
            Err(e) => {
                return (
                    CaseOutcome::Error,
                    Some(format!("verify_command error ({cmd}): {e}")),
                )
            }
        }
    }

    // 3. No verifier — smoke test always passes.
    (CaseOutcome::Pass, None)
}

/// Default wall-clock budget for every `verify_command` execution.
/// A child that does not exit within this window is killed.
const VERIFY_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Execute a shell command and return `Ok(true)` iff exit code is 0.
///
/// Spawns the child with piped stdout/stderr; two background threads drain
/// both pipes to prevent pipe-buffer deadlock when the child emits a large
/// amount of output before it exits.  The main thread polls `try_wait` until
/// the child exits or `timeout` elapses.  On timeout the child is killed,
/// reaped, and an error is returned — the drain threads detach and finish
/// on their own once the OS closes the pipes.
fn run_verify_command(cmd: &str, timeout: std::time::Duration) -> Result<bool> {
    use std::io::Read;
    use std::process::Stdio;

    let mut child = std::process::Command::new(if cfg!(windows) { "cmd" } else { "sh" })
        .args(if cfg!(windows) { vec!["/C", cmd] } else { vec!["-c", cmd] })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn verify_command: {cmd}"))?;

    // Drain stdout/stderr in background threads to avoid pipe-buffer deadlock.
    // We do not need the output — only the exit code — so the handles are
    // intentionally detached (not joined).  They finish once the pipes close.
    let mut out_pipe = child.stdout.take().expect("stdout piped");
    let mut err_pipe = child.stderr.take().expect("stderr piped");
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out_pipe.read_to_end(&mut b);
    });
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err_pipe.read_to_end(&mut b);
    });

    // Poll until the child exits or the wall-clock deadline is reached.
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait(); // reap to avoid a zombie process
            anyhow::bail!(
                "verify_command timed out after {timeout:?} and was killed: {cmd}"
            );
        }
        match child
            .try_wait()
            .with_context(|| format!("poll verify_command: {cmd}"))?
        {
            Some(status) => return Ok(status.success()),
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
}

fn truncate(s: &str, max: usize) -> &str {
    &s[..crate::util::byte_floor(s, max)]
}

// ─────────────────────────────────────────────────────────────────────────────
// Suite runner
// ─────────────────────────────────────────────────────────────────────────────

/// Run every case in `cases` and return an [`EvalReport`].
///
/// `max_steps` is a HARD cap on the total steps the suite may consume.  In
/// headless mode each case costs exactly one step.  Once `max_steps` steps
/// are consumed, every remaining case is **not executed** and receives a
/// [`CaseOutcome::Error`] verdict with a "max_steps cap reached" reason.
/// Pass [`u32::MAX`] to allow all cases to run without limit.
pub fn run_suite(suite_path: &str, cases: &[EvalCase], max_steps: u32) -> EvalReport {
    let suite_start = Instant::now();
    // GOLD-ARCH-07 — canonical time helper (overflow-safe), not raw duration_since.
    let timestamp_unix = crate::time::now_unix_secs();

    let mut results = Vec::with_capacity(cases.len());
    let mut steps_used: u32 = 0;
    for case in cases {
        // Hard-cap enforcement — stop + bounded verdict, not log+continue.
        if steps_used >= max_steps {
            results.push(CaseResult {
                id: case.id.clone(),
                description: case.description.clone(),
                outcome: CaseOutcome::Error,
                failure_reason: Some(format!(
                    "not executed: max_steps cap ({max_steps}) reached"
                )),
                elapsed_secs: 0.0,
                steps: 0,
            });
            continue;
        }
        let r = run_case(case);
        steps_used = steps_used.saturating_add(r.steps);
        results.push(r);
    }

    let passed = results.iter().filter(|r| r.outcome == CaseOutcome::Pass).count();
    let failed = results.iter().filter(|r| r.outcome == CaseOutcome::Fail).count();
    let errored = results.iter().filter(|r| r.outcome == CaseOutcome::Error).count();

    EvalReport {
        suite_path: suite_path.to_owned(),
        timestamp_unix,
        total: results.len(),
        passed,
        failed,
        errored,
        elapsed_secs: suite_start.elapsed().as_secs_f64(),
        cases: results,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI surface
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Args, Debug, Clone)]
pub struct EvalArgs {
    /// Path to the JSON suite file (array of EvalCase).
    pub suite: PathBuf,
    /// Hard cap on the total evaluation steps (cases) the suite may run.
    /// Cases beyond this limit are not executed and receive an Error verdict.
    #[arg(long, default_value = "25")]
    pub max_steps: u32,
    /// Provider preset to use for live runs (future; no-op in headless mode).
    #[arg(long)]
    pub preset: Option<String>,
    /// Emit only the JSON report to stdout; suppress the summary table + Markdown.
    #[arg(long)]
    pub json: bool,
    /// Write report files to this directory instead of the default eval-runs/<ts>/.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
}

/// Entry point called from the `Commands` dispatch match.
pub async fn run_eval_cmd(args: EvalArgs) -> Result<()> {
    let suite_path = &args.suite;
    let raw = std::fs::read_to_string(suite_path)
        .with_context(|| format!("read suite file {}", suite_path.display()))?;
    let cases: Vec<EvalCase> = serde_json::from_str(&raw)
        .with_context(|| format!("parse suite JSON from {}", suite_path.display()))?;

    if cases.is_empty() {
        anyhow::bail!("suite file contains no cases: {}", suite_path.display());
    }

    let suite_label = suite_path.to_string_lossy().to_string();
    let report = run_suite(&suite_label, &cases, args.max_steps);

    // ── JSON-only mode ─────────────────────────────────────────────────────
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return if report.all_passed() {
            Ok(())
        } else {
            anyhow::bail!("{}/{} cases failed", report.failed + report.errored, report.total)
        };
    }

    // ── Human-readable summary ─────────────────────────────────────────────
    println!();
    println!("  neoth eval  ({} cases from {})", cases.len(), suite_path.display());
    println!();
    println!("  total   : {}", report.total);
    println!("  passed  : {}", report.passed);
    println!("  failed  : {}", report.failed);
    println!("  errored : {}", report.errored);
    println!("  elapsed : {:.3}s", report.elapsed_secs);
    println!();

    for r in &report.cases {
        let icon = match r.outcome {
            CaseOutcome::Pass => "PASS",
            CaseOutcome::Fail => "FAIL",
            CaseOutcome::Error => "ERR ",
        };
        if let Some(ref reason) = r.failure_reason {
            println!("  [{}] {} — {}", icon, r.id, reason);
        } else {
            println!("  [{}] {}", icon, r.id);
        }
    }
    println!();

    // ── Write report files ─────────────────────────────────────────────────
    let out_dir = resolve_out_dir(&args)?;
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("create eval output dir {}", out_dir.display()))?;

    let json_path = out_dir.join("report.json");
    let md_path = out_dir.join("report.md");

    std::fs::write(&json_path, serde_json::to_string_pretty(&report)?)
        .with_context(|| format!("write {}", json_path.display()))?;
    std::fs::write(&md_path, report.to_markdown())
        .with_context(|| format!("write {}", md_path.display()))?;

    println!("  report written to {}", out_dir.display());
    println!();

    if report.all_passed() {
        println!("  PASS — all {} cases passed", report.total);
        Ok(())
    } else {
        println!(
            "  FAIL — {}/{} cases did not pass",
            report.failed + report.errored,
            report.total
        );
        anyhow::bail!(
            "eval suite {}: {}/{} cases failed",
            suite_path.display(),
            report.failed + report.errored,
            report.total
        )
    }
}

fn resolve_out_dir(args: &EvalArgs) -> Result<PathBuf> {
    if let Some(ref d) = args.out_dir {
        return Ok(d.clone());
    }
    let home = crate::config::FreedomConfig::default_neoth_home();
    let ts = crate::time::now_unix_secs();
    Ok(home.join("eval-runs").join(ts.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tc(id: &str, answer: &str, expect: &str) -> EvalCase {
        EvalCase {
            id: id.to_owned(),
            description: format!("test case {id}"),
            prompt: format!("prompt for {id}"),
            answer: Some(answer.to_owned()),
            expect_contains: Some(expect.to_owned()),
            verify_command: None,
            max_steps: None,
        }
    }

    fn tc_no_verifier(id: &str) -> EvalCase {
        EvalCase {
            id: id.to_owned(),
            description: format!("smoke {id}"),
            prompt: "hello".to_owned(),
            answer: None,
            expect_contains: None,
            verify_command: None,
            max_steps: None,
        }
    }

    // ── Case-level ────────────────────────────────────────────────────────

    #[test]
    fn case_passes_when_answer_contains_needle() {
        let case = tc("tc-01", "The capital of France is Paris.", "Paris");
        let result = run_case(&case);
        assert_eq!(result.outcome, CaseOutcome::Pass);
        assert!(result.failure_reason.is_none());
    }

    #[test]
    fn case_fails_when_answer_missing_needle() {
        let case = tc("tc-02", "The capital of France is Lyon.", "Paris");
        let result = run_case(&case);
        assert_eq!(result.outcome, CaseOutcome::Fail);
        assert!(result.failure_reason.is_some());
        assert!(result.failure_reason.unwrap().contains("Paris"));
    }

    #[test]
    fn case_passes_with_no_verifier_smoke_test() {
        let case = tc_no_verifier("tc-03");
        let result = run_case(&case);
        assert_eq!(result.outcome, CaseOutcome::Pass);
    }

    #[test]
    fn case_check_is_case_insensitive() {
        let case = tc("tc-04", "The answer is PARIS.", "paris");
        let result = run_case(&case);
        assert_eq!(result.outcome, CaseOutcome::Pass);
    }

    // ── Suite-level ───────────────────────────────────────────────────────

    #[test]
    fn suite_counts_pass_fail_correctly() {
        let cases = vec![
            tc("s-01", "answer contains needle", "needle"),
            tc("s-02", "answer does NOT", "missing"),
            tc_no_verifier("s-03"),
        ];
        let report = run_suite("test.json", &cases, u32::MAX);
        assert_eq!(report.total, 3);
        assert_eq!(report.passed, 2); // s-01 + s-03
        assert_eq!(report.failed, 1); // s-02
        assert_eq!(report.errored, 0);
        assert!(!report.all_passed());
    }

    #[test]
    fn suite_all_passed_when_every_case_passes() {
        let cases = vec![
            tc("a-01", "yes the word is here", "here"),
            tc_no_verifier("a-02"),
        ];
        let report = run_suite("all_pass.json", &cases, u32::MAX);
        assert_eq!(report.passed, 2);
        assert!(report.all_passed());
    }

    // ── Report serialisation ──────────────────────────────────────────────

    #[test]
    fn report_json_round_trips() {
        let cases = vec![tc("r-01", "contains needle", "needle")];
        let report = run_suite("rt.json", &cases, u32::MAX);
        let json = serde_json::to_string(&report).unwrap();
        let back: EvalReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total, 1);
        assert_eq!(back.passed, 1);
        assert_eq!(back.cases[0].id, "r-01");
    }

    #[test]
    fn markdown_contains_pass_and_fail_markers() {
        let cases = vec![
            tc("m-01", "answer with expected", "expected"),
            tc("m-02", "answer without", "missing"),
        ];
        let report = run_suite("md.json", &cases, u32::MAX);
        let md = report.to_markdown();
        assert!(md.contains("NEOTH Eval Report"));
        assert!(md.contains("Pass"));
        assert!(md.contains("Fail"));
        assert!(md.contains("m-01"));
        assert!(md.contains("m-02"));
        assert!(md.contains("Overall: FAIL"));
    }

    #[test]
    fn markdown_all_pass_shows_overall_pass() {
        let cases = vec![tc("p-01", "has needle", "needle")];
        let report = run_suite("pass.json", &cases, u32::MAX);
        let md = report.to_markdown();
        assert!(md.contains("Overall: PASS"));
    }

    // ── Hardening: timeout + max_steps hard cap ───────────────────────────

    /// NEOTH-AUDIT-EVAL-RUNNER-HARDENING-01 (a) — a verify_command that runs
    /// longer than the supplied timeout must be killed and return an Err.
    #[test]
    fn verify_command_timeout_kills_long_child() {
        // A command that blocks for ~30 s — well beyond the 1-second test
        // timeout.  On Windows `ping -n 30 127.0.0.1 > nul` gives ~29 s of
        // wait; on Unix `sleep 30` does the same.
        #[cfg(windows)]
        let long_cmd = "ping -n 30 127.0.0.1 > nul";
        #[cfg(not(windows))]
        let long_cmd = "sleep 30";

        let short = std::time::Duration::from_secs(1);
        let result = run_verify_command(long_cmd, short);
        assert!(result.is_err(), "expected Err on timeout, got Ok");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("timed out"),
            "error must mention 'timed out', got: {msg}"
        );
    }

    /// NEOTH-AUDIT-EVAL-RUNNER-HARDENING-01 (b) — max_steps is a HARD cap:
    /// once the step budget is exhausted, remaining cases are not executed and
    /// receive Error verdicts, not a silent continue.
    #[test]
    fn max_steps_hard_cap_stops_suite() {
        let cases = vec![
            tc("cap-01", "answer has needle", "needle"),
            tc("cap-02", "answer has needle", "needle"),
            tc("cap-03", "answer has needle", "needle"),
        ];
        // max_steps=2 → cap-01 and cap-02 run (2 steps consumed);
        // cap-03 must be bounded, not executed.
        let report = run_suite("cap.json", &cases, 2);
        assert_eq!(report.total, 3, "all cases appear in report");
        assert_eq!(report.passed, 2, "cap-01 and cap-02 pass");
        assert_eq!(report.errored, 1, "cap-03 is a bounded error");
        assert_eq!(report.failed, 0);

        let bounded = &report.cases[2];
        assert_eq!(bounded.id, "cap-03");
        assert_eq!(bounded.outcome, CaseOutcome::Error);
        assert_eq!(bounded.steps, 0, "bounded case consumed no steps");
        let reason = bounded.failure_reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("max_steps"),
            "failure_reason must mention max_steps, got: {reason}"
        );
        assert!(
            reason.contains("2"),
            "failure_reason must include the cap value, got: {reason}"
        );
    }

    // ── Fixture: 2-case suite JSON → report pass:1 total:2 ───────────────

    #[test]
    fn two_case_fixture_suite_produces_correct_report() {
        let json = r#"[
            {
                "id": "fix-01",
                "description": "capital of Germany",
                "prompt": "What is the capital of Germany?",
                "answer": "The capital of Germany is Berlin.",
                "expect_contains": "Berlin"
            },
            {
                "id": "fix-02",
                "description": "deliberately failing case",
                "prompt": "What is the capital of Spain?",
                "answer": "The capital of Spain is not provided.",
                "expect_contains": "Madrid"
            }
        ]"#;
        let cases: Vec<EvalCase> = serde_json::from_str(json).unwrap();
        let report = run_suite("fixture.json", &cases, u32::MAX);
        assert_eq!(report.total, 2);
        assert_eq!(report.passed, 1, "fix-01 should pass");
        assert_eq!(report.failed, 1, "fix-02 should fail (Madrid missing)");
        assert_eq!(report.errored, 0);
        assert!(!report.all_passed());
    }
}
