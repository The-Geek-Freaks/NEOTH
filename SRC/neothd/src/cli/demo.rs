//! `neoth demo` — scripted end-to-end smoke test.
//!
//! Runs NEOTH's safe, read-only capabilities in sequence and prints a
//! clear pass/fail summary.  Every step is independent: a failure in one
//! step is recorded but does not abort the rest of the sequence.
//!
//! Steps (in order):
//!   1. onboarding-status  — FreedomConfig + device snapshot
//!   2. device-profile     — detect_device_profile() + recommend_tier()
//!   3. memory-eval        — tempDB precision harness (MUST pass)
//!   4. code-intel         — risk ranking on "." (coupling=false)
//!   5. doctor             — run_all_checks() summary
//!   6. github-availability — tools::github::locate_gh() probe (no network)
//!
//! The only step whose failure causes `run_demo` to return `Err` is
//! memory-eval: it uses a self-contained temp DB and has no environmental
//! dependencies.  All other steps are environment-dependent and only
//! contribute to the summary line.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::code_intel::{run_code_intel, CodeIntelArgs};
use crate::cli::device_profile::{detect_device_profile, recommend_tier};
use crate::cli::doctor::{run_all_checks, CheckStatus};
use crate::cli::memory_eval::{run_memory_eval_cmd, MemoryEvalArgs};
use crate::cli::onboarding_status::{run_onboarding_status, OnboardingStatusArgs};
use crate::config::FreedomConfig;
use crate::tools::github;

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/// NEOTH demo — scripted read-only smoke test.
///
/// Runs every key surface in sequence and prints a pass/fail summary.
/// Safe to run at any time: no writes, no network beyond what doctor already
/// performs, no real PR creation.
#[derive(Args, Debug, Default)]
pub struct DemoArgs {
    /// Emit JSON for the final summary instead of a markdown table.
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Step tracking
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct StepResult {
    name: &'static str,
    ok: bool,
    note: String,
}

impl StepResult {
    fn pass(name: &'static str, note: impl Into<String>) -> Self {
        Self { name, ok: true, note: note.into() }
    }

    fn fail(name: &'static str, note: impl Into<String>) -> Self {
        Self { name, ok: false, note: note.into() }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the full demo sequence. Returns `Err` only when memory-eval fails
/// (the one must-pass step with no environmental dependencies).
pub async fn run_demo(args: DemoArgs) -> Result<()> {
    println!("# NEOTH Demo — read-only smoke test\n");

    let mut steps: Vec<StepResult> = Vec::new();
    let mut memory_eval_failed = false;

    // ── Step 1: onboarding-status ────────────────────────────────────────
    println!("## Step 1 — onboarding-status\n");
    {
        // neoth: run_onboarding_status prints its own output to stdout.
        let result =
            run_onboarding_status(OnboardingStatusArgs { json: false }).await;
        match result {
            Ok(()) => steps.push(StepResult::pass("onboarding-status", "OK")),
            Err(e) => steps.push(StepResult::fail(
                "onboarding-status",
                format!("ERR: {e}"),
            )),
        }
    }

    // ── Step 2: device-profile ───────────────────────────────────────────
    println!("\n## Step 2 — device-profile\n");
    {
        // No dedicated run fn; call the primitives directly and print.
        // This is exactly what OnboardingSnapshot::from_config does.
        let profile = detect_device_profile();
        let tier = recommend_tier(profile.total_ram_gb, profile.gpu_present);
        println!(
            "  RAM:       {:.1} GB",
            profile.total_ram_gb
        );
        println!("  CPU cores: {}", profile.cpu_cores);
        println!("  GPU:       {}", if profile.gpu_present { "yes" } else { "no" });
        println!("  AI tier:   {} — {}", tier.as_str(), tier.rationale());
        steps.push(StepResult::pass(
            "device-profile",
            format!(
                "{:.1} GB RAM / {} cores / GPU={} → {}",
                profile.total_ram_gb,
                profile.cpu_cores,
                profile.gpu_present,
                tier.as_str()
            ),
        ));
    }

    // ── Step 3: memory-eval (MUST pass) ─────────────────────────────────
    println!("\n## Step 3 — memory-eval (must-pass)\n");
    {
        let result = run_memory_eval_cmd(MemoryEvalArgs { json: false }).await;
        match result {
            Ok(()) => steps.push(StepResult::pass("memory-eval", "harness passed")),
            Err(e) => {
                memory_eval_failed = true;
                steps.push(StepResult::fail(
                    "memory-eval",
                    format!("ERR: {e}"),
                ));
            }
        }
    }

    // ── Step 4: code-intel ───────────────────────────────────────────────
    println!("\n## Step 4 — code-intel\n");
    {
        // neoth: coupling=false avoids the code_map.db dependency entirely.
        // repo="." — we use the source tree the operator is standing in.
        let result = run_code_intel(CodeIntelArgs {
            repo: PathBuf::from("."),
            top: 10,
            coupling: false,
        })
        .await;
        match result {
            Ok(()) => steps.push(StepResult::pass("code-intel", "OK")),
            Err(e) => steps.push(StepResult::fail(
                "code-intel",
                format!("ERR: {e}"),
            )),
        }
    }

    // ── Step 5: doctor (summary only) ────────────────────────────────────
    println!("\n## Step 5 — doctor\n");
    {
        let home = FreedomConfig::default_neoth_home();
        // neoth: run_all_checks is synchronous + pure — no I/O beyond stat().
        let outcomes = run_all_checks(&home);
        let total = outcomes.len();
        let pass = outcomes
            .iter()
            .filter(|o| o.status == CheckStatus::Pass)
            .count();
        let warn = outcomes
            .iter()
            .filter(|o| o.status == CheckStatus::Warn)
            .count();
        let fail = outcomes
            .iter()
            .filter(|o| o.status == CheckStatus::Fail)
            .count();
        println!(
            "  doctor: {total} checks — {pass} PASS / {warn} WARN / {fail} FAIL"
        );
        let note = format!("{pass}/{total} PASS ({warn} WARN, {fail} FAIL)");
        if fail == 0 {
            steps.push(StepResult::pass("doctor", note));
        } else {
            // FAIL checks are environment problems, not a demo blocker.
            steps.push(StepResult::fail("doctor", note));
        }
    }

    // ── Step 6: github-availability ──────────────────────────────────────
    println!("\n## Step 6 — github-availability\n");
    {
        // neoth: locate_gh() probes PATH for the `gh` binary — no network,
        // no auth, no PR created.
        match github::locate_gh() {
            Some(path) => {
                println!("  gh found at: {}", path.display());
                println!("  neoth github pr-create: AVAILABLE");
                steps.push(StepResult::pass(
                    "github-availability",
                    format!("gh at {}", path.display()),
                ));
            }
            None => {
                println!("  gh not found on PATH");
                println!("  neoth github pr-create: NOT AVAILABLE (install gh CLI)");
                // gh being absent is an environment choice, not a demo failure.
                steps.push(StepResult::pass(
                    "github-availability",
                    "gh not on PATH — pr-create unavailable (env choice)",
                ));
            }
        }
    }

    // ── Summary ──────────────────────────────────────────────────────────
    let ok_count = steps.iter().filter(|s| s.ok).count();
    let total = steps.len();

    println!("\n---\n");
    if args.json {
        // Minimal JSON summary array.
        print!("[");
        for (i, s) in steps.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            // GR-fix: serialise the strings via serde_json instead of a hand-built
            // template that only escaped `"` — a note from format!("ERR: {e}") can
            // carry backslashes/newlines/control chars and produced invalid JSON.
            print!(
                "{{\"step\":{}, \"ok\":{}, \"note\":{}}}",
                serde_json::to_string(s.name).unwrap_or_else(|_| "\"\"".into()),
                s.ok,
                serde_json::to_string(&s.note).unwrap_or_else(|_| "\"\"".into())
            );
        }
        println!("]");
    } else {
        println!("| Step | Status | Note |");
        println!("|---|---|---|");
        for s in &steps {
            println!(
                "| {} | {} | {} |",
                s.name,
                if s.ok { "OK" } else { "FAIL" },
                s.note
            );
        }
    }

    println!("\n**NEOTH DEMO: {ok_count}/{total} steps OK**");

    if memory_eval_failed {
        anyhow::bail!(
            "demo: memory-eval failed (must-pass) — {ok_count}/{total} steps OK"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// E2E smoke: the full demo pipeline must return Ok on a stock checkout.
    ///
    /// memory-eval uses a self-contained temp DB (no real operator store
    /// touched).  All other steps are read-only and environment-tolerant:
    /// they report warn/fail in the summary but do NOT cause this test to fail.
    #[tokio::test]
    async fn test_run_demo_returns_ok() {
        let args = DemoArgs { json: false };
        let result = run_demo(args).await;
        assert!(
            result.is_ok(),
            "demo must-pass step failed: {:?}",
            result.unwrap_err()
        );
    }

    /// JSON output path: the demo also returns Ok when json=true.
    #[tokio::test]
    async fn test_run_demo_json_returns_ok() {
        let args = DemoArgs { json: true };
        let result = run_demo(args).await;
        assert!(result.is_ok(), "demo json path failed: {:?}", result.unwrap_err());
    }
}
