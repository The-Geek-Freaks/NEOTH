//! GOLD-FEAT-05 — `neoth self-edit --diff <file> [--dry-run]`
//!
//! CLI surface for the five-layer self-source-edit gate stack.
//!
//! ## Usage
//!
//! ```text
//! neoth self-edit --diff <path/to/edit.patch> [--dry-run]
//! ```
//!
//! ## Gate invocation
//!
//! 1. Load `FreedomConfig` from `~/.neoth/freedom.yaml`.
//! 2. Read and validate the diff file (must be a readable unified-diff).
//! 3. Open a short-lived WAL writer for audit emission.
//! 4. Call `coding::self_source_gate::run_gate_stack` — all 5 layers run.
//! 5. Print result.
//!
//! ## WAL audit
//!
//! The CLI opens a dedicated WAL segment at
//! `~/.neoth/wal/self_edit_audit.wal` for audit frames. For a real apply the
//! audit trail is REQUIRED: if the WAL writer cannot be opened the command
//! refuses (rather than mutating the source tree with no forensic record).
//! `--dry-run` (which never applies) may proceed with only a warning.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use tracing::warn;

use crate::cli::OutputFormat;
use crate::coding::self_source::{diff_line_count, diff_paths};
use crate::coding::self_source_gate::{GateError, run_gate_stack};
use crate::config::FreedomConfig;

/// `neoth self-edit` — propose a source-code edit against NEOTH's own source
/// tree, subject to the five-layer safety gate stack.
///
/// Requires `freedom.yaml::coding.self_edit.enabled = true` and a non-empty
/// `allowed_modules` allowlist. The operator's autonomy level must be
/// `Elevated` or `Full` (Strict and Standard are denied at Layer 3).
#[derive(Args, Debug)]
pub struct SelfEditArgs {
    /// Path to the unified-diff (`.patch`) file to evaluate and apply.
    ///
    /// Must be a standard unified diff with `--- a/` / `+++ b/` headers.
    /// Paths in the diff are relative to the source root (auto-detected from
    /// the binary path, or set in `freedom.yaml::coding.self_edit.source_root`).
    #[arg(long, value_name = "FILE")]
    pub diff: PathBuf,

    /// Evaluate all five gates but do NOT apply the diff to the live tree.
    ///
    /// Even in dry-run mode, all gates run (worktree is created and tested)
    /// so you get a full pass/fail result without modifying the live source.
    /// No `SelfEditApplied` WAL frame is emitted in dry-run mode.
    #[arg(long, default_value = "false")]
    pub dry_run: bool,

    /// Acknowledge the self-edit before applying. REQUIRED at Elevated/Full
    /// autonomy — the permission gate (Layer 3) refuses a self-source edit
    /// without this explicit ack (policy: never auto-apply, even at Full).
    /// Not needed for `--dry-run`, which never applies to the live tree.
    #[arg(long, default_value = "false")]
    pub yes: bool,
}

/// Entry point for `neoth self-edit`.
pub async fn run_self_edit(args: SelfEditArgs, output: OutputFormat) -> Result<()> {
    // 1. Read the diff file.
    let diff_path = args
        .diff
        .canonicalize()
        .with_context(|| format!("cannot access diff file: {}", args.diff.display()))?;

    let diff_text = std::fs::read_to_string(&diff_path)
        .with_context(|| format!("read diff file {}", diff_path.display()))?;

    if diff_text.trim().is_empty() {
        anyhow::bail!("diff file is empty: {}", diff_path.display());
    }

    // 2. Load FreedomConfig.
    let cfg = FreedomConfig::load_from_path(&FreedomConfig::default_path())
        .unwrap_or_else(|e| {
            warn!(error = %e, "self_edit: cannot load freedom.yaml — using defaults (kill-switch will refuse)");
            FreedomConfig::default()
        });

    // 3. Pre-validate diff paths (fast fail before opening WAL / worktree).
    let target_paths = diff_paths(&diff_text).map_err(|e| {
        anyhow::anyhow!("invalid diff: {e}")
    })?;

    // 3b. Pre-validate line count cap (Layer-2 size check performed here so
    // the error message appears before WAL open, which is best-effort).
    let line_count = diff_line_count(&diff_text);
    let max = cfg.coding.self_edit.max_lines_changed;
    if line_count > max {
        anyhow::bail!(
            "diff has {line_count} changed lines, exceeding the \
             max_lines_changed cap of {max} \
             (set freedom.yaml::coding.self_edit.max_lines_changed to raise this limit)"
        );
    }

    match output {
        OutputFormat::Table => {
            println!(
                "self-edit: evaluating diff ({} path(s), {line_count} changed line(s)){}",
                target_paths.len(),
                if args.dry_run { " [DRY RUN]" } else { "" },
            );
        }
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                r#"{{"status":"evaluating","paths":{},"lines":{line_count},"dry_run":{}}}"#,
                serde_json::to_string(&target_paths)
                    .unwrap_or_else(|_| "[]".into()),
                args.dry_run
            );
        }
    }

    // 4. Open a short-lived WAL writer for audit emission. For a real apply the
    // audit trail is REQUIRED: if the WAL is unavailable we refuse rather than
    // silently mutate the source tree with no forensic record. Dry-run (no
    // apply) may proceed without it.
    let wal_dir = FreedomConfig::default_wal_dir();
    let wal_handle = open_audit_wal(&wal_dir);
    if wal_handle.is_none() {
        if args.dry_run {
            warn!("self_edit: WAL writer unavailable — dry-run proceeds without audit");
        } else {
            anyhow::bail!(
                "self-edit requires an audit trail, but the WAL writer at {} is \
                 unavailable — refusing to apply. Free disk space / fix permissions on \
                 the WAL directory, or use --dry-run to preview without applying.",
                wal_dir.display()
            );
        }
    }

    // 5. Run all five gates. `args.yes` is the operator's explicit acknowledgement
    // that Layer 3 requires before applying a Confirm-level self-edit.
    let result = run_gate_stack(
        &diff_text,
        &diff_path,
        &cfg,
        args.dry_run,
        args.yes,
        wal_handle.as_ref(),
    )
    .await;

    // WAL writer dropped here; background task flushes on drop.
    drop(wal_handle);

    match result {
        Ok(outcome) => {
            match output {
                OutputFormat::Table => {
                    if outcome.dry_run {
                        println!(
                            "self-edit: ALL 5 GATES PASSED (dry-run) — diff NOT applied\n\
                             paths: {:?}\n\
                             diff_hash: {}",
                            outcome.target_paths, outcome.diff_hash
                        );
                    } else {
                        println!(
                            "self-edit: ALL 5 GATES PASSED — diff applied to live tree\n\
                             paths: {:?}\n\
                             diff_hash: {}",
                            outcome.target_paths, outcome.diff_hash
                        );
                    }
                }
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        r#"{{"status":"{}","paths":{},"diff_hash":"{}","dry_run":{}}}"#,
                        if outcome.dry_run { "passed_dry_run" } else { "applied" },
                        serde_json::to_string(&outcome.target_paths)
                            .unwrap_or_else(|_| "[]".into()),
                        outcome.diff_hash,
                        outcome.dry_run
                    );
                }
            }
            Ok(())
        }
        Err(GateError::KillSwitch(reason)) => {
            anyhow::bail!("REFUSED (layer 1 kill-switch): {reason}")
        }
        Err(GateError::Allowlist(reason)) => {
            anyhow::bail!("REFUSED (layer 2 allowlist): {reason}")
        }
        Err(GateError::Permission(reason)) => {
            anyhow::bail!("REFUSED (layer 3 permission): {reason}")
        }
        Err(GateError::Worktree(reason)) => {
            anyhow::bail!("REFUSED (layer 4 worktree): {reason}")
        }
        Err(GateError::GreenTest(reason)) => {
            anyhow::bail!("REFUSED (layer 5 green-test): {reason}")
        }
        Err(GateError::Audit(e)) => {
            anyhow::bail!("GATE ERROR (audit): {e}")
        }
    }
}

// ── WAL open helper ───────────────────────────────────────────────────────────

/// Try to open a short-lived WAL writer at `<wal_dir>/self_edit_audit.wal`.
///
/// Returns `None` on failure — the caller logs a warning and continues without
/// WAL (gates provide the security; WAL is best-effort audit trail).
fn open_audit_wal(wal_dir: &std::path::Path) -> Option<crate::wal::writer::WalWriterHandle> {
    if let Err(e) = std::fs::create_dir_all(wal_dir) {
        warn!(error = %e, dir = %wal_dir.display(), "self_edit: cannot create WAL dir");
        return None;
    }
    let segment = wal_dir.join("self_edit_audit.wal");
    match crate::wal::writer::spawn(segment) {
        Ok((handle, _join)) => Some(handle),
        Err(e) => {
            warn!(error = %e, "self_edit: cannot open WAL writer");
            None
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Integration tests for the CLI live in _test.bat self_edit.
    // Unit coverage for gate logic is in coding::self_source_gate::tests.
    //
    // This module tests the pre-validation guards that run BEFORE the gate
    // stack (so they don't require a real cargo workspace).

    use crate::coding::self_source::{diff_line_count, diff_paths};

    #[test]
    fn rejects_empty_diff() {
        let result = diff_paths("");
        assert!(result.is_err());
    }

    #[test]
    fn diff_line_count_below_cap_passes() {
        let diff = concat!(
            "--- a/src/cli/foo.rs\n",
            "+++ b/src/cli/foo.rs\n",
            "@@ -1,1 +1,2 @@\n",
            " keep\n",
            "+added\n",
        );
        let count = diff_line_count(diff);
        assert!(count <= 200, "expected count ≤ 200, got {count}");
    }
}
