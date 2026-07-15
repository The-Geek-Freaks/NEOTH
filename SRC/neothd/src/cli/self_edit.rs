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

    /// Expected SHA-256 hex digest of the diff file (TOCTOU guard).
    ///
    /// When provided, the diff bytes are hashed immediately after reading and
    /// compared to this value. Any mismatch causes a hard refusal BEFORE any
    /// gate runs, ensuring the file was not swapped between proposal-acceptance
    /// and apply. The GUI always passes this; CLI callers may omit it.
    #[arg(long, value_name = "SHA256")]
    pub expect_hash: Option<String>,
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

    // 1b. TOCTOU guard — verify hash before any gate runs.
    if let Some(ref expected) = args.expect_hash {
        check_expect_hash(diff_text.as_bytes(), expected)?;
    }

    // 2. Load FreedomConfig.
    let cfg = FreedomConfig::load_from_path(&FreedomConfig::default_path())
        .unwrap_or_else(|e| {
            warn!(error = %e, "self_edit: cannot load freedom.yaml — using defaults (kill-switch will refuse)");
            FreedomConfig::default()
        });

    // 3. Pre-validate diff paths (fast fail before opening WAL / worktree).
    let target_paths = diff_paths(&diff_text).map_err(|e| anyhow::anyhow!("invalid diff: {e}"))?;

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
        OutputFormat::Json => {
            eprintln!(
                "self-edit: evaluating {} path(s), {line_count} changed line(s){}",
                target_paths.len(),
                if args.dry_run { " [DRY RUN]" } else { "" },
            );
        }
        OutputFormat::Jsonl => {
            println!(
                r#"{{"status":"evaluating","paths":{},"lines":{line_count},"dry_run":{}}}"#,
                serde_json::to_string(&target_paths)
                    .expect("validated source paths are always JSON-serializable"),
                args.dry_run
            );
        }
    }

    // 4. Open a short-lived WAL writer for audit emission. For a real apply the
    // audit trail is REQUIRED: if the WAL is unavailable we refuse rather than
    // silently mutate the source tree with no forensic record. Dry-run (no
    // apply) may proceed without it.
    let wal_dir = FreedomConfig::default_wal_dir();
    let wal = open_audit_wal(&wal_dir);
    if wal.is_none() {
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
    let (wal_handle, wal_join) = match wal {
        Some((handle, join)) => (Some(handle), Some(join)),
        None => (None, None),
    };

    // 5. Run all five gates. `args.yes` is the operator's explicit acknowledgement
    // that Layer 3 requires before applying a Confirm-level self-edit.
    let result = run_gate_stack(
        &diff_text,
        &cfg,
        args.dry_run,
        args.yes,
        wal_handle.as_ref(),
    )
    .await;

    // Drop the handle (closes the writer channel), then AWAIT the writer task
    // so every audit frame — especially SelfEditApplied — is durably flushed
    // before the process can exit. A kill between apply and flush would
    // otherwise leave a live-tree mutation with no `applied` forensic record.
    drop(wal_handle);
    if let Some(join) = wal_join
        && tokio::time::timeout(std::time::Duration::from_secs(5), join)
            .await
            .is_err()
    {
        warn!("self_edit: WAL writer did not flush within 5s — audit frame may be incomplete");
    }

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
                        if outcome.dry_run {
                            "passed_dry_run"
                        } else {
                            "applied"
                        },
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
        Err(GateError::Cooldown(reason)) => {
            anyhow::bail!("REFUSED (apply cooldown): {reason}")
        }
        Err(GateError::StateDrift(reason)) => {
            anyhow::bail!("REFUSED (base-SHA drift): {reason}")
        }
        Err(GateError::AuditFailedAfterApply(reason)) => {
            // The live tree WAS mutated but the required audit frame failed — an
            // inconsistent state. Surface it loudly; never report clean success.
            anyhow::bail!(
                "INCONSISTENT: the edit was applied to the live source tree but the required \
                 audit frame could not be written ({reason}). Verify the working tree with \
                 `git status`/`git diff` and check the WAL — the change is NOT audited."
            )
        }
        Err(GateError::Audit(e)) => {
            anyhow::bail!("GATE ERROR (audit): {e}")
        }
    }
}

// ── WAL open helper ───────────────────────────────────────────────────────────

/// Try to open a short-lived WAL writer at `<wal_dir>/self_edit_audit.wal`.
///
/// Returns the writer handle AND its task `JoinHandle` — the caller must await
/// the join after dropping the handle so audit frames are flushed before exit.
/// Returns `None` on failure — the caller logs a warning and continues without
/// WAL (gates provide the security; WAL is best-effort audit trail).
type AuditWal = (
    crate::wal::writer::WalWriterHandle,
    tokio::task::JoinHandle<()>,
);

fn open_audit_wal(wal_dir: &std::path::Path) -> Option<AuditWal> {
    if let Err(e) = std::fs::create_dir_all(wal_dir) {
        warn!(error = %e, dir = %wal_dir.display(), "self_edit: cannot create WAL dir");
        return None;
    }
    let segment = wal_dir.join("self_edit_audit.wal");
    match crate::wal::writer::spawn(segment) {
        Ok((handle, join)) => Some((handle, join)),
        Err(e) => {
            warn!(error = %e, "self_edit: cannot open WAL writer");
            None
        }
    }
}

// ── Expect-hash guard ────────────────────────────────────────────────────────

/// Verify that `diff_bytes` SHA-256 matches `expected_hex`.
///
/// Called immediately after reading the diff file so any TOCTOU swap between
/// proposal-acceptance and the apply invocation is caught before gates run.
fn check_expect_hash(diff_bytes: &[u8], expected_hex: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    let actual = hex::encode(Sha256::digest(diff_bytes));
    if actual != expected_hex {
        anyhow::bail!(
            "diff hash mismatch — TOCTOU guard: expected {expected_hex}, got {actual}. \
             The diff file may have been modified after the proposal was accepted."
        );
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Integration tests for the CLI live in _test.bat self_edit.
    // Unit coverage for gate logic is in coding::self_source_gate::tests.
    //
    // This module tests the pre-validation guards that run BEFORE the gate
    // stack (so they don't require a real cargo workspace).

    use super::*;
    use crate::coding::self_source::{diff_line_count, diff_paths};

    // ── diff pre-validation ──────────────────────────────────────────────────

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

    // ── expect-hash guard ────────────────────────────────────────────────────

    #[test]
    fn expect_hash_accepts_correct_hash() {
        use sha2::{Digest, Sha256};
        let data = b"--- a/src/cli/foo.rs\n+++ b/src/cli/foo.rs\n@@ -1 +1 @@\n-old\n+new\n";
        let expected = hex::encode(Sha256::digest(data));
        assert!(check_expect_hash(data, &expected).is_ok());
    }

    #[test]
    fn expect_hash_rejects_wrong_hash() {
        let data = b"--- a/src/cli/foo.rs\n+++ b/src/cli/foo.rs\n@@ -1 +1 @@\n-old\n+new\n";
        let err = check_expect_hash(data, "deadbeefdeadbeef").unwrap_err();
        assert!(
            err.to_string().contains("TOCTOU"),
            "expected TOCTOU in error, got: {err}"
        );
    }

    #[test]
    fn expect_hash_rejects_empty_expected() {
        let data = b"some diff bytes";
        let err = check_expect_hash(data, "").unwrap_err();
        assert!(err.to_string().contains("mismatch"), "got: {err}");
    }
}
