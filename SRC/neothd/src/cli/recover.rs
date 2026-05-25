//! R-06 (Session 24) — `neoth recover` operator-facing CLI.
//!
//! Surfaces every `*.bak` snapshot R-02's `shrink_safe_write` left
//! behind, classifies each by [`crate::recovery::BakVerdict`], and
//! offers three actions:
//!
//! - `neoth recover --list`     (default) — print every bak + verdict.
//! - `neoth recover --restore <live-path>` — move `<live-path>.bak`
//!   into `<live-path>` (snapshots the current live first via
//!   `shrink_safe_write` so the operator can undo if needed).
//! - `neoth recover --clean`    — remove every `.bak` whose verdict
//!   is `Stale` (live is same-or-larger than bak; no data loss).
//!   Confirms before deleting in TTY mode; non-interactive callers
//!   must pass `--yes`.
//!
//! Read-only by default. Destructive actions require an explicit flag
//! per the AGENTER hard rule "no destructive op without operator GO".

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::recovery::{BakReport, BakVerdict, bak_path, scan_for_baks};

#[derive(Args, Debug, Clone)]
pub struct RecoverArgs {
    /// Default mode: list every `.bak` + verdict.
    #[arg(long, conflicts_with_all = ["restore", "clean"])]
    pub list: bool,

    /// Restore a `.bak` over its live counterpart. Operator passes
    /// the LIVE path (e.g. `~/.neoth/freedom.yaml`), not the bak
    /// path — keeps the UX symmetric with how the bak was named.
    #[arg(long, value_name = "LIVE_PATH", conflicts_with_all = ["list", "clean"])]
    pub restore: Option<PathBuf>,

    /// Remove every `.bak` classified as `Stale` (live is same-or-
    /// larger than bak; safe to discard). Confirms before deleting
    /// unless `--yes` is also passed.
    #[arg(long, conflicts_with_all = ["list", "restore"])]
    pub clean: bool,

    /// Skip the destructive-op confirm prompt. Required for
    /// non-interactive / CI use of `--clean`.
    #[arg(long)]
    pub yes: bool,

    /// Override the scan root. Defaults to `~/.neoth/`.
    #[arg(long, value_name = "PATH")]
    pub home: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_recover(args: RecoverArgs) -> Result<()> {
    let home = args
        .home
        .clone()
        .unwrap_or_else(|| FreedomConfig::default_neoth_home());

    if let Some(live) = args.restore.as_deref() {
        return run_restore(live, &args.output);
    }
    if args.clean {
        return run_clean(&home, args.yes, &args.output);
    }
    // Default + --list
    run_list(&home, &args.output)
}

fn run_list(home: &std::path::Path, output: &OutputFormat) -> Result<()> {
    let reports = scan_for_baks(home).context("scan for bak files")?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&reports)?);
        }
        OutputFormat::Table => render_list_table(&reports),
    }
    Ok(())
}

fn render_list_table(reports: &[BakReport]) {
    if reports.is_empty() {
        println!("No `.bak` snapshots present. Nothing to recover.");
        return;
    }
    println!("# {} bak file(s) found", reports.len());
    println!(
        "  {:<48} {:<12} {:<12} {}",
        "live_path", "live_size", "bak_size", "verdict",
    );
    for r in reports {
        let live_size = r
            .live_size
            .map(|s| s.to_string())
            .unwrap_or_else(|| "(missing)".into());
        let verdict = match r.verdict {
            BakVerdict::LiveMissing => "LIVE_MISSING",
            BakVerdict::LiveShrunk => "LIVE_SHRUNK",
            BakVerdict::LiveOk => "LIVE_OK",
            BakVerdict::Stale => "STALE",
        };
        println!(
            "  {:<48} {:<12} {:<12} {}",
            truncate(&r.live_path.display().to_string(), 48),
            live_size,
            r.bak_size,
            verdict,
        );
    }
    println!();
    println!("Restore one: `neoth recover --restore <live-path>`");
    println!("Clean stale: `neoth recover --clean`");
}

fn run_restore(live: &std::path::Path, output: &OutputFormat) -> Result<()> {
    let bak = bak_path(live);
    if !bak.exists() {
        anyhow::bail!(
            "no bak found at {} — pass the LIVE path, not the .bak path",
            bak.display(),
        );
    }
    let bak_bytes = std::fs::read(&bak)
        .with_context(|| format!("read bak {}", bak.display()))?;

    // If the live file exists, snapshot it BEFORE we overwrite.
    // shrink_safe_write does the right thing: when the bak content
    // is shorter than the current live file, a new pre-restore bak
    // is written; otherwise it's a same-size-or-grow path with no
    // bak (operator can re-restore from the original bak in
    // either case).
    let bak_was_re_snapshotted = crate::recovery::shrink_safe_write(live, &bak_bytes)?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "live_path": live.display().to_string(),
                    "bak_path": bak.display().to_string(),
                    "bytes_restored": bak_bytes.len(),
                    "pre_restore_snapshot_taken": bak_was_re_snapshotted,
                }),
            );
        }
        OutputFormat::Table => {
            println!(
                "Restored {bytes} bytes from {bak} to {live}.",
                bytes = bak_bytes.len(),
                bak = bak.display(),
                live = live.display(),
            );
            if bak_was_re_snapshotted {
                println!(
                    "Pre-restore live content saved to {} (in case the restore is wrong).",
                    bak.display(),
                );
            }
        }
    }
    Ok(())
}

fn run_clean(
    home: &std::path::Path,
    skip_confirm: bool,
    output: &OutputFormat,
) -> Result<()> {
    let reports = scan_for_baks(home).context("scan for bak files")?;
    let candidates: Vec<&BakReport> = reports
        .iter()
        .filter(|r| matches!(r.verdict, BakVerdict::LiveOk | BakVerdict::Stale))
        .collect();

    if candidates.is_empty() {
        println!("No stale `.bak` files to clean. (Every bak still represents potentially-lost data.)");
        return Ok(());
    }

    if !skip_confirm {
        println!("About to delete {} stale .bak file(s):", candidates.len());
        for c in &candidates {
            println!("  - {}", c.bak_path.display());
        }
        println!("Re-run with `--yes` to confirm deletion.");
        return Ok(());
    }

    let mut deleted = 0usize;
    for c in &candidates {
        match std::fs::remove_file(&c.bak_path) {
            Ok(()) => deleted += 1,
            Err(e) => tracing::warn!(
                path = %c.bak_path.display(),
                error = %e,
                "failed to delete stale bak — continuing",
            ),
        }
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "scanned": reports.len(),
                    "deleted": deleted,
                    "candidates": candidates.len(),
                }),
            );
        }
        OutputFormat::Table => {
            println!("Deleted {deleted} of {} candidate(s).", candidates.len());
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn args_with_home(home: PathBuf) -> RecoverArgs {
        RecoverArgs {
            list: true,
            restore: None,
            clean: false,
            yes: false,
            home: Some(home),
            output: OutputFormat::Json,
        }
    }

    #[tokio::test]
    async fn list_does_not_error_on_empty_home() {
        let dir = tempdir().unwrap();
        let args = args_with_home(dir.path().to_path_buf());
        run_recover(args).await.unwrap();
    }

    #[tokio::test]
    async fn restore_errors_when_no_bak_present() {
        let dir = tempdir().unwrap();
        let live = dir.path().join("freedom.yaml");
        std::fs::write(&live, b"current").unwrap();
        let mut args = args_with_home(dir.path().to_path_buf());
        args.list = false;
        args.restore = Some(live);
        let r = run_recover(args).await;
        assert!(r.is_err());
        let msg = format!("{:?}", r.unwrap_err());
        assert!(msg.contains("no bak found"), "got: {msg}");
    }

    #[tokio::test]
    async fn restore_writes_bak_content_to_live_path() {
        let dir = tempdir().unwrap();
        let live = dir.path().join("freedom.yaml");
        // Live is a shrunken version; bak holds the pre-shrink state.
        std::fs::write(&live, b"x").unwrap();
        std::fs::write(bak_path(&live), b"full operator profile contents").unwrap();

        let mut args = args_with_home(dir.path().to_path_buf());
        args.list = false;
        args.restore = Some(live.clone());
        run_recover(args).await.unwrap();

        let after = std::fs::read_to_string(&live).unwrap();
        assert_eq!(after, "full operator profile contents");
    }

    #[tokio::test]
    async fn clean_requires_yes_flag_in_non_interactive_path() {
        let dir = tempdir().unwrap();
        // Create one safe-to-clean bak (LiveOk: live bigger than bak).
        std::fs::write(dir.path().join("a.yaml"), b"BIG-LIVE-FILE-XYZ").unwrap();
        std::fs::write(dir.path().join("a.yaml.bak"), b"sm").unwrap();

        let mut args = args_with_home(dir.path().to_path_buf());
        args.list = false;
        args.clean = true;
        args.yes = false; // → confirm step, no actual delete
        run_recover(args).await.unwrap();
        assert!(
            dir.path().join("a.yaml.bak").exists(),
            "no --yes → bak must NOT be deleted",
        );

        // Now with --yes the same bak gets removed.
        let mut args2 = args_with_home(dir.path().to_path_buf());
        args2.list = false;
        args2.clean = true;
        args2.yes = true;
        run_recover(args2).await.unwrap();
        assert!(
            !dir.path().join("a.yaml.bak").exists(),
            "--yes → bak deleted",
        );
    }

    #[tokio::test]
    async fn clean_leaves_data_loss_baks_untouched() {
        // A LiveShrunk verdict means the live file is SMALLER than
        // the bak — operator may have lost data. Clean must NOT
        // delete these even with --yes.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("b.yaml"), b"x").unwrap();
        std::fs::write(dir.path().join("b.yaml.bak"), b"BIG-PRE-SHRINK-CONTENT").unwrap();

        let mut args = args_with_home(dir.path().to_path_buf());
        args.list = false;
        args.clean = true;
        args.yes = true;
        run_recover(args).await.unwrap();
        assert!(
            dir.path().join("b.yaml.bak").exists(),
            "LiveShrunk bak must survive --clean --yes (potential data loss)",
        );
    }

    #[tokio::test]
    async fn clean_leaves_live_missing_baks_untouched() {
        // LiveMissing → operator likely wants to restore. Definitely
        // don't auto-delete these.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("c.yaml.bak"), b"CCC").unwrap();
        let mut args = args_with_home(dir.path().to_path_buf());
        args.list = false;
        args.clean = true;
        args.yes = true;
        run_recover(args).await.unwrap();
        assert!(
            dir.path().join("c.yaml.bak").exists(),
            "LiveMissing bak must survive --clean (operator should restore)",
        );
    }
}
