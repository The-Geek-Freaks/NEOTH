//! `neoth-migrate` — Phase-3 cutover binary (V10-06 GA blocker).
//!
//! Reads 12 Jarvis memory stores, emits a `dry-run` report or an
//! `apply` migration into the NEOTH WAL + tier views.
//!
//! Lives outside `neothd` so a daemon release doesn't carry the
//! migration-only deps (pulldown-cmark today; future lance + git2).
//! Operators run this once at Day-65, then never again.
//!
//! ## CLI
//!
//! ```text
//! neoth-migrate dry-run [--root <PATH>]
//!     Scan-only. No WAL writes. Prints JSON report of every
//!     discovered store: path, kind, row-count estimate, sample
//!     entries (first 3 rows / files), reader-readiness flag.
//!
//! neoth-migrate apply --confirm [--root <PATH>] [--wal-segment <PATH>]
//!     Actually migrate. Requires explicit `--confirm` because the
//!     operation appends thousands of frames to the WAL + cannot be
//!     undone (replay-only).
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod readers;

/// Phase-3 store-migration tool. See module-doc for usage examples.
#[derive(Parser, Debug)]
#[command(
    name = "neoth-migrate",
    version,
    about = "Phase-3 Jarvis-store cutover for NEOTH (V10-06)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan-only. Walks every known store, reports rows + sample
    /// entries. Never writes to the WAL.
    DryRun(DryRunArgs),
    /// Actually migrate. Requires `--confirm` to avoid running by
    /// accident from a shell script.
    Apply(ApplyArgs),
}

#[derive(clap::Args, Debug)]
struct DryRunArgs {
    /// Operator home override. Default: `$HOME` resolved at runtime.
    #[arg(long, value_name = "PATH")]
    root: Option<std::path::PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ApplyArgs {
    /// Operator home override. Default: `$HOME` resolved at runtime.
    #[arg(long, value_name = "PATH")]
    root: Option<std::path::PathBuf>,
    /// Required positive consent. Without it the binary refuses to run.
    #[arg(long)]
    confirm: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::DryRun(args) => run_dry_run(args),
        Command::Apply(args) => run_apply(args),
    }
}

fn run_dry_run(args: DryRunArgs) -> Result<()> {
    let home = args.root.clone().unwrap_or_else(default_home);
    tracing::info!(home = %home.display(), "neoth-migrate dry-run");
    let report = readers::scan_all(&home);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_apply(args: ApplyArgs) -> Result<()> {
    if !args.confirm {
        anyhow::bail!(
            "refusing to apply without --confirm. Run `neoth-migrate dry-run` first \
             to inspect what would be migrated, then re-run with --confirm."
        );
    }
    // Phase-3 cutover apply is intentionally a follow-up implementation
    // PR — this binary's dry-run path is the V10-06 foundation that
    // operators consult at Day-62. The apply path lands once the WAL
    // writer + per-reader emitters are wired in.
    anyhow::bail!(
        "apply path not yet implemented — Phase-3 deliverable. Use dry-run today \
         to validate your Jarvis store layout; apply ships in the V10-06 follow-up."
    );
}

fn default_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}
