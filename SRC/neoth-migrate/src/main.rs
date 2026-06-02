//! `neoth-migrate` — prior-AI memory import tool.
//!
//! Imports memory from a previous AI assistant into the NEOTH WAL +
//! tier views. The operator declares THEIR OWN stores in an
//! `import-manifest.yaml` (see `examples/import-manifest.example.yaml`);
//! nothing is hardcoded to any one machine. Emits a `dry-run` report
//! or an `apply` migration.
//!
//! Lives outside `neothd` so a daemon release doesn't carry the
//! migration-only deps (pulldown-cmark today; future lance + git2).
//! Operators run this once during cutover, then never again.
//!
//! ## CLI
//!
//! ```text
//! neoth-migrate dry-run --manifest <PATH> [--root <PATH>]
//!     Scan-only. No WAL writes. Reads the operator's import manifest
//!     and prints a JSON report of every declared source: path, kind,
//!     row-count estimate, sample entries (first 3 rows / files).
//!
//! neoth-migrate apply --manifest <PATH> --confirm [--root <PATH>]
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
    about = "Phase-3 prior-agent store cutover for NEOTH (V10-06)"
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
    /// Path to your import manifest (YAML). Declare your prior-AI
    /// memory stores here — see examples/import-manifest.example.yaml.
    #[arg(long, value_name = "PATH")]
    manifest: std::path::PathBuf,
    /// Operator home override. Default: `$HOME` resolved at runtime.
    #[arg(long, value_name = "PATH")]
    root: Option<std::path::PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ApplyArgs {
    /// Path to your import manifest (YAML). Same file you used for
    /// dry-run.
    #[arg(long, value_name = "PATH")]
    manifest: std::path::PathBuf,
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
    let manifest = readers::load_manifest(&args.manifest)?;
    tracing::info!(
        home = %home.display(),
        sources = manifest.sources.len(),
        "neoth-migrate dry-run"
    );
    let report = readers::scan_all(&manifest.sources, &home);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_apply(args: ApplyArgs) -> Result<()> {
    // Validate the manifest loads before talking about confirm, so a
    // bad manifest is the first thing the operator hears about.
    let _manifest = readers::load_manifest(&args.manifest)?;
    if !args.confirm {
        anyhow::bail!(
            "refusing to apply without --confirm. Run `neoth-migrate dry-run --manifest \
             <PATH>` first to inspect what would be migrated, then re-run with --confirm."
        );
    }
    // The apply path (WAL writer + per-reader emitters) is a follow-up
    // implementation; today the dry-run path is what operators use to
    // validate their import layout before a cutover.
    anyhow::bail!(
        "Memory import (apply) is not yet available in this release. Use \
         `neoth-migrate dry-run --manifest <PATH>` to preview your import sources."
    );
}

fn default_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}
