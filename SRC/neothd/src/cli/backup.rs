//! `neoth backup` / `neoth restore` — Phase 33c BS-2.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::daemon::backup;

#[derive(Args, Debug, Clone)]
pub struct BackupArgs {
    /// Output path for the `.tar.gz`. Defaults to
    /// `~/.neoth/backups/neoth-<UTC-timestamp>.tar.gz`.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Skip raw WAL segments. Default behaviour bundles them — the
    /// WAL is the source of truth + the operator-flow audit (2026-05-19)
    /// flagged "default-without-WAL produces inconsistent restores
    /// where views.db cursors reference segments that don't exist".
    /// Pass `--no-wal` to opt out (saves disk, but restored host needs
    /// to re-index from scratch).
    #[arg(long = "no-wal")]
    pub skip_wal: bool,
    /// Exclude `credentials.yaml` (API keys, channel tokens) from the
    /// tarball. By default it IS bundled — otherwise a restore is
    /// missing every key — but the archive is plaintext, so backup
    /// prints a warning and `--no-credentials` lets you opt out (e.g.
    /// when the archive will live on untrusted storage).
    #[arg(long = "no-credentials")]
    pub skip_credentials: bool,
    /// Override the ~/.neoth source dir (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Args, Debug, Clone)]
pub struct RestoreArgs {
    /// Path to the `.tar.gz` to restore.
    pub archive: PathBuf,
    /// Target directory. Defaults to `~/.neoth/`.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Overwrite the target if it's non-empty.
    #[arg(long)]
    pub force: bool,
    /// Output format.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_backup(args: BackupArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let out = args.out.unwrap_or_else(backup::default_backup_path);
    let include_wal = !args.skip_wal;
    let include_credentials = !args.skip_credentials;
    let outcome = backup::write_backup(&home, &out, include_wal, include_credentials)
        .with_context(|| format!("write backup to {}", out.display()))?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "wrote": out.display().to_string(),
                    "entries": outcome.included,
                    "include_wal": include_wal,
                    "includes_plaintext_credentials": outcome.included_plaintext_credentials,
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "backup written: {} ({} top-level entries)",
                out.display(),
                outcome.included
            );
            if !include_wal {
                println!("(WAL segments skipped per --no-wal; restored host will need re-index)");
            } else {
                println!("(WAL segments bundled — full consistent restore)");
            }
        }
    }
    // Loud plaintext-secrets warning regardless of output format — the
    // operator must know the archive carries unencrypted API keys/tokens.
    if outcome.included_plaintext_credentials {
        eprintln!(
            "⚠  WARNING: this backup contains credentials.yaml in PLAINTEXT (API keys, channel tokens).\n\
             ⚠  Store it on encrypted media. Re-run with --no-credentials to exclude them."
        );
    }
    Ok(())
}

pub async fn run_restore(args: RestoreArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let n = backup::restore_backup(&args.archive, &home, args.force)
        .with_context(|| format!("restore from {}", args.archive.display()))?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "restored": home.display().to_string(),
                    "entries": n,
                })
            );
        }
        OutputFormat::Table => {
            println!("restored {n} entry/entries into {}", home.display());
        }
    }
    Ok(())
}
