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
    let n = backup::write_backup(&home, &out, include_wal)
        .with_context(|| format!("write backup to {}", out.display()))?;
    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "wrote": out.display().to_string(),
                    "entries": n,
                    "include_wal": include_wal,
                })
            );
        }
        OutputFormat::Table => {
            println!("backup written: {} ({n} top-level entries)", out.display());
            if !include_wal {
                println!("(WAL segments skipped per --no-wal; restored host will need re-index)");
            } else {
                println!("(WAL segments bundled — full consistent restore)");
            }
        }
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
