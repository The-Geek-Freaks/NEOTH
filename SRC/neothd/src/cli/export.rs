//! `neoth export` — operator data dump. Phase 33c BS-8.
//!
//! Produces a JSONL-or-MD bundle of every event NEOTH stores about the
//! operator. Pure read; pairs with `neoth backup` for the full GDPR
//! right-to-export surface.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::daemon::export;

#[derive(Args, Debug, Clone)]
pub struct ExportArgs {
    /// Output directory. Default: `~/.neoth/exports/neoth-export-<UTC>/`.
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Filter to events at-or-after this date. Format `YYYY-MM-DD`.
    /// Defaults to "everything ever recorded".
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,

    /// Output format. `jsonl` = one event per line (default, lossless).
    /// `md` = human-readable digest grouped by day.
    #[arg(long, default_value = "jsonl")]
    pub format: String,

    /// Override the `~/.neoth/` home dir (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Output format for the summary line (NOT the export bundle itself).
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_export(args: ExportArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let out = args.out.unwrap_or_else(export::default_export_dir);
    let format = export::ExportFormat::from_str(&args.format).ok_or_else(|| {
        anyhow::anyhow!("invalid --format '{}'. Expected: jsonl | md", args.format)
    })?;
    let since = export::parse_since(args.since.as_deref())?;

    let summary = export::run_export(&home, &out, format, since)
        .with_context(|| format!("export {} → {}", home.display(), out.display()))?;

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        OutputFormat::Table => {
            println!("# NEOTH export → {}", summary.output_dir);
            println!("  idx_episode        : {}", summary.episode_rows);
            println!("  idx_consolidated   : {}", summary.consolidated_rows);
            println!("  idx_longterm       : {}", summary.longterm_rows);
            println!("  idx_groundtruth    : {}", summary.groundtruth_rows);
            println!("  archive files      : {}", summary.archive_files_copied);
        }
    }
    Ok(())
}
