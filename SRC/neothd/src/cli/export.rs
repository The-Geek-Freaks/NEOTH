//! `neoth export` — operator data dump. Phase 33c BS-8.
//!
//! Produces a JSONL-or-MD bundle of every event NEOTH stores about the
//! operator plus a redacted `communication_profile.json` (or explicit absent
//! marker). It never exports communication-profile subjects, evidence, or
//! declared context. Pure read; pairs with `neoth backup` for the full operator
//! GDPR right-to-export surface.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::daemon::{export, train_export};

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

    /// Reserved private-DSAR selector. Generic export has no authenticated
    /// private DSAR authority, so this currently fails without reading or
    /// writing local state.
    #[arg(long, value_name = "SUBJECT", conflicts_with = "list_subjects")]
    pub subject: Option<String>,

    /// Reserved private-DSAR inventory. Generic export has no authenticated
    /// private DSAR authority, so this currently fails without reading or
    /// printing local state.
    #[arg(long, conflicts_with_all = ["subject", "out", "since"])]
    pub list_subjects: bool,

    #[command(subcommand)]
    pub action: Option<ExportAction>,

    /// Output format for the summary line (NOT the export bundle itself).
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ExportAction {
    /// Build a local redacted SFT JSONL from exact Accepted terminal receipts.
    #[command(name = "training-set")]
    TrainingSet(TrainingSetArgs),
}

#[derive(Args, Debug, Clone)]
pub struct TrainingSetArgs {
    /// Explicit JSONL destination. A sibling `.manifest.json` is published with it.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    #[arg(long, value_enum)]
    pub format: TrainingSetFormatArg,
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum TrainingSetFormatArg { Openai, Sharegpt }
impl TrainingSetFormatArg { fn as_export_format(self) -> train_export::TrainingSetFormat { match self { Self::Openai => train_export::TrainingSetFormat::Openai, Self::Sharegpt => train_export::TrainingSetFormat::Sharegpt } } }

pub async fn run_export(args: ExportArgs) -> Result<()> {
    ensure_generic_export_authority(&args)?;
    if let Some(ExportAction::TrainingSet(training)) = args.action {
        return run_training_set(training, args.output);
    }
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let out = args.out.unwrap_or_else(export::default_export_dir);
    let format = export::ExportFormat::from_str(&args.format).ok_or_else(|| anyhow::anyhow!("invalid --format '{}'. Expected: jsonl | md", args.format))?;
    let since = export::parse_since(args.since.as_deref())?;
    let summary = export::run_export(&home, &out, format, since).with_context(|| format!("export {} → {}", home.display(), out.display()))?;
    match args.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&summary)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&summary)?),
        OutputFormat::Table => {
            println!("# NEOTH export → {}", summary.output_dir);
            println!("  idx_episode        : {}", summary.episode_rows);
            println!("  idx_consolidated   : {}", summary.consolidated_rows);
            println!("  idx_longterm       : {}", summary.longterm_rows);
            println!("  idx_groundtruth    : {}", summary.groundtruth_rows);
            println!(
                "  communication file : schema={} state={} state_schema={} redacted={}",
                summary.communication_profile_export_schema_version,
                if summary.communication_profile_state_present {
                    "present"
                } else {
                    "absent"
                },
                summary
                    .communication_profile_state_schema_version
                    .map_or_else(|| "-".to_owned(), |version| version.to_string()),
                summary.communication_profile_redacted,
            );
            println!("  archive files      : {}", summary.archive_files_copied);
        }
    }
    Ok(())
}

fn run_training_set(args: TrainingSetArgs, output: OutputFormat) -> Result<()> {
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);
    let summary = train_export::export_training_set(&home, &args.out, args.format.as_export_format())?;
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&summary)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&summary)?),
        OutputFormat::Table => {
            println!("# NEOTH training-set export");
            println!("  dataset             : {}", summary.output_path);
            println!("  manifest            : {}", summary.manifest_path);
            println!("  format              : {}", summary.format);
            println!("  exported            : {}", summary.exported);
            println!("  teacher corrected   : {}", summary.teacher_corrected);
            println!("  excluded negatives  : {}", summary.excluded_needs_correction + summary.excluded_not_helpful);
            println!("  excluded unlabelled : {}", summary.excluded_unlabelled);
            println!("  excluded legacy     : {}", summary.excluded_legacy_unbound);
            println!("  excluded missing    : {}", summary.excluded_missing_source);
            println!("  excluded duplicate  : {}", summary.excluded_duplicate_binding);
            println!("  excluded teacher    : {}", summary.excluded_teacher_ambiguous);
            println!("  unchanged           : {}", summary.unchanged);
        }
    }
    Ok(())
}

fn ensure_generic_export_authority(args: &ExportArgs) -> Result<()> {
    if args.subject.is_some() || args.list_subjects { return Err(export::private_dsar_authority_unavailable()); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_dsar_flags_remain_parser_compatible() {
        use crate::cli::{Cli, Commands};
        use clap::Parser;

        let cli =
            Cli::try_parse_from(["neoth", "export", "--subject", "native:matrix:abc"]).unwrap();
        let Commands::Export(args) = cli.command else {
            panic!("export command expected")
        };
        assert_eq!(args.subject.as_deref(), Some("native:matrix:abc"));
        assert!(!args.list_subjects);

        let cli = Cli::try_parse_from(["neoth", "export", "--list-subjects"]).unwrap();
        let Commands::Export(args) = cli.command else {
            panic!("export command expected")
        };
        assert!(args.list_subjects);
        assert!(args.subject.is_none());

        assert!(
            Cli::try_parse_from([
                "neoth",
                "export",
                "--list-subjects",
                "--subject",
                "operator",
            ])
            .is_err()
        );
    }

    #[test]
    fn training_set_cli_is_explicit() {
        use crate::cli::{Cli, Commands}; use clap::Parser;
        let cli = Cli::try_parse_from(["neoth", "export", "training-set", "--out", "set.jsonl", "--format", "openai"]).unwrap();
        assert!(matches!(cli.command, Commands::Export(ExportArgs { action: Some(ExportAction::TrainingSet(TrainingSetArgs { format: TrainingSetFormatArg::Openai, .. })), .. })));
        assert!(Cli::try_parse_from(["neoth", "export", "training-set", "--format", "openai"]).is_err());
        assert!(Cli::try_parse_from(["neoth", "export", "training-set", "--out", "set.jsonl", "--format", "openai", "--text", "no"]).is_err());
    }

    #[test]
    fn private_dsar_flags_fail_closed_before_export_io() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("must-not-write");
        let home = root.path().join("must-not-read");
        let base = ExportArgs {
            out: Some(output.clone()),
            since: None,
            format: "jsonl".to_owned(),
            home: Some(home.clone()),
            subject: None,
            list_subjects: false,
            action: None,
            output: OutputFormat::Table,
        };

        for args in [
            ExportArgs {
                subject: Some("native:matrix:private-handle".to_owned()),
                ..base.clone()
            },
            ExportArgs {
                list_subjects: true,
                ..base
            },
        ] {
            let error = ensure_generic_export_authority(&args).unwrap_err();
            assert!(
                error
                    .downcast_ref::<export::PrivateDsarAuthorityUnavailable>()
                    .is_some()
            );
            assert_eq!(error.to_string(), "private DSAR authority unavailable");
        }
        assert!(!output.exists());
        assert!(!home.exists());
    }
}
