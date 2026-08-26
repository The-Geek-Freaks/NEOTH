//! `neoth export` — operator data dump. Phase 33c BS-8.
//!
//! Produces a JSONL-or-MD bundle of every event NEOTH stores about the
//! operator plus a redacted `communication_profile.json` (or explicit absent
//! marker). It never exports communication-profile subjects, evidence, or
//! declared context. Pure read; pairs with `neoth backup` for the full operator
//! GDPR right-to-export surface.

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

    /// Output format for the summary line (NOT the export bundle itself).
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_export(args: ExportArgs) -> Result<()> {
    ensure_generic_export_authority(&args)?;
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);

    let out = args.out.unwrap_or_else(export::default_export_dir);
    let format = export::ExportFormat::from_str(&args.format).ok_or_else(|| {
        anyhow::anyhow!("invalid --format '{}'. Expected: jsonl | md", args.format)
    })?;
    let since = export::parse_since(args.since.as_deref())?;

    let summary = export::run_export(&home, &out, format, since)
        .with_context(|| format!("export {} → {}", home.display(), out.display()))?;

    match args.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
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

/// Reject unimplemented private-subject export modes before resolving a home,
/// creating an output path, reading state, or rendering any output.
fn ensure_generic_export_authority(args: &ExportArgs) -> Result<()> {
    if args.subject.is_some() || args.list_subjects {
        return Err(export::private_dsar_authority_unavailable());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
