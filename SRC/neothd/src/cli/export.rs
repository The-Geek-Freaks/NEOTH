//! `neoth export` — operator data dump. Phase 33c BS-8.
//!
//! Produces a JSONL-or-MD bundle of every event NEOTH stores about the
//! operator plus a canonical typed `communication_profile.json` (or explicit
//! absent marker). `--subject` instead emits a communication-only bundle for
//! one exact pseudonymous channel subject. Pure read; pairs with `neoth backup`
//! for the full operator GDPR right-to-export surface.

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

    /// Export only this exact pseudonymous communication-profile subject.
    /// Obtain handles with `--list-subjects`. This mode excludes operator-wide
    /// memory tables and archives from the bundle.
    #[arg(long, value_name = "SUBJECT", conflicts_with = "list_subjects")]
    pub subject: Option<String>,

    /// Strictly inventory pseudonymous communication-profile subject handles.
    /// No export directory is created and no profile content is printed.
    #[arg(long, conflicts_with_all = ["subject", "out", "since"])]
    pub list_subjects: bool,

    /// Output format for the summary line (NOT the export bundle itself).
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_export(args: ExportArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);

    if args.list_subjects {
        let inventory = export::communication_profile_inventory(&home)
            .with_context(|| format!("inventory communication profiles in {}", home.display()))?;
        return render_subject_inventory(&inventory, &args.output);
    }

    let out = args.out.unwrap_or_else(export::default_export_dir);
    let format = export::ExportFormat::from_str(&args.format).ok_or_else(|| {
        anyhow::anyhow!("invalid --format '{}'. Expected: jsonl | md", args.format)
    })?;
    let since = export::parse_since(args.since.as_deref())?;

    let summary = match args.subject.as_deref() {
        Some(subject) => export::run_communication_subject_export(&home, &out, subject)
            .with_context(|| {
                format!(
                    "export selected communication subject {} → {}",
                    home.display(),
                    out.display()
                )
            })?,
        None => export::run_export(&home, &out, format, since)
            .with_context(|| format!("export {} → {}", home.display(), out.display()))?,
    };

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
                "  communication      : {} selected subject(s), {} dimension(s), {} evidence record(s), {} context record(s)",
                summary.communication_profile_subjects,
                summary.communication_profile_dimensions,
                summary.communication_profile_evidence_records,
                summary.communication_profile_declared_context_records,
            );
            println!(
                "  communication file : schema={} state={} state_schema={}",
                summary.communication_profile_export_schema_version,
                if summary.communication_profile_state_present {
                    "present"
                } else {
                    "absent"
                },
                summary
                    .communication_profile_state_schema_version
                    .map_or_else(|| "-".to_owned(), |version| version.to_string()),
            );
            println!(
                "  subject selector   : sha256:{} ({})",
                &summary.communication_profile_subject_sha256
                    [..summary.communication_profile_subject_sha256.len().min(16)],
                if summary.communication_profile_operator_subject {
                    "operator"
                } else {
                    "pseudonymous channel subject"
                },
            );
            println!(
                "  bundle scope       : {}",
                if summary.communication_profile_only {
                    "selected communication profile only"
                } else {
                    "operator data plus operator communication profile"
                }
            );
            println!("  archive files      : {}", summary.archive_files_copied);
        }
    }
    Ok(())
}

fn render_subject_inventory(
    inventory: &export::CommunicationProfileInventory,
    output: &OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(inventory)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(inventory)?),
        OutputFormat::Table => {
            println!("# Communication-profile subject inventory");
            println!(
                "  state              : {}",
                if inventory.state_present {
                    "present"
                } else {
                    "absent"
                }
            );
            if inventory.subjects.is_empty() {
                println!("  No communication-profile subjects stored.");
            } else {
                println!("  Handles are pseudonymous exact selectors; case-sensitive and private.");
                for subject in &inventory.subjects {
                    println!(
                        "  {}  sha256:{}  kind={}  dimensions={} evidence={} context={}",
                        subject.subject_handle,
                        &subject.subject_sha256[..subject.subject_sha256.len().min(16)],
                        if subject.operator_subject {
                            "operator"
                        } else {
                            "channel"
                        },
                        subject.dimensions,
                        subject.evidence_records,
                        subject.declared_context_records,
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn subject_selector_and_inventory_are_explicit_cli_modes() {
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
}
