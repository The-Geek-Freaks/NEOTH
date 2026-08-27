//! `neoth history` — private, review-only historical export onboarding.
//!
//! V1 intentionally ends at human review/rejection.  It has no command that
//! may learn from an export, invoke tools/links, or mutate profile/recall data.

use std::path::PathBuf;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::path::Path;

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use crate::connectors::local_import::{
    approve_import_root, capture_verified_history_source,
    issue_interactive_history_import_capability,
};
use crate::memory::history_onboarding;
use crate::memory::store;

#[derive(Args, Debug, Clone)]
pub struct HistoryArgs {
    #[command(subcommand)]
    pub action: HistoryAction,

    #[cfg(test)]
    #[arg(skip)]
    database_override_for_test: Option<PathBuf>,

    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HistoryAction {
    /// Explicit interactive authorization to capture one no-follow export.
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Scan {
        /// Export file; it is read as data only and never executed.
        path: PathBuf,
        /// `chatgpt_export`, `claude_export`, or `openclaw_history`.
        #[arg(long, value_name = "FAMILY")]
        source: String,
    },
    /// Show bounded neutral excerpts for one batch, including resolved rows.
    Preview {
        #[arg(value_name = "BATCH_ID")]
        batch_id: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show the caller's own batches and privacy-exclusion counts.
    Status,
    /// Show only pending candidates for a batch. This is read-only.
    Review {
        #[arg(value_name = "BATCH_ID")]
        batch_id: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Reject exactly one pending candidate in the caller's subject namespace.
    Reject {
        #[arg(value_name = "CANDIDATE_ID")]
        candidate_id: String,
    },
    /// Logically delete exactly one review batch. This does not sanitize media.
    Purge {
        #[arg(value_name = "BATCH_ID")]
        batch_id: String,
        /// Required acknowledgement for a logical journal-row deletion.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run_history(args: HistoryArgs) -> Result<()> {
    let subject = trusted_current_subject()?;
    run_history_for_subject(args, &subject)
}

fn run_history_for_subject(args: HistoryArgs, subject: &str) -> Result<()> {
    #[cfg(not(test))]
    let db_path = store::default_history_path();
    #[cfg(test)]
    let db_path = args
        .database_override_for_test
        .clone()
        .unwrap_or_else(store::default_history_path);
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    let captured_scan = match &args.action {
        HistoryAction::Scan { path, source } => {
            let family = history_onboarding::SourceFamily::parse(source)?;
            let parent = path.parent().ok_or_else(|| {
                anyhow::anyhow!("history scan requires a selected export file")
            })?;
            let leaf = path.file_name().ok_or_else(|| {
                anyhow::anyhow!("history scan requires a selected export file")
            })?;
            let root = approve_import_root(parent)
                .context("approve the selected history-export directory")?;
            let mut plan_key = [0_u8; 32];
            getrandom::getrandom(&mut plan_key)
                .context("obtain OS randomness for history import authority")?;
            let capability = issue_interactive_history_import_capability(
                root,
                plan_key,
                subject,
                family.as_str(),
                Path::new(leaf),
                history_onboarding::MAX_SOURCE_BYTES,
            )
            .context("issue history import authority")?;
            let verified = capture_verified_history_source(capability)
            .context("capture selected history export through the bound handle")?;
            Some((family, verified))
        }
        _ => None,
    };
    let mut conn = store::open_private_history(&db_path)?;
    match args.action {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        HistoryAction::Scan { .. } => {
            let (family, verified) = captured_scan
                .ok_or_else(|| anyhow::anyhow!("missing history scan capture"))?;
            let status = history_onboarding::scan_verified_source(
                &mut conn,
                subject,
                family,
                verified,
                crate::time::now_unix_i64(),
            )?;
            print_status(args.output, &status);
        }
        HistoryAction::Preview { batch_id, limit } => {
            print_candidates(
                args.output,
                history_onboarding::preview(&conn, subject, &batch_id, limit)?,
            );
        }
        HistoryAction::Status => {
            print_statuses(
                args.output,
                history_onboarding::status(&conn, subject)?,
            );
        }
        HistoryAction::Review { batch_id, limit } => {
            print_candidates(
                args.output,
                history_onboarding::review(&conn, subject, &batch_id, limit)?,
            );
        }
        HistoryAction::Reject { candidate_id } => {
            let changed = history_onboarding::reject(
                &mut conn,
                subject,
                &candidate_id,
                crate::time::now_unix_i64(),
            )?;
            ensure!(changed, "pending candidate not found for this operator subject");
            print_json_or_table(args.output, serde_json::json!({"rejected": candidate_id}));
        }
        HistoryAction::Purge { batch_id, yes } => {
            ensure!(yes, "history purge requires --yes");
            let changed = history_onboarding::purge(&mut conn, subject, &batch_id)?;
            ensure!(changed, "history batch not found for this operator subject");
            print_json_or_table(
                args.output,
                serde_json::json!({
                    "logical_journal_purge": batch_id,
                    "media_sanitization": "not performed",
                }),
            );
        }
    }
    Ok(())
}

fn trusted_current_subject() -> Result<String> {
    let config = crate::config::FreedomConfig::load_from_default_path()
        .context("load freedom.yaml for current operator identity")?;
    let subject = config
        .operator_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("history commands require configured operator_id"))?;
    Ok(subject)
}

fn print_status(output: OutputFormat, status: &history_onboarding::BatchStatus) {
    print_json_or_table(
        output,
        serde_json::json!({
            "batch_id": status.batch_id,
            "source_family": status.source_family,
            "state": status.state,
            "candidate_count": status.candidate_count,
            "excluded_privacy_mode_count": status.excluded_privacy_mode_count,
            "skipped_structural_count": status.skipped_structural_count,
        }),
    );
}

fn print_statuses(output: OutputFormat, statuses: Vec<history_onboarding::BatchStatus>) {
    let rows = statuses.into_iter().map(|status| serde_json::json!({
        "batch_id": status.batch_id,
        "source_family": status.source_family,
        "state": status.state,
        "candidate_count": status.candidate_count,
        "excluded_privacy_mode_count": status.excluded_privacy_mode_count,
        "skipped_structural_count": status.skipped_structural_count,
    })).collect::<Vec<_>>();
    print_json_or_table(output, serde_json::Value::Array(rows));
}

fn print_candidates(output: OutputFormat, candidates: Vec<history_onboarding::CandidatePreview>) {
    let rows = candidates.into_iter().map(|candidate| serde_json::json!({
        "candidate_id": candidate.candidate_id,
        "batch_id": candidate.batch_id,
        "conversation_id": candidate.conversation_id,
        "turn_id": candidate.turn_id,
        "position": candidate.position,
        "kind": candidate.kind,
        "state": candidate.state,
        "excerpt": candidate.excerpt,
    })).collect::<Vec<_>>();
    print_json_or_table(output, serde_json::Value::Array(rows));
}

fn print_json_or_table(output: OutputFormat, value: serde_json::Value) {
    match output {
        OutputFormat::Json => println!("{value}"),
        OutputFormat::Jsonl => match value {
            serde_json::Value::Array(rows) => {
                for row in rows {
                    println!("{row}");
                }
            }
            other => println!("{other}"),
        },
        OutputFormat::Table => println!("{value}"),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use clap::Parser;

    use super::*;

    #[test]
    fn root_cli_rejects_history_database_redirect_flags() {
        let batch = "a".repeat(64);
        for flag in ["--db", "--database"] {
            let error = crate::cli::Cli::try_parse_from([
                "neoth",
                "history",
                "preview",
                &batch,
                flag,
                "redirect.db",
            ])
            .unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn failed_cli_capture_does_not_create_explicit_database() {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("history.db");
        let args = HistoryArgs {
            action: HistoryAction::Scan {
                path: root.path().join("missing-export.json"),
                source: "openclaw_history".to_string(),
            },
            database_override_for_test: Some(database.clone()),
            output: OutputFormat::Table,
        };
        assert!(run_history_for_subject(args, "operator-a").is_err());
        assert!(!database.exists());
        for sidecar in ["-wal", "-shm", "-journal"] {
            let mut path = OsString::from(database.as_os_str());
            path.push(sidecar);
            assert!(!PathBuf::from(path).exists());
        }
    }

    #[test]
    fn production_history_path_cannot_redirect_into_views_database() {
        let _env = crate::test_env::lock();
        let home = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("NEOTH_HOME");
        unsafe { std::env::set_var("NEOTH_HOME", home.path()) };
        let views_path = store::default_path();
        drop(store::open(&views_path).unwrap());
        let args = HistoryArgs {
            action: HistoryAction::Preview {
                batch_id: "a".repeat(64),
                limit: 1,
            },
            database_override_for_test: None,
            output: OutputFormat::Table,
        };

        run_history_for_subject(args, "operator-a").unwrap();
        let history_path = store::default_history_path();

        match previous {
            Some(value) => unsafe { std::env::set_var("NEOTH_HOME", value) },
            None => unsafe { std::env::remove_var("NEOTH_HOME") },
        }
        let views = store::open(&views_path).unwrap();
        let history_tables: i64 = views
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name LIKE 'history_onboarding_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let version: i64 = views
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((history_tables, version), (0, 37));
        assert!(history_path.exists());
    }
}
