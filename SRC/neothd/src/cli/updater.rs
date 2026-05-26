//! `neoth updater` — operator-facing view of U-01..U-04 lane.
//!
//! Subcommands:
//!   - `neoth updater status` — render the most recent
//!     `UpdaterTaskResultPayload`s as a table.
//!   - `neoth updater check` — bootstrap entry for cron+manual
//!     pass (wire-up lands in U-01/02/03; CLI surface here so
//!     `neoth updater status`'s "Run `neoth updater check`"
//!     prompt resolves).
//!
//! The actual WAL-read happens when U-01/02/03 wire up; today
//! this command accepts a `--from-jsonl <path>` flag for the
//! operator (or test) to feed in a synthetic payload list.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::wal::payloads_u04::{UpdaterTaskResultPayload, render_updater_status};

#[derive(Args, Debug, Clone)]
pub struct UpdaterArgs {
    #[command(subcommand)]
    pub action: UpdaterAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UpdaterAction {
    /// Print the most recent updater task results in a readable
    /// table. Wired against a JSONL file today (`--from-jsonl`);
    /// the live WAL-read path lands when U-01/02/03 surface the
    /// reader hook.
    Status {
        /// Path to a JSONL file containing one
        /// `UpdaterTaskResultPayload` per line. When omitted, the
        /// command prints the friendly "no record yet" message.
        #[arg(long, value_name = "PATH")]
        from_jsonl: Option<PathBuf>,
    },
    /// Bootstrap entry. Today's slice prints a friendly hint —
    /// the actual check pipeline lands with U-01..U-03.
    Check,
}

pub fn run_updater(args: UpdaterArgs) -> Result<()> {
    match args.action {
        UpdaterAction::Status { from_jsonl } => {
            let results = match from_jsonl {
                Some(path) => load_results_from_jsonl(&path)?,
                None => Vec::new(),
            };
            print!("{}", render_updater_status(&results));
            Ok(())
        }
        UpdaterAction::Check => {
            println!(
                "neoth updater check — \
                 will run U-01 (self-update), U-02 (skills+plugins), \
                 U-03 (CLI versions) when wired. Today: no-op."
            );
            Ok(())
        }
    }
}

/// Load `UpdaterTaskResultPayload` entries from a JSONL file —
/// one payload per line. Skips malformed lines silently (operator
/// might have an in-progress file).
pub fn load_results_from_jsonl(path: &std::path::Path) -> Result<Vec<UpdaterTaskResultPayload>> {
    let body = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(body
        .lines()
        .filter_map(|l| serde_json::from_str::<UpdaterTaskResultPayload>(l).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::payloads_u04::{ComponentOutcome, UpdaterTaskKind};

    fn sample_result() -> UpdaterTaskResultPayload {
        UpdaterTaskResultPayload {
            task_kind: UpdaterTaskKind::CliVersions,
            ts_unix: 100,
            duration_ms: 500,
            components: vec![
                ComponentOutcome::up_to_date("claude-cli", "1.2.3"),
                ComponentOutcome::upgraded("codex", "0.4.0", "0.5.0"),
            ],
        }
    }

    #[test]
    fn load_jsonl_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("nope.jsonl");
        let r = load_results_from_jsonl(&bogus).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn load_jsonl_parses_well_formed_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.jsonl");
        let line = serde_json::to_string(&sample_result()).unwrap();
        std::fs::write(&path, format!("{line}\n{line}\n")).unwrap();
        let r = load_results_from_jsonl(&path).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].task_kind, UpdaterTaskKind::CliVersions);
    }

    #[test]
    fn load_jsonl_skips_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed.jsonl");
        let line = serde_json::to_string(&sample_result()).unwrap();
        std::fs::write(&path, format!("{line}\nnot-json-at-all\n{line}\n")).unwrap();
        let r = load_results_from_jsonl(&path).unwrap();
        // Malformed line silently skipped; 2 good ones survive.
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn run_status_no_jsonl_prints_bootstrap_hint() {
        // Just verify no error from the no-args path.
        let args = UpdaterArgs {
            action: UpdaterAction::Status { from_jsonl: None },
        };
        run_updater(args).expect("status no-jsonl");
    }

    #[test]
    fn run_status_with_jsonl_renders_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.jsonl");
        let line = serde_json::to_string(&sample_result()).unwrap();
        std::fs::write(&path, format!("{line}\n")).unwrap();
        let args = UpdaterArgs {
            action: UpdaterAction::Status {
                from_jsonl: Some(path),
            },
        };
        run_updater(args).expect("status with jsonl");
    }

    #[test]
    fn run_check_prints_today_noop_hint() {
        let args = UpdaterArgs {
            action: UpdaterAction::Check,
        };
        run_updater(args).expect("check no-op");
    }
}
