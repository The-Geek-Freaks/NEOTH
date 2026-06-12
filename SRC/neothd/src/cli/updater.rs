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

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::config::FreedomConfig;
use crate::wal::events::EVENT_TYPE_UPDATER_TASK_RESULT;
use crate::wal::payloads_u04::{UpdaterTaskResultPayload, render_updater_status};

#[derive(Args, Debug, Clone)]
pub struct UpdaterArgs {
    #[command(subcommand)]
    pub action: UpdaterAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UpdaterAction {
    /// Print the most recent updater task results in a readable
    /// table.
    ///
    /// Default mode reads from the live WAL at
    /// `~/.neoth/wal/000001.wal`. Override with `--wal-segment
    /// <path>` to read a specific segment, or `--from-jsonl
    /// <path>` for a synthetic file (operator dry-runs +
    /// integration tests).
    Status {
        /// Path to a specific WAL segment to scan for
        /// `0x45 UPDATER_TASK_RESULT` frames. Defaults to
        /// `~/.neoth/wal/000001.wal`.
        #[arg(long, value_name = "PATH", conflicts_with = "from_jsonl")]
        wal_segment: Option<PathBuf>,
        /// Path to a JSONL file containing one
        /// `UpdaterTaskResultPayload` per line. Overrides the WAL
        /// scan when set; used by tests + operator dry-runs.
        #[arg(long, value_name = "PATH")]
        from_jsonl: Option<PathBuf>,
    },
    /// Bootstrap entry. Today's slice prints a friendly hint —
    /// the actual check pipeline lands with U-01..U-03.
    Check,
}

pub fn run_updater(args: UpdaterArgs) -> Result<()> {
    match args.action {
        UpdaterAction::Status {
            wal_segment,
            from_jsonl,
        } => {
            let results = if let Some(path) = from_jsonl {
                load_results_from_jsonl(&path)?
            } else {
                let segment = wal_segment
                    .unwrap_or_else(|| FreedomConfig::default_wal_dir().join("000001.wal"));
                load_results_from_wal(&segment)?
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

/// Scan a WAL segment for `0x45 UPDATER_TASK_RESULT` frames and
/// deserialize each payload. Frame ordering is preserved, so the
/// most recent result-per-task is the LAST entry per task_kind
/// in the returned Vec.
///
/// Returns an empty Vec when the segment file doesn't exist
/// (operator hasn't started `neoth serve` yet) — same friendly
/// behaviour as the JSONL path.
pub fn load_results_from_wal(segment_path: &Path) -> Result<Vec<UpdaterTaskResultPayload>> {
    let bytes = match std::fs::read(segment_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    // GOLD-ARCH-03: for_each_frame so UPDATER_TASK_RESULT frames inside a
    // v2/zstd-compressed segment are read, not silently skipped.
    if let Err(e) = crate::wal::scan::for_each_frame(&bytes, |_, decoded| {
        if decoded.header.event_type == EVENT_TYPE_UPDATER_TASK_RESULT {
            if let Ok(payload) = serde_json::from_slice::<UpdaterTaskResultPayload>(decoded.payload)
            {
                out.push(payload);
            }
        }
        Ok(())
    }) {
        // GR-103 — surface a tamper-suspect segment (its updater-result frames
        // won't be read) instead of silently discarding the error.
        tracing::warn!(error = %e, "updater-results scan: skipping a tamper-suspect WAL segment");
    }
    Ok(out)
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
    fn run_status_with_explicit_missing_wal_prints_bootstrap_hint() {
        // Point at a tempdir-segment that doesn't exist. The WAL
        // reader returns empty + render_updater_status prints the
        // "no record yet" friendly line. No error.
        let dir = tempfile::tempdir().unwrap();
        let args = UpdaterArgs {
            action: UpdaterAction::Status {
                wal_segment: Some(dir.path().join("nonexistent.wal")),
                from_jsonl: None,
            },
        };
        run_updater(args).expect("status with missing wal");
    }

    #[test]
    fn run_status_with_jsonl_renders_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.jsonl");
        let line = serde_json::to_string(&sample_result()).unwrap();
        std::fs::write(&path, format!("{line}\n")).unwrap();
        let args = UpdaterArgs {
            action: UpdaterAction::Status {
                wal_segment: None,
                from_jsonl: Some(path),
            },
        };
        run_updater(args).expect("status with jsonl");
    }

    #[test]
    fn load_from_wal_missing_segment_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let r = load_results_from_wal(&dir.path().join("absent.wal")).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn load_from_wal_too_short_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.wal");
        std::fs::write(&path, [0u8; 5]).unwrap();
        let r = load_results_from_wal(&path).unwrap();
        assert!(r.is_empty());
    }

    #[tokio::test]
    async fn load_from_wal_returns_emitted_results_only() {
        // Spawn a WAL writer, emit one 0x45 UPDATER_TASK_RESULT
        // frame + one 0x10 BOOT frame, scan back. Only the 0x45
        // payload should round-trip.
        use crate::wal::events::EVENT_TYPE_BOOT;
        use crate::wal::{EventFlags, HeaderBuilder};

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("u04.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        // Emit one unrelated BOOT frame first.
        let boot_payload = b"boot";
        let boot_header = HeaderBuilder::new(EVENT_TYPE_BOOT, boot_payload).build();
        writer
            .append(boot_header, boot_payload.to_vec())
            .await
            .unwrap();

        // Emit the UPDATER_TASK_RESULT.
        let payload = sample_result();
        let body = serde_json::to_vec(&payload).unwrap();
        let header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_RESULT, &body)
            .flags(EventFlags::SYNTHETIC)
            .build();
        writer.append(header, body).await.unwrap();

        // Tiny wait so fsync flushes; the synchronous fs::read
        // below otherwise races the writer thread.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(writer);

        let results = load_results_from_wal(&seg).unwrap();
        assert_eq!(results.len(), 1, "only the 0x45 frame should match");
        assert_eq!(results[0].task_kind, payload.task_kind);
        assert_eq!(results[0].ts_unix, payload.ts_unix);
    }

    #[test]
    fn run_check_prints_today_noop_hint() {
        let args = UpdaterArgs {
            action: UpdaterAction::Check,
        };
        run_updater(args).expect("check no-op");
    }
}
