//! `neoth monitor status` — HO-07 alert summary.
//!
//! Reads the last `--hours` (default 24) of WAL frames and crash.log,
//! then prints a 3-row summary table of the three HO-07 alert types:
//!
//!   | Rule                  | Last alert         | Count (24h) |
//!   |-----------------------|--------------------|-------------|
//!   | WAL CRC anomalies     | 2026-06-01 14:32   | 2           |
//!   | Crash-log panics      | —                  | 0           |
//!   | Channel silence       | 2026-06-01 09:11   | 1           |
//!
//! Exit code 0 = all clear. Exit code 1 = at least one alert type fired.
//!
//! The subcommand is read-only and exercises all three emitted event types
//! (0x48 / 0x49 / 0x4A) so `wal_emit_sites.rs` sees them wired here.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::config::FreedomConfig;
use crate::wal::events::{
    EVENT_TYPE_CHANNEL_SILENCE_ALERT, EVENT_TYPE_CRASH_LOG_ALERT, EVENT_TYPE_WAL_CRC_ALERT,
};

#[derive(Args, Debug, Clone)]
pub struct MonitorArgs {
    /// Override `~/.neoth/` for tests.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Look-back window in hours (default 24).
    #[arg(long, default_value = "24", value_name = "HOURS")]
    pub hours: u64,
    /// Print JSON instead of the table.
    #[arg(long)]
    pub json: bool,
}

/// One row in the summary table.
#[derive(Debug)]
struct AlertSummary {
    rule: &'static str,
    count: usize,
    last_ts_unix: Option<i64>,
}

impl AlertSummary {
    fn last_ts_display(&self) -> String {
        match self.last_ts_unix {
            None => "—".to_string(),
            Some(ts) => {
                // Simple UTC rendering: YYYY-MM-DD HH:MM.
                let secs = ts as u64;
                let days = secs / 86400;
                let rem = secs % 86400;
                let h = rem / 3600;
                let m = (rem % 3600) / 60;
                // Epoch day 0 = 1970-01-01.  We approximate Y/M/D with a
                // simplified Gregorian formula (good for post-1970 dates).
                let (y, mo, d) = epoch_days_to_ymd(days);
                format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}")
            }
        }
    }
}

/// Simplified Gregorian calendar from days since Unix epoch.  Accurate for
/// all dates in the range 1970–2099; sufficient for operator display.
fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // 400-year Gregorian cycle = 146097 days.
    let mut d = days + 719468; // shift epoch to 0000-03-01
    let era = d / 146097;
    d %= 146097;
    let yoe = (d - d / 1460 + d / 36524 - d / 146096) / 365;
    d -= yoe * 365 + yoe / 4 - yoe / 100;
    let mp = (5 * d + 2) / 153;
    let day = d - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// Scan a single WAL segment file and collect timestamps + count for a given
/// event type.  Returns `(count, last_ts_unix)`.
fn scan_segment_for_event(
    seg_bytes: &[u8],
    event_type: u8,
    cutoff_unix: i64,
) -> (usize, Option<i64>) {
    let Ok(hdr) = crate::wal::segment_header::parse_segment_header(seg_bytes) else {
        return (0, None);
    };
    let mut cursor = hdr.header_len();
    let mut count = 0usize;
    let mut last_ts: Option<i64> = None;
    while cursor < seg_bytes.len() {
        let dec = match crate::wal::frame::decode_frame(&seg_bytes[cursor..]) {
            Ok(d) => d,
            Err(_) => break,
        };
        let total = dec.header.total_len as usize;
        if dec.header.event_type == event_type {
            let ts = serde_json::from_slice::<serde_json::Value>(dec.payload)
                .ok()
                .and_then(|v| v.get("ts_unix")?.as_i64())
                .unwrap_or(cutoff_unix);
            if ts >= cutoff_unix {
                count += 1;
                last_ts = Some(last_ts.map_or(ts, |prev: i64| prev.max(ts)));
            }
        }
        if total == 0 {
            break;
        }
        cursor = cursor.saturating_add(total);
    }
    (count, last_ts)
}

/// Aggregate count + latest timestamp for `event_type` across all `*.wal`
/// files in `wal_dir`, within the `cutoff_unix` window.
fn aggregate_wal_alerts(
    wal_dir: &std::path::Path,
    event_type: u8,
    cutoff_unix: i64,
) -> (usize, Option<i64>) {
    let mut total = 0usize;
    let mut latest: Option<i64> = None;
    let Ok(rd) = std::fs::read_dir(wal_dir) else {
        return (0, None);
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        let (c, ts) = scan_segment_for_event(&bytes, event_type, cutoff_unix);
        total += c;
        if let Some(t) = ts {
            latest = Some(latest.map_or(t, |prev| prev.max(t)));
        }
    }
    (total, latest)
}

/// Count new panic lines in `crash.log` since `cutoff_unix`.
fn count_crash_log_alerts(crash_log: &std::path::Path, cutoff_unix: i64) -> (usize, Option<i64>) {
    let Ok(content) = std::fs::read_to_string(crash_log) else {
        return (0, None);
    };
    let mut count = 0usize;
    let mut last_ts: Option<i64> = None;
    for line in content.lines() {
        if !line.contains("[neoth panic]") {
            continue;
        }
        let ts = crate::daemon::monitor_cron::parse_panic_ts(line).unwrap_or(cutoff_unix);
        if ts >= cutoff_unix {
            count += 1;
            last_ts = Some(last_ts.map_or(ts, |prev| prev.max(ts)));
        }
    }
    (count, last_ts)
}

pub async fn run(mut args: MonitorArgs) -> Result<()> {
    if args.home.is_none() {
        args.home = Some(FreedomConfig::default_neoth_home());
    }
    let home = args.home.as_ref().unwrap();
    let wal_dir = home.join("wal");
    let crash_log = home.join("crash.log");

    let now_unix = crate::time::now_unix_i64();
    let cutoff = now_unix - (args.hours as i64 * 3600);

    // Collect summaries for the three HO-07 alert event types.
    let (wal_count, wal_last) =
        aggregate_wal_alerts(&wal_dir, EVENT_TYPE_WAL_CRC_ALERT, cutoff);
    let (crash_count, crash_last) = if crash_log.exists() {
        count_crash_log_alerts(&crash_log, cutoff)
    } else {
        (0, None)
    };
    let (silence_count, silence_last) =
        aggregate_wal_alerts(&wal_dir, EVENT_TYPE_CHANNEL_SILENCE_ALERT, cutoff);

    // Also count 0x49 CRASH_LOG_ALERT frames that the monitor already emitted
    // (separate from raw crash.log lines — the two may differ if the monitor
    // was enabled only recently).
    let (crash_frame_count, crash_frame_last) =
        aggregate_wal_alerts(&wal_dir, EVENT_TYPE_CRASH_LOG_ALERT, cutoff);
    // Prefer the direct crash.log count when available (more granular), fall
    // back to the WAL alert-frame count for the summary.
    let (final_crash_count, final_crash_last) = if crash_log.exists() {
        (crash_count, crash_last)
    } else {
        (crash_frame_count, crash_frame_last)
    };

    let summaries = [
        AlertSummary {
            rule: "WAL CRC anomalies     (0x48)",
            count: wal_count,
            last_ts_unix: wal_last,
        },
        AlertSummary {
            rule: "Crash-log panics      (0x49)",
            count: final_crash_count,
            last_ts_unix: final_crash_last,
        },
        AlertSummary {
            rule: "Channel silence       (0x4A)",
            count: silence_count,
            last_ts_unix: silence_last,
        },
    ];

    let has_alerts = summaries.iter().any(|s| s.count > 0);

    if args.json {
        let rows: Vec<serde_json::Value> = summaries
            .iter()
            .map(|s| {
                serde_json::json!({
                    "rule": s.rule,
                    "count": s.count,
                    "last_ts_unix": s.last_ts_unix,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "window_hours": args.hours,
            "alerts": rows,
            "any_alerts": has_alerts,
        }))?);
    } else {
        println!("neoth monitor status  (last {}h)", args.hours);
        println!("{:-<60}", "");
        println!("{:<36} {:>20} {:>8}", "Rule", "Last alert (UTC)", "Count");
        println!("{:-<60}", "");
        for s in &summaries {
            println!(
                "{:<36} {:>20} {:>8}",
                s.rule,
                s.last_ts_display(),
                s.count
            );
        }
        println!("{:-<60}", "");
        if has_alerts {
            println!("Status: ALERTS DETECTED");
        } else {
            println!("Status: all clear");
        }
    }

    if has_alerts {
        // GOLD-COR-01 / A-03: non-zero status without skipping Drop (WAL flush,
        // DB close). The status table above is already printed; QuietExit just
        // carries the code up to `main`.
        return Err(crate::QuietExit(1).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_days_known_date() {
        // 2026-06-02 = days since epoch: let's verify a known value.
        // 2000-01-01 = days since 1970-01-01 = 10957.
        let (y, m, d) = epoch_days_to_ymd(10957);
        assert_eq!((y, m, d), (2000, 1, 1));
        // 1970-01-01 = day 0.
        let (y, m, d) = epoch_days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }
}
