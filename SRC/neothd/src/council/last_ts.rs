//! B-3 (Session 13) — persist + read the timestamp of the most recent
//! council debate so `TriggerContext::seconds_since_last_council` is real
//! instead of hardcoded `u64::MAX`. Without this the rate-cooldown gate
//! (`trigger::should_convene` Gate 2) never fires, and council debates
//! can stack up on back-to-back prompts.
//!
//! Persistence: a one-line file at `~/.neoth/council_last.json` with a
//! single field `{ "last_unix": u64 }`. Atomic write via tempfile-rename
//! so a crash mid-write never leaves a malformed file. Read failures
//! return `u64::MAX` (semantics: "no record, the gate is open").

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const FILENAME: &str = "council_last.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct LastRecord {
    last_unix: u64,
}

pub fn path(home: &Path) -> PathBuf {
    home.join(FILENAME)
}

/// Return seconds since the last recorded council debate at `now`.
/// `u64::MAX` when the file is missing, malformed, or in the future.
pub fn seconds_since_last(home: &Path, now_unix: u64) -> u64 {
    let p = path(home);
    let Ok(body) = fs::read_to_string(&p) else {
        return u64::MAX;
    };
    let Ok(rec) = serde_json::from_str::<LastRecord>(&body) else {
        return u64::MAX;
    };
    now_unix.saturating_sub(rec.last_unix)
}

/// Record `now_unix` as the most recent council timestamp. Atomic write
/// — temp file in same dir, then rename. Failure is non-fatal: the
/// caller's audit continues with a warning. The rate-cooldown gate
/// simply doesn't tighten until the next successful write.
pub fn record(home: &Path, now_unix: u64) -> Result<()> {
    fs::create_dir_all(home).with_context(|| format!("create {}", home.display()))?;
    let target = path(home);
    let tmp = target.with_extension("json.tmp");
    let body = serde_json::to_string(&LastRecord {
        last_unix: now_unix,
    })?;
    fs::write(&tmp, body.as_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &target).with_context(|| format!("rename {}", target.display()))?;
    Ok(())
}

/// Current wall-clock seconds since Unix epoch. Used by callers to feed
/// `record` + `seconds_since_last`. Centralised so tests can substitute
/// a clock without sprinkling SystemTime calls across the dispatch
/// path.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn seconds_since_last_returns_max_when_file_missing() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(seconds_since_last(tmp.path(), 1_000_000), u64::MAX);
    }

    #[test]
    fn seconds_since_last_returns_max_when_file_malformed() {
        let tmp = TempDir::new().unwrap();
        fs::write(path(tmp.path()), b"not json").unwrap();
        assert_eq!(seconds_since_last(tmp.path(), 1_000_000), u64::MAX);
    }

    #[test]
    fn record_then_read_round_trips_zero_seconds() {
        let tmp = TempDir::new().unwrap();
        record(tmp.path(), 1_700_000_000).unwrap();
        let elapsed = seconds_since_last(tmp.path(), 1_700_000_000);
        assert_eq!(elapsed, 0);
    }

    #[test]
    fn record_then_read_returns_actual_delta() {
        let tmp = TempDir::new().unwrap();
        record(tmp.path(), 1_700_000_000).unwrap();
        let elapsed = seconds_since_last(tmp.path(), 1_700_000_060);
        assert_eq!(elapsed, 60);
    }

    #[test]
    fn record_overwrites_previous_value() {
        let tmp = TempDir::new().unwrap();
        record(tmp.path(), 1_700_000_000).unwrap();
        record(tmp.path(), 1_700_001_000).unwrap();
        let elapsed = seconds_since_last(tmp.path(), 1_700_001_000);
        assert_eq!(elapsed, 0);
    }

    #[test]
    fn seconds_since_last_saturates_when_now_before_record() {
        // Clock went backwards (rare but real on VM snapshots / NTP
        // jumps). `saturating_sub` returns 0 — gate behaves as if no
        // cooldown remains rather than wrapping to a huge u64 value.
        let tmp = TempDir::new().unwrap();
        record(tmp.path(), 2_000_000_000).unwrap();
        let elapsed = seconds_since_last(tmp.path(), 1_000_000_000);
        assert_eq!(elapsed, 0);
    }

    #[test]
    fn record_leaves_no_tmp_file_after_success() {
        let tmp = TempDir::new().unwrap();
        record(tmp.path(), 1_700_000_000).unwrap();
        let tmp_path = path(tmp.path()).with_extension("json.tmp");
        assert!(!tmp_path.exists(), "atomic rename must not leave .tmp");
    }
}
