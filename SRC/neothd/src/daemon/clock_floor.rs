//! Monotonic clock floor — Phase 33c BS-5.
//!
//! The HLC writer trusts `SystemTime::now()` to produce monotonically
//! increasing nanoseconds. If the operator (or NTP, or a VM snapshot
//! rollback) sets the clock backwards, frames written after the rewind
//! get smaller `physical_ns` than frames written before — recall ordering
//! breaks, decay math fails, and the audit trail looks tampered with.
//!
//! Defence: persist the highest `now_ns` we've ever observed to
//! `~/.neoth/clock.floor` and check it at startup + on every consolidation
//! pass. If the current clock is more than `MAX_ROLLBACK_NS` below the
//! floor, refuse to write (operator can pass `--allow-clock-rollback` to
//! the daemon as an explicit override — e.g. they intentionally restored
//! a backup).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::FreedomConfig;

/// `~/.neoth/clock.floor`.
pub fn default_floor_path() -> PathBuf {
    FreedomConfig::default_neoth_home().join("clock.floor")
}

/// How far behind the floor the system clock can be before we refuse to
/// run. 60 seconds covers NTP slew + DST adjustments + small VM-snapshot
/// drift while still catching real rollbacks.
pub const MAX_ROLLBACK_NS: u64 = 60 * 1_000_000_000;

/// Read the persisted floor. Returns `0` when the file is missing or
/// unparseable — a fresh install has no floor, that's fine.
pub fn read_floor(path: &Path) -> u64 {
    let Ok(body) = std::fs::read_to_string(path) else {
        return 0;
    };
    body.trim().parse::<u64>().unwrap_or(0)
}

/// Write `now_ns` as the new floor, but only when it actually exceeds the
/// currently-stored value. Cheap call — safe to invoke from every WAL
/// frame's hot path.
pub fn persist_floor(path: &Path, now_ns: u64) -> Result<()> {
    let current = read_floor(path);
    if now_ns <= current {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create clock-floor dir {}", parent.display()))?;
    }
    std::fs::write(path, format!("{now_ns}\n"))
        .with_context(|| format!("write clock floor {}", path.display()))?;
    Ok(())
}

/// Check that `now_ns` is at most `MAX_ROLLBACK_NS` below the persisted
/// floor. Returns `Ok(())` on the happy path, `Err` with a human-readable
/// message that includes the gap when the clock rolled back too far.
pub fn check(path: &Path, now_ns: u64) -> Result<()> {
    let floor = read_floor(path);
    if floor == 0 {
        // Fresh install: nothing to compare against.
        return Ok(());
    }
    if now_ns >= floor {
        return Ok(());
    }
    let gap_ns = floor - now_ns;
    if gap_ns <= MAX_ROLLBACK_NS {
        // Tolerable drift (NTP slew, DST, small VM snapshot).
        return Ok(());
    }
    let gap_secs = gap_ns / 1_000_000_000;
    anyhow::bail!(
        "clock rollback detected: system clock is {gap_secs} seconds before \
         the last observed timestamp (floor file: {}). Pass \
         --allow-clock-rollback to override (rare; usually means a backup \
         restore or VM snapshot rewind).",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_floor_returns_zero_when_missing() {
        let dir = tempdir().unwrap();
        assert_eq!(read_floor(&dir.path().join("absent")), 0);
    }

    #[test]
    fn read_floor_tolerates_garbage_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clock.floor");
        std::fs::write(&path, "not a number").unwrap();
        assert_eq!(read_floor(&path), 0);
    }

    #[test]
    fn persist_writes_when_now_exceeds_floor() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clock.floor");
        persist_floor(&path, 100).unwrap();
        assert_eq!(read_floor(&path), 100);
        persist_floor(&path, 200).unwrap();
        assert_eq!(read_floor(&path), 200);
    }

    #[test]
    fn persist_no_op_when_now_below_or_equal_floor() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clock.floor");
        persist_floor(&path, 500).unwrap();
        persist_floor(&path, 200).unwrap(); // earlier — must NOT overwrite
        assert_eq!(read_floor(&path), 500);
        persist_floor(&path, 500).unwrap(); // equal — also no-op
        assert_eq!(read_floor(&path), 500);
    }

    #[test]
    fn check_passes_on_fresh_install() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("absent");
        assert!(check(&path, 1_000_000).is_ok());
    }

    #[test]
    fn check_passes_when_clock_advanced() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clock.floor");
        persist_floor(&path, 1_000).unwrap();
        assert!(check(&path, 2_000).is_ok());
    }

    #[test]
    fn check_tolerates_small_rollback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clock.floor");
        let floor = 100 * 1_000_000_000u64; // 100s
        persist_floor(&path, floor).unwrap();
        // Roll back 30s — still within the 60s window.
        assert!(check(&path, floor - 30 * 1_000_000_000).is_ok());
    }

    #[test]
    fn check_fails_on_large_rollback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clock.floor");
        let floor = 1_000 * 1_000_000_000u64;
        persist_floor(&path, floor).unwrap();
        // Roll back 5 minutes — far beyond the 60s tolerance.
        let r = check(&path, floor - 5 * 60 * 1_000_000_000);
        assert!(r.is_err(), "5-minute rollback must fail");
        let msg = format!("{r:?}");
        assert!(msg.contains("clock rollback"));
        assert!(msg.contains("--allow-clock-rollback"));
    }
}
