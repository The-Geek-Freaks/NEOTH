//! Rolling-24h council-convene counter — GOLD-SEC-32 / B-19.
//!
//! The council budget gate (`trigger.rs` Gate 3) only caps by EUR, and only
//! when `remaining_budget_eur` is tracked. On the local/free path (or when
//! autonomy lifts budget tracking) the council could convene unbounded — a
//! runaway autonomous loop with no ceiling. This module is the missing HARD
//! cap: a count limit over a rolling 24-hour window, enforced at the convene
//! site regardless of the EUR budget.
//!
//! State is a tiny JSON array of unix-second timestamps at
//! `<home>/council_convene_log.json`. Every read prunes entries older than
//! 24h, so the file stays bounded (~`MAX_CONVENES_PER_24H` entries). All I/O
//! is best-effort: a missing/corrupt file reads as "no convenes", a failed
//! save logs at debug and never blocks a turn.

use std::path::{Path, PathBuf};

/// Hard ceiling on council convenes in any rolling 24-hour window. Generous
/// enough that an interactive operator never hits it (that would be a convene
/// every ~3 minutes, non-stop, for a day), but it stops a runaway autonomous
/// loop from fanning out provider calls without bound. A fixed safety
/// backstop, like the WAL/decompression caps — not an operator tunable.
pub const MAX_CONVENES_PER_24H: u32 = 500;

const WINDOW_SECS: i64 = 24 * 60 * 60;

fn log_path(home: &Path) -> PathBuf {
    home.join("council_convene_log.json")
}

/// Load the timestamp log, dropping anything outside the rolling window.
fn load_pruned(home: &Path, now_unix: i64) -> Vec<i64> {
    let cutoff = now_unix - WINDOW_SECS;
    let raw = std::fs::read(log_path(home)).unwrap_or_default();
    let mut tss: Vec<i64> = serde_json::from_slice(&raw).unwrap_or_default();
    tss.retain(|&t| t > cutoff);
    tss
}

/// How many council convenes happened in the last 24h.
pub fn count_last_24h(home: &Path, now_unix: i64) -> u32 {
    load_pruned(home, now_unix).len() as u32
}

/// True when the rolling-24h convene count has reached the hard cap.
pub fn cap_reached(home: &Path, now_unix: i64) -> bool {
    count_last_24h(home, now_unix) >= MAX_CONVENES_PER_24H
}

/// Record one council convene at `now_unix`. Best-effort: prunes the window,
/// appends, and writes back. A write failure is logged at debug and ignored
/// (the cap is a safety backstop, not load-bearing for correctness).
pub fn record_convene(home: &Path, now_unix: i64) {
    let mut tss = load_pruned(home, now_unix);
    tss.push(now_unix);
    match serde_json::to_vec(&tss) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(log_path(home), bytes) {
                tracing::debug!(error = %e, "council convene log write failed (cap is best-effort)");
            }
        }
        Err(e) => tracing::debug!(error = %e, "council convene log serialize failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn empty_log_counts_zero_and_not_capped() {
        let dir = tempdir().unwrap();
        assert_eq!(count_last_24h(dir.path(), 1_000_000), 0);
        assert!(!cap_reached(dir.path(), 1_000_000));
    }

    #[test]
    fn record_increments_within_window() {
        let dir = tempdir().unwrap();
        let now = 1_000_000;
        record_convene(dir.path(), now);
        record_convene(dir.path(), now + 10);
        record_convene(dir.path(), now + 20);
        assert_eq!(count_last_24h(dir.path(), now + 30), 3);
    }

    #[test]
    fn entries_outside_24h_window_are_pruned() {
        let dir = tempdir().unwrap();
        let now = 2_000_000;
        // Two old (just outside the window) + one recent.
        record_convene(dir.path(), now - WINDOW_SECS - 5);
        record_convene(dir.path(), now - WINDOW_SECS - 1);
        record_convene(dir.path(), now - 100);
        // Only the recent one survives the rolling window at `now`.
        assert_eq!(count_last_24h(dir.path(), now), 1);
    }

    #[test]
    fn cap_reached_at_threshold() {
        let dir = tempdir().unwrap();
        let now = 3_000_000;
        // Seed the log file directly with exactly MAX timestamps in-window.
        let tss: Vec<i64> = (0..MAX_CONVENES_PER_24H as i64).map(|i| now - i).collect();
        std::fs::write(log_path(dir.path()), serde_json::to_vec(&tss).unwrap()).unwrap();
        assert!(cap_reached(dir.path(), now));
        assert_eq!(count_last_24h(dir.path(), now), MAX_CONVENES_PER_24H);
    }

    #[test]
    fn corrupt_log_reads_as_empty() {
        let dir = tempdir().unwrap();
        std::fs::write(log_path(dir.path()), b"not json at all").unwrap();
        assert_eq!(count_last_24h(dir.path(), 1), 0);
    }
}
