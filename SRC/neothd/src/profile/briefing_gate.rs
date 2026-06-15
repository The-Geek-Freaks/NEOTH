//! P-08 (Session 22, 2026-05-23) — operator-home briefing gate.
//!
//! Wraps [`super::briefing_policy::should_emit_now`] with the
//! disk-loading concerns that callers (cron runner, channel-side
//! proactive paths) shouldn't have to repeat:
//!   1. Load the most recent [`super::estimators::BehaviouralProfile`]
//!      snapshot from `~/.neoth/profile/behavioural.json` via
//!      [`super::snapshot::load_snapshot`].
//!   2. Read the operator's last-active timestamp from
//!      `~/.neoth/profile/last_active_unix.txt` (one decimal integer,
//!      no newline policing — atomic write via
//!      [`record_last_active`]).
//!   3. Pass both into `should_emit_now` + return the verdict.
//!
//! Missing snapshot / missing last-active file → returns `Skip` with
//! an operator-readable reason. The cron task / proactive path treats
//! Skip as "do nothing this tick" — never emit a brief without
//! evidence the operator is reachable + receptive.
//!
//! ## Why a separate module from `briefing_policy`
//!
//! `briefing_policy` is pure — no I/O, fully unit-testable without
//! tempdirs or fs setup. The disk-loading wrapper here is the
//! integration layer. Tests live alongside both: pure tests in
//! `briefing_policy`, I/O tests here.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::briefing_policy::{BriefingPolicy, EmitVerdict, should_emit_now};
use super::snapshot::load_snapshot;

/// Relative path under operator's NEOTH home where the last-active
/// timestamp is persisted. Single decimal integer (no newline).
pub const LAST_ACTIVE_RELATIVE_PATH: &str = "profile/last_active_unix.txt";

/// Absolute path to the last-active marker for a given home.
pub fn last_active_path(home: &Path) -> PathBuf {
    home.join(LAST_ACTIVE_RELATIVE_PATH)
}

/// Persist the operator's most recent activity timestamp. Called from
/// every RAW_TEXT-emitting code path (chat, channel ingress) so the
/// briefing gate sees current data without scanning the WAL.
///
/// Atomic write via `.txt.tmp` + rename. Mode 0600 on unix.
pub fn record_last_active(home: &Path, unix_ts: i64) -> Result<()> {
    let path = last_active_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "create parent dir for last_active marker: {}",
                parent.display()
            )
        })?;
    }
    let bytes = unix_ts.to_string().into_bytes();
    let tmp = path.with_extension("txt.tmp");
    crate::config::credentials::write_mode_0600(&tmp, &bytes)
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read the operator's last-active timestamp. Returns `None` when:
///   - the file doesn't exist (fresh install, no chat / channel
///     activity yet — gate treats as "operator never engaged")
///   - the file is empty
///   - the contents fail to parse as i64
///
/// The briefing gate treats `None` as "operator inactive forever"
/// which the silent_after_inactive_secs check then turns into Skip.
pub fn load_last_active(home: &Path) -> Option<i64> {
    let path = last_active_path(home);
    let s = std::fs::read_to_string(&path).ok()?;
    s.trim().parse::<i64>().ok()
}

/// Full briefing gate. Loads the snapshot + last-active timestamp,
/// composes them with `should_emit_now`, returns the verdict. Caller
/// (cron runner, channel proactive path) emits or skips based on the
/// outcome.
///
/// `now_unix` is the caller-supplied "now" so tests can pin
/// deterministic verdicts without time mocking. `current_hour` is the
/// local hour the caller resolved from their timezone.
pub fn should_emit_for_briefing(
    home: &Path,
    now_unix: i64,
    current_hour: u8,
    policy: &BriefingPolicy,
) -> EmitVerdict {
    let Some(profile) = load_snapshot(home) else {
        return EmitVerdict::Skip {
            reason: "no behavioural snapshot on disk — run profile aggregation first",
        };
    };
    let last_active = load_last_active(home).unwrap_or(0);
    let seconds_since = now_unix.saturating_sub(last_active);
    should_emit_now(current_hour, seconds_since, &profile.temporal, policy)
}

/// Convenience: use the current system clock for `now_unix`. For
/// production code that wants determinism + replay-ability, the
/// explicit [`should_emit_for_briefing`] version is preferred.
pub fn should_emit_for_briefing_now(
    home: &Path,
    current_hour: u8,
    policy: &BriefingPolicy,
) -> EmitVerdict {
    let now = crate::time::now_unix_i64();
    should_emit_for_briefing(home, now, current_hour, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::estimators::{BehaviouralProfile, ObservedTurn};
    use crate::profile::snapshot::{aggregate_and_persist, persist_snapshot};
    use tempfile::tempdir;

    fn turn(ts: i64, text: &str) -> ObservedTurn {
        ObservedTurn {
            ts_unix: ts,
            text: text.to_string(),
        }
    }

    // ── last_active record / load ─────────────────────────────────────

    #[test]
    fn last_active_relative_path_drift_guard() {
        // Pin: caller code paths assume this exact filename.
        assert_eq!(LAST_ACTIVE_RELATIVE_PATH, "profile/last_active_unix.txt");
    }

    #[test]
    fn load_last_active_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        assert!(load_last_active(dir.path()).is_none());
    }

    #[test]
    fn record_then_load_round_trips_timestamp() {
        let dir = tempdir().unwrap();
        record_last_active(dir.path(), 1_700_000_000).expect("record");
        assert_eq!(load_last_active(dir.path()), Some(1_700_000_000));
    }

    #[test]
    fn record_overwrites_previous_timestamp() {
        let dir = tempdir().unwrap();
        record_last_active(dir.path(), 1_700_000_000).unwrap();
        record_last_active(dir.path(), 1_700_001_234).unwrap();
        assert_eq!(load_last_active(dir.path()), Some(1_700_001_234));
    }

    #[test]
    fn load_last_active_returns_none_for_malformed_content() {
        // Pin: a corrupt marker (e.g. operator hand-edited) degrades
        // to None rather than panicking — briefing gate falls back to
        // Skip ("operator never engaged"), defensive default.
        let dir = tempdir().unwrap();
        let path = last_active_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not-a-number").unwrap();
        assert!(load_last_active(dir.path()).is_none());
    }

    #[test]
    fn record_creates_parent_dir() {
        // Fresh install: ~/.neoth/profile/ doesn't exist yet. Record
        // must create the dir on the fly.
        let dir = tempdir().unwrap();
        let nested = dir.path().join("never-existed");
        record_last_active(&nested, 1234).expect("record on fresh dir");
        assert_eq!(load_last_active(&nested), Some(1234));
    }

    // ── should_emit_for_briefing — full gate behaviour ────────────────

    #[test]
    fn missing_snapshot_returns_skip_with_actionable_reason() {
        // P-08 contract: no snapshot ⇒ Skip with an operator-readable
        // reason that points at the prerequisite (run aggregation
        // first). Cron task wouldn't accidentally emit before the
        // estimator has run at least once.
        let dir = tempdir().unwrap();
        let v = should_emit_for_briefing(dir.path(), 0, 9, &BriefingPolicy::default());
        match v {
            EmitVerdict::Skip { reason } => {
                assert!(
                    reason.contains("no behavioural snapshot"),
                    "reason: {reason}"
                );
                assert!(reason.contains("aggregation"), "reason: {reason}");
            }
            EmitVerdict::Emit { .. } => panic!("must Skip when snapshot missing"),
        }
    }

    #[test]
    fn snapshot_present_but_no_last_active_treats_operator_as_inactive_forever() {
        // P-08 invariant: no last-active marker ⇒ treat as inactive
        // forever ⇒ silent_after_inactive_secs trips ⇒ Skip. Catches
        // a fresh install where snapshot somehow exists but operator
        // has never engaged the daemon (e.g. snapshot copied from
        // backup).
        let dir = tempdir().unwrap();
        // Persist a snapshot with a peak at hour 9 (so the
        // active-hour gate would pass at hour 9).
        // 10 turns all at the same hour-of-day (separated by 1 day
        // each) so the temporal estimator sees a single peak hour.
        // hour_index_for(ts) follows the rem_euclid(86400)/3600 math
        // the estimator uses; we pre-compute the expected hour from
        // the seed timestamp and align the test to it.
        let seed_ts = 1_700_000_000_i64;
        let _hour_target = ((seed_ts.rem_euclid(86_400)) / 3600) as u8;
        let samples = (0..10)
            .map(|i| turn(seed_ts + i * 86_400, "msg"))
            .collect::<Vec<_>>();
        aggregate_and_persist(dir.path(), &samples).unwrap();
        // No record_last_active — load_last_active returns None →
        // unwrap_or(0) → seconds_since = now - 0 = now (very large).
        // The test asserts Skip regardless of `current_hour` — pass
        // 9 as an arbitrary value; the inactivity gate trips first.
        let now = 1_700_000_000;
        let v = should_emit_for_briefing(dir.path(), now, 9, &BriefingPolicy::default());
        assert!(
            matches!(v, EmitVerdict::Skip { .. }),
            "missing last_active must trigger Skip via inactivity gate, got {v:?}"
        );
    }

    #[test]
    fn snapshot_plus_recent_activity_in_active_hour_returns_emit() {
        // P-08 happy path: snapshot says operator is active at hour 9,
        // operator engaged 60s ago. Brief should fire.
        let dir = tempdir().unwrap();
        // 10 turns all at the same hour-of-day (separated by 1 day
        // each) so the temporal estimator sees a single peak hour.
        // hour_index_for(ts) follows the rem_euclid(86400)/3600 math
        // the estimator uses; we pre-compute the expected hour from
        // the seed timestamp and align the test to it.
        let seed_ts = 1_700_000_000_i64;
        let hour_target = ((seed_ts.rem_euclid(86_400)) / 3600) as u8;
        let samples = (0..10)
            .map(|i| turn(seed_ts + i * 86_400, "msg"))
            .collect::<Vec<_>>();
        aggregate_and_persist(dir.path(), &samples).unwrap();
        record_last_active(dir.path(), 1_700_000_940).unwrap(); // 60s before now
        let now = 1_700_001_000;
        let v = should_emit_for_briefing(dir.path(), now, hour_target, &BriefingPolicy::default());
        assert!(
            matches!(v, EmitVerdict::Emit { .. }),
            "active hour + recent activity must Emit, got {v:?}"
        );
    }

    #[test]
    fn snapshot_plus_stale_activity_returns_skip() {
        // Operator is active at hour 9 typically, but hasn't engaged
        // in 3 days → Skip (default silent_after_inactive_secs=48h).
        let dir = tempdir().unwrap();
        // 10 turns all at the same hour-of-day (separated by 1 day
        // each) so the temporal estimator sees a single peak hour.
        // hour_index_for(ts) follows the rem_euclid(86400)/3600 math
        // the estimator uses; we pre-compute the expected hour from
        // the seed timestamp and align the test to it.
        let seed_ts = 1_700_000_000_i64;
        let hour_target = ((seed_ts.rem_euclid(86_400)) / 3600) as u8;
        let samples = (0..10)
            .map(|i| turn(seed_ts + i * 86_400, "msg"))
            .collect::<Vec<_>>();
        aggregate_and_persist(dir.path(), &samples).unwrap();
        let now = 1_700_000_000_i64 + 3 * 24 * 3600; // 3 days later
        record_last_active(dir.path(), 1_700_000_000).unwrap();
        // Use hour_target so the active-hour gate passes, leaving the
        // inactivity gate as the sole Skip trigger.
        let v = should_emit_for_briefing(dir.path(), now, hour_target, &BriefingPolicy::default());
        assert!(
            matches!(v, EmitVerdict::Skip { .. }),
            "3-day inactivity must Skip, got {v:?}"
        );
    }

    #[test]
    fn inactive_hour_returns_skip_even_with_recent_activity() {
        // Operator typically active at hour 9 (only), brief fires at
        // hour 3 (3 AM, dead hour). Skip.
        let dir = tempdir().unwrap();
        // 10 turns all at the same hour-of-day (separated by 1 day
        // each) so the temporal estimator sees a single peak hour.
        // hour_index_for(ts) follows the rem_euclid(86400)/3600 math
        // the estimator uses; we pre-compute the expected hour from
        // the seed timestamp and align the test to it.
        let seed_ts = 1_700_000_000_i64;
        let hour_target = ((seed_ts.rem_euclid(86_400)) / 3600) as u8;
        let samples = (0..10)
            .map(|i| turn(seed_ts + i * 86_400, "msg"))
            .collect::<Vec<_>>();
        aggregate_and_persist(dir.path(), &samples).unwrap();
        record_last_active(dir.path(), 1_700_000_940).unwrap();
        let now = 1_700_001_000;
        // Query an hour that's NOT hour_target so the active-hour
        // gate trips. `(hour_target + 12) % 24` reliably picks the
        // opposite-side-of-day hour, guaranteed to have 0 hits.
        let inactive_hour = (hour_target + 12) % 24;
        let v =
            should_emit_for_briefing(dir.path(), now, inactive_hour, &BriefingPolicy::default());
        match v {
            EmitVerdict::Skip { reason } => {
                assert!(reason.contains("activity window"), "reason: {reason}");
            }
            EmitVerdict::Emit { .. } => panic!(
                "hour {inactive_hour} is outside active window (peak={hour_target}) — must Skip"
            ),
        }
    }

    #[test]
    fn empty_snapshot_with_active_threshold_zero_emits() {
        // Operator override: active_threshold=0 disables the active-
        // window gate so every cron tick (with recent activity) emits.
        // Useful for operator who explicitly wants reminders even at
        // unusual hours.
        let dir = tempdir().unwrap();
        // Empty profile — every hour bucket has 0 hits.
        persist_snapshot(dir.path(), &BehaviouralProfile::default()).unwrap();
        record_last_active(dir.path(), 1_700_000_940).unwrap();
        let policy = BriefingPolicy {
            silent_after_inactive_secs: 86_400,
            active_threshold: 0,
        };
        let now = 1_700_001_000;
        let v = should_emit_for_briefing(dir.path(), now, 3, &policy);
        assert!(matches!(v, EmitVerdict::Emit { .. }), "got {v:?}");
    }

    #[test]
    fn should_emit_for_briefing_now_uses_system_clock() {
        // Smoke test the system-clock variant — primarily that it
        // doesn't panic against a missing snapshot. The actual
        // verdict depends on when the test runs; we only care that
        // the call surface is live.
        let dir = tempdir().unwrap();
        let v = should_emit_for_briefing_now(dir.path(), 12, &BriefingPolicy::default());
        // Missing snapshot ⇒ Skip regardless of time.
        assert!(matches!(v, EmitVerdict::Skip { .. }));
    }
}
