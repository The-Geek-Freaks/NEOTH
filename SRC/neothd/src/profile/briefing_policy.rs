//! P-08 — briefing-emit cron policy (when to fire a proactive
//! briefing, not what content to put in it).
//!
//! NEOTH's cron scheduler can fire a "morning brief" / "weekly stats"
//! / "stand-up summary" workflow at any cadence the operator wants.
//! The DECISION whether to actually emit (vs skip silently because
//! the operator isn't using NEOTH right now) lives here as a pure-fn
//! gate that consults the behavioural-profile estimates.
//!
//! Without this gate every brief fires verbatim at its cron time —
//! including 07:30 mornings when the operator slept in. With it,
//! NEOTH skips silently if (a) the operator hasn't used NEOTH in the
//! recent past + (b) the current hour is OUTSIDE the operator's
//! typical activity window per `TemporalEstimate`.
//!
//! Pure-fn surface; the cron task consumes `should_emit_now` before
//! running its workflow. The estimator + the seconds-since-last-turn
//! input both come from the aggregation cron (P-01) + the WAL
//! read-side respectively.

use super::estimators::TemporalEstimate;

/// One operator-tunable briefing-emit policy. Default values fit
/// most operators; tweak in `freedom.yaml::briefings.<id>` per
/// briefing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BriefingPolicy {
    /// Skip the brief if the operator hasn't engaged NEOTH for
    /// at least this many seconds before brief time. 0 = always
    /// emit regardless of recent activity.
    pub silent_after_inactive_secs: i64,
    /// Skip the brief when the current hour is OUTSIDE the operator's
    /// active hours per their `TemporalEstimate`. An "active hour"
    /// is one with at least `active_threshold` hits in the rolling
    /// 30-day window the estimator was built from. 0 disables the
    /// active-window gate entirely (brief fires every cron tick).
    pub active_threshold: u32,
}

impl Default for BriefingPolicy {
    fn default() -> Self {
        Self {
            silent_after_inactive_secs: 48 * 3600, // 48h
            active_threshold: 2,
        }
    }
}

/// Verdict for one prospective briefing emit. Carries the reason
/// (operator-readable) so `neoth wal show` can surface WHY a
/// briefing fired or skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmitVerdict {
    Emit { reason: &'static str },
    Skip { reason: &'static str },
}

impl EmitVerdict {
    pub fn is_emit(&self) -> bool {
        matches!(self, Self::Emit { .. })
    }
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Emit { reason } | Self::Skip { reason } => reason,
        }
    }
}

/// Decide whether to emit a briefing right now. `current_hour` is
/// the local hour 0..=23 (caller resolves timezone); `temporal` is
/// the operator's per-hour usage distribution from
/// `estimate_temporal`; `seconds_since_last_turn` is the WAL-side
/// "how long since the operator's last RAW_TEXT" reading.
///
/// Order of gates (first Skip wins):
///   1. Force-disabled active-hour gate (`active_threshold == 0`) →
///      skip the active-window check entirely.
///   2. Active-window gate — if `current_hour` has fewer than
///      `active_threshold` hits in the temporal profile, skip.
///   3. Activity-recency gate — if operator inactive longer than
///      `silent_after_inactive_secs`, skip ("you've been away").
///   4. Otherwise emit.
pub fn should_emit_now(
    current_hour: u8,
    seconds_since_last_turn: i64,
    temporal: &TemporalEstimate,
    policy: &BriefingPolicy,
) -> EmitVerdict {
    if (current_hour as usize) >= temporal.hour_buckets.len() {
        return EmitVerdict::Skip {
            reason: "current_hour out of range — caller bug",
        };
    }
    if policy.active_threshold > 0 {
        let hits = temporal.hour_buckets[current_hour as usize];
        if hits < policy.active_threshold {
            return EmitVerdict::Skip {
                reason: "current hour is outside operator's typical activity window",
            };
        }
    }
    if policy.silent_after_inactive_secs > 0
        && seconds_since_last_turn >= policy.silent_after_inactive_secs
    {
        return EmitVerdict::Skip {
            reason: "operator inactive longer than silent_after_inactive_secs",
        };
    }
    EmitVerdict::Emit {
        reason: "active hour + recent operator engagement",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporal_with_hits(hour: u8, hits: u32) -> TemporalEstimate {
        let mut buckets = [0u32; 24];
        buckets[hour as usize] = hits;
        TemporalEstimate {
            hour_buckets: buckets,
            peak_hour: Some(hour),
        }
    }

    #[test]
    fn default_policy_pinned() {
        let p = BriefingPolicy::default();
        assert_eq!(p.silent_after_inactive_secs, 48 * 3600);
        assert_eq!(p.active_threshold, 2);
    }

    #[test]
    fn emit_when_active_hour_and_recent_engagement() {
        let temp = temporal_with_hits(9, 5);
        let v = should_emit_now(9, 60, &temp, &BriefingPolicy::default());
        assert!(v.is_emit());
    }

    #[test]
    fn skip_when_outside_active_window() {
        // Operator never uses NEOTH at 3am. Brief at 3am must skip.
        let temp = temporal_with_hits(9, 5); // active only at 9am
        let v = should_emit_now(3, 60, &temp, &BriefingPolicy::default());
        assert!(!v.is_emit());
        assert!(v.reason().contains("activity window"));
    }

    #[test]
    fn skip_when_operator_inactive_for_long() {
        let temp = temporal_with_hits(9, 5);
        // 72h inactive vs 48h default threshold → skip.
        let v = should_emit_now(9, 72 * 3600, &temp, &BriefingPolicy::default());
        assert!(!v.is_emit());
        assert!(v.reason().contains("inactive"));
    }

    #[test]
    fn active_threshold_zero_disables_window_gate() {
        let temp = temporal_with_hits(9, 0); // operator never used 3am
        let policy = BriefingPolicy {
            silent_after_inactive_secs: 0,
            active_threshold: 0,
        };
        // With both gates disabled, brief always emits.
        let v = should_emit_now(3, 999_999, &temp, &policy);
        assert!(v.is_emit());
    }

    #[test]
    fn silent_after_zero_disables_inactivity_gate() {
        let temp = temporal_with_hits(9, 5);
        let policy = BriefingPolicy {
            silent_after_inactive_secs: 0,
            active_threshold: 2,
        };
        // Operator inactive for a year but active-hour gate passes
        // + inactivity gate disabled → emit.
        let v = should_emit_now(9, 365 * 24 * 3600, &temp, &policy);
        assert!(v.is_emit());
    }

    #[test]
    fn out_of_range_hour_returns_skip_with_caller_bug_reason() {
        let temp = temporal_with_hits(0, 5);
        let v = should_emit_now(99, 60, &temp, &BriefingPolicy::default());
        assert!(!v.is_emit());
        assert!(v.reason().contains("caller bug"));
    }

    #[test]
    fn active_window_gate_uses_strict_less_than() {
        // hits == threshold means "active enough" — gate passes.
        let temp = temporal_with_hits(9, 2);
        let policy = BriefingPolicy {
            silent_after_inactive_secs: 0,
            active_threshold: 2,
        };
        let v = should_emit_now(9, 60, &temp, &policy);
        assert!(v.is_emit());
    }

    #[test]
    fn verdict_is_emit_predicate_pinned() {
        let emit = EmitVerdict::Emit { reason: "x" };
        let skip = EmitVerdict::Skip { reason: "y" };
        assert!(emit.is_emit());
        assert!(!skip.is_emit());
        assert_eq!(emit.reason(), "x");
        assert_eq!(skip.reason(), "y");
    }
}
