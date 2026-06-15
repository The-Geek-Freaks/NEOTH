//! GOLD-ARCH-07 — canonical wall-clock helpers with defined overflow semantics.
//!
//! Roughly seven modules each re-derived "now, since the unix epoch" as
//! `SystemTime::now().duration_since(UNIX_EPOCH).map(...).unwrap_or(0)`, each
//! picking its own behaviour for a clock set BEFORE the epoch (a misconfigured
//! machine). This centralises that decision so it is defined once:
//!
//! - a pre-epoch clock (the `duration_since` error case) saturates to `0`;
//! - the `i64` form additionally saturates a far-future overflow to `i64::MAX`
//!   rather than wrapping negative.
//!
//! The existing per-module `now_unix*` helpers now delegate here, so their call
//! sites are unchanged.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the unix epoch. `0` if the clock is before the epoch.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Nanoseconds since the unix epoch, clamped into a `u64` (it does not overflow
/// until ~year 2554). `0` if the clock is before the epoch.
pub fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Seconds since the unix epoch as a signed `i64` (for SQLite / signed columns).
/// `0` before the epoch; `i64::MAX` past the far-future overflow point rather
/// than wrapping negative.
pub fn now_unix_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Nanoseconds since the unix epoch as a signed `i64` (for SQLite / signed
/// columns that store nanosecond timestamps — e.g. the groundtruth + episode
/// ledgers). `0` before the epoch; `i64::MAX` past the far-future overflow point
/// (~year 2262 for i64-nanos) rather than wrapping negative.
pub fn now_unix_ns_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_are_positive_and_consistent() {
        let s = now_unix_secs();
        let i = now_unix_i64();
        let ns = now_unix_ns();
        // A sane test machine is well past the epoch and before the year-2554
        // u64-nanos overflow, so every form is a real, positive timestamp.
        assert!(s > 1_700_000_000, "seconds look like a real unix time: {s}");
        assert!(i > 1_700_000_000, "i64 seconds match: {i}");
        assert_eq!(i as u64, s, "the i64 + u64 second forms agree");
        // Nanos are seconds * 1e9 within the same call window (allow a 2s skew).
        assert!(ns / 1_000_000_000 >= s - 2 && ns / 1_000_000_000 <= s + 2);
    }

    #[test]
    fn ns_i64_matches_ns_u64_within_skew_and_is_positive() {
        let ns_i = now_unix_ns_i64();
        let ns_u = now_unix_ns();
        // On a sane machine both are the same real nanosecond clock (within a
        // small call-to-call skew) and the i64 form is a real positive value
        // (the i64-nanos overflow is ~year 2262, far past any test machine).
        assert!(ns_i > 1_700_000_000_000_000_000, "i64 nanos look real: {ns_i}");
        let diff = (ns_i as i128 - ns_u as i128).abs();
        assert!(diff < 2_000_000_000, "i64 + u64 nanos agree within 2s: {diff}");
    }

    #[test]
    fn forms_advance_monotonically_across_calls() {
        let a = now_unix_ns();
        let b = now_unix_ns();
        assert!(b >= a, "nanos do not go backwards within a process");
    }
}
