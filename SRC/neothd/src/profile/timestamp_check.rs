//! M1 timestamp normalisation — `SPEC_profile_claim_guard.md`.
//!
//! Rule-NLP that catches LLM time hallucinations before they reach the
//! profile state. The extractor sometimes emits a claim like
//! `{"date": "2020-01-15"}` when the conversation window is from
//! 2026-05-15 — that's either a long-ago fact (probably OK to keep) or
//! a hallucination (probably not). The M1 check makes the operator's
//! policy explicit: reject claims whose embedded ISO-8601 dates fall
//! outside `[window_oldest - padding, window_newest + padding]`.
//!
//! v0.1 scope:
//!   - Scan `claim.value_json` for ISO-8601 date strings (yyyy-mm-dd).
//!   - When found, check against the window's anchor `[oldest, newest]`
//!     plus a configurable `padding_days`.
//!   - Relative time phrases ("last Thursday", "in 3 weeks") are left
//!     for a future rule-NLP layer — too lossy to handle conservatively
//!     in pure Rust. The check is opt-in (caller passes `Some(policy)`)
//!     so the spec's strict reading lands when the date-parser layer
//!     matures.

use chrono::{Datelike, NaiveDate};
use serde_json::Value;

use crate::profile::delta::ProfileDelta;
use crate::profile::types::AttributedWindow;

/// Operator-supplied bounds for M1. `padding_days` defaults to 1 per
/// the spec — most legitimate "this happened then" claims fall inside
/// the conversation-window range plus a one-day grace.
#[derive(Clone, Copy, Debug)]
pub struct TimestampPolicy {
    pub window_oldest_unix: i64,
    pub window_newest_unix: i64,
    pub padding_days: i64,
}

impl TimestampPolicy {
    /// Convenience: derive the window-anchor bounds from an
    /// [`AttributedWindow`]. Returns `None` when the window is empty.
    pub fn from_window(window: &AttributedWindow, padding_days: i64) -> Option<Self> {
        if window.segments.is_empty() {
            return None;
        }
        let ts_ns: Vec<i64> = window.segments.iter().map(|s| s.segment.ts_ns).collect();
        let min_ns = ts_ns.iter().min().copied().unwrap_or(0);
        let max_ns = ts_ns.iter().max().copied().unwrap_or(0);
        Some(Self {
            window_oldest_unix: min_ns / 1_000_000_000,
            window_newest_unix: max_ns / 1_000_000_000,
            padding_days,
        })
    }

    /// True iff `ts_unix` falls within `[oldest - padding, newest + padding]`.
    pub fn allows(&self, ts_unix: i64) -> bool {
        let pad_secs = self.padding_days * 86_400;
        ts_unix >= self.window_oldest_unix - pad_secs
            && ts_unix <= self.window_newest_unix + pad_secs
    }
}

/// Scan a delta for out-of-window ISO-8601 dates. Returns `Some(field)`
/// of the first offending claim on failure, `None` when every claim
/// passes (or has no date strings to check).
pub fn first_out_of_window_field<'a>(
    delta: &'a ProfileDelta,
    policy: &TimestampPolicy,
) -> Option<&'a str> {
    for claim in &delta.claims {
        if let Some(date) = first_iso_date_in_value(&claim.value_json) {
            let ts_unix = date.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
            if !policy.allows(ts_unix) {
                return Some(claim.field.as_str());
            }
        }
    }
    None
}

/// Find the first ISO-8601 date (yyyy-mm-dd) anywhere in a JSON value.
/// Recurses into objects + arrays so a date nested under any key turns
/// up. Returns `None` when no parseable date is present — that's the
/// common case for "value is a string but not a date" (location names,
/// language codes, etc.).
pub fn first_iso_date_in_value(value: &Value) -> Option<NaiveDate> {
    match value {
        Value::String(s) => parse_iso_date_anywhere(s),
        Value::Array(arr) => arr.iter().find_map(first_iso_date_in_value),
        Value::Object(map) => map.values().find_map(first_iso_date_in_value),
        _ => None,
    }
}

/// Pull the first yyyy-mm-dd date out of a string. Tolerates surrounding
/// text ("on 2026-05-15 I noticed...") so the LLM's free-form reasoning
/// in claim values doesn't hide a date.
fn parse_iso_date_anywhere(s: &str) -> Option<NaiveDate> {
    // Lightweight scanner: find every 10-char window matching the
    // yyyy-mm-dd shape, parse, return the first hit. Avoids a regex
    // dep at call-time (regex is already in the binary but we keep
    // hot-path checks lean).
    let bytes = s.as_bytes();
    if bytes.len() < 10 {
        return None;
    }
    for start in 0..=(bytes.len() - 10) {
        let window = &bytes[start..start + 10];
        if window[4] != b'-' || window[7] != b'-' {
            continue;
        }
        if !window[0..4].iter().all(|b| b.is_ascii_digit())
            || !window[5..7].iter().all(|b| b.is_ascii_digit())
            || !window[8..10].iter().all(|b| b.is_ascii_digit())
        {
            continue;
        }
        // SAFETY: ASCII digits + dashes — slicing 10 bytes at an
        // ASCII boundary is valid UTF-8.
        let candidate = std::str::from_utf8(window).ok()?;
        if let Ok(date) = NaiveDate::parse_from_str(candidate, "%Y-%m-%d") {
            // Sanity: reject obvious garbage like year 0001.
            if date.year() >= 1900 && date.year() <= 2200 {
                return Some(date);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::delta::RawClaim;
    use crate::profile::types::{
        AttributedSegment, Attribution, ConversationSegment, SegmentOrigin,
    };

    fn seg(ts_ns: i64) -> AttributedSegment {
        AttributedSegment {
            segment: ConversationSegment {
                event_id: 1,
                ts_ns,
                origin: SegmentOrigin::OperatorInbound,
                text: "x".into(),
            },
            attribution: Attribution::UserSpeech,
            confidence: 0.9,
            matched_signals: vec![],
        }
    }

    fn delta_with(value: serde_json::Value) -> ProfileDelta {
        ProfileDelta {
            extraction_id: "ext".into(),
            conversation_hash: "h".into(),
            claims: vec![RawClaim {
                field: "identity.last_visit".into(),
                value_json: value,
                confidence: 0.8,
                reasoning: "".into(),
                evidence_event_ids: vec![],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn policy_from_window_returns_none_on_empty_window() {
        let w = AttributedWindow {
            trigger_event_id: 1,
            segments: vec![],
        };
        assert!(TimestampPolicy::from_window(&w, 1).is_none());
    }

    #[test]
    fn policy_allows_within_window() {
        let p = TimestampPolicy {
            window_oldest_unix: 1000,
            window_newest_unix: 2000,
            padding_days: 0,
        };
        assert!(p.allows(1500));
        assert!(p.allows(1000));
        assert!(p.allows(2000));
        assert!(!p.allows(999));
        assert!(!p.allows(2001));
    }

    #[test]
    fn policy_padding_extends_bounds_symmetrically() {
        let p = TimestampPolicy {
            window_oldest_unix: 1000,
            window_newest_unix: 2000,
            padding_days: 1,
        };
        assert!(p.allows(1000 - 86_400));
        assert!(p.allows(2000 + 86_400));
        assert!(!p.allows(1000 - 86_401));
        assert!(!p.allows(2000 + 86_401));
    }

    #[test]
    fn parse_iso_date_anywhere_finds_embedded_date() {
        let d = parse_iso_date_anywhere("on 2026-05-15 I noticed").unwrap();
        assert_eq!(d, NaiveDate::from_ymd_opt(2026, 5, 15).unwrap());
    }

    #[test]
    fn parse_iso_date_anywhere_returns_first_match() {
        let d = parse_iso_date_anywhere("between 2020-01-01 and 2025-12-31").unwrap();
        assert_eq!(d, NaiveDate::from_ymd_opt(2020, 1, 1).unwrap());
    }

    #[test]
    fn parse_iso_date_anywhere_rejects_invalid_year() {
        assert!(parse_iso_date_anywhere("0001-01-01 is too old").is_none());
        assert!(parse_iso_date_anywhere("9999-01-01 is too far").is_none());
    }

    #[test]
    fn parse_iso_date_anywhere_returns_none_when_no_date() {
        assert!(parse_iso_date_anywhere("just plain text").is_none());
        assert!(parse_iso_date_anywhere("short").is_none());
    }

    #[test]
    fn first_iso_date_recurses_into_nested_object() {
        let v = serde_json::json!({
            "outer": {
                "inner": "the event happened 2026-05-15"
            }
        });
        let d = first_iso_date_in_value(&v).unwrap();
        assert_eq!(d, NaiveDate::from_ymd_opt(2026, 5, 15).unwrap());
    }

    #[test]
    fn first_iso_date_recurses_into_array() {
        let v = serde_json::json!([null, 42, "2026-05-15"]);
        let d = first_iso_date_in_value(&v).unwrap();
        assert_eq!(d, NaiveDate::from_ymd_opt(2026, 5, 15).unwrap());
    }

    #[test]
    fn out_of_window_date_detected() {
        let policy = TimestampPolicy {
            // Anchor 2026-05-15 ± 1d (1_778_803_200 = 2026-05-15 00:00 UTC).
            window_oldest_unix: 1_778_716_800,
            window_newest_unix: 1_778_803_200,
            padding_days: 1,
        };
        let delta = delta_with(serde_json::json!({"date": "2020-01-15"}));
        let bad = first_out_of_window_field(&delta, &policy);
        assert_eq!(bad, Some("identity.last_visit"));
    }

    #[test]
    fn in_window_date_passes() {
        // Derive bounds from chrono to avoid hand-calculated drift.
        let day = NaiveDate::from_ymd_opt(2026, 5, 15).unwrap();
        let ts = day.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        let policy = TimestampPolicy {
            window_oldest_unix: ts - 86400,
            window_newest_unix: ts,
            padding_days: 1,
        };
        let delta = delta_with(serde_json::json!({"date": "2026-05-15"}));
        let bad = first_out_of_window_field(&delta, &policy);
        assert!(bad.is_none(), "expected in-window pass, got {bad:?}");
    }

    #[test]
    fn claim_value_without_date_passes() {
        let policy = TimestampPolicy {
            window_oldest_unix: 0,
            window_newest_unix: 100,
            padding_days: 0,
        };
        let delta = delta_with(serde_json::json!("Berlin"));
        let bad = first_out_of_window_field(&delta, &policy);
        assert!(bad.is_none());
    }
}
