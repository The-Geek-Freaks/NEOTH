//! ADV-13 — deterministic relative-time normalisation (the rule-NLP
//! layer [`crate::profile::timestamp_check`] explicitly defers to).
//!
//! The profile extractor LLM sees a conversation window and emits dated
//! claims. When the operator writes a RELATIVE time ("I moved here 3
//! years ago", "vor 2 Wochen umgezogen") the LLM has to resolve it
//! against *some* reference — and left to itself it anchors on its own
//! training-cutoff "now", not the conversation's actual time. That
//! silently produces wrong absolute dates in `idx_profile`.
//!
//! This stage rewrites the common relative expressions to absolute
//! `yyyy-mm-dd` BEFORE the LLM call, anchored on the segment's real
//! `ts_ns`. Two properties matter:
//!
//!   - **Deterministic**: pure rule rewrite against a fixed reference
//!     date — no wall-clock `now()`, no LLM. The same window always
//!     produces the same prompt, preserving the extractor's G.1
//!     determinism contract.
//!   - **Conservative**: only unambiguous expressions are rewritten.
//!     Bare German "morgen" is deliberately NOT matched (it collides
//!     with "morning" / "guten Morgen"); anything we don't recognise is
//!     left verbatim for the LLM, which is the safe failure mode.
//!
//! Bilingual EN + DE, matching the rest of NEOTH's operator surface.

use std::borrow::Cow;

use chrono::{DateTime, Datelike, Days, Months, NaiveDate};
use regex::{Captures, Regex};
use std::sync::LazyLock;

/// Calendar unit a relative expression shifts by. Week is a 7-day
/// multiple of Day; Month/Year use calendar arithmetic (variable month
/// length) via chrono so "1 month ago" from the 31st lands correctly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unit {
    Day,
    Week,
    Month,
    Year,
}

/// Map an EN or DE unit word (any inflection in the regexes below) to a
/// [`Unit`]. Lowercased + prefix-matched so `tag`/`tage`/`tagen` all
/// resolve to `Day` without enumerating every form twice.
fn classify_unit(word: &str) -> Option<Unit> {
    let w = word.to_ascii_lowercase();
    if w.starts_with("day") || w.starts_with("tag") {
        Some(Unit::Day)
    } else if w.starts_with("week") || w.starts_with("woche") || w.starts_with("wochen") {
        Some(Unit::Week)
    } else if w.starts_with("month") || w.starts_with("monat") {
        Some(Unit::Month)
    } else if w.starts_with("year") || w.starts_with("jahr") {
        Some(Unit::Year)
    } else {
        None
    }
}

/// Sanity bounds — a normalised date outside `[1900, 2200]` is almost
/// certainly an absurd input ("9999 years ago") rather than a real
/// operator fact. Matches [`crate::profile::timestamp_check`]'s own
/// year guard so the two stages agree on what counts as a plausible
/// date.
const SANE_MIN_YEAR: i32 = 1900;
const SANE_MAX_YEAR: i32 = 2200;

/// Reject a computed date whose year is implausible so the caller leaves
/// the original phrase verbatim instead of emitting e.g. `-7973-05-28`.
fn sane_year(date: NaiveDate) -> Option<NaiveDate> {
    (SANE_MIN_YEAR..=SANE_MAX_YEAR)
        .contains(&date.year())
        .then_some(date)
}

/// Shift `reference` by `n` units in the given direction. Returns `None`
/// on calendar overflow OR an implausible result year (absurd `n` like
/// "9999 years ago") so the caller leaves the original text untouched
/// rather than panic or emit garbage.
fn shift(reference: NaiveDate, n: u32, unit: Unit, past: bool) -> Option<NaiveDate> {
    let shifted = match unit {
        Unit::Day => {
            let days = Days::new(n as u64);
            if past {
                reference.checked_sub_days(days)
            } else {
                reference.checked_add_days(days)
            }
        }
        Unit::Week => {
            let days = Days::new(n as u64 * 7);
            if past {
                reference.checked_sub_days(days)
            } else {
                reference.checked_add_days(days)
            }
        }
        Unit::Month => {
            let months = Months::new(n);
            if past {
                reference.checked_sub_months(months)
            } else {
                reference.checked_add_months(months)
            }
        }
        Unit::Year => {
            let months = Months::new(n.checked_mul(12)?);
            if past {
                reference.checked_sub_months(months)
            } else {
                reference.checked_add_months(months)
            }
        }
    }?;
    sane_year(shifted)
}

/// `yyyy-mm-dd` — the same shape [`crate::profile::timestamp_check`]
/// parses back out, so a normalised claim round-trips through the M1
/// window check.
fn fmt(date: NaiveDate) -> String {
    date.format("%Y-%m-%d").to_string()
}

// EN "<n> <unit> ago"  (e.g. "3 years ago")
static EN_PAST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(\d{1,4})\s+(days?|weeks?|months?|years?)\s+ago\b").unwrap()
});

// DE "vor <n> <unit>"  (e.g. "vor 2 Wochen")
static DE_PAST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bvor\s+(\d{1,4})\s+(tagen?|wochen?|monaten?|jahren?)\b").unwrap()
});

// EN + DE "in <n> <unit>"  (e.g. "in 3 days" / "in 3 Tagen")
static FUTURE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\bin\s+(\d{1,4})\s+(days?|weeks?|months?|years?|tagen?|wochen?|monaten?|jahren?)\b",
    )
    .unwrap()
});

// EN "last|next <unit>"  (single-unit; week/month/year only)
static EN_LASTNEXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(last|next)\s+(week|month|year)\b").unwrap());

// DE "letzte[n]|nächste[n] <unit>"
static DE_LASTNEXT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(letzte[rnsm]?|n(?:ä|ae)chste[rnsm]?)\s+(woche|monat|jahr)\b").unwrap()
});

// Single-token relative days (unambiguous EN + DE only).
static SINGLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(today|yesterday|tomorrow|heute|gestern|vorgestern)\b").unwrap()
});

/// Cheap pre-check: skip all regex work (and borrow the input) unless a
/// trigger root is present. Keeps the hot path allocation-free for the
/// overwhelming majority of segments that carry no relative expression.
fn needs_normalization(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const ROOTS: &[&str] = &[
        "ago",
        "vor ",
        "in ",
        "last ",
        "next ",
        "letzte",
        "nächste",
        "naechste",
        "today",
        "yesterday",
        "tomorrow",
        "heute",
        "gestern",
        "vorgestern",
    ];
    ROOTS.iter().any(|r| lower.contains(r))
}

/// Rewrite the deterministic relative-time expressions in `text` to
/// absolute `yyyy-mm-dd`, anchored on `reference`. Pure function; borrows
/// when nothing is rewritten. Unrecognised or overflowing expressions
/// are left verbatim.
pub fn normalize_relative_dates(text: &str, reference: NaiveDate) -> Cow<'_, str> {
    if !needs_normalization(text) {
        return Cow::Borrowed(text);
    }

    let mut s = EN_PAST_RE
        .replace_all(text, |c: &Captures| {
            numeric_replacement(c, reference, /*past=*/ true)
        })
        .into_owned();
    s = DE_PAST_RE
        .replace_all(&s, |c: &Captures| {
            numeric_replacement(c, reference, /*past=*/ true)
        })
        .into_owned();
    s = FUTURE_RE
        .replace_all(&s, |c: &Captures| {
            numeric_replacement(c, reference, /*past=*/ false)
        })
        .into_owned();
    s = EN_LASTNEXT_RE
        .replace_all(&s, |c: &Captures| single_unit_replacement(c, reference))
        .into_owned();
    s = DE_LASTNEXT_RE
        .replace_all(&s, |c: &Captures| single_unit_replacement(c, reference))
        .into_owned();
    s = SINGLE_RE
        .replace_all(&s, |c: &Captures| single_word_replacement(c, reference))
        .into_owned();

    Cow::Owned(s)
}

/// Replace a `<n> <unit>`-shaped match (capture 1 = count, capture 2 =
/// unit word). Leaves the original text on a bad count / unknown unit /
/// calendar overflow.
fn numeric_replacement(caps: &Captures, reference: NaiveDate, past: bool) -> String {
    let whole = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
    let parsed = (|| {
        let n: u32 = caps.get(1)?.as_str().parse().ok()?;
        let unit = classify_unit(caps.get(2)?.as_str())?;
        shift(reference, n, unit, past)
    })();
    match parsed {
        Some(date) => fmt(date),
        None => whole.to_string(),
    }
}

/// Replace a "last/next <unit>" / "letzte/nächste <unit>" match. The
/// determiner (capture 1) decides direction; capture 2 is the unit. `n`
/// is always 1.
fn single_unit_replacement(caps: &Captures, reference: NaiveDate) -> String {
    let whole = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
    let parsed = (|| {
        let determiner = caps.get(1)?.as_str().to_ascii_lowercase();
        let past = determiner.starts_with("last") || determiner.starts_with("letzte");
        let unit = classify_unit(caps.get(2)?.as_str())?;
        shift(reference, 1, unit, past)
    })();
    match parsed {
        Some(date) => fmt(date),
        None => whole.to_string(),
    }
}

/// Replace a single-token relative day (today/yesterday/tomorrow + DE).
fn single_word_replacement(caps: &Captures, reference: NaiveDate) -> String {
    let whole = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
    let word = whole.to_ascii_lowercase();
    let date = match word.as_str() {
        "today" | "heute" => Some(reference),
        "yesterday" | "gestern" => reference.checked_sub_days(Days::new(1)),
        "vorgestern" => reference.checked_sub_days(Days::new(2)),
        "tomorrow" => reference.checked_add_days(Days::new(1)),
        _ => None,
    };
    match date {
        Some(d) => fmt(d),
        None => whole.to_string(),
    }
}

/// Derive the anchor date from a WAL/segment `ts_ns` (nanoseconds since
/// the unix epoch, UTC). Returns `None` for a clock-fault sentinel or an
/// out-of-range timestamp.
pub fn reference_date_from_unix_ns(ts_ns: i64) -> Option<NaiveDate> {
    if ts_ns <= 0 {
        return None;
    }
    let secs = ts_ns / 1_000_000_000;
    let nanos = (ts_ns % 1_000_000_000) as u32;
    DateTime::from_timestamp(secs, nanos).map(|dt| dt.date_naive())
}

/// Convenience for the extraction render path: normalise a segment's
/// text against its own `ts_ns`. When the timestamp is unusable (clock
/// fault, pre-epoch) the text is returned unchanged — better to ship the
/// raw relative phrase than to anchor it on a bogus date.
pub fn normalize_segment(text: &str, ts_ns: i64) -> Cow<'_, str> {
    match reference_date_from_unix_ns(ts_ns) {
        Some(reference) => normalize_relative_dates(text, reference),
        None => Cow::Borrowed(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-05-28 — the session date, used as the reference anchor.
    fn anchor() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 5, 28).unwrap()
    }

    #[test]
    fn en_n_years_ago() {
        let out = normalize_relative_dates("I moved here 3 years ago.", anchor());
        assert_eq!(out, "I moved here 2023-05-28.");
    }

    #[test]
    fn en_n_days_and_weeks_ago() {
        assert_eq!(
            normalize_relative_dates("started 10 days ago", anchor()),
            "started 2026-05-18"
        );
        assert_eq!(
            normalize_relative_dates("met 2 weeks ago", anchor()),
            "met 2026-05-14"
        );
    }

    #[test]
    fn en_months_ago_uses_calendar_arithmetic() {
        // 2 months before 2026-05-28 is 2026-03-28 (not 60 days).
        assert_eq!(
            normalize_relative_dates("left 2 months ago", anchor()),
            "left 2026-03-28"
        );
    }

    #[test]
    fn de_vor_n_einheiten() {
        assert_eq!(
            normalize_relative_dates("vor 2 Wochen umgezogen", anchor()),
            "2026-05-14 umgezogen"
        );
        assert_eq!(
            normalize_relative_dates("das war vor 3 Jahren", anchor()),
            "das war 2023-05-28"
        );
        assert_eq!(
            normalize_relative_dates("vor 5 Tagen angefangen", anchor()),
            "2026-05-23 angefangen"
        );
    }

    #[test]
    fn en_de_in_n_future() {
        assert_eq!(
            normalize_relative_dates("ship in 3 days", anchor()),
            "ship 2026-05-31"
        );
        assert_eq!(
            normalize_relative_dates("fertig in 2 Wochen", anchor()),
            "fertig 2026-06-11"
        );
    }

    #[test]
    fn en_last_next_single_unit() {
        assert_eq!(
            normalize_relative_dates("last week", anchor()),
            "2026-05-21"
        );
        assert_eq!(
            normalize_relative_dates("next month", anchor()),
            "2026-06-28"
        );
        assert_eq!(
            normalize_relative_dates("last year", anchor()),
            "2025-05-28"
        );
    }

    #[test]
    fn de_letzte_naechste_single_unit() {
        assert_eq!(
            normalize_relative_dates("letzte Woche", anchor()),
            "2026-05-21"
        );
        assert_eq!(
            normalize_relative_dates("nächsten Monat", anchor()),
            "2026-06-28"
        );
        assert_eq!(
            normalize_relative_dates("letztes Jahr", anchor()),
            "2025-05-28"
        );
    }

    #[test]
    fn single_token_days_en_de() {
        assert_eq!(normalize_relative_dates("today", anchor()), "2026-05-28");
        assert_eq!(
            normalize_relative_dates("yesterday", anchor()),
            "2026-05-27"
        );
        assert_eq!(normalize_relative_dates("heute", anchor()), "2026-05-28");
        assert_eq!(normalize_relative_dates("gestern", anchor()), "2026-05-27");
        assert_eq!(
            normalize_relative_dates("vorgestern", anchor()),
            "2026-05-26"
        );
        assert_eq!(normalize_relative_dates("tomorrow", anchor()), "2026-05-29");
    }

    #[test]
    fn bare_german_morgen_is_not_rewritten() {
        // "morgen" collides with "morning" / "guten Morgen" — left alone.
        let s = "guten Morgen, bis morgen";
        assert_eq!(normalize_relative_dates(s, anchor()), s);
    }

    #[test]
    fn clean_text_is_borrowed_unchanged() {
        let s = "I live in Berlin and like rust";
        // "in " IS a trigger root, so it pays for the regex pass — but the
        // result must equal the input (no relative expression matched).
        let out = normalize_relative_dates(s, anchor());
        assert_eq!(out, s);
    }

    #[test]
    fn text_without_trigger_roots_borrows() {
        let s = "Berlin, rustacean, opus model";
        match normalize_relative_dates(s, anchor()) {
            Cow::Borrowed(b) => assert_eq!(b, s),
            Cow::Owned(_) => panic!("expected Borrowed for trigger-free text"),
        }
    }

    #[test]
    fn multiple_expressions_in_one_segment() {
        let out = normalize_relative_dates(
            "joined 2 years ago, promoted last month, vacation in 3 weeks",
            anchor(),
        );
        assert_eq!(
            out,
            "joined 2024-05-28, promoted 2026-04-28, vacation 2026-06-18"
        );
    }

    #[test]
    fn absurd_count_is_left_verbatim_not_panicked() {
        // 9999 years before 2026 overflows chrono's year range → leave
        // the phrase untouched rather than crash the extraction render.
        let s = "9999 years ago";
        assert_eq!(normalize_relative_dates(s, anchor()), s);
    }

    #[test]
    fn case_insensitive_matching() {
        assert_eq!(
            normalize_relative_dates("3 YEARS AGO", anchor()),
            "2023-05-28"
        );
        assert_eq!(normalize_relative_dates("Today", anchor()), "2026-05-28");
    }

    #[test]
    fn does_not_match_unrelated_units() {
        // "minutes" is not a calendar unit we normalise.
        let s = "in 3 minutes";
        assert_eq!(normalize_relative_dates(s, anchor()), s);
    }

    #[test]
    fn reference_from_ns_round_trips() {
        // 2026-05-28 00:00:00 UTC in ns.
        let dt = NaiveDate::from_ymd_opt(2026, 5, 28)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc();
        let ns = dt.timestamp_nanos_opt().unwrap();
        assert_eq!(reference_date_from_unix_ns(ns), Some(anchor()));
    }

    #[test]
    fn reference_from_ns_rejects_clock_fault() {
        assert_eq!(reference_date_from_unix_ns(0), None);
        assert_eq!(reference_date_from_unix_ns(-1), None);
    }

    #[test]
    fn normalize_segment_uses_segment_timestamp() {
        // ts_ns for 2026-05-28 → "yesterday" resolves to 2026-05-27.
        let ns = NaiveDate::from_ymd_opt(2026, 5, 28)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_nanos_opt()
            .unwrap();
        assert_eq!(normalize_segment("yesterday", ns), "2026-05-27");
    }

    #[test]
    fn normalize_segment_passes_through_on_bad_timestamp() {
        // Clock-fault ts → text returned unchanged (don't anchor on a
        // bogus date).
        assert_eq!(normalize_segment("3 years ago", 0), "3 years ago");
    }

    #[test]
    fn determinism_same_input_same_output() {
        let a = normalize_relative_dates("vor 2 Wochen", anchor());
        let b = normalize_relative_dates("vor 2 Wochen", anchor());
        assert_eq!(a, b);
    }
}
