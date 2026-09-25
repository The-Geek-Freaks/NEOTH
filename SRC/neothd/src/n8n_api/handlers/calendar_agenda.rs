//! Pure, redacted local-day projection for the future calendar agenda route.
//!
//! This module intentionally has no HTTP, credential, consent, or CalDAV I/O.
//! Callers must supply already-supported events plus an explicit IANA timezone.
//! DST boundaries are resolved from the timezone database; a local midnight
//! that is nonexistent or ambiguous is rejected instead of guessed.

use anyhow::{Context, Result};
use chrono::{DateTime, LocalResult, NaiveDate, TimeZone, Utc};
use chrono_tz::Tz;
use serde::Serialize;

use crate::email::calendar::CalendarEvent;

/// The pure projection refuses oversized caller input as well as output caps.
pub const AGENDA_INPUT_EVENT_LIMIT: usize = 200;
pub const AGENDA_OUTPUT_LIMIT_MAX: usize = 100;

/// A deliberately redacted agenda item. IDs, attendees, descriptions and
/// provider metadata never enter the n8n-facing agenda response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgendaItem {
    pub start: String,
    pub end: String,
    pub summary: String,
    pub location: String,
    pub conflict: bool,
}

/// Projection result for exactly one local calendar day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgendaProjection {
    pub day: String,
    pub timezone: String,
    pub events: Vec<AgendaItem>,
    /// True means qualifying events were omitted solely because `limit` capped
    /// output; it is distinct from a genuinely empty day.
    pub truncated: bool,
}

#[derive(Clone)]
struct Candidate {
    item: AgendaItem,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

/// Project events overlapping `YYYY-MM-DD` in `timezone_name`.
///
/// Timed intervals use half-open instant overlap against local-day boundaries.
/// All-day events use half-open date intervals `[DTSTART, DTEND)`. Input dates,
/// timezone names, mixed all-day/timed values, and unsupported floating values
/// are rejected so a caller cannot manufacture incomplete availability.
pub fn project_local_day_agenda(
    events: &[CalendarEvent], timezone_name: &str, day: &str, limit: usize,
) -> Result<AgendaProjection> {
    if events.len() > AGENDA_INPUT_EVENT_LIMIT {
        anyhow::bail!("agenda input exceeds {AGENDA_INPUT_EVENT_LIMIT} event limit");
    }
    if !(1..=AGENDA_OUTPUT_LIMIT_MAX).contains(&limit) {
        anyhow::bail!("agenda limit must be within 1..={AGENDA_OUTPUT_LIMIT_MAX}");
    }
    let timezone: Tz = timezone_name.parse()
        .with_context(|| format!("invalid IANA timezone `{timezone_name}`"))?;
    let date = NaiveDate::parse_from_str(day, "%Y-%m-%d")
        .with_context(|| format!("invalid local day `{day}`; expected YYYY-MM-DD"))?;
    if date.format("%Y-%m-%d").to_string() != day {
        anyhow::bail!("invalid local day `{day}`; expected canonical YYYY-MM-DD");
    }
    let next_date = date.succ_opt().context("local day overflows supported date range")?;
    let day_start = local_midnight(timezone, date)?;
    let day_end = local_midnight(timezone, next_date)?;
    let mut candidates = Vec::new();
    for event in events {
        if let Some(candidate) = candidate_for_day(event, timezone, date, day_start, day_end)? {
            candidates.push(candidate);
        }
    }
    candidates.sort_by(|left, right| left.start.cmp(&right.start).then_with(|| left.end.cmp(&right.end)));
    for index in 0..candidates.len() {
        let conflict = candidates.iter().enumerate().any(|(other_index, other)| {
            index != other_index && candidates[index].start < other.end && other.start < candidates[index].end
        });
        candidates[index].item.conflict = conflict;
    }
    let truncated = candidates.len() > limit;
    let events = candidates.into_iter().take(limit).map(|candidate| candidate.item).collect();
    Ok(AgendaProjection { day: day.to_string(), timezone: timezone_name.to_string(), events, truncated })
}

fn local_midnight(timezone: Tz, date: NaiveDate) -> Result<DateTime<Utc>> {
    let local = date.and_hms_opt(0, 0, 0).context("midnight construction failed")?;
    match timezone.from_local_datetime(&local) {
        LocalResult::Single(value) => Ok(value.with_timezone(&Utc)),
        LocalResult::Ambiguous(_, _) => anyhow::bail!("local midnight for {date} in {timezone} is ambiguous (DST fold)"),
        LocalResult::None => anyhow::bail!("local midnight for {date} in {timezone} does not exist (DST gap)"),
    }
}

fn candidate_for_day(
    event: &CalendarEvent, timezone: Tz, day: NaiveDate,
    day_start: DateTime<Utc>, day_end: DateTime<Utc>,
) -> Result<Option<Candidate>> {
    let start_date = parse_date_only(&event.start_rfc3339);
    let end_date = parse_date_only(&event.end_rfc3339);
    match (start_date, end_date) {
        (Some(start), Some(end)) => {
            if end <= start { anyhow::bail!("all-day event `{}` has non-positive [start,end) interval", event.summary); }
            if start <= day && day < end {
                let start_instant = local_midnight(timezone, start)?;
                let end_instant = local_midnight(timezone, end)?;
                return Ok(Some(Candidate { item: AgendaItem {
                    start: event.start_rfc3339.clone(), end: event.end_rfc3339.clone(),
                    summary: event.summary.clone(), location: event.location.clone(), conflict: false,
                }, start: start_instant, end: end_instant }));
            }
            Ok(None)
        }
        (Some(_), None) | (None, Some(_)) => anyhow::bail!("event `{}` mixes all-day and timed values", event.summary),
        (None, None) => {
            let start = parse_supported_instant(&event.start_rfc3339)
                .with_context(|| format!("invalid timed DTSTART for `{}`", event.summary))?;
            let end = parse_supported_instant(&event.end_rfc3339)
                .with_context(|| format!("invalid timed DTEND for `{}`", event.summary))?;
            if end <= start { anyhow::bail!("timed event `{}` must end after it starts", event.summary); }
            if start < day_end && end > day_start {
                return Ok(Some(Candidate { item: AgendaItem {
                    start: start.with_timezone(&timezone).to_rfc3339(), end: end.with_timezone(&timezone).to_rfc3339(),
                    summary: event.summary.clone(), location: event.location.clone(), conflict: false,
                }, start, end }));
            }
            Ok(None)
        }
    }
}

fn parse_date_only(value: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
        .filter(|date| date.format("%Y-%m-%d").to_string() == value)
        .or_else(|| NaiveDate::parse_from_str(value, "%Y%m%d").ok()
            .filter(|date| date.format("%Y%m%d").to_string() == value))
}

fn parse_supported_instant(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value).map(|value| value.with_timezone(&Utc))
        .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%SZ")
            .map(|value| value.and_utc()))
        .map_err(Into::into)
}

use chrono::NaiveDateTime;

#[cfg(test)]
mod tests {
    use super::*;

    fn event(summary: &str, start: &str, end: &str) -> CalendarEvent {
        CalendarEvent { calendar_id: "primary".into(), event_id: "private-id".into(), summary: summary.into(), description: "private notes".into(), location: "Room 4".into(), start_rfc3339: start.into(), end_rfc3339: end.into(), attendees: vec!["private@example.test".into()] }
    }

    #[test]
    fn projects_offsets_and_detects_conflicts_and_redacts_serialized_output() {
        let events = [
            event("A", "2026-05-30T19:30:00Z", "2026-05-30T20:00:00Z"),
            event("B", "2026-05-30T20:00:00Z", "2026-05-30T21:00:00Z"),
            event("C", "2026-05-30T19:45:00Z", "2026-05-30T20:15:00Z"),
        ];
        let agenda = project_local_day_agenda(&events, "Europe/Berlin", "2026-05-30", 10).unwrap();
        assert_eq!(agenda.events.len(), 3);
        assert!(agenda.events.iter().find(|item| item.summary == "A").unwrap().conflict);
        assert!(agenda.events.iter().find(|item| item.summary == "B").unwrap().conflict);
        assert!(agenda.events[0].start.ends_with("+02:00"));
        let json = serde_json::to_string(&agenda).unwrap();
        assert!(!json.contains("private-id"));
        assert!(!json.contains("private notes"));
        assert!(!json.contains("private@example.test"));
    }

    #[test]
    fn back_to_back_events_do_not_conflict_and_offsets_roll_into_local_day() {
        let back_to_back = [
            event("A", "2026-05-30T19:00:00Z", "2026-05-30T20:00:00Z"),
            event("B", "2026-05-30T20:00:00Z", "2026-05-30T21:00:00Z"),
        ];
        let agenda = project_local_day_agenda(&back_to_back, "Europe/Berlin", "2026-05-30", 10).unwrap();
        assert!(agenda.events.iter().all(|item| !item.conflict));
        let rollover = [event("Midnight", "2026-05-30T22:30:00Z", "2026-05-30T23:00:00Z")];
        let next_day = project_local_day_agenda(&rollover, "Europe/Berlin", "2026-05-31", 10).unwrap();
        assert_eq!(next_day.events[0].start, "2026-05-31T00:30:00+02:00");
    }

    #[test]
    fn projects_all_day_half_open_and_marks_truncation() {
        let events = [event("Two days", "20260530", "20260601"), event("Later", "20260530", "20260531")];
        let agenda = project_local_day_agenda(&events, "Europe/Berlin", "2026-05-31", 1).unwrap();
        assert_eq!(agenda.events.len(), 1);
        assert_eq!(agenda.events[0].summary, "Two days");
        assert!(!agenda.truncated);
        let capped = project_local_day_agenda(&events, "Europe/Berlin", "2026-05-30", 1).unwrap();
        assert!(capped.truncated);
    }

    #[test]
    fn rejects_bad_days_ranges_mixed_values_and_floating_times() {
        assert!(project_local_day_agenda(&[], "Europe/Berlin", "2026-2-3", 1).is_err());
        assert!(project_local_day_agenda(&[event("bad", "20260530", "20260530")], "Europe/Berlin", "2026-05-30", 1).is_err());
        assert!(project_local_day_agenda(&[event("mixed", "20260530", "2026-05-30T09:00:00Z")], "Europe/Berlin", "2026-05-30", 1).is_err());
        assert!(project_local_day_agenda(&[event("floating", "20260530T090000", "20260530T100000")], "Europe/Berlin", "2026-05-30", 1).is_err());
        assert!(project_local_day_agenda(&[event("zero", "20260530T090000Z", "20260530T090000Z")], "Europe/Berlin", "2026-05-30", 1).is_err());
        assert!(project_local_day_agenda(&[], "Europe/Berlin", "2026-05-30", 0).is_err());
        assert!(project_local_day_agenda(&[], "Europe/Berlin", "2026-05-30", 101).is_err());
        let too_many = vec![event("many", "20260530", "20260531"); AGENDA_INPUT_EVENT_LIMIT + 1];
        assert!(project_local_day_agenda(&too_many, "Europe/Berlin", "2026-05-30", 1).is_err());
    }
}
