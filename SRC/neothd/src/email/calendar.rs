//! EM-02 — Google Calendar adapter primitives.
//!
//! Pure-data + serialiser surface for the Google Calendar path.
//! Same pattern as [`super::gmail`]: ships the config primitives,
//! URL builders, event model, ICS exporter, and slot-conflict
//! helper. The actual network fetch + create-event call lands in
//! EM-02b once a Calendar API client is wired (`reqwest` is
//! already a dep so the follow-up is a thin add).
//!
//! ## Scope
//!
//! Two-tier: `CalendarReadonly` for slot-conflict scans + the
//! read-only "what's on my calendar today?" surface; `CalendarEvents`
//! for write paths (auto-create from email content — gated to
//! ReviewQueue + operator approve, per the OB-03 "NEOTH never
//! mutates operator config behind their back" rule).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Google Calendar OAuth scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarScope {
    /// View calendars + events but never modify.
    CalendarReadonly,
    /// Full read + write — required for create-event flows.
    CalendarEvents,
}

impl CalendarScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CalendarReadonly => "https://www.googleapis.com/auth/calendar.readonly",
            Self::CalendarEvents => "https://www.googleapis.com/auth/calendar.events",
        }
    }

    pub fn audit_tag(self) -> &'static str {
        match self {
            Self::CalendarReadonly => "calendar_readonly",
            Self::CalendarEvents => "calendar_events",
        }
    }
}

/// API endpoints — pinned so operator-config drift can't put us
/// on a stale beta URL.
pub const GOOGLE_CALENDAR_API_BASE: &str = "https://www.googleapis.com/calendar/v3";

/// Default `primary` calendar id — Google special-cases this
/// string for the operator's main calendar.
pub const PRIMARY_CALENDAR_ID: &str = "primary";

/// One calendar event. Fields stay close to the Google Calendar v3
/// shape; we deserialize directly from the API response when EM-02b
/// wires the network call. Timestamps are RFC 3339 strings so the
/// adapter doesn't pull in a date-time crate beyond what's already
/// in the workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarEvent {
    /// Calendar id — `"primary"` for the operator's main calendar.
    #[serde(default = "default_primary")]
    pub calendar_id: String,
    /// Event id. Empty for not-yet-created drafts.
    #[serde(default)]
    pub event_id: String,
    pub summary: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub location: String,
    /// RFC 3339 start. Examples: `"2026-05-30T09:00:00+02:00"` or
    /// the all-day form `"2026-05-30"` (date-only — Google flags
    /// these as "all-day").
    pub start_rfc3339: String,
    /// RFC 3339 end. Mirror semantics of `start_rfc3339`.
    pub end_rfc3339: String,
    #[serde(default)]
    pub attendees: Vec<String>,
}

fn default_primary() -> String {
    PRIMARY_CALENDAR_ID.to_string()
}

impl CalendarEvent {
    /// True when the event is marked as all-day (date-only RFC 3339
    /// forms with no time component).
    pub fn is_all_day(&self) -> bool {
        !self.start_rfc3339.contains('T') && !self.end_rfc3339.contains('T')
    }
}

/// Build the URL operators GET to list events between two RFC 3339
/// timestamps. The token query param is omitted — the caller
/// attaches the Bearer in the Authorization header at fetch time.
pub fn list_events_url(
    calendar_id: &str,
    time_min_rfc3339: &str,
    time_max_rfc3339: &str,
    max_results: u16,
) -> String {
    format!(
        "{base}/calendars/{cal}/events?timeMin={min}&timeMax={max}&singleEvents=true\
         &orderBy=startTime&maxResults={n}",
        base = GOOGLE_CALENDAR_API_BASE,
        cal = url_encode(calendar_id),
        min = url_encode(time_min_rfc3339),
        max = url_encode(time_max_rfc3339),
        n = max_results,
    )
}

/// Build the URL operators POST to create an event on a calendar.
pub fn create_event_url(calendar_id: &str) -> String {
    format!(
        "{base}/calendars/{cal}/events",
        base = GOOGLE_CALENDAR_API_BASE,
        cal = url_encode(calendar_id),
    )
}

/// JSON body for the create-event POST. Pure-function — caller
/// handles the HTTP layer.
pub fn create_event_body(event: &CalendarEvent) -> String {
    // Build via serde so escape rules stay correct for free.
    let body = serde_json::json!({
        "summary": event.summary,
        "description": event.description,
        "location": event.location,
        "start": time_block(&event.start_rfc3339),
        "end": time_block(&event.end_rfc3339),
        "attendees": event.attendees.iter().map(|email| {
            serde_json::json!({ "email": email })
        }).collect::<Vec<_>>(),
    });
    serde_json::to_string(&body).expect("json::Value always serialises")
}

fn time_block(rfc3339: &str) -> serde_json::Value {
    if rfc3339.contains('T') {
        serde_json::json!({ "dateTime": rfc3339 })
    } else {
        serde_json::json!({ "date": rfc3339 })
    }
}

/// Render the event as an ICS VEVENT — operators paste this into
/// any RFC 5545 calendar app. Useful for the "save without sending
/// to Google" path operators with privacy concerns might prefer.
pub fn render_ics(event: &CalendarEvent) -> String {
    // Minimal RFC 5545 subset — operators feed this to .ics imports.
    let attendees: String = event
        .attendees
        .iter()
        .map(|a| format!("ATTENDEE;CN={a}:mailto:{a}\n"))
        .collect();
    let stamp = format_compact_basic(&event.start_rfc3339);
    let dtstart = ics_time(&event.start_rfc3339);
    let dtend = ics_time(&event.end_rfc3339);
    let uid = if event.event_id.is_empty() {
        format!(
            "neoth-draft-{}",
            short_hash(&event.summary, &event.start_rfc3339)
        )
    } else {
        event.event_id.clone()
    };
    format!(
        "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//NEOTH//EM-02//EN\n\
         BEGIN:VEVENT\nUID:{uid}\nDTSTAMP:{stamp}\n\
         DTSTART:{dtstart}\nDTEND:{dtend}\n\
         SUMMARY:{summary}\n\
         {desc}{loc}{att}\
         END:VEVENT\nEND:VCALENDAR\n",
        summary = escape_ics(&event.summary),
        desc = if event.description.is_empty() {
            String::new()
        } else {
            format!("DESCRIPTION:{}\n", escape_ics(&event.description))
        },
        loc = if event.location.is_empty() {
            String::new()
        } else {
            format!("LOCATION:{}\n", escape_ics(&event.location))
        },
        att = attendees,
    )
}

/// Convert an RFC 3339 timestamp to the ICS basic-format string —
/// `20260530T090000Z` style. Best-effort: strips `:` and `-` from
/// the date+time portion, drops the `+02:00`-style offset (operators
/// who care about TZ semantics use the `dateTime` Google-API path,
/// not the ICS exporter).
fn ics_time(rfc3339: &str) -> String {
    // Take everything up to a `+` or the literal `Z` and strip
    // separators.
    let cutoff = rfc3339
        .find('+')
        .or_else(|| rfc3339.find('Z'))
        .unwrap_or(rfc3339.len());
    let stem = &rfc3339[..cutoff];
    let stripped: String = stem.chars().filter(|c| *c != ':' && *c != '-').collect();
    if rfc3339.ends_with('Z') {
        format!("{stripped}Z")
    } else {
        stripped
    }
}

fn format_compact_basic(rfc3339: &str) -> String {
    let t = ics_time(rfc3339);
    if t.ends_with('Z') { t } else { format!("{t}Z") }
}

fn short_hash(a: &str, b: &str) -> String {
    let combined = format!("{a}|{b}");
    let h = xxhash_rust::xxh3::xxh3_64(combined.as_bytes());
    format!("{:08x}", h & 0xFFFF_FFFF)
}

fn escape_ics(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(';', "\\;")
        .replace('\n', "\\n")
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── Slot conflict ─────────────────────────────────────────────────

/// Pure helper: does `[candidate_start, candidate_end)` overlap any
/// event in `existing`? Sorts internally so caller can pass events
/// in any order. Times compared as strings via the RFC 3339 lex
/// property (sorted lexicographically == sorted chronologically when
/// all timestamps use the same offset / zulu form).
pub fn has_conflict(
    candidate_start: &str,
    candidate_end: &str,
    existing: &[CalendarEvent],
) -> bool {
    for e in existing {
        let starts_before_we_end = e.start_rfc3339.as_str() < candidate_end;
        let ends_after_we_start = e.end_rfc3339.as_str() > candidate_start;
        if starts_before_we_end && ends_after_we_start {
            return true;
        }
    }
    false
}

/// Operator-facing rendering of a list of events as plain text —
/// the calendar adapter inlines this into a chat reply when the
/// operator asks "what's on my calendar?".
pub fn render_event_list(events: &[CalendarEvent]) -> String {
    if events.is_empty() {
        return "(no events in window)\n".to_string();
    }
    let mut sorted: Vec<&CalendarEvent> = events.iter().collect();
    sorted.sort_by(|a, b| a.start_rfc3339.cmp(&b.start_rfc3339));
    let mut out = String::new();
    for e in sorted {
        out.push_str(&format!(
            "- {} → {}  {}{}\n",
            e.start_rfc3339,
            e.end_rfc3339,
            e.summary,
            if e.location.is_empty() {
                String::new()
            } else {
                format!(" @ {}", e.location)
            },
        ));
    }
    out
}

/// Build the authorize URL for a calendar-only OAuth flow. Reuses
/// the gmail builder shape via direct construction (the gmail
/// module doesn't expose a generic builder so we duplicate the
/// 8-line shell here — small enough that DRY would be more
/// indirection than it saves).
pub fn build_calendar_authorize_url(
    client_id: &str,
    redirect_uri: &str,
    scopes: &[CalendarScope],
    pkce_challenge: &str,
    state: &str,
) -> String {
    let sorted: BTreeSet<CalendarScope> = scopes.iter().copied().collect();
    let scope_str = sorted
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{base}?client_id={cid}&redirect_uri={ru}&response_type=code\
         &scope={scope}&state={state}&code_challenge={chal}&code_challenge_method=S256\
         &access_type=offline&prompt=consent",
        base = super::gmail::GOOGLE_OAUTH_AUTHORIZE_ENDPOINT,
        cid = url_encode(client_id),
        ru = url_encode(redirect_uri),
        scope = url_encode(&scope_str),
        state = url_encode(state),
        chal = url_encode(pkce_challenge),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(summary: &str, start: &str, end: &str) -> CalendarEvent {
        CalendarEvent {
            calendar_id: PRIMARY_CALENDAR_ID.into(),
            event_id: String::new(),
            summary: summary.into(),
            description: String::new(),
            location: String::new(),
            start_rfc3339: start.into(),
            end_rfc3339: end.into(),
            attendees: vec![],
        }
    }

    // ── scope surface ─────────────────────────────────────────────

    #[test]
    fn scope_as_str_carries_google_url() {
        assert_eq!(
            CalendarScope::CalendarReadonly.as_str(),
            "https://www.googleapis.com/auth/calendar.readonly"
        );
        assert_eq!(
            CalendarScope::CalendarEvents.as_str(),
            "https://www.googleapis.com/auth/calendar.events"
        );
    }

    #[test]
    fn scope_audit_tag_snake_case() {
        assert_eq!(
            CalendarScope::CalendarReadonly.audit_tag(),
            "calendar_readonly"
        );
        assert_eq!(CalendarScope::CalendarEvents.audit_tag(), "calendar_events");
    }

    // ── endpoints + constants ─────────────────────────────────────

    #[test]
    fn api_base_pinned() {
        assert_eq!(
            GOOGLE_CALENDAR_API_BASE,
            "https://www.googleapis.com/calendar/v3"
        );
        assert_eq!(PRIMARY_CALENDAR_ID, "primary");
    }

    // ── all-day detection ─────────────────────────────────────────

    #[test]
    fn is_all_day_true_for_date_only() {
        let e = event("All day", "2026-05-30", "2026-05-31");
        assert!(e.is_all_day());
    }

    #[test]
    fn is_all_day_false_for_datetime() {
        let e = event("Meeting", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        assert!(!e.is_all_day());
    }

    // ── URL builders ──────────────────────────────────────────────

    #[test]
    fn list_events_url_has_required_query_params() {
        let url = list_events_url(
            "primary",
            "2026-05-26T00:00:00Z",
            "2026-05-27T00:00:00Z",
            50,
        );
        assert!(url.starts_with(GOOGLE_CALENDAR_API_BASE));
        assert!(url.contains("/calendars/primary/events"));
        assert!(url.contains("timeMin=2026-05-26T00%3A00%3A00Z"));
        assert!(url.contains("timeMax=2026-05-27T00%3A00%3A00Z"));
        assert!(url.contains("singleEvents=true"));
        assert!(url.contains("orderBy=startTime"));
        assert!(url.contains("maxResults=50"));
    }

    #[test]
    fn list_events_url_encodes_calendar_id() {
        let url = list_events_url("op@example.com", "a", "b", 1);
        assert!(url.contains("/calendars/op%40example.com/events"));
    }

    #[test]
    fn create_event_url_points_at_events_collection() {
        let url = create_event_url("primary");
        assert_eq!(
            url,
            "https://www.googleapis.com/calendar/v3/calendars/primary/events"
        );
    }

    // ── create body ───────────────────────────────────────────────

    #[test]
    fn create_event_body_uses_date_time_for_timestamps() {
        let e = event("Meeting", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        let body = create_event_body(&e);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["summary"], "Meeting");
        assert_eq!(v["start"]["dateTime"], "2026-05-30T09:00:00Z");
        assert_eq!(v["end"]["dateTime"], "2026-05-30T10:00:00Z");
    }

    #[test]
    fn create_event_body_uses_date_for_all_day() {
        let e = event("Holiday", "2026-05-30", "2026-05-31");
        let body = create_event_body(&e);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["start"]["date"], "2026-05-30");
        assert_eq!(v["end"]["date"], "2026-05-31");
        assert!(v["start"].get("dateTime").is_none());
    }

    #[test]
    fn create_event_body_lists_attendees_as_email_objects() {
        let mut e = event("Sync", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        e.attendees = vec!["a@x.com".into(), "b@y.com".into()];
        let body = create_event_body(&e);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let att = v["attendees"].as_array().unwrap();
        assert_eq!(att.len(), 2);
        assert_eq!(att[0]["email"], "a@x.com");
        assert_eq!(att[1]["email"], "b@y.com");
    }

    // ── ICS export ────────────────────────────────────────────────

    #[test]
    fn render_ics_includes_vevent_envelope() {
        let e = event("Meeting", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        let ics = render_ics(&e);
        assert!(ics.contains("BEGIN:VCALENDAR"));
        assert!(ics.contains("VERSION:2.0"));
        assert!(ics.contains("BEGIN:VEVENT"));
        assert!(ics.contains("END:VEVENT"));
        assert!(ics.contains("END:VCALENDAR"));
        assert!(ics.contains("SUMMARY:Meeting"));
        assert!(ics.contains("DTSTART:20260530T090000Z"));
        assert!(ics.contains("DTEND:20260530T100000Z"));
    }

    #[test]
    fn render_ics_escapes_commas_semis_newlines_in_text() {
        let mut e = event("a,b;c\nd", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        e.description = "line1\nline2".into();
        let ics = render_ics(&e);
        assert!(ics.contains("SUMMARY:a\\,b\\;c\\nd"));
        assert!(ics.contains("DESCRIPTION:line1\\nline2"));
    }

    #[test]
    fn render_ics_emits_attendees() {
        let mut e = event("Sync", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        e.attendees = vec!["a@x.com".into()];
        let ics = render_ics(&e);
        assert!(ics.contains("ATTENDEE;CN=a@x.com:mailto:a@x.com"));
    }

    #[test]
    fn render_ics_omits_empty_optional_fields() {
        let e = event("Bare", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        let ics = render_ics(&e);
        assert!(!ics.contains("DESCRIPTION:"));
        assert!(!ics.contains("LOCATION:"));
        assert!(!ics.contains("ATTENDEE;"));
    }

    #[test]
    fn render_ics_uid_falls_back_to_hash_when_event_id_empty() {
        let e = event("Bare", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        let ics = render_ics(&e);
        // UID prefix must exist + must be deterministic for same input.
        assert!(ics.contains("UID:neoth-draft-"));
        let ics2 = render_ics(&e);
        assert_eq!(ics, ics2);
    }

    // ── conflict detection ────────────────────────────────────────

    #[test]
    fn has_conflict_true_when_candidate_overlaps_start() {
        let existing = vec![event(
            "Booked",
            "2026-05-30T09:00:00Z",
            "2026-05-30T10:00:00Z",
        )];
        assert!(has_conflict(
            "2026-05-30T08:30:00Z",
            "2026-05-30T09:30:00Z",
            &existing,
        ));
    }

    #[test]
    fn has_conflict_true_when_candidate_overlaps_end() {
        let existing = vec![event(
            "Booked",
            "2026-05-30T09:00:00Z",
            "2026-05-30T10:00:00Z",
        )];
        assert!(has_conflict(
            "2026-05-30T09:30:00Z",
            "2026-05-30T10:30:00Z",
            &existing,
        ));
    }

    #[test]
    fn has_conflict_true_when_candidate_inside_existing() {
        let existing = vec![event(
            "Booked",
            "2026-05-30T09:00:00Z",
            "2026-05-30T10:00:00Z",
        )];
        assert!(has_conflict(
            "2026-05-30T09:15:00Z",
            "2026-05-30T09:45:00Z",
            &existing,
        ));
    }

    #[test]
    fn has_conflict_false_when_back_to_back() {
        // Existing 09:00-10:00; candidate 10:00-11:00 — touching but
        // not overlapping. Treated as free.
        let existing = vec![event(
            "Booked",
            "2026-05-30T09:00:00Z",
            "2026-05-30T10:00:00Z",
        )];
        assert!(!has_conflict(
            "2026-05-30T10:00:00Z",
            "2026-05-30T11:00:00Z",
            &existing,
        ));
    }

    #[test]
    fn has_conflict_false_when_no_existing() {
        assert!(!has_conflict(
            "2026-05-30T09:00:00Z",
            "2026-05-30T10:00:00Z",
            &[],
        ));
    }

    // ── render_event_list ─────────────────────────────────────────

    #[test]
    fn render_event_list_empty_returns_no_events_line() {
        assert!(render_event_list(&[]).contains("no events"));
    }

    #[test]
    fn render_event_list_sorted_by_start_time() {
        let later = event("Later", "2026-05-30T15:00:00Z", "2026-05-30T16:00:00Z");
        let earlier = event("Earlier", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        let s = render_event_list(&[later, earlier]);
        let early_pos = s.find("Earlier").unwrap();
        let late_pos = s.find("Later").unwrap();
        assert!(early_pos < late_pos);
    }

    #[test]
    fn render_event_list_appends_location_when_present() {
        let mut e = event("Sync", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        e.location = "Room A".into();
        let s = render_event_list(&[e]);
        assert!(s.contains("@ Room A"));
    }

    // ── calendar authorize URL ────────────────────────────────────

    #[test]
    fn calendar_authorize_url_carries_required_params() {
        let url = build_calendar_authorize_url(
            "client.apps.googleusercontent.com",
            "http://127.0.0.1:9001/cb",
            &[CalendarScope::CalendarReadonly],
            "chal-xyz",
            "state-1",
        );
        assert!(url.starts_with(super::super::gmail::GOOGLE_OAUTH_AUTHORIZE_ENDPOINT));
        assert!(url.contains("client_id=client.apps.googleusercontent.com"));
        assert!(url.contains("state=state-1"));
        assert!(url.contains("code_challenge=chal-xyz"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("calendar.readonly"));
    }

    #[test]
    fn calendar_authorize_url_dedups_and_sorts_scopes() {
        let url = build_calendar_authorize_url(
            "x",
            "y",
            &[
                CalendarScope::CalendarEvents,
                CalendarScope::CalendarReadonly,
                CalendarScope::CalendarEvents,
            ],
            "c",
            "s",
        );
        // Both scopes appear; readonly comes first (enum order).
        assert!(url.contains("calendar.readonly"));
        assert!(url.contains("calendar.events"));
        let ro_pos = url.find("calendar.readonly").unwrap();
        let ev_pos = url.find("calendar.events").unwrap();
        assert!(ro_pos < ev_pos);
    }

    // ── serde ────────────────────────────────────────────────────

    #[test]
    fn scope_serialises_snake_case() {
        let s = CalendarScope::CalendarEvents;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"calendar_events\"");
    }

    #[test]
    fn calendar_event_serde_roundtrip_keeps_all_fields() {
        let mut e = event("Sync", "2026-05-30T09:00:00Z", "2026-05-30T10:00:00Z");
        e.event_id = "evt-1".into();
        e.description = "desc".into();
        e.location = "Room".into();
        e.attendees = vec!["a@x.com".into()];
        let json = serde_json::to_string(&e).unwrap();
        let back: CalendarEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn calendar_event_default_calendar_id_is_primary() {
        // Missing calendar_id in JSON → fills with "primary".
        let json = r#"{"summary":"x","start_rfc3339":"2026-05-30T09:00:00Z","end_rfc3339":"2026-05-30T10:00:00Z"}"#;
        let e: CalendarEvent = serde_json::from_str(json).unwrap();
        assert_eq!(e.calendar_id, "primary");
    }
}
