//! EM-02b — CalDAV **calendar** transport (VEVENT), the event counterpart to
//! the VTODO task surface in [`super::caldav`].
//!
//! CalDAV (RFC 4791) is plain HTTP with the WebDAV `REPORT` verb over iCalendar
//! bodies. This module reuses the proven primitives from [`super::caldav`] — the
//! multistatus parser ([`super::caldav::parse_multistatus`]), the ICS line
//! unfolder + property splitter, the `resource_url` builder, and `validate_uid`
//! — plus the shared [`crate::email::calendar::CalendarEvent`] model +
//! [`crate::email::calendar::render_ics`] VEVENT renderer. Nothing here is a
//! second copy of logic that already exists.
//!
//! Split, mirroring `caldav.rs`: the VEVENT parser ([`parse_vevent`]) +
//! multistatus fold ([`parse_events_multistatus`]) are PURE and unit-tested;
//! the network calls ([`list_events_against`] / [`create_event_against`]) are
//! the thin, untested I/O shells (same shape as `caldav::list_tasks`). The
//! `_against` functions take an explicit `base_url` so a local stub can inject
//! a URL.

use anyhow::{Context, Result};

use super::caldav::{parse_multistatus, parse_property, resource_url, unfold_ics, CreateOutcome};
use crate::email::calendar::{render_ics, CalendarEvent};
use crate::providers::http_client;

/// The `REPORT` body: a `calendar-query` filtering for `VEVENT`, asking for the
/// `calendar-data` of each match. Mirrors `caldav::CALENDAR_QUERY_VTODO`.
pub const CALENDAR_QUERY_VEVENT: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <C:calendar-data/>
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT"/>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>"#;

/// Parse the FIRST `VEVENT` component out of an iCalendar `calendar-data` blob
/// into a [`CalendarEvent`]. `None` when there is no VEVENT carrying a SUMMARY
/// (an event with no title is not worth listing — mirrors `parse_vtodo`).
///
/// DTSTART/DTEND/LOCATION/DESCRIPTION are kept VERBATIM (the server may store
/// `20260530T090000Z` basic-UTC, an RFC-3339 form, or a date-only all-day
/// value) — we display what the server has rather than guess a normalization.
pub fn parse_vevent(ics: &str) -> Option<CalendarEvent> {
    let mut in_vevent = false;
    let (mut uid, mut summary, mut start, mut end, mut location, mut description) =
        (None, None, None, None, None, None);

    for line in unfold_ics(ics) {
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("BEGIN:VEVENT") {
            in_vevent = true;
            continue;
        }
        if upper.starts_with("END:VEVENT") {
            break; // first VEVENT only
        }
        if !in_vevent {
            continue;
        }
        let Some((name, value)) = parse_property(&line) else {
            continue;
        };
        match name.as_str() {
            "UID" => uid = Some(value.to_string()),
            "SUMMARY" => summary = Some(unescape_ics_text(value)),
            "DTSTART" => start = Some(value.to_string()),
            "DTEND" => end = Some(value.to_string()),
            "LOCATION" => location = Some(unescape_ics_text(value)),
            "DESCRIPTION" => description = Some(unescape_ics_text(value)),
            _ => {}
        }
    }

    let summary = summary?;
    if summary.is_empty() {
        return None;
    }
    Some(CalendarEvent {
        calendar_id: crate::email::calendar::PRIMARY_CALENDAR_ID.to_string(),
        event_id: uid.unwrap_or_default(),
        summary,
        description: description.unwrap_or_default(),
        location: location.unwrap_or_default(),
        // An event with no DTEND is valid (DTEND defaults to DTSTART); mirror
        // the start so the model's non-optional fields stay populated.
        start_rfc3339: start.clone().unwrap_or_default(),
        end_rfc3339: end.or(start).unwrap_or_default(),
        attendees: Vec::new(),
    })
}

/// Reverse of the RFC 5545 §3.3.11 text escape applied by `render_ics` /
/// `escape_ics_text`: `\\` → `\`, `\;` → `;`, `\,` → `,`, `\n`/`\N` → newline.
fn unescape_ics_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') | Some('N') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some(';') => out.push(';'),
                Some(',') => out.push(','),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Fold a WebDAV multistatus body into the VEVENTs it carries. PURE — the
/// caller does the network `REPORT`.
pub fn parse_events_multistatus(multistatus_xml: &str) -> Vec<CalendarEvent> {
    parse_multistatus(multistatus_xml)
        .into_iter()
        .filter_map(|entry| parse_vevent(&entry.calendar_data))
        .collect()
}

/// List VEVENTs from a CalDAV calendar collection. Issues the `REPORT`
/// calendar-query (HTTP Basic auth, `Depth: 1`) + parses the response. The
/// network shell; the parsing is in the pure fns above.
pub async fn list_events_against(
    calendar_url: &str,
    username: &str,
    password: &str,
) -> Result<Vec<CalendarEvent>> {
    let method = reqwest::Method::from_bytes(b"REPORT").expect("REPORT is a valid method token");
    let resp = http_client::build_client()?
        .request(method, calendar_url)
        .basic_auth(username, Some(password))
        .header("Depth", "1")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/xml; charset=utf-8",
        )
        .body(CALENDAR_QUERY_VEVENT)
        .send()
        .await
        .with_context(|| format!("CalDAV REPORT request to {calendar_url}"))?;
    let status = resp.status();
    let text = resp.text().await.context("read CalDAV response body")?;
    if !status.is_success() {
        let snippet: String = text.chars().take(200).collect();
        anyhow::bail!("CalDAV REPORT failed: HTTP {status} — {snippet}");
    }
    Ok(parse_events_multistatus(&text))
}

/// Deterministic resource UID for an event. Same `(summary, start)` → same UID,
/// so `create_event_against` is idempotent (a re-run hits the existing
/// resource via `If-None-Match: *` → 412, never duplicates). Path-safe hex.
pub fn event_uid(event: &CalendarEvent) -> String {
    if !event.event_id.is_empty() {
        return event.event_id.clone();
    }
    let key = format!("{}\u{1f}{}", event.summary, event.start_rfc3339);
    format!("neoth-evt-{:016x}", xxhash_rust::xxh3::xxh3_64(key.as_bytes()))
}

/// PUT a VEVENT to `<calendar_url>/<uid>.ics`. UID-keyed + `If-None-Match: *`
/// for idempotency: a duplicate `(summary, start)` returns
/// [`CreateOutcome::AlreadyExists`] (the server 412s) instead of writing twice.
/// The ICS body comes from the shared `render_ics`, CRLF-normalized per
/// RFC 5545. Reuses `validate_uid` so an operator-supplied event id can't
/// escape the collection path.
pub async fn create_event_against(
    calendar_url: &str,
    username: &str,
    password: &str,
    event: &CalendarEvent,
) -> Result<CreateOutcome> {
    let uid = event_uid(event);
    super::caldav::validate_uid(&uid)?;

    // Ensure the ICS UID matches the resource name (render_ics uses event_id
    // when set) so the server-side component + the href agree.
    let mut event = event.clone();
    event.event_id = uid.clone();
    let body = render_ics(&event).replace('\n', "\r\n");

    let url = resource_url(calendar_url, &uid);
    let resp = http_client::build_client()?
        .put(&url)
        .basic_auth(username, Some(password))
        .header(reqwest::header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        // Idempotency: only create if it does not already exist.
        .header(reqwest::header::IF_NONE_MATCH, "*")
        .body(body)
        .send()
        .await
        .with_context(|| format!("CalDAV PUT request to {url}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::PRECONDITION_FAILED {
        return Ok(CreateOutcome::AlreadyExists);
    }
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let snippet: String = text.chars().take(200).collect();
        anyhow::bail!("CalDAV PUT failed: HTTP {status} — {snippet}");
    }
    Ok(CreateOutcome::Created)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_VEVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n\
        UID:abc-123\r\nSUMMARY:Team sync\r\nDTSTART:20260530T090000Z\r\n\
        DTEND:20260530T100000Z\r\nLOCATION:Room 4\r\n\
        DESCRIPTION:Weekly\\, all hands\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn parse_vevent_extracts_all_fields() {
        let e = parse_vevent(SAMPLE_VEVENT).expect("parses");
        assert_eq!(e.event_id, "abc-123");
        assert_eq!(e.summary, "Team sync");
        assert_eq!(e.start_rfc3339, "20260530T090000Z");
        assert_eq!(e.end_rfc3339, "20260530T100000Z");
        assert_eq!(e.location, "Room 4");
        assert_eq!(e.description, "Weekly, all hands", "comma unescaped");
    }

    #[test]
    fn parse_vevent_none_without_summary() {
        let ics = "BEGIN:VEVENT\r\nUID:x\r\nDTSTART:20260101\r\nEND:VEVENT\r\n";
        assert!(parse_vevent(ics).is_none());
    }

    #[test]
    fn parse_vevent_none_when_not_an_event() {
        let ics = "BEGIN:VTODO\r\nUID:x\r\nSUMMARY:a task\r\nEND:VTODO\r\n";
        assert!(parse_vevent(ics).is_none(), "a VTODO is not a VEVENT");
    }

    #[test]
    fn parse_vevent_dtend_defaults_to_dtstart() {
        let ics =
            "BEGIN:VEVENT\r\nUID:x\r\nSUMMARY:Quick\r\nDTSTART:20260530T090000Z\r\nEND:VEVENT\r\n";
        let e = parse_vevent(ics).expect("parses");
        assert_eq!(e.start_rfc3339, "20260530T090000Z");
        assert_eq!(e.end_rfc3339, "20260530T090000Z", "missing DTEND mirrors DTSTART");
    }

    #[test]
    fn parse_events_multistatus_collects_each_vevent() {
        let xml = format!(
            r#"<?xml version="1.0"?><multistatus xmlns="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
                <response><href>/c/1.ics</href><propstat><prop>
                  <cal:calendar-data><![CDATA[{a}]]></cal:calendar-data>
                </prop></propstat></response>
                <response><href>/c/2.ics</href><propstat><prop>
                  <cal:calendar-data><![CDATA[{b}]]></cal:calendar-data>
                </prop></propstat></response>
            </multistatus>"#,
            a = SAMPLE_VEVENT,
            b = "BEGIN:VEVENT\r\nUID:y\r\nSUMMARY:Lunch\r\nDTSTART:20260530T120000Z\r\nEND:VEVENT\r\n",
        );
        let events = parse_events_multistatus(&xml);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "Team sync");
        assert_eq!(events[1].summary, "Lunch");
    }

    #[test]
    fn event_uid_is_deterministic_and_honours_explicit_id() {
        let mut e = CalendarEvent {
            calendar_id: "primary".into(),
            event_id: String::new(),
            summary: "Standup".into(),
            description: String::new(),
            location: String::new(),
            start_rfc3339: "2026-05-30T09:00:00Z".into(),
            end_rfc3339: "2026-05-30T09:15:00Z".into(),
            attendees: vec![],
        };
        let u1 = event_uid(&e);
        let u2 = event_uid(&e);
        assert_eq!(u1, u2, "same (summary,start) → same uid");
        assert!(u1.starts_with("neoth-evt-"));
        // An explicit event_id wins verbatim.
        e.event_id = "my-id".into();
        assert_eq!(event_uid(&e), "my-id");
    }

    #[test]
    fn render_then_parse_round_trips_summary() {
        // render_ics (shared) → CRLF body → parse_vevent recovers the summary.
        let e = CalendarEvent {
            calendar_id: "primary".into(),
            event_id: "rt-1".into(),
            summary: "Design review".into(),
            description: String::new(),
            location: "HQ".into(),
            start_rfc3339: "2026-05-30T09:00:00Z".into(),
            end_rfc3339: "2026-05-30T10:00:00Z".into(),
            attendees: vec![],
        };
        let ics = render_ics(&e).replace('\n', "\r\n");
        let back = parse_vevent(&ics).expect("round-trips");
        assert_eq!(back.summary, "Design review");
        assert_eq!(back.event_id, "rt-1");
        assert_eq!(back.location, "HQ");
    }

    #[test]
    fn unescape_handles_all_escapes() {
        assert_eq!(unescape_ics_text(r"a\,b\;c\\d\ne"), "a,b;c\\d\ne");
        assert_eq!(unescape_ics_text("plain"), "plain");
    }
}
