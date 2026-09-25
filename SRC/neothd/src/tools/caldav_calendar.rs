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
use futures_util::StreamExt;

use super::caldav::{CaldavEndpoint, CreateOutcome, parse_multistatus, parse_property, unfold_ics};
use crate::email::calendar::{CalendarEvent, render_ics};

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

/// The agenda reader is deliberately smaller than the generic HTTP timeout:
/// a morning briefing must fail visibly rather than retain a socket forever.
pub const AGENDA_REPORT_TIMEOUT_SECS: u64 = 15;
/// Maximum XML body accepted from one calendar collection REPORT.
pub const AGENDA_REPORT_MAX_BYTES: usize = 1_048_576;
/// Maximum VEVENT rows accepted from one agenda REPORT.
pub const AGENDA_REPORT_MAX_EVENTS: usize = 200;

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

/// Parse a VEVENT only when its temporal semantics can be projected safely.
///
/// `TZID`, floating local timestamps, and recurrence rules require calendar
/// expansion against a timezone database. This bounded reader does not claim
/// free time for values it cannot expand, so it rejects them explicitly.
pub fn parse_supported_vevent(ics: &str) -> Result<Option<CalendarEvent>> {
    let mut components: Vec<String> = Vec::new();
    let mut finished_vevent = 0u8;
    let (mut uid, mut summary, mut start, mut end, mut location) =
        (None, None, None, None, None);
    for line in unfold_ics(ics) {
        let Some((raw_name, value)) = line.split_once(':') else { continue };
        let name = raw_name.split(';').next().unwrap_or_default().trim().to_ascii_uppercase();
        if name == "BEGIN" {
            let component = value.trim().to_ascii_uppercase();
            let allowed = match component.as_str() {
                "VCALENDAR" => components.is_empty(),
                "VEVENT" => components.is_empty()
                    || (components.len() == 1 && components[0] == "VCALENDAR"),
                "VALARM" => matches!(components.last().map(String::as_str), Some("VEVENT")),
                _ => false,
            };
            if !allowed {
                anyhow::bail!("CalDAV calendar-data has unsupported or misplaced BEGIN:{component}");
            }
            if component == "VEVENT" && finished_vevent != 0 {
                anyhow::bail!("CalDAV calendar-data contains multiple VEVENT components");
            }
            components.push(component);
            continue;
        }
        if name == "END" {
            let component = value.trim().to_ascii_uppercase();
            let open = components.pop().context("CalDAV calendar-data has unmatched END component")?;
            if open != component {
                anyhow::bail!("CalDAV calendar-data closes {component} while {open} is open");
            }
            if component == "VEVENT" { finished_vevent += 1; }
            continue;
        }
        let direct_event = matches!(components.as_slice(), [event] if event == "VEVENT")
            || matches!(components.as_slice(), [calendar, event] if calendar == "VCALENDAR" && event == "VEVENT");
        if !direct_event {
            continue;
        }
        let mut pieces = raw_name.split(';');
        let name = pieces.next().unwrap_or_default().trim().to_ascii_uppercase();
        let params: Vec<&str> = pieces.collect();
        if params.iter().any(|p| p.trim().to_ascii_uppercase().starts_with("TZID=")) {
            anyhow::bail!("CalDAV VEVENT `{name}` uses TZID; timezone expansion is unsupported");
        }
        if matches!(name.as_str(), "RRULE" | "RDATE" | "EXDATE" | "RECURRENCE-ID") {
            anyhow::bail!("CalDAV VEVENT `{name}` recurrence is unsupported");
        }
        match name.as_str() {
            "UID" => set_once(&mut uid, value.to_string(), "UID")?,
            "SUMMARY" => set_once(&mut summary, unescape_ics_text(value), "SUMMARY")?,
            "DTSTART" => set_once(&mut start, value.to_string(), "DTSTART")?,
            "DTEND" => set_once(&mut end, value.to_string(), "DTEND")?,
            "LOCATION" => set_once(&mut location, unescape_ics_text(value), "LOCATION")?,
            _ => {}
        }
    }
    if !components.is_empty() || finished_vevent != 1 {
        anyhow::bail!("CalDAV calendar-data has an unterminated or missing VEVENT");
    }
    let summary = summary.filter(|s| !s.is_empty())
        .context("CalDAV VEVENT missing or empty SUMMARY")?;
    let start = start.context("CalDAV VEVENT missing DTSTART")?;
    let end = end.unwrap_or_else(|| start.clone());
    validate_supported_calendar_range(&start, &end)?;
    Ok(Some(CalendarEvent {
        calendar_id: crate::email::calendar::PRIMARY_CALENDAR_ID.to_string(),
        event_id: uid.unwrap_or_default(), summary, description: String::new(),
        location: location.unwrap_or_default(), start_rfc3339: start, end_rfc3339: end,
        attendees: Vec::new(),
    }))
}

fn set_once(slot: &mut Option<String>, value: String, property: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        anyhow::bail!("CalDAV VEVENT has duplicate {property}");
    }
    Ok(())
}

fn validate_supported_calendar_range(start: &str, end: &str) -> Result<()> {
    let start_date = parse_calendar_date(start);
    let end_date = parse_calendar_date(end);
    match (start_date, end_date) {
        (Some(start), Some(end)) if end > start => return Ok(()),
        (Some(_), Some(_)) => anyhow::bail!("CalDAV VEVENT all-day DTEND precedes DTSTART"),
        (Some(_), None) | (None, Some(_)) => anyhow::bail!("CalDAV VEVENT mixes all-day and timed values"),
        (None, None) => {}
    }
    let parse_instant = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .map(|v| v.with_timezone(&chrono::Utc))
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%SZ")
                .map(|v| v.and_utc()))
    };
    let start = parse_instant(start).map_err(|_| anyhow::anyhow!(
        "CalDAV VEVENT DTSTART must be RFC3339 with an offset, basic UTC, or date-only (floating time is unsupported)"))?;
    let end = parse_instant(end).map_err(|_| anyhow::anyhow!(
        "CalDAV VEVENT DTEND must be RFC3339 with an offset, basic UTC, or date-only (floating time is unsupported)"))?;
    if end <= start { anyhow::bail!("CalDAV VEVENT DTEND must be after DTSTART"); }
    Ok(())
}

fn parse_calendar_date(value: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(value, "%Y%m%d").ok()
        .filter(|date| date.format("%Y%m%d").to_string() == value)
        .or_else(|| chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
            .filter(|date| date.format("%Y-%m-%d").to_string() == value))
}

/// Bounded, timeout-controlled CalDAV REPORT for agenda consumers.
/// Unlike [`list_events_against`], this rejects malformed XML, unsupported
/// temporal semantics, response overrun, and event-count truncation.
pub async fn list_supported_events_against(
    calendar_url: &str, username: &str, password: &str,
) -> Result<Vec<CalendarEvent>> {
    let endpoint = CaldavEndpoint::parse(calendar_url)?;
    let method = reqwest::Method::from_bytes(b"REPORT").expect("REPORT is valid");
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(AGENDA_REPORT_TIMEOUT_SECS);
    let response = tokio::time::timeout(
        agenda_remaining(deadline)?,
        endpoint.client()?.request(method, endpoint.collection_url())
            .basic_auth(username, Some(password)).header("Depth", "1")
            .header(reqwest::header::CONTENT_TYPE, "application/xml; charset=utf-8")
            .body(CALENDAR_QUERY_VEVENT).send(),
    ).await.context("CalDAV VEVENT REPORT timed out")??;
    let status = response.status();
    if !status.is_success() { anyhow::bail!("CalDAV REPORT failed: HTTP {status}"); }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = tokio::time::timeout(
        agenda_remaining(deadline)?, stream.next(),
    ).await.context("CalDAV VEVENT response body timed out")? {
        let chunk = chunk.context("read CalDAV VEVENT response body")?;
        if bytes.len().saturating_add(chunk.len()) > AGENDA_REPORT_MAX_BYTES {
            anyhow::bail!("CalDAV VEVENT REPORT exceeds {AGENDA_REPORT_MAX_BYTES} byte limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    let xml = std::str::from_utf8(&bytes).context("CalDAV VEVENT response is not UTF-8")?;
    let entries = parse_supported_multistatus(xml)?;
    if entries.len() > AGENDA_REPORT_MAX_EVENTS {
        anyhow::bail!("CalDAV VEVENT REPORT exceeds {AGENDA_REPORT_MAX_EVENTS} event limit");
    }
    entries.into_iter()
        .map(|calendar_data| parse_supported_vevent(&calendar_data))
        .collect::<Result<Vec<_>>>()
        .map(|events| events.into_iter().flatten().collect())
}

fn agenda_remaining(deadline: tokio::time::Instant) -> Result<std::time::Duration> {
    deadline.checked_duration_since(tokio::time::Instant::now())
        .context("CalDAV VEVENT REPORT timed out")
}

fn parse_supported_multistatus(xml: &str) -> Result<Vec<String>> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut buffer = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut root_closed = false;
    let mut entries = Vec::new();
    let mut response: Option<StrictResponse> = None;
    let mut capture: Option<(usize, StrictField)> = None;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(node)) => {
                let name = node.local_name();
                let name = std::str::from_utf8(name.as_ref()).context("CalDAV XML element is not UTF-8")?.to_ascii_lowercase();
                if path.is_empty() {
                    if root_closed || name != "multistatus" {
                        anyhow::bail!("CalDAV REPORT did not return one multistatus XML root");
                    }
                } else if name == "response" {
                    if !path_matches(&path, &["multistatus"]) {
                        anyhow::bail!("CalDAV response is outside the multistatus root");
                    }
                    if response.is_some() { anyhow::bail!("nested CalDAV response entry"); }
                    response = Some(StrictResponse::default());
                } else if matches!(name.as_str(), "status" | "calendar-data") {
                    let expected: &[&str] = if name == "status" {
                        &["multistatus", "response", "propstat"]
                    } else {
                        &["multistatus", "response", "propstat", "prop"]
                    };
                    if response.is_none() || !path_matches(&path, expected) {
                        anyhow::bail!("CalDAV `{name}` is outside its required DAV response path");
                    }
                    if capture.is_some() { anyhow::bail!("nested CalDAV response field"); }
                    let field = if name == "status" { StrictField::Status } else { StrictField::CalendarData };
                    response.as_mut().expect("response checked above").begin_field(field)?;
                    capture = Some((path.len() + 1, field));
                } else if !valid_dav_structure(&path, &name) {
                    anyhow::bail!("CalDAV XML has unsupported `{name}` at this nesting depth");
                }
                path.push(name);
            }
            Ok(Event::Empty(node)) => {
                let name = node.local_name();
                let name = std::str::from_utf8(name.as_ref()).context("CalDAV XML element is not UTF-8")?.to_ascii_lowercase();
                if path.is_empty() && name == "multistatus" && !root_closed {
                    root_closed = true;
                } else {
                    anyhow::bail!("CalDAV multistatus has unsupported empty `{name}` element");
                }
            }
            Ok(Event::Text(text)) => {
                if let Some((_, field)) = capture {
                    let raw = String::from_utf8_lossy(&text);
                    let value = quick_xml::escape::unescape(&raw)
                        .map(|value| value.into_owned())
                        .map_err(|error| anyhow::anyhow!("malformed CalDAV XML text: {error}"))?;
                    response.as_mut().context("CalDAV response field outside response")?.append(field, value)?;
                } else if path.is_empty() && !String::from_utf8_lossy(&text).trim().is_empty() {
                    anyhow::bail!("text outside CalDAV multistatus root");
                }
            }
            Ok(Event::CData(text)) => {
                let (_, field) = capture.context("CalDAV CDATA outside expected response field")?;
                let value = String::from_utf8(text.into_inner().to_vec())
                    .context("CalDAV calendar-data is not UTF-8")?;
                response.as_mut().context("CalDAV response field outside response")?.append(field, value)?;
            }
            Ok(Event::End(node)) => {
                let name = node.local_name();
                let name = std::str::from_utf8(name.as_ref()).context("CalDAV XML element is not UTF-8")?.to_ascii_lowercase();
                let depth = path.len();
                if path.last().map(String::as_str) != Some(name.as_str()) {
                    anyhow::bail!("CalDAV XML closing element nesting is invalid");
                }
                if capture.as_ref().is_some_and(|(field_depth, _)| *field_depth == depth) {
                    capture = None;
                }
                if path_matches(&path, &["multistatus", "response"]) {
                    entries.push(response.take().context("CalDAV response nesting is invalid")?.finish()?);
                }
                if path_matches(&path, &["multistatus"]) { root_closed = true; }
                path.pop();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {},
            Err(error) => return Err(anyhow::anyhow!("malformed CalDAV multistatus XML: {error}")),
        }
        buffer.clear();
    }
    if !path.is_empty() || capture.is_some() || response.is_some() || !root_closed {
        anyhow::bail!("malformed or incomplete CalDAV multistatus XML");
    }
    Ok(entries)
}

fn valid_dav_structure(path: &[String], name: &str) -> bool {
    (path_matches(path, &["multistatus", "response"])
        && matches!(name, "href" | "propstat"))
        || (path_matches(path, &["multistatus", "response", "propstat"])
            && name == "prop")
}

fn path_matches(path: &[String], expected: &[&str]) -> bool {
    path.len() == expected.len()
        && path.iter().zip(expected).all(|(actual, expected)| actual.as_str() == *expected)
}

#[derive(Default)]
struct StrictResponse {
    status: Option<String>,
    calendar_data: Option<String>,
    status_fields: u8,
    calendar_data_fields: u8,
}
#[derive(Clone, Copy)]
enum StrictField { Status, CalendarData }
impl StrictResponse {
    fn begin_field(&mut self, field: StrictField) -> Result<()> {
        let count = match field {
            StrictField::Status => &mut self.status_fields,
            StrictField::CalendarData => &mut self.calendar_data_fields,
        };
        *count = count.saturating_add(1);
        if *count != 1 { anyhow::bail!("CalDAV response entry has duplicate required field"); }
        Ok(())
    }
    fn append(&mut self, field: StrictField, value: String) -> Result<()> {
        let slot = match field { StrictField::Status => &mut self.status, StrictField::CalendarData => &mut self.calendar_data };
        if let Some(existing) = slot { existing.push_str(&value); } else { *slot = Some(value); }
        Ok(())
    }
    fn finish(self) -> Result<String> {
        let status = self.status.context("CalDAV response entry is missing HTTP status")?;
        let code = status.split_whitespace().nth(1).context("malformed CalDAV response HTTP status")?
            .parse::<u16>().context("malformed CalDAV response HTTP status")?;
        if !(200..300).contains(&code) { anyhow::bail!("CalDAV response entry failed: {status}"); }
        self.calendar_data.context("CalDAV response entry is missing calendar-data")
    }
}

/// List VEVENTs from a CalDAV calendar collection. Issues the `REPORT`
/// calendar-query (HTTP Basic auth, `Depth: 1`) + parses the response. The
/// network shell; the parsing is in the pure fns above.
pub async fn list_events_against(
    calendar_url: &str,
    username: &str,
    password: &str,
) -> Result<Vec<CalendarEvent>> {
    let endpoint = CaldavEndpoint::parse(calendar_url)?;
    let method = reqwest::Method::from_bytes(b"REPORT").expect("REPORT is a valid method token");
    let resp = endpoint
        .client()?
        .request(method, endpoint.collection_url())
        .basic_auth(username, Some(password))
        .header("Depth", "1")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/xml; charset=utf-8",
        )
        .body(CALENDAR_QUERY_VEVENT)
        .send()
        .await
        .context("send CalDAV VEVENT REPORT request")?;
    let status = resp.status();
    let text = resp.text().await.context("read CalDAV response body")?;
    if !status.is_success() {
        anyhow::bail!("CalDAV REPORT failed: HTTP {status}");
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
    format!(
        "neoth-evt-{:016x}",
        xxhash_rust::xxh3::xxh3_64(key.as_bytes())
    )
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

    let endpoint = CaldavEndpoint::parse(calendar_url)?;
    let url = endpoint.resource_url(&uid)?;
    let resp = endpoint
        .client()?
        .put(url.clone())
        .basic_auth(username, Some(password))
        .header(
            reqwest::header::CONTENT_TYPE,
            "text/calendar; charset=utf-8",
        )
        // Idempotency: only create if it does not already exist.
        .header(reqwest::header::IF_NONE_MATCH, "*")
        .body(body)
        .send()
        .await
        .context("send CalDAV VEVENT PUT request")?;
    let status = resp.status();
    if status == reqwest::StatusCode::PRECONDITION_FAILED {
        return Ok(CreateOutcome::AlreadyExists);
    }
    if !status.is_success() {
        anyhow::bail!("CalDAV PUT failed: HTTP {status}");
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
        assert_eq!(
            e.end_rfc3339, "20260530T090000Z",
            "missing DTEND mirrors DTSTART"
        );
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

    #[test]
    fn supported_vevent_accepts_basic_utc_rfc3339_offsets_and_all_day() {
        for (start, end) in [
            ("20260530T090000Z", "20260530T100000Z"),
            ("2026-05-30T09:00:00+02:00", "2026-05-30T10:00:00+02:00"),
            ("20260530", "20260531"),
        ] {
            let ics = format!("BEGIN:VEVENT\nSUMMARY:ok\nDTSTART:{start}\nDTEND:{end}\nEND:VEVENT");
            assert!(parse_supported_vevent(&ics).unwrap().is_some(), "{start}");
        }
    }

    #[test]
    fn supported_vevent_rejects_tzid_floating_and_recurrence() {
        for (ics, expected) in [
            ("BEGIN:VEVENT\nSUMMARY:x\nDTSTART;TZID=Europe/Berlin:20260530T090000\nDTEND;TZID=Europe/Berlin:20260530T100000\nEND:VEVENT", "TZID"),
            ("BEGIN:VEVENT\nSUMMARY:x\nDTSTART:20260530T090000\nDTEND:20260530T100000\nEND:VEVENT", "floating"),
            ("BEGIN:VEVENT\nSUMMARY:x\nDTSTART:20260530T090000Z\nDTEND:20260530T100000Z\nRRULE:FREQ=DAILY\nEND:VEVENT", "recurrence"),
        ] {
            assert!(parse_supported_vevent(ics).unwrap_err().to_string().contains(expected));
        }
    }

    #[tokio::test]
    async fn bounded_report_uses_real_loopback_tcp_and_rejects_bad_responses() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::{method, path};
        let server = MockServer::start().await;
        let url = format!("{}/calendar", server.uri());
        Mock::given(method("REPORT")).and(path("/calendar"))
            .respond_with(ResponseTemplate::new(207).set_body_string(
                "<multistatus xmlns=\"DAV:\"><response><propstat><prop><calendar-data><![CDATA[BEGIN:VEVENT\nSUMMARY:TCP\nDTSTART:20260530T090000Z\nDTEND:20260530T100000Z\nEND:VEVENT]]></calendar-data></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"))
            .mount(&server).await;
        let events = list_supported_events_against(&url, "user", "password").await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "TCP");

        let bad_server = MockServer::start().await;
        Mock::given(method("REPORT")).respond_with(ResponseTemplate::new(503)).mount(&bad_server).await;
        assert!(list_supported_events_against(&bad_server.uri(), "u", "p").await.unwrap_err().to_string().contains("HTTP 503"));
    }

    #[tokio::test]
    async fn bounded_report_rejects_malformed_oversize_and_unsupported_entries() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use wiremock::matchers::method;
        let malformed = MockServer::start().await;
        Mock::given(method("REPORT")).respond_with(ResponseTemplate::new(207).set_body_string("<multistatus"))
            .mount(&malformed).await;
        assert!(list_supported_events_against(&malformed.uri(), "u", "p").await.unwrap_err().to_string().contains("malformed"));

        let oversized = MockServer::start().await;
        Mock::given(method("REPORT")).respond_with(ResponseTemplate::new(207).set_body_bytes(vec![b'x'; AGENDA_REPORT_MAX_BYTES + 1]))
            .mount(&oversized).await;
        assert!(list_supported_events_against(&oversized.uri(), "u", "p").await.unwrap_err().to_string().contains("byte limit"));

        let unsupported = MockServer::start().await;
        Mock::given(method("REPORT")).respond_with(ResponseTemplate::new(207).set_body_string(
            "<multistatus><response><propstat><prop><calendar-data><![CDATA[BEGIN:VEVENT\nSUMMARY:x\nDTSTART;TZID=Europe/Berlin:20260530T090000\nEND:VEVENT]]></calendar-data></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"))
            .mount(&unsupported).await;
        assert!(list_supported_events_against(&unsupported.uri(), "u", "p").await.unwrap_err().to_string().contains("TZID"));
    }

    #[test]
    fn strict_multistatus_rejects_missing_status_duplicate_data_and_bad_entries() {
        assert!(parse_supported_multistatus("<multistatus/>").unwrap().is_empty());
        for xml in [
            "<multistatus><response><propstat><prop><calendar-data>x</calendar-data></prop></propstat></response></multistatus>",
            "<multistatus><response><propstat><status>HTTP/1.1 403 Denied</status><prop><calendar-data>x</calendar-data></prop></propstat></response></multistatus>",
            "<multistatus><response><propstat><status>HTTP/1.1 200 OK</status><prop><calendar-data>x</calendar-data><calendar-data>y</calendar-data></prop></propstat></response></multistatus>",
        ] {
            assert!(parse_supported_multistatus(xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn strict_multistatus_rejects_misplaced_entries_and_scalar_markup() {
        for xml in [
            "<multistatus><wrapper><response><propstat><prop><calendar-data>x</calendar-data></prop><status>HTTP/1.1 200 OK</status></propstat></response></wrapper></multistatus>",
            "<multistatus><response><propstat><prop><calendar-data><b>x</b></calendar-data></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>",
        ] {
            assert!(parse_supported_multistatus(xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn supported_vevent_rejects_multiple_duplicate_unterminated_and_empty_summary() {
        for ics in [
            "BEGIN:VEVENT\nSUMMARY:a\nDTSTART:20260530T090000Z\nDTEND:20260530T100000Z\nEND:VEVENT\nBEGIN:VEVENT\nSUMMARY:b\nEND:VEVENT",
            "BEGIN:VEVENT\nSUMMARY:a\nDTSTART:20260530T090000Z\nDTSTART:20260530T093000Z\nDTEND:20260530T100000Z\nEND:VEVENT",
            "BEGIN:VEVENT\nSUMMARY:a\nDTSTART:20260530T090000Z",
            "BEGIN:VEVENT\nSUMMARY:\nDTSTART:20260530T090000Z\nDTEND:20260530T100000Z\nEND:VEVENT",
        ] {
            assert!(parse_supported_vevent(ics).is_err(), "{ics}");
        }
    }

    #[test]
    fn supported_vevent_ignores_balanced_valarm_but_rejects_bad_component_shapes() {
        let valid = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Meeting\nDTSTART:20260530T090000Z\nDTEND:20260530T100000Z\nBEGIN:VALARM\nSUMMARY:Alarm title\nEND:VALARM\nEND:VEVENT\nEND:VCALENDAR";
        assert_eq!(parse_supported_vevent(valid).unwrap().unwrap().summary, "Meeting");
        for ics in [
            "BEGIN:VEVENT\nSUMMARY:Meeting\nDTSTART:20260530T090000Z\nDTEND:20260530T100000Z\nBEGIN:VALARM\nEND:VEVENT",
            "BEGIN:VEVENT\nSUMMARY:Meeting\nDTSTART:20260530T090000Z\nDTEND:20260530T100000Z\nBEGIN:VTODO\nEND:VTODO\nEND:VEVENT",
        ] {
            assert!(parse_supported_vevent(ics).is_err(), "{ics}");
        }
    }

    #[tokio::test]
    async fn event_network_paths_reject_remote_plain_http_before_dispatch() {
        let ephemeral_password = uuid::Uuid::new_v4().to_string();
        let list_error = list_events_against(
            "http://calendar.example/dav/events",
            "private-user",
            &ephemeral_password,
        )
        .await
        .unwrap_err();
        assert!(list_error.to_string().contains("must use HTTPS"));

        let event = CalendarEvent {
            calendar_id: "primary".into(),
            event_id: "evt-1".into(),
            summary: "Private meeting".into(),
            description: "Sensitive notes".into(),
            location: String::new(),
            start_rfc3339: "2026-05-30T09:00:00Z".into(),
            end_rfc3339: "2026-05-30T10:00:00Z".into(),
            attendees: vec![],
        };
        let create_error = create_event_against(
            "http://calendar.example/dav/events",
            "private-user",
            &ephemeral_password,
            &event,
        )
        .await
        .unwrap_err();
        assert!(create_error.to_string().contains("must use HTTPS"));
    }
}
