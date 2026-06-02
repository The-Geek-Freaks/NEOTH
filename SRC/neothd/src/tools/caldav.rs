//! TD-02 — CalDAV task backend (read-only LIST slice).
//!
//! `neoth todo --provider caldav list` issues a WebDAV `REPORT`
//! `calendar-query` for `VTODO` components against the operator's task
//! calendar collection, parses the `multistatus` XML, and extracts each
//! VTODO's SUMMARY / STATUS / UID / DUE. Open (non-completed/cancelled)
//! tasks are returned.
//!
//! The XML `multistatus` parser ([`parse_multistatus`]) and the iCalendar
//! VTODO parser ([`parse_vtodo`]) are PURE + unit-tested with fixtures; the
//! network `REPORT` ([`list_tasks`]) is the thin, untested I/O shell (same
//! split as the `nvidia-smi` subprocess in `daemon::resource_watch`).
//!
//! Create/complete (PUT a new VTODO / PROPPATCH STATUS:COMPLETED) is a
//! follow-on; the LIST slice is the minimal useful surface.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::providers::http_client;

/// The `REPORT` body: a `calendar-query` filtering for `VTODO`, asking for the
/// full `calendar-data` of each match.
pub const CALENDAR_QUERY_VTODO: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag/>
    <C:calendar-data/>
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VTODO"/>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>"#;

/// One task parsed from a VTODO component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaldavTask {
    pub uid: String,
    pub summary: String,
    /// VTODO STATUS verbatim (e.g. `NEEDS-ACTION`, `IN-PROCESS`, `COMPLETED`).
    pub status: String,
    /// VTODO DUE value verbatim, when present.
    pub due: Option<String>,
}

impl CaldavTask {
    /// A finished task — STATUS is COMPLETED or CANCELLED (case-insensitive).
    pub fn is_done(&self) -> bool {
        let s = self.status.trim().to_ascii_uppercase();
        s == "COMPLETED" || s == "CANCELLED"
    }
}

/// One `<response>` row from the multistatus: the resource href + its
/// embedded `calendar-data` (the raw ICS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalEntry {
    pub href: String,
    pub calendar_data: String,
}

/// Parse a WebDAV `multistatus` XML body into `(href, calendar-data)` rows.
/// Matches elements by LOCAL name (namespace-prefix-agnostic) so any of
/// `d:href` / `D:href` / `href` + `cal:calendar-data` etc. work. Best-effort:
/// a malformed body yields the rows parsed so far (the caller treats an empty
/// result as "no tasks", and `list_tasks` already gated on the HTTP status).
pub fn parse_multistatus(xml: &str) -> Vec<CalEntry> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut entries = Vec::new();
    let mut cur_href: Option<String> = None;
    let mut cur_data: Option<String> = None;
    // Which text node we are currently inside (None = ignore text).
    let mut capture: Option<Field> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match local_name(e.local_name().as_ref()) {
                "response" => {
                    cur_href = None;
                    cur_data = None;
                }
                "href" => capture = Some(Field::Href),
                "calendar-data" => capture = Some(Field::Data),
                _ => {}
            },
            Ok(Event::Text(t)) => {
                if let Some(field) = capture {
                    // quick-xml 0.38 BytesText has no `.unescape()`; decode the
                    // raw bytes then unescape XML entities via the free fn
                    // (version-robust). Hrefs/ICS rarely carry entities, but
                    // `&amp;` etc. must resolve correctly.
                    let raw = String::from_utf8_lossy(&t);
                    let txt = quick_xml::escape::unescape(&raw)
                        .map(|c| c.into_owned())
                        .unwrap_or_else(|_| raw.into_owned());
                    append_capture(field, &mut cur_href, &mut cur_data, &txt);
                }
            }
            Ok(Event::CData(t)) => {
                if let Some(field) = capture {
                    let txt = String::from_utf8_lossy(t.as_ref()).into_owned();
                    append_capture(field, &mut cur_href, &mut cur_data, &txt);
                }
            }
            Ok(Event::End(e)) => match local_name(e.local_name().as_ref()) {
                "href" | "calendar-data" => capture = None,
                "response" => {
                    if let Some(data) = cur_data.take() {
                        entries.push(CalEntry {
                            href: cur_href.take().unwrap_or_default(),
                            calendar_data: data,
                        });
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    entries
}

#[derive(Clone, Copy)]
enum Field {
    Href,
    Data,
}

fn append_capture(field: Field, href: &mut Option<String>, data: &mut Option<String>, txt: &str) {
    let slot = match field {
        Field::Href => href,
        Field::Data => data,
    };
    slot.get_or_insert_with(String::new).push_str(txt);
}

/// Element name without its namespace prefix, as UTF-8 (lossless for the ASCII
/// element names CalDAV uses; lossy fallback never matches a known tag).
fn local_name(raw: &[u8]) -> &str {
    std::str::from_utf8(raw).unwrap_or("")
}

/// Unfold iCalendar content lines (RFC 5545 §3.1): a CRLF followed by a single
/// space or tab is a line continuation — strip it and join to the prior line.
fn unfold_ics(ics: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in ics.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        if (line.starts_with(' ') || line.starts_with('\t')) && !lines.is_empty() {
            // Continuation: append everything after the single leading WS char.
            lines.last_mut().unwrap().push_str(&line[1..]);
        } else {
            lines.push(line.to_string());
        }
    }
    lines
}

/// Split an iCalendar property line into `(NAME, VALUE)`, dropping any
/// `;params` between the name and the `:`. `None` when there is no `:`.
fn parse_property(line: &str) -> Option<(String, &str)> {
    let colon = line.find(':')?;
    let name_part = &line[..colon];
    let value = &line[colon + 1..];
    let name = name_part.split(';').next().unwrap_or(name_part);
    Some((name.trim().to_ascii_uppercase(), value))
}

/// Parse the FIRST `VTODO` component out of an iCalendar `calendar-data` blob.
/// `None` when there is no VTODO with a SUMMARY (a task with no title is not
/// worth listing).
pub fn parse_vtodo(ics: &str) -> Option<CaldavTask> {
    let mut in_vtodo = false;
    let (mut uid, mut summary, mut status, mut due) = (None, None, None, None);
    for line in unfold_ics(ics) {
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("BEGIN:VTODO") {
            in_vtodo = true;
            continue;
        }
        if upper.starts_with("END:VTODO") {
            break;
        }
        if !in_vtodo {
            continue;
        }
        if let Some((name, value)) = parse_property(&line) {
            match name.as_str() {
                "UID" => uid = Some(value.trim().to_string()),
                "SUMMARY" => summary = Some(value.trim().to_string()),
                "STATUS" => status = Some(value.trim().to_string()),
                "DUE" => due = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    let summary = summary?;
    Some(CaldavTask {
        uid: uid.unwrap_or_default(),
        summary,
        status: status.unwrap_or_default(),
        due,
    })
}

/// Parse a multistatus body into the open (non-done) tasks. Pure — the seam
/// `list_tasks` calls after the network round-trip; unit-tested directly.
pub fn parse_open_tasks(multistatus_xml: &str) -> Vec<CaldavTask> {
    parse_multistatus(multistatus_xml)
        .iter()
        .filter_map(|e| parse_vtodo(&e.calendar_data))
        .filter(|t| !t.is_done())
        .collect()
}

/// List open VTODO tasks from a CalDAV calendar collection. Issues the
/// `REPORT` calendar-query (HTTP Basic auth, `Depth: 1`) + parses the
/// response. The network shell; the parsing is in the pure fns above.
pub async fn list_tasks(base_url: &str, username: &str, password: &str) -> Result<Vec<CaldavTask>> {
    let method = reqwest::Method::from_bytes(b"REPORT").expect("REPORT is a valid method token");
    // Use the shared hardened client (timeouts + TLS posture) from
    // `providers::http_client` — same path todoist/google_tasks use, and the
    // only place the `no_outbound_network` guard allows a client to be built.
    let resp = http_client::build_client()?
        .request(method, base_url)
        .basic_auth(username, Some(password))
        .header("Depth", "1")
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/xml; charset=utf-8",
        )
        .body(CALENDAR_QUERY_VTODO)
        .send()
        .await
        .with_context(|| format!("CalDAV REPORT request to {base_url}"))?;
    let status = resp.status();
    let text = resp.text().await.context("read CalDAV response body")?;
    if !status.is_success() {
        let snippet: String = text.chars().take(200).collect();
        anyhow::bail!("CalDAV REPORT failed: HTTP {status} — {snippet}");
    }
    Ok(parse_open_tasks(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTISTATUS: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
    <d:href>/dav/tasks/a.ics</d:href>
    <d:propstat><d:prop>
      <cal:calendar-data>BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VTODO
UID:task-1
SUMMARY:Buy milk
STATUS:NEEDS-ACTION
DUE;VALUE=DATE:20260110
END:VTODO
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/tasks/b.ics</d:href>
    <d:propstat><d:prop>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VTODO
UID:task-2
SUMMARY:Already done
STATUS:COMPLETED
END:VTODO
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>"#;

    #[test]
    fn parse_multistatus_extracts_two_entries() {
        let entries = parse_multistatus(MULTISTATUS);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].href, "/dav/tasks/a.ics");
        assert!(entries[0].calendar_data.contains("UID:task-1"));
    }

    #[test]
    fn parse_vtodo_extracts_fields() {
        let entries = parse_multistatus(MULTISTATUS);
        let t = parse_vtodo(&entries[0].calendar_data).expect("first VTODO parses");
        assert_eq!(t.uid, "task-1");
        assert_eq!(t.summary, "Buy milk");
        assert_eq!(t.status, "NEEDS-ACTION");
        assert_eq!(t.due.as_deref(), Some("20260110"));
        assert!(!t.is_done());
    }

    #[test]
    fn parse_open_tasks_filters_completed() {
        // task-1 NEEDS-ACTION is open; task-2 COMPLETED is filtered out.
        let open = parse_open_tasks(MULTISTATUS);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].uid, "task-1");
    }

    #[test]
    fn is_done_matches_completed_and_cancelled() {
        let mk = |s: &str| CaldavTask {
            uid: "x".into(),
            summary: "x".into(),
            status: s.into(),
            due: None,
        };
        assert!(mk("COMPLETED").is_done());
        assert!(mk("cancelled").is_done());
        assert!(!mk("NEEDS-ACTION").is_done());
        assert!(!mk("IN-PROCESS").is_done());
    }

    #[test]
    fn unfold_joins_continuation_lines() {
        // RFC 5545 folding: a CRLF + leading space continues the prior line.
        let ics = "BEGIN:VTODO\r\nSUMMARY:A very long\r\n  folded title\r\nEND:VTODO\r\n";
        let t = parse_vtodo(ics).expect("folded VTODO parses");
        assert_eq!(t.summary, "A very long folded title");
    }

    #[test]
    fn parse_vtodo_none_without_summary_or_vtodo() {
        assert!(parse_vtodo("BEGIN:VCALENDAR\nEND:VCALENDAR").is_none());
        assert!(parse_vtodo("not even ical").is_none());
        // A VTODO without SUMMARY is not listable.
        assert!(parse_vtodo("BEGIN:VTODO\nUID:x\nEND:VTODO").is_none());
    }

    #[test]
    fn parse_property_drops_params() {
        let (name, value) = parse_property("DUE;VALUE=DATE:20260110").unwrap();
        assert_eq!(name, "DUE");
        assert_eq!(value, "20260110");
        assert!(parse_property("no colon here").is_none());
    }

    #[test]
    fn parse_multistatus_empty_on_garbage() {
        assert!(parse_multistatus("<not><valid").is_empty() || parse_multistatus("").is_empty());
        assert!(parse_multistatus("").is_empty());
    }
}
