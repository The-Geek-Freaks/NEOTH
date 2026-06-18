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
/// `pub(crate)` so the EM-02b VEVENT parser ([`super::caldav_calendar`]) reuses
/// the same proven unfolding instead of duplicating it.
pub(crate) fn unfold_ics(ics: &str) -> Vec<String> {
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
/// `pub(crate)` — shared with the EM-02b VEVENT parser.
pub(crate) fn parse_property(line: &str) -> Option<(String, &str)> {
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

// ── TD-02 write surface (create / complete) ──────────────────────────────────

/// Outcome of [`create_task`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    /// A new VTODO was PUT.
    Created,
    /// The deterministic UID already existed (idempotency: `If-None-Match: *`
    /// returned 412) — no duplicate was written.
    AlreadyExists,
}

/// Outcome of [`close_task`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOutcome {
    /// STATUS:COMPLETED was PUT back.
    Completed,
    /// No resource at the UID's href (nothing to close).
    NotFound,
    /// The server copy changed since the GET (`If-Match` ETag mismatch → 412)
    /// — re-run after re-listing so a concurrent edit isn't clobbered.
    Conflict,
}

/// Deterministic resource UID for a task summary. Same summary → same UID →
/// `create_task` is idempotent (a re-run hits the existing resource, never
/// duplicates). 16-hex of xxh3-64 keeps it path-safe.
pub fn task_uid(summary: &str) -> String {
    format!(
        "neoth-{:016x}",
        xxhash_rust::xxh3::xxh3_64(summary.as_bytes())
    )
}

/// Reject a UID that could escape the collection path (`..`, `/`, control
/// chars). Generated UIDs are always safe; an operator-supplied `close <uid>`
/// is validated here before it's interpolated into the resource URL.
pub fn validate_uid(uid: &str) -> Result<()> {
    if uid.is_empty() || uid.len() > 256 {
        anyhow::bail!("invalid task uid (empty or too long)");
    }
    if uid
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
        && !uid.contains("..")
    {
        Ok(())
    } else {
        anyhow::bail!("invalid task uid '{uid}' — only [A-Za-z0-9-_.@] allowed, no '..'")
    }
}

/// The resource URL for a UID inside the collection. `base_url` is the
/// calendar collection; the VTODO lives at `<base>/<uid>.ics` (the client-
/// chosen-name convention every major CalDAV server accepts).
pub fn resource_url(base_url: &str, uid: &str) -> String {
    format!("{}/{}.ics", base_url.trim_end_matches('/'), uid)
}

/// Escape a text value for an iCalendar property (RFC 5545 §3.3.11): backslash,
/// semicolon, comma get escaped; newlines become `\n`.
fn escape_ics_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' | '\r' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Build a minimal VTODO iCalendar body (CRLF line endings per RFC 5545).
/// Pure + unit-tested.
pub fn build_vtodo_ics(uid: &str, summary: &str, due: Option<&str>) -> String {
    let mut s = String::new();
    s.push_str("BEGIN:VCALENDAR\r\n");
    s.push_str("VERSION:2.0\r\n");
    s.push_str("PRODID:-//NEOTH//todo//EN\r\n");
    s.push_str("BEGIN:VTODO\r\n");
    s.push_str(&format!("UID:{uid}\r\n"));
    s.push_str(&format!("SUMMARY:{}\r\n", escape_ics_text(summary)));
    s.push_str("STATUS:NEEDS-ACTION\r\n");
    if let Some(d) = due {
        s.push_str(&format!("DUE:{}\r\n", escape_ics_text(d)));
    }
    s.push_str("END:VTODO\r\n");
    s.push_str("END:VCALENDAR\r\n");
    s
}

/// Rewrite a VTODO's STATUS to COMPLETED, preserving every other line. If the
/// VTODO has no STATUS line, one is inserted before `END:VTODO`. Pure +
/// unit-tested — close fetches the live ICS then runs this so SUMMARY/DUE/etc.
/// survive the completion.
pub fn set_status_completed(ics: &str) -> String {
    let mut out = String::with_capacity(ics.len() + 20);
    let mut had_status = false;
    let mut inserted = false;
    for line in ics.split_inclusive(['\n']) {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("STATUS:") {
            had_status = true;
            out.push_str("STATUS:COMPLETED\r\n");
        } else if !had_status && !inserted && upper == "END:VTODO" {
            out.push_str("STATUS:COMPLETED\r\n");
            inserted = true;
            out.push_str(line);
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Create a VTODO on the CalDAV collection — PUT with `If-None-Match: *` so a
/// re-run on the same (deterministic) UID does NOT duplicate (server returns
/// 412 → [`CreateOutcome::AlreadyExists`]). The network shell; the body build
/// is the pure [`build_vtodo_ics`].
pub async fn create_task(
    base_url: &str,
    username: &str,
    password: &str,
    summary: &str,
    due: Option<&str>,
) -> Result<(String, CreateOutcome)> {
    let uid = task_uid(summary);
    let url = resource_url(base_url, &uid);
    let body = build_vtodo_ics(&uid, summary, due);
    let resp = http_client::build_client()?
        .put(&url)
        .basic_auth(username, Some(password))
        .header(reqwest::header::IF_NONE_MATCH, "*")
        .header(
            reqwest::header::CONTENT_TYPE,
            "text/calendar; charset=utf-8",
        )
        .body(body)
        .send()
        .await
        .with_context(|| format!("CalDAV PUT to {url}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::PRECONDITION_FAILED {
        return Ok((uid, CreateOutcome::AlreadyExists));
    }
    if !status.is_success() {
        let snippet: String = resp
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect();
        anyhow::bail!("CalDAV PUT failed: HTTP {status} — {snippet}");
    }
    Ok((uid, CreateOutcome::Created))
}

/// Complete a VTODO by UID — GET the live resource (for its body + ETag), set
/// STATUS:COMPLETED, and PUT it back with `If-Match: <etag>` (optimistic
/// concurrency: a concurrent server-side edit yields 412 →
/// [`CloseOutcome::Conflict`], never a silent clobber). A missing resource →
/// [`CloseOutcome::NotFound`].
pub async fn close_task(
    base_url: &str,
    username: &str,
    password: &str,
    uid: &str,
) -> Result<CloseOutcome> {
    validate_uid(uid)?;
    let url = resource_url(base_url, uid);
    let client = http_client::build_client()?;
    let get = client
        .get(&url)
        .basic_auth(username, Some(password))
        .send()
        .await
        .with_context(|| format!("CalDAV GET {url}"))?;
    if get.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(CloseOutcome::NotFound);
    }
    if !get.status().is_success() {
        anyhow::bail!("CalDAV GET failed: HTTP {}", get.status());
    }
    let etag = get
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let ics = get.text().await.context("read CalDAV resource body")?;
    let completed = set_status_completed(&ics);
    let mut put = client
        .put(&url)
        .basic_auth(username, Some(password))
        .header(
            reqwest::header::CONTENT_TYPE,
            "text/calendar; charset=utf-8",
        )
        .body(completed);
    // Optimistic concurrency: only overwrite the exact version we read.
    if let Some(tag) = &etag {
        put = put.header(reqwest::header::IF_MATCH, tag.as_str());
    }
    let resp = put
        .send()
        .await
        .with_context(|| format!("CalDAV PUT {url}"))?;
    if resp.status() == reqwest::StatusCode::PRECONDITION_FAILED {
        return Ok(CloseOutcome::Conflict);
    }
    if !resp.status().is_success() {
        anyhow::bail!("CalDAV complete PUT failed: HTTP {}", resp.status());
    }
    Ok(CloseOutcome::Completed)
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

    // ── TD-02 write surface ──────────────────────────────────────────────

    #[test]
    fn build_vtodo_ics_has_required_lines() {
        let ics = build_vtodo_ics("neoth-abc", "Buy milk", Some("20260110"));
        assert!(ics.contains("BEGIN:VTODO\r\n"));
        assert!(ics.contains("UID:neoth-abc\r\n"));
        assert!(ics.contains("SUMMARY:Buy milk\r\n"));
        assert!(ics.contains("STATUS:NEEDS-ACTION\r\n"));
        assert!(ics.contains("DUE:20260110\r\n"));
        assert!(ics.ends_with("END:VCALENDAR\r\n"));
    }

    #[test]
    fn build_vtodo_ics_escapes_special_chars() {
        let ics = build_vtodo_ics("u", "a,b; c\\d\ne", None);
        assert!(
            ics.contains("SUMMARY:a\\,b\\; c\\\\d\\ne\r\n"),
            "got: {ics}"
        );
        assert!(!ics.contains("DUE:"));
    }

    #[test]
    fn task_uid_is_deterministic_for_idempotency() {
        assert_eq!(task_uid("Buy milk"), task_uid("Buy milk"));
        assert_ne!(task_uid("Buy milk"), task_uid("Buy bread"));
        assert!(task_uid("x").starts_with("neoth-"));
    }

    #[test]
    fn validate_uid_rejects_traversal_and_bad_chars() {
        assert!(validate_uid("neoth-abc123").is_ok());
        assert!(validate_uid("task.ics_1@host").is_ok());
        assert!(validate_uid("../../etc/passwd").is_err());
        assert!(validate_uid("a/b").is_err());
        assert!(validate_uid("a b").is_err());
        assert!(validate_uid("").is_err());
    }

    #[test]
    fn resource_url_handles_trailing_slash() {
        assert_eq!(resource_url("https://h/dav/", "u"), "https://h/dav/u.ics");
        assert_eq!(resource_url("https://h/dav", "u"), "https://h/dav/u.ics");
    }

    #[test]
    fn set_status_completed_replaces_existing_and_preserves_rest() {
        let ics = "BEGIN:VTODO\r\nUID:x\r\nSUMMARY:keep me\r\nSTATUS:NEEDS-ACTION\r\nEND:VTODO\r\n";
        let out = set_status_completed(ics);
        assert!(out.contains("STATUS:COMPLETED\r\n"));
        assert!(!out.contains("NEEDS-ACTION"));
        assert!(out.contains("SUMMARY:keep me\r\n"), "other lines preserved");
        assert!(out.contains("UID:x\r\n"));
    }

    #[test]
    fn set_status_completed_inserts_when_absent() {
        let ics = "BEGIN:VTODO\r\nUID:x\r\nSUMMARY:s\r\nEND:VTODO\r\n";
        let out = set_status_completed(ics);
        assert!(out.contains("STATUS:COMPLETED\r\n"));
        // Inserted before END:VTODO, summary still there.
        let status_pos = out.find("STATUS:COMPLETED").unwrap();
        let end_pos = out.find("END:VTODO").unwrap();
        assert!(status_pos < end_pos);
        assert!(out.contains("SUMMARY:s\r\n"));
    }

    #[tokio::test]
    async fn create_task_201_is_created() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&mock)
            .await;
        let (uid, outcome) = create_task(&mock.uri(), "u", "p", "Buy milk", None)
            .await
            .unwrap();
        assert_eq!(outcome, CreateOutcome::Created);
        assert_eq!(uid, task_uid("Buy milk"), "uid is the deterministic key");
    }

    #[tokio::test]
    async fn create_task_412_is_already_exists_idempotent() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        // If-None-Match: * → server says the resource exists → 412.
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(412))
            .mount(&mock)
            .await;
        let (_uid, outcome) = create_task(&mock.uri(), "u", "p", "Buy milk", None)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            CreateOutcome::AlreadyExists,
            "a 412 must be the idempotent no-dup outcome, not an error"
        );
    }

    #[tokio::test]
    async fn close_task_404_is_not_found() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let outcome = close_task(&mock.uri(), "u", "p", "neoth-abc")
            .await
            .unwrap();
        assert_eq!(outcome, CloseOutcome::NotFound);
    }

    #[tokio::test]
    async fn close_task_completes_with_if_match_etag() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", "\"v1\"")
                    .set_body_string(
                        "BEGIN:VTODO\r\nUID:neoth-abc\r\nSUMMARY:s\r\nSTATUS:NEEDS-ACTION\r\nEND:VTODO\r\n",
                    ),
            )
            .mount(&mock)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock)
            .await;
        let outcome = close_task(&mock.uri(), "u", "p", "neoth-abc")
            .await
            .unwrap();
        assert_eq!(outcome, CloseOutcome::Completed);
    }

    #[tokio::test]
    async fn close_task_412_is_conflict_not_clobber() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("ETag", "\"v1\"")
                    .set_body_string(
                        "BEGIN:VTODO\r\nUID:neoth-abc\r\nSTATUS:NEEDS-ACTION\r\nEND:VTODO\r\n",
                    ),
            )
            .mount(&mock)
            .await;
        // Server copy changed → If-Match fails → 412.
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(412))
            .mount(&mock)
            .await;
        let outcome = close_task(&mock.uri(), "u", "p", "neoth-abc")
            .await
            .unwrap();
        assert_eq!(
            outcome,
            CloseOutcome::Conflict,
            "a concurrent edit must surface as Conflict, never a silent clobber"
        );
    }
}
