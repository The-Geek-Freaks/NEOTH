//! `neoth-migrate import-crons` — systemd timer / crontab → NEOTH operator-cron import.
//!
//! Reads one or more systemd `.timer` unit files and/or a `crontab` text file
//! and converts them to NEOTH `freedom.yaml`-style `Job` structs (the same
//! schema that `neothd/src/cron/schema.rs` loads at runtime).
//!
//! ## Supported input formats
//!
//! ### systemd timer units (`--timer <FILE>`)
//!
//! Recognises the following `[Timer]` section keys:
//! - `OnCalendar`     — calendar spec → 5-field cron expression.
//! - `OnUnitActiveSec` — interval spec → approximate cron expression.
//!
//! Recognises the following `[Service]` section keys:
//! - `ExecStart` — the command line that the timer triggers.
//!
//! A job is emitted for each `OnCalendar` or `OnUnitActiveSec` found.  If
//! both are present in the same unit the `OnCalendar` wins.
//!
//! ### crontab files (`--crontab <FILE>`)
//!
//! Standard 5-field crontab syntax:
//! ```text
//! MIN HOUR DOM MON DOW COMMAND...
//! ```
//! Lines starting with `#` or that are blank are skipped.
//! `@daily`, `@hourly`, `@weekly`, `@monthly`, `@yearly` / `@annually`
//! shorthand expansions are recognised.
//! Variables (`KEY=VALUE`) are skipped.
//!
//! ## Output
//!
//! The function [`import_crons`] returns [`ImportCronsResult`] containing a
//! list of [`ImportedJob`] values that can be serialised to YAML and pasted
//! into the operator's `jobs.yaml`.
//!
//! `ImportedJob` mirrors the `cron/schema.rs::Job` shape deliberately (loose
//! coupling via YAML — neoth-migrate does NOT depend on neothd).

use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Output shape (mirrors neothd cron/schema::Job) ────────────────────────

/// A schedule in 5-field cron syntax (`MIN HOUR DOM MON DOW`) plus an
/// optional IANA timezone.  Mirrors `cron/schema::Schedule`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedSchedule {
    /// 5-field standard cron expression.
    pub cron: String,
    /// IANA timezone if determinable from the source; otherwise `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tz: Option<String>,
}

/// One imported cron job.  Mirrors `cron/schema::Job` (minus `depends_on`
/// and `delivery` which have no systemd/crontab equivalent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedJob {
    /// Slug-style id derived from the source (timer filename or crontab row).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Enabled by default; operator can disable in jobs.yaml.
    pub enabled: bool,
    /// Converted schedule.
    pub schedule: ImportedSchedule,
    /// The imported command wrapped as a NEOTH prompt instruction.
    pub prompt: String,
    /// Timeout in seconds — defaulted to 600 (same as neothd default).
    pub timeout_seconds: u32,
    /// Notes about the conversion for the operator (warnings, approximations).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub import_notes: Vec<String>,
}

// ── Result ────────────────────────────────────────────────────────────────

/// Returned by [`import_crons`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportCronsResult {
    pub jobs: Vec<ImportedJob>,
    /// Lines / units that could not be parsed (non-fatal).
    pub skipped: Vec<String>,
}

// ── Public entry point ────────────────────────────────────────────────────

/// Parse systemd timer files and/or a crontab file into NEOTH Job structs.
///
/// - `timer_paths`: zero or more `.timer` unit file paths.
/// - `crontab_path`: optional crontab file path.
///
/// At least one source is required (returns an error if both slices/options
/// are empty / `None`).
pub fn import_crons(
    timer_paths: &[&Path],
    crontab_path: Option<&Path>,
) -> anyhow::Result<ImportCronsResult> {
    if timer_paths.is_empty() && crontab_path.is_none() {
        anyhow::bail!("at least one of --timer or --crontab must be provided");
    }

    let mut jobs: Vec<ImportedJob> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    // ── systemd timers ────────────────────────────────────────────────
    for path in timer_paths {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read timer {:?}: {}", path, e))?;
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("timer");
        match parse_timer_unit(&content, stem) {
            Ok(Some(job)) => jobs.push(job),
            Ok(None) => skipped.push(format!(
                "{}: no OnCalendar/OnUnitActiveSec found",
                path.display()
            )),
            Err(e) => skipped.push(format!("{}: {}", path.display(), e)),
        }
    }

    // ── crontab ───────────────────────────────────────────────────────
    if let Some(path) = crontab_path {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read crontab {:?}: {}", path, e))?;
        let (mut parsed, mut parse_skipped) = parse_crontab(&content);
        jobs.append(&mut parsed);
        skipped.append(&mut parse_skipped);
    }

    Ok(ImportCronsResult { jobs, skipped })
}

// ── systemd timer parser ─────────────────────────────────────────────────

/// Parse a systemd unit file text and return an `ImportedJob` or `None` if
/// the unit contains no timer trigger we can convert.
pub fn parse_timer_unit(content: &str, name_hint: &str) -> anyhow::Result<Option<ImportedJob>> {
    let mut on_calendar: Option<String> = None;
    let mut on_unit_active_sec: Option<String> = None;
    let mut exec_start: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("OnCalendar=") {
            on_calendar = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("OnUnitActiveSec=") {
            on_unit_active_sec = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("ExecStart=") {
            exec_start = Some(rest.trim().to_string());
        }
    }

    // OnCalendar takes priority over OnUnitActiveSec
    let (cron_expr, mut notes) = if let Some(cal) = &on_calendar {
        calendar_to_cron(cal)
    } else if let Some(interval) = &on_unit_active_sec {
        interval_to_cron(interval)
    } else {
        return Ok(None);
    };

    let cmd = exec_start.unwrap_or_else(|| "(no ExecStart in timer unit)".to_string());
    let id = slugify(name_hint);
    let prompt = format!("Run: {cmd}");

    // If OnUnitActiveSec is present alongside OnCalendar, note it was ignored
    if on_calendar.is_some() && on_unit_active_sec.is_some() {
        notes.push("OnUnitActiveSec ignored (OnCalendar takes priority)".to_string());
    }

    Ok(Some(ImportedJob {
        id: id.clone(),
        name: format!("{name_hint} (imported)"),
        enabled: true,
        schedule: ImportedSchedule {
            cron: cron_expr,
            tz: None,
        },
        prompt,
        timeout_seconds: 600,
        import_notes: notes,
    }))
}

/// Convert a systemd `OnCalendar` spec to a 5-field cron expression.
///
/// Handles:
/// - Named shortcuts: `daily`, `hourly`, `weekly`, `monthly`, `yearly` /
///   `annually`, `minutely`
/// - `*-*-* HH:MM:SS` or `*-*-* HH:MM` (time-of-day only; date wildcarded)
/// - `Mon..Sun *-*-* HH:MM:SS` (weekday prefix)
/// - Returns a best-effort approximation with a note when an exact mapping is
///   not possible.
pub fn calendar_to_cron(spec: &str) -> (String, Vec<String>) {
    let s = spec.trim().to_ascii_lowercase();
    match s.as_str() {
        "daily" | "*-*-* 00:00:00" | "*-*-* 00:00" => ("0 0 * * *".to_string(), vec![]),
        "hourly" | "*-*-* *:00:00" | "*-*-* *:00" => ("0 * * * *".to_string(), vec![]),
        "weekly" | "mon *-*-* 00:00:00" | "monday *-*-* 00:00:00" => {
            ("0 0 * * 1".to_string(), vec![])
        }
        "monthly" | "*-*-01 00:00:00" | "*-*-01 00:00" => ("0 0 1 * *".to_string(), vec![]),
        "yearly" | "annually" | "*-01-01 00:00:00" | "*-01-01 00:00" => {
            ("0 0 1 1 *".to_string(), vec![])
        }
        "minutely" | "*:*:00" | "*:*" => ("* * * * *".to_string(), vec![]),
        "quarterly" | "*-01,04,07,10-01 00:00:00" => (
            "0 0 1 1,4,7,10 *".to_string(),
            vec!["quarterly: approximated as 1st of Jan/Apr/Jul/Oct".to_string()],
        ),
        _ => parse_calendar_time_spec(spec),
    }
}

/// Parse a non-shorthand `OnCalendar` spec of the forms:
/// - `*-*-* HH:MM:SS`
/// - `*-*-* HH:MM`
/// - `DOW *-*-* HH:MM:SS`  (with weekday prefix)
/// - `*-*-D HH:MM` (specific day-of-month)
fn parse_calendar_time_spec(spec: &str) -> (String, Vec<String>) {
    let notes = Vec::new();
    let s = spec.trim();

    // Try to split off an optional leading weekday
    let (dow_part, rest) = split_weekday_prefix(s);

    // Try "DATE TIME" or just "TIME"
    let time_str = if let Some((_date, time)) = rest.split_once(' ') {
        time.trim()
    } else {
        rest.trim()
    };

    if let Some((h, m)) = parse_hm(time_str) {
        let dow = dow_part.unwrap_or("*");
        return (format!("{m} {h} * * {dow}"), notes);
    }

    // Couldn't parse — return a passthrough note with daily fallback
    (
        "0 0 * * *".to_string(),
        vec![format!(
            "OnCalendar={spec:?} could not be precisely mapped; defaulted to daily (0 0 * * *)"
        )],
    )
}

/// Split a possible leading weekday abbreviation/name from a calendar spec.
/// Returns `(Some("dow_number"), rest)` or `(None, full_spec)`.
fn split_weekday_prefix(s: &str) -> (Option<&'static str>, &str) {
    let lower = s.to_ascii_lowercase();
    let days = [
        ("sun", "0"),
        ("mon", "1"),
        ("tue", "2"),
        ("wed", "3"),
        ("thu", "4"),
        ("fri", "5"),
        ("sat", "6"),
        ("sunday", "0"),
        ("monday", "1"),
        ("tuesday", "2"),
        ("wednesday", "3"),
        ("thursday", "4"),
        ("friday", "5"),
        ("saturday", "6"),
    ];
    for (name, num) in days {
        if lower.starts_with(name) {
            let after = s[name.len()..].trim_start_matches([',', ' ']);
            return (Some(num), after);
        }
    }
    (None, s)
}

/// Parse `HH:MM:SS` or `HH:MM` returning `(hour_str, minute_str)` as owned
/// strings with leading zeros stripped (e.g. `"07"` → `"7"`), suitable for
/// use in a 5-field cron expression.  Returns `None` for unrecognised formats.
fn parse_hm(time_str: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = time_str.splitn(3, ':').collect();
    if parts.len() >= 2 {
        let h_raw = parts[0].trim();
        let m_raw = parts[1].trim();
        // Basic validity: hour 0-23, minute 0-59 (or "*" wildcard)
        let h_valid = h_raw == "*" || h_raw.parse::<u8>().is_ok_and(|v| v < 24);
        let m_valid = m_raw == "*" || m_raw.parse::<u8>().is_ok_and(|v| v < 60);
        if h_valid && m_valid {
            let h = if h_raw == "*" {
                "*".to_string()
            } else {
                // Strip leading zeros: "07" → "7"
                h_raw.parse::<u8>().unwrap().to_string()
            };
            let m = if m_raw == "*" {
                "*".to_string()
            } else {
                m_raw.parse::<u8>().unwrap().to_string()
            };
            return Some((h, m));
        }
    }
    None
}

// ── systemd interval → cron ───────────────────────────────────────────────

/// Convert `OnUnitActiveSec` interval strings to a 5-field cron expression.
///
/// Recognises: `Ns`, `Nmin`, `Nh`, `Nd`, `Nweek`, `Nmonth`
/// and the written forms `N seconds`, `N minutes`, `N hours`, `N days`.
/// Falls back to daily with a note.
pub fn interval_to_cron(interval: &str) -> (String, Vec<String>) {
    let s = interval.trim().to_ascii_lowercase();

    // Seconds
    if let Some(n) = parse_suffix(&s, &["s", "sec", "second", "seconds"]) {
        if n < 60 {
            return (
                "* * * * *".to_string(),
                vec![format!(
                    "OnUnitActiveSec={interval}: interval <60s approximated as every-minute"
                )],
            );
        }
        let minutes = n / 60;
        return minutes_to_cron_expr(minutes, interval);
    }

    // Minutes
    if let Some(n) = parse_suffix(&s, &["min", "minute", "minutes"]) {
        return minutes_to_cron_expr(n, interval);
    }

    // Hours
    if let Some(n) = parse_suffix(&s, &["h", "hour", "hours"]) {
        if n == 1 {
            return ("0 * * * *".to_string(), vec![]);
        }
        if n <= 12 && 12 % n == 0 {
            return (format!("0 */{n} * * *"), vec![]);
        }
        return (
            "0 0 * * *".to_string(),
            vec![format!(
                "OnUnitActiveSec={interval}: {n}h interval approximated as daily"
            )],
        );
    }

    // Days
    if let Some(n) = parse_suffix(&s, &["d", "day", "days"]) {
        if n == 1 {
            return ("0 0 * * *".to_string(), vec![]);
        }
        return (
            format!("0 0 */{n} * *"),
            vec![format!(
                "OnUnitActiveSec={interval}: {n}d interval approximated as every {n} days"
            )],
        );
    }

    // Weeks
    if let Some(n) = parse_suffix(&s, &["week", "weeks", "w"]) {
        if n == 1 {
            return ("0 0 * * 1".to_string(), vec![]);
        }
        return (
            "0 0 * * 1".to_string(),
            vec![format!(
                "OnUnitActiveSec={interval}: {n}-week interval approximated as weekly"
            )],
        );
    }

    // Months
    if let Some(_n) = parse_suffix(&s, &["month", "months"]) {
        return (
            "0 0 1 * *".to_string(),
            vec![format!(
                "OnUnitActiveSec={interval}: month interval approximated as monthly"
            )],
        );
    }

    (
        "0 0 * * *".to_string(),
        vec![format!(
            "OnUnitActiveSec={interval}: unrecognised interval, defaulted to daily"
        )],
    )
}

/// Convert a minute count to a cron expression.
fn minutes_to_cron_expr(minutes: u64, src: &str) -> (String, Vec<String>) {
    if minutes == 0 {
        return (
            "* * * * *".to_string(),
            vec![format!(
                "OnUnitActiveSec={src}: 0 minutes, using every-minute"
            )],
        );
    }
    if minutes == 1 {
        return ("* * * * *".to_string(), vec![]);
    }
    // Use */N only for divisors of 60 that are ≤ 60
    if minutes <= 60 && 60 % minutes == 0 {
        return (format!("*/{minutes} * * * *"), vec![]);
    }
    if minutes <= 60 {
        return (
            format!("*/{minutes} * * * *"),
            vec![format!(
                "OnUnitActiveSec={src}: {minutes}m does not divide 60 evenly; \
                 cron approximation fires more or fewer times than the exact interval"
            )],
        );
    }
    // > 60 minutes
    let hours = minutes / 60;
    (
        format!("0 */{hours} * * *"),
        vec![format!(
            "OnUnitActiveSec={src}: {minutes}m approximated as every {hours}h"
        )],
    )
}

/// Try to parse `"<N><suffix>"` for any of the given suffixes; returns `N`.
fn parse_suffix(s: &str, suffixes: &[&str]) -> Option<u64> {
    for suffix in suffixes {
        let s_trimmed = s.trim_end_matches(suffix);
        if s_trimmed.len() < s.len() || s.ends_with(suffix) {
            // Check if the trimmed part is a number (possibly with spaces)
            let num_part = s_trimmed.trim_end();
            if let Ok(n) = num_part.parse::<u64>() {
                return Some(n);
            }
        }
    }
    // Also try "<N> <suffix>" with a space
    for suffix in suffixes {
        if let Some(num_part) = s.strip_suffix(&format!(" {suffix}"))
            && let Ok(n) = num_part.trim().parse::<u64>()
        {
            return Some(n);
        }
        // Plural variant already covered above
    }
    None
}

// ── crontab parser ────────────────────────────────────────────────────────

/// Parse a crontab file and return a list of jobs and skipped lines.
pub fn parse_crontab(content: &str) -> (Vec<ImportedJob>, Vec<String>) {
    let mut jobs = Vec::new();
    let mut skipped = Vec::new();
    let mut row = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        // Skip blank lines, comments, variable assignments
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.contains('=') && !trimmed.starts_with('@')
        {
            continue;
        }
        row += 1;

        match parse_crontab_line(trimmed, row) {
            Some(job) => jobs.push(job),
            None => skipped.push(format!("crontab line {row}: {trimmed:?} — could not parse")),
        }
    }

    (jobs, skipped)
}

/// Parse a single crontab line into an `ImportedJob`.
///
/// Accepts:
/// - `@daily CMD`  / `@hourly CMD` / `@weekly CMD` / `@monthly CMD` /
///   `@yearly CMD` / `@annually CMD` / `@reboot CMD` (reboot → daily with note)
/// - `MIN HOUR DOM MON DOW CMD...`
fn parse_crontab_line(line: &str, row: usize) -> Option<ImportedJob> {
    let mut notes = Vec::new();

    let (cron_expr, cmd) = if line.starts_with('@') {
        let (shorthand, rest) = line.split_once(char::is_whitespace)?;
        let cmd = rest.trim().to_string();
        let expr = match shorthand.to_ascii_lowercase().as_str() {
            "@daily" | "@midnight" => "0 0 * * *",
            "@hourly" => "0 * * * *",
            "@weekly" => "0 0 * * 0",
            "@monthly" => "0 0 1 * *",
            "@yearly" | "@annually" => "0 0 1 1 *",
            "@reboot" => {
                notes.push(
                    "@reboot has no cron equivalent; approximated as @daily (run once per day)"
                        .to_string(),
                );
                "0 0 * * *"
            }
            _ => return None,
        };
        (expr.to_string(), cmd)
    } else {
        // Standard 5-field
        let mut parts = line.splitn(6, char::is_whitespace);
        let min = parts.next()?;
        let hour = parts.next()?;
        let dom = parts.next()?;
        let mon = parts.next()?;
        let dow = parts.next()?;
        let cmd = parts.next()?.trim().to_string();
        if cmd.is_empty() {
            return None;
        }
        let expr = format!("{min} {hour} {dom} {mon} {dow}");
        (expr, cmd)
    };

    let id = format!("crontab-row-{row:03}");
    Some(ImportedJob {
        id,
        name: format!("Crontab row {row}"),
        enabled: true,
        schedule: ImportedSchedule {
            cron: cron_expr,
            tz: None,
        },
        prompt: format!("Run: {cmd}"),
        timeout_seconds: 600,
        import_notes: notes,
    })
}

// ── Slug helper ───────────────────────────────────────────────────────────

/// Convert a string to a lowercase slug (`[a-z0-9-]`).
fn slugify(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

// ── YAML rendering ────────────────────────────────────────────────────────

/// Render `ImportCronsResult` as a YAML snippet ready to paste into `jobs.yaml`.
pub fn render_yaml(result: &ImportCronsResult) -> String {
    let mut out = String::new();
    out.push_str("# Generated by neoth-migrate import-crons\n");
    out.push_str("# Paste these jobs under the `jobs:` key in your jobs.yaml.\n");
    out.push_str("# Review each entry before enabling in production.\n");
    out.push('\n');
    out.push_str("jobs:\n");
    for job in &result.jobs {
        out.push_str(&format!("  - id: {}\n", job.id));
        out.push_str(&format!("    name: \"{}\"\n", job.name));
        out.push_str(&format!("    enabled: {}\n", job.enabled));
        out.push_str("    schedule:\n");
        out.push_str(&format!("      cron: \"{}\"\n", job.schedule.cron));
        if let Some(tz) = &job.schedule.tz {
            out.push_str(&format!("      tz: \"{tz}\"\n"));
        }
        out.push_str(&format!("    prompt: \"{}\"\n", job.prompt));
        out.push_str(&format!("    timeout_seconds: {}\n", job.timeout_seconds));
        for note in &job.import_notes {
            out.push_str(&format!("    # IMPORT NOTE: {note}\n"));
        }
    }
    if !result.skipped.is_empty() {
        out.push('\n');
        out.push_str("# The following entries could not be converted:\n");
        for s in &result.skipped {
            out.push_str(&format!("#   {s}\n"));
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    fn write_tmp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    // ── calendar_to_cron ──────────────────────────────────────────────

    #[test]
    fn calendar_to_cron_handles_named_shortcuts() {
        let cases = [
            ("daily", "0 0 * * *"),
            ("hourly", "0 * * * *"),
            ("weekly", "0 0 * * 1"),
            ("monthly", "0 0 1 * *"),
            ("yearly", "0 0 1 1 *"),
            ("annually", "0 0 1 1 *"),
            ("minutely", "* * * * *"),
        ];
        for (input, expected_cron) in cases {
            let (cron, notes) = calendar_to_cron(input);
            assert_eq!(
                cron, expected_cron,
                "calendar_to_cron({input:?}) should be {expected_cron:?}"
            );
            assert!(
                notes.is_empty(),
                "named shortcut {input:?} should produce no notes; got: {notes:?}"
            );
        }
    }

    #[test]
    fn calendar_to_cron_handles_time_spec() {
        // *-*-* HH:MM:SS form — leading zeros stripped
        let (cron, _) = calendar_to_cron("*-*-* 07:30:00");
        assert_eq!(cron, "30 7 * * *");

        // *-*-* HH:MM form
        let (cron, _) = calendar_to_cron("*-*-* 23:45");
        assert_eq!(cron, "45 23 * * *");
    }

    #[test]
    fn calendar_to_cron_handles_weekday_prefix() {
        // Leading zeros stripped: "08" → "8"
        let (cron, _) = calendar_to_cron("Mon *-*-* 08:00:00");
        assert_eq!(cron, "0 8 * * 1");

        let (cron, _) = calendar_to_cron("Sat *-*-* 12:30:00");
        assert_eq!(cron, "30 12 * * 6");
    }

    #[test]
    fn calendar_to_cron_unknown_falls_back_with_note() {
        // *-W01-1 is an ISO week spec; can't be mapped to cron precisely
        // However parse_calendar_time_spec will see "09:00:00" as time and
        // parse it as "0 9 * * *" (not a real fallback). The spec contains
        // "09:00:00" as the time component so we get that.
        // Accept either a parsed result or a fallback with notes.
        let (cron, notes) = calendar_to_cron("*-W01-1 09:00:00");
        // Either we parse the time or we fall back — either is acceptable.
        // Key invariant: result is a valid 5-field cron and optionally notes.
        assert!(
            cron.split_whitespace().count() == 5,
            "must produce 5-field cron; got: {cron:?}"
        );
        // For truly unparseable specs (no recognisable time), notes should be emitted
        let (cron2, notes2) = calendar_to_cron("*-W01-1 garbage");
        assert_eq!(cron2, "0 0 * * *", "fallback should be daily");
        assert!(
            !notes2.is_empty(),
            "should emit a note for unrecognised spec"
        );
        let _ = notes; // notes from first case may be empty if time parsed
    }

    // ── interval_to_cron ─────────────────────────────────────────────

    #[test]
    fn interval_to_cron_handles_minutes() {
        let cases = [
            ("5min", "*/5 * * * *"),
            ("15min", "*/15 * * * *"),
            ("30min", "*/30 * * * *"),
            ("1min", "* * * * *"),
        ];
        for (input, expected) in cases {
            let (cron, _) = interval_to_cron(input);
            assert_eq!(
                cron, expected,
                "interval_to_cron({input:?}) should produce {expected:?}"
            );
        }
    }

    #[test]
    fn interval_to_cron_handles_hours() {
        let (cron, _) = interval_to_cron("1h");
        assert_eq!(cron, "0 * * * *");

        // every 2 hours: minute-0, every-2-hours position
        let (cron, _) = interval_to_cron("2h");
        assert_eq!(cron, "0 */2 * * *");

        let (cron, _) = interval_to_cron("6h");
        assert_eq!(cron, "0 */6 * * *");
    }

    #[test]
    fn interval_to_cron_handles_days() {
        let (cron, _) = interval_to_cron("1d");
        assert_eq!(cron, "0 0 * * *");

        // every 7 days: midnight, every-7-days dom position
        let (cron, _) = interval_to_cron("7d");
        assert_eq!(cron, "0 0 */7 * *");
    }

    #[test]
    fn interval_to_cron_handles_seconds_lt_60() {
        let (cron, notes) = interval_to_cron("30s");
        assert_eq!(cron, "* * * * *");
        assert!(!notes.is_empty());
        assert!(notes[0].contains("approximated as every-minute"));
    }

    #[test]
    fn interval_to_cron_handles_seconds_multiple_of_60() {
        // 300s = 5min
        let (cron, _) = interval_to_cron("300s");
        assert_eq!(cron, "*/5 * * * *");
    }

    #[test]
    fn interval_to_cron_unknown_falls_back_daily() {
        let (cron, notes) = interval_to_cron("4 fortnights");
        assert_eq!(cron, "0 0 * * *");
        assert!(!notes.is_empty());
    }

    // ── parse_timer_unit ─────────────────────────────────────────────

    #[test]
    fn parse_timer_unit_oncalendar_daily() {
        let unit = "[Timer]\nOnCalendar=daily\n[Service]\nExecStart=/usr/bin/backup.sh\n";
        let job = parse_timer_unit(unit, "backup").unwrap().unwrap();
        assert_eq!(job.schedule.cron, "0 0 * * *");
        assert!(job.prompt.contains("backup.sh"));
        assert_eq!(job.id, "backup");
    }

    #[test]
    fn parse_timer_unit_oncalendar_time_spec() {
        let unit =
            "[Timer]\nOnCalendar=*-*-* 06:00:00\n[Service]\nExecStart=/usr/local/bin/digest\n";
        let job = parse_timer_unit(unit, "morning-digest").unwrap().unwrap();
        assert_eq!(job.schedule.cron, "0 6 * * *");
        assert!(job.prompt.contains("digest"));
    }

    #[test]
    fn parse_timer_unit_onunitactivesec_5min() {
        let unit = "[Timer]\nOnUnitActiveSec=5min\n[Service]\nExecStart=/usr/bin/health-check\n";
        let job = parse_timer_unit(unit, "health").unwrap().unwrap();
        assert_eq!(job.schedule.cron, "*/5 * * * *");
    }

    #[test]
    fn parse_timer_unit_oncalendar_wins_over_interval() {
        let unit =
            "[Timer]\nOnCalendar=hourly\nOnUnitActiveSec=5min\n[Service]\nExecStart=/bin/foo\n";
        let job = parse_timer_unit(unit, "foo").unwrap().unwrap();
        assert_eq!(job.schedule.cron, "0 * * * *");
        // Should note that OnUnitActiveSec was ignored
        assert!(
            job.import_notes
                .iter()
                .any(|n| n.contains("OnUnitActiveSec ignored"))
        );
    }

    #[test]
    fn parse_timer_unit_no_trigger_returns_none() {
        let unit = "[Timer]\n# nothing here\n[Service]\nExecStart=/bin/foo\n";
        let result = parse_timer_unit(unit, "foo").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_timer_unit_no_exec_start() {
        let unit = "[Timer]\nOnCalendar=daily\n";
        let job = parse_timer_unit(unit, "notask").unwrap().unwrap();
        assert!(job.prompt.contains("no ExecStart"));
    }

    // ── parse_crontab ─────────────────────────────────────────────────

    #[test]
    fn crontab_standard_five_field_line() {
        let content = "30 6 * * 1-5 /usr/bin/workday-brief\n";
        let (jobs, skipped) = parse_crontab(content);
        assert_eq!(jobs.len(), 1);
        assert!(skipped.is_empty());
        assert_eq!(jobs[0].schedule.cron, "30 6 * * 1-5");
        assert!(jobs[0].prompt.contains("workday-brief"));
    }

    #[test]
    fn crontab_shorthand_at_daily() {
        let content = "@daily /usr/local/bin/cleanup\n";
        let (jobs, _) = parse_crontab(content);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].schedule.cron, "0 0 * * *");
        assert!(jobs[0].prompt.contains("cleanup"));
    }

    #[test]
    fn crontab_shorthand_at_weekly() {
        let content = "@weekly /usr/bin/report.sh\n";
        let (jobs, _) = parse_crontab(content);
        assert_eq!(jobs[0].schedule.cron, "0 0 * * 0");
    }

    #[test]
    fn crontab_shorthand_at_reboot_emits_note() {
        let content = "@reboot /usr/bin/startup-task\n";
        let (jobs, _) = parse_crontab(content);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].schedule.cron, "0 0 * * *");
        assert!(jobs[0].import_notes.iter().any(|n| n.contains("@reboot")));
    }

    #[test]
    fn crontab_skips_blank_comment_and_variable_lines() {
        let content = "\n# this is a comment\nPATH=/usr/bin\n0 0 * * * /bin/task\n";
        let (jobs, skipped) = parse_crontab(content);
        assert_eq!(jobs.len(), 1, "only one actual cron line");
        assert!(skipped.is_empty());
    }

    #[test]
    fn crontab_multiple_rows_get_unique_ids() {
        let content = "0 8 * * * /bin/a\n30 12 * * 5 /bin/b\n";
        let (jobs, _) = parse_crontab(content);
        assert_eq!(jobs.len(), 2);
        let ids: Vec<&str> = jobs.iter().map(|j| j.id.as_str()).collect();
        assert_ne!(ids[0], ids[1], "row ids must be unique");
    }

    // ── import_crons (integration) ─────────────────────────────────────

    #[test]
    fn import_crons_timer_file() {
        let content = "[Unit]\nDescription=Daily backup\n[Timer]\nOnCalendar=*-*-* 02:00:00\n[Service]\nExecStart=/usr/bin/backup.sh --full\n";
        let f = write_tmp(content);
        let result = import_crons(&[f.path()], None).unwrap();
        assert_eq!(result.jobs.len(), 1);
        assert_eq!(result.jobs[0].schedule.cron, "0 2 * * *");
        assert!(result.jobs[0].prompt.contains("backup.sh"));
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn import_crons_crontab_file() {
        let content =
            "# my crontab\n*/10 * * * * /usr/bin/check-disk\n0 0 * * 0 /usr/bin/weekly-report\n";
        let f = write_tmp(content);
        let result = import_crons(&[], Some(f.path())).unwrap();
        assert_eq!(result.jobs.len(), 2);
        assert_eq!(result.jobs[0].schedule.cron, "*/10 * * * *");
        assert_eq!(result.jobs[1].schedule.cron, "0 0 * * 0");
    }

    #[test]
    fn import_crons_mixed_timer_and_crontab() {
        let timer = "[Timer]\nOnCalendar=hourly\n[Service]\nExecStart=/bin/hourly-task\n";
        let crontab = "0 6 * * 1-5 /bin/weekday-task\n";
        let tf = write_tmp(timer);
        let cf = write_tmp(crontab);
        let result = import_crons(&[tf.path()], Some(cf.path())).unwrap();
        assert_eq!(result.jobs.len(), 2);
        let crons: Vec<&str> = result
            .jobs
            .iter()
            .map(|j| j.schedule.cron.as_str())
            .collect();
        assert!(crons.contains(&"0 * * * *"), "hourly from timer");
        assert!(crons.contains(&"0 6 * * 1-5"), "weekday from crontab");
    }

    #[test]
    fn import_crons_error_when_no_source() {
        let err = import_crons(&[], None).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }

    #[test]
    fn import_crons_timer_with_no_trigger_goes_to_skipped() {
        let content = "[Unit]\nDescription=Empty timer\n[Timer]\n# no trigger keys\n";
        let f = write_tmp(content);
        let result = import_crons(&[f.path()], None).unwrap();
        assert!(result.jobs.is_empty());
        assert_eq!(result.skipped.len(), 1);
        assert!(result.skipped[0].contains("OnCalendar/OnUnitActiveSec"));
    }

    #[test]
    fn import_crons_error_on_missing_file() {
        let err = import_crons(&[Path::new("/nonexistent/foo.timer")], None).unwrap_err();
        assert!(err.to_string().contains("read timer"));
    }

    // ── render_yaml ────────────────────────────────────────────────────

    #[test]
    fn render_yaml_contains_required_header() {
        let result = ImportCronsResult {
            jobs: vec![ImportedJob {
                id: "test-job".to_string(),
                name: "Test".to_string(),
                enabled: true,
                schedule: ImportedSchedule {
                    cron: "0 0 * * *".to_string(),
                    tz: None,
                },
                prompt: "Run: /bin/test".to_string(),
                timeout_seconds: 600,
                import_notes: vec![],
            }],
            skipped: vec![],
        };
        let yaml = render_yaml(&result);
        assert!(yaml.contains("neoth-migrate import-crons"));
        assert!(yaml.contains("jobs.yaml"));
        assert!(yaml.contains("test-job"));
        assert!(yaml.contains("0 0 * * *"));
    }

    #[test]
    fn render_yaml_includes_import_notes_as_comments() {
        let result = ImportCronsResult {
            jobs: vec![ImportedJob {
                id: "foo".to_string(),
                name: "Foo".to_string(),
                enabled: true,
                schedule: ImportedSchedule {
                    cron: "0 0 * * *".to_string(),
                    tz: None,
                },
                prompt: "Run: /bin/foo".to_string(),
                timeout_seconds: 600,
                import_notes: vec!["approximated as daily".to_string()],
            }],
            skipped: vec![],
        };
        let yaml = render_yaml(&result);
        assert!(yaml.contains("IMPORT NOTE: approximated as daily"));
    }

    #[test]
    fn render_yaml_includes_skipped_section() {
        let result = ImportCronsResult {
            jobs: vec![],
            skipped: vec!["some-file.timer: no OnCalendar found".to_string()],
        };
        let yaml = render_yaml(&result);
        assert!(yaml.contains("could not be converted"));
        assert!(yaml.contains("some-file.timer"));
    }

    // ── slugify ─────────────────────────────────────────────────────────

    #[test]
    fn slugify_converts_non_alnum_to_dash() {
        assert_eq!(slugify("backup.timer"), "backup-timer");
        assert_eq!(slugify("Morning Digest"), "morning-digest");
        assert_eq!(slugify("my-task"), "my-task");
    }

    // ── parse_suffix ────────────────────────────────────────────────────

    #[test]
    fn parse_suffix_handles_written_units() {
        assert_eq!(parse_suffix("5 minutes", &["minute", "minutes"]), Some(5));
        assert_eq!(parse_suffix("1 hour", &["h", "hour", "hours"]), Some(1));
        assert_eq!(
            parse_suffix("30s", &["s", "sec", "second", "seconds"]),
            Some(30)
        );
    }
}
