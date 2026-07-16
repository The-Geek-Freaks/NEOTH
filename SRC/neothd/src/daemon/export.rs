//! Operator data export — Phase 33c BS-8.
//!
//! GDPR right-to-export: produce a portable dump of everything NEOTH
//! knows about the operator, in formats the operator can read without
//! NEOTH.
//!
//! ## Scope
//!
//! - **episodic** (`idx_episode`)   — every RAW_TEXT + channel I/O frame
//! - **consolidated** (`idx_consolidated`)
//! - **long-term** (`idx_longterm`)
//! - **ground truth** (`idx_groundtruth`, including revoked rows for
//!   audit completeness)
//! - **communication profile** — canonical typed operator-subject state, or
//!   one explicitly selected channel subject in communication-only DSAR mode
//! - **archive sessions** — copied verbatim into the export bundle
//!
//! ## Formats
//!
//! - `jsonl` (default) — one event per line, machine-readable, pipes
//!   cleanly into `jq` or a re-importer.
//! - `md`              — markdown digest, organised by day. Human-readable;
//!   not a roundtrip target.
//!
//! Date filter `--since YYYY-MM-DD` narrows the export to events at or
//! after that day. Useful for incremental exports.
//!
//! Pure read — `neoth export` does not mutate any view, does not write
//! the WAL, does not call providers. Normal operator export never enumerates
//! or bulk-serializes other channel subjects.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rusqlite::Connection;
use serde::Serialize;

use crate::config::FreedomConfig;
use crate::memory::store;

pub(crate) const OPERATOR_COMMUNICATION_SUBJECT: &str = "operator";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    Jsonl,
    Md,
}

impl ExportFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "jsonl" => Some(ExportFormat::Jsonl),
            "md" => Some(ExportFormat::Md),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ExportSummary {
    pub episode_rows: usize,
    pub consolidated_rows: usize,
    pub longterm_rows: usize,
    pub groundtruth_rows: usize,
    pub communication_profile_export_schema_version: u32,
    pub communication_profile_state_present: bool,
    pub communication_profile_state_schema_version: Option<u32>,
    pub communication_profile_subjects: usize,
    pub communication_profile_dimensions: usize,
    pub communication_profile_evidence_records: usize,
    pub communication_profile_declared_context_records: usize,
    pub communication_profile_subject_sha256: String,
    pub communication_profile_operator_subject: bool,
    pub communication_profile_only: bool,
    pub archive_files_copied: usize,
    pub output_dir: String,
}

#[derive(Serialize)]
struct CommunicationProfileExport<'a> {
    export_schema_version: u32,
    state_present: bool,
    state_schema_version: Option<u32>,
    subject_sha256: String,
    operator_subject: bool,
    subject_present: bool,
    since_filter_applied: bool,
    typed_subject: Option<&'a crate::profile::communication::SubjectCommunicationProfile>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CommunicationProfileExportCounts {
    state_present: bool,
    state_schema_version: Option<u32>,
    subjects: usize,
    dimensions: usize,
    evidence_records: usize,
    declared_context_records: usize,
    subject_sha256: String,
    operator_subject: bool,
}

/// One opaque, pseudonymous selector returned only by the explicit inventory
/// command. Normal operator exports never enumerate these handles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommunicationProfileSubjectInventory {
    pub subject_handle: String,
    pub subject_sha256: String,
    pub operator_subject: bool,
    pub dimensions: usize,
    pub evidence_records: usize,
    pub declared_context_records: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommunicationProfileInventory {
    pub state_present: bool,
    pub state_schema_version: Option<u32>,
    pub subjects: Vec<CommunicationProfileSubjectInventory>,
}

/// One row from `idx_episode` in the export bundle.
#[derive(Serialize)]
struct ExportEpisode {
    table: &'static str,
    event_id: i64,
    event_type: i64,
    ts_ns: i64,
    text: String,
    text_hash: String,
    channel: Option<String>,
    sender_id: Option<String>,
    importance: f64,
    last_access_ts: i64,
}

#[derive(Serialize)]
struct ExportConsolidated {
    table: &'static str,
    id: i64,
    kind: String,
    day: String,
    event_id: Option<i64>,
    text: String,
    importance: f64,
    consolidated_ts: i64,
}

#[derive(Serialize)]
struct ExportLongterm {
    table: &'static str,
    id: i64,
    event_id: i64,
    text: String,
    importance: f64,
    promoted_ts: i64,
}

#[derive(Serialize)]
struct ExportGroundtruth {
    table: &'static str,
    id: i64,
    statement: String,
    source: String,
    scope: String,
    asserted_at: i64,
    revoked_at: Option<i64>,
}

/// Run a full export. `since_unix_ns` is `0` to dump everything.
pub fn run_export(
    home: &Path,
    output_dir: &Path,
    format: ExportFormat,
    since_unix_ns: i64,
) -> Result<ExportSummary> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("create export dir {}", output_dir.display()))?;

    let db = home.join("views.db");
    let mut summary = ExportSummary {
        output_dir: output_dir.display().to_string(),
        ..Default::default()
    };

    if db.exists() {
        let conn = store::open(&db)?;
        match format {
            ExportFormat::Jsonl => {
                summary.episode_rows = export_episodes_jsonl(&conn, output_dir, since_unix_ns)?;
                summary.consolidated_rows =
                    export_consolidated_jsonl(&conn, output_dir, since_unix_ns)?;
                summary.longterm_rows = export_longterm_jsonl(&conn, output_dir, since_unix_ns)?;
                summary.groundtruth_rows = export_groundtruth_jsonl(&conn, output_dir)?;
            }
            ExportFormat::Md => {
                summary.episode_rows = export_episodes_md(&conn, output_dir, since_unix_ns)?;
                summary.groundtruth_rows = export_groundtruth_md(&conn, output_dir)?;
            }
        }
    }

    let communication =
        export_communication_profile(home, output_dir, OPERATOR_COMMUNICATION_SUBJECT, false)?;
    apply_communication_summary(&mut summary, communication);

    let archive_src = home.join("archive").join("sessions");
    if archive_src.exists() {
        let archive_dst = output_dir.join("archive").join("sessions");
        summary.archive_files_copied = copy_archive(&archive_src, &archive_dst)?;
    }

    Ok(summary)
}

/// Export exactly one explicitly selected communication-profile subject.
///
/// This intentionally omits every memory table and archived session: those
/// stores are operator-wide and cannot be safely attributed to one channel
/// subject. The output directory must be empty so stale files cannot leak into
/// a data-subject bundle.
pub fn run_communication_subject_export(
    home: &Path,
    output_dir: &Path,
    subject_id: &str,
) -> Result<ExportSummary> {
    validate_communication_subject_selector(subject_id)?;
    ensure_empty_subject_export_dir(output_dir)?;

    let communication = export_communication_profile(home, output_dir, subject_id, true)?;
    let mut summary = ExportSummary {
        communication_profile_only: true,
        output_dir: output_dir.display().to_string(),
        ..Default::default()
    };
    apply_communication_summary(&mut summary, communication);
    Ok(summary)
}

fn ensure_empty_subject_export_dir(output_dir: &Path) -> Result<()> {
    match std::fs::read_dir(output_dir) {
        Ok(mut entries) => {
            if entries.next().transpose()?.is_some() {
                bail!(
                    "communication-subject export requires an empty output directory to prevent cross-subject data leakage"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(output_dir)
                .with_context(|| format!("create export dir {}", output_dir.display()))?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect export dir {}", output_dir.display()));
        }
    }
    Ok(())
}

fn apply_communication_summary(
    summary: &mut ExportSummary,
    communication: CommunicationProfileExportCounts,
) {
    summary.communication_profile_export_schema_version = 1;
    summary.communication_profile_state_present = communication.state_present;
    summary.communication_profile_state_schema_version = communication.state_schema_version;
    summary.communication_profile_subjects = communication.subjects;
    summary.communication_profile_dimensions = communication.dimensions;
    summary.communication_profile_evidence_records = communication.evidence_records;
    summary.communication_profile_declared_context_records = communication.declared_context_records;
    summary.communication_profile_subject_sha256 = communication.subject_sha256;
    summary.communication_profile_operator_subject = communication.operator_subject;
}

fn export_communication_profile(
    home: &Path,
    output_dir: &Path,
    subject_id: &str,
    require_subject: bool,
) -> Result<CommunicationProfileExportCounts> {
    const EXPORT_SCHEMA_VERSION: u32 = 1;

    validate_communication_subject_selector(subject_id)?;

    let state_path = crate::profile::communication::state_path(home);
    let state_present = state_path
        .try_exists()
        .with_context(|| format!("inspect communication profile at {}", state_path.display()))?;
    let state = crate::profile::communication::load_state(home).with_context(|| {
        format!(
            "strictly load communication profile for export from {}",
            state_path.display()
        )
    })?;
    let subject = state.subjects.get(subject_id);
    if require_subject && subject.is_none() {
        bail!(
            "selected communication-profile subject was not found; selectors are exact and case-sensitive"
        );
    }
    let (dimensions, evidence_records, declared_context_records) = subject
        .map(communication_profile_counts)
        .unwrap_or_default();
    let body = serde_json::to_vec_pretty(&CommunicationProfileExport {
        export_schema_version: EXPORT_SCHEMA_VERSION,
        state_present,
        state_schema_version: state_present.then_some(state.schema_version),
        subject_sha256: communication_subject_sha256(subject_id),
        operator_subject: subject_id == OPERATOR_COMMUNICATION_SUBJECT,
        subject_present: subject.is_some(),
        // Communication preferences are current state, not event rows; a
        // date filter cannot safely carve evidence out without recomputing it.
        since_filter_applied: false,
        typed_subject: subject,
    })
    .context("serialize typed communication profile export")?;
    let output = output_dir.join("communication_profile.json");
    crate::util::atomic_write::atomic_write_private(&output, &body)
        .with_context(|| format!("write communication profile export {}", output.display()))?;

    Ok(CommunicationProfileExportCounts {
        state_present,
        state_schema_version: state_present.then_some(state.schema_version),
        subjects: usize::from(subject.is_some()),
        dimensions,
        evidence_records,
        declared_context_records,
        subject_sha256: communication_subject_sha256(subject_id),
        operator_subject: subject_id == OPERATOR_COMMUNICATION_SUBJECT,
    })
}

fn communication_profile_counts(
    subject: &crate::profile::communication::SubjectCommunicationProfile,
) -> (usize, usize, usize) {
    let dimensions = subject
        .evidence
        .keys()
        .chain(subject.estimates.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let evidence_records = subject.evidence.values().map(Vec::len).sum();
    let declared_context_records = usize::from(subject.declared_context.is_some());
    (dimensions, evidence_records, declared_context_records)
}

pub(crate) fn validate_communication_subject_selector(subject_id: &str) -> Result<()> {
    if subject_id.is_empty()
        || subject_id.trim() != subject_id
        || subject_id.len() > 256
        || subject_id.chars().any(char::is_control)
    {
        bail!("invalid communication-profile subject selector");
    }
    Ok(())
}

pub(crate) fn communication_subject_sha256(subject_id: &str) -> String {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"neoth.communication.audit-subject.v1\0");
    hasher.update(subject_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// Strict, read-only inventory used to obtain exact pseudonymous handles for
/// an explicit data-subject export or erasure. This is never called by normal
/// operator export.
pub fn communication_profile_inventory(home: &Path) -> Result<CommunicationProfileInventory> {
    let state_path = crate::profile::communication::state_path(home);
    let state_present = state_path
        .try_exists()
        .with_context(|| format!("inspect communication profile at {}", state_path.display()))?;
    let state = crate::profile::communication::load_state(home).with_context(|| {
        format!(
            "strictly load communication profile inventory from {}",
            state_path.display()
        )
    })?;
    let subjects = state
        .subjects
        .iter()
        .map(|(subject_id, subject)| {
            let (dimensions, evidence_records, declared_context_records) =
                communication_profile_counts(subject);
            CommunicationProfileSubjectInventory {
                subject_handle: subject_id.clone(),
                subject_sha256: communication_subject_sha256(subject_id),
                operator_subject: subject_id == OPERATOR_COMMUNICATION_SUBJECT,
                dimensions,
                evidence_records,
                declared_context_records,
            }
        })
        .collect();
    Ok(CommunicationProfileInventory {
        state_present,
        state_schema_version: state_present.then_some(state.schema_version),
        subjects,
    })
}

fn export_episodes_jsonl(conn: &Connection, dir: &Path, since: i64) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT event_id, event_type, ts_ns, text, text_hash, channel, sender_id, \
                importance, last_access_ts \
         FROM idx_episode \
         WHERE ts_ns >= ?1 \
         ORDER BY ts_ns ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![since], |r| {
            Ok(ExportEpisode {
                table: "idx_episode",
                event_id: r.get(0)?,
                event_type: r.get(1)?,
                ts_ns: r.get(2)?,
                text: r.get(3)?,
                text_hash: r.get(4)?,
                channel: r.get(5)?,
                sender_id: r.get(6)?,
                importance: r.get(7)?,
                last_access_ts: r.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let path = dir.join("idx_episode.jsonl");
    write_jsonl(&path, rows.iter())?;
    Ok(rows.len())
}

fn export_consolidated_jsonl(conn: &Connection, dir: &Path, since: i64) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, day, event_id, text, importance, consolidated_ts \
         FROM idx_consolidated \
         WHERE consolidated_ts >= ?1 \
         ORDER BY consolidated_ts ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![since], |r| {
            Ok(ExportConsolidated {
                table: "idx_consolidated",
                id: r.get(0)?,
                kind: r.get(1)?,
                day: r.get(2)?,
                event_id: r.get(3)?,
                text: r.get(4)?,
                importance: r.get(5)?,
                consolidated_ts: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let path = dir.join("idx_consolidated.jsonl");
    write_jsonl(&path, rows.iter())?;
    Ok(rows.len())
}

fn export_longterm_jsonl(conn: &Connection, dir: &Path, since: i64) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT id, event_id, text, importance, promoted_ts \
         FROM idx_longterm \
         WHERE promoted_ts >= ?1 \
         ORDER BY promoted_ts ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![since], |r| {
            Ok(ExportLongterm {
                table: "idx_longterm",
                id: r.get(0)?,
                event_id: r.get(1)?,
                text: r.get(2)?,
                importance: r.get(3)?,
                promoted_ts: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let path = dir.join("idx_longterm.jsonl");
    write_jsonl(&path, rows.iter())?;
    Ok(rows.len())
}

fn export_groundtruth_jsonl(conn: &Connection, dir: &Path) -> Result<usize> {
    let mut stmt = conn.prepare(
        "SELECT id, statement, source, scope, asserted_at, revoked_at \
         FROM idx_groundtruth \
         ORDER BY asserted_at ASC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(ExportGroundtruth {
                table: "idx_groundtruth",
                id: r.get(0)?,
                statement: r.get(1)?,
                source: r.get(2)?,
                scope: r.get(3)?,
                asserted_at: r.get(4)?,
                revoked_at: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let path = dir.join("idx_groundtruth.jsonl");
    write_jsonl(&path, rows.iter())?;
    Ok(rows.len())
}

fn export_episodes_md(conn: &Connection, dir: &Path, since: i64) -> Result<usize> {
    use std::io::Write as _;
    let mut stmt = conn.prepare(
        "SELECT event_id, ts_ns, text, channel \
         FROM idx_episode \
         WHERE ts_ns >= ?1 \
         ORDER BY ts_ns ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![since], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let path = dir.join("episodes.md");
    let mut f =
        std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
    writeln!(f, "# NEOTH episode export\n")?;
    let mut current_day = String::new();
    for (event_id, ts_ns, text, channel) in &rows {
        let day = format_day(*ts_ns);
        if day != current_day {
            writeln!(f, "\n## {day}\n")?;
            current_day = day;
        }
        let chan = channel.as_deref().unwrap_or("-");
        writeln!(
            f,
            "- `{event_id:>8}` [{chan}] {}",
            text.replace('\n', " ")
                .chars()
                .take(200)
                .collect::<String>(),
        )?;
    }
    Ok(rows.len())
}

fn export_groundtruth_md(conn: &Connection, dir: &Path) -> Result<usize> {
    use std::io::Write as _;
    let mut stmt = conn.prepare(
        "SELECT id, statement, source, scope, asserted_at, revoked_at \
         FROM idx_groundtruth \
         ORDER BY scope, asserted_at",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<i64>>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let path = dir.join("groundtruth.md");
    let mut f =
        std::fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
    writeln!(f, "# NEOTH ground-truth export\n")?;
    let mut current_scope = String::new();
    for (id, statement, source, scope, _asserted, revoked) in &rows {
        if scope != &current_scope {
            writeln!(f, "\n## scope = `{scope}`\n")?;
            current_scope = scope.clone();
        }
        let status = if revoked.is_some() { "~~revoked~~" } else { "" };
        writeln!(f, "- `{id:>4}` [{source}] {statement} {status}")?;
    }
    Ok(rows.len())
}

fn write_jsonl<T: Serialize>(path: &Path, rows: impl Iterator<Item = T>) -> Result<()> {
    use std::io::Write as _;
    let mut f =
        std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    for row in rows {
        let line = serde_json::to_string(&row).context("serialize export row")?;
        writeln!(f, "{line}").with_context(|| format!("write to {}", path.display()))?;
    }
    Ok(())
}

fn copy_archive(src: &Path, dst: &Path) -> Result<usize> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("create archive export dir {}", dst.display()))?;
    let mut count = 0usize;
    fn copy_recursive(from: &Path, to: &Path, count: &mut usize) -> Result<()> {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = to.join(entry.file_name());
            if src_path.is_dir() {
                copy_recursive(&src_path, &dst_path, count)?;
            } else {
                std::fs::copy(&src_path, &dst_path)?;
                *count += 1;
            }
        }
        Ok(())
    }
    copy_recursive(src, dst, &mut count)?;
    Ok(count)
}

fn format_day(ts_ns: i64) -> String {
    use chrono::{DateTime, Utc};
    let secs = ts_ns / 1_000_000_000;
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "1970-01-01".into())
}

/// Parse a `YYYY-MM-DD` date string into a unix-nanosecond floor. Returns
/// `Ok(0)` when `since` is `None` (export everything).
pub fn parse_since(since: Option<&str>) -> Result<i64> {
    let Some(s) = since else {
        return Ok(0);
    };
    let day = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .with_context(|| format!("parse --since '{s}' as YYYY-MM-DD"))?;
    let dt = day
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| anyhow::anyhow!("bad date {s}"))?
        .and_utc();
    Ok(dt.timestamp_nanos_opt().unwrap_or(0))
}

/// Default export destination: `~/.neoth/exports/neoth-export-<UTC>/`.
pub fn default_export_dir() -> PathBuf {
    let stamp = crate::time::utc_now().format("%Y%m%d-%H%M%S");
    FreedomConfig::default_neoth_home()
        .join("exports")
        .join(format!("neoth-export-{stamp}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use tempfile::tempdir;

    fn seed(db: &Path) {
        let conn = store::open(db).unwrap();
        // SQLite literal numerics don't allow Rust's `_` digit separators —
        // pass through params instead so the test stays readable AND parses.
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, ?1, 'hello', 'h', 0.5, 0)",
            params![1_700_000_000_000_000_000_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (2, 1, ?1, 'world', 'h', 0.7, 0)",
            params![1_700_100_000_000_000_000_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth \
             (statement, source, scope, asserted_at, revoked_at) \
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                "sam is the operator",
                "onboarding",
                "global",
                1_700_000_000_000_000_000_i64
            ],
        )
        .unwrap();
    }

    #[test]
    fn parse_since_accepts_yyyy_mm_dd() {
        let ns = parse_since(Some("2026-05-14")).unwrap();
        assert!(ns > 0);
        assert_eq!(parse_since(None).unwrap(), 0);
    }

    #[test]
    fn parse_since_rejects_garbage() {
        assert!(parse_since(Some("not-a-date")).is_err());
    }

    #[test]
    fn jsonl_export_writes_one_line_per_row() {
        let home = tempdir().unwrap();
        let out = tempdir().unwrap();
        seed(&home.path().join("views.db"));

        let s = run_export(home.path(), out.path(), ExportFormat::Jsonl, 0).unwrap();
        assert_eq!(s.episode_rows, 2);
        assert_eq!(s.groundtruth_rows, 1);

        let body = std::fs::read_to_string(out.path().join("idx_episode.jsonl")).unwrap();
        assert_eq!(body.lines().count(), 2);
        for line in body.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["table"], "idx_episode");
        }
    }

    #[test]
    fn jsonl_export_respects_since_filter() {
        let home = tempdir().unwrap();
        let out = tempdir().unwrap();
        seed(&home.path().join("views.db"));

        // Filter to events at-or-after the SECOND seed row.
        let s = run_export(
            home.path(),
            out.path(),
            ExportFormat::Jsonl,
            1_700_100_000_000_000_000,
        )
        .unwrap();
        assert_eq!(s.episode_rows, 1);
        let body = std::fs::read_to_string(out.path().join("idx_episode.jsonl")).unwrap();
        assert!(body.contains("world"));
        assert!(!body.contains("hello"));
    }

    #[test]
    fn md_export_groups_by_day() {
        let home = tempdir().unwrap();
        let out = tempdir().unwrap();
        seed(&home.path().join("views.db"));

        let s = run_export(home.path(), out.path(), ExportFormat::Md, 0).unwrap();
        assert_eq!(s.episode_rows, 2);
        let body = std::fs::read_to_string(out.path().join("episodes.md")).unwrap();
        assert!(body.contains("# NEOTH episode export"));
        assert!(body.contains("## 2023-11-14")); // 1_700_000_000 → 2023-11-14
        assert!(body.contains("hello"));
        let gt = std::fs::read_to_string(out.path().join("groundtruth.md")).unwrap();
        assert!(gt.contains("sam is the operator"));
        assert!(gt.contains("scope = `global`"));
    }

    #[test]
    fn empty_home_returns_zero_counts() {
        let home = tempdir().unwrap();
        let out = tempdir().unwrap();
        let s = run_export(home.path(), out.path(), ExportFormat::Jsonl, 0).unwrap();
        assert_eq!(s.episode_rows, 0);
        assert_eq!(s.communication_profile_export_schema_version, 1);
        assert!(!s.communication_profile_state_present);
        assert_eq!(s.communication_profile_state_schema_version, None);
        assert_eq!(s.communication_profile_subjects, 0);
        assert_eq!(s.communication_profile_dimensions, 0);
        let communication =
            std::fs::read_to_string(out.path().join("communication_profile.json")).unwrap();
        let communication: serde_json::Value = serde_json::from_str(&communication).unwrap();
        assert_eq!(communication["export_schema_version"], 1);
        assert_eq!(communication["state_present"], false);
        assert_eq!(communication["operator_subject"], true);
        assert_eq!(
            communication["subject_sha256"],
            communication_subject_sha256(OPERATOR_COMMUNICATION_SUBJECT)
        );
        assert_eq!(communication["subject_present"], false);
        assert!(communication["typed_subject"].is_null());
        assert_eq!(s.archive_files_copied, 0);
    }

    #[test]
    fn communication_export_is_typed_and_operator_subject_scoped() {
        use crate::profile::communication::{
            CommunicationScope, DirectnessPreference, PreferenceValue,
        };

        let home = tempdir().unwrap();
        let out = tempdir().unwrap();
        let policy = crate::config::CommunicationProfileConfig::default();
        crate::profile::communication::set_explicit_preference(
            home.path(),
            &policy,
            "operator",
            "operator-session",
            PreferenceValue::Directness(DirectnessPreference::Direct),
            [1; 32],
            1_700_000_000,
            CommunicationScope::Global,
            false,
        )
        .unwrap();
        crate::profile::communication::set_explicit_preference(
            home.path(),
            &policy,
            "other-human",
            "other-session",
            PreferenceValue::Directness(DirectnessPreference::Gentle),
            [2; 32],
            1_700_000_001,
            CommunicationScope::Global,
            false,
        )
        .unwrap();

        let summary = run_export(home.path(), out.path(), ExportFormat::Md, 0).unwrap();
        assert!(summary.communication_profile_state_present);
        assert_eq!(summary.communication_profile_state_schema_version, Some(1));
        assert_eq!(summary.communication_profile_subjects, 1);
        assert_eq!(summary.communication_profile_dimensions, 1);
        assert_eq!(summary.communication_profile_evidence_records, 1);
        assert_eq!(summary.communication_profile_declared_context_records, 0);

        let body = std::fs::read_to_string(out.path().join("communication_profile.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["state_present"], true);
        assert_eq!(value["state_schema_version"], 1);
        assert_eq!(value["operator_subject"], true);
        assert_eq!(
            value["subject_sha256"],
            communication_subject_sha256(OPERATOR_COMMUNICATION_SUBJECT)
        );
        assert_eq!(value["subject_present"], true);
        assert_eq!(value["since_filter_applied"], false);
        assert_eq!(value["typed_subject"]["revision"], 1);
        assert!(body.contains("operator-session"));
        assert!(!body.contains("other-human"));
        assert!(!body.contains("other-session"));
        assert!(!body.contains("gentle"));

        let inventory = communication_profile_inventory(home.path()).unwrap();
        assert!(inventory.state_present);
        assert_eq!(inventory.subjects.len(), 2);
        assert_eq!(inventory.subjects[0].subject_handle, "operator");
        assert_eq!(inventory.subjects[1].subject_handle, "other-human");
        assert!(inventory.subjects[0].operator_subject);
        assert!(!inventory.subjects[1].operator_subject);

        seed(&home.path().join("views.db"));
        let archive = home.path().join("archive/sessions/2026-05-14");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::write(archive.join("private-operator-session.md"), "private").unwrap();
        let subject_out = tempdir().unwrap();
        let selected =
            run_communication_subject_export(home.path(), subject_out.path(), "other-human")
                .unwrap();
        assert!(selected.communication_profile_only);
        assert!(!selected.communication_profile_operator_subject);
        assert_eq!(selected.communication_profile_subjects, 1);
        assert_eq!(selected.episode_rows, 0);
        assert_eq!(selected.groundtruth_rows, 0);
        assert_eq!(selected.archive_files_copied, 0);
        let files = std::fs::read_dir(subject_out.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            files,
            vec![std::ffi::OsString::from("communication_profile.json")]
        );
        let selected_body =
            std::fs::read_to_string(subject_out.path().join("communication_profile.json")).unwrap();
        assert!(selected_body.contains("other-human"));
        assert!(selected_body.contains("other-session"));
        assert!(selected_body.contains("gentle"));
        assert!(!selected_body.contains("operator-session"));
        assert!(!selected_body.contains("private-operator-session"));
    }

    #[test]
    fn explicit_subject_export_rejects_unknown_case_and_nonempty_destination() {
        use crate::profile::communication::{
            CommunicationScope, DirectnessPreference, PreferenceValue,
        };

        let home = tempdir().unwrap();
        crate::profile::communication::set_explicit_preference(
            home.path(),
            &crate::config::CommunicationProfileConfig::default(),
            "native:matrix:AbC",
            "subject-session",
            PreferenceValue::Directness(DirectnessPreference::Direct),
            [4; 32],
            1_700_000_000,
            CommunicationScope::Global,
            false,
        )
        .unwrap();

        let out = tempdir().unwrap();
        let error = run_communication_subject_export(home.path(), out.path(), "native:matrix:abc")
            .unwrap_err();
        assert!(format!("{error:#}").contains("exact and case-sensitive"));
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);

        std::fs::write(out.path().join("stale-operator-data.jsonl"), "private").unwrap();
        let error = run_communication_subject_export(home.path(), out.path(), "native:matrix:AbC")
            .unwrap_err();
        assert!(format!("{error:#}").contains("prevent cross-subject data leakage"));
    }

    #[test]
    fn corrupt_present_communication_state_fails_export_loudly() {
        let home = tempdir().unwrap();
        let out = tempdir().unwrap();
        let state_path = crate::profile::communication::state_path(home.path());
        std::fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        std::fs::write(&state_path, b"{not-json").unwrap();

        let error = run_export(home.path(), out.path(), ExportFormat::Jsonl, 0).unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("strictly load communication profile for export"));
        assert!(detail.contains("communication.json"));

        let error = communication_profile_inventory(home.path()).unwrap_err();
        assert!(format!("{error:#}").contains("strictly load communication profile inventory"));
    }

    #[test]
    fn copies_archive_session_files() {
        let home = tempdir().unwrap();
        let out = tempdir().unwrap();
        let day = home
            .path()
            .join("archive")
            .join("sessions")
            .join("2026-05-14");
        std::fs::create_dir_all(&day).unwrap();
        std::fs::write(day.join("a.md"), "alpha").unwrap();
        std::fs::write(day.join("b.md"), "beta").unwrap();
        let s = run_export(home.path(), out.path(), ExportFormat::Jsonl, 0).unwrap();
        assert_eq!(s.archive_files_copied, 2);
        assert!(out.path().join("archive/sessions/2026-05-14/a.md").exists());
    }
}
