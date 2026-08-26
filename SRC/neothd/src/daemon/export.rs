//! Operator data export — Phase 33c BS-8.
//!
//! GDPR-style operator export: produce a portable dump of exportable operator
//! data in formats the operator can read without NEOTH. The separately
//! persisted communication profile is intentionally represented only by its
//! redacted projection below.
//!
//! ## Scope
//!
//! - **episodic** (`idx_episode`)   — every RAW_TEXT + channel I/O frame
//! - **consolidated** (`idx_consolidated`)
//! - **long-term** (`idx_longterm`)
//! - **ground truth** (`idx_groundtruth`, including revoked rows for
//!   audit completeness)
//! - **communication profile** — a schema-versioned redacted projection of
//!   active operator accommodations only
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
//! Pure read — `neoth export` does not mutate any view, does not write the
//! WAL, does not call providers, enumerate private subjects, or serialize the
//! communication-profile persistence model.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Serialize;

use crate::config::FreedomConfig;
use crate::memory::store;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    Jsonl,
    Md,
}

/// Generic export has no authenticated private DSAR authority. Keep this
/// distinct from an absent selector or malformed state so future authority
/// work must add a separate, reviewed boundary rather than widening export.
#[derive(Debug)]
pub struct PrivateDsarAuthorityUnavailable;

impl std::fmt::Display for PrivateDsarAuthorityUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("private DSAR authority unavailable")
    }
}

impl std::error::Error for PrivateDsarAuthorityUnavailable {}

pub(crate) fn private_dsar_authority_unavailable() -> anyhow::Error {
    PrivateDsarAuthorityUnavailable.into()
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
    pub communication_profile_redacted: bool,
    pub archive_files_copied: usize,
    pub output_dir: String,
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
    let communication =
        crate::profile::communication::load_redacted_export(home).with_context(|| {
            format!(
                "strictly load communication profile for redacted export from {}",
                crate::profile::communication::state_path(home).display()
            )
        })?;

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

    export_redacted_communication_profile(output_dir, &communication)?;
    apply_communication_summary(&mut summary, &communication);

    let archive_src = home.join("archive").join("sessions");
    if archive_src.exists() {
        let archive_dst = output_dir.join("archive").join("sessions");
        summary.archive_files_copied = copy_archive(&archive_src, &archive_dst)?;
    }

    Ok(summary)
}

fn apply_communication_summary(
    summary: &mut ExportSummary,
    communication: &crate::profile::communication::RedactedCommunicationProfileExport,
) {
    summary.communication_profile_export_schema_version = communication.export_schema_version;
    summary.communication_profile_state_present = communication.state_present;
    summary.communication_profile_state_schema_version = communication.state_schema_version;
    summary.communication_profile_redacted = communication.redacted;
}

/// Serializes only the explicit redacted DTO, never the persistence model.
fn export_redacted_communication_profile(
    output_dir: &Path,
    communication: &crate::profile::communication::RedactedCommunicationProfileExport,
) -> Result<()> {
    let body = serde_json::to_vec_pretty(communication)
        .context("serialize redacted communication profile export")?;
    let output = output_dir.join("communication_profile.json");
    crate::util::atomic_write::atomic_write_private(&output, &body)
        .with_context(|| format!("write communication profile export {}", output.display()))?;
    Ok(())
}

pub(crate) fn communication_subject_sha256(subject_id: &str) -> String {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"neoth.communication.audit-subject.v1\0");
    hasher.update(subject_id.as_bytes());
    hex::encode(hasher.finalize())
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
    fn empty_home_exports_only_redacted_absent_metadata() {
        let home = tempdir().unwrap();
        let out = tempdir().unwrap();
        let s = run_export(home.path(), out.path(), ExportFormat::Jsonl, 0).unwrap();
        assert_eq!(s.episode_rows, 0);
        assert_eq!(s.communication_profile_export_schema_version, 2);
        assert!(!s.communication_profile_state_present);
        assert_eq!(s.communication_profile_state_schema_version, None);
        assert!(s.communication_profile_redacted);
        let communication =
            std::fs::read_to_string(out.path().join("communication_profile.json")).unwrap();
        let communication: serde_json::Value = serde_json::from_str(&communication).unwrap();
        assert_eq!(communication["export_schema_version"], 2);
        assert_eq!(communication["state_present"], false);
        assert_eq!(
            communication["state_schema_version"],
            serde_json::Value::Null
        );
        assert_eq!(communication["redacted"], true);
        assert_eq!(
            communication["active_accommodations"],
            serde_json::json!([])
        );
        assert_eq!(s.archive_files_copied, 0);
    }

    #[test]
    fn communication_export_v2_contains_only_active_concrete_accommodations() {
        use crate::profile::communication::{
            DeclaredContext, DeclaredContextKind, DeclaredContextPromptUse, DirectnessPreference,
            PreferenceValue, StructurePreference,
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
            false,
        )
        .unwrap();
        crate::profile::communication::set_explicit_preference(
            home.path(),
            &policy,
            "operator",
            "operator-structure-session",
            PreferenceValue::Structure(StructurePreference::Bullets),
            [3; 32],
            1_700_000_002,
            false,
        )
        .unwrap();
        crate::profile::communication::set_test_scoped_preference(
            home.path(),
            &policy,
            "other-human",
            "other-session",
            PreferenceValue::Directness(DirectnessPreference::Gentle),
            [2; 32],
            1_700_000_001,
        )
        .unwrap();
        crate::profile::communication::declare_context(
            home.path(),
            &policy,
            "operator",
            DeclaredContextKind::Autistic,
            [4; 32],
            DeclaredContextPromptUse::LabelAndAccommodations,
            1_700_000_003,
            false,
        )
        .unwrap();

        // Fixture an inactive accommodation and an explicitly declared but
        // revoked medical context. Neither may affect the generic projection.
        let mut state = crate::profile::communication::load_state(home.path()).unwrap();
        let operator = state.subjects.get_mut("operator").unwrap();
        operator
            .estimates
            .get_mut(&crate::profile::communication::CommunicationDimension::Structure)
            .unwrap()
            .active = false;
        operator.declared_context.as_mut().unwrap().revoked_at_unix = Some(1_700_000_004);
        state
            .subjects
            .get_mut("other-human")
            .unwrap()
            .declared_context = Some(DeclaredContext {
            kind: DeclaredContextKind::Adhd,
            explicitly_asserted_by_operator: true,
            source_event_hash: hex::encode([5; 32]),
            prompt_use: DeclaredContextPromptUse::LabelAndAccommodations,
            set_at_unix: 1_700_000_005,
            revoked_at_unix: None,
        });
        let state_bytes = serde_json::to_vec_pretty(&state).unwrap();
        std::fs::write(
            crate::profile::communication::state_path(home.path()),
            state_bytes,
        )
        .unwrap();

        let summary = run_export(home.path(), out.path(), ExportFormat::Md, 0).unwrap();
        assert!(summary.communication_profile_state_present);
        assert_eq!(summary.communication_profile_state_schema_version, Some(2));
        assert_eq!(summary.communication_profile_export_schema_version, 2);
        assert!(summary.communication_profile_redacted);

        let body = std::fs::read_to_string(out.path().join("communication_profile.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["state_present"], true);
        assert_eq!(value["state_schema_version"], 2);
        assert_eq!(
            value["active_accommodations"],
            serde_json::json!([{
                "dimension": "directness",
                "value": "direct",
            }])
        );
        let operator_hash = hex::encode([1; 32]);
        let other_hash = hex::encode([2; 32]);
        let declared_hash = hex::encode([4; 32]);
        let active_declared_hash = hex::encode([5; 32]);
        for forbidden in [
            "operator",
            "operator-session",
            "operator-structure-session",
            "other-human",
            "other-session",
            "gentle",
            "explicit_setting",
            "global",
            "test",
            "session_id",
            "confidence",
            "provenance",
            "scope",
            "scope_provenance",
            "event_hash",
            "observed_at_unix",
            "first_seen_unix",
            "last_seen_unix",
            "set_at_unix",
            "revoked_at_unix",
            "declared_context",
            "autistic",
            "adhd",
            "label_and_accommodations",
            "1700000004",
            operator_hash.as_str(),
            other_hash.as_str(),
            declared_hash.as_str(),
            active_declared_hash.as_str(),
        ] {
            assert!(
                !body.contains(forbidden),
                "redacted export leaked {forbidden}"
            );
        }
    }

    #[test]
    fn generic_export_api_has_no_persistence_model_serialization_path() {
        let source = include_str!("export.rs");
        let persistence_type = ["Subject", "CommunicationProfile"].concat();
        let former_payload_field = ["typed", "subject"].join("_");
        let redacted_dto = ["Redacted", "CommunicationProfileExport"].concat();

        assert!(!source.contains(&persistence_type));
        assert!(!source.contains(&former_payload_field));
        assert!(source.contains(&redacted_dto));
    }

    #[test]
    fn corrupt_present_communication_state_fails_before_generic_export_writes() {
        let home = tempdir().unwrap();
        let out = home.path().join("must-not-be-created");
        let state_path = crate::profile::communication::state_path(home.path());
        std::fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        std::fs::write(&state_path, b"{not-json").unwrap();

        let error = run_export(home.path(), &out, ExportFormat::Jsonl, 0).unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("strictly load communication profile for redacted export"));
        assert!(detail.contains("communication.json"));
        assert!(!out.exists());
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
