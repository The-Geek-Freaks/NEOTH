//! Private, review-only onboarding for historical assistant exports.
//!
//! This module deliberately has no dependency on profile learning, recall,
//! raw transcript retention, ground truth, Babel, or proactive scheduling.
//! Historical text is untrusted evidence until a future, separately-audited
//! explicit-setting capability exists.  V1 therefore supports only scan,
//! preview, status, review, reject, and exact-batch purge.

use anyhow::{Context, Result, anyhow, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

const PARSER_SCHEMA_VERSION: i64 = 1;
pub const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CANDIDATES_PER_BATCH: usize = 4_096;
const MAX_CONVERSATION_ID_BYTES: usize = 128;
const MAX_EXCERPT_BYTES: usize = 360;
const MAX_TURN_BYTES: usize = 32 * 1024;

/// Private review-journal schema.  It must never be joined into a recall or
/// profile query.  DDL contains no DML/backfill so opening an existing DB
/// cannot silently reinterpret historic records.
pub(crate) const HISTORY_ONBOARDING_V38_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS history_onboarding_batches (
        batch_id TEXT PRIMARY KEY NOT NULL
            CHECK(length(batch_id) = 64 AND batch_id NOT GLOB '*[^0-9a-f]*'),
        operator_subject TEXT NOT NULL
            CHECK(length(CAST(operator_subject AS BLOB)) BETWEEN 1 AND 128),
        source_family TEXT NOT NULL
            CHECK(source_family IN ('chatgpt_export','claude_export','openclaw_history')),
        source_sha256 BLOB NOT NULL CHECK(length(source_sha256) = 32),
        source_object_sha256 BLOB NOT NULL CHECK(length(source_object_sha256) = 32),
        source_path_sha256 BLOB NOT NULL CHECK(length(source_path_sha256) = 32),
        parser_schema_version INTEGER NOT NULL CHECK(parser_schema_version = 1),
        state TEXT NOT NULL DEFAULT 'active'
            CHECK(state IN ('active','invalidated','purged')),
        scanned_at_unix INTEGER NOT NULL,
        candidate_count INTEGER NOT NULL CHECK(candidate_count BETWEEN 0 AND 4096),
        excluded_privacy_mode_count INTEGER NOT NULL CHECK(excluded_privacy_mode_count >= 0),
        skipped_structural_count INTEGER NOT NULL CHECK(skipped_structural_count >= 0),
        UNIQUE(batch_id, operator_subject),
        UNIQUE(operator_subject, source_family, source_object_sha256, source_sha256,
               parser_schema_version)
    ) STRICT;
    CREATE INDEX IF NOT EXISTS history_onboarding_batches_subject_state
        ON history_onboarding_batches(operator_subject, state, scanned_at_unix DESC);
    CREATE INDEX IF NOT EXISTS history_onboarding_batches_object
        ON history_onboarding_batches(operator_subject, source_object_sha256);
    CREATE INDEX IF NOT EXISTS history_onboarding_batches_path
        ON history_onboarding_batches(operator_subject, source_path_sha256);

    CREATE TABLE IF NOT EXISTS history_onboarding_candidates (
        candidate_id TEXT PRIMARY KEY NOT NULL
            CHECK(length(candidate_id) = 64 AND candidate_id NOT GLOB '*[^0-9a-f]*'),
        batch_id TEXT NOT NULL,
        operator_subject TEXT NOT NULL
            CHECK(length(CAST(operator_subject AS BLOB)) BETWEEN 1 AND 128),
        conversation_id TEXT NOT NULL
            CHECK(length(CAST(conversation_id AS BLOB)) BETWEEN 1 AND 128),
        turn_id TEXT NOT NULL CHECK(length(CAST(turn_id AS BLOB)) BETWEEN 1 AND 128),
        position INTEGER NOT NULL CHECK(position >= 0),
        content_sha256 BLOB NOT NULL CHECK(length(content_sha256) = 32),
        excerpt TEXT NOT NULL CHECK(length(CAST(excerpt AS BLOB)) BETWEEN 1 AND 360),
        kind TEXT NOT NULL CHECK(kind IN ('operator_turn','assistant_turn')),
        state TEXT NOT NULL DEFAULT 'pending'
            CHECK(state IN ('pending','rejected','revoked')),
        created_at_unix INTEGER NOT NULL,
        resolved_at_unix INTEGER,
        UNIQUE(batch_id, conversation_id, turn_id, position),
        FOREIGN KEY(batch_id, operator_subject)
            REFERENCES history_onboarding_batches(batch_id, operator_subject) ON DELETE CASCADE,
        CHECK((state = 'pending' AND resolved_at_unix IS NULL)
              OR (state <> 'pending' AND resolved_at_unix IS NOT NULL))
    ) STRICT;
    CREATE INDEX IF NOT EXISTS history_onboarding_candidates_subject_state
        ON history_onboarding_candidates(operator_subject, state, created_at_unix DESC);
    CREATE INDEX IF NOT EXISTS history_onboarding_candidates_batch_state
        ON history_onboarding_candidates(batch_id, state, position);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFamily {
    ChatgptExport,
    ClaudeExport,
    OpenclawHistory,
}

impl SourceFamily {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "chatgpt_export" => Ok(Self::ChatgptExport),
            "claude_export" => Ok(Self::ClaudeExport),
            "openclaw_history" => Ok(Self::OpenclawHistory),
            _ => Err(anyhow!(
                "unknown source family '{value}'; use chatgpt_export, claude_export, \
                 or openclaw_history"
            )),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ChatgptExport => "chatgpt_export",
            Self::ClaudeExport => "claude_export",
            Self::OpenclawHistory => "openclaw_history",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePreview {
    pub candidate_id: String,
    pub batch_id: String,
    pub conversation_id: String,
    pub turn_id: String,
    pub position: i64,
    pub kind: String,
    pub state: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchStatus {
    pub batch_id: String,
    pub source_family: String,
    pub state: String,
    pub candidate_count: i64,
    pub excluded_privacy_mode_count: i64,
    pub skipped_structural_count: i64,
}

struct ParsedTurn {
    conversation_id: String,
    turn_id: String,
    position: usize,
    kind: &'static str,
    text: String,
}

struct ParseReport {
    turns: Vec<ParsedTurn>,
    excluded_privacy_mode_count: usize,
    skipped_structural_count: usize,
}

/// Scan one export into the private review journal.  Parsing occurs before the
/// transaction; once the transaction starts, a batch and all candidates land
/// together or none land. A changed physical source object invalidates pending
/// candidates from its old content even when Windows path aliases differ.
/// Persist only a Connector-Control-captured, capability-bound source. The
/// caller never supplies ambient bytes, raw path, or a subject string as an
/// authority credential; the opaque source binds the configured subject.
pub(crate) fn scan_verified_source(
    conn: &mut Connection,
    operator_subject: &str,
    source_family: SourceFamily,
    source: crate::connectors::local_import::VerifiedHistorySource,
    now_unix: i64,
) -> Result<BatchStatus> {
    validate_subject(operator_subject)?;
    ensure!(source.binds_subject(operator_subject), "history source subject binding mismatch");
    ensure!(
        source.binds_source_family(source_family.as_str()),
        "history source family binding mismatch"
    );
    ensure!(source.bytes().len() <= MAX_SOURCE_BYTES, "history export exceeds its size bound");
    ensure!(
        sha256(source.bytes()).as_slice() == source.source_sha256(),
        "history source digest mismatch"
    );
    let source_sha256 = source.source_sha256().to_vec();
    let source_object_sha256 = source.source_object_id().to_vec();
    let path_sha256 = source.source_path_sha256().to_vec();
    ensure!(
        source.source_object_id().iter().any(|byte| *byte != 0),
        "history source object binding is invalid"
    );
    let report = parse_source(source_family, source.bytes())?;
    ensure!(
        report.turns.len() <= MAX_CANDIDATES_PER_BATCH,
        "history export yields more than {MAX_CANDIDATES_PER_BATCH} review candidates"
    );
    let batch_id = hex::encode(sha256(
        format!(
            "neoth.history-onboarding.v1\0{}\0{}\0{}\0{}",
            operator_subject,
            source_family.as_str(),
            hex::encode(&source_sha256),
            hex::encode(&source_object_sha256),
        )
        .as_bytes(),
    ));

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin history-onboarding scan transaction")?;
    if let Some(existing) = status_by_batch_tx(&tx, operator_subject, &batch_id)? {
        tx.commit().context("commit idempotent history-onboarding scan")?;
        return Ok(existing);
    }
    tx.execute(
        "UPDATE history_onboarding_batches
         SET state='invalidated'
         WHERE operator_subject=?1
           AND (source_object_sha256=?2 OR source_path_sha256=?3)
           AND (source_object_sha256<>?2 OR source_family<>?4 OR source_sha256<>?5)
           AND state='active'",
        params![
            operator_subject,
            &source_object_sha256,
            &path_sha256,
            source_family.as_str(),
            &source_sha256,
        ],
    )
    .context("invalidate prior source-hash batch")?;
    tx.execute(
        "UPDATE history_onboarding_candidates
         SET state='revoked', resolved_at_unix=?1
         WHERE operator_subject=?2 AND state='pending'
           AND batch_id IN (
               SELECT batch_id FROM history_onboarding_batches
               WHERE operator_subject=?2
                 AND (source_object_sha256=?3 OR source_path_sha256=?4)
                 AND (source_object_sha256<>?3 OR source_family<>?5 OR source_sha256<>?6)
            )",
        params![
            now_unix,
            operator_subject,
            &source_object_sha256,
            &path_sha256,
            source_family.as_str(),
            &source_sha256,
        ],
    )
    .context("revoke pending candidates from modified source")?;
    tx.execute(
        "INSERT INTO history_onboarding_batches
         (batch_id,operator_subject,source_family,source_sha256,source_object_sha256,
          source_path_sha256,
          parser_schema_version,scanned_at_unix,candidate_count,excluded_privacy_mode_count,
          skipped_structural_count)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            batch_id,
            operator_subject,
            source_family.as_str(),
            &source_sha256,
            &source_object_sha256,
            &path_sha256,
            PARSER_SCHEMA_VERSION,
            now_unix,
            report.turns.len() as i64,
            report.excluded_privacy_mode_count as i64,
            report.skipped_structural_count as i64,
        ],
    )
    .context("insert history-onboarding batch")?;
    for turn in report.turns {
        insert_candidate(&tx, operator_subject, &batch_id, turn, now_unix)?;
    }
    let status = status_by_batch_tx(&tx, operator_subject, &batch_id)?
        .ok_or_else(|| anyhow!("new history-onboarding batch disappeared during scan"))?;
    tx.commit().context("commit history-onboarding scan")?;
    Ok(status)
}

pub fn preview(
    conn: &Connection,
    operator_subject: &str,
    batch_id: &str,
    limit: usize,
) -> Result<Vec<CandidatePreview>> {
    validate_subject(operator_subject)?;
    validate_digest_id(batch_id, "batch id")?;
    let limit = limit.min(200);
    let mut statement = conn.prepare(
        "SELECT candidate_id,batch_id,conversation_id,turn_id,position,kind,state,excerpt
         FROM history_onboarding_candidates
         WHERE operator_subject=?1 AND batch_id=?2
         ORDER BY position,candidate_id LIMIT ?3",
    )?;
    statement
        .query_map(params![operator_subject, batch_id, limit as i64], row_to_preview)?
        .context("read history-onboarding preview")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decode history-onboarding preview")
}

pub fn review(
    conn: &Connection,
    operator_subject: &str,
    batch_id: &str,
    limit: usize,
) -> Result<Vec<CandidatePreview>> {
    validate_subject(operator_subject)?;
    validate_digest_id(batch_id, "batch id")?;
    let limit = limit.min(200);
    let mut statement = conn.prepare(
        "SELECT candidate_id,batch_id,conversation_id,turn_id,position,kind,state,excerpt
         FROM history_onboarding_candidates
         WHERE operator_subject=?1 AND batch_id=?2 AND state='pending'
         ORDER BY position,candidate_id LIMIT ?3",
    )?;
    statement
        .query_map(params![operator_subject, batch_id, limit as i64], row_to_preview)?
        .context("read pending history-onboarding review")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decode pending history-onboarding review")
}

pub fn status(conn: &Connection, operator_subject: &str) -> Result<Vec<BatchStatus>> {
    validate_subject(operator_subject)?;
    let mut statement = conn.prepare(
        "SELECT batch_id,source_family,state,candidate_count,excluded_privacy_mode_count,
                skipped_structural_count
         FROM history_onboarding_batches
         WHERE operator_subject=?1 ORDER BY scanned_at_unix DESC,batch_id DESC",
    )?;
    statement
        .query_map([operator_subject], row_to_status)?
        .context("read history-onboarding status")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decode history-onboarding status")
}

pub fn reject(
    conn: &mut Connection,
    operator_subject: &str,
    candidate_id: &str,
    now_unix: i64,
) -> Result<bool> {
    validate_subject(operator_subject)?;
    validate_digest_id(candidate_id, "candidate id")?;
    let changed = conn.execute(
        "UPDATE history_onboarding_candidates SET state='rejected',resolved_at_unix=?1
         WHERE candidate_id=?2 AND operator_subject=?3 AND state='pending'",
        params![now_unix, candidate_id, operator_subject],
    )?;
    Ok(changed == 1)
}

/// Logically remove exactly one subject-owned journal batch. SQLite/WAL pages
/// and the original source are not sanitized; applied settings do not exist in
/// V1 and therefore cannot be silently rolled back.
pub fn purge(conn: &mut Connection, operator_subject: &str, batch_id: &str) -> Result<bool> {
    validate_subject(operator_subject)?;
    validate_digest_id(batch_id, "batch id")?;
    let changed = conn.execute(
        "DELETE FROM history_onboarding_batches WHERE batch_id=?1 AND operator_subject=?2",
        params![batch_id, operator_subject],
    )?;
    Ok(changed == 1)
}

fn status_by_batch_tx(
    tx: &Transaction<'_>,
    operator_subject: &str,
    batch_id: &str,
) -> Result<Option<BatchStatus>> {
    tx.query_row(
        "SELECT batch_id,source_family,state,candidate_count,excluded_privacy_mode_count,
                skipped_structural_count
         FROM history_onboarding_batches WHERE operator_subject=?1 AND batch_id=?2",
        params![operator_subject, batch_id],
        row_to_status,
    )
        .optional()
        .context("read history-onboarding batch status")
}

fn insert_candidate(
    tx: &Transaction<'_>,
    operator_subject: &str,
    batch_id: &str,
    turn: ParsedTurn,
    now_unix: i64,
) -> Result<()> {
    let content_sha256 = sha256(turn.text.as_bytes());
    let candidate_id = hex::encode(candidate_identity_sha256(
        batch_id,
        &turn.conversation_id,
        &turn.turn_id,
        turn.position,
    ));
    tx.execute(
        "INSERT INTO history_onboarding_candidates
         (candidate_id,batch_id,operator_subject,conversation_id,turn_id,position,
          content_sha256,excerpt,kind,created_at_unix)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            candidate_id,
            batch_id,
            operator_subject,
            turn.conversation_id,
            turn.turn_id,
            turn.position as i64,
            content_sha256,
            neutral_excerpt(&turn.text),
            turn.kind,
            now_unix,
        ],
    )
    .context("insert history-onboarding candidate")?;
    Ok(())
}

fn candidate_identity_sha256(
    batch_id: &str,
    conversation_id: &str,
    turn_id: &str,
    position: usize,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"NEOTH\0HISTORY_CANDIDATE\0SHA256\0V2");
    let position = (position as u64).to_be_bytes();
    for field in [
        batch_id.as_bytes(),
        conversation_id.as_bytes(),
        turn_id.as_bytes(),
        position.as_slice(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn parse_source(family: SourceFamily, bytes: &[u8]) -> Result<ParseReport> {
    ensure!(bytes.len() <= MAX_SOURCE_BYTES, "history export exceeds {MAX_SOURCE_BYTES} bytes");
    let value: Value = serde_json::from_slice(bytes).context("parse history export as JSON")?;
    let mut turns = Vec::new();
    let mut excluded_privacy_mode_count = 0;
    let mut skipped_structural_count = 0;
    let container_private = has_privacy_marker(&value);
    visit_family_records(family, &value, |position, record| {
        if container_private || has_privacy_marker(record) {
            excluded_privacy_mode_count += 1;
            return Ok(());
        }
        let Some((conversation_id, turn_id, role, text)) = extract_record(record, position)? else {
            skipped_structural_count += 1;
            return Ok(());
        };
        ensure!(text.len() <= MAX_TURN_BYTES, "history turn exceeds {MAX_TURN_BYTES} bytes");
        ensure!(!text.trim().is_empty(), "history turn text is empty");
        ensure!(!neutral_excerpt(&text).is_empty(), "history turn excerpt is empty");
        let kind = match role.as_str() {
            "user" | "operator" | "human" => "operator_turn",
            "assistant" => "assistant_turn",
            _ => {
                skipped_structural_count += 1;
                return Ok(());
            }
        };
        ensure!(
            turns.len() < MAX_CANDIDATES_PER_BATCH,
            "history export yields more than {MAX_CANDIDATES_PER_BATCH} review candidates"
        );
        turns.push(ParsedTurn {
            conversation_id: bounded_id(&conversation_id, "conversation")?,
            turn_id: bounded_id(&turn_id, "turn")?,
            position,
            kind,
            text,
        });
        Ok(())
    })?;
    Ok(ParseReport {
        turns,
        excluded_privacy_mode_count,
        skipped_structural_count,
    })
}

fn visit_family_records(
    family: SourceFamily,
    value: &Value,
    mut visit: impl FnMut(usize, &Value) -> Result<()>,
) -> Result<()> {
    match family {
        SourceFamily::ChatgptExport => {
            if let Some(array) = value.as_array() {
                for (position, record) in array.iter().enumerate() {
                    visit(position, record)?;
                }
            } else if let Some(mapping) = value.get("mapping").and_then(Value::as_object) {
                for (position, record) in mapping.values().enumerate() {
                    visit(position, record)?;
                }
            } else if let Some(array) = value.get("conversations").and_then(Value::as_array) {
                for (position, record) in array.iter().enumerate() {
                    visit(position, record)?;
                }
            } else {
                return Err(anyhow!("unrecognized ChatGPT export schema"));
            }
        }
        SourceFamily::ClaudeExport => {
            let array = value
                .as_array()
                .or_else(|| value.get("messages").and_then(Value::as_array))
                .ok_or_else(|| anyhow!("unrecognized Claude export schema"))?;
            for (position, record) in array.iter().enumerate() {
                visit(position, record)?;
            }
        }
        SourceFamily::OpenclawHistory => {
            let array = value
                .get("messages")
                .and_then(Value::as_array)
                .or_else(|| value.as_array())
                .ok_or_else(|| anyhow!("unrecognized OpenClaw history schema"))?;
            for (position, record) in array.iter().enumerate() {
                visit(position, record)?;
            }
        }
    }
    Ok(())
}

fn extract_record(
    record: &Value,
    position: usize,
) -> Result<Option<(String, String, String, String)>> {
    let message = record.get("message").unwrap_or(record);
    let role = field_string(message, &["role", "author.role", "sender.role"]);
    let text = field_string(message, &["content.parts", "content.text", "content", "text"]);
    if role.is_none() && text.is_none() {
        return Ok(None);
    }
    let role = role.ok_or_else(|| anyhow!("candidate-bearing history record lacks a role"))?;
    let text = text.ok_or_else(|| anyhow!("candidate-bearing history record lacks text"))?;
    let conversation_id = field_string(record, &["conversation_id", "conversationId", "session_id"])
        .or_else(|| field_string(message, &["conversation_id", "conversationId", "session_id"]))
        .unwrap_or_else(|| format!("conversation-{position}"));
    let turn_id = field_string(record, &["id", "message_id", "uuid"])
        .or_else(|| field_string(message, &["id", "message_id", "uuid"]))
        .unwrap_or_else(|| format!("turn-{position}"));
    Ok(Some((conversation_id, turn_id, role, text)))
}

fn field_string(value: &Value, paths: &[&str]) -> Option<String> {
    for path in paths {
        let mut current = value;
        let mut found = true;
        for key in path.split('.') {
            let Some(next) = current.get(key) else {
                found = false;
                break;
            };
            current = next;
        }
        if !found {
            continue;
        }
        match current {
            Value::String(text) => return Some(text.clone()),
            Value::Array(parts) if path.ends_with("parts") => {
                let joined = parts.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ");
                if !joined.is_empty() {
                    return Some(joined);
                }
            }
            _ => {}
        }
    }
    None
}

fn has_privacy_marker(value: &Value) -> bool {
    const KEYS: &[&str] = &[
        "incognito", "is_incognito", "private", "is_private", "ephemeral",
        "is_ephemeral", "temporary", "is_temporary", "temporary_chat", "privacy_mode",
    ];
    match value {
        Value::Object(object) => {
            KEYS.iter().any(|key| object.get(*key).and_then(Value::as_bool) == Some(true))
                || object.values().any(has_privacy_marker)
        }
        Value::Array(values) => values.iter().any(has_privacy_marker),
        _ => false,
    }
}

fn row_to_preview(row: &rusqlite::Row<'_>) -> rusqlite::Result<CandidatePreview> {
    Ok(CandidatePreview {
        candidate_id: row.get(0)?, batch_id: row.get(1)?, conversation_id: row.get(2)?,
        turn_id: row.get(3)?, position: row.get(4)?, kind: row.get(5)?, state: row.get(6)?,
        excerpt: row.get(7)?,
    })
}

fn row_to_status(row: &rusqlite::Row<'_>) -> rusqlite::Result<BatchStatus> {
    Ok(BatchStatus {
        batch_id: row.get(0)?, source_family: row.get(1)?, state: row.get(2)?,
        candidate_count: row.get(3)?, excluded_privacy_mode_count: row.get(4)?,
        skipped_structural_count: row.get(5)?,
    })
}

fn neutral_excerpt(text: &str) -> String {
    let mut rendered = String::with_capacity(text.len().min(MAX_EXCERPT_BYTES));
    for character in text.chars() {
        if rendered.len() + character.len_utf8() > MAX_EXCERPT_BYTES {
            break;
        }
        if character.is_control() {
            rendered.push(' ');
        } else {
            rendered.push(character);
        }
    }
    rendered.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn bounded_id(value: &str, label: &str) -> Result<String> {
    ensure!(
        !value.is_empty()
            && value.len() <= MAX_CONVERSATION_ID_BYTES
            && value.chars().all(|character| !character.is_control()),
        "{label} id out of bounds"
    );
    Ok(value.to_owned())
}

fn validate_subject(subject: &str) -> Result<()> {
    ensure!(
        !subject.is_empty()
            && subject.len() <= 128
            && subject.chars().all(|character| !character.is_control()),
        "operator subject out of bounds"
    );
    Ok(())
}

fn validate_digest_id(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "invalid {label}"
    );
    Ok(())
}

fn sha256(bytes: &[u8]) -> Vec<u8> { Sha256::digest(bytes).to_vec() }

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use std::{fs, path::Path};

    #[cfg(any(unix, windows))]
    use crate::connectors::local_import::{
        approve_import_root, capture_verified_history_source,
        issue_interactive_history_import_capability,
    };
    use super::*;

    #[test]
    fn candidate_identity_is_unambiguous_across_backslash_zero_boundaries() {
        let first = candidate_identity_sha256("batch", r"a\0b", "c", 7);
        let second = candidate_identity_sha256("batch", "a", r"b\0c", 7);
        assert_ne!(first, second);
    }

    #[cfg(any(unix, windows))]
    fn scan_fixture(
        conn: &mut Connection,
        subject: &str,
        family: SourceFamily,
        path: &Path,
        now_unix: i64,
    ) -> Result<BatchStatus> {
        let root = approve_import_root(path.parent().expect("fixture parent"))?;
        let leaf = Path::new(path.file_name().expect("fixture leaf"));
        let capability = issue_interactive_history_import_capability(
            root,
            [7_u8; 32],
            subject,
            family.as_str(),
            leaf,
            MAX_SOURCE_BYTES,
        )?;
        let verified = capture_verified_history_source(capability)?;
        scan_verified_source(conn, subject, family, verified, now_unix)
    }

    #[test]
    fn all_three_families_parse_neutral_review_candidates() {
        let chatgpt = concat!(
            r#"{"mapping":{"n":{"id":"a","conversation_id":"c","message":{"author":{#,
            r#""role":"user"},"#,
            r#""content":{"parts":["hello"]}}}}}"#,
        ).as_bytes();
        let claude = concat!(
            r#"{"messages":[{"id":"a","conversation_id":"c","role":"user",#,
            r#""text":"hello"}]}"#,
        ).as_bytes();
        let openclaw = concat!(
            r#"{"messages":[{"id":"a","session_id":"c","role":"user",#,
            r#""content":"hello"}]}"#,
        ).as_bytes();
        assert_eq!(
            parse_source(SourceFamily::ChatgptExport, chatgpt).unwrap().turns.len(),
            1
        );
        assert_eq!(
            parse_source(SourceFamily::ClaudeExport, claude).unwrap().turns.len(),
            1
        );
        assert_eq!(
            parse_source(SourceFamily::OpenclawHistory, openclaw).unwrap().turns.len(),
            1
        );
    }

    #[test]
    fn privacy_records_produce_no_candidates() {
        let source = concat!(
            r#"{"messages":[{"id":"a","session_id":"c","role":"user",#,
            r#""content":"secret","metadata":{"incognito":true}}]}"#,
        ).as_bytes();
        let report = parse_source(SourceFamily::OpenclawHistory, source).unwrap();
        assert!(report.turns.is_empty());
        assert_eq!(report.excluded_privacy_mode_count, 1);
    }

    #[test]
    fn every_supported_privacy_alias_excludes_direct_message_records() {
        for flag in [
            "is_incognito",
            "is_private",
            "is_ephemeral",
            "is_temporary",
            "temporary_chat",
        ] {
            let source = format!(
                "{{\"messages\":[{{\"id\":\"a\",\"role\":\"user\",\
                 \"content\":\"secret\",\"message\":{{\"{flag}\":true}}}}]}}"
            );
            let report = parse_source(SourceFamily::OpenclawHistory, source.as_bytes()).unwrap();
            assert!(report.turns.is_empty(), "privacy alias {flag} admitted a candidate");
            assert_eq!(report.excluded_privacy_mode_count, 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn every_family_and_privacy_alias_excludes_before_any_candidate_write() {
        let cases = [
            (
                SourceFamily::ChatgptExport,
                concat!(
                    r#"{"metadata":{"is_incognito":true},"mapping":{"n":{"id":"a","message":{#,
                    r#""author":{"role":"user"},"content":{"parts":["secret"]}}}}}"#,
                ),
            ),
            (
                SourceFamily::ClaudeExport,
                concat!(
                    r#"{"messages":[{"id":"a","role":"user","text":"secret",#,
                    r#""metadata":{"temporary_chat":true}}]}"#,
                ),
            ),
            (
                SourceFamily::OpenclawHistory,
                concat!(
                    r#"{"messages":[{"id":"a","role":"user","content":"secret",#,
                    r#""message":{"is_ephemeral":true}}]}"#,
                ),
            ),
        ];
        for (position, (family, source)) in cases.iter().enumerate() {
            let home = tempfile::tempdir().unwrap();
            let source_path = home.path().join(format!("privacy-{position}.json"));
            fs::write(&source_path, source).unwrap();
            let mut conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
            let status = scan_fixture(&mut conn, "operator-a", *family, &source_path, 1).unwrap();
            assert_eq!(status.candidate_count, 0);
            assert_eq!(status.excluded_privacy_mode_count, 1);
            assert!(review(&conn, "operator-a", &status.batch_id, 1).unwrap().is_empty());
        }
    }

    #[test]
    fn excerpt_is_inert_and_bounded() {
        let excerpt = neutral_excerpt(
            "<script>run()</script>\n[open](https://bad.invalid)\u{0000}",
        );
        assert!(!excerpt.contains('\n'));
        assert!(!excerpt.contains('\0'));
        assert!(excerpt.len() <= MAX_EXCERPT_BYTES);
    }

    #[test]
    fn candidate_bound_accepts_4096_and_rejects_4097_before_unbounded_growth() {
        fn export_with(count: usize) -> Vec<u8> {
            let mut source = String::from("{\"messages\":[");
            for position in 0..count {
                if position != 0 {
                    source.push(',');
                }
                source.push_str(&format!(
                    "{{\"id\":\"{position}\",\"role\":\"user\",\"content\":\"x\"}}"
                ));
            }
            source.push_str("]}");
            source.into_bytes()
        }
        assert_eq!(
            parse_source(SourceFamily::OpenclawHistory, &export_with(4_096))
                .unwrap()
                .turns
                .len(),
            4_096
        );
        assert!(parse_source(SourceFamily::OpenclawHistory, &export_with(4_097)).is_err());
    }

    #[test]
    fn state_transition_reject_is_subject_isolated() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        let batch = "a".repeat(64);
        conn.execute(
            "INSERT INTO history_onboarding_batches \
             (batch_id,operator_subject,source_family,source_sha256,source_object_sha256, \
              source_path_sha256, \
              parser_schema_version,scanned_at_unix,candidate_count,excluded_privacy_mode_count, \
              skipped_structural_count) \
             VALUES (?1,'a','chatgpt_export',zeroblob(32),zeroblob(32),zeroblob(32),1,1,1,0,0)",
            [&batch],
        ).unwrap();
        let candidate = "b".repeat(64);
        conn.execute(
            "INSERT INTO history_onboarding_candidates \
             (candidate_id,batch_id,operator_subject,conversation_id,turn_id,position, \
              content_sha256,excerpt,kind,created_at_unix) \
             VALUES (?1,?2,'a','c','t',0,zeroblob(32),'safe','operator_turn',1)",
            params![candidate, batch],
        ).unwrap();
        assert!(!reject(&mut conn, "b", &candidate, 2).unwrap());
        assert!(reject(&mut conn, "a", &candidate, 2).unwrap());
    }

    #[test]
    fn purge_is_exact_batch_only() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        let one = "a".repeat(64);
        let two = "b".repeat(64);
        for batch in [&one, &two] {
            conn.execute(
                "INSERT INTO history_onboarding_batches \
                 (batch_id,operator_subject,source_family,source_sha256,source_object_sha256, \
                  source_path_sha256, \
                  parser_schema_version,scanned_at_unix,candidate_count, \
                  excluded_privacy_mode_count,skipped_structural_count) \
                 VALUES (?1,'a','chatgpt_export',zeroblob(32),zeroblob(32),zeroblob(32), \
                         1,1,0,0,0)",
                [batch],
            ).unwrap();
        }
        assert!(!purge(&mut conn, "other", &one).unwrap());
        assert!(purge(&mut conn, "a", &one).unwrap());
        assert_eq!(status(&conn, "a").unwrap().len(), 1);
        assert_eq!(status(&conn, "a").unwrap()[0].batch_id, two);
    }

    #[test]
    fn composite_subject_fk_blocks_cross_subject_rows_and_cascades_exactly() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        let batch = "a".repeat(64);
        let candidate = "b".repeat(64);
        conn.execute(
            "INSERT INTO history_onboarding_batches \
             (batch_id,operator_subject,source_family,source_sha256,source_object_sha256, \
              source_path_sha256, \
              parser_schema_version,scanned_at_unix,candidate_count,excluded_privacy_mode_count, \
              skipped_structural_count) \
             VALUES (?1,'owner','chatgpt_export',zeroblob(32),zeroblob(32),zeroblob(32), \
                     1,1,0,0,0)",
            [&batch],
        ).unwrap();
        assert!(conn.execute(
            "INSERT INTO history_onboarding_candidates \
             (candidate_id,batch_id,operator_subject,conversation_id,turn_id,position, \
              content_sha256,excerpt,kind,created_at_unix) \
             VALUES (?1,?2,'other','c','t',0,zeroblob(32),'safe','operator_turn',1)",
            params![candidate, batch],
        ).is_err());
        assert!(conn.execute(
            "INSERT INTO history_onboarding_candidates \
             (candidate_id,batch_id,operator_subject,conversation_id,turn_id,position, \
              content_sha256,excerpt,kind,state,created_at_unix,resolved_at_unix) \
             VALUES (?1,?2,'owner','c','t',0,zeroblob(32),'safe','operator_turn', \
                     'attested',1,1)",
            params![candidate, batch],
        ).is_err());
        let valid = "c".repeat(64);
        conn.execute(
            "INSERT INTO history_onboarding_candidates \
             (candidate_id,batch_id,operator_subject,conversation_id,turn_id,position, \
              content_sha256,excerpt,kind,created_at_unix) \
             VALUES (?1,?2,'owner','c','t',0,zeroblob(32),'safe','operator_turn',1)",
            params![valid, batch],
        ).unwrap();
        assert!(purge(&mut conn, "owner", &batch).unwrap());
        let children: i64 = conn.query_row(
            "SELECT COUNT(*) FROM history_onboarding_candidates", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(children, 0);
    }

    #[cfg(unix)]
    #[test]
    fn same_hash_is_idempotent_and_changed_source_revokes_pending_candidates() {
        let home = tempfile::tempdir().unwrap();
        let source_path = home.path().join("export.json");
        fs::write(
            &source_path,
            r#"{"messages":[
                {"id":"a","session_id":"c","role":"user","content":"one"},
                {"id":"b","session_id":"c","role":"user","content":"still pending"}
            ]}"#,
        ).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        let first = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &source_path,
            1,
        ).unwrap();
        let repeated = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &source_path,
            2,
        ).unwrap();
        assert_eq!(first.batch_id, repeated.batch_id);
        assert_eq!(status(&conn, "operator-a").unwrap().len(), 1);
        let resolved = review(&conn, "operator-a", &first.batch_id, 1).unwrap().pop().unwrap();
        assert!(reject(&mut conn, "operator-a", &resolved.candidate_id, 2).unwrap());
        fs::write(
            &source_path,
            r#"{"messages":[{"id":"b","session_id":"c","role":"user","content":"two"}]}"#,
        ).unwrap();
        let second = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &source_path,
            3,
        ).unwrap();
        assert_ne!(first.batch_id, second.batch_id);
        let prior = status(&conn, "operator-a").unwrap().into_iter()
            .find(|batch| batch.batch_id == first.batch_id).unwrap();
        assert_eq!(prior.state, "invalidated");
        assert!(review(&conn, "operator-a", &first.batch_id, 10).unwrap().is_empty());
        let prior_state: String = conn.query_row(
            "SELECT state FROM history_onboarding_candidates WHERE candidate_id=?1",
            [&resolved.candidate_id],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(prior_state, "rejected");
        let revoked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM history_onboarding_candidates
             WHERE batch_id=?1 AND state='revoked'",
            [&first.batch_id],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(revoked, 1);
    }

    #[cfg(unix)]
    #[test]
    fn identical_bytes_at_distinct_selected_paths_do_not_alias_a_batch() {
        let home = tempfile::tempdir().unwrap();
        let first_path = home.path().join("first.json");
        let second_path = home.path().join("second.json");
        let source = r#"{"messages":[{"id":"a","role":"user","content":"one"}]}"#;
        fs::write(&first_path, source).unwrap();
        fs::write(&second_path, source).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        let first = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &first_path,
            1,
        )
        .unwrap();
        let second = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &second_path,
            2,
        )
        .unwrap();
        assert_ne!(first.batch_id, second.batch_id);
        assert_eq!(status(&conn, "operator-a").unwrap().len(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_alias_uses_physical_object_for_invalidation() {
        let home = tempfile::tempdir().unwrap();
        let lower = home.path().join("export.json");
        let upper = home.path().join("EXPORT.JSON");
        fs::write(
            &lower,
            r#"{"messages":[{"id":"a","role":"user","content":"one"}]}"#,
        )
        .unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        let first = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &lower,
            1,
        )
        .unwrap();
        fs::write(
            &upper,
            r#"{"messages":[{"id":"b","role":"user","content":"two"}]}"#,
        )
        .unwrap();
        let second = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &upper,
            2,
        )
        .unwrap();
        assert_ne!(first.batch_id, second.batch_id);
        let prior = status(&conn, "operator-a")
            .unwrap()
            .into_iter()
            .find(|batch| batch.batch_id == first.batch_id)
            .unwrap();
        assert_eq!(prior.state, "invalidated");
        assert!(review(&conn, "operator-a", &first.batch_id, 10).unwrap().is_empty());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn same_selector_atomic_replacement_invalidates_even_with_identical_bytes() {
        assert_selector_replacement_invalidates("one", "one");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn same_selector_atomic_replacement_invalidates_with_changed_bytes() {
        assert_selector_replacement_invalidates("one", "two");
    }

    #[cfg(any(unix, windows))]
    fn assert_selector_replacement_invalidates(first_text: &str, second_text: &str) {
        let home = tempfile::tempdir().unwrap();
        let selected = home.path().join("export.json");
        let replacement = home.path().join("replacement.json");
        let export = |text: &str| {
            format!(r#"{{"messages":[{{"id":"a","role":"user","content":"{text}"}}]}}"#)
        };
        fs::write(&selected, export(first_text)).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        let first = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &selected,
            1,
        )
        .unwrap();
        fs::write(&replacement, export(second_text)).unwrap();
        fs::remove_file(&selected).unwrap();
        fs::rename(&replacement, &selected).unwrap();
        let second = scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &selected,
            2,
        )
        .unwrap();
        assert_ne!(first.batch_id, second.batch_id);
        let prior = status(&conn, "operator-a")
            .unwrap()
            .into_iter()
            .find(|batch| batch.batch_id == first.batch_id)
            .unwrap();
        assert_eq!(prior.state, "invalidated");
        assert!(review(&conn, "operator-a", &first.batch_id, 10).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn invalid_candidate_aborts_the_entire_scan_transaction() {
        let home = tempfile::tempdir().unwrap();
        let source_path = home.path().join("export.json");
        let oversized_id = "x".repeat(MAX_CONVERSATION_ID_BYTES + 1);
        fs::write(
            &source_path,
            format!(concat!(
                r#"{{"messages":[{{"id":"a","session_id":"{oversized_id}","role":"user",#,
                r#""content":"one"}}]}}"#,
            )),
        ).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        assert!(scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &source_path,
            1,
        ).is_err());
        assert!(status(&conn, "operator-a").unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn candidate_insert_failure_rolls_back_the_entire_scan_transaction() {
        let home = tempfile::tempdir().unwrap();
        let source_path = home.path().join("export.json");
        fs::write(
            &source_path,
            r#"{"messages":[
                {"id":"a","session_id":"c","role":"user","content":"one"},
                {"id":"b","session_id":"c","role":"user","content":"two"}
            ]}"#,
        )
        .unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_second_history_candidate
             BEFORE INSERT ON history_onboarding_candidates WHEN NEW.position=1
             BEGIN SELECT RAISE(ABORT, 'injected candidate failure'); END;",
        )
        .unwrap();
        assert!(scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &source_path,
            1,
        )
        .is_err());
        let batches: i64 = conn.query_row(
            "SELECT COUNT(*) FROM history_onboarding_batches",
            [],
            |row| row.get(0),
        ).unwrap();
        let candidates: i64 = conn.query_row(
            "SELECT COUNT(*) FROM history_onboarding_candidates",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!((batches, candidates), (0, 0));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn captured_source_cannot_cross_operator_subjects() {
        let home = tempfile::tempdir().unwrap();
        let source_path = home.path().join("export.json");
        fs::write(
            &source_path,
            r#"{"messages":[{"id":"a","role":"user","content":"one"}]}"#,
        )
        .unwrap();
        let root = approve_import_root(home.path()).unwrap();
        let capability = issue_interactive_history_import_capability(
            root,
            [3_u8; 32],
            "owner",
            SourceFamily::OpenclawHistory.as_str(),
            Path::new("export.json"),
            MAX_SOURCE_BYTES,
        )
        .unwrap();
        let source = capture_verified_history_source(capability).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        assert!(scan_verified_source(
            &mut conn,
            "other",
            SourceFamily::OpenclawHistory,
            source,
            1,
        )
        .is_err());
        assert!(status(&conn, "owner").unwrap().is_empty());
        assert!(status(&conn, "other").unwrap().is_empty());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn captured_source_cannot_cross_source_families() {
        let home = tempfile::tempdir().unwrap();
        let source_path = home.path().join("export.json");
        fs::write(
            &source_path,
            r#"{"mapping":{}}"#,
        )
        .unwrap();
        let root = approve_import_root(home.path()).unwrap();
        let capability = issue_interactive_history_import_capability(
            root,
            [4_u8; 32],
            "owner",
            SourceFamily::ChatgptExport.as_str(),
            Path::new("export.json"),
            MAX_SOURCE_BYTES,
        )
        .unwrap();
        let source = capture_verified_history_source(capability).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        assert!(scan_verified_source(
            &mut conn,
            "owner",
            SourceFamily::OpenclawHistory,
            source,
            1,
        )
        .is_err());
        assert!(status(&conn, "owner").unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn scan_never_writes_profile_or_recall_surfaces() {
        let home = tempfile::tempdir().unwrap();
        let source_path = home.path().join("export.json");
        fs::write(
            &source_path,
            r#"{"messages":[{"id":"a","session_id":"c","role":"user","content":"one"}]}"#,
        ).unwrap();
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(HISTORY_ONBOARDING_V38_SQL).unwrap();
        conn.execute_batch(
            "CREATE TABLE idx_profile (value TEXT); \
             CREATE TABLE idx_groundtruth (statement TEXT); \
             CREATE TABLE raw_turns (text TEXT); \
             CREATE TABLE proactive_queue (payload TEXT);",
        ).unwrap();
        scan_fixture(
            &mut conn,
            "operator-a",
            SourceFamily::OpenclawHistory,
            &source_path,
            1,
        ).unwrap();
        for table in ["idx_profile", "idx_groundtruth", "raw_turns", "proactive_queue"] {
            let count: i64 = conn.query_row(
                &format!("SELECT COUNT(*) FROM {table}"),
                [],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(count, 0, "history onboarding touched {table}");
        }
    }
}
