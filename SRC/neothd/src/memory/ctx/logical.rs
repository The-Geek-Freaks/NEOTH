//! Explicit logical-document mutations, owned by the existing ctx transaction.
//! An epoch rejects stale requests; it does not grant permission to mutate.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::IndexReport;
use super::logical_request::{
    self, LogicalAction, LogicalMutationRequest, ValidatedLogicalMutation,
};

pub(crate) const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS ctx_logical_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    epoch INTEGER NOT NULL CHECK(epoch>=0)
);
INSERT OR IGNORE INTO ctx_logical_state(singleton,epoch) VALUES(1,0);
CREATE TABLE IF NOT EXISTS logical_documents (
    logical_id TEXT PRIMARY KEY NOT NULL,
    current_source_id INTEGER NOT NULL UNIQUE
        REFERENCES sources(id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    current_revision TEXT NOT NULL,
    current_event_id TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS sources_logical_identity
    ON sources(logical_id) WHERE logical_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS logical_document_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    logical_id TEXT NOT NULL REFERENCES logical_documents(logical_id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK(action IN ('register','revise','metadata_rename')),
    request_sha256 TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK(epoch>=0),
    source_id_at_result INTEGER NOT NULL,
    revision_at_result TEXT NOT NULL,
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS logical_document_events_owner ON logical_document_events(logical_id);
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalReport {
    pub logical_document_id: String,
    pub logical_event_id: String,
    pub action: String,
    pub authorization_epoch: i64,
    pub source_id: i64,
    pub content_revision_id: String,
    pub label: String,
    pub file_path: Option<String>,
    pub chunk_count: usize,
    pub indexed_bytes: usize,
    pub indexed_text_sha256: String,
    pub indexed_text_utf8_bytes: u64,
    /// Extractor assertion; None means the raw container is unknown.
    pub raw_container_sha256: Option<String>,
    pub indexed_ts: i64,
    pub previous_label: Option<String>,
    pub previous_file_path: Option<String>,
    pub current_event_id: String,
    pub replayed: bool,
    pub is_current: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogicalStatus {
    pub logical_document_id: String,
    pub authorization_epoch: i64,
    pub source_id: i64,
    pub content_revision_id: String,
    pub current_event_id: String,
    pub label: String,
    pub file_path: Option<String>,
}

pub const MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;

fn decode_request(request_json: &[u8]) -> Result<ValidatedLogicalMutation> {
    ensure!(
        request_json.len() <= MAX_REQUEST_BYTES,
        "logical request exceeds 10 MiB"
    );
    let request: LogicalMutationRequest =
        serde_json::from_slice(request_json).context("decode logical document request")?;
    logical_request::validate(request)
}

/// Pure preflight for callers that have not opened a store yet.
pub fn validate_request(request_json: &[u8]) -> Result<()> {
    decode_request(request_json).map(|_| ())
}

/// Share the owner's identity rules with callers before they open a store.
pub fn validate_identity(identity: &str) -> Result<()> {
    logical_request::validate_identifier("logical_document_id", identity)
}

/// This explicit caller-owned operation is not a watcher or a consent bypass.
pub fn apply(conn: &mut Connection, request_json: &[u8]) -> Result<LogicalReport> {
    let request = decode_request(request_json)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Must precede replay: a deleted old registration must never resurrect.
    ensure!(
        epoch(&tx)? == request.authorization_epoch(),
        "stale logical authorization epoch"
    );
    if let Some(report) = replay(&tx, &request)? {
        tx.commit()?;
        return Ok(report);
    }
    let current = current_state(&tx, request.logical_document_id())?;
    let expected = request.expected();
    match request.action() {
        LogicalAction::Register => ensure!(current.is_none(), "logical identity already exists"),
        LogicalAction::Revise | LogicalAction::MetadataRename => {
            let current = current
                .as_ref()
                .context("logical identity does not exist")?;
            let expected = expected.context("missing logical current-state guard")?;
            ensure!(
                current.source_id == expected.source_id
                    && current.content_revision_id == expected.content_revision_id
                    && current.current_event_id == expected.current_event_id,
                "stale logical current-state guard"
            );
        }
    }

    let mut report = match request.action() {
        LogicalAction::Register | LogicalAction::Revise => {
            let indexed = request
                .indexed_content()
                .context("missing indexed content")?;
            let index = indexed.request();
            let collision: Option<i64> = tx
                .query_row(
                    "SELECT id FROM sources WHERE label=?1",
                    [&index.label],
                    |row| row.get(0),
                )
                .optional()?;
            ensure!(
                collision.is_none()
                    || (request.action() == LogicalAction::Revise
                        && collision == current.as_ref().map(|state| state.source_id)),
                "logical target label belongs to another source"
            );
            if let Some(current) = &current {
                // Keep logical owner and historical ledger. Its source FK is deferred.
                super::delete_for_label(&tx, &current.label)?;
            }
            let indexed_report = super::index_document_in_transaction(&tx, index)?;
            let revision = request
                .content_revision_id()
                .context("missing content revision")?;
            tx.execute(
                "UPDATE sources SET logical_id=?1, logical_revision=?2 WHERE id=?3",
                params![
                    request.logical_document_id(),
                    revision,
                    indexed_report.source_id
                ],
            )?;
            if request.action() == LogicalAction::Register {
                tx.execute(
                    "INSERT INTO logical_documents(logical_id,current_source_id,current_revision,current_event_id)
                     VALUES(?1,?2,?3,?4)",
                    params![request.logical_document_id(), indexed_report.source_id, revision, request.logical_event_id()],
                )?;
            } else {
                tx.execute(
                    "UPDATE logical_documents SET current_source_id=?1,current_revision=?2,current_event_id=?3
                     WHERE logical_id=?4",
                    params![indexed_report.source_id, revision, request.logical_event_id(), request.logical_document_id()],
                )?;
            }
            from_index_report(
                &request,
                &indexed,
                indexed_report,
                index.file_path.clone(),
                revision,
            )
        }
        LogicalAction::MetadataRename => {
            let current = current.as_ref().context("missing current source")?;
            logical_request::lineage_metadata_bytes(
                &current.label,
                current.file_path.as_deref(),
                &request,
            )?;
            let (label, path) = request
                .rename_metadata()
                .context("missing rename metadata")?;
            let collision: Option<i64> = tx
                .query_row("SELECT id FROM sources WHERE label=?1", [label], |row| {
                    row.get(0)
                })
                .optional()?;
            ensure!(
                collision.is_none() || collision == Some(current.source_id),
                "logical target label belongs to another source"
            );
            let mut report = current_result(&tx, &current.current_event_id)?;
            ensure!(
                report.source_id == current.source_id
                    && report.content_revision_id == current.content_revision_id
                    && report.logical_document_id == request.logical_document_id()
                    && report.logical_event_id == current.current_event_id,
                "logical current result does not match source"
            );
            tx.execute(
                "UPDATE sources SET label=?1,file_path=?2 WHERE id=?3",
                params![label, path, current.source_id],
            )?;
            for table in ["chunks", "chunks_trigram"] {
                tx.execute(
                    &format!("UPDATE {table} SET file_path=?1 WHERE source_id=?2"),
                    params![path, current.source_id],
                )?;
            }
            tx.execute(
                "UPDATE logical_documents SET current_event_id=?1 WHERE logical_id=?2",
                params![request.logical_event_id(), request.logical_document_id()],
            )?;
            report.logical_event_id = request.logical_event_id().to_owned();
            report.action = action_name(request.action()).to_owned();
            report.authorization_epoch = request.authorization_epoch();
            report.previous_label = Some(current.label.clone());
            report.previous_file_path = current.file_path.clone();
            report.label = label.to_owned();
            report.file_path = path.map(str::to_owned);
            report
        }
    };
    report.current_event_id = request.logical_event_id().to_owned();
    report.replayed = false;
    report.is_current = true;
    tx.execute(
        "INSERT INTO logical_document_events(event_id,logical_id,action,request_sha256,epoch,
         source_id_at_result,revision_at_result,result_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            request.logical_event_id(),
            request.logical_document_id(),
            action_name(request.action()),
            request.request_semantics_sha256(),
            request.authorization_epoch(),
            report.source_id,
            report.content_revision_id,
            serde_json::to_string(&report)?
        ],
    )?;
    tx.commit().context("commit logical document mutation")?;
    Ok(report)
}

fn from_index_report(
    request: &ValidatedLogicalMutation,
    indexed: &logical_request::IndexedContentRef<'_>,
    report: IndexReport,
    path: Option<String>,
    revision: &str,
) -> LogicalReport {
    LogicalReport {
        logical_document_id: request.logical_document_id().to_owned(),
        logical_event_id: request.logical_event_id().to_owned(),
        action: action_name(request.action()).to_owned(),
        authorization_epoch: request.authorization_epoch(),
        source_id: report.source_id,
        content_revision_id: revision.to_owned(),
        label: report.label,
        file_path: path,
        chunk_count: report.chunk_count,
        indexed_bytes: report.bytes,
        indexed_text_sha256: indexed.indexed_text_sha256().to_owned(),
        indexed_text_utf8_bytes: indexed.indexed_text_utf8_bytes(),
        raw_container_sha256: indexed.raw_container_sha256().map(str::to_owned),
        indexed_ts: report.indexed_ts,
        previous_label: None,
        previous_file_path: None,
        current_event_id: request.logical_event_id().to_owned(),
        replayed: false,
        is_current: true,
    }
}

fn action_name(action: LogicalAction) -> &'static str {
    match action {
        LogicalAction::Register => "register",
        LogicalAction::Revise => "revise",
        LogicalAction::MetadataRename => "metadata_rename",
    }
}

fn current_result(conn: &Connection, event: &str) -> Result<LogicalReport> {
    let json: String = conn.query_row(
        "SELECT result_json FROM logical_document_events WHERE event_id=?1",
        [event],
        |row| row.get(0),
    )?;
    serde_json::from_str(&json).context("decode stored logical document result")
}

fn replay(
    tx: &Transaction<'_>,
    request: &ValidatedLogicalMutation,
) -> Result<Option<LogicalReport>> {
    let stored: Option<(String, String, String, String)> = tx.query_row(
        "SELECT logical_id,action,request_sha256,result_json FROM logical_document_events WHERE event_id=?1",
        [request.logical_event_id()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional()?;
    let Some((owner, action, digest, json)) = stored else {
        return Ok(None);
    };
    ensure!(
        owner == request.logical_document_id()
            && action == action_name(request.action())
            && digest == request.request_semantics_sha256(),
        "logical event reused with different semantics"
    );
    let current = current_state(tx, &owner)?.context("logical replay owner missing")?;
    let mut report: LogicalReport = serde_json::from_str(&json)?;
    ensure!(
        report.logical_document_id == owner
            && report.logical_event_id == request.logical_event_id(),
        "logical stored result identity mismatch"
    );
    report.current_event_id = current.current_event_id;
    report.is_current = report.current_event_id == report.logical_event_id;
    report.replayed = true;
    Ok(Some(report))
}

pub fn epoch(conn: &Connection) -> Result<i64> {
    let value: i64 = conn.query_row(
        "SELECT epoch FROM ctx_logical_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    ensure!(value >= 0, "invalid logical authorization epoch");
    Ok(value)
}

pub fn status(conn: &Connection, identity: &str) -> Result<Option<LogicalStatus>> {
    validate_identity(identity)?;
    current_state(conn, identity)
}

type LogicalCurrentStateRow = (
    i64,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn current_state(conn: &Connection, identity: &str) -> Result<Option<LogicalStatus>> {
    let current: Option<LogicalCurrentStateRow> = conn
        .query_row(
            "SELECT d.current_source_id,d.current_revision,d.current_event_id,s.label,s.file_path,
             s.logical_id,s.logical_revision FROM logical_documents d
             JOIN sources s ON s.id=d.current_source_id WHERE d.logical_id=?1",
            [identity],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((source_id, revision, event, label, path, source_owner, source_revision)) = current
    else {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM logical_documents WHERE logical_id=?1)",
            [identity],
            |row| row.get(0),
        )?;
        ensure!(!exists, "logical current source is missing");
        return Ok(None);
    };
    ensure!(
        source_owner.as_deref() == Some(identity)
            && source_revision.as_deref() == Some(revision.as_str()),
        "logical source projection mismatch"
    );
    Ok(Some(LogicalStatus {
        logical_document_id: identity.to_owned(),
        authorization_epoch: epoch(conn)?,
        source_id,
        content_revision_id: revision,
        current_event_id: event,
        label,
        file_path: path,
    }))
}

pub(super) fn refuse_legacy_replacement(tx: &Transaction<'_>, label: &str) -> Result<()> {
    let bound: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sources WHERE label=?1 AND logical_id IS NOT NULL)",
        [label],
        |row| row.get(0),
    )?;
    ensure!(
        !bound,
        "logical source requires an explicit guarded revision"
    );
    Ok(())
}

pub(super) fn remove_owner_for_source(tx: &Transaction<'_>, source_id: i64) -> Result<()> {
    // Cascade events from the logical owner, not from the replaced physical source.
    tx.execute(
        "DELETE FROM logical_documents WHERE current_source_id=?1",
        [source_id],
    )?;
    Ok(())
}

pub(super) fn advance_after_purge(tx: &Transaction<'_>, removed: usize) -> Result<()> {
    if removed > 0 {
        let next = epoch(tx)?
            .checked_add(1)
            .context("logical authorization epoch exhausted")?;
        ensure!(
            tx.execute(
                "UPDATE ctx_logical_state SET epoch=?1 WHERE singleton=1",
                [next]
            )? == 1,
            "logical authorization epoch row missing"
        );
    }
    Ok(())
}

/// Historical test fixtures must remove successor objects before downgrading.
#[cfg(test)]
pub(crate) fn remove_schema_for_legacy_fixture(conn: &Connection) -> Result<()> {
    let owners: i64 = conn.query_row("SELECT count(*) FROM logical_documents", [], |row| {
        row.get(0)
    })?;
    ensure!(
        owners == 0,
        "legacy fixture must not discard logical owners"
    );
    conn.execute_batch(
        "DROP TABLE logical_document_events;
         DROP INDEX sources_logical_identity;
         ALTER TABLE sources DROP COLUMN logical_revision;
         ALTER TABLE sources DROP COLUMN logical_id;
         DROP TABLE logical_documents;
         DROP TABLE ctx_logical_state;",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
