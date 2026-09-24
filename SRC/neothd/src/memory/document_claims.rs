//! B7 document-memory claim application.
//!
//! This module owns only the SQLite effect boundary. Approval, staging, and
//! audit delivery belong to their callers. The applied-once ledger and the
//! ground-truth mutation share one savepoint so a document replay cannot inflate
//! corroboration confidence or confirmed-count values.

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest as _, Sha256};

use crate::memory::groundtruth::{self, Source};

pub const MAX_DOCUMENT_CLAIMS: usize = 128;
pub const MAX_DOCUMENT_CLAIM_BYTES: usize = 4 * 1024;
pub const MAX_DOCUMENT_SCOPE_BYTES: usize = 128;
pub const MAX_DOCUMENT_PROPOSAL_ID_BYTES: usize = 128;

/// Fresh-schema and migration definition for the B7 applied-once ledger.
pub const DOCUMENT_CLAIM_SCHEMA_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS b7_applied_document_claim (
        source_bytes_sha256 TEXT NOT NULL
            CHECK(length(source_bytes_sha256) = 64 AND source_bytes_sha256 NOT GLOB '*[^0-9a-f]*'),
        claim_sha256 TEXT NOT NULL
            CHECK(length(claim_sha256) = 64 AND claim_sha256 NOT GLOB '*[^0-9a-f]*'),
        scope TEXT NOT NULL
            CHECK(length(scope) BETWEEN 1 AND 128),
        proposal_id TEXT NOT NULL
            CHECK(length(proposal_id) BETWEEN 1 AND 128),
        fact_id INTEGER CHECK(fact_id IS NULL OR fact_id > 0),
        applied_at_ns INTEGER NOT NULL,
        PRIMARY KEY (source_bytes_sha256, claim_sha256, scope),
        FOREIGN KEY (fact_id) REFERENCES idx_groundtruth(id) ON DELETE SET NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS idx_b7_applied_document_claim_fact
        ON b7_applied_document_claim(fact_id);
"#;

/// Approved, bounded memory payload supplied by the B7 coordinator.
/// Claims are untrusted until `groundtruth` corroborates them; B7 uses the
/// existing non-attested `BulkText` source and never adds a document source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentClaimBatch {
    pub proposal_id: String,
    pub source_bytes_sha256: String,
    pub scope: String,
    pub claims: Vec<String>,
}

/// Compact effect receipt. It deliberately has no raw claim text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentClaimApplyReceipt {
    pub fact_ids: Vec<i64>,
    pub applied_count: usize,
    pub replayed_count: usize,
}

/// Apply an approved document claim batch once per `(source, claim, scope)`.
///
/// The savepoint works on a bare connection and inside a caller-owned SQLite
/// transaction. It does not emit an audit/WAL record; the approved coordinator
/// records that separate effect after this database boundary succeeds.
pub fn apply_document_claim_batch(
    conn: &Connection,
    batch: &DocumentClaimBatch,
    now_ns: i64,
) -> Result<DocumentClaimApplyReceipt> {
    let claims = validate_batch(batch)?;
    conn.execute_batch("SAVEPOINT b7_document_claim_batch")
        .context("begin B7 document-claim savepoint")?;

    let result: Result<DocumentClaimApplyReceipt> = (|| {
        let mut fact_ids = Vec::with_capacity(claims.len());
        let mut applied_count = 0usize;
        let mut replayed_count = 0usize;

        for claim in claims {
            let claim_sha256 = claim_sha256(claim);
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO b7_applied_document_claim \
                 (source_bytes_sha256, claim_sha256, scope, proposal_id, fact_id, applied_at_ns) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![
                    &batch.source_bytes_sha256,
                    &claim_sha256,
                    &batch.scope,
                    &batch.proposal_id,
                    now_ns,
                ],
            )?;
            if inserted == 0 {
                let fact_id: i64 = conn
                    .query_row(
                        "SELECT fact_id FROM b7_applied_document_claim \
                         WHERE source_bytes_sha256 = ?1 AND claim_sha256 = ?2 AND scope = ?3",
                        params![&batch.source_bytes_sha256, &claim_sha256, &batch.scope],
                        |row| row.get::<_, Option<i64>>(0),
                    )
                    .optional()?
                    .flatten()
                    .context("B7 previously applied fact removed; replay refused")?;
                fact_ids.push(fact_id);
                replayed_count += 1;
                continue;
            }

            let fact_id = groundtruth::insert(conn, claim, &Source::BulkText, &batch.scope, now_ns)?;
            let updated = conn.execute(
                "UPDATE b7_applied_document_claim SET fact_id = ?1 \
                 WHERE source_bytes_sha256 = ?2 AND claim_sha256 = ?3 AND scope = ?4 AND fact_id IS NULL",
                params![fact_id, &batch.source_bytes_sha256, &claim_sha256, &batch.scope],
            )?;
            ensure!(updated == 1, "B7 applied-once ledger reservation was not completed");
            fact_ids.push(fact_id);
            applied_count += 1;
        }
        Ok(DocumentClaimApplyReceipt { fact_ids, applied_count, replayed_count })
    })();

    match result {
        Ok(receipt) => match conn.execute_batch("RELEASE SAVEPOINT b7_document_claim_batch") {
            Ok(()) => Ok(receipt),
            Err(release_error) => {
                let _ = conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT b7_document_claim_batch; \
                     RELEASE SAVEPOINT b7_document_claim_batch",
                );
                Err(anyhow::Error::new(release_error).context("commit B7 document-claim savepoint"))
            }
        },
        Err(error) => {
            let rollback = conn.execute_batch(
                "ROLLBACK TO SAVEPOINT b7_document_claim_batch; \
                 RELEASE SAVEPOINT b7_document_claim_batch",
            );
            if let Err(rollback_error) = rollback {
                return Err(error.context(format!(
                    "rollback B7 document-claim savepoint failed: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

fn validate_batch(batch: &DocumentClaimBatch) -> Result<Vec<&str>> {
    ensure!(is_sha256_hex(&batch.source_bytes_sha256), "B7 source SHA-256 must be 64 lowercase hex characters");
    ensure!(is_metadata(&batch.scope, MAX_DOCUMENT_SCOPE_BYTES), "B7 claim scope must be non-empty, trimmed, and at most {MAX_DOCUMENT_SCOPE_BYTES} bytes");
    ensure!(is_metadata(&batch.proposal_id, MAX_DOCUMENT_PROPOSAL_ID_BYTES), "B7 proposal id must be non-empty, trimmed, and at most {MAX_DOCUMENT_PROPOSAL_ID_BYTES} bytes");
    ensure!(!batch.claims.is_empty() && batch.claims.len() <= MAX_DOCUMENT_CLAIMS, "B7 document claim count must be between 1 and {MAX_DOCUMENT_CLAIMS}");

    let mut claims = Vec::with_capacity(batch.claims.len());
    for claim in &batch.claims {
        let trimmed = claim.trim();
        ensure!(!trimmed.is_empty() && trimmed.len() <= MAX_DOCUMENT_CLAIM_BYTES, "B7 document claim must be non-empty after trimming and at most {MAX_DOCUMENT_CLAIM_BYTES} bytes");
        claims.push(trimmed);
    }
    Ok(claims)
}

fn is_metadata(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value == value.trim() && value.len() <= maximum
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn claim_sha256(claim: &str) -> String {
    hex::encode(Sha256::digest(claim.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE idx_groundtruth (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, statement TEXT NOT NULL, source TEXT NOT NULL, \
                scope TEXT NOT NULL, asserted_at INTEGER NOT NULL, revoked_at INTEGER, \
                fact_state TEXT NOT NULL DEFAULT 'verified', source_weight TEXT NOT NULL DEFAULT '{}', \
                confidence REAL NOT NULL DEFAULT 0.5, evidence TEXT NOT NULL DEFAULT '[]', \
                maturity TEXT NOT NULL DEFAULT 'emerging', confirmed_count INTEGER NOT NULL DEFAULT 0\
             );",
        ).unwrap();
        conn.execute_batch(DOCUMENT_CLAIM_SCHEMA_SQL).unwrap();
        conn
    }

    fn batch(source: char, claims: &[&str]) -> DocumentClaimBatch {
        DocumentClaimBatch {
            proposal_id: "b7-proposal-1".to_owned(),
            source_bytes_sha256: source.to_string().repeat(64),
            scope: "document-review".to_owned(),
            claims: claims.iter().map(|claim| (*claim).to_owned()).collect(),
        }
    }

    #[test]
    fn invalid_batch_never_creates_a_ledger_or_fact_row() {
        let conn = conn();
        let mut invalid = batch('A', &["fact"]);
        invalid.scope = " ".to_owned();
        assert!(apply_document_claim_batch(&conn, &invalid, 1).is_err());
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM b7_applied_document_claim", [], |row| row.get(0)).unwrap(), 0);
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0)).unwrap(), 0);
    }
    #[test]
    fn first_apply_then_same_document_replay_does_not_inflate_fact() {
        let conn = conn();
        let batch = batch('a', &["  retain this fact  "]);
        let first = apply_document_claim_batch(&conn, &batch, 1).unwrap();
        let replay = apply_document_claim_batch(&conn, &batch, 2).unwrap();
        assert_eq!(first.applied_count, 1);
        assert_eq!(replay.replayed_count, 1);
        assert_eq!(first.fact_ids, replay.fact_ids);
        let state: (f64, i64) = conn.query_row(
            "SELECT confidence, confirmed_count FROM idx_groundtruth", [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(state, (0.5, 0));
    }

    #[test]
    fn different_document_corroborates_once_then_replays() {
        let conn = conn();
        apply_document_claim_batch(&conn, &batch('a', &["retain this fact"]), 1).unwrap();
        let second = apply_document_claim_batch(&conn, &batch('b', &["retain this fact"]), 2).unwrap();
        let replay = apply_document_claim_batch(&conn, &batch('b', &["retain this fact"]), 3).unwrap();
        assert_eq!(second.applied_count, 1);
        assert_eq!(replay.applied_count, 0);
        let state: (f64, i64) = conn.query_row(
            "SELECT confidence, confirmed_count FROM idx_groundtruth", [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert!(state.0 > 0.5);
        assert_eq!(state.1, 1);
    }

    #[test]
    fn batch_failure_rolls_back_ledger_and_fact_effects() {
        let conn = conn();
        conn.execute_batch("CREATE TRIGGER fail_b7_fact_link BEFORE UPDATE OF fact_id ON b7_applied_document_claim BEGIN SELECT RAISE(ABORT, 'injected B7 failure'); END;").unwrap();
        assert!(apply_document_claim_batch(&conn, &batch('a', &["one", "two"]), 1).is_err());
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM b7_applied_document_claim", [], |row| row.get(0)).unwrap(), 0);
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0)).unwrap(), 0);
    }

    #[test]
    fn caller_owned_transaction_can_roll_back_the_whole_batch() {
        let conn = conn();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        apply_document_claim_batch(&conn, &batch('a', &["fact"]), 1).unwrap();
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM b7_applied_document_claim", [], |row| row.get(0)).unwrap(), 0);
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0)).unwrap(), 0);
    }

    #[test]
    fn production_store_omi_hard_purge_keeps_tombstone_and_refuses_replay() {
        use crate::memory::omi::{
            OmiCommitOptions, OmiConversation, commit_conversation, purge_conversation,
        };

        let root = tempfile::tempdir().unwrap();
        let mut conn = crate::memory::store::open(&root.path().join("views.db")).unwrap();
        crate::coding::store::ensure_schema(&conn).unwrap();
        assert_eq!(conn.query_row::<i64, _, _>("PRAGMA foreign_keys", [], |row| row.get(0)).unwrap(), 1);
        let source_id = "conv-b7";
        let statement = "OMI summary held for B7 purge regression.";
        let conversation = OmiConversation {
            source_id: source_id.to_owned(), revision: "r1".to_owned(), status: "completed".to_owned(),
            source: None, language: None, started_at_ms: None, finished_at_ms: None, call_id: None,
            title: None, summary: Some(statement.to_owned()), metadata: None,
            segments: Vec::new(), media: Vec::new(), actions: Vec::new(),
        };
        let omi = commit_conversation(&mut conn, &conversation, OmiCommitOptions::default(), 1).unwrap();
        let expected_fact_id = omi.groundtruth_id.unwrap();
        let batch = DocumentClaimBatch {
            proposal_id: "b7-omi-purge".to_owned(), source_bytes_sha256: "a".repeat(64),
            scope: format!("omi:{source_id}"), claims: vec![statement.to_owned()],
        };
        let applied = apply_document_claim_batch(&conn, &batch, 2).unwrap();
        assert_eq!(applied.fact_ids, vec![expected_fact_id]);
        assert_eq!(purge_conversation(&mut conn, source_id, 3).unwrap().groundtruth, 1);
        let tombstone: Option<i64> = conn.query_row(
            "SELECT fact_id FROM b7_applied_document_claim", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(tombstone, None);
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0)).unwrap(), 0);
        let replay = apply_document_claim_batch(&conn, &batch, 4).unwrap_err();
        assert!(format!("{replay:#}").contains("previously applied fact removed; replay refused"));
        assert_eq!(conn.query_row::<i64, _, _>("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0)).unwrap(), 0);
    }
    #[test]
    fn reopened_database_replays_from_durable_ledger() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("b7.db");
        let first_conn = Connection::open(&path).unwrap();
        first_conn.execute_batch(
            "CREATE TABLE idx_groundtruth (\
                id INTEGER PRIMARY KEY AUTOINCREMENT, statement TEXT NOT NULL, source TEXT NOT NULL, \
                scope TEXT NOT NULL, asserted_at INTEGER NOT NULL, revoked_at INTEGER, \
                fact_state TEXT NOT NULL DEFAULT 'verified', source_weight TEXT NOT NULL DEFAULT '{}', \
                confidence REAL NOT NULL DEFAULT 0.5, evidence TEXT NOT NULL DEFAULT '[]', \
                maturity TEXT NOT NULL DEFAULT 'emerging', confirmed_count INTEGER NOT NULL DEFAULT 0\
             );",
        ).unwrap();
        first_conn.execute_batch(DOCUMENT_CLAIM_SCHEMA_SQL).unwrap();
        let payload = batch('a', &["fact"]);
        apply_document_claim_batch(&first_conn, &payload, 1).unwrap();
        drop(first_conn);
        let reopened = Connection::open(&path).unwrap();
        let replay = apply_document_claim_batch(&reopened, &payload, 2).unwrap();
        assert_eq!(replay.applied_count, 0);
        assert_eq!(replay.replayed_count, 1);
    }
}
