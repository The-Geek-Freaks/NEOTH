//! Foreign-event indexer for accepted cluster gossip.
//!
//! Current main persists accepted peer frames in `idx_foreign_events` without a
//! `processed` column so the table stays a queryable backup surface. This module
//! keeps that contract: it records local processing state in
//! `idx_foreign_indexed_events` and never deletes or mutates foreign rows.
//!
//! Canonical protocol rows are already materialized transactionally by
//! `cluster::durable_sync` into `mesh_sync_materialized`; this background
//! indexer only marks those rows observed and never replays peer-local ids.
//! Legacy effects are deliberately narrow:
//! - `0x90` / `0x91`: NO-OP in the gossip path — peer `event_id` fields are the
//!   peer's own local SQLite autoincrements and have no stable mapping to our
//!   `idx_episode.event_id` (also a local autoincrement). `idx_episode` carries no
//!   `origin_peer_pk` column, so option (i) provenance-gated lookup is impossible.
//!   Option (ii) chosen: log and skip rather than mutate an unrelated local row.
//!   (Fix: NEOTH-AUDIT-MESH-IDENTITY-RETRY-01.)
//! - `0x92`: same NO-OP rationale as 0x90/0x91.
//! - `0x98`: in the gossip indexer loop, skipped (groundtruth IDs are local
//!   SQLite autoincrements, not peer-stable). The same-origin restore path
//!   (`DES-13-AUTO-RESTORE-01`) uses `apply_groundtruth_revoke` directly.
//! - `0x94`, `0x13`, unknown, malformed payloads: mark indexed, no local write.
//!
//! Foreign events never create local episodes or groundtruth facts.
//!
//! # pub(crate) conflict helpers
//!
//! `apply_episode_boost`, `apply_episode_decay_sql`, and `apply_groundtruth_revoke`
//! are extracted as `pub(crate)` so the restore path in `cli/cluster.rs` (via
//! `cluster::wal_sync::apply_restore_frame`) can reuse the same SQL logic without
//! duplication.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Deserialize;
use tracing::{debug, trace, warn};

const BATCH_LIMIT: i64 = 64;
const POLL_INTERVAL: Duration = Duration::from_secs(30);
const IMPORTANCE_MIN: f64 = 0.0;
const IMPORTANCE_MAX: f64 = 1.0;
const DECAY_FLOOR: f64 = 0.10;

// Peer payloads carry more fields (kind/day/ts/from_importance/reason/…);
// serde ignores unknown fields, so only what the indexer consumes is declared.
// pub(crate) so the restore path in wal_sync.rs can deserialize the same shapes.
#[derive(Debug, Deserialize)]
pub(crate) struct EpisodeConsolidatedPayload {
    pub(crate) event_id: i64,
    pub(crate) importance: f64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EpisodePromotedPayload {
    pub(crate) event_id: i64,
    pub(crate) to_importance: f64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EpisodeArchivedPayload {
    pub(crate) event_id: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GroundtruthRevokedPayload {
    /// Local SQLite rowid in `idx_groundtruth` of the fact to revoke.
    pub(crate) id: i64,
}

#[derive(Debug)]
struct PendingRow {
    id: i64,
    event_type: u8,
    /// Frame body. Currently unused: the cross-peer episode boost/decay handlers
    /// are NO-OPs (MESH-IDENTITY-RETRY-01 — a peer's numeric episode id can't be
    /// safely resolved to a local row). Retained on the row so the payload is
    /// available once a peer→local episode mapping lands and the handlers can
    /// decode it again.
    #[allow(dead_code)]
    payload: Vec<u8>,
    /// Peer that produced this event (`idx_foreign_events.origin_peer_pk`).
    /// Threaded through for log messages when skipping cross-peer episode ops.
    origin_peer_pk: String,
    envelope_version: u16,
    has_canonical_content: bool,
}

/// Apply up to 64 not-yet-indexed foreign events to local recall surfaces.
///
/// Returns the number of rows marked indexed in this pass.
///
/// Fix NEOTH-AUDIT-MESH-IDENTITY-RETRY-01 (b): retryable per-row errors are
/// logged and the row is left unprocessed so it will be re-fetched next tick.
/// Terminal no-ops (unknown type, malformed payload, cross-peer episode ops)
/// return `Ok(())` from dispatch and are always marked indexed.
pub fn process_pending(conn: &Connection) -> Result<usize> {
    ensure_marker_table(conn)?;
    let rows = fetch_pending(conn)?;
    let mut processed = 0usize;

    for row in rows {
        match process_one(conn, &row) {
            Ok(()) => processed += 1,
            Err(e) => {
                warn!(
                    foreign_event_id = row.id,
                    event_type = row.event_type,
                    error = %e,
                    "foreign_indexer: retryable error — row left unprocessed for next tick"
                );
                // Do NOT increment `processed`; row will be re-fetched next tick.
            }
        }
    }

    Ok(processed)
}

fn ensure_marker_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_foreign_indexed_events (
            foreign_event_id INTEGER PRIMARY KEY,
            indexed_at       INTEGER NOT NULL
        );
        "#,
    )
    .context("foreign_indexer: create marker table")
}

fn fetch_pending(conn: &Connection) -> Result<Vec<PendingRow>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT e.id, e.event_type, e.payload, e.origin_peer_pk, \
                    e.envelope_version, e.content_payload IS NOT NULL \
             FROM idx_foreign_events e \
             LEFT JOIN idx_foreign_indexed_events i \
               ON i.foreign_event_id = e.id \
             WHERE i.foreign_event_id IS NULL \
             ORDER BY e.received_at ASC, e.id ASC \
             LIMIT ?1",
        )
        .context("foreign_indexer: prepare fetch_pending")?;

    stmt.query_map([BATCH_LIMIT], |r| {
        let raw_event_type: i64 = r.get(1)?;
        Ok(PendingRow {
            id: r.get(0)?,
            event_type: u8::try_from(raw_event_type).unwrap_or(u8::MAX),
            payload: r.get(2)?,
            origin_peer_pk: r.get(3)?,
            envelope_version: u16::try_from(r.get::<_, i64>(4)?).unwrap_or(u16::MAX),
            has_canonical_content: r.get::<_, i64>(5)? != 0,
        })
    })
    .context("foreign_indexer: query fetch_pending")?
    .collect::<rusqlite::Result<Vec<_>>>()
    .context("foreign_indexer: collect fetch_pending")
}

fn process_one(conn: &Connection, row: &PendingRow) -> Result<()> {
    conn.execute_batch("SAVEPOINT foreign_indexer_row")
        .context("foreign_indexer: begin row savepoint")?;

    let result = process_one_inner(conn, row);
    match result {
        Ok(()) => conn
            .execute_batch("RELEASE foreign_indexer_row")
            .context("foreign_indexer: release row savepoint"),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO foreign_indexer_row");
            let _ = conn.execute_batch("RELEASE foreign_indexer_row");
            Err(e)
        }
    }
}

fn process_one_inner(conn: &Connection, row: &PendingRow) -> Result<()> {
    if marker_exists(conn, row.id)? {
        return Ok(());
    }

    // Fix NEOTH-AUDIT-MESH-IDENTITY-RETRY-01 (b): do NOT mark processed on Err.
    // dispatch_foreign_row returns Ok(()) for all terminal no-ops (unknown type,
    // malformed payload, or skipped cross-peer operations). It propagates Err only
    // for retryable infrastructure failures (e.g. SQLite busy/locked).
    // Marking processed on a retryable Err would permanently suppress the row.
    dispatch_foreign_row(conn, row)?;

    conn.execute(
        "INSERT OR IGNORE INTO idx_foreign_indexed_events \
         (foreign_event_id, indexed_at) VALUES (?1, ?2)",
        rusqlite::params![row.id, crate::time::now_unix_i64()],
    )
    .context("foreign_indexer: mark indexed")?;

    Ok(())
}

fn marker_exists(conn: &Connection, foreign_event_id: i64) -> Result<bool> {
    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM idx_foreign_indexed_events WHERE foreign_event_id = ?1",
            [foreign_event_id],
            |r| r.get(0),
        )
        .context("foreign_indexer: check marker")?;
    Ok(n != 0)
}

fn dispatch_foreign_row(conn: &Connection, row: &PendingRow) -> Result<()> {
    if row.envelope_version == crate::cluster::gossip_wire::SYNC_ENVELOPE_VERSION
        && row.has_canonical_content
    {
        trace!(
            foreign_event_id = row.id,
            origin_peer_pk = %row.origin_peer_pk,
            "foreign_indexer: canonical v5 content already materialized transactionally"
        );
        return Ok(());
    }
    match row.event_type {
        crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED => {
            handle_episode_consolidated(conn, row)
        }
        crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED => handle_episode_promoted(conn, row),
        crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED => handle_episode_decay(conn, row),
        crate::wal::events::EVENT_TYPE_CONSOLIDATION_PASS => {
            trace!(
                foreign_event_id = row.id,
                "foreign_indexer: CONSOLIDATION_PASS no-op"
            );
            Ok(())
        }
        crate::wal::events::EVENT_TYPE_GROUNDTRUTH_REVOKED => {
            trace!(
                foreign_event_id = row.id,
                "foreign_indexer: GROUNDTRUTH_REVOKED skipped; peer payload uses local-only ids"
            );
            Ok(())
        }
        crate::wal::events::EVENT_TYPE_UPDATE_RAN => {
            trace!(
                foreign_event_id = row.id,
                "foreign_indexer: UPDATE_RAN capability signal no-op"
            );
            Ok(())
        }
        other => {
            trace!(
                foreign_event_id = row.id,
                event_type = other,
                "foreign_indexer: unknown event type no-op"
            );
            Ok(())
        }
    }
}

// foreign_frame_payload removed: all gossip-path episode handlers now skip
// frame decoding (they are NO-OPs; see fix NEOTH-AUDIT-MESH-IDENTITY-RETRY-01 a).

fn handle_episode_consolidated(_conn: &Connection, row: &PendingRow) -> Result<()> {
    // Fix NEOTH-AUDIT-MESH-IDENTITY-RETRY-01 (a).
    //
    // `EpisodeConsolidatedPayload.event_id` is the PEER's local SQLite autoincrement.
    // It has no stable relationship to our `idx_episode.event_id` (our own autoincrement).
    // Applying a boost with the peer's numeric id would mutate an UNRELATED local row.
    //
    // Option (ii) chosen: skip cross-peer boost; log and return Ok(()).
    // Option (i) (provenance-gated lookup via origin_peer_pk) is not possible because
    // `idx_episode` has no `origin_peer_pk` column — there is no join path from a peer
    // episode id to the local row that originated from that same peer.
    //
    // A skipped mutation is safe; a wrong mutation is data corruption.
    trace!(
        foreign_event_id = row.id,
        origin_peer_pk = %row.origin_peer_pk,
        "foreign_indexer: EPISODE_CONSOLIDATED skipped — peer episode_id not resolvable to local idx_episode row"
    );
    Ok(())
}

fn handle_episode_promoted(_conn: &Connection, row: &PendingRow) -> Result<()> {
    // Same rationale as handle_episode_consolidated (fix NEOTH-AUDIT-MESH-IDENTITY-RETRY-01 a).
    // Peer event_id is not resolvable to a local idx_episode row.
    trace!(
        foreign_event_id = row.id,
        origin_peer_pk = %row.origin_peer_pk,
        "foreign_indexer: EPISODE_PROMOTED skipped — peer episode_id not resolvable to local idx_episode row"
    );
    Ok(())
}

// boost_episode_importance (private trace wrapper) removed: no longer called
// from any gossip-path handler. apply_episode_boost is still pub(crate) and
// used by the restore path (DES-13-AUTO-RESTORE-01).

// ---------------------------------------------------------------------------
// pub(crate) conflict helpers — shared by gossip indexer AND restore path
// ---------------------------------------------------------------------------

/// Outcome of applying a peer importance boost to a local episode.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BoostOutcome {
    /// Local importance was raised to the peer value.
    Applied,
    /// Local importance was already >= peer value; no write performed.
    Idempotent,
    /// No `idx_episode` row exists for `event_id`.
    Missing,
}

/// Boost a local episode's importance with the MAX rule.
///
/// Uses read-then-conditional-write so callers (gossip loop and restore path)
/// can distinguish Applied/Idempotent/Missing for dry-run reporting without a
/// second SELECT. With `dry_run`, the same comparison runs but the UPDATE is
/// skipped. Single-threaded CLI invocation makes this safe.
pub(crate) fn apply_episode_boost(
    conn: &Connection,
    event_id: i64,
    peer_importance: f64,
    dry_run: bool,
) -> Result<BoostOutcome> {
    if !peer_importance.is_finite() {
        return Ok(BoostOutcome::Idempotent);
    }
    let importance = peer_importance.clamp(IMPORTANCE_MIN, IMPORTANCE_MAX);
    let local_imp: Option<f64> = match conn.query_row(
        "SELECT importance FROM idx_episode WHERE event_id = ?1",
        [event_id],
        |r| r.get::<_, f64>(0),
    ) {
        Ok(v) => Some(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(anyhow::anyhow!("apply_episode_boost: {e}")),
    };
    let local = match local_imp {
        None => return Ok(BoostOutcome::Missing),
        Some(v) => v,
    };
    if local >= importance {
        return Ok(BoostOutcome::Idempotent);
    }
    if dry_run {
        return Ok(BoostOutcome::Applied);
    }
    conn.execute(
        "UPDATE idx_episode SET importance = ?1 WHERE event_id = ?2",
        rusqlite::params![importance, event_id],
    )
    .context("apply_episode_boost: update importance")?;
    Ok(BoostOutcome::Applied)
}

/// Soft-decay a local episode's importance, floored at [`DECAY_FLOOR`].
///
/// Returns `true` when the local row was found and SQL executed,
/// `false` when no row exists for `event_id`.
pub(crate) fn apply_episode_decay_sql(conn: &Connection, event_id: i64) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM idx_episode WHERE event_id = ?1",
            [event_id],
            |r| r.get(0),
        )
        .context("apply_episode_decay_sql: check existence")?;
    if count == 0 {
        return Ok(false);
    }
    conn.execute(
        "UPDATE idx_episode \
         SET importance = MIN(importance, MAX(importance * 0.5, ?1)) \
         WHERE event_id = ?2",
        rusqlite::params![DECAY_FLOOR, event_id],
    )
    .context("apply_episode_decay_sql: update")?;
    Ok(true)
}

fn handle_episode_decay(_conn: &Connection, row: &PendingRow) -> Result<()> {
    // Same rationale as handle_episode_consolidated (fix NEOTH-AUDIT-MESH-IDENTITY-RETRY-01 a).
    // Peer event_id is not resolvable to a local idx_episode row.
    trace!(
        foreign_event_id = row.id,
        origin_peer_pk = %row.origin_peer_pk,
        "foreign_indexer: EPISODE_ARCHIVED skipped — peer episode_id not resolvable to local idx_episode row"
    );
    Ok(())
}

/// Outcome of applying a groundtruth revocation.
///
/// Used by the restore path (`DES-13-AUTO-RESTORE-01`). The gossip indexer
/// loop does NOT invoke this — 0x98 events are skipped there because
/// groundtruth IDs are local SQLite autoincrements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GroundtruthRevokeOutcome {
    /// `revoked_at` was set on the matching row.
    Applied,
    /// No `idx_groundtruth` row with the given id.
    Missing,
    /// Row already has `revoked_at IS NOT NULL`.
    AlreadyRevoked,
    /// Row has `fact_state = 'contradicted'` — closed fact, skip per conflict matrix.
    Contradicted,
}

/// Revoke a groundtruth fact by setting `revoked_at` if the row is eligible.
///
/// Eligibility (conflict matrix):
/// - Row must exist.
/// - `revoked_at` must be NULL.
/// - `fact_state` must NOT be `'contradicted'`.
///
/// Never creates new rows. Hard constraint: 0x98 may only SET `revoked_at`
/// on an existing row where `revoked_at IS NULL`.
pub(crate) fn apply_groundtruth_revoke(
    conn: &Connection,
    gt_row_id: i64,
    received_at: i64,
) -> Result<GroundtruthRevokeOutcome> {
    let row = conn.query_row(
        "SELECT revoked_at, fact_state FROM idx_groundtruth WHERE id = ?1",
        [gt_row_id],
        |r| {
            let revoked_at: Option<i64> = r.get(0)?;
            let fact_state: String = r.get(1)?;
            Ok((revoked_at, fact_state))
        },
    );
    let (revoked_at, fact_state) = match row {
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(GroundtruthRevokeOutcome::Missing);
        }
        Err(e) => return Err(anyhow::anyhow!("apply_groundtruth_revoke: {e}")),
        Ok(pair) => pair,
    };
    if revoked_at.is_some() {
        return Ok(GroundtruthRevokeOutcome::AlreadyRevoked);
    }
    if fact_state == "contradicted" {
        return Ok(GroundtruthRevokeOutcome::Contradicted);
    }
    conn.execute(
        "UPDATE idx_groundtruth SET revoked_at = ?1 \
         WHERE id = ?2 AND revoked_at IS NULL",
        rusqlite::params![received_at, gt_row_id],
    )
    .context("apply_groundtruth_revoke: set revoked_at")?;
    Ok(GroundtruthRevokeOutcome::Applied)
}

/// Spawn the foreign-event indexer loop.
///
/// The task is WAL-free. SQLite is opened inside `spawn_blocking` per tick so a
/// `rusqlite::Connection` never crosses an async boundary.
pub struct ForeignIndexerHandle {
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl ForeignIndexerHandle {
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        if let Err(e) = self.task.await {
            warn!(error = %e, "foreign_indexer: shutdown join failed");
        }
    }
}

pub fn spawn_foreign_indexer(neoth_home: PathBuf) -> ForeignIndexerHandle {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
            }

            let home = neoth_home.clone();
            let result = tokio::task::spawn_blocking(move || -> Result<usize> {
                let conn = crate::memory::store::open(&home.join("views.db"))
                    .context("foreign_indexer: open views.db")?;
                process_pending(&conn)
            })
            .await;

            match result {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => debug!(processed = n, "foreign_indexer: tick indexed rows"),
                Ok(Err(e)) => warn!(error = %e, "foreign_indexer: tick error"),
                Err(e) => warn!(error = %e, "foreign_indexer: blocking task failed"),
            }
        }
    });

    ForeignIndexerHandle {
        shutdown: shutdown_tx,
        task,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS idx_foreign_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                origin_peer_pk  TEXT    NOT NULL,
                stable_node_id  TEXT    NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
                auth_epoch      INTEGER NOT NULL DEFAULT 1 CHECK(auth_epoch > 0),
                membership_epoch INTEGER NOT NULL DEFAULT 1 CHECK(membership_epoch > 0),
                fence_state     TEXT NOT NULL DEFAULT 'legacy_unbound'
                                     CHECK(fence_state IN ('active','legacy_unbound')),
                origin_seq      INTEGER NOT NULL,
                event_type      INTEGER NOT NULL,
                payload         BLOB    NOT NULL,
                received_at     INTEGER NOT NULL,
                envelope_version INTEGER NOT NULL DEFAULT 0,
                content_sha256  BLOB,
                content_kind    TEXT,
                content_payload BLOB,
                UNIQUE (stable_node_id, auth_epoch, origin_seq)
            );
            CREATE INDEX IF NOT EXISTS idx_foreign_events_peer
                ON idx_foreign_events (stable_node_id, auth_epoch, received_at DESC);

            CREATE TABLE IF NOT EXISTS idx_episode (
                event_id   INTEGER PRIMARY KEY,
                importance REAL    NOT NULL DEFAULT 0.5
            );

            CREATE TABLE IF NOT EXISTS idx_groundtruth (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                revoked_at INTEGER,
                fact_state TEXT NOT NULL DEFAULT 'verified'
            );
            "#,
        )
        .unwrap();
        conn
    }

    fn insert_foreign_event(conn: &Connection, event_type: u8, payload: &[u8]) -> i64 {
        let next_seq: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(origin_seq), 0) + 1 \
                 FROM idx_foreign_events WHERE origin_peer_pk = 'peer1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let header = crate::wal::HeaderBuilder::new(event_type, payload).build();
        let frame = crate::wal::frame::encode_frame(&header, payload);
        conn.execute(
            "INSERT INTO idx_foreign_events \
             (origin_peer_pk, origin_seq, event_type, payload, received_at) \
             VALUES ('peer1', ?1, ?2, ?3, ?4)",
            rusqlite::params![
                next_seq,
                event_type as i64,
                frame,
                1_700_000_000_i64 + next_seq
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn indexed_count(conn: &Connection) -> i64 {
        conn.query_row("SELECT count(*) FROM idx_foreign_indexed_events", [], |r| {
            r.get(0)
        })
        .unwrap()
    }

    #[test]
    fn empty_table_is_noop_and_creates_marker_table() {
        let conn = open_test_db();
        assert_eq!(process_pending(&conn).unwrap(), 0);
        assert_eq!(indexed_count(&conn), 0);
    }

    // Fix NEOTH-AUDIT-MESH-IDENTITY-RETRY-01 (a): cross-peer episode events must NOT
    // mutate local idx_episode rows. The peer's event_id is the peer's own SQLite
    // autoincrement and has no mapping to our idx_episode.event_id.
    #[test]
    fn cross_peer_episode_consolidated_is_noop_local_importance_unchanged() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (42, 0.4)",
            [],
        )
        .unwrap();
        let payload =
            serde_json::json!({"event_id": 42, "importance": 0.8, "ts": 1000}).to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            payload.as_bytes(),
        );

        assert_eq!(process_pending(&conn).unwrap(), 1);
        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 42",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // Must remain 0.4 — gossip boost must NOT apply the peer's 0.8 to our row.
        assert!(
            (importance - 0.4).abs() < 1e-9,
            "cross-peer boost must not mutate local row"
        );
        assert_eq!(indexed_count(&conn), 1);
    }

    #[test]
    fn missing_episode_is_not_created() {
        let conn = open_test_db();
        let payload = serde_json::json!({
            "event_id": 99,
            "from_importance": 0.4,
            "to_importance": 0.9,
            "ts": 1000
        })
        .to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED,
            payload.as_bytes(),
        );

        assert_eq!(process_pending(&conn).unwrap(), 1);
        let episodes: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(episodes, 0);
    }

    #[test]
    fn cross_peer_episode_promoted_is_noop_local_importance_unchanged() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (77, 0.3)",
            [],
        )
        .unwrap();
        let payload = serde_json::json!({
            "event_id": 77,
            "from_importance": 0.7,
            "to_importance": 0.95,
            "ts": 1000
        })
        .to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED,
            payload.as_bytes(),
        );

        assert_eq!(process_pending(&conn).unwrap(), 1);
        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 77",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // Must remain 0.3 — gossip promote must NOT apply the peer's 0.95 to our row.
        assert!(
            (importance - 0.3).abs() < 1e-9,
            "cross-peer promote must not mutate local row"
        );
    }

    #[test]
    fn cross_peer_episode_consolidated_out_of_range_importance_is_noop() {
        // Even an out-of-range peer importance must not mutate the local row.
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (10, 0.4)",
            [],
        )
        .unwrap();
        let payload =
            serde_json::json!({"event_id": 10, "importance": 100.0, "ts": 1000}).to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            payload.as_bytes(),
        );

        process_pending(&conn).unwrap();
        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 10",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // Must remain 0.4 — gossip handler is a NO-OP regardless of payload value.
        assert!(
            (importance - 0.4).abs() < 1e-9,
            "cross-peer event must not mutate local row"
        );
    }

    #[test]
    fn cross_peer_episode_archived_is_noop_local_importance_unchanged() {
        // Cross-peer EPISODE_ARCHIVED events must not decay local episodes.
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (30, 0.5)",
            [],
        )
        .unwrap();
        for _ in 0..10 {
            let payload = serde_json::json!({
                "event_id": 30,
                "reason": "below_forget_floor",
                "last_importance": 0.5,
                "ts": 1000
            })
            .to_string();
            insert_foreign_event(
                &conn,
                crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED,
                payload.as_bytes(),
            );
        }

        assert_eq!(process_pending(&conn).unwrap(), 10);
        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 30",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // Must remain 0.5 — gossip decay must NOT mutate the local row.
        assert!(
            (importance - 0.5).abs() < 1e-9,
            "cross-peer decay must not mutate local row"
        );

        // Second pass: all rows already indexed, nothing new to process.
        assert_eq!(process_pending(&conn).unwrap(), 0);
    }

    #[test]
    fn decay_does_not_boost_already_subfloor_importance() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (31, 0.05)",
            [],
        )
        .unwrap();
        let payload = serde_json::json!({
            "event_id": 31,
            "reason": "below_forget_floor",
            "last_importance": 0.05,
            "ts": 1000
        })
        .to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED,
            payload.as_bytes(),
        );

        assert_eq!(process_pending(&conn).unwrap(), 1);
        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 31",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!((importance - 0.05).abs() < 1e-9);
    }

    #[test]
    fn groundtruth_revoke_is_indexed_but_not_applied() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at) VALUES (7, NULL)",
            [],
        )
        .unwrap();
        let payload = serde_json::json!({"id": 7, "ts": 1_704_067_200_000_000_000_i64}).to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_GROUNDTRUTH_REVOKED,
            payload.as_bytes(),
        );

        assert_eq!(process_pending(&conn).unwrap(), 1);
        let revoked_at: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM idx_groundtruth WHERE id = 7",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(revoked_at, None);
        assert_eq!(indexed_count(&conn), 1);
    }

    #[test]
    fn unknown_and_malformed_events_are_indexed_without_local_writes() {
        let conn = open_test_db();
        insert_foreign_event(&conn, 0xFF, b"{\"whatever\":true}");
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            b"not json",
        );

        assert_eq!(process_pending(&conn).unwrap(), 2);
        assert_eq!(indexed_count(&conn), 2);
        let episodes: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(episodes, 0);
    }

    // -----------------------------------------------------------------------
    // Fix NEOTH-AUDIT-MESH-IDENTITY-RETRY-01 invariant tests
    // -----------------------------------------------------------------------

    /// Core invariant (fix a): a peer boost/decay event whose numeric event_id
    /// happens to match a local idx_episode row must NOT alter that local row.
    /// The match is coincidental — they are independent autoincrements.
    #[test]
    fn peer_episode_event_id_collision_does_not_mutate_local_row() {
        let conn = open_test_db();
        // Local episode with event_id = 1 (first autoincrement in our DB).
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (1, 0.6)",
            [],
        )
        .unwrap();
        // Peer sends CONSOLIDATED with event_id = 1 (its own first autoincrement).
        // The numeric id collides, but the peer's row is unrelated to ours.
        let boost_payload =
            serde_json::json!({"event_id": 1, "importance": 0.99, "ts": 1000}).to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            boost_payload.as_bytes(),
        );
        // Peer sends PROMOTED with event_id = 1.
        let promote_payload =
            serde_json::json!({"event_id": 1, "from_importance": 0.6, "to_importance": 0.99, "ts": 1001})
                .to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED,
            promote_payload.as_bytes(),
        );
        // Peer sends ARCHIVED (decay) with event_id = 1.
        let decay_payload =
            serde_json::json!({"event_id": 1, "reason": "archived", "ts": 1002}).to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED,
            decay_payload.as_bytes(),
        );

        assert_eq!(process_pending(&conn).unwrap(), 3);

        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // Must remain exactly 0.6 — no gossip event mutated it.
        assert!(
            (importance - 0.6).abs() < 1e-9,
            "local episode importance must be unchanged after cross-peer events; got {importance}"
        );
        assert_eq!(
            indexed_count(&conn),
            3,
            "all three rows must be marked indexed"
        );
    }

    #[test]
    fn canonical_v5_row_is_already_materialized_and_only_marked_indexed() {
        let conn = open_test_db();
        let payload =
            serde_json::json!({"event_id": 42, "importance": 0.9, "ts": 1000}).to_string();
        let id = insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            payload.as_bytes(),
        );
        conn.execute(
            "UPDATE idx_foreign_events SET envelope_version=?2,content_payload=?3 WHERE id=?1",
            rusqlite::params![
                id,
                i64::from(crate::cluster::gossip_wire::SYNC_ENVELOPE_VERSION),
                b"canonical".as_slice(),
            ],
        )
        .unwrap();

        assert_eq!(process_pending(&conn).unwrap(), 1);
        assert_eq!(indexed_count(&conn), 1);
    }

    /// Fix (b): a retryable error from process_one must leave the row in
    /// idx_foreign_events unprocessed so it is re-fetched on the next tick.
    ///
    /// We simulate a retryable infrastructure failure by dropping
    /// idx_foreign_indexed_events AFTER ensure_marker_table ran, which causes
    /// marker_exists to fail with "no such table" — an Err that must NOT mark
    /// the row processed.
    #[test]
    fn retryable_error_leaves_row_unprocessed() {
        let conn = open_test_db();
        ensure_marker_table(&conn).unwrap();

        let payload = serde_json::json!({"event_id": 5, "importance": 0.7, "ts": 1000}).to_string();
        let fid = insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            payload.as_bytes(),
        );

        // Simulate a retryable infrastructure error: drop the marker table so
        // marker_exists returns Err("no such table"). process_one must propagate
        // this Err without running the INSERT OR IGNORE that marks the row.
        conn.execute_batch("DROP TABLE idx_foreign_indexed_events")
            .unwrap();

        let row = PendingRow {
            id: fid,
            event_type: crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            payload: conn
                .query_row(
                    "SELECT payload FROM idx_foreign_events WHERE id = ?1",
                    [fid],
                    |r| r.get(0),
                )
                .unwrap(),
            origin_peer_pk: "peer1".to_string(),
            envelope_version: 0,
            has_canonical_content: false,
        };

        // process_one must return Err (marker table gone → Err propagates).
        let result = process_one(&conn, &row);
        assert!(result.is_err(), "expected Err when marker table is missing");

        // Recreate the marker table and verify the row is NOT marked processed.
        conn.execute_batch(
            "CREATE TABLE idx_foreign_indexed_events (
                foreign_event_id INTEGER PRIMARY KEY,
                indexed_at       INTEGER NOT NULL
            )",
        )
        .unwrap();
        assert_eq!(
            indexed_count(&conn),
            0,
            "row must not be marked processed after a retryable error"
        );
    }

    /// Fix (b): terminal no-ops (unknown type, groundtruth skip, etc.) must be
    /// marked processed so they do not block the queue on the next tick.
    #[test]
    fn terminal_noop_outcome_marks_row_processed() {
        let conn = open_test_db();
        // Unknown event type → terminal no-op.
        insert_foreign_event(&conn, 0xAB, b"{\"whatever\":true}");
        // GROUNDTRUTH_REVOKED → skipped (local-id-only), but still terminal no-op.
        let gt_payload = serde_json::json!({"id": 1, "ts": 0}).to_string();
        insert_foreign_event(
            &conn,
            crate::wal::events::EVENT_TYPE_GROUNDTRUTH_REVOKED,
            gt_payload.as_bytes(),
        );

        assert_eq!(process_pending(&conn).unwrap(), 2);
        assert_eq!(
            indexed_count(&conn),
            2,
            "terminal no-ops must be marked processed"
        );

        // Second pass: both rows already indexed, nothing new.
        assert_eq!(process_pending(&conn).unwrap(), 0);
    }

    // -----------------------------------------------------------------------
    // Unit tests for pub(crate) conflict helpers
    // -----------------------------------------------------------------------

    #[test]
    fn apply_episode_boost_applied_when_peer_higher() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (1, 0.3)",
            [],
        )
        .unwrap();
        let outcome = apply_episode_boost(&conn, 1, 0.8, false).unwrap();
        assert_eq!(outcome, BoostOutcome::Applied);
        let imp: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!((imp - 0.8).abs() < 1e-9);
    }

    #[test]
    fn apply_episode_boost_idempotent_when_local_equal_or_higher() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (2, 0.9)",
            [],
        )
        .unwrap();
        let outcome = apply_episode_boost(&conn, 2, 0.7, false).unwrap();
        assert_eq!(outcome, BoostOutcome::Idempotent);
        // value unchanged
        let imp: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!((imp - 0.9).abs() < 1e-9);
    }

    #[test]
    fn apply_episode_boost_missing_when_no_row() {
        let conn = open_test_db();
        let outcome = apply_episode_boost(&conn, 999, 0.5, false).unwrap();
        assert_eq!(outcome, BoostOutcome::Missing);
    }

    #[test]
    fn apply_episode_decay_sql_found_and_not_found() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (5, 0.8)",
            [],
        )
        .unwrap();
        let found = apply_episode_decay_sql(&conn, 5).unwrap();
        assert!(found);
        let imp: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 5",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // 0.8 * 0.5 = 0.4, above DECAY_FLOOR
        assert!((imp - 0.4).abs() < 1e-9);

        let not_found = apply_episode_decay_sql(&conn, 888).unwrap();
        assert!(!not_found);
    }

    #[test]
    fn apply_groundtruth_revoke_applied() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at, fact_state) VALUES (10, NULL, 'verified')",
            [],
        )
        .unwrap();
        let outcome = apply_groundtruth_revoke(&conn, 10, 1_700_000_000).unwrap();
        assert_eq!(outcome, GroundtruthRevokeOutcome::Applied);
        let ra: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM idx_groundtruth WHERE id = 10",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ra, Some(1_700_000_000));
    }

    #[test]
    fn apply_groundtruth_revoke_missing() {
        let conn = open_test_db();
        let outcome = apply_groundtruth_revoke(&conn, 99, 0).unwrap();
        assert_eq!(outcome, GroundtruthRevokeOutcome::Missing);
    }

    #[test]
    fn apply_groundtruth_revoke_already_revoked() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at, fact_state) VALUES (11, 12345, 'verified')",
            [],
        )
        .unwrap();
        let outcome = apply_groundtruth_revoke(&conn, 11, 99999).unwrap();
        assert_eq!(outcome, GroundtruthRevokeOutcome::AlreadyRevoked);
    }

    #[test]
    fn apply_groundtruth_revoke_contradicted() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at, fact_state) VALUES (12, NULL, 'contradicted')",
            [],
        )
        .unwrap();
        let outcome = apply_groundtruth_revoke(&conn, 12, 0).unwrap();
        assert_eq!(outcome, GroundtruthRevokeOutcome::Contradicted);
        // revoked_at must remain NULL
        let ra: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM idx_groundtruth WHERE id = 12",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ra, None);
    }
}
