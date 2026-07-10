//! Foreign-event indexer for accepted cluster gossip.
//!
//! Current main persists accepted peer frames in `idx_foreign_events` without a
//! `processed` column so the table stays a queryable backup surface. This module
//! keeps that contract: it records local processing state in
//! `idx_foreign_indexed_events` and never deletes or mutates foreign rows.
//!
//! Applied effects are deliberately narrow:
//! - `0x90` / `0x91`: boost an existing local episode's importance.
//! - `0x92`: soft-decay an existing local episode, floored at `0.10`.
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
    payload: Vec<u8>,
}

/// Apply up to 64 not-yet-indexed foreign events to local recall surfaces.
///
/// Returns number of rows marked indexed in this pass. Per-row dispatch errors
/// are logged and still marked indexed so one bad peer payload cannot wedge the
/// queue.
pub fn process_pending(conn: &Connection) -> Result<usize> {
    ensure_marker_table(conn)?;
    let rows = fetch_pending(conn)?;
    let mut processed = 0usize;

    for row in rows {
        process_one(conn, &row)?;
        processed += 1;
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
            "SELECT e.id, e.event_type, e.payload \
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

    if let Err(e) = dispatch_foreign_row(conn, row) {
        warn!(
            foreign_event_id = row.id,
            event_type = row.event_type,
            error = %e,
            "foreign_indexer: dispatch error; marking indexed to unblock queue"
        );
    }

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

fn foreign_frame_payload(row: &PendingRow) -> Result<&[u8]> {
    let decoded = crate::wal::frame::decode_frame(&row.payload)
        .context("foreign_indexer: decode stored WAL frame")?;
    anyhow::ensure!(
        decoded.header.event_type == row.event_type,
        "foreign_indexer: stored event_type mismatch for foreign_event_id={} \
         row_type={} frame_type={}",
        row.id,
        row.event_type,
        decoded.header.event_type
    );
    Ok(decoded.payload)
}

fn handle_episode_consolidated(conn: &Connection, row: &PendingRow) -> Result<()> {
    let frame_payload = foreign_frame_payload(row)?;
    let payload: EpisodeConsolidatedPayload = match serde_json::from_slice(frame_payload) {
        Ok(p) => p,
        Err(e) => {
            trace!(
                foreign_event_id = row.id,
                error = %e,
                "foreign_indexer: malformed episode payload"
            );
            return Ok(());
        }
    };

    boost_episode_importance(conn, row, payload.event_id, payload.importance)
}

fn handle_episode_promoted(conn: &Connection, row: &PendingRow) -> Result<()> {
    let frame_payload = foreign_frame_payload(row)?;
    let payload: EpisodePromotedPayload = match serde_json::from_slice(frame_payload) {
        Ok(p) => p,
        Err(e) => {
            trace!(
                foreign_event_id = row.id,
                error = %e,
                "foreign_indexer: malformed episode promoted payload"
            );
            return Ok(());
        }
    };

    boost_episode_importance(conn, row, payload.event_id, payload.to_importance)
}

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
/// second SELECT. Single-threaded CLI invocation makes this safe.
pub(crate) fn apply_episode_boost(
    conn: &Connection,
    event_id: i64,
    peer_importance: f64,
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
    conn.execute(
        "UPDATE idx_episode SET importance = ?1 WHERE event_id = ?2",
        rusqlite::params![importance, event_id],
    )
    .context("apply_episode_boost: update importance")?;
    Ok(BoostOutcome::Applied)
}

fn boost_episode_importance(
    conn: &Connection,
    row: &PendingRow,
    event_id: i64,
    peer_importance: f64,
) -> Result<()> {
    match apply_episode_boost(conn, event_id, peer_importance)? {
        BoostOutcome::Applied => trace!(
            foreign_event_id = row.id,
            episode_event_id = event_id,
            peer_importance,
            "foreign_indexer: episode importance boost applied"
        ),
        BoostOutcome::Idempotent => trace!(
            foreign_event_id = row.id,
            episode_event_id = event_id,
            peer_importance,
            "foreign_indexer: boost no-op (local >= peer or non-finite)"
        ),
        BoostOutcome::Missing => trace!(
            foreign_event_id = row.id,
            episode_event_id = event_id,
            "foreign_indexer: boost skipped — no local episode row"
        ),
    }
    Ok(())
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

fn handle_episode_decay(conn: &Connection, row: &PendingRow) -> Result<()> {
    let frame_payload = foreign_frame_payload(row)?;
    let payload: EpisodeArchivedPayload = match serde_json::from_slice(frame_payload) {
        Ok(p) => p,
        Err(e) => {
            trace!(
                foreign_event_id = row.id,
                error = %e,
                "foreign_indexer: malformed episode archived payload"
            );
            return Ok(());
        }
    };
    let found = apply_episode_decay_sql(conn, payload.event_id)?;
    trace!(
        foreign_event_id = row.id,
        episode_event_id = payload.event_id,
        decay_floor = DECAY_FLOOR,
        "foreign_indexer: episode soft decay {}",
        if found { "applied" } else { "skipped (row missing)" }
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
                origin_seq      INTEGER NOT NULL,
                event_type      INTEGER NOT NULL,
                payload         BLOB    NOT NULL,
                received_at     INTEGER NOT NULL,
                UNIQUE (origin_peer_pk, origin_seq)
            );
            CREATE INDEX IF NOT EXISTS idx_foreign_events_peer
                ON idx_foreign_events (origin_peer_pk, received_at DESC);

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

    #[test]
    fn episode_consolidated_boosts_existing_local_importance() {
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
        assert!((importance - 0.8).abs() < 1e-9);
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
    fn episode_promoted_uses_to_importance_for_boost() {
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
        assert!((importance - 0.95).abs() < 1e-9);
    }

    #[test]
    fn large_peer_importance_is_clamped() {
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
        assert!((importance - 1.0).abs() < 1e-9);
    }

    #[test]
    fn decay_floors_and_second_pass_does_not_reapply() {
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
        let first_importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 30",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(first_importance >= DECAY_FLOOR - 1e-9);

        assert_eq!(process_pending(&conn).unwrap(), 0);
        let second_importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 30",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!((second_importance - first_importance).abs() < 1e-9);
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
        let outcome = apply_episode_boost(&conn, 1, 0.8).unwrap();
        assert_eq!(outcome, BoostOutcome::Applied);
        let imp: f64 = conn
            .query_row("SELECT importance FROM idx_episode WHERE event_id = 1", [], |r| r.get(0))
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
        let outcome = apply_episode_boost(&conn, 2, 0.7).unwrap();
        assert_eq!(outcome, BoostOutcome::Idempotent);
        // value unchanged
        let imp: f64 = conn
            .query_row("SELECT importance FROM idx_episode WHERE event_id = 2", [], |r| r.get(0))
            .unwrap();
        assert!((imp - 0.9).abs() < 1e-9);
    }

    #[test]
    fn apply_episode_boost_missing_when_no_row() {
        let conn = open_test_db();
        let outcome = apply_episode_boost(&conn, 999, 0.5).unwrap();
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
            .query_row("SELECT importance FROM idx_episode WHERE event_id = 5", [], |r| r.get(0))
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
            .query_row("SELECT revoked_at FROM idx_groundtruth WHERE id = 10", [], |r| r.get(0))
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
            .query_row("SELECT revoked_at FROM idx_groundtruth WHERE id = 12", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ra, None);
    }
}
