//! G-02 CLUSTER-02b — Foreign-event indexer background cron.
//!
//! Reads unprocessed rows from `idx_foreign_events` (persisted by the
//! `cluster::wal_sync` gossip path via `ingest_foreign_event`) and promotes
//! them into local recall surfaces.
//!
//! ## Design contract
//!
//! - **WAL-free**: this cron reads + writes `views.db` only; it never appends
//!   to the operator's WAL. A crash between dispatch and `processed=1` is safe
//!   because all write actions are idempotent (see per-event docs below).
//! - **Local-only reinforcement**: foreign events are never used to CREATE new
//!   local rows. A peer signal for an episode or groundtruth fact that this
//!   node does not hold is silently skipped. This preserves the invariant that
//!   `idx_episode` and `idx_groundtruth` contain only operator-attested truth.
//! - **Forward-compatible**: unknown `event_type` values are marked processed
//!   with a trace log — they do not block the queue.
//!
//! ## Groundtruth-revoke ID caveat
//!
//! `idx_groundtruth.id` is a SQLite AUTOINCREMENT value that is local to this
//! node. A foreign peer's groundtruth ids are its own AUTOINCREMENT values and
//! bear no relation to ours. In practice, `0x98 GROUNDTRUTH_REVOKED` events are
//! only useful when the same fact exists on both nodes with the same integer id
//! (e.g. after a full groundtruth sync), which is rare in v1.0. The action is
//! safe because the `WHERE id = ? AND revoked_at IS NULL` guard is a no-op for
//! mismatched ids. Long-term, a content-hash-based groundtruth id would remove
//! this ambiguity; tracked as a post-v1.0 follow-up.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Deserialize;
use tracing::{debug, trace, warn};

// ── Importance scale bounds ───────────────────────────────────────────────────
//
// The local importance column uses the range [0.0, 1.0]:
//   FORGET_FLOOR = 0.10  (rows below this are dropped at consolidation)
//   PROMOTION_THRESHOLD = 0.65  (warm → cold promotion)
//   maximum = 1.0  (fully reinforced / pinned)
//
// Peer-supplied importance values MUST be clamped into this range before
// reaching the SQL MAX(). A non-finite or out-of-range value from a
// compromised peer must not corrupt the local importance column.
const IMPORTANCE_MAX: f64 = 1.0;
const IMPORTANCE_MIN: f64 = 0.0;

// ── Decay floor ───────────────────────────────────────────────────────────────
//
// A single peer signal must not zero-out a locally-held episode. Applying the
// same floor as the consolidation pass (FORGET_FLOOR = 0.10) matches the
// minimum importance a row can hold before the daemon's own consolidation
// sweep would drop it. This prevents a flood of 0x92 events from driving
// importance to zero before the local sweep acts.
//
// Note: full per-peer dedup (one decay per event_id per N hours) is out of
// scope for v1.0. The UNIQUE (origin_peer_pk, origin_seq) constraint on
// idx_foreign_events already blocks a single peer from replaying the exact
// same frame; a peer with multiple origin_seq values can still trigger
// multiple decays, but each is floored at DECAY_FLOOR.
const DECAY_FLOOR: f64 = 0.10;

// ── Timestamp validation bounds ───────────────────────────────────────────────
//
// `revoked_at` stores Unix-nanoseconds (i64) — matching the `now_ns: i64`
// parameter of `memory::groundtruth::revoke`. Allowed range:
//   lower bound: 1 ns  (strictly positive; 0 and negatives are invalid)
//   upper bound: now + 1 day in nanoseconds
const ONE_DAY_NS: i64 = 86_400 * 1_000_000_000_i64;

// ── WAL event type constants (Replicate band — wal_sync.rs:95-101) ──────────

/// Peer episode transitioned to consolidated tier (importance boost applicable).
const EVENT_EPISODE_CONSOLIDATED: u8 = 0x90;
/// Peer episode transitioned to promoted tier (importance boost applicable).
const EVENT_EPISODE_PROMOTED: u8 = 0x91;
/// Peer episode transitioned to archived/cold tier (soft-decay applicable).
const EVENT_EPISODE_ARCHIVED: u8 = 0x92;
/// Aggregate consolidation-pass counts — no per-row action at v1.0.
const EVENT_CONSOLIDATION_PASS: u8 = 0x94;
/// Peer revoked a groundtruth fact — revoke locally if we hold the same id.
const EVENT_GROUNDTRUTH_REVOKED: u8 = 0x98;
/// Component updated — capability signal, log only.
const EVENT_UPDATE_RAN: u8 = 0x13;

// ── Payload shapes ───────────────────────────────────────────────────────────

/// Payload for `EPISODE_CONSOLIDATED` (0x90), `EPISODE_PROMOTED` (0x91),
/// and `EPISODE_ARCHIVED` (0x92).
#[derive(Debug, Deserialize)]
struct EpisodeEventPayload {
    event_id: i64,
    importance: f64,
    #[allow(dead_code)]
    ts: i64,
}

/// Payload for `GROUNDTRUTH_REVOKED` (0x98).
#[derive(Debug, Deserialize)]
struct GroundtruthRevokedPayload {
    id: i64,
    ts: i64,
}

// ── Internal row type ────────────────────────────────────────────────────────

struct PendingRow {
    id: i64,
    event_type: u8,
    payload: Vec<u8>,
}

// ── Core processing function ─────────────────────────────────────────────────

/// Drain up to 64 unprocessed rows from `idx_foreign_events`, promote each
/// into the appropriate local recall surface, then mark all of them as
/// `processed = 1`.
///
/// Returns the number of rows processed (0 when the queue is empty).
///
/// # Idempotency
///
/// All write actions are idempotent:
/// - Episode importance updates use `MAX(importance, peer_importance)` so
///   re-processing raises but never lowers importance.
/// - Episode decay uses a multiplicative factor; repeated halving converges.
/// - Groundtruth revocation has a `WHERE revoked_at IS NULL` guard so it is
///   a no-op when already revoked.
pub fn process_pending(conn: &Connection) -> Result<usize> {
    let rows = fetch_pending(conn)?;
    if rows.is_empty() {
        return Ok(0);
    }

    let mut processed_ids: Vec<i64> = Vec::with_capacity(rows.len());

    for row in &rows {
        let result = dispatch_foreign_row(conn, row);
        if let Err(e) = result {
            warn!(
                foreign_event_id = row.id,
                event_type = row.event_type,
                error = %e,
                "foreign_indexer: dispatch error (marking processed to unblock queue)"
            );
        }
        // Always mark processed — errors must not block the queue indefinitely.
        processed_ids.push(row.id);
    }

    mark_processed(conn, &processed_ids)?;
    Ok(processed_ids.len())
}

/// Fetch up to 64 unprocessed rows ordered by `received_at ASC` (FIFO).
fn fetch_pending(conn: &Connection) -> Result<Vec<PendingRow>> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, event_type, payload \
             FROM idx_foreign_events \
             WHERE processed = 0 \
             ORDER BY received_at ASC \
             LIMIT 64",
        )
        .context("foreign_indexer: prepare fetch_pending")?;

    let rows = stmt
        .query_map([], |r| {
            Ok(PendingRow {
                id: r.get(0)?,
                event_type: r.get::<_, i64>(1)? as u8,
                payload: r.get(2)?,
            })
        })
        .context("foreign_indexer: query fetch_pending")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("foreign_indexer: collect fetch_pending")?;

    Ok(rows)
}

/// Mark a batch of row ids as `processed = 1` in a single UPDATE.
fn mark_processed(conn: &Connection, ids: &[i64]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    // Build a parameterised placeholder list: (?, ?, ...)
    let placeholders = ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "UPDATE idx_foreign_events SET processed = 1 WHERE id IN ({placeholders})"
    );
    let params = rusqlite::params_from_iter(ids.iter().map(|id| rusqlite::types::Value::Integer(*id)));
    conn.execute(&sql, params)
        .context("foreign_indexer: mark_processed")?;
    Ok(())
}

/// Route a single row to the appropriate handler based on `event_type`.
fn dispatch_foreign_row(conn: &Connection, row: &PendingRow) -> Result<()> {
    match row.event_type {
        EVENT_EPISODE_CONSOLIDATED | EVENT_EPISODE_PROMOTED => {
            handle_episode_boost(conn, row)?;
        }
        EVENT_EPISODE_ARCHIVED => {
            handle_episode_decay(conn, row)?;
        }
        EVENT_CONSOLIDATION_PASS => {
            // Aggregate counts — no per-row action at v1.0.
            trace!(
                foreign_event_id = row.id,
                "foreign_indexer: CONSOLIDATION_PASS — no-op at v1.0"
            );
        }
        EVENT_GROUNDTRUTH_REVOKED => {
            handle_groundtruth_revoke(conn, row)?;
        }
        EVENT_UPDATE_RAN => {
            // Capability signal — log only, no local state change.
            trace!(
                foreign_event_id = row.id,
                "foreign_indexer: UPDATE_RAN — capability signal, no local action"
            );
        }
        other => {
            // Forward-compatible: unknown types are skipped, not errored.
            trace!(
                foreign_event_id = row.id,
                event_type = other,
                "foreign_indexer: unknown event_type — forward-compat no-op"
            );
        }
    }
    Ok(())
}

// ── Per-event handlers ───────────────────────────────────────────────────────

/// `0x90` / `0x91` — Boost local episode importance to `MAX(local, peer)`,
/// but ONLY if the episode exists locally (never create phantom rows).
fn handle_episode_boost(conn: &Connection, row: &PendingRow) -> Result<()> {
    let payload: EpisodeEventPayload = match serde_json::from_slice(&row.payload) {
        Ok(p) => p,
        Err(e) => {
            trace!(
                foreign_event_id = row.id,
                error = %e,
                "foreign_indexer: malformed episode payload — skipping"
            );
            return Ok(());
        }
    };

    // Security: reject non-finite peer-supplied importance values (NaN, ±Inf)
    // and clamp finite values into the local importance scale [0.0, 1.0].
    // A compromised peer sending 1e300 or NaN must not corrupt local recall
    // scoring or trigger spurious PROMOTION_THRESHOLD crossings.
    if !payload.importance.is_finite() {
        trace!(
            foreign_event_id = row.id,
            episode_event_id = payload.event_id,
            peer_importance = payload.importance,
            "foreign_indexer: non-finite importance — skipping boost"
        );
        return Ok(());
    }
    let importance = payload.importance.clamp(IMPORTANCE_MIN, IMPORTANCE_MAX);

    // Guard: only update if the episode exists locally.
    conn.execute(
        "UPDATE idx_episode \
         SET importance = MAX(importance, ?1) \
         WHERE event_id = ?2 \
         AND EXISTS (SELECT 1 FROM idx_episode WHERE event_id = ?2)",
        rusqlite::params![importance, payload.event_id],
    )
    .context("foreign_indexer: episode importance boost")?;

    trace!(
        foreign_event_id = row.id,
        episode_event_id = payload.event_id,
        peer_importance = payload.importance,
        clamped_importance = importance,
        "foreign_indexer: episode importance boost applied (no-op if not held locally)"
    );
    Ok(())
}

/// `0x92` — Apply a soft decay (×0.5) to a local episode if it exists.
/// This is a signal that the peer moved the episode to cold/archived tier.
fn handle_episode_decay(conn: &Connection, row: &PendingRow) -> Result<()> {
    let payload: EpisodeEventPayload = match serde_json::from_slice(&row.payload) {
        Ok(p) => p,
        Err(e) => {
            trace!(
                foreign_event_id = row.id,
                error = %e,
                "foreign_indexer: malformed episode archived payload — skipping"
            );
            return Ok(());
        }
    };

    // Apply ×0.5 decay but floor at DECAY_FLOOR (0.10) so repeated 0x92
    // events from a peer (each with a distinct origin_seq) cannot drive
    // importance to zero before the local consolidation sweep acts.
    // Using MAX(importance * 0.5, DECAY_FLOOR) ensures the row stays above
    // the forget threshold until the daemon's own pass decides to drop it.
    conn.execute(
        "UPDATE idx_episode \
         SET importance = MAX(importance * 0.5, ?1) \
         WHERE event_id = ?2",
        rusqlite::params![DECAY_FLOOR, payload.event_id],
    )
    .context("foreign_indexer: episode soft decay")?;

    trace!(
        foreign_event_id = row.id,
        episode_event_id = payload.event_id,
        decay_floor = DECAY_FLOOR,
        "foreign_indexer: episode soft decay applied (no-op if not held locally)"
    );
    Ok(())
}

/// `0x98` — Revoke a local groundtruth row if it exists and is not already
/// revoked. See module-level caveat on integer ID mismatch.
fn handle_groundtruth_revoke(conn: &Connection, row: &PendingRow) -> Result<()> {
    let payload: GroundtruthRevokedPayload = match serde_json::from_slice(&row.payload) {
        Ok(p) => p,
        Err(e) => {
            trace!(
                foreign_event_id = row.id,
                error = %e,
                "foreign_indexer: malformed groundtruth_revoked payload — skipping"
            );
            return Ok(());
        }
    };

    // Security: validate the peer-supplied `ts` before writing it as
    // `revoked_at`. The column stores Unix-nanoseconds (i64), matching the
    // `memory::groundtruth::revoke(now_ns: i64)` API.
    //
    // Reject:
    //  • ts <= 0  — zero or negative is not a valid nanosecond epoch
    //  • ts > now + 1 day  — far-future values would make the revocation
    //    appear to "never expire" in any consumer doing `WHERE revoked_at < now`
    //
    // On rejection mark the row processed (to unblock the queue) and skip.
    let now_ns = crate::time::now_unix_ns() as i64;
    if payload.ts <= 0 || payload.ts > now_ns + ONE_DAY_NS {
        warn!(
            foreign_event_id = row.id,
            groundtruth_id = payload.id,
            peer_ts = payload.ts,
            now_ns,
            "foreign_indexer: 0x98 ts out of range — skipping revoke"
        );
        return Ok(());
    }

    // Guard: only revoke if the id is locally held AND not yet revoked.
    conn.execute(
        "UPDATE idx_groundtruth \
         SET revoked_at = ?1 \
         WHERE id = ?2 AND revoked_at IS NULL",
        rusqlite::params![payload.ts, payload.id],
    )
    .context("foreign_indexer: groundtruth revoke")?;

    trace!(
        foreign_event_id = row.id,
        groundtruth_id = payload.id,
        "foreign_indexer: groundtruth revoke applied (no-op if not held locally or already revoked)"
    );
    Ok(())
}

// ── Spawn loop ───────────────────────────────────────────────────────────────

/// Spawn the foreign-event indexer background loop.
///
/// Pattern mirrors `spawn_cluster_audit_ingester` from `cli/serve_tasks.rs`.
/// The loop wakes every 30 s, opens `views.db`, drains up to 64 unprocessed
/// foreign events per tick, then sleeps again.
///
/// WAL-free: no [`crate::wal::writer::WalWriterHandle`] is captured; the
/// connection is opened fresh each tick inside `spawn_blocking` so the
/// `rusqlite::Connection` (not `Send`) never crosses an `await` boundary.
///
/// Gated behind `#[cfg(feature = "cluster")]` to match the rest of the
/// cluster feature set.
#[cfg(feature = "cluster")]
pub fn spawn_foreign_indexer(neoth_home: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        const POLL_INTERVAL: Duration = Duration::from_secs(30);
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            let home = neoth_home.clone();
            let result = tokio::task::spawn_blocking(move || -> Result<usize> {
                let db_path = home.join("views.db");
                let conn = crate::memory::store::open(&db_path)
                    .context("foreign_indexer: open views.db")?;
                process_pending(&conn)
            })
            .await;

            match result {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => {
                    debug!(processed = n, "foreign_indexer: tick drained rows");
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "foreign_indexer: tick error");
                }
                Err(e) => {
                    warn!(error = %e, "foreign_indexer: spawn_blocking panicked");
                }
            }
        }
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── In-memory DB helpers ─────────────────────────────────────────────────

    /// Open an in-memory SQLite DB with the minimal schema needed by the
    /// foreign indexer: `idx_foreign_events` (with `processed` column),
    /// `idx_episode`, and `idx_groundtruth`.
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
                processed       INTEGER NOT NULL DEFAULT 0,
                UNIQUE (origin_peer_pk, origin_seq)
            );
            CREATE INDEX IF NOT EXISTS idx_foreign_events_unprocessed
                ON idx_foreign_events (processed, received_at ASC)
                WHERE processed = 0;

            -- Minimal idx_episode: only the columns the foreign indexer touches.
            CREATE TABLE IF NOT EXISTS idx_episode (
                event_id   INTEGER PRIMARY KEY,
                importance REAL    NOT NULL DEFAULT 0.5
            );

            -- Minimal idx_groundtruth: only the columns the foreign indexer touches.
            CREATE TABLE IF NOT EXISTS idx_groundtruth (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                revoked_at INTEGER
            );
            "#,
        )
        .unwrap();
        conn
    }

    fn insert_foreign_event(
        conn: &Connection,
        event_type: u8,
        payload: &[u8],
    ) -> i64 {
        conn.execute(
            "INSERT INTO idx_foreign_events \
             (origin_peer_pk, origin_seq, event_type, payload, received_at, processed) \
             VALUES ('peer1', ?, ?, ?, 1000, 0)",
            rusqlite::params![
                conn.query_row(
                    "SELECT COALESCE(MAX(origin_seq), 0) + 1 FROM idx_foreign_events \
                     WHERE origin_peer_pk = 'peer1'",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap(),
                event_type as i64,
                payload,
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[test]
    fn process_pending_empty_table_is_noop() {
        let conn = open_test_db();
        let n = process_pending(&conn).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn process_pending_episode_consolidated_boosts_local_importance() {
        let conn = open_test_db();

        // Insert a local episode with low importance.
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (42, 0.4)",
            [],
        )
        .unwrap();

        // Insert a foreign event signalling peer boosted the same episode.
        let payload =
            serde_json::json!({"event_id": 42, "importance": 0.8, "ts": 1000}).to_string();
        insert_foreign_event(&conn, EVENT_EPISODE_CONSOLIDATED, payload.as_bytes());

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 1);

        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 42",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            (importance - 0.8).abs() < 1e-9,
            "importance should be boosted to 0.8, got {importance}"
        );

        let processed: i64 = conn
            .query_row(
                "SELECT processed FROM idx_foreign_events WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(processed, 1);
    }

    #[test]
    fn process_pending_skips_episode_not_held_locally() {
        let conn = open_test_db();

        // No idx_episode row for event_id=99.
        let payload =
            serde_json::json!({"event_id": 99, "importance": 0.9, "ts": 2000}).to_string();
        insert_foreign_event(&conn, EVENT_EPISODE_CONSOLIDATED, payload.as_bytes());

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 1, "row was processed (not errored)");

        let episode_count: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(episode_count, 0, "no phantom episode row created");
    }

    #[test]
    fn process_pending_groundtruth_revoked_revokes_local_row() {
        let conn = open_test_db();

        // Insert a local groundtruth row.
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at) VALUES (7, NULL)",
            [],
        )
        .unwrap();

        let payload =
            serde_json::json!({"id": 7, "ts": 1_234_567_890_i64}).to_string();
        insert_foreign_event(&conn, EVENT_GROUNDTRUTH_REVOKED, payload.as_bytes());

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 1);

        let revoked_at: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM idx_groundtruth WHERE id = 7",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(revoked_at.is_some(), "revoked_at should be set");
        assert_eq!(revoked_at.unwrap(), 1_234_567_890_i64);
    }

    #[test]
    fn process_pending_groundtruth_revoked_no_local_row_is_noop() {
        let conn = open_test_db();

        // No idx_groundtruth row for id=99.
        let payload =
            serde_json::json!({"id": 99, "ts": 1_000_000_i64}).to_string();
        insert_foreign_event(&conn, EVENT_GROUNDTRUTH_REVOKED, payload.as_bytes());

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 1, "row processed without error");

        let gt_count: i64 = conn
            .query_row("SELECT count(*) FROM idx_groundtruth", [], |r| r.get(0))
            .unwrap();
        assert_eq!(gt_count, 0, "idx_groundtruth still empty");
    }

    #[test]
    fn process_pending_marks_processed_after_handling() {
        let conn = open_test_db();

        // Episode row for event_type 0x90.
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (1, 0.5)",
            [],
        )
        .unwrap();
        let ep_payload =
            serde_json::json!({"event_id": 1, "importance": 0.7, "ts": 100}).to_string();
        insert_foreign_event(&conn, EVENT_EPISODE_CONSOLIDATED, ep_payload.as_bytes());

        // Groundtruth row for event_type 0x98.
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at) VALUES (5, NULL)",
            [],
        )
        .unwrap();
        let gt_payload = serde_json::json!({"id": 5, "ts": 200}).to_string();
        insert_foreign_event(&conn, EVENT_GROUNDTRUTH_REVOKED, gt_payload.as_bytes());

        // No-op event_type 0x13.
        let noop_payload = b"{\"component\":\"neothd\",\"old_version\":\"1.0\",\"new_version\":\"1.1\",\"status\":\"ok\"}";
        insert_foreign_event(&conn, EVENT_UPDATE_RAN, noop_payload);

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 3);

        let processed_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_foreign_events WHERE processed = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(processed_count, 3, "all three rows marked processed");

        // Second call returns 0 — queue is empty.
        let count2 = process_pending(&conn).unwrap();
        assert_eq!(count2, 0);
    }

    #[test]
    fn process_pending_unknown_event_type_is_skipped_not_errored() {
        let conn = open_test_db();

        insert_foreign_event(&conn, 0xFF, b"{\"whatever\":true}");

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 1, "processed without error");

        let processed: i64 = conn
            .query_row(
                "SELECT processed FROM idx_foreign_events WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(processed, 1);
    }

    // ── Security guard tests ─────────────────────────────────────────────

    /// Finding: importance value far above 1.0 is clamped, not passed raw.
    ///
    /// Note: JSON cannot represent IEEE Inf/NaN literals so we cannot test
    /// non-finite values through the serde_json path. The `is_finite()` guard
    /// in `handle_episode_boost` exists for callers that construct an
    /// `EpisodeEventPayload` directly (e.g. future binary encodings). Here we
    /// verify that a very large finite float (100.0) is clamped to 1.0.
    #[test]
    fn boost_large_importance_is_clamped_to_max() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (10, 0.4)",
            [],
        )
        .unwrap();

        // Peer sends importance = 100.0 — must be clamped to 1.0.
        let payload =
            serde_json::json!({"event_id": 10, "importance": 100.0, "ts": 1000}).to_string();
        insert_foreign_event(&conn, EVENT_EPISODE_CONSOLIDATED, payload.as_bytes());
        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 1);
        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 10",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            (importance - 1.0).abs() < 1e-9,
            "importance 100.0 must be clamped to 1.0, got {importance}"
        );
    }

    /// Finding: importance above 1.0 is clamped to 1.0 before the SQL MAX.
    #[test]
    fn boost_importance_clamped_to_importance_max() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (20, 0.5)",
            [],
        )
        .unwrap();
        // Peer sends importance = 999.0 — must be clamped to 1.0.
        let payload =
            serde_json::json!({"event_id": 20, "importance": 999.0, "ts": 1000}).to_string();
        insert_foreign_event(&conn, EVENT_EPISODE_CONSOLIDATED, payload.as_bytes());
        process_pending(&conn).unwrap();
        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 20",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            (importance - 1.0).abs() < 1e-9,
            "peer importance 999.0 must clamp to 1.0, got {importance}"
        );
    }

    /// Finding: repeated 0x92 decay events cannot drive importance below DECAY_FLOOR.
    #[test]
    fn decay_floors_at_decay_floor_after_repeated_events() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (30, 0.5)",
            [],
        )
        .unwrap();

        // Insert 10 distinct 0x92 events for the same episode. Each halves
        // importance; without a floor 0.5 × 0.5^10 ≈ 0.00049 < DECAY_FLOOR.
        for _ in 0..10 {
            let payload =
                serde_json::json!({"event_id": 30, "importance": 0.5, "ts": 1000}).to_string();
            insert_foreign_event(&conn, EVENT_EPISODE_ARCHIVED, payload.as_bytes());
        }

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 10);

        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 30",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            importance >= DECAY_FLOOR - 1e-9,
            "importance {importance} must not drop below DECAY_FLOOR {DECAY_FLOOR}"
        );
    }

    /// Finding: 0x98 with ts <= 0 is skipped (row marked processed, no DB write).
    #[test]
    fn revoke_ts_zero_or_negative_is_skipped() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at) VALUES (42, NULL)",
            [],
        )
        .unwrap();

        for bad_ts in &[0_i64, -1, i64::MIN] {
            let payload =
                serde_json::json!({"id": 42, "ts": *bad_ts}).to_string();
            insert_foreign_event(&conn, EVENT_GROUNDTRUTH_REVOKED, payload.as_bytes());
        }

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 3, "all three rows must be marked processed");

        // The groundtruth row must NOT have been revoked.
        let revoked_at: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM idx_groundtruth WHERE id = 42",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            revoked_at.is_none(),
            "bad-ts revoke must not write revoked_at, got {revoked_at:?}"
        );
    }

    /// Finding: 0x98 with ts > now + 1 day is skipped.
    #[test]
    fn revoke_far_future_ts_is_skipped() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at) VALUES (43, NULL)",
            [],
        )
        .unwrap();

        // i64::MAX is astronomically in the future.
        let payload = serde_json::json!({"id": 43, "ts": i64::MAX}).to_string();
        insert_foreign_event(&conn, EVENT_GROUNDTRUTH_REVOKED, payload.as_bytes());

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 1);

        let revoked_at: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM idx_groundtruth WHERE id = 43",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            revoked_at.is_none(),
            "far-future ts must not write revoked_at, got {revoked_at:?}"
        );
    }

    /// Sanity: a valid ts in the plausible past is accepted.
    #[test]
    fn revoke_valid_ts_is_accepted() {
        let conn = open_test_db();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at) VALUES (44, NULL)",
            [],
        )
        .unwrap();

        // A plausible Unix-nanosecond timestamp: 2024-01-01T00:00:00Z
        let valid_ts: i64 = 1_704_067_200_000_000_000_i64;
        let payload = serde_json::json!({"id": 44, "ts": valid_ts}).to_string();
        insert_foreign_event(&conn, EVENT_GROUNDTRUTH_REVOKED, payload.as_bytes());

        process_pending(&conn).unwrap();

        let revoked_at: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM idx_groundtruth WHERE id = 44",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            revoked_at,
            Some(valid_ts),
            "valid ts must be accepted and written"
        );
    }

    #[test]
    fn process_pending_malformed_payload_json_skips_gracefully() {
        let conn = open_test_db();

        insert_foreign_event(&conn, EVENT_EPISODE_CONSOLIDATED, b"not json");

        let count = process_pending(&conn).unwrap();
        assert_eq!(count, 1, "processed without panic");

        let episode_count: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(episode_count, 0, "no phantom episode row created");

        let processed: i64 = conn
            .query_row(
                "SELECT processed FROM idx_foreign_events WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(processed, 1);
    }
}
