//! Durable, secondary Hippocampus membership derived from existing tier rows.
//!
//! This module owns only an event-id bucket. It never copies text or
//! importance, and it never participates in normal recall ranking. The
//! existing WAL-indexed tier rows remain the sole live source of truth.

use std::path::Path;

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, Transaction, params};
use serde::Serialize;

/// Fixed Jarvis-derived selection contract. Keep separate from the 0.65
/// long-term promotion rule in `memory::tiers`.
pub const IMPORTANCE_SELECTION_THRESHOLD: f64 = 0.75;
pub const MAX_READ_ROWS: usize = 100;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub selected: usize,
    pub removed: usize,
}

/// Current source row joined to a durable membership id for operator-only
/// inspection. `text` is read from the live tier, never the membership table.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HippocampusRow {
    pub event_id: i64,
    pub tier: &'static str,
    pub text: String,
    pub importance: f64,
    pub ts_ns: i64,
    pub selected_at_ns: i64,
}

/// Reconcile membership while the caller's existing consolidation transaction
/// is open. The upsert and stale-membership removal therefore roll back with
/// tier decay, movement, archival, or an injected failure.
pub fn reconcile(tx: &Transaction<'_>, selected_at_ns: i64) -> Result<ReconcileReport> {
    let selected = tx.execute(
        "INSERT OR IGNORE INTO idx_hippocampus (event_id, selected_at_ns) \
         SELECT event_id, ?1 FROM ( \
             SELECT event_id, importance FROM idx_episode \
             UNION ALL \
             SELECT event_id, importance FROM idx_consolidated WHERE event_id IS NOT NULL \
             UNION ALL \
             SELECT event_id, importance FROM idx_longterm \
         ) AS live WHERE importance >= ?2",
        params![selected_at_ns, IMPORTANCE_SELECTION_THRESHOLD],
    )?;
    let removed = tx.execute(
        "DELETE FROM idx_hippocampus AS membership \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM ( \
                 SELECT event_id, importance FROM idx_episode \
                 UNION ALL \
                 SELECT event_id, importance FROM idx_consolidated WHERE event_id IS NOT NULL \
                 UNION ALL \
                 SELECT event_id, importance FROM idx_longterm \
             ) AS live \
             WHERE live.event_id = membership.event_id AND live.importance >= ?1 \
         )",
        params![IMPORTANCE_SELECTION_THRESHOLD],
    )?;
    Ok(ReconcileReport { selected, removed })
}

/// Open an already-existing views database without a schema upgrade, sidecar,
/// WAL append, or any other write-capable operation.
pub fn open_read_only(path: &Path) -> Result<Connection> {
    ensure!(
        path.is_file(),
        "views database is absent: {}",
        path.display()
    );
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open Hippocampus view read-only {}", path.display()))?;
    conn.pragma_update(None, "query_only", "ON")
        .context("set Hippocampus inspection connection query_only")?;
    Ok(conn)
}

/// Read only memberships that still join to a current eligible source row.
/// Ordering is deterministic: importance, source timestamp, then event id.
pub fn query_current_rows(
    conn: &Connection,
    query: Option<&str>,
    limit: usize,
) -> Result<Vec<HippocampusRow>> {
    let limit = limit.min(MAX_READ_ROWS);
    if limit == 0 {
        return Ok(Vec::new());
    }
    let query = query
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(crate::memory::escape_like);
    let mut stmt = conn.prepare(
        "WITH live AS ( \
             SELECT event_id, 'hot' AS tier, text, importance, ts_ns FROM idx_episode \
             UNION ALL \
             SELECT event_id, 'warm', text, importance, consolidated_ts \
             FROM idx_consolidated WHERE event_id IS NOT NULL \
             UNION ALL \
             SELECT event_id, 'cold', text, importance, promoted_ts FROM idx_longterm \
         ) \
         SELECT live.event_id, live.tier, live.text, live.importance, live.ts_ns, membership.selected_at_ns \
         FROM idx_hippocampus AS membership \
         JOIN live ON live.event_id = membership.event_id \
         WHERE (?1 IS NULL OR live.text LIKE '%' || ?1 || '%' ESCAPE '\\') \
           AND live.importance >= ?2 \
         ORDER BY live.importance DESC, live.ts_ns DESC, live.event_id ASC \
         LIMIT ?3",
    )?;
    let rows = stmt
        .query_map(
            params![query, IMPORTANCE_SELECTION_THRESHOLD, limit as i64],
            |row| {
                let tier: String = row.get(1)?;
                let tier = match tier.as_str() {
                    "hot" => "hot",
                    "warm" => "warm",
                    "cold" => "cold",
                    _ => {
                        return Err(rusqlite::Error::InvalidColumnType(
                            1,
                            "tier".into(),
                            rusqlite::types::Type::Text,
                        ));
                    }
                };
                Ok(HippocampusRow {
                    event_id: row.get(0)?,
                    tier,
                    text: row.get(2)?,
                    importance: row.get(3)?,
                    ts_ns: row.get(4)?,
                    selected_at_ns: row.get(5)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        (dir, conn)
    }

    fn insert_hot(conn: &Connection, event_id: i64, importance: f64, ts_ns: i64) {
        conn.execute(
            "INSERT INTO idx_episode (event_id,event_type,ts_ns,text,text_hash,importance,last_access_ts) \
             VALUES (?1,1,?2,?3,?4,?5,?2)",
            params![event_id, ts_ns, format!("event-{event_id}"), format!("hash-{event_id}"), importance],
        )
        .unwrap();
    }

    #[test]
    fn selection_boundary_is_inclusive_and_idempotent() {
        let (_dir, mut conn) = open();
        insert_hot(&conn, 1, 0.749_999, 10);
        insert_hot(&conn, 2, IMPORTANCE_SELECTION_THRESHOLD, 20);
        insert_hot(&conn, 3, 0.9, 30);
        let tx = conn.transaction().unwrap();
        assert_eq!(reconcile(&tx, 100).unwrap().selected, 2);
        tx.commit().unwrap();
        let tx = conn.transaction().unwrap();
        assert_eq!(reconcile(&tx, 200).unwrap(), ReconcileReport::default());
        tx.commit().unwrap();
        let ids: Vec<i64> = conn
            .prepare("SELECT event_id FROM idx_hippocampus ORDER BY event_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(ids, vec![2, 3]);
    }

    #[test]
    fn reconcile_removes_decayed_and_missing_membership_atomically() {
        let (_dir, mut conn) = open();
        insert_hot(&conn, 7, 0.8, 10);
        let tx = conn.transaction().unwrap();
        reconcile(&tx, 100).unwrap();
        tx.commit().unwrap();
        conn.execute(
            "UPDATE idx_episode SET importance = 0.74 WHERE event_id = 7",
            [],
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        assert_eq!(reconcile(&tx, 200).unwrap().removed, 1);
        tx.commit().unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM idx_hippocampus", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn read_only_query_hides_stale_rows_and_uses_stable_order() {
        let (dir, mut conn) = open();
        insert_hot(&conn, 11, 0.8, 10);
        insert_hot(&conn, 12, 0.9, 10);
        insert_hot(&conn, 13, 0.95, 20);
        insert_hot(&conn, 14, 0.8, 30);
        let tx = conn.transaction().unwrap();
        reconcile(&tx, 100).unwrap();
        tx.commit().unwrap();
        conn.execute("DELETE FROM idx_episode WHERE event_id = 11", [])
            .unwrap();
        conn.execute(
            "UPDATE idx_episode SET importance = 0.74 WHERE event_id = 14",
            [],
        )
        .unwrap();
        drop(conn);
        let read_only = open_read_only(&dir.path().join("views.db")).unwrap();
        let rows = query_current_rows(&read_only, None, 20).unwrap();
        assert_eq!(
            rows.iter().map(|row| row.event_id).collect::<Vec<_>>(),
            vec![13, 12]
        );
        assert_eq!(
            query_current_rows(&read_only, Some("event-13"), 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            query_current_rows(&read_only, None, 1).unwrap()[0].event_id,
            13
        );
    }
}
