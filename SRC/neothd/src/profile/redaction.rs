//! Operator-asserted profile redactions — `SPEC_profile_claim_guard.md` H2.
//!
//! When an operator says "forget my location and never re-extract it,
//! even if I mention Berlin again later", that's a redaction: a per-field
//! marker that forbids the extractor pipeline from proposing future
//! claims against that field. Backed by `idx_profile_redactions`.
//!
//! Stage 5 and the final apply-time race recheck consult this registry. Normal
//! entries block an exact profile field. The `_tombstone.<topic>` entries that
//! `neoth memory --forget <topic>` writes atomically block the topic in any
//! future claim field or structured value.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

/// One redaction row. `never_recreate` is the H2 invariant — when true,
/// the guard rejects any future claim matching this field. `revoked_at`
/// is operator-driven unlock (rare; the original GDPR-style redaction
/// is intentionally permanent until explicit lift).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Redaction {
    pub id: i64,
    pub field: String,
    pub never_recreate: bool,
    pub reason: Option<String>,
    pub asserted_by: String,
    pub asserted_at: i64,
    pub revoked_at: Option<i64>,
}

impl Redaction {
    /// True when the redaction is currently active (not revoked).
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// Add a new redaction. Fails if an active redaction for the same field
/// already exists (UNIQUE index on (field, revoked_at IS NULL)).
pub fn add(
    conn: &Connection,
    field: &str,
    never_recreate: bool,
    reason: Option<&str>,
    asserted_by: &str,
    now_unix: i64,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO idx_profile_redactions \
         (field, never_recreate, reason, asserted_by, asserted_at, revoked_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
        params![
            field,
            if never_recreate { 1 } else { 0 },
            reason,
            asserted_by,
            now_unix,
        ],
    )
    .with_context(|| format!("insert redaction for `{field}`"))?;
    Ok(conn.last_insert_rowid())
}

/// Revoke an active redaction by id. Returns `true` if a row was updated.
pub fn revoke(conn: &Connection, id: i64, now_unix: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE idx_profile_redactions SET revoked_at = ?1 \
         WHERE id = ?2 AND revoked_at IS NULL",
        params![now_unix, id],
    )?;
    Ok(n > 0)
}

/// Look up the active redaction for a field. Returns `None` when no
/// active redaction exists (the most common path — most fields have
/// no redaction).
pub fn lookup_active(conn: &Connection, field: &str) -> Result<Option<Redaction>> {
    let row = conn
        .query_row(
            "SELECT id, field, never_recreate, reason, asserted_by, asserted_at, revoked_at \
             FROM idx_profile_redactions \
             WHERE field = ?1 AND revoked_at IS NULL \
             LIMIT 1",
            params![field],
            row_to_redaction,
        )
        .ok();
    Ok(row)
}

/// List every redaction, active first. Used by `neoth profile redactions`
/// CLI when it lands.
pub fn list_all(conn: &Connection) -> Result<Vec<Redaction>> {
    let mut stmt = conn.prepare(
        "SELECT id, field, never_recreate, reason, asserted_by, asserted_at, revoked_at \
         FROM idx_profile_redactions \
         ORDER BY revoked_at IS NOT NULL, asserted_at DESC",
    )?;
    let rows = stmt
        .query_map([], row_to_redaction)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect redactions")?;
    Ok(rows)
}

/// Active permanent redactions used by the final apply-time race recheck.
/// Returning complete rows preserves the redaction id/asserting actor needed
/// by the `PROFILE_REDACT_BLOCKED` audit event.
pub fn list_active(conn: &Connection) -> Result<Vec<Redaction>> {
    let mut stmt = conn.prepare(
        "SELECT id, field, never_recreate, reason, asserted_by, asserted_at, revoked_at \
         FROM idx_profile_redactions \
         WHERE revoked_at IS NULL AND never_recreate = 1 \
         ORDER BY asserted_at DESC, id DESC",
    )?;
    stmt.query_map([], row_to_redaction)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect active redactions")
}

fn row_to_redaction(r: &rusqlite::Row<'_>) -> rusqlite::Result<Redaction> {
    let never_recreate_int: i64 = r.get(2)?;
    Ok(Redaction {
        id: r.get(0)?,
        field: r.get(1)?,
        never_recreate: never_recreate_int != 0,
        reason: r.get(3)?,
        asserted_by: r.get(4)?,
        asserted_at: r.get(5)?,
        revoked_at: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use tempfile::tempdir;

    fn open_test_conn() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        (dir, conn)
    }

    #[test]
    fn add_creates_active_redaction() {
        let (_dir, conn) = open_test_conn();
        let id = add(
            &conn,
            "identity.location",
            true,
            Some("operator GDPR delete"),
            "operator",
            100,
        )
        .unwrap();
        assert!(id > 0);
        let r = lookup_active(&conn, "identity.location").unwrap().unwrap();
        assert!(r.is_active());
        assert!(r.never_recreate);
        assert_eq!(r.field, "identity.location");
        assert_eq!(r.reason.as_deref(), Some("operator GDPR delete"));
    }

    #[test]
    fn duplicate_active_redaction_for_same_field_rejected() {
        let (_dir, conn) = open_test_conn();
        add(&conn, "identity.x", true, None, "operator", 1).unwrap();
        let err = add(&conn, "identity.x", true, None, "operator", 2).unwrap_err();
        assert!(err.to_string().contains("insert redaction"));
    }

    #[test]
    fn revoke_marks_inactive_and_allows_re_add() {
        let (_dir, conn) = open_test_conn();
        let id = add(&conn, "identity.x", true, None, "operator", 1).unwrap();
        assert!(revoke(&conn, id, 100).unwrap());
        // After revocation, look-up returns None.
        assert!(lookup_active(&conn, "identity.x").unwrap().is_none());
        // And a new redaction for the same field can be added.
        let id2 = add(&conn, "identity.x", true, None, "operator", 200).unwrap();
        assert_ne!(id, id2);
    }

    #[test]
    fn revoke_idempotent_on_already_revoked_row() {
        let (_dir, conn) = open_test_conn();
        let id = add(&conn, "f", true, None, "op", 1).unwrap();
        assert!(revoke(&conn, id, 100).unwrap());
        // Second revoke returns false — no rows updated.
        assert!(!revoke(&conn, id, 200).unwrap());
    }

    #[test]
    fn lookup_active_returns_none_for_unknown_field() {
        let (_dir, conn) = open_test_conn();
        assert!(lookup_active(&conn, "never.seen").unwrap().is_none());
    }

    #[test]
    fn list_all_orders_active_before_revoked() {
        let (_dir, conn) = open_test_conn();
        let id1 = add(&conn, "a", true, None, "op", 1).unwrap();
        let _ = add(&conn, "b", true, None, "op", 2).unwrap();
        revoke(&conn, id1, 100).unwrap();
        let rows = list_all(&conn).unwrap();
        assert_eq!(rows.len(), 2);
        // Active row first
        assert!(rows[0].is_active());
        assert_eq!(rows[0].field, "b");
        // Revoked row second
        assert!(!rows[1].is_active());
        assert_eq!(rows[1].field, "a");
    }
}
