//! Ground-truth view — Phase 28c R-24 GT-2.
//!
//! Authoritative facts the operator stored explicitly. Decay-immune,
//! scope-tagged, revocable. Surfaced in every recall hit BEFORE any episodic
//! row so a stale Hebbian-decayed memory cannot overwrite an operator
//! ground truth.
//!
//! ## Why a separate table?
//!
//! Sliding "if importance ≥ 0.95 treat as fact" is the failure mode this
//! module exists to prevent. Ground-truth lives in `idx_groundtruth` with
//! its own scoring path (no Hebbian decay, no FORGET_FLOOR sweep, no
//! consolidation pass). Promotion is always explicit (`neoth groundtruth
//! add`); revocation is `neoth groundtruth revoke <id>`.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

/// Where a ground-truth row came from. Stored as a free-form string in
/// SQLite (the column is `TEXT NOT NULL`) but constrained to this set at
/// insert time so the audit trail stays clean.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// Picked up during the wizard's Q&A path.
    Onboarding,
    /// Operator typed `neoth groundtruth add` after init.
    OperatorRuntime,
    /// Subnet scan (`arp -a` / `nmap -sn`) discovered the host.
    NmapScan,
    ArpScan,
    /// Imported from another agent's memory store.
    ImportHermes,
    ImportOpenclaw,
    ImportOpenhuman,
    ImportVeronica,
    /// Operator pasted a markdown file; the bulk-text extractor produced
    /// this claim.
    BulkText,
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::Onboarding => "onboarding",
            Source::OperatorRuntime => "operator-runtime",
            Source::NmapScan => "nmap-scan",
            Source::ArpScan => "arp-scan",
            Source::ImportHermes => "import:hermes",
            Source::ImportOpenclaw => "import:openclaw",
            Source::ImportOpenhuman => "import:openhuman",
            Source::ImportVeronica => "import:veronica",
            Source::BulkText => "bulk-text",
        }
    }
}

/// Scope = "to whom / where" this fact applies. Free-form so operators can
/// extend with their own tags, but the wizard + scanners use:
///   - `global`            — applies anywhere
///   - `host:<hostname>`   — single machine
///   - `session:<id>`      — single conversation (rare; usually a normal
///                           episode is the right bucket for that)
pub type Scope = String;

/// One row from `idx_groundtruth`. `revoked_at = None` means active.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroundTruth {
    pub id: i64,
    pub statement: String,
    pub source: String,
    pub scope: String,
    pub asserted_at: i64,
    pub revoked_at: Option<i64>,
}

/// Insert a new ground-truth row. Returns the new id.
pub fn insert(
    conn: &Connection,
    statement: &str,
    source: &Source,
    scope: &str,
    now_ns: i64,
) -> Result<i64> {
    if statement.trim().is_empty() {
        anyhow::bail!("ground-truth statement must be non-empty");
    }
    conn.execute(
        "INSERT INTO idx_groundtruth (statement, source, scope, asserted_at, revoked_at) \
         VALUES (?1, ?2, ?3, ?4, NULL)",
        params![statement.trim(), source.as_str(), scope, now_ns],
    )
    .context("insert ground-truth")?;
    Ok(conn.last_insert_rowid())
}

/// Mark a row revoked. Sets `revoked_at`. Idempotent — re-revoking an
/// already-revoked row updates the timestamp but is otherwise a no-op.
/// Returns `true` if a row was modified, `false` if the id is unknown.
pub fn revoke(conn: &Connection, id: i64, now_ns: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE idx_groundtruth SET revoked_at = ?1 WHERE id = ?2",
        params![now_ns, id],
    )?;
    Ok(n > 0)
}

/// Active rows for one scope (revoked_at IS NULL).
pub fn list_for_scope(conn: &Connection, scope: &str) -> Result<Vec<GroundTruth>> {
    let mut stmt = conn.prepare(
        "SELECT id, statement, source, scope, asserted_at, revoked_at \
         FROM idx_groundtruth \
         WHERE scope = ?1 AND revoked_at IS NULL \
         ORDER BY asserted_at DESC",
    )?;
    let rows = stmt
        .query_map(params![scope], row_to_gt)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every active ground-truth row, used by the recall surface to prepend
/// authoritative facts ahead of episodic hits.
pub fn surface_for_recall(conn: &Connection, limit: usize) -> Result<Vec<GroundTruth>> {
    let mut stmt = conn.prepare(
        "SELECT id, statement, source, scope, asserted_at, revoked_at \
         FROM idx_groundtruth \
         WHERE revoked_at IS NULL \
         ORDER BY asserted_at DESC \
         LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![limit as i64], row_to_gt)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Count of active rows. Used by `neoth memory --tier` summary lines.
pub fn count_active(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT count(*) FROM idx_groundtruth WHERE revoked_at IS NULL",
        [],
        |r| r.get(0),
    )?)
}

fn row_to_gt(r: &rusqlite::Row<'_>) -> rusqlite::Result<GroundTruth> {
    Ok(GroundTruth {
        id: r.get(0)?,
        statement: r.get(1)?,
        source: r.get(2)?,
        scope: r.get(3)?,
        asserted_at: r.get(4)?,
        revoked_at: r.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use tempfile::tempdir;

    fn open() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let conn = store::open(&db).unwrap();
        (dir, conn)
    }

    #[test]
    fn insert_returns_new_id_and_persists() {
        let (_dir, conn) = open();
        let id = insert(
            &conn,
            "primary nas is at 192.168.178.20",
            &Source::Onboarding,
            "global",
            1_000,
        )
        .unwrap();
        assert!(id > 0);
        let rows = list_for_scope(&conn, "global").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].statement, "primary nas is at 192.168.178.20");
        assert_eq!(rows[0].source, "onboarding");
        assert!(rows[0].revoked_at.is_none());
    }

    #[test]
    fn insert_trims_whitespace_and_rejects_empty() {
        let (_dir, conn) = open();
        let id = insert(&conn, "  trimmed  ", &Source::OperatorRuntime, "global", 1).unwrap();
        let row: String = conn
            .query_row(
                "SELECT statement FROM idx_groundtruth WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(row, "trimmed");
        let err = insert(&conn, "   ", &Source::OperatorRuntime, "global", 1).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn revoke_marks_revoked_at_and_filters_from_scope_listing() {
        let (_dir, conn) = open();
        let id = insert(&conn, "x", &Source::OperatorRuntime, "global", 1).unwrap();
        assert_eq!(list_for_scope(&conn, "global").unwrap().len(), 1);
        let modified = revoke(&conn, id, 9_999).unwrap();
        assert!(modified);
        assert_eq!(list_for_scope(&conn, "global").unwrap().len(), 0);
        // Row still in table, just hidden from active queries.
        let raw_count: i64 = conn
            .query_row("SELECT count(*) FROM idx_groundtruth", [], |r| r.get(0))
            .unwrap();
        assert_eq!(raw_count, 1);
    }

    #[test]
    fn revoke_unknown_id_returns_false() {
        let (_dir, conn) = open();
        let modified = revoke(&conn, 99_999, 1).unwrap();
        assert!(!modified);
    }

    #[test]
    fn surface_for_recall_returns_active_rows_only_descending() {
        let (_dir, conn) = open();
        insert(&conn, "a", &Source::Onboarding, "global", 1).unwrap();
        insert(&conn, "b", &Source::Onboarding, "global", 2).unwrap();
        let id_c = insert(&conn, "c", &Source::Onboarding, "global", 3).unwrap();
        revoke(&conn, id_c, 4).unwrap();
        let out = surface_for_recall(&conn, 10).unwrap();
        let texts: Vec<&str> = out.iter().map(|g| g.statement.as_str()).collect();
        assert_eq!(texts, vec!["b", "a"], "c revoked, b newer than a");
    }

    #[test]
    fn count_active_excludes_revoked() {
        let (_dir, conn) = open();
        insert(&conn, "a", &Source::Onboarding, "global", 1).unwrap();
        let id = insert(&conn, "b", &Source::Onboarding, "global", 2).unwrap();
        revoke(&conn, id, 3).unwrap();
        assert_eq!(count_active(&conn).unwrap(), 1);
    }

    #[test]
    fn source_strings_match_spec() {
        assert_eq!(Source::Onboarding.as_str(), "onboarding");
        assert_eq!(Source::ImportHermes.as_str(), "import:hermes");
        assert_eq!(Source::NmapScan.as_str(), "nmap-scan");
    }
}
