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
use rusqlite::{Connection, OptionalExtension, params};
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
    /// OM-01 — promoted from the operator's LOCAL OMI backend transcript feed
    /// (SC-14: only ever a self-hosted endpoint; api.omi.me is refused at
    /// daemon startup).
    Omi,
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
            Source::Omi => "omi",
        }
    }

    /// GOLD-ADAPT-MEM-01 — is this source the operator directly attesting (typed
    /// it, ran the scan on their own network, pasted their own file)? Such facts
    /// are trusted on sight (`Verified`). Externally-sourced facts (another
    /// agent's memory store, an OMI transcript) start as `Candidate` and must be
    /// corroborated before they are surfaced.
    pub fn is_operator_attested(&self) -> bool {
        matches!(
            self,
            Source::Onboarding
                | Source::OperatorRuntime
                | Source::BulkText
                | Source::NmapScan
                | Source::ArpScan
        )
    }

    /// The fact-state a freshly-inserted row from this source starts in.
    pub fn initial_fact_state(&self) -> FactState {
        if self.is_operator_attested() {
            FactState::Verified
        } else {
            FactState::Candidate
        }
    }
}

/// GOLD-ADAPT-MEM-01 — the trust state of a ground-truth fact. Only `Verified`
/// facts are surfaced into recall / council prompts; everything else is held
/// back until corroborated (≥2 distinct sources) or operator-confirmed.
///
/// Lifecycle: `Raw`/`Candidate` (unverified) → `Verified` (trusted) → may later
/// become `Superseded` (a newer fact replaced it), `Contradicted` (conflicts
/// with another verified fact), or `Deprecated` (operator retired it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactState {
    Raw,
    Candidate,
    Verified,
    Superseded,
    Contradicted,
    Deprecated,
}

impl FactState {
    pub fn as_str(self) -> &'static str {
        match self {
            FactState::Raw => "raw",
            FactState::Candidate => "candidate",
            FactState::Verified => "verified",
            FactState::Superseded => "superseded",
            FactState::Contradicted => "contradicted",
            FactState::Deprecated => "deprecated",
        }
    }

    /// Parse a stored/CLI fact-state string. `None` for an unknown value.
    pub fn parse(s: &str) -> Option<FactState> {
        match s.trim().to_ascii_lowercase().as_str() {
            "raw" => Some(FactState::Raw),
            "candidate" => Some(FactState::Candidate),
            "verified" => Some(FactState::Verified),
            "superseded" => Some(FactState::Superseded),
            "contradicted" => Some(FactState::Contradicted),
            "deprecated" => Some(FactState::Deprecated),
            _ => None,
        }
    }

    /// Only verified facts are trusted into recall / council injection.
    pub fn is_trusted(self) -> bool {
        matches!(self, FactState::Verified)
    }
}

/// GOLD-ADAPT-MEM-01 — a `Candidate` auto-promotes to `Verified` once this many
/// DISTINCT sources have independently asserted the same fact.
const CORROBORATION_THRESHOLD: usize = 2;

/// Parse a `source_weight` JSON `{source: count}` map (best-effort: a malformed
/// value yields an empty map so a corrupt column never breaks an insert).
fn parse_source_weight(json: &str) -> std::collections::BTreeMap<String, u32> {
    serde_json::from_str(json).unwrap_or_default()
}

/// Serialize a `source_weight` map back to JSON (`{}` on failure).
fn source_weight_json(map: &std::collections::BTreeMap<String, u32>) -> String {
    serde_json::to_string(map).unwrap_or_else(|_| "{}".to_string())
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
    /// GOLD-ADAPT-MEM-01 — trust state (only `verified` rows feed recall/council).
    #[serde(default = "default_fact_state")]
    pub fact_state: String,
    /// GOLD-ADAPT-MEM-01 — JSON `{source: count}` corroboration map.
    #[serde(default = "default_source_weight")]
    pub source_weight: String,
}

fn default_fact_state() -> String {
    "verified".to_string()
}
fn default_source_weight() -> String {
    "{}".to_string()
}

impl GroundTruth {
    /// GOLD-ADAPT-MEM-02 — number of DISTINCT sources that have asserted this
    /// fact (from the `source_weight` JSON map). Used to pick the more-credible
    /// fact when two contradict. A malformed map counts as 1 (the row exists).
    pub fn source_count(&self) -> usize {
        parse_source_weight(&self.source_weight).len().max(1)
    }
}

/// Insert a ground-truth fact, or CORROBORATE an existing identical one
/// (GOLD-ADAPT-MEM-01). Returns the row id (new or existing).
///
/// New facts start in the source's [`Source::initial_fact_state`] — operator-
/// attested → `Verified`, external (import/omi) → `Candidate`. Re-asserting the
/// same `(statement, scope)` among ACTIVE rows merges the asserting source into
/// the `source_weight` map and auto-promotes a `Candidate` to `Verified` once
/// ≥ [`CORROBORATION_THRESHOLD`] DISTINCT sources have asserted it (an operator
/// re-assertion verifies immediately). A fact the operator already moved to a
/// terminal state (verified / superseded / contradicted / deprecated) keeps that
/// state — only its corroboration map grows. The signature is unchanged so
/// existing callers (incl. `daemon::omi_ingest_task`) are unaffected.
pub fn insert(
    conn: &Connection,
    statement: &str,
    source: &Source,
    scope: &str,
    now_ns: i64,
) -> Result<i64> {
    let stmt = statement.trim();
    if stmt.is_empty() {
        anyhow::bail!("ground-truth statement must be non-empty");
    }

    // Corroboration path: an active row with the SAME statement + scope already
    // exists → merge this source instead of creating a duplicate.
    let existing: Option<(i64, String, String)> = conn
        .query_row(
            "SELECT id, fact_state, source_weight FROM idx_groundtruth \
             WHERE statement = ?1 AND scope = ?2 AND revoked_at IS NULL LIMIT 1",
            params![stmt, scope],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .context("query existing ground-truth")?;

    let id = if let Some((id, state_str, sw_json)) = existing {
        let mut weights = parse_source_weight(&sw_json);
        *weights.entry(source.as_str().to_string()).or_insert(0) += 1;
        let mut state = FactState::parse(&state_str).unwrap_or(FactState::Candidate);
        // Only an unverified (Raw/Candidate) fact is promotable; a terminal state
        // the operator set is never silently flipped by a fresh assertion.
        let promotable = matches!(state, FactState::Raw | FactState::Candidate);
        if promotable && (source.is_operator_attested() || weights.len() >= CORROBORATION_THRESHOLD)
        {
            state = FactState::Verified;
        }
        conn.execute(
            "UPDATE idx_groundtruth SET source_weight = ?1, fact_state = ?2 WHERE id = ?3",
            params![source_weight_json(&weights), state.as_str(), id],
        )
        .context("corroborate ground-truth")?;
        id
    } else {
        let state = source.initial_fact_state();
        let mut weights = std::collections::BTreeMap::new();
        weights.insert(source.as_str().to_string(), 1u32);
        conn.execute(
            "INSERT INTO idx_groundtruth \
                (statement, source, scope, asserted_at, revoked_at, fact_state, source_weight) \
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)",
            params![stmt, source.as_str(), scope, now_ns, state.as_str(), source_weight_json(&weights)],
        )
        .context("insert ground-truth")?;
        conn.last_insert_rowid()
    };

    // GOLD-ADAPT-MEM-02 — best-effort contradiction scan for the (re)asserted
    // fact. No-op unless the row is now Verified (gated inside). Covers direct
    // operator inserts AND corroboration-promotions (both end here). A detection
    // failure must NEVER propagate to the insert caller.
    if let Err(e) = crate::memory::contradiction::detect_contradictions_for(conn, id, now_ns) {
        tracing::debug!(error = %e, id, "contradiction scan failed (non-fatal)");
    }
    Ok(id)
}

/// GOLD-ADAPT-MEM-01 — set a fact's trust state explicitly (operator transition:
/// promote/demote/supersede/deprecate). Returns `true` if a row was updated.
pub fn set_fact_state(conn: &Connection, id: i64, state: FactState) -> Result<bool> {
    let n = conn.execute(
        "UPDATE idx_groundtruth SET fact_state = ?1 WHERE id = ?2",
        params![state.as_str(), id],
    )?;
    Ok(n > 0)
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

/// Active rows for one scope (revoked_at IS NULL). Returns ALL trust states
/// (incl. candidates) so the operator's `neoth groundtruth list` shows the full
/// picture with each row's `fact_state` — only the RECALL surface gates on
/// verified.
pub fn list_for_scope(conn: &Connection, scope: &str) -> Result<Vec<GroundTruth>> {
    let mut stmt = conn.prepare(
        "SELECT id, statement, source, scope, asserted_at, revoked_at, fact_state, source_weight \
         FROM idx_groundtruth \
         WHERE scope = ?1 AND revoked_at IS NULL \
         ORDER BY asserted_at DESC",
    )?;
    let rows = stmt
        .query_map(params![scope], row_to_gt)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Active ground-truth rows for the recall surface, which prepends authoritative
/// facts ahead of episodic hits. GOLD-ADAPT-MEM-01: only `verified` facts are
/// surfaced by default; `include_unverified = true` is the operator inspection
/// path that also returns candidates (and other non-revoked states).
pub fn surface_for_recall(
    conn: &Connection,
    limit: usize,
    include_unverified: bool,
) -> Result<Vec<GroundTruth>> {
    let state_filter = if include_unverified {
        ""
    } else {
        "AND fact_state = 'verified' "
    };
    let sql = format!(
        "SELECT id, statement, source, scope, asserted_at, revoked_at, fact_state, source_weight \
         FROM idx_groundtruth \
         WHERE revoked_at IS NULL {state_filter}\
         ORDER BY asserted_at DESC \
         LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
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
        fact_state: r.get(6)?,
        source_weight: r.get(7)?,
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
        let out = surface_for_recall(&conn, 10, false).unwrap();
        let texts: Vec<&str> = out.iter().map(|g| g.statement.as_str()).collect();
        assert_eq!(texts, vec!["b", "a"], "c revoked, b newer than a");
    }

    // ── GOLD-ADAPT-MEM-01 fact state machine ──

    #[test]
    fn operator_source_inserts_verified_and_surfaces_immediately() {
        let (_dir, conn) = open();
        let id = insert(&conn, "nas at 10.0.0.5", &Source::OperatorRuntime, "global", 1).unwrap();
        let st: String = conn
            .query_row("SELECT fact_state FROM idx_groundtruth WHERE id=?1", params![id], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "verified", "operator-attested facts are verified on sight");
        assert_eq!(surface_for_recall(&conn, 10, false).unwrap().len(), 1);
    }

    #[test]
    fn external_source_starts_candidate_and_is_held_back_from_recall() {
        let (_dir, conn) = open();
        let id = insert(&conn, "alice prefers tea", &Source::Omi, "global", 1).unwrap();
        let st: String = conn
            .query_row("SELECT fact_state FROM idx_groundtruth WHERE id=?1", params![id], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "candidate", "external (omi) facts start unverified");
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            0,
            "a candidate fact is NOT surfaced into recall"
        );
        // The operator can still inspect it.
        assert_eq!(surface_for_recall(&conn, 10, true).unwrap().len(), 1);
    }

    #[test]
    fn two_distinct_sources_corroborate_a_candidate_into_verified() {
        let (_dir, conn) = open();
        let id1 = insert(&conn, "team standup is at 9am", &Source::Omi, "global", 1).unwrap();
        // Same statement+scope from a SECOND distinct source → corroborated.
        let id2 =
            insert(&conn, "team standup is at 9am", &Source::ImportHermes, "global", 2).unwrap();
        assert_eq!(id1, id2, "the duplicate corroborates, it does not create a new row");
        let (st, sw): (String, String) = conn
            .query_row(
                "SELECT fact_state, source_weight FROM idx_groundtruth WHERE id=?1",
                params![id1],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(st, "verified", "≥2 distinct sources auto-promote candidate→verified");
        assert!(sw.contains("omi") && sw.contains("import:hermes"), "both sources recorded");
        assert_eq!(surface_for_recall(&conn, 10, false).unwrap().len(), 1, "now surfaces");
    }

    #[test]
    fn same_source_reassertion_does_not_promote_a_candidate() {
        let (_dir, conn) = open();
        let id = insert(&conn, "router pw rotated", &Source::Omi, "global", 1).unwrap();
        let id2 = insert(&conn, "router pw rotated", &Source::Omi, "global", 2).unwrap();
        assert_eq!(id, id2);
        let st: String = conn
            .query_row("SELECT fact_state FROM idx_groundtruth WHERE id=?1", params![id], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "candidate", "one source asserting twice is NOT corroboration");
    }

    #[test]
    fn operator_reassertion_verifies_an_external_candidate() {
        let (_dir, conn) = open();
        let id = insert(&conn, "vpn endpoint is x", &Source::Omi, "global", 1).unwrap();
        let id2 = insert(&conn, "vpn endpoint is x", &Source::OperatorRuntime, "global", 2).unwrap();
        assert_eq!(id, id2);
        let st: String = conn
            .query_row("SELECT fact_state FROM idx_groundtruth WHERE id=?1", params![id], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "verified", "an operator re-assertion verifies immediately");
    }

    #[test]
    fn set_fact_state_deprecate_removes_from_recall() {
        let (_dir, conn) = open();
        let id = insert(&conn, "old fact", &Source::OperatorRuntime, "global", 1).unwrap();
        assert_eq!(surface_for_recall(&conn, 10, false).unwrap().len(), 1);
        assert!(set_fact_state(&conn, id, FactState::Deprecated).unwrap());
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            0,
            "a deprecated fact is no longer surfaced"
        );
        assert!(!set_fact_state(&conn, 99_999, FactState::Verified).unwrap(), "unknown id → false");
    }

    #[test]
    fn corroboration_never_revives_an_operator_terminal_state() {
        let (_dir, conn) = open();
        let id = insert(&conn, "decommissioned host", &Source::OperatorRuntime, "global", 1).unwrap();
        set_fact_state(&conn, id, FactState::Deprecated).unwrap();
        // A fresh external assertion of the same statement must NOT revive it.
        let id2 = insert(&conn, "decommissioned host", &Source::Omi, "global", 2).unwrap();
        assert_eq!(id, id2);
        let st: String = conn
            .query_row("SELECT fact_state FROM idx_groundtruth WHERE id=?1", params![id], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "deprecated", "a terminal state set by the operator is not silently flipped");
    }

    #[test]
    fn fact_state_round_trips_and_is_trusted_only_when_verified() {
        for fs in [
            FactState::Raw,
            FactState::Candidate,
            FactState::Verified,
            FactState::Superseded,
            FactState::Contradicted,
            FactState::Deprecated,
        ] {
            assert_eq!(FactState::parse(fs.as_str()), Some(fs));
        }
        assert!(FactState::Verified.is_trusted());
        assert!(!FactState::Candidate.is_trusted());
        assert_eq!(FactState::parse("VERIFIED"), Some(FactState::Verified));
        assert_eq!(FactState::parse("nonsense"), None);
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
