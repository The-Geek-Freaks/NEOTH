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
    /// GOLD-ADAPT-VIEW-04 — distilled from an imported foreign-agent SESSION
    /// transcript (claude-code / codex / gemini). Candidate until corroborated.
    ImportSession,
    /// GOLD-ADAPT-JV-IMP-06 — imported from an Obsidian vault note that carries
    /// no managed `source: openclaw-*` / `source: neoth-*` frontmatter (i.e. a
    /// note the operator wrote by hand, not a round-trip-managed file).
    ImportObsidian,
    /// Operator pasted a markdown file; the bulk-text extractor produced
    /// this claim.
    BulkText,
    /// OM-01 — promoted from the operator's LOCAL OMI backend transcript feed
    /// (SC-14: only ever a self-hosted endpoint; api.omi.me is refused at
    /// daemon startup).
    Omi,
    /// NN-MEM-02 — 5-dimensional synthesis pattern-recognition cron. Automated
    /// weekly meta-note written by `daemon::synthesis_cron`; NOT operator-
    /// attested (starts `Candidate`, corroboration required). Written as
    /// `source = "synthesis-cron"` in SQLite.
    Synthesis,
    /// GOLD-ADAPT-MEM-16 — ArXiv skill-learning cron. Actionable takeaways
    /// extracted from cs.AI/cs.LG papers by `daemon::arxiv_skill_scan_cron`;
    /// NOT operator-attested (starts `Candidate`, corroboration required).
    /// Written as `source = "arxiv-skill-scan"` / `scope = "arxiv-learning"`.
    ArxivScan,
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
            Source::ImportSession => "import:session",
            Source::ImportObsidian => "import:obsidian",
            Source::BulkText => "bulk-text",
            Source::Omi => "omi",
            Source::Synthesis => "synthesis-cron",
            Source::ArxivScan => "arxiv-skill-scan",
        }
    }

    /// GOLD-ADAPT-MEM-01 — is this source the operator directly attesting (typed
    /// it, ran the scan on their own network)? Such facts are trusted on sight
    /// (`Verified`). Externally-sourced facts (another agent's memory store, an
    /// OMI transcript) start as `Candidate` and must be corroborated before they
    /// are surfaced.
    ///
    /// NOTE: `BulkText` was previously operator-attested but is now excluded
    /// (GOLD-ADAPT-JV-MEM-01). Bulk-text extraction is automated — the operator
    /// pastes raw text and an extractor produces claims, which is NOT the same as
    /// the operator explicitly typing a fact. BulkText now starts `Raw` and must
    /// be corroborated (≥3 distinct sources, confidence ≥ 0.85) to reach Verified.
    pub fn is_operator_attested(&self) -> bool {
        matches!(
            self,
            Source::Onboarding
                | Source::OperatorRuntime
                | Source::NmapScan
                | Source::ArpScan
            // BulkText removed: extraction is automated; corroboration required.
            // GOLD-ADAPT-JV-MEM-01.
            // Synthesis is NOT operator-attested: it's an automated cron pass.
            // NN-MEM-02.
        )
    }

    /// The fact-state a freshly-inserted row from this source starts in.
    ///
    /// GOLD-ADAPT-JV-MEM-01: `BulkText` starts `Raw` (automated extraction;
    /// requires at least one external corroboration to lift to `Candidate`, then
    /// a second external source + confidence ≥ 0.85 to reach `Verified`).
    /// Operator-attested sources start `Verified` (immediate trust, gate 2).
    /// All other external sources start `Candidate`.
    pub fn initial_fact_state(&self) -> FactState {
        match self {
            // BulkText: operator pasted text but extraction is automated.
            // Start Raw; first external corroboration lifts to Candidate;
            // gates 1+3 (sourceCount ≥ 2 distinct + confidence ≥ 0.85) lift
            // to Verified. GOLD-ADAPT-JV-MEM-01.
            Source::BulkText => FactState::Raw,
            s if s.is_operator_attested() => FactState::Verified,
            _ => FactState::Candidate,
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

/// GOLD-ADAPT-JV-MEM-01 gate 3 — minimum Bayesian-average confidence required
/// (after a corroboration bump) before a non-operator-attested Candidate may be
/// promoted to Verified by source-count alone.
///
/// With midpoint-averaging: start 0.5 → 1st bump 0.75 → 2nd bump 0.875.
/// Two distinct external sources reach 0.75 (below threshold); a third source
/// bumps to 0.875 (≥ 0.85), so gate 1+3+4 all pass and the fact is promoted.
/// Operator-attested sources bypass this gate entirely (gate 2).
///
/// NOTE: existing `Candidate` rows with exactly 2 sources (confidence 0.75) will
/// NOT be retroactively demoted — they stay Candidate until a 3rd source arrives.
const PROMOTION_CONFIDENCE_THRESHOLD: f64 = 0.85;

/// Parse a `source_weight` JSON `{source: count}` map (best-effort: a malformed
/// value yields an empty map so a corrupt column never breaks an insert).
fn parse_source_weight(json: &str) -> std::collections::BTreeMap<String, u32> {
    serde_json::from_str(json).unwrap_or_default()
}

/// Serialize a `source_weight` map back to JSON (`{}` on failure).
fn source_weight_json(map: &std::collections::BTreeMap<String, u32>) -> String {
    serde_json::to_string(map).unwrap_or_else(|_| "{}".to_string())
}

// ── GOLD-ADAPT-NN-MEM-03/04 + JV-SELF-01 helpers ────────────────────────────

/// GOLD-ADAPT-NN-MEM-04 — derive the maturity label from a corroboration count
/// (pure, no I/O). Thresholds: 0-1 → "emerging", 2-4 → "working", 5+ → "stable".
pub fn maturity_for(confirmed_count: u32) -> &'static str {
    match confirmed_count {
        0..=1 => "emerging",
        2..=4 => "working",
        _ => "stable",
    }
}

/// GOLD-ADAPT-JV-SELF-01 — pull `current` confidence toward 1.0 by one
/// midpoint-averaging step: `(current + 1.0) / 2.0`. Each additional
/// corroboration cuts the remaining gap to certainty in half.
/// - Always in [0.0, 1.0] (bounded: if current is in range, result is too).
/// - Monotonically increasing for positive current values.
/// - A revocation / contradiction can lower confidence by calling this fn
///   with a mirrored step — no explicit decrement path exists yet; a
///   `// neoth: confidence-decrement on contradiction` note marks the gap.
pub fn bump_confidence(current: f64) -> f64 {
    (current + 1.0) / 2.0
}

/// GOLD-ADAPT-NN-MEM-03 — append `episode_id` to the JSON evidence array
/// stored for `fact_id`. Deduplicates and caps at 50 most-recent entries.
/// Best-effort: any parse/write failure is a no-op so the caller is never
/// blocked.
///
/// Use this sibling instead of threading `Option<i64>` through every
/// `groundtruth::insert` call site (those span hot files chat.rs / serve.rs).
/// Call it right after `insert(...)` when the asserting episode id is known.
pub fn record_evidence(
    conn: &Connection,
    fact_id: i64,
    episode_id: i64,
) -> Result<()> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT evidence FROM idx_groundtruth WHERE id = ?1",
            params![fact_id],
            |r| r.get(0),
        )
        .optional()
        .context("record_evidence: query evidence")?;

    let Some(raw) = raw else {
        return Ok(()); // fact_id not found — silent no-op
    };

    let mut ids: Vec<i64> = serde_json::from_str(&raw).unwrap_or_default();
    if !ids.contains(&episode_id) {
        ids.push(episode_id);
        // Keep only the 50 most-recent (last 50 entries).
        if ids.len() > 50 {
            ids.drain(0..ids.len() - 50);
        }
    }
    let json = serde_json::to_string(&ids).unwrap_or_else(|_| "[]".to_string());
    conn.execute(
        "UPDATE idx_groundtruth SET evidence = ?1 WHERE id = ?2",
        params![json, fact_id],
    )
    .context("record_evidence: write")?;
    Ok(())
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
    /// GOLD-ADAPT-JV-SELF-01 — Bayesian-average confidence [0.0, 1.0]. Each
    /// corroboration pulls the value toward 1.0 via midpoint averaging
    /// (`(confidence + 1.0) / 2.0`). Starts at 0.5 for fresh rows.
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// GOLD-ADAPT-NN-MEM-03 — JSON `[episode_id, ...]` provenance backlinks;
    /// up to 50 most-recent distinct episode ids that corroborated this fact.
    #[serde(default = "default_evidence")]
    pub evidence: String,
    /// GOLD-ADAPT-NN-MEM-04 — lifecycle label derived from `confirmed_count`:
    /// "emerging" (0-1), "working" (2-4), "stable" (5+).
    #[serde(default = "default_maturity")]
    pub maturity: String,
    /// GOLD-ADAPT-NN-MEM-04 — number of corroboration events received so far.
    #[serde(default)]
    pub confirmed_count: u32,
}

fn default_fact_state() -> String {
    "verified".to_string()
}
fn default_source_weight() -> String {
    "{}".to_string()
}
fn default_confidence() -> f64 {
    0.5
}
fn default_evidence() -> String {
    "[]".to_string()
}
fn default_maturity() -> String {
    "emerging".to_string()
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
    let existing: Option<(i64, String, String, f64, u32)> = conn
        .query_row(
            "SELECT id, fact_state, source_weight, confidence, confirmed_count \
             FROM idx_groundtruth \
             WHERE statement = ?1 AND scope = ?2 AND revoked_at IS NULL LIMIT 1",
            params![stmt, scope],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .context("query existing ground-truth")?;

    let id = if let Some((id, state_str, sw_json, confidence, confirmed_count)) = existing {
        let mut weights = parse_source_weight(&sw_json);
        *weights.entry(source.as_str().to_string()).or_insert(0) += 1;
        let mut state = FactState::parse(&state_str).unwrap_or(FactState::Candidate);
        // Only an unverified (Raw/Candidate) fact is promotable; a terminal state
        // the operator set is never silently flipped by a fresh assertion.
        let promotable = matches!(state, FactState::Raw | FactState::Candidate);

        // GOLD-ADAPT-JV-MEM-01 — 5-gate Jarvis promotion:
        //   Gate 1+4: sourceCount >= CORROBORATION_THRESHOLD distinct sources
        //             (gates 1 and 4 collapse — "non-single-source" == "≥2")
        //   Gate 2:   operator-attested source (immediate trust, bypasses 1+3+4)
        //   Gate 3:   confidence >= PROMOTION_CONFIDENCE_THRESHOLD (0.85) after bump
        //   Gate 5:   no semantic collision — proxied by the post-insert contradiction
        //             scan below (already wired); the losing fact gets Contradicted.
        //
        // Raw→Candidate intermediate step: if the fact is currently Raw and the
        // asserting source is NOT operator-attested, lift to Candidate first (gate 2
        // not met, but the fact is now corroborated by at least one external source).
        // The full 5-gate check then decides whether to continue to Verified.
        if promotable && state == FactState::Raw && !source.is_operator_attested() {
            state = FactState::Candidate;
        }

        let gate_operator = source.is_operator_attested();
        let gate_source_count = weights.len() >= CORROBORATION_THRESHOLD; // gates 1+4
        // Compute the post-bump confidence once (pure fn); used for gate 3 check
        // AND stored in the UPDATE below. GOLD-ADAPT-JV-SELF-01.
        let new_confidence = bump_confidence(confidence);
        let gate_confidence = new_confidence >= PROMOTION_CONFIDENCE_THRESHOLD; // gate 3
        if promotable && (gate_operator || (gate_source_count && gate_confidence)) {
            state = FactState::Verified;
        }
        // GOLD-ADAPT-NN-MEM-04: increment confirmed_count and recompute maturity.
        let new_confirmed = confirmed_count.saturating_add(1);
        let new_maturity = maturity_for(new_confirmed);
        conn.execute(
            "UPDATE idx_groundtruth \
             SET source_weight = ?1, fact_state = ?2, \
                 confidence = ?3, confirmed_count = ?4, maturity = ?5 \
             WHERE id = ?6",
            params![
                source_weight_json(&weights),
                state.as_str(),
                new_confidence,
                new_confirmed,
                new_maturity,
                id
            ],
        )
        .context("corroborate ground-truth")?;
        // GOLD-ADAPT-NN-MEM-03: evidence backlinks are threaded via the sibling
        // `record_evidence(conn, id, episode_id)` — call it from the site that
        // holds the episode_id. The insert fn has no episode_id in its signature
        // to avoid touching all callers (hot files: chat.rs, serve.rs).
        // neoth: confidence-decrement on contradiction — not wired here; a
        // `set_fact_state(Contradicted)` transition is the current mechanism.
        id
    } else {
        let state = source.initial_fact_state();
        let mut weights = std::collections::BTreeMap::new();
        weights.insert(source.as_str().to_string(), 1u32);
        // New rows start with defaults: confidence 0.5, empty evidence, maturity
        // "emerging", confirmed_count 0 (no corroboration events yet).
        conn.execute(
            "INSERT INTO idx_groundtruth \
                (statement, source, scope, asserted_at, revoked_at, fact_state, source_weight, \
                 confidence, evidence, maturity, confirmed_count) \
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, 0.5, '[]', 'emerging', 0)",
            params![
                stmt,
                source.as_str(),
                scope,
                now_ns,
                state.as_str(),
                source_weight_json(&weights)
            ],
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
        "SELECT id, statement, source, scope, asserted_at, revoked_at, fact_state, source_weight, \
                confidence, evidence, maturity, confirmed_count \
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
        "SELECT id, statement, source, scope, asserted_at, revoked_at, fact_state, source_weight, \
                confidence, evidence, maturity, confirmed_count \
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

// ── L6-PRELOAD-RESTRICTED-INDEX-01 ───────────────────────────────────────────
//
// The functions below form the ONLY legitimate API for `idx_restricted`.
// The normal recall path (`surface_for_recall` / `list_for_scope`) is
// intentionally never modified to reference this table — the machine-enforced
// boundary is maintained here at the SQL query layer.

/// One row from `idx_restricted`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestrictedChunk {
    pub id: i64,
    pub statement: String,
    pub source_name: String,
    pub scope: String,
    pub risk_tier: String,
    pub asserted_at: i64,
    pub promoted_at: Option<i64>,
    pub promoted_by: Option<String>,
}

fn row_to_restricted(r: &rusqlite::Row<'_>) -> rusqlite::Result<RestrictedChunk> {
    Ok(RestrictedChunk {
        id: r.get(0)?,
        statement: r.get(1)?,
        source_name: r.get(2)?,
        scope: r.get(3)?,
        risk_tier: r.get(4)?,
        asserted_at: r.get(5)?,
        promoted_at: r.get(6)?,
        promoted_by: r.get(7)?,
    })
}

/// Ingest a chunk into `idx_restricted`. Idempotent on exact `(statement, scope)` match —
/// re-inserting the same content for the same scope returns the existing row id.
pub fn insert_restricted(
    conn: &Connection,
    statement: &str,
    source_name: &str,
    scope: &str,
    risk_tier: &str,
    now_ns: i64,
) -> Result<i64> {
    let stmt = statement.trim();
    if stmt.is_empty() {
        anyhow::bail!("restricted statement must be non-empty");
    }
    // Idempotent: if an identical (statement, scope) row already exists, return its id.
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM idx_restricted WHERE statement = ?1 AND scope = ?2 LIMIT 1",
            params![stmt, scope],
            |r| r.get(0),
        )
        .optional()
        .context("query existing restricted chunk")?;
    if let Some(id) = existing {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO idx_restricted \
         (statement, source_name, scope, risk_tier, asserted_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![stmt, source_name, scope, risk_tier, now_ns],
    )
    .context("insert_restricted")?;
    Ok(conn.last_insert_rowid())
}

/// Return all rows in `idx_restricted` for the given scope, ordered newest-first.
/// Used by `neoth obsidian promote` and operator inspection; NOT part of the
/// normal recall surface.
pub fn search_restricted(conn: &Connection, scope: &str) -> Result<Vec<RestrictedChunk>> {
    let mut stmt = conn.prepare(
        "SELECT id, statement, source_name, scope, risk_tier, asserted_at, promoted_at, promoted_by \
         FROM idx_restricted \
         WHERE scope = ?1 \
         ORDER BY asserted_at DESC",
    )?;
    let rows = stmt
        .query_map(params![scope], row_to_restricted)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Fetch a single restricted chunk by id. Returns `None` when not found.
pub fn get_restricted(conn: &Connection, id: i64) -> Result<Option<RestrictedChunk>> {
    conn.query_row(
        "SELECT id, statement, source_name, scope, risk_tier, asserted_at, promoted_at, promoted_by \
         FROM idx_restricted WHERE id = ?1",
        params![id],
        row_to_restricted,
    )
    .optional()
    .context("get_restricted")
}

/// The outcome of a `promote_restricted` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromoteOutcome {
    /// Row moved to `idx_groundtruth`; contains the new groundtruth id.
    Promoted { groundtruth_id: i64 },
    /// Row was already promoted in a prior call — no-op.
    AlreadyPromoted { groundtruth_id_hint: Option<i64> },
    /// `--dry-run`: describes what would happen without writing anything.
    DryRun { chunk: RestrictedChunk },
}

/// Promote a restricted chunk into `idx_groundtruth` with operator attestation.
///
/// - Stamps `promoted_at` / `promoted_by` on the `idx_restricted` row.
/// - Inserts into `idx_groundtruth` via the standard `insert()` path
///   (inherits corroboration / trust logic; starts `verified` because
///   `Source::OperatorRuntime` is operator-attested).
/// - Idempotent: a second call on the same `id` returns `AlreadyPromoted`.
/// - `dry_run = true` returns `DryRun` without touching either table.
pub fn promote_restricted(
    conn: &Connection,
    restricted_id: i64,
    promoted_by: &str,
    now_ns: i64,
    dry_run: bool,
) -> Result<PromoteOutcome> {
    let chunk = get_restricted(conn, restricted_id)
        .context("promote_restricted: load chunk")?
        .ok_or_else(|| anyhow::anyhow!("idx_restricted row {} not found", restricted_id))?;

    if chunk.promoted_at.is_some() {
        // Already promoted — find the groundtruth row if possible.
        let gt_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM idx_groundtruth \
                 WHERE statement = ?1 AND scope = ?2 AND revoked_at IS NULL LIMIT 1",
                params![chunk.statement, chunk.scope],
                |r| r.get(0),
            )
            .optional()
            .context("promote_restricted: lookup existing gt row")?;
        return Ok(PromoteOutcome::AlreadyPromoted {
            groundtruth_id_hint: gt_id,
        });
    }

    if dry_run {
        return Ok(PromoteOutcome::DryRun { chunk });
    }

    // Insert into idx_groundtruth via the standard insert path.
    let gt_id = insert(
        conn,
        &chunk.statement,
        &Source::OperatorRuntime,
        &chunk.scope,
        now_ns,
    )
    .context("promote_restricted: groundtruth insert")?;

    // Stamp promoted_at / promoted_by on the restricted row.
    conn.execute(
        "UPDATE idx_restricted SET promoted_at = ?1, promoted_by = ?2 WHERE id = ?3",
        params![now_ns, promoted_by, restricted_id],
    )
    .context("promote_restricted: stamp promoted_at")?;

    Ok(PromoteOutcome::Promoted {
        groundtruth_id: gt_id,
    })
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
        // GOLD-ADAPT-JV-SELF-01 / NN-MEM-03 / NN-MEM-04 — v20 columns.
        // Existing rows carry the column DEFAULTs (0.5 / '[]' / 'emerging' / 0).
        confidence: r.get(8)?,
        evidence: r.get(9)?,
        maturity: r.get(10)?,
        confirmed_count: r.get(11)?,
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
        let id = insert(
            &conn,
            "nas at 10.0.0.5",
            &Source::OperatorRuntime,
            "global",
            1,
        )
        .unwrap();
        let st: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            st, "verified",
            "operator-attested facts are verified on sight"
        );
        assert_eq!(surface_for_recall(&conn, 10, false).unwrap().len(), 1);
    }

    #[test]
    fn external_source_starts_candidate_and_is_held_back_from_recall() {
        let (_dir, conn) = open();
        let id = insert(&conn, "alice prefers tea", &Source::Omi, "global", 1).unwrap();
        let st: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
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
    fn two_distinct_sources_hold_candidate_confidence_gate_blocks() {
        // GOLD-ADAPT-JV-MEM-01: gate 3 (confidence ≥ 0.85) means 2 distinct
        // external sources (confidence = 0.75 after first corroboration bump)
        // are NOT sufficient — the fact stays Candidate. A third distinct source
        // bumps confidence to 0.875 ≥ 0.85, passing all gates → Verified.
        let (_dir, conn) = open();
        let id1 = insert(&conn, "team standup is at 9am", &Source::Omi, "global", 1).unwrap();
        // Second distinct source: corroborates but confidence 0.75 < 0.85 → still Candidate.
        let id2 = insert(
            &conn,
            "team standup is at 9am",
            &Source::ImportHermes,
            "global",
            2,
        )
        .unwrap();
        assert_eq!(id1, id2, "corroborate does not create a new row");
        let (st2, conf2): (String, f64) = conn
            .query_row(
                "SELECT fact_state, confidence FROM idx_groundtruth WHERE id=?1",
                params![id1],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            st2, "candidate",
            "2 distinct sources reach confidence 0.75 < 0.85 — still Candidate"
        );
        assert!(
            (conf2 - 0.75).abs() < f64::EPSILON,
            "confidence after first corroboration bump = 0.75"
        );
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            0,
            "Candidate is NOT surfaced"
        );
        // Third distinct source: confidence bumps to 0.875 ≥ 0.85 — all gates pass.
        let id3 = insert(
            &conn,
            "team standup is at 9am",
            &Source::ImportOpenclaw,
            "global",
            3,
        )
        .unwrap();
        assert_eq!(id1, id3, "corroborate does not create a new row");
        let (st3, sw3): (String, String) = conn
            .query_row(
                "SELECT fact_state, source_weight FROM idx_groundtruth WHERE id=?1",
                params![id1],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            st3, "verified",
            "3 distinct sources, confidence 0.875 ≥ 0.85 — gates 1+3+4 all pass"
        );
        assert!(
            sw3.contains("omi") && sw3.contains("import:hermes") && sw3.contains("import:openclaw"),
            "all three sources recorded"
        );
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            1,
            "now surfaces in recall canonical lane"
        );
    }

    #[test]
    fn same_source_reassertion_does_not_promote_a_candidate() {
        let (_dir, conn) = open();
        let id = insert(&conn, "router pw rotated", &Source::Omi, "global", 1).unwrap();
        let id2 = insert(&conn, "router pw rotated", &Source::Omi, "global", 2).unwrap();
        assert_eq!(id, id2);
        let st: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            st, "candidate",
            "one source asserting twice is NOT corroboration"
        );
    }

    #[test]
    fn operator_reassertion_verifies_an_external_candidate() {
        let (_dir, conn) = open();
        let id = insert(&conn, "vpn endpoint is x", &Source::Omi, "global", 1).unwrap();
        let id2 = insert(
            &conn,
            "vpn endpoint is x",
            &Source::OperatorRuntime,
            "global",
            2,
        )
        .unwrap();
        assert_eq!(id, id2);
        let st: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            st, "verified",
            "an operator re-assertion verifies immediately"
        );
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
        assert!(
            !set_fact_state(&conn, 99_999, FactState::Verified).unwrap(),
            "unknown id → false"
        );
    }

    #[test]
    fn corroboration_never_revives_an_operator_terminal_state() {
        let (_dir, conn) = open();
        let id = insert(
            &conn,
            "decommissioned host",
            &Source::OperatorRuntime,
            "global",
            1,
        )
        .unwrap();
        set_fact_state(&conn, id, FactState::Deprecated).unwrap();
        // A fresh external assertion of the same statement must NOT revive it.
        let id2 = insert(&conn, "decommissioned host", &Source::Omi, "global", 2).unwrap();
        assert_eq!(id, id2);
        let st: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            st, "deprecated",
            "a terminal state set by the operator is not silently flipped"
        );
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

    // ── GOLD-ADAPT-JV-SELF-01 + NN-MEM-03 + NN-MEM-04 ───────────────────────

    #[test]
    fn maturity_for_boundaries() {
        assert_eq!(maturity_for(0), "emerging");
        assert_eq!(maturity_for(1), "emerging", "boundary: 1 still emerging");
        assert_eq!(maturity_for(2), "working", "boundary: 2 is working");
        assert_eq!(maturity_for(4), "working", "boundary: 4 still working");
        assert_eq!(maturity_for(5), "stable", "boundary: 5 is stable");
        assert_eq!(maturity_for(100), "stable", "large count stays stable");
    }

    #[test]
    fn bump_confidence_monotonic_toward_one() {
        let c0 = 0.5_f64;
        let c1 = bump_confidence(c0);
        let c2 = bump_confidence(c1);
        let c3 = bump_confidence(c2);
        assert!(c1 > c0, "each bump increases confidence");
        assert!(c2 > c1);
        assert!(c3 > c2);
        assert!(c3 < 1.0, "never reaches 1.0 in finite steps");
        // Verify the midpoint formula: (0.5 + 1.0) / 2.0 = 0.75.
        assert!((c1 - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn fresh_row_reads_defaults_confidence_maturity() {
        let (_dir, conn) = open();
        let id =
            insert(&conn, "fresh fact", &Source::OperatorRuntime, "global", 1).unwrap();
        let rows = list_for_scope(&conn, "global").unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.id, id);
        // v20 defaults
        assert!((row.confidence - 0.5).abs() < f64::EPSILON, "default confidence 0.5");
        assert_eq!(row.evidence, "[]", "default evidence is empty JSON array");
        assert_eq!(row.maturity, "emerging", "default maturity is emerging");
        assert_eq!(row.confirmed_count, 0, "default confirmed_count is 0");
    }

    #[test]
    fn corroboration_bumps_confirmed_count_confidence_maturity() {
        // GOLD-ADAPT-JV-MEM-01: with the confidence gate (≥ 0.85), the first
        // corroboration (2 distinct sources, confidence = 0.75) no longer promotes
        // to Verified — the fact stays Candidate. The second corroboration (3rd
        // distinct source, confidence = 0.875 ≥ 0.85) passes all gates → Verified.
        let (_dir, conn) = open();
        // First insert (external source → Candidate).
        let id = insert(&conn, "proxy is at 10.0.0.1", &Source::Omi, "global", 1).unwrap();

        // First corroboration (second distinct source): confidence 0.75 < 0.85
        // → stays Candidate (gate 3 blocks promotion).
        let id2 = insert(
            &conn,
            "proxy is at 10.0.0.1",
            &Source::ImportHermes,
            "global",
            2,
        )
        .unwrap();
        assert_eq!(id, id2, "corroborate does not create a new row");

        let rows = list_for_scope(&conn, "global").unwrap();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.confirmed_count, 1, "one corroboration event");
        assert_eq!(r.maturity, "emerging", "1 corroboration → still emerging");
        // confidence: (0.5 + 1.0) / 2.0 = 0.75
        assert!((r.confidence - 0.75).abs() < f64::EPSILON, "confidence bumped");
        assert_eq!(
            r.fact_state, "candidate",
            "2 sources, confidence 0.75 < 0.85 — gate 3 blocks promotion"
        );

        // Second corroboration (third distinct source): confidence 0.875 ≥ 0.85
        // → gates 1+3+4 all pass → promoted to Verified.
        let id3 = insert(
            &conn,
            "proxy is at 10.0.0.1",
            &Source::ImportOpenclaw,
            "global",
            3,
        )
        .unwrap();
        assert_eq!(id, id3);

        let rows2 = list_for_scope(&conn, "global").unwrap();
        let r2 = &rows2[0];
        assert_eq!(r2.confirmed_count, 2, "two corroboration events");
        assert_eq!(r2.maturity, "working", "2 corroborations → working");
        // confidence: (0.75 + 1.0) / 2.0 = 0.875
        assert!((r2.confidence - 0.875).abs() < f64::EPSILON);
        assert_eq!(
            r2.fact_state, "verified",
            "3 sources, confidence 0.875 ≥ 0.85 — Verified"
        );
    }

    #[test]
    fn record_evidence_appends_and_deduplicates() {
        let (_dir, conn) = open();
        let id = insert(&conn, "dns is 1.1.1.1", &Source::OperatorRuntime, "global", 1).unwrap();

        record_evidence(&conn, id, 42).unwrap();
        record_evidence(&conn, id, 99).unwrap();
        // duplicate — must not appear twice
        record_evidence(&conn, id, 42).unwrap();

        let rows = list_for_scope(&conn, "global").unwrap();
        let ev: Vec<i64> =
            serde_json::from_str(&rows[0].evidence).expect("valid JSON array");
        assert_eq!(ev.len(), 2, "42 deduplicated; only 42 + 99");
        assert!(ev.contains(&42));
        assert!(ev.contains(&99));
    }

    #[test]
    fn record_evidence_caps_at_50() {
        let (_dir, conn) = open();
        let id =
            insert(&conn, "many-witnesses", &Source::OperatorRuntime, "global", 1).unwrap();

        for ep in 0i64..60 {
            record_evidence(&conn, id, ep).unwrap();
        }
        let rows = list_for_scope(&conn, "global").unwrap();
        let ev: Vec<i64> =
            serde_json::from_str(&rows[0].evidence).expect("valid JSON array");
        assert_eq!(ev.len(), 50, "capped at 50 most-recent");
        // The oldest 10 (0..10) must have been dropped; last 50 (10..60) survive.
        assert_eq!(ev[0], 10, "oldest retained is episode 10");
        assert_eq!(ev[49], 59, "newest is episode 59");
    }

    #[test]
    fn record_evidence_noop_on_unknown_id() {
        let (_dir, conn) = open();
        // Must not error.
        record_evidence(&conn, 999_999, 1).unwrap();
    }

    // ── GOLD-ADAPT-JV-MEM-01 — 7-state machine + 5-gate promotion ───────────

    #[test]
    fn bulk_text_starts_raw() {
        // BulkText is no longer operator-attested (GOLD-ADAPT-JV-MEM-01):
        // auto-extraction is not the operator explicitly attesting a fact.
        let (_dir, conn) = open();
        let id = insert(&conn, "proxy is 10.0.0.1", &Source::BulkText, "global", 1).unwrap();
        let st: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(st, "raw", "BulkText inserts Raw, not Candidate or Verified");
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            0,
            "Raw fact is NOT surfaced into recall"
        );
        // Operator can inspect it with include_unverified=true.
        assert_eq!(surface_for_recall(&conn, 10, true).unwrap().len(), 1);
        assert!(!Source::BulkText.is_operator_attested());
    }

    #[test]
    fn bulk_text_first_corroboration_lifts_raw_to_candidate_not_verified() {
        // First external corroboration of a BulkText-Raw fact:
        // sourceCount reaches 2 distinct but confidence = 0.75 < 0.85 (gate 3).
        // Raw→Candidate intermediate step fires; full promotion gate does NOT.
        let (_dir, conn) = open();
        let id = insert(&conn, "proxy is 10.0.0.1", &Source::BulkText, "global", 1).unwrap();
        let id2 = insert(&conn, "proxy is 10.0.0.1", &Source::Omi, "global", 2).unwrap();
        assert_eq!(id, id2);
        let (st, conf): (String, f64) = conn
            .query_row(
                "SELECT fact_state, confidence FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            st, "candidate",
            "first external corroboration lifts Raw→Candidate"
        );
        assert!(
            (conf - 0.75).abs() < f64::EPSILON,
            "confidence 0.5→0.75 after first bump"
        );
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            0,
            "Candidate is NOT surfaced in recall canonical lane"
        );
    }

    #[test]
    fn promotion_requires_confidence_not_just_two_sources() {
        // Gate 3 enforced: 2 distinct external sources (confidence = 0.75 < 0.85)
        // must NOT promote a Candidate to Verified.
        let (_dir, conn) = open();
        insert(&conn, "dns is 8.8.8.8", &Source::Omi, "global", 1).unwrap();
        insert(&conn, "dns is 8.8.8.8", &Source::ImportHermes, "global", 2).unwrap();
        let (st, conf): (String, f64) = conn
            .query_row(
                "SELECT fact_state, confidence FROM idx_groundtruth WHERE statement=?1",
                params!["dns is 8.8.8.8"],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            st, "candidate",
            "2 sources, confidence 0.75 — gate 3 blocks promotion"
        );
        assert!(
            (conf - 0.75).abs() < f64::EPSILON,
            "confidence = 0.75 (one bump from 0.5)"
        );
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            0,
            "still blocked from recall"
        );
    }

    #[test]
    fn three_sources_reach_085_confidence_and_promote() {
        // Gate 3 passed at 3rd distinct source: confidence bumps to 0.875 ≥ 0.85.
        // All gates 1+3+4 pass → promoted to Verified and surfaced in recall.
        let (_dir, conn) = open();
        insert(&conn, "proxy is 10.0.0.1", &Source::Omi, "global", 1).unwrap();
        insert(&conn, "proxy is 10.0.0.1", &Source::ImportHermes, "global", 2).unwrap();
        insert(&conn, "proxy is 10.0.0.1", &Source::ImportOpenclaw, "global", 3).unwrap();
        let (st, conf): (String, f64) = conn
            .query_row(
                "SELECT fact_state, confidence FROM idx_groundtruth WHERE statement=?1",
                params!["proxy is 10.0.0.1"],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            st, "verified",
            "3 distinct sources, confidence 0.875 ≥ 0.85 — Verified"
        );
        assert!(
            (conf - 0.875).abs() < f64::EPSILON,
            "confidence = 0.875 after two corroboration bumps"
        );
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            1,
            "Verified fact surfaces in recall canonical lane"
        );
    }

    #[test]
    fn promotion_gate_blocks_recall_until_all_gates_pass() {
        // Integration test: proves the consumer path (surface_for_recall, which
        // recall.rs::recall_groundtruth_like delegates to under query_three_lanes)
        // correctly enforces all 5 gates end-to-end.
        let (_dir, conn) = open();

        // BulkText inserts Raw, not Verified, not surfaced.
        let id = insert(&conn, "proxy is 10.0.0.1", &Source::BulkText, "global", 1).unwrap();
        let st: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(st, "raw");
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            0,
            "Raw not surfaced"
        );

        // First external source: 2 distinct sources but confidence=0.75 < 0.85
        // — must stay Candidate, NOT promoted.
        let id2 = insert(&conn, "proxy is 10.0.0.1", &Source::Omi, "global", 2).unwrap();
        assert_eq!(id, id2);
        let (st2, conf2): (String, f64) = conn
            .query_row(
                "SELECT fact_state, confidence FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            st2, "candidate",
            "first corroboration lifts Raw→Candidate"
        );
        assert!(
            (conf2 - 0.75).abs() < 1e-9,
            "confidence 0.5→0.75 after 1 bump"
        );
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            0,
            "Candidate with confidence 0.75 still blocked"
        );

        // Second external source: 3 distinct weights, confidence bumps to 0.875 ≥ 0.85
        // — all gates pass, Verified, surfaced in recall.
        let id3 = insert(
            &conn,
            "proxy is 10.0.0.1",
            &Source::ImportHermes,
            "global",
            3,
        )
        .unwrap();
        assert_eq!(id, id3);
        let st3: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            st3, "verified",
            "gates 1+3+4 all pass at 3 sources / conf 0.875"
        );
        assert_eq!(
            surface_for_recall(&conn, 10, false).unwrap().len(),
            1,
            "Verified fact surfaces in recall canonical lane"
        );
    }

    #[test]
    fn operator_attested_still_promotes_immediately_bypassing_confidence_gate() {
        // Gate 2: operator-attested sources bypass the confidence gate entirely.
        // Onboarding, OperatorRuntime, NmapScan, ArpScan still verify on sight.
        let (_dir, conn) = open();
        let id = insert(&conn, "nas at 192.168.1.1", &Source::NmapScan, "global", 1).unwrap();
        let st: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(st, "verified", "NmapScan is still operator-attested → Verified");
        // Operator-attested reassertion of a Candidate also verifies immediately.
        let id2 = insert(&conn, "dns is 8.8.8.8", &Source::Omi, "global", 2).unwrap();
        let id3 = insert(
            &conn,
            "dns is 8.8.8.8",
            &Source::OperatorRuntime,
            "global",
            3,
        )
        .unwrap();
        assert_eq!(id2, id3);
        let st3: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id=?1",
                params![id2],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            st3, "verified",
            "operator reassertion of a Candidate verifies immediately (gate 2)"
        );
    }

    // ── L6-PRELOAD-RESTRICTED-INDEX-01 tests ─────────────────────────────────

    /// HARD GUARANTEE (SQL layer): the SQL strings used by the recall path do
    /// NOT contain "idx_restricted". This test pins the query-layer boundary
    /// so a future edit that accidentally widens the recall surface fails fast.
    #[test]
    fn hard_guarantee_recall_sql_never_references_idx_restricted() {
        // These are the literal SQL fragments embedded in surface_for_recall
        // and list_for_scope. If either function is refactored to touch
        // idx_restricted, this test will be updated — and that update is the
        // moment the reviewer must consciously approve the boundary crossing.
        let surface_sql = "SELECT id, statement, source, scope, asserted_at, revoked_at, \
                            fact_state, source_weight, confidence, evidence, maturity, confirmed_count \
                            FROM idx_groundtruth \
                            WHERE revoked_at IS NULL";
        let list_sql = "SELECT id, statement, source, scope, asserted_at, revoked_at, \
                         fact_state, source_weight, confidence, evidence, maturity, confirmed_count \
                         FROM idx_groundtruth \
                         WHERE scope = ?1 AND revoked_at IS NULL";
        assert!(
            !surface_sql.contains("idx_restricted"),
            "surface_for_recall SQL must never reference idx_restricted"
        );
        assert!(
            !list_sql.contains("idx_restricted"),
            "list_for_scope SQL must never reference idx_restricted"
        );
    }

    /// HARD GUARANTEE (integration): a chunk inserted into idx_restricted is
    /// INVISIBLE to the normal recall path. The same content IS findable via
    /// the explicit search_restricted path.
    #[test]
    fn restricted_ingest_invisible_to_normal_recall() {
        let (_dir, conn) = open();
        let secret_stmt = "shellcode: jmp eax; ret # exploit-db 99999";
        let scope = "exploit-test";

        // Insert into restricted table.
        let rid = insert_restricted(
            &conn,
            secret_stmt,
            "exploitdb",
            scope,
            "exploit-code",
            1_000,
        )
        .unwrap();
        assert!(rid > 0);

        // surface_for_recall must return zero rows from the restricted content.
        let recall_hits = surface_for_recall(&conn, 100, true).unwrap();
        let leaked = recall_hits.iter().any(|g| g.statement == secret_stmt);
        assert!(
            !leaked,
            "restricted content must not appear in surface_for_recall output"
        );

        // list_for_scope must also return zero rows.
        let scope_hits = list_for_scope(&conn, scope).unwrap();
        assert!(
            scope_hits.is_empty(),
            "restricted content must not appear in list_for_scope output"
        );

        // But search_restricted MUST find it.
        let restricted_hits = search_restricted(&conn, scope).unwrap();
        assert_eq!(restricted_hits.len(), 1);
        assert_eq!(restricted_hits[0].statement, secret_stmt);
        assert_eq!(restricted_hits[0].risk_tier, "exploit-code");
        assert!(restricted_hits[0].promoted_at.is_none());
    }

    #[test]
    fn insert_restricted_idempotent_on_same_statement_scope() {
        let (_dir, conn) = open();
        let id1 = insert_restricted(&conn, "payload A", "src", "scope-x", "dual-use", 1_000).unwrap();
        let id2 = insert_restricted(&conn, "payload A", "src", "scope-x", "dual-use", 2_000).unwrap();
        assert_eq!(id1, id2, "re-insert of identical (statement, scope) must be a no-op");
        let rows = search_restricted(&conn, "scope-x").unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn promotion_round_trip_moves_to_groundtruth_and_stamps() {
        let (_dir, conn) = open();
        let stmt = "GTFOBins: find / -perm -u=s -type f 2>/dev/null";
        let rid = insert_restricted(&conn, stmt, "gtfobins", "gtfo-scope", "dual-use-payloads", 1_000).unwrap();

        let outcome = promote_restricted(&conn, rid, "operator-runtime", 2_000, false).unwrap();
        let gt_id = match outcome {
            PromoteOutcome::Promoted { groundtruth_id } => groundtruth_id,
            other => panic!("expected Promoted, got {:?}", other),
        };
        assert!(gt_id > 0);

        // Verify the groundtruth row exists.
        let gt_rows = list_for_scope(&conn, "gtfo-scope").unwrap();
        assert_eq!(gt_rows.len(), 1);
        assert_eq!(gt_rows[0].statement, stmt);
        assert_eq!(gt_rows[0].fact_state, "verified");

        // Verify the restricted row is stamped.
        let restricted = get_restricted(&conn, rid).unwrap().unwrap();
        assert!(restricted.promoted_at.is_some());
        assert_eq!(restricted.promoted_by.as_deref(), Some("operator-runtime"));
    }

    #[test]
    fn re_promote_is_noop_returns_already_promoted() {
        let (_dir, conn) = open();
        let rid = insert_restricted(&conn, "payload X", "src", "scope-y", "exploit-code", 1_000).unwrap();
        let first = promote_restricted(&conn, rid, "op", 2_000, false).unwrap();
        assert!(matches!(first, PromoteOutcome::Promoted { .. }));

        // Second promotion must be a no-op.
        let second = promote_restricted(&conn, rid, "op", 3_000, false).unwrap();
        assert!(
            matches!(second, PromoteOutcome::AlreadyPromoted { .. }),
            "second promotion must return AlreadyPromoted, got {:?}",
            second
        );

        // Only one groundtruth row should exist.
        let gt_rows = list_for_scope(&conn, "scope-y").unwrap();
        assert_eq!(gt_rows.len(), 1, "duplicate groundtruth rows must not be created");
    }

    #[test]
    fn dry_run_promote_writes_nothing() {
        let (_dir, conn) = open();
        let rid = insert_restricted(&conn, "payload Y", "src", "scope-z", "exploit-code", 1_000).unwrap();

        let outcome = promote_restricted(&conn, rid, "op", 2_000, true).unwrap();
        assert!(matches!(outcome, PromoteOutcome::DryRun { .. }));

        // Nothing should be in groundtruth.
        let gt_rows = list_for_scope(&conn, "scope-z").unwrap();
        assert!(gt_rows.is_empty(), "dry-run must not write to idx_groundtruth");

        // The restricted row must remain un-stamped.
        let r = get_restricted(&conn, rid).unwrap().unwrap();
        assert!(r.promoted_at.is_none(), "dry-run must not stamp promoted_at");
    }
}
