//! GOLD-ADAPT-MEM-02 — contradiction detection + ledger over ground-truth facts.
//!
//! Two operator facts can disagree ("the nas is at X" vs "the nas is at Y";
//! "the vpn is up" vs "the vpn is not up"). This module detects such pairs and
//! records them in `idx_contradictions`, then flags the LOWER-credibility fact
//! (fewer corroborating sources, per MEM-01's `source_weight`) as
//! [`FactState::Contradicted`] so it drops out of recall (`surface_for_recall`
//! already gates on `verified`).
//!
//! ## No embeddings — a text-similarity proxy
//! NEOTH has no text embeddings for facts (`idx_embedding` is CLIP-media-only),
//! so the plan's "cosine" similarity is replaced by **token-Jaccard** over
//! normalised statement tokens, split into a SUBJECT part (before the first
//! copula) and a VALUE part (after it). Two facts contradict when they share a
//! subject (subject-Jaccard ≥ [`SUBJECT_SIM_THRESHOLD`]) AND either their
//! polarity differs (one carries a negation marker the other lacks — reusing
//! `council::factual_check::DEFAULT_NEGATION_MARKERS`, bilingual EN/DE) OR their
//! value tokens diverge.
//!
//! ## Triggers (no new cron, no `serve_tasks.rs`)
//! Detection runs best-effort inside [`crate::memory::groundtruth::insert`] for
//! every newly-verified fact (covers direct inserts AND corroboration-promotions
//! — both end in `insert`). [`scan_contradictions`] is the operator on-demand
//! full re-scan (`neoth groundtruth contradictions --detect`).
//!
//! ## WAL
//! Detections are logged via `tracing` (no new WAL event). The free slot
//! `0x9D EVENT_TYPE_CONTRADICTION_DETECTED` is reserved for a future PR that can
//! touch the (currently parallel-hot) `wal/events.rs`.

use std::collections::HashSet;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::council::factual_check::DEFAULT_NEGATION_MARKERS;
use crate::memory::groundtruth::{self, FactState, GroundTruth};

/// Minimum subject-token Jaccard for two facts to be considered "about the same
/// thing" — below this they're different subjects (e.g. nas vs router).
pub const SUBJECT_SIM_THRESHOLD: f32 = 0.5;

/// Minimum fused confidence for a pair to be emitted into the ledger.
pub const EMIT_THRESHOLD: f32 = 0.7;

/// Bilingual stopwords dropped from token sets so common glue words don't
/// inflate the overlap. Includes the copulas (which delimit subject/value).
const STOPWORDS: &[&str] = &[
    "is", "are", "was", "were", "the", "a", "an", "in", "at", "of", "to", "and", "or", "has",
    "have", "be", "it", "its", "on", "for", // English
    "und", "ist", "sind", "war", "die", "der", "das", "ein", "eine", "von", "zu", "auf", "hat",
    "bei", "im", "am", // German
];

/// Words that delimit a fact's SUBJECT (left) from its VALUE (right).
const COPULAS: &[&str] = &[
    "is", "are", "was", "were", "ist", "sind", "war", "has", "have", "hat", "at", "bei", "=",
];

/// A detected contradiction pair (canonical `a_id < b_id`).
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedPair {
    pub a_id: i64,
    pub b_id: i64,
    pub confidence: f32,
    /// `true` = polarity flip (the loser is auto-flagged Contradicted); `false` =
    /// value divergence (recorded for operator review, no auto-flag).
    pub negation: bool,
}

/// Cap on how many same-scope peers a single insert-time scan compares against
/// (newest-first) — bounds per-insert latency on a large fact corpus.
const MAX_PEERS: usize = 500;

/// One stored ledger row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContradictionRow {
    pub ledger_id: i64,
    pub fact_a_id: i64,
    pub fact_b_id: i64,
    pub confidence: f32,
    pub detected_at: i64,
    pub resolved_at: Option<i64>,
    pub decision: String,
}

/// Lowercase + split + strip per-token ASCII punctuation (char-based so German
/// umlauts survive) + drop stopwords. Returns the content-token set. The
/// production path uses the subject/value split below; this flat set is the
/// reference used by tests.
#[cfg(test)]
fn token_set(s: &str) -> HashSet<String> {
    s.to_lowercase()
        .split_whitespace()
        .map(|t| t.trim_matches(|c: char| c.is_ascii_punctuation()).to_string())
        .filter(|t| !t.is_empty() && !STOPWORDS.contains(&t.as_str()))
        .collect()
}

/// Raw lowercased tokens (punctuation-trimmed) in order — used for subject/value
/// splitting where ORDER matters (the copula position).
fn ordered_tokens(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split_whitespace()
        .map(|t| t.trim_matches(|c: char| c.is_ascii_punctuation()).to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Content tokens BEFORE the first copula (the subject). If no copula is found,
/// the first 3 content tokens. Stopwords (other than the copula delimiter) are
/// dropped so "the primary nas" and "primary nas" match.
fn subject_tokens(s: &str) -> HashSet<String> {
    let toks = ordered_tokens(s);
    let cut = toks.iter().position(|t| COPULAS.contains(&t.as_str()));
    let head: Vec<&String> = match cut {
        Some(i) => toks[..i].iter().collect(),
        None => toks.iter().take(3).collect(),
    };
    head.into_iter()
        .filter(|t| !STOPWORDS.contains(&t.as_str()))
        .cloned()
        .collect()
}

/// Content tokens AFTER the first copula (the value). Empty if no copula.
fn value_tokens(s: &str) -> HashSet<String> {
    let toks = ordered_tokens(s);
    match toks.iter().position(|t| COPULAS.contains(&t.as_str())) {
        Some(i) => toks[i + 1..]
            .iter()
            .filter(|t| !STOPWORDS.contains(&t.as_str()))
            .cloned()
            .collect(),
        None => HashSet::new(),
    }
}

/// Jaccard overlap `|a∩b| / |a∪b|`. 0.0 when both empty.
fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count() as f32;
    let union = a.union(b).count() as f32;
    if union == 0.0 { 0.0 } else { inter / union }
}

/// Does the statement carry a negation marker? Token-exact for single-word
/// markers (so "no" matches but "now" does not) + substring for the multi-word
/// markers ("stimmt nicht").
fn has_negation(s: &str) -> bool {
    let lower = s.to_lowercase();
    let toks: HashSet<String> = lower
        .split_whitespace()
        .map(|t| t.trim_matches(|c: char| c.is_ascii_punctuation() && c != '\'').to_string())
        .collect();
    DEFAULT_NEGATION_MARKERS.iter().any(|m| {
        if m.contains(' ') {
            lower.contains(m)
        } else {
            toks.contains(*m)
        }
    })
}

/// The outcome of comparing two facts: a confidence plus whether the signal is a
/// **negation/polarity flip** (an UNAMBIGUOUS contradiction the detector may
/// auto-resolve by flagging the loser `Contradicted`) versus a value divergence
/// (AMBIGUOUS — could be a legitimately multi-valued attribute like two meetings
/// or two servers; recorded for the operator's review but NEVER auto-resolved).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PairSignal {
    pub confidence: f32,
    /// `true` = polarity flip (auto-resolvable); `false` = value divergence only.
    pub negation: bool,
}

/// Pure pairwise signal that two statements contradict, or `None`.
///
/// Same subject (subject-Jaccard ≥ [`SUBJECT_SIM_THRESHOLD`]) AND a disagreement
/// signal — opposite polarity (negation XOR) OR diverging value tokens.
/// `confidence = subject_jaccard·0.6 + (negation ? 0.4 : value_diverges ? 0.3 : 0)`.
pub fn pair_confidence(stmt_a: &str, stmt_b: &str) -> Option<PairSignal> {
    let subj = jaccard(&subject_tokens(stmt_a), &subject_tokens(stmt_b));
    if subj < SUBJECT_SIM_THRESHOLD {
        return None;
    }
    let negation = has_negation(stmt_a) != has_negation(stmt_b);
    let va = value_tokens(stmt_a);
    let vb = value_tokens(stmt_b);
    // Diverging values: both have a value and they are not equal sets. (Identical
    // values with the same subject = the same fact, not a contradiction.)
    let value_diverges = !va.is_empty() && !vb.is_empty() && va != vb;

    if !negation && !value_diverges {
        return None;
    }
    let signal = if negation { 0.4 } else { 0.3 };
    let confidence = (subj * 0.6 + signal).min(1.0);
    if confidence >= EMIT_THRESHOLD {
        Some(PairSignal { confidence, negation })
    } else {
        None
    }
}

/// Only Verified facts are compared — unverified (Raw/Candidate) and terminal
/// states (Superseded/Contradicted/Deprecated) are skipped. Comparing only
/// trusted facts keeps the ledger meaningful and prevents a candidate from
/// flagging an established fact before it is itself corroborated.
fn is_comparable(fact_state: &str) -> bool {
    matches!(FactState::parse(fact_state), Some(FactState::Verified))
}

/// PURE: all contradicting pairs within `facts` (same scope only), canonical
/// `a_id < b_id`, deduped. Caller supplies the rows; no DB access.
pub fn detect_contradictions(facts: &[GroundTruth]) -> Vec<DetectedPair> {
    let mut out = Vec::new();
    for i in 0..facts.len() {
        for j in (i + 1)..facts.len() {
            let a = &facts[i];
            let b = &facts[j];
            if a.scope != b.scope {
                continue;
            }
            if !is_comparable(&a.fact_state) || !is_comparable(&b.fact_state) {
                continue;
            }
            if let Some(sig) = pair_confidence(&a.statement, &b.statement) {
                let (lo, hi) = if a.id < b.id { (a.id, b.id) } else { (b.id, a.id) };
                out.push(DetectedPair {
                    a_id: lo,
                    b_id: hi,
                    confidence: sig.confidence,
                    negation: sig.negation,
                });
            }
        }
    }
    out
}

/// The loser of a contradiction = the fact with FEWER corroborating sources
/// (MEM-01 `source_weight`); tie → the OLDER fact (lower id). Returns the id to
/// flag `Contradicted`.
fn loser_id(a: &GroundTruth, b: &GroundTruth) -> i64 {
    let ca = a.source_count();
    let cb = b.source_count();
    if ca < cb {
        a.id
    } else if cb < ca {
        b.id
    } else if a.id <= b.id {
        a.id
    } else {
        b.id
    }
}

/// Record one detected pair into `idx_contradictions` (idempotent — `INSERT OR
/// IGNORE` on the unique canonical pair) and flag the loser `Contradicted`
/// (guarded: only an active Verified loser is flipped). Returns `true` if a new
/// ledger row was created.
fn record_pair(
    conn: &Connection,
    a: &GroundTruth,
    b: &GroundTruth,
    sig: PairSignal,
    now_ns: i64,
) -> Result<bool> {
    let (lo, hi) = if a.id < b.id { (a.id, b.id) } else { (b.id, a.id) };
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO idx_contradictions \
            (fact_a_id, fact_b_id, confidence, detected_at, resolved_at, decision) \
         VALUES (?1, ?2, ?3, ?4, NULL, 'pending')",
        params![lo, hi, sig.confidence as f64, now_ns],
    )?;
    // AUTO-RESOLVE ONLY a polarity/negation contradiction ("vpn up" vs "vpn not
    // up") — that is unambiguous. A value divergence ("nas at X" vs "nas at Y")
    // could be a legitimately multi-valued attribute (two meetings, two servers),
    // so it is RECORDED in the ledger for the operator but the loser is NOT
    // silently hidden. The operator resolves value divergences via the CLI.
    if sig.negation {
        let loser = loser_id(a, b);
        let winner = if loser == a.id { b.id } else { a.id };
        // Flip the loser only if it is currently Verified (don't touch a terminal
        // state, and don't re-flip an already-Contradicted row).
        let loser_state: Option<String> = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id = ?1 AND revoked_at IS NULL",
                params![loser],
                |r| r.get(0),
            )
            .optional()?;
        if matches!(loser_state.as_deref().and_then(FactState::parse), Some(FactState::Verified)) {
            groundtruth::set_fact_state(conn, loser, FactState::Contradicted)?;
            tracing::info!(
                fact_a_id = lo,
                fact_b_id = hi,
                loser_id = loser,
                winner_id = winner,
                confidence = sig.confidence,
                "MEM-02: polarity contradiction — loser flagged Contradicted",
            );
        }
    } else if inserted > 0 {
        tracing::info!(
            fact_a_id = lo,
            fact_b_id = hi,
            confidence = sig.confidence,
            "MEM-02: value-divergence recorded for operator review (no auto-flag)",
        );
    }
    Ok(inserted > 0)
}

/// Read the active Verified rows in one scope for comparison, newest-first,
/// capped at [`MAX_PEERS`] (a new contradiction almost always involves a recent
/// fact, and this bounds per-insert latency on a large corpus).
fn active_verified_in_scope(conn: &Connection, scope: &str) -> Result<Vec<GroundTruth>> {
    groundtruth::list_for_scope(conn, scope).map(|rows| {
        rows.into_iter()
            .filter(|g| is_comparable(&g.fact_state))
            .take(MAX_PEERS)
            .collect()
    })
}

/// TRIGGER 1 — best-effort detection for one freshly-(re)asserted fact. No-op
/// unless the row is active + Verified. Compares it against every other active
/// Verified fact in the same scope. Records pairs + flags losers. Returns the
/// detected `(lo, hi)` pairs.
pub fn detect_contradictions_for(
    conn: &Connection,
    new_id: i64,
    now_ns: i64,
) -> Result<Vec<(i64, i64)>> {
    let row: Option<GroundTruth> = conn
        .query_row(
            "SELECT id, statement, source, scope, asserted_at, revoked_at, fact_state, source_weight \
             FROM idx_groundtruth WHERE id = ?1",
            params![new_id],
            row_to_gt,
        )
        .optional()
        .context("load new fact for contradiction scan")?;
    let Some(new_fact) = row else { return Ok(Vec::new()) };
    if new_fact.revoked_at.is_some() || !is_comparable(&new_fact.fact_state) {
        return Ok(Vec::new());
    }
    let peers = active_verified_in_scope(conn, &new_fact.scope)?;
    let mut detected = Vec::new();
    for peer in &peers {
        if peer.id == new_fact.id {
            continue;
        }
        if let Some(sig) = pair_confidence(&new_fact.statement, &peer.statement) {
            if record_pair(conn, &new_fact, peer, sig, now_ns)? {
                let (lo, hi) =
                    if new_fact.id < peer.id { (new_fact.id, peer.id) } else { (peer.id, new_fact.id) };
                detected.push((lo, hi));
            }
        }
    }
    Ok(detected)
}

/// TRIGGER 2 — full re-scan over every active Verified fact (grouped by scope).
/// Idempotent (existing pairs are `INSERT OR IGNORE`d). Returns the count of NEW
/// ledger rows created.
pub fn scan_contradictions(conn: &Connection, now_ns: i64) -> Result<usize> {
    let all = groundtruth::surface_for_recall(conn, 100_000, true)?;
    let verified: Vec<GroundTruth> =
        all.into_iter().filter(|g| is_comparable(&g.fact_state)).collect();
    let mut new_rows = 0usize;
    for i in 0..verified.len() {
        for j in (i + 1)..verified.len() {
            let a = &verified[i];
            let b = &verified[j];
            if a.scope != b.scope {
                continue;
            }
            if let Some(sig) = pair_confidence(&a.statement, &b.statement) {
                if record_pair(conn, a, b, sig, now_ns)? {
                    new_rows += 1;
                }
            }
        }
    }
    Ok(new_rows)
}

/// List ledger rows, newest first. `include_resolved=false` hides dismissed pairs.
pub fn list_contradictions(
    conn: &Connection,
    include_resolved: bool,
) -> Result<Vec<ContradictionRow>> {
    let sql = if include_resolved {
        "SELECT id, fact_a_id, fact_b_id, confidence, detected_at, resolved_at, decision \
         FROM idx_contradictions ORDER BY detected_at DESC"
    } else {
        "SELECT id, fact_a_id, fact_b_id, confidence, detected_at, resolved_at, decision \
         FROM idx_contradictions WHERE decision = 'pending' ORDER BY detected_at DESC"
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(ContradictionRow {
                ledger_id: r.get(0)?,
                fact_a_id: r.get(1)?,
                fact_b_id: r.get(2)?,
                confidence: r.get::<_, f64>(3)? as f32,
                detected_at: r.get(4)?,
                resolved_at: r.get(5)?,
                decision: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Operator dismissal: mark a ledger row resolved AND restore recall visibility.
/// Dismissing a contradiction means the operator judged both facts legitimate, so
/// any fact this detection auto-flagged `Contradicted` is re-promoted to
/// `Verified` (it surfaces in recall again). Returns `true` if a pending row was
/// dismissed.
pub fn resolve(conn: &Connection, ledger_id: i64, now_ns: i64) -> Result<bool> {
    let pair: Option<(i64, i64)> = conn
        .query_row(
            "SELECT fact_a_id, fact_b_id FROM idx_contradictions \
             WHERE id = ?1 AND decision != 'dismissed'",
            params![ledger_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((a, b)) = pair else { return Ok(false) };
    conn.execute(
        "UPDATE idx_contradictions SET decision = 'dismissed', resolved_at = ?1 WHERE id = ?2",
        params![now_ns, ledger_id],
    )?;
    // Restore any fact THIS detection auto-flagged Contradicted back to Verified.
    for id in [a, b] {
        let st: Option<String> = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE id = ?1 AND revoked_at IS NULL",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        if matches!(st.as_deref().and_then(FactState::parse), Some(FactState::Contradicted)) {
            groundtruth::set_fact_state(conn, id, FactState::Verified)?;
        }
    }
    Ok(true)
}

/// GOLD-ADAPT-MEM-02 GDPR cascade — delete every ledger row referencing any of
/// `revoked_ids` (a forgotten fact must not linger as a live leg of a pair).
/// Returns the number of ledger rows deleted.
pub fn forget_for_ids(conn: &Connection, revoked_ids: &[i64]) -> Result<i64> {
    if revoked_ids.is_empty() {
        return Ok(0);
    }
    let placeholders = revoked_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "DELETE FROM idx_contradictions \
         WHERE fact_a_id IN ({p}) OR fact_b_id IN ({p})",
        p = placeholders
    );
    // The id list is bound once per IN clause; double it for params_from_iter
    // (avoids the fragile twice-pushed &dyn ToSql pattern).
    let doubled: Vec<i64> = revoked_ids.iter().chain(revoked_ids.iter()).copied().collect();
    let n = conn.execute(&sql, rusqlite::params_from_iter(doubled))?;
    Ok(n as i64)
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
    use crate::memory::groundtruth::Source;
    use crate::memory::store;

    fn gt(id: i64, statement: &str, scope: &str, fact_state: &str, source_weight: &str) -> GroundTruth {
        GroundTruth {
            id,
            statement: statement.to_string(),
            source: "operator-runtime".to_string(),
            scope: scope.to_string(),
            asserted_at: id,
            revoked_at: None,
            fact_state: fact_state.to_string(),
            source_weight: source_weight.to_string(),
        }
    }

    #[test]
    fn token_set_drops_stopwords_and_punctuation() {
        let ts = token_set("The NAS is at 192.168.1.1!");
        assert!(ts.contains("nas"));
        assert!(ts.contains("192.168.1.1"));
        assert!(!ts.contains("the") && !ts.contains("is") && !ts.contains("at"));
    }

    #[test]
    fn subject_tokens_stop_at_copula() {
        assert!(subject_tokens("primary nas is at 192.168.1.1").contains("nas"));
        assert!(!subject_tokens("primary nas is at 192.168.1.1").contains("192.168.1.1"));
        assert!(subject_tokens("primary nas at 10.0.0.5").contains("nas"));
    }

    #[test]
    fn jaccard_overlap() {
        let a: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let b: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        assert_eq!(jaccard(&a, &b), 1.0);
        let c: HashSet<String> = ["c"].iter().map(|s| s.to_string()).collect();
        assert_eq!(jaccard(&a, &c), 0.0);
    }

    #[test]
    fn has_negation_token_exact_bilingual() {
        assert!(has_negation("the vpn is not up"));
        assert!(has_negation("der server ist nicht erreichbar"));
        assert!(has_negation("that is false"));
        assert!(!has_negation("the vpn is up now")); // "now" must NOT match "no"
        assert!(!has_negation("nas at 10.0.0.5"));
    }

    #[test]
    fn pair_confidence_value_divergence_is_recorded_not_negation() {
        let sig = pair_confidence("nas is at 192.168.1.20", "nas is at 10.0.0.5");
        assert!(sig.is_some(), "same subject, diverging value → recorded");
        let sig = sig.unwrap();
        assert!(sig.confidence >= EMIT_THRESHOLD);
        assert!(!sig.negation, "value divergence is ambiguous → no auto-flag");
    }

    #[test]
    fn pair_confidence_negation_flip_is_auto_resolvable() {
        let sig = pair_confidence("the vpn is up", "the vpn is not up");
        assert!(sig.is_some(), "same subject, opposite polarity → contradiction");
        assert!(sig.unwrap().negation, "a polarity flip is auto-resolvable");
    }

    #[test]
    fn pair_confidence_identical_is_not_a_contradiction() {
        assert!(pair_confidence("nas is at 192.168.1.1", "nas is at 192.168.1.1").is_none());
    }

    #[test]
    fn pair_confidence_different_subject_suppressed() {
        // Same value, different subject (nas vs router) → not a contradiction.
        assert!(pair_confidence("nas is at 192.168.1.1", "router is at 192.168.1.1").is_none());
    }

    #[test]
    fn detect_contradictions_same_scope_only() {
        let facts = vec![
            gt(1, "nas is at 192.168.1.20", "global", "verified", "{}"),
            gt(2, "nas is at 10.0.0.5", "host:cube", "verified", "{}"),
        ];
        assert!(detect_contradictions(&facts).is_empty(), "different scope → no pair");
        let same = vec![
            gt(1, "nas is at 192.168.1.20", "global", "verified", "{}"),
            gt(2, "nas is at 10.0.0.5", "global", "verified", "{}"),
        ];
        let pairs = detect_contradictions(&same);
        assert_eq!(pairs.len(), 1);
        assert_eq!((pairs[0].a_id, pairs[0].b_id), (1, 2));
    }

    #[test]
    fn detect_skips_non_verified() {
        let facts = vec![
            gt(1, "nas is at 192.168.1.20", "global", "verified", "{}"),
            gt(2, "nas is at 10.0.0.5", "global", "candidate", "{}"),
        ];
        assert!(detect_contradictions(&facts).is_empty(), "candidate not compared");
    }

    #[test]
    fn loser_is_lower_source_count_then_older() {
        let a = gt(1, "x", "global", "verified", r#"{"omi":1}"#); // 1 source
        let b = gt(2, "x", "global", "verified", r#"{"omi":1,"import:hermes":1}"#); // 2 sources
        assert_eq!(loser_id(&a, &b), 1, "fewer sources loses");
        let c = gt(5, "x", "global", "verified", "{}");
        let d = gt(9, "x", "global", "verified", "{}");
        assert_eq!(loser_id(&c, &d), 5, "tie → older id loses");
    }

    #[test]
    fn end_to_end_negation_contradiction_auto_flags_loser_and_dismiss_restores() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        // Fact A: corroborated by TWO operator sources → verified, 2-source credibility.
        groundtruth::insert(&conn, "vpn is up", &Source::OperatorRuntime, "global", 1).unwrap();
        groundtruth::insert(&conn, "vpn is up", &Source::Onboarding, "global", 2).unwrap();
        assert!(list_contradictions(&conn, false).unwrap().is_empty());
        // Fact B: a single operator assertion of the OPPOSITE polarity → verified, 1 source.
        groundtruth::insert(&conn, "vpn is not up", &Source::OperatorRuntime, "global", 3).unwrap();
        let pending = list_contradictions(&conn, false).unwrap();
        assert_eq!(pending.len(), 1, "polarity contradiction recorded");
        // B (1 source) loses to A (2 sources) → B flagged Contradicted, drops from recall.
        let b_state: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE statement = 'vpn is not up'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(b_state, "contradicted", "the lower-credibility loser is auto-flagged");
        let surfaced: Vec<_> = groundtruth::surface_for_recall(&conn, 10, false)
            .unwrap()
            .into_iter()
            .map(|g| g.statement)
            .collect();
        assert!(!surfaced.contains(&"vpn is not up".to_string()), "contradicted fact hidden");
        // Dismissing the contradiction restores the loser to recall (complete undo).
        assert!(resolve(&conn, pending[0].ledger_id, 999).unwrap());
        let restored: String = conn
            .query_row(
                "SELECT fact_state FROM idx_groundtruth WHERE statement = 'vpn is not up'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(restored, "verified", "dismiss re-promotes the flagged fact");
    }

    #[test]
    fn value_divergence_is_recorded_but_never_auto_hides_a_fact() {
        // A legitimately multi-valued attribute (two different standup times) must
        // be surfaced to the operator but NEVER silently dropped from recall.
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        groundtruth::insert(&conn, "standup is at 9am", &Source::OperatorRuntime, "global", 1)
            .unwrap();
        groundtruth::insert(&conn, "standup is at 5pm", &Source::OperatorRuntime, "global", 2)
            .unwrap();
        // Recorded in the ledger for operator review...
        assert_eq!(list_contradictions(&conn, false).unwrap().len(), 1, "ledger records it");
        // ...but BOTH facts stay verified + surface (no destructive auto-hide).
        let surfaced: Vec<_> = groundtruth::surface_for_recall(&conn, 10, false)
            .unwrap()
            .into_iter()
            .map(|g| g.statement)
            .collect();
        assert!(surfaced.contains(&"standup is at 9am".to_string()));
        assert!(
            surfaced.contains(&"standup is at 5pm".to_string()),
            "a value divergence does NOT hide a multi-valued fact"
        );
    }

    #[test]
    fn resolve_dismisses_a_ledger_row() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_contradictions (fact_a_id, fact_b_id, confidence, detected_at) \
             VALUES (1, 2, 0.9, 100)",
            [],
        )
        .unwrap();
        let id: i64 = conn
            .query_row("SELECT id FROM idx_contradictions", [], |r| r.get(0))
            .unwrap();
        assert!(resolve(&conn, id, 200).unwrap());
        assert!(list_contradictions(&conn, false).unwrap().is_empty(), "dismissed hidden");
        assert_eq!(list_contradictions(&conn, true).unwrap().len(), 1, "still in full list");
    }

    #[test]
    fn forget_for_ids_clears_both_legs() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_contradictions (fact_a_id, fact_b_id, confidence, detected_at) \
             VALUES (1, 2, 0.9, 100)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_contradictions (fact_a_id, fact_b_id, confidence, detected_at) \
             VALUES (3, 4, 0.9, 100)",
            [],
        )
        .unwrap();
        assert_eq!(forget_for_ids(&conn, &[2]).unwrap(), 1, "the (1,2) pair is deleted");
        assert_eq!(forget_for_ids(&conn, &[99]).unwrap(), 0, "unknown id no-op");
        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM idx_contradictions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
    }
}
