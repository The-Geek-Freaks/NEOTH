//! GOLD-ADAPT-MEM-02 — contradiction detection + ledger over ground-truth facts.
//!
//! Two operator facts can disagree ("the nas is at X" vs "the nas is at Y";
//! "the vpn is up" vs "the vpn is not up"). This module detects such pairs and
//! records them in `idx_contradictions`, then flags the LOWER-credibility fact
//! (fewer corroborating sources, per MEM-01's `source_weight`) as
//! [`FactState::Contradicted`] so it drops out of recall (`surface_for_recall`
//! already gates on `verified`).
//!
//! ## Subject similarity: deterministic Jaccard, with an optional semantic lift
//! The always-available core is **token-Jaccard** over normalised statement
//! tokens, split into a SUBJECT part (before the first copula) and a VALUE part
//! (after it). Two facts contradict when they share a subject (subject-Jaccard ≥
//! [`SUBJECT_SIM_THRESHOLD`]) AND either their polarity differs (one carries a
//! negation marker the other lacks — reusing
//! `council::factual_check::DEFAULT_NEGATION_MARKERS`, bilingual EN/DE) OR their
//! value tokens diverge (value-Jaccard < [`VALUE_JACCARD_THRESHOLD`], so a
//! superset like "nas at X" vs "nas at X primary" is NOT flagged).
//!
//! The **on-demand scan** ([`scan_contradictions`]) optionally takes an
//! [`crate::providers::embed::EmbedProvider`] and replaces the subject-Jaccard
//! gate with embedding COSINE (catches "nas" ≈ "storage server"), falling back to
//! Jaccard on any embed failure — mirroring `council::dissent`. The synchronous
//! insert-time path ([`detect_contradictions_for`], inside `groundtruth::insert`)
//! stays Jaccard-only: it runs in a sync DB callback with no async runtime or
//! provider in scope. Values are token-normalised ("5pm" ≡ "17:00") so equivalent
//! values don't false-diverge.
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
use crate::providers::embed::{EmbedProvider, EmbedRequest, cosine};

/// Minimum subject-token Jaccard for two facts to be considered "about the same
/// thing" — below this they're different subjects (e.g. nas vs router).
pub const SUBJECT_SIM_THRESHOLD: f32 = 0.5;

/// Minimum value-token Jaccard ABOVE which two values count as "the same" (so NOT
/// a divergence). Replaces the old exact set-inequality test, which false-flagged
/// a superset ("nas at X" vs "nas at X primary", overlap 0.5) as a contradiction.
pub const VALUE_JACCARD_THRESHOLD: f32 = 0.5;

/// Minimum subject-embedding COSINE for the semantic on-demand scan to treat two
/// facts as the same subject. Set higher than the Jaccard threshold because
/// cosine on L2-normalised paraphrase embeddings clusters high (0.8–0.95); 0.75
/// is conservative enough to avoid cross-topic false positives while still
/// catching "nas" ≈ "storage server".
pub const SUBJECT_SIM_COSINE_THRESHOLD: f32 = 0.75;

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

/// Canonicalise a single lowercased token so equivalent VALUES don't false-
/// diverge: a 12-hour clock time → 24h ("5pm" → "17:00", "9am" → "09:00",
/// "12am" → "00:00", "12pm" → "12:00") and "h:mm"/"hh:mm" → zero-padded "HH:MM".
/// Everything else (IPs, hostnames, words) is returned unchanged — distinct IPs
/// already compare correctly as opaque tokens.
fn normalize_token(t: &str) -> String {
    // 12-hour clock: <digits>am / <digits>pm
    if let Some(hour) = t.strip_suffix("am").or_else(|| t.strip_suffix("pm")) {
        if !hour.is_empty() && hour.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(h) = hour.parse::<u32>() {
                if h <= 12 {
                    let h24 = match (h, t.ends_with("pm")) {
                        (12, false) => 0,    // 12am = midnight
                        (12, true) => 12,    // 12pm = noon
                        (h, false) => h,     // 1am..11am
                        (h, true) => h + 12, // 1pm..11pm
                    };
                    return format!("{h24:02}:00");
                }
            }
        }
    }
    // h:mm / hh:mm → zero-padded HH:MM
    if let Some((hh, mm)) = t.split_once(':') {
        if !hh.is_empty()
            && hh.bytes().all(|b| b.is_ascii_digit())
            && mm.len() == 2
            && mm.bytes().all(|b| b.is_ascii_digit())
        {
            if let Ok(h) = hh.parse::<u32>() {
                if h < 24 {
                    return format!("{h:02}:{mm}");
                }
            }
        }
    }
    t.to_string()
}

/// Truncate a multi-clause fact to its FIRST clause when a conjunction joins two
/// separate copula-bearing clauses ("nas is at X and router is at Y" → "nas is at
/// X"), so the second clause's tokens don't bleed into this fact's subject/value.
/// Conservative: only truncates when a COPULA actually appears AFTER the
/// conjunction (so "server is up and responsive" — no second copula — is left
/// whole). The slice is guarded so a rare Unicode case-shift can never panic.
fn first_clause(s: &str) -> &str {
    let lower = s.to_lowercase();
    for conj in [" and ", " und ", " oder "] {
        if let Some(pos) = lower.find(conj) {
            if !s.is_char_boundary(pos) {
                continue;
            }
            let tail_has_copula = lower[pos + conj.len()..]
                .split_whitespace()
                .any(|w| COPULAS.contains(&w.trim_matches(|c: char| c.is_ascii_punctuation())));
            if tail_has_copula {
                return &s[..pos];
            }
        }
    }
    s
}

/// Raw lowercased tokens (punctuation-trimmed + value-normalised) in order — used
/// for subject/value splitting where ORDER matters (the copula position).
fn ordered_tokens(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split_whitespace()
        .map(|t| normalize_token(t.trim_matches(|c: char| c.is_ascii_punctuation())))
        .filter(|t| !t.is_empty())
        .collect()
}

/// Content tokens BEFORE the first copula (the subject). If no copula is found,
/// the first 3 content tokens. Stopwords (other than the copula delimiter) are
/// dropped so "the primary nas" and "primary nas" match.
fn subject_tokens(s: &str) -> HashSet<String> {
    let toks = ordered_tokens(first_clause(s));
    match toks.iter().position(|t| COPULAS.contains(&t.as_str())) {
        // Everything before the copula (stopwords dropped).
        Some(i) => toks[..i]
            .iter()
            .filter(|t| !STOPWORDS.contains(&t.as_str()))
            .cloned()
            .collect(),
        // No copula: the first 3 CONTENT tokens. Filter stopwords FIRST so they
        // don't consume the budget ("the primary nas server" → {primary,nas,server}).
        None => toks
            .iter()
            .filter(|t| !STOPWORDS.contains(&t.as_str()))
            .take(3)
            .cloned()
            .collect(),
    }
}

/// Content tokens AFTER the first copula (the value). Empty if no copula.
fn value_tokens(s: &str) -> HashSet<String> {
    let toks = ordered_tokens(first_clause(s));
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
    // Values DIVERGE when both are present AND their overlap is below the
    // threshold — a Jaccard test, not exact inequality, so a superset ("nas at X"
    // vs "nas at X primary", overlap 0.5) is NOT flagged as a contradiction.
    let vj = jaccard(&va, &vb);
    let value_diverges = !va.is_empty() && !vb.is_empty() && vj < VALUE_JACCARD_THRESHOLD;

    if !negation && !value_diverges {
        return None;
    }
    // A polarity flip is a strong fixed signal; a value divergence scales with how
    // disjoint the values are (fully disjoint vj=0 → 0.3, near-threshold → ~0.15).
    let signal = if negation { 0.4 } else { (1.0 - vj) * 0.3 };
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

/// Cosine of two facts' SUBJECT phrases via the embedding provider. The subject
/// phrase is the sorted content tokens joined by spaces (deterministic; order
/// barely matters for these short phrases). Returns `Err` so the caller owns the
/// Jaccard fallback — mirrors `council::dissent::score_dissent_via_embedding`.
async fn subject_sim_via_embedding(
    stmt_a: &str,
    stmt_b: &str,
    provider: &dyn EmbedProvider,
) -> Result<f32> {
    fn phrase(s: &str) -> String {
        let mut toks: Vec<String> = subject_tokens(s).into_iter().collect();
        toks.sort();
        toks.join(" ")
    }
    let (pa, pb) = (phrase(stmt_a), phrase(stmt_b));
    if pa.is_empty() || pb.is_empty() {
        return Ok(0.0);
    }
    let ra = provider.embed(EmbedRequest::new(pa)).await?;
    let rb = provider.embed(EmbedRequest::new(pb)).await?;
    Ok(cosine(&ra.vector, &rb.vector))
}

/// Semantic variant of [`pair_confidence`]: the subject gate uses embedding COSINE
/// (catches "nas" ≈ "storage server") with a Jaccard FALLBACK on any embed
/// failure. The negation + value-divergence logic is identical to the sync path,
/// so on embed failure this returns exactly what [`pair_confidence`] would.
pub async fn pair_confidence_semantic(
    stmt_a: &str,
    stmt_b: &str,
    provider: &dyn EmbedProvider,
) -> Option<PairSignal> {
    // Subject weight: cosine when the embed succeeds + clears the cosine gate;
    // Jaccard (the deterministic core) on embed failure.
    let subj = match subject_sim_via_embedding(stmt_a, stmt_b, provider).await {
        Ok(cos) if cos >= SUBJECT_SIM_COSINE_THRESHOLD => cos,
        Ok(_) => return None, // cosine below the gate → different subjects
        Err(_) => {
            let j = jaccard(&subject_tokens(stmt_a), &subject_tokens(stmt_b));
            if j < SUBJECT_SIM_THRESHOLD {
                return None;
            }
            j
        }
    };
    let negation = has_negation(stmt_a) != has_negation(stmt_b);
    let va = value_tokens(stmt_a);
    let vb = value_tokens(stmt_b);
    let vj = jaccard(&va, &vb);
    let value_diverges = !va.is_empty() && !vb.is_empty() && vj < VALUE_JACCARD_THRESHOLD;
    if !negation && !value_diverges {
        return None;
    }
    let signal = if negation { 0.4 } else { (1.0 - vj) * 0.3 };
    let confidence = (subj * 0.6 + signal).min(1.0);
    if confidence >= EMIT_THRESHOLD {
        Some(PairSignal { confidence, negation })
    } else {
        None
    }
}

/// TRIGGER 2 — full re-scan over every active Verified fact (grouped by scope).
/// Idempotent (existing pairs are `INSERT OR IGNORE`d). Returns the count of NEW
/// ledger rows created.
///
/// When `embed` is `Some`, subject similarity uses embedding cosine (semantic;
/// catches paraphrased subjects) with a per-pair Jaccard fallback; `None` runs the
/// deterministic Jaccard path unchanged.
pub async fn scan_contradictions(
    conn: &Connection,
    now_ns: i64,
    embed: Option<&dyn EmbedProvider>,
) -> Result<usize> {
    let all = groundtruth::surface_for_recall(conn, 100_000, true)?;
    let verified: Vec<GroundTruth> =
        all.into_iter().filter(|g| is_comparable(&g.fact_state)).collect();
    tracing::info!(
        facts = verified.len(),
        semantic = embed.is_some(),
        "MEM-02: contradiction scan starting",
    );
    let mut new_rows = 0usize;
    for i in 0..verified.len() {
        for j in (i + 1)..verified.len() {
            let a = &verified[i];
            let b = &verified[j];
            if a.scope != b.scope {
                continue;
            }
            let sig = match embed {
                Some(p) => pair_confidence_semantic(&a.statement, &b.statement, p).await,
                None => pair_confidence(&a.statement, &b.statement),
            };
            if let Some(sig) = sig {
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

    // ── Hardening: stopword-first fallback, value-Jaccard, multi-clause, time ──

    #[test]
    fn subject_tokens_copula_free_drops_stopwords_before_truncating() {
        // A leading stopword must NOT steal a slot from a content token: the
        // budget is the first 3 CONTENT tokens, so 'nas' survives despite 'the'.
        let s = subject_tokens("the big primary nas");
        assert!(s.contains("nas"), "content token survives the stopword budget");
        assert!(!s.contains("the"));
    }

    #[test]
    fn superset_value_is_not_a_contradiction() {
        // "nas at X" vs "nas at X primary" — the second is a superset, overlap
        // 0.5, which is NOT below VALUE_JACCARD_THRESHOLD → no contradiction.
        assert!(
            pair_confidence("nas is at 192.168.1.20", "nas is at 192.168.1.20 primary").is_none(),
            "a value superset must not be flagged",
        );
    }

    #[test]
    fn disjoint_value_still_fires() {
        // Genuinely different values (overlap 0) still diverge.
        let sig = pair_confidence("nas is at 192.168.1.20", "nas is at 192.168.1.21");
        assert!(sig.is_some());
        assert!(!sig.unwrap().negation);
    }

    #[test]
    fn first_clause_isolates_subject_and_value_in_multi_clause_facts() {
        // The router clause must not bleed into the nas fact's value set.
        let v = value_tokens("nas is at 192.168.1.20 and router is at 10.0.0.1");
        assert!(v.contains("192.168.1.20"));
        assert!(!v.contains("router"), "second clause must be truncated");
        assert!(!v.contains("10.0.0.1"));
        // Whole when the conjunction has no second copula ("up and responsive").
        assert!(value_tokens("vpn is up and responsive").contains("up"));
        assert!(value_tokens("vpn is up and responsive").contains("responsive"));
    }

    #[test]
    fn multi_clause_pair_detects_only_the_diverging_clause() {
        let facts = vec![
            gt(1, "nas is at 192.168.1.20 and router is at 10.0.0.1", "global", "verified", "{}"),
            gt(2, "nas is at 10.0.0.5 and router is at 10.0.0.1", "global", "verified", "{}"),
        ];
        // Only the nas value diverges (router is identical in both) → exactly one pair.
        assert_eq!(detect_contradictions(&facts).len(), 1);
    }

    #[test]
    fn time_normalisation_equivalence_is_not_a_contradiction() {
        // "5pm" ≡ "17:00" — equivalent values must NOT false-diverge.
        assert!(pair_confidence("standup is at 5pm", "standup is at 17:00").is_none());
        assert!(pair_confidence("standup is at 9:00", "standup is at 09:00").is_none());
    }

    #[test]
    fn time_normalisation_divergence_still_fires() {
        assert!(pair_confidence("standup is at 5pm", "standup is at 9am").is_some());
    }

    #[test]
    fn normalize_token_clock_edges() {
        assert_eq!(normalize_token("12am"), "00:00", "midnight");
        assert_eq!(normalize_token("12pm"), "12:00", "noon");
        assert_eq!(normalize_token("5pm"), "17:00");
        assert_eq!(normalize_token("9am"), "09:00");
        assert_eq!(normalize_token("17:00"), "17:00");
        // Non-time tokens are returned verbatim (no false normalisation).
        assert_eq!(normalize_token("192.168.1.20"), "192.168.1.20");
        assert_eq!(normalize_token("team"), "team");
        assert_eq!(normalize_token("spam"), "spam");
    }

    // ── Semantic (embedding-cosine) on-demand scan ───────────────────────────

    use crate::providers::embed::EmbedResponse;

    /// Mock embedder that maps each subject phrase to one of three orthogonal
    /// slots by keyword, so synonyms ("nas" / "storage") share a slot and score
    /// cosine 1.0. Mirrors the SlotMock pattern in `council::dissent` tests.
    struct SlotMockEmbed;

    #[async_trait::async_trait]
    impl EmbedProvider for SlotMockEmbed {
        fn name(&self) -> &'static str {
            "slot-mock"
        }
        fn default_dim(&self) -> usize {
            3
        }
        async fn embed(&self, req: EmbedRequest) -> anyhow::Result<EmbedResponse> {
            let t = req.text.to_lowercase();
            let slot = if t.contains("nas") || t.contains("storage") {
                0
            } else if t.contains("router") {
                1
            } else {
                2
            };
            let mut v = vec![0.0f32; 3];
            v[slot] = 1.0;
            Ok(EmbedResponse {
                vector: v,
                model: "slot-mock".into(),
                latency: std::time::Duration::from_micros(1),
            })
        }
    }

    #[tokio::test]
    async fn scan_with_embed_catches_synonym_subjects_jaccard_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        // Synonym subjects ("nas" vs "storage server") with diverging values. The
        // subjects share ZERO tokens, so the insert-time Jaccard trigger records
        // nothing — the ledger is empty after both inserts.
        groundtruth::insert(&conn, "nas is at 192.168.1.20", &Source::OperatorRuntime, "global", 1)
            .unwrap();
        groundtruth::insert(
            &conn,
            "storage server is at 10.0.0.5",
            &Source::OperatorRuntime,
            "global",
            2,
        )
        .unwrap();
        assert!(list_contradictions(&conn, true).unwrap().is_empty(), "Jaccard insert sees nothing");
        // Deterministic re-scan (None) also finds nothing — subjects don't overlap.
        assert_eq!(scan_contradictions(&conn, 10, None).await.unwrap(), 0);
        // Semantic scan clusters nas ≈ storage → records the contradiction.
        let mock = SlotMockEmbed;
        assert_eq!(
            scan_contradictions(&conn, 20, Some(&mock)).await.unwrap(),
            1,
            "embedding cosine catches the synonym subject"
        );
    }

    #[tokio::test]
    async fn scan_none_embed_runs_the_deterministic_path() {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        groundtruth::insert(&conn, "nas is at 192.168.1.20", &Source::OperatorRuntime, "global", 1)
            .unwrap();
        groundtruth::insert(&conn, "nas is at 10.0.0.5", &Source::OperatorRuntime, "global", 2)
            .unwrap();
        // Insert-time already recorded the divergence; clear it to exercise the
        // scan(None) detection path directly.
        conn.execute("DELETE FROM idx_contradictions", []).unwrap();
        assert_eq!(
            scan_contradictions(&conn, 99, None).await.unwrap(),
            1,
            "deterministic None-embed scan re-detects the value divergence"
        );
    }

    #[tokio::test]
    async fn pair_confidence_semantic_falls_back_to_jaccard_on_embed_error() {
        // A failing embedder must make the semantic path return exactly what the
        // sync Jaccard path returns.
        struct FailingEmbed;
        #[async_trait::async_trait]
        impl EmbedProvider for FailingEmbed {
            fn name(&self) -> &'static str {
                "failing"
            }
            fn default_dim(&self) -> usize {
                3
            }
            async fn embed(&self, _req: EmbedRequest) -> anyhow::Result<EmbedResponse> {
                anyhow::bail!("embed model unavailable")
            }
        }
        let f = FailingEmbed;
        // Same-subject diverging value → both paths agree (Some, !negation).
        let sync = pair_confidence("nas is at 192.168.1.20", "nas is at 10.0.0.5");
        let semantic =
            pair_confidence_semantic("nas is at 192.168.1.20", "nas is at 10.0.0.5", &f).await;
        assert_eq!(sync.is_some(), semantic.is_some());
        assert_eq!(sync.unwrap().negation, semantic.unwrap().negation);
        // Different subject → both None.
        assert!(
            pair_confidence_semantic("nas is at 192.168.1.1", "router is at 192.168.1.1", &f)
                .await
                .is_none()
        );
    }
}
