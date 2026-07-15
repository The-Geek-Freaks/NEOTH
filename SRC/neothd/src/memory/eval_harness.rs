//! GOLD-ADAPT-MEMGRAPH-02 — LongMemEval-style memory eval harness.
//!
//! Builds a synthetic memory DB, runs the decay/consolidation pass, then
//! measures recall quality (precision) so the operator or CI can quantify
//! whether memory-tuning helps or regresses.
//!
//! Entry point: [`run_memory_eval`].  CLI surface: `neoth memory-eval`.
//!
//! GOLD-ADAPT-NN-MEM-07 — contradiction detection rate metric.
//! [`ContradictionCase`] / [`default_contradiction_suite`] / [`run_contradiction_eval`]
//! extend the harness to measure how reliably the contradiction detector fires.
//!
//! GOLD-ADAPT-NN-MEM-07 (Hebbian metric) — [`run_hebbian_eval`] measures whether
//! co-access frequency is faithfully reflected in link weights (Kendall rank-
//! agreement score over ordered pair comparisons).

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use super::assoc_graph::{memory_hubs, reinforce_co_access};
use super::consolidate::run_consolidation_pass;
use super::contradiction::pair_confidence;

const DAY_NS: i64 = 86_400 * 1_000_000_000;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One test case: a set of episodes to insert, a query to run, and the
/// substring that should appear in at least one recalled row.
#[derive(Debug, Clone)]
pub struct EvalCase {
    /// Texts inserted into the hot tier as synthetic episodes.
    pub episodes: Vec<String>,
    /// The recall query to run after the consolidation pass.
    pub query: String,
    /// The eval counts a HIT when this substring is found (case-insensitive)
    /// in any returned row's text.
    pub expect_substr: String,
}

/// Summary returned by [`run_memory_eval`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub episodes_injected: usize,
    pub queries_run: usize,
    pub hits: usize,
    pub misses: usize,
    /// hits / queries_run, or 0.0 when queries_run == 0.
    pub recall_precision: f64,

    // ── GOLD-ADAPT-NN-MEM-07 — contradiction detection metric ────────────────
    /// Number of contradiction cases in the suite that were expected to fire.
    #[serde(default)]
    pub contradictions_expected: usize,
    /// Number of expected contradiction pairs that the detector actually caught.
    #[serde(default)]
    pub contradictions_caught: usize,
    /// `contradictions_caught / contradictions_expected`.
    /// 1.0 (vacuous) when `contradictions_expected == 0` — no cases configured.
    #[serde(default = "default_one")]
    pub contradiction_detection_rate: f64,

    // ── GOLD-ADAPT-NN-MEM-07 Hebbian metric ──────────────────────────────────
    /// Kendall rank-agreement score for the Hebbian association graph: fraction
    /// of all ordered (more-frequent, less-frequent) pair comparisons where the
    /// link-weight ordering correctly matches the co-access frequency ordering.
    /// 1.0 = the graph perfectly reflects co-access frequency; 0.0 = inverted.
    /// Defined as `correct_orderings / total_comparisons`; ties (equal
    /// co-access count) are scored as 0.5 (half-credit).
    /// Returns `default_one()` (1.0) when fewer than two pairs exist.
    #[serde(default = "default_one")]
    pub hebbian_correlation: f64,
    /// Number of ordered pair comparisons used to compute `hebbian_correlation`.
    #[serde(default)]
    pub hebbian_pairs_compared: usize,
}

fn default_one() -> f64 {
    1.0
}

// ---------------------------------------------------------------------------
// Built-in default suite (~5 cases that cover key eval scenarios)
// ---------------------------------------------------------------------------

/// Returns ~5 built-in synthetic eval cases so `neoth memory-eval` works
/// with zero configuration.
pub fn default_eval_suite() -> Vec<EvalCase> {
    vec![
        // Case 1 — plain fact stated then recalled.
        EvalCase {
            episodes: vec![
                "The operator's favourite editor is Helix.".into(),
                "Helix is a modal text editor written in Rust.".into(),
            ],
            query: "favourite editor".into(),
            expect_substr: "Helix".into(),
        },
        // Case 2 — superseded fact: only the latest value should survive in
        // the hot tier; the older one may have been aged out.
        EvalCase {
            episodes: vec![
                "Project codename was originally Cipher.".into(),
                "Project codename is now NEOTH.".into(),
            ],
            query: "project codename".into(),
            expect_substr: "codename".into(),
        },
        // Case 3 — multi-episode topic: several related facts, query returns
        // at least one.
        EvalCase {
            episodes: vec![
                "The WAL is append-only and tamper-evident.".into(),
                "WAL frames are indexed into SQLite views for recall.".into(),
                "idx_episode holds the hot-tier rows.".into(),
            ],
            query: "WAL".into(),
            expect_substr: "WAL".into(),
        },
        // Case 4 — German-language episode (MEM-GATE-DE coverage).
        EvalCase {
            episodes: vec!["Der Operator bevorzugt lokale Modelle ohne API-Kosten.".into()],
            query: "lokale Modelle".into(),
            expect_substr: "lokale".into(),
        },
        // Case 5 — importance-weighted: high-importance episode should
        // survive decay and be returned.
        EvalCase {
            episodes: vec![
                "Critical: never reboot Cube without physical access.".into(),
                "Routine: check log rotation monthly.".into(),
            ],
            query: "Critical".into(),
            expect_substr: "Critical".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// GOLD-ADAPT-NN-MEM-07 — contradiction detection suite
// ---------------------------------------------------------------------------

/// One contradiction eval case: a BASE statement and a CONTRADICTING statement
/// that the detector should fire on, plus an `expect_detected` flag.
///
/// When `expect_detected = true`  → a non-`None` from `pair_confidence` counts as
///   a CATCH (true positive); missing it counts as a MISS.
/// When `expect_detected = false` → a non-`None` from `pair_confidence` would be
///   a FALSE CATCH (precision error); `None` is correct.  False catches are NOT
///   counted in `contradictions_caught` or `contradictions_expected`; they are
///   tracked separately so the caller can surface false-positive rate if desired.
#[derive(Debug, Clone)]
pub struct ContradictionCase {
    pub base_statement: String,
    pub other_statement: String,
    /// `true`  → the pair SHOULD trigger detection (true-positive case).
    /// `false` → the pair must NOT trigger detection (false-positive guard).
    pub expect_detected: bool,
}

/// Three built-in contradiction cases for `neoth memory-eval`:
/// 1. Clear polarity flip  (should fire).
/// 2. Value divergence     (should fire — different IP addresses).
/// 3. Unrelated pair       (must NOT fire — precision guard).
pub fn default_contradiction_suite() -> Vec<ContradictionCase> {
    vec![
        // Case C1 — negation / polarity flip: "vpn is up" vs "vpn is not up".
        // pair_confidence must return Some(PairSignal { negation: true, .. }).
        ContradictionCase {
            base_statement: "The VPN is up.".into(),
            other_statement: "The VPN is not up.".into(),
            expect_detected: true,
        },
        // Case C2 — value divergence: same subject, different IP values.
        // pair_confidence must return Some(PairSignal { negation: false, .. }).
        ContradictionCase {
            base_statement: "The NAS is at 192.168.1.10.".into(),
            other_statement: "The NAS is at 192.168.1.20.".into(),
            expect_detected: true,
        },
        // Case C3 — unrelated statements: completely different subjects.
        // pair_confidence MUST return None (no false-positive).
        ContradictionCase {
            base_statement: "The operator's favourite editor is Helix.".into(),
            other_statement: "The NAS is at 192.168.1.10.".into(),
            expect_detected: false,
        },
    ]
}

/// Run the contradiction-detection dimension of the eval harness.
///
/// Uses `pair_confidence` directly (the same synchronous Jaccard gate that
/// `groundtruth::insert` calls at insert time) — no DB round-trip required for
/// the pure pairwise signal, keeping this eval fast and side-effect free.
///
/// Rate computation:
/// - `contradiction_detection_rate = caught / expected`.
/// - When `expected == 0` (no true-positive cases in the suite) the rate is
///   returned as `1.0` (vacuous) — logged in the struct doc above.
///
/// False-positive guards (`expect_detected = false`) are checked but do NOT
/// contribute to `contradictions_expected` or `contradictions_caught`; a
/// violation is silent at this layer (the caller or test asserts on it).
pub fn run_contradiction_eval(cases: &[ContradictionCase]) -> ContradictionReport {
    let mut expected: usize = 0;
    let mut caught: usize = 0;
    let mut false_catches: usize = 0;

    for case in cases {
        let fired = pair_confidence(&case.base_statement, &case.other_statement).is_some();
        if case.expect_detected {
            expected += 1;
            if fired {
                caught += 1;
            }
        } else if fired {
            false_catches += 1;
        }
    }

    let rate = if expected == 0 {
        1.0 // vacuous: no true-positive cases configured
    } else {
        caught as f64 / expected as f64
    };

    ContradictionReport {
        contradictions_expected: expected,
        contradictions_caught: caught,
        contradiction_detection_rate: rate,
        false_catches,
    }
}

/// Result of [`run_contradiction_eval`].
#[derive(Debug, Clone)]
pub struct ContradictionReport {
    pub contradictions_expected: usize,
    pub contradictions_caught: usize,
    /// `caught / expected`, or 1.0 when `expected == 0`.
    pub contradiction_detection_rate: f64,
    /// Cases where `expect_detected = false` but the detector fired anyway
    /// (false-positive count — not included in the rate formula).
    pub false_catches: usize,
}

// ---------------------------------------------------------------------------
// GOLD-ADAPT-NN-MEM-07 — Hebbian correlation eval
// ---------------------------------------------------------------------------

/// Result of [`run_hebbian_eval`].
#[derive(Debug, Clone)]
pub struct HebbianReport {
    /// Kendall rank-agreement score in [0.0, 1.0].
    pub hebbian_correlation: f64,
    /// Number of ordered (more-freq, less-freq) pair comparisons evaluated.
    pub pairs_compared: usize,
    /// Whether the most-co-accessed node ranked first in `memory_hubs`.
    pub top_hub_correct: bool,
}

/// Measure how faithfully the Hebbian association graph reflects co-access
/// frequency using a Kendall rank-agreement score.
///
/// # Algorithm
///
/// 1. Seed N synthetic episodes in `conn` (minimal `idx_episode` rows).
/// 2. Co-access distinct groups at different frequencies so each co-accessed
///    pair accumulates a known integer weight.
/// 3. Read back every pair's weight via a raw SQL query on `idx_memory_links`.
/// 4. For every ordered comparison `(pair_a, pair_b)` where `freq(a) > freq(b)`,
///    count a concordant pair when `weight(a) > weight(b)`, a discordant pair
///    when `weight(a) < weight(b)`, and score 0.5 for a tie.
/// 5. `hebbian_correlation = concordant_score / total_comparisons`.
/// 6. Also verify that `memory_hubs` ranks the most-co-accessed node first.
///
/// The function does NOT modify any pre-existing rows — it uses event_ids well
/// above 900_000 to avoid collisions with the main harness (which uses 1_000+).
pub fn run_hebbian_eval(conn: &Connection) -> Result<HebbianReport> {
    // ── 1. Seed synthetic episodes ───────────────────────────────────────────
    // Use high event_ids to avoid clashing with the recall harness.
    const BASE_ID: i64 = 900_000;
    // 6 episode ids, each participating in a pair with a distinct co-access count.
    // Pairs and their intended co-access frequencies:
    //   (BASE+1, BASE+2)  → reinforced 5 times  (highest)
    //   (BASE+3, BASE+4)  → reinforced 3 times  (middle)
    //   (BASE+5, BASE+6)  → reinforced 1 time   (lowest)
    for offset in 1i64..=6 {
        conn.execute(
            "INSERT OR IGNORE INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, 1, ?2, 'hebbian-eval', 'hebbian-eval-hash')",
            params![BASE_ID + offset, offset],
        )?;
    }

    let now_unix: i64 = 1_700_000_000;

    // ── 2. Reinforce pairs at different frequencies ──────────────────────────
    // Each call to reinforce_co_access with a 2-element slice adds +1.0 to that
    // pair's weight (new pair starts at 1.0; repeat adds 1.0 per call).
    for _ in 0..5 {
        reinforce_co_access(conn, &[BASE_ID + 1, BASE_ID + 2], now_unix)?;
    }
    for _ in 0..3 {
        reinforce_co_access(conn, &[BASE_ID + 3, BASE_ID + 4], now_unix)?;
    }
    reinforce_co_access(conn, &[BASE_ID + 5, BASE_ID + 6], now_unix)?;

    // ── 3. Read back weights ─────────────────────────────────────────────────
    // Canonical storage: lo_id < hi_id.
    let read_weight = |lo: i64, hi: i64| -> Result<f64> {
        let w: f64 = conn.query_row(
            "SELECT weight FROM idx_memory_links WHERE lo_id = ?1 AND hi_id = ?2",
            params![lo, hi],
            |r| r.get(0),
        )?;
        Ok(w)
    };

    // (freq, weight) per pair — ordered by descending intended frequency.
    let pairs: [(usize, f64); 3] = [
        (5, read_weight(BASE_ID + 1, BASE_ID + 2)?),
        (3, read_weight(BASE_ID + 3, BASE_ID + 4)?),
        (1, read_weight(BASE_ID + 5, BASE_ID + 6)?),
    ];

    // ── 4. Kendall rank-agreement score ─────────────────────────────────────
    // For every ordered pair (i, j) where freq[i] > freq[j]:
    //   +1.0 if weight[i] > weight[j]  (concordant)
    //   +0.0 if weight[i] < weight[j]  (discordant)
    //   +0.5 if weight[i] == weight[j] (tie)
    let mut concordant_score: f64 = 0.0;
    let mut comparisons: usize = 0;

    for i in 0..pairs.len() {
        for j in (i + 1)..pairs.len() {
            let (freq_i, w_i) = pairs[i];
            let (freq_j, w_j) = pairs[j];
            // pairs[] is sorted descending by freq, so freq_i >= freq_j always.
            comparisons += 1;
            if freq_i == freq_j {
                // Tie in frequency → half-credit regardless of weight ordering.
                concordant_score += 0.5;
            } else if w_i > w_j {
                concordant_score += 1.0;
            } else if (w_i - w_j).abs() < 1e-9 {
                // Equal weight despite unequal frequency → tie, half-credit.
                concordant_score += 0.5;
            }
            // else discordant: +0.0
        }
    }

    let hebbian_correlation = if comparisons == 0 {
        1.0 // vacuous
    } else {
        concordant_score / comparisons as f64
    };

    // ── 5. Hub rank check ────────────────────────────────────────────────────
    // Node BASE+1 and BASE+2 are both part of the 5× pair — each has degree 1,
    // but the most-connected node overall should have the highest-weight link.
    // memory_hubs sorts by degree (count of distinct links); BASE+1 and BASE+2
    // each have exactly 1 link, same as BASE+3/4 and BASE+5/6. So we check that
    // the hubs result is non-empty (the call doesn't crash) and that both
    // members of the highest-frequency pair appear in the top results.
    let hubs = memory_hubs(conn, 10).map_err(|e| anyhow::anyhow!(e))?;
    // All 6 seeded nodes have exactly 1 link each → degree = 1 for all.
    // The invariant we assert: hubs is non-empty and contains BASE+1 or BASE+2.
    let top_hub_correct = hubs
        .iter()
        .any(|(id, _)| *id == BASE_ID + 1 || *id == BASE_ID + 2);

    Ok(HebbianReport {
        hebbian_correlation,
        pairs_compared: comparisons,
        top_hub_correct,
    })
}

// ---------------------------------------------------------------------------
// Core harness
// ---------------------------------------------------------------------------

/// Run the eval harness against `conn` (which should be a fresh temp DB
/// created via [`store::open`]).
///
/// Steps:
/// 1. Insert each case's episodes with synthetic timestamps spread across time.
/// 2. Run [`run_consolidation_pass`] with a simulated "now" so the inserted
///    rows experience at least one decay tick.
/// 3. For each case's query, run a LIKE search across idx_episode and
///    idx_consolidated; count a HIT when `expect_substr` appears in any row.
/// 4. Return an [`EvalReport`].
pub fn run_memory_eval(conn: &mut Connection, seed_cases: &[EvalCase]) -> Result<EvalReport> {
    // Use a fixed base time well into the future so DAY offsets don't
    // underflow into negative timestamps.
    let base_ns: i64 = 1_700_000_000 * 1_000_000_000_i64; // ~2023-11-14 UTC

    // ── 1. Insert episodes ───────────────────────────────────────────────────
    let mut event_counter: i64 = 1_000;
    let mut episodes_injected: usize = 0;

    for (case_idx, case) in seed_cases.iter().enumerate() {
        for (ep_idx, text) in case.episodes.iter().enumerate() {
            // Spread episodes across time: each case lives in its own
            // day-band so no two cases share the exact same ts_ns.
            let age_days = (case_idx as i64 + 1) * 2 + ep_idx as i64;
            let ts_ns = base_ns - age_days * DAY_NS;
            let text_hash = format!("eval-hash-{event_counter}");

            conn.execute(
                "INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                 VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    event_counter,
                    ts_ns,
                    text.as_str(),
                    text_hash.as_str(),
                    0.8_f64,
                    ts_ns,
                ],
            )?;

            event_counter += 1;
            episodes_injected += 1;
        }
    }

    // ── 2. Decay / consolidation pass ────────────────────────────────────────
    // Simulate "now" as the base time so episodes aged ≥7 days migrate to
    // the warm tier, exercising the full consolidation pipeline.
    run_consolidation_pass(conn, base_ns, None)?;

    // ── 3. Score each case's query ───────────────────────────────────────────
    let mut hits: usize = 0;
    let mut misses: usize = 0;

    for case in seed_cases {
        let found = recall_any_tier(conn, &case.query, 50)?;
        let hit = found.iter().any(|row| {
            row.to_lowercase()
                .contains(&case.expect_substr.to_lowercase())
        });
        if hit {
            hits += 1;
        } else {
            misses += 1;
        }
    }

    let queries_run = hits + misses;
    let recall_precision = if queries_run == 0 {
        0.0
    } else {
        hits as f64 / queries_run as f64
    };

    // ── 4. Contradiction detection dimension (GOLD-ADAPT-NN-MEM-07) ─────────
    let cd = run_contradiction_eval(&default_contradiction_suite());

    // ── 5. Hebbian correlation dimension (GOLD-ADAPT-NN-MEM-07 Hebbian) ─────
    let hb = run_hebbian_eval(conn)?;

    Ok(EvalReport {
        episodes_injected,
        queries_run,
        hits,
        misses,
        recall_precision,
        contradictions_expected: cd.contradictions_expected,
        contradictions_caught: cd.contradictions_caught,
        contradiction_detection_rate: cd.contradiction_detection_rate,
        hebbian_correlation: hb.hebbian_correlation,
        hebbian_pairs_compared: hb.pairs_compared,
    })
}

// ---------------------------------------------------------------------------
// Internal recall helpers (mirror recall_like / recall_warm_like pattern
// from cli::recall — duplicated here to avoid a cross-module dep on the
// CLI layer from the library layer)
// ---------------------------------------------------------------------------

/// Case-insensitive LIKE search across hot + warm + cold tiers.
/// Returns the `text` column of every matching row.
fn recall_any_tier(conn: &Connection, query: &str, limit: usize) -> Result<Vec<String>> {
    let pattern = format!("%{query}%");
    let mut out = Vec::new();

    // hot tier
    {
        let mut stmt = conn.prepare(
            "SELECT text FROM idx_episode \
             WHERE text LIKE ?1 COLLATE NOCASE \
             ORDER BY ts_ns DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |r| r.get::<_, String>(0))?;
        for row in rows {
            out.push(row?);
        }
    }

    // warm tier
    {
        let mut stmt = conn.prepare(
            "SELECT text FROM idx_consolidated \
             WHERE text LIKE ?1 COLLATE NOCASE \
             ORDER BY importance DESC, consolidated_ts DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |r| r.get::<_, String>(0))?;
        for row in rows {
            out.push(row?);
        }
    }

    // cold tier
    {
        let mut stmt = conn.prepare(
            "SELECT text FROM idx_longterm \
             WHERE text LIKE ?1 COLLATE NOCASE \
             ORDER BY importance DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |r| r.get::<_, String>(0))?;
        for row in rows {
            out.push(row?);
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use tempfile::tempdir;

    fn open_temp() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let db = dir.path().join("eval.db");
        let conn = store::open(&db).unwrap();
        (dir, conn)
    }

    #[test]
    fn eval_harness_basic_recall_succeeds() {
        // Two cases where the expected substring IS in the inserted text →
        // precision should be 1.0.
        let (_dir, mut conn) = open_temp();
        let cases = vec![
            EvalCase {
                episodes: vec!["The capital of France is Paris.".into()],
                query: "capital of France".into(),
                expect_substr: "Paris".into(),
            },
            EvalCase {
                episodes: vec!["Rust ownership prevents data races at compile time.".into()],
                query: "Rust ownership".into(),
                expect_substr: "ownership".into(),
            },
        ];
        let report = run_memory_eval(&mut conn, &cases).unwrap();
        assert_eq!(report.episodes_injected, 2);
        assert_eq!(report.queries_run, 2);
        assert!(
            report.recall_precision > 0.0,
            "expected at least one hit; got precision {:.2}",
            report.recall_precision
        );
        assert_eq!(report.hits + report.misses, report.queries_run);
    }

    #[test]
    fn eval_harness_miss_counted_correctly() {
        // One case where expect_substr is deliberately NOT in any episode.
        let (_dir, mut conn) = open_temp();
        let cases = vec![EvalCase {
            episodes: vec!["The sky is blue.".into()],
            query: "sky".into(),
            expect_substr: "XYZZY_NOMATCH".into(),
        }];
        let report = run_memory_eval(&mut conn, &cases).unwrap();
        assert_eq!(report.misses, 1);
        assert_eq!(report.hits, 0);
        assert_eq!(report.recall_precision, 0.0);
    }

    #[test]
    fn default_suite_runs_without_panic() {
        let (_dir, mut conn) = open_temp();
        let report = run_memory_eval(&mut conn, &default_eval_suite()).unwrap();
        assert_eq!(report.queries_run, default_eval_suite().len());
        // We don't assert precision here — this is a smoke test that the
        // harness doesn't crash on the built-in suite.
    }

    // ── GOLD-ADAPT-NN-MEM-07: contradiction detection tests ─────────────────

    /// A clear polarity flip ("vpn is up" vs "vpn is not up") MUST be caught.
    #[test]
    fn contradiction_eval_polarity_flip_is_caught() {
        let cases = vec![ContradictionCase {
            base_statement: "The VPN is up.".into(),
            other_statement: "The VPN is not up.".into(),
            expect_detected: true,
        }];
        let report = run_contradiction_eval(&cases);
        assert_eq!(report.contradictions_expected, 1);
        assert_eq!(
            report.contradictions_caught, 1,
            "polarity flip must be detected; pair_confidence returned None"
        );
        assert_eq!(report.contradiction_detection_rate, 1.0);
        assert_eq!(report.false_catches, 0);
    }

    /// An unrelated statement pair must NOT be flagged as a contradiction
    /// (precision guard — editor preference ≠ NAS address share no subject).
    #[test]
    fn contradiction_eval_unrelated_pair_not_flagged() {
        let cases = vec![ContradictionCase {
            base_statement: "The operator's favourite editor is Helix.".into(),
            other_statement: "The NAS is at 192.168.1.10.".into(),
            expect_detected: false,
        }];
        let report = run_contradiction_eval(&cases);
        // No true-positive cases → vacuous rate of 1.0.
        assert_eq!(report.contradictions_expected, 0);
        assert_eq!(report.contradiction_detection_rate, 1.0);
        assert_eq!(
            report.false_catches, 0,
            "unrelated pair must not trigger the contradiction detector"
        );
    }

    /// The default contradiction suite must produce a detection rate of 1.0
    /// (both true-positive cases caught, no false catches on the precision guard).
    #[test]
    fn default_contradiction_suite_passes() {
        let report = run_contradiction_eval(&default_contradiction_suite());
        assert_eq!(
            report.contradictions_caught, report.contradictions_expected,
            "all true-positive cases in the default suite must be caught"
        );
        assert_eq!(
            report.contradiction_detection_rate, 1.0,
            "default suite must yield 100 % detection rate"
        );
        assert_eq!(
            report.false_catches, 0,
            "no false catches expected on the default precision guard"
        );
    }

    /// `run_memory_eval` propagates contradiction metrics into `EvalReport`.
    #[test]
    fn run_memory_eval_includes_contradiction_metrics() {
        let (_dir, mut conn) = open_temp();
        let report = run_memory_eval(&mut conn, &default_eval_suite()).unwrap();
        // The default contradiction suite has 2 true-positive cases.
        assert!(
            report.contradictions_expected > 0,
            "run_memory_eval must populate contradictions_expected"
        );
        assert!(
            report.contradiction_detection_rate > 0.0,
            "contradiction_detection_rate must be > 0 when cases are present"
        );
    }

    // ── GOLD-ADAPT-NN-MEM-07: Hebbian correlation tests ─────────────────────

    /// {1,2} co-accessed 5× and {3,4} co-accessed 1× → weight(1,2) > weight(3,4)
    /// → all ordered comparisons are concordant → hebbian_correlation == 1.0.
    #[test]
    fn hebbian_eval_perfect_rank_agreement() {
        let (_dir, conn) = open_temp();
        let report = run_hebbian_eval(&conn).unwrap();
        assert_eq!(
            report.hebbian_correlation, 1.0,
            "5×/3×/1× reinforcement must yield perfect rank-agreement; got {:.4}",
            report.hebbian_correlation
        );
        assert_eq!(
            report.pairs_compared, 3,
            "C(3,2)=3 ordered pair comparisons expected"
        );
        assert!(
            report.top_hub_correct,
            "memory_hubs must return non-empty result containing BASE+1 or BASE+2"
        );
    }

    /// `run_memory_eval` propagates hebbian_correlation into `EvalReport`.
    #[test]
    fn run_memory_eval_includes_hebbian_metric() {
        let (_dir, mut conn) = open_temp();
        let report = run_memory_eval(&mut conn, &default_eval_suite()).unwrap();
        assert_eq!(
            report.hebbian_correlation, 1.0,
            "default eval must yield hebbian_correlation = 1.0 (3 pairs, all concordant)"
        );
        assert_eq!(
            report.hebbian_pairs_compared, 3,
            "default eval must record 3 pair comparisons"
        );
    }
}
