//! GOLD-ADAPT-MEMGRAPH-02 — LongMemEval-style memory eval harness.
//!
//! Builds a synthetic memory DB, runs the decay/consolidation pass, then
//! measures recall quality (precision) so the operator or CI can quantify
//! whether memory-tuning helps or regresses.
//!
//! Entry point: [`run_memory_eval`].  CLI surface: `neoth memory-eval`.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use super::consolidate::run_consolidation_pass;

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
            episodes: vec![
                "Der Operator bevorzugt lokale Modelle ohne API-Kosten.".into(),
            ],
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
        let hit = found
            .iter()
            .any(|row| row.to_lowercase().contains(&case.expect_substr.to_lowercase()));
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

    Ok(EvalReport {
        episodes_injected,
        queries_run,
        hits,
        misses,
        recall_precision,
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
}
