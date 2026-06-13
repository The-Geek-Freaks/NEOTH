//! GOLD-ADAPT-MEM-07 — Hebbian co-access association graph between memory rows.
//!
//! Distinct from the scalar per-row "Hebbian" importance reinforcement: this is
//! a **pairwise** association graph. When several memories are recalled together
//! for one query they are "co-accessed" → a symmetric weighted link between each
//! pair is created or reinforced ("fired together, wired together"). Recall can
//! then 1-hop-expand to associated memories, and `neoth recall --assoc <id>`
//! queries the neighbourhood directly.
//!
//! Edges are SYMMETRIC + stored canonically (`lo_id < hi_id`, one row per pair —
//! a `CHECK(lo_id < hi_id)` enforces it at the SQL level). Weights decay on the
//! existing `decay_task` cadence and prune below a floor, so an association that
//! is never re-formed fades away (episodic associations are short-lived by
//! design — semantic identity is the MEM-06 entity graph's job).
//!
//! Adapted from the A-Mem / MemPalace `hebbianLinks` pattern; mirrors the
//! `memory/entities.rs` SQL idioms (rusqlite + `ON CONFLICT DO UPDATE`).

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

/// Hard cap on the co-access set size, bounding the O(n²) pair fan-out
/// (`C(50,2)=1225`). The recall hook already passes only the top-K results, but
/// this caps any caller defensively.
const MAX_PAIR_SET: usize = 50;

/// Reinforce the co-access association between every unordered pair of
/// `event_ids` (deduped, capped to [`MAX_PAIR_SET`]). A new pair is inserted at
/// weight 1.0; a repeat bumps the weight by 1.0. All upserts run in one
/// transaction. Returns the number of pair-upserts performed.
///
/// Caller (normal recall) treats this best-effort — a failure must never fail or
/// re-rank the recall. Endpoints must be real positive episode `event_id`s
/// (warm-summary synthetic negatives + groundtruth ids are filtered out before
/// the call).
pub fn reinforce_co_access(conn: &Connection, event_ids: &[i64], now_unix: i64) -> Result<usize> {
    // Dedup (preserving order) + cap — so a duplicated id in one recall can't
    // double-count a pair, and a huge result set can't explode the fan-out.
    let mut seen = std::collections::HashSet::new();
    let ids: Vec<i64> = event_ids
        .iter()
        .copied()
        .filter(|&id| seen.insert(id))
        .take(MAX_PAIR_SET)
        .collect();
    if ids.len() < 2 {
        return Ok(0);
    }
    let tx = conn.unchecked_transaction().context("begin co-access tx")?;
    let mut n = 0usize;
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            let (a, b) = (ids[i], ids[j]);
            if a == b {
                continue; // self-link guard (defensive; dedup already removes dups)
            }
            let (lo, hi) = if a < b { (a, b) } else { (b, a) };
            tx.execute(
                "INSERT INTO idx_memory_links (lo_id, hi_id, weight, last_co_access) \
                 VALUES (?1, ?2, 1.0, ?3) \
                 ON CONFLICT(lo_id, hi_id) DO UPDATE SET weight = weight + 1.0, last_co_access = ?3",
                params![lo, hi, now_unix],
            )
            .context("upsert co-access link")?;
            n += 1;
        }
    }
    tx.commit().context("commit co-access tx")?;
    Ok(n)
}

/// The 1-hop association neighbourhood of `event_id`: the other endpoint of each
/// link touching it, ordered by weight DESC, capped at `limit`. A
/// **dangling-endpoint guard** skips any partner id that no longer exists in a
/// live tier (`idx_episode` hot or `idx_longterm` cold) — defence-in-depth
/// against a missed forget cascade so a forgotten memory never resurfaces here.
pub fn associated(conn: &Connection, event_id: i64, limit: usize) -> Result<Vec<(i64, f64)>> {
    let mut stmt = conn
        .prepare(
            "SELECT other_id, weight FROM ( \
                SELECT CASE WHEN lo_id = ?1 THEN hi_id ELSE lo_id END AS other_id, weight \
                FROM idx_memory_links WHERE lo_id = ?1 OR hi_id = ?1 \
             ) \
             WHERE EXISTS (SELECT 1 FROM idx_episode WHERE event_id = other_id) \
                OR EXISTS (SELECT 1 FROM idx_longterm WHERE event_id = other_id) \
             ORDER BY weight DESC LIMIT ?2",
        )
        .context("prepare associated query")?;
    let rows = stmt
        .query_map(params![event_id, limit as i64], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?))
        })
        .context("run associated query")?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Decay every link weight by `factor` (multiplicative) then prune links that
/// fell below `floor`. Runs on the `decay_task` cadence (2 h). Returns the
/// number of links pruned. With factor 0.98 at 2 h cadence a link halves in
/// ~3 days of no reinforcement and drops below a 0.05 floor in ~10 days.
pub fn decay_links(conn: &Connection, factor: f64, floor: f64) -> Result<usize> {
    conn.execute(
        "UPDATE idx_memory_links SET weight = weight * ?1 WHERE weight > 0.0",
        params![factor],
    )
    .context("decay link weights")?;
    let pruned = conn
        .execute("DELETE FROM idx_memory_links WHERE weight < ?1", params![floor])
        .context("prune decayed links")?;
    Ok(pruned)
}

/// GDPR forget cascade: delete every link touching `event_id`. Called from
/// `memory::forget` for each forgotten episode so no link dangles. Returns rows
/// deleted.
pub fn forget_links_for_event(conn: &Connection, event_id: i64) -> Result<i64> {
    let n = conn
        .execute(
            "DELETE FROM idx_memory_links WHERE lo_id = ?1 OR hi_id = ?1",
            params![event_id],
        )
        .context("forget links for event")? as i64;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;

    fn conn() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let c = store::open(&dir.path().join("v.db")).unwrap();
        (dir, c)
    }

    /// Seed a minimal `idx_episode` row so an event_id counts as a live endpoint
    /// (the dangling-endpoint guard in `associated` requires it).
    fn seed_episode(conn: &Connection, event_id: i64) {
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, 1, 1, 'x', 'h')",
            params![event_id],
        )
        .unwrap();
    }

    fn weight(conn: &Connection, lo: i64, hi: i64) -> f64 {
        conn.query_row(
            "SELECT weight FROM idx_memory_links WHERE lo_id = ?1 AND hi_id = ?2",
            params![lo, hi],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn reinforce_inserts_pairs_and_accumulates_on_repeat() {
        let (_d, c) = conn();
        let n = reinforce_co_access(&c, &[1, 2, 3], 100).unwrap();
        assert_eq!(n, 3, "C(3,2) = 3 pairs");
        assert!((weight(&c, 1, 2) - 1.0).abs() < 1e-9);
        // Second co-access of the same set bumps each pair to 2.0.
        reinforce_co_access(&c, &[1, 2, 3], 200).unwrap();
        assert!((weight(&c, 1, 2) - 2.0).abs() < 1e-9);
        assert!((weight(&c, 2, 3) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn reinforce_normalises_pair_order_and_dedups_ids() {
        let (_d, c) = conn();
        // Unordered + a duplicated id in one call → ONE canonical pair, weight 1.0.
        let n = reinforce_co_access(&c, &[3, 1, 3], 1).unwrap();
        assert_eq!(n, 1, "dup id deduped → single (1,3) pair");
        assert!((weight(&c, 1, 3) - 1.0).abs() < 1e-9, "not double-counted");
        // The canonical row is (lo=1, hi=3) regardless of input order.
        let exists: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM idx_memory_links WHERE lo_id = 1 AND hi_id = 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
    }

    #[test]
    fn reinforce_caps_the_pair_fan_out() {
        let (_d, c) = conn();
        let big: Vec<i64> = (1..=60).collect(); // 60 > MAX_PAIR_SET
        let n = reinforce_co_access(&c, &big, 1).unwrap();
        assert_eq!(n, MAX_PAIR_SET * (MAX_PAIR_SET - 1) / 2, "capped to C(50,2)");
    }

    #[test]
    fn reinforce_single_or_empty_is_noop() {
        let (_d, c) = conn();
        assert_eq!(reinforce_co_access(&c, &[7], 1).unwrap(), 0);
        assert_eq!(reinforce_co_access(&c, &[], 1).unwrap(), 0);
    }

    #[test]
    fn associated_orders_by_weight_desc() {
        let (_d, c) = conn();
        for id in [1, 2, 3] {
            seed_episode(&c, id);
        }
        // (1,2) co-accessed twice → weight 2; (1,3) once → weight 1.
        reinforce_co_access(&c, &[1, 2], 1).unwrap();
        reinforce_co_access(&c, &[1, 2], 2).unwrap();
        reinforce_co_access(&c, &[1, 3], 3).unwrap();
        let assoc = associated(&c, 1, 10).unwrap();
        assert_eq!(assoc.len(), 2);
        assert_eq!(assoc[0].0, 2, "heaviest link first");
        assert!(assoc[0].1 > assoc[1].1);
        assert_eq!(assoc[1].0, 3);
    }

    #[test]
    fn associated_unknown_event_is_empty() {
        let (_d, c) = conn();
        assert!(associated(&c, 999, 10).unwrap().is_empty());
    }

    #[test]
    fn associated_skips_dangling_endpoint() {
        let (_d, c) = conn();
        seed_episode(&c, 1); // 1 is live; 2 is NOT seeded (simulates a missed cascade)
        reinforce_co_access(&c, &[1, 2], 1).unwrap();
        let assoc = associated(&c, 1, 10).unwrap();
        assert!(
            assoc.is_empty(),
            "a link to a non-existent endpoint must not surface: {assoc:?}"
        );
    }

    #[test]
    fn decay_reduces_weights_and_prunes_below_floor() {
        let (_d, c) = conn();
        reinforce_co_access(&c, &[1, 2, 3], 1).unwrap(); // each pair weight 1.0
        // Decay by 0.5 → 0.5 (above a 0.1 floor): nothing pruned.
        assert_eq!(decay_links(&c, 0.5, 0.1).unwrap(), 0);
        assert!((weight(&c, 1, 2) - 0.5).abs() < 1e-9);
        // Decay again → 0.25, then a 0.3 floor prunes all three.
        let pruned = decay_links(&c, 0.5, 0.3).unwrap();
        assert_eq!(pruned, 3, "all three links pruned below floor");
        let remaining: i64 = c
            .query_row("SELECT COUNT(*) FROM idx_memory_links", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn forget_links_removes_every_pair_touching_the_event() {
        let (_d, c) = conn();
        reinforce_co_access(&c, &[1, 2, 3], 1).unwrap(); // (1,2),(1,3),(2,3)
        let deleted = forget_links_for_event(&c, 1).unwrap();
        assert_eq!(deleted, 2, "(1,2) and (1,3) gone");
        let remaining: i64 = c
            .query_row("SELECT COUNT(*) FROM idx_memory_links", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1, "(2,3) survives");
    }
}
