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
//!
//! ## GOLD-ADAPT-JV-MEM-08 — Hebbian feedback on edges
//!
//! Two counters on each `idx_memory_links` row — `feedback_success` and
//! `feedback_failure` (v20, already in schema) — track how often a co-access
//! pair led to a *useful* recall outcome versus a bad one.
//!
//! Call [`record_link_feedback`] when a recall outcome is known (success = the
//! pair was useful, failure = the pair was noise). The adjusted weight used for
//! ranking is computed by [`link_effective_weight`] — positive feedback boosts
//! the raw co-access weight, negative feedback dampens it.  The 1-hop
//! neighbourhood query ([`associated`]) applies this adjustment so associations
//! that repeatedly proved useful surface above ones that never did.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

/// Hard cap on the co-access set size, bounding the O(n²) pair fan-out
/// (`C(50,2)=1225`). The recall hook already passes only the top-K results, but
/// this caps any caller defensively.
const MAX_PAIR_SET: usize = 50;

/// MEM-07b — default tumbling-window width for the co-occurrence bootstrap: 1 h
/// in nanoseconds. Episodes in the same hour bucket are treated as co-occurring.
/// 1 h matches the natural attention span (a single sitting) without merging
/// unrelated morning/evening sessions the way a 1-day bucket would.
pub const DEFAULT_BOOTSTRAP_WINDOW_NS: u64 = 3_600_000_000_000;
/// MEM-07b — weight added per window a pair co-occurs in. Deliberately small:
/// a bootstrap edge is INFERRED temporal proximity, not a confirmed co-recall
/// (which the live path scores at +1.0).
const BOOTSTRAP_WEIGHT_PER_WINDOW: f64 = 0.15;
/// MEM-07b — ceiling on a bootstrap edge weight: strictly below the 1.0 a single
/// live co-recall produces, so a bootstrap edge never masquerades as live-learned.
const BOOTSTRAP_MAX_WEIGHT: f64 = 0.9;
/// MEM-07b — skip a window with more than this many episodes: such a dense hour
/// is an ingestion burst (import/backfill), not a conversation, and pairing it
/// would create hundreds of spurious associations.
const MAX_BOOTSTRAP_WINDOW_EPISODES: usize = 20;
/// MEM-07b — backstop on the total distinct pairs the bootstrap will track, so a
/// huge episode history can't balloon the in-memory accumulator. Once reached,
/// accumulation stops (existing counts are still inserted).
const MAX_BOOTSTRAP_PAIRS: usize = 50_000;

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
/// link touching it, ordered by **feedback-adjusted effective weight** DESC,
/// capped at `limit`. A **dangling-endpoint guard** skips any partner id that no
/// longer exists in a live tier (`idx_episode` hot or `idx_longterm` cold) —
/// defence-in-depth against a missed forget cascade so a forgotten memory never
/// resurfaces here.
///
/// The effective weight is computed via [`link_effective_weight`] using the
/// `feedback_success` / `feedback_failure` counters on each edge row
/// (GOLD-ADAPT-JV-MEM-08). A co-access pair that repeatedly proved useful to the
/// operator ranks above one that never received positive feedback.
pub fn associated(conn: &Connection, event_id: i64, limit: usize) -> Result<Vec<(i64, f64)>> {
    let mut stmt = conn
        .prepare(
            "SELECT other_id, weight, feedback_success, feedback_failure FROM ( \
                SELECT CASE WHEN lo_id = ?1 THEN hi_id ELSE lo_id END AS other_id, \
                       weight, feedback_success, feedback_failure \
                FROM idx_memory_links WHERE lo_id = ?1 OR hi_id = ?1 \
             ) \
             WHERE EXISTS (SELECT 1 FROM idx_episode WHERE event_id = other_id) \
                OR EXISTS (SELECT 1 FROM idx_longterm WHERE event_id = other_id)",
        )
        .context("prepare associated query")?;
    // Collect all live neighbours, apply feedback-adjusted weight, then sort+cap.
    let mut rows: Vec<(i64, f64)> = stmt
        .query_map(params![event_id], |r| {
            let other_id: i64 = r.get(0)?;
            let raw_weight: f64 = r.get(1)?;
            let success: i64 = r.get(2)?;
            let failure: i64 = r.get(3)?;
            let eff = link_effective_weight(
                raw_weight,
                success.max(0) as u32,
                failure.max(0) as u32,
            );
            Ok((other_id, eff))
        })
        .context("run associated query")?
        .filter_map(|r| r.ok())
        .collect();
    // Sort by effective weight DESC (stable within ties by id for determinism).
    rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    rows.truncate(limit);
    Ok(rows)
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
        .execute(
            "DELETE FROM idx_memory_links WHERE weight < ?1",
            params![floor],
        )
        .context("prune decayed links")?;
    Ok(pruned)
}

/// GOLD-ADAPT-GRAPH-01 — return the most-connected nodes in the association
/// graph, sorted by degree descending. Degree = number of distinct links that
/// touch a node (either as `lo_id` or `hi_id`). Returns up to `limit` entries
/// as `(memory_id, degree)` pairs. A node with no links has degree 0 and never
/// appears; the result is empty when the table is empty.
pub fn memory_hubs(conn: &Connection, limit: usize) -> rusqlite::Result<Vec<(i64, u32)>> {
    let mut stmt = conn.prepare(
        "SELECT node_id, COUNT(*) AS degree FROM ( \
             SELECT lo_id AS node_id FROM idx_memory_links \
             UNION ALL \
             SELECT hi_id AS node_id FROM idx_memory_links \
         ) GROUP BY node_id ORDER BY degree DESC LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![limit as i64], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u32))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
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

// ── GOLD-ADAPT-JV-MEM-08 — Hebbian feedback on edges ────────────────────────

/// Compute the feedback-adjusted effective weight for a link.
///
/// Formula:
/// ```text
/// effective = weight * (1 + (success − failure) / (success + failure + 1))
/// ```
/// The correction term is in `(−1, +1)` exclusive:
/// - All successes → correction near `+1.0` → weight roughly doubled.
/// - All failures  → correction near `−1.0` → weight approaches zero.
/// - Balanced / no feedback (success == failure == 0) → correction 0.0 →
///   weight unchanged.
///
/// The result is floored at `0.0` so a heavily-penalised link never goes
/// negative (it decays toward the prune floor via the normal decay cadence
/// instead of being silently zeroed here).
///
/// This is a **pure** function — no DB access. Call it in row-mappers where
/// both counters are available.
pub fn link_effective_weight(weight: f64, success: u32, failure: u32) -> f64 {
    let correction = (success as f64 - failure as f64) / (success + failure + 1) as f64;
    (weight * (1.0 + correction)).max(0.0)
}

/// GOLD-ADAPT-JV-MEM-08 — record operator/signal feedback for the link between
/// `a_id` and `b_id`.
///
/// Canonicalises the pair (`lo < hi`) and increments either `feedback_success`
/// or `feedback_failure` on the existing row. Returns `true` if the row existed
/// and was updated, `false` if no such link exists (a link is **never** created
/// from feedback alone — `reinforce_co_access` owns link creation).
///
/// Safe to call multiple times for the same pair; each call adds 1 to the
/// relevant counter (idempotent-safe in the sense that it never corrupts, but
/// repeated calls do accumulate — callers must not double-fire per event).
pub fn record_link_feedback(
    conn: &Connection,
    a_id: i64,
    b_id: i64,
    success: bool,
) -> rusqlite::Result<bool> {
    let (lo, hi) = if a_id < b_id { (a_id, b_id) } else { (b_id, a_id) };
    let col = if success {
        "feedback_success"
    } else {
        "feedback_failure"
    };
    // Build the SQL string with the column name interpolated (safe: col is a
    // compile-time constant string, never user input).
    let sql = format!(
        "UPDATE idx_memory_links SET {col} = {col} + 1 \
         WHERE lo_id = ?1 AND hi_id = ?2"
    );
    let rows_changed = conn.execute(&sql, rusqlite::params![lo, hi])?;
    Ok(rows_changed > 0)
}

/// Accumulate all unordered canonical (lo<hi) pairs of one window's episode ids
/// into `pair_counts` (+1 per pair). Returns `false` once the global pair cap is
/// hit so the caller can stop the scan.
fn accumulate_window_pairs(
    ids: &[i64],
    pair_counts: &mut std::collections::HashMap<(i64, i64), u32>,
) -> bool {
    if ids.len() < 2 {
        return true;
    }
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            let (a, b) = (ids[i], ids[j]);
            if a == b {
                continue;
            }
            let key = if a < b { (a, b) } else { (b, a) };
            // Only let an existing key grow once the cap is reached — never add a
            // NEW key past the cap (bounds the map).
            if pair_counts.len() >= MAX_BOOTSTRAP_PAIRS && !pair_counts.contains_key(&key) {
                return false;
            }
            *pair_counts.entry(key).or_insert(0) += 1;
        }
    }
    true
}

/// MEM-07b — bootstrap co-occurrence edges from episode history.
///
/// Walks `idx_episode` in chronological order, assigns each episode to a tumbling
/// bucket of `window_ns` nanoseconds, and counts the distinct buckets in which
/// each canonical `(lo_id, hi_id)` pair co-appears. A NEW edge is inserted at
/// `weight = min(0.15 * count, 0.9)`. Existing edges (live-learned or from a
/// prior bootstrap) are NEVER modified (`ON CONFLICT DO NOTHING`) — so the
/// bootstrap is idempotent on re-run and can never inflate a live weight.
///
/// Windows with more than [`MAX_BOOTSTRAP_WINDOW_EPISODES`] episodes are skipped
/// (ingestion-burst guard). A bootstrapped weight-0.15 edge decays below the
/// 0.05 prune floor in ~4.6 days of no reinforcement (0.30 in ~7.4 days), so a
/// bootstrap edge is a weak hint that fades unless a real co-recall confirms it.
///
/// Returns the number of edges created (0 when every pair already existed).
pub fn bootstrap_co_occurrence(conn: &Connection, window_ns: u64, now_unix: i64) -> Result<usize> {
    if window_ns == 0 {
        anyhow::bail!("bootstrap window must be non-zero");
    }
    let mut stmt = conn
        .prepare("SELECT event_id, ts_ns FROM idx_episode ORDER BY ts_ns ASC")
        .context("bootstrap: prepare episode cursor")?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
        .context("bootstrap: query episodes")?;

    let mut pair_counts: std::collections::HashMap<(i64, i64), u32> =
        std::collections::HashMap::new();
    let mut current_bucket: Option<u64> = None;
    let mut bucket_ids: Vec<i64> = Vec::new();
    let mut skipped_windows: u64 = 0;
    let mut capped = false;

    'scan: for row in rows {
        let (event_id, ts_ns) = row.context("bootstrap: read episode row")?;
        // Corrupt/pre-epoch negatives wrap to a far bucket — harmless (they pair
        // only with each other, and DO NOTHING covers the rare collision).
        let bucket = (ts_ns as u64) / window_ns;
        match current_bucket {
            Some(b) if b == bucket => bucket_ids.push(event_id),
            _ => {
                if current_bucket.is_some() {
                    if bucket_ids.len() > MAX_BOOTSTRAP_WINDOW_EPISODES {
                        skipped_windows += 1;
                    } else if !accumulate_window_pairs(&bucket_ids, &mut pair_counts) {
                        capped = true;
                        break 'scan;
                    }
                }
                current_bucket = Some(bucket);
                bucket_ids.clear();
                bucket_ids.push(event_id);
            }
        }
    }
    // Flush the final bucket (unless we already stopped at the cap).
    if !capped && current_bucket.is_some() {
        if bucket_ids.len() > MAX_BOOTSTRAP_WINDOW_EPISODES {
            skipped_windows += 1;
        } else {
            let _ = accumulate_window_pairs(&bucket_ids, &mut pair_counts);
        }
    }

    let tx = conn
        .unchecked_transaction()
        .context("bootstrap: begin insert tx")?;
    let mut created = 0usize;
    for ((lo, hi), count) in &pair_counts {
        let weight = (BOOTSTRAP_WEIGHT_PER_WINDOW * (*count as f64)).min(BOOTSTRAP_MAX_WEIGHT);
        created += tx
            .execute(
                "INSERT INTO idx_memory_links (lo_id, hi_id, weight, last_co_access) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(lo_id, hi_id) DO NOTHING",
                params![lo, hi, weight, now_unix],
            )
            .context("bootstrap: insert link")?;
    }
    tx.commit().context("bootstrap: commit insert tx")?;

    tracing::debug!(
        pairs = pair_counts.len(),
        edges_created = created,
        skipped_windows,
        capped,
        "assoc_graph: co-occurrence bootstrap complete"
    );
    Ok(created)
}

// ── GOLD-ADAPT-GRAPH-03 — Louvain community detection ────────────────────────

/// One level of Louvain modularity optimisation over a weighted undirected graph.
///
/// Input: list of canonical `(lo, hi, weight)` edges (lo < hi). Isolated nodes
/// (nodes that appear in no edge) are not represented in the input and are omitted
/// from the output — the caller is responsible for deciding what to do with them
/// (here: omit, documented in [`detect_communities`]).
///
/// Algorithm (greedy single-level Louvain):
/// 1. Assign every node its own community.
/// 2. Iterate over nodes in ascending id order (deterministic).
/// 3. For each node, compute the modularity gain of moving it into each neighbouring
///    community; pick the best gain. Accept only when gain > 0.
/// 4. Repeat until a full pass yields no improvement.
///
/// Modularity gain for moving node `i` from its current community `c_i` into
/// community `c_j`:
///   ΔQ = [k_{i,c_j} / m] − [k_i · Σ_{c_j} / (2m²)]
/// where `k_{i,c_j}` = sum of weights from `i` to nodes in `c_j`, `m` = total
/// edge weight sum, `k_i` = weighted degree of `i`, `Σ_{c_j}` = sum of weighted
/// degrees of all nodes in `c_j`.
///
/// Returns communities as `Vec<Vec<node_id>>`, each inner vec sorted ascending,
/// outer sorted by size desc then min-id asc. Empty input → empty output.
pub fn louvain(edges: &[(i64, i64, f64)]) -> Vec<Vec<i64>> {
    if edges.is_empty() {
        return Vec::new();
    }

    // Collect sorted unique node ids so iteration is deterministic.
    let mut node_set: Vec<i64> = {
        let mut s = std::collections::BTreeSet::new();
        for &(lo, hi, _) in edges {
            s.insert(lo);
            s.insert(hi);
        }
        s.into_iter().collect()
    };
    node_set.sort_unstable();
    let n = node_set.len();

    // Index: node_id → 0-based position.
    let idx: std::collections::HashMap<i64, usize> = node_set
        .iter()
        .enumerate()
        .map(|(i, &id)| (id, i))
        .collect();

    // Build adjacency: adj[u] = Vec<(v, weight)>.
    let mut adj: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
    let mut total_weight = 0.0f64;
    for &(lo, hi, w) in edges {
        let u = idx[&lo];
        let v = idx[&hi];
        adj[u].push((v, w));
        adj[v].push((u, w));
        total_weight += w; // each edge counted once here
    }
    // total_weight = m (sum of all edge weights, each edge once)
    let m = total_weight;
    if m <= 0.0 {
        // All weights are zero or negative — treat as one community per node.
        return node_set.into_iter().map(|id| vec![id]).collect();
    }

    // Weighted degree of each node.
    let k: Vec<f64> = adj
        .iter()
        .map(|neighbours| neighbours.iter().map(|(_, w)| w).sum())
        .collect();

    // Community assignment: comm[u] = community id (0-based, initially u itself).
    let mut comm: Vec<usize> = (0..n).collect();

    // sigma_tot[c] = sum of weighted degrees of nodes in community c.
    let mut sigma_tot: Vec<f64> = k.clone();

    let mut improved = true;
    while improved {
        improved = false;
        for u in 0..n {
            let c_u = comm[u];

            // k_{u, c} = sum of edge weights from u to nodes in community c.
            let mut k_u_c: std::collections::HashMap<usize, f64> =
                std::collections::HashMap::new();
            for &(v, w) in &adj[u] {
                *k_u_c.entry(comm[v]).or_insert(0.0) += w;
            }

            // Remove u from its current community for the gain calculation.
            sigma_tot[c_u] -= k[u];

            // Staying in c_u is evaluated as one of the candidate communities
            // below (c_u appears in k_u_c when u has a neighbour in its own
            // community), so the move only fires on a strictly better target.
            // Best gain: try every neighbouring community + staying in c_u.
            let mut best_gain = 0.0f64; // only move if strictly positive
            let mut best_comm = c_u;

            // Candidate communities: neighbours' communities + current.
            let mut candidates: Vec<usize> = k_u_c.keys().copied().collect();
            candidates.sort_unstable(); // deterministic tie-breaking
            candidates.dedup();

            for c_t in candidates {
                let k_u_ct = k_u_c.get(&c_t).copied().unwrap_or(0.0);
                // ΔQ = k_{u,c_t}/m − k_u · sigma_tot[c_t] / (2m²)
                let gain = k_u_ct / m - k[u] * sigma_tot[c_t] / (2.0 * m * m);
                if gain > best_gain {
                    best_gain = gain;
                    best_comm = c_t;
                }
            }

            // Put u back / move u.
            sigma_tot[best_comm] += k[u];
            if best_comm != c_u {
                comm[u] = best_comm;
                improved = true;
            } else {
                // Undo: sigma_tot[c_u] was already reduced above; restore.
                // (We put u back into c_u via best_comm = c_u, already done.)
            }
        }
    }

    // Collect communities: label → members.
    let mut groups: std::collections::HashMap<usize, Vec<i64>> =
        std::collections::HashMap::new();
    for (u, &c) in comm.iter().enumerate() {
        groups.entry(c).or_default().push(node_set[u]);
    }

    // Sort each community's members, then sort communities: size desc, min_id asc.
    let mut result: Vec<Vec<i64>> = groups
        .into_values()
        .map(|mut v| {
            v.sort_unstable();
            v
        })
        .collect();
    result.sort_by(|a, b| {
        b.len().cmp(&a.len()).then_with(|| a[0].cmp(&b[0]))
    });
    result
}

/// GOLD-ADAPT-GRAPH-03 — detect communities in the association graph using one
/// level of Louvain modularity optimisation over the `idx_memory_links` edge set.
///
/// Loads all `(lo_id, hi_id, weight)` rows, runs [`louvain`], and returns the
/// communities as `Vec<Vec<i64>>` (each inner vec sorted asc, outer sorted by
/// size desc then min-id asc). Isolated nodes (nodes with no edges in the table)
/// are omitted — they never appear in `idx_memory_links` and therefore cannot be
/// assigned to any graph community. An empty table returns an empty vec.
pub fn detect_communities(conn: &Connection) -> rusqlite::Result<Vec<Vec<i64>>> {
    let mut stmt =
        conn.prepare("SELECT lo_id, hi_id, weight FROM idx_memory_links WHERE weight > 0")?;
    let edges: Vec<(i64, i64, f64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(louvain(&edges))
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
        assert_eq!(
            n,
            MAX_PAIR_SET * (MAX_PAIR_SET - 1) / 2,
            "capped to C(50,2)"
        );
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

    // ── MEM-07b: co-occurrence bootstrap ────────────────────────────────────

    /// Seed an `idx_episode` row at an explicit `ts_ns` so it lands in a chosen
    /// bootstrap bucket.
    fn seed_episode_at(conn: &Connection, event_id: i64, ts_ns: i64) {
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, 1, ?2, 'x', 'h')",
            params![event_id, ts_ns],
        )
        .unwrap();
    }

    const W: u64 = 1000; // small test window

    #[test]
    fn bootstrap_links_same_window_episodes_at_base_weight() {
        let (_d, c) = conn();
        for id in [1, 2] {
            seed_episode_at(&c, id, 0); // same bucket
        }
        let created = bootstrap_co_occurrence(&c, W, 100).unwrap();
        assert_eq!(created, 1, "one (1,2) edge");
        assert!(
            (weight(&c, 1, 2) - 0.15).abs() < 1e-9,
            "base bootstrap weight 0.15"
        );
    }

    #[test]
    fn bootstrap_is_idempotent() {
        let (_d, c) = conn();
        for id in [1, 2, 3] {
            seed_episode_at(&c, id, 0);
        }
        assert_eq!(
            bootstrap_co_occurrence(&c, W, 100).unwrap(),
            3,
            "C(3,2)=3 edges"
        );
        // Re-run creates nothing + leaves weights untouched (DO NOTHING).
        assert_eq!(
            bootstrap_co_occurrence(&c, W, 200).unwrap(),
            0,
            "re-run is a no-op"
        );
        assert!((weight(&c, 1, 2) - 0.15).abs() < 1e-9);
    }

    #[test]
    fn bootstrap_never_overwrites_a_live_edge() {
        let (_d, c) = conn();
        seed_episode_at(&c, 1, 0);
        seed_episode_at(&c, 2, 0);
        // A live co-recall first → weight 1.0.
        reinforce_co_access(&c, &[1, 2], 1).unwrap();
        // Bootstrap must NOT touch it (DO NOTHING).
        assert_eq!(
            bootstrap_co_occurrence(&c, W, 100).unwrap(),
            0,
            "live edge skipped"
        );
        assert!(
            (weight(&c, 1, 2) - 1.0).abs() < 1e-9,
            "live weight preserved"
        );
    }

    #[test]
    fn bootstrap_normalises_pairs_to_canonical_order() {
        let (_d, c) = conn();
        for id in [5, 2, 8] {
            seed_episode_at(&c, id, 0);
        }
        // Would panic/abort on the CHECK(lo_id<hi_id) if any pair were unordered.
        let created = bootstrap_co_occurrence(&c, W, 100).unwrap();
        assert_eq!(created, 3, "(2,5),(2,8),(5,8)");
        let unordered: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM idx_memory_links WHERE lo_id >= hi_id",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(unordered, 0, "every row is canonical lo<hi");
    }

    #[test]
    fn bootstrap_single_episode_window_makes_no_edge() {
        let (_d, c) = conn();
        seed_episode_at(&c, 1, 0);
        assert_eq!(bootstrap_co_occurrence(&c, W, 100).unwrap(), 0);
    }

    #[test]
    fn bootstrap_does_not_link_across_windows() {
        let (_d, c) = conn();
        seed_episode_at(&c, 1, 0); // bucket 0
        seed_episode_at(&c, 2, (W as i64) * 5); // bucket 5
        assert_eq!(
            bootstrap_co_occurrence(&c, W, 100).unwrap(),
            0,
            "different windows → no edge"
        );
    }

    #[test]
    fn bootstrap_skips_a_dense_ingestion_burst_window() {
        let (_d, c) = conn();
        // MAX_BOOTSTRAP_WINDOW_EPISODES + 1 episodes in one bucket → skipped whole.
        for id in 1..=(MAX_BOOTSTRAP_WINDOW_EPISODES as i64 + 1) {
            seed_episode_at(&c, id, 0);
        }
        assert_eq!(
            bootstrap_co_occurrence(&c, W, 100).unwrap(),
            0,
            "dense window skipped"
        );
    }

    // ── GOLD-ADAPT-GRAPH-01: memory_hubs ─────────────────────────────────

    #[test]
    fn memory_hubs_returns_most_connected_node_first() {
        let (_d, c) = conn();
        // Build a star topology around id=1: co-access with 2, 3, 4, 5.
        // id=1 appears in 4 links (degree 4); ids 2..5 each appear in 1 link
        // (degree 1). id=2 and id=3 share one additional pair (degree 2 each).
        //   links after reinforce_co_access([1,2,3,4,5]):
        //     (1,2),(1,3),(1,4),(1,5),(2,3),(2,4),(2,5),(3,4),(3,5),(4,5) → 10 links
        //   C(5,2)=10: degrees:
        //     1 → 4 links, 2 → 4 links, 3 → 4 links, 4 → 4 links, 5 → 4 links
        // Use smaller, unequal sets so one node clearly wins.
        // co-access [1,2]: links (1,2)
        // co-access [1,3]: links (1,3)
        // co-access [1,4]: links (1,4)
        // → id=1 has degree 3; ids 2,3,4 each have degree 1.
        reinforce_co_access(&c, &[1, 2], 1).unwrap();
        reinforce_co_access(&c, &[1, 3], 2).unwrap();
        reinforce_co_access(&c, &[1, 4], 3).unwrap();

        let hubs = memory_hubs(&c, 10).unwrap();
        assert!(!hubs.is_empty(), "at least one hub must be returned");

        // id=1 must rank first with degree 3.
        assert_eq!(hubs[0].0, 1, "id=1 has highest degree (3 links)");
        assert_eq!(hubs[0].1, 3, "degree of id=1 is 3");

        // All other nodes (2, 3, 4) must have degree 1.
        for &(node_id, degree) in &hubs[1..] {
            assert!(
                [2i64, 3, 4].contains(&node_id),
                "unexpected node in hub list: {node_id}"
            );
            assert_eq!(degree, 1, "node {node_id} must have degree 1");
        }

        // limit is honoured: requesting top-1 returns exactly one row.
        let top1 = memory_hubs(&c, 1).unwrap();
        assert_eq!(top1.len(), 1);
        assert_eq!(top1[0].0, 1, "top-1 hub must be id=1");
    }

    #[test]
    fn memory_hubs_empty_table_returns_empty_vec() {
        let (_d, c) = conn();
        let hubs = memory_hubs(&c, 10).unwrap();
        assert!(hubs.is_empty(), "no links → no hubs");
    }

    // ── GOLD-ADAPT-GRAPH-03: Louvain community detection ─────────────────

    /// Fully-connected triad: {1,2,3}. All three are in the same community.
    #[test]
    fn louvain_single_clique_returns_one_community() {
        let edges = vec![(1, 2, 1.0), (1, 3, 1.0), (2, 3, 1.0)];
        let communities = louvain(&edges);
        assert_eq!(communities.len(), 1, "one tight clique → one community");
        let mut members = communities[0].clone();
        members.sort_unstable();
        assert_eq!(members, vec![1, 2, 3]);
    }

    /// Two dense clusters {1,2,3} and {4,5,6} connected by a single weak
    /// bridge edge (3,4). Louvain must separate them.
    #[test]
    fn louvain_two_clusters_separated_by_weak_bridge() {
        let edges = vec![
            // cluster A
            (1, 2, 3.0),
            (1, 3, 3.0),
            (2, 3, 3.0),
            // cluster B
            (4, 5, 3.0),
            (4, 6, 3.0),
            (5, 6, 3.0),
            // weak bridge
            (3, 4, 0.1),
        ];
        let communities = louvain(&edges);
        assert_eq!(communities.len(), 2, "two clusters → two communities");
        // Outer is sorted by size desc then min-id asc: both size 3, so {1,2,3} first.
        assert_eq!(communities[0], vec![1, 2, 3]);
        assert_eq!(communities[1], vec![4, 5, 6]);
    }

    /// Empty edge list → empty result (no panic).
    #[test]
    fn louvain_empty_edges_returns_empty() {
        let communities = louvain(&[]);
        assert!(communities.is_empty(), "no edges → empty communities");
    }

    /// DB-level smoke test: insert links via reinforce_co_access and verify that
    /// detect_communities groups them correctly.
    #[test]
    fn detect_communities_groups_two_clusters() {
        let (_d, c) = conn();
        // cluster A: 1-2-3 fully linked
        reinforce_co_access(&c, &[1, 2, 3], 1).unwrap();
        reinforce_co_access(&c, &[1, 2, 3], 2).unwrap();
        reinforce_co_access(&c, &[1, 2, 3], 3).unwrap();
        // cluster B: 4-5-6 fully linked
        reinforce_co_access(&c, &[4, 5, 6], 4).unwrap();
        reinforce_co_access(&c, &[4, 5, 6], 5).unwrap();
        reinforce_co_access(&c, &[4, 5, 6], 6).unwrap();
        // weak bridge (manually insert a low-weight edge so it doesn't swamp the
        // intra-cluster weights, which are at 3.0 after 3 reinforcements).
        c.execute(
            "INSERT INTO idx_memory_links (lo_id, hi_id, weight, last_co_access) \
             VALUES (3, 4, 0.1, 7) ON CONFLICT(lo_id, hi_id) DO NOTHING",
            [],
        )
        .unwrap();

        let communities = detect_communities(&c).unwrap();
        assert_eq!(communities.len(), 2, "two dense clusters → two communities");
        let a = &communities[0];
        let b = &communities[1];
        assert_eq!(a, &vec![1, 2, 3], "cluster A is {{1,2,3}}");
        assert_eq!(b, &vec![4, 5, 6], "cluster B is {{4,5,6}}");
    }

    /// Empty table → empty communities (no panic, no error).
    #[test]
    fn detect_communities_empty_table_returns_empty() {
        let (_d, c) = conn();
        let communities = detect_communities(&c).unwrap();
        assert!(communities.is_empty(), "no links → no communities");
    }

    // ── GOLD-ADAPT-JV-MEM-08: Hebbian feedback on edges ─────────────────

    /// `link_effective_weight` — pure formula tests.
    #[test]
    fn link_effective_weight_pure_formula() {
        // Equal feedback (or no feedback) → correction 0 → unchanged.
        let base = 2.0f64;
        let eff_none = link_effective_weight(base, 0, 0);
        assert!(
            (eff_none - base).abs() < 1e-9,
            "no feedback → weight unchanged: {eff_none}"
        );
        let eff_balanced = link_effective_weight(base, 5, 5);
        // correction = 0/11 = 0 → weight * 1.0 = base
        assert!(
            (eff_balanced - base).abs() < 1e-9,
            "balanced → weight unchanged: {eff_balanced}"
        );

        // More successes → effective weight above raw.
        let eff_success = link_effective_weight(base, 3, 0);
        assert!(
            eff_success > base,
            "success>failure → effective above base: {eff_success}"
        );

        // More failures → effective weight below raw.
        let eff_failure = link_effective_weight(base, 0, 3);
        assert!(
            eff_failure < base,
            "failure>success → effective below base: {eff_failure}"
        );

        // Never negative regardless of extreme failure counts.
        let eff_extreme = link_effective_weight(1.0, 0, 1_000_000);
        assert!(
            eff_extreme >= 0.0,
            "floored at zero: {eff_extreme}"
        );

        // All-success approaches weight * 2 as counts grow large.
        let eff_big_success = link_effective_weight(1.0, 10_000, 0);
        assert!(
            eff_big_success > 1.9,
            "large success count → near 2×: {eff_big_success}"
        );
    }

    /// `record_link_feedback` — bumps `feedback_success` on an existing link.
    #[test]
    fn record_link_feedback_increments_success_counter() {
        let (_d, c) = conn();
        reinforce_co_access(&c, &[1, 2], 1).unwrap(); // creates (1,2)

        let updated = record_link_feedback(&c, 1, 2, true).unwrap();
        assert!(updated, "existing link → returns true");

        let success: i64 = c
            .query_row(
                "SELECT feedback_success FROM idx_memory_links WHERE lo_id = 1 AND hi_id = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(success, 1, "feedback_success bumped to 1");

        let failure: i64 = c
            .query_row(
                "SELECT feedback_failure FROM idx_memory_links WHERE lo_id = 1 AND hi_id = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(failure, 0, "feedback_failure untouched");
    }

    /// `record_link_feedback` — bumps `feedback_failure` on an existing link.
    #[test]
    fn record_link_feedback_increments_failure_counter() {
        let (_d, c) = conn();
        reinforce_co_access(&c, &[3, 4], 1).unwrap(); // creates (3,4)

        let updated = record_link_feedback(&c, 4, 3, false).unwrap(); // reversed order → canonical
        assert!(updated, "existing link (reversed input) → returns true");

        let failure: i64 = c
            .query_row(
                "SELECT feedback_failure FROM idx_memory_links WHERE lo_id = 3 AND hi_id = 4",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(failure, 1, "feedback_failure bumped to 1");
    }

    /// `record_link_feedback` — returns false and creates NO row for unknown pair.
    #[test]
    fn record_link_feedback_returns_false_for_absent_link() {
        let (_d, c) = conn();
        // No links created at all.
        let updated = record_link_feedback(&c, 10, 20, true).unwrap();
        assert!(!updated, "absent link → false returned");

        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM idx_memory_links", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "no row created from feedback alone");
    }

    /// `record_link_feedback` — multiple calls accumulate independently on each counter.
    #[test]
    fn record_link_feedback_accumulates_on_repeat_calls() {
        let (_d, c) = conn();
        reinforce_co_access(&c, &[5, 6], 1).unwrap();

        record_link_feedback(&c, 5, 6, true).unwrap();
        record_link_feedback(&c, 5, 6, true).unwrap();
        record_link_feedback(&c, 5, 6, false).unwrap();

        let (s, f): (i64, i64) = c
            .query_row(
                "SELECT feedback_success, feedback_failure \
                 FROM idx_memory_links WHERE lo_id = 5 AND hi_id = 6",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(s, 2, "two success calls");
        assert_eq!(f, 1, "one failure call");
    }

    /// `associated` with positive feedback ranks the boosted link above the plain one.
    #[test]
    fn associated_ranks_feedback_boosted_link_higher() {
        let (_d, c) = conn();
        for id in [1i64, 2, 3] {
            seed_episode(&c, id);
        }
        // Create two links from node 1: (1,2) with weight 1.0 and (1,3) with weight 1.0.
        reinforce_co_access(&c, &[1, 2], 1).unwrap();
        reinforce_co_access(&c, &[1, 3], 2).unwrap();

        // Give (1,2) positive feedback → effective weight boosted above raw 1.0.
        // (1,3) stays at raw 1.0 effective (no feedback, correction = 0).
        record_link_feedback(&c, 1, 2, true).unwrap();

        let assoc = associated(&c, 1, 10).unwrap();
        assert_eq!(assoc.len(), 2);
        assert_eq!(assoc[0].0, 2, "node 2 (boosted by feedback) should rank first");
        assert!(
            assoc[0].1 > assoc[1].1,
            "boosted eff weight {:.4} must exceed raw eff weight {:.4}",
            assoc[0].1, assoc[1].1
        );
    }

    /// `associated` with negative feedback ranks the penalised link below the plain one.
    #[test]
    fn associated_ranks_feedback_penalised_link_lower() {
        let (_d, c) = conn();
        for id in [1i64, 2, 3] {
            seed_episode(&c, id);
        }
        reinforce_co_access(&c, &[1, 2], 1).unwrap();
        reinforce_co_access(&c, &[1, 3], 2).unwrap();

        // Give (1,2) negative feedback → effective weight drops below raw 1.0.
        record_link_feedback(&c, 1, 2, false).unwrap();

        let assoc = associated(&c, 1, 10).unwrap();
        assert_eq!(assoc.len(), 2);
        assert_eq!(
            assoc[0].0, 3,
            "node 3 (no feedback, higher eff weight) must rank first"
        );
        assert!(
            assoc[0].1 > assoc[1].1,
            "plain eff weight {:.4} must exceed penalised eff weight {:.4}",
            assoc[0].1, assoc[1].1
        );
    }
}
