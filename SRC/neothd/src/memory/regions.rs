//! M-08 (Session 24) — 6-region memory recall surface.
//!
//! NEOTH's brain metaphor partitions episodic memory into six
//! pseudo-anatomical regions, each tuned to a different event
//! shape. M-08 ships the recall surface that proves each region's
//! query works AND that the six cooperate (no event vanishes; no
//! event double-counts inside the same primary-region query).
//!
//! ## Region mapping (event-type bands)
//!
//! - **Hippocampus** — episodic memory + recall reinforcement.
//!   `0x01..=0x0F` (raw text / reinforce / turn-journal anchors) +
//!   `0x90..=0x9F` (memory tier ops).
//! - **Insula** — sensory in/out: every channel + MCP-toolcall
//!   surface. `0x30..=0x3F` (channels / ingress sanitizer).
//! - **Cerebellum** — procedural / orchestration: provider calls,
//!   council, kanban, MCP, plugins. `0x20..=0x2F` (provider) +
//!   `0x60..=0x6F` (council) + `0x70..=0x7F` (kanban) +
//!   `0xC0..=0xCF` (MCP / plugin).
//! - **BasalGanglia** — habits + reflexes: cron + hooks.
//!   `0x40..=0x4F` (cron) + `0x80..=0x8F` (hooks).
//! - **Hypothalamus** — drives + self-model: lifecycle (boot /
//!   shutdown / refusal / preset) + profile. `0x10..=0x1F` +
//!   `0xB0..=0xBF`.
//! - **Amygdala** — emotional salience. **Transverse overlay**: any
//!   event in ANY primary region with `importance >= 0.85` ALSO
//!   appears via Amygdala recall. Amygdala is never the
//!   primary-region classification for [`classify_region`] — calling
//!   it that would steal events from their structurally-correct
//!   region. Operators querying "what really mattered this week"
//!   ask the Amygdala helper directly.
//!
//! ## Coordination contract
//!
//! Pin via [`tests::six_regions_partition_every_event_type_band`]:
//! every primary region's event-type predicate is DISJOINT from
//! every other primary region. No event_type lands in two regions'
//! `event_type IN (...)` filters at once. Untagged bands (today
//! `0x00`, `0x50..=0x5F`, `0xA0..=0xAF`, `0xD0..=0xFF`) fall
//! through to [`MemoryRegion::Hippocampus`] as the operator-
//! visible default — preferable to silent drop because every
//! event the operator's grep finds reaches at least one region.
//!
//! ## Why no schema migration
//!
//! Adding a `region` column would require an indexer rewrite +
//! migration v11→v12. The CASE-over-`event_type` SQL covers the
//! same ground at no migration cost. The classifier helper lives
//! here so the recall + future GUI per-region surface agree on
//! the same mapping.

use std::collections::HashMap;

use anyhow::Result;
use rusqlite::{Connection, params};

use crate::memory::views::EpisodeHit;

/// Importance threshold above which a row counts as
/// "emotionally salient" and surfaces via Amygdala recall.
/// Drawn from the existing `tiers::PROMOTION_THRESHOLD` family
/// (0.65 promote / 0.85 amygdala / 1.0 max) so the operator sees
/// the same shoulder across the recall + consolidation surfaces.
pub const AMYGDALA_THRESHOLD: f64 = 0.85;

/// One of the six brain regions episodic memory partitions into.
/// See module docs for the band-to-region mapping. Variants are
/// `Copy`/`Eq`/`Hash` so the count-by-region helper can key into
/// a HashMap without owning a String.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRegion {
    Hippocampus,
    Amygdala,
    Insula,
    Cerebellum,
    BasalGanglia,
    Hypothalamus,
}

impl MemoryRegion {
    /// Stable wire form. Operators see this in `neoth memory
    /// --region <name>` + JSON output. Pinned by drift-guard test.
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryRegion::Hippocampus => "hippocampus",
            MemoryRegion::Amygdala => "amygdala",
            MemoryRegion::Insula => "insula",
            MemoryRegion::Cerebellum => "cerebellum",
            MemoryRegion::BasalGanglia => "basal_ganglia",
            MemoryRegion::Hypothalamus => "hypothalamus",
        }
    }

    /// Inverse of [`as_str`]. Case-insensitive, whitespace-trimmed.
    /// Returns `None` for unknown input — callers prompt the
    /// operator for one of the canonical names.
    pub fn parse(s: &str) -> Option<MemoryRegion> {
        match s.trim().to_lowercase().as_str() {
            "hippocampus" => Some(MemoryRegion::Hippocampus),
            "amygdala" => Some(MemoryRegion::Amygdala),
            "insula" => Some(MemoryRegion::Insula),
            "cerebellum" => Some(MemoryRegion::Cerebellum),
            "basal_ganglia" | "basal-ganglia" | "basalganglia" => Some(MemoryRegion::BasalGanglia),
            "hypothalamus" => Some(MemoryRegion::Hypothalamus),
            _ => None,
        }
    }

    /// All six variants in operator-visible order. Used by
    /// [`count_by_region`] + the CLI summary surface.
    pub fn all() -> [MemoryRegion; 6] {
        [
            MemoryRegion::Hippocampus,
            MemoryRegion::Amygdala,
            MemoryRegion::Insula,
            MemoryRegion::Cerebellum,
            MemoryRegion::BasalGanglia,
            MemoryRegion::Hypothalamus,
        ]
    }
}

/// Map a WAL `event_type` to its PRIMARY region. Amygdala is the
/// transverse salience overlay + is never the primary
/// classification — pure-event-type rows always belong to
/// exactly one of the other five regions. See module docs.
///
/// Untagged event types fall through to `Hippocampus` so the
/// operator's grep finds the row somewhere. Pre-rule "default to
/// Hippocampus" beats "default to None" because a missing region
/// = silent drop, which is worse than a misclassification the
/// operator can re-tag.
pub fn classify_region(event_type: u8) -> MemoryRegion {
    match event_type {
        // Hippocampus: episodic + memory ops
        0x01..=0x0F => MemoryRegion::Hippocampus,
        0x90..=0x9F => MemoryRegion::Hippocampus,
        // Hypothalamus: lifecycle (incl. refusal / preset) + profile
        0x10..=0x1F => MemoryRegion::Hypothalamus,
        0xB0..=0xBF => MemoryRegion::Hypothalamus,
        // Cerebellum: provider / council / kanban / MCP+plugin
        0x20..=0x2F => MemoryRegion::Cerebellum,
        0x60..=0x6F => MemoryRegion::Cerebellum,
        0x70..=0x7F => MemoryRegion::Cerebellum,
        0xC0..=0xCF => MemoryRegion::Cerebellum,
        // Insula: channels / ingress / egress
        0x30..=0x3F => MemoryRegion::Insula,
        // BasalGanglia: cron + hooks
        0x40..=0x4F => MemoryRegion::BasalGanglia,
        0x80..=0x8F => MemoryRegion::BasalGanglia,
        // Untagged bands fall back to Hippocampus default.
        _ => MemoryRegion::Hippocampus,
    }
}

/// SQL predicate for the WHERE clause that selects every event_type
/// belonging to `region`. Returns `("predicate", Vec<event_type>)`.
/// The predicate is a parameterised `event_type IN (?, ?, ...)`
/// fragment; the caller binds the byte vec.
///
/// Amygdala returns the special "importance overlay" predicate
/// because it's not an event-type partition — see [`recall_from_region`]
/// for how the caller dispatches Amygdala specially.
fn event_types_for_region(region: MemoryRegion) -> Vec<u8> {
    // Enumerate every u8 + filter by classify_region. Cheap
    // (256 calls; runs once per region query) and AUTOMATICALLY
    // stays in sync with classify_region — no second source of
    // truth to drift.
    (0u8..=255u8)
        .filter(|et| classify_region(*et) == region)
        .collect()
}

/// Recall rows from one region with a LIKE-substring query.
/// Mirrors the existing `cli::recall::recall_hot_like` shape so
/// the operator-visible result is consistent across recall
/// surfaces.
///
/// - For `Amygdala`: filters by `importance >= AMYGDALA_THRESHOLD`
///   regardless of event_type.
/// - For every other region: filters by `event_type IN
///   (...region's bands...)`.
///
/// Both branches also apply the LIKE `query` filter + `LIMIT
/// ?`. Returns hits sorted by `(importance DESC, ts_ns DESC)`
/// so the operator's most-salient + most-recent rows come first.
pub fn recall_from_region(
    conn: &Connection,
    region: MemoryRegion,
    query: &str,
    limit: usize,
) -> Result<Vec<EpisodeHit>> {
    // Escape LIKE wildcards so a query of `%`/`_` matches literally
    // (GOLD-SEC-04 / A-08); each LIKE pairs the pattern with ESCAPE '\'.
    let pattern = format!("%{}%", crate::memory::escape_like(query));
    let limit_i = limit as i64;
    let rows = match region {
        MemoryRegion::Amygdala => {
            let mut stmt = conn.prepare(
                "SELECT event_id, event_type, ts_ns, text, text_hash, \
                        channel, sender_id, operator_id, importance \
                 FROM idx_episode \
                 WHERE importance >= ?1 AND text COLLATE NOCASE LIKE ?2 ESCAPE '\\' \
                 ORDER BY importance DESC, ts_ns DESC \
                 LIMIT ?3",
            )?;
            stmt.query_map(params![AMYGDALA_THRESHOLD, pattern, limit_i], |r| {
                Ok(EpisodeHit {
                    event_id: r.get(0)?,
                    event_type: r.get::<_, i64>(1)? as u8,
                    ts_ns: r.get(2)?,
                    text: r.get(3)?,
                    text_hash: r.get(4)?,
                    channel: r.get(5)?,
                    sender_id: r.get(6)?,
                    operator_id: r.get(7)?,
                    tier: "hot".to_string(),
                    importance: Some(r.get::<_, f64>(8)?),
                    access_count: 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        }
        primary => {
            let types = event_types_for_region(primary);
            // Build the placeholder list — `?2,?3,?4,...` after the
            // `?1` LIKE binding. Final `?N` is the LIMIT binding.
            let mut placeholders = Vec::with_capacity(types.len());
            for i in 0..types.len() {
                placeholders.push(format!("?{}", i + 2));
            }
            let limit_idx = types.len() + 2;
            let sql = format!(
                "SELECT event_id, event_type, ts_ns, text, text_hash, \
                        channel, sender_id, operator_id, importance \
                 FROM idx_episode \
                 WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                   AND event_type IN ({}) \
                 ORDER BY importance DESC, ts_ns DESC \
                 LIMIT ?{}",
                placeholders.join(","),
                limit_idx,
            );
            let mut stmt = conn.prepare(&sql)?;
            // Bind: ?1 = pattern, ?2..?N = event types, ?LIMIT = limit.
            let mut binds: Vec<rusqlite::types::Value> = Vec::with_capacity(types.len() + 2);
            binds.push(pattern.clone().into());
            for et in &types {
                binds.push((*et as i64).into());
            }
            binds.push(limit_i.into());
            let bind_refs: Vec<&dyn rusqlite::ToSql> =
                binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
            stmt.query_map(rusqlite::params_from_iter(bind_refs.iter().copied()), |r| {
                Ok(EpisodeHit {
                    event_id: r.get(0)?,
                    event_type: r.get::<_, i64>(1)? as u8,
                    ts_ns: r.get(2)?,
                    text: r.get(3)?,
                    text_hash: r.get(4)?,
                    channel: r.get(5)?,
                    sender_id: r.get(6)?,
                    operator_id: r.get(7)?,
                    tier: "hot".to_string(),
                    importance: r.get::<_, Option<f64>>(8)?,
                    access_count: 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        }
    };
    Ok(rows)
}

/// Count `idx_episode` rows per region. Operator-facing summary +
/// drift-guard fodder for the M-08 cooperation tests. Amygdala
/// row count is a SEPARATE summed total (importance overlay) — the
/// other five sum to the total row count exactly.
pub fn count_by_region(conn: &Connection) -> Result<HashMap<MemoryRegion, i64>> {
    let mut out: HashMap<MemoryRegion, i64> = HashMap::new();
    for region in MemoryRegion::all() {
        let count = match region {
            MemoryRegion::Amygdala => conn.query_row(
                "SELECT count(*) FROM idx_episode WHERE importance >= ?1",
                params![AMYGDALA_THRESHOLD],
                |r| r.get::<_, i64>(0),
            )?,
            primary => {
                let types = event_types_for_region(primary);
                let placeholders: Vec<String> =
                    (1..=types.len()).map(|i| format!("?{i}")).collect();
                let sql = format!(
                    "SELECT count(*) FROM idx_episode WHERE event_type IN ({})",
                    placeholders.join(","),
                );
                let binds: Vec<rusqlite::types::Value> =
                    types.iter().map(|et| (*et as i64).into()).collect();
                let bind_refs: Vec<&dyn rusqlite::ToSql> =
                    binds.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                conn.query_row(
                    &sql,
                    rusqlite::params_from_iter(bind_refs.iter().copied()),
                    |r| r.get::<_, i64>(0),
                )?
            }
        };
        out.insert(region, count);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;

    // ── Region classifier: drift guards ───────────────────────────────

    #[test]
    fn region_as_str_pinned_for_audit() {
        assert_eq!(MemoryRegion::Hippocampus.as_str(), "hippocampus");
        assert_eq!(MemoryRegion::Amygdala.as_str(), "amygdala");
        assert_eq!(MemoryRegion::Insula.as_str(), "insula");
        assert_eq!(MemoryRegion::Cerebellum.as_str(), "cerebellum");
        assert_eq!(MemoryRegion::BasalGanglia.as_str(), "basal_ganglia");
        assert_eq!(MemoryRegion::Hypothalamus.as_str(), "hypothalamus");
    }

    #[test]
    fn region_parse_accepts_canonical_plus_basal_ganglia_aliases() {
        for r in MemoryRegion::all() {
            assert_eq!(MemoryRegion::parse(r.as_str()), Some(r));
            assert_eq!(MemoryRegion::parse(&r.as_str().to_uppercase()), Some(r));
        }
        // basal_ganglia accepts the hyphen + no-separator variant.
        assert_eq!(
            MemoryRegion::parse("basal-ganglia"),
            Some(MemoryRegion::BasalGanglia)
        );
        assert_eq!(
            MemoryRegion::parse("basalganglia"),
            Some(MemoryRegion::BasalGanglia)
        );
        assert!(MemoryRegion::parse("nope").is_none());
        assert!(MemoryRegion::parse("").is_none());
    }

    #[test]
    fn classify_region_pins_each_band_to_expected_region() {
        // Hippocampus: 0x01..0x0F + 0x90..0x9F
        assert_eq!(classify_region(0x01), MemoryRegion::Hippocampus);
        assert_eq!(classify_region(0x05), MemoryRegion::Hippocampus);
        assert_eq!(classify_region(0x93), MemoryRegion::Hippocampus);
        // Hypothalamus: 0x10..0x1F + 0xB0..0xBF
        assert_eq!(classify_region(0x10), MemoryRegion::Hypothalamus);
        assert_eq!(classify_region(0x16), MemoryRegion::Hypothalamus);
        assert_eq!(classify_region(0xB5), MemoryRegion::Hypothalamus);
        // Cerebellum: 0x20..0x2F + 0x60..0x6F + 0x70..0x7F + 0xC0..0xCF
        assert_eq!(classify_region(0x20), MemoryRegion::Cerebellum);
        assert_eq!(classify_region(0x65), MemoryRegion::Cerebellum);
        assert_eq!(classify_region(0x70), MemoryRegion::Cerebellum);
        assert_eq!(classify_region(0xC4), MemoryRegion::Cerebellum);
        // Insula: 0x30..0x3F
        assert_eq!(classify_region(0x32), MemoryRegion::Insula);
        // BasalGanglia: 0x40..0x4F + 0x80..0x8F
        assert_eq!(classify_region(0x41), MemoryRegion::BasalGanglia);
        assert_eq!(classify_region(0x83), MemoryRegion::BasalGanglia);
    }

    #[test]
    fn six_regions_partition_every_event_type_band() {
        // Coordination contract pin: every event_type (0..=255)
        // classifies to EXACTLY ONE primary region (Amygdala is
        // never primary — it's a transverse overlay). No event
        // double-counts; none vanishes.
        let mut tally: HashMap<MemoryRegion, usize> = HashMap::new();
        for et in 0u8..=255u8 {
            let region = classify_region(et);
            assert_ne!(
                region,
                MemoryRegion::Amygdala,
                "event_type 0x{et:02X} must NOT classify as Amygdala primary",
            );
            *tally.entry(region).or_insert(0) += 1;
        }
        // Sanity: every primary region gets at least one event type
        // (catches a regression that collapses two bands into one
        // region by accident).
        for region in [
            MemoryRegion::Hippocampus,
            MemoryRegion::Insula,
            MemoryRegion::Cerebellum,
            MemoryRegion::BasalGanglia,
            MemoryRegion::Hypothalamus,
        ] {
            let count = tally.get(&region).copied().unwrap_or(0);
            assert!(
                count > 0,
                "region {region:?} must own ≥1 event_type band, got {count}",
            );
        }
        // Sum check: every u8 gets classified somewhere.
        let total: usize = tally.values().sum();
        assert_eq!(total, 256);
    }

    #[test]
    fn untagged_event_type_falls_through_to_hippocampus() {
        // The default-Hippocampus rule: 0x00 + the unclaimed bands
        // (0x50..0x5F / 0xA0..0xAF / 0xD0..0xFF) all reach
        // Hippocampus. Pin so a future band reclassification
        // doesn't silently drop the operator's grep.
        for et in [0x00u8, 0x50, 0x5A, 0xA0, 0xAF, 0xD0, 0xE0, 0xFF] {
            assert_eq!(
                classify_region(et),
                MemoryRegion::Hippocampus,
                "0x{et:02X} must fall through to Hippocampus",
            );
        }
    }

    // ── recall_from_region + count_by_region: behavioural pins ────────

    fn open() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("v.db");
        let conn = store::open(&db).unwrap();
        (dir, conn)
    }

    fn seed(conn: &Connection, event_id: i64, event_type: u8, text: &str, importance: f64) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?3)",
            params![
                event_id,
                event_type as i64,
                event_id,
                text,
                format!("h{event_id}"),
                importance
            ],
        )
        .unwrap();
    }

    #[test]
    fn recall_from_each_primary_region_returns_only_its_event_types() {
        let (_dir, conn) = open();
        // Seed one event in each primary region's canonical band +
        // tag with a common keyword so the LIKE matches all.
        seed(&conn, 1, 0x01, "shared keyword hippo", 0.5);
        seed(&conn, 2, 0x32, "shared keyword insula", 0.5);
        seed(&conn, 3, 0x65, "shared keyword cerebellum", 0.5);
        seed(&conn, 4, 0x41, "shared keyword basal", 0.5);
        seed(&conn, 5, 0x10, "shared keyword hypothalamus", 0.5);

        for (region, marker) in [
            (MemoryRegion::Hippocampus, "hippo"),
            (MemoryRegion::Insula, "insula"),
            (MemoryRegion::Cerebellum, "cerebellum"),
            (MemoryRegion::BasalGanglia, "basal"),
            (MemoryRegion::Hypothalamus, "hypothalamus"),
        ] {
            let hits = recall_from_region(&conn, region, "shared keyword", 10).unwrap();
            assert_eq!(
                hits.len(),
                1,
                "region {region:?} must return exactly 1 row (got {})",
                hits.len(),
            );
            assert!(
                hits[0].text.contains(marker),
                "region {region:?} returned wrong row: text={:?}",
                hits[0].text,
            );
        }
    }

    #[test]
    fn amygdala_returns_high_importance_rows_regardless_of_event_type() {
        let (_dir, conn) = open();
        // Mix of low + high importance across multiple regions.
        seed(&conn, 1, 0x01, "low importance hippo", 0.1);
        seed(&conn, 2, 0x32, "high importance insula", 0.95);
        seed(&conn, 3, 0x65, "high importance cerebellum", 0.90);
        seed(&conn, 4, 0x41, "low importance basal", 0.5);
        seed(&conn, 5, 0x10, "very high importance hypo", 0.99);

        let hits = recall_from_region(&conn, MemoryRegion::Amygdala, "importance", 10).unwrap();
        assert_eq!(hits.len(), 3, "exactly 3 rows above AMYGDALA_THRESHOLD");
        // Sorted by importance DESC.
        let imps: Vec<f64> = hits.iter().map(|h| h.importance.unwrap_or(0.0)).collect();
        for w in imps.windows(2) {
            assert!(
                w[0] >= w[1],
                "amygdala results must sort by importance DESC"
            );
        }
    }

    #[test]
    fn count_by_region_partitions_rows_correctly() {
        let (_dir, conn) = open();
        seed(&conn, 1, 0x01, "a", 0.5); // Hippocampus
        seed(&conn, 2, 0x01, "b", 0.95); // Hippocampus + Amygdala (overlay)
        seed(&conn, 3, 0x32, "c", 0.5); // Insula
        seed(&conn, 4, 0x65, "d", 0.5); // Cerebellum
        seed(&conn, 5, 0x41, "e", 0.95); // BasalGanglia + Amygdala (overlay)
        seed(&conn, 6, 0x10, "f", 0.5); // Hypothalamus

        let counts = count_by_region(&conn).unwrap();
        assert_eq!(counts[&MemoryRegion::Hippocampus], 2);
        assert_eq!(counts[&MemoryRegion::Insula], 1);
        assert_eq!(counts[&MemoryRegion::Cerebellum], 1);
        assert_eq!(counts[&MemoryRegion::BasalGanglia], 1);
        assert_eq!(counts[&MemoryRegion::Hypothalamus], 1);
        // Amygdala overlay catches both 0.95s regardless of primary region.
        assert_eq!(counts[&MemoryRegion::Amygdala], 2);

        // Cooperation contract: the 5 primary regions sum to the
        // total row count exactly (Amygdala is transverse + double-
        // counted by design — see module docs).
        let primary_sum = counts[&MemoryRegion::Hippocampus]
            + counts[&MemoryRegion::Insula]
            + counts[&MemoryRegion::Cerebellum]
            + counts[&MemoryRegion::BasalGanglia]
            + counts[&MemoryRegion::Hypothalamus];
        let total: i64 = conn
            .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            primary_sum, total,
            "5 primary regions must sum to total rows (transverse Amygdala is double-counted)",
        );
    }

    #[test]
    fn recall_respects_limit_and_sort_order() {
        let (_dir, conn) = open();
        // Three Hippocampus events with distinct importance values.
        seed(&conn, 1, 0x01, "alpha", 0.5);
        seed(&conn, 2, 0x01, "alpha medium", 0.7);
        seed(&conn, 3, 0x01, "alpha top", 0.9);

        let hits = recall_from_region(&conn, MemoryRegion::Hippocampus, "alpha", 2).unwrap();
        assert_eq!(hits.len(), 2, "limit=2 must cap");
        // Sorted by importance DESC: top → medium.
        assert!(hits[0].text.contains("top"), "got {:?}", hits[0].text);
        assert!(hits[1].text.contains("medium"), "got {:?}", hits[1].text);
    }

    #[test]
    fn empty_region_returns_no_rows_no_error() {
        let (_dir, conn) = open();
        // Seed only Hippocampus; query Insula → empty result, no error.
        seed(&conn, 1, 0x01, "only hippo", 0.5);
        let hits = recall_from_region(&conn, MemoryRegion::Insula, "only", 10).unwrap();
        assert!(hits.is_empty());
    }
}
