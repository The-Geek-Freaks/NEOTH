//! GOLD-ADAPT-MEM-06 — knowledge-graph layer (entities + relations).
//!
//! NEOTH's recall has been flat (FTS5 + HNSW) with no structural knowledge
//! representation. This adds the one real gap: a typed-entity / weighted-
//! directed-relation store with bounded BFS neighbour expansion, so a query
//! about "Alice" can surface "Mozilla" via a 1-hop `works_at` edge.
//!
//! This slice ships the **persistence + query** layer (schema in
//! `store.rs`, this module, the `neoth recall --graph` consumer, and the
//! `forget` cascade). The LLM entity/relation **extraction at ingest** + the
//! additive recall Stage-3 score-blend land in a later slice. Pure SQL — no
//! `petgraph` dependency needed for depth-bounded BFS.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

/// A stored entity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entity {
    pub id: i64,
    pub name: String,
    pub entity_type: String,
    /// How many sightings created/reinforced this entity — the MEM-14
    /// credibility signal (more independent sources ⇒ more trustworthy).
    pub source_count: i64,
    /// Merged attribute facts as a JSON object string, e.g.
    /// `{"role":"engineer","city":"Berlin"}` (MEM-14 attribute merge).
    pub attributes: String,
}

/// One node reached during neighbour expansion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub id: i64,
    pub name: String,
    /// Hops from the start entity (1 = direct).
    pub depth: u32,
    /// The relation label of the edge that first reached this node.
    pub via_relation: String,
    /// The reached entity's `source_count` — neighbours are ordered by depth
    /// then DESCENDING source_count, so the most-corroborated facts surface
    /// first (MEM-14 credibility).
    pub source_count: i64,
}

/// Resolve an entity id by exact (case-insensitive) name.
pub fn resolve_entity_id(conn: &Connection, name: &str) -> Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM idx_entities WHERE name = ?1 COLLATE NOCASE",
        params![name.trim()],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .context("resolve entity id")
}

/// Merge `new` attribute facts into an existing `{...}` JSON attributes string
/// (overlay: new keys add, existing keys are overwritten with the latest value).
/// Invalid stored JSON is an error: treating it as empty would erase evidence
/// on the next merge. Returns a sorted-key JSON object string.
pub(crate) fn merge_attributes(
    existing_json: &str,
    new: &BTreeMap<String, String>,
) -> Result<String> {
    let mut merged: BTreeMap<String, String> =
        serde_json::from_str(existing_json).context("parse stored entity attributes")?;
    for (k, v) in new {
        merged.insert(k.clone(), v.clone());
    }
    serde_json::to_string(&merged).context("serialize merged entity attributes")
}

/// Insert the entity if absent (with `attrs` as its initial attributes), else
/// bump its `source_count` + `last_seen` AND overlay `attrs` onto its stored
/// attributes (MEM-14 dedup + attribute merge + credibility). Returns the id.
pub fn resolve_or_create_entity_with_attrs(
    conn: &Connection,
    name: &str,
    entity_type: &str,
    attrs: &BTreeMap<String, String>,
    now_unix: i64,
) -> Result<i64> {
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("entity name must be non-empty");
    }
    if let Some(id) = resolve_entity_id(conn, name)? {
        // Attribute merge: overlay any new attribute facts onto the stored set.
        if !attrs.is_empty() {
            let existing: String = conn
                .query_row(
                    "SELECT attributes FROM idx_entities WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .context("load stored entity attributes")?;
            let merged = merge_attributes(&existing, attrs)?;
            conn.execute(
                "UPDATE idx_entities SET source_count = source_count + 1, last_seen = ?2, \
                 attributes = ?3 WHERE id = ?1",
                params![id, now_unix, merged],
            )
            .context("merge entity attributes")?;
        } else {
            conn.execute(
                "UPDATE idx_entities SET source_count = source_count + 1, last_seen = ?2 WHERE id = ?1",
                params![id, now_unix],
            )
            .context("bump entity source_count")?;
        }
        return Ok(id);
    }
    let attrs_json = merge_attributes("{}", attrs)?;
    conn.execute(
        "INSERT INTO idx_entities (name, entity_type, attributes, first_seen, last_seen) \
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![name, entity_type, attrs_json, now_unix],
    )
    .context("insert entity")?;
    Ok(conn.last_insert_rowid())
}

/// [`resolve_or_create_entity_with_attrs`] with no attributes — for relation
/// endpoints and callers that only need the id (the dedup/credibility signal
/// MEM-14 builds on). Returns the entity id.
pub fn resolve_or_create_entity(
    conn: &Connection,
    name: &str,
    entity_type: &str,
    now_unix: i64,
) -> Result<i64> {
    resolve_or_create_entity_with_attrs(conn, name, entity_type, &BTreeMap::new(), now_unix)
}

/// Fetch a single entity by (case-insensitive) name with its merged
/// `attributes` + `source_count` credibility. `None` when unknown. Powers the
/// `neoth recall --graph` header line (MEM-14).
pub fn get_entity(conn: &Connection, name: &str) -> Result<Option<Entity>> {
    conn.query_row(
        "SELECT id, name, entity_type, source_count, attributes \
         FROM idx_entities WHERE name = ?1 COLLATE NOCASE",
        params![name.trim()],
        |r| {
            Ok(Entity {
                id: r.get(0)?,
                name: r.get(1)?,
                entity_type: r.get(2)?,
                source_count: r.get(3)?,
                attributes: r.get(4)?,
            })
        },
    )
    .optional()
    .context("get entity")
}

/// Every entity in the index, most-corroborated first. Backs the OKF knowledge
/// export (`cli::okf`) — one concept document per entity.
pub fn list_all(conn: &Connection) -> Result<Vec<Entity>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, entity_type, source_count, attributes \
         FROM idx_entities ORDER BY source_count DESC, name ASC",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok(Entity {
                id: r.get(0)?,
                name: r.get(1)?,
                entity_type: r.get(2)?,
                source_count: r.get(3)?,
                attributes: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Insert (or reinforce) a directed relation `src --relation--> dst`.
///
/// On conflict the behaviour depends on `valid_to`:
/// - If the existing row is **active** (`valid_to IS NULL`): bump `weight`
///   (co-occurrence reinforcement).
/// - If the existing row is **closed** (`valid_to IS NOT NULL`): re-open it
///   (reset `valid_to = NULL`) and set `weight = ?4` fresh — a superseded
///   relation corroborated anew by a subsequent extraction becomes active
///   again rather than silently accumulating weight on a closed edge.
///
/// The `WHERE idx_relations.valid_to IS NULL` clause on the DO UPDATE is
/// SQLite-supported (partial ON CONFLICT target). When the row is closed
/// the DO UPDATE guard fails and the conflict falls through to a plain
/// INSERT — but UNIQUE prevents a second row. We therefore handle the
/// re-open case in a separate follow-up UPDATE after the initial upsert.
pub fn insert_relation(
    conn: &Connection,
    src_id: i64,
    dst_id: i64,
    relation: &str,
    weight: f64,
) -> Result<()> {
    // Attempt to INSERT. If the triple exists and is ACTIVE, bump weight.
    // If the triple exists and is CLOSED, the DO UPDATE guard (valid_to IS NULL)
    // fails, so the INSERT is silently ignored — we then re-open it below.
    conn.execute(
        "INSERT INTO idx_relations (src_id, dst_id, relation, weight) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(src_id, dst_id, relation) DO UPDATE \
         SET weight = weight + ?4 WHERE idx_relations.valid_to IS NULL",
        params![src_id, dst_id, relation, weight],
    )
    .context("insert relation")?;
    // Re-open a closed relation that a new extraction re-asserts.
    conn.execute(
        "UPDATE idx_relations SET valid_to = NULL, weight = ?4 \
         WHERE src_id = ?1 AND dst_id = ?2 AND relation = ?3 AND valid_to IS NOT NULL",
        params![src_id, dst_id, relation, weight],
    )
    .context("reopen closed relation")?;
    Ok(())
}

/// Close an active relation triple by stamping `valid_to`.
///
/// Sets `valid_to = ended_ts.to_string()` (Unix nanoseconds as a decimal
/// string) on the row `(src_id, dst_id, relation)` **only when it is
/// currently active** (`valid_to IS NULL`). Returns `Ok(true)` when a row
/// was actually closed, `Ok(false)` when the relation did not exist or was
/// already closed (idempotent — safe to call multiple times).
///
/// Called by `invalidate_relation_by_names` (the public name-based API)
/// and directly from tests.
pub fn invalidate_relation(
    conn: &Connection,
    src_id: i64,
    dst_id: i64,
    relation: &str,
    ended_ts: i64,
) -> Result<bool> {
    let n = conn
        .execute(
            "UPDATE idx_relations SET valid_to = ?1 \
             WHERE src_id = ?2 AND dst_id = ?3 AND relation = ?4 AND valid_to IS NULL",
            params![ended_ts.to_string(), src_id, dst_id, relation],
        )
        .context("invalidate relation")?;
    Ok(n > 0)
}

/// Name-based wrapper for [`invalidate_relation`].
///
/// Resolves `subject` and `object` to entity ids via case-insensitive lookup.
/// Returns `Ok(false)` if either name is unknown (the entities may not yet
/// exist in the graph). When `relation` is `"*"` the function closes **every**
/// active edge between the two entities regardless of the relation label
/// (wildcard close — used when the contradiction detector cannot parse a
/// specific predicate from the statement).
///
/// Best-effort: callers treat errors as non-fatal (log-and-ignore). This
/// mirrors the non-fatal pattern already used for contradiction scan
/// failures in `groundtruth::insert`.
pub fn invalidate_relation_by_names(
    conn: &Connection,
    subject: &str,
    predicate: &str,
    object: &str,
    ended_ts: i64,
) -> Result<bool> {
    let Some(src_id) = resolve_entity_id(conn, subject)? else {
        return Ok(false);
    };
    let Some(dst_id) = resolve_entity_id(conn, object)? else {
        return Ok(false);
    };
    if predicate == "*" {
        // Wildcard: close every active edge between the two entities.
        let n = conn
            .execute(
                "UPDATE idx_relations SET valid_to = ?1 \
                 WHERE src_id = ?2 AND dst_id = ?3 AND valid_to IS NULL",
                params![ended_ts.to_string(), src_id, dst_id],
            )
            .context("invalidate all relations between entities")?;
        Ok(n > 0)
    } else {
        invalidate_relation(conn, src_id, dst_id, predicate, ended_ts)
    }
}

/// Direct (1-hop) neighbours of `id`, both out- and in-edges, as
/// `(other_id, relation)`. Only **active** edges (`valid_to IS NULL`) are
/// returned — superseded/invalidated edges are invisible to BFS.
fn one_hop(conn: &Connection, id: i64) -> Result<Vec<(i64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT dst_id, relation FROM idx_relations \
         WHERE src_id = ?1 AND valid_to IS NULL \
         UNION \
         SELECT src_id, relation FROM idx_relations \
         WHERE dst_id = ?1 AND valid_to IS NULL",
    )?;
    let rows = stmt.query_map(params![id], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("collect one-hop entity relations")
}

/// Bounded breadth-first expansion from the entity named `name`: returns every
/// reachable entity within `max_depth` hops (deduped, nearest-depth wins),
/// ordered by depth then name. Empty when the start entity is unknown.
pub fn get_neighbors(conn: &Connection, name: &str, max_depth: u32) -> Result<Vec<Neighbor>> {
    let Some(start) = resolve_entity_id(conn, name)? else {
        return Ok(Vec::new());
    };
    use std::collections::{HashSet, VecDeque};
    let mut seen: HashSet<i64> = HashSet::from([start]);
    let mut out: Vec<Neighbor> = Vec::new();
    let mut queue: VecDeque<(i64, u32)> = VecDeque::from([(start, 0u32)]);
    while let Some((id, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        for (other, relation) in one_hop(conn, id)? {
            if seen.insert(other) {
                queue.push_back((other, depth + 1));
                // Resolve the name + credibility lazily.
                let row: Option<(String, i64)> = conn
                    .query_row(
                        "SELECT name, source_count FROM idx_entities WHERE id = ?1",
                        params![other],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                if let Some((nm, source_count)) = row {
                    out.push(Neighbor {
                        id: other,
                        name: nm,
                        depth: depth + 1,
                        via_relation: relation,
                        source_count,
                    });
                }
            }
        }
    }
    // Nearest first, then most-corroborated (DESC source_count), then name.
    out.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then_with(|| b.source_count.cmp(&a.source_count))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(out)
}

/// GDPR `forget` cascade: delete entities whose name matches `like_pattern`
/// (a `LIKE` with `\` escape) + every relation touching a deleted entity.
/// Returns `(entities_deleted, relations_deleted)`.
pub fn forget_entities_like(conn: &Connection, like_pattern: &str) -> Result<(i64, i64)> {
    let victim_ids: Vec<i64> = {
        // GDPR (F68): match the topic in BOTH the entity name AND its attribute
        // values — a topic stored only as an attribute value (e.g. an entity
        // "Alice" with attributes {"employer":"AcmeCorp"}) must also be erased,
        // mirroring idx_profile's `field … OR value_json …` match in forget.rs.
        let mut stmt = conn.prepare(
            "SELECT id FROM idx_entities \
             WHERE name COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                OR attributes COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        )?;
        let rows = stmt.query_map(params![like_pattern], |r| r.get::<_, i64>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("collect entity ids for forget cascade")?
    };
    if victim_ids.is_empty() {
        return Ok((0, 0));
    }
    let placeholders = victim_ids
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let rels = conn.execute(
        &format!("DELETE FROM idx_relations WHERE src_id IN ({placeholders}) OR dst_id IN ({placeholders})"),
        rusqlite::params_from_iter(victim_ids.iter().chain(victim_ids.iter()).copied()),
    )? as i64;
    let ents = conn.execute(
        &format!("DELETE FROM idx_entities WHERE id IN ({placeholders})"),
        rusqlite::params_from_iter(victim_ids.iter().copied()),
    )? as i64;
    Ok((ents, rels))
}

/// One extracted entity: name, type, and any attribute facts stated about it
/// (`{"role":"engineer"}` …) — merged into the stored entity on each sighting
/// (MEM-14).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntityFact {
    pub name: String,
    pub etype: String,
    pub attributes: BTreeMap<String, String>,
}

/// LLM extraction result: typed entities + directed relations (relation
/// endpoints are entity NAMES, resolved to ids at persist time).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extraction {
    pub entities: Vec<EntityFact>,
    /// `(src_name, relation, dst_name)`.
    pub relations: Vec<(String, String, String)>,
}

const EXTRACTION_SYSTEM: &str = "You are a precise knowledge-graph extractor. Output STRICT JSON only — no prose, \
     no markdown fences. Extract ONLY entities + relations explicitly stated in the text.";

/// Build the extraction prompt. Pure — testable without a provider.
pub fn build_extraction_prompt(text: &str) -> String {
    format!(
        "Extract entities and relations from the TEXT as JSON of exactly this shape:\n\
         {{\"entities\":[{{\"name\":\"...\",\"type\":\"person|org|place|concept|thing\",\"attributes\":{{\"<key>\":\"<value>\"}}}}],\
         \"relations\":[{{\"src\":\"<entity name>\",\"relation\":\"<short verb phrase>\",\"dst\":\"<entity name>\"}}]}}\n\
         Rules: only entities/relations explicitly present; `attributes` is OPTIONAL — short factual key/value pairs about the entity (role, location, …), omit or leave {{}} if none; relation endpoints must be entity names from the entities list; JSON only.\n\nTEXT:\n{text}"
    )
}

/// Slice out the outermost `{...}` JSON object (tolerates markdown fences or
/// chatter around it).
fn extract_json_object(s: &str) -> Option<&str> {
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    (end > start).then(|| &s[start..=end])
}

/// Parse a provider's extraction response into an [`Extraction`]. Pure —
/// tested directly. Empty/whitespace names are dropped; a missing type
/// defaults to `unknown`.
pub fn parse_extraction(response: &str) -> Result<Extraction> {
    #[derive(serde::Deserialize)]
    struct RawEnt {
        name: String,
        #[serde(default)]
        r#type: String,
        #[serde(default)]
        attributes: serde_json::Map<String, serde_json::Value>,
    }
    #[derive(serde::Deserialize)]
    struct RawRel {
        src: String,
        relation: String,
        dst: String,
    }
    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(default)]
        entities: Vec<RawEnt>,
        #[serde(default)]
        relations: Vec<RawRel>,
    }
    let json = extract_json_object(response)
        .context("entity-extraction response contained no JSON object")?;
    let raw: Raw = serde_json::from_str(json).context("parse entity-extraction JSON")?;
    let entities = raw
        .entities
        .into_iter()
        .filter(|e| !e.name.trim().is_empty())
        .map(|e| {
            let ty = e.r#type.trim();
            // Normalise attributes to non-empty string key/values (numbers →
            // their text form, nulls/empties dropped) so the merge stays JSON
            // string→string.
            let attributes = e
                .attributes
                .into_iter()
                .filter_map(|(k, v)| {
                    let key = k.trim();
                    if key.is_empty() {
                        return None;
                    }
                    let val = match v {
                        serde_json::Value::String(s) => s.trim().to_string(),
                        serde_json::Value::Null => return None,
                        other => other.to_string(),
                    };
                    (!val.is_empty()).then(|| (key.to_string(), val))
                })
                .collect();
            EntityFact {
                name: e.name.trim().to_string(),
                etype: if ty.is_empty() {
                    "unknown".to_string()
                } else {
                    ty.to_string()
                },
                attributes,
            }
        })
        .collect();
    let relations = raw
        .relations
        .into_iter()
        .filter(|r| {
            !r.src.trim().is_empty() && !r.dst.trim().is_empty() && !r.relation.trim().is_empty()
        })
        .map(|r| {
            (
                r.src.trim().to_string(),
                r.relation.trim().to_string(),
                r.dst.trim().to_string(),
            )
        })
        .collect();
    Ok(Extraction {
        entities,
        relations,
    })
}

/// Run the LLM extraction for `text` through `provider`. Sampling-capable
/// providers receive temperature 0 as a determinism hint; incompatible leaves
/// omit it with a warning. Returns the parsed [`Extraction`].
pub async fn entity_extract(
    text: &str,
    provider: &dyn crate::providers::Provider,
) -> Result<Extraction> {
    let temperature =
        crate::providers::internal_temperature(provider, 0.0, "memory.entity_extract");
    let req = crate::providers::Request {
        prompt: build_extraction_prompt(text),
        system: Some(EXTRACTION_SYSTEM.to_string()),
        temperature,
        ..Default::default()
    };
    let completion = provider
        .complete(req)
        .await
        .context("entity-extraction provider call")?;
    parse_extraction(&completion.text)
}

/// Persist an [`Extraction`]: resolve/create every entity, then insert each
/// relation (auto-creating any endpoint entity the entities list omitted).
/// Returns `(entities_seen, relations_inserted)`.
pub fn persist_extraction(
    conn: &Connection,
    ex: &Extraction,
    now_unix: i64,
) -> Result<(usize, usize)> {
    use std::collections::HashMap;
    let mut ids: HashMap<String, i64> = HashMap::new();
    for ef in &ex.entities {
        let id = resolve_or_create_entity_with_attrs(
            conn,
            &ef.name,
            &ef.etype,
            &ef.attributes,
            now_unix,
        )?;
        ids.insert(ef.name.to_lowercase(), id);
    }
    let mut rels = 0usize;
    for (src, relation, dst) in &ex.relations {
        let src_id = ensure_entity(conn, &mut ids, src, now_unix)?;
        let dst_id = ensure_entity(conn, &mut ids, dst, now_unix)?;
        insert_relation(conn, src_id, dst_id, relation, 1.0)?;
        rels += 1;
    }
    Ok((ex.entities.len(), rels))
}

fn ensure_entity(
    conn: &Connection,
    ids: &mut std::collections::HashMap<String, i64>,
    name: &str,
    now_unix: i64,
) -> Result<i64> {
    let key = name.to_lowercase();
    if let Some(id) = ids.get(&key) {
        return Ok(*id);
    }
    let id = resolve_or_create_entity(conn, name, "unknown", now_unix)?;
    ids.insert(key, id);
    Ok(id)
}

/// Extract from `text` via `provider` and persist in one call. The ingest +
/// `neoth recall --extract` consumers use this.
pub async fn extract_and_persist(
    conn: &Connection,
    text: &str,
    provider: &dyn crate::providers::Provider,
    now_unix: i64,
) -> Result<(usize, usize)> {
    let ex = entity_extract(text, provider).await?;
    persist_extraction(conn, &ex, now_unix)
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

    #[test]
    fn resolve_or_create_dedups_and_counts() {
        let (_d, c) = conn();
        let a1 = resolve_or_create_entity(&c, "Alice", "person", 100).unwrap();
        let a2 = resolve_or_create_entity(&c, "alice", "person", 200).unwrap(); // case-insensitive
        assert_eq!(a1, a2, "same entity");
        let sc: i64 = c
            .query_row(
                "SELECT source_count FROM idx_entities WHERE id = ?1",
                params![a1],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sc, 2, "source_count bumped on re-resolve");
        assert!(resolve_or_create_entity(&c, "  ", "x", 1).is_err());
    }

    #[test]
    fn one_hop_neighbour_surfaces_via_relation() {
        let (_d, c) = conn();
        let alice = resolve_or_create_entity(&c, "Alice", "person", 1).unwrap();
        let moz = resolve_or_create_entity(&c, "Mozilla", "org", 1).unwrap();
        insert_relation(&c, alice, moz, "works_at", 1.0).unwrap();
        let n = get_neighbors(&c, "Alice", 1).unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].name, "Mozilla");
        assert_eq!(n[0].depth, 1);
        assert_eq!(n[0].via_relation, "works_at");
        // The edge is bidirectional in BFS: querying Mozilla reaches Alice.
        assert_eq!(get_neighbors(&c, "Mozilla", 1).unwrap()[0].name, "Alice");
    }

    #[test]
    fn bfs_respects_depth_bound() {
        let (_d, c) = conn();
        let a = resolve_or_create_entity(&c, "A", "x", 1).unwrap();
        let b = resolve_or_create_entity(&c, "B", "x", 1).unwrap();
        let cc = resolve_or_create_entity(&c, "C", "x", 1).unwrap();
        insert_relation(&c, a, b, "r", 1.0).unwrap();
        insert_relation(&c, b, cc, "r", 1.0).unwrap();
        // depth 1 from A → only B.
        let d1 = get_neighbors(&c, "A", 1).unwrap();
        assert_eq!(
            d1.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            vec!["B"]
        );
        // depth 2 from A → B then C.
        let d2 = get_neighbors(&c, "A", 2).unwrap();
        assert_eq!(d2.len(), 2);
        assert!(d2.iter().any(|n| n.name == "C" && n.depth == 2));
    }

    #[test]
    fn relation_weight_reinforces_on_repeat() {
        let (_d, c) = conn();
        let a = resolve_or_create_entity(&c, "A", "x", 1).unwrap();
        let b = resolve_or_create_entity(&c, "B", "x", 1).unwrap();
        insert_relation(&c, a, b, "r", 1.0).unwrap();
        insert_relation(&c, a, b, "r", 0.5).unwrap();
        let w: f64 = c
            .query_row(
                "SELECT weight FROM idx_relations WHERE src_id=?1 AND dst_id=?2",
                params![a, b],
                |r| r.get(0),
            )
            .unwrap();
        assert!((w - 1.5).abs() < 1e-9, "weight accumulates");
    }

    #[test]
    fn unknown_entity_yields_no_neighbours() {
        let (_d, c) = conn();
        assert!(get_neighbors(&c, "Nobody", 3).unwrap().is_empty());
    }

    #[test]
    fn forget_cascades_entities_and_relations() {
        let (_d, c) = conn();
        let a = resolve_or_create_entity(&c, "Alice", "person", 1).unwrap();
        let b = resolve_or_create_entity(&c, "Bob", "person", 1).unwrap();
        insert_relation(&c, a, b, "knows", 1.0).unwrap();
        let (ents, rels) = forget_entities_like(&c, "Alice").unwrap();
        assert_eq!(ents, 1);
        assert_eq!(rels, 1, "the knows edge touching Alice is gone");
        assert!(resolve_entity_id(&c, "Alice").unwrap().is_none());
        assert!(
            resolve_entity_id(&c, "Bob").unwrap().is_some(),
            "Bob survives"
        );
    }

    #[test]
    fn forget_matches_topic_in_attribute_value_not_just_name() {
        // F68 (GDPR): a topic stored only as an ATTRIBUTE value must also be
        // erased — name "Alice" doesn't contain the topic, the employer does.
        let (_d, c) = conn();
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("employer".to_string(), "AcmeCorp".to_string());
        resolve_or_create_entity_with_attrs(&c, "Alice", "person", &attrs, 1).unwrap();
        resolve_or_create_entity(&c, "Bob", "person", 1).unwrap(); // bystander, no match
        let (ents, _rels) = forget_entities_like(&c, "%AcmeCorp%").unwrap();
        assert_eq!(ents, 1, "entity matched via attribute value, not name");
        assert!(
            resolve_entity_id(&c, "Alice").unwrap().is_none(),
            "Alice erased via her AcmeCorp attribute"
        );
        assert!(
            resolve_entity_id(&c, "Bob").unwrap().is_some(),
            "unrelated entity survives"
        );
    }

    #[test]
    fn parse_extraction_handles_fences_and_drops_empties() {
        let resp = "Sure! ```json\n{\"entities\":[{\"name\":\"Alice\",\"type\":\"person\"},\
            {\"name\":\"  \",\"type\":\"x\"},{\"name\":\"Mozilla\"}],\
            \"relations\":[{\"src\":\"Alice\",\"relation\":\"works at\",\"dst\":\"Mozilla\"},\
            {\"src\":\"\",\"relation\":\"x\",\"dst\":\"y\"}]}\n``` done";
        let ex = parse_extraction(resp).unwrap();
        assert_eq!(ex.entities.len(), 2, "empty-name entity dropped");
        assert_eq!(ex.entities[1].name, "Mozilla");
        assert_eq!(ex.entities[1].etype, "unknown", "missing type → unknown");
        assert_eq!(ex.relations.len(), 1, "empty-src relation dropped");
        assert_eq!(
            ex.relations[0],
            ("Alice".into(), "works at".into(), "Mozilla".into())
        );
    }

    // ── MEM-14: attribute merge + source_count credibility ──────────────────

    #[test]
    fn merge_attributes_overlays_new_keys() {
        let mut a = BTreeMap::new();
        a.insert("role".to_string(), "engineer".to_string());
        a.insert("city".to_string(), "Berlin".to_string());
        let merged = merge_attributes("{\"role\":\"intern\"}", &a).unwrap();
        let back: BTreeMap<String, String> = serde_json::from_str(&merged).unwrap();
        assert_eq!(
            back.get("role").unwrap(),
            "engineer",
            "existing key overwritten"
        );
        assert_eq!(back.get("city").unwrap(), "Berlin", "new key added");
        assert!(merge_attributes("not json", &a).is_err());
    }

    #[test]
    fn corrupt_stored_attributes_block_resighting_without_partial_count_bump() {
        let (_d, c) = conn();
        let id = resolve_or_create_entity(&c, "Alice", "person", 100).unwrap();
        c.execute(
            "UPDATE idx_entities SET attributes = '{not json' WHERE id = ?1",
            params![id],
        )
        .unwrap();
        let mut attrs = BTreeMap::new();
        attrs.insert("city".to_string(), "Berlin".to_string());
        let error =
            resolve_or_create_entity_with_attrs(&c, "Alice", "person", &attrs, 200).unwrap_err();
        assert!(error.to_string().contains("parse stored entity attributes"));
        let entity = get_entity(&c, "Alice").unwrap().unwrap();
        assert_eq!(entity.source_count, 1);
        assert_eq!(entity.attributes, "{not json");
    }

    #[test]
    fn resolve_with_attrs_merges_on_resighting() {
        let (_d, c) = conn();
        let mut a1 = BTreeMap::new();
        a1.insert("role".to_string(), "engineer".to_string());
        let id = resolve_or_create_entity_with_attrs(&c, "Alice", "person", &a1, 100).unwrap();
        let mut a2 = BTreeMap::new();
        a2.insert("city".to_string(), "Berlin".to_string());
        let id2 = resolve_or_create_entity_with_attrs(&c, "alice", "person", &a2, 200).unwrap();
        assert_eq!(id, id2, "same entity (case-insensitive)");
        let e = get_entity(&c, "Alice").unwrap().expect("entity exists");
        assert_eq!(e.source_count, 2, "credibility bumped on re-sighting");
        let attrs: BTreeMap<String, String> = serde_json::from_str(&e.attributes).unwrap();
        assert_eq!(attrs.get("role").unwrap(), "engineer", "first attr kept");
        assert_eq!(
            attrs.get("city").unwrap(),
            "Berlin",
            "second attr merged in"
        );
    }

    #[test]
    fn get_neighbors_orders_by_source_count_within_depth() {
        let (_d, c) = conn();
        let a = resolve_or_create_entity(&c, "A", "x", 1).unwrap();
        let low = resolve_or_create_entity(&c, "Low", "x", 1).unwrap();
        let high = resolve_or_create_entity(&c, "High", "x", 1).unwrap();
        // Corroborate "High" twice more → higher source_count.
        resolve_or_create_entity(&c, "High", "x", 2).unwrap();
        resolve_or_create_entity(&c, "High", "x", 3).unwrap();
        insert_relation(&c, a, low, "r", 1.0).unwrap();
        insert_relation(&c, a, high, "r", 1.0).unwrap();
        let n = get_neighbors(&c, "A", 1).unwrap();
        assert_eq!(n.len(), 2);
        assert_eq!(n[0].name, "High", "most-corroborated neighbour ranks first");
        assert!(n[0].source_count > n[1].source_count);
    }

    #[test]
    fn get_entity_unknown_is_none() {
        let (_d, c) = conn();
        assert!(get_entity(&c, "Nobody").unwrap().is_none());
    }

    #[test]
    fn parse_extraction_captures_and_normalises_attributes() {
        let resp = "{\"entities\":[{\"name\":\"Alice\",\"type\":\"person\",\
            \"attributes\":{\"role\":\"engineer\",\"age\":42,\"note\":null,\"  \":\"x\"}}],\
            \"relations\":[]}";
        let ex = parse_extraction(resp).unwrap();
        assert_eq!(ex.entities.len(), 1);
        let attrs = &ex.entities[0].attributes;
        assert_eq!(attrs.get("role").unwrap(), "engineer");
        assert_eq!(attrs.get("age").unwrap(), "42", "number stringified");
        assert!(!attrs.contains_key("note"), "null dropped");
        assert!(!attrs.contains_key("  "), "blank key dropped");
    }

    #[test]
    fn parse_extraction_no_json_errors() {
        assert!(parse_extraction("no json here").is_err());
    }

    // ── refines-MEM-06: invalidate_relation + BFS visibility ─────────────────

    #[test]
    fn invalidate_relation_stamps_valid_to_and_hides_from_bfs() {
        let (_d, c) = conn();
        let now = 1_000_000i64;
        let alice = resolve_or_create_entity(&c, "Alice", "person", now).unwrap();
        let moz = resolve_or_create_entity(&c, "Mozilla", "org", now).unwrap();
        insert_relation(&c, alice, moz, "works_at", 1.0).unwrap();

        // Confirm the relation is active (valid_to IS NULL).
        let vt: Option<String> = c
            .query_row(
                "SELECT valid_to FROM idx_relations \
                 WHERE src_id=?1 AND dst_id=?2 AND relation=?3",
                params![alice, moz, "works_at"],
                |r| r.get(0),
            )
            .unwrap();
        assert!(vt.is_none(), "relation starts active (valid_to IS NULL)");

        // Act: close the relation directly.
        let closed = invalidate_relation(&c, alice, moz, "works_at", now + 1).unwrap();
        assert!(closed, "invalidate_relation returns true when row was open");

        // valid_to is now set.
        let vt2: Option<String> = c
            .query_row(
                "SELECT valid_to FROM idx_relations \
                 WHERE src_id=?1 AND dst_id=?2 AND relation=?3",
                params![alice, moz, "works_at"],
                |r| r.get(0),
            )
            .unwrap();
        assert!(vt2.is_some(), "valid_to stamped after invalidation");

        // BFS get_neighbors no longer surfaces Mozilla via the closed edge.
        let neighbours = get_neighbors(&c, "Alice", 1).unwrap();
        assert!(neighbours.is_empty(), "closed relation invisible to BFS");

        // A second invalidate is a no-op (already closed).
        let noop = invalidate_relation(&c, alice, moz, "works_at", now + 2).unwrap();
        assert!(!noop, "idempotent: already-closed row returns false");
    }

    #[test]
    fn invalidate_relation_by_names_resolves_and_closes() {
        let (_d, c) = conn();
        let now = 2_000_000i64;
        let alice = resolve_or_create_entity(&c, "Alice", "person", now).unwrap();
        let moz = resolve_or_create_entity(&c, "Mozilla", "org", now).unwrap();
        insert_relation(&c, alice, moz, "works_at", 1.0).unwrap();

        let closed =
            invalidate_relation_by_names(&c, "Alice", "works_at", "Mozilla", now + 1).unwrap();
        assert!(closed, "name-based close succeeds");
        assert!(
            get_neighbors(&c, "Alice", 1).unwrap().is_empty(),
            "BFS sees nothing"
        );

        // Unknown entity returns false without error.
        let miss =
            invalidate_relation_by_names(&c, "Nobody", "works_at", "Mozilla", now + 2).unwrap();
        assert!(!miss, "unknown subject returns false (not an error)");
    }

    #[test]
    fn invalidate_relation_wildcard_closes_all_edges() {
        let (_d, c) = conn();
        let now = 3_000_000i64;
        let alice = resolve_or_create_entity(&c, "Alice", "person", now).unwrap();
        let moz = resolve_or_create_entity(&c, "Mozilla", "org", now).unwrap();
        insert_relation(&c, alice, moz, "works_at", 1.0).unwrap();
        insert_relation(&c, alice, moz, "contributes_to", 1.0).unwrap();

        // Both edges active before wildcard close.
        assert_eq!(get_neighbors(&c, "Alice", 1).unwrap().len(), 1);

        let closed = invalidate_relation_by_names(&c, "Alice", "*", "Mozilla", now + 1).unwrap();
        assert!(closed, "wildcard close stamped at least one row");
        assert!(
            get_neighbors(&c, "Alice", 1).unwrap().is_empty(),
            "all edges closed"
        );
    }

    #[test]
    fn insert_relation_reopens_closed_edge_on_reassertion() {
        let (_d, c) = conn();
        let now = 4_000_000i64;
        let alice = resolve_or_create_entity(&c, "Alice", "person", now).unwrap();
        let moz = resolve_or_create_entity(&c, "Mozilla", "org", now).unwrap();
        insert_relation(&c, alice, moz, "works_at", 1.0).unwrap();

        // Close it.
        invalidate_relation(&c, alice, moz, "works_at", now + 1).unwrap();
        assert!(get_neighbors(&c, "Alice", 1).unwrap().is_empty(), "closed");

        // Re-asserting the same triple re-opens the edge.
        insert_relation(&c, alice, moz, "works_at", 1.0).unwrap();
        let neighbours = get_neighbors(&c, "Alice", 1).unwrap();
        assert_eq!(neighbours.len(), 1, "re-opened edge visible to BFS");
        assert_eq!(neighbours[0].name, "Mozilla");
    }

    struct MockProvider(String);
    #[async_trait::async_trait]
    impl crate::providers::Provider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                termination: Default::default(),
                text: self.0.clone(),
                identity: Default::default(),
                model: "mock".into(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn extract_and_persist_populates_graph_end_to_end() {
        let (_d, c) = conn();
        let provider = MockProvider(
            "{\"entities\":[{\"name\":\"Alice\",\"type\":\"person\"},{\"name\":\"Mozilla\",\"type\":\"org\"}],\
             \"relations\":[{\"src\":\"Alice\",\"relation\":\"works at\",\"dst\":\"Mozilla\"}]}"
                .to_string(),
        );
        let (ents, rels) = extract_and_persist(&c, "Alice works at Mozilla.", &provider, 100)
            .await
            .unwrap();
        assert_eq!((ents, rels), (2, 1));
        // The full pipeline is live: querying "Alice" surfaces Mozilla via 1 hop.
        let n = get_neighbors(&c, "Alice", 1).unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].name, "Mozilla");
        assert_eq!(n[0].via_relation, "works at");
    }

    #[test]
    fn build_extraction_prompt_carries_text_and_schema() {
        let p = build_extraction_prompt("Bob lives in Berlin");
        assert!(p.contains("Bob lives in Berlin"));
        assert!(p.contains("\"entities\""));
        assert!(p.contains("\"relations\""));
    }
}
