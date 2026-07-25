//! GDPR retroactive forgetting — C-15.
//!
//! "Forget X" is structurally different from Hebbian decay:
//!   - **Decay** is probabilistic + slow (years to drop below
//!     FORGET_FLOOR without reinforcement); driven by
//!     `consolidate.rs::run_consolidation_pass`.
//!   - **Forget** is explicit, immediate, transactional,
//!     operator-initiated when DSGVO / personal request demands it.
//!
//! The cascade is SQLite-transactional across every recall/profile/graph tier,
//! embeddings, raw transcripts, pending/outbox state and the queryable foreign
//! gossip ledger. Ground-truth assertions are revoked to preserve audit
//! provenance. The same transaction installs a `_tombstone.<topic>` sentinel,
//! which blocks profile re-extraction and future raw peer frames containing the
//! topic. The confirmed CLI path also appends a TOMBSTONE_REQUESTED audit frame.
//!
//! The default forget leaves historical payload bytes in the tamper-evident
//! WAL. Operators requiring physical erasure use
//! `neoth memory --forget <topic> --confirm --physical`: the CLI rewrites both
//! live and sealed/compressed segments, zeroes matching payloads, marks the
//! frames REDACTED, recomputes CRCs, emits signed redaction markers, and fails
//! loudly if any segment cannot be proven complete.

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::collections::HashSet;

use crate::memory::embeddings;

/// What was deleted by a single `forget` call. Returned for the audit
/// trail + the operator's confirm summary.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct ForgetReport {
    pub episode_rows: i64,
    pub consolidated_rows: i64,
    pub longterm_rows: i64,
    /// GOLD-ADAPT-ODY-26 — raw transcript turns deleted (`raw_turns`). The
    /// ODY-26 raw-transcript table is FTS-searchable via `neoth recall
    /// --transcript`; it was added after this cascade was written and was never
    /// wiped, so a forgotten topic stayed fully recoverable in the transcript —
    /// a GDPR right-to-erasure hole. The `raw_turns_ad` AFTER DELETE trigger
    /// keeps `raw_turns_fts` in sync.
    #[serde(default)]
    pub raw_turn_rows: i64,
    pub groundtruth_revoked: i64,
    pub embedding_rows: i64,
    /// Structured-profile claims deleted (GDPR cascade, GOLD-SEC-28 /
    /// CR-007). Previously `forget` left `idx_profile` rows intact, so a
    /// right-to-erasure request silently kept the operator's extracted
    /// profile claims about the topic.
    pub profile_rows: i64,
    /// In-flight profile-extraction rows deleted (GOLD-SEC-28): pending deltas
    /// not yet applied + queued outbox WAL frames. Without these, a topic the
    /// operator forgot would re-materialise when the pending delta is applied or
    /// the outbox frame is written — a right-to-erasure hole.
    #[serde(default)]
    pub profile_pending_rows: i64,
    #[serde(default)]
    pub profile_outbox_rows: i64,
    /// GOLD-ADAPT-MEM-06 — knowledge-graph cascade: entities whose name matches
    /// the topic + every relation touching them. Without this a forgotten
    /// subject would linger as a graph node with edges.
    #[serde(default)]
    pub entity_rows: i64,
    #[serde(default)]
    pub relation_rows: i64,
    /// GOLD-ADAPT-MEM-07 — co-access association links deleted: every
    /// `idx_memory_links` row touching a forgotten episode. Without this a
    /// forgotten memory would dangle as a graph endpoint.
    #[serde(default)]
    pub link_rows: i64,
    /// GOLD-ADAPT-MEM-02 — contradiction ledger rows deleted: every
    /// `idx_contradictions` row referencing a revoked ground-truth fact. Without
    /// this a forgotten fact lingers as a live leg of a pair — both a dangling
    /// reference and a GDPR re-identification risk (the ledger reveals that fact A
    /// contradicted fact B).
    #[serde(default)]
    pub contradiction_rows: i64,
    /// Accepted raw peer-gossip frames removed from the queryable foreign
    /// backup surface. These bytes can contain the forgotten topic even after
    /// every local recall projection has been erased.
    #[serde(default)]
    pub foreign_event_rows: i64,
    /// L6-PRELOAD (GDPR) — restricted Vault chunks deleted. `idx_restricted`
    /// carries free statement text preloaded from the operator's Obsidian vault
    /// and was added after this cascade was written; NO path deleted from it, so
    /// a right-to-erasure `forget` left statements about the topic physically on
    /// disk in a store the promote path can lift straight back into recall.
    #[serde(default)]
    pub restricted_rows: i64,
    /// D4 (GDPR) — People-scorer entries wiped from `~/.neoth/people.json`
    /// whose display name matches the forgotten topic. people.json is an
    /// operator-visible store (`neoth memory --people`) that the SQLite-only
    /// forget cascade previously never touched (the forget doc claimed "all
    /// operator-visible paths read from SQLite" — people.json is the exception).
    #[serde(default)]
    pub people_rows: i64,
    pub topic: String,
}

impl ForgetReport {
    pub fn total(&self) -> i64 {
        self.episode_rows
            + self.consolidated_rows
            + self.longterm_rows
            + self.raw_turn_rows
            + self.groundtruth_revoked
            + self.embedding_rows
            + self.profile_rows
            + self.profile_pending_rows
            + self.profile_outbox_rows
            + self.entity_rows
            + self.relation_rows
            + self.link_rows
            + self.contradiction_rows
            + self.foreign_event_rows
            + self.restricted_rows
            + self.people_rows
    }
}

/// Read-only, transactionally consistent preview of [`forget_by_topic`].
///
/// Every counter intentionally mirrors one mutation leg below, including the
/// indirect channel/sender embedding cascade and the filesystem-backed people
/// scorer. Any schema/read error is returned: a GDPR preview must never silently
/// under-report what the confirmed operation will erase.
pub fn preview_forget_by_topic(conn: &Connection, topic: &str) -> Result<ForgetReport> {
    if topic.trim().is_empty() {
        anyhow::bail!(
            "forget: topic must be non-empty (use `neoth memory purge` for a wholesale wipe)"
        );
    }
    let pattern = format!("%{}%", crate::memory::escape_like(topic));
    let tx = conn
        .unchecked_transaction()
        .context("begin forget preview transaction")?;

    let count = |sql: &str, label: &str| -> Result<i64> {
        tx.query_row(sql, rusqlite::params![&pattern], |row| row.get(0))
            .with_context(|| format!("count {label} for forget preview"))
    };

    let episode_rows = count(
        "SELECT COUNT(*) FROM idx_episode WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "idx_episode",
    )?;
    let consolidated_rows = count(
        "SELECT COUNT(*) FROM idx_consolidated WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "idx_consolidated",
    )?;
    let longterm_rows = count(
        "SELECT COUNT(*) FROM idx_longterm WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "idx_longterm",
    )?;
    let raw_turn_rows = count(
        "SELECT COUNT(*) FROM raw_turns WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "raw_turns",
    )?;
    let profile_rows = count(
        "SELECT COUNT(*) FROM idx_profile \
         WHERE field COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
            OR value_json COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "idx_profile",
    )?;
    let profile_pending_rows = count(
        "SELECT COUNT(*) FROM idx_profile_pending \
         WHERE delta_json COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "idx_profile_pending",
    )?;
    let profile_outbox_rows = count(
        "SELECT COUNT(*) FROM idx_profile_outbox \
         WHERE CAST(payload AS TEXT) COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "idx_profile_outbox",
    )?;
    let groundtruth_revoked = count(
        "SELECT COUNT(*) FROM idx_groundtruth \
         WHERE revoked_at IS NULL AND statement COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "active idx_groundtruth",
    )?;
    let restricted_rows = count(
        "SELECT COUNT(*) FROM idx_restricted \
         WHERE statement COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
            OR source_name COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "idx_restricted",
    )?;
    let entity_rows = count(
        "SELECT COUNT(*) FROM idx_entities \
         WHERE name COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
            OR attributes COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
        "idx_entities",
    )?;
    let relation_rows = count(
        "SELECT COUNT(*) FROM idx_relations \
         WHERE src_id IN (SELECT id FROM idx_entities \
                          WHERE name COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                             OR attributes COLLATE NOCASE LIKE ?1 ESCAPE '\\') \
            OR dst_id IN (SELECT id FROM idx_entities \
                          WHERE name COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                             OR attributes COLLATE NOCASE LIKE ?1 ESCAPE '\\')",
        "idx_relations",
    )?;
    let link_rows = count(
        "WITH forgotten(event_id) AS ( \
             SELECT event_id FROM idx_episode \
             WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
             UNION \
             SELECT event_id FROM idx_consolidated \
             WHERE event_id IS NOT NULL \
               AND text COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
             UNION \
             SELECT event_id FROM idx_longterm \
             WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
         ) \
         SELECT COUNT(*) FROM idx_memory_links \
         WHERE lo_id IN (SELECT event_id FROM forgotten) \
            OR hi_id IN (SELECT event_id FROM forgotten)",
        "idx_memory_links",
    )?;
    let contradiction_rows = count(
        "SELECT COUNT(*) FROM idx_contradictions \
         WHERE fact_a_id IN (SELECT id FROM idx_groundtruth \
                             WHERE revoked_at IS NULL \
                               AND statement COLLATE NOCASE LIKE ?1 ESCAPE '\\') \
            OR fact_b_id IN (SELECT id FROM idx_groundtruth \
                             WHERE revoked_at IS NULL \
                               AND statement COLLATE NOCASE LIKE ?1 ESCAPE '\\')",
        "idx_contradictions",
    )?;

    // Direct source refs and indirect channel/sender refs can overlap. Count a
    // set of row ids so the preview matches the sequential DELETE operations,
    // where an already-deleted direct match cannot be counted a second time.
    let mut embedding_ids = HashSet::new();
    {
        let mut stmt = tx
            .prepare(
                "SELECT id FROM idx_embedding \
                 WHERE source_ref COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            )
            .context("prepare direct embedding preview")?;
        let rows = stmt
            .query_map(rusqlite::params![&pattern], |row| row.get::<_, i64>(0))
            .context("query direct embedding preview")?;
        for row in rows {
            embedding_ids.insert(row.context("read direct embedding preview row")?);
        }
    }
    let channel_sender_pairs: Vec<(String, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT DISTINCT channel, sender_id FROM idx_episode \
                 WHERE channel IS NOT NULL AND sender_id IS NOT NULL \
                   AND text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            )
            .context("prepare channel/sender embedding preview")?;
        stmt.query_map(rusqlite::params![&pattern], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .context("query channel/sender embedding preview")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect channel/sender embedding preview")?
    };
    for (channel, sender_id) in channel_sender_pairs {
        let source_pattern = format!(
            "{}:%:{}:%",
            crate::memory::escape_like(&channel),
            crate::memory::escape_like(&sender_id),
        );
        let mut stmt = tx
            .prepare(
                "SELECT id FROM idx_embedding \
                 WHERE source_ref COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            )
            .context("prepare indirect embedding preview")?;
        let rows = stmt
            .query_map(rusqlite::params![source_pattern], |row| {
                row.get::<_, i64>(0)
            })
            .context("query indirect embedding preview")?;
        for row in rows {
            embedding_ids.insert(row.context("read indirect embedding preview row")?);
        }
    }
    let embedding_rows =
        i64::try_from(embedding_ids.len()).context("embedding preview count exceeds i64")?;
    let foreign_event_rows = i64::try_from(matching_foreign_event_ids(&tx, topic)?.len())
        .context("foreign-event preview count exceeds i64")?;

    tx.commit().context("finish forget preview transaction")?;

    let people_rows = match conn
        .path()
        .map(std::path::Path::new)
        .and_then(|path| path.parent())
    {
        Some(home) => crate::memory::people::count_people_by_display(home, topic)
            .context("count people.json rows for forget preview")?,
        None => 0,
    };

    Ok(ForgetReport {
        episode_rows,
        consolidated_rows,
        longterm_rows,
        raw_turn_rows,
        groundtruth_revoked,
        embedding_rows,
        profile_rows,
        profile_pending_rows,
        profile_outbox_rows,
        entity_rows,
        relation_rows,
        link_rows,
        contradiction_rows,
        foreign_event_rows,
        restricted_rows,
        people_rows,
        topic: topic.to_string(),
    })
}

/// Cascade-delete every row matching `topic` (case-insensitive LIKE)
/// across all 4 memory tiers + the embedding store. Ground-truth rows
/// are REVOKED (not deleted) so the immutability invariant is honoured
/// while still satisfying the operator's right-to-erasure: a revoked
/// row stops surfacing in recall but the audit record persists.
///
/// `now_unix` is the timestamp stamped on the revocation marker;
/// callers pass `unix_seconds_now()` from the daemon clock to keep
/// time consistent with surrounding WAL events.
///
/// Pure-SQLite version — does NOT emit a WAL tombstone audit frame.
/// Callers that want the audit anchor use [`forget_by_topic_with_audit`].
pub fn forget_by_topic(conn: &Connection, topic: &str, now_unix: i64) -> Result<ForgetReport> {
    forget_by_topic_as_source(conn, topic, now_unix, "memory")
}

fn forget_by_topic_as_source(
    conn: &Connection,
    topic: &str,
    now_unix: i64,
    source: &str,
) -> Result<ForgetReport> {
    if topic.trim().is_empty() {
        anyhow::bail!(
            "forget: topic must be non-empty (use `neoth memory purge` for a wholesale wipe)"
        );
    }
    // Escape LIKE wildcards so a topic of `%`/`_` matches literally —
    // otherwise `forget "%"` would wipe every row (GOLD-SEC-04 / A-08).
    // Every LIKE below pairs the pattern with `ESCAPE '\'`.
    let pattern = format!("%{}%", crate::memory::escape_like(topic));

    // GR-fix (review): wrap the whole SQLite cascade in ONE transaction. The
    // module doc promises forget is "transactional", but the ~7 DELETE/UPDATE legs
    // + helper cascades ran under autocommit — a mid-cascade failure (disk full,
    // I/O error) left a PARTIAL erasure (some tiers wiped, others not), the worst
    // outcome for a GDPR right-to-erasure op. `unchecked_transaction()` takes
    // `&self` (no signature change for the 48 store callers; same pattern as
    // assoc_graph.rs / wiki/ingest.rs). On any `?` the tx drops un-committed →
    // full rollback. NOTE: the people.json wipe + the CLI-side HNSW snapshot
    // rebuild are filesystem ops OUTSIDE SQLite — they run post-commit (people)
    // or in the CLI caller (HNSW), so the cascade is SQLite-atomic, not
    // end-to-end-atomic across the JSON file (documented design boundary).
    let tx = conn
        .unchecked_transaction()
        .context("begin forget cascade transaction")?;

    // Install the anti-resurrection sentinel in the SAME SQLite transaction as
    // the cascade. The old cluster-only helper wrote it after commit and the
    // public CLI never called that helper, leaving a crash window (and in
    // practice no product wiring at all). INSERT OR IGNORE makes repeat-forget
    // idempotent against the active-redaction unique index.
    let sentinel_field = tombstone_sentinel_field(topic);
    let sentinel_reason = format!("forget_by_topic at ts_unix={now_unix} (source={source})");
    tx.execute(
        "INSERT OR IGNORE INTO idx_profile_redactions \
         (field, never_recreate, reason, asserted_by, asserted_at, revoked_at) \
         VALUES (?1, 1, ?2, ?3, ?4, NULL)",
        rusqlite::params![sentinel_field, sentinel_reason, source, now_unix],
    )
    .context("install forget anti-resurrection sentinel")?;

    // GR-165: collect channel-side (channel, sender_id) pairs BEFORE the
    // episode delete below destroys the correlation. Channel ingest keys
    // idx_embedding with opaque "channel:chat_id:sender_id:ts" source_refs
    // that never contain the topic string — these pairs drive the second
    // embedding-wipe leg further down.
    let channel_sender_pairs: Vec<(String, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT DISTINCT channel, sender_id FROM idx_episode \
                 WHERE channel IS NOT NULL AND sender_id IS NOT NULL \
                   AND text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            )
            .context("prepare channel/sender pre-collect")?;
        stmt.query_map(rusqlite::params![pattern], |r| Ok((r.get(0)?, r.get(1)?)))
            .context("query channel/sender pairs for embedding wipe")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("collect channel/sender pairs")?
    };

    // GOLD-ADAPT-MEM-07 — collect matching event ids from every queryable tier
    // BEFORE the deletes below remove them. Links retain the original event id
    // when an episode consolidates/promotes, so looking only in idx_episode
    // leaves warm/cold endpoints dangling after a GDPR forget.
    let forgotten_event_ids: Vec<i64> = {
        let mut stmt = tx
            .prepare(
                "SELECT event_id FROM idx_episode \
                 WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                 UNION \
                 SELECT event_id FROM idx_consolidated \
                 WHERE event_id IS NOT NULL \
                   AND text COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                 UNION \
                 SELECT event_id FROM idx_longterm \
                 WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            )
            .context("prepare event_id pre-collect for link cascade")?;
        stmt.query_map(rusqlite::params![pattern], |r| r.get::<_, i64>(0))
            .context("query event_ids for link cascade")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("collect event_ids for link cascade")?
    };

    let episode_rows = tx
        .execute(
            "DELETE FROM idx_episode WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_episode")? as i64;

    let consolidated_rows = tx
        .execute(
            "DELETE FROM idx_consolidated WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_consolidated")? as i64;

    let longterm_rows = tx
        .execute(
            "DELETE FROM idx_longterm WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_longterm")? as i64;

    // GOLD-ADAPT-ODY-26 — raw-transcript cascade. The raw_turns table is
    // FTS-searchable via `neoth recall --transcript`; without this leg a
    // forgotten topic stayed fully recoverable in the transcript (GDPR
    // right-to-erasure hole). The `raw_turns_ad` AFTER DELETE trigger keeps
    // `raw_turns_fts` in sync, so the topic stops surfacing immediately.
    let raw_turn_rows = crate::memory::transcript_store::forget_turns_like(&tx, &pattern)
        .context("delete from raw_turns")?;

    // Structured-profile claims: hard delete any claim whose field name OR
    // value mentions the topic. GDPR right-to-erasure cascade (GOLD-SEC-28
    // / CR-007) — `forget` previously skipped idx_profile, leaving the
    // operator's extracted claims about the topic on disk.
    let profile_rows = tx
        .execute(
            "DELETE FROM idx_profile \
             WHERE field COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                OR value_json COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_profile")? as i64;

    // L6-PRELOAD — restricted Vault chunks. `idx_restricted` holds free
    // statement text preloaded from the operator's Obsidian vault and was added
    // after this cascade was written; no path in the tree deleted from it, so a
    // right-to-erasure `forget` left statements about the topic physically on
    // disk — and `promote_restricted` can lift them straight back into
    // ground-truth and live recall.
    let restricted_rows = tx
        .execute(
            "DELETE FROM idx_restricted \
             WHERE statement COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                OR source_name COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_restricted")? as i64;

    // GOLD-ADAPT-MEM-02 — collect the ground-truth ids that WILL be revoked,
    // BEFORE the revoke runs, so the contradiction-ledger cascade can reference
    // them (the revoke flips `revoked_at`, not the id, but pre-collecting keeps
    // the cascade independent of revoke ordering — mirrors the forgotten_event_ids
    // pattern above).
    let revoked_gt_ids: Vec<i64> = {
        let mut stmt = tx
            .prepare(
                "SELECT id FROM idx_groundtruth \
                 WHERE revoked_at IS NULL AND statement COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            )
            .context("pre-collect groundtruth ids for contradiction cascade")?;
        stmt.query_map(rusqlite::params![pattern], |r| r.get::<_, i64>(0))
            .context("query groundtruth ids for contradiction cascade")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("collect groundtruth ids for contradiction cascade")?
    };

    // Ground-truth: revoke instead of delete. The row itself stays for
    // audit (operator can prove they didn't assert X after revocation),
    // but recall queries filter on `revoked_at IS NULL` so it stops
    // surfacing.
    let groundtruth_revoked = tx
        .execute(
            "UPDATE idx_groundtruth \
             SET revoked_at = ?1 \
             WHERE revoked_at IS NULL AND statement COLLATE NOCASE LIKE ?2 ESCAPE '\\'",
            rusqlite::params![now_unix, pattern],
        )
        .context("revoke idx_groundtruth")? as i64;

    // GOLD-ADAPT-MEM-02 — cascade the GDPR wipe into the contradiction ledger so
    // a revoked fact never lingers as a live leg of a pair.
    let contradiction_rows = crate::memory::contradiction::forget_for_ids(&tx, &revoked_gt_ids)?;

    // GOLD-SEC-28 — in-flight profile extractions. A pending delta or a queued
    // outbox frame mentioning the topic would re-materialise the forgotten data
    // when it's later applied / written, so the erasure must cover them too.
    // `delta_json` is TEXT; the outbox `payload` is a BLOB → CAST to TEXT so the
    // topic substring is matched byte-for-byte.
    let profile_pending_rows = tx
        .execute(
            "DELETE FROM idx_profile_pending WHERE delta_json COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_profile_pending")? as i64;

    let profile_outbox_rows = tx
        .execute(
            "DELETE FROM idx_profile_outbox \
             WHERE CAST(payload AS TEXT) COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_profile_outbox")? as i64;

    // Embeddings: hard delete. Vectors carry no audit value — they're
    // a derived index, not an assertion. Two legs: path-keyed refs match
    // the topic pattern directly; channel-keyed refs (opaque ids) match
    // via the (channel, sender_id) pairs pre-collected above (GR-165).
    let mut embedding_rows =
        embeddings::wipe_by_source_ref_pattern(&tx, &pattern).context("wipe idx_embedding")?;
    if !channel_sender_pairs.is_empty() {
        embedding_rows += embeddings::wipe_by_channel_sender_refs(&tx, &channel_sender_pairs)
            .context("wipe idx_embedding channel-side")?;
    }

    // GOLD-ADAPT-MEM-06 — cascade the GDPR wipe into the knowledge graph:
    // entities whose name matches the topic + every relation touching them.
    let (entity_rows, relation_rows) =
        crate::memory::entities::forget_entities_like(&tx, &pattern)?;

    // GOLD-ADAPT-MEM-07 — cascade into the co-access association graph: drop
    // every link touching a forgotten episode so none is left dangling.
    let mut link_rows: i64 = 0;
    for eid in &forgotten_event_ids {
        link_rows += crate::memory::assoc_graph::forget_links_for_event(&tx, *eid)?;
    }

    // Raw peer gossip is a queryable backup surface (`neoth cluster events` /
    // export), not merely a transport buffer. Purge matching frames in the
    // same transaction so a forget cannot leave the topic recoverable there.
    // A malformed/mismatched raw frame is deleted conservatively: we cannot
    // prove that opaque PII does not contain the topic.
    let foreign_event_ids = matching_foreign_event_ids(&tx, topic)?;
    let mut foreign_event_rows = 0i64;
    for id in foreign_event_ids {
        foreign_event_rows += tx
            .execute("DELETE FROM idx_foreign_events WHERE id = ?1", [id])
            .context("delete forgotten foreign-event frame")? as i64;
    }

    // GR-fix: commit the SQLite cascade atomically. Any `?` above dropped `tx`
    // un-committed → full rollback (no partial erasure). Everything below this
    // line is a post-commit filesystem op, intentionally outside the SQLite tx.
    tx.commit().context("commit forget cascade transaction")?;

    // D4 (GDPR) — cascade into the operator-visible people-scorer store
    // (`~/.neoth/people.json`). The people-home is the directory the conn's
    // views.db lives in (both sit in ~/.neoth/). Match on the human-readable
    // display name (person_key is opaque). Non-fatal: an in-memory conn or a
    // missing file → 0.
    let people_rows = match conn
        .path()
        .map(std::path::Path::new)
        .and_then(|p| p.parent())
    {
        Some(home) => crate::memory::people::forget_people_by_display(home, topic)
            .context("erase matching people.json rows after SQLite forget commit")?,
        None => 0,
    };

    Ok(ForgetReport {
        episode_rows,
        consolidated_rows,
        longterm_rows,
        raw_turn_rows,
        groundtruth_revoked,
        embedding_rows,
        profile_rows,
        profile_pending_rows,
        profile_outbox_rows,
        entity_rows,
        relation_rows,
        link_rows,
        contradiction_rows,
        foreign_event_rows,
        restricted_rows,
        people_rows,
        topic: topic.to_string(),
    })
}

/// Concern-2 fix (Session 24) — sentinel-redaction name prefix.
///
/// Every `forget_by_topic` transaction writes a row into
/// `idx_profile_redactions` with `field = "{TOMBSTONE_SENTINEL_PREFIX}{topic_lowercase}"`
/// alongside the SQLite wipe. This sentinel row:
///
/// - Is NOT a real profile field — the `_tombstone.` namespace
///   never collides with operator dot-paths like `identity.name`
///   or `skills.rust`.
/// - Carries `never_recreate = true`; both Stage 5 and the final apply-time
///   race recheck hard-reject future claims whose field or value mentions the
///   topic.
/// - Is consulted by the live raw-gossip persistence boundary, so a buffered
///   peer frame containing the topic is dropped instead of restoring it to the
///   queryable foreign ledger.
///
/// Choosing the sentinel namespace (rather than a new table)
/// reuses the existing redaction registry's UNIQUE-active index. It is a local
/// anti-resurrection policy; it does not authorize a peer to delete local data.
pub const TOMBSTONE_SENTINEL_PREFIX: &str = "_tombstone.";

/// Concern-2 fix (Session 24) — derive the canonical sentinel
/// field name for a tombstone topic. Lowercases the topic so
/// `forget("Berlin")` + `forget("berlin")` collapse to the same
/// sentinel + the UNIQUE active-redaction index dedupes
/// repeat-forgets.
pub fn tombstone_sentinel_field(topic: &str) -> String {
    format!(
        "{}{}",
        TOMBSTONE_SENTINEL_PREFIX,
        topic.trim().to_lowercase()
    )
}

/// Concern-2 fix (Session 24) — true iff `field` is a tombstone
/// sentinel row (i.e. a `_tombstone.<topic>` entry in
/// `idx_profile_redactions`). The profile and raw-gossip boundaries use this
/// discriminator to select topic-based matching rather than exact-field matching.
pub fn is_tombstone_sentinel(field: &str) -> bool {
    field.starts_with(TOMBSTONE_SENTINEL_PREFIX)
}

/// Concern-2 fix (Session 24) — extract the topic from a tombstone
/// sentinel field. Returns `None` for non-sentinel fields. Useful
/// for the gossip-receive matcher that asks "does this inbound
/// frame's text match any tombstoned topic?".
pub fn topic_from_sentinel(field: &str) -> Option<&str> {
    field.strip_prefix(TOMBSTONE_SENTINEL_PREFIX)
}

/// Case-insensitive topic match used by every anti-resurrection boundary.
/// Empty topics never match. Unicode lowercasing mirrors the canonical
/// lowercase sentinel and is strictly stronger than SQLite's ASCII-only
/// `NOCASE` collation for newly arriving data.
pub(crate) fn text_contains_topic(text: &str, topic: &str) -> bool {
    let topic = topic.trim();
    !topic.is_empty() && text.to_lowercase().contains(&topic.to_lowercase())
}

fn json_contains_topic(value: &serde_json::Value, topic: &str) -> bool {
    match value {
        serde_json::Value::String(text) => text_contains_topic(text, topic),
        serde_json::Value::Array(values) => {
            values.iter().any(|value| json_contains_topic(value, topic))
        }
        serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
            text_contains_topic(key, topic) || json_contains_topic(value, topic)
        }),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

/// Match a topic against structured JSON without being fooled by JSON escape
/// sequences. Non-JSON payloads fall back to a lossy UTF-8 text match because
/// RAW_TEXT historically also existed as a plain byte payload.
pub(crate) fn payload_contains_topic(payload: &[u8], topic: &str) -> bool {
    match serde_json::from_slice::<serde_json::Value>(payload) {
        Ok(value) => json_contains_topic(&value, topic),
        Err(_) => text_contains_topic(&String::from_utf8_lossy(payload), topic),
    }
}

/// Does an active redaction field block this profile claim? Normal redactions
/// match the exact profile field. `_tombstone.<topic>` sentinels instead match
/// the topic in either the claim's field or its structured value.
pub(crate) fn redaction_blocks_claim(
    redacted_field: &str,
    claim_field: &str,
    claim_value: &serde_json::Value,
) -> bool {
    if !is_tombstone_sentinel(redacted_field) {
        return redacted_field == claim_field;
    }
    let Some(topic) = topic_from_sentinel(redacted_field) else {
        return false;
    };
    !topic.is_empty()
        && (text_contains_topic(claim_field, topic) || json_contains_topic(claim_value, topic))
}

/// Active local forget topics. Receive-side raw gossip consults this registry
/// before writing a peer frame back into the queryable backup surface.
#[cfg(feature = "cluster")]
pub(crate) fn active_tombstone_topics(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT field FROM idx_profile_redactions \
             WHERE revoked_at IS NULL AND never_recreate = 1 \
               AND field GLOB '_tombstone.*' \
             ORDER BY field ASC",
        )
        .context("prepare active tombstone lookup")?;
    stmt.query_map([], |row| row.get::<_, String>(0))
        .context("query active tombstones")?
        .filter_map(|row| match row {
            Ok(field) => topic_from_sentinel(&field)
                .filter(|topic| !topic.is_empty())
                .map(|topic| Ok(topic.to_string())),
            Err(error) => Some(Err(error)),
        })
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("collect active tombstones")
}

/// Decode one canonical foreign WAL frame and match only its logical payload.
/// The stored outer event type must agree with the CRC-checked inner header.
pub(crate) fn foreign_frame_contains_topic(
    frame: &[u8],
    event_type: u8,
    topic: &str,
) -> Result<bool> {
    let decoded = crate::wal::frame::decode_frame(frame)
        .map_err(|error| anyhow::anyhow!("decode foreign WAL frame: {error}"))?;
    anyhow::ensure!(
        decoded.header.total_len as usize == frame.len(),
        "foreign WAL frame has trailing bytes"
    );
    anyhow::ensure!(
        decoded.header.event_type == event_type,
        "foreign WAL frame event type mismatch: outer=0x{event_type:02X}, inner=0x{:02X}",
        decoded.header.event_type
    );
    Ok(payload_contains_topic(decoded.payload, topic))
}

/// IDs in the foreign backup ledger that the forget cascade must delete.
/// Invalid event-type values or malformed raw frames are included
/// conservatively because their opaque bytes cannot be proven unrelated.
pub(crate) fn matching_foreign_event_ids(conn: &Connection, topic: &str) -> Result<Vec<i64>> {
    let mut stmt = conn
        .prepare("SELECT id, event_type, payload FROM idx_foreign_events")
        .context("prepare foreign-event forget scan")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .context("query foreign-event forget scan")?;
    let mut matches = Vec::new();
    for row in rows {
        let (id, raw_event_type, frame) = row.context("read foreign-event forget candidate")?;
        let Ok(event_type) = u8::try_from(raw_event_type) else {
            matches.push(id);
            continue;
        };
        if !crate::wal::events::is_raw_ingress_event(event_type) {
            continue;
        }
        match foreign_frame_contains_topic(&frame, event_type, topic) {
            Ok(true) | Err(_) => matches.push(id),
            Ok(false) => {}
        }
    }
    Ok(matches)
}

/// Like [`forget_by_topic`] but additionally emits a
/// `EVENT_TYPE_TOMBSTONE_REQUESTED` (0xF1) WAL frame recording the
/// erasure intent + expected scope. The frame is durably appended before the
/// mutation starts, so an audit failure cannot produce an unaudited erasure and
/// a later mutation failure still leaves a truthful record of the request. This
/// is the audit-anchor that survives
/// even if Phase-2 physical recompaction replaces the original
/// payload bytes — the tombstone frame proves "operator requested
/// erasure of topic X at time T, affecting N rows" and remains in
/// the WAL by design.
///
/// `source` is `"cli"` | `"gui"` | `"api"` — recorded in the payload
/// so audit consumers can attribute the request.
///
/// The connection is owned and returned deliberately: `Connection` is `Send`
/// but not `Sync`, so an async caller must not retain `&Connection` across the
/// durable WAL append.
pub async fn forget_by_topic_with_audit(
    conn: Connection,
    topic: &str,
    now_unix: i64,
    source: &str,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<(Connection, ForgetReport)> {
    let preview = preview_forget_by_topic(&conn, topic)?;
    // F67 — serialize the WHOLE preview so the tombstone intent covers EVERY
    // counted category. The actual cascade runs only after this frame has been
    // fsynced by `append`; any future report field is captured automatically.
    let payload = {
        let mut v = serde_json::to_value(&preview).context("serialize ForgetReport preview")?;
        let obj = v
            .as_object_mut()
            .expect("ForgetReport serializes to a JSON object");
        obj.insert("ts_unix".into(), serde_json::json!(now_unix));
        obj.insert("source".into(), serde_json::json!(source));
        obj.insert("phase".into(), serde_json::json!("intent"));
        serde_json::to_vec(&v).context("serialize TOMBSTONE_REQUESTED payload")?
    };
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_TOMBSTONE_REQUESTED,
        &payload,
    )
    .build();
    writer
        .append(header, payload)
        .await
        .context("append TOMBSTONE_REQUESTED WAL frame")?;
    let report = forget_by_topic_as_source(&conn, topic, now_unix, source)?;
    Ok((conn, report))
}

/// Compatibility name for the cluster-aware forget path. Every forget now
/// installs the local anti-resurrection sentinel atomically with the cascade,
/// and raw peer-ingest consults it before persisting a future frame. Keep this
/// wrapper for the earlier cluster-aware call path; there is no longer a weaker
/// public path that omits the replay guard.
pub async fn forget_by_topic_with_cluster_propagation(
    conn: Connection,
    topic: &str,
    now_unix: i64,
    source: &str,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<(Connection, ForgetReport)> {
    forget_by_topic_with_audit(conn, topic, now_unix, source, writer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;

    fn unit(v: Vec<f32>) -> Vec<f32> {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        v.into_iter().map(|x| x / n).collect()
    }

    fn seed_db() -> Connection {
        // Use the canonical store opener against a temp file so we get
        // the real v6 schema (idx_episode + idx_consolidated +
        // idx_longterm + idx_groundtruth + idx_embedding). TempDir is
        // leaked intentionally — tests share the live conn and don't
        // need the file to outlive the test.
        let temp = tempfile::tempdir().unwrap();
        let temp_db = temp.path().join("seed.db");
        let conn = store::open(&temp_db).unwrap();
        std::mem::forget(temp); // keep the dir alive for the test's lifetime
        // Hand-insert rows touching every tier so forget exercises
        // each branch.
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, 1, 'I worked at AcmeCorp', 'h1', 0.6, 0), \
                    (2, 1, 2, 'unrelated note about lunch', 'h2', 0.5, 0)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO idx_consolidated (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('summary', '2026-05-01', NULL, 'summary mentions AcmeCorp', 'h3', 0.5, 1, 0)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO idx_longterm (event_id, text, text_hash, importance, promoted_ts, last_access_ts) \
             VALUES (10, 'long-term about AcmeCorp', 'h4', 0.9, 0, 0)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth (statement, source, scope, asserted_at) \
             VALUES ('Operator worked at AcmeCorp', 'wizard', 'identity', 0), \
                    ('Operator likes pizza', 'wizard', 'identity', 0)",
            [],
        )
        .unwrap();
        let v = unit(vec![1.0, 0.0, 0.0, 0.0]);
        embeddings::upsert(&conn, "image", "AcmeCorp-logo.png", "clip", &v).unwrap();
        embeddings::upsert(&conn, "image", "vacation.png", "clip", &v).unwrap();
        conn
    }

    #[test]
    fn forget_cascade_rolls_back_on_mid_cascade_failure() {
        // GR-fix regression: the cascade is now wrapped in one transaction, so a
        // failure mid-cascade must leave the DB FULLY INTACT (not a partial wipe).
        let conn = seed_db();
        let before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_episode WHERE text LIKE '%AcmeCorp%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, 1, "precondition: the AcmeCorp episode exists");
        // Sabotage a LATE cascade leg: drop a table that a delete AFTER the early
        // idx_episode delete targets, so the cascade fails mid-flight.
        conn.execute("DROP TABLE idx_profile_outbox", []).unwrap();
        let r = forget_by_topic(&conn, "AcmeCorp", 0);
        assert!(
            r.is_err(),
            "a mid-cascade DB error must surface as Err, not a silent partial wipe"
        );
        // The transaction rolled back → the early idx_episode delete is undone.
        let after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_episode WHERE text LIKE '%AcmeCorp%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            after, 1,
            "rollback: the AcmeCorp episode must survive a failed cascade (no partial erasure)"
        );
    }

    #[test]
    fn forget_report_audit_payload_covers_every_category() {
        // F67 — the tombstone audit frame serializes the WHOLE ForgetReport, so
        // every counted category is provable (the old hand-built payload listed
        // only 6 of 12). This guards the payload-completeness contract.
        let report = ForgetReport {
            people_rows: 3,
            contradiction_rows: 1,
            ..Default::default()
        };
        let v = serde_json::to_value(&report).unwrap();
        let obj = v.as_object().unwrap();
        for k in [
            "episode_rows",
            "consolidated_rows",
            "longterm_rows",
            "raw_turn_rows",
            "groundtruth_revoked",
            "embedding_rows",
            "profile_rows",
            "profile_pending_rows",
            "profile_outbox_rows",
            "entity_rows",
            "relation_rows",
            "link_rows",
            "contradiction_rows",
            "foreign_event_rows",
            "people_rows",
            "topic",
        ] {
            assert!(obj.contains_key(k), "audit payload missing category: {k}");
        }
        assert_eq!(obj["people_rows"], 3);
    }

    #[test]
    fn forget_by_topic_cascades_into_people_json() {
        // D4 (GDPR) — forget cascades into ~/.neoth/people.json (next to the
        // conn's views.db, resolved via conn.path().parent()).
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let people = crate::memory::people::People {
            schema_version: crate::memory::people::PEOPLE_SCHEMA_VERSION,
            rows: vec![crate::memory::people::PersonStat {
                person_key: "k".into(),
                channel: "telegram".into(),
                display: Some("Alice AcmeCorp".into()),
                interaction_count: 1.0,
                reply_to_bot_count: 0.0,
                msg_len_total: 10.0,
                last_seen_unix: 1,
                decay_anchor_unix: 1,
            }],
        };
        crate::memory::people::save_people(dir.path(), &people).unwrap();
        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        assert_eq!(preview.people_rows, 1);
        let report = forget_by_topic(&conn, "AcmeCorp", 1_700_000_000).unwrap();
        assert_eq!(preview, report, "preview must match confirmed cascade");
        assert_eq!(
            report.people_rows, 1,
            "people.json row erased via the cascade"
        );
        assert!(
            crate::memory::people::load_people(dir.path())
                .rows
                .is_empty()
        );
    }

    #[test]
    fn forget_topic_wipes_all_tiers_plus_revokes_groundtruth() {
        let conn = seed_db();
        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        let report = forget_by_topic(&conn, "AcmeCorp", 1_700_000_000).unwrap();
        assert_eq!(preview, report, "preview must match confirmed cascade");
        assert_eq!(report.episode_rows, 1, "exactly the AcmeCorp episode");
        assert_eq!(report.consolidated_rows, 1);
        assert_eq!(report.longterm_rows, 1);
        assert_eq!(report.groundtruth_revoked, 1);
        assert_eq!(
            report.embedding_rows, 1,
            "logo embedding wiped, vacation kept"
        );
        assert_eq!(report.total(), 5);
    }

    /// GR-165: channel-ingested embeddings carry the opaque
    /// "channel:chat_id:sender_id:ts" source_ref that a `%topic%` pattern
    /// can never match — the cascade must derive (channel, sender_id)
    /// from the matching episode rows and wipe those vectors too.
    #[test]
    fn forget_wipes_channel_side_embeddings_by_sender() {
        let conn = seed_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts, channel, sender_id) \
             VALUES (3, 1, 3, 'whatsapp message about AcmeCorp', 'h5', 0.7, 0, 'whatsapp', '987654321')",
            [],
        ).unwrap();
        let v = unit(vec![0.0, 1.0, 0.0, 0.0]);
        embeddings::upsert(
            &conn,
            "image",
            "whatsapp:442071234:987654321:1717000000",
            "clip",
            &v,
        )
        .unwrap();
        // Different sender on another channel — must survive.
        embeddings::upsert(&conn, "image", "telegram:1:555:1717000001", "clip", &v).unwrap();

        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        assert_eq!(preview.embedding_rows, 2);
        let report = forget_by_topic(&conn, "AcmeCorp", 1_700_000_000).unwrap();
        assert_eq!(
            report.embedding_rows, 2,
            "path-keyed logo + channel-keyed whatsapp embedding wiped"
        );
        let left: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_embedding", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 2, "vacation.png + telegram embedding survive");
    }

    #[test]
    fn forget_cascades_into_raw_transcript_turns() {
        // GOLD-ADAPT-ODY-26 (review fix): the raw_turns transcript table is
        // FTS-searchable via `neoth recall --transcript`. A forget must wipe
        // matching turns (else the full prompt/response text stays recoverable
        // — a GDPR right-to-erasure hole). The raw_turns_ad DELETE trigger keeps
        // raw_turns_fts in sync, so the FTS search stops surfacing it too.
        use crate::memory::transcript_store::{insert_turn, search_turns};
        let conn = seed_db();
        insert_turn(
            &conn,
            "sess-1",
            "operator",
            1,
            "tell me about AcmeCorp earnings",
        )
        .unwrap();
        insert_turn(
            &conn,
            "sess-1",
            "agent",
            2,
            "AcmeCorp posted a loss last quarter",
        )
        .unwrap();
        insert_turn(&conn, "sess-1", "operator", 3, "what's for lunch today").unwrap();

        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        assert_eq!(preview.raw_turn_rows, 2);
        let report = forget_by_topic(&conn, "AcmeCorp", 1_700_000_000).unwrap();
        assert_eq!(report.raw_turn_rows, 2, "both AcmeCorp turns wiped");

        // FTS no longer surfaces the topic (DELETE trigger synced raw_turns_fts).
        assert!(
            search_turns(&conn, "AcmeCorp", 0, 10).unwrap().is_empty(),
            "forgotten topic must not survive in raw_turns_fts"
        );
        // Unrelated turn untouched + still searchable.
        let left: i64 = conn
            .query_row("SELECT COUNT(*) FROM raw_turns", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1, "the unrelated lunch turn survives");
        assert_eq!(
            search_turns(&conn, "lunch", 0, 10).unwrap().len(),
            1,
            "unrelated turn still searchable"
        );
    }

    #[test]
    fn forget_leaves_unrelated_rows_intact() {
        let conn = seed_db();
        forget_by_topic(&conn, "AcmeCorp", 1_700_000_000).unwrap();
        let lunch: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_episode WHERE text LIKE '%lunch%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lunch, 1, "unrelated episode must survive");
        let pizza: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_groundtruth WHERE statement LIKE '%pizza%' AND revoked_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pizza, 1, "unrelated groundtruth must stay active");
    }

    #[test]
    fn forget_empty_topic_errors() {
        let conn = seed_db();
        let err = forget_by_topic(&conn, "   ", 0).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn forget_zero_matches_returns_zero_report() {
        let conn = seed_db();
        let report = forget_by_topic(&conn, "NoSuchThing", 0).unwrap();
        assert_eq!(report.total(), 0);
        assert_eq!(report.topic, "NoSuchThing");
    }

    #[test]
    fn forget_escapes_like_wildcards_no_mass_delete() {
        // GOLD-SEC-04 / A-08: a topic of `%` must be a LITERAL, not a
        // wildcard — otherwise it would wipe the entire memory store.
        let conn = seed_db();
        let report = forget_by_topic(&conn, "%", 0).unwrap();
        assert_eq!(
            report.total(),
            0,
            "`%` must match literally, not everything"
        );
        // The real rows are untouched.
        let episodes: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_episode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(episodes, 2, "no episode may be deleted by a `%` topic");
        // `_` is also escaped (would otherwise match any single char).
        let report_underscore = forget_by_topic(&conn, "_", 0).unwrap();
        assert_eq!(report_underscore.total(), 0);
    }

    #[test]
    fn forget_cascades_to_idx_profile() {
        // GOLD-SEC-28 / CR-007: structured profile claims about the topic
        // must be erased too.
        let conn = seed_db();
        conn.execute(
            "INSERT INTO idx_profile (extraction_id, event_id, field, value_json, confidence, applied_at) \
             VALUES ('x1', 1, 'identity.employer', '\"AcmeCorp\"', 0.9, 0), \
                    ('x2', 2, 'identity.food', '\"pizza\"', 0.9, 0)",
            [],
        )
        .unwrap();
        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        assert_eq!(preview.profile_rows, 1);
        let report = forget_by_topic(&conn, "AcmeCorp", 0).unwrap();
        assert_eq!(
            report.profile_rows, 1,
            "the AcmeCorp profile claim is deleted"
        );
        let acme: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_profile WHERE value_json LIKE '%AcmeCorp%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(acme, 0, "no AcmeCorp profile claim survives erasure");
        let pizza: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_profile WHERE value_json LIKE '%pizza%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pizza, 1, "unrelated profile claim survives");
    }

    #[test]
    fn forget_cascades_to_in_flight_pending_and_outbox_gold_sec_28() {
        // GOLD-SEC-28 — a pending delta or a queued outbox frame mentioning the
        // topic would re-materialise the forgotten data when later applied /
        // written; erasure must cover both (delta_json TEXT + payload BLOB).
        let conn = seed_db();
        conn.execute(
            "INSERT INTO idx_profile_pending (extraction_id, delta_json, claim_count, created_at_unix) \
             VALUES ('p1', '{\"field\":\"identity.employer\",\"value\":\"AcmeCorp\"}', 1, 0), \
                    ('p2', '{\"field\":\"identity.food\",\"value\":\"pizza\"}', 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_profile_outbox (extraction_id, event_type, payload, enqueued_at) \
             VALUES ('p1', 1, CAST('claim about AcmeCorp' AS BLOB), 0), \
                    ('p2', 1, CAST('claim about pizza' AS BLOB), 0)",
            [],
        )
        .unwrap();

        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        assert_eq!(preview.profile_pending_rows, 1);
        assert_eq!(preview.profile_outbox_rows, 1);
        let report = forget_by_topic(&conn, "AcmeCorp", 0).unwrap();
        assert_eq!(
            report.profile_pending_rows, 1,
            "pending AcmeCorp delta deleted"
        );
        assert_eq!(
            report.profile_outbox_rows, 1,
            "outbox AcmeCorp frame deleted"
        );

        let pending_left: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_profile_pending", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pending_left, 1, "unrelated pending delta survives");
        let outbox_left: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_profile_outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(outbox_left, 1, "unrelated outbox frame survives");
        let acme_pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_profile_pending WHERE delta_json LIKE '%AcmeCorp%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            acme_pending, 0,
            "no AcmeCorp pending delta survives erasure"
        );
    }

    #[test]
    fn forget_purges_matching_raw_foreign_frames_and_installs_sentinel() {
        let conn = seed_db();
        let insert_frame = |seq: i64, event_type: u8, payload: serde_json::Value| {
            let payload = serde_json::to_vec(&payload).unwrap();
            let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
            let frame = crate::wal::frame::encode_frame(&header, &payload);
            conn.execute(
                "INSERT INTO idx_foreign_events \
                 (origin_peer_pk, origin_seq, event_type, payload, received_at) \
                 VALUES ('peer', ?1, ?2, ?3, 1)",
                rusqlite::params![seq, event_type as i64, frame],
            )
            .unwrap();
        };
        insert_frame(
            1,
            crate::wal::events::EVENT_TYPE_RAW_TEXT,
            serde_json::json!({"text": "AcmeCorp peer memory"}),
        );
        insert_frame(
            2,
            crate::wal::events::EVENT_TYPE_RAW_TEXT,
            serde_json::json!({"text": "unrelated peer memory"}),
        );
        // A metadata-only replication event is not arbitrary text and must not
        // be deleted merely because a crafted test payload contains the topic.
        insert_frame(
            3,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            serde_json::json!({"note": "AcmeCorp", "event_id": 1, "importance": 0.8}),
        );

        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        assert_eq!(preview.foreign_event_rows, 1);
        let report = forget_by_topic(&conn, "AcmeCorp", 1_700).unwrap();
        assert_eq!(report.foreign_event_rows, 1);
        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM idx_foreign_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 2);
        let sentinel =
            crate::profile::redaction::lookup_active(&conn, &tombstone_sentinel_field("AcmeCorp"))
                .unwrap()
                .expect("every forget installs its anti-resurrection sentinel");
        assert!(sentinel.never_recreate);
    }

    #[test]
    fn forget_erases_restricted_vault_chunks() {
        // External review PR4-002: `idx_restricted` carries free statement text
        // from the operator's vault and NO path in the tree deleted from it, so
        // a right-to-erasure forget left the topic physically on disk — and
        // `promote_restricted` can lift it back into live recall.
        let conn = seed_db();
        crate::memory::groundtruth::insert_restricted(
            &conn,
            "Alexa Muster lives in Bonn",
            "vault-notes",
            "people",
            "personal-data",
            1_000,
        )
        .unwrap();
        crate::memory::groundtruth::insert_restricted(
            &conn,
            "unrelated statement",
            "vault-notes",
            "people",
            "personal-data",
            1_000,
        )
        .unwrap();

        let preview = preview_forget_by_topic(&conn, "Alexa Muster").unwrap();
        assert_eq!(
            preview.restricted_rows, 1,
            "the preview must not under-report what the confirmed forget erases"
        );

        let report = forget_by_topic(&conn, "Alexa Muster", 2_000).unwrap();
        assert_eq!(report.restricted_rows, 1);
        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_restricted WHERE statement LIKE '%Alexa Muster%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "the forgotten statement must be gone on disk");
        let untouched: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_restricted", [], |row| row.get(0))
            .unwrap();
        assert_eq!(untouched, 1, "unrelated chunks must survive");
    }

    #[test]
    fn forget_preview_matches_graph_cascades_without_mutating() {
        let conn = seed_db();
        conn.execute(
            "INSERT INTO idx_entities (id, name, entity_type, attributes) VALUES \
             (100, 'AcmeCorp', 'company', '{}'), (101, 'Alice', 'person', '{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_relations (id, src_id, dst_id, relation) \
             VALUES (200, 101, 100, 'works_at')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_memory_links (lo_id, hi_id, weight, last_co_access) \
             VALUES (1, 2, 1.0, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_contradictions (fact_a_id, fact_b_id, confidence, detected_at) \
             VALUES (1, 2, 0.9, 0)",
            [],
        )
        .unwrap();

        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        assert_eq!(preview.entity_rows, 1);
        assert_eq!(preview.relation_rows, 1);
        assert_eq!(preview.link_rows, 1);
        assert_eq!(preview.contradiction_rows, 1);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM idx_entities", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            2,
            "preview must be read-only"
        );

        let report = forget_by_topic(&conn, "AcmeCorp", 1_700).unwrap();
        assert_eq!(
            preview, report,
            "preview must match confirmed graph cascade"
        );
    }

    #[test]
    fn forget_removes_links_for_matching_warm_and_cold_memories() {
        let conn = seed_db();
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('retained', '2026-05-02', 3, 'warm AcmeCorp memory', 'h5', 0.7, 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_memory_links (lo_id, hi_id, weight, last_co_access) VALUES \
             (1, 2, 1.0, 0), (2, 3, 1.0, 0), (2, 10, 1.0, 0)",
            [],
        )
        .unwrap();

        let preview = preview_forget_by_topic(&conn, "AcmeCorp").unwrap();
        assert_eq!(preview.link_rows, 3, "all three tier endpoints are visible");

        let report = forget_by_topic(&conn, "AcmeCorp", 1_700).unwrap();
        assert_eq!(report.link_rows, 3);
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_memory_links", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 0, "no warm/cold association endpoint may dangle");
    }

    #[tokio::test]
    async fn forget_with_audit_emits_tombstone_wal_frame() {
        use crate::wal::events::EVENT_TYPE_TOMBSTONE_REQUESTED;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;
        use tokio::fs::read;

        let conn = seed_db();
        let dir = tempdir().unwrap();
        let seg = dir.path().join("tombstone.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();

        let (_conn, report) = forget_by_topic_with_audit(conn, "AcmeCorp", 1700, "cli", &writer)
            .await
            .unwrap();
        assert!(
            report.episode_rows >= 1,
            "expected at least one episode wipe"
        );

        drop(writer);
        let _ = join.await;

        // Walk the WAL — first frame after the SegmentHeader must be
        // the TOMBSTONE_REQUESTED audit anchor.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut found = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == EVENT_TYPE_TOMBSTONE_REQUESTED {
                let p: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                found = Some(p);
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let payload = found.expect("TOMBSTONE_REQUESTED frame must be present");
        assert_eq!(payload["topic"], "AcmeCorp");
        assert_eq!(payload["source"], "cli");
        assert_eq!(payload["ts_unix"], 1700);
        assert_eq!(payload["phase"], "intent");
        assert!(payload["episode_rows"].as_i64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn audit_failure_prevents_the_forget_mutation() {
        use crate::wal::writer::spawn;

        let conn = seed_db();
        let before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM idx_episode WHERE text LIKE '%AcmeCorp%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(before > 0);
        let observer = Connection::open(conn.path().expect("seed database path")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let (writer, join) = spawn(dir.path().join("closed.wal")).unwrap();
        join.abort();
        let _ = join.await;

        let error = forget_by_topic_with_audit(conn, "AcmeCorp", 1700, "cli", &writer)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("append TOMBSTONE_REQUESTED"),
            "unexpected error: {error:#}"
        );
        let after: i64 = observer
            .query_row(
                "SELECT COUNT(*) FROM idx_episode WHERE text LIKE '%AcmeCorp%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            after, before,
            "no row may be erased without its audit intent"
        );
    }

    // ── Concern-2 (Session 24) tombstone sentinel + cluster path ──────

    #[test]
    fn tombstone_sentinel_field_lowercases_and_prefixes() {
        // Case-collapse is the spec: forget("Berlin") and
        // forget("BERLIN") + forget("berlin") all collapse to the
        // SAME sentinel so the UNIQUE active-redaction index dedupes
        // repeat-forgets cleanly.
        assert_eq!(tombstone_sentinel_field("Berlin"), "_tombstone.berlin");
        assert_eq!(tombstone_sentinel_field("BERLIN"), "_tombstone.berlin");
        assert_eq!(tombstone_sentinel_field("  berlin  "), "_tombstone.berlin");
    }

    #[test]
    fn is_tombstone_sentinel_recognises_only_prefixed_fields() {
        assert!(is_tombstone_sentinel("_tombstone.berlin"));
        assert!(is_tombstone_sentinel("_tombstone."));
        assert!(!is_tombstone_sentinel("identity.name"));
        assert!(!is_tombstone_sentinel("skills.rust"));
        assert!(!is_tombstone_sentinel(""));
        // Drift guard: a future profile-field starting with `_` is
        // NOT a tombstone unless it matches the full prefix.
        assert!(!is_tombstone_sentinel("_private.x"));
    }

    #[test]
    fn topic_from_sentinel_extracts_or_returns_none() {
        assert_eq!(topic_from_sentinel("_tombstone.berlin"), Some("berlin"));
        assert_eq!(topic_from_sentinel("_tombstone."), Some(""));
        assert_eq!(topic_from_sentinel("identity.name"), None);
    }

    #[tokio::test]
    async fn cluster_propagation_writes_sentinel_redaction_alongside_wipe() {
        use crate::wal::events::EVENT_TYPE_TOMBSTONE_REQUESTED;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;
        use tokio::fs::read;

        let conn = seed_db();
        let dir = tempdir().unwrap();
        let seg = dir.path().join("cluster.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();

        let (conn, report) =
            forget_by_topic_with_cluster_propagation(conn, "AcmeCorp", 1700, "cli", &writer)
                .await
                .unwrap();
        assert!(
            report.episode_rows >= 1,
            "local wipe must still happen (Concern-2 layers ON TOP of forget_with_audit)",
        );

        // Sentinel redaction landed.
        let sentinel_field = tombstone_sentinel_field("AcmeCorp");
        let row = crate::profile::redaction::lookup_active(&conn, &sentinel_field)
            .unwrap()
            .expect("sentinel redaction must be present after cluster propagation");
        assert!(
            row.never_recreate,
            "sentinel redaction must carry never_recreate=true so claim-guard blocks future deltas",
        );

        drop(writer);
        let _ = join.await;

        // 0xF1 audit frame still emitted (layered ON TOP, not instead).
        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut found_0xf1 = false;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == EVENT_TYPE_TOMBSTONE_REQUESTED {
                found_0xf1 = true;
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        assert!(
            found_0xf1,
            "cluster-propagation variant must STILL emit the 0xF1 audit anchor",
        );
    }

    #[tokio::test]
    async fn cluster_propagation_is_idempotent_on_repeat_forget() {
        // Operator runs forget("X"), then forget("X") again. The
        // sentinel UNIQUE active-redaction index would reject the
        // second insert; the function must swallow that as "already
        // tombstoned" not propagate as an error.
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let conn = seed_db();
        let dir = tempdir().unwrap();
        let seg = dir.path().join("cluster-repeat.wal");
        let (writer, join) = spawn(seg).unwrap();

        let (conn, _) =
            forget_by_topic_with_cluster_propagation(conn, "AcmeCorp", 1700, "cli", &writer)
                .await
                .expect("first call");
        // Second call must NOT bail with a UNIQUE constraint Err.
        let (conn, report2) =
            forget_by_topic_with_cluster_propagation(conn, "AcmeCorp", 1800, "cli", &writer)
                .await
                .expect("second call must be idempotent");
        // Second call's local-wipe rows are 0 because the first call
        // already wiped them — but no Err.
        assert_eq!(report2.episode_rows, 0);
        // Sentinel still exactly one active row (UNIQUE index).
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_profile_redactions \
                 WHERE field = ?1 AND revoked_at IS NULL",
                rusqlite::params![tombstone_sentinel_field("AcmeCorp")],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "exactly one active sentinel after repeat forget");

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn cluster_propagation_case_collapses_topic_for_sentinel_dedup() {
        // forget("Berlin") followed by forget("berlin") must produce
        // ONE sentinel — case-collapse + dedup contract pinned.
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let conn = seed_db();
        let dir = tempdir().unwrap();
        let seg = dir.path().join("cluster-case.wal");
        let (writer, join) = spawn(seg).unwrap();

        let (conn, _) =
            forget_by_topic_with_cluster_propagation(conn, "Berlin", 100, "cli", &writer)
                .await
                .unwrap();
        let (conn, _) =
            forget_by_topic_with_cluster_propagation(conn, "berlin", 200, "cli", &writer)
                .await
                .unwrap();
        let (conn, _) =
            forget_by_topic_with_cluster_propagation(conn, "BERLIN", 300, "cli", &writer)
                .await
                .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_profile_redactions \
                 WHERE field = '_tombstone.berlin' AND revoked_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "case-collapse + dedup must yield ONE sentinel");

        drop(writer);
        let _ = join.await;
    }
}
