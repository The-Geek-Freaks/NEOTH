//! GDPR retroactive forgetting — C-15.
//!
//! "Forget X" is structurally different from Hebbian decay:
//!   - **Decay** is probabilistic + slow (years to drop below
//!     FORGET_FLOOR without reinforcement); driven by
//!     `consolidate.rs::run_consolidation_pass`.
//!   - **Forget** is explicit, immediate, transactional,
//!     operator-initiated when DSGVO / personal request demands it.
//!
//! ## What this module does today (v0.1.x)
//!
//! The shipped path is **SQLite-only**: cascade-delete across the
//! four memory-tier views + the embedding store, revoke ground-truth
//! rows. The operator's recall queries stop surfacing the topic
//! immediately.
//!
//! ## What it does NOT do yet (Phase 2)
//!
//! WAL tombstone frames + HMAC recompaction is **deferred**. The
//! original RAW_TEXT WAL events still contain the topic on disk; the
//! SQLite indexes no longer point at them, but a low-level WAL reader
//! can still see the original frames. Per the AD-4 decision logged in
//! `PLAN/FEATURE_EVAL.md`, the intent is to replace those payload bytes
//! with a TOMBSTONE frame and recompute the HMAC chain over the
//! tombstone — that keeps the audit trail tamper-evident while making
//! the content unrecoverable. Implementation lives in
//! `wal::compaction::rewrite_with_tombstone` once it ships.
//!
//! Operators who need full WAL-layer wipe today should run
//! `neoth backup` first, then `neoth memory --forget` for the SQLite
//! wipe, then manually delete the WAL segments containing the topic
//! (or wait for Phase 2). For most GDPR use cases the SQLite wipe is
//! sufficient because all operator-visible paths (recall, chat,
//! Obsidian sync) read from SQLite, not directly from WAL.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::memory::embeddings;

/// What was deleted by a single `forget` call. Returned for the audit
/// trail + the operator's confirm summary.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct ForgetReport {
    pub episode_rows: i64,
    pub consolidated_rows: i64,
    pub longterm_rows: i64,
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
    pub topic: String,
}

impl ForgetReport {
    pub fn total(&self) -> i64 {
        self.episode_rows
            + self.consolidated_rows
            + self.longterm_rows
            + self.groundtruth_revoked
            + self.embedding_rows
            + self.profile_rows
            + self.profile_pending_rows
            + self.profile_outbox_rows
    }
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
    if topic.trim().is_empty() {
        anyhow::bail!(
            "forget: topic must be non-empty (use `neoth memory purge` for a wholesale wipe)"
        );
    }
    // Escape LIKE wildcards so a topic of `%`/`_` matches literally —
    // otherwise `forget "%"` would wipe every row (GOLD-SEC-04 / A-08).
    // Every LIKE below pairs the pattern with `ESCAPE '\'`.
    let pattern = format!("%{}%", crate::memory::escape_like(topic));

    let episode_rows = conn
        .execute(
            "DELETE FROM idx_episode WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_episode")? as i64;

    let consolidated_rows = conn
        .execute(
            "DELETE FROM idx_consolidated WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_consolidated")? as i64;

    let longterm_rows = conn
        .execute(
            "DELETE FROM idx_longterm WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_longterm")? as i64;

    // Structured-profile claims: hard delete any claim whose field name OR
    // value mentions the topic. GDPR right-to-erasure cascade (GOLD-SEC-28
    // / CR-007) — `forget` previously skipped idx_profile, leaving the
    // operator's extracted claims about the topic on disk.
    let profile_rows = conn
        .execute(
            "DELETE FROM idx_profile \
             WHERE field COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
                OR value_json COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_profile")? as i64;

    // Ground-truth: revoke instead of delete. The row itself stays for
    // audit (operator can prove they didn't assert X after revocation),
    // but recall queries filter on `revoked_at IS NULL` so it stops
    // surfacing.
    let groundtruth_revoked = conn
        .execute(
            "UPDATE idx_groundtruth \
             SET revoked_at = ?1 \
             WHERE revoked_at IS NULL AND statement COLLATE NOCASE LIKE ?2 ESCAPE '\\'",
            rusqlite::params![now_unix, pattern],
        )
        .context("revoke idx_groundtruth")? as i64;

    // GOLD-SEC-28 — in-flight profile extractions. A pending delta or a queued
    // outbox frame mentioning the topic would re-materialise the forgotten data
    // when it's later applied / written, so the erasure must cover them too.
    // `delta_json` is TEXT; the outbox `payload` is a BLOB → CAST to TEXT so the
    // topic substring is matched byte-for-byte.
    let profile_pending_rows = conn
        .execute(
            "DELETE FROM idx_profile_pending WHERE delta_json COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_profile_pending")? as i64;

    let profile_outbox_rows = conn
        .execute(
            "DELETE FROM idx_profile_outbox \
             WHERE CAST(payload AS TEXT) COLLATE NOCASE LIKE ?1 ESCAPE '\\'",
            rusqlite::params![pattern],
        )
        .context("delete from idx_profile_outbox")? as i64;

    // Embeddings: hard delete. Vectors carry no audit value — they're
    // a derived index, not an assertion.
    let embedding_rows =
        embeddings::wipe_by_source_ref_pattern(conn, &pattern).context("wipe idx_embedding")?;

    Ok(ForgetReport {
        episode_rows,
        consolidated_rows,
        longterm_rows,
        groundtruth_revoked,
        embedding_rows,
        profile_rows,
        profile_pending_rows,
        profile_outbox_rows,
        topic: topic.to_string(),
    })
}

/// Concern-2 fix (Session 24) — sentinel-redaction name prefix.
///
/// `forget_by_topic_with_cluster_propagation` writes a row into
/// `idx_profile_redactions` with `field = "{TOMBSTONE_SENTINEL_PREFIX}{topic_lowercase}"`
/// alongside the SQLite wipe + 0xF1 WAL frame. This sentinel row:
///
/// - Is NOT a real profile field — the `_tombstone.` namespace
///   never collides with operator dot-paths like `identity.name`
///   or `skills.rust`.
/// - Carries `never_recreate = true` so the existing claim-guard
///   path (`ProfileClaimGuard::check_all`) hard-rejects any future
///   extraction that mentions the topic, even on this node.
/// - Will be the source of truth the gossip-receive path consults
///   when the cluster ships (Phase 5+): an inbound episode/profile
///   frame whose text matches an active `_tombstone.<topic>` row
///   gets dropped instead of replayed.
///
/// Choosing the sentinel namespace (rather than a new table)
/// reuses the existing redaction registry's UNIQUE-active index +
/// the cluster-replication that `idx_profile_redactions` gets for
/// free when cluster gossip lands.
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
/// `idx_profile_redactions`). The cluster gossip-receive path will
/// pre-filter inbound frames by checking every active redaction's
/// `is_tombstone_sentinel(field)` flag before replaying.
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

/// Like [`forget_by_topic`] but additionally emits a
/// `EVENT_TYPE_TOMBSTONE_REQUESTED` (0xF1) WAL frame recording the
/// erasure intent + scope. This is the audit-anchor that survives
/// even if Phase-2 physical recompaction replaces the original
/// payload bytes — the tombstone frame proves "operator requested
/// erasure of topic X at time T, affecting N rows" and remains in
/// the WAL by design.
///
/// `source` is `"cli"` | `"gui"` | `"api"` — recorded in the payload
/// so audit consumers can attribute the request.
pub async fn forget_by_topic_with_audit(
    conn: &Connection,
    topic: &str,
    now_unix: i64,
    source: &str,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<ForgetReport> {
    let report = forget_by_topic(conn, topic, now_unix)?;
    let payload = serde_json::to_vec(&serde_json::json!({
        "topic": report.topic,
        "episode_rows": report.episode_rows,
        "consolidated_rows": report.consolidated_rows,
        "longterm_rows": report.longterm_rows,
        "groundtruth_revoked": report.groundtruth_revoked,
        "embedding_rows": report.embedding_rows,
        "profile_rows": report.profile_rows,
        "ts_unix": now_unix,
        "source": source,
    }))
    .context("serialize TOMBSTONE_REQUESTED payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_TOMBSTONE_REQUESTED,
        &payload,
    )
    .build();
    writer
        .append(header, payload)
        .await
        .context("append TOMBSTONE_REQUESTED WAL frame")?;
    Ok(report)
}

/// Concern-2 fix (Session 24) — cluster-aware variant of
/// [`forget_by_topic_with_audit`]. Same SQLite wipe + 0xF1 WAL
/// emit, PLUS writes a sentinel redaction row
/// `_tombstone.<topic>` (via [`crate::profile::redaction::add`])
/// with `never_recreate = true`. The sentinel:
///
/// 1. Blocks LOCAL re-extraction immediately — the existing
///    `ProfileClaimGuard::check_all` rejects any future delta
///    containing the topic.
/// 2. Will be the source of truth the cluster gossip-receive
///    path checks (Phase 5+) before replaying any inbound
///    episode/profile frame. A `_tombstone.berlin` row on
///    node A prevents node B's buffered "Berlin" episodes
///    from being re-applied when B reconnects.
///
/// The pre-existing `forget_by_topic_with_audit` stays for the
/// pure-local path; this new variant is the right choice anywhere
/// the operator may be running cluster mode (now or in future).
///
/// Idempotency: a repeat call against the same topic is a no-op
/// for the sentinel (the UNIQUE active-redaction index drops the
/// duplicate insert silently) but still re-wipes any new SQLite
/// rows that match + still emits a fresh 0xF1 audit frame.
pub async fn forget_by_topic_with_cluster_propagation(
    conn: &Connection,
    topic: &str,
    now_unix: i64,
    source: &str,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<ForgetReport> {
    // 1. Local wipe + 0xF1 WAL frame — the existing audit-anchored path.
    let report = forget_by_topic_with_audit(conn, topic, now_unix, source, writer).await?;

    // 2. Sentinel redaction. Idempotent via the UNIQUE active-redaction
    //    index; a duplicate insert returns an Err that we deliberately
    //    swallow because "tombstone already present" is the desired
    //    end-state. Any OTHER error (e.g. schema missing) propagates
    //    so the caller sees a real problem.
    let field = tombstone_sentinel_field(topic);
    let reason =
        format!("forget_by_topic_with_cluster_propagation at ts_unix={now_unix} (source={source})");
    match crate::profile::redaction::add(
        conn,
        &field,
        /*never_recreate=*/ true,
        Some(&reason),
        source,
        now_unix,
    ) {
        Ok(_id) => {
            tracing::info!(
                topic = %topic,
                field = %field,
                "Concern-2: tombstone sentinel redaction written; future re-extraction blocked",
            );
        }
        Err(e) => {
            // The UNIQUE active-redaction index path. Distinguish
            // "already present" (fine) from any other DB error.
            // anyhow wraps the rusqlite error in a `with_context`
            // chain — walk the chain so the UNIQUE-violation match
            // catches the underlying SQLite error message regardless
            // of how many context layers anyhow added on top.
            let is_unique_violation = e.chain().any(|err| {
                let msg = err.to_string();
                msg.contains("UNIQUE") || msg.contains("constraint failed")
            });
            if !is_unique_violation {
                return Err(e).context("write tombstone sentinel redaction");
            }
            tracing::debug!(
                topic = %topic,
                field = %field,
                "Concern-2: tombstone sentinel already active (repeat forget) — no-op",
            );
        }
    }

    Ok(report)
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
    fn forget_topic_wipes_all_tiers_plus_revokes_groundtruth() {
        let conn = seed_db();
        let report = forget_by_topic(&conn, "AcmeCorp", 1_700_000_000).unwrap();
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
        assert_eq!(report.total(), 0, "`%` must match literally, not everything");
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
        let report = forget_by_topic(&conn, "AcmeCorp", 0).unwrap();
        assert_eq!(report.profile_rows, 1, "the AcmeCorp profile claim is deleted");
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

        let report = forget_by_topic(&conn, "AcmeCorp", 0).unwrap();
        assert_eq!(report.profile_pending_rows, 1, "pending AcmeCorp delta deleted");
        assert_eq!(report.profile_outbox_rows, 1, "outbox AcmeCorp frame deleted");

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
        assert_eq!(acme_pending, 0, "no AcmeCorp pending delta survives erasure");
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

        let report = forget_by_topic_with_audit(&conn, "AcmeCorp", 1700, "cli", &writer)
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
        assert!(payload["episode_rows"].as_i64().unwrap() >= 1);
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

        let report =
            forget_by_topic_with_cluster_propagation(&conn, "AcmeCorp", 1700, "cli", &writer)
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

        forget_by_topic_with_cluster_propagation(&conn, "AcmeCorp", 1700, "cli", &writer)
            .await
            .expect("first call");
        // Second call must NOT bail with a UNIQUE constraint Err.
        let report2 =
            forget_by_topic_with_cluster_propagation(&conn, "AcmeCorp", 1800, "cli", &writer)
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

        forget_by_topic_with_cluster_propagation(&conn, "Berlin", 100, "cli", &writer)
            .await
            .unwrap();
        forget_by_topic_with_cluster_propagation(&conn, "berlin", 200, "cli", &writer)
            .await
            .unwrap();
        forget_by_topic_with_cluster_propagation(&conn, "BERLIN", 300, "cli", &writer)
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
