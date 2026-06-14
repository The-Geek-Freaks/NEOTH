//! M-07 sibling — ground-truth + forget cooperation.
//!
//! Unit tests cover groundtruth + forget in isolation; this file
//! pins the cross-module behaviour that mid-2025 audits flagged:
//!
//! - **Forget does NOT touch ground truth.** SPEC GT-3 makes
//!   `idx_groundtruth` decay-immune; forget-by-topic must respect
//!   that boundary even when the topic matches a ground-truth
//!   statement. Pre-rule a refactor that broadened the forget WHERE
//!   clause could silently wipe operator-asserted facts; this test
//!   makes that regression loud.
//! - **Revocation hides from recall surface but keeps the row.**
//!   `revoke_at` is set, the row remains queryable by id for
//!   forensic reasons, but `surface_for_recall` + `count_active`
//!   exclude it. Mirrors the `superseded_at` pattern in
//!   `idx_profile` so the two contracts stay coherent.
//! - **Insert rejects whitespace-only statements.** Boundary input
//!   validation; the unit test already pins it but the integration
//!   surface is what `neoth groundtruth add ""` exercises.

use neothd::memory::forget::forget_by_topic;
use neothd::memory::groundtruth::{
    Source, count_active, insert as insert_gt, revoke, surface_for_recall,
};
use neothd::memory::store;
use rusqlite::params;

fn seed_episode_with_topic(conn: &rusqlite::Connection, event_id: i64, text: &str) {
    conn.execute(
        "INSERT INTO idx_episode \
         (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
         VALUES (?1, 1, 0, ?2, 'h', 0.5, 0)",
        params![event_id, text],
    )
    .unwrap();
}

#[test]
fn forget_topic_revokes_matching_groundtruth_but_keeps_row_addressable() {
    // The operator stored "my city is Berlin" as ground truth. They
    // later run `neoth memory --forget Berlin` to GDPR-wipe every
    // mention. Contract (see `memory/forget.rs` doc): ground-truth
    // rows are REVOKED (not deleted) so the immutability invariant
    // holds — recall stops surfacing them, but the row remains in
    // the table with `revoked_at` populated so the audit trail can
    // prove "operator asserted X, then erased X at T".
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();

    let gt_id = insert_gt(&conn, "my city is Berlin", &Source::Onboarding, "self", 0).unwrap();
    // Unrelated ground truth must survive untouched.
    let other_id = insert_gt(
        &conn,
        "my favourite editor is Vim",
        &Source::Onboarding,
        "preferences",
        0,
    )
    .unwrap();
    // Two episodes mention Berlin too.
    seed_episode_with_topic(&conn, 1, "I went to Berlin yesterday");
    seed_episode_with_topic(&conn, 2, "Berlin is cold in winter");
    seed_episode_with_topic(&conn, 3, "unrelated chatter");

    let report = forget_by_topic(&conn, "Berlin", 1_700_000_000).unwrap();
    assert!(report.episode_rows >= 1, "episodic rows must be wiped");
    assert_eq!(
        report.groundtruth_revoked, 1,
        "exactly the Berlin GT row is revoked",
    );

    // The MATCHING gt row stops surfacing via recall but the row
    // remains in the table with `revoked_at` set — addressable for
    // forensic queries.
    let gt: Vec<_> = surface_for_recall(&conn, 50, true).unwrap();
    assert_eq!(gt.len(), 1, "only the non-matching gt row is still active");
    assert_eq!(gt[0].id, other_id);
    let (statement, revoked_at): (String, Option<i64>) = conn
        .query_row(
            "SELECT statement, revoked_at FROM idx_groundtruth WHERE id = ?1",
            params![gt_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(statement, "my city is Berlin", "row still addressable");
    assert_eq!(
        revoked_at,
        Some(1_700_000_000),
        "revoked_at must be stamped at the forget call's ts",
    );

    // The unrelated episode is also still there.
    let unrelated_left: i64 = conn
        .query_row(
            "SELECT count(*) FROM idx_episode WHERE event_id = 3",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(unrelated_left, 1, "non-matching episode must be untouched");
}

#[test]
fn forget_does_not_revoke_non_matching_groundtruth_rows() {
    // Cross-tier safety pin: forget("X") only revokes gt rows whose
    // statement matches "X". An unrelated gt row stays active even
    // when other tiers had matches.
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    let active_id = insert_gt(
        &conn,
        "my preferred timezone is UTC",
        &Source::Onboarding,
        "preferences",
        0,
    )
    .unwrap();
    seed_episode_with_topic(&conn, 1, "Berlin trip notes");

    let report = forget_by_topic(&conn, "Berlin", 99).unwrap();
    assert!(report.episode_rows >= 1);
    assert_eq!(
        report.groundtruth_revoked, 0,
        "unrelated GT row must NOT be revoked",
    );

    let revoked_at: Option<i64> = conn
        .query_row(
            "SELECT revoked_at FROM idx_groundtruth WHERE id = ?1",
            params![active_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(revoked_at.is_none(), "unrelated GT row must stay active");
}

#[test]
fn revoke_hides_groundtruth_from_recall_but_keeps_row_addressable() {
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    let id = insert_gt(&conn, "my city is Berlin", &Source::Onboarding, "self", 100).unwrap();

    assert_eq!(count_active(&conn).unwrap(), 1);

    let modified = revoke(&conn, id, 200).unwrap();
    assert!(modified, "revoke must report it changed a row");

    // surface_for_recall + count_active both exclude revoked rows.
    assert_eq!(count_active(&conn).unwrap(), 0);
    assert!(surface_for_recall(&conn, 50, true).unwrap().is_empty());

    // Forensic addressability: the row is STILL in the table with
    // revoked_at populated.
    let (statement, revoked_at): (String, i64) = conn
        .query_row(
            "SELECT statement, revoked_at FROM idx_groundtruth WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(statement, "my city is Berlin");
    assert_eq!(revoked_at, 200);
}

#[test]
fn revoking_unknown_id_returns_false_without_error() {
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    let modified = revoke(&conn, 99_999, 1).unwrap();
    assert!(!modified, "unknown id is a no-op, not an Err");
}

#[test]
fn insert_rejects_whitespace_only_statement() {
    // Boundary input validation pinned at the integration surface
    // — `neoth groundtruth add "   "` must Err loudly.
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    let r = insert_gt(&conn, "   ", &Source::OperatorRuntime, "self", 0);
    assert!(r.is_err(), "whitespace-only statement must be rejected");
    let msg = format!("{:?}", r.unwrap_err());
    assert!(msg.contains("non-empty"), "error must explain why: {msg}");
}

#[test]
fn insert_trims_leading_and_trailing_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    let id = insert_gt(
        &conn,
        "  my city is Berlin\n",
        &Source::Onboarding,
        "self",
        0,
    )
    .unwrap();
    let statement: String = conn
        .query_row(
            "SELECT statement FROM idx_groundtruth WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        statement, "my city is Berlin",
        "leading/trailing whitespace must be stripped",
    );
}
