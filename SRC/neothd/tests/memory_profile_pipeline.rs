//! M-07 batch-2 — profile pipeline end-to-end integration.
//!
//! Pure unit tests cover:
//!   - `profile::apply::apply_delta` semantics (insert / reinforce / supersede)
//!   - `profile::lookup::top_claims_for_chat` query shape
//!   - `cli/profile` conflict detection + resolution (AR-05)
//!
//! This file pins the **end-to-end** post-apply state — after
//! `apply_delta` runs against a fresh `idx_profile`, the
//! `top_claims_for_chat` reader must see the new claims in the order
//! and confidence the spec promises. Catches a class of bugs that
//! only surface when the WRITE path's `superseded_at` policy and the
//! READ path's `WHERE superseded_at IS NULL` filter disagree.
//!
//! Each test runs against a fresh `views.db` via `tempfile::tempdir`
//! + the real `memory::store::open` schema; no mocking.

use neothd::memory::store;
use neothd::profile::apply::apply_delta;
use neothd::profile::delta::{ProfileDelta, RawClaim};
use neothd::profile::lookup::{top_claims_for_chat, PROFILE_BOUNDARY_HEADER, render_for_synthesis_prompt};
use neothd::wal::writer;

fn raw_claim(field: &str, value: serde_json::Value, confidence: f32) -> RawClaim {
    RawClaim {
        field: field.to_string(),
        value_json: value,
        confidence,
        reasoning: format!("operator stated {field}"),
        evidence_event_ids: vec![1],
    }
}

fn delta(extraction_id: &str, claims: Vec<RawClaim>) -> ProfileDelta {
    ProfileDelta {
        extraction_id: extraction_id.into(),
        conversation_hash: "test-hash".into(),
        claims,
        ..Default::default()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn apply_delta_inserts_claim_visible_to_top_claims_for_chat() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let segment = dir.path().join("000001.wal");

    let mut conn = store::open(&db).unwrap();
    let (writer, join) = writer::spawn(segment).unwrap();

    let d = delta(
        "ext-1",
        vec![raw_claim("identity.location", serde_json::json!("Berlin"), 0.9)],
    );
    let outcome = apply_delta(&mut conn, &writer, &d, 1_700_000_000)
        .await
        .expect("apply_delta");
    assert_eq!(outcome.claims_applied, 1);
    assert!(!outcome.idempotent_skip);

    let claims = top_claims_for_chat(&conn, 0.6, 50).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].field, "identity.location");
    assert_eq!(claims[0].value_json, "\"Berlin\"");
    assert!((claims[0].confidence - 0.9).abs() < 1e-6);

    drop(writer);
    let _ = join.await;
}

#[tokio::test(flavor = "current_thread")]
async fn apply_delta_supersede_path_hides_old_value_from_recall() {
    // Pin the WRITE→READ contract: when apply_delta marks an old row
    // `superseded_at = now`, the READ path must immediately stop
    // surfacing it. Pre-rule regression hole: a query that forgot
    // the IS NULL filter would show BOTH values to the synthesis
    // prompt and confuse the model.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let segment = dir.path().join("000001.wal");
    let mut conn = store::open(&db).unwrap();
    let (writer, join) = writer::spawn(segment).unwrap();

    let d1 = delta(
        "ext-old",
        vec![raw_claim("identity.location", serde_json::json!("Berlin"), 0.7)],
    );
    apply_delta(&mut conn, &writer, &d1, 100).await.unwrap();

    let d2 = delta(
        "ext-new",
        vec![raw_claim("identity.location", serde_json::json!("Munich"), 0.9)],
    );
    let outcome = apply_delta(&mut conn, &writer, &d2, 200).await.unwrap();
    assert_eq!(outcome.claims_superseded, 1, "Munich must supersede Berlin");

    let claims = top_claims_for_chat(&conn, 0.6, 50).unwrap();
    assert_eq!(claims.len(), 1, "exactly one ACTIVE row per field");
    assert_eq!(claims[0].value_json, "\"Munich\"", "newest value wins");

    drop(writer);
    let _ = join.await;
}

#[tokio::test(flavor = "current_thread")]
async fn apply_delta_below_min_confidence_is_hidden_from_chat_lookup() {
    // The recall reader threshold (0.6 per SPEC_proactive_learning §5.1)
    // must filter low-confidence claims out even when they're active
    // in the table. Pins the "noisy data doesn't bias the answer"
    // contract.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let segment = dir.path().join("000001.wal");
    let mut conn = store::open(&db).unwrap();
    let (writer, join) = writer::spawn(segment).unwrap();

    let d = delta(
        "ext-low-conf",
        vec![raw_claim("identity.role", serde_json::json!("guesser"), 0.4)],
    );
    apply_delta(&mut conn, &writer, &d, 1).await.unwrap();

    let high = top_claims_for_chat(&conn, 0.6, 50).unwrap();
    assert!(high.is_empty(), "0.4-confidence claim must be invisible at 0.6 floor");
    let low = top_claims_for_chat(&conn, 0.3, 50).unwrap();
    assert_eq!(low.len(), 1, "0.4-confidence claim visible at 0.3 floor");

    drop(writer);
    let _ = join.await;
}

#[tokio::test(flavor = "current_thread")]
async fn apply_delta_is_idempotent_on_repeat_extraction_id() {
    // Same extraction_id replayed = idempotent_skip + no duplicate row.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let segment = dir.path().join("000001.wal");
    let mut conn = store::open(&db).unwrap();
    let (writer, join) = writer::spawn(segment).unwrap();

    let d = delta(
        "ext-repeat",
        vec![raw_claim("identity.location", serde_json::json!("Berlin"), 0.9)],
    );
    let first = apply_delta(&mut conn, &writer, &d, 1).await.unwrap();
    assert_eq!(first.claims_applied, 1);
    assert!(!first.idempotent_skip);

    let second = apply_delta(&mut conn, &writer, &d, 1).await.unwrap();
    assert!(second.idempotent_skip, "second apply must skip");
    assert_eq!(second.claims_applied, 0);

    let claims = top_claims_for_chat(&conn, 0.0, 50).unwrap();
    assert_eq!(claims.len(), 1, "no duplicate row from replayed delta");

    drop(writer);
    let _ = join.await;
}

#[tokio::test(flavor = "current_thread")]
async fn rendered_prompt_block_carries_adv_03_boundary_header() {
    // End-to-end: apply a claim, read it back via top_claims_for_chat,
    // render through render_for_synthesis_prompt — the boundary header
    // (ADV-03 prompt-injection defence) must appear verbatim at the
    // start. Pre-rule a refactor that dropped the header would let
    // a hostile claim value behave like an instruction.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let segment = dir.path().join("000001.wal");
    let mut conn = store::open(&db).unwrap();
    let (writer, join) = writer::spawn(segment).unwrap();

    let d = delta(
        "ext-render",
        vec![raw_claim(
            "identity.role",
            serde_json::json!("security researcher"),
            0.9,
        )],
    );
    apply_delta(&mut conn, &writer, &d, 1).await.unwrap();
    let claims = top_claims_for_chat(&conn, 0.6, 50).unwrap();
    let rendered = render_for_synthesis_prompt(&claims);

    assert!(
        rendered.starts_with(PROFILE_BOUNDARY_HEADER),
        "boundary header must appear verbatim at the start: {rendered}",
    );
    assert!(rendered.contains("identity.role"));
    assert!(rendered.contains("security researcher"));

    drop(writer);
    let _ = join.await;
}

#[tokio::test(flavor = "current_thread")]
async fn rendered_prompt_block_is_empty_when_no_claims_above_floor() {
    // Empty input → empty render. Pre-rule a refactor that always
    // emitted the boundary header would waste tokens on every chat
    // turn with no profile data.
    let claims: Vec<neothd::profile::lookup::ProfileClaim> = Vec::new();
    let rendered = render_for_synthesis_prompt(&claims);
    assert!(
        rendered.is_empty(),
        "empty input must render to empty string, got: {rendered:?}",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn empty_extraction_id_is_rejected_by_apply_delta() {
    // Boundary input validation: an empty extraction_id makes the
    // idempotency check meaningless. Apply must refuse instead of
    // silently inserting an orphan row.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let segment = dir.path().join("000001.wal");
    let mut conn = store::open(&db).unwrap();
    let (writer, join) = writer::spawn(segment).unwrap();

    let bad = delta("", vec![raw_claim("any.field", serde_json::json!("v"), 0.9)]);
    let r = apply_delta(&mut conn, &writer, &bad, 1).await;
    assert!(r.is_err(), "empty extraction_id must Err");
    let msg = format!("{:?}", r.unwrap_err());
    assert!(
        msg.contains("extraction_id"),
        "error must name the field: {msg}",
    );

    drop(writer);
    let _ = join.await;
}
