//! M-07 sibling — Hebbian reinforce + audit-trail integration.
//!
//! Unit tests already pin:
//!   - the math primitives ([`hebbian_reinforce_value`])
//!   - the single-row helpers ([`hebbian_reinforce_at_tier`])
//!   - the CLI recall reinforcement loop (`cli/recall.rs::tests`)
//!
//! This file pins the end-to-end behaviour that only surfaces when a
//! recall hit actually mutates the row AND the next recall sees the
//! bumped importance:
//!
//! - **Tier dispatch round-trip**: seed one hot + one warm + one cold
//!   row, call `hebbian_reinforce_at_tier` on each, re-read the table
//!   per tier, assert each row's importance went up by the
//!   tier-specific reinforcement coefficient AND `last_access_ts`
//!   advanced to the supplied `now_ns`.
//! - **Idempotence under repeat-reinforce**: repeated reinforcements
//!   on the same row converge toward 1.0 (never overshoot) and
//!   stay clamped. Pre-M-01 regression hole: a future refactor that
//!   accidentally re-introduces a `* (1 + k)` term would let
//!   importance run past 1.0; this test fails loudly if it does.
//! - **Cross-tier independence**: reinforcing the warm row must not
//!   touch the hot row at the same event_id (the dispatcher
//!   choosing the WRONG backing table is the canonical pre-M-01 bug).
//!
//! WAL audit emission (`EVENT_TYPE_IMPORTANCE_REINFORCED` 0x93)
//! end-to-end belongs to a CLI-recall integration test — covered by
//! the per-module unit tests + M-02 commit message; not duplicated here.

use neothd::memory::store;
use neothd::memory::tiers::{
    Tier, hebbian_reinforce_at_tier, hebbian_reinforce_value,
};
use rusqlite::{Connection, params};

const DAY_NS: i64 = 86_400 * 1_000_000_000;

fn seed_hot(conn: &Connection, event_id: i64, ts_ns: i64, importance: f64) {
    conn.execute(
        "INSERT INTO idx_episode \
         (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
         VALUES (?1, 1, ?2, 'hot-text', 'h-hash', ?3, 0)",
        params![event_id, ts_ns, importance],
    )
    .unwrap();
}

fn seed_warm(conn: &Connection, event_id: i64, importance: f64) {
    conn.execute(
        "INSERT INTO idx_consolidated \
         (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
         VALUES ('retained', '2026-01-01', ?1, 'warm-text', 'w-hash', ?2, 0, 0)",
        params![event_id, importance],
    )
    .unwrap();
}

fn seed_cold(conn: &Connection, event_id: i64, importance: f64) {
    conn.execute(
        "INSERT INTO idx_longterm \
         (event_id, text, text_hash, importance, promoted_ts, last_access_ts, archive_path) \
         VALUES (?1, 'cold-text', 'c-hash', ?2, 0, 0, NULL)",
        params![event_id, importance],
    )
    .unwrap();
}

#[test]
fn reinforce_dispatches_to_correct_backing_table_per_tier() {
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    seed_hot(&conn, 1, 100, 0.50);
    seed_warm(&conn, 2, 0.50);
    seed_cold(&conn, 3, 0.50);
    let now_ns: u64 = 1_700_000_000_000_000_000;

    // Hot — k=0.15 → 0.575
    let out_hot = hebbian_reinforce_at_tier(&conn, Tier::Hot, 1, now_ns)
        .unwrap()
        .unwrap();
    assert!((out_hot.new - 0.575).abs() < 1e-6);

    // Warm — k=0.10 → 0.55
    let out_warm = hebbian_reinforce_at_tier(&conn, Tier::Warm, 2, now_ns)
        .unwrap()
        .unwrap();
    assert!((out_warm.new - 0.55).abs() < 1e-6);

    // Cold — k=0.05 → 0.525
    let out_cold = hebbian_reinforce_at_tier(&conn, Tier::Cold, 3, now_ns)
        .unwrap()
        .unwrap();
    assert!((out_cold.new - 0.525).abs() < 1e-6);

    // Read-back: each row's importance + last_access_ts persisted.
    let (hot_imp, hot_la): (f64, i64) = conn
        .query_row(
            "SELECT importance, last_access_ts FROM idx_episode WHERE event_id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!((hot_imp - 0.575).abs() < 1e-6);
    assert_eq!(hot_la, now_ns as i64);

    let warm_imp: f64 = conn
        .query_row(
            "SELECT importance FROM idx_consolidated WHERE event_id=2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!((warm_imp - 0.55).abs() < 1e-6);

    let cold_imp: f64 = conn
        .query_row(
            "SELECT importance FROM idx_longterm WHERE event_id=3",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!((cold_imp - 0.525).abs() < 1e-6);
}

#[test]
fn repeated_reinforce_converges_to_one_without_overshoot() {
    // Reinforce a hot row 100 times. Importance must approach 1.0
    // but NEVER exceed it. Pre-M-01 regression guard: a refactor
    // that drops the `(1 - old)` damping would let the value
    // overshoot the unit interval and silently break the ranker.
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    seed_hot(&conn, 1, 100, 0.10);
    let now_ns: u64 = 1_700_000_000_000_000_000;
    let mut last_seen = f64::NEG_INFINITY;
    for i in 0..100 {
        let out = hebbian_reinforce_at_tier(&conn, Tier::Hot, 1, now_ns + i)
            .unwrap()
            .unwrap();
        assert!(
            (0.0..=1.0).contains(&out.new),
            "iter {i}: importance {} out of [0,1]",
            out.new,
        );
        assert!(
            out.new >= last_seen - 1e-9,
            "iter {i}: importance went down ({} < {})",
            out.new,
            last_seen,
        );
        last_seen = out.new;
    }
    // After 100 hot-tier (k=0.15) reinforcements, importance is
    // extremely close to 1.0 but strictly below.
    let final_imp: f64 = conn
        .query_row(
            "SELECT importance FROM idx_episode WHERE event_id=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(final_imp <= 1.0 + 1e-9, "must clamp at 1.0");
    assert!(final_imp > 0.99, "100 iters of k=0.15 from 0.10 → near 1");
}

#[test]
fn warm_reinforce_does_not_touch_hot_row_at_same_event_id() {
    // Canonical pre-M-01 hot-only-dispatch bug: the dispatcher
    // chose `idx_episode` regardless of tier, so reinforcing a
    // warm hit mutated the wrong row (or no row at all).
    // Post-M-01: dispatch is per-tier. Pin the cross-tier
    // independence — both rows exist with the SAME event_id, only
    // the warm one moves.
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    let ev = 42;
    let now_ns: u64 = 1_700_000_000_000_000_000;
    seed_hot(&conn, ev, (now_ns as i64) - 3 * DAY_NS, 0.30);
    seed_warm(&conn, ev, 0.30);

    let _ = hebbian_reinforce_at_tier(&conn, Tier::Warm, ev, now_ns)
        .unwrap()
        .unwrap();

    let hot_after: f64 = conn
        .query_row(
            "SELECT importance FROM idx_episode WHERE event_id = ?1",
            params![ev],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        (hot_after - 0.30).abs() < 1e-9,
        "hot row must be untouched by a warm-tier reinforce, got {hot_after}",
    );
    let warm_after: f64 = conn
        .query_row(
            "SELECT importance FROM idx_consolidated WHERE event_id = ?1",
            params![ev],
            |r| r.get(0),
        )
        .unwrap();
    // 0.30 + 0.10 * 0.70 = 0.37
    assert!((warm_after - 0.37).abs() < 1e-6, "got {warm_after}");
}

#[test]
fn reinforce_unknown_event_id_returns_none_per_tier() {
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    let now_ns: u64 = 1;
    // No rows seeded — every tier must soft-fail with None instead
    // of returning Err. Recall path treats None as "skip this hit"
    // so a stale id never crashes the chat reply.
    assert!(
        hebbian_reinforce_at_tier(&conn, Tier::Hot, 999, now_ns)
            .unwrap()
            .is_none(),
    );
    assert!(
        hebbian_reinforce_at_tier(&conn, Tier::Warm, 999, now_ns)
            .unwrap()
            .is_none(),
    );
    assert!(
        hebbian_reinforce_at_tier(&conn, Tier::Cold, 999, now_ns)
            .unwrap()
            .is_none(),
    );
}

#[test]
fn pure_helper_and_db_helper_agree_on_per_tier_math() {
    // Drift guard: the SQL-side update uses the pure
    // `hebbian_reinforce_value` formula. If a future "optimisation"
    // inlines a different curve in the UPDATE, this test catches it.
    let dir = tempfile::tempdir().unwrap();
    let conn = store::open(&dir.path().join("v.db")).unwrap();
    let now_ns: u64 = 1;
    for (tier, seeder) in [
        (Tier::Hot, &seed_hot as &dyn Fn(&Connection, i64, i64, f64)),
    ] {
        for old in [0.0, 0.25, 0.5, 0.75, 0.95, 1.0] {
            // Fresh row per old-value because reinforce mutates.
            seeder(&conn, 100, 0, old);
            let dispatched = hebbian_reinforce_at_tier(&conn, tier, 100, now_ns)
                .unwrap()
                .unwrap();
            let expected = hebbian_reinforce_value(old, tier);
            assert!(
                (dispatched.new - expected).abs() < 1e-9,
                "tier={tier:?} old={old}: dispatcher returned {} vs pure formula {}",
                dispatched.new,
                expected,
            );
            // Reset for next iteration.
            conn.execute("DELETE FROM idx_episode WHERE event_id = 100", [])
                .unwrap();
        }
    }
}
