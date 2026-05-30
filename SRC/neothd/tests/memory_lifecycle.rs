//! M-07 (Session 24, A1 top-priority gap) — memory lifecycle integration
//! tests. Pure unit tests inside `memory::*` modules pin individual
//! algorithms; this file pins the **end-to-end** flows that only
//! surface when WAL writer + indexer + views.db + consolidate +
//! recall all cooperate.
//!
//! ## Scope of this file
//!
//! - **WAL → indexer → views.db round-trip.** A RAW_TEXT frame written
//!   via the real `wal::writer::spawn` handle must end up queryable
//!   via `idx_episode` after a single `indexer::replay_once` pass.
//! - **Consolidation end-to-end.** Seed `idx_episode` directly with
//!   rows spread across hot / warm / cold ages, drive one
//!   `run_consolidation_pass`, assert the per-tier outcomes match
//!   the schedule (hot → warm migration at 7d, warm → cold promotion
//!   at 90d above PROMOTION_THRESHOLD, cold-tier sweep below
//!   FORGET_FLOOR). Pin the [`PassReport`] surface so a future
//!   refactor of the pass body can't quietly drop a count.
//! - **Ground-truth survives every consolidation pass.** Seed one
//!   row in `idx_groundtruth`, run 365 consolidation passes against
//!   it, assert the row + count are unchanged.
//!
//! ## Out of scope (separate M-07 sibling files)
//!
//! - Profile pipeline integration (extraction → idx_profile → recall)
//! - CLI-recall + Hebbian reinforce + 0x93 WAL frame round-trip
//! - 6-region SQLite view cooperation (M-08)
//!
//! Each test uses a fresh `tempfile::tempdir` so they're trivially
//! parallel-safe + don't touch `~/.neoth/`.

use std::path::Path;
use std::time::Duration;

use neothd::memory::consolidate::{PassReport, run_consolidation_pass};
use neothd::memory::store;
use neothd::memory::tiers::{FORGET_FLOOR, PROMOTION_THRESHOLD};
use neothd::wal::builder::make_header;
use neothd::wal::events::EVENT_TYPE_RAW_TEXT;
use neothd::wal::writer;
use rusqlite::params;

const DAY_NS: i64 = 86_400 * 1_000_000_000;

// ── WAL → indexer → views.db round-trip ───────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn wal_raw_text_frame_round_trips_through_indexer_into_idx_episode() {
    let dir = tempfile::tempdir().unwrap();
    let segment = dir.path().join("000001.wal");
    let db = dir.path().join("views.db");

    // Real WAL writer. spawn() does the SegmentHeader prelude on
    // first append; we don't have to fabricate it.
    let (handle, join) = writer::spawn(segment.clone()).expect("spawn writer");

    let body = b"the operator typed this exact prompt";
    let header = make_header(EVENT_TYPE_RAW_TEXT, body);
    handle
        .append(header, body.to_vec())
        .await
        .expect("append RAW_TEXT");

    // Drop the writer + wait for its task to flush. The indexer's
    // partial-frame guard would otherwise stop short of the tail.
    drop(handle);
    let _ = join.await;

    // Index everything in the segment.
    let mut conn = store::open(&db).expect("open views.db");
    let indexed = neothd::memory::indexer::replay_once(&mut conn, &segment)
        .await
        .expect("replay_once");
    assert_eq!(indexed, 1, "exactly one RAW_TEXT frame was appended");

    // The row must be queryable via the schema the recall path uses.
    let (text, hash): (String, String) = conn
        .query_row(
            "SELECT text, text_hash FROM idx_episode WHERE event_type = ?1",
            params![EVENT_TYPE_RAW_TEXT as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("RAW_TEXT row indexed");
    assert_eq!(text, "the operator typed this exact prompt");
    assert!(!hash.is_empty(), "text_hash must be set by the indexer");
}

#[tokio::test(flavor = "current_thread")]
async fn indexer_replay_is_idempotent_across_calls() {
    // Replaying the same segment twice must not duplicate rows —
    // the per-segment cursor in `wal_cursor` is the contract.
    let dir = tempfile::tempdir().unwrap();
    let segment = dir.path().join("000001.wal");
    let db = dir.path().join("views.db");

    let (handle, join) = writer::spawn(segment.clone()).unwrap();
    for i in 0..3 {
        let body = format!("event-{i}");
        let header = make_header(EVENT_TYPE_RAW_TEXT, body.as_bytes());
        handle
            .append(header, body.into_bytes())
            .await
            .expect("append");
    }
    drop(handle);
    let _ = join.await;

    let mut conn = store::open(&db).unwrap();
    let first = neothd::memory::indexer::replay_once(&mut conn, &segment)
        .await
        .unwrap();
    assert_eq!(first, 3);
    let second = neothd::memory::indexer::replay_once(&mut conn, &segment)
        .await
        .unwrap();
    assert_eq!(second, 0, "second pass must re-index zero frames");

    let total: i64 = conn
        .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 3, "idempotent — no duplicate rows");
}

// ── Consolidation end-to-end ──────────────────────────────────────────

/// Seed `idx_episode` directly with rows spanning the three age
/// buckets and one full consolidation cycle. Returns the connection
/// + `now_ns` anchor for the calling assertion to read back.
fn seed_episodes_across_tiers(db: &Path, now_ns: i64) -> rusqlite::Connection {
    let conn = store::open(db).expect("open views.db");
    // 3-day-old, importance 0.6 — stays hot, just decays.
    insert_event(&conn, 1, now_ns - 3 * DAY_NS, 0.60);
    // 10-day-old, importance 0.5 — migrates hot → warm.
    insert_event(&conn, 2, now_ns - 10 * DAY_NS, 0.50);
    // 10-day-old, importance 0.05 — hot-archived (below floor).
    insert_event(&conn, 3, now_ns - 10 * DAY_NS, 0.05);
    // 95-day-old warm row, importance 0.80 — warm → cold promote.
    insert_consolidated(&conn, 95, 0.80, now_ns);
    // 95-day-old warm row, importance 0.30 — warm-archived (below PROMOTE).
    insert_consolidated(&conn, 95, 0.30, now_ns);
    // Existing cold row, importance 0.05 — cold-tier sweep (below FORGET).
    insert_longterm(&conn, 99, 0.05);
    conn
}

fn insert_event(conn: &rusqlite::Connection, event_id: i64, ts_ns: i64, importance: f64) {
    conn.execute(
        "INSERT INTO idx_episode \
         (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
         VALUES (?1, 1, ?2, ?3, ?4, ?5, ?2)",
        params![
            event_id,
            ts_ns,
            format!("event-{event_id}"),
            format!("hash-{event_id}"),
            importance,
        ],
    )
    .unwrap();
}

fn insert_consolidated(conn: &rusqlite::Connection, day_ago: i64, importance: f64, now_ns: i64) {
    let ts_ns = now_ns - day_ago * DAY_NS;
    let day = chrono::DateTime::<chrono::Utc>::from_timestamp(ts_ns / 1_000_000_000, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "1970-01-01".into());
    conn.execute(
        "INSERT INTO idx_consolidated \
         (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
         VALUES ('retained', ?1, NULL, 'text', 'hash', ?2, ?3, ?3)",
        params![day, importance, ts_ns],
    )
    .unwrap();
}

fn insert_longterm(conn: &rusqlite::Connection, event_id: i64, importance: f64) {
    conn.execute(
        "INSERT INTO idx_longterm \
         (event_id, text, text_hash, importance, promoted_ts, last_access_ts, archive_path) \
         VALUES (?1, 'text', 'hash', ?2, 0, 0, NULL)",
        params![event_id, importance],
    )
    .unwrap();
}

#[test]
fn consolidation_pass_walks_every_tier_in_one_call() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let now_ns: i64 = 1_700_000_000_000_000_000;
    let mut conn = seed_episodes_across_tiers(&db, now_ns);

    let report: PassReport = run_consolidation_pass(&mut conn, now_ns, None).expect("pass");

    // Hot tier — 3 events decayed (the 3-day, 10-day-above-floor,
    // and 10-day-below-floor each got their importance multiplied
    // before further routing). One migrates, one archives.
    assert_eq!(report.hot_decayed, 3, "every hot row decayed once");
    assert_eq!(report.consolidated, 1, "10-day-old above-floor migrated");
    assert_eq!(report.hot_archived, 1, "10-day-old below-floor archived");

    // Warm tier — 2 warm rows entered the pass (the 95-day pair
    // seeded above). One survives the post-decay PROMOTION_THRESHOLD
    // check + promotes; the other archives. Plus the migrated hot row
    // is a NEW warm row but it's < 90d so it doesn't enter the
    // warm-to-cold phase this pass — that's expected.
    assert_eq!(
        report.warm_decayed, 2,
        "two pre-existing warm rows decayed (newly-consolidated row was inserted post-decay)",
    );
    assert_eq!(
        report.promoted, 1,
        "0.80 row crossed the 90d boundary above PROMOTE"
    );
    assert_eq!(report.warm_archived, 1, "0.30 row crossed below PROMOTE");

    // Cold tier — one pre-existing row at importance 0.05. After
    // decay it's still well below FORGET_FLOOR so the sweep deletes
    // it. M-06 surfaces this in cold_swept.
    assert_eq!(report.cold_decayed, 1);
    assert_eq!(report.cold_swept, 1, "below-floor cold row was swept");

    // Concrete state checks — the tier counts on disk match the
    // semantic outcome.
    let hot_left: i64 = conn
        .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(hot_left, 1, "only event 1 (3-day-old) remains hot");

    let cold_left: i64 = conn
        .query_row("SELECT count(*) FROM idx_longterm", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        cold_left, 1,
        "pre-existing cold row swept, promoted row landed"
    );

    let warm_left: i64 = conn
        .query_row("SELECT count(*) FROM idx_consolidated", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        warm_left, 1,
        "old warm pair gone (1 promoted + 1 archived), 1 freshly-consolidated row remains",
    );
}

#[test]
fn consolidation_is_no_op_when_views_are_already_caught_up() {
    // Running the pass twice in a row must leave the second call
    // as a deterministic small no-op: every row keeps shifting by
    // its decay factor, but nothing migrates because the youngest
    // surviving rows are all freshly post-migration.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let now_ns: i64 = 1_700_000_000_000_000_000;
    let mut conn = seed_episodes_across_tiers(&db, now_ns);

    let first = run_consolidation_pass(&mut conn, now_ns, None).unwrap();
    assert!(first.consolidated >= 1, "first pass migrates");

    let second = run_consolidation_pass(&mut conn, now_ns, None).unwrap();
    assert_eq!(second.consolidated, 0, "no new hot rows older than 7d");
    assert_eq!(second.promoted, 0, "no more warm rows older than 90d");
    assert_eq!(second.hot_archived, 0);
    assert_eq!(second.warm_archived, 0);
    // The hot row that survived the first pass got decayed once;
    // the second pass decays it again (still hot).
    assert_eq!(second.hot_decayed, 1);
}

// ── Ground-truth survives consolidation forever ───────────────────────

#[test]
fn groundtruth_row_survives_one_full_year_of_consolidation_passes() {
    // SPEC GT-3: idx_groundtruth is decay-immune by design — the
    // consolidate pass must never touch it. Pin this with a 365-pass
    // simulation. If a future refactor accidentally pulls
    // idx_groundtruth into the decay UPDATE, this test screams.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();

    conn.execute(
        "INSERT INTO idx_groundtruth \
         (statement, source, scope, asserted_at, revoked_at) \
         VALUES ('my city is Berlin', 'operator', 'self', 0, NULL)",
        [],
    )
    .unwrap();

    let mut now_ns: i64 = 1_700_000_000_000_000_000;
    for _ in 0..365 {
        run_consolidation_pass(&mut conn, now_ns, None).unwrap();
        now_ns += DAY_NS;
    }

    let row_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM idx_groundtruth WHERE revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        row_count, 1,
        "groundtruth row must survive 365 consolidation passes (GT-3)",
    );
    let statement: String = conn
        .query_row(
            "SELECT statement FROM idx_groundtruth WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(statement, "my city is Berlin");
}

// ── Defensive: assert the seed values straddle the documented thresholds ──

#[test]
fn seed_values_match_documented_thresholds() {
    // Drift guard: this file's seeding logic assumes specific decay
    // factors. If a future tier-tuning bumps FORGET_FLOOR up past
    // 0.30 or drops PROMOTION_THRESHOLD below 0.60, the consolidation
    // assertions above silently change meaning. Pin the values here
    // so a tier-config change forces a test review.
    assert!(
        (FORGET_FLOOR - 0.10).abs() < 1e-9,
        "FORGET_FLOOR drift — review seed values in this file",
    );
    assert!(
        (PROMOTION_THRESHOLD - 0.65).abs() < 1e-9,
        "PROMOTION_THRESHOLD drift — review seed values in this file",
    );
}

// ── Sanity: writer + indexer concurrency under a real timer ───────────

#[tokio::test(flavor = "current_thread")]
async fn indexer_can_catch_up_after_writer_flush_completes() {
    // Smoke test: write 5 frames + close the writer, sleep, index.
    // The point is that `indexer::replay_once` doesn't need the
    // writer to be alive to find the bytes — the segment file is
    // the source of truth.
    let dir = tempfile::tempdir().unwrap();
    let segment = dir.path().join("000001.wal");
    let db = dir.path().join("views.db");

    let (handle, join) = writer::spawn(segment.clone()).unwrap();
    for i in 0..5 {
        let body = format!("flush-then-index-{i}");
        let header = make_header(EVENT_TYPE_RAW_TEXT, body.as_bytes());
        handle.append(header, body.into_bytes()).await.unwrap();
    }
    drop(handle);
    let _ = join.await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut conn = store::open(&db).unwrap();
    let n = neothd::memory::indexer::replay_once(&mut conn, &segment)
        .await
        .unwrap();
    assert_eq!(n, 5);
}
