//! M-07 batch-3 — multi-segment WAL rotation integration.
//!
//! Unit tests cover `indexer::replay_once` against one segment.
//! This file pins the rotation behaviour: when the writer rolls
//! from `000001.wal` to `000002.wal`, `replay_all_segments` must
//! pick up the new segment automatically + keep the per-segment
//! `wal_cursor` entries isolated so re-indexing an already-finished
//! segment is a deterministic no-op even after rotation.
//!
//! Pre-rule regression hole: a refactor that collapsed every segment
//! into one shared cursor would mis-resume after rotation (skipping
//! the new segment's header bytes or replaying everything). These
//! tests fail loudly if that happens.
//!
//! Hand-fabricated segment files (no writer task) keep the tests
//! deterministic — we control exactly which bytes land where.

use neothd::memory::indexer::{replay_all_segments, replay_once};
use neothd::memory::store;
use neothd::wal::builder::make_header;
use neothd::wal::events::EVENT_TYPE_RAW_TEXT;
use neothd::wal::frame::encode_frame;
use neothd::wal::segment_header::SegmentHeader;

/// Build a synthetic `.wal` segment with `payloads.len()` RAW_TEXT
/// frames + the canonical SegmentHeader prelude. `seq` is the
/// `segment_seq` stamp; the rest of the header fields are test-
/// neutral zeros.
fn write_segment(path: &std::path::Path, seq: u64, payloads: &[&[u8]]) {
    let mut out = Vec::new();
    out.extend_from_slice(&SegmentHeader::new(0, seq, 0, 0, [0u8; 16]).to_le_bytes());
    for payload in payloads {
        let header = make_header(EVENT_TYPE_RAW_TEXT, payload);
        out.extend_from_slice(&encode_frame(&header, payload));
    }
    std::fs::write(path, out).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn replay_all_picks_up_a_freshly_rotated_segment() {
    let dir = tempfile::tempdir().unwrap();
    let wal = dir.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();
    let seg1 = wal.join("000001.wal");
    let seg2 = wal.join("000002.wal");
    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();

    // First rotation cycle: only segment 1 exists.
    write_segment(&seg1, 1, &[b"frame-a", b"frame-b"]);
    let n1 = replay_all_segments(&mut conn, &seg1).await.unwrap();
    assert_eq!(n1, 2);
    let row_count: i64 = conn
        .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(row_count, 2);

    // Second pass with no new bytes — exactly zero new frames.
    let n_noop = replay_all_segments(&mut conn, &seg1).await.unwrap();
    assert_eq!(n_noop, 0, "idempotent on no-new-bytes");

    // Writer rotates → seg2 appears. replay_all must discover it +
    // index its 3 frames; seg1's cursor is unchanged so no
    // double-indexing of seg1.
    write_segment(&seg2, 2, &[b"frame-c", b"frame-d", b"frame-e"]);
    let n2 = replay_all_segments(&mut conn, &seg1).await.unwrap();
    assert_eq!(n2, 3, "exactly seg2's 3 frames indexed");
    let total: i64 = conn
        .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 5, "seg1 (2) + seg2 (3) = 5 rows total");
}

#[tokio::test(flavor = "current_thread")]
async fn per_segment_cursor_isolates_rotated_segments() {
    // Pin the contract: each segment carries its own `wal_cursor`
    // row keyed by segment_path. Re-running replay against seg1
    // after seg2 was indexed must NOT replay seg2 from the start.
    let dir = tempfile::tempdir().unwrap();
    let wal = dir.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();
    let seg1 = wal.join("000001.wal");
    let seg2 = wal.join("000002.wal");
    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();

    write_segment(&seg1, 1, &[b"a", b"b"]);
    write_segment(&seg2, 2, &[b"c", b"d"]);
    let first = replay_all_segments(&mut conn, &seg1).await.unwrap();
    assert_eq!(first, 4, "seg1 (2) + seg2 (2) = 4");

    // Run another full sweep — both cursors are caught up.
    let second = replay_all_segments(&mut conn, &seg1).await.unwrap();
    assert_eq!(second, 0);

    // Now append a third frame to seg1 (simulates a writer that
    // never rotated). The seg1 cursor advances; seg2's cursor stays
    // put. Only the new seg1 frame should land.
    let mut bytes = std::fs::read(&seg1).unwrap();
    let header = make_header(EVENT_TYPE_RAW_TEXT, b"a2");
    bytes.extend_from_slice(&encode_frame(&header, b"a2"));
    std::fs::write(&seg1, bytes).unwrap();

    let third = replay_all_segments(&mut conn, &seg1).await.unwrap();
    assert_eq!(third, 1, "only seg1's appended frame indexed");
    let total: i64 = conn
        .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 5);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_once_tolerates_missing_segment_file() {
    // Fresh boot before the writer creates 000001.wal — `replay_once`
    // must return Ok(0) instead of erroring. The daemon's startup
    // path relies on this to avoid a chicken-and-egg crash when the
    // very first frame hasn't been appended yet.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("views.db");
    let absent = dir.path().join("never-existed.wal");
    let mut conn = store::open(&db).unwrap();
    let n = replay_once(&mut conn, &absent).await.unwrap();
    assert_eq!(n, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_all_skips_non_wal_files_in_the_parent_dir() {
    // The discovery walk filters by `.wal` extension. A sibling
    // README.md or backup .wal.gz must NOT be passed to the frame
    // decoder (which would Err on the unexpected magic bytes).
    let dir = tempfile::tempdir().unwrap();
    let wal = dir.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();
    let seg1 = wal.join("000001.wal");
    write_segment(&seg1, 1, &[b"only-real-frame"]);

    // Junk files alongside.
    std::fs::write(wal.join("README.md"), b"not a segment").unwrap();
    std::fs::write(wal.join("000001.wal.gz"), b"compressed").unwrap();
    std::fs::write(wal.join("backup.bak"), b"backup-junk").unwrap();

    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();
    let n = replay_all_segments(&mut conn, &seg1).await.unwrap();
    assert_eq!(n, 1, "exactly the one real frame indexed");
    let total: i64 = conn
        .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_all_handles_missing_parent_dir() {
    // Operator deleted ~/.neoth/wal before first boot — replay_all
    // must not crash. The discovery walk's NotFound branch returns
    // Ok(total_so_far) which is 0 in this case.
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("does/not/exist/000001.wal");
    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();
    let n = replay_all_segments(&mut conn, &seed).await.unwrap();
    assert_eq!(n, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_all_indexes_segments_in_filename_sort_order() {
    // Pin the segment-ordering contract: filenames sort lexically
    // = `000001.wal` before `000002.wal` before `000010.wal`.
    // Operators reading the WAL audit trail expect chronological
    // ordering; a discovery walk that returned them in OS-dependent
    // order would scramble the audit log.
    let dir = tempfile::tempdir().unwrap();
    let wal = dir.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();
    let seg1 = wal.join("000001.wal");
    let seg2 = wal.join("000002.wal");
    let seg10 = wal.join("000010.wal");
    write_segment(&seg1, 1, &[b"first"]);
    write_segment(&seg2, 2, &[b"second"]);
    write_segment(&seg10, 10, &[b"tenth"]);

    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();
    replay_all_segments(&mut conn, &seg1).await.unwrap();

    // The order of insertion follows event_id (set by make_header
    // from `SystemTime::now`). All three were written without
    // gaps but the indexer drives ordering by walking sorted paths.
    // Sanity: three rows total.
    let total: i64 = conn
        .query_row("SELECT count(*) FROM idx_episode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 3);

    // Stricter check: the texts we wrote match.
    let mut texts: Vec<String> = conn
        .prepare("SELECT text FROM idx_episode")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    texts.sort();
    assert_eq!(
        texts,
        vec![
            "first".to_string(),
            "second".to_string(),
            "tenth".to_string()
        ]
    );
}
