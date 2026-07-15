//! Release-proof durability matrix — end-to-end crash-recovery through the
//! REAL replay path (`memory::indexer::replay_all_segments`) + the writer's
//! own tail scanner (`wal::recovery::scan_tail`).
//!
//! ## Why this exists (the gap it fills)
//! Per-module unit tests already prove the building blocks in isolation:
//!   - `wal::recovery` — torn-tail / torn-header / corrupt-CRC offset reporting
//!   - `wal::scan` — torn tail silently skipped, mid-segment corruption fails loud
//!   - `wal::frame` — CRC corruption rejected by `decode_frame`
//!   - `wal::compaction` — compaction-marker tamper detection
//!   - `wal::redact` — redaction in sealed/compressed segments, corrupt-magic refusal
//!   - `tests/memory_wal_rotation.rs` proves rotation / per-segment cursor / missing
//!     file / non-`.wal` junk / sort order.
//!
//! NONE of them prove the property an operator actually relies on after a crash:
//! that the indexer, fed a segment whose final frame was half-written when the
//! process died, **recovers every COMPLETE frame, drops the torn tail without
//! erroring, and resumes from exactly the recovery offset once the frame is
//! finished**. This file pins that end-to-end, and cross-checks that the two
//! independent recovery mechanisms (replay's decode loop and `scan_tail`) agree
//! on the good-prefix boundary.
//!
//! ## The matrix
//! | Crash shape                | replay_all_segments      | scan_tail            |
//! |----------------------------|--------------------------|----------------------|
//! | clean segment              | indexes all N            | Clean{through=len}   |
//! | torn final frame (mid-app) | indexes N-1, no error    | TornAt{good_through} |
//! | torn frame then completed  | resumes, indexes the +1  | Clean (after finish) |
//! | CRC-corrupt mid frame      | stops at the good prefix | TornAt at that frame |
//!
//! Hand-fabricated segments (no live writer task) keep the bytes deterministic.

use neothd::memory::indexer::replay_all_segments;
use neothd::memory::store;
use neothd::wal::builder::make_header;
use neothd::wal::events::EVENT_TYPE_RAW_TEXT;
use neothd::wal::frame::encode_frame;
use neothd::wal::recovery::{ScanResult, scan_tail};
use neothd::wal::segment_header::SegmentHeader;

/// The canonical segment prelude these tests share.
fn prelude(seq: u64) -> Vec<u8> {
    SegmentHeader::new(0, seq, 0, 0, [0u8; 16])
        .to_le_bytes()
        .to_vec()
}

/// One canonical CRC-valid RAW_TEXT frame. A 1µs gap keeps consecutive
/// `event_id`s (derived from the wall clock) distinct so `INSERT OR IGNORE`
/// never silently drops a row on a coarse-resolution clock.
fn frame(payload: &[u8]) -> Vec<u8> {
    std::thread::sleep(std::time::Duration::from_micros(1));
    let header = make_header(EVENT_TYPE_RAW_TEXT, payload);
    encode_frame(&header, payload)
}

#[tokio::test(flavor = "current_thread")]
async fn clean_segment_replays_fully_and_scans_clean() {
    let dir = tempfile::tempdir().unwrap();
    let wal = dir.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();
    let seg = wal.join("000001.wal");

    let mut bytes = prelude(1);
    for p in [b"alpha".as_slice(), b"bravo", b"charlie"] {
        bytes.extend_from_slice(&frame(p));
    }
    let clean_len = bytes.len() as u64;
    std::fs::write(&seg, &bytes).unwrap();

    // scan_tail: every frame parses + CRC-verifies through to EOF.
    assert_eq!(scan_tail(&bytes), ScanResult::Clean { through: clean_len });

    // replay: all three complete frames indexed.
    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();
    let n = replay_all_segments(&mut conn, &seg).await.unwrap();
    assert_eq!(n, 3, "clean segment → all 3 frames indexed");
}

#[tokio::test(flavor = "current_thread")]
async fn torn_final_frame_recovers_complete_prefix_then_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let wal = dir.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();
    let seg = wal.join("000001.wal");

    // Three complete frames + a fourth that the "crash" truncated mid-write.
    let mut good = prelude(1);
    for p in [b"one".as_slice(), b"two", b"three"] {
        good.extend_from_slice(&frame(p));
    }
    let good_through = good.len() as u64;
    let frame4 = frame(b"four-was-mid-append");

    // Crash image: good prefix + a torn (last 6 bytes lost) fourth frame.
    let mut torn = good.clone();
    torn.extend_from_slice(&frame4[..frame4.len() - 6]);
    std::fs::write(&seg, &torn).unwrap();

    // scan_tail flags the tear exactly at the good-prefix boundary.
    match scan_tail(&torn) {
        ScanResult::TornAt {
            good_through: g,
            torn_at,
        } => {
            assert_eq!(
                g, good_through,
                "good_through = end of the last complete frame"
            );
            assert_eq!(
                torn_at, good_through,
                "tear begins where the half-frame starts"
            );
        }
        other => panic!("expected TornAt, got {other:?}"),
    }

    // replay tolerates the torn tail: indexes the 3 complete frames, no error.
    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();
    let n1 = replay_all_segments(&mut conn, &seg).await.unwrap();
    assert_eq!(n1, 3, "torn tail dropped, complete prefix recovered");

    // Re-running before the frame is finished is a deterministic no-op
    // (the per-segment cursor parked at good_through).
    let n_noop = replay_all_segments(&mut conn, &seg).await.unwrap();
    assert_eq!(n_noop, 0, "no progress until the half-frame is completed");

    // Writer recovers + completes the fourth frame. Replay resumes from the
    // recovery offset and indexes exactly the newly-completed frame.
    let mut completed = good;
    completed.extend_from_slice(&frame4);
    std::fs::write(&seg, &completed).unwrap();
    assert_eq!(
        scan_tail(&completed),
        ScanResult::Clean {
            through: completed.len() as u64
        },
        "segment is clean once the frame is fully written"
    );
    let n2 = replay_all_segments(&mut conn, &seg).await.unwrap();
    assert_eq!(n2, 1, "resume indexes only the completed fourth frame");
}

#[tokio::test(flavor = "current_thread")]
async fn crc_corrupt_mid_frame_halts_replay_at_good_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let wal = dir.path().join("wal");
    std::fs::create_dir_all(&wal).unwrap();
    let seg = wal.join("000001.wal");

    let pre = prelude(1);
    let f1 = frame(b"first-intact");
    let f2 = frame(b"second-will-be-corrupted");
    let f3 = frame(b"third-after-corruption");

    let f2_start = pre.len() + f1.len();
    let mut bytes = pre;
    bytes.extend_from_slice(&f1);
    bytes.extend_from_slice(&f2);
    bytes.extend_from_slice(&f3);

    // Flip a byte inside frame 2 → its CRC no longer matches.
    let corrupt_at = f2_start + f1_mid_offset(&f2);
    bytes[corrupt_at] ^= 0xFF;
    std::fs::write(&seg, &bytes).unwrap();

    // scan_tail reports the tear at frame 2's boundary (frame 1 is the good prefix).
    match scan_tail(&bytes) {
        ScanResult::TornAt { good_through, .. } => {
            assert_eq!(
                good_through, f2_start as u64,
                "good prefix ends at frame 2's start"
            );
        }
        other => panic!("expected TornAt at the corrupt frame, got {other:?}"),
    }

    // replay stops at the corruption (fail-safe: never index past a bad frame),
    // so only the intact frame 1 lands — frame 3 is unreachable until repair.
    let db = dir.path().join("views.db");
    let mut conn = store::open(&db).unwrap();
    let n = replay_all_segments(&mut conn, &seg).await.unwrap();
    assert_eq!(n, 1, "only the pre-corruption frame is indexed");
}

/// A byte offset comfortably inside a frame's body (past the preamble/header,
/// before the trailing CRC) so the flip lands on payload/CRC-covered bytes.
fn f1_mid_offset(frame_bytes: &[u8]) -> usize {
    frame_bytes.len() / 2
}
