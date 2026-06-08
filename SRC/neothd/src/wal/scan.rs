//! GOLD-ARCH-03 — the single v2-transparent WAL frame iterator.
//!
//! Every caller that scans a sealed segment's frames should go through
//! [`for_each_frame`] (or [`super::compaction::logical_segment_bytes`] directly
//! when it also needs the reconstructed byte slice for windowing, e.g. HMAC
//! marker verification). The hazard this closes: a finalized COMPRESSED (v2)
//! segment stores its frames as one zstd blob after a 61-byte header. Callers
//! that skipped a hard-coded `SEGMENT_HEADER_LEN` (60) and ran `decode_frame`
//! over the RAW file bytes therefore (a) misaligned by 1 byte even on an
//! uncompressed v2 segment, and (b) silently saw ZERO frames on every
//! compressed segment — the indexer dropped events, rollback/undo lost
//! snapshots, audits read nothing. `for_each_frame` reconstructs the logical
//! (decompressed) bytes once via `logical_segment_bytes`, then walks frames
//! from the correct header offset.

use anyhow::Result;

use super::compaction::logical_segment_bytes;
use super::frame::{DecodedFrame, decode_frame};
use super::segment_header::SEGMENT_HEADER_LEN;

/// Iterate every frame in a WAL segment, transparently handling v1 (plain) and
/// v2 (zstd-compressed) segments. `cb` receives `(cursor, &frame)` where
/// `cursor` is the frame's byte offset inside the LOGICAL (decompressed)
/// segment — identical to the offset v1 callers already tracked, and the value
/// the `wal_cursor` table + rollback `absolute_offset` are measured in.
///
/// Stops cleanly at a torn / short trailing frame (a crashed writer may leave a
/// partial frame), guards against a `total_len == 0` infinite loop, and treats a
/// segment shorter than a header as empty (not an error). Returns the first
/// error from `cb` (a caller may `bail!` to abort the walk early) or from an
/// unreconstructable — tamper-suspect — compressed blob.
pub(crate) fn for_each_frame<F>(seg_bytes: &[u8], mut cb: F) -> Result<()>
where
    F: FnMut(usize, &DecodedFrame<'_>) -> Result<()>,
{
    if seg_bytes.len() < SEGMENT_HEADER_LEN {
        return Ok(());
    }
    let (header_len, logical) = logical_segment_bytes(seg_bytes)?;
    let mut cursor = header_len;
    while cursor < logical.len() {
        let dec = match decode_frame(&logical[cursor..]) {
            Ok(d) => d,
            // Torn / partial trailing frame (crashed writer) — stop walking.
            Err(_) => break,
        };
        let total = dec.header.total_len as usize;
        if total == 0 {
            // Defensive: a zero-length frame would loop forever.
            break;
        }
        cb(cursor, &dec)?;
        cursor += total;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::HeaderBuilder;
    use crate::wal::compress::compress_frames;
    use crate::wal::frame::encode_frame;
    use crate::wal::segment_header::{
        SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_V2_LEN, SegmentHeaderV2,
    };

    fn frame_bytes(event_type: u8, payload: &[u8]) -> Vec<u8> {
        let h = HeaderBuilder::new(event_type, payload).build();
        encode_frame(&h, payload)
    }

    /// Three distinct frames concatenated, plus each frame's length.
    fn three_frames() -> (Vec<u8>, Vec<usize>) {
        let f1 = frame_bytes(0x01, b"one");
        let f2 = frame_bytes(0x02, b"two-two");
        let f3 = frame_bytes(0x03, b"three-three-three");
        let lens = vec![f1.len(), f2.len(), f3.len()];
        let mut all = Vec::new();
        all.extend_from_slice(&f1);
        all.extend_from_slice(&f2);
        all.extend_from_slice(&f3);
        (all, lens)
    }

    fn uncompressed_segment(frames: &[u8]) -> Vec<u8> {
        let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], 0);
        let mut seg = hdr.to_le_bytes().to_vec();
        seg.extend_from_slice(frames);
        seg
    }

    fn compressed_segment(frames: &[u8]) -> Vec<u8> {
        let blob = compress_frames(frames).unwrap();
        let hdr = SegmentHeaderV2::new(1, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
        let mut seg = hdr.to_le_bytes().to_vec();
        seg.extend_from_slice(&blob);
        seg
    }

    #[test]
    fn empty_or_short_segment_yields_no_frames() {
        let mut called = 0;
        for_each_frame(&[0u8; 10], |_, _| {
            called += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(called, 0);
    }

    #[test]
    fn uncompressed_segment_yields_all_frames_with_logical_cursors() {
        let (frames, lens) = three_frames();
        let seg = uncompressed_segment(&frames);
        let mut seen: Vec<(usize, u8, Vec<u8>)> = Vec::new();
        for_each_frame(&seg, |cursor, dec| {
            seen.push((cursor, dec.header.event_type, dec.payload.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen.len(), 3);
        // Cursors are measured inside the logical slice (header_len = 61 here).
        assert_eq!(seen[0].0, SEGMENT_HEADER_V2_LEN);
        assert_eq!(seen[1].0, SEGMENT_HEADER_V2_LEN + lens[0]);
        assert_eq!(seen[2].0, SEGMENT_HEADER_V2_LEN + lens[0] + lens[1]);
        assert_eq!(seen[0].1, 0x01);
        assert_eq!(seen[2].2, b"three-three-three");
    }

    #[test]
    fn compressed_v2_segment_yields_all_frames() {
        // THE BUG FIX: a raw-byte scanner (skip 60 + decode_frame on the file
        // bytes) sees ZERO frames here because the body is a zstd blob.
        let (frames, _) = three_frames();
        let seg = compressed_segment(&frames);
        let mut seen: Vec<u8> = Vec::new();
        for_each_frame(&seg, |_, dec| {
            seen.push(dec.header.event_type);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            seen,
            vec![0x01, 0x02, 0x03],
            "every frame inside the zstd blob must be iterated, not skipped"
        );
    }

    #[test]
    fn torn_tail_after_good_frames_is_silently_skipped() {
        let (frames, _) = three_frames();
        let mut seg = uncompressed_segment(&frames);
        seg.extend_from_slice(b"garbage partial frame tail"); // not a full frame
        let mut called = 0;
        for_each_frame(&seg, |_, _| {
            called += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(called, 3, "the torn tail after the 3 good frames is dropped");
    }

    #[test]
    fn cb_error_aborts_the_walk_early() {
        let (frames, _) = three_frames();
        let seg = uncompressed_segment(&frames);
        let mut called = 0;
        let r = for_each_frame(&seg, |_, _| {
            called += 1;
            if called == 2 {
                anyhow::bail!("caller stop");
            }
            Ok(())
        });
        assert!(r.is_err(), "a cb error propagates out of the walk");
        assert_eq!(called, 2, "the walk stops at the failing frame");
    }
}
