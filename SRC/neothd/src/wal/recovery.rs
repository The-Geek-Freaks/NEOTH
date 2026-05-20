//! WAL torn-frame recovery (Pick #35, Session 14).
//!
//! Why this exists: an unclean shutdown (Windows hard-kill, power
//! loss, OOM) can leave the last WAL frame partially written. The
//! indexer's `replay_once` walks frames until it hits a parse error
//! and stops; but the WRITER reopens at `metadata().len()` — which
//! includes the torn tail bytes. The next append lands AFTER the
//! garbage, producing a segment that contains a parse-fail island
//! between two valid regions. Subsequent `neoth verify` runs would
//! also choke on the torn frame.
//!
//! The fix is to scan the tail at writer-startup, find the offset of
//! the last verified-good frame, and truncate to that point BEFORE
//! the WriterState is constructed. A `RECOVERY_TRUNCATED` (0x50) WAL
//! event documents what was dropped so the operator's audit log
//! reflects the truncation.
//!
//! ## Algorithm
//!
//! Walk frames starting at `SEGMENT_HEADER_LEN` using `frame::decode_frame`.
//! For each frame:
//!   - parse-error → torn at current offset
//!   - parsed but `total_len` out of sanity range (too small to be a
//!     frame at all OR larger than `MAX_PAYLOAD_BYTES + headers`) → torn
//!   - parsed but `offset + total_len > bytes.len()` → torn (cut short)
//!   - parsed cleanly → advance by `total_len`, repeat
//!
//! End-of-buffer with no error = `Clean { through: offset }`.
//!
//! Recovery action is truncate-not-quarantine: partial-payload bytes
//! cannot be recovered into meaningful events, and a `.torn` sidecar
//! file adds complexity without operator-actionable value for a
//! solo-operator deployment. The torn bytes are gone.
//!
//! ## What this is NOT
//!
//! - **Not a full segment audit.** Mid-segment torn frames (between
//!   good frames on either side) cannot happen with the current
//!   append-only writer — only the TAIL can be torn. If a segment
//!   has mid-frame corruption it indicates filesystem-level damage,
//!   which is outside the scope of this recovery pass.
//! - **Not a checksum scan over the whole segment.** That's what
//!   `neoth verify` is for. Recovery only walks the tail.

use super::frame::decode_frame;
use super::header::{CRC_LEN, HEADER_BODY_LEN, PREAMBLE_LEN};
use super::segment_header::SEGMENT_HEADER_LEN;
use super::writer::MAX_PAYLOAD_BYTES;

/// Minimum plausible frame size: preamble + header body + 0-byte
/// payload + CRC. Anything smaller in `total_len` is corruption.
pub const MIN_FRAME_LEN: usize = PREAMBLE_LEN + HEADER_BODY_LEN + CRC_LEN;

/// Maximum plausible frame size: preamble + header body + max payload
/// + CRC. Anything larger indicates a corrupt length field.
pub const MAX_FRAME_LEN: usize = PREAMBLE_LEN + HEADER_BODY_LEN + MAX_PAYLOAD_BYTES + CRC_LEN;

/// Result of scanning a segment's tail for torn frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanResult {
    /// Tail is clean — every frame from `SEGMENT_HEADER_LEN` through
    /// `through` parsed + CRC-verified. The writer should reopen at
    /// `through` for the next append.
    Clean { through: u64 },
    /// Tail is torn — frames from `SEGMENT_HEADER_LEN` through
    /// `good_through` parsed cleanly, but the bytes starting at
    /// `torn_at` are corrupt or truncated. The writer should
    /// truncate the segment to `good_through` and emit a
    /// `RECOVERY_TRUNCATED` audit frame.
    TornAt { good_through: u64, torn_at: u64 },
}

impl ScanResult {
    /// Byte offset the writer should reopen at — `Clean.through` or
    /// `TornAt.good_through`. Always returns a usable resume point.
    pub fn resume_offset(self) -> u64 {
        match self {
            ScanResult::Clean { through } => through,
            ScanResult::TornAt { good_through, .. } => good_through,
        }
    }

    /// `true` when the scan found torn bytes that need truncation.
    pub fn is_torn(self) -> bool {
        matches!(self, ScanResult::TornAt { .. })
    }
}

/// Walk frames from `SEGMENT_HEADER_LEN` to the end of `segment_bytes`.
/// Returns `Clean` when every frame decodes + CRC-validates;
/// `TornAt` on the first corrupt or truncated frame.
///
/// The scan is single-pass and bounded by `segment_bytes.len()` —
/// safe to run against multi-MB segments without unbounded recursion
/// or auxiliary storage.
pub fn scan_tail(segment_bytes: &[u8]) -> ScanResult {
    // Segment header itself is verified separately by `SegmentHeader::
    // decode`. If the segment is too short to even hold a header, the
    // scan returns Clean-at-len: there's nothing to truncate, the
    // writer's `open_segment` handles the new-segment path.
    if segment_bytes.len() < SEGMENT_HEADER_LEN {
        return ScanResult::Clean {
            through: segment_bytes.len() as u64,
        };
    }
    let mut offset: usize = SEGMENT_HEADER_LEN;
    let mut last_good: usize = SEGMENT_HEADER_LEN;

    while offset < segment_bytes.len() {
        let slice = &segment_bytes[offset..];

        // First sanity: the slice must hold at least a minimum frame.
        // If shorter we have torn-bytes-without-even-a-header at the
        // tail. Treat as torn.
        if slice.len() < MIN_FRAME_LEN {
            return ScanResult::TornAt {
                good_through: last_good as u64,
                torn_at: offset as u64,
            };
        }

        match decode_frame(slice) {
            Ok(decoded) => {
                let total = decoded.header.total_len as usize;
                // Sanity: total_len must be plausible.
                if !(MIN_FRAME_LEN..=MAX_FRAME_LEN).contains(&total) {
                    return ScanResult::TornAt {
                        good_through: last_good as u64,
                        torn_at: offset as u64,
                    };
                }
                // Sanity: the frame must FIT in the remaining bytes.
                // `decode_frame` already checks this for the case where
                // the header is intact but the payload+CRC ran short;
                // belt-and-suspenders for the case where decode_frame
                // is permissive.
                if offset.checked_add(total).is_none() || offset + total > segment_bytes.len() {
                    return ScanResult::TornAt {
                        good_through: last_good as u64,
                        torn_at: offset as u64,
                    };
                }
                last_good = offset + total;
                offset = last_good;
            }
            Err(_) => {
                // Parse / CRC / magic failure — torn at current offset.
                return ScanResult::TornAt {
                    good_through: last_good as u64,
                    torn_at: offset as u64,
                };
            }
        }
    }
    ScanResult::Clean {
        through: last_good as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::HeaderBuilder;
    use crate::wal::frame::encode_frame;
    use crate::wal::segment_header::SegmentHeader;

    fn fake_segment_header_bytes() -> Vec<u8> {
        // SegmentHeader::new(generation, segment_seq, first_event_id,
        //                    segment_start_ts_ns, node_id)
        let header = SegmentHeader::new(1, 1, 0, 0, [0u8; 16]);
        header.to_le_bytes().to_vec()
    }

    fn append_frame(buf: &mut Vec<u8>, event_type: u8, payload: &[u8]) {
        let header = HeaderBuilder::new(event_type, payload).build();
        let frame = encode_frame(&header, payload);
        buf.extend_from_slice(&frame);
    }

    #[test]
    fn scan_empty_segment_returns_clean() {
        let bytes = fake_segment_header_bytes();
        match scan_tail(&bytes) {
            ScanResult::Clean { through } => {
                assert_eq!(through, SEGMENT_HEADER_LEN as u64);
            }
            other => panic!("expected Clean, got {other:?}"),
        }
    }

    #[test]
    fn scan_segment_with_two_good_frames_is_clean() {
        let mut bytes = fake_segment_header_bytes();
        append_frame(&mut bytes, 0x10, b"first payload");
        append_frame(&mut bytes, 0x11, b"second payload");
        let total_len = bytes.len() as u64;
        match scan_tail(&bytes) {
            ScanResult::Clean { through } => assert_eq!(through, total_len),
            other => panic!("expected Clean, got {other:?}"),
        }
    }

    #[test]
    fn scan_segment_with_torn_tail_returns_torn_at() {
        let mut bytes = fake_segment_header_bytes();
        append_frame(&mut bytes, 0x10, b"intact frame");
        let intact_end = bytes.len();
        // Append a torn frame: cut off the last 5 bytes after writing
        // a complete second frame.
        append_frame(&mut bytes, 0x11, b"this will be cut");
        bytes.truncate(bytes.len() - 5);
        match scan_tail(&bytes) {
            ScanResult::TornAt {
                good_through,
                torn_at,
            } => {
                assert_eq!(good_through, intact_end as u64);
                assert_eq!(torn_at, intact_end as u64);
            }
            other => panic!("expected TornAt, got {other:?}"),
        }
    }

    #[test]
    fn scan_segment_with_torn_header_returns_torn_at() {
        let mut bytes = fake_segment_header_bytes();
        append_frame(&mut bytes, 0x10, b"good");
        let intact_end = bytes.len();
        // Append 3 bytes of garbage — too short to even contain a
        // minimum frame.
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE]);
        match scan_tail(&bytes) {
            ScanResult::TornAt {
                good_through,
                torn_at,
            } => {
                assert_eq!(good_through, intact_end as u64);
                assert_eq!(torn_at, intact_end as u64);
            }
            other => panic!("expected TornAt, got {other:?}"),
        }
    }

    #[test]
    fn scan_segment_with_corrupt_crc_returns_torn_at() {
        let mut bytes = fake_segment_header_bytes();
        append_frame(&mut bytes, 0x10, b"good");
        let intact_end = bytes.len();
        append_frame(&mut bytes, 0x11, b"this frame will have corrupt CRC");
        // Flip the last CRC byte of the second frame.
        let len = bytes.len();
        bytes[len - 1] ^= 0xFF;
        match scan_tail(&bytes) {
            ScanResult::TornAt {
                good_through,
                torn_at,
            } => {
                assert_eq!(good_through, intact_end as u64);
                assert_eq!(torn_at, intact_end as u64);
            }
            other => panic!("expected TornAt for corrupt CRC, got {other:?}"),
        }
    }

    #[test]
    fn scan_segment_below_segment_header_returns_clean_at_len() {
        // Pathological: a file with fewer than SEGMENT_HEADER_LEN bytes
        // (probably a fresh-but-not-yet-written segment file). Scan
        // returns Clean at the file's len so the writer's open_segment
        // path can take over with the new-segment header write.
        let bytes = vec![0u8; SEGMENT_HEADER_LEN - 10];
        match scan_tail(&bytes) {
            ScanResult::Clean { through } => assert_eq!(through, bytes.len() as u64),
            other => panic!("expected Clean, got {other:?}"),
        }
    }

    #[test]
    fn scan_result_resume_offset_picks_safe_value() {
        let clean = ScanResult::Clean { through: 1024 };
        assert_eq!(clean.resume_offset(), 1024);
        let torn = ScanResult::TornAt {
            good_through: 1024,
            torn_at: 1500,
        };
        assert_eq!(torn.resume_offset(), 1024);
    }

    #[test]
    fn scan_result_is_torn_predicate() {
        assert!(!ScanResult::Clean { through: 0 }.is_torn());
        assert!(
            ScanResult::TornAt {
                good_through: 0,
                torn_at: 0,
            }
            .is_torn()
        );
    }

    #[test]
    fn min_max_frame_constants_sane() {
        // MIN_FRAME_LEN is the empty-payload frame size.
        // MAX_FRAME_LEN is the same plus MAX_PAYLOAD_BYTES.
        const _: () = assert!(MIN_FRAME_LEN > 0);
        const _: () = assert!(MAX_FRAME_LEN > MIN_FRAME_LEN);
        assert_eq!(MAX_FRAME_LEN - MIN_FRAME_LEN, MAX_PAYLOAD_BYTES);
    }
}
