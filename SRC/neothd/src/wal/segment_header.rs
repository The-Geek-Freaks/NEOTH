// SegmentHeader — WAL segment file headers.
//
// Spec: PLAN/SPEC_wal_lifecycle.md §2. Wire format is little-endian throughout.
//
// ## Format versions
//
// **v1 (60 bytes):** magic(8) + format_version(4) + generation(4) +
//   segment_seq(8) + first_event_id(8) + segment_start_ts_ns(8) +
//   node_id(16) + header_crc32c(4).
//   CRC32c covers bytes [0..56); frames follow uncompressed.
//
// **v2 (61 bytes):** same layout + 1-byte `flags` appended AFTER header_crc32c.
//   The flags byte is NOT covered by the CRC (CRC still covers bytes [0..56)).
//   When SEGMENT_FLAG_COMPRESSED (0x01) is set, the bytes after the 61-byte
//   header are a single zstd frame containing all WAL frames for this segment.
//   Reader decompresses before parsing individual WAL frames.
//
// S8 conformance: NO `#[repr(C, packed)]`. Explicit `from_le_bytes` and
// `to_le_bytes` per SPEC_wire_header_v2_slim.md §11 pattern.
//
// Workstream F (CT-10/E-20/V1x-06) — v1.2 milestone ships v2 + zstd-3.

use crate::wal::error::{HeaderParseError, WalError};

pub const SEGMENT_MAGIC: [u8; 8] = *b"NEOT-SEG";
/// v1 header size — unchanged for backward compat.
pub const SEGMENT_HEADER_LEN: usize = 60;
/// v2 header size — 60 bytes + 1 flags byte.
pub const SEGMENT_HEADER_V2_LEN: usize = 61;
/// Current format version written by the writer.
/// Bumped from 1 → 2 in Workstream F (CT-10/E-20/V1x-06).
pub const SEGMENT_FORMAT_VERSION: u32 = 2;
/// Legacy v1 constant — reader accepts both 1 and 2.
pub const SEGMENT_FORMAT_VERSION_V1: u32 = 1;
pub const SEGMENT_HEADER_CRC_COVERED: usize = 56;

/// CT-10 (Session 21) — segment-flag bit values for the v1.2 wire format.
/// The `flags` byte is the 61st byte of a v2 header, appended after
/// `header_crc32c` and NOT covered by the CRC.
///
/// **Workstream F**: SEGMENT_FLAG_COMPRESSED is now HONOURED. When set the
/// frame body is a single zstd frame; reader decompresses before parsing.
pub const SEGMENT_FLAG_COMPRESSED: u8 = 0x01;
pub const SEGMENT_FLAG_SEALED: u8 = 0x02;
pub const SEGMENT_FLAG_DEFERRED_REPLICATION: u8 = 0x04;

/// v1 segment header — 60 bytes, no flags, all frames uncompressed.
/// Produced by pre-Workstream-F writers; still accepted by the reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentHeader {
    pub magic: [u8; 8],
    pub segment_format_version: u32,
    pub generation: u32,
    pub segment_seq: u64,
    pub first_event_id: u64,
    pub segment_start_ts_ns: u64,
    pub node_id: [u8; 16],
    pub header_crc32c: u32,
}

/// v2 segment header — 61 bytes. Adds a `flags: u8` slot after `header_crc32c`.
/// Written by Workstream-F writers. When `flags & SEGMENT_FLAG_COMPRESSED != 0`
/// the frame body is a zstd-compressed blob; reader must decompress it first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentHeaderV2 {
    pub magic: [u8; 8],
    pub segment_format_version: u32,
    pub generation: u32,
    pub segment_seq: u64,
    pub first_event_id: u64,
    pub segment_start_ts_ns: u64,
    pub node_id: [u8; 16],
    pub header_crc32c: u32,
    /// Bit flags for this segment. See `SEGMENT_FLAG_*` constants.
    pub flags: u8,
}

/// Unified result from `parse_segment_header` — caller uses pattern-match
/// to determine header length and whether decompression is needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParsedSegmentHeader {
    V1(SegmentHeader),
    V2(SegmentHeaderV2),
}

impl ParsedSegmentHeader {
    pub fn segment_seq(&self) -> u64 {
        match self {
            Self::V1(h) => h.segment_seq,
            Self::V2(h) => h.segment_seq,
        }
    }

    pub fn segment_format_version(&self) -> u32 {
        match self {
            Self::V1(h) => h.segment_format_version,
            Self::V2(h) => h.segment_format_version,
        }
    }

    /// True when the frame body following this header is zstd-compressed.
    pub fn is_compressed(&self) -> bool {
        match self {
            Self::V1(_) => false,
            Self::V2(h) => (h.flags & SEGMENT_FLAG_COMPRESSED) != 0,
        }
    }

    /// Wire length of this header in bytes (60 for v1, 61 for v2).
    pub fn header_len(&self) -> usize {
        match self {
            Self::V1(_) => SEGMENT_HEADER_LEN,
            Self::V2(_) => SEGMENT_HEADER_V2_LEN,
        }
    }
}

impl SegmentHeader {
    /// Construct a new v1 header with `header_crc32c` computed over the other
    /// fields. The CRC is automatically derived from the rest of the struct.
    pub fn new(
        generation: u32,
        segment_seq: u64,
        first_event_id: u64,
        segment_start_ts_ns: u64,
        node_id: [u8; 16],
    ) -> Self {
        let mut hdr = SegmentHeader {
            magic: SEGMENT_MAGIC,
            segment_format_version: SEGMENT_FORMAT_VERSION_V1,
            generation,
            segment_seq,
            first_event_id,
            segment_start_ts_ns,
            node_id,
            header_crc32c: 0,
        };
        hdr.header_crc32c = hdr.compute_crc();
        hdr
    }

    /// CRC32c over the 56 bytes preceding the `header_crc32c` field.
    fn compute_crc(&self) -> u32 {
        let mut buf = [0u8; SEGMENT_HEADER_CRC_COVERED];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..12].copy_from_slice(&self.segment_format_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.generation.to_le_bytes());
        buf[16..24].copy_from_slice(&self.segment_seq.to_le_bytes());
        buf[24..32].copy_from_slice(&self.first_event_id.to_le_bytes());
        buf[32..40].copy_from_slice(&self.segment_start_ts_ns.to_le_bytes());
        buf[40..56].copy_from_slice(&self.node_id);
        crc32c::crc32c(&buf)
    }

    /// Parse exactly 60 bytes as a v1 header. Validates magic, version (must
    /// be 1), and CRC. Returns `UnknownFormat` for any other version so callers
    /// can fall through to v2 parsing.
    pub fn from_le_bytes(b: &[u8; SEGMENT_HEADER_LEN]) -> Result<Self, WalError> {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&b[0..8]);
        if magic != SEGMENT_MAGIC {
            return Err(WalError::Header(HeaderParseError::InvalidMagic {
                got: [magic[0], magic[1], magic[2], magic[3]],
            }));
        }
        let segment_format_version = u32::from_le_bytes(b[8..12].try_into().unwrap());
        if segment_format_version != SEGMENT_FORMAT_VERSION_V1 {
            return Err(WalError::UnknownFormat {
                version: segment_format_version as u8,
            });
        }
        let generation = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let segment_seq = u64::from_le_bytes(b[16..24].try_into().unwrap());
        let first_event_id = u64::from_le_bytes(b[24..32].try_into().unwrap());
        let segment_start_ts_ns = u64::from_le_bytes(b[32..40].try_into().unwrap());
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&b[40..56]);
        let header_crc32c = u32::from_le_bytes(b[56..60].try_into().unwrap());

        let computed = crc32c::crc32c(&b[0..SEGMENT_HEADER_CRC_COVERED]);
        if computed != header_crc32c {
            return Err(WalError::SegmentHeaderCorrupt {
                seq: segment_seq,
                expected_crc: header_crc32c,
                got_crc: computed,
            });
        }

        Ok(SegmentHeader {
            magic,
            segment_format_version,
            generation,
            segment_seq,
            first_event_id,
            segment_start_ts_ns,
            node_id,
            header_crc32c,
        })
    }

    pub fn to_le_bytes(&self) -> [u8; SEGMENT_HEADER_LEN] {
        let mut b = [0u8; SEGMENT_HEADER_LEN];
        b[0..8].copy_from_slice(&self.magic);
        b[8..12].copy_from_slice(&self.segment_format_version.to_le_bytes());
        b[12..16].copy_from_slice(&self.generation.to_le_bytes());
        b[16..24].copy_from_slice(&self.segment_seq.to_le_bytes());
        b[24..32].copy_from_slice(&self.first_event_id.to_le_bytes());
        b[32..40].copy_from_slice(&self.segment_start_ts_ns.to_le_bytes());
        b[40..56].copy_from_slice(&self.node_id);
        b[56..60].copy_from_slice(&self.header_crc32c.to_le_bytes());
        b
    }
}

impl SegmentHeaderV2 {
    /// Construct a new v2 header. CRC is computed over the same 56 bytes as v1
    /// (the flags byte is NOT included in the CRC — backward-compatible with
    /// any CRC tools that only read 60 bytes). Pass `flags = 0` for an
    /// uncompressed v2 segment; `flags = SEGMENT_FLAG_COMPRESSED` for zstd.
    pub fn new(
        generation: u32,
        segment_seq: u64,
        first_event_id: u64,
        segment_start_ts_ns: u64,
        node_id: [u8; 16],
        flags: u8,
    ) -> Self {
        let mut hdr = SegmentHeaderV2 {
            magic: SEGMENT_MAGIC,
            segment_format_version: SEGMENT_FORMAT_VERSION,
            generation,
            segment_seq,
            first_event_id,
            segment_start_ts_ns,
            node_id,
            header_crc32c: 0,
            flags,
        };
        hdr.header_crc32c = hdr.compute_crc();
        hdr
    }

    fn compute_crc(&self) -> u32 {
        let mut buf = [0u8; SEGMENT_HEADER_CRC_COVERED];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..12].copy_from_slice(&self.segment_format_version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.generation.to_le_bytes());
        buf[16..24].copy_from_slice(&self.segment_seq.to_le_bytes());
        buf[24..32].copy_from_slice(&self.first_event_id.to_le_bytes());
        buf[32..40].copy_from_slice(&self.segment_start_ts_ns.to_le_bytes());
        buf[40..56].copy_from_slice(&self.node_id);
        crc32c::crc32c(&buf)
    }

    /// Parse exactly 61 bytes as a v2 header.
    pub fn from_le_bytes(b: &[u8; SEGMENT_HEADER_V2_LEN]) -> Result<Self, WalError> {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&b[0..8]);
        if magic != SEGMENT_MAGIC {
            return Err(WalError::Header(HeaderParseError::InvalidMagic {
                got: [magic[0], magic[1], magic[2], magic[3]],
            }));
        }
        let segment_format_version = u32::from_le_bytes(b[8..12].try_into().unwrap());
        if segment_format_version != SEGMENT_FORMAT_VERSION {
            return Err(WalError::UnknownFormat {
                version: segment_format_version as u8,
            });
        }
        let generation = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let segment_seq = u64::from_le_bytes(b[16..24].try_into().unwrap());
        let first_event_id = u64::from_le_bytes(b[24..32].try_into().unwrap());
        let segment_start_ts_ns = u64::from_le_bytes(b[32..40].try_into().unwrap());
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&b[40..56]);
        let header_crc32c = u32::from_le_bytes(b[56..60].try_into().unwrap());
        let flags = b[60];

        let computed = crc32c::crc32c(&b[0..SEGMENT_HEADER_CRC_COVERED]);
        if computed != header_crc32c {
            return Err(WalError::SegmentHeaderCorrupt {
                seq: segment_seq,
                expected_crc: header_crc32c,
                got_crc: computed,
            });
        }

        Ok(SegmentHeaderV2 {
            magic,
            segment_format_version,
            generation,
            segment_seq,
            first_event_id,
            segment_start_ts_ns,
            node_id,
            header_crc32c,
            flags,
        })
    }

    pub fn to_le_bytes(&self) -> [u8; SEGMENT_HEADER_V2_LEN] {
        let mut b = [0u8; SEGMENT_HEADER_V2_LEN];
        b[0..8].copy_from_slice(&self.magic);
        b[8..12].copy_from_slice(&self.segment_format_version.to_le_bytes());
        b[12..16].copy_from_slice(&self.generation.to_le_bytes());
        b[16..24].copy_from_slice(&self.segment_seq.to_le_bytes());
        b[24..32].copy_from_slice(&self.first_event_id.to_le_bytes());
        b[32..40].copy_from_slice(&self.segment_start_ts_ns.to_le_bytes());
        b[40..56].copy_from_slice(&self.node_id);
        b[56..60].copy_from_slice(&self.header_crc32c.to_le_bytes());
        b[60] = self.flags;
        b
    }
}

/// Auto-detect the segment header format from raw segment bytes.
/// Reads the version field from bytes [8..12] and dispatches:
/// - version 1 → parse first 60 bytes as `SegmentHeader` (v1)
/// - version 2 → parse first 61 bytes as `SegmentHeaderV2`
/// - anything else → `WalError::UnknownFormat`
///
/// This is the single entry point used by the reader and migrate tool.
pub fn parse_segment_header(raw: &[u8]) -> Result<ParsedSegmentHeader, WalError> {
    if raw.len() < SEGMENT_HEADER_LEN {
        return Err(WalError::UnknownFormat { version: 0 });
    }
    // Peek at magic first.
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&raw[0..8]);
    if magic != SEGMENT_MAGIC {
        return Err(WalError::Header(HeaderParseError::InvalidMagic {
            got: [magic[0], magic[1], magic[2], magic[3]],
        }));
    }
    let version = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    match version {
        SEGMENT_FORMAT_VERSION_V1 => {
            let arr: &[u8; SEGMENT_HEADER_LEN] = raw[..SEGMENT_HEADER_LEN].try_into().unwrap();
            Ok(ParsedSegmentHeader::V1(SegmentHeader::from_le_bytes(arr)?))
        }
        SEGMENT_FORMAT_VERSION => {
            if raw.len() < SEGMENT_HEADER_V2_LEN {
                return Err(WalError::UnknownFormat { version: 2 });
            }
            let arr: &[u8; SEGMENT_HEADER_V2_LEN] =
                raw[..SEGMENT_HEADER_V2_LEN].try_into().unwrap();
            Ok(ParsedSegmentHeader::V2(SegmentHeaderV2::from_le_bytes(
                arr,
            )?))
        }
        other => Err(WalError::UnknownFormat {
            version: other as u8,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(seq: u64) -> SegmentHeader {
        SegmentHeader::new(7, seq, 42, 1_700_000_000_000_000_000, [9u8; 16])
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let h = fixture(3);
        let bytes = h.to_le_bytes();
        assert_eq!(bytes.len(), 60);
        let parsed = SegmentHeader::from_le_bytes(&bytes).expect("parse");
        assert_eq!(parsed, h);
    }

    #[test]
    fn parser_rejects_bad_magic() {
        let h = fixture(1);
        let mut bytes = h.to_le_bytes();
        bytes[0] = b'X';
        let err = SegmentHeader::from_le_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            WalError::Header(HeaderParseError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn parser_rejects_wrong_format_version() {
        let h = fixture(1);
        let mut bytes = h.to_le_bytes();
        bytes[8] = 0x99; // segment_format_version = 0x99
        // need to recompute CRC32c so we don't get CRC error instead
        let new_crc = crc32c::crc32c(&bytes[..SEGMENT_HEADER_CRC_COVERED]);
        bytes[56..60].copy_from_slice(&new_crc.to_le_bytes());
        let err = SegmentHeader::from_le_bytes(&bytes).unwrap_err();
        assert!(matches!(err, WalError::UnknownFormat { .. }));
    }

    #[test]
    fn parser_rejects_corrupt_crc() {
        let h = fixture(1);
        let mut bytes = h.to_le_bytes();
        bytes[12] ^= 0x01; // corrupt generation field
        let err = SegmentHeader::from_le_bytes(&bytes).unwrap_err();
        match err {
            WalError::SegmentHeaderCorrupt {
                seq,
                expected_crc: _,
                got_crc: _,
            } => assert_eq!(seq, 1),
            other => panic!("expected SegmentHeaderCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn new_computes_consistent_crc() {
        let a = fixture(5);
        let b = SegmentHeader::new(7, 5, 42, 1_700_000_000_000_000_000, [9u8; 16]);
        assert_eq!(a.header_crc32c, b.header_crc32c);
        assert_ne!(a.header_crc32c, 0);
    }

    // ── CT-10 v1.2 flag-bit reservations ───────────────────────

    #[test]
    fn segment_flag_bit_values_pinned_and_distinct() {
        // Drift guard — a v1.2 developer re-using one of these bits
        // for a different feature would silently corrupt existing
        // segments. Pin both the values AND mutual distinctness.
        assert_eq!(SEGMENT_FLAG_COMPRESSED, 0x01);
        assert_eq!(SEGMENT_FLAG_SEALED, 0x02);
        assert_eq!(SEGMENT_FLAG_DEFERRED_REPLICATION, 0x04);
        // Distinct bits — bitwise OR of all three uses every reserved
        // bit exactly once.
        assert_eq!(
            SEGMENT_FLAG_COMPRESSED | SEGMENT_FLAG_SEALED | SEGMENT_FLAG_DEFERRED_REPLICATION,
            0x07
        );
        // No overlap.
        assert_eq!(SEGMENT_FLAG_COMPRESSED & SEGMENT_FLAG_SEALED, 0);
        assert_eq!(
            SEGMENT_FLAG_COMPRESSED & SEGMENT_FLAG_DEFERRED_REPLICATION,
            0
        );
        assert_eq!(SEGMENT_FLAG_SEALED & SEGMENT_FLAG_DEFERRED_REPLICATION, 0);
    }
}
