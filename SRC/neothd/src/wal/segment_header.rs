// SegmentHeader — first 60 bytes of every WAL segment file.
//
// Spec: PLAN/SPEC_wal_lifecycle.md §2. Wire format is little-endian throughout.
// CRC32c covers bytes [0..56); the 4-byte CRC field itself is excluded.
//
// S8 conformance: NO `#[repr(C, packed)]`. Explicit `from_le_bytes(&[u8; 60])`
// and `to_le_bytes() -> [u8; 60]` per SPEC_wire_header_v2_slim.md §11 pattern.

use crate::wal::error::{HeaderParseError, WalError};

pub const SEGMENT_MAGIC: [u8; 8] = *b"NEOT-SEG";
pub const SEGMENT_HEADER_LEN: usize = 60;
pub const SEGMENT_FORMAT_VERSION: u32 = 1;
pub const SEGMENT_HEADER_CRC_COVERED: usize = 56;

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

impl SegmentHeader {
    /// Construct a new header with `header_crc32c` computed over the other
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
            segment_format_version: SEGMENT_FORMAT_VERSION,
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

    /// Parse 60 bytes into a typed struct. Validates magic, version, and CRC.
    pub fn from_le_bytes(b: &[u8; SEGMENT_HEADER_LEN]) -> Result<Self, WalError> {
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
}
