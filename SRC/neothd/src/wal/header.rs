// EventHeaderV2 -- 96-byte WAL header.
// SPEC_wire_header_v2_slim.md §3-§11. Wire format is authoritative; the Rust struct
// is for ergonomics. NEVER dump struct to disk directly. S8 fix: no #[repr(C, packed)].

use super::error::HeaderParseError;
use super::hlc::Hlc;
use super::types::{EventFlags, EventId, Importance, NodeId, SessionId, WalCategory, WalScope};

pub const MAGIC: [u8; 4] = *b"NEOT";
pub const WAL_FORMAT_VERSION: u8 = 0x02;
pub const EVENT_SCHEMA_VERSION: u8 = 0x04;
pub const HEADER_BODY_LEN: usize = 96;
pub const CRC_LEN: usize = 4;
pub const PREAMBLE_LEN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventHeaderV2 {
    pub wal_format_version: u8,
    pub event_schema_version: u8,
    pub event_type: u8,
    pub event_subtype: u8,
    pub flags: EventFlags,
    pub header_len: u16,
    pub reserved_len: u16,
    pub total_len: u32,
    pub payload_len: u32,
    pub generation: u32,
    pub event_id: EventId,
    pub hlc: Hlc,
    pub importance: Importance,
    pub scope: WalScope,
    pub category: WalCategory,
    pub session_id: SessionId,
    pub node_id: NodeId,
    pub payload_hash: u64,
}

impl EventHeaderV2 {
    pub const HEADER_BODY_LEN: usize = HEADER_BODY_LEN;
    pub const WAL_FORMAT_VERSION: u8 = WAL_FORMAT_VERSION;
    pub const EVENT_SCHEMA_VERSION: u8 = EVENT_SCHEMA_VERSION;
    pub const MAGIC: [u8; 4] = MAGIC;

    /// Parse 96 bytes (header body, EXCLUDING the 4-byte magic preamble).
    /// All multi-byte integers are little-endian. Validates invariants.
    pub fn from_le_bytes(b: &[u8; HEADER_BODY_LEN]) -> Result<Self, HeaderParseError> {
        let wal_format_version = b[0];
        if wal_format_version != WAL_FORMAT_VERSION {
            return Err(HeaderParseError::UnknownWalFormat {
                got: wal_format_version,
            });
        }
        let event_schema_version = b[1];
        if event_schema_version != EVENT_SCHEMA_VERSION {
            return Err(HeaderParseError::UnknownSchema {
                got: event_schema_version,
            });
        }
        let event_type = b[2];
        let event_subtype = b[3];
        let flags_byte = b[4];
        let header_len = u16::from_le_bytes([b[5], b[6]]);
        if header_len != HEADER_BODY_LEN as u16 {
            return Err(HeaderParseError::InvalidHeaderLen { got: header_len });
        }
        let reserved_len = u16::from_le_bytes([b[7], b[8]]);
        let total_len = u32::from_le_bytes([b[9], b[10], b[11], b[12]]);
        let payload_len = u32::from_le_bytes([b[13], b[14], b[15], b[16]]);
        // GOLD-COR-06 / A-80: frame-header length self-consistency. `total_len`
        // MUST equal preamble + header body + reserved + payload + CRC. Without
        // this, `total_len` was effectively unvalidated — `decode_frame` derived
        // payload boundaries from `payload_len` alone, so a corrupt/forged
        // `total_len` slipped through every consumer of `from_le_bytes`. u64
        // arithmetic avoids the u32 overflow a near-`u32::MAX` payload_len would
        // cause. (Computed bound, not attacker-influenced beyond the header.)
        let expected_total = PREAMBLE_LEN as u64
            + HEADER_BODY_LEN as u64
            + reserved_len as u64
            + payload_len as u64
            + CRC_LEN as u64;
        if total_len as u64 != expected_total {
            return Err(HeaderParseError::InconsistentTotalLen {
                total_len,
                payload_len,
                reserved_len,
                expected: expected_total,
            });
        }
        let generation = u32::from_le_bytes([b[17], b[18], b[19], b[20]]);
        let event_id_raw = u64::from_le_bytes(b[21..29].try_into().unwrap());
        let hlc_physical_ns = u64::from_le_bytes(b[29..37].try_into().unwrap());
        let hlc_logical = u32::from_le_bytes(b[37..41].try_into().unwrap());
        let importance_raw = f32::from_le_bytes(b[41..45].try_into().unwrap());
        let scope = WalScope::from_le_bytes(b[45..49].try_into().unwrap());
        let category = WalCategory::from_le_bytes(b[49..53].try_into().unwrap());
        let session_id_raw: [u8; 16] = b[53..69].try_into().unwrap();
        let node_id_raw: [u8; 16] = b[69..85].try_into().unwrap();
        let payload_hash = u64::from_le_bytes(b[85..93].try_into().unwrap());
        let reserved_arr: [u8; 3] = b[93..96].try_into().unwrap();

        if reserved_arr != [0u8; 3] {
            return Err(HeaderParseError::NonzeroReserved(reserved_arr));
        }
        if flags_byte & 0xE0 != 0 {
            return Err(HeaderParseError::InvalidFlagBits(flags_byte));
        }
        let flags = EventFlags::from_bits(flags_byte)
            .ok_or(HeaderParseError::InvalidFlagBits(flags_byte))?;

        Ok(EventHeaderV2 {
            wal_format_version,
            event_schema_version,
            event_type,
            event_subtype,
            flags,
            header_len,
            reserved_len,
            total_len,
            payload_len,
            generation,
            event_id: EventId(event_id_raw),
            hlc: Hlc::new(hlc_physical_ns, hlc_logical)?,
            importance: Importance::new(importance_raw)?,
            scope,
            category,
            session_id: SessionId(session_id_raw),
            node_id: NodeId(node_id_raw),
            payload_hash,
        })
    }

    /// Serialize to 96-byte little-endian array. Reserved bytes left as zero.
    pub fn to_le_bytes(&self) -> [u8; HEADER_BODY_LEN] {
        let mut b = [0u8; HEADER_BODY_LEN];
        b[0] = self.wal_format_version;
        b[1] = self.event_schema_version;
        b[2] = self.event_type;
        b[3] = self.event_subtype;
        b[4] = self.flags.bits();
        b[5..7].copy_from_slice(&self.header_len.to_le_bytes());
        b[7..9].copy_from_slice(&self.reserved_len.to_le_bytes());
        b[9..13].copy_from_slice(&self.total_len.to_le_bytes());
        b[13..17].copy_from_slice(&self.payload_len.to_le_bytes());
        b[17..21].copy_from_slice(&self.generation.to_le_bytes());
        b[21..29].copy_from_slice(&self.event_id.0.to_le_bytes());
        b[29..37].copy_from_slice(&self.hlc.physical_ns().to_le_bytes());
        b[37..41].copy_from_slice(&self.hlc.logical().to_le_bytes());
        b[41..45].copy_from_slice(&self.importance.raw().to_le_bytes());
        b[45..49].copy_from_slice(&self.scope.to_le_bytes());
        b[49..53].copy_from_slice(&self.category.to_le_bytes());
        b[53..69].copy_from_slice(&self.session_id.0);
        b[69..85].copy_from_slice(&self.node_id.0);
        b[85..93].copy_from_slice(&self.payload_hash.to_le_bytes());
        // b[93..96] left as [0, 0, 0]
        b
    }

    /// Constructor for the empty/minimal frame used in test vectors and as
    /// a default when callers fill specific fields afterwards.
    pub fn empty() -> Self {
        EventHeaderV2 {
            wal_format_version: WAL_FORMAT_VERSION,
            event_schema_version: EVENT_SCHEMA_VERSION,
            event_type: 0,
            event_subtype: 0,
            flags: EventFlags::empty(),
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + CRC_LEN) as u32,
            payload_len: 0,
            generation: 0,
            event_id: EventId::NONE,
            hlc: Hlc::EPOCH,
            importance: Importance::ZERO,
            scope: WalScope::UNSET,
            category: WalCategory::UNSET,
            session_id: SessionId::ZERO,
            node_id: NodeId::ZERO,
            payload_hash: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_header_roundtrip() {
        let h = EventHeaderV2::empty();
        let bytes = h.to_le_bytes();
        assert_eq!(bytes.len(), HEADER_BODY_LEN);
        let parsed = EventHeaderV2::from_le_bytes(&bytes).expect("parse");
        assert_eq!(h, parsed);
    }

    #[test]
    fn populated_header_roundtrip() {
        let h = EventHeaderV2 {
            wal_format_version: WAL_FORMAT_VERSION,
            event_schema_version: EVENT_SCHEMA_VERSION,
            event_type: 0x10,
            event_subtype: 0x02,
            flags: EventFlags::TOMBSTONE | EventFlags::SYNTHETIC,
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            // GOLD-COR-06: total_len must satisfy 4+96+reserved+payload+4.
            // For payload_len=1100, reserved=0 ⇒ 104+1100 = 1204.
            total_len: 1204,
            payload_len: 1100,
            generation: 7,
            event_id: EventId(0xDEADBEEFCAFEBABE),
            hlc: Hlc::new(1_700_000_000_000_000_000, 5).unwrap(),
            importance: Importance::new(0.42).unwrap(),
            scope: WalScope(99),
            category: WalCategory(1),
            session_id: SessionId([1u8; 16]),
            node_id: NodeId([2u8; 16]),
            payload_hash: 0x0102030405060708,
        };
        let bytes = h.to_le_bytes();
        let parsed = EventHeaderV2::from_le_bytes(&bytes).expect("parse");
        assert_eq!(h, parsed);
    }

    /// GOLD-PROG-19 — pin the EXACT little-endian byte offset of every field in
    /// the 96-byte EventHeaderV2 wire layout. The round-trip test above proves
    /// self-consistency, but a field REORDER would round-trip cleanly while
    /// silently shifting every external consumer's interpretation. These
    /// hardcoded offset asserts (independent of `to_le_bytes`'s own ranges) fail
    /// loudly the moment a field moves, changes width, or flips endianness.
    /// Offsets are SPEC_wire_header_v2_slim.md §3-§11 authoritative.
    #[test]
    fn wire_format_byte_offsets_pinned() {
        let event_id = 0xA1A2A3A4A5A6A7A8u64;
        let phys = 1_700_000_000_000_000_000u64;
        let logical = 5u32;
        let scope = WalScope(0xB1B2B3B4u32);
        let category = WalCategory(0xC1C2C3C4u32);
        let session = [0x51u8; 16];
        let node = [0x6Eu8; 16];
        let payload_hash = 0xD1D2D3D4D5D6D7D8u64;
        let total_len = 0xE1E2E3E4u32;
        let payload_len = 0xF1F2F3F4u32;
        let generation = 0x71727374u32;
        let reserved_len = 0x0203u16;

        let h = EventHeaderV2 {
            wal_format_version: WAL_FORMAT_VERSION,
            event_schema_version: EVENT_SCHEMA_VERSION,
            event_type: 0xAB,
            event_subtype: 0xCD,
            flags: EventFlags::TOMBSTONE,
            header_len: HEADER_BODY_LEN as u16,
            reserved_len,
            total_len,
            payload_len,
            generation,
            event_id: EventId(event_id),
            hlc: Hlc::new(phys, logical).unwrap(),
            importance: Importance::new(0.5).unwrap(),
            scope,
            category,
            session_id: SessionId(session),
            node_id: NodeId(node),
            payload_hash,
        };
        let b = h.to_le_bytes();

        assert_eq!(b.len(), HEADER_BODY_LEN);
        assert_eq!(b[0], WAL_FORMAT_VERSION, "byte 0: wal_format_version");
        assert_eq!(b[1], EVENT_SCHEMA_VERSION, "byte 1: event_schema_version");
        assert_eq!(b[2], 0xAB, "byte 2: event_type");
        assert_eq!(b[3], 0xCD, "byte 3: event_subtype");
        assert_eq!(b[4], h.flags.bits(), "byte 4: flags");
        assert_eq!(
            &b[5..7],
            &96u16.to_le_bytes(),
            "bytes 5..7: header_len = 96"
        );
        assert_eq!(
            &b[7..9],
            &reserved_len.to_le_bytes(),
            "bytes 7..9: reserved_len"
        );
        assert_eq!(
            &b[9..13],
            &total_len.to_le_bytes(),
            "bytes 9..13: total_len"
        );
        assert_eq!(
            &b[13..17],
            &payload_len.to_le_bytes(),
            "bytes 13..17: payload_len"
        );
        assert_eq!(
            &b[17..21],
            &generation.to_le_bytes(),
            "bytes 17..21: generation"
        );
        assert_eq!(
            &b[21..29],
            &event_id.to_le_bytes(),
            "bytes 21..29: event_id"
        );
        assert_eq!(
            &b[29..37],
            &phys.to_le_bytes(),
            "bytes 29..37: hlc.physical_ns"
        );
        assert_eq!(
            &b[37..41],
            &logical.to_le_bytes(),
            "bytes 37..41: hlc.logical"
        );
        assert_eq!(
            &b[41..45],
            &h.importance.raw().to_le_bytes(),
            "bytes 41..45: importance f32"
        );
        assert_eq!(&b[45..49], &scope.to_le_bytes(), "bytes 45..49: scope");
        assert_eq!(
            &b[49..53],
            &category.to_le_bytes(),
            "bytes 49..53: category"
        );
        assert_eq!(&b[53..69], &session, "bytes 53..69: session_id");
        assert_eq!(&b[69..85], &node, "bytes 69..85: node_id");
        assert_eq!(
            &b[85..93],
            &payload_hash.to_le_bytes(),
            "bytes 85..93: payload_hash"
        );
        assert_eq!(&b[93..96], &[0u8, 0, 0], "bytes 93..96: reserved = zero");
    }

    #[test]
    fn parser_rejects_inconsistent_total_len() {
        // GOLD-COR-06 / A-80: a header whose total_len does not match
        // 4+96+reserved+payload+4 must be rejected at parse time — before this
        // check, total_len was effectively unvalidated.
        let mut h = EventHeaderV2::empty();
        h.payload_len = 100;
        h.total_len = 104 + 100; // consistent: parses fine.
        let bytes = h.to_le_bytes();
        EventHeaderV2::from_le_bytes(&bytes).expect("consistent total_len must parse");

        // Now corrupt total_len directly in the wire bytes (offset 9..13).
        let mut corrupt = bytes;
        corrupt[9..13].copy_from_slice(&9999u32.to_le_bytes());
        let r = EventHeaderV2::from_le_bytes(&corrupt);
        assert!(
            matches!(
                r,
                Err(HeaderParseError::InconsistentTotalLen {
                    total_len: 9999,
                    payload_len: 100,
                    reserved_len: 0,
                    expected: 204,
                })
            ),
            "expected InconsistentTotalLen, got {r:?}"
        );
    }

    #[test]
    fn parser_rejects_wrong_wal_format() {
        let mut bytes = EventHeaderV2::empty().to_le_bytes();
        bytes[0] = 0x99;
        let r = EventHeaderV2::from_le_bytes(&bytes);
        assert!(matches!(
            r,
            Err(HeaderParseError::UnknownWalFormat { got: 0x99 })
        ));
    }

    #[test]
    fn parser_rejects_wrong_schema() {
        let mut bytes = EventHeaderV2::empty().to_le_bytes();
        bytes[1] = 0x03;
        let r = EventHeaderV2::from_le_bytes(&bytes);
        assert!(matches!(
            r,
            Err(HeaderParseError::UnknownSchema { got: 0x03 })
        ));
    }

    #[test]
    fn parser_rejects_nonzero_reserved() {
        let mut bytes = EventHeaderV2::empty().to_le_bytes();
        bytes[93] = 0x01;
        let r = EventHeaderV2::from_le_bytes(&bytes);
        assert!(matches!(r, Err(HeaderParseError::NonzeroReserved(_))));
    }

    #[test]
    fn parser_rejects_reserved_flag_bits() {
        let mut bytes = EventHeaderV2::empty().to_le_bytes();
        bytes[4] = 0x80;
        let r = EventHeaderV2::from_le_bytes(&bytes);
        assert!(matches!(r, Err(HeaderParseError::InvalidFlagBits(0x80))));
    }

    #[test]
    fn alignment_safe_on_misaligned_input() {
        // Verify byte-by-byte access does not SIGBUS on misaligned input
        // (this matters on aarch64; on x86 alignment is permissive).
        let h = EventHeaderV2::empty();
        let bytes = h.to_le_bytes();
        let mut buf = [0u8; 200];
        let offset = 3; // misaligned
        buf[offset..offset + HEADER_BODY_LEN].copy_from_slice(&bytes);
        let slice: &[u8; HEADER_BODY_LEN] =
            buf[offset..offset + HEADER_BODY_LEN].try_into().unwrap();
        let parsed = EventHeaderV2::from_le_bytes(slice).expect("parse misaligned");
        assert_eq!(h, parsed);
    }
}
