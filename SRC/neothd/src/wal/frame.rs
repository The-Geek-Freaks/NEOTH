// Frame encoder/decoder -- SPEC_wire_header_v2_slim.md §4, §12.
// Frame layout:
//   [0..4)              magic preamble b"NEOT"
//   [4..100)            96-byte header body
//   [100..100+R)        reserved padding (R = reserved_len; v1.1 always 0)
//   [100+R..100+R+P)    payload (P = payload_len)
//   [100+R+P..+4)       CRC32c (little-endian, covers frame[0..total_len-4])
//
// total_len = 4 + 96 + R + P + 4 = P + 104 (for v1.1 R=0).

use super::error::HeaderParseError;
use super::header::{CRC_LEN, EventHeaderV2, HEADER_BODY_LEN, MAGIC, PREAMBLE_LEN};

pub fn encode_frame(header: &EventHeaderV2, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len();
    let reserved_len = header.reserved_len as usize;
    let total_len = PREAMBLE_LEN + HEADER_BODY_LEN + reserved_len + payload_len + CRC_LEN;

    // F-24: encode-time invariant — the header MUST describe the same
    // frame length we are about to emit. `HeaderBuilder::build` always
    // computes this correctly; a mismatch here means a caller stamped
    // `EventHeaderV2 { total_len: …, … }` by hand with a wrong value,
    // which would silently produce frames the decoder rejects as
    // size-mismatched (and worse, could let the writer commit a frame
    // whose self-declared length disagrees with the segment layout).
    // Hard assert rather than debug_assert: cheap to check + catches
    // corruption in release builds.
    assert_eq!(
        header.total_len as usize, total_len,
        "encode_frame: header.total_len ({}) disagrees with actual frame length ({}). \
         Did the caller bypass HeaderBuilder?",
        header.total_len, total_len,
    );
    assert_eq!(
        header.payload_len as usize, payload_len,
        "encode_frame: header.payload_len ({}) disagrees with actual payload length ({})",
        header.payload_len, payload_len,
    );

    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&header.to_le_bytes());
    frame.resize(frame.len() + reserved_len, 0u8);
    frame.extend_from_slice(payload);

    let crc = crc32c::crc32c(&frame);
    frame.extend_from_slice(&crc.to_le_bytes());
    debug_assert_eq!(frame.len(), total_len);
    frame
}

pub struct DecodedFrame<'a> {
    pub header: EventHeaderV2,
    pub payload: &'a [u8],
}

pub fn decode_frame(frame: &[u8]) -> Result<DecodedFrame<'_>, HeaderParseError> {
    let need = PREAMBLE_LEN + HEADER_BODY_LEN + CRC_LEN;
    if frame.len() < need {
        return Err(HeaderParseError::BufferTooShort {
            got: frame.len(),
            need,
        });
    }
    let magic_arr: [u8; 4] = frame[0..4].try_into().unwrap();
    if magic_arr != MAGIC {
        return Err(HeaderParseError::InvalidMagic { got: magic_arr });
    }
    let header_bytes: &[u8; HEADER_BODY_LEN] =
        frame[4..4 + HEADER_BODY_LEN]
            .try_into()
            .map_err(|_| HeaderParseError::BufferTooShort {
                got: frame.len(),
                need,
            })?;
    let header = EventHeaderV2::from_le_bytes(header_bytes)?;

    let reserved_len = header.reserved_len as usize;
    let payload_len = header.payload_len as usize;
    let expected_total = PREAMBLE_LEN + HEADER_BODY_LEN + reserved_len + payload_len + CRC_LEN;
    if frame.len() < expected_total {
        return Err(HeaderParseError::BufferTooShort {
            got: frame.len(),
            need: expected_total,
        });
    }

    let payload_start = PREAMBLE_LEN + HEADER_BODY_LEN + reserved_len;
    let payload_end = payload_start + payload_len;
    let crc_offset = payload_end;

    let crc_bytes: [u8; 4] = frame[crc_offset..crc_offset + CRC_LEN].try_into().unwrap();
    let crc_got = u32::from_le_bytes(crc_bytes);
    let crc_computed = crc32c::crc32c(&frame[..crc_offset]);
    if crc_got != crc_computed {
        return Err(HeaderParseError::CrcMismatch {
            expected: crc_computed,
            got: crc_got,
        });
    }

    Ok(DecodedFrame {
        header,
        payload: &frame[payload_start..payload_end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::hlc::Hlc;
    use crate::wal::types::{EventFlags, EventId, Importance, NodeId, SessionId};

    fn populated_header(payload_len: u32) -> EventHeaderV2 {
        EventHeaderV2 {
            wal_format_version: EventHeaderV2::WAL_FORMAT_VERSION,
            event_schema_version: EventHeaderV2::EVENT_SCHEMA_VERSION,
            event_type: 0x01,
            event_subtype: 0x00,
            flags: EventFlags::empty(),
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + payload_len as usize + CRC_LEN) as u32,
            payload_len,
            generation: 1,
            event_id: EventId(42),
            hlc: Hlc::new(1_700_000_000_000_000_000, 0).unwrap(),
            importance: Importance::new(0.5).unwrap(),
            scope: 0,
            category: 0,
            session_id: SessionId([0u8; 16]),
            node_id: NodeId([0u8; 16]),
            payload_hash: 0,
        }
    }

    #[test]
    fn frame_roundtrip_empty_payload() {
        let h = populated_header(0);
        let frame = encode_frame(&h, b"");
        assert_eq!(frame.len(), 104);
        let dec = decode_frame(&frame).expect("decode");
        assert_eq!(dec.header, h);
        assert_eq!(dec.payload, b"");
    }

    #[test]
    fn frame_roundtrip_with_payload() {
        let payload = b"hello-neoth-wal";
        let h = populated_header(payload.len() as u32);
        let frame = encode_frame(&h, payload);
        let dec = decode_frame(&frame).expect("decode");
        assert_eq!(dec.payload, payload);
        assert_eq!(dec.header.payload_len as usize, payload.len());
    }

    #[test]
    fn frame_rejects_bad_magic() {
        let h = populated_header(0);
        let mut frame = encode_frame(&h, b"");
        frame[0] = b'X';
        let r = decode_frame(&frame);
        assert!(matches!(r, Err(HeaderParseError::InvalidMagic { .. })));
    }

    #[test]
    fn frame_rejects_crc_corruption() {
        let h = populated_header(4);
        let mut frame = encode_frame(&h, b"abcd");
        let len = frame.len();
        frame[len - 4] ^= 0x01;
        let r = decode_frame(&frame);
        assert!(matches!(r, Err(HeaderParseError::CrcMismatch { .. })));
    }

    /// F-24: a hand-constructed header with `total_len` disagreeing
    /// from the actual frame length must panic in `encode_frame`
    /// rather than silently producing a frame the decoder rejects.
    #[test]
    #[should_panic(expected = "total_len")]
    fn encode_panics_on_total_len_mismatch() {
        let mut h = populated_header(0);
        // Lie about total_len — pretend we have a 4-byte payload that
        // we are not actually going to write.
        h.total_len += 4;
        let _ = encode_frame(&h, b"");
    }

    /// F-24: the same invariant for `payload_len` — catches the
    /// "I forgot to update payload_len after stringifying" class of bug.
    #[test]
    #[should_panic(expected = "payload_len")]
    fn encode_panics_on_payload_len_mismatch() {
        let mut h = populated_header(8);
        // Header says 8 bytes of payload; we pass 4 actual bytes.
        // total_len would also be wrong, so adjust it back to keep the
        // payload_len assert firing first.
        h.total_len = (PREAMBLE_LEN + HEADER_BODY_LEN + 4 + CRC_LEN) as u32;
        let _ = encode_frame(&h, b"abcd");
    }

    /// F-24: when the header values match reality, encode succeeds
    /// (sanity check that the asserts are not over-eager).
    #[test]
    fn encode_succeeds_when_header_and_payload_agree() {
        let payload = b"hello world";
        let h = populated_header(payload.len() as u32);
        let frame = encode_frame(&h, payload);
        let dec = decode_frame(&frame).expect("decode round-trips");
        assert_eq!(dec.payload, payload);
    }
}
