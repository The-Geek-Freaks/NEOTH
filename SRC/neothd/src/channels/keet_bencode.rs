//! R-2 Phase 3 — minimal bencode codec for Hyperswarm DHT packets.
//!
//! Hyperswarm (and the underlying mainline DHT) frames packets as
//! bencode. This module ships the subset needed to encode
//! `AnnouncePacket` / `LookupPacket` + decode `LookupResponse` —
//! integers, byte-strings, lists, dicts (sorted-key on encode).
//!
//! Hand-rolled instead of pulling `bendy` as a dep — the surface is
//! ~150 lines + the wire shape is locked-in for two decades. Spec
//! reference: [BEP-3](https://www.bittorrent.org/beps/bep_0003.html).
//!
//! v0.1 ships the codec only. The Phase 3 follow-up swaps
//! `keet_udp::encode_lookup_payload` from the JSON placeholder to
//! `encode(BencodeValue::from_packet(&packet))` so the dialer
//! actually speaks the protocol Hyperswarm bootstrap nodes
//! understand.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

/// One bencode value. Tree-recursive — every node is one of four
/// kinds matching the BEP-3 wire shape exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BencodeValue {
    /// `i<digits>e` — signed 64-bit integer.
    Integer(i64),
    /// `<len>:<raw bytes>` — opaque byte string. Hyperswarm
    /// announce/lookup payloads use this for keys + node ids.
    Bytes(Vec<u8>),
    /// `l<items>e` — ordered list.
    List(Vec<BencodeValue>),
    /// `d<sorted key/value pairs>e` — BEP-3 mandates byte-sorted
    /// keys. `BTreeMap` preserves the sort invariant for us on
    /// every insert.
    Dict(BTreeMap<Vec<u8>, BencodeValue>),
}

impl BencodeValue {
    /// Convenience — wrap a UTF-8 string as `Bytes`. Bencode is
    /// binary-safe; the cast is one-way (caller decoding back gets
    /// `Bytes` and must `from_utf8` if they expected text).
    pub fn from_str(s: &str) -> Self {
        BencodeValue::Bytes(s.as_bytes().to_vec())
    }
}

/// Encode a bencode value to its on-wire bytes. Recursive +
/// allocation-friendly — Hyperswarm packets are <1 KB so this is
/// cheap. Dict keys are emitted in BTreeMap iteration order, which
/// matches BEP-3 byte-sort.
pub fn encode(value: &BencodeValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &BencodeValue, out: &mut Vec<u8>) {
    match value {
        BencodeValue::Integer(n) => {
            out.push(b'i');
            out.extend_from_slice(n.to_string().as_bytes());
            out.push(b'e');
        }
        BencodeValue::Bytes(bytes) => {
            out.extend_from_slice(bytes.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(bytes);
        }
        BencodeValue::List(items) => {
            out.push(b'l');
            for item in items {
                encode_into(item, out);
            }
            out.push(b'e');
        }
        BencodeValue::Dict(map) => {
            out.push(b'd');
            for (k, v) in map {
                // Key is always a byte-string in bencode.
                out.extend_from_slice(k.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(k);
                encode_into(v, out);
            }
            out.push(b'e');
        }
    }
}

/// Decode bencode bytes back into a value tree. Returns the parsed
/// value + the index just past the last consumed byte (so callers
/// can validate trailing input is empty, or chain decoders).
pub fn decode(input: &[u8]) -> Result<BencodeValue> {
    let (value, consumed) = decode_at(input, 0)?;
    if consumed != input.len() {
        bail!(
            "bencode: {} trailing bytes after value end (input {} consumed {})",
            input.len() - consumed,
            input.len(),
            consumed
        );
    }
    Ok(value)
}

fn decode_at(input: &[u8], at: usize) -> Result<(BencodeValue, usize)> {
    if at >= input.len() {
        bail!("bencode: unexpected EOF at offset {at}");
    }
    match input[at] {
        b'i' => decode_int(input, at + 1),
        b'l' => decode_list(input, at + 1),
        b'd' => decode_dict(input, at + 1),
        c if c.is_ascii_digit() => decode_bytes(input, at),
        c => bail!("bencode: unknown type byte 0x{c:02x} at offset {at}"),
    }
}

fn decode_int(input: &[u8], at: usize) -> Result<(BencodeValue, usize)> {
    let end = find_byte(input, at, b'e')
        .ok_or_else(|| anyhow::anyhow!("bencode: integer missing 'e' terminator at {at}"))?;
    let digits = &input[at..end];
    let s = std::str::from_utf8(digits)
        .with_context(|| format!("bencode: integer body not utf-8 at {at}"))?;
    if s.is_empty() {
        bail!("bencode: empty integer at {at}");
    }
    // BEP-3 forbids leading zeros (except for the literal "0") and "-0".
    if s == "-0" {
        bail!("bencode: -0 is not a valid integer at {at}");
    }
    let unsigned = s.strip_prefix('-').unwrap_or(s);
    if unsigned.len() > 1 && unsigned.starts_with('0') {
        bail!("bencode: leading zero in integer `{s}` at {at}");
    }
    let n: i64 = s
        .parse()
        .with_context(|| format!("bencode: parse integer `{s}` at {at}"))?;
    Ok((BencodeValue::Integer(n), end + 1))
}

fn decode_bytes(input: &[u8], at: usize) -> Result<(BencodeValue, usize)> {
    let colon = find_byte(input, at, b':')
        .ok_or_else(|| anyhow::anyhow!("bencode: byte-string missing ':' at {at}"))?;
    let len_str = std::str::from_utf8(&input[at..colon])
        .with_context(|| format!("bencode: length prefix not utf-8 at {at}"))?;
    let len: usize = len_str
        .parse()
        .with_context(|| format!("bencode: parse length `{len_str}` at {at}"))?;
    let start = colon + 1;
    let end = start + len;
    if end > input.len() {
        bail!(
            "bencode: byte-string of len {len} runs past EOF (start {start}, input {})",
            input.len()
        );
    }
    Ok((BencodeValue::Bytes(input[start..end].to_vec()), end))
}

fn decode_list(input: &[u8], mut at: usize) -> Result<(BencodeValue, usize)> {
    let mut items = Vec::new();
    while at < input.len() && input[at] != b'e' {
        let (val, next) = decode_at(input, at)?;
        items.push(val);
        at = next;
    }
    if at >= input.len() {
        bail!("bencode: list missing 'e' terminator");
    }
    Ok((BencodeValue::List(items), at + 1))
}

fn decode_dict(input: &[u8], mut at: usize) -> Result<(BencodeValue, usize)> {
    let mut map = BTreeMap::new();
    let mut last_key: Option<Vec<u8>> = None;
    while at < input.len() && input[at] != b'e' {
        let (key_val, after_key) = decode_at(input, at)?;
        let key = match key_val {
            BencodeValue::Bytes(b) => b,
            other => bail!("bencode: dict key must be byte-string, got {other:?}"),
        };
        // BEP-3 requires strict byte-sort. Enforce — silently
        // accepting unsorted keys would mask a malformed packet
        // (or worse, a duplicated key).
        if let Some(prev) = &last_key {
            if &key <= prev {
                bail!(
                    "bencode: dict keys must be strictly byte-sorted; \
                     {:?} not after {:?}",
                    key,
                    prev
                );
            }
        }
        let (value, after_val) = decode_at(input, after_key)?;
        last_key = Some(key.clone());
        map.insert(key, value);
        at = after_val;
    }
    if at >= input.len() {
        bail!("bencode: dict missing 'e' terminator");
    }
    Ok((BencodeValue::Dict(map), at + 1))
}

fn find_byte(input: &[u8], from: usize, b: u8) -> Option<usize> {
    input
        .iter()
        .skip(from)
        .position(|x| *x == b)
        .map(|p| p + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict_of(pairs: &[(&str, BencodeValue)]) -> BencodeValue {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert(k.as_bytes().to_vec(), v.clone());
        }
        BencodeValue::Dict(m)
    }

    // ── Encode shape pins ────────────────────────────────────────────

    #[test]
    fn encode_zero_integer() {
        assert_eq!(encode(&BencodeValue::Integer(0)), b"i0e");
    }

    #[test]
    fn encode_positive_integer() {
        assert_eq!(encode(&BencodeValue::Integer(42)), b"i42e");
    }

    #[test]
    fn encode_negative_integer() {
        assert_eq!(encode(&BencodeValue::Integer(-7)), b"i-7e");
    }

    #[test]
    fn encode_empty_bytes() {
        assert_eq!(encode(&BencodeValue::Bytes(vec![])), b"0:");
    }

    #[test]
    fn encode_short_byte_string() {
        assert_eq!(encode(&BencodeValue::from_str("spam")), b"4:spam");
    }

    #[test]
    fn encode_binary_bytes() {
        // Bencode is binary-safe — non-utf8 must round-trip.
        let v = BencodeValue::Bytes(vec![0x00, 0xff, 0x42]);
        let enc = encode(&v);
        assert_eq!(enc, b"3:\x00\xff\x42");
    }

    #[test]
    fn encode_empty_list() {
        assert_eq!(encode(&BencodeValue::List(vec![])), b"le");
    }

    #[test]
    fn encode_mixed_list_matches_bep3_example() {
        let v = BencodeValue::List(vec![
            BencodeValue::from_str("spam"),
            BencodeValue::Integer(42),
        ]);
        assert_eq!(encode(&v), b"l4:spami42ee");
    }

    #[test]
    fn encode_empty_dict() {
        assert_eq!(encode(&BencodeValue::Dict(BTreeMap::new())), b"de");
    }

    #[test]
    fn encode_dict_sorts_keys_byte_order() {
        // BTreeMap byte-sorts on insert; encoder must emit "bar"
        // before "foo" even though we inserted in reverse order.
        let v = dict_of(&[
            ("foo", BencodeValue::Integer(42)),
            ("bar", BencodeValue::from_str("spam")),
        ]);
        assert_eq!(encode(&v), b"d3:bar4:spam3:fooi42ee");
    }

    // ── Decode shape pins ────────────────────────────────────────────

    #[test]
    fn decode_integer_round_trip() {
        for n in [0_i64, 1, -1, 42, -7, i64::MAX, i64::MIN] {
            let v = BencodeValue::Integer(n);
            assert_eq!(decode(&encode(&v)).unwrap(), v);
        }
    }

    #[test]
    fn decode_byte_string_round_trip() {
        for bytes in [
            vec![],
            b"spam".to_vec(),
            vec![0x00, 0xff, 0x42, 0x13],
            vec![0u8; 256], // 3-digit length prefix
        ] {
            let v = BencodeValue::Bytes(bytes);
            assert_eq!(decode(&encode(&v)).unwrap(), v);
        }
    }

    #[test]
    fn decode_list_round_trip() {
        let v = BencodeValue::List(vec![
            BencodeValue::from_str("spam"),
            BencodeValue::Integer(42),
            BencodeValue::List(vec![BencodeValue::Integer(1)]),
        ]);
        assert_eq!(decode(&encode(&v)).unwrap(), v);
    }

    #[test]
    fn decode_dict_round_trip() {
        let v = dict_of(&[
            ("a", BencodeValue::Integer(1)),
            ("b", BencodeValue::from_str("two")),
            ("c", BencodeValue::List(vec![BencodeValue::Integer(3)])),
        ]);
        assert_eq!(decode(&encode(&v)).unwrap(), v);
    }

    #[test]
    fn decode_nested_dict_round_trip() {
        // Hyperswarm announce shape: outer dict with nested list
        // of node entries + nested dict of options.
        let v = dict_of(&[
            (
                "nodes",
                BencodeValue::List(vec![
                    BencodeValue::from_str("n1"),
                    BencodeValue::from_str("n2"),
                ]),
            ),
            (
                "opts",
                dict_of(&[
                    ("port", BencodeValue::Integer(49737)),
                    ("v", BencodeValue::Integer(1)),
                ]),
            ),
        ]);
        let enc = encode(&v);
        assert_eq!(decode(&enc).unwrap(), v);
    }

    // ── Error paths ──────────────────────────────────────────────────

    #[test]
    fn decode_rejects_unknown_type_byte() {
        assert!(decode(b"x").is_err());
    }

    #[test]
    fn decode_rejects_integer_missing_terminator() {
        assert!(decode(b"i42").is_err());
    }

    #[test]
    fn decode_rejects_empty_integer() {
        assert!(decode(b"ie").is_err());
    }

    #[test]
    fn decode_rejects_minus_zero_integer() {
        assert!(decode(b"i-0e").is_err());
    }

    #[test]
    fn decode_rejects_leading_zero_integer() {
        assert!(decode(b"i07e").is_err());
        assert!(decode(b"i-07e").is_err());
    }

    #[test]
    fn decode_accepts_single_zero_integer() {
        assert_eq!(decode(b"i0e").unwrap(), BencodeValue::Integer(0));
    }

    #[test]
    fn decode_rejects_byte_string_past_eof() {
        // length 9, only 4 bytes follow
        assert!(decode(b"9:spam").is_err());
    }

    #[test]
    fn decode_rejects_byte_string_missing_colon() {
        assert!(decode(b"4spam").is_err());
    }

    #[test]
    fn decode_rejects_list_missing_terminator() {
        assert!(decode(b"l4:spam").is_err());
    }

    #[test]
    fn decode_rejects_dict_missing_terminator() {
        assert!(decode(b"d3:foo4:bar1").is_err());
    }

    #[test]
    fn decode_rejects_dict_with_unsorted_keys() {
        // "foo" before "bar" — BEP-3 violation. Must error.
        let bad = b"d3:fooi1e3:bari2ee";
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_rejects_dict_with_duplicate_keys() {
        // Same key twice — fails the strict-sort check.
        let bad = b"d3:fooi1e3:fooi2ee";
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_rejects_dict_with_non_bytes_key() {
        // Bencode dicts MUST have byte-string keys. Integer key →
        // reject. Encoder always uses BTreeMap<Vec<u8>, _> so we
        // can only hit this path on malicious incoming bytes.
        let bad = b"di1ei2ee";
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // Valid integer followed by stray bytes.
        assert!(decode(b"i42ex").is_err());
    }

    // ── Hyperswarm-shape round trips ─────────────────────────────────

    #[test]
    fn hyperswarm_announce_dict_round_trip() {
        // Subset of the real announce shape: discovery_key (20-byte
        // SHA-1-style), port (u16), node-id (32-byte ed25519 pub).
        let announce = dict_of(&[
            ("discovery_key", BencodeValue::Bytes(vec![0xab; 20])),
            ("port", BencodeValue::Integer(49_737)),
            ("pub_key", BencodeValue::Bytes(vec![0xde; 32])),
        ]);
        let enc = encode(&announce);
        // First two bytes must be `d3` — first key after sort is "discovery_key".
        assert_eq!(&enc[..2], b"d1"); // length-prefix of "discovery_key" = 13 → starts with 1
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, announce);
    }

    #[test]
    fn round_trip_with_large_byte_string() {
        // 4 KB payload — exercises the multi-digit length prefix.
        let bytes = vec![0x55u8; 4096];
        let v = BencodeValue::Bytes(bytes);
        assert_eq!(decode(&encode(&v)).unwrap(), v);
    }
}
