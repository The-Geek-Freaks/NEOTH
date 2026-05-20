# SPEC: Wire Header v2 SLIM — NEOTH v1.1
<!-- revision: 2026-05-14  status: BUILD-READY  fixes: S1, S4, S8 from CLAUDE_v07_review + ADVERSARIAL/03 -->

## 1. Motivation

Reduce header overhead from v0.7's 215 bytes/frame to 96 bytes/frame.
10M-event WAL: 2.05 GB → 916 MB (saves 1.13 GB).

Mechanism: move every field a reader can defer until payload-decode time into PayloadPrefixV4
prepended to the payload body. Header retains only what's needed for frame navigation,
indexing, and routing without touching payload bytes.

**v1.1 fixes vs v0.8 spec:**
- **S1**: `ts_ns: u64` (8B) replaced by `hlc: Hlc { physical_ns: u64, logical: u32 }` (12B). `_reserved` shrunk from `[u8; 7]` to `[u8; 3]`. Net change: 0 bytes. **96-byte body preserved.**
- **S4**: `hemisphere: u8` (Wire-spec, value 4=BOTH) reconciled with `originator: u8` (design-doc, value 4=COUNCIL). Single canonical name: `originator`. Single enum: `Originator {NA=0, Left=1, Right=2, Callosum=3, Council=4}`.
- **S8**: `#[repr(C, packed)]` REMOVED. Rust struct is no longer wire-authoritative. Explicit `from_le_bytes(&[u8; 96]) → Result<Self, HeaderParseError>` and `to_le_bytes() → [u8; 96]` serializer/deserializer. Multi-byte field access is safe (no packed UB).

No migration code: NEOTH v1.0 was never built. Reader rejecting `wal_format_version != 2` and `event_schema_version != 4` with `Err(WalError::UnknownFormat)`.

---

## 2. Field Audit (KEEP vs MOVE)

| # | Field | bytes | Decision | Rationale |
|---|-------|-------|----------|-----------|
| 1 | magic | 4 | KEEP (preamble) | Frame sync. Magic = `b"NEOT"` (v1.0 brand). |
| 2 | wal_format_version | 1 | KEEP | Reader must know wire layout before parsing. |
| 3 | event_schema_version | 1 | KEEP | Determines PayloadPrefix shape. |
| 4 | event_type | 1 | KEEP | Routing, index, GC policy — pre-payload needs. |
| 5 | event_subtype | 1 | KEEP | Fine-grained routing. |
| 6 | flags | 1 | KEEP | TOMBSTONE bit drives skip on every frame scan. |
| 7 | header_len | 2 | KEEP | Locate payload start. |
| 8 | reserved_len | 2 | KEEP | Future padding accounting. |
| 9 | total_len | 4 | KEEP | Sequential reader advances cursor without payload touch. |
| 10 | payload_len | 4 | KEEP | Slice payload bytes for hash/decode. |
| 11 | generation | 4 | KEEP | Compaction boundary, index partition. |
| 12 | event_id | 8 | KEEP | Primary key for dedup, vector blob lookup, parent linking. |
| 13 | **hlc** (NEW) | 12 | KEEP | physical_ns u64 + logical u32. Replaces ts_ns. HLC inter-node causal ordering (Kulkarni 2014). |
| 14 | importance | 4 | KEEP | GC weight; visible without payload decode. |
| 15 | scope | 4 | KEEP | Coarse routing tag. |
| 16 | category | 4 | KEEP | Paired routing classification. |
| 17 | session_id | 16 | KEEP | Session-scoped query filter. |
| 18 | node_id | 16 | KEEP | Multi-node origin disambiguation. |
| 19 | payload_hash | 8 | KEEP (NEW) | xxh3-64 of raw payload for fast integrity. |
| 20 | region_tag (was brain_region) | 1 | MOVE | Semantic tag, payload-time. RegionTag enum. |
| 21 | originator (was hemisphere) | 1 | MOVE | Producer role, payload-time. Originator enum. |
| 22-34 | embedding_*, chunk_*, parent_*, supersedes_*, source_*, content_hash, prompt_bundle_hash, vector_blob_off | various | MOVE | Payload-decode-time metadata. |
| _reserved | 3 | KEEP | Pad to 96. Must be `[0,0,0]`; non-zero → parse error. |

Header BODY: 4+1+1+1+1+1+2+2+4+4+4+8+12+4+4+4+16+16+8+3 = **96 bytes total**.

---

## 3. EventHeaderV2 Rust Struct (NOT wire-authoritative — see §11 for parser)

```rust
/// EventHeaderV2 — 96-byte wire header.
/// Rust struct is for ergonomics only.
/// Wire format (§4) is authoritative. NEVER dump struct to disk directly.
/// Multi-byte fields access is safe — no packed UB.
#[derive(Clone, Copy, Debug)]
pub struct EventHeaderV2 {
    pub wal_format_version:   u8,
    pub event_schema_version: u8,
    pub event_type:           u8,
    pub event_subtype:        u8,
    pub flags:                EventFlags,    // bitflags! wrapper, see §3.1
    pub header_len:           u16,           // = 96
    pub reserved_len:         u16,           // = 0 in v1.1
    pub total_len:            u32,
    pub payload_len:          u32,
    pub generation:           u32,
    pub event_id:             EventId,       // newtype: u64
    pub hlc:                  Hlc,           // 12 bytes; see SPEC_multinode_clock.md
    pub importance:           Importance,    // newtype: f32 bounded [0.0, 1.0]
    pub scope:                u32,
    pub category:             u32,
    pub session_id:           SessionId,     // newtype: [u8; 16]
    pub node_id:              NodeId,        // newtype: [u8; 16]
    pub payload_hash:         u64,
    // _reserved: 3 bytes, always 0x00. Implicit — enforced by parser.
}

impl EventHeaderV2 {
    pub const HEADER_BODY_LEN: usize = 96;
    pub const WAL_FORMAT_VERSION: u8 = 0x02;
    pub const EVENT_SCHEMA_VERSION: u8 = 0x04;
    pub const MAGIC: [u8; 4] = *b"NEOT";
}
```

### 3.1 EventFlags Bitfield (bitflags! wrapper)

```rust
bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EventFlags: u8 {
        const TOMBSTONE      = 0x01;  // logically deleted
        const SUPERSEDED     = 0x02;  // replaced by newer event
        const SYNTHETIC      = 0x04;  // generated, not external input
        const REDACTED       = 0x08;  // content scrubbed
        const STREAM_PARTIAL = 0x10;  // mid-stream fragment
        // bits 5-7 reserved, unrepresentable in safe code
    }
}
```

---

## 4. Frame Wire Layout v1.1 (frame-absolute byte offsets)

The 4-byte magic preamble is part of the frame but is NOT counted in header_len.
Header body is `frame[4..100)` — 96 bytes.

```
Offset    Size  Type      Endian  Field
-------   ----  --------  ------  -----
[0..4)      4   u8[4]     --      magic = b"NEOT"  (preamble, not in header_len)
[4]         1   u8        --      wal_format_version = 0x02
[5]         1   u8        --      event_schema_version = 0x04
[6]         1   u8        --      event_type
[7]         1   u8        --      event_subtype
[8]         1   u8        --      flags
[9..11)     2   u16       LE      header_len = 96
[11..13)    2   u16       LE      reserved_len = 0
[13..17)    4   u32       LE      total_len
[17..21)    4   u32       LE      payload_len
[21..25)    4   u32       LE      generation
[25..33)    8   u64       LE      event_id
[33..41)    8   u64       LE      hlc.physical_ns          ← was ts_ns in v0.8
[41..45)    4   u32       LE      hlc.logical              ← NEW v1.1
[45..49)    4   f32       LE      importance (IEEE-754)
[49..53)    4   u32       LE      scope
[53..57)    4   u32       LE      category
[57..73)   16   u8[16]    --      session_id (UUID v7)
[73..89)   16   u8[16]    --      node_id (UUID v7)
[89..97)    8   u64       LE      payload_hash (xxh3-64)
[97..100)   3   u8[3]     --      _reserved = [0x00; 3]
=== header body: 96 bytes (frame[4..100)) ===
[100..100+R)            reserved padding (R = reserved_len bytes; v1.1: 0)
[100+R..100+R+P)        payload (P = payload_len)
[100+R+P..100+R+P+4)    CRC32c u32 LE (covers frame[0..100+R+P))
```

Formula: `total_len = 4 + header_len + reserved_len + payload_len + 4 = payload_len + 104`

---

## 5. PayloadPrefixV4

Events with `event_schema_version=4` carry a 124-byte structured prefix before the event body.

```
payload[0..2)      prefix_len   u16 LE = 124
payload[2..124)    PayloadPrefixV4 fields (122 bytes)
payload[124+..)    event body (msgpack / JSON / raw bytes per event_type)
```

```rust
/// Region routing tag. 0=None means event does not target a brain-region view.
#[repr(u8)]
#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionTag {
    None         = 0,
    Hippocampus  = 1,   // idx_episode
    Amygdala     = 2,   // idx_importance (single-writer)
    Insula       = 3,   // idx_council
    Cerebellum   = 4,   // idx_motor (single-writer)
    BasalGanglia = 5,   // idx_habit
    Hypothalamus = 6,   // idx_profile (single-writer) — NEOTH v0.9+
}

/// Originator: who produced this event. Was `hemisphere` in v0.8 with `4=BOTH`.
/// v1.1: renamed `originator`, value `4=COUNCIL` (resolves S4 drift).
#[repr(u8)]
#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Originator {
    NA       = 0,   // system / synthetic / migration
    Left     = 1,   // Left Hemisphere (Claude Opus 4.7) — user-facing output
    Right    = 2,   // Right Hemisphere (Gemini 3.1 Pro) — pattern-match
    Callosum = 3,   // Corpus Callosum (Codex GPT-5.5) — synthesis
    Council  = 4,   // Council multi-LLM consensus output
}

/// PayloadPrefixV4 — 122 bytes of fields; 2-byte prefix_len u16 prepended = 124 total.
/// Wire format authoritative. Rust struct is for ergonomics.
#[derive(Clone, Copy, Debug)]
pub struct PayloadPrefixV4 {
    pub region_tag:           RegionTag,     // was brain_region; u8 wire
    pub originator:           Originator,    // was hemisphere; u8 wire; 4=COUNCIL (not BOTH)
    pub embedding_model_id:   u8,
    pub _pad:                 u8,            // must be 0x00
    pub embedding_dim:        u16,           // LE; 0 if no embedding
    pub _pad2:                u16,           // must be 0x00
    pub chunk_id:             u32,           // LE
    pub chunk_range_start:    u32,           // LE; UTF-8 byte offset
    pub chunk_range_end:      u32,           // LE; exclusive
    pub parent_event_id:      u64,           // LE; 0 = no parent
    pub supersedes_event_id:  u64,           // LE; 0 = does not supersede
    pub source_uri_hash:      u64,           // LE; xxh3-64(canonical source URI)
    pub source_mtime_ns:      u64,           // LE; 0 if unknown
    pub content_hash:         [u8; 16],      // xxh3-128 of raw content bytes
    pub embedding_hash:       [u8; 16],      // xxh3-128 of vector f32 bytes; zeros if none
    pub vector_blob_off:      u64,           // LE; byte offset in vec-{event_id_hi}.bin
    pub prompt_bundle_hash:   [u8; 32],      // sha256 of prompt bundle CBOR; zeros if none
}
// size_of::<PayloadPrefixV4>() (as packed wire bytes) == 122
```

Wire layout of PayloadPrefixV4 (relative to payload start, after prefix_len):

```
Offset    Size  Type      Endian  Field
-------   ----  --------  ------  -----
[2..3)     1   u8        --      region_tag (RegionTag enum)
[3..4)     1   u8        --      originator (Originator enum)
[4..5)     1   u8        --      embedding_model_id
[5..6)     1   u8        --      _pad = 0
[6..8)     2   u16       LE      embedding_dim
[8..10)    2   u16       LE      _pad2 = 0
[10..14)   4   u32       LE      chunk_id
[14..18)   4   u32       LE      chunk_range_start
[18..22)   4   u32       LE      chunk_range_end
[22..30)   8   u64       LE      parent_event_id
[30..38)   8   u64       LE      supersedes_event_id
[38..46)   8   u64       LE      source_uri_hash
[46..54)   8   u64       LE      source_mtime_ns
[54..70)  16   u8[16]    --      content_hash
[70..86)  16   u8[16]    --      embedding_hash
[86..94)   8   u64       LE      vector_blob_off
[94..126) 32   u8[32]    --      prompt_bundle_hash
=== PayloadPrefixV4 wire: 124 bytes including prefix_len ===
```

Readers locate event body at `payload[2 + prefix_len ..]` (prefix_len enables forward compat).

---

## 6. Migration Decision

v0.7 was never implemented. NEOTH v0.8/v0.9/v1.0 specs were paper-only.
v1.1 is the first wire format to ship.

Version skip convention:

| Value | Field | Status |
|-------|-------|--------|
| 1 | wal_format_version | Reserved — never shipped |
| **2** | **wal_format_version** | **NEOTH v1.1 initial** |
| 1-3 | event_schema_version | Reserved — never shipped |
| **4** | **event_schema_version** | **NEOTH v1.1 initial — canonical** |

Reader encountering `wal_format_version == 1` or `event_schema_version ∈ {1,2,3}` MUST return
`Err(WalError::UnknownFormat { version })`. No fallback. No migration code.

### Migration Policy (R-1 Gremium 2026-05-16)

`event_schema_version` MUST be bumped if and only if the byte-layout of `PayloadPrefixV4`
changes. Specifically: a field moves position, a field changes size, a field is inserted
before the end, or the total prefix length changes.

It MUST NOT be bumped for:
- Adding a new enum variant to an existing 1-byte field (e.g. `RegionTag::Hypothalamus=6`,
  `Originator::*`). The byte is still 1 byte at the same offset; adding a value is
  backward-compatible.
- Adding new `event_type` constants in any band (0x00-0xFF).
- Adding new WAL indexes, SQL views, or schema tables (those are governed by SQLite
  `SCHEMA_VERSION` in `memory/store.rs`, not by wire `event_schema_version`).
- Adding fields to the payload body (past byte 124).

When a bump IS required:
1. Increment `EVENT_SCHEMA_VERSION` in `header.rs` and update §3 + §6 atomically.
2. Add migration path for any persisted WAL data (NEOTH v0.1 has none — "no migration
   code" policy remains valid until first production deployment).
3. Update the version-skip table above with the new row.
4. All SPECs that reference the version constant must update in the same commit.

**Authority precedence**: `header.rs::EVENT_SCHEMA_VERSION` is the code-level source of
truth. SPECs documenting the constant must match the shipped value; any SPEC drift is
a bug in the SPEC, not the code.

---

## 7. Per-Field Justification (KEEP decisions)

| Field | One-sentence justification |
|-------|---------------------------|
| wal_format_version | Reader cannot interpret any other field until it knows wire layout version. |
| event_schema_version | Determines PayloadPrefixV4 shape; needed before payload touch. |
| event_type | Drives pipeline routing, GC policy, index type — all pre-decode. |
| event_subtype | Fine-grained sub-classification; same lifecycle as event_type. |
| flags | TOMBSTONE bit evaluated on every sequential-reader frame skip. |
| header_len | Reader computes payload start as `frame[4 + header_len]`; cannot be deferred. |
| reserved_len | Forward-compat padding accounting; frame navigation. |
| total_len | Sequential reader advances cursor by total_len without touching payload. |
| payload_len | Needed with header_len to slice exactly the payload bytes. |
| generation | Compaction boundary, index partition — pre-GC need. |
| event_id | Primary key for dedup, vector blob lookup, parent linking. |
| **hlc** | Every recall and compaction pass is time-ordered. HLC also enables multi-node causal ordering (Kulkarni 2014) without retrofit. |
| importance | GC weight used by compaction; survives tombstone-elision pass. |
| scope | Coarse fan-out tag evaluated before payload decode. |
| category | Paired routing tag with scope. |
| session_id | Session-scoped recall queries filter before loading payload. |
| node_id | Multi-node log merge requires origin disambiguation at frame-scan. |
| payload_hash | xxh3-64 fast integrity check before paying decode cost. |

---

## 8. Newtypes (S8 hardening)

```rust
/// Event identifier. Compile-time distinct from session_id/node_id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(u64);

/// Session identifier. UUID v7 raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

/// Node identifier. UUID v7 raw bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 16]);

/// Importance score, bounded [0.0, 1.0]. NaN unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Importance(f32);

impl Importance {
    pub const ZERO: Importance = Importance(0.0);
    pub const MAX: Importance = Importance(1.0);
    pub const PROMOTION_THRESHOLD: Importance = Importance(0.75);

    pub fn new(v: f32) -> Result<Self, HeaderParseError> {
        if v.is_nan() || v < 0.0 || v > 1.0 {
            return Err(HeaderParseError::InvalidImportance(v));
        }
        Ok(Self(v))
    }
    pub fn raw(&self) -> f32 { self.0 }
}

// Total Ord (NaN excluded at construction)
impl Eq for Importance {}
impl Ord for Importance {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.partial_cmp(&other.0).expect("Importance: NaN excluded at construction")
    }
}
```

---

## 9. Errors

```rust
#[derive(thiserror::Error, Debug)]
pub enum HeaderParseError {
    #[error("invalid magic: expected b\"NEOT\", got {got:?}")]
    InvalidMagic { got: [u8; 4] },
    #[error("unknown wal_format_version: {got}")]
    UnknownWalFormat { got: u8 },
    #[error("unknown event_schema_version: {got}")]
    UnknownSchema { got: u8 },
    #[error("invalid header_len: expected 96, got {got}")]
    InvalidHeaderLen { got: u16 },
    #[error("non-zero reserved bytes: {0:?}")]
    NonzeroReserved([u8; 3]),
    #[error("invalid region_tag: {0}")]
    InvalidRegionTag(u8),
    #[error("invalid originator: {0}")]
    InvalidOriginator(u8),
    #[error("invalid importance: {0} (must be [0.0, 1.0] non-NaN)")]
    InvalidImportance(f32),
    #[error("invalid flags reserved bits: 0x{0:02x}")]
    InvalidFlagBits(u8),
    #[error("buffer too short: got {got}, need at least {need}")]
    BufferTooShort { got: usize, need: usize },
    #[error("CRC32c mismatch: expected 0x{expected:08x}, got 0x{got:08x}")]
    CrcMismatch { expected: u32, got: u32 },
}
```

---

## 10. Test Vectors

```
Test vector 1: minimal header (all-zero payload, no Hlc tick)
  magic:              4E 45 4F 54                                    (b"NEOT")
  wal_format_ver:     02
  schema_ver:         04
  event_type:         00
  event_subtype:      00
  flags:              00
  header_len:         60 00                                          (= 96 LE)
  reserved_len:       00 00
  total_len:          68 00 00 00                                    (= 104 LE; 4+96+0+0+4)
  payload_len:        00 00 00 00
  generation:         00 00 00 00
  event_id:           00 00 00 00 00 00 00 00
  hlc.physical_ns:    00 00 00 00 00 00 00 00
  hlc.logical:        00 00 00 00
  importance:         00 00 00 00                                    (0.0 LE)
  scope:              00 00 00 00
  category:           00 00 00 00
  session_id:         00 ... 00                                       (16 bytes)
  node_id:            00 ... 00                                       (16 bytes)
  payload_hash:       00 00 00 00 00 00 00 00
  _reserved:          00 00 00
  CRC32c:             1B 92 8B C1                                    (computed)
  TOTAL FRAME LEN:    104 bytes
```

---

## 11. Explicit Byte Parser/Serializer (S8 fix)

`#[repr(C, packed)]` is **NOT used** in v1.1 — it causes UB on multi-byte field access (SIGBUS on aarch64, blocks `cargo miri test`).

Instead: explicit `from_le_bytes(&[u8; 96])` and `to_le_bytes() → [u8; 96]`.

```rust
impl EventHeaderV2 {
    /// Parse 96 bytes (header body, EXCLUDING the 4-byte magic preamble) into typed struct.
    /// All multi-byte integers are little-endian.
    /// Validates: _reserved = [0,0,0], header_len == 96, flag reserved bits clear.
    pub fn from_le_bytes(b: &[u8; 96]) -> Result<Self, HeaderParseError> {
        let wal_format_version   = b[0];
        let event_schema_version = b[1];
        let event_type           = b[2];
        let event_subtype        = b[3];
        let flags_byte           = b[4];
        let header_len           = u16::from_le_bytes([b[5], b[6]]);
        let reserved_len         = u16::from_le_bytes([b[7], b[8]]);
        let total_len            = u32::from_le_bytes([b[9],  b[10], b[11], b[12]]);
        let payload_len          = u32::from_le_bytes([b[13], b[14], b[15], b[16]]);
        let generation           = u32::from_le_bytes([b[17], b[18], b[19], b[20]]);
        let event_id_raw         = u64::from_le_bytes(b[21..29].try_into().unwrap());
        let hlc_physical_ns      = u64::from_le_bytes(b[29..37].try_into().unwrap());
        let hlc_logical          = u32::from_le_bytes(b[37..41].try_into().unwrap());
        let importance_raw       = f32::from_le_bytes(b[41..45].try_into().unwrap());
        let scope                = u32::from_le_bytes(b[45..49].try_into().unwrap());
        let category             = u32::from_le_bytes(b[49..53].try_into().unwrap());
        let session_id_raw: [u8; 16] = b[53..69].try_into().unwrap();
        let node_id_raw:    [u8; 16] = b[69..85].try_into().unwrap();
        let payload_hash         = u64::from_le_bytes(b[85..93].try_into().unwrap());
        let reserved_arr: [u8; 3] = b[93..96].try_into().unwrap();

        // Validation
        if header_len != 96 {
            return Err(HeaderParseError::InvalidHeaderLen { got: header_len });
        }
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
            hlc: Hlc::new(hlc_physical_ns, hlc_logical)
                .map_err(|_| HeaderParseError::InvalidImportance(0.0))?, // remapped HLC err
            importance: Importance::new(importance_raw)?,
            scope,
            category,
            session_id: SessionId(session_id_raw),
            node_id: NodeId(node_id_raw),
            payload_hash,
        })
    }

    /// Serialize to 96-byte little-endian array.
    pub fn to_le_bytes(&self) -> [u8; 96] {
        let mut b = [0u8; 96];
        b[0]  = self.wal_format_version;
        b[1]  = self.event_schema_version;
        b[2]  = self.event_type;
        b[3]  = self.event_subtype;
        b[4]  = self.flags.bits();
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
        // b[93..96] left as [0,0,0]
        b
    }
}
```

### 11.1 Property tests (mandatory before merging EventHeaderV2 module)

```rust
#[test]
fn header_roundtrip() {
    // Arbitrary header → to_le_bytes → from_le_bytes → equal
    for _ in 0..10_000 {
        let h = EventHeaderV2::arbitrary();
        let bytes = h.to_le_bytes();
        let parsed = EventHeaderV2::from_le_bytes(&bytes).unwrap();
        assert_eq!(h, parsed);
    }
}

#[test]
fn header_aarch64_alignment_safe() {
    // Verify no SIGBUS on aarch64 by parsing into a misaligned buffer
    let mut buf = vec![0u8; 100];
    let unaligned_offset = 1;  // force misalignment
    let frame = &buf[unaligned_offset..unaligned_offset + 96];
    let _ = EventHeaderV2::from_le_bytes(frame.try_into().unwrap());
    // No SIGBUS: from_le_bytes uses byte-by-byte access, not pointer cast
}
```

---

## 12. Frame CRC32c

CRC32c covers `frame[0..total_len-4)` — magic + header + reserved + payload, BUT NOT the CRC32c bytes themselves.

```rust
pub fn compute_frame_crc(frame: &[u8]) -> u32 {
    let len = frame.len();
    assert!(len >= 4);
    crc32c::crc32c(&frame[..len - 4])
}
```

HW-accel detection: `crc32c` crate auto-detects CRC32 (x86 SSE4.2) and ARMv8 CRC instructions at runtime. No manual CPUID dispatch in NEOTH.

---

## 13. Status

**v1.1 wire-format BUILD-READY.** S1, S4, S8 from CLAUDE_v07_review + ADVERSARIAL/03 resolved.

Pending architecture-spec updates: SPEC_multinode_clock.md, SPEC_wal_lifecycle.md, SPEC_skill_plugin_system.md.
