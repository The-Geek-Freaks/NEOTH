// WAL error types -- SPEC_wire_header_v2_slim.md §9, SPEC_multinode_clock.md §3.1
// Single error tree for header parse, HLC, and writer concerns.

use std::io;
use thiserror::Error;

use super::types::NodeId;

#[derive(Error, Debug)]
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

    #[error("HLC error: {0}")]
    Hlc(#[from] HlcError),
}

#[derive(Error, Debug)]
pub enum HlcError {
    #[error("post-epoch logical without physical (physical_ns=0, logical={0})")]
    PostEpochLogicalWithoutPhysical(u32),

    #[error("HLC logical counter overflow (peer={peer_node_id:?})")]
    LogicalOverflow { peer_node_id: Option<NodeId> },
}

#[derive(Error, Debug)]
pub enum WalError {
    #[error("WAL header parse error")]
    Header(#[from] HeaderParseError),

    #[error("WAL I/O error")]
    Io(#[from] io::Error),

    #[error("HLC tick error")]
    Hlc(#[from] HlcError),

    #[error("unknown wal_format_version on read")]
    UnknownFormat { version: u8 },

    #[error("payload exceeds max segment size ({0} > {1} bytes)")]
    PayloadTooLarge(usize, usize),

    #[error("WAL writer task closed")]
    WriterClosed,

    #[error("WAL writer queue full — refusing sync append (capacity={capacity})")]
    WriterBackpressured { capacity: usize },

    #[error("WAL disk quota breached: {used} / {ceiling} bytes — refusing write")]
    QuotaExceeded { used: u64, ceiling: u64 },

    #[error(
        "WAL segment header CRC mismatch on seq {seq}: expected 0x{expected_crc:08x}, got 0x{got_crc:08x}"
    )]
    SegmentHeaderCorrupt {
        seq: u64,
        expected_crc: u32,
        got_crc: u32,
    },

    /// Workstream F (CT-10/E-20/V1x-06) — zstd compression failed.
    #[error("WAL segment compression failed: {0}")]
    Compress(String),

    /// Workstream F (CT-10/E-20/V1x-06) — zstd decompression failed.
    #[error("WAL segment decompression failed: {0}")]
    Decompress(String),
}
