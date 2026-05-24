// WAL module -- Day-2 wire format + writer.
// See PLAN/SPEC_wire_header_v2_slim.md, PLAN/SPEC_wal_lifecycle.md,
// and PLAN/SPEC_multinode_clock.md for the normative spec.

pub mod builder;
pub mod compaction;
/// Workstream F (CT-10/E-20/V1x-06) — zstd compress/decompress helpers
/// for sealed WAL segments. Pure sync wrappers; the writer calls them
/// during segment finalization (not on the hot per-frame path).
pub mod compress;
#[cfg(windows)]
pub mod dpapi;
pub mod error;
pub mod events;
pub mod frame;
pub mod header;
pub mod hlc;
pub mod recovery;
pub mod redact;
pub mod segment_header;
pub mod snapshot;
pub mod types;
#[cfg(windows)]
pub mod win_acl;
#[cfg(windows)]
pub mod win_native;
pub mod writer;

// Re-exports of the small set of types that callers outside wal/ actually
// consume today. The rest (hlc_tick_local, RegionTag, Originator, MAGIC,
// constants, encoder/decoder etc.) are reachable through their fully-qualified
// paths under wal::header, wal::hlc, wal::frame, wal::types, wal::writer.
//
// Why not blanket re-export everything: dead_code warnings on items that no
// upstream consumer uses yet make the build output noisy and hide real
// regressions. Re-exports get added here as wired-up Day-by-Day.
pub use builder::{HeaderBuilder, make_header};
pub use types::EventFlags;
pub use writer::spawn;
// Re-exports consumed by in-crate tests (recall, chat, serve, indexer suites).
// Marked allow(unused_imports) because non-test code paths reach these via
// fully-qualified module paths; the re-export is for ergonomic test imports.
#[allow(unused_imports)]
pub use header::EventHeaderV2;
#[allow(unused_imports)]
pub use hlc::Hlc;
#[allow(unused_imports)]
pub use types::{EventId, Importance, NodeId, SessionId};
// WalError gets re-exported once an external caller consumes it directly;
// for now `?` conversion via thiserror handles propagation.
