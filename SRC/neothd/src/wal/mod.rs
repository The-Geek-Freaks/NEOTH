// WAL module -- Day-2 wire format + writer.
// See PLAN/SPEC_wire_header_v2_slim.md, PLAN/SPEC_wal_lifecycle.md,
// and PLAN/SPEC_multinode_clock.md for the normative spec.

pub mod builder;
pub mod compaction;
/// Workstream F (CT-10/E-20/V1x-06) — zstd compress/decompress helpers
/// for sealed WAL segments. Pure sync wrappers; the writer calls them
/// during segment finalization (not on the hot per-frame path).
pub mod compress;
/// ADV-01 (F4 finding, SPEC §4.3) — HMAC-SHA256 authenticator + .cpt
/// file format + crash-recovery apply path. Closes the pre-placed-
/// .cpt-injection attack window on the WAL recovery boundary.
pub mod cpt_auth;
pub mod cpt_format;
pub mod cpt_recovery;
#[cfg(windows)]
pub mod dpapi;
pub mod error;
pub mod events;
pub mod frame;
pub mod header;
pub mod hlc;
pub mod payloads_u04;
pub mod payloads_w08;
pub mod proof_bundle;
pub mod recovery;
/// KF-03 — operator proof-bundle signing key (ed25519, DAU-safe auto-managed).
pub mod signing;
pub mod redact;
pub mod segment_header;
pub mod snapshot;
pub mod types;
/// Round-3 v0.4 QU-08 — derived read-only views over the WAL
/// indexer's SQLite tables. Starts with `episode` (60-min temporal-
/// window grouping over `idx_episode`); more views land per
/// follow-up items.
pub mod views;
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

/// Concern-1 fix (Session 24) — process-global HLC state.
///
/// **Why this exists:** [`builder::HeaderBuilder::build`] pre-fix
/// created a fresh `Hlc::new(now_ns, 0)` per frame. The HLC algorithm
/// in [`hlc`] is correct (Kulkarni 2014 textbook + logical-counter
/// tie-break), but the logical counter never INCREMENTED at any
/// call site — every call site allocated a new clock starting at
/// `logical = 0`. Under Windows's 15.6 ms `SystemTime::now()`
/// quantization, every event in the same window stamped
/// `(same_ns, 0)` → total-order ties + audit chain forks.
///
/// **Contract:** every call site that wants an HLC-stamped header
/// must reach for this global through
/// [`builder::HeaderBuilder::build`] (which calls
/// `hlc_tick_local(&mut guard, now_ns)` internally), or through
/// the gossip-receive path (which calls `hlc_tick_receive`). Direct
/// `Hlc::new(now_ns, 0)` is reserved for tests + the EPOCH sentinel.
///
/// **Mutex choice:** `std::sync::Mutex::new` is `const` since 1.63
/// for `Mutex<Hlc>` because `Hlc` is plain-old-data. No `OnceLock`
/// needed. Poisoned-mutex recovery uses `into_inner()` so a panic
/// in one frame builder doesn't permanently brick the WAL surface
/// for the rest of the process.
pub(crate) static GLOBAL_HLC: std::sync::Mutex<hlc::Hlc> = std::sync::Mutex::new(hlc::Hlc::EPOCH);
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
