//! WAL header builder — single source of truth for `EventHeaderV2` construction.
//!
//! Phase 33a (AU-B3) — extracted from 4 near-identical builders in
//! `cli/chat.rs::build_header`, `cli/serve.rs::build_pipeline_header`,
//! `cli/serve.rs::boot_header`, and `cron/runner.rs::write_event`. Those
//! call sites drifted independently and would have continued to do so as
//! R-22/R-23/R-24 added more event-types.
//!
//! Use [`HeaderBuilder::new`] for the common case; chain `.flags()` /
//! `.importance()` / `.session()` / `.node()` for non-default values.
//!
//! HLC stamping: `now_ns` is sampled at build time via `SystemTime::now`.
//! `event_id` is set to `now_ns` for monotonic ordering; switch to a real
//! UUID-v7 / Snowflake source once Phase 19 cluster mode lands.

use std::time::{SystemTime, UNIX_EPOCH};

use super::header::{CRC_LEN, EventHeaderV2, HEADER_BODY_LEN, PREAMBLE_LEN};
use super::hlc::Hlc;
use super::types::{EventFlags, EventId, Importance, NodeId, SessionId};

/// Defaults applied to every header unless explicitly overridden.
const DEFAULT_IMPORTANCE: f32 = 0.5;

/// Builder for [`EventHeaderV2`] with sane defaults + override chain.
///
/// Encapsulates the four invariants every WAL frame must satisfy:
///   1. `wal_format_version` / `event_schema_version` match the current
///      header constants — never inlined elsewhere.
///   2. `total_len = PREAMBLE_LEN + HEADER_BODY_LEN + payload.len() + CRC_LEN`
///   3. `payload_hash = xxh3_64(payload)`
///   4. `event_id` + `hlc` are derived from a single `now_ns` sample, so
///      the two stay in sync.
pub struct HeaderBuilder<'p> {
    event_type: u8,
    event_subtype: u8,
    flags: EventFlags,
    importance: f32,
    scope: u32,
    category: u32,
    session_id: SessionId,
    node_id: NodeId,
    payload: &'p [u8],
}

impl<'p> HeaderBuilder<'p> {
    /// Start a builder for a frame carrying `payload` and tagged `event_type`.
    pub fn new(event_type: u8, payload: &'p [u8]) -> Self {
        Self {
            event_type,
            event_subtype: 0,
            flags: EventFlags::empty(),
            importance: DEFAULT_IMPORTANCE,
            scope: 0,
            category: 0,
            session_id: SessionId([0u8; 16]),
            node_id: NodeId([0u8; 16]),
            payload,
        }
    }

    pub fn event_subtype(mut self, v: u8) -> Self {
        self.event_subtype = v;
        self
    }

    pub fn flags(mut self, f: EventFlags) -> Self {
        self.flags = f;
        self
    }

    /// Clamped to `[0.0, 1.0]` on build via [`Importance::new`].
    pub fn importance(mut self, v: f32) -> Self {
        self.importance = v;
        self
    }

    pub fn scope(mut self, v: u32) -> Self {
        self.scope = v;
        self
    }

    pub fn category(mut self, v: u32) -> Self {
        self.category = v;
        self
    }

    pub fn session(mut self, id: SessionId) -> Self {
        self.session_id = id;
        self
    }

    pub fn node(mut self, id: NodeId) -> Self {
        self.node_id = id;
        self
    }

    /// Materialise the header. Samples `SystemTime::now` exactly once so
    /// `event_id` and `hlc.physical_ns` are guaranteed to match.
    ///
    /// On clock-rollback or an unreasonable system clock, falls back to
    /// `Hlc::EPOCH` and `now_ns = 0`. That's deliberately conservative —
    /// it preserves frame validity rather than panicking; the audit trail
    /// will still show the rolled-back boundary because `now_ns` will
    /// regress visibly between adjacent frames. Phase 33c BS-5 adds a
    /// hard monotonic-floor guard at the daemon level.
    pub fn build(self) -> EventHeaderV2 {
        let now_ns: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let hlc = Hlc::new(now_ns, 0).unwrap_or(Hlc::EPOCH);
        let payload_hash = xxhash_rust::xxh3::xxh3_64(self.payload);
        let payload_len = self.payload.len();
        EventHeaderV2 {
            wal_format_version: EventHeaderV2::WAL_FORMAT_VERSION,
            event_schema_version: EventHeaderV2::EVENT_SCHEMA_VERSION,
            event_type: self.event_type,
            event_subtype: self.event_subtype,
            flags: self.flags,
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + payload_len + CRC_LEN) as u32,
            payload_len: payload_len as u32,
            generation: 0,
            event_id: EventId(now_ns),
            hlc,
            importance: Importance::new(self.importance).unwrap_or(Importance::ZERO),
            scope: self.scope,
            category: self.category,
            session_id: self.session_id,
            node_id: self.node_id,
            payload_hash,
        }
    }
}

/// Convenience constructor — `make_header(et, payload)` is shorthand for
/// `HeaderBuilder::new(et, payload).build()` with all defaults.
pub fn make_header(event_type: u8, payload: &[u8]) -> EventHeaderV2 {
    HeaderBuilder::new(event_type, payload).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::{EVENT_TYPE_BOOT, EVENT_TYPE_RAW_TEXT};

    #[test]
    fn make_header_sets_defaults() {
        let payload = b"hello";
        let h = make_header(EVENT_TYPE_RAW_TEXT, payload);
        assert_eq!(h.event_type, EVENT_TYPE_RAW_TEXT);
        assert_eq!(h.event_subtype, 0);
        assert_eq!(h.payload_len, payload.len() as u32);
        assert_eq!(
            h.total_len,
            (PREAMBLE_LEN + HEADER_BODY_LEN + payload.len() + CRC_LEN) as u32,
        );
        assert_eq!(h.flags, EventFlags::empty());
        assert!((h.importance.raw() - DEFAULT_IMPORTANCE).abs() < 1e-6);
        assert_eq!(h.payload_hash, xxhash_rust::xxh3::xxh3_64(payload));
        // event_id derived from now_ns; cannot pin exactly but must be non-zero
        // unless the system clock is at the unix epoch (CI sandboxes sometimes).
        // Either way it must match hlc.physical_ns().
        assert_eq!(h.event_id.0, h.hlc.physical_ns());
    }

    #[test]
    fn header_builder_chains_overrides() {
        let payload = b"boot";
        let session = SessionId([7u8; 16]);
        let node = NodeId([3u8; 16]);
        let h = HeaderBuilder::new(EVENT_TYPE_BOOT, payload)
            .flags(EventFlags::SYNTHETIC)
            .importance(0.9)
            .session(session)
            .node(node)
            .scope(42)
            .category(1)
            .event_subtype(0x05)
            .build();
        assert_eq!(h.event_type, EVENT_TYPE_BOOT);
        assert_eq!(h.event_subtype, 0x05);
        assert_eq!(h.flags, EventFlags::SYNTHETIC);
        assert!((h.importance.raw() - 0.9).abs() < 1e-6);
        assert_eq!(h.session_id.0, session.0);
        assert_eq!(h.node_id.0, node.0);
        assert_eq!(h.scope, 42);
        assert_eq!(h.category, 1);
    }

    #[test]
    fn build_is_idempotent_modulo_clock() {
        // Two builds with identical inputs differ only in the timestamp; all
        // other fields must match. Catches drift in default values.
        let payload = b"x";
        let a = make_header(0x01, payload);
        let b = make_header(0x01, payload);
        assert_eq!(a.event_type, b.event_type);
        assert_eq!(a.event_subtype, b.event_subtype);
        assert_eq!(a.flags, b.flags);
        assert_eq!(a.payload_len, b.payload_len);
        assert_eq!(a.total_len, b.total_len);
        assert_eq!(a.scope, b.scope);
        assert_eq!(a.category, b.category);
        assert_eq!(a.session_id.0, b.session_id.0);
        assert_eq!(a.node_id.0, b.node_id.0);
        assert_eq!(a.payload_hash, b.payload_hash);
        assert!(b.event_id.0 >= a.event_id.0); // monotonic within the same process
    }

    #[test]
    fn invalid_importance_falls_back_to_zero() {
        // Importance::new returns Err for NaN / out-of-range; builder must not
        // panic, must produce a valid header.
        let h = HeaderBuilder::new(0x01, b"").importance(f32::NAN).build();
        assert_eq!(h.importance.raw(), 0.0);
    }
}
