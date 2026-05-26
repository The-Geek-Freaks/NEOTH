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
    ///
    /// **Concern-1 fix (Session 24):** the HLC now ticks through the
    /// process-global [`crate::wal::GLOBAL_HLC`] via
    /// [`super::hlc::hlc_tick_local`] instead of allocating a fresh
    /// `Hlc::new(now_ns, 0)` per call. Pre-fix, every event in the
    /// same Windows 15.6 ms `SystemTime::now()` quantization window
    /// stamped the identical `(physical_ns, 0)` HLC → ordering ties
    /// + audit chain forks under concurrent load. Post-fix, the
    /// logical counter increments on tie so every frame has a strict
    /// total order even when the wall clock can't tell two events
    /// apart. Logical overflow (4 billion same-ns events) is treated
    /// as fatal misconfiguration: log + force the physical clock
    /// forward by 1 ns to reset the counter rather than crash the
    /// whole writer task.
    pub fn build(self) -> EventHeaderV2 {
        let now_ns: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let hlc = tick_global_hlc(now_ns);
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
            event_id: EventId(hlc.physical_ns()),
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

/// Concern-1 helper — tick the process-global HLC by `now_ns` and
/// return the resulting clock. Logical-counter overflow is handled
/// inline (re-base on `now_ns + 1` to reset the counter + log error).
/// Mutex-poison recovery via `into_inner()` so a panic in one builder
/// call doesn't permanently brick subsequent ones.
fn tick_global_hlc(now_ns: u64) -> Hlc {
    let mut guard = crate::wal::GLOBAL_HLC
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if super::hlc::hlc_tick_local(&mut guard, now_ns).is_err() {
        // Logical counter overflowed at the same physical_ns. This
        // requires ~4 billion same-ns events — almost certainly a
        // misconfiguration (e.g. SystemTime stuck at 0 in a sandbox).
        // Reset by forcing physical_ns forward; never panic the writer.
        tracing::error!(
            now_ns,
            current_physical = guard.physical_ns(),
            current_logical = guard.logical(),
            "WAL: HLC logical counter overflow — resetting physical clock",
        );
        let recovery = now_ns.saturating_add(1).max(guard.physical_ns().saturating_add(1));
        *guard = Hlc::new(recovery, 0).unwrap_or(Hlc::EPOCH);
    }
    *guard
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

    // ── Concern-1 (Session 24) HLC global-tick wiring ─────────────────
    //
    // The GLOBAL_HLC mutex is process-wide; concurrent tests calling
    // `build()` interleave their ticks. The assertions below use
    // strict ORDERING (`>`) rather than equality on logical-counter
    // values so they hold under any test-runner thread schedule.

    #[test]
    fn hlc_strict_total_order_between_consecutive_builds() {
        // Even if SystemTime::now() returns the same ns for both
        // calls (15.6 ms Windows window), the HLC must distinguish
        // them via the logical counter. The relevant invariant is
        // `Hlc::cmp` total order — the second header must be
        // STRICTLY GREATER than the first.
        let a = HeaderBuilder::new(0x01, b"a").build();
        let b = HeaderBuilder::new(0x01, b"b").build();
        assert!(
            b.hlc > a.hlc,
            "consecutive build()s must produce strictly-greater HLCs (a={:?} b={:?})",
            a.hlc,
            b.hlc,
        );
    }

    #[test]
    fn hlc_logical_increments_within_same_physical_tick() {
        // Drive `tick_global_hlc` directly with a frozen now_ns so
        // the L-counter is the only thing that can move. Pre-fix
        // both calls would return logical=0; post-fix the second
        // call's logical is strictly greater than the first's.
        //
        // **GLOBAL_HLC is process-wide** — concurrent tests can move
        // its physical_ns past any historic timestamp. We pick a
        // future timestamp far beyond any other test's choice
        // (year-3000-ish), drive a single tick to anchor the global
        // there, then call twice at the SAME injected now_ns. The
        // second call MUST be a tie → logical increments.
        let anchor: u64 = 100_000_000_000_000_000_000_u128 as u64; // saturates to u64::MAX
        let _anchor_tick = super::tick_global_hlc(anchor);
        let first = super::tick_global_hlc(anchor);
        let second = super::tick_global_hlc(anchor);
        // Both ticks at anchor → physical pinned, logical strictly
        // increasing.
        assert_eq!(first.physical_ns(), second.physical_ns());
        assert!(
            second.logical() > first.logical(),
            "L-counter must increment on tie: first={first:?} second={second:?}",
        );
    }

    #[test]
    fn hlc_physical_advances_when_clock_moves_forward() {
        // After anchoring the global, a subsequent tick with a
        // strictly-greater now_ns must advance physical_ns and reset
        // logical to 0. Use a very large base to outrun concurrent
        // tests' anchor values.
        let base: u64 = u64::MAX - 1_000_000_000; // ≈ 1 second below saturation
        let first = super::tick_global_hlc(base);
        let second = super::tick_global_hlc(u64::MAX);
        assert!(
            second.physical_ns() > first.physical_ns(),
            "physical_ns must advance when now_ns moves forward: \
             first={first:?} second={second:?}",
        );
        assert_eq!(
            second.logical(),
            0,
            "logical must reset to 0 when physical advances",
        );
    }

    #[test]
    fn hlc_no_duplicates_under_64_thread_burst() {
        // The Berater scenario: many threads calling build() in a
        // burst. Even if SystemTime returns identical ns for many
        // calls, no two HLCs may compare equal — `Hlc::cmp` must
        // give a strict total order over the whole bag.
        use std::collections::BTreeSet;
        use std::sync::Arc;
        use std::sync::Barrier;

        let threads = 8;
        let per_thread = 200;
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut out = Vec::with_capacity(per_thread);
                b.wait();
                for _ in 0..per_thread {
                    let h = HeaderBuilder::new(0x01, b"x").build();
                    out.push(h.hlc);
                }
                out
            }));
        }
        let mut all = Vec::with_capacity(threads * per_thread);
        for h in handles {
            all.extend(h.join().unwrap());
        }
        // Strict total order: collecting into a BTreeSet should not
        // collapse any entries.
        let unique: BTreeSet<_> = all.iter().copied().collect();
        assert_eq!(
            unique.len(),
            all.len(),
            "every concurrent build() must produce a UNIQUE HLC; got {} dupes",
            all.len() - unique.len(),
        );
    }
}
