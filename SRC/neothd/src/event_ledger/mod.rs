//! P-05 (Session 24) — Event Ledger JSON sidecar.
//!
//! A2 (openclaw adopt) flagged the cold-start UX gap: the Slint
//! GUI (when it ships) needs to display a summary of recent
//! activity ("you had 12 chats / 3 cron fires / 2 refusals this
//! week") on its first paint. Today the only authoritative source
//! is the WAL — opening + decoding it during GUI bootstrap is
//! ~50-200 ms on a warm cache and worse on a cold one. By the
//! time the operator sees pixels, the spinner has already
//! lingered too long.
//!
//! The Event Ledger is a lightweight JSON sidecar at
//! `~/.neoth/event_ledger.json` that the daemon updates
//! incrementally as it writes WAL frames. The GUI cold-start path
//! reads + parses the sidecar in <5 ms with `serde_json`, gives
//! the operator a first paint, then asks the daemon for live
//! updates over the existing channels.
//!
//! ## Shape
//!
//! [`Ledger`] carries: rolling counters per event_type, a
//! bounded ring buffer of the last N event headers (event_id +
//! event_type + ts_ns), and a `last_updated_unix` watermark so
//! the GUI can show "data as of …".
//!
//! ## Write-side contract
//!
//! - **Atomic-rename writes only.** [`save`] writes
//!   `event_ledger.json.tmp` first then renames. Concurrent GUI
//!   readers never observe a partial file.
//! - **Lock-protected.** A `Mutex<Ledger>` lives in the daemon's
//!   shared state; every WAL append takes the lock, applies the
//!   `record` update, then writes. Single-writer contract; the
//!   GUI never writes.
//!
//! ## Out of scope
//!
//! - Reactive streaming (GUI gets updates over the existing event
//!   bus + a follow-up `subscribe()` API; the ledger is cold-start
//!   only).
//! - Encrypted-at-rest sidecar (the underlying WAL is mode-0600 /
//!   DACL-restricted; the ledger inherits the same trust boundary
//!   via [`crate::config::credentials::write_mode_0600`]).

use std::collections::{HashMap, VecDeque};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Default ring-buffer capacity. Tuned for "recent activity GUI
/// surface" — 256 events covers a typical operator's last 1-2
/// hours of WAL activity. Operators with chat-heavy workloads
/// widen via [`Ledger::with_capacity`].
pub const DEFAULT_RECENT_CAPACITY: usize = 256;

/// One row in the ledger's recent-event ring buffer. Carries
/// only the metadata the GUI needs for a summary line; the
/// payload bodies stay in the WAL.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecentEvent {
    pub event_id: u64,
    pub event_type: u8,
    pub ts_ns: u64,
}

/// The sidecar shape. Serialised verbatim to
/// `event_ledger.json`. Operators can `cat` the file to inspect
/// it; the shape is intentionally human-readable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    /// Map of event_type (hex like "0x01") → cumulative count.
    /// Hex keys keep operator `jq` queries readable.
    #[serde(default)]
    pub counts_by_event_type: HashMap<String, u64>,
    /// Bounded ring of the most-recent events. Oldest entry is
    /// trimmed when the buffer reaches capacity. A `VecDeque` so the
    /// at-capacity trim is an O(1) `pop_front` instead of `Vec::remove(0)`,
    /// which shifted every surviving element on each append (quadratic
    /// over a busy WAL).
    #[serde(default)]
    pub recent: VecDeque<RecentEvent>,
    /// Capacity of the ring buffer. Defaults to
    /// [`DEFAULT_RECENT_CAPACITY`].
    #[serde(default = "default_capacity")]
    pub recent_capacity: usize,
    /// Unix-seconds wall clock of the most recent [`record`] call.
    /// Surfaces as "data as of …" in the GUI summary.
    #[serde(default)]
    pub last_updated_unix: i64,
}

fn default_capacity() -> usize {
    DEFAULT_RECENT_CAPACITY
}

impl Ledger {
    /// Fresh empty ledger with the default ring capacity.
    pub fn new() -> Self {
        Self {
            counts_by_event_type: HashMap::new(),
            recent: VecDeque::new(),
            recent_capacity: DEFAULT_RECENT_CAPACITY,
            last_updated_unix: 0,
        }
    }

    /// Fresh empty ledger with an explicit ring capacity. Clamped
    /// to ≥1 (defensive: a misconfigured operator passing 0
    /// wouldn't break `record`).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            recent_capacity: capacity.max(1),
            ..Self::new()
        }
    }

    /// Apply one WAL append. Bumps the per-event-type counter +
    /// pushes the metadata into the ring (trimming the oldest
    /// entry when at capacity) + stamps `last_updated_unix`.
    pub fn record(&mut self, event: RecentEvent, now_unix: i64) {
        let key = format!("0x{:02X}", event.event_type);
        *self.counts_by_event_type.entry(key).or_insert(0) += 1;
        if self.recent_capacity == 0 {
            self.recent_capacity = DEFAULT_RECENT_CAPACITY;
        }
        if self.recent.len() >= self.recent_capacity {
            self.recent.pop_front();
        }
        self.recent.push_back(event);
        self.last_updated_unix = now_unix;
    }

    /// Total event count across all event types. Useful for the
    /// GUI's top-line summary widget.
    pub fn total_events(&self) -> u64 {
        self.counts_by_event_type.values().sum()
    }

    /// Top-N event types by count. Sorted desc then alphabetical
    /// for stable output. Returns up to `n` `(event_type_hex,
    /// count)` pairs.
    pub fn top_event_types(&self, n: usize) -> Vec<(String, u64)> {
        let mut pairs: Vec<(String, u64)> = self
            .counts_by_event_type
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs.truncate(n);
        pairs
    }
}

/// Atomically write the ledger to `path`. Uses the credentials
/// helper for mode-0600 / DACL-restricted output so the file
/// inherits the same trust boundary as the WAL.
pub fn save(path: &Path, ledger: &Ledger) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir for {}", path.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(ledger).context("serialise event ledger")?;
    let tmp = path.with_extension("json.tmp");
    crate::config::credentials::write_mode_0600(&tmp, &bytes)
        .with_context(|| format!("write tmp {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Load the ledger from `path`. Returns `Ok(Ledger::new())` for
/// missing file OR zero-length file (atomic-rename race window)
/// so the daemon's bootstrap + the GUI's cold-start path both
/// call this unconditionally.
pub fn load(path: &Path) -> Result<Ledger> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Ledger::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if bytes.is_empty() {
        return Ok(Ledger::new());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn ev(event_id: u64, event_type: u8, ts_ns: u64) -> RecentEvent {
        RecentEvent {
            event_id,
            event_type,
            ts_ns,
        }
    }

    #[test]
    fn new_ledger_is_empty() {
        let l = Ledger::new();
        assert!(l.counts_by_event_type.is_empty());
        assert!(l.recent.is_empty());
        assert_eq!(l.recent_capacity, DEFAULT_RECENT_CAPACITY);
        assert_eq!(l.last_updated_unix, 0);
        assert_eq!(l.total_events(), 0);
    }

    #[test]
    fn with_capacity_clamps_zero_to_one() {
        let l = Ledger::with_capacity(0);
        assert_eq!(l.recent_capacity, 1);
    }

    #[test]
    fn record_increments_count_and_pushes_recent() {
        let mut l = Ledger::new();
        l.record(ev(1, 0x01, 100), 1700);
        l.record(ev(2, 0x01, 200), 1701);
        l.record(ev(3, 0x10, 300), 1702);

        assert_eq!(l.counts_by_event_type["0x01"], 2);
        assert_eq!(l.counts_by_event_type["0x10"], 1);
        assert_eq!(l.recent.len(), 3);
        assert_eq!(l.last_updated_unix, 1702);
        assert_eq!(l.total_events(), 3);
    }

    #[test]
    fn record_trims_oldest_entry_when_at_capacity() {
        let mut l = Ledger::with_capacity(3);
        for i in 1..=5 {
            l.record(ev(i, 0x01, i * 100), i as i64);
        }
        // Cap=3 → only last 3 events survive.
        assert_eq!(l.recent.len(), 3);
        assert_eq!(l.recent[0].event_id, 3);
        assert_eq!(l.recent[1].event_id, 4);
        assert_eq!(l.recent[2].event_id, 5);
        // Counters always cumulative regardless of ring trim.
        assert_eq!(l.counts_by_event_type["0x01"], 5);
        assert_eq!(l.total_events(), 5);
    }

    #[test]
    fn record_ring_trim_preserves_fifo_order_past_capacity() {
        // COR-28: the trim moved from `Vec::remove(0)` (O(n) shift) to
        // `VecDeque::pop_front` (O(1)). Filling well past capacity must
        // still leave exactly the last N events in insertion order —
        // front = oldest survivor, back = newest.
        let cap = 4;
        let mut l = Ledger::with_capacity(cap);
        for i in 1u64..=10 {
            l.record(ev(i, 0x01, i * 100), i as i64);
        }
        assert_eq!(l.recent.len(), cap);
        let ids: Vec<u64> = l.recent.iter().map(|e| e.event_id).collect();
        assert_eq!(ids, vec![7, 8, 9, 10]);
        // Index 0 is still the oldest survivor (front), matching the
        // pre-VecDeque semantics relied on elsewhere in these tests.
        assert_eq!(l.recent[0].event_id, 7);
    }

    #[test]
    fn record_recovers_from_zero_capacity_on_first_use() {
        // Hand-crafted ledger with recent_capacity=0 — record must
        // not divide-by-zero or infinite-trim. Pin the
        // self-healing fallback to DEFAULT_RECENT_CAPACITY.
        let mut l = Ledger::new();
        l.recent_capacity = 0;
        l.record(ev(1, 0x01, 100), 1700);
        assert_eq!(l.recent_capacity, DEFAULT_RECENT_CAPACITY);
        assert_eq!(l.recent.len(), 1);
    }

    #[test]
    fn event_type_keys_use_uppercase_hex_with_0x_prefix() {
        // Drift guard for the operator-facing key format. `jq` queries
        // in the wild expect `"0x01"` not `"1"` or `"0X01"`.
        let mut l = Ledger::new();
        l.record(ev(1, 0x0A, 100), 1);
        l.record(ev(2, 0xFF, 200), 2);
        assert!(l.counts_by_event_type.contains_key("0x0A"));
        assert!(l.counts_by_event_type.contains_key("0xFF"));
    }

    #[test]
    fn top_event_types_sorts_desc_with_alphabetical_tiebreak() {
        let mut l = Ledger::new();
        // 0x01: 3 / 0x10: 5 / 0xA0: 1 / 0xC4: 5 (tied with 0x10)
        for _ in 0..3 {
            l.record(ev(0, 0x01, 0), 0);
        }
        for _ in 0..5 {
            l.record(ev(0, 0x10, 0), 0);
        }
        l.record(ev(0, 0xA0, 0), 0);
        for _ in 0..5 {
            l.record(ev(0, 0xC4, 0), 0);
        }
        let top = l.top_event_types(10);
        // Tied at 5: alphabetical → "0x10" < "0xC4" → 0x10 first.
        assert_eq!(top[0], ("0x10".to_string(), 5));
        assert_eq!(top[1], ("0xC4".to_string(), 5));
        assert_eq!(top[2], ("0x01".to_string(), 3));
        assert_eq!(top[3], ("0xA0".to_string(), 1));
        // Cap at N.
        let top_2 = l.top_event_types(2);
        assert_eq!(top_2.len(), 2);
    }

    // ── save / load: persistence ──────────────────────────────────────

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("event_ledger.json");
        let mut l = Ledger::with_capacity(5);
        l.record(ev(1, 0x01, 100), 1700);
        l.record(ev(2, 0x10, 200), 1701);

        save(&path, &l).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.counts_by_event_type, l.counts_by_event_type);
        assert_eq!(loaded.recent, l.recent);
        assert_eq!(loaded.recent_capacity, 5);
        assert_eq!(loaded.last_updated_unix, 1701);
    }

    #[test]
    fn load_returns_default_for_missing_file() {
        let dir = tempdir().unwrap();
        let l = load(&dir.path().join("never-existed.json")).unwrap();
        assert!(l.counts_by_event_type.is_empty());
    }

    #[test]
    fn load_returns_default_for_zero_length_file() {
        // Atomic-rename race window. Bootstrap path must not crash
        // on an empty file.
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, b"").unwrap();
        let l = load(&path).unwrap();
        assert!(l.counts_by_event_type.is_empty());
    }

    #[test]
    fn load_propagates_parse_error_for_garbage_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("garbage.json");
        std::fs::write(&path, b"{ not real json }").unwrap();
        let r = load(&path);
        assert!(r.is_err(), "garbage JSON must Err so the daemon can warn");
    }

    #[test]
    fn save_is_atomic_via_tmp_then_rename() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("event_ledger.json");
        let mut l = Ledger::new();
        l.record(ev(1, 0x01, 100), 1700);
        save(&path, &l).unwrap();
        // The .tmp companion must be GONE after save (renamed to
        // path). Pre-rule a regression that drops the rename would
        // leave the .tmp + corrupt the operator's audit.
        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "tmp companion must be renamed away");
        assert!(path.exists(), "final ledger file must exist");
    }
}
