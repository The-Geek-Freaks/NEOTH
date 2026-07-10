//! GOLD-FEAT-06 — swarm dashboard core types.
//!
//! [`NodeResourceSnapshot`] is the per-node resource record written to the WAL
//! as an `EXTENDED/LocalSnapshot` (0x00/0x04) frame by this node, or received
//! via gossip as an `EXTENDED/SwarmResourceSnapshot` (0x00/0x03) frame from a
//! peer. [`SwarmTable`] is a pure in-memory index of the most recent snapshot
//! per node — it has no I/O of its own and is rebuilt from WAL frames on every
//! `neoth cluster swarm` invocation.
//!
//! # Gossip replication (deferred — TODO DES-14)
//! `wal_sync::classify_event` keys on the `event_type` byte only (0x00 for all
//! EXTENDED frames). It cannot distinguish `LocalSnapshot` (subtype 0x04) from
//! `SwarmResourceSnapshot` (subtype 0x03) without a protocol extension. Until
//! that extension lands, LocalSnapshot frames are written but NOT gossip-replicated
//! to peers. The shippable core is: local WAL emission + `neoth cluster swarm`
//! reads those frames. Do NOT edit `wal_sync.rs` (hot file, parallel session).

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── NodeResourceSnapshot ─────────────────────────────────────────────────────

/// Per-node resource snapshot for the GOLD-FEAT-06 swarm dashboard.
///
/// Serde: serialized as JSON payload in `EXTENDED/LocalSnapshot` WAL frames.
/// Field names are stable on-disk identifiers — do NOT rename them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeResourceSnapshot {
    /// Stable node identifier (hostname or operator-assigned name).
    pub node_id: String,
    /// OS hostname of the emitting node.
    pub hostname: String,
    /// CPU utilisation in percent. Clamped to `[0.0, 100.0]` on construction.
    pub cpu_pct: f32,
    /// RAM currently in use (MiB).
    pub ram_used_mb: u64,
    /// Total installed RAM (MiB). Invariant: `ram_used_mb <= ram_total_mb`.
    pub ram_total_mb: u64,
    /// VRAM currently in use (MiB). `None` on CPU-only / no-GPU hosts.
    pub vram_used_mb: Option<u64>,
    /// Total VRAM installed (MiB). `None` on CPU-only / no-GPU hosts.
    pub vram_total_mb: Option<u64>,
    /// Wall-clock seconds since the Unix epoch (via [`crate::time::now_unix_i64`]).
    pub ts_unix: i64,
}

impl NodeResourceSnapshot {
    /// Construct a snapshot, clamping and validating field invariants.
    ///
    /// Clamp rules:
    /// - `cpu_pct` → `[0.0, 100.0]`
    /// - `ram_used_mb` → `[0, ram_total_mb]`
    /// - `vram_used_mb` → `[0, vram_total_mb]` (when both `Some`)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: String,
        hostname: String,
        cpu_pct: f32,
        ram_used_mb: u64,
        ram_total_mb: u64,
        vram_used_mb: Option<u64>,
        vram_total_mb: Option<u64>,
        ts_unix: i64,
    ) -> Self {
        let cpu_pct = cpu_pct.clamp(0.0, 100.0);
        let ram_used_mb = ram_used_mb.min(ram_total_mb);
        let (vram_used_mb, vram_total_mb) = match (vram_used_mb, vram_total_mb) {
            (Some(u), Some(t)) => (Some(u.min(t)), Some(t)),
            pair => pair,
        };
        Self {
            node_id,
            hostname,
            cpu_pct,
            ram_used_mb,
            ram_total_mb,
            vram_used_mb,
            vram_total_mb,
            ts_unix,
        }
    }
}

// ── SwarmTable ───────────────────────────────────────────────────────────────

/// In-memory index of the most recent [`NodeResourceSnapshot`] per node.
///
/// This is a pure read-side view rebuilt from WAL frames — it has no I/O and
/// no persistence of its own. Callers control stale-entry eviction via
/// [`SwarmTable::prune`].
#[derive(Default)]
pub struct SwarmTable {
    peers: HashMap<String, NodeResourceSnapshot>,
}

impl SwarmTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the snapshot for `snap.node_id`.
    /// If a snapshot for the same node_id already exists, it is overwritten
    /// (the new snapshot is assumed to be more recent).
    pub fn upsert(&mut self, snap: NodeResourceSnapshot) {
        self.peers.insert(snap.node_id.clone(), snap);
    }

    /// Remove entries whose `ts_unix` is more than `stale_after_secs` seconds
    /// behind `now_unix_i64()`.
    pub fn prune(&mut self, stale_after_secs: i64) {
        let now = crate::time::now_unix_i64();
        self.peers
            .retain(|_, v| (now - v.ts_unix) <= stale_after_secs);
    }

    /// Return all snapshots sorted ascending by `node_id`.
    pub fn rows(&self) -> Vec<&NodeResourceSnapshot> {
        let mut v: Vec<&NodeResourceSnapshot> = self.peers.values().collect();
        v.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        v
    }

    /// Number of nodes currently in the table.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// True when no nodes are tracked.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

// ── SwarmConfig ──────────────────────────────────────────────────────────────

/// Configuration for the GOLD-FEAT-06 resource-snapshot cron.
///
/// # Config integration (TODO FEAT-06)
/// This struct is intentionally standalone. `config/mod.rs` is owned by a
/// parallel session and cannot be edited. Once that session completes, add:
/// ```yaml
/// # freedom.yaml
/// swarm:
///   enabled: true
///   interval_secs: 30
///   stale_after_secs: 300
/// ```
/// and a corresponding `swarm: SwarmConfig` field to `FreedomConfig`.
/// Until then, callers use [`SwarmConfig::default()`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmConfig {
    /// Enable the resource-snapshot cron (default: `true`).
    pub enabled: bool,
    /// Seconds between local snapshot samples (default: `30`).
    pub interval_secs: u64,
    /// Seconds after which a peer's snapshot is considered stale (default: `300`).
    pub stale_after_secs: i64,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            stale_after_secs: 300,
        }
    }
}

impl SwarmConfig {
    /// Convert `interval_secs` to a [`Duration`].
    pub fn interval_duration(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(node_id: &str, ts_unix: i64) -> NodeResourceSnapshot {
        NodeResourceSnapshot::new(
            node_id.to_string(),
            "box".to_string(),
            42.5,
            4096,
            16384,
            Some(2048),
            Some(8192),
            ts_unix,
        )
    }

    // ── NodeResourceSnapshot construction + invariants ────────────────────

    #[test]
    fn cpu_pct_clamped_low() {
        let s = NodeResourceSnapshot::new(
            "n".into(), "h".into(), -5.0, 0, 0, None, None, 0,
        );
        assert_eq!(s.cpu_pct, 0.0);
    }

    #[test]
    fn cpu_pct_clamped_high() {
        let s = NodeResourceSnapshot::new(
            "n".into(), "h".into(), 150.0, 0, 0, None, None, 0,
        );
        assert_eq!(s.cpu_pct, 100.0);
    }

    #[test]
    fn ram_used_clamped_to_total() {
        let s = NodeResourceSnapshot::new(
            "n".into(), "h".into(), 50.0, 99999, 8192, None, None, 0,
        );
        assert_eq!(s.ram_used_mb, 8192, "ram_used_mb must not exceed ram_total_mb");
    }

    #[test]
    fn vram_used_clamped_to_total() {
        let s = NodeResourceSnapshot::new(
            "n".into(), "h".into(), 50.0, 0, 0, Some(9999), Some(8192), 0,
        );
        assert_eq!(s.vram_used_mb, Some(8192));
        assert_eq!(s.vram_total_mb, Some(8192));
    }

    #[test]
    fn vram_none_when_both_none() {
        let s = NodeResourceSnapshot::new(
            "n".into(), "h".into(), 0.0, 0, 0, None, None, 0,
        );
        assert_eq!(s.vram_used_mb, None);
        assert_eq!(s.vram_total_mb, None);
    }

    // ── SwarmTable upsert / rows ──────────────────────────────────────────

    #[test]
    fn upsert_inserts_and_overwrites() {
        let mut t = SwarmTable::new();
        t.upsert(snap("alpha", 100));
        t.upsert(snap("beta", 200));
        assert_eq!(t.len(), 2);

        // Overwrite alpha with a fresher snapshot.
        let fresh = NodeResourceSnapshot::new(
            "alpha".into(), "box2".into(), 99.0, 100, 200, None, None, 999,
        );
        t.upsert(fresh.clone());
        assert_eq!(t.len(), 2, "upsert must not grow the table for an existing node");
        let rows = t.rows();
        let alpha = rows.iter().find(|r| r.node_id == "alpha").unwrap();
        assert_eq!(alpha.ts_unix, 999, "stale alpha snapshot was not replaced");
    }

    #[test]
    fn rows_sorted_by_node_id() {
        let mut t = SwarmTable::new();
        t.upsert(snap("zz", 1));
        t.upsert(snap("aa", 2));
        t.upsert(snap("mm", 3));
        let ids: Vec<&str> = t.rows().iter().map(|r| r.node_id.as_str()).collect();
        assert_eq!(ids, ["aa", "mm", "zz"]);
    }

    // ── SwarmTable prune ──────────────────────────────────────────────────

    #[test]
    fn prune_removes_stale_entries() {
        let mut t = SwarmTable::new();
        // ts_unix = 0 is ~50 years ago; stale_after_secs = 1 → must be pruned.
        t.upsert(snap("old", 0));
        // A very recent snapshot (far future to guarantee freshness).
        t.upsert(snap("fresh", i64::MAX / 2));
        t.prune(1);
        assert_eq!(t.len(), 1, "old snapshot should be pruned");
        assert!(t.rows().iter().any(|r| r.node_id == "fresh"));
    }

    #[test]
    fn prune_keeps_all_when_large_window() {
        let mut t = SwarmTable::new();
        t.upsert(snap("a", 0));
        t.upsert(snap("b", 1));
        t.prune(i64::MAX);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn prune_empty_table_is_noop() {
        let mut t = SwarmTable::new();
        t.prune(60);
        assert!(t.is_empty());
    }

    // ── SwarmConfig defaults / interval_duration ──────────────────────────

    #[test]
    fn swarm_config_default_values() {
        let cfg = SwarmConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.interval_secs, 30);
        assert_eq!(cfg.stale_after_secs, 300);
        assert_eq!(cfg.interval_duration(), Duration::from_secs(30));
    }
}
