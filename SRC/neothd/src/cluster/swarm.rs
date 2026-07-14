//! GOLD-FEAT-06 — swarm dashboard core types.
//!
//! [`NodeResourceSnapshot`] is the per-node resource record written to the WAL
//! as an `EXTENDED/LocalSnapshot` (0x00/0x04) frame by this node, or received
//! via gossip as an `EXTENDED/SwarmResourceSnapshot` (0x00/0x03) frame from a
//! peer. [`SwarmTable`] is a pure in-memory index of the most recent snapshot
//! per node — it has no I/O of its own and is rebuilt from WAL frames on every
//! `neoth cluster swarm` invocation.
//!
//! # Gossip replication (GOLD-FEAT-06 gossip-piggyback)
//! `wal_sync::classify_event_ext` now keys on `(event_type, event_subtype)`.
//! `SwarmResourceSnapshot` (0x03) frames are `Replicate`; `LocalSnapshot` (0x04)
//! frames remain `DoNotGossip`. The heartbeat loop in `hyperswarm` piggybacks a
//! minimal snapshot on every heartbeat using [`encode_snapshot_gossip_payload`];
//! the receive path decodes it with [`decode_snapshot_gossip_payload`] and writes
//! it to the local WAL so `neoth cluster swarm` shows peer rows.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use crate::config::SwarmConfig;
use crate::wal::writer::WalWriterHandle;

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

// ── Gossip wire helpers (GOLD-FEAT-06 gossip-piggyback) ─────────────────────

/// `EVENT_TYPE_EXTENDED` byte for EXTENDED gossip frames.
const GOSSIP_ET_EXTENDED: u8 = 0x00;

/// Subtype byte for `SwarmResourceSnapshot` on the gossip wire.
const GOSSIP_SUB_SWARM_SNAP: u8 = 0x03; // matches ExtendedSubtype::SwarmResourceSnapshot

/// Encode a [`NodeResourceSnapshot`] into a raw gossip payload.
///
/// The payload is a canonical CRC-protected WAL frame. Normal WAL gossip and
/// synthetic heartbeat snapshots therefore share exactly one wire format; the
/// transport's own message framing treats these bytes as opaque and does not
/// need a stripped-header variant.
///
/// The receiver reconstructs the snapshot with [`decode_snapshot_gossip_payload`]
/// and writes a full EXTENDED/SwarmResourceSnapshot WAL frame to the local WAL
/// so `neoth cluster swarm` can display peer rows.
pub fn encode_snapshot_gossip_payload(snap: &NodeResourceSnapshot) -> Option<Vec<u8>> {
    let json = serde_json::to_vec(snap).ok()?;
    let header = crate::wal::HeaderBuilder::new(GOSSIP_ET_EXTENDED, &json)
        .event_subtype(GOSSIP_SUB_SWARM_SNAP)
        .build();
    Some(crate::wal::frame::encode_frame(&header, &json))
}

/// Decode a gossip payload previously produced by [`encode_snapshot_gossip_payload`].
///
/// Validates frame magic, declared lengths and CRC, then checks
/// `(event_type, event_subtype) == (0x00, 0x03)` before decoding the JSON.
pub fn decode_snapshot_gossip_payload(payload: &[u8]) -> Option<NodeResourceSnapshot> {
    let decoded = crate::wal::frame::decode_frame(payload).ok()?;
    if decoded.header.event_type != GOSSIP_ET_EXTENDED
        || decoded.header.event_subtype != GOSSIP_SUB_SWARM_SNAP
    {
        return None;
    }
    serde_json::from_slice(decoded.payload).ok()
}

/// Persist a validated peer snapshot gossip payload as a normal local WAL
/// frame so the read-side swarm dashboard sees it regardless of transport.
/// Returns `true` only after the frame was accepted by the WAL writer.
pub fn emit_peer_snapshot_to_wal(writer: &WalWriterHandle, gossip_payload: &[u8]) -> bool {
    let Some(snapshot) = decode_snapshot_gossip_payload(gossip_payload) else {
        return false;
    };
    let Ok(json) = serde_json::to_vec(&snapshot) else {
        return false;
    };
    let header = crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &json)
        .event_subtype(crate::wal::events::ExtendedSubtype::SwarmResourceSnapshot as u8)
        .build();
    match writer.try_append_sync(header, json) {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!(
                error = %e,
                "cluster: peer snapshot WAL write failed; sender must retry"
            );
            false
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
        let s = NodeResourceSnapshot::new("n".into(), "h".into(), -5.0, 0, 0, None, None, 0);
        assert_eq!(s.cpu_pct, 0.0);
    }

    #[test]
    fn cpu_pct_clamped_high() {
        let s = NodeResourceSnapshot::new("n".into(), "h".into(), 150.0, 0, 0, None, None, 0);
        assert_eq!(s.cpu_pct, 100.0);
    }

    #[test]
    fn ram_used_clamped_to_total() {
        let s = NodeResourceSnapshot::new("n".into(), "h".into(), 50.0, 99999, 8192, None, None, 0);
        assert_eq!(
            s.ram_used_mb, 8192,
            "ram_used_mb must not exceed ram_total_mb"
        );
    }

    #[test]
    fn vram_used_clamped_to_total() {
        let s = NodeResourceSnapshot::new(
            "n".into(),
            "h".into(),
            50.0,
            0,
            0,
            Some(9999),
            Some(8192),
            0,
        );
        assert_eq!(s.vram_used_mb, Some(8192));
        assert_eq!(s.vram_total_mb, Some(8192));
    }

    #[test]
    fn vram_none_when_both_none() {
        let s = NodeResourceSnapshot::new("n".into(), "h".into(), 0.0, 0, 0, None, None, 0);
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
            "alpha".into(),
            "box2".into(),
            99.0,
            100,
            200,
            None,
            None,
            999,
        );
        t.upsert(fresh.clone());
        assert_eq!(
            t.len(),
            2,
            "upsert must not grow the table for an existing node"
        );
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
        assert_eq!(cfg.interval_duration(), std::time::Duration::from_secs(30));
    }

    // ── Gossip wire encode / decode (GOLD-FEAT-06 gossip-piggyback) ───────

    fn peer_snap(node_id: &str) -> NodeResourceSnapshot {
        NodeResourceSnapshot::new(
            node_id.to_string(),
            "peer-host".to_string(),
            37.5,
            2048,
            8192,
            Some(512),
            Some(4096),
            1_700_000_000,
        )
    }

    #[test]
    fn encode_decode_snapshot_roundtrip() {
        let original = peer_snap("peer-deadbeef");
        let encoded = encode_snapshot_gossip_payload(&original).expect("encode must not fail");
        let frame = crate::wal::frame::decode_frame(&encoded).expect("canonical WAL frame");
        assert_eq!(frame.header.event_type, GOSSIP_ET_EXTENDED);
        assert_eq!(frame.header.event_subtype, GOSSIP_SUB_SWARM_SNAP);
        assert_eq!(frame.header.total_len as usize, encoded.len());

        let decoded = decode_snapshot_gossip_payload(&encoded)
            .expect("decode must succeed on a valid payload");
        assert_eq!(decoded, original, "decoded snapshot must match original");
    }

    #[test]
    fn decode_rejects_wrong_event_type() {
        let original = peer_snap("x");
        let json = serde_json::to_vec(&original).unwrap();
        let header = crate::wal::HeaderBuilder::new(0x90, &json)
            .event_subtype(GOSSIP_SUB_SWARM_SNAP)
            .build();
        let encoded = crate::wal::frame::encode_frame(&header, &json);
        assert!(decode_snapshot_gossip_payload(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_wrong_subtype() {
        let original = peer_snap("x");
        let json = serde_json::to_vec(&original).unwrap();
        let header = crate::wal::HeaderBuilder::new(GOSSIP_ET_EXTENDED, &json)
            .event_subtype(0x04)
            .build();
        let encoded = crate::wal::frame::encode_frame(&header, &json);
        assert!(decode_snapshot_gossip_payload(&encoded).is_none());
    }

    #[test]
    fn decode_rejects_too_short_payload() {
        assert!(decode_snapshot_gossip_payload(&[0u8; 100]).is_none());
        assert!(decode_snapshot_gossip_payload(&[]).is_none());
    }

    #[test]
    fn decode_rejects_crc_tampering() {
        let original = peer_snap("x");
        let mut encoded = encode_snapshot_gossip_payload(&original).unwrap();
        let payload_index = 100;
        encoded[payload_index] ^= 0x01;
        assert!(decode_snapshot_gossip_payload(&encoded).is_none());
    }

    /// Core correctness test for GOLD-FEAT-06 gossip-piggyback: a received
    /// peer snapshot encoded with [`encode_snapshot_gossip_payload`] round-trips
    /// through [`decode_snapshot_gossip_payload`] and lands in the local
    /// [`SwarmTable`] via `upsert`, with stale-prune leaving a fresh entry intact.
    #[test]
    fn received_peer_snapshot_upserts_into_swarm_table() {
        // Simulate: peer sends a SwarmResourceSnapshot gossip frame.
        let peer_snap_in = peer_snap("peer-aabbccdd");
        let payload = encode_snapshot_gossip_payload(&peer_snap_in).expect("encode");

        // Receive path: decode + upsert.
        let decoded =
            decode_snapshot_gossip_payload(&payload).expect("receive path must decode the payload");
        let mut table = SwarmTable::new();
        table.upsert(decoded.clone());

        assert_eq!(table.len(), 1, "peer snapshot must appear in the table");
        let row = table.rows()[0];
        assert_eq!(row.node_id, "peer-aabbccdd");
        assert_eq!(row.hostname, "peer-host");
        assert_eq!(row.cpu_pct, 37.5);

        // A second snapshot from the same peer overwrites (fresher wins). Use a
        // real "now" ts so the 1-second prune below keeps it (prune compares
        // against crate::time::now_unix_i64(), not the fixture epoch).
        let fresher = NodeResourceSnapshot::new(
            "peer-aabbccdd".to_string(),
            "peer-host-v2".to_string(),
            55.0,
            3000,
            8192,
            None,
            None,
            crate::time::now_unix_i64(),
        );
        table.upsert(fresher);
        assert_eq!(
            table.len(),
            1,
            "upsert must not grow the table for same node_id"
        );
        assert_eq!(table.rows()[0].hostname, "peer-host-v2");

        // Stale-prune must evict a snapshot whose ts_unix is 0 (50 years ago).
        let stale = NodeResourceSnapshot::new(
            "stale-peer".to_string(),
            "old".to_string(),
            0.0,
            0,
            0,
            None,
            None,
            0,
        );
        table.upsert(stale);
        assert_eq!(table.len(), 2);
        table.prune(1); // 1 second stale window
        assert_eq!(table.len(), 1, "stale entry must be pruned");
        assert_eq!(table.rows()[0].node_id, "peer-aabbccdd");
    }

    // ── Wire-compat: GOLD-FEAT-06 real-value upgrade ──────────────────────
    //
    // After the GOLD-FEAT-06 upgrade, gossip payloads carry REAL CPU/RAM/VRAM
    // values instead of placeholder zeros. These tests verify that:
    //   (a) real values round-trip correctly through encode/decode;
    //   (b) the old "zeros + Noise-PK hostname" format is still parseable —
    //       nodes running the old firmware must not crash when they encounter
    //       upgraded payloads, and upgraded nodes must handle any old frames
    //       still present in WAL replays (serde_json ignores unknown fields by
    //       default and accepts any valid JSON for known fields).

    /// Real CPU/RAM/VRAM values round-trip through the gossip wire codec.
    #[test]
    fn wire_compat_real_values_roundtrip() {
        let real = NodeResourceSnapshot::new(
            "shadow-pc".to_string(),
            "shadow-pc".to_string(),
            45.3,         // real CPU% (not a placeholder 0.0)
            8_192_u64,    // 8 GiB used
            32_768_u64,   // 32 GiB total
            Some(6_144),  // 6 GiB VRAM used (e.g. RTX 3080)
            Some(10_240), // 10 GiB VRAM total
            1_700_000_000,
        );
        let encoded = encode_snapshot_gossip_payload(&real).unwrap();
        let decoded = decode_snapshot_gossip_payload(&encoded).unwrap();
        assert_eq!(
            decoded, real,
            "real-values snapshot must survive wire roundtrip"
        );
        assert!(
            (decoded.cpu_pct - 45.3).abs() < 0.001,
            "cpu_pct must be preserved"
        );
        assert_eq!(decoded.ram_used_mb, 8_192);
        assert_eq!(decoded.ram_total_mb, 32_768);
        assert_eq!(decoded.vram_used_mb, Some(6_144));
        assert_eq!(decoded.vram_total_mb, Some(10_240));
    }

    /// Placeholder-zero payloads (old firmware style) are still decodable —
    /// wire backward compatibility: upgraded receivers tolerate old senders.
    #[test]
    fn wire_compat_old_zeros_still_parse() {
        let old_style = NodeResourceSnapshot::new(
            "a1b2c3d4e5f6".to_string(), // Noise-PK hex placeholder
            "a1b2c3d4e5f6".to_string(),
            0.0,
            0,
            0,
            None,
            None,
            1_700_000_000,
        );
        let encoded = encode_snapshot_gossip_payload(&old_style).unwrap();
        let decoded = decode_snapshot_gossip_payload(&encoded).unwrap();
        assert_eq!(decoded.cpu_pct, 0.0);
        assert_eq!(decoded.ram_total_mb, 0);
        assert_eq!(decoded.vram_used_mb, None);
        assert_eq!(decoded.node_id, "a1b2c3d4e5f6");
    }

    /// CPU-only host (no VRAM): None fields round-trip correctly.
    #[test]
    fn wire_compat_cpu_only_host_no_vram() {
        let cpu_only = NodeResourceSnapshot::new(
            "headless-node".to_string(),
            "headless-node".to_string(),
            12.5,
            4_096,
            16_384,
            None,
            None,
            1_700_000_000,
        );
        let encoded = encode_snapshot_gossip_payload(&cpu_only).unwrap();
        let decoded = decode_snapshot_gossip_payload(&encoded).unwrap();
        assert_eq!(
            decoded.vram_used_mb, None,
            "CPU-only: vram_used_mb must stay None"
        );
        assert_eq!(
            decoded.vram_total_mb, None,
            "CPU-only: vram_total_mb must stay None"
        );
        assert_eq!(decoded.ram_total_mb, 16_384);
    }
}
