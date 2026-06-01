//! Cluster mode scaffold — R-7 (Borg-style multi-node coordination).
//!
//! Per `memory/neoth-arch-v2.md` Phase 19 / R-7, NEOTH will eventually run
//! across multiple operator hosts that share:
//!   - **Peer discovery** via a Hyperswarm topic derived from a shared
//!     cluster secret in `freedom.yaml`.
//!   - **WAL federation**: read-side Hypercore replication of remote
//!     peers' WAL so `idx_episode` learns about events from siblings.
//!   - **Provider routing**: an orchestrator maintains a load table
//!     (rolling token/sec per peer) and dispatches each request to the
//!     peer with the most idle headroom.
//!   - **Election**: default orchestrator is "the instance the operator
//!     interacts with most" (channel ingress count in last 24h). Manual
//!     override via `cluster_roles` table.
//!
//! v0.1.x scope: types + dispatcher trait + stubs. Hyperswarm transport
//! is multi-week (shares the R-A1 research note with Keet). What ships
//! now is the orchestrator shape so future implementations slot in
//! without re-designing the data model.

use std::time::Instant;

use serde::{Deserialize, Serialize};

/// R-7 Session 19 (2026-05-21): peeroxide-backed Hyperswarm
/// discovery wire. Brings up a swarm, joins a topic, accepts
/// peer connections. Heartbeat exchange + registry write
/// land in the protocol-design follow-up.
pub mod hyperswarm;

/// Cluster auto-discovery primitives (Phase 1) — `cluster_key`
/// derivation + HMAC-authenticated announce packets used by the
/// future mDNS / Tailscale / Hysteria-relay discovery surfaces.
/// SPEC: `PLAN/SPEC_cluster_auto_discovery_2026-05-22.md`.
pub mod discovery;
pub mod identity;
pub mod peer_auth;

/// Phase 4 persisted peer registry — `~/.neoth/cluster.yaml`.
/// `neoth cluster confirm <pub_key>` writes here; `revoke` removes;
/// Phase 6 gossip refreshes `last_seen_unix` on each authenticated
/// announce.
pub mod registry;

/// Phase 2 mDNS announcer + listener — `_neoth._udp.local.`
/// service, cross-platform via `mdns-sd` crate. Identity surface
/// (`MdnsIdentity`) carries the pre-signed authenticator so this
/// module doesn't touch secret-key material itself.
pub mod mdns;

/// Phase 3 Tailscale magic-DNS peer enumeration via
/// `tailscale status --json` shell-out. Soft-fails when the
/// Tailscale CLI isn't on PATH so operators not on a tailnet
/// pay zero cost.
pub mod tailscale;

/// Q2-ratified `announce_on_untrusted_wifi: false` policy + SSID
/// allowlist. Decides whether the Phase 2 mDNS announcer should
/// run on the current network.
pub mod policy;

/// CLI ↔ daemon audit-frame bridge. `neoth cluster confirm` /
/// `revoke` drop sidecar JSONs that the serve loop ingests +
/// emits as WAL 0xE6 / 0xE7 frames on next tick.
pub mod audit_sidecar;

/// R-7 heartbeat wire protocol — per Chorus chat
/// `019E4A48975F25C0BD9F8B96BC085C94`. CBOR frames, u32 LE
/// length-prefix, 5s ± 20% jittered cadence, protocol-version
/// handshake on connect. Connection-loop integration into
/// hyperswarm::spawn_discovery lands as a follow-up.
pub mod heartbeat;

/// Phase 6 gossip state-sync primitives — `GossipTag` (per-event
/// do_not_gossip opt-out), `GossipPolicy` (replicate_raw_ingress +
/// replay_budget_days), `ReplayBudget` resolved view. Wire protocol
/// (vector-clock gossip + JSONL append-stream) lands in follow-ups
/// per `PLAN/SPEC_cluster_phase6_gossip_state_sync_2026-05-22.md`.
pub mod gossip;

/// Phase 6 wire protocol primitives — VectorClock (Lamport 1978),
/// GossipFrame envelope, GossipAcceptance receiver-side decision
/// composing the existing GossipTag + ReplayBudget + per-origin
/// dedup. Real transport (Hysteria relay or direct peer connection)
/// + JSONL append-stream + BudgetToken Raft consensus land in
/// multi-week follow-ups per
/// `PLAN/SPEC_cluster_phase6_gossip_state_sync_2026-05-22.md`.
pub mod gossip_wire;

/// Phase 5 Hysteria-shared relay registration primitives — operator-
/// configured `RelayConfig` (endpoint + 5-peer-per-key cap),
/// `RelayRegistration` wire shape, `PeerRoster` in-memory store with
/// register / refresh / unregister / prune_stale. The standalone
/// `neoth-relay` daemon + the Hysteria-side socket plumbing land in
/// multi-week follow-ups per
/// `PLAN/SPEC_cluster_phase5_hysteria_relay_2026-05-22.md`.
pub mod relay;

/// C-5 (Session 21) — typed payload shapes for cluster lifecycle
/// WAL events `EVENT_TYPE_CLUSTER_ROLE_CHANGED` (0xE8) +
/// `EVENT_TYPE_CLUSTER_REQUEST_FORWARDED` (0xE9). Pure-fn surface;
/// transport wiring (C-1..C-4) is gated on the K-1 Hyperswarm
/// path decision.
pub mod wal_payloads;

// ── Cluster C-1..C-4 (Session 21, 2026-05-23) — Pears transport ──────
//
// Agent panel verdict on D-101 picked the Pears HTTP bridge as the
// shared transport for both Keet messaging + cluster operations. The
// four C-* modules below are the cluster-side counterparts of
// channels::pears_bridge:
//
//   C-1  pears_peer_discovery — peer announce/lookup over cluster topic
//        (adopts openclaw bonjour watchdog state machine)
//   C-2  pears_federation     — WAL segment shipping trait (default
//        impl returns Deferred until live `pear` validation)
//   C-3  pears_routing        — request routing policy + decision shape
//   C-4  pears_election       — lowest-pubkey-wins orchestrator election
//
// All four are unit-tested but UNTESTED against a live `pear` runtime —
// the actual transport round-trip needs operator-side K-3.5 pairing
// validation first. Gated behind freedom.yaml::cluster.transport =
// "pears" (default "disabled"), with a one-shot operator warn on first
// enable explaining the live-test gap.
pub mod pears_election;
pub mod pears_federation;
pub mod pears_peer_discovery;
pub mod pears_routing;

/// Stable identifier for a peer in the cluster. Format = UUID v7 string.
/// First peer that brings a freshly-paired cluster online is the genesis;
/// every join writes its UUID into the local cluster_roles table.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Per-peer load reading. Drives `OrchestratingPolicy::pick_peer` so the
/// dispatcher can route to whoever has the most idle headroom right now.
#[derive(Clone, Debug)]
pub struct PeerLoad {
    pub peer: PeerId,
    /// Rolling tokens/sec the peer is currently chewing. Higher = busier.
    pub tokens_per_sec: f64,
    /// Last update timestamp. Stale loads (older than ~30s) demote the
    /// peer to "unknown" — better to send to a fresh idle peer than a
    /// silent one.
    pub last_observed: Instant,
    /// Whether the peer self-reported as healthy in its last heartbeat.
    pub healthy: bool,
}

/// What the orchestrator decided. Returned to the caller of
/// [`OrchestratingPolicy::pick_peer`] so the caller can either route or
/// fall back to local execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingDecision {
    Local,
    Remote(PeerId),
    /// No peer is healthy enough to take the request and the policy refuses
    /// local execution (e.g. operator pinned a workload to remote-only).
    /// The caller must surface this as an error to the operator.
    NoPeerAvailable,
}

/// Policy trait. v0.1.x scope provides `LocalOnly` (current behaviour:
/// always run locally) + `LeastLoaded` (route to the healthy peer with
/// the lowest `tokens_per_sec`). Operators pick the policy in
/// `freedom.yaml::cluster.policy`.
pub trait OrchestratingPolicy: Send + Sync {
    fn pick_peer(&self, peers: &[PeerLoad]) -> RoutingDecision;
}

/// Single-node mode. Every request stays local. Used until the operator
/// pairs a second node.
pub struct LocalOnly;

impl OrchestratingPolicy for LocalOnly {
    fn pick_peer(&self, _peers: &[PeerLoad]) -> RoutingDecision {
        RoutingDecision::Local
    }
}

/// Least-loaded routing. Picks the healthy peer with the lowest observed
/// tokens/sec. Falls back to `Local` when no healthy remote peer exists.
pub struct LeastLoaded {
    /// How stale a peer's `last_observed` may be before we ignore it.
    /// Default 30s.
    pub max_load_age: std::time::Duration,
}

impl Default for LeastLoaded {
    fn default() -> Self {
        Self {
            max_load_age: std::time::Duration::from_secs(30),
        }
    }
}

impl OrchestratingPolicy for LeastLoaded {
    fn pick_peer(&self, peers: &[PeerLoad]) -> RoutingDecision {
        let now = Instant::now();
        let fresh = peers
            .iter()
            .filter(|p| p.healthy && now.duration_since(p.last_observed) <= self.max_load_age);
        let best = fresh.min_by(|a, b| {
            a.tokens_per_sec
                .partial_cmp(&b.tokens_per_sec)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        match best {
            Some(p) => RoutingDecision::Remote(p.peer.clone()),
            None => RoutingDecision::Local,
        }
    }
}

/// Hyperswarm-backed peer discovery — stub for v0.1.x. Returns
/// `NoPeerAvailable` synchronously until the real transport lands.
#[derive(Debug)]
pub struct HyperswarmPeerRegistry;

impl HyperswarmPeerRegistry {
    pub fn join(_topic: &str) -> anyhow::Result<Self> {
        anyhow::bail!(
            "cluster: Hyperswarm peer discovery deferred. \
             Single-node operation is fully supported via LocalOnly policy."
        )
    }
}

/// R-7 (2026-05-21): in-memory peer-load registry with staleness
/// eviction. Holds the per-peer `PeerLoad` snapshot that routing
/// policies (`LeastLoaded`, future variants) consult.
///
/// Lifecycle: the daemon's heartbeat reader calls
/// `record_heartbeat(load)` on every inbound PEER_HEARTBEAT WAL
/// frame; the router calls `known_peers()` before deciding where
/// to fan out work. `prune_stale(now, max_age)` runs on a
/// background tick + drops peers we haven't heard from.
///
/// Single-threaded API today — wrap in `Arc<Mutex<…>>` at the
/// daemon-bootstrap layer once real Hyperswarm wire lands.
#[derive(Default, Debug)]
pub struct PeerLoadRegistry {
    peers: std::collections::HashMap<String, PeerLoad>,
}

impl PeerLoadRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or update) a peer's load snapshot. Existing entry is
    /// overwritten — last-write-wins semantics matching the daemon's
    /// heartbeat-reader pattern elsewhere.
    pub fn record_heartbeat(&mut self, load: PeerLoad) {
        self.peers.insert(load.peer.as_str().to_string(), load);
    }

    /// Drop peers whose `last_observed` is older than `now - max_age`.
    /// Returns the number of peers evicted so callers can log.
    pub fn prune_stale(&mut self, now: Instant, max_age: std::time::Duration) -> usize {
        let before = self.peers.len();
        self.peers
            .retain(|_id, load| now.saturating_duration_since(load.last_observed) <= max_age);
        before - self.peers.len()
    }

    /// Snapshot of every still-tracked peer. The routing policies
    /// (`LeastLoaded::pick_peer`) accept this directly.
    pub fn known_peers(&self) -> Vec<PeerLoad> {
        self.peers.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn local_only_always_routes_local() {
        let p = LocalOnly;
        assert_eq!(p.pick_peer(&[]), RoutingDecision::Local);
        let l = PeerLoad {
            peer: PeerId::new("p1"),
            tokens_per_sec: 0.0,
            last_observed: Instant::now(),
            healthy: true,
        };
        assert_eq!(p.pick_peer(&[l]), RoutingDecision::Local);
    }

    #[test]
    fn least_loaded_picks_lowest_tps_peer() {
        let now = Instant::now();
        let peers = vec![
            PeerLoad {
                peer: PeerId::new("busy"),
                tokens_per_sec: 100.0,
                last_observed: now,
                healthy: true,
            },
            PeerLoad {
                peer: PeerId::new("idle"),
                tokens_per_sec: 5.0,
                last_observed: now,
                healthy: true,
            },
            PeerLoad {
                peer: PeerId::new("medium"),
                tokens_per_sec: 30.0,
                last_observed: now,
                healthy: true,
            },
        ];
        let policy = LeastLoaded::default();
        assert_eq!(
            policy.pick_peer(&peers),
            RoutingDecision::Remote(PeerId::new("idle"))
        );
    }

    #[test]
    fn least_loaded_ignores_unhealthy_peers() {
        let now = Instant::now();
        let peers = vec![
            PeerLoad {
                peer: PeerId::new("zero"),
                tokens_per_sec: 0.0,
                last_observed: now,
                healthy: false,
            },
            PeerLoad {
                peer: PeerId::new("low"),
                tokens_per_sec: 10.0,
                last_observed: now,
                healthy: true,
            },
        ];
        let policy = LeastLoaded::default();
        assert_eq!(
            policy.pick_peer(&peers),
            RoutingDecision::Remote(PeerId::new("low")),
        );
    }

    #[test]
    fn least_loaded_ignores_stale_observations() {
        let stale = Instant::now() - Duration::from_secs(60);
        let fresh = Instant::now();
        let peers = vec![
            PeerLoad {
                peer: PeerId::new("stale-idle"),
                tokens_per_sec: 0.0,
                last_observed: stale,
                healthy: true,
            },
            PeerLoad {
                peer: PeerId::new("fresh-medium"),
                tokens_per_sec: 50.0,
                last_observed: fresh,
                healthy: true,
            },
        ];
        let policy = LeastLoaded {
            max_load_age: Duration::from_secs(30),
        };
        assert_eq!(
            policy.pick_peer(&peers),
            RoutingDecision::Remote(PeerId::new("fresh-medium")),
        );
    }

    #[test]
    fn least_loaded_falls_back_to_local_when_no_healthy_peer() {
        let policy = LeastLoaded::default();
        assert_eq!(policy.pick_peer(&[]), RoutingDecision::Local);
    }

    #[test]
    fn hyperswarm_join_bails_in_v0_1() {
        let r = HyperswarmPeerRegistry::join("test-topic");
        assert!(r.is_err());
        let msg = format!("{}", r.unwrap_err());
        assert!(msg.contains("deferred"));
    }

    // ── R-7 PeerLoadRegistry ─────────────────────────────────────────

    fn load_at(peer: &str, tps: f64, when: Instant) -> PeerLoad {
        PeerLoad {
            peer: PeerId::new(peer),
            tokens_per_sec: tps,
            last_observed: when,
            healthy: true,
        }
    }

    #[test]
    fn registry_starts_empty() {
        let r = PeerLoadRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.known_peers().is_empty());
    }

    #[test]
    fn registry_records_and_overwrites_per_peer() {
        let mut r = PeerLoadRegistry::new();
        let now = Instant::now();
        r.record_heartbeat(load_at("alpha", 10.0, now));
        r.record_heartbeat(load_at("alpha", 20.0, now));
        assert_eq!(r.len(), 1, "second heartbeat for same peer overwrites");
        let p = r.known_peers();
        assert_eq!(p[0].tokens_per_sec, 20.0);
    }

    #[test]
    fn registry_prune_stale_evicts_old_entries() {
        let mut r = PeerLoadRegistry::new();
        let old = Instant::now() - Duration::from_secs(120);
        let fresh = Instant::now();
        r.record_heartbeat(load_at("old", 5.0, old));
        r.record_heartbeat(load_at("fresh", 5.0, fresh));
        let evicted = r.prune_stale(Instant::now(), Duration::from_secs(60));
        assert_eq!(evicted, 1, "exactly one stale peer dropped");
        assert_eq!(r.len(), 1);
        assert_eq!(r.known_peers()[0].peer.as_str(), "fresh");
    }

    #[test]
    fn registry_prune_keeps_everyone_when_max_age_huge() {
        let mut r = PeerLoadRegistry::new();
        let now = Instant::now();
        r.record_heartbeat(load_at("a", 1.0, now));
        r.record_heartbeat(load_at("b", 1.0, now));
        let evicted = r.prune_stale(now, Duration::from_secs(10_000));
        assert_eq!(evicted, 0);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn registry_feeds_least_loaded_routing() {
        // Integration: the registry's snapshot is the shape
        // LeastLoaded::pick_peer expects. Pin that hookup.
        let mut r = PeerLoadRegistry::new();
        let now = Instant::now();
        r.record_heartbeat(load_at("busy", 100.0, now));
        r.record_heartbeat(load_at("idle", 5.0, now));
        let policy = LeastLoaded {
            max_load_age: Duration::from_secs(30),
        };
        let decision = policy.pick_peer(&r.known_peers());
        match decision {
            RoutingDecision::Remote(p) => assert_eq!(p.as_str(), "idle"),
            other => panic!("expected Remote(idle), got {other:?}"),
        }
    }
}
