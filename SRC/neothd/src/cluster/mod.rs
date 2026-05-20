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
}
