//! Cluster C-3 (Session 21, 2026-05-23) — peer-aware request routing
//! for the Pears-transport cluster.
//!
//! Sits between the daemon's request handler + the per-peer
//! [`super::pears_peer_discovery::PearsPeerDiscovery`]. Given a request
//! + the current peer set, decides which peer fields it.
//!
//! ## Policy
//!
//! Today: "send to orchestrator" — the elected node ([`super::pears_election`])
//! handles every cluster-routed request. This is the simplest correct
//! policy + matches the Phase 5 architect verdict on small-cluster
//! orchestration. Future work (load-aware routing, capability-filter
//! routing) lands as additional `RoutingPolicy` variants without
//! breaking the trait shape.
//!
//! ## Status
//!
//! Unit-tested but UNTESTED against a live `pear` runtime — the
//! transport that delivers `route_to_peer` results into a remote peer's
//! request handler is the same K-3.5 / K-2b round-trip the federation
//! module is gated on. The routing logic itself is independent of
//! transport (the decision pins to deterministic policy + the
//! transport just ships the bytes) so the unit tests pin the
//! invariants regardless of `pear` availability.

use std::collections::BTreeSet;

use super::pears_election::{Election, PeerPubkey};

/// Policy describing which peer fields a routed request. Today the
/// only variant is `SendToOrchestrator`; future variants extend the
/// router without re-shaping the trait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingPolicy {
    /// Default: every cluster-routed request goes to the elected
    /// orchestrator. Matches the v0.1 architect verdict on
    /// small-cluster operation.
    SendToOrchestrator,
    /// Reserved for v0.2: route to lowest-load peer with the
    /// requested capability. Today panics if hit — callers MUST
    /// pin `SendToOrchestrator` for now (the variant is included so
    /// the policy enum surfaces what's coming).
    #[doc(hidden)]
    SendToLowestLoadPeerWithCapability,
}

/// Decision shape — which peer handles the request + why. `None`
/// orchestrator means the local node fields it (solo cluster or local
/// is the elected orchestrator).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingDecision {
    pub target: RoutingTarget,
    pub reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingTarget {
    /// Local node handles the request — no remote ship needed.
    /// Fired when the local pubkey is the elected orchestrator OR
    /// when no peers are connected (solo cluster).
    Local,
    /// Ship to a remote peer. The transport layer is expected to
    /// use this pubkey to look up the per-peer Pears subscribe topic
    /// + post the request body there.
    Remote(PeerPubkey),
}

/// Route a single request given the policy + current election. Pure
/// function — fully unit-testable, no I/O.
///
/// The actual request bytes aren't a parameter: the routing decision
/// depends only on the current cluster topology + the requested
/// capability (future). Callers compose:
///
/// ```ignore
/// let election = discovery.sweep_and_elect(now).await.1;
/// let decision = route(RoutingPolicy::SendToOrchestrator, &election);
/// match decision.target {
///     RoutingTarget::Local => handle_local(request),
///     RoutingTarget::Remote(pk) => ship_to_peer(pk, request).await?,
/// }
/// ```
pub fn route(policy: RoutingPolicy, election: &Election) -> RoutingDecision {
    match policy {
        RoutingPolicy::SendToOrchestrator => {
            match (&election.orchestrator, election.local_is_orchestrator) {
                (Some(pk), false) => RoutingDecision {
                    target: RoutingTarget::Remote(pk.clone()),
                    reason: "elected orchestrator is a remote peer",
                },
                (Some(_), true) => RoutingDecision {
                    target: RoutingTarget::Local,
                    reason: "local node is the elected orchestrator",
                },
                (None, _) => RoutingDecision {
                    target: RoutingTarget::Local,
                    reason: "no peers in cluster; local handles request",
                },
            }
        }
        RoutingPolicy::SendToLowestLoadPeerWithCapability => RoutingDecision {
            target: RoutingTarget::Local,
            reason: "policy reserved for v0.2 — falling back to local",
        },
    }
}

/// Convenience: compute the routing decision directly from a peer set
/// + local pubkey, running the election inline. Useful for callers
/// that don't already have an `Election` handy.
pub fn route_from_peer_set(
    policy: RoutingPolicy,
    peer_set: &BTreeSet<PeerPubkey>,
    local_pubkey: &PeerPubkey,
) -> RoutingDecision {
    let election = super::pears_election::elect_orchestrator(peer_set, local_pubkey);
    route(policy, &election)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(s: &str) -> PeerPubkey {
        PeerPubkey(s.into())
    }

    fn set_of(ks: &[&str]) -> BTreeSet<PeerPubkey> {
        ks.iter().map(|s| pk(s)).collect()
    }

    #[test]
    fn solo_cluster_routes_local() {
        // Single node = local handles every request.
        let set = set_of(&["ada"]);
        let d = route_from_peer_set(RoutingPolicy::SendToOrchestrator, &set, &pk("ada"));
        assert_eq!(d.target, RoutingTarget::Local);
        assert!(d.reason.contains("orchestrator"));
    }

    #[test]
    fn empty_cluster_routes_local() {
        // Defensive: if the registry is somehow empty (transport just
        // came up, no peers yet), default to local handling.
        let set: BTreeSet<PeerPubkey> = BTreeSet::new();
        let d = route_from_peer_set(RoutingPolicy::SendToOrchestrator, &set, &pk("ada"));
        assert_eq!(d.target, RoutingTarget::Local);
        assert!(d.reason.contains("no peers"));
    }

    #[test]
    fn local_orchestrator_routes_local() {
        // ada is lexicographically lowest → orchestrator → local
        // routes to itself.
        let set = set_of(&["ada", "bob", "carol"]);
        let d = route_from_peer_set(RoutingPolicy::SendToOrchestrator, &set, &pk("ada"));
        assert_eq!(d.target, RoutingTarget::Local);
        assert!(d.reason.contains("local node is the elected orchestrator"));
    }

    #[test]
    fn remote_orchestrator_routes_to_that_peer() {
        // bob is local; ada (lower pubkey) is orchestrator → bob
        // routes to ada.
        let set = set_of(&["ada", "bob", "carol"]);
        let d = route_from_peer_set(RoutingPolicy::SendToOrchestrator, &set, &pk("bob"));
        assert_eq!(d.target, RoutingTarget::Remote(pk("ada")));
    }

    #[test]
    fn routing_decision_carries_human_readable_reason() {
        // Every variant carries a non-empty `reason` so operator logs
        // can say "routed to X because Y" without callers fabricating
        // the explanation.
        for policy in [
            RoutingPolicy::SendToOrchestrator,
            RoutingPolicy::SendToLowestLoadPeerWithCapability,
        ] {
            let set = set_of(&["ada"]);
            let d = route_from_peer_set(policy, &set, &pk("ada"));
            assert!(!d.reason.is_empty(), "policy {policy:?} reason empty");
        }
    }

    #[test]
    fn v02_policy_falls_back_to_local_today() {
        // Forward-compat pin: the v0.2 variant is shipped as a hidden
        // enum member so the type sees what's coming. Today it MUST
        // fall back to local rather than panic — the unit test catches
        // a future implementation that accidentally panics or returns
        // a wrong-shape decision.
        let set = set_of(&["ada", "bob"]);
        let d = route(
            RoutingPolicy::SendToLowestLoadPeerWithCapability,
            &super::super::pears_election::elect_orchestrator(&set, &pk("bob")),
        );
        assert_eq!(d.target, RoutingTarget::Local);
        assert!(d.reason.contains("v0.2"));
    }

    #[test]
    fn route_is_deterministic_for_identical_inputs() {
        // Routing decisions MUST be reproducible — two nodes with the
        // same peer-set view + local pubkey must compute the same
        // RoutingDecision. Pinned so a future refactor that
        // accidentally introduces RNG / time-based tiebreaks trips
        // here at unit-test time.
        let set = set_of(&["ada", "bob", "carol"]);
        let a = route_from_peer_set(RoutingPolicy::SendToOrchestrator, &set, &pk("bob"));
        let b = route_from_peer_set(RoutingPolicy::SendToOrchestrator, &set, &pk("bob"));
        assert_eq!(a, b);
    }
}
