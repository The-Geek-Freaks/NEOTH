//! Cluster C-4 (Session 21, 2026-05-23) — orchestrator election heuristic
//! for the Pears-transport cluster.
//!
//! Algorithm: lowest-pubkey wins. Deterministic, no quorum negotiation, no
//! timing dependence — every peer with the same view of the cluster reaches
//! the same orchestrator on the same tick. Re-election on PeerJoin /
//! PeerLeave events.
//!
//! Why not Raft / Paxos: solo-operator + small-cluster (1-5 nodes per the
//! Session 21 architect verdict on Phase 5). Full consensus protocols add
//! complexity that the operator's use case doesn't surface — the smartest
//! wins council already handles the actual decision-making, and the
//! orchestrator picked here is just "which peer fields the request first".
//! When the operator's cluster outgrows 5 nodes, swap this module for a
//! Raft impl without changing callers (the trait shape stays).
//!
//! Status: pure algorithm, fully unit-tested. The transport that feeds
//! peer-set updates into [`elect_orchestrator`] is [`super::pears_peer_discovery`],
//! which is gated behind `freedom.yaml::cluster.transport = "pears"` and
//! flagged UNTESTED against a live `pear` runtime until operator-side
//! K-3.5 pairing has been verified end-to-end. The election logic itself
//! does not depend on the transport — the same function picks an
//! orchestrator regardless of how the peer set arrived.
//!
//! ## QUELLEN provenance
//!
//! No direct port — the algorithm is too simple to warrant one. The
//! watchdog/restart pattern in [`super::pears_peer_discovery`] adopts ideas
//! from `QUELLEN/openclaw/extensions/bonjour/src/advertiser.ts` (state
//! tracking + restart-window debouncing), which is the discovery-layer
//! input to this election module.

use std::collections::BTreeSet;

/// Peer identifier in the cluster. Pears bridges hand out a hex
/// public-key string when a peer announces itself — that becomes the
/// `pubkey` field. Newtype wrapping so future swaps (binary key,
/// PeerId opaque type) don't require call-site rewrites.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerPubkey(pub String);

impl PeerPubkey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Election outcome: who fields cluster-wide requests this round.
/// `None` when the peer set is empty (the operator's own node is the
/// only one; no election needed — fallback to local). When the local
/// peer wins, callers handle as "I am the orchestrator this round".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Election {
    pub orchestrator: Option<PeerPubkey>,
    /// Total peers considered (including the local one). Surfaced
    /// so operator-facing logs can say "elected X out of N".
    pub peer_count: usize,
    /// `true` when the local peer won — saves callers an
    /// `orchestrator == local_pubkey` comparison.
    pub local_is_orchestrator: bool,
}

/// Lowest-pubkey-wins election. Deterministic + side-effect-free; every
/// peer in the cluster with the same `peer_set` view reaches the same
/// answer. `local_pubkey` MUST be a member of `peer_set` (the operator's
/// node announces itself on join); when it isn't, the function treats
/// the local node as absent (returns `local_is_orchestrator: false`).
///
/// Why lowest-pubkey: simplest stable rule + the pubkey is already the
/// per-peer identity the discovery layer surfaces. No tiebreaks needed
/// (pubkeys are unique by construction). No timing dependence — the
/// same vote arrives at the same answer on every node.
pub fn elect_orchestrator(peer_set: &BTreeSet<PeerPubkey>, local_pubkey: &PeerPubkey) -> Election {
    let orchestrator = peer_set.iter().next().cloned();
    let local_is_orchestrator = orchestrator.as_ref().is_some_and(|o| o == local_pubkey);
    Election {
        orchestrator,
        peer_count: peer_set.len(),
        local_is_orchestrator,
    }
}

/// Recompute the election from a peer-event stream. The discovery layer
/// (see [`super::pears_peer_discovery`]) emits `PeerEvent::Joined` /
/// `Left` as the live peer set changes; this folds the events into the
/// running set + returns the new election. Callers replay events to
/// rebuild state after a daemon restart.
pub fn apply_peer_event(
    set: &mut BTreeSet<PeerPubkey>,
    event: PeerEvent,
    local_pubkey: &PeerPubkey,
) -> Election {
    match event {
        PeerEvent::Joined(p) => {
            set.insert(p);
        }
        PeerEvent::Left(p) => {
            set.remove(&p);
        }
    }
    elect_orchestrator(set, local_pubkey)
}

/// Discovery-layer event surfaced into the election. Mirrors the WAL
/// `CLUSTER_PEER_CONNECTED` (0xE0) / `CLUSTER_PEER_DISCONNECTED` (0xE1)
/// frame shape so the same struct round-trips into audit storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEvent {
    Joined(PeerPubkey),
    Left(PeerPubkey),
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
    fn empty_peer_set_returns_none_orchestrator() {
        let set = BTreeSet::new();
        let e = elect_orchestrator(&set, &pk("ada"));
        assert!(e.orchestrator.is_none());
        assert_eq!(e.peer_count, 0);
        assert!(!e.local_is_orchestrator);
    }

    #[test]
    fn solo_peer_self_elects_as_orchestrator() {
        let set = set_of(&["ada"]);
        let e = elect_orchestrator(&set, &pk("ada"));
        assert_eq!(e.orchestrator.as_ref().map(|p| p.as_str()), Some("ada"));
        assert_eq!(e.peer_count, 1);
        assert!(e.local_is_orchestrator);
    }

    #[test]
    fn lowest_pubkey_wins_among_three_peers() {
        // a < b < c lexically; election picks `a` regardless of which
        // peer is the local one.
        let set = set_of(&["ada", "bob", "carol"]);
        let from_ada = elect_orchestrator(&set, &pk("ada"));
        let from_bob = elect_orchestrator(&set, &pk("bob"));
        let from_carol = elect_orchestrator(&set, &pk("carol"));
        assert_eq!(from_ada.orchestrator, from_bob.orchestrator);
        assert_eq!(from_bob.orchestrator, from_carol.orchestrator);
        assert_eq!(
            from_ada.orchestrator.as_ref().map(|p| p.as_str()),
            Some("ada")
        );
        assert!(from_ada.local_is_orchestrator);
        assert!(!from_bob.local_is_orchestrator);
        assert!(!from_carol.local_is_orchestrator);
    }

    #[test]
    fn election_is_deterministic_under_pubkey_insertion_order() {
        // BTreeSet auto-sorts; the algorithm doesn't depend on
        // insertion order. Pin this so a future refactor that swaps
        // BTreeSet → HashSet (loses ordering) trips the test instead
        // of silently introducing non-determinism in elections.
        let mut a: BTreeSet<PeerPubkey> = BTreeSet::new();
        a.insert(pk("z_last"));
        a.insert(pk("a_first"));
        a.insert(pk("m_middle"));
        let mut b: BTreeSet<PeerPubkey> = BTreeSet::new();
        b.insert(pk("a_first"));
        b.insert(pk("m_middle"));
        b.insert(pk("z_last"));
        assert_eq!(
            elect_orchestrator(&a, &pk("x")),
            elect_orchestrator(&b, &pk("x"))
        );
    }

    #[test]
    fn local_absent_from_peer_set_returns_false_local_flag() {
        // Defence-in-depth: if a caller forgets to register the local
        // node in the peer set, the election picks a remote
        // orchestrator + local_is_orchestrator stays false. No
        // accidental "I am orchestrator" claim from a stale local
        // pubkey.
        let set = set_of(&["bob", "carol"]);
        let e = elect_orchestrator(&set, &pk("ada"));
        assert_eq!(e.orchestrator.as_ref().map(|p| p.as_str()), Some("bob"));
        assert!(!e.local_is_orchestrator);
    }

    // ── apply_peer_event ────────────────────────────────────────────

    #[test]
    fn apply_joined_event_inserts_peer_and_returns_new_election() {
        let mut set = set_of(&["ada"]);
        let e = apply_peer_event(&mut set, PeerEvent::Joined(pk("bob")), &pk("ada"));
        assert!(set.contains(&pk("bob")));
        assert_eq!(e.peer_count, 2);
        // ada still wins (ada < bob lexically).
        assert_eq!(e.orchestrator.as_ref().map(|p| p.as_str()), Some("ada"));
    }

    #[test]
    fn apply_left_event_removes_peer_and_recomputes() {
        // ada leaves; bob now wins (lowest remaining).
        let mut set = set_of(&["ada", "bob"]);
        let e = apply_peer_event(&mut set, PeerEvent::Left(pk("ada")), &pk("bob"));
        assert!(!set.contains(&pk("ada")));
        assert_eq!(e.peer_count, 1);
        assert_eq!(e.orchestrator.as_ref().map(|p| p.as_str()), Some("bob"));
        assert!(e.local_is_orchestrator);
    }

    #[test]
    fn apply_join_then_left_returns_to_original_election() {
        // join + leave is the no-op contract — the election before is
        // the election after. Useful invariant for fault-recovery: a
        // peer that bounces (left + rejoined) should land us back in
        // the same state as before the bounce, not in some derived
        // half-state. Pinned here.
        let mut set = set_of(&["ada", "carol"]);
        let before = elect_orchestrator(&set, &pk("ada"));
        let _ = apply_peer_event(&mut set, PeerEvent::Joined(pk("bob")), &pk("ada"));
        let after = apply_peer_event(&mut set, PeerEvent::Left(pk("bob")), &pk("ada"));
        assert_eq!(before, after);
    }

    #[test]
    fn apply_left_on_missing_peer_is_silent_noop() {
        // A `Left` event for a peer the local node never saw must
        // not panic — the cluster transport can replay stale events
        // during reconnection; an idempotent remove is the right
        // semantic.
        let mut set = set_of(&["ada"]);
        let e = apply_peer_event(&mut set, PeerEvent::Left(pk("ghost")), &pk("ada"));
        assert_eq!(set.len(), 1);
        assert_eq!(e.peer_count, 1);
        assert!(e.local_is_orchestrator);
    }
}
