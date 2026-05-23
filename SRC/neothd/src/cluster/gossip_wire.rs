//! Cluster Phase 6 — gossip wire protocol primitives.
//!
//! Builds on the policy primitives shipped earlier this session
//! (`cluster::gossip` — GossipTag, GossipPolicy, ReplayBudget) with
//! the **frame envelope + vector-clock ordering** the cross-peer
//! WAL replication needs.
//!
//! v0.1 scope = **VectorClock + GossipFrame types + ordering
//! primitives + tests**. The actual transport (Hysteria relay or
//! direct peer connection) + the JSONL append-stream + the
//! BudgetToken Raft consensus ship in multi-week follow-ups per
//! `PLAN/SPEC_cluster_phase6_gossip_state_sync_2026-05-22.md`.
//!
//! ## Vector clocks — what + why
//!
//! Per Lamport 1978 — each peer holds a map of peer-id → logical
//! counter. The map captures "I know peer X has issued ≥ N events
//! that I've seen". On send, the origin attaches its current VC;
//! on receive, the recipient `merge()`s VCs by element-wise max
//! then increments its own slot.
//!
//! Compare two VCs:
//!   - `VC1 ≤ VC2` ⇔ ∀peer: VC1[peer] ≤ VC2[peer]
//!   - `VC1 < VC2` ⇔ VC1 ≤ VC2 AND ∃peer: VC1[peer] < VC2[peer]
//!   - `VC1 || VC2` (concurrent) ⇔ NOT(VC1 ≤ VC2) AND NOT(VC2 ≤ VC1)
//!
//! Concurrent events surface as **conflicts** the receiver
//! application-layer resolver (CRDT-style merge, last-writer-wins,
//! operator manual reconcile) handles. The wire layer just
//! reports the relation honestly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::gossip::GossipTag;

/// Stable peer identifier used as the VC key. v0.1 uses the
/// `peer_pub_key_hex` (64-char lowercase) — same shape as
/// `cluster::registry::PairedPeer::pub_key_hex`. Newtype keeps the
/// VC API typesafe so peer_id strings don't get accidentally swapped
/// for cluster_key strings (different namespace).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One peer's logical-time view of the cluster. BTreeMap so serde
/// + compare iterate in deterministic order — important for the
/// reproducible event-hash gossip uses to dedupe replays.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct VectorClock {
    pub clocks: BTreeMap<PeerId, u64>,
}

/// Strict ordering relation between two vector clocks. Captures
/// the three mutually-exclusive cases the gossip receiver branches
/// on per Lamport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcOrdering {
    /// `lhs < rhs` — lhs happened-before rhs.
    Before,
    /// `lhs == rhs` — every counter equal; same logical time.
    Equal,
    /// `lhs > rhs` — rhs happened-before lhs.
    After,
    /// Neither dominates — concurrent events. Conflict resolution
    /// is the receiver's responsibility (CRDT merge, LWW, manual).
    Concurrent,
}

impl VectorClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment THIS peer's counter — call on every local event
    /// before attaching the VC to an outgoing GossipFrame.
    pub fn tick(&mut self, self_id: &PeerId) {
        *self.clocks.entry(self_id.clone()).or_insert(0) += 1;
    }

    /// Merge another VC into self by element-wise max. Used on
    /// receive: recipient sees the sender's view + updates its own.
    /// Returns the number of slots that changed (operator-visible
    /// "gossip absorbed N updates" metric).
    pub fn merge(&mut self, other: &VectorClock) -> usize {
        let mut changed = 0;
        for (peer, &other_n) in &other.clocks {
            let own = self.clocks.entry(peer.clone()).or_insert(0);
            if other_n > *own {
                *own = other_n;
                changed += 1;
            }
        }
        changed
    }

    /// Read this peer's slot — 0 when the peer is unknown to us.
    pub fn get(&self, peer: &PeerId) -> u64 {
        self.clocks.get(peer).copied().unwrap_or(0)
    }

    /// Lamport ordering. See module doc — Before/After/Equal/Concurrent.
    pub fn compare(&self, other: &VectorClock) -> VcOrdering {
        // Walk the union of peer-ids; missing keys count as 0.
        let mut lhs_dominates_any = false;
        let mut rhs_dominates_any = false;
        let mut peers: std::collections::BTreeSet<&PeerId> = std::collections::BTreeSet::new();
        peers.extend(self.clocks.keys());
        peers.extend(other.clocks.keys());
        for peer in peers {
            let l = self.get(peer);
            let r = other.get(peer);
            if l > r {
                lhs_dominates_any = true;
            } else if r > l {
                rhs_dominates_any = true;
            }
            if lhs_dominates_any && rhs_dominates_any {
                return VcOrdering::Concurrent;
            }
        }
        match (lhs_dominates_any, rhs_dominates_any) {
            (false, false) => VcOrdering::Equal,
            (true, false) => VcOrdering::After,
            (false, true) => VcOrdering::Before,
            (true, true) => VcOrdering::Concurrent, // unreachable per early-return but exhaustive
        }
    }
}

/// One gossip envelope ready for the wire. `payload` is the opaque
/// WAL frame bytes — the gossip layer treats it as a blob and
/// passes responsibility for parse/apply to the receiver's WAL
/// indexer.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GossipFrame {
    /// Sender's logical-time view at emit. Recipient merges this
    /// into its own VC before applying the payload (or before
    /// deferring on concurrent / older-than-budget conflicts).
    pub vector_clock: VectorClock,
    /// Which peer emitted this frame. Stable identity tied to the
    /// cluster registry (`PairedPeer::pub_key_hex`).
    pub origin: PeerId,
    /// Origin's logical sequence — monotonic per-peer, used by the
    /// dedup table to drop replays without re-applying the payload.
    pub event_seq: u64,
    /// Unix-epoch seconds at emit. Used for the
    /// `cluster::gossip::ReplayBudget` window check.
    pub timestamp_unix: i64,
    /// Operator-flagged opt-out tag. `DoNotGossip` frames MUST NOT
    /// reach this point — the emitter side drops them BEFORE
    /// wrapping. Carried here for receiver-side defence-in-depth
    /// (if a buggy emitter leaks a tagged frame, the receiver
    /// drops it on inspection).
    pub tag: GossipTag,
    /// Opaque WAL frame bytes. Receiver's WAL indexer parses +
    /// applies + sources the event_id back to `origin / event_seq`
    /// for audit.
    pub payload: Vec<u8>,
}

impl GossipFrame {
    /// Predicate the receiver runs before merging the VC + applying
    /// the payload. Composes three checks:
    ///   1. Tag is replicable (defence — emitter should have dropped
    ///      DoNotGossip frames upstream)
    ///   2. Inside the operator's ReplayBudget window
    ///   3. Not a duplicate (origin / event_seq already in dedup map)
    ///
    /// Returns the typed `GossipAcceptance` so the caller can log
    /// the specific reason a frame was dropped (operator-visible
    /// "dropped N gossip frames: window-exceeded=3, duplicate=1").
    pub fn evaluate_acceptance(
        &self,
        budget: &super::gossip::ReplayBudget,
        now_ts_unix: i64,
        last_seen_seq: Option<u64>,
    ) -> GossipAcceptance {
        if !self.tag.is_replicable() {
            return GossipAcceptance::DroppedDoNotGossipTag;
        }
        if !budget.is_within_budget(self.timestamp_unix, now_ts_unix) {
            return GossipAcceptance::DroppedOutsideReplayBudget;
        }
        if let Some(last) = last_seen_seq {
            if self.event_seq <= last {
                return GossipAcceptance::DroppedDuplicate {
                    last_seen_seq: last,
                };
            }
        }
        GossipAcceptance::Accept
    }
}

/// Receiver-side decision per inbound `GossipFrame`. Operator
/// surfaces the counts in `neoth doctor cluster gossip`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipAcceptance {
    /// Apply the payload + merge the VC.
    Accept,
    /// `GossipTag::DoNotGossip` should never reach the receiver —
    /// defence-in-depth drop, log at warn.
    DroppedDoNotGossipTag,
    /// Timestamp older than the operator's `ReplayBudget` window.
    /// Receiver may ask the origin to re-pair fresh.
    DroppedOutsideReplayBudget,
    /// Already applied (event_seq ≤ last seen for this origin).
    DroppedDuplicate { last_seen_seq: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::gossip::{GossipPolicy, ReplayBudget};

    fn pid(s: &str) -> PeerId {
        PeerId::new(s)
    }

    fn vc(pairs: &[(&str, u64)]) -> VectorClock {
        let mut clocks = BTreeMap::new();
        for (p, n) in pairs {
            clocks.insert(pid(p), *n);
        }
        VectorClock { clocks }
    }

    // ── VectorClock primitives ──────────────────────────────────────

    #[test]
    fn vc_default_is_empty() {
        let v = VectorClock::default();
        assert!(v.clocks.is_empty());
        assert_eq!(v.get(&pid("alex-laptop")), 0);
    }

    #[test]
    fn vc_tick_increments_only_self_slot() {
        let mut v = VectorClock::new();
        let self_id = pid("alex-laptop");
        v.tick(&self_id);
        v.tick(&self_id);
        v.tick(&self_id);
        assert_eq!(v.get(&self_id), 3);
        assert_eq!(v.get(&pid("alex-phone")), 0, "other slots untouched");
    }

    #[test]
    fn vc_merge_takes_elementwise_max() {
        let mut local = vc(&[("alex-laptop", 5), ("alex-phone", 2)]);
        let remote = vc(&[("alex-laptop", 3), ("alex-phone", 7), ("home-server", 1)]);
        let changed = local.merge(&remote);
        assert_eq!(changed, 2, "phone bumped from 2→7, home-server 0→1");
        assert_eq!(local.get(&pid("alex-laptop")), 5, "stayed at 5 (higher)");
        assert_eq!(local.get(&pid("alex-phone")), 7);
        assert_eq!(local.get(&pid("home-server")), 1);
    }

    #[test]
    fn vc_merge_with_subset_returns_zero_changed() {
        let mut local = vc(&[("a", 5), ("b", 5)]);
        let remote = vc(&[("a", 3), ("b", 4)]);
        assert_eq!(local.merge(&remote), 0);
    }

    #[test]
    fn vc_compare_equal_clocks() {
        assert_eq!(vc(&[("a", 1)]).compare(&vc(&[("a", 1)])), VcOrdering::Equal);
        assert_eq!(
            VectorClock::new().compare(&VectorClock::new()),
            VcOrdering::Equal
        );
    }

    #[test]
    fn vc_compare_before_when_lhs_strictly_smaller() {
        let lhs = vc(&[("a", 1), ("b", 2)]);
        let rhs = vc(&[("a", 1), ("b", 3)]);
        assert_eq!(lhs.compare(&rhs), VcOrdering::Before);
    }

    #[test]
    fn vc_compare_after_when_lhs_strictly_larger() {
        let lhs = vc(&[("a", 5), ("b", 7)]);
        let rhs = vc(&[("a", 5), ("b", 6)]);
        assert_eq!(lhs.compare(&rhs), VcOrdering::After);
    }

    #[test]
    fn vc_compare_concurrent_on_conflicting_slots() {
        // a: lhs ahead; b: rhs ahead — neither dominates.
        let lhs = vc(&[("a", 3), ("b", 1)]);
        let rhs = vc(&[("a", 2), ("b", 4)]);
        assert_eq!(lhs.compare(&rhs), VcOrdering::Concurrent);
        assert_eq!(rhs.compare(&lhs), VcOrdering::Concurrent);
    }

    #[test]
    fn vc_compare_treats_missing_keys_as_zero() {
        // lhs has slot for `a`; rhs is empty.
        let lhs = vc(&[("a", 1)]);
        let rhs = VectorClock::new();
        assert_eq!(lhs.compare(&rhs), VcOrdering::After);
        assert_eq!(rhs.compare(&lhs), VcOrdering::Before);
    }

    // ── GossipFrame acceptance ──────────────────────────────────────

    fn fixture_frame(seq: u64, ts: i64, tag: GossipTag) -> GossipFrame {
        GossipFrame {
            vector_clock: vc(&[("alex-laptop", seq)]),
            origin: pid("alex-laptop"),
            event_seq: seq,
            timestamp_unix: ts,
            tag,
            payload: vec![0x01, 0x02, 0x03],
        }
    }

    #[test]
    fn frame_accepts_replicable_within_budget_no_dup() {
        let policy = GossipPolicy::default();
        let budget = ReplayBudget::from_policy(&policy);
        let now = 100_000_i64;
        let f = fixture_frame(5, now - 60, GossipTag::Replicate);
        assert_eq!(
            f.evaluate_acceptance(&budget, now, None),
            GossipAcceptance::Accept
        );
    }

    #[test]
    fn frame_drops_do_not_gossip_tag_via_defence_in_depth() {
        let policy = GossipPolicy::default();
        let budget = ReplayBudget::from_policy(&policy);
        let now = 100_000_i64;
        let f = fixture_frame(5, now, GossipTag::DoNotGossip);
        assert_eq!(
            f.evaluate_acceptance(&budget, now, None),
            GossipAcceptance::DroppedDoNotGossipTag
        );
    }

    #[test]
    fn frame_drops_outside_replay_budget() {
        let policy = GossipPolicy::default();
        let budget = ReplayBudget::from_policy(&policy);
        let now = 1_000_000_i64;
        // 31 days ago — outside the 30-day default window.
        let f = fixture_frame(5, now - 32 * 86_400, GossipTag::Replicate);
        assert_eq!(
            f.evaluate_acceptance(&budget, now, None),
            GossipAcceptance::DroppedOutsideReplayBudget
        );
    }

    #[test]
    fn frame_drops_duplicate_event_seq() {
        let policy = GossipPolicy::default();
        let budget = ReplayBudget::from_policy(&policy);
        let now = 100_000_i64;
        let f = fixture_frame(5, now, GossipTag::Replicate);
        // Receiver has already applied event_seq 5 for this origin.
        assert_eq!(
            f.evaluate_acceptance(&budget, now, Some(5)),
            GossipAcceptance::DroppedDuplicate { last_seen_seq: 5 }
        );
        // event_seq < last → also duplicate (out-of-order replay).
        let older = fixture_frame(3, now, GossipTag::Replicate);
        assert_eq!(
            older.evaluate_acceptance(&budget, now, Some(5)),
            GossipAcceptance::DroppedDuplicate { last_seen_seq: 5 }
        );
    }

    #[test]
    fn frame_accepts_next_seq_after_last_seen() {
        let policy = GossipPolicy::default();
        let budget = ReplayBudget::from_policy(&policy);
        let now = 100_000_i64;
        // Receiver has applied 5; this is 6 — fresh.
        let f = fixture_frame(6, now, GossipTag::Replicate);
        assert_eq!(
            f.evaluate_acceptance(&budget, now, Some(5)),
            GossipAcceptance::Accept
        );
    }

    #[test]
    fn frame_serde_round_trip_via_json() {
        let f = fixture_frame(42, 1_700_000_000, GossipTag::Replicate);
        let json = serde_json::to_string(&f).unwrap();
        let back: GossipFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn vc_serde_round_trip_via_json() {
        let v = vc(&[("alex-laptop", 12), ("home-server", 7)]);
        let json = serde_json::to_string(&v).unwrap();
        let back: VectorClock = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn peer_id_transparent_serde_form() {
        let p = pid("alex-laptop");
        let json = serde_json::to_string(&p).unwrap();
        // #[serde(transparent)] → just a string, no wrapper object.
        assert_eq!(json, "\"alex-laptop\"");
    }
}
