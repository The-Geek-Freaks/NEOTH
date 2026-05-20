// Hybrid Logical Clock -- SPEC_multinode_clock.md §2-3
// Kulkarni et al. 2014. 12 bytes on wire (u64 physical_ns LE + u32 logical LE).
// S9 fix: overflow returns Result, never panics.

use super::error::HlcError;
use super::types::NodeId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hlc {
    physical_ns: u64,
    logical: u32,
}

impl Hlc {
    pub const EPOCH: Hlc = Hlc {
        physical_ns: 0,
        logical: 0,
    };

    pub fn new(physical_ns: u64, logical: u32) -> Result<Self, HlcError> {
        if physical_ns == 0 && logical != 0 {
            return Err(HlcError::PostEpochLogicalWithoutPhysical(logical));
        }
        Ok(Hlc {
            physical_ns,
            logical,
        })
    }

    pub fn physical_ns(&self) -> u64 {
        self.physical_ns
    }

    pub fn logical(&self) -> u32 {
        self.logical
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.physical_ns
            .cmp(&other.physical_ns)
            .then(self.logical.cmp(&other.logical))
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// On local event generation. Updates `current` in-place.
/// Returns Err on logical-counter overflow; caller should emit
/// `0x2F CLOCK_LOGICAL_OVERFLOW` and abort the offending operation.
pub fn hlc_tick_local(current: &mut Hlc, now_ns: u64) -> Result<(), HlcError> {
    if now_ns > current.physical_ns {
        current.physical_ns = now_ns;
        current.logical = 0;
    } else {
        current.logical = current
            .logical
            .checked_add(1)
            .ok_or(HlcError::LogicalOverflow { peer_node_id: None })?;
    }
    Ok(())
}

/// On receiving a remote HLC (gossip / replication). Merges peer into local.
/// Per Kulkarni 2014: take max of physical, advance logical accordingly.
///
/// F-23: param order + non-optional `peer_node_id` aligned with
/// `SPEC_multinode_clock.md §3.3`. `hlc_tick_receive` is only ever
/// called with a known peer (gossip frames carry a node id), so the
/// previous `Option<NodeId>` always lived as `Some(_)` at call sites —
/// the spec-aligned `NodeId` makes that invariant unrepresentable in
/// the wrong shape. The error variant keeps `Option<NodeId>` because
/// `hlc_tick_local` (no peer involved) reuses the same overflow error.
pub fn hlc_tick_receive(
    current: &mut Hlc,
    now_ns: u64,
    peer_hlc: Hlc,
    peer_node_id: NodeId,
) -> Result<(), HlcError> {
    let max_phys = current.physical_ns.max(peer_hlc.physical_ns).max(now_ns);

    if max_phys == current.physical_ns && max_phys == peer_hlc.physical_ns {
        let next = current.logical.max(peer_hlc.logical);
        current.logical = next.checked_add(1).ok_or(HlcError::LogicalOverflow {
            peer_node_id: Some(peer_node_id),
        })?;
    } else if max_phys == current.physical_ns {
        current.logical = current
            .logical
            .checked_add(1)
            .ok_or(HlcError::LogicalOverflow {
                peer_node_id: Some(peer_node_id),
            })?;
    } else if max_phys == peer_hlc.physical_ns {
        current.physical_ns = peer_hlc.physical_ns;
        current.logical = peer_hlc
            .logical
            .checked_add(1)
            .ok_or(HlcError::LogicalOverflow {
                peer_node_id: Some(peer_node_id),
            })?;
    } else {
        current.physical_ns = max_phys;
        current.logical = 0;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_zero() {
        assert_eq!(Hlc::EPOCH.physical_ns(), 0);
        assert_eq!(Hlc::EPOCH.logical(), 0);
    }

    #[test]
    fn new_rejects_post_epoch_logical_without_physical() {
        let r = Hlc::new(0, 5);
        assert!(matches!(
            r,
            Err(HlcError::PostEpochLogicalWithoutPhysical(5))
        ));
    }

    #[test]
    fn tick_local_advances_physical_when_now_greater() {
        let mut h = Hlc::new(1000, 42).unwrap();
        hlc_tick_local(&mut h, 2000).unwrap();
        assert_eq!(h.physical_ns(), 2000);
        assert_eq!(h.logical(), 0);
    }

    #[test]
    fn tick_local_advances_logical_when_now_lower_or_equal() {
        let mut h = Hlc::new(2000, 5).unwrap();
        hlc_tick_local(&mut h, 1000).unwrap();
        assert_eq!(h.physical_ns(), 2000);
        assert_eq!(h.logical(), 6);
    }

    #[test]
    fn tick_local_overflow_returns_err() {
        let mut h = Hlc::new(2000, u32::MAX).unwrap();
        let r = hlc_tick_local(&mut h, 1000);
        assert!(matches!(
            r,
            Err(HlcError::LogicalOverflow { peer_node_id: None })
        ));
    }

    #[test]
    fn ordering_physical_then_logical() {
        let a = Hlc::new(1000, 0).unwrap();
        let b = Hlc::new(1000, 1).unwrap();
        let c = Hlc::new(2000, 0).unwrap();
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn receive_peer_overflow_records_node_id() {
        // F-23: new signature `(current, now_ns, peer_hlc, peer_node_id: NodeId)`.
        let mut local = Hlc::new(1000, 0).unwrap();
        let peer = Hlc::new(1000, u32::MAX).unwrap();
        let peer_node = NodeId::from_bytes([7u8; 16]);
        let r = hlc_tick_receive(&mut local, 500, peer, peer_node);
        match r {
            Err(HlcError::LogicalOverflow { peer_node_id }) => {
                // Error variant still carries Option for the local-tick reuse.
                assert_eq!(peer_node_id, Some(peer_node));
            }
            other => panic!("expected LogicalOverflow, got {other:?}"),
        }
    }

    #[test]
    fn receive_advances_physical_when_now_dominates() {
        // Spec §3.3 branch 1: now_ns > both local + peer → physical=now_ns,
        // logical=0. Tests the rewritten param order.
        let mut current = Hlc::new(1000, 5).unwrap();
        let peer = Hlc::new(500, 10).unwrap();
        let peer_node = NodeId::from_bytes([1u8; 16]);
        hlc_tick_receive(&mut current, 2000, peer, peer_node).unwrap();
        assert_eq!(current.physical_ns(), 2000);
        assert_eq!(current.logical(), 0);
    }

    #[test]
    fn receive_merges_logicals_when_physical_equal() {
        // Spec §3.3 branch 2: both at same physical → take max(logicals) + 1.
        let mut current = Hlc::new(1000, 5).unwrap();
        let peer = Hlc::new(1000, 8).unwrap();
        let peer_node = NodeId::from_bytes([2u8; 16]);
        hlc_tick_receive(&mut current, 999, peer, peer_node).unwrap();
        assert_eq!(current.physical_ns(), 1000);
        assert_eq!(current.logical(), 9); // max(5, 8) + 1
    }

    #[test]
    fn receive_advances_logical_when_local_dominates() {
        // Spec §3.3 branch 3: local physical > both → bump local logical.
        let mut current = Hlc::new(1000, 5).unwrap();
        let peer = Hlc::new(600, 100).unwrap();
        let peer_node = NodeId::from_bytes([3u8; 16]);
        hlc_tick_receive(&mut current, 800, peer, peer_node).unwrap();
        assert_eq!(current.physical_ns(), 1000);
        assert_eq!(current.logical(), 6);
    }

    #[test]
    fn receive_jumps_to_peer_physical_when_peer_dominates() {
        // Spec §3.3 branch 4: peer physical > both → take peer physical
        // + peer logical + 1.
        let mut current = Hlc::new(1000, 5).unwrap();
        let peer = Hlc::new(1500, 3).unwrap();
        let peer_node = NodeId::from_bytes([4u8; 16]);
        hlc_tick_receive(&mut current, 800, peer, peer_node).unwrap();
        assert_eq!(current.physical_ns(), 1500);
        assert_eq!(current.logical(), 4);
    }
}
