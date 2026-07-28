//! SL-00(1c) — outbound peer-stream registry.
//!
//! The per-peer connection task owns the only handle to its SecretStream, so
//! anything elsewhere in the daemon that wants to SEND a frame to a specific
//! peer (a `TaskResult` reply in SL-01, a gossip frame in SL-01b) cannot touch
//! the stream directly. Instead each connection task registers an outbound
//! `mpsc::Sender<WireFrame>` here, keyed by the peer's Noise static pubkey hex
//! (the authenticated identity — never a payload-supplied id). The connection
//! task `select!`s on that channel's receiver and writes whatever it receives.
//!
//! `send_to` is **fail-closed**: an unknown peer (never connected, or already
//! gone) returns `Err` rather than silently dropping — the caller decides
//! whether that is fatal. Sends are non-blocking (`try_send`); a full channel
//! (a wedged/slow peer) returns `Err` instead of blocking the caller, so one
//! bad peer can't stall the daemon.
//!
//! Locking: a `std::sync::Mutex` guards the map. The lock is held only for the
//! map lookup/clone of the `Sender` — `try_send` runs AFTER the guard drops, so
//! no lock is ever held across an await or a channel operation.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::heartbeat::WireFrame;
use super::membership::{AuthEpoch, MembershipEffectGuard, MembershipGrant, StableNodeId};

/// Bounded outbound queue per peer. Big enough to absorb a burst of replies /
/// gossip without backpressure on the sender, small enough that a wedged peer
/// is detected (via a full-channel `Err`) instead of buffering unboundedly.
pub const OUTBOUND_QUEUE_DEPTH: usize = 64;

/// Reason a directed send could not be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// No live connection to this peer (never paired, or disconnected).
    UnknownPeer,
    /// The peer's outbound queue is full — peer is wedged or far behind.
    QueueFull,
    /// The connection task's receiver is gone (race with disconnect).
    Closed,
    /// The retained membership generation is no longer authoritative.
    MembershipRevoked,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::UnknownPeer => f.write_str("no live connection to peer"),
            SendError::QueueFull => f.write_str("peer outbound queue full"),
            SendError::Closed => f.write_str("peer connection closing"),
            SendError::MembershipRevoked => {
                f.write_str("peer membership generation is no longer authoritative")
            }
        }
    }
}

impl std::error::Error for SendError {}

/// Registry of live outbound channels, keyed by peer Noise static pubkey hex.
#[derive(Clone)]
struct LiveSender {
    generation: u64,
    stable_node_id: Option<StableNodeId>,
    auth_epoch: Option<AuthEpoch>,
    membership_grant: Option<MembershipGrant>,
    sender: tokio::sync::mpsc::Sender<AuthorizedWireFrame>,
    cancel: tokio::sync::watch::Sender<bool>,
}

pub(crate) struct AuthorizedWireFrame {
    frame: WireFrame,
    effect_guard: Option<MembershipEffectGuard>,
}

impl AuthorizedWireFrame {
    pub(crate) fn effect_guard_mut(&mut self) -> Option<&mut MembershipEffectGuard> {
        self.effect_guard.as_mut()
    }
}

impl std::ops::Deref for AuthorizedWireFrame {
    type Target = WireFrame;

    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}

#[derive(Default)]
pub struct PeerStreamRegistry {
    senders: Mutex<HashMap<String, LiveSender>>,
    next_generation: AtomicU64,
    effects: std::sync::Arc<super::membership::GenerationEffectRegistry>,
}

impl PeerStreamRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_effect_registry(
        effects: std::sync::Arc<super::membership::GenerationEffectRegistry>,
    ) -> Self {
        Self {
            effects,
            ..Self::default()
        }
    }

    pub(crate) fn effect_registry(
        &self,
    ) -> std::sync::Arc<super::membership::GenerationEffectRegistry> {
        std::sync::Arc::clone(&self.effects)
    }

    /// Lock the inner map, RECOVERING from a poisoned mutex instead of
    /// panicking. The critical sections are pure `HashMap` ops that can't leave
    /// the map half-modified, so a poisoned lock (a panic elsewhere while held)
    /// still hands back consistent data — and panicking the connection task on
    /// poison would be a worse failure than continuing. (SL-00(1c) review.)
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<String, LiveSender>> {
        self.senders
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Register a peer's outbound channel. Replaces any prior entry (a
    /// reconnect supersedes the stale channel). Returns the receiver the
    /// connection task should drain.
    #[cfg(test)]
    fn register(&self, peer_pk_hex: &str) -> tokio::sync::mpsc::Receiver<AuthorizedWireFrame> {
        self.register_generation(peer_pk_hex, None, None).1
    }

    pub(crate) fn register_authorized_session(
        &self,
        peer_pk_hex: &str,
        grant: &MembershipGrant,
    ) -> (
        u64,
        tokio::sync::mpsc::Receiver<AuthorizedWireFrame>,
        tokio::sync::watch::Receiver<bool>,
    ) {
        self.register_generation_inner(
            peer_pk_hex,
            Some(grant.stable_node_id().clone()),
            Some(grant.auth_epoch()),
            Some(grant.clone()),
        )
    }

    #[cfg(test)]
    fn register_generation(
        &self,
        peer_pk_hex: &str,
        stable_node_id: Option<StableNodeId>,
        auth_epoch: Option<AuthEpoch>,
    ) -> (u64, tokio::sync::mpsc::Receiver<AuthorizedWireFrame>) {
        let (generation, receiver, _cancel) =
            self.register_generation_inner(peer_pk_hex, stable_node_id, auth_epoch, None);
        (generation, receiver)
    }

    fn register_generation_inner(
        &self,
        peer_pk_hex: &str,
        stable_node_id: Option<StableNodeId>,
        auth_epoch: Option<AuthEpoch>,
        membership_grant: Option<MembershipGrant>,
    ) -> (
        u64,
        tokio::sync::mpsc::Receiver<AuthorizedWireFrame>,
        tokio::sync::watch::Receiver<bool>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        let (cancel, cancel_rx) = tokio::sync::watch::channel(false);
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        let mut map = self.guard();
        map.insert(
            peer_pk_hex.to_string(),
            LiveSender {
                generation,
                stable_node_id,
                auth_epoch,
                membership_grant,
                sender: tx,
                cancel,
            },
        );
        (generation, rx, cancel_rx)
    }

    /// Remove a peer's channel (connection ended). Idempotent.
    pub fn unregister(&self, peer_pk_hex: &str) {
        let mut map = self.guard();
        map.remove(peer_pk_hex);
    }

    /// Remove only the generation owned by the dropping session. A stale
    /// session can never erase a newer reconnect.
    pub fn unregister_generation(&self, peer_pk_hex: &str, generation: u64) -> bool {
        let mut map = self.guard();
        if map
            .get(peer_pk_hex)
            .is_some_and(|entry| entry.generation == generation)
        {
            map.remove(peer_pk_hex);
            true
        } else {
            false
        }
    }

    /// Tear down every carrier session bound to a stable node. Dropping all
    /// senders closes their outbound receivers and quarantines queued frames.
    pub fn revoke_stable_node(&self, stable_node_id: &StableNodeId) -> usize {
        self.teardown_stable_node(stable_node_id).routes_evicted
    }

    fn teardown_stable_node(
        &self,
        stable_node_id: &StableNodeId,
    ) -> crate::cluster::membership::CarrierTeardownReceipt {
        let removed = {
            let mut map = self.guard();
            let keys = map
                .iter()
                .filter_map(|(key, entry)| {
                    (entry.stable_node_id.as_ref() == Some(stable_node_id)).then(|| key.clone())
                })
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| map.remove(&key))
                .collect::<Vec<_>>()
        };
        let routes_evicted = removed.len();
        let mut queued_effects_dropped = 0usize;
        let mut close_signals = Vec::with_capacity(routes_evicted);
        for entry in removed {
            queued_effects_dropped += entry
                .sender
                .max_capacity()
                .saturating_sub(entry.sender.capacity());
            let _ = entry.cancel.send(true);
            close_signals.push(entry.cancel);
        }
        // The watch receiver is owned by the connection task. Its disappearance
        // is the exact local teardown ACK: the SecretStream task has left its
        // cancellation select and dropped the live transport state.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        while close_signals
            .iter()
            .any(|cancel| cancel.receiver_count() != 0)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let closed_sessions = close_signals
            .iter()
            .filter(|cancel| cancel.receiver_count() == 0)
            .count();
        crate::cluster::membership::CarrierTeardownReceipt {
            closed_sessions,
            routes_evicted,
            queued_effects_dropped,
            status: if routes_evicted == 0 {
                "no_live_sessions".into()
            } else if closed_sessions == routes_evicted {
                "closed".into()
            } else {
                "partial".into()
            },
        }
    }

    /// Send a frame to one peer. Fail-closed: unknown/closed/full → `Err`.
    pub fn send_to(&self, peer_pk_hex: &str, frame: WireFrame) -> Result<(), SendError> {
        // Clone the Sender out under the lock, then drop the guard BEFORE
        // try_send so the lock is never held across the channel op.
        let sender = {
            let map = self.guard();
            map.get(peer_pk_hex)
                .map(|entry| (entry.sender.clone(), entry.membership_grant.clone()))
        };
        let Some((sender, membership_grant)) = sender else {
            return Err(SendError::UnknownPeer);
        };
        let effect_guard = if let Some(grant) = membership_grant {
            Some(
                grant
                    .begin_effect(crate::time::now_unix_i64())
                    .map_err(|_| SendError::MembershipRevoked)?,
            )
        } else {
            #[cfg(not(test))]
            return Err(SendError::MembershipRevoked);
            #[cfg(test)]
            None
        };
        sender
            .try_send(AuthorizedWireFrame {
                frame,
                effect_guard,
            })
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => SendError::QueueFull,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => SendError::Closed,
            })
    }

    /// Best-effort broadcast to every live peer. Returns the count delivered to
    /// (queued on) successfully. Never errors — a wedged peer is skipped.
    pub fn broadcast(&self, frame: &WireFrame) -> usize {
        let senders: Vec<(
            String,
            tokio::sync::mpsc::Sender<AuthorizedWireFrame>,
            Option<MembershipGrant>,
        )> = {
            let map = self.guard();
            map.iter()
                .map(|(key, entry)| {
                    (
                        key.clone(),
                        entry.sender.clone(),
                        entry.membership_grant.clone(),
                    )
                })
                .collect()
        };
        let mut delivered = 0;
        for (_peer, sender, membership_grant) in senders {
            let effect_guard = membership_grant
                .as_ref()
                .and_then(|grant| grant.begin_effect(crate::time::now_unix_i64()).ok());
            if membership_grant.is_some() && effect_guard.is_none() {
                continue;
            }
            #[cfg(not(test))]
            if membership_grant.is_none() {
                continue;
            }
            if sender
                .try_send(AuthorizedWireFrame {
                    frame: frame.clone(),
                    effect_guard,
                })
                .is_ok()
            {
                delivered += 1;
            }
        }
        delivered
    }

    /// Number of peers with a live outbound channel.
    pub fn peer_count(&self) -> usize {
        self.guard().len()
    }

    /// Snapshot of the connected peer pubkey hexes (for status/observability).
    pub fn connected_peers(&self) -> Vec<String> {
        let mut v: Vec<String> = self.guard().keys().cloned().collect();
        v.sort();
        v
    }

    pub fn connected_members(&self) -> Vec<(StableNodeId, AuthEpoch, u64)> {
        let mut members = self
            .guard()
            .values()
            .filter_map(|entry| {
                Some((
                    entry.stable_node_id.clone()?,
                    entry.auth_epoch?,
                    entry.generation,
                ))
            })
            .collect::<Vec<_>>();
        members.sort_by(|left, right| left.0.cmp(&right.0).then(left.2.cmp(&right.2)));
        members
    }

    pub fn connected_routes(&self) -> Vec<(String, MembershipGrant, u64)> {
        let now = crate::time::now_unix_i64();
        let mut routes = self
            .guard()
            .iter()
            .filter_map(|(transport, entry)| {
                let grant = entry.membership_grant.as_ref()?;
                grant.revalidate(now).ok()?;
                Some((transport.clone(), grant.clone(), entry.generation))
            })
            .collect::<Vec<_>>();
        routes.sort_by(|left, right| {
            left.1
                .stable_node_id()
                .cmp(right.1.stable_node_id())
                .then(left.2.cmp(&right.2))
        });
        routes
    }
}

impl crate::cluster::membership::LiveCarrierSessions for PeerStreamRegistry {
    fn carrier(&self) -> crate::cluster::membership::CarrierKind {
        crate::cluster::membership::CarrierKind::Peeroxide
    }

    fn teardown_stable_node(
        &self,
        stable_node_id: &StableNodeId,
    ) -> crate::cluster::membership::CarrierTeardownReceipt {
        Self::teardown_stable_node(self, stable_node_id)
    }

    fn live_membership_generations(
        &self,
    ) -> Vec<crate::cluster::membership::LiveMembershipGeneration> {
        let mut generations = self
            .guard()
            .values()
            .filter_map(|entry| {
                let grant = entry.membership_grant.as_ref()?;
                Some(crate::cluster::membership::LiveMembershipGeneration {
                    stable_node_id: grant.stable_node_id().clone(),
                    carrier: grant.carrier(),
                    auth_epoch: grant.auth_epoch(),
                    membership_epoch: grant.membership_epoch(),
                    kind: "route".into(),
                })
            })
            .collect::<Vec<_>>();
        generations.sort_by(|left, right| {
            left.stable_node_id
                .cmp(&right.stable_node_id)
                .then(left.auth_epoch.cmp(&right.auth_epoch))
                .then(left.membership_epoch.cmp(&right.membership_epoch))
        });
        generations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::heartbeat::{FrameBody, FrameKind, GoodbyeBody};

    fn sample_frame() -> WireFrame {
        WireFrame {
            kind: FrameKind::Goodbye,
            sequence: 1,
            sent_unix_ms: 1_700_000_000_000,
            peer_id: "p".into(),
            body: FrameBody::Goodbye(GoodbyeBody { reason: None }),
        }
    }

    #[test]
    fn send_to_unknown_peer_fails_closed() {
        let reg = PeerStreamRegistry::new();
        assert_eq!(
            reg.send_to("deadbeef", sample_frame()),
            Err(SendError::UnknownPeer),
            "sending to a peer that never connected must error, not silently drop"
        );
    }

    #[tokio::test]
    async fn register_then_send_delivers() {
        let reg = PeerStreamRegistry::new();
        let mut rx = reg.register("aa11");
        assert_eq!(reg.peer_count(), 1);
        reg.send_to("aa11", sample_frame())
            .expect("registered peer accepts a frame");
        let got = rx.recv().await.expect("frame arrives on the receiver");
        assert_eq!(got.kind, FrameKind::Goodbye);
    }

    #[test]
    fn unregister_removes_the_peer() {
        let reg = PeerStreamRegistry::new();
        let _rx = reg.register("bb22");
        assert_eq!(reg.peer_count(), 1);
        reg.unregister("bb22");
        assert_eq!(reg.peer_count(), 0);
        assert_eq!(
            reg.send_to("bb22", sample_frame()),
            Err(SendError::UnknownPeer)
        );
    }

    #[tokio::test]
    async fn send_to_full_queue_reports_queue_full() {
        let reg = PeerStreamRegistry::new();
        // Hold the receiver but never drain it; fill the bounded queue.
        let _rx = reg.register("cc33");
        let mut full = false;
        for _ in 0..(OUTBOUND_QUEUE_DEPTH + 4) {
            if reg.send_to("cc33", sample_frame()) == Err(SendError::QueueFull) {
                full = true;
                break;
            }
        }
        assert!(
            full,
            "a never-drained queue must eventually report QueueFull, not block"
        );
    }

    #[tokio::test]
    async fn closed_receiver_reports_closed() {
        let reg = PeerStreamRegistry::new();
        let rx = reg.register("dd44");
        drop(rx); // connection task gone
        assert_eq!(
            reg.send_to("dd44", sample_frame()),
            Err(SendError::Closed),
            "a dropped receiver surfaces as Closed"
        );
    }

    #[tokio::test]
    async fn broadcast_counts_only_live_deliveries() {
        let reg = PeerStreamRegistry::new();
        let mut rx1 = reg.register("e1");
        let rx2 = reg.register("e2");
        drop(rx2); // one peer's task is gone
        let delivered = reg.broadcast(&sample_frame());
        assert_eq!(delivered, 1, "broadcast delivers only to the live peer");
        assert!(rx1.recv().await.is_some());
    }

    #[test]
    fn connected_peers_is_sorted_snapshot() {
        let reg = PeerStreamRegistry::new();
        let _a = reg.register("zz");
        let _b = reg.register("aa");
        assert_eq!(
            reg.connected_peers(),
            vec!["aa".to_string(), "zz".to_string()]
        );
    }

    #[test]
    fn stale_generation_unregister_cannot_remove_reconnect() {
        let reg = PeerStreamRegistry::new();
        let (old_generation, old_rx) = reg.register_generation("aa", None, None);
        let (new_generation, _new_rx) = reg.register_generation("aa", None, None);
        assert!(
            old_rx.is_closed(),
            "reconnect closes old outbound generation"
        );
        assert!(!reg.unregister_generation("aa", old_generation));
        assert_eq!(reg.connected_peers(), vec!["aa".to_string()]);
        assert!(reg.unregister_generation("aa", new_generation));
        assert!(reg.connected_peers().is_empty());
    }

    #[test]
    fn revoke_closes_every_matching_stable_node_session() {
        let reg = PeerStreamRegistry::new();
        let stable = StableNodeId::parse("ab".repeat(32)).unwrap();
        let other = StableNodeId::parse("cd".repeat(32)).unwrap();
        let (_, first) = reg.register_generation(
            "peeroxide-key",
            Some(stable.clone()),
            Some(AuthEpoch::INITIAL),
        );
        let (_, second) =
            reg.register_generation("iroh-key", Some(stable.clone()), Some(AuthEpoch::INITIAL));
        let (_, survivor) = reg.register_generation("other", Some(other), Some(AuthEpoch::INITIAL));
        assert_eq!(reg.revoke_stable_node(&stable), 2);
        assert!(first.is_closed());
        assert!(second.is_closed());
        assert!(!survivor.is_closed());
        assert_eq!(reg.connected_peers(), vec!["other".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn teardown_receipt_waits_for_connection_task_cancellation_ack() {
        let registry = std::sync::Arc::new(PeerStreamRegistry::new());
        let stable = StableNodeId::parse("ef".repeat(32)).unwrap();
        let (_generation, outbound, mut cancel) = registry.register_generation_inner(
            "peeroxide-live",
            Some(stable.clone()),
            Some(AuthEpoch::INITIAL),
            None,
        );
        let connection = tokio::spawn(async move {
            cancel.changed().await.expect("revocation cancellation");
            assert!(*cancel.borrow(), "revocation must set the cancellation bit");
            drop(outbound);
            drop(cancel);
        });

        let revoke_registry = std::sync::Arc::clone(&registry);
        let receipt =
            tokio::task::spawn_blocking(move || revoke_registry.teardown_stable_node(&stable))
                .await
                .unwrap();
        connection.await.unwrap();

        assert_eq!(receipt.closed_sessions, 1);
        assert_eq!(receipt.routes_evicted, 1);
        assert_eq!(receipt.status, "closed");
        assert!(registry.connected_peers().is_empty());
    }
}
