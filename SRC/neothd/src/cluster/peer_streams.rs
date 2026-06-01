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

use super::heartbeat::WireFrame;

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
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::UnknownPeer => f.write_str("no live connection to peer"),
            SendError::QueueFull => f.write_str("peer outbound queue full"),
            SendError::Closed => f.write_str("peer connection closing"),
        }
    }
}

impl std::error::Error for SendError {}

/// Registry of live outbound channels, keyed by peer Noise static pubkey hex.
#[derive(Default)]
pub struct PeerStreamRegistry {
    senders: Mutex<HashMap<String, tokio::sync::mpsc::Sender<WireFrame>>>,
}

impl PeerStreamRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock the inner map, RECOVERING from a poisoned mutex instead of
    /// panicking. The critical sections are pure `HashMap` ops that can't leave
    /// the map half-modified, so a poisoned lock (a panic elsewhere while held)
    /// still hands back consistent data — and panicking the connection task on
    /// poison would be a worse failure than continuing. (SL-00(1c) review.)
    fn guard(&self) -> std::sync::MutexGuard<'_, HashMap<String, tokio::sync::mpsc::Sender<WireFrame>>> {
        self.senders.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Register a peer's outbound channel. Replaces any prior entry (a
    /// reconnect supersedes the stale channel). Returns the receiver the
    /// connection task should drain.
    pub fn register(&self, peer_pk_hex: &str) -> tokio::sync::mpsc::Receiver<WireFrame> {
        let (tx, rx) = tokio::sync::mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        let mut map = self.guard();
        map.insert(peer_pk_hex.to_string(), tx);
        rx
    }

    /// Remove a peer's channel (connection ended). Idempotent.
    pub fn unregister(&self, peer_pk_hex: &str) {
        let mut map = self.guard();
        map.remove(peer_pk_hex);
    }

    /// Send a frame to one peer. Fail-closed: unknown/closed/full → `Err`.
    pub fn send_to(&self, peer_pk_hex: &str, frame: WireFrame) -> Result<(), SendError> {
        // Clone the Sender out under the lock, then drop the guard BEFORE
        // try_send so the lock is never held across the channel op.
        let sender = {
            let map = self.guard();
            map.get(peer_pk_hex).cloned()
        };
        let Some(sender) = sender else {
            return Err(SendError::UnknownPeer);
        };
        sender.try_send(frame).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => SendError::QueueFull,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => SendError::Closed,
        })
    }

    /// Best-effort broadcast to every live peer. Returns the count delivered to
    /// (queued on) successfully. Never errors — a wedged peer is skipped.
    pub fn broadcast(&self, frame: &WireFrame) -> usize {
        let senders: Vec<(String, tokio::sync::mpsc::Sender<WireFrame>)> = {
            let map = self.guard();
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        let mut delivered = 0;
        for (_peer, sender) in senders {
            if sender.try_send(frame.clone()).is_ok() {
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
        reg.send_to("aa11", sample_frame()).expect("registered peer accepts a frame");
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
        assert_eq!(reg.send_to("bb22", sample_frame()), Err(SendError::UnknownPeer));
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
        assert!(full, "a never-drained queue must eventually report QueueFull, not block");
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
        assert_eq!(reg.connected_peers(), vec!["aa".to_string(), "zz".to_string()]);
    }
}
