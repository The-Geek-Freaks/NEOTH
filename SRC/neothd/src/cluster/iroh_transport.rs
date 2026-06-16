//! iroh QUIC cluster transport — "dial keys, not IP addresses".
//!
//! An alternative to the peeroxide Hyperswarm transport (`hyperswarm.rs`).
//! iroh gives us: a stable cryptographic **EndpointId** (dial peers by key, not
//! by IP), QUIC bi-directional streams, NAT-traversal + hole-punching, and a
//! relay fallback when a direct path can't be found — exactly what cluster
//! gossip + WAL-sync need, without us owning the transport plumbing.
//!
//! Feature-gated (`cluster-iroh`), default-off so the base build stays lean
//! (iroh pulls the full QUIC + relay stack).
//!
//! ## Shape
//!
//! - [`IrohTransport::bind`] brings up an [`Endpoint`] + a [`Router`] that
//!   accepts NEOTH's cluster ALPN. Each inbound connection opens one
//!   bi-stream carrying a single gossip frame; the supplied [`FrameHandler`]
//!   maps that request frame → the reply frame (the gossip protocol is
//!   request/response: peer sends its frame, we reply with ours). This is the
//!   seam the live gossip path wires into — the handler deserialises the
//!   `GossipFrame`, runs `wal_sync::GossipState::accept_inbound`, and replies
//!   with `build_outbound`.
//! - [`IrohTransport::addr`] is the dial key (`EndpointAddr`) to share with
//!   peers — the iroh equivalent of a Hyperswarm topic ticket.
//! - [`IrohTransport::send_frame`] dials a peer by its `EndpointAddr` and does
//!   one request/response round-trip.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};

/// Shared set of known peer endpoint-ids (dial keys). Learned from inbound
/// connections + seeded from `cluster.peers` in freedom.yaml.
pub type PeerRegistry = Arc<Mutex<HashSet<EndpointId>>>;

/// ALPN for NEOTH cluster gossip. Both ends must present the same bytestring or
/// iroh aborts the handshake — a cheap protocol/version guard.
pub const NEOTH_CLUSTER_ALPN: &[u8] = b"neoth/cluster/gossip/1";

/// Hard cap on a single gossip frame (DoS guard on the QUIC read). Gossip
/// frames are small (a vector clock + a band of WAL frames); 4 MiB is generous.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Maps an inbound request frame to the reply frame. Pure bytes in / bytes out
/// so the transport stays gossip-agnostic; the cluster supplies the real
/// `GossipFrame` decode → `accept_inbound` → `build_outbound` logic.
pub type FrameHandler = Arc<dyn Fn(Vec<u8>) -> Vec<u8> + Send + Sync>;

#[derive(Clone)]
struct GossipProtocol {
    handler: FrameHandler,
    peers: PeerRegistry,
}

// `ProtocolHandler` requires `Debug`, but `FrameHandler` (a boxed closure) can't
// derive it — provide an opaque one.
impl std::fmt::Debug for GossipProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipProtocol").finish_non_exhaustive()
    }
}

impl ProtocolHandler for GossipProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // EndpointAddr exchange: learn this peer's dial key from the inbound
        // connection so we can gossip BACK to it (outbound broadcast).
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(connection.remote_id());
        // One inbound bi-stream per connection = one gossip request/response.
        let (mut send, mut recv) = connection.accept_bi().await?;
        let request = recv
            .read_to_end(MAX_FRAME_BYTES)
            .await
            .map_err(AcceptError::from_err)?;
        let reply = (self.handler)(request);
        send.write_all(&reply).await.map_err(AcceptError::from_err)?;
        send.finish().map_err(AcceptError::from_err)?;
        // Wait for the peer to read the reply + close, so the response isn't cut.
        connection.closed().await;
        Ok(())
    }
}

/// A bound iroh cluster transport: an accepting endpoint + the means to dial
/// peers by key.
pub struct IrohTransport {
    router: Router,
    peers: PeerRegistry,
}

impl IrohTransport {
    /// Bind an endpoint (with iroh's N0 relay/discovery preset) and start
    /// accepting NEOTH cluster connections. Resolves once the endpoint is
    /// online (has a reachable address / relay home).
    pub async fn bind(handler: FrameHandler) -> Result<Self> {
        let peers: PeerRegistry = Arc::new(Mutex::new(HashSet::new()));
        let endpoint = Endpoint::bind(presets::N0)
            .await
            .context("iroh: bind endpoint")?;
        let router = Router::builder(endpoint)
            .accept(
                NEOTH_CLUSTER_ALPN,
                GossipProtocol {
                    handler,
                    peers: Arc::clone(&peers),
                },
            )
            .spawn();
        // Block until the endpoint has a path peers can reach it on.
        router.endpoint().online().await;
        Ok(Self { router, peers })
    }

    /// Number of known peers (learned inbound + seeded).
    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Seed a peer by its endpoint-id string (hex). Returns false if unparseable.
    pub fn add_peer_id(&self, id: &str) -> bool {
        match id.trim().parse::<EndpointId>() {
            Ok(eid) => {
                self.peers
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(eid);
                true
            }
            Err(_) => false,
        }
    }

    /// Broadcast one gossip frame to every known peer (best-effort, dial-by-key).
    /// Returns how many peers accepted the round-trip.
    pub async fn broadcast(&self, frame: &[u8]) -> usize {
        let targets: Vec<EndpointId> = self
            .peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect();
        let mut delivered = 0;
        for peer in targets {
            if self.send_frame(peer, frame).await.is_ok() {
                delivered += 1;
            }
        }
        delivered
    }

    /// This node's dial key — share it with peers so they can `send_frame` to us.
    pub fn addr(&self) -> EndpointAddr {
        self.router.endpoint().addr()
    }

    /// This node's stable cryptographic id (hex), for logging / peer maps.
    pub fn node_id(&self) -> String {
        self.router.endpoint().id().to_string()
    }

    /// Dial a peer by its `EndpointAddr` and do one gossip request/response
    /// round-trip: write `frame`, read the peer's reply (capped).
    pub async fn send_frame(
        &self,
        peer: impl Into<EndpointAddr>,
        frame: &[u8],
    ) -> Result<Vec<u8>> {
        let conn = self
            .router
            .endpoint()
            .connect(peer, NEOTH_CLUSTER_ALPN)
            .await
            .context("iroh: connect to peer")?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("iroh: open_bi: {e}"))?;
        send.write_all(frame)
            .await
            .map_err(|e| anyhow::anyhow!("iroh: write frame: {e}"))?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("iroh: finish: {e}"))?;
        let reply = recv
            .read_to_end(MAX_FRAME_BYTES)
            .await
            .map_err(|e| anyhow::anyhow!("iroh: read reply: {e}"))?;
        conn.close(0u32.into(), b"done");
        Ok(reply)
    }

    /// Gracefully shut down the router + endpoint (flushes queued closes).
    pub async fn shutdown(self) -> Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("iroh: router shutdown: {e}"))?;
        Ok(())
    }
}

/// A gossip-aware [`FrameHandler`] — the iroh↔gossip bridge for the live-flip.
///
/// It routes every inbound frame through the SAME security stack the peeroxide
/// path uses, so flipping the transport to iroh preserves the cluster's
/// guarantees:
///   - **(2) frame acceptance + (4) replay** — `GossipState::accept_inbound`
///     runs `evaluate_acceptance` (replicable tag / within replay budget / not
///     a duplicate via the per-origin dedup high-water) and merges the vector
///     clock (causal frontier — stale frames can't advance state);
///   - **(5) consent/policy band** — the DoNotGossip re-check on the payload's
///     OWN event_type (byte 2 of the inner WAL header), so a mistagged frame
///     can't smuggle a private band across.
///
/// **(3) peer trust** + **(1) node capabilities** are enforced BEFORE frames
/// reach here: iroh's QUIC channel is authenticated by EndpointId, and the
/// caller verifies the peer's `cluster_key` HMAC proof (`cluster::peer_auth`)
/// on the Hello before admitting gossip — exactly as the peeroxide loop does.
pub fn gossip_handler(
    state: std::sync::Arc<std::sync::Mutex<crate::cluster::wal_sync::GossipState>>,
) -> FrameHandler {
    use crate::cluster::gossip::GossipPolicy;
    use crate::cluster::gossip_wire::{GossipAcceptance, GossipFrame};
    let policy = GossipPolicy::default();
    std::sync::Arc::new(move |req: Vec<u8>| -> Vec<u8> {
        let reply = |accepted: bool, verdict: &str| {
            serde_json::to_vec(
                &serde_json::json!({ "accepted": accepted, "verdict": verdict }),
            )
            .unwrap_or_default()
        };
        let frame: GossipFrame = match serde_json::from_slice(&req) {
            Ok(f) => f,
            Err(_) => return reply(false, "malformed"),
        };
        // payload's own event_type = byte 2 of the inner WAL header (foreign
        // frame → read without HMAC, exactly like the peeroxide loop).
        let payload_et = frame.payload.get(2).copied();
        let now = crate::time::now_unix_i64();
        let verdict = {
            let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
            g.accept_inbound(&frame, payload_et, &policy, now)
        };
        reply(
            matches!(verdict, GossipAcceptance::Accept),
            &format!("{verdict:?}"),
        )
    })
}

/// Newest `*.wal` segment in `dir` (the live one). Inlined (the wal_sync copy
/// is private).
fn newest_wal_segment(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut segs: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "wal").unwrap_or(false))
        .collect();
    segs.sort();
    segs.pop()
}

/// Outbound gossip broadcast tick for iroh — the send-side counterpart to
/// `wal_sync::spawn_gossip_tick` (which serves the peeroxide streams). Every 30s
/// it reads the active WAL segment tail, band-filters replicable frames with the
/// SAME `collect_gossipable_frames` + `build_outbound` the peeroxide path uses,
/// and broadcasts each as a bare `GossipFrame` (JSON) to every known peer via
/// `IrohTransport::broadcast` (dial-by-key). Best-effort: the cursor always
/// advances (receiver dedups + replay-budget cover gaps).
pub fn spawn_gossip_broadcast(
    transport: Arc<IrohTransport>,
    segment_path: std::path::PathBuf,
) -> tokio::task::JoinHandle<()> {
    use crate::cluster::PeerPubkey;
    use crate::cluster::gossip::GossipPolicy;
    use crate::cluster::wal_sync::{GossipState, collect_gossipable_frames};
    tokio::spawn(async move {
        let policy = GossipPolicy::default();
        let mut state = GossipState::new();
        let self_id = PeerPubkey::new(uuid::Uuid::now_v7().to_string());
        let wal_dir = segment_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let mut current = segment_path.clone();
        let mut last_offset = 0usize;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if transport.peer_count() == 0 {
                continue; // no peers ⇒ nothing to gossip
            }
            let active = newest_wal_segment(&wal_dir).unwrap_or_else(|| current.clone());
            if active != current {
                current = active.clone();
                last_offset = 0; // rollover ⇒ offset is meaningless for the new file
            }
            let Ok(bytes) = tokio::fs::read(&current).await else {
                continue;
            };
            let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
                continue;
            };
            if hdr.is_compressed() {
                continue; // finalised/rolled segment — body is zstd, skip
            }
            let header_len = hdr.header_len();
            if bytes.len() <= header_len {
                continue;
            }
            let body = &bytes[header_len..];
            let (frames, new_offset) = collect_gossipable_frames(body, last_offset, &policy, 32);
            last_offset = new_offset; // always advance (best-effort)
            for (event_type, raw) in frames {
                let ts = crate::time::now_unix_i64();
                if let Some(gframe) = state.build_outbound(&self_id, event_type, raw, ts, &policy) {
                    if let Ok(wire) = serde_json::to_vec(&gframe) {
                        let _ = transport.broadcast(&wire).await;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two endpoints, one round-trip: B dials A by key, A's handler replies.
    /// Proves the real iroh send/accept path (bind → connect → bi-stream →
    /// handler → reply) works end-to-end. `#[ignore]` — it brings up real iroh
    /// endpoints (relay/discovery), so it needs a network; run manually:
    /// `cargo test -p neothd --features cluster-iroh loopback_frame_round_trip -- --ignored`.
    #[tokio::test]
    #[ignore = "real iroh endpoints — needs network (relay/discovery)"]
    async fn loopback_frame_round_trip() {
        // A echoes "<req>+ack".
        let handler: FrameHandler = Arc::new(|req: Vec<u8>| {
            let mut r = req;
            r.extend_from_slice(b"+ack");
            r
        });
        let a = IrohTransport::bind(handler).await.expect("bind A");
        let b = IrohTransport::bind(Arc::new(|r| r)).await.expect("bind B");

        let reply = b
            .send_frame(a.addr(), b"gossip-hello")
            .await
            .expect("round-trip");
        assert_eq!(reply, b"gossip-hello+ack");

        a.shutdown().await.expect("shutdown A");
        b.shutdown().await.expect("shutdown B");
    }

    #[test]
    fn alpn_is_versioned() {
        assert!(NEOTH_CLUSTER_ALPN.ends_with(b"/1"));
    }

    #[test]
    fn gossip_handler_rejects_malformed_and_replies_json() {
        use crate::cluster::wal_sync::GossipState;
        let state = std::sync::Arc::new(std::sync::Mutex::new(GossipState::new()));
        let handler = gossip_handler(state);
        // A non-GossipFrame byte blob must be rejected (decode failure), not
        // panic — and the reply is a parseable JSON verdict.
        let reply = handler(b"not a gossip frame".to_vec());
        let v: serde_json::Value = serde_json::from_slice(&reply).expect("json reply");
        assert_eq!(v["accepted"], false);
        assert_eq!(v["verdict"], "malformed");
    }
}
