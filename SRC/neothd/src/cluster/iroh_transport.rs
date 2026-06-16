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

use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};

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
}

impl IrohTransport {
    /// Bind an endpoint (with iroh's N0 relay/discovery preset) and start
    /// accepting NEOTH cluster connections. Resolves once the endpoint is
    /// online (has a reachable address / relay home).
    pub async fn bind(handler: FrameHandler) -> Result<Self> {
        let endpoint = Endpoint::bind(presets::N0)
            .await
            .context("iroh: bind endpoint")?;
        let router = Router::builder(endpoint)
            .accept(NEOTH_CLUSTER_ALPN, GossipProtocol { handler })
            .spawn();
        // Block until the endpoint has a path peers can reach it on.
        router.endpoint().online().await;
        Ok(Self { router })
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
    pub async fn send_frame(&self, peer: EndpointAddr, frame: &[u8]) -> Result<Vec<u8>> {
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
