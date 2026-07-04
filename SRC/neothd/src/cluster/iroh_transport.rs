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

use crate::cluster::discovery::ClusterKey;
use crate::cluster::peer_auth::{compute_cluster_key_proof, verify_peer_proof};
use crate::wal::events::{
    EVENT_TYPE_CLUSTER_GOSSIP_DROPPED, EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED,
    EVENT_TYPE_CLUSTER_GOSSIP_SENT,
};
use crate::wal::writer::WalWriterHandle;

/// Shared set of known peer endpoint-ids (dial keys). Learned from inbound
/// connections + seeded from `cluster.peers` in freedom.yaml.
pub type PeerRegistry = Arc<Mutex<HashSet<EndpointId>>>;

/// D3 — length of the `cluster_key` HMAC proof carried as the Hello prefix on
/// every authenticated gossip stream (32-byte HMAC-SHA256, see
/// [`crate::cluster::peer_auth`]).
const CLUSTER_PROOF_BYTES: usize = 32;

/// F19 — best-effort WAL audit for an inbound gossip decision over iroh. Uses
/// the SYNC WAL append so it works from the sync [`FrameHandler`] closure AND
/// the async accept path, and reuses the same cluster-band codes the peeroxide
/// path uses: `0xEE CLUSTER_GOSSIP_RECEIVED` (accepted) / `0xEF
/// CLUSTER_GOSSIP_DROPPED` (rejected, carries the reason).
fn emit_gossip_audit(
    writer: &Option<Arc<WalWriterHandle>>,
    accepted: bool,
    verdict: &str,
    origin: &str,
) {
    let Some(w) = writer else { return };
    let event_type = if accepted {
        EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED
    } else {
        EVENT_TYPE_CLUSTER_GOSSIP_DROPPED
    };
    let payload = serde_json::json!({
        "accepted": accepted,
        "verdict": verdict,
        "origin": origin,
        "transport": "iroh",
        "ts_unix": crate::time::now_unix_i64(),
    })
    .to_string()
    .into_bytes();
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    if let Err(e) = w.try_append_sync(header, payload) {
        tracing::debug!(error = %e, "iroh gossip audit append failed");
    }
}

/// Send-side gossip audit (`0xED CLUSTER_GOSSIP_SENT`) for the iroh broadcast
/// tick — the symmetric counterpart to the receive-side `emit_gossip_audit`
/// and parity with the peeroxide path's `wal_sync::emit_gossip_sent_wal`.
/// Best-effort + synchronous (runs inside the broadcast task).
fn emit_gossip_sent(
    writer: &Option<Arc<WalWriterHandle>>,
    frame_count: usize,
    delivered: usize,
    peer_count: usize,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "frame_count": frame_count,
        "delivered": delivered,
        "peer_count": peer_count,
        "transport": "iroh",
        "ts_unix": crate::time::now_unix_i64(),
    })
    .to_string()
    .into_bytes();
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_CLUSTER_GOSSIP_SENT, &payload).build();
    if let Err(e) = w.try_append_sync(header, payload) {
        tracing::debug!(error = %e, "iroh gossip-sent audit append failed");
    }
}

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
    /// D3 — when present, every inbound connection must present a valid
    /// `cluster_key` HMAC proof (Hello prefix) before its frame reaches the
    /// handler. `None` keeps the legacy unauthenticated path (no key configured).
    cluster_key: Option<Arc<ClusterKey>>,
    /// Our own endpoint id — the proof's verifier half.
    our_id: EndpointId,
    /// D3 reject-audit sink (gossip-dropped frames for the peer-auth path).
    writer: Option<Arc<WalWriterHandle>>,
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
        let peer_id = connection.remote_id();
        // One inbound bi-stream per connection = one gossip request/response.
        let (mut send, mut recv) = connection.accept_bi().await?;
        let request = recv
            .read_to_end(MAX_FRAME_BYTES)
            .await
            .map_err(AcceptError::from_err)?;

        // D3 — cluster_key Hello proof. When a key is configured the first
        // CLUSTER_PROOF_BYTES of the stream are the peer's HMAC proof and the
        // gossip frame follows. A peer that can reach the ALPN but can't prove
        // cluster membership is dropped BEFORE add_peer / before its frame is
        // evaluated — parity with the peeroxide Hello gate. (iroh's QUIC channel
        // already authenticates the peer's EndpointId at the transport level; the
        // proof binds that id to our shared cluster_key, closing the
        // authorization gap.)
        let frame: Vec<u8> = match &self.cluster_key {
            Some(key) => {
                if request.len() < CLUSTER_PROOF_BYTES {
                    emit_gossip_audit(
                        &self.writer,
                        false,
                        "peer_auth_missing_proof",
                        &peer_id.to_string(),
                    );
                    return Ok(()); // reject: too short to carry a proof
                }
                let (proof, frame) = request.split_at(CLUSTER_PROOF_BYTES);
                let claimed: [u8; 32] =
                    proof.try_into().expect("split_at(32) yields exactly 32 bytes");
                if !verify_peer_proof(key, &claimed, peer_id.as_bytes(), self.our_id.as_bytes()) {
                    emit_gossip_audit(
                        &self.writer,
                        false,
                        "peer_auth_failed",
                        &peer_id.to_string(),
                    );
                    return Ok(()); // reject: not a proven cluster member
                }
                frame.to_vec()
            }
            None => request, // legacy: no key configured → no proof expected
        };

        // Proof OK (or no key configured) → learn this peer's dial key so we can
        // gossip BACK to it (outbound broadcast).
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(peer_id);
        let reply = (self.handler)(frame);
        send.write_all(&reply)
            .await
            .map_err(AcceptError::from_err)?;
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
    /// D3 — our cluster_key. The dial side prepends a Hello proof when present
    /// so a peeroxide-parity authorization handshake runs on every send.
    cluster_key: Option<Arc<ClusterKey>>,
}

impl IrohTransport {
    /// Bind an endpoint (with iroh's N0 relay/discovery preset) and start
    /// accepting NEOTH cluster connections. Resolves once the endpoint is
    /// online (has a reachable address / relay home).
    ///
    /// `cluster_key` (D3): when `Some`, the accept path requires a valid
    /// `cluster_key` HMAC proof on every inbound connection and the dial path
    /// prepends ours. `writer` (F19): the gossip-decision audit sink.
    pub async fn bind(
        handler: FrameHandler,
        cluster_key: Option<Arc<ClusterKey>>,
        writer: Option<Arc<WalWriterHandle>>,
    ) -> Result<Self> {
        let peers: PeerRegistry = Arc::new(Mutex::new(HashSet::new()));
        let endpoint = Endpoint::bind(presets::N0)
            .await
            .context("iroh: bind endpoint")?;
        let our_id = endpoint.id();
        let router = Router::builder(endpoint)
            .accept(
                NEOTH_CLUSTER_ALPN,
                GossipProtocol {
                    handler,
                    peers: Arc::clone(&peers),
                    cluster_key: cluster_key.clone(),
                    our_id,
                    writer,
                },
            )
            .spawn();
        // Block until the endpoint has a path peers can reach it on.
        router.endpoint().online().await;
        Ok(Self {
            router,
            peers,
            cluster_key,
        })
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
    pub async fn send_frame(&self, peer: impl Into<EndpointAddr>, frame: &[u8]) -> Result<Vec<u8>> {
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
        // D3 — prepend our cluster_key Hello proof so the acceptor can verify
        // our membership before evaluating the frame. proof = HMAC(cluster_key,
        // DOMAIN || our_id || peer_id) — signer-first asymmetry guards against a
        // reflection attack (see cluster::peer_auth).
        if let Some(key) = &self.cluster_key {
            let our_id = self.router.endpoint().id();
            let peer_id = conn.remote_id();
            let proof = compute_cluster_key_proof(key, our_id.as_bytes(), peer_id.as_bytes());
            send.write_all(&proof)
                .await
                .map_err(|e| anyhow::anyhow!("iroh: write proof: {e}"))?;
        }
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

    /// GOLD-DELTA-10 — one-shot dial with a caller-supplied ALPN (the Babel
    /// federation submission path). Binds a throwaway endpoint, sends
    /// `frame`, returns the peer's reply. No cluster-key proof: federation
    /// auth is the Ed25519 batch signature, verified receiver-side — the
    /// aggregation node is deliberately NOT a cluster member.
    pub async fn dial_once_with_alpn(
        endpoint_id: &str,
        alpn: &'static [u8],
        frame: &[u8],
    ) -> Result<Vec<u8>> {
        let eid: EndpointId = endpoint_id
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid federation endpoint id"))?;
        let ep = Endpoint::bind(presets::N0)
            .await
            .context("iroh: bind federation endpoint")?;
        let conn = ep
            .connect(eid, alpn)
            .await
            .context("iroh: connect federation node")?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("iroh: open_bi: {e}"))?;
        send.write_all(frame)
            .await
            .map_err(|e| anyhow::anyhow!("iroh: write batch: {e}"))?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("iroh: finish: {e}"))?;
        let reply = recv
            .read_to_end(MAX_FRAME_BYTES)
            .await
            .map_err(|e| anyhow::anyhow!("iroh: read receipt: {e}"))?;
        conn.close(0u32.into(), b"done");
        ep.close().await;
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
/// **(1) node capabilities** are checked downstream as on the peeroxide path.
///
/// ⚠ **(3) peer trust — iroh path NOT yet at parity (D3).** iroh's QUIC channel
/// authenticates the peer's `EndpointId` at the TRANSPORT level, but — unlike
/// the peeroxide loop — the iroh accept path does NOT yet verify a `cluster_key`
/// HMAC proof (`cluster::peer_auth`) on a Hello before admitting gossip: peers
/// are admitted by `EndpointId` / `cluster.peers` seed only, so a remote that
/// reaches the ALPN can have frames evaluated without proving cluster
/// membership. The `accept_inbound` stack below still gates frame
/// acceptance/replay/band, but membership proof is missing. The cluster_key
/// Hello handshake (+ the WAL audit F19 + the shared `GossipState`/real
/// `self_id` F56) is tracked in GOLD `GR-RESID-IROH`; the iroh transport stays
/// EXPERIMENTAL (feature `cluster-iroh`, off by default; peeroxide is the
/// authenticated default carrier) until that lands.
pub fn gossip_handler(
    state: std::sync::Arc<std::sync::Mutex<crate::cluster::wal_sync::GossipState>>,
    writer: Option<Arc<WalWriterHandle>>,
) -> FrameHandler {
    use crate::cluster::gossip::GossipPolicy;
    use crate::cluster::gossip_wire::{GossipAcceptance, GossipFrame};
    let policy = GossipPolicy::default();
    std::sync::Arc::new(move |req: Vec<u8>| -> Vec<u8> {
        let reply = |accepted: bool, verdict: &str| {
            serde_json::to_vec(&serde_json::json!({ "accepted": accepted, "verdict": verdict }))
                .unwrap_or_default()
        };
        let frame: GossipFrame = match serde_json::from_slice(&req) {
            Ok(f) => f,
            Err(_) => {
                // F19 — a malformed inbound frame is a dropped gossip decision.
                emit_gossip_audit(&writer, false, "malformed", "unknown");
                return reply(false, "malformed");
            }
        };
        // payload's own event_type = byte 2 of the inner WAL header (foreign
        // frame → read without HMAC, exactly like the peeroxide loop).
        let payload_et = frame.payload.get(2).copied();
        let now = crate::time::now_unix_i64();
        let origin = frame.origin.as_str().to_string();
        let verdict = {
            let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
            let v = g.accept_inbound(&frame, payload_et, &policy, now);
            // accept_inbound is check-only since G02-CLUSTER-02. This path
            // has no foreign-event persistence step (idx_foreign_events
            // ingest is the peeroxide loop's job), so commit immediately —
            // preserving the pre-split dedup/VC semantics here.
            if matches!(v, GossipAcceptance::Accept) {
                g.commit_inbound(&frame);
            }
            v
        };
        let accepted = matches!(verdict, GossipAcceptance::Accept);
        let verdict_str = format!("{verdict:?}");
        // F19 — audit the inbound gossip decision (0xEE accepted / 0xEF dropped),
        // matching the peeroxide path's WAL coverage.
        emit_gossip_audit(&writer, accepted, &verdict_str, &origin);
        reply(accepted, &verdict_str)
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
    state: Arc<Mutex<crate::cluster::wal_sync::GossipState>>,
    self_id: crate::cluster::PeerPubkey,
    writer: Option<Arc<WalWriterHandle>>,
) -> tokio::task::JoinHandle<()> {
    use crate::cluster::gossip::GossipPolicy;
    use crate::cluster::wal_sync::collect_gossipable_frames;
    tokio::spawn(async move {
        let policy = GossipPolicy::default();
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
            let frame_count = frames.len();
            let mut delivered = 0usize;
            for (event_type, raw) in frames {
                let ts = crate::time::now_unix_i64();
                // F56 — build_outbound ticks + reads the SHARED vector clock.
                // Scope the std Mutex guard so it drops BEFORE the broadcast
                // await (a std guard is !Send and must never cross an await).
                let gframe_opt = {
                    let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
                    g.build_outbound(&self_id, event_type, raw, ts, &policy)
                };
                if let Some(gframe) = gframe_opt {
                    if let Ok(wire) = serde_json::to_vec(&gframe) {
                        delivered += transport.broadcast(&wire).await;
                    }
                }
            }
            // GR-RESID-IROH follow-up — send-side audit (0xED), parity with the
            // peeroxide gossip-tick. Only when frames actually went out so an
            // idle tick leaves no noise.
            if frame_count > 0 {
                emit_gossip_sent(&writer, frame_count, delivered, transport.peer_count());
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
        let a = IrohTransport::bind(handler, None, None)
            .await
            .expect("bind A");
        let b = IrohTransport::bind(Arc::new(|r| r), None, None)
            .await
            .expect("bind B");

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
        let handler = gossip_handler(state, None);
        // A non-GossipFrame byte blob must be rejected (decode failure), not
        // panic — and the reply is a parseable JSON verdict.
        let reply = handler(b"not a gossip frame".to_vec());
        let v: serde_json::Value = serde_json::from_slice(&reply).expect("json reply");
        assert_eq!(v["accepted"], false);
        assert_eq!(v["verdict"], "malformed");
    }

    // F19 — a rejected inbound gossip decision leaves a 0xEF CLUSTER_GOSSIP_DROPPED
    // WAL audit frame (the gap vs the peeroxide path that GR-RESID-IROH closes).
    #[tokio::test]
    async fn gossip_handler_emits_dropped_audit_for_malformed_frame() {
        use crate::cluster::wal_sync::GossipState;
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let writer = Arc::new(writer);
        let state = Arc::new(Mutex::new(GossipState::new()));
        let handler = gossip_handler(Arc::clone(&state), Some(Arc::clone(&writer)));
        let reply = handler(b"not a gossip frame".to_vec());
        let v: serde_json::Value = serde_json::from_slice(&reply).expect("json reply");
        assert_eq!(v["accepted"], false);
        // Release every WalWriterHandle sender (the test's + the closure's), then
        // drain so the queued audit frame is flushed before we read the segment.
        drop(handler);
        drop(writer);
        let _ = join.await;
        let bytes = std::fs::read(&seg).unwrap();
        let mut dropped = 0usize;
        let _ = crate::wal::scan::for_each_frame(&bytes, |_, d| {
            if d.header.event_type == EVENT_TYPE_CLUSTER_GOSSIP_DROPPED {
                dropped += 1;
            }
            Ok(())
        });
        assert_eq!(
            dropped, 1,
            "a malformed inbound gossip frame writes one 0xEF DROPPED audit"
        );
    }

    // GR-RESID-IROH follow-up — the send-side broadcast tick writes a 0xED
    // CLUSTER_GOSSIP_SENT audit, closing the F19 parity (receive + send).
    #[tokio::test]
    async fn emit_gossip_sent_writes_0xed_audit_frame() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let writer = Arc::new(writer);
        emit_gossip_sent(&Some(Arc::clone(&writer)), 3, 2, 1);
        drop(writer);
        let _ = join.await;
        let bytes = std::fs::read(&seg).unwrap();
        let mut sent = 0usize;
        let _ = crate::wal::scan::for_each_frame(&bytes, |_, d| {
            if d.header.event_type == EVENT_TYPE_CLUSTER_GOSSIP_SENT {
                sent += 1;
            }
            Ok(())
        });
        assert_eq!(
            sent, 1,
            "a non-empty broadcast tick writes one 0xED SENT audit"
        );
    }
}
