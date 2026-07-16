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
//!   `GossipFrame`, commits it through the shared durable sync state machine,
//!   and replies only with the exact post-commit ACK.
//! - [`IrohTransport::addr`] is the dial key (`EndpointAddr`) to share with
//!   peers — the iroh equivalent of a Hyperswarm topic ticket.
//! - [`IrohTransport::send_frame`] dials a peer by its `EndpointAddr` and does
//!   one request/response round-trip.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
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
const GOSSIP_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn bounded_gossip_send<F>(
    timeout: std::time::Duration,
    send: F,
) -> std::result::Result<F::Output, tokio::time::error::Elapsed>
where
    F: Future,
{
    tokio::time::timeout(timeout, send).await
}

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
pub const NEOTH_CLUSTER_ALPN: &[u8] = b"neoth/cluster/gossip/3";

/// Hard cap on a single gossip frame (DoS guard on the QUIC read). Gossip
/// frames are small (a vector clock + a band of WAL frames); 4 MiB is generous.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Maps an inbound request frame to the reply frame. Pure bytes in / bytes out
/// so the transport stays gossip-agnostic; the cluster supplies the real
/// `GossipFrame` decode → `accept_inbound` → `build_outbound` logic.
pub type FrameHandler = Arc<
    dyn Fn(crate::cluster::PeerPubkey, Vec<u8>) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
struct GossipProtocol {
    handler: FrameHandler,
    peers: PeerRegistry,
    /// D3 — every inbound connection must present a valid `cluster_key` HMAC
    /// proof (Hello prefix) before its frame reaches the handler.
    cluster_key: Arc<ClusterKey>,
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

        // D3 — the first CLUSTER_PROOF_BYTES of the stream are the peer's HMAC
        // proof and the gossip frame follows. A peer that can reach the ALPN but can't prove
        // cluster membership is dropped BEFORE add_peer / before its frame is
        // evaluated — parity with the peeroxide Hello gate. (iroh's QUIC channel
        // already authenticates the peer's EndpointId at the transport level; the
        // proof binds that id to our shared cluster_key, closing the
        // authorization gap.)
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
        let claimed: [u8; 32] = proof
            .try_into()
            .expect("split_at(32) yields exactly 32 bytes");
        if !verify_peer_proof(
            &self.cluster_key,
            &claimed,
            peer_id.as_bytes(),
            self.our_id.as_bytes(),
        ) {
            emit_gossip_audit(
                &self.writer,
                false,
                "peer_auth_failed",
                &peer_id.to_string(),
            );
            return Ok(()); // reject: not a proven cluster member
        }
        let frame = frame.to_vec();

        // Bind the logical gossip origin to the authenticated QUIC endpoint.
        // Without this check a valid cluster member could write rows under a
        // different peer identity and poison that peer's dedup namespace.
        let authenticated_origin = peer_id.to_string();
        let origin_matches =
            serde_json::from_slice::<crate::cluster::gossip_wire::GossipFrame>(&frame)
                .ok()
                .is_some_and(|gossip| gossip.origin.as_str() == authenticated_origin);
        if !origin_matches {
            emit_gossip_audit(
                &self.writer,
                false,
                "peer_origin_mismatch",
                &authenticated_origin,
            );
            return Ok(());
        }

        // Proof OK → learn this peer's dial key so we can
        // gossip BACK to it (outbound broadcast).
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(peer_id);
        let reply =
            (self.handler)(crate::cluster::PeerPubkey::new(authenticated_origin), frame).await;
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
    /// D3 — our cluster_key. The dial side prepends a Hello proof on every send.
    cluster_key: Arc<ClusterKey>,
}

impl IrohTransport {
    /// Bind an endpoint (with iroh's N0 relay/discovery preset) and start
    /// accepting NEOTH cluster connections. Resolves once the endpoint is
    /// online (has a reachable address / relay home).
    ///
    /// `cluster_key` (D3) is mandatory at the type boundary: the accept path
    /// requires a valid proof on every inbound connection and the dial path
    /// prepends ours. `writer` (F19) is the gossip-decision audit sink.
    pub async fn bind(
        handler: FrameHandler,
        cluster_key: Arc<ClusterKey>,
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
                    cluster_key: Arc::clone(&cluster_key),
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

    pub fn known_peers(&self) -> Vec<EndpointId> {
        let mut peers: Vec<_> = self
            .peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect();
        peers.sort_by_key(|peer| peer.to_string());
        peers
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
            if let Ok(reply) = self.send_frame(peer, frame).await
                && serde_json::from_slice::<crate::cluster::gossip_wire::GossipAck>(&reply).is_ok()
            {
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
        let our_id = self.router.endpoint().id();
        let peer_id = conn.remote_id();
        let proof =
            compute_cluster_key_proof(&self.cluster_key, our_id.as_bytes(), peer_id.as_bytes());
        send.write_all(&proof)
            .await
            .map_err(|e| anyhow::anyhow!("iroh: write proof: {e}"))?;
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
    ///
    /// The router shutdown API is shared-reference based and idempotent, so do
    /// not require unique ownership here. Shutdown must remain effective if a
    /// future observer temporarily holds another `Arc<IrohTransport>`; making
    /// teardown depend on `Arc::try_unwrap` can otherwise retain the inbound
    /// handler's WAL sender and deadlock the writer drain.
    pub async fn shutdown(&self) -> Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("iroh: router shutdown: {e}"))?;
        Ok(())
    }
}

/// A gossip-aware [`FrameHandler`] — the iroh↔gossip bridge for the live-flip.
///
/// It routes every inbound frame through the SAME durable state machine the
/// peeroxide path uses: authenticated origin binding, version/digest/CRC/ACL
/// validation, contiguous sequence enforcement, transactional content and
/// receipt persistence, then an exact ACK after COMMIT.
///
/// **(1) node capabilities** are checked downstream as on the peeroxide path.
///
/// **(3) peer trust** is enforced by `GossipProtocol` before this handler runs:
/// iroh authenticates the remote `EndpointId`, then the Hello prefix proves
/// shared-cluster membership with an asymmetric HMAC over both transport
/// identities. Missing or invalid proofs are rejected before peer admission and
/// audited as dropped gossip. Production and test transports both require an
/// explicit cluster key at construction.
pub fn gossip_handler(
    state: crate::cluster::wal_sync::SharedGossipState,
    persist_tx: Option<crate::cluster::wal_sync::ForeignPersistTx>,
    writer: Option<Arc<WalWriterHandle>>,
    reload_controller: Arc<crate::config::reload::ReloadController>,
) -> FrameHandler {
    use crate::cluster::gossip_wire::GossipFrame;
    std::sync::Arc::new(move |authenticated_peer, req: Vec<u8>| {
        let persist_tx = persist_tx.clone();
        let writer = writer.clone();
        let state = Arc::clone(&state);
        let reload_controller = Arc::clone(&reload_controller);
        Box::pin(async move {
            let reject = |verdict: &str| {
                serde_json::to_vec(&serde_json::json!({
                    "accepted": false,
                    "verdict": verdict,
                }))
                .unwrap_or_default()
            };
            let frame: GossipFrame = match serde_json::from_slice(&req) {
                Ok(frame) => frame,
                Err(_) => {
                    emit_gossip_audit(&writer, false, "malformed", authenticated_peer.as_str());
                    return reject("malformed");
                }
            };
            if frame.origin != authenticated_peer {
                emit_gossip_audit(
                    &writer,
                    false,
                    "peer_origin_mismatch",
                    authenticated_peer.as_str(),
                );
                return reject("peer_origin_mismatch");
            }
            let frame_for_frontier = frame.clone();
            let Some(tx) = persist_tx else {
                emit_gossip_audit(
                    &writer,
                    false,
                    "durable_writer_unavailable",
                    authenticated_peer.as_str(),
                );
                return reject("durable_writer_unavailable");
            };
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let job = crate::cluster::wal_sync::ForeignPersistJob {
                authenticated_peer: authenticated_peer.clone(),
                frame,
                policy: reload_controller.gossip_policy(),
                reply: reply_tx,
            };
            match tx.try_send(job) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    emit_gossip_audit(
                        &writer,
                        false,
                        "durable_writer_full",
                        authenticated_peer.as_str(),
                    );
                    return reject("durable_writer_full");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    emit_gossip_audit(
                        &writer,
                        false,
                        "durable_writer_closed",
                        authenticated_peer.as_str(),
                    );
                    return reject("durable_writer_closed");
                }
            }
            match reply_rx.await {
                Ok(Ok(commit @ crate::cluster::durable_sync::InboundCommit::Committed(_)))
                | Ok(Ok(commit @ crate::cluster::durable_sync::InboundCommit::Duplicate(_)))
                | Ok(Ok(
                    commit @ crate::cluster::durable_sync::InboundCommit::DuplicateUnbound(_),
                )) => {
                    let frontier_merged =
                        crate::cluster::durable_sync::merge_frontier_after_durable_commit(
                            &state,
                            &frame_for_frontier,
                            &commit,
                        );
                    let ack = commit
                        .ack()
                        .expect("committed/duplicate inbound has an ACK");
                    let verdict = if frontier_merged {
                        "committed"
                    } else {
                        "duplicate_unbound"
                    };
                    emit_gossip_audit(&writer, true, verdict, authenticated_peer.as_str());
                    serde_json::to_vec(&ack).unwrap_or_default()
                }
                Ok(Ok(crate::cluster::durable_sync::InboundCommit::Gap { expected, received })) => {
                    let verdict = format!("sequence_gap:{expected}:{received}");
                    emit_gossip_audit(&writer, false, &verdict, authenticated_peer.as_str());
                    reject(&verdict)
                }
                Ok(Ok(crate::cluster::durable_sync::InboundCommit::Dropped(verdict))) => {
                    let verdict = format!("{verdict:?}");
                    emit_gossip_audit(&writer, false, &verdict, authenticated_peer.as_str());
                    reject(&verdict)
                }
                Ok(Err(error)) => {
                    emit_gossip_audit(
                        &writer,
                        false,
                        "db_commit_failed",
                        authenticated_peer.as_str(),
                    );
                    tracing::warn!(%error, peer = %authenticated_peer.as_str(), "iroh durable mesh commit failed; ACK withheld");
                    reject("db_commit_failed")
                }
                Err(_) => reject("durable_writer_reply_dropped"),
            }
        })
    })
}

/// Outbound gossip broadcast tick for iroh — the send-side counterpart to
/// `wal_sync::spawn_gossip_tick` (which serves the peeroxide streams). Every 30s
/// it cycles every live or sealed WAL segment using the same per-peer durable
/// cursor and pending-frame store as peeroxide, then sends one bare
/// `GossipFrame` (JSON) per known peer. Only an exact authenticated ACK advances
/// that peer's cursor.
pub fn spawn_gossip_broadcast(
    transport: Arc<IrohTransport>,
    segment_path: std::path::PathBuf,
    state: crate::cluster::wal_sync::SharedGossipState,
    self_id: crate::cluster::PeerPubkey,
    writer: Option<Arc<WalWriterHandle>>,
    reload_controller: Arc<crate::config::reload::ReloadController>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let wal_dir = segment_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let db_path = wal_dir
            .parent()
            .map(|home| home.join("views.db"))
            .unwrap_or_else(|| std::path::PathBuf::from("views.db"));
        let durable = crate::cluster::durable_sync::DurableMeshSync::new(db_path);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if transport.peer_count() == 0 {
                continue; // no peers ⇒ nothing to gossip
            }
            let policy = reload_controller.gossip_policy();

            let mut delivered = 0usize;
            for endpoint in transport.known_peers() {
                let peer = crate::cluster::PeerPubkey::new(endpoint.to_string());
                match durable
                    .prepare_peer_frame(&peer, &self_id, &wal_dir, &policy, &state)
                    .await
                {
                    Ok(Some(prepared)) => {
                        let Ok(wire) = serde_json::to_vec(&prepared.frame) else {
                            continue;
                        };
                        let attempt_store = durable.clone();
                        let attempt_peer = peer.clone();
                        match tokio::task::spawn_blocking(move || {
                            attempt_store.record_send_attempt(&attempt_peer)
                        })
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh attempt persistence failed closed");
                                continue;
                            }
                            Err(error) => {
                                tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh attempt task panicked");
                                continue;
                            }
                        }
                        match bounded_gossip_send(
                            GOSSIP_SEND_TIMEOUT,
                            transport.send_frame(endpoint, &wire),
                        )
                        .await
                        {
                            Ok(Ok(reply)) => {
                                let Ok(ack) = serde_json::from_slice::<
                                    crate::cluster::gossip_wire::GossipAck,
                                >(&reply) else {
                                    tracing::warn!(peer = %peer.as_str(), "iroh mesh peer withheld or returned malformed ACK");
                                    continue;
                                };
                                let ack_store = durable.clone();
                                let ack_peer = peer.clone();
                                let ack_origin = self_id.clone();
                                match tokio::task::spawn_blocking(move || {
                                    ack_store.acknowledge_outbound(&ack_peer, &ack_origin, &ack)
                                })
                                .await
                                {
                                    Ok(Ok(_)) => delivered += 1,
                                    Ok(Err(error)) => {
                                        tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh ACK rejected")
                                    }
                                    Err(error) => {
                                        tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh ACK task panicked")
                                    }
                                }
                            }
                            Ok(Err(error)) => {
                                tracing::debug!(%error, peer = %peer.as_str(), "iroh mesh send failed; pending frame retained")
                            }
                            Err(_) => tracing::warn!(
                                peer = %peer.as_str(),
                                timeout_secs = GOSSIP_SEND_TIMEOUT.as_secs(),
                                "iroh mesh peer timed out; pending frame retained"
                            ),
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(%error, peer = %peer.as_str(), "iroh durable mesh prepare failed closed")
                    }
                }
            }
            // Send-side audit (0xED), parity with the peeroxide gossip tick.
            // Only emit when frames actually went out so an idle tick leaves
            // no noise.
            if delivered > 0 {
                emit_gossip_sent(&writer, delivered, delivered, transport.peer_count());
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stalled_peer_send_is_bounded_by_the_gossip_timeout() {
        let stalled = std::future::pending::<anyhow::Result<Vec<u8>>>();
        let outcome = bounded_gossip_send(std::time::Duration::ZERO, stalled).await;
        assert!(
            outcome.is_err(),
            "a peer that never resolves must hit the send timeout"
        );
    }

    fn test_cluster_key() -> Arc<ClusterKey> {
        Arc::new(ClusterKey([0x42; 32]))
    }

    fn test_reload_controller() -> Arc<crate::config::reload::ReloadController> {
        Arc::new(crate::config::reload::ReloadController::new(
            crate::config::FreedomConfig::default(),
            std::path::PathBuf::from("missing-freedom.yaml"),
        ))
    }

    /// Two endpoints, one round-trip: B dials A by key, A's handler replies.
    /// Proves the real iroh send/accept path (bind → connect → bi-stream →
    /// handler → reply) works end-to-end. `#[ignore]` — it brings up real iroh
    /// endpoints (relay/discovery), so it needs a network; run manually:
    /// `cargo test -p neoth --features cluster-iroh loopback_frame_round_trip -- --ignored`.
    #[tokio::test]
    #[ignore = "real iroh endpoints — needs network (relay/discovery)"]
    async fn loopback_frame_round_trip() {
        // A echoes "<req>+ack".
        let handler: FrameHandler = Arc::new(|_, req: Vec<u8>| {
            Box::pin(async move {
                let mut reply = req;
                reply.extend_from_slice(b"+ack");
                reply
            })
        });
        let a = IrohTransport::bind(handler, test_cluster_key(), None)
            .await
            .expect("bind A");
        let b = IrohTransport::bind(
            Arc::new(|_, bytes| Box::pin(async move { bytes })),
            test_cluster_key(),
            None,
        )
        .await
        .expect("bind B");

        let payload = vec![1, 2, 3];
        let envelope = crate::cluster::gossip_wire::SyncEnvelope {
            version: crate::cluster::gossip_wire::SYNC_ENVELOPE_VERSION,
            content_id: "iroh-loopback".into(),
            updated_at_unix: crate::time::now_unix_i64(),
            content: crate::cluster::gossip_wire::SyncContent::Metadata {
                event_type: 0x94,
                event_subtype: 0,
                wal_frame: payload.clone(),
            },
        };
        let request = crate::cluster::gossip_wire::GossipFrame {
            protocol_version: crate::cluster::gossip_wire::SYNC_PROTOCOL_VERSION,
            vector_clock: crate::cluster::gossip_wire::VectorClock::new(),
            origin: crate::cluster::PeerPubkey::new(b.node_id()),
            event_seq: 1,
            content_sha256: envelope.content_sha256(),
            timestamp_unix: crate::time::now_unix_i64(),
            tag: crate::cluster::gossip::GossipTag::Replicate,
            payload,
            envelope,
        };
        let request = serde_json::to_vec(&request).unwrap();
        let reply = b.send_frame(a.addr(), &request).await.expect("round-trip");
        let mut expected = request;
        expected.extend_from_slice(b"+ack");
        assert_eq!(reply, expected);

        a.shutdown().await.expect("shutdown A");
        b.shutdown().await.expect("shutdown B");
    }

    #[test]
    fn alpn_is_versioned() {
        assert!(NEOTH_CLUSTER_ALPN.ends_with(b"/3"));
    }

    #[tokio::test]
    async fn gossip_handler_rejects_malformed_and_replies_json() {
        use crate::cluster::wal_sync::GossipState;
        let state = std::sync::Arc::new(std::sync::Mutex::new(GossipState::new()));
        let handler = gossip_handler(state, None, None, test_reload_controller());
        // A non-GossipFrame byte blob must be rejected (decode failure), not
        // panic — and the reply is a parseable JSON verdict.
        let reply = handler(
            crate::cluster::PeerPubkey::new("test-peer"),
            b"not a gossip frame".to_vec(),
        )
        .await;
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
        let (writer, join) =
            crate::wal::spawn_for_home(seg.clone(), dir.path().to_path_buf()).unwrap();
        let writer = Arc::new(writer);
        let state = Arc::new(Mutex::new(GossipState::new()));
        let handler = gossip_handler(
            Arc::clone(&state),
            None,
            Some(Arc::clone(&writer)),
            test_reload_controller(),
        );
        let reply = handler(
            crate::cluster::PeerPubkey::new("test-peer"),
            b"not a gossip frame".to_vec(),
        )
        .await;
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

    #[tokio::test]
    async fn dropping_gossip_handler_releases_its_wal_sender() {
        use crate::cluster::wal_sync::GossipState;

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn_for_home(seg, dir.path().to_path_buf()).unwrap();
        let writer = Arc::new(writer);
        let weak = Arc::downgrade(&writer);
        let handler = gossip_handler(
            Arc::new(Mutex::new(GossipState::new())),
            None,
            Some(Arc::clone(&writer)),
            test_reload_controller(),
        );

        drop(writer);
        assert!(
            weak.upgrade().is_some(),
            "the live inbound handler owns the audit sender"
        );
        drop(handler);
        assert!(
            weak.upgrade().is_none(),
            "transport teardown must release the handler-owned audit sender"
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .expect("WAL writer exits after the final handler sender is released")
            .expect("WAL writer task joins cleanly");
    }

    #[tokio::test]
    async fn iroh_handler_ack_is_after_durable_commit() {
        use crate::cluster::gossip_wire::{
            GossipFrame, SYNC_ENVELOPE_VERSION, SYNC_PROTOCOL_VERSION, SyncContent, SyncEnvelope,
            VectorClock,
        };
        use crate::cluster::wal_sync::GossipState;
        use sha2::Digest as _;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let (persist_tx, persist_join) =
            crate::cluster::wal_sync::spawn_foreign_persist_writer(db_path.clone());
        let inner = br#"{"event_count":1}"#;
        let header = crate::wal::HeaderBuilder::new(0x94, inner).build();
        let payload = crate::wal::frame::encode_frame(&header, inner);
        let timestamp = crate::cluster::wal_sync::gossip_payload_timestamp_unix(&payload).unwrap();
        let envelope = SyncEnvelope {
            version: SYNC_ENVELOPE_VERSION,
            content_id: format!("metadata:{}", hex::encode(sha2::Sha256::digest(&payload))),
            updated_at_unix: timestamp,
            content: SyncContent::Metadata {
                event_type: 0x94,
                event_subtype: 0,
                wal_frame: payload.clone(),
            },
        };
        let origin = crate::cluster::PeerPubkey::new("iroh-peer-pk");
        let frame = GossipFrame {
            protocol_version: SYNC_PROTOCOL_VERSION,
            vector_clock: VectorClock::new(),
            origin: origin.clone(),
            event_seq: 1,
            content_sha256: envelope.content_sha256(),
            timestamp_unix: timestamp,
            tag: crate::cluster::gossip::GossipTag::Replicate,
            payload,
            envelope,
        };
        let receiver = Arc::new(Mutex::new(GossipState::new()));
        let handler = gossip_handler(
            receiver,
            Some(persist_tx.clone()),
            None,
            test_reload_controller(),
        );
        let reply = handler(origin, serde_json::to_vec(&frame).unwrap()).await;
        let ack: crate::cluster::gossip_wire::GossipAck =
            serde_json::from_slice(&reply).expect("post-commit ACK");
        assert_eq!(ack.origin_seq, 1);
        let conn = crate::memory::store::open(&db_path).unwrap();
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM idx_foreign_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            rows, 1,
            "ACK is observable only after the foreign row committed"
        );
        drop(conn);
        drop(handler);
        drop(persist_tx);
        persist_join.await.unwrap();
    }

    // GR-RESID-IROH follow-up — the send-side broadcast tick writes a 0xED
    // CLUSTER_GOSSIP_SENT audit, closing the F19 parity (receive + send).
    #[tokio::test]
    async fn emit_gossip_sent_writes_0xed_audit_frame() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) =
            crate::wal::spawn_for_home(seg.clone(), dir.path().to_path_buf()).unwrap();
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
