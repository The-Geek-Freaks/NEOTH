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

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};

use crate::cluster::discovery::ClusterKey;
use crate::cluster::membership::{
    CarrierKind, MembershipGrant, MembershipStore, StableNodeId, TransportIdentity,
};
use crate::cluster::peer_auth::{compute_cluster_key_proof, verify_peer_proof};
use crate::wal::events::{
    EVENT_TYPE_CLUSTER_GOSSIP_DROPPED, EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED,
    EVENT_TYPE_CLUSTER_GOSSIP_SENT,
};
use crate::wal::writer::WalWriterHandle;

/// Shared set of known peer endpoint-ids (dial keys). Learned from inbound
/// connections + seeded from `cluster.peers` in freedom.yaml.
pub type PeerRegistry = Arc<Mutex<HashMap<EndpointId, MembershipGrant>>>;

#[derive(Default)]
struct IrohLiveRegistry {
    next_generation: AtomicU64,
    sessions: Mutex<HashMap<(StableNodeId, u64), Connection>>,
}

impl IrohLiveRegistry {
    fn register(
        self: &Arc<Self>,
        stable_node_id: StableNodeId,
        connection: Connection,
    ) -> IrohSessionGuard {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((stable_node_id.clone(), generation), connection);
        IrohSessionGuard {
            registry: Arc::clone(self),
            stable_node_id,
            generation,
        }
    }

    fn close_stable_node(&self, stable_node_id: &StableNodeId) -> (usize, usize) {
        let connections = {
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let keys = sessions
                .keys()
                .filter(|(stable, _)| stable == stable_node_id)
                .cloned()
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|key| sessions.remove(&key))
                .collect::<Vec<_>>()
        };
        let signalled = connections.len();
        let mut closed = 0usize;
        for connection in connections {
            connection.close(0u32.into(), b"membership revoked");
            if connection.close_reason().is_some() {
                closed += 1;
            }
        }
        (signalled, closed)
    }
}

struct IrohSessionGuard {
    registry: Arc<IrohLiveRegistry>,
    stable_node_id: StableNodeId,
    generation: u64,
}

impl Drop for IrohSessionGuard {
    fn drop(&mut self) {
        self.registry
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&(self.stable_node_id.clone(), self.generation));
    }
}

/// D3 — length of the `cluster_key` HMAC proof carried as the Hello prefix on
/// every authenticated gossip stream (32-byte HMAC-SHA256, see
/// [`crate::cluster::peer_auth`]).
const CLUSTER_PROOF_BYTES: usize = 32;
const GOSSIP_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Match the public Hyperswarm ingress cap: healthy clusters are single-digit,
/// while a flood must not create an unbounded number of live QUIC handlers.
const MAX_CONCURRENT_INBOUND_GOSSIP: usize = 64;
/// Pre-auth work is deliberately short: no membership/effect state exists yet.
const GOSSIP_PRE_AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Admitted I/O may include a durable commit and therefore gets the larger
/// existing gossip network budget.
const GOSSIP_ADMITTED_TIMEOUT: std::time::Duration = GOSSIP_SEND_TIMEOUT;
const IROH_REJECT_CODE: u32 = 0;

#[derive(Clone, Copy, Debug)]
struct IrohInboundTimeouts {
    pre_auth: std::time::Duration,
    admitted: std::time::Duration,
}

impl Default for IrohInboundTimeouts {
    fn default() -> Self {
        Self {
            pre_auth: GOSSIP_PRE_AUTH_TIMEOUT,
            admitted: GOSSIP_ADMITTED_TIMEOUT,
        }
    }
}

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
    operator_requested: usize,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "frame_count": frame_count,
        "delivered": delivered,
        "peer_count": peer_count,
        "operator_requested": operator_requested,
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
pub struct AuthorizedFrameReply {
    pub bytes: Vec<u8>,
    effect_guard: Option<crate::cluster::membership::MembershipEffectGuard>,
}

impl AuthorizedFrameReply {
    fn rejected(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            effect_guard: None,
        }
    }

    fn authorized(
        bytes: Vec<u8>,
        effect_guard: crate::cluster::membership::MembershipEffectGuard,
    ) -> Self {
        Self {
            bytes,
            effect_guard: Some(effect_guard),
        }
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        if let Some(effect_guard) = self.effect_guard.take() {
            effect_guard.finish()?;
        }
        Ok(self.bytes)
    }
}

struct AuthorizedOutboundReply {
    bytes: Vec<u8>,
    effect_guard: crate::cluster::membership::MembershipEffectGuard,
}

impl AuthorizedOutboundReply {
    fn finish(self) -> Result<Vec<u8>> {
        self.effect_guard.finish()?;
        Ok(self.bytes)
    }
}

pub type FrameHandler = Arc<
    dyn Fn(MembershipGrant, Vec<u8>) -> Pin<Box<dyn Future<Output = AuthorizedFrameReply> + Send>>
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
    membership_store: MembershipStore,
    live_sessions: Arc<IrohLiveRegistry>,
    /// D3 reject-audit sink (gossip-dropped frames for the peer-auth path).
    writer: Option<Arc<WalWriterHandle>>,
    /// Shared across every cloned router handler. Acquired before `accept_bi`
    /// so unauthenticated peers cannot park unbounded accept/proof futures.
    inbound_slots: Arc<tokio::sync::Semaphore>,
    timeouts: IrohInboundTimeouts,
}

// `ProtocolHandler` requires `Debug`, but `FrameHandler` (a boxed closure) can't
// derive it — provide an opaque one.
impl std::fmt::Debug for GossipProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipProtocol").finish_non_exhaustive()
    }
}

impl GossipProtocol {
    fn reject(
        &self,
        connection: &Connection,
        peer_id: EndpointId,
        verdict: &str,
        close_reason: &'static [u8],
    ) {
        emit_gossip_audit(&self.writer, false, verdict, &peer_id.to_string());
        connection.close(IROH_REJECT_CODE.into(), close_reason);
    }
}

impl ProtocolHandler for GossipProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer_id = connection.remote_id();
        let _inbound_slot = match Arc::clone(&self.inbound_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    peer = %peer_id,
                    max = MAX_CONCURRENT_INBOUND_GOSSIP,
                    "iroh: inbound gossip limit reached — rejecting connection"
                );
                self.reject(
                    &connection,
                    peer_id,
                    "inbound_capacity_exhausted",
                    b"inbound capacity",
                );
                return Ok(());
            }
        };
        // One inbound bi-stream per connection = one gossip request/response.
        let (mut send, mut recv) =
            match tokio::time::timeout(self.timeouts.pre_auth, connection.accept_bi()).await {
                Ok(Ok(streams)) => streams,
                Ok(Err(error)) => {
                    self.reject(
                        &connection,
                        peer_id,
                        "accept_bi_failed",
                        b"accept stream failed",
                    );
                    return Err(error.into());
                }
                Err(_) => {
                    self.reject(
                        &connection,
                        peer_id,
                        "accept_bi_timeout",
                        b"accept stream timeout",
                    );
                    return Ok(());
                }
            };
        // D3 — read only the fixed proof before allowing a 4 MiB allocation.
        // Unknown/passphrase-only peers fail here without frame allocation.
        let mut claimed = [0_u8; CLUSTER_PROOF_BYTES];
        match tokio::time::timeout(self.timeouts.pre_auth, recv.read_exact(&mut claimed)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                self.reject(
                    &connection,
                    peer_id,
                    "peer_auth_missing_proof",
                    b"proof incomplete",
                );
                return Ok(());
            }
            Err(_) => {
                self.reject(
                    &connection,
                    peer_id,
                    "peer_auth_proof_timeout",
                    b"proof timeout",
                );
                return Ok(());
            }
        }

        // The first CLUSTER_PROOF_BYTES of the stream are the peer's HMAC
        // proof and the gossip frame follows. A peer that can reach the ALPN but can't prove
        // cluster membership is dropped BEFORE add_peer / before its frame is
        // evaluated — parity with the peeroxide Hello gate. (iroh's QUIC channel
        // already authenticates the peer's EndpointId at the transport level; the
        // proof binds that id to our shared cluster_key, closing the
        // authorization gap.)
        if !verify_peer_proof(
            &self.cluster_key,
            &claimed,
            peer_id.as_bytes(),
            self.our_id.as_bytes(),
        ) {
            self.reject(&connection, peer_id, "peer_auth_failed", b"proof rejected");
            return Ok(()); // reject: not a proven cluster member
        }
        let authenticated_transport = match TransportIdentity::parse(peer_id.to_string()) {
            Ok(identity) => identity,
            Err(error) => {
                self.reject(
                    &connection,
                    peer_id,
                    "transport_identity_invalid",
                    b"identity rejected",
                );
                tracing::debug!(%error, "iroh membership transport identity invalid");
                return Ok(());
            }
        };
        let membership_grant = match self.membership_store.admit(
            CarrierKind::Iroh,
            &authenticated_transport,
            crate::time::now_unix_i64(),
        ) {
            Ok(grant) => grant,
            Err(error) => {
                self.reject(
                    &connection,
                    peer_id,
                    "membership_rejected",
                    b"membership rejected",
                );
                tracing::debug!(%error, "iroh membership admission rejected");
                return Ok(());
            }
        };
        let mut session_effect = membership_grant
            .begin_effect(crate::time::now_unix_i64())
            .map_err(|error| AcceptError::from_err(std::io::Error::other(error.to_string())))?;
        let _live_session = self.live_sessions.register(
            membership_grant.stable_node_id().clone(),
            connection.clone(),
        );
        let frame = match tokio::time::timeout(
            self.timeouts.admitted,
            recv.read_to_end(MAX_FRAME_BYTES - CLUSTER_PROOF_BYTES),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => {
                self.reject(
                    &connection,
                    peer_id,
                    "frame_read_failed",
                    b"frame read failed",
                );
                return Err(AcceptError::from_err(error));
            }
            Err(_) => {
                self.reject(&connection, peer_id, "frame_read_timeout", b"frame timeout");
                return Ok(());
            }
        };

        // Bind the logical gossip origin to the authenticated QUIC endpoint.
        // Without this check a valid cluster member could write rows under a
        // different peer identity and poison that peer's dedup namespace.
        let authenticated_origin = membership_grant.stable_node_id().as_str();
        let origin_matches =
            serde_json::from_slice::<crate::cluster::gossip_wire::GossipFrame>(&frame)
                .ok()
                .is_some_and(|gossip| gossip.origin.as_str() == authenticated_origin);
        if !origin_matches {
            self.reject(
                &connection,
                peer_id,
                "peer_origin_mismatch",
                b"origin rejected",
            );
            return Ok(());
        }

        let reply = match tokio::time::timeout(
            self.timeouts.admitted,
            (self.handler)(membership_grant.clone(), frame),
        )
        .await
        {
            Ok(reply) => reply,
            Err(_) => {
                self.reject(
                    &connection,
                    peer_id,
                    "frame_handler_timeout",
                    b"handler timeout",
                );
                return Ok(());
            }
        };
        let mut outbound = session_effect
            .begin_external(crate::time::now_unix_i64())
            .map_err(|error| AcceptError::from_err(std::io::Error::other(error.to_string())))?;
        outbound.mark_transport_may_have_started();
        let write_result = tokio::select! {
            biased;
            _ = outbound.cancelled() => {
                outbound.persist_indeterminate_if_cancelled(
                    "iroh_reply_write_locally_aborted_without_remote_read_ack",
                    crate::time::now_unix_i64(),
                ).map_err(|error| {
                    AcceptError::from_err(std::io::Error::other(error.to_string()))
                })?;
                return Err(AcceptError::from_err(std::io::Error::other(
                    "iroh membership revoked while writing reply",
                )));
            }
            result = tokio::time::timeout(
                self.timeouts.admitted,
                send.write_all(&reply.bytes),
            ) => result,
        };
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                connection.close(IROH_REJECT_CODE.into(), b"reply write failed");
                outbound
                    .persist_indeterminate_if_cancelled(
                        "iroh_reply_write_failed_during_membership_revocation",
                        crate::time::now_unix_i64(),
                    )
                    .map_err(|persist_error| {
                        AcceptError::from_err(std::io::Error::other(persist_error.to_string()))
                    })?;
                return Err(AcceptError::from_err(error));
            }
            Err(_) => {
                self.reject(
                    &connection,
                    peer_id,
                    "reply_write_timeout",
                    b"reply timeout",
                );
                outbound
                    .persist_indeterminate_if_cancelled(
                        "iroh_reply_write_timed_out_during_membership_revocation",
                        crate::time::now_unix_i64(),
                    )
                    .map_err(|persist_error| {
                        AcceptError::from_err(std::io::Error::other(persist_error.to_string()))
                    })?;
                return Err(AcceptError::from_err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "iroh reply write timed out",
                )));
            }
        }
        if let Err(error) = send.finish() {
            connection.close(IROH_REJECT_CODE.into(), b"reply finish failed");
            outbound
                .persist_indeterminate_if_cancelled(
                    "iroh_reply_finish_failed_during_membership_revocation",
                    crate::time::now_unix_i64(),
                )
                .map_err(|persist_error| {
                    AcceptError::from_err(std::io::Error::other(persist_error.to_string()))
                })?;
            return Err(AcceptError::from_err(error));
        }
        if let Err(error) = reply.finish() {
            outbound
                .persist_indeterminate_if_cancelled(
                    "iroh_reply_classification_failed_during_membership_revocation",
                    crate::time::now_unix_i64(),
                )
                .map_err(|persist_error| {
                    AcceptError::from_err(std::io::Error::other(persist_error.to_string()))
                })?;
            return Err(AcceptError::from_err(std::io::Error::other(
                error.to_string(),
            )));
        }
        // The peer close is the only acknowledgement available that it
        // consumed the reply. Keep the external permit until that boundary.
        let remote_close_result = tokio::select! {
            biased;
            _ = outbound.cancelled() => {
                outbound.persist_indeterminate_if_cancelled(
                    "iroh_reply_finished_without_remote_read_ack",
                    crate::time::now_unix_i64(),
                ).map_err(|error| {
                    AcceptError::from_err(std::io::Error::other(error.to_string()))
                })?;
                return Err(AcceptError::from_err(std::io::Error::other(
                    "iroh membership revoked before remote reply acknowledgement",
                )));
            }
            result = tokio::time::timeout(
                self.timeouts.admitted,
                connection.closed(),
            ) => result,
        };
        if remote_close_result.is_err() {
            self.reject(
                &connection,
                peer_id,
                "remote_close_ack_timeout",
                b"remote close timeout",
            );
            outbound
                .persist_indeterminate_if_cancelled(
                    "iroh_reply_remote_ack_timed_out_during_membership_revocation",
                    crate::time::now_unix_i64(),
                )
                .map_err(|persist_error| {
                    AcceptError::from_err(std::io::Error::other(persist_error.to_string()))
                })?;
            return Err(AcceptError::from_err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "iroh remote reply acknowledgement timed out",
            )));
        }
        if let Err(error) = outbound.validate(crate::time::now_unix_i64()) {
            outbound
                .persist_indeterminate_if_cancelled(
                    "iroh_reply_write_completed_without_remote_read_ack",
                    crate::time::now_unix_i64(),
                )
                .map_err(|persist_error| {
                    AcceptError::from_err(std::io::Error::other(persist_error.to_string()))
                })?;
            return Err(AcceptError::from_err(std::io::Error::other(
                error.to_string(),
            )));
        }
        drop(outbound);
        // Publish the dial route only while the admitted session generation is
        // still live. Revoke captures this session effect, closes the QUIC
        // connection, and waits for the final check/drop ACK. If authority
        // changes between insertion and finish, remove the just-published route
        // before acknowledging session completion.
        session_effect
            .validate(crate::time::now_unix_i64())
            .map_err(|error| AcceptError::from_err(std::io::Error::other(error.to_string())))?;
        self.peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_id, membership_grant.clone());
        if let Err(error) = session_effect.finish() {
            prune_stable_node_routes(&self.peers, membership_grant.stable_node_id());
            return Err(AcceptError::from_err(std::io::Error::other(
                error.to_string(),
            )));
        }
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
    membership_store: MembershipStore,
    live_sessions: Arc<IrohLiveRegistry>,
}

impl IrohTransport {
    /// Bind an endpoint (with iroh's N0 relay/discovery preset) and start
    /// accepting NEOTH cluster connections. Resolves once the endpoint is
    /// online (has a reachable address / relay home).
    ///
    /// `cluster_key` (D3) is mandatory at the type boundary: the accept path
    /// requires a valid proof on every inbound connection and the dial path
    /// prepends ours. `writer` (F19) is the gossip-decision audit sink.
    #[cfg(test)]
    pub async fn bind(
        handler: FrameHandler,
        cluster_key: Arc<ClusterKey>,
        writer: Option<Arc<WalWriterHandle>>,
        membership_store: MembershipStore,
    ) -> Result<Self> {
        Self::bind_with_secret(
            handler,
            cluster_key,
            writer,
            iroh::SecretKey::generate(),
            membership_store,
        )
        .await
    }

    /// Bind with an explicitly owned endpoint identity. The runtime supervisor
    /// uses this boundary so one cluster-key generation keeps a stable dial id
    /// across daemon restarts instead of silently minting a new peer identity.
    pub async fn bind_with_secret(
        handler: FrameHandler,
        cluster_key: Arc<ClusterKey>,
        writer: Option<Arc<WalWriterHandle>>,
        endpoint_secret: iroh::SecretKey,
        membership_store: MembershipStore,
    ) -> Result<Self> {
        let peers: PeerRegistry = Arc::new(Mutex::new(HashMap::new()));
        let live_sessions = Arc::new(IrohLiveRegistry::default());
        let inbound_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_INBOUND_GOSSIP));
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(endpoint_secret)
            .bind()
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
                    membership_store: membership_store.clone(),
                    live_sessions: Arc::clone(&live_sessions),
                    writer,
                    inbound_slots,
                    timeouts: IrohInboundTimeouts::default(),
                },
            )
            .spawn();
        // Block until the endpoint has a path peers can reach it on.
        router.endpoint().online().await;
        Ok(Self {
            router,
            peers,
            cluster_key,
            membership_store,
            live_sessions,
        })
    }

    /// Number of known peers (learned inbound + seeded).
    pub fn peer_count(&self) -> usize {
        self.known_members().len()
    }

    pub fn known_peers(&self) -> Vec<EndpointId> {
        self.known_members()
            .into_iter()
            .map(|(peer, _)| peer)
            .collect()
    }

    fn known_members(&self) -> Vec<(EndpointId, MembershipGrant)> {
        let now = crate::time::now_unix_i64();
        let mut registry = self.peers.lock().unwrap_or_else(|p| p.into_inner());
        registry.retain(|_, grant| grant.revalidate(now).is_ok());
        let mut peers: Vec<_> = registry
            .iter()
            .map(|(peer, grant)| (*peer, grant.clone()))
            .collect();
        peers.sort_by_key(|(peer, _)| peer.to_string());
        peers
    }

    pub fn revoke_stable_node(
        &self,
        stable_node_id: &crate::cluster::membership::StableNodeId,
    ) -> usize {
        prune_stable_node_routes(&self.peers, stable_node_id)
    }

    /// Seed a peer by its endpoint-id string (hex). Returns false if unparseable.
    pub fn add_peer_id(&self, id: &str) -> bool {
        match id.trim().parse::<EndpointId>() {
            Ok(eid) => {
                let Ok(identity) = TransportIdentity::parse(eid.to_string()) else {
                    return false;
                };
                let Ok(grant) = self.membership_store.admit(
                    CarrierKind::Iroh,
                    &identity,
                    crate::time::now_unix_i64(),
                ) else {
                    return false;
                };
                self.peers
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(eid, grant);
                true
            }
            Err(_) => false,
        }
    }

    /// Broadcast one gossip frame to every known peer (best-effort, dial-by-key).
    /// Returns how many peers accepted the round-trip.
    pub async fn broadcast(&self, frame: &[u8]) -> usize {
        let targets = self.known_peers();
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

    /// True only while both the protocol router and its underlying endpoint
    /// are live. A retained `Arc<IrohTransport>` is not health evidence.
    pub fn is_healthy(&self) -> bool {
        !self.router.is_shutdown() && !self.router.endpoint().is_closed()
    }

    /// Dial a peer by its `EndpointAddr` and do one gossip request/response
    /// round-trip: write `frame`, read the peer's reply (capped).
    pub async fn send_frame(&self, peer: impl Into<EndpointAddr>, frame: &[u8]) -> Result<Vec<u8>> {
        self.send_frame_authorized(peer.into(), frame)
            .await?
            .finish()
    }

    async fn send_frame_authorized(
        &self,
        peer: EndpointAddr,
        frame: &[u8],
    ) -> Result<AuthorizedOutboundReply> {
        let transport = TransportIdentity::parse(peer.id.to_string())?;
        let grant = self.membership_store.admit(
            CarrierKind::Iroh,
            &transport,
            crate::time::now_unix_i64(),
        )?;
        let mut effect = grant.begin_effect(crate::time::now_unix_i64())?;
        let mut external = effect
            .begin_external(crate::time::now_unix_i64())
            .context("iroh: membership revoked before outbound permit")?;
        external.mark_transport_may_have_started();
        let connect = self.router.endpoint().connect(peer, NEOTH_CLUSTER_ALPN);
        tokio::pin!(connect);
        let conn = tokio::select! {
            biased;
            _ = external.cancelled() => {
                external.persist_indeterminate_if_cancelled(
                    "iroh_connect_locally_aborted_without_remote_ack",
                    crate::time::now_unix_i64(),
                )?;
                anyhow::bail!("iroh: membership revoked while connecting to peer")
            }
            result = &mut connect => result.context("iroh: connect to peer")?,
        };
        let _live_session = self
            .live_sessions
            .register(grant.stable_node_id().clone(), conn.clone());
        let exchange_result = {
            let exchange = async {
                let (mut send, mut recv) = conn
                    .open_bi()
                    .await
                    .map_err(|e| anyhow::anyhow!("iroh: open_bi: {e}"))?;
                // D3 — prepend our cluster_key Hello proof so the acceptor can
                // verify membership before evaluating the frame.
                let our_id = self.router.endpoint().id();
                let peer_id = conn.remote_id();
                let proof = compute_cluster_key_proof(
                    &self.cluster_key,
                    our_id.as_bytes(),
                    peer_id.as_bytes(),
                );
                send.write_all(&proof)
                    .await
                    .map_err(|e| anyhow::anyhow!("iroh: write proof: {e}"))?;
                send.write_all(frame)
                    .await
                    .map_err(|e| anyhow::anyhow!("iroh: write frame: {e}"))?;
                send.finish()
                    .map_err(|e| anyhow::anyhow!("iroh: finish: {e}"))?;
                recv.read_to_end(MAX_FRAME_BYTES)
                    .await
                    .map_err(|e| anyhow::anyhow!("iroh: read reply: {e}"))
            };
            tokio::pin!(exchange);
            tokio::select! {
                biased;
                _ = external.cancelled() => {
                    external.persist_indeterminate_if_cancelled(
                        "iroh_exchange_locally_aborted_without_remote_ack",
                        crate::time::now_unix_i64(),
                    )?;
                    Err(anyhow::anyhow!(
                        "iroh: membership revoked during outbound exchange"
                    ))
                }
                result = &mut exchange => result,
            }
        };
        let reply = match exchange_result {
            Ok(reply) => reply,
            Err(error) => {
                external.persist_indeterminate_if_cancelled(
                    "iroh_exchange_failed_during_membership_revocation",
                    crate::time::now_unix_i64(),
                )?;
                return Err(error);
            }
        };
        conn.close(0u32.into(), b"done");
        if let Err(error) = external.validate(crate::time::now_unix_i64()) {
            external.persist_indeterminate_if_cancelled(
                "iroh_exchange_completed_without_membership_classification",
                crate::time::now_unix_i64(),
            )?;
            return Err(error).context("iroh: membership changed before outbound classification");
        }
        drop(external);
        Ok(AuthorizedOutboundReply {
            bytes: reply,
            effect_guard: effect,
        })
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

fn prune_stable_node_routes(peers: &PeerRegistry, stable_node_id: &StableNodeId) -> usize {
    let mut registry = peers.lock().unwrap_or_else(|p| p.into_inner());
    let before = registry.len();
    registry.retain(|_, grant| grant.stable_node_id() != stable_node_id);
    before - registry.len()
}

impl crate::cluster::membership::LiveCarrierSessions for IrohTransport {
    fn carrier(&self) -> CarrierKind {
        CarrierKind::Iroh
    }

    fn teardown_stable_node(
        &self,
        stable_node_id: &crate::cluster::membership::StableNodeId,
    ) -> crate::cluster::membership::CarrierTeardownReceipt {
        let routes_evicted = self.revoke_stable_node(stable_node_id);
        let (signalled, closed_sessions) = self.live_sessions.close_stable_node(stable_node_id);
        crate::cluster::membership::CarrierTeardownReceipt {
            closed_sessions,
            routes_evicted,
            queued_effects_dropped: 0,
            status: if routes_evicted == 0 && signalled == 0 {
                "no_live_sessions".into()
            } else if closed_sessions == signalled {
                "closed".into()
            } else {
                "partial".into()
            },
        }
    }

    fn live_membership_generations(
        &self,
    ) -> Vec<crate::cluster::membership::LiveMembershipGeneration> {
        let mut generations = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(
                |grant| crate::cluster::membership::LiveMembershipGeneration {
                    stable_node_id: grant.stable_node_id().clone(),
                    carrier: grant.carrier(),
                    auth_epoch: grant.auth_epoch(),
                    membership_epoch: grant.membership_epoch(),
                    kind: crate::cluster::membership::LiveMembershipKind::Route,
                },
            )
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
    std::sync::Arc::new(move |membership_grant, req: Vec<u8>| {
        let persist_tx = persist_tx.clone();
        let writer = writer.clone();
        let state = Arc::clone(&state);
        let reload_controller = Arc::clone(&reload_controller);
        Box::pin(async move {
            let authenticated_peer = crate::cluster::PeerPubkey::new(
                membership_grant.stable_node_id().as_str().to_string(),
            );
            let reject = |verdict: &str| {
                AuthorizedFrameReply::rejected(
                    serde_json::to_vec(&serde_json::json!({
                        "accepted": false,
                        "verdict": verdict,
                    }))
                    .unwrap_or_default(),
                )
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
                membership_grant: membership_grant.clone(),
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
                Ok(Ok(authorized)) => {
                    let crate::cluster::wal_sync::AuthorizedInboundCommit {
                        commit,
                        effect_guard,
                    } = authorized;
                    match commit {
                        commit @ crate::cluster::durable_sync::InboundCommit::Committed(_)
                        | commit @ crate::cluster::durable_sync::InboundCommit::Duplicate(_)
                        | commit @ crate::cluster::durable_sync::InboundCommit::DuplicateUnbound(
                            _,
                        ) => {
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
                            AuthorizedFrameReply::authorized(
                                serde_json::to_vec(&ack).unwrap_or_default(),
                                effect_guard,
                            )
                        }
                        crate::cluster::durable_sync::InboundCommit::Gap { expected, received } => {
                            let verdict = format!("sequence_gap:{expected}:{received}");
                            emit_gossip_audit(
                                &writer,
                                false,
                                &verdict,
                                authenticated_peer.as_str(),
                            );
                            if let Err(error) = effect_guard.finish() {
                                tracing::warn!(%error, "iroh membership effect barrier failed");
                                return reject("membership_barrier_failed");
                            }
                            reject(&verdict)
                        }
                        crate::cluster::durable_sync::InboundCommit::Dropped(verdict) => {
                            let verdict = format!("{verdict:?}");
                            emit_gossip_audit(
                                &writer,
                                false,
                                &verdict,
                                authenticated_peer.as_str(),
                            );
                            if let Err(error) = effect_guard.finish() {
                                tracing::warn!(%error, "iroh membership effect barrier failed");
                                return reject("membership_barrier_failed");
                            }
                            reject(&verdict)
                        }
                    }
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
/// it cycles every live or sealed WAL segment; a durable local `request-sync`
/// row accelerates one paired peer to the one-second control cadence until
/// caught up. Both paths use the same per-peer durable cursor and pending-frame
/// store as peeroxide. Only an exact authenticated ACK advances that cursor.
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
        let regular_interval = std::time::Duration::from_secs(30);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut next_regular_tick = tokio::time::Instant::now();
        loop {
            ticker.tick().await;
            let now = crate::time::now_unix_i64();
            let known_members = transport.known_members();
            let known_grants = known_members
                .iter()
                .map(|(_, grant)| grant.clone())
                .collect::<Vec<_>>();
            let due_requests = match durable.claim_due_sync_requests_authorized(now, &known_grants)
            {
                Ok(requests) => requests,
                Err(error) => {
                    tracing::warn!(%error, "iroh mesh request queue claim failed closed");
                    Vec::new()
                }
            };
            let requested_claims: HashMap<String, crate::cluster::durable_sync::MeshSyncRequest> =
                due_requests
                    .into_iter()
                    .map(|request| (request.peer_pk.clone(), request))
                    .collect();

            let regular_due = tokio::time::Instant::now() >= next_regular_tick;
            if regular_due {
                next_regular_tick = tokio::time::Instant::now() + regular_interval;
            }
            if known_members.is_empty()
                || (!regular_due
                    && !known_members.iter().any(|(_, grant)| {
                        requested_claims.contains_key(grant.stable_node_id().as_str())
                    }))
            {
                continue;
            }

            let policy = reload_controller.gossip_policy();

            let mut delivered = 0usize;
            let mut operator_requested = 0usize;
            for (endpoint, grant) in known_members {
                let peer =
                    crate::cluster::PeerPubkey::new(grant.stable_node_id().as_str().to_string());
                let request_claim = requested_claims.get(peer.as_str());
                let requested = request_claim.is_some();
                if !regular_due && !requested {
                    continue;
                }
                match durable
                    .prepare_peer_frame_authorized(&grant, &self_id, &wal_dir, &policy, &state)
                    .await
                {
                    Ok(Some(prepared)) => {
                        let wire = match serde_json::to_vec(&prepared.frame) {
                            Ok(wire) => wire,
                            Err(error) => {
                                tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh frame serialization failed closed");
                                if let Some(claim) = request_claim {
                                    if let Err(persist_error) = durable
                                        .mark_sync_request_waiting_authorized(
                                            &grant,
                                            claim,
                                            crate::time::now_unix_i64(),
                                            "durable mesh frame serialization failed",
                                        )
                                    {
                                        tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh request serialization failure could not be persisted");
                                    }
                                }
                                continue;
                            }
                        };
                        let attempt_store = durable.clone();
                        let attempt_grant = grant.clone();
                        match tokio::task::spawn_blocking(move || {
                            attempt_store.record_send_attempt_authorized(&attempt_grant)
                        })
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh attempt persistence failed closed");
                                if let Some(claim) = request_claim
                                    && let Err(persist_error) = durable
                                        .mark_sync_request_waiting_authorized(
                                            &grant,
                                            claim,
                                            crate::time::now_unix_i64(),
                                            &format!("mesh attempt persistence failed: {error}"),
                                        )
                                {
                                    tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh request attempt failure could not be persisted");
                                }
                                continue;
                            }
                            Err(error) => {
                                tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh attempt task panicked");
                                if let Some(claim) = request_claim
                                    && let Err(persist_error) = durable
                                        .mark_sync_request_waiting_authorized(
                                            &grant,
                                            claim,
                                            crate::time::now_unix_i64(),
                                            "mesh attempt persistence task panicked",
                                        )
                                {
                                    tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh request attempt panic could not be persisted");
                                }
                                continue;
                            }
                        }
                        if let Some(claim) = request_claim {
                            match durable.mark_sync_request_sending_authorized(
                                &grant,
                                claim,
                                crate::time::now_unix_i64(),
                            ) {
                                Ok(true) => {}
                                Ok(false) => {
                                    tracing::debug!(peer = %peer.as_str(), "iroh mesh request lease was superseded before transport send");
                                    continue;
                                }
                                Err(error) => {
                                    tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh request send-attempt claim failed closed");
                                    continue;
                                }
                            }
                        }
                        match bounded_gossip_send(
                            GOSSIP_SEND_TIMEOUT,
                            transport.send_frame_authorized(endpoint.into(), &wire),
                        )
                        .await
                        {
                            Ok(Ok(reply)) => {
                                let ack = match serde_json::from_slice::<
                                    crate::cluster::gossip_wire::GossipAck,
                                >(&reply.bytes)
                                {
                                    Ok(ack) => ack,
                                    Err(_) => {
                                        tracing::warn!(peer = %peer.as_str(), "iroh mesh peer withheld or returned malformed ACK");
                                        if let Some(claim) = request_claim {
                                            if let Err(persist_error) = durable
                                                .mark_sync_request_waiting_authorized(
                                                    &grant,
                                                    claim,
                                                    crate::time::now_unix_i64(),
                                                    "peer withheld or returned a malformed ACK",
                                                )
                                            {
                                                tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh malformed-ACK state could not be persisted");
                                            }
                                        }
                                        continue;
                                    }
                                };
                                let ack_store = durable.clone();
                                let ack_origin = self_id.clone();
                                let AuthorizedOutboundReply {
                                    bytes: _,
                                    effect_guard,
                                } = reply;
                                match tokio::task::spawn_blocking(move || {
                                    let outcome = ack_store.acknowledge_outbound_authorized(
                                        &effect_guard,
                                        &ack_origin,
                                        &ack,
                                    )?;
                                    Ok::<_, anyhow::Error>((outcome, effect_guard))
                                })
                                .await
                                {
                                    Ok(Ok((_, effect_guard))) => match effect_guard.finish() {
                                        Ok(()) => {
                                            delivered += 1;
                                            if requested {
                                                operator_requested += 1;
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(%error, peer = %peer.as_str(), "iroh membership barrier failed after durable ACK");
                                        }
                                    },
                                    Ok(Err(error)) => {
                                        tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh ACK rejected");
                                        if let Some(claim) = request_claim {
                                            if let Err(persist_error) = durable
                                                .mark_sync_request_waiting_authorized(
                                                    &grant,
                                                    claim,
                                                    crate::time::now_unix_i64(),
                                                    &format!("peer ACK was rejected: {error}"),
                                                )
                                            {
                                                tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh rejected-ACK state could not be persisted");
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh ACK task panicked");
                                        if let Some(claim) = request_claim {
                                            if let Err(persist_error) = durable
                                                .mark_sync_request_waiting_authorized(
                                                    &grant,
                                                    claim,
                                                    crate::time::now_unix_i64(),
                                                    "peer ACK persistence task panicked",
                                                )
                                            {
                                                tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh ACK panic state could not be persisted");
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(Err(error)) => {
                                tracing::debug!(%error, peer = %peer.as_str(), "iroh mesh send failed; pending frame retained");
                                if let Some(claim) = request_claim {
                                    if let Err(persist_error) = durable
                                        .mark_sync_request_waiting_authorized(
                                            &grant,
                                            claim,
                                            crate::time::now_unix_i64(),
                                            &format!("active iroh carrier send failed: {error}"),
                                        )
                                    {
                                        tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh send-failure state could not be persisted");
                                    }
                                }
                            }
                            Err(_) => {
                                tracing::warn!(
                                    peer = %peer.as_str(),
                                    timeout_secs = GOSSIP_SEND_TIMEOUT.as_secs(),
                                    "iroh mesh peer timed out; pending frame retained"
                                );
                                if let Some(claim) = request_claim {
                                    if let Err(persist_error) = durable
                                        .mark_sync_request_waiting_authorized(
                                            &grant,
                                            claim,
                                            crate::time::now_unix_i64(),
                                            "active iroh peer timed out",
                                        )
                                    {
                                        tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh timeout state could not be persisted");
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        if let Some(claim) = request_claim
                            && let Err(error) = durable.mark_sync_request_complete_authorized(
                                &grant,
                                claim,
                                crate::time::now_unix_i64(),
                            )
                        {
                            tracing::warn!(%error, peer = %peer.as_str(), "iroh mesh request completion could not be persisted");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, peer = %peer.as_str(), "iroh durable mesh prepare failed closed");
                        if let Some(claim) = request_claim {
                            if let Err(persist_error) = durable
                                .mark_sync_request_waiting_authorized(
                                    &grant,
                                    claim,
                                    crate::time::now_unix_i64(),
                                    &format!("durable mesh prepare failed: {error}"),
                                )
                            {
                                tracing::warn!(%persist_error, peer = %peer.as_str(), "iroh mesh prepare-failure state could not be persisted");
                            }
                        }
                    }
                }
            }
            // Send-side audit (0xED), parity with the peeroxide gossip tick.
            // Only emit when frames actually went out so an idle tick leaves
            // no noise.
            if delivered > 0 {
                emit_gossip_sent(
                    &writer,
                    delivered,
                    delivered,
                    transport.peer_count(),
                    operator_requested,
                );
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

    fn test_membership(
        authority_home: &std::path::Path,
        identity_home: &std::path::Path,
        transport_id: &str,
    ) -> (MembershipStore, MembershipGrant) {
        let now = crate::time::now_unix_i64();
        let identity =
            crate::cluster::membership::LocalNodeIdentity::load_or_create(identity_home).unwrap();
        let transport = TransportIdentity::parse(transport_id).unwrap();
        let attestation = identity
            .attest_endpoint(
                CarrierKind::Iroh,
                transport.clone(),
                crate::cluster::membership::BootId::new(),
                "iroh-test".into(),
                "test".into(),
                crate::cluster::membership::AuthEpoch::INITIAL,
                crate::cluster::membership::MembershipEpoch::new(2).unwrap(),
                Some("test".into()),
                now + 3_600,
            )
            .unwrap();
        let store = MembershipStore::open(authority_home).unwrap();
        store
            .confirm_attestation(
                &attestation,
                CarrierKind::Iroh,
                &transport,
                "test",
                "iroh-test",
                now,
            )
            .unwrap();
        let grant = store.admit(CarrierKind::Iroh, &transport, now).unwrap();
        (store, grant)
    }

    const TEST_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    const TEST_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(150);

    async fn test_endpoint(alpns: bool) -> Endpoint {
        let mut builder = Endpoint::builder(presets::N0DisableRelay);
        if alpns {
            builder = builder.alpns(vec![NEOTH_CLUSTER_ALPN.to_vec()]);
        }
        builder.bind().await.expect("bind hermetic iroh endpoint")
    }

    async fn connect_test_peer(server: &Endpoint, client: &Endpoint) -> (Connection, Connection) {
        let accept_server = server.clone();
        let accepting = tokio::spawn(async move {
            accept_server
                .accept()
                .await
                .expect("incoming test connection")
                .await
                .expect("accept test QUIC connection")
        });
        let client_connection = tokio::time::timeout(
            TEST_IO_TIMEOUT,
            client.connect(server.addr(), NEOTH_CLUSTER_ALPN),
        )
        .await
        .expect("local connect timeout")
        .expect("connect local endpoint");
        let server_connection = tokio::time::timeout(TEST_IO_TIMEOUT, accepting)
            .await
            .expect("local accept timeout")
            .expect("accept task");
        (client_connection, server_connection)
    }

    fn test_protocol(
        our_id: EndpointId,
        membership_store: MembershipStore,
        capacity: usize,
        handler: FrameHandler,
    ) -> (GossipProtocol, PeerRegistry, Arc<IrohLiveRegistry>) {
        let peers = PeerRegistry::default();
        let live_sessions = Arc::new(IrohLiveRegistry::default());
        (
            GossipProtocol {
                handler,
                peers: Arc::clone(&peers),
                cluster_key: test_cluster_key(),
                our_id,
                membership_store,
                live_sessions: Arc::clone(&live_sessions),
                writer: None,
                inbound_slots: Arc::new(tokio::sync::Semaphore::new(capacity)),
                timeouts: IrohInboundTimeouts {
                    pre_auth: TEST_PHASE_TIMEOUT,
                    admitted: TEST_PHASE_TIMEOUT,
                },
            },
            peers,
            live_sessions,
        )
    }

    fn test_gossip_frame(grant: &MembershipGrant) -> Vec<u8> {
        let payload = vec![1, 2, 3];
        let envelope = crate::cluster::gossip_wire::SyncEnvelope {
            version: crate::cluster::gossip_wire::SYNC_ENVELOPE_VERSION,
            content_id: "iroh-timeout-test".into(),
            updated_at_unix: crate::time::now_unix_i64(),
            content: crate::cluster::gossip_wire::SyncContent::Metadata {
                event_type: 0x94,
                event_subtype: 0,
                wal_frame: payload.clone(),
            },
        };
        serde_json::to_vec(&crate::cluster::gossip_wire::GossipFrame {
            protocol_version: crate::cluster::gossip_wire::SYNC_PROTOCOL_VERSION,
            vector_clock: crate::cluster::gossip_wire::VectorClock::new(),
            origin: crate::cluster::PeerPubkey::new(grant.stable_node_id().as_str().to_string()),
            event_seq: 1,
            content_sha256: envelope.content_sha256(),
            timestamp_unix: crate::time::now_unix_i64(),
            tag: crate::cluster::gossip::GossipTag::Replicate,
            payload,
            envelope,
        })
        .unwrap()
    }

    async fn wait_for_protocol(
        task: tokio::task::JoinHandle<Result<(), AcceptError>>,
    ) -> Result<(), AcceptError> {
        tokio::time::timeout(TEST_IO_TIMEOUT, task)
            .await
            .expect("inbound protocol did not terminate")
            .expect("inbound protocol task panicked")
    }

    async fn assert_remote_closed(connection: &Connection) {
        tokio::time::timeout(TEST_IO_TIMEOUT, connection.closed())
            .await
            .expect("remote connection did not observe explicit close");
    }

    #[tokio::test]
    async fn inbound_connection_without_bi_stream_times_out_and_closes() {
        let server = test_endpoint(true).await;
        let client = test_endpoint(false).await;
        let (client_connection, server_connection) = connect_test_peer(&server, &client).await;
        let authority = tempfile::tempdir().unwrap();
        let store = MembershipStore::open(authority.path()).unwrap();
        let handler_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&handler_calls);
        let handler: FrameHandler = Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { AuthorizedFrameReply::rejected(Vec::new()) })
        });
        let (protocol, peers, live_sessions) = test_protocol(server.id(), store, 1, handler);
        let slots = Arc::clone(&protocol.inbound_slots);
        let accepting = tokio::spawn(async move { protocol.accept(server_connection).await });

        assert!(wait_for_protocol(accepting).await.is_ok());
        assert_remote_closed(&client_connection).await;
        assert_eq!(handler_calls.load(Ordering::Relaxed), 0);
        assert!(peers.lock().unwrap().is_empty());
        assert!(live_sessions.sessions.lock().unwrap().is_empty());
        assert_eq!(slots.available_permits(), 1);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn inbound_partial_proof_times_out_before_membership_state() {
        let server = test_endpoint(true).await;
        let client = test_endpoint(false).await;
        let (client_connection, server_connection) = connect_test_peer(&server, &client).await;
        let authority = tempfile::tempdir().unwrap();
        let store = MembershipStore::open(authority.path()).unwrap();
        let handler_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&handler_calls);
        let handler: FrameHandler = Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { AuthorizedFrameReply::rejected(Vec::new()) })
        });
        let (protocol, peers, live_sessions) = test_protocol(server.id(), store, 1, handler);
        let slots = Arc::clone(&protocol.inbound_slots);
        let accepting = tokio::spawn(async move { protocol.accept(server_connection).await });
        let (mut send, _recv) = client_connection.open_bi().await.unwrap();
        send.write_all(&[0x42; CLUSTER_PROOF_BYTES - 1])
            .await
            .unwrap();

        assert!(wait_for_protocol(accepting).await.is_ok());
        assert_remote_closed(&client_connection).await;
        assert_eq!(handler_calls.load(Ordering::Relaxed), 0);
        assert!(peers.lock().unwrap().is_empty());
        assert!(live_sessions.sessions.lock().unwrap().is_empty());
        assert_eq!(slots.available_permits(), 1);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn authenticated_inbound_frame_that_never_ends_times_out() {
        let server = test_endpoint(true).await;
        let client = test_endpoint(false).await;
        let (client_connection, server_connection) = connect_test_peer(&server, &client).await;
        let authority = tempfile::tempdir().unwrap();
        let identity = tempfile::tempdir().unwrap();
        let (store, _) =
            test_membership(authority.path(), identity.path(), &client.id().to_string());
        let handler_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&handler_calls);
        let handler: FrameHandler = Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { AuthorizedFrameReply::rejected(Vec::new()) })
        });
        let (protocol, peers, live_sessions) = test_protocol(server.id(), store, 1, handler);
        let slots = Arc::clone(&protocol.inbound_slots);
        let accepting = tokio::spawn(async move { protocol.accept(server_connection).await });
        let (mut send, _recv) = client_connection.open_bi().await.unwrap();
        let proof = compute_cluster_key_proof(
            &test_cluster_key(),
            client.id().as_bytes(),
            server.id().as_bytes(),
        );
        send.write_all(&proof).await.unwrap();
        send.write_all(b"{").await.unwrap();

        assert!(wait_for_protocol(accepting).await.is_ok());
        assert_remote_closed(&client_connection).await;
        assert_eq!(handler_calls.load(Ordering::Relaxed), 0);
        assert!(peers.lock().unwrap().is_empty());
        assert!(live_sessions.sessions.lock().unwrap().is_empty());
        assert_eq!(slots.available_permits(), 1);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn authenticated_inbound_handler_that_never_replies_times_out() {
        let server = test_endpoint(true).await;
        let client = test_endpoint(false).await;
        let (client_connection, server_connection) = connect_test_peer(&server, &client).await;
        let authority = tempfile::tempdir().unwrap();
        let identity = tempfile::tempdir().unwrap();
        let (store, grant) =
            test_membership(authority.path(), identity.path(), &client.id().to_string());
        let handler_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&handler_calls);
        let handler: FrameHandler = Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::pending())
        });
        let (protocol, peers, live_sessions) = test_protocol(server.id(), store, 1, handler);
        let slots = Arc::clone(&protocol.inbound_slots);
        let accepting = tokio::spawn(async move { protocol.accept(server_connection).await });
        let (mut send, _recv) = client_connection.open_bi().await.unwrap();
        let proof = compute_cluster_key_proof(
            &test_cluster_key(),
            client.id().as_bytes(),
            server.id().as_bytes(),
        );
        send.write_all(&proof).await.unwrap();
        send.write_all(&test_gossip_frame(&grant)).await.unwrap();
        send.finish().unwrap();

        assert!(wait_for_protocol(accepting).await.is_ok());
        assert_remote_closed(&client_connection).await;
        assert_eq!(handler_calls.load(Ordering::Relaxed), 1);
        assert!(peers.lock().unwrap().is_empty());
        assert!(live_sessions.sessions.lock().unwrap().is_empty());
        assert_eq!(slots.available_permits(), 1);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn inbound_remote_close_ack_is_bounded_and_never_publishes_route() {
        let server = test_endpoint(true).await;
        let client = test_endpoint(false).await;
        let (client_connection, server_connection) = connect_test_peer(&server, &client).await;
        let authority = tempfile::tempdir().unwrap();
        let identity = tempfile::tempdir().unwrap();
        let (store, grant) =
            test_membership(authority.path(), identity.path(), &client.id().to_string());
        let handler_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&handler_calls);
        let handler: FrameHandler = Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { AuthorizedFrameReply::rejected(b"ack".to_vec()) })
        });
        let (protocol, peers, live_sessions) = test_protocol(server.id(), store, 1, handler);
        let slots = Arc::clone(&protocol.inbound_slots);
        let accepting = tokio::spawn(async move { protocol.accept(server_connection).await });
        let (mut send, mut recv) = client_connection.open_bi().await.unwrap();
        let proof = compute_cluster_key_proof(
            &test_cluster_key(),
            client.id().as_bytes(),
            server.id().as_bytes(),
        );
        send.write_all(&proof).await.unwrap();
        send.write_all(&test_gossip_frame(&grant)).await.unwrap();
        send.finish().unwrap();
        let reply = tokio::time::timeout(TEST_IO_TIMEOUT, recv.read_to_end(MAX_FRAME_BYTES))
            .await
            .expect("server did not write reply before test timeout")
            .unwrap();
        assert_eq!(reply, b"ack");

        assert!(wait_for_protocol(accepting).await.is_err());
        assert_remote_closed(&client_connection).await;
        assert_eq!(handler_calls.load(Ordering::Relaxed), 1);
        assert!(peers.lock().unwrap().is_empty());
        assert!(live_sessions.sessions.lock().unwrap().is_empty());
        assert_eq!(slots.available_permits(), 1);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn saturated_inbound_capacity_rejects_then_reuses_slot_for_valid_peer() {
        let server = test_endpoint(true).await;
        let first_client = test_endpoint(false).await;
        let second_client = test_endpoint(false).await;
        let valid_client = test_endpoint(false).await;
        let authority = tempfile::tempdir().unwrap();
        let identity = tempfile::tempdir().unwrap();
        let (store, valid_grant) = test_membership(
            authority.path(),
            identity.path(),
            &valid_client.id().to_string(),
        );
        let handler_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = Arc::clone(&handler_calls);
        let handler: FrameHandler = Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { AuthorizedFrameReply::rejected(b"ack".to_vec()) })
        });
        let (protocol, peers, live_sessions) = test_protocol(server.id(), store, 1, handler);
        let slots = Arc::clone(&protocol.inbound_slots);

        let (first_connection, first_server_connection) =
            connect_test_peer(&server, &first_client).await;
        let (second_connection, second_server_connection) =
            connect_test_peer(&server, &second_client).await;
        let first_protocol = protocol.clone();
        let first =
            tokio::spawn(async move { first_protocol.accept(first_server_connection).await });
        tokio::time::timeout(TEST_IO_TIMEOUT, async {
            while slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first inbound request did not acquire capacity");

        let second_protocol = protocol.clone();
        let second =
            tokio::spawn(async move { second_protocol.accept(second_server_connection).await });
        assert!(wait_for_protocol(second).await.is_ok());
        assert_remote_closed(&second_connection).await;
        assert_eq!(slots.available_permits(), 0);

        assert!(wait_for_protocol(first).await.is_ok());
        assert_remote_closed(&first_connection).await;
        assert_eq!(slots.available_permits(), 1);

        let (valid_connection, valid_server_connection) =
            connect_test_peer(&server, &valid_client).await;
        let valid_protocol = protocol.clone();
        let valid =
            tokio::spawn(async move { valid_protocol.accept(valid_server_connection).await });
        let (mut send, mut recv) = valid_connection.open_bi().await.unwrap();
        let proof = compute_cluster_key_proof(
            &test_cluster_key(),
            valid_client.id().as_bytes(),
            server.id().as_bytes(),
        );
        send.write_all(&proof).await.unwrap();
        send.write_all(&test_gossip_frame(&valid_grant))
            .await
            .unwrap();
        send.finish().unwrap();
        let reply = tokio::time::timeout(TEST_IO_TIMEOUT, recv.read_to_end(MAX_FRAME_BYTES))
            .await
            .expect("valid peer did not receive reply before test timeout")
            .unwrap();
        assert_eq!(reply, b"ack");
        valid_connection.close(0u32.into(), b"reply read");
        assert!(wait_for_protocol(valid).await.is_ok());

        assert_eq!(handler_calls.load(Ordering::Relaxed), 1);
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(peers.lock().unwrap().len(), 1);
        assert!(peers.lock().unwrap().contains_key(&valid_client.id()));
        assert!(live_sessions.sessions.lock().unwrap().is_empty());

        first_client.close().await;
        second_client.close().await;
        valid_client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn revoke_closes_live_iroh_connection_and_prunes_exact_route() {
        let server = Endpoint::builder(presets::N0DisableRelay)
            .alpns(vec![NEOTH_CLUSTER_ALPN.to_vec()])
            .bind()
            .await
            .expect("bind hermetic server endpoint");
        let client = Endpoint::builder(presets::N0DisableRelay)
            .bind()
            .await
            .expect("bind hermetic client endpoint");
        let server_addr = server.addr();
        let accept_server = server.clone();
        let accepting = tokio::spawn(async move {
            accept_server
                .accept()
                .await
                .expect("incoming connection")
                .await
                .expect("accept QUIC connection")
        });
        let client_connection = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.connect(server_addr, NEOTH_CLUSTER_ALPN),
        )
        .await
        .expect("local connect timeout")
        .expect("connect local endpoint");
        let server_connection = tokio::time::timeout(std::time::Duration::from_secs(5), accepting)
            .await
            .expect("local accept timeout")
            .expect("accept task");

        let authority = tempfile::tempdir().unwrap();
        let identity = tempfile::tempdir().unwrap();
        let (_store, grant) =
            test_membership(authority.path(), identity.path(), &client.id().to_string());
        let stable_node_id = grant.stable_node_id().clone();
        let peers = PeerRegistry::default();
        peers.lock().unwrap().insert(client.id(), grant);
        let live = Arc::new(IrohLiveRegistry::default());
        let _session = live.register(stable_node_id.clone(), server_connection);

        assert_eq!(prune_stable_node_routes(&peers, &stable_node_id), 1);
        let (signalled, closed) = live.close_stable_node(&stable_node_id);
        assert_eq!((signalled, closed), (1, 1));
        assert!(peers.lock().unwrap().is_empty());
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_connection.closed(),
        )
        .await
        .expect("remote connection did not observe revocation close");

        client.close().await;
        server.close().await;
    }

    /// Two endpoints, one round-trip: B dials A by key, A's handler replies.
    /// Proves the real iroh send/accept path (bind → connect → bi-stream →
    /// handler → reply) works end-to-end. `#[ignore]` — it brings up real iroh
    /// endpoints (relay/discovery), so it needs a network; run manually:
    /// `cargo test -p neoth --features cluster-iroh loopback_frame_round_trip -- --ignored`.
    #[tokio::test]
    #[ignore = "real iroh endpoints — needs network (relay/discovery)"]
    async fn loopback_frame_round_trip() {
        let authority = tempfile::tempdir().unwrap();
        let identity_a = tempfile::tempdir().unwrap();
        let identity_b = tempfile::tempdir().unwrap();
        let secret_a = iroh::SecretKey::generate();
        let secret_b = iroh::SecretKey::generate();
        let (store, _) = test_membership(
            authority.path(),
            identity_a.path(),
            &secret_a.public().to_string(),
        );
        let (_, grant_b) = test_membership(
            authority.path(),
            identity_b.path(),
            &secret_b.public().to_string(),
        );
        // A echoes "<req>+ack".
        let handler: FrameHandler = Arc::new(|_, req: Vec<u8>| {
            Box::pin(async move {
                let mut reply = req;
                reply.extend_from_slice(b"+ack");
                AuthorizedFrameReply::rejected(reply)
            })
        });
        let a = IrohTransport::bind_with_secret(
            handler,
            test_cluster_key(),
            None,
            secret_a,
            store.clone(),
        )
        .await
        .expect("bind A");
        let b = IrohTransport::bind_with_secret(
            Arc::new(|_, bytes| Box::pin(async move { AuthorizedFrameReply::rejected(bytes) })),
            test_cluster_key(),
            None,
            secret_b,
            store,
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
            origin: crate::cluster::PeerPubkey::new(grant_b.stable_node_id().as_str().to_string()),
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
        let authority = tempfile::tempdir().unwrap();
        let identity = tempfile::tempdir().unwrap();
        let (_, grant) = test_membership(authority.path(), identity.path(), "test-peer");
        // A non-GossipFrame byte blob must be rejected (decode failure), not
        // panic — and the reply is a parseable JSON verdict.
        let reply = handler(grant, b"not a gossip frame".to_vec()).await;
        let v: serde_json::Value = serde_json::from_slice(&reply.bytes).expect("json reply");
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
        let identity = tempfile::tempdir().unwrap();
        let (_, grant) = test_membership(dir.path(), identity.path(), "test-peer");
        let reply = handler(grant, b"not a gossip frame".to_vec()).await;
        let v: serde_json::Value = serde_json::from_slice(&reply.bytes).expect("json reply");
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
        let identity = tempfile::tempdir().unwrap();
        let (_, grant) = test_membership(dir.path(), identity.path(), "iroh-peer-pk");
        let origin = crate::cluster::PeerPubkey::new(grant.stable_node_id().as_str().to_string());
        let mut vector_clock = VectorClock::new();
        vector_clock.tick(&origin);
        let frame = GossipFrame {
            protocol_version: SYNC_PROTOCOL_VERSION,
            vector_clock,
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
        let reply = handler(grant, serde_json::to_vec(&frame).unwrap()).await;
        let ack: crate::cluster::gossip_wire::GossipAck =
            serde_json::from_slice(&reply.bytes).expect("post-commit ACK");
        assert_eq!(ack.origin_seq, 1);
        reply.finish().expect("finish membership effect barrier");
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
        emit_gossip_sent(&Some(Arc::clone(&writer)), 3, 2, 1, 0);
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
