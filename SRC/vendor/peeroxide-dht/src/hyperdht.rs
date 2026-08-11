#![deny(clippy::all)]

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand::random;
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

use libudx::{UdxAsyncStream, UdxRuntime, UdxSocket};

use crate::blind_relay::{BlindRelayClient, RelayError};
use crate::crypto::{
    NS_ANNOUNCE, NS_MUTABLE_PUT, NS_UNANNOUNCE, ann_signable, hash, mutable_signable,
    sign_detached, verify_detached,
};
use crate::holepuncher::{HolepunchEvent, Holepuncher};
use crate::hyperdht_messages::{
    ANNOUNCE, AnnounceMessage, FIND_PEER, FIREWALL_OPEN, FIREWALL_UNKNOWN, HandshakeMessage,
    HolepunchMessage, HolepunchPayload, HyperPeer, IMMUTABLE_GET, IMMUTABLE_PUT, LOOKUP,
    MUTABLE_GET, MUTABLE_PUT, MutablePutRequest, NoisePayload, PEER_HANDSHAKE, PEER_HOLEPUNCH,
    RelayThroughInfo, SecretStreamInfo, UNANNOUNCE, UdxInfo, decode_hyper_peer_from_bytes,
    decode_lookup_raw_reply_from_bytes, decode_mutable_get_response_from_bytes,
    encode_announce_to_bytes, encode_hyper_peer_to_bytes, encode_mutable_put_request_to_bytes,
};
use crate::messages::Ipv4Peer;
use crate::noise::Keypair as NoiseKeypair;
use crate::noise_wrap::{NoiseWrap, NoiseWrapResult};
use crate::peer::NodeId;
use crate::persistent::{
    HandlerReply, IncomingHyperRequest, Persistent, PersistentConfig, PersistentStats,
};
use crate::protomux::Mux;
use crate::query::QueryReply;
use crate::router::{ForwardEntry, HandshakeAction, HolepunchAction, Router};
use crate::rpc::{DhtConfig, DhtError, DhtHandle, UserQueryParams, UserRequestParams};
use crate::secret_stream::{SecretStream, SecretStreamError};
use crate::secure_payload::SecurePayload;
use crate::socket_pool::SocketPool;

// ── Errors ────────────────────────────────────────────────────────────────────

static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(1);

/// Maximum number of remote handshake/holepunch events awaiting the local
/// server. This is intentionally small: unauthenticated UDP input must never
/// create an unbounded in-memory work queue.
const SERVER_EVENT_QUEUE_CAPACITY: usize = 64;
const GENERIC_DHT_REJECTION: u64 = 1;
/// Authenticated peers may retain a short-lived secret for a subsequent
/// holepunch exchange.  Keep both the lifetime and cardinality bounded: the
/// generic DHT server is exposed to arbitrary authenticated peers, not only
/// NEOTH's companion pairing workflow.
const SERVER_SESSION_CAPACITY: usize = 64;
const SERVER_SESSION_TTL: Duration = Duration::from_secs(5 * 60);
const SERVER_SESSION_GC_INTERVAL: Duration = Duration::from_secs(60);
/// Holepunching can keep sockets and timers alive for tens of seconds.  The
/// server actor therefore owns a small, fixed number of such attempts.
const SERVER_HOLEPUNCH_TASK_CAPACITY: usize = 8;
/// Reclaim expired remote routing state even while the DHT receives no lookup
/// for those targets. Per-request GC below also handles sustained traffic.
const ROUTING_STATE_GC_INTERVAL: Duration = Duration::from_secs(60);

fn next_stream_id() -> u32 {
    NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed)
}

/// A holepunch reply may carry a peer address, but it is not allowed to expand
/// the set of egress destinations. The reply can nominate an endpoint only
/// when it exactly agrees with the locally selected relay endpoint for this
/// DHT request. A peer-provided handshake address is not local egress
/// authority and therefore cannot satisfy this check by itself.
fn trusted_holepunch_peer(
    established_peer: &Ipv4Peer,
    reported_peer: &Ipv4Peer,
) -> Option<Ipv4Peer> {
    (established_peer == reported_peer).then(|| established_peer.clone())
}

/// Determines whether a direct connection should be attempted instead of holepunching.
///
/// Returns `true` (direct connect) when ANY of:
/// - The handshake was NOT relayed (client reached server directly)
/// - Server reports FIREWALL_OPEN
/// - Server has no holepunch relays (can't holepunch even if we wanted to)
/// - Both peers share the same host address
///
/// Matches Node.js connect.js decision logic.
pub fn should_direct_connect(
    relayed: bool,
    firewall: u64,
    remote_holepunchable: bool,
    same_host: bool,
) -> bool {
    !relayed || firewall == FIREWALL_OPEN || !remote_holepunchable || same_host
}

#[derive(Debug, Error)]
/// Errors returned by HyperDHT operations.
#[non_exhaustive]
pub enum HyperDhtError {
    /// Error propagated from the underlying DHT client.
    #[error("DHT error: {0}")]
    Dht(#[from] DhtError),
    /// Error while encoding or decoding protocol data.
    #[error("encoding error: {0}")]
    Encoding(#[from] crate::compact_encoding::EncodingError),
    /// Error from Noise handshake or session setup.
    #[error("noise error: {0}")]
    Noise(#[from] crate::noise::NoiseError),
    /// Error from the Noise wrapper layer.
    #[error("noise wrap error: {0}")]
    NoiseWrap(#[from] crate::noise_wrap::NoiseWrapError),
    /// Error from the router state machine.
    #[error("router error: {0}")]
    Router(#[from] crate::router::RouterError),
    /// Error while wrapping or unwrapping secure payloads.
    #[error("secure payload error: {0}")]
    SecurePayload(#[from] crate::secure_payload::SecurePayloadError),
    /// This DHT instance has been destroyed.
    #[error("node destroyed")]
    Destroyed,
    /// A signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// A content hash did not match.
    #[error("invalid hash")]
    InvalidHash,
    /// The internal channel was closed.
    #[error("channel closed")]
    ChannelClosed,
    /// No peer was found for the requested target.
    #[error("peer not found")]
    PeerNotFound,
    /// No relay nodes were available for the operation.
    #[error("no relay nodes available")]
    NoRelayNodes,
    /// The handshake failed with the given message.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    /// Hole punching did not succeed.
    #[error("holepunch failed")]
    HolepunchFailed,
    /// Hole punching was aborted by the remote side.
    #[error("holepunch aborted")]
    HolepunchAborted,
    /// The remote firewall rejected the connection.
    #[error("firewall rejected")]
    FirewallRejected,
    /// Error from the UDX transport layer.
    #[error("UDX error: {0}")]
    Udx(#[from] libudx::UdxError),
    /// Error from the secret stream layer.
    #[error("secret stream error: {0}")]
    SecretStream(#[from] SecretStreamError),
    /// Failed to establish a UDX stream.
    #[error("stream establishment failed: {0}")]
    StreamEstablishment(String),
    /// Error from the relay subsystem.
    #[error("relay error: {0}")]
    Relay(#[from] RelayError),
}

// ── Server events (forwarded to listen() subscribers) ────────────────────────

#[derive(Debug)]
/// Events forwarded to server-side listeners.
#[non_exhaustive]
pub enum ServerEvent {
    /// A peer handshake request that may need local server handling.
    PeerHandshake {
        /// The decoded handshake message.
        msg: HandshakeMessage,
        /// Address of the peer that sent the request.
        from: Ipv4Peer,
        /// Optional DHT target associated with the request.
        target: Option<NodeId>,
        /// Reply capability for the generated response. It retains the
        /// network-admission slot until it is sent or dropped.
        reply_tx: ServerReply,
    },
    /// A peer holepunch request that may need local server handling.
    PeerHolepunch {
        /// The decoded holepunch message.
        msg: HolepunchMessage,
        /// Address of the peer that sent the request.
        from: Ipv4Peer,
        /// Address of the peer we should punch toward.
        peer_address: Ipv4Peer,
        /// Optional DHT target associated with the request.
        target: Option<NodeId>,
        /// Reply capability for the generated response. It retains the
        /// network-admission slot until it is sent or dropped.
        reply_tx: ServerReply,
    },
}

/// The reply capability attached to a locally handled server event.
///
/// It owns the original [`crate::rpc::UserRequest`], including its bounded
/// admission permit. Sending the response or dropping this value completes the
/// request lifecycle; extracting a raw one-shot sender is deliberately not
/// possible, so dequeuing an event cannot evade the remote admission limit.
pub struct ServerReply {
    request: Option<crate::rpc::UserRequest>,
}

impl fmt::Debug for ServerReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerReply")
            .field("pending", &self.request.is_some())
            .finish()
    }
}

impl ServerReply {
    fn new(request: crate::rpc::UserRequest) -> Self {
        Self {
            request: Some(request),
        }
    }

    /// Send a successful reply and release its admission slot.
    pub fn send(mut self, value: Option<Vec<u8>>) -> Result<(), Option<Vec<u8>>> {
        let Some(mut request) = self.request.take() else {
            return Err(value);
        };
        request.reply(value);
        Ok(())
    }

    fn error(mut self, code: u64) {
        if let Some(mut request) = self.request.take() {
            request.error(code);
        }
    }
}

impl ServerEvent {
    fn reject(self, code: u64) {
        match self {
            Self::PeerHandshake { reply_tx, .. } | Self::PeerHolepunch { reply_tx, .. } => {
                reply_tx.error(code);
            }
        }
    }
}

// ── KeyPair ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
/// An Ed25519 key pair (libsodium layout: seed‖public_key).
pub struct KeyPair {
    /// The 32-byte public key.
    pub public_key: [u8; 32],
    /// The 64-byte secret key in libsodium layout.
    pub secret_key: [u8; 64],
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let seed: [u8; 32] = random();
        Self::from_seed(seed)
    }

    /// Derive a deterministic key pair from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pk: [u8; 32] = signing_key.verifying_key().to_bytes();
        let mut sk = [0u8; 64];
        sk[..32].copy_from_slice(&seed);
        sk[32..].copy_from_slice(&pk);
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &to_hex(self.public_key))
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    fn to_noise_keypair(&self) -> NoiseKeypair {
        NoiseKeypair {
            public_key: self.public_key,
            secret_key: self.secret_key,
        }
    }
}

// ── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
/// Result from a LOOKUP query.
#[non_exhaustive]
pub struct LookupResult {
    /// Node that returned the lookup result.
    pub from: Ipv4Peer,
    /// Optional intermediate hop used to reach the node.
    pub to: Option<Ipv4Peer>,
    /// Peers advertised by the node.
    pub peers: Vec<HyperPeer>,
}

#[derive(Debug, Clone)]
/// Result from an ANNOUNCE operation.
#[non_exhaustive]
pub struct AnnounceResult {
    /// Closest nodes contacted during the announce.
    pub closest_nodes: Vec<Ipv4Peer>,
}

#[derive(Debug, Clone)]
/// Result from an immutable put operation.
#[non_exhaustive]
pub struct ImmutablePutResult {
    /// Content hash used as the target key.
    pub hash: [u8; 32],
    /// Closest nodes contacted during the write.
    pub closest_nodes: Vec<Ipv4Peer>,
}

#[derive(Debug, Clone)]
/// Result from a mutable put operation.
#[non_exhaustive]
pub struct MutablePutResult {
    /// Public key used as the mutable record key.
    pub public_key: [u8; 32],
    /// Closest nodes contacted during the write.
    pub closest_nodes: Vec<Ipv4Peer>,
    /// Record sequence number that was written.
    pub seq: u64,
    /// Signature over the stored value.
    pub signature: [u8; 64],
    /// Number of commit-phase requests that timed out.
    pub commit_timeouts: u32,
}

#[derive(Debug, Clone)]
/// Result from a mutable get operation.
#[non_exhaustive]
pub struct MutableGetResult {
    /// Retrieved value bytes.
    pub value: Vec<u8>,
    /// Sequence number attached to the value.
    pub seq: u64,
    /// Signature verifying the value.
    pub signature: [u8; 64],
    /// Node that returned the value.
    pub from: Ipv4Peer,
}

#[derive(Debug, Clone)]
/// Metadata needed to establish a peer connection.
#[non_exhaustive]
pub struct ConnectResult {
    /// Remote peer's public key.
    pub remote_public_key: [u8; 32],
    /// Locally selected endpoint used for the connection: a direct server for
    /// explicit `connect_to`, or the relay used for a relayed exchange.
    pub server_address: Ipv4Peer,
    /// DHT endpoint that returned the handshake reply; this may be a relay.
    pub client_address: Ipv4Peer,
    /// Whether the connection was relayed through a third party.
    pub is_relayed: bool,
    /// Final Noise state and negotiated keys.
    pub noise: NoiseWrapResult,
    /// Local UDX stream id to use for the connection.
    pub local_stream_id: u32,
    /// Remote UDX metadata advertised by the peer.
    pub remote_udx: Option<UdxInfo>,
}

/// Established encrypted connection to a peer.
///
/// Wraps a [`SecretStream`] over a UDX transport, keeping the underlying
/// socket alive for the connection's lifetime.
#[non_exhaustive]
pub struct PeerConnection {
    /// Encrypted bidirectional stream to the peer.
    pub stream: SecretStream<UdxAsyncStream>,
    /// Remote peer's public key.
    pub remote_public_key: [u8; 32],
    /// Remote peer's network address (used by server-side relay to connect data streams).
    pub remote_addr: Option<std::net::SocketAddr>,
    /// The UDX socket underlying this connection. Public so relay flows
    /// in downstream crates can reuse the control channel's socket for
    /// data streams (matching Node.js behaviour).
    pub socket: UdxSocket,
    _relay_task: Option<JoinHandle<()>>,
}

impl PeerConnection {
    /// Create a new peer connection from its components.
    pub fn new(
        stream: SecretStream<UdxAsyncStream>,
        remote_public_key: [u8; 32],
        socket: UdxSocket,
        relay_task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            stream,
            remote_public_key,
            remote_addr: None,
            socket,
            _relay_task: relay_task,
        }
    }

    /// Create a new peer connection with a known remote address.
    pub fn with_remote_addr(
        stream: SecretStream<UdxAsyncStream>,
        remote_public_key: [u8; 32],
        remote_addr: std::net::SocketAddr,
        socket: UdxSocket,
        relay_task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            stream,
            remote_public_key,
            remote_addr: Some(remote_addr),
            socket,
            _relay_task: relay_task,
        }
    }
}

impl fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerConnection")
            .field("remote_public_key", &&self.remote_public_key[..8])
            .field("remote_addr", &self.remote_addr)
            .field("relayed", &self._relay_task.is_some())
            .finish_non_exhaustive()
    }
}

/// Configuration used by the server-side handshake and holepunch handler.
#[non_exhaustive]
pub struct ServerConfig {
    /// Server identity key pair.
    pub key_pair: KeyPair,
    /// Firewall mode advertised to connecting peers.
    pub firewall: u64,
}

impl ServerConfig {
    /// Create a new server configuration.
    pub fn new(key_pair: KeyPair, firewall: u64) -> Self {
        Self { key_pair, firewall }
    }
}

// ── Bootstrap defaults ────────────────────────────────────────────────────────

/// The three public HyperDHT bootstrap nodes (from `hyperdht/lib/constants.js`).
///
/// Format: `suggestedIP@hostname:port`.  `parse_bootstrap_str`
/// extracts the IP before `@`, so these work without DNS resolution.
pub const DEFAULT_BOOTSTRAP: [&str; 3] = [
    "88.99.3.86@node1.hyperdht.org:49737",
    "142.93.90.113@node2.hyperdht.org:49737",
    "138.68.147.8@node3.hyperdht.org:49737",
];

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
/// Configuration for a HyperDHT instance.
#[non_exhaustive]
pub struct HyperDhtConfig {
    /// DHT transport and bootstrap settings.
    pub dht: DhtConfig,
    /// Persistent storage settings for stored records.
    pub persistent: PersistentConfig,
}

impl HyperDhtConfig {
    /// Create a config pre-populated with the public HyperDHT bootstrap nodes.
    ///
    /// This is the typical starting point for connecting to the live network.
    /// `DhtConfig::default()` intentionally keeps `bootstrap` empty so that
    /// unit tests can run without network access.
    pub fn with_public_bootstrap() -> Self {
        Self {
            dht: DhtConfig {
                bootstrap: DEFAULT_BOOTSTRAP.iter().map(|s| (*s).to_string()).collect(),
                ..DhtConfig::default()
            },
            persistent: PersistentConfig::default(),
        }
    }
}

// ── AdminRequest ──────────────────────────────────────────────────────────────

enum AdminRequest {
    PersistentStats {
        reply: oneshot::Sender<PersistentStats>,
    },
}

// ── HyperDhtHandle ────────────────────────────────────────────────────────────

#[derive(Clone)]
/// Main public HyperDHT API handle.
pub struct HyperDhtHandle {
    dht: DhtHandle,
    router: Arc<Mutex<Router>>,
    server_tx: mpsc::Sender<ServerEvent>,
    admin_tx: mpsc::UnboundedSender<AdminRequest>,
}

impl HyperDhtHandle {
    // ── WIRE STATS ────────────────────────────────────────────────────────────

    /// Snapshot of cumulative wire bytes (sent, received) since this DHT
    /// node started. Counts every UDP datagram exchanged at the IO layer
    /// — queries, requests, replies, retries, relays, and any user-issued
    /// puts/gets — regardless of which higher-level operation produced them.
    ///
    /// Useful for distinguishing "useful payload throughput" (what consumers
    /// see) from "raw network throughput" (what the OS sees). The ratio
    /// between them is the DHT's protocol amplification factor.
    pub fn wire_stats(&self) -> (u64, u64) {
        self.dht.wire_stats()
    }

    /// Borrow the shared wire-counter handle for long-lived sampling. The
    /// returned counters are `Arc<AtomicU64>` internally; cloning is cheap.
    pub fn wire_counters(&self) -> crate::io::WireCounters {
        self.dht.wire_counters()
    }

    // ── LOOKUP ────────────────────────────────────────────────────────────────

    /// Query the DHT for peers advertising the target.
    pub async fn lookup(&self, target: [u8; 32]) -> Result<Vec<LookupResult>, HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: LOOKUP,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?;

        let mut results = Vec::new();
        for reply in replies {
            if let Some(value) = &reply.value {
                if let Ok(raw) = decode_lookup_raw_reply_from_bytes(value) {
                    if !raw.peers.is_empty() {
                        results.push(LookupResult {
                            from: reply.from.clone(),
                            to: None,
                            peers: raw.peers,
                        });
                    }
                }
            }
        }
        Ok(results)
    }

    // ── ANNOUNCE ─────────────────────────────────────────────────────────────

    /// Announce this peer under the given target.
    pub async fn announce(
        &self,
        target: [u8; 32],
        key_pair: &KeyPair,
        relay_addresses: &[Ipv4Peer],
    ) -> Result<AnnounceResult, HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: LOOKUP,
                value: None,
                commit: true,
                concurrency: None,
            })
            .await?;

        let mut closest_nodes = Vec::new();

        for reply in &replies {
            closest_nodes.push(reply.from.clone());

            let token = match &reply.token {
                Some(t) => *t,
                None => continue,
            };
            let node_id = match &reply.from_id {
                Some(id) => *id,
                None => continue,
            };

            let peer = HyperPeer {
                public_key: key_pair.public_key,
                relay_addresses: relay_addresses.iter().take(3).cloned().collect(),
            };

            let peer_encoded = encode_hyper_peer_to_bytes(&peer)?;
            let signable =
                ann_signable(&target, &token, &node_id, &peer_encoded, &[], &NS_ANNOUNCE);
            let signature = sign_detached(&signable, &key_pair.secret_key);

            let ann = AnnounceMessage {
                peer: Some(peer),
                refresh: None,
                signature: Some(signature),
                bump: 0,
            };
            let ann_bytes = encode_announce_to_bytes(&ann)?;

            let _ = self
                .dht
                .request(
                    UserRequestParams {
                        token: Some(token),
                        command: ANNOUNCE,
                        target: Some(target),
                        value: Some(ann_bytes),
                    },
                    &reply.from.host,
                    reply.from.port,
                )
                .await;
        }

        Ok(AnnounceResult { closest_nodes })
    }

    // ── FIND_PEER ─────────────────────────────────────────────────────────────

    /// Return the first peer record found for the target.
    pub async fn find_peer(&self, target: [u8; 32]) -> Result<Option<HyperPeer>, HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: FIND_PEER,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?;

        for reply in replies {
            if let Some(value) = reply.value {
                if let Ok(peer) = decode_hyper_peer_from_bytes(&value) {
                    return Ok(Some(peer));
                }
            }
        }
        Ok(None)
    }

    /// Run a FIND_PEER query and return all raw replies.
    ///
    /// Unlike [`find_peer`](Self::find_peer), this returns every reply from
    /// the iterative query so callers can try connecting through each
    /// responding node's address.
    pub async fn query_find_peer(
        &self,
        target: [u8; 32],
    ) -> Result<Vec<QueryReply>, HyperDhtError> {
        Ok(self
            .dht
            .query(UserQueryParams {
                target,
                command: FIND_PEER,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?)
    }

    // ── UNANNOUNCE ────────────────────────────────────────────────────────────

    /// Remove a previously announced peer record.
    pub async fn unannounce(
        &self,
        target: [u8; 32],
        key_pair: &KeyPair,
    ) -> Result<(), HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: LOOKUP,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?;

        for reply in &replies {
            let token = match &reply.token {
                Some(t) => *t,
                None => continue,
            };
            let node_id = match &reply.from_id {
                Some(id) => *id,
                None => continue,
            };

            let peer = HyperPeer {
                public_key: key_pair.public_key,
                relay_addresses: vec![],
            };
            let peer_encoded = encode_hyper_peer_to_bytes(&peer)?;
            let signable = ann_signable(
                &target,
                &token,
                &node_id,
                &peer_encoded,
                &[],
                &NS_UNANNOUNCE,
            );
            let signature = sign_detached(&signable, &key_pair.secret_key);

            let ann = AnnounceMessage {
                peer: Some(peer),
                refresh: None,
                signature: Some(signature),
                bump: 0,
            };
            let ann_bytes = encode_announce_to_bytes(&ann)?;

            let _ = self
                .dht
                .request(
                    UserRequestParams {
                        token: Some(token),
                        command: UNANNOUNCE,
                        target: Some(target),
                        value: Some(ann_bytes),
                    },
                    &reply.from.host,
                    reply.from.port,
                )
                .await;
        }

        Ok(())
    }

    // ── IMMUTABLE_PUT ────────────────────────────────────────────────────────

    /// Store immutable content under its content hash.
    pub async fn immutable_put(&self, value: &[u8]) -> Result<ImmutablePutResult, HyperDhtError> {
        let target = hash(value);

        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: IMMUTABLE_GET,
                value: None,
                commit: true,
                concurrency: None,
            })
            .await?;

        let mut closest_nodes = Vec::new();

        for reply in &replies {
            closest_nodes.push(reply.from.clone());

            let token = match &reply.token {
                Some(t) => *t,
                None => continue,
            };

            let _ = self
                .dht
                .request(
                    UserRequestParams {
                        token: Some(token),
                        command: IMMUTABLE_PUT,
                        target: Some(target),
                        value: Some(value.to_vec()),
                    },
                    &reply.from.host,
                    reply.from.port,
                )
                .await;
        }

        Ok(ImmutablePutResult {
            hash: target,
            closest_nodes,
        })
    }

    // ── IMMUTABLE_GET ────────────────────────────────────────────────────────

    /// Fetch immutable content by content hash.
    pub async fn immutable_get(&self, target: [u8; 32]) -> Result<Option<Vec<u8>>, HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: IMMUTABLE_GET,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?;

        for reply in replies {
            if let Some(value) = reply.value {
                if hash(&value) == target {
                    return Ok(Some(value));
                }
            }
        }
        Ok(None)
    }

    // ── MUTABLE_PUT ───────────────────────────────────────────────────────────

    /// Store a signed mutable record for the given key pair.
    pub async fn mutable_put(
        &self,
        key_pair: &KeyPair,
        value: &[u8],
        seq: u64,
    ) -> Result<MutablePutResult, HyperDhtError> {
        let target = hash(&key_pair.public_key);
        let signable = mutable_signable(&NS_MUTABLE_PUT, seq, value);
        let signature = sign_detached(&signable, &key_pair.secret_key);

        let put = MutablePutRequest {
            public_key: key_pair.public_key,
            seq,
            value: value.to_vec(),
            signature,
        };
        let put_bytes = encode_mutable_put_request_to_bytes(&put)?;

        let seq_bytes = encode_compact_uint(seq);

        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: MUTABLE_GET,
                value: Some(seq_bytes),
                commit: true,
                concurrency: None,
            })
            .await?;

        let mut closest_nodes = Vec::new();
        let mut commit_timeouts: u32 = 0;

        for reply in &replies {
            closest_nodes.push(reply.from.clone());

            let token = match &reply.token {
                Some(t) => *t,
                None => continue,
            };

            if let Err(DhtError::RequestFailed(_)) = self
                .dht
                .request(
                    UserRequestParams {
                        token: Some(token),
                        command: MUTABLE_PUT,
                        target: Some(target),
                        value: Some(put_bytes.clone()),
                    },
                    &reply.from.host,
                    reply.from.port,
                )
                .await
            {
                commit_timeouts += 1;
            }
        }

        Ok(MutablePutResult {
            public_key: key_pair.public_key,
            closest_nodes,
            seq,
            signature,
            commit_timeouts,
        })
    }

    // ── MUTABLE_GET ───────────────────────────────────────────────────────────

    /// Fetch and verify a mutable record for the given public key.
    pub async fn mutable_get(
        &self,
        public_key: &[u8; 32],
        seq: u64,
    ) -> Result<Option<MutableGetResult>, HyperDhtError> {
        let target = hash(public_key);
        let seq_bytes = encode_compact_uint(seq);

        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: MUTABLE_GET,
                value: Some(seq_bytes),
                commit: false,
                concurrency: None,
            })
            .await?;

        for reply in replies {
            if let Some(value) = &reply.value {
                if let Ok(resp) = decode_mutable_get_response_from_bytes(value) {
                    if resp.seq >= seq {
                        let signable = mutable_signable(&NS_MUTABLE_PUT, resp.seq, &resp.value);
                        if verify_detached(&resp.signature, &signable, public_key) {
                            return Ok(Some(MutableGetResult {
                                value: resp.value,
                                seq: resp.seq,
                                signature: resp.signature,
                                from: reply.from,
                            }));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Wait until the DHT is bootstrapped.
    pub async fn bootstrapped(&self) -> Result<(), HyperDhtError> {
        self.dht.bootstrapped().await.map_err(HyperDhtError::Dht)
    }

    /// Destroy the underlying DHT instance.
    pub async fn destroy(&self) -> Result<(), HyperDhtError> {
        self.dht.destroy().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the number of nodes in the routing table.
    pub async fn table_size(&self) -> Result<usize, HyperDhtError> {
        self.dht.table_size().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the local port the DHT server socket is bound to.
    pub async fn local_port(&self) -> Result<u16, HyperDhtError> {
        self.dht.local_port().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the DHT server socket for multiplexing UDX streams.
    pub async fn server_socket(&self) -> Result<Option<UdxSocket>, HyperDhtError> {
        self.dht.server_socket().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the actual listen socket (bound to the advertised server port).
    pub async fn listen_socket(&self) -> Result<Option<UdxSocket>, HyperDhtError> {
        self.dht.listen_socket().await.map_err(HyperDhtError::Dht)
    }

    /// Access the shared router state.
    pub fn router(&self) -> &Arc<Mutex<Router>> {
        &self.router
    }

    /// Access the underlying DHT handle.
    pub fn dht(&self) -> &DhtHandle {
        &self.dht
    }

    /// Returns persistent storage statistics collected from the request handler.
    pub async fn persistent_stats(&self) -> Result<PersistentStats, HyperDhtError> {
        let (tx, rx) = oneshot::channel();
        self.admin_tx
            .send(AdminRequest::PersistentStats { reply: tx })
            .map_err(|_| HyperDhtError::Destroyed)?;
        rx.await.map_err(|_| HyperDhtError::Destroyed)
    }

    /// Mark a target as having a local server available.
    ///
    /// Returns `false` if the bounded routing table cannot admit a new target.
    /// Existing targets can always be refreshed.
    pub fn register_server(&self, target: &[u8; 32]) -> bool {
        if let Ok(mut router) = self.router.lock() {
            router.set(
                target,
                ForwardEntry {
                    relay: None,
                    has_server: true,
                    inserted: std::time::Instant::now(),
                },
            )
        } else {
            false
        }
    }

    /// Remove the local-server marker for a target.
    pub fn unregister_server(&self, target: &[u8; 32]) {
        if let Ok(mut router) = self.router.lock() {
            router.delete(target);
        }
    }

    /// Access the server event sender.
    pub fn server_sender(&self) -> &mpsc::Sender<ServerEvent> {
        &self.server_tx
    }

    // ── CONNECT (client-side holepunch orchestration) ─────────────────────

    /// Connect to a remote peer using the DHT and relay fallback.
    pub async fn connect(
        &self,
        key_pair: &KeyPair,
        remote_public_key: [u8; 32],
        runtime: &UdxRuntime,
    ) -> Result<PeerConnection, HyperDhtError> {
        self.connect_with_nodes(key_pair, remote_public_key, &[], runtime)
            .await
    }

    /// Connect to a remote peer, optionally using known relay addresses first.
    ///
    /// Connection strategy (matches Node.js `findAndConnect`):
    /// 1. Try provided `relay_addresses` first (optimistic pre-connect).
    /// 2. Run FIND_NODE to discover all DHT nodes close to the target,
    ///    then try `connect_through_node` for each one.
    /// 3. Try relay addresses found in peer records via FIND_PEER query.
    pub async fn connect_with_nodes(
        &self,
        key_pair: &KeyPair,
        remote_public_key: [u8; 32],
        relay_addresses: &[Ipv4Peer],
        runtime: &UdxRuntime,
    ) -> Result<PeerConnection, HyperDhtError> {
        let mut last_err = HyperDhtError::NoRelayNodes;
        let mut tried: Vec<(String, u16)> = Vec::new();

        // Phase 1: Optimistic pre-connect through provided relay addresses.
        for relay in relay_addresses {
            tried.push((relay.host.clone(), relay.port));
            match self
                .connect_through_node(key_pair, &remote_public_key, relay, false, runtime)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::debug!(relay = %format!("{}:{}", relay.host, relay.port), err = %e, "pre-connect relay attempt failed");
                    last_err = e;
                }
            }
        }

        // Phase 2: Walk the DHT to find nodes close to hash(remotePublicKey).
        // Use FIND_NODE (internal command all DHT nodes handle) to ensure we
        // discover the server's own node — FIND_PEER (user command) might not
        // reach all nodes in small networks.
        let target = hash(&remote_public_key);
        let table_size = self.dht.table_size().await.unwrap_or(0);
        tracing::debug!(
            table_size,
            "connect_with_nodes: routing table size before FIND_NODE"
        );
        let node_replies = self
            .dht
            .find_node(target)
            .await
            .map_err(HyperDhtError::Dht)?;
        tracing::debug!(
            reply_count = node_replies.len(),
            "connect_with_nodes: FIND_NODE completed"
        );

        if relay_addresses.is_empty() && node_replies.is_empty() {
            return Err(HyperDhtError::PeerNotFound);
        }

        // Collect all unique candidate addresses from replies AND their closer_nodes.
        let mut candidates: Vec<Ipv4Peer> = Vec::new();
        for reply in &node_replies {
            candidates.push(reply.from.clone());
            for cn in &reply.closer_nodes {
                if !candidates
                    .iter()
                    .any(|c| c.host == cn.host && c.port == cn.port)
                {
                    candidates.push(cn.clone());
                }
            }
        }
        tracing::debug!(
            candidate_count = candidates.len(),
            "connect_with_nodes: total candidates (replies + closer_nodes)"
        );

        for (i, candidate) in candidates.iter().enumerate() {
            let skip = tried
                .iter()
                .any(|(h, p)| h == &candidate.host && *p == candidate.port);
            tracing::debug!(
                i,
                candidate = %format!("{}:{}", candidate.host, candidate.port),
                skip,
                "connect_with_nodes: candidate check"
            );
            if skip {
                continue;
            }
            tried.push((candidate.host.clone(), candidate.port));
            tracing::debug!(candidate = %format!("{}:{}", candidate.host, candidate.port), "connect_with_nodes: trying node candidate");
            match self
                .connect_through_node(key_pair, &remote_public_key, candidate, false, runtime)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::debug!(relay = %format!("{}:{}", candidate.host, candidate.port), err = %e, "query relay attempt failed");
                    last_err = e;
                }
            }
        }

        // Phase 3: Also try relay addresses from a FIND_PEER query (peer records).
        let peer_replies = self.query_find_peer(target).await?;
        for reply in &peer_replies {
            if let Some(value) = &reply.value {
                if let Ok(peer) = decode_hyper_peer_from_bytes(value) {
                    for relay in &peer.relay_addresses {
                        if tried
                            .iter()
                            .any(|(h, p)| h == &relay.host && *p == relay.port)
                        {
                            continue;
                        }
                        tried.push((relay.host.clone(), relay.port));
                        match self
                            .connect_through_node(
                                key_pair,
                                &remote_public_key,
                                relay,
                                false,
                                runtime,
                            )
                            .await
                        {
                            Ok(result) => return Ok(result),
                            Err(e) => {
                                tracing::debug!(relay = %format!("{}:{}", relay.host, relay.port), err = %e, "peer record relay attempt failed");
                                last_err = e;
                            }
                        }
                    }
                }
            }
        }

        Err(last_err)
    }

    /// Connect directly to a peer at a known address, bypassing DHT routing.
    ///
    /// Sends a PEER_HANDSHAKE directly to `target_addr` for `remote_public_key`.
    /// Useful when the target's address is already known (e.g. from prior
    /// configuration or out-of-band exchange), avoiding the FIND_NODE phase
    /// that requires the target to be well-propagated in the DHT.
    pub async fn connect_to(
        &self,
        key_pair: &KeyPair,
        remote_public_key: [u8; 32],
        target_addr: std::net::SocketAddr,
        runtime: &UdxRuntime,
    ) -> Result<PeerConnection, HyperDhtError> {
        let relay = Ipv4Peer {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
        };
        self.connect_through_node(key_pair, &remote_public_key, &relay, true, runtime)
            .await
    }

    async fn connect_through_node(
        &self,
        key_pair: &KeyPair,
        remote_public_key: &[u8; 32],
        relay: &Ipv4Peer,
        direct_target: bool,
        runtime: &UdxRuntime,
    ) -> Result<PeerConnection, HyperDhtError> {
        let target = hash(remote_public_key);

        // Phase 1: Noise IK handshake via PEER_HANDSHAKE relay
        let mut nw = NoiseWrap::new_initiator(key_pair.to_noise_keypair(), *remote_public_key);

        let local_stream_id = next_stream_id();

        let local_payload = NoisePayload {
            version: 1,
            error: 0,
            firewall: FIREWALL_UNKNOWN,
            holepunch: None,
            addresses4: vec![],
            addresses6: vec![],
            udx: Some(UdxInfo {
                version: 1,
                reusable_socket: true,
                id: u64::from(local_stream_id),
                seq: 0,
            }),
            secret_stream: Some(SecretStreamInfo { version: 1 }),
            relay_through: None,
            relay_addresses: None,
        };

        let noise_bytes = nw.send(&local_payload)?;
        let handshake_value = Router::encode_client_handshake(noise_bytes, None, None)?;

        let resp = self
            .dht
            .request(
                UserRequestParams {
                    token: None,
                    command: PEER_HANDSHAKE,
                    target: Some(target),
                    value: Some(handshake_value),
                },
                &relay.host,
                relay.port,
            )
            .await?;

        if resp.error != 0 {
            return Err(HyperDhtError::HandshakeFailed(format!(
                "error code {}",
                resp.error
            )));
        }

        let reply_value = resp
            .value
            .ok_or_else(|| HyperDhtError::HandshakeFailed("empty reply".into()))?;

        let hs_result = {
            let router = self
                .router
                .lock()
                .map_err(|_| HyperDhtError::ChannelClosed)?;
            router.validate_handshake_reply(&reply_value, relay, &resp.from, !direct_target)?
        };

        let remote_payload = nw.recv(&hs_result.noise)?;
        let nw_result = nw.finalize()?;

        if remote_payload.error != 0 {
            return Err(HyperDhtError::FirewallRejected);
        }

        // Check if the remote peer wants us to relay through a third node.
        if let Some(ref relay_through) = remote_payload.relay_through {
            let relay_addrs = remote_payload.relay_addresses.clone().unwrap_or_default();
            tracing::debug!(
                relay_pk = ?&relay_through.public_key[..8],
                relay_addr_hints = relay_addrs.len(),
                "remote requested relay_through"
            );
            return Box::pin(self.relay_connection(
                key_pair,
                relay_through,
                &relay_addrs,
                &nw_result,
                false,
                true,
                runtime,
            ))
            .await;
        }

        // Skip holepunching when the remote peer is directly reachable.
        // Node.js (connect.js) checks:
        //   payload.firewall === FIREWALL.OPEN  -- server says it's open
        //   (relayed && !remoteHolepunchable)   -- relayed but server has no HP relays
        // In either case, connect directly using the server address from the handshake.
        let remote_holepunchable = remote_payload
            .holepunch
            .as_ref()
            .is_some_and(|hp| !hp.relays.is_empty());

        tracing::debug!(
            relayed = hs_result.relayed,
            firewall = remote_payload.firewall,
            remote_holepunchable,
            server_address = %format!("{}:{}", hs_result.server_address.host, hs_result.server_address.port),
            "handshake complete, deciding connection path"
        );

        if !hs_result.relayed
            && should_direct_connect(
                hs_result.relayed,
                remote_payload.firewall,
                remote_holepunchable,
                hs_result.server_address.host == hs_result.client_address.host,
            )
        {
            // The explicitly requested direct endpoint is locally known. Do
            // not promote remote-advertised or reply metadata to an egress
            // destination, even after Noise authentication.
            let connect_addr = hs_result.server_address.clone();

            let direct = ConnectResult {
                remote_public_key: nw_result.remote_public_key,
                server_address: connect_addr,
                client_address: hs_result.client_address,
                is_relayed: false,
                noise: nw_result,
                local_stream_id,
                remote_udx: remote_payload.udx.clone(),
            };
            let shared = self.server_socket().await?;
            return establish_stream_with_socket(&direct, runtime, shared).await;
        }

        // Phase 2: Holepunch rounds via PEER_HOLEPUNCH relay
        let server_address = hs_result.server_address.clone();
        let hp_result = self
            .run_holepunch_rounds(
                &nw_result,
                &remote_payload,
                relay,
                &target,
                &server_address,
                runtime,
                local_stream_id,
            )
            .await?;
        let shared = self.server_socket().await?;
        establish_stream_with_socket(&hp_result, runtime, shared).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_holepunch_rounds(
        &self,
        nw_result: &NoiseWrapResult,
        remote_payload: &NoisePayload,
        relay: &Ipv4Peer,
        target: &[u8; 32],
        server_address: &Ipv4Peer,
        runtime: &UdxRuntime,
        local_stream_id: u32,
    ) -> Result<ConnectResult, HyperDhtError> {
        let sp = SecurePayload::new(nw_result.holepunch_secret);
        let pool = SocketPool::new("0.0.0.0".into());
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        let hp_id = remote_payload.holepunch.as_ref().map_or(0, |hp| hp.id);

        let mut puncher = Holepuncher::new(
            &pool,
            runtime,
            true,
            true,
            remote_payload.firewall,
            event_tx,
        )
        .await
        .map_err(|_| HyperDhtError::HolepunchFailed)?;

        // Probe round: exchange addresses without punching
        let probe_payload = HolepunchPayload {
            error: 0,
            firewall: puncher.nat.firewall,
            round: 0,
            connected: false,
            punching: false,
            addresses: None,
            remote_address: None,
            token: Some(sp.token(&server_address.host)),
            remote_token: None,
        };

        let encrypted_probe = sp.encrypt(&probe_payload)?;
        let hp_value = Router::encode_client_holepunch(hp_id, encrypted_probe, None)?;

        let hp_resp = self
            .dht
            .request(
                UserRequestParams {
                    token: None,
                    command: PEER_HOLEPUNCH,
                    target: Some(*target),
                    value: Some(hp_value),
                },
                &relay.host,
                relay.port,
            )
            .await?;

        if hp_resp.error != 0 {
            puncher.destroy();
            return Err(HyperDhtError::HolepunchFailed);
        }

        if let Some(reply_value) = &hp_resp.value {
            let hp_result = {
                let router = self
                    .router
                    .lock()
                    .map_err(|_| HyperDhtError::ChannelClosed)?;
                router.validate_holepunch_reply(reply_value, relay, &hp_resp.from, relay)?
            };
            let Some(trusted_peer) = trusted_holepunch_peer(relay, &hp_result.peer_address) else {
                puncher.destroy();
                return Err(HyperDhtError::HolepunchFailed);
            };

            if let Ok(remote_hp) = sp.decrypt(&hp_result.payload) {
                // The authenticated payload's advertised address list is
                // capability data, not egress authority. Punch only the
                // endpoint independently correlated by the handshake path.
                puncher.update_remote(
                    remote_hp.punching,
                    remote_hp.firewall,
                    std::slice::from_ref(&trusted_peer),
                    Some(trusted_peer.host.as_str()),
                );
            }
        }

        // Punch round: send with punching=true, then initiate punch
        let punch_payload = HolepunchPayload {
            error: 0,
            firewall: puncher.nat.firewall,
            round: 1,
            connected: false,
            punching: true,
            addresses: None,
            remote_address: None,
            token: Some(sp.token(&server_address.host)),
            remote_token: None,
        };

        let encrypted_punch = sp.encrypt(&punch_payload)?;
        let hp_punch_value = Router::encode_client_holepunch(hp_id, encrypted_punch, None)?;

        let punch_resp = self
            .dht
            .request(
                UserRequestParams {
                    token: None,
                    command: PEER_HOLEPUNCH,
                    target: Some(*target),
                    value: Some(hp_punch_value),
                },
                &relay.host,
                relay.port,
            )
            .await?;

        if let Some(reply_value) = &punch_resp.value {
            let hp_result = {
                let router = self
                    .router
                    .lock()
                    .map_err(|_| HyperDhtError::ChannelClosed)?;
                router.validate_holepunch_reply(reply_value, relay, &punch_resp.from, relay)?
            };
            let Some(trusted_peer) = trusted_holepunch_peer(relay, &hp_result.peer_address) else {
                puncher.destroy();
                return Err(HyperDhtError::HolepunchFailed);
            };

            if let Ok(remote_hp) = sp.decrypt(&hp_result.payload) {
                // Preserve the same authority boundary for the actual punch:
                // a remote payload cannot nominate additional UDP targets.
                puncher.update_remote(
                    remote_hp.punching,
                    remote_hp.firewall,
                    std::slice::from_ref(&trusted_peer),
                    Some(trusted_peer.host.as_str()),
                );
            }
        }

        // Initiate the actual punch
        let punched = puncher.punch(&pool, runtime).await;
        if !punched {
            puncher.destroy();
            return Err(HyperDhtError::HolepunchFailed);
        }

        // Wait for the punch to connect
        match tokio::time::timeout(std::time::Duration::from_secs(10), event_rx.recv()).await {
            Ok(Some(HolepunchEvent::Connected { addr })) => {
                let connected_addr = Ipv4Peer {
                    host: addr.ip().to_string(),
                    port: addr.port(),
                };
                Ok(ConnectResult {
                    remote_public_key: nw_result.remote_public_key,
                    server_address: connected_addr.clone(),
                    client_address: connected_addr,
                    is_relayed: true,
                    noise: nw_result.clone(),
                    local_stream_id,
                    remote_udx: remote_payload.udx.clone(),
                })
            }
            Ok(Some(HolepunchEvent::Aborted)) | Ok(None) => Err(HyperDhtError::HolepunchAborted),
            Err(_) => {
                puncher.destroy();
                Err(HyperDhtError::HolepunchFailed)
            }
        }
    }

    /// Establish an encrypted connection to a peer via a relay node.
    ///
    /// The relay node forwards raw UDX packets between the two peers using
    /// the blind-relay protocol. The returned [`PeerConnection`] is encrypted
    /// end-to-end with the original peer's keys (the relay cannot read the data).
    ///
    /// `relay_addr_hints` are optional addresses where the relay may be reachable
    /// directly (e.g. from the server's NoisePayload `relay_addresses`). They are
    /// tried first before falling back to full DHT routing.
    #[allow(clippy::too_many_arguments)]
    async fn relay_connection(
        &self,
        key_pair: &KeyPair,
        relay_through: &RelayThroughInfo,
        relay_addr_hints: &[Ipv4Peer],
        noise_result: &NoiseWrapResult,
        relay_is_initiator: bool,
        noise_is_initiator: bool,
        runtime: &UdxRuntime,
    ) -> Result<PeerConnection, HyperDhtError> {
        // 1. HyperDHT connection to the relay node.
        // Try known addresses first (pre-connect), then fall back to DHT routing.
        // Node.js does `dht.connect(publicKey)` — we enhance with address hints.
        let relay_conn = self
            .connect_with_nodes(
                key_pair,
                relay_through.public_key,
                relay_addr_hints,
                runtime,
            )
            .await?;

        let relay_addr = relay_conn.remote_addr.ok_or_else(|| {
            HyperDhtError::StreamEstablishment("relay connection has no remote_addr".into())
        })?;

        // 2. Protomux over the control channel.
        let (mux, mux_run) = Mux::new(relay_conn.stream);
        let mux_task = tokio::spawn(mux_run);

        // 3. Open blind-relay client with our public key as channel id.
        // The relay server uses `id = socket.remotePublicKey` (our key).
        let mut relay_client =
            BlindRelayClient::open(&mux, Some(key_pair.public_key.to_vec())).await?;
        relay_client.wait_opened().await?;

        let data_stream_id = next_stream_id();

        let pair_response = relay_client
            .pair(
                relay_is_initiator,
                &relay_through.token,
                u64::from(data_stream_id),
            )
            .await?;

        let remote_id = u32::try_from(pair_response.remote_id).map_err(|_| {
            HyperDhtError::StreamEstablishment("relay remote_id out of u32 range".into())
        })?;

        // 4. Connect data UDX stream through the relay, reusing the control
        //    channel's socket so the relay sees traffic from the same source address.
        let data_stream = runtime.create_stream(data_stream_id).await?;
        data_stream
            .connect(&relay_conn.socket, remote_id, relay_addr)
            .await?;

        // 5. Wrap with SecretStream::from_session using the original peer's
        //    Noise keys (end-to-end encryption through the relay).
        let async_stream = data_stream.into_async_stream();
        let ss = SecretStream::from_session(
            noise_is_initiator,
            async_stream,
            noise_result.tx,
            noise_result.rx,
            noise_result.handshake_hash,
            noise_result.remote_public_key,
        )
        .await?;

        Ok(PeerConnection {
            stream: ss,
            remote_public_key: noise_result.remote_public_key,
            remote_addr: Some(relay_addr),
            socket: relay_conn.socket,
            _relay_task: Some(mux_task),
        })
    }
}

/// Create a UDX stream, connect it to the remote peer, and wrap with
/// [`SecretStream::from_session`] using the Noise handshake keys.
///
/// Call after [`HyperDhtHandle::connect`] to upgrade a [`ConnectResult`]
/// into an encrypted bidirectional stream.
///
/// A fresh UDX socket bound to an ephemeral port is created for the stream.
/// To reuse an existing socket (Node.js-style single-socket multiplexing),
/// use [`establish_stream_with_socket`] instead.
pub async fn establish_stream(
    result: &ConnectResult,
    runtime: &UdxRuntime,
) -> Result<PeerConnection, HyperDhtError> {
    establish_stream_with_socket(result, runtime, None).await
}

/// Call after [`HyperDhtHandle::connect`] to upgrade a [`ConnectResult`]
/// into an encrypted bidirectional stream, optionally reusing an existing socket.
///
/// When `shared_socket` is `Some`, the stream reuses that socket (matching
/// the Node.js single-socket multiplexing model). When `None`, a fresh socket
/// bound to an ephemeral port is created.
pub async fn establish_stream_with_socket(
    result: &ConnectResult,
    runtime: &UdxRuntime,
    shared_socket: Option<UdxSocket>,
) -> Result<PeerConnection, HyperDhtError> {
    let remote_udx = result
        .remote_udx
        .as_ref()
        .ok_or_else(|| HyperDhtError::StreamEstablishment("no remote UDX info".into()))?;

    let remote_id = u32::try_from(remote_udx.id)
        .map_err(|_| HyperDhtError::StreamEstablishment("remote UDX id out of u32 range".into()))?;

    let addr: SocketAddr = SocketAddr::new(
        result
            .server_address
            .host
            .parse()
            .map_err(|e| HyperDhtError::StreamEstablishment(format!("invalid address: {e}")))?,
        result.server_address.port,
    );

    tracing::debug!(local_id = result.local_stream_id, remote_id, %addr, "establishing UDX stream");
    let socket = if let Some(s) = shared_socket {
        s
    } else {
        let s = runtime.create_socket().await?;
        s.bind("0.0.0.0:0".parse().expect("valid addr")).await?;
        s
    };
    let stream = runtime.create_stream(result.local_stream_id).await?;
    stream.connect(&socket, remote_id, addr).await?;

    let async_stream = stream.into_async_stream();
    let ss = SecretStream::from_session(
        result.noise.is_initiator,
        async_stream,
        result.noise.tx,
        result.noise.rx,
        result.noise.handshake_hash,
        result.noise.remote_public_key,
    )
    .await?;
    tracing::debug!("SecretStream established");

    Ok(PeerConnection {
        remote_public_key: result.remote_public_key,
        stream: ss,
        remote_addr: Some(addr),
        socket,
        _relay_task: None,
    })
}

// ── Server-side event handler ─────────────────────────────────────────────────

/// Per-server state for pending handshake and holepunch exchanges.
pub struct ServerSession {
    /// Cached holepunch secrets indexed by remote public key.
    holepunch_secrets: std::collections::HashMap<[u8; 32], ServerPeerState>,
    /// One active authenticated static key per concrete UDP endpoint.  This
    /// prevents a single source address from manufacturing a set of candidate
    /// secrets that each incoming packet must try.
    session_by_endpoint: std::collections::HashMap<(String, u16), [u8; 32]>,
    capacity: usize,
    ttl: Duration,
    #[cfg(test)]
    holepunch_decrypt_attempts: usize,
}

#[allow(dead_code)]
struct ServerPeerState {
    holepunch_secret: [u8; 32],
    remote_public_key: [u8; 32],
    client_address: Ipv4Peer,
    local_stream_id: u32,
    remote_udx: Option<UdxInfo>,
    last_authenticated_at: Instant,
}

impl ServerSession {
    fn new() -> Self {
        Self {
            holepunch_secrets: std::collections::HashMap::new(),
            session_by_endpoint: std::collections::HashMap::new(),
            capacity: SERVER_SESSION_CAPACITY,
            ttl: SERVER_SESSION_TTL,
            #[cfg(test)]
            holepunch_decrypt_attempts: 0,
        }
    }

    #[cfg(test)]
    fn with_limits_for_test(capacity: usize, ttl: Duration) -> Self {
        Self {
            holepunch_secrets: std::collections::HashMap::new(),
            session_by_endpoint: std::collections::HashMap::new(),
            capacity,
            ttl,
            holepunch_decrypt_attempts: 0,
        }
    }

    fn gc_expired(&mut self) -> usize {
        self.gc_expired_at(Instant::now())
    }

    fn gc_expired_at(&mut self, now: Instant) -> usize {
        let before = self.holepunch_secrets.len();
        self.holepunch_secrets.retain(|_, state| {
            now.checked_duration_since(state.last_authenticated_at)
                .is_none_or(|age| age < self.ttl)
        });
        let sessions = &self.holepunch_secrets;
        self.session_by_endpoint.retain(|endpoint, public_key| {
            sessions
                .get(public_key)
                .is_some_and(|state| Self::endpoint_key(&state.client_address) == *endpoint)
        });
        before.saturating_sub(self.holepunch_secrets.len())
    }

    fn endpoint_key(peer: &Ipv4Peer) -> (String, u16) {
        (peer.host.clone(), peer.port)
    }

    /// Store a successful Noise authentication.  Existing remote keys refresh
    /// their TTL in place.  New keys never evict a live session when the cap is
    /// reached; the handshake is rejected instead.
    fn admit_authenticated_at(&mut self, mut state: ServerPeerState, now: Instant) -> bool {
        self.gc_expired_at(now);
        state.last_authenticated_at = now;
        let endpoint = Self::endpoint_key(&state.client_address);
        let public_key = state.remote_public_key;

        if let Some(existing_key) = self.session_by_endpoint.get(&endpoint)
            && *existing_key != public_key
        {
            // A different static key on the same source endpoint is a new
            // candidate-secret amplification attempt. Do not replace a live
            // authenticated session merely because another key appeared there.
            return false;
        }

        if let Some(existing) = self.holepunch_secrets.get(&public_key) {
            let old_endpoint = Self::endpoint_key(&existing.client_address);
            let existing_key = existing.remote_public_key;
            if old_endpoint != endpoint {
                // A reauthenticated static key may move endpoints, but only
                // when the new endpoint is not owned by another live key.
                self.session_by_endpoint.remove(&old_endpoint);
            }
            self.holepunch_secrets.insert(public_key, state);
            self.session_by_endpoint.insert(endpoint, existing_key);
            return true;
        }

        if self.holepunch_secrets.len() >= self.capacity {
            return false;
        }

        self.holepunch_secrets.insert(public_key, state);
        self.session_by_endpoint.insert(endpoint, public_key);
        true
    }

    fn admit_authenticated(&mut self, state: ServerPeerState) -> bool {
        self.admit_authenticated_at(state, Instant::now())
    }

    /// Return a holepunch secret only when the encrypted payload and both
    /// transport-facing addresses agree with one authenticated session.
    ///
    /// `reported_peer` is decoded from a relayed packet and is therefore never
    /// authority by itself. Generic `run_server` has no authenticated relay
    /// delegation protocol, so accepting a relayed holepunch requires it to
    /// describe the exact endpoint that completed the Noise handshake and to
    /// arrive from that same endpoint. This intentionally fails closed for a
    /// relay whose source differs from the authenticated client.
    fn authenticated_holepunch_secret(
        &mut self,
        encrypted_payload: &[u8],
        actual_from: &Ipv4Peer,
        reported_peer: &Ipv4Peer,
    ) -> Option<([u8; 32], Ipv4Peer)> {
        self.gc_expired();

        let endpoint = Self::endpoint_key(actual_from);
        let public_key = *self.session_by_endpoint.get(&endpoint)?;
        let (secret, client_address) = {
            let state = self.holepunch_secrets.get(&public_key)?;
            if state.client_address != *actual_from || state.client_address != *reported_peer {
                return None;
            }
            (state.holepunch_secret, state.client_address.clone())
        };

        #[cfg(test)]
        {
            self.holepunch_decrypt_attempts += 1;
        }
        SecurePayload::new(secret)
            .decrypt(encrypted_payload)
            .ok()
            .map(|_| (secret, client_address))
    }

    #[cfg(test)]
    fn holepunch_decrypt_attempts(&self) -> usize {
        self.holepunch_decrypt_attempts
    }
}

/// Bounded server-owned execution for remote holepunch requests.  The permits
/// live inside the joined tasks, so task completion (or shutdown) releases
/// capacity without leaving background work detached from `run_server`.
struct ServerPunchWork {
    admission: Arc<Semaphore>,
    tasks: JoinSet<()>,
}

impl ServerPunchWork {
    fn new() -> Self {
        Self::with_limit(SERVER_HOLEPUNCH_TASK_CAPACITY)
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            admission: Arc::new(Semaphore::new(limit)),
            tasks: JoinSet::new(),
        }
    }

    #[cfg(test)]
    fn with_limit_for_test(limit: usize) -> Self {
        Self::with_limit(limit)
    }

    /// Reap every task that already finished without blocking the DHT actor.
    fn reap_completed(&mut self) -> usize {
        let mut reaped = 0;
        while let Some(result) = self.tasks.try_join_next() {
            reaped += 1;
            if let Err(error) = result {
                tracing::warn!(%error, "server holepunch task ended unexpectedly");
            }
        }
        reaped
    }

    /// Fail closed when all punch slots are occupied.  The future is only
    /// accepted after an owned permit has been acquired, and is always retained
    /// in this actor's `JoinSet`.
    fn try_spawn<F>(&mut self, work: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.reap_completed();
        let Ok(permit) = Arc::clone(&self.admission).try_acquire_owned() else {
            return false;
        };

        self.tasks.spawn(async move {
            let _permit = permit;
            work.await;
        });
        true
    }

    /// Stop accepting work before cancelling it, then await every join result.
    /// This is deliberately explicit instead of relying on `JoinSet` drop,
    /// which would abort work without proving it was drained.
    async fn shutdown(&mut self) {
        self.admission.close();
        self.tasks.abort_all();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                tracing::warn!(%error, "server holepunch task failed during shutdown");
            }
        }
    }
}

/// Run the server-side request loop for peer handshakes and holepunches.
pub async fn run_server(
    mut event_rx: mpsc::Receiver<ServerEvent>,
    config: ServerConfig,
    runtime: UdxRuntime,
) {
    let mut session = ServerSession::new();
    let mut punch_work = ServerPunchWork::new();
    let mut gc_tick = tokio::time::interval(SERVER_SESSION_GC_INTERVAL);
    gc_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = gc_tick.tick() => {
                session.gc_expired();
                punch_work.reap_completed();
            }
            event = event_rx.recv() => {
                let Some(event) = event else {
                    break;
                };
                punch_work.reap_completed();
                match event {
                    ServerEvent::PeerHandshake {
                        msg,
                        from,
                        target,
                        reply_tx,
                    } => {
                        let reply = handle_server_handshake(
                            &config,
                            &mut session,
                            msg,
                            &from,
                            target.as_ref(),
                        );
                        let _ = reply_tx.send(reply);
                    }
                    ServerEvent::PeerHolepunch {
                        msg,
                        from,
                        peer_address,
                        target: _,
                        reply_tx,
                    } => {
                        let reply = handle_server_holepunch(
                            &config,
                            &mut session,
                            &runtime,
                            &mut punch_work,
                            msg,
                            &from,
                            &peer_address,
                        )
                        .await;
                        let _ = reply_tx.send(reply);
                    }
                }
            }
        }
    }

    punch_work.shutdown().await;
}

fn handle_server_handshake(
    config: &ServerConfig,
    session: &mut ServerSession,
    msg: HandshakeMessage,
    from: &Ipv4Peer,
    _target: Option<&NodeId>,
) -> Option<Vec<u8>> {
    let mut nw = NoiseWrap::new_responder(config.key_pair.to_noise_keypair());

    let remote_payload = match nw.recv(&msg.noise) {
        Ok(p) => p,
        Err(_) => return None,
    };

    if remote_payload.error != 0 {
        return None;
    }

    let local_stream_id = next_stream_id();

    let reply_payload = NoisePayload {
        version: 1,
        error: 0,
        firewall: config.firewall,
        holepunch: None,
        addresses4: vec![],
        addresses6: vec![],
        udx: Some(UdxInfo {
            version: 1,
            reusable_socket: true,
            id: u64::from(local_stream_id),
            seq: 0,
        }),
        secret_stream: Some(SecretStreamInfo { version: 1 }),
        relay_through: None,
        relay_addresses: None,
    };

    let noise_reply = match nw.send(&reply_payload) {
        Ok(b) => b,
        Err(_) => return None,
    };

    let nw_result = match nw.finalize() {
        Ok(r) => r,
        Err(_) => return None,
    };

    if !session.admit_authenticated(ServerPeerState {
        holepunch_secret: nw_result.holepunch_secret,
        remote_public_key: nw_result.remote_public_key,
        client_address: from.clone(),
        local_stream_id,
        remote_udx: remote_payload.udx.clone(),
        last_authenticated_at: Instant::now(),
    }) {
        tracing::debug!("server session admission rejected at capacity");
        return None;
    }

    let reply_msg = HandshakeMessage {
        mode: crate::hyperdht_messages::MODE_REPLY,
        noise: noise_reply,
        // `from` is the request sender (and can be a relay), not this
        // server's endpoint. This generic server has no independently
        // observed public endpoint to advertise, so omit it rather than
        // causing a client to self-connect or promote relay metadata.
        peer_address: None,
        relay_address: None,
    };

    crate::hyperdht_messages::encode_handshake_to_bytes(&reply_msg).ok()
}

async fn handle_server_holepunch(
    config: &ServerConfig,
    session: &mut ServerSession,
    runtime: &UdxRuntime,
    punch_work: &mut ServerPunchWork,
    msg: HolepunchMessage,
    actual_from: &Ipv4Peer,
    reported_peer: &Ipv4Peer,
) -> Option<Vec<u8>> {
    let (matched_secret, verified_peer) =
        session.authenticated_holepunch_secret(&msg.payload, actual_from, reported_peer)?;
    let sp = SecurePayload::new(matched_secret);

    let remote_hp = sp.decrypt(&msg.payload).ok()?;

    let reply_hp = HolepunchPayload {
        error: 0,
        firewall: config.firewall,
        round: remote_hp.round,
        connected: false,
        punching: remote_hp.punching,
        addresses: Some(vec![verified_peer.clone()]),
        remote_address: Some(verified_peer.clone()),
        token: Some(sp.token(&verified_peer.host)),
        remote_token: remote_hp.token,
    };

    let encrypted_reply = sp.encrypt(&reply_hp).ok()?;

    if remote_hp.punching
        && !punch_work.try_spawn(run_server_holepunch_work(
            runtime.handle(),
            remote_hp.firewall,
            verified_peer.clone(),
        ))
    {
        tracing::debug!("server holepunch admission rejected at capacity");
        return None;
    }

    let reply_msg = HolepunchMessage {
        mode: crate::hyperdht_messages::MODE_REPLY,
        id: msg.id,
        payload: encrypted_reply,
        peer_address: Some(verified_peer.clone()),
    };

    crate::hyperdht_messages::encode_holepunch_msg_to_bytes(&reply_msg).ok()
}

async fn run_server_holepunch_work(
    runtime_handle: Arc<libudx::RuntimeHandle>,
    remote_firewall: u64,
    verified_peer: Ipv4Peer,
) {
    let runtime = UdxRuntime::shared(runtime_handle);
    let pool = SocketPool::new("0.0.0.0".into());
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let Ok(mut puncher) =
        Holepuncher::new(&pool, &runtime, true, false, remote_firewall, event_tx).await
    else {
        return;
    };

    puncher.update_remote(
        true,
        remote_firewall,
        std::slice::from_ref(&verified_peer),
        Some(verified_peer.host.as_str()),
    );
    let _ = puncher.punch(&pool, &runtime).await;
}

// ── Startup ownership ─────────────────────────────────────────────────────────

/// Owns the two background tasks that make up a HyperDHT node.
///
/// The raw DHT task must outlive the request handler, but both tasks must be
/// drained before the runtime used to create them is dropped.  This owner makes
/// that relationship explicit instead of losing the request-handler join handle
/// behind the public DHT task.
pub struct HyperDhtOwner {
    dht: HyperDhtHandle,
    raw_dht_task: Option<JoinHandle<Result<(), HyperDhtError>>>,
    request_handler_task: Option<JoinHandle<()>>,
}

impl HyperDhtOwner {
    /// Access the DHT controlled by this owner.
    pub fn handle(&self) -> &HyperDhtHandle {
        &self.dht
    }

    /// Stop the DHT and drain both owned background tasks.
    ///
    /// This method is deliberately idempotent with respect to a caller having
    /// already destroyed the DHT through [`HyperDhtHandle::destroy`]: it always
    /// drains both tasks and reports the first task failure instead.
    pub async fn shutdown(&mut self) -> Result<(), HyperDhtError> {
        // The actor may already have destroyed the DHT.  Either way, requesting
        // destruction first closes the request subscription so its handler can
        // finish before its JoinHandle is released.
        let _ = self.dht.destroy().await;

        let raw_result = match self.raw_dht_task.as_mut() {
            Some(task) => map_raw_dht_task(task.await),
            None => Ok(()),
        };
        // Keep each JoinHandle in `self` until its await has completed.  If
        // this future is itself cancelled, `Drop` can still abort either task
        // rather than accidentally detaching a handle held in a local.
        self.raw_dht_task.take();
        let request_result = match self.request_handler_task.as_mut() {
            Some(task) => map_request_handler_task(task.await),
            None => Ok(()),
        };
        self.request_handler_task.take();

        raw_result.and(request_result)
    }

    /// Wait for either owned task to finish, then stop and drain the other.
    ///
    /// This is used by the legacy [`spawn`] compatibility wrapper.  It retains
    /// the historic single JoinHandle surface while ensuring the nested task is
    /// never detached.
    pub async fn join(mut self) -> Result<(), HyperDhtError> {
        tokio::select! {
            raw_result = self.raw_dht_task.as_mut().expect("HyperDhtOwner raw DHT task is present before join") => {
                let result = map_raw_dht_task(raw_result);
                self.raw_dht_task.take();
                let _ = self.shutdown().await;
                result
            }
            request_result = self.request_handler_task.as_mut().expect("HyperDhtOwner request handler task is present before join") => {
                let result = map_request_handler_task(request_result);
                self.request_handler_task.take();
                let _ = self.shutdown().await;
                result
            }
        }
    }
}

impl Drop for HyperDhtOwner {
    fn drop(&mut self) {
        // Async destruction cannot run from Drop.  Aborting here is the
        // cancellation fallback: it prevents either owned task from becoming a
        // detached background task when a startup future is cancelled.  Normal
        // paths use `shutdown`/`join`, which drain both tasks first.
        if let Some(task) = &self.raw_dht_task {
            task.abort();
        }
        if let Some(task) = &self.request_handler_task {
            task.abort();
        }
    }
}

fn map_raw_dht_task(
    result: Result<Result<(), HyperDhtError>, tokio::task::JoinError>,
) -> Result<(), HyperDhtError> {
    match result {
        Ok(result) => result,
        Err(_) => Err(HyperDhtError::ChannelClosed),
    }
}

fn map_request_handler_task(
    result: Result<(), tokio::task::JoinError>,
) -> Result<(), HyperDhtError> {
    match result {
        Ok(()) => Ok(()),
        Err(_) => Err(HyperDhtError::ChannelClosed),
    }
}

/// A started HyperDHT node whose task ownership is available before bootstrap.
///
/// Keep this value alive while awaiting [`Self::bootstrapped`].  On a timeout
/// or bootstrap error, call [`Self::shutdown`] to close and drain both nested
/// tasks.  Once startup succeeds, [`Self::finish`] transfers their ownership to
/// a [`HyperDhtOwner`].
pub struct HyperDhtStartup {
    owner: HyperDhtOwner,
    server_rx: mpsc::Receiver<ServerEvent>,
}

impl HyperDhtStartup {
    /// Access the started DHT before bootstrap has completed.
    pub fn handle(&self) -> &HyperDhtHandle {
        self.owner.handle()
    }

    /// Wait until the started DHT has completed bootstrap.
    pub async fn bootstrapped(&self) -> Result<(), HyperDhtError> {
        self.handle().bootstrapped().await
    }

    /// Transfer task ownership and the server event stream to the caller.
    pub fn finish(self) -> (HyperDhtOwner, HyperDhtHandle, mpsc::Receiver<ServerEvent>) {
        let handle = self.owner.handle().clone();
        (self.owner, handle, self.server_rx)
    }

    /// Stop the started DHT and drain all of its tasks.
    pub async fn shutdown(mut self) -> Result<(), HyperDhtError> {
        self.owner.shutdown().await
    }
}

/// Start a HyperDHT instance while retaining ownership before bootstrap.
pub async fn spawn_starting(
    runtime: &UdxRuntime,
    config: HyperDhtConfig,
) -> Result<HyperDhtStartup, HyperDhtError> {
    let (dht_join, dht_handle) = crate::rpc::spawn(runtime, config.dht).await?;
    let persistent_config = config.persistent;

    let request_rx = dht_handle
        .subscribe_requests()
        .await
        .ok_or(HyperDhtError::ChannelClosed)?;

    let router = Arc::new(Mutex::new(Router::new()));
    let (server_tx, server_rx) = mpsc::channel(SERVER_EVENT_QUEUE_CAPACITY);
    let (admin_tx, admin_rx) = mpsc::unbounded_channel::<AdminRequest>();

    let request_task = tokio::spawn(run_request_handler(
        request_rx,
        persistent_config,
        dht_handle.clone(),
        Arc::clone(&router),
        server_tx.clone(),
        admin_rx,
    ));

    let handle = HyperDhtHandle {
        dht: dht_handle,
        router,
        server_tx,
        admin_tx,
    };
    Ok(HyperDhtStartup {
        owner: HyperDhtOwner {
            dht: handle,
            raw_dht_task: Some(tokio::spawn(async move {
                match dht_join.await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(HyperDhtError::Dht(error)),
                    Err(_) => Err(HyperDhtError::ChannelClosed),
                }
            })),
            request_handler_task: Some(request_task),
        },
        server_rx,
    })
}

/// Create a HyperDHT instance and start its background tasks.
///
/// This source-compatible convenience function retains the historic single
/// JoinHandle result.  The returned task owns and drains both the raw DHT and
/// request-handler tasks; use [`spawn_starting`] when startup itself must be
/// cancellation-safe.
pub async fn spawn(
    runtime: &UdxRuntime,
    config: HyperDhtConfig,
) -> Result<
    (
        JoinHandle<Result<(), HyperDhtError>>,
        HyperDhtHandle,
        mpsc::Receiver<ServerEvent>,
    ),
    HyperDhtError,
> {
    let startup = spawn_starting(runtime, config).await?;
    let (owner, handle, server_rx) = startup.finish();
    Ok((tokio::spawn(owner.join()), handle, server_rx))
}

async fn run_request_handler(
    mut rx: tokio::sync::mpsc::Receiver<crate::rpc::UserRequest>,
    config: PersistentConfig,
    dht: DhtHandle,
    router: Arc<Mutex<Router>>,
    server_tx: mpsc::Sender<ServerEvent>,
    mut admin_rx: mpsc::UnboundedReceiver<AdminRequest>,
) {
    let mut storage = Persistent::new(config);
    let mut gc_tick = tokio::time::interval(ROUTING_STATE_GC_INTERVAL);
    gc_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let mut req = tokio::select! {
            biased;
            _ = gc_tick.tick() => {
                storage.gc();
                if let Ok(mut route_cache) = router.lock() {
                    route_cache.gc();
                }
                continue;
            }
            Some(admin_req) = admin_rx.recv() => {
                storage.gc();
                if let Ok(mut route_cache) = router.lock() {
                    route_cache.gc();
                }
                match admin_req {
                    AdminRequest::PersistentStats { reply } => {
                        let _ = reply.send(storage.stats());
                    }
                }
                continue;
            }
            req = rx.recv() => match req {
                Some(r) => r,
                None => break,
            },
        };
        // The interval above reclaims idle state. Reclaim here as well so a
        // busy request stream cannot postpone expiry indefinitely.
        storage.gc();
        if let Ok(mut route_cache) = router.lock() {
            route_cache.gc();
        }
        match req.command {
            PEER_HANDSHAKE => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: PEER_HANDSHAKE");
                handle_peer_handshake(req, &dht, &router, &server_tx);
                continue;
            }
            PEER_HOLEPUNCH => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: PEER_HOLEPUNCH");
                handle_peer_holepunch(req, &dht, &router, &server_tx);
                continue;
            }
            _ => {}
        }

        let node_id = req.id;

        let incoming = IncomingHyperRequest {
            command: req.command,
            target: req.target,
            token: req.token,
            value: req.value.clone(),
            from: req.from.clone(),
            id: node_id,
        };

        let reply = match req.command {
            FIND_PEER => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: FIND_PEER");
                storage.on_find_peer(&incoming)
            }
            LOOKUP => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: LOOKUP");
                storage.on_lookup(&incoming)
            }
            ANNOUNCE => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: ANNOUNCE");
                let own_id = dht.table_id().await.ok().flatten();
                if let Some(nid) = own_id {
                    let result = storage.on_announce(&incoming, &nid);
                    let forward_admitted = if !matches!(&result, HandlerReply::Silent) {
                        if let Some(target) = incoming.target {
                            match router.lock() {
                                Ok(mut r) => {
                                    let already_server =
                                        r.get(&target).is_some_and(|e| e.has_server);
                                    already_server
                                        || r.set(
                                            &target,
                                            ForwardEntry {
                                                relay: Some(incoming.from.clone()),
                                                has_server: false,
                                                inserted: std::time::Instant::now(),
                                            },
                                        )
                                }
                                // A poisoned route cache is not safe to
                                // mutate or acknowledge as admitted.
                                Err(_) => false,
                            }
                        } else {
                            true
                        }
                    } else {
                        true
                    };
                    if forward_admitted {
                        result
                    } else {
                        // The persistent handler did validate the packet, but
                        // this node cannot retain a new forwarding route
                        // without evicting a live entry. Do not acknowledge
                        // it as admitted.
                        HandlerReply::Silent
                    }
                } else {
                    HandlerReply::Silent
                }
            }
            UNANNOUNCE => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: UNANNOUNCE");
                let own_id = dht.table_id().await.ok().flatten();
                if let Some(nid) = own_id {
                    storage.on_unannounce(&incoming, &nid)
                } else {
                    HandlerReply::Silent
                }
            }
            MUTABLE_PUT => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: MUTABLE_PUT");
                storage.on_mutable_put(&incoming)
            }
            MUTABLE_GET => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: MUTABLE_GET");
                storage.on_mutable_get(&incoming)
            }
            IMMUTABLE_PUT => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: IMMUTABLE_PUT");
                storage.on_immutable_put(&incoming)
            }
            IMMUTABLE_GET => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: IMMUTABLE_GET");
                storage.on_immutable_get(&incoming)
            }
            _ => {
                tracing::debug!(cmd = req.command, from = %format!("{}:{}", req.from.host, req.from.port), "request: unknown command");
                drop(req);
                continue;
            }
        };

        match reply {
            HandlerReply::Value(v) | HandlerReply::ValueNoToken(v) => {
                req.reply(v);
            }
            HandlerReply::Error(code) => {
                req.error(code);
            }
            HandlerReply::Silent => {
                drop(req);
            }
        }
    }
}

/// Attempts to queue an externally driven server event without awaiting
/// capacity. A saturated or closed local-server queue is an admission failure,
/// so the inbound DHT request is rejected immediately. The event owns its reply
/// capability and admission slot; no per-event waiter task is created.
fn try_admit_server_event(server_tx: &mpsc::Sender<ServerEvent>, event: ServerEvent) -> bool {
    match server_tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(event))
        | Err(mpsc::error::TrySendError::Closed(event)) => {
            event.reject(GENERIC_DHT_REJECTION);
            false
        }
    }
}

fn handle_peer_handshake(
    mut req: crate::rpc::UserRequest,
    dht: &DhtHandle,
    router: &Arc<Mutex<Router>>,
    server_tx: &mpsc::Sender<ServerEvent>,
) {
    let Some(value) = &req.value else {
        req.error(1);
        return;
    };

    let action = {
        let router = match router.lock() {
            Ok(r) => r,
            Err(_) => {
                req.error(1);
                return;
            }
        };
        match router.route_handshake(req.target.as_ref(), &req.from, value) {
            Ok(a) => a,
            Err(_) => {
                req.error(1);
                return;
            }
        }
    };

    match action {
        HandshakeAction::Relay { value, to } => {
            tracing::info!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "handshake RELAY — forwarding between peers"
            );
            let _ = dht.relay(PEER_HANDSHAKE, req.target, Some(value), &to);
            req.reply(None);
        }
        HandshakeAction::Reply(value) => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "handshake REPLY");
            req.reply(Some(value));
        }
        HandshakeAction::HandleLocally(msg) => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "handshake HANDLE_LOCALLY");
            let from = req.from.clone();
            let target = req.target;

            let _ = try_admit_server_event(
                server_tx,
                ServerEvent::PeerHandshake {
                    msg,
                    from,
                    target,
                    reply_tx: ServerReply::new(req),
                },
            );
        }
        HandshakeAction::CloserNodes => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "handshake CLOSER_NODES");
            req.reply(None);
        }
        HandshakeAction::Drop => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "handshake DROP");
            drop(req);
        }
    }
}

fn handle_peer_holepunch(
    mut req: crate::rpc::UserRequest,
    dht: &DhtHandle,
    router: &Arc<Mutex<Router>>,
    server_tx: &mpsc::Sender<ServerEvent>,
) {
    let Some(value) = &req.value else {
        req.error(1);
        return;
    };

    let action = {
        let router = match router.lock() {
            Ok(r) => r,
            Err(_) => {
                req.error(1);
                return;
            }
        };
        match router.route_holepunch(req.target.as_ref(), &req.from, value) {
            Ok(a) => a,
            Err(_) => {
                req.error(1);
                return;
            }
        }
    };

    match action {
        HolepunchAction::Relay { value, to } => {
            tracing::info!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "holepunch RELAY — forwarding between peers"
            );
            let _ = dht.relay(PEER_HOLEPUNCH, req.target, Some(value), &to);
            req.reply(None);
        }
        HolepunchAction::Reply { value, to } => {
            tracing::debug!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "holepunch REPLY"
            );
            let _ = dht.relay(PEER_HOLEPUNCH, req.target, Some(value), &to);
            req.reply(None);
        }
        HolepunchAction::HandleLocally { msg, peer_address } => {
            tracing::debug!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                peer = %format!("{:?}", peer_address),
                "holepunch HANDLE_LOCALLY"
            );
            let from = req.from.clone();
            let target = req.target;

            let _ = try_admit_server_event(
                server_tx,
                ServerEvent::PeerHolepunch {
                    msg,
                    from,
                    peer_address,
                    target,
                    reply_tx: ServerReply::new(req),
                },
            );
        }
        HolepunchAction::Drop => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "holepunch DROP");
            drop(req);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn encode_compact_uint(v: u64) -> Vec<u8> {
    let mut state = crate::compact_encoding::State::new();
    crate::compact_encoding::preencode_uint(&mut state, v);
    state.alloc();
    crate::compact_encoding::encode_uint(&mut state, v);
    state.buffer
}

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").ok();
            s
        })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperdht_messages::{FIREWALL_CONSISTENT, FIREWALL_RANDOM};

    fn test_peer() -> Ipv4Peer {
        Ipv4Peer {
            host: "198.51.100.1".to_string(),
            port: 42_424,
        }
    }

    fn test_handshake_event(request: crate::rpc::UserRequest) -> ServerEvent {
        ServerEvent::PeerHandshake {
            msg: HandshakeMessage {
                mode: 0,
                noise: Vec::new(),
                peer_address: None,
                relay_address: None,
            },
            from: test_peer(),
            target: None,
            reply_tx: ServerReply::new(request),
        }
    }

    fn test_holepunch_event(request: crate::rpc::UserRequest) -> ServerEvent {
        ServerEvent::PeerHolepunch {
            msg: HolepunchMessage {
                mode: 0,
                id: 0,
                payload: Vec::new(),
                peer_address: None,
            },
            from: test_peer(),
            peer_address: test_peer(),
            target: None,
            reply_tx: ServerReply::new(request),
        }
    }

    async fn assert_server_event_admission_is_bounded_and_recovers(
        mut make_event: impl FnMut(crate::rpc::UserRequest) -> ServerEvent,
    ) {
        let (server_tx, mut server_rx) = mpsc::channel(SERVER_EVENT_QUEUE_CAPACITY);
        for _ in 0..SERVER_EVENT_QUEUE_CAPACITY {
            let (reply_tx, _reply_rx) = oneshot::channel();
            server_tx
                .try_send(make_event(crate::rpc::UserRequest::test_with_reply(
                    0, reply_tx,
                )))
                .expect("queue must admit exactly its configured capacity");
        }
        assert_eq!(server_rx.len(), SERVER_EVENT_QUEUE_CAPACITY);

        let (request_reply_tx, request_reply_rx) = oneshot::channel();
        let request = crate::rpc::UserRequest::test_with_reply(1, request_reply_tx);
        assert!(
            !try_admit_server_event(&server_tx, make_event(request)),
            "full server event queue must reject immediately"
        );
        assert_eq!(
            request_reply_rx
                .await
                .expect("full-queue rejection must reply to the DHT request"),
            (GENERIC_DHT_REJECTION, None)
        );

        for _ in 0..SERVER_EVENT_QUEUE_CAPACITY {
            drop(server_rx.recv().await.expect("queued server event"));
        }

        let (request_reply_tx, request_reply_rx) = oneshot::channel();
        let request = crate::rpc::UserRequest::test_with_reply(2, request_reply_tx);
        assert!(
            try_admit_server_event(&server_tx, make_event(request),),
            "admission must recover after one event drains"
        );

        let event = server_rx.recv().await.expect("recovered server event");
        match event {
            ServerEvent::PeerHandshake { reply_tx, .. }
            | ServerEvent::PeerHolepunch { reply_tx, .. } => {
                reply_tx
                    .send(Some(vec![0xA5]))
                    .expect("event reply capability must remain attached after admission");
            }
        }
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), request_reply_rx)
                .await
                .expect("accepted request waiter must finish")
                .expect("accepted request reply"),
            (0, Some(vec![0xA5]))
        );
    }

    #[test]
    fn hyperdht_config_defaults() {
        let cfg = HyperDhtConfig::default();
        assert_eq!(cfg.dht.port, 0);
        assert_eq!(cfg.dht.host, "0.0.0.0");
        assert_eq!(cfg.dht.concurrency, 10);
        assert!(cfg.dht.bootstrap.is_empty());
        assert_eq!(
            cfg.persistent.max_records,
            PersistentConfig::default().max_records
        );
        assert_eq!(
            cfg.persistent.max_per_key,
            PersistentConfig::default().max_per_key
        );
    }

    #[tokio::test]
    async fn peer_handshake_admission_is_bounded_and_recovers() {
        assert_server_event_admission_is_bounded_and_recovers(test_handshake_event).await;
    }

    #[tokio::test]
    async fn peer_holepunch_admission_is_bounded_and_recovers() {
        assert_server_event_admission_is_bounded_and_recovers(test_holepunch_event).await;
    }

    #[tokio::test]
    async fn closed_server_event_queue_rejects_immediately() {
        let (server_tx, server_rx) = mpsc::channel(SERVER_EVENT_QUEUE_CAPACITY);
        drop(server_rx);

        let (request_reply_tx, request_reply_rx) = oneshot::channel();
        let request = crate::rpc::UserRequest::test_with_reply(1, request_reply_tx);

        assert!(
            !try_admit_server_event(&server_tx, test_handshake_event(request),),
            "closed server event queue must reject immediately"
        );
        assert_eq!(
            request_reply_rx
                .await
                .expect("closed-queue rejection must reply to the DHT request"),
            (GENERIC_DHT_REJECTION, None)
        );
    }

    #[test]
    fn keypair_generate_produces_unique_keys() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn keypair_from_seed_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = KeyPair::from_seed(seed);
        let kp2 = KeyPair::from_seed(seed);
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.secret_key, kp2.secret_key);
    }

    #[test]
    fn keypair_public_key_matches_secret() {
        let kp = KeyPair::from_seed([0x11u8; 32]);
        assert_eq!(&kp.secret_key[32..], &kp.public_key);
    }

    #[test]
    fn keypair_sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let msg = b"test message";
        let sig = sign_detached(msg, &kp.secret_key);
        assert!(verify_detached(&sig, msg, &kp.public_key));
    }

    #[test]
    fn encode_compact_uint_round_trips() {
        use crate::compact_encoding::{State, decode_uint};
        for val in [0u64, 1, 127, 128, 255, 65535, u64::MAX / 2] {
            let bytes = encode_compact_uint(val);
            let mut s = State::from_buffer(&bytes);
            let decoded = decode_uint(&mut s).unwrap();
            assert_eq!(decoded, val, "compact uint round-trip failed for {val}");
        }
    }

    #[test]
    fn hyperdht_error_display() {
        let e = HyperDhtError::Destroyed;
        assert!(e.to_string().contains("destroyed"));
        let e2 = HyperDhtError::InvalidSignature;
        assert!(e2.to_string().contains("signature"));
    }

    #[test]
    fn keypair_debug_hides_secret() {
        let kp = KeyPair::from_seed([0x42u8; 32]);
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("KeyPair"));
        assert!(!dbg.contains("secret_key"));
    }

    #[tokio::test]
    async fn spawn_and_destroy() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                ..DhtConfig::default()
            },
            persistent: PersistentConfig::default(),
        };
        let (join, handle, _server_rx) = spawn(&runtime, config).await.expect("spawn");
        handle.destroy().await.expect("destroy");
        tokio::time::timeout(std::time::Duration::from_secs(5), join)
            .await
            .expect("legacy join must finish after destroy")
            .expect("legacy join task must not panic")
            .expect("legacy join must drain both DHT tasks cleanly");
    }

    #[tokio::test]
    async fn starting_shutdown_drains_dht_and_request_handler() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                ..DhtConfig::default()
            },
            persistent: PersistentConfig::default(),
        };

        let startup = spawn_starting(&runtime, config).await.expect("start DHT");
        tokio::time::timeout(std::time::Duration::from_secs(5), startup.shutdown())
            .await
            .expect("shutdown must not leave a DHT task behind")
            .expect("shutdown must drain raw DHT and request handler");
    }

    #[tokio::test]
    async fn wire_stats_starts_at_zero_and_is_addressable() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                ..DhtConfig::default()
            },
            persistent: PersistentConfig::default(),
        };
        let (join, handle, _rx) = spawn(&runtime, config).await.expect("spawn");
        let (sent, received) = handle.wire_stats();
        assert_eq!(sent, 0, "no traffic yet");
        assert_eq!(received, 0);
        // Counters are shared via Arc — incrementing through `wire_counters()`
        // must be visible via `wire_stats()`.
        let counters = handle.wire_counters();
        counters
            .bytes_sent
            .fetch_add(123, std::sync::atomic::Ordering::Relaxed);
        counters
            .bytes_received
            .fetch_add(456, std::sync::atomic::Ordering::Relaxed);
        let (sent, received) = handle.wire_stats();
        assert_eq!(sent, 123);
        assert_eq!(received, 456);
        handle.destroy().await.expect("destroy");
        tokio::time::timeout(std::time::Duration::from_secs(5), join)
            .await
            .expect("legacy join must finish after destroy")
            .expect("legacy join task must not panic")
            .expect("legacy join must drain both DHT tasks cleanly");
    }

    #[test]
    fn next_stream_id_is_unique() {
        let a = next_stream_id();
        let b = next_stream_id();
        let c = next_stream_id();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[tokio::test]
    async fn establish_stream_missing_udx_info() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let nw_result = NoiseWrapResult {
            remote_public_key: [0xAA; 32],
            tx: [1; 32],
            rx: [2; 32],
            handshake_hash: [3; 64],
            holepunch_secret: [4; 32],
            is_initiator: true,
        };
        let result = ConnectResult {
            remote_public_key: [0xAA; 32],
            server_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 9999,
            },
            client_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 8888,
            },
            is_relayed: false,
            noise: nw_result,
            local_stream_id: 1,
            remote_udx: None,
        };
        let err = establish_stream(&result, &runtime).await.unwrap_err();
        assert!(matches!(err, HyperDhtError::StreamEstablishment(_)));
    }

    #[tokio::test]
    async fn establish_stream_bad_address() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let nw_result = NoiseWrapResult {
            remote_public_key: [0xBB; 32],
            tx: [1; 32],
            rx: [2; 32],
            handshake_hash: [3; 64],
            holepunch_secret: [4; 32],
            is_initiator: true,
        };
        let result = ConnectResult {
            remote_public_key: [0xBB; 32],
            server_address: Ipv4Peer {
                host: "not-an-ip".into(),
                port: 9999,
            },
            client_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 8888,
            },
            is_relayed: false,
            noise: nw_result,
            local_stream_id: next_stream_id(),
            remote_udx: Some(UdxInfo {
                version: 1,
                reusable_socket: true,
                id: 42,
                seq: 0,
            }),
        };
        let err = establish_stream(&result, &runtime).await.unwrap_err();
        assert!(matches!(err, HyperDhtError::StreamEstablishment(_)));
    }

    #[tokio::test]
    async fn establish_stream_remote_id_overflow() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let nw_result = NoiseWrapResult {
            remote_public_key: [0xCC; 32],
            tx: [1; 32],
            rx: [2; 32],
            handshake_hash: [3; 64],
            holepunch_secret: [4; 32],
            is_initiator: true,
        };
        let result = ConnectResult {
            remote_public_key: [0xCC; 32],
            server_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 9999,
            },
            client_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 8888,
            },
            is_relayed: false,
            noise: nw_result,
            local_stream_id: next_stream_id(),
            remote_udx: Some(UdxInfo {
                version: 1,
                reusable_socket: true,
                id: u64::from(u32::MAX) + 1,
                seq: 0,
            }),
        };
        let err = establish_stream(&result, &runtime).await.unwrap_err();
        assert!(matches!(err, HyperDhtError::StreamEstablishment(_)));
    }

    #[test]
    fn default_bootstrap_has_three_nodes() {
        assert_eq!(DEFAULT_BOOTSTRAP.len(), 3);
        for entry in &DEFAULT_BOOTSTRAP {
            assert!(entry.contains('@'), "missing @ in {entry}");
            assert!(entry.ends_with(":49737"), "wrong port in {entry}");
        }
    }

    #[test]
    fn with_public_bootstrap_populates_nodes() {
        let cfg = HyperDhtConfig::with_public_bootstrap();
        assert_eq!(cfg.dht.bootstrap.len(), 3);
        assert_eq!(cfg.dht.bootstrap[0], DEFAULT_BOOTSTRAP[0]);
        assert_eq!(cfg.dht.bootstrap[1], DEFAULT_BOOTSTRAP[1]);
        assert_eq!(cfg.dht.bootstrap[2], DEFAULT_BOOTSTRAP[2]);
        assert_eq!(cfg.dht.port, 0);
        assert!(cfg.dht.firewalled);
    }

    #[test]
    fn direct_connect_when_not_relayed() {
        assert!(should_direct_connect(false, FIREWALL_RANDOM, true, false));
    }

    #[test]
    fn direct_connect_when_firewall_open() {
        assert!(should_direct_connect(true, FIREWALL_OPEN, true, false));
    }

    #[test]
    fn direct_connect_when_not_holepunchable() {
        assert!(should_direct_connect(true, FIREWALL_RANDOM, false, false));
    }

    #[test]
    fn direct_connect_when_same_host() {
        assert!(should_direct_connect(true, FIREWALL_RANDOM, true, true));
    }

    #[test]
    fn holepunch_when_relayed_firewalled_holepunchable_different_host() {
        assert!(!should_direct_connect(true, FIREWALL_RANDOM, true, false));
        assert!(!should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            true,
            false
        ));
        assert!(!should_direct_connect(true, FIREWALL_UNKNOWN, true, false));
    }

    #[test]
    fn direct_connect_all_conditions_false_except_one() {
        assert!(should_direct_connect(false, FIREWALL_RANDOM, true, false));
        assert!(should_direct_connect(true, FIREWALL_OPEN, true, false));
        assert!(should_direct_connect(true, FIREWALL_RANDOM, false, false));
        assert!(should_direct_connect(true, FIREWALL_RANDOM, true, true));
    }

    // ── Scenario-matrix topology tests ───────────────────────────────────
    //
    // These map to the user-defined topology matrix:
    //   T1: both open
    //   T2: sender firewalled, receiver open
    //   T3: sender open, receiver firewalled
    //   T4: both firewalled, same network
    //   T5: both firewalled, different networks
    //   T6: one behind CGNAT
    //
    // For each topology we test the connection decision from the
    // *connector's* perspective (the one calling should_direct_connect).

    #[test]
    fn topology_both_open() {
        // T1: Neither side relayed, both FIREWALL_OPEN → direct connect
        assert!(should_direct_connect(false, FIREWALL_OPEN, true, false));
    }

    #[test]
    fn topology_sender_firewalled_receiver_open() {
        // T2: Sender is firewalled, discovered receiver via relay (relayed=true).
        // Receiver is FIREWALL_OPEN → direct connect (firewall==OPEN branch).
        assert!(should_direct_connect(true, FIREWALL_OPEN, true, false));
    }

    #[test]
    fn topology_sender_open_receiver_firewalled() {
        // T3: Sender is open. Found receiver via relay (relayed=true).
        // Receiver is firewalled (CONSISTENT), holepunchable → holepunch.
        assert!(!should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            true,
            false
        ));
        // If receiver is NOT holepunchable → direct connect (fallback).
        assert!(should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            false,
            false
        ));
    }

    #[test]
    fn topology_both_firewalled_same_network() {
        // T4: Both firewalled, same network (same_host=true).
        // same_host → direct connect regardless of firewall state.
        assert!(should_direct_connect(true, FIREWALL_RANDOM, true, true));
        assert!(should_direct_connect(true, FIREWALL_CONSISTENT, true, true));
    }

    #[test]
    fn topology_both_firewalled_different_networks() {
        // T5: Both firewalled, different networks.
        // When holepunchable → holepunch attempt.
        assert!(!should_direct_connect(true, FIREWALL_RANDOM, true, false));
        assert!(!should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            true,
            false
        ));
        // When NOT holepunchable → direct connect fallback (no HP relay).
        assert!(should_direct_connect(true, FIREWALL_RANDOM, false, false));
        assert!(should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            false,
            false
        ));
    }

    #[test]
    fn topology_one_behind_cgnat() {
        // T6: CGNAT peer is FIREWALL_RANDOM and holepunchable.
        // Non-CGNAT peer connects via relay → holepunch.
        assert!(!should_direct_connect(true, FIREWALL_RANDOM, true, false));
        // CGNAT peer with no holepunch support → direct connect fallback.
        assert!(should_direct_connect(true, FIREWALL_RANDOM, false, false));
    }

    #[test]
    fn holepunch_reply_cannot_expand_beyond_locally_selected_relay() {
        let local_relay = test_peer();
        let victim = Ipv4Peer {
            host: "192.0.2.120".to_string(),
            port: 53,
        };

        assert_eq!(
            trusted_holepunch_peer(&local_relay, &local_relay),
            Some(local_relay.clone())
        );
        assert!(
            trusted_holepunch_peer(&local_relay, &victim).is_none(),
            "an authenticated remote payload cannot add arbitrary UDP targets"
        );
    }

    fn test_server_peer_state(byte: u8) -> ServerPeerState {
        ServerPeerState {
            holepunch_secret: [byte; 32],
            remote_public_key: [byte; 32],
            client_address: Ipv4Peer {
                host: format!("198.51.100.{byte}"),
                port: 42_424,
            },
            local_stream_id: u32::from(byte),
            remote_udx: None,
            last_authenticated_at: Instant::now(),
        }
    }

    #[test]
    fn server_holepunch_requires_authenticated_source_and_reported_peer_binding() {
        let mut sessions = ServerSession::with_limits_for_test(1, Duration::from_secs(60));
        let source = test_peer();
        let victim = Ipv4Peer {
            host: "192.0.2.99".to_string(),
            port: 3478,
        };
        let secret = [0x5a; 32];
        assert!(sessions.admit_authenticated(ServerPeerState {
            holepunch_secret: secret,
            remote_public_key: [0x5a; 32],
            client_address: source.clone(),
            local_stream_id: 7,
            remote_udx: None,
            last_authenticated_at: Instant::now(),
        }));

        // This payload has the valid secret derived from the authenticated
        // Noise session, but its relay metadata attempts to nominate a victim.
        // The generic server must reject before it can reply or spawn punch work.
        let encrypted = SecurePayload::with_local_secret(secret, [0x33; 32])
            .encrypt(&HolepunchPayload {
                error: 0,
                firewall: FIREWALL_OPEN,
                round: 1,
                connected: false,
                punching: true,
                addresses: Some(vec![victim.clone()]),
                remote_address: Some(victim.clone()),
                token: None,
                remote_token: None,
            })
            .expect("test holepunch payload encodes");

        assert!(
            sessions
                .authenticated_holepunch_secret(&encrypted, &source, &victim)
                .is_none(),
            "wire peer metadata alone must not authorize a server punch"
        );
        assert!(
            sessions
                .authenticated_holepunch_secret(&encrypted, &victim, &source)
                .is_none(),
            "an authenticated secret cannot be replayed from a different source"
        );

        let (matched_secret, verified_peer) = sessions
            .authenticated_holepunch_secret(&encrypted, &source, &source)
            .expect("the authenticated source/session binding is accepted");
        assert_eq!(matched_secret, secret);
        assert_eq!(verified_peer, source);
    }

    #[test]
    fn server_session_endpoint_index_limits_holepunch_to_one_decrypt_candidate() {
        let mut sessions = ServerSession::with_limits_for_test(64, Duration::from_secs(60));
        let source = test_peer();
        let secret = [0x11; 32];
        assert!(sessions.admit_authenticated(ServerPeerState {
            holepunch_secret: secret,
            remote_public_key: [0x11; 32],
            client_address: source.clone(),
            local_stream_id: 1,
            remote_udx: None,
            last_authenticated_at: Instant::now(),
        }));

        for key_byte in 2..=64 {
            assert!(
                !sessions.admit_authenticated(ServerPeerState {
                    holepunch_secret: [key_byte; 32],
                    remote_public_key: [key_byte; 32],
                    client_address: source.clone(),
                    local_stream_id: u32::from(key_byte),
                    remote_udx: None,
                    last_authenticated_at: Instant::now(),
                }),
                "a second static key at one endpoint must be rejected"
            );
        }
        assert_eq!(sessions.holepunch_secrets.len(), 1);
        assert_eq!(sessions.session_by_endpoint.len(), 1);

        let encrypted = SecurePayload::with_local_secret(secret, [0x22; 32])
            .encrypt(&HolepunchPayload {
                error: 0,
                firewall: FIREWALL_OPEN,
                round: 1,
                connected: false,
                punching: false,
                addresses: None,
                remote_address: None,
                token: None,
                remote_token: None,
            })
            .expect("test holepunch payload encodes");
        assert!(
            sessions
                .authenticated_holepunch_secret(&encrypted, &source, &source)
                .is_some()
        );
        assert_eq!(
            sessions.holepunch_decrypt_attempts(),
            1,
            "endpoint-indexed session lookup must try exactly one secret"
        );
    }

    #[test]
    fn server_sessions_are_bounded_refresh_authenticated_and_reclaim_expired() {
        let initial = std::time::Instant::now();
        let ttl = std::time::Duration::from_secs(10);
        let mut sessions = ServerSession::with_limits_for_test(2, ttl);

        assert!(sessions.admit_authenticated_at(test_server_peer_state(1), initial));
        assert!(sessions.admit_authenticated_at(test_server_peer_state(2), initial));
        assert_eq!(sessions.holepunch_secrets.len(), 2);

        assert!(
            !sessions.admit_authenticated_at(test_server_peer_state(3), initial),
            "a new remote session must not evict an authenticated live session"
        );
        assert_eq!(sessions.holepunch_secrets.len(), 2);

        assert!(
            sessions.admit_authenticated_at(test_server_peer_state(1), initial + ttl / 2),
            "a reauthenticated remote key must refresh in place even at capacity"
        );
        assert_eq!(sessions.holepunch_secrets.len(), 2);

        assert_eq!(
            sessions.gc_expired_at(initial + ttl + std::time::Duration::from_secs(1)),
            1,
            "only the unrefreshed session may expire"
        );
        assert!(sessions.holepunch_secrets.contains_key(&[1; 32]));
        assert!(!sessions.holepunch_secrets.contains_key(&[2; 32]));

        assert!(
            sessions.admit_authenticated_at(
                test_server_peer_state(3),
                initial + ttl + std::time::Duration::from_secs(1),
            ),
            "capacity must recover after TTL garbage collection"
        );
        assert_eq!(sessions.holepunch_secrets.len(), 2);
    }

    #[tokio::test]
    async fn server_punch_work_rejects_at_capacity_and_recovers_after_reap() {
        let mut work = ServerPunchWork::with_limit_for_test(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();

        assert!(work.try_spawn(async move {
            let _ = started_tx.send(());
            let _ = release_rx.await;
        }));
        started_rx.await.expect("first punch work must start");

        assert!(
            !work.try_spawn(async {}),
            "saturated punch admission must reject without creating a detached task"
        );
        assert_eq!(work.tasks.len(), 1);

        release_tx.send(()).expect("first punch work release");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if work.reap_completed() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed punch work must be reaped");

        assert!(
            work.try_spawn(async {}),
            "punch admission must recover once the actor reaps the completed task"
        );
        work.shutdown().await;
    }

    #[tokio::test]
    async fn server_punch_work_shutdown_aborts_and_drains_without_detach() {
        struct DropSignal(Option<oneshot::Sender<()>>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let mut work = ServerPunchWork::with_limit_for_test(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();

        assert!(work.try_spawn(async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        }));
        started_rx.await.expect("punch work must start");

        work.shutdown().await;

        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .expect("shutdown must abort and drop running punch work")
            .expect("drop signal sender must remain connected");
        assert!(
            work.tasks.is_empty(),
            "shutdown must drain every punch task"
        );
        assert!(
            work.admission.is_closed(),
            "shutdown must permanently close punch admission before draining"
        );
    }
}
