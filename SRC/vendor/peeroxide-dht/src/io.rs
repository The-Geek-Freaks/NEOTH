//! IO layer for the DHT-RPC protocol.
//!
//! Faithful Rust port of the Node.js dht-rpc IO layer.
//! The [`Io`] struct is driven by the caller from a `tokio::select!` loop.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::Blake2bMac;
use tokio::time::Instant;

use libudx::{
    Datagram, RawDatagramCompletion, RawFallbackObserver, RawFallbackOutcome, UdxRuntime,
    UdxSocket,
};

use crate::hyperdht_messages::PEER_HANDSHAKE;
use crate::messages::{self, Ipv4Peer, Response};
use crate::peer::{self, NodeId};
use crate::routing_table::{RoutingTable, K};

type Blake2bMac256 = Blake2bMac<U32>;

const ERROR_INVALID_TOKEN: u64 = 2;
const DEFAULT_TIMEOUT_MS: u64 = 1000;
const DEFAULT_RETRIES: u32 = 3;
/// Number of request TIDs retained in the actor-owned egress retry FIFO.
///
/// Requests beyond this scheduling window remain marked on their inflight entry
/// and are rediscovered by [`Io::drain`]. That keeps retry memory bounded without
/// dropping a request when libudx applies raw-egress backpressure.
const PENDING_SEND_CAPACITY: usize = 1024;
/// Number of encoded replies retained after a raw-egress `WouldBlock`.
///
/// This is deliberately a distinct bound from [`PENDING_SEND_CAPACITY`]: an
/// incoming reply owns bytes rather than an inflight request TID, so it cannot
/// be rediscovered from the request table. The two bounded queues may each
/// reach their own capacity under pressure.
const PENDING_REPLY_CAPACITY: usize = 1024;
/// Aggregate bytes retained by [`PENDING_REPLY_CAPACITY`].
///
/// Match libudx's socket-wide raw-egress byte reservation. A reply that would
/// exceed this bound keeps the former terminal-drop behavior.
const PENDING_REPLY_BYTE_CAPACITY: usize = 1_048_576;

/// libudx deliberately reports finite raw egress saturation as WouldBlock.
/// DHT UDP traffic is retryable; suppressing only this expected condition keeps
/// an attacker or busy peer from converting bounded backpressure into a log
/// amplification path.
fn is_egress_backpressure(error: &libudx::UdxError) -> bool {
    matches!(error, libudx::UdxError::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock)
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IoError {
    #[error("UDP error: {0}")]
    Udx(#[from] libudx::UdxError),
    #[error("address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("encoding error: {0}")]
    Encoding(#[from] crate::compact_encoding::EncodingError),
    #[error("routing table lock poisoned")]
    LockPoisoned,
}

pub type IoResult<T> = Result<T, IoError>;

// ── Public config / stats / types ─────────────────────────────────────────────

/// IO layer configuration.
#[derive(Debug, Clone)]
pub struct IoConfig {
    pub max_window: usize,
    pub port: u16,
    pub host: String,
    pub firewalled: bool,
    pub ephemeral: bool,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            max_window: 80,
            port: 0,
            host: "0.0.0.0".to_string(),
            firewalled: true,
            ephemeral: true,
        }
    }
}

/// Receipt-safe owner scope for optional socket-route diagnostics.
///
/// Ordinary callers remain unscoped. The RPC bootstrap path maps the existing
/// listener-owned companion scope into this value before binding its `Io`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum IoDiagnosticScope {
    #[default]
    Unscoped,
    Pair,
    Active,
}

/// IO layer statistics.
#[derive(Debug, Clone, Default)]
pub struct IoStats {
    pub active: u64,
    pub total: u64,
    pub responses: u64,
    pub timeouts: u64,
    pub retries: u64,
}

/// Fixed, secret-free client response-dispatch evidence owned by one `Io`.
///
/// Disabled unless the existing companion diagnostics opt-in is present. It
/// intentionally records neither TIDs nor remote endpoints.
struct ClientResponseDiagnostics {
    enabled: bool,
    emitted: u8,
}

impl ClientResponseDiagnostics {
    fn from_environment() -> Self {
        Self {
            enabled: std::env::var("NEOTH_COMPANION_DIAGNOSTICS").as_deref() == Ok("1"),
            emitted: 0,
        }
    }

    fn phase(&mut self, phase: &'static str) {
        let bit = match phase {
            "client_socket_datagram_observed" => 1 << 0,
            "server_socket_datagram_observed" => 1 << 1,
            "datagram_decode_rejected" => 1 << 2,
            "response_tid_unmatched" => 1 << 3,
            "handshake_response_tid_known_wrong_source" => 1 << 4,
            "handshake_response_exact_matched" => 1 << 5,
            _ => return,
        };
        if self.enabled && self.emitted & bit == 0 {
            self.emitted |= bit;
            eprintln!("NEOTH_COMPANION_CLIENT_RESPONSE_PHASE={phase}");
        }
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self { enabled: true, emitted: 0 }
    }

    #[cfg(test)]
    fn emitted(&self) -> u8 {
        self.emitted
    }
}

/// Fixed, secret-free socket receive evidence for one `Io` socket role.
///
/// This callback reports raw queue lifecycle and valid UDX route classification
/// before DHT decoding. It never reports packet identity, endpoint, payload, or
/// response/request correlation.
#[derive(Clone)]
struct RawFallbackDiagnostics {
    enabled: bool,
    socket_kind: SocketKind,
    scope: IoDiagnosticScope,
    emitted: Arc<AtomicU8>,
}

impl RawFallbackDiagnostics {
    fn from_environment(socket_kind: SocketKind, scope: IoDiagnosticScope) -> Self {
        Self {
            enabled: std::env::var("NEOTH_COMPANION_DIAGNOSTICS").as_deref() == Ok("1"),
            socket_kind,
            scope,
            emitted: Arc::new(AtomicU8::new(0)),
        }
    }

    fn observer(&self) -> Option<RawFallbackObserver> {
        if !self.enabled {
            return None;
        }
        let diagnostics = self.clone();
        Some(Arc::new(move |outcome| diagnostics.phase(outcome)))
    }

    fn phase(&self, outcome: RawFallbackOutcome) {
        let (bit, phase) = match outcome {
            RawFallbackOutcome::Observed => (1, "raw_fallback_observed"),
            RawFallbackOutcome::Enqueued => (1 << 1, "raw_fallback_enqueued"),
            RawFallbackOutcome::QueueFull => (1 << 2, "raw_fallback_queue_full"),
            RawFallbackOutcome::ReceiverClosed => (1 << 3, "raw_fallback_receiver_closed"),
            RawFallbackOutcome::UdxMappedSourceAdmitted => (1 << 4, "udx_route_admitted"),
            RawFallbackOutcome::UdxMappedSourceRejected => (1 << 5, "udx_route_rejected"),
            RawFallbackOutcome::UdxUnknownRouteFallback => (1 << 6, "udx_route_unknown_fallback"),
        };
        if self.emitted.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
            return;
        }
        let role = match self.socket_kind {
            SocketKind::Client => "client",
            SocketKind::Server => "server",
        };
        let is_udx_route = matches!(
            outcome,
            RawFallbackOutcome::UdxMappedSourceAdmitted
                | RawFallbackOutcome::UdxMappedSourceRejected
                | RawFallbackOutcome::UdxUnknownRouteFallback
        );
        if !is_udx_route || self.scope == IoDiagnosticScope::Unscoped {
            eprintln!("NEOTH_COMPANION_CLIENT_RESPONSE_PHASE={role}_{phase}");
        } else {
            match self.scope {
                IoDiagnosticScope::Pair => {
                    eprintln!("NEOTH_COMPANION_CONNECT_PHASE=pair_{role}_{phase}");
                }
                IoDiagnosticScope::Active => {
                    eprintln!("NEOTH_COMPANION_CONNECT_PHASE=active_{role}_{phase}");
                }
                IoDiagnosticScope::Unscoped => unreachable!("unscoped route is handled above"),
            }
        }
    }

    #[cfg(test)]
    fn for_test(socket_kind: SocketKind) -> Self {
        Self {
            enabled: true,
            socket_kind,
            scope: IoDiagnosticScope::Unscoped,
            emitted: Arc::new(AtomicU8::new(0)),
        }
    }

    #[cfg(test)]
    fn emitted(&self) -> u8 {
        self.emitted.load(Ordering::Relaxed)
    }
}
/// Wire-byte counters shared between the IO layer and consumers (e.g. progress
/// reporters in `peeroxide-cli`). Increments are `Relaxed` — these are
/// observability metrics, not synchronization primitives.
///
/// The counters track every UDP datagram the IO layer hands to or receives
/// from the OS sockets, regardless of which protocol layer originated it
/// (queries, requests, replies, relays, retries — all counted).
#[derive(Debug, Clone, Default)]
pub struct WireCounters {
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
}

impl WireCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
        )
    }
}

/// Which socket was used for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Client,
    Server,
}

/// Info about an inflight request that was resolved by a response.
#[derive(Debug, Clone)]
pub struct ResolvedRequest {
    pub tid: u16,
    pub to: Ipv4Peer,
    pub command: u64,
    pub internal: bool,
    pub target: Option<NodeId>,
}

/// Events emitted by the IO layer.
pub enum IoEvent {
    IncomingRequest(IncomingRequest),
    Response {
        tid: u16,
        from: Ipv4Peer,
        to: Ipv4Peer,
        id: Option<NodeId>,
        token: Option<[u8; 32]>,
        closer_nodes: Vec<Ipv4Peer>,
        error: u64,
        value: Option<Vec<u8>>,
        rtt: Duration,
        request: ResolvedRequest,
    },
}

/// An incoming request (server-side).
pub struct IncomingRequest {
    pub tid: u16,
    pub from: Ipv4Peer,
    pub to: Ipv4Peer,
    pub id: Option<NodeId>,
    pub token: Option<[u8; 32]>,
    pub internal: bool,
    pub command: u64,
    pub target: Option<NodeId>,
    pub value: Option<Vec<u8>>,
    pub(crate) reply_ctx: ReplyContext,
}

/// Parameters for creating an outgoing request.
#[derive(Debug, Clone)]
pub struct RequestParams {
    pub to: Ipv4Peer,
    pub token: Option<[u8; 32]>,
    pub internal: bool,
    pub command: u64,
    pub target: Option<NodeId>,
    pub value: Option<Vec<u8>>,
}

/// A timeout event — emitted when a request exceeds all retries.
#[derive(Debug, Clone)]
pub struct TimeoutEvent {
    pub tid: u16,
    pub to: Ipv4Peer,
    pub command: u64,
    pub internal: bool,
    pub target: Option<NodeId>,
}

// ── Private types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReplyContext {
    pub(crate) socket_kind: SocketKind,
}

/// Bundled parameters for `send_reply_internal` to stay under clippy's argument limit.
struct ReplyInternalParams {
    socket_kind: SocketKind,
    tid: u16,
    target: Option<NodeId>,
    error: u64,
    include_token: bool,
    value: Option<Vec<u8>>,
}

struct InflightEntry {
    tid: u16,
    to: Ipv4Peer,
    addr: SocketAddr,
    internal: bool,
    command: u64,
    target: Option<NodeId>,
    buffer: Vec<u8>,
    socket_kind: SocketKind,
    sent: u32,
    retries: u32,
    deadline: Instant,
    timestamp: Instant,
    /// The request awaits actor-owned send admission, because congestion
    /// deferred it or libudx returned `WouldBlock`. It must not consume a DHT
    /// retry, deadline, or congestion-window slot before it is accepted.
    egress_pending: bool,
}

struct PendingSend {
    tid: u16,
}

/// An encoded server reply retained until raw UDP egress accepts it or the
/// existing DHT request/retry horizon expires.
struct PendingReply {
    buffer: Vec<u8>,
    addr: SocketAddr,
    socket_kind: SocketKind,
    expires_at: Instant,
    diagnostics: Option<Arc<crate::hyperdht::IncomingConnectDiagnostics>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InflightSendOutcome {
    Sent,
    Backpressured,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplySendOutcome {
    Sent,
    Backpressured,
    Failed,
}

// ── CongestionWindow ──────────────────────────────────────────────────────────

/// Congestion window — direct port of JS CongestionWindow class.
pub struct CongestionWindow {
    i: usize,
    total: i32,
    window: [i32; 4],
    max_window: i32,
}

impl CongestionWindow {
    pub fn new(max_window: usize) -> Self {
        Self {
            i: 0,
            total: 0,
            window: [0; 4],
            max_window: max_window as i32,
        }
    }

    /// Returns true if the window is full and no more sends should be attempted.
    pub fn is_full(&self) -> bool {
        self.total >= 2 * self.max_window || self.window[self.i] >= self.max_window
    }

    /// Decrement the current quarter (called on response received).
    pub fn recv(&mut self) {
        if self.window[self.i] > 0 {
            self.window[self.i] -= 1;
            self.total -= 1;
        }
    }

    /// Increment the current quarter (called on send).
    pub fn send(&mut self) {
        self.total += 1;
        self.window[self.i] += 1;
    }

    /// Advance to the next quarter, clearing the oldest.
    pub fn drain(&mut self) {
        self.i = (self.i + 1) & 3;
        self.total -= self.window[self.i];
        self.window[self.i] = 0;
    }

    /// Reset all counters.
    pub fn clear(&mut self) {
        self.i = 0;
        self.total = 0;
        self.window = [0; 4];
    }
}

// ── Io ────────────────────────────────────────────────────────────────────────

pub struct Io {
    client_socket: UdxSocket,
    server_socket: UdxSocket,
    client_rx: tokio::sync::mpsc::Receiver<Datagram>,
    server_rx: tokio::sync::mpsc::Receiver<Datagram>,
    inflight: Vec<InflightEntry>,
    congestion: CongestionWindow,
    pending: VecDeque<PendingSend>,
    pending_replies: VecDeque<PendingReply>,
    pending_reply_bytes: usize,
    tid: u16,
    secrets: Option<[[u8; 32]; 2]>,
    rotate_countdown: u32,
    firewalled: bool,
    pub ephemeral: bool,
    pub stats: IoStats,
    pub wire: WireCounters,
    client_response_diagnostics: ClientResponseDiagnostics,
    table: Arc<Mutex<RoutingTable>>,
    destroying: bool,
}

impl Io {
    /// Create and bind the IO layer (two sockets).
    pub async fn bind(
        runtime: &UdxRuntime,
        table: Arc<Mutex<RoutingTable>>,
        config: IoConfig,
    ) -> IoResult<Self> {
        Self::bind_with_diagnostic_scope(runtime, table, config, IoDiagnosticScope::Unscoped).await
    }

    /// Bind an Io with the already-owned listener scope used by companion
    /// diagnostics. This changes only optional marker attribution.
    pub(crate) async fn bind_with_diagnostic_scope(
        runtime: &UdxRuntime,
        table: Arc<Mutex<RoutingTable>>,
        config: IoConfig,
        diagnostic_scope: IoDiagnosticScope,
    ) -> IoResult<Self> {
        let server_addr: SocketAddr = format!("{}:{}", config.host, config.port)
            .parse()
            .map_err(IoError::AddrParse)?;
        let client_addr: SocketAddr = format!("{}:0", config.host)
            .parse()
            .map_err(IoError::AddrParse)?;

        let server_raw_fallback_diagnostics =
            RawFallbackDiagnostics::from_environment(SocketKind::Server, diagnostic_scope);
        let client_raw_fallback_diagnostics =
            RawFallbackDiagnostics::from_environment(SocketKind::Client, diagnostic_scope);

        let server_socket = runtime.create_socket().await?;
        server_socket.bind(server_addr).await?;
        let server_rx = server_socket
            .recv_start_with_observer(server_raw_fallback_diagnostics.observer())?;

        let client_socket = runtime.create_socket().await?;
        client_socket.bind(client_addr).await?;
        let client_rx = client_socket
            .recv_start_with_observer(client_raw_fallback_diagnostics.observer())?;

        let tid: u16 = rand::random();

        Ok(Io {
            client_socket,
            server_socket,
            client_rx,
            server_rx,
            inflight: Vec::new(),
            congestion: CongestionWindow::new(config.max_window),
            pending: VecDeque::new(),
            pending_replies: VecDeque::new(),
            pending_reply_bytes: 0,
            tid,
            secrets: None,
            rotate_countdown: 10,
            firewalled: config.firewalled,
            ephemeral: config.ephemeral,
            stats: IoStats::default(),
            wire: WireCounters::default(),
            client_response_diagnostics: ClientResponseDiagnostics::from_environment(),
            table,
            destroying: false,
        })
    }

    /// Get a clone of the wire-byte counters. Cheap (Arc clone).
    pub fn wire_counters(&self) -> WireCounters {
        self.wire.clone()
    }

    pub async fn server_local_addr(&self) -> IoResult<std::net::SocketAddr> {
        self.server_socket.local_addr().await.map_err(IoError::from)
    }

    pub fn server_socket(&self) -> UdxSocket {
        self.server_socket.clone()
    }

    pub fn primary_socket(&self) -> UdxSocket {
        if self.firewalled {
            self.client_socket.clone()
        } else {
            self.server_socket.clone()
        }
    }

    /// Receive and decode the next message from either socket.
    /// Returns None only if both channels are closed.
    pub async fn recv(&mut self) -> Option<IoEvent> {
        loop {
            let (datagram, socket_kind) = tokio::select! {
                biased;
                msg = self.client_rx.recv() => (msg?, SocketKind::Client),
                msg = self.server_rx.recv() => (msg?, SocketKind::Server),
            };
            self.wire
                .bytes_received
                .fetch_add(datagram.data.len() as u64, Ordering::Relaxed);
            tracing::debug!(
                from = %datagram.addr,
                len = datagram.data.len(),
                first_byte = datagram.data.first().copied().unwrap_or(0),
                ?socket_kind,
                "IO::recv raw datagram"
            );
            if let Some(event) = self.process_datagram(datagram, socket_kind) {
                return Some(event);
            }
        }
    }

    /// Drain congestion window and rotate secrets. Call every ~750 ms.
    pub fn drain(&mut self) {
        if let Some(secrets) = &mut self.secrets {
            self.rotate_countdown -= 1;
            if self.rotate_countdown == 0 {
                self.rotate_countdown = 10;
                // Rotate: swap[0] and [1], then re-hash old [0] (now at [1]).
                secrets.swap(0, 1);
                // Hash secrets[1] (the old secrets[0]) with itself.
                if let Ok(mut mac) = Blake2bMac256::new_from_slice(&secrets[1]) {
                    mac.update(&secrets[1]);
                    let hash = mac.finalize().into_bytes();
                    secrets[1].copy_from_slice(&hash);
                }
            }
        }

        self.congestion.drain();

        // A backpressured reply is retried at most once per actor drain. Keep
        // the request FIFO reachable even when this socket remains saturated.
        let client_socket = self.client_socket.clone();
        let server_socket = self.server_socket.clone();
        self.drain_one_pending_reply(move |reply| {
            let socket = match reply.socket_kind {
                SocketKind::Client => &client_socket,
                SocketKind::Server => &server_socket,
            };
            Self::send_pending_reply(socket, reply)
        });

        self.drain_pending_requests();
    }

    fn drain_pending_requests(&mut self) {
        while !self.congestion.is_full() {
            // The FIFO is intentionally bounded. If it was full when another
            // socket rejection happened, that entry remains marked in
            // `inflight` and is rediscovered here once there is scheduling
            // capacity. The actor is the sole owner of both structures.
            let pending = self.pending.pop_front().or_else(|| {
                self.inflight
                    .iter()
                    .find(|entry| entry.egress_pending)
                    .map(|entry| PendingSend { tid: entry.tid })
            });

            let Some(pending) = pending else {
                break;
            };
            let Some(idx) = self.inflight.iter().position(|e| e.tid == pending.tid) else {
                continue;
            };

            if self.send_inflight_at(idx) == InflightSendOutcome::Backpressured {
                // Preserve FIFO ordering and wait for the next actor drain.
                // Retrying synchronously here would spin while the bounded
                // libudx writer remains full.
                self.requeue_pending_front(pending);
                break;
            }
        }
    }

    fn drain_one_pending_reply<F>(&mut self, send: F)
    where
        F: FnOnce(&PendingReply) -> Result<(), libudx::UdxError>,
    {
        self.prune_expired_pending_reply_prefix(Instant::now());
        let Some(reply) = self.take_pending_reply() else {
            return;
        };
        let result = send(&reply);
        if self.finish_pending_reply(reply, result) == ReplySendOutcome::Backpressured {
            // A front requeue preserves FIFO ordering and avoids spinning while
            // the bounded libudx writer remains full.
            self.pending_replies.rotate_right(1);
        }
    }

    fn prune_expired_pending_reply_prefix(&mut self, now: Instant) {
        let initial_len = self.pending_replies.len();
        for _ in 0..initial_len {
            let Some(reply) = self.pending_replies.front() else {
                return;
            };
            if reply.expires_at > now {
                return;
            }
            if let Some(reply) = self.take_pending_reply() {
                Self::phase_pending_reply(&reply, "handshake_reply_expired");
            }
        }
    }

    fn take_pending_reply(&mut self) -> Option<PendingReply> {
        let reply = self.pending_replies.pop_front()?;
        self.pending_reply_bytes = self
            .pending_reply_bytes
            .saturating_sub(reply.buffer.len());
        Some(reply)
    }

    /// Return the earliest deadline across all inflight requests.
    /// Returns a far-future instant if there are no inflight requests.
    pub fn next_timeout_deadline(&self) -> Instant {
        self.inflight
            .iter()
            .map(|e| e.deadline)
            .min()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600))
    }

    /// Check for expired timeouts. Returns events for timed-out requests.
    /// Retries are handled internally.
    pub fn check_timeouts(&mut self) -> Vec<TimeoutEvent> {
        let now = Instant::now();
        let mut timeout_indices: Vec<usize> = Vec::new();
        let mut retry_indices: Vec<usize> = Vec::new();

        for (i, entry) in self.inflight.iter().enumerate() {
            if !entry.egress_pending && entry.deadline <= now {
                if entry.sent > entry.retries {
                    timeout_indices.push(i);
                } else {
                    retry_indices.push(i);
                }
            }
        }

        // Process retries first (in-place, no index shifts).
        for &i in &retry_indices {
            // A raw egress rejection must not consume a DHT retry. Count it
            // only when the attempt leaves the actor (or fails for another
            // transport reason, preserving the legacy failure semantics).
            if self.send_inflight_at(i) != InflightSendOutcome::Backpressured {
                self.stats.retries += 1;
            }
        }

        // Remove timed-out entries from highest to lowest index.
        timeout_indices.sort_unstable_by(|a, b| b.cmp(a));
        let mut events = Vec::with_capacity(timeout_indices.len());
        for i in timeout_indices {
            let entry = self.inflight.swap_remove(i);
            self.congestion.recv();
            self.stats.active = self.stats.active.saturating_sub(1);
            self.stats.timeouts += 1;
            events.push(TimeoutEvent {
                tid: entry.tid,
                to: entry.to,
                command: entry.command,
                internal: entry.internal,
                target: entry.target,
            });
        }
        events
    }

    /// Create an outgoing request.
    /// Returns the assigned TID, or `None` if the IO is destroying or the
    /// destination address is invalid.
    pub fn create_request(&mut self, params: RequestParams) -> Option<u16> {
        if self.destroying {
            return None;
        }

        let addr_str = format!("{}:{}", params.to.host, params.to.port);
        let addr: SocketAddr = addr_str.parse().ok()?;

        let tid = self.tid;
        self.tid = self.tid.wrapping_add(1);

        let socket_kind = if self.firewalled {
            SocketKind::Client
        } else {
            SocketKind::Server
        };

        let include_id = !self.ephemeral && socket_kind == SocketKind::Server;
        let id = if include_id {
            self.table.lock().ok().map(|t| *t.id())
        } else {
            None
        };

        let request = messages::Request {
            tid,
            to: params.to.clone(),
            id,
            token: params.token,
            internal: params.internal,
            command: params.command,
            target: params.target,
            value: params.value,
        };

        let buffer = match messages::encode_request_to_bytes(&request) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(err = %e, "create_request: encode failed");
                return None;
            }
        };

        self.stats.active += 1;
        self.stats.total += 1;

        let now = Instant::now();
        let to_str = format!("{}:{}", params.to.host, params.to.port);

        let entry = InflightEntry {
            tid,
            to: params.to,
            addr,
            internal: params.internal,
            command: params.command,
            target: params.target,
            buffer,
            socket_kind,
            sent: 0,
            retries: DEFAULT_RETRIES,
            deadline: now + Duration::from_millis(DEFAULT_TIMEOUT_MS),
            timestamp: now,
            egress_pending: false,
        };

        self.inflight.push(entry);

        let cong_full = self.congestion.is_full();
        tracing::debug!(
            tid,
            command = params.command,
            to = %to_str,
            ?socket_kind,
            cong_full,
            inflight_count = self.inflight.len(),
            "create_request: new inflight"
        );

        if cong_full {
            // The scheduling FIFO is bounded. `mark_egress_pending` retains
            // the request on its inflight entry even when the FIFO is full, so
            // the next actor drain can recover it without a packet drop.
            self.mark_egress_pending(self.inflight.len() - 1);
        } else {
            let idx = self.inflight.len() - 1;
            self.send_inflight_at(idx);
        }

        Some(tid)
    }

    /// Send a reply to an incoming request.
    pub fn send_reply(&mut self, req: &IncomingRequest, error: u64, value: Option<&[u8]>) {
        let socket_kind = req.reply_ctx.socket_kind;
        let include_token = error == 0;
        self.send_reply_internal(
            &req.from,
            ReplyInternalParams {
                socket_kind,
                tid: req.tid,
                target: req.target,
                error,
                include_token,
                value: value.map(|v| v.to_vec()),
            },
            None,
        );
    }

    /// Send a reply using explicit parameters (for deferred/delayed replies).
    /// Unlike `send_reply`, this does not require an `IncomingRequest` reference.
    pub(crate) fn send_reply_deferred(
        &mut self,
        to: &Ipv4Peer,
        ctx: ReplyContext,
        tid: u16,
        target: Option<NodeId>,
        error: u64,
        value: Option<&[u8]>,
        diagnostics: Option<Arc<crate::hyperdht::IncomingConnectDiagnostics>>,
    ) {
        let include_token = error == 0;
        self.send_reply_internal(
            to,
            ReplyInternalParams {
                socket_kind: ctx.socket_kind,
                tid,
                target,
                error,
                include_token,
                value: value.map(|v| v.to_vec()),
            },
            diagnostics,
        );
    }

    /// Generate a token for the given host using `secret[secret_index]`.
    pub fn token(&mut self, host: &str, secret_index: usize) -> [u8; 32] {
        self.init_secrets_if_needed();
        let secrets = match self.secrets.as_ref() {
            Some(s) => *s,
            None => return [0u8; 32],
        };
        let key = &secrets[secret_index % 2];
        match Blake2bMac256::new_from_slice(key) {
            Ok(mut mac) => {
                mac.update(host.as_bytes());
                let hash = mac.finalize().into_bytes();
                let mut token = [0u8; 32];
                token.copy_from_slice(&hash);
                token
            }
            Err(_) => [0u8; 32],
        }
    }

    /// Validate an incoming token against both secrets.
    pub fn validate_token(&mut self, host: &str, token: &[u8; 32]) -> bool {
        let t0 = self.token(host, 0);
        let t1 = self.token(host, 1);
        &t0 == token || &t1 == token
    }

    /// Send a fire-and-forget relay request (no inflight tracking, no response).
    /// Used by the Router to forward PEER_HANDSHAKE/PEER_HOLEPUNCH messages
    /// to relay targets.
    pub fn relay(
        &mut self,
        command: u64,
        target: Option<NodeId>,
        value: Option<Vec<u8>>,
        to: &Ipv4Peer,
    ) -> bool {
        if self.destroying {
            return false;
        }

        let addr: SocketAddr = match format!("{}:{}", to.host, to.port).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };

        let tid = self.tid;
        self.tid = self.tid.wrapping_add(1);

        let socket_kind = if self.firewalled {
            SocketKind::Client
        } else {
            SocketKind::Server
        };

        let include_id = !self.ephemeral && socket_kind == SocketKind::Server;
        let id = if include_id {
            self.table.lock().ok().map(|t| *t.id())
        } else {
            None
        };

        let request = messages::Request {
            tid,
            to: to.clone(),
            id,
            token: None,
            internal: false,
            command,
            target,
            value,
        };

        let buffer = match messages::encode_request_to_bytes(&request) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(err = %e, "relay: encode failed");
                return false;
            }
        };

        let socket = match socket_kind {
            SocketKind::Client => &self.client_socket,
            SocketKind::Server => &self.server_socket,
        };

        let buffer_len = buffer.len() as u64;
        if let Err(e) = socket.send_to(&buffer, addr) {
            if !is_egress_backpressure(&e) {
                tracing::warn!(err = %e, "relay: send_to failed");
            }
            return false;
        }
        self.wire
            .bytes_sent
            .fetch_add(buffer_len, Ordering::Relaxed);

        true
    }

    /// Destroy the IO layer, closing both sockets.
    pub async fn destroy(mut self) -> IoResult<()> {
        self.destroying = true;
        for entry in self.inflight.drain(..) {
            self.congestion.recv();
            self.stats.active = self.stats.active.saturating_sub(1);
            tracing::debug!(tid = entry.tid, "destroy: dropping inflight request");
        }
        self.client_socket.close().await?;
        self.server_socket.close().await?;
        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn init_secrets_if_needed(&mut self) {
        if self.secrets.is_none() {
            let s0: [u8; 32] = rand::random();
            let s1: [u8; 32] = rand::random();
            self.secrets = Some([s0, s1]);
        }
    }

    /// Encode and send a response message.
    fn send_reply_internal(
        &mut self,
        to: &Ipv4Peer,
        params: ReplyInternalParams,
        diagnostics: Option<Arc<crate::hyperdht::IncomingConnectDiagnostics>>,
    ) {
        let include_id = !self.ephemeral && params.socket_kind == SocketKind::Server;

        let (id, closer_nodes) = match self.table.lock() {
            Ok(table) => {
                let id = if include_id { Some(*table.id()) } else { None };
                let closer_nodes: Vec<Ipv4Peer> = if let Some(t) = &params.target {
                    table
                        .closest(t, K)
                        .into_iter()
                        .map(|n| Ipv4Peer {
                            host: n.host.clone(),
                            port: n.port,
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                (id, closer_nodes)
            }
            Err(_) => (None, Vec::new()),
        };

        let token = if params.include_token {
            Some(self.token(&to.host, 1))
        } else {
            None
        };

        let response = Response {
            tid: params.tid,
            to: to.clone(),
            id,
            token,
            closer_nodes,
            error: params.error,
            value: params.value,
        };

        let bytes = match messages::encode_response_to_bytes(&response) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(err = %e, "send_reply_internal: encode failed");
                Self::phase_diagnostics(&diagnostics, "handshake_reply_prepare_failed");
                return;
            }
        };

        let addr_str = format!("{}:{}", to.host, to.port);
        let addr: SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(err = %e, "send_reply_internal: invalid address");
                Self::phase_diagnostics(&diagnostics, "handshake_reply_prepare_failed");
                return;
            }
        };

        let reply_horizon = DEFAULT_TIMEOUT_MS * u64::from(DEFAULT_RETRIES + 1);
        let reply = PendingReply {
            buffer: bytes,
            addr,
            socket_kind: params.socket_kind,
            // Match the existing initial send plus retry horizon: a reply may
            // wait for raw-egress admission, but it cannot live indefinitely.
            expires_at: Instant::now() + Duration::from_millis(reply_horizon),
            diagnostics,
        };
        let result = {
            let socket = match reply.socket_kind {
                SocketKind::Client => &self.client_socket,
                SocketKind::Server => &self.server_socket,
            };
            Self::send_pending_reply(socket, &reply)
        };
        self.finish_pending_reply(reply, result);
    }

    fn phase_diagnostics(
        diagnostics: &Option<Arc<crate::hyperdht::IncomingConnectDiagnostics>>,
        phase: &'static str,
    ) {
        if let Some(diagnostics) = diagnostics {
            diagnostics.phase(phase);
        }
    }

    fn phase_pending_reply(reply: &PendingReply, phase: &'static str) {
        Self::phase_diagnostics(&reply.diagnostics, phase);
    }

    fn phase_reply_os_completion(
        diagnostics: Arc<crate::hyperdht::IncomingConnectDiagnostics>,
        completion: RawDatagramCompletion,
    ) {
        diagnostics.phase(match completion {
            RawDatagramCompletion::Sent => "handshake_reply_udp_os_send_succeeded",
            RawDatagramCompletion::SendFailed => "handshake_reply_udp_os_send_failed",
            RawDatagramCompletion::DroppedBeforeSend => "handshake_reply_udp_os_send_dropped",
        });
    }

    fn send_pending_reply(
        socket: &UdxSocket,
        reply: &PendingReply,
    ) -> Result<(), libudx::UdxError> {
        if let Some(diagnostics) = &reply.diagnostics {
            let diagnostics = Arc::clone(diagnostics);
            socket.send_to_observed(
                &reply.buffer,
                reply.addr,
                Box::new(move |completion| {
                    Self::phase_reply_os_completion(diagnostics, completion);
                }),
            )
        } else {
            socket.send_to(&reply.buffer, reply.addr)
        }
    }

    /// Account for one reply egress attempt. A raw queue rejection retains the
    /// exact encoded reply; all other outcomes preserve the old terminal
    /// behavior.
    fn finish_pending_reply(
        &mut self,
        reply: PendingReply,
        result: Result<(), libudx::UdxError>,
    ) -> ReplySendOutcome {
        match result {
            Ok(()) => {
                self.wire
                    .bytes_sent
                    .fetch_add(reply.buffer.len() as u64, Ordering::Relaxed);
                Self::phase_pending_reply(&reply, "handshake_reply_udp_accepted");
                ReplySendOutcome::Sent
            }
            Err(error) if is_egress_backpressure(&error) => {
                let reply_len = reply.buffer.len();
                if self.pending_replies.len() < PENDING_REPLY_CAPACITY
                    && self.pending_reply_bytes.saturating_add(reply_len)
                        <= PENDING_REPLY_BYTE_CAPACITY
                {
                    Self::phase_pending_reply(&reply, "handshake_reply_udp_queued");
                    self.pending_reply_bytes += reply_len;
                    self.pending_replies.push_back(reply);
                } else {
                    Self::phase_pending_reply(&reply, "handshake_reply_udp_queue_dropped");
                }
                ReplySendOutcome::Backpressured
            }
            Err(error) => {
                tracing::warn!(err = %error, "send_reply_internal: send_to failed");
                Self::phase_pending_reply(&reply, "handshake_reply_udp_terminal_error");
                ReplySendOutcome::Failed
            }
        }
    }

    /// Actually send the inflight entry at index `idx`.
    ///
    /// `libudx::UdxSocket::send_to` uses a finite `try_send` queue. On its
    /// expected `WouldBlock` result this method leaves the entry's DHT send
    /// state untouched and lets `drain` retry it through the actor-owned FIFO.
    fn send_inflight_at(&mut self, idx: usize) -> InflightSendOutcome {
        let (buffer, addr, socket_kind) = {
            let entry = &self.inflight[idx];
            (entry.buffer.clone(), entry.addr, entry.socket_kind)
        };

        let socket = match socket_kind {
            SocketKind::Client => &self.client_socket,
            SocketKind::Server => &self.server_socket,
        };

        let result = socket.send_to(&buffer, addr);
        self.finish_inflight_send(idx, buffer.len() as u64, result)
    }

    /// Commit an attempted inflight send after libudx has accepted or rejected
    /// it. Kept separate from socket selection so the `WouldBlock` state
    /// transition is deterministic and independently testable.
    fn finish_inflight_send(
        &mut self,
        idx: usize,
        buffer_len: u64,
        result: Result<(), libudx::UdxError>,
    ) -> InflightSendOutcome {
        match result {
            Ok(()) => {
                let entry = &mut self.inflight[idx];
                entry.sent += 1;
                entry.deadline = Instant::now() + Duration::from_millis(DEFAULT_TIMEOUT_MS);
                entry.egress_pending = false;
                self.congestion.send();
                self.wire
                    .bytes_sent
                    .fetch_add(buffer_len, Ordering::Relaxed);
                InflightSendOutcome::Sent
            }
            Err(error) if is_egress_backpressure(&error) => {
                self.mark_egress_pending(idx);
                InflightSendOutcome::Backpressured
            }
            Err(error) => {
                // Preserve the former DHT transport-failure behavior for
                // non-backpressure errors: it consumed an attempted send and
                // later participates in the normal timeout/retry policy.
                tracing::warn!(err = %error, "send_inflight_at: send_to failed");
                let entry = &mut self.inflight[idx];
                entry.sent += 1;
                entry.deadline = Instant::now() + Duration::from_millis(DEFAULT_TIMEOUT_MS);
                entry.egress_pending = false;
                self.congestion.send();
                InflightSendOutcome::Failed
            }
        }
    }

    /// Mark an inflight request for actor-owned send admission. The FIFO is
    /// capped; a marked entry omitted because the FIFO is full is recovered by
    /// the bounded scheduling pass in [`Self::drain`].
    fn mark_egress_pending(&mut self, idx: usize) {
        let tid = {
            let entry = &mut self.inflight[idx];
            if entry.egress_pending {
                return;
            }
            entry.egress_pending = true;
            entry.tid
        };
        if self.pending.len() < PENDING_SEND_CAPACITY {
            self.pending.push_back(PendingSend { tid });
        }
    }

    fn requeue_pending_front(&mut self, pending: PendingSend) {
        if self.pending.len() < PENDING_SEND_CAPACITY {
            self.pending.push_front(pending);
        }
    }

    /// Decode and dispatch a datagram from either socket.
    fn process_datagram(&mut self, datagram: Datagram, socket_kind: SocketKind) -> Option<IoEvent> {
        self.client_response_diagnostics.phase(match socket_kind {
            SocketKind::Client => "client_socket_datagram_observed",
            SocketKind::Server => "server_socket_datagram_observed",
        });
        if datagram.data.len() < 2 {
            return None;
        }

        let (host, port) = match datagram.addr {
            SocketAddr::V4(v4) => (v4.ip().to_string(), v4.port()),
            SocketAddr::V6(_) => return None,
        };

        if port == 0 {
            return None;
        }

        let from = Ipv4Peer { host, port };

        match messages::decode_message(&datagram.data) {
            Err(ref e) => {
                tracing::debug!(
                    from = %format!("{}:{}", from.host, from.port),
                    len = datagram.data.len(),
                    first_byte = datagram.data.first().copied().unwrap_or(0),
                    err = %e,
                    "process_datagram: decode failed"
                );
                self.client_response_diagnostics
                    .phase("datagram_decode_rejected");
                None
            }
            Ok(messages::Message::Request(req)) => {
                // Validate token if present.
                if req.token.is_some() {
                    let token_val = req
                        .token
                        .as_ref()
                        .map(|t| self.validate_token(&from.host, t));
                    if token_val == Some(false) {
                        let tid = req.tid;
                        let target = req.target;
                        let from_clone = from.clone();
                        self.send_reply_internal(
                            &from_clone,
                            ReplyInternalParams {
                                socket_kind,
                                tid,
                                target,
                                error: ERROR_INVALID_TOKEN,
                                include_token: true,
                                value: None,
                            },
                            None,
                        );
                        return None;
                    }
                }

                // Validate incoming ID.
                let validated_id = req.id.and_then(|id| {
                    let expected = peer::peer_id(&from.host, from.port);
                    if expected == id {
                        Some(expected)
                    } else {
                        None
                    }
                });

                Some(IoEvent::IncomingRequest(IncomingRequest {
                    tid: req.tid,
                    from: from.clone(),
                    to: req.to,
                    id: validated_id,
                    token: req.token,
                    internal: req.internal,
                    command: req.command,
                    target: req.target,
                    value: req.value,
                    reply_ctx: ReplyContext { socket_kind },
                }))
            }

            Ok(messages::Message::Response(res)) => {
                // A TID alone is not an authentication boundary: it is a u16
                // value and can be guessed. Bind the response to the exact
                // UDP endpoint recorded when this request was created before
                // removing or accounting for the inflight entry. This is
                // deliberately per-entry so relay and multi-target requests
                // use their actual expected response source.
                let pos = match self
                    .inflight
                    .iter()
                    .position(|entry| entry.tid == res.tid && entry.to == from)
                {
                    Some(p) => p,
                    None => {
                        match self.inflight.iter().find(|entry| {
                            entry.tid == res.tid
                                && !entry.internal
                                && entry.command == PEER_HANDSHAKE
                        }) {
                            Some(_) => {
                                self.client_response_diagnostics
                                    .phase("handshake_response_tid_known_wrong_source");
                            }
                            None if !self.inflight.iter().any(|entry| entry.tid == res.tid) => {
                                self.client_response_diagnostics.phase("response_tid_unmatched");
                            }
                            None => {}
                        }
                        tracing::debug!(
                            tid = res.tid,
                            from = %format!("{}:{}", from.host, from.port),
                            "response TID/source did not match an inflight request"
                        );
                        return None;
                    }
                };
                let entry = self.inflight.swap_remove(pos);
                if !entry.internal && entry.command == PEER_HANDSHAKE {
                    self.client_response_diagnostics
                        .phase("handshake_response_exact_matched");
                }

                let rtt = entry.timestamp.elapsed();

                self.congestion.recv();
                self.stats.active = self.stats.active.saturating_sub(1);
                self.stats.responses += 1;

                // Validate incoming ID.
                let validated_id = res.id.and_then(|id| {
                    let expected = peer::peer_id(&from.host, from.port);
                    if expected == id {
                        Some(expected)
                    } else {
                        None
                    }
                });

                let request = ResolvedRequest {
                    tid: entry.tid,
                    to: entry.to,
                    command: entry.command,
                    internal: entry.internal,
                    target: entry.target,
                };

                Some(IoEvent::Response {
                    tid: res.tid,
                    from,
                    to: res.to,
                    id: validated_id,
                    token: res.token,
                    closer_nodes: res.closer_nodes,
                    error: res.error,
                    value: res.value,
                    rtt,
                    request,
                })
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CongestionWindow tests ────────────────────────────────────────────────

    #[test]
    fn congestion_window_basic() {
        let mut cw = CongestionWindow::new(10);
        assert!(!cw.is_full());

        for _ in 0..10 {
            cw.send();
        }
        // window[0] == 10 == max_window → full
        assert!(cw.is_full());

        cw.recv();
        assert!(!cw.is_full());
    }

    #[test]
    fn congestion_window_drain_clears_oldest() {
        let mut cw = CongestionWindow::new(80);
        // Send 5 in quarter 0.
        for _ in 0..5 {
            cw.send();
        }
        assert_eq!(cw.total, 5);

        // Drain advances to quarter 1, clears quarter 1 (which is 0).
        cw.drain();
        assert_eq!(cw.total, 5); // nothing cleared yet (quarter 1 was 0)

        // Advance through all 4 quarters; original quarter 0 becomes the "oldest".
        cw.drain(); // → quarter 2
        cw.drain(); // → quarter 3
        cw.drain(); // → quarter 0 again; clears window[0] = 5
        assert_eq!(cw.total, 0);
        assert_eq!(cw.window[0], 0);
    }

    #[test]
    fn congestion_window_full_condition_total() {
        // total >= 2 * max_window triggers full
        let mut cw = CongestionWindow::new(5);
        // Send across two quarters so no single quarter hits max.
        for _ in 0..5 {
            cw.send();
        }
        cw.drain(); // advance to quarter 1
        for _ in 0..5 {
            cw.send();
        }
        // total = 10 = 2 * 5 → full
        assert!(cw.is_full());
    }

    #[test]
    fn congestion_window_full_condition_single_quarter() {
        let mut cw = CongestionWindow::new(3);
        cw.send();
        cw.send();
        cw.send();
        // window[0] == 3 == max_window → full
        assert!(cw.is_full());
    }

    #[test]
    fn congestion_window_clear() {
        let mut cw = CongestionWindow::new(10);
        for _ in 0..5 {
            cw.send();
        }
        cw.clear();
        assert_eq!(cw.total, 0);
        assert!(!cw.is_full());
    }

    #[tokio::test]
    async fn would_block_egress_preserves_request_until_actor_retry_succeeds() {
        let runtime = UdxRuntime::new().expect("runtime");
        let table = Arc::new(Mutex::new(RoutingTable::new([0u8; 32])));
        let mut io = Io::bind(&runtime, table, IoConfig::default())
            .await
            .expect("io bind");

        let original_deadline = Instant::now() - Duration::from_secs(1);
        io.inflight.push(InflightEntry {
            tid: 7,
            to: Ipv4Peer {
                host: "127.0.0.1".to_string(),
                port: 4242,
            },
            addr: "127.0.0.1:4242".parse().expect("loopback address"),
            internal: false,
            command: 1,
            target: None,
            buffer: vec![1, 2, 3],
            socket_kind: SocketKind::Client,
            sent: 0,
            retries: DEFAULT_RETRIES,
            deadline: original_deadline,
            timestamp: Instant::now(),
            egress_pending: false,
        });

        // This is the exact error UdxSocket::send_to returns when its bounded
        // raw-egress queue is saturated. Injecting the result makes the test
        // deterministic without relying on scheduler timing to fill a queue.
        let saturated = Err(libudx::UdxError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "UDX raw egress queue is full",
        )));
        assert_eq!(
            io.finish_inflight_send(0, 3, saturated),
            InflightSendOutcome::Backpressured
        );
        assert_eq!(io.inflight[0].sent, 0);
        assert_eq!(io.inflight[0].deadline, original_deadline);
        assert!(io.inflight[0].egress_pending);
        assert_eq!(io.congestion.total, 0);
        assert_eq!(io.pending.len(), 1);
        assert_eq!(io.wire.snapshot().0, 0);
        assert!(io.check_timeouts().is_empty());
        assert_eq!(io.stats.retries, 0);

        // The next actor-owned scheduling pass takes the retained TID and
        // commits state only after libudx accepts the datagram.
        let pending = io.pending.pop_front().expect("retained pending send");
        assert_eq!(pending.tid, 7);
        assert_eq!(
            io.finish_inflight_send(0, 3, Ok(())),
            InflightSendOutcome::Sent
        );
        assert_eq!(io.inflight[0].sent, 1);
        assert!(io.inflight[0].deadline > original_deadline);
        assert!(!io.inflight[0].egress_pending);
        assert_eq!(io.congestion.total, 1);
        assert_eq!(io.wire.snapshot().0, 3);

        io.destroy().await.expect("io destroy");
    }

    fn test_pending_reply_with_buffer(buffer: Vec<u8>, expires_at: Instant) -> PendingReply {
        PendingReply {
            buffer,
            addr: "127.0.0.1:4243".parse().expect("loopback address"),
            socket_kind: SocketKind::Server,
            expires_at,
            diagnostics: None,
        }
    }

    fn test_pending_reply(expires_at: Instant) -> PendingReply {
        test_pending_reply_with_buffer(vec![4, 5, 6], expires_at)
    }

    fn raw_egress_would_block() -> Result<(), libudx::UdxError> {
        Err(libudx::UdxError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "UDX raw egress queue is full",
        )))
    }

    #[tokio::test]
    async fn deferred_handshake_reply_diagnostics_cover_queue_retry_and_expiry() {
        let runtime = UdxRuntime::new().expect("runtime");
        let table = Arc::new(Mutex::new(RoutingTable::new([0u8; 32])));
        let mut io = Io::bind(&runtime, table, IoConfig::default())
            .await
            .expect("io bind");
        let diagnostics = Arc::new(
            crate::hyperdht::IncomingConnectDiagnostics::for_test(
                crate::hyperdht::CompanionDiagnosticScope::Active,
            ),
        );
        let mut queued = test_pending_reply(Instant::now() + Duration::from_secs(4));
        queued.diagnostics = Some(Arc::clone(&diagnostics));
        assert_eq!(
            io.finish_pending_reply(queued, raw_egress_would_block()),
            ReplySendOutcome::Backpressured
        );
        io.drain_one_pending_reply(|_| Ok(()));
        let mut expired = test_pending_reply(Instant::now() - Duration::from_millis(1));
        expired.diagnostics = Some(Arc::clone(&diagnostics));
        io.pending_reply_bytes = expired.buffer.len();
        io.pending_replies.push_back(expired);
        io.drain_one_pending_reply(|_| Ok(()));
        assert_eq!(
            diagnostics.emitted(),
            (1 << 10) | (1 << 11) | (1 << 15),
            "a queued handshake reply must record retention, accepted retry, and expiry"
        );
        io.destroy().await.expect("io destroy");
    }

    #[test]
    fn deferred_handshake_reply_os_completion_preserves_the_listener_tag() {
        let diagnostics = Arc::new(
            crate::hyperdht::IncomingConnectDiagnostics::for_test(
                crate::hyperdht::CompanionDiagnosticScope::Active,
            ),
        );
        for completion in [
            RawDatagramCompletion::Sent,
            RawDatagramCompletion::SendFailed,
            RawDatagramCompletion::DroppedBeforeSend,
        ] {
            Io::phase_reply_os_completion(Arc::clone(&diagnostics), completion);
        }
        assert_eq!(
            diagnostics.emitted(),
            (1 << 16) | (1 << 17) | (1 << 18),
            "only the tagged deferred reply maps writer completion into active-listener phases"
        );
    }

    #[tokio::test]
    async fn would_block_reply_egress_retains_owned_bytes_until_retry_succeeds() {
        let runtime = UdxRuntime::new().expect("runtime");
        let table = Arc::new(Mutex::new(RoutingTable::new([0u8; 32])));
        let mut io = Io::bind(&runtime, table, IoConfig::default())
            .await
            .expect("io bind");

        for buffer in [vec![4, 5, 6], vec![7, 8]] {
            assert_eq!(
                io.finish_pending_reply(
                    test_pending_reply_with_buffer(
                        buffer,
                        Instant::now() + Duration::from_secs(4),
                    ),
                    raw_egress_would_block(),
                ),
                ReplySendOutcome::Backpressured
            );
        }
        assert_eq!(io.pending_replies.len(), 2);
        assert_eq!(
            io.pending_replies.front().expect("queued reply").buffer,
            vec![4, 5, 6]
        );
        assert_eq!(io.pending_reply_bytes, 5);
        assert_eq!(io.wire.snapshot().0, 0);

        let mut observed = Vec::new();
        io.drain_one_pending_reply(|reply| {
            observed.push(reply.buffer.clone());
            raw_egress_would_block()
        });
        assert_eq!(observed, vec![vec![4, 5, 6]]);
        assert_eq!(io.pending_replies.len(), 2);
        assert_eq!(io.pending_reply_bytes, 5);
        assert_eq!(
            io.pending_replies.front().expect("front reply preserved").buffer,
            vec![4, 5, 6]
        );

        io.drain_one_pending_reply(|reply| {
            assert_eq!(reply.buffer, vec![4, 5, 6]);
            Ok(())
        });
        assert_eq!(io.pending_replies.len(), 1);
        assert_eq!(io.pending_reply_bytes, 2);
        io.drain_one_pending_reply(|reply| {
            assert_eq!(reply.buffer, vec![7, 8]);
            Ok(())
        });
        assert!(io.pending_replies.is_empty());
        assert_eq!(io.pending_reply_bytes, 0);
        assert_eq!(io.wire.snapshot().0, 5);

        assert_eq!(
            io.finish_pending_reply(
                test_pending_reply(Instant::now() + Duration::from_secs(4)),
                raw_egress_would_block(),
            ),
            ReplySendOutcome::Backpressured
        );
        io.drain_one_pending_reply(|_| raw_egress_would_block());
        let request_to = Ipv4Peer {
            host: "127.0.0.1".to_string(),
            port: 4244,
        };
        let mut request = test_inflight_entry(92, request_to);
        request.sent = 0;
        io.inflight.push(request);
        io.congestion.send();
        io.stats.active = 1;
        io.pending.push_back(PendingSend { tid: 92 });
        io.drain_pending_requests();
        assert!(io.inflight[0].sent > 0 || io.inflight[0].egress_pending);
        assert!(io.pending.is_empty(), "request FIFO must make progress");

        io.destroy().await.expect("io destroy");
    }

    #[tokio::test]
    async fn reply_egress_queue_is_bounded_and_expired_reply_is_terminal() {
        let runtime = UdxRuntime::new().expect("runtime");
        let table = Arc::new(Mutex::new(RoutingTable::new([0u8; 32])));
        let mut io = Io::bind(&runtime, table, IoConfig::default())
            .await
            .expect("io bind");

        for _ in 0..PENDING_REPLY_CAPACITY {
            io.pending_replies
                .push_back(test_pending_reply(Instant::now() + Duration::from_secs(4)));
        }
        io.pending_reply_bytes = PENDING_REPLY_CAPACITY * 3;
        assert_eq!(
            io.finish_pending_reply(
                test_pending_reply(Instant::now() + Duration::from_secs(4)),
                raw_egress_would_block(),
            ),
            ReplySendOutcome::Backpressured
        );
        assert_eq!(io.pending_replies.len(), PENDING_REPLY_CAPACITY);

        io.pending_replies.clear();
        let retained = test_pending_reply_with_buffer(
            vec![0; PENDING_REPLY_BYTE_CAPACITY - 2],
            Instant::now() + Duration::from_secs(4),
        );
        io.pending_reply_bytes = retained.buffer.len();
        io.pending_replies.push_back(retained);
        assert_eq!(
            io.finish_pending_reply(
                test_pending_reply(Instant::now() + Duration::from_secs(4)),
                raw_egress_would_block(),
            ),
            ReplySendOutcome::Backpressured
        );
        assert_eq!(io.pending_replies.len(), 1);
        assert_eq!(io.pending_reply_bytes, PENDING_REPLY_BYTE_CAPACITY - 2);

        io.pending_replies.clear();
        io.pending_reply_bytes = 0;
        assert_eq!(
            io.finish_pending_reply(
                test_pending_reply(Instant::now() + Duration::from_secs(4)),
                Err(libudx::UdxError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "terminal raw egress error",
                ))),
            ),
            ReplySendOutcome::Failed
        );
        assert!(io.pending_replies.is_empty());

        io.pending_reply_bytes = 9;
        io.pending_replies
            .push_back(test_pending_reply(Instant::now() - Duration::from_millis(1)));
        io.pending_replies
            .push_back(test_pending_reply(Instant::now() - Duration::from_millis(1)));
        io.pending_replies
            .push_back(test_pending_reply(Instant::now() + Duration::from_secs(4)));
        io.drain_one_pending_reply(|_| Ok(()));
        assert!(io.pending_replies.is_empty());
        assert_eq!(io.pending_reply_bytes, 0);
        assert_eq!(io.wire.snapshot().0, 3);

        io.destroy().await.expect("io destroy");
    }

    fn test_inflight_entry(tid: u16, to: Ipv4Peer) -> InflightEntry {
        test_inflight_entry_with_command(tid, to, 1)
    }

    fn test_inflight_entry_with_command(tid: u16, to: Ipv4Peer, command: u64) -> InflightEntry {
        test_inflight_entry_with_command_and_internal(tid, to, command, false)
    }

    fn test_inflight_entry_with_command_and_internal(
        tid: u16,
        to: Ipv4Peer,
        command: u64,
        internal: bool,
    ) -> InflightEntry {
        let addr = format!("{}:{}", to.host, to.port)
            .parse()
            .expect("loopback address");
        InflightEntry {
            tid,
            to,
            addr,
            internal,
            command,
            target: None,
            buffer: vec![1, 2, 3],
            socket_kind: SocketKind::Client,
            sent: 1,
            retries: DEFAULT_RETRIES,
            deadline: Instant::now() + Duration::from_secs(1),
            timestamp: Instant::now(),
            egress_pending: false,
        }
    }

    fn response_datagram(tid: u16, from: Ipv4Peer) -> Datagram {
        let data = messages::encode_response_to_bytes(&Response {
            tid,
            to: from.clone(),
            id: None,
            token: None,
            closer_nodes: Vec::new(),
            error: 0,
            value: None,
        })
        .expect("response encoding");
        let addr = format!("{}:{}", from.host, from.port)
            .parse()
            .expect("loopback address");
        Datagram { data, addr }
    }

    #[tokio::test]
    async fn guessed_tid_from_wrong_source_does_not_consume_inflight_request() {
        let runtime = UdxRuntime::new().expect("runtime");
        let table = Arc::new(Mutex::new(RoutingTable::new([0u8; 32])));
        let mut io = Io::bind(&runtime, table, IoConfig::default())
            .await
            .expect("io bind");
        let expected = Ipv4Peer {
            host: "127.0.0.1".to_string(),
            port: 4242,
        };
        let forged = Ipv4Peer {
            host: "127.0.0.2".to_string(),
            port: 4242,
        };
        io.inflight.push(test_inflight_entry(73, expected));
        io.congestion.send();
        io.stats.active = 1;

        assert!(io
            .process_datagram(response_datagram(73, forged), SocketKind::Client)
            .is_none());
        assert_eq!(io.inflight.len(), 1, "wrong source must retain the request");
        assert_eq!(io.inflight[0].tid, 73);
        assert_eq!(io.congestion.total, 1, "wrong source must not free a slot");
        assert_eq!(io.stats.active, 1);
        assert_eq!(io.stats.responses, 0);

        io.destroy().await.expect("io destroy");
    }

    #[tokio::test]
    async fn response_from_expected_source_resolves_matching_inflight_request() {
        let runtime = UdxRuntime::new().expect("runtime");
        let table = Arc::new(Mutex::new(RoutingTable::new([0u8; 32])));
        let mut io = Io::bind(&runtime, table, IoConfig::default())
            .await
            .expect("io bind");
        let expected = Ipv4Peer {
            host: "127.0.0.1".to_string(),
            port: 4242,
        };
        io.inflight.push(test_inflight_entry(74, expected.clone()));
        io.congestion.send();
        io.stats.active = 1;

        let event = io
            .process_datagram(response_datagram(74, expected), SocketKind::Client)
            .expect("expected source resolves request");
        let IoEvent::Response { request, .. } = event else {
            panic!("expected response event");
        };
        assert_eq!(request.tid, 74);
        assert_eq!(io.inflight.len(), 0);
        assert_eq!(io.congestion.total, 0);
        assert_eq!(io.stats.active, 0);
        assert_eq!(io.stats.responses, 1);

        io.destroy().await.expect("io destroy");
    }

    async fn expect_raw_fallback_pair(
        events: &mut tokio::sync::mpsc::UnboundedReceiver<RawFallbackOutcome>,
        terminal: RawFallbackOutcome,
        context: &str,
    ) {
        let observed = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap_or_else(|_| panic!("{context}: observed outcome timed out"))
            .unwrap_or_else(|| panic!("{context}: observer channel closed"));
        assert_eq!(
            observed,
            RawFallbackOutcome::Observed,
            "{context}: each raw packet begins with observed"
        );
        let terminal_observation = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap_or_else(|_| panic!("{context}: terminal outcome timed out"))
            .unwrap_or_else(|| panic!("{context}: observer channel closed"));
        assert_eq!(
            terminal_observation, terminal,
            "{context}: observed packet receives its exact queue lifecycle outcome"
        );
    }

    #[tokio::test]
    async fn raw_fallback_diagnostics_cover_client_and_server_queue_lifecycle() {
        let runtime = UdxRuntime::new().expect("runtime");
        let table = Arc::new(Mutex::new(RoutingTable::new([0u8; 32])));
        let mut io = Io::bind(&runtime, table, IoConfig::default())
            .await
            .expect("io bind");
        io.client_response_diagnostics = ClientResponseDiagnostics::for_test();

        let sender = runtime.create_socket().await.expect("sender socket");
        sender
            .bind("127.0.0.1:0".parse().expect("sender bind address"))
            .await
            .expect("sender bind");

        let client_diagnostics = RawFallbackDiagnostics::for_test(SocketKind::Client);
        let client_diagnostic_observer = client_diagnostics
            .observer()
            .expect("test diagnostics observer is enabled");
        let (client_events_tx, mut client_events) = tokio::sync::mpsc::unbounded_channel();
        let client_observer: RawFallbackObserver = Arc::new(move |outcome| {
            client_diagnostic_observer(outcome);
            let _ = client_events_tx.send(outcome);
        });
        let mut client_rx = io
            .client_socket
            .recv_start_with_observer(Some(client_observer))
            .expect("replace client raw receiver with observer");
        let client_addr = io.client_socket.local_addr().await.expect("client address");
        sender
            .send_to(&[0xa5], client_addr)
            .expect("send client passthrough datagram");
        let received = tokio::time::timeout(Duration::from_secs(1), client_rx.recv())
            .await
            .expect("client raw passthrough is bounded")
            .expect("client receiver stays open");
        assert_eq!(received.data, vec![0xa5]);
        expect_raw_fallback_pair(
            &mut client_events,
            RawFallbackOutcome::Enqueued,
            "first client raw packet",
        )
        .await;
        assert_eq!(
            client_diagnostics.emitted(),
            (1 << 0) | (1 << 1),
            "the actual client diagnostics observer retains observed and enqueued bits"
        );
        assert_eq!(
            io.client_response_diagnostics.emitted(),
            0,
            "pre-Io raw lifecycle must not claim a DHT response classification"
        );

        // Fill the existing raw receiver one observed packet at a time. Waiting
        // for every terminal callback avoids relying on sender writer-queue
        // admission or executor timing while leaving the bounded raw queue full.
        for byte in 0..128u16 {
            sender
                .send_to(&[(byte & 0xff) as u8], client_addr)
                .expect("send client raw queue fill packet");
            expect_raw_fallback_pair(
                &mut client_events,
                RawFallbackOutcome::Enqueued,
                "client raw queue fill packet",
            )
            .await;
        }

        sender
            .send_to(&[0xb2], client_addr)
            .expect("send client raw queue full packet");
        expect_raw_fallback_pair(
            &mut client_events,
            RawFallbackOutcome::QueueFull,
            "client raw queue full packet",
        )
        .await;
        assert_ne!(
            client_diagnostics.emitted() & (1 << 2),
            0,
            "the actual client diagnostics observer records queue-full"
        );

        drop(client_rx);
        sender
            .send_to(&[0xc3], client_addr)
            .expect("send after client receiver close");
        expect_raw_fallback_pair(
            &mut client_events,
            RawFallbackOutcome::ReceiverClosed,
            "client raw receiver close packet",
        )
        .await;
        assert_ne!(
            client_diagnostics.emitted() & (1 << 3),
            0,
            "the actual client diagnostics observer records receiver-closed"
        );

        let server_diagnostics = RawFallbackDiagnostics::for_test(SocketKind::Server);
        let server_diagnostic_observer = server_diagnostics
            .observer()
            .expect("test diagnostics observer is enabled");
        let (server_events_tx, mut server_events) = tokio::sync::mpsc::unbounded_channel();
        let server_observer: RawFallbackObserver = Arc::new(move |outcome| {
            server_diagnostic_observer(outcome);
            let _ = server_events_tx.send(outcome);
        });
        let mut server_rx = io
            .server_socket
            .recv_start_with_observer(Some(server_observer))
            .expect("replace server raw receiver with observer");
        let server_addr = io.server_socket.local_addr().await.expect("server address");
        sender
            .send_to(&[0x5a], server_addr)
            .expect("send server passthrough datagram");
        let received = tokio::time::timeout(Duration::from_secs(1), server_rx.recv())
            .await
            .expect("server raw passthrough is bounded")
            .expect("server receiver stays open");
        assert_eq!(received.data, vec![0x5a]);
        expect_raw_fallback_pair(
            &mut server_events,
            RawFallbackOutcome::Enqueued,
            "first server raw packet",
        )
        .await;
        assert_eq!(
            server_diagnostics.emitted(),
            (1 << 0) | (1 << 1),
            "the actual server diagnostics observer remains role-local"
        );
        assert!(
            client_events.try_recv().is_err(),
            "server raw packet has no client observer outcome"
        );
        assert_eq!(
            io.client_response_diagnostics.emitted(),
            0,
            "server raw lifecycle cannot consume client handshake diagnostics"
        );

        sender.close().await.expect("sender close");
        io.destroy().await.expect("io destroy");
    }

    #[test]
    fn raw_fallback_diagnostics_record_route_outcomes_per_socket_role() {
        let client = RawFallbackDiagnostics::for_test(SocketKind::Client);
        let client_observer = client.observer().expect("client observer");
        client_observer(RawFallbackOutcome::UdxMappedSourceAdmitted);
        client_observer(RawFallbackOutcome::UdxMappedSourceRejected);
        assert_eq!(
            client.emitted(),
            (1 << 4) | (1 << 5),
            "client route observations use fixed, local one-shot bits"
        );

        let server = RawFallbackDiagnostics::for_test(SocketKind::Server);
        let server_observer = server.observer().expect("server observer");
        server_observer(RawFallbackOutcome::UdxUnknownRouteFallback);
        assert_eq!(
            server.emitted(),
            1 << 6,
            "server unknown-route fallback stays role-local"
        );
        assert_eq!(
            client.emitted(),
            (1 << 4) | (1 << 5),
            "server route observations cannot mutate client diagnostics"
        );
    }
    #[tokio::test]
    async fn client_handshake_response_diagnostics_distinguish_handshake_from_other_responses() {
        let runtime = UdxRuntime::new().expect("runtime");
        let table = Arc::new(Mutex::new(RoutingTable::new([0u8; 32])));
        let mut io = Io::bind(&runtime, table, IoConfig::default())
            .await
            .expect("io bind");
        io.client_response_diagnostics = ClientResponseDiagnostics::for_test();
        let expected = Ipv4Peer {
            host: "127.0.0.1".to_string(),
            port: 4242,
        };
        let wrong_source = Ipv4Peer {
            host: "127.0.0.2".to_string(),
            port: 4242,
        };

        // An internal Ping shares command zero with PEER_HANDSHAKE. Its exact
        // response resolves normally, but must not claim a handshake phase.
        io.inflight.push(test_inflight_entry_with_command_and_internal(
            70,
            expected.clone(),
            PEER_HANDSHAKE,
            true,
        ));
        io.congestion.send();
        io.stats.active = 1;
        assert!(io
            .process_datagram(response_datagram(70, expected.clone()), SocketKind::Client)
            .is_some());
        assert_eq!(io.client_response_diagnostics.emitted(), 1 << 0);

        // The same internal Ping must not consume the strict-source handshake
        // evidence either.
        io.inflight.push(test_inflight_entry_with_command_and_internal(
            71,
            expected.clone(),
            PEER_HANDSHAKE,
            true,
        ));
        io.congestion.send();
        io.stats.active = 1;
        assert!(io
            .process_datagram(response_datagram(71, wrong_source.clone()), SocketKind::Client)
            .is_none());
        assert_eq!(io.inflight.len(), 1, "wrong source retains internal Ping");
        assert_eq!(io.client_response_diagnostics.emitted(), 1 << 0);

        // Preserve strict source matching for a real external handshake.
        io.inflight.push(test_inflight_entry_with_command(
            72,
            expected.clone(),
            PEER_HANDSHAKE,
        ));
        io.congestion.send();
        io.stats.active = 2;
        assert!(io
            .process_datagram(response_datagram(72, wrong_source), SocketKind::Client)
            .is_none());
        assert_eq!(io.inflight.len(), 2, "wrong source retains handshake request");
        assert_eq!(
            io.client_response_diagnostics.emitted(),
            (1 << 0) | (1 << 4),
            "only an actual handshake request records the strict-source mismatch"
        );

        assert!(io
            .process_datagram(response_datagram(72, expected.clone()), SocketKind::Client)
            .is_some());
        assert_eq!(
            io.client_response_diagnostics.emitted(),
            (1 << 0) | (1 << 4) | (1 << 5),
            "matching handshake source is classified before normal resolution"
        );

        assert!(io
            .process_datagram(response_datagram(73, expected), SocketKind::Client)
            .is_none());
        assert_eq!(
            io.client_response_diagnostics.emitted(),
            (1 << 0) | (1 << 3) | (1 << 4) | (1 << 5),
            "unknown TIDs are actor-wide and do not consume an inflight request"
        );

        io.destroy().await.expect("io destroy");
    }

    // ── TID wrap test ─────────────────────────────────────────────────────────

    #[test]
    fn tid_wraps() {
        // u16 wrapping: 65535 + 1 = 0
        let tid: u16 = 65535;
        let next = tid.wrapping_add(1);
        assert_eq!(next, 0);
    }

    // ── Token tests ───────────────────────────────────────────────────────────

    fn compute_token(host: &str, secret: &[u8; 32]) -> [u8; 32] {
        let mut mac = Blake2bMac256::new_from_slice(secret).unwrap();
        mac.update(host.as_bytes());
        let hash = mac.finalize().into_bytes();
        let mut token = [0u8; 32];
        token.copy_from_slice(&hash);
        token
    }

    #[test]
    fn token_generation_deterministic() {
        let secret = [0xABu8; 32];
        let host = "192.168.1.1";
        let t1 = compute_token(host, &secret);
        let t2 = compute_token(host, &secret);
        assert_eq!(t1, t2);
    }

    #[test]
    fn token_generation_different_host() {
        let secret = [0xABu8; 32];
        let t1 = compute_token("192.168.1.1", &secret);
        let t2 = compute_token("192.168.1.2", &secret);
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_generation_different_secret() {
        let s1 = [0xABu8; 32];
        let s2 = [0xCDu8; 32];
        let host = "10.0.0.1";
        let t1 = compute_token(host, &s1);
        let t2 = compute_token(host, &s2);
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_validation_both_secrets() {
        let secrets = [[0x11u8; 32], [0x22u8; 32]];
        let host = "10.0.0.1";

        let t0 = compute_token(host, &secrets[0]);
        let t1 = compute_token(host, &secrets[1]);

        // Simulate validate_token logic: token matches either secret[0] or secret[1].
        let validate = |token: &[u8; 32]| -> bool {
            let v0 = compute_token(host, &secrets[0]);
            let v1 = compute_token(host, &secrets[1]);
            &v0 == token || &v1 == token
        };

        assert!(validate(&t0));
        assert!(validate(&t1));
    }

    #[test]
    fn token_validation_wrong_host_fails() {
        let secrets = [[0x11u8; 32], [0x22u8; 32]];
        let host = "10.0.0.1";
        let wrong_host = "10.0.0.2";

        let token = compute_token(host, &secrets[0]);

        let validate_wrong = |token: &[u8; 32]| -> bool {
            let v0 = compute_token(wrong_host, &secrets[0]);
            let v1 = compute_token(wrong_host, &secrets[1]);
            &v0 == token || &v1 == token
        };

        assert!(!validate_wrong(&token));
    }
}
