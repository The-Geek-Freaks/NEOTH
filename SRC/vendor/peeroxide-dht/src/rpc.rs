#![deny(clippy::all)]

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::{Instant, interval, sleep_until};

use libudx::{UdxRuntime, UdxSocket};

use crate::io::{Io, IoConfig, IoEvent, ReplyContext, RequestParams, TimeoutEvent};
use crate::messages::{Command, Ipv4Peer};
use crate::peer::{NodeId, peer_id};
use crate::query::{
    IoResponseData, Query, QueryReply, QueryRequest, QueryResult, parse_bootstrap_str,
    resolve_bootstrap_nodes,
};
use crate::routing_table::{Node, RoutingTable, TableEvent};

const TICK_INTERVAL_MS: u64 = 5_000;
const DRAIN_INTERVAL_MS: u64 = 750;
const SLEEPING_INTERVAL_MS: u64 = 3 * TICK_INTERVAL_MS;
const REFRESH_TICKS: u64 = 60;
const RECENT_NODE: u64 = 12;
const OLD_NODE: u64 = 360;
const MAX_REPINGING: u32 = 3;
const DOWN_HINTS_RATE_LIMIT: u32 = 50;

/// Maximum number of network-originated requests waiting for one subscriber.
///
/// A slow consumer must not let an unauthenticated remote peer grow memory
/// without bound.  This deliberately modest capacity still permits a normal
/// burst while making overload fail closed at the DHT boundary.
const EXTERNAL_REQUEST_QUEUE_CAPACITY: usize = 64;
/// How frequently the single DHT actor checks its bounded external-reply
/// ledger.  This keeps replies prompt without creating one detached task per
/// remote request.
const EXTERNAL_REPLY_POLL_INTERVAL_MS: u64 = 10;

/// Maximum number of wire-originated delayed-ping replies the DHT actor will
/// retain at once. `internal` is an untrusted on-wire bit, so it cannot grant
/// a remote peer unbounded timers or deferred replies.
const DELAYED_PING_QUEUE_CAPACITY: usize = 64;
const MAX_DELAYED_PING_DELAY_MS: u32 = 10_000;

const CMD_PING: u64 = Command::Ping as u64;
const CMD_PING_NAT: u64 = Command::PingNat as u64;
const CMD_FIND_NODE: u64 = Command::FindNode as u64;
const CMD_DOWN_HINT: u64 = Command::DownHint as u64;
const CMD_DELAYED_PING: u64 = Command::DelayedPing as u64;

const ERR_UNKNOWN_COMMAND: u64 = 1;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
/// Errors returned by [`DhtHandle`] and [`spawn`].
#[non_exhaustive]
pub enum DhtError {
    /// Underlying I/O failed.
    #[error("IO error: {0}")]
    Io(#[from] crate::io::IoError),
    /// The DHT node has been destroyed.
    #[error("node destroyed")]
    Destroyed,
    /// The internal command channel is closed.
    #[error("command channel closed")]
    ChannelClosed,
    /// Bootstrapping did not complete successfully.
    #[error("bootstrap failed")]
    BootstrapFailed,
    /// A request failed with the given message.
    #[error("request failed: {0}")]
    RequestFailed(String),
}

// ── Public config / request / response types ──────────────────────────────────

/// Configuration for creating a DHT node.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DhtConfig {
    /// Bootstrap node addresses.
    pub bootstrap: Vec<String>,
    /// Local port to bind.
    pub port: u16,
    /// Local host to bind.
    pub host: String,
    /// Whether to force ephemeral mode.
    pub ephemeral: Option<bool>,
    /// Whether to advertise as firewalled.
    pub firewalled: bool,
    /// Query concurrency limit.
    pub concurrency: usize,
    /// Maximum query window size.
    pub max_window: usize,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            bootstrap: vec![],
            port: 0,
            host: "0.0.0.0".to_string(),
            ephemeral: None,
            firewalled: true,
            concurrency: 10,
            max_window: 80,
        }
    }
}

#[derive(Debug, Clone)]
/// Response to a ping request.
#[non_exhaustive]
pub struct PingResponse {
    /// Remote peer that replied.
    pub from: Ipv4Peer,
    /// Optional peer id reported by the remote node.
    pub id: Option<NodeId>,
    /// Round-trip time for the ping.
    pub rtt: Duration,
    /// Reflexive address: our address as seen by the remote node.
    pub to: Option<Ipv4Peer>,
    /// Nodes returned by the remote peer (closer nodes from its routing table).
    pub closer_nodes: Vec<Ipv4Peer>,
}

#[derive(Debug, Clone)]
/// Data returned from a DHT request.
#[non_exhaustive]
pub struct ResponseData {
    /// Remote peer that replied.
    pub from: Ipv4Peer,
    /// Optional peer id reported by the remote node.
    pub id: Option<NodeId>,
    /// Optional response token.
    pub token: Option<[u8; 32]>,
    /// Nodes returned by the remote peer.
    pub closer_nodes: Vec<Ipv4Peer>,
    /// Response error code.
    pub error: u64,
    /// Optional response value.
    pub value: Option<Vec<u8>>,
    /// Round-trip time for the request.
    pub rtt: Duration,
}

#[derive(Debug, Clone)]
/// Parameters for a user-driven DHT query.
pub struct UserQueryParams {
    /// Query target node id.
    pub target: NodeId,
    /// RPC command to send.
    pub command: u64,
    /// Optional query payload.
    pub value: Option<Vec<u8>>,
    /// Whether the query is a commit.
    pub commit: bool,
    /// Optional per-query concurrency override.
    pub concurrency: Option<usize>,
}

#[derive(Debug, Clone)]
/// Parameters for a user-driven DHT request.
pub struct UserRequestParams {
    /// Optional request token.
    pub token: Option<[u8; 32]>,
    /// RPC command to send.
    pub command: u64,
    /// Optional target node id.
    pub target: Option<NodeId>,
    /// Optional request payload.
    pub value: Option<Vec<u8>>,
}

/// An incoming user-facing request forwarded from the DHT.
pub struct UserRequest {
    /// Origin peer for the request.
    pub from: Ipv4Peer,
    /// Optional origin peer id.
    pub id: Option<NodeId>,
    /// Optional request token.
    pub token: Option<[u8; 32]>,
    /// RPC command received.
    pub command: u64,
    /// Optional target node id.
    pub target: Option<NodeId>,
    /// Optional request payload.
    pub value: Option<Vec<u8>>,
    reply_tx: Option<oneshot::Sender<(u64, Option<Vec<u8>>)>>,
}

impl UserRequest {
    /// Replies to the request with a value and success code.
    pub fn reply(&mut self, value: Option<Vec<u8>>) {
        if let Some(tx) = self.reply_tx.take() {
            let _ = tx.send((0, value));
        }
    }

    /// Replies to the request with an error code.
    pub fn error(&mut self, code: u64) {
        if let Some(tx) = self.reply_tx.take() {
            let _ = tx.send((code, None));
        }
    }

    #[cfg(test)]
    pub(crate) fn test_with_reply(
        command: u64,
        reply_tx: oneshot::Sender<(u64, Option<Vec<u8>>)>,
    ) -> Self {
        Self {
            from: Ipv4Peer {
                host: "198.51.100.1".to_string(),
                port: 42_424,
            },
            id: None,
            token: None,
            command,
            target: None,
            value: None,
            reply_tx: Some(reply_tx),
        }
    }
}

// ── Internal command channel ──────────────────────────────────────────────────

enum DhtCommand {
    Bootstrapped {
        reply_tx: oneshot::Sender<Result<(), DhtError>>,
    },
    Ping {
        host: String,
        port: u16,
        reply_tx: oneshot::Sender<Result<PingResponse, DhtError>>,
    },
    FindNode {
        target: NodeId,
        reply_tx: oneshot::Sender<Result<Vec<QueryReply>, DhtError>>,
    },
    Query {
        params: UserQueryParams,
        reply_tx: oneshot::Sender<Result<Vec<QueryReply>, DhtError>>,
    },
    Request {
        params: UserRequestParams,
        host: String,
        port: u16,
        reply_tx: oneshot::Sender<Result<ResponseData, DhtError>>,
    },
    Relay {
        command: u64,
        target: Option<NodeId>,
        value: Option<Vec<u8>>,
        to: Ipv4Peer,
    },
    SubscribeRequests {
        reply_tx: oneshot::Sender<mpsc::Receiver<UserRequest>>,
    },
    TableSize {
        reply_tx: oneshot::Sender<usize>,
    },
    Destroy {
        reply_tx: oneshot::Sender<Result<(), DhtError>>,
    },
    LocalPort {
        reply_tx: oneshot::Sender<Result<u16, DhtError>>,
    },
    TableId {
        reply_tx: oneshot::Sender<Option<NodeId>>,
    },
    ServerSocket {
        reply_tx: oneshot::Sender<Option<UdxSocket>>,
    },
    ListenSocket {
        reply_tx: oneshot::Sender<Option<UdxSocket>>,
    },
}

// ── Standalone (non-query) inflight tracking ──────────────────────────────────

enum StandaloneRequest {
    Ping(oneshot::Sender<Result<PingResponse, DhtError>>),
    UserRequest(oneshot::Sender<Result<ResponseData, DhtError>>),
    Reping {
        new_node: Node,
        old_node_id: NodeId,
        last_seen_tick: u64,
    },
    Check {
        node_id: NodeId,
        last_seen_tick: u64,
    },
}

struct DeferredReply {
    from: Ipv4Peer,
    reply_ctx: ReplyContext,
    tid: u16,
    target: Option<NodeId>,
    error: u64,
    value: Option<Vec<u8>>,
}

/// Actor-owned admission ledger for delayed pings.
///
/// Delayed pings are a wire command, not a privileged local operation.  The
/// ledger deliberately contains reply values instead of spawned sleepers: a
/// remote peer can consume at most [`DELAYED_PING_QUEUE_CAPACITY`] slots, and
/// actor shutdown drops every pending entry synchronously.  Consequently there
/// is no detached timer or unbounded deferred-reply producer to clean up.
struct DelayedPingQueue {
    by_deadline: BTreeMap<Instant, Vec<DeferredReply>>,
    len: usize,
}

impl DelayedPingQueue {
    fn new() -> Self {
        Self {
            by_deadline: BTreeMap::new(),
            len: 0,
        }
    }

    fn try_admit(&mut self, deadline: Instant, reply: DeferredReply) -> Result<(), DeferredReply> {
        if self.len >= DELAYED_PING_QUEUE_CAPACITY {
            return Err(reply);
        }

        self.by_deadline.entry(deadline).or_default().push(reply);
        self.len += 1;
        Ok(())
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.by_deadline.keys().next().copied()
    }

    fn drain_due(&mut self, now: Instant) -> Vec<DeferredReply> {
        let mut due = Vec::new();
        while let Some(deadline) = self.next_deadline() {
            if deadline > now {
                break;
            }

            if let Some(mut replies) = self.by_deadline.remove(&deadline) {
                self.len -= replies.len();
                due.append(&mut replies);
            }
        }
        due
    }

    /// Cancels all delayed replies as part of actor shutdown.
    fn cancel_all(&mut self) {
        self.by_deadline.clear();
        self.len = 0;
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len
    }
}

// ── DhtHandle (user-facing, Send + Sync + Clone) ──────────────────────────────

/// Handle for interacting with a running DHT node.
#[derive(Clone)]
pub struct DhtHandle {
    cmd_tx: mpsc::UnboundedSender<DhtCommand>,
    wire: crate::io::WireCounters,
}

impl DhtHandle {
    /// Snapshot of cumulative wire bytes (sent, received) since the DHT
    /// started. Counts every UDP datagram exchanged by this node, including
    /// retries, queries, replies, and relays.
    pub fn wire_stats(&self) -> (u64, u64) {
        self.wire.snapshot()
    }

    /// Borrow the shared wire-counter handle. Useful when you want a long-
    /// lived reference (e.g. for periodic sampling from a UI thread) without
    /// going through `wire_stats()` repeatedly.
    pub fn wire_counters(&self) -> crate::io::WireCounters {
        self.wire.clone()
    }
}

impl DhtHandle {
    /// Waits until the node has finished bootstrapping.
    pub async fn bootstrapped(&self) -> Result<(), DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::Bootstrapped { reply_tx: tx })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)?
    }

    /// Sends a ping to `host:port`.
    pub async fn ping(&self, host: &str, port: u16) -> Result<PingResponse, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::Ping {
                host: host.to_string(),
                port,
                reply_tx: tx,
            })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)?
    }

    /// Runs a `find_node` query for `target`.
    pub async fn find_node(&self, target: NodeId) -> Result<Vec<QueryReply>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::FindNode {
                target,
                reply_tx: tx,
            })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)?
    }

    /// Runs a custom DHT query.
    pub async fn query(&self, params: UserQueryParams) -> Result<Vec<QueryReply>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::Query {
                params,
                reply_tx: tx,
            })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)?
    }

    /// Sends a request to a remote peer.
    pub async fn request(
        &self,
        params: UserRequestParams,
        host: &str,
        port: u16,
    ) -> Result<ResponseData, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::Request {
                params,
                host: host.to_string(),
                port,
                reply_tx: tx,
            })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)?
    }

    /// Fire-and-forget relay send (no response tracking).
    /// Relays an RPC command to `to` without waiting for a reply.
    pub fn relay(
        &self,
        command: u64,
        target: Option<NodeId>,
        value: Option<Vec<u8>>,
        to: &Ipv4Peer,
    ) -> Result<(), DhtError> {
        self.cmd_tx
            .send(DhtCommand::Relay {
                command,
                target,
                value,
                to: to.clone(),
            })
            .map_err(|_| DhtError::ChannelClosed)
    }

    /// Subscribes to forwarded user requests.
    pub async fn subscribe_requests(&self) -> Option<mpsc::Receiver<UserRequest>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::SubscribeRequests { reply_tx: tx })
            .ok()?;
        rx.await.ok()
    }

    /// Returns the current routing table size.
    pub async fn table_size(&self) -> Result<usize, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::TableSize { reply_tx: tx })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)
    }

    /// Destroys the running DHT node.
    pub async fn destroy(&self) -> Result<(), DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::Destroy { reply_tx: tx })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)?
    }

    /// Returns the local bound port.
    pub async fn local_port(&self) -> Result<u16, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::LocalPort { reply_tx: tx })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)?
    }

    /// Returns the node's current routing table ID, or None if not yet assigned.
    pub async fn table_id(&self) -> Result<Option<NodeId>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::TableId { reply_tx: tx })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)
    }

    /// Returns a shared reference to the DHT server socket for UDX stream multiplexing.
    pub async fn server_socket(&self) -> Result<Option<UdxSocket>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::ServerSocket { reply_tx: tx })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)
    }

    /// Returns the actual listen socket (the socket bound to the advertised port).
    pub async fn listen_socket(&self) -> Result<Option<UdxSocket>, DhtError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(DhtCommand::ListenSocket { reply_tx: tx })
            .map_err(|_| DhtError::ChannelClosed)?;
        rx.await.map_err(|_| DhtError::ChannelClosed)
    }
}

// ── DhtNode (internal background actor) ──────────────────────────────────────

struct DhtNode {
    io: Io,
    table: Arc<Mutex<RoutingTable>>,
    config: DhtConfig,
    local_port: u16,
    tick: u64,
    refresh_ticks: u64,
    repinging: u32,
    bootstrapped: bool,
    bootstrap_waiters: Vec<oneshot::Sender<Result<(), DhtError>>>,

    active_queries: HashMap<u64, Query>,
    tid_to_query: HashMap<u16, (u64, bool)>,
    standalone_tids: HashMap<u16, StandaloneRequest>,
    next_query_id: u64,

    cmd_rx: mpsc::UnboundedReceiver<DhtCommand>,
    request_subscribers: Vec<mpsc::Sender<UserRequest>>,

    destroyed: bool,
    last_tick_time: Instant,
    down_hints_per_tick: u32,
    bootstrap_query_id: Option<u64>,
    delayed_pings: DelayedPingQueue,
    /// The single actor owns every external reply receiver.  Its length is
    /// bounded by `external_request_admission`, so no remote request creates a
    /// detached waiter task or an unbounded reply registry.
    pending_user_replies: PendingUserReplyLedger,
    external_request_admission: Arc<Semaphore>,

    needs_id_update: bool,
    addr_samples: Vec<Ipv4Peer>,
}

/// Attempts to hand a remote request to one live subscriber without awaiting
/// queue capacity. Closed subscribers are removed; a full subscriber remains
/// eligible after its consumer drains it. The caller owns the returned request
/// and must reject it on the wire without creating a deferred reply waiter.
///
/// Returning the request intact is deliberate: it preserves its one-shot
/// responder for an immediate actor-side rejection and avoids a heap allocation
/// on the remote overload path.
#[allow(clippy::result_large_err)]
fn try_admit_user_request(
    request_subscribers: &mut Vec<mpsc::Sender<UserRequest>>,
    external_request_admission: &Arc<Semaphore>,
    user_req: UserRequest,
) -> Result<OwnedSemaphorePermit, UserRequest> {
    let permit = match Arc::clone(external_request_admission).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(user_req),
    };
    let mut pending = Some(user_req);

    request_subscribers.retain(|tx| {
        let Some(request) = pending.take() else {
            return !tx.is_closed();
        };

        match tx.try_send(request) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(request)) => {
                pending = Some(request);
                true
            }
            Err(mpsc::error::TrySendError::Closed(request)) => {
                pending = Some(request);
                false
            }
        }
    });

    match pending {
        Some(user_req) => Err(user_req),
        None => Ok(permit),
    }
}

/// An accepted external request's reply receiver and the wire context needed to
/// finish it. Values are polled by the sole DHT actor; they are never handed to
/// unbounded per-request tasks.
struct PendingUserReply {
    from: Ipv4Peer,
    reply_ctx: ReplyContext,
    tid: u16,
    target: Option<NodeId>,
    reply_rx: oneshot::Receiver<(u64, Option<Vec<u8>>)>,
    /// The actor-owned reply ledger holds the admission slot. A consumer can
    /// dequeue or drop `UserRequest`, but cannot release the slot before the
    /// reply receiver resolves or closes and this entry is removed.
    admission_permit: OwnedSemaphorePermit,
}

/// Fixed-size actor-owned ledger for externally forwarded user requests.
///
/// The semaphore is the first admission gate; this structural bound is the
/// second. Keeping the permit in the ledger couples capacity to reply-entry
/// lifetime and makes a reply-registry overflow impossible even under a
/// continuously ready inbound I/O branch.
struct PendingUserReplyLedger {
    entries: Vec<PendingUserReply>,
}

impl PendingUserReplyLedger {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(EXTERNAL_REQUEST_QUEUE_CAPACITY),
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn try_push(&mut self, entry: PendingUserReply) -> Result<(), PendingUserReply> {
        if self.entries.len() >= EXTERNAL_REQUEST_QUEUE_CAPACITY {
            return Err(entry);
        }
        self.entries.push(entry);
        Ok(())
    }

    fn take_ready(&mut self) -> Vec<(PendingUserReply, (u64, Option<Vec<u8>>))> {
        let mut entries = std::mem::take(&mut self.entries);
        let mut ready = Vec::new();
        for index in (0..entries.len()).rev() {
            let outcome = match entries[index].reply_rx.try_recv() {
                Ok((error, value)) => Some((error, value)),
                Err(oneshot::error::TryRecvError::Closed) => Some((ERR_UNKNOWN_COMMAND, None)),
                Err(oneshot::error::TryRecvError::Empty) => None,
            };
            if let Some(outcome) = outcome {
                ready.push((entries.swap_remove(index), outcome));
            }
        }
        self.entries = entries;
        ready
    }
}

impl DhtNode {
    async fn run(mut self) -> Result<(), DhtError> {
        let own_id = {
            let t = self.table.lock().map_err(|_| DhtError::ChannelClosed)?;
            *t.id()
        };

        self.start_bootstrap(own_id);

        let mut drain_interval = interval(Duration::from_millis(DRAIN_INTERVAL_MS));
        let mut tick_interval = interval(Duration::from_millis(TICK_INTERVAL_MS));
        let mut external_reply_poll =
            interval(Duration::from_millis(EXTERNAL_REPLY_POLL_INTERVAL_MS));
        external_reply_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if self.destroyed {
                break;
            }

            // Poll before entering the biased select. This makes a completed
            // or dropped user reply observable between every inbound packet;
            // capacity recovery never depends on the 10 ms timer winning
            // against a continuously ready I/O branch.
            if !self.pending_user_replies.is_empty() {
                self.poll_pending_user_replies();
            }

            let timeout_at = self.io.next_timeout_deadline();
            let delayed_ping_deadline = self.delayed_pings.next_deadline();

            tokio::select! {
                biased;

                // Keep a due bounded delayed reply ahead of a continuous
                // stream of input packets. Otherwise a flood could retain all
                // admission slots indefinitely despite the fixed capacity.
                _ = sleep_until(delayed_ping_deadline.unwrap_or_else(Instant::now)), if delayed_ping_deadline.is_some() => {
                    self.flush_due_delayed_pings();
                },

                Some(event) = self.io.recv() => {
                    self.handle_io_event(event);
                },

                _ = drain_interval.tick() => {
                    self.io.drain();
                },

                _ = tokio::time::sleep_until(timeout_at) => {
                    let timeouts = self.io.check_timeouts();
                    for evt in timeouts {
                        self.handle_timeout(evt);
                    }
                },

                _ = tick_interval.tick() => {
                    self.handle_tick();
                },

                _ = external_reply_poll.tick(), if !self.pending_user_replies.is_empty() => {
                    self.poll_pending_user_replies();
                },

                Some(cmd) = self.cmd_rx.recv() => {
                    if self.handle_command(cmd) {
                        break;
                    }
                },
            }
        }

        // Delayed pings are actor-owned values, not background tasks. Flush
        // already-due replies while I/O is still available, then cancel the
        // remaining bounded ledger before teardown. No sleeper can outlive the
        // node because no sleeper was spawned.
        self.flush_due_delayed_pings();
        self.delayed_pings.cancel_all();
        self.io.destroy().await?;
        Ok(())
    }

    fn start_bootstrap(&mut self, own_id: NodeId) {
        let bootstrap_nodes: Vec<(String, u16)> = self
            .config
            .bootstrap
            .iter()
            .filter_map(|s| parse_bootstrap_str(s))
            .collect();

        let (result_tx, _result_rx) = oneshot::channel::<QueryResult>();
        let query_id = self.next_query_id;
        self.next_query_id += 1;
        self.bootstrap_query_id = Some(query_id);

        let mut q = Query::new(
            query_id,
            own_id,
            true,
            CMD_FIND_NODE,
            None,
            self.config.concurrency,
            false,
            result_tx,
            Arc::clone(&self.table),
            own_id,
        );

        q.add_from_table();
        q.add_nodes(&bootstrap_nodes);

        let requests = q.poll_requests();
        self.dispatch_query_requests(query_id, requests);

        if q.is_finished() {
            self.on_query_removed(query_id);
        } else {
            self.active_queries.insert(query_id, q);
        }

        tracing::debug!(query_id, "bootstrap query started");
    }

    fn handle_io_event(&mut self, event: IoEvent) {
        match event {
            IoEvent::IncomingRequest(req) => {
                self.add_node_from_network(req.from.clone(), req.id);
                self.handle_incoming_request(req);
            }
            IoEvent::Response {
                tid,
                from,
                id,
                token,
                closer_nodes,
                error,
                value,
                rtt,
                request: _request,
                to,
            } => {
                self.add_node_from_network(from.clone(), id);

                if self.needs_id_update && to.port != 0 && !to.host.is_empty() {
                    self.addr_samples.push(to.clone());
                }

                let data = IoResponseData {
                    from: from.clone(),
                    from_id: id,
                    token,
                    closer_nodes: closer_nodes.clone(),
                    error,
                    value: value.clone(),
                    rtt,
                };

                if let Some((query_id, is_commit)) = self.tid_to_query.remove(&tid) {
                    if is_commit {
                        let finished = self
                            .active_queries
                            .get_mut(&query_id)
                            .map(|q| q.on_commit_done())
                            .unwrap_or(true);
                        if finished {
                            self.active_queries.remove(&query_id);
                            self.on_query_removed(query_id);
                        }
                    } else {
                        let reqs = self
                            .active_queries
                            .get_mut(&query_id)
                            .map(|q| q.on_response(data))
                            .unwrap_or_default();
                        self.dispatch_query_requests(query_id, reqs);
                        if self
                            .active_queries
                            .get(&query_id)
                            .map(|q| q.is_finished())
                            .unwrap_or(false)
                        {
                            self.active_queries.remove(&query_id);
                            self.on_query_removed(query_id);
                        }
                    }
                } else if let Some(standalone) = self.standalone_tids.remove(&tid) {
                    self.handle_standalone_response(
                        standalone,
                        ResponseData {
                            from,
                            id,
                            token,
                            closer_nodes,
                            error,
                            value,
                            rtt,
                        },
                        to,
                    );
                }
            }
        }
    }

    fn handle_incoming_request(&mut self, req: crate::io::IncomingRequest) {
        // `internal` is serialized on the network. It selects a protocol
        // command namespace, but does not authenticate the sender or exempt a
        // request from resource admission.
        if req.internal {
            match req.command {
                CMD_PING => {
                    self.io.send_reply(&req, 0, None);
                }
                CMD_DELAYED_PING => {
                    self.handle_delayed_ping(req);
                }
                CMD_PING_NAT => {
                    if let Some(ref val) = req.value {
                        if val.len() >= 2 {
                            let port = u16::from_le_bytes([val[0], val[1]]);
                            if port != 0 {
                                self.io.send_reply(&req, 0, None);
                            }
                        }
                    }
                }
                CMD_FIND_NODE => {
                    if req.target.is_some() {
                        self.io.send_reply(&req, 0, None);
                    }
                }
                CMD_DOWN_HINT => {
                    self.handle_down_hint_request(&req);
                    self.io.send_reply(&req, 0, None);
                }
                _ => {
                    let has_target = req.target.is_some();
                    let _ = has_target;
                    self.io.send_reply(&req, ERR_UNKNOWN_COMMAND, None);
                }
            }
        } else {
            self.forward_user_request(req);
        }
    }

    fn handle_delayed_ping(&mut self, req: crate::io::IncomingRequest) {
        let delay_ms = match &req.value {
            Some(v) if v.len() >= 4 => u32::from_le_bytes([v[0], v[1], v[2], v[3]]),
            _ => return,
        };

        if delay_ms > MAX_DELAYED_PING_DELAY_MS {
            self.io.send_reply(&req, ERR_UNKNOWN_COMMAND, None);
            return;
        }

        let reply = DeferredReply {
            from: req.from,
            reply_ctx: req.reply_ctx,
            tid: req.tid,
            target: req.target,
            error: 0,
            value: None,
        };
        let deadline = Instant::now() + Duration::from_millis(delay_ms as u64);

        // Reject before allocating a task or entering an unbounded deferred
        // channel. The remote controls the `internal` flag, so this applies to
        // every wire delayed-ping request, including forged internal ones.
        if let Err(mut rejected) = self.delayed_pings.try_admit(deadline, reply) {
            rejected.error = ERR_UNKNOWN_COMMAND;
            self.handle_deferred_reply(rejected);
        }
    }

    fn flush_due_delayed_pings(&mut self) {
        for reply in self.delayed_pings.drain_due(Instant::now()) {
            self.handle_deferred_reply(reply);
        }
    }

    fn handle_down_hint_request(&mut self, req: &crate::io::IncomingRequest) {
        let val = match &req.value {
            Some(v) if v.len() >= 6 => v.clone(),
            _ => return,
        };

        let ip_bytes: [u8; 4] = [val[0], val[1], val[2], val[3]];
        let port = u16::from_le_bytes([val[4], val[5]]);
        let host = Ipv4Addr::from(ip_bytes).to_string();
        let node_id = peer_id(&host, port);

        let (found_id, found_host, found_port, seen_tick, pinged_tick) = {
            let table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            if let Some(node) = table.get(&node_id) {
                (
                    node.id,
                    node.host.clone(),
                    node.port,
                    node.seen_tick,
                    node.pinged_tick,
                )
            } else {
                return;
            }
        };

        if pinged_tick < self.tick {
            if let Ok(mut table) = self.table.lock() {
                if let Some(node) = table.get_mut(&found_id) {
                    node.down_hints += 1;
                    node.pinged_tick = self.tick;
                }
            }

            let params = RequestParams {
                to: Ipv4Peer {
                    host: found_host,
                    port: found_port,
                },
                token: None,
                internal: true,
                command: CMD_PING,
                target: None,
                value: None,
            };

            if let Some(tid) = self.io.create_request(params) {
                self.standalone_tids.insert(
                    tid,
                    StandaloneRequest::Check {
                        node_id: found_id,
                        last_seen_tick: seen_tick,
                    },
                );
            }
        }
    }

    fn forward_user_request(&mut self, req: crate::io::IncomingRequest) {
        let (reply_tx, reply_rx) = oneshot::channel::<(u64, Option<Vec<u8>>)>();

        let user_req = UserRequest {
            from: req.from.clone(),
            id: req.id,
            token: req.token,
            command: req.command,
            target: req.target,
            value: req.value.clone(),
            reply_tx: Some(reply_tx),
        };

        let admission_permit = match try_admit_user_request(
            &mut self.request_subscribers,
            &self.external_request_admission,
            user_req,
        ) {
            Ok(admission_permit) => admission_permit,
            Err(_) => {
            // The request never entered a consumer-owned queue. Reply directly
            // from the DHT actor and do not create a reply-waiter task that no
            // consumer can ever satisfy.
            self.io.send_reply(&req, ERR_UNKNOWN_COMMAND, None);
            return;
            }
        };

        let pending = PendingUserReply {
            from: req.from.clone(),
            reply_ctx: req.reply_ctx,
            tid: req.tid,
            target: req.target,
            reply_rx,
            admission_permit,
        };
        if self.pending_user_replies.try_push(pending).is_err() {
            // This cannot happen while the semaphore and ledger capacities
            // agree, but remains a fail-closed structural guard if that
            // invariant ever changes.
            self.io.send_reply(&req, ERR_UNKNOWN_COMMAND, None);
        }
    }

    fn poll_pending_user_replies(&mut self) {
        for (reply, (error, value)) in self.pending_user_replies.take_ready() {
            self.handle_deferred_reply(DeferredReply {
                from: reply.from,
                reply_ctx: reply.reply_ctx,
                tid: reply.tid,
                target: reply.target,
                error,
                value,
            });
        }
    }

    fn handle_standalone_response(
        &mut self,
        standalone: StandaloneRequest,
        resp: ResponseData,
        reflexive_addr: Ipv4Peer,
    ) {
        match standalone {
            StandaloneRequest::Ping(reply_tx) => {
                let to = if reflexive_addr.port != 0 && !reflexive_addr.host.is_empty() {
                    Some(reflexive_addr)
                } else {
                    None
                };
                let _ = reply_tx.send(Ok(PingResponse {
                    from: resp.from,
                    id: resp.id,
                    rtt: resp.rtt,
                    to,
                    closer_nodes: resp.closer_nodes,
                }));
            }
            StandaloneRequest::UserRequest(reply_tx) => {
                let _ = reply_tx.send(Ok(resp));
            }
            StandaloneRequest::Reping {
                new_node,
                old_node_id,
                last_seen_tick,
            } => {
                self.repinging = self.repinging.saturating_sub(1);
                let stale = {
                    let table = self.table.lock().ok();
                    table
                        .and_then(|t| t.get(&old_node_id).map(|n| n.seen_tick <= last_seen_tick))
                        .unwrap_or(true)
                };
                if stale {
                    if let Ok(mut table) = self.table.lock() {
                        table.remove(&old_node_id);
                        table.add(new_node);
                    }
                }
            }
            StandaloneRequest::Check {
                node_id,
                last_seen_tick,
            } => {
                let stale = {
                    let table = self.table.lock().ok();
                    table
                        .and_then(|t| t.get(&node_id).map(|n| n.seen_tick <= last_seen_tick))
                        .unwrap_or(false)
                };
                if stale {
                    if let Ok(mut table) = self.table.lock() {
                        table.remove(&node_id);
                    }
                }
            }
        }
    }

    fn handle_timeout(&mut self, evt: TimeoutEvent) {
        if let Some((query_id, is_commit)) = self.tid_to_query.remove(&evt.tid) {
            if is_commit {
                let finished = self
                    .active_queries
                    .get_mut(&query_id)
                    .map(|q| q.on_commit_done())
                    .unwrap_or(true);
                if finished {
                    self.active_queries.remove(&query_id);
                    self.on_query_removed(query_id);
                }
            } else {
                let reqs = self
                    .active_queries
                    .get_mut(&query_id)
                    .map(|q| q.on_timeout(&evt.to))
                    .unwrap_or_default();
                self.dispatch_query_requests(query_id, reqs);
                if self
                    .active_queries
                    .get(&query_id)
                    .map(|q| q.is_finished())
                    .unwrap_or(false)
                {
                    self.active_queries.remove(&query_id);
                    self.on_query_removed(query_id);
                }
            }
        } else if let Some(standalone) = self.standalone_tids.remove(&evt.tid) {
            self.handle_standalone_timeout(standalone);
        }
    }

    fn handle_standalone_timeout(&mut self, standalone: StandaloneRequest) {
        match standalone {
            StandaloneRequest::Ping(reply_tx) => {
                let _ = reply_tx.send(Err(DhtError::RequestFailed("timeout".into())));
            }
            StandaloneRequest::UserRequest(reply_tx) => {
                let _ = reply_tx.send(Err(DhtError::RequestFailed("timeout".into())));
            }
            StandaloneRequest::Reping {
                new_node,
                old_node_id,
                ..
            } => {
                self.repinging = self.repinging.saturating_sub(1);
                if let Ok(mut table) = self.table.lock() {
                    table.remove(&old_node_id);
                    table.add(new_node);
                }
            }
            StandaloneRequest::Check { node_id, .. } => {
                if let Ok(mut table) = self.table.lock() {
                    table.remove(&node_id);
                }
            }
        }
    }

    fn handle_tick(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_tick_time).as_millis() as u64;

        if elapsed > SLEEPING_INTERVAL_MS {
            self.tick += 2 * OLD_NODE;
            self.tick += 8 - (self.tick & 7);
            self.refresh_ticks = 1;
        } else {
            self.tick += 1;
        }

        self.last_tick_time = now;
        self.down_hints_per_tick = 0;

        if !self.bootstrapped {
            return;
        }

        if (self.tick & 7) == 0 {
            self.ping_some();
        }

        self.refresh_ticks = self.refresh_ticks.saturating_sub(1);
        if self.refresh_ticks == 0 {
            self.refresh_ticks = REFRESH_TICKS;
            self.run_refresh();
        }
    }

    fn ping_some(&mut self) {
        let cnt = if !self.standalone_tids.is_empty() {
            3usize
        } else {
            5
        };

        let nodes: Vec<(NodeId, String, u16, u64)> = {
            let table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            if table.is_empty() {
                drop(table);
                self.run_refresh();
                return;
            }
            let all = table.closest(table.id(), table.len().min(50));
            let mut v: Vec<_> = all
                .iter()
                .filter(|n| n.pinged_tick < self.tick)
                .map(|n| (n.id, n.host.clone(), n.port, n.seen_tick))
                .collect();
            v.sort_by_key(|(_, _, _, seen)| *seen);
            v.truncate(cnt);
            v
        };

        for (node_id, host, port, last_seen) in nodes {
            if let Ok(mut table) = self.table.lock() {
                if let Some(node) = table.get_mut(&node_id) {
                    node.pinged_tick = self.tick;
                }
            }
            let params = RequestParams {
                to: Ipv4Peer { host, port },
                token: None,
                internal: true,
                command: CMD_PING,
                target: None,
                value: None,
            };
            if let Some(tid) = self.io.create_request(params) {
                self.standalone_tids.insert(
                    tid,
                    StandaloneRequest::Check {
                        node_id,
                        last_seen_tick: last_seen,
                    },
                );
            }
        }
    }

    fn run_refresh(&mut self) {
        self.refresh_ticks = REFRESH_TICKS;

        let target = {
            let table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            table.random().map(|n| n.id).unwrap_or_else(|| *table.id())
        };

        let own_id = {
            let table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            *table.id()
        };

        let (result_tx, result_rx) = oneshot::channel::<QueryResult>();
        let query_id = self.next_query_id;
        self.next_query_id += 1;

        let concurrency = (self.config.concurrency / 8).max(2);

        let mut q = Query::new(
            query_id,
            target,
            true,
            CMD_FIND_NODE,
            None,
            concurrency,
            false,
            result_tx,
            Arc::clone(&self.table),
            own_id,
        );
        q.add_from_table();

        let reqs = q.poll_requests();
        self.dispatch_query_requests(query_id, reqs);
        self.active_queries.insert(query_id, q);

        tokio::spawn(async move {
            let _ = result_rx.await;
        });
    }

    fn handle_command(&mut self, cmd: DhtCommand) -> bool {
        match cmd {
            DhtCommand::Bootstrapped { reply_tx } => {
                if self.bootstrapped {
                    let _ = reply_tx.send(Ok(()));
                } else {
                    self.bootstrap_waiters.push(reply_tx);
                }
            }

            DhtCommand::Ping {
                host,
                port,
                reply_tx,
            } => {
                let target = self.table.lock().ok().map(|t| *t.id());
                let params = RequestParams {
                    to: Ipv4Peer { host, port },
                    token: None,
                    internal: true,
                    command: CMD_FIND_NODE,
                    target,
                    value: None,
                };
                if let Some(tid) = self.io.create_request(params) {
                    self.standalone_tids
                        .insert(tid, StandaloneRequest::Ping(reply_tx));
                } else {
                    let _ = reply_tx.send(Err(DhtError::Destroyed));
                }
            }

            DhtCommand::FindNode { target, reply_tx } => {
                self.start_query(target, true, CMD_FIND_NODE, None, false, None, reply_tx);
            }

            DhtCommand::Query { params, reply_tx } => {
                let concurrency = params.concurrency.unwrap_or(self.config.concurrency);
                self.start_query(
                    params.target,
                    false,
                    params.command,
                    params.value,
                    params.commit,
                    Some(concurrency),
                    reply_tx,
                );
            }

            DhtCommand::Request {
                params,
                host,
                port,
                reply_tx,
            } => {
                let rparams = RequestParams {
                    to: Ipv4Peer { host, port },
                    token: params.token,
                    internal: false,
                    command: params.command,
                    target: params.target,
                    value: params.value,
                };
                if let Some(tid) = self.io.create_request(rparams) {
                    self.standalone_tids
                        .insert(tid, StandaloneRequest::UserRequest(reply_tx));
                } else {
                    let _ = reply_tx.send(Err(DhtError::Destroyed));
                }
            }

            DhtCommand::Relay {
                command,
                target,
                value,
                to,
            } => {
                self.io.relay(command, target, value, &to);
            }

            DhtCommand::SubscribeRequests { reply_tx } => {
                let (tx, rx) = mpsc::channel(EXTERNAL_REQUEST_QUEUE_CAPACITY);
                self.request_subscribers.push(tx);
                let _ = reply_tx.send(rx);
            }

            DhtCommand::TableSize { reply_tx } => {
                let size = self.table.lock().map(|t| t.len()).unwrap_or(0);
                let _ = reply_tx.send(size);
            }

            DhtCommand::Destroy { reply_tx } => {
                self.destroyed = true;
                let _ = reply_tx.send(Ok(()));
                return true;
            }

            DhtCommand::LocalPort { reply_tx } => {
                let _ = reply_tx.send(Ok(self.local_port));
            }

            DhtCommand::TableId { reply_tx } => {
                let id = self.table.lock().ok().map(|t| *t.id());
                let _ = reply_tx.send(id);
            }

            DhtCommand::ServerSocket { reply_tx } => {
                let socket = Some(self.io.primary_socket());
                let _ = reply_tx.send(socket);
            }

            DhtCommand::ListenSocket { reply_tx } => {
                let socket = Some(self.io.server_socket());
                let _ = reply_tx.send(socket);
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn start_query(
        &mut self,
        target: NodeId,
        internal: bool,
        command: u64,
        value: Option<Vec<u8>>,
        commit: bool,
        concurrency: Option<usize>,
        reply_tx: oneshot::Sender<Result<Vec<QueryReply>, DhtError>>,
    ) {
        let own_id = {
            let table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => {
                    let _ = reply_tx.send(Err(DhtError::ChannelClosed));
                    return;
                }
            };
            *table.id()
        };

        let concurrency = concurrency.unwrap_or(self.config.concurrency);
        let (result_tx, result_rx) = oneshot::channel::<QueryResult>();
        let query_id = self.next_query_id;
        self.next_query_id += 1;

        let mut q = Query::new(
            query_id,
            target,
            internal,
            command,
            value,
            concurrency,
            commit,
            result_tx,
            Arc::clone(&self.table),
            own_id,
        );

        q.add_from_table();

        let reqs = q.poll_requests();
        self.dispatch_query_requests(query_id, reqs);
        self.active_queries.insert(query_id, q);

        tokio::spawn(async move {
            match result_rx.await {
                Ok(result) => {
                    let _ = reply_tx.send(Ok(result.closest_replies));
                }
                Err(_) => {
                    let _ = reply_tx.send(Err(DhtError::ChannelClosed));
                }
            }
        });
    }

    fn dispatch_query_requests(&mut self, query_id: u64, requests: Vec<QueryRequest>) {
        for req in requests {
            match req {
                QueryRequest::Query(params) => {
                    if let Some(tid) = self.io.create_request(params) {
                        self.tid_to_query.insert(tid, (query_id, false));
                    }
                }
                QueryRequest::Commit(params) => {
                    if let Some(tid) = self.io.create_request(params) {
                        self.tid_to_query.insert(tid, (query_id, true));
                    }
                }
                QueryRequest::DownHint(params) => {
                    if self.down_hints_per_tick < DOWN_HINTS_RATE_LIMIT {
                        self.down_hints_per_tick += 1;
                        let _ = self.io.create_request(params);
                    }
                }
            }
        }
    }

    fn add_node_from_network(&mut self, from: Ipv4Peer, from_id: Option<NodeId>) {
        let id = match from_id {
            Some(id) => id,
            None => return,
        };

        let own_id = {
            let table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            *table.id()
        };

        if id == own_id {
            return;
        }

        {
            let mut table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            if let Some(node) = table.get_mut(&id) {
                node.seen_tick = self.tick;
                node.pinged_tick = self.tick;
                return;
            }
        }

        let new_node = Node {
            id,
            host: from.host,
            port: from.port,
            token: None,
            added_tick: self.tick,
            seen_tick: self.tick,
            pinged_tick: self.tick,
            down_hints: 0,
        };

        let added = {
            let mut table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            table.add(new_node.clone())
        };

        if !added {
            self.handle_bucket_full(new_node);
        }
    }

    fn handle_bucket_full(&mut self, new_node: Node) {
        if !self.bootstrapped || self.repinging >= MAX_REPINGING {
            return;
        }

        let events: Vec<TableEvent> = {
            let mut table = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            table.drain_events()
        };

        for evt in events {
            let TableEvent::BucketFull {
                new_node: evt_new_node,
                bucket_index: _,
            } = evt;
            {
                let oldest = {
                    let table = match self.table.lock() {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    let close = table.closest(&evt_new_node.id, 20);
                    close
                        .iter()
                        .filter(|n| n.pinged_tick < self.tick)
                        .min_by(|a, b| {
                            a.pinged_tick
                                .cmp(&b.pinged_tick)
                                .then(a.added_tick.cmp(&b.added_tick))
                        })
                        .map(|n| (n.id, n.host.clone(), n.port, n.seen_tick))
                };

                if let Some((old_id, old_host, old_port, last_seen)) = oldest {
                    if self.tick - last_seen < RECENT_NODE
                        && self.tick.saturating_sub(
                            self.table
                                .lock()
                                .ok()
                                .and_then(|t| t.get(&old_id).map(|n| n.added_tick))
                                .unwrap_or(0),
                        ) > OLD_NODE
                    {
                        return;
                    }

                    if let Ok(mut table) = self.table.lock() {
                        if let Some(node) = table.get_mut(&old_id) {
                            node.pinged_tick = self.tick;
                        }
                    }

                    let params = RequestParams {
                        to: Ipv4Peer {
                            host: old_host,
                            port: old_port,
                        },
                        token: None,
                        internal: true,
                        command: CMD_PING,
                        target: None,
                        value: None,
                    };
                    if let Some(tid) = self.io.create_request(params) {
                        self.repinging += 1;
                        self.standalone_tids.insert(
                            tid,
                            StandaloneRequest::Reping {
                                new_node: evt_new_node,
                                old_node_id: old_id,
                                last_seen_tick: last_seen,
                            },
                        );
                    }
                }
            }
        }

        let _ = new_node;
    }

    fn on_query_removed(&mut self, query_id: u64) {
        if self.bootstrap_query_id == Some(query_id) {
            self.bootstrap_query_id = None;
            self.mark_bootstrapped();
        }
    }

    fn handle_deferred_reply(&mut self, reply: DeferredReply) {
        self.io.send_reply_deferred(
            &reply.from,
            reply.reply_ctx,
            reply.tid,
            reply.target,
            reply.error,
            reply.value.as_deref(),
        );
    }

    fn mark_bootstrapped(&mut self) {
        if self.bootstrapped {
            return;
        }

        if self.needs_id_update {
            if let Some(addr) = self.determine_address_from_samples() {
                let new_id = peer_id(&addr.host, addr.port);
                if let Ok(mut table) = self.table.lock() {
                    table.rebuild_with_id(new_id);
                }
                tracing::debug!(host = %addr.host, port = addr.port, "updated node ID from NAT samples");
            }
            self.needs_id_update = false;
        }

        self.bootstrapped = true;
        tracing::debug!("DHT node bootstrapped");
        for tx in self.bootstrap_waiters.drain(..) {
            let _ = tx.send(Ok(()));
        }
    }

    fn determine_address_from_samples(&self) -> Option<Ipv4Peer> {
        if self.addr_samples.is_empty() {
            return None;
        }

        let mut counts: HashMap<String, usize> = HashMap::new();
        for sample in &self.addr_samples {
            let key = format!("{}:{}", sample.host, sample.port);
            *counts.entry(key).or_default() += 1;
        }

        let best = counts.into_iter().max_by_key(|(_, count)| *count)?;
        let (host_port, _) = best;
        let parts: Vec<&str> = host_port.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port: u16 = parts[0].parse().ok()?;
            let host = parts[1].to_string();
            Some(Ipv4Peer { host, port })
        } else {
            None
        }
    }
}

// ── Spawn ─────────────────────────────────────────────────────────────────────

/// Spawns a DHT node and returns its join handle and public handle.
pub async fn spawn(
    runtime: &UdxRuntime,
    config: DhtConfig,
) -> Result<(tokio::task::JoinHandle<Result<(), DhtError>>, DhtHandle), DhtError> {
    let table_id: NodeId = rand::random();
    let table = Arc::new(Mutex::new(RoutingTable::new(table_id)));

    let ephemeral = config.ephemeral.unwrap_or(!config.bootstrap.is_empty());
    let io_config = IoConfig {
        max_window: config.max_window,
        port: config.port,
        host: config.host.clone(),
        firewalled: config.firewalled,
        ephemeral,
    };

    let io = Io::bind(runtime, Arc::clone(&table), io_config).await?;
    let local_port = io
        .server_local_addr()
        .await
        .map(|a| a.port())
        .unwrap_or(config.port);

    let is_wildcard = config.host == "0.0.0.0" || config.host == "::";
    let needs_id_update = !ephemeral && is_wildcard;

    if !ephemeral && !is_wildcard {
        let deterministic_id = peer_id(&config.host, local_port);
        if let Ok(mut t) = table.lock() {
            t.rebuild_with_id(deterministic_id);
        }
    }

    let mut config = config;
    config.bootstrap = resolve_bootstrap_nodes(&config.bootstrap).await;

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let node = DhtNode {
        io,
        table,
        config,
        local_port,
        tick: 0,
        refresh_ticks: REFRESH_TICKS,
        repinging: 0,
        bootstrapped: false,
        bootstrap_waiters: Vec::new(),
        active_queries: HashMap::new(),
        tid_to_query: HashMap::new(),
        standalone_tids: HashMap::new(),
        next_query_id: 0,
        cmd_rx,
        request_subscribers: Vec::new(),
        destroyed: false,
        last_tick_time: Instant::now(),
        down_hints_per_tick: 0,
        bootstrap_query_id: None,
        delayed_pings: DelayedPingQueue::new(),
        pending_user_replies: PendingUserReplyLedger::new(),
        external_request_admission: Arc::new(Semaphore::new(EXTERNAL_REQUEST_QUEUE_CAPACITY)),
        needs_id_update,
        addr_samples: Vec::new(),
    };

    let wire = node.io.wire_counters();
    let handle = tokio::spawn(node.run());
    let dht_handle = DhtHandle { cmd_tx, wire };

    Ok((handle, dht_handle))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user_request(
        command: u64,
        reply_tx: oneshot::Sender<(u64, Option<Vec<u8>>)>,
    ) -> UserRequest {
        UserRequest {
            from: Ipv4Peer {
                host: "198.51.100.1".to_string(),
                port: 42_424,
            },
            id: None,
            token: None,
            command,
            target: None,
            value: None,
            reply_tx: Some(reply_tx),
        }
    }

    #[test]
    fn test_dht_config_defaults() {
        let cfg = DhtConfig::default();
        assert_eq!(cfg.port, 0);
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.concurrency, 10);
        assert_eq!(cfg.max_window, 80);
        assert!(cfg.firewalled);
        assert!(cfg.bootstrap.is_empty());
        assert!(cfg.ephemeral.is_none());
    }

    #[test]
    fn test_bootstrap_parse_simple() {
        let (host, port) = parse_bootstrap_str("127.0.0.1:10001").expect("parse");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 10001);
    }

    #[test]
    fn test_bootstrap_parse_with_at() {
        let (host, port) =
            parse_bootstrap_str("10.0.0.1@bootstrap.example.com:24242").expect("should parse");
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 24242);
    }

    #[test]
    fn test_bootstrap_parse_bad_no_colon() {
        assert!(parse_bootstrap_str("localhost").is_none());
    }

    #[test]
    fn test_bootstrap_parse_bad_port() {
        assert!(parse_bootstrap_str("localhost:notaport").is_none());
    }

    #[test]
    fn test_err_display() {
        let e = DhtError::Destroyed;
        assert!(e.to_string().contains("destroyed"));
    }

    #[test]
    fn test_down_hints_rate_limit_constant() {
        assert_eq!(DOWN_HINTS_RATE_LIMIT, 50);
    }

    #[test]
    fn test_tick_constants() {
        assert_eq!(REFRESH_TICKS, 60);
        assert_eq!(RECENT_NODE, 12);
        assert_eq!(OLD_NODE, 360);
    }

    fn test_delayed_reply(tid: u16) -> DeferredReply {
        DeferredReply {
            from: Ipv4Peer {
                host: "198.51.100.2".to_string(),
                port: 42_425,
            },
            reply_ctx: ReplyContext {
                socket_kind: crate::io::SocketKind::Server,
            },
            tid,
            target: None,
            error: 0,
            value: None,
        }
    }

    #[test]
    fn forged_wire_internal_delayed_pings_are_capacity_limited() {
        // A peer can forge `internal: true` on the wire, so the queue must
        // impose the exact same cap for every delayed-ping-shaped request.
        let mut delayed_pings = DelayedPingQueue::new();
        let deadline = Instant::now() + Duration::from_secs(10);

        for tid in 0..DELAYED_PING_QUEUE_CAPACITY as u16 {
            assert!(
                delayed_pings
                    .try_admit(deadline, test_delayed_reply(tid))
                    .is_ok(),
                "the fixed delayed-ping capacity must admit its final slot"
            );
        }
        assert_eq!(delayed_pings.len(), DELAYED_PING_QUEUE_CAPACITY);

        assert!(
            delayed_pings
                .try_admit(deadline, test_delayed_reply(u16::MAX))
                .is_err(),
            "a forged internal delayed ping must be rejected rather than spawning work"
        );
        assert_eq!(delayed_pings.len(), DELAYED_PING_QUEUE_CAPACITY);
    }

    #[test]
    fn delayed_ping_queue_recovers_after_due_entries_are_drained() {
        let mut delayed_pings = DelayedPingQueue::new();
        let now = Instant::now();
        let deadline = now + Duration::from_millis(MAX_DELAYED_PING_DELAY_MS as u64);

        for tid in 0..DELAYED_PING_QUEUE_CAPACITY as u16 {
            assert!(
                delayed_pings
                    .try_admit(deadline, test_delayed_reply(tid))
                    .is_ok()
            );
        }

        let drained = delayed_pings.drain_due(deadline);
        assert_eq!(drained.len(), DELAYED_PING_QUEUE_CAPACITY);
        assert_eq!(delayed_pings.len(), 0);
        assert!(delayed_pings.next_deadline().is_none());

        assert!(
            delayed_pings
                .try_admit(deadline, test_delayed_reply(9_999))
                .is_ok(),
            "capacity must be available as soon as due work is drained"
        );
        assert_eq!(delayed_pings.len(), 1);
    }

    #[test]
    fn delayed_ping_shutdown_drains_due_and_cancels_without_detached_timers() {
        let mut delayed_pings = DelayedPingQueue::new();
        let now = Instant::now();
        assert!(delayed_pings.try_admit(now, test_delayed_reply(1)).is_ok());
        assert!(
            delayed_pings
                .try_admit(now + Duration::from_secs(10), test_delayed_reply(2))
                .is_ok()
        );

        // This mirrors the actor shutdown path: drain replies that are already
        // due, cancel the rest synchronously, and leave no spawned sleeper.
        let due = delayed_pings.drain_due(now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].tid, 1);
        delayed_pings.cancel_all();

        assert_eq!(delayed_pings.len(), 0);
        assert!(delayed_pings.next_deadline().is_none());
        assert!(
            delayed_pings
                .drain_due(Instant::now() + Duration::from_secs(60))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn external_request_admission_stays_bounded_after_dequeue_until_reply_or_drop() {
        let (subscriber_tx, mut subscriber_rx) = mpsc::channel(EXTERNAL_REQUEST_QUEUE_CAPACITY);
        let mut subscribers = vec![subscriber_tx];
        let admission = Arc::new(Semaphore::new(EXTERNAL_REQUEST_QUEUE_CAPACITY));

        for command in 0..EXTERNAL_REQUEST_QUEUE_CAPACITY as u64 {
            let (reply_tx, _reply_rx) = oneshot::channel();
            assert!(
                try_admit_user_request(
                    &mut subscribers,
                    &admission,
                    test_user_request(command, reply_tx),
                )
                .is_ok(),
                "queue must admit exactly its configured capacity"
            );
        }
        assert_eq!(subscriber_rx.len(), EXTERNAL_REQUEST_QUEUE_CAPACITY);

        let mut held = Vec::with_capacity(EXTERNAL_REQUEST_QUEUE_CAPACITY);
        while let Some(request) = subscriber_rx.recv().await {
            held.push(request);
            if held.len() == EXTERNAL_REQUEST_QUEUE_CAPACITY {
                break;
            }
        }
        assert!(
            subscriber_rx.is_empty(),
            "all requests were dequeued but held"
        );

        let (reject_tx, reject_rx) = oneshot::channel();
        let mut rejected = try_admit_user_request(
            &mut subscribers,
            &admission,
            test_user_request(EXTERNAL_REQUEST_QUEUE_CAPACITY as u64, reject_tx),
        )
        .expect_err("dequeued but unreplied requests must retain every admission slot");
        rejected.error(ERR_UNKNOWN_COMMAND);
        assert_eq!(
            reject_rx.await.expect("rejection reply must be delivered"),
            (ERR_UNKNOWN_COMMAND, None)
        );

        let mut completed = held.pop().expect("held request");
        completed.reply(None);

        let (recovery_tx, _recovery_rx) = oneshot::channel();
        assert!(
            try_admit_user_request(
                &mut subscribers,
                &admission,
                test_user_request(9_999, recovery_tx)
            )
            .is_ok(),
            "replying must release exactly one admission slot"
        );
        assert_eq!(subscriber_rx.len(), 1);

        drop(held);
        let (drop_recovery_tx, _drop_recovery_rx) = oneshot::channel();
        assert!(
            try_admit_user_request(
                &mut subscribers,
                &admission,
                test_user_request(10_000, drop_recovery_tx),
            )
            .is_ok(),
            "dropping a held request must release its admission slot"
        );
        drop(subscriber_rx.recv().await.expect("recovered request"));
        drop(subscriber_rx.recv().await.expect("drop-recovered request"));
    }

    #[tokio::test]
    async fn closed_external_request_queue_rejects_without_waiter() {
        let (subscriber_tx, subscriber_rx) = mpsc::channel(EXTERNAL_REQUEST_QUEUE_CAPACITY);
        drop(subscriber_rx);
        let mut subscribers = vec![subscriber_tx];
        let admission = Arc::new(Semaphore::new(EXTERNAL_REQUEST_QUEUE_CAPACITY));

        let (reject_tx, reject_rx) = oneshot::channel();
        let mut rejected = try_admit_user_request(
            &mut subscribers,
            &admission,
            test_user_request(1, reject_tx),
        )
        .expect_err("a closed external queue must fail closed");
        rejected.error(ERR_UNKNOWN_COMMAND);

        assert_eq!(
            reject_rx.await.expect("closed-queue rejection reply"),
            (ERR_UNKNOWN_COMMAND, None)
        );
        assert!(subscribers.is_empty(), "closed subscriber must be pruned");
    }

    #[tokio::test]
    async fn external_request_admission_skips_full_and_closed_subscribers_without_losing_reply() {
        let (first_tx, mut first_rx) = mpsc::channel(1);
        let (first_fill_tx, _first_fill_rx) = oneshot::channel();
        assert!(
            first_tx
                .try_send(test_user_request(10, first_fill_tx))
                .is_ok()
        );

        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);

        let (third_tx, mut third_rx) = mpsc::channel(1);
        let mut subscribers = vec![first_tx, closed_tx, third_tx];
        let admission = Arc::new(Semaphore::new(EXTERNAL_REQUEST_QUEUE_CAPACITY));

        let (reply_tx, reply_rx) = oneshot::channel();
        assert!(
            try_admit_user_request(
                &mut subscribers,
                &admission,
                test_user_request(11, reply_tx)
            )
            .is_ok(),
            "the available third subscriber must receive the preserved request"
        );
        assert_eq!(
            subscribers.len(),
            2,
            "the full first sender remains eligible while the closed sender is pruned"
        );

        let mut delivered_to_third = third_rx.recv().await.expect("third request");
        assert_eq!(delivered_to_third.command, 11);
        delivered_to_third.reply(Some(vec![0xA5]));
        assert_eq!(
            reply_rx.await.expect("third subscriber reply"),
            (0, Some(vec![0xA5]))
        );

        let retained_first = first_rx.recv().await.expect("original first request");
        assert_eq!(retained_first.command, 10);
        drop(retained_first);

        let (follow_up_tx, _follow_up_rx) = oneshot::channel();
        assert!(
            try_admit_user_request(
                &mut subscribers,
                &admission,
                test_user_request(12, follow_up_tx),
            )
            .is_ok()
        );
        let delivered_to_retained_first = first_rx.recv().await.expect("retained first request");
        assert_eq!(delivered_to_retained_first.command, 12);
    }
}
