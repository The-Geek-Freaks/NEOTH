//! R-7 live-wire scaffold — peeroxide Hyperswarm bridge.
//!
//! Per `PLAN/PROGRESS.md` post-v0.1 backlog. The Phase-3 dep
//! block lifted in Session 19 (commit `d44a0e8`) — peeroxide
//! 1.3.x is the maintained pure-Rust Hyperswarm port. This
//! module is the integration site: bring up a swarm, join a
//! topic derived from the operator's cluster ID, hand each
//! incoming peer connection off to the heartbeat exchanger.
//!
//! ## Operator-facing wire
//!
//! ```ignore
//! use std::sync::{Arc, Mutex};
//! use crate::cluster::{hyperswarm, PeerLoadRegistry};
//!
//! // Production path: always supply the cluster_key so inbound-peer
//! // proof enforcement is armed. `spawn_discovery` (no key) is
//! // crate-internal only.
//! let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
//! let cluster_key = Arc::new(identity.key);
//! let handle = hyperswarm::spawn_discovery_with_wal(
//!     "my-cluster",
//!     Some(cluster_key),
//!     registry,
//!     Some(Arc::new(wal_writer)),
//! ).await?;
//! // ... daemon runs ...
//! handle.shutdown().await?;
//! ```
//!
//! ## Why a scaffold
//!
//! peeroxide ships a Noise-encrypted AsyncRead+AsyncWrite per
//! peer connection but the cross-peer wire protocol is
//! NEOTH-specific (heartbeat frame with load + last-seen +
//! capabilities). The protocol itself needs a separate Chorus
//! pass — until that lands, this module brings up the swarm
//! + logs peer connections + exposes the surface the future
//! protocol implementer plugs into.
//!
//! ## What this module owns
//!
//! - [`derive_topic`] — operator-supplied cluster name →
//!   32-byte topic via peeroxide's `discovery_key`.
//! - [`SwarmHandle`] — RAII wrapper around the spawned
//!   peeroxide swarm + the JoinHandle. Drop aborts the task.
//! - [`spawn_discovery_with_wal`] — bring up the swarm, join the
//!   topic, spawn the peer-acceptor loop. Returns the
//!   handle. (`spawn_discovery` is a crate-internal convenience
//!   wrapper; external callers should always supply a cluster_key.)
//!
//! ## What this module does NOT do (yet)
//!
//! - Heartbeat protocol exchange. The peer-acceptor logs each
//!   new connection but doesn't yet write/read frames. That
//!   ships in the follow-up commit alongside the WAL
//!   `0xE0..=0xE7` band reservation for cluster-event frames.
//! - LOCAL→registry write path. Once heartbeats land,
//!   `registry.lock().record_heartbeat(peer_load)` fires per
//!   received frame.
//! - DHT bootstrap-server config from `freedom.yaml`. Today
//!   we use peeroxide's public bootstrap default — a future
//!   commit reads
//!   `freedom.yaml::cluster.hyperswarm.bootstrap` for
//!   operator-private DHT networks.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use super::discovery::ClusterKey;
use super::executor::ClusterTaskJob;
use super::heartbeat::{
    self, FrameBody, FrameKind, HeartbeatBody, HelloBody, PROTOCOL_NAME, PROTOCOL_VERSION,
    TaskDelegateBody, TaskResultBody, TaskResultStatus, WireFrame,
};
use super::gossip::GossipPolicy;
use super::gossip_wire::GossipAcceptance;
use super::local_load;
use super::peer_auth::{compute_cluster_key_proof, verify_peer_proof};
use super::peer_streams::PeerStreamRegistry;
use super::wal_sync::GossipState;
use super::{PeerSessionId, PeerLoad, PeerLoadRegistry};
use crate::permissions::{self, Action, AutonomyLevel, Decision};
use crate::wal::writer::WalWriterHandle;

/// Optional WAL writer handle threaded into `spawn_discovery`
/// so each per-peer task emits `0xE0..=0xE5 CLUSTER_*` frames
/// into the audit chain. CLI one-shots that don't have a
/// live writer pass `None`; the daemon's `cli::serve` path
/// threads its handle through.
pub type ClusterWalWriter = Option<Arc<WalWriterHandle>>;

/// SL-00(1b) DoS hardening: maximum number of concurrent peer sessions on the
/// public DHT transport. Reached only under a connection flood (a healthy home
/// cluster is single-digit peers); excess inbound connections are dropped.
const MAX_CONCURRENT_PEER_SESSIONS: usize = 64;

/// SL-00(1b) DoS hardening: wall-clock budget for the Hello handshake
/// (write-our-Hello + read-peer-Hello). A peer that connects but stalls
/// without completing the handshake is dropped instead of pinning a task /
/// session slot indefinitely. Generous enough for real WAN round-trips.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Derive a 32-byte Hyperswarm topic from an operator-supplied
/// cluster name. Pure function — operator-facing wire form is
/// the cluster name string; peeroxide hashes it via
/// `discovery_key` (BLAKE2b under the hood) so two daemons
/// configured with the same name find each other.
pub fn derive_topic(cluster_name: &str) -> [u8; 32] {
    peeroxide::discovery_key(cluster_name.as_bytes())
}

/// RAII handle to a running Hyperswarm discovery transport.
///
/// **Lifecycle (SL-00(1b) review fix):** peeroxide's swarm actor breaks its
/// command loop as soon as the LAST `cmd_tx` (its `SwarmHandle`) drops, which
/// destroys the DHT + unannounces. We therefore RETAIN peeroxide's handle for
/// the whole transport lifetime — dropping it earlier would tear the swarm
/// down on the next tick (announce-then-die). Holding it also keeps the
/// connection receiver alive so the accept loop actually sees peers.
///
/// Teardown order on [`shutdown`](Self::shutdown): `leave(topic)` (unannounce)
/// → drop the peeroxide handle (actor breaks its loop) → abort our accept loop
/// → await the actor task so DHT sockets close before the process exits.
pub struct SwarmHandle {
    /// peeroxide command handle. `Some` while live; dropping it stops the DHT.
    peer_handle: Option<peeroxide::SwarmHandle>,
    /// The joined topic — used to `leave()` (unannounce) on graceful shutdown.
    topic: [u8; 32],
    /// peeroxide's DHT actor task — awaited on shutdown for clean socket close.
    swarm_task: Option<tokio::task::JoinHandle<()>>,
    /// Our per-peer connection-accept loop.
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

impl SwarmHandle {
    /// Explicit graceful shutdown — unannounces, stops the DHT actor, and
    /// awaits termination. Use over `Drop` when the caller wants synchronous
    /// teardown (daemon SIGTERM path) with no lingering DHT announce.
    pub async fn shutdown(mut self) -> Result<()> {
        // 1. Unannounce + stop discovery for our topic (best-effort — the
        //    handle-drop below also tears the swarm down, this just makes the
        //    unannounce prompt rather than waiting for the actor to wind down).
        if let Some(h) = self.peer_handle.as_ref() {
            if let Err(e) = h.leave(self.topic).await {
                debug!(error = %e, "hyperswarm: leave on shutdown failed (continuing teardown)");
            }
        }
        // 2. Drop the command handle → last cmd_tx gone → actor breaks its loop
        //    → DHT destroyed + unannounced.
        self.peer_handle = None;
        // 3. Abort our accept loop (it would otherwise observe a closed conn_rx).
        if let Some(t) = self.accept_task.take() {
            t.abort();
            let _ = t.await;
        }
        // 4. Await the actor task so the DHT finishes closing its IO sockets
        //    before we return (cancelled/panicked still means it's gone).
        if let Some(t) = self.swarm_task.take() {
            let _ = t.await;
        }
        Ok(())
    }
}

impl Drop for SwarmHandle {
    fn drop(&mut self) {
        // RAII fallback (test cleanup / panics): dropping the peeroxide handle
        // stops the actor; abort our task handles so they don't leak.
        self.peer_handle = None;
        if let Some(t) = self.accept_task.take() {
            t.abort();
        }
        if let Some(t) = self.swarm_task.take() {
            t.abort();
        }
    }
}

/// Bring up a peeroxide swarm, join the cluster's topic, and
/// spawn a background loop that handles each incoming peer
/// connection. Returns a `SwarmHandle` that the daemon's
/// shutdown path drops cleanly.
///
/// `registry` is held by `Arc<Mutex>` so the loop can write
/// peer-load snapshots into it once the heartbeat protocol
/// ships (follow-up). Today the loop only logs.
pub(crate) async fn spawn_discovery(
    cluster_name: &str,
    registry: Arc<Mutex<PeerLoadRegistry>>,
) -> Result<SwarmHandle> {
    // No-auth/no-wal path (CLI one-shots / tests): a throwaway peer-stream
    // registry — nothing external sends directed frames on this path.
    spawn_discovery_with_wal(
        cluster_name,
        None,
        registry,
        None,
        Arc::new(PeerStreamRegistry::new()),
        // No-auth path never accepts delegated tasks: Strict autonomy + no
        // executor ⇒ any TaskDelegate is rejected. neoth_home for completeness.
        AutonomyLevel::Strict,
        crate::config::FreedomConfig::default_neoth_home(),
        None,
    )
    .await
}

/// Same as [`spawn_discovery`] but threads a live
/// `WalWriterHandle` into every per-peer task so cluster
/// lifecycle events emit `0xE0..=0xE5` frames. Used by
/// `cli::serve` which holds the writer; CLI one-shots call
/// [`spawn_discovery`] (no writer).
pub async fn spawn_discovery_with_wal(
    cluster_name: &str,
    // SL-00(1b): the shared cluster_key. `Some` enforces the cluster_key
    // proof in every peer handshake (the activated transport path always
    // passes it); `None` is the legacy/no-auth path (CLI one-shots / tests).
    cluster_key: Option<Arc<ClusterKey>>,
    registry: Arc<Mutex<PeerLoadRegistry>>,
    wal_writer: ClusterWalWriter,
    // SL-00(1c): shared registry of per-peer outbound channels. The daemon
    // holds a clone so SL-01/SL-01b can send directed frames to a peer.
    peer_streams: Arc<PeerStreamRegistry>,
    // SL-01 accept-gate inputs threaded into every peer session.
    autonomy: AutonomyLevel,
    neoth_home: std::path::PathBuf,
    dispatch_tx: Option<tokio::sync::mpsc::Sender<ClusterTaskJob>>,
) -> Result<SwarmHandle> {
    let topic = derive_topic(cluster_name);
    let config = peeroxide::SwarmConfig::with_public_bootstrap();
    let (swarm_task, handle, mut conn_rx) = peeroxide::spawn(config)
        .await
        .context("peeroxide::spawn — bring up Hyperswarm")?;
    // Our own Noise static pubkey — the same for every peer session. Bound
    // into the cluster_key proof so a captured proof can't be replayed.
    let own_noise_pk: [u8; 32] = handle.key_pair().public_key;

    // SL-00(1b) DoS hardening: bound concurrent peer sessions. The swarm sits
    // on the PUBLIC DHT, so an attacker who knows the cluster name (public) can
    // open connections; each previously span an unbounded task. The semaphore
    // caps live sessions — excess inbound connections are dropped (closed) with
    // a warn rather than spawning unbounded tasks / exhausting memory. The
    // per-peer handshake itself is time-bounded inside handle_peeroxide_connection.
    let session_limiter = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PEER_SESSIONS));

    let cluster_name_owned = cluster_name.to_string();
    let own_peer_id = local_peer_id();
    let accept_task = tokio::spawn(async move {
        while let Some(conn) = conn_rx.recv().await {
            let peer_hex = hex_encode(conn.remote_public_key());
            // Acquire a session slot BEFORE spawning. `try_acquire_owned` is
            // non-blocking: at capacity we drop the connection immediately so a
            // flood can't queue unbounded work. The permit is held for the
            // peer task's lifetime and released on drop.
            let permit = match Arc::clone(&session_limiter).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        peer = %peer_hex,
                        max = MAX_CONCURRENT_PEER_SESSIONS,
                        "hyperswarm: peer-session limit reached — dropping inbound connection"
                    );
                    // Dropping `conn` closes the SecretStream.
                    drop(conn);
                    continue;
                }
            };
            debug!(peer = %peer_hex, "hyperswarm: peer connected — driving handshake");
            let cluster = cluster_name_owned.clone();
            let own_id = own_peer_id.clone();
            let reg = Arc::clone(&registry);
            let wal = wal_writer.clone();
            let ckey = cluster_key.clone();
            let streams = Arc::clone(&peer_streams);
            let home = neoth_home.clone();
            let dtx = dispatch_tx.clone();
            tokio::spawn(async move {
                // Hold the permit until this session ends.
                let _permit = permit;
                let peer_hex_for_wal = peer_hex.clone();
                if let Err(e) = handle_peeroxide_connection(
                    conn,
                    cluster,
                    own_id,
                    reg,
                    wal.clone(),
                    ckey,
                    own_noise_pk,
                    streams,
                    autonomy,
                    home,
                    dtx,
                )
                .await
                {
                    warn!(
                        peer = %peer_hex,
                        error = %e,
                        "hyperswarm: peer session ended with error"
                    );
                    // 0xE1 with reason=error if we never made it through handshake
                    // is also recorded inside the handler; this branch covers
                    // late-failure paths.
                    emit_peer_disconnected_wal(
                        wal.as_deref(),
                        &peer_hex_for_wal,
                        "error",
                        Some(&e.to_string()),
                    );
                } else {
                    debug!(peer = %peer_hex, "hyperswarm: peer session ended cleanly");
                }
            });
        }
        warn!("hyperswarm: connection receiver closed — discovery loop exiting");
    });

    // SL-00(1b) review fix: announce on the DHT ONLY AFTER the accept loop is
    // live. The loop blocks on an empty `conn_rx` until peers actually connect,
    // so spawning it first costs nothing and closes the window where the node
    // was visible on the public DHT before the auth guardian was polling.
    handle
        .join(topic, peeroxide::JoinOpts::default())
        .await
        .with_context(|| format!("peeroxide join topic for cluster `{cluster_name}`"))?;

    info!(
        cluster = cluster_name,
        topic_hex = %hex_encode(&topic),
        "hyperswarm: announced + listening on topic"
    );

    Ok(SwarmHandle {
        peer_handle: Some(handle),
        topic,
        swarm_task: Some(swarm_task),
        accept_task: Some(accept_task),
    })
}

/// Derive a stable per-process peer id. UUID v7 (when
/// `uuid::Uuid::now_v7` is reachable) carries a unix-ms
/// timestamp so audit consumers see roughly when each peer
/// came up.
fn local_peer_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Drive one peer connection end-to-end against peeroxide's
/// SecretStream: handshake (`Hello` round-trip + validate) +
/// inbound-frame loop until clean close.
///
/// SecretStream is message-framed by Noise (each `write` is
/// one ciphertext, each `read` returns the next plaintext or
/// `None` on EOF), so this function bypasses the
/// length-prefix layer in [`super::heartbeat::write_framed`] +
/// [`read_framed`] — those exist for the `tokio::io::duplex`
/// test path and any future non-Noise transport.
#[allow(clippy::too_many_arguments)]
async fn handle_peeroxide_connection(
    mut conn: peeroxide::SwarmConnection,
    cluster_name: String,
    own_peer_id: String,
    registry: Arc<Mutex<PeerLoadRegistry>>,
    wal_writer: ClusterWalWriter,
    // SL-00(1b): the shared cluster_key (Some on the activated transport path,
    // None on the legacy/no-auth path) + our own Noise static pubkey, used to
    // prove + verify cluster membership in the Hello exchange.
    cluster_key: Option<Arc<ClusterKey>>,
    own_noise_pk: [u8; 32],
    // SL-00(1c): registry of outbound channels so other subsystems can send
    // directed frames to this peer; the session loop drains its receiver.
    peer_streams: Arc<PeerStreamRegistry>,
    // SL-01: the 3-checkpoint accept-gate inputs. `autonomy` is the node's
    // level; `neoth_home` locates cluster.yaml (pairing) + leases.json;
    // `dispatch_tx` hands an accepted task to the executor (None ⇒ no executor,
    // e.g. no-provider / CLI one-shot — a delegate then gets a "no_provider"
    // rejection).
    autonomy: AutonomyLevel,
    neoth_home: std::path::PathBuf,
    dispatch_tx: Option<tokio::sync::mpsc::Sender<ClusterTaskJob>>,
) -> Result<()> {
    let remote_pk_hex = hex_encode(conn.remote_public_key());
    // Peer's Noise static key from the authenticated channel — the identity
    // the cluster_key proof binds to (NOT anything from the frame payload).
    let peer_noise_pk: [u8; 32] = *conn.remote_public_key();
    let stream = &mut conn.peer.stream;

    // SL-02b: start the handshake round-trip clock — the elapsed time from our
    // Hello write to the peer's validated Hello is recorded as this peer's RTT.
    let handshake_start = tokio::time::Instant::now();

    // ── Step 1: send our Hello ──
    let our_hello = WireFrame {
        kind: FrameKind::Hello,
        sequence: 0,
        sent_unix_ms: now_unix_ms(),
        peer_id: own_peer_id.clone(),
        body: FrameBody::Hello(HelloBody {
            protocol: PROTOCOL_NAME.to_string(),
            version: PROTOCOL_VERSION,
            cluster_name_hash: derive_topic(&cluster_name),
            // Capabilities discovery from the daemon's bound
            // providers lands in a follow-up; today the
            // operator-visible information is "this peer is up
            // + reachable + speaks our protocol", which is what
            // the LeastLoaded routing needs to start emitting
            // PeerLoad rows.
            capabilities: Vec::new(),
            capabilities_schema_version: 1,
            // SL-00(1b): prove we hold the shared cluster_key. signer = us,
            // verifier = the peer (the peer recomputes proof(us, them)).
            cluster_key_proof: cluster_key
                .as_ref()
                .map(|k| compute_cluster_key_proof(k, &own_noise_pk, &peer_noise_pk)),
        }),
    };
    let our_hello_bytes = heartbeat::encode_frame(&our_hello).context("encode our Hello")?;
    // SL-00(1b): bound the Hello write — a peer that accepts the connection but
    // stalls the read side must not pin this task indefinitely.
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.write(&our_hello_bytes)).await {
        Ok(r) => r.context("write Hello to peer")?,
        Err(_) => {
            emit_peer_rejected_wal(
                wal_writer.as_deref(),
                "(unknown)",
                "timed out writing Hello",
            );
            anyhow::bail!("timed out writing Hello to peer after {HANDSHAKE_TIMEOUT:?}");
        }
    };

    // ── Step 2: read peer's Hello ──
    // SL-00(1b): bound the Hello read — the primary DoS guard. A peer that
    // connects but never sends a Hello is dropped after HANDSHAKE_TIMEOUT
    // instead of holding a session slot forever.
    let peer_read = match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read()).await {
        Ok(r) => r,
        Err(_) => {
            emit_peer_rejected_wal(
                wal_writer.as_deref(),
                "(unknown)",
                "timed out waiting for peer Hello",
            );
            anyhow::bail!("timed out waiting for peer Hello after {HANDSHAKE_TIMEOUT:?}");
        }
    };
    let peer_bytes = match peer_read {
        Ok(Some(b)) => b,
        Ok(None) => {
            emit_peer_rejected_wal(
                wal_writer.as_deref(),
                "(unknown)",
                "peer closed before sending Hello",
            );
            anyhow::bail!("peer closed before sending Hello");
        }
        Err(e) => {
            emit_peer_rejected_wal(
                wal_writer.as_deref(),
                "(unknown)",
                &format!("read peer Hello: {e}"),
            );
            return Err(anyhow::anyhow!("read peer Hello: {e}"));
        }
    };
    let peer_frame = match heartbeat::decode_frame(&peer_bytes) {
        Ok(f) => f,
        Err(e) => {
            emit_peer_rejected_wal(
                wal_writer.as_deref(),
                "(unknown)",
                &format!("decode peer Hello: {e}"),
            );
            return Err(e).context("decode peer Hello");
        }
    };
    if peer_frame.kind != FrameKind::Hello {
        emit_peer_rejected_wal(
            wal_writer.as_deref(),
            &peer_frame.peer_id,
            &format!("peer first frame was {:?}, expected Hello", peer_frame.kind),
        );
        anyhow::bail!("peer first frame was {:?}, expected Hello", peer_frame.kind);
    }
    let peer_id = peer_frame.peer_id.clone();
    let mut peer_capabilities: Vec<String> = match peer_frame.body {
        FrameBody::Hello(ref body) => {
            if let Err(e) = heartbeat::validate_hello(body) {
                emit_peer_rejected_wal(
                    wal_writer.as_deref(),
                    &peer_id,
                    &format!("validate peer Hello: {e}"),
                );
                return Err(e).context("validate peer Hello");
            }
            let expected_hash = derive_topic(&cluster_name);
            if body.cluster_name_hash != expected_hash {
                emit_peer_rejected_wal(
                    wal_writer.as_deref(),
                    &peer_id,
                    &format!("cluster_name_hash mismatch for local cluster `{cluster_name}`"),
                );
                anyhow::bail!(
                    "peer cluster_name_hash does not match local cluster `{cluster_name}`"
                );
            }
            // SL-00(1b): the cluster_name_hash is PUBLIC — it only proves the
            // peer knows the cluster's name. The cluster_key proof below is
            // what proves shared-secret possession. Fail-closed: when we hold
            // a cluster_key (the activated path always does), a missing OR
            // mismatched proof is a hard rejection. `peer_pk` is the peer's
            // Noise static key from the authenticated channel (never the
            // payload); we recompute proof(peer_pk, own_pk) and constant-time
            // compare.
            if let Some(ref ckey) = cluster_key {
                match body.cluster_key_proof {
                    Some(ref claimed) => {
                        if !verify_peer_proof(ckey, claimed, &peer_noise_pk, &own_noise_pk) {
                            emit_peer_rejected_wal(
                                wal_writer.as_deref(),
                                &peer_id,
                                "cluster_key_proof mismatch — peer not a cluster member",
                            );
                            anyhow::bail!("peer cluster_key_proof invalid — unauthorized");
                        }
                    }
                    None => {
                        emit_peer_rejected_wal(
                            wal_writer.as_deref(),
                            &peer_id,
                            "missing cluster_key_proof — peer unauthorized",
                        );
                        anyhow::bail!("peer Hello missing cluster_key_proof — unauthorized");
                    }
                }
            }
            body.capabilities.clone()
        }
        _ => {
            emit_peer_rejected_wal(
                wal_writer.as_deref(),
                &peer_id,
                "peer Hello frame body shape mismatch",
            );
            anyhow::bail!("peer Hello frame body shape mismatch");
        }
    };

    info!(
        peer_id = %peer_id,
        capability_count = peer_capabilities.len(),
        "hyperswarm: handshake complete"
    );
    emit_peer_connected_wal(
        wal_writer.as_deref(),
        &peer_id,
        &remote_pk_hex,
        &cluster_name,
    );

    // SL-02b: record the handshake RTT + bump this peer's stability (a
    // successful connection is a stability hit). Best-effort, once per
    // connection — NOT per heartbeat (a per-heartbeat cluster.yaml write would
    // be heavy I/O). No-op for an unpaired peer; surfaces in
    // `neoth cluster topology`. Per-heartbeat fidelity + a miss-on-disconnect
    // signal are a throttled-write follow-on slice.
    let handshake_rtt_ms = handshake_start.elapsed().as_millis() as u64;
    // COR-16/A-43: best-effort, but a write failure (disk full, perms,
    // serde) must not vanish — log it so a peer's RTT/stability silently
    // freezing in `neoth cluster topology` is diagnosable.
    if let Err(e) = crate::cluster::registry::refresh_rtt(&neoth_home, &remote_pk_hex, handshake_rtt_ms)
    {
        tracing::warn!(error = %e, peer = %remote_pk_hex, "cluster registry refresh_rtt failed (non-fatal)");
    }
    if let Err(e) = crate::cluster::registry::refresh_stability(&neoth_home, &remote_pk_hex, true) {
        tracing::warn!(error = %e, peer = %remote_pk_hex, "cluster registry refresh_stability failed (non-fatal)");
    }

    // ── Step 3: bidirectional session loop (SL-00(1c)) ──
    //
    // CANCEL-SAFETY (critical): peeroxide's `SecretStream::read()` uses
    // `read_exact` into local buffers, so it is NOT cancel-safe — cancelling a
    // partially-completed read (the trap with `select!`/`timeout` on the read
    // arm) would consume bytes off the wire and desync the Noise frame stream,
    // corrupting the connection. So we NEVER cancel a read.
    //
    // Instead the loop is read-to-completion: we drain pending OUTBOUND frames
    // and send our heartbeat (when due) BETWEEN reads, then block on exactly
    // one inbound read. The protocol has BOTH peers heartbeating every ~5s, so
    // a read returns at least that often, giving us a regular window to write;
    // a genuinely dead peer makes `read()` return `Err` via the udx RTO-timeout
    // failure, so we still detect death without a cancellable timeout.
    let mut seen_first_heartbeat = false;
    let mut last_healthy: Option<bool> = None;
    let mut last_capabilities_hash: Option<[u8; 32]> = None;

    // SL-01b: per-connection gossip anti-entropy state (dedup keyed by origin +
    // VC convergence for THIS peer). Node-global merge across peers is a
    // follow-on with persistence; per-connection is correct for dedup since a
    // connection is to one peer. Policy default = privacy-safe (raw-ingress off,
    // 30d budget); a `freedom.yaml::cluster.gossip` override is a follow-on.
    let mut gossip_state = GossipState::new();
    let gossip_policy = GossipPolicy::default();

    // SL-00(1c): register this peer's outbound channel; the Drop guard removes
    // it on EVERY exit path (clean disconnect, error, supersede).
    let mut outbound_rx = peer_streams.register(&remote_pk_hex);
    struct UnregisterGuard {
        reg: Arc<PeerStreamRegistry>,
        key: String,
    }
    impl Drop for UnregisterGuard {
        fn drop(&mut self) {
            self.reg.unregister(&self.key);
        }
    }
    let _unreg = UnregisterGuard {
        reg: Arc::clone(&peer_streams),
        key: remote_pk_hex.clone(),
    };

    // Outbound heartbeat: our advertised capabilities mirror the Hello (empty
    // for now — capability discovery from bound providers is a follow-up).
    let local_capabilities: Vec<String> = Vec::new();
    let mut out_seq: u64 = 1; // Hello was sequence 0
    let mut sent_first_heartbeat = false;
    let mut outbound_alive = true;
    // StdRng (not ThreadRng) — this future is `tokio::spawn`ed, so the RNG held
    // across awaits must be `Send`.
    let mut hb_rng = {
        use rand::SeedableRng;
        rand::rngs::StdRng::from_os_rng()
    };
    let mut hb_interval = heartbeat::next_jittered_interval(&mut hb_rng);
    let mut last_heartbeat = tokio::time::Instant::now();

    loop {
        // ── (a) Send our heartbeat — once immediately, then every interval.
        // Driven here (between reads) rather than from a cancellable timer so a
        // read is never interrupted. Pacing is bounded by the peer's own
        // heartbeat cadence, which is the same ~5s.
        if !sent_first_heartbeat || last_heartbeat.elapsed() >= hb_interval {
            let hb = WireFrame {
                kind: FrameKind::Heartbeat,
                sequence: out_seq,
                sent_unix_ms: now_unix_ms(),
                peer_id: own_peer_id.clone(),
                body: FrameBody::Heartbeat(local_load::local_load_snapshot(&local_capabilities)),
            };
            out_seq = out_seq.wrapping_add(1);
            match heartbeat::encode_frame(&hb) {
                Ok(b) => {
                    if let Err(e) = stream.write(&b).await {
                        emit_peer_disconnected_wal(
                            wal_writer.as_deref(),
                            &peer_id,
                            "error",
                            Some(&e.to_string()),
                        );
                        return Err(anyhow::anyhow!("write heartbeat: {e}"));
                    }
                    if !sent_first_heartbeat {
                        sent_first_heartbeat = true;
                        if let FrameBody::Heartbeat(ref body) = hb.body {
                            emit_heartbeat_sent_wal(wal_writer.as_deref(), &peer_id, body);
                        }
                    }
                }
                // Encode failure is a local bug, not a peer fault — skip this
                // tick rather than tearing down the connection.
                Err(e) => {
                    warn!(peer_id = %peer_id, error = %e, "encode heartbeat failed; skipping tick")
                }
            }
            last_heartbeat = tokio::time::Instant::now();
            hb_interval = heartbeat::next_jittered_interval(&mut hb_rng);
        }

        // ── (b) Drain any queued OUTBOUND frames (non-blocking). Directed
        // task/gossip frames (SL-01/SL-01b) ride this path; they are delivered
        // on the next loop turn, bounded by the read cadence above.
        while outbound_alive {
            match outbound_rx.try_recv() {
                Ok(frame) => match heartbeat::encode_frame(&frame) {
                    Ok(b) => {
                        if let Err(e) = stream.write(&b).await {
                            emit_peer_disconnected_wal(
                                wal_writer.as_deref(),
                                &peer_id,
                                "error",
                                Some(&e.to_string()),
                            );
                            return Err(anyhow::anyhow!("write outbound frame: {e}"));
                        }
                    }
                    Err(e) => {
                        warn!(peer_id = %peer_id, error = %e, "encode outbound frame failed; dropping")
                    }
                },
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                // Sender dropped (peer reconnected → this session superseded).
                // Stop draining; keep serving inbound until the read closes.
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    outbound_alive = false;
                    break;
                }
            }
        }

        // ── (c) Read exactly ONE inbound frame to completion (never cancelled).
        let bytes = match stream.read().await {
            Ok(Some(b)) => b,
            Ok(None) => {
                info!(peer_id = %peer_id, "hyperswarm: peer disconnected cleanly");
                emit_peer_disconnected_wal(wal_writer.as_deref(), &peer_id, "eof", None);
                return Ok(());
            }
            Err(e) => {
                emit_peer_disconnected_wal(
                    wal_writer.as_deref(),
                    &peer_id,
                    "error",
                    Some(&e.to_string()),
                );
                return Err(anyhow::anyhow!("read peer frame: {e}"));
            }
        };
        let frame = match heartbeat::decode_frame(&bytes) {
            Ok(f) => f,
            Err(e) => {
                emit_peer_disconnected_wal(
                    wal_writer.as_deref(),
                    &peer_id,
                    "error",
                    Some(&e.to_string()),
                );
                return Err(e).context("decode peer frame");
            }
        };

        // ── SL-01: intercept task frames BEFORE the sync handler (which has no
        // provider / lease / autonomy access). TaskDelegate runs the accept
        // gate + dispatches to the executor; TaskResult (we were the master) is
        // audited. Both `continue` — they never reach handle_inbound_frame.
        if frame.kind == FrameKind::TaskDelegate {
            if let FrameBody::TaskDelegate(delegate) = frame.body {
                handle_task_delegate(
                    delegate,
                    &remote_pk_hex,
                    &own_peer_id,
                    autonomy,
                    &neoth_home,
                    wal_writer.clone(),
                    &peer_streams,
                    dispatch_tx.as_ref(),
                )
                .await;
            }
            continue;
        }
        if frame.kind == FrameKind::TaskResult {
            if let FrameBody::TaskResult(r) = &frame.body {
                // Master-side: we delegated a task and got a reply. Full
                // correlation (task_id → pending request) is the SL-01-master
                // follow-up; today we audit-log receipt.
                info!(
                    peer_id = %peer_id,
                    task_id = %r.task_id,
                    "cluster: received TaskResult from peer"
                );
            }
            continue;
        }
        // SL-01b: inbound WAL gossip. Run the receive ACL (tag/budget/dedup +
        // a band re-check on the payload's OWN event_type, byte 2 of the inner
        // WAL header — extracted WITHOUT HMAC validation since it is a foreign
        // node's frame), audit accept/drop, then DROP the payload (applying it
        // into local memory is the deferred foreign-event-store slice).
        if frame.kind == FrameKind::Gossip {
            if let FrameBody::Gossip(gframe) = frame.body {
                let payload_et = gframe.payload.get(2).copied();
                let now = now_unix_secs() as i64;
                match gossip_state.accept_inbound(&gframe, payload_et, &gossip_policy, now) {
                    GossipAcceptance::Accept => {
                        emit_gossip_received_wal(wal_writer.as_deref(), &gframe, payload_et);
                    }
                    dropped => {
                        emit_gossip_dropped_wal(wal_writer.as_deref(), &gframe, &dropped);
                    }
                }
            }
            continue;
        }

        let kind = frame.kind;
        let body_clone = frame.body.clone();
        match handle_inbound_frame(frame, &peer_id, &mut peer_capabilities, &registry) {
            Ok(true) => {
                // Audit-anchor the heartbeat-band events.
                if kind == FrameKind::Heartbeat {
                    if let FrameBody::Heartbeat(b) = body_clone {
                        if !seen_first_heartbeat {
                            seen_first_heartbeat = true;
                            emit_heartbeat_first_wal(wal_writer.as_deref(), &peer_id, &b);
                        }
                        if let Some(prev) = last_healthy {
                            if prev != b.healthy {
                                emit_peer_health_changed_wal(
                                    wal_writer.as_deref(),
                                    &peer_id,
                                    prev,
                                    b.healthy,
                                    b.tokens_per_sec,
                                );
                            }
                        }
                        last_healthy = Some(b.healthy);

                        if let Some(prev_hash) = last_capabilities_hash {
                            if prev_hash != b.capabilities_hash {
                                emit_capabilities_changed_wal(
                                    wal_writer.as_deref(),
                                    &peer_id,
                                    &peer_capabilities,
                                );
                            }
                        }
                        last_capabilities_hash = Some(b.capabilities_hash);
                    }
                } else if kind == FrameKind::CapabilityUpdate {
                    emit_capabilities_changed_wal(wal_writer.as_deref(), &peer_id, &peer_capabilities);
                }
            }
            Ok(false) => {
                // Goodbye path — kind is Goodbye by elimination
                emit_peer_disconnected_wal(wal_writer.as_deref(), &peer_id, "goodbye", None);
                return Ok(());
            }
            Err(e) => {
                emit_peer_disconnected_wal(
                    wal_writer.as_deref(),
                    &peer_id,
                    "error",
                    Some(&e.to_string()),
                );
                return Err(e);
            }
        }
    }
}

// ── WAL emit helpers — best-effort, never bubble up ──────────────

fn emit_peer_connected_wal(
    writer: Option<&WalWriterHandle>,
    peer_id: &str,
    remote_pk_hex: &str,
    cluster: &str,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "peer_id": peer_id,
        "remote_public_key_hex": remote_pk_hex,
        "cluster": cluster,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_PEER_CONNECTED,
        payload,
    );
}

fn emit_peer_disconnected_wal(
    writer: Option<&WalWriterHandle>,
    peer_id: &str,
    reason: &str,
    error: Option<&str>,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "peer_id": peer_id,
        "reason": reason,
        "error": error.map(crate::security::redact::redact_text),
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_PEER_DISCONNECTED,
        payload,
    );
}

fn emit_peer_rejected_wal(writer: Option<&WalWriterHandle>, peer_id_claim: &str, reason: &str) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "peer_id_claim": peer_id_claim,
        "reason": crate::security::redact::redact_text(reason),
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_PEER_REJECTED,
        payload,
    );
}

fn emit_heartbeat_first_wal(writer: Option<&WalWriterHandle>, peer_id: &str, body: &HeartbeatBody) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "peer_id": peer_id,
        "tokens_per_sec": body.tokens_per_sec,
        "healthy": body.healthy,
        "inflight_requests": body.inflight_requests,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_HEARTBEAT_FIRST,
        payload,
    );
}

/// SL-00(1c): emitted once per connection when we send our FIRST outbound
/// heartbeat — the send-side mirror of `emit_heartbeat_first_wal`. Anchors the
/// bidirectional transport in the audit chain without per-tick WAL noise.
fn emit_heartbeat_sent_wal(writer: Option<&WalWriterHandle>, peer_id: &str, body: &HeartbeatBody) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "peer_id": peer_id,
        "tokens_per_sec": body.tokens_per_sec,
        "inflight_requests": body.inflight_requests,
        "healthy": body.healthy,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(w, crate::wal::events::EVENT_TYPE_CLUSTER_HEARTBEAT_SENT, payload);
}

fn emit_peer_health_changed_wal(
    writer: Option<&WalWriterHandle>,
    peer_id: &str,
    from_healthy: bool,
    to_healthy: bool,
    last_tps: f64,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "peer_id": peer_id,
        "from_healthy": from_healthy,
        "to_healthy": to_healthy,
        "last_tps": last_tps,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_PEER_HEALTH_CHANGED,
        payload,
    );
}

fn emit_capabilities_changed_wal(
    writer: Option<&WalWriterHandle>,
    peer_id: &str,
    capabilities: &[String],
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "peer_id": peer_id,
        "capabilities": capabilities,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_CAPABILITIES_CHANGED,
        payload,
    );
}

fn fire_wal(writer: &WalWriterHandle, event_type: u8, payload: Vec<u8>) {
    let header = crate::wal::make_header(event_type, &payload);
    if let Err(e) = writer.try_append_sync(header, payload) {
        warn!(
            event_type = format!("0x{event_type:02X}"),
            error = %e,
            "hyperswarm: WAL emit failed (best-effort)"
        );
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── SL-01 task-delegation accept gate + handler ────────────────────────────

/// Outcome of the 3-checkpoint accept gate. `Accept{lease_backed}` records
/// whether a lease (vs an Allow-level autonomy) authorized it, for the audit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TaskGateOutcome {
    Accept { lease_backed: bool },
    Reject(&'static str),
}

/// The pure accept-gate decision (SL-01). Mirrors the shipped capability-lease
/// semantics ([[neoth_session32_burndown]]): a lease upgrades a `Confirm` to
/// `Allow` but NEVER overrides a `Deny`. `is_paired` is a hard pre-checkpoint.
///
/// - not paired ⇒ Reject("not_paired")
/// - autonomy `Deny` (Strict) ⇒ Reject("autonomy_deny") regardless of lease
/// - autonomy `Confirm` (Standard) ⇒ Accept iff an active lease, else
///   Reject("no_active_lease") — the lease is the operator's standing grant
/// - autonomy `Allow` (Elevated/Full) ⇒ Accept (is_paired is the per-peer gate
///   here; no lease required once the operator opted into that autonomy level)
fn cluster_task_gate(is_paired: bool, decision: &Decision, lease_active: bool) -> TaskGateOutcome {
    if !is_paired {
        return TaskGateOutcome::Reject("not_paired");
    }
    match decision {
        Decision::Allow => TaskGateOutcome::Accept { lease_backed: lease_active },
        Decision::Confirm(_) => {
            if lease_active {
                TaskGateOutcome::Accept { lease_backed: true }
            } else {
                TaskGateOutcome::Reject("no_active_lease")
            }
        }
        Decision::Deny(_) => TaskGateOutcome::Reject("autonomy_deny"),
    }
}

/// Handle an inbound `TaskDelegate` frame: validate → run the 3-checkpoint gate
/// → on accept dispatch to the executor (WAL 0xEB) → on reject reply a
/// `TaskResult{Rejected}` (WAL 0xEC). Best-effort: never returns Err (a bad
/// task is not a transport error). `remote_pk_hex` is the AUTHENTICATED Noise
/// key — the only identity the gate trusts.
#[allow(clippy::too_many_arguments)]
async fn handle_task_delegate(
    body: TaskDelegateBody,
    remote_pk_hex: &str,
    own_peer_id: &str,
    autonomy: AutonomyLevel,
    neoth_home: &std::path::Path,
    wal_writer: ClusterWalWriter,
    peer_streams: &PeerStreamRegistry,
    dispatch_tx: Option<&tokio::sync::mpsc::Sender<ClusterTaskJob>>,
) {
    let task_id = body.task_id.clone();

    // Pre-checkpoint: validate the frame BEFORE spending gate work. A malformed
    // frame is rejected even from an unpaired peer.
    if let Err(e) = heartbeat::validate_task_delegate(&body) {
        debug!(error = %e, "cluster: rejecting malformed TaskDelegate");
        reply_task_rejected(peer_streams, remote_pk_hex, own_peer_id, &task_id, "malformed");
        emit_task_rejected_wal(wal_writer.as_deref(), &task_id, remote_pk_hex, "malformed");
        return;
    }

    // Checkpoint 3 (pure, zero-cost) FIRST so a flood of frames can't force
    // disk I/O on a guaranteed-Deny path (review DoS finding). Strict ⇒ Deny ⇒
    // reject without touching the registry or lease store.
    let decision = permissions::evaluate(&Action::ClusterTaskAccept, autonomy);
    if matches!(decision, Decision::Deny(_)) {
        reply_task_rejected(peer_streams, remote_pk_hex, own_peer_id, &task_id, "autonomy_deny");
        emit_task_rejected_wal(wal_writer.as_deref(), &task_id, remote_pk_hex, "autonomy_deny");
        return;
    }

    // Checkpoint 1: the peer is operator-paired (registry membership of the
    // AUTHENTICATED Noise key, never a payload field). One disk read.
    let is_paired = crate::cluster::registry::is_paired(neoth_home, remote_pk_hex);

    // Checkpoint 2: a fresh lease read — but ONLY when it can change the
    // outcome (a `Confirm` level, i.e. Standard). At an `Allow` level
    // (Elevated/Full) the lease is not required, so skip the I/O. Fresh load is
    // cross-process correct (a CLI `neoth lease grant` must be visible) + runs
    // off the runtime thread.
    let lease_active = if is_paired && matches!(decision, Decision::Confirm(_)) {
        check_cluster_lease(neoth_home, remote_pk_hex).await
    } else {
        false
    };

    match cluster_task_gate(is_paired, &decision, lease_active) {
        TaskGateOutcome::Reject(reason) => {
            reply_task_rejected(peer_streams, remote_pk_hex, own_peer_id, &task_id, reason);
            emit_task_rejected_wal(wal_writer.as_deref(), &task_id, remote_pk_hex, reason);
        }
        TaskGateOutcome::Accept { lease_backed } => {
            // Dispatch off-loop to the executor. Bounded channel ⇒ a busy
            // executor (one inference already running) means try_send fails and
            // we reply busy rather than queueing unboundedly.
            let job = ClusterTaskJob {
                task_id: task_id.clone(),
                prompt: body.prompt,
                reply_peer_pk: remote_pk_hex.to_string(),
                wal_writer: wal_writer.clone(),
            };
            match dispatch_tx {
                Some(tx) => match tx.try_send(job) {
                    Ok(()) => {
                        emit_task_accepted_wal(
                            wal_writer.as_deref(),
                            &task_id,
                            remote_pk_hex,
                            lease_backed,
                            autonomy,
                        );
                    }
                    // Full ⇒ an inference is already running (bounded(1)) — back
                    // off. Closed ⇒ the executor task died (panic) — surface it
                    // as a DISTINCT, operator-visible reason rather than hiding
                    // a dead executor behind "busy" (review finding).
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        reply_task_rejected(peer_streams, remote_pk_hex, own_peer_id, &task_id, "busy");
                        emit_task_rejected_wal(wal_writer.as_deref(), &task_id, remote_pk_hex, "busy");
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        error!(task_id = %task_id, "cluster executor channel closed — executor task is gone");
                        reply_task_rejected(
                            peer_streams,
                            remote_pk_hex,
                            own_peer_id,
                            &task_id,
                            "executor_dead",
                        );
                        emit_task_rejected_wal(
                            wal_writer.as_deref(),
                            &task_id,
                            remote_pk_hex,
                            "executor_dead",
                        );
                    }
                },
                None => {
                    // No executor wired (no provider / CLI one-shot path).
                    reply_task_rejected(
                        peer_streams,
                        remote_pk_hex,
                        own_peer_id,
                        &task_id,
                        "no_provider",
                    );
                    emit_task_rejected_wal(
                        wal_writer.as_deref(),
                        &task_id,
                        remote_pk_hex,
                        "no_provider",
                    );
                }
            }
        }
    }
}

/// Fresh, off-thread lease check for `ClusterTaskAccept` on `subject`.
/// Fail-closed: any load error ⇒ no lease.
async fn check_cluster_lease(neoth_home: &std::path::Path, subject: &str) -> bool {
    let path = crate::permissions::lease::LeaseStore::default_path(neoth_home);
    let subject = subject.to_string();
    let now = now_unix_secs() as i64;
    tokio::task::spawn_blocking(move || {
        match crate::permissions::lease::LeaseStore::load(&path) {
            Ok(store) => store.active_for(
                &subject,
                &crate::permissions::lease::LeaseScope::ClusterTaskAccept,
                now,
            ),
            Err(_) => false,
        }
    })
    .await
    .unwrap_or(false)
}

/// Queue a `TaskResult{Rejected}` reply via the peer's outbound channel.
fn reply_task_rejected(
    peer_streams: &PeerStreamRegistry,
    remote_pk_hex: &str,
    own_peer_id: &str,
    task_id: &str,
    reason: &str,
) {
    let frame = WireFrame {
        kind: FrameKind::TaskResult,
        sequence: 0,
        sent_unix_ms: now_unix_ms(),
        peer_id: own_peer_id.to_string(),
        body: FrameBody::TaskResult(TaskResultBody {
            task_id: task_id.to_string(),
            status: TaskResultStatus::Rejected {
                reason: reason.to_string(),
            },
            result: None,
            provider_name: None,
        }),
    };
    if let Err(e) = peer_streams.send_to(remote_pk_hex, frame) {
        debug!(error = %e, task_id, "cluster: could not deliver rejection (peer gone)");
    }
}

fn emit_task_accepted_wal(
    writer: Option<&WalWriterHandle>,
    task_id: &str,
    peer_pk_hex: &str,
    lease_backed: bool,
    autonomy: AutonomyLevel,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "task_id": task_id,
        "peer_pubkey": peer_pk_hex,
        "lease_backed": lease_backed,
        "autonomy": format!("{autonomy:?}"),
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(w, crate::wal::events::EVENT_TYPE_CLUSTER_TASK_ACCEPTED, payload);
}

fn emit_task_rejected_wal(
    writer: Option<&WalWriterHandle>,
    task_id: &str,
    peer_pk_hex: &str,
    reason: &str,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "task_id": task_id,
        "peer_pubkey": peer_pk_hex,
        "reason": reason,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(w, crate::wal::events::EVENT_TYPE_CLUSTER_TASK_REJECTED, payload);
}

/// SL-01b: an inbound gossip frame was ACCEPTED (the receive ACL passed). The
/// payload is NOT applied to local memory (deferred) — this records that the
/// node learned of the peer's event + converged its VC.
fn emit_gossip_received_wal(
    writer: Option<&WalWriterHandle>,
    frame: &super::gossip_wire::GossipFrame,
    payload_event_type: Option<u8>,
) {
    let Some(w) = writer else { return };
    let payload = serde_json::json!({
        "origin_peer": frame.origin.as_str(),
        "event_seq": frame.event_seq,
        "payload_event_type": payload_event_type,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(w, crate::wal::events::EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED, payload);
}

/// SL-01b: an inbound gossip frame was DROPPED, with the reason discriminant.
fn emit_gossip_dropped_wal(
    writer: Option<&WalWriterHandle>,
    frame: &super::gossip_wire::GossipFrame,
    verdict: &GossipAcceptance,
) {
    let Some(w) = writer else { return };
    let reason = match verdict {
        GossipAcceptance::Accept => "accepted", // not reached on this path
        GossipAcceptance::DroppedDoNotGossipTag => "do_not_gossip",
        GossipAcceptance::DroppedOutsideReplayBudget => "outside_replay_budget",
        GossipAcceptance::DroppedDuplicate { .. } => "duplicate",
    };
    let payload = serde_json::json!({
        "origin_peer": frame.origin.as_str(),
        "event_seq": frame.event_seq,
        "reason": reason,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(w, crate::wal::events::EVENT_TYPE_CLUSTER_GOSSIP_DROPPED, payload);
}

// ── Connection-loop primitives (testable against tokio::io::duplex) ────────
//
// Per-connection lifecycle:
//   1. our_hello frame → peer
//   2. read peer's hello, validate (protocol, version, cluster hash)
//   3. spawn reader loop: read_framed → handle_frame → record_heartbeat
//   4. (sender loop with jittered ticker lands when the daemon ships
//      an internal token-rate meter; today the receive half alone gives
//      the cluster meaningful peer-discovery + health observability)

/// Send our Hello over a fresh peer connection. Pure send +
/// flush; caller pairs with [`receive_hello`].
pub(crate) async fn send_hello<W: AsyncWrite + Unpin>(
    sink: &mut W,
    peer_id: &str,
    cluster_name: &str,
    capabilities: Vec<String>,
) -> Result<()> {
    let frame = WireFrame {
        kind: FrameKind::Hello,
        sequence: 0,
        sent_unix_ms: now_unix_ms(),
        peer_id: peer_id.to_string(),
        body: FrameBody::Hello(HelloBody {
            protocol: PROTOCOL_NAME.to_string(),
            version: PROTOCOL_VERSION,
            cluster_name_hash: derive_topic(cluster_name),
            capabilities,
            capabilities_schema_version: 1,
            // send_hello is a test/helper path (not the authenticated main
            // handshake); it carries no cluster_key proof.
            cluster_key_proof: None,
        }),
    };
    heartbeat::write_framed(sink, &frame)
        .await
        .context("write our Hello frame")?;
    sink.flush().await.context("flush our Hello")?;
    Ok(())
}

/// Read the peer's Hello frame + validate. Returns the
/// HelloBody so the caller learns peer capabilities up front.
/// Bails when the frame's first message isn't Hello, when
/// protocol/version mismatch, or when the cluster hash
/// doesn't match ours.
///
/// `pub(crate)` ON PURPOSE (SL-00(1b) review): this is a `tokio::io::duplex`
/// test primitive that does NOT verify the `cluster_key_proof`. The production
/// handshake runs through `handle_peeroxide_connection`, which is fail-closed
/// on the proof. Keeping this crate-private prevents a future caller from
/// standing up an unauthenticated Hello exchange.
pub(crate) async fn receive_hello<R: AsyncRead + Unpin>(
    source: &mut R,
    expected_cluster_name: &str,
) -> Result<(String, HelloBody)> {
    let frame = heartbeat::read_framed(source)
        .await
        .context("read peer Hello frame")?;
    if frame.kind != FrameKind::Hello {
        anyhow::bail!("peer first frame was {:?}, expected Hello", frame.kind);
    }
    let FrameBody::Hello(body) = frame.body else {
        anyhow::bail!("peer Hello kind/body mismatch — frame.body is not Hello");
    };
    heartbeat::validate_hello(&body).context("validate peer Hello")?;
    let expected_hash = derive_topic(expected_cluster_name);
    if body.cluster_name_hash != expected_hash {
        anyhow::bail!(
            "peer cluster_name_hash does not match local cluster `{expected_cluster_name}`"
        );
    }
    Ok((frame.peer_id, body))
}

/// Handle one inbound frame from a peer. Heartbeats record
/// into the registry; CapabilityUpdate refreshes the cached
/// capability list per peer; Goodbye prunes the peer
/// immediately. Returns true when the caller's read loop
/// should keep going, false when the peer signalled exit.
pub fn handle_inbound_frame(
    frame: WireFrame,
    peer_id_expected: &str,
    capabilities: &mut Vec<String>,
    registry: &Arc<Mutex<PeerLoadRegistry>>,
) -> Result<bool> {
    if frame.peer_id != peer_id_expected {
        anyhow::bail!(
            "frame peer_id {:?} does not match handshake peer_id {peer_id_expected:?}",
            frame.peer_id
        );
    }
    match frame.body {
        FrameBody::Hello(_) => {
            anyhow::bail!("duplicate Hello after handshake");
        }
        FrameBody::Heartbeat(body) => {
            heartbeat::validate_heartbeat(&body).context("validate incoming heartbeat")?;
            record_heartbeat_into_registry(peer_id_expected, &body, registry);
            Ok(true)
        }
        FrameBody::CapabilityUpdate(body) => {
            heartbeat::validate_capabilities(&body)
                .context("validate incoming capability update")?;
            *capabilities = body.capabilities;
            debug!(
                peer_id = peer_id_expected,
                count = capabilities.len(),
                "hyperswarm: peer capability list updated"
            );
            Ok(true)
        }
        FrameBody::Goodbye(body) => {
            info!(
                peer_id = peer_id_expected,
                reason = %body.reason.unwrap_or_else(|| "(unspecified)".to_string()),
                "hyperswarm: peer sent Goodbye, dropping connection"
            );
            Ok(false)
        }
        // SL-01: task frames are intercepted in the async session loop BEFORE
        // this sync handler (they need provider/lease/autonomy access this fn
        // doesn't have). Reaching here means the intercept has a bug — fail
        // loudly rather than silently no-op.
        FrameBody::TaskDelegate(_) | FrameBody::TaskResult(_) | FrameBody::Gossip(_) => {
            anyhow::bail!(
                "task/gossip frame reached sync handle_inbound_frame — must be intercepted in the session loop"
            );
        }
    }
}

/// Stamp a heartbeat into the shared registry. Pulled out so
/// the test suite can pin the registry-write contract without
/// touching the read loop.
fn record_heartbeat_into_registry(
    peer_id: &str,
    body: &HeartbeatBody,
    registry: &Arc<Mutex<PeerLoadRegistry>>,
) {
    let load = PeerLoad {
        peer: PeerSessionId::new(peer_id),
        tokens_per_sec: body.tokens_per_sec,
        last_observed: Instant::now(),
        healthy: body.healthy,
    };
    match registry.lock() {
        Ok(mut r) => r.record_heartbeat(load),
        Err(e) => warn!(
            error = %e,
            "hyperswarm: registry mutex poisoned; dropping heartbeat"
        ),
    }
}

/// Run the per-connection inbound-frame loop until the peer
/// closes, sends Goodbye, or the link errors. Returns Ok when
/// the loop exited cleanly (Goodbye / EOF) and Err on
/// transport / validation failure.
pub async fn run_inbound_loop<R: AsyncRead + Unpin>(
    source: &mut R,
    peer_id: &str,
    mut capabilities: Vec<String>,
    registry: Arc<Mutex<PeerLoadRegistry>>,
) -> Result<()> {
    loop {
        let frame = match heartbeat::read_framed(source).await {
            Ok(f) => f,
            Err(e) => {
                // A clean peer disconnect surfaces as an io error whose
                // kind is UnexpectedEof (read_exact hit end-of-stream).
                // Match the typed kind by walking the anyhow cause chain
                // instead of substring-matching the Display string — the
                // old check keyed on the "read frame len-prefix" context
                // and would mis-handle a renamed context or treat a
                // non-EOF error at that read as a clean disconnect.
                let is_eof = e
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                    .map(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
                    .unwrap_or(false);
                if is_eof {
                    info!(peer_id, "hyperswarm: peer disconnected (EOF)");
                    return Ok(());
                }
                return Err(e);
            }
        };
        match handle_inbound_frame(frame, peer_id, &mut capabilities, &registry) {
            Ok(true) => continue,
            Ok(false) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Lowercase hex encoding without a separate `hex` dep.
fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_task_gate_truth_table() {
        let allow = Decision::Allow;
        let confirm = Decision::Confirm("c".into());
        let deny = Decision::Deny("d".into());

        // Unpaired ⇒ always reject regardless of autonomy/lease.
        assert_eq!(
            cluster_task_gate(false, &allow, true),
            TaskGateOutcome::Reject("not_paired")
        );

        // Deny (Strict) ⇒ reject even when paired + leased (lease never
        // overrides a Deny — the shipped lease semantics).
        assert_eq!(
            cluster_task_gate(true, &deny, true),
            TaskGateOutcome::Reject("autonomy_deny")
        );

        // Confirm (Standard): accept IFF an active lease; else fail-closed.
        assert_eq!(
            cluster_task_gate(true, &confirm, true),
            TaskGateOutcome::Accept { lease_backed: true }
        );
        assert_eq!(
            cluster_task_gate(true, &confirm, false),
            TaskGateOutcome::Reject("no_active_lease")
        );

        // Allow (Elevated/Full): accept; lease_backed reflects whether a lease
        // also covered it (audit detail), but is not required.
        assert_eq!(
            cluster_task_gate(true, &allow, false),
            TaskGateOutcome::Accept { lease_backed: false }
        );
        assert_eq!(
            cluster_task_gate(true, &allow, true),
            TaskGateOutcome::Accept { lease_backed: true }
        );
    }

    #[test]
    fn derive_topic_is_deterministic_for_same_input() {
        let a = derive_topic("neoth-cluster");
        let b = derive_topic("neoth-cluster");
        assert_eq!(a, b, "discovery_key must be deterministic");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn derive_topic_differs_for_different_inputs() {
        let a = derive_topic("neoth-cluster");
        let b = derive_topic("other-cluster");
        assert_ne!(a, b, "different names must yield different topics");
    }

    #[test]
    fn derive_topic_handles_empty_string() {
        // Empty name still produces a 32-byte digest (the
        // empty-string hash). We want the function to be
        // total — operator config validation rejects empty
        // names upstream, but the helper shouldn't panic.
        let topic = derive_topic("");
        assert_eq!(topic.len(), 32);
    }

    #[test]
    fn hex_encode_matches_known_vectors() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // ── Connection-loop coverage (via tokio::io::duplex) ────────────

    use super::super::heartbeat::{
        CapabilityUpdateBody, FrameBody, FrameKind, GoodbyeBody, HeartbeatBody, HelloBody,
        PROTOCOL_NAME, PROTOCOL_VERSION, WireFrame,
    };
    use std::time::Duration;

    fn fake_heartbeat_frame(peer_id: &str, seq: u64, tps: f64, healthy: bool) -> WireFrame {
        WireFrame {
            kind: FrameKind::Heartbeat,
            sequence: seq,
            sent_unix_ms: 1_700_000_000_000,
            peer_id: peer_id.to_string(),
            body: FrameBody::Heartbeat(HeartbeatBody {
                tokens_per_sec: tps,
                inflight_requests: 0,
                healthy,
                capabilities_hash: [0; 32],
            }),
        }
    }

    fn fake_hello_frame(peer_id: &str, cluster: &str) -> WireFrame {
        WireFrame {
            kind: FrameKind::Hello,
            sequence: 0,
            sent_unix_ms: 1_700_000_000_000,
            peer_id: peer_id.to_string(),
            body: FrameBody::Hello(HelloBody {
                protocol: PROTOCOL_NAME.to_string(),
                version: PROTOCOL_VERSION,
                cluster_name_hash: derive_topic(cluster),
                capabilities: vec!["claude_cli".into()],
                capabilities_schema_version: 1,
                cluster_key_proof: None,
            }),
        }
    }

    #[tokio::test]
    async fn send_then_receive_hello_round_trips_via_duplex() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let send_task = tokio::spawn(async move {
            send_hello(&mut a, "peer-A", "neoth-test", vec!["claude_cli".into()])
                .await
                .unwrap();
        });
        let (peer_id, body) = receive_hello(&mut b, "neoth-test").await.unwrap();
        send_task.await.unwrap();
        assert_eq!(peer_id, "peer-A");
        assert_eq!(body.protocol, PROTOCOL_NAME);
        assert_eq!(body.capabilities, vec!["claude_cli"]);
    }

    #[tokio::test]
    async fn receive_hello_rejects_mismatched_cluster_hash() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        // Send a Hello with cluster `wrong-cluster` but the
        // receiver expects `right-cluster` — the hash mismatch
        // must bail.
        let send_task = tokio::spawn(async move {
            send_hello(&mut writer, "peer-X", "wrong-cluster", vec![])
                .await
                .unwrap();
        });
        let err = receive_hello(&mut reader, "right-cluster")
            .await
            .unwrap_err()
            .to_string();
        send_task.await.unwrap();
        assert!(
            err.contains("cluster_name_hash") || err.contains("right-cluster"),
            "diagnostic must name the cluster mismatch: {err}"
        );
    }

    #[tokio::test]
    async fn receive_hello_rejects_first_frame_not_being_hello() {
        // Peer sends Heartbeat as first frame — must bail.
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let send_task = tokio::spawn(async move {
            let frame = fake_heartbeat_frame("peer-Y", 1, 1.0, true);
            heartbeat::write_framed(&mut writer, &frame).await.unwrap();
        });
        let err = receive_hello(&mut reader, "any")
            .await
            .unwrap_err()
            .to_string();
        send_task.await.unwrap();
        assert!(err.contains("expected Hello"), "diagnostic: {err}");
    }

    #[test]
    fn handle_inbound_heartbeat_records_into_registry() {
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let mut caps: Vec<String> = vec![];
        let frame = fake_heartbeat_frame("peer-R", 5, 7.5, true);
        let keep_going = handle_inbound_frame(frame, "peer-R", &mut caps, &registry).unwrap();
        assert!(keep_going, "heartbeat must not close the loop");

        let snapshot = registry.lock().unwrap().known_peers();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].peer.as_str(), "peer-R");
        assert_eq!(snapshot[0].tokens_per_sec, 7.5);
        assert!(snapshot[0].healthy);
    }

    #[test]
    fn handle_inbound_heartbeat_rejects_peer_id_mismatch() {
        // Frame's peer_id must match the handshake peer_id —
        // defense against a hostile peer impersonating
        // another sibling on the same stream.
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let mut caps: Vec<String> = vec![];
        let frame = fake_heartbeat_frame("imposter", 1, 5.0, true);
        let err = handle_inbound_frame(frame, "expected-peer", &mut caps, &registry)
            .unwrap_err()
            .to_string();
        assert!(err.contains("peer_id"), "diagnostic: {err}");
        assert_eq!(registry.lock().unwrap().known_peers().len(), 0);
    }

    #[test]
    fn handle_inbound_capability_update_refreshes_cache() {
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let mut caps: Vec<String> = vec!["old".into()];
        let frame = WireFrame {
            kind: FrameKind::CapabilityUpdate,
            sequence: 9,
            sent_unix_ms: 1_700_000_000_000,
            peer_id: "peer-C".into(),
            body: FrameBody::CapabilityUpdate(CapabilityUpdateBody {
                capabilities: vec!["new_one".into(), "new_two".into()],
            }),
        };
        let keep = handle_inbound_frame(frame, "peer-C", &mut caps, &registry).unwrap();
        assert!(keep);
        assert_eq!(caps, vec!["new_one", "new_two"]);
    }

    #[test]
    fn handle_inbound_goodbye_signals_loop_exit() {
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let mut caps: Vec<String> = vec![];
        let frame = WireFrame {
            kind: FrameKind::Goodbye,
            sequence: 99,
            sent_unix_ms: 1_700_000_000_000,
            peer_id: "peer-G".into(),
            body: FrameBody::Goodbye(GoodbyeBody {
                reason: Some("rotation".into()),
            }),
        };
        let keep = handle_inbound_frame(frame, "peer-G", &mut caps, &registry).unwrap();
        assert!(!keep, "Goodbye must terminate the loop");
    }

    #[test]
    fn handle_inbound_rejects_duplicate_hello() {
        // Hello is handshake-only; a second Hello mid-stream
        // is protocol abuse.
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let mut caps: Vec<String> = vec![];
        let frame = fake_hello_frame("peer-D", "test");
        let err = handle_inbound_frame(frame, "peer-D", &mut caps, &registry)
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate Hello"), "diagnostic: {err}");
    }

    #[test]
    fn handle_inbound_rejects_nan_heartbeat() {
        // validate_heartbeat fires inside the handler; the
        // registry never sees NaN values.
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let mut caps: Vec<String> = vec![];
        let frame = fake_heartbeat_frame("peer-N", 1, f64::NAN, true);
        assert!(handle_inbound_frame(frame, "peer-N", &mut caps, &registry).is_err());
        assert_eq!(registry.lock().unwrap().known_peers().len(), 0);
    }

    #[tokio::test]
    async fn run_inbound_loop_processes_multiple_frames_then_exits_on_goodbye() {
        let (mut sender, mut receiver) = tokio::io::duplex(2048);
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let reg_ro = Arc::clone(&registry);

        // Sender writes 3 heartbeats then Goodbye.
        let sender_task = tokio::spawn(async move {
            for (i, tps) in [(1u64, 2.0), (2, 4.0), (3, 1.5)] {
                let frame = fake_heartbeat_frame("peer-Q", i, tps, true);
                heartbeat::write_framed(&mut sender, &frame).await.unwrap();
            }
            let goodbye = WireFrame {
                kind: FrameKind::Goodbye,
                sequence: 4,
                sent_unix_ms: 1_700_000_000_000,
                peer_id: "peer-Q".into(),
                body: FrameBody::Goodbye(GoodbyeBody { reason: None }),
            };
            heartbeat::write_framed(&mut sender, &goodbye)
                .await
                .unwrap();
        });

        let loop_result = tokio::time::timeout(
            Duration::from_secs(5),
            run_inbound_loop(&mut receiver, "peer-Q", vec![], registry),
        )
        .await
        .expect("loop must finish within timeout");
        sender_task.await.unwrap();
        loop_result.expect("inbound loop");

        let snapshot = reg_ro.lock().unwrap().known_peers();
        assert_eq!(snapshot.len(), 1);
        // Last heartbeat (tps=1.5) wins.
        assert_eq!(snapshot[0].tokens_per_sec, 1.5);
    }

    #[tokio::test]
    async fn run_inbound_loop_returns_ok_on_clean_eof() {
        // Peer closes the connection without sending Goodbye
        // — read_framed returns Err. The loop should treat
        // that as clean disconnect (Ok) so the daemon's
        // accept loop doesn't log a spurious error.
        let (sender, mut receiver) = tokio::io::duplex(1024);
        drop(sender); // immediate EOF
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let r = tokio::time::timeout(
            Duration::from_secs(2),
            run_inbound_loop(&mut receiver, "peer-X", vec![], registry),
        )
        .await
        .expect("must not hang");
        assert!(r.is_ok(), "EOF without Goodbye → Ok");
    }

    #[tokio::test]
    async fn run_inbound_loop_non_eof_error_surfaces_as_err() {
        // COR-21: a non-EOF transport error (connection reset) at the
        // len-prefix read must surface as Err. The old Display-string match
        // keyed on the "read frame len-prefix" context and would have wrongly
        // treated this as a clean disconnect (Ok); the typed UnexpectedEof
        // check correctly distinguishes EOF from a real transport failure.
        struct ResetReader;
        impl tokio::io::AsyncRead for ResetReader {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "synthetic reset",
                )))
            }
        }
        let mut reader = ResetReader;
        let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
        let r = run_inbound_loop(&mut reader, "peer-R", vec![], registry).await;
        assert!(r.is_err(), "non-EOF transport error must surface as Err");
    }

    #[test]
    fn now_unix_ms_is_monotonic_within_call_horizon() {
        let a = now_unix_ms();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = now_unix_ms();
        assert!(b >= a, "monotonic within process lifetime");
    }
}
