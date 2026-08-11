//! R-7 peeroxide Hyperswarm transport.
//!
//! Per `PLAN/PROGRESS.md` post-v0.1 backlog. The Phase-3 dep
//! block lifted in Session 19 (commit `d44a0e8`) — peeroxide
//! 1.3.x is the maintained pure-Rust Hyperswarm port. This
//! module brings up a swarm, joins the cluster topic, authenticates peers, and
//! hands each connection to the live heartbeat/task/gossip protocol.
//!
//! ## Operator-facing wire
//!
//! ```ignore
//! use std::sync::{Arc, Mutex};
//! use crate::cluster::{hyperswarm, PeerLoadRegistry};
//!
//! // Production path: always supply the cluster_key so inbound-peer
//! // proof enforcement is armed.
//! let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
//! let cluster_key = Arc::new(identity.key);
//! let handle = hyperswarm::spawn_discovery_with_wal(
//!     "my-cluster",
//!     cluster_key,
//!     registry,
//!     Some(Arc::new(wal_writer)),
//!     peer_streams,
//!     Arc::new(Mutex::new(crate::cluster::wal_sync::GossipState::new())),
//!     Arc::clone(&reload_controller),
//!     neoth_home,
//!     Some(dispatch_tx),
//! ).await?;
//! // ... daemon runs ...
//! handle.shutdown().await?;
//! ```
//!
//! ## What this module owns
//!
//! - [`derive_topic`] — operator-supplied cluster name →
//!   32-byte topic via peeroxide's `discovery_key`.
//! - [`SwarmHandle`] — RAII wrapper around the spawned
//!   peeroxide swarm + the JoinHandle. Drop aborts the task.
//! - [`spawn_discovery_with_wal`] — bring up the swarm, join the
//!   topic, spawn the peer-acceptor loop. Returns the handle.
//!   Callers always supply a cluster_key (the keyless convenience
//!   wrapper was deleted — it had no consumer).
//! - [`spawn_public_rendezvous`] — narrow one-shot public-bootstrap entry
//!   point for an already-authorized protocol such as companion pairing.
//!
//! Peeroxide's public bootstrap set remains the discovery boundary; private
//! bootstrap selection is intentionally not exposed as a half-wired option.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::io::AsyncRead;
// Only the test-gated `send_hello` writes; production sinks go through
// `heartbeat::write_framed` with concrete stream types.
#[cfg(test)]
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use super::discovery::ClusterKey;
use super::executor::ClusterTaskJob;
use super::gossip_wire::GossipAcceptance;
use super::heartbeat::{
    self, FrameBody, FrameKind, HeartbeatBody, HelloBody, PROTOCOL_NAME, PROTOCOL_VERSION,
    TaskDelegateBody, TaskResultBody, TaskResultStatus, WireFrame,
};
use super::local_load;
use super::peer_auth::{compute_cluster_key_proof, verify_peer_proof};
use super::peer_streams::PeerStreamRegistry;
use super::{PeerLoad, PeerLoadRegistry, PeerPubkey, PeerSessionId};
use crate::permissions::{self, Action, AutonomyLevel, Decision};
use crate::wal::writer::WalWriterHandle;

/// Optional WAL writer handle threaded into `spawn_discovery_with_wal`
/// so each per-peer task emits `0xE0..=0xE5 CLUSTER_*` frames
/// into the audit chain. CLI one-shots that don't have a
/// live writer pass `None`; the daemon's `cli::serve` path
/// threads its handle through.
pub type ClusterWalWriter = Option<Arc<WalWriterHandle>>;

/// SL-00(1b) DoS hardening: maximum number of concurrent peer sessions on the
/// public DHT transport. Reached only under a connection flood (a healthy home
/// cluster is single-digit peers); excess inbound connections are dropped.
const MAX_CONCURRENT_PEER_SESSIONS: usize = 64;

/// Startup must either return a fully joined swarm or prove every spawned
/// actor/accept task gone before returning `Err` to the runtime supervisor.
const SWARM_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const STARTUP_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const STARTUP_DESTROY_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// The runtime supervisor gives a carrier generation 45 seconds to start.
/// Keep the final cleanup budget outside this local wait so cancellation never
/// drops an owned DHT startup while the supervisor is still willing to retry.
const SWARM_BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(35);

#[derive(Debug)]
struct StartupTeardownUncertain(String);

impl std::fmt::Display for StartupTeardownUncertain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StartupTeardownUncertain {}

fn uncertain_start_error(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(StartupTeardownUncertain(message.into()))
}

/// `peeroxide::spawn` does not return its internal task handle on `Err`, and a
/// timed-out cleanup may have had to abort the wrapper that owns the DHT join.
/// The runtime supervisor must terminally poison instead of treating either as
/// a clean, retryable start failure.
pub(crate) fn start_error_has_uncertain_teardown(error: &anyhow::Error) -> bool {
    error.root_cause().is::<StartupTeardownUncertain>()
}

#[cfg(test)]
pub(crate) fn test_uncertain_start_error(message: &str) -> anyhow::Error {
    uncertain_start_error(message)
}

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
/// → drop the peeroxide handle (actor breaks its loop) → signal + await our
/// accept loop, which cancels and awaits every owned peer session → await the
/// actor task so DHT sockets close before the process exits.
pub struct SwarmHandle {
    /// peeroxide command handle. `Some` while live; dropping it stops the DHT.
    peer_handle: Option<peeroxide::SwarmHandle>,
    /// The joined topic — used to `leave()` (unannounce) on graceful shutdown.
    topic: [u8; 32],
    /// peeroxide's DHT actor task — awaited on shutdown for clean socket close.
    swarm_task: Option<tokio::task::JoinHandle<()>>,
    /// Our per-peer connection-accept loop.
    accept_task: Option<tokio::task::JoinHandle<()>>,
    /// Graceful stop signal for the accept loop. Unlike aborting its JoinHandle,
    /// this lets it await cancellation of every peer session that owns WAL and
    /// cluster-dispatch senders.
    accept_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// Stable authenticated origin used by every local gossip frame: the
    /// peeroxide Noise static public key in lowercase hex.
    own_peer_id: String,
}

/// A short-lived, operator-triggered public Hyperswarm rendezvous.
///
/// This is deliberately narrower than [`SwarmHandle`]: it owns no cluster
/// identity, protocol, or peer-accept task. It is for one-invite consumers such
/// as companion pairing which need bounded sequential accepts behind the
/// reviewed public-bootstrap boundary
/// without being allowed to construct a second Peeroxide dialer themselves.
/// The receiver yields the raw Noise connection because the caller owns its
/// application protocol; bootstrap, spawn, join, leave, and task teardown stay
/// in this module.
pub(crate) struct PublicRendezvous {
    peer_handle: Option<peeroxide::SwarmHandle>,
    topic: [u8; 32],
    swarm_task: Option<tokio::task::JoinHandle<()>>,
    connections: tokio::sync::mpsc::Receiver<peeroxide::SwarmConnection>,
}

async fn public_start_shutdown_requested(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    loop {
        if shutdown.changed().await.is_err() || *shutdown.borrow() {
            return;
        }
    }
}

enum BootstrapWait<T, E> {
    Ready(std::result::Result<T, E>),
    CancelledOrExpired,
}

/// Race a bootstrap future with the persistent pre-auth shutdown/deadline.
///
/// This is deliberately independent from Peeroxide so the cancellation order
/// is hermetically testable. Its caller retains the `SwarmStartup` owner until
/// it has either transferred ownership with `finish` or awaited `shutdown`.
async fn wait_for_bootstrap_or_stop<T, E>(
    bootstrap: impl std::future::Future<Output = std::result::Result<T, E>>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    deadline: tokio::time::Instant,
) -> BootstrapWait<T, E> {
    tokio::select! {
        biased;
        _ = public_start_shutdown_requested(shutdown) => BootstrapWait::CancelledOrExpired,
        _ = tokio::time::sleep_until(deadline) => BootstrapWait::CancelledOrExpired,
        result = bootstrap => BootstrapWait::Ready(result),
    }
}

async fn shutdown_unfinished_swarm_start(
    startup: peeroxide::SwarmStartup,
    stage: &'static str,
) -> Result<()> {
    match tokio::time::timeout(STARTUP_CLEANUP_TIMEOUT, startup.shutdown()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(uncertain_start_error(format!(
            "peeroxide startup {stage} failed and owned DHT teardown returned an error: {error}"
        ))),
        Err(_) => Err(uncertain_start_error(format!(
            "peeroxide startup {stage} exceeded the {} second teardown budget; DHT drain was not proven",
            STARTUP_CLEANUP_TIMEOUT.as_secs()
        ))),
    }
}

/// Request actor destruction and wait for its join. The actor owns the nested
/// `HyperDhtOwner` after `SwarmStartup::finish`, so its completed join is the
/// proof that every DHT task drained. This normal path must never abort it.
async fn shutdown_started_public_rendezvous(
    peer_handle: peeroxide::SwarmHandle,
    swarm_task: tokio::task::JoinHandle<()>,
) -> Result<()> {
    match tokio::time::timeout(STARTUP_DESTROY_REQUEST_TIMEOUT, peer_handle.destroy()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(%error, "public rendezvous destroy request failed; closing command channel")
        }
        Err(_) => warn!("public rendezvous destroy request timed out; closing command channel"),
    }
    drop(peer_handle);
    swarm_task.await.map_err(|error| {
        uncertain_start_error(format!(
            "public rendezvous actor ended without proving nested DHT-owner drain: {error}"
        ))
    })
}

impl PublicRendezvous {
    /// Receive the next encrypted connection for this rendezvous topic.
    pub(crate) async fn recv(&mut self) -> Option<peeroxide::SwarmConnection> {
        self.connections.recv().await
    }

    /// Stop advertising the topic, then release the control handle while a
    /// caller consumes its authenticated Noise stream. No further dialing
    /// authority remains once the invite reaches a terminal transition.
    pub(crate) async fn leave(&mut self) -> Result<()> {
        let Some(handle) = self.peer_handle.take() else {
            anyhow::bail!("public rendezvous was already shut down");
        };
        let result =
            match tokio::time::timeout(std::time::Duration::from_secs(2), handle.leave(self.topic))
                .await
            {
                Ok(result) => result.context("peeroxide leave public rendezvous topic"),
                Err(_) => Err(anyhow::anyhow!(
                    "peeroxide leave public rendezvous topic timed out"
                )),
            };
        drop(handle);
        result
    }

    /// Gracefully destroy the Peeroxide actor and await its nested DHT owner.
    ///
    /// Dropping this value remains an abort-only last resort for panics, but
    /// every normal listener terminal path reaches this explicit join.
    pub(crate) async fn shutdown(mut self) {
        match (self.peer_handle.take(), self.swarm_task.take()) {
            (Some(handle), Some(task)) => {
                if let Err(error) = shutdown_started_public_rendezvous(handle, task).await {
                    error!(%error, "public rendezvous graceful teardown was not proven");
                }
            }
            (None, Some(task)) => {
                if let Err(error) = task.await {
                    error!(%error, "public rendezvous actor ended without graceful teardown proof");
                }
            }
            (Some(handle), None) => drop(handle),
            (None, None) => {}
        }
    }
}

impl Drop for PublicRendezvous {
    fn drop(&mut self) {
        self.peer_handle = None;
        if let Some(task) = self.swarm_task.take() {
            task.abort();
        }
    }
}

/// Build server-only discovery options for an advertised companion invite.
fn server_only_join_opts() -> peeroxide::JoinOpts {
    // A companion invite is an advertised rendezvous for an incoming phone.
    // Client mode would let the daemon initiate to any observer of the topic,
    // consume the one-shot invite, and invert that trust direction.
    let mut options = peeroxide::JoinOpts::default();
    options.server = true;
    options.client = false;
    options
}

/// Build the fixed public-bootstrap configuration for a v2 pairing rendezvous.
///
/// Keeping this construction beside the sole spawn caller prevents an optional
/// or keyless public rendezvous from being reintroduced by a future caller.
fn public_rendezvous_config(expected_remote_static_key: [u8; 32]) -> peeroxide::SwarmConfig {
    let mut config = peeroxide::SwarmConfig::with_public_bootstrap();
    // Mandatory v2 companion admission: a public topic alone can never reserve
    // a transport slot. Peeroxide verifies this static key during the responder
    // Noise handshake, before reply, registration, stream establishment, or the
    // bounded connection receiver.
    config.server_expected_remote_static_key = Some(expected_remote_static_key);
    config
}

/// Start a public-bootstrap, one-topic rendezvous for an explicit
/// operator-triggered protocol. This is the only generic public Peeroxide
/// construction boundary: consumers receive a typed owner rather than a
/// dialer/configuration surface.
pub(crate) async fn spawn_public_rendezvous(
    topic: [u8; 32],
    expected_remote_static_key: [u8; 32],
    deadline: tokio::time::Instant,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<PublicRendezvous> {
    // Reject persistent pre-cancellation / already-expired admission before
    // constructing the public-bootstrap config.
    if *shutdown.borrow() || tokio::time::Instant::now() >= deadline {
        anyhow::bail!("public rendezvous cancelled or expired before bootstrap spawn");
    }
    let config = public_rendezvous_config(expected_remote_static_key);
    let startup = peeroxide::spawn_starting(config)
        .await
        .context("peeroxide begin public rendezvous startup")?;

    match wait_for_bootstrap_or_stop(startup.bootstrapped(), &mut shutdown, deadline).await {
        BootstrapWait::Ready(Ok(())) => {}
        BootstrapWait::Ready(Err(error)) => {
            if let Err(cleanup_error) =
                shutdown_unfinished_swarm_start(startup, "public rendezvous bootstrap").await
            {
                return Err(cleanup_error.context(format!(
                    "peeroxide public rendezvous bootstrap failed: {error}"
                )));
            }
            return Err(error).context("peeroxide bootstrap public rendezvous");
        }
        BootstrapWait::CancelledOrExpired => {
            shutdown_unfinished_swarm_start(startup, "public rendezvous cancellation")
                .await
                .context("public rendezvous cancelled or expired while bootstrapping")?;
            anyhow::bail!("public rendezvous cancelled or expired during bootstrap");
        }
    }

    let (swarm_task, peer_handle, connections) = startup
        .finish()
        .await
        .map_err(|error| {
            uncertain_start_error(format!(
                "peeroxide public rendezvous finish failed after bootstrap without retained cleanup ownership: {error}"
            ))
        })
        .context("peeroxide finish public rendezvous startup")?;

    let join_result = tokio::select! {
        biased;
        _ = public_start_shutdown_requested(&mut shutdown) => None,
        _ = tokio::time::sleep_until(deadline) => None,
        result = peer_handle.join(topic, server_only_join_opts()) => Some(result),
    };
    match join_result {
        Some(Ok(())) => {}
        Some(Err(error)) => {
            shutdown_started_public_rendezvous(peer_handle, swarm_task)
                .await
                .context("public rendezvous join failure cleanup")?;
            return Err(error).context("peeroxide join public rendezvous topic");
        }
        None => {
            shutdown_started_public_rendezvous(peer_handle, swarm_task)
                .await
                .context("public rendezvous cancelled join cleanup")?;
            anyhow::bail!("public rendezvous cancelled or expired during topic join");
        }
    }

    Ok(PublicRendezvous {
        peer_handle: Some(peer_handle),
        topic,
        swarm_task: Some(swarm_task),
        connections,
    })
}

impl SwarmHandle {
    pub fn own_peer_id(&self) -> &str {
        &self.own_peer_id
    }

    /// The carrier is live only while both owned critical workers are still
    /// running. Retaining their handles alone is not runtime evidence.
    pub(crate) fn is_healthy(&self) -> bool {
        self.peer_handle.is_some()
            && self
                .swarm_task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
            && self
                .accept_task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
    }

    /// Explicit graceful shutdown — unannounces, stops the DHT actor, and
    /// awaits termination. Use over `Drop` when the caller wants synchronous
    /// teardown (daemon SIGTERM path) with no lingering DHT announce.
    pub async fn shutdown(mut self) -> Result<()> {
        // 1. Unannounce + stop discovery for our topic (best-effort — the
        //    handle-drop below also tears the swarm down, this just makes the
        //    unannounce prompt rather than waiting for the actor to wind down).
        if let Some(h) = self.peer_handle.as_ref()
            && let Err(e) = h.leave(self.topic).await
        {
            debug!(error = %e, "hyperswarm: leave on shutdown failed (continuing teardown)");
        }
        // 2. Drop the command handle → last cmd_tx gone → actor breaks its loop
        //    → DHT destroyed + unannounced.
        self.peer_handle = None;
        // 3. Stop the accept loop and await its owned peer-session JoinSet.
        if let Some(shutdown) = self.accept_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(t) = self.accept_task.take() {
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
        if let Some(shutdown) = self.accept_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(t) = self.accept_task.take() {
            t.abort();
        }
        if let Some(t) = self.swarm_task.take() {
            t.abort();
        }
    }
}

async fn await_or_abort_startup_task(
    mut task: tokio::task::JoinHandle<()>,
    task_name: &'static str,
    cleanup_timeout: std::time::Duration,
) -> bool {
    match tokio::time::timeout(cleanup_timeout, &mut task).await {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            warn!(%error, task = task_name, "hyperswarm startup cleanup task failed");
            false
        }
        Err(_) => {
            task.abort();
            let _ = task.await;
            warn!(
                task = task_name,
                "hyperswarm startup cleanup exceeded deadline and was aborted"
            );
            false
        }
    }
}

async fn cleanup_failed_swarm_start(
    peer_handle: peeroxide::SwarmHandle,
    accept_shutdown: tokio::sync::oneshot::Sender<()>,
    accept_task: tokio::task::JoinHandle<()>,
    swarm_task: tokio::task::JoinHandle<()>,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + STARTUP_CLEANUP_TIMEOUT;
    let _ = accept_shutdown.send(());
    // Ask the actor to destroy the DHT before dropping the final command
    // sender. Regardless of that reply, the actor-task join below is the proof
    // that topic leave, DHT shutdown, and runtime socket cleanup completed.
    let destroy_timeout = STARTUP_DESTROY_REQUEST_TIMEOUT
        .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
    if tokio::time::timeout(destroy_timeout, peer_handle.destroy())
        .await
        .is_err()
    {
        warn!("hyperswarm startup cleanup destroy request exceeded deadline");
    }
    drop(peer_handle);
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let (accept_clean, actor_clean) = tokio::join!(
        await_or_abort_startup_task(accept_task, "accept", remaining),
        await_or_abort_startup_task(swarm_task, "actor", remaining),
    );
    if accept_clean && actor_clean {
        Ok(())
    } else {
        Err(uncertain_start_error(
            "hyperswarm startup failed and complete task/DHT teardown was not proven",
        ))
    }
}

/// Owns every live peer session spawned by the accept loop. Explicit shutdown
/// awaits cancellation so session-held WAL writers and task-dispatch senders
/// are gone before [`SwarmHandle::shutdown`] returns.
#[derive(Default)]
struct PeerSessions {
    tasks: tokio::task::JoinSet<()>,
}

impl PeerSessions {
    fn spawn(&mut self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        self.tasks.spawn(task);
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    async fn join_next(&mut self) -> Option<Result<(), tokio::task::JoinError>> {
        self.tasks.join_next().await
    }

    async fn shutdown(&mut self) {
        self.tasks.shutdown().await;
    }
}

/// Bring up a peeroxide swarm, join the cluster's topic, and thread a live
/// `WalWriterHandle` into every per-peer task so cluster
/// lifecycle events emit `0xE0..=0xE5` frames. Used by
/// `cli::serve`, which holds the writer. This is the only
/// discovery entry point — a WAL-free variant was never built.
// The capabilities stay explicit here: grouping them into a reusable context
// could accidentally carry a prior instance's key, WAL, or reload policy.
#[allow(clippy::too_many_arguments)]
pub async fn spawn_discovery_with_wal(
    cluster_name: &str,
    // SL-00(1b): the mandatory shared cluster_key. The type boundary makes an
    // unauthenticated discovery/handshake path impossible.
    cluster_key: Arc<ClusterKey>,
    registry: Arc<Mutex<PeerLoadRegistry>>,
    wal_writer: ClusterWalWriter,
    // SL-00(1c): shared registry of per-peer outbound channels. The daemon
    // holds a clone so SL-01/SL-01b can send directed frames to a peer.
    peer_streams: Arc<PeerStreamRegistry>,
    gossip_state: super::wal_sync::SharedGossipState,
    // SL-01 accept-gate policy source threaded into every peer session. Each
    // inbound task obtains a fresh immutable snapshot at the side-effect leaf.
    reload_controller: Arc<crate::config::reload::ReloadController>,
    neoth_home: std::path::PathBuf,
    dispatch_tx: Option<tokio::sync::mpsc::Sender<ClusterTaskJob>>,
) -> Result<SwarmHandle> {
    let topic = derive_topic(cluster_name);
    // Transport identity is node identity, not rendezvous-key identity.
    // Persist before any DHT actor starts; cluster-passphrase rotation must
    // never mint a new Noise key and silently evade a tombstone.
    let local_identity = super::membership::LocalNodeIdentity::load_or_create(&neoth_home)
        .context("load stable cluster node identity")?;
    let mut config = peeroxide::SwarmConfig::with_public_bootstrap();
    config.key_pair = Some(local_identity.peeroxide_key_pair());
    // `spawn_starting` hands us the DHT owner before the potentially long
    // public bootstrap wait. Keep ten seconds of the supervisor's 45-second
    // generation budget available for a proved shutdown instead of letting an
    // outer timeout cancel this future while the owner is still live.
    let bootstrap_deadline = tokio::time::Instant::now() + SWARM_BOOTSTRAP_TIMEOUT;
    let startup = match peeroxide::spawn_starting(config).await {
        Ok(startup) => startup,
        Err(error) => {
            // peeroxide owns an internal DHT task but does not return its join
            // handle on `Err`; callers cannot prove teardown and must not retry
            // another carrier generation in this process.
            return Err(uncertain_start_error(format!(
                "peeroxide::spawn_starting failed before handing out cleanup ownership: {error}"
            )))
            .context("peeroxide::spawn_starting — begin Hyperswarm");
        }
    };
    match tokio::time::timeout_at(bootstrap_deadline, startup.bootstrapped()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if let Err(cleanup_error) =
                shutdown_unfinished_swarm_start(startup, "cluster bootstrap").await
            {
                return Err(cleanup_error.context(format!(
                    "peeroxide bootstrap for cluster `{cluster_name}` failed: {error}"
                )));
            }
            return Err(error)
                .with_context(|| format!("peeroxide bootstrap for cluster `{cluster_name}`"));
        }
        Err(_) => {
            shutdown_unfinished_swarm_start(startup, "cluster bootstrap timeout")
                .await
                .with_context(|| {
                    format!(
                        "peeroxide bootstrap for cluster `{cluster_name}` timed out after {} seconds",
                        SWARM_BOOTSTRAP_TIMEOUT.as_secs()
                    )
                })?;
            anyhow::bail!(
                "peeroxide bootstrap for cluster `{cluster_name}` timed out after {} seconds",
                SWARM_BOOTSTRAP_TIMEOUT.as_secs()
            );
        }
    }
    let (swarm_task, handle, mut conn_rx) = startup.finish().await.map_err(|error| {
        // `finish` consumes the explicit startup owner. The vendor performs
        // its own shutdown on its only fallible pre-actor operation, but does
        // not return an owner for us to await, so fail closed rather than let
        // the runtime supervisor start another generation beside it.
        uncertain_start_error(format!(
            "peeroxide finish for cluster `{cluster_name}` failed after bootstrap without retained cleanup ownership: {error}"
        ))
    })?;
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
    let own_peer_id = hex_encode(&own_noise_pk);
    let accept_peer_id = own_peer_id.clone();
    let (accept_shutdown, mut accept_shutdown_rx) = tokio::sync::oneshot::channel();
    let accept_task = tokio::spawn(async move {
        let mut peer_sessions = PeerSessions::default();
        loop {
            let conn = tokio::select! {
                biased;
                _ = &mut accept_shutdown_rx => {
                    debug!("hyperswarm: peer acceptor received shutdown");
                    break;
                }
                joined = peer_sessions.join_next(), if !peer_sessions.is_empty() => {
                    if let Some(Err(error)) = joined {
                        warn!(%error, "hyperswarm: owned peer session task panicked");
                    }
                    continue;
                }
                conn = conn_rx.recv() => match conn {
                    Some(conn) => conn,
                    None => {
                        warn!("hyperswarm: connection receiver closed — discovery loop exiting");
                        break;
                    }
                },
            };
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
            let own_id = accept_peer_id.clone();
            let reg = Arc::clone(&registry);
            let wal = wal_writer.clone();
            let ckey = cluster_key.clone();
            let streams = Arc::clone(&peer_streams);
            let state = Arc::clone(&gossip_state);
            let home = neoth_home.clone();
            let dtx = dispatch_tx.clone();
            let reload = Arc::clone(&reload_controller);
            peer_sessions.spawn(async move {
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
                    state,
                    reload,
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
        peer_sessions.shutdown().await;
        debug!("hyperswarm: peer acceptor and all sessions stopped");
    });

    // SL-00(1b) review fix: announce on the DHT ONLY AFTER the accept loop is
    // live. The loop blocks on an empty `conn_rx` until peers actually connect,
    // so spawning it first costs nothing and closes the window where the node
    // was visible on the public DHT before the auth guardian was polling.
    match tokio::time::timeout(
        SWARM_JOIN_TIMEOUT,
        handle.join(topic, peeroxide::JoinOpts::default()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if let Err(cleanup_error) =
                cleanup_failed_swarm_start(handle, accept_shutdown, accept_task, swarm_task).await
            {
                return Err(cleanup_error.context(format!(
                    "peeroxide join topic for cluster `{cluster_name}` failed: {error}"
                )));
            }
            return Err(error)
                .with_context(|| format!("peeroxide join topic for cluster `{cluster_name}`"));
        }
        Err(_) => {
            let timeout_error = format!(
                "peeroxide join topic for cluster `{cluster_name}` timed out after {} seconds",
                SWARM_JOIN_TIMEOUT.as_secs()
            );
            if let Err(cleanup_error) =
                cleanup_failed_swarm_start(handle, accept_shutdown, accept_task, swarm_task).await
            {
                return Err(cleanup_error.context(timeout_error));
            }
            anyhow::bail!(
                "peeroxide join topic for cluster `{cluster_name}` timed out after {} seconds",
                SWARM_JOIN_TIMEOUT.as_secs()
            );
        }
    }

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
        accept_shutdown: Some(accept_shutdown),
        own_peer_id,
    })
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
    // SL-00(1b): the mandatory shared cluster_key + our own Noise static
    // pubkey, used to prove + verify cluster membership in the Hello exchange.
    cluster_key: Arc<ClusterKey>,
    own_noise_pk: [u8; 32],
    // SL-00(1c): registry of outbound channels so other subsystems can send
    // directed frames to this peer; the session loop drains its receiver.
    peer_streams: Arc<PeerStreamRegistry>,
    gossip_state: super::wal_sync::SharedGossipState,
    // SL-01: the 3-checkpoint accept-gate inputs. `reload_controller` supplies
    // the active immutable policy; `neoth_home` locates cluster.yaml + leases;
    // `dispatch_tx` hands an accepted task to the executor (None ⇒ no executor,
    // e.g. no-provider / CLI one-shot — a delegate then gets a "no_provider"
    // rejection).
    reload_controller: Arc<crate::config::reload::ReloadController>,
    neoth_home: std::path::PathBuf,
    dispatch_tx: Option<tokio::sync::mpsc::Sender<ClusterTaskJob>>,
) -> Result<()> {
    let remote_pk_hex = hex_encode(conn.remote_public_key());
    // Peer's Noise static key from the authenticated channel — the identity
    // the cluster_key proof binds to (NOT anything from the frame payload).
    let peer_noise_pk: [u8; 32] = *conn.remote_public_key();
    // SL-02b: start the handshake round-trip clock — the elapsed time from our
    // Hello write to the peer's validated Hello is recorded as this peer's RTT.

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
            cluster_key_proof: Some(compute_cluster_key_proof(
                &cluster_key,
                &own_noise_pk,
                &peer_noise_pk,
            )),
        }),
    };
    let our_hello_bytes = heartbeat::encode_frame(&our_hello).context("encode our Hello")?;
    // SL-00(1b): bound the Hello write — a peer that accepts the connection but
    // stalls the read side must not pin this task indefinitely.
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.write(&our_hello_bytes)).await {
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
    let peer_read = match tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.read()).await {
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
    if peer_id != remote_pk_hex {
        emit_peer_rejected_wal(
            wal_writer.as_deref(),
            &peer_id,
            "Hello peer_id does not match authenticated Noise public key",
        );
        anyhow::bail!(
            "peer Hello identity mismatch: claimed `{peer_id}`, authenticated `{remote_pk_hex}`"
        );
    }
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
            // what proves shared-secret possession. The key is mandatory at
            // the API boundary, so a missing OR mismatched proof is always a
            // hard rejection. `peer_pk` is the peer's
            // Noise static key from the authenticated channel (never the
            // payload); we recompute proof(peer_pk, own_pk) and constant-time
            // compare.
            match body.cluster_key_proof {
                Some(ref claimed) => {
                    if !verify_peer_proof(&cluster_key, claimed, &peer_noise_pk, &own_noise_pk) {
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

    // Shared-passphrase proof only gets a peer this far. Authorization comes
    // exclusively from exact, carrier-qualified membership authority.
    let membership_store = super::membership::MembershipStore::open(&neoth_home)
        .context("open cluster membership authority")?
        .with_effect_registry(peer_streams.effect_registry());
    let authenticated_transport = super::membership::TransportIdentity::peeroxide(&peer_noise_pk);
    let membership_grant = match membership_store.admit(
        super::membership::CarrierKind::Peeroxide,
        &authenticated_transport,
        now_unix_secs() as i64,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            emit_peer_rejected_wal(
                wal_writer.as_deref(),
                &peer_id,
                "membership authority rejected authenticated transport",
            );
            return Err(error).context("peeroxide membership admission rejected");
        }
    };
    let registration_effect = membership_grant
        .begin_effect(now_unix_secs() as i64)
        .context("begin peeroxide route-registration generation")?;

    info!(
        stable_node_id = %membership_grant.stable_node_id(),
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

    // GOLD-R3-09: both inbound commits and outbound ACK application use the
    // authoritative instance DB. No per-connection dedup/cursor state exists.
    let durable_mesh = super::durable_sync::DurableMeshSync::new(neoth_home.join("views.db"));

    // SL-00(1c): register this peer's outbound channel; the Drop guard removes
    // it on EVERY exit path (clean disconnect, error, supersede).
    let (session_generation, mut outbound_rx, mut membership_cancel) =
        peer_streams.register_authorized_session(&remote_pk_hex, &membership_grant);
    struct UnregisterGuard {
        reg: Arc<PeerStreamRegistry>,
        key: String,
        generation: u64,
    }
    impl Drop for UnregisterGuard {
        fn drop(&mut self) {
            self.reg.unregister_generation(&self.key, self.generation);
        }
    }
    let _unreg = UnregisterGuard {
        reg: Arc::clone(&peer_streams),
        key: remote_pk_hex.clone(),
        generation: session_generation,
    };
    // The route-registration lease becomes the lifetime lease for the exact
    // authenticated transport generation. Revoke therefore waits for the
    // SecretStream task itself to exit; a short route-map teardown timeout can
    // never be mistaken for the generation's final cancellation ACK.
    let mut session_effect = registration_effect;
    session_effect
        .validate(now_unix_secs() as i64)
        .context("membership changed while registering peeroxide route")?;

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
        // Reconnect and every loop turn re-read authority. This closes stale
        // sessions after revoke even if their passphrase proof remains valid.
        membership_grant
            .revalidate(now_unix_secs() as i64)
            .context("peeroxide membership revoked during session")?;

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
                    let mut heartbeat_permit = session_effect
                        .begin_external(now_unix_secs() as i64)
                        .context("heartbeat lost membership admission before write")?;
                    heartbeat_permit.mark_transport_may_have_started();
                    let write = tokio::select! {
                        biased;
                        _ = heartbeat_permit.cancelled() => {
                            heartbeat_permit.persist_indeterminate_if_cancelled(
                                "peeroxide_heartbeat_write_locally_aborted_without_remote_ack",
                                now_unix_secs() as i64,
                            )?;
                            anyhow::bail!(
                                "peeroxide membership generation cancelled before heartbeat write"
                            );
                        }
                        result = conn.write(&b) => result,
                    };
                    if let Err(e) = write {
                        heartbeat_permit.persist_indeterminate_if_cancelled(
                            "peeroxide_heartbeat_write_failed_during_membership_revocation",
                            now_unix_secs() as i64,
                        )?;
                        emit_peer_disconnected_wal(
                            wal_writer.as_deref(),
                            &peer_id,
                            "error",
                            Some(&e.to_string()),
                        );
                        return Err(anyhow::anyhow!("write heartbeat: {e}"));
                    }
                    if let Err(error) = heartbeat_permit.validate(now_unix_secs() as i64) {
                        heartbeat_permit.persist_indeterminate_if_cancelled(
                            "peeroxide_heartbeat_completed_without_remote_ack",
                            now_unix_secs() as i64,
                        )?;
                        return Err(error)
                            .context("membership changed before heartbeat classification");
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
                Ok(mut frame) => match membership_grant
                    .revalidate(now_unix_secs() as i64)
                    .and_then(|()| heartbeat::encode_frame(&frame))
                {
                    Ok(b) => {
                        let guard = frame
                            .effect_guard_mut()
                            .context("outbound frame omitted its membership effect lease")?;
                        let mut permit = guard
                            .begin_external(now_unix_secs() as i64)
                            .context("outbound frame lost membership admission before write")?;
                        permit.mark_transport_may_have_started();
                        let write = tokio::select! {
                            biased;
                            _ = permit.cancelled() => {
                                permit.persist_indeterminate_if_cancelled(
                                    "peeroxide_frame_write_locally_aborted_without_remote_ack",
                                    now_unix_secs() as i64,
                                )?;
                                anyhow::bail!(
                                    "peeroxide membership generation cancelled before outbound write"
                                );
                            }
                            result = conn.write(&b) => result,
                        };
                        if let Err(e) = write {
                            permit.persist_indeterminate_if_cancelled(
                                "peeroxide_frame_write_failed_during_membership_revocation",
                                now_unix_secs() as i64,
                            )?;
                            emit_peer_disconnected_wal(
                                wal_writer.as_deref(),
                                &peer_id,
                                "error",
                                Some(&e.to_string()),
                            );
                            return Err(anyhow::anyhow!("write outbound frame: {e}"));
                        }
                        if let Err(error) = permit.validate(now_unix_secs() as i64) {
                            permit.persist_indeterminate_if_cancelled(
                                "peeroxide_frame_write_completed_without_remote_ack",
                                now_unix_secs() as i64,
                            )?;
                            return Err(error).context(
                                "membership changed before outbound write classification",
                            );
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
        // Revocation is the sole safe cancellation case: the task exits and
        // drops the complete SecretStream, so a partially-read Noise frame is
        // never reused. Ordinary timers still never cancel reads.
        let read = tokio::select! {
            biased;
            _ = session_effect.cancelled() => {
                anyhow::bail!("peeroxide membership generation cancelled during live session");
            }
            changed = membership_cancel.changed() => {
                let reason = if changed.is_ok() && *membership_cancel.borrow() {
                    "peeroxide membership revoked during live session"
                } else {
                    "peeroxide membership session owner stopped"
                };
                anyhow::bail!(reason);
            }
            result = conn.read() => result,
        };
        let bytes = match read {
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
        membership_grant
            .revalidate(now_unix_secs() as i64)
            .context("membership revoked before inbound effect")?;

        // ── SL-01: intercept task frames BEFORE the sync handler (which has no
        // provider / lease / autonomy access). TaskDelegate runs the accept
        // gate + dispatches to the executor; TaskResult (we were the master) is
        // audited. Both `continue` — they never reach handle_inbound_frame.
        if frame.kind == FrameKind::TaskDelegate {
            if let FrameBody::TaskDelegate(delegate) = frame.body {
                let autonomy_policy = reload_controller.autonomy_policy();
                handle_task_delegate(
                    delegate,
                    &remote_pk_hex,
                    &own_peer_id,
                    &autonomy_policy,
                    &neoth_home,
                    wal_writer.clone(),
                    &peer_streams,
                    dispatch_tx.as_ref(),
                    &membership_grant,
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
        if frame.kind == FrameKind::GossipAck {
            if let FrameBody::GossipAck(ack) = frame.body {
                let durable = durable_mesh.clone();
                let local_origin = PeerPubkey::new(own_peer_id.clone());
                let authorized = membership_grant.clone();
                tokio::task::spawn_blocking(move || {
                    let effect = authorized.begin_effect(now_unix_secs() as i64)?;
                    let result =
                        durable.acknowledge_outbound_authorized(&effect, &local_origin, &ack)?;
                    effect.finish()?;
                    Ok::<_, anyhow::Error>(result)
                })
                .await
                .context("durable mesh ACK task panicked")??;
            }
            continue;
        }
        // GOLD-R3-09: one shared DB transaction validates order, deduplicates,
        // stores the canonical envelope, materializes typed content and advances
        // the inbound high-water mark. Only its post-COMMIT result can emit ACK.
        if frame.kind == FrameKind::Gossip {
            if let FrameBody::Gossip(gframe) = frame.body {
                let authenticated_peer =
                    PeerPubkey::new(membership_grant.stable_node_id().as_str().to_string());
                if gframe.origin != authenticated_peer {
                    tracing::warn!(
                        claimed = %gframe.origin.as_str(),
                        authenticated = %authenticated_peer.as_str(),
                        "cluster: durable gossip origin does not match active stable member"
                    );
                    continue;
                }
                let payload_et =
                    crate::cluster::wal_sync::gossip_payload_event_meta(&gframe.payload)
                        .map(|(event_type, _)| event_type);
                let durable = durable_mesh.clone();
                let frame_for_commit = gframe.clone();
                let policy = reload_controller.gossip_policy();
                let authorized = membership_grant.clone();
                let (committed, mut effect_guard) = tokio::task::spawn_blocking(move || {
                    let effect = authorized.begin_effect(now_unix_secs() as i64)?;
                    let committed =
                        durable.persist_inbound_authorized(&effect, &frame_for_commit, &policy);
                    Ok::<_, anyhow::Error>((committed, effect))
                })
                .await
                .context("durable inbound mesh task panicked")??;
                match committed {
                    Ok(commit @ super::durable_sync::InboundCommit::Committed(_))
                    | Ok(commit @ super::durable_sync::InboundCommit::Duplicate(_))
                    | Ok(commit @ super::durable_sync::InboundCommit::DuplicateUnbound(_)) => {
                        let frontier_merged =
                            super::durable_sync::merge_frontier_after_durable_commit(
                                &gossip_state,
                                &gframe,
                                &commit,
                            );
                        if !frontier_merged {
                            warn!(origin = %gframe.origin.as_str(), seq = gframe.event_seq,
                                "legacy mesh duplicate ACKed without causal-frontier merge");
                        }
                        let ack = commit
                            .ack()
                            .expect("committed/duplicate inbound has an ACK")
                            .clone();
                        emit_gossip_received_wal(wal_writer.as_deref(), &gframe, payload_et);
                        let mut ack_permit = effect_guard
                            .begin_external(now_unix_secs() as i64)
                            .context(
                                "membership changed after durable gossip commit; ACK withheld",
                            )?;
                        ack_permit.mark_transport_may_have_started();
                        let ack_frame = WireFrame {
                            kind: FrameKind::GossipAck,
                            sequence: out_seq,
                            sent_unix_ms: now_unix_ms(),
                            peer_id: own_peer_id.clone(),
                            body: FrameBody::GossipAck(ack),
                        };
                        out_seq = out_seq.wrapping_add(1);
                        let encoded = heartbeat::encode_frame(&ack_frame)
                            .context("encode durable gossip ACK")?;
                        let ack_write = tokio::select! {
                            biased;
                            _ = ack_permit.cancelled() => {
                                ack_permit.persist_indeterminate_if_cancelled(
                                    "peeroxide_gossip_ack_locally_aborted_without_remote_ack",
                                    now_unix_secs() as i64,
                                )?;
                                anyhow::bail!(
                                    "peeroxide membership generation cancelled before durable gossip ACK"
                                );
                            }
                            result = conn.write(&encoded) => result,
                        };
                        if let Err(error) = ack_write {
                            ack_permit.persist_indeterminate_if_cancelled(
                                "peeroxide_gossip_ack_write_failed_during_membership_revocation",
                                now_unix_secs() as i64,
                            )?;
                            return Err(error).context("write durable gossip ACK");
                        }
                        if let Err(error) = ack_permit.validate(now_unix_secs() as i64) {
                            ack_permit.persist_indeterminate_if_cancelled(
                                "peeroxide_gossip_ack_write_completed_without_remote_ack",
                                now_unix_secs() as i64,
                            )?;
                            return Err(error)
                                .context("membership changed before gossip ACK classification");
                        }
                        effect_guard.finish()?;
                    }
                    Ok(super::durable_sync::InboundCommit::Gap { expected, received }) => {
                        let dropped = GossipAcceptance::DroppedGap { expected, received };
                        emit_gossip_dropped_wal(wal_writer.as_deref(), &gframe, &dropped);
                        effect_guard.finish()?;
                    }
                    Ok(super::durable_sync::InboundCommit::Dropped(dropped)) => {
                        emit_gossip_dropped_wal(wal_writer.as_deref(), &gframe, &dropped);
                        effect_guard.finish()?;
                    }
                    Err(error) => {
                        tracing::warn!(%error, origin = %gframe.origin.as_str(), seq = gframe.event_seq,
                            "cluster: durable inbound commit failed — ACK withheld");
                        effect_guard.finish()?;
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
                        if let Some(prev) = last_healthy
                            && prev != b.healthy
                        {
                            emit_peer_health_changed_wal(
                                wal_writer.as_deref(),
                                &peer_id,
                                prev,
                                b.healthy,
                                b.tokens_per_sec,
                            );
                        }
                        last_healthy = Some(b.healthy);

                        if let Some(prev_hash) = last_capabilities_hash
                            && prev_hash != b.capabilities_hash
                        {
                            emit_capabilities_changed_wal(
                                wal_writer.as_deref(),
                                &peer_id,
                                &peer_capabilities,
                            );
                        }
                        last_capabilities_hash = Some(b.capabilities_hash);
                    }
                } else if kind == FrameKind::CapabilityUpdate {
                    emit_capabilities_changed_wal(
                        wal_writer.as_deref(),
                        &peer_id,
                        &peer_capabilities,
                    );
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
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_HEARTBEAT_SENT,
        payload,
    );
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
    crate::time::now_unix_secs()
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
        Decision::Allow => TaskGateOutcome::Accept {
            lease_backed: lease_active,
        },
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

/// GOLD-PROG-06 — queue the operator-facing proactive notification for an
/// accepted cluster task. The daemon drain loop (`daemon/proactive_dispatcher`)
/// gates delivery per autonomy (`Action::ProactiveChannelSend`) and routes to
/// the operator's default channel — this producer only records the fact.
/// Queue I/O is std::fs → `spawn_blocking` so the peer read loop never stalls
/// on disk. Best-effort: a queue failure must not fail the accept (the task is
/// already dispatched to the executor).
async fn notify_task_accepted(neoth_home: &std::path::Path, task_id: &str, peer_pk_hex: &str) {
    let home = neoth_home.to_path_buf();
    let task_id = task_id.to_string();
    let peer_short: String = peer_pk_hex.chars().take(16).collect();
    let join = tokio::task::spawn_blocking(move || {
        let queue_path = home.join("proactive_queue.json");
        let item = crate::proactive::ProactiveItem {
            priority: 50,
            dedup_key: format!("cluster:accept:{task_id}"),
            channel: String::new(), // operator's default channel
            source: "cluster_task_accept".to_string(),
            body: format!(
                "Cluster: task {task_id} accepted from peer {peer_short}... — running locally."
            ),
            scheduled_for_unix: 0,
            is_failure: false,
            // A day-old "accepted" notice is stale noise — expire it.
            expires_unix: (now_unix_secs() as i64).saturating_add(86_400),
        };
        // H-1: locked load→enqueue→save so a concurrent drain tick can't
        // lose this notice. `false` from enqueue = duplicate accept
        // (re-delivered frame) — prior item wins, nothing written.
        match crate::proactive::ProactiveQueue::enqueue_at(&queue_path, item) {
            Ok(true) => debug!(task_id = %task_id, "cluster: proactive accept notice queued"),
            Ok(false) => {}
            Err(e) => warn!(error = %e, task_id = %task_id,
                "cluster: proactive accept notice not persisted"),
        }
    });
    if let Err(e) = join.await {
        warn!(error = %e, "cluster: proactive accept-notice task panicked");
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
    autonomy_policy: &crate::permissions::AutonomyPolicySnapshot,
    neoth_home: &std::path::Path,
    wal_writer: ClusterWalWriter,
    peer_streams: &PeerStreamRegistry,
    dispatch_tx: Option<&tokio::sync::mpsc::Sender<ClusterTaskJob>>,
    membership_grant: &super::membership::MembershipGrant,
) {
    let task_id = body.task_id.clone();

    // Pre-checkpoint: validate the frame BEFORE spending gate work. A malformed
    // frame is rejected even from an unpaired peer.
    if let Err(e) = heartbeat::validate_task_delegate(&body) {
        debug!(error = %e, "cluster: rejecting malformed TaskDelegate");
        reply_task_rejected(
            peer_streams,
            remote_pk_hex,
            own_peer_id,
            &task_id,
            "malformed",
        );
        emit_task_rejected_wal(wal_writer.as_deref(), &task_id, remote_pk_hex, "malformed");
        return;
    }

    // Checkpoint 3 (pure, zero-cost) FIRST so a flood of frames can't force
    // disk I/O on a guaranteed-Deny path (review DoS finding). Strict ⇒ Deny ⇒
    // reject without touching the registry or lease store.
    let decision = permissions::evaluate(&Action::ClusterTaskAccept, autonomy_policy);
    if matches!(decision, Decision::Deny(_)) {
        reply_task_rejected(
            peer_streams,
            remote_pk_hex,
            own_peer_id,
            &task_id,
            "autonomy_deny",
        );
        emit_task_rejected_wal(
            wal_writer.as_deref(),
            &task_id,
            remote_pk_hex,
            "autonomy_deny",
        );
        return;
    }

    // Checkpoint 1: re-read dedicated authority. `cluster.yaml` is not an
    // authorization source and a passphrase holder is not necessarily active.
    let is_paired = membership_grant.revalidate(now_unix_secs() as i64).is_ok();

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
            let job = match ClusterTaskJob::authorized(
                task_id.clone(),
                body.prompt,
                remote_pk_hex.to_string(),
                membership_grant.clone(),
            ) {
                Ok(job) => job,
                Err(error) => {
                    warn!(
                        task_id = %task_id,
                        stable_node_id = %membership_grant.stable_node_id(),
                        %error,
                        "cluster: membership generation revoked before task queue registration"
                    );
                    reply_task_rejected(
                        peer_streams,
                        remote_pk_hex,
                        own_peer_id,
                        &task_id,
                        "membership_revoked",
                    );
                    emit_task_rejected_wal(
                        wal_writer.as_deref(),
                        &task_id,
                        remote_pk_hex,
                        "membership_revoked",
                    );
                    return;
                }
            };
            match dispatch_tx {
                Some(tx) => match tx.try_send(job) {
                    Ok(()) => {
                        emit_task_accepted_wal(
                            wal_writer.as_deref(),
                            &task_id,
                            remote_pk_hex,
                            lease_backed,
                            autonomy_policy.level(),
                        );
                        notify_task_accepted(neoth_home, &task_id, remote_pk_hex).await;
                    }
                    // Full ⇒ an inference is already running (bounded(1)) — back
                    // off. Closed ⇒ the executor task died (panic) — surface it
                    // as a DISTINCT, operator-visible reason rather than hiding
                    // a dead executor behind "busy" (review finding).
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        reply_task_rejected(
                            peer_streams,
                            remote_pk_hex,
                            own_peer_id,
                            &task_id,
                            "busy",
                        );
                        emit_task_rejected_wal(
                            wal_writer.as_deref(),
                            &task_id,
                            remote_pk_hex,
                            "busy",
                        );
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
    tokio::task::spawn_blocking(
        move || match crate::permissions::lease::LeaseStore::load(&path) {
            Ok(store) => store.active_for(
                &subject,
                &crate::permissions::lease::LeaseScope::ClusterTaskAccept,
                now,
            ),
            Err(_) => false,
        },
    )
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
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_TASK_ACCEPTED,
        payload,
    );
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
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_TASK_REJECTED,
        payload,
    );
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
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_GOSSIP_RECEIVED,
        payload,
    );
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
        GossipAcceptance::DroppedProtocolVersion { .. } => "protocol_version",
        GossipAcceptance::DroppedContentDigest => "content_digest",
        GossipAcceptance::DroppedGap { .. } => "sequence_gap",
    };
    let payload = serde_json::json!({
        "origin_peer": frame.origin.as_str(),
        "event_seq": frame.event_seq,
        "reason": reason,
        "ts_unix": now_unix_secs(),
    })
    .to_string()
    .into_bytes();
    fire_wal(
        w,
        crate::wal::events::EVENT_TYPE_CLUSTER_GOSSIP_DROPPED,
        payload,
    );
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
/// flush; caller pairs with [`receive_hello`]. Test-only: the
/// production handshake is `handle_peeroxide_connection` (fail-closed
/// on the cluster_key proof — this helper carries none).
#[cfg(test)]
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
/// `#[cfg(test)]` ON PURPOSE (SL-00(1b) review, tightened from
/// pub(crate) in the dead-code sweep): this is a `tokio::io::duplex`
/// test primitive that does NOT verify the `cluster_key_proof`. The production
/// handshake runs through `handle_peeroxide_connection`, which is fail-closed
/// on the proof. Test-gating prevents a future caller from
/// standing up an unauthenticated Hello exchange.
#[cfg(test)]
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
        FrameBody::TaskDelegate(_)
        | FrameBody::TaskResult(_)
        | FrameBody::Gossip(_)
        | FrameBody::GossipAck(_) => {
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
    crate::time::now_unix_ms()
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
    fn public_rendezvous_join_is_server_only() {
        let options = server_only_join_opts();
        assert!(options.server);
        assert!(!options.client);
    }

    #[test]
    fn public_rendezvous_requires_and_wires_the_expected_remote_static_key() {
        let expected = [0x5au8; 32];
        let config = public_rendezvous_config(expected);
        assert_eq!(config.server_expected_remote_static_key, Some(expected));
    }

    #[tokio::test]
    async fn public_bootstrap_wait_returns_ready_without_constructing_a_dht() {
        let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
        let outcome = wait_for_bootstrap_or_stop(
            async { Ok::<_, &'static str>("bootstrapped") },
            &mut shutdown,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;

        assert!(matches!(outcome, BootstrapWait::Ready(Ok("bootstrapped"))));
    }

    #[tokio::test]
    async fn public_bootstrap_wait_prioritizes_persistent_shutdown_without_constructing_a_dht() {
        let (shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
        shutdown_tx.send(true).expect("shutdown receiver is live");
        let outcome = wait_for_bootstrap_or_stop(
            std::future::pending::<std::result::Result<(), &'static str>>(),
            &mut shutdown,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;

        assert!(matches!(outcome, BootstrapWait::CancelledOrExpired));
    }

    #[tokio::test]
    async fn public_bootstrap_wait_rejects_an_expired_deadline_without_constructing_a_dht() {
        let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
        let outcome = wait_for_bootstrap_or_stop(
            std::future::pending::<std::result::Result<(), &'static str>>(),
            &mut shutdown,
            tokio::time::Instant::now() - std::time::Duration::from_millis(1),
        )
        .await;

        assert!(matches!(outcome, BootstrapWait::CancelledOrExpired));
    }

    #[tokio::test]
    async fn startup_cleanup_aborts_and_awaits_a_stuck_task() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("cleanup target started");

        assert!(
            !await_or_abort_startup_task(task, "test", std::time::Duration::from_millis(10)).await
        );

        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .expect("aborted task was awaited")
            .expect("drop signal sent");
    }

    #[tokio::test]
    async fn owned_peer_sessions_release_wal_senders_on_shutdown() {
        let home = tempfile::tempdir().unwrap();
        let (writer, writer_join) =
            crate::wal::writer::spawn(home.path().join("peer-session-shutdown.wal")).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let held_writer = writer.clone();
        let mut sessions = PeerSessions::default();
        sessions.spawn(async move {
            let _held_writer = held_writer;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), started_rx)
            .await
            .expect("owned peer session never started")
            .expect("owned peer session dropped its start signal");

        drop(writer);
        tokio::time::timeout(std::time::Duration::from_secs(3), sessions.shutdown())
            .await
            .expect("peer-session JoinSet shutdown did not await cancellation");
        tokio::time::timeout(std::time::Duration::from_secs(3), writer_join)
            .await
            .expect("peer session retained its WAL sender after shutdown")
            .expect("WAL writer task panicked");
    }

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
            TaskGateOutcome::Accept {
                lease_backed: false
            }
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

    // ── GOLD-PROG-06 — proactive accept notice ──────────────────────────────

    #[tokio::test]
    async fn notify_task_accepted_enqueues_once_and_dedups_redelivery() {
        let home = tempfile::tempdir().expect("tempdir");
        let peer = "ab".repeat(32);
        notify_task_accepted(home.path(), "t-42", &peer).await;
        notify_task_accepted(home.path(), "t-42", &peer).await; // re-delivered frame

        let q =
            crate::proactive::ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .expect("queue readable");
        let items = q.peek();
        assert_eq!(
            items.len(),
            1,
            "duplicate accept dedups on cluster:accept:<task_id>"
        );
        let item = &items[0];
        assert_eq!(item.source, "cluster_task_accept");
        assert_eq!(item.dedup_key, "cluster:accept:t-42");
        assert!(
            item.body.contains("t-42"),
            "body names the task: {}",
            item.body
        );
        assert!(
            !item.body.contains(&peer),
            "full peer key never reaches the operator channel"
        );
        assert!(
            item.expires_unix > 0,
            "accept notice must expire, not linger"
        );
        assert!(
            item.channel.is_empty(),
            "routes to the operator default channel"
        );

        // A different task queues alongside.
        notify_task_accepted(home.path(), "t-43", &peer).await;
        let q2 =
            crate::proactive::ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .expect("queue readable");
        assert_eq!(q2.peek().len(), 2);
    }
}
