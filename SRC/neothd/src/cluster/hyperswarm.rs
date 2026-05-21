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
//! let registry = Arc::new(Mutex::new(PeerLoadRegistry::new()));
//! let handle = hyperswarm::spawn_discovery("my-cluster", Arc::clone(&registry)).await?;
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
//! - [`spawn_discovery`] — bring up the swarm, join the
//!   topic, spawn the peer-acceptor loop. Returns the
//!   handle.
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
use tracing::{debug, info, warn};

use super::heartbeat::{
    self, FrameBody, FrameKind, HeartbeatBody, HelloBody, WireFrame, PROTOCOL_NAME,
    PROTOCOL_VERSION,
};
use super::{PeerId, PeerLoad, PeerLoadRegistry};

/// Derive a 32-byte Hyperswarm topic from an operator-supplied
/// cluster name. Pure function — operator-facing wire form is
/// the cluster name string; peeroxide hashes it via
/// `discovery_key` (BLAKE2b under the hood) so two daemons
/// configured with the same name find each other.
pub fn derive_topic(cluster_name: &str) -> [u8; 32] {
    peeroxide::discovery_key(cluster_name.as_bytes())
}

/// RAII handle to a running Hyperswarm discovery task. Drop
/// aborts the background task (best-effort — peeroxide's
/// internal connections shut down lazily on the next tick).
pub struct SwarmHandle {
    join: Option<tokio::task::JoinHandle<()>>,
}

impl SwarmHandle {
    /// Explicit shutdown — aborts the discovery task and
    /// awaits its termination. Use over Drop when the caller
    /// wants synchronous teardown (test cleanup, daemon SIGTERM
    /// path).
    pub async fn shutdown(mut self) -> Result<()> {
        let Some(handle) = self.join.take() else {
            return Ok(());
        };
        handle.abort();
        match handle.await {
            Ok(()) => Ok(()),
            Err(e) if e.is_cancelled() => Ok(()),
            Err(e) => anyhow::bail!("hyperswarm task panic: {e}"),
        }
    }
}

impl Drop for SwarmHandle {
    fn drop(&mut self) {
        if let Some(h) = self.join.take() {
            h.abort();
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
pub async fn spawn_discovery(
    cluster_name: &str,
    _registry: Arc<Mutex<PeerLoadRegistry>>,
) -> Result<SwarmHandle> {
    let topic = derive_topic(cluster_name);
    let config = peeroxide::SwarmConfig::with_public_bootstrap();
    let (_swarm_task, handle, mut conn_rx) = peeroxide::spawn(config)
        .await
        .context("peeroxide::spawn — bring up Hyperswarm")?;

    handle
        .join(topic, peeroxide::JoinOpts::default())
        .await
        .with_context(|| format!("peeroxide join topic for cluster `{cluster_name}`"))?;

    info!(
        cluster = cluster_name,
        topic_hex = %hex_encode(&topic),
        "hyperswarm: announced + listening on topic"
    );

    let join = tokio::spawn(async move {
        while let Some(conn) = conn_rx.recv().await {
            let peer_hex = hex_encode(conn.remote_public_key());
            debug!(peer = %peer_hex, "hyperswarm: peer connected");
            // TODO follow-up: spawn heartbeat protocol task,
            //   write to registry on receive. Today we just
            //   log + drop the connection so peeroxide cleans
            //   it up.
            drop(conn);
        }
        warn!("hyperswarm: connection receiver closed — discovery loop exiting");
    });

    Ok(SwarmHandle { join: Some(join) })
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
pub async fn send_hello<W: AsyncWrite + Unpin>(
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
pub async fn receive_hello<R: AsyncRead + Unpin>(
    source: &mut R,
    expected_cluster_name: &str,
) -> Result<(String, HelloBody)> {
    let frame = heartbeat::read_framed(source)
        .await
        .context("read peer Hello frame")?;
    if frame.kind != FrameKind::Hello {
        anyhow::bail!(
            "peer first frame was {:?}, expected Hello",
            frame.kind
        );
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
        peer: PeerId::new(peer_id),
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
                let msg = e.to_string();
                // EOF on a clean peer disconnect surfaces as an
                // io error; surface as Ok so the caller's
                // accept-loop doesn't treat clean shutdown as
                // a failure to retry against.
                if msg.contains("read frame len-prefix") {
                    info!(peer_id, "hyperswarm: peer disconnected");
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
        WireFrame, PROTOCOL_NAME, PROTOCOL_VERSION,
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
            heartbeat::write_framed(&mut sender, &goodbye).await.unwrap();
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

    #[test]
    fn now_unix_ms_is_monotonic_within_call_horizon() {
        let a = now_unix_ms();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = now_unix_ms();
        assert!(b >= a, "monotonic within process lifetime");
    }
}
