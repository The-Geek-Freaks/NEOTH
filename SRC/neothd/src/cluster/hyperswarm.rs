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

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::PeerLoadRegistry;

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
}
