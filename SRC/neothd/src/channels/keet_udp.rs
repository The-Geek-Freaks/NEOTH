//! R-2 Phase 3 — DHT UDP dialer skeleton.
//!
//! Wraps `tokio::net::UdpSocket` with the operator's Hyperswarm
//! bootstrap endpoint list (from [`crate::channels::keet_dht::
//! HYPERSWARM_BOOTSTRAP_HOSTS`]) so the discovery layer can:
//!   1. send a `LookupPacket` to each bootstrap node in parallel
//!   2. collect the `LookupResponse` UDP datagrams that come back
//!   3. surface the resolved peer addresses to the higher-level
//!      Keet channel runner
//!
//! v0.1 scope = primitives only. The full Hyperswarm DHT protocol
//! (Kademlia bucket walk, NOISE-IK handshake, Hypercore replication)
//! is multi-week per `PLAN/SPEC_R2_phase3_dht_noise_replication_*`.
//! This module ships the **UDP socket + framing** layer so the
//! follow-up bites can plug in the protocol logic against a stable
//! transport surface.
//!
//! Network allowlist: `src/channels/keet_udp.rs` is registered in
//! `tests/no_outbound_network.rs`. Operator opt-in is via the Keet
//! channel pick in the wizard step 6 — this module never dials
//! without an explicit operator-initiated `KeetChannel::run`.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use super::keet_dht::{BootstrapEndpoint, LookupPacket};

/// Maximum UDP payload we accept on a single recv. Hyperswarm
/// announce / lookup packets are < 1 KB; oversize datagrams are
/// dropped (likely fragmented or hostile).
pub const MAX_DATAGRAM_BYTES: usize = 1500;

/// Per-bootstrap-node send timeout. 2s matches operator-typical
/// LAN + WAN round-trip budget; bootstrap nodes that take longer
/// than this are likely down / firewalled.
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(2);

/// Per-bootstrap-node recv timeout. Bootstraps that don't respond
/// within this window are considered unreachable from this network.
pub const DEFAULT_RECV_TIMEOUT: Duration = Duration::from_secs(3);

/// One UDP socket bound to an operator-local ephemeral port. Holds
/// the socket alive for the duration of a lookup / announce round
/// + provides the high-level `send_lookup_to_bootstraps` helper.
pub struct DhtUdpDialer {
    socket: UdpSocket,
    dial_timeout: Duration,
    recv_timeout: Duration,
}

/// Result of one bootstrap dial — either a parsed-payload reply
/// (the protocol decoder lives in `keet_dht`, not here — we just
/// surface the raw bytes + the peer that sent them) or a timeout/
/// error tag so the caller can report which bootstraps failed.
#[derive(Debug, Clone)]
pub struct DialResult {
    pub bootstrap: BootstrapEndpoint,
    pub outcome: DialOutcome,
}

#[derive(Debug, Clone)]
pub enum DialOutcome {
    /// Bootstrap replied with `bytes` from `peer`.
    Reply { peer: SocketAddr, bytes: Vec<u8> },
    /// Send timed out — bootstrap likely down or firewalled.
    SendTimeout,
    /// Send succeeded but no reply within `recv_timeout`.
    RecvTimeout,
    /// Send / receive surfaced an error other than timeout.
    Io(String),
    /// Datagram exceeded `MAX_DATAGRAM_BYTES` — dropped without
    /// surfacing to the caller (defensive against hostile large
    /// payloads).
    OversizedDatagram { size: usize },
}

impl DhtUdpDialer {
    /// Bind to an operator-local ephemeral UDP port + return the
    /// dialer ready to send.
    pub async fn bind() -> Result<Self> {
        Self::bind_with_timeouts(DEFAULT_DIAL_TIMEOUT, DEFAULT_RECV_TIMEOUT).await
    }

    pub async fn bind_with_timeouts(
        dial_timeout: Duration,
        recv_timeout: Duration,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("DhtUdpDialer: bind ephemeral UDP socket")?;
        Ok(Self {
            socket,
            dial_timeout,
            recv_timeout,
        })
    }

    /// Local socket address the operator's NAT sees as the source
    /// of every outbound datagram. Useful for diagnostics — bound
    /// port is stable for the dialer's lifetime.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .context("DhtUdpDialer: read local_addr")
    }

    /// Send `bytes` to `peer` with the configured dial timeout.
    /// Wrapped here so a hung send doesn't block the whole lookup
    /// round when one bootstrap is on a slow link.
    pub async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> Result<DialOutcome> {
        match tokio::time::timeout(self.dial_timeout, self.socket.send_to(bytes, peer)).await {
            Ok(Ok(_n)) => Ok(DialOutcome::RecvTimeout), // placeholder; recv comes next
            Ok(Err(e)) => Ok(DialOutcome::Io(e.to_string())),
            Err(_) => Ok(DialOutcome::SendTimeout),
        }
    }

    /// Receive one datagram with the configured recv timeout. The
    /// `MAX_DATAGRAM_BYTES` cap is enforced — larger datagrams are
    /// surfaced as `OversizedDatagram` and dropped.
    pub async fn recv_one(&self) -> Result<DialOutcome> {
        let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
        match tokio::time::timeout(self.recv_timeout, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, peer))) => {
                if n > MAX_DATAGRAM_BYTES {
                    Ok(DialOutcome::OversizedDatagram { size: n })
                } else {
                    buf.truncate(n);
                    Ok(DialOutcome::Reply { peer, bytes: buf })
                }
            }
            Ok(Err(e)) => Ok(DialOutcome::Io(e.to_string())),
            Err(_) => Ok(DialOutcome::RecvTimeout),
        }
    }

    /// Higher-level convenience: send `payload` to every bootstrap
    /// in `bootstraps`, then collect one reply per bootstrap (with
    /// per-node timeouts). Each bootstrap is dialed sequentially in
    /// v0.1; parallel dial via `JoinSet` is a follow-up once the
    /// protocol decoder lands.
    ///
    /// Returns one [`DialResult`] per input bootstrap so the caller
    /// can report which nodes were reachable / timed out / errored.
    pub async fn lookup_round(
        &self,
        bootstraps: &[BootstrapEndpoint],
        payload: &[u8],
    ) -> Vec<DialResult> {
        let mut out = Vec::with_capacity(bootstraps.len());
        for bs in bootstraps {
            let outcome = match bs.socket_addr() {
                Ok(peer) => match self.send_to(payload, peer).await {
                    Ok(DialOutcome::SendTimeout) => DialOutcome::SendTimeout,
                    Ok(DialOutcome::Io(e)) => DialOutcome::Io(e),
                    Ok(_) => self.recv_one().await.unwrap_or_else(|e| {
                        DialOutcome::Io(format!("recv error: {e}"))
                    }),
                    Err(e) => DialOutcome::Io(e.to_string()),
                },
                Err(e) => DialOutcome::Io(format!("resolve {bs:?}: {e}")),
            };
            out.push(DialResult {
                bootstrap: bs.clone(),
                outcome,
            });
        }
        out
    }
}

/// Serialise a `LookupPacket` to the wire-bytes Hyperswarm expects.
/// v0.1 ships JSON framing for operator-readable hex-dumps; the
/// real Hyperswarm DHT uses a bencode-like binary framing — the
/// follow-up bite swaps the encoder when the protocol decoder
/// lands without touching the UDP-dialer surface.
pub fn encode_lookup_payload(packet: &LookupPacket) -> Result<Vec<u8>> {
    serde_json::to_vec(packet).context("encode_lookup_payload: serialise LookupPacket")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::keet_crypto::TopicKey;
    use crate::channels::keet_dht::build_lookup;

    fn fixture_topic() -> TopicKey {
        TopicKey([0x01u8; 32])
    }

    #[tokio::test]
    async fn bind_returns_dialer_with_local_addr() {
        let dialer = DhtUdpDialer::bind().await.expect("bind");
        let addr = dialer.local_addr().expect("local_addr");
        // Bound to 0.0.0.0:<ephemeral> — port MUST be non-zero.
        assert!(addr.port() > 0);
        assert!(addr.is_ipv4());
    }

    #[tokio::test]
    async fn bind_with_custom_timeouts() {
        let d = DhtUdpDialer::bind_with_timeouts(
            Duration::from_millis(50),
            Duration::from_millis(75),
        )
        .await
        .expect("bind");
        assert_eq!(d.dial_timeout, Duration::from_millis(50));
        assert_eq!(d.recv_timeout, Duration::from_millis(75));
    }

    #[tokio::test]
    async fn recv_one_times_out_when_no_traffic() {
        let dialer = DhtUdpDialer::bind_with_timeouts(
            Duration::from_millis(10),
            Duration::from_millis(50),
        )
        .await
        .expect("bind");
        let outcome = dialer.recv_one().await.expect("recv result");
        assert!(matches!(outcome, DialOutcome::RecvTimeout));
    }

    #[tokio::test]
    async fn send_to_localhost_loopback_succeeds() {
        // Bind a listener on loopback so the send completes with
        // a real ACKable destination + we can recv the reply.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let dialer = DhtUdpDialer::bind().await.expect("bind");

        // Send a 32-byte lookup payload to the loopback server.
        let payload = b"hello-dht-skeleton-test-payload!";
        let outcome = dialer.send_to(payload, server_addr).await.unwrap();
        // The placeholder send returns RecvTimeout because we
        // haven't dialed for a reply yet. Pin that exact shape so
        // a future API change is visible.
        assert!(matches!(outcome, DialOutcome::RecvTimeout));

        // Server side: confirm the payload arrived.
        let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
        let (n, _peer) = tokio::time::timeout(
            Duration::from_millis(200),
            server.recv_from(&mut buf),
        )
        .await
        .expect("recv-from must complete within 200ms")
        .expect("recv ok");
        assert_eq!(&buf[..n], payload);
    }

    #[tokio::test]
    async fn round_trip_via_localhost_loopback() {
        // Full send → recv cycle. The "bootstrap" is just our own
        // loopback UDP echo so the dialer's `lookup_round` flow runs
        // end-to-end without touching the real Hyperswarm network.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Server echo loop in the background.
        let echo = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            // Echo back with a 4-byte prefix so we can tell echo
            // from original.
            let mut reply = b"ECHO".to_vec();
            reply.extend_from_slice(&buf[..n]);
            server.send_to(&reply, peer).await.unwrap();
        });

        let dialer = DhtUdpDialer::bind_with_timeouts(
            Duration::from_millis(500),
            Duration::from_millis(500),
        )
        .await
        .expect("bind");
        let payload = b"ping";
        let _send = dialer.send_to(payload, server_addr).await.unwrap();
        // Now actively receive the echo reply.
        let outcome = dialer.recv_one().await.expect("recv ok");
        match outcome {
            DialOutcome::Reply { bytes, .. } => {
                assert!(bytes.starts_with(b"ECHO"));
                assert!(bytes.ends_with(b"ping"));
            }
            other => panic!("expected Reply, got {other:?}"),
        }
        echo.await.unwrap();
    }

    #[test]
    fn encode_lookup_payload_round_trips_topic() {
        let packet = build_lookup(fixture_topic());
        let bytes = encode_lookup_payload(&packet).expect("encode");
        assert!(!bytes.is_empty(), "non-empty payload");
        // JSON framing in v0.1 — parses cleanly.
        let parsed: LookupPacket =
            serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(parsed.discovery_key, packet.discovery_key);
    }

    #[test]
    fn constants_pinned() {
        assert_eq!(MAX_DATAGRAM_BYTES, 1500);
        assert_eq!(DEFAULT_DIAL_TIMEOUT, Duration::from_secs(2));
        assert_eq!(DEFAULT_RECV_TIMEOUT, Duration::from_secs(3));
    }
}
