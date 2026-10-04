use std::fmt;
use std::time::Duration;

use rand::Rng;
use tokio::sync::mpsc;

use peeroxide_dht::crypto::hash;
use peeroxide_dht::hyperdht::{HyperDhtHandle, KeyPair};
use peeroxide_dht::messages::Ipv4Peer;

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(4).fold(String::new(), |mut s, b| {
        fmt::Write::write_fmt(&mut s, format_args!("{b:02x}")).ok();
        s
    })
}

/// 10-minute refresh interval, matching Node.js `REFRESH_INTERVAL`.
const REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// Up to 2-minute random jitter added to refresh interval.
const REFRESH_JITTER_MS: u64 = 120_000;

/// One discovery lookup can return an attacker-controlled list of relay
/// candidates.  Keep the per-peer payload bounded before it reaches the swarm
/// actor, even when the actor's event queue has spare capacity.
const MAX_RELAY_ADDRESSES_PER_PEER: usize = 8;
const MAX_LOOKUP_RESULTS: usize = 32;
const MAX_PEERS_PER_LOOKUP_RESULT: usize = 256;

const COMPANION_DIAGNOSTICS_ENV: &str = "NEOTH_COMPANION_DIAGNOSTICS";

/// Emits only a fixed, secret-free discovery outcome while the explicit
/// companion diagnostic mode is enabled. Callers emit once per bounded
/// refresh operation, never once per untrusted peer, topic, key, endpoint,
/// payload, or error.
fn companion_discovery_phase(phase: &str) {
    if std::env::var(COMPANION_DIAGNOSTICS_ENV).as_deref() == Ok("1") {
        eprintln!("NEOTH_COMPANION_DISCOVERY_PHASE={phase}");
    }
}

pub(crate) enum DiscoveryEvent {
    PeerFound {
        public_key: [u8; 32],
        relay_addresses: Vec<Ipv4Peer>,
        topic: [u8; 32],
    },
    RefreshComplete {
        topic: [u8; 32],
    },
}

pub(crate) struct PeerDiscoveryConfig {
    pub topic: [u8; 32],
    pub is_server: bool,
    pub is_client: bool,
}

pub(crate) async fn run_discovery(
    config: PeerDiscoveryConfig,
    dht: HyperDhtHandle,
    key_pair: KeyPair,
    relay_addresses: Vec<Ipv4Peer>,
    event_tx: mpsc::Sender<DiscoveryEvent>,
    mut cancel_rx: tokio::sync::oneshot::Receiver<()>,
) {
    do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx).await;

    loop {
        let jitter_ms = rand::rng().random_range(0..REFRESH_JITTER_MS);
        let delay = REFRESH_INTERVAL + Duration::from_millis(jitter_ms);

        tokio::select! {
            _ = tokio::time::sleep(delay) => {
                do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx).await;
            }
            _ = &mut cancel_rx => break,
        }
    }
}

async fn do_refresh(
    config: &PeerDiscoveryConfig,
    dht: &HyperDhtHandle,
    key_pair: &KeyPair,
    relay_addresses: &[Ipv4Peer],
    event_tx: &mpsc::Sender<DiscoveryEvent>,
) {
    if config.is_server {
        let topic_announce = match dht.announce(config.topic, key_pair, relay_addresses).await {
            Ok(r) => {
                tracing::debug!(closest = r.closest_nodes.len(), "announce complete");
                true
            }
            Err(e) => {
                tracing::warn!(err = %e, "announce failed");
                false
            }
        };

        // Self-announce: announce hash(publicKey) so that nodes closest to our
        // public key store a ForwardEntry. This is how PEER_HANDSHAKE requests
        // get routed — Node.js does this in persistent.js announce().
        let pk_target = hash(&key_pair.public_key);
        let key_announce = match dht.announce(pk_target, key_pair, relay_addresses).await {
            Ok(r) => {
                tracing::debug!(
                    closest = r.closest_nodes.len(),
                    "self-announce (hash(pk)) complete"
                );
                true
            }
            Err(e) => {
                tracing::warn!(err = %e, "self-announce (hash(pk)) failed");
                false
            }
        };

        companion_discovery_phase(if topic_announce && key_announce {
            "announce_success"
        } else {
            "announce_failure"
        });
    }

    if config.is_client {
        match dht.lookup(config.topic).await {
            Ok(results) => {
                let mut found_peer = false;
                for result in results.into_iter().take(MAX_LOOKUP_RESULTS) {
                    tracing::debug!(
                        from = %format!("{}:{}", result.from.host, result.from.port),
                        peer_count = result.peers.len(),
                        "lookup result"
                    );
                    for peer in result.peers.into_iter().take(MAX_PEERS_PER_LOOKUP_RESULT) {
                        found_peer = true;
                        tracing::debug!(
                            pk = %hex_short(&peer.public_key),
                            relay_count = peer.relay_addresses.len(),
                            "discovered peer"
                        );
                        let relay_addresses = if peer.relay_addresses.is_empty() {
                            vec![result.from.clone()]
                        } else {
                            peer.relay_addresses
                                .into_iter()
                                .take(MAX_RELAY_ADDRESSES_PER_PEER)
                                .collect()
                        };
                        // Peer discoveries are best-effort.  Waiting here
                        // would let one maliciously large lookup result pin a
                        // discovery task behind a full actor queue; dropping
                        // excess candidates is safe because the next refresh
                        // re-advertises live peers.
                        let _ = event_tx.try_send(DiscoveryEvent::PeerFound {
                            public_key: peer.public_key,
                            relay_addresses,
                            topic: config.topic,
                        });
                    }
                }
                companion_discovery_phase(if found_peer {
                    "lookup_peers"
                } else {
                    "lookup_none"
                });
            }
            Err(e) => {
                tracing::warn!(err = %e, "lookup failed");
                companion_discovery_phase("lookup_failure");
            }
        }
    }

    // Flush callers depend on this state transition, so unlike best-effort
    // peer candidates it is delivered with bounded backpressure.
    let _ = event_tx
        .send(DiscoveryEvent::RefreshComplete {
            topic: config.topic,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_address_limit_is_hard_and_deterministic() {
        let peers: Vec<_> = (0..(MAX_RELAY_ADDRESSES_PER_PEER + 3))
            .map(|port| Ipv4Peer {
                host: "127.0.0.1".to_owned(),
                port: port as u16,
            })
            .collect();

        let capped: Vec<_> = peers
            .into_iter()
            .take(MAX_RELAY_ADDRESSES_PER_PEER)
            .collect();
        assert_eq!(capped.len(), MAX_RELAY_ADDRESSES_PER_PEER);
        assert_eq!(capped[0].port, 0);
        assert_eq!(
            capped[MAX_RELAY_ADDRESSES_PER_PEER - 1].port,
            (MAX_RELAY_ADDRESSES_PER_PEER - 1) as u16
        );
    }
}
