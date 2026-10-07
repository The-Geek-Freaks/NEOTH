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
    /// Terminal outcomes of the two server publications required to accept a
    /// routed peer handshake. This carries no key, address, or DHT error.
    ServerPublicationComplete {
        topic: [u8; 32],
        topic_announce_succeeded: bool,
        key_announce_succeeded: bool,
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
    if !initial_refresh_completed_before_cancel(
        do_refresh(&config, &dht, &key_pair, &relay_addresses, &event_tx),
        &mut cancel_rx,
    )
    .await
    {
        return;
    }

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

/// Run the first refresh unless this topic has already been left.
///
/// A server refresh emits its terminal publication receipt only after both
/// topic and self-route announcements return. Once leave has retired the
/// topic, dropping an in-flight first refresh prevents that stale receipt (and
/// its diagnostics) from outliving the route that owns it.
async fn initial_refresh_completed_before_cancel<F>(
    refresh: F,
    cancel_rx: &mut tokio::sync::oneshot::Receiver<()>,
) -> bool
where
    F: std::future::Future,
{
    tokio::select! {
        biased;
        _ = cancel_rx => false,
        _ = refresh => true,
    }
}

/// Start the two independent server publications together and retain each
/// terminal outcome for the strict combined receipt.
async fn await_both_announcements<Topic, Key>(
    topic_announce: Topic,
    key_announce: Key,
) -> (Topic::Output, Key::Output)
where
    Topic: std::future::Future,
    Key: std::future::Future,
{
    tokio::join!(topic_announce, key_announce)
}

async fn do_refresh(
    config: &PeerDiscoveryConfig,
    dht: &HyperDhtHandle,
    key_pair: &KeyPair,
    relay_addresses: &[Ipv4Peer],
    event_tx: &mpsc::Sender<DiscoveryEvent>,
) {
    if config.is_server {
        // Self-announce: announce hash(publicKey) so that nodes closest to our
        // public key store a ForwardEntry. This is how PEER_HANDSHAKE requests
        // get routed — Node.js does this in persistent.js announce().
        let pk_target = hash(&key_pair.public_key);
        let (topic_announce, key_announce) = await_both_announcements(
            async {
                match dht.announce(config.topic, key_pair, relay_addresses).await {
                    Ok(r) => {
                        tracing::debug!(closest = r.closest_nodes.len(), "announce complete");
                        true
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "announce failed");
                        false
                    }
                }
            },
            async {
                match dht.announce(pk_target, key_pair, relay_addresses).await {
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
                }
            },
        )
        .await;

        companion_discovery_phase(if topic_announce {
            "server_topic_announce_succeeded"
        } else {
            "server_topic_announce_failed"
        });
        companion_discovery_phase(if key_announce {
            "server_key_announce_succeeded"
        } else {
            "server_key_announce_failed"
        });

        companion_discovery_phase(if topic_announce && key_announce {
            "announce_success"
        } else {
            "announce_failure"
        });

        // Keep generic refresh completion separate from publication truth:
        // callers that need an inbound PEER_HANDSHAKE route must observe both
        // terminal outcomes, while ordinary flush users keep their established
        // "first refresh completed" semantics below.
        let _ = event_tx
            .send(DiscoveryEvent::ServerPublicationComplete {
                topic: config.topic,
                topic_announce_succeeded: topic_announce,
                key_announce_succeeded: key_announce,
            })
            .await;
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
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

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

    #[tokio::test]
    async fn server_announcements_start_together_wait_for_both_and_keep_split_outcomes() {
        let (topic_entered_tx, topic_entered_rx) = tokio::sync::oneshot::channel();
        let (key_entered_tx, key_entered_rx) = tokio::sync::oneshot::channel();
        let (topic_release_tx, topic_release_rx) = tokio::sync::oneshot::channel();
        let (key_release_tx, key_release_rx) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(await_both_announcements(
            async move {
                let _ = topic_entered_tx.send(());
                topic_release_rx
                    .await
                    .expect("topic publication release remains live")
            },
            async move {
                let _ = key_entered_tx.send(());
                key_release_rx
                    .await
                    .expect("self-route publication release remains live")
            },
        ));

        tokio::time::timeout(Duration::from_secs(3), async {
            topic_entered_rx
                .await
                .expect("topic publication must start before any release");
            key_entered_rx
                .await
                .expect("self-route publication must start before any release");
        })
        .await
        .expect("both publications must enter before either release within the fixture deadline");
        topic_release_tx
            .send(true)
            .expect("topic publication waiter remains live");
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "one completed announcement must not produce a combined receipt"
        );
        key_release_tx
            .send(false)
            .expect("self-route publication waiter remains live");

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), waiter)
                .await
                .expect("both released announcements complete within the fixture deadline")
                .expect("combined announcement helper must not panic"),
            (true, false),
            "the split result remains explicit for the existing strict readiness gate"
        );
    }

    #[tokio::test]
    async fn initial_refresh_cancellation_drops_both_pending_server_announcements() {
        struct RefreshDropProbe(Arc<AtomicBool>);

        impl Drop for RefreshDropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
        let (topic_entered_tx, topic_entered_rx) = tokio::sync::oneshot::channel();
        let (key_entered_tx, key_entered_rx) = tokio::sync::oneshot::channel();
        let topic_dropped = Arc::new(AtomicBool::new(false));
        let key_dropped = Arc::new(AtomicBool::new(false));
        let topic_dropped_by_refresh = Arc::clone(&topic_dropped);
        let key_dropped_by_refresh = Arc::clone(&key_dropped);
        let waiter = tokio::spawn(async move {
            initial_refresh_completed_before_cancel(
                await_both_announcements(
                    async move {
                        let _probe = RefreshDropProbe(topic_dropped_by_refresh);
                        let _ = topic_entered_tx.send(());
                        std::future::pending::<bool>().await
                    },
                    async move {
                        let _probe = RefreshDropProbe(key_dropped_by_refresh);
                        let _ = key_entered_tx.send(());
                        std::future::pending::<bool>().await
                    },
                ),
                &mut cancel_rx,
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(3), async {
            topic_entered_rx
                .await
                .expect("topic publication must be polling before cancellation");
            key_entered_rx
                .await
                .expect("self-route publication must be polling before cancellation");
        })
        .await
        .expect("both publications must enter before cancellation within the fixture deadline");
        cancel_tx
            .send(())
            .expect("both pending publications keep the cancellation receiver live");

        assert!(
            !tokio::time::timeout(Duration::from_secs(3), waiter)
                .await
                .expect("cancelled announcements settle within the fixture deadline")
                .expect("initial refresh/cancellation waiter must not panic"),
            "route cancellation wins and suppresses the stale first-refresh completion"
        );
        assert!(
            topic_dropped.load(Ordering::SeqCst) && key_dropped.load(Ordering::SeqCst),
            "cancellation drops both pending publications before a late receipt can be emitted"
        );
    }
}
