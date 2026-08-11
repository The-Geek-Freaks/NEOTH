use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::hyperdht_messages::{
    self, HandshakeMessage, HolepunchMessage, MODE_FROM_CLIENT, MODE_FROM_RELAY,
    MODE_FROM_SECOND_RELAY, MODE_FROM_SERVER, MODE_REPLY,
};
use crate::messages::Ipv4Peer;

const DEFAULT_FORWARD_TTL: Duration = Duration::from_secs(20 * 60);
/// Hard cap for routing entries learned from remote announces plus explicit
/// local-server registrations.  Admission rejects new targets after GC rather
/// than discarding a live route that was already authorized/registered.
const MAX_FORWARD_ENTRIES: usize = 4_096;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RouterError {
    #[error("bad handshake reply")]
    BadHandshakeReply,
    #[error("bad holepunch reply")]
    BadHolepunchReply,
    #[error("encoding error: {0}")]
    Encoding(#[from] crate::compact_encoding::EncodingError),
}

pub type Result<T> = std::result::Result<T, RouterError>;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HandshakeResult {
    pub noise: Vec<u8>,
    /// Whether the caller intentionally sent the handshake through a relay.
    pub relayed: bool,
    /// Locally selected request destination: direct server for `connect_to`,
    /// otherwise the relay. Reply metadata never replaces this value.
    pub server_address: Ipv4Peer,
    /// The DHT node that returned the reply; this may be a relay.
    pub client_address: Ipv4Peer,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HolepunchResult {
    pub from: Ipv4Peer,
    pub to: Ipv4Peer,
    pub payload: Vec<u8>,
    pub peer_address: Ipv4Peer,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HandshakeAction {
    Reply(Vec<u8>),
    Relay { value: Vec<u8>, to: Ipv4Peer },
    HandleLocally(HandshakeMessage),
    CloserNodes,
    Drop,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HolepunchAction {
    Reply { value: Vec<u8>, to: Ipv4Peer },
    Relay { value: Vec<u8>, to: Ipv4Peer },
    HandleLocally {
        msg: HolepunchMessage,
        peer_address: Ipv4Peer,
    },
    Drop,
}

#[non_exhaustive]
pub struct ForwardEntry {
    pub relay: Option<Ipv4Peer>,
    pub has_server: bool,
    pub inserted: Instant,
}

pub struct Router {
    forwards: HashMap<[u8; 32], ForwardEntry>,
    ttl: Duration,
}

impl Router {
    pub fn new() -> Self {
        Self {
            forwards: HashMap::new(),
            ttl: DEFAULT_FORWARD_TTL,
        }
    }

    /// Insert or refresh a route.
    ///
    /// A refresh of an existing target remains possible at capacity. A new
    /// target is rejected once GC has reclaimed everything expired, preventing
    /// unauthenticated network traffic from growing this map without bound.
    pub fn set(&mut self, target: &[u8; 32], entry: ForwardEntry) -> bool {
        self.gc();

        if let Some(existing) = self.forwards.get_mut(target) {
            *existing = entry;
            return true;
        }

        if self.forwards.len() >= MAX_FORWARD_ENTRIES {
            return false;
        }

        self.forwards.insert(*target, entry);
        true
    }

    pub fn get(&self, target: &[u8; 32]) -> Option<&ForwardEntry> {
        let entry = self.forwards.get(target)?;
        // Server entries (local listeners) never expire — they persist until
        // explicitly removed via `delete()` / `unregister_server()`.  Only
        // forwarded announce entries are subject to TTL expiry.  This matches
        // Node.js where server entries use `retain` and live as long as the
        // server is active.
        if !entry.has_server && entry.inserted.elapsed() > self.ttl {
            return None;
        }
        Some(entry)
    }

    pub fn delete(&mut self, target: &[u8; 32]) {
        self.forwards.remove(target);
    }

    pub fn gc(&mut self) {
        self.forwards
            .retain(|_, entry| entry.has_server || entry.inserted.elapsed() <= self.ttl);
    }

    pub fn validate_handshake_reply(
        &self,
        reply_value: &[u8],
        expected_from: &Ipv4Peer,
        actual_from: &Ipv4Peer,
        relayed: bool,
    ) -> Result<HandshakeResult> {
        let hs = hyperdht_messages::decode_handshake_from_bytes(reply_value)
            .map_err(|_| RouterError::BadHandshakeReply)?;

        if hs.mode != MODE_REPLY
            || expected_from.host != actual_from.host
            || expected_from.port != actual_from.port
            || hs.noise.is_empty()
        {
            return Err(RouterError::BadHandshakeReply);
        }

        Ok(HandshakeResult {
            noise: hs.noise,
            relayed,
            // Reply peer metadata is not endpoint authority. The caller's
            // chosen request destination is the only locally correlated
            // address available at this layer.
            server_address: expected_from.clone(),
            client_address: actual_from.clone(),
        })
    }

    pub fn validate_holepunch_reply(
        &self,
        reply_value: &[u8],
        expected_from: &Ipv4Peer,
        actual_from: &Ipv4Peer,
        actual_to: &Ipv4Peer,
    ) -> Result<HolepunchResult> {
        let hp = hyperdht_messages::decode_holepunch_msg_from_bytes(reply_value)
            .map_err(|_| RouterError::BadHolepunchReply)?;

        if hp.mode != MODE_REPLY
            || expected_from.host != actual_from.host
            || expected_from.port != actual_from.port
        {
            return Err(RouterError::BadHolepunchReply);
        }

        let peer_address = hp.peer_address.unwrap_or_else(|| expected_from.clone());

        Ok(HolepunchResult {
            from: actual_from.clone(),
            to: actual_to.clone(),
            payload: hp.payload,
            peer_address,
        })
    }

    pub fn encode_client_handshake(
        noise: Vec<u8>,
        peer_address: Option<Ipv4Peer>,
        relay_address: Option<Ipv4Peer>,
    ) -> Result<Vec<u8>> {
        let msg = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise,
            peer_address,
            relay_address,
        };
        Ok(hyperdht_messages::encode_handshake_to_bytes(&msg)?)
    }

    pub fn encode_client_holepunch(
        id: u64,
        payload: Vec<u8>,
        peer_address: Option<Ipv4Peer>,
    ) -> Result<Vec<u8>> {
        let msg = HolepunchMessage {
            mode: MODE_FROM_CLIENT,
            id,
            payload,
            peer_address,
        };
        Ok(hyperdht_messages::encode_holepunch_msg_to_bytes(&msg)?)
    }

    pub fn route_handshake(
        &self,
        target: Option<&[u8; 32]>,
        from: &Ipv4Peer,
        value: &[u8],
    ) -> Result<HandshakeAction> {
        let hs = match hyperdht_messages::decode_handshake_from_bytes(value) {
            Ok(h) => h,
            Err(_) => return Ok(HandshakeAction::Drop),
        };

        let state = target.and_then(|t| self.get(t));
        let is_server = state.is_some_and(|s| s.has_server);
        let relay = state.and_then(|s| s.relay.clone());

        if is_server {
            match hs.mode {
                MODE_FROM_CLIENT | MODE_FROM_RELAY | MODE_FROM_SECOND_RELAY => {
                    Ok(HandshakeAction::HandleLocally(hs))
                }
                _ => Ok(HandshakeAction::Drop),
            }
        } else {
            match hs.mode {
                MODE_FROM_CLIENT => {
                    if hs.noise.is_empty() {
                        return Ok(HandshakeAction::Drop);
                    }
                    // `relay_address` was decoded from the packet and is only
                    // protocol metadata.  It must not become an arbitrary UDP
                    // egress target: a client can otherwise turn this node into
                    // an unauthenticated relay/SSRF primitive.  Only the
                    // locally-resolved route for the requested target is trusted
                    // to select an outbound relay destination.
                    match relay {
                        Some(target_addr) => {
                            let relayed = HandshakeMessage {
                                mode: MODE_FROM_RELAY,
                                noise: hs.noise,
                                peer_address: Some(from.clone()),
                                relay_address: None,
                            };
                            let encoded =
                                hyperdht_messages::encode_handshake_to_bytes(&relayed)?;
                            Ok(HandshakeAction::Relay {
                                value: encoded,
                                to: target_addr,
                            })
                        }
                        None => Ok(HandshakeAction::CloserNodes),
                    }
                }
                MODE_FROM_RELAY => {
                    let Some(relay_addr) = relay else {
                        return Ok(HandshakeAction::Drop);
                    };
                    if hs.noise.is_empty() {
                        return Ok(HandshakeAction::Drop);
                    }
                    let relayed = HandshakeMessage {
                        mode: MODE_FROM_SECOND_RELAY,
                        noise: hs.noise,
                        peer_address: hs.peer_address,
                        relay_address: Some(from.clone()),
                    };
                    let encoded = hyperdht_messages::encode_handshake_to_bytes(&relayed)?;
                    Ok(HandshakeAction::Relay {
                        value: encoded,
                        to: relay_addr,
                    })
                }
                MODE_FROM_SERVER => {
                    let Some(_peer_address) = hs.peer_address else {
                        return Ok(HandshakeAction::Drop);
                    };
                    let Some(to) = relay else {
                        return Ok(HandshakeAction::Drop);
                    };
                    if hs.noise.is_empty() {
                        return Ok(HandshakeAction::Drop);
                    }
                    let reply = HandshakeMessage {
                        mode: MODE_REPLY,
                        noise: hs.noise,
                        peer_address: Some(from.clone()),
                        relay_address: None,
                    };
                    let encoded = hyperdht_messages::encode_handshake_to_bytes(&reply)?;
                    // `peer_address` is wire metadata, not egress authority.
                    // A reply can leave only through a locally-resolved route
                    // for this target, which also binds the reply to a prior
                    // locally admitted forwarding correlation.
                    Ok(HandshakeAction::Relay { value: encoded, to })
                }
                _ => Ok(HandshakeAction::Drop),
            }
        }
    }

    pub fn route_holepunch(
        &self,
        target: Option<&[u8; 32]>,
        from: &Ipv4Peer,
        value: &[u8],
    ) -> Result<HolepunchAction> {
        let hp = match hyperdht_messages::decode_holepunch_msg_from_bytes(value) {
            Ok(h) => h,
            Err(_) => return Ok(HolepunchAction::Drop),
        };

        let state = target.and_then(|t| self.get(t));
        let is_server = state.is_some_and(|s| s.has_server);
        let relay = state.and_then(|s| s.relay.clone());

        match hp.mode {
            MODE_FROM_CLIENT => {
                // Same authority boundary as the handshake path: the wire
                // `peer_address` remains part of the relayed protocol message,
                // but cannot choose where this node emits UDP.  That decision is
                // made exclusively by locally-maintained forward state.
                let Some(to) = relay else {
                    return Ok(HolepunchAction::Drop);
                };
                let relayed = HolepunchMessage {
                    mode: MODE_FROM_RELAY,
                    id: hp.id,
                    payload: hp.payload,
                    peer_address: Some(from.clone()),
                };
                let encoded = hyperdht_messages::encode_holepunch_msg_to_bytes(&relayed)?;
                Ok(HolepunchAction::Relay {
                    value: encoded,
                    to,
                })
            }
            MODE_FROM_RELAY => {
                if !is_server {
                    return Ok(HolepunchAction::Drop);
                }
                let Some(peer_address) = hp.peer_address.clone() else {
                    return Ok(HolepunchAction::Drop);
                };
                Ok(HolepunchAction::HandleLocally {
                    msg: hp,
                    peer_address,
                })
            }
            MODE_FROM_SERVER => {
                let Some(_peer_address) = hp.peer_address else {
                    return Ok(HolepunchAction::Drop);
                };
                let Some(to) = relay else {
                    return Ok(HolepunchAction::Drop);
                };
                let reply = HolepunchMessage {
                    mode: MODE_REPLY,
                    id: hp.id,
                    payload: hp.payload,
                    peer_address: Some(from.clone()),
                };
                let encoded = hyperdht_messages::encode_holepunch_msg_to_bytes(&reply)?;
                // The server's packet-supplied peer address is metadata only.
                // Reply egress is bound to locally maintained forwarding state.
                Ok(HolepunchAction::Reply { value: encoded, to })
            }
            _ => Ok(HolepunchAction::Drop),
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(host: &str, port: u16) -> Ipv4Peer {
        Ipv4Peer {
            host: host.into(),
            port,
        }
    }

    fn target_key() -> [u8; 32] {
        [0xaa; 32]
    }

    #[test]
    fn forward_cache_set_get_delete() {
        let mut router = Router::new();
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: Some(peer("1.2.3.4", 1000)),
                has_server: false,
                inserted: Instant::now(),
            },
        );

        assert!(router.get(&key).is_some());
        router.delete(&key);
        assert!(router.get(&key).is_none());
    }

    #[test]
    fn forward_cache_expires() {
        let mut router = Router::new();
        router.ttl = Duration::from_millis(1);
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: None,
                has_server: false,
                inserted: Instant::now() - Duration::from_secs(1),
            },
        );

        assert!(router.get(&key).is_none());
    }

    #[test]
    fn gc_removes_expired() {
        let mut router = Router::new();
        router.ttl = Duration::from_millis(1);
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: None,
                has_server: false,
                inserted: Instant::now() - Duration::from_secs(1),
            },
        );

        assert_eq!(router.forwards.len(), 1);
        router.gc();
        assert_eq!(router.forwards.len(), 0);
    }

    #[test]
    fn forward_cache_is_bounded_refreshable_and_recovers_after_gc() {
        let mut router = Router::new();

        // More than the hard cap of unique, live forwarding targets must not
        // grow the map or evict an existing route.
        for index in 0..MAX_FORWARD_ENTRIES {
            let mut target = [0u8; 32];
            target[..8].copy_from_slice(&(index as u64).to_le_bytes());
            assert!(router.set(
                &target,
                ForwardEntry {
                    relay: Some(peer("1.2.3.4", 1000)),
                    has_server: false,
                    inserted: Instant::now(),
                },
            ));
        }
        assert_eq!(router.forwards.len(), MAX_FORWARD_ENTRIES);

        let mut refresh_target = [0u8; 32];
        refresh_target[..8].copy_from_slice(&0u64.to_le_bytes());

        let mut overflow_target = [0u8; 32];
        overflow_target[..8].copy_from_slice(&(MAX_FORWARD_ENTRIES as u64).to_le_bytes());
        assert!(!router.set(
            &overflow_target,
            ForwardEntry {
                relay: Some(peer("2.3.4.5", 2000)),
                has_server: false,
                inserted: Instant::now(),
            },
        ));
        assert_eq!(router.forwards.len(), MAX_FORWARD_ENTRIES);
        assert!(router.get(&overflow_target).is_none());
        assert!(
            router.get(&refresh_target).is_some(),
            "a rejected new target must not evict an existing live route"
        );

        // Refreshing a live target at capacity is accepted rather than
        // failing or evicting a different route.
        assert!(router.set(
            &refresh_target,
            ForwardEntry {
                relay: Some(peer("3.4.5.6", 3000)),
                has_server: false,
                inserted: Instant::now(),
            },
        ));
        assert_eq!(router.forwards.len(), MAX_FORWARD_ENTRIES);

        // Expire the refreshed entry without reading it, then GC releases
        // exactly that slot for the previously rejected target.
        router
            .forwards
            .get_mut(&refresh_target)
            .unwrap()
            .inserted = Instant::now() - router.ttl - Duration::from_secs(1);
        router.gc();
        assert_eq!(router.forwards.len(), MAX_FORWARD_ENTRIES - 1);
        assert!(router.set(
            &overflow_target,
            ForwardEntry {
                relay: Some(peer("2.3.4.5", 2000)),
                has_server: false,
                inserted: Instant::now(),
            },
        ));
        assert_eq!(router.forwards.len(), MAX_FORWARD_ENTRIES);
    }

    #[test]
    fn forward_entry_persists_within_20_min_ttl() {
        let mut router = Router::new();
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: Some(peer("5.5.5.5", 2000)),
                has_server: false,
                inserted: Instant::now() - Duration::from_secs(19 * 60),
            },
        );

        assert!(
            router.get(&key).is_some(),
            "entry should persist within 20-minute TTL"
        );
    }

    #[test]
    fn forward_entry_expires_after_20_min_ttl() {
        let mut router = Router::new();
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: Some(peer("5.5.5.5", 2000)),
                has_server: false,
                inserted: Instant::now() - Duration::from_secs(21 * 60),
            },
        );

        assert!(
            router.get(&key).is_none(),
            "entry should expire after 20-minute TTL"
        );
    }

    #[test]
    fn forward_entry_refresh_extends_lifetime() {
        let mut router = Router::new();
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: Some(peer("5.5.5.5", 2000)),
                has_server: false,
                inserted: Instant::now() - Duration::from_secs(21 * 60),
            },
        );
        assert!(router.get(&key).is_none());

        router.set(
            &key,
            ForwardEntry {
                relay: Some(peer("5.5.5.5", 2000)),
                has_server: false,
                inserted: Instant::now(),
            },
        );
        assert!(
            router.get(&key).is_some(),
            "re-announced entry should be accessible again"
        );
    }

    #[test]
    fn gc_preserves_fresh_entries() {
        let mut router = Router::new();
        let key1 = [0x11; 32];
        let key2 = [0x22; 32];

        router.set(
            &key1,
            ForwardEntry {
                relay: Some(peer("1.1.1.1", 100)),
                has_server: false,
                inserted: Instant::now(),
            },
        );
        router.set(
            &key2,
            ForwardEntry {
                relay: Some(peer("2.2.2.2", 200)),
                has_server: false,
                inserted: Instant::now() - Duration::from_secs(21 * 60),
            },
        );

        router.gc();
        assert!(router.get(&key1).is_some(), "fresh entry should survive gc");
        assert_eq!(router.forwards.len(), 1, "expired entry should be removed by gc");
    }

    #[test]
    fn default_ttl_matches_nodejs_20_minutes() {
        let router = Router::new();
        assert_eq!(router.ttl, Duration::from_secs(20 * 60));
    }

    #[test]
    fn server_entry_never_expires_on_ttl() {
        let mut router = Router::new();
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: None,
                has_server: true,
                inserted: Instant::now() - Duration::from_secs(60 * 60),
            },
        );

        assert!(
            router.get(&key).is_some(),
            "server entry must survive past TTL"
        );
    }

    #[test]
    fn server_entry_survives_gc() {
        let mut router = Router::new();
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: None,
                has_server: true,
                inserted: Instant::now() - Duration::from_secs(60 * 60),
            },
        );

        router.gc();
        assert_eq!(
            router.forwards.len(),
            1,
            "server entry must survive gc"
        );
    }

    #[test]
    fn server_entry_routes_handshake_after_ttl() {
        let mut router = Router::new();
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: None,
                has_server: true,
                inserted: Instant::now() - Duration::from_secs(60 * 60),
            },
        );

        let client_hs = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise: vec![10, 20, 30],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&client_hs).unwrap();

        let action = router
            .route_handshake(Some(&key), &peer("2.3.4.5", 3000), &encoded)
            .unwrap();
        assert!(
            matches!(action, HandshakeAction::HandleLocally(_)),
            "server entry must still route handshakes after TTL expiry window"
        );
    }

    #[test]
    fn server_entry_removed_by_delete() {
        let mut router = Router::new();
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: None,
                has_server: true,
                inserted: Instant::now(),
            },
        );

        assert!(router.get(&key).is_some());
        router.delete(&key);
        assert!(
            router.get(&key).is_none(),
            "delete() must remove server entries (unregister lifecycle)"
        );
        assert_eq!(router.forwards.len(), 0);
    }

    #[test]
    fn validate_handshake_reply_good() {
        let reply_msg = HandshakeMessage {
            mode: MODE_REPLY,
            noise: vec![1, 2, 3],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&reply_msg).unwrap();
        let from = peer("1.2.3.4", 1000);

        let router = Router::new();
        let result = router
            .validate_handshake_reply(&encoded, &from, &from, false)
            .unwrap();
        assert_eq!(result.noise, vec![1, 2, 3]);
        assert!(!result.relayed);
        assert_eq!(result.server_address.host, "1.2.3.4");
    }

    #[test]
    fn handshake_reply_peer_metadata_never_replaces_request_destination() {
        let expected = peer("198.51.100.10", 49737);
        let reply_msg = HandshakeMessage {
            mode: MODE_REPLY,
            noise: vec![1, 2, 3],
            // A server must omit this unless it has a real locally observed
            // endpoint, but even a malicious value cannot make the client
            // self-connect or nominate an egress target.
            peer_address: Some(peer("192.0.2.44", 53)),
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&reply_msg).unwrap();
        let router = Router::new();

        let direct = router
            .validate_handshake_reply(&encoded, &expected, &expected, false)
            .unwrap();
        assert!(!direct.relayed);
        assert_eq!(direct.server_address, expected);

        let relayed = router
            .validate_handshake_reply(&encoded, &expected, &expected, true)
            .unwrap();
        assert!(relayed.relayed);
        assert_eq!(relayed.server_address, expected);
    }

    #[test]
    fn validate_handshake_reply_wrong_mode() {
        let reply_msg = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise: vec![1, 2, 3],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&reply_msg).unwrap();
        let from = peer("1.2.3.4", 1000);

        let router = Router::new();
        assert!(
            router
                .validate_handshake_reply(&encoded, &from, &from, false)
                .is_err()
        );
    }

    #[test]
    fn validate_handshake_reply_wrong_from() {
        let reply_msg = HandshakeMessage {
            mode: MODE_REPLY,
            noise: vec![1, 2, 3],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&reply_msg).unwrap();

        let router = Router::new();
        assert!(
            router
                .validate_handshake_reply(
                    &encoded,
                    &peer("1.2.3.4", 1000),
                    &peer("5.6.7.8", 2000),
                    false,
                )
                .is_err()
        );
    }

    #[test]
    fn route_handshake_client_to_relay() {
        let mut router = Router::new();
        let key = target_key();
        router.set(
            &key,
            ForwardEntry {
                relay: Some(peer("9.9.9.9", 5000)),
                has_server: false,
                inserted: Instant::now(),
            },
        );

        let client_hs = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise: vec![10, 20, 30],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&client_hs).unwrap();
        let from = peer("2.3.4.5", 3000);

        let action = router.route_handshake(Some(&key), &from, &encoded).unwrap();
        match action {
            HandshakeAction::Relay { value, to } => {
                assert_eq!(to.host, "9.9.9.9");
                assert_eq!(to.port, 5000);
                let decoded = hyperdht_messages::decode_handshake_from_bytes(&value).unwrap();
                assert_eq!(decoded.mode, MODE_FROM_RELAY);
                assert_eq!(decoded.peer_address.unwrap().host, "2.3.4.5");
            }
            other => panic!("Expected Relay, got {other:?}"),
        }
    }

    #[test]
    fn route_handshake_local_server_handles_locally() {
        let mut router = Router::new();
        let key = target_key();
        router.set(
            &key,
            ForwardEntry {
                relay: None,
                has_server: true,
                inserted: Instant::now(),
            },
        );

        let client_hs = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise: vec![10, 20, 30],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&client_hs).unwrap();

        let action = router
            .route_handshake(Some(&key), &peer("2.3.4.5", 3000), &encoded)
            .unwrap();
        match action {
            HandshakeAction::HandleLocally(hs) => {
                assert_eq!(hs.noise, vec![10, 20, 30]);
            }
            other => panic!("Expected HandleLocally, got {other:?}"),
        }
    }

    #[test]
    fn route_handshake_relayed_to_local_server() {
        let mut router = Router::new();
        let key = target_key();
        router.set(
            &key,
            ForwardEntry {
                relay: None,
                has_server: true,
                inserted: Instant::now(),
            },
        );

        let relayed_hs = HandshakeMessage {
            mode: MODE_FROM_RELAY,
            noise: vec![40, 50],
            peer_address: Some(peer("1.1.1.1", 2000)),
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&relayed_hs).unwrap();

        let action = router
            .route_handshake(Some(&key), &peer("9.9.9.9", 5000), &encoded)
            .unwrap();
        match action {
            HandshakeAction::HandleLocally(hs) => {
                assert_eq!(hs.noise, vec![40, 50]);
                assert_eq!(hs.peer_address.unwrap().host, "1.1.1.1");
            }
            other => panic!("Expected HandleLocally for relay-to-server, got {other:?}"),
        }
    }

    #[test]
    fn route_handshake_self_announce_then_relay() {
        let mut router = Router::new();
        let pk_hash = [0xbb; 32];

        router.set(
            &pk_hash,
            ForwardEntry {
                relay: Some(peer("10.0.0.5", 4000)),
                has_server: false,
                inserted: Instant::now(),
            },
        );

        let client_hs = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise: vec![1, 2, 3, 4],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&client_hs).unwrap();

        let action = router
            .route_handshake(Some(&pk_hash), &peer("8.8.8.8", 6000), &encoded)
            .unwrap();
        match action {
            HandshakeAction::Relay { to, .. } => {
                assert_eq!(to.host, "10.0.0.5");
                assert_eq!(to.port, 4000);
            }
            other => panic!("Expected Relay to server via self-announce entry, got {other:?}"),
        }
    }

    #[test]
    fn route_handshake_expired_entry_falls_through() {
        let mut router = Router::new();
        router.ttl = Duration::from_millis(1);
        let key = target_key();

        router.set(
            &key,
            ForwardEntry {
                relay: Some(peer("9.9.9.9", 5000)),
                has_server: false,
                inserted: Instant::now() - Duration::from_secs(1),
            },
        );

        let client_hs = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise: vec![10, 20, 30],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&client_hs).unwrap();

        let action = router
            .route_handshake(Some(&key), &peer("2.3.4.5", 3000), &encoded)
            .unwrap();
        assert!(matches!(action, HandshakeAction::CloserNodes));
    }

    #[test]
    fn route_handshake_client_no_relay_closer_nodes() {
        let router = Router::new();
        let key = target_key();

        let client_hs = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise: vec![10, 20, 30],
            peer_address: None,
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&client_hs).unwrap();

        let action = router
            .route_handshake(Some(&key), &peer("2.3.4.5", 3000), &encoded)
            .unwrap();
        assert!(matches!(action, HandshakeAction::CloserNodes));
    }

    #[test]
    fn route_handshake_client_relay_address_cannot_select_udp_egress() {
        let mut router = Router::new();
        let key = target_key();
        let victim = peer("192.0.2.44", 53);
        let client_hs = HandshakeMessage {
            mode: MODE_FROM_CLIENT,
            noise: vec![10, 20, 30],
            peer_address: None,
            relay_address: Some(victim.clone()),
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&client_hs).unwrap();
        let from = peer("2.3.4.5", 3000);

        // A packet-supplied relay address alone must never produce a UDP relay.
        let action = router.route_handshake(Some(&key), &from, &encoded).unwrap();
        assert!(matches!(action, HandshakeAction::CloserNodes));

        // The same address becomes eligible only after local routing state has
        // independently resolved it for this target.
        assert!(router.set(
            &key,
            ForwardEntry {
                relay: Some(victim.clone()),
                has_server: false,
                inserted: Instant::now(),
            },
        ));
        let action = router.route_handshake(Some(&key), &from, &encoded).unwrap();
        match action {
            HandshakeAction::Relay { to, .. } => assert_eq!(to, victim),
            other => panic!("Expected Relay through trusted local route, got {other:?}"),
        }
    }

    #[test]
    fn route_handshake_server_peer_address_requires_local_forward_correlation() {
        let mut router = Router::new();
        let key = target_key();
        let from = peer("5.5.5.5", 7000);
        let victim = peer("192.0.2.46", 443);
        let trusted_relay = peer("198.51.100.10", 4000);

        let server_hs = HandshakeMessage {
            mode: MODE_FROM_SERVER,
            noise: vec![1, 2],
            peer_address: Some(victim.clone()),
            relay_address: None,
        };
        let encoded = hyperdht_messages::encode_handshake_to_bytes(&server_hs).unwrap();

        // A packet-supplied client address cannot induce a reply relay.
        let action = router.route_handshake(None, &from, &encoded).unwrap();
        assert!(matches!(action, HandshakeAction::Drop));

        // A previously admitted local route for this exact DHT target is the
        // sole authority for reply egress, even when packet metadata differs.
        assert!(router.set(
            &key,
            ForwardEntry {
                relay: Some(trusted_relay.clone()),
                has_server: false,
                inserted: Instant::now(),
            },
        ));
        let action = router.route_handshake(Some(&key), &from, &encoded).unwrap();
        match action {
            HandshakeAction::Relay { value, to } => {
                assert_eq!(to, trusted_relay);
                assert_ne!(to, victim);
                let decoded = hyperdht_messages::decode_handshake_from_bytes(&value).unwrap();
                assert_eq!(decoded.mode, MODE_REPLY);
                assert_eq!(decoded.peer_address.unwrap().host, "5.5.5.5");
            }
            other => panic!("Expected Relay through trusted local route, got {other:?}"),
        }
    }

    #[test]
    fn route_holepunch_client_to_relay() {
        let mut router = Router::new();
        let key = target_key();
        router.set(
            &key,
            ForwardEntry {
                relay: Some(peer("9.9.9.9", 5000)),
                has_server: false,
                inserted: Instant::now(),
            },
        );

        let client_hp = HolepunchMessage {
            mode: MODE_FROM_CLIENT,
            id: 42,
            payload: vec![0xaa, 0xbb],
            peer_address: None,
        };
        let encoded = hyperdht_messages::encode_holepunch_msg_to_bytes(&client_hp).unwrap();

        let action = router
            .route_holepunch(Some(&key), &peer("2.3.4.5", 3000), &encoded)
            .unwrap();
        match action {
            HolepunchAction::Relay { value, to } => {
                assert_eq!(to.host, "9.9.9.9");
                let decoded = hyperdht_messages::decode_holepunch_msg_from_bytes(&value).unwrap();
                assert_eq!(decoded.mode, MODE_FROM_RELAY);
                assert_eq!(decoded.id, 42);
                assert_eq!(decoded.peer_address.unwrap().host, "2.3.4.5");
            }
            other => panic!("Expected Relay, got {other:?}"),
        }
    }

    #[test]
    fn route_holepunch_client_peer_address_cannot_select_udp_egress() {
        let mut router = Router::new();
        let key = target_key();
        let victim = peer("192.0.2.45", 123);
        let client_hp = HolepunchMessage {
            mode: MODE_FROM_CLIENT,
            id: 42,
            payload: vec![0xaa, 0xbb],
            peer_address: Some(victim.clone()),
        };
        let encoded = hyperdht_messages::encode_holepunch_msg_to_bytes(&client_hp).unwrap();
        let from = peer("2.3.4.5", 3000);

        // A packet-supplied peer address alone must never produce a UDP relay.
        let action = router.route_holepunch(Some(&key), &from, &encoded).unwrap();
        assert!(matches!(action, HolepunchAction::Drop));

        // The same address becomes eligible only after local routing state has
        // independently resolved it for this target.
        assert!(router.set(
            &key,
            ForwardEntry {
                relay: Some(victim.clone()),
                has_server: false,
                inserted: Instant::now(),
            },
        ));
        let action = router.route_holepunch(Some(&key), &from, &encoded).unwrap();
        match action {
            HolepunchAction::Relay { to, .. } => assert_eq!(to, victim),
            other => panic!("Expected Relay through trusted local route, got {other:?}"),
        }
    }

    #[test]
    fn route_holepunch_server_peer_address_requires_local_forward_correlation() {
        let mut router = Router::new();
        let key = target_key();
        let victim = peer("192.0.2.47", 161);
        let trusted_relay = peer("198.51.100.11", 5000);

        let server_hp = HolepunchMessage {
            mode: MODE_FROM_SERVER,
            id: 99,
            payload: vec![0xcc],
            peer_address: Some(victim.clone()),
        };
        let encoded = hyperdht_messages::encode_holepunch_msg_to_bytes(&server_hp).unwrap();

        // A packet-supplied client address cannot induce a reply relay.
        let action = router
            .route_holepunch(None, &peer("5.5.5.5", 7000), &encoded)
            .unwrap();
        assert!(matches!(action, HolepunchAction::Drop));

        // A previously admitted local route for this exact DHT target is the
        // sole authority for reply egress, even when packet metadata differs.
        assert!(router.set(
            &key,
            ForwardEntry {
                relay: Some(trusted_relay.clone()),
                has_server: false,
                inserted: Instant::now(),
            },
        ));
        let action = router
            .route_holepunch(Some(&key), &peer("5.5.5.5", 7000), &encoded)
            .unwrap();
        match action {
            HolepunchAction::Reply { value, to } => {
                assert_eq!(to, trusted_relay);
                assert_ne!(to, victim);
                let decoded = hyperdht_messages::decode_holepunch_msg_from_bytes(&value).unwrap();
                assert_eq!(decoded.mode, MODE_REPLY);
                assert_eq!(decoded.id, 99);
            }
            other => panic!("Expected Reply through trusted local route, got {other:?}"),
        }
    }

    #[test]
    fn validate_holepunch_reply_good() {
        let reply_msg = HolepunchMessage {
            mode: MODE_REPLY,
            id: 1,
            payload: vec![0xdd],
            peer_address: None,
        };
        let encoded = hyperdht_messages::encode_holepunch_msg_to_bytes(&reply_msg).unwrap();
        let from = peer("1.2.3.4", 1000);
        let to = peer("5.6.7.8", 2000);

        let router = Router::new();
        let result = router
            .validate_holepunch_reply(&encoded, &from, &from, &to)
            .unwrap();
        assert_eq!(result.payload, vec![0xdd]);
        assert_eq!(result.peer_address.host, "1.2.3.4");
    }

    #[test]
    fn encode_client_handshake_roundtrip() {
        let encoded =
            Router::encode_client_handshake(vec![1, 2, 3], None, None).unwrap();
        let decoded = hyperdht_messages::decode_handshake_from_bytes(&encoded).unwrap();
        assert_eq!(decoded.mode, MODE_FROM_CLIENT);
        assert_eq!(decoded.noise, vec![1, 2, 3]);
    }

    #[test]
    fn encode_client_holepunch_roundtrip() {
        let encoded =
            Router::encode_client_holepunch(42, vec![0xaa], Some(peer("1.2.3.4", 1000)))
                .unwrap();
        let decoded = hyperdht_messages::decode_holepunch_msg_from_bytes(&encoded).unwrap();
        assert_eq!(decoded.mode, MODE_FROM_CLIENT);
        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.peer_address.unwrap().host, "1.2.3.4");
    }
}
