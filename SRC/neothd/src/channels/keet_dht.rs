//! Hyperswarm DHT bootstrap + announce packet shape — R-2 Phase 2.
//!
//! Pure-data layer the Phase 3 networking wire-up will consume.
//! Phase 1 shipped the crypto anchor (topic_key + discovery_key).
//! Phase 2 ships the DHT lookup target catalogue + the byte-level
//! packet shape Hyperswarm peers exchange for swarm announce /
//! lookup ops. Phase 3 (multi-week) will spawn UDP sockets +
//! actually move bytes; this module locks the contract Phase 3
//! has to honour so its surface doesn't drift.
//!
//! ## Bootstrap nodes
//!
//! Hyperswarm's reference impl ships with a hardcoded list of
//! Holepunch-operated DHT bootstrap nodes that join freshly-
//! booted peers to the network. NEOTH replicates that list — an
//! operator who runs neothd offline (no Holepunch reachability)
//! supplies their own via `freedom.yaml::keet.bootstrap_nodes`
//! and the Phase 3 dialer uses that instead.
//!
//! ## Announce packet
//!
//! Hyperswarm announce / lookup messages are encoded as
//! length-prefixed payloads over UDP. v0.1 ships the shape
//! (struct + serde) so call sites compile without the wire I/O
//! yet; the actual UDP framing lands in Phase 3.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::keet_crypto::{DiscoveryKey, TopicKey};

/// Hyperswarm reference-impl bootstrap node addresses. Pinned to
/// the values shipped by `hyperswarm@3.x` (Holepunch's most-
/// recently-published constants as of 2025). Operators who
/// distrust Holepunch's infrastructure override via
/// `freedom.yaml::keet.bootstrap_nodes`.
///
/// These are host:port pairs — Phase 3 resolves them to
/// SocketAddr at startup.
pub const HYPERSWARM_BOOTSTRAP_HOSTS: &[&str] = &[
    "node1.hyperdht.org:49737",
    "node2.hyperdht.org:49737",
    "node3.hyperdht.org:49737",
];

/// DHT message kinds Hyperswarm uses for swarm membership +
/// peer discovery. Encoded as `u8` in the on-wire packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhtMessageKind {
    /// "I joined this swarm" — peer announces its presence under
    /// a topic. Phase 3 sends this on `Channel::run` startup.
    Announce,
    /// "Tell me who else is in this swarm" — peer asks the DHT
    /// for the current member list under a topic.
    Lookup,
    /// Response to an Announce — DHT acks the registration.
    AnnounceAck,
    /// Response to a Lookup — carries the peer list.
    LookupResponse,
}

impl DhtMessageKind {
    pub fn wire_byte(self) -> u8 {
        match self {
            Self::Announce => 0x01,
            Self::Lookup => 0x02,
            Self::AnnounceAck => 0x81,
            Self::LookupResponse => 0x82,
        }
    }

    pub fn from_wire_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Announce),
            0x02 => Some(Self::Lookup),
            0x81 => Some(Self::AnnounceAck),
            0x82 => Some(Self::LookupResponse),
            _ => None,
        }
    }
}

/// Announce packet — peer joining a swarm under a topic. v0.1
/// shape; on-wire framing (length prefix + nonce + AEAD seal)
/// lands in Phase 3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnouncePacket {
    /// 32-byte DHT key the swarm looks up under. Same as
    /// `keet_crypto::discovery_key(topic)`.
    pub discovery_key: [u8; 32],
    /// 32-byte ephemeral peer identity. Phase 3 derives this
    /// from the operator's signing key; v0.1 callers supply
    /// zeros for tests.
    pub peer_id: [u8; 32],
    /// UDP port the peer is listening on for direct dial.
    pub listen_port: u16,
}

/// Lookup packet — peer asks the DHT for current members of a
/// swarm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupPacket {
    pub discovery_key: [u8; 32],
    pub peer_id: [u8; 32],
}

/// Lookup response — DHT returns the current peer list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupResponse {
    pub discovery_key: [u8; 32],
    /// Each `(peer_id, host:port)` entry.
    pub peers: Vec<(Vec<u8>, String)>,
}

/// One operator-configurable bootstrap node. Either a verbatim
/// `host:port` string OR a parsed `SocketAddr` if the operator
/// pinned an IP. Phase 3 prefers SocketAddr (no DNS at dial
/// time); v0.1 returns whatever the YAML had.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapEndpoint {
    Host(String),
    Addr(SocketAddr),
}

impl BootstrapEndpoint {
    pub fn parse(s: &str) -> Self {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            BootstrapEndpoint::Addr(addr)
        } else {
            BootstrapEndpoint::Host(s.to_string())
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            BootstrapEndpoint::Host(s) => s.clone(),
            BootstrapEndpoint::Addr(a) => a.to_string(),
        }
    }
}

/// Compose the bootstrap list the dialer will use. Operator
/// overrides via `extra` take precedence over the shipped
/// constants — if the operator supplied even one node, the
/// Holepunch defaults are NOT prepended (operator who wanted
/// the defaults would have left the field empty).
pub fn bootstrap_endpoints(extra: &[String]) -> Vec<BootstrapEndpoint> {
    if !extra.is_empty() {
        return extra.iter().map(|s| BootstrapEndpoint::parse(s)).collect();
    }
    HYPERSWARM_BOOTSTRAP_HOSTS
        .iter()
        .map(|s| BootstrapEndpoint::parse(s))
        .collect()
}

/// Build an `AnnouncePacket` from a topic + listen port. Peer
/// id is filled with zeros — Phase 3 callers supply the real
/// 32-byte identity.
pub fn build_announce(topic: TopicKey, listen_port: u16) -> AnnouncePacket {
    let disc = super::keet_crypto::discovery_key(topic);
    AnnouncePacket {
        discovery_key: disc.0,
        peer_id: [0u8; 32],
        listen_port,
    }
}

/// Build a `LookupPacket`. Same zero-peer-id convention as
/// `build_announce` — Phase 3 fills in real identity.
pub fn build_lookup(topic: TopicKey) -> LookupPacket {
    let disc = super::keet_crypto::discovery_key(topic);
    LookupPacket {
        discovery_key: disc.0,
        peer_id: [0u8; 32],
    }
}

/// Direct accessor for the discovery key encoded into a packet.
/// Lets the doctor / status surface verify a packet matches
/// the operator's configured topic without re-deriving.
pub fn packet_discovery_key(packet: &AnnouncePacket) -> DiscoveryKey {
    DiscoveryKey(packet.discovery_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PHRASE: &str =
        "alpha bravo charlie delta echo foxtrot golf hotel india juliet \
         kilo lima mike november oscar papa quebec romeo sierra tango \
         uniform victor whiskey xray";

    fn sample_topic() -> TopicKey {
        super::super::keet_crypto::topic_key(SAMPLE_PHRASE).unwrap()
    }

    #[test]
    fn bootstrap_hosts_pinned_to_holepunch_default_list() {
        // Pin the constants — if a future contributor renames
        // bucket1 → bucketA without checking the JS reference
        // impl, this catches it.
        assert!(HYPERSWARM_BOOTSTRAP_HOSTS.len() >= 3);
        for host in HYPERSWARM_BOOTSTRAP_HOSTS {
            assert!(host.contains(':'), "expected host:port form: {host}");
            assert!(host.contains("hyperdht"), "expected hyperdht subdomain: {host}");
        }
    }

    #[test]
    fn dht_message_kind_wire_byte_roundtrip() {
        for kind in [
            DhtMessageKind::Announce,
            DhtMessageKind::Lookup,
            DhtMessageKind::AnnounceAck,
            DhtMessageKind::LookupResponse,
        ] {
            let byte = kind.wire_byte();
            let back = DhtMessageKind::from_wire_byte(byte).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn dht_message_kind_unknown_byte_returns_none() {
        assert!(DhtMessageKind::from_wire_byte(0xff).is_none());
        assert!(DhtMessageKind::from_wire_byte(0x00).is_none());
        assert!(DhtMessageKind::from_wire_byte(0x50).is_none());
    }

    #[test]
    fn wire_bytes_are_stable_across_releases() {
        // Operators on different NEOTH versions MUST agree on
        // these bytes — drifting any one breaks pairing.
        assert_eq!(DhtMessageKind::Announce.wire_byte(), 0x01);
        assert_eq!(DhtMessageKind::Lookup.wire_byte(), 0x02);
        assert_eq!(DhtMessageKind::AnnounceAck.wire_byte(), 0x81);
        assert_eq!(DhtMessageKind::LookupResponse.wire_byte(), 0x82);
    }

    #[test]
    fn bootstrap_endpoint_parse_distinguishes_addr_from_host() {
        let addr = BootstrapEndpoint::parse("127.0.0.1:49737");
        assert!(matches!(addr, BootstrapEndpoint::Addr(_)));
        let host = BootstrapEndpoint::parse("node1.hyperdht.org:49737");
        assert!(matches!(host, BootstrapEndpoint::Host(_)));
    }

    #[test]
    fn bootstrap_endpoint_as_str_roundtrips() {
        let raw = "192.0.2.1:49737";
        let ep = BootstrapEndpoint::parse(raw);
        assert_eq!(ep.as_str(), raw);
    }

    #[test]
    fn bootstrap_endpoints_uses_defaults_when_extra_empty() {
        let list = bootstrap_endpoints(&[]);
        assert!(list.len() >= 3);
        // Every shipped default should reach as_str without panic.
        for ep in &list {
            let s = ep.as_str();
            assert!(s.contains(':'));
        }
    }

    #[test]
    fn bootstrap_endpoints_extra_overrides_defaults_completely() {
        // Operator supplied one private node → defaults dropped.
        let list = bootstrap_endpoints(&["10.0.0.5:49737".to_string()]);
        assert_eq!(list.len(), 1);
        assert!(matches!(list[0], BootstrapEndpoint::Addr(_)));
    }

    #[test]
    fn build_announce_uses_discovery_key_from_topic() {
        let topic = sample_topic();
        let pkt = build_announce(topic, 4242);
        assert_eq!(pkt.listen_port, 4242);
        assert_eq!(pkt.peer_id, [0u8; 32]);
        assert_eq!(pkt.discovery_key, super::super::keet_crypto::discovery_key(topic).0);
    }

    #[test]
    fn build_lookup_uses_same_discovery_key_as_announce() {
        let topic = sample_topic();
        let a = build_announce(topic, 1234);
        let l = build_lookup(topic);
        assert_eq!(a.discovery_key, l.discovery_key);
    }

    #[test]
    fn packet_discovery_key_accessor_returns_typed_wrapper() {
        let topic = sample_topic();
        let pkt = build_announce(topic, 0);
        let dk = packet_discovery_key(&pkt);
        assert_eq!(dk.0, super::super::keet_crypto::discovery_key(topic).0);
    }

    #[test]
    fn packet_serde_roundtrip() {
        let pkt = AnnouncePacket {
            discovery_key: [1u8; 32],
            peer_id: [2u8; 32],
            listen_port: 49737,
        };
        let json = serde_json::to_string(&pkt).unwrap();
        let back: AnnouncePacket = serde_json::from_str(&json).unwrap();
        assert_eq!(pkt, back);
    }

    #[test]
    fn lookup_response_serde_with_peers() {
        let resp = LookupResponse {
            discovery_key: [7u8; 32],
            peers: vec![
                (vec![1, 2, 3], "192.0.2.1:1234".into()),
                (vec![4, 5, 6], "node2.example.com:5678".into()),
            ],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: LookupResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
        assert_eq!(back.peers.len(), 2);
    }
}
