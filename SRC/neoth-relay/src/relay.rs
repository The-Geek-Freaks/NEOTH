//! Inline copy of the `neothd::cluster::relay` primitives.
//!
//! Duplicated intentionally per Rule of Three — two callers today,
//! factor into a shared `neoth-cluster-types` crate when the third
//! lands. Wire shape is pinned by serde so both sides round-trip
//! identically; structural drift surfaces at deserialise time.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_PEERS_PER_KEY: u32 = 5;
pub const MAX_PEERS_PER_KEY_CEILING: u32 = 50;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelayRegistration {
    pub cluster_key_hex: String,
    pub peer_pub_key_hex: String,
    pub instance_label: String,
    pub listen_port: u16,
    pub registered_at_unix: i64,
}

#[derive(Clone, Debug, Default)]
pub struct PeerRoster {
    pub max_peers_per_key: u32,
    pub buckets: HashMap<String, Vec<RelayRegistration>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationOutcome {
    Registered,
    Refreshed,
    RejectedAtCap { cap: u32 },
    Malformed { reason: &'static str },
}

impl PeerRoster {
    pub fn new(max_peers_per_key: u32) -> Self {
        Self {
            max_peers_per_key,
            buckets: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn count_for(&self, cluster_key_hex: &str) -> usize {
        self.buckets
            .get(cluster_key_hex)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub fn total_peers(&self) -> usize {
        self.buckets.values().map(|v| v.len()).sum()
    }

    pub fn register(&mut self, reg: RelayRegistration) -> RegistrationOutcome {
        if reg.cluster_key_hex.len() != 64
            || !reg.cluster_key_hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return RegistrationOutcome::Malformed {
                reason: "cluster_key_hex must be 64 lowercase-hex chars",
            };
        }
        if reg.peer_pub_key_hex.len() != 64
            || !reg.peer_pub_key_hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return RegistrationOutcome::Malformed {
                reason: "peer_pub_key_hex must be 64 lowercase-hex chars",
            };
        }
        if reg.instance_label.trim().is_empty() {
            return RegistrationOutcome::Malformed {
                reason: "instance_label must not be empty",
            };
        }
        if reg.listen_port == 0 {
            return RegistrationOutcome::Malformed {
                reason: "listen_port must be > 0",
            };
        }
        let bucket = self
            .buckets
            .entry(reg.cluster_key_hex.clone())
            .or_default();
        if let Some(existing) = bucket
            .iter_mut()
            .find(|r| r.peer_pub_key_hex == reg.peer_pub_key_hex)
        {
            existing.instance_label = reg.instance_label;
            existing.listen_port = reg.listen_port;
            existing.registered_at_unix = reg.registered_at_unix;
            return RegistrationOutcome::Refreshed;
        }
        if bucket.len() >= self.max_peers_per_key as usize {
            return RegistrationOutcome::RejectedAtCap {
                cap: self.max_peers_per_key,
            };
        }
        bucket.push(reg);
        RegistrationOutcome::Registered
    }

    pub fn unregister(&mut self, cluster_key_hex: &str, peer_pub_key_hex: &str) -> bool {
        let Some(bucket) = self.buckets.get_mut(cluster_key_hex) else {
            return false;
        };
        let before = bucket.len();
        bucket.retain(|r| r.peer_pub_key_hex != peer_pub_key_hex);
        let removed = bucket.len() < before;
        if bucket.is_empty() {
            self.buckets.remove(cluster_key_hex);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    fn fixture(cluster: &str, peer: &str, port: u16) -> RelayRegistration {
        RelayRegistration {
            cluster_key_hex: cluster.into(),
            peer_pub_key_hex: peer.into(),
            instance_label: format!("peer-{}", &peer[..4]),
            listen_port: port,
            registered_at_unix: 1,
        }
    }

    #[test]
    fn defaults_pinned_to_neothd_shape() {
        // Match neothd::cluster::relay constants — drift surfaces here.
        assert_eq!(DEFAULT_MAX_PEERS_PER_KEY, 5);
        assert_eq!(MAX_PEERS_PER_KEY_CEILING, 50);
    }

    #[test]
    fn register_then_refresh_then_reject_at_cap() {
        let mut r = PeerRoster::new(2);
        let cluster = hex64(0xaa);
        assert_eq!(
            r.register(fixture(&cluster, &hex64(0x01), 1)),
            RegistrationOutcome::Registered
        );
        assert_eq!(
            r.register(fixture(&cluster, &hex64(0x01), 2)),
            RegistrationOutcome::Refreshed
        );
        assert_eq!(
            r.register(fixture(&cluster, &hex64(0x02), 3)),
            RegistrationOutcome::Registered
        );
        assert_eq!(
            r.register(fixture(&cluster, &hex64(0x03), 4)),
            RegistrationOutcome::RejectedAtCap { cap: 2 }
        );
    }

    #[test]
    fn malformed_inputs_rejected() {
        let mut r = PeerRoster::new(5);
        // Bad hex length.
        assert!(matches!(
            r.register(fixture("ZZ", &hex64(0x01), 1)),
            RegistrationOutcome::Malformed { .. }
        ));
        // Empty label.
        let bad = RelayRegistration {
            cluster_key_hex: hex64(0xaa),
            peer_pub_key_hex: hex64(0x01),
            instance_label: "  ".into(),
            listen_port: 1,
            registered_at_unix: 1,
        };
        assert!(matches!(
            r.register(bad),
            RegistrationOutcome::Malformed { .. }
        ));
        // Zero port.
        assert!(matches!(
            r.register(fixture(&hex64(0xaa), &hex64(0x01), 0)),
            RegistrationOutcome::Malformed { .. }
        ));
    }

    #[test]
    fn unregister_drops_empty_buckets() {
        let mut r = PeerRoster::new(5);
        let cluster = hex64(0xaa);
        r.register(fixture(&cluster, &hex64(0x01), 1));
        assert!(r.unregister(&cluster, &hex64(0x01)));
        assert_eq!(r.total_peers(), 0);
        assert!(!r.buckets.contains_key(&cluster));
    }

    #[test]
    fn serde_round_trip_matches_neothd_wire_shape() {
        // Pin the JSON wire form — drift between this and
        // neothd::cluster::relay::RelayRegistration would break
        // operator-deployed relays after a daemon upgrade.
        let reg = fixture(&hex64(0xaa), &hex64(0x01), 4242);
        let json = serde_json::to_string(&reg).unwrap();
        // Field names match snake_case wire form.
        assert!(json.contains("\"cluster_key_hex\""));
        assert!(json.contains("\"peer_pub_key_hex\""));
        assert!(json.contains("\"instance_label\""));
        assert!(json.contains("\"listen_port\""));
        assert!(json.contains("\"registered_at_unix\""));
        let back: RelayRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reg);
    }
}
