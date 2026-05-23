//! mDNS announcer + listener — Phase 2 of cluster auto-discovery.
//!
//! Cross-platform via the `mdns-sd` crate (pure-Rust zeroconf
//! client, no system Avahi/Bonjour dependency). The announcer
//! registers a `_neoth._udp.local.` service with TXT records
//! carrying:
//!   - `pubkey` = lowercase-hex of operator's 32-byte ed25519
//!     pub key (per Q2 ratification — raw key, not pseudonym)
//!   - `auth` = lowercase-hex of `sign_announce(cluster_key,
//!     label, pub_key, addr)` HMAC-SHA256 authenticator
//!   - `label` = operator-readable instance label
//!
//! The listener subscribes to the same service type + filters
//! every received announcement through `verify_announce` so
//! HMAC-failing impersonations from peers without `cluster_key`
//! are rejected before they surface to the caller.
//!
//! Operator-facing knobs (Phase 2 wire-in via freedom.yaml):
//!   - `cluster.mdns.enabled` (bool, default true via Q4 ratify)
//!   - `cluster.mdns.service_name` (str, default
//!     `_neoth._udp.local.`)
//!   - `cluster.mdns.interval_secs` (u64, default 60)
//!
//! Q2 ratify follow-on: `cluster.announce_on_untrusted_wifi`
//! gate lives in the caller (cli/serve decides whether to call
//! `spawn_announcer` at all based on the SSID check). This
//! module assumes the caller already cleared the policy.

use std::net::IpAddr;

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};

use super::discovery::{ClusterAnnouncePacket, ClusterKey, DiscoveryVia};

/// Default mDNS service type. `_neoth._udp.local.` follows the
/// standard `_<servicename>._<proto>.local.` pattern.
pub const DEFAULT_SERVICE_TYPE: &str = "_neoth._udp.local.";

/// Default re-announce cadence. Mirrors the spec's 60-second
/// default — high enough to keep the entry alive past LAN cache
/// expiry, low enough that a coffee-shop wifi switch propagates
/// within a minute.
pub const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 60;

/// Operator-supplied identity for the announcer. Carries the
/// already-signed authenticator so this module doesn't need to
/// touch the secret key material itself.
#[derive(Clone, Debug)]
pub struct MdnsIdentity {
    pub instance_label: String,
    /// 32-byte ed25519 public key.
    pub pub_key: [u8; 32],
    /// Listen socket the operator's peers should dial.
    pub listen_port: u16,
    /// Pre-signed HMAC-SHA256 over (NS || pub_key || addr_len ||
    /// addr_str || label_len || label_bytes). Caller computes
    /// this via `discovery::sign_announce`.
    pub auth: [u8; 32],
    /// IP addresses the announcer should publish for this host.
    /// Caller decides which interfaces to expose (LAN-only vs
    /// Tailscale CGNAT vs both); the mDNS daemon picks the
    /// best match per query.
    pub local_ips: Vec<IpAddr>,
}

/// Hex-encode 32 bytes lowercase — used for both `pubkey` and
/// `auth` TXT records. Decoder roundtrip lives below.
pub fn hex_encode_32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Parse a 64-char lowercase-hex string back to 32 bytes. Returns
/// None on wrong length / non-hex.
pub fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Compose the TXT record properties an announcer publishes.
/// Caller passes the bytes from a verified `ClusterAnnouncePacket`
/// (or hand-constructed identity); helper returns the
/// `(key, value)` tuples `mdns-sd` expects.
pub fn announce_txt_records(
    label: &str,
    pub_key: &[u8; 32],
    auth: &[u8; 32],
) -> Vec<(String, String)> {
    vec![
        ("label".to_string(), label.to_string()),
        ("pubkey".to_string(), hex_encode_32(pub_key)),
        ("auth".to_string(), hex_encode_32(auth)),
        // Schema version — Phase 6 (gossip state-sync) bumps to 2
        // when the announce shape gains a `gossip_port` field.
        ("v".to_string(), "1".to_string()),
    ]
}

/// Parse the inverse — convert a TXT-records map back to an
/// `ClusterAnnouncePacket`. Skips records with unrecognized
/// schema versions so a future Phase 6 announcer publishing
/// `v: 2` doesn't trigger spurious "malformed" warnings on
/// older receivers.
pub fn parse_announce_txt(
    txt: &std::collections::HashMap<String, String>,
    addr: std::net::SocketAddr,
) -> Option<ClusterAnnouncePacket> {
    // Schema version check — current parser handles v=1 only.
    if txt.get("v").map(|s| s.as_str()) != Some("1") {
        return None;
    }
    let label = txt.get("label")?.clone();
    let pub_key = hex_decode_32(txt.get("pubkey")?)?;
    let auth = hex_decode_32(txt.get("auth")?)?;
    Some(ClusterAnnouncePacket {
        instance_label: label,
        pub_key,
        addr,
        auth,
    })
}

/// Spawn the mDNS announcer. Returns the live `ServiceDaemon`
/// handle so the caller can shut it down by dropping the handle.
///
/// The daemon registers the service + maintains its TTL in the
/// background; callers don't need a separate re-announce loop.
pub fn spawn_announcer(identity: &MdnsIdentity) -> Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new().context("create mdns daemon")?;
    let host_name = format!("{}.local.", sanitize_for_dns(&identity.instance_label));
    let txt = announce_txt_records(&identity.instance_label, &identity.pub_key, &identity.auth);
    let info = ServiceInfo::new(
        DEFAULT_SERVICE_TYPE,
        &sanitize_for_dns(&identity.instance_label),
        &host_name,
        identity.local_ips.as_slice(),
        identity.listen_port,
        Some(
            txt.into_iter()
                .collect::<std::collections::HashMap<String, String>>(),
        ),
    )
    .context("build mdns ServiceInfo")?;
    daemon.register(info).context("register mdns service")?;
    Ok(daemon)
}

/// Sanitize a label for DNS: lowercase, replace non-[a-z0-9-]
/// with `-`, collapse repeated `-`, trim leading/trailing.
/// Matches RFC 1035 host-name rules so mdns-sd accepts the
/// value as both the instance name and the host portion.
pub fn sanitize_for_dns(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for c in s.chars() {
        let lower = c.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Compose a `DiscoveryVia` for peers surfaced via this transport.
/// Helper so callers don't need to import the enum to tag the
/// surfaced peer.
pub fn via() -> DiscoveryVia {
    DiscoveryVia::Mdns
}

/// Verify a parsed announce against the operator's cluster_key.
/// Wraps `discovery::verify_announce` so mdns-side callers don't
/// reach across modules.
pub fn verify_with_cluster_key(packet: &ClusterAnnouncePacket, key: &ClusterKey) -> bool {
    super::discovery::verify_announce(key, packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn hex_encode_decode_roundtrip() {
        let bytes = [0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x42, 0x13]
            .into_iter()
            .chain(std::iter::repeat_n(0x55, 24))
            .collect::<Vec<_>>();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let hex = hex_encode_32(&arr);
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("deadbeef00ff4213"));
        let back = hex_decode_32(&hex).unwrap();
        assert_eq!(back, arr);
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(hex_decode_32("deadbeef").is_none());
        assert!(hex_decode_32(&"a".repeat(63)).is_none());
        assert!(hex_decode_32(&"a".repeat(65)).is_none());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        let mut bad = "ab".repeat(31);
        bad.push_str("xy");
        assert!(hex_decode_32(&bad).is_none());
    }

    #[test]
    fn announce_txt_records_contain_schema_version_one() {
        let txt = announce_txt_records("label", &[1u8; 32], &[2u8; 32]);
        let map: HashMap<_, _> = txt.into_iter().collect();
        assert_eq!(map.get("v").map(|s| s.as_str()), Some("1"));
        assert_eq!(map.get("label").map(|s| s.as_str()), Some("label"));
        assert!(map.get("pubkey").unwrap().starts_with("01"));
        assert!(map.get("auth").unwrap().starts_with("02"));
    }

    #[test]
    fn parse_announce_txt_v1_roundtrip() {
        let label = "laptop-alpha";
        let pub_key = [0xabu8; 32];
        let auth = [0xcdu8; 32];
        let map: HashMap<_, _> = announce_txt_records(label, &pub_key, &auth)
            .into_iter()
            .collect();
        let addr: std::net::SocketAddr = "192.0.2.1:4242".parse().unwrap();
        let pkt = parse_announce_txt(&map, addr).expect("v1 parse");
        assert_eq!(pkt.instance_label, label);
        assert_eq!(pkt.pub_key, pub_key);
        assert_eq!(pkt.auth, auth);
        assert_eq!(pkt.addr, addr);
    }

    #[test]
    fn parse_announce_txt_unknown_version_returns_none() {
        // Phase 6 will publish v=2; the v=1 parser must skip
        // gracefully instead of mis-decoding.
        let mut map = HashMap::new();
        map.insert("v".to_string(), "2".to_string());
        map.insert("label".to_string(), "x".to_string());
        map.insert("pubkey".to_string(), "0".repeat(64));
        map.insert("auth".to_string(), "0".repeat(64));
        let addr: std::net::SocketAddr = "192.0.2.1:0".parse().unwrap();
        assert!(parse_announce_txt(&map, addr).is_none());
    }

    #[test]
    fn parse_announce_txt_missing_field_returns_none() {
        let mut map = HashMap::new();
        map.insert("v".to_string(), "1".to_string());
        // No label / pubkey / auth.
        let addr: std::net::SocketAddr = "192.0.2.1:0".parse().unwrap();
        assert!(parse_announce_txt(&map, addr).is_none());
    }

    #[test]
    fn sanitize_for_dns_basic() {
        assert_eq!(sanitize_for_dns("Laptop Alpha"), "laptop-alpha");
        assert_eq!(sanitize_for_dns("home-server.lan"), "home-server-lan");
        assert_eq!(sanitize_for_dns("---weird---"), "weird");
        assert_eq!(sanitize_for_dns("MULTI___UNDER"), "multi-under");
        assert_eq!(sanitize_for_dns(""), "");
        assert_eq!(sanitize_for_dns("OK1"), "ok1");
    }

    #[test]
    fn via_returns_mdns_tag() {
        assert_eq!(via(), DiscoveryVia::Mdns);
    }

    #[test]
    fn verify_with_cluster_key_accepts_legit_packet() {
        use super::super::discovery::{ClusterAnnouncePacket, cluster_key, sign_announce};
        let key = cluster_key("alpha bravo charlie delta").unwrap();
        let pub_key = [0xabu8; 32];
        let addr: std::net::SocketAddr = "192.0.2.1:4242".parse().unwrap();
        let label = "laptop";
        let auth = sign_announce(&key, label, &pub_key, &addr);
        let pkt = ClusterAnnouncePacket {
            instance_label: label.into(),
            pub_key,
            addr,
            auth,
        };
        assert!(verify_with_cluster_key(&pkt, &key));
    }

    #[test]
    fn verify_with_cluster_key_rejects_wrong_key() {
        use super::super::discovery::{ClusterAnnouncePacket, cluster_key, sign_announce};
        let key_a = cluster_key("phrase a").unwrap();
        let key_b = cluster_key("phrase b").unwrap();
        let pub_key = [0x12u8; 32];
        let addr: std::net::SocketAddr = "192.0.2.1:4242".parse().unwrap();
        let auth = sign_announce(&key_a, "label", &pub_key, &addr);
        let pkt = ClusterAnnouncePacket {
            instance_label: "label".into(),
            pub_key,
            addr,
            auth,
        };
        assert!(!verify_with_cluster_key(&pkt, &key_b));
    }

    #[test]
    fn default_constants_pinned() {
        assert_eq!(DEFAULT_SERVICE_TYPE, "_neoth._udp.local.");
        assert_eq!(DEFAULT_ANNOUNCE_INTERVAL_SECS, 60);
    }
}
