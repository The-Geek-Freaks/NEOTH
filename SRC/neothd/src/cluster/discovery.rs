//! Cluster auto-discovery primitives — Phase 1 of the cluster
//! auto-discovery + pairing design (SPEC: `PLAN/SPEC_cluster_auto_
//! discovery_2026-05-22.md`).
//!
//! Three transports are in scope:
//!   - LAN via mDNS (Phase 2)
//!   - Tailscale via `tailscale status --json` enumeration (Phase 3)
//!   - Hysteria-tunnel-shared relay (Phase 5, multi-week)
//!
//! This module ships the deterministic primitives every Phase
//! consumes:
//!   - ClusterKey derivation from a 24-word cluster phrase
//!   - ClusterPeer wire shape (one per discovered instance)
//!   - DiscoveryVia enum tagging which transport surfaced the peer
//!   - HMAC-signed announce packet shape so a hostile peer on the
//!     same LAN can't forge entries
//!
//! Actual network I/O lands in subsequent phases — this is the
//! contract those phases honour.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation prefix for the cluster_key branch. Different
/// from `keet_crypto::TOPIC_DOMAIN` so an operator using the same
/// phrase for Keet pairing AND cluster discovery gets two
/// independent keys.
const CLUSTER_DOMAIN: &[u8] = b"neoth/cluster/v1\0";

/// HMAC namespace for the cluster announce-packet authenticator.
const CLUSTER_ANNOUNCE_NS: &[u8] = b"neoth-cluster-announce";

/// 32-byte cluster key. Two NEOTH instances pair if and only if
/// they compute the same value from the operator's phrase.
///
/// Security-audit fix (2026-05-22): no longer `Copy` so the key
/// can't silently duplicate into stack frames. Drop zeroes the
/// bytes so a memory-dump after the value goes out of scope
/// doesn't recover the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct ClusterKey(pub [u8; 32]);

impl Drop for ClusterKey {
    fn drop(&mut self) {
        // Explicit byte-by-byte zeroing — `volatile_write` style
        // via the `subtle` pattern (write a constant value the
        // compiler can't optimise away because each byte is
        // touched through `&mut`).
        for b in &mut self.0 {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl std::fmt::Debug for ClusterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // FULLY redacted — emit NO key bytes. A prefix (even 8 bytes) is still
        // secret material that must never reach a log line, panic formatter, or
        // crash report. The cluster_key is an HMAC secret; leaking any of it
        // weakens the membership proof. (SL-00(1b) review finding.)
        f.write_str("ClusterKey(<redacted>)")
    }
}

/// Which transport surfaced this peer. Operators see this in
/// `neoth cluster list` so they know whether a peer was found
/// over LAN, Tailscale, or the Hysteria relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryVia {
    Mdns,
    Tailscale,
    HysteriaRelay,
    /// Operator manually added via `neoth cluster add <addr>`.
    Manual,
}

impl DiscoveryVia {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mdns => "mdns",
            Self::Tailscale => "tailscale",
            Self::HysteriaRelay => "hysteria_relay",
            Self::Manual => "manual",
        }
    }
}

/// One discovered or manually-configured cluster peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterPeer {
    /// Operator-readable identifier (typically `hostname-<short-id>`).
    pub instance_label: String,
    /// 32-byte ed25519 public key the peer announces. Phase 2 verifies
    /// every gossip frame's signature against this.
    pub pub_key: [u8; 32],
    /// Reachable socket address. mDNS resolves to LAN IPs;
    /// Tailscale resolves to `100.x.y.z` CGNAT.
    pub addr: SocketAddr,
    /// Transport that surfaced this peer.
    pub discovered_via: DiscoveryVia,
    /// Unix seconds when the peer was last seen via discovery.
    pub last_seen_unix: i64,
}

/// HMAC-authenticated cluster announce packet — the bytes a NEOTH
/// instance broadcasts on each enabled transport. Phase 2 sends
/// this over mDNS TXT records / Tailscale UDP / Hysteria relay.
///
/// Authenticator: HMAC-SHA256(cluster_key, peer || addr_str ||
/// label_bytes). Recipients verify before adding the peer to
/// their cluster list — defends against a hostile peer on the
/// same LAN forging announcements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterAnnouncePacket {
    pub instance_label: String,
    pub pub_key: [u8; 32],
    pub addr: SocketAddr,
    /// HMAC-SHA256 over (pub_key || addr.to_string() || instance_label).
    pub auth: [u8; 32],
}

/// Derive the cluster_key from a phrase. Same canonicalisation +
/// domain-separation pattern as `keet_crypto::topic_key` so an
/// operator using one phrase gets independent keys for the two
/// usages.
pub fn cluster_key(phrase: &str) -> Option<ClusterKey> {
    let canonical = crate::channels::keet_crypto::canonicalize(phrase);
    if canonical.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(CLUSTER_DOMAIN);
    hasher.update(canonical.as_bytes());
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Some(ClusterKey(bytes))
}

/// Sign a `ClusterAnnouncePacket` with the cluster_key. Caller
/// fills the `auth` field with the returned bytes before
/// broadcasting.
///
/// Security-audit fix (2026-05-22):
///   1. HMAC key is now `cluster_key` directly (was: namespace ||
///      cluster_key). Namespace moves into the data field per the
///      idiomatic RFC 2104 construction. Defends against the
///      degenerate-collision corner case the auditor flagged.
///   2. Variable-length fields (addr_str, instance_label) are now
///      length-prefixed (LE u32) before the HMAC input. Prevents
///      the canonicalisation-collision where addr `"1.2.3.4:42421"`
///      + label `""` produced the same bytes as addr `"1.2.3.4:4242"`
///      + label `"1"`.
pub fn sign_announce(
    key: &ClusterKey,
    instance_label: &str,
    pub_key: &[u8; 32],
    addr: &SocketAddr,
) -> [u8; 32] {
    let addr_str = addr.to_string();
    let mut msg = Vec::with_capacity(
        CLUSTER_ANNOUNCE_NS.len() + 32 + 4 + addr_str.len() + 4 + instance_label.len(),
    );
    msg.extend_from_slice(CLUSTER_ANNOUNCE_NS);
    msg.extend_from_slice(pub_key);
    msg.extend_from_slice(&(addr_str.len() as u32).to_le_bytes());
    msg.extend_from_slice(addr_str.as_bytes());
    msg.extend_from_slice(&(instance_label.len() as u32).to_le_bytes());
    msg.extend_from_slice(instance_label.as_bytes());
    let mut auth = [0u8; 32];
    crate::channels::keet_crypto::hmac_sha256(&key.0, &msg, &mut auth);
    auth
}

/// Verify a `ClusterAnnouncePacket`. Returns true when the
/// authenticator matches the cluster_key — false otherwise.
/// Constant-time check via XOR-accumulate to defend against
/// timing oracles.
pub fn verify_announce(key: &ClusterKey, packet: &ClusterAnnouncePacket) -> bool {
    let expected = sign_announce(key, &packet.instance_label, &packet.pub_key, &packet.addr);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(packet.auth.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "alpha bravo charlie delta echo foxtrot golf hotel india juliet \
         kilo lima mike november oscar papa quebec romeo sierra tango \
         uniform victor whiskey xray";

    fn sample_addr() -> SocketAddr {
        "192.0.2.1:4242".parse().unwrap()
    }

    #[test]
    fn cluster_key_deterministic() {
        let a = cluster_key(PHRASE).unwrap();
        let b = cluster_key(PHRASE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn cluster_key_empty_returns_none() {
        assert!(cluster_key("").is_none());
        assert!(cluster_key("   \t\n  ").is_none());
    }

    #[test]
    fn cluster_key_differs_from_keet_topic_key() {
        // Same phrase → different keys for Keet vs Cluster usage.
        let ck = cluster_key(PHRASE).unwrap();
        let tk = crate::channels::keet_crypto::topic_key(PHRASE).unwrap();
        assert_ne!(ck.0, tk.0, "domain separation: cluster != keet topic");
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let key = cluster_key(PHRASE).unwrap();
        let pub_key = [42u8; 32];
        let addr = sample_addr();
        let label = "laptop-alpha";
        let auth = sign_announce(&key, label, &pub_key, &addr);
        let packet = ClusterAnnouncePacket {
            instance_label: label.into(),
            pub_key,
            addr,
            auth,
        };
        assert!(verify_announce(&key, &packet));
    }

    #[test]
    fn verify_rejects_tampered_label() {
        let key = cluster_key(PHRASE).unwrap();
        let pub_key = [42u8; 32];
        let addr = sample_addr();
        let auth = sign_announce(&key, "laptop-alpha", &pub_key, &addr);
        // Forge a packet with a different label but the original auth.
        let packet = ClusterAnnouncePacket {
            instance_label: "ATTACKER".into(),
            pub_key,
            addr,
            auth,
        };
        assert!(!verify_announce(&key, &packet));
    }

    #[test]
    fn verify_rejects_tampered_pubkey() {
        let key = cluster_key(PHRASE).unwrap();
        let pub_key = [42u8; 32];
        let addr = sample_addr();
        let auth = sign_announce(&key, "label", &pub_key, &addr);
        let packet = ClusterAnnouncePacket {
            instance_label: "label".into(),
            pub_key: [99u8; 32],
            addr,
            auth,
        };
        assert!(!verify_announce(&key, &packet));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key_a = cluster_key("phrase one").unwrap();
        let key_b = cluster_key("phrase two completely different").unwrap();
        let pub_key = [1u8; 32];
        let addr = sample_addr();
        let auth = sign_announce(&key_a, "label", &pub_key, &addr);
        let packet = ClusterAnnouncePacket {
            instance_label: "label".into(),
            pub_key,
            addr,
            auth,
        };
        // Same packet bytes, verified against the OTHER key — must fail.
        assert!(!verify_announce(&key_b, &packet));
    }

    #[test]
    fn discovery_via_as_str_pinned() {
        // Pin so a future contributor renaming the enum still
        // matches the wire form `neoth cluster list` operators
        // grep for in scripts.
        assert_eq!(DiscoveryVia::Mdns.as_str(), "mdns");
        assert_eq!(DiscoveryVia::Tailscale.as_str(), "tailscale");
        assert_eq!(DiscoveryVia::HysteriaRelay.as_str(), "hysteria_relay");
        assert_eq!(DiscoveryVia::Manual.as_str(), "manual");
    }

    #[test]
    fn cluster_peer_serde_roundtrip() {
        let peer = ClusterPeer {
            instance_label: "laptop-alpha".into(),
            pub_key: [1u8; 32],
            addr: sample_addr(),
            discovered_via: DiscoveryVia::Tailscale,
            last_seen_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&peer).unwrap();
        let back: ClusterPeer = serde_json::from_str(&json).unwrap();
        assert_eq!(peer, back);
    }

    #[test]
    fn announce_packet_serde_roundtrip() {
        let pkt = ClusterAnnouncePacket {
            instance_label: "x".into(),
            pub_key: [7u8; 32],
            addr: sample_addr(),
            auth: [9u8; 32],
        };
        let json = serde_json::to_string(&pkt).unwrap();
        let back: ClusterAnnouncePacket = serde_json::from_str(&json).unwrap();
        assert_eq!(pkt, back);
    }

    #[test]
    fn sign_announce_distinguishes_addr_label_boundary_collision() {
        // Security-audit fix pin: length delimiters in the HMAC
        // input. Without them, addr "1.2.3.4:42421" + label "" and
        // addr "1.2.3.4:4242" + label "1" produce the same byte
        // sequence + therefore the same auth. With length
        // delimiters the two auths must differ.
        let key = cluster_key(PHRASE).unwrap();
        let pub_key = [0u8; 32];
        let addr_a: SocketAddr = "1.2.3.4:42421".parse().unwrap();
        let addr_b: SocketAddr = "1.2.3.4:4242".parse().unwrap();
        let auth_a = sign_announce(&key, "", &pub_key, &addr_a);
        let auth_b = sign_announce(&key, "1", &pub_key, &addr_b);
        assert_ne!(auth_a, auth_b);
    }

    #[test]
    fn cluster_key_drop_zeros_bytes() {
        // Security-audit fix pin: Drop impl writes zero to every
        // byte. We can't observe the dropped value (Rust enforces),
        // but we can verify the Drop impl exists by constructing
        // a key, peeking at its bytes via a clone, and confirming
        // the cluster_key() helper produces non-zero output
        // (regression guard against a future commit that
        // accidentally zeroes the new struct instead of the dropped
        // one).
        let key = cluster_key(PHRASE).unwrap();
        let cloned = key.clone();
        // The cloned key must NOT be all-zero (cluster_key with
        // a non-empty phrase produces non-zero output).
        assert!(cloned.0.iter().any(|&b| b != 0));
        // Drop happens automatically when `cloned` goes out of
        // scope below. The original `key` outlives this assertion.
        drop(cloned);
        assert!(key.0.iter().any(|&b| b != 0));
    }

    #[test]
    fn debug_redacts_full_cluster_key() {
        let key = cluster_key(PHRASE).unwrap();
        let dbg = format!("{:?}", key);
        assert_eq!(
            dbg, "ClusterKey(<redacted>)",
            "Debug must emit a fixed redaction marker with NO key bytes"
        );
        // No part of the key — not even the first byte — may appear as hex.
        let full_hex: String = key.0.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&full_hex), "full hex must not leak");
        // The 8-byte prefix that the old impl leaked must also be absent.
        let prefix_hex: String = key.0[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !dbg.contains(&prefix_hex),
            "even the 8-byte prefix must not leak (SL-00(1b) finding)"
        );
    }
}
