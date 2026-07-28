//! Signed StableNode mDNS discovery.
//!
//! The passphrase-derived cluster key is only a rendezvous filter. Identity is
//! a signed [`EndpointAttestation`] from the persistent [`LocalNodeIdentity`],
//! binding the StableNode signing key to the exact persistent carrier identity,
//! endpoint, daemon boot, authority epochs, optional invite digest, and expiry.
//! A valid announce is still only an untrusted enrollment candidate; it never
//! creates Active membership.
//!
//! Operator-facing knobs (freedom.yaml):
//!   - `cluster.mdns.enabled` (bool, default true via Q4 ratify) —
//!     WIRED: `cli/serve` gates `spawn_announcer` on the validated
//!     `FreedomConfig` snapshot + `policy::gate_discover`, the same policy
//!     path `neoth cluster discover` uses.
//!   - `cluster.mdns.service_name` / `cluster.mdns.interval_secs` —
//!     NOT consumed: the service type is pinned to
//!     [`DEFAULT_SERVICE_TYPE`] (both ends must agree anyway) and
//!     `mdns-sd` maintains the announce TTL itself (no re-announce
//!     loop to tune).
//!
//! Q2 ratify follow-on: the untrusted-wifi gate lives in the caller
//! (cli/serve + cli/cluster consult `AnnouncePolicy` / SSID before
//! calling `spawn_announcer`). This module assumes the caller
//! already cleared the policy.

use std::net::IpAddr;

use anyhow::{Context, Result};
use base64::Engine as _;
use mdns_sd::{ServiceDaemon, ServiceInfo};

use super::discovery::{ClusterAnnouncePacket, ClusterKey, DiscoveryVia};
use super::membership::{
    AuthEpoch, BootId, CarrierKind, EndpointAttestation, LocalNodeIdentity, MembershipEpoch,
    TransportIdentity,
};

/// Default mDNS service type. `_neoth._udp.local.` follows the
/// standard `_<servicename>._<proto>.local.` pattern.
pub const DEFAULT_SERVICE_TYPE: &str = "_neoth._udp.local.";

/// Default re-announce cadence. Mirrors the spec's 60-second
/// default — high enough to keep the entry alive past LAN cache
/// expiry, low enough that a coffee-shop wifi switch propagates
/// within a minute.
pub const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub struct MdnsIdentity {
    pub instance_label: String,
    pub attestation: EndpointAttestation,
    /// Passphrase proof used only to filter rendezvous domains.
    pub rendezvous_proof: [u8; 32],
    pub listen_port: u16,
    pub local_ips: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdnsAttestedCandidate {
    pub instance_label: String,
    pub attestation: EndpointAttestation,
    pub addr: std::net::SocketAddr,
    pub rendezvous_proof: [u8; 32],
}

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

const ATTESTATION_CHUNK_BYTES: usize = 180;
const MAX_ATTESTATION_CHUNKS: usize = 16;

pub fn announce_txt_records(
    label: &str,
    attestation: &EndpointAttestation,
    rendezvous_proof: &[u8; 32],
) -> Result<Vec<(String, String)>> {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(attestation).context("serialize mDNS endpoint attestation")?);
    let chunks = encoded
        .as_bytes()
        .chunks(ATTESTATION_CHUNK_BYTES)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !chunks.is_empty() && chunks.len() <= MAX_ATTESTATION_CHUNKS,
        "mDNS endpoint attestation exceeds bounded TXT capacity"
    );
    let mut records = vec![
        ("label".to_string(), label.to_string()),
        (
            "stable_node_id".to_string(),
            attestation.stable_node_id.as_str().to_string(),
        ),
        (
            "rendezvous_proof".to_string(),
            hex_encode_32(rendezvous_proof),
        ),
        ("attestation_chunks".to_string(), chunks.len().to_string()),
        ("v".to_string(), "2".to_string()),
    ];
    for (index, chunk) in chunks.into_iter().enumerate() {
        records.push((
            format!("attestation_{index}"),
            std::str::from_utf8(chunk)
                .context("base64 mDNS attestation chunk is not UTF-8")?
                .to_string(),
        ));
    }
    Ok(records)
}

pub fn parse_announce_txt(
    txt: &std::collections::HashMap<String, String>,
    addr: std::net::SocketAddr,
    now_unix: i64,
) -> Option<MdnsAttestedCandidate> {
    if txt.get("v").map(String::as_str) != Some("2") {
        return None;
    }
    let label = txt.get("label")?.clone();
    let stable_node_id = txt.get("stable_node_id")?;
    let rendezvous_proof = hex_decode_32(txt.get("rendezvous_proof")?)?;
    let chunk_count = txt.get("attestation_chunks")?.parse::<usize>().ok()?;
    if chunk_count == 0 || chunk_count > MAX_ATTESTATION_CHUNKS {
        return None;
    }
    let mut encoded = String::new();
    for index in 0..chunk_count {
        encoded.push_str(txt.get(&format!("attestation_{index}"))?);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    let attestation = serde_json::from_slice::<EndpointAttestation>(&bytes).ok()?;
    if attestation.stable_node_id.as_str() != stable_node_id
        || attestation.carrier != CarrierKind::Peeroxide
        || attestation.endpoint != addr.to_string()
        || attestation
            .verify_exact(
                CarrierKind::Peeroxide,
                &attestation.transport_identity,
                &addr.to_string(),
                now_unix,
            )
            .is_err()
    {
        return None;
    }
    Some(MdnsAttestedCandidate {
        instance_label: label,
        attestation,
        addr,
        rendezvous_proof,
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
    let txt = announce_txt_records(
        &identity.instance_label,
        &identity.attestation,
        &identity.rendezvous_proof,
    )?;
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

/// The operator-readable label this node announces as. Hostname when
/// the OS provides one; otherwise a `neoth-<unix_ts>` label persisted
/// to `<neoth_home>/node_label` so the derived node id stays stable
/// across reboots.
pub fn node_label(neoth_home: &std::path::Path) -> String {
    let env_label = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    node_label_from(env_label, neoth_home)
}

/// Testable core of [`node_label`] — `env_label` is the
/// COMPUTERNAME/HOSTNAME value when present.
pub fn node_label_from(env_label: Option<String>, neoth_home: &std::path::Path) -> String {
    if let Some(l) = env_label {
        return l;
    }
    let path = neoth_home.join("node_label");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if !s.is_empty() {
            return s.to_string();
        }
    }
    let label = format!("neoth-{}", crate::time::now_unix_secs());
    // Best-effort persist; an unwritable home just means the label
    // (and thus the derived node id) changes next boot.
    let _ = std::fs::write(&path, &label);
    label
}

/// The primary outbound LAN IP — the classic UDP-connect trick: a
/// `connect` on a UDP socket picks the route without sending a packet.
/// `None` on hosts with no route (announce is skipped there anyway).
// ponytail: single primary IP only — multi-homed hosts announce their
// default-route interface; publish-all-interfaces needs a per-addr
// auth field (announce schema v2).
pub fn primary_local_ip() -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect(("192.0.2.1", 80)).ok()?; // TEST-NET-1: never sent, route-select only
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip)
}

#[allow(clippy::too_many_arguments)]
pub fn build_announce_identity(
    key: &ClusterKey,
    local_identity: &LocalNodeIdentity,
    node_label: &str,
    ip: IpAddr,
    listen_port: u16,
    boot_id: BootId,
    auth_epoch: AuthEpoch,
    membership_epoch: MembershipEpoch,
    invitation_digest: Option<String>,
    expires_at_unix: i64,
) -> Result<MdnsIdentity> {
    let addr = std::net::SocketAddr::new(ip, listen_port);
    let transport_identity =
        TransportIdentity::peeroxide(&local_identity.peeroxide_key_pair().public_key);
    let attestation = local_identity.attest_endpoint(
        CarrierKind::Peeroxide,
        transport_identity,
        boot_id.clone(),
        format!("mdns:{}", boot_id.as_str()),
        addr.to_string(),
        auth_epoch,
        membership_epoch,
        invitation_digest,
        expires_at_unix,
    )?;
    let rendezvous_proof =
        super::discovery::sign_announce(key, node_label, &attestation.signing_public_key, &addr);
    Ok(MdnsIdentity {
        instance_label: node_label.to_string(),
        attestation,
        listen_port,
        rendezvous_proof,
        local_ips: vec![ip],
    })
}

/// Verify only the rendezvous proof. Signed StableNode verification happens in
/// [`parse_announce_txt`]; neither check grants membership.
pub fn verify_with_cluster_key(candidate: &MdnsAttestedCandidate, key: &ClusterKey) -> bool {
    super::discovery::verify_announce(
        key,
        &ClusterAnnouncePacket {
            instance_label: candidate.instance_label.clone(),
            pub_key: candidate.attestation.signing_public_key,
            addr: candidate.addr,
            auth: candidate.rendezvous_proof,
        },
    )
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

    fn signed_identity(
        home: &std::path::Path,
        key: &ClusterKey,
        carrier: CarrierKind,
    ) -> MdnsIdentity {
        let local = LocalNodeIdentity::load_or_create(home).unwrap();
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        if carrier == CarrierKind::Peeroxide {
            return build_announce_identity(
                key,
                &local,
                "office-pc",
                ip,
                49737,
                BootId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
                AuthEpoch::new(7).unwrap(),
                MembershipEpoch::new(11).unwrap(),
                Some("invite-digest".into()),
                1_900_000_000,
            )
            .unwrap();
        }
        let addr = std::net::SocketAddr::new(ip, 49737);
        let attestation = local
            .attest_endpoint(
                carrier,
                TransportIdentity::parse("iroh-persistent-id").unwrap(),
                BootId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
                "mdns:test".into(),
                addr.to_string(),
                AuthEpoch::new(7).unwrap(),
                MembershipEpoch::new(11).unwrap(),
                Some("invite-digest".into()),
                1_900_000_000,
            )
            .unwrap();
        MdnsIdentity {
            instance_label: "office-pc".into(),
            rendezvous_proof: super::super::discovery::sign_announce(
                key,
                "office-pc",
                &attestation.signing_public_key,
                &addr,
            ),
            attestation,
            listen_port: addr.port(),
            local_ips: vec![ip],
        }
    }

    fn txt(identity: &MdnsIdentity) -> HashMap<String, String> {
        announce_txt_records(
            &identity.instance_label,
            &identity.attestation,
            &identity.rendezvous_proof,
        )
        .unwrap()
        .into_iter()
        .collect()
    }

    #[test]
    fn production_announce_round_trips_signed_stable_identity_and_exact_carrier() {
        let home = tempfile::tempdir().unwrap();
        let key = super::super::discovery::cluster_key("phrase a").unwrap();
        let identity = signed_identity(home.path(), &key, CarrierKind::Peeroxide);
        let addr = identity.attestation.endpoint.parse().unwrap();
        let candidate = parse_announce_txt(&txt(&identity), addr, 1_800_000_000).unwrap();
        assert_eq!(
            candidate.attestation.stable_node_id,
            *LocalNodeIdentity::load_existing(home.path())
                .unwrap()
                .unwrap()
                .stable_node_id()
        );
        assert_eq!(candidate.attestation.carrier, CarrierKind::Peeroxide);
        assert_eq!(candidate.attestation.endpoint, addr.to_string());
        assert_eq!(
            candidate.attestation.transport_identity,
            TransportIdentity::peeroxide(
                &LocalNodeIdentity::load_existing(home.path())
                    .unwrap()
                    .unwrap()
                    .peeroxide_key_pair()
                    .public_key
            )
        );
        assert_eq!(
            candidate.attestation.invitation_digest.as_deref(),
            Some("invite-digest")
        );
        assert!(verify_with_cluster_key(&candidate, &key));
        let records = txt(&identity);
        assert!(!records.contains_key("pubkey"));
        assert!(!records.contains_key("auth"));
        assert_eq!(records.get("v").map(String::as_str), Some("2"));
    }

    #[test]
    fn rendezvous_wrong_key_is_rejected_without_becoming_membership() {
        let home = tempfile::tempdir().unwrap();
        let key_a = super::super::discovery::cluster_key("phrase a").unwrap();
        let key_b = super::super::discovery::cluster_key("phrase b").unwrap();
        let identity = signed_identity(home.path(), &key_a, CarrierKind::Peeroxide);
        let addr = identity.attestation.endpoint.parse().unwrap();
        let candidate = parse_announce_txt(&txt(&identity), addr, 1_800_000_000).unwrap();
        assert!(!verify_with_cluster_key(&candidate, &key_b));
    }

    #[test]
    fn attestation_tamper_and_wrong_carrier_are_rejected() {
        let home = tempfile::tempdir().unwrap();
        let key = super::super::discovery::cluster_key("phrase a").unwrap();
        let identity = signed_identity(home.path(), &key, CarrierKind::Peeroxide);
        let addr = identity.attestation.endpoint.parse().unwrap();
        let mut tampered = txt(&identity);
        let chunk = tampered.get_mut("attestation_0").unwrap();
        let replacement = if chunk.starts_with('A') { "B" } else { "A" };
        chunk.replace_range(0..1, replacement);
        assert!(parse_announce_txt(&tampered, addr, 1_800_000_000).is_none());

        let iroh = signed_identity(home.path(), &key, CarrierKind::Iroh);
        assert!(parse_announce_txt(&txt(&iroh), addr, 1_800_000_000).is_none());
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
    fn default_constants_pinned() {
        assert_eq!(DEFAULT_SERVICE_TYPE, "_neoth._udp.local.");
        assert_eq!(DEFAULT_ANNOUNCE_INTERVAL_SECS, 60);
    }

    #[test]
    fn node_label_prefers_env_then_persists_fallback() {
        let home = tempfile::tempdir().unwrap();
        // Env label wins outright — nothing persisted.
        assert_eq!(
            node_label_from(Some("office-pc".into()), home.path()),
            "office-pc"
        );
        assert!(!home.path().join("node_label").exists());
        // No env ⇒ generated + persisted ⇒ stable on re-read.
        let first = node_label_from(None, home.path());
        assert!(first.starts_with("neoth-"), "generated label: {first}");
        let second = node_label_from(None, home.path());
        assert_eq!(first, second, "persisted label must be stable");
    }
}
