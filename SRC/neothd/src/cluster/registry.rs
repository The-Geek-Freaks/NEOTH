//! Persisted cluster peer registry — Phase 4 of the auto-discovery
//! SPEC. Operator-confirmed peers live in `~/.neoth/cluster.yaml`;
//! discovery (Phase 2 mDNS / Phase 3 Tailscale) surfaces candidates,
//! `neoth cluster confirm` promotes them into this registry, and
//! `revoke` removes them.
//!
//! Atomic .tmp + rename writes — mid-write crash leaves either the
//! prior good file OR the new good file, never a half-written one.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::discovery::DiscoveryVia;

/// One paired peer — the operator confirmed this device + it's now
/// part of the cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PairedPeer {
    /// 64-char lowercase-hex of the peer's ed25519 pub key.
    pub pub_key_hex: String,
    /// Operator-readable label as the peer announced.
    pub instance_label: String,
    /// Last-known socket address. Phase 6 gossip updates this on
    /// successful reconnect.
    pub addr: String,
    /// Transport that surfaced the peer initially.
    pub discovered_via: DiscoveryVia,
    /// Unix seconds when the operator confirmed the peer.
    pub paired_at_unix: i64,
    /// Unix seconds when discovery last saw this peer announce.
    /// Phase 2+ refreshes on each successful HMAC-verified announce.
    pub last_seen_unix: i64,
}

impl Default for PairedPeer {
    fn default() -> Self {
        Self {
            pub_key_hex: String::new(),
            instance_label: String::new(),
            addr: String::new(),
            discovered_via: DiscoveryVia::Manual,
            paired_at_unix: 0,
            last_seen_unix: 0,
        }
    }
}

/// Top-level shape of `~/.neoth/cluster.yaml`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterRegistry {
    /// All confirmed peers, sorted by `pub_key_hex` for stable
    /// on-disk diffs.
    pub peers: Vec<PairedPeer>,
}

/// Default path: `<neoth_home>/cluster.yaml`.
pub fn default_path(home: &Path) -> PathBuf {
    home.join("cluster.yaml")
}

/// Load the registry. Missing file → empty default. Malformed
/// YAML is a hard error — silently disabling every paired peer
/// would mask the corruption.
pub fn load(home: &Path) -> Result<ClusterRegistry> {
    let path = default_path(home);
    if !path.exists() {
        return Ok(ClusterRegistry::default());
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read cluster registry at {}", path.display()))?;
    let mut reg: ClusterRegistry = serde_yaml::from_str(&body)
        .with_context(|| format!("parse cluster registry YAML at {}", path.display()))?;
    reg.peers.sort_by(|a, b| a.pub_key_hex.cmp(&b.pub_key_hex));
    Ok(reg)
}

/// Write the registry atomically via `.tmp` + rename.
pub fn save(home: &Path, reg: &ClusterRegistry) -> Result<()> {
    let path = default_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create cluster registry dir {}", parent.display()))?;
    }
    // Sort before write so on-disk order is stable across runs.
    let mut sorted = reg.clone();
    sorted
        .peers
        .sort_by(|a, b| a.pub_key_hex.cmp(&b.pub_key_hex));
    let tmp = path.with_extension("yaml.tmp");
    let body = serde_yaml::to_string(&sorted).with_context(|| "serialize cluster registry")?;
    std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Add or update a peer. If a peer with the same `pub_key_hex`
/// exists, the new entry replaces the old (preserves `paired_at_unix`
/// from the original — re-confirm doesn't reset the timestamp).
pub fn upsert(home: &Path, mut peer: PairedPeer) -> Result<()> {
    let mut reg = load(home)?;
    if let Some(existing) = reg.peers.iter().find(|p| p.pub_key_hex == peer.pub_key_hex) {
        peer.paired_at_unix = existing.paired_at_unix;
    }
    reg.peers.retain(|p| p.pub_key_hex != peer.pub_key_hex);
    reg.peers.push(peer);
    save(home, &reg)
}

/// Remove a peer by pub_key_hex (or unique prefix). Returns Ok(true)
/// when a peer was removed, Ok(false) when no match found (idempotent
/// `revoke` on a ghost is a no-op).
///
/// Prefix matching: when `key_or_prefix` is shorter than 64 chars,
/// matches any peer whose `pub_key_hex` starts with it. Errors on
/// ambiguous match (multiple peers with that prefix).
pub fn remove(home: &Path, key_or_prefix: &str) -> Result<bool> {
    let mut reg = load(home)?;
    let matches: Vec<usize> = reg
        .peers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.pub_key_hex.starts_with(key_or_prefix))
        .map(|(i, _)| i)
        .collect();
    match matches.len() {
        0 => Ok(false),
        1 => {
            reg.peers.remove(matches[0]);
            save(home, &reg)?;
            Ok(true)
        }
        n => anyhow::bail!(
            "prefix `{}` matches {} peers — use a longer prefix",
            key_or_prefix,
            n
        ),
    }
}

/// True when a peer with the given pub_key_hex (or unique prefix)
/// is already paired.
pub fn is_paired(home: &Path, key_or_prefix: &str) -> bool {
    let Ok(reg) = load(home) else {
        return false;
    };
    reg.peers
        .iter()
        .any(|p| p.pub_key_hex.starts_with(key_or_prefix))
}

/// Update `last_seen_unix` for a paired peer. No-op when the peer
/// isn't paired yet — Phase 2 discovery passes every authenticated
/// announce through this; only the paired ones update.
pub fn refresh_last_seen(home: &Path, pub_key_hex: &str, ts_unix: i64) -> Result<bool> {
    let mut reg = load(home)?;
    let mut changed = false;
    for p in reg.peers.iter_mut() {
        if p.pub_key_hex == pub_key_hex {
            p.last_seen_unix = ts_unix;
            changed = true;
            break;
        }
    }
    if changed {
        save(home, &reg)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_peer(hex_prefix: &str, label: &str) -> PairedPeer {
        let full = format!("{hex_prefix}{}", "0".repeat(64 - hex_prefix.len()));
        PairedPeer {
            pub_key_hex: full,
            instance_label: label.into(),
            addr: "192.0.2.1:4242".into(),
            discovered_via: DiscoveryVia::Mdns,
            paired_at_unix: 1_700_000_000,
            last_seen_unix: 1_700_000_000,
        }
    }

    #[test]
    fn load_missing_file_returns_empty_default() {
        let dir = tempdir().unwrap();
        let reg = load(dir.path()).unwrap();
        assert!(reg.peers.is_empty());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let mut reg = ClusterRegistry::default();
        reg.peers.push(sample_peer("ab", "laptop"));
        reg.peers.push(sample_peer("cd", "server"));
        save(dir.path(), &reg).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.peers.len(), 2);
        // Sort order pinned: alphabetical by pub_key_hex.
        assert_eq!(loaded.peers[0].instance_label, "laptop");
        assert_eq!(loaded.peers[1].instance_label, "server");
    }

    #[test]
    fn upsert_adds_new_peer() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "alpha")).unwrap();
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers.len(), 1);
        assert_eq!(reg.peers[0].instance_label, "alpha");
    }

    #[test]
    fn upsert_preserves_original_paired_at_on_reconfirm() {
        let dir = tempdir().unwrap();
        let original = sample_peer("ab", "alpha");
        let orig_ts = original.paired_at_unix;
        upsert(dir.path(), original).unwrap();
        // Re-confirm with a different label + a NEW paired_at — the
        // original ts must survive.
        let mut updated = sample_peer("ab", "alpha-renamed");
        updated.paired_at_unix = 9_999_999_999;
        upsert(dir.path(), updated).unwrap();
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers.len(), 1);
        assert_eq!(reg.peers[0].instance_label, "alpha-renamed");
        assert_eq!(reg.peers[0].paired_at_unix, orig_ts);
    }

    #[test]
    fn remove_full_key_returns_true_on_first_call() {
        let dir = tempdir().unwrap();
        let peer = sample_peer("ab", "alpha");
        let full_key = peer.pub_key_hex.clone();
        upsert(dir.path(), peer).unwrap();
        assert!(remove(dir.path(), &full_key).unwrap());
        // Second call is no-op.
        assert!(!remove(dir.path(), &full_key).unwrap());
    }

    #[test]
    fn remove_short_prefix_works_when_unique() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "alpha")).unwrap();
        upsert(dir.path(), sample_peer("cd", "charlie")).unwrap();
        // Short prefix "ab" unique → removes alpha.
        assert!(remove(dir.path(), "ab").unwrap());
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers.len(), 1);
        assert_eq!(reg.peers[0].instance_label, "charlie");
    }

    #[test]
    fn remove_ambiguous_prefix_errors() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab1", "alpha")).unwrap();
        upsert(dir.path(), sample_peer("ab2", "bravo")).unwrap();
        let err = remove(dir.path(), "ab").unwrap_err();
        assert!(err.to_string().contains("matches 2"));
    }

    #[test]
    fn is_paired_finds_full_and_prefix() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("dead", "alpha")).unwrap();
        assert!(is_paired(dir.path(), "dead"));
        assert!(is_paired(
            dir.path(),
            "dead0000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_paired(dir.path(), "beef"));
    }

    #[test]
    fn refresh_last_seen_updates_paired_only() {
        let dir = tempdir().unwrap();
        let mut peer = sample_peer("ab", "alpha");
        peer.last_seen_unix = 100;
        upsert(dir.path(), peer.clone()).unwrap();
        // Update via full pub_key_hex.
        assert!(refresh_last_seen(dir.path(), &peer.pub_key_hex, 200).unwrap());
        let reg = load(dir.path()).unwrap();
        assert_eq!(reg.peers[0].last_seen_unix, 200);
        // Unknown peer → no-op false.
        let ghost = format!("ff{}", "0".repeat(62));
        assert!(!refresh_last_seen(dir.path(), &ghost, 999).unwrap());
    }

    #[test]
    fn save_atomic_leaves_no_tmp() {
        let dir = tempdir().unwrap();
        upsert(dir.path(), sample_peer("ab", "a")).unwrap();
        let tmp = default_path(dir.path()).with_extension("yaml.tmp");
        assert!(!tmp.exists());
    }

    #[test]
    fn malformed_yaml_is_hard_error() {
        let dir = tempdir().unwrap();
        std::fs::write(default_path(dir.path()), ": : :\n").unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn paired_peer_serde_round_trip_preserves_every_field() {
        let original = PairedPeer {
            pub_key_hex: "ab".repeat(32),
            instance_label: "label".into(),
            addr: "10.0.0.5:443".into(),
            discovered_via: DiscoveryVia::Tailscale,
            paired_at_unix: 1_234_567_890,
            last_seen_unix: 1_234_567_999,
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        let back: PairedPeer = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }
}
