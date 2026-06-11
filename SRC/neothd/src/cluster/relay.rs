//! Cluster Phase 5 — Hysteria-shared relay registration primitives.
//!
//! Per the Session 21 architect verdict (`neoth_open_decisions_verdicts`):
//!   - **Standalone `neoth-relay` daemon**, not embedded in `neothd`
//!     and not forked from Hysteria. Single-responsibility + AIO
//!     compliant install path.
//!   - **5 peers per cluster_key cap** — covers all realistic personal
//!     topologies (home + work + laptop + phone + spare), prevents a
//!     compromised cluster_key flooding the relay with synthetic peers.
//!   - **Single-relay-per-cluster** in Phase 5; defer mesh federation
//!     to Phase 5.4 once the single-relay baseline is battle-tested.
//!
//! v0.1 scope = **registration protocol types + roster + cap enforcement
//! primitives + tests**. The actual `neoth-relay` binary + the
//! Hysteria-side socket plumbing + the relay-to-relay mesh ship in
//! follow-up bites per
//! `PLAN/SPEC_cluster_phase5_hysteria_relay_2026-05-22.md`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Default peer-cap per `cluster_key`. Five = home + work + laptop +
/// phone + spare; covers every realistic single-operator personal
/// topology while keeping a compromised key from flooding the relay.
pub const DEFAULT_MAX_PEERS_PER_KEY: u32 = 5;

/// Hard ceiling regardless of operator override. Beyond 50 the
/// relay's per-key bucket walking becomes a hot path + a single
/// compromised key becomes a real DoS vector.
pub const MAX_PEERS_PER_KEY_CEILING: u32 = 50;

/// GR-009 — env var the relay **client** reads its bearer token from,
/// mirroring the `neoth-relay` server (`SRC/neoth-relay/src/main.rs`).
/// The token is a shared secret, so it is sourced from the environment
/// ONLY and is deliberately NOT a [`RelayConfig`] field — that keeps it
/// out of `freedom.yaml` (where it would land in plaintext on disk and in
/// every config backup). When the relay-client transport ships (Phase 5
/// follow-up, `SPEC_cluster_phase5_hysteria_relay`), its registration
/// request sends `Authorization: Bearer <resolve_token()>`.
pub const RELAY_TOKEN_ENV: &str = "NEOTH_RELAY_TOKEN";

/// Operator-tweakable relay knobs (lives at
/// `freedom.yaml::cluster.relay`).
///
/// GR-009 — note the absence of a `token` field: the relay's bearer
/// secret is env-only ([`RELAY_TOKEN_ENV`]), never serialized here, so it
/// cannot leak into the on-disk `freedom.yaml`. The
/// `relay_config_yaml_carries_no_token_field` test guards against a future
/// contributor re-introducing a serde token field.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct RelayConfig {
    /// Reachable address of the operator's `neoth-relay`
    /// (e.g. `relay.example.org:443`). Empty = no relay configured;
    /// the operator stays single-cluster + LAN/Tailscale-only.
    pub endpoint: String,
    /// Peer-cap per cluster_key. Default 5; operator override
    /// clamped to `[1, MAX_PEERS_PER_KEY_CEILING]`.
    pub max_peers_per_key: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            max_peers_per_key: DEFAULT_MAX_PEERS_PER_KEY,
        }
    }
}

impl RelayConfig {
    /// Resolved cap — clamps the operator's value to the safe range
    /// with tracing-warn on clamp.
    pub fn resolved_max_peers(&self) -> u32 {
        if self.max_peers_per_key == 0 {
            tracing::warn!(
                "RelayConfig: max_peers_per_key=0 disables the relay entirely; \
                 clamping to default {DEFAULT_MAX_PEERS_PER_KEY}"
            );
            return DEFAULT_MAX_PEERS_PER_KEY;
        }
        if self.max_peers_per_key > MAX_PEERS_PER_KEY_CEILING {
            tracing::warn!(
                requested = self.max_peers_per_key,
                ceiling = MAX_PEERS_PER_KEY_CEILING,
                "RelayConfig: max_peers_per_key above ceiling; clamping"
            );
            return MAX_PEERS_PER_KEY_CEILING;
        }
        self.max_peers_per_key
    }

    /// True ⇔ operator has configured a relay endpoint.
    pub fn is_configured(&self) -> bool {
        !self.endpoint.trim().is_empty()
    }

    /// GR-009 — resolve the relay bearer token from the environment
    /// ([`RELAY_TOKEN_ENV`]), mirroring the `neoth-relay` server's own
    /// CLI-flag-or-env resolution. Returns `None` when unset or blank
    /// (whitespace-only), so the future relay-client transport can decide
    /// to connect token-less only against a loopback/dev relay. The token
    /// is never read from `self` — it is env-only by design, never a
    /// `freedom.yaml` field.
    pub fn resolve_token(&self) -> Option<String> {
        Self::token_from_env(std::env::var(RELAY_TOKEN_ENV).ok())
    }

    /// Pure core of [`resolve_token`] — a raw env value maps to a usable
    /// token only when present and non-blank. Split out so the filtering
    /// rule is unit-tested without touching process env (which races other
    /// tests — see `memory/neoth_ci_env_race_flakiness`).
    fn token_from_env(raw: Option<String>) -> Option<String> {
        raw.filter(|t| !t.trim().is_empty())
    }
}

/// One peer registration record stored in the relay's per-cluster
/// roster. Wire shape — serde-stable for the future
/// `neoth-relay` HTTP / WebSocket admin surface.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelayRegistration {
    /// 64-char lowercase-hex of the operator's cluster_key (shared
    /// secret derived in Cluster Phase 1 — see `cluster::discovery`).
    pub cluster_key_hex: String,
    /// 64-char lowercase-hex of the peer's ed25519 pub key.
    pub peer_pub_key_hex: String,
    /// Operator-readable instance label ("my-laptop", "home-server", ...).
    pub instance_label: String,
    /// Listen port the peer expects relayed connections on.
    pub listen_port: u16,
    /// Unix seconds when the registration was created / last
    /// refreshed. Relay-side garbage-collection drops registrations
    /// older than the operator-tuned TTL.
    pub registered_at_unix: i64,
}

/// In-memory roster the relay maintains. Keyed by `cluster_key_hex`
/// → Vec of registrations. Pure data — actual relay daemon owns
/// the Arc<RwLock<PeerRoster>> wrapper for concurrent access.
#[derive(Clone, Debug, Default)]
pub struct PeerRoster {
    pub max_peers_per_key: u32,
    pub buckets: HashMap<String, Vec<RelayRegistration>>,
}

/// Outcome of `register()`. Operator-visible — `neoth-relay`'s admin
/// HTTP surface returns one of these tags per registration call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// New peer pub_key added to the cluster's bucket.
    Registered,
    /// Existing pub_key — bumped `registered_at_unix` in place.
    Refreshed,
    /// Bucket already at the operator-configured cap +
    /// the incoming pub_key isn't already present. Caller bails
    /// with operator-readable error; legitimate operator who hit
    /// the cap removes a stale peer via `neoth cluster revoke
    /// <pub_key>` first.
    RejectedAtCap { cap: u32 },
    /// Malformed registration (wrong hex length, zero-byte fields).
    /// Defensive — the relay never panics on hostile input.
    Malformed { reason: &'static str },
}

impl PeerRoster {
    pub fn new(max_peers_per_key: u32) -> Self {
        Self {
            max_peers_per_key,
            buckets: HashMap::new(),
        }
    }

    /// Count peers currently in the cluster's bucket. Zero when
    /// the cluster is unknown.
    pub fn count_for(&self, cluster_key_hex: &str) -> usize {
        self.buckets
            .get(cluster_key_hex)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Register (or refresh) one peer in the roster. Enforces the
    /// per-key cap; rejects malformed inputs.
    pub fn register(&mut self, reg: RelayRegistration) -> RegistrationOutcome {
        // Defensive validation — the relay surface MUST stay safe
        // against malformed inputs from compromised/rogue clients.
        if reg.cluster_key_hex.len() != 64
            || !reg
                .cluster_key_hex
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return RegistrationOutcome::Malformed {
                reason: "cluster_key_hex must be 64 lowercase-hex chars",
            };
        }
        if reg.peer_pub_key_hex.len() != 64
            || !reg
                .peer_pub_key_hex
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
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
        let bucket = self.buckets.entry(reg.cluster_key_hex.clone()).or_default();
        // Refresh path — pub_key already present in bucket.
        if let Some(existing) = bucket
            .iter_mut()
            .find(|r| r.peer_pub_key_hex == reg.peer_pub_key_hex)
        {
            existing.instance_label = reg.instance_label;
            existing.listen_port = reg.listen_port;
            existing.registered_at_unix = reg.registered_at_unix;
            return RegistrationOutcome::Refreshed;
        }
        // Add path — bucket at cap rejects.
        if bucket.len() >= self.max_peers_per_key as usize {
            return RegistrationOutcome::RejectedAtCap {
                cap: self.max_peers_per_key,
            };
        }
        bucket.push(reg);
        RegistrationOutcome::Registered
    }

    /// Remove a peer from its bucket. Returns true when something
    /// was actually removed; false when the pub_key wasn't present
    /// (operator already revoked, or registration never reached
    /// the relay).
    pub fn unregister(&mut self, cluster_key_hex: &str, peer_pub_key_hex: &str) -> bool {
        let Some(bucket) = self.buckets.get_mut(cluster_key_hex) else {
            return false;
        };
        let before = bucket.len();
        bucket.retain(|r| r.peer_pub_key_hex != peer_pub_key_hex);
        let removed = bucket.len() < before;
        if bucket.is_empty() {
            // Tidy: drop empty buckets so iteration costs stay
            // proportional to active clusters.
            self.buckets.remove(cluster_key_hex);
        }
        removed
    }

    /// Drop registrations older than `cap_age_secs` (used by the
    /// relay's GC tick — stale peers that never refreshed beyond
    /// the TTL get evicted).
    pub fn prune_stale(&mut self, now_ts_unix: i64, cap_age_secs: i64) -> usize {
        let mut evicted = 0;
        self.buckets.retain(|_key, bucket| {
            let before = bucket.len();
            bucket.retain(|r| now_ts_unix.saturating_sub(r.registered_at_unix) <= cap_age_secs);
            evicted += before - bucket.len();
            !bucket.is_empty()
        });
        evicted
    }

    /// Total peer count across every cluster — operator-readable
    /// "load" metric for the relay's admin HTTP surface.
    pub fn total_peers(&self) -> usize {
        self.buckets.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(cluster: &str, peer: &str, port: u16, ts: i64) -> RelayRegistration {
        RelayRegistration {
            cluster_key_hex: cluster.to_string(),
            peer_pub_key_hex: peer.to_string(),
            instance_label: format!("peer-{}", &peer[..4]),
            listen_port: port,
            registered_at_unix: ts,
        }
    }

    fn hex64(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn default_config_uses_5_peers_per_key() {
        let cfg = RelayConfig::default();
        assert_eq!(cfg.max_peers_per_key, DEFAULT_MAX_PEERS_PER_KEY);
        assert_eq!(cfg.resolved_max_peers(), 5);
    }

    #[test]
    fn default_config_has_empty_endpoint() {
        let cfg = RelayConfig::default();
        assert!(cfg.endpoint.is_empty());
        assert!(!cfg.is_configured());
    }

    #[test]
    fn is_configured_reads_endpoint() {
        let mut cfg = RelayConfig::default();
        cfg.endpoint = "relay.example.org:443".into();
        assert!(cfg.is_configured());
        cfg.endpoint = "   ".into();
        assert!(
            !cfg.is_configured(),
            "whitespace-only endpoint is unconfigured"
        );
    }

    #[test]
    fn resolved_max_peers_clamps_zero_to_default() {
        let mut cfg = RelayConfig::default();
        cfg.max_peers_per_key = 0;
        assert_eq!(cfg.resolved_max_peers(), DEFAULT_MAX_PEERS_PER_KEY);
    }

    #[test]
    fn resolved_max_peers_clamps_excessive_to_ceiling() {
        let mut cfg = RelayConfig::default();
        cfg.max_peers_per_key = 9_999;
        assert_eq!(cfg.resolved_max_peers(), MAX_PEERS_PER_KEY_CEILING);
    }

    #[test]
    fn roster_registers_new_peer() {
        let mut roster = PeerRoster::new(5);
        let outcome = roster.register(registration(&hex64(0xaa), &hex64(0x01), 4242, 1));
        assert_eq!(outcome, RegistrationOutcome::Registered);
        assert_eq!(roster.count_for(&hex64(0xaa)), 1);
        assert_eq!(roster.total_peers(), 1);
    }

    #[test]
    fn roster_refreshes_existing_peer_in_place() {
        let mut roster = PeerRoster::new(5);
        roster.register(registration(&hex64(0xaa), &hex64(0x01), 4242, 1));
        let outcome = roster.register(registration(&hex64(0xaa), &hex64(0x01), 5252, 1234));
        assert_eq!(outcome, RegistrationOutcome::Refreshed);
        assert_eq!(roster.count_for(&hex64(0xaa)), 1, "no duplicate add");
        let bucket = roster.buckets.get(&hex64(0xaa)).unwrap();
        assert_eq!(bucket[0].listen_port, 5252);
        assert_eq!(bucket[0].registered_at_unix, 1234);
    }

    #[test]
    fn roster_rejects_at_cap() {
        let mut roster = PeerRoster::new(2);
        let cluster = hex64(0xaa);
        assert_eq!(
            roster.register(registration(&cluster, &hex64(0x01), 1, 1)),
            RegistrationOutcome::Registered
        );
        assert_eq!(
            roster.register(registration(&cluster, &hex64(0x02), 2, 2)),
            RegistrationOutcome::Registered
        );
        // 3rd unique peer in a cap=2 bucket → rejected.
        assert_eq!(
            roster.register(registration(&cluster, &hex64(0x03), 3, 3)),
            RegistrationOutcome::RejectedAtCap { cap: 2 }
        );
        assert_eq!(roster.count_for(&cluster), 2);
    }

    #[test]
    fn roster_allows_refresh_even_at_cap() {
        let mut roster = PeerRoster::new(2);
        let cluster = hex64(0xaa);
        roster.register(registration(&cluster, &hex64(0x01), 1, 1));
        roster.register(registration(&cluster, &hex64(0x02), 2, 2));
        // Existing pub_key 0x01 re-registers — should refresh, not reject.
        assert_eq!(
            roster.register(registration(&cluster, &hex64(0x01), 9, 9)),
            RegistrationOutcome::Refreshed
        );
    }

    #[test]
    fn roster_rejects_malformed_cluster_key() {
        let mut roster = PeerRoster::new(5);
        let bad = registration("ZZZ", &hex64(0x01), 1, 1);
        assert!(matches!(
            roster.register(bad),
            RegistrationOutcome::Malformed { .. }
        ));
    }

    #[test]
    fn roster_rejects_malformed_peer_pub_key() {
        let mut roster = PeerRoster::new(5);
        let bad = registration(&hex64(0xaa), "short", 1, 1);
        assert!(matches!(
            roster.register(bad),
            RegistrationOutcome::Malformed { .. }
        ));
    }

    #[test]
    fn roster_rejects_uppercase_hex() {
        let mut roster = PeerRoster::new(5);
        let bad = RelayRegistration {
            cluster_key_hex: "AA".repeat(32),
            peer_pub_key_hex: hex64(0x01),
            instance_label: "x".into(),
            listen_port: 1,
            registered_at_unix: 1,
        };
        assert!(matches!(
            roster.register(bad),
            RegistrationOutcome::Malformed { .. }
        ));
    }

    #[test]
    fn roster_rejects_empty_label() {
        let mut roster = PeerRoster::new(5);
        let bad = RelayRegistration {
            cluster_key_hex: hex64(0xaa),
            peer_pub_key_hex: hex64(0x01),
            instance_label: "   ".into(),
            listen_port: 1,
            registered_at_unix: 1,
        };
        assert!(matches!(
            roster.register(bad),
            RegistrationOutcome::Malformed { .. }
        ));
    }

    #[test]
    fn roster_rejects_zero_port() {
        let mut roster = PeerRoster::new(5);
        let bad = registration(&hex64(0xaa), &hex64(0x01), 0, 1);
        assert!(matches!(
            roster.register(bad),
            RegistrationOutcome::Malformed { .. }
        ));
    }

    #[test]
    fn roster_unregister_returns_true_when_present() {
        let mut roster = PeerRoster::new(5);
        roster.register(registration(&hex64(0xaa), &hex64(0x01), 1, 1));
        assert!(roster.unregister(&hex64(0xaa), &hex64(0x01)));
        assert_eq!(roster.count_for(&hex64(0xaa)), 0);
        assert!(
            !roster.buckets.contains_key(&hex64(0xaa)),
            "empty bucket dropped"
        );
    }

    #[test]
    fn roster_unregister_returns_false_when_absent() {
        let mut roster = PeerRoster::new(5);
        assert!(!roster.unregister(&hex64(0xaa), &hex64(0x01)));
    }

    #[test]
    fn roster_prune_stale_evicts_old_registrations() {
        let mut roster = PeerRoster::new(5);
        let cluster = hex64(0xaa);
        roster.register(registration(&cluster, &hex64(0x01), 1, 1_000));
        roster.register(registration(&cluster, &hex64(0x02), 2, 2_000));
        // Cap age 500s; now = 3_000 → both registrations older than cap.
        let evicted = roster.prune_stale(3_000, 500);
        assert_eq!(evicted, 2);
        assert_eq!(roster.total_peers(), 0);
    }

    #[test]
    fn roster_prune_stale_keeps_recent() {
        let mut roster = PeerRoster::new(5);
        let cluster = hex64(0xaa);
        roster.register(registration(&cluster, &hex64(0x01), 1, 1_000));
        roster.register(registration(&cluster, &hex64(0x02), 2, 2_900));
        // Cap age 500s; only the 1_000 registration is stale.
        let evicted = roster.prune_stale(3_000, 500);
        assert_eq!(evicted, 1);
        assert_eq!(roster.total_peers(), 1);
    }

    #[test]
    fn config_serde_round_trip_via_yaml() {
        let original = RelayConfig {
            endpoint: "relay.example.org:443".into(),
            max_peers_per_key: 10,
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        let back: RelayConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn token_from_env_filters_blank_and_absent() {
        // GR-009: a real token survives; absent / blank env → no token.
        assert_eq!(
            RelayConfig::token_from_env(Some("s3cr3t-bearer".into())),
            Some("s3cr3t-bearer".into())
        );
        assert_eq!(RelayConfig::token_from_env(None), None);
        assert_eq!(RelayConfig::token_from_env(Some("   ".into())), None);
        assert_eq!(RelayConfig::token_from_env(Some(String::new())), None);
    }

    #[test]
    fn relay_config_yaml_carries_no_token_field() {
        // GR-009 secret-hygiene guard: the relay bearer token is env-only
        // (NEOTH_RELAY_TOKEN), NEVER a serialized config field — otherwise
        // it would land in plaintext in freedom.yaml + every backup. If a
        // future change adds a serde `token`/`secret`/`bearer` field to
        // RelayConfig, this test fails and forces the env-only decision to
        // be re-justified.
        let cfg = RelayConfig {
            endpoint: "relay.example.org:443".into(),
            max_peers_per_key: 5,
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap().to_ascii_lowercase();
        for forbidden in ["token", "secret", "bearer", "password", "auth"] {
            assert!(
                !yaml.contains(forbidden),
                "RelayConfig yaml must not serialize a `{forbidden}` field \
                 (relay secret is env-only): {yaml}"
            );
        }
    }

    #[test]
    fn registration_serde_round_trip_via_yaml() {
        let original = registration(&hex64(0xaa), &hex64(0x01), 4242, 1_000);
        let yaml = serde_yaml::to_string(&original).unwrap();
        let back: RelayRegistration = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn constants_pinned() {
        assert_eq!(DEFAULT_MAX_PEERS_PER_KEY, 5);
        assert_eq!(MAX_PEERS_PER_KEY_CEILING, 50);
    }
}
