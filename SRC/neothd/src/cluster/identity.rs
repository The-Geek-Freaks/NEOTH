//! SL-00 — cluster identity resolution.
//!
//! Combines the PUBLIC rendezvous name (`freedom.yaml::cluster.name`) with the
//! SECRET shared passphrase (`credentials.yaml::cluster_passphrase`) into the
//! pair every cluster transport needs: a topic name + the HMAC `cluster_key`.
//!
//! Fail-closed: BOTH halves are required. Missing either ⇒ no identity ⇒ the
//! transport stays inert (the daemon never announces on the public DHT, and
//! no announce/frame can be authenticated). This is the gate SL-00(1b) will
//! consult before bringing the Hyperswarm transport up.

use crate::cluster::discovery::{ClusterKey, cluster_key};
use crate::config::FreedomConfig;
use crate::config::credentials::Credentials;

/// A fully-resolved cluster identity. The `key` is never logged/printed.
pub struct ClusterIdentity {
    /// Public rendezvous name — seeds the Hyperswarm DHT topic + mDNS service.
    pub name: String,
    /// HMAC key derived from the shared passphrase. Authenticates announces,
    /// gossip frames, and delegated-task frames.
    pub key: ClusterKey,
}

impl std::fmt::Debug for ClusterIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterIdentity")
            .field("name", &self.name)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Resolve the cluster identity, or `None` when this node has no cluster
/// configured. Fail-closed: a non-empty `cluster.name` AND a non-empty
/// `cluster_passphrase` are both required.
pub fn resolve_cluster_identity(
    freedom: &FreedomConfig,
    creds: &Credentials,
) -> Option<ClusterIdentity> {
    let name = freedom
        .cluster
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let phrase = creds.cluster_passphrase.as_ref()?.expose();
    // `cluster_key` returns None on an empty/whitespace phrase.
    let key = cluster_key(phrase)?;
    Some(ClusterIdentity {
        name: name.to_string(),
        key,
    })
}

/// SL-00(1b) transport activation gate. Returns `Some(identity)` ONLY when
/// BOTH the master-switch is on (`cluster.enabled == true`) AND a full
/// identity resolves. This is the single source of truth the daemon consults
/// before bringing the Hyperswarm transport up — keeping it a pure function
/// (instead of inline in `serve`) makes the safety gate unit-testable.
///
/// Default-install behaviour: `enabled` defaults `false`, so a fresh node
/// returns `None` here even if a stray name/passphrase were present ⇒ no
/// DHT announce. Fail-closed on every axis.
pub fn cluster_transport_activation(
    freedom: &FreedomConfig,
    creds: &Credentials,
) -> Option<ClusterIdentity> {
    if !freedom.cluster.enabled {
        return None;
    }
    resolve_cluster_identity(freedom, creds)
}

/// Operator-facing identity status (for `neoth cluster status` / doctor).
/// Reports whether a cluster identity is configured + the PUBLIC name; never
/// exposes the key or the passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterIdentityStatus {
    pub name: Option<String>,
    pub has_passphrase: bool,
    /// True only when BOTH a name and a passphrase are present.
    pub configured: bool,
    /// The transport master-switch (`cluster.enabled`). Reported separately
    /// from `configured` so the operator can tell a complete-but-disabled
    /// identity apart from a live transport.
    pub enabled: bool,
    /// True only when the identity is complete AND the master-switch is on —
    /// i.e. the daemon will actually bring the Hyperswarm transport up. Mirrors
    /// [`cluster_transport_activation`] returning `Some`.
    pub transport_active: bool,
}

pub fn cluster_identity_status(
    freedom: &FreedomConfig,
    creds: &Credentials,
) -> ClusterIdentityStatus {
    let name = freedom
        .cluster
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let has_passphrase = creds
        .cluster_passphrase
        .as_ref()
        .map(|s| !s.expose().trim().is_empty())
        .unwrap_or(false);
    let configured = name.is_some() && has_passphrase;
    let enabled = freedom.cluster.enabled;
    ClusterIdentityStatus {
        name,
        has_passphrase,
        configured,
        enabled,
        transport_active: configured && enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClusterConfig;
    use crate::secret::SecretString;

    fn freedom_with_name(name: Option<&str>) -> FreedomConfig {
        let mut f = FreedomConfig::default();
        f.cluster = ClusterConfig {
            name: name.map(str::to_string),
            ..Default::default()
        };
        f
    }
    fn creds_with_phrase(phrase: Option<&str>) -> Credentials {
        let mut c = Credentials::default();
        c.cluster_passphrase = phrase.map(|p| SecretString::new(p.to_string()));
        c
    }

    #[test]
    fn resolves_when_both_present() {
        let id = resolve_cluster_identity(
            &freedom_with_name(Some("home-lab")),
            &creds_with_phrase(Some("alpha bravo charlie delta")),
        )
        .expect("both present ⇒ Some");
        assert_eq!(id.name, "home-lab");
    }

    #[test]
    fn fail_closed_without_name() {
        assert!(
            resolve_cluster_identity(
                &freedom_with_name(None),
                &creds_with_phrase(Some("alpha bravo charlie delta"))
            )
            .is_none(),
            "no name ⇒ no identity"
        );
        // Empty/whitespace name is also rejected.
        assert!(
            resolve_cluster_identity(
                &freedom_with_name(Some("   ")),
                &creds_with_phrase(Some("alpha bravo charlie delta"))
            )
            .is_none()
        );
    }

    #[test]
    fn fail_closed_without_passphrase() {
        assert!(
            resolve_cluster_identity(
                &freedom_with_name(Some("home-lab")),
                &creds_with_phrase(None)
            )
            .is_none(),
            "no passphrase ⇒ no identity"
        );
        // Empty passphrase ⇒ cluster_key returns None ⇒ no identity.
        assert!(
            resolve_cluster_identity(
                &freedom_with_name(Some("home-lab")),
                &creds_with_phrase(Some("   "))
            )
            .is_none()
        );
    }

    /// Build a freedom config with name + the transport master-switch state.
    fn freedom_with(name: Option<&str>, enabled: bool) -> FreedomConfig {
        let mut f = FreedomConfig::default();
        f.cluster = ClusterConfig {
            name: name.map(str::to_string),
            enabled,
            ..Default::default()
        };
        f
    }

    #[test]
    fn activation_gate_truth_table() {
        let full_phrase = creds_with_phrase(Some("alpha bravo charlie delta"));

        // 1. Master-switch OFF + full identity ⇒ None (the default-install
        //    safety gate: even a stray name+passphrase never auto-announces).
        assert!(
            cluster_transport_activation(&freedom_with(Some("home-lab"), false), &full_phrase)
                .is_none(),
            "enabled=false MUST gate the transport off even with a full identity"
        );

        // 2. Master-switch ON but no name ⇒ None.
        assert!(
            cluster_transport_activation(&freedom_with(None, true), &full_phrase).is_none(),
            "enabled=true without a name ⇒ no transport"
        );

        // 3. Master-switch ON, name present, but no passphrase ⇒ None.
        assert!(
            cluster_transport_activation(
                &freedom_with(Some("home-lab"), true),
                &creds_with_phrase(None)
            )
            .is_none(),
            "enabled=true without a passphrase ⇒ no transport"
        );

        // 4. Master-switch ON + full identity ⇒ Some (the only activation path).
        let active =
            cluster_transport_activation(&freedom_with(Some("home-lab"), true), &full_phrase)
                .expect("enabled=true + full identity ⇒ transport activates");
        assert_eq!(active.name, "home-lab");
    }

    #[test]
    fn status_reports_enabled_and_transport_active() {
        let phrase = creds_with_phrase(Some("alpha bravo charlie delta"));
        // Complete identity, switch OFF ⇒ configured but NOT active.
        let off = cluster_identity_status(&freedom_with(Some("home-lab"), false), &phrase);
        assert!(off.configured);
        assert!(!off.enabled);
        assert!(!off.transport_active, "switch off ⇒ transport not active");
        // Complete identity, switch ON ⇒ active.
        let on = cluster_identity_status(&freedom_with(Some("home-lab"), true), &phrase);
        assert!(on.configured && on.enabled && on.transport_active);
        // Switch ON but identity incomplete ⇒ enabled true, but not active.
        let incomplete = cluster_identity_status(&freedom_with(None, true), &phrase);
        assert!(incomplete.enabled);
        assert!(!incomplete.configured);
        assert!(
            !incomplete.transport_active,
            "enabled without identity ⇒ not active"
        );
    }

    #[test]
    fn default_install_never_activates() {
        // A pristine FreedomConfig + empty Credentials must never bring the
        // transport up — the single most important invariant of this slice.
        assert!(
            cluster_transport_activation(&FreedomConfig::default(), &Credentials::default())
                .is_none(),
            "fresh install MUST NOT join any cluster / announce on the DHT"
        );
    }

    #[test]
    fn same_phrase_same_key_deterministic() {
        let a = resolve_cluster_identity(
            &freedom_with_name(Some("x")),
            &creds_with_phrase(Some("the same phrase")),
        )
        .unwrap();
        let b = resolve_cluster_identity(
            &freedom_with_name(Some("y")),
            &creds_with_phrase(Some("the same phrase")),
        )
        .unwrap();
        assert_eq!(
            a.key.0, b.key.0,
            "same phrase ⇒ same key regardless of name"
        );
    }

    #[test]
    fn status_reports_configured_only_when_complete() {
        let full = cluster_identity_status(
            &freedom_with_name(Some("home-lab")),
            &creds_with_phrase(Some("alpha bravo charlie delta")),
        );
        assert!(full.configured);
        assert_eq!(full.name.as_deref(), Some("home-lab"));
        assert!(full.has_passphrase);

        let name_only = cluster_identity_status(
            &freedom_with_name(Some("home-lab")),
            &creds_with_phrase(None),
        );
        assert!(
            !name_only.configured,
            "name without passphrase is not configured"
        );
        assert!(!name_only.has_passphrase);

        let neither = cluster_identity_status(&freedom_with_name(None), &creds_with_phrase(None));
        assert!(!neither.configured);
        assert!(neither.name.is_none());
    }

    #[test]
    fn debug_redacts_key() {
        let id = resolve_cluster_identity(
            &freedom_with_name(Some("home-lab")),
            &creds_with_phrase(Some("alpha bravo charlie delta")),
        )
        .unwrap();
        let dbg = format!("{id:?}");
        assert!(dbg.contains("home-lab"));
        assert!(dbg.contains("<redacted>"), "key must never appear in Debug");
    }
}
