//! Cluster announce-policy helpers — Phase 2/3 operational privacy
//! per Q2 ratification ("`announce_on_untrusted_wifi: false`
//! flag — default false; operator-named trusted SSID list").
//!
//! The mDNS announcer fires only when the policy resolves to
//! `ShouldAnnounce::Yes`. On untrusted networks the announcer
//! stays silent — the operator's pub_key + instance label never
//! leak onto a shared LAN.
//!
//! Tailscale enumeration is unaffected (the tailnet itself is
//! the trust boundary).

use serde::{Deserialize, Serialize};

/// Operator-tweakable mDNS announce policy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct AnnouncePolicy {
    /// When true: announce on any reachable network. When false:
    /// announce only on SSIDs in `trusted_ssids`. Default false
    /// per Q2 ratification — opt-in to broadcasting.
    pub announce_on_untrusted_wifi: bool,
    /// SSIDs the operator marked as trusted for mDNS broadcasts.
    /// Match is case-sensitive whole-string (no glob/regex —
    /// operator can list multiple variants if their home network
    /// uses multiple SSIDs).
    pub trusted_ssids: Vec<String>,
}

/// Verdict returned by `evaluate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShouldAnnounce {
    /// Announcer should spawn / continue running.
    Yes,
    /// Announcer should stay silent. The reason carries
    /// operator-readable context for the doctor / status surface.
    No(NoReason),
}

/// Why the announcer is suppressed. Operator-readable via
/// `as_str()` for log lines + doctor detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoReason {
    /// `cluster.mdns.enabled = false` in freedom.yaml.
    Disabled,
    /// Current SSID isn't in the trusted list + the policy
    /// forbids broadcasting on untrusted networks.
    UntrustedSsid,
    /// No SSID information available (operator on wired / VPN /
    /// the OS doesn't expose it). Treated as "untrusted" — the
    /// announcer stays silent to err on the safe side.
    SsidUnknown,
}

impl NoReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "mdns_disabled",
            Self::UntrustedSsid => "untrusted_ssid",
            Self::SsidUnknown => "ssid_unknown",
        }
    }
}

/// Decide whether the announcer should run on the current network.
///
/// `mdns_enabled` = `freedom.yaml::cluster.mdns.enabled`.
/// `current_ssid` = SSID the caller obtained from the OS (typically
/// via `iwgetid` / `netsh wlan show interfaces` / `networksetup
/// -getairportnetwork`). `None` when wired / VPN / unknown.
pub fn evaluate(
    mdns_enabled: bool,
    policy: &AnnouncePolicy,
    current_ssid: Option<&str>,
) -> ShouldAnnounce {
    if !mdns_enabled {
        return ShouldAnnounce::No(NoReason::Disabled);
    }
    if policy.announce_on_untrusted_wifi {
        return ShouldAnnounce::Yes;
    }
    match current_ssid {
        None => ShouldAnnounce::No(NoReason::SsidUnknown),
        Some(ssid) if policy.trusted_ssids.iter().any(|s| s == ssid) => {
            ShouldAnnounce::Yes
        }
        Some(_) => ShouldAnnounce::No(NoReason::UntrustedSsid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_policy() -> AnnouncePolicy {
        AnnouncePolicy {
            announce_on_untrusted_wifi: true,
            trusted_ssids: vec![],
        }
    }

    fn strict_policy() -> AnnouncePolicy {
        AnnouncePolicy {
            announce_on_untrusted_wifi: false,
            trusted_ssids: vec!["home-wifi".into(), "home-wifi-5g".into()],
        }
    }

    #[test]
    fn disabled_short_circuits_regardless_of_policy() {
        assert_eq!(
            evaluate(false, &open_policy(), Some("anything")),
            ShouldAnnounce::No(NoReason::Disabled)
        );
        assert_eq!(
            evaluate(false, &strict_policy(), Some("home-wifi")),
            ShouldAnnounce::No(NoReason::Disabled)
        );
    }

    #[test]
    fn open_policy_announces_on_any_ssid() {
        assert_eq!(
            evaluate(true, &open_policy(), Some("coffee-shop")),
            ShouldAnnounce::Yes
        );
        assert_eq!(evaluate(true, &open_policy(), None), ShouldAnnounce::Yes);
    }

    #[test]
    fn strict_policy_announces_on_trusted_ssid() {
        assert_eq!(
            evaluate(true, &strict_policy(), Some("home-wifi")),
            ShouldAnnounce::Yes
        );
        assert_eq!(
            evaluate(true, &strict_policy(), Some("home-wifi-5g")),
            ShouldAnnounce::Yes
        );
    }

    #[test]
    fn strict_policy_suppresses_on_untrusted_ssid() {
        assert_eq!(
            evaluate(true, &strict_policy(), Some("coffee-shop")),
            ShouldAnnounce::No(NoReason::UntrustedSsid)
        );
    }

    #[test]
    fn strict_policy_suppresses_when_ssid_unknown() {
        // Wired connection, VPN, or OS that doesn't expose SSID
        // → err on the safe side.
        assert_eq!(
            evaluate(true, &strict_policy(), None),
            ShouldAnnounce::No(NoReason::SsidUnknown)
        );
    }

    #[test]
    fn ssid_match_is_case_sensitive() {
        // home-wifi != Home-WiFi → suppressed. Operators with
        // multiple capitalisations list both variants.
        assert_eq!(
            evaluate(true, &strict_policy(), Some("Home-WiFi")),
            ShouldAnnounce::No(NoReason::UntrustedSsid)
        );
    }

    #[test]
    fn no_reason_as_str_pinned() {
        assert_eq!(NoReason::Disabled.as_str(), "mdns_disabled");
        assert_eq!(NoReason::UntrustedSsid.as_str(), "untrusted_ssid");
        assert_eq!(NoReason::SsidUnknown.as_str(), "ssid_unknown");
    }

    #[test]
    fn default_policy_is_opt_in() {
        let p = AnnouncePolicy::default();
        assert!(!p.announce_on_untrusted_wifi);
        assert!(p.trusted_ssids.is_empty());
        // Default policy + no SSID → suppressed.
        assert_eq!(
            evaluate(true, &p, None),
            ShouldAnnounce::No(NoReason::SsidUnknown)
        );
    }

    #[test]
    fn serde_roundtrip_via_yaml() {
        let original = AnnouncePolicy {
            announce_on_untrusted_wifi: false,
            trusted_ssids: vec!["a".into(), "b".into()],
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        let back: AnnouncePolicy = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(original, back);
    }
}
