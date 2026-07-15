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

pub use crate::config::{ClusterAnnouncePolicy as AnnouncePolicy, ClusterTransport};

/// Verdict returned by `evaluate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShouldAnnounce {
    /// Announcer should spawn / continue running.
    Yes,
    /// Announcer should stay silent. The reason carries
    /// operator-readable context for the doctor / status surface.
    No(NoReason),
}

/// Verdict for `cluster discover` — should the listener scan
/// proceed without operator `--force`? Mirrors `ShouldAnnounce`
/// but pins the discover-side semantics: `Proceed` means the
/// scan is safe to run, `SkipWith(reason)` means the operator's
/// announce policy says No so the discover surfaces the
/// explanation + suggested fix instead of running blind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverGate {
    Proceed,
    SkipWith(NoReason),
}

/// Decide whether `neoth cluster discover` should start its mDNS
/// browse without an operator `--force`. The decision shares the
/// `evaluate()` logic so the policy is consistent across the
/// announce path + the discover surface.
///
/// `Proceed` ⇔ `ShouldAnnounce::Yes`. The browse runs without
/// extra noise.
///
/// `SkipWith(reason)` ⇔ `ShouldAnnounce::No(reason)`. The caller
/// prints the reason + actionable fix + (if not `--force`) bails
/// out before spawning the mDNS daemon.
pub fn gate_discover(
    mdns_enabled: bool,
    policy: &AnnouncePolicy,
    current_ssid: Option<&str>,
) -> DiscoverGate {
    match evaluate(mdns_enabled, policy, current_ssid) {
        ShouldAnnounce::Yes => DiscoverGate::Proceed,
        ShouldAnnounce::No(reason) => DiscoverGate::SkipWith(reason),
    }
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
        Some(ssid) if policy.trusted_ssids.iter().any(|s| s == ssid) => ShouldAnnounce::Yes,
        Some(_) => ShouldAnnounce::No(NoReason::UntrustedSsid),
    }
}

/// Cross-platform SSID lookup. Shells to the OS's wifi-info
/// utility + parses the SSID out of stdout. Returns `None` when:
///   - the OS doesn't expose it (wired connection, VPN, headless)
///   - the utility isn't on PATH
///   - parsing fails (unexpected output format from an OS upgrade)
///
/// None is the SAFE answer for the policy evaluator — strict
/// policy treats unknown SSID as untrusted.
pub fn current_ssid() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        ssid_via_netsh()
    }
    #[cfg(target_os = "macos")]
    {
        ssid_via_networksetup()
    }
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    {
        ssid_via_iwgetid()
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        None
    }
}

#[cfg(target_os = "windows")]
fn ssid_via_netsh() -> Option<String> {
    let output = std::process::Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_netsh_ssid(&stdout)
}

#[cfg(target_os = "macos")]
fn ssid_via_networksetup() -> Option<String> {
    // networksetup -getairportnetwork takes a device name; we
    // try `en0` (typical primary wifi) first, then fall through.
    for dev in ["en0", "en1"] {
        let output = std::process::Command::new("networksetup")
            .args(["-getairportnetwork", dev])
            .output()
            .ok();
        if let Some(out) = output
            && out.status.success()
            && let Some(ssid) = parse_networksetup_ssid(&String::from_utf8_lossy(&out.stdout))
        {
            return Some(ssid);
        }
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
fn ssid_via_iwgetid() -> Option<String> {
    let output = std::process::Command::new("iwgetid")
        .arg("-r")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Parse the "SSID :" line from `netsh wlan show interfaces`
/// stdout. Operator-locale-aware: matches both the English
/// "SSID" and the German "SSID" labels (same word in both).
/// Returns None when no SSID line is found OR when the line
/// has empty value.
pub fn parse_netsh_ssid(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Look for an exact "SSID" prefix (avoid matching "BSSID").
        let after_label = trimmed.strip_prefix("SSID").filter(|rest| {
            // First char after "SSID" must be space or colon —
            // BSSID would have 'I' here.
            rest.chars()
                .next()
                .map(|c| c == ' ' || c == ':')
                .unwrap_or(false)
        });
        let Some(rest) = after_label else { continue };
        if let Some((_, value)) = rest.split_once(':') {
            let ssid = value.trim();
            if !ssid.is_empty() {
                return Some(ssid.to_string());
            }
        }
    }
    None
}

/// Parse `networksetup -getairportnetwork enN` stdout. Format:
/// `Current Wi-Fi Network: <ssid>` (one line). When the device
/// isn't associated, the tool emits "You are not associated with
/// an AirPort network." — None in that case.
pub fn parse_networksetup_ssid(stdout: &str) -> Option<String> {
    let line = stdout.lines().next()?.trim();
    let after = line.strip_prefix("Current Wi-Fi Network:")?;
    let ssid = after.trim();
    if ssid.is_empty() {
        None
    } else {
        Some(ssid.to_string())
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
    fn parse_netsh_ssid_extracts_home_wifi() {
        // Real Windows 11 `netsh wlan show interfaces` snippet,
        // trimmed for the relevant lines + with leading-spaces
        // preserved as netsh actually emits.
        let stdout = "    Name                   : Wi-Fi\n\
                      Description            : Intel Wi-Fi 6 AX201\n\
                      GUID                   : abc-123\n\
                      Physical address       : aa:bb:cc:dd:ee:ff\n\
                      Interface type         : Primary\n\
                      State                  : connected\n\
                      SSID                   : home-wifi\n\
                      BSSID                  : 11:22:33:44:55:66\n\
                      Network type           : Infrastructure\n";
        assert_eq!(parse_netsh_ssid(stdout), Some("home-wifi".to_string()));
    }

    #[test]
    fn parse_netsh_ssid_skips_bssid_line() {
        // BSSID must NOT be picked up as SSID.
        let stdout = "    BSSID                  : 11:22:33:44:55:66\n";
        assert_eq!(parse_netsh_ssid(stdout), None);
    }

    #[test]
    fn parse_netsh_ssid_returns_none_when_no_ssid_line() {
        let stdout = "Some unrelated output\nNo SSID information available\n";
        assert_eq!(parse_netsh_ssid(stdout), None);
    }

    #[test]
    fn parse_netsh_ssid_returns_none_when_empty_value() {
        // Disconnected state — netsh emits the line but with no value.
        let stdout = "    SSID                   : \n";
        assert_eq!(parse_netsh_ssid(stdout), None);
    }

    #[test]
    fn parse_networksetup_ssid_extracts_current_network() {
        let stdout = "Current Wi-Fi Network: home-wifi-5g\n";
        assert_eq!(
            parse_networksetup_ssid(stdout),
            Some("home-wifi-5g".to_string())
        );
    }

    #[test]
    fn parse_networksetup_ssid_handles_not_associated() {
        let stdout = "You are not associated with an AirPort network.\n";
        assert_eq!(parse_networksetup_ssid(stdout), None);
    }

    #[test]
    fn parse_networksetup_ssid_handles_empty_value() {
        let stdout = "Current Wi-Fi Network:    \n";
        assert_eq!(parse_networksetup_ssid(stdout), None);
    }

    #[test]
    fn current_ssid_does_not_panic() {
        // Cross-platform smoke — the helper might return Some or
        // None depending on the test runner's network state, but
        // it MUST NOT panic regardless of platform / connectivity.
        let _ = current_ssid();
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

    // ── gate_discover ──────────────────────────────────────────────

    #[test]
    fn gate_discover_proceeds_under_open_policy() {
        assert_eq!(
            gate_discover(true, &open_policy(), Some("coffee-shop")),
            DiscoverGate::Proceed
        );
        assert_eq!(
            gate_discover(true, &open_policy(), None),
            DiscoverGate::Proceed
        );
    }

    #[test]
    fn gate_discover_proceeds_on_strict_plus_trusted_ssid() {
        assert_eq!(
            gate_discover(true, &strict_policy(), Some("home-wifi")),
            DiscoverGate::Proceed
        );
    }

    #[test]
    fn gate_discover_skips_when_disabled() {
        assert_eq!(
            gate_discover(false, &open_policy(), Some("home-wifi")),
            DiscoverGate::SkipWith(NoReason::Disabled)
        );
    }

    #[test]
    fn gate_discover_skips_on_strict_untrusted_ssid() {
        assert_eq!(
            gate_discover(true, &strict_policy(), Some("coffee-shop")),
            DiscoverGate::SkipWith(NoReason::UntrustedSsid)
        );
    }

    #[test]
    fn gate_discover_skips_when_ssid_unknown() {
        assert_eq!(
            gate_discover(true, &strict_policy(), None),
            DiscoverGate::SkipWith(NoReason::SsidUnknown)
        );
    }
}
