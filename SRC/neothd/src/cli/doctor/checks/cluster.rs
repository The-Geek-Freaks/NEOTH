//! Cluster-domain doctor checks (GOLD-ARCH-06): mDNS announcer +
//! registry. Both cfg variants live here so the outcome count stays
//! stable with and without the `cluster` feature.

use std::path::Path;

use super::super::{CheckOutcome, CheckStatus};

/// Cluster mDNS announcer state — surfaces whether the announcer
/// would actually broadcast on the current network. Composes the
/// Q2-ratified `policy::gate_discover` verdict with the paired-peer
/// count so the check stays quiet for single-instance operators
/// and only warns when the operator HAS paired peers but the
/// announcer is silenced by SSID gating.
#[cfg(feature = "cluster")]
pub(crate) fn check_cluster_mdns_announcer(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let (mdns_enabled, policy) = crate::cluster::policy::load_policy_from_freedom(&freedom_path);
    let ssid = crate::cluster::policy::current_ssid();
    let peer_count = crate::cluster::registry::load(home)
        .map(|r| r.peers.len())
        .unwrap_or(0);
    evaluate_announcer_state(mdns_enabled, &policy, ssid.as_deref(), peer_count)
}

/// GOLD-SEC-16: slim build (no `cluster` feature) — there is no announcer to
/// inspect, so the check passes with an honest "not compiled" note. Keeping the
/// stub means `run_all_checks` returns the same outcome count in both build
/// configurations (the count-pins stay stable).
#[cfg(not(feature = "cluster"))]
pub(crate) fn check_cluster_mdns_announcer(_home: &Path) -> CheckOutcome {
    CheckOutcome {
        name: "cluster mDNS announcer",
        status: CheckStatus::Pass,
        detail: "cluster feature not compiled in this build".to_string(),
    }
}

/// Pure decision matrix for [`check_cluster_mdns_announcer`].
///
/// PASS paths (silent / informational):
///   - announcer disabled by operator (`mdns.enabled = false`)
///   - announcer policy yields Yes — running on current network
///   - announcer would skip, but operator has no paired peers
///     (single-instance — nothing to broadcast to anyway)
///
/// WARN paths (operator has paired peers AND announcer is silent):
///   - UntrustedSsid: peers won't find this host on the current SSID
///   - SsidUnknown: peers won't find this host on wired/VPN/headless
///
/// Each WARN carries the actionable fix (add SSID to trusted list,
/// flip `announce_on_untrusted_wifi`, or pair via Tailscale).
#[cfg(feature = "cluster")]
pub(crate) fn evaluate_announcer_state(
    mdns_enabled: bool,
    policy: &crate::cluster::policy::AnnouncePolicy,
    current_ssid: Option<&str>,
    paired_peers: usize,
) -> CheckOutcome {
    use crate::cluster::policy::{DiscoverGate, NoReason, gate_discover};
    let name = "cluster mDNS announcer";
    match gate_discover(mdns_enabled, policy, current_ssid) {
        DiscoverGate::Proceed => {
            let ssid_label = current_ssid
                .map(|s| format!("SSID `{s}`"))
                .unwrap_or_else(|| "any-network (announce_on_untrusted_wifi = true)".to_string());
            CheckOutcome {
                name,
                status: CheckStatus::Pass,
                detail: format!(
                    "announcer would run on {ssid_label} — {paired_peers} paired peer(s)"
                ),
            }
        }
        DiscoverGate::SkipWith(NoReason::Disabled) => CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "announcer disabled (cluster.mdns.enabled = false)".to_string(),
        },
        DiscoverGate::SkipWith(NoReason::UntrustedSsid) => {
            let ssid_label = current_ssid.unwrap_or("<unknown>");
            if paired_peers == 0 {
                CheckOutcome {
                    name,
                    status: CheckStatus::Pass,
                    detail: format!(
                        "announcer silent on SSID `{ssid_label}` (not in trusted list, \
                         no paired peers — single-instance)"
                    ),
                }
            } else {
                CheckOutcome {
                    name,
                    status: CheckStatus::Warn,
                    detail: format!(
                        "announcer silent on SSID `{ssid_label}` — {paired_peers} paired \
                         peer(s) won't find this host. Fix: add SSID to \
                         `cluster.policy.trusted_ssids` in freedom.yaml, OR pair via \
                         Tailscale (tailnet bypasses SSID gate)."
                    ),
                }
            }
        }
        DiscoverGate::SkipWith(NoReason::SsidUnknown) => {
            if paired_peers == 0 {
                CheckOutcome {
                    name,
                    status: CheckStatus::Pass,
                    detail: "announcer silent — no SSID (wired/VPN) + no paired peers".to_string(),
                }
            } else {
                CheckOutcome {
                    name,
                    status: CheckStatus::Warn,
                    detail: format!(
                        "announcer silent — no SSID detected (wired/VPN/headless); \
                         {paired_peers} paired peer(s) won't find this host via mDNS. \
                         Fix: set `cluster.policy.announce_on_untrusted_wifi: true` \
                         in freedom.yaml, OR pair via Tailscale."
                    ),
                }
            }
        }
    }
}

/// Cluster registry surface — Phase 4 doctor entry. Reads
/// `~/.neoth/cluster.yaml` + reports peer count + stale-peer warning
/// when any paired peer hasn't been seen in 14 days. Empty registry
/// passes silently — single-instance operators don't see noise.
#[cfg(feature = "cluster")]
pub(crate) fn check_cluster_registry(home: &Path) -> CheckOutcome {
    let reg = match crate::cluster::registry::load(home) {
        Ok(r) => r,
        Err(e) => {
            return CheckOutcome {
                name: "cluster registry",
                status: CheckStatus::Warn,
                detail: format!("cluster.yaml unreadable: {e}"),
            };
        }
    };
    if reg.peers.is_empty() {
        return CheckOutcome {
            name: "cluster registry",
            status: CheckStatus::Pass,
            detail: "no confirmed cluster peers (single-instance)".to_string(),
        };
    }
    const STALE_AFTER_SECS: i64 = 14 * 86_400;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut stale = Vec::new();
    for p in &reg.peers {
        if now - p.last_seen_unix > STALE_AFTER_SECS {
            stale.push(format!(
                "{}({})",
                p.instance_label,
                &p.pub_key_hex[..8.min(p.pub_key_hex.len())]
            ));
        }
    }
    let detail = format!(
        "{} confirmed peer(s); {} stale (>14d since last_seen)",
        reg.peers.len(),
        stale.len()
    );
    let status = if stale.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };
    let detail = if stale.is_empty() {
        detail
    } else {
        format!("{} — stale: {}", detail, stale.join(", "))
    };
    CheckOutcome {
        name: "cluster registry",
        status,
        detail,
    }
}

/// GOLD-SEC-16: slim build (no `cluster` feature) — no cluster registry to read.
#[cfg(not(feature = "cluster"))]
pub(crate) fn check_cluster_registry(_home: &Path) -> CheckOutcome {
    CheckOutcome {
        name: "cluster registry",
        status: CheckStatus::Pass,
        detail: "cluster feature not compiled in this build".to_string(),
    }
}
