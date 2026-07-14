//! Cluster-domain doctor checks (GOLD-ARCH-06): mDNS announcer +
//! registry. Both cfg variants live here so the outcome count stays
//! stable with and without the `cluster` feature.

use std::path::Path;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus};

/// Cluster mDNS announcer state — surfaces whether the announcer
/// would actually broadcast on the current network. Composes the
/// Q2-ratified `policy::gate_discover` verdict with the paired-peer
/// count so the check stays quiet for single-instance operators
/// and only warns when the operator HAS paired peers but the
/// announcer is silenced by SSID gating.
#[cfg(feature = "cluster")]
pub(crate) fn check_cluster_mdns_announcer(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let config = match crate::config::FreedomConfig::load_from_path_or_default(&freedom_path) {
        Ok(config) => config,
        Err(error) => {
            return CheckOutcome {
                name: "cluster mDNS announcer",
                status: CheckStatus::Fail,
                detail: format!("cannot load cluster policy: {error}"),
            };
        }
    };
    let ssid = crate::cluster::policy::current_ssid();
    let peer_count = match crate::cluster::registry::load(home) {
        Ok(registry) => registry.peers.len(),
        Err(error) => {
            return CheckOutcome {
                name: "cluster mDNS announcer",
                status: CheckStatus::Fail,
                detail: format!("cannot load paired-peer registry: {error}"),
            };
        }
    };
    evaluate_announcer_state(
        config.cluster.mdns.enabled,
        &config.cluster.policy,
        ssid.as_deref(),
        peer_count,
    )
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
    let now = crate::time::now_unix_i64();
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

/// Registration: this domain's diagnostics, run in order by
/// `run_all_checks`. Adding a check = add the fn + a `CheckDoc` here.
pub(crate) const CHECKS: &[CheckFn] = &[check_cluster_registry, check_cluster_mdns_announcer];

/// Operator runbook entries for this domain (the `--explain` surface).
pub(crate) const DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "cluster registry",
        purpose: "Cluster auto-discovery Phase 4 visibility surface. \
                  Reads `~/.neoth/cluster.yaml` + reports the count \
                  of confirmed peers + warns when any haven't been \
                  seen in 14 days (Phase 2+ gossip refreshes \
                  last_seen_unix on each authenticated announce). \
                  Single-instance operators see Pass with `no \
                  confirmed cluster peers` — no noise.",
        common_failures: "Peer device offline for >14 days (laptop \
                          retired, server move, network change). \
                          Stale entry keeps eating Phase 6 gossip \
                          retry budget until revoked.",
        fix: "Verify the peer device is still reachable: `neoth \
              cluster list` shows the addr + via. If the device \
              is truly gone, `neoth cluster revoke <pub_key_prefix>` \
              removes it. If it's just been offline, leave it — \
              gossip will refresh once the peer returns.",
    },
    CheckDoc {
        name: "cluster mDNS announcer",
        purpose: "Cluster auto-discovery Phase 2 announcer state. \
                  Composes `cluster.mdns.enabled` + the Q2-ratified \
                  announce policy (announce_on_untrusted_wifi + \
                  trusted_ssids) + the OS-detected current SSID to \
                  report whether the announcer would actually \
                  broadcast on the current network. Noise scales \
                  with paired peers — single-instance operators \
                  never see WARN.",
        common_failures: "Paired-peer operator joins coffee-shop \
                          wifi (untrusted SSID) → announcer goes \
                          silent → peers can't auto-rediscover. \
                          OR operator on wired/VPN with no SSID \
                          → strict default treats unknown SSID as \
                          untrusted → silent.",
        fix: "Add the current SSID to `cluster.policy.trusted_ssids` \
              in freedom.yaml, OR set `cluster.policy.announce_on_untrusted_wifi: \
              true` for broadcast-on-any-network, OR pair peers \
              via Tailscale (tailnet bypasses the SSID gate). \
              `neoth cluster discover` surfaces the same verdict \
              + suggested fix before scanning.",
    },
];
