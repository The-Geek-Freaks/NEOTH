//! Cluster-domain doctor checks (GOLD-ARCH-06): mDNS announcer +
//! registry. Both cfg variants live here so the outcome count stays
//! stable with and without the `cluster` feature.

use std::path::Path;

use super::super::{CheckDoc, CheckFn, CheckOutcome, CheckStatus};

/// Unresolved typed mesh conflicts are never a silent LWW detail. This check
/// is deliberately read-only: doctor must not create or migrate views.db.
pub(crate) fn check_cluster_conflicts(home: &Path) -> CheckOutcome {
    const NAME: &str = "cluster mesh conflicts";
    let db_path = home.join("views.db");
    if !db_path.exists() {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "no mesh database yet; 0 unresolved conflicts".to_string(),
        };
    }
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = match rusqlite::Connection::open_with_flags(&db_path, flags) {
        Ok(conn) => conn,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: format!("cannot read {}: {error}", db_path.display()),
            };
        }
    };
    let table_exists = match conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
             WHERE type = 'table' AND name = 'mesh_sync_conflicts')",
        [],
        |row| row.get::<_, bool>(0),
    ) {
        Ok(exists) => exists,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: format!("cannot inspect mesh conflict schema: {error}"),
            };
        }
    };
    if !table_exists {
        return CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "mesh conflict ledger not initialized; 0 unresolved conflicts".to_string(),
        };
    }
    let has_resolution_column = match conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('mesh_sync_conflicts') \
             WHERE name = 'resolved_at')",
        [],
        |row| row.get::<_, bool>(0),
    ) {
        Ok(exists) => exists,
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: format!("cannot inspect mesh conflict columns: {error}"),
            };
        }
    };
    let sql = if has_resolution_column {
        "SELECT count(*) FROM mesh_sync_conflicts WHERE resolved_at IS NULL"
    } else {
        // v29 databases have not been migrated by a normal runtime open yet;
        // every row in that schema is unresolved.
        "SELECT count(*) FROM mesh_sync_conflicts"
    };
    let count = match conn.query_row(sql, [], |row| row.get::<_, i64>(0)) {
        Ok(count) if count >= 0 => count,
        Ok(count) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: format!("invalid negative conflict count {count}"),
            };
        }
        Err(error) => {
            return CheckOutcome {
                name: NAME,
                status: CheckStatus::Fail,
                detail: format!("cannot query mesh conflict ledger: {error}"),
            };
        }
    };
    if count == 0 {
        CheckOutcome {
            name: NAME,
            status: CheckStatus::Pass,
            detail: "0 unresolved typed mesh conflicts".to_string(),
        }
    } else {
        CheckOutcome {
            name: NAME,
            status: CheckStatus::Warn,
            detail: format!(
                "{count} unresolved typed mesh conflict(s); inspect with `neoth cluster \
                 conflicts`, then acknowledge with `neoth cluster conflicts resolve \
                 <content-id> --prefer <origin>`"
            ),
        }
    }
}

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
pub(crate) const CHECKS: &[CheckFn] = &[
    check_cluster_registry,
    check_cluster_mdns_announcer,
    check_cluster_conflicts,
];

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
    CheckDoc {
        name: "cluster mesh conflicts",
        purpose: "Reads the durable typed-conflict ledger in views.db without \
                  creating or migrating it. Warns whenever same-content mesh \
                  variants still need an explicit operator decision.",
        common_failures: "Two origins publish different canonical values for \
                          the same stable content id, or one origin replaces a \
                          value while an older digest remains materialized.",
        fix: "Run `neoth cluster conflicts` to inspect origins and digests. \
              Then run `neoth cluster conflicts resolve <content-id> --prefer \
              <origin>`. The decision is persisted; a future new digest pair \
              becomes unresolved again instead of being hidden.",
    },
];

#[cfg(test)]
mod conflict_tests {
    use super::*;
    use rusqlite::params;

    #[test]
    fn missing_mesh_db_is_a_clean_zero_conflict_state() {
        let dir = tempfile::tempdir().unwrap();
        let outcome = check_cluster_conflicts(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("0 unresolved"));
        assert!(!dir.path().join("views.db").exists());
    }

    #[test]
    fn unresolved_conflict_warns_and_resolution_clears_warning() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = crate::memory::store::open(&db_path).unwrap();
        let incumbent = [1_u8; 32];
        let incoming = [2_u8; 32];
        conn.execute(
            "INSERT INTO mesh_sync_conflicts \
             (content_id, incumbent_origin, incoming_origin, incumbent_sha256, \
              incoming_sha256, policy, observed_at) \
             VALUES ('memory:test', 'peer-a', 'peer-b', ?1, ?2, \
                     'cross_origin_typed_conflict', 10)",
            params![incumbent.as_slice(), incoming.as_slice()],
        )
        .unwrap();
        drop(conn);

        let unresolved = check_cluster_conflicts(dir.path());
        assert_eq!(unresolved.status, CheckStatus::Warn);
        assert!(unresolved.detail.contains("1 unresolved"));

        let conn = crate::memory::store::open(&db_path).unwrap();
        conn.execute(
            "UPDATE mesh_sync_conflicts \
             SET resolved_at = 20, preferred_origin = 'peer-a'",
            [],
        )
        .unwrap();
        drop(conn);
        let resolved = check_cluster_conflicts(dir.path());
        assert_eq!(resolved.status, CheckStatus::Pass);
        assert!(resolved.detail.contains("0 unresolved"));
    }
}
