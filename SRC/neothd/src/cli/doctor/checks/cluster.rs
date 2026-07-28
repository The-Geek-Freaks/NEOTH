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
    let peer_count = match crate::cluster::membership::inspect_authority_read_only(
        home,
        crate::time::now_unix_i64(),
    ) {
        Ok(Some(health)) => match usize::try_from(health.active) {
            Ok(active) => active,
            Err(error) => {
                return CheckOutcome {
                    name: "cluster mDNS announcer",
                    status: CheckStatus::Fail,
                    detail: format!("invalid active membership count: {error}"),
                };
            }
        },
        Ok(None) => 0,
        Err(error) => {
            return CheckOutcome {
                name: "cluster mDNS announcer",
                status: CheckStatus::Fail,
                detail: format!("cannot inspect membership authority read-only: {error}"),
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

/// Dedicated authority health. `cluster.yaml` is intentionally not read:
/// legacy data enters only through MembershipStore's one-time importer.
#[cfg(feature = "cluster")]
pub(crate) fn check_cluster_registry(home: &Path) -> CheckOutcome {
    let cluster_enabled =
        crate::config::FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))
            .map(|config| config.cluster.enabled)
            .unwrap_or(false);
    let Some(health) = (match crate::cluster::membership::inspect_authority_read_only(
        home,
        crate::time::now_unix_i64(),
    ) {
        Ok(health) => health,
        Err(error) => {
            return CheckOutcome {
                name: "cluster membership authority",
                status: CheckStatus::Fail,
                detail: format!("membership DB read-only inspection failed: {error}"),
            };
        }
    }) else {
        return CheckOutcome {
            name: "cluster membership authority",
            status: if cluster_enabled {
                CheckStatus::Fail
            } else {
                CheckStatus::Pass
            },
            detail: if cluster_enabled {
                "cluster is enabled but membership authority is missing".to_string()
            } else {
                "membership DB not initialized (single-instance)".to_string()
            },
        };
    };
    if health.integrity != "ok"
        || health.schema_version != crate::cluster::membership::AUTHORITY_SCHEMA_VERSION
        || !health.local_identity_valid
    {
        return CheckOutcome {
            name: "cluster membership authority",
            status: CheckStatus::Fail,
            detail: format!(
                "authority integrity={} schema={}/{} local_identity_valid={}",
                health.integrity,
                health.schema_version,
                crate::cluster::membership::AUTHORITY_SCHEMA_VERSION,
                health.local_identity_valid
            ),
        };
    }
    let issues = health.expired_active
        + health.legacy_unattested
        + health.active_without_valid_binding
        + health.expired_invites
        + u64::from(health.floor_projection_mismatch)
        + u64::from(health.pending_outbox > 0)
        + health.pending_revocations
        + health.indeterminate_revocations;
    CheckOutcome {
        name: "cluster membership authority",
        status: if issues == 0 {
            CheckStatus::Pass
        } else {
            CheckStatus::Warn
        },
        detail: format!(
            "{} active; {} pending; {} expired active; {} legacy unattested; {} active \
             without valid binding; pending outbox={} (teardown={}, audit={}); expired \
             invites={}; revocations pending={} indeterminate={}; \
             floor/projection mismatch={}{}",
            health.active,
            health.pending,
            health.expired_active,
            health.legacy_unattested,
            health.active_without_valid_binding,
            health.pending_outbox,
            health.pending_teardown,
            health.pending_audit,
            health.expired_invites,
            health.pending_revocations,
            health.indeterminate_revocations,
            health.floor_projection_mismatch,
            if health.pending_revocations + health.indeterminate_revocations > 0 {
                "; inspect with `neoth cluster revoke-status <request-id>`"
            } else {
                ""
            }
        ),
    }
}

#[cfg(feature = "cluster")]
pub(crate) async fn check_cluster_runtime_membership(home: &Path) -> CheckOutcome {
    let name = "cluster membership runtime";
    if !home.join("cluster-membership.db").exists() {
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "membership authority not initialized; no live generations".into(),
        };
    }
    let daemon_pid = match crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid")) {
        Ok(pid) => pid,
        Err(error) => {
            return CheckOutcome {
                name,
                status: CheckStatus::Fail,
                detail: format!("cannot inspect daemon ownership: {error}"),
            };
        }
    };
    let Some(daemon_pid) = daemon_pid else {
        return CheckOutcome {
            name,
            status: CheckStatus::Pass,
            detail: "daemon offline; no process-local membership generations".into(),
        };
    };
    let health = match crate::daemon::audit_rpc::membership_runtime_health(home).await {
        Ok(health) => health,
        Err(error) => {
            return CheckOutcome {
                name,
                status: CheckStatus::Fail,
                detail: format!(
                    "daemon PID {daemon_pid} is live but authenticated membership health RPC failed: {error}"
                ),
            };
        }
    };
    if health.wire_version != 1 {
        return CheckOutcome {
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "daemon returned unsupported membership runtime wire version {}",
                health.wire_version
            ),
        };
    }
    if !health.invalid_live_generations.is_empty() {
        let examples = health
            .invalid_live_generations
            .iter()
            .take(3)
            .map(|generation| {
                format!(
                    "{}:{}@{}/{}",
                    generation.stable_node_id,
                    generation.kind,
                    generation.auth_epoch.get(),
                    generation.membership_epoch.get()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return CheckOutcome {
            name,
            status: CheckStatus::Fail,
            detail: format!(
                "{} revoked or stale live generation(s) remain after authority commit: {examples}",
                health.invalid_live_generations.len()
            ),
        };
    }
    if !health.unresolved_revocations.is_empty() {
        let examples = health
            .unresolved_revocations
            .iter()
            .take(3)
            .map(|status| format!("{}:{}", status.request_id, status.state.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        return CheckOutcome {
            name,
            status: CheckStatus::Warn,
            detail: format!(
                "{} unresolved revocation intent(s): {examples}; inspect with \
                 `neoth cluster revoke-status <request-id>`",
                health.unresolved_revocations.len()
            ),
        };
    }
    CheckOutcome {
        name,
        status: CheckStatus::Pass,
        detail: format!(
            "{} live route/effect generation(s), all exact-current",
            health.live_generations.len()
        ),
    }
}

#[cfg(not(feature = "cluster"))]
pub(crate) async fn check_cluster_runtime_membership(_home: &Path) -> CheckOutcome {
    CheckOutcome {
        name: "cluster membership runtime",
        status: CheckStatus::Pass,
        detail: "cluster feature not compiled in this build".into(),
    }
}

/// GOLD-SEC-16: slim build (no `cluster` feature) — no cluster registry to read.
#[cfg(not(feature = "cluster"))]
pub(crate) fn check_cluster_registry(_home: &Path) -> CheckOutcome {
    CheckOutcome {
        name: "cluster membership authority",
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
        name: "cluster membership authority",
        purpose: "Validates dedicated cluster-membership.db schema/integrity and \
                  reports invalid authorization projections without consulting \
                  cluster.yaml as a second authority.",
        common_failures: "Expired Active bindings, one-time imported legacy \
                          unattested rows, pending audit/teardown outbox work, \
                          or a tombstone/state projection mismatch.",
        fix: "Inspect `neoth cluster list --output json`. Re-enroll expired or \
              legacy Pending nodes with a signed carrier attestation. Restart \
              the daemon to replay pending teardown/audit outbox work.",
    },
    CheckDoc {
        name: "cluster membership runtime",
        purpose: "Uses the daemon's authenticated authority RPC to verify that every live \
                  route and queued, in-flight, network, or durable effect still matches the \
                  exact current StableNode/AuthEpoch/MembershipEpoch generation.",
        common_failures: "A revoked or restamped generation remains live, or a daemon that owns \
                          the membership authority has lost its required loopback RPC listener.",
        fix: "Treat this as fail-closed. Stop the daemon if it did not already terminate, inspect \
              the revoke receipt and carrier teardown, then restart and confirm the check passes.",
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

#[cfg(all(test, feature = "cluster"))]
mod membership_authority_tests {
    use super::*;
    use rusqlite::params;

    #[test]
    fn doctor_membership_inspection_is_byte_read_only() {
        let home = tempfile::tempdir().unwrap();
        crate::cluster::membership::LocalNodeIdentity::load_or_create(home.path()).unwrap();
        let store = crate::cluster::membership::MembershipStore::open(home.path()).unwrap();
        drop(store);
        let path = home.path().join("cluster-membership.db");
        let before = std::fs::read(&path).unwrap();

        let outcome = check_cluster_registry(home.path());

        assert_eq!(outcome.status, CheckStatus::Pass);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn doctor_surfaces_binding_floor_invite_and_outbox_invariants() {
        let home = tempfile::tempdir().unwrap();
        let identity =
            crate::cluster::membership::LocalNodeIdentity::load_or_create(home.path()).unwrap();
        let store = crate::cluster::membership::MembershipStore::open(home.path()).unwrap();
        let conn = rusqlite::Connection::open(store.path()).unwrap();
        let now = crate::time::now_unix_i64();
        conn.execute(
            "INSERT INTO members
             (stable_node_id,label,state,auth_epoch,membership_epoch,created_at,updated_at)
             VALUES (?1,'broken','active',1,1,?2,?2)",
            params![identity.stable_node_id().as_str(), now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transport_bindings
             (stable_node_id,carrier,transport_identity,endpoint,assurance,
              auth_epoch,membership_epoch,expires_at,attestation_digest)
             VALUES (?1,'peeroxide',?1,'test','signed_attestation',1,1,?2,'digest')",
            params![identity.stable_node_id().as_str(), now - 1],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO enrollment_invites
             (invite_id,invitation_digest,stable_node_id,signing_public_key,carrier,
              transport_identity,endpoint,label,auth_epoch,membership_epoch,
              created_at,expires_at,consumed_at)
             VALUES ('expired','expired-digest',?1,?2,'peeroxide',?1,'test',
                     'broken',1,1,?3,?4,NULL)",
            params![
                identity.stable_node_id().as_str(),
                identity.verifying_key().to_bytes().as_slice(),
                now - 2,
                now - 1
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO membership_outbox
             (kind,stable_node_id,auth_epoch,membership_epoch,payload,created_at)
             VALUES ('audit',?1,1,1,'{}',?2)",
            params![identity.stable_node_id().as_str(), now],
        )
        .unwrap();
        conn.execute(
            "UPDATE authority_meta SET membership_epoch=2,revocation_floor=2
             WHERE singleton=1",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO revocation_intents
             (request_id,request_digest,stable_node_id,reason,source,
              snapshot_version,snapshot_digest,authority_epoch,
              member_auth_epoch,member_membership_epoch,state,
              external_effects_unclassified,tombstone_committed,receipt_id,
              indeterminate_reason,created_at,updated_at)
             VALUES (?1,?2,?3,'operator_cli','operator_cli',1,?4,1,1,1,
                     'indeterminate',0,0,NULL,'provider outcome unknown',?5,?5)",
            params![
                crate::cluster::membership::new_revocation_request_id(),
                "a".repeat(64),
                identity.stable_node_id().as_str(),
                "b".repeat(64),
                now
            ],
        )
        .unwrap();
        drop(conn);

        let health = crate::cluster::membership::inspect_authority_read_only(home.path(), now)
            .unwrap()
            .unwrap();
        assert_eq!(health.expired_active, 1);
        assert_eq!(health.active_without_valid_binding, 1);
        assert_eq!(health.expired_invites, 1);
        assert_eq!(health.pending_outbox, 1);
        assert_eq!(health.pending_audit, 1);
        assert_eq!(health.indeterminate_revocations, 1);
        assert!(health.floor_projection_mismatch);
        let outcome = check_cluster_registry(home.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("indeterminate=1"));
        assert!(outcome.detail.contains("revoke-status"));
    }
}
