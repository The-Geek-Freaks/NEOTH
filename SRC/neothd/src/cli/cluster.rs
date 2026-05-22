//! `neoth cluster` — operator-facing cluster status surface (R-7).
//!
//! The Hyperswarm transport that R-7 needs for real peer discovery is
//! deferred (R-A1 research note). v0.1.x ships single-node operation
//! via the `LocalOnly` policy. This CLI surfaces what the daemon
//! would do today + what the operator would configure once the
//! transport lands so the experience is concrete now and the
//! upgrade path is visible.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::cluster::{LeastLoaded, LocalOnly, OrchestratingPolicy, PeerLoad, RoutingDecision};
use crate::config::FreedomConfig;

#[derive(Args, Debug, Clone)]
pub struct ClusterArgs {
    #[command(subcommand)]
    pub action: ClusterAction,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClusterAction {
    /// Print the active policy + known peer state.
    Status,
    /// Run the routing policy against a synthetic load table to show
    /// what `pick_peer` would decide. Useful for sanity-checking the
    /// `LeastLoaded` selection logic without spinning up a real
    /// cluster.
    Plan {
        /// Synthetic peers: `name:tokens_per_sec,name:tokens_per_sec,...`
        #[arg(long, value_name = "SPEC", default_value = "")]
        peers: String,
        /// Policy override for this invocation. `local-only` or
        /// `least-loaded`. Defaults to `least-loaded` when peers are
        /// supplied, `local-only` otherwise.
        #[arg(long, value_name = "POLICY")]
        policy: Option<String>,
    },
    /// SPEC `cluster_auto_discovery` Phase 4: list confirmed peers
    /// from `~/.neoth/cluster.yaml`.
    List,
    /// SPEC Phase 2 mDNS scan — spawn the `mdns-sd` daemon for
    /// `--timeout` seconds, print every authenticated announce
    /// the listener sees. Does NOT write to cluster.yaml — use
    /// `neoth cluster confirm <pub_key>` after reviewing the
    /// output.
    Discover {
        /// How long the scan runs before printing the final
        /// summary. Default 10s — long enough for one
        /// announce cycle from typical-cadence peers.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        /// Scan even when the operator's announce policy
        /// resolves to No (mdns disabled, untrusted SSID, or
        /// SSID unknown). Without this flag the discover
        /// surface prints the policy verdict + suggested fix
        /// and exits without browsing — the safe-by-default
        /// path mirrors the Q2-ratified announce gate.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Confirm a discovered peer + add to the registry. Phase 4
    /// of the SPEC — Phase 2 mDNS / Phase 3 Tailscale surface
    /// candidates; this command writes them in atomically.
    Confirm {
        /// 64-char lowercase-hex of the peer's pub key. Strict
        /// validation: must be exactly 64 chars of [0-9a-f].
        pub_key: String,
        /// Operator-readable label. Required at confirm time;
        /// Phase 2 announces will refresh it.
        #[arg(long)]
        label: String,
        /// Reachable socket address. Phase 6 gossip overrides.
        #[arg(long)]
        addr: String,
        /// Transport that surfaced the peer. Defaults to "manual"
        /// (operator typed the pub_key in directly).
        #[arg(long, default_value = "manual")]
        via: String,
    },
    /// Remove a confirmed peer by pub_key OR unique prefix.
    Revoke {
        pub_key: String,
    },
    /// Enable cluster auto-discovery (writes
    /// `freedom.yaml::cluster.mdns.enabled = true`).
    Enable,
    /// Disable cluster auto-discovery.
    Disable,
}

/// Strict validation: 64-char lowercase hex. Phase 4 architect
/// verdict pinned this — confirm shouldn't accept arbitrary
/// strings.
pub fn validate_pub_key_hex(s: &str) -> Result<()> {
    if s.len() != 64 {
        anyhow::bail!(
            "pub_key must be exactly 64 hex chars (got {} chars)",
            s.len()
        );
    }
    if !s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        anyhow::bail!(
            "pub_key must be lowercase hex [0-9a-f]; got a char outside that range"
        );
    }
    Ok(())
}

pub async fn run_cluster(args: ClusterArgs) -> Result<()> {
    match args.action {
        ClusterAction::Status => run_status(&args.output),
        ClusterAction::Plan { peers, policy } => run_plan(&peers, policy.as_deref(), &args.output),
        ClusterAction::List => run_list(),
        ClusterAction::Discover { timeout, force } => run_discover(timeout, force).await,
        ClusterAction::Confirm {
            pub_key,
            label,
            addr,
            via,
        } => run_confirm(&pub_key, &label, &addr, &via),
        ClusterAction::Revoke { pub_key } => run_revoke(&pub_key),
        ClusterAction::Enable => run_toggle(true),
        ClusterAction::Disable => run_toggle(false),
    }
}

async fn run_discover(timeout_secs: u64, force: bool) -> Result<()> {
    // Surface the Q2-ratified announce policy verdict before
    // touching the mDNS daemon. The browse itself is listen-only
    // (no leak), but the operator's announcer is silent on
    // untrusted networks — that asymmetry surprises operators
    // who paired two hosts on home wifi + then ran discover on
    // a coffee shop SSID. The verdict + suggested fix go out
    // first; `--force` bypasses the gate for operators who want
    // the listen-only scan anyway.
    let freedom_path = FreedomConfig::default_neoth_home().join("freedom.yaml");
    let (mdns_enabled, policy) =
        crate::cluster::policy::load_policy_from_freedom(&freedom_path);
    let ssid = crate::cluster::policy::current_ssid();
    let gate = crate::cluster::policy::gate_discover(
        mdns_enabled,
        &policy,
        ssid.as_deref(),
    );
    match gate {
        crate::cluster::policy::DiscoverGate::Proceed => {
            let ssid_label = ssid
                .as_deref()
                .map(|s| format!("SSID `{s}`"))
                .unwrap_or_else(|| "wired/VPN/unknown SSID".to_string());
            println!("announce policy: allowed on this network ({ssid_label})");
        }
        crate::cluster::policy::DiscoverGate::SkipWith(reason) => {
            print_skip_with_fix(reason, ssid.as_deref());
            if !force {
                println!(
                    "\nRe-run with `--force` to scan anyway (listen-only — \
                     no announce leak)."
                );
                return Ok(());
            }
            println!("(--force passed — scanning anyway)");
        }
    }

    println!(
        "scanning for NEOTH peers via mDNS for {timeout_secs}s on {}…",
        crate::cluster::mdns::DEFAULT_SERVICE_TYPE
    );
    let daemon = mdns_sd::ServiceDaemon::new()
        .map_err(|e| anyhow::anyhow!("mdns daemon: {e}"))?;
    let receiver = daemon
        .browse(crate::cluster::mdns::DEFAULT_SERVICE_TYPE)
        .map_err(|e| anyhow::anyhow!("mdns browse: {e}"))?;
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs.max(1));
    let mut seen: std::collections::HashMap<String, (String, String)> = Default::default();
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, async {
            receiver.recv_async().await.ok()
        })
        .await
        {
            Ok(Some(event)) => {
                if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                    let txt: std::collections::HashMap<String, String> = info
                        .get_properties()
                        .iter()
                        .map(|p| (p.key().to_string(), p.val_str().to_string()))
                        .collect();
                    let label = txt
                        .get("label")
                        .cloned()
                        .unwrap_or_else(|| info.get_fullname().to_string());
                    let pubkey = txt.get("pubkey").cloned().unwrap_or_default();
                    let port = info.get_port();
                    let addr_line = info
                        .get_addresses()
                        .iter()
                        .next()
                        .map(|a| format!("{a}:{port}"))
                        .unwrap_or_else(|| format!("(no addr):{port}"));
                    if !pubkey.is_empty() {
                        seen.insert(pubkey, (label, addr_line));
                    }
                }
            }
            _ => break,
        }
    }
    let _ = daemon.shutdown();

    // Phase 3 — Tailscale magic-DNS enumeration. Runs in parallel
    // with the mDNS scan above; soft-fails when Tailscale CLI is
    // missing so non-tailnet operators pay zero cost.
    let ts_port = crate::cluster::tailscale::DEFAULT_NEOTH_LISTEN_PORT;
    let ts_candidates = match crate::cluster::tailscale::enumerate(ts_port).await {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, "tailscale enumeration soft-failed");
            Vec::new()
        }
    };

    if seen.is_empty() && ts_candidates.is_empty() {
        println!("(no peers seen during scan window)");
    } else {
        if !seen.is_empty() {
            println!(
                "{:<16} {:<24} {:<22} {:<10}",
                "pub_key", "label", "addr", "via"
            );
            for (pub_key, (label, addr)) in &seen {
                let key_short = &pub_key[..16.min(pub_key.len())];
                println!(
                    "{:<16} {:<24} {:<22} {:<10}",
                    key_short, label, addr, "mdns"
                );
            }
        }
        if !ts_candidates.is_empty() {
            if seen.is_empty() {
                println!(
                    "{:<16} {:<24} {:<22} {:<10}",
                    "pub_key", "label", "addr", "via"
                );
            }
            for cand in &ts_candidates {
                println!(
                    "{:<16} {:<24} {:<22} {:<10}",
                    "(probe-only)", cand.host_name, cand.addr, "tailscale"
                );
            }
            println!(
                "\nNote: Tailscale candidates are TCP-probed only — they don't broadcast a pub_key. \
                 Operator obtains the peer's pub_key out-of-band (e.g. peer runs `neoth identity show`)."
            );
        }
        println!(
            "\nRun `neoth cluster confirm <pub_key> --label <label> --addr <addr> --via <mdns|tailscale>` \
             to add a peer (Phase 4 require-consent gate)."
        );
    }
    Ok(())
}

/// Operator-readable explanation + concrete fix for the
/// `DiscoverGate::SkipWith(reason)` path. Each `NoReason`
/// variant maps to a one-line cause + an actionable command
/// the operator can run to flip the verdict to `Proceed`.
fn print_skip_with_fix(
    reason: crate::cluster::policy::NoReason,
    ssid: Option<&str>,
) {
    use crate::cluster::policy::NoReason;
    match reason {
        NoReason::Disabled => {
            println!(
                "announce policy: SKIP (cluster.mdns.enabled = false in freedom.yaml).\n\
                 Fix: run `neoth cluster enable` to flip it on (Q4-ratified default)."
            );
        }
        NoReason::UntrustedSsid => {
            let label = ssid.unwrap_or("<unknown>");
            println!(
                "announce policy: SKIP — current SSID `{label}` isn't in \
                 `cluster.policy.trusted_ssids`.\n\
                 Fix: add the SSID to `cluster.policy.trusted_ssids` in \
                 freedom.yaml, or set `announce_on_untrusted_wifi: true` \
                 for broadcast-on-any-network."
            );
        }
        NoReason::SsidUnknown => {
            println!(
                "announce policy: SKIP — no SSID detected (wired / VPN / OS \
                 doesn't expose it).\n\
                 Fix: set `cluster.policy.announce_on_untrusted_wifi: true` \
                 in freedom.yaml, OR connect to a wifi listed in \
                 `cluster.policy.trusted_ssids`."
            );
        }
    }
}

fn run_list() -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let reg = crate::cluster::registry::load(&home)?;
    if reg.peers.is_empty() {
        println!(
            "(no confirmed cluster peers — run `neoth cluster discover` for an mDNS scan, \
             then `neoth cluster confirm <pub_key>` to add a peer)"
        );
        return Ok(());
    }
    println!(
        "{:<16} {:<24} {:<22} {:<14}",
        "pub_key", "label", "addr", "via"
    );
    for p in &reg.peers {
        let key_short = &p.pub_key_hex[..16.min(p.pub_key_hex.len())];
        println!(
            "{:<16} {:<24} {:<22} {:<14}",
            key_short,
            p.instance_label,
            p.addr,
            p.discovered_via.as_str(),
        );
    }
    Ok(())
}

fn run_confirm(pub_key: &str, label: &str, addr: &str, via: &str) -> Result<()> {
    let pub_key_norm = pub_key.trim().to_ascii_lowercase();
    // Strict validation per Phase 4 audit: 64-char lowercase hex.
    // Prefix matching is reserved for `revoke` where we have a
    // candidate set to disambiguate against; `confirm` writes a
    // new entry so the full key MUST be present.
    validate_pub_key_hex(&pub_key_norm)?;
    if label.trim().is_empty() {
        anyhow::bail!("--label required (operator-readable instance name)");
    }
    if let Err(e) = addr.trim().parse::<std::net::SocketAddr>() {
        anyhow::bail!("--addr must parse as SocketAddr (host:port): {e}");
    }
    let via_enum = match via.trim().to_ascii_lowercase().as_str() {
        "mdns" => crate::cluster::discovery::DiscoveryVia::Mdns,
        "tailscale" => crate::cluster::discovery::DiscoveryVia::Tailscale,
        "hysteria_relay" | "hysteria" => {
            crate::cluster::discovery::DiscoveryVia::HysteriaRelay
        }
        "manual" | "" => crate::cluster::discovery::DiscoveryVia::Manual,
        other => anyhow::bail!(
            "unknown discovered_via `{}` — use mdns/tailscale/hysteria_relay/manual",
            other
        ),
    };
    let home = FreedomConfig::default_neoth_home();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let peer = crate::cluster::registry::PairedPeer {
        pub_key_hex: pub_key_norm.clone(),
        instance_label: label.into(),
        addr: addr.into(),
        discovered_via: via_enum,
        paired_at_unix: now,
        last_seen_unix: now,
    };
    crate::cluster::registry::upsert(&home, peer)?;
    // Drop a sidecar so the running daemon emits WAL 0xE6
    // on its next tick. Best-effort — sidecar write failure
    // doesn't roll back the registry change.
    let payload = serde_json::json!({
        "label": label,
        "addr": addr,
        "discovered_via": via_enum.as_str(),
    });
    if let Err(e) = crate::cluster::audit_sidecar::write_sidecar(
        &home,
        crate::cluster::audit_sidecar::ClusterAuditKind::PeerConfirmed,
        &pub_key_norm,
        payload,
    ) {
        tracing::warn!(error = %e, "cluster confirm sidecar write failed (non-fatal)");
    }
    let key_short = &pub_key_norm[..16.min(pub_key_norm.len())];
    println!("confirmed peer `{label}` ({key_short}) via {via_enum_str}", via_enum_str = via_enum.as_str());
    Ok(())
}

fn run_revoke(pub_key: &str) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let key = pub_key.trim().to_ascii_lowercase();
    if crate::cluster::registry::remove(&home, &key)? {
        // Best-effort sidecar drop for the WAL 0xE7 audit frame.
        let payload = serde_json::json!({});
        if let Err(e) = crate::cluster::audit_sidecar::write_sidecar(
            &home,
            crate::cluster::audit_sidecar::ClusterAuditKind::PeerRevoked,
            &key,
            payload,
        ) {
            tracing::warn!(error = %e, "cluster revoke sidecar write failed (non-fatal)");
        }
        println!("revoked peer `{key}`");
    } else {
        println!("no peer matched `{key}` (no-op)");
    }
    Ok(())
}

fn run_toggle(enabled: bool) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let freedom_path = home.join("freedom.yaml");
    let body = if freedom_path.exists() {
        std::fs::read_to_string(&freedom_path)?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body)?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };
    let cluster_key_val = serde_yaml::Value::from("cluster");
    let mut cluster_map = map
        .get(&cluster_key_val)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    let mdns_key = serde_yaml::Value::from("mdns");
    let mut mdns_map = cluster_map
        .get(&mdns_key)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    mdns_map.insert(
        serde_yaml::Value::from("enabled"),
        serde_yaml::Value::from(enabled),
    );
    cluster_map.insert(mdns_key, serde_yaml::Value::Mapping(mdns_map));
    map.insert(cluster_key_val, serde_yaml::Value::Mapping(cluster_map));
    let tmp = freedom_path.with_extension("yaml.tmp");
    std::fs::write(&tmp, serde_yaml::to_string(&root)?)?;
    std::fs::rename(&tmp, &freedom_path)?;
    println!(
        "cluster.mdns.enabled = {} (in {})",
        enabled,
        freedom_path.display()
    );
    Ok(())
}

fn run_status(output: &OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().ok();
    let operator = cfg
        .as_ref()
        .and_then(|c| c.operator_id.clone())
        .unwrap_or_else(|| "(unset)".to_string());

    // v0.1.x always reports single-node; once Hyperswarm transport
    // lands, this reads the peer registry instead.
    let mode = "single-node";
    let policy_name = "local-only";
    let peer_count = 0usize;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "mode": mode,
                "policy": policy_name,
                "peer_count": peer_count,
                "operator_id": operator,
                "transport": "deferred (R-A1 — Hyperswarm research)",
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Cluster status");
            println!("  mode             : {mode}");
            println!("  policy           : {policy_name}");
            println!("  peer count       : {peer_count}");
            println!("  operator id      : {operator}");
            println!("  transport        : deferred (R-A1)");
            println!();
            println!(
                "  Single-node operation is the only supported mode in v0.1.x. \
                 Multi-host federation lands when the Hyperswarm transport ships \
                 (see QUELLEN/research/R-A1_hyperswarm.md)."
            );
        }
    }
    Ok(())
}

fn run_plan(peers_spec: &str, policy: Option<&str>, output: &OutputFormat) -> Result<()> {
    let peers = parse_peers(peers_spec)?;
    let policy_name = policy.unwrap_or(if peers.is_empty() {
        "local-only"
    } else {
        "least-loaded"
    });
    let decision = match policy_name {
        "local-only" => LocalOnly.pick_peer(&peers),
        "least-loaded" => LeastLoaded::default().pick_peer(&peers),
        other => anyhow::bail!("unknown policy `{other}` — known: local-only, least-loaded"),
    };
    let decision_str = decision_label(&decision);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let peer_rows: Vec<_> = peers
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "peer": p.peer.as_str(),
                        "tokens_per_sec": p.tokens_per_sec,
                        "healthy": p.healthy,
                    })
                })
                .collect();
            let body = serde_json::json!({
                "policy": policy_name,
                "peers": peer_rows,
                "decision": decision_str,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Cluster routing plan");
            println!("  policy   : {policy_name}");
            if peers.is_empty() {
                println!("  peers    : (none — would route Local)");
            } else {
                println!("  peers    :");
                for p in &peers {
                    println!(
                        "    - {} tps={:.1} healthy={}",
                        p.peer.as_str(),
                        p.tokens_per_sec,
                        p.healthy
                    );
                }
            }
            println!("  decision : {decision_str}");
        }
    }
    Ok(())
}

fn decision_label(d: &RoutingDecision) -> String {
    match d {
        RoutingDecision::Local => "Local".to_string(),
        RoutingDecision::Remote(peer) => format!("Remote({})", peer.as_str()),
        RoutingDecision::NoPeerAvailable => "NoPeerAvailable".to_string(),
    }
}

/// Parse `name:tps,name:tps,...` into a synthetic peer-load table.
/// Empty string returns an empty vec. Used by `neoth cluster plan` so
/// operators can rehearse the routing decision without a real swarm.
fn parse_peers(spec: &str) -> Result<Vec<PeerLoad>> {
    use crate::cluster::PeerId;
    use std::time::Instant;
    if spec.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in spec.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, tps_str) = entry
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("peer entry `{entry}` missing `:tps`"))?;
        let tps: f64 = tps_str
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("peer entry `{entry}` has non-numeric tps: {e}"))?;
        out.push(PeerLoad {
            peer: PeerId::new(name.trim()),
            tokens_per_sec: tps,
            last_observed: Instant::now(),
            healthy: true,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_pub_key_hex_accepts_64_lowercase_hex() {
        let ok = "0".repeat(64);
        assert!(validate_pub_key_hex(&ok).is_ok());
        let ok = "ab".repeat(32);
        assert!(validate_pub_key_hex(&ok).is_ok());
        let ok = format!("{}{}", "deadbeef".repeat(7), "fedcba98");
        assert!(validate_pub_key_hex(&ok).is_ok());
    }

    #[test]
    fn validate_pub_key_hex_rejects_wrong_length() {
        // Too short.
        assert!(validate_pub_key_hex("ab").is_err());
        // Too long.
        assert!(validate_pub_key_hex(&"a".repeat(65)).is_err());
        // Empty.
        assert!(validate_pub_key_hex("").is_err());
    }

    #[test]
    fn validate_pub_key_hex_rejects_uppercase() {
        // Strict lowercase — operator copy-paste from `gh api` etc.
        // sometimes uppercases; we want to surface the formatting
        // bug at validate time.
        let upper = "AB".repeat(32);
        assert!(validate_pub_key_hex(&upper).is_err());
    }

    #[test]
    fn validate_pub_key_hex_rejects_non_hex_chars() {
        let mut bad = "a".repeat(62);
        bad.push_str("xy");
        assert!(validate_pub_key_hex(&bad).is_err());
        // Whitespace inside also rejected (caller trims first).
        let with_space = format!("{}  {}", "a".repeat(31), "b".repeat(31));
        assert!(validate_pub_key_hex(&with_space).is_err());
    }

    #[test]
    fn parse_peers_returns_empty_on_blank() {
        let r = parse_peers("").unwrap();
        assert!(r.is_empty());
        let r = parse_peers("   ").unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn parse_peers_handles_well_formed_spec() {
        let r = parse_peers("a:10,b:5.5,c:0").unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].peer.as_str(), "a");
        assert!((r[0].tokens_per_sec - 10.0).abs() < 1e-9);
        assert!((r[1].tokens_per_sec - 5.5).abs() < 1e-9);
        assert_eq!(r[2].tokens_per_sec, 0.0);
    }

    #[test]
    fn parse_peers_errors_on_missing_colon() {
        let r = parse_peers("nope");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("missing"));
    }

    #[test]
    fn parse_peers_errors_on_non_numeric_tps() {
        let r = parse_peers("a:not-a-number");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("non-numeric"));
    }

    #[tokio::test]
    async fn run_plan_local_only_routes_local() {
        let args = ClusterArgs {
            action: ClusterAction::Plan {
                peers: "a:10,b:1".into(),
                policy: Some("local-only".into()),
            },
            output: OutputFormat::Json,
        };
        run_cluster(args).await.expect("local-only run");
    }

    #[tokio::test]
    async fn run_plan_rejects_unknown_policy() {
        let args = ClusterArgs {
            action: ClusterAction::Plan {
                peers: "a:1".into(),
                policy: Some("unknown-thing".into()),
            },
            output: OutputFormat::Json,
        };
        let err = run_cluster(args).await.unwrap_err();
        assert!(err.to_string().contains("unknown policy"));
    }

    #[test]
    fn decision_label_round_trips_known_variants() {
        use crate::cluster::PeerId;
        assert_eq!(decision_label(&RoutingDecision::Local), "Local");
        assert_eq!(
            decision_label(&RoutingDecision::Remote(PeerId::new("p1"))),
            "Remote(p1)"
        );
        assert_eq!(
            decision_label(&RoutingDecision::NoPeerAvailable),
            "NoPeerAvailable"
        );
    }

    #[test]
    fn print_skip_with_fix_handles_all_reasons() {
        // Smoke — exercises every NoReason variant so a future
        // variant addition is forced to update the match arm.
        use crate::cluster::policy::NoReason;
        print_skip_with_fix(NoReason::Disabled, None);
        print_skip_with_fix(NoReason::UntrustedSsid, Some("coffee-shop"));
        print_skip_with_fix(NoReason::SsidUnknown, None);
    }

    #[test]
    fn discover_action_carries_force_flag() {
        // Field-presence pin so the clap derivation doesn't drift
        // away from the policy verdict surfacing contract.
        let action = ClusterAction::Discover {
            timeout: 5,
            force: true,
        };
        match action {
            ClusterAction::Discover { timeout, force } => {
                assert_eq!(timeout, 5);
                assert!(force);
            }
            _ => panic!("expected Discover variant"),
        }
    }
}
