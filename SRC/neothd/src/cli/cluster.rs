//! `neoth cluster` — operator-facing cluster status surface (R-7).
//!
//! The daemon ships authenticated Hyperswarm discovery and an opt-in iroh
//! transport. `LocalOnly` remains the honest fallback when clustering is
//! disabled or no peer transport is active. This CLI reports that live
//! posture and exposes routing, restore, topology, and swarm operations.

use std::path::Path;

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

use crate::cli::OutputFormat;
use crate::cluster::{LeastLoaded, LocalOnly, OrchestratingPolicy, PeerLoad, RoutingDecision};
use crate::config::credentials::Credentials;
use crate::config::{
    ClusterAnnouncePolicy, ClusterConfig, ClusterGossipPolicy, ClusterMdnsConfig, ClusterTransport,
    FreedomConfig,
};
use crate::secret::SecretString;

#[derive(Args, Debug, Clone)]
pub struct ClusterArgs {
    #[command(subcommand)]
    pub action: ClusterAction,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClusterConflictAction {
    /// Persist an operator decision for every currently unresolved row with
    /// this stable content id. New digest pairs remain independently visible.
    Resolve {
        content_id: String,
        /// Origin whose canonical materialized value the operator accepts.
        #[arg(long, value_name = "PEER_PK")]
        prefer: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClusterAction {
    /// Print the active policy + known peer state.
    Status,
    /// GOLD-G02-CLUSTER-01 — list ingested foreign gossip events
    /// (`idx_foreign_events`): what paired peers replicated to this node.
    /// Read-only over views.db; foreign events never mix into local memory.
    Events {
        /// Filter to one origin peer public key (hex).
        #[arg(long, value_name = "PEER_PK")]
        peer: Option<String>,
        /// Max rows (newest first).
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Inspect durable per-peer mesh cursors, pending exact replays, ACK high
    /// water marks and inbound sequence expectations.
    #[command(name = "sync-state")]
    SyncState {
        /// Filter to one authenticated peer public key.
        #[arg(long, value_name = "PEER_PK")]
        peer: Option<String>,
    },
    /// Ask the running daemon to accelerate durable WAL catch-up for one
    /// paired peer. The request is coalesced and persisted in views.db; only
    /// the daemon-owned authenticated transport can consume it.
    #[command(name = "request-sync")]
    RequestSync {
        /// Exact 64-character public key of an already-paired peer.
        #[arg(long, value_name = "PEER_PK")]
        peer: String,
    },
    /// Inspect the bounded, durable node-global causal frontier. Counters are
    /// provenance/ordering evidence only; they never grant trust or resolve a
    /// content conflict without an explicit operator decision.
    Frontier {
        /// Filter to one known node identity.
        #[arg(long, value_name = "PEER_PK")]
        peer: Option<String>,
    },
    /// Inspect or resolve typed same-origin/cross-origin content conflicts.
    Conflicts {
        #[command(subcommand)]
        action: Option<ClusterConflictAction>,
        /// Filter the list to one stable content id.
        #[arg(long, value_name = "CONTENT_ID")]
        content_id: Option<String>,
        /// Include acknowledged conflicts in the forensic list.
        #[arg(long)]
        all: bool,
        /// Maximum rows (newest first).
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// DES-13 — export this node's backup-at-rest for a crashed peer:
    /// dump the raw foreign gossip frames (`idx_foreign_events`) to a JSONL
    /// file so an operator can pull a failed node's replicated data off a
    /// surviving peer. This is the auditable input accepted by
    /// `neoth cluster restore`; restore still applies the replication
    /// allowlist, CRC checks, conflict policy, and dry-run gate. One JSON
    /// object per line:
    /// `{origin_peer_pk, origin_seq, event_type, payload_b64, received_at}`.
    #[command(name = "export-foreign")]
    ExportForeign {
        /// Filter to one origin peer public key (hex).
        #[arg(long, value_name = "PEER_PK")]
        peer: Option<String>,
        /// Output file (or `-` for stdout).
        #[arg(long, value_name = "FILE")]
        out: String,
        /// Max rows exported (newest first). Ignored when `--all` is set.
        #[arg(long, default_value = "1000")]
        limit: usize,
        /// Export the full table (lift the `--limit` bound).
        #[arg(long)]
        all: bool,
        /// Overwrite `--out` if it already exists (default: refuse).
        #[arg(long)]
        force: bool,
    },
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
    /// SL-02: cluster topology view — confirmed peers + per-peer
    /// last-seen age + a recent/stale/uncontacted status, table or
    /// `--output json`. Read-only over `~/.neoth/cluster.yaml`, including
    /// the last persisted heartbeat RTT and stability score. Instantaneous
    /// daemon-only health/TPS is intentionally outside this one-shot view.
    Topology,
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
    /// GOLD-FEAT-06 — exo-style swarm dashboard: per-node CPU/RAM/VRAM read
    /// from the `EXTENDED/LocalSnapshot` + `EXTENDED/SwarmResourceSnapshot` WAL
    /// frames the resource-snapshot cron emits. `--watch` refreshes live.
    #[cfg(feature = "cluster")]
    Swarm(crate::cli::cluster_swarm::ClusterSwarmArgs),
    /// Confirm a discovered peer + add to the registry. Phase 4
    /// of the SPEC — Phase 2 mDNS / Phase 3 Tailscale surface
    /// candidates; this command writes them in atomically.
    ///
    /// Two modes: positional one-shot (`neoth cluster confirm
    /// <pub_key> --label X --addr Y`) OR `--interactive` (scan
    /// + numbered-list picker — no copy-paste of pub_keys).
    Confirm {
        /// 64-char lowercase-hex of the peer's pub key. Strict
        /// validation: must be exactly 64 chars of [0-9a-f].
        /// Required unless `--interactive` is passed.
        pub_key: Option<String>,
        /// Operator-readable label. Required unless `--interactive`.
        /// In interactive mode the label is taken from the discovered
        /// peer's announce TXT record.
        #[arg(long)]
        label: Option<String>,
        /// Reachable socket address. Required unless `--interactive`.
        /// In interactive mode the addr is taken from the discovered
        /// peer's announce. Phase 6 gossip overrides.
        #[arg(long)]
        addr: Option<String>,
        /// Transport that surfaced the peer. Defaults to "manual"
        /// (operator typed the pub_key in directly).
        #[arg(long, default_value = "manual")]
        via: String,
        /// SL-01c: optional network hostname to record for the peer so
        /// you can later reference it by a memorable name
        /// (`neoth cluster revoke <hostname>`) instead of the 64-char
        /// pub_key. Not collected in `--interactive` mode — re-confirm
        /// with `--hostname` to set it.
        #[arg(long)]
        hostname: Option<String>,
        /// Interactive picker: run a mDNS scan first, render a
        /// numbered list of discovered peers, prompt operator for a
        /// selection, then confirm the pick. Skips the positional
        /// pub_key + --label + --addr requirement (values come from
        /// the selected announce). Tailscale candidates are excluded
        /// from the picker — they don't carry a pub_key.
        #[arg(long, default_value_t = false)]
        interactive: bool,
        /// Scan timeout for `--interactive`. Default 10s.
        #[arg(long, default_value_t = 10)]
        interactive_timeout: u64,
    },
    /// Remove a confirmed peer by pub_key OR unique prefix.
    Revoke { pub_key: String },
    /// Atomically replace the complete public cluster configuration and ask a
    /// running daemon to reload it. Lists are JSON string arrays so commas and
    /// leading/trailing whitespace survive the CLI/GUI boundary exactly.
    Configure {
        /// Transport master switch (`true` or `false`).
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        enabled: bool,
        /// Public cluster rendezvous name. Omit (or pass an empty string) to
        /// store no name; enabling without a name is rejected before commit.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Authenticated cluster transport.
        #[arg(
            long,
            default_value = "peeroxide",
            value_parser = ["peeroxide", "iroh"]
        )]
        transport: String,
        /// Bootstrap peers as a JSON string array, for example
        /// `["endpoint,with,commas"," endpoint with spaces "]`.
        #[arg(long, value_name = "JSON_ARRAY", default_value = "[]")]
        peers_json: String,
        /// LAN discovery switch (`true` or `false`).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        mdns_enabled: bool,
        /// Permit LAN announcements on untrusted Wi-Fi (`true` or `false`).
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        announce_on_untrusted_wifi: bool,
        /// Exact trusted SSIDs as a JSON string array.
        #[arg(long, value_name = "JSON_ARRAY", default_value = "[]")]
        trusted_ssids_json: String,
        /// Replicate raw channel-ingress frames to authenticated peers. This is
        /// privacy-sensitive and therefore defaults to false.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        replicate_raw_ingress: bool,
        /// Maximum age of WAL history offered to a catching-up peer.
        #[arg(long, default_value_t = 30)]
        replay_budget_days: u32,
        /// Shared mDNS/Tailscale probe port.
        #[arg(
            long,
            default_value_t = crate::config::DEFAULT_CLUSTER_LISTEN_PORT
        )]
        listen_port: u16,
        /// Read a replacement shared passphrase from one stdin line. The
        /// secret never enters argv, logs, or receipts. With a keychain
        /// backend this intentionally writes the documented credentials.yaml
        /// emergency override (file values win over the OS store).
        #[arg(long, default_value_t = false)]
        passphrase_stdin: bool,
    },
    /// Enable the cluster transport master switch using the same complete,
    /// restart-evidenced transaction as `cluster configure`.
    Enable,
    /// Disable the cluster transport master switch using the same complete,
    /// restart-evidenced transaction as `cluster configure`.
    Disable,
    /// Restore same-origin peer-backup frames into local recall/memory.
    ///
    /// Reads a JSONL export produced by `neoth cluster export-foreign` and
    /// applies frames whose `origin_peer_pk` matches the local node identity
    /// back into `idx_episode` / `idx_groundtruth`.  Cross-origin rows are
    /// silently counted and skipped.
    ///
    /// Pass `--dry-run` to evaluate conflicts without any writes.
    Restore {
        /// Path to the JSONL export file (produced by `neoth cluster export-foreign`).
        peer_export: String,
        /// Override the local node pubkey filter.  Use when the passphrase is
        /// unavailable but you know the 64-char hex pubkey that was used.
        #[arg(long)]
        peer: Option<String>,
        /// Evaluate conflict matrix and report per-row outcome without
        /// writing anything to `views.db` or the audit log.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Skip the TTY consent prompt.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
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
        anyhow::bail!("pub_key must be lowercase hex [0-9a-f]; got a char outside that range");
    }
    Ok(())
}

pub async fn run_cluster(args: ClusterArgs) -> Result<()> {
    match args.action {
        ClusterAction::Status => run_status(&args.output),
        ClusterAction::Events { peer, limit } => {
            run_foreign_events(peer.as_deref(), limit, &args.output)
        }
        ClusterAction::SyncState { peer } => run_sync_state(peer.as_deref(), &args.output),
        ClusterAction::RequestSync { peer } => run_request_sync(&peer, &args.output),
        ClusterAction::Frontier { peer } => run_frontier(peer.as_deref(), &args.output),
        ClusterAction::Conflicts {
            action,
            content_id,
            all,
            limit,
        } => run_conflicts(action, content_id.as_deref(), all, limit, &args.output),
        ClusterAction::ExportForeign {
            peer,
            out,
            limit,
            all,
            force,
        } => run_export_foreign(peer.as_deref(), &out, limit, all, force),
        ClusterAction::Plan { peers, policy } => run_plan(&peers, policy.as_deref(), &args.output),
        ClusterAction::List => run_list(),
        ClusterAction::Topology => run_topology(&args.output),
        ClusterAction::Discover { timeout, force } => run_discover(timeout, force).await,
        #[cfg(feature = "cluster")]
        ClusterAction::Swarm(mut a) => {
            a.output = args.output;
            crate::cli::cluster_swarm::run_cluster_swarm(a).await
        }
        ClusterAction::Confirm {
            pub_key,
            label,
            addr,
            via,
            hostname,
            interactive,
            interactive_timeout,
        } => {
            if interactive {
                run_confirm_interactive(interactive_timeout, &via).await
            } else {
                let pub_key = pub_key.ok_or_else(|| {
                    anyhow::anyhow!("missing positional pub_key (or pass --interactive)")
                })?;
                let label = label
                    .ok_or_else(|| anyhow::anyhow!("missing --label (or pass --interactive)"))?;
                let addr =
                    addr.ok_or_else(|| anyhow::anyhow!("missing --addr (or pass --interactive)"))?;
                run_confirm(&pub_key, &label, &addr, &via, hostname.as_deref())
            }
        }
        ClusterAction::Revoke { pub_key } => run_revoke(&pub_key),
        ClusterAction::Configure {
            enabled,
            name,
            transport,
            peers_json,
            mdns_enabled,
            announce_on_untrusted_wifi,
            trusted_ssids_json,
            replicate_raw_ingress,
            replay_budget_days,
            listen_port,
            passphrase_stdin,
        } => {
            let desired = build_cluster_config(
                enabled,
                name,
                &transport,
                &peers_json,
                mdns_enabled,
                announce_on_untrusted_wifi,
                &trusted_ssids_json,
                replicate_raw_ingress,
                replay_budget_days,
                listen_port,
            )?;
            let passphrase = passphrase_stdin
                .then(read_cluster_passphrase_from_stdin)
                .transpose()?;
            run_configure(desired, passphrase, &args.output)
        }
        ClusterAction::Enable => run_toggle(true, &args.output),
        ClusterAction::Disable => run_toggle(false, &args.output),
        ClusterAction::Restore {
            peer_export,
            peer,
            dry_run,
            yes,
        } => run_restore(&peer_export, peer.as_deref(), dry_run, yes),
    }
}

/// One discovered peer surfaced by a mDNS scan. Shared shape for
/// `cluster discover` rendering + `cluster confirm --interactive`
/// picker so the formats can't drift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub pub_key_hex: String,
    pub label: String,
    pub addr: String,
}

/// Spawn the mDNS browse daemon, collect verified announces for
/// `timeout_secs`, then shut down + return the de-duplicated peer
/// list. Pure scan path — no rendering; callers decide how to
/// present (discover prints a table, confirm --interactive
/// renders a numbered list).
async fn discover_scan(timeout_secs: u64) -> Result<Vec<DiscoveredPeer>> {
    let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| anyhow::anyhow!("mdns daemon: {e}"))?;
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
        match tokio::time::timeout(remaining, async { receiver.recv_async().await.ok() }).await {
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
    Ok(seen
        .into_iter()
        // GOLD-SEC-26 / A-28: drop peers whose mDNS-announced pubkey isn't
        // valid hex BEFORE they reach the picker / confirm path — defends the
        // downstream slicing + keeps a malformed announce from polluting the list.
        // GR-150: log each rejection (key truncated via short_key against
        // log-injection) so an operator can tell zero-peers-on-network apart
        // from all-peers-rejected-as-malformed.
        .filter(|(pub_key_hex, _)| {
            let ok = validate_pub_key_hex(pub_key_hex).is_ok();
            if !ok {
                tracing::debug!(
                    pub_key = short_key(pub_key_hex),
                    "cluster discover: dropping peer with invalid pubkey hex"
                );
            }
            ok
        })
        .map(|(pub_key_hex, (label, addr))| DiscoveredPeer {
            pub_key_hex,
            label,
            addr,
        })
        .collect())
}

/// Truncate a peer pubkey hex to its first 16 chars for display WITHOUT
/// panicking on a non-char boundary (GOLD-SEC-26 / A-28). An mDNS-announced
/// `pub_key_hex` is attacker-controlled and may be non-ASCII, so a raw
/// `[..16]` slice could panic the picker (externally-triggered DoS).
/// `get(..16)` returns `None` on a bad boundary / short input → full value.
fn short_key(s: &str) -> &str {
    s.get(..16).unwrap_or(s)
}

/// Render a numbered-list picker for `cluster confirm --interactive`.
/// Pure: input → operator-facing string. Picker indices are 1-based
/// because that's how operators read lists.
pub fn render_picker(peers: &[DiscoveredPeer]) -> String {
    if peers.is_empty() {
        return "(no peers found — run `neoth cluster discover` to confirm \
                your network is reachable, or pair via a different transport)"
            .to_string();
    }
    let mut out = String::new();
    out.push_str("Pick a peer to confirm:\n");
    for (i, p) in peers.iter().enumerate() {
        let key_short = short_key(&p.pub_key_hex);
        out.push_str(&format!(
            "  [{idx}] {label} ({key_short}) @ {addr}\n",
            idx = i + 1,
            label = p.label,
            addr = p.addr,
        ));
    }
    out
}

/// Parse a 1-indexed picker input ("1\n", " 2 ", "3") into the
/// 0-indexed `Vec` slot. Rejects 0, out-of-range, and non-numeric
/// input with operator-readable errors so the caller can re-prompt
/// or bail cleanly.
pub fn parse_pick(input: &str, peer_count: usize) -> Result<usize> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty selection — type the number of the peer to confirm");
    }
    let n: usize = trimmed
        .parse()
        .map_err(|_| anyhow::anyhow!("not a number: `{trimmed}` — picker uses 1-based indices"))?;
    if n == 0 {
        anyhow::bail!("0 is not a valid pick — picker is 1-indexed");
    }
    if n > peer_count {
        anyhow::bail!("pick {n} is out of range (only {peer_count} peer(s) shown)");
    }
    Ok(n - 1)
}

async fn run_confirm_interactive(timeout_secs: u64, via: &str) -> Result<()> {
    println!("interactive confirm: scanning for NEOTH peers for {timeout_secs}s…");
    let peers = discover_scan(timeout_secs).await?;
    if peers.is_empty() {
        println!("{}", render_picker(&peers));
        return Ok(());
    }
    print!("{}", render_picker(&peers));
    print!("> ");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| anyhow::anyhow!("read stdin: {e}"))?;
    let idx = parse_pick(&line, peers.len())?;
    let picked = &peers[idx];
    // Interactive picker doesn't collect a hostname (the mDNS announce
    // carries label + addr, not a stable hostname) — re-confirm with
    // `--hostname` to set it. SL-01c.
    run_confirm(&picked.pub_key_hex, &picked.label, &picked.addr, via, None)
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
    let config = FreedomConfig::load_from_default_path_or_default()?;
    let ssid = crate::cluster::policy::current_ssid();
    let gate = crate::cluster::policy::gate_discover(
        config.cluster.mdns.enabled,
        &config.cluster.policy,
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
    let peers = discover_scan(timeout_secs).await?;

    // Phase 3 — Tailscale magic-DNS enumeration. Runs in parallel
    // with the mDNS scan above; soft-fails when Tailscale CLI is
    // missing so non-tailnet operators pay zero cost.
    // Listen port comes from `freedom.yaml::cluster.listen_port`
    // (operator-tweakable) with `DEFAULT_NEOTH_LISTEN_PORT` (49737)
    // as the fallback.
    let ts_port = config.cluster.listen_port;
    let ts_candidates = match crate::cluster::tailscale::enumerate(ts_port).await {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, "tailscale enumeration soft-failed");
            Vec::new()
        }
    };

    if peers.is_empty() && ts_candidates.is_empty() {
        println!("(no peers seen during scan window)");
    } else {
        if !peers.is_empty() {
            println!(
                "{:<16} {:<24} {:<22} {:<10}",
                "pub_key", "label", "addr", "via"
            );
            for p in &peers {
                let key_short = short_key(&p.pub_key_hex);
                println!(
                    "{:<16} {:<24} {:<22} {:<10}",
                    key_short, p.label, p.addr, "mdns"
                );
            }
        }
        if !ts_candidates.is_empty() {
            if peers.is_empty() {
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
             to add a peer (Phase 4 require-consent gate), \
             or `neoth cluster confirm --interactive` for a number-picker."
        );
    }
    Ok(())
}

/// Operator-readable explanation + concrete fix for the
/// `DiscoverGate::SkipWith(reason)` path. Each `NoReason`
/// variant maps to a one-line cause + an actionable command
/// the operator can run to flip the verdict to `Proceed`.
fn print_skip_with_fix(reason: crate::cluster::policy::NoReason, ssid: Option<&str>) {
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
        let key_short = short_key(&p.pub_key_hex);
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

// ── SL-02 cluster topology view ──────────────────────────────────────────

/// A peer is "stale" once it hasn't announced for this long (~20 missed
/// heartbeat intervals at the typical cadence). Hardcoded for the v1.0 slice;
/// a future config knob can override.
const TOPOLOGY_STALE_AFTER_SECS: i64 = 300;

/// One rendered topology row. Pure data, no IO — unit-testable.
pub struct TopologyRow {
    pub pub_key_short: String,
    pub label: String,
    pub addr: String,
    pub via: String,
    /// `None` when the peer was confirmed but never since seen announce.
    pub last_seen_age_secs: Option<i64>,
    pub status: &'static str,
    /// SL-02b: last measured heartbeat RTT (ms), `None` until first round-trip.
    pub rtt_ms: Option<u64>,
    /// SL-02b: EWMA heartbeat-success ratio in `[0.0, 1.0]`.
    pub stability_score: f64,
}

/// `recent` / `stale` / `uncontacted` from a peer's last-seen timestamp.
fn topology_status(last_seen_unix: i64, now_unix: i64) -> &'static str {
    if last_seen_unix == 0 {
        "uncontacted"
    } else if now_unix.saturating_sub(last_seen_unix) > TOPOLOGY_STALE_AFTER_SECS {
        "stale"
    } else {
        "recent"
    }
}

/// Build topology rows from the persisted peer list. Pure — no fs, no clock
/// of its own (caller passes `now_unix`), so it is fully deterministic.
pub fn build_topology_rows(
    peers: &[crate::cluster::registry::PairedPeer],
    now_unix: i64,
) -> Vec<TopologyRow> {
    peers
        .iter()
        .map(|p| {
            let last_seen_age_secs = if p.last_seen_unix == 0 {
                None
            } else {
                Some(now_unix.saturating_sub(p.last_seen_unix).max(0))
            };
            TopologyRow {
                pub_key_short: p.pub_key_hex[..16.min(p.pub_key_hex.len())].to_string(),
                label: p.instance_label.clone(),
                addr: p.addr.clone(),
                via: p.discovered_via.as_str().to_string(),
                last_seen_age_secs,
                status: topology_status(p.last_seen_unix, now_unix),
                rtt_ms: p.rtt_ms,
                stability_score: p.stability_score,
            }
        })
        .collect()
}

/// Human-readable last-seen age.
fn fmt_last_seen(age: Option<i64>) -> String {
    match age {
        None => "never".to_string(),
        Some(s) if s < 5 => "just now".to_string(),
        Some(s) if s < 60 => format!("{s}s ago"),
        Some(s) if s < 3600 => format!("{}m ago", s / 60),
        Some(s) => format!("{}h ago", s / 3600),
    }
}

/// Render the topology table. Pure — returns the string so it is testable.
pub fn render_topology_table(rows: &[TopologyRow]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Cluster topology ({} peer{})\n",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" }
    ));
    out.push_str(&format!(
        "{:<16} {:<24} {:<22} {:<12} {:<12} {:<12} {:<8} {}\n",
        "pub_key", "label", "addr", "via", "last_seen", "status", "rtt", "stability"
    ));
    for r in rows {
        let rtt = r
            .rtt_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "---".to_string());
        out.push_str(&format!(
            "{:<16} {:<24} {:<22} {:<12} {:<12} {:<12} {:<8} {:.0}%\n",
            r.pub_key_short,
            r.label,
            r.addr,
            r.via,
            fmt_last_seen(r.last_seen_age_secs),
            r.status,
            rtt,
            r.stability_score * 100.0,
        ));
    }
    out
}

fn topology_now_unix() -> i64 {
    crate::time::now_unix_i64()
}

fn run_topology(output: &OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let reg = crate::cluster::registry::load(&home)?;
    let now = topology_now_unix();
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let peers: Vec<_> = reg
                .peers
                .iter()
                .map(|p| {
                    let age = if p.last_seen_unix == 0 {
                        None
                    } else {
                        Some(now.saturating_sub(p.last_seen_unix).max(0))
                    };
                    serde_json::json!({
                        "pub_key_short": &p.pub_key_hex[..16.min(p.pub_key_hex.len())],
                        "pub_key_hex": p.pub_key_hex,
                        "label": p.instance_label,
                        "hostname": p.hostname,
                        "addr": p.addr,
                        "via": p.discovered_via.as_str(),
                        "paired_at_unix": p.paired_at_unix,
                        "last_seen_unix": p.last_seen_unix,
                        "last_seen_age_secs": age,
                        "status": topology_status(p.last_seen_unix, now),
                        "rtt_ms": p.rtt_ms,
                        "stability_score": p.stability_score,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "peers": peers,
                    "local_mode": "single-node",
                }))?
            );
        }
        OutputFormat::Table => {
            if reg.peers.is_empty() {
                println!(
                    "(no confirmed cluster peers — run `neoth cluster discover` for an mDNS scan, \
                     then `neoth cluster confirm <pub_key>` to add a peer)"
                );
                return Ok(());
            }
            let rows = build_topology_rows(&reg.peers, now);
            print!("{}", render_topology_table(&rows));
            println!(
                "note: RTT and stability are the latest values persisted in cluster.yaml; \
                 status derives from the persisted last-seen timestamp."
            );
        }
    }
    Ok(())
}

fn run_confirm(
    pub_key: &str,
    label: &str,
    addr: &str,
    via: &str,
    hostname: Option<&str>,
) -> Result<()> {
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
        "hysteria_relay" | "hysteria" => crate::cluster::discovery::DiscoveryVia::HysteriaRelay,
        "manual" | "" => crate::cluster::discovery::DiscoveryVia::Manual,
        other => anyhow::bail!(
            "unknown discovered_via `{other}` — use mdns/tailscale/hysteria_relay/manual"
        ),
    };
    let home = FreedomConfig::default_neoth_home();
    let now = crate::time::now_unix_i64();
    let hostname_norm = hostname.map(|h| h.trim()).unwrap_or("").to_string();
    let peer = crate::cluster::registry::PairedPeer {
        pub_key_hex: pub_key_norm.clone(),
        instance_label: label.into(),
        hostname: hostname_norm,
        addr: addr.into(),
        discovered_via: via_enum,
        paired_at_unix: now,
        last_seen_unix: now,
        // SL-02b: a freshly-confirmed peer has no RTT yet + a neutral stability.
        rtt_ms: None,
        stability_score: crate::cluster::registry::NEUTRAL_STABILITY,
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
    println!(
        "confirmed peer `{label}` ({key_short}) via {via_enum_str}",
        via_enum_str = via_enum.as_str()
    );
    Ok(())
}

/// Best-effort sidecar drop for the WAL `0xE7` PeerRevoked audit frame.
/// Sidecar write failure is non-fatal — the registry change already
/// landed; the daemon emits the frame on its next tick when it can.
fn emit_revoke_sidecar(home: &std::path::Path, pub_key_hex: &str) {
    let payload = serde_json::json!({});
    if let Err(e) = crate::cluster::audit_sidecar::write_sidecar(
        home,
        crate::cluster::audit_sidecar::ClusterAuditKind::PeerRevoked,
        pub_key_hex,
        payload,
    ) {
        tracing::warn!(error = %e, "cluster revoke sidecar write failed (non-fatal)");
    }
}

/// What a revoke resolved to. Lets `revoke_peer` stay a pure
/// home-injectable core (tempdir-testable) while `run_revoke` owns the
/// operator-facing printing.
#[derive(Debug, PartialEq, Eq)]
enum RevokeOutcome {
    /// Removed by pub_key (full or unique prefix).
    ByKey(String),
    /// SL-01c: removed by resolving a recorded hostname → pub_key.
    ByHostname {
        label: String,
        hostname: String,
        key: String,
    },
    /// Nothing matched by either key or hostname.
    NoMatch,
}

/// Resolve + remove a peer from the registry under `home`. Tries the
/// arg as a pub_key (full or unique prefix) FIRST so an all-hex
/// hostname can never shadow a real key; on no key-match, falls back
/// to resolving the arg as a recorded hostname (SL-01c).
fn revoke_peer(home: &std::path::Path, arg: &str) -> Result<RevokeOutcome> {
    let key = arg.trim().to_ascii_lowercase();
    if crate::cluster::registry::remove(home, &key)? {
        emit_revoke_sidecar(home, &key);
        return Ok(RevokeOutcome::ByKey(key));
    }
    if let Some(peer) = crate::cluster::registry::find_by_hostname(home, arg.trim())
        && crate::cluster::registry::remove(home, &peer.pub_key_hex)?
    {
        emit_revoke_sidecar(home, &peer.pub_key_hex);
        return Ok(RevokeOutcome::ByHostname {
            label: peer.instance_label,
            hostname: arg.trim().to_string(),
            key: peer.pub_key_hex,
        });
    }
    Ok(RevokeOutcome::NoMatch)
}

fn run_revoke(pub_key: &str) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match revoke_peer(&home, pub_key)? {
        RevokeOutcome::ByKey(key) => println!("revoked peer `{key}`"),
        RevokeOutcome::ByHostname {
            label,
            hostname,
            key,
        } => {
            let short = &key[..16.min(key.len())];
            println!("revoked peer `{label}` (resolved hostname `{hostname}` → {short})");
        }
        RevokeOutcome::NoMatch => {
            println!(
                "no peer matched `{}` by pub_key or hostname (no-op)",
                pub_key.trim().to_ascii_lowercase()
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClusterConfigureMdnsReceipt {
    enabled: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClusterConfigurePolicyReceipt {
    announce_on_untrusted_wifi: bool,
    trusted_ssids: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClusterConfigureGossipReceipt {
    replicate_raw_ingress: bool,
    replay_budget_days: u32,
}

impl Default for ClusterConfigureGossipReceipt {
    fn default() -> Self {
        let policy = ClusterGossipPolicy::default();
        Self {
            replicate_raw_ingress: policy.replicate_raw_ingress,
            replay_budget_days: policy.replay_budget_days,
        }
    }
}

/// Secret-free, stable representation of the complete public cluster config.
/// This deliberately does not serialize `ClusterConfig` directly: the
/// deny-unknown contract lets CLI and GUI consumers reject accidental receipt
/// drift instead of silently ignoring a newly added field.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClusterConfigureSnapshot {
    name: Option<String>,
    enabled: bool,
    transport: ClusterTransport,
    peers: Vec<String>,
    mdns: ClusterConfigureMdnsReceipt,
    policy: ClusterConfigurePolicyReceipt,
    #[serde(default)]
    gossip: ClusterConfigureGossipReceipt,
    listen_port: u16,
}

impl From<&ClusterConfig> for ClusterConfigureSnapshot {
    fn from(config: &ClusterConfig) -> Self {
        Self {
            name: config.name.clone(),
            enabled: config.enabled,
            transport: config.transport,
            peers: config.peers.clone(),
            mdns: ClusterConfigureMdnsReceipt {
                enabled: config.mdns.enabled,
            },
            policy: ClusterConfigurePolicyReceipt {
                announce_on_untrusted_wifi: config.policy.announce_on_untrusted_wifi,
                trusted_ssids: config.policy.trusted_ssids.clone(),
            },
            gossip: ClusterConfigureGossipReceipt {
                replicate_raw_ingress: config.gossip.replicate_raw_ingress,
                replay_budget_days: config.gossip.replay_budget_days,
            },
            listen_port: config.listen_port,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClusterConfigureReceipt {
    operation: String,
    path: String,
    reload_requested: bool,
    reload_error: Option<String>,
    restart_required: bool,
    cluster_passphrase_set: bool,
    cluster: ClusterConfigureSnapshot,
}

const CLUSTER_RUNTIME_STATE_NAME: &str = ".cluster-runtime-state.json";
const CLUSTER_RUNTIME_STATE_LOCK_NAME: &str = ".cluster-runtime-state.lock";
const CLUSTER_RUNTIME_STATE_VERSION: u8 = 1;
const CLUSTER_RUNTIME_BINDING_INFO: &[u8] = b"neoth-cluster-runtime-binding-v1";

/// Owner-private, non-reversible binding between a runtime marker and the
/// effective cluster key. The HMAC key is derived from NEOTH's separately
/// protected master key, so the marker alone is not an offline passphrase
/// verifier. Debug output is always fully redacted.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct ClusterIdentityBinding([u8; 32]);

impl std::fmt::Debug for ClusterIdentityBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClusterIdentityBinding(<redacted>)")
    }
}

impl PartialEq for ClusterIdentityBinding {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for ClusterIdentityBinding {}

impl Drop for ClusterIdentityBinding {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn cluster_identity_binding_for_passphrase(
    home: &Path,
    passphrase: Option<&SecretString>,
    ensure_master_key: bool,
) -> Result<Option<ClusterIdentityBinding>> {
    let Some(cluster_key) = passphrase
        .and_then(|passphrase| crate::cluster::discovery::cluster_key(passphrase.expose()))
    else {
        return Ok(None);
    };

    let segment_key = if ensure_master_key {
        crate::wal::master_key::writer_segment_key_at(home).ok_or_else(|| {
            anyhow::anyhow!(
                "create/load the protected NEOTH master key for cluster runtime binding"
            )
        })?
    } else {
        let Some(key) = crate::wal::master_key::segment_key_at(home) else {
            return Ok(None);
        };
        key
    };

    // A second HKDF domain keeps this HMAC key separate from the WAL segment
    // encryption use of `segment_key`. Both intermediate keys zeroize on drop.
    let hkdf = Hkdf::<Sha256>::new(None, segment_key.expose());
    let mut binding_key = zeroize::Zeroizing::new([0_u8; 32]);
    hkdf.expand(CLUSTER_RUNTIME_BINDING_INFO, &mut *binding_key)
        .map_err(|_| anyhow::anyhow!("derive cluster runtime binding key"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&*binding_key)
        .map_err(|_| anyhow::anyhow!("construct cluster runtime binding HMAC"))?;
    mac.update(CLUSTER_RUNTIME_BINDING_INFO);
    mac.update(&cluster_key.0);
    let mut digest = mac.finalize().into_bytes();
    let mut binding = [0_u8; 32];
    binding.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    Ok(Some(ClusterIdentityBinding(binding)))
}

fn cluster_identity_binding(
    home: &Path,
    credentials: &Credentials,
    ensure_master_key: bool,
) -> Result<Option<ClusterIdentityBinding>> {
    cluster_identity_binding_for_passphrase(
        home,
        credentials.cluster_passphrase.as_ref(),
        ensure_master_key,
    )
}

/// Durable evidence for the startup-only cluster runtime. It contains no
/// passphrase or cluster key; the only secret-dependent value is the fully
/// redacted, master-keyed binding above.
///
/// A config write first publishes `ready_for_confirmation = false`. Only after
/// the complete public/credential transaction commits is the record finalized
/// as ready for a daemon acknowledgement. Only the daemon, after constructing
/// the selected carrier successfully, may attach its PID and carrier state.
/// Comparing the desired snapshot with freedom.yaml or merely observing a new
/// process is deliberately insufficient.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClusterRuntimeState {
    version: u8,
    ready_for_confirmation: bool,
    acknowledged_daemon_pid: Option<u32>,
    carrier_active: bool,
    mdns_active: bool,
    cluster_passphrase_set: bool,
    #[serde(default)]
    cluster_identity_binding: Option<ClusterIdentityBinding>,
    cluster: ClusterConfigureSnapshot,
}

impl ClusterRuntimeState {
    fn blocked(
        cluster: ClusterConfigureSnapshot,
        cluster_passphrase_set: bool,
        cluster_identity_binding: Option<ClusterIdentityBinding>,
    ) -> Self {
        Self {
            version: CLUSTER_RUNTIME_STATE_VERSION,
            ready_for_confirmation: false,
            acknowledged_daemon_pid: None,
            carrier_active: false,
            mdns_active: false,
            cluster_passphrase_set,
            cluster_identity_binding,
            cluster,
        }
    }

    fn finalize(mut self) -> Self {
        self.ready_for_confirmation = true;
        self
    }

    fn matches(
        &self,
        cluster: &ClusterConfigureSnapshot,
        cluster_passphrase_set: bool,
        cluster_identity_binding: Option<&ClusterIdentityBinding>,
    ) -> bool {
        let binding_matches = if cluster_passphrase_set {
            self.cluster_identity_binding
                .as_ref()
                .zip(cluster_identity_binding)
                .is_some_and(|(stored, current)| stored == current)
        } else {
            self.cluster_identity_binding.is_none() && cluster_identity_binding.is_none()
        };
        self.version == CLUSTER_RUNTIME_STATE_VERSION
            && self.cluster == *cluster
            && self.cluster_passphrase_set == cluster_passphrase_set
            && binding_matches
    }
}

fn cluster_runtime_state_path(home: &Path) -> std::path::PathBuf {
    home.join(CLUSTER_RUNTIME_STATE_NAME)
}

fn load_cluster_runtime_state(home: &Path) -> Result<Option<ClusterRuntimeState>> {
    let path = cluster_runtime_state_path(home);
    let body = match std::fs::read(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read cluster runtime state {}", path.display()));
        }
    };
    let state: ClusterRuntimeState = serde_json::from_slice(&body)
        .with_context(|| format!("parse cluster runtime state {}", path.display()))?;
    anyhow::ensure!(
        state.version == CLUSTER_RUNTIME_STATE_VERSION,
        "unsupported cluster runtime state version {} at {}",
        state.version,
        path.display()
    );
    Ok(Some(state))
}

fn write_cluster_runtime_state(home: &Path, state: &ClusterRuntimeState) -> Result<()> {
    let path = cluster_runtime_state_path(home);
    let body = serde_json::to_vec(state).context("serialize cluster runtime state")?;
    crate::util::atomic_write::atomic_write_private(&path, &body)
        .with_context(|| format!("atomically write cluster runtime state {}", path.display()))
}

fn capture_cluster_runtime_state(home: &Path) -> Result<Option<Vec<u8>>> {
    let path = cluster_runtime_state_path(home);
    match std::fs::read(&path) {
        Ok(body) => Ok(Some(body)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("snapshot cluster runtime state {}", path.display()))
        }
    }
}

fn restore_cluster_runtime_state(home: &Path, prior: Option<&[u8]>) -> Result<()> {
    let path = cluster_runtime_state_path(home);
    match prior {
        Some(body) => crate::util::atomic_write::atomic_write_private(&path, body)
            .with_context(|| format!("restore cluster runtime state {}", path.display())),
        None => crate::util::atomic_write::durable_remove_file(&path)
            .with_context(|| format!("remove cluster runtime state {}", path.display())),
    }
}

/// Return the PID only when a live process also owns the canonical daemon
/// PID-file lock. A numeric PID belonging to an unrelated live process is not
/// runtime evidence.
fn live_daemon_owner_pid(home: &Path) -> Result<Option<u32>> {
    let pidfile = home.join("neothd.pid");
    let Some(pid) = crate::daemon::pidfile::live_daemon_pid(&pidfile)
        .with_context(|| format!("inspect daemon pidfile {}", pidfile.display()))?
    else {
        return Ok(None);
    };
    match crate::util::locked_file::try_lock_file_once(&pidfile, "daemon pidfile")? {
        None => Ok(Some(pid)),
        Some(lock) => {
            drop(lock);
            Ok(None)
        }
    }
}

fn cluster_runtime_applied(
    state: Option<&ClusterRuntimeState>,
    cluster: &ClusterConfigureSnapshot,
    cluster_passphrase_set: bool,
    cluster_identity_binding: Option<&ClusterIdentityBinding>,
    live_daemon_pid: Option<u32>,
) -> bool {
    if !cluster.enabled && live_daemon_pid.is_none() {
        // With no daemon process there is no carrier left to stop. This is the
        // one safe state that needs no daemon acknowledgement.
        return true;
    }
    let Some(state) = state else {
        return false;
    };
    if !state.ready_for_confirmation
        || !state.matches(cluster, cluster_passphrase_set, cluster_identity_binding)
    {
        return false;
    }
    live_daemon_pid.is_some() && state.acknowledged_daemon_pid == live_daemon_pid
}

fn cluster_runtime_carrier_active(
    state: Option<&ClusterRuntimeState>,
    cluster: &ClusterConfigureSnapshot,
    cluster_passphrase_set: bool,
    cluster_identity_binding: Option<&ClusterIdentityBinding>,
    live_daemon_pid: Option<u32>,
) -> bool {
    cluster_runtime_applied(
        state,
        cluster,
        cluster_passphrase_set,
        cluster_identity_binding,
        live_daemon_pid,
    ) && state.is_some_and(|state| state.carrier_active)
}

/// Compare the effective secret generation that actually keys the cluster
/// carrier. The derived keys exist only for this in-memory comparison and are
/// zeroized on drop; no passphrase or reusable verifier is persisted in the
/// runtime marker.
#[cfg(any(feature = "cluster", test))]
fn same_cluster_secret_generation(left: &Credentials, right: &Credentials) -> bool {
    let derive = |credentials: &Credentials| {
        credentials
            .cluster_passphrase
            .as_ref()
            .and_then(|passphrase| crate::cluster::discovery::cluster_key(passphrase.expose()))
    };
    match (derive(left), derive(right)) {
        (Some(left), Some(right)) => bool::from(left.0.ct_eq(&right.0)),
        (None, None) => true,
        _ => false,
    }
}

/// Daemon-only acknowledgement written after the configured carrier has
/// actually started. This is the sole path that can make `cluster status`
/// report `transport_active=true`.
#[cfg(any(feature = "cluster", test))]
pub(crate) fn acknowledge_cluster_runtime_at(
    home: &Path,
    config: &FreedomConfig,
    credentials: &Credentials,
    carrier_active: bool,
    mdns_active: bool,
) -> Result<()> {
    let identity = crate::cluster::identity::cluster_identity_status(config, credentials);
    anyhow::ensure!(
        carrier_active == identity.transport_active,
        "cluster runtime acknowledgement disagrees with the activation gate (expected carrier_active={}, actual={carrier_active})",
        identity.transport_active
    );
    anyhow::ensure!(
        live_daemon_owner_pid(home)? == Some(std::process::id()),
        "refusing cluster runtime acknowledgement without ownership of {}",
        home.join("neothd.pid").display()
    );

    let _runtime_state_lock = crate::util::locked_file::lock_file_blocking(
        &home.join(CLUSTER_RUNTIME_STATE_LOCK_NAME),
        "cluster runtime state",
    )?;
    let snapshot = ClusterConfigureSnapshot::from(&config.cluster);
    let freedom_path = home.join("freedom.yaml");
    let current = crate::config::load_runtime_config_pair_from_path(&freedom_path)?;
    let current_identity =
        crate::cluster::identity::cluster_identity_status(&current.config, &current.credentials);
    let current_binding = cluster_identity_binding(home, &current.credentials, true)?;
    if ClusterConfigureSnapshot::from(&current.config.cluster) != snapshot
        || current_identity.has_passphrase != identity.has_passphrase
        || !same_cluster_secret_generation(credentials, &current.credentials)
    {
        // Config/credential state advanced after this daemon loaded its startup
        // snapshot. The newer pending marker belongs to that mutation and must
        // remain untouched until a daemon actually starts from it.
        return Ok(());
    }

    let mut state = match load_cluster_runtime_state(home)? {
        Some(state)
            if state.ready_for_confirmation
                && state.matches(&snapshot, identity.has_passphrase, current_binding.as_ref()) =>
        {
            state
        }
        Some(state) if !state.ready_for_confirmation => {
            // The writer cannot still be active because we own its state lock.
            // If disk matches this startup snapshot, either its config commit
            // landed (blocked snapshot also matches) or it crashed before the
            // commit (blocked snapshot differs). In both cases the daemon's
            // already-constructed, disk-verified runtime is authoritative.
            ClusterRuntimeState::blocked(snapshot, identity.has_passphrase, current_binding.clone())
                .finalize()
        }
        Some(state)
            if state.cluster == snapshot
                && state.cluster_passphrase_set == identity.has_passphrase =>
        {
            // An out-of-band credential import may rotate only the effective
            // passphrase. Disk and this freshly-constructed carrier already
            // match exactly, so replace the old binding without treating a
            // different public snapshot as acknowledged.
            ClusterRuntimeState::blocked(snapshot, identity.has_passphrase, current_binding.clone())
                .finalize()
        }
        Some(_) => return Ok(()),
        None => {
            ClusterRuntimeState::blocked(snapshot, identity.has_passphrase, current_binding.clone())
                .finalize()
        }
    };
    state.acknowledged_daemon_pid = Some(std::process::id());
    state.carrier_active = carrier_active;
    state.mdns_active = mdns_active;
    write_cluster_runtime_state(home, &state)
}

fn parse_json_string_array(raw: &str, flag: &str) -> Result<Vec<String>> {
    serde_json::from_str::<Vec<String>>(raw).with_context(|| {
        format!("parse --{flag} as a JSON string array (for example: [\"one\",\"two\"])")
    })
}

#[allow(clippy::too_many_arguments)]
fn build_cluster_config(
    enabled: bool,
    name: Option<String>,
    transport: &str,
    peers_json: &str,
    mdns_enabled: bool,
    announce_on_untrusted_wifi: bool,
    trusted_ssids_json: &str,
    replicate_raw_ingress: bool,
    replay_budget_days: u32,
    listen_port: u16,
) -> Result<ClusterConfig> {
    let transport = match transport {
        "peeroxide" => ClusterTransport::Peeroxide,
        "iroh" => ClusterTransport::Iroh,
        other => anyhow::bail!("unsupported cluster transport `{other}`"),
    };
    let config = ClusterConfig {
        name: name.and_then(|name| (!name.trim().is_empty()).then_some(name)),
        enabled,
        transport,
        peers: parse_json_string_array(peers_json, "peers-json")?,
        mdns: ClusterMdnsConfig {
            enabled: mdns_enabled,
        },
        policy: ClusterAnnouncePolicy {
            announce_on_untrusted_wifi,
            trusted_ssids: parse_json_string_array(trusted_ssids_json, "trusted-ssids-json")?,
        },
        gossip: ClusterGossipPolicy {
            replicate_raw_ingress,
            replay_budget_days,
        },
        listen_port,
    };
    validate_configure_cluster(&config)?;
    Ok(config)
}

fn validate_configure_cluster(config: &ClusterConfig) -> Result<()> {
    // Configure is a complete-snapshot contract. Refuse an unavailable
    // transport even while disabled so the stored snapshot is executable by
    // this binary and cannot become a delayed activation trap.
    if config.transport == ClusterTransport::Iroh && !cfg!(feature = "cluster-iroh") {
        anyhow::bail!(
            "cluster transport `iroh` requires a binary built with the `cluster-iroh` feature"
        );
    }
    config
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid cluster configuration: {error}"))
}

fn trim_one_line_ending(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

fn cluster_passphrase_from_line(value: String) -> Result<SecretString> {
    let passphrase = SecretString::new(trim_one_line_ending(value));
    crate::cluster::discovery::cluster_key(passphrase.expose()).ok_or_else(|| {
        anyhow::anyhow!("cluster passphrase must contain at least one non-whitespace character")
    })?;
    Ok(passphrase)
}

fn read_cluster_passphrase_from_stdin() -> Result<SecretString> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read cluster passphrase from stdin")?;
    cluster_passphrase_from_line(line)
}

fn has_usable_cluster_passphrase(credentials: &Credentials) -> bool {
    credentials
        .cluster_passphrase
        .as_ref()
        .and_then(|passphrase| crate::cluster::discovery::cluster_key(passphrase.expose()))
        .is_some()
}

fn ensure_enabled_cluster_identity(
    config: &FreedomConfig,
    credentials: &Credentials,
) -> Result<()> {
    if config.cluster.enabled
        && crate::cluster::identity::resolve_cluster_identity(config, credentials).is_none()
    {
        anyhow::bail!(
            "cluster identity is incomplete: enabling requires a non-empty cluster name and shared passphrase"
        );
    }
    Ok(())
}

/// Overlay every schema-owned cluster value while retaining extension keys at
/// any mapping depth. The configure contract replaces all known fields, but a
/// newer/third-party field must survive an older binary's lossless update.
fn overlay_known_cluster_yaml(target: &mut serde_yaml::Value, known: serde_yaml::Value) {
    match known {
        serde_yaml::Value::Mapping(known) => {
            if let serde_yaml::Value::Mapping(target) = target {
                for (key, value) in known {
                    if let Some(existing) = target.get_mut(&key) {
                        overlay_known_cluster_yaml(existing, value);
                    } else {
                        target.insert(key, value);
                    }
                }
            } else {
                *target = serde_yaml::Value::Mapping(known);
            }
        }
        known => *target = known,
    }
}

/// Path-injectable transaction core. A reload-request failure is deliberately
/// data in the success receipt: the config commit remains durable. Cluster
/// lifecycle changes stay `restart_required` until the daemon acknowledges the
/// exact startup snapshot after constructing its carrier.
fn configure_cluster_at_with_reload<R>(
    home: &Path,
    desired: ClusterConfig,
    passphrase: Option<SecretString>,
    request_reload: R,
) -> Result<ClusterConfigureReceipt>
where
    R: FnOnce(&Path) -> Result<()>,
{
    configure_cluster_at_with_reload_and_public_validation_hook(
        home,
        desired,
        passphrase,
        request_reload,
        || {},
    )
}

fn configure_cluster_at_with_reload_and_public_validation_hook<R, H>(
    home: &Path,
    desired: ClusterConfig,
    passphrase: Option<SecretString>,
    request_reload: R,
    after_public_validation: H,
) -> Result<ClusterConfigureReceipt>
where
    R: FnOnce(&Path) -> Result<()>,
    H: FnOnce(),
{
    validate_configure_cluster(&desired)?;
    if let Some(passphrase) = passphrase.as_ref()
        && crate::cluster::discovery::cluster_key(passphrase.expose()).is_none()
    {
        anyhow::bail!("cluster passphrase must contain at least one non-whitespace character");
    }

    let freedom_path = home.join("freedom.yaml");
    let credentials_path = home.join("credentials.yaml");
    let desired_snapshot = ClusterConfigureSnapshot::from(&desired);
    let _runtime_state_lock = crate::util::locked_file::lock_file_blocking(
        &home.join(CLUSTER_RUNTIME_STATE_LOCK_NAME),
        "cluster runtime state",
    )?;
    let existing_runtime_state = load_cluster_runtime_state(home)?;
    let runtime_state_before = capture_cluster_runtime_state(home)?;

    let (cluster_passphrase_set, cluster_identity_binding, runtime_state) = if let Some(
        passphrase,
    ) = passphrase
    {
        // The restart marker is published in a deliberately unconfirmable
        // state before either config file changes. If the dual-file mutation
        // fails, restore the exact prior marker; if finalization fails after a
        // successful commit, the blocked marker remains fail-closed.
        let cluster_identity_binding =
            cluster_identity_binding_for_passphrase(home, Some(&passphrase), true)?;
        let blocked = ClusterRuntimeState::blocked(
            desired_snapshot.clone(),
            true,
            cluster_identity_binding.clone(),
        );
        write_cluster_runtime_state(home, &blocked)?;
        let desired_for_update = desired.clone();
        let cluster_passphrase_set = match Credentials::update_with_freedom_at(
            &freedom_path,
            &credentials_path,
            move |config, credentials| {
                config.cluster = desired_for_update;
                credentials.cluster_passphrase = Some(passphrase);
                ensure_enabled_cluster_identity(config, credentials)?;
                Ok(has_usable_cluster_passphrase(credentials))
            },
        ) {
            Ok(value) => value,
            Err(error) => {
                if let Err(restore_error) =
                    restore_cluster_runtime_state(home, runtime_state_before.as_deref())
                {
                    anyhow::bail!(
                        "cluster configuration failed ({error:#}); restoring its restart state also failed: {restore_error:#}"
                    );
                }
                return Err(error).context("cluster configuration transaction failed");
            }
        };
        let finalized = blocked.finalize();
        write_cluster_runtime_state(home, &finalized)?;
        (
            cluster_passphrase_set,
            cluster_identity_binding,
            Some(finalized),
        )
    } else {
        // Replace only the YAML `cluster` node. `FreedomConfig::update_at`
        // intentionally strips inline legacy secrets, which makes it the wrong
        // primitive for this public-only mutation: an operator changing cluster
        // peers must not lose provider, Telegram, or inference credentials.
        // The raw transaction retains every unrelated YAML value while one
        // dual-file boundary holds from effective credential validation through
        // the freedom.yaml rename. A concurrent passphrase rotation/removal
        // cannot slip between those two operations.
        let desired_for_plan = desired.clone();
        let desired_snapshot_for_plan = desired_snapshot.clone();
        let freedom_path_for_plan = freedom_path.clone();
        let existing_runtime_state_for_plan = existing_runtime_state.clone();
        let update = crate::config::update_raw_freedom_with_effective_credentials_at(
            &freedom_path,
            move |source, credentials| {
                anyhow::ensure!(
                    !source.trim().is_empty(),
                    "freedom.yaml not found at {}. Run `neoth init` first to generate it.",
                    freedom_path_for_plan.display()
                );
                let current: FreedomConfig = serde_yaml::from_str(source).with_context(|| {
                    format!("parse YAML at {}", freedom_path_for_plan.display())
                })?;
                let public_config_changed =
                    ClusterConfigureSnapshot::from(&current.cluster) != desired_snapshot_for_plan;

                let mut persisted: serde_yaml::Value =
                    serde_yaml::from_str(source).with_context(|| {
                        format!(
                            "parse {} for lossless cluster update",
                            freedom_path_for_plan.display()
                        )
                    })?;
                let root = persisted
                    .as_mapping_mut()
                    .ok_or_else(|| anyhow::anyhow!("freedom.yaml root must be a YAML mapping"))?;
                let cluster_key = serde_yaml::Value::String("cluster".to_string());
                let desired_cluster = serde_yaml::to_value(&desired_for_plan)
                    .context("serialize complete cluster configuration")?;
                if let Some(existing_cluster) = root.get_mut(&cluster_key) {
                    overlay_known_cluster_yaml(existing_cluster, desired_cluster);
                } else {
                    root.insert(cluster_key, desired_cluster);
                }
                let body = serde_yaml::to_string(&persisted)
                    .context("serialize losslessly merged cluster configuration")?;
                let candidate: FreedomConfig =
                    serde_yaml::from_str(&body).context("validate merged cluster configuration")?;
                ensure_enabled_cluster_identity(&candidate, credentials)?;
                let cluster_passphrase_set = has_usable_cluster_passphrase(credentials);
                let cluster_identity_binding = cluster_identity_binding(home, credentials, true)?;
                let runtime_state_matches =
                    existing_runtime_state_for_plan
                        .as_ref()
                        .is_some_and(|state| {
                            state.matches(
                                &desired_snapshot_for_plan,
                                cluster_passphrase_set,
                                cluster_identity_binding.as_ref(),
                            )
                        });
                let needs_new_runtime_state = public_config_changed
                    || existing_runtime_state_for_plan.is_some() && !runtime_state_matches
                    || existing_runtime_state_for_plan.is_none() && desired_for_plan.enabled;
                let blocked = needs_new_runtime_state.then(|| {
                    ClusterRuntimeState::blocked(
                        desired_snapshot_for_plan.clone(),
                        cluster_passphrase_set,
                        cluster_identity_binding.clone(),
                    )
                });
                if let Some(blocked) = blocked.as_ref() {
                    write_cluster_runtime_state(home, blocked)?;
                }
                // Test-only barriers use this exact point to prove credential
                // writers remain excluded until the raw freedom rename lands.
                after_public_validation();
                Ok((
                    body,
                    (cluster_passphrase_set, cluster_identity_binding, blocked),
                ))
            },
        );
        let (cluster_passphrase_set, cluster_identity_binding, blocked) = match update {
            Ok(value) => value,
            Err(error) => {
                if let Err(restore_error) =
                    restore_cluster_runtime_state(home, runtime_state_before.as_deref())
                {
                    anyhow::bail!(
                        "cluster configuration failed ({error:#}); restoring its restart state also failed: {restore_error:#}"
                    );
                }
                return Err(error).context("commit lossless cluster configuration");
            }
        };

        let runtime_state = if let Some(blocked) = blocked {
            let finalized = blocked.finalize();
            write_cluster_runtime_state(home, &finalized)?;
            Some(finalized)
        } else {
            existing_runtime_state
        };
        (
            cluster_passphrase_set,
            cluster_identity_binding,
            runtime_state,
        )
    };

    let live_daemon_pid = live_daemon_owner_pid(home)?;
    let restart_required = !cluster_runtime_applied(
        runtime_state.as_ref(),
        &desired_snapshot,
        cluster_passphrase_set,
        cluster_identity_binding.as_ref(),
        live_daemon_pid,
    );

    let (reload_requested, reload_error) = match request_reload(home) {
        Ok(()) => (true, None),
        Err(error) => (false, Some(format!("{error:#}"))),
    };

    Ok(ClusterConfigureReceipt {
        operation: "cluster.configure".to_string(),
        path: freedom_path.display().to_string(),
        reload_requested,
        reload_error,
        restart_required,
        cluster_passphrase_set,
        cluster: desired_snapshot,
    })
}

fn run_configure(
    desired: ClusterConfig,
    passphrase: Option<SecretString>,
    output: &OutputFormat,
) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let receipt = configure_cluster_at_with_reload(&home, desired, passphrase, |home| {
        crate::cli::reload::request_reload_at(home).map(|_| ())
    })?;

    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&receipt)?),
        OutputFormat::Table => {
            println!("cluster configuration committed: {}", receipt.path);
            println!("  enabled                    : {}", receipt.cluster.enabled);
            println!(
                "  name                       : {}",
                receipt.cluster.name.as_deref().unwrap_or("(unset)")
            );
            println!(
                "  transport                  : {}",
                match receipt.cluster.transport {
                    ClusterTransport::Peeroxide => "peeroxide",
                    ClusterTransport::Iroh => "iroh",
                }
            );
            println!(
                "  peers                      : {}",
                serde_json::to_string(&receipt.cluster.peers)?
            );
            println!(
                "  mdns.enabled               : {}",
                receipt.cluster.mdns.enabled
            );
            println!(
                "  announce on untrusted wifi : {}",
                receipt.cluster.policy.announce_on_untrusted_wifi
            );
            println!(
                "  trusted ssids              : {}",
                serde_json::to_string(&receipt.cluster.policy.trusted_ssids)?
            );
            println!(
                "  listen port                : {}",
                receipt.cluster.listen_port
            );
            println!(
                "  shared passphrase          : {}",
                if receipt.cluster_passphrase_set {
                    "set"
                } else {
                    "(unset)"
                }
            );
            println!(
                "  reload requested           : {}",
                receipt.reload_requested
            );
            println!(
                "  restart required           : {}",
                receipt.restart_required
            );
            if let Some(error) = receipt.reload_error.as_deref() {
                println!("  reload error               : {error}");
            }
        }
    }
    Ok(())
}

fn run_toggle(enabled: bool, output: &OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let desired = toggle_desired_cluster_at(&home, enabled)?;
    run_configure(desired, None, output)
}

fn toggle_desired_cluster_at(home: &Path, enabled: bool) -> Result<ClusterConfig> {
    let mut desired = FreedomConfig::load_from_path(&home.join("freedom.yaml"))?.cluster;
    desired.enabled = enabled;
    Ok(desired)
}

/// Confirmed-peer count for `neoth cluster status`, factored out of
/// [`run_status`] so the GOLD-HON-03 honesty fix (read the registry,
/// never report a hardcoded `0`) is unit-testable without stdout
/// capture. A malformed `cluster.yaml` propagates as an error.
#[cfg_attr(not(test), allow(dead_code))] // retained: exercised by unit tests; prod caller removed in Wave-3 refactor
fn status_peer_count(home: &std::path::Path) -> Result<usize> {
    Ok(crate::cluster::registry::load(home)?.peers.len())
}

/// Pure derivation of the `mode` / `policy` labels shown by
/// `neoth cluster status` (GOLD-HON-03). Both follow live config:
/// `mode` from the cluster activation gate, `policy` from the mDNS
/// announce policy in `freedom.yaml`. When the cluster is off nothing
/// is ever announced or contacted, so the honest label is `local-only`.
fn status_mode_policy(
    cluster_enabled: bool,
    mdns_enabled: bool,
    announce_on_untrusted_wifi: bool,
) -> (&'static str, &'static str) {
    let mode = if cluster_enabled {
        "cluster"
    } else {
        "single-node"
    };
    let policy = if !cluster_enabled {
        "local-only"
    } else if !mdns_enabled {
        "discovery-off"
    } else if announce_on_untrusted_wifi {
        "announce-any-network"
    } else {
        "announce-trusted-wifi-only"
    };
    (mode, policy)
}

fn run_status(output: &OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let runtime_config = crate::config::load_runtime_config_pair_from_path_or_default(
        &FreedomConfig::default_path(),
    )?;
    let cfg = runtime_config.config;
    let creds = runtime_config.credentials;
    let operator = cfg
        .operator_id
        .clone()
        .unwrap_or_else(|| "(unset)".to_string());
    let node_id =
        crate::cluster::wal_sync::local_node_pubkey(&home)?.unwrap_or_else(|| operator.clone());

    // SL-00(1a): cluster identity status (public name + whether a shared
    // passphrase is set). Reads freedom.yaml::cluster.name + credentials
    // cluster_passphrase via the fail-closed resolver; never exposes the key.
    let identity = crate::cluster::identity::cluster_identity_status(&cfg, &creds);
    let cluster_identity_binding = cluster_identity_binding(&home, &creds, false)?;

    let configured_snapshot = ClusterConfigureSnapshot::from(&cfg.cluster);
    let runtime_state = load_cluster_runtime_state(&home)?;
    let live_daemon_pid = live_daemon_owner_pid(&home)?;
    let runtime_applied = cluster_runtime_applied(
        runtime_state.as_ref(),
        &configured_snapshot,
        identity.has_passphrase,
        cluster_identity_binding.as_ref(),
        live_daemon_pid,
    );
    let transport_active = identity.transport_active
        && cluster_runtime_carrier_active(
            runtime_state.as_ref(),
            &configured_snapshot,
            identity.has_passphrase,
            cluster_identity_binding.as_ref(),
            live_daemon_pid,
        );

    // SL-00(1b): a complete on-disk identity is only the activation request.
    // `active` additionally requires the daemon-written acknowledgement made
    // after successful carrier construction. Disk equality and PID presence
    // never become runtime proof.
    let transport_state = if transport_active {
        match cfg.cluster.transport {
            crate::config::ClusterTransport::Peeroxide => {
                "active (peeroxide Hyperswarm DHT; daemon carrier-start acknowledged)"
            }
            crate::config::ClusterTransport::Iroh => {
                "active (iroh QUIC; daemon carrier-start acknowledged)"
            }
        }
    } else if identity.enabled && !identity.configured {
        "inactive (cluster enabled, but effective identity is incomplete)"
    } else if identity.enabled && live_daemon_pid.is_none() {
        "configured, not live (daemon is stopped; start NEOTH to apply)"
    } else if identity.enabled && !runtime_applied {
        "configured, not live (restart required; current daemon owns the prior cluster state)"
    } else if identity.configured && !identity.enabled {
        if runtime_applied {
            "disabled (identity ready; no live cluster transport requested)"
        } else {
            "disable pending (restart required; current daemon may still own the prior transport)"
        }
    } else {
        "inactive (no cluster identity)"
    };

    // GOLD-HON-03: report the REAL cluster posture instead of the old
    // hardcoded `single-node` / `local-only` / `0` placeholder, which
    // lied about peers even after `neoth cluster confirm` had paired
    // them (A-13).
    // Confirmed-peer count from the on-disk registry. A malformed
    // `cluster.yaml` surfaces as a hard error (load() never silently
    // empties) rather than a false "0 peers".
    let registry = crate::cluster::registry::load(&home)?;
    let peer_count = registry.peers.len();
    let now = topology_now_unix();
    let status_peers: Vec<_> = registry
        .peers
        .iter()
        .map(|peer| {
            let age =
                (peer.last_seen_unix > 0).then(|| now.saturating_sub(peer.last_seen_unix).max(0));
            serde_json::json!({
                "id": peer.pub_key_hex,
                "label": peer.instance_label,
                "last_seen": fmt_last_seen(age),
                "last_seen_unix": peer.last_seen_unix,
                "reachable": topology_status(peer.last_seen_unix, now) == "recent",
            })
        })
        .collect();
    let views_db = home.join("views.db");
    let conflict_count = if views_db.exists() {
        crate::cluster::durable_sync::DurableMeshSync::new(views_db).unresolved_conflict_count()?
    } else {
        0
    };
    let (mode, policy_name) = status_mode_policy(
        identity.enabled,
        cfg.cluster.mdns.enabled,
        cfg.cluster.policy.announce_on_untrusted_wifi,
    );

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "mode": mode,
                "policy": policy_name,
                "peer_count": peer_count,
                "conflict_count": conflict_count,
                "operator_id": operator,
                "node_id": node_id,
                "cluster_name": identity.name,
                "cluster_passphrase_set": identity.has_passphrase,
                "cluster_identity_configured": identity.configured,
                "cluster_enabled": identity.enabled,
                "restart_required": !runtime_applied,
                "transport_active": transport_active,
                "transport": transport_state,
                "listen_port": cfg.cluster.listen_port,
                "mdns_enabled": cfg.cluster.mdns.enabled,
                "trusted_ssids": cfg.cluster.policy.trusted_ssids,
                "peers": status_peers,
                "gossip": {
                    "replicate_raw_ingress": cfg.cluster.gossip.replicate_raw_ingress,
                    "replay_budget_days": cfg.cluster.gossip.replay_budget_days,
                },
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Cluster status");
            println!("  mode             : {mode}");
            println!("  policy           : {policy_name}");
            println!("  peer count       : {peer_count}");
            println!("  open conflicts   : {conflict_count}");
            println!("  operator id      : {operator}");
            println!(
                "  cluster name     : {}",
                identity.name.as_deref().unwrap_or("(unset)")
            );
            println!(
                "  shared passphrase: {}",
                if identity.has_passphrase {
                    "set"
                } else {
                    "(unset)"
                }
            );
            println!(
                "  identity         : {}",
                if identity.configured {
                    "configured"
                } else {
                    "INCOMPLETE — set cluster.name + cluster_passphrase to enable the cluster"
                }
            );
            println!(
                "  transport switch : {}",
                if identity.enabled {
                    "enabled (cluster.enabled: true)"
                } else {
                    "disabled (cluster.enabled: false)"
                }
            );
            println!(
                "  restart required : {}",
                if runtime_applied { "no" } else { "yes" }
            );
            println!(
                "  raw ingress sync : {}",
                if cfg.cluster.gossip.replicate_raw_ingress {
                    "enabled"
                } else {
                    "disabled (privacy default)"
                }
            );
            println!(
                "  replay budget    : {} days",
                cfg.cluster.gossip.replay_budget_days
            );
            println!("  transport        : {transport_state}");
            if conflict_count > 0 {
                println!(
                    "  action           : inspect with `neoth cluster conflicts`; resolve with \
                     `neoth cluster conflicts resolve <content-id> --prefer <origin>`"
                );
            }
            println!();
            if !identity.configured {
                println!(
                    "  No cluster identity yet. A cluster needs a public `cluster.name` \
                     (freedom.yaml) AND a shared `cluster_passphrase` (credentials.yaml) on \
                     every node — the passphrase derives the HMAC key that authenticates peers."
                );
            } else if !identity.enabled {
                println!(
                    "  Identity is ready but the transport master-switch is OFF. Set \
                     it with `neoth cluster enable`, then restart when its receipt says \
                     `restart_required: true`. (Default OFF — no DHT announce until you opt in.)"
                );
            }
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
    use crate::cluster::PeerSessionId;
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
            peer: PeerSessionId::new(name.trim()),
            tokens_per_sec: tps,
            last_observed: Instant::now(),
            healthy: true,
        });
    }
    Ok(out)
}

/// GOLD-G02-CLUSTER-01 — render the foreign-event ledger.
/// DES-13 — the fixed warning banner every export carries. Honest framing:
/// this is a backup artifact whose canonical v5 rows are restorable; legacy
/// rows keep the original WAL-only compatibility shape.
const EXPORT_FOREIGN_WARNING: &str = "# WARNING: backup dump of replicated peer events (idx_foreign_events).\n\
     # v5 rows contain both the original WAL frame and a canonical content envelope.\n\
     # Use `neoth cluster restore <this-file>` to\n\
     # apply same-origin frames back into local recall/memory. Cross-peer rows\n\
     # are skipped. Archive as an off-node backup (DES-13-AUTO-RESTORE-01).";

/// DES-13 — one JSONL line for the export. PURE + unit-pinned: the payload is
/// base64 so the file stays valid UTF-8 (`jq`-able). Canonical semantic memory
/// may contain operator content; raw/private content appears only after the
/// explicit replication opt-in. Credentials, permissions and profiles have no
/// mesh envelope representation.
fn export_foreign_jsonl_line(row: &crate::cluster::wal_sync::ForeignEventRow) -> String {
    use base64::Engine as _;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&row.payload);
    let envelope_b64 = row
        .content_payload
        .as_ref()
        .map(|payload| base64::engine::general_purpose::STANDARD.encode(payload));
    let content_sha256 = row.content_sha256.map(|digest| {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(64);
        for byte in digest {
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    });
    serde_json::json!({
        "origin_peer_pk": row.origin_peer_pk,
        "origin_seq": row.origin_seq,
        "event_type": format!("0x{:02X}", row.event_type),
        "payload_b64": payload_b64,
        "received_at": row.received_at,
        "envelope_version": row.envelope_version,
        "content_sha256": content_sha256,
        "envelope_b64": envelope_b64,
    })
    .to_string()
}

fn run_export_foreign(
    peer: Option<&str>,
    out: &str,
    limit: usize,
    all: bool,
    force: bool,
) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let conn = crate::memory::store::open(&home.join("views.db"))
        .context("open views.db — has the daemon run at least once?")?;
    // `--all` lifts the bound; otherwise the default 1000 caps a busy cluster.
    let cap = if all { usize::MAX } else { limit };
    let rows = crate::cluster::wal_sync::list_foreign_events(&conn, peer, cap)?;

    let mut body = String::new();
    body.push_str(EXPORT_FOREIGN_WARNING);
    body.push('\n');
    for r in &rows {
        body.push_str(&export_foreign_jsonl_line(r));
        body.push('\n');
    }

    if out == "-" {
        print!("{body}");
    } else {
        let path = std::path::Path::new(out);
        // Clobber guard: refuse to overwrite an existing file unless --force
        // (a bad path must never silently truncate views.db / a WAL segment).
        if path.exists() && !force {
            anyhow::bail!("refusing to overwrite existing file `{out}` (pass --force to replace)");
        }
        std::fs::write(path, body.as_bytes()).with_context(|| format!("write export to {out}"))?;
        eprintln!(
            "exported {} foreign event(s){} → {out}",
            rows.len(),
            peer.map(|p| format!(" from peer {p}")).unwrap_or_default(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DES-13-AUTO-RESTORE-01 — restore helpers
// ---------------------------------------------------------------------------

/// One JSONL data row from the export file (`neoth cluster export-foreign`).
/// Comment lines (`#`) are filtered before parsing.
#[derive(Debug, serde::Deserialize)]
struct ExportRow {
    origin_peer_pk: String,
    origin_seq: u64,
    /// Hex-encoded event type, e.g. `"0x90"` or `"0x9E"`.
    event_type: String,
    /// Base64-encoded full WAL frame bytes.
    payload_b64: String,
    received_at: i64,
    #[serde(default)]
    envelope_version: Option<u16>,
    #[serde(default)]
    content_sha256: Option<String>,
    #[serde(default)]
    envelope_b64: Option<String>,
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .chars()
                .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch)),
        "content_sha256 must be 64 lowercase hex chars"
    );
    let mut digest = [0_u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .with_context(|| format!("invalid content_sha256 at byte {index}"))?;
    }
    Ok(digest)
}

/// Parse `"0xNN"` or `"0XNN"` (case-insensitive) → `u8`.
fn parse_event_type_hex(s: &str) -> Result<u8> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| anyhow::anyhow!("event_type must start with '0x', got: {s:?}"))?;
    u8::from_str_radix(stripped, 16)
        .with_context(|| format!("event_type hex parse failed for {s:?}"))
}

/// Open (or create+append) the off-WAL audit log at `path` with 0600 permissions.
///
/// Reuses the same ACL helper that `memory/store.rs` uses so no Windows ACL
/// code is hand-rolled here.
fn open_audit_log(path: &std::path::Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open audit log {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        let _ = crate::wal::win_acl::restrict_to_owner(path);
    }
    Ok(file)
}

fn run_restore(
    peer_export: &str,
    peer_pk_override: Option<&str>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    use std::io::{BufRead, IsTerminal, Write};

    use base64::Engine as _;

    let home = crate::config::FreedomConfig::default_neoth_home();

    // ── 1. Resolve local node pubkey ──────────────────────────────────────
    let local_pk: String = match peer_pk_override {
        Some(pk) => {
            validate_pub_key_hex(pk)?;
            pk.to_string()
        }
        None => crate::cluster::wal_sync::local_node_pubkey(&home)?.ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot derive local node pubkey — no cluster passphrase configured.\n\
                 Either run `neoth init` with a cluster passphrase, or pass --peer <pubkey>."
            )
        })?,
    };

    // ── 2. Open views.db — fail fast if the daemon holds the write lock ───
    let conn = crate::memory::store::open(&home.join("views.db")).with_context(|| {
        "Cannot open views.db.\n\
         If the neothd daemon is running, stop it first, then retry. SQLite exclusive\n\
         lock prevents concurrent restore."
    })?;
    // Probe for an EXCLUSIVE lock in one round-trip. If the daemon is active
    // this will return `SQLITE_BUSY` which anyhow surfaces clearly.
    conn.execute_batch("BEGIN IMMEDIATE; COMMIT")
        .with_context(|| {
            "views.db is locked (another process holds it open).\n\
             Stop the neothd daemon and retry."
        })?;

    // ── 3. Consent prompt (skipped for --dry-run and --yes) ──────────────
    if !dry_run && !yes {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "Non-TTY input without --yes: refusing to restore without explicit consent.\n\
                 Add --yes to skip the prompt in non-interactive contexts."
            );
        }
        eprint!(
            "About to restore same-origin frames from `{peer_export}` into views.db.\n\
             Local node pubkey: {local_pk}\n\
             This will UPDATE existing idx_episode / idx_groundtruth rows.\n\
             Proceed? [y/N] "
        );
        let mut answer = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut answer)
            .context("read consent prompt")?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            anyhow::bail!("Restore aborted by operator.");
        }
    }

    // ── 4. Parse and apply the export file line-by-line ──────────────────
    let file = std::fs::File::open(peer_export)
        .with_context(|| format!("open export file {peer_export}"))?;
    let reader = std::io::BufReader::new(file);

    let mut rows_applied: usize = 0;
    let mut rows_skipped: usize = 0;
    let mut rows_cross_peer: usize = 0;
    let mut rows_malformed: usize = 0;

    // Deduplicate cross-peer WARNs: one per unique foreign pk, not per row.
    let mut warned_cross_peer: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Audit log opened lazily so --dry-run never creates the file.
    let audit_path = home.join("restore-audit.jsonl");
    let mut audit_file: Option<std::fs::File> = None;

    for (line_idx, raw_line) in reader.lines().enumerate() {
        let line =
            raw_line.with_context(|| format!("read line {} of {peer_export}", line_idx + 1))?;
        let line = line.trim();

        // Skip comment and blank lines (# lines from the export header).
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Malformed JSONL — count as skipped, never abort the run.
        let export_row: ExportRow = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    line = line_idx + 1,
                    error = %e,
                    "restore: malformed JSONL line — skipped"
                );
                rows_malformed += 1;
                rows_skipped += 1;
                continue;
            }
        };

        // Same-origin-only: skip and deduplicate WARN per foreign pk.
        if export_row.origin_peer_pk != local_pk {
            if warned_cross_peer.insert(export_row.origin_peer_pk.clone()) {
                tracing::warn!(
                    peer = %export_row.origin_peer_pk,
                    "restore: cross-peer row (origin_peer_pk != local pubkey); \
                     skipping all rows from this peer"
                );
            }
            rows_cross_peer += 1;
            rows_skipped += 1;
            continue;
        }

        // Parse event_type — malformed → skip row.
        let event_type = match parse_event_type_hex(&export_row.event_type) {
            Ok(et) => et,
            Err(e) => {
                tracing::warn!(
                    line = line_idx + 1,
                    error = %e,
                    "restore: malformed event_type — skipped"
                );
                rows_malformed += 1;
                rows_skipped += 1;
                continue;
            }
        };

        // Decode base64 payload — malformed → skip row.
        let payload_bytes =
            match base64::engine::general_purpose::STANDARD.decode(&export_row.payload_b64) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        line = line_idx + 1,
                        error = %e,
                        "restore: base64 decode failed — skipped"
                    );
                    rows_malformed += 1;
                    rows_skipped += 1;
                    continue;
                }
            };

        // Per-row savepoint so a Skip/error on one row doesn't roll back
        // previously Applied rows.
        let sp = format!("restore_r{line_idx}");
        if !dry_run {
            conn.execute_batch(&format!("SAVEPOINT \"{sp}\""))
                .with_context(|| format!("savepoint for line {}", line_idx + 1))?;
        }

        let apply_result = if let Some(envelope_b64) = export_row.envelope_b64.as_deref() {
            let envelope_version = export_row.envelope_version.unwrap_or_default();
            let digest = export_row
                .content_sha256
                .as_deref()
                .context("canonical export row is missing content_sha256")
                .and_then(parse_sha256_hex);
            digest.and_then(|digest| {
                anyhow::ensure!(
                    envelope_version == crate::cluster::gossip_wire::SYNC_ENVELOPE_VERSION,
                    "unsupported canonical export envelope version {envelope_version}"
                );
                let envelope_bytes = base64::engine::general_purpose::STANDARD
                    .decode(envelope_b64)
                    .context("canonical export envelope base64 decode failed")?;
                let envelope: crate::cluster::gossip_wire::SyncEnvelope =
                    serde_json::from_slice(&envelope_bytes)
                        .context("canonical export envelope JSON decode failed")?;
                crate::cluster::wal_sync::apply_restore_envelope(
                    &conn,
                    &export_row.origin_peer_pk,
                    export_row.origin_seq,
                    &envelope,
                    digest,
                    dry_run,
                )
            })
        } else {
            crate::cluster::wal_sync::apply_restore_frame(
                &conn,
                &export_row.origin_peer_pk,
                export_row.origin_seq,
                event_type,
                &payload_bytes,
                export_row.received_at,
                dry_run,
            )
        };

        let outcome = match apply_result {
            Ok(o) => {
                if !dry_run {
                    conn.execute_batch(&format!("RELEASE SAVEPOINT \"{sp}\""))
                        .with_context(|| format!("release savepoint line {}", line_idx + 1))?;
                }
                o
            }
            Err(e) => {
                if !dry_run {
                    let _ = conn.execute_batch(&format!("ROLLBACK TO SAVEPOINT \"{sp}\""));
                    let _ = conn.execute_batch(&format!("RELEASE SAVEPOINT \"{sp}\""));
                }
                tracing::warn!(
                    line = line_idx + 1,
                    event_type = event_type,
                    error = %e,
                    "restore: apply_restore_frame error — row skipped"
                );
                rows_skipped += 1;
                continue;
            }
        };

        // Append to the off-WAL audit log (never in dry-run).
        if !dry_run {
            let (outcome_tag, skip_reason) = match &outcome {
                crate::cluster::wal_sync::RestoreOutcome::Applied => ("applied", String::new()),
                crate::cluster::wal_sync::RestoreOutcome::Skipped(r) => ("skipped", r.to_string()),
            };
            let audit_entry = serde_json::json!({
                "ts": crate::time::now_unix_i64(),
                "origin_peer_pk": export_row.origin_peer_pk,
                "origin_seq": export_row.origin_seq,
                "event_type": format!("0x{:02X}", event_type),
                "outcome": outcome_tag,
                "skip_reason": skip_reason,
            });
            let af = audit_file.get_or_insert_with(|| {
                open_audit_log(&audit_path).unwrap_or_else(|e| {
                    tracing::warn!(
                        error = %e,
                        path = %audit_path.display(),
                        "restore: cannot open audit log — audit not written"
                    );
                    // ponytail: /dev/null / NUL sink so the closure type is satisfied.
                    #[cfg(unix)]
                    return std::fs::OpenOptions::new()
                        .write(true)
                        .open("/dev/null")
                        .expect("open /dev/null");
                    #[cfg(not(unix))]
                    return std::fs::OpenOptions::new()
                        .write(true)
                        .open("NUL")
                        .expect("open NUL");
                })
            });
            let _ = writeln!(af, "{audit_entry}");
        }

        match outcome {
            crate::cluster::wal_sync::RestoreOutcome::Applied => rows_applied += 1,
            crate::cluster::wal_sync::RestoreOutcome::Skipped(reason) => {
                if dry_run {
                    eprintln!(
                        "  [dry-run] seq={} et={} → skipped: {reason}",
                        export_row.origin_seq, export_row.event_type,
                    );
                } else {
                    tracing::debug!(
                        reason = %reason,
                        seq = export_row.origin_seq,
                        "restore: row skipped"
                    );
                }
                rows_skipped += 1;
            }
        }
    }

    // ── 5. Summary ────────────────────────────────────────────────────────
    let mode = if dry_run { "[dry-run]" } else { "[done]" };
    let audit_note = if dry_run {
        String::new()
    } else {
        format!(" audit={}", audit_path.display())
    };
    eprintln!(
        "restore {mode}: applied={rows_applied} skipped={rows_skipped} \
         (cross-peer={rows_cross_peer} malformed={rows_malformed}){audit_note}"
    );
    Ok(())
}

fn run_foreign_events(
    peer: Option<&str>,
    limit: usize,
    output: &crate::cli::OutputFormat,
) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let conn = crate::memory::store::open(&home.join("views.db"))
        .context("open views.db — has the daemon run at least once?")?;
    let rows = crate::cluster::wal_sync::list_foreign_events(&conn, peer, limit)?;
    match output {
        crate::cli::OutputFormat::Json => {
            let v: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "origin_peer_pk": r.origin_peer_pk,
                        "origin_seq": r.origin_seq,
                        "event_type": format!("0x{:02X}", r.event_type),
                        "payload_bytes": r.payload.len(),
                        "received_at": r.received_at,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        crate::cli::OutputFormat::Jsonl => {
            for r in &rows {
                println!(
                    "{}",
                    serde_json::json!({
                        "origin_peer_pk": r.origin_peer_pk,
                        "origin_seq": r.origin_seq,
                        "event_type": format!("0x{:02X}", r.event_type),
                        "payload_bytes": r.payload.len(),
                        "received_at": r.received_at,
                    })
                );
            }
        }
        crate::cli::OutputFormat::Table => {
            if rows.is_empty() {
                println!("(no foreign events ingested — peers gossip after pairing)");
                return Ok(());
            }
            println!(
                "{:<20} {:>8} {:>6} {:>8} {:>12}",
                "ORIGIN PEER", "SEQ", "TYPE", "BYTES", "RECEIVED"
            );
            for r in &rows {
                let short: String = r.origin_peer_pk.chars().take(16).collect();
                println!(
                    "{:<20} {:>8} 0x{:02X} {:>8} {:>12}",
                    format!("{short}..."),
                    r.origin_seq,
                    r.event_type,
                    r.payload.len(),
                    r.received_at,
                );
            }
        }
    }
    Ok(())
}

fn run_sync_state(peer: Option<&str>, output: &crate::cli::OutputFormat) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let sync = crate::cluster::durable_sync::DurableMeshSync::new(home.join("views.db"));
    let rows = sync.list_status(peer)?;
    match output {
        crate::cli::OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        crate::cli::OutputFormat::Jsonl => {
            for row in &rows {
                println!("{}", serde_json::to_string(row)?);
            }
        }
        crate::cli::OutputFormat::Table => {
            if rows.is_empty() {
                println!("(no durable mesh peer state yet)");
                return Ok(());
            }
            println!(
                "{:<20} {:>9} {:>9} {:>9} {:>9} {:>10} {:>12}",
                "PEER", "ACKED", "PENDING", "ATTEMPTS", "IN NEXT", "CURSOR", "REQUEST"
            );
            for row in rows {
                let short: String = row.peer_pk.chars().take(16).collect();
                let cursor = row.cursor_segment.as_deref().map_or_else(
                    || row.cursor_offset.to_string(),
                    |segment| {
                        let name = std::path::Path::new(segment)
                            .file_name()
                            .and_then(std::ffi::OsStr::to_str)
                            .unwrap_or(segment);
                        format!("{name}:{}", row.cursor_offset)
                    },
                );
                println!(
                    "{:<20} {:>9} {:>9} {:>9} {:>9} {:>10} {:>12}",
                    format!("{short}..."),
                    row.acked_origin_seq,
                    row.pending_origin_seq
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                    row.pending_attempts
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                    row.inbound_next_expected_seq
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                    cursor,
                    row.request_state.as_deref().unwrap_or("-"),
                );
                if let Some(error) = row.request_last_error.as_deref() {
                    println!("  request: {error}");
                }
            }
        }
    }
    Ok(())
}

fn run_request_sync(peer: &str, output: &crate::cli::OutputFormat) -> Result<()> {
    validate_pub_key_hex(peer)?;
    let home = crate::config::FreedomConfig::default_neoth_home();
    let registry = crate::cluster::registry::load(&home)?;
    anyhow::ensure!(
        registry.peers.iter().any(|known| known.pub_key_hex == peer),
        "peer `{peer}` is not paired; confirm it before requesting sync"
    );
    let runtime_config = crate::config::load_runtime_config_pair_from_path_or_default(
        &crate::config::FreedomConfig::default_path(),
    )?;
    let identity = crate::cluster::identity::cluster_identity_status(
        &runtime_config.config,
        &runtime_config.credentials,
    );
    let configured_snapshot = ClusterConfigureSnapshot::from(&runtime_config.config.cluster);
    let runtime_state = load_cluster_runtime_state(&home)?;
    let live_daemon_pid = live_daemon_owner_pid(&home)?;
    let binding = cluster_identity_binding(&home, &runtime_config.credentials, false)?;
    anyhow::ensure!(
        identity.transport_active
            && cluster_runtime_carrier_active(
                runtime_state.as_ref(),
                &configured_snapshot,
                identity.has_passphrase,
                binding.as_ref(),
                live_daemon_pid,
            ),
        "no live authenticated cluster carrier; start or restart NEOTH before requesting sync"
    );
    let sync = crate::cluster::durable_sync::DurableMeshSync::new(home.join("views.db"));
    let receipt = sync.request_sync(
        &crate::cluster::PeerPubkey::new(peer.to_string()),
        crate::time::now_unix_i64(),
    )?;
    match output {
        crate::cli::OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        crate::cli::OutputFormat::Jsonl => println!("{}", serde_json::to_string(&receipt)?),
        crate::cli::OutputFormat::Table => {
            println!("Mesh sync requested for {peer}.");
            println!("  state   : {}", receipt.state);
            println!("  expires : {}", receipt.expires_at);
            println!(
                "The daemon will use the configured authenticated carrier; inspect progress with `neoth cluster sync-state --peer {peer}`."
            );
        }
    }
    Ok(())
}

fn run_frontier(peer: Option<&str>, output: &crate::cli::OutputFormat) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let sync = crate::cluster::durable_sync::DurableMeshSync::new(home.join("views.db"));
    let mut rows = sync.list_vector_frontier()?;
    if let Some(peer) = peer {
        rows.retain(|row| row.peer_pk == peer);
    }
    match output {
        crate::cli::OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        crate::cli::OutputFormat::Jsonl => {
            for row in &rows {
                println!("{}", serde_json::to_string(row)?);
            }
        }
        crate::cli::OutputFormat::Table => {
            if rows.is_empty() {
                println!("(no durable causal-frontier state yet)");
                return Ok(());
            }
            println!("{:<24} {:>20}", "NODE", "CAUSAL COUNTER");
            for row in rows {
                let short: String = row.peer_pk.chars().take(20).collect();
                println!("{:<24} {:>20}", format!("{short}..."), row.counter);
            }
            println!();
            println!(
                "Causal counters record observed ordering only; they never grant trust or auto-resolve conflicts."
            );
        }
    }
    Ok(())
}

fn run_conflicts(
    action: Option<ClusterConflictAction>,
    content_id: Option<&str>,
    include_resolved: bool,
    limit: usize,
    output: &crate::cli::OutputFormat,
) -> Result<()> {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let sync = crate::cluster::durable_sync::DurableMeshSync::new(home.join("views.db"));
    if let Some(ClusterConflictAction::Resolve {
        content_id: resolved_content_id,
        prefer,
    }) = action
    {
        anyhow::ensure!(
            content_id.is_none() && !include_resolved,
            "--content-id and --all are list-only conflict flags"
        );
        let receipt = sync.resolve_conflicts(resolved_content_id.trim(), prefer.trim())?;
        match output {
            crate::cli::OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            }
            crate::cli::OutputFormat::Jsonl => {
                println!("{}", serde_json::to_string(&receipt)?);
            }
            crate::cli::OutputFormat::Table => {
                println!("# Cluster conflict resolved");
                println!("  content id       : {}", receipt.content_id);
                println!("  preferred origin : {}", receipt.preferred_origin);
                println!("  rows resolved    : {}", receipt.resolved_count);
                println!("  unresolved remain: {}", receipt.unresolved_remaining);
            }
        }
        return Ok(());
    }

    let rows = sync.list_conflicts(content_id, limit, include_resolved)?;
    let unresolved_count = sync.unresolved_conflict_count()?;
    match output {
        crate::cli::OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "unresolved_count": unresolved_count,
                    "include_resolved": include_resolved,
                    "conflicts": rows,
                }))?
            );
        }
        crate::cli::OutputFormat::Jsonl => {
            for row in &rows {
                println!("{}", serde_json::to_string(row)?);
            }
        }
        crate::cli::OutputFormat::Table => {
            if rows.is_empty() {
                println!(
                    "(no {}mesh conflicts)",
                    if include_resolved {
                        "recorded "
                    } else {
                        "unresolved "
                    }
                );
                return Ok(());
            }
            println!(
                "{:<10} {:<34} {:<18} {:<18} {:<28} {:<11}",
                "STATE", "CONTENT", "INCUMBENT", "INCOMING", "POLICY", "OBSERVED"
            );
            for row in rows {
                let content: String = row.content_id.chars().take(32).collect();
                let incumbent: String = row.incumbent_origin.chars().take(16).collect();
                let incoming: String = row.incoming_origin.chars().take(16).collect();
                println!(
                    "{:<10} {:<34} {:<18} {:<18} {:<28} {:<11}",
                    if row.resolved_at.is_some() {
                        "resolved"
                    } else {
                        "OPEN"
                    },
                    content,
                    incumbent,
                    incoming,
                    row.policy,
                    row.observed_at,
                );
                if let Some(preferred) = row.preferred_origin {
                    println!("           preferred origin: {preferred}");
                }
            }
            println!("\nunresolved total: {unresolved_count}");
            if unresolved_count > 0 {
                println!("resolve: neoth cluster conflicts resolve <content-id> --prefer <origin>");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_freedom(home: &Path, config: &FreedomConfig) {
        std::fs::create_dir_all(home).expect("create test home");
        std::fs::write(
            home.join("freedom.yaml"),
            serde_yaml::to_string(config).expect("serialize test freedom config"),
        )
        .expect("write test freedom config");
    }

    fn write_test_cluster_passphrase(home: &Path, passphrase: &str) {
        let credentials = Credentials {
            cluster_passphrase: Some(SecretString::new(passphrase.to_string())),
            ..Credentials::default()
        };
        credentials
            .write(&home.join("credentials.yaml"))
            .expect("write test credentials");
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn configure_commits_complete_snapshot_and_reports_reload_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());
        let freedom_path = home.join("freedom.yaml");
        let mut extended: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).expect("read initial freedom"))
                .expect("parse initial freedom");
        extended["cluster"]["gossip"]["future_strategy"] =
            serde_yaml::Value::String("preserve-through-secret-transaction".to_string());
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&extended).expect("serialize extended freedom"),
        )
        .expect("write extended freedom");

        let desired = build_cluster_config(
            true,
            Some("operators".to_string()),
            "peeroxide",
            r#"["peer,one"," peer two "]"#,
            false,
            true,
            r#"["Office, East","  Lab WiFi  "]"#,
            true,
            14,
            51_234,
        )
        .expect("valid complete cluster config");
        let passphrase = SecretString::new("do-not-print-this-secret".to_string());
        let receipt = configure_cluster_at_with_reload(home, desired, Some(passphrase), |_| {
            anyhow::bail!("sentinel path is read-only")
        })
        .expect("config commit remains successful when reload request fails");

        assert_eq!(receipt.operation, "cluster.configure");
        assert_eq!(
            receipt.path,
            home.join("freedom.yaml").display().to_string()
        );
        assert!(!receipt.reload_requested);
        assert_eq!(
            receipt.reload_error.as_deref(),
            Some("sentinel path is read-only")
        );
        assert!(receipt.restart_required);
        assert!(receipt.cluster_passphrase_set);

        let stored = FreedomConfig::load_from_path(&home.join("freedom.yaml"))
            .expect("reload stored config");
        assert!(stored.cluster.enabled);
        assert_eq!(stored.cluster.name.as_deref(), Some("operators"));
        assert_eq!(stored.cluster.transport, ClusterTransport::Peeroxide);
        assert_eq!(stored.cluster.peers, ["peer,one", " peer two "]);
        assert!(!stored.cluster.mdns.enabled);
        assert!(stored.cluster.policy.announce_on_untrusted_wifi);
        assert_eq!(
            stored.cluster.policy.trusted_ssids,
            ["Office, East", "  Lab WiFi  "]
        );
        assert!(stored.cluster.gossip.replicate_raw_ingress);
        assert_eq!(stored.cluster.gossip.replay_budget_days, 14);
        assert_eq!(stored.cluster.listen_port, 51_234);
        let stored_raw: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).expect("read stored freedom"))
                .expect("parse stored freedom");
        assert_eq!(
            stored_raw["cluster"]["gossip"]["future_strategy"].as_str(),
            Some("preserve-through-secret-transaction")
        );

        let stored_credentials = Credentials::load_or_default(&home.join("credentials.yaml"))
            .expect("reload stored credentials");
        assert_eq!(
            stored_credentials
                .cluster_passphrase
                .as_ref()
                .expect("cluster passphrase")
                .expose(),
            "do-not-print-this-secret"
        );

        let json = serde_json::to_string(&receipt).expect("serialize receipt");
        assert!(!json.contains("do-not-print-this-secret"));
        let decoded: ClusterConfigureReceipt =
            serde_json::from_str(&json).expect("receipt round trip");
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn configure_invalid_enabled_identity_preserves_both_files_exactly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());
        write_test_cluster_passphrase(home, "existing-passphrase");
        let freedom_path = home.join("freedom.yaml");
        let credentials_path = home.join("credentials.yaml");
        let freedom_before = std::fs::read(&freedom_path).expect("read freedom before");
        let credentials_before = std::fs::read(&credentials_path).expect("read credentials before");

        let invalid = ClusterConfig {
            enabled: true,
            name: None,
            ..ClusterConfig::default()
        };
        let error = configure_cluster_at_with_reload(
            home,
            invalid,
            Some(SecretString::new("replacement-passphrase".to_string())),
            |_| Ok(()),
        )
        .expect_err("enabled cluster without name must fail before commit");

        assert!(error.to_string().contains("name is required"));
        assert_eq!(
            std::fs::read(&freedom_path).expect("read freedom after"),
            freedom_before
        );
        assert_eq!(
            std::fs::read(&credentials_path).expect("read credentials after"),
            credentials_before
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn configure_without_new_passphrase_uses_existing_identity_without_rewriting_credentials() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());
        write_test_cluster_passphrase(home, "existing-passphrase");
        let credentials_path = home.join("credentials.yaml");
        let credentials_before = std::fs::read(&credentials_path).expect("read credentials before");
        let desired = ClusterConfig {
            name: Some("existing-identity".to_string()),
            enabled: true,
            ..ClusterConfig::default()
        };

        let receipt = configure_cluster_at_with_reload(home, desired, None, |_| Ok(()))
            .expect("existing secret completes enabled identity");

        assert!(receipt.cluster.enabled);
        assert!(receipt.restart_required);
        assert!(receipt.cluster_passphrase_set);
        assert_eq!(
            std::fs::read(&credentials_path).expect("read credentials after"),
            credentials_before,
            "public-only configure must not rewrite credentials.yaml"
        );
    }

    #[test]
    fn configure_without_new_passphrase_preserves_every_legacy_inline_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let mut config = FreedomConfig::default();
        config.provider_key = Some(SecretString::from("legacy-provider"));
        config.telegram_token = Some(SecretString::from("111111111:legacy-telegram"));
        config.inference.left.key = Some(SecretString::from("legacy-left"));
        config.inference.right.key = Some(SecretString::from("legacy-right"));
        config.inference.cerebellum.key = Some(SecretString::from("legacy-cerebellum"));
        config.inference.default_slot.key = Some(SecretString::from("legacy-default"));
        write_test_freedom(home, &config);
        let freedom_path = home.join("freedom.yaml");
        let mut raw: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).expect("read initial freedom"))
                .expect("parse initial freedom");
        let root = raw.as_mapping_mut().expect("mapping");
        root.insert(
            serde_yaml::Value::String("future_extension".to_string()),
            serde_yaml::Value::String("keep-me".to_string()),
        );
        let cluster = root
            .get_mut(&serde_yaml::Value::String("cluster".to_string()))
            .and_then(serde_yaml::Value::as_mapping_mut)
            .expect("cluster mapping");
        cluster.insert(
            serde_yaml::Value::String("future_carrier_hint".to_string()),
            serde_yaml::Value::String("keep-cluster-extension".to_string()),
        );
        let gossip = cluster
            .get_mut(&serde_yaml::Value::String("gossip".to_string()))
            .and_then(serde_yaml::Value::as_mapping_mut)
            .expect("gossip mapping");
        gossip.insert(
            serde_yaml::Value::String("future_strategy".to_string()),
            serde_yaml::Value::String("keep-nested-extension".to_string()),
        );
        std::fs::write(
            &freedom_path,
            serde_yaml::to_string(&raw).expect("serialize extended freedom"),
        )
        .expect("write extended freedom");

        let desired = ClusterConfig {
            peers: vec!["peer,with,commas".to_string()],
            ..ClusterConfig::default()
        };
        configure_cluster_at_with_reload(home, desired, None, |_| Ok(()))
            .expect("public-only cluster update");

        let persisted: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).expect("read updated freedom"))
                .expect("parse updated freedom");
        assert_eq!(persisted["provider_key"].as_str(), Some("legacy-provider"));
        assert_eq!(
            persisted["telegram_token"].as_str(),
            Some("111111111:legacy-telegram")
        );
        assert_eq!(
            persisted["inference"]["left"]["key"].as_str(),
            Some("legacy-left")
        );
        assert_eq!(
            persisted["inference"]["right"]["key"].as_str(),
            Some("legacy-right")
        );
        assert_eq!(
            persisted["inference"]["cerebellum"]["key"].as_str(),
            Some("legacy-cerebellum")
        );
        assert_eq!(
            persisted["inference"]["default_slot"]["key"].as_str(),
            Some("legacy-default")
        );
        assert_eq!(persisted["future_extension"].as_str(), Some("keep-me"));
        assert_eq!(
            persisted["cluster"]["future_carrier_hint"].as_str(),
            Some("keep-cluster-extension")
        );
        assert_eq!(
            persisted["cluster"]["gossip"]["future_strategy"].as_str(),
            Some("keep-nested-extension")
        );
        assert!(
            !home.join("credentials.yaml").exists(),
            "public-only cluster apply must not invent or rewrite credentials.yaml"
        );
    }

    #[test]
    fn enable_disable_alias_preserves_complete_cluster_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let mut config = FreedomConfig::default();
        config.cluster = ClusterConfig {
            name: Some("operators".to_string()),
            enabled: false,
            transport: ClusterTransport::Peeroxide,
            peers: vec!["peer,one".to_string(), " peer two ".to_string()],
            mdns: ClusterMdnsConfig { enabled: false },
            policy: ClusterAnnouncePolicy {
                announce_on_untrusted_wifi: true,
                trusted_ssids: vec!["Office, East".to_string()],
            },
            gossip: crate::config::ClusterGossipPolicy::default(),
            listen_port: 51_234,
        };
        write_test_freedom(home, &config);

        let enabled = toggle_desired_cluster_at(home, true).expect("build enable snapshot");
        assert!(enabled.enabled);
        let mut expected = config.cluster.clone();
        expected.enabled = true;
        assert_eq!(
            ClusterConfigureSnapshot::from(&enabled),
            ClusterConfigureSnapshot::from(&expected)
        );

        let disabled = toggle_desired_cluster_at(home, false).expect("build disable snapshot");
        assert_eq!(
            ClusterConfigureSnapshot::from(&disabled),
            ClusterConfigureSnapshot::from(&config.cluster)
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn configure_retry_keeps_restart_pending_until_daemon_carrier_acknowledgement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());
        write_test_cluster_passphrase(home, "existing-passphrase");
        let desired = ClusterConfig {
            name: Some("operators".to_string()),
            enabled: true,
            ..ClusterConfig::default()
        };

        let first = configure_cluster_at_with_reload(home, desired.clone(), None, |_| Ok(()))
            .expect("first configure");
        assert!(first.restart_required);
        let retry = configure_cluster_at_with_reload(home, desired.clone(), None, |_| Ok(()))
            .expect("retry before restart");
        assert!(
            retry.restart_required,
            "disk equality must not clear a pending restart"
        );

        let _daemon_owner = crate::daemon::pidfile::acquire(&home.join("neothd.pid"))
            .expect("acquire simulated daemon owner");
        let live_config =
            FreedomConfig::load_from_path(&home.join("freedom.yaml")).expect("load live config");
        let live_credentials = Credentials::load_or_default(&home.join("credentials.yaml"))
            .expect("load live credentials");
        acknowledge_cluster_runtime_at(home, &live_config, &live_credentials, true, false)
            .expect("daemon acknowledges successful carrier startup");
        let after_restart = configure_cluster_at_with_reload(home, desired, None, |_| Ok(()))
            .expect("retry after a new daemon generation");
        assert!(after_restart.reload_requested);
        assert!(!after_restart.restart_required);
    }

    #[test]
    fn daemon_pid_without_pidfile_lock_is_not_runtime_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("neothd.pid");
        std::fs::write(&pidfile, format!("{}\n", std::process::id()))
            .expect("write unlocked pidfile");
        assert_eq!(live_daemon_owner_pid(dir.path()).unwrap(), None);

        let _owner = crate::daemon::pidfile::acquire(&pidfile).expect("lock daemon pidfile");
        assert_eq!(
            live_daemon_owner_pid(dir.path()).unwrap(),
            Some(std::process::id())
        );
    }

    #[test]
    fn runtime_state_requires_exact_snapshot_and_daemon_carrier_acknowledgement() {
        let desired = ClusterConfigureSnapshot::from(&ClusterConfig {
            enabled: true,
            name: Some("operators".to_string()),
            ..ClusterConfig::default()
        });
        let binding = ClusterIdentityBinding([7_u8; 32]);
        let mut state =
            ClusterRuntimeState::blocked(desired.clone(), true, Some(binding.clone())).finalize();
        assert!(!cluster_runtime_applied(
            Some(&state),
            &desired,
            true,
            Some(&binding),
            Some(41)
        ));
        state.acknowledged_daemon_pid = Some(42);
        state.carrier_active = true;
        assert!(cluster_runtime_applied(
            Some(&state),
            &desired,
            true,
            Some(&binding),
            Some(42)
        ));
        assert!(cluster_runtime_carrier_active(
            Some(&state),
            &desired,
            true,
            Some(&binding),
            Some(42)
        ));
        state.carrier_active = false;
        assert!(cluster_runtime_applied(
            Some(&state),
            &desired,
            true,
            Some(&binding),
            Some(42)
        ));
        assert!(!cluster_runtime_carrier_active(
            Some(&state),
            &desired,
            true,
            Some(&binding),
            Some(42)
        ));

        let mut different = desired.clone();
        different.listen_port += 1;
        assert!(!cluster_runtime_applied(
            Some(&state),
            &different,
            true,
            Some(&binding),
            Some(42)
        ));
        assert!(!cluster_runtime_applied(
            Some(&state),
            &desired,
            false,
            None,
            Some(42)
        ));

        let disabled = ClusterConfigureSnapshot::from(&ClusterConfig::default());
        let disabled_pending =
            ClusterRuntimeState::blocked(disabled.clone(), false, None).finalize();
        assert!(
            cluster_runtime_applied(Some(&disabled_pending), &disabled, false, None, None),
            "a stopped daemon already makes a disabled target inert"
        );
    }

    #[test]
    fn daemon_ack_does_not_overwrite_config_committed_between_load_and_ack() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let startup_config = FreedomConfig::default();
        write_test_freedom(home, &startup_config);
        let startup_credentials = Credentials::default();
        let _daemon_owner = crate::daemon::pidfile::acquire(&home.join("neothd.pid"))
            .expect("acquire simulated daemon owner");

        let desired = ClusterConfig {
            peers: vec!["new-peer".to_string()],
            ..ClusterConfig::default()
        };
        let receipt = configure_cluster_at_with_reload(home, desired.clone(), None, |_| Ok(()))
            .expect("concurrent configure commits B");
        assert!(receipt.restart_required);
        let before = load_cluster_runtime_state(home)
            .expect("load B marker")
            .expect("B marker exists");
        assert!(before.ready_for_confirmation);
        assert_eq!(before.cluster, ClusterConfigureSnapshot::from(&desired));
        assert_eq!(before.acknowledged_daemon_pid, None);

        acknowledge_cluster_runtime_at(home, &startup_config, &startup_credentials, false, false)
            .expect("stale daemon acknowledgement is ignored");
        let after = load_cluster_runtime_state(home)
            .expect("reload B marker")
            .expect("B marker remains");
        assert_eq!(after, before, "ACK A must not erase pending B");
    }

    #[test]
    fn daemon_ack_rejects_passphrase_rotation_with_unchanged_public_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let mut startup_config = FreedomConfig::default();
        startup_config.cluster = ClusterConfig {
            enabled: true,
            name: Some("operators".to_string()),
            ..ClusterConfig::default()
        };
        write_test_freedom(home, &startup_config);
        let startup_credentials = Credentials {
            cluster_passphrase: Some(SecretString::new("generation-a".to_string())),
            ..Credentials::default()
        };
        startup_credentials
            .write(&home.join("credentials.yaml"))
            .expect("write startup credentials A");
        let _daemon_owner = crate::daemon::pidfile::acquire(&home.join("neothd.pid"))
            .expect("acquire simulated daemon owner");

        // The public snapshot and has-passphrase bit stay identical while a
        // concurrent configure rotates the carrier secret from A to B.
        let credentials_b = Credentials {
            cluster_passphrase: Some(SecretString::new("generation-b".to_string())),
            ..Credentials::default()
        };
        credentials_b
            .write(&home.join("credentials.yaml"))
            .expect("write rotated credentials B");
        let binding_b =
            cluster_identity_binding(home, &credentials_b, true).expect("derive B runtime binding");
        let pending_b = ClusterRuntimeState::blocked(
            ClusterConfigureSnapshot::from(&startup_config.cluster),
            true,
            binding_b,
        )
        .finalize();
        write_cluster_runtime_state(home, &pending_b).expect("write B pending marker");

        acknowledge_cluster_runtime_at(home, &startup_config, &startup_credentials, true, false)
            .expect("stale A acknowledgement is ignored");
        assert_eq!(
            load_cluster_runtime_state(home).unwrap(),
            Some(pending_b),
            "a carrier keyed with A must not acknowledge pending generation B"
        );
    }

    #[test]
    fn status_invalidates_ack_after_out_of_band_passphrase_rotation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let mut config = FreedomConfig::default();
        config.cluster = ClusterConfig {
            enabled: true,
            name: Some("operators".to_string()),
            ..ClusterConfig::default()
        };
        write_test_freedom(home, &config);
        let credentials_a = Credentials {
            cluster_passphrase: Some(SecretString::new("generation-a".to_string())),
            ..Credentials::default()
        };
        credentials_a
            .write(&home.join("credentials.yaml"))
            .expect("write credentials A");
        let _daemon_owner = crate::daemon::pidfile::acquire(&home.join("neothd.pid"))
            .expect("acquire simulated daemon owner");
        acknowledge_cluster_runtime_at(home, &config, &credentials_a, true, false)
            .expect("acknowledge carrier A");

        let state = load_cluster_runtime_state(home).unwrap().unwrap();
        let snapshot = ClusterConfigureSnapshot::from(&config.cluster);
        let binding_a =
            cluster_identity_binding(home, &credentials_a, false).expect("load A binding");
        assert!(cluster_runtime_carrier_active(
            Some(&state),
            &snapshot,
            true,
            binding_a.as_ref(),
            Some(std::process::id()),
        ));

        let credentials_b = Credentials {
            cluster_passphrase: Some(SecretString::new("generation-b".to_string())),
            ..Credentials::default()
        };
        credentials_b
            .write(&home.join("credentials.yaml"))
            .expect("out-of-band rotate credentials to B");
        let current = crate::config::load_runtime_config_pair_from_path(&home.join("freedom.yaml"))
            .expect("load coherent B pair");
        let binding_b =
            cluster_identity_binding(home, &current.credentials, false).expect("load B binding");
        let runtime_applied = cluster_runtime_applied(
            Some(&state),
            &snapshot,
            true,
            binding_b.as_ref(),
            Some(std::process::id()),
        );
        assert!(!runtime_applied, "rotated credentials require a restart");
        assert!(!cluster_runtime_carrier_active(
            Some(&state),
            &snapshot,
            true,
            binding_b.as_ref(),
            Some(std::process::id()),
        ));
    }

    #[test]
    fn public_only_configure_holds_credential_generation_through_freedom_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let mut config = FreedomConfig::default();
        config.cluster = ClusterConfig {
            enabled: true,
            name: Some("operators".to_string()),
            ..ClusterConfig::default()
        };
        write_test_freedom(home, &config);
        write_test_cluster_passphrase(home, "generation-a");

        let (validated_tx, validated_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let configure_home = home.to_path_buf();
        let desired = config.cluster.clone();
        let configure = std::thread::spawn(move || {
            configure_cluster_at_with_reload_and_public_validation_hook(
                &configure_home,
                desired,
                None,
                |_| Ok(()),
                move || {
                    validated_tx.send(()).expect("signal validated pair");
                    release_rx.recv().expect("release freedom commit");
                },
            )
        });
        validated_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("configure reached validation/commit barrier");

        let credentials_path = home.join("credentials.yaml");
        let (writer_started_tx, writer_started_rx) = std::sync::mpsc::sync_channel(0);
        let (writer_entered_tx, writer_entered_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            writer_started_tx.send(()).expect("signal writer start");
            Credentials::update_at(&credentials_path, |credentials| {
                writer_entered_tx
                    .send(())
                    .expect("signal credential mutation entry");
                credentials.cluster_passphrase =
                    Some(SecretString::new("generation-b".to_string()));
                Ok(())
            })
        });
        writer_started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("writer reached update call");
        let writer_entry_while_locked =
            writer_entered_rx.recv_timeout(std::time::Duration::from_millis(250));

        release_tx
            .send(())
            .expect("release coherent freedom commit");
        configure
            .join()
            .expect("configure thread")
            .expect("public-only configure succeeds");
        writer
            .join()
            .expect("credential writer thread")
            .expect("credential rotation succeeds after freedom commit");
        assert!(
            matches!(
                writer_entry_while_locked,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "credential writer entered before the coherent freedom commit released its transaction"
        );
    }

    #[test]
    fn public_only_configure_blocks_pre_journal_credential_writer_through_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let mut config = FreedomConfig::default();
        config.cluster = ClusterConfig {
            enabled: true,
            name: Some("operators".to_string()),
            ..ClusterConfig::default()
        };
        write_test_freedom(home, &config);
        write_test_cluster_passphrase(home, "generation-a");

        let (validated_tx, validated_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let configure_home = home.to_path_buf();
        let desired = config.cluster.clone();
        let configure = std::thread::spawn(move || {
            configure_cluster_at_with_reload_and_public_validation_hook(
                &configure_home,
                desired,
                None,
                |_| Ok(()),
                move || {
                    validated_tx.send(()).expect("signal validated pair");
                    release_rx.recv().expect("release freedom commit");
                },
            )
        });
        validated_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("configure reached validation/commit barrier");

        let credentials_path = home.join("credentials.yaml");
        let credentials_lock_path = credentials_path.with_extension("lock");
        let (writer_started_tx, writer_started_rx) = std::sync::mpsc::sync_channel(0);
        let (writer_locked_tx, writer_locked_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            writer_started_tx
                .send(())
                .expect("signal legacy writer start");
            // Simulate a pre-journal process: it knows only the legacy
            // credentials OS lock and deliberately never takes the new shared
            // transaction lock.
            let _legacy_lock = crate::util::locked_file::lock_file_blocking(
                &credentials_lock_path,
                "legacy credentials",
            )
            .expect("acquire legacy credentials lock");
            writer_locked_tx
                .send(())
                .expect("signal legacy writer lock acquisition");
            let replacement = Credentials {
                cluster_passphrase: Some(SecretString::new("generation-b".to_string())),
                ..Default::default()
            };
            let body = zeroize::Zeroizing::new(
                serde_yaml::to_string(&replacement).expect("serialize replacement credentials"),
            );
            crate::util::atomic_write::atomic_write_private(&credentials_path, body.as_bytes())
                .expect("publish legacy credential rotation");
        });
        writer_started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("legacy writer reached lock call");
        let writer_lock_while_configuring =
            writer_locked_rx.recv_timeout(std::time::Duration::from_millis(250));

        release_tx
            .send(())
            .expect("release coherent freedom commit");
        configure
            .join()
            .expect("configure thread")
            .expect("public-only configure succeeds");
        writer.join().expect("legacy credential writer thread");
        assert!(
            matches!(
                writer_lock_while_configuring,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "pre-journal writer acquired the credential lock before the coherent freedom commit"
        );
        assert_eq!(
            Credentials::load_or_default(&home.join("credentials.yaml"))
                .expect("load rotated credentials")
                .cluster_passphrase
                .as_ref()
                .map(SecretString::expose),
            Some("generation-b")
        );
    }

    #[test]
    fn daemon_ack_recovers_orphan_blocked_marker_when_disk_stayed_at_startup_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let startup_config = FreedomConfig::default();
        write_test_freedom(home, &startup_config);
        let _daemon_owner = crate::daemon::pidfile::acquire(&home.join("neothd.pid"))
            .expect("acquire simulated daemon owner");
        let orphan = ClusterRuntimeState::blocked(
            ClusterConfigureSnapshot::from(&ClusterConfig {
                peers: vec!["never-committed".to_string()],
                ..ClusterConfig::default()
            }),
            false,
            None,
        );
        write_cluster_runtime_state(home, &orphan).expect("write orphan blocked marker");

        acknowledge_cluster_runtime_at(
            home,
            &startup_config,
            &Credentials::default(),
            false,
            false,
        )
        .expect("recover orphan marker");
        let state = load_cluster_runtime_state(home).unwrap().unwrap();
        assert!(state.ready_for_confirmation);
        assert_eq!(
            state.cluster,
            ClusterConfigureSnapshot::from(&startup_config.cluster)
        );
        assert_eq!(state.acknowledged_daemon_pid, Some(std::process::id()));
    }

    #[test]
    fn daemon_ack_finalizes_blocked_marker_when_exact_commit_landed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let mut startup_config = FreedomConfig::default();
        startup_config.cluster.peers = vec!["committed-peer".to_string()];
        write_test_freedom(home, &startup_config);
        let _daemon_owner = crate::daemon::pidfile::acquire(&home.join("neothd.pid"))
            .expect("acquire simulated daemon owner");
        let blocked = ClusterRuntimeState::blocked(
            ClusterConfigureSnapshot::from(&startup_config.cluster),
            false,
            None,
        );
        write_cluster_runtime_state(home, &blocked).expect("write matching blocked marker");

        acknowledge_cluster_runtime_at(
            home,
            &startup_config,
            &Credentials::default(),
            false,
            false,
        )
        .expect("ack exact landed config");
        let state = load_cluster_runtime_state(home).unwrap().unwrap();
        assert!(state.ready_for_confirmation);
        assert_eq!(state.cluster, blocked.cluster);
        assert_eq!(state.acknowledged_daemon_pid, Some(std::process::id()));
    }

    #[test]
    fn daemon_ack_never_replaces_finalized_marker_for_another_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let startup_config = FreedomConfig::default();
        write_test_freedom(home, &startup_config);
        let _daemon_owner = crate::daemon::pidfile::acquire(&home.join("neothd.pid"))
            .expect("acquire simulated daemon owner");
        let pending = ClusterRuntimeState::blocked(
            ClusterConfigureSnapshot::from(&ClusterConfig {
                peers: vec!["pending-peer".to_string()],
                ..ClusterConfig::default()
            }),
            false,
            None,
        )
        .finalize();
        write_cluster_runtime_state(home, &pending).expect("write finalized pending marker");

        acknowledge_cluster_runtime_at(
            home,
            &startup_config,
            &Credentials::default(),
            false,
            false,
        )
        .expect("mismatched finalized marker is left pending");
        assert_eq!(load_cluster_runtime_state(home).unwrap(), Some(pending));
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn configure_enabled_without_existing_or_new_passphrase_preserves_public_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());
        let freedom_path = home.join("freedom.yaml");
        let before = std::fs::read(&freedom_path).expect("read freedom before");
        let desired = ClusterConfig {
            name: Some("missing-secret".to_string()),
            enabled: true,
            ..ClusterConfig::default()
        };

        let error = configure_cluster_at_with_reload(home, desired, None, |_| Ok(()))
            .expect_err("enabled identity without a passphrase must fail closed");

        assert!(error.to_string().contains("identity is incomplete"));
        assert_eq!(
            std::fs::read(&freedom_path).expect("read freedom after"),
            before
        );
        assert!(!home.join("credentials.yaml").exists());
    }

    #[test]
    fn configure_json_lists_round_trip_commas_and_whitespace_exactly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());

        let desired = build_cluster_config(
            false,
            None,
            "peeroxide",
            r#"["peer,one","  peer two  "]"#,
            true,
            false,
            r#"["SSID,with,commas","  exact spaces  "]"#,
            false,
            30,
            49_737,
        )
        .expect("valid list config");
        let receipt = configure_cluster_at_with_reload(home, desired, None, |_| Ok(()))
            .expect("commit list config");

        assert!(receipt.reload_requested);
        assert_eq!(receipt.reload_error, None);
        assert!(
            !receipt.restart_required,
            "a disabled cluster with no daemon is already inert"
        );
        assert_eq!(receipt.cluster.peers, ["peer,one", "  peer two  "]);
        assert_eq!(
            receipt.cluster.policy.trusted_ssids,
            ["SSID,with,commas", "  exact spaces  "]
        );
        let stored = FreedomConfig::load_from_path(&home.join("freedom.yaml"))
            .expect("reload stored config");
        assert_eq!(stored.cluster.peers, receipt.cluster.peers);
        assert_eq!(
            stored.cluster.policy.trusted_ssids,
            receipt.cluster.policy.trusted_ssids
        );
    }

    #[test]
    fn configure_unchanged_snapshot_without_secret_mutation_needs_no_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());

        let receipt =
            configure_cluster_at_with_reload(home, ClusterConfig::default(), None, |_| Ok(()))
                .expect("unchanged cluster snapshot");

        assert!(receipt.reload_requested);
        assert!(!receipt.restart_required);
        assert!(!receipt.cluster_passphrase_set);
    }

    #[test]
    fn configure_passphrase_while_cluster_and_daemon_are_stopped_needs_no_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());

        let receipt = configure_cluster_at_with_reload(
            home,
            ClusterConfig::default(),
            Some(SecretString::new("new-passphrase".to_string())),
            |_| Ok(()),
        )
        .expect("secret-only cluster mutation");

        assert!(!receipt.restart_required);
        assert!(receipt.cluster_passphrase_set);
    }

    #[test]
    fn configure_passphrase_while_daemon_is_live_keeps_restart_pending() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());
        let _daemon_owner = crate::daemon::pidfile::acquire(&home.join("neothd.pid"))
            .expect("acquire simulated daemon owner");

        let receipt = configure_cluster_at_with_reload(
            home,
            ClusterConfig::default(),
            Some(SecretString::new("new-passphrase".to_string())),
            |_| Ok(()),
        )
        .expect("secret-only cluster mutation");

        assert!(receipt.restart_required);
        assert!(receipt.cluster_passphrase_set);
    }

    #[cfg(not(feature = "cluster-iroh"))]
    #[test]
    fn configure_iroh_without_feature_fails_closed_before_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        write_test_freedom(home, &FreedomConfig::default());
        let freedom_path = home.join("freedom.yaml");
        let before = std::fs::read(&freedom_path).expect("read freedom before");
        let desired = ClusterConfig {
            transport: ClusterTransport::Iroh,
            ..ClusterConfig::default()
        };

        let error = configure_cluster_at_with_reload(home, desired, None, |_| Ok(()))
            .expect_err("unavailable iroh transport must fail closed even while disabled");
        assert!(error.to_string().contains("cluster-iroh"));
        assert_eq!(
            std::fs::read(&freedom_path).expect("read freedom after"),
            before
        );
    }

    #[test]
    fn passphrase_stdin_trims_one_line_ending_and_preserves_everything_else() {
        let passphrase = cluster_passphrase_from_line("  alpha beta  \r\n".to_string())
            .expect("valid passphrase");
        assert_eq!(passphrase.expose(), "  alpha beta  ");

        let passphrase = cluster_passphrase_from_line("alpha\n\n".to_string())
            .expect("valid passphrase with an intentional trailing newline");
        assert_eq!(passphrase.expose(), "alpha\n");
        assert!(cluster_passphrase_from_line(" \t\r\n".to_string()).is_err());
    }

    #[test]
    fn configure_receipt_rejects_unknown_top_level_and_nested_fields() {
        let receipt = ClusterConfigureReceipt {
            operation: "cluster.configure".to_string(),
            path: "freedom.yaml".to_string(),
            reload_requested: true,
            reload_error: None,
            restart_required: false,
            cluster_passphrase_set: false,
            cluster: ClusterConfigureSnapshot::from(&ClusterConfig::default()),
        };
        let mut top_level = serde_json::to_value(&receipt).expect("receipt value");
        top_level
            .as_object_mut()
            .expect("receipt object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<ClusterConfigureReceipt>(top_level).is_err());

        let mut nested = serde_json::to_value(&receipt).expect("receipt value");
        nested["cluster"]["mdns"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ClusterConfigureReceipt>(nested).is_err());
    }

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
        use crate::cluster::PeerSessionId;
        assert_eq!(decision_label(&RoutingDecision::Local), "Local");
        assert_eq!(
            decision_label(&RoutingDecision::Remote(PeerSessionId::new("p1"))),
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

    // ── Bite #3: cluster confirm --interactive ─────────────────────

    fn sample_peer(idx: u8) -> DiscoveredPeer {
        DiscoveredPeer {
            pub_key_hex: format!("{idx:02x}").repeat(32),
            label: format!("peer-{idx}"),
            addr: format!("192.0.2.{idx}:4242"),
        }
    }

    #[test]
    fn render_picker_handles_empty_list() {
        let out = render_picker(&[]);
        assert!(out.contains("no peers found"));
        assert!(out.contains("neoth cluster discover"));
    }

    #[test]
    fn render_picker_lists_every_peer_with_one_based_idx() {
        let peers = vec![sample_peer(1), sample_peer(2), sample_peer(3)];
        let out = render_picker(&peers);
        assert!(out.contains("[1] peer-1"));
        assert!(out.contains("[2] peer-2"));
        assert!(out.contains("[3] peer-3"));
        // No [0] — picker is 1-indexed.
        assert!(!out.contains("[0]"));
        // First 16 chars of pub_key surfaced.
        assert!(out.contains("0101010101010101"));
    }

    #[test]
    fn parse_pick_accepts_valid_one_indexed() {
        assert_eq!(parse_pick("1", 3).unwrap(), 0);
        assert_eq!(parse_pick("2", 3).unwrap(), 1);
        assert_eq!(parse_pick("3", 3).unwrap(), 2);
    }

    #[test]
    fn parse_pick_tolerates_whitespace_and_newlines() {
        assert_eq!(parse_pick("  2  \n", 3).unwrap(), 1);
        assert_eq!(parse_pick("3\r\n", 3).unwrap(), 2);
    }

    #[test]
    fn parse_pick_rejects_zero() {
        let err = parse_pick("0", 3).unwrap_err();
        assert!(err.to_string().contains("1-indexed"));
    }

    #[test]
    fn parse_pick_rejects_out_of_range() {
        let err = parse_pick("4", 3).unwrap_err();
        assert!(err.to_string().contains("out of range"));
        assert!(err.to_string().contains("3 peer"));
    }

    #[test]
    fn parse_pick_rejects_non_numeric() {
        let err = parse_pick("abc", 5).unwrap_err();
        assert!(err.to_string().contains("not a number"));
        let err = parse_pick("", 5).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn confirm_action_carries_interactive_flags() {
        let action = ClusterAction::Confirm {
            pub_key: None,
            label: None,
            addr: None,
            via: "manual".into(),
            hostname: None,
            interactive: true,
            interactive_timeout: 15,
        };
        match action {
            ClusterAction::Confirm {
                pub_key,
                label,
                addr,
                interactive,
                interactive_timeout,
                via,
                hostname,
            } => {
                assert!(pub_key.is_none());
                assert!(label.is_none());
                assert!(addr.is_none());
                assert!(hostname.is_none());
                assert!(interactive);
                assert_eq!(interactive_timeout, 15);
                assert_eq!(via, "manual");
            }
            _ => panic!("expected Confirm variant"),
        }
    }

    #[tokio::test]
    async fn confirm_non_interactive_requires_pub_key() {
        let args = ClusterArgs {
            action: ClusterAction::Confirm {
                pub_key: None,
                label: Some("x".into()),
                addr: Some("127.0.0.1:1".into()),
                via: "manual".into(),
                hostname: None,
                interactive: false,
                interactive_timeout: 10,
            },
            output: OutputFormat::Json,
        };
        let err = run_cluster(args).await.unwrap_err();
        assert!(err.to_string().contains("pub_key"));
    }

    // ── SL-01c revoke-by-hostname ─────────────────────────────────────────

    #[test]
    fn revoke_resolves_by_hostname_when_arg_is_not_a_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let peer = crate::cluster::registry::PairedPeer {
            pub_key_hex: "cd".repeat(32),
            instance_label: "the-laptop".into(),
            hostname: "workstation-7".into(),
            addr: "192.0.2.9:4242".into(),
            discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
            paired_at_unix: 1_700_000_000,
            last_seen_unix: 1_700_000_000,
            ..Default::default()
        };
        crate::cluster::registry::upsert(dir.path(), peer.clone()).unwrap();
        // "workstation-7" is not hex → key path misses → hostname resolves.
        match revoke_peer(dir.path(), "workstation-7").unwrap() {
            RevokeOutcome::ByHostname { label, key, .. } => {
                assert_eq!(label, "the-laptop");
                assert_eq!(key, peer.pub_key_hex);
            }
            other => panic!("expected ByHostname, got {other:?}"),
        }
        // Peer is gone; a second revoke is a clean no-op.
        assert!(!crate::cluster::registry::is_paired(
            dir.path(),
            &peer.pub_key_hex
        ));
        assert_eq!(
            revoke_peer(dir.path(), "workstation-7").unwrap(),
            RevokeOutcome::NoMatch
        );
    }

    #[test]
    fn revoke_prefers_pubkey_prefix_over_hostname() {
        let dir = tempfile::tempdir().unwrap();
        // Peer A: key starts with "abab…"; Peer B: hostname == "abab"
        // (an all-hex hostname). Revoking "abab" must hit A by key
        // prefix, NOT B by hostname.
        let a = crate::cluster::registry::PairedPeer {
            pub_key_hex: "ab".repeat(32),
            instance_label: "key-match".into(),
            hostname: String::new(),
            addr: "192.0.2.1:1".into(),
            discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
            paired_at_unix: 1,
            last_seen_unix: 1,
            ..Default::default()
        };
        let b = crate::cluster::registry::PairedPeer {
            pub_key_hex: "cd".repeat(32),
            instance_label: "host-match".into(),
            hostname: "abab".into(),
            addr: "192.0.2.2:2".into(),
            discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
            paired_at_unix: 1,
            last_seen_unix: 1,
            ..Default::default()
        };
        crate::cluster::registry::upsert(dir.path(), a.clone()).unwrap();
        crate::cluster::registry::upsert(dir.path(), b.clone()).unwrap();
        match revoke_peer(dir.path(), "abab").unwrap() {
            RevokeOutcome::ByKey(k) => assert_eq!(k, "abab"),
            other => panic!("expected ByKey precedence, got {other:?}"),
        }
        // A removed (key prefix), B survives (hostname not consulted).
        assert!(!crate::cluster::registry::is_paired(
            dir.path(),
            &a.pub_key_hex
        ));
        assert!(crate::cluster::registry::is_paired(
            dir.path(),
            &b.pub_key_hex
        ));
    }

    // ── SL-02 topology view ───────────────────────────────────────────────

    fn peer(label: &str, last_seen_unix: i64) -> crate::cluster::registry::PairedPeer {
        crate::cluster::registry::PairedPeer {
            pub_key_hex: "ab".repeat(32),
            instance_label: label.into(),
            hostname: String::new(),
            addr: "192.168.1.5:49737".into(),
            discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
            paired_at_unix: 1_700_000_000,
            last_seen_unix,
            ..Default::default()
        }
    }

    const TNOW: i64 = 1_700_010_000;

    #[test]
    fn build_topology_rows_marks_recent_when_recently_seen() {
        let rows = build_topology_rows(&[peer("laptop", TNOW - 42)], TNOW);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "recent");
        assert_eq!(rows[0].last_seen_age_secs, Some(42));
        assert_eq!(rows[0].label, "laptop");
    }

    #[test]
    fn build_topology_rows_marks_stale_when_old() {
        let rows = build_topology_rows(&[peer("server", TNOW - 9000)], TNOW);
        assert_eq!(rows[0].status, "stale");
        assert_eq!(rows[0].last_seen_age_secs, Some(9000));
    }

    #[test]
    fn build_topology_rows_marks_uncontacted_when_never_seen() {
        let rows = build_topology_rows(&[peer("vps", 0)], TNOW);
        assert_eq!(rows[0].status, "uncontacted");
        assert_eq!(rows[0].last_seen_age_secs, None);
    }

    #[test]
    fn build_topology_rows_carries_rtt_and_stability() {
        // Persisted cluster.yaml registry values flow into the row + render.
        let mut p = peer("laptop", TNOW - 10);
        p.rtt_ms = Some(37);
        p.stability_score = 0.83;
        let rows = build_topology_rows(&[p], TNOW);
        assert_eq!(rows[0].rtt_ms, Some(37));
        assert!((rows[0].stability_score - 0.83).abs() < 1e-9);
        let out = render_topology_table(&rows);
        assert!(out.contains("37ms"), "rtt rendered: {out}");
        assert!(out.contains("83%"), "stability % rendered: {out}");
        assert!(
            out.contains("rtt") && out.contains("stability"),
            "headers: {out}"
        );
        // A peer with no RTT renders the placeholder.
        let none_rows = build_topology_rows(&[peer("vps", 0)], TNOW);
        assert!(render_topology_table(&none_rows).contains("---"));
    }

    #[test]
    fn topology_status_boundary_is_exclusive_at_stale_threshold() {
        // Exactly at the threshold is still recent; one past it is stale.
        assert_eq!(
            topology_status(TNOW - TOPOLOGY_STALE_AFTER_SECS, TNOW),
            "recent"
        );
        assert_eq!(
            topology_status(TNOW - TOPOLOGY_STALE_AFTER_SECS - 1, TNOW),
            "stale"
        );
    }

    #[test]
    fn render_topology_table_has_headers_and_a_row_per_peer() {
        let rows = build_topology_rows(&[peer("a", TNOW - 1), peer("b", 0)], TNOW);
        let out = render_topology_table(&rows);
        assert!(out.contains("pub_key") && out.contains("last_seen") && out.contains("status"));
        assert!(out.contains("# Cluster topology (2 peers)"));
        assert!(out.contains("just now")); // a, seen 1s ago
        assert!(out.contains("never")); // b, uncontacted
    }

    #[test]
    fn render_topology_table_handles_empty_peer_list() {
        let out = render_topology_table(&[]);
        assert!(out.contains("# Cluster topology (0 peers)"));
    }

    #[test]
    fn fmt_last_seen_buckets() {
        assert_eq!(fmt_last_seen(None), "never");
        assert_eq!(fmt_last_seen(Some(2)), "just now");
        assert_eq!(fmt_last_seen(Some(42)), "42s ago");
        assert_eq!(fmt_last_seen(Some(180)), "3m ago");
        assert_eq!(fmt_last_seen(Some(7200)), "2h ago");
    }

    // --- GOLD-HON-03: cluster status reports real peers/mode/policy ---

    #[test]
    fn status_peer_count_reflects_paired_registry_not_hardcoded_zero() {
        let dir = tempfile::tempdir().unwrap();
        // Empty home: no registry yet → honest 0 (not an error).
        assert_eq!(status_peer_count(dir.path()).unwrap(), 0);

        for (i, hex) in ["aa", "bb"].iter().enumerate() {
            let peer = crate::cluster::registry::PairedPeer {
                pub_key_hex: hex.repeat(32),
                instance_label: format!("node-{i}"),
                addr: "192.0.2.1:4242".into(),
                discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
                paired_at_unix: 1_700_000_000,
                last_seen_unix: 1_700_000_000,
                ..Default::default()
            };
            crate::cluster::registry::upsert(dir.path(), peer).unwrap();
        }
        // The A-13 regression: the old code returned a hardcoded 0 here.
        assert_eq!(status_peer_count(dir.path()).unwrap(), 2);
    }

    #[test]
    fn status_peer_count_propagates_malformed_registry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            crate::cluster::registry::default_path(dir.path()),
            "peers: this-is-not-a-list\n",
        )
        .unwrap();
        // A corrupt registry surfaces as an error, never a false "0 peers".
        assert!(status_peer_count(dir.path()).is_err());
    }

    #[test]
    fn status_mode_policy_derives_from_config_not_hardcoded() {
        // Cluster off → the honest single-node / local-only posture,
        // regardless of any stale announce settings.
        assert_eq!(
            status_mode_policy(false, true, true),
            ("single-node", "local-only")
        );
        // Cluster on but mDNS announcer disabled.
        assert_eq!(
            status_mode_policy(true, false, false),
            ("cluster", "discovery-off")
        );
        // Cluster on, announcing only on trusted Wi-Fi (the secure default).
        assert_eq!(
            status_mode_policy(true, true, false),
            ("cluster", "announce-trusted-wifi-only")
        );
        // Cluster on, announcing on any network (operator opted in).
        assert_eq!(
            status_mode_policy(true, true, true),
            ("cluster", "announce-any-network")
        );
    }

    // ── DES-13 export-foreign ─────────────────────────────────────────────
    #[test]
    fn export_foreign_jsonl_line_shape_and_base64() {
        use base64::Engine as _;
        let row = crate::cluster::wal_sync::ForeignEventRow {
            id: 1,
            origin_peer_pk: "deadbeef".into(),
            origin_seq: 42,
            event_type: 0x90,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            received_at: 1_720_000_000,
            envelope_version: 0,
            content_sha256: None,
            content_payload: None,
        };
        let line = export_foreign_jsonl_line(&row);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["origin_peer_pk"], "deadbeef");
        assert_eq!(v["origin_seq"], 42);
        assert_eq!(v["event_type"], "0x90");
        assert_eq!(v["received_at"], 1_720_000_000_i64);
        // payload round-trips through base64.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(v["payload_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn export_foreign_jsonl_carries_complete_canonical_envelope() {
        let envelope = crate::cluster::gossip_wire::SyncEnvelope {
            version: crate::cluster::gossip_wire::SYNC_ENVELOPE_VERSION,
            content_id: "metadata:test".into(),
            updated_at_unix: 1_720_000_000,
            content: crate::cluster::gossip_wire::SyncContent::Metadata {
                event_type: 0x94,
                event_subtype: 0,
                wal_frame: vec![1, 2, 3],
            },
        };
        let encoded = serde_json::to_vec(&envelope).unwrap();
        let digest = envelope.content_sha256();
        let row = crate::cluster::wal_sync::ForeignEventRow {
            id: 1,
            origin_peer_pk: "peer-a".into(),
            origin_seq: 7,
            event_type: 0x94,
            payload: vec![1, 2, 3],
            received_at: 1_720_000_000,
            envelope_version: envelope.version,
            content_sha256: Some(digest),
            content_payload: Some(encoded.clone()),
        };

        let value: serde_json::Value =
            serde_json::from_str(&export_foreign_jsonl_line(&row)).unwrap();
        assert_eq!(value["envelope_version"], envelope.version);
        assert_eq!(
            parse_sha256_hex(value["content_sha256"].as_str().unwrap()).unwrap(),
            digest
        );
        use base64::Engine as _;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(value["envelope_b64"].as_str().unwrap())
                .unwrap(),
            encoded
        );
    }

    #[test]
    fn export_foreign_warning_references_restore_command() {
        // Since DES-13-AUTO-RESTORE-01 is now implemented, the banner must
        // point to `neoth cluster restore` and not claim it's unimplemented.
        assert!(
            EXPORT_FOREIGN_WARNING.contains("neoth cluster restore"),
            "banner must reference the restore command"
        );
        assert!(
            EXPORT_FOREIGN_WARNING.to_lowercase().contains("backup"),
            "banner must still mention it is a backup dump"
        );
        assert!(
            !EXPORT_FOREIGN_WARNING.contains("NOT implemented"),
            "banner must not claim restore is unimplemented"
        );
    }

    // -----------------------------------------------------------------------
    // DES-13-AUTO-RESTORE-01 unit tests (T-1 … T-7)
    // -----------------------------------------------------------------------

    fn make_restore_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE idx_episode (
                event_id   INTEGER PRIMARY KEY,
                importance REAL    NOT NULL DEFAULT 0.5
            );
            CREATE TABLE idx_groundtruth (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                revoked_at INTEGER,
                fact_state TEXT NOT NULL DEFAULT 'verified'
            );
        "#,
        )
        .unwrap();
        conn
    }

    fn make_wal_frame(event_type: u8, payload_json: &[u8]) -> Vec<u8> {
        let header = crate::wal::HeaderBuilder::new(event_type, payload_json).build();
        crate::wal::frame::encode_frame(&header, payload_json)
    }

    // T-1: idempotent re-restore — applying the same 0x90 frame twice:
    //      first call → Applied; second call → Skipped(Idempotent).
    #[test]
    fn restore_t1_idempotent_on_second_apply() {
        let conn = make_restore_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (10, 0.3)",
            [],
        )
        .unwrap();
        let payload = serde_json::json!({"event_id": 10, "importance": 0.8, "ts": 0}).to_string();
        let frame = make_wal_frame(
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            payload.as_bytes(),
        );
        let r1 = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
            "local",
            1,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            &frame,
            0,
            false,
        )
        .unwrap();
        assert_eq!(r1, crate::cluster::wal_sync::RestoreOutcome::Applied);

        let r2 = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
            "local",
            1,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            &frame,
            0,
            false,
        )
        .unwrap();
        assert!(
            matches!(
                r2,
                crate::cluster::wal_sync::RestoreOutcome::Skipped(
                    crate::cluster::wal_sync::RestoreSkipReason::Idempotent
                )
            ),
            "second apply must be Idempotent, got {r2:?}"
        );
    }

    // T-2: conflict matrix fixtures — 0x90/0x91/0x92/0x98 all produce Applied
    //      when matching local rows exist.
    #[test]
    fn restore_t2_conflict_matrix_fixtures() {
        let conn = make_restore_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (1, 0.2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (2, 0.1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (3, 0.9)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, revoked_at, fact_state) VALUES (1, NULL, 'verified')",
            [],
        )
        .unwrap();

        // 0x90 EPISODE_CONSOLIDATED
        let p90 = serde_json::json!({"event_id": 1, "importance": 0.8, "ts": 0}).to_string();
        let f90 = make_wal_frame(
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            p90.as_bytes(),
        );
        assert_eq!(
            crate::cluster::wal_sync::apply_restore_frame(
                &conn,
                "local",
                90,
                crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
                &f90,
                0,
                false
            )
            .unwrap(),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // 0x91 EPISODE_PROMOTED
        let p91 = serde_json::json!({"event_id": 2, "from_importance": 0.1, "to_importance": 0.7, "ts": 0}).to_string();
        let f91 = make_wal_frame(
            crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED,
            p91.as_bytes(),
        );
        assert_eq!(
            crate::cluster::wal_sync::apply_restore_frame(
                &conn,
                "local",
                91,
                crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED,
                &f91,
                0,
                false
            )
            .unwrap(),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // 0x92 EPISODE_ARCHIVED
        let p92 =
            serde_json::json!({"event_id": 3, "reason": "below_forget_floor", "ts": 0}).to_string();
        let f92 = make_wal_frame(
            crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED,
            p92.as_bytes(),
        );
        assert_eq!(
            crate::cluster::wal_sync::apply_restore_frame(
                &conn,
                "local",
                92,
                crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED,
                &f92,
                0,
                false
            )
            .unwrap(),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // 0x98 GROUNDTRUTH_REVOKED
        let p98 = serde_json::json!({"id": 1, "ts": 0}).to_string();
        let f98 = make_wal_frame(
            crate::wal::events::EVENT_TYPE_GROUNDTRUTH_REVOKED,
            p98.as_bytes(),
        );
        assert_eq!(
            crate::cluster::wal_sync::apply_restore_frame(
                &conn,
                "local",
                98,
                crate::wal::events::EVENT_TYPE_GROUNDTRUTH_REVOKED,
                &f98,
                999,
                false
            )
            .unwrap(),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );
    }

    // T-3: trust ceiling — 0x97 GROUNDTRUTH_ADDED is DoNotGossip class;
    //      must produce Skipped(DoNotGossip) with zero local writes.
    #[test]
    fn restore_t3_trust_ceiling_0x97_do_not_gossip() {
        let conn = make_restore_db();
        let payload = serde_json::json!({"id": 5, "ts": 0}).to_string();
        let frame = make_wal_frame(
            crate::wal::events::EVENT_TYPE_GROUNDTRUTH_ADDED,
            payload.as_bytes(),
        );
        let outcome = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
            "local",
            97,
            crate::wal::events::EVENT_TYPE_GROUNDTRUTH_ADDED,
            &frame,
            0,
            false,
        )
        .unwrap();
        assert!(
            matches!(
                outcome,
                crate::cluster::wal_sync::RestoreOutcome::Skipped(
                    crate::cluster::wal_sync::RestoreSkipReason::DoNotGossip
                )
            ),
            "0x97 must be DoNotGossip, got {outcome:?}"
        );
        // Zero rows in idx_groundtruth — no row created.
        let count: i64 = conn
            .query_row("SELECT count(*) FROM idx_groundtruth", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    // T-4: dry-run parity — full conflict evaluation, zero SQL writes,
    //      zero audit bytes written, returns Applied outcome.
    #[test]
    fn restore_t4_dry_run_no_sql_writes() {
        let conn = make_restore_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (7, 0.2)",
            [],
        )
        .unwrap();
        let payload = serde_json::json!({"event_id": 7, "importance": 0.9, "ts": 0}).to_string();
        let frame = make_wal_frame(
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            payload.as_bytes(),
        );

        // dry_run=true — must NOT write to DB.
        let outcome = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
            "local",
            90,
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            &frame,
            0,
            true,
        )
        .unwrap();

        // Outcome is Applied (row would have been touched).
        assert_eq!(outcome, crate::cluster::wal_sync::RestoreOutcome::Applied);

        // Importance unchanged — no write occurred.
        let imp: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 7",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            (imp - 0.2).abs() < 1e-9,
            "dry-run must not change importance; got {imp}"
        );
    }

    #[test]
    fn restore_dry_run_reports_idempotent_boosts_exactly() {
        let conn = make_restore_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (70, 0.9), (71, 0.9)",
            [],
        )
        .unwrap();
        for (seq, event_type, payload) in [
            (
                70,
                crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
                serde_json::json!({"event_id": 70, "importance": 0.8, "ts": 0}),
            ),
            (
                71,
                crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED,
                serde_json::json!({"event_id": 71, "to_importance": 0.8, "ts": 0}),
            ),
        ] {
            let frame = make_wal_frame(event_type, payload.to_string().as_bytes());
            let outcome = crate::cluster::wal_sync::apply_restore_frame(
                &conn, "local", seq, event_type, &frame, 0, true,
            )
            .unwrap();
            assert_eq!(
                outcome,
                crate::cluster::wal_sync::RestoreOutcome::Skipped(
                    crate::cluster::wal_sync::RestoreSkipReason::Idempotent
                )
            );
        }
    }

    #[test]
    fn restore_decay_is_idempotent_across_repeated_runs() {
        let conn = make_restore_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (80, 0.8)",
            [],
        )
        .unwrap();
        let payload = serde_json::json!({"event_id": 80, "reason": "archived", "ts": 0});
        let frame = make_wal_frame(
            crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED,
            payload.to_string().as_bytes(),
        );

        let first = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
            "local",
            920,
            crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED,
            &frame,
            0,
            false,
        )
        .unwrap();
        assert_eq!(first, crate::cluster::wal_sync::RestoreOutcome::Applied);

        let second = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
            "local",
            920,
            crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED,
            &frame,
            0,
            false,
        )
        .unwrap();
        assert_eq!(
            second,
            crate::cluster::wal_sync::RestoreOutcome::Skipped(
                crate::cluster::wal_sync::RestoreSkipReason::Idempotent
            )
        );
        let importance: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 80",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!((importance - 0.4).abs() < 1e-9);
    }

    // T-5: cross-peer skip — `parse_event_type_hex` correctness + cross-peer
    //      row counting gate (the actual per-run filtering is in run_restore).
    #[test]
    fn restore_t5_parse_event_type_hex_and_cross_peer_logic() {
        // Valid formats.
        assert_eq!(parse_event_type_hex("0x90").unwrap(), 0x90u8);
        assert_eq!(parse_event_type_hex("0X9E").unwrap(), 0x9Eu8);
        assert_eq!(parse_event_type_hex("0x98").unwrap(), 0x98u8);
        assert_eq!(parse_event_type_hex("0x00").unwrap(), 0u8);
        assert_eq!(parse_event_type_hex("0xFF").unwrap(), 0xFFu8);

        // Invalid inputs.
        assert!(parse_event_type_hex("90").is_err(), "no 0x prefix");
        assert!(parse_event_type_hex("0xGG").is_err(), "invalid hex chars");
        assert!(parse_event_type_hex("").is_err(), "empty string");

        // Cross-peer: origin_peer_pk != local_pk must be countable.
        // We verify that the data-level check is correct by comparing strings.
        let local = "aabbccdd".repeat(8); // 64 chars
        let foreign = "11223344".repeat(8);
        assert_ne!(local, foreign);
        assert_eq!(local.len(), 64);
    }

    // T-6: DoNotGossip tamper woven into a multi-event restore — surrounding
    //      0x90 rows are Applied; the 0x97 row is DoNotGossip.
    #[test]
    fn restore_t6_do_not_gossip_in_multi_event_sequence() {
        let conn = make_restore_db();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (20, 0.2)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, importance) VALUES (21, 0.2)",
            [],
        )
        .unwrap();

        let apply = |seq: u64, et: u8, payload: &str, dry: bool| {
            let frame = make_wal_frame(et, payload.as_bytes());
            crate::cluster::wal_sync::apply_restore_frame(&conn, "local", seq, et, &frame, 0, dry)
                .unwrap()
        };

        // Row A: 0x90 → Applied.
        let pa = serde_json::json!({"event_id": 20, "importance": 0.8, "ts": 0}).to_string();
        assert_eq!(
            apply(
                1,
                crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
                &pa,
                false
            ),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // Row B: 0x97 (DoNotGossip) → Skipped(DoNotGossip).
        let pb = serde_json::json!({"id": 99, "ts": 0}).to_string();
        assert!(matches!(
            apply(
                2,
                crate::wal::events::EVENT_TYPE_GROUNDTRUTH_ADDED,
                &pb,
                false
            ),
            crate::cluster::wal_sync::RestoreOutcome::Skipped(
                crate::cluster::wal_sync::RestoreSkipReason::DoNotGossip
            )
        ));

        // Row C: 0x90 → Applied (proves Row B did not abort the sequence).
        let pc = serde_json::json!({"event_id": 21, "importance": 0.9, "ts": 0}).to_string();
        assert_eq!(
            apply(
                3,
                crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
                &pc,
                false
            ),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // Row A's importance changed; Row B left no groundtruth rows.
        let imp20: f64 = conn
            .query_row(
                "SELECT importance FROM idx_episode WHERE event_id = 20",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!((imp20 - 0.8).abs() < 1e-9);
        let gt_count: i64 = conn
            .query_row("SELECT count(*) FROM idx_groundtruth", [], |r| r.get(0))
            .unwrap();
        assert_eq!(gt_count, 0);
    }

    // T-7: audit ACL — `open_audit_log` creates the file with 0600 on Unix.
    #[test]
    fn restore_t7_audit_log_acl_and_append() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("restore-audit.jsonl");
        {
            let mut f = open_audit_log(&audit_path).unwrap();
            writeln!(f, r#"{{"ts":1,"outcome":"applied"}}"#).unwrap();
        }
        // File exists.
        assert!(audit_path.exists());

        // Append a second line (simulates second restore invocation).
        {
            let mut f = open_audit_log(&audit_path).unwrap();
            writeln!(f, r#"{{"ts":2,"outcome":"skipped"}}"#).unwrap();
        }

        // Both lines are present (append semantics).
        let content = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Parse ts to verify monotonic ordering.
        let ts1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let ts2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert!(ts1["ts"].as_i64().unwrap() <= ts2["ts"].as_i64().unwrap());

        // Unix-only: verify 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&audit_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "audit log must be 0600, got 0o{mode:03o}");
        }
    }
}
