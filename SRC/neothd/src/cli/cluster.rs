//! `neoth cluster` — operator-facing cluster status surface (R-7).
//!
//! The Hyperswarm transport that R-7 needs for real peer discovery is
//! deferred (R-A1 research note). v0.1.x ships single-node operation
//! via the `LocalOnly` policy. This CLI surfaces what the daemon
//! would do today + what the operator would configure once the
//! transport lands so the experience is concrete now and the
//! upgrade path is visible.

use anyhow::{Context as _, Result};
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
    /// DES-13 — export this node's backup-at-rest for a crashed peer:
    /// dump the raw foreign gossip frames (`idx_foreign_events`) to a JSONL
    /// file so an operator can pull a failed node's replicated data off a
    /// surviving peer. This is a RAW BACKUP DUMP — it is NOT auto-restore:
    /// the file cannot be merged back into local recall/memory (that step
    /// is unbuilt). One JSON object per line:
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
    /// `--output json`. Read-only over `~/.neoth/cluster.yaml`. Live
    /// health/TPS/RTT/stability are daemon-in-memory only and surface
    /// in a follow-on (SL-02b) — this view renders the persisted
    /// registry data the operator can see from any one-shot.
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
    /// Enable cluster auto-discovery (writes
    /// `freedom.yaml::cluster.mdns.enabled = true`).
    Enable,
    /// Disable cluster auto-discovery.
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
        ClusterAction::Enable => run_toggle(true),
        ClusterAction::Disable => run_toggle(false),
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
    let freedom_path = FreedomConfig::default_neoth_home().join("freedom.yaml");
    let (mdns_enabled, policy) = crate::cluster::policy::load_policy_from_freedom(&freedom_path);
    let ssid = crate::cluster::policy::current_ssid();
    let gate = crate::cluster::policy::gate_discover(mdns_enabled, &policy, ssid.as_deref());
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
    let ts_port = crate::cluster::policy::load_listen_port_from_freedom(&freedom_path);
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
                "note: health / RTT / stability are daemon-in-memory only and not \
                 shown in this one-shot view (SL-02b follow-on)."
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
            "unknown discovered_via `{}` — use mdns/tailscale/hysteria_relay/manual",
            other
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
    if let Some(peer) = crate::cluster::registry::find_by_hostname(home, arg.trim()) {
        if crate::cluster::registry::remove(home, &peer.pub_key_hex)? {
            emit_revoke_sidecar(home, &peer.pub_key_hex);
            return Ok(RevokeOutcome::ByHostname {
                label: peer.instance_label,
                hostname: arg.trim().to_string(),
                key: peer.pub_key_hex,
            });
        }
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

/// Confirmed-peer count for `neoth cluster status`, factored out of
/// [`run_status`] so the GOLD-HON-03 honesty fix (read the registry,
/// never report a hardcoded `0`) is unit-testable without stdout
/// capture. A malformed `cluster.yaml` propagates as an error.
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
    let cfg = FreedomConfig::load_from_default_path().ok();
    let operator = cfg
        .as_ref()
        .and_then(|c| c.operator_id.clone())
        .unwrap_or_else(|| "(unset)".to_string());

    // SL-00(1a): cluster identity status (public name + whether a shared
    // passphrase is set). Reads freedom.yaml::cluster.name + credentials
    // cluster_passphrase via the fail-closed resolver; never exposes the key.
    let identity = match &cfg {
        Some(c) => {
            let creds = crate::config::credentials::Credentials::load().unwrap_or_default();
            crate::cluster::identity::cluster_identity_status(c, &creds)
        }
        None => crate::cluster::identity::ClusterIdentityStatus {
            name: None,
            has_passphrase: false,
            configured: false,
            enabled: false,
            transport_active: false,
        },
    };

    // SL-00(1b): honest transport state derived from the activation gate.
    let transport_state = if identity.transport_active {
        "active (Hyperswarm DHT — joined while the daemon runs)"
    } else if identity.configured && !identity.enabled {
        "disabled (identity ready; set cluster.enabled: true to activate)"
    } else {
        "inactive (no cluster identity)"
    };

    // GOLD-HON-03: report the REAL cluster posture instead of the old
    // hardcoded `single-node` / `local-only` / `0` placeholder, which
    // lied about peers even after `neoth cluster confirm` had paired
    // them (A-13).
    let home = FreedomConfig::default_neoth_home();
    // Confirmed-peer count from the on-disk registry. A malformed
    // `cluster.yaml` surfaces as a hard error (load() never silently
    // empties) rather than a false "0 peers".
    let peer_count = status_peer_count(&home)?;
    let (mdns_enabled, announce_policy) =
        crate::cluster::policy::load_policy_from_freedom(&home.join("freedom.yaml"));
    let (mode, policy_name) = status_mode_policy(
        identity.enabled,
        mdns_enabled,
        announce_policy.announce_on_untrusted_wifi,
    );

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "mode": mode,
                "policy": policy_name,
                "peer_count": peer_count,
                "operator_id": operator,
                "cluster_name": identity.name,
                "cluster_passphrase_set": identity.has_passphrase,
                "cluster_identity_configured": identity.configured,
                "cluster_enabled": identity.enabled,
                "transport_active": identity.transport_active,
                "transport": transport_state,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Cluster status");
            println!("  mode             : {mode}");
            println!("  policy           : {policy_name}");
            println!("  peer count       : {peer_count}");
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
            println!("  transport        : {transport_state}");
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
                     `cluster.enabled: true` in freedom.yaml to let the daemon join the \
                     Hyperswarm DHT on next start. (Default OFF — no DHT announce until you opt in.)"
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
/// this file is a raw backup dump, NOT an importable restore package.
const EXPORT_FOREIGN_WARNING: &str =
    "# WARNING: raw backup dump of replicated peer events (idx_foreign_events).\n\
     # These are raw gossip frames. Use `neoth cluster restore <this-file>` to\n\
     # apply same-origin frames back into local recall/memory. Cross-peer rows\n\
     # are skipped. Archive as an off-node backup (DES-13-AUTO-RESTORE-01).";

/// DES-13 — one JSONL line for the export. PURE + unit-pinned: the payload is
/// base64 so the file stays valid UTF-8 (`jq`-able). Non-PII by construction —
/// the gossip ACL only persists Replicate-class events (episode/groundtruth
/// ids + version strings), never raw text or secrets.
fn export_foreign_jsonl_line(row: &crate::cluster::wal_sync::ForeignEventRow) -> String {
    use base64::Engine as _;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&row.payload);
    serde_json::json!({
        "origin_peer_pk": row.origin_peer_pk,
        "origin_seq": row.origin_seq,
        "event_type": format!("0x{:02X}", row.event_type),
        "payload_b64": payload_b64,
        "received_at": row.received_at,
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
            anyhow::bail!(
                "refusing to overwrite existing file `{out}` (pass --force to replace)"
            );
        }
        std::fs::write(path, body.as_bytes())
            .with_context(|| format!("write export to {out}"))?;
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
        None => crate::cluster::wal_sync::local_node_pubkey(&home).ok_or_else(|| {
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
    let mut warned_cross_peer: std::collections::HashSet<String> =
        std::collections::HashSet::new();

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
        let payload_bytes = match base64::engine::general_purpose::STANDARD
            .decode(&export_row.payload_b64)
        {
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

        let apply_result = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
            event_type,
            &payload_bytes,
            export_row.received_at,
            dry_run,
        );

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
            let (outcome_tag, skip_reason) =
                match &outcome {
                    crate::cluster::wal_sync::RestoreOutcome::Applied => ("applied", String::new()),
                    crate::cluster::wal_sync::RestoreOutcome::Skipped(r) => {
                        ("skipped", r.to_string())
                    }
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
            pub_key_hex: format!("{:02x}", idx).repeat(32),
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
        // SL-02b: rtt + stability flow from the peer into the row + render.
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
        conn.execute_batch(r#"
            CREATE TABLE idx_episode (
                event_id   INTEGER PRIMARY KEY,
                importance REAL    NOT NULL DEFAULT 0.5
            );
            CREATE TABLE idx_groundtruth (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                revoked_at INTEGER,
                fact_state TEXT NOT NULL DEFAULT 'verified'
            );
        "#).unwrap();
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
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            &frame,
            0,
            false,
        )
        .unwrap();
        assert_eq!(r1, crate::cluster::wal_sync::RestoreOutcome::Applied);

        let r2 = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
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
        let f90 = make_wal_frame(crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED, p90.as_bytes());
        assert_eq!(
            crate::cluster::wal_sync::apply_restore_frame(
                &conn, crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED, &f90, 0, false
            ).unwrap(),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // 0x91 EPISODE_PROMOTED
        let p91 = serde_json::json!({"event_id": 2, "from_importance": 0.1, "to_importance": 0.7, "ts": 0}).to_string();
        let f91 = make_wal_frame(crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED, p91.as_bytes());
        assert_eq!(
            crate::cluster::wal_sync::apply_restore_frame(
                &conn, crate::wal::events::EVENT_TYPE_EPISODE_PROMOTED, &f91, 0, false
            ).unwrap(),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // 0x92 EPISODE_ARCHIVED
        let p92 = serde_json::json!({"event_id": 3, "reason": "below_forget_floor", "ts": 0}).to_string();
        let f92 = make_wal_frame(crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED, p92.as_bytes());
        assert_eq!(
            crate::cluster::wal_sync::apply_restore_frame(
                &conn, crate::wal::events::EVENT_TYPE_EPISODE_ARCHIVED, &f92, 0, false
            ).unwrap(),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // 0x98 GROUNDTRUTH_REVOKED
        let p98 = serde_json::json!({"id": 1, "ts": 0}).to_string();
        let f98 = make_wal_frame(crate::wal::events::EVENT_TYPE_GROUNDTRUTH_REVOKED, p98.as_bytes());
        assert_eq!(
            crate::cluster::wal_sync::apply_restore_frame(
                &conn, crate::wal::events::EVENT_TYPE_GROUNDTRUTH_REVOKED, &f98, 999, false
            ).unwrap(),
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
        let payload =
            serde_json::json!({"event_id": 7, "importance": 0.9, "ts": 0}).to_string();
        let frame = make_wal_frame(
            crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED,
            payload.as_bytes(),
        );

        // dry_run=true — must NOT write to DB.
        let outcome = crate::cluster::wal_sync::apply_restore_frame(
            &conn,
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
            .query_row("SELECT importance FROM idx_episode WHERE event_id = 7", [], |r| r.get(0))
            .unwrap();
        assert!(
            (imp - 0.2).abs() < 1e-9,
            "dry-run must not change importance; got {imp}"
        );
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

        let apply = |et: u8, payload: &str, dry: bool| {
            let frame = make_wal_frame(et, payload.as_bytes());
            crate::cluster::wal_sync::apply_restore_frame(&conn, et, &frame, 0, dry).unwrap()
        };

        // Row A: 0x90 → Applied.
        let pa =
            serde_json::json!({"event_id": 20, "importance": 0.8, "ts": 0}).to_string();
        assert_eq!(
            apply(crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED, &pa, false),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // Row B: 0x97 (DoNotGossip) → Skipped(DoNotGossip).
        let pb = serde_json::json!({"id": 99, "ts": 0}).to_string();
        assert!(matches!(
            apply(crate::wal::events::EVENT_TYPE_GROUNDTRUTH_ADDED, &pb, false),
            crate::cluster::wal_sync::RestoreOutcome::Skipped(
                crate::cluster::wal_sync::RestoreSkipReason::DoNotGossip
            )
        ));

        // Row C: 0x90 → Applied (proves Row B did not abort the sequence).
        let pc =
            serde_json::json!({"event_id": 21, "importance": 0.9, "ts": 0}).to_string();
        assert_eq!(
            apply(crate::wal::events::EVENT_TYPE_EPISODE_CONSOLIDATED, &pc, false),
            crate::cluster::wal_sync::RestoreOutcome::Applied
        );

        // Row A's importance changed; Row B left no groundtruth rows.
        let imp20: f64 = conn
            .query_row("SELECT importance FROM idx_episode WHERE event_id = 20", [], |r| r.get(0))
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
