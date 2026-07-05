//! Tailscale magic-DNS peer enumeration — Phase 3 of cluster
//! auto-discovery.
//!
//! Operator running Tailscale on their devices already has a
//! tailnet — the `tailscale` binary exposes the host list via
//! `tailscale status --json`. We shell to it, parse the JSON
//! envelope, and for each peer try the well-known NEOTH listen
//! port. The probe is a 200ms TCP connect — if it succeeds, the
//! peer is a candidate to be merged into the discovery feed.
//!
//! Why not mDNS over Tailscale: Tailscale's MagicDNS layer is
//! authoritative per-tailnet (no LAN multicast needed); we get
//! the peer list deterministically without spraying broadcasts.
//! Trade-off: the operator must have Tailscale CLI on PATH.
//! Missing binary is a soft fail — Phase 3 returns an empty
//! list and logs the reason at info level.

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;

/// Default NEOTH listen port the Phase 3 probe tries on every
/// Tailscale-reachable peer. Same default as the Phase 2 mDNS
/// announce port; operators who run a non-default port supply
/// the override via `freedom.yaml::cluster.listen_port` — wired
/// via [`super::policy::load_listen_port_from_freedom`].
pub const DEFAULT_NEOTH_LISTEN_PORT: u16 = 49737;

/// Default TCP-connect timeout for the Phase 3 probe. Tailscale's
/// magic-DNS resolves locally; the network hop to the peer is
/// typically <50ms even on slow links, so 500ms is the "broken"
/// threshold without padding for false negatives.
pub const PROBE_TIMEOUT_MS: u64 = 500;

/// Parsed shape of `tailscale status --json`. We only consume a
/// subset — the `Self.HostName` for the local instance + the
/// `Peer` map containing `HostName` + `TailscaleIPs` for every
/// other tailnet member. Unrecognised fields are ignored so a
/// Tailscale CLI upgrade doesn't break this.
#[derive(Debug, Deserialize)]
pub struct TailscaleStatus {
    #[serde(rename = "Self")]
    pub self_node: TailscaleSelf,
    #[serde(rename = "Peer", default)]
    pub peers: std::collections::HashMap<String, TailscalePeer>,
}

#[derive(Debug, Deserialize)]
pub struct TailscaleSelf {
    #[serde(rename = "HostName", default)]
    pub host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TailscalePeer {
    #[serde(rename = "HostName", default)]
    pub host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
    /// Tailscale exposes "Online" bool per peer — we use this to
    /// short-circuit the TCP probe (offline peers definitely
    /// won't answer; saves the timeout budget).
    #[serde(rename = "Online", default)]
    pub online: bool,
}

/// One candidate the Phase 3 enumeration surfaced. Caller decides
/// whether to probe the NEOTH port + whether to verify via
/// cluster_key HMAC (Phase 3 doesn't have an HMAC channel — the
/// Tailscale tailnet itself is the authentication boundary, so
/// we treat presence as "authenticated by Tailscale's WireGuard
/// crypto").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleCandidate {
    pub host_name: String,
    pub addr: SocketAddr,
    pub online: bool,
}

/// Shell out to `tailscale status --json`. Returns Ok(None) when
/// the binary is missing (soft fail — operator may not run
/// Tailscale), Err on JSON parse failure or non-zero exit.
pub async fn fetch_status() -> Result<Option<TailscaleStatus>> {
    let mut cmd = tokio::process::Command::new("tailscale");
    cmd.arg("status").arg("--json");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => anyhow::bail!("spawn tailscale: {e}"),
    };
    if !output.status.success() {
        anyhow::bail!(
            "tailscale status --json exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let body = String::from_utf8_lossy(&output.stdout);
    let status: TailscaleStatus = serde_json::from_str(&body)?;
    Ok(Some(status))
}

/// Filter a parsed status into candidate peers. Each peer gets one
/// candidate per Tailscale IP — typically a single 100.x.y.z address.
/// `port` is the NEOTH listen port to compose into the SocketAddr.
pub fn candidates_from_status(status: &TailscaleStatus, port: u16) -> Vec<TailscaleCandidate> {
    let mut out = Vec::new();
    for peer in status.peers.values() {
        for ip in &peer.tailscale_ips {
            if let Ok(parsed) = ip.parse::<std::net::IpAddr>() {
                out.push(TailscaleCandidate {
                    host_name: peer.host_name.clone(),
                    addr: SocketAddr::new(parsed, port),
                    online: peer.online,
                });
            }
        }
    }
    // Stable order by host_name + addr so `neoth cluster discover`
    // renders peers consistently across runs.
    out.sort_by(|a, b| a.host_name.cmp(&b.host_name).then(a.addr.cmp(&b.addr)));
    out
}

/// TCP-probe a single candidate. Returns true when the NEOTH
/// listen port answers within `PROBE_TIMEOUT_MS`. Phase 6
/// gossip-handshake replaces this with a real protocol probe.
pub async fn probe_candidate(addr: SocketAddr) -> bool {
    let connect = tokio::net::TcpStream::connect(addr);
    matches!(
        tokio::time::timeout(Duration::from_millis(PROBE_TIMEOUT_MS), connect).await,
        Ok(Ok(_))
    )
}

/// Map a probe task's join error to a reachability result.
///
/// COR-21: the old call site did `h.await.unwrap_or(false)`, which
/// silently swallowed BOTH a cancelled task and a *panicked* task as
/// "not reachable" — hiding any bug in `probe_candidate`. A cancelled
/// probe is genuinely "no answer" (false); a panic is surfaced as an
/// error so enumeration fails loudly instead of under-reporting peers.
fn probe_result(joined: std::result::Result<bool, tokio::task::JoinError>) -> Result<bool> {
    match joined {
        Ok(reachable) => Ok(reachable),
        Err(e) if e.is_cancelled() => Ok(false),
        Err(e) => Err(anyhow::anyhow!("tailscale probe task panicked: {e}")),
    }
}

/// Top-level enumeration: fetch status, build candidate list,
/// probe each one in parallel. Returns the candidates that
/// answered. Missing-binary returns empty list.
///
/// Uses `JoinSet` instead of `Vec<JoinHandle>` so all probe tasks are
/// aborted automatically if this future is cancelled mid-loop (e.g. a
/// SIGTERM arriving while probes are in flight). A bare `Vec<JoinHandle>`
/// would detach the already-spawned tasks on drop, leaving them running
/// and holding their TCP sockets until the runtime shuts down.
pub async fn enumerate(port: u16) -> Result<Vec<TailscaleCandidate>> {
    let Some(status) = fetch_status().await? else {
        return Ok(Vec::new());
    };
    let candidates = candidates_from_status(&status, port);
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    // Parallel probe — each probe owns its own timeout so the
    // whole batch can't drag past PROBE_TIMEOUT_MS * candidates.
    // JoinSet aborts all contained tasks on drop, providing automatic
    // cleanup if this future is cancelled between spawns.
    let mut set: tokio::task::JoinSet<(usize, bool)> = tokio::task::JoinSet::new();
    for (i, cand) in candidates.iter().enumerate() {
        let addr = cand.addr;
        set.spawn(async move { (i, probe_candidate(addr).await) });
    }
    let mut answered = Vec::new();
    while let Some(res) = set.join_next().await {
        match res {
            Ok((i, reachable)) => {
                if reachable {
                    answered.push(candidates[i].clone());
                }
            }
            // COR-21 semantics via probe_result: cancelled = "no answer",
            // panic = loud error instead of silently under-reporting peers.
            Err(e) => {
                let _ = probe_result(Err(e))?;
            }
        }
    }
    // Restore stable insertion order (JoinSet completes out-of-order).
    answered.sort_by(|a, b| a.host_name.cmp(&b.host_name).then(a.addr.cmp(&b.addr)));
    Ok(answered)
}

/// Tag returned by Phase 3 — pin the via field for caller convenience.
pub fn via() -> super::discovery::DiscoveryVia {
    super::discovery::DiscoveryVia::Tailscale
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_STATUS_JSON: &str = r#"{
        "Self": {
            "HostName": "laptop-alpha",
            "TailscaleIPs": ["100.64.0.1"]
        },
        "Peer": {
            "abc123": {
                "HostName": "home-server",
                "TailscaleIPs": ["100.64.0.2"],
                "Online": true
            },
            "def456": {
                "HostName": "tablet",
                "TailscaleIPs": ["100.64.0.3"],
                "Online": false
            }
        }
    }"#;

    #[test]
    fn parse_sample_status_extracts_self_and_peers() {
        let status: TailscaleStatus = serde_json::from_str(SAMPLE_STATUS_JSON).unwrap();
        assert_eq!(status.self_node.host_name, "laptop-alpha");
        assert_eq!(status.peers.len(), 2);
        let server = status.peers.get("abc123").unwrap();
        assert_eq!(server.host_name, "home-server");
        assert!(server.online);
        let tablet = status.peers.get("def456").unwrap();
        assert!(!tablet.online);
    }

    #[test]
    fn candidates_from_status_sorts_by_hostname() {
        let status: TailscaleStatus = serde_json::from_str(SAMPLE_STATUS_JSON).unwrap();
        let cands = candidates_from_status(&status, DEFAULT_NEOTH_LISTEN_PORT);
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[0].host_name, "home-server");
        assert_eq!(cands[1].host_name, "tablet");
        assert_eq!(cands[0].addr.port(), DEFAULT_NEOTH_LISTEN_PORT);
    }

    #[test]
    fn candidates_includes_offline_peers() {
        // Online flag is informational — caller decides whether
        // to skip offline peers; enumeration includes them.
        let status: TailscaleStatus = serde_json::from_str(SAMPLE_STATUS_JSON).unwrap();
        let cands = candidates_from_status(&status, 1234);
        let tablet = cands.iter().find(|c| c.host_name == "tablet").unwrap();
        assert!(!tablet.online);
    }

    #[test]
    fn candidates_handles_empty_peer_map() {
        let json = r#"{"Self":{"HostName":"x","TailscaleIPs":[]},"Peer":{}}"#;
        let status: TailscaleStatus = serde_json::from_str(json).unwrap();
        let cands = candidates_from_status(&status, 49737);
        assert!(cands.is_empty());
    }

    #[test]
    fn candidates_ignores_malformed_ip() {
        let json = r#"{
            "Self": {"HostName":"x","TailscaleIPs":[]},
            "Peer": {
                "p1": {"HostName":"good","TailscaleIPs":["100.64.0.5"],"Online":true},
                "p2": {"HostName":"broken","TailscaleIPs":["not-an-ip"],"Online":true}
            }
        }"#;
        let status: TailscaleStatus = serde_json::from_str(json).unwrap();
        let cands = candidates_from_status(&status, 49737);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].host_name, "good");
    }

    #[test]
    fn parse_tolerates_unknown_fields() {
        // Tailscale CLI upgrade adds new fields — we must not break.
        let json = r#"{
            "Self": {"HostName":"x","TailscaleIPs":["100.64.0.1"],"NewField":42},
            "Peer": {},
            "AnotherNewTopLevelField": "ignored"
        }"#;
        let status: TailscaleStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.self_node.host_name, "x");
    }

    #[test]
    fn default_constants_pinned() {
        // Operators reading scripts grep for these — pin so a
        // future drift surfaces here, not in production.
        assert_eq!(DEFAULT_NEOTH_LISTEN_PORT, 49737);
        assert_eq!(PROBE_TIMEOUT_MS, 500);
    }

    #[tokio::test]
    async fn probe_candidate_errors_quickly_on_dead_port() {
        // Use port 1 on localhost — should refuse connect
        // immediately, well within the 500ms budget.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let started = std::time::Instant::now();
        let answered = probe_candidate(addr).await;
        let elapsed = started.elapsed();
        assert!(!answered);
        // Probe must not hang past its own timeout.
        assert!(
            elapsed < Duration::from_millis(PROBE_TIMEOUT_MS * 2),
            "probe ran too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn via_returns_tailscale_tag() {
        assert_eq!(via(), super::super::discovery::DiscoveryVia::Tailscale);
    }

    #[tokio::test]
    async fn probe_result_maps_cancel_to_false_and_surfaces_panic() {
        // COR-21: a normal join passes the bool through; a cancelled probe is
        // "no answer" (false); a panicked probe surfaces as Err instead of
        // being silently swallowed as not-reachable (the old unwrap_or(false)).
        assert!(probe_result(Ok(true)).unwrap());
        assert!(!probe_result(Ok(false)).unwrap());

        let h: tokio::task::JoinHandle<bool> =
            tokio::spawn(async { panic!("intentional probe panic") });
        let joined = h.await;
        assert!(joined.as_ref().unwrap_err().is_panic());
        assert!(
            probe_result(joined).is_err(),
            "a panicked probe must surface as Err"
        );

        let h2: tokio::task::JoinHandle<bool> = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            true
        });
        h2.abort();
        let cancelled = h2.await;
        assert!(cancelled.as_ref().unwrap_err().is_cancelled());
        assert!(
            !probe_result(cancelled).unwrap(),
            "a cancelled probe maps to false"
        );
    }
}
