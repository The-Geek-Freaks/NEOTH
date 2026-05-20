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
    /// Print the active policy + known peer state. v0.1.x always
    /// reports `single-node` until Hyperswarm transport lands.
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
}

pub async fn run_cluster(args: ClusterArgs) -> Result<()> {
    match args.action {
        ClusterAction::Status => run_status(&args.output),
        ClusterAction::Plan { peers, policy } => run_plan(&peers, policy.as_deref(), &args.output),
    }
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
}
