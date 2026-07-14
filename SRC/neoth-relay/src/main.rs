//! `neoth-relay` — standalone Hysteria-shared peer registry daemon.
//!
//! Per architect verdict Session 21: separate binary from `neothd`,
//! not embedded, not a Hysteria fork. Single-responsibility, AIO-
//! compliant install path. Operators deploy on a cheap edge node
//! without pulling the full daemon stack.
//!
//! Hysteria is an external sidecar: it owns the public QUIC/TLS/auth listener
//! and forwards plain TCP to this process's loopback bind. `neoth-relay` never
//! embeds or spawns Hysteria.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;
use tracing::info;

mod hysteria;
mod relay;
mod serve;

use hysteria::{
    HealthCheckOutcome, HysteriaOnboardingPath, HysteriaTransportConfig, WHY_TUNNEL_COPY,
    check_relay_forward_target,
};

#[derive(Parser, Debug)]
#[command(
    name = "neoth-relay",
    version,
    about = "NEOTH relay daemon — Cluster Phase 5"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the relay daemon and serve its bounded HTTP/1.1 registry API.
    Serve {
        /// Listen address. Default loopback-only for safe local
        /// testing. A non-loopback bind (e.g. `0.0.0.0:8443`) is a
        /// PUBLIC deploy and REQUIRES an auth token (`--token` or the
        /// `NEOTH_RELAY_TOKEN` env var) — the relay refuses to start an
        /// unauthenticated public listener that anyone could use to
        /// write or delete cluster peers.
        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: String,
        /// Bearer token required on EVERY request
        /// (`Authorization: Bearer <token>`). Mandatory for any
        /// non-loopback bind. Prefer the `NEOTH_RELAY_TOKEN` env var —
        /// a token passed on the command line is visible to other
        /// users via the process list (`ps`).
        #[arg(long)]
        token: Option<String>,
        /// Peer cap per cluster_key. Default 5 (matches the
        /// architect-ratified `DEFAULT_MAX_PEERS_PER_KEY`); hard
        /// ceiling `MAX_PEERS_PER_KEY_CEILING` (50) enforced.
        #[arg(long, default_value_t = relay::DEFAULT_MAX_PEERS_PER_KEY)]
        max_peers_per_key: u32,
        /// Optional external-Hysteria deployment contract. When supplied,
        /// `forward_to` must exactly match this process's loopback `--bind`,
        /// and a non-empty sidecar auth scheme is mandatory. Mismatches abort
        /// startup before any socket is opened.
        #[arg(long)]
        hysteria_config: Option<PathBuf>,
    },
    /// Print version + build info without binding a socket. Useful
    /// for operators verifying the binary deployed correctly
    /// before opening firewall rules.
    Status {
        /// Optional Hysteria config (YAML) to include in the
        /// status report. Probes the relay's configured `forward_to` TCP target;
        /// this does not verify the sidecar's public QUIC/TLS/auth listener.
        #[arg(long)]
        hysteria_config: Option<PathBuf>,
    },
    /// Print the external-sidecar deployment choices and diagnose an optional
    /// Hysteria deployment contract.
    Doctor {
        /// Optional Hysteria config (YAML); when present, runs the
        /// relay-target health check. When absent, shows deployment guidance.
        #[arg(long)]
        hysteria_config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            bind,
            token,
            max_peers_per_key,
            hysteria_config,
        } => {
            if max_peers_per_key > relay::MAX_PEERS_PER_KEY_CEILING {
                anyhow::bail!(
                    "--max-peers-per-key {max_peers_per_key} exceeds ceiling {} \
                     (architect-pinned safety cap)",
                    relay::MAX_PEERS_PER_KEY_CEILING
                );
            }
            let addr: SocketAddr = bind
                .parse()
                .with_context(|| format!("parse --bind `{bind}`"))?;
            if let Some(path) = hysteria_config.as_ref() {
                let cfg = load_hysteria_config(path)?;
                cfg.validate_for_relay_bind(addr).with_context(|| {
                    format!(
                        "validate external Hysteria contract {} against --bind {addr}",
                        path.display()
                    )
                })?;
                info!(
                    hysteria = %cfg.summary(),
                    "external Hysteria contract accepted; sidecar owns public QUIC/auth, relay owns loopback TCP target"
                );
            }
            // Resolve the auth token: CLI flag first, then the
            // NEOTH_RELAY_TOKEN env var (preferred — not visible in `ps`).
            // Empty values are treated as "no token".
            let token = token
                .or_else(|| std::env::var("NEOTH_RELAY_TOKEN").ok())
                .filter(|t| !t.is_empty());
            // Fail closed: a public (non-loopback) bind without a token
            // would expose the cluster peer roster to anyone (GOLD-SEC-01).
            if serve::public_bind_requires_token(&addr, token.is_some()) {
                anyhow::bail!(
                    "refusing to bind public address {addr} without authentication — \
                     set --token <TOKEN> or NEOTH_RELAY_TOKEN. The relay manages \
                     cluster peer state; an unauthenticated public listener lets \
                     anyone register or delete peers."
                );
            }
            let roster: Arc<Mutex<relay::PeerRoster>> =
                Arc::new(Mutex::new(relay::PeerRoster::new(max_peers_per_key)));
            info!(
                bind = %addr,
                max_peers_per_key,
                auth = token.is_some(),
                "neoth-relay starting"
            );
            serve::serve(addr, roster, token.map(Arc::new)).await
        }
        Command::Status { hysteria_config } => {
            println!(
                "neoth-relay {} — Cluster Phase 5",
                env!("CARGO_PKG_VERSION")
            );
            println!("ready to bind via `neoth-relay serve --bind <addr>`");
            println!(
                "defaults: max_peers_per_key={} (ceiling {})",
                relay::DEFAULT_MAX_PEERS_PER_KEY,
                relay::MAX_PEERS_PER_KEY_CEILING,
            );
            if let Some(path) = hysteria_config {
                let cfg = load_hysteria_config(&path)?;
                println!("hysteria: {}", cfg.summary());
                for w in cfg.validate() {
                    println!("warning: {w}");
                }
                println!(
                    "transport-boundary: external Hysteria owns public QUIC/TLS/auth; neoth-relay owns forward_to TCP"
                );
                let outcome = check_relay_forward_target(&cfg).await;
                let detail = outcome.summary();
                println!("relay-target-health: {detail}");
                if !outcome.is_passable() {
                    anyhow::bail!("relay forward-target health check failed: {detail}");
                }
            }
            Ok(())
        }
        Command::Doctor { hysteria_config } => {
            println!("── Why tunnel? ──────────────────────────────────────");
            println!("{WHY_TUNNEL_COPY}");
            println!();
            println!("── Onboarding paths (HW-2) ─────────────────────────");
            for path in [
                HysteriaOnboardingPath::SelfHost,
                HysteriaOnboardingPath::BringExisting,
                HysteriaOnboardingPath::Skip,
            ] {
                println!("  ({}) {}", path.as_str(), path.description());
            }
            println!();
            if let Some(cfg_path) = hysteria_config {
                let cfg = load_hysteria_config(&cfg_path)?;
                println!("── Loaded Hysteria config ──────────────────────────");
                println!("{}", cfg.summary());
                for w in cfg.validate() {
                    println!("warning: {w}");
                }
                println!(
                    "boundary: this probes forward_to only; verify public QUIC/TLS/auth with Hysteria tooling"
                );
                let outcome = check_relay_forward_target(&cfg).await;
                println!();
                println!("── Relay forward-target health ─────────────────────");
                let label = match &outcome {
                    HealthCheckOutcome::Ok => "OK",
                    HealthCheckOutcome::NotConfigured => "SKIPPED (direct TCP mode)",
                    HealthCheckOutcome::MissingForwardTo
                    | HealthCheckOutcome::InvalidForwardTarget(_)
                    | HealthCheckOutcome::ConnectionRefused(_)
                    | HealthCheckOutcome::Timeout => "FAIL",
                };
                println!("status: {label}");
                let detail = outcome.summary();
                println!("detail: {detail}");
                if !outcome.is_passable() {
                    anyhow::bail!("relay forward-target health check failed: {detail}");
                }
            } else {
                println!("(no --hysteria-config supplied — running in informational mode)");
            }
            Ok(())
        }
    }
}

fn load_hysteria_config(path: &std::path::Path) -> Result<HysteriaTransportConfig> {
    let yaml = std::fs::read_to_string(path)
        .with_context(|| format!("read hysteria config {}", path.display()))?;
    let cfg: HysteriaTransportConfig = serde_yaml::from_str(&yaml)
        .with_context(|| format!("parse hysteria config {}", path.display()))?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_serve_defaults_bind_to_loopback_8443() {
        let cli = Cli::parse_from(["neoth-relay", "serve"]);
        match cli.command {
            Command::Serve {
                bind,
                token,
                max_peers_per_key,
                hysteria_config,
            } => {
                assert_eq!(bind, "127.0.0.1:8443");
                assert!(token.is_none());
                assert_eq!(max_peers_per_key, relay::DEFAULT_MAX_PEERS_PER_KEY);
                assert!(hysteria_config.is_none());
            }
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn cli_serve_honours_custom_bind_and_cap() {
        let cli = Cli::parse_from([
            "neoth-relay",
            "serve",
            "--bind",
            "0.0.0.0:9000",
            "--token",
            "s3cr3t",
            "--max-peers-per-key",
            "10",
        ]);
        match cli.command {
            Command::Serve {
                bind,
                token,
                max_peers_per_key,
                hysteria_config,
            } => {
                assert_eq!(bind, "0.0.0.0:9000");
                assert_eq!(token.as_deref(), Some("s3cr3t"));
                assert_eq!(max_peers_per_key, 10);
                assert!(hysteria_config.is_none());
            }
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn cli_serve_accepts_hysteria_config_flag() {
        let cli = Cli::parse_from([
            "neoth-relay",
            "serve",
            "--hysteria-config",
            "/etc/neoth/hysteria.yaml",
        ]);
        match cli.command {
            Command::Serve {
                hysteria_config, ..
            } => {
                assert_eq!(
                    hysteria_config.as_deref(),
                    Some(std::path::Path::new("/etc/neoth/hysteria.yaml")),
                );
            }
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn cli_status_command_parses() {
        let cli = Cli::parse_from(["neoth-relay", "status"]);
        assert!(matches!(cli.command, Command::Status { .. }));
    }

    #[test]
    fn cli_doctor_command_parses_with_optional_config() {
        let cli = Cli::parse_from(["neoth-relay", "doctor"]);
        match cli.command {
            Command::Doctor { hysteria_config } => assert!(hysteria_config.is_none()),
            _ => panic!("expected Doctor"),
        }
        let cli = Cli::parse_from(["neoth-relay", "doctor", "--hysteria-config", "/tmp/h.yaml"]);
        match cli.command {
            Command::Doctor { hysteria_config } => {
                assert!(hysteria_config.is_some());
            }
            _ => panic!("expected Doctor"),
        }
    }

    #[test]
    fn load_hysteria_config_round_trips_yaml() {
        // Pin the parser's wire contract against a representative
        // operator YAML — drift here would silently change the
        // doctor + status surfaces in subtle ways.
        let yaml =
            "listen: ':443'\nforward_to: '127.0.0.1:8443'\nauth_scheme: 'password'\nnote: 'op-x'\n";
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), yaml).unwrap();
        let cfg = load_hysteria_config(f.path()).unwrap();
        assert_eq!(cfg.listen, ":443");
        assert_eq!(cfg.forward_to, "127.0.0.1:8443");
        assert_eq!(cfg.auth_scheme, "password");
        assert_eq!(cfg.note, "op-x");
    }
}
