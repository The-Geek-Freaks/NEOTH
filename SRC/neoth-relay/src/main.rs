//! `neoth-relay` — standalone Hysteria-shared peer registry daemon.
//!
//! Per architect verdict Session 21: separate binary from `neothd`,
//! not embedded, not a Hysteria fork. Single-responsibility, AIO-
//! compliant install path. Operators deploy on a cheap edge node
//! without pulling the full daemon stack.
//!
//! v0.1 scope = minimal serve loop + in-memory `PeerRoster`. Cluster
//! Phase 5 wire (Hysteria socket plumbing + relay-to-relay mesh)
//! ships in multi-week follow-ups.

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
    check_hysteria_listener,
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
    /// Start the relay daemon. Binds to `--bind` + serves the
    /// register / unregister / status endpoints over a minimal
    /// HTTP-line framing (real axum integration follows in a
    /// later bite).
    Serve {
        /// Listen address. Default loopback-only for safe local
        /// testing; operators bind to a public IP via
        /// `--bind 0.0.0.0:8443`.
        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: String,
        /// Peer cap per cluster_key. Default 5 (matches the
        /// architect-ratified `DEFAULT_MAX_PEERS_PER_KEY`); hard
        /// ceiling `MAX_PEERS_PER_KEY_CEILING` (50) enforced.
        #[arg(long, default_value_t = relay::DEFAULT_MAX_PEERS_PER_KEY)]
        max_peers_per_key: u32,
        /// Optional path to the Hysteria sidecar config (YAML
        /// matching `HysteriaTransportConfig`). Loaded at startup +
        /// validated for operator-painful misconfigs; warnings
        /// surface in stdout but don't block the bind.
        #[arg(long)]
        hysteria_config: Option<PathBuf>,
    },
    /// Print version + build info without binding a socket. Useful
    /// for operators verifying the binary deployed correctly
    /// before opening firewall rules.
    Status {
        /// Optional Hysteria config (YAML) to include in the
        /// status report. Runs `validate()` + `check_hysteria_listener`
        /// (3s TCP probe) so operators see the live sidecar state
        /// without binding the relay socket.
        #[arg(long)]
        hysteria_config: Option<PathBuf>,
    },
    /// Operator walkthrough screens (HW-1..HW-4): print the
    /// "Why tunnel?" copy, the 3 onboarding paths + their
    /// descriptions, and run a health check against an optional
    /// Hysteria config. Used by the future GUI wizard and by
    /// operators running `neoth-relay doctor` to debug a sidecar.
    Doctor {
        /// Optional Hysteria config (YAML); when present, runs the
        /// HW-3 health check + reports the outcome. When absent,
        /// shows the onboarding paths + "Why tunnel?" copy only.
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
            if let Some(path) = hysteria_config.as_ref() {
                let cfg = load_hysteria_config(path)?;
                for w in cfg.validate() {
                    eprintln!("warning: {w}");
                }
                info!(hysteria = %cfg.summary(), "Hysteria sidecar metadata loaded");
            }
            let addr: SocketAddr = bind
                .parse()
                .with_context(|| format!("parse --bind `{bind}`"))?;
            let roster: Arc<Mutex<relay::PeerRoster>> =
                Arc::new(Mutex::new(relay::PeerRoster::new(max_peers_per_key)));
            info!(
                bind = %addr,
                max_peers_per_key,
                "neoth-relay starting"
            );
            serve::serve(addr, roster).await
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
                let outcome = check_hysteria_listener(&cfg).await;
                println!("health-check: {}", outcome.summary());
                if !outcome.is_passable() {
                    eprintln!(
                        "health-check failed — run `neoth-relay doctor --hysteria-config <path>` for details"
                    );
                }
                // Surface the bail-message contract from the v1 stub
                // so operators see the deferred-transport context.
                if let Err(e) = hysteria::connect_via_hysteria(&cfg) {
                    println!("transport: {e}");
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
                let outcome = check_hysteria_listener(&cfg).await;
                println!();
                println!("── Health check (HW-3) ─────────────────────────────");
                let label = match &outcome {
                    HealthCheckOutcome::Ok => "OK",
                    HealthCheckOutcome::NotConfigured => "SKIPPED (HW-4 decline path)",
                    HealthCheckOutcome::MissingForwardTo
                    | HealthCheckOutcome::ConnectionRefused(_)
                    | HealthCheckOutcome::Timeout => "FAIL",
                };
                println!("status: {label}");
                println!("detail: {}", outcome.summary());
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
                max_peers_per_key,
                hysteria_config,
            } => {
                assert_eq!(bind, "127.0.0.1:8443");
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
            "--max-peers-per-key",
            "10",
        ]);
        match cli.command {
            Command::Serve {
                bind,
                max_peers_per_key,
                hysteria_config,
            } => {
                assert_eq!(bind, "0.0.0.0:9000");
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
