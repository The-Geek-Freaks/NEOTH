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
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;
use tracing::info;

mod hysteria;
mod relay;
mod serve;

#[derive(Parser, Debug)]
#[command(name = "neoth-relay", version, about = "NEOTH relay daemon — Cluster Phase 5")]
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
        /// architect-ratified DEFAULT_MAX_PEERS_PER_KEY).
        #[arg(long, default_value_t = relay::DEFAULT_MAX_PEERS_PER_KEY)]
        max_peers_per_key: u32,
    },
    /// Print version + build info without binding a socket. Useful
    /// for operators verifying the binary deployed correctly
    /// before opening firewall rules.
    Status,
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
        } => {
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
        Command::Status => {
            println!("neoth-relay {} — Cluster Phase 5", env!("CARGO_PKG_VERSION"));
            println!("ready to bind via `neoth-relay serve --bind <addr>`");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_serve_defaults_bind_to_loopback_8443() {
        let cli = Cli::parse_from(["neoth-relay", "serve"]);
        match cli.command {
            Command::Serve { bind, max_peers_per_key } => {
                assert_eq!(bind, "127.0.0.1:8443");
                assert_eq!(max_peers_per_key, relay::DEFAULT_MAX_PEERS_PER_KEY);
            }
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn cli_serve_honours_custom_bind_and_cap() {
        let cli = Cli::parse_from(["neoth-relay", "serve", "--bind", "0.0.0.0:9000", "--max-peers-per-key", "10"]);
        match cli.command {
            Command::Serve { bind, max_peers_per_key } => {
                assert_eq!(bind, "0.0.0.0:9000");
                assert_eq!(max_peers_per_key, 10);
            }
            _ => panic!("expected Serve"),
        }
    }

    #[test]
    fn cli_status_command_parses() {
        let cli = Cli::parse_from(["neoth-relay", "status"]);
        assert!(matches!(cli.command, Command::Status));
    }
}
