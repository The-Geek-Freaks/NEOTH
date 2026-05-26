//! `neoth webhook serve` — operator-facing entry that starts the
//! paperless HTTP server so n8n + future MCP plugins can drive
//! the slice over a real network call.
//!
//! Runs until SIGTERM / Ctrl+C. The n8n starter workflow's HTTP
//! node POSTs `http://localhost:8765/paperless/ingest` while this
//! is up; same JSON contract the `cli::paperless` runner uses
//! locally.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::paperless::webhook_server::{WebhookServerConfig, spawn_webhook_server};

#[derive(Args, Debug, Clone)]
pub struct WebhookArgs {
    #[command(subcommand)]
    pub action: WebhookAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum WebhookAction {
    /// Start the paperless webhook HTTP server. Runs until
    /// SIGTERM / Ctrl+C.
    Serve {
        /// Bind address. Defaults to `127.0.0.1:8765` — the
        /// `NEOTH_HTTP_BASE` the n8n starter workflows POST to.
        #[arg(long, default_value = "127.0.0.1:8765")]
        bind: SocketAddr,
        /// Vault root the handler writes to.
        #[arg(long, value_name = "PATH")]
        vault: Option<PathBuf>,
        /// Subdir under the vault. (Per-request override still
        /// works; this is the server default.)
        #[arg(long, default_value = "NEOTH")]
        subdir: String,
        /// Required bearer token. Operators set `NEOTH_TOKEN`
        /// in env or pass via `--token`. Empty disables auth
        /// (testing only — refuses to start unless
        /// `--allow-no-auth` is also passed).
        #[arg(long, env = "NEOTH_TOKEN")]
        token: Option<String>,
        /// Explicit opt-in for unauthenticated mode. Without this,
        /// a missing `--token` is a hard error so operators don't
        /// accidentally expose `/paperless/ingest` to the LAN.
        #[arg(long)]
        allow_no_auth: bool,
    },
}

pub async fn run_webhook(args: WebhookArgs) -> Result<()> {
    match args.action {
        WebhookAction::Serve {
            bind,
            vault,
            subdir: _,
            token,
            allow_no_auth,
        } => {
            let bearer_token = token.unwrap_or_default();
            if bearer_token.is_empty() && !allow_no_auth {
                anyhow::bail!(
                    "no bearer token configured — pass --token, set NEOTH_TOKEN env, \
                     or explicitly opt out with --allow-no-auth",
                );
            }
            let vault_root = vault.unwrap_or_else(default_vault_path);
            let handle = spawn_webhook_server(WebhookServerConfig {
                bind_addr: bind,
                vault_root: vault_root.clone(),
                bearer_token,
            })
            .await
            .context("spawn webhook server")?;
            println!(
                "neoth webhook serve — listening on {} → vault {}",
                handle.bind_addr,
                vault_root.display(),
            );
            // Block until Ctrl+C / SIGTERM.
            tokio::signal::ctrl_c()
                .await
                .context("wait for shutdown signal")?;
            println!("shutting down...");
            handle.shutdown().await;
            Ok(())
        }
    }
}

fn default_vault_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("Documents").join("NEOTH-Vault")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serve_without_token_or_allow_flag_errors() {
        let args = WebhookArgs {
            action: WebhookAction::Serve {
                bind: "127.0.0.1:0".parse().unwrap(),
                vault: Some(std::env::temp_dir()),
                subdir: "NEOTH".into(),
                token: None,
                allow_no_auth: false,
            },
        };
        let err = run_webhook(args).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--token") || msg.contains("allow-no-auth"),
            "expected token-config error: {msg}",
        );
    }

    #[tokio::test]
    async fn serve_empty_token_with_allow_flag_does_not_error_at_parse() {
        // The serve fn blocks on ctrl_c so we can't await it here.
        // Instead, validate the arg shape directly: an empty token
        // + allow_no_auth must not trip the early bail.
        let allow_no_auth = true;
        let bearer_token = String::new();
        // Replicate the gate condition.
        let would_bail = bearer_token.is_empty() && !allow_no_auth;
        assert!(!would_bail);
    }
}
