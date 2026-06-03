//! `neoth email` — EM-01b inbound IMAP fetch + triage.
//!
//! `fetch` connects to the operator's IMAP inbox (Gmail by default), pulls the
//! newest UNSEEN messages non-destructively (`BODY.PEEK[]`), and runs each
//! through the shipped sanitizer→threat pipeline ([`crate::email::inbound`]),
//! reporting a per-email band + the action NEOTH is allowed to take.
//!
//! The live socket lives behind the `imap_fetch` build feature (rustls IMAP +
//! mailparse). Auth resolution + the triage pipeline are always compiled, so
//! `--dry-run` works on every build.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::email::gmail::{AuthMethod, GMAIL_IMAP_HOST, GMAIL_IMAP_PORT, ImapConnectionConfig};

#[derive(Args, Debug, Clone)]
pub struct EmailArgs {
    #[command(subcommand)]
    pub action: EmailAction,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum EmailAction {
    /// Fetch newest UNSEEN inbox messages over IMAP (non-destructive
    /// `BODY.PEEK[]`) and triage each through the sanitizer→threat pipeline.
    ///
    /// Auth resolves: `NEOTH_IMAP_PASSWORD` env (app-password) →
    /// `credentials.yaml::google_oauth_*` refreshed to an XOAUTH2 access
    /// token. Username: `--username` → `NEOTH_IMAP_USERNAME`.
    Fetch {
        /// Max number of newest UNSEEN messages to pull (clamped to 200).
        #[arg(long, default_value_t = 10)]
        limit: usize,
        /// IMAP username (the email address for Gmail). Falls back to
        /// `NEOTH_IMAP_USERNAME`.
        #[arg(long)]
        username: Option<String>,
        /// IMAP host (default Gmail).
        #[arg(long, default_value = GMAIL_IMAP_HOST)]
        host: String,
        /// IMAP TLS port (default 993).
        #[arg(long, default_value_t = GMAIL_IMAP_PORT)]
        port: u16,
        /// Show the resolved connection (host/port/user/auth-kind) WITHOUT
        /// connecting, authenticating, or fetching. Never prints the secret.
        #[arg(long)]
        dry_run: bool,
    },
}

pub async fn run_email(args: EmailArgs) -> Result<()> {
    match args.action {
        EmailAction::Fetch {
            limit,
            username,
            host,
            port,
            dry_run,
        } => run_fetch(args.output, limit, username, host, port, dry_run).await,
    }
}

async fn run_fetch(
    output: OutputFormat,
    limit: usize,
    username: Option<String>,
    host: String,
    port: u16,
    dry_run: bool,
) -> Result<()> {
    let username = username
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("NEOTH_IMAP_USERNAME").ok().filter(|s| !s.is_empty()))
        .context(
            "no IMAP username — pass --username <email> or set NEOTH_IMAP_USERNAME",
        )?;
    let auth = resolve_auth(&username).await?;
    let cfg = ImapConnectionConfig {
        host,
        port,
        username: username.clone(),
        auth,
        use_tls: true,
    };

    if dry_run {
        // Never prints the password / token — only its KIND.
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "dry_run": true,
                    "host": cfg.host,
                    "port": cfg.port,
                    "username": cfg.username,
                    "auth_kind": cfg.auth.kind_str(),
                })
            ),
            OutputFormat::Table => println!(
                "[dry-run] would fetch from {}:{} as {} (auth: {}) — nothing sent",
                cfg.host,
                cfg.port,
                cfg.username,
                cfg.auth.kind_str()
            ),
        }
        return Ok(());
    }

    fetch_and_triage(output, &cfg, limit).await
}

/// Resolve the IMAP auth method without ever surfacing the secret in an
/// error. App-password env wins (works for any IMAP host); otherwise mint an
/// XOAUTH2 access token from the stored Google OAuth refresh token.
async fn resolve_auth(username: &str) -> Result<AuthMethod> {
    if let Ok(pw) = std::env::var("NEOTH_IMAP_PASSWORD") {
        if !pw.is_empty() {
            return Ok(AuthMethod::PasswordPlain { password: pw });
        }
    }

    let creds = crate::config::credentials::Credentials::load_or_default(
        &crate::config::credentials::default_path(),
    )
    .context("load credentials.yaml")?;
    let (Some(client_id), Some(client_secret), Some(refresh_token)) = (
        creds.google_oauth_client_id.filter(|s| !s.is_empty()),
        creds.google_oauth_client_secret,
        creds.google_oauth_refresh_token,
    ) else {
        anyhow::bail!(
            "no IMAP credentials for {username} — set NEOTH_IMAP_PASSWORD (app-password) \
             OR add google_oauth_{{client_id,client_secret,refresh_token}} to \
             ~/.neoth/credentials.yaml with the https://mail.google.com/ scope so an \
             XOAUTH2 token can be minted."
        );
    };
    // Reuses the Google Tasks OAuth refresh (same token endpoint); the access
    // token is never persisted. A refresh failure surfaces only the HTTP
    // status (the adapter guarantees no token leak in its error).
    let access = crate::tools::google_tasks::refresh_access_token(
        &client_id,
        &client_secret,
        &refresh_token,
    )
    .await
    .context("mint XOAUTH2 access token from the stored Google refresh token")?;
    Ok(AuthMethod::OAuth2Xoauth2 {
        access_token: access.expose().to_string(),
    })
}

#[cfg(feature = "imap_fetch")]
async fn fetch_and_triage(
    output: OutputFormat,
    cfg: &ImapConnectionConfig,
    limit: usize,
) -> Result<()> {
    use crate::email::inbound::{InboundAction, triage_inbound};

    let emails = crate::email::imap_fetch::fetch_unseen(cfg, limit)
        .await
        .context("IMAP fetch failed")?;
    let mut triaged: Vec<_> = emails.iter().map(triage_inbound).collect();

    // PL-05b — optional LLM second-opinion on the borderline ReviewQueue band.
    // Gated default-OFF (cost): only when `email.llm_tiebreak` is set AND a
    // provider is configured. A provider error per-email is fail-safe (the
    // deterministic ReviewQueue verdict stands). No call is made for any
    // non-ReviewQueue email, so there is zero LLM cost on a clean inbox.
    let fcfg = crate::config::FreedomConfig::load_from_default_path().unwrap_or_default();
    if fcfg.email.llm_tiebreak && triaged.iter().any(|t| t.action == InboundAction::ReviewQueue) {
        match crate::providers::from_config(&fcfg).await {
            Ok(provider) => {
                let allow = fcfg.email.llm_tiebreak_allow_downgrade;
                let mut reviewed = Vec::with_capacity(triaged.len());
                for t in triaged {
                    // Caller-side cost/safety gate (independent of the callee's
                    // own ReviewQueue guard): only borderline emails ever reach
                    // the provider, so a clean inbox makes zero LLM calls and a
                    // Quarantine/Dropped email is never re-classified.
                    if t.action == InboundAction::ReviewQueue {
                        reviewed.push(
                            crate::email::threat_tiebreak::tiebreak_review_inbound(
                                t,
                                provider.as_ref(),
                                allow,
                            )
                            .await,
                        );
                    } else {
                        reviewed.push(t);
                    }
                }
                triaged = reviewed;
            }
            Err(e) => tracing::warn!(
                error = %e,
                "email.llm_tiebreak is on but no provider is configured — keeping deterministic verdicts"
            ),
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&triaged)?);
        }
        OutputFormat::Table => {
            if triaged.is_empty() {
                println!("(no unseen messages)");
                return Ok(());
            }
            for t in &triaged {
                let score = t.threat.as_ref().map(|a| a.score).unwrap_or(0);
                let tb = t
                    .tiebreak
                    .map(|v| format!("  (llm:{})", v.as_str()))
                    .unwrap_or_default();
                println!(
                    "[{}] score={:<3} {}  —  {}{}",
                    t.action.as_str(),
                    score,
                    t.from,
                    t.subject,
                    tb
                );
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "imap_fetch"))]
async fn fetch_and_triage(
    _output: OutputFormat,
    _cfg: &ImapConnectionConfig,
    _limit: usize,
) -> Result<()> {
    anyhow::bail!(
        "this build was compiled without the `imap_fetch` feature — live IMAP fetch is \
         unavailable. Release binaries include it; from source, rebuild with \
         `cargo build --features imap_fetch`. (`--dry-run` works on every build.)"
    )
}
