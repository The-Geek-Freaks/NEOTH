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
        /// Re-process messages already in the local seen-state table (P1c
        /// dedup). By default a re-fetch SKIPS mail NEOTH already triaged
        /// (UNSEEN + `BODY.PEEK[]` would otherwise re-pull it forever); pass
        /// this to triage them again (e.g. after enabling the tie-breaker).
        #[arg(long)]
        include_seen: bool,
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
            include_seen,
        } => run_fetch(args.output, limit, username, host, port, dry_run, include_seen).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_fetch(
    output: OutputFormat,
    limit: usize,
    username: Option<String>,
    host: String,
    port: u16,
    dry_run: bool,
    include_seen: bool,
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

    fetch_and_triage(output, &cfg, limit, include_seen).await
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
    include_seen: bool,
) -> Result<()> {
    use crate::email::inbound::{InboundAction, triage_inbound};

    let fetched = crate::email::imap_fetch::fetch_unseen(cfg, limit)
        .await
        .context("IMAP fetch failed")?;

    // P1c — dedup against the local seen-state so an UNSEEN message NEOTH
    // already triaged isn't re-pulled forever (BODY.PEEK[] never sets \Seen).
    // Best-effort: a views.db open failure degrades to "process everything".
    let seen_conn = crate::memory::store::open(
        &crate::config::FreedomConfig::default_neoth_home().join("views.db"),
    )
    .ok();
    let (emails, skipped) = if include_seen {
        (fetched, 0usize)
    } else if let Some(conn) = &seen_conn {
        let mut fresh = Vec::with_capacity(fetched.len());
        let mut n_skipped = 0usize;
        for e in fetched {
            match crate::email::seen_store::is_seen(conn, e.dedup_key()) {
                Ok(true) => n_skipped += 1,
                _ => fresh.push(e), // unseen, or a query error → process it
            }
        }
        (fresh, n_skipped)
    } else {
        (fetched, 0)
    };

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

    // P1a — annotate each triage with the trusted-sender + SPF/DKIM/DMARC
    // visibility signals. Runs AFTER triage + tie-break and NEVER changes the
    // band ("trusted but still sanitized"). `triaged[i]` stays aligned with
    // `emails[i]` (the tie-break loop preserves order).
    triaged = triaged
        .into_iter()
        .zip(emails.iter())
        .map(|(t, e)| {
            crate::email::sender_policy::annotate_sender_policy(t, e, &fcfg.email.trusted_domains)
        })
        .collect();

    // EM-01b/PL-05b — record each inbound-mail security decision in the audit
    // ledger (metadata only). Best-effort: an audit gap never blocks the fetch.
    emit_email_audit_batch(&triaged).await;

    // P1c — record the processed messages as seen so the next fetch skips them.
    // After triage + audit, so a crash mid-run doesn't mark un-triaged mail.
    if let Some(conn) = &seen_conn {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        for e in &emails {
            let _ = crate::email::seen_store::mark_seen(conn, e.dedup_key(), Some(&e.uid), now);
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({ "skipped_already_seen": skipped, "triaged": &triaged })
            );
        }
        OutputFormat::Table => {
            if skipped > 0 {
                println!("({skipped} already-seen message(s) skipped — pass --include-seen to re-triage)");
            }
            if triaged.is_empty() {
                println!("(no new unseen messages)");
                return Ok(());
            }
            for t in &triaged {
                let score = t.threat.as_ref().map(|a| a.score).unwrap_or(0);
                let tb = t
                    .tiebreak
                    .map(|v| format!("  (llm:{})", v.as_str()))
                    .unwrap_or_default();
                let trust = if t.sender_trusted { "  [trusted]" } else { "" };
                let auth = t
                    .auth
                    .map(|a| {
                        format!(
                            "  (spf:{} dkim:{} dmarc:{})",
                            a.spf.as_str(),
                            a.dkim.as_str(),
                            a.dmarc.as_str()
                        )
                    })
                    .unwrap_or_default();
                println!(
                    "[{}] score={:<3} {}  —  {}{}{}{}",
                    t.action.as_str(),
                    score,
                    t.from,
                    t.subject,
                    trust,
                    tb,
                    auth
                );
            }
        }
    }
    Ok(())
}

/// Inbound-email audit — emits up to three frame KINDS per triaged message
/// (metadata ONLY: sender DOMAIN, never the full From / body / subject):
///   - `0x3D EMAIL_INGRESS_TRIAGED`     — every message (the base record).
///   - `0x30 EMAIL_INGRESS_QUARANTINED` — additionally when the body was
///     withheld (quarantine / dropped-at-sanitizer).
///   - `0x31 EMAIL_TIEBREAK_APPLIED`    — additionally when the LLM tie-breaker
///     was consulted (a security-relevant override record).
/// When a daemon owns the WAL, FORWARD each over audit-RPC; otherwise open ONE
/// one-shot writer for the whole batch. Best-effort — an audit gap never blocks
/// the fetch.
#[cfg(feature = "imap_fetch")]
async fn emit_email_audit_batch(triaged: &[crate::email::inbound::InboundTriage]) {
    use crate::email::inbound::{InboundAction, extract_from_domain};
    use crate::wal::events::{
        EVENT_TYPE_EMAIL_INGRESS_QUARANTINED, EVENT_TYPE_EMAIL_INGRESS_TRIAGED,
        EVENT_TYPE_EMAIL_TIEBREAK_APPLIED,
    };
    if triaged.is_empty() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // (event_type, payload) frames for the whole batch.
    let mut frames: Vec<(u8, Vec<u8>)> = Vec::new();
    for t in triaged {
        let from_domain = extract_from_domain(&t.from);
        let score = t.threat.as_ref().map(|a| a.score);
        frames.push((
            EVENT_TYPE_EMAIL_INGRESS_TRIAGED,
            serde_json::to_vec(&serde_json::json!({
                "uid": t.uid,
                "from_domain": from_domain,
                "score": score,
                "action": t.action.as_str(),
                "tiebreak": t.tiebreak.map(|v| v.as_str()),
                // P1a — sender-trust + SPF/DKIM/DMARC visibility in the audit.
                "sender_trusted": t.sender_trusted,
                "auth": t.auth.map(|a| serde_json::json!({
                    "spf": a.spf.as_str(),
                    "dkim": a.dkim.as_str(),
                    "dmarc": a.dmarc.as_str(),
                })),
                "ts_unix": now,
            }))
            .unwrap_or_default(),
        ));
        if matches!(
            t.action,
            InboundAction::Quarantine | InboundAction::DroppedAtSanitizer
        ) {
            frames.push((
                EVENT_TYPE_EMAIL_INGRESS_QUARANTINED,
                serde_json::to_vec(&serde_json::json!({
                    "uid": t.uid,
                    "from_domain": from_domain,
                    "score": score,
                    "action": t.action.as_str(),
                    "ts_unix": now,
                }))
                .unwrap_or_default(),
            ));
        }
        if let Some(v) = t.tiebreak {
            frames.push((
                EVENT_TYPE_EMAIL_TIEBREAK_APPLIED,
                serde_json::to_vec(&serde_json::json!({
                    "uid": t.uid,
                    "from_domain": from_domain,
                    "verdict": v.as_str(),
                    // Input band is always review-queue; a quarantine/deliver
                    // result means the LLM overrode the deterministic rules.
                    "resulting_action": t.action.as_str(),
                    "ts_unix": now,
                }))
                .unwrap_or_default(),
            ));
        }
    }

    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile()),
        Ok(Some(_))
    );
    if daemon_live {
        let home = crate::config::FreedomConfig::default_neoth_home();
        for (event_type, payload) in &frames {
            if let Err(e) =
                crate::daemon::audit_rpc::try_post_audit_frame(&home, *event_type, payload).await
            {
                tracing::debug!(error = %e, "email: audit frame forward skipped (listener unreachable)");
            }
        }
        return;
    }
    let segment = crate::config::FreedomConfig::default_wal_dir().join("000001.wal");
    if let Some(p) = segment.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let (writer, _join) = match crate::wal::writer::spawn(segment) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "email: WAL writer spawn failed; inbound audit not recorded");
            return;
        }
    };
    for (event_type, payload) in frames {
        let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
        if let Err(e) = writer.try_append_sync(header, payload) {
            tracing::warn!(error = %e, "email: inbound audit frame append failed (audit gap)");
        }
    }
}

#[cfg(not(feature = "imap_fetch"))]
async fn fetch_and_triage(
    _output: OutputFormat,
    _cfg: &ImapConnectionConfig,
    _limit: usize,
    _include_seen: bool,
) -> Result<()> {
    anyhow::bail!(
        "this build was compiled without the `imap_fetch` feature — live IMAP fetch is \
         unavailable. Release binaries include it; from source, rebuild with \
         `cargo build --features imap_fetch`. (`--dry-run` works on every build.)"
    )
}
