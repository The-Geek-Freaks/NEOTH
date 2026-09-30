//! `neoth slack test [--account <id>]` — Slack credential pre-flight (A-7).
//!
//! Validates `xoxb-` bot token + `xapp-` app token by calling
//! `auth.test` + `apps.connections.open`. The returned WSS URL is deliberately
//! withheld from CLI output while still proving the runtime's Socket Mode
//! credentials before the daemon starts its channel loop.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use crate::channels::registry::{ChannelAccountId, ChannelId, ChannelRef};
use crate::channels::slack_api;
use crate::cli::OutputFormat;
use crate::config::{FreedomConfig, RuntimeConfigPair};
use crate::secret::SecretString;

#[derive(Args, Debug, Clone)]
pub struct SlackArgs {
    #[command(subcommand)]
    pub action: SlackAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SlackAction {
    /// Auth-test one Slack credential binding. For a named account map,
    /// `--account` is required; the command never guesses a default account.
    /// Calls `auth.test` + `apps.connections.open` without revealing the WSS URL.
    Test {
        /// Exact configured Slack account. Required whenever a Slack account map is active.
        #[arg(long)]
        account: Option<ChannelAccountId>,
    },
    /// Send a one-shot message to a Slack channel via `chat.postMessage`.
    /// A named Slack account map requires `--account`; legacy scalar Slack
    /// uses no selector. `channel` accepts an
    /// id (`Cxxxxxx`), a DM id (`Dxxxxxx`), or `#channel-name` (Slack
    /// resolves server-side). Returns the message timestamp (Slack's
    /// `ts`) so operators can correlate with later edits/reactions.
    Send {
        /// Exact configured Slack account. Required whenever a Slack account map is active.
        #[arg(long)]
        account: Option<ChannelAccountId>,
        /// Channel id or `#name`.
        #[arg(long)]
        channel: String,
        /// Message body (UTF-8, Slack mrkdwn supported).
        #[arg(long)]
        message: String,
    },
}

pub async fn run_slack(args: SlackArgs) -> Result<()> {
    match args.action {
        SlackAction::Test { account } => run_test(account, &args.output).await,
        SlackAction::Send {
            account,
            channel,
            message,
        } => run_send(account, &channel, &message, &args.output).await,
    }
}

async fn run_send(
    account: Option<ChannelAccountId>,
    channel: &str,
    message: &str,
    output: &OutputFormat,
) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let pair = crate::config::load_runtime_config_pair_from_path_or_default_for_diagnostic(
        &home.join("freedom.yaml"),
    )
    .context("load coherent Slack config and credentials for send")?;
    run_send_with(
        &pair,
        account.as_ref(),
        channel,
        message,
        output,
        |token, channel, message| async move {
            slack_api::post_message(&token, &channel, &message).await
        },
    )
    .await
}

async fn run_send_with<F, Fut>(
    pair: &RuntimeConfigPair,
    account: Option<&ChannelAccountId>,
    channel: &str,
    message: &str,
    output: &OutputFormat,
    post_message: F,
) -> Result<()>
where
    F: FnOnce(SecretString, String, String) -> Fut,
    Fut: std::future::Future<Output = Result<slack_api::PostMessageResult>>,
{
    let bot_token = resolve_slack_send_selection(pair, account)?;
    run_send_with_selected_token(bot_token, channel, message, output, post_message).await
}

async fn run_send_with_selected_token<F, Fut>(
    bot_token: SecretString,
    channel: &str,
    message: &str,
    output: &OutputFormat,
    post_message: F,
) -> Result<()>
where
    F: FnOnce(SecretString, String, String) -> Fut,
    Fut: std::future::Future<Output = Result<slack_api::PostMessageResult>>,
{
    let result = post_message(bot_token, channel.to_string(), message.to_string())
        .await
        .context("Slack chat.postMessage")?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Table => {
            if result.ok {
                println!(
                    "# Slack send — OK\n  channel: {}\n  ts:      {}",
                    result.channel.as_deref().unwrap_or(channel),
                    result.ts.as_deref().unwrap_or("(missing)"),
                );
            } else {
                println!(
                    "# Slack send — FAIL\n  channel: {channel}\n  error:   {}",
                    result.error.as_deref().unwrap_or("(no error string)"),
                );
            }
        }
    }
    if !result.ok {
        anyhow::bail!(
            "Slack send failed: {}",
            result.error.as_deref().unwrap_or("unknown")
        );
    }
    Ok(())
}

struct SlackTestSelection {
    account: Option<ChannelAccountId>,
    bot_token: SecretString,
    app_token: SecretString,
    expected_team_id: Option<String>,
}

struct SlackPreflightResult {
    account: Option<ChannelAccountId>,
    auth: slack_api::AuthTestResult,
    socket: slack_api::SocketOpenResult,
    team_id_matches: Option<bool>,
}

impl SlackPreflightResult {
    fn socket_mode_ready(&self) -> bool {
        self.auth.ok
            && self.socket.ok
            && socket_url_is_usable(self.socket.url.as_deref())
            && self.team_id_matches != Some(false)
    }
}

fn ensure_preflight_success(result: &SlackPreflightResult) -> Result<()> {
    anyhow::ensure!(
        result.socket_mode_ready(),
        "Slack pre-flight failed; inspect the rendered status"
    );
    Ok(())
}

fn socket_url_is_usable(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        url::Url::parse(value).is_ok_and(|url| url.scheme() == "wss" && url.host_str().is_some())
    })
}

fn slack_account_map_active(pair: &RuntimeConfigPair) -> bool {
    !pair.config.channel_accounts.slack.is_empty()
        || pair.credentials.slack_account_map_active()
        || pair.raw_credentials.slack_account_map_active()
}

/// Resolve the exact coherent bot credential for an operator-requested manual
/// send. Named maps require an explicit account and never fall back to a
/// scalar credential; legacy scalar Slack remains bot-token-only.
fn resolve_slack_send_selection(
    pair: &RuntimeConfigPair,
    requested_account: Option<&ChannelAccountId>,
) -> Result<SecretString> {
    if slack_account_map_active(pair) {
        let requested_account = requested_account
            .context("Slack account map is active; pass `neoth slack send --account <id>`")?;
        let accounts = pair.authenticated_slack_accounts().map_err(|_| {
            anyhow::anyhow!(
                "Slack account map is invalid; repair matching policy and credential entries before sending"
            )
        })?;
        let account = accounts
            .into_iter()
            .find(|account| {
                !account.is_legacy_singleton()
                    && account.channel_ref()
                        == &ChannelRef::new(ChannelId::Slack, requested_account.clone())
            })
            .ok_or_else(|| {
                anyhow::anyhow!("Slack account `{requested_account}` is not configured")
            })?;
        return Ok(account.bot_token().clone());
    }

    anyhow::ensure!(
        requested_account.is_none(),
        "--account is invalid for legacy scalar Slack; omit it to send with the legacy singleton"
    );
    pair.credentials.slack_bot_token.clone().context(
        "no slack_bot_token in credentials.yaml. Run `neoth init --force` or add it manually before sending.",
    )
}

/// Resolve the exact coherent credential generation before either remote probe.
/// Map mode requires an explicit account and never falls back to shadowed scalar
/// fields, even when the named map is partial or invalid.
fn resolve_slack_test_selection(
    pair: &RuntimeConfigPair,
    requested_account: Option<&ChannelAccountId>,
) -> Result<SlackTestSelection> {
    if slack_account_map_active(pair) {
        let requested_account = requested_account
            .context("Slack account map is active; pass `neoth slack test --account <id>`")?;
        let accounts = pair.authenticated_slack_accounts().map_err(|_| {
            anyhow::anyhow!(
                "Slack account map is invalid; repair matching policy and credential entries before pre-flight"
            )
        })?;
        let account = accounts
            .into_iter()
            .find(|account| {
                !account.is_legacy_singleton()
                    && account.channel_ref()
                        == &ChannelRef::new(ChannelId::Slack, requested_account.clone())
            })
            .ok_or_else(|| {
                anyhow::anyhow!("Slack account `{requested_account}` is not configured")
            })?;
        return Ok(SlackTestSelection {
            account: Some(requested_account.clone()),
            bot_token: account.bot_token().clone(),
            app_token: account.app_token().clone(),
            expected_team_id: account.team_id().map(str::to_owned),
        });
    }

    anyhow::ensure!(
        requested_account.is_none(),
        "--account is invalid for legacy scalar Slack; omit it to test the legacy singleton"
    );
    let bot_token = pair.credentials.slack_bot_token.clone().context(
        "no slack_bot_token in credentials.yaml. Run `neoth init --force` or add it manually.",
    )?;
    let app_token = pair.credentials.slack_app_token.clone().context(
        "no slack_app_token in credentials.yaml. Socket mode requires the xapp-... token. Add it via the Slack app's Basic Information page → App-Level Tokens.",
    )?;
    Ok(SlackTestSelection {
        account: None,
        bot_token,
        app_token,
        expected_team_id: None,
    })
}

async fn run_preflight_with<AuthProbe, SocketProbe, AuthFuture, SocketFuture>(
    selection: SlackTestSelection,
    auth_probe: AuthProbe,
    socket_probe: SocketProbe,
) -> Result<SlackPreflightResult>
where
    AuthProbe: FnOnce(SecretString) -> AuthFuture,
    SocketProbe: FnOnce(SecretString) -> SocketFuture,
    AuthFuture: std::future::Future<Output = Result<slack_api::AuthTestResult>>,
    SocketFuture: std::future::Future<Output = Result<slack_api::SocketOpenResult>>,
{
    let auth = auth_probe(selection.bot_token)
        .await
        .map_err(|_| anyhow::anyhow!("Slack auth.test pre-flight request failed"))?;
    let socket = socket_probe(selection.app_token)
        .await
        .map_err(|_| anyhow::anyhow!("Slack Socket Mode pre-flight request failed"))?;
    let team_id_matches = selection.expected_team_id.as_deref().map(|expected| {
        auth.team_id
            .as_deref()
            .and_then(|observed| crate::config::normalize_slack_team_id(observed).ok())
            .as_deref()
            == Some(expected)
    });
    Ok(SlackPreflightResult {
        account: selection.account,
        auth,
        socket,
        team_id_matches,
    })
}

fn redacted_auth_result(auth: &slack_api::AuthTestResult) -> serde_json::Value {
    json!({
        "ok": auth.ok,
        "bot_id": auth.bot_id,
        "team": auth.team,
        "team_id": auth.team_id,
        "user": auth.user,
        "error": auth.error.as_ref().map(|_| "Slack rejected auth.test"),
    })
}

fn redacted_socket_result(socket: &slack_api::SocketOpenResult) -> serde_json::Value {
    json!({
        "ok": socket.ok,
        "error": socket.error.as_ref().map(|_| "Slack rejected apps.connections.open"),
    })
}

fn render_preflight_json(result: &SlackPreflightResult) -> Result<String> {
    Ok(serde_json::to_string_pretty(&json!({
        "account": result.account.as_ref().map(ChannelAccountId::as_str),
        "auth_test": redacted_auth_result(&result.auth),
        "socket_mode_open": redacted_socket_result(&result.socket),
        "socket_url_usable": socket_url_is_usable(result.socket.url.as_deref()),
        "team_id_matches": result.team_id_matches,
        "socket_mode_ready": result.socket_mode_ready(),
    }))?)
}

async fn run_test(account: Option<ChannelAccountId>, output: &OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let pair = crate::config::load_runtime_config_pair_from_path_or_default_for_diagnostic(
        &home.join("freedom.yaml"),
    )
    .context("load coherent Slack config and credentials for pre-flight")?;
    let selection = resolve_slack_test_selection(&pair, account.as_ref())?;
    let result = run_preflight_with(
        selection,
        |bot_token| async move { slack_api::auth_test(&bot_token).await },
        |app_token| async move { slack_api::socket_mode_open(&app_token).await },
    )
    .await?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", render_preflight_json(&result)?);
        }
        OutputFormat::Table => {
            println!("# Slack pre-flight");
            if let Some(account) = result.account.as_ref() {
                println!("  account:             {}", account.as_str());
            }
            if result.auth.ok {
                println!(
                    "  auth.test:           OK — team={} bot={} user={}",
                    result.auth.team.as_deref().unwrap_or("?"),
                    result.auth.bot_id.as_deref().unwrap_or("?"),
                    result.auth.user.as_deref().unwrap_or("?"),
                );
            } else {
                println!("  auth.test:           FAIL — Slack rejected auth.test");
            }
            if result.socket.ok {
                println!("  apps.connections.open: OK");
            } else {
                println!("  apps.connections.open: FAIL — Slack rejected apps.connections.open");
            }
            if result.socket.ok && !socket_url_is_usable(result.socket.url.as_deref()) {
                println!(
                    "  socket endpoint:      FAIL — Slack did not return a usable Socket Mode endpoint"
                );
            }
            if result.team_id_matches == Some(false) {
                println!(
                    "  team binding:         FAIL — auth.test workspace does not match this account"
                );
            }
            println!();
            if result.socket_mode_ready() {
                println!(
                    "  Credentials valid. The live Socket Mode loop will \
                     consume these tokens without re-prompting."
                );
            } else {
                println!(
                    "  One or both calls failed — fix tokens in credentials.yaml; \
                     otherwise the Socket Mode loop won't start."
                );
            }
        }
    }
    ensure_preflight_success(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::{
        channels::registry::ChannelAccountId,
        cli::{Cli, Commands},
        config::credentials::{Credentials, SlackAccountCredentials},
        config::{FreedomConfig, RuntimeConfigPair, SlackAccountConfig},
        secret::SecretString,
    };
    use clap::Parser;
    use tempfile::tempdir;

    // These tests mutate the process-global HOME/USERPROFILE, so they
    // hold crate::test_env::lock() for the whole body. Plain `#[test]`
    // + a synchronous block_on (not `#[tokio::test]`) so the
    // std::sync::MutexGuard isn't held across an `.await`
    // (clippy::await_holding_lock under -D warnings).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    fn mapped_slack_pair(team_id: Option<&str>) -> RuntimeConfigPair {
        let account = ChannelAccountId::new("work").unwrap();
        let mut pair = RuntimeConfigPair {
            config: FreedomConfig::default(),
            raw_credentials: Credentials::default(),
            credentials: Credentials::default(),
        };
        pair.config.channel_accounts.slack.insert(
            account.clone(),
            SlackAccountConfig {
                allowed_user_id: "U123PRIVATE".into(),
                team_id: team_id.map(str::to_owned),
                incarnation: None,
            },
        );
        let secrets = SlackAccountCredentials {
            bot_token: Some(SecretString::from("xoxb-work-secret")),
            app_token: Some(SecretString::from("xapp-work-secret")),
        };
        pair.raw_credentials
            .channel_accounts
            .slack
            .insert(account.clone(), secrets.clone());
        pair.credentials
            .channel_accounts
            .slack
            .insert(account, secrets);
        pair
    }

    fn add_second_named_slack_account(pair: &mut RuntimeConfigPair) {
        let account = ChannelAccountId::new("personal").unwrap();
        pair.config.channel_accounts.slack.insert(
            account.clone(),
            SlackAccountConfig {
                allowed_user_id: "U456PRIVATE".into(),
                team_id: Some("TPERSONAL".into()),
                incarnation: None,
            },
        );
        let secrets = SlackAccountCredentials {
            bot_token: Some(SecretString::from("xoxb-personal-secret")),
            app_token: Some(SecretString::from("xapp-personal-secret")),
        };
        pair.raw_credentials
            .channel_accounts
            .slack
            .insert(account.clone(), secrets.clone());
        pair.credentials
            .channel_accounts
            .slack
            .insert(account, secrets);
    }

    fn auth_ok(team_id: Option<&str>) -> slack_api::AuthTestResult {
        slack_api::AuthTestResult {
            ok: true,
            bot_id: Some("B123".into()),
            team: Some("Workspace".into()),
            team_id: team_id.map(str::to_owned),
            user: Some("neoth".into()),
            url: Some("https://workspace.slack.com/secret".into()),
            error: None,
        }
    }

    fn socket_ok() -> slack_api::SocketOpenResult {
        slack_api::SocketOpenResult {
            ok: true,
            url: Some("wss://wss-primary.slack.com/link-secret".into()),
            error: None,
        }
    }

    fn post_ok() -> slack_api::PostMessageResult {
        slack_api::PostMessageResult {
            ok: true,
            ts: Some("1700000000.000100".into()),
            channel: Some("C123".into()),
            error: None,
        }
    }

    #[test]
    fn mapped_slack_preflight_requires_an_explicit_account() {
        let error = resolve_slack_test_selection(&mapped_slack_pair(None), None)
            .err()
            .expect("mapped Slack configuration must require --account")
            .to_string();
        assert!(error.contains("--account"));
        assert!(!error.contains("xoxb-work-secret"));
    }

    #[test]
    fn mapped_slack_preflight_selects_exact_account_and_calls_both_probes() {
        let account = ChannelAccountId::new("work").unwrap();
        let mut pair = mapped_slack_pair(Some("TWORK"));
        add_second_named_slack_account(&mut pair);
        let selection = resolve_slack_test_selection(&pair, Some(&account)).unwrap();
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let socket_calls = Arc::new(AtomicUsize::new(0));
        let auth_token = Arc::new(Mutex::new(None));
        let socket_token = Arc::new(Mutex::new(None));
        let auth_calls_for_probe = Arc::clone(&auth_calls);
        let socket_calls_for_probe = Arc::clone(&socket_calls);
        let auth_token_for_probe = Arc::clone(&auth_token);
        let socket_token_for_probe = Arc::clone(&socket_token);

        let result = block_on(run_preflight_with(
            selection,
            move |token| {
                auth_calls_for_probe.fetch_add(1, Ordering::SeqCst);
                *auth_token_for_probe.lock().unwrap() = Some(token.expose().to_owned());
                async { Ok(auth_ok(Some("TWORK"))) }
            },
            move |token| {
                socket_calls_for_probe.fetch_add(1, Ordering::SeqCst);
                *socket_token_for_probe.lock().unwrap() = Some(token.expose().to_owned());
                async { Ok(socket_ok()) }
            },
        ))
        .unwrap();

        assert_eq!(result.account.as_ref(), Some(&account));
        assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
        assert_eq!(socket_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            auth_token.lock().unwrap().as_deref(),
            Some("xoxb-work-secret")
        );
        assert_eq!(
            socket_token.lock().unwrap().as_deref(),
            Some("xapp-work-secret")
        );
        assert_eq!(result.team_id_matches, Some(true));
        assert!(result.socket_mode_ready());
    }

    #[test]
    fn mapped_slack_preflight_accepts_an_explicit_named_default_account() {
        let work = ChannelAccountId::new("work").unwrap();
        let default = ChannelAccountId::new("default").unwrap();
        let mut pair = mapped_slack_pair(None);
        let policy = pair
            .config
            .channel_accounts
            .slack
            .remove(&work)
            .expect("work policy");
        let raw_secrets = pair
            .raw_credentials
            .channel_accounts
            .slack
            .remove(&work)
            .expect("work raw secrets");
        let secrets = pair
            .credentials
            .channel_accounts
            .slack
            .remove(&work)
            .expect("work effective secrets");
        pair.config
            .channel_accounts
            .slack
            .insert(default.clone(), policy);
        pair.raw_credentials
            .channel_accounts
            .slack
            .insert(default.clone(), raw_secrets);
        pair.credentials
            .channel_accounts
            .slack
            .insert(default.clone(), secrets);

        let selection = resolve_slack_test_selection(&pair, Some(&default)).unwrap();
        assert_eq!(selection.account.as_ref(), Some(&default));
    }

    #[test]
    fn mapped_slack_preflight_marks_stored_team_mismatch_unready_and_redacts_urls() {
        let account = ChannelAccountId::new("work").unwrap();
        let selection =
            resolve_slack_test_selection(&mapped_slack_pair(Some("TWORK")), Some(&account))
                .unwrap();
        let result = block_on(run_preflight_with(
            selection,
            |_token| async { Ok(auth_ok(Some("TOTHER"))) },
            |_token| async { Ok(socket_ok()) },
        ))
        .unwrap();

        assert_eq!(result.team_id_matches, Some(false));
        assert!(!result.socket_mode_ready());
        let rendered = render_preflight_json(&result).unwrap();
        assert!(rendered.contains("\"account\": \"work\""));
        assert!(!rendered.contains("link-secret"));
        assert!(!rendered.contains("workspace.slack.com"));
    }

    #[test]
    fn slack_preflight_requires_a_usable_socket_url_and_returns_a_payload_free_failure() {
        let account = ChannelAccountId::new("work").unwrap();
        let selection =
            resolve_slack_test_selection(&mapped_slack_pair(None), Some(&account)).unwrap();
        let result = block_on(run_preflight_with(
            selection,
            |_token| async { Ok(auth_ok(None)) },
            |_token| async {
                Ok(slack_api::SocketOpenResult {
                    ok: true,
                    url: None,
                    error: None,
                })
            },
        ))
        .unwrap();

        assert!(!result.socket_mode_ready());
        assert!(!socket_url_is_usable(result.socket.url.as_deref()));
        assert!(!socket_url_is_usable(Some(
            "https://wss-primary.slack.com/link"
        )));
        assert!(!socket_url_is_usable(Some("wss://")));
        let error = ensure_preflight_success(&result).unwrap_err().to_string();
        assert_eq!(
            error,
            "Slack pre-flight failed; inspect the rendered status"
        );
    }

    #[test]
    fn slack_preflight_rejects_failed_auth_even_when_socket_endpoint_is_usable() {
        let account = ChannelAccountId::new("work").unwrap();
        let selection =
            resolve_slack_test_selection(&mapped_slack_pair(None), Some(&account)).unwrap();
        let result = block_on(run_preflight_with(
            selection,
            |_token| async {
                Ok(slack_api::AuthTestResult {
                    ok: false,
                    bot_id: None,
                    team: None,
                    team_id: None,
                    user: None,
                    url: None,
                    error: Some("provider-detail-that-must-not-escape".into()),
                })
            },
            |_token| async { Ok(socket_ok()) },
        ))
        .unwrap();

        assert!(!result.socket_mode_ready());
        assert_eq!(
            ensure_preflight_success(&result).unwrap_err().to_string(),
            "Slack pre-flight failed; inspect the rendered status"
        );
    }

    #[test]
    fn mapped_slack_preflight_redacts_provider_failure_detail() {
        let account = ChannelAccountId::new("work").unwrap();
        let selection =
            resolve_slack_test_selection(&mapped_slack_pair(None), Some(&account)).unwrap();
        let error = block_on(run_preflight_with(
            selection,
            |_token| async { Err(anyhow::anyhow!("provider echoed xoxb-work-secret")) },
            |_token| async { Ok(socket_ok()) },
        ))
        .err()
        .expect("provider failure must fail the pre-flight")
        .to_string();

        assert!(error.contains("auth.test pre-flight request failed"));
        assert!(!error.contains("xoxb-work-secret"));
    }

    #[test]
    fn legacy_slack_preflight_keeps_scalar_selection_without_account() {
        let mut pair = RuntimeConfigPair {
            config: FreedomConfig::default(),
            raw_credentials: Credentials::default(),
            credentials: Credentials::default(),
        };
        pair.credentials.slack_bot_token = Some(SecretString::from("xoxb-legacy"));
        pair.credentials.slack_app_token = Some(SecretString::from("xapp-legacy"));

        let selection = resolve_slack_test_selection(&pair, None).unwrap();
        assert!(selection.account.is_none());
        assert_eq!(selection.expected_team_id, None);
        let auth_token = Arc::new(Mutex::new(None));
        let socket_token = Arc::new(Mutex::new(None));
        let auth_token_for_probe = Arc::clone(&auth_token);
        let socket_token_for_probe = Arc::clone(&socket_token);
        let result = block_on(run_preflight_with(
            selection,
            move |token| {
                *auth_token_for_probe.lock().unwrap() = Some(token.expose().to_owned());
                async { Ok(auth_ok(None)) }
            },
            move |token| {
                *socket_token_for_probe.lock().unwrap() = Some(token.expose().to_owned());
                async { Ok(socket_ok()) }
            },
        ))
        .unwrap();
        assert!(result.socket_mode_ready());
        assert_eq!(auth_token.lock().unwrap().as_deref(), Some("xoxb-legacy"));
        assert_eq!(socket_token.lock().unwrap().as_deref(), Some("xapp-legacy"));
    }

    #[test]
    fn mapped_slack_preflight_rejects_unknown_or_partial_accounts_without_scalar_fallback() {
        let unknown = ChannelAccountId::new("unknown").unwrap();
        let unknown_error = resolve_slack_test_selection(&mapped_slack_pair(None), Some(&unknown))
            .err()
            .expect("unknown named account must be refused")
            .to_string();
        assert!(unknown_error.contains("not configured"));
        assert!(!unknown_error.contains("xoxb-work-secret"));

        let mut partial = mapped_slack_pair(None);
        partial.credentials.channel_accounts.slack.clear();
        partial.raw_credentials.channel_accounts.slack.clear();
        partial.credentials.slack_bot_token = Some(SecretString::from("xoxb-shadow"));
        partial.credentials.slack_app_token = Some(SecretString::from("xapp-shadow"));
        let work = ChannelAccountId::new("work").unwrap();
        let partial_error = resolve_slack_test_selection(&partial, Some(&work))
            .err()
            .expect("partial map must not fall back to scalar credentials")
            .to_string();
        assert!(partial_error.contains("account map is invalid"));
        assert!(!partial_error.contains("xoxb-shadow"));
    }

    #[test]
    fn credentials_only_slack_map_refuses_scalar_shadow_fallback() {
        let mut pair = RuntimeConfigPair {
            config: FreedomConfig::default(),
            raw_credentials: Credentials::default(),
            credentials: Credentials::default(),
        };
        let account = ChannelAccountId::new("work").unwrap();
        pair.credentials.channel_accounts.slack.insert(
            account.clone(),
            SlackAccountCredentials {
                bot_token: Some(SecretString::from("xoxb-map-only")),
                app_token: Some(SecretString::from("xapp-map-only")),
            },
        );
        pair.credentials.slack_bot_token = Some(SecretString::from("xoxb-shadow"));
        pair.credentials.slack_app_token = Some(SecretString::from("xapp-shadow"));

        let error = resolve_slack_test_selection(&pair, Some(&account))
            .err()
            .expect("credentials-only map must not use scalar shadows")
            .to_string();
        assert!(error.contains("account map is invalid"));
        assert!(!error.contains("xoxb-map-only"));
        assert!(!error.contains("xoxb-shadow"));
    }

    #[test]
    fn mapped_slack_send_selects_the_exact_account_before_the_injected_post_seam() {
        let work = ChannelAccountId::new("work").unwrap();
        let mut pair = mapped_slack_pair(None);
        add_second_named_slack_account(&mut pair);
        let observed = Arc::new(Mutex::new(None));
        let observed_for_post = Arc::clone(&observed);
        block_on(run_send_with(
            &pair,
            Some(&work),
            "C123",
            "hello",
            &OutputFormat::Json,
            move |token, channel, message| {
                *observed_for_post.lock().unwrap() =
                    Some((token.expose().to_owned(), channel, message));
                async { Ok(post_ok()) }
            },
        ))
        .unwrap();
        assert_eq!(
            observed.lock().unwrap().as_ref(),
            Some(&(
                "xoxb-work-secret".to_string(),
                "C123".to_string(),
                "hello".to_string()
            ))
        );
    }

    #[test]
    fn mapped_slack_send_refuses_missing_unknown_or_partial_accounts_before_post_selection() {
        let work = ChannelAccountId::new("work").unwrap();
        let missing = resolve_slack_send_selection(&mapped_slack_pair(None), None).unwrap_err();
        assert!(missing.to_string().contains("slack send --account"));

        let unknown = ChannelAccountId::new("unknown").unwrap();
        let unknown_error =
            resolve_slack_send_selection(&mapped_slack_pair(None), Some(&unknown)).unwrap_err();
        assert!(unknown_error.to_string().contains("not configured"));

        let mut partial = mapped_slack_pair(None);
        partial.credentials.channel_accounts.slack.clear();
        partial.raw_credentials.channel_accounts.slack.clear();
        partial.credentials.slack_bot_token = Some(SecretString::from("xoxb-shadow"));
        let post_calls = Arc::new(AtomicUsize::new(0));
        let post_calls_for_attempt = Arc::clone(&post_calls);
        let partial_error = block_on(run_send_with(
            &partial,
            Some(&work),
            "C123",
            "must not send",
            &OutputFormat::Json,
            move |_token, _channel, _message| {
                post_calls_for_attempt.fetch_add(1, Ordering::SeqCst);
                async { Ok(post_ok()) }
            },
        ))
        .unwrap_err();
        assert!(partial_error.to_string().contains("account map is invalid"));
        assert!(!partial_error.to_string().contains("xoxb-shadow"));
        assert_eq!(post_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn legacy_slack_send_uses_only_the_bot_token_and_rejects_an_account_selector() {
        let mut pair = RuntimeConfigPair {
            config: FreedomConfig::default(),
            raw_credentials: Credentials::default(),
            credentials: Credentials::default(),
        };
        pair.credentials.slack_bot_token = Some(SecretString::from("xoxb-legacy"));
        let token = resolve_slack_send_selection(&pair, None).unwrap();
        assert_eq!(token.expose(), "xoxb-legacy");
        let account = ChannelAccountId::new("work").unwrap();
        let error = resolve_slack_send_selection(&pair, Some(&account)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid for legacy scalar Slack")
        );
    }

    #[test]
    fn public_cli_parses_slack_test_account_selector() {
        let parsed = Cli::try_parse_from(["neoth", "slack", "test", "--account", "work"])
            .expect("public CLI must accept Slack account selector");
        assert!(matches!(
            parsed.command,
            Commands::Slack(SlackArgs {
                action: SlackAction::Test {
                    account: Some(account)
                },
                ..
            }) if account.as_str() == "work"
        ));
    }

    #[test]
    fn public_cli_parses_slack_send_account_selector() {
        let parsed = Cli::try_parse_from([
            "neoth",
            "slack",
            "send",
            "--account",
            "work",
            "--channel",
            "C123",
            "--message",
            "hello",
        ])
        .expect("public CLI must accept a Slack send account selector");
        assert!(matches!(
            parsed.command,
            Commands::Slack(SlackArgs {
                action: SlackAction::Send {
                    account: Some(account),
                    channel,
                    message,
                },
                ..
            }) if account.as_str() == "work" && channel == "C123" && message == "hello"
        ));
    }

    #[test]
    fn slack_test_errors_when_credentials_missing() {
        // Point HOME at a tempdir so the coherent pair loader sees no
        // configuration and returns empty first-run defaults, then the
        // explicit legacy-token check fires with an actionable message.
        let _env = crate::test_env::lock();
        let dir = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_user = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("HOME", dir.path());
            std::env::set_var("USERPROFILE", dir.path());
        }
        let args = SlackArgs {
            action: SlackAction::Test { account: None },
            output: OutputFormat::Json,
        };
        let r = block_on(run_slack(args));
        if let Some(v) = prev_home {
            unsafe { std::env::set_var("HOME", v) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
        if let Some(v) = prev_user {
            unsafe { std::env::set_var("USERPROFILE", v) };
        } else {
            unsafe { std::env::remove_var("USERPROFILE") };
        }
        let err = r.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("slack_bot_token") || msg.contains("slack_app_token"),
            "expected missing-token error, got: {msg}"
        );
    }

    #[test]
    fn slack_send_errors_with_actionable_message_when_bot_token_missing() {
        // Same HOME-redirect dance as the test above so we deterministically
        // see an empty credentials.yaml.
        let _env = crate::test_env::lock();
        let dir = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_user = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("HOME", dir.path());
            std::env::set_var("USERPROFILE", dir.path());
        }
        let args = SlackArgs {
            action: SlackAction::Send {
                account: None,
                channel: "#general".into(),
                message: "hello".into(),
            },
            output: OutputFormat::Json,
        };
        let r = block_on(run_slack(args));
        if let Some(v) = prev_home {
            unsafe { std::env::set_var("HOME", v) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
        if let Some(v) = prev_user {
            unsafe { std::env::set_var("USERPROFILE", v) };
        } else {
            unsafe { std::env::remove_var("USERPROFILE") };
        }
        let err = r.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("slack_bot_token"),
            "send must surface the missing bot-token error: {msg}"
        );
        // The error message must point the operator at the fix path.
        assert!(
            msg.contains("neoth init") || msg.contains("credentials.yaml"),
            "actionable hint missing: {msg}"
        );
    }
}
