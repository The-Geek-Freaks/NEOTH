//! `neoth slack test` — Slack credential pre-flight (A-7).
//!
//! Validates `xoxb-` bot token + `xapp-` app token by calling
//! `auth.test` + `apps.connections.open`. Returns the WSS URL Phase-2
//! socket-mode loop will dial, proving the operator's app config is
//! correct before the runtime loop lands.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::channels::slack_api;
use crate::cli::OutputFormat;
use crate::config::credentials::Credentials;

#[derive(Args, Debug, Clone)]
pub struct SlackArgs {
    #[command(subcommand)]
    pub action: SlackAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SlackAction {
    /// Auth-test the configured Slack tokens. Reads
    /// `credentials.yaml::slack_bot_token` + `slack_app_token`, calls
    /// Slack's `auth.test` + `apps.connections.open`, and reports the
    /// result. Phase-2 socket-mode loop will dial the WSS URL this
    /// returns.
    Test,
    /// Send a one-shot message to a Slack channel via `chat.postMessage`.
    /// Uses `credentials.yaml::slack_bot_token`. `channel` accepts an
    /// id (`Cxxxxxx`), a DM id (`Dxxxxxx`), or `#channel-name` (Slack
    /// resolves server-side). Returns the message timestamp (Slack's
    /// `ts`) so operators can correlate with later edits/reactions.
    Send {
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
        SlackAction::Test => run_test(&args.output).await,
        SlackAction::Send { channel, message } => run_send(&channel, &message, &args.output).await,
    }
}

async fn run_send(channel: &str, message: &str, output: &OutputFormat) -> Result<()> {
    let creds = Credentials::load().context("load credentials.yaml")?;
    let bot = creds.slack_bot_token.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no slack_bot_token in credentials.yaml. Run `neoth init --force` \
             or add it manually before sending."
        )
    })?;
    let result = slack_api::post_message(bot, channel, message)
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

async fn run_test(output: &OutputFormat) -> Result<()> {
    let creds = Credentials::load().context("load credentials.yaml")?;
    let bot = creds.slack_bot_token.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no slack_bot_token in credentials.yaml. Run `neoth init --force` \
             or add it manually."
        )
    })?;
    let app = creds.slack_app_token.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no slack_app_token in credentials.yaml. Socket mode requires \
             the xapp-... token. Add it via the Slack app's Basic Information \
             page → App-Level Tokens."
        )
    })?;

    let auth = slack_api::auth_test(bot).await?;
    let socket = slack_api::socket_mode_open(app).await?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "auth_test": auth,
                "socket_mode_open": socket,
                "phase2_ready": auth.ok && socket.ok,
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("# Slack pre-flight");
            if auth.ok {
                println!(
                    "  auth.test:           OK — team={} bot={} user={}",
                    auth.team.as_deref().unwrap_or("?"),
                    auth.bot_id.as_deref().unwrap_or("?"),
                    auth.user.as_deref().unwrap_or("?"),
                );
            } else {
                println!(
                    "  auth.test:           FAIL — {}",
                    auth.error.as_deref().unwrap_or("(no error)"),
                );
            }
            if socket.ok {
                println!("  apps.connections.open: OK");
                println!(
                    "    WSS URL (Phase 2 loop will dial this): {}",
                    socket.url.as_deref().unwrap_or("?"),
                );
            } else {
                println!(
                    "  apps.connections.open: FAIL — {}",
                    socket.error.as_deref().unwrap_or("(no error)"),
                );
            }
            println!();
            if auth.ok && socket.ok {
                println!(
                    "  Credentials valid. The Phase-2 socket-mode loop will \
                     consume these tokens without re-prompting."
                );
            } else {
                println!(
                    "  One or both calls failed — fix tokens in credentials.yaml \
                     before Phase 2 ships, otherwise the loop won't start."
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn slack_test_errors_when_credentials_missing() {
        // Point HOME at a tempdir so the credentials loader sees no
        // file + returns the default empty struct, then our explicit
        // check fires with the actionable message.
        let dir = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_user = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("HOME", dir.path());
            std::env::set_var("USERPROFILE", dir.path());
        }
        let args = SlackArgs {
            action: SlackAction::Test,
            output: OutputFormat::Json,
        };
        let r = run_slack(args).await;
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

    #[tokio::test]
    async fn slack_send_errors_with_actionable_message_when_bot_token_missing() {
        // Same HOME-redirect dance as the test above so we deterministically
        // see an empty credentials.yaml.
        let dir = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_user = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("HOME", dir.path());
            std::env::set_var("USERPROFILE", dir.path());
        }
        let args = SlackArgs {
            action: SlackAction::Send {
                channel: "#general".into(),
                message: "hello".into(),
            },
            output: OutputFormat::Json,
        };
        let r = run_slack(args).await;
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
