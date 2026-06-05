//! `neoth channel list` — read-only inventory of the messaging channels and
//! whether each is configured, parallel to `neoth provider list`.
//!
//! The configured-state predicates here are the SAME ones `cli/serve.rs` uses
//! to decide whether to actually start each channel, so `list` reflects reality
//! (a channel shown CONFIGURED is one the daemon would bring up). Pure +
//! read-only: no network, no mutation, no secrets printed (only presence).
//!
//! The mutating sub-actions (`add`/`test`/`remove`) stay deferred — the
//! credential-writing + live-connection-test surfaces are their own slices.
//! `list` is the safe inventory operators ask for first ("which channels are
//! wired right now?") without grepping `freedom.yaml` + `credentials.yaml`.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::cli::OutputFormat;
use crate::config::credentials::Credentials;
use crate::config::FreedomConfig;
use crate::secret::SecretString;

/// One channel's configured-state, derived purely from config + credentials.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelStatus {
    /// Stable channel id (`telegram`, `slack`, `whatsapp`, `keet`, `discord`).
    pub name: &'static str,
    /// True when the credentials the daemon needs to START this channel are
    /// present. Never reflects live reachability — that is `channel test`.
    pub configured: bool,
    /// Operator-readable note: what is set, or exactly what to set. Names the
    /// config/credential key — never the secret value.
    pub detail: String,
}

/// Honest configured-state of every messaging channel. Mirrors the
/// start-decision predicates in `cli/serve.rs` (Telegram bot token in
/// `freedom.yaml`; Slack/WhatsApp/Keet credentials in `credentials.yaml`).
/// PURE — same inputs always yield the same rows.
pub fn channel_statuses(cfg: &FreedomConfig, creds: &Credentials) -> Vec<ChannelStatus> {
    // Telegram — the bot token's durable home is credentials.yaml (the wizard +
    // `save_public_to_default_path` STRIP telegram_token from freedom.yaml, then
    // the runtime merges it back from credentials.yaml at load). So check the
    // credential store first; a manual freedom.yaml edit (cfg) also counts.
    let telegram = creds.telegram_token.is_some() || cfg.telegram_token.is_some();
    // Slack — socket mode needs BOTH the bot (xoxb) and app (xapp) tokens.
    let slack = creds.slack_bot_token.is_some() && creds.slack_app_token.is_some();
    // WhatsApp — access token + phone id are the minimum to send; the verify
    // token additionally unlocks the inbound webhook listener.
    let whatsapp = creds.whatsapp_token.is_some() && creds.whatsapp_phone_id.is_some();
    // Keet — the 24-word pairing phrase.
    let keet = creds.keet_seed_phrase.is_some();

    vec![
        ChannelStatus {
            name: "telegram",
            configured: telegram,
            detail: if telegram {
                "bot token set (credentials.yaml)".to_string()
            } else {
                "add via `neoth channel add telegram` (or `neoth init`, @BotFather)".to_string()
            },
        },
        ChannelStatus {
            name: "slack",
            configured: slack,
            detail: if slack {
                "bot (xoxb) + app (xapp) tokens set — socket mode".to_string()
            } else {
                "needs slack_bot_token (xoxb) + slack_app_token (xapp) in credentials.yaml".to_string()
            },
        },
        ChannelStatus {
            name: "whatsapp",
            configured: whatsapp,
            detail: if whatsapp {
                "access token + phone id set (whatsapp_verify_token enables inbound)".to_string()
            } else {
                "needs whatsapp_token + whatsapp_phone_id in credentials.yaml".to_string()
            },
        },
        ChannelStatus {
            name: "keet",
            configured: keet,
            detail: if keet {
                "24-word pairing phrase set".to_string()
            } else {
                "needs keet_seed_phrase (24-word pairing phrase) in credentials.yaml".to_string()
            },
        },
        // Discord ships an outbound adapter but has no credentials.yaml field
        // yet (serve.rs notes the inbound credential wiring is a follow-up), so
        // it is never CONFIGURED via the credential store today — say so plainly
        // rather than implying a path that doesn't exist.
        ChannelStatus {
            name: "discord",
            configured: false,
            detail: "outbound adapter present; no credentials.yaml field yet (inbound wiring is a follow-up)".to_string(),
        },
    ]
}

/// Count of configured channels — small helper the renderers share.
fn configured_count(rows: &[ChannelStatus]) -> usize {
    rows.iter().filter(|r| r.configured).count()
}

/// `neoth channel list` — load config + credentials, render the inventory.
/// Missing/unreadable files degrade to defaults (everything UNCONFIGURED), the
/// honest answer on a fresh install.
pub fn run_list(output: &OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
    let creds = Credentials::load_or_default(&crate::config::credentials::default_path())
        .unwrap_or_default();
    let rows = channel_statuses(&cfg, &creds);
    print!("{}", render(&rows, output)?);
    Ok(())
}

/// Render the inventory as table or JSON. Returned as a String so it is
/// unit-testable without capturing stdout.
fn render(rows: &[ChannelStatus], output: &OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let obj = serde_json::json!({
                "channels": rows,
                "configured": configured_count(rows),
                "total": rows.len(),
            });
            Ok(format!("{}\n", serde_json::to_string_pretty(&obj)?))
        }
        OutputFormat::Table => {
            let mut out = String::new();
            out.push_str("# Messaging channels\n\n");
            out.push_str(&format!("{:<10} {:<12}  detail\n", "channel", "status"));
            out.push_str(&format!(
                "{:<10} {:<12}  {}\n",
                "-".repeat(10),
                "-".repeat(12),
                "-".repeat(40)
            ));
            for r in rows {
                let status = if r.configured { "[configured]" } else { "[ off ]" };
                out.push_str(&format!("{:<10} {:<12}  {}\n", r.name, status, r.detail));
            }
            out.push_str(&format!(
                "\n{} of {} channels configured. Connect via `neoth init` / edit credentials.yaml.\n",
                configured_count(rows),
                rows.len()
            ));
            Ok(out)
        }
    }
}

// ── `neoth channel test <channel>` ────────────────────────────────────────

/// What `channel test <name>` does — decided purely from config + credentials
/// so the dispatch is unit-testable without touching the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelTestPlan {
    /// Unknown channel name.
    Unknown,
    /// Known channel, not configured (nothing to test).
    NotConfigured,
    /// Telegram `getMe` live check.
    Telegram,
    /// Slack `auth.test` live check.
    Slack,
    /// WhatsApp phone-node live check.
    Whatsapp,
    /// Keet — OFFLINE seed-phrase format validation (no network).
    KeetOffline,
    /// Discord — no credential field yet, not testable.
    DiscordNoCred,
}

/// Decide the test plan for `<name>`. PURE. Slack needs only the BOT token to
/// `auth.test` (the app token is for socket mode, not auth), so the test bar
/// is lower than the "startable" bar `channel_statuses` uses for slack.
pub fn plan_channel_test(name: &str, cfg: &FreedomConfig, creds: &Credentials) -> ChannelTestPlan {
    let yes_if = |configured: bool, yes: ChannelTestPlan| {
        if configured {
            yes
        } else {
            ChannelTestPlan::NotConfigured
        }
    };
    match name.trim().to_ascii_lowercase().as_str() {
        "telegram" => yes_if(
            cfg.telegram_token.is_some() || creds.telegram_token.is_some(),
            ChannelTestPlan::Telegram,
        ),
        "slack" => yes_if(creds.slack_bot_token.is_some(), ChannelTestPlan::Slack),
        "whatsapp" => yes_if(
            creds.whatsapp_token.is_some() && creds.whatsapp_phone_id.is_some(),
            ChannelTestPlan::Whatsapp,
        ),
        "keet" => yes_if(creds.keet_seed_phrase.is_some(), ChannelTestPlan::KeetOffline),
        "discord" => ChannelTestPlan::DiscordNoCred,
        _ => ChannelTestPlan::Unknown,
    }
}

/// Outcome of a channel test — render-agnostic + serde for `--output json`.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelTestResult {
    pub channel: String,
    /// `ok` (live check passed) / `fail` (live check failed) / `skipped`
    /// (not configured / not testable).
    pub status: &'static str,
    pub detail: String,
}

/// `neoth channel test <channel>` — live pre-flight for ONE channel: validate
/// the configured credentials actually work. Telegram/Slack/WhatsApp make a
/// read-only API call (getMe / auth.test / phone-node GET — no message sent,
/// nothing billed); Keet validates the seed phrase OFFLINE; Discord has no
/// credential field yet. The network calls delegate to the channel adapters
/// (already in the `no_outbound_network` allowlist) — this dispatcher stays
/// network-free + secret-free.
pub async fn run_test(name: &str, output: &OutputFormat) -> Result<()> {
    let cfg = FreedomConfig::load_from_default_path().unwrap_or_default();
    let creds = Credentials::load_or_default(&crate::config::credentials::default_path())
        .unwrap_or_default();
    let chan = name.trim().to_ascii_lowercase();

    let result = match plan_channel_test(&chan, &cfg, &creds) {
        ChannelTestPlan::Unknown => anyhow::bail!(
            "unknown channel `{name}`. Known: telegram, slack, whatsapp, keet, discord. \
             `neoth channel list` shows configured state."
        ),
        ChannelTestPlan::NotConfigured => skipped(
            chan,
            "not configured — `neoth channel list` shows what to set".to_string(),
        ),
        ChannelTestPlan::DiscordNoCred => skipped(
            chan,
            "no credentials.yaml field yet — outbound adapter only".to_string(),
        ),
        ChannelTestPlan::Telegram => {
            let ch = crate::channels::telegram::TelegramChannel::new(
                // The token may live in either store; the plan guarantees at least
                // one is Some, so the cfg-or-creds chain never hits the expect.
                cfg.telegram_token
                    .clone()
                    .or_else(|| creds.telegram_token.clone())
                    .expect("plan guarantees configured"),
                cfg.telegram_user_id,
            );
            match ch.validate().await {
                Ok(user) => ok(chan, format!("bot @{user}")),
                Err(e) => fail(chan, e.to_string()),
            }
        }
        ChannelTestPlan::Slack => {
            let bot = creds.slack_bot_token.clone().expect("plan guarantees configured");
            match crate::channels::slack_api::auth_test(&bot).await {
                Ok(r) if r.ok => ok(
                    chan,
                    format!(
                        "team {} as {}",
                        r.team.as_deref().unwrap_or("?"),
                        r.user.as_deref().unwrap_or("?")
                    ),
                ),
                Ok(r) => fail(chan, r.error.unwrap_or_else(|| "auth.test returned ok=false".into())),
                Err(e) => fail(chan, e.to_string()),
            }
        }
        ChannelTestPlan::Whatsapp => {
            let token = creds.whatsapp_token.clone().expect("plan guarantees configured");
            let phone = creds.whatsapp_phone_id.clone().expect("plan guarantees configured");
            match crate::channels::whatsapp_api::validate_token(&token, &phone).await {
                Ok(r) if r.ok => ok(
                    chan,
                    format!("number {}", r.display_phone_number.as_deref().unwrap_or("?")),
                ),
                Ok(r) => fail(chan, r.error.unwrap_or_else(|| "validate returned ok=false".into())),
                Err(e) => fail(chan, e.to_string()),
            }
        }
        ChannelTestPlan::KeetOffline => {
            let seed = creds.keet_seed_phrase.clone().expect("plan guarantees configured");
            let v = crate::channels::keet::validate_seed_phrase(seed.expose());
            if v.is_valid() {
                ok(chan, "valid 24-word pairing phrase (offline format check)".to_string())
            } else {
                fail(chan, format!("seed phrase invalid: {}", v.as_str()))
            }
        }
    };

    print!("{}", render_test(&result, output)?);
    Ok(())
}

fn ok(channel: String, detail: String) -> ChannelTestResult {
    ChannelTestResult { channel, status: "ok", detail }
}
fn fail(channel: String, detail: String) -> ChannelTestResult {
    ChannelTestResult { channel, status: "fail", detail }
}
fn skipped(channel: String, detail: String) -> ChannelTestResult {
    ChannelTestResult { channel, status: "skipped", detail }
}

fn render_test(r: &ChannelTestResult, output: &OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            Ok(format!("{}\n", serde_json::to_string_pretty(r)?))
        }
        OutputFormat::Table => {
            let glyph = match r.status {
                "ok" => "✓",
                "fail" => "✗",
                _ => "–",
            };
            Ok(format!("{glyph} {} — {}\n", r.channel, r.detail))
        }
    }
}

// ── `neoth channel add <channel>` ─────────────────────────────────────────

/// Per-channel inputs the operator supplied (read from stdin / no-echo prompt).
/// All optional so the validator reports exactly which required field is
/// missing rather than panicking.
#[derive(Debug, Default, Clone)]
pub struct ChannelAddFields {
    /// telegram bot token / whatsapp access token.
    pub token: Option<String>,
    /// slack bot token (`xoxb-…`).
    pub bot_token: Option<String>,
    /// slack app token (`xapp-…`).
    pub app_token: Option<String>,
    /// whatsapp phone-number id (numeric).
    pub phone_id: Option<String>,
    /// keet 24-word pairing phrase.
    pub seed: Option<String>,
}

fn require(v: &Option<String>, what: &str) -> Result<String> {
    match v.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => Ok(s.to_string()),
        None => anyhow::bail!("missing {what}"),
    }
}

/// Validate `fields` for `channel` and fold them into `base` credentials,
/// returning the updated [`Credentials`] ready to persist. PURE — no I/O, so
/// it is fully unit-tested. Existing credentials for OTHER channels are
/// preserved (only the named channel's fields are touched). Rejects
/// unknown/unsupported channels + missing/invalid fields with a clear message.
pub fn stage_channel_add(
    channel: &str,
    fields: &ChannelAddFields,
    base: Credentials,
) -> Result<Credentials> {
    let mut creds = base;
    match channel.trim().to_ascii_lowercase().as_str() {
        "telegram" => {
            let t = require(&fields.token, "telegram bot token (from @BotFather)")?;
            crate::cli::init::validate_telegram_token(&t)?;
            creds.telegram_token = Some(SecretString::from(t.as_str()));
        }
        "slack" => {
            let bot = require(&fields.bot_token, "slack bot token (xoxb-…)")?;
            let app = require(&fields.app_token, "slack app token (xapp-…)")?;
            if !bot.starts_with("xoxb-") {
                anyhow::bail!("slack bot token should start with `xoxb-`");
            }
            if !app.starts_with("xapp-") {
                anyhow::bail!("slack app token should start with `xapp-` (socket-mode app token)");
            }
            creds.slack_bot_token = Some(SecretString::from(bot.as_str()));
            creds.slack_app_token = Some(SecretString::from(app.as_str()));
        }
        "whatsapp" => {
            let t = require(&fields.token, "whatsapp access token")?;
            let phone = require(&fields.phone_id, "whatsapp phone-number id")?;
            if !phone.chars().all(|c| c.is_ascii_digit()) {
                anyhow::bail!(
                    "whatsapp phone id must be the NUMERIC phone-number id from the Meta console \
                     (not the phone number itself)"
                );
            }
            creds.whatsapp_token = Some(SecretString::from(t.as_str()));
            creds.whatsapp_phone_id = Some(phone);
        }
        "keet" => {
            let seed = require(&fields.seed, "keet 24-word pairing phrase")?;
            let v = crate::channels::keet::validate_seed_phrase(&seed);
            if !v.is_valid() {
                anyhow::bail!("keet seed phrase invalid: {}", v.as_str());
            }
            creds.keet_seed_phrase = Some(SecretString::from(seed.as_str()));
        }
        "discord" => anyhow::bail!(
            "discord has no credentials.yaml field yet — outbound adapter only; inbound \
             credential wiring is a follow-up"
        ),
        other => anyhow::bail!(
            "unknown channel `{other}`. Addable: telegram, slack, whatsapp, keet. \
             `neoth channel list` shows configured state."
        ),
    }
    Ok(creds)
}

/// `neoth channel add <channel>` — collect the channel's credential(s) and
/// persist them to `credentials.yaml` (the single durable secret store; the
/// runtime config merges it at load). Secrets are read with NO terminal echo
/// when stdin is an interactive TTY (and the `wizard` feature is built, the
/// release default); a piped/non-wizard stdin falls back to a plain line read
/// (`printf 'token\n' | neoth channel add telegram` works for scripting). The
/// secret value is never printed back — only a path + the next-step pointer.
pub async fn run_add(channel: &str, output: &OutputFormat) -> Result<()> {
    let chan = channel.trim().to_ascii_lowercase();
    let path = crate::config::credentials::default_path();
    let base = Credentials::load_or_default(&path).unwrap_or_default();

    // Reject discord/unknown BEFORE prompting (no point asking for a token we
    // can't store) — let the staging validator produce the precise message.
    if !matches!(chan.as_str(), "telegram" | "slack" | "whatsapp" | "keet") {
        stage_channel_add(&chan, &ChannelAddFields::default(), base)?;
        return Ok(()); // unreachable — the line above always errors for these
    }

    let fields = prompt_channel_fields(&chan)?;
    let updated = stage_channel_add(&chan, &fields, base)?;
    updated
        .write(&path)
        .with_context(|| format!("write credentials to {}", path.display()))?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "channel": chan,
                    "saved": true,
                    "path": path.display().to_string(),
                }))?
            );
        }
        OutputFormat::Table => {
            println!("✓ {chan} credentials saved (mode-0600) to {}", path.display());
            println!("  validate the credentials work: `neoth channel test {chan}`");
            println!("  start serving the channel:      `neoth serve`");
        }
    }
    Ok(())
}

/// Prompt for each field the channel needs. Prompts go to STDERR so stdout
/// stays clean for `--output json` / piping.
fn prompt_channel_fields(channel: &str) -> Result<ChannelAddFields> {
    let mut f = ChannelAddFields::default();
    match channel {
        "telegram" => f.token = Some(read_secret("Telegram bot token (from @BotFather)")?),
        "slack" => {
            f.bot_token = Some(read_secret("Slack bot token (xoxb-…)")?);
            f.app_token = Some(read_secret("Slack app token (xapp-…, socket mode)")?);
        }
        "whatsapp" => {
            f.token = Some(read_secret("WhatsApp access token")?);
            f.phone_id = Some(read_plain("WhatsApp phone-number id (numeric, from Meta console)")?);
        }
        "keet" => f.seed = Some(read_secret("Keet 24-word pairing phrase")?),
        _ => {}
    }
    Ok(f)
}

/// Read a SECRET field. No terminal echo on an interactive TTY (wizard build);
/// plain line read when piped or built without the `wizard` feature.
fn read_secret(prompt: &str) -> Result<String> {
    #[cfg(feature = "wizard")]
    {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            return dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(prompt)
                .interact()
                .context("read secret (hidden) input");
        }
    }
    read_plain(prompt)
}

/// Read a non-secret line from stdin (prompt to stderr).
fn read_plain(prompt: &str) -> Result<String> {
    use std::io::Write;
    eprint!("{prompt}: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context("read stdin")?;
    Ok(line.trim().to_string())
}

// ── `neoth channel remove <channel>` ──────────────────────────────────────

/// Clear `channel`'s credentials from `base`, returning the updated
/// [`Credentials`] + whether anything was actually configured (so the caller
/// can say "nothing to remove" rather than rewriting an unchanged file). PURE —
/// only the named channel's fields are cleared; other channels are untouched.
pub fn stage_channel_remove(channel: &str, base: Credentials) -> Result<(Credentials, bool)> {
    let mut creds = base;
    let removed = match channel.trim().to_ascii_lowercase().as_str() {
        "telegram" => {
            let had = creds.telegram_token.is_some();
            creds.telegram_token = None;
            had
        }
        "slack" => {
            let had = creds.slack_bot_token.is_some() || creds.slack_app_token.is_some();
            creds.slack_bot_token = None;
            creds.slack_app_token = None;
            had
        }
        "whatsapp" => {
            let had = creds.whatsapp_token.is_some() || creds.whatsapp_phone_id.is_some();
            creds.whatsapp_token = None;
            creds.whatsapp_phone_id = None;
            creds.whatsapp_verify_token = None;
            creds.whatsapp_app_secret = None;
            had
        }
        "keet" => {
            let had = creds.keet_seed_phrase.is_some();
            creds.keet_seed_phrase = None;
            had
        }
        // Discord stores no credential, so there is never anything to remove.
        "discord" => false,
        other => anyhow::bail!(
            "unknown channel `{other}`. Removable: telegram, slack, whatsapp, keet. \
             `neoth channel list` shows configured state."
        ),
    };
    Ok((creds, removed))
}

/// `neoth channel remove <channel>` — clear a channel's credentials from
/// credentials.yaml (atomic mode-0600 rewrite; the file is deleted when the
/// last credential is removed). No network. After removal `neoth serve` won't
/// start the channel.
pub fn run_remove(channel: &str, output: &OutputFormat) -> Result<()> {
    let chan = channel.trim().to_ascii_lowercase();
    let path = crate::config::credentials::default_path();
    let base = Credentials::load_or_default(&path).unwrap_or_default();
    let (updated, removed) = stage_channel_remove(&chan, base)?;

    if removed {
        updated
            .write(&path)
            .with_context(|| format!("rewrite credentials at {}", path.display()))?;
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "channel": chan,
                    "removed": removed,
                }))?
            );
        }
        OutputFormat::Table if removed => {
            println!("✓ removed {chan} credentials from {}", path.display());
            println!("  `neoth serve` will no longer start it. Re-add: `neoth channel add {chan}`");
        }
        OutputFormat::Table => {
            println!("– {chan} was not configured — nothing to remove.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds_empty() -> Credentials {
        Credentials::default()
    }

    #[test]
    fn fresh_install_has_no_configured_channels() {
        let rows = channel_statuses(&FreedomConfig::default(), &creds_empty());
        assert_eq!(rows.len(), 5, "telegram/slack/whatsapp/keet/discord");
        assert_eq!(configured_count(&rows), 0);
        // Every off channel names exactly how to set its credential.
        assert!(rows.iter().all(|r| !r.configured));
        assert!(rows.iter().find(|r| r.name == "telegram").unwrap().detail.contains("channel add telegram"));
    }

    #[test]
    fn telegram_configured_via_freedom_yaml_token() {
        let mut cfg = FreedomConfig::default();
        cfg.telegram_token = Some(SecretString::from("123:abc"));
        let rows = channel_statuses(&cfg, &creds_empty());
        let t = rows.iter().find(|r| r.name == "telegram").unwrap();
        assert!(t.configured);
        assert!(t.detail.contains("bot token set"));
        // No secret value ever leaks into the detail string.
        assert!(!t.detail.contains("123:abc"));
    }

    #[test]
    fn telegram_configured_via_credentials_store() {
        // Regression for the e2e-caught bug: telegram's durable token lives in
        // credentials.yaml (freedom.yaml strips it), so a creds-only token MUST
        // read as configured — both in the inventory and the test planner.
        let mut creds = creds_empty();
        creds.telegram_token = Some(SecretString::from("123:abc"));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(
            rows.iter().find(|r| r.name == "telegram").unwrap().configured,
            "credentials.yaml telegram_token must read as configured"
        );
        assert_eq!(
            plan_channel_test("telegram", &FreedomConfig::default(), &creds),
            ChannelTestPlan::Telegram
        );
    }

    #[test]
    fn slack_needs_both_bot_and_app_token() {
        let mut creds = creds_empty();
        creds.slack_bot_token = Some(SecretString::from("xoxb-1"));
        // Only the bot token → still NOT configured (socket mode needs both).
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(!rows.iter().find(|r| r.name == "slack").unwrap().configured);
        creds.slack_app_token = Some(SecretString::from("xapp-1"));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(rows.iter().find(|r| r.name == "slack").unwrap().configured);
    }

    #[test]
    fn whatsapp_needs_token_and_phone_id() {
        let mut creds = creds_empty();
        creds.whatsapp_token = Some(SecretString::from("EAA..."));
        assert!(!channel_statuses(&FreedomConfig::default(), &creds)
            .iter()
            .find(|r| r.name == "whatsapp")
            .unwrap()
            .configured);
        creds.whatsapp_phone_id = Some("1234567890".to_string());
        assert!(channel_statuses(&FreedomConfig::default(), &creds)
            .iter()
            .find(|r| r.name == "whatsapp")
            .unwrap()
            .configured);
    }

    #[test]
    fn keet_configured_by_seed_phrase_and_discord_always_off() {
        let mut creds = creds_empty();
        creds.keet_seed_phrase = Some(SecretString::from("word ".repeat(24)));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(rows.iter().find(|r| r.name == "keet").unwrap().configured);
        // Discord has no credential field → never reported configured.
        let d = rows.iter().find(|r| r.name == "discord").unwrap();
        assert!(!d.configured);
        assert!(d.detail.contains("no credentials.yaml field yet"));
    }

    #[test]
    fn plan_channel_test_routes_each_channel_purely() {
        let cfg = FreedomConfig::default();
        let creds = creds_empty();
        // Fresh install: known-but-unconfigured → NotConfigured; discord special; unknown.
        assert_eq!(plan_channel_test("telegram", &cfg, &creds), ChannelTestPlan::NotConfigured);
        assert_eq!(plan_channel_test("slack", &cfg, &creds), ChannelTestPlan::NotConfigured);
        assert_eq!(plan_channel_test("keet", &cfg, &creds), ChannelTestPlan::NotConfigured);
        assert_eq!(plan_channel_test("discord", &cfg, &creds), ChannelTestPlan::DiscordNoCred);
        assert_eq!(plan_channel_test("nope", &cfg, &creds), ChannelTestPlan::Unknown);

        // Telegram token → live plan; case-insensitive.
        let mut cfg2 = FreedomConfig::default();
        cfg2.telegram_token = Some(SecretString::from("t"));
        assert_eq!(plan_channel_test("telegram", &cfg2, &creds), ChannelTestPlan::Telegram);
        assert_eq!(plan_channel_test("TELEGRAM", &cfg2, &creds), ChannelTestPlan::Telegram);

        // Slack auth.test needs only the BOT token (app token is for socket mode).
        let mut creds_s = creds_empty();
        creds_s.slack_bot_token = Some(SecretString::from("xoxb"));
        assert_eq!(plan_channel_test("slack", &cfg, &creds_s), ChannelTestPlan::Slack);

        // WhatsApp needs BOTH token + phone id.
        let mut creds_w = creds_empty();
        creds_w.whatsapp_token = Some(SecretString::from("t"));
        assert_eq!(plan_channel_test("whatsapp", &cfg, &creds_w), ChannelTestPlan::NotConfigured);
        creds_w.whatsapp_phone_id = Some("123".to_string());
        assert_eq!(plan_channel_test("whatsapp", &cfg, &creds_w), ChannelTestPlan::Whatsapp);

        // Keet seed → offline plan.
        let mut creds_k = creds_empty();
        creds_k.keet_seed_phrase = Some(SecretString::from("x"));
        assert_eq!(plan_channel_test("keet", &cfg, &creds_k), ChannelTestPlan::KeetOffline);
    }

    #[test]
    fn render_test_table_and_json() {
        let r = ChannelTestResult {
            channel: "telegram".to_string(),
            status: "ok",
            detail: "bot @neoth".to_string(),
        };
        assert!(render_test(&r, &OutputFormat::Table).unwrap().contains("✓ telegram"));
        let j: serde_json::Value =
            serde_json::from_str(&render_test(&r, &OutputFormat::Json).unwrap()).unwrap();
        assert_eq!(j["status"], "ok");
        assert_eq!(j["channel"], "telegram");
        // A failed/skipped status renders its own glyph.
        let f = ChannelTestResult { channel: "slack".to_string(), status: "fail", detail: "bad token".to_string() };
        assert!(render_test(&f, &OutputFormat::Table).unwrap().starts_with("✗"));
        let s = ChannelTestResult { channel: "discord".to_string(), status: "skipped", detail: "no field".to_string() };
        assert!(render_test(&s, &OutputFormat::Table).unwrap().starts_with("–"));
    }

    fn valid_tg_token() -> String {
        // 9-digit id (in the 8-12 range) + 35 [a-z] chars.
        format!("123456789:{}", "a".repeat(35))
    }

    #[test]
    fn stage_add_telegram_validates_and_stores_token() {
        let f = ChannelAddFields { token: Some(valid_tg_token()), ..Default::default() };
        let c = stage_channel_add("telegram", &f, Credentials::default()).unwrap();
        assert_eq!(c.telegram_token.as_ref().unwrap().expose(), valid_tg_token());
    }

    #[test]
    fn stage_add_telegram_rejects_bad_and_missing() {
        let bad = ChannelAddFields { token: Some("not-a-token".into()), ..Default::default() };
        assert!(stage_channel_add("telegram", &bad, Credentials::default()).is_err());
        let e = stage_channel_add("telegram", &ChannelAddFields::default(), Credentials::default())
            .unwrap_err();
        assert!(e.to_string().contains("missing"));
    }

    #[test]
    fn stage_add_slack_needs_both_tokens_with_prefixes() {
        let only_bot = ChannelAddFields { bot_token: Some("xoxb-1".into()), ..Default::default() };
        assert!(stage_channel_add("slack", &only_bot, Credentials::default()).is_err());
        let wrong_prefix = ChannelAddFields {
            bot_token: Some("nope".into()),
            app_token: Some("xapp-1".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("slack", &wrong_prefix, Credentials::default()).is_err());
        let good = ChannelAddFields {
            bot_token: Some("xoxb-1".into()),
            app_token: Some("xapp-1".into()),
            ..Default::default()
        };
        let c = stage_channel_add("slack", &good, Credentials::default()).unwrap();
        assert!(c.slack_bot_token.is_some() && c.slack_app_token.is_some());
    }

    #[test]
    fn stage_add_whatsapp_requires_numeric_phone_id() {
        let nonnum = ChannelAddFields {
            token: Some("EAAtoken".into()),
            phone_id: Some("not-numeric".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("whatsapp", &nonnum, Credentials::default()).is_err());
        let good = ChannelAddFields {
            token: Some("EAAtoken".into()),
            phone_id: Some("1234567890".into()),
            ..Default::default()
        };
        let c = stage_channel_add("whatsapp", &good, Credentials::default()).unwrap();
        assert_eq!(c.whatsapp_phone_id.as_deref(), Some("1234567890"));
        assert!(c.whatsapp_token.is_some());
    }

    #[test]
    fn stage_add_keet_validates_seed_phrase() {
        let bad = ChannelAddFields { seed: Some("too short".into()), ..Default::default() };
        assert!(stage_channel_add("keet", &bad, Credentials::default()).is_err());
        // 24 valid lowercase words (3-8 chars, [a-z]).
        let good_seed = vec!["abandon"; 24].join(" ");
        let good = ChannelAddFields { seed: Some(good_seed), ..Default::default() };
        assert!(stage_channel_add("keet", &good, Credentials::default()).unwrap().keet_seed_phrase.is_some());
    }

    #[test]
    fn stage_add_rejects_discord_and_unknown() {
        assert!(stage_channel_add("discord", &ChannelAddFields::default(), Credentials::default()).is_err());
        assert!(stage_channel_add("bogus", &ChannelAddFields::default(), Credentials::default()).is_err());
    }

    #[test]
    fn stage_add_preserves_other_channels() {
        let mut base = Credentials::default();
        base.telegram_token = Some(SecretString::from(valid_tg_token().as_str()));
        let f = ChannelAddFields {
            bot_token: Some("xoxb-1".into()),
            app_token: Some("xapp-1".into()),
            ..Default::default()
        };
        let c = stage_channel_add("slack", &f, base).unwrap();
        assert!(c.telegram_token.is_some(), "existing telegram must be preserved");
        assert!(c.slack_bot_token.is_some(), "new slack must be added");
    }

    #[test]
    fn stage_remove_clears_only_the_named_channel() {
        // Start with telegram + slack configured.
        let mut base = Credentials::default();
        base.telegram_token = Some(SecretString::from(valid_tg_token().as_str()));
        base.slack_bot_token = Some(SecretString::from("xoxb-1"));
        base.slack_app_token = Some(SecretString::from("xapp-1"));
        let (c, removed) = stage_channel_remove("slack", base).unwrap();
        assert!(removed);
        assert!(c.slack_bot_token.is_none() && c.slack_app_token.is_none(), "slack cleared");
        assert!(c.telegram_token.is_some(), "telegram untouched");
    }

    #[test]
    fn stage_remove_reports_false_when_nothing_configured() {
        let (_, removed) = stage_channel_remove("telegram", Credentials::default()).unwrap();
        assert!(!removed);
        // Discord never stores anything → always false, never an error.
        let (_, d) = stage_channel_remove("discord", Credentials::default()).unwrap();
        assert!(!d);
    }

    #[test]
    fn stage_remove_clears_all_whatsapp_fields() {
        let mut base = Credentials::default();
        base.whatsapp_token = Some(SecretString::from("EAA"));
        base.whatsapp_phone_id = Some("123".to_string());
        base.whatsapp_verify_token = Some(SecretString::from("v"));
        base.whatsapp_app_secret = Some(SecretString::from("s"));
        let (c, removed) = stage_channel_remove("whatsapp", base).unwrap();
        assert!(removed);
        assert!(c.whatsapp_token.is_none() && c.whatsapp_phone_id.is_none());
        assert!(c.whatsapp_verify_token.is_none() && c.whatsapp_app_secret.is_none());
    }

    #[test]
    fn stage_remove_rejects_unknown_channel() {
        assert!(stage_channel_remove("bogus", Credentials::default()).is_err());
    }

    #[test]
    fn render_table_and_json_reflect_configured_count() {
        let mut cfg = FreedomConfig::default();
        cfg.telegram_token = Some(SecretString::from("t"));
        let rows = channel_statuses(&cfg, &creds_empty());
        let table = render(&rows, &OutputFormat::Table).unwrap();
        assert!(table.contains("[configured]"));
        assert!(table.contains("1 of 5 channels configured"));
        let json = render(&rows, &OutputFormat::Json).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["configured"], 1);
        assert_eq!(v["total"], 5);
        assert_eq!(v["channels"][0]["name"], "telegram");
        assert_eq!(v["channels"][0]["configured"], true);
    }
}
