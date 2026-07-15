//! `neoth channel list` — read-only inventory of the messaging channels and
//! whether each is configured, parallel to `neoth provider list`.
//!
//! The configured-state predicates are driven by `channels/probe.rs` via
//! [`probe_all`], so `list` always agrees with `neoth status`. Pure +
//! read-only: no network, no mutation, no secrets printed (only presence).
//!
//! The mutating sub-actions (`add`/`test`/`remove`) cover all 15 registered
//! channel kinds; `list` drives from the same probe as `neoth status`.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::channels::probe::{ChannelCredsView, ProbeStatus, probe_all};
use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::credentials::Credentials;
use crate::secret::SecretString;

/// One channel's configured-state, derived purely from config + credentials.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelStatus {
    /// Stable channel id (`telegram`, `slack`, `whatsapp`, `discord`, ...).
    pub name: &'static str,
    /// Canonical probe verdict. This distinguishes complete, degraded,
    /// broken, unavailable, and absent adapters in every output format.
    pub status: ProbeStatus,
    /// True when the credentials the daemon needs to START this channel are
    /// present. Compatibility field; prefer `status` for new consumers. Never
    /// reflects live reachability — that is `channel test`.
    pub configured: bool,
    /// Operator-readable note: what is set, or exactly what to set. Names the
    /// config/credential key — never the secret value.
    pub detail: String,
}

/// Honest configured-state of every messaging channel. Delegates to
/// [`probe_all`] so the predicates are always in sync with `neoth status`
/// and the `channels/probe.rs` registry. PURE — same inputs always yield
/// the same rows. `configured` is true when the probe status is anything
/// other than `NotConfigured` or `Unavailable` (includes partial errors so
/// operators can see credentials that need repair).
pub fn channel_statuses(cfg: &FreedomConfig, creds: &Credentials) -> Vec<ChannelStatus> {
    let view = ChannelCredsView::from_config(Some(cfg), creds);
    probe_all(&view)
        .into_iter()
        .map(|h| ChannelStatus {
            name: h.channel,
            status: h.status,
            configured: !matches!(
                h.status,
                ProbeStatus::NotConfigured | ProbeStatus::Unavailable
            ),
            detail: h.message,
        })
        .collect()
}

/// Count of configured channels — small helper the renderers share.
fn configured_count(rows: &[ChannelStatus]) -> usize {
    rows.iter().filter(|r| r.configured).count()
}

/// `neoth channel list` — load config + credentials, render the inventory.
/// A missing credentials file is fine (fresh install). A bad file is an error
/// — silent fallback would hide operator-visible corruption.
pub fn run_list(output: &OutputFormat) -> Result<()> {
    run_list_at(&FreedomConfig::default_neoth_home(), output)
}

fn run_list_at(home: &std::path::Path, output: &OutputFormat) -> Result<()> {
    let rows = load_channel_statuses_at(home)?;
    print!("{}", render(&rows, output)?);
    Ok(())
}

pub(crate) fn load_channel_statuses_at(home: &std::path::Path) -> Result<Vec<ChannelStatus>> {
    let config_path = home.join("freedom.yaml");
    let credentials_path = home.join("credentials.yaml");
    let cfg = FreedomConfig::load_from_path_or_default(&config_path)?;
    let creds =
        Credentials::load_effective(&credentials_path, cfg.secrets_backend).with_context(|| {
            format!(
                "load effective credentials at {} — file/keychain cannot be read; \
                 repair it before running `neoth channel list`",
                credentials_path.display()
            )
        })?;
    Ok(channel_statuses(&cfg, &creds))
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
            out.push_str(&format!("{:<22} {:<18}  detail\n", "channel", "status"));
            out.push_str(&format!(
                "{:<22} {:<18}  {}\n",
                "-".repeat(22),
                "-".repeat(18),
                "-".repeat(40)
            ));
            for r in rows {
                let status = format!("{} {}", r.status.glyph(), r.status.as_str());
                out.push_str(&format!("{:<22} {:<18}  {}\n", r.name, status, r.detail));
            }
            out.push_str(&format!(
                "\n{} of {} channels configured. Use `neoth channel add <name>` and `neoth channel test <name>`.\n",
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
    /// Repository-owned Baileys sidecar authenticated health check.
    WhatsappBaileys,
    /// Authenticated Keet companion full-duplex + joined-topic check.
    Keet,
    /// Discord `GET /users/@me` live identity check.
    Discord,
    /// Read-only signal-cli registered-account check.
    Signal,
    /// Read-only LINE bot identity check.
    Line,
    /// IRC has no side-effect-free authentication probe.
    Irc,
    /// Authenticated BlueBubbles ping.
    IMessageBlueBubbles,
    /// Read-only Mattermost current-user identity check.
    Mattermost,
    /// Read-only Google Pub/Sub subscription check.
    GoogleChat,
    /// Matrix `/account/whoami` token check; password-only auth is unavailable.
    Matrix,
    /// Twitch OAuth identity + scope validation.
    Twitch,
    /// Nostr relay WebSocket reachability without subscribe/publish.
    Nostr,
}

/// Decide the test plan for `<name>`. PURE. Slack needs only the BOT token to
/// `auth.test` (the app token is for socket mode, not auth), so the test bar
/// is lower than the "startable" bar `channel_statuses` uses for slack.
pub fn plan_channel_test(name: &str, cfg: &FreedomConfig, creds: &Credentials) -> ChannelTestPlan {
    let view = ChannelCredsView::from_config(Some(cfg), creds);
    let yes_if = |configured: bool, yes: ChannelTestPlan| {
        if configured {
            yes
        } else {
            ChannelTestPlan::NotConfigured
        }
    };
    match name.trim().to_ascii_lowercase().as_str() {
        "telegram" => yes_if(view.telegram_token, ChannelTestPlan::Telegram),
        "slack" => yes_if(view.slack_bot, ChannelTestPlan::Slack),
        "whatsapp" => yes_if(
            view.whatsapp_token && view.whatsapp_phone_id,
            ChannelTestPlan::Whatsapp,
        ),
        "keet" => yes_if(
            view.keet_bridge_url
                && view.keet_topic
                && view.keet_allowed_senders
                && view.keet_bearer,
            ChannelTestPlan::Keet,
        ),
        "discord" => yes_if(view.discord_bot, ChannelTestPlan::Discord),
        "signal" => yes_if(
            view.signal_cli_url && view.signal_phone_number,
            ChannelTestPlan::Signal,
        ),
        "line" => yes_if(
            view.line_access_token || view.line_channel_secret,
            ChannelTestPlan::Line,
        ),
        "irc" => yes_if(view.irc_server && view.irc_nick, ChannelTestPlan::Irc),
        "imessage" | "imessage_bluebubbles" | "bluebubbles" => yes_if(
            view.bluebubbles_url && view.bluebubbles_password,
            ChannelTestPlan::IMessageBlueBubbles,
        ),
        "mattermost" => yes_if(
            view.mattermost_url && view.mattermost_token,
            ChannelTestPlan::Mattermost,
        ),
        "gchat" | "google_chat" => yes_if(
            view.gchat_sa_json && view.gchat_subscription,
            ChannelTestPlan::GoogleChat,
        ),
        "matrix" => yes_if(
            view.matrix_homeserver && view.matrix_user_id && view.matrix_login,
            ChannelTestPlan::Matrix,
        ),
        "twitch" => yes_if(
            view.twitch_username && view.twitch_oauth && view.twitch_channels,
            ChannelTestPlan::Twitch,
        ),
        "nostr" => yes_if(view.nostr_key && view.nostr_relays, ChannelTestPlan::Nostr),
        // Aliases for probe-canonical names.
        "whatsapp_business" => yes_if(
            view.whatsapp_token && view.whatsapp_phone_id,
            ChannelTestPlan::Whatsapp,
        ),
        "whatsapp_baileys" => yes_if(
            view.whatsapp_baileys_url
                && view.whatsapp_baileys_token
                && view.whatsapp_baileys_allowed_senders,
            ChannelTestPlan::WhatsappBaileys,
        ),
        _ => ChannelTestPlan::Unknown,
    }
}

/// Outcome of a channel test — render-agnostic + serde for `--output json`.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelTestResult {
    pub channel: String,
    /// `ok` (live check passed) / `fail` (live check failed) / `skipped`
    /// (not configured) / `unavailable` (no safe live probe or missing runtime).
    pub status: &'static str,
    pub detail: String,
}

/// `neoth channel test <channel>` — live pre-flight for ONE channel: validate
/// the configured credentials actually work. Every live check is read-only:
/// no test chat is sent, no inbound queue is consumed, and no relay event is
/// published. Protocols that cannot prove auth without side effects return a
/// typed `unavailable` result. The network calls delegate to channel adapters
/// (already in the `no_outbound_network` allowlist) — this dispatcher stays
/// network-free + secret-free.
pub async fn run_test(name: &str, output: &OutputFormat) -> Result<()> {
    let result = test_channel(name).await?;
    print!("{}", render_test(&result, output)?);
    match channel_test_exit_code(result.status) {
        None => Ok(()),
        Some(code) => Err(crate::QuietExit(code).into()),
    }
}

/// Process status contract for scripts/installers: a live success is zero, a
/// completed-but-failed probe is 1, and an unavailable/skipped probe is 2.
/// Unknown future states fail closed as 1.
fn channel_test_exit_code(status: &str) -> Option<i32> {
    match status {
        "ok" => None,
        "skipped" | "unavailable" => Some(2),
        _ => Some(1),
    }
}

/// Render-free channel verification for slash/GUI callers. A failed live
/// credential check remains a typed `status = "fail"` result so callers can
/// refuse to claim the channel was connected.
pub(crate) async fn test_channel(name: &str) -> Result<ChannelTestResult> {
    test_channel_at(&FreedomConfig::default_neoth_home(), name).await
}

/// Home-scoped credential verification for action/GUI callers. Config and
/// credentials both fail closed; a corrupt freedom.yaml must never be replaced
/// by permissive defaults while deciding which credential is active.
pub(crate) async fn test_channel_at(
    home: &std::path::Path,
    name: &str,
) -> Result<ChannelTestResult> {
    let config_path = home.join("freedom.yaml");
    let credentials_path = home.join("credentials.yaml");
    let cfg = FreedomConfig::load_from_path(&config_path)
        .with_context(|| format!("load config at {}", config_path.display()))?;
    let creds =
        Credentials::load_effective(&credentials_path, cfg.secrets_backend).with_context(|| {
            format!(
                "load effective credentials at {} — file/keychain cannot be read; \
             repair it before running `neoth channel test`",
                credentials_path.display()
            )
        })?;
    let chan = name.trim().to_ascii_lowercase();

    let result = match plan_channel_test(&chan, &cfg, &creds) {
        ChannelTestPlan::Unknown => anyhow::bail!(
            "unknown channel `{name}`. Known: telegram, slack, whatsapp_business, \
             whatsapp_baileys, keet, discord, signal, line, irc, imessage_bluebubbles, \
             mattermost, gchat, matrix, twitch, nostr \
             (aliases: whatsapp, google_chat, imessage, bluebubbles). \
             `neoth channel list` shows configured state."
        ),
        ChannelTestPlan::NotConfigured => skipped(
            chan,
            "not configured — `neoth channel list` shows what to set".to_string(),
        ),
        ChannelTestPlan::Keet => {
            let url = creds
                .keet_bridge_url
                .as_deref()
                .expect("plan guarantees configured");
            let token = creds
                .keet_bridge_bearer_token
                .clone()
                .expect("plan guarantees configured");
            let topic = creds
                .keet_topic
                .as_ref()
                .map(|topic| topic.expose())
                .expect("plan guarantees configured");
            match crate::channels::keet::probe_bridge(url, token, topic).await {
                Ok(_) => ok(
                    chan,
                    "authenticated companion is ready, full-duplex, and joined to the configured topic"
                        .to_string(),
                ),
                Err(error) => fail(chan, error.to_string()),
            }
        }
        ChannelTestPlan::Signal => {
            let url = creds
                .signal_cli_url
                .as_deref()
                .expect("plan guarantees configured");
            let number = creds
                .signal_phone_number
                .as_deref()
                .expect("plan guarantees configured");
            match crate::channels::signal_api::probe_registration(url, number).await {
                Ok(detail) => ok(chan, detail),
                Err(error) => fail(chan, error.to_string()),
            }
        }
        ChannelTestPlan::Line => {
            let Some(token) = creds.line_channel_access_token.as_ref() else {
                return Ok(fail(
                    chan,
                    "LINE channel secret is present, but line_channel_access_token is missing"
                        .to_string(),
                ));
            };
            if creds.line_channel_secret.is_none() {
                return Ok(fail(
                    chan,
                    "LINE token may send, but line_channel_secret is missing; inbound webhook signatures cannot be verified"
                        .to_string(),
                ));
            }
            match crate::channels::line_api::probe_bot_info(token).await {
                Ok(detail) => ok(chan, detail),
                Err(error) => fail(chan, error.to_string()),
            }
        }
        ChannelTestPlan::Irc => unavailable(
            chan,
            if cfg!(feature = "irc-channel") {
                "IRC has no protocol-defined side-effect-free credential probe; registering the configured nick could collide with the live adapter, so use daemon runtime status"
            } else {
                "this binary lacks the `irc-channel` runtime feature"
            }
            .to_string(),
        ),
        ChannelTestPlan::IMessageBlueBubbles => {
            let channel = crate::channels::imessage_bluebubbles::BlueBubblesChannel::new(
                creds
                    .bluebubbles_url
                    .clone()
                    .expect("plan guarantees configured"),
                creds
                    .bluebubbles_password
                    .clone()
                    .expect("plan guarantees configured"),
                None,
                None,
            )
            .context("build BlueBubbles channel for readiness probe")?;
            match channel.probe_readiness().await {
                Ok(detail) => ok(chan, detail),
                Err(error) => fail(chan, error.to_string()),
            }
        }
        ChannelTestPlan::Mattermost => {
            let url = creds
                .mattermost_url
                .as_deref()
                .expect("plan guarantees configured");
            let token = creds
                .mattermost_token
                .as_ref()
                .expect("plan guarantees configured");
            match crate::channels::mattermost_api::probe_identity(url, token).await {
                Ok((id, username)) => ok(chan, format!("authenticated as @{username} ({id})")),
                Err(error) => fail(chan, error.to_string()),
            }
        }
        ChannelTestPlan::GoogleChat => {
            #[cfg(feature = "gchat-channel")]
            {
                let path = std::path::Path::new(
                    creds
                        .gchat_service_account_json
                        .as_deref()
                        .expect("plan guarantees configured"),
                );
                let subscription = creds
                    .gchat_subscription
                    .clone()
                    .expect("plan guarantees configured");
                match crate::channels::gchat::GChatChannel::new(path, subscription) {
                    Ok(channel) => match channel.probe_subscription().await {
                        Ok(detail) => ok(chan, detail),
                        Err(error) => fail(chan, error.to_string()),
                    },
                    Err(error) => fail(chan, error.to_string()),
                }
            }
            #[cfg(not(feature = "gchat-channel"))]
            {
                unavailable(
                    chan,
                    "this binary lacks the `gchat-channel` runtime feature".to_string(),
                )
            }
        }
        ChannelTestPlan::Matrix => {
            #[cfg(feature = "matrix-channel")]
            {
                let homeserver = creds
                    .matrix_homeserver
                    .as_deref()
                    .expect("plan guarantees configured");
                let user_id = creds
                    .matrix_user_id
                    .as_deref()
                    .expect("plan guarantees configured");
                match creds.matrix_access_token.as_ref() {
                    Some(token) => match crate::channels::matrix_client::probe_access_token(
                        homeserver, user_id, token,
                    )
                    .await
                    {
                        Ok(detail) => ok(chan, detail),
                        Err(error) => fail(chan, error.to_string()),
                    },
                    None => unavailable(
                        chan,
                        "Matrix password login creates device/session state; a read-only live probe requires matrix_access_token"
                            .to_string(),
                    ),
                }
            }
            #[cfg(not(feature = "matrix-channel"))]
            {
                unavailable(
                    chan,
                    "this binary lacks the `matrix-channel` runtime feature".to_string(),
                )
            }
        }
        ChannelTestPlan::Twitch => {
            let username = creds
                .twitch_username
                .as_deref()
                .expect("plan guarantees configured");
            let token = creds
                .twitch_oauth_token
                .as_ref()
                .expect("plan guarantees configured");
            match crate::channels::readiness::probe_twitch(username, token).await {
                Ok(detail) if cfg!(feature = "irc-channel") => ok(chan, detail),
                Ok(detail) => unavailable(
                    chan,
                    format!("{detail}; this binary lacks the `irc-channel` runtime feature"),
                ),
                Err(error) => fail(chan, error.to_string()),
            }
        }
        ChannelTestPlan::Nostr => {
            #[cfg(feature = "nostr-channel")]
            {
                let key = creds
                    .nostr_secret_key
                    .as_ref()
                    .expect("plan guarantees configured");
                let relays = creds
                    .nostr_relays
                    .as_deref()
                    .expect("plan guarantees configured");
                match crate::channels::nostr::probe_relays(key, relays).await {
                    Ok(detail) => ok(chan, detail),
                    Err(error) => fail(chan, error.to_string()),
                }
            }
            #[cfg(not(feature = "nostr-channel"))]
            {
                unavailable(
                    chan,
                    "this binary lacks the `nostr-channel` runtime feature".to_string(),
                )
            }
        }
        ChannelTestPlan::Telegram => {
            if cfg.telegram_user_id.is_none() {
                return Ok(fail(
                    chan,
                    "telegram_user_id is missing; NEOTH refuses an open inbound Telegram adapter"
                        .to_string(),
                ));
            }
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
            let bot = creds
                .slack_bot_token
                .clone()
                .expect("plan guarantees configured");
            match crate::channels::slack_api::auth_test(&bot).await {
                Ok(r) if r.ok => ok(
                    chan,
                    format!(
                        "team {} as {}",
                        r.team.as_deref().unwrap_or("?"),
                        r.user.as_deref().unwrap_or("?")
                    ),
                ),
                Ok(r) => fail(
                    chan,
                    r.error
                        .unwrap_or_else(|| "auth.test returned ok=false".into()),
                ),
                Err(e) => fail(chan, e.to_string()),
            }
        }
        ChannelTestPlan::Discord => {
            let token = creds
                .discord_bot_token
                .clone()
                .expect("plan guarantees configured");
            let channel = crate::channels::discord::DiscordChannel::new(token)
                .context("build Discord channel for live identity test")?;
            match channel.validate_bot().await {
                Ok(identity) => {
                    let display = identity
                        .global_name
                        .as_deref()
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or(&identity.username);
                    ok(chan, format!("bot {display} ({})", identity.id))
                }
                Err(e) => fail(chan, e.to_string()),
            }
        }
        ChannelTestPlan::Whatsapp => {
            let token = creds
                .whatsapp_token
                .clone()
                .expect("plan guarantees configured");
            let phone = creds
                .whatsapp_phone_id
                .clone()
                .expect("plan guarantees configured");
            match crate::channels::whatsapp_api::validate_token(&token, &phone).await {
                Ok(r) if r.ok => ok(
                    chan,
                    format!(
                        "number {}",
                        r.display_phone_number.as_deref().unwrap_or("?")
                    ),
                ),
                Ok(r) => fail(
                    chan,
                    r.error
                        .unwrap_or_else(|| "validate returned ok=false".into()),
                ),
                Err(e) => fail(chan, e.to_string()),
            }
        }
        ChannelTestPlan::WhatsappBaileys => {
            let url = creds
                .whatsapp_baileys_url
                .as_deref()
                .expect("plan guarantees configured");
            let token = creds
                .whatsapp_baileys_token
                .clone()
                .expect("plan guarantees configured");
            match crate::channels::whatsapp_baileys::probe_bridge(url, token).await {
                Ok(health) if health.connected && health.linked => ok(
                    chan,
                    format!(
                        "bridge connected as {} at cursor {}",
                        health.account_id.as_deref().unwrap_or("?"),
                        health.latest_cursor
                    ),
                ),
                Ok(_) => fail(
                    chan,
                    "bridge authenticated but WhatsApp is not paired/connected; scan its QR"
                        .to_string(),
                ),
                Err(e) => fail(chan, e.to_string()),
            }
        }
    };

    Ok(result)
}

fn ok(channel: String, detail: String) -> ChannelTestResult {
    ChannelTestResult {
        channel,
        status: "ok",
        detail,
    }
}
fn fail(channel: String, detail: String) -> ChannelTestResult {
    // P1 — run the provider's error text through the secret redactor before it
    // reaches the operator-visible result. Meta/Slack/Telegram normally don't
    // echo token fragments in errors, but a trust product must not assume: a
    // bearer token / key / id pattern in the error becomes `[REDACTED:<kind>]`.
    let detail = crate::security::redact::redact_text(&detail);
    ChannelTestResult {
        channel,
        status: "fail",
        detail,
    }
}
fn skipped(channel: String, detail: String) -> ChannelTestResult {
    ChannelTestResult {
        channel,
        status: "skipped",
        detail,
    }
}

fn unavailable(channel: String, detail: String) -> ChannelTestResult {
    ChannelTestResult {
        channel,
        status: "unavailable",
        detail,
    }
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
                "unavailable" => "⊘",
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
    /// Telegram's exact numeric inbound sender allowlist. It is public policy
    /// and therefore persisted in freedom.yaml, not credentials.yaml.
    pub telegram_user_id: Option<u64>,
    /// telegram bot token / whatsapp access token / discord bot token /
    /// line channel access token / mattermost token.
    pub token: Option<String>,
    /// slack bot token (`xoxb-…`).
    pub bot_token: Option<String>,
    /// slack app token (`xapp-…`).
    pub app_token: Option<String>,
    /// whatsapp phone-number id (numeric).
    pub phone_id: Option<String>,
    /// WhatsApp webhook verification token (inbound challenge).
    pub verify_token: Option<String>,
    /// WhatsApp Meta app secret (inbound HMAC verification).
    pub app_secret: Option<String>,
    /// Deprecated speculative native-Keet seed flag retained for parse
    /// compatibility. The companion integration rejects it.
    pub seed: Option<String>,
    /// B9 — base URL (signal-cli daemon / BlueBubbles server / Mattermost).
    pub url: Option<String>,
    /// B9 — signal own phone number (E.164).
    pub phone: Option<String>,
    /// B9 — irc server host (no scheme).
    pub server: Option<String>,
    /// B9 — irc bot nick.
    pub nick: Option<String>,
    /// B9 — password/secret (irc NickServ · BlueBubbles server password ·
    /// LINE channel secret).
    pub password: Option<String>,
    /// B9 — irc channels csv (`#neoth,#dev`).
    pub channels_csv: Option<String>,
    /// Matrix inbound/invite sender allowlist (`@user:server`) or Keet exact
    /// companion sender IDs (comma-separated).
    pub allowed_sender: Option<String>,
    /// Matrix room-id allowlist, comma-separated (`!id:server`).
    pub allowed_rooms_csv: Option<String>,
    /// Matrix-only explicit opt-out from the encrypted-room requirement.
    pub allow_plaintext: bool,
}

/// B9 — a base URL field must be `http(s)://…` (fail fast on a bare host —
/// the adapters build request URLs by string-joining).
fn require_http_url(v: &Option<String>, what: &str) -> Result<String> {
    let s = require(v, what)?;
    if !(s.starts_with("http://") || s.starts_with("https://")) {
        anyhow::bail!("{what} must start with http:// or https:// (got `{s}`)");
    }
    Ok(s.trim_end_matches('/').to_string())
}

/// B9 — an E.164-ish phone number: `+` then 7-15 digits.
fn require_e164(v: &Option<String>, what: &str) -> Result<String> {
    let s = require(v, what)?;
    let digits = s.strip_prefix('+').unwrap_or("");
    if digits.len() < 7 || digits.len() > 15 || !digits.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("{what} must be E.164, e.g. +491701234567 (got `{s}`)");
    }
    Ok(s)
}

fn require(v: &Option<String>, what: &str) -> Result<String> {
    match v.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => Ok(s.to_string()),
        None => anyhow::bail!("missing {what}"),
    }
}

fn validate_matrix_user_id(value: &str, what: &str) -> Result<()> {
    let Some((localpart, server)) = value.strip_prefix('@').and_then(|id| id.split_once(':'))
    else {
        anyhow::bail!("{what} must have the form `@user:server` (got `{value}`)");
    };
    if localpart.is_empty()
        || server.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        anyhow::bail!("{what} must have the form `@user:server` (got `{value}`)");
    }
    Ok(())
}

fn validate_matrix_room_csv(value: &str) -> Result<String> {
    let mut rooms = std::collections::BTreeSet::new();
    for room in value
        .split(',')
        .map(str::trim)
        .filter(|room| !room.is_empty())
    {
        if !crate::channels::routing::is_valid_matrix_room_id(room) {
            anyhow::bail!("Matrix allowed room `{room}` must have the form `!opaque:server`");
        }
        rooms.insert(room.to_string());
    }
    if rooms.is_empty() {
        anyhow::bail!("Matrix allowed room list contains no room IDs");
    }
    Ok(rooms.into_iter().collect::<Vec<_>>().join(","))
}

fn validate_whatsapp_sender_csv(value: &str) -> Result<String> {
    let mut senders = std::collections::BTreeSet::new();
    for sender in value
        .split(',')
        .map(str::trim)
        .filter(|sender| !sender.is_empty())
    {
        let valid_e164 = sender.strip_prefix('+').is_some_and(|digits| {
            (7..=15).contains(&digits.len())
                && digits.chars().all(|character| character.is_ascii_digit())
        });
        let valid_jid = sender.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && matches!(domain, "s.whatsapp.net" | "lid")
                && !sender.chars().any(|character| character.is_whitespace())
        });
        if !valid_e164 && !valid_jid {
            anyhow::bail!(
                "Baileys allowed sender `{sender}` must be E.164 or an exact @s.whatsapp.net/@lid JID"
            );
        }
        senders.insert(sender.to_ascii_lowercase());
    }
    if senders.is_empty() {
        anyhow::bail!("Baileys sender allowlist must contain at least one sender");
    }
    Ok(senders.into_iter().collect::<Vec<_>>().join(","))
}

fn validate_whatsapp_group_csv(value: &str) -> Result<Option<String>> {
    let mut groups = std::collections::BTreeSet::new();
    for group in value
        .split(',')
        .map(str::trim)
        .filter(|group| !group.is_empty())
    {
        let Some(local) = group.strip_suffix("@g.us") else {
            anyhow::bail!("Baileys allowed group `{group}` must be an exact …@g.us JID");
        };
        if local.is_empty() || !local.chars().all(|character| character.is_ascii_digit()) {
            anyhow::bail!("Baileys allowed group `{group}` has an invalid group JID");
        }
        groups.insert(group.to_ascii_lowercase());
    }
    Ok((!groups.is_empty()).then(|| groups.into_iter().collect::<Vec<_>>().join(",")))
}

fn normalize_twitch_channels(value: &str) -> Result<String> {
    let mut channels = std::collections::BTreeSet::new();
    for channel in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let name = channel.trim_start_matches('#').to_ascii_lowercase();
        if name.is_empty()
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            anyhow::bail!("invalid Twitch channel `{channel}`; use comma-separated channel names");
        }
        channels.insert(format!("#{name}"));
    }
    if channels.is_empty() {
        anyhow::bail!("Twitch needs at least one channel room (--channels-csv)");
    }
    Ok(channels.into_iter().collect::<Vec<_>>().join(","))
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
            let user_id = fields.telegram_user_id.context(
                "missing telegram user ID (--telegram-user-id); NEOTH refuses an open inbound sender policy",
            )?;
            if user_id == 0 {
                anyhow::bail!("telegram user ID must be a positive integer");
            }
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
        "whatsapp" | "whatsapp_business" => {
            let t = require(&fields.token, "whatsapp access token")?;
            let phone = require(&fields.phone_id, "whatsapp phone-number id")?;
            let verify = require(&fields.verify_token, "whatsapp webhook verify token")?;
            let app_secret = require(&fields.app_secret, "whatsapp Meta app secret")?;
            if !phone.chars().all(|c| c.is_ascii_digit()) {
                anyhow::bail!(
                    "whatsapp phone id must be the NUMERIC phone-number id from the Meta console \
                     (not the phone number itself)"
                );
            }
            creds.whatsapp_token = Some(SecretString::from(t.as_str()));
            creds.whatsapp_phone_id = Some(phone);
            creds.whatsapp_verify_token = Some(SecretString::from(verify.as_str()));
            creds.whatsapp_app_secret = Some(SecretString::from(app_secret.as_str()));
        }
        "whatsapp_baileys" => {
            let url = require_http_url(&fields.url, "Baileys bridge URL")?;
            // The live adapter applies the strict remote-HTTPS/loopback-HTTP
            // policy too; validate here so bad config is never persisted.
            let parsed = reqwest::Url::parse(&url).context("parse Baileys bridge URL")?;
            if !matches!(parsed.scheme(), "http" | "https") {
                anyhow::bail!("Baileys bridge URL must use HTTP or HTTPS");
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                anyhow::bail!("Baileys bridge URL must not contain credentials");
            }
            if parsed.query().is_some() || parsed.fragment().is_some() {
                anyhow::bail!("Baileys bridge URL must not contain a query or fragment");
            }
            let host = parsed.host_str().unwrap_or_default();
            let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
            if parsed.scheme() == "http" && !loopback {
                anyhow::bail!("remote Baileys bridge URLs must use HTTPS; HTTP is loopback-only");
            }
            let token = require(&fields.token, "Baileys bridge bearer token")?;
            if token.len() < 32
                || !token.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
                })
            {
                anyhow::bail!("Baileys bridge bearer token must be 32+ URL-safe ASCII characters");
            }
            let senders = validate_whatsapp_sender_csv(&require(
                &fields.allowed_sender,
                "Baileys sender allowlist (--allowed-sender)",
            )?)?;
            let groups = validate_whatsapp_group_csv(
                fields.allowed_rooms_csv.as_deref().unwrap_or_default(),
            )?;
            creds.whatsapp_baileys_url = Some(url);
            creds.whatsapp_baileys_token = Some(SecretString::from(token.as_str()));
            creds.whatsapp_baileys_allowed_senders = Some(senders);
            creds.whatsapp_baileys_allowed_groups = groups;
        }
        "keet" => {
            if fields
                .seed
                .as_deref()
                .is_some_and(|seed| !seed.trim().is_empty())
            {
                anyhow::bail!(
                    "--seed belongs to the removed speculative native Keet transport; \
                     use the repository-owned companion URL/token/topic contract"
                );
            }
            let url = require_http_url(&fields.url, "Keet companion URL")?;
            let token = require(&fields.token, "Keet companion bearer token")?;
            crate::channels::keet_bridge::KeetBridge::new(&url, SecretString::from(token.as_str()))
                .context("validate Keet companion URL/token")?;
            let topic = require(&fields.server, "Keet topic (--server)")?;
            crate::channels::keet_bridge::validate_topic(&topic).context("validate Keet topic")?;
            let allowed_senders = crate::channels::keet::normalize_allowed_senders(&require(
                &fields.allowed_sender,
                "Keet sender allowlist (--allowed-sender)",
            )?)?;
            creds.keet_bridge_url = Some(url);
            creds.keet_topic = Some(SecretString::from(topic));
            creds.keet_allowed_senders = Some(allowed_senders);
            creds.keet_bridge_bearer_token = Some(SecretString::from(token.as_str()));
            // Never preserve a speculative seed beside the real companion
            // contract: it is not consumed and would mislead operators.
            creds.keet_seed_phrase = None;
        }
        "discord" => {
            let t = require(
                &fields.token,
                "discord bot token (from the developer portal)",
            )?;
            creds.discord_bot_token = Some(SecretString::from(t.as_str()));
        }
        "signal" => {
            let url = require_http_url(&fields.url, "signal-cli daemon URL")?;
            let phone = require_e164(&fields.phone, "signal phone number")?;
            creds.signal_cli_url = Some(url);
            creds.signal_phone_number = Some(phone);
        }
        "line" => {
            let t = require(&fields.token, "LINE channel access token")?;
            // The channel secret verifies inbound webhook signatures — optional
            // (push-only works without it), but inbound stays off until set.
            creds.line_channel_access_token = Some(SecretString::from(t.as_str()));
            if let Some(s) = fields
                .password
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                creds.line_channel_secret = Some(SecretString::from(s));
            }
        }
        "irc" => {
            let server = require(&fields.server, "irc server host (e.g. irc.libera.chat)")?;
            if server.contains("://") {
                anyhow::bail!("irc server is a bare host, not a URL (drop the scheme)");
            }
            let nick = require(&fields.nick, "irc bot nick")?;
            creds.irc_server = Some(server);
            creds.irc_nick = Some(nick);
            if let Some(pw) = fields
                .password
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                creds.irc_password = Some(SecretString::from(pw));
            }
            if let Some(ch) = fields
                .channels_csv
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                creds.irc_channels = Some(ch.to_string());
            }
        }
        "imessage" | "imessage_bluebubbles" | "bluebubbles" => {
            let url = require_http_url(&fields.url, "BlueBubbles server URL")?;
            let pw = require(&fields.password, "BlueBubbles server password")?;
            creds.bluebubbles_url = Some(url);
            creds.bluebubbles_password = Some(SecretString::from(pw.as_str()));
        }
        "mattermost" => {
            let url = require_http_url(&fields.url, "Mattermost server URL")?;
            let t = require(&fields.token, "Mattermost bot/personal-access token")?;
            creds.mattermost_url = Some(url);
            creds.mattermost_token = Some(SecretString::from(t.as_str()));
        }
        "gchat" | "google_chat" => {
            let path = require(
                &fields.url,
                "path to the GCP service-account JSON key (the file stays where it is)",
            )?;
            if !std::path::Path::new(&path).is_file() {
                anyhow::bail!("service-account key not found at `{path}`");
            }
            let sub = require(
                &fields.server,
                "Pub/Sub subscription (projects/<p>/subscriptions/<s>)",
            )?;
            if !sub.starts_with("projects/") || !sub.contains("/subscriptions/") {
                anyhow::bail!(
                    "subscription must be the full resource name \
                     `projects/<project>/subscriptions/<name>` (got `{sub}`)"
                );
            }
            creds.gchat_service_account_json = Some(path);
            creds.gchat_subscription = Some(sub);
        }
        "matrix" => {
            let url = require_http_url(&fields.url, "Matrix homeserver URL")?;
            let user_id = require(&fields.nick, "Matrix user ID (@user:server.org)")?;
            validate_matrix_user_id(&user_id, "Matrix user ID")?;
            let pw = fields
                .password
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let tok = fields
                .token
                .as_ref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            if pw.is_none() && tok.is_none() {
                anyhow::bail!(
                    "Matrix needs either --password (account password) or \
                     --token (pre-issued access token)"
                );
            }
            creds.matrix_password = pw.map(SecretString::from);
            creds.matrix_access_token = tok.map(SecretString::from);
            creds.matrix_homeserver = Some(url);
            creds.matrix_user_id = Some(user_id);
            let allowed_user = fields
                .allowed_sender
                .as_ref()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(|value| {
                    validate_matrix_user_id(value, "Matrix allowed sender")?;
                    Ok::<_, anyhow::Error>(value.to_string())
                })
                .transpose()?;
            if let Some(allowed_user) = allowed_user {
                creds.matrix_allowed_user_id = Some(allowed_user);
            }
            let allowed_rooms = fields
                .allowed_rooms_csv
                .as_ref()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(validate_matrix_room_csv)
                .transpose()?;
            if let Some(allowed_rooms) = allowed_rooms {
                creds.matrix_allowed_room_ids = Some(allowed_rooms);
            }
            creds.matrix_require_encryption = Some(!fields.allow_plaintext);
        }
        "twitch" => {
            let nick = require(&fields.nick, "Twitch bot username")?.to_ascii_lowercase();
            let token = require(&fields.token, "Twitch OAuth token (oauth:…)")?;
            let channels = normalize_twitch_channels(&require(
                &fields.channels_csv,
                "Twitch channels (comma-separated)",
            )?)?;
            creds.twitch_username = Some(nick);
            creds.twitch_oauth_token = Some(SecretString::from(token.as_str()));
            creds.twitch_channels = Some(channels);
        }
        "nostr" => {
            let key = require(&fields.token, "Nostr secret key (nsec1… or 64-char hex)")?;
            let relays = require(
                &fields.channels_csv,
                "Nostr relay list (comma-separated wss:// URLs)",
            )?;
            #[cfg(feature = "nostr-channel")]
            {
                let key = SecretString::from(key.as_str());
                let relays = crate::channels::nostr::validate_configuration(&key, &relays)?;
                creds.nostr_secret_key = Some(key);
                creds.nostr_relays = Some(relays);
            }
            #[cfg(not(feature = "nostr-channel"))]
            {
                let _ = (key, relays);
                anyhow::bail!(
                    "this binary lacks the `nostr-channel` feature; install a release build with Nostr support before adding Nostr credentials"
                );
            }
        }
        other => anyhow::bail!(
            "unknown channel `{other}`. Addable: telegram, slack, whatsapp, keet, discord, \
             whatsapp_baileys, signal, line, irc, imessage, mattermost, gchat, matrix, twitch, nostr. \
             `neoth channel list` shows configured state."
        ),
    }
    Ok(creds)
}

/// CLI flags for `neoth channel add` — mirrors [`ChannelAddFields`] 1:1 so the
/// GUI (or any non-interactive caller) can pass all credential values as
/// `--long-flag` arguments without stdin prompts.
///
/// Passed from the clap `ChannelAction::Add` variant into [`run_add`]; kept
/// separate from `ChannelAddFields` so the internal staging API stays free of
/// clap types.
#[derive(Debug, Default, Clone)]
pub struct ChannelAddFlags {
    pub telegram_user_id: Option<u64>,
    pub token: Option<String>,
    pub bot_token: Option<String>,
    pub app_token: Option<String>,
    pub phone_id: Option<String>,
    pub verify_token: Option<String>,
    pub app_secret: Option<String>,
    pub seed: Option<String>,
    pub url: Option<String>,
    pub phone: Option<String>,
    pub server: Option<String>,
    pub nick: Option<String>,
    pub password: Option<String>,
    pub channels_csv: Option<String>,
    pub allowed_sender: Option<String>,
    pub allowed_rooms_csv: Option<String>,
    pub allow_plaintext: bool,
}

impl ChannelAddFlags {
    /// True when at least one flag was supplied (→ non-interactive path).
    fn any_set(&self) -> bool {
        self.telegram_user_id.is_some()
            || self.token.is_some()
            || self.bot_token.is_some()
            || self.app_token.is_some()
            || self.phone_id.is_some()
            || self.verify_token.is_some()
            || self.app_secret.is_some()
            || self.seed.is_some()
            || self.url.is_some()
            || self.phone.is_some()
            || self.server.is_some()
            || self.nick.is_some()
            || self.password.is_some()
            || self.channels_csv.is_some()
            || self.allowed_sender.is_some()
            || self.allowed_rooms_csv.is_some()
            || self.allow_plaintext
    }

    fn into_fields(self) -> ChannelAddFields {
        ChannelAddFields {
            telegram_user_id: self.telegram_user_id,
            token: self.token,
            bot_token: self.bot_token,
            app_token: self.app_token,
            phone_id: self.phone_id,
            verify_token: self.verify_token,
            app_secret: self.app_secret,
            seed: self.seed,
            url: self.url,
            phone: self.phone,
            server: self.server,
            nick: self.nick,
            password: self.password,
            channels_csv: self.channels_csv,
            allowed_sender: self.allowed_sender,
            allowed_rooms_csv: self.allowed_rooms_csv,
            allow_plaintext: self.allow_plaintext,
        }
    }
}

/// Required flags per channel, for the "no TTY + no flags" bail message.
fn required_flags_for(channel: &str) -> &'static str {
    match channel {
        "telegram" => "--token --telegram-user-id",
        "slack" => "--bot-token --app-token",
        "whatsapp" => "--token --phone-id --verify-token --app-secret",
        "whatsapp_baileys" => "--url --token --allowed-sender [--allowed-rooms-csv]",
        "keet" => "--url --token --server (topic) --allowed-sender",
        "discord" => "--token",
        "signal" => "--url --phone",
        "line" => "--token  [--password]",
        "irc" => "--server --nick  [--password --channels-csv]",
        "imessage" | "imessage_bluebubbles" | "bluebubbles" => "--url --password",
        "mattermost" => "--url --token",
        "gchat" | "google_chat" => "--url --server",
        "whatsapp_business" => "--token --phone-id --verify-token --app-secret",
        "matrix" => {
            "--url (homeserver) --nick (user_id) [--password | --token (access_token)] [--allowed-sender] [--allowed-rooms-csv] [--allow-plaintext]"
        }
        "twitch" => "--nick --token --channels-csv",
        "nostr" => "--token (nsec1… key or 64-char hex) --channels-csv (relay wss:// URLs csv)",
        _ => "(unknown channel)",
    }
}

/// `neoth channel add <channel>` — collect the channel's credentials/policy and
/// persist them through the canonical config writers. Telegram spans
/// credentials.yaml (token) and freedom.yaml (exact sender ID); that pair uses
/// one locked rollback-safe transaction. Other channels remain single-file.
///
/// **Non-interactive path** (GUI / scripting): when `flags` has at least one
/// field set, `ChannelAddFields` is built directly from the flags and stdin is
/// never read.  If `flags` is empty AND stdin is not a TTY, the command bails
/// with a message listing the required flags for that channel.
///
/// **Interactive path**: when no flags are set and stdin is a TTY the existing
/// `prompt_channel_fields` flow runs unchanged.
///
/// JSON output shape (--output json):
/// ```json
/// {"ok": true, "channel": "telegram", "saved": true}
/// ```
pub async fn run_add(channel: &str, flags: &ChannelAddFlags, output: &OutputFormat) -> Result<()> {
    run_add_at(&FreedomConfig::default_neoth_home(), channel, flags, output).await
}

/// Home-scoped channel credential mutation shared by CLI and action surfaces.
/// Input collection happens before the locked, reload-under-lock RMW.
pub(crate) async fn run_add_at(
    home: &std::path::Path,
    channel: &str,
    flags: &ChannelAddFlags,
    output: &OutputFormat,
) -> Result<()> {
    let chan = channel.trim().to_ascii_lowercase();
    let path = home.join("credentials.yaml");
    let freedom_path = home.join("freedom.yaml");

    // Reject unknown channels BEFORE prompting (no point asking for a token we
    // can't store) — let the staging validator produce the precise message.
    // Uses a throwaway default base because the purpose is purely name validation
    // (stage_channel_add always bails for unknown names regardless of base).
    if !matches!(
        chan.as_str(),
        "telegram"
            | "slack"
            | "whatsapp"
            | "whatsapp_business"
            | "whatsapp_baileys"
            | "keet"
            | "discord"
            | "signal"
            | "line"
            | "irc"
            | "imessage"
            | "imessage_bluebubbles"
            | "bluebubbles"
            | "mattermost"
            | "gchat"
            | "google_chat"
            | "matrix"
            | "twitch"
            | "nostr"
    ) {
        stage_channel_add(&chan, &ChannelAddFields::default(), Credentials::default())?;
        return Ok(()); // unreachable — the line above always errors for these
    }

    // B17: collect ALL interactive input BEFORE entering the lock.
    // prompt_channel_fields / flag parsing must complete here; never hold
    // CRED_LOCK or the OS file lock while waiting at a terminal prompt.
    let fields = if flags.any_set() {
        // Non-interactive: build fields directly from CLI flags.
        flags.clone().into_fields()
    } else {
        // No flags supplied — decide between interactive prompt and hard bail.
        let is_tty = {
            #[cfg(feature = "wizard")]
            {
                use std::io::IsTerminal;
                std::io::stdin().is_terminal()
            }
            #[cfg(not(feature = "wizard"))]
            {
                false
            }
        };

        if is_tty {
            prompt_channel_fields(&chan)?
        } else {
            anyhow::bail!(
                "non-interactive stdin with no flags supplied for channel `{chan}`.\n\
                 Pass the required flags: neoth channel add {chan} {flags}",
                flags = required_flags_for(&chan)
            );
        }
    };

    if chan == "telegram" {
        // Telegram's token and inbound sender policy are one logical adoption.
        // The dual-file writer loads both strictly, commits each via atomic
        // rename, and restores both snapshots if the second commit fails.
        Credentials::update_with_freedom_at(&freedom_path, &path, |config, credentials| {
            let updated = stage_channel_add(&chan, &fields, credentials.clone())?;
            config.telegram_user_id = fields.telegram_user_id;
            *credentials = updated;
            Ok(())
        })
        .with_context(|| {
            format!(
                "update Telegram token + sender policy at {} and {}",
                path.display(),
                freedom_path.display()
            )
        })?;
        crate::cli::reload::request_reload_at(home).with_context(|| {
            "Telegram token and sender policy were stored, but the live-reload request failed; run `neoth reload` before trusting the active adapter"
        })?;
    } else {
        // B17 RMW: acquire cross-process lock, reload under lock, mutate, write atomically.
        // If credentials.yaml exists but is corrupt the load inside update_at returns Err
        // and update_at propagates without touching the file (STOP invariant).
        Credentials::update_at(&path, |c| {
            let updated = stage_channel_add(&chan, &fields, c.clone())?;
            *c = updated;
            Ok(())
        })
        .with_context(|| format!("update credentials at {}", path.display()))?;
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&add_result_json(&chan))?);
        }
        OutputFormat::Table => {
            if chan == "telegram" {
                println!(
                    "✓ telegram credentials saved to {} and exact sender policy to {}",
                    path.display(),
                    freedom_path.display()
                );
            } else {
                println!(
                    "✓ {chan} credentials saved (mode-0600) to {}",
                    path.display()
                );
            }
            println!("  validate the credentials work: `neoth channel test {chan}`");
            println!("  start serving the channel:      `neoth serve`");
        }
    }
    Ok(())
}

fn add_result_json(channel: &str) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "channel": channel,
        "saved": true,
    })
}

/// Prompt for each field the channel needs. Prompts go to STDERR so stdout
/// stays clean for `--output json` / piping.
fn prompt_channel_fields(channel: &str) -> Result<ChannelAddFields> {
    let mut f = ChannelAddFields::default();
    match channel {
        "telegram" => {
            f.token = Some(read_secret("Telegram bot token (from @BotFather)")?);
            let user_id = read_plain("Allowed Telegram user ID (numeric, from @userinfobot)")?;
            f.telegram_user_id = Some(
                user_id
                    .trim()
                    .parse::<u64>()
                    .context("Telegram user ID must be a positive integer")?,
            );
        }
        "slack" => {
            f.bot_token = Some(read_secret("Slack bot token (xoxb-…)")?);
            f.app_token = Some(read_secret("Slack app token (xapp-…, socket mode)")?);
        }
        "whatsapp" | "whatsapp_business" => {
            f.token = Some(read_secret("WhatsApp access token")?);
            f.phone_id = Some(read_plain(
                "WhatsApp phone-number id (numeric, from Meta console)",
            )?);
            f.verify_token = Some(read_secret("WhatsApp webhook verification token")?);
            f.app_secret = Some(read_secret("WhatsApp Meta app secret")?);
        }
        "whatsapp_baileys" => {
            f.url = Some(read_plain(
                "Baileys bridge URL (usually http://127.0.0.1:9120)",
            )?);
            f.token = Some(read_secret("Baileys bridge bearer token (32+ characters)")?);
            f.allowed_sender = Some(read_plain(
                "Allowed senders, comma-separated (E.164 or exact WhatsApp JID)",
            )?);
            f.allowed_rooms_csv = Some(read_plain(
                "Allowed group JIDs, comma-separated (blank denies all groups)",
            )?);
        }
        "keet" => {
            f.url = Some(read_plain(
                "NEOTH Keet companion URL (usually http://127.0.0.1:9130)",
            )?);
            f.token = Some(read_secret(
                "Keet companion bearer token (32+ URL-safe characters)",
            )?);
            f.server = Some(read_plain(
                "Keet topic capability printed by the companion (nk1_…)",
            )?);
            f.allowed_sender = Some(read_plain(
                "Allowed 43-character Keet sender IDs from the companion, comma-separated",
            )?);
        }
        "discord" => f.token = Some(read_secret("Discord bot token (developer portal)")?),
        "signal" => {
            f.url = Some(read_plain(
                "signal-cli daemon URL (e.g. http://127.0.0.1:8080)",
            )?);
            f.phone = Some(read_plain("Signal phone number (E.164, e.g. +4917…)")?);
        }
        "line" => {
            f.token = Some(read_secret("LINE channel access token")?);
            f.password = Some(read_secret(
                "LINE channel secret (empty = push-only, no inbound webhook)",
            )?);
        }
        "irc" => {
            f.server = Some(read_plain("IRC server host (e.g. irc.libera.chat)")?);
            f.nick = Some(read_plain("IRC bot nick")?);
            f.password = Some(read_secret("NickServ/bouncer password (empty = none)")?);
            f.channels_csv = Some(read_plain("Channels to join, csv (e.g. #neoth,#dev)")?);
        }
        "imessage" | "imessage_bluebubbles" | "bluebubbles" => {
            f.url = Some(read_plain(
                "BlueBubbles server URL (e.g. http://192.168.1.5:1234)",
            )?);
            f.password = Some(read_secret("BlueBubbles server password")?);
        }
        "mattermost" => {
            f.url = Some(read_plain(
                "Mattermost server URL (e.g. https://mm.example.com)",
            )?);
            f.token = Some(read_secret("Mattermost bot/personal-access token")?);
        }
        "gchat" | "google_chat" => {
            f.url = Some(read_plain(
                "Path to the GCP service-account JSON key (kept in place, only the path is stored)",
            )?);
            f.server = Some(read_plain(
                "Pub/Sub subscription (projects/<p>/subscriptions/<s>)",
            )?);
        }
        "matrix" => {
            f.url = Some(read_plain(
                "Matrix homeserver URL (e.g. https://matrix.org)",
            )?);
            f.nick = Some(read_plain("Matrix user ID (@user:server.org)")?);
            let use_token = read_plain(
                "Auth method: type `token` to enter an access token, or press Enter for password",
            )?;
            if use_token.trim().eq_ignore_ascii_case("token") {
                f.token = Some(read_secret("Matrix access token (syt_…)")?);
            } else {
                f.password = Some(read_secret("Matrix account password")?);
            }
            f.allowed_sender = Some(read_plain(
                "Allowed Matrix inviter/sender (@user:server; blank disables sender rule)",
            )?);
            f.allowed_rooms_csv = Some(read_plain(
                "Allowed Matrix room IDs (!id:server, comma-separated; blank disables room rule)",
            )?);
            let plaintext = read_plain(
                "Allow plaintext Matrix rooms? Type `yes` to opt out of E2EE enforcement",
            )?;
            f.allow_plaintext = plaintext.trim().eq_ignore_ascii_case("yes");
        }
        "twitch" => {
            f.nick = Some(read_plain("Twitch bot username")?);
            f.token = Some(read_secret("Twitch OAuth token (oauth:…)")?);
            f.channels_csv = Some(read_plain(
                "Twitch channels to join, comma-separated (e.g. #mychannel)",
            )?);
        }
        "nostr" => {
            f.token = Some(read_secret(
                "Nostr secret key (nsec1… bech32 or 64-char hex)",
            )?);
            f.channels_csv = Some(read_plain(
                "Nostr relay URLs, comma-separated (e.g. wss://relay.damus.io)",
            )?);
        }
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
    std::io::stdin()
        .read_line(&mut line)
        .context("read stdin")?;
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
        "whatsapp" | "whatsapp_business" => {
            let had = creds.whatsapp_token.is_some() || creds.whatsapp_phone_id.is_some();
            creds.whatsapp_token = None;
            creds.whatsapp_phone_id = None;
            creds.whatsapp_verify_token = None;
            creds.whatsapp_app_secret = None;
            had
        }
        "whatsapp_baileys" => {
            let had = creds.whatsapp_baileys_url.is_some()
                || creds.whatsapp_baileys_token.is_some()
                || creds.whatsapp_baileys_allowed_senders.is_some()
                || creds.whatsapp_baileys_allowed_groups.is_some();
            creds.whatsapp_baileys_url = None;
            creds.whatsapp_baileys_token = None;
            creds.whatsapp_baileys_allowed_senders = None;
            creds.whatsapp_baileys_allowed_groups = None;
            had
        }
        "keet" => {
            let had = creds.keet_bridge_url.is_some()
                || creds.keet_topic.is_some()
                || creds.keet_allowed_senders.is_some()
                || creds.keet_seed_phrase.is_some()
                || creds.keet_bridge_bearer_token.is_some();
            creds.keet_bridge_url = None;
            creds.keet_topic = None;
            creds.keet_allowed_senders = None;
            creds.keet_seed_phrase = None;
            creds.keet_bridge_bearer_token = None;
            had
        }
        "discord" => {
            let had = creds.discord_bot_token.is_some();
            creds.discord_bot_token = None;
            had
        }
        "signal" => {
            let had = creds.signal_cli_url.is_some() || creds.signal_phone_number.is_some();
            creds.signal_cli_url = None;
            creds.signal_phone_number = None;
            had
        }
        "line" => {
            let had = creds.line_channel_access_token.is_some();
            creds.line_channel_access_token = None;
            creds.line_channel_secret = None;
            creds.line_webhook_port = None;
            had
        }
        "irc" => {
            let had = creds.irc_server.is_some() || creds.irc_nick.is_some();
            creds.irc_server = None;
            creds.irc_port = None;
            creds.irc_nick = None;
            creds.irc_password = None;
            creds.irc_channels = None;
            creds.irc_tls = None;
            creds.irc_allowed_nick = None;
            creds.irc_allowed_account = None;
            had
        }
        "imessage" | "imessage_bluebubbles" | "bluebubbles" => {
            let had = creds.bluebubbles_url.is_some() || creds.bluebubbles_password.is_some();
            creds.bluebubbles_url = None;
            creds.bluebubbles_password = None;
            creds.bluebubbles_chat_guid = None;
            creds.imessage_allowed_sender = None;
            had
        }
        "mattermost" => {
            let had = creds.mattermost_url.is_some() || creds.mattermost_token.is_some();
            creds.mattermost_url = None;
            creds.mattermost_token = None;
            creds.mattermost_allowed_user_id = None;
            had
        }
        "gchat" | "google_chat" => {
            let had =
                creds.gchat_service_account_json.is_some() || creds.gchat_subscription.is_some();
            creds.gchat_service_account_json = None;
            creds.gchat_subscription = None;
            creds.gchat_allowed_sender = None;
            had
        }
        "matrix" => {
            let had = creds.matrix_homeserver.is_some()
                || creds.matrix_user_id.is_some()
                || creds.matrix_password.is_some()
                || creds.matrix_access_token.is_some()
                || creds.matrix_allowed_user_id.is_some()
                || creds.matrix_allowed_room_ids.is_some()
                || creds.matrix_require_encryption.is_some();
            creds.matrix_homeserver = None;
            creds.matrix_user_id = None;
            creds.matrix_password = None;
            creds.matrix_access_token = None;
            creds.matrix_store_path = None;
            creds.matrix_allowed_user_id = None;
            creds.matrix_allowed_room_ids = None;
            creds.matrix_require_encryption = None;
            had
        }
        "twitch" => {
            let had = creds.twitch_username.is_some();
            creds.twitch_username = None;
            creds.twitch_oauth_token = None;
            creds.twitch_channels = None;
            had
        }
        "nostr" => {
            let had = creds.nostr_secret_key.is_some();
            creds.nostr_secret_key = None;
            creds.nostr_relays = None;
            creds.nostr_allowed_pubkey = None;
            had
        }
        other => anyhow::bail!(
            "unknown channel `{other}`. Removable: telegram, slack, whatsapp, keet, discord, \
             whatsapp_baileys, signal, line, irc, imessage, mattermost, gchat, matrix, twitch, nostr. \
             `neoth channel list` shows configured state."
        ),
    };
    Ok((creds, removed))
}

/// `neoth channel remove <channel>` — clear a channel's durable adoption
/// state. Telegram removes both its bot token and exact sender policy in the
/// same rollback-safe transaction used by add/reconfigure; other channels
/// update credentials.yaml atomically. No network. After removal `neoth serve`
/// won't start the channel.
pub fn run_remove(channel: &str, output: &OutputFormat) -> Result<()> {
    run_remove_at(&FreedomConfig::default_neoth_home(), channel, output)
}

/// Home-scoped counterpart to [`run_remove`], used by slash rollback and
/// disconnect so every step operates on the same credential store.
pub(crate) fn run_remove_at(
    home: &std::path::Path,
    channel: &str,
    output: &OutputFormat,
) -> Result<()> {
    let chan = channel.trim().to_ascii_lowercase();
    let path = home.join("credentials.yaml");
    let freedom_path = home.join("freedom.yaml");
    let mut was_removed = false;
    if chan == "telegram" {
        Credentials::update_with_freedom_at(&freedom_path, &path, |config, credentials| {
            let (updated, token_removed) = stage_channel_remove(&chan, credentials.clone())?;
            let policy_removed = config.telegram_user_id.take().is_some();
            *credentials = updated;
            was_removed = token_removed || policy_removed;
            Ok(())
        })
        .with_context(|| {
            format!(
                "remove Telegram token + sender policy at {} and {}",
                path.display(),
                freedom_path.display()
            )
        })?;
        crate::cli::reload::request_reload_at(home).with_context(|| {
            "Telegram token and sender policy were removed, but the live-reload request failed; run `neoth reload` before trusting the active adapter"
        })?;
    } else {
        // B17 RMW: collect the removal outcome via a captured mutable bool;
        // the update_at closure holds the lock for the whole load→mutate→write cycle.
        Credentials::update_at(&path, |c| {
            let (updated, removed) = stage_channel_remove(&chan, c.clone())?;
            *c = updated;
            was_removed = removed;
            Ok(())
        })
        .with_context(|| format!("update credentials at {}", path.display()))?;
    }
    let removed = was_removed;

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
            if chan == "telegram" {
                println!(
                    "✓ removed telegram credentials from {} and sender policy from {}",
                    path.display(),
                    freedom_path.display()
                );
            } else {
                println!("✓ removed {chan} credentials from {}", path.display());
            }
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
    // ALL_CHANNELS is only referenced by the coverage/parity tests below, so it
    // lives in the test-module scope (a module-level import would be unused in
    // the non-test lib build → `-D warnings`).
    use crate::channels::probe::ALL_CHANNELS;

    const TEST_KEET_TOPIC: &str = "nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const TEST_KEET_SENDER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const TEST_KEET_SENDER_TWO: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    fn creds_empty() -> Credentials {
        Credentials::default()
    }

    #[test]
    fn fresh_install_has_no_configured_channels() {
        let rows = channel_statuses(&FreedomConfig::default(), &creds_empty());
        assert_eq!(
            rows.len(),
            ALL_CHANNELS.len(),
            "must cover all 15 channel kinds"
        );
        assert_eq!(configured_count(&rows), 0);
        // Every off channel has configured=false (all NotConfigured).
        assert!(rows.iter().all(|r| !r.configured));
        // Telegram detail comes from probe.rs: "no telegram_token".
        assert!(
            rows.iter()
                .find(|r| r.name == "telegram")
                .unwrap()
                .detail
                .contains("telegram_token")
        );
    }

    #[test]
    fn list_loader_uses_the_selected_home_credentials() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("credentials.yaml"),
            "slack_bot_token: '  '\nslack_app_token: xapp-live\n",
        )
        .unwrap();

        let rows = load_channel_statuses_at(home.path()).unwrap();
        let slack = rows.iter().find(|row| row.name == "slack").unwrap();
        assert_eq!(slack.status, ProbeStatus::Error);
        assert!(slack.configured, "partial non-blank config remains visible");
        assert!(slack.detail.contains("BOTH"));
    }

    #[test]
    fn telegram_configured_via_freedom_yaml_token() {
        let mut cfg = FreedomConfig::default();
        cfg.telegram_token = Some(SecretString::from("123:abc"));
        let rows = channel_statuses(&cfg, &creds_empty());
        let t = rows.iter().find(|r| r.name == "telegram").unwrap();
        // Token set but no user_id → probe returns Error → configured=true.
        assert!(t.configured);
        // Probe.rs message: "token set but telegram_user_id missing…" or
        // "token + user_id configured (polling loop)".
        assert!(
            t.detail.contains("token set") || t.detail.contains("token + user_id"),
            "detail: {}",
            t.detail
        );
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
            rows.iter()
                .find(|r| r.name == "telegram")
                .unwrap()
                .configured,
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
        // Only the bot token → probe returns Error → configured=true (partial creds present),
        // but the detail string explains what is missing.
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        let row = rows.iter().find(|r| r.name == "slack").unwrap();
        assert!(
            row.configured,
            "partial slack creds: Error != NotConfigured → configured=true"
        );
        assert!(
            row.detail.contains("BOTH") || row.detail.contains("app"),
            "detail must explain missing app token: {}",
            row.detail
        );
        // Both tokens → configured=true (Ok status).
        creds.slack_app_token = Some(SecretString::from("xapp-1"));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(rows.iter().find(|r| r.name == "slack").unwrap().configured);
    }

    #[test]
    fn whatsapp_needs_token_and_phone_id() {
        let mut creds = creds_empty();
        creds.whatsapp_token = Some(SecretString::from("EAA..."));
        // After probe delegation the canonical name is "whatsapp_business".
        // With only token: Error → configured=true; detail explains what's missing.
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        let row = rows
            .iter()
            .find(|r| r.name == "whatsapp_business")
            .expect("whatsapp_business must be present");
        assert!(
            row.configured,
            "partial whatsapp creds: Error != NotConfigured → configured=true"
        );
        creds.whatsapp_phone_id = Some("1234567890".to_string());
        // Full send-capable creds → configured=true (Warn or Ok status).
        assert!(
            channel_statuses(&FreedomConfig::default(), &creds)
                .iter()
                .find(|r| r.name == "whatsapp_business")
                .unwrap()
                .configured
        );
    }

    #[test]
    fn legacy_keet_seed_is_visible_as_broken_config_and_discord_uses_bot_token() {
        let mut creds = creds_empty();
        creds.keet_seed_phrase = Some(SecretString::from("word ".repeat(24)));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        let keet = rows.iter().find(|r| r.name == "keet").unwrap();
        assert!(keet.configured);
        assert_eq!(keet.status, ProbeStatus::Error);
        assert!(keet.detail.contains("ignored"));
        // GOLD-PROG-16: Discord is unconfigured until discord_bot_token is set.
        let d = rows.iter().find(|r| r.name == "discord").unwrap();
        assert!(!d.configured);
        // Detail comes from probe.rs: "no discord_bot_token".
        assert!(
            d.detail.contains("discord_bot_token"),
            "discord detail: {}",
            d.detail
        );
        // With a bot token present → configured (gateway receive loop).
        creds.discord_bot_token = Some(SecretString::from("bot-xyz"));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(
            rows.iter()
                .find(|r| r.name == "discord")
                .unwrap()
                .configured
        );
    }

    #[test]
    fn plan_channel_test_routes_each_channel_purely() {
        let cfg = FreedomConfig::default();
        let creds = creds_empty();
        // Fresh install: known-but-unconfigured → NotConfigured; discord special; unknown.
        assert_eq!(
            plan_channel_test("telegram", &cfg, &creds),
            ChannelTestPlan::NotConfigured
        );
        assert_eq!(
            plan_channel_test("slack", &cfg, &creds),
            ChannelTestPlan::NotConfigured
        );
        assert_eq!(
            plan_channel_test("keet", &cfg, &creds),
            ChannelTestPlan::NotConfigured
        );
        assert_eq!(
            plan_channel_test("discord", &cfg, &creds),
            ChannelTestPlan::NotConfigured,
            "no discord token → NotConfigured (B9: discord token is storable now)"
        );
        let mut creds_dc = creds_empty();
        creds_dc.discord_bot_token = Some(SecretString::from("bot"));
        assert_eq!(
            plan_channel_test("discord", &cfg, &creds_dc),
            ChannelTestPlan::Discord
        );
        assert_eq!(
            plan_channel_test("nope", &cfg, &creds),
            ChannelTestPlan::Unknown
        );

        // Telegram token → live plan; case-insensitive.
        let mut cfg2 = FreedomConfig::default();
        cfg2.telegram_token = Some(SecretString::from("t"));
        assert_eq!(
            plan_channel_test("telegram", &cfg2, &creds),
            ChannelTestPlan::Telegram
        );
        assert_eq!(
            plan_channel_test("TELEGRAM", &cfg2, &creds),
            ChannelTestPlan::Telegram
        );

        // Slack auth.test needs only the BOT token (app token is for socket mode).
        let mut creds_s = creds_empty();
        creds_s.slack_bot_token = Some(SecretString::from("xoxb"));
        assert_eq!(
            plan_channel_test("slack", &cfg, &creds_s),
            ChannelTestPlan::Slack
        );

        // WhatsApp needs BOTH token + phone id.
        let mut creds_w = creds_empty();
        creds_w.whatsapp_token = Some(SecretString::from("t"));
        assert_eq!(
            plan_channel_test("whatsapp", &cfg, &creds_w),
            ChannelTestPlan::NotConfigured
        );
        creds_w.whatsapp_phone_id = Some("123".to_string());
        assert_eq!(
            plan_channel_test("whatsapp", &cfg, &creds_w),
            ChannelTestPlan::Whatsapp
        );

        // A legacy Keet seed never turns the companion into a live plan.
        let mut creds_k = creds_empty();
        creds_k.keet_seed_phrase = Some(SecretString::from("x"));
        assert_eq!(
            plan_channel_test("keet", &cfg, &creds_k),
            ChannelTestPlan::NotConfigured
        );
        creds_k.keet_bridge_url = Some("http://127.0.0.1:9130".into());
        creds_k.keet_topic = Some(SecretString::from(TEST_KEET_TOPIC));
        creds_k.keet_allowed_senders = Some(TEST_KEET_SENDER.into());
        creds_k.keet_bridge_bearer_token =
            Some(SecretString::from("0123456789abcdef0123456789abcdef"));
        assert_eq!(
            plan_channel_test("keet", &cfg, &creds_k),
            ChannelTestPlan::Keet
        );
    }

    #[test]
    fn channel_test_fail_redacts_secrets_in_error_text() {
        // P1 — a provider error that echoes a token must NOT reach the operator
        // result verbatim; the secret redactor masks it.
        let r = fail(
            "slack".to_string(),
            "auth.test failed: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 rejected".to_string(),
        );
        assert_eq!(r.status, "fail");
        assert!(
            !r.detail
                .contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            "secret leaked: {}",
            r.detail
        );
        assert!(
            r.detail.contains("[REDACTED"),
            "expected a redaction marker: {}",
            r.detail
        );
    }

    #[test]
    fn render_test_table_and_json() {
        let r = ChannelTestResult {
            channel: "telegram".to_string(),
            status: "ok",
            detail: "bot @neoth".to_string(),
        };
        assert!(
            render_test(&r, &OutputFormat::Table)
                .unwrap()
                .contains("✓ telegram")
        );
        let j: serde_json::Value =
            serde_json::from_str(&render_test(&r, &OutputFormat::Json).unwrap()).unwrap();
        assert_eq!(j["status"], "ok");
        assert_eq!(j["channel"], "telegram");
        // A failed/skipped status renders its own glyph.
        let f = ChannelTestResult {
            channel: "slack".to_string(),
            status: "fail",
            detail: "bad token".to_string(),
        };
        assert!(
            render_test(&f, &OutputFormat::Table)
                .unwrap()
                .starts_with("✗")
        );
        let s = ChannelTestResult {
            channel: "discord".to_string(),
            status: "skipped",
            detail: "no field".to_string(),
        };
        assert!(
            render_test(&s, &OutputFormat::Table)
                .unwrap()
                .starts_with("–")
        );
        assert_eq!(channel_test_exit_code("ok"), None);
        assert_eq!(channel_test_exit_code("fail"), Some(1));
        assert_eq!(channel_test_exit_code("skipped"), Some(2));
        assert_eq!(channel_test_exit_code("unavailable"), Some(2));
        let unavailable = unavailable(
            "irc".to_string(),
            "no side-effect-free authentication probe".to_string(),
        );
        assert!(
            render_test(&unavailable, &OutputFormat::Table)
                .unwrap()
                .starts_with("⊘")
        );
        assert_eq!(channel_test_exit_code("future-state"), Some(1));
    }

    fn valid_tg_token() -> String {
        // 9-digit id (in the 8-12 range) + 35 [a-z] chars.
        format!("123456789:{}", "a".repeat(35))
    }

    #[test]
    fn stage_add_telegram_validates_and_stores_token() {
        let f = ChannelAddFields {
            telegram_user_id: Some(123_456_789),
            token: Some(valid_tg_token()),
            ..Default::default()
        };
        let c = stage_channel_add("telegram", &f, Credentials::default()).unwrap();
        assert_eq!(
            c.telegram_token.as_ref().unwrap().expose(),
            valid_tg_token()
        );
    }

    #[test]
    fn stage_add_telegram_rejects_bad_and_missing() {
        let bad = ChannelAddFields {
            telegram_user_id: Some(123_456_789),
            token: Some("not-a-token".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("telegram", &bad, Credentials::default()).is_err());
        let e = stage_channel_add(
            "telegram",
            &ChannelAddFields::default(),
            Credentials::default(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("missing"));

        let zero_sender = ChannelAddFields {
            telegram_user_id: Some(0),
            token: Some(valid_tg_token()),
            ..Default::default()
        };
        let error =
            stage_channel_add("telegram", &zero_sender, Credentials::default()).unwrap_err();
        assert!(error.to_string().contains("positive integer"));
    }

    #[test]
    fn stage_add_slack_needs_both_tokens_with_prefixes() {
        let only_bot = ChannelAddFields {
            bot_token: Some("xoxb-1".into()),
            ..Default::default()
        };
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
    fn stage_add_whatsapp_requires_full_verified_inbound_contract() {
        let nonnum = ChannelAddFields {
            token: Some("EAAtoken".into()),
            phone_id: Some("not-numeric".into()),
            verify_token: Some("verify".into()),
            app_secret: Some("app-secret".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("whatsapp", &nonnum, Credentials::default()).is_err());
        let outbound_only = ChannelAddFields {
            token: Some("EAAtoken".into()),
            phone_id: Some("1234567890".into()),
            ..Default::default()
        };
        assert!(
            stage_channel_add("whatsapp", &outbound_only, Credentials::default()).is_err(),
            "channel add must not silently persist an outbound-only adoption"
        );
        let good = ChannelAddFields {
            token: Some("EAAtoken".into()),
            phone_id: Some("1234567890".into()),
            verify_token: Some("verify".into()),
            app_secret: Some("app-secret".into()),
            ..Default::default()
        };
        let c = stage_channel_add("whatsapp", &good, Credentials::default()).unwrap();
        assert_eq!(c.whatsapp_phone_id.as_deref(), Some("1234567890"));
        assert!(c.whatsapp_token.is_some());
        assert!(c.whatsapp_verify_token.is_some());
        assert!(c.whatsapp_app_secret.is_some());
    }

    #[test]
    fn stage_add_baileys_is_complete_and_does_not_touch_meta() {
        let mut base = Credentials::default();
        base.whatsapp_token = Some(SecretString::from("meta-token"));
        base.whatsapp_phone_id = Some("1234567890".into());
        let fields = ChannelAddFields {
            url: Some("http://127.0.0.1:9120".into()),
            token: Some("0123456789abcdef0123456789abcdef".into()),
            allowed_sender: Some("+491701234567,491709999999@s.whatsapp.net".into()),
            allowed_rooms_csv: Some("120363012345678901@g.us".into()),
            ..Default::default()
        };
        let creds = stage_channel_add("whatsapp_baileys", &fields, base).unwrap();
        assert_eq!(
            creds.whatsapp_baileys_url.as_deref(),
            Some("http://127.0.0.1:9120")
        );
        assert!(creds.whatsapp_baileys_token.is_some());
        assert!(creds.whatsapp_baileys_allowed_senders.is_some());
        assert_eq!(
            creds.whatsapp_baileys_allowed_groups.as_deref(),
            Some("120363012345678901@g.us")
        );
        assert!(
            creds.whatsapp_token.is_some(),
            "Meta token must remain intact"
        );
        assert_eq!(creds.whatsapp_phone_id.as_deref(), Some("1234567890"));
    }

    #[test]
    fn stage_add_baileys_rejects_unsafe_or_partial_config() {
        let base = ChannelAddFields {
            url: Some("http://bridge.example.com:9120".into()),
            token: Some("0123456789abcdef0123456789abcdef".into()),
            allowed_sender: Some("+491701234567".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("whatsapp_baileys", &base, Credentials::default()).is_err());
        let mut short_token = base.clone();
        short_token.url = Some("http://127.0.0.1:9120".into());
        short_token.token = Some("short".into());
        assert!(
            stage_channel_add("whatsapp_baileys", &short_token, Credentials::default()).is_err()
        );
        let mut no_senders = base;
        no_senders.url = Some("https://bridge.example.com".into());
        no_senders.allowed_sender = None;
        assert!(
            stage_channel_add("whatsapp_baileys", &no_senders, Credentials::default()).is_err()
        );
    }

    #[test]
    fn stage_add_keet_requires_hardened_companion_contract() {
        let bad = ChannelAddFields {
            seed: Some("too short".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("keet", &bad, Credentials::default()).is_err());
        let good = ChannelAddFields {
            url: Some("http://127.0.0.1:9130".into()),
            token: Some("0123456789abcdef0123456789abcdef".into()),
            server: Some(TEST_KEET_TOPIC.into()),
            allowed_sender: Some(format!(
                "{TEST_KEET_SENDER_TWO},{TEST_KEET_SENDER},{TEST_KEET_SENDER_TWO}"
            )),
            ..Default::default()
        };
        let staged = stage_channel_add("keet", &good, Credentials::default()).unwrap();
        assert_eq!(
            staged.keet_bridge_url.as_deref(),
            Some("http://127.0.0.1:9130")
        );
        assert_eq!(
            staged.keet_topic.as_ref().map(SecretString::expose),
            Some(TEST_KEET_TOPIC)
        );
        let expected_senders = format!("{TEST_KEET_SENDER},{TEST_KEET_SENDER_TWO}");
        assert_eq!(
            staged.keet_allowed_senders.as_deref(),
            Some(expected_senders.as_str())
        );
        assert!(staged.keet_bridge_bearer_token.is_some());
        assert!(staged.keet_seed_phrase.is_none());

        let mut wrong_topic = good.clone();
        wrong_topic.server = Some("topic".into());
        assert!(stage_channel_add("keet", &wrong_topic, Credentials::default()).is_err());

        let mut remote = good;
        remote.url = Some("https://bridge.example.com".into());
        assert!(stage_channel_add("keet", &remote, Credentials::default()).is_err());
    }

    #[test]
    fn stage_add_rejects_missing_fields_and_unknown() {
        // discord IS addable now (B9) — but a missing token still errors.
        assert!(
            stage_channel_add(
                "discord",
                &ChannelAddFields::default(),
                Credentials::default()
            )
            .is_err()
        );
        assert!(
            stage_channel_add(
                "bogus",
                &ChannelAddFields::default(),
                Credentials::default()
            )
            .is_err()
        );
    }

    #[test]
    fn stage_add_discord_stores_token() {
        let f = ChannelAddFields {
            token: Some("bot-token".into()),
            ..Default::default()
        };
        let c = stage_channel_add("discord", &f, Credentials::default()).unwrap();
        assert!(c.discord_bot_token.is_some());
    }

    #[test]
    fn stage_add_signal_validates_url_and_e164() {
        let bad_url = ChannelAddFields {
            url: Some("127.0.0.1:8080".into()),
            phone: Some("+491701234567".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("signal", &bad_url, Credentials::default()).is_err());
        let bad_phone = ChannelAddFields {
            url: Some("http://127.0.0.1:8080".into()),
            phone: Some("0170-123".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("signal", &bad_phone, Credentials::default()).is_err());
        let good = ChannelAddFields {
            url: Some("http://127.0.0.1:8080/".into()),
            phone: Some("+491701234567".into()),
            ..Default::default()
        };
        let c = stage_channel_add("signal", &good, Credentials::default()).unwrap();
        assert_eq!(c.signal_cli_url.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(c.signal_phone_number.as_deref(), Some("+491701234567"));
    }

    #[test]
    fn stage_add_line_secret_optional_push_only() {
        let push_only = ChannelAddFields {
            token: Some("line-token".into()),
            password: Some("  ".into()),
            ..Default::default()
        };
        let c = stage_channel_add("line", &push_only, Credentials::default()).unwrap();
        assert!(c.line_channel_access_token.is_some());
        assert!(c.line_channel_secret.is_none(), "blank secret stays unset");
        let full = ChannelAddFields {
            token: Some("line-token".into()),
            password: Some("channel-secret".into()),
            ..Default::default()
        };
        let c = stage_channel_add("line", &full, Credentials::default()).unwrap();
        assert!(c.line_channel_secret.is_some());
    }

    #[test]
    fn stage_add_irc_requires_bare_host_and_nick() {
        let with_scheme = ChannelAddFields {
            server: Some("https://irc.libera.chat".into()),
            nick: Some("neoth".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("irc", &with_scheme, Credentials::default()).is_err());
        let good = ChannelAddFields {
            server: Some("irc.libera.chat".into()),
            nick: Some("neoth".into()),
            password: Some("".into()),
            channels_csv: Some("#neoth,#dev".into()),
            ..Default::default()
        };
        let c = stage_channel_add("irc", &good, Credentials::default()).unwrap();
        assert_eq!(c.irc_server.as_deref(), Some("irc.libera.chat"));
        assert_eq!(c.irc_nick.as_deref(), Some("neoth"));
        assert!(c.irc_password.is_none(), "empty password stays unset");
        assert_eq!(c.irc_channels.as_deref(), Some("#neoth,#dev"));
    }

    #[test]
    fn stage_add_imessage_and_mattermost_aliases_and_urls() {
        for alias in ["imessage", "imessage_bluebubbles", "bluebubbles"] {
            let f = ChannelAddFields {
                url: Some("http://192.168.1.5:1234".into()),
                password: Some("bb-pass".into()),
                ..Default::default()
            };
            let c = stage_channel_add(alias, &f, Credentials::default()).unwrap();
            assert!(c.bluebubbles_url.is_some() && c.bluebubbles_password.is_some());
        }
        let f = ChannelAddFields {
            url: Some("https://mm.example.com/".into()),
            token: Some("mm-token".into()),
            ..Default::default()
        };
        let c = stage_channel_add("mattermost", &f, Credentials::default()).unwrap();
        assert_eq!(c.mattermost_url.as_deref(), Some("https://mm.example.com"));
        assert!(c.mattermost_token.is_some());
    }

    #[test]
    fn stage_add_gchat_validates_key_path_and_subscription() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("sa.json");
        std::fs::write(&key, "{}").unwrap();
        let key_str = key.display().to_string();
        // missing key file → err
        let f = ChannelAddFields {
            url: Some(dir.path().join("nope.json").display().to_string()),
            server: Some("projects/p/subscriptions/s".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("gchat", &f, Credentials::default()).is_err());
        // malformed subscription → err
        let f = ChannelAddFields {
            url: Some(key_str.clone()),
            server: Some("my-sub".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("gchat", &f, Credentials::default()).is_err());
        // good — both alias spellings
        for alias in ["gchat", "google_chat"] {
            let f = ChannelAddFields {
                url: Some(key_str.clone()),
                server: Some("projects/p/subscriptions/s".into()),
                ..Default::default()
            };
            let c = stage_channel_add(alias, &f, Credentials::default()).unwrap();
            assert_eq!(
                c.gchat_service_account_json.as_deref(),
                Some(key_str.as_str())
            );
            assert_eq!(
                c.gchat_subscription.as_deref(),
                Some("projects/p/subscriptions/s")
            );
        }
        // remove clears everything
        let mut base = Credentials::default();
        base.gchat_service_account_json = Some(key_str);
        base.gchat_subscription = Some("projects/p/subscriptions/s".into());
        base.gchat_allowed_sender = Some("users/1".into());
        let (c, removed) = stage_channel_remove("gchat", base).unwrap();
        assert!(removed);
        assert!(
            c.gchat_service_account_json.is_none()
                && c.gchat_subscription.is_none()
                && c.gchat_allowed_sender.is_none()
        );
    }

    #[test]
    fn stage_remove_b9_channels_clear_all_fields() {
        let mut base = Credentials::default();
        base.irc_server = Some("irc.libera.chat".into());
        base.irc_nick = Some("neoth".into());
        base.irc_allowed_nick = Some("alex".into());
        base.irc_allowed_account = Some("alex".into());
        let (c, removed) = stage_channel_remove("irc", base).unwrap();
        assert!(removed);
        assert!(
            c.irc_server.is_none()
                && c.irc_nick.is_none()
                && c.irc_allowed_nick.is_none()
                && c.irc_allowed_account.is_none()
        );
        let mut base = Credentials::default();
        base.bluebubbles_url = Some("http://x".into());
        base.bluebubbles_password = Some(SecretString::from("pw"));
        let (c, removed) = stage_channel_remove("imessage", base).unwrap();
        assert!(removed);
        assert!(c.bluebubbles_url.is_none() && c.bluebubbles_password.is_none());
        // removing an unconfigured B9 channel reports false, no error
        let (_, removed) = stage_channel_remove("signal", Credentials::default()).unwrap();
        assert!(!removed);
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
        assert!(
            c.telegram_token.is_some(),
            "existing telegram must be preserved"
        );
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
        assert!(
            c.slack_bot_token.is_none() && c.slack_app_token.is_none(),
            "slack cleared"
        );
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
    fn stage_remove_keet_clears_runtime_and_legacy_state() {
        let base = Credentials {
            keet_bridge_url: Some("http://127.0.0.1:9130".into()),
            keet_topic: Some(SecretString::from(TEST_KEET_TOPIC)),
            keet_allowed_senders: Some(TEST_KEET_SENDER.into()),
            keet_seed_phrase: Some(SecretString::from("legacy seed")),
            keet_bridge_bearer_token: Some(SecretString::from("legacy bearer")),
            slack_bot_token: Some(SecretString::from("xoxb-keep")),
            ..Default::default()
        };
        let (cleared, removed) = stage_channel_remove("keet", base).unwrap();
        assert!(removed);
        assert!(cleared.keet_bridge_url.is_none());
        assert!(cleared.keet_topic.is_none());
        assert!(cleared.keet_allowed_senders.is_none());
        assert!(cleared.keet_seed_phrase.is_none());
        assert!(cleared.keet_bridge_bearer_token.is_none());
        assert!(
            cleared.slack_bot_token.is_some(),
            "unrelated secret changed"
        );
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
    fn stage_remove_baileys_clears_only_baileys_fields() {
        let mut base = Credentials::default();
        base.whatsapp_token = Some(SecretString::from("meta"));
        base.whatsapp_baileys_url = Some("http://127.0.0.1:9120".into());
        base.whatsapp_baileys_token = Some(SecretString::from("0123456789abcdef0123456789abcdef"));
        base.whatsapp_baileys_allowed_senders = Some("+491701234567".into());
        base.whatsapp_baileys_allowed_groups = Some("120363012345678901@g.us".into());
        let (creds, removed) = stage_channel_remove("whatsapp_baileys", base).unwrap();
        assert!(removed);
        assert!(creds.whatsapp_baileys_url.is_none());
        assert!(creds.whatsapp_baileys_token.is_none());
        assert!(creds.whatsapp_baileys_allowed_senders.is_none());
        assert!(creds.whatsapp_baileys_allowed_groups.is_none());
        assert!(
            creds.whatsapp_token.is_some(),
            "Meta token must remain intact"
        );
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
        let total = ALL_CHANNELS.len();
        let table = render(&rows, &OutputFormat::Table).unwrap();
        assert!(table.contains("error"));
        assert!(table.contains("not_configured"));
        assert!(
            table.contains(&format!("1 of {total} channels configured")),
            "table: {table}"
        );
        let json = render(&rows, &OutputFormat::Json).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["configured"], 1);
        assert_eq!(v["total"], total);
        assert_eq!(v["channels"][0]["name"], "telegram");
        assert_eq!(v["channels"][0]["status"], "error");
        assert_eq!(v["channels"][0]["configured"], true);
    }

    #[test]
    fn add_json_reports_persistence_not_connection() {
        let value = add_result_json("telegram");
        assert_eq!(value["ok"], true);
        assert_eq!(value["saved"], true);
        assert!(value.get("configured").is_none());
        assert!(value.get("connected").is_none());
    }

    // ── ChannelAddFlags non-interactive path ─────────────────────────────

    #[test]
    fn flags_any_set_false_when_all_none() {
        assert!(!ChannelAddFlags::default().any_set());
    }

    #[test]
    fn flags_any_set_true_when_one_field_provided() {
        let f = ChannelAddFlags {
            token: Some("tok".into()),
            ..Default::default()
        };
        assert!(f.any_set());
    }

    #[test]
    fn flags_into_fields_maps_all_fields() {
        let flags = ChannelAddFlags {
            telegram_user_id: Some(42),
            token: Some("t".into()),
            bot_token: Some("b".into()),
            app_token: Some("a".into()),
            phone_id: Some("p".into()),
            verify_token: Some("v".into()),
            app_secret: Some("as".into()),
            seed: Some("s".into()),
            url: Some("u".into()),
            phone: Some("ph".into()),
            server: Some("sv".into()),
            nick: Some("n".into()),
            password: Some("pw".into()),
            channels_csv: Some("c".into()),
            allowed_sender: Some("@alice:example.org".into()),
            allowed_rooms_csv: Some("!safe:example.org".into()),
            allow_plaintext: true,
        };
        let f = flags.into_fields();
        assert_eq!(f.telegram_user_id, Some(42));
        assert_eq!(f.token.as_deref(), Some("t"));
        assert_eq!(f.bot_token.as_deref(), Some("b"));
        assert_eq!(f.app_token.as_deref(), Some("a"));
        assert_eq!(f.phone_id.as_deref(), Some("p"));
        assert_eq!(f.verify_token.as_deref(), Some("v"));
        assert_eq!(f.app_secret.as_deref(), Some("as"));
        assert_eq!(f.seed.as_deref(), Some("s"));
        assert_eq!(f.url.as_deref(), Some("u"));
        assert_eq!(f.phone.as_deref(), Some("ph"));
        assert_eq!(f.server.as_deref(), Some("sv"));
        assert_eq!(f.nick.as_deref(), Some("n"));
        assert_eq!(f.password.as_deref(), Some("pw"));
        assert_eq!(f.channels_csv.as_deref(), Some("c"));
        assert_eq!(f.allowed_sender.as_deref(), Some("@alice:example.org"));
        assert_eq!(f.allowed_rooms_csv.as_deref(), Some("!safe:example.org"));
        assert!(f.allow_plaintext);
    }

    /// Non-interactive add for telegram: flags → stage → write → credentials present.
    #[test]
    fn noninteractive_add_telegram_writes_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        let flags = ChannelAddFlags {
            telegram_user_id: Some(123_456_789),
            token: Some(valid_tg_token()),
            ..Default::default()
        };
        let fields = flags.into_fields();
        let updated = stage_channel_add("telegram", &fields, Credentials::default()).unwrap();
        updated.write(&path).unwrap();
        let reloaded = Credentials::load_or_default(&path).unwrap();
        assert_eq!(
            reloaded.telegram_token.as_ref().unwrap().expose(),
            valid_tg_token()
        );
    }

    /// Non-interactive add for slack: --bot-token + --app-token → credentials stored.
    #[test]
    fn noninteractive_add_slack_writes_both_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        let flags = ChannelAddFlags {
            bot_token: Some("xoxb-1".into()),
            app_token: Some("xapp-1".into()),
            ..Default::default()
        };
        let fields = flags.into_fields();
        let updated = stage_channel_add("slack", &fields, Credentials::default()).unwrap();
        updated.write(&path).unwrap();
        let reloaded = Credentials::load_or_default(&path).unwrap();
        assert!(reloaded.slack_bot_token.is_some() && reloaded.slack_app_token.is_some());
    }

    /// Missing required field (no --token for telegram) → stage_channel_add errors.
    #[test]
    fn noninteractive_add_missing_required_field_errors() {
        let flags = ChannelAddFlags {
            // token intentionally absent
            ..Default::default()
        };
        let fields = flags.into_fields();
        let err = stage_channel_add("telegram", &fields, Credentials::default()).unwrap_err();
        assert!(
            err.to_string().contains("missing"),
            "expected 'missing' in: {err}"
        );
    }

    /// required_flags_for returns the right hint for every known channel.
    #[test]
    fn required_flags_for_covers_known_channels() {
        let channels = [
            "telegram",
            "slack",
            "whatsapp",
            "whatsapp_business",
            "keet",
            "discord",
            "signal",
            "line",
            "irc",
            "imessage",
            "imessage_bluebubbles",
            "bluebubbles",
            "mattermost",
            "gchat",
            "google_chat",
            "matrix",
            "twitch",
            "nostr",
        ];
        for ch in channels {
            let hint = required_flags_for(ch);
            assert!(
                !hint.is_empty() && hint != "(unknown channel)",
                "missing hint for channel `{ch}`"
            );
        }
    }

    // ── B17 regression tests ──────────────────────────────────────────────

    fn write_malformed(path: &std::path::Path) {
        std::fs::write(path, "this is = not [valid yaml SENTINEL").unwrap();
    }

    fn write_invalid_utf8(path: &std::path::Path) {
        std::fs::write(path, [0xFF, 0xFE, 0x00, 0x42]).unwrap();
    }

    fn malformed_original_bytes(path: &std::path::Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    fn write_default_freedom(home: &std::path::Path) {
        std::fs::write(
            home.join("freedom.yaml"),
            serde_yaml::to_string(&FreedomConfig::default()).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn run_add_and_remove_telegram_commit_complete_adoption() {
        let home = tempfile::tempdir().unwrap();
        write_default_freedom(home.path());
        let flags = ChannelAddFlags {
            telegram_user_id: Some(123_456_789),
            token: Some(valid_tg_token()),
            ..Default::default()
        };

        run_add_at(home.path(), "telegram", &flags, &OutputFormat::Json)
            .await
            .unwrap();

        let config = FreedomConfig::load_from_path(&home.path().join("freedom.yaml")).unwrap();
        let credentials =
            Credentials::load_or_default(&home.path().join("credentials.yaml")).unwrap();
        assert_eq!(config.telegram_user_id, Some(123_456_789));
        assert_eq!(
            credentials.telegram_token.as_ref().unwrap().expose(),
            valid_tg_token()
        );
        let telegram = channel_statuses(&config, &credentials)
            .into_iter()
            .find(|row| row.name == "telegram")
            .unwrap();
        assert_eq!(telegram.status, ProbeStatus::Ok);

        let reload_sentinel = home
            .path()
            .join(crate::config::reload::RELOAD_SENTINEL_NAME);
        assert!(reload_sentinel.exists());
        std::fs::remove_file(&reload_sentinel).unwrap();

        run_remove_at(home.path(), "telegram", &OutputFormat::Json).unwrap();

        let config = FreedomConfig::load_from_path(&home.path().join("freedom.yaml")).unwrap();
        let credentials =
            Credentials::load_or_default(&home.path().join("credentials.yaml")).unwrap();
        assert_eq!(config.telegram_user_id, None);
        assert!(credentials.telegram_token.is_none());
        let telegram = channel_statuses(&config, &credentials)
            .into_iter()
            .find(|row| row.name == "telegram")
            .unwrap();
        assert_eq!(telegram.status, ProbeStatus::NotConfigured);
        assert!(reload_sentinel.exists());
    }

    #[tokio::test]
    async fn run_add_telegram_malformed_freedom_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        let freedom_path = home.path().join("freedom.yaml");
        let credentials_path = home.path().join("credentials.yaml");
        let malformed = b"telegram_user_id: [broken\n";
        let original_credentials = "discord_bot_token: existing-discord-token\n";
        std::fs::write(&freedom_path, malformed).unwrap();
        std::fs::write(&credentials_path, original_credentials).unwrap();
        let flags = ChannelAddFlags {
            telegram_user_id: Some(123_456_789),
            token: Some(valid_tg_token()),
            ..Default::default()
        };

        let error = run_add_at(home.path(), "telegram", &flags, &OutputFormat::Json)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("update Telegram token + sender policy")
        );
        assert_eq!(std::fs::read(&freedom_path).unwrap(), malformed);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            original_credentials.as_bytes()
        );
        assert!(
            !home
                .path()
                .join(crate::config::reload::RELOAD_SENTINEL_NAME)
                .exists()
        );
    }

    #[test]
    fn run_add_malformed_yaml_exits_nonzero_file_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        write_malformed(&path);
        let original = malformed_original_bytes(&path);

        // Simulate non-interactive flag path so stdin isn't needed.
        let flags = ChannelAddFlags {
            telegram_user_id: Some(123_456_789),
            token: Some(valid_tg_token()),
            ..Default::default()
        };
        // We can't call run_add without tokio here, so test the underlying
        // update_at directly (which run_add delegates to).
        let r = Credentials::update_at(&path, |c| {
            let updated = stage_channel_add("telegram", &flags.clone().into_fields(), c.clone())?;
            *c = updated;
            Ok(())
        });
        assert!(r.is_err(), "update_at on malformed YAML must return Err");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "malformed file bytes must be unchanged"
        );
    }

    #[test]
    fn run_remove_malformed_yaml_exits_nonzero_file_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        write_malformed(&path);
        let original = malformed_original_bytes(&path);

        let mut was_removed = false;
        let r = Credentials::update_at(&path, |c| {
            let (updated, removed) = stage_channel_remove("telegram", c.clone())?;
            *c = updated;
            was_removed = removed;
            Ok(())
        });
        assert!(r.is_err(), "update_at on malformed YAML must return Err");
        assert!(!was_removed);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn run_list_malformed_yaml_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        write_malformed(&path);
        // run_list calls load_or_default with ? — test that load fails.
        let r = Credentials::load_or_default(&path);
        assert!(r.is_err(), "malformed YAML must propagate as Err");
    }

    #[test]
    fn run_test_malformed_yaml_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        write_malformed(&path);
        let r = Credentials::load_or_default(&path);
        assert!(
            r.is_err(),
            "malformed YAML must propagate as Err for run_test path"
        );
    }

    #[tokio::test]
    async fn test_channel_at_malformed_config_fails_closed_and_preserves_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let malformed = b"telegram_user_id: [broken\n";
        std::fs::write(&path, malformed).unwrap();

        let error = test_channel_at(dir.path(), "telegram").await.unwrap_err();

        assert!(error.to_string().contains("load config"));
        assert_eq!(std::fs::read(path).unwrap(), malformed);
    }

    #[test]
    fn run_add_invalid_utf8_is_err_and_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        write_invalid_utf8(&path);
        let original = malformed_original_bytes(&path);

        let r = Credentials::update_at(&path, |_c| -> anyhow::Result<()> { Ok(()) });
        assert!(r.is_err(), "update_at on invalid UTF-8 must return Err");
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn run_add_missing_file_succeeds() {
        // Fresh install: no credentials.yaml → update_at creates it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        assert!(!path.exists());
        Credentials::update_at(&path, |c| {
            let fields = ChannelAddFields {
                telegram_user_id: Some(123_456_789),
                token: Some(valid_tg_token()),
                ..Default::default()
            };
            let updated = stage_channel_add("telegram", &fields, c.clone())?;
            *c = updated;
            Ok(())
        })
        .unwrap();
        let loaded = Credentials::load_or_default(&path).unwrap();
        assert!(loaded.telegram_token.is_some());
    }

    // ── B21 new tests ─────────────────────────────────────────────────────

    /// channel_statuses must return exactly one row per ALL_CHANNELS entry, no
    /// omissions and no duplicates — by construction the "add succeeds, list
    /// omits" bug becomes impossible.
    #[test]
    fn all_channels_and_list_have_one_to_one_coverage() {
        let rows = channel_statuses(&FreedomConfig::default(), &creds_empty());
        assert_eq!(
            rows.len(),
            ALL_CHANNELS.len(),
            "channel_statuses row count must equal ALL_CHANNELS"
        );
        for kind in &ALL_CHANNELS {
            let name = kind.as_str();
            assert!(
                rows.iter().any(|r| r.name == name),
                "channel `{name}` from ALL_CHANNELS is missing from channel_statuses output"
            );
        }
        // No duplicates.
        let mut seen = std::collections::HashSet::new();
        for r in &rows {
            assert!(
                seen.insert(r.name),
                "duplicate channel name `{}` in output",
                r.name
            );
        }
    }

    /// Helper: minimum credentials needed for a channel to appear as configured.
    fn min_creds_for_channel(name: &str) -> Credentials {
        let mut c = Credentials::default();
        match name {
            "telegram" => {
                c.telegram_token = Some(SecretString::from(
                    "123456789:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ))
            }
            "slack" => {
                c.slack_bot_token = Some(SecretString::from("xoxb-1"));
                c.slack_app_token = Some(SecretString::from("xapp-1"));
            }
            "whatsapp_business" => {
                c.whatsapp_token = Some(SecretString::from("tok"));
                c.whatsapp_phone_id = Some("1234567890".into());
            }
            "whatsapp_baileys" => {
                c.whatsapp_baileys_url = Some("http://127.0.0.1:9120".into());
                c.whatsapp_baileys_token =
                    Some(SecretString::from("0123456789abcdef0123456789abcdef"));
                c.whatsapp_baileys_allowed_senders = Some("+491701234567".into());
            }
            "keet" => {
                c.keet_bridge_url = Some("http://127.0.0.1:9130".into());
                c.keet_topic = Some(SecretString::from(TEST_KEET_TOPIC));
                c.keet_allowed_senders = Some(TEST_KEET_SENDER.into());
                c.keet_bridge_bearer_token =
                    Some(SecretString::from("0123456789abcdef0123456789abcdef"));
            }
            "discord" => c.discord_bot_token = Some(SecretString::from("bot")),
            "signal" => {
                c.signal_cli_url = Some("http://127.0.0.1:8080".into());
                c.signal_phone_number = Some("+491701234567".into());
            }
            "imessage_bluebubbles" => {
                c.bluebubbles_url = Some("http://192.168.1.1:1234".into());
                c.bluebubbles_password = Some(SecretString::from("pw"));
            }
            "matrix" => {
                c.matrix_homeserver = Some("https://matrix.org".into());
                c.matrix_user_id = Some("@bot:matrix.org".into());
                c.matrix_password = Some(SecretString::from("pw"));
            }
            "line" => c.line_channel_access_token = Some(SecretString::from("tok")),
            "irc" => {
                c.irc_server = Some("irc.libera.chat".into());
                c.irc_nick = Some("neoth".into());
            }
            "mattermost" => {
                c.mattermost_url = Some("https://mm.example.com".into());
                c.mattermost_token = Some(SecretString::from("tok"));
            }
            "twitch" => {
                c.twitch_username = Some("neoth_bot".into());
                c.twitch_oauth_token = Some(SecretString::from("oauth:abc"));
                c.twitch_channels = Some("#neoth".into());
            }
            "nostr" => {
                c.nostr_secret_key = Some(SecretString::from("nsec1test"));
                c.nostr_relays = Some("wss://relay.example.com".into());
            }
            "gchat" => {
                c.gchat_service_account_json = Some("/path/to/sa.json".into());
                c.gchat_subscription = Some("projects/p/subscriptions/s".into());
            }
            _ => {}
        }
        c
    }

    /// For every channel in ALL_CHANNELS, plan_channel_test with the canonical
    /// as_str() name must never return Unknown — only NotConfigured, a live plan,
    /// or a typed unavailable plan.
    #[test]
    fn no_unknown_test_plan_for_configured_channel() {
        let cfg = FreedomConfig::default();
        for kind in &ALL_CHANNELS {
            let name = kind.as_str();
            let creds = min_creds_for_channel(name);
            let plan = plan_channel_test(name, &cfg, &creds);
            assert_ne!(
                plan,
                ChannelTestPlan::Unknown,
                "channel `{name}` returned Unknown from plan_channel_test"
            );
            // Also check: empty creds → NotConfigured not Unknown.
            let empty_plan = plan_channel_test(name, &cfg, &creds_empty());
            assert_ne!(
                empty_plan,
                ChannelTestPlan::Unknown,
                "channel `{name}` with empty creds returned Unknown (must be NotConfigured)"
            );
        }
    }

    /// Adding via CLI alias should appear as configured in channel_statuses.
    #[test]
    fn every_addable_alias_appears_in_channel_statuses() {
        // "whatsapp" alias maps to "whatsapp_business" in the list.
        let mut creds = creds_empty();
        creds.whatsapp_token = Some(SecretString::from("tok"));
        creds.whatsapp_phone_id = Some("1234567890".into());
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(
            rows.iter()
                .find(|r| r.name == "whatsapp_business")
                .unwrap()
                .configured,
            "whatsapp add should appear as whatsapp_business configured"
        );
        // "imessage" / "bluebubbles" alias → "imessage_bluebubbles"
        let mut creds2 = creds_empty();
        creds2.bluebubbles_url = Some("http://x".into());
        creds2.bluebubbles_password = Some(SecretString::from("pw"));
        let rows2 = channel_statuses(&FreedomConfig::default(), &creds2);
        assert!(
            rows2
                .iter()
                .find(|r| r.name == "imessage_bluebubbles")
                .unwrap()
                .configured,
            "imessage/bluebubbles add should appear as imessage_bluebubbles configured"
        );
        // "google_chat" alias → "gchat"
        let mut creds3 = creds_empty();
        creds3.gchat_service_account_json = Some("/p".into());
        creds3.gchat_subscription = Some("projects/p/subscriptions/s".into());
        let rows3 = channel_statuses(&FreedomConfig::default(), &creds3);
        assert!(
            rows3.iter().find(|r| r.name == "gchat").unwrap().configured,
            "google_chat add should appear as gchat configured"
        );
    }

    /// Partial creds report consistently between channel_statuses and probe_channel.
    #[test]
    fn partial_creds_give_consistent_status_in_list_and_probe() {
        use crate::channels::ChannelKind;
        use crate::channels::probe::{ChannelCredsView, probe_channel};

        // Signal: only URL — probe gives Error, list gives configured=true.
        let mut creds = creds_empty();
        creds.signal_cli_url = Some("http://127.0.0.1:8080".into());
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        assert!(
            rows.iter().find(|r| r.name == "signal").unwrap().configured,
            "partial signal: Error → configured=true"
        );
        let view = ChannelCredsView::from_config(None, &creds);
        assert_eq!(
            probe_channel(ChannelKind::Signal, &view).status,
            ProbeStatus::Error,
            "probe_channel must agree with channel_statuses for partial signal"
        );

        // Slack: only bot token — probe gives Error, list gives configured=true.
        let mut creds2 = creds_empty();
        creds2.slack_bot_token = Some(SecretString::from("xoxb-1"));
        let rows2 = channel_statuses(&FreedomConfig::default(), &creds2);
        assert!(
            rows2.iter().find(|r| r.name == "slack").unwrap().configured,
            "partial slack: Error → configured=true"
        );
        let view2 = ChannelCredsView::from_config(None, &creds2);
        assert_eq!(
            probe_channel(ChannelKind::Slack, &view2).status,
            ProbeStatus::Error
        );
    }

    /// Feature-gated channels must name their feature. Legacy Keet seed state
    /// remains a visible error and never counts as a companion capability.
    #[test]
    fn feature_gated_channels_show_feature_requirement_in_detail() {
        // Matrix → detail must mention "matrix-channel".
        let mut creds = creds_empty();
        creds.matrix_homeserver = Some("https://matrix.org".into());
        creds.matrix_user_id = Some("@bot:matrix.org".into());
        creds.matrix_password = Some(SecretString::from("pw"));
        let rows = channel_statuses(&FreedomConfig::default(), &creds);
        let m = rows.iter().find(|r| r.name == "matrix").unwrap();
        assert!(
            m.detail.contains("matrix-channel"),
            "matrix detail must mention feature: {}",
            m.detail
        );

        // IRC → detail must mention "irc-channel".
        let mut creds2 = creds_empty();
        creds2.irc_server = Some("irc.libera.chat".into());
        creds2.irc_nick = Some("neoth".into());
        let rows2 = channel_statuses(&FreedomConfig::default(), &creds2);
        let i = rows2.iter().find(|r| r.name == "irc").unwrap();
        assert!(
            i.detail.contains("irc-channel"),
            "irc detail must mention feature: {}",
            i.detail
        );

        // Keet with only a legacy seed stays broken and never claims transport.
        let mut creds3 = creds_empty();
        creds3.keet_seed_phrase = Some(SecretString::from("x"));
        let rows3 = channel_statuses(&FreedomConfig::default(), &creds3);
        let k = rows3.iter().find(|r| r.name == "keet").unwrap();
        assert!(
            k.configured && k.status == ProbeStatus::Error && k.detail.contains("ignored"),
            "Keet detail must flag incomplete companion configuration: {}",
            k.detail
        );

        // Nostr → detail must mention "nostr-channel".
        let mut creds4 = creds_empty();
        creds4.nostr_secret_key = Some(SecretString::from("nsec1test"));
        creds4.nostr_relays = Some("wss://relay.example.com".into());
        let rows4 = channel_statuses(&FreedomConfig::default(), &creds4);
        let n = rows4.iter().find(|r| r.name == "nostr").unwrap();
        assert!(
            n.detail.contains("nostr-channel"),
            "nostr detail must mention feature: {}",
            n.detail
        );
    }

    #[test]
    fn matrix_add_requires_homeserver_and_auth() {
        // Missing nick (user_id) → fail.
        let url_only = ChannelAddFields {
            url: Some("https://matrix.org".into()),
            password: Some("pw".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("matrix", &url_only, Credentials::default()).is_err());

        // Missing auth (no password, no token) → fail.
        let no_auth = ChannelAddFields {
            url: Some("https://matrix.org".into()),
            nick: Some("@bot:matrix.org".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("matrix", &no_auth, Credentials::default()).is_err());

        // url + nick + password → ok, stores password not access_token.
        let good_pw = ChannelAddFields {
            url: Some("https://matrix.org".into()),
            nick: Some("@bot:matrix.org".into()),
            password: Some("pw".into()),
            ..Default::default()
        };
        let c = stage_channel_add("matrix", &good_pw, Credentials::default()).unwrap();
        assert_eq!(c.matrix_homeserver.as_deref(), Some("https://matrix.org"));
        assert_eq!(c.matrix_user_id.as_deref(), Some("@bot:matrix.org"));
        assert!(c.matrix_password.is_some());
        assert!(c.matrix_access_token.is_none());
        assert_eq!(c.matrix_require_encryption, Some(true));

        // url + nick + token → ok, stores access_token not password.
        let good_tok = ChannelAddFields {
            url: Some("https://matrix.org".into()),
            nick: Some("@bot:matrix.org".into()),
            token: Some("syt_abc".into()),
            ..Default::default()
        };
        let c2 = stage_channel_add("matrix", &good_tok, Credentials::default()).unwrap();
        assert!(c2.matrix_access_token.is_some());
        assert!(c2.matrix_password.is_none());

        // When both are supplied the token is retained and wins at runtime;
        // password remains a deliberate fallback, never silently discarding
        // the explicitly configured token.
        let both = ChannelAddFields {
            url: Some("https://matrix.org".into()),
            nick: Some("@bot:matrix.org".into()),
            password: Some("pw".into()),
            token: Some("syt_preferred".into()),
            allowed_sender: Some("@alice:matrix.org".into()),
            allowed_rooms_csv: Some("!safe:matrix.org, !ops:matrix.org, !safe:matrix.org".into()),
            allow_plaintext: true,
            ..Default::default()
        };
        let c3 = stage_channel_add("matrix", &both, Credentials::default()).unwrap();
        assert!(c3.matrix_password.is_some());
        assert_eq!(
            c3.matrix_access_token.as_ref().map(|v| v.expose()),
            Some("syt_preferred")
        );
        assert_eq!(
            c3.matrix_allowed_user_id.as_deref(),
            Some("@alice:matrix.org")
        );
        assert_eq!(
            c3.matrix_allowed_room_ids.as_deref(),
            Some("!ops:matrix.org,!safe:matrix.org")
        );
        assert_eq!(c3.matrix_require_encryption, Some(false));

        let invalid_policy = ChannelAddFields {
            url: Some("https://matrix.org".into()),
            nick: Some("@bot:matrix.org".into()),
            token: Some("syt_abc".into()),
            allowed_rooms_csv: Some("not-a-room".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("matrix", &invalid_policy, Credentials::default()).is_err());

        // remove clears all matrix fields.
        let (cleared, removed) = stage_channel_remove("matrix", c3).unwrap();
        assert!(removed);
        assert!(
            cleared.matrix_homeserver.is_none()
                && cleared.matrix_user_id.is_none()
                && cleared.matrix_password.is_none()
                && cleared.matrix_access_token.is_none()
                && cleared.matrix_allowed_user_id.is_none()
                && cleared.matrix_allowed_room_ids.is_none()
                && cleared.matrix_require_encryption.is_none()
        );
    }

    #[test]
    fn twitch_add_and_remove_roundtrip() {
        let f = ChannelAddFields {
            nick: Some("NEOTH_Bot".into()),
            token: Some("oauth:abc123".into()),
            channels_csv: Some(" MyRoom, #other_room, #MYROOM ".into()),
            ..Default::default()
        };
        let c = stage_channel_add("twitch", &f, Credentials::default()).unwrap();
        assert_eq!(c.twitch_username.as_deref(), Some("neoth_bot"));
        assert!(c.twitch_oauth_token.is_some());
        assert_eq!(c.twitch_channels.as_deref(), Some("#myroom,#other_room"));

        let missing_rooms = ChannelAddFields {
            nick: Some("neoth_bot".into()),
            token: Some("oauth:abc123".into()),
            ..Default::default()
        };
        assert!(stage_channel_add("twitch", &missing_rooms, Credentials::default()).is_err());

        let (cleared, removed) = stage_channel_remove("twitch", c).unwrap();
        assert!(removed);
        assert!(cleared.twitch_username.is_none() && cleared.twitch_oauth_token.is_none());

        // Removing unconfigured twitch → false, no error.
        let (_, r) = stage_channel_remove("twitch", Credentials::default()).unwrap();
        assert!(!r);
    }

    #[cfg(feature = "nostr-channel")]
    #[test]
    fn nostr_add_uses_runtime_key_parser_and_secure_relay_validator() {
        let hex64 = ChannelAddFields {
            token: Some("11".repeat(32)),
            channels_csv: Some("WSS://Relay.Example.com, wss://relay.example.com/room".into()),
            ..Default::default()
        };
        let c = stage_channel_add("nostr", &hex64, Credentials::default()).unwrap();
        assert!(c.nostr_secret_key.is_some());
        assert_eq!(
            c.nostr_relays.as_deref(),
            Some("wss://relay.example.com/,wss://relay.example.com/room")
        );

        let leaked_secret = "nsec1-not-a-real-key-secret-material";
        let bad_key = ChannelAddFields {
            token: Some(leaked_secret.into()),
            channels_csv: Some("wss://relay.example.com".into()),
            ..Default::default()
        };
        let error = stage_channel_add("nostr", &bad_key, Credentials::default())
            .unwrap_err()
            .to_string();
        assert!(!error.contains(leaked_secret));

        for relay in ["ws://relay.example.com", "https://relay.example.com"] {
            let insecure = ChannelAddFields {
                token: Some("11".repeat(32)),
                channels_csv: Some(relay.into()),
                ..Default::default()
            };
            assert!(stage_channel_add("nostr", &insecure, Credentials::default()).is_err());
        }

        // Missing relays → rejected.
        let no_relays = ChannelAddFields {
            token: Some("11".repeat(32)),
            channels_csv: None,
            ..Default::default()
        };
        assert!(stage_channel_add("nostr", &no_relays, Credentials::default()).is_err());

        // Remove clears all nostr fields.
        let mut base = Credentials::default();
        base.nostr_secret_key = Some(SecretString::from("nsec1test"));
        base.nostr_relays = Some("wss://relay.example.com".into());
        base.nostr_allowed_pubkey = Some("npub1abc".into());
        let (cleared, removed) = stage_channel_remove("nostr", base).unwrap();
        assert!(removed);
        assert!(
            cleared.nostr_secret_key.is_none()
                && cleared.nostr_relays.is_none()
                && cleared.nostr_allowed_pubkey.is_none()
        );
    }

    #[cfg(not(feature = "nostr-channel"))]
    #[test]
    fn nostr_add_refuses_when_runtime_is_not_compiled() {
        let fields = ChannelAddFields {
            token: Some("11".repeat(32)),
            channels_csv: Some("wss://relay.example.com".into()),
            ..Default::default()
        };
        let error = stage_channel_add("nostr", &fields, Credentials::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("lacks the `nostr-channel` feature"));
        assert!(!error.contains(&"11".repeat(32)));
    }

    #[test]
    fn channel_test_plan_routes_all_readiness_adapters() {
        let cfg = FreedomConfig::default();

        // Empty creds → NotConfigured (not Unknown).
        assert_eq!(
            plan_channel_test("signal", &cfg, &creds_empty()),
            ChannelTestPlan::NotConfigured
        );

        // Fully configured Signal has a non-consuming `/v1/accounts` probe.
        let mut creds = creds_empty();
        creds.signal_cli_url = Some("http://127.0.0.1:8080".into());
        creds.signal_phone_number = Some("+491701234567".into());
        assert_eq!(
            plan_channel_test("signal", &cfg, &creds),
            ChannelTestPlan::Signal
        );

        // whatsapp_baileys → NotConfigured with no dedicated creds.
        assert_eq!(
            plan_channel_test("whatsapp_baileys", &cfg, &creds_empty()),
            ChannelTestPlan::NotConfigured
        );
        let mut baileys = creds_empty();
        baileys.whatsapp_baileys_url = Some("http://127.0.0.1:9120".into());
        baileys.whatsapp_baileys_token =
            Some(SecretString::from("0123456789abcdef0123456789abcdef"));
        baileys.whatsapp_baileys_allowed_senders = Some("+491701234567".into());
        assert_eq!(
            plan_channel_test("whatsapp_baileys", &cfg, &baileys),
            ChannelTestPlan::WhatsappBaileys
        );

        // Matrix is a typed plan; the dispatcher distinguishes safe token auth
        // from side-effectful password login.
        let mut creds2 = creds_empty();
        creds2.matrix_homeserver = Some("https://matrix.org".into());
        creds2.matrix_user_id = Some("@bot:matrix.org".into());
        creds2.matrix_password = Some(SecretString::from("pw"));
        assert_eq!(
            plan_channel_test("matrix", &cfg, &creds2),
            ChannelTestPlan::Matrix
        );

        // Nostr connects without subscribing or publishing.
        let mut creds3 = creds_empty();
        creds3.nostr_secret_key = Some(SecretString::from("nsec1test"));
        creds3.nostr_relays = Some("wss://relay.example.com".into());
        assert_eq!(
            plan_channel_test("nostr", &cfg, &creds3),
            ChannelTestPlan::Nostr
        );

        let mut irc = creds_empty();
        irc.irc_server = Some("irc.example.org".into());
        irc.irc_nick = Some("neoth".into());
        assert_eq!(plan_channel_test("irc", &cfg, &irc), ChannelTestPlan::Irc);

        let mut line = creds_empty();
        line.line_channel_secret = Some(SecretString::from("secret-only"));
        assert_eq!(
            plan_channel_test("line", &cfg, &line),
            ChannelTestPlan::Line,
            "partial LINE credentials must become a typed failure, not skipped"
        );

        // Truly unknown name still returns Unknown.
        assert_eq!(
            plan_channel_test("totally_bogus_channel", &cfg, &creds_empty()),
            ChannelTestPlan::Unknown
        );
    }
}
