//! GOLD-ADOPT-27 — channel health-probe registry (Agent-Reach "channel doctor").
//!
//! A pure, per-[`ChannelKind`] config-completeness check so operators instantly
//! see which channel adapters are live, misconfigured, or simply absent —
//! surfaced in `neoth status` and warned by the MONITOR cron.
//!
//! The probe is PURE: it classifies a [`ChannelCredsView`] (presence booleans
//! only — never a secret value) into a [`ProbeStatus`] + an operator-readable
//! message. The view is assembled from `freedom.yaml` + `credentials.yaml`; the
//! probe itself does no IO, so it is trivially testable and can't leak a token.

use crate::channels::ChannelKind;

/// Health verdict for one channel adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    /// Fully configured — the adapter can run.
    Ok,
    /// Usable but with a gap an operator should know about (e.g. send works,
    /// inbound doesn't).
    Warn,
    /// Partially configured in a way that WILL fail (e.g. one of a required
    /// token pair) — operator action required.
    Error,
    /// Named for backward compatibility, but no supported adapter exists.
    /// Credentials cannot make this channel runnable.
    Unavailable,
    /// No credentials present — the channel is simply off (not an error).
    NotConfigured,
}

impl ProbeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeStatus::Ok => "ok",
            ProbeStatus::Warn => "warn",
            ProbeStatus::Error => "error",
            ProbeStatus::Unavailable => "unavailable",
            ProbeStatus::NotConfigured => "not_configured",
        }
    }
    /// A glyph for the `neoth status` table.
    pub fn glyph(self) -> &'static str {
        match self {
            ProbeStatus::Ok => "✓",
            ProbeStatus::Warn => "⚠",
            ProbeStatus::Error => "✗",
            ProbeStatus::Unavailable => "⊘",
            ProbeStatus::NotConfigured => "·",
        }
    }
}

/// One channel's health row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelHealth {
    /// Stable snake_case channel id ([`ChannelKind::as_str`]).
    pub channel: &'static str,
    pub status: ProbeStatus,
    pub message: String,
}

/// Credential-presence view the pure probe classifies. Booleans only — assembled
/// from the config + credentials so the probe never touches a secret value.
#[derive(Debug, Clone, Default)]
pub struct ChannelCredsView {
    pub telegram_token: bool,
    pub telegram_user_id: bool,
    pub slack_bot: bool,
    pub slack_app: bool,
    pub whatsapp_token: bool,
    pub whatsapp_phone_id: bool,
    pub whatsapp_verify_token: bool,
    pub whatsapp_baileys_url: bool,
    pub whatsapp_baileys_token: bool,
    pub whatsapp_baileys_allowed_senders: bool,
    pub whatsapp_baileys_allowed_groups: bool,
    /// A legacy Keet seed is present. It is never consumed by a transport.
    pub keet_seed: bool,
    pub discord_bot: bool,
    pub signal_cli_url: bool,
    /// GOLD-FEAT-10b — BlueBubbles iMessage relay.
    pub bluebubbles_url: bool,
    pub bluebubbles_password: bool,
    pub signal_phone_number: bool,
    pub matrix_homeserver: bool,
    pub matrix_user_id: bool,
    /// True when EITHER a password OR a pre-issued access token is present.
    pub matrix_login: bool,
    /// Any Matrix field is present, including store/policy-only partial config.
    /// Keeps auxiliary-only adoptions visible as errors instead of silently
    /// classifying them as unconfigured.
    pub matrix_config_present: bool,
    /// At least one explicit invite rule exists (allowed sender or room ids).
    pub matrix_invite_policy: bool,
    /// Effective encrypted-room policy (`None` in legacy config means true).
    pub matrix_encryption_required: bool,
    /// GOLD-FEAT-10 — LINE long-lived channel access token (sending) present.
    pub line_access_token: bool,
    /// GOLD-FEAT-10 — LINE channel secret (inbound signature verify) present.
    pub line_channel_secret: bool,
    /// GOLD-FEAT-10 — IRC server host present.
    pub irc_server: bool,
    /// GOLD-FEAT-10 — IRC bot nick present.
    pub irc_nick: bool,
    /// GOLD-FEAT-10 — Mattermost server URL present.
    pub mattermost_url: bool,
    /// GOLD-FEAT-10 — Mattermost personal-access/bot token present.
    pub mattermost_token: bool,
    /// GOLD-FEAT-10 — Twitch bot username present.
    pub twitch_username: bool,
    /// GOLD-FEAT-10 — Twitch OAuth token present.
    pub twitch_oauth: bool,
    /// GOLD-FEAT-10 — Nostr identity secret key present.
    pub nostr_key: bool,
    /// GOLD-FEAT-10 — Nostr relay list present.
    pub nostr_relays: bool,
    /// B9 — Google Chat service-account JSON path present.
    pub gchat_sa_json: bool,
    /// B9 — Google Chat Pub/Sub subscription name present.
    pub gchat_subscription: bool,
}

impl ChannelCredsView {
    /// Assemble from the loaded `freedom.yaml` (telegram lives there) +
    /// `credentials.yaml` (everything else). Matrix additionally rejects blank
    /// values, but no secret value is copied, retained, or rendered.
    pub fn from_config(
        cfg: Option<&crate::config::FreedomConfig>,
        creds: &crate::config::credentials::Credentials,
    ) -> Self {
        let matrix_homeserver = creds
            .matrix_homeserver
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let matrix_user_id = creds
            .matrix_user_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let matrix_login = creds
            .matrix_password
            .as_ref()
            .is_some_and(|value| !value.expose().trim().is_empty())
            || creds
                .matrix_access_token
                .as_ref()
                .is_some_and(|value| !value.expose().trim().is_empty());
        let matrix_invite_policy = creds
            .matrix_allowed_user_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || creds
                .matrix_allowed_room_ids
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
        let matrix_config_present = creds.matrix_homeserver.is_some()
            || creds.matrix_user_id.is_some()
            || creds.matrix_password.is_some()
            || creds.matrix_access_token.is_some()
            || creds.matrix_store_path.is_some()
            || creds.matrix_allowed_user_id.is_some()
            || creds.matrix_allowed_room_ids.is_some()
            || creds.matrix_require_encryption.is_some();
        Self {
            telegram_token: cfg.is_some_and(|c| c.telegram_token.is_some())
                || creds.telegram_token.is_some(),
            telegram_user_id: cfg.is_some_and(|c| c.telegram_user_id.is_some()),
            slack_bot: creds.slack_bot_token.is_some(),
            slack_app: creds.slack_app_token.is_some(),
            whatsapp_token: creds.whatsapp_token.is_some(),
            whatsapp_phone_id: creds.whatsapp_phone_id.is_some(),
            whatsapp_verify_token: creds.whatsapp_verify_token.is_some(),
            whatsapp_baileys_url: creds
                .whatsapp_baileys_url
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            whatsapp_baileys_token: creds
                .whatsapp_baileys_token
                .as_ref()
                .is_some_and(|value| !value.expose().trim().is_empty()),
            whatsapp_baileys_allowed_senders: creds
                .whatsapp_baileys_allowed_senders
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            whatsapp_baileys_allowed_groups: creds
                .whatsapp_baileys_allowed_groups
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            keet_seed: creds.keet_seed_phrase.is_some(),
            // GOLD-PROG-16 wired `credentials.discord_bot_token`; serve_tasks
            // now builds `DiscordChannel::new(creds.discord_bot_token)` + spawns
            // the gateway receive loop, so presence == configured.
            discord_bot: creds.discord_bot_token.is_some(),
            signal_cli_url: creds.signal_cli_url.is_some(),
            bluebubbles_url: creds.bluebubbles_url.is_some(),
            bluebubbles_password: creds.bluebubbles_password.is_some(),
            signal_phone_number: creds.signal_phone_number.is_some(),
            matrix_homeserver,
            matrix_user_id,
            matrix_login,
            matrix_config_present,
            matrix_invite_policy,
            matrix_encryption_required: creds.matrix_requires_encryption(),
            line_access_token: creds.line_channel_access_token.is_some(),
            line_channel_secret: creds.line_channel_secret.is_some(),
            irc_server: creds.irc_server.is_some(),
            irc_nick: creds.irc_nick.is_some(),
            mattermost_url: creds.mattermost_url.is_some(),
            mattermost_token: creds.mattermost_token.is_some(),
            twitch_username: creds.twitch_username.is_some(),
            twitch_oauth: creds.twitch_oauth_token.is_some(),
            nostr_key: creds.nostr_secret_key.is_some(),
            nostr_relays: creds.nostr_relays.is_some(),
            gchat_sa_json: creds.gchat_service_account_json.is_some(),
            gchat_subscription: creds.gchat_subscription.is_some(),
        }
    }
}

/// Every channel the probe reports on, in display order.
pub const ALL_CHANNELS: [ChannelKind; 15] = [
    ChannelKind::Telegram,
    ChannelKind::Slack,
    ChannelKind::WhatsAppBusiness,
    ChannelKind::WhatsAppBaileys,
    ChannelKind::Keet,
    ChannelKind::Discord,
    ChannelKind::Signal,
    ChannelKind::IMessageBlueBubbles,
    ChannelKind::Matrix,
    ChannelKind::Line,
    ChannelKind::Irc,
    ChannelKind::Mattermost,
    ChannelKind::Twitch,
    ChannelKind::Nostr,
    ChannelKind::GoogleChat,
];

/// Classify one channel's health from the credential view. Pure.
pub fn probe_channel(kind: ChannelKind, v: &ChannelCredsView) -> ChannelHealth {
    let (status, message) = match kind {
        ChannelKind::Telegram => {
            if !v.telegram_token {
                (ProbeStatus::NotConfigured, "no telegram_token")
            } else if !v.telegram_user_id {
                (
                    // GR-126 — an OPEN inbound allowlist on an autonomous agent is a
                    // security exposure (anyone who finds the bot can drive it), not a
                    // mere caveat. Rate it Error (must-fix before exposing), at least
                    // as severe as a functional misconfig like the missing Slack pair.
                    ProbeStatus::Error,
                    "token set but telegram_user_id missing — the inbound sender allowlist is OPEN; anyone who finds the bot can drive the agent. Set telegram_user_id before exposing it",
                )
            } else {
                (ProbeStatus::Ok, "token + user_id configured (polling loop)")
            }
        }
        ChannelKind::Slack => match (v.slack_bot, v.slack_app) {
            (true, true) => (ProbeStatus::Ok, "bot + app tokens configured (socket mode)"),
            (false, false) => (ProbeStatus::NotConfigured, "no slack tokens"),
            _ => (
                ProbeStatus::Error,
                "socket mode needs BOTH slack_bot_token (xoxb-) AND slack_app_token (xapp-)",
            ),
        },
        ChannelKind::WhatsAppBusiness => {
            if !v.whatsapp_token && !v.whatsapp_phone_id {
                (ProbeStatus::NotConfigured, "no whatsapp credentials")
            } else if !v.whatsapp_token || !v.whatsapp_phone_id {
                (
                    ProbeStatus::Error,
                    "needs BOTH whatsapp_token AND whatsapp_phone_id to send",
                )
            } else if !v.whatsapp_verify_token {
                (
                    ProbeStatus::Warn,
                    "send works; inbound webhook needs whatsapp_verify_token",
                )
            } else {
                (
                    ProbeStatus::Ok,
                    "token + phone_id + verify_token configured",
                )
            }
        }
        ChannelKind::WhatsAppBaileys => {
            if !v.whatsapp_baileys_url
                && !v.whatsapp_baileys_token
                && !v.whatsapp_baileys_allowed_senders
                && !v.whatsapp_baileys_allowed_groups
            {
                (
                    ProbeStatus::NotConfigured,
                    "no dedicated Baileys bridge credentials",
                )
            } else if !v.whatsapp_baileys_url || !v.whatsapp_baileys_token {
                (
                    ProbeStatus::Error,
                    "Baileys needs BOTH whatsapp_baileys_url and whatsapp_baileys_token",
                )
            } else if !v.whatsapp_baileys_allowed_senders {
                (
                    ProbeStatus::Error,
                    "Baileys sender allowlist is mandatory; set whatsapp_baileys_allowed_senders",
                )
            } else if v.whatsapp_baileys_allowed_groups {
                (
                    ProbeStatus::Ok,
                    "authenticated Baileys bridge + sender/group policy configured",
                )
            } else {
                (
                    ProbeStatus::Ok,
                    "authenticated Baileys bridge + sender policy configured; groups denied",
                )
            }
        }
        ChannelKind::Keet => (
            ProbeStatus::Unavailable,
            if v.keet_seed {
                "unsupported: Keet exposes no public chat API; legacy keet_seed_phrase is ignored (run `neoth channel remove keet` to erase it)"
            } else {
                "unsupported: Keet exposes no public chat API; no network adapter is compiled"
            },
        ),
        ChannelKind::Discord => {
            if v.discord_bot {
                (
                    ProbeStatus::Ok,
                    "bot token configured (gateway receive loop)",
                )
            } else {
                (ProbeStatus::NotConfigured, "no discord_bot_token")
            }
        }
        ChannelKind::Signal => match (v.signal_cli_url, v.signal_phone_number) {
            (true, true) => (
                ProbeStatus::Ok,
                "signal_cli_url + phone_number configured (poll loop) — requires a running signal-cli daemon at that URL",
            ),
            (false, false) => (ProbeStatus::NotConfigured, "no signal config"),
            _ => (
                ProbeStatus::Error,
                "Signal needs BOTH signal_cli_url AND signal_phone_number",
            ),
        },
        ChannelKind::IMessageBlueBubbles => match (v.bluebubbles_url, v.bluebubbles_password) {
            (true, true) => (
                ProbeStatus::Ok,
                "bluebubbles_url + password configured (poll loop) — requires a reachable BlueBubbles server on the operator's Mac",
            ),
            (false, false) => (ProbeStatus::NotConfigured, "no bluebubbles config"),
            _ => (
                ProbeStatus::Error,
                "BlueBubbles needs BOTH bluebubbles_url AND bluebubbles_password",
            ),
        },
        ChannelKind::Matrix => probe_matrix(v, cfg!(feature = "matrix-channel")),
        ChannelKind::Line => match (v.line_access_token, v.line_channel_secret) {
            (true, true) => (
                ProbeStatus::Ok,
                "line_channel_access_token + line_channel_secret configured — inbound via the /line/webhook listener (front it with a public HTTPS reverse proxy), outbound via push",
            ),
            (false, false) => (ProbeStatus::NotConfigured, "no line config"),
            (true, false) => (
                ProbeStatus::Warn,
                "send works; inbound webhook needs line_channel_secret to verify the X-Line-Signature",
            ),
            (false, true) => (
                ProbeStatus::Error,
                "LINE needs line_channel_access_token to send (the channel secret alone cannot push)",
            ),
        },
        ChannelKind::Irc => probe_irc(v, cfg!(feature = "irc-channel")),
        ChannelKind::Mattermost => match (v.mattermost_url, v.mattermost_token) {
            (true, true) => (
                ProbeStatus::Ok,
                "mattermost_url + mattermost_token configured — NEOTH dials out to the WebSocket API (no public URL)",
            ),
            (false, false) => (ProbeStatus::NotConfigured, "no mattermost config"),
            _ => (
                ProbeStatus::Error,
                "Mattermost needs BOTH mattermost_url AND mattermost_token",
            ),
        },
        ChannelKind::Twitch => probe_twitch(v, cfg!(feature = "irc-channel")),
        ChannelKind::Nostr => probe_nostr(v, cfg!(feature = "nostr-channel")),
        ChannelKind::GoogleChat => probe_gchat(v, cfg!(feature = "gchat-channel")),
    };
    ChannelHealth {
        channel: kind.as_str(),
        status,
        message: message.to_string(),
    }
}

fn probe_irc(v: &ChannelCredsView, runtime_compiled: bool) -> (ProbeStatus, &'static str) {
    match (v.irc_server, v.irc_nick) {
        (false, false) => (ProbeStatus::NotConfigured, "no irc config"),
        (true, true) if !runtime_compiled => (
            ProbeStatus::Error,
            "IRC credentials are complete, but this binary lacks the `irc-channel` feature and cannot start the adapter",
        ),
        (true, true) => (
            ProbeStatus::Ok,
            "irc_server + irc_nick configured; `irc-channel` runtime is compiled",
        ),
        _ => (ProbeStatus::Error, "IRC needs BOTH irc_server AND irc_nick"),
    }
}

fn probe_twitch(v: &ChannelCredsView, runtime_compiled: bool) -> (ProbeStatus, &'static str) {
    match (v.twitch_username, v.twitch_oauth) {
        (false, false) => (ProbeStatus::NotConfigured, "no twitch config"),
        (true, true) if !runtime_compiled => (
            ProbeStatus::Error,
            "Twitch credentials are complete, but this binary lacks the `irc-channel` feature and cannot start the adapter",
        ),
        (true, true) => (
            ProbeStatus::Ok,
            "twitch_username + twitch_oauth_token configured; `irc-channel` runtime is compiled",
        ),
        _ => (
            ProbeStatus::Error,
            "Twitch needs BOTH twitch_username AND twitch_oauth_token",
        ),
    }
}

fn probe_nostr(v: &ChannelCredsView, runtime_compiled: bool) -> (ProbeStatus, &'static str) {
    match (v.nostr_key, v.nostr_relays) {
        (false, false) => (ProbeStatus::NotConfigured, "no nostr config"),
        (true, true) if !runtime_compiled => (
            ProbeStatus::Error,
            "Nostr credentials are complete, but this binary lacks the `nostr-channel` feature and cannot start the adapter",
        ),
        (true, true) => (
            ProbeStatus::Ok,
            "nostr_secret_key + nostr_relays configured; `nostr-channel` NIP-17 runtime is compiled",
        ),
        _ => (
            ProbeStatus::Error,
            "Nostr needs BOTH nostr_secret_key AND nostr_relays",
        ),
    }
}

fn probe_gchat(v: &ChannelCredsView, runtime_compiled: bool) -> (ProbeStatus, &'static str) {
    match (v.gchat_sa_json, v.gchat_subscription) {
        (false, false) => (ProbeStatus::NotConfigured, "no gchat config"),
        (true, true) if !runtime_compiled => (
            ProbeStatus::Error,
            "Google Chat credentials are complete, but this binary lacks the `gchat-channel` feature and cannot start the adapter",
        ),
        (true, true) => (
            ProbeStatus::Ok,
            "Google Chat service account + subscription configured; `gchat-channel` Pub/Sub runtime is compiled",
        ),
        _ => (
            ProbeStatus::Error,
            "Google Chat needs BOTH gchat_service_account_json AND gchat_subscription",
        ),
    }
}

/// Matrix needs more than credential presence: user id is a runtime input,
/// the feature must actually be compiled, and invite/encryption posture must
/// be visible rather than reported as a generic `Ok`.
fn probe_matrix(v: &ChannelCredsView, runtime_compiled: bool) -> (ProbeStatus, &'static str) {
    let any = v.matrix_config_present
        || v.matrix_homeserver
        || v.matrix_user_id
        || v.matrix_login
        || v.matrix_invite_policy;
    if !any {
        return (ProbeStatus::NotConfigured, "no matrix config");
    }
    if !(v.matrix_homeserver && v.matrix_user_id && v.matrix_login) {
        return (
            ProbeStatus::Error,
            "Matrix needs matrix_homeserver, matrix_user_id, and either matrix_password or matrix_access_token",
        );
    }
    if !runtime_compiled {
        return (
            ProbeStatus::Error,
            "Matrix credentials are complete, but this binary lacks the `matrix-channel` feature and cannot start the adapter",
        );
    }
    if !v.matrix_invite_policy && v.matrix_encryption_required {
        return (
            ProbeStatus::Warn,
            "Matrix runtime is compiled and encrypted rooms are required; existing joined rooms can run, but all invitations are denied until matrix_allowed_user_id or matrix_allowed_room_ids is set",
        );
    }
    if !v.matrix_invite_policy {
        return (
            ProbeStatus::Warn,
            "Matrix runtime is compiled; plaintext rooms are explicitly allowed and all invitations are denied until matrix_allowed_user_id or matrix_allowed_room_ids is set",
        );
    }
    if !v.matrix_encryption_required {
        return (
            ProbeStatus::Warn,
            "Matrix runtime and invite policy are configured; matrix_require_encryption=false explicitly permits plaintext rooms",
        );
    }
    (
        ProbeStatus::Ok,
        "Matrix `matrix-channel` runtime compiled; access/password auth, explicit invite policy, and encrypted-room enforcement configured",
    )
}

/// Probe every channel. Display/registry order is [`ALL_CHANNELS`].
pub fn probe_all(v: &ChannelCredsView) -> Vec<ChannelHealth> {
    ALL_CHANNELS.iter().map(|k| probe_channel(*k, v)).collect()
}

/// The channels in an `Error` (actively misconfigured) state — what the MONITOR
/// cron warns about and `neoth status` highlights.
pub fn misconfigured(v: &ChannelCredsView) -> Vec<ChannelHealth> {
    probe_all(v)
        .into_iter()
        .filter(|h| h.status == ProbeStatus::Error)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_states() {
        let none = ChannelCredsView::default();
        assert_eq!(
            probe_channel(ChannelKind::Telegram, &none).status,
            ProbeStatus::NotConfigured
        );
        let token_only = ChannelCredsView {
            telegram_token: true,
            ..Default::default()
        };
        // GR-126 — open inbound allowlist (no user_id) is a security exposure → Error.
        assert_eq!(
            probe_channel(ChannelKind::Telegram, &token_only).status,
            ProbeStatus::Error
        );
        let full = ChannelCredsView {
            telegram_token: true,
            telegram_user_id: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::Telegram, &full).status,
            ProbeStatus::Ok
        );
    }

    #[test]
    fn slack_needs_both_tokens_else_error() {
        let bot_only = ChannelCredsView {
            slack_bot: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::Slack, &bot_only).status,
            ProbeStatus::Error
        );
        let both = ChannelCredsView {
            slack_bot: true,
            slack_app: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::Slack, &both).status,
            ProbeStatus::Ok
        );
        assert_eq!(
            probe_channel(ChannelKind::Slack, &ChannelCredsView::default()).status,
            ProbeStatus::NotConfigured
        );
    }

    #[test]
    fn whatsapp_partial_is_error_missing_verify_is_warn() {
        let token_only = ChannelCredsView {
            whatsapp_token: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::WhatsAppBusiness, &token_only).status,
            ProbeStatus::Error
        );
        let send_ready = ChannelCredsView {
            whatsapp_token: true,
            whatsapp_phone_id: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::WhatsAppBusiness, &send_ready).status,
            ProbeStatus::Warn
        );
        let full = ChannelCredsView {
            whatsapp_token: true,
            whatsapp_phone_id: true,
            whatsapp_verify_token: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::WhatsAppBusiness, &full).status,
            ProbeStatus::Ok
        );
    }

    #[test]
    fn baileys_probe_requires_dedicated_transport_and_sender_policy() {
        let meta_only = ChannelCredsView {
            whatsapp_token: true,
            whatsapp_phone_id: true,
            whatsapp_verify_token: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::WhatsAppBaileys, &meta_only).status,
            ProbeStatus::NotConfigured,
            "Meta credentials must not activate Baileys"
        );
        let transport_only = ChannelCredsView {
            whatsapp_baileys_url: true,
            whatsapp_baileys_token: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::WhatsAppBaileys, &transport_only).status,
            ProbeStatus::Error
        );
        let complete = ChannelCredsView {
            whatsapp_baileys_allowed_senders: true,
            ..transport_only
        };
        assert_eq!(
            probe_channel(ChannelKind::WhatsAppBaileys, &complete).status,
            ProbeStatus::Ok
        );
    }

    #[test]
    fn keet_is_unavailable_even_when_legacy_seed_is_present() {
        let v = ChannelCredsView {
            keet_seed: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::Keet, &v).status,
            ProbeStatus::Unavailable
        );
        assert!(
            probe_channel(ChannelKind::Keet, &v)
                .message
                .contains("ignored")
        );

        let empty = ChannelCredsView::default();
        assert_eq!(
            probe_channel(ChannelKind::Keet, &empty).status,
            ProbeStatus::Unavailable
        );
    }

    #[test]
    fn discord_ok_when_bot_token_set_else_not_configured() {
        // GOLD-PROG-16 wired discord_bot_token + the gateway receive loop, so a
        // present token reports Ok (was wrongly pinned NotConfigured before).
        let none = ChannelCredsView::default();
        assert_eq!(
            probe_channel(ChannelKind::Discord, &none).status,
            ProbeStatus::NotConfigured
        );
        let configured = ChannelCredsView {
            discord_bot: true,
            ..Default::default()
        };
        assert_eq!(
            probe_channel(ChannelKind::Discord, &configured).status,
            ProbeStatus::Ok
        );
    }

    #[test]
    fn matrix_probe_requires_complete_config_and_compiled_runtime() {
        let partial = ChannelCredsView {
            matrix_homeserver: true,
            matrix_login: true,
            ..Default::default()
        };
        assert_eq!(probe_matrix(&partial, true).0, ProbeStatus::Error);
        assert!(probe_matrix(&partial, true).1.contains("matrix_user_id"));

        let complete = ChannelCredsView {
            matrix_homeserver: true,
            matrix_user_id: true,
            matrix_login: true,
            matrix_invite_policy: true,
            matrix_encryption_required: true,
            ..Default::default()
        };
        assert_eq!(probe_matrix(&complete, false).0, ProbeStatus::Error);
        assert!(
            probe_matrix(&complete, false)
                .1
                .contains("lacks the `matrix-channel` feature")
        );
        assert_eq!(probe_matrix(&complete, true).0, ProbeStatus::Ok);
    }

    #[test]
    fn matrix_probe_surfaces_invite_and_plaintext_posture() {
        let no_invite_rule = ChannelCredsView {
            matrix_homeserver: true,
            matrix_user_id: true,
            matrix_login: true,
            matrix_encryption_required: true,
            ..Default::default()
        };
        assert_eq!(probe_matrix(&no_invite_rule, true).0, ProbeStatus::Warn);
        assert!(
            probe_matrix(&no_invite_rule, true)
                .1
                .contains("all invitations are denied")
        );

        let plaintext = ChannelCredsView {
            matrix_invite_policy: true,
            matrix_encryption_required: false,
            ..no_invite_rule
        };
        assert_eq!(probe_matrix(&plaintext, true).0, ProbeStatus::Warn);
        assert!(
            probe_matrix(&plaintext, true)
                .1
                .contains("permits plaintext")
        );
    }

    #[test]
    fn matrix_probe_surfaces_auxiliary_only_and_blank_partial_config() {
        let aux_only = crate::config::credentials::Credentials {
            matrix_store_path: Some("/srv/neoth/matrix".into()),
            matrix_require_encryption: Some(false),
            ..Default::default()
        };
        let view = ChannelCredsView::from_config(None, &aux_only);
        assert!(view.matrix_config_present);
        assert_eq!(probe_matrix(&view, true).0, ProbeStatus::Error);

        let blank = crate::config::credentials::Credentials {
            matrix_homeserver: Some("   ".into()),
            matrix_user_id: Some("".into()),
            matrix_access_token: Some(crate::secret::SecretString::from("  ")),
            matrix_allowed_room_ids: Some("   ".into()),
            ..Default::default()
        };
        let blank_view = ChannelCredsView::from_config(None, &blank);
        assert!(blank_view.matrix_config_present);
        assert!(!blank_view.matrix_homeserver);
        assert!(!blank_view.matrix_user_id);
        assert!(!blank_view.matrix_login);
        assert!(!blank_view.matrix_invite_policy);
        assert_eq!(probe_matrix(&blank_view, true).0, ProbeStatus::Error);
    }

    #[test]
    fn optional_channel_probes_never_claim_ok_when_runtime_feature_is_absent() {
        let view = ChannelCredsView {
            irc_server: true,
            irc_nick: true,
            twitch_username: true,
            twitch_oauth: true,
            nostr_key: true,
            nostr_relays: true,
            gchat_sa_json: true,
            gchat_subscription: true,
            ..Default::default()
        };

        for (status, message) in [
            probe_irc(&view, false),
            probe_twitch(&view, false),
            probe_nostr(&view, false),
            probe_gchat(&view, false),
        ] {
            assert_eq!(status, ProbeStatus::Error);
            assert!(message.contains("lacks the"));
        }
        assert_eq!(probe_irc(&view, true).0, ProbeStatus::Ok);
        assert_eq!(probe_twitch(&view, true).0, ProbeStatus::Ok);
        assert_eq!(probe_nostr(&view, true).0, ProbeStatus::Ok);
        assert_eq!(probe_gchat(&view, true).0, ProbeStatus::Ok);
    }

    #[test]
    fn probe_all_covers_every_channel_and_misconfigured_filters_errors() {
        let v = ChannelCredsView {
            slack_bot: true, // slack → Error (missing app token)
            ..Default::default()
        };
        let all = probe_all(&v);
        assert_eq!(all.len(), ALL_CHANNELS.len());
        let bad = misconfigured(&v);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].channel, "slack");
        assert_eq!(bad[0].status, ProbeStatus::Error);
    }

    #[test]
    fn status_glyphs_are_distinct() {
        let s = [
            ProbeStatus::Ok,
            ProbeStatus::Warn,
            ProbeStatus::Error,
            ProbeStatus::Unavailable,
            ProbeStatus::NotConfigured,
        ];
        let glyphs: std::collections::HashSet<_> = s.iter().map(|x| x.glyph()).collect();
        assert_eq!(glyphs.len(), 5, "each status needs a distinct glyph");
    }
}
