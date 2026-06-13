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
    /// No credentials present — the channel is simply off (not an error).
    NotConfigured,
}

impl ProbeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeStatus::Ok => "ok",
            ProbeStatus::Warn => "warn",
            ProbeStatus::Error => "error",
            ProbeStatus::NotConfigured => "not_configured",
        }
    }
    /// A glyph for the `neoth status` table.
    pub fn glyph(self) -> &'static str {
        match self {
            ProbeStatus::Ok => "✓",
            ProbeStatus::Warn => "⚠",
            ProbeStatus::Error => "✗",
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
    pub keet_seed: bool,
    pub discord_bot: bool,
    pub signal_cli_url: bool,
    pub signal_phone_number: bool,
}

impl ChannelCredsView {
    /// Assemble from the loaded `freedom.yaml` (telegram lives there) +
    /// `credentials.yaml` (everything else). Reads only `.is_some()` — no
    /// secret value is copied.
    pub fn from_config(
        cfg: Option<&crate::config::FreedomConfig>,
        creds: &crate::config::credentials::Credentials,
    ) -> Self {
        Self {
            telegram_token: cfg.is_some_and(|c| c.telegram_token.is_some())
                || creds.telegram_token.is_some(),
            telegram_user_id: cfg.is_some_and(|c| c.telegram_user_id.is_some()),
            slack_bot: creds.slack_bot_token.is_some(),
            slack_app: creds.slack_app_token.is_some(),
            whatsapp_token: creds.whatsapp_token.is_some(),
            whatsapp_phone_id: creds.whatsapp_phone_id.is_some(),
            whatsapp_verify_token: creds.whatsapp_verify_token.is_some(),
            keet_seed: creds.keet_seed_phrase.is_some(),
            // Discord has no credential field wired from config yet (the adapter
            // takes a bot token but the daemon never constructs it from config).
            discord_bot: false,
            signal_cli_url: creds.signal_cli_url.is_some(),
            signal_phone_number: creds.signal_phone_number.is_some(),
        }
    }
}

/// Every channel the probe reports on, in display order.
pub const ALL_CHANNELS: [ChannelKind; 7] = [
    ChannelKind::Telegram,
    ChannelKind::Slack,
    ChannelKind::WhatsAppBusiness,
    ChannelKind::WhatsAppBaileys,
    ChannelKind::Keet,
    ChannelKind::Discord,
    ChannelKind::Signal,
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
        ChannelKind::WhatsAppBaileys => (
            ProbeStatus::NotConfigured,
            "Baileys bridge not configured (alternative WhatsApp transport)",
        ),
        ChannelKind::Keet => {
            if v.keet_seed {
                (
                    // GR-014 — NOT Ok: KeetChannel::run() always bails (the inbound
                    // receive loop is deferred to K-3), so Keet cannot serve as a
                    // running channel. Outbound send_text via the Pears bridge does
                    // work, hence Warn (partial), not Ok (claims 'adapter can run').
                    ProbeStatus::Warn,
                    "keet_seed configured: outbound send_text works via the Pears bridge, but the inbound receive loop is DEFERRED (K-3) — KeetChannel::run() bails, so Keet can't serve inbound yet. Use Telegram for inbound",
                )
            } else {
                (ProbeStatus::NotConfigured, "no keet_seed_phrase")
            }
        }
        ChannelKind::Discord => (
            ProbeStatus::NotConfigured,
            "adapter present but no Discord bot token is wired from config yet",
        ),
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
    };
    ChannelHealth {
        channel: kind.as_str(),
        status,
        message: message.to_string(),
    }
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
    fn keet_warn_when_seed_present_because_run_is_deferred() {
        // GR-014 — keet_seed set → Warn, NOT Ok: outbound send works but
        // KeetChannel::run() always bails (inbound deferred to K-3).
        let v = ChannelCredsView {
            keet_seed: true,
            ..Default::default()
        };
        assert_eq!(probe_channel(ChannelKind::Keet, &v).status, ProbeStatus::Warn);
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
            ProbeStatus::NotConfigured,
        ];
        let glyphs: std::collections::HashSet<_> = s.iter().map(|x| x.glyph()).collect();
        assert_eq!(glyphs.len(), 4, "each status needs a distinct glyph");
    }
}
