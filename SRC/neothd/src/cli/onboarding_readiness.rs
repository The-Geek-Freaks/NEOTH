//! Shared post-init readiness evaluation.
//!
//! Doctor, the proactive post-init nudge, and `onboarding-status` must agree
//! about whether the configured provider and at least one channel are usable.
//! Keep the checks here aligned with the construction requirements in
//! `providers::from_config`; in particular, a credentials file by itself is
//! not proof that a metered provider has a key, while local/CLI providers do
//! not require that file at all.

use std::path::Path;

use anyhow::{Context, Result};

use crate::cli::init::ProviderKind;
use crate::config::FreedomConfig;
use crate::config::credentials::Credentials;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OnboardingReadiness {
    pub(crate) provider_gap: Option<String>,
    pub(crate) channel_names: Vec<&'static str>,
}

impl OnboardingReadiness {
    pub(crate) fn provider_ready(&self) -> bool {
        self.provider_gap.is_none()
    }

    pub(crate) fn channel_ready(&self) -> bool {
        !self.channel_names.is_empty()
    }

    pub(crate) fn gaps(&self) -> Vec<String> {
        let mut gaps = Vec::new();
        if let Some(gap) = &self.provider_gap {
            gaps.push(gap.clone());
        }
        if !self.channel_ready() {
            gaps.push(
                "no configured messaging channel can start - run `neoth init` or `neoth credential set`"
                    .to_string(),
            );
        }
        gaps
    }
}

pub(crate) fn load(home: &Path) -> Result<(FreedomConfig, OnboardingReadiness)> {
    let freedom_path = home.join("freedom.yaml");
    let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path)
        .with_context(|| format!("load coherent runtime config at {}", freedom_path.display()))?;
    let readiness = evaluate(&pair.config, &pair.credentials);
    Ok((pair.config, readiness))
}

pub(crate) fn evaluate(cfg: &FreedomConfig, credentials: &Credentials) -> OnboardingReadiness {
    OnboardingReadiness {
        provider_gap: provider_gap(cfg),
        channel_names: configured_channels(credentials),
    }
}

fn provider_gap(cfg: &FreedomConfig) -> Option<String> {
    let kind = match cfg.provider_kind {
        Some(ProviderKind::Skip) | None => {
            return Some(
                "provider not configured - run `neoth init` or `neoth hemispheres set`".to_string(),
            );
        }
        Some(kind) => kind,
    };

    let missing_key = || {
        Some(format!(
            "{} requires provider_key in credentials.yaml",
            kind.as_provider_id()
        ))
    };
    let require_text = |value: &Option<String>, field: &str| {
        value
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .map(|_| ())
            .ok_or_else(|| format!("{} requires {field} in freedom.yaml", kind.as_provider_id()))
    };

    match kind {
        // OAuth/local execution paths intentionally have no credentials.yaml
        // requirement. Dedicated provider/tooling doctor checks cover missing
        // binaries, model weights, local services and sidecars.
        ProviderKind::ClaudeCli
        | ProviderKind::LocalQwen
        | ProviderKind::LocalOuro
        | ProviderKind::LocalOllama => None,
        ProviderKind::RecursiveMas => {
            if !cfg!(feature = "recursive-mas") {
                Some("recursive_mas requires a build with the `recursive-mas` feature".to_string())
            } else if !cfg.recursive_mas.enabled {
                Some("recursive_mas is selected but recursive_mas.enabled is false".to_string())
            } else {
                None
            }
        }
        // Local OpenAI-compatible servers commonly use no key. Runtime needs
        // only an explicit endpoint and model.
        ProviderKind::OpenaiCompat => require_text(&cfg.provider_endpoint, "provider_endpoint")
            .and_then(|_| require_text(&cfg.provider_model, "provider_model"))
            .err(),
        ProviderKind::AwsBedrock => {
            if let Err(gap) = require_text(&cfg.provider_model, "provider_model") {
                return Some(gap);
            }
            crate::providers::aws_credentials::resolve_chain(
                None,
                &crate::providers::aws_credentials::env_var_getter,
                None,
            )
            .err()
            .map(|e| format!("aws_bedrock credentials unavailable: {e}"))
        }
        ProviderKind::AzureOpenAi => {
            if cfg.provider_key.is_none() {
                return missing_key();
            }
            require_text(&cfg.provider_endpoint, "provider_endpoint")
                .and_then(|_| require_text(&cfg.provider_model, "provider_model"))
                .err()
        }
        ProviderKind::OpenaiApi
        | ProviderKind::AnthropicApi
        | ProviderKind::GeminiApi
        | ProviderKind::Cohere
        | ProviderKind::GitHubCopilot => {
            if cfg.provider_key.is_some() {
                None
            } else {
                missing_key()
            }
        }
        ProviderKind::Skip => unreachable!("handled above"),
    }
}

fn configured_channels(credentials: &Credentials) -> Vec<&'static str> {
    let mut channels = Vec::new();
    if credentials.telegram_token.is_some() {
        channels.push("Telegram");
    }
    if credentials.whatsapp_token.is_some()
        && credentials.whatsapp_phone_id.is_some()
        && credentials.whatsapp_verify_token.is_some()
        && credentials.whatsapp_app_secret.is_some()
        && credentials
            .whatsapp_allowed_sender
            .as_deref()
            .is_some_and(|value| {
                crate::channels::whatsapp_webhook::normalize_allowed_sender(value).is_ok()
            })
    {
        channels.push("WhatsApp Cloud");
    }
    if credentials.whatsapp_baileys_url.is_some()
        && credentials.whatsapp_baileys_token.is_some()
        && credentials.whatsapp_baileys_allowed_senders.is_some()
    {
        channels.push("WhatsApp Baileys");
    }
    if credentials.slack_bot_token.is_some()
        && credentials.slack_app_token.is_some()
        && credentials
            .slack_allowed_user_id
            .as_deref()
            .is_some_and(|value| crate::channels::slack::normalize_allowed_user_id(value).is_ok())
    {
        channels.push("Slack");
    }
    if credentials.discord_bot_token.is_some()
        && credentials
            .discord_allowed_user_id
            .as_deref()
            .is_some_and(|id| crate::channels::discord::normalize_allowed_sender_id(id).is_ok())
    {
        channels.push("Discord");
    }
    if credentials.signal_cli_url.is_some()
        && credentials.signal_phone_number.is_some()
        && credentials
            .signal_allowed_sender
            .as_deref()
            .is_some_and(|value| crate::channels::signal_api::validate_signal_number(value).is_ok())
    {
        channels.push("Signal");
    }
    if credentials.matrix_homeserver.is_some()
        && credentials.matrix_user_id.is_some()
        && (credentials.matrix_access_token.is_some() || credentials.matrix_password.is_some())
    {
        channels.push("Matrix");
    }
    if credentials.line_channel_access_token.is_some()
        && credentials.line_channel_secret.is_some()
        && credentials
            .line_allowed_sender
            .as_deref()
            .is_some_and(|value| crate::channels::line_api::normalize_allowed_sender(value).is_ok())
    {
        channels.push("LINE");
    }
    if credentials.irc_server.is_some()
        && credentials.irc_nick.is_some()
        && credentials.irc_channels.is_some()
    {
        channels.push("IRC");
    }
    if credentials.mattermost_url.is_some() && credentials.mattermost_token.is_some() {
        channels.push("Mattermost");
    }
    if credentials.twitch_username.is_some()
        && credentials.twitch_oauth_token.is_some()
        && credentials.twitch_channels.is_some()
    {
        channels.push("Twitch");
    }
    if credentials.nostr_secret_key.is_some() && credentials.nostr_relays.is_some() {
        channels.push("Nostr");
    }
    if credentials.bluebubbles_url.is_some()
        && credentials.bluebubbles_password.is_some()
        && credentials.bluebubbles_chat_guid.is_some()
    {
        channels.push("iMessage/BlueBubbles");
    }
    if credentials.gchat_service_account_json.is_some() && credentials.gchat_subscription.is_some()
    {
        channels.push("Google Chat");
    }
    channels
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    fn cfg(kind: ProviderKind) -> FreedomConfig {
        FreedomConfig {
            provider_kind: Some(kind),
            ..FreedomConfig::default()
        }
    }

    #[test]
    fn self_contained_providers_do_not_require_credentials_yaml() {
        for kind in [
            ProviderKind::ClaudeCli,
            ProviderKind::LocalQwen,
            ProviderKind::LocalOuro,
            ProviderKind::LocalOllama,
        ] {
            assert!(provider_gap(&cfg(kind)).is_none(), "{kind:?}");
        }
    }

    #[test]
    fn metered_provider_requires_an_actual_provider_key() {
        let cfg = cfg(ProviderKind::OpenaiApi);
        let credentials = Credentials {
            telegram_token: Some(SecretString::from("123:abc")),
            ..Credentials::default()
        };
        let status = evaluate(&cfg, &credentials);
        assert!(!status.provider_ready());
        assert!(status.channel_ready());
    }

    #[test]
    fn openai_compat_allows_keyless_local_endpoint_but_requires_model() {
        let mut cfg = cfg(ProviderKind::OpenaiCompat);
        cfg.provider_endpoint = Some("http://127.0.0.1:1234/v1".to_string());
        assert!(provider_gap(&cfg).unwrap().contains("provider_model"));
        cfg.provider_model = Some("local-model".to_string());
        assert!(provider_gap(&cfg).is_none());
    }

    #[test]
    fn all_shipped_channel_families_are_visible_to_readiness() {
        let credentials = Credentials {
            matrix_homeserver: Some("https://matrix.example".to_string()),
            matrix_user_id: Some("@neoth:example".to_string()),
            matrix_access_token: Some(SecretString::from("matrix-token")),
            ..Credentials::default()
        };
        assert_eq!(configured_channels(&credentials), vec!["Matrix"]);
    }

    #[test]
    fn discord_is_visible_only_with_exact_sender_policy() {
        let token_only = Credentials {
            discord_bot_token: Some(SecretString::from("discord-token")),
            ..Credentials::default()
        };
        assert!(!configured_channels(&token_only).contains(&"Discord"));

        let complete = Credentials {
            discord_allowed_user_id: Some("123456789012345678".into()),
            ..token_only
        };
        assert!(configured_channels(&complete).contains(&"Discord"));
    }
}
