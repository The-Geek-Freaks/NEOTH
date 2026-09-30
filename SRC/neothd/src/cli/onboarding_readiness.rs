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

use crate::channels::probe::ProbeStatus;
use crate::channels::registry::channel_descriptors;
use crate::cli::channel::channel_statuses;
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
        channel_names: configured_channels(cfg, credentials),
    }
}

pub(crate) fn has_ready_channel(cfg: &FreedomConfig, credentials: &Credentials) -> bool {
    !configured_channels(cfg, credentials).is_empty()
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

fn configured_channels(cfg: &FreedomConfig, credentials: &Credentials) -> Vec<&'static str> {
    // Account-map readiness and legacy-shadow rules belong to the canonical
    // channel status projection; retain this registry's display-name order.
    let statuses = channel_statuses(cfg, credentials);
    channel_descriptors()
        .iter()
        .filter_map(|descriptor| {
            statuses
                .iter()
                .find(|status| status.name == descriptor.id.as_str())
                .and_then(|status| {
                    matches!(status.status, ProbeStatus::Ok | ProbeStatus::Warn)
                        .then_some(descriptor.display_name)
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::registry::ChannelAccountId;
    use crate::config::credentials::{SlackAccountCredentials, TelegramAccountCredentials};
    use crate::config::{SlackAccountConfig, TelegramAccountConfig};
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
        let mut cfg = cfg(ProviderKind::OpenaiApi);
        cfg.telegram_user_id = Some(42);
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
    fn token_only_telegram_is_not_ready() {
        let credentials = Credentials {
            telegram_token: Some(SecretString::from("123:abc")),
            ..Credentials::default()
        };
        assert!(
            !configured_channels(&FreedomConfig::default(), &credentials).contains(&"Telegram")
        );

        let mut cfg = FreedomConfig::default();
        cfg.telegram_user_id = Some(42);
        assert!(configured_channels(&cfg, &credentials).contains(&"Telegram"));
    }

    #[test]
    fn named_telegram_and_slack_maps_are_ready_without_legacy_fields() {
        let telegram = ChannelAccountId::new("family".to_string()).unwrap();
        let slack = ChannelAccountId::new("ops".to_string()).unwrap();
        let mut cfg = FreedomConfig::default();
        cfg.channel_accounts.telegram.insert(
            telegram.clone(),
            TelegramAccountConfig {
                allowed_user_id: 42,
                ..TelegramAccountConfig::default()
            },
        );
        cfg.channel_accounts.slack.insert(
            slack.clone(),
            SlackAccountConfig {
                allowed_user_id: "U0123456789".to_string(),
                ..SlackAccountConfig::default()
            },
        );
        let mut credentials = Credentials::default();
        credentials.channel_accounts.telegram.insert(
            telegram,
            TelegramAccountCredentials {
                token: Some(SecretString::from("123:telegram-token")),
            },
        );
        credentials.channel_accounts.slack.insert(
            slack,
            SlackAccountCredentials {
                bot_token: Some(SecretString::from("xoxb-slack-token")),
                app_token: Some(SecretString::from("xapp-slack-token")),
            },
        );

        assert_eq!(cfg.telegram_user_id, None);
        assert!(credentials.telegram_token.is_none());
        assert!(credentials.slack_bot_token.is_none());
        assert!(credentials.slack_app_token.is_none());
        assert_eq!(
            configured_channels(&cfg, &credentials),
            vec!["Telegram", "Slack"]
        );
    }

    #[test]
    fn configured_channel_names_follow_descriptor_order_without_duplicates() {
        let telegram = ChannelAccountId::new("family".to_string()).unwrap();
        let telegram_secondary = ChannelAccountId::new("work".to_string()).unwrap();
        let slack = ChannelAccountId::new("ops".to_string()).unwrap();
        let mut cfg = FreedomConfig::default();
        cfg.channel_accounts.telegram.insert(
            telegram.clone(),
            TelegramAccountConfig {
                allowed_user_id: 42,
                ..TelegramAccountConfig::default()
            },
        );
        cfg.channel_accounts.telegram.insert(
            telegram_secondary.clone(),
            TelegramAccountConfig {
                allowed_user_id: 7,
                ..TelegramAccountConfig::default()
            },
        );
        cfg.channel_accounts.slack.insert(
            slack.clone(),
            SlackAccountConfig {
                allowed_user_id: "U0123456789".to_string(),
                ..SlackAccountConfig::default()
            },
        );
        let mut credentials = Credentials {
            discord_bot_token: Some(SecretString::from("discord-token")),
            discord_allowed_user_id: Some("123456789012345678".to_string()),
            ..Credentials::default()
        };
        credentials.channel_accounts.telegram.insert(
            telegram,
            TelegramAccountCredentials {
                token: Some(SecretString::from("123:telegram-token")),
            },
        );
        credentials.channel_accounts.telegram.insert(
            telegram_secondary,
            TelegramAccountCredentials {
                token: Some(SecretString::from("456:secondary-telegram-token")),
            },
        );
        credentials.channel_accounts.slack.insert(
            slack,
            SlackAccountCredentials {
                bot_token: Some(SecretString::from("xoxb-slack-token")),
                app_token: Some(SecretString::from("xapp-slack-token")),
            },
        );

        let names = configured_channels(&cfg, &credentials);
        assert_eq!(names, vec!["Telegram", "Slack", "Discord"]);
        let unique = names.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), names.len());
    }

    #[test]
    fn invalid_named_maps_are_excluded_and_do_not_fall_back_to_legacy_credentials() {
        let telegram = ChannelAccountId::new("family".to_string()).unwrap();
        let slack = ChannelAccountId::new("ops".to_string()).unwrap();
        let mut cfg = FreedomConfig::default();
        cfg.channel_accounts.telegram.insert(
            telegram.clone(),
            TelegramAccountConfig {
                allowed_user_id: 42,
                ..TelegramAccountConfig::default()
            },
        );
        cfg.channel_accounts.slack.insert(
            slack.clone(),
            SlackAccountConfig {
                allowed_user_id: "U0123456789".to_string(),
                ..SlackAccountConfig::default()
            },
        );
        let mut credentials = Credentials::default();
        credentials
            .channel_accounts
            .telegram
            .insert(telegram, TelegramAccountCredentials { token: None });
        credentials.channel_accounts.slack.insert(
            slack,
            SlackAccountCredentials {
                bot_token: Some(SecretString::from("xoxb-named-slack-token")),
                app_token: None,
            },
        );

        assert!(configured_channels(&cfg, &credentials).is_empty());

        cfg.telegram_user_id = Some(42);
        credentials.telegram_token = Some(SecretString::from("123:legacy-telegram-token"));
        credentials.slack_bot_token = Some(SecretString::from("xoxb-legacy-slack-token"));
        credentials.slack_app_token = Some(SecretString::from("xapp-legacy-slack-token"));
        assert!(configured_channels(&cfg, &credentials).is_empty());
    }

    #[test]
    fn descriptor_projection_returns_ordered_usable_channels_and_excludes_incomplete_ones() {
        assert!(configured_channels(&FreedomConfig::default(), &Credentials::default()).is_empty());

        let mut cfg = FreedomConfig::default();
        cfg.telegram_user_id = Some(42);
        let credentials = Credentials {
            telegram_token: Some(SecretString::from("123:abc")),
            slack_bot_token: Some(SecretString::from("slack-token")),
            keet_bridge_url: Some("http://127.0.0.1:8123".to_string()),
            keet_topic: Some(SecretString::from("topic")),
            keet_allowed_senders: Some("peer-1".to_string()),
            keet_bridge_bearer_token: Some(SecretString::from("bearer")),
            discord_bot_token: Some(SecretString::from("discord-token")),
            discord_allowed_user_id: Some("123456789012345678".to_string()),
            ..Credentials::default()
        };
        assert_eq!(
            configured_channels(&cfg, &credentials),
            vec!["Telegram", "Keet", "Discord"]
        );
    }

    #[test]
    fn feature_gated_irc_readiness_matches_the_compiled_runtime() {
        let credentials = Credentials {
            irc_server: Some("irc.example".to_string()),
            irc_nick: Some("neoth".to_string()),
            irc_allowed_account: Some("operator".to_string()),
            ..Credentials::default()
        };
        assert_eq!(
            configured_channels(&FreedomConfig::default(), &credentials).contains(&"IRC"),
            cfg!(feature = "irc-channel")
        );
    }

    #[test]
    fn discord_is_visible_only_with_exact_sender_policy() {
        let token_only = Credentials {
            discord_bot_token: Some(SecretString::from("discord-token")),
            ..Credentials::default()
        };
        assert!(!configured_channels(&FreedomConfig::default(), &token_only).contains(&"Discord"));

        let complete = Credentials {
            discord_allowed_user_id: Some("123456789012345678".into()),
            ..token_only
        };
        assert!(configured_channels(&FreedomConfig::default(), &complete).contains(&"Discord"));
    }
}
