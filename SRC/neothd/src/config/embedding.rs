//! Explicit local embedding-model selection.
//!
//! This configuration is intentionally separate from `inference`: selecting a
//! model never changes chat or profile-provider routing, and neither variant
//! authorizes a remote embedding provider.

use serde::{Deserialize, Serialize};

/// The closed set of locally supported embedding-model families.
///
/// `Qwen3Q8` is the compatibility default. `BgeM3` is an operator opt-in and
/// must become ready through its own verified local artifact route; consumers
/// must never substitute Qwen or a cloud provider when it is unavailable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingModel {
    #[default]
    Qwen3Q8,
    BgeM3,
}

impl EmbeddingModel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Qwen3Q8 => "qwen3_q8",
            Self::BgeM3 => "bge_m3",
        }
    }
}

/// YAML representation of `embed.model`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmbeddingConfig {
    pub model: EmbeddingModel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FreedomConfig;
    use crate::config::inference::InferenceProvider;

    #[test]
    fn absent_embed_selection_defaults_to_qwen3_q8() {
        let config: FreedomConfig = serde_yaml::from_str("operator_id: operator\n").unwrap();
        assert_eq!(config.embed.model, EmbeddingModel::Qwen3Q8);
    }

    #[test]
    fn bge_m3_round_trips_at_the_embed_namespace() {
        let config: FreedomConfig = serde_yaml::from_str(
            "operator_id: operator\nembed:\n  model: bge_m3\n",
        )
        .unwrap();
        assert_eq!(config.embed.model, EmbeddingModel::BgeM3);
        assert!(serde_yaml::to_string(&config).unwrap().contains("model: bge_m3"));
    }

    #[test]
    fn unknown_embedding_model_fails_configuration_parse() {
        assert!(serde_yaml::from_str::<FreedomConfig>(
            "operator_id: operator\nembed:\n  model: remote_mystery\n",
        )
        .is_err());
    }

    #[test]
    fn embedding_selection_does_not_change_chat_or_profile_provider_routes() {
        let config: FreedomConfig = serde_yaml::from_str(
            "operator_id: operator\nprovider_kind: claude_cli\nembed:\n  model: bge_m3\ninference:\n  profile_provider: local_ouro\n",
        )
        .unwrap();
        assert_eq!(config.embed.model, EmbeddingModel::BgeM3);
        assert_eq!(
            config.provider_kind,
            Some(crate::cli::init::ProviderKind::ClaudeCli)
        );
        assert_eq!(
            config.inference.profile_provider,
            Some(InferenceProvider::LocalOuro)
        );
    }
}
