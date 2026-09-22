//! Closed operator policy for Council hemisphere provider dispatch.
//!
//! This module only admits an already selected concrete provider/model pair.
//! It deliberately does not choose a replacement route, create an authority,
//! or carry a reload epoch. Dispatchers retain the returned decision with the
//! accepted configuration snapshot that selected their candidate.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};

use super::inference::{HemisphereRole, InferenceProvider};

/// Optional closed allow-list for Council hemisphere dispatch.
///
/// Its absence preserves legacy routing. Once present, every omitted role is
/// denied so an operator cannot accidentally broaden a partially configured
/// policy through topology fallback.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RolePolicyConfig {
    /// One exact provider binding for each admitted role.
    pub rules: Vec<RolePolicyRule>,
}

impl RolePolicyConfig {
    /// Admit an already resolved provider/model pair for `role`.
    pub fn resolve(
        &self,
        role: HemisphereRole,
        provider: InferenceProvider,
        final_model: &str,
    ) -> Result<RoleDispatchDecision, RoleDispatchViolation> {
        let candidate = RoleDispatchCandidate::new(role, provider, final_model);
        let policy = self.identity();
        if final_model.trim().is_empty() {
            return Err(candidate.violation(policy, RoleDispatchViolationReason::ModelNotAllowed));
        }
        let Some(rule) = self.rules.iter().find(|rule| rule.role == role) else {
            return Err(candidate.violation(policy, RoleDispatchViolationReason::RoleUnconfigured));
        };

        if rule.provider != provider {
            return Err(
                candidate.violation(policy, RoleDispatchViolationReason::ProviderNotAllowed)
            );
        }

        if rule
            .model
            .as_deref()
            .is_some_and(|model| model != final_model)
        {
            return Err(candidate.violation(policy, RoleDispatchViolationReason::ModelNotAllowed));
        }

        Ok(candidate.decision(policy))
    }

    /// Stable identity of the complete accepted policy. The digest includes
    /// every normalized rule so changing another role cannot be mistaken for
    /// the same policy at an attempt/audit boundary.
    pub fn identity(&self) -> RolePolicyIdentity {
        let mut rules = self.rules.clone();
        rules.sort_by_key(|rule| rule.role);
        let canonical = rules
            .iter()
            .map(|rule| {
                format!(
                    "{}\u{1f}{}\u{1f}",
                    rule.role.as_str(),
                    rule.provider.as_str(),
                ) + rule.model.as_deref().unwrap_or("")
            })
            .collect::<Vec<_>>()
            .join("\u{1e}");
        RolePolicyIdentity::ConfiguredPolicy {
            digest: hex::encode(Sha256::digest(canonical.as_bytes())),
        }
    }

    fn validate(&self) -> Result<(), String> {
        let mut seen_roles = BTreeSet::new();
        for rule in &self.rules {
            if !seen_roles.insert(rule.role) {
                return Err(format!(
                    "role_policy contains more than one rule for `{}`",
                    rule.role.as_str()
                ));
            }
            if let Some(model) = rule.model.as_deref() {
                validate_exact_model(model)?;
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RolePolicyConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawRolePolicyConfig {
            rules: Vec<RolePolicyRule>,
        }

        let raw = RawRolePolicyConfig::deserialize(deserializer)?;
        let config = Self { rules: raw.rules };
        config.validate().map_err(D::Error::custom)?;
        Ok(config)
    }
}

/// One exact provider binding for a closed hemisphere role.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RolePolicyRule {
    pub role: HemisphereRole,
    pub provider: InferenceProvider,
    /// An exact final wire-model ID. `None` admits every concrete model for
    /// the configured provider; it never admits another provider or role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

fn validate_exact_model(model: &str) -> Result<(), String> {
    if model.trim().is_empty() {
        return Err("role_policy model must not be empty".to_string());
    }
    if model != model.trim() {
        return Err("role_policy model must not have leading or trailing whitespace".to_string());
    }
    if model.chars().any(|character| character.is_control()) {
        return Err("role_policy model must not contain control characters".to_string());
    }
    if model.contains(['*', '?', '[', ']']) {
        return Err("role_policy model must be an exact ID, not a wildcard".to_string());
    }
    Ok(())
}

/// Retained identity of the policy that admitted a concrete dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolePolicyIdentity {
    /// No role policy was configured, so legacy routing remains in effect.
    CompatibilityDefault,
    /// Digest of the complete normalized configured policy that admitted this
    /// dispatch. The holder remains responsible for retaining its accepted
    /// configuration snapshot; this is an identity, not a mutable epoch.
    ConfiguredPolicy { digest: String },
}

/// Successful, content-free authorization for one already selected dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoleDispatchDecision {
    pub role: HemisphereRole,
    pub provider: InferenceProvider,
    pub model: String,
    pub policy: RolePolicyIdentity,
}

/// Stable, content-free reason for a denied hemisphere dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleDispatchViolationReason {
    RoleUnconfigured,
    ProviderNotAllowed,
    ModelNotAllowed,
}

impl RoleDispatchViolationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoleUnconfigured => "role_unconfigured",
            Self::ProviderNotAllowed => "provider_not_allowed",
            Self::ModelNotAllowed => "model_not_allowed",
        }
    }
}

impl std::fmt::Display for RoleDispatchViolationReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for RoleDispatchViolationReason {}

/// A denied concrete dispatch, including its requested identity for audit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoleDispatchViolation {
    pub role: HemisphereRole,
    pub provider: InferenceProvider,
    pub model: String,
    pub policy: RolePolicyIdentity,
    pub reason: RoleDispatchViolationReason,
}

impl std::fmt::Display for RoleDispatchViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "role dispatch denied for `{}` through `{}`: {}",
            self.role.as_str(),
            self.provider.as_str(),
            self.reason
        )
    }
}

impl std::error::Error for RoleDispatchViolation {}

#[derive(Clone, Copy)]
struct RoleDispatchCandidate<'a> {
    role: HemisphereRole,
    provider: InferenceProvider,
    final_model: &'a str,
}

impl<'a> RoleDispatchCandidate<'a> {
    const fn new(role: HemisphereRole, provider: InferenceProvider, final_model: &'a str) -> Self {
        Self {
            role,
            provider,
            final_model,
        }
    }

    fn decision(self, policy: RolePolicyIdentity) -> RoleDispatchDecision {
        RoleDispatchDecision {
            role: self.role,
            provider: self.provider,
            model: self.final_model.to_owned(),
            policy,
        }
    }

    fn violation(
        self,
        policy: RolePolicyIdentity,
        reason: RoleDispatchViolationReason,
    ) -> RoleDispatchViolation {
        RoleDispatchViolation {
            role: self.role,
            provider: self.provider,
            model: self.final_model.to_owned(),
            policy,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn left_openai_rule(model: Option<&str>) -> RolePolicyRule {
        RolePolicyRule {
            role: HemisphereRole::Left,
            provider: InferenceProvider::OpenAi,
            model: model.map(str::to_owned),
        }
    }

    #[test]
    fn rule_round_trips_through_yaml() {
        let config = RolePolicyConfig {
            rules: vec![left_openai_rule(Some("gpt-5.6"))],
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: RolePolicyConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn rejects_duplicate_roles_and_invalid_exact_models() {
        for yaml in [
            "rules:\n  - role: left\n    provider: openai_api\n  - role: left\n    provider: gemini_api\n",
            "rules:\n  - role: left\n    provider: openai_api\n    model: ''\n",
            "rules:\n  - role: left\n    provider: openai_api\n    model: gpt-*\n",
            "rules:\n  - role: left\n    provider: openai_api\n    unexpected: true\n",
            "rules:\n  - role: unknown\n    provider: openai_api\n",
            "rules:\n  - role: left\n    provider: unknown\n",
        ] {
            assert!(
                serde_yaml::from_str::<RolePolicyConfig>(yaml).is_err(),
                "{yaml}"
            );
        }
    }

    #[test]
    fn policy_omission_and_exact_decisions_fail_closed_as_required() {
        let config = RolePolicyConfig {
            rules: vec![left_openai_rule(Some("gpt-5.6"))],
        };
        let decision = config
            .resolve(HemisphereRole::Left, InferenceProvider::OpenAi, "gpt-5.6")
            .unwrap();
        assert!(matches!(
            decision.policy,
            RolePolicyIdentity::ConfiguredPolicy { .. }
        ));
        assert_eq!(
            config
                .resolve(HemisphereRole::Right, InferenceProvider::OpenAi, "gpt-5.6")
                .unwrap_err()
                .reason,
            RoleDispatchViolationReason::RoleUnconfigured
        );
        assert_eq!(
            config
                .resolve(HemisphereRole::Left, InferenceProvider::Gemini, "gpt-5.6")
                .unwrap_err()
                .reason,
            RoleDispatchViolationReason::ProviderNotAllowed
        );
        assert_eq!(
            config
                .resolve(HemisphereRole::Left, InferenceProvider::OpenAi, "gpt-5.5")
                .unwrap_err()
                .reason,
            RoleDispatchViolationReason::ModelNotAllowed
        );
        let denied = config
            .resolve(HemisphereRole::Left, InferenceProvider::OpenAi, "")
            .unwrap_err();
        assert_eq!(denied.reason, RoleDispatchViolationReason::ModelNotAllowed);
        assert!(matches!(
            denied.policy,
            RolePolicyIdentity::ConfiguredPolicy { .. }
        ));
    }

    #[test]
    fn policy_identity_is_order_independent_and_covers_every_rule() {
        let baseline = RolePolicyConfig {
            rules: vec![
                left_openai_rule(Some("gpt-5.6")),
                RolePolicyRule {
                    role: HemisphereRole::Right,
                    provider: InferenceProvider::Gemini,
                    model: Some("gemini-2.5-pro".to_string()),
                },
            ],
        };
        let reordered = RolePolicyConfig {
            rules: vec![baseline.rules[1].clone(), baseline.rules[0].clone()],
        };

        let decision_digest = |policy: &RolePolicyConfig| match policy
            .resolve(HemisphereRole::Left, InferenceProvider::OpenAi, "gpt-5.6")
            .unwrap()
            .policy
        {
            RolePolicyIdentity::ConfiguredPolicy { digest } => digest,
            RolePolicyIdentity::CompatibilityDefault => {
                unreachable!("configured policy has a digest")
            }
        };
        let violation_digest = |policy: &RolePolicyConfig| match policy
            .resolve(HemisphereRole::Left, InferenceProvider::OpenAi, "gpt-5.5")
            .unwrap_err()
            .policy
        {
            RolePolicyIdentity::ConfiguredPolicy { digest } => digest,
            RolePolicyIdentity::CompatibilityDefault => {
                unreachable!("configured policy has a digest")
            }
        };

        let baseline_decision = decision_digest(&baseline);
        let baseline_violation = violation_digest(&baseline);
        assert_eq!(baseline_decision, baseline_violation);
        assert_eq!(baseline_decision, decision_digest(&reordered));
        assert_eq!(baseline_violation, violation_digest(&reordered));

        let mut changed_provider = baseline.clone();
        changed_provider.rules[1].provider = InferenceProvider::AnthropicApi;
        assert_ne!(baseline_decision, decision_digest(&changed_provider));
        assert_ne!(baseline_violation, violation_digest(&changed_provider));

        let mut changed_model = baseline;
        changed_model.rules[1].model = Some("gemini-2.5-flash".to_string());
        assert_ne!(baseline_decision, decision_digest(&changed_model));
        assert_ne!(baseline_violation, violation_digest(&changed_model));
    }
}
