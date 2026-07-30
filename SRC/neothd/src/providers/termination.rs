//! Provider-native completion termination metadata.
//!
//! Provider adapters must preserve authoritative wire signals instead of
//! reducing a refusal or safety-filter stop to an empty string or a generic
//! transport error.  This module deliberately does not decide whether or how
//! to retry; it only gives downstream policy code typed, serializable facts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Native facts describing why a provider stopped producing a completion.
///
/// `Default` represents a legacy completion whose adapter did not expose a
/// native finish reason.  That makes the field safe for old persisted shapes
/// and for providers that have not adopted native termination metadata yet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProviderTermination {
    /// Provider-native finish/stop reason, preserved verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    /// Present only when the provider authoritatively signalled a refusal or
    /// safety/content filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<ProviderRefusal>,
    /// Provider-specific structured facts which have no portable equivalent
    /// (for example Gemini safety ratings or Anthropic stop details).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub native_details: BTreeMap<String, Value>,
    /// Redacted identifier-only evidence reported by a trusted router response.
    ///
    /// This is observational provenance, never authorization, billing, or
    /// routing identity. `CompletionIdentity` remains authoritative for those
    /// decisions. Adapters must not copy arbitrary router metadata here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_upstream: Option<ObservedUpstreamEvidence>,
}

impl ProviderTermination {
    /// Preserve a provider's ordinary finish reason.
    pub fn finished(finish_reason: Option<String>) -> Self {
        Self {
            finish_reason,
            ..Self::default()
        }
    }

    /// Preserve an authoritative refusal/filter signal.
    pub fn refused(
        finish_reason: Option<String>,
        origin: RefusalOrigin,
        reason: impl Into<String>,
        message: Option<String>,
    ) -> Self {
        Self {
            finish_reason,
            refusal: Some(ProviderRefusal {
                origin,
                retryability: Retryability::Unknown,
                reason: reason.into(),
                message,
            }),
            native_details: BTreeMap::new(),
            observed_upstream: None,
        }
    }

    /// Attach one provider-native structured detail without flattening it.
    pub fn with_native_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.native_details.insert(key.into(), value);
        self
    }

    /// Retain provider-documented retry guidance without turning it into
    /// authorization. The recovery coordinator still owns the final decision.
    pub fn with_retryability(mut self, retryability: Retryability) -> Self {
        if let Some(refusal) = self.refusal.as_mut() {
            refusal.retryability = retryability;
        }
        self
    }

    pub fn is_refusal(&self) -> bool {
        self.refusal.is_some()
    }
}

/// Bounded provider/model identifiers observed in a trusted router response.
///
/// This intentionally cannot retain opaque metadata, prompts, credentials, or
/// request payloads. It is evidence about the upstream selected by a router,
/// not a substitute for the authorized [`crate::providers::CompletionIdentity`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedUpstreamEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

impl ObservedUpstreamEvidence {
    const MAX_IDENTIFIER_BYTES: usize = 256;

    pub(crate) fn from_wire(
        provider: Option<&str>,
        model: Option<&str>,
    ) -> Result<Option<Self>, ObservedUpstreamEvidenceError> {
        let evidence = Self {
            provider: Self::validated_identifier(provider, ObservedUpstreamField::Provider)?,
            model: Self::validated_identifier(model, ObservedUpstreamField::Model)?,
        };
        Ok((evidence.provider.is_some() || evidence.model.is_some()).then_some(evidence))
    }

    pub(crate) fn merge_into(
        accumulated: &mut Option<Self>,
        observed: Option<Self>,
    ) -> Result<(), ObservedUpstreamEvidenceError> {
        let Some(observed) = observed else {
            return Ok(());
        };
        let Some(existing) = accumulated.as_mut() else {
            *accumulated = Some(observed);
            return Ok(());
        };
        if Self::fields_conflict(&existing.provider, &observed.provider) {
            return Err(ObservedUpstreamEvidenceError::Conflict(
                ObservedUpstreamField::Provider,
            ));
        }
        if Self::fields_conflict(&existing.model, &observed.model) {
            return Err(ObservedUpstreamEvidenceError::Conflict(
                ObservedUpstreamField::Model,
            ));
        }
        if existing.provider.is_none() {
            existing.provider = observed.provider;
        }
        if existing.model.is_none() {
            existing.model = observed.model;
        }
        Ok(())
    }

    fn validated_identifier(
        raw: Option<&str>,
        field: ObservedUpstreamField,
    ) -> Result<Option<String>, ObservedUpstreamEvidenceError> {
        let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        if value.len() > Self::MAX_IDENTIFIER_BYTES
            || value.chars().any(char::is_control)
            || !crate::security::redact::find_secret_kinds(value).is_empty()
        {
            return Err(ObservedUpstreamEvidenceError::Invalid(field));
        }
        Ok(Some(value.to_owned()))
    }

    fn fields_conflict(existing: &Option<String>, observed: &Option<String>) -> bool {
        matches!((existing, observed), (Some(existing), Some(observed)) if existing != observed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservedUpstreamEvidenceError {
    Invalid(ObservedUpstreamField),
    Conflict(ObservedUpstreamField),
}

impl std::fmt::Display for ObservedUpstreamEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(field) => write!(
                formatter,
                "OpenRouter observed upstream {} is not a bounded identifier",
                field.as_str()
            ),
            Self::Conflict(field) => write!(
                formatter,
                "OpenRouter returned conflicting observed upstream {} values",
                field.as_str()
            ),
        }
    }
}

impl std::error::Error for ObservedUpstreamEvidenceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservedUpstreamField {
    Provider,
    Model,
}

impl ObservedUpstreamField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Model => "model",
        }
    }
}

/// Portable refusal/filter facts retained from a provider response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRefusal {
    pub origin: RefusalOrigin,
    /// A downstream recovery policy may refine this value.  Adapters use
    /// `Unknown` unless the provider contract makes retry semantics explicit.
    #[serde(default)]
    pub retryability: Retryability,
    /// Provider-native reason or category, preserved verbatim.
    pub reason: String,
    /// Optional provider-authored human-readable refusal text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Which authoritative part of the provider response signalled refusal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalOrigin {
    /// No origin was retained by a legacy or incomplete adapter.
    #[default]
    Unknown,
    /// A dedicated refusal field in the assistant message.
    ProviderMessage,
    /// A provider-native finish or stop reason.
    FinishReason,
    /// A provider blocked the prompt before candidate generation.
    PromptFilter,
    /// A provider filtered a generated candidate.
    CandidateFilter,
    /// A meta-provider/router guardrail blocked the request before an upstream
    /// model leaf accepted it.
    RouterGuardrail,
}

impl RefusalOrigin {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::ProviderMessage => "provider_message",
            Self::FinishReason => "finish_reason",
            Self::PromptFilter => "prompt_filter",
            Self::CandidateFilter => "candidate_filter",
            Self::RouterGuardrail => "router_guardrail",
        }
    }
}

/// Whether the same leaf may be retried after a native refusal.
///
/// This is descriptive metadata, not retry authorization.  The current direct
/// adapters intentionally emit `Unknown`; policy-aware recovery owns any
/// future refinement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Retryability {
    #[default]
    Unknown,
    SameProvider,
    DifferentProvider,
    NotRetryable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_empty_shape_deserializes_to_non_refusal_default() {
        let termination: ProviderTermination =
            serde_json::from_str("{}").expect("legacy empty shape");
        assert_eq!(termination, ProviderTermination::default());
        assert!(!termination.is_refusal());
    }

    #[test]
    fn refusal_round_trip_preserves_native_details() {
        let termination = ProviderTermination::refused(
            Some("content_filter".into()),
            RefusalOrigin::FinishReason,
            "content_filter",
            None,
        )
        .with_native_detail(
            "safety_ratings",
            serde_json::json!([{"category": "HARM_CATEGORY_DANGEROUS_CONTENT"}]),
        );

        let encoded = serde_json::to_string(&termination).expect("serialize");
        let decoded: ProviderTermination = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, termination);
    }

    #[test]
    fn observed_upstream_merges_partial_evidence_and_rejects_conflicts() {
        let mut accumulated = ObservedUpstreamEvidence::from_wire(
            Some("Anthropic"),
            Some("anthropic/claude-sonnet-4"),
        )
        .unwrap();
        ObservedUpstreamEvidence::merge_into(
            &mut accumulated,
            ObservedUpstreamEvidence::from_wire(Some("Anthropic"), None).unwrap(),
        )
        .unwrap();
        assert_eq!(
            accumulated,
            Some(ObservedUpstreamEvidence {
                provider: Some("Anthropic".into()),
                model: Some("anthropic/claude-sonnet-4".into()),
            })
        );

        let error = ObservedUpstreamEvidence::merge_into(
            &mut accumulated,
            ObservedUpstreamEvidence::from_wire(Some("OpenAI"), None).unwrap(),
        )
        .expect_err("provider conflict must fail");
        assert_eq!(
            error.to_string(),
            "OpenRouter returned conflicting observed upstream provider values"
        );
    }

    #[test]
    fn observed_upstream_rejects_non_identifier_data_without_echoing_it() {
        let secret = "sk-test\nprompt body";
        let error = ObservedUpstreamEvidence::from_wire(Some(secret), None)
            .expect_err("control characters must be rejected");
        assert!(!error.to_string().contains(secret));

        let credential = concat!("sk-", "FAKE_TEST_OPENAI_AAAAAAAAAAAAAA");
        for (provider, model) in [(Some(credential), None), (None, Some(credential))] {
            let error = ObservedUpstreamEvidence::from_wire(provider, model)
                .expect_err("secret-shaped observed identifiers must be rejected");
            assert!(!error.to_string().contains(credential));
        }
    }
}
