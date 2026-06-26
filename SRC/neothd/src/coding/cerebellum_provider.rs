//! Cerebellum LLM adapter — wraps a `providers::Provider` (the
//! hemisphere-bound LLM resolved from `InferenceTopology`) so the
//! decomposer can call it through its provider-agnostic
//! [`DecomposerLlm`] trait.
//!
//! Pick #5b per `PLAN/SPEC_coding_workflow.md` — completes the
//! v1.0 ship-blocker chain by bridging the decomposer to a real
//! cerebellum hemisphere provider (claude_cli, openai_api,
//! local_qwen, ...).
//!
//! The wrapper is intentionally thin: forward `complete()` to the
//! underlying provider with no temperature/top_p overrides (the
//! decomposer prompt is structured enough that adapter defaults
//! produce stable JSON). Future picks (#9 LLM second-opinion
//! classify) can layer a lower-temperature sub-call on top by
//! threading sampling args through.

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::decomposer::DecomposerLlm;
use crate::providers::{Provider, Request};

/// Adapter from `Box<dyn Provider>` to `DecomposerLlm`. Constructed
/// per-`neoth code` invocation via `providers::from_config_for_role`.
/// The wrapper owns the provider — Pick #5b's CLI entry hands it off
/// to the decomposer for the lifetime of one decomposition call.
pub struct CerebellumDecomposer {
    provider: Box<dyn Provider>,
}

impl CerebellumDecomposer {
    pub fn new(provider: Box<dyn Provider>) -> Self {
        Self { provider }
    }

    /// Underlying provider's short identifier (`claude_cli`,
    /// `openai_api`, ...). Surfaced in the CLI's "Cerebellum bound
    /// to: X" line for operator transparency before the LLM call
    /// fires.
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }
}

#[async_trait]
impl DecomposerLlm for CerebellumDecomposer {
    async fn complete(&self, prompt: &str) -> Result<String> {
        let req = Request {
            prompt: prompt.to_string(),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: vec![],
            thinking_budget: None,
        };
        let completion = self
            .provider
            .complete(req)
            .await
            .context("cerebellum LLM complete call")?;
        Ok(completion.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::providers::Completion;

    /// Scripted in-memory provider — returns a pre-baked text on every
    /// `complete` call. Used to verify the adapter forwards the
    /// prompt + relays the response without mutation.
    struct ScriptedProvider {
        canned_response: String,
    }

    #[async_trait]
    impl Provider for ScriptedProvider {
        fn name(&self) -> &'static str {
            "scripted"
        }

        async fn complete(&self, _req: Request) -> Result<Completion> {
            Ok(Completion {
                text: self.canned_response.clone(),
                model: "test".to_string(),
                latency: Duration::from_millis(1),
                input_tokens: Some(0),
                output_tokens: Some(0),
            })
        }
    }

    #[tokio::test]
    async fn cerebellum_decomposer_forwards_completion_text() {
        let provider = Box::new(ScriptedProvider {
            canned_response: r#"{"tasks":[],"clarifying_question":"need more detail"}"#.to_string(),
        });
        let llm = CerebellumDecomposer::new(provider);
        let result = llm.complete("test prompt").await.expect("complete ok");
        assert!(
            result.contains("clarifying_question"),
            "adapter must return the provider's text verbatim"
        );
    }

    #[tokio::test]
    async fn cerebellum_decomposer_exposes_provider_name() {
        let provider = Box::new(ScriptedProvider {
            canned_response: "{}".to_string(),
        });
        let llm = CerebellumDecomposer::new(provider);
        assert_eq!(llm.provider_name(), "scripted");
    }

    #[tokio::test]
    async fn cerebellum_decomposer_propagates_provider_errors() {
        // A provider that always errors must surface as Err from the
        // adapter, not get swallowed.
        struct FailingProvider;

        #[async_trait]
        impl Provider for FailingProvider {
            fn name(&self) -> &'static str {
                "failing"
            }
            async fn complete(&self, _req: Request) -> Result<Completion> {
                anyhow::bail!("simulated upstream failure")
            }
        }

        let llm = CerebellumDecomposer::new(Box::new(FailingProvider));
        let err = llm.complete("anything").await.unwrap_err();
        assert!(
            err.to_string().contains("cerebellum LLM complete")
                || err
                    .chain()
                    .any(|e| e.to_string().contains("simulated upstream failure")),
            "error context lost: {err}"
        );
    }
}
