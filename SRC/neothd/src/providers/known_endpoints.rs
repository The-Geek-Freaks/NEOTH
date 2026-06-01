//! Well-known OpenAI-compatible endpoints (Pick #11 Phase C, Session
//! 14).
//!
//! Curated list of LLM providers that expose an OpenAI-compatible
//! REST surface (`POST {endpoint}/chat/completions` with `Bearer
//! <key>`). Each entry maps to NEOTH's existing `OpenaiCompat`
//! provider variant — no new `InferenceProvider` variants needed.
//! The wizard surfaces these as named options ("DeepSeek (direct)",
//! "xAI Grok (direct)", …) so operators don't have to memorise URLs
//! + default model ids.
//!
//! ## Curation criteria
//!
//! Entries here MUST satisfy ALL of:
//!
//! 1. **OpenAI-compatible wire shape** — `chat/completions` POST with
//!    standard `messages` envelope. Adapters that need their own
//!    request format (Cohere, classic Bedrock invoke) get their own
//!    `InferenceProvider` variant instead.
//! 2. **Direct provider, not a gateway** — architectural correction
//!    (Session 14, 2026-05-18): NEOTH supersedes gateways
//!    like Hermes / OpenClaw / Airforce / Routeway. Those don't
//!    belong here. OpenRouter is the deliberate exception — it's a
//!    routing service explicitly designed to expose every provider
//!    behind one endpoint, complementary to NEOTH's per-provider
//!    config rather than competing with it.
//! 3. **Public API documentation** — operators must be able to
//!    obtain credentials + read the spec independently.
//! 4. **Currently maintained** — last platform update within 6
//!    months at curation time. Drift-checked annually.
//!
//! ## Update policy
//!
//! When a provider's flagship model name changes (e.g. Mistral
//! ships "Mistral Large 3"), bump the `default_model` here AND the
//! corresponding entry in
//! `crate::models::cli_detect::bundled_cli_models` if relevant.
//! The K-Models-Discovery refresh task (Pick #3) will eventually
//! supplant the hardcoded `default_model` field by reading the live
//! `/v1/models` endpoint per provider — for now the hardcode is the
//! offline-mode baseline.

/// One well-known OpenAI-compatible endpoint.
#[derive(Clone, Debug, PartialEq)]
pub struct KnownEndpoint {
    /// Operator-facing display name shown in the wizard select.
    pub display: &'static str,
    /// Short stable id used in `provider_id` slug + telemetry.
    /// Matches the lower-cased shorthand operators type when
    /// piping the daemon (e.g. `provider_id=deepseek`).
    pub provider_id: &'static str,
    /// Base REST URL — `/chat/completions` is appended automatically
    /// by `OpenAiAdapter::new_compat`. Trailing slash safe; the
    /// adapter strips it on construction.
    pub endpoint: &'static str,
    /// Default model id when the operator doesn't supply one. Picked
    /// to be the provider's flagship — operator can override via
    /// `freedom.yaml::provider_model` or wizard step.
    pub default_model: &'static str,
    /// One-line operator-readable purpose / niche.
    pub summary: &'static str,
    /// Documentation URL for credentials + API reference.
    pub doc_url: &'static str,
    /// Whether the provider exposes `/v1/models` for the
    /// K-Models-Discovery catalog refresh task to enumerate.
    pub has_list_models: bool,
}

/// Pinned 2026-05-18 snapshot. Cross-checked against an offline
/// provider-catalogue research dump + each provider's public docs.
pub const KNOWN_ENDPOINTS: &[KnownEndpoint] = &[
    KnownEndpoint {
        display: "DeepSeek (direct)",
        provider_id: "deepseek",
        endpoint: "https://api.deepseek.com/v1",
        default_model: "deepseek-v3.2",
        summary: "DeepSeek V3.2 + R1 reasoning — strong code + math, low cost",
        doc_url: "https://api-docs.deepseek.com",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "xAI Grok (direct)",
        provider_id: "xai",
        endpoint: "https://api.x.ai/v1",
        default_model: "grok-4-fast-non-reasoning",
        summary: "Grok 4 family — real-time data integration, vision",
        doc_url: "https://docs.x.ai/docs/api-reference",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "Mistral AI",
        provider_id: "mistral",
        endpoint: "https://api.mistral.ai/v1",
        default_model: "mistral-large-latest",
        summary: "Mistral Large + Codestral — EU-hosted, function calling",
        doc_url: "https://docs.mistral.ai/api",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "Moonshot Kimi",
        provider_id: "moonshot",
        endpoint: "https://api.moonshot.cn/v1",
        default_model: "kimi-k2",
        summary: "Kimi K2 / K2.5 — long-context (200k+), Chinese-native",
        doc_url: "https://platform.moonshot.cn/docs/api",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "Z.ai GLM",
        provider_id: "zai",
        endpoint: "https://open.bigmodel.cn/api/paas/v4",
        default_model: "glm-4.6",
        summary: "ChatGLM 4.6 / 4.7 — bilingual EN/ZH, agent + tool use",
        doc_url: "https://open.bigmodel.cn/dev/api",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "Together AI",
        provider_id: "together",
        endpoint: "https://api.together.xyz/v1",
        default_model: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        summary: "OSS models hosted (Llama, Mixtral, Qwen, DeepSeek)",
        doc_url: "https://docs.together.ai",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "Groq",
        provider_id: "groq",
        endpoint: "https://api.groq.com/openai/v1",
        default_model: "llama-3.3-70b-versatile",
        summary: "Low-latency hosted Llama / Mixtral / Gemma (LPU)",
        doc_url: "https://console.groq.com/docs",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "OpenRouter",
        provider_id: "openrouter",
        endpoint: "https://openrouter.ai/api/v1",
        default_model: "anthropic/claude-opus-4-7",
        summary: "Meta-router across 100+ models; per-call provider routing",
        doc_url: "https://openrouter.ai/docs",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "Fireworks AI",
        provider_id: "fireworks",
        endpoint: "https://api.fireworks.ai/inference/v1",
        default_model: "accounts/fireworks/models/llama-v3p3-70b-instruct",
        summary: "OSS model inference + fine-tuning, function calling",
        doc_url: "https://docs.fireworks.ai",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "Perplexity AI",
        provider_id: "perplexity",
        endpoint: "https://api.perplexity.ai",
        default_model: "sonar-pro",
        summary: "Sonar Pro — built-in web search + citations",
        doc_url: "https://docs.perplexity.ai",
        has_list_models: false,
    },
    KnownEndpoint {
        display: "Ollama (local)",
        provider_id: "ollama",
        endpoint: "http://localhost:11434/v1",
        default_model: "llama3.3",
        summary: "Local OSS model runner — no key required, OpenAI-compat",
        doc_url: "https://github.com/ollama/ollama/blob/main/docs/openai.md",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "LM Studio (local)",
        provider_id: "lm_studio",
        endpoint: "http://localhost:1234/v1",
        default_model: "auto",
        summary: "Local OSS model GUI runner — OpenAI-compat server",
        doc_url: "https://lmstudio.ai/docs/local-server",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "vLLM (local)",
        provider_id: "vllm",
        endpoint: "http://localhost:8000/v1",
        default_model: "auto",
        summary: "Local high-throughput inference server — OpenAI-compat",
        doc_url: "https://docs.vllm.ai",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "llama.cpp server (local)",
        provider_id: "llama_cpp",
        endpoint: "http://localhost:8080/v1",
        default_model: "auto",
        summary: "Local llama.cpp HTTP server — OpenAI-compat, GGUF models",
        doc_url: "https://github.com/ggerganov/llama.cpp/tree/master/examples/server",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "gpt4free (local proxy)",
        provider_id: "gpt4free",
        endpoint: "http://localhost:1337/v1",
        default_model: "gpt-4o",
        summary: "Free/scraped endpoint aggregator — OpenAI-compat (use at own risk)",
        doc_url: "https://github.com/xtekky/gpt4free",
        has_list_models: true,
    },
    KnownEndpoint {
        display: "text-generation-webui (local)",
        provider_id: "text_generation_webui",
        endpoint: "http://localhost:5000/v1",
        default_model: "auto",
        summary: "Oobabooga's web UI — OpenAI-compat API for loaded GGUF/safetensors",
        doc_url: "https://github.com/oobabooga/text-generation-webui",
        has_list_models: true,
    },
];

/// Look up a known endpoint by its `provider_id` slug.
pub fn find_by_id(provider_id: &str) -> Option<&'static KnownEndpoint> {
    KNOWN_ENDPOINTS
        .iter()
        .find(|e| e.provider_id == provider_id)
}

/// All entries whose endpoint resolves to `localhost` / `127.0.0.1` —
/// surfaced separately in the wizard so operators see the local-only
/// options grouped together.
pub fn local_only() -> impl Iterator<Item = &'static KnownEndpoint> {
    KNOWN_ENDPOINTS
        .iter()
        .filter(|e| e.endpoint.contains("localhost") || e.endpoint.contains("127.0.0.1"))
}

/// All entries that hit a remote (cloud) endpoint. Inverse of
/// [`local_only`]. Consent gate applies to these via the existing
/// `ProviderKind::OpenaiCompat` cloud classification.
pub fn cloud_only() -> impl Iterator<Item = &'static KnownEndpoint> {
    KNOWN_ENDPOINTS
        .iter()
        .filter(|e| !e.endpoint.contains("localhost") && !e.endpoint.contains("127.0.0.1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_entries() {
        assert!(!KNOWN_ENDPOINTS.is_empty());
        assert!(
            KNOWN_ENDPOINTS.len() >= 10,
            "catalog should cover at least the major direct + meta providers"
        );
    }

    #[test]
    fn catalog_entries_have_required_fields_set() {
        for e in KNOWN_ENDPOINTS {
            assert!(!e.display.is_empty(), "display empty for {}", e.provider_id);
            assert!(
                !e.provider_id.is_empty(),
                "provider_id empty for {}",
                e.display
            );
            assert!(!e.endpoint.is_empty(), "endpoint empty for {}", e.display);
            assert!(
                !e.default_model.is_empty(),
                "default_model empty for {}",
                e.display
            );
            assert!(!e.summary.is_empty(), "summary empty for {}", e.display);
            assert!(!e.doc_url.is_empty(), "doc_url empty for {}", e.display);
        }
    }

    #[test]
    fn provider_ids_are_lowercase_snake_compatible() {
        for e in KNOWN_ENDPOINTS {
            assert_eq!(
                e.provider_id,
                e.provider_id.to_ascii_lowercase(),
                "provider_id must be lowercase: {}",
                e.provider_id
            );
            for c in e.provider_id.chars() {
                assert!(
                    c.is_ascii_alphanumeric() || c == '_',
                    "provider_id {} contains non-ascii-alnum char: {c}",
                    e.provider_id
                );
            }
        }
    }

    #[test]
    fn provider_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in KNOWN_ENDPOINTS {
            assert!(
                seen.insert(e.provider_id),
                "duplicate provider_id: {}",
                e.provider_id
            );
        }
    }

    #[test]
    fn endpoints_are_https_or_localhost_only() {
        for e in KNOWN_ENDPOINTS {
            let ok = e.endpoint.starts_with("https://")
                || e.endpoint.contains("localhost")
                || e.endpoint.contains("127.0.0.1");
            assert!(
                ok,
                "endpoint {} should be https:// or localhost: {}",
                e.provider_id, e.endpoint
            );
        }
    }

    #[test]
    fn doc_urls_are_https() {
        for e in KNOWN_ENDPOINTS {
            assert!(
                e.doc_url.starts_with("https://"),
                "doc_url for {} must be https: {}",
                e.provider_id,
                e.doc_url
            );
        }
    }

    #[test]
    fn find_by_id_returns_known() {
        let deepseek = find_by_id("deepseek").expect("deepseek must be present");
        assert_eq!(deepseek.display, "DeepSeek (direct)");
        assert_eq!(deepseek.endpoint, "https://api.deepseek.com/v1");
    }

    #[test]
    fn find_by_id_returns_none_for_unknown() {
        assert!(find_by_id("never_seen").is_none());
        assert!(find_by_id("").is_none());
        assert!(find_by_id("DEEPSEEK").is_none(), "case-sensitive");
    }

    #[test]
    fn local_only_returns_local_endpoints() {
        let locals: Vec<_> = local_only().collect();
        assert!(!locals.is_empty(), "expect ollama/lmstudio/vllm at least");
        for e in &locals {
            assert!(
                e.endpoint.contains("localhost") || e.endpoint.contains("127.0.0.1"),
                "{} should be local",
                e.provider_id
            );
        }
    }

    #[test]
    fn cloud_only_returns_remote_endpoints() {
        let cloud: Vec<_> = cloud_only().collect();
        assert!(!cloud.is_empty());
        for e in &cloud {
            assert!(
                !e.endpoint.contains("localhost") && !e.endpoint.contains("127.0.0.1"),
                "{} should be remote",
                e.provider_id
            );
        }
    }

    #[test]
    fn local_and_cloud_partition_the_catalog() {
        let total = KNOWN_ENDPOINTS.len();
        let local_count = local_only().count();
        let cloud_count = cloud_only().count();
        assert_eq!(
            local_count + cloud_count,
            total,
            "local + cloud must cover every entry"
        );
    }

    #[test]
    fn curated_providers_present() {
        // Pin the AIRFORCE-research outcomes: every direct-provider
        // identified in the competitor scan must be in the catalog.
        let must_have = [
            "deepseek",
            "xai",
            "mistral",
            "moonshot",
            "zai",
            "groq",
            "openrouter",
        ];
        for id in must_have {
            assert!(
                find_by_id(id).is_some(),
                "AIRFORCE-research catalog must include: {id}"
            );
        }
    }
}
