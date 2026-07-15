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

/// Loopback host bounded so it does NOT match near-miss addresses: the host
/// must sit right after `//`, `@`, or `[`, and end at `:`, `/`, `]`, or the end
/// of string. Plain `contains("::1")` wrongly flags `[::100]`, `contains
/// ("127.0.0.1")` flags `127.0.0.10`, and `contains("localhost")` flags
/// `localhost.evil.com` — all remote hosts a substring match would call local.
static RE_LOCAL_ENDPOINT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    // Loopback host forms: `localhost`, any 127.x IPv4 loopback, compressed
    // `::1`, the full-form `0:0:0:0:0:0:0:1`, and the IPv4-mapped
    // `::ffff:127.0.0.1`. All must be bounded (start after //, @, or [ and end
    // at :, /, ], or end) so near-miss hosts like [::100] / 127.0.0.10 /
    // localhost.evil.com are NOT treated as local.
    regex::Regex::new(
        r"(?i)(?:^|//|@|\[)(?:localhost|127\.0\.0\.1|::1|0:0:0:0:0:0:0:1|::ffff:127\.0\.0\.1)(?:[:/\]]|$)",
    )
    .unwrap()
});

/// Return `true` when `endpoint` resolves to the local machine — `localhost`,
/// `127.0.0.1`, or the IPv6 loopback (`::1` / `[::1]`) — as a bounded host, not
/// a loose substring. Used by [`local_only`], [`cloud_only`], and the wizard
/// key-ping locality skip.
#[inline]
pub(crate) fn is_local_endpoint(endpoint: &str) -> bool {
    RE_LOCAL_ENDPOINT.is_match(endpoint)
}

/// Extract the bare host from an endpoint URL: strips scheme, userinfo, path,
/// port, and IPv6 brackets. Returns `None` if a host can't be isolated.
fn endpoint_host(endpoint: &str) -> Option<&str> {
    let after_scheme = endpoint.split("://").nth(1).unwrap_or(endpoint);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?; // drop any user:pass@
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest.split(']').next(); // [ipv6]:port -> ipv6
    }
    // host:port -> host, but only strip a trailing numeric port when the host
    // isn't itself a bare (colon-bearing) IPv6 literal.
    match host_port.rfind(':') {
        Some(i)
            if host_port[..i].find(':').is_none()
                && host_port[i + 1..].chars().all(|c| c.is_ascii_digit()) =>
        {
            Some(&host_port[..i])
        }
        _ => Some(host_port),
    }
}

/// Return `true` when `endpoint` is NOT a public, routable address: loopback,
/// RFC-1918 private (10/8, 172.16/12, 192.168/16), link-local (169.254/16 —
/// includes the cloud instance-metadata service), or IPv6 ULA (fc00::/7) /
/// link-local (fe80::/10). A domain name is treated as public. Used to gate the
/// ZF-03 wizard key-ping: the bearer key must never be POSTed to a non-public
/// host (an operator's LAN box, a metadata service, or a tampered endpoint).
pub(crate) fn is_non_public_endpoint(endpoint: &str) -> bool {
    if is_local_endpoint(endpoint) {
        return true;
    }
    match endpoint_host(endpoint).and_then(|h| h.parse::<std::net::IpAddr>().ok()) {
        Some(std::net::IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_link_local() || ip.is_loopback() || ip.is_unspecified()
        }
        Some(std::net::IpAddr::V6(ip)) => {
            // An IPv4-mapped address (`::ffff:a.b.c.d`) must be judged by its
            // embedded IPv4 — otherwise `::ffff:192.168.1.1` or the mapped IMDS
            // `::ffff:169.254.169.254` would sail past the pure-IPv6 checks below.
            if let Some(v4) = ip.to_ipv4_mapped() {
                return v4.is_private()
                    || v4.is_link_local()
                    || v4.is_loopback()
                    || v4.is_unspecified();
            }
            let seg0 = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (seg0 & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
        None => false, // domain name (or unparseable) → treat as public
    }
}

/// All entries whose endpoint resolves to `localhost` / `127.0.0.1` /
/// `[::1]` — surfaced separately in the wizard so operators see the
/// local-only options grouped together.
pub fn local_only() -> impl Iterator<Item = &'static KnownEndpoint> {
    KNOWN_ENDPOINTS
        .iter()
        .filter(|e| is_local_endpoint(e.endpoint))
}

/// All entries that hit a remote (cloud) endpoint. Inverse of
/// [`local_only`]. Consent gate applies to these via the existing
/// `ProviderKind::OpenaiCompat` cloud classification.
pub fn cloud_only() -> impl Iterator<Item = &'static KnownEndpoint> {
    KNOWN_ENDPOINTS
        .iter()
        .filter(|e| !is_local_endpoint(e.endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_entries() {
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
            let ok = e.endpoint.starts_with("https://") || is_local_endpoint(e.endpoint);
            assert!(
                ok,
                "endpoint {} should be https:// or local (localhost/127.0.0.1/::1): {}",
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
                is_local_endpoint(e.endpoint),
                "{} should be local (localhost/127.0.0.1/::1): {}",
                e.provider_id,
                e.endpoint
            );
        }
    }

    #[test]
    fn cloud_only_returns_remote_endpoints() {
        let cloud: Vec<_> = cloud_only().collect();
        assert!(!cloud.is_empty());
        for e in &cloud {
            assert!(
                !is_local_endpoint(e.endpoint),
                "{} should be remote (not localhost/127.0.0.1/::1): {}",
                e.provider_id,
                e.endpoint
            );
        }
    }

    #[test]
    fn is_local_endpoint_matches_ipv6_loopback() {
        assert!(
            is_local_endpoint("http://[::1]:11434/v1"),
            "[::1] bracketed form"
        );
        assert!(is_local_endpoint("http://::1:11434/v1"), "bare ::1 form");
        assert!(is_local_endpoint("http://localhost:11434/v1"), "localhost");
        assert!(is_local_endpoint("http://127.0.0.1:11434/v1"), "127.0.0.1");
        assert!(
            is_local_endpoint("http://localhost/v1"),
            "localhost no port"
        );
        // Wave-10: full-form + IPv4-mapped IPv6 loopback must also be local.
        assert!(
            is_local_endpoint("https://[0:0:0:0:0:0:0:1]:11434/v1"),
            "full-form ::1"
        );
        assert!(
            is_local_endpoint("https://[::ffff:127.0.0.1]:8080/v1"),
            "IPv4-mapped loopback"
        );
        assert!(
            !is_local_endpoint("https://api.openai.com/v1"),
            "cloud endpoint"
        );
        assert!(
            !is_local_endpoint("https://api.deepseek.com/v1"),
            "cloud endpoint 2"
        );
        // Wave-8 regression: near-miss hosts a substring match wrongly flagged.
        assert!(
            !is_local_endpoint("http://127.0.0.10/v1"),
            "127.0.0.10 is not loopback"
        );
        assert!(
            !is_local_endpoint("http://[::100]:8080/v1"),
            "[::100] is not loopback"
        );
        assert!(
            !is_local_endpoint("http://[::1a]:8080/v1"),
            "[::1a] is not loopback"
        );
        assert!(
            !is_local_endpoint("http://localhost.evil.com/v1"),
            "localhost.evil.com is remote"
        );
    }

    #[test]
    fn is_non_public_endpoint_blocks_private_and_metadata() {
        // Non-public: loopback, RFC-1918, link-local (incl. IMDS), ULA.
        for e in [
            "http://127.0.0.1:11434/v1",
            "https://[::1]:8080/v1",
            "https://192.168.1.100/v1",
            "https://10.0.0.5:8000/v1",
            "https://172.16.4.2/v1",
            "https://169.254.169.254/latest/meta-data", // AWS IMDS
            "http://user:pass@10.1.2.3:9000/v1",
            "https://[fc00::1]:8080/v1", // ULA
            "https://[fe80::1]:8080/v1", // link-local
            // Wave-19: IPv4-mapped forms of private / IMDS addresses.
            "https://[::ffff:192.168.1.100]:8080/v1",
            "https://[::ffff:10.0.0.5]/v1",
            "https://[::ffff:169.254.169.254]/latest/meta-data",
            "https://[::ffff:127.0.0.1]:8080/v1",
        ] {
            assert!(is_non_public_endpoint(e), "must be blocked: {e}");
        }
        // Public: real cloud provider hosts and public IPs are pingable.
        for e in [
            "https://api.openai.com/v1",
            "https://api.anthropic.com",
            "https://8.8.8.8/v1",
            "https://[2606:4700:4700::1111]/v1",
        ] {
            assert!(!is_non_public_endpoint(e), "must be public: {e}");
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
