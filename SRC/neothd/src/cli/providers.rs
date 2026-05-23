//! `neoth provider {list, show}` — C-1 (Session 13).
//!
//! Surface the full `InferenceProvider` matrix to operators so they can
//! discover that NEOTH's `OpenaiCompat` adapter covers Together / Groq /
//! Mistral / DeepSeek / Cohere / Perplexity / Ollama / LM Studio / vLLM
//! without needing a separate first-class variant.
//!
//! `neoth provider list [--output json]` — print every supported provider
//! with implementation status + compat-endpoint examples.
//! `neoth provider show <provider> [--output json]` — print details for
//! one provider, including the cloud-label NEOTH surfaces during consent.

use anyhow::Result;
use serde_json::json;

use crate::cli::OutputFormat;
use crate::config::inference::InferenceProvider;

/// Static list of known OpenAI-compatible endpoints. Operators configure
/// `inference.{role}.endpoint = "https://api.X.com/v1"` + the
/// `openai_compat` provider to route through any of these without an
/// adapter-specific variant.
///
/// Pick #11 Phase C (Session 14): superseded by the structured
/// [`crate::providers::known_endpoints::KNOWN_ENDPOINTS`] catalogue
/// — that surface carries endpoint URL + default model + doc link
/// per provider. This legacy `OPENAI_COMPAT_TARGETS` string list
/// stays for backwards-compat with existing operator scripts that
/// scrape `neoth provider list` output.
pub const OPENAI_COMPAT_TARGETS: &[&str] = &[
    "together.ai",
    "groq.com",
    "mistral.ai",
    "deepseek.com",
    "perplexity.ai",
    "openrouter.ai",
    "xai (api.x.ai/v1)",
    "moonshot.cn (Kimi)",
    "open.bigmodel.cn (GLM)",
    "fireworks.ai",
    "ollama (localhost)",
    "lm_studio (localhost)",
    "vllm (localhost)",
];

const ALL_PROVIDERS: &[InferenceProvider] = &[
    InferenceProvider::ClaudeCli,
    InferenceProvider::AnthropicApi,
    InferenceProvider::OpenAi,
    InferenceProvider::OpenAiCompat,
    InferenceProvider::Gemini,
    InferenceProvider::LocalQwen,
    InferenceProvider::AwsBedrock,
    InferenceProvider::AzureOpenAi,
    InferenceProvider::LocalOuro,
];

fn is_compat_aware(p: InferenceProvider) -> bool {
    matches!(p, InferenceProvider::OpenAiCompat)
}

pub fn run_list(output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let entries: Vec<_> = ALL_PROVIDERS
                .iter()
                .map(|p| {
                    let mut obj = json!({
                        "id": p.as_str(),
                        "description": p.description(),
                        "implemented": p.is_implemented(),
                    });
                    if is_compat_aware(*p) {
                        obj.as_object_mut()
                            .unwrap()
                            .insert("compat_examples".into(), json!(OPENAI_COMPAT_TARGETS));
                    }
                    obj
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        OutputFormat::Table => {
            println!("# Supported LLM providers");
            println!();
            println!("{:<16} {:<10}  description", "id", "status");
            println!(
                "{:<16} {:<10}  {}",
                "-".repeat(16),
                "-".repeat(10),
                "-".repeat(40)
            );
            for p in ALL_PROVIDERS {
                let status = if p.is_implemented() { "ready" } else { "stub" };
                println!("{:<16} {status:<10}  {}", p.as_str(), p.description());
            }
            println!();
            println!("`openai_compat` covers these endpoints via a configurable URL:");
            for target in OPENAI_COMPAT_TARGETS {
                println!("  - {target}");
            }
            println!();
            println!("Bind a provider to a hemisphere with:");
            println!("  neoth hemispheres set --role <left|right|cerebellum> \\");
            println!("    --provider <id> [--model …] [--key …] [--endpoint …]");
        }
    }
    Ok(())
}

/// Pick #11 Phase C (Session 14) — `neoth provider known` lists the
/// structured well-known OpenAI-compatible endpoints catalogue (with
/// pre-filled endpoint URL, default model, doc link, summary).
pub fn run_known(output: &OutputFormat) -> Result<()> {
    use crate::providers::known_endpoints::KNOWN_ENDPOINTS;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let entries: Vec<_> = KNOWN_ENDPOINTS
                .iter()
                .map(|e| {
                    json!({
                        "id": e.provider_id,
                        "display": e.display,
                        "endpoint": e.endpoint,
                        "default_model": e.default_model,
                        "summary": e.summary,
                        "doc_url": e.doc_url,
                        "has_list_models": e.has_list_models,
                        "is_local": e.endpoint.contains("localhost")
                            || e.endpoint.contains("127.0.0.1"),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        OutputFormat::Table => {
            println!("# Known OpenAI-compatible providers");
            println!();
            println!("Configure via `neoth hemispheres set --role <X> --provider openai_compat \\");
            println!("    --endpoint <URL> --model <model_id>` using values below.");
            println!();
            println!("## Cloud providers");
            for e in KNOWN_ENDPOINTS
                .iter()
                .filter(|e| !e.endpoint.contains("localhost") && !e.endpoint.contains("127.0.0.1"))
            {
                println!("\n  {} ({})", e.display, e.provider_id);
                println!("    endpoint:      {}", e.endpoint);
                println!("    default_model: {}", e.default_model);
                println!("    summary:       {}", e.summary);
                println!("    docs:          {}", e.doc_url);
            }
            println!();
            println!("## Local (loopback) providers — no key required");
            for e in KNOWN_ENDPOINTS
                .iter()
                .filter(|e| e.endpoint.contains("localhost") || e.endpoint.contains("127.0.0.1"))
            {
                println!("\n  {} ({})", e.display, e.provider_id);
                println!("    endpoint:      {}", e.endpoint);
                println!("    default_model: {}", e.default_model);
                println!("    summary:       {}", e.summary);
                println!("    docs:          {}", e.doc_url);
            }
        }
    }
    Ok(())
}

pub fn run_show(provider_str: &str, output: &OutputFormat) -> Result<()> {
    let provider = InferenceProvider::from_str(provider_str).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown provider `{provider_str}`. Run `neoth provider list` for the full list."
        )
    })?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let mut obj = json!({
                "id": provider.as_str(),
                "description": provider.description(),
                "implemented": provider.is_implemented(),
            });
            if is_compat_aware(provider) {
                obj.as_object_mut()
                    .unwrap()
                    .insert("compat_examples".into(), json!(OPENAI_COMPAT_TARGETS));
            }
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
        OutputFormat::Table => {
            println!("# Provider — {}", provider.as_str());
            println!(
                "  status:      {}",
                if provider.is_implemented() {
                    "ready"
                } else {
                    "stub"
                }
            );
            println!("  description: {}", provider.description());
            if is_compat_aware(provider) {
                println!("  compat:      covers these endpoints via configurable URL:");
                for target in OPENAI_COMPAT_TARGETS {
                    println!("    - {target}");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_providers_covers_every_variant() {
        // Drift guard: when a new variant is added to InferenceProvider,
        // the operator-facing list must grow too or `provider list` will
        // silently omit it. Asserting equality on the full enum via
        // exhaustive match in a no-op fn keeps the compiler honest.
        fn _all_covered(p: InferenceProvider) -> bool {
            match p {
                InferenceProvider::ClaudeCli
                | InferenceProvider::AnthropicApi
                | InferenceProvider::OpenAi
                | InferenceProvider::OpenAiCompat
                | InferenceProvider::Gemini
                | InferenceProvider::LocalQwen
                | InferenceProvider::AwsBedrock
                | InferenceProvider::AzureOpenAi
                | InferenceProvider::LocalOuro => true,
            }
        }
        assert_eq!(
            ALL_PROVIDERS.len(),
            9,
            "ALL_PROVIDERS must enumerate every InferenceProvider variant"
        );
        for p in ALL_PROVIDERS {
            assert!(_all_covered(*p));
        }
    }

    #[test]
    fn openai_compat_targets_is_non_empty() {
        assert!(!OPENAI_COMPAT_TARGETS.is_empty());
        assert!(OPENAI_COMPAT_TARGETS.iter().any(|t| t.contains("groq")));
        assert!(OPENAI_COMPAT_TARGETS.iter().any(|t| t.contains("ollama")));
    }

    #[test]
    fn run_list_succeeds_for_table_output() {
        run_list(&OutputFormat::Table).unwrap();
    }

    #[test]
    fn run_list_succeeds_for_json_output() {
        run_list(&OutputFormat::Json).unwrap();
    }

    #[test]
    fn run_show_rejects_unknown_provider() {
        let err = run_show("nope", &OutputFormat::Table).unwrap_err();
        assert!(err.to_string().contains("nope"));
        assert!(err.to_string().contains("neoth provider list"));
    }

    #[test]
    fn run_show_accepts_each_implemented_provider() {
        for p in ALL_PROVIDERS {
            run_show(p.as_str(), &OutputFormat::Table)
                .unwrap_or_else(|e| panic!("show {} failed: {e}", p.as_str()));
        }
    }

    #[test]
    fn is_compat_aware_flags_only_openai_compat() {
        assert!(is_compat_aware(InferenceProvider::OpenAiCompat));
        assert!(!is_compat_aware(InferenceProvider::ClaudeCli));
        assert!(!is_compat_aware(InferenceProvider::LocalQwen));
        assert!(!is_compat_aware(InferenceProvider::Gemini));
    }
}
