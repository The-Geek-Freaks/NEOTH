//! `neoth provider {list, show}` — C-1 (Session 13).
//!
//! Surface the full `InferenceProvider` matrix to operators so they can
//! discover that NEOTH's `OpenaiCompat` adapter covers Together / Groq /
//! Mistral / DeepSeek / Fireworks / Cerebras / Nebius / Cohere / Perplexity /
//! Ollama / LM Studio / vLLM without needing a separate first-class variant.
//!
//! `neoth provider list [--output json]` — print every supported provider
//! with implementation status + compat-endpoint examples.
//! `neoth provider show <provider> [--output json]` — print details for
//! one provider, including the cloud-label NEOTH surfaces during consent.

use anyhow::{Context, Result};
use serde_json::json;

use crate::cli::OutputFormat;
use crate::cli::init::catalog_model_ids_for_provider;
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
    "cerebras.ai",
    "nebius.ai (AI Studio)",
    "ollama (localhost)",
    "lm_studio (localhost)",
    "vllm (localhost)",
];

/// Render an operator-safe endpoint without ever echoing URL credentials,
/// query parameters, or fragments.  Invalid input deliberately becomes a
/// fixed marker rather than a partial copy of potentially sensitive text.
pub(crate) fn safe_operator_endpoint(endpoint: Option<&str>) -> Option<String> {
    endpoint.map(|raw| match url::Url::parse(raw) {
        Ok(mut parsed) => {
            if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
                return "(invalid endpoint)".to_owned();
            }
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string().trim_end_matches('/').to_owned()
        }
        Err(_) => "(invalid endpoint)".to_owned(),
    })
}

// The provider list is a public operator contract. Keep this alias at the
// CLI boundary, but make the config enum the only roster authority so GUI
// onboarding and `neoth provider list` cannot drift apart.
const ALL_PROVIDERS: &[InferenceProvider] = InferenceProvider::ALL;

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
    // MV-01c — best-effort live-catalog model list. Empty Vec when the
    // catalog is missing/stale or the provider has no catalog source
    // (LocalQwen / LocalOuro / AzureOpenAi → silent). Never fails run_show.
    let catalog_models = catalog_model_ids_for_provider(provider);
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
            if !catalog_models.is_empty() {
                obj.as_object_mut()
                    .unwrap()
                    .insert("available_models".into(), json!(catalog_models));
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
            if !catalog_models.is_empty() {
                println!("  available models (live catalog):");
                for id in &catalog_models {
                    println!("    - {id}");
                }
            }
        }
    }
    Ok(())
}

/// Pure: which hemisphere roles are wired to `target` in the topology. The
/// SAME `slot_for` resolution the runtime uses, so this reflects what the
/// daemon would actually dispatch. Single mode → one collapsed label (all
/// roles share `default_slot`); triplet/custom → the matching role labels.
fn provider_bindings(
    topo: &crate::config::inference::InferenceTopology,
    target: InferenceProvider,
) -> Vec<String> {
    use crate::config::inference::{HemisphereRole, TopologyMode};
    if topo.mode == TopologyMode::Single {
        return if topo.slot_for(HemisphereRole::Left).provider == Some(target) {
            vec!["all hemispheres (single mode)".to_string()]
        } else {
            Vec::new()
        };
    }
    [
        (HemisphereRole::Left, "left"),
        (HemisphereRole::Right, "right"),
        (HemisphereRole::Cerebellum, "cerebellum"),
    ]
    .into_iter()
    .filter(|(role, _)| topo.slot_for(*role).provider == Some(target))
    .map(|(_, label)| label.to_string())
    .collect()
}

/// `neoth provider test <id>` — a SAFE wiring check: is `<id>` actually
/// dispatched on any hemisphere, and where? It does NOT make a live LLM call
/// (that would bill a metered provider) and does NOT construct the provider
/// (which could eagerly load local weights) — it points at
/// `neoth hemispheres test --role <r> --question "Reply with OK"` for the real
/// round-trip, which already exists. Honest scope: confirm the wiring + hand
/// off the round-trip.
pub fn run_test(provider_str: &str, output: &OutputFormat) -> Result<()> {
    let target = InferenceProvider::from_str(provider_str).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown provider `{provider_str}`. Run `neoth provider list` for the full list."
        )
    })?;
    let cfg = crate::config::FreedomConfig::load_from_default_path()
        .map_err(|e| anyhow::anyhow!("load freedom.yaml: {e}"))?;
    let roles = provider_bindings(&cfg.inference, target);
    let wired = !roles.is_empty();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "provider": target.as_str(),
                    "wired": wired,
                    "roles": roles,
                    "live_round_trip": "neoth hemispheres test --role <role> --question \"Reply with OK\"",
                }))?
            );
        }
        OutputFormat::Table => {
            if wired {
                println!(
                    "✓ provider `{}` is wired into: {}",
                    target.as_str(),
                    roles.join(", ")
                );
                println!(
                    "  live round-trip: `neoth hemispheres test --role {} --question \"Reply with OK\"`",
                    // first concrete role label, or 'left' for the single-mode collapse
                    roles
                        .iter()
                        .find(|r| matches!(r.as_str(), "left" | "right" | "cerebellum"))
                        .map(String::as_str)
                        .unwrap_or("left")
                );
            } else {
                println!(
                    "✗ provider `{}` is not wired into any hemisphere.",
                    target.as_str()
                );
                println!(
                    "  bind it: `neoth hemispheres set --role <left|right|cerebellum> --provider {}`",
                    target.as_str()
                );
                println!("  see current bindings: `neoth hemispheres show`");
            }
        }
    }
    Ok(())
}

/// A read-only registry record for a named provider authority.  This is a
/// configuration projection only: it never constructs an adapter, consults
/// credentials, grants consent, or starts model discovery.
fn provider_instance_records(cfg: &crate::config::FreedomConfig) -> Result<Vec<serde_json::Value>> {
    use crate::config::inference::{HemisphereRole, HemisphereSlot};
    use std::collections::BTreeMap;

    let mut references: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for role in [
        HemisphereRole::Left,
        HemisphereRole::Right,
        HemisphereRole::Cerebellum,
    ] {
        let binding = cfg.inference.resolve_role_binding(role)?;
        if let Some(id) = binding.provider_instance_id {
            references
                .entry(id)
                .or_default()
                .push(format!("role:{}", role.as_str()));
        }
    }
    if let Some(id) = cfg.inference.profile_provider_instance_id.as_ref() {
        references
            .entry(id.as_str().to_owned())
            .or_default()
            .push("profile".to_owned());
    }
    for (index, slot) in cfg.fallback.chain.iter().enumerate() {
        let binding = cfg.inference.resolve_explicit_slot_binding(slot)?;
        if let Some(id) = binding.provider_instance_id {
            references
                .entry(id)
                .or_default()
                .push(format!("fallback:{index}"));
        }
    }

    cfg.inference
        .provider_instances
        .iter()
        .map(|instance| {
            let binding = cfg
                .inference
                .resolve_explicit_slot_binding(&HemisphereSlot {
                    provider_instance_id: Some(instance.id.clone()),
                    ..Default::default()
                })?;
            let configured_model = instance.model.clone();
            let display_model = configured_model.as_deref().map(|model| {
                binding
                    .models_aliases
                    .get(model)
                    .cloned()
                    .unwrap_or_else(|| cfg.resolve_model_alias(model).to_owned())
            });
            let catalog_key = crate::cli::init::catalog_key_for_resolved_binding(&binding);
            Ok(json!({
                "id": instance.id.as_str(),
                "descriptor": binding.provider_descriptor_id.clone(),
                "configured_model": configured_model,
                "display_model": display_model,
                "endpoint": safe_operator_endpoint(instance.endpoint.as_deref()),
                "region": instance.region,
                "catalog_key": catalog_key,
                "references": references.remove(instance.id.as_str()).unwrap_or_default(),
            }))
        })
        .collect()
}

fn load_provider_instance_records() -> Result<Vec<serde_json::Value>> {
    load_provider_instance_records_at(&crate::config::FreedomConfig::default_path())
}

fn load_provider_instance_records_at(path: &std::path::Path) -> Result<Vec<serde_json::Value>> {
    let cfg = crate::config::FreedomConfig::load_public_from_path(path)
        .context("load freedom.yaml for named provider-instance view")?;
    cfg.inference.validate_provider_instances()?;
    provider_instance_records(&cfg)
}

pub fn run_instance_list(output: &OutputFormat) -> Result<()> {
    let records = load_provider_instance_records()?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"instances": records}))?
            );
        }
        OutputFormat::Table => {
            println!("# Named provider instances");
            for record in &records {
                let id = record["id"].as_str().unwrap_or("(invalid)");
                let descriptor = record["descriptor"].as_str().unwrap_or("(invalid)");
                let configured_model = record["configured_model"]
                    .as_str()
                    .unwrap_or("(unconfigured)");
                let model = record["display_model"].as_str().unwrap_or("(unconfigured)");
                let endpoint = record["endpoint"].as_str().unwrap_or("");
                let region = record["region"].as_str().unwrap_or("");
                let catalog_key = record["catalog_key"].as_str().unwrap_or("(invalid)");
                let refs = record["references"]
                    .as_array()
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                println!(
                    "  {id:<16} descriptor={descriptor:<16} configured_model={configured_model:<28} display_model={model:<28} endpoint={endpoint} region={region} catalog_key={catalog_key} refs={refs}"
                );
            }
        }
    }
    Ok(())
}

fn find_provider_instance_record(
    records: Vec<serde_json::Value>,
    id: &str,
) -> Result<serde_json::Value> {
    records
        .into_iter()
        .find(|record| record["id"].as_str() == Some(id))
        .ok_or_else(|| anyhow::anyhow!("unknown provider instance `{id}`"))
}

pub fn run_instance_show(id: &str, output: &OutputFormat) -> Result<()> {
    let records = load_provider_instance_records()?;
    let record = find_provider_instance_record(records, id)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&record)?)
        }
        OutputFormat::Table => {
            println!(
                "# Named provider instance: {}",
                record["id"].as_str().unwrap_or("(invalid)")
            );
            for key in [
                "descriptor",
                "configured_model",
                "display_model",
                "endpoint",
                "region",
                "catalog_key",
                "references",
            ] {
                println!("  {key}: {}", record[key]);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderInstanceAddRequest {
    id: crate::config::inference::ProviderInstanceId,
    descriptor: String,
    model: Option<String>,
    endpoint: Option<String>,
    openai_compat_profile: Option<crate::config::inference::OpenAiCompatibleProfile>,
    region: Option<String>,
    api_version: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ProviderInstanceAddResult {
    pub record: serde_json::Value,
    pub snapshot_segment: std::path::PathBuf,
    pub snapshot_offset: Option<u64>,
    pub prior_source_sha256: String,
}

fn parse_openai_compat_profile(
    profile: Option<&str>,
) -> Result<Option<crate::config::inference::OpenAiCompatibleProfile>> {
    use crate::config::inference::OpenAiCompatibleProfile;
    profile
        .map(|value| match value {
            "generic" => Ok(OpenAiCompatibleProfile::Generic),
            "openrouter" | "open_router" => Ok(OpenAiCompatibleProfile::OpenRouter),
            "deepseek" | "deep_seek" => Ok(OpenAiCompatibleProfile::DeepSeek),
            "moonshot_kimi" | "moonshot" | "kimi" => Ok(OpenAiCompatibleProfile::MoonshotKimi),
            "qwen_chat" | "qwen" | "qwen_openai_compat" => Ok(OpenAiCompatibleProfile::QwenChat),
            "qwen_responses" => Ok(OpenAiCompatibleProfile::QwenResponses),
            "qwen_anthropic_compat" | "qwen_anthropic" => {
                Ok(OpenAiCompatibleProfile::QwenAnthropicCompat)
            }
            "qwen_dash_scope" | "dashscope" => Ok(OpenAiCompatibleProfile::QwenDashScope),
            _ => anyhow::bail!("unknown OpenAI-compatible profile `{value}`"),
        })
        .transpose()
}

fn provider_instance_add_request(
    id: &str,
    descriptor: &str,
    model: Option<String>,
    endpoint: Option<String>,
    openai_compat_profile: Option<String>,
    region: Option<String>,
    api_version: Option<String>,
) -> Result<ProviderInstanceAddRequest> {
    let id = crate::config::inference::ProviderInstanceId::parse(id)
        .context("validate named provider instance id")?;
    let provider = crate::config::inference::provider_descriptor(descriptor).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown provider descriptor `{descriptor}` for instance `{}`",
            id.as_str()
        )
    })?;
    Ok(ProviderInstanceAddRequest {
        id,
        descriptor: provider.as_str().to_owned(),
        model,
        endpoint,
        openai_compat_profile: parse_openai_compat_profile(openai_compat_profile.as_deref())?,
        region,
        api_version,
    })
}

fn prepare_provider_instance_add_at(
    path: &std::path::Path,
    request: &ProviderInstanceAddRequest,
) -> Result<(
    crate::config::PreparedFreedomUpdate,
    (crate::config::RollbackConfig, serde_json::Value),
)> {
    crate::config::FreedomConfig::prepare_public_update_at(path, |cfg| {
        cfg.inference.validate_provider_instances()?;
        anyhow::ensure!(
            !cfg.inference
                .provider_instances
                .iter()
                .any(|instance| instance.id == request.id),
            "provider instance `{}` already exists",
            request.id.as_str()
        );
        cfg.inference
            .provider_instances
            .push(crate::config::inference::ProviderInstance {
                id: request.id.clone(),
                descriptor: request.descriptor.clone(),
                model: request.model.clone(),
                models_aliases: Default::default(),
                key: None,
                endpoint: request.endpoint.clone(),
                openai_compat_profile: request.openai_compat_profile,
                region: request.region.clone(),
                api_version: request.api_version.clone(),
            });
        cfg.inference.validate_provider_instances()?;
        let record =
            find_provider_instance_record(provider_instance_records(cfg)?, request.id.as_str())?;
        Ok((cfg.rollback.clone(), record))
    })
    .context("prepare named provider-instance add")
}

/// Add one public named provider instance without creating a provider, touching credentials,
/// binding a role/fallback, granting consent, or starting discovery. The rollback writer drains before CAS.
pub(crate) async fn add_instance_at(
    home: &std::path::Path,
    request: ProviderInstanceAddRequest,
) -> Result<ProviderInstanceAddResult> {
    let path = home.join("freedom.yaml");
    let (prepared, (rollback, record)) = prepare_provider_instance_add_at(&path, &request)?;
    let prior_yaml_bytes = prepared
        .source_bytes()
        .ok_or_else(|| anyhow::anyhow!("freedom.yaml is missing at {}", path.display()))?;
    let prior_source_sha256 = prepared.source_sha256();
    let now_unix = crate::time::now_unix_i64();
    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir)
        .context("create WAL dir for provider-instance rollback snapshot")?;
    let snapshot_segment = crate::wal::writer::unique_standalone_segment_path(
        &wal_dir,
        "provider-instance-add-snapshot",
    );
    let (snapshot_writer, snapshot_completion) =
        crate::wal::writer::spawn_for_home_with_completion(
            snapshot_segment.clone(),
            home.to_path_buf(),
        )
        .context("spawn WAL writer for provider-instance add snapshot")?;
    let snapshot_result = crate::wal::snapshot::emit_if_policy_allows(
        &snapshot_writer,
        &rollback,
        crate::wal::snapshot::MutationKind::ConfigWrite,
        path.display().to_string(),
        prior_yaml_bytes,
        now_unix,
        Some("provider instance add via CLI".to_string()),
    )
    .await
    .context("emit pre-mutation snapshot for provider-instance add");
    drop(snapshot_writer);
    let completion_result = snapshot_completion
        .wait()
        .await
        .context("complete provider-instance add snapshot WAL writer");
    let snapshot_offset = match (snapshot_result, completion_result) {
        (Ok(offset), Ok(())) => offset,
        (Err(snapshot_error), Ok(())) => return Err(snapshot_error),
        (Ok(_), Err(completion_error)) => return Err(completion_error),
        (Err(snapshot_error), Err(completion_error)) => {
            return Err(anyhow::anyhow!(
                "provider-instance rollback snapshot emission failed: {snapshot_error}; writer completion also failed: {completion_error}"
            ));
        }
    };
    prepared.commit().with_context(|| {
        format!(
            "publish reviewed provider instance add in {}",
            path.display()
        )
    })?;
    Ok(ProviderInstanceAddResult {
        record,
        snapshot_segment,
        snapshot_offset,
        prior_source_sha256,
    })
}

pub async fn run_instance_add(
    id: &str,
    descriptor: &str,
    model: Option<String>,
    endpoint: Option<String>,
    openai_compat_profile: Option<String>,
    region: Option<String>,
    api_version: Option<String>,
    output: &OutputFormat,
) -> Result<()> {
    let request = provider_instance_add_request(
        id,
        descriptor,
        model,
        endpoint,
        openai_compat_profile,
        region,
        api_version,
    )?;
    let result =
        add_instance_at(&crate::config::FreedomConfig::default_neoth_home(), request).await?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({ "instance": result.record, "snapshot_segment": result.snapshot_segment.display().to_string(), "snapshot_offset": result.snapshot_offset, "prior_source_sha256": result.prior_source_sha256 })
            )?
        ),
        OutputFormat::Table => {
            println!("# Added named provider instance: {}", result.record["id"]);
            for key in [
                "descriptor",
                "configured_model",
                "display_model",
                "endpoint",
                "region",
                "catalog_key",
                "references",
            ] {
                println!("  {key}: {}", result.record[key]);
            }
            println!("  snapshot: {}", result.snapshot_segment.display());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::inference::{HemisphereSlot, InferenceTopology, TopologyMode};

    #[test]
    fn provider_bindings_single_mode_collapses_to_one_label() {
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Single;
        topo.default_slot.provider = Some(InferenceProvider::ClaudeCli);
        assert_eq!(
            provider_bindings(&topo, InferenceProvider::ClaudeCli),
            vec!["all hemispheres (single mode)".to_string()]
        );
        // A provider that isn't the single-mode slot is not wired.
        assert!(provider_bindings(&topo, InferenceProvider::LocalQwen).is_empty());
    }

    #[test]
    fn provider_bindings_triplet_lists_matching_roles_with_default_fallback() {
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Triplet;
        topo.left = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };
        topo.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };
        // `right` is unset → falls back to default_slot (gemini).
        topo.default_slot.provider = Some(InferenceProvider::Gemini);
        assert_eq!(
            provider_bindings(&topo, InferenceProvider::ClaudeCli),
            vec!["left"]
        );
        assert_eq!(
            provider_bindings(&topo, InferenceProvider::LocalQwen),
            vec!["cerebellum"]
        );
        assert_eq!(
            provider_bindings(&topo, InferenceProvider::Gemini),
            vec!["right"]
        );
        // A provider on no slot is unwired.
        assert!(provider_bindings(&topo, InferenceProvider::OpenAi).is_empty());
    }

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
                | InferenceProvider::LocalOuro
                | InferenceProvider::Cohere
                | InferenceProvider::GitHubCopilot
                | InferenceProvider::LocalOllama
                | InferenceProvider::RecursiveMas => true,
            }
        }
        assert_eq!(
            ALL_PROVIDERS.len(),
            13,
            "ALL_PROVIDERS must enumerate every InferenceProvider variant"
        );
        for p in ALL_PROVIDERS {
            assert!(_all_covered(*p));
        }
    }

    #[test]
    fn openai_compat_targets_cover_local_and_hosted_providers() {
        assert!(OPENAI_COMPAT_TARGETS.iter().any(|t| t.contains("groq")));
        assert!(OPENAI_COMPAT_TARGETS.iter().any(|t| t.contains("ollama")));
    }

    #[test]
    fn adopt31_h1_targets_are_discoverable_in_the_legacy_public_roster() {
        // `OPENAI_COMPAT_TARGETS` is part of the public `provider list` output
        // contract. Keep the three prepared, Generic OpenAI-compatible cloud
        // presets visible here without turning them into provider enum variants.
        let h1_targets = ["fireworks.ai", "cerebras.ai", "nebius.ai (AI Studio)"];
        for target in h1_targets {
            let occurrences = OPENAI_COMPAT_TARGETS
                .iter()
                .filter(|listed| **listed == target)
                .count();
            assert_eq!(
                occurrences, 1,
                "ADOPT31-H1 target {target} must appear exactly once"
            );
        }

        let positions: Vec<_> = h1_targets
            .iter()
            .map(|target| {
                OPENAI_COMPAT_TARGETS
                    .iter()
                    .position(|listed| listed == target)
                    .expect("target uniqueness asserted above")
            })
            .collect();
        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "existing Fireworks placement must remain ahead of the H1 additions"
        );
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
    fn run_show_catalog_section_is_silent_safe_for_catalog_keyed_providers() {
        // MV-01c: catalog-keyed providers (anthropic_api, openai_api)
        // must not fail run_show when no catalog file exists — the
        // "available models" section is a best-effort silent no-op.
        // (The model-filtering logic itself is unit-tested in init.rs.)
        for p in [
            InferenceProvider::AnthropicApi,
            InferenceProvider::OpenAi,
            InferenceProvider::Gemini,
        ] {
            run_show(p.as_str(), &OutputFormat::Json)
                .unwrap_or_else(|e| panic!("json show {} failed: {e}", p.as_str()));
        }
    }

    #[test]
    fn is_compat_aware_flags_only_openai_compat() {
        assert!(is_compat_aware(InferenceProvider::OpenAiCompat));
        assert!(!is_compat_aware(InferenceProvider::ClaudeCli));
        assert!(!is_compat_aware(InferenceProvider::LocalQwen));
        assert!(!is_compat_aware(InferenceProvider::Gemini));
    }

    #[test]
    fn named_instance_records_keep_unbound_entries_and_redact_endpoint_authority() {
        let cfg: crate::config::FreedomConfig = serde_yaml::from_str(
            "models_aliases: { '@fast': global-fast }\ninference:\n  mode: custom\n  provider_instances:\n    - id: compat_a\n      descriptor: openai_compat\n      endpoint: https://user:secret@a.example/v1?token=sentinel#fragment\n      model: '@fast'\n      models_aliases: { '@fast': instance-fast }\n      region: eu-central-1\n    - id: compat_b\n      descriptor: openai_compat\n      endpoint: https://b.example/v1\n      model: '@fast'\n  left: { provider_instance_id: compat_a }\n  right: { provider_instance_id: compat_a }\n  cerebellum: { provider: local_qwen }\nfallback:\n  chain:\n    - { provider_instance_id: compat_a }\n",
        )
        .expect("valid named-instance fixture");
        let records = provider_instance_records(&cfg).expect("pure registry projection");
        assert_eq!(records.len(), 2);
        let first = &records[0];
        assert_eq!(first["id"], "compat_a");
        assert_eq!(first["configured_model"], "@fast");
        assert_eq!(first["display_model"], "instance-fast");
        assert_eq!(first["endpoint"], "https://a.example/v1");
        assert_eq!(first["region"], "eu-central-1");
        assert_eq!(first["catalog_key"], "openai_compat__compat_a");
        assert_eq!(
            first["references"],
            json!(["role:left", "role:right", "fallback:0"])
        );
        let second = &records[1];
        assert_eq!(second["id"], "compat_b");
        assert_eq!(second["display_model"], "global-fast");
        assert_eq!(second["references"], json!([]));
        let rendered = serde_json::to_string(&records).expect("serialize records");
        for secret in ["user", "secret", "token", "sentinel", "fragment"] {
            assert!(
                !rendered.contains(secret),
                "registry output must redact {secret}"
            );
        }
        let unknown = find_provider_instance_record(records, "compat_missing")
            .expect_err("show must reject an unknown named instance before output");
        assert!(unknown.to_string().contains("compat_missing"));
    }

    #[test]
    fn safe_operator_endpoint_rejects_malformed_source_without_echoing_it() {
        assert_eq!(
            safe_operator_endpoint(Some("%%%secret-route?token=sentinel")),
            Some("(invalid endpoint)".to_owned())
        );
    }

    #[test]
    fn named_instance_view_reads_only_public_config_without_migration_or_credentials() {
        let home = tempfile::tempdir().expect("temporary instance view home");
        let freedom = home.path().join("freedom.yaml");
        let credentials = home.path().join("credentials.yaml");
        let public = b"secrets_backend: keychain\ninference:\n  provider_instances:\n    - id: inspect_only\n      descriptor: openai_compat\n      model: view-model\n      endpoint: https://example.invalid/v1\n";
        let private = b"[deliberately invalid private credential YAML";
        std::fs::write(&freedom, public).expect("write public configuration");
        std::fs::write(&credentials, private).expect("write unreadable credential content");

        let records = load_provider_instance_records_at(&freedom)
            .expect("public view never loads credentials or requires the OS store");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["id"], "inspect_only");
        assert_eq!(records[0]["display_model"], "view-model");
        assert_eq!(std::fs::read(&freedom).unwrap(), public);
        assert_eq!(std::fs::read(&credentials).unwrap(), private);
        let mut names: Vec<_> = std::fs::read_dir(home.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                std::ffi::OsString::from("credentials.yaml"),
                std::ffi::OsString::from("freedom.yaml"),
            ]
        );
    }

    #[test]
    fn provider_instance_add_rejects_invalid_duplicate_and_unknown_before_snapshot() {
        assert!(
            provider_instance_add_request(
                "Invalid-ID",
                "openai_compat",
                None,
                None,
                None,
                None,
                None
            )
            .is_err()
        );
        assert!(
            provider_instance_add_request(
                "compat_a",
                "unknown_descriptor",
                None,
                None,
                None,
                None,
                None
            )
            .is_err()
        );
        let home = tempfile::tempdir().unwrap();
        let freedom = home.path().join("freedom.yaml");
        std::fs::write(&freedom, "future_extension: preserve\ninference:\n  provider_instances:\n    - id: compat_a\n      descriptor: openai_compat\n").unwrap();
        let request = provider_instance_add_request(
            "compat_a",
            "openai_compat",
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(prepare_provider_instance_add_at(&freedom, &request).is_err());
        assert!(
            !home.path().join("wal").exists(),
            "invalid add must fail before rollback snapshot creation"
        );
        assert_eq!(
            std::fs::read_to_string(&freedom).unwrap(),
            "future_extension: preserve\ninference:\n  provider_instances:\n    - id: compat_a\n      descriptor: openai_compat\n"
        );
    }

    #[test]
    fn provider_instance_add_preparation_is_lossless_and_cas_bound() {
        let home = tempfile::tempdir().unwrap();
        let freedom = home.path().join("freedom.yaml");
        std::fs::write(&freedom, "future_extension: preserve\ninference: {}\n").unwrap();
        let request = provider_instance_add_request(
            "compat_a",
            "openai_compat",
            Some("vendor-model".into()),
            Some("https://user:secret@vendor.example/v1?token=sentinel".into()),
            None,
            Some("eu-central-1".into()),
            None,
        )
        .unwrap();
        let (prepared, (_, record)) = prepare_provider_instance_add_at(&freedom, &request).unwrap();
        assert_eq!(record["id"], "compat_a");
        assert_eq!(record["endpoint"], "https://vendor.example/v1");
        crate::config::FreedomConfig::update_at(&freedom, |cfg| {
            cfg.language_primary = Some("de".to_owned());
            Ok(())
        })
        .unwrap();
        let winning_generation = std::fs::read(&freedom).unwrap();
        assert!(
            prepared.commit().is_err(),
            "a stale add plan must refuse publication"
        );
        assert_eq!(std::fs::read(&freedom).unwrap(), winning_generation);
    }

    #[tokio::test]
    async fn provider_instance_add_snapshots_exact_prior_bytes_and_preserves_credentials() {
        let home = tempfile::tempdir().unwrap();
        let freedom = home.path().join("freedom.yaml");
        let credentials = home.path().join("credentials.yaml");
        std::fs::write(&freedom, "future_extension: preserve\ninference: {}\n").unwrap();
        std::fs::write(&credentials, "unrelated_future_secret: retain\n").unwrap();
        let before = std::fs::read(&freedom).unwrap();
        let credentials_before = std::fs::read(&credentials).unwrap();
        let request = provider_instance_add_request(
            "compat_a",
            "openai_compat",
            Some("vendor-model".into()),
            Some("https://vendor.example/v1".into()),
            None,
            None,
            None,
        )
        .unwrap();
        let result = add_instance_at(home.path(), request).await.unwrap();
        assert!(result.snapshot_offset.is_some());
        let snapshot_bytes = std::fs::read(&result.snapshot_segment).unwrap();
        let mut cursor = &snapshot_bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..];
        let mut before_state = None;
        while !cursor.is_empty() {
            let frame = crate::wal::frame::decode_frame(cursor).unwrap();
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_PRE_MUTATION_SNAPSHOT {
                let snapshot: crate::wal::snapshot::PreMutationSnapshot =
                    serde_json::from_slice(frame.payload).unwrap();
                before_state = Some(snapshot.before_state_bytes().unwrap());
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        assert_eq!(
            before_state.unwrap(),
            before,
            "rollback frame carries the exact prepared source bytes"
        );
        assert_eq!(
            std::fs::read(&credentials).unwrap(),
            credentials_before,
            "public add must not mutate private credentials"
        );
        assert_eq!(result.record["references"], json!([]));
    }
}
