//! Provider/model/topology catalog helpers for the `neoth init` wizard
//! (GOLD-ARCH-05): provider + hemisphere-model prompts, local presets,
//! catalog lookups, council-depth cost warning. Split out of `cli/init.rs`.

use anyhow::{Context, Result};

use super::{InitArgs, ProviderKind};

/// Resolve a provider API key from (in order): --provider-key, env, interactive
/// password prompt. Returns None if user skips.
pub(crate) fn prompt_provider_key(
    args: &InitArgs,
    interactive: bool,
    kind: ProviderKind,
) -> Result<Option<String>> {
    if let Some(k) = &args.provider_key {
        return Ok(Some(k.clone()));
    }
    if !interactive {
        return Ok(::std::option::Option::None);
    }
    #[cfg(feature = "wizard")]
    {
        let label = match kind {
            ProviderKind::OpenaiApi => "OpenAI API key (sk-...)",
            ProviderKind::GeminiApi => "Gemini API key",
            ProviderKind::OpenaiCompat => "API key (or blank if endpoint is unauthenticated)",
            _ => "API key",
        };
        let key: String =
            dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(format!("[5/9] {label}"))
                .allow_empty_password(matches!(kind, ProviderKind::OpenaiCompat))
                .interact()
                .context("provider key input")?;
        if key.is_empty() {
            Ok(::std::option::Option::None)
        } else {
            Ok(Some(key))
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        let _ = kind;
        Ok(::std::option::Option::None)
    }
}

/// E-2 Phase 4 (Session 14 Pick #23) — operator-readable cost warning
/// for council recursion. Spells out the leaf-call multiplication so a
/// hand-edited `freedom.yaml::hemisphere_council_depth: 4` (or a wizard
/// raise above 1) gets matched with the actual token-burn math BEFORE
/// the operator commits.
///
/// Returns the multi-line warning text ready to `println!` — pure-fn so
/// the same string lands in the wizard's interactive screen, in the
/// non-interactive `eprintln!` warning, and in the unit tests pinning
/// the math.
pub fn render_council_depth_cost_warning(depth: u8) -> String {
    // 3 hemispheres per recursion level → 3^depth leaf calls in the
    // worst case. Clamp the exponent to u32 so a malicious depth=255
    // can't overflow at the call site (the type-system clamps to 4
    // before this fn is invoked, but we stay defensive).
    let safe_depth: u32 = (depth as u32).min(u32::from(
        crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
    ));
    let leaf_calls = 3u64.saturating_pow(safe_depth);
    let default_cap: u32 = crate::config::inference::DEFAULT_MAX_CALLS_PER_USER_MESSAGE;
    let cap_note = if (leaf_calls as u32) > default_cap {
        format!(
            "exceeds council.max_calls_per_user_message default cap of {default_cap}\n     \
             → late hemispheres will surface `budget-exhausted` (Pick #19 BudgetToken). \
             Raise the cap in freedom.yaml if you want all leaves to run."
        )
    } else {
        format!("fits within the council.max_calls_per_user_message default cap of {default_cap}")
    };
    format!(
        "\
    ┌──────────────────────────────────────────────────────────────────┐\n  \
    │  COUNCIL DEPTH COST WARNING (E-2 Phase 4)                        │\n  \
    └──────────────────────────────────────────────────────────────────┘\n  \
      depth={depth} → up to {leaf_calls} leaf LLM calls per user message\n  \
      ({cap_note})\n  \
      Cloud-token cost at typical pricing: roughly €0.02-€0.50 per message at depth 2,\n  \
      scaling linearly with the leaf count.\n  \
      Operator-recommended defaults:\n  \
        depth=1: flat 3-hemisphere council (default)\n  \
        depth=2: fractal sub-councils — useful for high-stakes prompts only\n  \
        depth=3+: research / debugging — manual budget tuning required"
    )
}

/// Helper: prompt the operator to pick one `InferenceProvider`. Used in
/// per-hemisphere + embedding choices. Default lands on the operator's
/// already-chosen step-5 provider, so a single-key flow stays one click.
#[cfg(feature = "wizard")]
pub(crate) fn prompt_inference_provider(
    prompt: &str,
    default: Option<crate::config::inference::InferenceProvider>,
) -> Result<crate::config::inference::InferenceProvider> {
    use crate::config::inference::InferenceProvider;

    let options = [
        InferenceProvider::ClaudeCli,
        InferenceProvider::AnthropicApi,
        InferenceProvider::OpenAi,
        InferenceProvider::OpenAiCompat,
        InferenceProvider::Gemini,
        InferenceProvider::LocalQwen,
        InferenceProvider::AwsBedrock,
        InferenceProvider::AzureOpenAi,
    ];
    let labels: Vec<String> = options
        .iter()
        .map(|p| {
            let stub = if p.is_implemented() { "" } else { " [stub]" };
            format!("{:<15}{stub}  {}", p.as_str(), p.description())
        })
        .collect();
    let default_idx = default
        .and_then(|d| options.iter().position(|p| *p == d))
        .unwrap_or(0);
    let pick = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(prompt)
        .items(&labels)
        .default(default_idx)
        .interact()
        .context("provider select")?;
    Ok(options[pick])
}

#[cfg(not(feature = "wizard"))]
pub(crate) fn prompt_inference_provider(
    _prompt: &str,
    default: Option<crate::config::inference::InferenceProvider>,
) -> Result<crate::config::inference::InferenceProvider> {
    Ok(default.unwrap_or(crate::config::inference::InferenceProvider::ClaudeCli))
}

/// Per-role recommendation from SPEC_hemisphere_provider_selection.md §2.
/// Surfaced as a *suggestion* in the wizard — never enforced. Returning
/// `InferenceProvider` (not `Option`) lets the prompt always pre-select
/// a sane default for a one-keystroke confirm.
/// Finding 6 (Session 13) — apply the wizard's `local-only` topology
/// preset. All three hemispheres + the single-mode default slot are
/// bound to `LocalQwen`, mode is set to `Triplet` (so per-hemisphere
/// lookup honours the explicit slots rather than collapsing to a
/// single-mode fallback). Pure function — tested directly without
/// running the interactive wizard.
pub(crate) fn apply_local_only_preset(topology: &mut crate::config::inference::InferenceTopology) {
    use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
    let local_slot = HemisphereSlot {
        provider: Some(InferenceProvider::LocalQwen),
        model: None,
        key: None,
        endpoint: None,
        region: None,
        api_version: None,
        // GOLD-WIRE-04: local-only preset leaves voices unset.
        voice: None,
    };
    topology.mode = TopologyMode::Triplet;
    topology.default_slot = local_slot.clone();
    topology.left = local_slot.clone();
    topology.right = local_slot.clone();
    topology.cerebellum = local_slot;
}

/// GOLD-ADOPT-12 — apply a multi-local hemisphere preset: each local slot
/// becomes an `OpenAiCompat` provider pointing at Ollama's `/v1` with the
/// planned quantized GGUF as its model. All-local → Triplet; a local+cloud mix
/// → Custom (roles past `preset.locals` keep their existing — typically cloud —
/// slot). Ollama needs no key, so `key` stays `None`.
pub(crate) fn apply_local_abliterated_preset(
    topology: &mut crate::config::inference::InferenceTopology,
    preset: &crate::models::hemisphere_preset::HemispherePreset,
) {
    use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
    let make_slot = |model_ref: &str| HemisphereSlot {
        provider: Some(InferenceProvider::OpenAiCompat),
        model: Some(model_ref.to_string()),
        key: None,
        endpoint: Some(preset.endpoint.clone()),
        region: None,
        api_version: None,
        voice: None,
    };
    topology.mode = if preset.is_all_local() {
        TopologyMode::Triplet
    } else {
        TopologyMode::Custom
    };
    for local in &preset.locals {
        let slot = make_slot(&local.ollama_model_ref);
        match local.role {
            "left" => topology.left = slot,
            "right" => topology.right = slot,
            "cerebellum" => topology.cerebellum = slot,
            _ => {}
        }
    }
    // Mirror the first local onto default_slot only when every hemisphere is
    // local (matches apply_local_only_preset); a mixed setup keeps the cloud
    // default so unspecified surfaces still reach a capable provider.
    if preset.is_all_local() {
        if let Some(first) = preset.locals.first() {
            topology.default_slot = make_slot(&first.ollama_model_ref);
        }
    }
}

/// GOLD-ADOPT-12 — interactive multi-local preset: VRAM-size the local model(s),
/// let the operator choose how many hemispheres run local (1..=max the hardware
/// supports), bind them to Ollama, and print the `ollama pull` commands. Falls
/// back to single-provider when no GPU/VRAM holds a usable local model.
#[cfg(feature = "wizard")]
pub(crate) fn apply_local_multi_preset_interactive(
    topology: &mut crate::config::inference::InferenceTopology,
) -> Result<()> {
    use crate::installers::ollama::DEFAULT_OLLAMA_PORT;
    use crate::models::gguf_variants::VariantClass;
    use crate::models::hemisphere_preset::{ROLES, build_local_preset};
    use crate::models::selector::recommended_local_count;

    let vram_mib = crate::installers::gpu::probe_gpu().vram_mib;
    let n_max = recommended_local_count(vram_mib);
    if n_max == 0 {
        println!(
            "  [5b/9] local-multi: no GPU/VRAM holds a usable (≥3B) local model — \
             staying single-provider. Add a GPU and re-run, or pick a cloud provider."
        );
        topology.mode = crate::config::inference::TopologyMode::Single;
        return Ok(());
    }
    // Operator chooses 1..=n_max local hemispheres (default = the max the
    // hardware supports): one local + cloud rest, or fully local.
    let count_labels: Vec<String> = (1..=n_max)
        .map(|n| {
            if n == 1 {
                "1 local hemisphere (biggest model; other 2 stay cloud)".to_string()
            } else if (n as usize) == ROLES.len() {
                format!("{n} local hemispheres (fully local, zero cloud)")
            } else {
                format!("{n} local hemispheres (rest stay cloud)")
            }
        })
        .collect();
    let pick = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("    how many hemispheres run a LOCAL abliterated model?")
        .items(&count_labels)
        .default((n_max - 1) as usize)
        .interact()
        .context("local count select")?;
    let n_local = (pick as u8) + 1;

    let preset = build_local_preset(
        vram_mib,
        n_local,
        VariantClass::Abliterated,
        DEFAULT_OLLAMA_PORT,
    );
    apply_local_abliterated_preset(topology, &preset);

    println!("  [5b/9] hemispheres (local-multi — abliterated Q4/Q8 via Ollama):");
    for l in &preset.locals {
        println!(
            "      {:<10}  {:>4.1}B {:<7} {}",
            l.role, l.param_b, l.quant_tag, l.repo
        );
    }
    if !preset.is_all_local() {
        println!("      (remaining hemispheres keep your cloud provider)");
    }
    if !preset.locals.is_empty() {
        println!(
            "      Each local hemisphere is wired to {} (no API key).",
            preset.endpoint
        );
        println!("      The next step offers to install Ollama + pull these models.");
    }
    Ok(())
}

/// GOLD-ADOPT-13 — collect the distinct Ollama-served local model refs the
/// applied topology points at (OpenAiCompat slots on the Ollama `/v1` endpoint
/// with an `hf.co/...` model). Pure + order-preserving + deduplicated, so the
/// provision step pulls each model exactly once.
pub(crate) fn collect_ollama_model_refs(
    topo: &crate::config::inference::InferenceTopology,
) -> Vec<String> {
    use crate::config::inference::InferenceProvider;
    let endpoint = crate::installers::ollama::openai_compat_endpoint(
        crate::installers::ollama::DEFAULT_OLLAMA_PORT,
    );
    let mut refs: Vec<String> = Vec::new();
    for slot in [&topo.left, &topo.right, &topo.cerebellum] {
        if slot.provider == Some(InferenceProvider::OpenAiCompat)
            && slot.endpoint.as_deref() == Some(endpoint.as_str())
        {
            if let Some(m) = slot.model.as_deref() {
                if m.starts_with("hf.co/") && !refs.iter().any(|r| r == m) {
                    refs.push(m.to_string());
                }
            }
        }
    }
    refs
}

/// Finding 6 (Session 13) — pick the default topology-select index for
/// the wizard's mode list (single=0, triplet=1, custom=2, local-only=3).
/// When the accelerator probe found anything other than CPU, the
/// privacy-positive `local-only` preset wins; otherwise `single`
/// remains the default because CPU Qwen is too slow for daily Council
/// mode.
pub(crate) fn topology_default_idx_for_probe(probe: &crate::daemon::accelerator::Probe) -> usize {
    if probe.picked != crate::daemon::accelerator::Accelerator::Cpu {
        3
    } else {
        0
    }
}

pub(crate) fn recommended_provider_for_role(
    role: &str,
) -> crate::config::inference::InferenceProvider {
    use crate::config::inference::InferenceProvider as I;
    match role {
        "left" => I::ClaudeCli,       // analytic / structured reasoning
        "right" => I::Gemini,         // creative / freeform
        "cerebellum" => I::LocalQwen, // fast pattern matching / routing
        _ => I::ClaudeCli,
    }
}

/// GOLD-ADOPT-12 — the LOCAL mirror of [`recommended_provider_for_role`]: which
/// LOCAL provider to recommend per hemisphere role for a fully-local brain. The
/// analytic LEFT role gets **`LocalOuro`** (ByteDance's looped LoopLM — explicit
/// multi-step reasoning, the local analog of the cloud default's `ClaudeCli`
/// on left); the creative RIGHT and fast CEREBELLUM roles get `LocalQwen`.
///
/// NOTE: a `left=Ouro` + `right/cerebellum=Qwen` split loads TWO local model
/// families, so the VRAM-shared [`apply_local_only_preset`] deliberately keeps a
/// single shared Qwen by default (noob-VRAM-safe). This Ouro-on-left
/// recommendation is applied only by the explicit `neoth hemispheres preset
/// local-reasoning`, where the operator opts into the extra VRAM cost knowingly.
pub(crate) fn recommended_local_provider_for_role(
    role: &str,
) -> crate::config::inference::InferenceProvider {
    use crate::config::inference::InferenceProvider as I;
    match role {
        "left" => I::LocalOuro,  // explicit-reasoning LoopLM for the analytic role
        "right" => I::LocalQwen, // creative / freeform
        "cerebellum" => I::LocalQwen, // fast routing
        _ => I::LocalQwen,
    }
}

/// Suggest a sensible default model per provider × role pair. Operators
/// editing in Custom mode want a starting point; they can override.
///
/// Bundled (hardcoded) defaults — kept as a safe baseline for fresh
/// installs / air-gapped setups / when the model catalog hasn't been
/// populated yet. The K-Models-Discovery catalog
/// (`~/.neoth/models_catalog.json`) overrides these when present —
/// see [`catalog_or_bundled_default_model_for`].
pub(crate) fn default_model_for(
    role: &str,
    provider: crate::config::inference::InferenceProvider,
) -> Option<&'static str> {
    use crate::config::inference::InferenceProvider as I;
    match (role, provider) {
        ("left", I::ClaudeCli) => Some("claude-opus-4-7"),
        ("left", I::AnthropicApi) => Some("claude-opus-4-7"),
        ("left", I::OpenAi) => Some("gpt-5.5"),
        ("right", I::Gemini) => Some("gemini-3.1-pro-preview"),
        ("right", I::ClaudeCli) => Some("claude-sonnet-4-6"),
        ("right", I::AnthropicApi) => Some("claude-sonnet-4-6"),
        ("cerebellum", I::LocalQwen) => Some("Qwen/Qwen2.5-3B-Instruct"),
        ("cerebellum", I::OpenAi) => Some("gpt-5.4-mini"),
        ("cerebellum", I::OpenAiCompat) => Some("qwen2.5-3b-instruct"),
        _ => None,
    }
}

/// Catalog-first default model lookup keyed by the wizard's
/// `ProviderKind` against an explicit catalog path. Production caller
/// uses [`catalog_recommended_for_provider_kind`] which resolves to
/// `~/.neoth/models_catalog.json`. Returns the provider's
/// `recommended_default()` when present, `None` otherwise.
pub(crate) fn catalog_recommended_for_provider_kind_at(
    catalog_path: &std::path::Path,
    kind: ProviderKind,
) -> Option<String> {
    use crate::models::catalog::ModelsCatalog;

    let key = kind.catalog_key()?;
    let catalog = ModelsCatalog::load_from(catalog_path);
    catalog
        .provider(key)
        .and_then(|pc| pc.recommended_default())
        .map(|m| m.id.clone())
}

/// Production wrapper for [`catalog_recommended_for_provider_kind_at`]
/// against the operator's actual `~/.neoth/models_catalog.json`.
pub(crate) fn catalog_recommended_for_provider_kind(kind: ProviderKind) -> Option<String> {
    use crate::config::FreedomConfig;
    use crate::models::catalog::ModelsCatalog;

    let home = FreedomConfig::default_neoth_home();
    let path = ModelsCatalog::default_path(&home);
    catalog_recommended_for_provider_kind_at(&path, kind)
}

/// Map an `InferenceProvider` to the catalog key used by
/// `crate::models::catalog`. Catalog keys mirror NEOTH's snake_case
/// `ProviderKind` strings (`anthropic_api`, `openai_api`, etc.).
pub(crate) fn catalog_key_for_provider(
    provider: crate::config::inference::InferenceProvider,
) -> Option<&'static str> {
    use crate::config::inference::InferenceProvider as I;
    Some(match provider {
        I::ClaudeCli | I::AnthropicApi => "anthropic_api",
        I::OpenAi => "openai_api",
        I::OpenAiCompat => "openai_compat",
        I::Gemini => "gemini_api",
        I::AwsBedrock => "aws_bedrock",
        // Local Qwen + AzureOpenAi + Cohere don't have a model-catalog
        // source today — fall through to bundled defaults.
        I::LocalQwen | I::LocalOuro | I::AzureOpenAi | I::Cohere => return None,
    })
}

/// Catalog-first default model resolution. Loads the discovery cache
/// at `~/.neoth/models_catalog.json` and returns the provider's
/// `recommended_default()` when present. Falls back to the
/// hardcoded bundled defaults from [`default_model_for`] when:
///   - the catalog file is missing (fresh install, no `neoth catalog
///     refresh` yet)
///   - the catalog has no entry for this provider (discovery skipped
///     it for cred reasons)
///   - the catalog has the entry but every model is deprecated
///
/// Pure helper — no network calls, no daemon dependencies. Wizard
/// runs this synchronously during step5 / step5b.
pub(crate) fn catalog_or_bundled_default_model_for(
    role: &str,
    provider: crate::config::inference::InferenceProvider,
) -> Option<String> {
    use crate::config::FreedomConfig;
    use crate::models::catalog::ModelsCatalog;

    if let Some(key) = catalog_key_for_provider(provider) {
        let home = FreedomConfig::default_neoth_home();
        let catalog_path = ModelsCatalog::default_path(&home);
        let catalog = ModelsCatalog::load_from(&catalog_path);
        if let Some(pc) = catalog.provider(key) {
            if let Some(recommended) = pc.recommended_default() {
                return Some(recommended.id.clone());
            }
        }
    }
    default_model_for(role, provider).map(String::from)
}

/// Custom-mode: prompt for the model identifier per hemisphere. Pre-fills
/// either the operator's step-5 default (if they want consistency) or the
/// `default_model_for(role, provider)` recommendation when the role-provider
/// pair has a known sensible default. Empty input → inherit from default_slot.
#[cfg(feature = "wizard")]
pub(crate) fn prompt_hemisphere_model(
    role: &str,
    provider: crate::config::inference::InferenceProvider,
    inherited_default: &Option<String>,
) -> Result<Option<String>> {
    // K-Models-Discovery (Session 14): try the cached catalog first;
    // fall back to the hardcoded bundled default. The catalog ALSO
    // surfaces a fuzzy-select option list when available so the
    // operator picks a real current model id with their up/down
    // arrows rather than typing one from memory.
    let suggestion: Option<String> =
        catalog_or_bundled_default_model_for(role, provider).or_else(|| inherited_default.clone());
    let catalog_choices = catalog_model_ids_for_provider(provider);

    let prompt = format!("      {role} model (empty → inherit default)");
    let theme = dialoguer::theme::ColorfulTheme::default();

    // Catalog has ≥2 entries → render a select with "type your own"
    // as the trailing option for full control.
    if catalog_choices.len() >= 2 {
        let mut items: Vec<String> = catalog_choices.to_vec();
        items.push("(type my own)".to_string());
        let default_idx = suggestion
            .as_ref()
            .and_then(|s| items.iter().position(|m| m == s))
            .unwrap_or(0);
        let selection = dialoguer::Select::with_theme(&theme)
            .with_prompt(&prompt)
            .items(&items)
            .default(default_idx)
            .interact()
            .context("hemisphere model select")?;
        if selection < items.len() - 1 {
            return Ok(Some(items[selection].clone()));
        }
        // "type my own" → fall through to free-text input below.
    }

    let mut input = dialoguer::Input::<String>::with_theme(&theme)
        .with_prompt(prompt)
        .allow_empty(true);
    if let Some(s) = suggestion.as_ref() {
        input = input.default(s.clone());
    }
    let raw = input.interact_text().context("hemisphere model input")?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(inherited_default.clone())
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

/// Catalog lookup: every non-deprecated model id the operator's
/// `~/.neoth/models_catalog.json` lists for `provider`. Empty `Vec`
/// when the catalog has no entry / no fresh entries. Pure helper —
/// no network calls.
pub(crate) fn catalog_model_ids_for_provider(
    provider: crate::config::inference::InferenceProvider,
) -> Vec<String> {
    use crate::config::FreedomConfig;
    use crate::models::catalog::ModelsCatalog;

    let Some(key) = catalog_key_for_provider(provider) else {
        return Vec::new();
    };
    let home = FreedomConfig::default_neoth_home();
    let catalog_path = ModelsCatalog::default_path(&home);
    let catalog = ModelsCatalog::load_from(&catalog_path);
    catalog
        .provider(key)
        .map(|pc| {
            pc.models
                .iter()
                .filter(|m| !m.deprecated)
                .map(|m| m.id.clone())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(not(feature = "wizard"))]
pub(crate) fn prompt_hemisphere_model(
    _role: &str,
    _provider: crate::config::inference::InferenceProvider,
    inherited_default: &Option<String>,
) -> Result<Option<String>> {
    Ok(inherited_default.clone())
}

/// Parse the `--inference-mode` flag. None → Single.
pub(crate) fn parse_topology_mode_arg(
    arg: Option<&str>,
) -> Result<crate::config::inference::TopologyMode> {
    use crate::config::inference::TopologyMode;
    match arg {
        None => Ok(TopologyMode::Single),
        Some(s) => TopologyMode::from_str(s).ok_or_else(|| {
            anyhow::anyhow!("invalid --inference-mode '{s}'. Expected: single | triplet | custom")
        }),
    }
}

/// K-4b (Session 21, 2026-05-23) — operator-facing Telegram prompt text.
/// Defaults depend on whether `pear` is on PATH: when present, Keet is
/// the recommended primary so Telegram is framed as the FALLBACK and
/// the wizard defaults to No more strongly; without pear, Telegram is
/// the only operator-private option so the prompt stays neutral.
///
/// Pure-fn so the K-4b restructure can be unit-tested without a TTY.
pub(crate) fn k4b_telegram_prompt_text(pear_present: bool) -> &'static str {
    if pear_present {
        "[6/9] Set up Telegram as a FALLBACK channel? (Keet is preferred primary; default: no)"
    } else {
        "[6/9] Set up a Telegram bot now? (optional, can add later)"
    }
}

/// True when the configured inference topology touches LocalQwen
/// anywhere — default slot, a hemisphere override, or the embedding
/// provider. Sole call site is `step5c_qwen_weights`'s skip-check.
pub(crate) fn inference_uses_local_qwen(
    topology: &crate::config::inference::InferenceTopology,
    provider_kind: &Option<ProviderKind>,
) -> bool {
    use crate::config::inference::InferenceProvider;

    if matches!(provider_kind, Some(ProviderKind::LocalQwen)) {
        return true;
    }
    if matches!(
        topology.default_slot.provider,
        Some(InferenceProvider::LocalQwen)
    ) {
        return true;
    }
    if matches!(
        topology.embedding_provider,
        Some(InferenceProvider::LocalQwen)
    ) {
        return true;
    }
    let hemis = [&topology.cerebellum, &topology.left, &topology.right];
    hemis
        .iter()
        .any(|slot| matches!(slot.provider, Some(InferenceProvider::LocalQwen)))
}
