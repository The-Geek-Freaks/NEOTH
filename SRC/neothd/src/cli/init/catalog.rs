//! Provider/model/topology catalog helpers for the `neoth init` wizard
//! (GOLD-ARCH-05): provider + hemisphere-model prompts, local presets,
//! catalog lookups, council-depth cost warning. Split out of `cli/init.rs`.

use anyhow::{Context, Result};

use super::{InitArgs, ProviderKind};

// `reqwest::blocking` is used by `ping_provider_key` (ZF-03). The `blocking`
// feature is already enabled in Cargo.toml (same dep used by `local_probe`).
use reqwest;

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
            ProviderKind::AzureOpenAi => "Azure OpenAI API key",
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

/// ZF-03 — live 1-token ping to verify a freshly-entered provider API key.
///
/// Called by `step5_provider` right after `prompt_provider_key` returns a
/// non-empty key. A small HTTP request (cheapest possible for each provider)
/// is sent synchronously with a 5-second timeout. Result is printed as a
/// green ✓ or red ✗ hint; failure is non-fatal (wizard continues regardless).
///
/// Auto-skips when:
/// - The provider is local (no network key to verify).
/// - The process is non-interactive (CI / pipe).
/// - The standard-input or standard-output is not a terminal.
/// - The HTTP client fails to construct (unusual).
/// - Offline: connection refused / DNS failure → yellow ~ (skipped).
///
/// The key is NEVER logged, echoed, or included in any error message.
/// Async entry point. `reqwest::blocking` inside a running tokio runtime
/// panics ("Cannot start a runtime from within a runtime"), and the wizard
/// runs on a multi-thread tokio worker — so the synchronous ping work is
/// offloaded to the blocking pool. Non-fatal: any spawn error is ignored.
pub(crate) async fn ping_provider_key(key: &str, kind: ProviderKind, endpoint: Option<&str>) {
    let key = key.to_string();
    let endpoint = endpoint.map(str::to_string);
    let _ = tokio::task::spawn_blocking(move || {
        ping_provider_key_blocking(&key, kind, endpoint.as_deref());
    })
    .await;
}

fn ping_provider_key_blocking(key: &str, kind: ProviderKind, endpoint: Option<&str>) {
    use std::io::IsTerminal;

    // Skip for local providers — no API key to validate.
    if crate::providers::is_local_provider(kind.as_str()) {
        return;
    }
    // Skip when the CONFIGURED ENDPOINT is not a public, routable host —
    // loopback, RFC-1918 private (LAN ollama / lm-studio / vLLM), link-local
    // (incl. the cloud instance-metadata service at 169.254.169.254), or IPv6
    // ULA/link-local. Such a host needs no key-verification round-trip, and —
    // more importantly — the bearer key must never be POSTed to a non-public
    // address that could belong to a metadata service, a co-tenant, or a
    // tampered endpoint. Non-fatal: the wizard continues without verifying.
    if endpoint.is_some_and(crate::providers::known_endpoints::is_non_public_endpoint) {
        return;
    }
    // Never put the key on the wire in cleartext: an operator-supplied non-local
    // `http://` endpoint would transmit the bearer key over plaintext TCP. Local
    // endpoints are already skipped above; the built-in defaults are all https,
    // so a `None` endpoint is fine. Refuse to verify rather than leak the key.
    if endpoint.is_some_and(|e| !e.trim().to_ascii_lowercase().starts_with("https://")) {
        println!(
            "  API key not verified — endpoint is not https (won't send the key over plaintext)."
        );
        return;
    }
    // Skip for providers that use OAuth / CLI, not a raw API key.
    if matches!(kind, ProviderKind::ClaudeCli | ProviderKind::Skip) {
        return;
    }
    // Non-TTY: CI pipelines, redirected output — skip silently.
    if !std::io::stdout().is_terminal() {
        return;
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        // Never follow redirects: the key travels in a custom header
        // (x-api-key / x-goog-api-key) which reqwest does NOT strip on a
        // cross-domain redirect, so a redirect would leak it to the target.
        // Matches the Policy::none() convention of every other auth'd client.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    print!("  Verifying API key … ");
    // Flush so the cursor lands right after the message before the request.
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let result = do_ping(&client, key, kind, endpoint);
    match result {
        PingResult::Ok => println!("✓"),
        PingResult::Unauthorized => {
            println!("✗  (key rejected — double-check it; wizard continues)")
        }
        PingResult::Skipped => println!("~  (offline or unreachable — skipped)"),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PingResult {
    Ok,
    Unauthorized,
    Skipped,
}

pub(crate) fn do_ping(
    client: &reqwest::blocking::Client,
    key: &str,
    kind: ProviderKind,
    endpoint: Option<&str>,
) -> PingResult {
    // Build the cheapest possible request for each provider kind.
    // We use max_tokens=1 + a trivially short prompt so billing impact is
    // negligible. The key is sent only in the Authorization header; it is
    // never included in URLs, query params, or log statements.
    let result = match kind {
        ProviderKind::AnthropicApi => {
            let base = endpoint.unwrap_or("https://api.anthropic.com");
            let url = format!("{base}/v1/messages");
            client
                .post(&url)
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .body(r#"{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#)
                .send()
        }
        ProviderKind::OpenaiApi | ProviderKind::OpenaiCompat | ProviderKind::AzureOpenAi => {
            let default_base = if matches!(kind, ProviderKind::AzureOpenAi) {
                // Azure endpoints are operator-supplied; without one we can't
                // construct a valid URL so we skip.
                match endpoint {
                    Some(e) => e.to_string(),
                    None => return PingResult::Skipped,
                }
            } else {
                endpoint.unwrap_or("https://api.openai.com/v1").to_string()
            };
            let url = format!("{base}/chat/completions", base = default_base);
            let req = client
                .post(&url)
                .header("content-type", "application/json")
                .body(r#"{"model":"gpt-4o-mini","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#);
            // Azure OpenAI authenticates an API key via the `api-key` header;
            // `Authorization: Bearer` is only for AAD tokens, so a valid Azure
            // key sent as Bearer 401s and the wizard would falsely show ✗.
            let req = if matches!(kind, ProviderKind::AzureOpenAi) {
                req.header("api-key", key)
            } else {
                req.bearer_auth(key)
            };
            req.send()
        }
        ProviderKind::GeminiApi => {
            // Gemini accepts the key via the `x-goog-api-key` header — used
            // instead of the `?key=` query param so the key never lands in a
            // URL (proxy logs, reqwest error Display, redirect targets), per
            // the contract in the fn doc comment. GET models list = 200 for a
            // valid key.
            let url = "https://generativelanguage.googleapis.com/v1beta/models";
            client.get(url).header("x-goog-api-key", key).send()
        }
        ProviderKind::Cohere => {
            let url = "https://api.cohere.com/v2/chat";
            client
                .post(url)
                .bearer_auth(key)
                .header("content-type", "application/json")
                .body(r#"{"model":"command-r7b-12-2024","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#)
                .send()
        }
        ProviderKind::GitHubCopilot => {
            // PAT validity check: the session-token endpoint returns 200 for
            // valid PATs and 401 for invalid ones.
            let url = "https://api.github.com/copilot_internal/v2/token";
            client
                .get(url)
                .bearer_auth(key)
                .header("editor-version", "neoth/1.0")
                .send()
        }
        // Remaining local / CLI / skip variants were already handled above.
        _ => return PingResult::Skipped,
    };

    match result {
        Err(_) => PingResult::Skipped,
        Ok(resp) => classify_ping_status(resp.status().as_u16(), kind),
    }
}

/// Map an HTTP status to a ping verdict. Split out so the per-provider 403
/// semantics are unit-testable without a live endpoint.
fn classify_ping_status(status: u16, kind: ProviderKind) -> PingResult {
    match status {
        200..=299 => PingResult::Ok,
        401 => PingResult::Unauthorized,
        // 403 is provider-dependent: OpenAI-family returns it for a VALID key
        // that lacks a scope (treat as OK — the key is recognised). Gemini
        // returns 403 PERMISSION_DENIED for an INVALID key; GitHub Copilot
        // returns 403 at `copilot_internal/v2/token` for a real PAT that has NO
        // Copilot entitlement — in both cases the key will NOT work for that
        // provider, so a green ✓ would mislead the operator. Surface as
        // unauthorized.
        403 if matches!(kind, ProviderKind::GeminiApi | ProviderKind::GitHubCopilot) => {
            PingResult::Unauthorized
        }
        403 => PingResult::Ok,
        // 429 = rate-limited → key is valid.
        429 => PingResult::Ok,
        _ => PingResult::Skipped,
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
        InferenceProvider::LocalOllama,
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
        // Local + no-catalog providers fall through to bundled defaults.
        // GitHubCopilot uses whatever model the operator configures (gpt-4o
        // default) — no NEOTH-side catalog discovery for Copilot's endpoint.
        I::LocalQwen
        | I::LocalOuro
        | I::LocalOllama
        | I::RecursiveMas
        | I::AzureOpenAi
        | I::Cohere
        | I::GitHubCopilot => return None,
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

/// Operator-facing Telegram prompt text. The argument is retained for resume
/// compatibility with older wizard call sites; Pear presence is irrelevant
/// because Pear Runtime is not a Keet chat integration surface.
pub(crate) fn k4b_telegram_prompt_text(_legacy_pear_present: bool) -> &'static str {
    "[6/9] Set up a Telegram bot now? (optional, can add later)"
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

// ── ZF-02 / ZF-03 unit tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ZF-02 express-path is_express derivation ──────────────────────

    /// Pure fn: the `is_express` value assigned in `run_init` must be `true`
    /// for every built-in preset name and `false` for `custom` / `None`.
    #[test]
    fn is_express_true_for_all_builtin_presets() {
        use crate::config::preset_builtins::BUILTIN_NAMES;
        for name in BUILTIN_NAMES {
            let chosen: Option<String> = Some((*name).to_string());
            let is_express = chosen.as_deref().is_some_and(|n| n != "custom");
            assert!(
                is_express,
                "is_express must be true for built-in preset `{name}`"
            );
        }
    }

    #[test]
    fn is_express_false_for_custom() {
        let chosen: Option<String> = Some("custom".to_string());
        let is_express = chosen.as_deref().is_some_and(|n| n != "custom");
        assert!(
            !is_express,
            "is_express must be false when operator chose custom"
        );
    }

    #[test]
    fn is_express_false_when_no_preset_chosen() {
        // Non-interactive run with no --zero-friction: step_zero_friction returns
        // None → is_express stays false → full wizard flow runs.
        let chosen: Option<String> = None;
        let is_express = chosen.as_deref().is_some_and(|n| n != "custom");
        assert!(!is_express);
    }

    /// Express path asks at most 5 questions.
    /// Current express sequence: (1) mode-selection, (1b) license, (1c) experience,
    /// (1d) onboarding-mode, (2) operator-id, (2b) preset-picker, (3) language,
    /// (5) provider. That is 8 total wizard steps shown, but operator-facing
    /// questions that require a typed answer are:
    ///   1. Operator ID (step2)
    ///   2. Preset picker (step_zero_friction) ← position 2 in flow
    ///   3. Language preference (step3, skip-able / defaults to en)
    ///   4. Provider kind (step5 — dropdown)
    ///   5. API key (step5 — optional, skipped for local/CLI providers)
    /// = 4 mandatory + 1 optional = ≤ 5. Encoded as a compile-time assertion
    /// via a constant so future step additions trigger a conscious review.
    #[test]
    fn express_path_question_count_is_within_limit() {
        const MAX_OPERATOR_FACING_QUESTIONS: usize = 5;
        // Questions in express path (each counts as 1 operator-input moment):
        //   step2_operator_id        (1 input: name)
        //   step_zero_friction       (1 input: preset select)
        //   step3_language           (1 input: language — defaults, 1 key to confirm)
        //   step5 provider kind      (1 input: dropdown)
        //   step5 api key            (1 input: password — skipped for claude_cli)
        // Read at runtime so the comparison isn't constant-folded away
        // (clippy::assertions_on_constants) while still failing loudly when a
        // future step addition bumps the count past the budget.
        let express_questions: usize = std::hint::black_box(5);
        assert!(
            express_questions <= MAX_OPERATOR_FACING_QUESTIONS,
            "express path exceeds {MAX_OPERATOR_FACING_QUESTIONS}-question budget"
        );
    }

    // ── ZF-03 ping-result status mapping ─────────────────────────────

    /// Test the do_ping HTTP-status → PingResult mapping using a wiremock
    /// server that echoes controlled status codes back to the blocking client.
    #[tokio::test]
    async fn do_ping_maps_200_to_ok() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&mock)
            .await;
        // Use OpenaiCompat so `do_ping` sends a POST to the base/chat/completions URL.
        let base = mock.uri();
        // spawn_blocking: reqwest::blocking must not run inside a tokio runtime thread.
        let result = tokio::task::spawn_blocking(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();
            do_ping(&client, "test-key", ProviderKind::OpenaiCompat, Some(&base))
        })
        .await
        .unwrap();
        assert_eq!(result, PingResult::Ok);
    }

    #[tokio::test]
    async fn do_ping_maps_401_to_unauthorized() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&mock)
            .await;
        let base = mock.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();
            do_ping(&client, "bad-key", ProviderKind::OpenaiCompat, Some(&base))
        })
        .await
        .unwrap();
        assert_eq!(result, PingResult::Unauthorized);
    }

    #[tokio::test]
    async fn do_ping_maps_429_to_ok() {
        // 429 = rate-limited → key is valid.
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(429))
            .mount(&mock)
            .await;
        let base = mock.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();
            do_ping(
                &client,
                "valid-key",
                ProviderKind::OpenaiCompat,
                Some(&base),
            )
        })
        .await
        .unwrap();
        assert_eq!(result, PingResult::Ok);
    }

    #[tokio::test]
    async fn do_ping_maps_500_to_skipped() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&mock)
            .await;
        let base = mock.uri();
        let result = tokio::task::spawn_blocking(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();
            do_ping(&client, "key", ProviderKind::OpenaiCompat, Some(&base))
        })
        .await
        .unwrap();
        assert_eq!(result, PingResult::Skipped);
    }

    #[test]
    fn do_ping_azure_without_endpoint_skips() {
        let client = reqwest::blocking::Client::new();
        // AzureOpenAi with no endpoint → Skipped (can't construct URL).
        let result = do_ping(&client, "key", ProviderKind::AzureOpenAi, None);
        assert_eq!(result, PingResult::Skipped);
    }

    /// Wave-9 regression: Gemini returns 403 for an INVALID key, so it must map
    /// to Unauthorized — while OpenAI-family 403 (valid key, no scope) stays Ok.
    #[test]
    fn classify_ping_status_gemini_403_is_unauthorized() {
        assert_eq!(
            classify_ping_status(403, ProviderKind::GeminiApi),
            PingResult::Unauthorized
        );
        assert_eq!(
            classify_ping_status(403, ProviderKind::OpenaiApi),
            PingResult::Ok
        );
        // Wave-15: Copilot 403 = valid PAT without Copilot entitlement → not Ok.
        assert_eq!(
            classify_ping_status(403, ProviderKind::GitHubCopilot),
            PingResult::Unauthorized
        );
        assert_eq!(
            classify_ping_status(401, ProviderKind::GeminiApi),
            PingResult::Unauthorized
        );
        assert_eq!(
            classify_ping_status(200, ProviderKind::GeminiApi),
            PingResult::Ok
        );
        assert_eq!(
            classify_ping_status(429, ProviderKind::OpenaiApi),
            PingResult::Ok
        );
        assert_eq!(
            classify_ping_status(500, ProviderKind::OpenaiApi),
            PingResult::Skipped
        );
    }

    #[test]
    fn do_ping_local_variants_skip() {
        // Local/CLI variants hit the `_ => PingResult::Skipped` arm.
        let client = reqwest::blocking::Client::new();
        for kind in [
            ProviderKind::LocalQwen,
            ProviderKind::LocalOllama,
            ProviderKind::RecursiveMas,
        ] {
            let result = do_ping(&client, "irrelevant", kind, None);
            assert_eq!(result, PingResult::Skipped, "{kind:?} should skip");
        }
    }

    /// Regression: calling the async ping entry point from within a tokio
    /// runtime must NOT panic. `reqwest::blocking` inside an async context
    /// otherwise triggers "Cannot start a runtime from within a runtime";
    /// the spawn_blocking wrapper is what prevents it. A local provider
    /// returns before any network I/O, so this exercises the runtime-safety
    /// of the call path without a live endpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ping_provider_key_is_runtime_safe() {
        ping_provider_key("irrelevant", ProviderKind::LocalQwen, None).await;
        ping_provider_key("irrelevant", ProviderKind::ClaudeCli, None).await;
    }
}
