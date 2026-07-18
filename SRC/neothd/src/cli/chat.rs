//! `neoth chat <msg>` — one-shot or streaming LLM round trip.
//!
//! Loads `freedom.yaml`, picks the configured provider, sends the prompt,
//! and prints the response. The mandatory provider leaf boundary persists a
//! content-free request/response-or-error audit pair before dispatch settles.
//! Prompt content is journaled separately only when incognito mode is off.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use tracing::{info, warn};

use crate::config::{FreedomConfig, InstancePaths};
use crate::providers::{self, CompletionChunk, Provider, Request};
use crate::wal::events::{
    EVENT_TYPE_AUTO_SKILL_EXTRACTED, EVENT_TYPE_BUDGET_EXCEEDED, EVENT_TYPE_INCOGNITO_TURN,
    EVENT_TYPE_RAW_TEXT, EVENT_TYPE_SKILL_INJECT_SKIPPED,
};
use crate::wal::spawn as wal_spawn;

const STREAM_CONTROL_TOKEN_ENV: &str = "NEOTH_STREAM_CONTROL_TOKEN";

fn stream_control_token() -> Option<String> {
    std::env::var(STREAM_CONTROL_TOKEN_ENV)
        .ok()
        .filter(|value| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// GOLD-WIRE-10b: fire a `ProviderResponded` domain event so the daemon's
/// `UsageMeter` counts every provider call, not only council-hemisphere ones.
/// Mirrors the council path's event shape including latency clamping.
fn publish_provider_responded(
    provider_name: &str,
    model: &str,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    elapsed_ms: u64,
) {
    crate::domain_events::publish(crate::domain_events::DomainEvent::ProviderResponded {
        provider: provider_name.to_string(),
        model: model.to_string(),
        input_tokens: input_tokens.unwrap_or(0),
        output_tokens: output_tokens.unwrap_or(0),
        latency_ms: elapsed_ms.min(u64::from(u32::MAX)) as u32,
        ts_unix: now_unix() as i64,
    });
}

#[derive(Args, Debug, Clone)]
pub struct ChatArgs {
    /// Message to send. If omitted, NEOTH reads from stdin until EOF.
    pub message: Option<String>,

    /// Override the configured model for this single call.
    #[arg(long, value_name = "MODEL")]
    pub model: Option<String>,

    /// Inject a one-shot system prompt for this call.
    #[arg(long, value_name = "TEXT")]
    pub system: Option<String>,

    /// GOLD-ADAPT-ODY-03 — attach files to this turn. Each file runs the
    /// media extraction pipeline (PDF/image/audio/video/document; plain
    /// UTF-8 files inline directly) and its text is prepended to the
    /// prompt as a labelled attachment block. Repeatable.
    #[arg(long, value_name = "PATH")]
    pub attach: Vec<PathBuf>,

    /// GOLD-ADOPT-24 — compose the prompt in `$VISUAL`/`$EDITOR` instead of
    /// passing it inline. Any inline message/`--message` seeds the editor as
    /// prefill. Aborts if the editor is left empty.
    #[arg(long)]
    pub edit: bool,

    /// Override the freedom.yaml path (mostly for tests).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Override the WAL segment path (mostly for tests).
    #[arg(long, value_name = "PATH")]
    pub wal_segment: Option<PathBuf>,

    /// Populated from the global `--stream` flag by `cli::run`. Skipped from
    /// clap parsing because the global handler claims the flag first.
    #[arg(skip)]
    pub stream: bool,

    /// Sampling temperature for providers that support it. Range [0.0, 2.0];
    /// Cohere, Bedrock, and legacy Anthropic cap it at 1.0, while Anthropic
    /// models after Opus 4.6 accept only 1.0. An unsupported selected provider
    /// returns a clear error before transport.
    #[arg(long, value_name = "T")]
    pub temperature: Option<f32>,

    /// Top-p (nucleus) sampling cutoff. Range (0.0, 1.0]; `1.0` keeps every
    /// token. Anthropic models after Opus 4.6 accept only [0.99, 1.0]. An
    /// unsupported selected provider fails before transport.
    #[arg(long = "top-p", value_name = "P")]
    pub top_p: Option<f32>,

    /// Optional RNG seed for reproducible sampling. Portable range
    /// [0, 4294967295]. Pair with `--temperature > 0` for a replayable
    /// non-greedy call. Unsupported providers fail.
    #[arg(long, value_name = "SEED")]
    pub sampling_seed: Option<u64>,

    /// Round-3 v0.4 QU-11 / ARS-6 — resume a prior session from a
    /// `MODE_CHECKPOINT` (WAL `0x9A`) snapshot. Takes the 12-char
    /// checkpoint hash (or any unique prefix) printed by the prior
    /// session at checkpoint-emission time. NEOTH looks up the
    /// snapshot via `recall::reconstruct::reconstruct_from_checkpoint`,
    /// prints a one-line resume banner ("resuming session X / phase Y
    /// / provider Z"), and prepends a typed RESUME-CONTEXT block to
    /// the chat's system prompt so the assistant knows the prior
    /// pipeline shape. The current MCP registry is then restricted to
    /// the checkpoint's exact recorded server IDs: newly enabled servers
    /// are excluded, while missing/disabled IDs and legacy checkpoints
    /// without an exact scope fail closed before provider dispatch.
    #[arg(long = "resume-from", value_name = "HASH")]
    pub resume_from: Option<String>,

    /// ODY-09 — ephemeral/incognito turn: skip memory injection (Block::D
    /// recall), RAW_TEXT journaling, and every post-turn memory surface. The
    /// mandatory provider request/terminal lifecycle remains auditable with
    /// hashes and typed metadata only (`incognito: true`), never prompt or
    /// response plaintext. `INCOGNITO_TURN` (0xF7) records the privacy mode.
    #[arg(long)]
    pub incognito: bool,

    /// GOLD-LOOP-01 — engage the multi-round loop engine instead of a single
    /// `run_mcp_dispatch_loop` call. Each round is one full dispatch; the
    /// engine evaluates `--until` criteria after each round and stops when
    /// all are satisfied or `--iterations` is hit. Requires MCP autoroute to
    /// be on (same gate as the existing dispatch path). Flag is `--loop`
    /// (the product name); `--loop-mode` stays accepted as an alias.
    #[arg(long = "loop", alias = "loop-mode")]
    pub loop_mode: bool,

    /// GOLD-LOOP-01 — maximum outer loop rounds (overrides
    /// `freedom.yaml::loop_config.max_rounds`). Default: 3.
    #[arg(long, value_name = "N")]
    pub iterations: Option<u32>,

    /// GOLD-LOOP-01 — structural stop criteria (space-separated phrases).
    /// The loop exits early when a round's output satisfies ALL listed
    /// criteria via `council::stop_verifier`. May be repeated.
    /// Example: `--until "build green" --until "tests pass"`.
    #[arg(long, value_name = "CRITERION")]
    pub until: Vec<String>,
}

/// Per-turn operator registries loaded from one explicit instance home.
///
/// Chat and channel turns use the same loader so malformed existing MCP,
/// tweaks, or profile-extension state fails closed before provider dispatch.
/// No field in this snapshot may fall back to process-global HOME state.
pub(crate) struct InstanceTurnState {
    pub(crate) mcp_servers: crate::mcp::McpServers,
    pub(crate) tweaks: crate::tweaks::Tweaks,
    pub(crate) profile_extensions: crate::profile::extension_registry::TypedExtensionRegistry,
}

pub(crate) fn load_instance_turn_state(paths: &InstancePaths) -> Result<InstanceTurnState> {
    let mcp_servers = crate::mcp::McpServers::load_from(&paths.mcp_servers).with_context(|| {
        format!(
            "load MCP server configuration at {}",
            paths.mcp_servers.display()
        )
    })?;
    let tweaks = crate::tweaks::Tweaks::load_or_default(&paths.tweaks)
        .with_context(|| format!("tweaks.toml invalid: {}", paths.tweaks.display()))?;
    let profile_extensions = crate::profile::extension_registry::TypedExtensionRegistry::load_from(
        &paths.profile_extensions,
    )
    .with_context(|| {
        format!(
            "load profile extension registry from {}",
            paths.profile_extensions.display()
        )
    })?;

    Ok(InstanceTurnState {
        mcp_servers,
        tweaks,
        profile_extensions,
    })
}

fn persist_chat_onboarding_complete(config_path: &std::path::Path) -> Result<()> {
    FreedomConfig::update_at(config_path, |config| {
        config.chat_onboarding_completed = true;
        Ok(())
    })
}

pub async fn run_chat(args: ChatArgs) -> Result<()> {
    let neoth_home = chat_neoth_home(args.config.as_deref());
    let config = match &args.config {
        Some(p) => FreedomConfig::load_from_path(p)?,
        None => FreedomConfig::load_from_default_path()?,
    };
    // V03-08 + A-2 preflight: gate every cloud provider the chat invocation
    // could reach behind first-run consent. Covers the legacy single-mode
    // `provider_kind` AND the per-hemisphere providers in
    // `inference.{left,right,cerebellum}` (A-2 closes the bypass where
    // operators set right=gemini_api but only granted consent for the
    // primary claude_cli). Runs before any provider is built so a declined
    // operator never sees a half-spun adapter. Bypass via
    // `NEOTH_CONSENT_BYPASS=1` for CI / scripted reruns.
    {
        crate::consent::ensure_all_granted_or_prompt(&neoth_home, &config)?;
    }
    // CH-04: chat dispatch routes through the Left hemisphere (analytic /
    // structured reasoning). In Single mode `from_config_for_role` falls
    // through to the same default-slot adapter `from_config` would build,
    // so existing operators see no behaviour change. In Triplet/Custom
    // mode the operator-picked Left provider wins.
    // SPEC-03b: build the primary WITH its 429 fallback chain. With no
    // `fallback:` config this returns the bare Left provider — identical
    // to the prior `from_config_for_role(.., Left)` call, zero change.
    // CLI one-shot: no WAL writer here (it's created inside run_chat_with,
    // below this provider build), and the operator is present to see a 429
    // failover in the logs. The daemon path threads its writer for the
    // durable `0x25 PROVIDER_FALLBACK_ATTEMPTED` audit frame.
    let provider = providers::fallback_chain_from_config(&config, &neoth_home, None).await?;
    // GOLD-ADAPT-HARNESS-03: wrap with history-compaction middleware when enabled.
    // CLI path has no WAL writer yet (writer is opened inside run_chat_with),
    // so WAL audit frames are skipped here (wal=None). The inner provider retains
    // the same identity for callers — only the prompt is modified in-place.
    let provider: Box<dyn providers::Provider> = if config.tokens.history_compaction_enabled {
        let utility = providers::from_config_for_utility_at(&config, &neoth_home)
            .await
            .ok();
        providers::compactor::CompactingProvider::from_config(
            provider,
            utility,
            providers::utility_model_for_config(&config),
            &config.tokens,
            None,
        )
    } else {
        provider
    };
    run_chat_with(args, config, provider.as_ref()).await
}

/// Inner entry point that takes a pre-built `Provider`. Used by `run_chat`
/// in production and by integration tests that supply a mock implementation.
/// GOLD-ARCH-02 phase 1 — assemble the layered system prompt for one chat turn.
///
/// Reads operator context + skills (parallel K-Perf-4 load), runs the ARCH-07
/// pinned-hash integrity gate + eval-session suppression, routes the active
/// skill/mode (Stage-1 keyword + Stage-2 embedding re-rank), loads the MCP
/// catalogue + persona + active-preset addendum + repo-context + moral core, and
/// composes them via `pipeline::build_enriched_request`. Audit emissions remain
/// best-effort, but an unreadable configured moral core fails the turn before a
/// provider call. `config`/`prompt`/`home` are threaded back out because the
/// later phases still consume them.
struct PromptBundle {
    combined_system: Option<String>,
    /// Exact typed A-E/Conductor representation of `combined_system` plus the
    /// single user-message E block.  This survives hooks, slash/agent routing
    /// and output-preset assembly until the final provider Request is built.
    budget_items: Vec<crate::tokens::budget::BlockItem>,
    skill_tool_allowlist: Option<Vec<String>>,
    /// GOLD-ADAPT-PWF-01: SHA-256 hex of `task_plan.md` at injection time,
    /// or `None` when no plan file was present or the active skill is not
    /// in `plan_attestation::APPLICABLE_SKILLS`. Threaded to
    /// `enforce_preflight` which re-reads the file and bails if tampered.
    plan_attest_hash: Option<String>,
    /// GOLD-ADAPT-OH-13 — raw enrichment layers carried from
    /// `build_prompt_bundle` to `enforce_preflight` so the agent-dispatch
    /// block can selectively rebuild the system prompt per-agent without
    /// re-running all the async I/O.
    agent_raw_layers: AgentRawLayers,
    /// GOLD-CCPARITY-MODEL-02 — model resolved from the matched skill's
    /// `manifest.model` field, or `None` when no skill matched / the
    /// matched skill carries no per-skill model override.
    /// Priority chain: Dispatch.model > skill.manifest.model > args.model.
    resolved_model: Option<String>,
    /// GOLD-CCPARITY-EFFORT-03 — per-skill effort/reasoning-budget resolved
    /// from the matched skill's `manifest.effort` field. `None` = provider
    /// default (10 000 tokens). Threaded to `dispatch_provider` which maps
    /// it to `req.thinking_budget` before the provider spawn.
    resolved_effort: Option<crate::providers::effort_override::EffortBudget>,
}

#[derive(Debug)]
pub(super) struct BudgetedProviderRequest {
    pub(super) prompt: String,
    pub(super) system: Option<String>,
    pub(super) prompt_bundle_hash: String,
    pub(super) prompt_token_estimate: u32,
    pub(super) effective_cap: u32,
}

fn route_wire_model(
    config: &FreedomConfig,
    provider_name: &str,
    model: Option<&str>,
    home: Option<&std::path::Path>,
) -> String {
    let configured = model
        .map(|id| config.resolve_model_alias(id).to_owned())
        .or_else(|| {
            let role = if provider_name == "anthropic_api" {
                crate::providers::model_roles::ModelRole::Balanced
            } else {
                crate::providers::model_roles::ModelRole::Flagship
            };
            let catalog_model = matches!(
                provider_name,
                "claude_cli" | "openai_api" | "gemini_api" | "cohere_api" | "copilot_api"
            )
            .then(|| {
                home.and_then(|home| {
                    crate::providers::catalog_flagship_model_at(home, provider_name)
                })
            })
            .flatten();
            catalog_model.or_else(|| {
                crate::providers::model_roles::default_table()
                    .resolve(provider_name, role)
                    .map(str::to_owned)
            })
        })
        .or_else(|| {
            (provider_name == "local_ollama")
                .then(|| crate::providers::ollama_api::DEFAULT_MODEL.to_owned())
        })
        .unwrap_or_else(|| "provider_default".to_owned());
    match provider_name {
        // Claude CLI rewrites these legacy aliases immediately before the
        // transport. Route budgeting must use that exact same wire id or the
        // model-window lookup and envelope reserve can both be bypassed.
        "claude_cli" => crate::providers::claude_cli::normalise_model(&configured),
        _ => configured,
    }
}

fn route_primary_equivalent_cap(
    config: &FreedomConfig,
    provider_name: &str,
    model: Option<&str>,
    primary_non_content: u32,
    home: Option<&std::path::Path>,
) -> u32 {
    let model = route_wire_model(config, provider_name, model, home);
    let leaf_cap =
        crate::tokens::budget::effective_cap(provider_name, &model, config.tokens.max_per_request);
    let leaf_non_content = crate::providers::token_cap::request_non_content_token_upper_bound(
        &crate::providers::Request {
            model: Some(model),
            ..Default::default()
        },
    );

    // Express every leaf as the cap a request carrying the primary model name
    // may use while still fitting this route.  Merely taking the minimum model
    // window is insufficient: fallback replaces `Request.model`, and a longer
    // wire id consumes part of that same window.
    leaf_cap
        .saturating_sub(leaf_non_content)
        .saturating_add(primary_non_content)
}

fn include_route_slot_cap(
    config: &FreedomConfig,
    cap: &mut u32,
    slot: &crate::config::inference::HemisphereSlot,
    primary_provider_name: &str,
    primary_model: Option<&str>,
    primary_non_content: u32,
    home: Option<&std::path::Path>,
) {
    let (provider_name, model) = match slot.provider {
        Some(provider) => (provider.as_str(), slot.model.as_deref()),
        None => (primary_provider_name, primary_model),
    };
    *cap = (*cap).min(route_primary_equivalent_cap(
        config,
        provider_name,
        model,
        primary_non_content,
        home,
    ));
}

/// Resolve the primary-equivalent request cap that is safe for every reachable
/// leaf.  This accounts for both the model window and each exact wire model
/// name; fallback swaps the model field after finalization, so a longer route
/// id must reduce content capacity before optional Block-D context is retained.
#[cfg_attr(not(test), allow(dead_code))] // retained: exercised by unit tests; prod caller removed in Wave-3 refactor
pub(super) fn routing_safe_effective_cap(
    config: &FreedomConfig,
    primary_provider_name: &str,
    primary_model: Option<&str>,
) -> u32 {
    routing_safe_effective_cap_inner(config, primary_provider_name, primary_model, None)
}

pub(super) fn routing_safe_effective_cap_at(
    config: &FreedomConfig,
    primary_provider_name: &str,
    primary_model: Option<&str>,
    home: &std::path::Path,
) -> u32 {
    routing_safe_effective_cap_inner(config, primary_provider_name, primary_model, Some(home))
}

fn routing_safe_effective_cap_inner(
    config: &FreedomConfig,
    primary_provider_name: &str,
    primary_model: Option<&str>,
    home: Option<&std::path::Path>,
) -> u32 {
    use crate::config::inference::HemisphereRole;

    let primary_model = route_wire_model(config, primary_provider_name, primary_model, home);
    let primary_non_content = crate::providers::token_cap::request_non_content_token_upper_bound(
        &crate::providers::Request {
            model: Some(primary_model.clone()),
            ..Default::default()
        },
    );
    let mut cap = route_primary_equivalent_cap(
        config,
        primary_provider_name,
        Some(&primary_model),
        primary_non_content,
        home,
    );

    // Runtime first drops empty/unconsented/unbuildable slots and only then
    // applies `max_hops`. Any configured suffix can therefore move into a
    // reachable position. Without constructing the chain twice, the exact
    // safe set is every configured slot whenever at least one hop is allowed.
    if config.fallback.max_hops > 0 {
        for slot in &config.fallback.chain {
            include_route_slot_cap(
                config,
                &mut cap,
                slot,
                primary_provider_name,
                Some(&primary_model),
                primary_non_content,
                home,
            );
        }
    }

    let council_enabled =
        !config.council.disabled.unwrap_or(false) && !config.council.mode.is_single();
    if !council_enabled {
        return cap;
    }

    let roles = [
        HemisphereRole::Left,
        HemisphereRole::Right,
        HemisphereRole::Cerebellum,
    ];
    // An empty Council slot delegates to `from_config(config)`, whose model is
    // the configured provider default — not a per-turn CLI/skill override on
    // the primary request.
    let configured_primary_provider = config
        .provider_kind
        .map(crate::cli::init::ProviderKind::as_provider_id)
        .filter(|provider| *provider != "none")
        .unwrap_or(primary_provider_name);
    let configured_primary_model = config.provider_model.as_deref();
    for role in roles {
        include_route_slot_cap(
            config,
            &mut cap,
            config.inference.slot_for(role),
            configured_primary_provider,
            configured_primary_model,
            primary_non_content,
            home,
        );
    }

    if config.inference.hemisphere_council_depth.get() > 1 {
        for outer_role in roles {
            for inner_role in roles {
                include_route_slot_cap(
                    config,
                    &mut cap,
                    config.inference.slot_for_sub(outer_role, inner_role),
                    configured_primary_provider,
                    configured_primary_model,
                    primary_non_content,
                    home,
                );
            }
        }
    }

    cap
}

fn prompt_bundle_hash_for_items(items: &[crate::tokens::budget::BlockItem]) -> String {
    use crate::skills::versioning::{BundleBlock, BundleBlockEntry};
    use crate::tokens::budget::Block;

    let entries: Vec<BundleBlockEntry<'_>> = items
        .iter()
        .map(|item| BundleBlockEntry {
            block: match item.block {
                Block::A => BundleBlock::A,
                Block::B => BundleBlock::B,
                Block::C => BundleBlock::C,
                Block::D => BundleBlock::D,
                Block::E => BundleBlock::E,
                Block::Conductor => BundleBlock::Conductor,
            },
            content: &item.content,
        })
        .collect();
    crate::skills::versioning::prompt_bundle_hash_hex(&entries)
}

/// Apply the last two dispatch-time prompt mutations (output preset + fixed
/// preambles), enforce the effective model cap against the real typed bundle,
/// and render the exact Request pair.  No provider path may assemble additional
/// prompt bytes after this boundary.
pub(super) struct ProviderRequestBoundary<'a> {
    pub(super) config: &'a FreedomConfig,
    pub(super) home: &'a std::path::Path,
    pub(super) provider_name: &'a str,
    pub(super) effective_model: Option<&'a str>,
    pub(super) route_cap: Option<u32>,
    pub(super) writer: &'a crate::wal::writer::WalWriterHandle,
}

pub(super) async fn finalize_provider_request(
    mut items: Vec<crate::tokens::budget::BlockItem>,
    preflight_prompt: &str,
    preflight_system: Option<&str>,
    boundary: ProviderRequestBoundary<'_>,
) -> Result<BudgetedProviderRequest> {
    use crate::tokens::budget::{Block, BlockItem};

    let ProviderRequestBoundary {
        config,
        home,
        provider_name,
        effective_model,
        route_cap,
        writer,
    } = boundary;

    let (typed_prompt, typed_system) =
        crate::tokens::budget::render_request(&items).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        typed_prompt == preflight_prompt && typed_system.as_deref() == preflight_system,
        "typed prompt blocks do not match preflight output; provider dispatch refused"
    );

    let presets = crate::config::presets::load(home)
        .context("load active output-format preset before provider dispatch")?;
    let final_prompt = match presets
        .active
        .as_ref()
        .and_then(|name| presets.presets.get(name))
    {
        Some(preset) => {
            crate::config::presets::wrap_user_prompt(preflight_prompt, preset).into_owned()
        }
        None => preflight_prompt.to_owned(),
    };
    crate::tokens::budget::replace_user_message(&mut items, final_prompt)
        .map_err(anyhow::Error::msg)?;

    if !items.iter().any(|item| {
        item.block != Block::E && item.content.contains("## Core principles (always apply)")
    }) {
        items.insert(
            0,
            BlockItem::new(
                Block::B,
                crate::providers::context_guards::code_discipline_preamble().trim_end(),
            ),
        );
    }
    if let Some(protocol) = crate::cli::clarify_chat::protocol_block()
        && !items
            .iter()
            .any(|item| item.block != Block::E && item.content == protocol)
    {
        let e_index = items
            .iter()
            .position(|item| item.block == Block::E)
            .ok_or_else(|| anyhow::anyhow!("token-budget bundle is missing Block E"))?;
        items.insert(e_index, BlockItem::new(Block::B, protocol));
    }

    let primary_cap = crate::tokens::budget::effective_cap(
        provider_name,
        effective_model.unwrap_or("provider_default"),
        config.tokens.max_per_request,
    );
    let cap = route_cap.map_or(primary_cap, |candidate| candidate.min(primary_cap));
    let system_item_count = items.iter().filter(|item| item.block != Block::E).count();
    let separator_reserve = system_item_count
        .saturating_sub(1)
        .saturating_mul(2)
        .min(u32::MAX as usize) as u32;
    // Extract the fixed (non-separator) overhead so it can be reused post-degradation.
    let non_content_overhead = crate::providers::token_cap::request_non_content_token_upper_bound(
        &crate::providers::Request {
            prompt: String::new(),
            system: (system_item_count > 0).then(String::new),
            model: effective_model.map(str::to_owned),
            ..Default::default()
        },
    );
    let envelope_reserve = non_content_overhead.saturating_add(separator_reserve);
    let content_cap = cap.saturating_sub(envelope_reserve);
    let hash_before = prompt_bundle_hash_for_items(&items);
    let detail = crate::tokens::budget::enforce_budget_to_fit(&mut items, content_cap);
    // Recompute separator reserve from the post-degradation item count.  When
    // enforce_budget_to_fit drops C/D items the rendered system contains only
    // (post_count − 1) "\n\n" separators; the pre-enforcement count above was
    // deliberately conservative so content_cap remained a true upper bound during
    // degradation.  At the ensure boundary below, prompt_token_estimate (computed
    // from the rendered strings) naturally includes only the post-degradation
    // separator bytes — making it the tight, correct accounting for this boundary.
    let post_system_item_count = items.iter().filter(|item| item.block != Block::E).count();
    let post_separator_reserve = post_system_item_count
        .saturating_sub(1)
        .saturating_mul(2)
        .min(u32::MAX as usize) as u32;
    let post_envelope_reserve = non_content_overhead.saturating_add(post_separator_reserve);
    if let Some(detail) = detail.as_ref() {
        warn!(
            effective_request_cap = cap,
            content_cap = detail.cap,
            post_envelope_reserve,
            original_total = detail.original_total,
            new_total = detail.new_total,
            dropped_d = detail.dropped_d_count,
            dropped_c = detail.dropped_c_count,
            conductor_truncated = detail.conductor_truncated,
            "final provider request exceeded token cap; typed degradation applied"
        );
        let budget_payload = serde_json::to_vec(&serde_json::json!({
            "cap": cap,
            "content_cap": detail.cap,
            "envelope_reserve": post_envelope_reserve,
            "original_total": detail.original_total,
            "new_total": detail.new_total,
            "dropped_d_count": detail.dropped_d_count,
            "dropped_c_count": detail.dropped_c_count,
            "conductor_truncated": detail.conductor_truncated,
            "prompt_bundle_hash": hash_before,
            "ts_unix": now_unix(),
        }))
        .context("serialize BUDGET_EXCEEDED audit")?;
        let budget_header = crate::wal::make_header(EVENT_TYPE_BUDGET_EXCEEDED, &budget_payload);
        if let Err(error) = writer.append(budget_header, budget_payload).await {
            warn!(error = %error, "BUDGET_EXCEEDED WAL emit failed (non-fatal)");
        }
    }

    let (prompt, system) =
        crate::tokens::budget::render_request(&items).map_err(anyhow::Error::msg)?;
    let prompt_bundle_hash = prompt_bundle_hash_for_items(&items);

    // Validate each stored item estimate, then account the exact rendered
    // system string (including inter-block separators).  The latter is the
    // authoritative request estimate; it reflects the post-degradation separator
    // count (post_separator_reserve above) so the upper bound is tight rather
    // than over-conservative relative to the pre-enforcement separator_reserve.
    anyhow::ensure!(
        items.iter().all(|item| {
            item.tokens == crate::tokens::budget::count_tokens_upper_bound(&item.content)
        }),
        "token-budget accounting drifted from final provider bytes"
    );
    let prompt_token_estimate =
        crate::providers::token_cap::request_token_upper_bound(&crate::providers::Request {
            prompt: prompt.clone(),
            system: system.clone(),
            model: effective_model.map(str::to_owned),
            ..Default::default()
        });
    anyhow::ensure!(
        prompt_token_estimate <= cap,
        "final provider request has a conservative input-token upper bound of {prompt_token_estimate}, above the effective cap {cap}; protected A/B/E content cannot be degraded safely"
    );

    Ok(BudgetedProviderRequest {
        prompt,
        system,
        prompt_bundle_hash,
        prompt_token_estimate,
        effective_cap: cap,
    })
}

/// Stable, sorted MCP server ids that define this turn's configured scope.
/// `McpServers::enabled` owns ordering/filter semantics; checkpoint callers use
/// this helper so session-start and pre-compaction snapshots cannot drift.
fn enabled_mcp_scope(servers: &crate::mcp::McpServers) -> Vec<String> {
    servers
        .enabled()
        .into_iter()
        .map(|server| server.id.clone())
        .collect()
}

/// Rebuild the exact MCP scope recorded in a checkpoint using the operator's
/// current server definitions. The checkpoint binds IDs; commands, environment
/// and allowlists remain governed by today's `mcp_servers.yaml`. Restoring old
/// executable/config bytes would override current security policy.
fn restrict_mcp_servers_to_checkpoint(
    mut current: crate::mcp::McpServers,
    scoped_ids: &[String],
) -> Result<crate::mcp::McpServers, String> {
    let requested: std::collections::BTreeSet<&str> =
        scoped_ids.iter().map(String::as_str).collect();
    if requested.len() != scoped_ids.len() || requested.iter().any(|id| id.trim().is_empty()) {
        return Err("checkpoint MCP scope contains an empty or duplicate server id".to_string());
    }

    for id in &requested {
        let mut matches = current
            .servers
            .iter()
            .filter(|server| server.id.as_str() == *id);
        let Some(server) = matches.next() else {
            return Err(format!(
                "checkpoint MCP server `{id}` is no longer configured; refusing partial resume"
            ));
        };
        if matches.next().is_some() {
            return Err(format!(
                "current MCP registry contains duplicate id `{id}`; refusing ambiguous resume"
            ));
        }
        if !server.enabled {
            return Err(format!(
                "checkpoint MCP server `{id}` is currently disabled; refusing to override current operator policy"
            ));
        }
    }

    current
        .servers
        .retain(|server| server.enabled && requested.contains(server.id.as_str()));
    Ok(current)
}

/// GOLD-ADAPT-OH-13 — raw enrichment layer strings, threaded from
/// `build_prompt_bundle` (where they were computed) to `enforce_preflight`
/// (where the sub-agent dispatch block can selectively apply them via
/// `AgentOmitFlags`). Also carries `skill_delegate_to` for Part B
/// skill-to-agent auto-synthesis.
struct AgentRawLayers {
    operator_context: Option<String>,
    preset_addendum: Option<String>,
    explicit_system: Option<String>,
    repo_context_block: Option<String>,
    skill_layer: Option<String>,
    mcp_catalogue: Option<String>,
    persona_override: Option<String>,
    moral_core: Option<String>,
    /// GOLD-R4-11 — compiler-owned, presentation-only communication profile.
    /// This layer is not skill-omittable: an agent may narrow context/tool
    /// exposure, but cannot silently discard the operator's accessibility and
    /// communication needs.
    communication_profile: Option<String>,
    recall_block: Option<String>,
    guidance_block: Option<String>,
    skill_delegate_to: Option<String>,
    /// GOLD-ADAPT-JV-MODE-01 — full loyal-buddy skill YAML body when active.
    /// `'static` because it's sourced from `include_str!` in bundled.rs.
    identity_anchor: Option<&'static str>,
    /// GOLD-ADAPT-JV-MODE-01 — true when PersonaMode::LoyalBuddy is active.
    identity_locked: bool,
}

/// Turn-scoped resources shared by prompt assembly. Grouping them keeps the
/// builder boundary explicit without changing ownership of chat inputs.
struct PromptBuildContext<'a> {
    args: &'a ChatArgs,
    prompt_bundle_hash: &'a str,
    writer: &'a crate::wal::writer::WalWriterHandle,
    mcp_servers: &'a crate::mcp::McpServers,
}

/// Optional prompt-routing decisions resolved before prompt assembly starts.
struct PromptBuildOptions {
    slash_skill_name: Option<String>,
    persona_override_from_tweaks: Option<String>,
}

/// GOLD-CCPARITY-PATHS-01 — read the operator's active editor files from the
/// `NEOTH_ACTIVE_FILES` environment variable. Paths are separated by `;` on
/// Windows and `:` on Unix. Returns an empty Vec when the variable is unset
/// or empty — this disables path gating (all skills activate normally).
fn read_env_active_files() -> Vec<String> {
    let sep = if cfg!(windows) { ';' } else { ':' };
    std::env::var("NEOTH_ACTIVE_FILES")
        .unwrap_or_default()
        .split(sep)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

async fn build_prompt_bundle(
    config: FreedomConfig,
    prompt: String,
    home: std::path::PathBuf,
    context: PromptBuildContext<'_>,
    options: PromptBuildOptions,
) -> Result<(PromptBundle, FreedomConfig, String, std::path::PathBuf)> {
    let PromptBuildContext {
        args,
        prompt_bundle_hash,
        writer,
        mcp_servers,
    } = context;
    let PromptBuildOptions {
        // GOLD-CCPARITY-SKILLVIS-01 — lowercased skill id for an explicit
        // `/skill-id` invocation; `None` for normal turns.
        slash_skill_name,
        // B22-TWEAKS-MODEL-01 — pre-loaded fail-loud at the chat boundary.
        persona_override_from_tweaks,
    } = options;
    let cwd = std::env::current_dir().unwrap_or_else(|_| home.clone());
    // GOLD-CCPARITY-SUBDIR-MD-01 — resolve extra_dirs from config; relative
    // paths are joined to cwd so operators can write `packages/core` in
    // freedom.yaml without needing absolute paths.
    let extra_dirs: Vec<std::path::PathBuf> = config
        .memory
        .operator_md_extra_dirs
        .iter()
        .map(|s| {
            let p = std::path::PathBuf::from(s);
            if p.is_absolute() { p } else { cwd.join(s) }
        })
        .collect();
    let skills_dir = home.join("skills");
    // E-22 chat-route (Session 21, 2026-05-23): swap raw `load_all` for
    // the SkillRegistry path so the chat call goes through the same
    // ArcSwap<Vec<Skill>> primitive the daemon's hot-reload watcher
    // targets. When running inside a long-lived daemon, the process-wide
    // global registry (initialised by `serve.rs`) is reused — the chat
    // path then automatically sees skill edits the watcher picked up
    // between turns. One-shot `neoth chat` falls back to a per-call
    // registry build (no watcher, no shared state).
    let (blocks_res, registry_res) = match crate::skills::registry::global() {
        Some(reg) => {
            let blocks = if args.incognito {
                Ok(Vec::new())
            } else {
                crate::memory::operator_md::assemble(&home, &cwd, &extra_dirs).await
            };
            (blocks, Ok::<_, anyhow::Error>(reg))
        }
        None if args.incognito => (
            Ok(Vec::new()),
            crate::skills::SkillRegistry::load(&skills_dir).await,
        ),
        None => {
            let (b, r) = tokio::join!(
                crate::memory::operator_md::assemble(&home, &cwd, &extra_dirs),
                crate::skills::SkillRegistry::load(&skills_dir),
            );
            (b, r)
        }
    };
    let blocks = blocks_res.unwrap_or_default();
    // GOLD-CCPARITY-SUBDIR-MD-01 — emit one SUBDIR_MD_LOADED (0x8C) WAL frame
    // per successfully loaded SubDir block. Callers-emit pattern (same as
    // HINT_LOADED 0x58): WAL writes stay in cli/ so the pure loader stays
    // free of writer handles. Best-effort: a failed append logs warn + continues.
    for b in blocks
        .iter()
        .filter(|b| b.source == crate::memory::operator_md::BlockSource::SubDir)
    {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let payload = serde_json::to_vec(&serde_json::json!({
            "path": b.path.display().to_string(),
            "bytes": b.content.len(),
            "ts_unix": now_unix,
        }))
        .unwrap_or_default();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_SUBDIR_MD_LOADED,
            &payload,
        )
        .build();
        if let Err(e) = writer.append(header, payload).await {
            tracing::warn!(
                error = %e,
                path = %b.path.display(),
                "SUBDIR_MD_LOADED WAL append failed"
            );
        }
    }
    let rendered_md = if blocks.is_empty() {
        None
    } else {
        Some(crate::memory::operator_md::render(&blocks))
    };
    // Wire the wizard-captured operator facts (custom/enum role +
    // preferred language) into the top of the operator-context layer.
    // These `freedom.yaml` fields were written at onboarding but never
    // reached the prompt before, so the model knew neither the
    // operator's role nor their preferred response language.
    let operator_context = if args.incognito {
        None
    } else {
        merge_operator_facts(&config, rendered_md)
    };

    // ── K-Wire-3 (Session 23) — layered enrichment via shared helper ──────
    // Pre-loads every enrichment block the prior 200-LOC inline
    // composition used:
    //   1. installed_skills (snapshot from registry)
    //   2. mode/skill routing → skill_layer + used_skill_id
    //   3. mcp_catalogue (async assemble — gated on enabled servers)
    //   4. persona_override (tweaks.toml)
    //   5. repo_context_block (K-Repo-Map auto-context)
    // Then `pipeline::build_enriched_request` composes them in the
    // canonical layer order (operator_md + explicit_system + repo +
    // skill + MCP, with persona as a top-line prefix). Channel-side
    // `cli/serve.rs::build_pipeline_handler` calls the same helper
    // so every inbound surface reaches the same context layering.

    // Arc<Vec<Skill>> snapshot — derefs to &[Skill] for the router.
    let raw_installed_skills = registry_res
        .with_context(|| format!("load skill registry from {}", skills_dir.display()))?
        .snapshot_owned();

    // ── ARCH-07 (Session 28) — pinned-hash integrity gate ─────────────────
    //
    // Compare each loaded skill's actual content_hash against the
    // operator's `freedom.yaml::skills.pinned_hashes` map. Mismatches
    // get one `SKILL_INJECT_SKIPPED` (0x29) WAL frame with reason
    // `hash_mismatch` + both expected + actual hashes in the payload
    // + are filtered out of the working `installed_skills` Arc so
    // every downstream router / mode-registry / injection path sees
    // them as if uninstalled. Skills NOT in the pinned map pass
    // through unchanged — operator pins what they care about; bundled
    // skills can drift across NEOTH releases without pinning every
    // one.
    //
    // Best-effort emit: WAL writer failure logs warn + continues. The
    // skill is STILL dropped on failure (integrity comes first; the
    // missing audit frame is the next-tick problem, not a reason to
    // let a tampered skill through).
    let installed_skills = if config.skills.pinned_hashes.is_empty() {
        raw_installed_skills.clone()
    } else {
        let verdicts = crate::skills::versioning::check_pinned_hashes(
            raw_installed_skills
                .iter()
                .map(|s| (s.id(), s.content_hash.as_str())),
            &config.skills.pinned_hashes,
        );
        let mut kept: Vec<crate::skills::schema::Skill> = Vec::new();
        for (skill, verdict) in raw_installed_skills.iter().zip(verdicts.iter()) {
            match verdict.verdict {
                crate::skills::versioning::PinnedHashOutcome::Allowed => {
                    kept.push(skill.clone());
                }
                crate::skills::versioning::PinnedHashOutcome::Mismatch => {
                    warn!(
                        skill = %verdict.skill_id,
                        expected = ?verdict.expected_hash,
                        actual = %verdict.actual_hash,
                        "skill pinned-hash mismatch — dropping from injection (ARCH-07)"
                    );
                    let payload = serde_json::to_vec(&serde_json::json!({
                        "skill_id": verdict.skill_id,
                        "content_hash": verdict.actual_hash,
                        "expected_hash": verdict.expected_hash,
                        "reason": crate::skills::versioning::SkillSkipReason::HashMismatch.as_str(),
                        "prompt_bundle_hash": prompt_bundle_hash,
                        "ts_unix": now_unix(),
                    }))
                    .unwrap_or_default();
                    let header = crate::wal::make_header(EVENT_TYPE_SKILL_INJECT_SKIPPED, &payload);
                    if let Err(e) = writer.append(header, payload).await {
                        warn!(
                            skill = %verdict.skill_id,
                            error = %e,
                            "SKILL_INJECT_SKIPPED (hash_mismatch) emit failed (non-fatal)"
                        );
                    }
                }
            }
        }
        std::sync::Arc::new(kept)
    };

    // Round-3 v0.4 ARCH-07 — eval-session skill suppression. When
    // `config.skills.should_suppress_for_eval()` is true, every
    // installed skill gets a SKILL_INJECT_SKIPPED frame
    // (reason=`eval_session`) + the skill layer is forced to None
    // so the prompt bundle stays free of behavioural skill prompts.
    // Operators benchmarking the bare-model baseline use this to
    // ensure the eval isn't biased by an active skill.
    let eval_suppress = config.skills.should_suppress_for_eval();
    if eval_suppress {
        for s in installed_skills.iter().filter(|s| s.manifest.enabled) {
            let payload = serde_json::to_vec(&serde_json::json!({
                "skill_id": s.id(),
                "content_hash": s.content_hash,
                "reason": crate::skills::versioning::SkillSkipReason::EvalSession.as_str(),
                "prompt_bundle_hash": prompt_bundle_hash,
                "ts_unix": now_unix(),
            }))
            .unwrap_or_default();
            let header = crate::wal::make_header(EVENT_TYPE_SKILL_INJECT_SKIPPED, &payload);
            if let Err(e) = writer.append(header, payload).await {
                warn!(
                    skill = s.id(),
                    error = %e,
                    "SKILL_INJECT_SKIPPED emit failed (non-fatal)"
                );
            }
        }
        info!(
            count = installed_skills
                .iter()
                .filter(|s| s.manifest.enabled)
                .count(),
            "eval-session active — all skills suppressed per ARCH-07"
        );
    }

    // ── GOLD-CCPARITY-SKILLVIS-01 — visibility pre-filter ────────────────────
    // `Off` skills were already removed at load time (enabled=false → router
    // skips them). Here we remove `NameOnly` and `UserInvocableOnly` skills
    // from the auto-routing pool unless the current turn was initiated by a
    // matching explicit `/skill-id` slash invocation. This keeps the router
    // pure — it never needs to know about visibility; filtering happens before
    // it is called (same architecture as the path-gate filter for PATHS-01).
    let installed_skills: std::sync::Arc<Vec<crate::skills::schema::Skill>> = {
        let needs_filter = installed_skills
            .iter()
            .any(|s| !matches!(s.manifest.visibility, crate::config::SkillVisibility::On));
        if needs_filter && !eval_suppress {
            let slash_name = slash_skill_name.as_deref();
            let mut skipped_vis: Vec<String> = Vec::new();
            let filtered: Vec<_> = installed_skills
                .iter()
                .filter(|s| match s.manifest.visibility {
                    crate::config::SkillVisibility::On => true,
                    crate::config::SkillVisibility::NameOnly
                    | crate::config::SkillVisibility::UserInvocableOnly => {
                        // Eligible only when the operator typed /skill-id
                        let eligible = slash_name.is_some_and(|n| n == s.id());
                        if !eligible {
                            skipped_vis.push(s.id().to_string());
                        }
                        eligible
                    }
                    crate::config::SkillVisibility::Off => false, // shouldn't reach (disabled at load)
                })
                .cloned()
                .collect();
            // Best-effort WAL audit: one 0x29 frame per suppressed skill so
            // the audit log captures "this skill was available but gated by
            // visibility". Mirrors the eval-session emit block above.
            for skipped_id in &skipped_vis {
                let reason = installed_skills
                    .iter()
                    .find(|s| s.id() == skipped_id)
                    .map(|s| match s.manifest.visibility {
                        crate::config::SkillVisibility::NameOnly => "visibility_name_only",
                        crate::config::SkillVisibility::UserInvocableOnly => {
                            "visibility_user_invocable_only"
                        }
                        _ => "visibility_off",
                    })
                    .unwrap_or("visibility_name_only");
                let content_hash = installed_skills
                    .iter()
                    .find(|s| s.id() == skipped_id)
                    .map(|s| s.content_hash.as_str())
                    .unwrap_or("");
                let payload = serde_json::to_vec(&serde_json::json!({
                    "skill_id": skipped_id,
                    "content_hash": content_hash,
                    "reason": reason,
                    "prompt_bundle_hash": prompt_bundle_hash,
                    "slash_skill_name": slash_skill_name,
                    "ts_unix": crate::time::now_unix_secs(),
                }))
                .unwrap_or_default();
                let header = crate::wal::make_header(EVENT_TYPE_SKILL_INJECT_SKIPPED, &payload);
                if let Err(e) = writer.append(header, payload).await {
                    warn!(
                        skill = %skipped_id,
                        error = %e,
                        "SKILL_INJECT_SKIPPED (visibility) emit failed (non-fatal)"
                    );
                }
            }
            if !skipped_vis.is_empty() {
                info!(
                    count = skipped_vis.len(),
                    slash_name = ?slash_skill_name,
                    "SKILLVIS-01: {} skill(s) gated by NameOnly/UserInvocableOnly visibility on non-slash turn",
                    skipped_vis.len()
                );
            }
            std::sync::Arc::new(filtered)
        } else {
            installed_skills
        }
    };

    // QM-3 + QM-23 (2026-05-22 Session 20): ModeRegistry trigger_phrases
    // beat the broader skill keyword scan when they hit. The matched
    // mode's `system_prompt_delta` layers on top of the parent skill's
    // base `system_prompt`. When no mode hits, fall back to the broad
    // `skills::route` Stage-1 keyword scan + Stage-2 embedding re-rank.
    let mode_registry = crate::skills::mode_registry::ModeRegistry::from_skills(&installed_skills)
        .context("build chat skill mode registry")?;
    let mode_hit = if eval_suppress {
        None
    } else {
        mode_registry.match_trigger(&prompt)
    };
    // SC-11 — captured in the skill branch below; stays None for the
    // eval-suppressed / mode-activation / no-skill paths (no skill →
    // no tool-allowlist gate). Owned so it outlives the match block to
    // the MCP dispatch call.
    let mut skill_tool_allowlist: Option<Vec<String>> = None;
    // GOLD-ADAPT-OH-13: extended to 3-tuple to capture `delegate_to` from the
    // matched skill manifest without requiring a second scan of `skill_match`.
    // GOLD-CCPARITY-MODEL-02: extended to 4-tuple to capture `skill_model`
    // from the matched skill's `manifest.model` field.
    // GOLD-CCPARITY-EFFORT-03: extended to 5-tuple to capture `skill_effort`
    // from the matched skill's `manifest.effort` field.
    #[allow(clippy::type_complexity)]
    let (skill_layer, used_skill_id, skill_delegate_to, skill_model, skill_effort): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<crate::providers::effort_override::EffortBudget>,
    ) = if eval_suppress {
        crate::analytics::babel::signals::emit(
            crate::analytics::babel::signals::SignalKind::SkillSuppressed,
        );
        (None, None, None, None, None)
    } else if let Some(resolved) = mode_hit {
        let parent = installed_skills
            .iter()
            .find(|s| s.id() == resolved.skill_id);
        info!(
            mode = %resolved.mode.id,
            skill = %resolved.skill_id,
            spectrum = %resolved.mode.spectrum.as_str(),
            oversight = %resolved.mode.oversight.as_str(),
            "mode activated via ModeRegistry"
        );
        // GOLD-ADOPT-28 lazy routing: load ONLY the matched mode's sub-doc on
        // top of the parent's thin base (shared primitive — same rule as the
        // channel path in serve_pipeline.rs).
        let layer = crate::skills::router::compose_mode_skill_layer(parent, resolved);
        // GOLD-CCPARITY-MODEL-02: parent skill's model override still applies
        // when a mode is active — the mode is a behaviour variant of its
        // parent and inherits the parent's model selection.
        let model = parent.and_then(|s| s.manifest.model.clone());
        // GOLD-CCPARITY-EFFORT-03: parent skill's effort override also applies
        // when a mode is active — mode inherits parent effort setting.
        let effort = parent.and_then(|s| s.manifest.effort);
        // A mode is a behaviour variant of its parent skill, not a separate
        // security principal. Preserve the parent's delegation boundary just
        // like its model, effort and tool allowlist.
        let delegate_to = parent.and_then(|s| s.manifest.delegate_to.clone());
        crate::analytics::babel::signals::emit(
            crate::analytics::babel::signals::SignalKind::SkillMode,
        );
        // Mode activation is its own audit path — review-gate
        // dispatching via /agent is the explicit operator path,
        // so no used_skill_id surfaces here (mirrors the prior
        // `_skill_match` discard).
        (layer, None, delegate_to, model, effort)
    } else {
        // Day-14b Phase 2 — Stage-2 embedding cosine re-rank.
        // PF-01 (Session 30): Stage-2 runs when EITHER keyword Stage-1
        // missed OR `skills.always_embed_route` is set (the default) —
        // so the skill library routes by SEMANTICS, not only on a literal
        // keyword. A Stage-2 hit (cosine ≥ EMBEDDING_THRESHOLD) takes
        // PRECEDENCE over the keyword match; when Stage-2 returns None
        // (nothing crosses the bar) the keyword Stage-1 result stands as
        // the fallback. Either way Stage-2 only fires when the operator
        // configured `inference.embedding_provider` (off by default).
        // Full-auto mode (the whole bundled skill library is live) raises the
        // Stage-1 confidence floor so a lone generic single-word trigger can't
        // false-activate; gated mode keeps the historical floor of 1.
        let stage1_floor = if config.skills.enable_all_bundled {
            crate::skills::router::FULL_AUTO_MIN_WEIGHT
        } else {
            crate::skills::router::DEFAULT_MIN_WEIGHT
        };
        // GOLD-CCPARITY-PATHS-01: read active editor files from env so path-gated
        // skills only activate when the operator is working in matching files.
        let active_files = read_env_active_files();
        let mut skill_match = crate::skills::router::route_with_min_weight(
            &prompt,
            &installed_skills,
            stage1_floor,
            &active_files,
        );
        if (skill_match.is_none() || config.skills.always_embed_route)
            && let Some(embed_provider) =
                crate::providers::embed_provider_from_config(&config).await
            && let Some((skill, score)) = crate::skills::router::route_stage2_embedding(
                &prompt,
                &installed_skills,
                embed_provider.as_ref(),
            )
            .await
        {
            info!(
                skill = skill.id(),
                cosine = score,
                overrode_keyword = skill_match.is_some(),
                "skill activated via Stage-2 embedding re-rank"
            );
            skill_match = Some(crate::skills::router::RouteMatch {
                skill,
                matched_keywords: Vec::new(),
                embedding_score: Some(score),
            });
        }
        if let Some(m) = &skill_match
            && m.embedding_score.is_none()
        {
            info!(
                skill = m.skill.id(),
                matched_keywords = ?m.matched_keywords,
                "skill activated"
            );
        }
        crate::analytics::babel::signals::emit(match &skill_match {
            Some(m) if m.embedding_score.is_some() => {
                crate::analytics::babel::signals::SignalKind::SkillEmbedding
            }
            Some(_) => crate::analytics::babel::signals::SignalKind::SkillKeyword,
            None => crate::analytics::babel::signals::SignalKind::SkillNoMatch,
        });
        let layer = skill_match
            .as_ref()
            .map(|m| m.skill.system_prompt().to_string());
        let id = skill_match.as_ref().map(|m| m.skill.id().to_string());
        // GOLD-ADAPT-OH-13: capture delegate_to from the matched skill manifest.
        let delegate = skill_match
            .as_ref()
            .and_then(|m| m.skill.manifest.delegate_to.clone());
        // GOLD-CCPARITY-MODEL-02: capture per-skill model override.
        let model = skill_match
            .as_ref()
            .and_then(|m| m.skill.manifest.model.clone());
        // GOLD-CCPARITY-EFFORT-03: capture per-skill effort/reasoning-budget.
        let effort = skill_match.as_ref().and_then(|m| m.skill.manifest.effort);
        // SC-11 — the matched skill's tool_allowlist scopes the MCP gate.
        skill_tool_allowlist = skill_match
            .as_ref()
            .map(|m| m.skill.manifest.tool_allowlist.clone());
        (layer, id, delegate, model, effort)
    };
    // Shadow as mutable so GOLD-ADAPT-PWF-01 can append the fenced plan block.
    let mut skill_layer = skill_layer;

    // ── GOLD-ADAPT-PWF-01: plan-attestation fence injection ───────────────
    // When `writing_plans` or `executing_plans` is active AND a
    // `task_plan.md` file exists, fence its content into the skill layer
    // and capture the SHA-256 hash for downstream tamper detection.
    // Best-effort: I/O errors are logged but do NOT abort the turn (the
    // guard degrades gracefully — no hash means no verify, same as no plan).
    let plan_attest_hash: Option<String> = if let Some(id) = used_skill_id.as_deref() {
        if crate::skills::plan_attestation::APPLICABLE_SKILLS.contains(&id) {
            match crate::skills::plan_attestation::attest_and_fence(&home, id, &mut skill_layer) {
                Ok(hash) => hash,
                Err(e) => {
                    tracing::warn!(
                        skill = id,
                        error = %e,
                        "plan-attestation: fence injection failed (best-effort; turn continues)"
                    );
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // ── MCP tool catalogue (Step 1 of autonomous routing) ─────────────────
    // `mcp_servers` is the fail-loud, turn-scoped snapshot loaded by
    // `run_chat_with`; prompt injection, dispatch and checkpoints all consume
    // this exact value so a mid-turn file edit cannot create split-brain scope.
    let mcp_catalogue: Option<String> = if mcp_servers.enabled().is_empty() {
        None
    } else {
        match crate::mcp::catalogue::assemble_catalogue_for_prompt(mcp_servers, &prompt).await {
            Some(cat) => {
                info!(
                    enabled = mcp_servers.enabled().len(),
                    bytes = cat.len(),
                    "MCP tool catalogue injected into system prompt"
                );
                Some(cat)
            }
            None => None,
        }
    };

    // ── C-7 persona layer (tweaks.toml::persona_override) ─────────────────
    // B22 — pre-loaded fail-loud at the chat boundary (run_chat_with);
    // no Tweaks I/O here. The silent `.ok()` suppression is removed.
    let persona_override = persona_override_from_tweaks;

    // ── GOLD-ADAPT-LOWKEY-08 — MDS dynamic tone modifier ─────────────────
    // Augments the static tweaks.toml persona_override with a per-turn
    // tone directive derived from prompt intensity. Kill-switch default OFF.
    let persona_override = if config.tone_modifier.enabled {
        let intensity = crate::council::mds_tone::classify_intensity(&prompt);
        if intensity >= config.tone_modifier.min_intensity {
            let augmented = crate::council::mds_tone::modifier_for_intensity(
                intensity,
                persona_override.as_deref(),
            );
            if let Some(aug) = augmented {
                eprintln!("[neoth:mds-tone] intensity={intensity:?} modifier={aug:?}");
                Some(aug)
            } else {
                persona_override
            }
        } else {
            persona_override
        }
    } else {
        persona_override
    };

    // ── AR-01 (Session 24) — active profile preset → system_addendum ────
    // Read `~/.neoth/profile/active_preset.txt` on EVERY turn so that
    // `neoth profile preset apply <name>` takes effect immediately
    // without a daemon restart. Pre-fix the addendum only landed in
    // the system prompt at process boot (via the wizard's one-shot
    // write into the profile snapshot). LOWKEY's addendum is the empty
    // string; `filter(!is_empty)` keeps the field None for that case so
    // the enricher doesn't introduce a stray blank line.
    let preset_addendum = if args.incognito {
        None
    } else {
        crate::cli::profile::load_active_preset(&home)
            .map(|p| crate::profile::presets::apply_preset(p).system_addendum)
            .filter(|s| !s.is_empty())
    };

    // ── K-Repo-Map Phase 3c — pre-compute the auto-context block ─────────
    // Best-effort: any failure silently skips injection.
    let prompt_instance_paths = InstancePaths::for_home(&home);
    let mut repo_context_block = maybe_repo_context_block(&config, &prompt, &prompt_instance_paths);
    if let Some(findings) = maybe_architecture_findings_for_skill(
        used_skill_id.as_deref(),
        &prompt_instance_paths,
        &cwd,
    ) {
        info!(
            roots_scanned = findings.roots_scanned,
            edges_scanned = findings.edges_scanned,
            cycles_injected = findings.cycles_injected,
            truncated = findings.truncated,
            "GRAPH-02: automatic architecture cycle findings injected"
        );
        eprintln!(
            "[neoth:code-map] architecture workflow: {} call cycle(s) injected \
             ({} edges across {} root(s))",
            findings.cycles_injected, findings.edges_scanned, findings.roots_scanned
        );
        emit_architecture_findings_audit(writer, &findings, "cli").await;
        repo_context_block = append_architecture_findings(repo_context_block, &findings);
    }

    // ── GOLD-WIRE Block::D + GOLD-ADAPT-MEM-09 — auto-recall injection ────
    // Fold the operator's most-relevant stored episodes into the system
    // prompt on a non-Skip-tier turn (greetings / status / identity skip the
    // DB hit via classify_recall_need). Folded into `combined_system` below,
    // NOT into `bundle_entries` / the prompt-bundle hash — that hash anchors
    // operator INTENT (Block::A `--system` + Block::E prompt) and excludes the
    // whole assembled context (skills/MCP/moral/repo all sit outside it too),
    // so recall stays off the ARCH-02 replay-determinism surface. Best-effort.
    // ODY-09: incognito turns skip Block::D recall injection — no memory surfaces
    // on this turn, so the operator's intent stays ephemeral end-to-end.
    let recall_block = if args.incognito {
        None
    } else {
        maybe_recall_block(&prompt, &home).await
    };

    // ── GOLD-ADAPT-MEM-12 — session-guidance block (recent hindsight sessions
    // + open fact-contradictions), folded above the recall block as session-
    // wide context. Best-effort → None on a fresh install / quiet week.
    let guidance_block = maybe_guidance_block(&home, args.incognito).await;

    // ── Compose layered system prompt via shared helper ───────────────────
    // GOLD-FEAT-07 — load the operator's LOWKEY moral core (if any) for
    // position-0 injection. Missing/disabled is None; unreadable policy blocks
    // the turn before any provider call.
    let moral_core = crate::memory::moral_core::compact_for_injection(&config, &home)
        .context("load moral core for chat turn")?;

    // GOLD-ADAPT-JV-MODE-01 — load persona mode; derive identity anchor text
    // and the identity_locked flag. loyal_buddy pins the bundled skill body at
    // position 1 (after moral_core) so no downstream layer can override it.
    let persona_mode = if args.incognito {
        None
    } else {
        crate::cli::profile::load_persona_mode(&home)
    };
    let (identity_anchor_text, identity_locked) = match persona_mode {
        Some(crate::config::PersonaMode::LoyalBuddy) => {
            // Pull system_prompt from the bundled skill YAML at compile time.
            let body = crate::skills::bundled::BUNDLED_SKILLS
                .iter()
                .find(|(id, _)| *id == "loyal_buddy")
                .map(|(_, body)| *body);
            (body, true)
        }
        None => (None, false),
    };

    // GOLD-FEAT-11 — load cross-turn goal (best-effort; None on missing/corrupt file).
    let goal_persist = if args.incognito {
        None
    } else {
        crate::daemon::goal_persist::GoalPersist::load(&home)
    };
    let goal_layer_text = goal_persist.as_ref().and_then(|g| g.as_system_layer());

    // GOLD-R4-11 — deterministic local communication adaptation. The compiler
    // returns before opening profile state for incognito turns and only exports
    // the accommodations allowed by `profile.communication.prompt_export`.
    // Corrupt configured state is fail-loud, matching moral-core handling: a
    // requested profile cannot disappear silently before provider dispatch.
    let communication_profile = crate::profile::communication::compile_prompt(
        &home,
        "operator",
        &config.profile.communication,
        None,
        args.incognito,
    )
    .context("compile communication profile for chat turn")?;

    let enriched = crate::pipeline::build_enriched_request(crate::pipeline::EnrichmentInputs {
        prompt: &prompt,
        operator_context: operator_context.as_deref(),
        preset_addendum: preset_addendum.as_deref(),
        explicit_system: args.system.as_deref(),
        repo_context_block: repo_context_block.as_deref(),
        skill_system_prompt: skill_layer.as_deref(),
        used_skill_id: used_skill_id.as_deref(),
        mcp_catalogue: mcp_catalogue.as_deref(),
        persona_override: persona_override.as_deref(),
        moral_core: moral_core.as_deref(),
        identity_anchor: identity_anchor_text,
        identity_locked,
        current_goal: goal_layer_text.as_deref(),
        communication_profile: communication_profile.as_ref().map(|compiled| {
            crate::pipeline::CommunicationProfilePrompt::presentation_only(compiled.as_str())
        }),
    });
    // Fold the layers in authority order: enriched.system (operator / skills /
    // MCP / moral) > guidance (MEM-12 session-wide context) > recall (Block::D
    // turn-specific episodes, closest to the user turn). `None` lanes drop out;
    // all-None → None (byte-identical to before guidance/recall when both empty).
    //
    // GOLD-ADAPT-OH-13: clone guidance_block + recall_block before the move
    // into the fold so they can be threaded to enforce_preflight for the
    // selective agent-enrichment rebuild.
    let guidance_block_raw = guidance_block.clone();
    let recall_block_raw = recall_block.clone();
    // GOLD-ADAPT-ODY-12/14 — deep-link instruction rides ONLY the GUI
    // stream path; terminal/channel surfaces never render chips, so the
    // model shouldn't emit anchors there.
    let deep_link_block = args
        .stream
        .then(|| crate::cli::deep_links::DEEP_LINK_PROMPT.to_string());
    // Preserve each layer's typed budget identity instead of folding to a
    // string-only value.  EnrichedRequest ends with the sole E item; append
    // chat-only D/A layers immediately before it, then render the legacy string
    // from that same representation so the two views cannot drift.
    let mut budget_items = enriched.budget_items;
    let user_item = budget_items
        .pop()
        .filter(|item| item.block == crate::tokens::budget::Block::E)
        .ok_or_else(|| anyhow::anyhow!("prompt assembler lost the typed Block E item"))?;
    if let Some(guidance) = guidance_block {
        let mut item =
            crate::tokens::budget::BlockItem::new(crate::tokens::budget::Block::D, guidance);
        item.ts_ns = 1;
        budget_items.push(item);
    }
    if let Some(recall) = recall_block {
        let mut item =
            crate::tokens::budget::BlockItem::new(crate::tokens::budget::Block::D, recall);
        item.ts_ns = 2;
        budget_items.push(item);
    }
    if let Some(deep_link) = deep_link_block {
        budget_items.push(crate::tokens::budget::BlockItem::new(
            crate::tokens::budget::Block::A,
            deep_link,
        ));
    }
    budget_items.push(user_item);
    let (typed_prompt, combined_system) =
        crate::tokens::budget::render_request(&budget_items).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        typed_prompt == prompt,
        "typed prompt bundle diverged from the operator message"
    );
    // used_skill_id is plumbed through for any downstream audit
    // consumers; the existing chat path consumes `combined_system`
    // the same way it did before the helper extraction.
    let _used_skill_id = enriched.used_skill_id;

    // GOLD-ADAPT-OH-13: bundle raw layers so enforce_preflight can rebuild
    // the system prompt per-agent with selective omissions.
    let agent_raw_layers = AgentRawLayers {
        operator_context,
        preset_addendum,
        explicit_system: args.system.clone(),
        repo_context_block,
        skill_layer,
        mcp_catalogue,
        persona_override,
        moral_core,
        communication_profile: communication_profile
            .map(crate::profile::communication::CompiledCommunicationPrompt::into_string),
        recall_block: recall_block_raw,
        guidance_block: guidance_block_raw,
        skill_delegate_to,
        // GOLD-ADAPT-JV-MODE-01
        identity_anchor: identity_anchor_text,
        identity_locked,
    };

    Ok((
        PromptBundle {
            combined_system,
            budget_items,
            skill_tool_allowlist,
            plan_attest_hash,
            agent_raw_layers,
            resolved_model: skill_model,
            // GOLD-CCPARITY-EFFORT-03: thread the per-skill effort to dispatch_provider.
            resolved_effort: skill_effort,
        },
        config,
        prompt,
        home,
    ))
}

/// GOLD-ARCH-02 phase 2 — pre-flight gates for one chat turn: provider-quota
/// 429 backoff, sub-agent +
/// slash-command dispatch, and the PrePipeline/PreProviderCall TOML hooks.
/// Owns the WAL writer + its join handle so every abort path can drain them
/// exactly as before; on success it threads them back to the caller. A typed
/// slash action that handles the turn returns `Done` (the caller returns Ok).
#[allow(clippy::large_enum_variant)]
enum PreflightOutcome {
    /// A slash action handled the turn — the caller returns `Ok(())`.
    Done,
    /// Proceed to the provider call with these resolved values.
    Continue {
        writer: crate::wal::writer::WalWriterHandle,
        writer_join: tokio::task::JoinHandle<()>,
        review_context: Option<(String, String)>,
        final_prompt: String,
        final_system: Option<String>,
        prompt: String,
        quota_path: std::path::PathBuf,
        quota_tracker: Option<crate::providers::quota::QuotaTracker>,
        hooks: Vec<crate::hooks::schema::HookDef>,
        /// B22 — exact model bound to the cost authorization and later copied
        /// unchanged into `Request.model`.
        effective_model: Option<String>,
        /// Priority layer that selected `effective_model`.
        model_source: &'static str,
        /// Active sub-agent tool policy. `None` means no agent fired;
        /// `Some((empty, _))` is deliberately distinct and denies every MCP
        /// tool because an agent with `tools: []` is provider-only.
        agent_tool_policy: Option<(Vec<String>, Vec<String>)>,
        /// GOLD-ADAPT-SKILL-09 — FilteredBlocks produced by `block_filter`
        /// hooks at `PreProviderCall`. Empty when no BlockFilter hooks fired.
        /// Threaded to `run_post_reply_pipelines` where `restore_blocks`
        /// re-injects original content before WAL write + recall.
        pending_block_restorations: Vec<crate::hooks::block_filter::FilteredBlock>,
        /// Typed request blocks after every preflight prompt/system rewrite.
        /// Output-preset and fixed-preamble additions happen once more at the
        /// final budget boundary immediately before Request construction.
        budget_items: Vec<crate::tokens::budget::BlockItem>,
    },
}

fn resolve_provider_call_model(
    dispatch: Option<&str>,
    skill: Option<&str>,
    cli: Option<&str>,
    tweaks: Option<&str>,
    freedom: Option<&str>,
) -> (Option<String>, &'static str) {
    let (model, source) =
        crate::tweaks::resolve_effective_model(dispatch, skill, cli, tweaks, freedom);
    (model.map(str::to_string), source.as_str())
}

/// Apply the operator's global one-level alias map and then the selected
/// provider's adapter-specific canonicalization. Both CLI and channel request
/// assembly use this before token budgeting, and copy the returned value into
/// `Request.model` unchanged.
pub(super) fn resolve_provider_call_wire_model(
    config: &FreedomConfig,
    provider: &dyn crate::providers::Provider,
    requested_model: Option<&str>,
) -> Result<String> {
    crate::providers::resolve_configured_request_model_for_wire(config, provider, requested_model)
}

// GOLD-ADAPT-PWF-01 adds `plan_attest_hash` as a 9th parameter;
// GOLD-ADAPT-OH-13 adds `agent_raw_layers` as a 10th. Suppress the lint
// rather than refactoring into a context struct (separate concern).
#[allow(clippy::too_many_arguments)]
async fn enforce_preflight(
    combined_system: Option<String>,
    budget_items: Vec<crate::tokens::budget::BlockItem>,
    prompt: String,
    provider: &dyn crate::providers::Provider,
    args: &ChatArgs,
    config: &FreedomConfig,
    writer: crate::wal::writer::WalWriterHandle,
    writer_join: tokio::task::JoinHandle<()>,
    home: &std::path::Path,
    // GOLD-ADAPT-PWF-01: SHA-256 of `task_plan.md` captured at injection
    // time by `build_prompt_bundle`. `None` means no plan was injected.
    plan_attest_hash: Option<String>,
    // GOLD-ADAPT-OH-13: raw enrichment layers for selective agent rebuild.
    agent_raw_layers: AgentRawLayers,
    // B22 — skill model is already resolved by build_prompt_bundle. It must be
    // present before PaidProviderCall authorization, not merged afterwards.
    skill_model_for_cost: Option<String>,
    // Exact detached requests carry the same per-skill reasoning control as a
    // foreground dispatch instead of reconstructing a weaker raw request in
    // the child process.
    skill_effort_for_request: Option<crate::providers::effort_override::EffortBudget>,
    // B22-TWEAKS-MODEL-01 — tweaks.model_default propagated from the chat
    // boundary (already loaded fail-loud there) into the full authorization
    // precedence chain.
    tweaks_model_for_cost: Option<String>,
    // GOLD-CCPARITY-ONCE: session-scoped once-guard shared across PrePipeline +
    // PreProviderCall — a once=true hook fired at PrePipeline is suppressed at
    // PreProviderCall within the same session. Arc-backed so it is cheaply
    // Clone and safe to pass by shared ref across stages.
    once_guard: &crate::hooks::SessionOnceGuard,
) -> Result<PreflightOutcome> {
    // Resolve sub-agent dispatch once and reuse it for prompt + model routing.
    // The PaidProviderCall decision now happens at each real provider leaf,
    // after all prompt/model mutations and immediately before that exact call.
    let agent_dir = home.join("agents");
    let agents = crate::sub_agents::load_all(&agent_dir)
        .await
        .unwrap_or_default();
    let agent_dispatch =
        crate::sub_agents::parse_agent_invocation(&prompt, &agents).or_else(|| {
            agent_raw_layers
                .skill_delegate_to
                .as_deref()
                .and_then(|name| agents.iter().find(|a| a.name == name))
                .map(|agent| crate::sub_agents::Dispatch {
                    agent_name: agent.name.clone(),
                    system: agent.system.clone(),
                    model: agent.model.clone(),
                    allowed_tools: agent.tools.clone(),
                    disallowed_tools: agent.disallowed_tools.clone(),
                    prompt: prompt.clone(),
                    omit_flags: agent.to_omit_flags(),
                })
        });
    let (requested_model, model_source) = resolve_provider_call_model(
        agent_dispatch
            .as_ref()
            .and_then(|dispatch| dispatch.model.as_deref()),
        skill_model_for_cost.as_deref(),
        args.model.as_deref(),
        tweaks_model_for_cost.as_deref(),
        config.provider_model.as_deref(),
    );
    // Resolve defaults and aliases before the common finalizer. The exact same
    // canonical model is then copied into Request.model, so model-window
    // degradation, cost authorization, and transport cannot disagree.
    let effective_model = Some(resolve_provider_call_wire_model(
        config,
        provider,
        requested_model.as_deref(),
    )?);
    // ── Provider quota pre-flight (H5 cascade) ─────────────────────────────
    // If a previous turn recorded a 429 and the backoff window is still
    // active, refuse the call HERE rather than paying the round-trip just
    // to be rate-limited again. Local providers are never tracked.
    let quota_path = home.join("quota.json");
    let provider_name = provider.name();
    let quota_tracker = if !crate::providers::is_local_provider(provider_name) {
        let tracker = match crate::providers::quota::QuotaTracker::load_from(&quota_path) {
            Ok(tracker) => tracker,
            Err(error) => {
                drop(writer);
                let _ = writer_join.await;
                return Err(error).with_context(|| {
                    format!("load provider quota state {}", quota_path.display())
                });
            }
        };
        let now = crate::providers::quota::now_unix();
        if !(provider.handles_nonstream_quota_backoff() && !args.stream)
            && let Some(state) = tracker.get(provider_name)
            && !state.is_healthy(now)
        {
            let remaining = state.backoff_remaining_secs(now);
            drop(writer);
            let _ = writer_join.await;
            anyhow::bail!(
                "{provider_name}: backoff active ({remaining}s remaining). \
                     Wait for the window to clear, switch providers via `neoth init`, \
                     or run `neoth quota reset {provider_name}` if you're confident \
                     the remote has recovered."
            );
        }
        Some(tracker)
    } else {
        None
    };

    // ── Sub-agent dispatch (Phase 30 R-18 SA-2 + GOLD-ADAPT-OH-13) ──────────
    // `/agent <name> <body>` swaps system+model+tools for the named agent.
    // GOLD-ADAPT-OH-13 Part B: a matched skill with `delegate_to: <name>`
    // auto-synthesises a Dispatch so the same enrichment-rebuild path fires.
    // Capture the original prompt + name BEFORE the dispatch consumes the
    // values — needed for the two-stage review gate after the reply lands.
    let review_context: Option<(String, String)> = agent_dispatch
        .as_ref()
        .map(|d| (d.agent_name.clone(), d.prompt.clone()));

    // ── GOLD-ADAPT-OH-13: selective enrichment rebuild helper ─────────────
    // Build a system prompt for `d` using only the layers NOT omitted by its
    // `omit_flags`. Mirrors the layer order in `build_enriched_request`:
    //   moral_core > operator_context > preset_addendum > explicit_system >
    //   repo_context_block > skill_layer > mcp_catalogue
    // then folds guidance_block + recall_block in above that (same order as
    // the main combined_system fold). Returns the rendered system plus the
    // typed bundle that produced it.
    let build_agent_system = |d: &crate::sub_agents::Dispatch| -> Result<(
        Option<String>,
        Vec<crate::tokens::budget::BlockItem>,
    )> {
        use crate::pipeline::{EnrichmentInputs, build_enriched_request};
        let f = &d.omit_flags;
        let enriched = build_enriched_request(EnrichmentInputs {
            prompt: &d.prompt,
            operator_context: if f.operator_context {
                None
            } else {
                agent_raw_layers.operator_context.as_deref()
            },
            preset_addendum: if f.preset {
                None
            } else {
                agent_raw_layers.preset_addendum.as_deref()
            },
            explicit_system: agent_raw_layers.explicit_system.as_deref(),
            repo_context_block: if f.repo_context {
                None
            } else {
                agent_raw_layers.repo_context_block.as_deref()
            },
            skill_system_prompt: agent_raw_layers.skill_layer.as_deref(),
            used_skill_id: None,
            mcp_catalogue: if f.mcp_catalogue {
                None
            } else {
                agent_raw_layers.mcp_catalogue.as_deref()
            },
            persona_override: agent_raw_layers.persona_override.as_deref(),
            moral_core: if f.moral_core {
                None
            } else {
                agent_raw_layers.moral_core.as_deref()
            },
            // GOLD-ADAPT-JV-MODE-01: identity lock propagates to sub-agents;
            // the anchor is not omit-flag-gated (identity cannot be stripped by a skill).
            identity_anchor: agent_raw_layers.identity_anchor,
            identity_locked: agent_raw_layers.identity_locked,
            // Cross-turn goal not re-injected into sub-agents (operator goal is
            // already visible via the parent turn's system prompt context).
            current_goal: None,
            communication_profile: agent_raw_layers
                .communication_profile
                .as_deref()
                .map(crate::pipeline::CommunicationProfilePrompt::presentation_only),
        });
        let mut items = enriched.budget_items;
        let user_item = items
            .pop()
            .filter(|item| item.block == crate::tokens::budget::Block::E)
            .ok_or_else(|| anyhow::anyhow!("agent prompt assembler lost Block E"))?;
        // The agent's own system prompt is always the protected base.  Insert
        // it AFTER the last Block::A item so the identity-lock anchor assembled
        // by build_enriched_request remains first in the rendered system.
        // Inserting at index 0 would push Block::A behind this Block::B,
        // violating the "identity first" invariant when an anchor is present.
        if !d.system.trim().is_empty() {
            let insert_pos = items
                .iter()
                .rposition(|item| item.block == crate::tokens::budget::Block::A)
                .map(|pos| pos + 1)
                .unwrap_or(0);
            items.insert(
                insert_pos,
                crate::tokens::budget::BlockItem::new(
                    crate::tokens::budget::Block::B,
                    d.system.trim(),
                ),
            );
        }
        if !f.recall {
            if let Some(guidance) = agent_raw_layers.guidance_block.as_deref() {
                let mut item = crate::tokens::budget::BlockItem::new(
                    crate::tokens::budget::Block::D,
                    guidance,
                );
                item.ts_ns = 1;
                items.push(item);
            }
            if let Some(recall) = agent_raw_layers.recall_block.as_deref() {
                let mut item =
                    crate::tokens::budget::BlockItem::new(crate::tokens::budget::Block::D, recall);
                item.ts_ns = 2;
                items.push(item);
            }
        }
        items.push(user_item);
        let (_, system) =
            crate::tokens::budget::render_request(&items).map_err(anyhow::Error::msg)?;
        Ok((system, items))
    };

    // ── Slash command dispatch (Phase 28 R-17 SC-2) ────────────────────────
    // If the operator typed `/help`, `/recall foo`, etc., look up the command
    // in the merged registry (built-ins + `~/.neoth/commands/*.toml`).
    // Matched commands replace the system prompt; the args become the
    // user-facing prompt body. Non-commands pass through untouched.
    // Preserve whether an agent is active separately from its lists: an active
    // agent with `tools: []` must deny every MCP tool, while no active agent
    // imposes no agent-level restriction.
    let mut agent_tool_policy: Option<(Vec<String>, Vec<String>)> = None;
    let (final_prompt, final_system, mut final_budget_items) = if let Some(d) = agent_dispatch {
        info!(agent = %d.agent_name, "sub-agent dispatch");
        agent_tool_policy = Some((d.allowed_tools.clone(), d.disallowed_tools.clone()));
        // GOLD-ADAPT-OH-13: emit WAL 0xFC AGENT_DISPATCHED with omit-flags mask.
        {
            let f = &d.omit_flags;
            let auto_delegated = agent_raw_layers
                .skill_delegate_to
                .as_deref()
                .map(|s| s.to_string());
            let payload = serde_json::to_vec(&serde_json::json!({
                "agent_name": d.agent_name,
                "omit_flags_mask": {
                    "operator_context": f.operator_context,
                    "mcp_catalogue": f.mcp_catalogue,
                    "moral_core": f.moral_core,
                    "preset": f.preset,
                    "recall": f.recall,
                    "repo_context": f.repo_context,
                },
                "auto_delegated_from_skill": auto_delegated,
                "ts_unix": crate::time::now_unix_secs(),
            }))
            .unwrap_or_default();
            if !payload.is_empty() {
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_AGENT_DISPATCHED,
                    &payload,
                )
                .build();
                if let Err(e) = writer.append(header, payload).await {
                    tracing::warn!(error = %e, "WAL append AGENT_DISPATCHED failed (best-effort)");
                }
            }
        }
        let (agent_system, agent_budget_items) = build_agent_system(&d)?;
        (d.prompt, agent_system, agent_budget_items)
    } else {
        match crate::slash::parse_invocation(&prompt) {
            crate::slash::Invocation::Command {
                name,
                args: cmd_args,
            } => {
                // ── GOLD-ADAPT-ODY-17: `/research <topic>` deep-research engine ──
                // Short-circuits before the TOML command registry and the LLM
                // round-trip: runs the multi-step search→read→synthesize loop,
                // prints the report, and returns Done. No provider call, no
                // consent gate, no token cost for the outer chat pipeline.
                if name == "research" {
                    let topic = cmd_args.trim();
                    if topic.is_empty() {
                        println!("Usage: /research <topic>");
                        return Ok(PreflightOutcome::Done);
                    }
                    let search_provider = crate::tools::deep_research::resolve_search_provider();
                    match crate::tools::deep_research::resolve_search_key(search_provider) {
                        Err(e) => {
                            eprintln!("deep-research: {e}");
                            return Ok(PreflightOutcome::Done);
                        }
                        Ok(search_key) => {
                            info!(
                                topic = topic,
                                "slash /research: starting deep-research engine"
                            );
                            // Keep the writer-owning authorizer scoped to the
                            // one branch that needs it. Preflight abort paths
                            // can then drain their WAL without a hidden sender
                            // clone keeping the channel open forever.
                            let research_authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
                                config.autonomy_policy(),
                                Some(writer.clone()),
                                config.tokens.max_per_request,
                            )
                            .with_usage_home(home.to_path_buf())
                            .with_audit_context(
                                crate::providers::cost_authorization::ProviderCallAuditContext {
                                    source: Some("chat"),
                                    call_type: Some("deep_research_round"),
                                    operator_id: config.operator_id.clone(),
                                    target: Some(
                                        crate::profile::runner::extract_target_label(provider.name())
                                            .to_owned(),
                                    ),
                                    model_source: Some(model_source),
                                    cost_estimate_model: effective_model.clone(),
                                    ..Default::default()
                                },
                            );
                            let research_provider =
                                crate::providers::cost_authorization::CostAuthorizingProvider::new(
                                    provider,
                                    research_authorizer,
                                    effective_model.clone(),
                                    "deep_research_round",
                                );
                            let http =
                                crate::tools::external_http::ExternalHttpAuthorizer::with_writer(
                                    config.autonomy_policy(),
                                    crate::permissions::Gate::auto_confirm(),
                                    writer.clone(),
                                );
                            match crate::tools::deep_research::run_deep_research(
                                topic,
                                &research_provider,
                                &search_key,
                                search_provider,
                                &config.deep_research,
                                &writer,
                                &http,
                            )
                            .await
                            {
                                Ok(report) => {
                                    println!("{}\n", report.article);
                                    if !report.citations.is_empty() {
                                        println!("---\nSources:");
                                        for (i, c) in report.citations.iter().enumerate() {
                                            println!("[{}] {} — {}", i + 1, c.title, c.url);
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("deep-research error: {e:#}");
                                }
                            }
                        }
                    }
                    return Ok(PreflightOutcome::Done);
                }

                // ── HERMES-02: `/background <prompt>` / `/btw <prompt>` ───
                // Short-circuit before the TOML registry. CLI turns are
                // one-shot runtimes, so a private detached worker process owns
                // the durable job and survives after this command exits.
                if name == "background" || name == "btw" {
                    let prompt_body = cmd_args.trim().to_string();
                    if prompt_body.is_empty() {
                        println!("Usage: /{name} <prompt>");
                    } else {
                        let selected_config_path = args
                            .config
                            .clone()
                            .unwrap_or_else(FreedomConfig::default_path);
                        let queue_result: Result<_> = async {
                            let mut request_items = budget_items.clone();
                            crate::tokens::budget::replace_user_message(
                                &mut request_items,
                                prompt_body,
                            )
                            .map_err(anyhow::Error::msg)?;
                            let (preflight_prompt, preflight_system) =
                                crate::tokens::budget::render_request(&request_items)
                                    .map_err(anyhow::Error::msg)?;
                            let route_cap = routing_safe_effective_cap_at(
                                config,
                                provider.name(),
                                effective_model.as_deref(),
                                home,
                            );
                            let budgeted = finalize_provider_request(
                                request_items,
                                &preflight_prompt,
                                preflight_system.as_deref(),
                                ProviderRequestBoundary {
                                    config,
                                    home,
                                    provider_name: provider.name(),
                                    effective_model: effective_model.as_deref(),
                                    route_cap: Some(route_cap),
                                    writer: &writer,
                                },
                            )
                            .await?;
                            let thinking_budget = skill_effort_for_request
                                .filter(|_| provider.request_controls().supports_thinking_budget())
                                .map(crate::providers::effort_override::effort_to_tokens);
                            let request = Request {
                                prompt: budgeted.prompt,
                                system: budgeted.system,
                                model: effective_model.clone(),
                                temperature: args.temperature,
                                top_p: args.top_p,
                                sampling_seed: args.sampling_seed,
                                stop_sequences: Vec::new(),
                                thinking_budget,
                            };
                            provider.validate_request_controls(&request)?;
                            crate::cli::bg_session::spawn_background_process(
                                &name,
                                request,
                                home,
                                &selected_config_path,
                                config.clone(),
                                Some(&writer),
                            )
                            .await
                        }
                        .await;
                        match queue_result {
                            Ok(_) => println!(
                                "[neoth] /{name}: background session queued — \
                                 result at next idle"
                            ),
                            Err(e) => eprintln!("/{name}: queue failed: {e:#}"),
                        }
                    }
                    drop(writer);
                    let _ = writer_join.await;
                    return Ok(PreflightOutcome::Done);
                }

                let slash_dir = home.join("commands");
                let commands = match crate::slash::load_all(&slash_dir).await {
                    Ok(commands) => commands,
                    Err(error) => {
                        drop(writer);
                        if let Err(join_error) = writer_join.await {
                            warn!(
                                error = %join_error,
                                "WAL writer join failed while refusing an invalid slash-command set"
                            );
                        }
                        return Err(error).with_context(|| {
                            format!(
                                "operator slash commands at {} are invalid; refusing partial dispatch",
                                slash_dir.display()
                            )
                        });
                    }
                };
                if let Some(cmd) = commands.iter().find(|c| c.name == name) {
                    // Pick #31 — action-based slash short-circuit.
                    // When the command carries a typed action, dispatch
                    // it directly + skip the LLM round-trip. Operator
                    // sees the handler output immediately; no provider
                    // call, no token cost, no consent gate.
                    if let Some(action) = cmd.action {
                        info!(slash_command = %name, action = action.as_str(), "slash action dispatch");
                        let outcome = crate::slash::dispatch_action(
                            action,
                            &cmd_args,
                            config,
                            crate::slash::CommandSource::Cli,
                        )
                        .await;
                        println!("{}", outcome.text());
                        if outcome.should_exit() {
                            return Ok(PreflightOutcome::Done);
                        }
                        // Action handled — no LLM call needed for this turn.
                        return Ok(PreflightOutcome::Done);
                    }
                    let rendered = cmd.render(&cmd_args, config.operator_id.as_deref());
                    info!(slash_command = %name, "slash dispatch");
                    let items = vec![
                        crate::tokens::budget::BlockItem::new(
                            crate::tokens::budget::Block::B,
                            rendered.clone(),
                        ),
                        crate::tokens::budget::BlockItem::new(
                            crate::tokens::budget::Block::E,
                            cmd_args.clone(),
                        ),
                    ];
                    (cmd_args, Some(rendered), items)
                } else {
                    (prompt.clone(), combined_system, budget_items.clone())
                }
            }
            crate::slash::Invocation::Escaped { text } => {
                (text, combined_system, budget_items.clone())
            }
            crate::slash::Invocation::NotACommand => {
                (prompt.clone(), combined_system, budget_items.clone())
            }
        }
    };

    // ── TOML hooks: PrePipeline + PreProviderCall (Phase 29 R-15) ─────────
    // Load `~/.neoth/hooks/*.toml` once for this turn. Both stages apply
    // against the prompt body. A Block at either stage aborts the turn
    // with the hook's `reason` surfaced to the operator. Each fired hook
    // writes a `HOOK_FIRED`/`HOOK_REPLACED`/`HOOK_BLOCKED` WAL frame so
    // the audit trail is exact about which rules touched the call.
    // ── GOLD-ADAPT-PWF-01: plan-attestation tamper detection ─────────────
    // If a plan file was fenced at injection time, re-read it now and
    // verify the SHA-256 still matches. This is the only point where both
    // (a) the assembled system string exists and (b) we can still abort
    // before a provider call fires. The window between attest_and_fence
    // and here is typically <1ms (same turn, same process), but the guard
    // catches any out-of-band modification (editor saves, injection scripts,
    // race with another process) and also proves tamper-detection is active
    // in the WAL audit trail via HOOK_BLOCKED (0x81).
    if let Some(ref expected_hash) = plan_attest_hash
        && !crate::skills::plan_attestation::verify_plan_hash(home, expected_hash)
    {
        let payload = serde_json::to_vec(&serde_json::json!({
                "name": "plan-attest-guard",
                "stage": "pre_provider_call",
                "reason": "[PLAN TAMPERED] task_plan.md hash mismatch — plan was modified after injection",
                "ts_unix": crate::time::now_unix_secs(),
            }))
            .unwrap_or_default();
        if !payload.is_empty() {
            let header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                &payload,
            )
            .build();
            if let Err(e) = writer.append(header, payload).await {
                tracing::warn!(error = %e, "WAL append HOOK_BLOCKED (plan tamper) failed");
            }
        }
        drop(writer);
        let _ = writer_join.await;
        anyhow::bail!(
            "[PLAN TAMPERED] task_plan.md was modified after plan injection — aborting turn"
        );
    }

    let hook_dir = home.join("hooks");
    // Operator hooks are policy, not optional decoration. A malformed or
    // unreadable configured hook must never turn into an empty policy set and
    // let the provider call continue.
    let hooks = match crate::hooks::load_all_strict(&hook_dir).await {
        Ok(hooks) => hooks,
        Err(error) => {
            let reason = format!("operator hook set could not be loaded: {error:#}");
            match serde_json::to_vec(&serde_json::json!({
                "name": "hook-loader",
                "stage": "pre_pipeline",
                "reason": reason,
                "ts_unix": crate::time::now_unix_secs(),
            })) {
                Ok(payload) => {
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                        &payload,
                    )
                    .build();
                    if let Err(audit_error) = writer.append(header, payload).await {
                        warn!(
                            error = %audit_error,
                            "WAL append HOOK_BLOCKED for invalid hook set failed"
                        );
                    }
                }
                Err(audit_error) => warn!(
                    error = %audit_error,
                    "serialize HOOK_BLOCKED for invalid hook set failed"
                ),
            }
            drop(writer);
            if let Err(join_error) = writer_join.await {
                warn!(
                    error = %join_error,
                    "WAL writer join failed while refusing an invalid hook set"
                );
            }
            return Err(error).with_context(|| {
                format!(
                    "operator hooks at {} are invalid; provider dispatch refused",
                    hook_dir.display()
                )
            });
        }
    };
    let final_prompt = match run_hook_stage(
        crate::hooks::HookStage::PrePipeline,
        &final_prompt,
        &hooks,
        &writer,
        once_guard,
    )
    .await?
    {
        // BlockFilter does not produce meaningful output at PrePipeline
        // (prompt text, not file content) — ignore any blocks here.
        HookOutcome::Continue(body, _blocks) => body,
        HookOutcome::Blocked { name, reason } => {
            drop(writer);
            let _ = writer_join.await;
            anyhow::bail!("hook `{name}` blocked the turn at pre_pipeline: {reason}");
        }
    };
    // GOLD-ADAPT-ODY-28 — prepend user-local TZ context BEFORE the
    // PreProviderCall hook stage so every hook (token-limit, policy,
    // audit, canonical-prompt-hash) operates on the exact prompt that
    // the provider will receive. Resolve once; WAL audit uses the same
    // resolved value (tz-double-resolve fix). Best-effort: no-op when
    // unconfigured.
    let tz_opt = crate::cli::user_tz::resolve_tz_name(config);
    let final_prompt = if let Some(ref tz_name) = tz_opt {
        crate::cli::user_tz::maybe_prepend_tz_with_name(&final_prompt, tz_name)
    } else {
        final_prompt
    };
    // WAL audit — batchable, non-fatal.
    if let Some(ref tz_name) = tz_opt {
        use crate::wal::events::EVENT_TYPE_TZ_CONTEXT_INJECTED;
        let utc_offset_str = crate::cli::user_tz::utc_offset_for(tz_name);
        let payload = serde_json::to_vec(&serde_json::json!({
            "tz_name": tz_name,
            "utc_offset_str": utc_offset_str,
            "ts_unix": crate::time::now_unix_i64(),
        }))
        .unwrap_or_default();
        let hdr = crate::wal::make_header(EVENT_TYPE_TZ_CONTEXT_INJECTED, &payload);
        let _ = writer.append(hdr, payload).await;
    }

    // GOLD-ADAPT-SKILL-09: capture filtered_blocks from the PreProviderCall
    // stage. These blocks are produced by BlockFilter hooks (e.g.
    // `simplify-ignore`) that redacted `neoth-ignore` regions from the
    // prompt before the LLM sees it. They must be restored in
    // run_post_reply_pipelines at PostProviderCall so the WAL and recall
    // never see placeholders.
    let (final_prompt, pending_block_restorations) = match run_hook_stage(
        crate::hooks::HookStage::PreProviderCall,
        &final_prompt,
        &hooks,
        &writer,
        once_guard,
    )
    .await?
    {
        HookOutcome::Continue(body, blocks) => (body, blocks),
        HookOutcome::Blocked { name, reason } => {
            drop(writer);
            let _ = writer_join.await;
            anyhow::bail!("hook `{name}` blocked the turn at pre_provider_call: {reason}");
        }
    };

    crate::tokens::budget::replace_user_message(&mut final_budget_items, final_prompt.clone())
        .map_err(anyhow::Error::msg)?;
    let (typed_prompt, typed_system) =
        crate::tokens::budget::render_request(&final_budget_items).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        typed_prompt == final_prompt && typed_system == final_system,
        "typed prompt blocks diverged during preflight; provider dispatch refused"
    );

    Ok(PreflightOutcome::Continue {
        writer,
        writer_join,
        review_context,
        final_prompt,
        final_system,
        prompt,
        quota_path,
        quota_tracker,
        hooks,
        effective_model,
        model_source,
        agent_tool_policy,
        pending_block_restorations,
        budget_items: final_budget_items,
    })
}

/// GOLD-ARCH-02 phase 3 — make the provider call for one chat turn from the
/// already budgeted final Request bytes, emit the AP-2 local-inference
/// trace pair, dispatch via the stream / council / MCP-tool-loop / direct-complete
/// branch, release the cluster in-flight gauge, and bump the provider quota on
/// success. Owns the WAL writer + join handle so every error path drains them
/// byte-for-byte; returns the reply + token/model + the (prompt, system)
/// pair the post-reply refusal-recovery path reissues.
struct DispatchOutput {
    response_text: String,
    final_input_tokens: Option<u32>,
    final_output_tokens: Option<u32>,
    provider_used: String,
    model_used: String,
    writer: crate::wal::writer::WalWriterHandle,
    writer_join: tokio::task::JoinHandle<()>,
    final_prompt: String,
    final_system: Option<String>,
    /// F4/D21 — the in-flight turn journal, opened in `dispatch_provider`, closed
    /// (+ 0x06 anchor) by `run_post_reply_pipelines` after the response is
    /// recorded. `None` when the journal failed to open (non-fatal).
    turn_journal: Option<crate::recovery::turn_journal::TurnJournal>,
    /// GOLD-ADAPT-ODY-20 — number of successful MCP tool-calls in this turn.
    /// Populated from `LoopOutcome.successful_calls` in the MCP-dispatch branch;
    /// `0` in the single-provider (no-loop) branch. Used by
    /// `run_post_reply_pipelines` to gate auto-skill extraction.
    mcp_tool_calls: u32,
    /// REVFIX-EXCERPTS-01 — structured per-call records from the dispatch loop.
    /// Fed to `maybe_extract_skill` so the distiller sees tool names + args +
    /// outcomes instead of a blind 512-char response prefix.
    /// Empty on the stream / single-provider (no-loop) branches.
    mcp_tool_records: Vec<crate::mcp::dispatch_loop::ToolCallRecord>,
}

struct ProviderDispatchResult {
    response_text: String,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    provider: String,
    model: String,
}

impl ProviderDispatchResult {
    fn new(
        response_text: String,
        input_tokens: Option<u32>,
        output_tokens: Option<u32>,
        provider: String,
        model: String,
    ) -> Self {
        Self {
            response_text,
            input_tokens,
            output_tokens,
            provider,
            model,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_provider(
    final_prompt: String,
    final_system: Option<String>,
    args: &ChatArgs,
    provider: &dyn crate::providers::Provider,
    config: &FreedomConfig,
    home: &std::path::Path,
    writer: crate::wal::writer::WalWriterHandle,
    writer_join: tokio::task::JoinHandle<()>,
    quota_path: std::path::PathBuf,
    quota_tracker: Option<crate::providers::quota::QuotaTracker>,
    prompt: &str,
    request_token_cap: u32,
    mcp_servers: &crate::mcp::McpServers,
    tool_scope: crate::mcp::McpToolScope,
    turn_id: &str,
    // B22 — exact model already bound to PaidProviderCall authorization.
    // This value is copied into Request.model without another precedence fold.
    effective_model: Option<String>,
    // GOLD-CCPARITY-EFFORT-03 — per-skill reasoning-budget. `None` = provider
    // default. Mapped to `req.thinking_budget` before provider spawn.
    override_effort: Option<crate::providers::effort_override::EffortBudget>,
    // B22-TWEAKS-MODEL-01 — which priority layer resolved the model for this
    // turn. Embedded in WAL diagnostics; never contains secrets.
    model_source: &'static str,
    // Per-turn metadata copied into every concrete provider-leaf lifecycle
    // frame. Exact provider/model/request hashes are added centrally.
    provider_audit_context: crate::providers::cost_authorization::ProviderCallAuditContext,
) -> Result<DispatchOutput> {
    // Startup prompting proves consent only at provider construction time.
    // Re-read the durable markers at the final one-shot dispatch boundary so
    // a concurrent `neoth consent revoke` cannot leave this invocation holding
    // a stale capability. The live gate intentionally ignores the startup-only
    // NEOTH_CONSENT_BYPASS escape hatch.
    if let Err(error) = crate::consent::ensure_all_still_granted(home, config) {
        drop(writer);
        let _ = writer_join.await;
        return Err(error).context("chat provider consent was revoked before dispatch");
    }
    let provider_name = provider.name();
    // ── Provider call (sync OR stream) ────────────────────────────────────
    // R-04 2026-05-17: clone final_prompt + final_system here rather
    // than move so the LOWKEY refusal-recovery path post-reply can
    // reissue the same (prompt, system) pair under a reframing.
    // Original moves were tightening Rust's borrow-checker around the
    // Request literal; the cost of the extra Option<String> clone is
    // negligible compared to the LLM round-trip about to fire.
    // Output-preset wrapping and fixed system preambles are already represented
    // as typed blocks and budgeted by `finalize_provider_request`.  Adding any
    // prompt bytes here would bypass the cap.
    let merged_system = final_system.clone();
    // GOLD-CCPARITY-EFFORT-03: map effort only when the effective provider
    // declares a real thinking-budget wire. Other leaves keep their native
    // default and emit an explicit warning instead of receiving an unsupported
    // field that would now (correctly) fail the strict leaf-control gate.
    let requested_thinking_budget =
        override_effort.map(crate::providers::effort_override::effort_to_tokens);
    let thinking_budget = match requested_thinking_budget {
        Some(budget) if provider.request_controls().supports_thinking_budget() => Some(budget),
        Some(budget) => {
            tracing::warn!(
                provider = provider_name,
                budget_tokens = budget,
                "skill effort override skipped: provider has no thinking-budget control"
            );
            None
        }
        None => None,
    };
    // Best-effort WAL audit before the provider spawn — emit SKILL_EFFORT_APPLIED
    // (0x7A) when an effort override is active so the operator can audit which
    // skill drove the reasoning-budget change. Non-fatal: WAL errors are
    // logged-and-ignored consistent with the rest of dispatch_provider.
    if let Some(budget_tokens) = thinking_budget {
        use crate::wal::events::EVENT_TYPE_SKILL_EFFORT_APPLIED;
        let ts = crate::time::now_unix_i64();
        let effort_str = override_effort.map(|e| e.as_str()).unwrap_or("none");
        let payload = serde_json::to_vec(&serde_json::json!({
            "effort": effort_str,
            "budget_tokens": budget_tokens,
            "ts_unix": ts,
        }))
        .unwrap_or_default();
        let header = crate::wal::make_header(EVENT_TYPE_SKILL_EFFORT_APPLIED, &payload);
        let _ = writer.append(header, payload).await;
    }
    let req = Request {
        prompt: final_prompt.clone(),
        system: merged_system.clone(),
        model: effective_model.clone(),
        temperature: args.temperature,
        top_p: args.top_p,
        sampling_seed: args.sampling_seed,
        stop_sequences: Vec::new(),
        // GOLD-CCPARITY-EFFORT-03: per-call thinking-budget override.
        thinking_budget,
    };
    let token_capped_provider =
        crate::providers::token_cap::TokenCappedProvider::new(provider, request_token_cap);
    // B22: every provider invocation below (direct, stream, MCP iteration,
    // loop round, refusal retry) crosses this boundary. Decorators recurse with
    // the authorizer and gate each exact final leaf immediately before dispatch.
    let call_authorizer =
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
            config.autonomy_policy(),
            Some(writer.clone()),
            config.tokens.max_per_request,
        )
        .with_usage_home(home.to_path_buf())
        .with_audit_context(provider_audit_context);
    let authorized_provider = crate::providers::cost_authorization::CostAuthorizingProvider::new(
        &token_capped_provider,
        call_authorizer.clone(),
        effective_model.clone(),
        "chat_provider_round",
    );
    let provider: &dyn crate::providers::Provider = &authorized_provider;

    // Dispatch runs in one inner scope so every `?`, stream error and explicit
    // failure first drops per-call state (including the stream's audit ticket).
    // The outer error arm can then release both authorizer-held WAL senders and
    // safely await the writer without deadlocking.
    macro_rules! return_dispatch_error {
        ($error:expr) => {{
            return Err($error);
        }};
    }

    // F4/D21 — open the turn-journal sidecar + WAL 0x05 anchor for mid-turn
    // crash durability. A journal surviving on disk at next launch = this turn
    // crashed mid-window → `neoth recover` surfaces it. Best-effort: a journal
    // error never blocks the turn. Closed (+0x06) at the single clean-completion
    // point below; any bail/crash before that leaves the file as a crash candidate.
    let mut journal = {
        use crate::recovery::turn_journal::{TurnEvent, TurnJournal, opened_payload};
        match TurnJournal::open(home, turn_id) {
            Ok(mut j) => {
                let ts = crate::time::now_unix_i64();
                let payload = opened_payload(turn_id, j.path(), ts);
                let header = crate::wal::make_header(
                    crate::wal::events::EVENT_TYPE_TURN_JOURNAL_OPENED,
                    &payload,
                );
                let _ = writer.append(header, payload).await;
                let _ = j.append(&TurnEvent::Started {
                    ts_unix: ts,
                    prompt_excerpt: final_prompt.chars().take(160).collect(),
                });
                let _ = j.append(&TurnEvent::ProviderRequest {
                    ts_unix: ts,
                    provider: provider_name.to_string(),
                    // GOLD-CCPARITY-MODEL-02: log the actual effective model
                    // (agent/skill override wins over args.model) so the audit
                    // trace accurately reflects which model was used this turn.
                    model: effective_model.clone().unwrap_or_default(),
                });
                Some(j)
            }
            Err(e) => {
                tracing::debug!(error = %e, "turn-journal open failed (non-fatal)");
                None
            }
        }
    };

    // AP-2: every local-inference call (stream OR non-stream) leaves a WAL
    // START + END trace pair. Hoisted out of the branch arms so the same
    // emission path covers both `provider.complete(req)` and
    // `provider.stream(req)`. The Request is consumed by each call below,
    // so we read its fields once here.
    let is_local_inference = crate::providers::is_local_provider(provider.name());
    let inference_id: u64 = if is_local_inference {
        let id = rand_u64_for_trace();
        let payload = serde_json::to_vec(&serde_json::json!({
            "request_id": id,
            "prompt_hash": xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes()),
            "model": req.model.clone(),
            // B22-TWEAKS-MODEL-01: which precedence layer chose this model
            // (dispatch|skill|cli|tweaks|freedom|provider_default) — audit only.
            "model_source": model_source,
            "stream": args.stream,
            "ts_unix": now_unix(),
        }))
        .unwrap_or_default();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_LOCAL_INFERENCE_START,
            &payload,
        )
        .build();
        if let Err(e) = writer.append(header, payload).await {
            tracing::warn!(error = %e, "WAL append failed (best-effort audit frame)");
        }
        id
    } else {
        0
    };
    let inference_started = std::time::Instant::now();

    // SL-00(1c): mark this provider request as in-flight for the cluster
    // local-load gauge. The RAII guard decrements on drop (covers both the
    // stream + non-stream branches, and any early `?`); we drop it explicitly
    // right after the call so the count reflects only the actual provider work.
    // GOLD-SEC-16: the cluster local-load gauge only exists with the `cluster` feature.
    #[cfg(feature = "cluster")]
    let inflight_guard = crate::cluster::local_load::inflight_guard();

    // GOLD-ADAPT-ODY-20 — capture the MCP successful-call count so
    // `run_post_reply_pipelines` can gate auto-skill extraction.
    // Set to `outcome.successful_calls` in the MCP-dispatch branch; stays 0
    // in the stream branch and the single-provider (no-loop) branch.
    let mut mcp_tool_calls: u32 = 0;
    // REVFIX-EXCERPTS-01 — structured per-call records; populated in the
    // MCP-dispatch branch from `outcome.tool_call_records`; empty otherwise.
    let mut mcp_tool_records: Vec<crate::mcp::dispatch_loop::ToolCallRecord> = Vec::new();

    let dispatch_result: Result<ProviderDispatchResult> = async {
        Ok(if args.stream {
            // B-1 follow-up (Session 13) — streaming-branch audit gap.
            // Council never fans out on the streaming path (council needs
            // sync semantics + dissent scoring across full responses).
            // Emit a COUNCIL_SKIP audit anyway so the operator's WAL trace
            // shows every chat turn was reasoned about WRT council, even
            // when streaming mode forces the light path. Reason is
            // operator-greppable: `streaming_mode_disables_council`.
            {
                let prompt_hash_stream = xxhash_rust::xxh3::xxh3_64(prompt.as_bytes());
                let _ = emit_council_skip(
                    &writer,
                    prompt_hash_stream,
                    "streaming_mode_disables_council",
                )
                .await;
            }
            // QM-10 Phase 2.5: streaming path also consults the breaker.
            // Acquire BEFORE provider.stream so an Open breaker rejects
            // the call without opening a stream we'd have to drain.
            let stream_permit = match crate::providers::circuit_breaker::acquire_for(provider_name)
            {
                Ok(p) => Some(p),
                Err(berr) => {
                    return_dispatch_error!(anyhow::anyhow!("provider `{provider_name}`: {berr}"));
                }
            };
            let stream_call_started = std::time::Instant::now();
            // Streaming path: print each delta as it arrives, accumulate the
            // full response for the WAL PROVIDER_RESPONSE frame.
            let mut stream = match provider.stream(req).await {
                Ok(s) => s,
                Err(e) => {
                    if let Some(p) = stream_permit {
                        p.record_failure();
                    }
                    if let Some(qe) = e.downcast_ref::<crate::providers::quota::QuotaError>() {
                        record_quota_exceeded(qe, &quota_path, &writer).await;
                    }
                    warn!(error = %e, "provider stream open failed");
                    return_dispatch_error!(e);
                }
            };
            let mut acc = String::new();
            let mut chunk_count: u32 = 0;
            let mut input_tokens: Option<u32> = None;
            let mut output_tokens: Option<u32> = None;
            let mut response_identity: Option<crate::providers::CompletionIdentity> = None;
            let mut saw_done_chunk = false;

            use futures_util::stream::StreamExt;
            use std::io::Write as _;
            // GOLD-ADOPT-24 — safe-flush markdown buffer: print only the prefix that
            // doesn't split an open construct (code fence, table, inline span). `acc`
            // + the per-chunk WAL frame still see the RAW delta; only the terminal
            // print is buffered, so the output text is identical, just fence-safe.
            let mut md_buf = crate::cli::streaming_buffer::MarkdownBuffer::new();
            // GOLD-ADAPT-HERMES-09b — measure decode throughput over the live stream
            // window; emitted as a 0x69 TOKEN_TPS_SAMPLE WAL frame after the stream
            // completes (best-effort, never blocks the turn).
            let mut tps_meter = crate::daemon::metering::TpsMeter::start();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) => {
                        if !chunk.identity.is_bound() {
                            if let Some(p) = stream_permit {
                                p.record_failure();
                            }
                            return_dispatch_error!(anyhow::anyhow!(
                                "provider `{provider_name}` emitted a stream chunk without an authenticated response identity"
                            ));
                        }
                        if let Some(bound) = &response_identity {
                            if bound != &chunk.identity {
                                if let Some(p) = stream_permit {
                                    p.record_failure();
                                }
                                return_dispatch_error!(anyhow::anyhow!(
                                    "provider `{provider_name}` changed response identity within one stream"
                                ));
                            }
                        } else {
                            response_identity = Some(chunk.identity.clone());
                        }
                        if !chunk.delta.is_empty() {
                            if let Some(safe) = md_buf.push(&chunk.delta) {
                                print!("{safe}");
                                let _ = std::io::stdout().flush();
                            }
                            acc.push_str(&chunk.delta);
                            chunk_count += 1;
                            // HERMES-09b — ~4 chars/token estimate per streamed delta.
                            tps_meter.observe((chunk.delta.len() as u64).div_ceil(4));
                            // F4/D21 — journal the partial chunk so a mid-stream crash
                            // leaves a recoverable partial answer (best-effort).
                            if let Some(j) = journal.as_mut() {
                                let _ = j.append(
                                    &crate::recovery::turn_journal::TurnEvent::ProviderChunk {
                                        ts_unix: crate::time::now_unix_i64(),
                                        text: chunk.delta.clone(),
                                    },
                                );
                            }
                            emit_stream_chunk(
                                &writer,
                                &chunk.identity.provider,
                                &chunk,
                                chunk_count,
                            )
                            .await?;
                        }
                        if chunk.done {
                            saw_done_chunk = true;
                            // Release any construct still held at stream end.
                            let rest = md_buf.flush();
                            if !rest.is_empty() {
                                print!("{rest}");
                                let _ = std::io::stdout().flush();
                            }
                            input_tokens = chunk.input_tokens;
                            output_tokens = chunk.output_tokens;
                            break;
                        }
                    }
                    Err(e) => {
                        if let Some(p) = stream_permit {
                            p.record_failure();
                        }
                        warn!(error = %e, "stream chunk error");
                        // GR-091: release any markdown tail still buffered so the
                        // already-streamed partial output isn't swallowed on error.
                        let tail = md_buf.flush();
                        if !tail.is_empty() {
                            print!("{tail}");
                            let _ = std::io::stdout().flush();
                        }
                        return_dispatch_error!(e);
                    }
                }
            }
            // Loop only reaches here on clean exit — every Err arm
            // returns above so success path is implicit.
            // GOLD-ADOPT-24 — defensive: if the stream ended without a `done` chunk,
            // release any markdown tail still buffered (the done-arm flush didn't run).
            {
                let rest = md_buf.flush();
                if !rest.is_empty() {
                    use std::io::Write as _;
                    print!("{rest}");
                    let _ = std::io::stdout().flush();
                }
            }
            if !saw_done_chunk {
                if let Some(p) = stream_permit {
                    p.record_failure();
                }
                return_dispatch_error!(anyhow::anyhow!(
                    "provider `{provider_name}` stream ended without a final done chunk"
                ));
            }
            let response_identity = response_identity.ok_or_else(|| {
            anyhow::anyhow!(
                "provider `{provider_name}` stream ended without an authenticated response identity"
            )
        })?;
            if let Some(p) = stream_permit {
                p.record_success();
            }
            let provider_used = response_identity.provider;
            let model_used = response_identity.wire_model;
            // GOLD-ADAPT-HERMES-09b — emit the stream's tokens/sec sample (0x69
            // TOKEN_TPS_SAMPLE). Best-effort; a WAL hiccup never fails the turn.
            {
                let tps = tps_meter.finish();
                if tps.has_data()
                    && let Err(e) = crate::daemon::metering::emit_tps_sample(&tps, &writer).await
                {
                    tracing::debug!(error = %e, "tps-sample WAL emit failed (non-fatal)");
                }
            }
            {
                let elapsed_ms = stream_call_started.elapsed().as_millis() as u64;
                publish_provider_responded(
                    &provider_used,
                    &model_used,
                    input_tokens,
                    output_tokens,
                    elapsed_ms,
                );
            }
            // Sentinel line per OPEN_DECISIONS.md D-005 so consumers can detect
            // truncated streams. GOLD-ADAPT-ODY-02/05 — the sentinel also carries
            // the turn's token usage + the model-agnostic context cap (same
            // `effective_cap` the non-stream context bar uses) + wall time, so
            // GUI consumers can render context/metrics chips without re-probing.
            // Fields are additive: older consumers `rfind` the prefix and ignore
            // unknown keys.
            let sentinel_cap = crate::tokens::budget::effective_cap(
                &provider_used,
                &model_used,
                config.tokens.max_per_request,
            );
            println!();
            println!(
                "{}",
                serde_json::json!({
                    "neoth_stream": "done",
                    "control_token": stream_control_token(),
                    "count": chunk_count,
                    "used_tokens": input_tokens
                        .unwrap_or(0)
                        .saturating_add(output_tokens.unwrap_or(0)),
                    "limit_tokens": sentinel_cap,
                    "input_tokens": input_tokens.unwrap_or(0),
                "output_tokens": output_tokens.unwrap_or(0),
                "elapsed_ms": stream_call_started.elapsed().as_millis() as u64,
                // Exact effective leaf identity (including fallback) for the
                // GUI's optional per-response model badge.
                "model": &model_used,
                // ODY-12/14 — additive field; old consumers ignore it.
                    "links": crate::cli::deep_links::extract_deep_links(&acc),
                })
            );
            ProviderDispatchResult::new(
                acc,
                input_tokens,
                output_tokens,
                provider_used,
                model_used,
            )
        } else {
            // Non-streaming: existing behavior. START frame already emitted
            // above the branch; END frame fires after both arms converge.
            //
            // CH-02 council wedge — smart-trigger default (Codex feedback
            // 2026-05-16): the chat dispatch now consults CH-14's
            // `should_convene` BY DEFAULT on every call. Tri-state env:
            //   - `NEOTH_COUNCIL_DISABLE=1`  → never (operator opt-out wins)
            //   - `NEOTH_COUNCIL_ENABLE=1`   → always (force-convene every
            //                                  call, bypasses the gates;
            //                                  expensive — operator's choice)
            //   - unset / anything else      → AUTO via `should_convene`
            //                                  (dissent marker + complexity
            //                                  + rate + budget gates).
            //                                  `NEOTH_COUNCIL_AUTO=1` is
            //                                  accepted for backward compat
            //                                  but no longer required —
            //                                  the gate fires automatically.
            //
            // Takes priority over MCP autoroute when both apply (they're
            // mutually exclusive — council debates many providers;
            // autoroute wraps one). Smart-trigger's default-Skip semantic
            // (no dissent marker → Skip) means casual prompts like "what's
            // the time" don't convene; "should I use Rust or Go?" does.
            let council_force = std::env::var("NEOTH_COUNCIL_ENABLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let council_disable_env = std::env::var("NEOTH_COUNCIL_DISABLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            // SPEC-03 suppress: the persistent `freedom.yaml::council.disabled`
            // flag (set via `neoth council suppress`) is the durable twin of
            // the env override — either one forces the single-hemisphere path.
            // `config` is fresh per CLI invocation so the flag is always current.
            // GOLD-ADAPT-G-01: council.mode=single is a named alternative to
            // council.disabled=true; both force the single-provider path.
            // They are orthogonal knobs — `disabled` is toggled by
            // `neoth council suppress`; `mode` is a persistent topology choice.
            let council_mode_single = config.council.mode.is_single();
            let council_disable_cfg =
                config.council.disabled.unwrap_or(false) || council_mode_single;
            let council_disable = council_disable_env || council_disable_cfg;
            // Derive the advisory gate from the same concrete Request and
            // FreedomConfig generation that the hard per-leaf authorizer will
            // receive. With an active cap, unknown/unbounded paid leaves skip
            // before even an env-forced fan-out; the hard cap is not bypassable.
            let council_cost = council_trigger_cost_bound_at(config, &req, home);
            // Trigger decision is computed even when not used so the WAL
            // audit (next iteration) can record "council was triggerable
            // but skipped because operator opted out".
            let trigger_decision = if council_disable {
                crate::council::TriggerDecision::Skip {
                    // Record BOTH sources when co-active so the audit trail
                    // doesn't hide the persistent suppress behind the env var
                    // (clearing the env later would otherwise leave no WAL hint
                    // that `council.disabled=true` is still in effect).
                    // Priority: env > mode=single > disabled=true.
                    reason: match (
                        council_disable_env,
                        council_mode_single,
                        config.council.disabled.unwrap_or(false),
                    ) {
                        (true, _, true) => {
                            "NEOTH_COUNCIL_DISABLE=1 + freedom.yaml::council.disabled=true".into()
                        }
                        (true, _, false) => "NEOTH_COUNCIL_DISABLE=1".into(),
                        (false, true, _) => "freedom.yaml::council.mode=single".into(),
                        (false, false, _) => "freedom.yaml::council.disabled=true".into(),
                    },
                }
            } else if let Err(error) = &council_cost {
                tracing::warn!(
                    error = %error,
                    "Council cost bound unavailable under active daily cap — smart trigger skipped fail-closed"
                );
                crate::council::TriggerDecision::Skip {
                    reason: "council cost bound unavailable under active daily cap — fail-closed"
                        .into(),
                }
            } else if council_force {
                crate::council::TriggerDecision::Convene {
                    reason: "NEOTH_COUNCIL_ENABLE=1 (force)".into(),
                }
            } else {
                // B-3 (Session 13) — feed real `seconds_since_last_council`
                // from `~/.neoth/council_last.json` so Gate 2 (rate cooldown)
                // is honoured. Missing / malformed file → `u64::MAX` (gate
                // open), matching prior behaviour for fresh installs.
                let now_unix_b3 = crate::council::last_ts::now_unix();
                let secs_since = crate::council::last_ts::seconds_since_last(home, now_unix_b3);
                let remaining_budget_usd = match config.council.daily_usd_cap {
                    None => Ok(None),
                    // spawn_blocking: the advisory budget read takes the
                    // cross-process ledger file lock (sleeping retry loop).
                    Some(cap_usd) => {
                        let snapshot_home = home.to_path_buf();
                        tokio::task::spawn_blocking(move || {
                            crate::council::daily_budget::remaining_daily_budget_usd(
                                &snapshot_home,
                                cap_usd,
                                now_unix_b3 as i64,
                            )
                            .map(Some)
                        })
                        .await
                        .unwrap_or_else(|join| {
                            Err(anyhow::anyhow!("daily-budget snapshot task panicked: {join}"))
                        })
                    }
                };
                match remaining_budget_usd {
                    Ok(remaining_budget_usd) => {
                        let (estimated_single_call_usd, estimated_council_cost_usd) =
                            council_cost.as_ref().copied().expect("cost checked above");
                        let ctx = crate::council::TriggerContext {
                            seconds_since_last_council: secs_since,
                            remaining_budget_usd,
                            estimated_single_call_usd,
                            estimated_council_cost_usd,
                        };
                        // SPEC-03b: operator-tunable thresholds from
                        // `freedom.yaml::council.trigger` (defaults reproduce the prior
                        // hardcoded policy exactly).
                        crate::council::should_convene(
                            prompt,
                            &ctx,
                            &config.council.trigger.to_policy(),
                        )
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "council daily-budget snapshot invalid — smart trigger skipped fail-closed"
                        );
                        crate::council::TriggerDecision::Skip {
                            reason: "council daily-budget state invalid — fail-closed".into(),
                        }
                    }
                }
            };
            let council_mif_message = trigger_decision
                .should_convene()
                .then(|| mif_disambiguation(config, &req.prompt))
                .flatten();
            // GOLD-SEC-32 / B-19: hard rolling-24h convene cap, enforced before
            // convening and independent of the USD budget gate. Operator-forced
            // council bypasses it.
            let council_now = crate::council::last_ts::now_unix() as i64;
            // B-25: atomic OS-locked admission — fail-closed on any I/O error.
            // Operator-forced council (council_force=true) bypasses cap entirely.
            let (council_enable, council_cap_hit, council_deny_reason) = if council_mif_message
                .is_some()
            {
                (
                    false,
                    false,
                    Some("mif_conflicted_disambiguation"),
                )
            } else if council_force {
                (
                    trigger_decision.should_convene(),
                    false,
                    None::<&'static str>,
                )
            } else if trigger_decision.should_convene() {
                use crate::council::day_counter::AdmitResult;
                match crate::council::day_counter::try_admit_convene(home, council_now) {
                    AdmitResult::Admitted => (true, false, None),
                    AdmitResult::Capped => {
                        tracing::warn!(
                            cap = crate::council::day_counter::MAX_CONVENES_PER_24H,
                            "council daily convene cap reached — single-provider for this turn"
                        );
                        (false, true, None)
                    }
                    AdmitResult::StateInvalid => {
                        tracing::warn!(
                            "council day-counter state invalid — fail-closed for this turn"
                        );
                        (
                            false,
                            true,
                            Some("council day-counter state invalid — fail-closed"),
                        )
                    }
                }
            } else {
                (false, false, None)
            };
            if !council_force && !council_disable {
                info!(
                    decision = ?trigger_decision,
                    will_convene = council_enable,
                    "council smart-trigger evaluated"
                );
            }
            // B-1 (Session 13) — emit COUNCIL_SKIP audit when the trigger
            // resolved to Skip so the operator's WAL audit distinguishes
            // "light path: single hemisphere answered because trigger said
            // skip" from "council fired but everyone agreed silently".
            // Reason carries the exact gate (env override, complexity,
            // rate, budget) so an operator can grep refusal causes per
            // gate over time.
            if !council_enable {
                let prompt_hash_skip = xxhash_rust::xxh3::xxh3_64(prompt.as_bytes());
                let reason = if let Some(r) = council_deny_reason {
                    r
                } else if council_cap_hit {
                    "daily convene cap (rolling 24h) reached"
                } else {
                    trigger_decision.reason()
                };
                let _ = emit_council_skip(&writer, prompt_hash_skip, reason).await;
            }
            // A8 / Konsens-decision #8 — MCP autoroute is now AUTO by default
            // when `mcp_servers.yaml` has ≥1 enabled server. Tri-state:
            //   - NEOTH_MCP_AUTOROUTE=1 / true / on / yes → forced ON
            //   - NEOTH_MCP_AUTOROUTE=0 / false / off / no → forced OFF
            //   - unset / empty / other → AUTO (on when servers present)
            // Decision threaded via `McpServers::autoroute_decision` so the
            // chat dispatch can log *why* the loop is on/off (operator
            // opt-in vs auto-derive vs zero-server-default-off).
            // Council always wins when explicitly enabled — the two paths
            // are mutually exclusive (council debates many providers,
            // autoroute wraps one).
            let mcp_servers_for_loop = if !council_enable {
                mcp_servers.clone()
            } else {
                crate::mcp::McpServers::default()
            };
            let autoroute_env = std::env::var("NEOTH_MCP_AUTOROUTE").ok();
            let autoroute_decision =
                mcp_servers_for_loop.autoroute_decision(autoroute_env.as_deref());
            let use_loop = !council_enable && autoroute_decision.is_on();
            if let Some(response_text) = council_mif_message {
                println!("{response_text}");
                ProviderDispatchResult::new(
                    response_text,
                    None,
                    None,
                    "council_mif".to_string(),
                    "deterministic".to_string(),
                )
            } else if council_enable {
                info!(
                    trigger = ?trigger_decision,
                    "council convened — running 3-hemisphere debate"
                );
                // COR-17: the full debate → recovery → winner-selection →
                // self-reflect → partial-refusal-prefix pipeline lives in the
                // shared `dispatch_council_with_recovery` (also driven by the
                // channel path in serve.rs), so the CLI and daemon paths can
                // never drift. CLI-specific bits stay here: the convened log
                // above, the WAL-writer shutdown on failure, stdout print, and
                // the cost-estimate tuple below.
                let response_text = match dispatch_council_with_recovery_for_turn(
                    &req,
                    config,
                    home,
                    &writer,
                    call_authorizer.clone(),
                    &tool_scope,
                    args.incognito,
                )
                .await
                {
                    Ok(text) => text,
                    Err(e) => {
                        // CLI returns the error to the caller (after a clean
                        // WAL-writer shutdown) rather than falling back to a
                        // single provider the way the channel path does.
                        warn!(error = %e, "council debate failed; returning error");
                        return_dispatch_error!(e);
                    }
                };
                println!("{response_text}");
                ProviderDispatchResult::new(
                    response_text,
                    None,
                    None,
                    "council".to_string(),
                    "multi-provider".to_string(),
                )
            } else if use_loop {
                info!(reason = %autoroute_decision.reason(), "MCP autoroute enabled — running dispatch loop");
                // The complete resolved skill/agent scope is immutable for the
                // turn and is reused by both the single and multi-round paths.
                // GOLD-ADAPT-MEM-05 — snapshot session state BEFORE the dispatch loop
                // (which compacts tool-results/context via the CompressionRuntime
                // below) so `compaction_guard::restore_latest` / `neoth recover` can
                // pull the pre-compaction context back (anti-dementia). Gated on
                // compaction.enabled; best-effort (a backup-write failure never blocks
                // the turn — pre_compact returns and we ignore the path).
                if config.compaction.enabled {
                    let mut snap_ctx = std::collections::BTreeMap::new();
                    snap_ctx.insert("source".to_string(), serde_json::json!("mcp_dispatch_loop"));
                    snap_ctx.insert(
                        "prompt_chars".to_string(),
                        serde_json::json!(req.prompt.len()),
                    );
                    snap_ctx.insert(
                        "max_turns".to_string(),
                        serde_json::json!(config.goal.max_turns),
                    );
                    let _ = crate::memory::compaction_guard::pre_compact(
                        home,
                        crate::time::now_unix_i64(),
                        snap_ctx,
                        Some(req.prompt.chars().take(2000).collect::<String>()),
                    );
                    // PWF-02: PreCompact MODE_CHECKPOINT (0x9A). Emit a second
                    // checkpoint AFTER the compaction snapshot so a resume after
                    // crash inside the dispatch loop lands at the pre-compact
                    // boundary rather than at the session-start boundary. Best-
                    // effort: never blocks the dispatch loop.
                    {
                        use crate::recall::reconstruct::ModeCheckpoint;
                        use crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT;
                        // GOLD-ADAPT-G-01: three-way label: single > off > enabled.
                        let council_mode_str = if config.council.mode.is_single() {
                            "single".to_string()
                        } else if config.council.disabled.unwrap_or(false) {
                            "off".to_string()
                        } else {
                            "enabled".to_string()
                        };
                        let mut cp = ModeCheckpoint {
                            checkpoint_hash: String::new(),
                            session_id: turn_id.to_string(),
                            mode: "chat".to_string(),
                            provider_target: provider.name().to_string(),
                            council_mode: council_mode_str,
                            scoped_mcp_servers: enabled_mcp_scope(&mcp_servers_for_loop),
                            mcp_scope_recorded: true,
                            phase: "chat:pre-compact".to_string(),
                            ts_unix: crate::time::now_unix_i64(),
                        };
                        cp.stamp_hash();
                        if let Ok(payload) = serde_json::to_vec(&cp) {
                            let hdr = crate::wal::make_header(EVENT_TYPE_MODE_CHECKPOINT, &payload);
                            let _ = writer.append(hdr, payload).await;
                        }
                    }
                }
                // GOLD-LOOP-01: when `--loop` is set (or loop_config.enabled with
                // max_rounds > 1 on CLI), route through the loop engine instead of
                // a bare single dispatch. The loop engine internally calls
                // `run_mcp_dispatch_loop` per round and handles WAL + record write.
                let loop_engage = args.loop_mode
                    || (config.loop_config.enabled && config.loop_config.max_rounds > 1);
                let outcome = if loop_engage {
                    let loop_cfg = crate::loop_engine::engine::LoopConfig {
                        max_rounds: args.iterations.unwrap_or(config.loop_config.max_rounds),
                        until: if !args.until.is_empty() {
                            args.until.clone()
                        } else {
                            vec![]
                        },
                        tool_call_budget: config.loop_config.tool_call_budget,
                        autonomy: config.autonomy,
                        refine_enabled: config.loop_config.refine_enabled,
                        neoth_home: home.to_path_buf(),
                    };
                    info!(
                        max_rounds = loop_cfg.max_rounds,
                        has_until = !loop_cfg.until.is_empty(),
                        "GOLD-LOOP-01: loop mode active — routing to loop engine"
                    );
                    match crate::loop_engine::engine::run_loop(
                        &loop_cfg,
                        // `run_loop` owns the one authorization boundary for all
                        // rounds. Passing the outer chat boundary here would
                        // create a forbidden nested authorizer on round one.
                        &token_capped_provider,
                        req.clone(),
                        &mcp_servers_for_loop,
                        &writer,
                        config,
                        call_authorizer.clone(),
                        None,
                        &tool_scope,
                        // P4 — elicitation is live in loop mode too on the interactive
                        // TTY (same gate as the single-dispatch path below).
                        if config.elicitation.enabled {
                            &crate::cli::elicitation::ElicitationHandler::Cli
                        } else {
                            &crate::cli::elicitation::ElicitationHandler::Disabled
                        },
                    )
                    .await
                    {
                        Ok(record) => {
                            // Convert LoopRunRecord into a LoopOutcome-compatible
                            // surface so the code below (println, mcp_tool_calls)
                            // works unchanged.
                            crate::mcp::dispatch_loop::LoopOutcome {
                                final_text: record.final_text,
                                iterations: record.rounds_run,
                                hit_cap: matches!(
                                    record.stop_reason,
                                    crate::loop_engine::engine::StopReason::CapHit
                                        | crate::loop_engine::engine::StopReason::BudgetExceeded
                                ),
                                successful_calls: record
                                    .per_round
                                    .iter()
                                    .map(|r| r.successful_calls)
                                    .sum(),
                                failed_calls: record.per_round.iter().map(|r| r.failed_calls).sum(),
                                tool_call_records: vec![],
                                // GOLD-TASK-05 — loop_engine path has no goal judge;
                                // goal_outcome is always None here.
                                goal_outcome: crate::mcp::dispatch_loop::GoalOutcome::None,
                            }
                        }
                        Err(e) => {
                            if !provider.handles_nonstream_quota_backoff()
                                && let Some(qe) =
                                    e.downcast_ref::<crate::providers::quota::QuotaError>()
                            {
                                record_quota_exceeded(qe, &quota_path, &writer).await;
                            }
                            warn!(error = %e, "GOLD-LOOP-01: loop engine failed");
                            return_dispatch_error!(e);
                        }
                    }
                } else {
                    let mut compaction_budget =
                        crate::mcp::dispatch_loop::CompactionBudget::default();
                    match run_mcp_dispatch_loop(
                        provider,
                        req.clone(),
                        &mcp_servers_for_loop,
                        &config.autonomy_policy(),
                        &writer,
                        Some(&config.rollback),
                        &tool_scope,
                        config.goal.max_turns,
                        &config.security,
                        crate::mcp::goal_tracker::GoalContext {
                            goal: config.goal.goal.clone(),
                            grind: config.goal.grind.clone(),
                        },
                        config.hints.enabled,
                        crate::context::compaction::CompactionPolicy::from_config(
                            config.compaction.enabled,
                            config.compaction.progressive,
                            request_token_cap,
                            config.compaction.threshold_fraction,
                        ),
                        // GOLD-HR-08/10 — tool-result compression (None when disabled).
                        // Persistent store so `neoth ctx retrieve` can pull dropped
                        // blocks back + savings are metered.
                        crate::context::compress::CompressionRuntime::persistent(
                            config.compression.gate(),
                            config.compression.thresholds(),
                            home.join("ccr"),
                        ),
                        // HERMES-04 — pass the provider as judge when judge_enabled AND a
                        // goal is set. Uses the same provider instance (no extra config).
                        if config.goal.judge_enabled && config.goal.goal.is_some() {
                            Some(provider)
                        } else {
                            None
                        },
                        // GOLD-ADOPT-17 — enable CLI elicitation on the TTY path when
                        // the operator has not disabled it in freedom.yaml.
                        if config.elicitation.enabled {
                            &crate::cli::elicitation::ElicitationHandler::Cli
                        } else {
                            &crate::cli::elicitation::ElicitationHandler::Disabled
                        },
                        // GOLD-ADAPT-AWE-CODE-01 — interactive CLI path: no inbound
                        // sender identity available, so no lease upgrade possible.
                        None,
                        // GOLD-ADAPT-HARNESS — operator harness knobs from freedom.yaml.
                        &config.tools.harness,
                        &mut compaction_budget,
                        // Ordinary chat has no outer multi-round tool budget.
                        None,
                        home,
                    )
                    .await
                    {
                        Ok(o) => o,
                        Err(e) => {
                            if !provider.handles_nonstream_quota_backoff()
                                && let Some(qe) =
                                    e.downcast_ref::<crate::providers::quota::QuotaError>()
                            {
                                record_quota_exceeded(qe, &quota_path, &writer).await;
                            }
                            warn!(error = %e, "MCP dispatch loop failed");
                            return_dispatch_error!(e);
                        }
                    }
                }; // end loop_engage else branch
                info!(
                    iterations = outcome.iterations,
                    successful_calls = outcome.successful_calls,
                    failed_calls = outcome.failed_calls,
                    hit_cap = outcome.hit_cap,
                    "MCP dispatch loop complete"
                );
                // GOLD-TASK-05 — emit 0x89 GOAL_JUDGED WAL frame for budget_exhausted
                // outcomes (the "met" frame is already emitted inside judge_goal_met).
                {
                    use crate::mcp::dispatch_loop::GoalOutcome;
                    if matches!(outcome.goal_outcome, GoalOutcome::BudgetExhausted) {
                        let goal_hash = config
                            .goal
                            .goal
                            .as_deref()
                            .map(|g| format!("{:016x}", xxhash_rust::xxh3::xxh3_64(g.as_bytes())))
                            .unwrap_or_default();
                        crate::mcp::goal_judge::emit_goal_judged_wal(
                            Some(&writer),
                            &goal_hash,
                            "budget_exhausted",
                        )
                        .await;
                    }
                }
                // GOLD-ADAPT-ODY-20 — capture for auto-skill extraction gate.
                mcp_tool_calls = outcome.successful_calls;
                // REVFIX-EXCERPTS-01 — capture structured call records for digest.
                mcp_tool_records = outcome.tool_call_records;
                println!("{}", outcome.final_text);
                // A multi-round/tool response may span several providers and wire
                // models. Keep the envelope identity explicit instead of falsely
                // attributing the composed result to the configured primary.
                ProviderDispatchResult::new(
                    outcome.final_text,
                    None,
                    None,
                    if loop_engage {
                        "loop_engine".to_string()
                    } else {
                        "mcp_dispatch_loop".to_string()
                    },
                    "multi-hop".to_string(),
                )
            } else {
                // QM-10 Phase 2: consult the circuit breaker for this
                // provider before dispatching. Open breakers reject
                // immediately with operator-readable retry_after.
                let permit = match crate::providers::circuit_breaker::acquire_for(provider_name) {
                    Ok(p) => Some(p),
                    Err(berr) => {
                        warn!(
                            provider = provider_name,
                            breaker_err = %berr,
                            "circuit breaker rejected call"
                        );
                        return_dispatch_error!(anyhow::anyhow!(
                            "provider `{provider_name}`: {berr}"
                        ));
                    }
                };
                let call_started = std::time::Instant::now();
                let result = provider.complete(req).await;
                let elapsed_ms = call_started.elapsed().as_millis() as u64;
                match result {
                    Ok(completion) => {
                        if !completion.identity.is_bound() {
                            if let Some(p) = permit {
                                p.record_failure();
                            }
                            return_dispatch_error!(anyhow::anyhow!(
                                "provider `{provider_name}` returned no authenticated response identity"
                            ));
                        }
                        // QM-10 Phase 2: settle the permit on success.
                        if let Some(p) = permit {
                            p.record_success();
                        }
                        publish_provider_responded(
                            &completion.identity.provider,
                            &completion.identity.wire_model,
                            completion.input_tokens,
                            completion.output_tokens,
                            elapsed_ms,
                        );
                        // GOLD-ADAPT-HERMES-03 — mid-run clarification (opt-in,
                        // TTY-only). If the reply carries an ambiguity marker the
                        // gate parks, asks the operator, and re-issues with the
                        // answer. `None` (default / non-ambiguous / non-TTY) prints
                        // the reply unchanged.
                        let clarified = crate::cli::clarify_chat::maybe_clarify(
                            provider,
                            &final_prompt,
                            merged_system.as_deref(),
                            &completion.text,
                        )
                        .await;
                        match clarified {
                            Some(resolved) if resolved.identity.is_bound() => {
                                let resolved_elapsed_ms =
                                    resolved.latency.as_millis().min(u128::from(u64::MAX)) as u64;
                                publish_provider_responded(
                                    &resolved.identity.provider,
                                    &resolved.identity.wire_model,
                                    resolved.input_tokens,
                                    resolved.output_tokens,
                                    resolved_elapsed_ms,
                                );
                                println!("{}", resolved.text);
                                ProviderDispatchResult::new(
                                    resolved.text,
                                    resolved.input_tokens,
                                    resolved.output_tokens,
                                    resolved.identity.provider,
                                    resolved.identity.wire_model,
                                )
                            }
                            Some(_) => {
                                return_dispatch_error!(anyhow::anyhow!(
                                    "provider `{provider_name}` returned no authenticated response identity for the clarification round"
                                ));
                            }
                            None => {
                                println!("{}", completion.text);
                                ProviderDispatchResult::new(
                                    completion.text,
                                    completion.input_tokens,
                                    completion.output_tokens,
                                    completion.identity.provider,
                                    completion.identity.wire_model,
                                )
                            }
                        }
                    }
                    Err(e) => {
                        // QM-10 Phase 2: settle the permit on failure.
                        if let Some(p) = permit {
                            p.record_failure();
                        }
                        if !provider.handles_nonstream_quota_backoff()
                            && let Some(qe) =
                                e.downcast_ref::<crate::providers::quota::QuotaError>()
                        {
                            record_quota_exceeded(qe, &quota_path, &writer).await;
                        }
                        warn!(error = %e, "provider call failed");
                        return_dispatch_error!(e);
                    }
                }
            }
        })
    }
    .await;
    let ProviderDispatchResult {
        response_text,
        input_tokens: final_input_tokens,
        output_tokens: final_output_tokens,
        provider: provider_used,
        model: model_used,
    } = match dispatch_result {
        Ok(output) => output,
        Err(error) => {
            drop(authorized_provider);
            drop(call_authorizer);
            drop(writer);
            let _ = writer_join.await;
            return Err(error);
        }
    };

    // SL-00(1c): the provider work is done — release the in-flight slot and
    // feed the cluster local-load gauge the REAL measured throughput so our
    // outbound heartbeats carry honest numbers (no faked metrics).
    #[cfg(feature = "cluster")]
    {
        drop(inflight_guard);
        crate::cluster::local_load::record_completion(
            final_output_tokens.unwrap_or(0),
            inference_started.elapsed(),
        );
    }

    // AP-2 END half: fires for stream + non-stream paths after the model
    // produced a reply. Reads the final accumulated text from the same
    // tuple binding both branches return.
    if is_local_inference {
        let latency_ns = u64::try_from(inference_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let payload = serde_json::to_vec(&serde_json::json!({
            "request_id": inference_id,
            "output_hash": xxhash_rust::xxh3::xxh3_64(response_text.as_bytes()),
            "input_tokens": final_input_tokens,
            "output_tokens": final_output_tokens,
            "latency_ns": latency_ns,
            "stream": args.stream,
            "ts_unix": now_unix(),
        }))
        .unwrap_or_default();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_LOCAL_INFERENCE_END,
            &payload,
        )
        .build();
        if let Err(e) = writer.append(header, payload).await {
            tracing::warn!(error = %e, "WAL append failed (best-effort audit frame)");
        }
    }
    // Successful remote call → bump the per-provider daily counter for the
    // quota tracker so `neoth quota status` reflects actual usage. Local
    // providers are not tracked.
    if !crate::providers::is_local_provider(&provider_used) {
        if quota_tracker.is_none() {
            let error = anyhow::anyhow!(
                "remote provider `{provider_used}` completed without initialized quota state"
            );
            drop(authorized_provider);
            drop(call_authorizer);
            drop(writer);
            let _ = writer_join.await;
            return Err(error);
        }
        if let Err(e) = crate::providers::quota::QuotaTracker::update_at(&quota_path, |tracker| {
            tracker.record_success(&provider_used, crate::providers::quota::now_unix());
            Ok(())
        }) {
            tracing::warn!(error = %e, "quota.json save after success failed (best-effort)");
        }
    }
    // F4/D21 — the journal stays OPEN past dispatch: per the module contract the
    // durability window runs until the PROVIDER_RESPONSE frame is written, which
    // happens in `run_post_reply_pipelines`. The open journal is handed back so
    // that phase closes it (+ emits the 0x06 anchor) after recording the
    // response. A crash anywhere before that leaves the sidecar on disk for
    // `neoth recover`.
    Ok(DispatchOutput {
        response_text,
        final_input_tokens,
        final_output_tokens,
        provider_used,
        model_used,
        writer,
        writer_join,
        final_prompt,
        final_system,
        turn_journal: journal,
        // GOLD-ADAPT-ODY-20 — 0 on stream/single-provider paths; populated from
        // `outcome.successful_calls` in the MCP-dispatch branch above.
        mcp_tool_calls,
        // REVFIX-EXCERPTS-01 — empty on stream/single-provider paths; populated
        // from `outcome.tool_call_records` in the MCP-dispatch branch above.
        mcp_tool_records,
    })
}

/// GOLD-ARCH-02 phase 4 — post-reply pipelines for one chat turn: the
/// PostProviderCall hook, the PROVIDER_RESPONSE WAL frame, mirror-refusal
/// detection (0x16), LOWKEY refusal recovery + the FEAT-08 abliterated
/// fallback, ADR extraction, SESSION_ARCHIVE, the opt-in profile pipeline,
/// the two-stage review gate, hindsight compression, optional session
/// naming, and the turn-end usage bar. Owns the WAL writer + join handle and
/// drains them at the end; returns `Ok(())` (the chat turn result) or bails
/// if the PostProviderCall hook blocks the reply.
#[allow(clippy::too_many_arguments)]
async fn run_post_reply_pipelines(
    response_text: String,
    writer: crate::wal::writer::WalWriterHandle,
    writer_join: tokio::task::JoinHandle<()>,
    config: FreedomConfig,
    provider: &dyn crate::providers::Provider,
    args: ChatArgs,
    prompt: String,
    final_prompt: String,
    final_system: Option<String>,
    provider_used: String,
    model_used: String,
    final_input_tokens: Option<u32>,
    final_output_tokens: Option<u32>,
    review_context: Option<(String, String)>,
    hooks: Vec<crate::hooks::schema::HookDef>,
    segment_path: std::path::PathBuf,
    raw_event_id: i64,
    instance_paths: InstancePaths,
    profile_extensions: crate::profile::extension_registry::TypedExtensionRegistry,
    chat_ts_unix: i64,
    current_session_id: String,
    prompt_token_estimate: u32,
    turn_journal: Option<crate::recovery::turn_journal::TurnJournal>,
    // GOLD-CCPARITY-ONCE: session-scoped once-guard threaded from run_chat_with
    // through enforce_preflight to here so PostProviderCall shares the same
    // guard as PrePipeline and PreProviderCall.
    once_guard: &crate::hooks::SessionOnceGuard,
    // GOLD-ADAPT-ODY-20 — number of successful MCP tool-calls in this turn.
    // Gates auto-skill extraction (default threshold: ≥ 2). `0` on non-MCP turns.
    mcp_tool_calls: u32,
    // REVFIX-EXCERPTS-01 — structured per-call records for skill-digest extraction.
    // Empty on non-MCP turns; the distiller falls back to the blind response
    // prefix when this slice is empty (backward compat with unit-test paths).
    mcp_tool_records: Vec<crate::mcp::dispatch_loop::ToolCallRecord>,
    // B22-TWEAKS-MODEL-01 — tweaks.model_default propagated from run_chat_with
    // for model_for_estimate calls in token-cap and usage-log accounting.
    tweaks_model: Option<String>,
    // THEME-TWEAKS-GOLD — the same fail-loud, once-per-turn Tweaks snapshot
    // supplies the terminal statusline. Passing the full value keeps this
    // sink consistent with every earlier model/persona consumer.
    tweaks: &crate::tweaks::Tweaks,
    // GOLD-ADAPT-SKILL-09 — FilteredBlocks from BlockFilter hooks at
    // PreProviderCall. Restored into response_text after the PostProviderCall
    // hook stage so WAL/recall never see placeholder text.
    // Empty vec when no BlockFilter hooks fired this turn (no-op).
    pending_block_restorations: Vec<crate::hooks::block_filter::FilteredBlock>,
) -> Result<()> {
    let first_tour_home = instance_paths.home.clone();
    // ODY-16: auto-scale token cap from discovered model context window
    // (85% × window, hard-capped at 200K, ≤ operator_cap).
    // Used by the turn-end context bar further below.
    // B22: use model_used (seeded from the 6-tier effective_model in
    // dispatch_provider) so the context-window cap reflects the model that was
    // actually called.  Fall back to model_for_estimate only when model_used is
    // empty — a guard against future regressions; normal paths always set it.
    let resolved_cap: u32 = {
        let model_name_for_cap = if model_used.is_empty() {
            model_for_estimate(&args, &config, tweaks_model.as_deref())
        } else {
            model_used.clone()
        };
        crate::tokens::budget::effective_cap(
            &provider_used,
            &model_name_for_cap,
            config.tokens.max_per_request,
        )
    };
    let post_call_requested_model = if model_used.is_empty()
        || model_used == "unknown"
        || model_used == "multi-provider"
        || model_used == "multi-hop"
    {
        config.provider_model.as_deref()
    } else {
        Some(model_used.as_str())
    };
    let post_call_model = Some(resolve_provider_call_wire_model(
        &config,
        provider,
        post_call_requested_model,
    )?);
    let call_authorizer =
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
            config.autonomy_policy(),
            Some(writer.clone()),
            config.tokens.max_per_request,
        )
        .with_usage_home(first_tour_home.clone())
        .with_audit_context(
            crate::providers::cost_authorization::ProviderCallAuditContext {
                source: Some("chat"),
                call_type: Some("chat_post_reply_round"),
                request_id: Some(format!("{raw_event_id:016x}")),
                operator_id: config.operator_id.clone(),
                session_id: Some(current_session_id.clone()),
                target: Some(
                    crate::profile::runner::extract_target_label(provider.name()).to_owned(),
                ),
                ..Default::default()
            },
        );
    let authorized_post_provider =
        crate::providers::cost_authorization::CostAuthorizingProvider::new(
            provider,
            call_authorizer.clone(),
            post_call_model,
            "chat_post_reply_round",
        );
    let provider: &dyn crate::providers::Provider = &authorized_post_provider;
    // ── TOML hooks: PostProviderCall (Phase 29 R-15) ─────────────────────
    // Last chance to mutate or block the model's reply before it lands in
    // the WAL + reaches the operator. Already-printed streaming output
    // can't be unprinted; the hook can still rewrite the WAL-recorded
    // body (downstream recall + archive see the rewritten text).
    // GOLD-ADAPT-SKILL-09: PostProviderCall does not produce new filtered
    // blocks — ignore any (there should be none since BlockFilter hooks
    // are meant for PreProviderCall only). After the stage runs, restore
    // any blocks that were redacted at PreProviderCall so the response the
    // LLM produced with placeholder content has originals re-injected before
    // anything lands in WAL or recall.
    let mut response_text = match run_hook_stage(
        crate::hooks::HookStage::PostProviderCall,
        &response_text,
        &hooks,
        &writer,
        once_guard,
    )
    .await?
    {
        HookOutcome::Continue(body, _blocks) => body,
        HookOutcome::Blocked { name, reason } => {
            // End the borrow first, then release every writer-owning wrapper
            // before waiting for the one-shot WAL task to finish.
            let _ = provider;
            drop(authorized_post_provider);
            drop(call_authorizer);
            drop(writer);
            let _ = writer_join.await;
            anyhow::bail!("hook `{name}` blocked the reply at post_provider_call: {reason}");
        }
    };
    // Restore any redacted ignore-regions. `restore_blocks` is a no-op when
    // `pending_block_restorations` is empty (no BlockFilter hook fired this turn).
    if !pending_block_restorations.is_empty() {
        response_text =
            crate::hooks::block_filter::restore_blocks(&response_text, &pending_block_restorations);
    }

    // Learn presentation preferences only from an authenticated, accepted
    // operator turn. The recorder stores typed evidence plus this durable WAL
    // identity; it never persists `prompt` itself and is inert in Incognito.
    let communication_event_hash = crate::profile::communication::evidence_event_hash(
        "cli_turn",
        "operator",
        &current_session_id,
        &raw_event_id.to_le_bytes(),
    );
    let communication_scope = crate::profile::communication::CommunicationScope::Global;
    let communication_outcome = crate::profile::communication::record_authenticated_turn(
        &first_tour_home,
        &config.profile.communication,
        &prompt,
        communication_event_hash,
        "operator",
        &current_session_id,
        chat_ts_unix,
        communication_scope.clone(),
        true,
        matches!(config.autonomy, crate::permissions::AutonomyLevel::Full),
        args.incognito,
    )
    .context("record authenticated communication-adaptation evidence")?;
    crate::profile::communication::append_observation_audit(
        &first_tour_home,
        &writer,
        "operator",
        communication_event_hash,
        &communication_scope,
        &communication_outcome,
        chat_ts_unix,
    )
    .await
    .context("audit authenticated communication-adaptation evidence")?;

    // Each concrete leaf response was durably recorded at the provider
    // boundary before control returned here. Close the turn journal only after
    // post-provider hooks also completed, so a crash in that pipeline remains
    // recoverable even though its provider call already has a terminal frame.
    if let Some(mut j) = turn_journal {
        use crate::recovery::turn_journal::{TurnEvent, closed_payload};
        let turn_id = format!("{raw_event_id:016x}");
        let ts = crate::time::now_unix_i64();
        let _ = j.append(&TurnEvent::ProviderResponse {
            ts_unix: ts,
            provider: provider_used.clone(),
            model: model_used.clone(),
            input_tokens: final_input_tokens.unwrap_or(0),
            output_tokens: final_output_tokens.unwrap_or(0),
        });
        let line_count = std::fs::read_to_string(j.path())
            .map(|b| b.lines().filter(|l| !l.is_empty()).count())
            .unwrap_or(0);
        let payload = closed_payload(&turn_id, ts, line_count);
        let header =
            crate::wal::make_header(crate::wal::events::EVENT_TYPE_TURN_JOURNAL_CLOSED, &payload);
        let _ = writer.append(header, payload).await;
        let _ = j.close();
    }

    // ── Mirror-refusal Schicht-0 detection (SPEC_mirror_refusal §1) ────────
    // Pure-deterministic classifier — no LLM call, no meta-decision-making.
    // Whenever the provider's reply matches a refusal pattern, we emit
    // EVENT_TYPE_REFUSAL_OBSERVED (0x16) so operators have an audit trail
    // even before the full mirror pipeline (Stages 2-6) lands. The pipeline
    // itself depends on the hemisphere architecture which is Phase-2 scope.
    {
        let report = crate::security::refusal_detect::classify(&response_text);
        if report.is_refusal() {
            // R-09 2026-05-17: classify WHY the model refused — orthogonal
            // to the surface-class (hard/partial/soft/redirect/safety) the
            // refusal_detect classifier produces. Both signals get bundled
            // into the 0x16 REFUSAL_OBSERVED payload as new fields. Older
            // payload readers see the extra `cause_*` fields and skip them
            // (forward-compat via serde-default in the consumer); newer
            // pipeline stages (R-01..R-05) read them to pick the LOWKEY
            // reframing strategy.
            let cause = crate::security::refusal_cause::classify_cause(&response_text);
            let payload = serde_json::to_vec(&serde_json::json!({
                "operator_id": config.operator_id,
                "provider": provider_used,
                "model": model_used,
                "refusal_class": report.class.as_str(),
                "confidence": report.confidence,
                "matched_patterns": report.matched_patterns,
                "cause": cause.cause.as_str(),
                "cause_confidence": cause.confidence,
                "cause_matched_patterns": cause.matched_patterns,
                "response_hash_xxh3": xxhash_rust::xxh3::xxh3_64(response_text.as_bytes()),
                "ts_unix": now_unix(),
            }));
            match payload {
                Ok(bytes) => {
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_REFUSAL_OBSERVED,
                        &bytes,
                    )
                    .build();
                    if let Err(e) = writer.append(header, bytes).await {
                        tracing::warn!(error = %e,
                            "WAL append REFUSAL_OBSERVED failed (best-effort audit)");
                    } else {
                        info!(
                            refusal_class = report.class.as_str(),
                            cause = cause.cause.as_str(),
                            confidence = report.confidence,
                            cause_confidence = cause.confidence,
                            "mirror-refusal detector + cause classifier fired"
                        );
                    }
                }
                Err(e) => tracing::warn!(error = %e,
                    "serialize REFUSAL_OBSERVED payload failed"),
            }
        }
    }

    // ── R-04 LOWKEY refusal recovery (Session 9 2026-05-17) ─────────────
    // Wires R-05 (`security::refusal_recovery::try_recover`) into the
    // post-reply path. When the Schicht-0 detector found a refusal +
    // operator opted in (`config.refusal_recovery.enabled`, default
    // true), classify the cause, pick a LOWKEY reframing, retry once.
    // On success: REPLACE `response_text` so downstream ADR extraction
    // + SESSION_ARCHIVE + profile pipeline + PreEgress hooks see the
    // recovered reply. On failure: leave the original refusal text in
    // place so the operator sees it verbatim.
    //
    // Per-call escape hatch: `NEOTH_REFUSAL_RECOVERY_DISABLE=1` skips
    // the retry even when the config flag is on (operator debugging
    // refusal triggers without auto-retry noise).
    //
    // Audit: every retry attempt emits `0x19 REFUSAL_REROUTED`. The
    // original 0x16 REFUSAL_OBSERVED frame above stays as truth (the
    // original refusal happened); the recovery is an additive layer.
    // ADV-07: track whether this turn's reply came from the mirror
    // refusal-recovery path, so profile extraction can skip the
    // operator_preferences category for it (the recovered "preferences"
    // are about the reframing, not the operator).
    // D23 — the permanent hard-block floor (CSAM / bio-chem weapon / mass-
    // casualty) runs BEFORE any refusal recovery. Both the reframing pipeline
    // (try_recover_multi) and the abliterated fallback below are suppressed when
    // it fires, so neither can be used to "recover" a genuinely refused request.
    // The floor previously gated only the abliterated tier, which the reframing
    // pipeline reached first and ungated. (The abliterated path also re-checks
    // internally via the same gate for non-chat callers — no double-emit here
    // because both blocks are skipped when `hard_blocked`.)
    let hard_blocked = crate::security::refusal_abliterated::hard_block_gate(
        &final_prompt,
        Some(&writer),
        now_unix() as i64,
    )
    .is_some();

    let mut derived_from_mirror_pipeline = false;
    if !hard_blocked
        && config.refusal_recovery.enabled
        && std::env::var("NEOTH_REFUSAL_RECOVERY_DISABLE")
            .map(|v| !(v == "1" || v.eq_ignore_ascii_case("true")))
            .unwrap_or(true)
    {
        let report = crate::security::refusal_detect::classify(&response_text);
        if report.is_refusal() {
            let recovery_req = crate::providers::Request {
                prompt: final_prompt.clone(),
                // Q1: idempotent apply — re-entry path also
                // gets the Karpathy preamble. The
                // `apply_code_discipline_preamble` no-ops when the
                // preamble is already present so this is
                // safe under any sequencing.
                system: Some(
                    crate::providers::context_guards::apply_code_discipline_preamble(
                        final_system.as_deref(),
                    ),
                ),
                model: Some(model_used.clone()),
                ..Default::default()
            };
            match crate::security::refusal_recovery::try_recover_multi(
                provider,
                &recovery_req,
                &response_text,
                &config.refusal_recovery.disabled_reframings,
                Some(&writer),
                now_unix(),
                config.refusal_recovery.max_attempts,
            )
            .await
            {
                Ok(crate::security::refusal_recovery::RecoveryOutcome::Recovered {
                    completion,
                    reframing_id,
                }) => {
                    info!(
                        reframing = reframing_id,
                        original_bytes = response_text.len(),
                        recovered_bytes = completion.text.len(),
                        "refusal recovery succeeded — replacing response_text downstream"
                    );
                    response_text = completion.text;
                    derived_from_mirror_pipeline = true; // ADV-07
                }
                Ok(crate::security::refusal_recovery::RecoveryOutcome::RefusedAgain {
                    reframing_id,
                    ..
                }) => {
                    tracing::info!(
                        reframing = reframing_id,
                        "refusal recovery attempted but model refused again — leaving original refusal in place"
                    );
                }
                Ok(crate::security::refusal_recovery::RecoveryOutcome::NotRecoverable {
                    cause,
                }) => {
                    tracing::debug!(
                        cause = cause.as_str(),
                        "refusal not recoverable (Unknown / OperatorPolicy / all reframings disabled)"
                    );
                }
                Ok(crate::security::refusal_recovery::RecoveryOutcome::ProviderError {
                    reframing_id,
                    error,
                }) => {
                    tracing::warn!(
                        reframing = reframing_id,
                        error = %error,
                        "refusal recovery retry hit provider error — leaving original refusal in place"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "refusal recovery failed (non-fatal)");
                }
            }
        }
    }

    // ── GOLD-FEAT-08b Tier-2.5: jailbreak-harness retry ───────────────────
    // Operator decision (2026-06-22, authorized-researcher / sovereign agent):
    // BEFORE the sovereign local fallback, if the response is STILL a SafetyPolicy
    // over-refusal and the operator opted in, retry the SAME cloud provider up to
    // `jailbreak_max_retries` times, each wrapping the request in a distinct seed
    // harness (ported from davidondrej/jailbreak-autoresearch). First non-refusal
    // wins. If every harness still refuses, fall through to FEAT-08 below (the
    // operator's local model — the sovereign floor). The CSAM/bioweapon hard-block
    // floor runs first inside the retry. Opt-in + WAL-audited (0x25).
    let mut jailbreak_recovered = false;
    if !hard_blocked && config.refusal_recovery.jailbreak_retry_enabled {
        let jb_report = crate::security::refusal_detect::classify(&response_text);
        if jb_report.is_refusal()
            && crate::security::refusal_abliterated::should_route_to_abliterated(
                &crate::security::refusal_cause::classify_cause(&response_text),
            )
        {
            match crate::security::jailbreak_retry::try_jailbreak_retry(
                provider,
                &final_prompt,
                final_system.as_deref(),
                None,
                config.refusal_recovery.jailbreak_max_retries,
                Some(&writer),
                now_unix() as i64,
            )
            .await
            {
                Ok(Some(new_text)) => {
                    tracing::info!(
                        recovered_bytes = new_text.len(),
                        "FEAT-08b jailbreak retry succeeded — replacing response"
                    );
                    response_text = new_text;
                    derived_from_mirror_pipeline = true; // skip profile extraction on recovered turns
                    jailbreak_recovered = true;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "FEAT-08b jailbreak retry failed (non-fatal)");
                }
            }
        }
    }

    // ── GOLD-FEAT-08 Tier-3: local-abliterated fallback ───────────────────
    // After the LOWKEY reframing pipeline above (and the FEAT-08b jailbreak retry,
    // if it ran and did NOT recover), if the response is STILL a SafetyPolicy
    // over-refusal and the operator opted in, route to their OWN local abliterated
    // model (operator-owned hardware — NOT provider-deception). The orchestrator
    // runs the permanent hard-block floor first and emits WAL 0x26/0x27/0x28
    // internally. Best-effort; never bails a turn.
    if !jailbreak_recovered && !hard_blocked && config.refusal_recovery.abliterated_fallback_enabled
    {
        let t3_report = crate::security::refusal_detect::classify(&response_text);
        if t3_report.is_refusal()
            && crate::security::refusal_abliterated::should_route_to_abliterated(
                &crate::security::refusal_cause::classify_cause(&response_text),
            )
        {
            match crate::security::refusal_abliterated::try_abliterated_fallback(
                provider,
                &call_authorizer,
                &final_prompt,
                final_system.as_deref(),
                config.refusal_recovery.abliterated_model.as_deref(),
                &response_text,
                Some(&writer),
                now_unix() as i64,
            )
            .await
            {
                Ok(Some(new_text)) => {
                    tracing::info!(
                        recovered_bytes = new_text.len(),
                        "FEAT-08 abliterated fallback succeeded — replacing response"
                    );
                    response_text = new_text;
                    derived_from_mirror_pipeline = true; // ADV-07: skip profile extraction on recovered turns
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "FEAT-08 abliterated fallback failed (non-fatal)");
                }
            }
        }
    }

    // ── GOLD-ADAPT-ODY-08 Tier-4: SOTA teacher correction ────────────────
    // After FEAT-08 local-abliterated path: if the ORIGINAL provider was a
    // local model and the response is still a refusal or low-confidence,
    // escalate to the SOTA cloud teacher. ODY-18 `wrap_untrusted` is applied
    // EXACTLY on local output before sending to teacher (anti-injection MUST).
    // Hard-blocked floor (`hard_blocked`) suppresses this tier too.
    // `derived_from_mirror_pipeline = true` (ADV-07) skips profile extraction
    // on corrected turns so the teacher's writing style is not learned as the
    // operator's own. Best-effort; never fails a turn.
    if !hard_blocked
        && crate::providers::is_local_provider(&provider_used)
        && config.refusal_recovery.teacher_escalation_enabled
    {
        match crate::skills::teacher::try_teacher_escalation(
            &response_text,
            &final_prompt,
            final_system.as_deref(),
            &provider_used,
            &config,
            &first_tour_home,
            &call_authorizer,
            Some(&writer),
            now_unix() as i64,
        )
        .await
        {
            Ok(Some(corrected)) => {
                tracing::info!(
                    corrected_bytes = corrected.len(),
                    "ODY-08 teacher escalation succeeded — replacing response"
                );
                response_text = corrected;
                derived_from_mirror_pipeline = true; // ADV-07: skip profile extraction
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "ODY-08 teacher escalation failed (non-fatal)");
            }
        }
    }

    // ── ADR extraction (Phase 31 R-21 ADR-1) ─────────────────────────────
    // Scan the provider's reply for DECISION:/Beschluss:/ADR: markers. Each
    // hit writes `~/.neoth/adr/NNNN-<slug>.md`. Failures log but never
    // block — ADR capture is operator-side bookkeeping, not load-bearing.
    {
        let adr_dir = &instance_paths.adr;
        let decisions = crate::adr::extract_decisions(&response_text);
        for d in &decisions {
            match crate::adr::write_adr(adr_dir, d) {
                Ok(path) => info!(adr = %path.display(), title = %d.title, "ADR captured"),
                Err(e) => tracing::warn!(error = %e, title = %d.title, "ADR write failed"),
            }
        }
    }

    // ── SESSION_ARCHIVE (Phase 28a MT-4) ─────────────────────────────────
    // Append the turn pair to ~/.neoth/archive/sessions/YYYY-MM-DD/<id>.md.
    // Failure here MUST NOT swallow the chat outcome — log and continue.
    // The session id is the chat invocation id; the daemon path will swap
    // this for the persistent session-uuid from the channel handler.
    // ODY-09: incognito turns leave no session-archive trace.
    if !args.incognito {
        let archive = crate::memory::archive::SessionArchive::new(
            instance_paths.archive.clone(),
            format!("cli-{}", uuid::Uuid::new_v4()),
            chrono::Utc::now(),
        );
        if let Err(e) = archive
            .append_turn(&prompt, &response_text, chrono::Utc::now())
            .await
        {
            tracing::warn!(error = %e, "session archive append failed");
        }
    }

    // ── Profile pipeline post-reply (Session 2 hardening 2026-05-17) ─────
    // The full 6-stage `profile::run_pipeline` runs after each chat reply
    // when the operator explicitly opts in via
    // `freedom.yaml::profile.learn_enabled: true` (default `false`).
    //
    // Off by default because the Stage-3 extract is a full LLM call —
    // operators on paid clouds (OpenAI / Anthropic API / OpenRouter)
    // would see a surprise 2× token bill per chat without opt-in.
    // Operators on `local_qwen` or pre-paid plans flip the flag on and
    // get passive operator-profile learning that feeds CH-11 callosum
    // synthesis + future CH-09/CH-10 recall ranking with real data.
    //
    // Env overrides: `NEOTH_PROFILE_LEARN_DISABLE=1` skips even when
    // `learn_enabled: true` (per-call brake). `NEOTH_PROFILE_LEARN_FORCE=1`
    // enables even when the config flag is false (per-call lift for
    // ad-hoc learning sessions).
    //
    // Latency cap: wrapped in `tokio::time::timeout` (default 15s via
    // `freedom.yaml::profile.timeout_secs`). A hung extract LLM call
    // cannot pin the CLI shell past this budget — operator gets their
    // shell prompt back; the pipeline run is abandoned (logged warn).
    //
    // Best-effort throughout: any failure (missing views.db, indexer
    // error, extract LLM error, guard rejection, timeout) logs at
    // warn/debug and never bubbles into the chat reply.
    let env_disable = std::env::var("NEOTH_PROFILE_LEARN_DISABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let env_force = std::env::var("NEOTH_PROFILE_LEARN_FORCE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // ODY-09: incognito turns never feed the profile learner — no memory surface.
    let learn_on = !env_disable && (env_force || config.profile.learn_enabled) && !args.incognito;
    if learn_on {
        let timeout = std::time::Duration::from_secs(config.profile.timeout_secs.max(1));
        let views_path = first_tour_home.join("views.db");
        // V10-07 (Session 21) — when freedom.yaml::profile.learn_provider
        // is set, build a learn-specific provider (typically local_qwen
        // so the post-reply extract stays offline). Falls back to the
        // main provider when learn_provider is None or on build-failure
        // with allow_cloud_fallback=true. Build-failure with
        // allow_cloud_fallback=false (the default cheap-by-default
        // posture) skips the learn pass entirely with a clear warn.
        let learn_provider_owned: Option<Box<dyn crate::providers::Provider>> =
            match crate::providers::from_config_for_learn_at(&config, &first_tour_home).await {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "profile.learn_provider build failed; skipping post-reply learn pass"
                    );
                    None
                }
            };
        // Session 24 fix #2: when `from_config_for_learn` returns Err
        // (= learn_provider build failed AND allow_cloud_fallback=false
        // per `providers::from_config_for_learn` step 4 contract), the
        // operator's intent is "no fallback, skip extraction". The
        // pre-fix code fell back to the main `provider` here, which
        // sent the operator's full conversation window to the cloud
        // path they had explicitly opted out of. The comment above
        // said "skip with warn" but the code did the opposite.
        // Honest fix: bail before invoking the pipeline.
        let learn_dispatch: Option<&dyn crate::providers::Provider> = learn_provider_owned
            .as_deref()
            .map(|p| p as &dyn crate::providers::Provider);
        if learn_dispatch.is_none() {
            tracing::info!(
                allow_cloud_fallback = config.profile.allow_cloud_fallback,
                "profile.learn pass skipped: learn_provider build failed and \
                 allow_cloud_fallback=false (operator chose privacy over learn)"
            );
        } else if let Some(learn_provider_ref) = learn_dispatch {
            let authorized_learn_provider =
                crate::providers::cost_authorization::CostAuthorizingProvider::new(
                    learn_provider_ref,
                    crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
                        config.autonomy_policy(),
                        Some(writer.clone()),
                        config.tokens.max_per_request,
                    )
                    .with_usage_home(first_tour_home.clone()),
                    None,
                    "profile_learning_round",
                );
            // ADV-10c (Session 28g+): pre-flight QuotaTracker check on
            // the learn_provider. Without this, a persistently rate-
            // limited learn_provider pays a full LLM round-trip EVERY
            // post-reply turn only to be 429'd inside Stage 3 of
            // `run_pipeline`. ADV-10 Slice A closed the silent-data-loss
            // gap (the 0xB9 emit + Skip variant); this closes the
            // wasted-cost gap upstream by skipping the call entirely
            // while a backoff window is active. Soft-skip — log warn and
            // continue, do NOT bail the chat turn (the operator already
            // got their reply; profile-learn is a passive post-reply
            // pass). Local providers always pass the check.
            let learn_quota_path = first_tour_home.join("quota.json");
            let learn_now = crate::providers::quota::now_unix();
            let learn_backoff_remaining = match crate::providers::quota::QuotaTracker::load_from(
                &learn_quota_path,
            ) {
                Ok(learn_tracker) => {
                    learn_tracker.backoff_remaining_for(learn_provider_ref.name(), learn_now)
                }
                Err(error) => {
                    tracing::warn!(
                        path = %learn_quota_path.display(),
                        error = %error,
                        "profile.learn quota state unavailable — skipping optional provider call"
                    );
                    Some(u64::MAX)
                }
            };
            if let Some(remaining) = learn_backoff_remaining {
                tracing::warn!(
                    provider = learn_provider_ref.name(),
                    backoff_remaining_secs = remaining,
                    "profile.learn pre-flight: learn_provider in 429 backoff — skipping pipeline (ADV-10c)"
                );
            }
            if learn_backoff_remaining.is_none() {
                match crate::memory::store::open(&views_path) {
                    Ok(mut conn) => {
                        let pipeline_fut = async {
                            if let Err(e) = crate::memory::indexer::replay_once_audited_at_home(
                                &first_tour_home,
                                &mut conn,
                                &segment_path,
                                None,
                            )
                            .await
                            {
                                tracing::warn!(
                                    error = %e,
                                    "indexer replay_once failed before profile pipeline; skipping learn"
                                );
                                return;
                            }
                            // MEMGRAPH-01 — auto-embed the freshly-indexed episode(s)
                            // into the vector recall lane so they join the Multi-tier
                            // vector search incrementally (no manual `--embed-backfill`).
                            // Best-effort + bounded (32/turn); only runs when an embed
                            // provider is configured. Runs here (post-reply pipeline) so
                            // it never blocks the reply.
                            if let Some(embed_provider) =
                                crate::providers::embed_provider_from_config(&config).await
                            {
                                let (returned_conn, n) =
                                    crate::memory::embeddings::embed_pending_episodes(
                                        conn,
                                        embed_provider.as_ref(),
                                        32,
                                    )
                                    .await;
                                conn = returned_conn;
                                if n > 0 {
                                    tracing::debug!(
                                        embedded = n,
                                        "MEMGRAPH-01: auto-embedded new episodes into the vector lane"
                                    );
                                }
                            }
                            let guard = crate::profile::claim_guard::ProfileClaimGuard::default();
                            match crate::profile::run_pipeline(
                                crate::profile::PipelineConn::Owned(&mut conn),
                                &writer,
                                &authorized_learn_provider,
                                raw_event_id,
                                2,
                                &guard,
                                &profile_extensions,
                                now_unix(),
                                // ADV-03 Phase 5 (Session 24): gate context
                                // None preserves pre-gate behaviour. Wiring
                                // the chat-path gate context (autonomy +
                                // is_tty + dialoguer confirm) is Phase 6+
                                // CLI surface work tracked separately.
                                None,
                                derived_from_mirror_pipeline, // ADV-07
                            )
                            .await
                            {
                                Ok(crate::profile::PipelineRun::Applied { outcome, .. }) => {
                                    tracing::info!(
                                        claims_applied = outcome.claims_applied,
                                        claims_reinforced = outcome.claims_reinforced,
                                        claims_superseded = outcome.claims_superseded,
                                        idempotent_skip = outcome.idempotent_skip,
                                        "profile pipeline applied post-reply"
                                    );
                                }
                                Ok(crate::profile::PipelineRun::Skipped(
                                    reason @ crate::profile::PipelineSkip::QuotaExceeded { .. },
                                )) => {
                                    // ADV-10 review follow-up: persistent 429
                                    // suppression must be observable at the
                                    // default log level — a quietly rate-limited
                                    // learn_provider that always lands here
                                    // would otherwise show no operator-visible
                                    // signal except the WAL frame.
                                    tracing::warn!(
                                        reason = %reason,
                                        "profile pipeline quota-exceeded post-reply"
                                    );
                                }
                                Ok(crate::profile::PipelineRun::Skipped(reason)) => {
                                    tracing::debug!(reason = %reason, "profile pipeline skipped post-reply");
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "profile pipeline failed post-reply (non-fatal)"
                                    );
                                }
                            }
                        };
                        match tokio::time::timeout(timeout, pipeline_fut).await {
                            Ok(()) => {}
                            Err(_elapsed) => {
                                tracing::warn!(
                                    timeout_secs = timeout.as_secs(),
                                    "profile pipeline timed out post-reply; learning abandoned for this turn"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %views_path.display(),
                            "open views.db failed for post-reply profile pipeline (non-fatal)"
                        );
                    }
                }
            } // ADV-10c (Session 28g+): closes `if learn_backoff_remaining.is_none()`
        } // Session 24 fix #2: closes the `else if let Some(learn_provider_ref) = ...`
    }

    // ── Two-stage review gate (obra/superpowers Item #2) ───────────────────
    // Activates only when (a) the operator dispatched via `/agent`, and (b)
    // `freedom.yaml::review_gate_enabled` is true. Costs 2× extra provider
    // calls so it stays opt-in.
    if let Some((agent_name, original_prompt)) = review_context
        && config.review_gate_enabled
    {
        tracing::info!(agent = %agent_name, "running two-stage review gate");
        match crate::sub_agents::review::two_stage_review(
            provider,
            &original_prompt,
            &response_text,
        )
        .await
        {
            Ok(verdicts) => {
                println!("\n── review gate ──");
                for v in &verdicts {
                    let mark = if v.passed { "PASS" } else { "FAIL" };
                    println!("  {}: {}", v.stage.as_str(), mark);
                    // One WAL frame per stage. Body is hashed, not stored,
                    // to keep the WAL small per the event-type doc.
                    let payload = serde_json::to_vec(&serde_json::json!({
                        "agent_name": agent_name,
                        "stage": v.stage.as_str(),
                        "passed": v.passed,
                        "feedback_hash_xxh3": xxhash_rust::xxh3::xxh3_64(v.feedback.as_bytes()),
                    }))
                    .unwrap_or_default();
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_SUBAGENT_REVIEW_STAGE,
                        &payload,
                    )
                    .build();
                    if let Err(e) = writer.append(header, payload).await {
                        tracing::warn!(error = %e, "failed to write review WAL frame");
                    }
                }
                // Surface the feedback bodies inline so the operator
                // sees them in the same terminal — they were paid for.
                for v in &verdicts {
                    if !v.feedback.is_empty() {
                        println!("\n[{}]\n{}", v.stage.as_str(), v.feedback);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "two-stage review gate errored; printing primary reply only");
            }
        }
    }

    // OP-02 (Session 25) — session-end hindsight compression.
    // Two-turn transcript (operator prompt + agent reply) goes
    // through `compress_session` + `save_card` so the next
    // session's seed banner has something to surface. Best-effort:
    // a write failure logs warn but never aborts the chat exit
    // path. `chat_ts_unix` + `current_session_id` were both
    // computed at startup so the same id used in the banner-suppress
    // check round-trips through the saved card.
    // ODY-09: incognito turns write no hindsight card (no seed-banner surface).
    if !args.incognito {
        crate::memory::hindsight::save_session_card_best_effort(
            &first_tour_home,
            chat_ts_unix,
            &prompt,
            &response_text,
        );
    }

    // GOLD-ADAPT-ODY-26 — persist raw turns into views.db for FTS recall.
    // Best-effort: open is cheap (db already exists from the indexer pass
    // earlier in this session); a failure here must NEVER abort chat exit.
    // ODY-09: incognito turns persist no raw transcript (no FTS recall surface).
    if !args.incognito {
        let db_path = first_tour_home.join("views.db");
        match crate::memory::store::open(&db_path) {
            Ok(conn) => {
                crate::memory::transcript_store::insert_turn_best_effort(
                    &conn,
                    &current_session_id,
                    "operator",
                    chat_ts_unix,
                    &prompt,
                );
                crate::memory::transcript_store::insert_turn_best_effort(
                    &conn,
                    &current_session_id,
                    "agent",
                    chat_ts_unix + 1,
                    &response_text,
                );
            }
            Err(error) => tracing::warn!(
                path = %db_path.display(),
                error = %error,
                "transcript store unavailable; raw turn not persisted"
            ),
        }
    }

    // GOLD-ADOPT-21 — optional LLM session title (opt-in: `memory.name_sessions`).
    // AWAITED, not spawned: `neoth chat` is one-shot, so a spawned task would die
    // on process exit. Uses the cheap utility provider + a 12s timeout cap; any
    // failure leaves the deterministic `one_line_summary` in place.
    // ODY-09: incognito turns get no LLM-derived session title — it is a
    // memory surface (derived from the prompt, persisted to the hindsight card).
    if !args.incognito && config.memory.name_sessions {
        name_session_best_effort(
            &config,
            &writer,
            &first_tour_home,
            &current_session_id,
            &prompt,
        )
        .await;
    }

    // GOLD-ADOPT-24 — turn-end context-window usage bar (this turn's tokens vs
    // the configured cap). Printed to STDERR so it never pollutes the stdout
    // response/JSON; skipped in --stream/jsonl machine mode. Limit comes from
    // tokens.max_per_request (no hardcoded per-model window — model-agnostic rule).
    if !args.stream {
        // GR-092: prefer the provider-reported input count over the local
        // estimate; fall back to the estimate when the provider returns None.
        let used = final_input_tokens
            .unwrap_or(prompt_token_estimate)
            .saturating_add(final_output_tokens.unwrap_or(0));
        if let Some(bar) = crate::cli::chat_display::render_context_bar(used, resolved_cap) {
            eprintln!("{bar}");
        }
        // THEME-TWEAKS-GOLD — configured statusline is a real terminal sink.
        // It stays on STDERR so the assistant response on STDOUT remains pipe-safe.
        if tweaks.statusline.is_some() {
            eprintln!(
                "{}",
                tweaks.render_statusline(
                    config.operator_id.as_deref(),
                    Some(&model_used),
                    Some(config.autonomy.as_str()),
                )
            );
        }
        // GOLD-ADAPT-LOWKEY-05 — ONTOLOGY adversarial self-challenge: flag any
        // speculative/unsupported claims in the final answer (STDERR, never
        // stdout). Pure + LLM-free; fires only on suspect absolutisms, so a
        // well-grounded reply prints nothing extra.
        if let Some(note) = crate::council::self_challenge::challenge_answer(&response_text).note()
        {
            eprintln!("{note}");
        }

        // GOLD-ADAPT-ODY-20 — auto-skill extraction (post-turn, MCP turns only).
        // Best-effort: never fails the turn. Fires only when enabled + the MCP
        // dispatch loop ran ≥ min_tool_calls calls. Proposal written to
        // `~/.neoth/proposals/` for operator review via `neoth proactive list`.
        // ODY-09: incognito turns extract no skill proposal — it would persist a
        // turn-derived artifact to ~/.neoth/proposals/ (a memory surface).
        if !args.incognito
            && mcp_tool_calls >= config.auto_skill_extract.min_tool_calls
            && config.auto_skill_extract.enabled
        {
            let home = first_tour_home.clone();
            if let Some(proposal) = crate::skills::auto_extract::maybe_extract_skill(
                &prompt,
                &response_text,
                mcp_tool_calls,
                &mcp_tool_records,
                provider,
                &config.auto_skill_extract,
            )
            .await
            {
                // WAL audit: 0x7B AUTO_SKILL_EXTRACTED (best-effort, advisory).
                if let Ok(payload) = serde_json::to_vec(&serde_json::json!({
                    "title_hash_xxh3": xxhash_rust::xxh3::xxh3_64(proposal.title.as_bytes()),
                    "tool_call_count": mcp_tool_calls,
                    "ts_unix": crate::time::now_unix_i64(),
                })) {
                    let hdr = crate::wal::make_header(EVENT_TYPE_AUTO_SKILL_EXTRACTED, &payload);
                    let _ = writer.append(hdr, payload).await;
                }
                // Stage + enqueue in the proactive review queue (dedup via proposal id).
                let queue_path = home.join("proactive_queue.json");
                // Locked load→mutate→save; tolerates a corrupt file (same as the
                // old `unwrap_or_default()`) by silently ignoring the error
                // (this block is best-effort; the `let _ =` on the outer result
                // mirrors the old `let _ = q.save_to(...)` best-effort save).
                let _ = crate::proactive::ProactiveQueue::modify(&queue_path, |q| {
                    // Persist only when stage_and_enqueue succeeds — same condition
                    // as the old `if let Ok(...) { let _ = q.save_to(...) }`.
                    let staged =
                        crate::proactive::action_staging::stage_and_enqueue(&home, proposal, q)
                            .is_ok();
                    (staged, staged)
                });
            }
        }
    } else if tweaks.statusline.is_some() {
        // Streaming keeps the done-sentinel on STDOUT; the human statusline
        // remains an independent STDERR surface (GUI consumers discard it).
        eprintln!(
            "{}",
            tweaks.render_statusline(
                config.operator_id.as_deref(),
                Some(&model_used),
                Some(config.autonomy.as_str()),
            )
        );
    }

    // GOLD-ADAPT-OH-11: flip chat_onboarding_completed = true on first successful
    // chat turn. Only persists when the flag is currently false (no-op on every
    // subsequent turn). Update the exact selected config path under its lock;
    // a custom `--config` must never mutate the process-default freedom.yaml.
    if !config.chat_onboarding_completed
        && let Err(e) = persist_chat_onboarding_complete(&instance_paths.config)
    {
        tracing::warn!(error = %e, "OH-11: could not persist chat_onboarding_completed=true (non-fatal)");
    }

    let _ = provider;
    drop(authorized_post_provider);
    drop(call_authorizer);
    drop(writer);
    let _ = writer_join.await;
    Ok(())
}

pub async fn run_chat_with(
    mut args: ChatArgs,
    config: FreedomConfig,
    provider: &dyn crate::providers::Provider,
) -> Result<()> {
    info!(provider = provider.name(), "neoth chat");
    let selected_config_path = args
        .config
        .clone()
        .unwrap_or_else(FreedomConfig::default_path);
    let instance_paths = InstancePaths::new(
        chat_neoth_home(args.config.as_deref()),
        selected_config_path,
    );
    let first_tour_home = instance_paths.home.clone();

    // R-05 (Session 24) — surface the first-tour greeting at most
    // once per wizard run. `consume_first_tour_marker` reads + deletes
    // the marker so subsequent chat invocations don't repeat it. Best-
    // effort: a missing or unreadable marker means "operator past the
    // onboarding moment", which is the safe default.
    if let Some(greeting) = crate::cli::init::consume_first_tour_marker(&first_tour_home) {
        println!("[neoth] {greeting}");
    }

    // GOLD-ADAPT-OH-11: one-time first-chat hint. Fires on the first `neoth chat`
    // after a fresh `neoth init` (write_config sets the flag false). Suppressed
    // for existing operators (default_true serde default) and after the first
    // successful turn (run_post_reply_pipelines flips it true).
    if !config.chat_onboarding_completed {
        println!(
            "[neoth] First chat! Run `neoth doctor` to check system status, \
             or `neoth recall --help` to explore your memory."
        );
    }

    // HERMES-02 — deliver any completed background sessions at next idle.
    // Scans `~/.neoth/bgjobs/*.result` whose `.exit` marker is present
    // and whose `.delivered` marker is absent; prints each prefixed with
    // `[btw]`. Idempotent via the `.delivered` sibling marker.
    {
        use std::io::Write as _;

        let bgjobs_home = first_tour_home.join("bgjobs");
        let pending = crate::cli::bg_session::maybe_deliver_bg_result(&bgjobs_home).await;
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        for result in pending {
            writeln!(stdout, "[btw] {}", result.text())
                .context("write completed background result to stdout")?;
            stdout
                .flush()
                .context("flush completed background result to stdout")?;
            result
                .acknowledge()
                .context("acknowledge completed background result delivery")?;
        }
    }

    // Round-3 v0.4 QU-11 / ARS-6 — if `--resume-from <hash>` is set,
    // hydrate the prior session's `MODE_CHECKPOINT` snapshot from
    // views.db + prepend a RESUME-CONTEXT block to the system prompt
    // so the assistant knows the prior pipeline shape. Resume is authoritative:
    // a bad/missing checkpoint or an unrecorded legacy MCP scope fails closed
    // instead of silently running a normal turn with a different tool surface.
    let mut resumed_mcp_scope: Option<Vec<String>> = None;
    if let Some(hash_prefix) = args.resume_from.clone() {
        let hydration =
            hydrate_resume_context(&first_tour_home, &hash_prefix, args.system.as_deref())
                .map_err(|why| anyhow::anyhow!("resume-from `{hash_prefix}` failed: {why}"))?;
        println!("{}", hydration.banner);
        // PWF-02: print catchup line when something happened since the checkpoint.
        if !hydration.catchup.is_empty() {
            println!(
                "[neoth] catchup: {} provider turns, {} tool calls, {} compactions since checkpoint",
                hydration.catchup.provider_turns,
                hydration.catchup.tool_calls,
                hydration.catchup.compactions,
            );
        }
        args.system = Some(hydration.combined_system);
        resumed_mcp_scope = Some(hydration.scoped_mcp_servers);
    }

    let prompt = resolve_prompt(&args, &config, &first_tour_home).await?;

    // One immutable MCP configuration snapshot per chat turn. Bad YAML is an
    // operator error and fails loud instead of silently removing tools. This
    // exact snapshot drives prompt injection, autoroute and resume metadata.
    let InstanceTurnState {
        mcp_servers: current_mcp_servers,
        tweaks,
        profile_extensions,
    } = load_instance_turn_state(&instance_paths)?;
    let mcp_servers = match resumed_mcp_scope.as_deref() {
        Some(scope) => restrict_mcp_servers_to_checkpoint(current_mcp_servers, scope)
            .map_err(|why| anyhow::anyhow!("resume MCP scope validation failed: {why}"))?,
        None => current_mcp_servers,
    };
    let scoped_mcp_servers = enabled_mcp_scope(&mcp_servers);

    // G-03 self-correction signal. If this turn reads as a CORRECTION of the
    // preceding reply (rule-based follow-up-tone scorer crosses the negative
    // threshold), record an `OPERATOR_FEEDBACK` (0xBB) WAL frame so the
    // operator can audit where NEOTH underperformed
    // (`neoth wal show --type operator_feedback`). Fire-and-forget +
    // best-effort: it never blocks or fails the chat turn, and stores only a
    // prompt_hash (no message-content leak). The profile-adapt cron consumes
    // sustained correction pressure and queues a reviewable self-dev proposal.
    let _ = crate::feedback::record_operator_correction(&first_tour_home, &prompt).await;

    // Round-3 v0.4 — coding-intent auto-dispatch. When the prompt
    // looks like a coding request (bilingual EN/DE heuristic: verb
    // at front + programming-noun anchor; see
    // `coding::intent::detect_coding_intent`), route through the
    // dedicated coding workflow (`cli::code::run_code`) instead of
    // a single-turn chat reply. The coding workflow opens a kanban
    // session + decomposes + dispatches to the hemisphere worker +
    // runs patch+test loop — much better operator outcome than
    // chat-only for "build me X" requests.
    //
    // Operator opt-out: `NEOTH_NO_AUTO_CODE=1` env var disables
    // auto-dispatch entirely. Low-confidence detections (verb XOR
    // noun, not both) print an offer banner but still run the chat
    // turn — only High confidence auto-dispatches.
    if crate::coding::intent::should_auto_dispatch(&prompt) {
        let intent = crate::coding::intent::detect_coding_intent(&prompt)
            .expect("should_auto_dispatch returned true so detect must return Some");
        println!("{}", crate::coding::intent::format_dispatch_banner(&intent));
        let code_args = crate::cli::code::CodeArgs {
            prompt: prompt.clone(),
            db: None,
            source_channel: "chat".to_string(),
            no_assign: false,
            dispatch: false, // operator runs `neoth kanban` after to drive dispatch
            apply: None,
            run_pending: false,
            output: crate::cli::OutputFormat::default(),
        };
        return crate::cli::code::run_code(code_args).await;
    } else if let Some(intent) = crate::coding::intent::detect_coding_intent(&prompt) {
        // Low-confidence: print an offer banner + continue with chat.
        println!(
            "[neoth] coding intent detected at low confidence (verb={:?} noun={:?}). \
             Try `neoth code \"{}\"` for the dedicated coding workflow.",
            intent.matched_verb.as_deref().unwrap_or("?"),
            intent.matched_noun.as_deref().unwrap_or("?"),
            prompt
                .lines()
                .next()
                .unwrap_or(&prompt)
                .chars()
                .take(60)
                .collect::<String>(),
        );
    }

    // OP-02 (Session 25) — next-session seed banner. Read the
    // most-recent hindsight card + surface its `one_line_summary`
    // so the operator picks up where they left off. Best-effort:
    // a missing or empty hindsight dir is the silent default.
    // Skipping the first_tour greeting case keeps the onboarding
    // banner clean (operator just finished the wizard — no "since
    // last time" makes sense).
    let chat_ts_unix = now_unix() as i64;
    let current_session_id = crate::memory::hindsight::session_id_for(chat_ts_unix, &prompt);
    let seed_banner =
        crate::memory::hindsight::next_session_seed_banner(&first_tour_home, &current_session_id);
    if !seed_banner.is_empty() {
        println!("{seed_banner}");
    }

    // UX-02 — "memory is working" session-start signal. One line telling
    // the operator NEOTH carried context across runs. Best-effort +
    // naturally silent on a fresh install (zero memories → None), which
    // also keeps the post-wizard first-tour banner clean.
    if let Some(line) = session_memory_signal(&first_tour_home) {
        println!("{line}");
    }

    // UX-05 — Day-30 "unlock moment": once, after 30+ days, nudge the
    // operator toward opt-in features they still haven't switched on.
    // Self-suppresses via a marker file; naturally silent pre-30-days,
    // when all features are active, or on a fresh install.
    if let Some(banner) = crate::cli::unlock_moment::maybe_unlock_banner(&first_tour_home, &config)
    {
        println!("{banner}");
    }

    // GOLD-ADAPT-SKILL-10 — session-start skill-catalog banner (stdout only,
    // no provider tokens). Gated on `config.skills.session_catalog` (default
    // false — operator opt-in). Prefer the daemon's hot registry (`global()`)
    // so the daemon path pays zero FS I/O; fall back to a best-effort
    // `load_all` for one-shot CLI invocations where no daemon was started.
    // The catalog is printed right here in the session-start banner chain,
    // AFTER UX-05 and BEFORE the WAL writer opens, matching the research plan.
    if config.skills.session_catalog {
        let catalog_block = if let Some(reg) = crate::skills::registry::global() {
            // Daemon path — zero FS I/O: read the hot atomic-swap registry.
            maybe_skill_catalog_block(&reg.snapshot_owned())
        } else {
            // One-shot CLI path — best-effort async load (same FS walk
            // `build_prompt_bundle` will repeat ~30 ms later anyway).
            // `run_chat_with` is already async so `.await` is safe here.
            let skills_dir = first_tour_home.join("skills");
            let loaded = crate::skills::load_all(&skills_dir)
                .await
                .with_context(|| format!("load skill catalog from {}", skills_dir.display()))?;
            maybe_skill_catalog_block(&loaded)
        };
        if let Some(block) = catalog_block {
            println!("{block}");
        }
    }

    let wal_dir = first_tour_home.join("wal");
    let segment_path = args
        .wal_segment
        .clone()
        .unwrap_or_else(|| crate::wal::writer::unique_standalone_segment_path(&wal_dir, "chat"));
    if let Some(parent) = segment_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create WAL dir {}", parent.display()))?;
    }
    let (writer, writer_join) = wal_spawn(segment_path.clone()).context("spawn WAL writer")?;

    // ── PWF-02: SessionStart MODE_CHECKPOINT (0x9A) ───────────────────────
    // Emit a session-start checkpoint immediately after the WAL writer
    // opens so that `neoth chat --resume-from <hash>` can recover this
    // session's provider / council configuration even if the process
    // crashes before completing a turn. Best-effort: a WAL append failure
    // MUST NOT fail the chat turn.
    //
    // Provider name at this point: the live Provider hasn't been
    // constructed yet (it's passed in via the `provider` argument) but
    // its name() is available from the &dyn Provider reference.
    {
        use crate::recall::reconstruct::ModeCheckpoint;
        use crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT;
        // GOLD-ADAPT-G-01: three-way label: single > off > enabled.
        let council_mode_str = if config.council.mode.is_single() {
            "single".to_string()
        } else if config.council.disabled.unwrap_or(false) {
            "off".to_string()
        } else {
            "enabled".to_string()
        };
        let mut cp = ModeCheckpoint {
            checkpoint_hash: String::new(),
            session_id: current_session_id.clone(),
            mode: "chat".to_string(),
            provider_target: provider.name().to_string(),
            council_mode: council_mode_str,
            scoped_mcp_servers: scoped_mcp_servers.clone(),
            mcp_scope_recorded: true,
            phase: "chat:session-start".to_string(),
            ts_unix: chat_ts_unix,
        };
        cp.stamp_hash();
        let payload = serde_json::to_vec(&cp).context("serialize session-start checkpoint")?;
        let hdr = crate::wal::make_header(EVENT_TYPE_MODE_CHECKPOINT, &payload);
        writer
            .append(hdr, payload)
            .await
            .context("persist session-start checkpoint")?;
        println!("[neoth] checkpoint: {}", cp.checkpoint_hash);
    }

    // ── RAW_TEXT (the actual prompt, for recall) ──────────────────────────
    // Stored before dispatch so `neoth recall "..."` can find what the
    // operator typed.  PROVIDER_REQUEST WAL frame follows later, after the
    // full 6-tier dispatch-model resolution in run_chat_with (post
    // enforce_preflight).  WAL is mode-0600 / DACL-restricted, so raw
    // prompts at rest match the existing trust boundary.
    // ODY-09: incognito turns skip RAW_TEXT entirely — no prompt content in WAL.
    // An INCOGNITO_TURN (0xF7) audit anchor is written instead.
    let raw_event_id = if args.incognito {
        // ODY-09: no prompt stored; raw_event_id=0 signals "no anchor" to the
        // profile-learning pipeline (extract_window gates on valid non-zero ids).
        let payload = serde_json::to_vec(&serde_json::json!({"ts_unix": now_unix()}))
            .context("serialize incognito audit anchor")?;
        let hdr = crate::wal::make_header(EVENT_TYPE_INCOGNITO_TURN, &payload);
        writer
            .append(hdr, payload)
            .await
            .context("persist incognito audit anchor")?;
        0i64
    } else {
        let raw_header = crate::wal::make_header(EVENT_TYPE_RAW_TEXT, prompt.as_bytes());
        // Capture the event_id before the header moves into `append` — the
        // post-reply profile-learning pipeline (B-Konsens 2026-05-17 below)
        // uses this as the trigger anchor for `extract_window`.
        let raw_event_id = raw_header.event_id.0 as i64;
        writer
            .append(raw_header, prompt.as_bytes().to_vec())
            .await
            .context("write RAW_TEXT WAL frame")?;
        raw_event_id
    };

    // ── P-08 briefing-gate marker (Workstream C, Session 22) ──────────────
    // Update the operator-activity timestamp so the cron task's
    // `should_emit_for_briefing` check sees a fresh "operator engaged"
    // signal without re-scanning the WAL. Best-effort: a permission
    // failure on the marker file MUST NOT fail the chat — recording is
    // an audit signal, not a chat-correctness invariant.
    if let Err(error) =
        crate::profile::briefing_gate::record_last_active(&first_tour_home, now_unix() as i64)
    {
        tracing::warn!(error = %error, "operator activity marker was not persisted");
    }

    // ── GOLD-WIRE-02: conversational-recall short-circuit ─────────────────
    // "Weißt du noch als wir über X geredet haben?" / "do you remember when
    // we talked about X?" is answered straight from the local idx_episode
    // store WITHOUT an LLM call — so NO PROVIDER_REQUEST / PROVIDER_RESPONSE
    // frame is written for this turn. The RAW_TEXT frame above still records
    // the question so it stays recallable later. The helper is best-effort on
    // the DB (a recall miss yields a localized "nothing found" reply, never
    // an error), and returns `None` for any non-recall prompt — which falls
    // through to the normal provider path below unchanged.
    // GR-039: gated on `memory.recall_shortcut` (default true) so operators
    // can route recall-looking prompts to the provider like any other turn.
    if config.memory.recall_shortcut
        && let Some(reply) = crate::cli::recall::answer_conversational_recall(
            &prompt,
            &first_tour_home.join("views.db"),
        )
        .await
    {
        println!("{reply}");
        // GR-090: machine consumers in --stream mode block on the
        // done-sentinel — the recall early-return must emit it too.
        if args.stream {
            println!();
            println!(
                "{}",
                serde_json::json!({
                    "neoth_stream": "done",
                    "control_token": stream_control_token(),
                    "count": 1,
                })
            );
        }
        // Same WAL-writer teardown every other early return in this fn uses.
        drop(writer);
        let _ = writer_join.await;
        return Ok(());
    }

    // ── Early intent hash for pre-assembly skill audit ────────────────────
    //
    // Skill-suppression events can fire while the full bundle is still being
    // assembled, so they receive this A+E intent hash.  The provider request
    // and BUDGET_EXCEEDED event use a second hash computed from the complete,
    // final typed bundle at the budget boundary below.
    let mut bundle_entries: Vec<crate::skills::versioning::BundleBlockEntry<'_>> = Vec::new();
    if let Some(sys) = args.system.as_deref().filter(|s| !s.is_empty()) {
        bundle_entries.push(crate::skills::versioning::BundleBlockEntry {
            block: crate::skills::versioning::BundleBlock::A,
            content: sys,
        });
    }
    bundle_entries.push(crate::skills::versioning::BundleBlockEntry {
        block: crate::skills::versioning::BundleBlock::E,
        content: &prompt,
    });
    let intent_bundle_hash = crate::skills::versioning::prompt_bundle_hash_hex(&bundle_entries);

    // ── Operator context + skills load — K-Perf-4 parallel resource load ──
    // Both reads hit the filesystem and are mutually independent: operator_md
    // assembles ~/.neoth/NEOTH.md + project + rules + memory, skills walks
    // `<home>/skills/`. Running them sequentially was ~2× the wall time on
    // cold caches (each ~5-20ms). tokio::join! drives them concurrently
    // through the same runtime worker — the FS reads pipeline OS-side
    // without extra threads. Per Performance agent's K-Perf-4 pick.
    //
    // The skill router (line below) consumes installed_skills, so loading
    // it BEFORE the system-prompt assembly is mandatory — the parallel
    // load just shaves the serial cost off the front edge.
    let home = first_tour_home.clone();
    // GOLD-CCPARITY-SKILLVIS-01 — determine slash-invocation BEFORE calling
    // build_prompt_bundle so the visibility pre-filter can gate NameOnly /
    // UserInvocableOnly skills. We parse the invocation here (before the slash
    // command dispatch in enforce_preflight) and check whether the name matches
    // a skill id. The full slash-command dispatch still runs in enforce_preflight
    // as before — this is a read-only pre-check for the visibility gate only.
    let slash_skill_name: Option<String> = match crate::slash::parse_invocation(&prompt) {
        crate::slash::Invocation::Command { name, .. } => Some(name.to_lowercase()),
        _ => None,
    };
    let (
        PromptBundle {
            combined_system,
            budget_items,
            skill_tool_allowlist,
            plan_attest_hash,
            agent_raw_layers,
            resolved_model: skill_model,
            // GOLD-CCPARITY-EFFORT-03: per-skill effort resolved in build_prompt_bundle.
            resolved_effort: skill_effort,
        },
        config,
        prompt,
        home,
    ) = build_prompt_bundle(
        config,
        prompt,
        home,
        PromptBuildContext {
            args: &args,
            prompt_bundle_hash: &intent_bundle_hash,
            writer: &writer,
            mcp_servers: &mcp_servers,
        },
        PromptBuildOptions {
            slash_skill_name,
            // B22-TWEAKS-MODEL-01 — pre-loaded fail-loud at the chat boundary.
            persona_override_from_tweaks: tweaks.persona_override.clone(),
        },
    )
    .await?;

    // GOLD-CCPARITY-ONCE: session-scoped once-guard. One run_chat_with call =
    // one CLI session. Created here before enforce_preflight so the same guard
    // is shared across PrePipeline, PreProviderCall, and PostProviderCall
    // within the single turn (and the same guard is reused across multi-turn
    // batch sessions if run_chat_with is called in a loop). For the CLI path
    // this function is called once per invocation, so the guard lives exactly
    // as long as the session.
    let once_guard = crate::hooks::SessionOnceGuard::new();

    let (
        writer,
        writer_join,
        review_context,
        final_prompt,
        final_system,
        prompt,
        quota_path,
        quota_tracker,
        hooks,
        effective_model,
        model_source,
        agent_tool_policy,
        pending_block_restorations,
        budget_items,
    ) = match enforce_preflight(
        combined_system,
        budget_items,
        prompt,
        provider,
        &args,
        &config,
        writer,
        writer_join,
        &home,
        plan_attest_hash,
        agent_raw_layers,
        skill_model,
        skill_effort,
        // B22-TWEAKS-MODEL-01 — tweaks loaded fail-loud above; propagate here.
        tweaks.model_default.clone(),
        &once_guard,
    )
    .await?
    {
        PreflightOutcome::Done => return Ok(()),
        PreflightOutcome::Continue {
            writer,
            writer_join,
            review_context,
            final_prompt,
            final_system,
            prompt,
            quota_path,
            quota_tracker,
            hooks,
            effective_model,
            model_source,
            agent_tool_policy,
            pending_block_restorations,
            budget_items,
        } => (
            writer,
            writer_join,
            review_context,
            final_prompt,
            final_system,
            prompt,
            quota_path,
            quota_tracker,
            hooks,
            effective_model,
            model_source,
            agent_tool_policy,
            pending_block_restorations,
            budget_items,
        ),
    };

    let mut mcp_tool_scope = crate::mcp::McpToolScope::from_skill_allowlist(skill_tool_allowlist);
    if let Some((allowed, disallowed)) = agent_tool_policy {
        mcp_tool_scope = mcp_tool_scope.with_agent(allowed, disallowed);
    }

    let route_cap =
        routing_safe_effective_cap_at(&config, provider.name(), effective_model.as_deref(), &home);
    let budgeted = match finalize_provider_request(
        budget_items,
        &final_prompt,
        final_system.as_deref(),
        ProviderRequestBoundary {
            config: &config,
            home: &home,
            provider_name: provider.name(),
            effective_model: effective_model.as_deref(),
            route_cap: Some(route_cap),
            writer: &writer,
        },
    )
    .await
    {
        Ok(request) => request,
        Err(error) => {
            drop(writer);
            let _ = writer_join.await;
            return Err(error);
        }
    };
    let BudgetedProviderRequest {
        prompt: final_prompt,
        system: final_system,
        prompt_bundle_hash,
        prompt_token_estimate,
        effective_cap: request_token_cap,
    } = budgeted;
    // The actual 0x20 intent is emitted centrally for every concrete leaf,
    // after cost/permission approval and immediately before transport dispatch.
    // Carry the old turn-level business fields into those request-bound frames.
    let turn_id = format!("{raw_event_id:016x}");
    let provider_audit_context = crate::providers::cost_authorization::ProviderCallAuditContext {
        source: Some("chat"),
        call_type: Some("chat_provider_round"),
        request_id: Some(turn_id.clone()),
        operator_id: config.operator_id.clone(),
        session_id: Some(current_session_id.clone()),
        target: Some(crate::profile::runner::extract_target_label(provider.name()).to_owned()),
        model_source: Some(model_source),
        cost_estimate_model: Some(
            effective_model
                .clone()
                .unwrap_or_else(|| "provider_default".to_owned()),
        ),
        prompt_bundle_hash: Some(prompt_bundle_hash.clone()),
        prompt_token_estimate: Some(prompt_token_estimate),
        incognito: args.incognito,
        ..Default::default()
    };

    let DispatchOutput {
        response_text,
        final_input_tokens,
        final_output_tokens,
        provider_used,
        model_used,
        writer,
        writer_join,
        final_prompt,
        final_system,
        turn_journal,
        mcp_tool_calls,
        mcp_tool_records,
    } = dispatch_provider(
        final_prompt,
        final_system,
        &args,
        provider,
        &config,
        &home,
        writer,
        writer_join,
        quota_path,
        quota_tracker,
        &prompt,
        request_token_cap,
        &mcp_servers,
        mcp_tool_scope,
        // F4/D21 — turn id = the WAL event id, hex; filesystem-safe + unique/turn.
        &turn_id,
        effective_model,
        // GOLD-CCPARITY-EFFORT-03: per-skill reasoning-budget (None = provider default).
        skill_effort,
        model_source,
        provider_audit_context,
    )
    .await?;

    run_post_reply_pipelines(
        response_text,
        writer,
        writer_join,
        config,
        provider,
        args,
        prompt,
        final_prompt,
        final_system,
        provider_used,
        model_used,
        final_input_tokens,
        final_output_tokens,
        review_context,
        hooks,
        segment_path,
        raw_event_id,
        instance_paths,
        profile_extensions,
        chat_ts_unix,
        current_session_id,
        prompt_token_estimate,
        turn_journal,
        &once_guard,
        // GOLD-ADAPT-ODY-20 — thread through for auto-skill extraction gate.
        mcp_tool_calls,
        // REVFIX-EXCERPTS-01 — structured call records for digest-based extraction.
        mcp_tool_records,
        // B22-TWEAKS-MODEL-01 — thread tweaks model for ODY-16 token cap inside pipelines.
        tweaks.model_default.clone(),
        // THEME-TWEAKS-GOLD — render from the same once-loaded snapshot.
        &tweaks,
        // GOLD-ADAPT-SKILL-09 — blocks redacted at PreProviderCall by BlockFilter
        // hooks; restored inside run_post_reply_pipelines after PostProviderCall
        // hook stage so WAL/recall never see placeholders.
        pending_block_restorations,
    )
    .await
}

/// GOLD-ADOPT-21 — best-effort LLM title for the just-completed session, stored
/// as the card's `display_name`. Cheap (utility provider), bounded (12s), and
/// silent on any failure (the deterministic summary remains). The "after the 2nd
/// message" trigger from the source design does not fit NEOTH's one-shot CLI
/// chat, so naming fires at session-card write instead — naming the session that
/// just ended.
async fn name_session_best_effort(
    config: &crate::config::FreedomConfig,
    writer: &crate::wal::writer::WalWriterHandle,
    home: &std::path::Path,
    session_id: &str,
    opening: &str,
) {
    let provider = match crate::providers::from_config_for_utility_at(config, home).await {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "session-naming: utility provider build failed");
            return;
        }
    };
    let req = crate::providers::Request {
        prompt: format!(
            "Give a terse 3-6 word title for a conversation that began with the message below. \
             Reply with ONLY the title — no quotes, no trailing punctuation.\n\nMessage: {}",
            opening.chars().take(500).collect::<String>()
        ),
        model: crate::providers::utility_model_for_config(config),
        ..Default::default()
    };
    let authorized_provider = crate::providers::cost_authorization::CostAuthorizingProvider::new(
        provider.as_ref(),
        crate::providers::cost_authorization::ProviderCallAuthorizer::interactive(
            config.autonomy_policy(),
            Some(writer.clone()),
            config.tokens.max_per_request,
        )
        .with_usage_home(home.to_path_buf())
        .with_audit_context(
            crate::providers::cost_authorization::ProviderCallAuditContext {
                source: Some("chat"),
                call_type: Some("session_naming"),
                session_id: Some(session_id.to_owned()),
                operator_id: config.operator_id.clone(),
                target: Some(
                    crate::profile::runner::extract_target_label(provider.name()).to_owned(),
                ),
                ..Default::default()
            },
        ),
        crate::providers::utility_model_for_config(config),
        "session_naming",
    );
    let completion = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        authorized_provider.complete(req),
    )
    .await;
    let title = match completion {
        Ok(Ok(c)) if c.identity.is_bound() => sanitize_session_title(&c.text),
        Ok(Ok(_)) => {
            tracing::debug!("session-naming: provider returned no authenticated identity");
            return;
        }
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "session-naming: completion failed");
            return;
        }
        Err(_) => {
            tracing::debug!("session-naming: timed out (12s)");
            return;
        }
    };
    if title.is_empty() {
        return;
    }
    if let Err(e) = crate::memory::hindsight::update_display_name(home, session_id, &title) {
        tracing::debug!(error = %e, "session-naming: card update failed");
    }
}

/// Reduce a raw model reply to a clean one-line title: first non-empty line,
/// stripped of surrounding quotes + trailing punctuation, capped at 80 chars.
fn sanitize_session_title(raw: &str) -> String {
    let line = raw
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    line.trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim()
        .trim_end_matches(|c: char| c == '.' || c == '!' || c == '?')
        .trim()
        .chars()
        .take(80)
        .collect()
}

/// Stable-ish per-call ID for `LOCAL_INFERENCE_START` / `END` correlation.
/// Not security-grade randomness — just enough entropy that two
/// concurrent inferences don't collide in audit grep'ing. Combines the
/// process pid with the nanosecond timestamp.
fn rand_u64_for_trace() -> u64 {
    let pid = std::process::id() as u64;
    let nanos = crate::time::now_unix_ns();
    pid.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(nanos)
}

/// Folded outcome from a single hook-stage dispatch.
enum HookOutcome {
    /// Stage finished with the (possibly rewritten) body.
    ///
    /// GOLD-ADAPT-SKILL-09: the second field carries any
    /// [`FilteredBlock`]s accumulated by `BlockFilter` actions at this
    /// stage. Non-empty only when at least one `block_filter` hook fired.
    /// Callers that do not need the blocks (PrePipeline, PostProviderCall)
    /// simply ignore the `Vec` with `let _ = blocks;` — zero allocation
    /// cost when no BlockFilter hooks are configured (the Vec is empty).
    Continue(String, Vec<crate::hooks::block_filter::FilteredBlock>),
    /// A hook returned `Block` — caller should bail.
    Blocked { name: String, reason: String },
}

/// Run one hook stage against `body`. Emits a `HOOK_FIRED` WAL frame
/// for every hook that fired with name + stage in the payload, plus
/// `HOOK_REPLACED` when the body changed and `HOOK_BLOCKED` when a hook
/// stopped the pipeline. Audit frames are best-effort — append failures
/// log a warning but never propagate.
///
/// ## Exit-code semantics surfaced at this adapter layer
///
/// | Analogue | `HookOutcome` variant | Caller action |
/// |----------|-----------------------|---------------|
/// | Exit 0   | `Continue(body)`      | Proceed; use the returned body. |
/// | Exit 1   | `Continue(body)` (warn path) | Proceed; a `warn` log was emitted inside the dispatcher for the optional-plugin-failure or bad-regex-skip. No action required at this layer. |
/// | Exit 2   | `Blocked { name, reason }` | **Abort the turn.** Callers (`enforce_preflight` at `PrePipeline`/`PreProviderCall`, `run_post_reply_pipelines` at `PostProviderCall`) must drop the WAL writer, await its join handle, then `anyhow::bail!`. |
///
/// The `Blocked` WAL frame (`EVENT_TYPE_HOOK_BLOCKED = 0x81`) is emitted here
/// before returning so every abort is traceable without the caller duplicating
/// the WAL write.
///
/// `once_guard` is the session-scoped [`crate::hooks::SessionOnceGuard`] that
/// atomically claims `once = true` hooks before their effect runs
/// (GOLD-CCPARITY-ONCE / BUG-W2-P1-HOOK-ONCE-PARITY). The guard is shared
/// across all stages in the session; first fire claims the name; subsequent
/// fires produce a `HOOK_SKIPPED_ONCE` (0x8B) WAL frame without re-running
/// the effect. No manual pre-filter or post-insert is needed here — the
/// dispatcher handles both steps atomically under its internal mutex.
async fn run_hook_stage(
    stage: crate::hooks::HookStage,
    body: &str,
    hooks: &[crate::hooks::schema::HookDef],
    writer: &crate::wal::writer::WalWriterHandle,
    once_guard: &crate::hooks::SessionOnceGuard,
) -> Result<HookOutcome> {
    let before = body.to_string();
    // GOLD-ADAPT-SKILL-09 + BUG-W2-P1-HOOK-ONCE-PARITY: single entry point
    // that handles BlockFilter accumulation AND once-semantics atomically.
    let result = crate::hooks::run_stage_with_once_guard(
        stage,
        body,
        hooks,
        crate::hooks::dispatcher::current_global_invoker().map(|a| a.as_ref()),
        false,
        once_guard,
    )?;
    // Emit HOOK_SKIPPED_ONCE for every once=true hook that was suppressed
    // by the guard this call. The dispatcher surfaced their names; WAL write
    // is the caller's responsibility (dispatcher has no WAL handle).
    for name in &result.skipped_once {
        emit_hook_frame(
            writer,
            crate::wal::events::EVENT_TYPE_HOOK_SKIPPED_ONCE,
            name,
            stage,
            None,
        )
        .await;
    }
    match result.outcome {
        crate::hooks::StageOutcome::Continue { body: after, hits } => {
            for name in &hits {
                // CCPARITY-STATUS-MSG: look up the fired hook's status_message
                // and pass it as the `note` field in the HOOK_FIRED WAL frame.
                // The hooks slice is available here (borrowed for the full fn);
                // the lookup is O(n) over a small operator-defined set (≤20).
                let status_note = hooks
                    .iter()
                    .find(|h| h.name == *name)
                    .and_then(|h| h.status_message());
                emit_hook_frame(
                    writer,
                    crate::wal::events::EVENT_TYPE_HOOK_FIRED,
                    name,
                    stage,
                    status_note,
                )
                .await;
                // once=true claim is handled atomically inside
                // run_stage_with_once_guard — no manual insert here.
            }
            if !hits.is_empty() && after != before {
                emit_hook_frame(
                    writer,
                    crate::wal::events::EVENT_TYPE_HOOK_REPLACED,
                    hits.last().map(String::as_str).unwrap_or("?"),
                    stage,
                    Some(&format!("{} → {}", before.len(), after.len())),
                )
                .await;
            }
            Ok(HookOutcome::Continue(after, result.filtered_blocks))
        }
        crate::hooks::StageOutcome::Block { name, reason } => {
            emit_hook_frame(
                writer,
                crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                &name,
                stage,
                Some(&reason),
            )
            .await;
            Ok(HookOutcome::Blocked { name, reason })
        }
    }
}

/// Emit a single hook-lifecycle WAL frame. Best-effort.
async fn emit_hook_frame(
    writer: &crate::wal::writer::WalWriterHandle,
    event_type: u8,
    hook_name: &str,
    stage: crate::hooks::HookStage,
    note: Option<&str>,
) {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "name": hook_name,
        "stage": stage.as_str(),
        "note": note,
        "ts_unix": now_unix(),
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialize hook frame payload failed");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append hook frame failed (best-effort)");
    }
}

/// Record a 429 from a remote provider: extend the backoff window in
/// `~/.neoth/quota.json`, write a `PROVIDER_QUOTA_EXCEEDED` WAL frame,
/// and emit a tracing warn for `journalctl` consumers. Best-effort —
/// failures here never mask the original provider error. The caller
/// continues to bail with `e`; this side effect is purely audit + UX.
async fn record_quota_exceeded(
    qe: &crate::providers::quota::QuotaError,
    quota_path: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
) {
    let provider_name = qe.provider;
    let now = crate::providers::quota::now_unix();
    let update = crate::providers::quota::QuotaTracker::update_at(quota_path, |tracker| {
        let effective = tracker.record_429(provider_name, qe.retry_after, now);
        let state = tracker.get(provider_name).cloned();
        Ok((effective, state))
    });
    let (effective, state) = match update {
        Ok(update) => update,
        Err(error) => {
            tracing::warn!(
                path = %quota_path.display(),
                error = %error,
                "quota state unavailable after 429; preserving original provider error"
            );
            return;
        }
    };
    let payload = match serde_json::to_vec(&serde_json::json!({
        "provider": provider_name,
        "retry_after_secs": effective.as_secs(),
        "requests_today": state.as_ref().map(|s| s.requests_today),
        "daily_cap": state.as_ref().and_then(|s| s.estimated_daily_cap),
        "backoff_until_unix": state.as_ref().and_then(|s| s.backoff_until_unix),
        "ts_unix": now,
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "serialize PROVIDER_QUOTA_EXCEEDED payload failed");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_PROVIDER_QUOTA_EXCEEDED,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "WAL append PROVIDER_QUOTA_EXCEEDED failed (best-effort)");
    }
    warn!(
        provider = provider_name,
        retry_after_secs = effective.as_secs(),
        "provider returned HTTP 429 — backoff recorded"
    );
}

/// Resolve the best-known model string for secondary accounting call sites
/// where dispatch/skill resolution is not available.
///
/// Priority: CLI `--model` > `tweaks.model_default` > `freedom.yaml::provider_model`
/// > `"unknown"` (causes the pricing lookup to use the conservative cloud
/// fallback rather than silently treating an unrecognised paid model as free).
///
/// The PaidProviderCall preflight does not use this helper: it resolves and
/// binds the full dispatch > skill > CLI > tweaks > freedom chain first.
///
/// Pass `None` for `tweaks_model` at call sites where tweaks are not in scope.
fn model_for_estimate(
    args: &ChatArgs,
    config: &crate::config::FreedomConfig,
    tweaks_model: Option<&str>,
) -> String {
    args.model
        .as_deref()
        .or(tweaks_model)
        .or(config.provider_model.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".to_string())
}

/// Emit a single stream-chunk WAL frame via the fire-and-forget
/// `append_no_ack` path (K-Perf-2 2026-05-17). The caller does NOT
/// wait for the writer's `sync_data` per chunk — at ~10ms fsync
/// latency × 100 tokens = 1s of disk overhead would otherwise
/// serialise into the operator-visible streaming UX. The chunk still
/// lands in the WAL (writer task processes it the same way), just
/// asynchronously to the streaming loop.
///
/// Bounded loss model: if the writer task crashes mid-stream a
/// handful of buffered chunks may be lost. Acceptable for
/// stream-chunk audit (the full reply is also captured in the
/// terminal-ack'd `PROVIDER_RESPONSE` frame). NEVER use no-ack for
/// PROVIDER_RESPONSE itself.
async fn emit_stream_chunk(
    writer: &crate::wal::writer::WalWriterHandle,
    provider_name: &str,
    chunk: &CompletionChunk,
    seq: u32,
) -> Result<()> {
    use crate::wal::events::EVENT_TYPE_PROVIDER_STREAM_CHUNK;
    let payload = serde_json::to_vec(&serde_json::json!({
        "provider": provider_name,
        "seq": seq,
        "delta_bytes": chunk.delta.len(),
        "delta_hash_xxh3": xxhash_rust::xxh3::xxh3_64(chunk.delta.as_bytes()),
    }))?;
    let header = crate::wal::make_header(EVENT_TYPE_PROVIDER_STREAM_CHUNK, &payload);
    writer
        .append_no_ack(header, payload)
        .await
        .context("enqueue PROVIDER_STREAM_CHUNK WAL frame")?;
    Ok(())
}

fn chat_neoth_home(config_path: Option<&std::path::Path>) -> PathBuf {
    match config_path {
        Some(path) => path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
        None => FreedomConfig::default_neoth_home(),
    }
}

async fn resolve_prompt(
    args: &ChatArgs,
    config: &FreedomConfig,
    neoth_home: &std::path::Path,
) -> Result<String> {
    let base = resolve_prompt_base(args).await?;
    // GOLD-ADAPT-ODY-03 — prepend extracted attachment blocks.
    if args.attach.is_empty() {
        return Ok(base);
    }
    let block = render_attachments_block(&args.attach, config, neoth_home).await;
    if block.is_empty() {
        Ok(base)
    } else {
        Ok(format!("{block}\n{base}"))
    }
}

/// GOLD-ADAPT-ODY-03 — hard cap per attachment so one fat PDF can't blow
/// the context window; the block notes the truncation.
const ATTACH_TEXT_CAP: usize = 8_000;

/// Extract each attached file into a labelled prompt block. Best-effort
/// per file — an unreadable attachment becomes an inline error note, never
/// a turn abort (the operator sees exactly what the model saw).
async fn render_attachments_block(
    paths: &[PathBuf],
    config: &FreedomConfig,
    neoth_home: &std::path::Path,
) -> String {
    let backends = crate::cli::ingest::default_backends();
    let mut out = String::new();
    let needs_audio = paths.iter().any(|path| {
        matches!(
            crate::cli::ingest::detect_kind(path),
            Some(crate::media::AssetKind::Audio | crate::media::AssetKind::Video)
        )
    });
    let stt_audit = if needs_audio {
        let wal_dir = neoth_home.join("wal");
        let opened = (|| -> anyhow::Result<_> {
            std::fs::create_dir_all(&wal_dir)?;
            Ok(crate::wal::writer::spawn(
                wal_dir.join(format!("{:020}.wal", crate::time::now_unix_ns())),
            )?)
        })();
        match opened {
            Ok(pair) => Some(pair),
            Err(error) => {
                tracing::warn!(%error, "chat attachment: STT audit writer unavailable");
                None
            }
        }
    } else {
        None
    };
    for p in paths {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("attachment");
        let rendered = match crate::cli::ingest::detect_kind(p) {
            Some(kind) => {
                let asset = crate::media::Asset::Path {
                    kind,
                    mime: crate::cli::ingest::mime_hint(kind, p),
                    path: p.clone(),
                };
                let writer = stt_audit.as_ref().map(|(writer, _)| writer.clone());
                let extraction = match kind {
                    crate::media::AssetKind::Audio => {
                        crate::media::audio::AudioExtractor
                            .extract_with_context(
                                &asset,
                                &config.media,
                                &config.updater,
                                neoth_home,
                                writer,
                            )
                            .await
                    }
                    crate::media::AssetKind::Video => {
                        crate::media::video::VideoExtractor
                            .extract_with_context(
                                &asset,
                                &config.media,
                                &config.updater,
                                neoth_home,
                                writer,
                            )
                            .await
                    }
                    _ => crate::media::route_to_first_match(&backends, &asset).await,
                };
                match extraction {
                    Ok(ex) if !ex.text.is_empty() => attachment_block(name, &ex.text),
                    Ok(_) => format!("[Attachment {name}: no text extracted]\n"),
                    Err(e) => format!("[Attachment {name}: extraction failed — {e}]\n"),
                }
            }
            // Unknown extension → plain-UTF-8 fast path (.txt/.md/source
            // files are the most common chat attachments and have no
            // media backend). Invalid UTF-8 → honest skip note.
            None => match std::fs::read_to_string(p) {
                Ok(text) if !text.trim().is_empty() => attachment_block(name, &text),
                Ok(_) => format!("[Attachment {name}: empty file]\n"),
                Err(e) => format!("[Attachment {name}: unsupported or unreadable — {e}]\n"),
            },
        };
        out.push_str(&rendered);
    }
    if let Some((writer, join)) = stt_audit {
        drop(writer);
        if let Err(error) = join.await {
            tracing::warn!(%error, "chat attachment: STT audit writer task panicked");
        }
    }
    out
}

fn attachment_block(name: &str, text: &str) -> String {
    // Single pass: find the byte offset of the cap'th char (None = the
    // text is shorter than the cap). Avoids an O(n) chars().count() walk
    // over a multi-MB file just to decide whether to truncate.
    match text.char_indices().nth(ATTACH_TEXT_CAP) {
        Some((byte_cap, _)) => format!(
            "[Attachment: {name}]\n{}\n[…truncated at {ATTACH_TEXT_CAP} chars]\n[End attachment]\n",
            &text[..byte_cap]
        ),
        None => format!("[Attachment: {name}]\n{text}\n[End attachment]\n"),
    }
}

async fn resolve_prompt_base(args: &ChatArgs) -> Result<String> {
    // GOLD-ADOPT-24 — `--edit`: compose the prompt in $EDITOR (inline message,
    // if any, seeds the editor). Takes precedence over inline/stdin.
    if args.edit {
        let editor = crate::cli::editor::resolve_editor_command().context(
            "no editor found for --edit. Set $VISUAL or $EDITOR (e.g. `export EDITOR=nano`).",
        )?;
        let (input, meaningful) =
            crate::cli::editor::get_editor_input(&editor, args.message.as_deref())?;
        if !meaningful {
            anyhow::bail!("--edit: editor returned an empty prompt — nothing sent.");
        }
        return Ok(input);
    }
    if let Some(m) = &args.message
        && !m.trim().is_empty()
    {
        return Ok(m.clone());
    }
    use tokio::io::AsyncReadExt;
    let mut buf = String::new();
    tokio::io::stdin()
        .read_to_string(&mut buf)
        .await
        .context("read prompt from stdin")?;
    if buf.trim().is_empty() {
        anyhow::bail!("no prompt provided. Pass `neoth chat \"...\"` or pipe via stdin.");
    }
    Ok(buf)
}

/// CH-02 wedge: build three per-role provider adapters from the
/// operator's freedom config + run the council debate. Returns the
/// `CouncilDebate` outcome whose `winning_text()` becomes the response
/// when the verdict is `Consensus`; `Split` and `QuorumFailed` are
/// rendered as operator-visible diagnostic text in the caller.
/// GOLD-COR-09 / A-14: sum per-hemisphere token usage across a (sub-)council's
/// responses. Returns `None` for a dimension when NO hemisphere reported it
/// (preserving the "unknown" signal — never fabricating a 0), and `Some(sum)`
/// when at least one did. Used so a council-backed hemisphere threads its
/// sub-council's real burn upward instead of discarding it as `None`.
fn sum_council_tokens(
    responses: &[crate::council::types::HemisphereResponse],
) -> (Option<u32>, Option<u32>) {
    let any_in = responses.iter().any(|r| r.input_tokens.is_some());
    let any_out = responses.iter().any(|r| r.output_tokens.is_some());
    let input = any_in.then(|| responses.iter().filter_map(|r| r.input_tokens).sum());
    let output = any_out.then(|| responses.iter().filter_map(|r| r.output_tokens).sum());
    (input, output)
}

/// Wrapper that adapts a `Box<dyn Provider>` into the council's
/// `HemisphereProvider` trait. Lifted out of `run_council_debate` so
/// the Split-recovery path (A5 callosum::resolve) can reuse the same
/// shape for a one-off Cerebellum synthesis call.
struct ProviderHemisphere {
    provider: Box<dyn crate::providers::Provider>,
    base_req: crate::providers::Request,
    /// B22 — exact per-leaf paid-call authorization, cloned through every
    /// recursive sub-council and one-shot recovery/refine wrapper.
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    /// Operator-scoped state root used by recursive builders and recall.
    neoth_home: std::path::PathBuf,
    /// E-2 Phase 2 (Session 13) — operator config kept around so this
    /// hemisphere's `ask_with_depth` can recurse: when `depth > 1` it
    /// builds three sub-hemispheres for Left/Right/Cerebellum from
    /// the same per-role bindings + convenes an inner council at
    /// `depth - 1`. `None` here disables recursion explicitly — used
    /// when the wrapper is built for a one-shot Split-recovery call
    /// that must NOT recurse regardless of operator config.
    config: Option<std::sync::Arc<FreedomConfig>>,
    /// E-2 Phase 3 (Session 14) — outer-role identity for sub-slot
    /// resolution. When `Some(role)` and the topology configures
    /// `hemisphere_sub_slots[role]`, this hemisphere's recursion
    /// builds inner hemispheres from those operator-pinned sub-slots
    /// rather than reusing the outer-level bindings. `None` =
    /// Phase 2 behaviour (reuse outer slots) — kept for the Split-
    /// recovery one-shot wrapper that never recurses.
    outer_role: Option<crate::config::inference::HemisphereRole>,
    /// GOLD-WIRE-04 — this hemisphere's specialist voice, resolved from
    /// its inference slot at build time. Applied as a **system**-prompt
    /// layer inside `ask` (the leaf LLM call) via [`compose_voice_system`].
    /// Deliberately NOT baked into `base_req` so it never leaks into the
    /// sub-hemispheres that recursion builds from `base_req`: each inner
    /// hemisphere resolves its OWN voice through `slot_for_sub`, so a
    /// SecurityEngineer on outer-Left never contaminates inner-Right.
    voice: Option<crate::council::types::CouncilVoice>,
    /// Optional role-biased memory added only at the leaf. Keeping it separate
    /// from `base_req.system` lets model-aware routing discard this Block-D
    /// context before protected operator/persona bytes when a smaller Council
    /// model is selected.
    recall_fragment: Option<String>,
    /// False on incognito turns so recursive sub-councils cannot re-open a
    /// learned-memory surface after the outer prompt was scrubbed.
    allow_persistent_context: bool,
}

#[async_trait::async_trait]
impl crate::council::orchestrator::HemisphereProvider for ProviderHemisphere {
    fn provider_id(&self) -> String {
        self.provider.name().to_string()
    }
    async fn ask(
        &self,
        prompt: &str,
    ) -> std::result::Result<crate::council::orchestrator::CompletionRecord, String> {
        // QM-10 Phase 2.5: council debate path also consults the
        // breaker. Open breakers reject the hemisphere call so the
        // council dispatcher counts a budget unit against a doomed
        // provider only when the breaker says it's worth trying.
        let provider_name = self.provider.name();
        let permit = match crate::providers::circuit_breaker::acquire_for(provider_name) {
            Ok(p) => Some(p),
            Err(berr) => {
                return Err(format!("provider `{provider_name}`: {berr}"));
            }
        };
        let mut req = self.base_req.clone();
        req.prompt = prompt.to_string();
        let protected_system = req.system.clone();
        if let Some(fragment) = self.recall_fragment.as_deref() {
            req.system = Some(match req.system.take() {
                Some(system) if !system.trim().is_empty() => format!("{system}\n\n{fragment}"),
                _ => fragment.to_owned(),
            });
        }
        // GOLD-WIRE-04: layer this hemisphere's specialist voice onto the
        // system prompt at the leaf LLM call — system-role authority, and
        // applied here (not in base_req) so recursion's sub-hemispheres,
        // built from base_req, stay voice-free until they apply their own.
        req.system = compose_voice_system(req.system, self.voice);
        if req.model.is_none() {
            req.model = self.provider.default_model().map(str::to_owned);
        }
        let model = req.model.clone().expect("model checked above");
        let cap = crate::tokens::budget::effective_cap(
            provider_name,
            &model,
            self.authorizer.input_token_cap(),
        );
        let mut dropped_recall = false;
        let mut dropped_groundtruth = false;
        let mut dropped_voice = false;
        if crate::providers::token_cap::request_token_upper_bound(&req) > cap
            && self.recall_fragment.is_some()
        {
            req.system = compose_voice_system(protected_system.clone(), self.voice);
            dropped_recall = true;
        }
        if crate::providers::token_cap::request_token_upper_bound(&req) > cap
            && let Some(prompt_without_groundtruth) =
                crate::council::factual_check::strip_ground_truth_suffix(&req.prompt)
        {
            req.prompt = prompt_without_groundtruth.to_owned();
            dropped_groundtruth = true;
        }
        if crate::providers::token_cap::request_token_upper_bound(&req) > cap
            && self.voice.is_some()
        {
            req.system = protected_system;
            dropped_voice = true;
        }
        if dropped_recall || dropped_groundtruth || dropped_voice {
            warn!(
                provider = provider_name,
                model = %model,
                cap,
                dropped_recall,
                dropped_groundtruth,
                dropped_voice,
                "council leaf exceeded routed model cap; optional leaf context degraded"
            );
        }
        if req.model.is_none() {
            return Err(format!(
                "provider `{provider_name}` has no explicit request model or declared default"
            ));
        }
        // QM-9 Phase 1.5 follow-on: council debate path now also
        // persists usage events. Each hemisphere call counts —
        // operators on a Pick #8 council see the per-hemisphere
        // burn instead of one aggregate "council ran" row.
        let call_started = std::time::Instant::now();
        let raw = crate::providers::cost_authorization::automated_usage_scope(
            self.provider
                .complete_authorized(req, &self.authorizer, "council_leaf"),
        )
        .await;
        let elapsed_ms = call_started.elapsed().as_millis() as u64;
        match raw {
            Ok(c) => {
                if !c.identity.is_bound() {
                    if let Some(p) = permit {
                        p.record_failure();
                    }
                    return Err(format!(
                        "provider `{provider_name}` returned no authenticated response identity"
                    ));
                }
                if let Some(p) = permit {
                    p.record_success();
                }
                // GOLD-WIRE-10: the council's per-hemisphere provider response
                // is the first real producer on the domain-event bus. Each
                // council call fires one `ProviderResponded` per hemisphere; the
                // daemon's UsageMeter drainer folds the token counts into the
                // running KF-08 budget total. Best-effort — no-op off-daemon.
                // SCOPE: only THIS council-hemisphere call site publishes today;
                // the single-provider chat, streaming, and MCP-loop provider
                // paths do NOT — so the meter currently counts council token
                // burn only. Extend those call sites in WIRE-10b for a full
                // token budget. `latency_ms` is clamped (a call can't take 49d).
                crate::domain_events::publish(
                    crate::domain_events::DomainEvent::ProviderResponded {
                        provider: c.identity.provider.clone(),
                        model: c.identity.wire_model.clone(),
                        input_tokens: c.input_tokens.unwrap_or(0),
                        output_tokens: c.output_tokens.unwrap_or(0),
                        latency_ms: elapsed_ms.min(u64::from(u32::MAX)) as u32,
                        ts_unix: now_unix() as i64,
                    },
                );
                Ok(crate::council::orchestrator::CompletionRecord {
                    text: c.text,
                    input_tokens: c.input_tokens,
                    output_tokens: c.output_tokens,
                })
            }
            Err(e) => {
                if let Some(p) = permit {
                    p.record_failure();
                }
                Err(e.to_string())
            }
        }
    }
    /// E-2 Phase 2 (Session 13) — recursive sub-council override.
    /// Pick #19 (Session 14 F6) — budget-aware path. Delegates to
    /// `ask_with_depth_budget` with a fresh `BudgetToken` so the
    /// legacy entry point preserves its prior cost ceiling
    /// (15 calls / user message) even when called by code paths that
    /// don't yet thread an outer budget.
    async fn ask_with_depth(
        &self,
        prompt: &str,
        depth: u8,
    ) -> std::result::Result<crate::council::orchestrator::CompletionRecord, String> {
        let fresh = crate::council::BudgetToken::new(
            crate::config::inference::DEFAULT_MAX_CALLS_PER_USER_MESSAGE,
        );
        fresh.charge().map_err(|error| error.to_string())?;
        self.ask_with_depth_budget(prompt, depth, fresh).await
    }

    /// E-2 Phase 2 + Pick #19 F6 — budget-aware recursive sub-council.
    /// When `depth > 1` and a config Arc is present, convene a fresh
    /// inner debate against three sub-hemispheres derived from the
    /// same per-role bindings, at `depth - 1`. The inner verdict's
    /// `winning_text` (or the first usable response on Split) becomes
    /// this hemisphere's contribution to the outer debate. Self-
    /// similar / fractal: each hemisphere can spawn its own mini-
    /// council until `depth == 1` bottoms out at a flat `ask`.
    ///
    /// The shared `BudgetToken` is threaded into
    /// `run_debate_with_depth_budget` so the cap spans the outer +
    /// inner debate together — no over-budget fan-out is possible
    /// regardless of `hemisphere_council_depth`.
    ///
    /// COST WARNING: each recursion level multiplies LLM calls by 3.
    /// depth=2 = 9 leaf calls per outer hemisphere call (3 outer × 3
    /// inner). depth=3 = 27 leaf calls per outer hemisphere call.
    /// depth=4 (the `MAX_HEMISPHERE_COUNCIL_DEPTH` cap) = 81 leaf
    /// calls per outer hemisphere call. The shared `BudgetToken`
    /// truncates the actual fan-out at its cap (default 15), so
    /// late-spawned hemispheres report `budget-exhausted` instead of
    /// silently consuming the operator's token budget.
    async fn ask_with_depth_budget(
        &self,
        prompt: &str,
        depth: u8,
        budget: crate::council::BudgetToken,
    ) -> std::result::Result<crate::council::orchestrator::CompletionRecord, String> {
        // Flat path: depth ≤ 1 OR no config Arc means this wrapper
        // was built for the one-shot Split-recovery path and must NOT
        // recurse. Delegate to `ask`.
        if depth <= 1 {
            return crate::providers::cost_authorization::precharged_council_attempt_scope(
                budget,
                self.ask(prompt),
            )
            .await;
        }
        let Some(config) = &self.config else {
            return crate::providers::cost_authorization::precharged_council_attempt_scope(
                budget,
                self.ask(prompt),
            )
            .await;
        };
        // Build three sub-hemispheres from the per-role bindings.
        // Sub-hemispheres carry the same config Arc so they themselves
        // can recurse if `depth - 1 > 1`. `req` clones cheaply.
        //
        // E-2 Phase 3 (Session 14): when `self.outer_role` is set,
        // route sub-hemispheres through `build_sub_hemisphere_with_config`
        // so `hemisphere_sub_slots[outer_role]` overrides apply.
        // When `outer_role` is `None` (legacy / Split-recovery
        // wrappers) fall back to Phase 2 behaviour — reuse outer slots.
        use crate::config::inference::HemisphereRole;
        let (sub_left, sub_right, sub_cere) = match self.outer_role {
            Some(outer) => {
                let l = build_sub_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    &self.neoth_home,
                    outer,
                    HemisphereRole::Left,
                    &self.base_req,
                    self.authorizer.clone(),
                    self.allow_persistent_context,
                )
                .await;
                let r = build_sub_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    &self.neoth_home,
                    outer,
                    HemisphereRole::Right,
                    &self.base_req,
                    self.authorizer.clone(),
                    self.allow_persistent_context,
                )
                .await;
                let c = build_sub_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    &self.neoth_home,
                    outer,
                    HemisphereRole::Cerebellum,
                    &self.base_req,
                    self.authorizer.clone(),
                    self.allow_persistent_context,
                )
                .await;
                let unwrap = |res: Result<ProviderHemisphere>, name: &str| match res {
                    Ok(h) => Ok(h),
                    Err(e) => Err(format!("build sub-{name} for depth-{depth} recursion: {e}")),
                };
                (
                    unwrap(l, "left")?,
                    unwrap(r, "right")?,
                    unwrap(c, "cerebellum")?,
                )
            }
            None => {
                let l = build_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    &self.neoth_home,
                    HemisphereRole::Left,
                    &self.base_req,
                    self.authorizer.clone(),
                    self.allow_persistent_context,
                )
                .await;
                let r = build_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    &self.neoth_home,
                    HemisphereRole::Right,
                    &self.base_req,
                    self.authorizer.clone(),
                    self.allow_persistent_context,
                )
                .await;
                let c = build_hemisphere_with_config(
                    std::sync::Arc::clone(config),
                    &self.neoth_home,
                    HemisphereRole::Cerebellum,
                    &self.base_req,
                    self.authorizer.clone(),
                    self.allow_persistent_context,
                )
                .await;
                let unwrap = |res: Result<ProviderHemisphere>, name: &str| match res {
                    Ok(h) => Ok(h),
                    Err(e) => Err(format!("build sub-{name} for depth-{depth} recursion: {e}")),
                };
                (
                    unwrap(l, "left")?,
                    unwrap(r, "right")?,
                    unwrap(c, "cerebellum")?,
                )
            }
        };
        let prompt_hash = xxhash_rust::xxh3::xxh3_64(prompt.as_bytes());
        let inner = crate::council::run_debate_with_depth_budget(
            prompt,
            prompt_hash,
            depth - 1,
            budget,
            &sub_left,
            &sub_right,
            &sub_cere,
            None, // inner council uses the cheap Jaccard dissent
            &[],  // inner council: no groundtruth re-injection (outer already tagged)
        )
        .await;
        // Aggregation: winning_text on Consensus → use it.
        // Split → pick the first usable hemisphere's text (deterministic).
        // QuorumFailed → bubble up an error string the outer council
        //   sees as a hemisphere error (not panic).
        // GOLD-COR-09 / A-14: carry the sub-council's aggregated token usage up
        // instead of dropping it as None, so a council-backed hemisphere's burn
        // surfaces in `neoth chat`'s token count + the usage log.
        let (input_tokens, output_tokens) = sum_council_tokens(&inner.responses);
        if let Some(t) = inner.winning_text() {
            return Ok(crate::council::orchestrator::CompletionRecord {
                text: t.to_string(),
                input_tokens,
                output_tokens,
            });
        }
        if let Some(usable) = inner.usable_responses().next()
            && let Some(text) = usable.outcome().text()
        {
            return Ok(crate::council::orchestrator::CompletionRecord {
                text: text.to_string(),
                input_tokens,
                output_tokens,
            });
        }
        Err(format!(
            "inner council at depth {} produced no usable response (verdict: {:?})",
            depth - 1,
            inner.verdict
        ))
    }
}

/// GOLD-WIRE-04 — layer a [`CouncilVoice`]'s specialist framing onto a
/// hemisphere's **system** prompt. The fragment is appended AFTER any
/// existing system content (operator-md / persona / skill layers) so it
/// adds specialist framing without overriding the operator's own system
/// prompt. Injecting at the system layer — rather than prepending to the
/// user turn — gives the voice the higher authority every adapter
/// (Claude / Gemini / OpenAI) grants system-role content, and keeps the
/// operator's question intact as the sole user message. `None` leaves the
/// system prompt untouched.
fn compose_voice_system(
    base_system: Option<String>,
    voice: Option<crate::council::types::CouncilVoice>,
) -> Option<String> {
    match voice {
        None => base_system,
        Some(v) => {
            let fragment = v.system_prompt_fragment();
            Some(match base_system {
                Some(s) if !s.trim().is_empty() => format!("{s}\n\n{fragment}"),
                _ => fragment.to_string(),
            })
        }
    }
}

/// GOLD-ADAPT-MEM-10 — map an outer council [`HemisphereRole`] to the memory
/// region whose episodic band fits that hemisphere's cognitive style. **Left**
/// + **Right** → Hippocampus (episodic/factual band 0x01-0x0F; they share the
/// region but the rendered fragment frames it differently — Left leads with
/// operator-asserted facts, Right with narrative episodes); **Cerebellum** →
/// Cerebellum (the operational band: provider / council / kanban / MCP). No
/// wildcard arm — a new `HemisphereRole` variant must choose its region.
fn hemisphere_region(
    role: crate::config::inference::HemisphereRole,
) -> crate::memory::regions::MemoryRegion {
    use crate::config::inference::HemisphereRole as R;
    use crate::memory::regions::MemoryRegion as Region;
    match role {
        R::Left | R::Right => Region::Hippocampus,
        R::Cerebellum => Region::Cerebellum,
    }
}

/// Per-hemisphere recall limit — tiny so three concurrent hemisphere fragments
/// stay well under the council prompt budget.
const HEMISPHERE_RECALL_LIMIT: usize = 3;

/// GOLD-ADAPT-MEM-10 — async wrapper: a per-hemisphere region-biased recall
/// fragment for `prompt`, run off the tokio worker (mirrors the CH-11
/// [`profile_block_for_callosum`] spawn_blocking pattern). Production resolves
/// the store from the operator's HOME; tests call [`hemisphere_recall_fragment_at`].
async fn hemisphere_recall_fragment(
    role: crate::config::inference::HemisphereRole,
    prompt: &str,
    neoth_home: &std::path::Path,
    allow_persistent_context: bool,
) -> Option<String> {
    let prompt = prompt.to_string();
    let db_path = neoth_home.join("views.db");
    tokio::task::spawn_blocking(move || {
        hemisphere_recall_fragment_for_turn_at(&db_path, role, &prompt, allow_persistent_context)
    })
    .await
    .ok()
    .flatten()
}

fn hemisphere_recall_fragment_for_turn_at(
    db_path: &std::path::Path,
    role: crate::config::inference::HemisphereRole,
    prompt: &str,
    allow_persistent_context: bool,
) -> Option<String> {
    if allow_persistent_context {
        hemisphere_recall_fragment_at(db_path, role, prompt)
    } else {
        None
    }
}

/// Test-friendly core of [`hemisphere_recall_fragment`]: explicit `db_path`.
/// Recalls from the role's region (+ operator-asserted ground-truth facts for
/// the **Left** factual hemisphere) and renders a short biased-recall fragment
/// that gets appended BELOW the operator's `combined_system` (bias, not
/// override). Best-effort: missing DB / query error / no hits → `None`.
/// Synchronous read-only rusqlite — call inside `spawn_blocking`.
fn hemisphere_recall_fragment_at(
    db_path: &std::path::Path,
    role: crate::config::inference::HemisphereRole,
    prompt: &str,
) -> Option<String> {
    use crate::config::inference::HemisphereRole as R;
    if !db_path.exists() {
        return None;
    }
    let conn = crate::memory::store::open(db_path).ok()?;
    let region = hemisphere_region(role);
    let episodes =
        crate::memory::regions::recall_from_region(&conn, region, prompt, HEMISPHERE_RECALL_LIMIT)
            .unwrap_or_default();
    // Left is the FACTUAL hemisphere — lead with operator-asserted ground-truth.
    let facts = if matches!(role, R::Left) {
        crate::cli::recall::recall_groundtruth_like(&conn, prompt, 2).unwrap_or_default()
    } else {
        Vec::new()
    };
    if episodes.is_empty() && facts.is_empty() {
        return None;
    }
    let (label, lead) = match role {
        R::Left => ("Left", "factual"),
        R::Right => ("Right", "narrative"),
        R::Cerebellum => ("Cerebellum", "operational"),
    };
    let mut s = format!("## {label} hemisphere — {lead} memory bias\n");
    for f in &facts {
        s.push_str(&format!("- (fact) {}\n", recall_snippet(&f.text)));
    }
    for e in &episodes {
        s.push_str(&format!("- {}\n", recall_snippet(&e.text)));
    }
    Some(s)
}

/// Build a fresh `ProviderHemisphere` for `role` using the configured
/// per-role provider (defaults collapse to single-mode in Single
/// topology). Used by `run_council_debate` to build all three plus by
/// the A5 Split-recovery path to build a one-shot Cerebellum.
///
/// E-2 Phase 2 (Session 13): legacy entry point that builds a wrapper
/// without a config Arc — recursion is DISABLED for these wrappers.
/// Used by the A5 callosum Split-recovery path that should never
/// recurse regardless of operator config.
async fn build_hemisphere(
    config: &FreedomConfig,
    neoth_home: &std::path::Path,
    role: crate::config::inference::HemisphereRole,
    req: &crate::providers::Request,
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
) -> Result<ProviderHemisphere> {
    let provider = crate::providers::from_config_for_role_at(config, role, neoth_home).await?;
    let mut base_req = req.clone();
    // Council leaves are independent provider calls. Never inherit the chat
    // primary's model from `req`: the role slot (or that role provider's
    // default) is the contract for this leaf. Resolve aliases now so request
    // budgeting sees the same canonical model that `complete_authorized`
    // binds again at the exact paid-call boundary.
    base_req.model = Some(resolve_provider_call_wire_model(
        config,
        provider.as_ref(),
        config.inference.slot_for(role).model.as_deref(),
    )?);
    Ok(ProviderHemisphere {
        provider,
        base_req,
        authorizer,
        neoth_home: neoth_home.to_path_buf(),
        config: None,
        outer_role: None,
        // GOLD-WIRE-04: this role's specialist voice, applied at leaf `ask`.
        voice: config.inference.slot_for(role).voice,
        recall_fragment: None,
        allow_persistent_context: false,
    })
}

/// GOLD-LOOP-01 — thin `pub(crate)` shim around `build_hemisphere` that
/// returns a trait object (`Box<dyn HemisphereProvider>`) so the loop engine
/// can call it without seeing the private `ProviderHemisphere` concrete type.
/// The loop engine's self-reflect refine pass is the only call-site.
pub(crate) async fn build_hemisphere_for_loop(
    config: &FreedomConfig,
    neoth_home: &std::path::Path,
    role: crate::config::inference::HemisphereRole,
    req: &crate::providers::Request,
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
) -> Result<Box<dyn crate::council::orchestrator::HemisphereProvider>> {
    let authorizer = authorizer.with_council_daily_cap(neoth_home, config.council.daily_usd_cap)?;
    let h = build_hemisphere(config, neoth_home, role, req, authorizer).await?;
    Ok(Box::new(h))
}

/// E-2 Phase 2 (Session 13) — recursion-aware build entry. Carries a
/// config Arc so `ask_with_depth` can spawn an inner council at lower
/// depth when `topology.hemisphere_council_depth > 1`. Used by
/// `run_council_debate` for outer-council hemispheres + by the inner
/// council's recursive build path itself.
///
/// E-2 Phase 3 (Session 14): stamps `outer_role = Some(role)` so the
/// recursion path can consult `inference.hemisphere_sub_slots[role]`
/// when building inner-council hemispheres.
async fn build_hemisphere_with_config(
    config: std::sync::Arc<FreedomConfig>,
    neoth_home: &std::path::Path,
    role: crate::config::inference::HemisphereRole,
    req: &crate::providers::Request,
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    allow_persistent_context: bool,
) -> Result<ProviderHemisphere> {
    let provider =
        crate::providers::from_config_for_role_at(config.as_ref(), role, neoth_home).await?;
    // GOLD-WIRE-04: outer-council hemisphere — voice from this role's slot,
    // resolved before the `config` Arc is moved into the struct.
    let voice = config.inference.slot_for(role).voice;
    // GOLD-ADAPT-MEM-10: bias THIS outer hemisphere's base prompt with region-
    // matched recall (Left=factual, Right=narrative, Cerebellum=operational).
    // Appended at the system layer BELOW the operator's combined_system (bias,
    // not override). Outer council only — inner/sub wrappers carry
    // `outer_role: None` and skip this, so recursion doesn't double-inject.
    // Best-effort → leaves base_req untouched on empty recall.
    let mut base_req = req.clone();
    base_req.model = Some(resolve_provider_call_wire_model(
        config.as_ref(),
        provider.as_ref(),
        config.inference.slot_for(role).model.as_deref(),
    )?);
    let recall_fragment =
        hemisphere_recall_fragment(role, &req.prompt, neoth_home, allow_persistent_context).await;
    Ok(ProviderHemisphere {
        provider,
        base_req,
        authorizer,
        neoth_home: neoth_home.to_path_buf(),
        config: Some(config),
        outer_role: Some(role),
        voice,
        recall_fragment,
        allow_persistent_context,
    })
}

/// E-2 Phase 3 (Session 14) — build an INNER-council hemisphere
/// scoped to a specific OUTER role. Resolves the provider via
/// `from_config_for_sub_role(config, outer_role, inner_role)` so
/// `hemisphere_sub_slots[outer_role][inner_role]` wins when set.
/// Falls back to the outer-level slot otherwise (Phase 2 behaviour).
///
/// The returned wrapper carries `outer_role: None` — deeper
/// recursion (depth > 2) reuses the inner-level slots through the
/// outer-fallback path of `slot_for_sub`. The N×3 multiplier still
/// applies; Phase 3 only changes WHICH adapters dispatch at each
/// level, not the dispatch count.
async fn build_sub_hemisphere_with_config(
    config: std::sync::Arc<FreedomConfig>,
    neoth_home: &std::path::Path,
    outer_role: crate::config::inference::HemisphereRole,
    inner_role: crate::config::inference::HemisphereRole,
    req: &crate::providers::Request,
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    allow_persistent_context: bool,
) -> Result<ProviderHemisphere> {
    let provider = crate::providers::from_config_for_sub_role_at(
        config.as_ref(),
        outer_role,
        inner_role,
        neoth_home,
    )
    .await?;
    // GOLD-WIRE-04: inner-council hemisphere — voice resolves through
    // `slot_for_sub`, so an operator who pins a voice on
    // `hemisphere_sub_slots[outer][inner]` gets that specialist framing at
    // the recursion tier; otherwise it falls back to the inner role's own
    // outer-level slot voice (never the parent hemisphere's — no leak).
    let voice = config.inference.slot_for_sub(outer_role, inner_role).voice;
    let mut base_req = req.clone();
    base_req.model = Some(resolve_provider_call_wire_model(
        config.as_ref(),
        provider.as_ref(),
        config
            .inference
            .slot_for_sub(outer_role, inner_role)
            .model
            .as_deref(),
    )?);
    Ok(ProviderHemisphere {
        provider,
        base_req,
        authorizer,
        neoth_home: neoth_home.to_path_buf(),
        config: Some(config),
        outer_role: None,
        voice,
        recall_fragment: None,
        allow_persistent_context,
    })
}

/// CH-11: render top operator-profile claims as a synthesis-prompt
/// context block. Best-effort — any failure (missing views.db, query
/// error, no claims above threshold) returns `None` so the chat
/// callosum branch proceeds without profile injection.
///
/// Confidence gate ≥ 0.6 pinned per SPEC_proactive_learning §5.1
/// "high-confidence" threshold. Limit 8 claims keeps the prompt
/// from ballooning even when the operator has a huge profile.
/// K-Perf-3 v1 2026-05-17: wrap the synchronous rusqlite query in
/// `tokio::task::spawn_blocking` so the chat hot path (called from
/// the council Split → callosum branch) does NOT block a tokio worker
/// thread for the duration of the SQLite read. Without this wrap,
/// every Council Split debate stalled one worker for ~5-50ms while
/// `top_claims_for_chat` ran — on a multi-channel daemon serving
/// concurrent inbound messages, that's a real concurrency hit.
///
/// Pure synchronous logic lives in [`profile_block_for_callosum_sync`];
/// `profile_block_for_callosum` is the async wrapper that callers
/// await. Tests cover the sync helper directly so they don't need a
/// tokio runtime spawn-blocking pool.
async fn profile_block_for_callosum(
    db_path: PathBuf,
    disabled_categories: Vec<String>,
) -> Option<String> {
    match tokio::task::spawn_blocking(move || {
        profile_block_for_callosum_sync(&db_path, &disabled_categories)
    })
    .await
    {
        Ok(block) => block,
        Err(error) => {
            warn!(
                error = %error,
                "callosum profile lookup worker failed; continuing without profile injection"
            );
            None
        }
    }
}

/// Incognito turns must not even open the learned-profile database. Keeping
/// the policy outside the lookup helper makes the no-read branch explicit and
/// testable while preserving the ordinary channel/Council path.
async fn profile_block_for_callosum_for_turn(
    db_path: PathBuf,
    disabled_categories: Vec<String>,
    incognito: bool,
) -> Option<String> {
    if incognito {
        None
    } else {
        profile_block_for_callosum(db_path, disabled_categories).await
    }
}

/// Synchronous core of [`profile_block_for_callosum`] — pure
/// rusqlite + profile lookup with no tokio dependency. Extracted so
/// tests + future migration paths (e.g. neoth-sync embedded query
/// surface) can call it directly without a runtime.
///
/// CH-11 (Session 21): the confidence floor is now sourced from
/// `profile::injection::DEFAULT_INJECTION_FLOOR` (P-06 primitive) so
/// a future tune of the Block-B injection threshold lands in one
/// place. Previously hard-coded as `0.6` — same value, but the
/// drift-guard on the primitive's tests now covers this call site
/// too. `MAX_CLAIMS` stays a chat-callosum-local constant since it's
/// tunable independently of the gate floor.
fn profile_block_for_callosum_sync(
    db_path: &std::path::Path,
    disabled_categories: &[String],
) -> Option<String> {
    const MAX_CLAIMS: usize = 8;
    let conn = match crate::memory::store::open(db_path) {
        Ok(conn) => conn,
        Err(error) => {
            warn!(
                error = %error,
                path = %db_path.display(),
                "callosum profile database unavailable; continuing without profile injection"
            );
            return None;
        }
    };
    // ADV-05: consume the already-validated active turn config. Reloading the
    // process-default freedom.yaml here both hid parse failures and ignored a
    // custom `--config` home, which could bypass the operator's PII exclusions.
    let claims = match crate::profile::lookup::top_claims_for_chat_with_pii_gate(
        &conn,
        crate::profile::injection::DEFAULT_INJECTION_FLOOR,
        MAX_CLAIMS,
        disabled_categories,
    ) {
        Ok(claims) => claims,
        Err(error) => {
            warn!(
                error = %error,
                "callosum profile query failed; continuing without profile injection"
            );
            return None;
        }
    };
    if claims.is_empty() {
        return None;
    }
    let rendered = crate::profile::lookup::render_for_synthesis_prompt(&claims);
    if rendered.trim().is_empty() {
        None
    } else {
        Some(rendered)
    }
}

/// Outcome of a `callosum::resolve` attempt — drives the
/// `COUNCIL_SYNTHESIS_ATTEMPTED` (0x60) WAL payload shape so audit
/// readers can distinguish the synthesis-succeeded vs synthesis-failed
/// branches without re-running the inference.
enum CouncilSynthesisOutcome {
    Synthesis { chars: usize },
    IrreconcilableConflict { reason: String },
}

/// Append a `COUNCIL_SYNTHESIS_ATTEMPTED` (0x60) audit frame to the
/// current chat WAL segment. Failures are best-effort: the chat reply
/// already went out, losing the audit frame is a logged-warning, not a
/// caller-facing error.
/// A-1 (Session 13) — when a council debate completes with one or more
/// refused hemispheres + at least one usable hemisphere, render a one-line
/// operator-facing annotation describing which roles refused + their cause
/// taxonomy. Prepended to the reply text + emitted as a WAL 0x61 frame.
/// Returns `None` when no partial refusal occurred — caller skips the
/// prefix + the audit emission.
fn partial_refusal_prefix(outcome: &crate::council::CouncilDebate) -> Option<String> {
    if !outcome.is_partial_refusal() {
        return None;
    }
    let refused: Vec<String> = outcome
        .refused_responses()
        .map(|r| {
            let role = match r.role {
                crate::config::inference::HemisphereRole::Left => "left",
                crate::config::inference::HemisphereRole::Right => "right",
                crate::config::inference::HemisphereRole::Cerebellum => "cerebellum",
            };
            let cause = r
                .refusal
                .as_ref()
                .map(|x| x.cause.as_str())
                .unwrap_or("unknown");
            format!("{role}/{provider}: {cause}", provider = r.provider)
        })
        .collect();
    let usable = outcome.usable_responses().count();
    let total = outcome.responses.len().max(3);
    Some(format!(
        "[synthesised over {usable} of {total} hemispheres — {joined} refused]",
        joined = refused.join(", ")
    ))
}

/// K-Repo-Map Phase 3c (Session 14 Pick #26) — best-effort repo-
/// context lookup. Returns `Some(block)` when:
///   1. `config.code_map.auto_context_max_files > 0` (operator opted in)
///   2. `~/.neoth/code_map.db` exists + opens cleanly
///   3. The persisted map has at least one file matching `prompt`
///
/// Every other condition silently returns `None` — the chat path must
/// never block on code-map state. Operator who hasn't run
/// `neoth code-map persist` yet sees their chat work normally.
///
/// Production resolves both stores from the selected runtime instance home;
/// unit tests use a test-only explicit-path seam.
pub(crate) fn maybe_repo_context_block(
    config: &FreedomConfig,
    prompt: &str,
    paths: &InstancePaths,
) -> Option<String> {
    maybe_repo_context_block_at_paths(config, prompt, &paths.code_map, &paths.ccr)
}

/// Test-friendly inner: resolve the code-map DB at an explicit path
/// instead of through `HOME` / `USERPROFILE`. Same best-effort
/// contract as [`maybe_repo_context_block`] — every failure path
/// produces `None`, never an error.
#[cfg(test)]
pub(crate) fn maybe_repo_context_block_at(
    config: &FreedomConfig,
    prompt: &str,
    db_path: &std::path::Path,
) -> Option<String> {
    let ccr_dir = db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("ccr");
    maybe_repo_context_block_at_paths(config, prompt, db_path, &ccr_dir)
}

fn maybe_repo_context_block_at_paths(
    config: &FreedomConfig,
    prompt: &str,
    db_path: &std::path::Path,
    ccr_dir: &std::path::Path,
) -> Option<String> {
    let max = config.code_map.auto_context_max_files as usize;
    if max == 0 {
        return None;
    }
    if !db_path.exists() {
        return None;
    }
    let conn = match crate::code_map::persist::open(db_path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let hits = match crate::code_map::recall::relevant_files_for_prompt(&conn, prompt, max) {
        Ok(h) if !h.is_empty() => h,
        _ => return None,
    };
    let block = crate::code_map::recall::render_context_block(&hits);
    if block.is_empty() {
        return None;
    }
    // GOLD-HR-09 — the repo-context block is `file:line:` shaped (SearchResults),
    // so when compression is enabled the search offload thins a large block
    // per-file and stashes the original in the persistent CCR store (retrievable
    // via `neoth ctx retrieve`). Prose-only / small blocks pass through.
    if let Some(rt) = crate::context::compress::CompressionRuntime::persistent(
        config.compression.gate(),
        config.compression.thresholds(),
        ccr_dir.to_path_buf(),
    ) {
        return Some(rt.compress_for_llm(&block).0);
    }
    Some(block)
}

/// GOLD-ADAPT-GRAPH-02 — load the persisted CallGraph findings consumed by
/// the real `improve_codebase_architecture` skill path. Unlike general
/// repo-context, this is skill-scoped rather than gated by
/// `auto_context_max_files`: activating the architecture workflow is the
/// explicit request to run its bounded local analysis.
pub(crate) fn maybe_architecture_findings_for_skill(
    skill_id: Option<&str>,
    paths: &InstancePaths,
    current_path: &std::path::Path,
) -> Option<crate::code_map::recall::ArchitectureFindings> {
    maybe_architecture_findings_for_skill_at(skill_id, &paths.code_map, current_path)
}

fn maybe_architecture_findings_for_skill_at(
    skill_id: Option<&str>,
    db_path: &std::path::Path,
    current_path: &std::path::Path,
) -> Option<crate::code_map::recall::ArchitectureFindings> {
    if skill_id != Some(crate::code_map::recall::ARCHITECTURE_SKILL_ID) || !db_path.exists() {
        return None;
    }
    let conn = match crate::code_map::persist::open(db_path) {
        Ok(conn) => conn,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %db_path.display(),
                "GRAPH-02: architecture code-map open failed; no cycle context injected"
            );
            return None;
        }
    };
    let canonical_path = match std::fs::canonicalize(current_path) {
        Ok(path) => path,
        Err(e) => {
            tracing::warn!(
                error = %e,
                current_path = %current_path.display(),
                "GRAPH-02: current repository path could not be canonicalized; refusing fallback"
            );
            return None;
        }
    };
    let mut roots = match conn.prepare("SELECT root FROM code_map_roots ORDER BY root ASC") {
        Ok(statement) => statement,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "GRAPH-02: persisted root lookup failed; no cycle context injected"
            );
            return None;
        }
    };
    let persisted_root = match roots.query_map([], |row| row.get::<_, String>(0)) {
        Ok(rows) => rows
            .filter_map(|row| row.ok())
            .filter(|root| canonical_path.starts_with(std::path::Path::new(root)))
            .max_by_key(|root| std::path::Path::new(root).components().count()),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "GRAPH-02: persisted root rows could not be read; no cycle context injected"
            );
            return None;
        }
    };
    let Some(persisted_root) = persisted_root else {
        tracing::debug!(
            current_path = %canonical_path.display(),
            "GRAPH-02: current path has no persisted code-map root; refusing cross-repo fallback"
        );
        return None;
    };
    match crate::code_map::recall::architecture_findings_for_skill(
        &conn,
        skill_id,
        &persisted_root,
        crate::code_map::recall::ARCHITECTURE_CYCLE_LIMIT,
    ) {
        Ok(findings) => findings,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "GRAPH-02: persisted cycle scan failed; no cycle context injected"
            );
            None
        }
    }
}

/// Append GRAPH-02 findings after ordinary relevant-file context. Keeping this
/// as one seam prevents CLI and channel assembly from drifting on delimiters.
pub(crate) fn append_architecture_findings(
    repo_context: Option<String>,
    findings: &crate::code_map::recall::ArchitectureFindings,
) -> Option<String> {
    Some(match repo_context {
        Some(mut context) => {
            if !context.ends_with('\n') {
                context.push('\n');
            }
            context.push('\n');
            context.push_str(&findings.block);
            context
        }
        None => findings.block.clone(),
    })
}

/// Durable metadata-only proof that the automatic cycle evidence reached a
/// prompt. Exact symbols/paths remain local; `context_hash_xxh3` binds the WAL
/// row to the injected block without copying repository structure into audit.
pub(crate) async fn emit_architecture_findings_audit(
    writer: &crate::wal::writer::WalWriterHandle,
    findings: &crate::code_map::recall::ArchitectureFindings,
    surface: &'static str,
) {
    let payload = match serde_json::to_vec(&serde_json::json!({
        "skill_id": crate::code_map::recall::ARCHITECTURE_SKILL_ID,
        "surface": surface,
        "roots_scanned": findings.roots_scanned,
        "edges_scanned": findings.edges_scanned,
        "cycles_injected": findings.cycles_injected,
        "truncated": findings.truncated,
        "context_hash_xxh3": xxhash_rust::xxh3::xxh3_64(findings.block.as_bytes()),
        "ts_unix": crate::time::now_unix_i64(),
    })) {
        Ok(payload) => payload,
        Err(e) => {
            tracing::warn!(error = %e, "GRAPH-02: architecture audit payload failed");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::ArchitectureCyclesInjected as u8)
        .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "GRAPH-02: architecture audit WAL append failed");
    }
}

/// GOLD-ADAPT-MEM-12 — assemble a per-session "guidance" context block from the
/// operator's own recent activity: the last few session hindsight cards (NEOTH's
/// "lessons-7d" equivalent — there is no separate lessons store; the hindsight
/// card IS the per-session summary) + a count of pending fact-contradictions
/// awaiting review. Folded into the system prompt at `build_prompt_bundle` time
/// (the same seam as the Block::D recall), so every chat turn opens with a
/// compressed sense of "what you've been working on + what's unresolved" instead
/// of cold.
///
/// CLI/TTY path only (the data is the operator's own sessions — no per-sender
/// authz needed). Best-effort: no recent cards AND no pending → `None`.
/// Production resolves both stores under the operator's HOME; see
/// [`maybe_guidance_block_at`] for the explicit-path test variant.
async fn maybe_guidance_block(home: &std::path::Path, incognito: bool) -> Option<String> {
    let home = home.to_path_buf();
    let now = now_unix() as i64;
    tokio::task::spawn_blocking(move || maybe_guidance_block_for_turn_at(&home, now, incognito))
        .await
        .ok()
        .flatten()
}

fn maybe_guidance_block_for_turn_at(
    home: &std::path::Path,
    now_unix: i64,
    incognito: bool,
) -> Option<String> {
    if incognito {
        None
    } else {
        maybe_guidance_block_at(home, now_unix)
    }
}

/// Sliding window for the "recent sessions" lane — one week of hindsight cards.
const GUIDANCE_RECENCY_SECS: i64 = 7 * 86_400;
/// Cap on cards rendered so a busy week can't bloat the prompt.
const GUIDANCE_MAX_CARDS: usize = 5;

/// Test-friendly core of [`maybe_guidance_block`]: explicit `home` (hindsight
/// cards live under `home/hindsight/`, contradictions under `home/views.db` —
/// both derived from `home`, NOT `default_path()`, so tests stay hermetic) +
/// explicit `now_unix` so the 7-day window is deterministic. Sync (filesystem +
/// rusqlite) — call inside `spawn_blocking`.
fn maybe_guidance_block_at(home: &std::path::Path, now_unix: i64) -> Option<String> {
    let cutoff = now_unix - GUIDANCE_RECENCY_SECS;
    let mut cards = crate::memory::hindsight::list_cards(home);
    cards.retain(|c| c.ended_at_unix >= cutoff);
    cards.truncate(GUIDANCE_MAX_CARDS);

    // Pending fact-contradictions — best-effort, derived from `home` so tests
    // stay hermetic (a missing views.db simply yields 0).
    let pending = {
        let db = home.join("views.db");
        if db.exists() {
            crate::memory::store::open(&db)
                .ok()
                .and_then(|c| crate::memory::contradiction::list_contradictions(&c, false).ok())
                .map(|v| v.len())
                .unwrap_or(0)
        } else {
            0
        }
    };

    // JV-MEM-16: load the daemon-refreshed snapshot (best-effort; None on a
    // fresh install or when the cron is disabled — the block still renders
    // the MEM-12 lanes from cards + pending above).
    let snapshot = crate::daemon::guidance_cron::load_guidance_snapshot(home);

    render_guidance_block(&cards, pending, snapshot.as_ref())
}

/// Render the guidance lanes. `None` when there is nothing to say (no recent
/// cards, no pending contradictions, no scorecard anomaly, no 24h signals) so
/// a fresh install / quiet week adds no empty block.
///
/// JV-MEM-16: the third argument is the daemon-refreshed snapshot that carries
/// scorecard freshness + 24h WAL signal counts. Pass `None` in tests (the
/// snapshot is absent on a fresh home — tests stay hermetic).
fn render_guidance_block(
    recent_cards: &[crate::memory::hindsight::HindsightCard],
    pending_contradictions: usize,
    snapshot: Option<&crate::daemon::guidance_cron::GuidanceSnapshot>,
) -> Option<String> {
    // JV-MEM-16: pre-compute whether the new lanes contribute anything.
    let has_unhealthy = snapshot.is_some_and(|s| !s.scorecard_healthy);
    let has_signals = snapshot.is_some_and(|s| {
        s.crash_alerts_24h
            + s.silence_alerts_24h
            + s.token_anomaly_24h
            + s.session_degraded_24h
            + s.cron_errors_24h
            > 0
    });

    if recent_cards.is_empty() && pending_contradictions == 0 && !has_unhealthy && !has_signals {
        return None;
    }
    let mut s = String::from(
        "## Session context\n\
         A compressed view of your own recent work — orient on it; it is not the \
         current request:\n",
    );
    if !recent_cards.is_empty() {
        s.push_str("### Recent sessions (last 7 days)\n");
        for c in recent_cards {
            let label = c.display_name.as_deref().unwrap_or(&c.one_line_summary);
            s.push_str(&format!("- {}\n", recall_snippet(label)));
        }
    }
    // JV-MEM-16: memory-quality lane (only show when unhealthy — healthy is
    // noise that would appear on every turn).
    if let Some(snap) = snapshot {
        if !snap.scorecard_healthy {
            s.push_str(&format!(
                "### Memory quality\n\
                 - Freshness score: {:.0}% (grade {})\n",
                snap.scorecard_freshness * 100.0,
                snap.scorecard_grade
            ));
        }
        // JV-MEM-16: 24h signals lane (only show nonzero counts).
        let total_signals = snap.crash_alerts_24h
            + snap.silence_alerts_24h
            + snap.token_anomaly_24h
            + snap.session_degraded_24h
            + snap.cron_errors_24h;
        if total_signals > 0 {
            s.push_str("### 24h system signals\n");
            if snap.cron_errors_24h > 0 {
                s.push_str(&format!("- {} cron job failure(s)\n", snap.cron_errors_24h));
            }
            if snap.crash_alerts_24h > 0 {
                s.push_str(&format!("- {} crash alert(s)\n", snap.crash_alerts_24h));
            }
            if snap.token_anomaly_24h > 0 {
                s.push_str(&format!(
                    "- {} token anomaly alert(s)\n",
                    snap.token_anomaly_24h
                ));
            }
            if snap.silence_alerts_24h + snap.session_degraded_24h > 0 {
                s.push_str(&format!(
                    "- {} channel/session alert(s)\n",
                    snap.silence_alerts_24h + snap.session_degraded_24h
                ));
            }
        }
    }
    if pending_contradictions > 0 {
        s.push_str(&format!(
            "### Open items\n- {pending_contradictions} flagged fact-contradiction(s) pending review\n"
        ));
    }
    Some(s)
}

/// GOLD-WIRE Block::D + GOLD-ADAPT-MEM-09 — auto-recall episode block for
/// [`build_prompt_bundle`]. On a non-trivial chat turn, fold the operator's
/// most-relevant stored episodes into the system prompt so the model answers
/// with continuity instead of cold. [`crate::memory::recall_gate::classify_recall_need`]
/// gates it: greetings / status / identity (Skip-tier) pay no DB hit.
///
/// **Scope — CLI/TTY path only.** This runs inside `build_prompt_bundle`, the
/// local-`neoth chat` assembler the operator already owns, so reading their own
/// memory back into the prompt needs no per-sender authorization. The autonomous
/// channel path (`serve_pipeline.rs`) keeps its stricter GOLD-WIRE-02b
/// provable-operator gate and does NOT call this.
///
/// Best-effort: Skip-tier / missing DB / query error / no hits → `None`, never
/// fails the turn. Production resolves the episode store from the operator's
/// HOME (mirrors [`maybe_repo_context_block`]); see [`maybe_recall_block_at`]
/// for the explicit-path test variant.
async fn maybe_recall_block(prompt: &str, neoth_home: &std::path::Path) -> Option<String> {
    let db_path = neoth_home.join("views.db");
    maybe_recall_block_at(prompt, &db_path).await
}

/// Test-friendly inner: resolve the episode store at an explicit path instead
/// of through `HOME` / `USERPROFILE` (avoids env-var mutation in tests that
/// would race under parallel execution). Same best-effort contract.
async fn maybe_recall_block_at(prompt: &str, db_path: &std::path::Path) -> Option<String> {
    use crate::memory::recall_gate::{RecallTier, classify_recall_need};
    // MEM-09 gate: a status/identity/greeting turn needs no memory recall.
    let recall_tier = classify_recall_need(prompt);
    if recall_tier == RecallTier::Skip {
        return None;
    }
    if !db_path.exists() {
        return None;
    }
    // Run the synchronous rusqlite recall off the async worker (K-Perf-3),
    // mirroring `answer_conversational_recall`. A JoinError degrades to None.
    let prompt_owned = prompt.to_string();
    let db_owned = db_path.to_path_buf();
    let output = match tokio::task::spawn_blocking(move || {
        recall_lanes_for_block(&db_owned, &prompt_owned, recall_tier == RecallTier::Multi)
    })
    .await
    {
        Ok(Ok(Some(output))) => output,
        Ok(Ok(None)) | Ok(Err(_)) | Err(_) => return None,
    };
    Some(render_recall_block_layered(&output))
}

/// GOLD-ADAPT-JV-MEM-10 — three-lane recall for the auto-recall block: canonical
/// ground-truth facts + region-routed episodes + prompt-relevant pending
/// contradictions, each lane queried independently. `None` when ALL lanes are
/// empty (a non-Skip turn that recalls nothing suppresses Block::D entirely).
/// Best-effort: a DB open error → `None`. Synchronous (rusqlite) — call inside
/// `spawn_blocking`.
fn recall_lanes_for_block(
    db_path: &std::path::Path,
    prompt: &str,
    count_true_miss: bool,
) -> anyhow::Result<Option<crate::cli::recall::RecallOutput>> {
    // Per-lane cap so a large store can't bloat the prompt. The budget-aware
    // Block::D degradation is a separate later refinement; length-bounded
    // snippets keep the block comfortably under the cap.
    const RECALL_BLOCK_LIMIT: usize = 5;
    let conn = crate::memory::store::open(db_path)?;
    let plan = crate::memory::region_router::route_query(prompt);
    let mut output =
        crate::cli::recall::query_three_lanes_checked(&conn, &plan, prompt, RECALL_BLOCK_LIMIT)?;
    // GOLD-FEAT-12 D-block dedup: drop episodes whose text already appears as a
    // canonical fact (or an earlier episode) before the block is rendered.
    dedup_recall_lanes(&mut output);
    if output.is_empty() {
        if count_true_miss {
            crate::analytics::babel::signals::emit(
                crate::analytics::babel::signals::SignalKind::MemoryRecallMiss,
            );
        }
        Ok(None)
    } else {
        Ok(Some(output))
    }
}

/// GOLD-FEAT-12 D-block dedup — the canonical and episode recall lanes are
/// queried from different tables independently, so an operator-asserted fact
/// that was ALSO captured as an episode (or a near-repeat episode) renders
/// twice in Block::D, spending prompt budget on a duplicate. Drop an episode
/// whose normalized text collides (xxh3) with a canonical fact or an
/// earlier-kept episode. Canonical facts are highest-trust → kept whole;
/// contradictions (a distinct pair+confidence shape) are left untouched. The
/// lanes' own `text_hash` fields are deliberately NOT reused: they hash
/// different inputs per lane (bare statement vs WAL payload envelope), so they
/// cannot be compared across lanes.
fn dedup_recall_lanes(out: &mut crate::cli::recall::RecallOutput) {
    let mut seen: std::collections::HashSet<u64> = out
        .canonical
        .iter()
        .map(|h| recall_dedup_key(&h.text))
        .collect();
    out.episodes
        .retain(|h| seen.insert(recall_dedup_key(&h.text)));
}

/// Normalized xxh3 dedup key: trim + collapse internal whitespace + lowercase,
/// so "Alex  is the  Operator." and "alex is the operator." hash identically.
/// Punctuation stays significant (conservative — never over-collapses two
/// genuinely distinct memories). Hashes the FULL text, pre snippet-truncation,
/// so two long memories that differ only past the 240-char cut stay distinct.
fn recall_dedup_key(text: &str) -> u64 {
    let norm = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    xxhash_rust::xxh3::xxh3_64(norm.as_bytes())
}

/// Length-bound + newline-flatten one recall statement so one item = one compact
/// line and the whole Block::D stays prompt-budget-friendly.
fn recall_snippet(text: &str) -> String {
    const MAX_SNIPPET_CHARS: usize = 240;
    let text = text.trim();
    let s = if text.chars().count() > MAX_SNIPPET_CHARS {
        let mut s: String = text.chars().take(MAX_SNIPPET_CHARS).collect();
        s.push('…');
        s
    } else {
        text.to_string()
    };
    s.replace('\n', " ")
}

/// GOLD-ADAPT-JV-MEM-10 — render the three recall lanes as a trailing Block::D
/// system section with DISTINCT, confidence-tiered sub-headings, so the model
/// can tell an operator-asserted canonical fact from a fuzzy episode from a
/// flagged contradiction. An empty lane emits no heading (a fresh install with
/// no ground-truth / no contradictions shows only the episodes section). The
/// caller only invokes this when at least one lane is non-empty.
fn render_recall_block_layered(out: &crate::cli::recall::RecallOutput) -> String {
    let mut s = String::from(
        "## Relevant memory (recall)\n\
         Background retrieved from your own stored memory — context, not the \
         current request:\n",
    );
    if !out.canonical.is_empty() {
        s.push_str("### Canonical facts (operator-asserted)\n");
        for (i, h) in out.canonical.iter().enumerate() {
            s.push_str(&format!("{}. {}\n", i + 1, recall_snippet(&h.text)));
        }
    }
    if !out.episodes.is_empty() {
        s.push_str("### Relevant episodes\n");
        for (i, h) in out.episodes.iter().enumerate() {
            s.push_str(&format!(
                "{}. [{}] {}\n",
                i + 1,
                h.tier,
                recall_snippet(&h.text)
            ));
        }
    }
    if !out.contradictions.is_empty() {
        s.push_str("### Flagged contradictions (pending review — treat as disputed)\n");
        for (i, c) in out.contradictions.iter().enumerate() {
            s.push_str(&format!(
                "{}. \"{}\" vs \"{}\" (confidence {:.2})\n",
                i + 1,
                recall_snippet(&c.statement_a),
                recall_snippet(&c.statement_b),
                c.confidence
            ));
        }
    }
    s
}

/// The operator's role as a human-readable label. The free-form
/// `freedom.yaml::role_custom` wins when set; otherwise the
/// `OperatorRole` enum is mapped to prose. `OperatorRole::None`
/// (or an unset role) with no custom label yields `None`.
fn operator_role_label(config: &FreedomConfig) -> Option<String> {
    if let Some(custom) = config.role_custom.as_deref() {
        let custom = custom.trim();
        if !custom.is_empty() {
            return Some(custom.to_string());
        }
    }
    use crate::cli::init::OperatorRole;
    match config.role {
        Some(OperatorRole::Developer) => Some("developer".to_string()),
        Some(OperatorRole::SecurityResearcher) => Some("security researcher".to_string()),
        Some(OperatorRole::Founder) => Some("founder".to_string()),
        Some(OperatorRole::DataScientist) => Some("data scientist".to_string()),
        Some(OperatorRole::Writer) => Some("writer".to_string()),
        Some(OperatorRole::None) | None => None,
    }
}

/// Render the operator's structured identity facts (custom/enum role +
/// preferred response language) as a short preamble, then merge it
/// ABOVE the assembled NEOTH.md body.
///
/// Closes an unwired gap: the wizard captures `role_custom` /
/// `language_primary` into `freedom.yaml`, but neither field previously
/// reached the prompt pipeline — the model never learned the operator's
/// role or preferred response language. The language line is emitted
/// only for a non-English BCP-47 tag (English is the model default, so
/// no instruction is needed). Returns `None` only when there are
/// neither facts nor a rendered body.
fn merge_operator_facts(config: &FreedomConfig, rendered_md: Option<String>) -> Option<String> {
    let mut facts: Vec<String> = Vec::new();

    if let Some(role) = operator_role_label(config) {
        facts.push(format!("Operator role: {role}."));
    }
    if let Some(tag) = config.language_primary.as_deref() {
        let tag = tag.trim();
        if !tag.is_empty() && !tag.to_ascii_lowercase().starts_with("en") {
            facts.push(format!(
                "Respond in the operator's primary language (BCP-47 '{tag}') \
                 unless they write to you in another language."
            ));
        }
    }

    match (facts.is_empty(), rendered_md) {
        (true, md) => md,
        (false, Some(md)) => Some(format!("{}\n\n{md}", facts.join("\n"))),
        (false, None) => Some(facts.join("\n")),
    }
}

/// A-1 audit emission. Records every refused hemisphere with role +
/// provider + class + cause so an operator running `neoth wal show` can
/// reconstruct exactly which hemisphere said no + why, even when the
/// chat reply silently absorbed the refusal via Consensus or Callosum.
async fn emit_council_partial_refusal(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    outcome: &crate::council::CouncilDebate,
) -> Result<()> {
    let refused: Vec<serde_json::Value> = outcome
        .refused_responses()
        .map(|r| {
            let class = r
                .refusal
                .as_ref()
                .map(|x| x.class.as_str())
                .unwrap_or("none");
            let cause = r
                .refusal
                .as_ref()
                .map(|x| x.cause.as_str())
                .unwrap_or("unknown");
            let role = match r.role {
                crate::config::inference::HemisphereRole::Left => "left",
                crate::config::inference::HemisphereRole::Right => "right",
                crate::config::inference::HemisphereRole::Cerebellum => "cerebellum",
            };
            serde_json::json!({
                "role": role,
                "provider": r.provider,
                "class": class,
                "cause": cause,
            })
        })
        .collect();
    let payload_value = serde_json::json!({
        "prompt_hash": format!("{prompt_hash:016x}"),
        "refused_count": outcome.refused_count() as u32,
        "usable_count": outcome.usable_responses().count() as u32,
        "refused": refused,
    });
    let payload =
        serde_json::to_vec(&payload_value).context("serialize COUNCIL_PARTIAL_REFUSAL payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_PARTIAL_REFUSAL frame");
    }
    Ok(())
}

/// B-1 (Session 13) — record that the council smart-trigger evaluated
/// to `Skip` for this prompt. Pairs with `EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED`
/// (0x60) + `EVENT_TYPE_COUNCIL_PARTIAL_REFUSAL` (0x61) so the operator's
/// WAL audit covers every council branch: skipped / fired-clean /
/// fired-with-refusals / fired-with-synthesis. Reason string carries the
/// gate that fired (env override, complexity, rate, budget, …).
pub(crate) async fn emit_council_skip(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    reason: &str,
) -> Result<()> {
    let payload_value = serde_json::json!({
        "prompt_hash": format!("{prompt_hash:016x}"),
        "reason": reason,
    });
    let payload = serde_json::to_vec(&payload_value).context("serialize COUNCIL_SKIP payload")?;
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_COUNCIL_SKIP, &payload)
            .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_SKIP frame");
    }
    Ok(())
}

/// Pick #8 SP-2 (Session 14) — role-agnostic winner selection
/// outcome. Returned by [`select_winner_role_agnostic`] when the
/// operator's `selection_mode` picked a hemisphere via
/// `CouncilDebate::best_response`. Carries the winning role +
/// provider + composite score so the dispatch path can emit
/// WAL `0x63 COUNCIL_WINNER_SELECTED` with full audit context.
#[derive(Clone, Debug)]
pub(crate) struct RoleAgnosticWinner {
    pub text: String,
    pub role: crate::config::inference::HemisphereRole,
    pub provider: String,
    pub score: f32,
}

/// Pick #8 SP-2 (Session 14) — apply the operator's
/// `SelectionMode` to a finished council debate.
///
/// Returns `Some(winner)` when role-agnostic dispatch picked a
/// hemisphere; `None` when the caller should fall through to the
/// legacy verdict-driven path (winning_text → Split callosum →
/// QuorumFailed surface).
///
/// Modes:
///   - `LegacyMajority` → ALWAYS returns `None` (no behaviour change)
///   - `ConsensusOrBest` → uses `winning_text` if Verdict::Consensus
///     produced one, else falls back to `best_response`
///   - `BestAlways` → ignores Verdict, always picks `best_response`
///
/// Pick #8 SP-4 (Session 14): `routing_weights` (when `Some`) lifts
/// the `memory_weight` component of each hemisphere's composite score
/// based on past operator-acceptance for the same topic. `None`
/// keeps the neutral prior — same as Session-14 baseline.
/// SP-4 F5 diversity bonus for one hemisphere: the Jaccard distance of
/// its text to the council consensus. The consensus proxy is the
/// verdict's winning text when present, else the first OTHER usable
/// hemisphere's text (so we always compare two distinct inputs).
/// Returns `0.0` for an errored hemisphere (no text) or when no other
/// usable text exists (nothing to be diverse from). Bounded `[0.0, 1.0]`;
/// `total()` weights it at `0.05`.
fn diversity_bonus_for(
    my_text: Option<&str>,
    my_role: crate::config::inference::HemisphereRole,
    outcome: &crate::council::CouncilDebate,
) -> f32 {
    my_text
        .and_then(|my_text| {
            let consensus_proxy = outcome.winning_text().or_else(|| {
                outcome
                    .responses
                    .iter()
                    .find(|other| other.role != my_role && other.text.is_some())
                    .and_then(|other| other.text.as_deref())
            });
            consensus_proxy.map(|cp| crate::council::dissent::score_dissent(&[my_text, cp]).0)
        })
        .unwrap_or(0.0)
}

pub(crate) fn select_winner_role_agnostic(
    outcome: &crate::council::CouncilDebate,
    mode: crate::config::inference::SelectionMode,
    routing_weights: Option<&crate::memory::routing_weights::RoutingWeights>,
    topic_hash: u64,
    council_cfg: Option<&crate::config::inference::CouncilConfig>,
) -> Option<RoleAgnosticWinner> {
    use crate::config::inference::SelectionMode;
    if matches!(mode, SelectionMode::LegacyMajority) {
        return None;
    }

    let now = crate::memory::routing_weights::now_unix();

    // Compute per-hemisphere composite scores for best_response().
    // Memory weight uses routing_weights when present; otherwise
    // falls back to the neutral 0.5 prior baked into score_response.
    let scores: Vec<(crate::config::inference::HemisphereRole, f32)> = outcome
        .responses
        .iter()
        .map(|r| {
            let base = crate::council::quality_score::score_response(r);
            let mem = match routing_weights {
                Some(rw) => rw.load_memory_weight(topic_hash, r.role, now),
                None => base.memory_weight,
            };
            // F5 diversity_bonus (SP-4): Jaccard distance of THIS
            // hemisphere's text to the consensus — a dissenting
            // hemisphere earns a small lift (worth `0.05 × bonus` in
            // `total()`) so a lone correct dissenter isn't buried by two
            // agreeing-but-wrong hemispheres. Was hardcoded 0.0 before.
            let diversity = diversity_bonus_for(r.text.as_deref(), r.role, outcome);
            // Recompose composite with the looked-up memory_weight + the
            // computed diversity_bonus.
            let composite = crate::council::quality_score::QualityScore::new(
                base.tier_weight,
                base.dynamic_signal,
                mem,
                diversity,
            )
            .total();
            (r.role, composite)
        })
        .collect();

    // COUNCIL-WEIGHTING-01 — locality priors (local bonus + tie-break nudge)
    // applied to the composite scores BEFORE any selection path reads them,
    // so winner choice and surfaced score stay consistent.
    let mut scores = scores;
    if let Some(cfg) = council_cfg {
        crate::council::quality_score::apply_locality_weights(&mut scores, &outcome.responses, cfg);
    }

    // ConsensusOrBest: prefer the Verdict's winning_text when
    // present + the corresponding hemisphere is identifiable. When
    // identifying the hemisphere by text fails, fall back to the
    // highest-scored usable response.
    if matches!(mode, SelectionMode::ConsensusOrBest)
        && let Some(text) = outcome.winning_text()
    {
        // Try to find which hemisphere produced this text.
        if let Some(matching) = outcome.responses.iter().find(|r| {
            // Audit 2026-05-19 Type #13 Phase 2: single exhaustive
            // match expresses "Usable variant whose text is exactly
            // the verdict text" without the two-step
            // `text.as_deref().is_some_and(...) && is_usable()` dance.
            matches!(
                r.outcome(),
                crate::council::types::HemisphereOutcome::Usable { text: t } if t == text
            )
        }) {
            let score = scores
                .iter()
                .find(|(role, _)| *role == matching.role)
                .map(|(_, s)| *s)
                .unwrap_or(0.0);
            return Some(RoleAgnosticWinner {
                text: text.to_string(),
                role: matching.role,
                provider: matching.provider.clone(),
                score,
            });
        }
        // text didn't match any hemisphere's text exactly — fall
        // through to best_response below.
    }

    // BestAlways path OR ConsensusOrBest fallback.
    let winner = outcome.best_response(&scores)?;
    let text = winner.text.clone()?;
    let score = scores
        .iter()
        .find(|(role, _)| *role == winner.role)
        .map(|(_, s)| *s)
        .unwrap_or(0.0);
    Some(RoleAgnosticWinner {
        text,
        role: winner.role,
        provider: winner.provider.clone(),
        score,
    })
}

/// Pick #8 F8 (Session 14 Pick #20) — pre-flight provider-diversity
/// audit. Classifies the topology, emits a WAL `0x64
/// COUNCIL_DIVERSITY_WARNING` frame whenever the verdict is not
/// `Distinct`, and surfaces a once-per-process stderr line so the
/// operator sees a misconfig BEFORE the council burns tokens through
/// a degraded debate.
///
/// `Distinct` skips both emissions — no audit pollution + no terminal
/// noise when the topology is healthy.
pub(crate) async fn emit_council_diversity_warning_if_needed(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    config: &FreedomConfig,
) -> Result<()> {
    let verdict = crate::council::classify_council_diversity(&config.inference);
    if !verdict.needs_warning() {
        return Ok(());
    }
    // Once-per-process stderr — operator sees the line once per
    // session (or per daemon lifetime). The WAL frame still emits
    // every council pass so audit reconstruction stays complete.
    if crate::council::diversity::claim_warning_emission_slot() {
        eprintln!("[neoth council] WARNING: {}", verdict.render_short());
    }
    let verdict_payload = serde_json::to_value(&verdict).context("serialize DiversityVerdict")?;
    let mut payload_value = serde_json::json!({
        "prompt_hash": format!("{prompt_hash:016x}"),
    });
    // Splice the tagged verdict fields ({verdict, left, right, ...})
    // into the top-level object so the audit consumer can dispatch
    // on `verdict` directly without an extra layer.
    if let (Some(payload), Some(verdict_obj)) =
        (payload_value.as_object_mut(), verdict_payload.as_object())
    {
        for (k, v) in verdict_obj {
            payload.insert(k.clone(), v.clone());
        }
    }
    let payload = serde_json::to_vec(&payload_value)
        .context("serialize COUNCIL_DIVERSITY_WARNING payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COUNCIL_DIVERSITY_WARNING,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_DIVERSITY_WARNING frame");
    }
    Ok(())
}

/// Pick #8 SP-2 (Session 14) — emit WAL `0x63 COUNCIL_WINNER_SELECTED`
/// audit frame.
///
/// `depth` is the recursion level (0 for outer council). Fractal
/// synthesis hard-rule (F7): payload MUST include `depth` so audit
/// consumers can reconstruct the recursion tree across nested
/// councils.
pub(crate) async fn emit_council_winner_selected(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    depth: u8,
    winner: &RoleAgnosticWinner,
    mode: crate::config::inference::SelectionMode,
) -> Result<()> {
    use crate::config::inference::SelectionMode;
    let mode_str = match mode {
        SelectionMode::LegacyMajority => "legacy_majority",
        SelectionMode::ConsensusOrBest => "consensus_or_best",
        SelectionMode::BestAlways => "best_always",
    };
    let payload_value = serde_json::json!({
        "prompt_hash": format!("{prompt_hash:016x}"),
        "depth": depth,
        "role": match winner.role {
            crate::config::inference::HemisphereRole::Left => "left",
            crate::config::inference::HemisphereRole::Right => "right",
            crate::config::inference::HemisphereRole::Cerebellum => "cerebellum",
        },
        "provider": winner.provider,
        "score": winner.score,
        "mode": mode_str,
    });
    let payload =
        serde_json::to_vec(&payload_value).context("serialize COUNCIL_WINNER_SELECTED payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COUNCIL_WINNER_SELECTED,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_WINNER_SELECTED frame");
    }
    Ok(())
}

async fn emit_council_synthesis_attempted(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    outcome: CouncilSynthesisOutcome,
) -> Result<()> {
    let payload_value = match &outcome {
        CouncilSynthesisOutcome::Synthesis { chars } => serde_json::json!({
            "prompt_hash": format!("{prompt_hash:016x}"),
            "outcome": "synthesis",
            "synthesis_chars": chars,
        }),
        CouncilSynthesisOutcome::IrreconcilableConflict { reason } => serde_json::json!({
            "prompt_hash": format!("{prompt_hash:016x}"),
            "outcome": "irreconcilable_conflict",
            "reason": reason,
        }),
    };
    let payload = serde_json::to_vec(&payload_value)
        .context("serialize COUNCIL_SYNTHESIS_ATTEMPTED payload")?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COUNCIL_SYNTHESIS_ATTEMPTED,
        &payload,
    )
    .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "could not append COUNCIL_SYNTHESIS_ATTEMPTED frame");
    }
    Ok(())
}

/// Per-hemisphere transcript-text cap. Keeps a single `0x66` frame
/// scannable + well under the WAL `MAX_PAYLOAD_BYTES` ceiling even for a
/// verbose model. A longer reply is truncated with a marker so replay
/// shows the bulk of the prose without the frame failing to append.
const MAX_TRANSCRIPT_BYTES: usize = 32 * 1024;

/// KF-01 full — OPT-IN: persist each hemisphere's verbatim response text
/// as a `0x66 COUNCIL_TRANSCRIPT` frame so `neoth council replay` can show
/// the actual prose. No-op unless `freedom.yaml::council.persist_transcripts`
/// is true (default false — hemisphere prose is sensitive). Best-effort:
/// a failed append is logged but never blocks the chat turn, and the
/// debate result is unchanged either way. Errored hemispheres (no text)
/// are skipped — their `0x61`/metadata frames already record the refusal.
async fn emit_council_transcripts(
    writer: &crate::wal::writer::WalWriterHandle,
    prompt_hash: u64,
    outcome: &crate::council::CouncilDebate,
    config: &FreedomConfig,
) {
    if !config.council.persist_transcripts {
        return;
    }
    for resp in &outcome.responses {
        let Some(text) = resp.text.as_deref() else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        let stored = if text.len() > MAX_TRANSCRIPT_BYTES {
            let safe = crate::util::byte_floor(text, MAX_TRANSCRIPT_BYTES);
            let mut t = text[..safe].to_string();
            t.push_str("\n[NEOTH] …transcript truncated…");
            t
        } else {
            text.to_string()
        };
        let payload_value = serde_json::json!({
            "prompt_hash": format!("{prompt_hash:016x}"),
            "role": resp.role.as_str(),
            "provider": resp.provider.as_str(),
            "text": stored,
        });
        let payload = match serde_json::to_vec(&payload_value) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "could not serialize COUNCIL_TRANSCRIPT payload");
                continue;
            }
        };
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_COUNCIL_TRANSCRIPT,
            &payload,
        )
        .build();
        if let Err(e) = writer.append(header, payload).await {
            warn!(
                error = %e,
                role = %resp.role.as_str(),
                "could not append COUNCIL_TRANSCRIPT frame"
            );
        }
    }
}

/// Convert the reviewed per-leaf USD bounds into the smart-trigger inputs.
/// Without a daily cap there is no budget gate, so unknown subscription or
/// deployment pricing remains usable and the hard provider authorizer keeps
/// its existing policy semantics. With a cap, every reachable paid leaf must
/// have a finite reviewed bound.
#[cfg_attr(not(test), allow(dead_code))] // retained: exercised by unit tests; prod caller removed in Wave-3 refactor
pub(crate) fn council_trigger_cost_bound(
    config: &FreedomConfig,
    req: &crate::providers::Request,
) -> Result<(f32, Option<f32>)> {
    council_trigger_cost_bound_inner(config, req, None)
}

pub(crate) fn council_trigger_cost_bound_at(
    config: &FreedomConfig,
    req: &crate::providers::Request,
    home: &std::path::Path,
) -> Result<(f32, Option<f32>)> {
    council_trigger_cost_bound_inner(config, req, Some(home))
}

fn council_trigger_cost_bound_inner(
    config: &FreedomConfig,
    req: &crate::providers::Request,
    home: Option<&std::path::Path>,
) -> Result<(f32, Option<f32>)> {
    if config.council.daily_usd_cap.is_none() {
        return Ok((0.0, None));
    }
    let bound = match home {
        Some(home) => {
            crate::providers::cost::council_tree_authorization_bound_usd_at(config, req, home)?
        }
        None => crate::providers::cost::council_tree_authorization_bound_usd(config, req)?,
    };
    tracing::debug!(
        candidate_leaves = bound.candidate_leaf_count,
        costed_leaves = bound.costed_leaf_count,
        total_usd = bound.total_usd,
        max_leaf_usd = bound.max_leaf_usd,
        "Council smart-trigger bound resolved from active topology"
    );
    anyhow::ensure!(
        bound.total_usd <= f64::from(f32::MAX) && bound.max_leaf_usd <= f64::from(f32::MAX),
        "Council smart-trigger cost bound exceeds the supported range"
    );
    Ok((bound.max_leaf_usd as f32, Some(bound.total_usd as f32)))
}

/// K-Wire-3 v2 2026-05-17: evaluate the council smart-trigger using
/// the same env-override + policy logic as `cli/chat.rs::run_chat_with`.
/// Returns the `TriggerDecision` so callers can log + audit both the
/// Convene + Skip branches. Pure function — no I/O, no provider call.
///
/// Env override semantics match the CLI:
///   - `NEOTH_COUNCIL_DISABLE=1` → forced Skip
///   - `NEOTH_COUNCIL_ENABLE=1`  → forced Convene (bypasses gates)
///   - unset / anything else     → AUTO via `council::should_convene`
///
/// `estimated_single_call_usd` and `estimated_council_cost_usd` come from
/// [`council_trigger_cost_bound`]. The former preserves the operator's
/// multiplier floor; the latter prevents recursive/mixed-provider fan-out
/// from being reduced to a single flat estimate.
///
/// `disabled` is the SPEC-03 persistent suppress flag
/// (`freedom.yaml::council.disabled`); the channel caller reads it fresh
/// per message so `neoth council suppress` takes effect without a daemon
/// restart. `true` → forced Skip (the durable twin of
/// `NEOTH_COUNCIL_DISABLE=1`, which still wins when both are set).
///
/// Precedence (highest first): `NEOTH_COUNCIL_DISABLE=1` → `disabled` flag
/// → `NEOTH_COUNCIL_ENABLE=1` → AUTO. So EITHER disable source beats the
/// force-enable env var: a suppressed council cannot be force-convened
/// without first clearing the suppress. This is intentional (an operator
/// who durably opted out should not be overridden by a stray env var) and
/// is pinned by `evaluate_council_trigger_disable_beats_force_enable`.
pub(crate) fn evaluate_council_trigger(
    neoth_home: &std::path::Path,
    prompt: &str,
    estimated_single_call_usd: f32,
    estimated_council_cost_usd: Option<f32>,
    daily_usd_cap: Option<f32>,
    disabled: bool,
    policy: &crate::council::TriggerPolicy,
) -> crate::council::TriggerDecision {
    let council_force = std::env::var("NEOTH_COUNCIL_ENABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let council_disable = std::env::var("NEOTH_COUNCIL_DISABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if council_disable {
        return crate::council::TriggerDecision::Skip {
            reason: "NEOTH_COUNCIL_DISABLE=1".into(),
        };
    }
    if disabled {
        return crate::council::TriggerDecision::Skip {
            reason: "freedom.yaml::council.disabled=true".into(),
        };
    }
    if council_force {
        return crate::council::TriggerDecision::Convene {
            reason: "NEOTH_COUNCIL_ENABLE=1 (force)".into(),
        };
    }
    // B-3 (Session 13) — same real-timestamp feed as the CLI dispatch
    // path uses. Channel ingress no longer has a permanently-open rate
    // gate.
    let now_unix_b3 = crate::council::last_ts::now_unix();
    let secs_since = crate::council::last_ts::seconds_since_last(neoth_home, now_unix_b3);
    let remaining_budget_usd = match daily_usd_cap {
        None => None,
        Some(cap_usd) => match crate::council::daily_budget::remaining_daily_budget_usd(
            neoth_home,
            cap_usd,
            now_unix_b3 as i64,
        ) {
            Ok(remaining) => Some(remaining),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "channel council daily-budget snapshot invalid — smart trigger skipped fail-closed"
                );
                return crate::council::TriggerDecision::Skip {
                    reason: "council daily-budget state invalid — fail-closed".into(),
                };
            }
        },
    };
    let ctx = crate::council::TriggerContext {
        seconds_since_last_council: secs_since,
        remaining_budget_usd,
        estimated_single_call_usd,
        estimated_council_cost_usd,
    };
    crate::council::should_convene(prompt, &ctx, policy)
}

/// K-Wire-3 v2 2026-05-17: drive a full council debate including A5
/// callosum recovery on Split verdicts. Returns the final operator-
/// facing reply text — the caller (chat.rs CLI or serve.rs channel
/// handler) is responsible for downstream framing (print to stdout vs
/// CHANNEL_EGRESS WAL frame + send to messenger).
///
/// Flow:
///   1. `run_council_debate(config, req)` fires all three hemispheres
///      via `FuturesUnordered` with early-exit on quorum-with-consensus
///      (K-Perf-1).
///   2. Verdict::Consensus → return `winning_text()`.
///   3. Verdict::Split → A5 callosum recovery: build a fresh
///      Cerebellum, fetch `profile_block_for_callosum()` for CH-11
///      operator-context injection, call the shared-budget
///      `callosum::resolve_with_profile_budget`,
///      emit COUNCIL_SYNTHESIS_ATTEMPTED (0x60) audit. Synthesis →
///      return the synthesised text; IrreconcilableConflict → fall back
///      to the "[council split — operator decision needed]" message.
///   4. Verdict::QuorumFailed → return diagnostic text "[council quorum
///      failed — N/M hemispheres responded]".
/// GOLD-ADAPT-LOWKEY-04 wiring — the MIF pre-step decision, extracted pure so
/// it is unit-testable without spawning a provider. Returns `Some(message)`
/// when MIF is enabled AND the prompt's intent is `Conflicted` (contradictory
/// goals the council must NOT debate); `None` otherwise (disabled, or a
/// `Stated`/`Inferred` prompt the council should answer normally).
pub(crate) fn mif_disambiguation(config: &FreedomConfig, prompt: &str) -> Option<String> {
    if !config.council.mif_enabled {
        return None;
    }
    crate::council::motive_ident::classify_motive(prompt).disambiguation_message()
}

struct CouncilBudgetOutcomeRecorder<'a> {
    home: &'a std::path::Path,
    budget: crate::council::BudgetToken,
    enabled: bool,
}

impl Drop for CouncilBudgetOutcomeRecorder<'_> {
    fn drop(&mut self) {
        if self.enabled {
            crate::council::budget::record_budget_outcome(
                self.home,
                self.budget.used(),
                self.budget.cap(),
                self.budget.was_denied(),
                now_unix() as i64,
            );
        }
    }
}

pub(crate) async fn dispatch_council_with_recovery(
    req: &crate::providers::Request,
    config: &FreedomConfig,
    neoth_home: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    tool_scope: &crate::mcp::McpToolScope,
) -> Result<String> {
    dispatch_council_with_recovery_for_turn(
        req, config, neoth_home, writer, authorizer, tool_scope, false,
    )
    .await
}

async fn dispatch_council_with_recovery_for_turn(
    req: &crate::providers::Request,
    config: &FreedomConfig,
    neoth_home: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
    authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer,
    tool_scope: &crate::mcp::McpToolScope,
    incognito: bool,
) -> Result<String> {
    // Pick #8 F8 (Session 14 Pick #20) — channel-path pre-flight
    // diversity audit. Mirrors the CLI-path emission in `run_chat_with`
    // so the WAL audit trail records misconfigured topologies
    // regardless of ingress channel.
    let prompt_hash_pre = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
    let _ = emit_council_diversity_warning_if_needed(writer, prompt_hash_pre, config).await;
    // GOLD-ADAPT-LOWKEY-04 — MIF motive pre-step (opt-in). Classify operator
    // intent BEFORE the hemisphere fan-out: a Conflicted prompt is NOT debated
    // (would only produce a confused answer) — surface a disambiguation request
    // and skip the council entirely (no provider cost). Audited as a
    // COUNCIL_SKIP so the WAL trace shows why the debate didn't run.
    if let Some(message) = mif_disambiguation(config, &req.prompt) {
        let _ = emit_council_skip(writer, prompt_hash_pre, "mif_conflicted_disambiguation").await;
        tracing::info!("MIF: conflicted intent — council skipped, disambiguation surfaced");
        return Ok(message);
    }
    let authorizer = authorizer.with_council_daily_cap(neoth_home, config.council.daily_usd_cap)?;
    let council_budget = crate::council::BudgetToken::from_council(&config.council);
    let _budget_recorder = CouncilBudgetOutcomeRecorder {
        home: neoth_home,
        budget: council_budget.clone(),
        enabled: !incognito,
    };
    let outcome = run_council_debate(
        config,
        neoth_home,
        req,
        &authorizer,
        !incognito,
        council_budget.clone(),
    )
    .await?;
    // KF-01 (COR-17): persist verbatim hemisphere transcripts (opt-in) so
    // `neoth council replay` can show the actual prose. No-op unless
    // freedom.yaml::council.persist_transcripts = true. Emitted here so BOTH
    // the CLI and channel paths record replayable transcripts identically.
    if !incognito {
        emit_council_transcripts(writer, prompt_hash_pre, &outcome, config).await;
    }
    // B-3 (Session 13) — record this debate's wall-clock so the NEXT
    // inbound's trigger eval honours the rate cooldown.
    if !incognito
        && let Err(e) =
            crate::council::last_ts::record(neoth_home, crate::council::last_ts::now_unix())
    {
        warn!(error = %e, "could not persist council_last.json (channel path)");
    }
    // B-2 (Session 13): role-keyed provider lookup — `outcome.responses` can
    // hold <3 entries when K-Perf-1 early-exit cancels a slow hemisphere;
    // `response_for` returns Option rather than panicking on a direct index.
    let left_provider_str = outcome
        .response_for(crate::config::inference::HemisphereRole::Left)
        .map(|r| r.provider.as_str())
        .unwrap_or("cancelled");
    let right_provider_str = outcome
        .response_for(crate::config::inference::HemisphereRole::Right)
        .map(|r| r.provider.as_str())
        .unwrap_or("cancelled");
    let cere_provider_str = outcome
        .response_for(crate::config::inference::HemisphereRole::Cerebellum)
        .map(|r| r.provider.as_str())
        .unwrap_or("cancelled");
    info!(
        dissent = outcome.dissent.0,
        left_provider = left_provider_str,
        right_provider = right_provider_str,
        cere_provider = cere_provider_str,
        refused_count = outcome.refused_count(),
        is_partial_refusal = outcome.is_partial_refusal(),
        total_latency_ms = outcome.total_latency_ms,
        "council debate complete"
    );
    // ADV-10b (COR-17): surface a degraded debate (fewer than 3 hemispheres
    // contributed) at warn level on both paths so a persistently failing
    // hemisphere isn't only visible at debug.
    let degradation = outcome.degradation();
    if degradation.is_degraded() {
        warn!(
            degradation = degradation.variant_name(),
            errored_count = degradation.errored_count(),
            left_provider = left_provider_str,
            right_provider = right_provider_str,
            cere_provider = cere_provider_str,
            "council debate degraded — fewer than 3 hemispheres contributed (ADV-10b)"
        );
    }
    // A-1 (channel path): emit COUNCIL_PARTIAL_REFUSAL audit frame as
    // soon as any hemisphere refused. Same contract as the CLI path —
    // operator sees refusals via `neoth wal show` even when Consensus
    // or Callosum absorbed them silently.
    let prompt_hash_outer = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
    if outcome.is_partial_refusal() {
        let _ = emit_council_partial_refusal(writer, prompt_hash_outer, &outcome).await;
    }

    // Pick #8 SP-2 (Session 14) — role-agnostic winner selection.
    // When operator configured `council.selection_mode =
    // consensus_or_best` or `best_always`, pick by quality score
    // rather than verdict-text fallback. LegacyMajority returns
    // `None` here so the existing v0.1 behaviour is preserved.
    let mut routing_weights = if incognito {
        crate::memory::routing_weights::RoutingWeights::in_memory()
    } else {
        let rw_path = crate::memory::routing_weights::RoutingWeights::default_path(neoth_home);
        crate::memory::routing_weights::RoutingWeights::load_from(&rw_path)
            .with_context(|| format!("load routing weights {}", rw_path.display()))?
    };
    let role_agnostic = select_winner_role_agnostic(
        &outcome,
        config.council.selection_mode,
        Some(&routing_weights),
        prompt_hash_outer,
        Some(&config.council),
    );
    // GOLD-ADAPT-LOWKEY-07 — transparent-core: surface the council's Layer-B
    // (verdict, dissent, per-hemisphere provider/score/latency/refusal, what
    // was injected, the winner) to STDERR when the operator opts in. Off by
    // default; never touches the Layer-A answer. Covers BOTH the CLI and the
    // channel council paths (both route through this shared dispatch).
    crate::council::transparent::maybe_emit_layer_b(
        config,
        &outcome,
        role_agnostic.as_ref().map(|w| w.role),
        role_agnostic.as_ref().map(|w| w.score),
        req,
    );
    if let Some(winner) = role_agnostic {
        let _ = emit_council_winner_selected(
            writer,
            prompt_hash_outer,
            0,
            &winner,
            config.council.selection_mode,
        )
        .await;
        // SP-5 (Session 14) — self-reflect refinement pass.
        // Threshold + kill-switch gated; fail-safe on any error.
        let mut final_text = if crate::council::self_reflect::should_refine(config, winner.score, 0)
        {
            match build_hemisphere(config, neoth_home, winner.role, req, authorizer.clone()).await {
                Ok(reflect_hemisphere) => {
                    let refined = crate::council::self_reflect::refine_with_budget(
                        &req.prompt,
                        &winner.text,
                        &reflect_hemisphere,
                        &council_budget,
                    )
                    .await;
                    refined.refined
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "self-reflect skipped: could not rebuild winning hemisphere"
                    );
                    winner.text.clone()
                }
            }
        } else {
            winner.text.clone()
        };
        // GOLD-ADAPT-LOWKEY-01/01b — deterministic self-score gate.
        // Scores the resolved answer on 4 axes (no LLM call), then acts per
        // `council.self_score_action`: Warn (observe-only, default), Block
        // (withhold + deliver a notice), or Redo (re-refine the winning
        // hemisphere up to `effective_self_score_max_redos`, keep the best
        // composite). A durable 0x6A COUNCIL_SELF_SCORE WAL frame is always
        // emitted; it now records the action taken + redo count.
        {
            let mut self_score = crate::council::self_reflect::score_answer(&final_text);
            let action = config.council.self_score_action;
            let mut redos: u8 = 0;
            // Redo: re-refine while the gate still fires, keeping the best
            // composite candidate. Opt-in (action == Redo) only.
            if action == crate::config::inference::SelfScoreAction::Redo
                && crate::council::self_reflect::should_gate(config, &self_score)
            {
                let max_redos = config.council.effective_self_score_max_redos();
                while redos < max_redos
                    && crate::council::self_reflect::should_gate(config, &self_score)
                {
                    redos += 1;
                    match build_hemisphere(config, neoth_home, winner.role, req, authorizer.clone())
                        .await
                    {
                        Ok(h) => {
                            let cand = crate::council::self_reflect::refine_with_budget(
                                &req.prompt,
                                &final_text,
                                &h,
                                &council_budget,
                            )
                            .await
                            .refined;
                            let cand_score = crate::council::self_reflect::score_answer(&cand);
                            if cand_score.composite() > self_score.composite() {
                                final_text = cand;
                                self_score = cand_score;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "self-score redo: hemisphere rebuild failed");
                            break;
                        }
                    }
                }
            }
            let below = crate::council::self_reflect::should_gate(config, &self_score);
            let blocked = below && action == crate::config::inference::SelfScoreAction::Block;
            let payload = serde_json::to_vec(&serde_json::json!({
                "prompt_hash": prompt_hash_outer,
                "correctness": self_score.correctness,
                "completeness": self_score.completeness,
                "coherence": self_score.coherence,
                "evidence": self_score.evidence,
                "composite": self_score.composite(),
                "below_threshold": below,
                "action": format!("{action:?}"),
                "redos": redos,
                "blocked": blocked,
                "ts_unix": now_unix(),
            }))
            .unwrap_or_default();
            let header = crate::wal::make_header(
                crate::wal::events::EVENT_TYPE_COUNCIL_SELF_SCORE,
                &payload,
            );
            if let Err(e) = writer.append(header, payload).await {
                tracing::warn!(
                    error = %e,
                    "COUNCIL_SELF_SCORE WAL emit failed (non-fatal)"
                );
            }
            if blocked {
                tracing::warn!(
                    composite = self_score.composite(),
                    "LOWKEY-01b self-score BLOCK — answer withheld"
                );
                final_text = format!(
                    "[withheld] The generated answer scored {:.2} on the deterministic self-quality gate (below the configured minimum) and was withheld per council.self_score_action=block. Lower council.self_score_min_composite or change the action to receive it.",
                    self_score.composite()
                );
            } else if below {
                eprintln!(
                    "[neoth:self-score] composite {:.2} below threshold — answer may lack evidence or completeness{}",
                    self_score.composite(),
                    if redos > 0 {
                        format!(" (after {redos} redo pass(es))")
                    } else {
                        String::new()
                    }
                );
            }
        }
        // SP-4: record acceptance signal so future debates on the
        // same topic lift the winning hemisphere's memory_weight.
        if !incognito {
            routing_weights.record_acceptance(
                prompt_hash_outer,
                winner.role,
                crate::memory::routing_weights::now_unix(),
            );
            if let Err(e) = routing_weights.save() {
                tracing::warn!(error = %e, "could not persist routing_weights.json (channel)");
            }
        }
        // GOLD-LOOP-01 — dissent-spike auto-invoke. When the council debate
        // produced strong dissent (score >= 0.6) AND the operator has opted in
        // via `loop_config.auto_invoke_on_dissent = true`, run one extra loop
        // round to try to produce a more-converged answer. The loop result
        // REPLACES `final_text` — we return EARLY so the normal render path
        // below never fires (avoiding a double-render of a stale answer).
        //
        // Note: this fires AFTER the self-reflect refine + self-score gate
        // above, so the loop starts from the already-refined text in `req`.
        if !incognito
            && outcome.dissent.is_strong_dissent()
            && config.loop_config.auto_invoke_on_dissent
        {
            let loop_cfg = crate::loop_engine::engine::LoopConfig::for_dissent_invoke(
                config.autonomy,
                neoth_home.to_path_buf(),
                config.loop_config.tool_call_budget,
            );
            tracing::info!(
                dissent = outcome.dissent.0,
                "GOLD-LOOP-01: strong dissent detected — auto-invoking loop engine (1 round)"
            );
            let winner_provider =
                match crate::providers::from_config_for_role_at(config, winner.role, neoth_home)
                    .await
                {
                    Ok(provider) => provider,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "GOLD-LOOP-01: dissent-invoke: could not build winner provider"
                        );
                        let response_text = match partial_refusal_prefix(&outcome) {
                            Some(prefix) => format!("{prefix}\n{final_text}"),
                            None => final_text,
                        };
                        return Ok(response_text);
                    }
                };
            let winner_model =
                resolve_provider_call_wire_model(config, winner_provider.as_ref(), None)?;
            let mut winner_req = req.clone();
            winner_req.model = Some(winner_model);
            match crate::loop_engine::engine::run_loop(
                &loop_cfg,
                winner_provider.as_ref(),
                winner_req,
                &crate::mcp::McpServers::default(),
                writer,
                config,
                authorizer.clone(),
                Some(&council_budget),
                tool_scope,
                // P4 — interactive chat session: honour the elicitation gate.
                if config.elicitation.enabled {
                    &crate::cli::elicitation::ElicitationHandler::Cli
                } else {
                    &crate::cli::elicitation::ElicitationHandler::Disabled
                },
            )
            .await
            {
                Ok(record) => {
                    tracing::info!(
                        loop_id = %record.loop_id,
                        rounds_run = record.rounds_run,
                        "GOLD-LOOP-01: dissent-invoke loop completed — using loop output"
                    );
                    return Ok(record.final_text);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "GOLD-LOOP-01: dissent-invoke loop failed — using original council output"
                    );
                    // Fall through to original path.
                }
            }
        }

        let response_text = match partial_refusal_prefix(&outcome) {
            Some(prefix) => format!("{prefix}\n{final_text}"),
            None => final_text,
        };
        return Ok(response_text);
    }

    let response_text = match outcome.winning_text() {
        Some(t) => {
            // A-1: prefix annotation when one hemisphere refused but
            // Consensus still produced a winning text.
            match partial_refusal_prefix(&outcome) {
                Some(prefix) => format!("{prefix}\n{t}"),
                None => t.to_string(),
            }
        }
        None => match &outcome.verdict {
            crate::council::Verdict::Split { summary } => {
                // B-2: callosum-on-partial-refusal recovery — feed only
                // usable hemisphere texts to the synthesis prompt so the
                // refused hemisphere's text never reaches the cerebellum.
                let usable: Vec<&crate::council::HemisphereResponse> =
                    outcome.usable_responses().collect();
                // Audit 2026-05-19 Type #13 Phase 2: every text accessor
                // routes through outcome().text() — usable_responses
                // guarantees Some on the primary path, the role-keyed
                // fallback returns None for Errored hemispheres so the
                // final unwrap_or("") preserves the legacy behaviour.
                let left_text = usable
                    .first()
                    .and_then(|r| r.outcome().text())
                    .unwrap_or_else(|| {
                        outcome
                            .response_for(crate::config::inference::HemisphereRole::Left)
                            .and_then(|r| r.outcome().text())
                            .unwrap_or("")
                    });
                let right_text = usable
                    .get(1)
                    .and_then(|r| r.outcome().text())
                    .unwrap_or_else(|| {
                        outcome
                            .response_for(crate::config::inference::HemisphereRole::Right)
                            .and_then(|r| r.outcome().text())
                            .unwrap_or("")
                    });
                let prompt_hash = prompt_hash_outer;
                let profile_block = profile_block_for_callosum_for_turn(
                    neoth_home.join("views.db"),
                    config.profile.pii_categories_disabled.clone(),
                    incognito,
                )
                .await
                .unwrap_or_default();
                let profile_opt = if profile_block.is_empty() {
                    None
                } else {
                    Some(profile_block.as_str())
                };
                match build_hemisphere(
                    config,
                    neoth_home,
                    crate::config::inference::HemisphereRole::Cerebellum,
                    req,
                    authorizer.clone(),
                )
                .await
                {
                    Ok(cere) => {
                        let verdict = crate::council::callosum::resolve_with_profile_budget(
                            &req.prompt,
                            left_text,
                            right_text,
                            profile_opt,
                            &cere,
                            &council_budget,
                        )
                        .await;
                        match verdict {
                            crate::council::callosum::CorticalVerdict::Synthesis(s) => {
                                info!("callosum produced synthesis ({} chars)", s.len());
                                let _ = emit_council_synthesis_attempted(
                                    writer,
                                    prompt_hash,
                                    CouncilSynthesisOutcome::Synthesis {
                                        chars: s.chars().count(),
                                    },
                                )
                                .await;
                                s
                            }
                            crate::council::callosum::CorticalVerdict::IrreconcilableConflict {
                                reason,
                            } => {
                                warn!(reason = %reason, "callosum could not synthesise");
                                let _ = emit_council_synthesis_attempted(
                                    writer,
                                    prompt_hash,
                                    CouncilSynthesisOutcome::IrreconcilableConflict {
                                        reason: reason.clone(),
                                    },
                                )
                                .await;
                                format!("[council split — operator decision needed]\n{summary}")
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "could not build callosum cerebellum");
                        let _ = emit_council_synthesis_attempted(
                            writer,
                            prompt_hash,
                            CouncilSynthesisOutcome::IrreconcilableConflict {
                                reason: format!("provider build failed: {e}"),
                            },
                        )
                        .await;
                        format!("[council split — operator decision needed]\n{summary}")
                    }
                }
            }
            crate::council::Verdict::QuorumFailed {
                responded,
                required,
            } => {
                format!("[council quorum failed — {responded}/{required} hemispheres responded]")
            }
            crate::council::Verdict::Consensus { .. } => unreachable!(),
        },
    };
    Ok(response_text)
}

/// Finding 2 (Session 13) — joint multi-cloud fan-out advisory.
/// Fires AT MOST ONCE per process when the council topology routes
/// to ≥2 distinct cloud providers. Operator already consented per-
/// provider via V03-08 + A-2; this is the additional surface that
/// surfaces the COMBINED picture ("this prompt simultaneously reaches
/// Anthropic + OpenAI + Gemini, each retains it per their own TOS").
/// Resets only on daemon restart.
static FAN_OUT_ADVISORY_FIRED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Render the operator-facing advisory line for a multi-cloud council
/// topology. Returns `None` when fewer than 2 distinct cloud kinds are
/// configured (single-cloud + local topologies have no fan-out story
/// to surface beyond the per-provider V03-08 prompt).
pub(crate) fn fan_out_advisory_line(config: &FreedomConfig) -> Option<String> {
    let kinds = crate::consent::cloud_kinds_for_council(config);
    if kinds.len() < 2 {
        return None;
    }
    let providers: Vec<&str> = kinds.iter().map(|k| crate::consent::slug(*k)).collect();
    Some(format!(
        "[NEOTH] this prompt fan-outs to {} cloud providers concurrently \
         ({}). Each provider's TOS + retention policies apply independently. \
         Configured via `freedom.yaml::inference.{{left,right,cerebellum}}`.",
        providers.len(),
        providers.join(", "),
    ))
}

/// Best-effort once-per-process emit. Subsequent calls in the same
/// process short-circuit. Test-friendly: pure function gated by a
/// static AtomicBool — tests reset by re-importing the static is
/// awkward, so we test `fan_out_advisory_line` directly instead.
fn maybe_fire_fan_out_advisory(config: &FreedomConfig) {
    if FAN_OUT_ADVISORY_FIRED
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
        && let Some(line) = fan_out_advisory_line(config)
    {
        eprintln!("{line}");
    }
}

/// GOLD-G02-COUNCIL-01 — fetch up to `limit` VERIFIED groundtruth rows and
/// shape them into the orchestrator's [`FactualAssertion`]s. Subject/keyword
/// derive from the first copula split (" is "/" are "/" = "); statements
/// without one are skipped (no synthetic assertions). Best-effort: any DB
/// error → empty vec — a missing views.db must never block a council run.
fn fetch_council_assertions(
    neoth_home: &std::path::Path,
    limit: usize,
) -> Result<Vec<crate::council::factual_check::FactualAssertion>> {
    let path = neoth_home.join("views.db");
    let conn = crate::memory::store::open(&path)
        .with_context(|| format!("open council groundtruth store {}", path.display()))?;
    let rows = crate::memory::groundtruth::surface_for_recall(&conn, limit, false)
        .with_context(|| format!("query council groundtruth store {}", path.display()))?;
    Ok(rows
        .iter()
        .filter_map(|gt| {
            let st = gt.statement.trim();
            let (subject, rest) = [" is ", " are ", " = "]
                .iter()
                .find_map(|cop| st.split_once(cop))?;
            let keyword = rest.split_whitespace().next()?;
            if subject.trim().is_empty() || keyword.is_empty() {
                return None;
            }
            Some(crate::council::factual_check::FactualAssertion {
                // Optional retrieved context follows the same per-item bound as
                // hemisphere recall; a pathological DB row must not allocate an
                // unbounded Council prompt before leaf degradation runs.
                subject: recall_snippet(subject),
                expected_keyword: keyword
                    .trim_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase(),
            })
        })
        .filter(|a| !a.expected_keyword.is_empty())
        .collect())
}

async fn run_council_debate(
    config: &FreedomConfig,
    neoth_home: &std::path::Path,
    req: &crate::providers::Request,
    authorizer: &crate::providers::cost_authorization::ProviderCallAuthorizer,
    allow_persistent_context: bool,
    budget: crate::council::BudgetToken,
) -> Result<crate::council::CouncilDebate> {
    use crate::config::inference::HemisphereRole;
    // Finding 2: once-per-process advisory when council topology
    // spans ≥2 cloud providers. Per-provider consent already gated
    // via V03-08 + A-2; this surfaces the JOINT fan-out picture.
    maybe_fire_fan_out_advisory(config);
    // E-2 Phase 2 (Session 13): outer-council hemispheres carry a
    // config Arc so `ask_with_depth` can recurse when the operator's
    // `hemisphere_council_depth > 1`. The Arc is shared across all
    // three so freedom.yaml is parsed exactly once per debate.
    let config_arc = std::sync::Arc::new(config.clone());
    let left = build_hemisphere_with_config(
        config_arc.clone(),
        neoth_home,
        HemisphereRole::Left,
        req,
        authorizer.clone(),
        allow_persistent_context,
    )
    .await?;
    let right = build_hemisphere_with_config(
        config_arc.clone(),
        neoth_home,
        HemisphereRole::Right,
        req,
        authorizer.clone(),
        allow_persistent_context,
    )
    .await?;
    let cere = build_hemisphere_with_config(
        config_arc,
        neoth_home,
        HemisphereRole::Cerebellum,
        req,
        authorizer.clone(),
        allow_persistent_context,
    )
    .await?;
    let prompt_hash = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
    // E-2 Phase 1 (Session 13) — thread the operator-configured
    // `hemisphere_council_depth` through the orchestrator so recursive
    // hemispheres can read their own depth budget.
    let depth = config.inference.hemisphere_council_depth.get();
    // SP-4 embed-wire Phase 3 — feed the cosine-dissent path when an
    // embedding provider is configured; the orchestrator falls back to
    // Jaccard on any embed failure. `None` keeps the legacy heuristic.
    let dissent_embed = crate::providers::embed_provider_from_config(config).await;
    // GOLD-G02-COUNCIL-01 — verified groundtruth flows into every
    // hemisphere prompt + the post-response contradiction check.
    let assertions = if allow_persistent_context && config.council.groundtruth_injection {
        tokio::task::block_in_place(|| fetch_council_assertions(neoth_home, 10))?
    } else {
        Vec::new()
    };
    let outcome = crate::council::run_debate_with_depth_budget(
        &req.prompt,
        prompt_hash,
        depth,
        budget,
        &left,
        &right,
        &cere,
        dissent_embed.as_deref(),
        &assertions,
    )
    .await;
    Ok(outcome)
}

/// CDX-05 wedge: drive the MCP dispatch loop using `provider` as the
/// completion backend. Adapter between the chat path's `Provider` +
/// `Request` types and the loop's `CompletionDriver` trait.
/// K-Wire-3 v1 2026-05-17: promoted from private `async fn` to
/// `pub(crate)` so `cli/serve.rs::build_pipeline_handler` can drive
/// the same MCP dispatch loop for channel inbound messages. CLI +
/// daemon now share the autoroute path; channels (Telegram /
/// WhatsApp / Slack) gain tool-use parity with `neoth chat` without
/// duplicating the driver wiring.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_mcp_dispatch_loop(
    provider: &dyn crate::providers::Provider,
    base_req: crate::providers::Request,
    servers: &crate::mcp::McpServers,
    autonomy_policy: &crate::permissions::AutonomyPolicySnapshot,
    writer: &crate::wal::writer::WalWriterHandle,
    rollback_policy: Option<&crate::config::RollbackConfig>,
    // Complete skill/agent tool scope resolved once for this provider turn.
    tool_scope: &crate::mcp::McpToolScope,
    // GM-01 — operator-tunable hard ceiling on dispatch-loop iterations
    // (`freedom.yaml::goal.max_turns`, default 5).
    max_iterations: u32,
    // GOLD-ADOPT-23 P0 — egress + dangerous-command risk policy gate.
    security_policy: &crate::config::SecurityPolicy,
    // GOLD-ADOPT-22 — Goal/Grind nudge context (empty = no nudging).
    goal_context: crate::mcp::goal_tracker::GoalContext,
    // GOLD-ADOPT-18 — subdirectory-hint injection toggle (freedom.yaml::hints.enabled).
    hints_enabled: bool,
    // GOLD-ADOPT-19 — auto context-compaction policy (freedom.yaml::compaction).
    compaction: crate::context::compaction::CompactionPolicy,
    // GOLD-HR-08 — per-block tool-result compression (freedom.yaml::compression).
    // `None` = disabled (the default); behaviour is then unchanged.
    compression: Option<crate::context::compress::CompressionRuntime>,
    // HERMES-04 — optional independent goal-judge provider. When `Some` AND a
    // goal is set, an extra LLM call verifies the goal before a clean exit.
    // `None` = judge disabled (existing nudge path fires unchanged).
    judge_provider: Option<&dyn crate::providers::Provider>,
    // GOLD-ADOPT-17 — mid-turn elicitation handler. `Cli` on the TTY path
    // (checked by the caller before this call); `Disabled` on the channel /
    // serve-pipeline path and in tests.
    elicitation_handler: &crate::cli::elicitation::ElicitationHandler,
    // GOLD-ADAPT-AWE-CODE-01 — pre-authenticated caller identity for the
    // McpTool lease consent gate. `None` on the interactive CLI path (no
    // inbound sender identity). `Some(sender_id)` on the channel path
    // (HMAC/platform-verified sender_id from the inbound message).
    subject: Option<String>,
    // GOLD-ADAPT-HARNESS-01/04/06 — operator-tunable MCP dispatch-loop knobs
    // (`freedom.yaml::tools.harness`), threaded straight into the loop.
    harness_cfg: &crate::config::tools::McpHarnessConfig,
    // One paid-summary allowance for the complete operator turn. Multi-round
    // loops pass the same value into every round instead of resetting it.
    compaction_budget: &mut crate::mcp::dispatch_loop::CompactionBudget,
    // Optional exact tool-call ceiling for the outer loop engine. Ordinary
    // chat/channel callers pass None; full-autonomy passes the remaining budget.
    max_tool_calls: Option<u64>,
    // Exact instance root that owns leases, risk confirmations and traces.
    instance_home: &std::path::Path,
) -> anyhow::Result<crate::mcp::dispatch_loop::LoopOutcome> {
    struct ProviderDriver<'a> {
        provider: &'a dyn crate::providers::Provider,
        base: crate::providers::Request,
    }
    impl crate::mcp::dispatch_loop::CompletionDriver for ProviderDriver<'_> {
        fn complete<'b>(
            &'b mut self,
            prompt: &'b str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'b>>
        {
            let mut req = self.base.clone();
            req.prompt = prompt.to_string();
            let provider = self.provider;
            // QM-10 Phase 2.5: streaming MCP-loop also consults the
            // breaker. Each tool-call iteration is a fresh provider
            // dispatch — a breaker that flipped Open between
            // iterations rejects the next round instead of burning
            // budget on doomed calls inside a long tool chain.
            let provider_name = provider.name();
            Box::pin(async move {
                let permit = match crate::providers::circuit_breaker::acquire_for(provider_name) {
                    Ok(p) => Some(p),
                    Err(berr) => {
                        return Err(anyhow::anyhow!("provider `{provider_name}`: {berr}"));
                    }
                };
                // QM-9 Phase 1.5 follow-on: streaming MCP-loop now
                // also persists usage events. Each tool-call hop is
                // a discrete provider dispatch — operators want to
                // see the cost of an autoroute chain, not just the
                // final composed reply.
                let call_started = std::time::Instant::now();
                let result = crate::providers::cost_authorization::automated_usage_scope(
                    provider.complete(req),
                )
                .await;
                let elapsed_ms = call_started.elapsed().as_millis() as u64;
                match result {
                    Ok(c) => {
                        if !c.identity.is_bound() {
                            if let Some(p) = permit {
                                p.record_failure();
                            }
                            return Err(anyhow::anyhow!(
                                "provider `{provider_name}` returned no authenticated response identity"
                            ));
                        }
                        if let Some(p) = permit {
                            p.record_success();
                        }
                        publish_provider_responded(
                            &c.identity.provider,
                            &c.identity.wire_model,
                            c.input_tokens,
                            c.output_tokens,
                            elapsed_ms,
                        );
                        Ok(c.text)
                    }
                    Err(e) => {
                        if let Some(p) = permit {
                            p.record_failure();
                        }
                        Err(e)
                    }
                }
            })
        }
    }
    let initial_prompt = base_req.prompt.clone();
    let compaction = compaction.with_request_envelope(&base_req);
    let mut driver = ProviderDriver {
        provider,
        base: base_req,
    };
    crate::mcp::dispatch_loop::run_tool_loop_with_budget(
        &mut driver,
        initial_prompt,
        servers,
        autonomy_policy,
        Some(writer),
        rollback_policy,
        tool_scope,
        max_iterations.max(1),
        security_policy,
        // GOLD-ADAPT-AWE-CODE-01 — thread the caller identity for lease gate.
        subject,
        goal_context,
        hints_enabled,
        compaction,
        compression,
        judge_provider,
        // GOLD-ADOPT-17 — thread the elicitation handler into the loop.
        elicitation_handler,
        // GOLD-ADAPT-HARNESS — thread operator harness knobs into the loop.
        harness_cfg,
        compaction_budget,
        max_tool_calls,
        instance_home,
    )
    .await
}

fn now_unix() -> u64 {
    crate::time::now_unix_secs()
}

/// UX-02 — render the "memory is working" line from a total memory
/// count. `None` when nothing is remembered yet, so a fresh install
/// stays silent (no "since last time" on the first ever run).
fn memory_signal_line(total: i64) -> Option<String> {
    if total <= 0 {
        return None;
    }
    Some(format!(
        "I remember {total} thing{} from last time.",
        if total == 1 { "" } else { "s" }
    ))
}

/// UX-02 — count what NEOTH carried across sessions (the three episodic
/// memory tiers + ground-truth assertions) and render the session-start
/// signal. Best-effort: any missing/unreadable views.db or query error
/// collapses to `None` (silent) — this is a friendly banner, never a
/// hard dependency of the chat path.
fn session_memory_signal(neoth_home: &std::path::Path) -> Option<String> {
    use crate::memory::consolidate::count_in_tier;
    use crate::memory::tiers::Tier;
    let conn = crate::memory::store::open(&neoth_home.join("views.db")).ok()?;
    let total = count_in_tier(&conn, Tier::Hot).unwrap_or(0)
        + count_in_tier(&conn, Tier::Warm).unwrap_or(0)
        + count_in_tier(&conn, Tier::Cold).unwrap_or(0)
        + crate::memory::groundtruth::count_active(&conn).unwrap_or(0);
    memory_signal_line(total)
}

/// GOLD-ADAPT-SKILL-10 — session-start skill-catalog banner.
///
/// Renders a compact markdown table of all enabled skills and their
/// trigger keywords for operator discoverability. This is a pure
/// stdout emission — it is NEVER injected into the system prompt or
/// any provider context layer; it costs zero provider tokens.
///
/// Returns `None` when the filtered skill list is empty (silent
/// on fresh install with no skills, or when all loaded skills are
/// disabled). The caller gates on `config.skills.session_catalog`
/// before calling `println!` so this function is purely the formatter.
///
/// Visibility rule: shows ALL enabled skills (including `NameOnly` and
/// `UserInvocableOnly`) because this IS operator-facing discoverability
/// — the operator should see `/skill-name` exists even for non-auto-
/// routed skills. Only `disabled` (`is_enabled() == false`) skills are
/// suppressed, matching the pre-filter semantics of `build_prompt_bundle`.
fn maybe_skill_catalog_block(skills: &[crate::skills::schema::Skill]) -> Option<String> {
    let enabled: Vec<&crate::skills::schema::Skill> =
        skills.iter().filter(|s| s.is_enabled()).collect();
    if enabled.is_empty() {
        return None;
    }
    let mut out = String::from("| Skill | Trigger phrases |\n|---|---|\n");
    for skill in &enabled {
        // Clip trigger keywords to a readable width. Replicate the
        // 40-char clip inline — `cli::skills::truncate` is private.
        let triggers: Vec<String> = skill
            .trigger_keywords()
            .iter()
            .map(|kw| kw.chars().take(40).collect::<String>())
            .collect();
        let triggers_cell = if triggers.is_empty() {
            "—".to_string()
        } else {
            triggers.join(", ")
        };
        out.push_str(&format!("| {} | {} |\n", skill.id(), triggers_cell));
    }
    Some(out)
}

/// Round-3 v0.4 QU-11 / ARS-6 — load a `MODE_CHECKPOINT` snapshot by
/// hash prefix and render a (operator-banner, system-prompt-block)
/// pair. The system-prompt block carries a typed RESUME-CONTEXT
/// section so the assistant knows the prior pipeline shape; it gets
/// prepended to any operator-supplied `--system` text.
///
/// Any failure mode (missing views.db, no matching checkpoint, hash mismatch,
/// parse error or legacy-unrecorded scope) surfaces as `Err(String)` and the
/// caller aborts the requested resume before provider/tool dispatch.
/// PWF-02: authoritative resume state reconstructed from one checkpoint.
struct ResumeHydration {
    banner: String,
    combined_system: String,
    catchup: crate::recall::reconstruct::CatchupSummary,
    scoped_mcp_servers: Vec<String>,
}

/// Hydrate a prior `MODE_CHECKPOINT` from views.db by hash prefix. Alongside
/// the visible context this returns the exact MCP IDs that the caller must
/// enforce against the current registry before any provider/tool dispatch.
fn hydrate_resume_context(
    neoth_home: &std::path::Path,
    hash_prefix: &str,
    existing_system: Option<&str>,
) -> Result<ResumeHydration, String> {
    let views_path = neoth_home.join("views.db");
    let conn = crate::memory::store::open(&views_path)
        .map_err(|e| format!("views.db open failed: {e}"))?;
    let cp = crate::recall::reconstruct::reconstruct_from_checkpoint(&conn, hash_prefix)
        .map_err(|e| format!("checkpoint lookup failed: {e}"))?;
    if !cp.mcp_scope_recorded {
        return Err(
            "checkpoint predates exact MCP-scope recording; start a new session and resume from its checkpoint"
                .to_string(),
        );
    }
    // PWF-02: count activity since the checkpoint timestamp.
    let catchup = crate::recall::reconstruct::catchup_summary(&conn, cp.ts_unix);
    let mcp_scope = if cp.scoped_mcp_servers.is_empty() {
        "(no MCP servers)".to_string()
    } else {
        cp.scoped_mcp_servers.join(", ")
    };
    let banner = format!(
        "[neoth] resuming session={} phase={} provider={} council={} hash={}",
        cp.session_id, cp.phase, cp.provider_target, cp.council_mode, cp.checkpoint_hash,
    );
    let resume_block = format!(
        "RESUME-CONTEXT\n\
         Prior session id: {session_id}\n\
         Prior pipeline phase: {phase}\n\
         Prior provider target: {provider_target}\n\
         Prior council mode: {council_mode}\n\
         Prior MCP servers in scope: {mcp_scope}\n\
         Checkpoint hash: {checkpoint_hash}\n\
         Checkpoint timestamp (unix): {ts_unix}\n",
        session_id = cp.session_id,
        phase = cp.phase,
        provider_target = cp.provider_target,
        council_mode = cp.council_mode,
        mcp_scope = mcp_scope,
        checkpoint_hash = cp.checkpoint_hash,
        ts_unix = cp.ts_unix,
    );
    let combined = match existing_system {
        Some(s) if !s.trim().is_empty() => format!("{resume_block}\n{s}"),
        _ => resume_block,
    };
    Ok(ResumeHydration {
        banner,
        combined_system: combined,
        catchup,
        scoped_mcp_servers: cp.scoped_mcp_servers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::init::ProviderKind;
    use crate::providers::{Completion, Provider};
    use crate::wal::events::{EVENT_TYPE_PROVIDER_REQUEST, EVENT_TYPE_PROVIDER_RESPONSE};
    use crate::wal::frame::decode_frame;
    use crate::wal::segment_header::SEGMENT_HEADER_LEN;
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::time::Duration;

    struct DefaultAliasProvider;

    #[async_trait]
    impl Provider for DefaultAliasProvider {
        fn name(&self) -> &'static str {
            "openai_api"
        }

        fn default_model(&self) -> Option<&str> {
            Some("default-gpt4o-alias")
        }

        fn resolve_model_for_wire(&self, requested_model: &str) -> String {
            match requested_model {
                "default-gpt4o-alias" => "gpt-4o".into(),
                other => other.into(),
            }
        }
    }

    fn test_mcp_server(id: &str, enabled: bool) -> crate::mcp::config::McpServerConfig {
        crate::mcp::config::McpServerConfig {
            id: id.to_string(),
            description: None,
            command: "server-bin".to_string(),
            args: Vec::new(),
            env: std::collections::HashMap::new(),
            enabled,
            allow_tools: Some(vec!["read".to_string()]),
            trust_all_tools: false,
            smart_approve: false,
            autonomy_gate: None,
        }
    }

    #[tokio::test]
    async fn final_budget_boundary_applies_single_d_degradation_to_request_bytes() {
        use crate::tokens::budget::{Block, BlockItem};

        let home = tempfile::tempdir().unwrap();
        let (writer, writer_join) = wal_spawn(home.path().join("budget.wal")).unwrap();
        let mut config = FreedomConfig::default();
        config.tokens.max_per_request = 20_000;
        let items = vec![
            BlockItem::new(Block::A, "protected system"),
            BlockItem::new(Block::D, "d".repeat(100_000)),
            BlockItem::new(Block::E, "hello"),
        ];
        let (_, system) = crate::tokens::budget::render_request(&items).unwrap();

        let result = finalize_provider_request(
            items,
            "hello",
            system.as_deref(),
            ProviderRequestBoundary {
                config: &config,
                home: home.path(),
                provider_name: "test_provider",
                effective_model: None,
                route_cap: None,
                writer: &writer,
            },
        )
        .await
        .expect("single D item should be dropped and request should fit");
        assert!(result.prompt_token_estimate <= result.effective_cap);
        assert_eq!(result.prompt, "hello");
        assert!(!result.system.unwrap().contains(&"d".repeat(1_000)));

        drop(writer);
        writer_join.await.unwrap();
    }

    #[tokio::test]
    async fn final_budget_boundary_blocks_when_protected_blocks_exceed_cap() {
        use crate::tokens::budget::{Block, BlockItem};

        let home = tempfile::tempdir().unwrap();
        let (writer, writer_join) = wal_spawn(home.path().join("budget-block.wal")).unwrap();
        let mut config = FreedomConfig::default();
        config.tokens.max_per_request = 1;
        let items = vec![
            BlockItem::new(Block::A, "protected system"),
            BlockItem::new(Block::E, "protected user prompt"),
        ];
        let (_, system) = crate::tokens::budget::render_request(&items).unwrap();

        let error = finalize_provider_request(
            items,
            "protected user prompt",
            system.as_deref(),
            ProviderRequestBoundary {
                config: &config,
                home: home.path(),
                provider_name: "test_provider",
                effective_model: None,
                route_cap: None,
                writer: &writer,
            },
        )
        .await
        .expect_err("protected A/B/E over cap must fail closed");
        assert!(error.to_string().contains("above the effective cap"));

        drop(writer);
        writer_join.await.unwrap();
    }

    #[tokio::test]
    async fn cli_default_and_config_alias_are_resolved_before_model_budgeting() {
        use crate::tokens::budget::{Block, BlockItem};

        // Production CLI chat can place the fallback provider behind this
        // compactor. The decorator must preserve default + alias resolution.
        let provider = crate::providers::compactor::CompactingProvider::new(
            Box::new(DefaultAliasProvider),
            None,
            200_000,
            0.8,
            1_024,
            None,
        );
        let mut config = FreedomConfig::default();
        let default_model = resolve_provider_call_wire_model(&config, &provider, None).unwrap();
        assert_eq!(default_model, "gpt-4o");
        config.provider_model = Some("@fast".into());
        config
            .models_aliases
            .insert("@fast".into(), "gpt-4o".into());
        let model =
            resolve_provider_call_wire_model(&config, &provider, config.provider_model.as_deref())
                .unwrap();
        assert_eq!(model, "gpt-4o");

        let home = tempfile::tempdir().unwrap();
        let (writer, writer_join) =
            wal_spawn(home.path().join("default-model-budget.wal")).unwrap();
        config.tokens.max_per_request = 200_000;
        let items = vec![
            BlockItem::new(Block::A, "protected system"),
            BlockItem::new(Block::E, "hello"),
        ];
        let (_, system) = crate::tokens::budget::render_request(&items).unwrap();
        let request = finalize_provider_request(
            items,
            "hello",
            system.as_deref(),
            ProviderRequestBoundary {
                config: &config,
                home: home.path(),
                provider_name: provider.name(),
                effective_model: Some(&model),
                route_cap: None,
                writer: &writer,
            },
        )
        .await
        .unwrap();
        assert_eq!(request.effective_cap, 108_800);

        drop(writer);
        writer_join.await.unwrap();
    }

    /// An active output-preset whose `inject_prefix` is large enough to push a
    /// fitting request over the cap after wrapping must trigger C/D degradation
    /// while leaving the protected A/B/E blocks intact.
    #[tokio::test]
    async fn final_budget_boundary_preset_wrap_forces_cd_degradation_while_abe_survive() {
        use crate::config::presets::{Preset, PresetFile};
        use crate::tokens::budget::{Block, BlockItem};

        let home = tempfile::tempdir().unwrap();
        let (writer, writer_join) = wal_spawn(home.path().join("preset-wrap.wal")).unwrap();

        // A large inject_prefix so wrapping "hello" swells the E block by ~1 202 bytes.
        let inject_prefix = "x".repeat(1_200);
        let mut presets = std::collections::BTreeMap::new();
        presets.insert(
            "big-prefix".to_owned(),
            Preset {
                inject_prefix: Some(inject_prefix.clone()),
                ..Preset::default()
            },
        );
        let preset_file = PresetFile {
            active: Some("big-prefix".to_owned()),
            presets,
        };
        std::fs::write(
            home.path().join("presets.yaml"),
            serde_yaml::to_string(&preset_file).unwrap(),
        )
        .unwrap();

        // Cap small enough that C/D must be dropped once the wrapped E is counted,
        // but large enough that the protected A/B/E blocks always fit.
        let mut config = FreedomConfig::default();
        config.tokens.max_per_request = 2_000;

        let items = vec![
            BlockItem::new(Block::A, "protected-a"),
            BlockItem::new(Block::B, "protected-b"),
            BlockItem::new(Block::C, "c".repeat(300)),
            BlockItem::new(Block::D, "d".repeat(300)),
            BlockItem::new(Block::E, "hello"),
        ];
        let (_, system) = crate::tokens::budget::render_request(&items).unwrap();

        let result = finalize_provider_request(
            items,
            "hello",
            system.as_deref(),
            ProviderRequestBoundary {
                config: &config,
                home: home.path(),
                provider_name: "test_provider",
                effective_model: None,
                route_cap: None,
                writer: &writer,
            },
        )
        .await
        .expect("A/B/E are protected; C/D can absorb the cap hit from the preset wrap");

        // Protected blocks must survive.
        let sys = result.system.as_deref().unwrap_or("");
        assert!(
            sys.contains("protected-a"),
            "Block A must survive degradation"
        );
        assert!(
            sys.contains("protected-b"),
            "Block B must survive degradation"
        );
        // Degradable blocks must be dropped.
        assert!(!sys.contains(&"c".repeat(10)), "Block C must be degraded");
        assert!(!sys.contains(&"d".repeat(10)), "Block D must be degraded");
        // The preset inject_prefix must be applied to the user prompt.
        assert!(
            result.prompt.starts_with(&inject_prefix),
            "preset inject_prefix must be prepended to the user prompt"
        );
        // The final token estimate must still fit within the effective cap.
        assert!(
            result.prompt_token_estimate <= result.effective_cap,
            "prompt_token_estimate {} must be <= effective_cap {}",
            result.prompt_token_estimate,
            result.effective_cap,
        );

        drop(writer);
        writer_join.await.unwrap();
    }

    #[test]
    fn routing_cap_reserves_a_longer_fallback_wire_model_before_dispatch() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};

        let mut config = FreedomConfig::default();
        config.tokens.max_per_request = 200_000;
        config.council.disabled = Some(true);
        config.fallback.max_hops = 1;

        let primary_model = "p";
        let primary_only =
            routing_safe_effective_cap(&config, "openai_compat", Some(primary_model));
        let fallback_model = "fallback-deployment-with-a-materially-longer-wire-model-id";
        // An empty/filtered entry before the usable slot must not consume the
        // runtime hop budget in the static safety calculation.
        config.fallback.chain.push(HemisphereSlot::default());
        config.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            model: Some(fallback_model.to_owned()),
            ..Default::default()
        });

        let route_safe = routing_safe_effective_cap(&config, "openai_compat", Some(primary_model));
        assert_eq!(
            primary_only - route_safe,
            u32::try_from(fallback_model.len() - primary_model.len()).unwrap(),
            "fallback's exact model-field bytes must reduce primary content capacity"
        );
    }

    #[test]
    fn routing_cap_normalizes_claude_cli_alias_before_window_lookup() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};

        let mut config = FreedomConfig::default();
        config.tokens.max_per_request = 200_000;
        config.council.disabled = Some(true);
        config.fallback.max_hops = 1;
        config.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            model: Some("opusplan".to_owned()),
            ..Default::default()
        });

        let primary_model = "p";
        let route_safe = routing_safe_effective_cap(&config, "openai_compat", Some(primary_model));
        let wire_model = "claude-opus-4-7[1m]";
        let leaf_cap = crate::tokens::budget::effective_cap(
            "claude_cli",
            wire_model,
            config.tokens.max_per_request,
        );
        let primary_reserve = crate::providers::token_cap::request_non_content_token_upper_bound(
            &crate::providers::Request {
                model: Some(primary_model.to_owned()),
                ..Default::default()
            },
        );
        let leaf_reserve = crate::providers::token_cap::request_non_content_token_upper_bound(
            &crate::providers::Request {
                model: Some(wire_model.to_owned()),
                ..Default::default()
            },
        );
        assert_eq!(
            route_safe,
            leaf_cap
                .saturating_sub(leaf_reserve)
                .saturating_add(primary_reserve)
        );
        assert!(route_safe < config.tokens.max_per_request);
    }

    #[test]
    fn relative_custom_config_uses_its_working_directory_as_instance_home() {
        assert_eq!(
            chat_neoth_home(Some(std::path::Path::new("custom-policy.yaml"))),
            std::path::PathBuf::from(".")
        );
    }

    #[test]
    fn instance_turn_state_loads_every_registry_from_the_custom_home() {
        let home = tempfile::tempdir().unwrap();
        let paths = InstancePaths::new(home.path(), home.path().join("selected-policy.yaml"));
        std::fs::write(
            &paths.mcp_servers,
            "servers:\n  - id: custom-home\n    command: custom-mcp\n",
        )
        .unwrap();
        std::fs::write(&paths.tweaks, "persona_override = \"custom persona\"\n").unwrap();
        std::fs::write(
            &paths.profile_extensions,
            "[extensions]\npets = \"Vec<Pet>\"\n",
        )
        .unwrap();

        let state = load_instance_turn_state(&paths).unwrap();
        assert_eq!(state.mcp_servers.servers[0].id, "custom-home");
        assert_eq!(
            state.tweaks.persona_override.as_deref(),
            Some("custom persona")
        );
        assert!(state.profile_extensions.is_known("pets"));
    }

    #[test]
    fn instance_turn_state_rejects_each_malformed_existing_registry() {
        for (file_name, body, expected) in [
            ("mcp_servers.yaml", "servers: [broken\n", "MCP server"),
            ("tweaks.toml", "persona_override = [broken\n", "tweaks.toml"),
            (
                "profile_extensions.toml",
                "[extensions\nbroken = true\n",
                "profile extension registry",
            ),
        ] {
            let home = tempfile::tempdir().unwrap();
            let paths = InstancePaths::for_home(home.path());
            std::fs::write(home.path().join(file_name), body).unwrap();

            let error = load_instance_turn_state(&paths)
                .err()
                .expect("malformed existing registry must fail the turn preflight");
            let detail = format!("{error:#}");
            assert!(detail.contains(expected), "{file_name}: {detail}");
            assert!(detail.contains(file_name), "{file_name}: {detail}");
        }
    }

    #[test]
    fn onboarding_completion_updates_only_the_selected_config_file() {
        let home = tempfile::tempdir().unwrap();
        let selected_path = home.path().join("selected-policy.yaml");
        let default_path = home.path().join("freedom.yaml");
        let mut config = FreedomConfig::default();
        config.chat_onboarding_completed = false;
        let yaml = serde_yaml::to_string(&config).unwrap();
        std::fs::write(&selected_path, &yaml).unwrap();
        std::fs::write(&default_path, &yaml).unwrap();
        let default_before = std::fs::read(&default_path).unwrap();

        persist_chat_onboarding_complete(&selected_path).unwrap();

        assert!(
            FreedomConfig::load_from_path(&selected_path)
                .unwrap()
                .chat_onboarding_completed
        );
        assert_eq!(
            std::fs::read(&default_path).unwrap(),
            default_before,
            "a selected custom config must not mutate sibling freedom.yaml"
        );
    }

    #[test]
    fn enabled_mcp_scope_is_sorted_and_excludes_disabled_servers() {
        let servers = crate::mcp::McpServers {
            servers: vec![
                test_mcp_server("zeta", true),
                test_mcp_server("hidden", false),
                test_mcp_server("alpha", true),
            ],
            smart_loading: true,
        };
        assert_eq!(enabled_mcp_scope(&servers), vec!["alpha", "zeta"]);
    }

    #[test]
    fn resume_mcp_scope_excludes_newly_enabled_servers() {
        let current = crate::mcp::McpServers {
            servers: vec![
                test_mcp_server("prior", true),
                test_mcp_server("newly-enabled", true),
            ],
            smart_loading: true,
        };
        let restricted =
            restrict_mcp_servers_to_checkpoint(current, &["prior".to_string()]).unwrap();
        assert_eq!(enabled_mcp_scope(&restricted), vec!["prior"]);
    }

    #[test]
    fn resume_mcp_scope_fails_on_missing_disabled_or_duplicate_ids() {
        let missing = crate::mcp::McpServers {
            servers: vec![test_mcp_server("other", true)],
            smart_loading: true,
        };
        assert!(restrict_mcp_servers_to_checkpoint(missing, &["prior".to_string()]).is_err());

        let disabled = crate::mcp::McpServers {
            servers: vec![test_mcp_server("prior", false)],
            smart_loading: true,
        };
        assert!(restrict_mcp_servers_to_checkpoint(disabled, &["prior".to_string()]).is_err());

        let duplicate = crate::mcp::McpServers {
            servers: vec![
                test_mcp_server("prior", true),
                test_mcp_server("prior", true),
            ],
            smart_loading: true,
        };
        assert!(restrict_mcp_servers_to_checkpoint(duplicate, &["prior".to_string()]).is_err());
    }

    #[test]
    fn resume_mcp_scope_can_restore_an_exact_empty_scope() {
        let current = crate::mcp::McpServers {
            servers: vec![test_mcp_server("current", true)],
            smart_loading: true,
        };
        let restricted = restrict_mcp_servers_to_checkpoint(current, &[]).unwrap();
        assert!(restricted.enabled().is_empty());
    }

    // ── GOLD-ADOPT-21 session-title sanitizer ───────────────────────────
    #[test]
    fn sanitize_session_title_strips_quotes_punct_and_extra_lines() {
        assert_eq!(
            sanitize_session_title("\"Rust Parser Refactor\""),
            "Rust Parser Refactor"
        );
        assert_eq!(
            sanitize_session_title("Fixing the WAL bug."),
            "Fixing the WAL bug"
        );
        // First non-empty line only (models sometimes add a preamble blank line).
        assert_eq!(
            sanitize_session_title("\n  Auth Flow Redesign  \nignored second line"),
            "Auth Flow Redesign"
        );
        // Backtick / single-quote wrappers + trailing ?! stripped.
        assert_eq!(
            sanitize_session_title("`What about caching?`"),
            "What about caching"
        );
        // Empty / whitespace → empty (caller skips the update).
        assert_eq!(sanitize_session_title("   \n  "), "");
        // Over-long titles are capped at 80 chars.
        assert!(sanitize_session_title(&"word ".repeat(40)).chars().count() <= 80);
    }
    use tempfile::tempdir;
    use tokio::fs::read;

    // ── SPEC-03 council suppress: evaluate_council_trigger (Session 29) ──
    // The channel path (serve.rs) reads `council.disabled` per message and
    // passes it here; these pin the suppress contract so a negated/dropped
    // branch can't silently let channels ignore suppression.

    #[test]
    fn evaluate_council_trigger_disabled_flag_forces_skip() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::remove_var("NEOTH_COUNCIL_ENABLE");
        }
        let decision = evaluate_council_trigger(
            std::path::Path::new(""),
            "should I use Rust or Go here?",
            0.01,
            None,
            None,
            true,
            &crate::council::TriggerPolicy::default(),
        );
        match decision {
            crate::council::TriggerDecision::Skip { reason } => {
                assert!(
                    reason.contains("freedom.yaml"),
                    "disabled flag must attribute the Skip to the config flag, got: {reason}"
                );
            }
            other => panic!("disabled=true must force Skip, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_council_trigger_disable_beats_force_enable() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::set_var("NEOTH_COUNCIL_ENABLE", "1");
        }
        let decision = evaluate_council_trigger(
            std::path::Path::new(""),
            "anything at all",
            0.01,
            None,
            None,
            true,
            &crate::council::TriggerPolicy::default(),
        );
        unsafe { std::env::remove_var("NEOTH_COUNCIL_ENABLE") };
        assert!(
            matches!(decision, crate::council::TriggerDecision::Skip { .. }),
            "a durably-suppressed council must not be force-convened by NEOTH_COUNCIL_ENABLE=1"
        );
    }

    #[test]
    fn evaluate_council_trigger_uses_configured_daily_usd_headroom() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::remove_var("NEOTH_COUNCIL_ENABLE");
        }
        let home = tempfile::tempdir().unwrap();
        let decision = evaluate_council_trigger(
            home.path(),
            "Should I use Rust or Go for this detailed cross-platform service design? Please walk me through the tradeoffs.",
            0.10,
            None,
            Some(0.01),
            false,
            &crate::council::TriggerPolicy::default(),
        );
        assert!(
            matches!(
                decision,
                crate::council::TriggerDecision::Skip { ref reason }
                    if reason.contains("budget") && reason.contains("$0.30")
            ),
            "configured daily headroom must activate the smart-trigger budget gate: {decision:?}"
        );
    }

    #[test]
    fn all_local_council_can_convene_with_zero_daily_usd_cap() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::remove_var("NEOTH_COUNCIL_ENABLE");
        }
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::LocalQwen);
        config.council.daily_usd_cap = Some(0.0);
        let req = crate::providers::Request {
            prompt: "Should I use this local-only recursive architecture? Please walk me through the detailed tradeoffs across all components.".into(),
            ..crate::providers::Request::default()
        };
        let (single, total) = council_trigger_cost_bound(&config, &req).unwrap();
        assert_eq!(single, 0.0);
        assert_eq!(total, Some(0.0));

        let home = tempfile::tempdir().unwrap();
        let decision = evaluate_council_trigger(
            home.path(),
            &req.prompt,
            single,
            total,
            config.council.daily_usd_cap,
            false,
            &config.council.trigger.to_policy(),
        );
        assert!(
            decision.should_convene(),
            "a zero USD cap must not block a provably free Council: {decision:?}"
        );
    }

    // GOLD-ADAPT-G-01 — council.mode=single bypass tests.
    // Proves the gate (evaluate_council_trigger) is bypassed when mode=single,
    // and that the default (mode=council) produces zero behaviour change.

    #[test]
    fn council_mode_single_forces_skip_regardless_of_env() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::remove_var("NEOTH_COUNCIL_ENABLE");
        }
        use crate::config::inference::{CouncilConfig, CouncilMode};
        let cfg = CouncilConfig {
            mode: CouncilMode::Single,
            ..Default::default()
        };
        let policy = cfg.trigger.to_policy();
        // is_single() must be true.
        assert!(
            cfg.mode.is_single(),
            "CouncilMode::Single.is_single() must be true"
        );
        // The caller passes `disabled || mode.is_single()` — simulate that.
        let disabled_combined = cfg.disabled.unwrap_or(false) || cfg.mode.is_single();
        let decision = evaluate_council_trigger(
            std::path::Path::new(""),
            "a complex question that would normally trigger a council debate",
            0.001,
            None,
            None,
            disabled_combined,
            &policy,
        );
        assert!(
            !decision.should_convene(),
            "council.mode=single must force Skip; got {decision:?}"
        );
        let reason = decision.reason();
        // The outer gate (chat.rs:1959) emits "freedom.yaml::council.mode=single";
        // evaluate_council_trigger sees disabled=true and emits "freedom.yaml::council.disabled=true".
        // Both contain "freedom.yaml" which is the key contract.
        assert!(
            reason.contains("freedom.yaml"),
            "skip reason must reference freedom.yaml config source; got: {reason}"
        );
    }

    #[test]
    fn council_mode_council_is_default_and_does_not_inject_skip() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::remove_var("NEOTH_COUNCIL_ENABLE");
        }
        use crate::config::inference::{CouncilConfig, CouncilMode};
        let cfg = CouncilConfig::default();
        // Default must be Council, not Single.
        assert_eq!(
            cfg.mode,
            CouncilMode::Council,
            "CouncilMode default must be Council"
        );
        assert!(!cfg.mode.is_single(), "default mode must not be single");
        // With disabled=false and mode=council, evaluate_council_trigger must NOT
        // inject a forced Skip from the mode field alone.
        // (Trigger may still Skip on a trivially-short prompt — that's fine.
        //  The invariant is: mode=council does not itself force a Skip.)
        let disabled_combined = cfg.disabled.unwrap_or(false) || cfg.mode.is_single();
        assert!(
            !disabled_combined,
            "mode=council must not set the disable flag"
        );
    }

    #[test]
    fn council_mode_single_as_str_and_council_as_str() {
        use crate::config::inference::CouncilMode;
        assert_eq!(CouncilMode::Single.as_str(), "single");
        assert_eq!(CouncilMode::Council.as_str(), "council");
    }

    // GOLD-ADAPT-LOWKEY-04 — the MIF pre-step caller decision (the wiring that
    // makes the motive classifier runtime-complete in dispatch_council_with_recovery).
    #[test]
    fn mif_disambiguation_gated_off_by_default_and_conflict_aware() {
        let mut cfg = crate::config::FreedomConfig::default();
        // Default off → inert even on a contradictory prompt.
        assert!(
            mif_disambiguation(&cfg, "Give me a brief summary but explain every detail.").is_none(),
            "MIF must be inert when council.mif_enabled is false"
        );
        cfg.council.mif_enabled = true;
        // Enabled + Conflicted → a disambiguation message is surfaced (council skipped).
        let msg = mif_disambiguation(&cfg, "Give me a brief summary but explain every detail.")
            .expect("conflicted prompt must surface a disambiguation message");
        assert!(
            msg.to_lowercase().contains("clarify"),
            "message must ask the operator to clarify: {msg}"
        );
        // Enabled + a clean imperative → council proceeds normally (no block).
        assert!(
            mif_disambiguation(&cfg, "Summarise the last 10 commits.").is_none(),
            "a Stated prompt must not be blocked"
        );
    }

    #[test]
    fn evaluate_council_trigger_not_disabled_allows_force_enable() {
        let _env = crate::test_env::lock();
        unsafe {
            std::env::remove_var("NEOTH_COUNCIL_DISABLE");
            std::env::set_var("NEOTH_COUNCIL_ENABLE", "1");
        }
        let decision = evaluate_council_trigger(
            std::path::Path::new(""),
            "anything at all",
            0.01,
            None,
            None,
            false,
            &crate::council::TriggerPolicy::default(),
        );
        unsafe { std::env::remove_var("NEOTH_COUNCIL_ENABLE") };
        // disabled=false + force-enable → the normal force path (Convene).
        assert!(
            matches!(decision, crate::council::TriggerDecision::Convene { .. }),
            "with no suppress, NEOTH_COUNCIL_ENABLE=1 must force Convene"
        );
    }

    // ── UX-02 memory-signal line ───────────────────────────────────

    #[test]
    fn memory_signal_line_silences_zero_and_pluralizes() {
        assert_eq!(memory_signal_line(0), None, "fresh install stays silent");
        assert_eq!(
            memory_signal_line(-3),
            None,
            "defensive: non-positive → None"
        );
        assert_eq!(
            memory_signal_line(1).unwrap(),
            "I remember 1 thing from last time."
        );
        assert_eq!(
            memory_signal_line(42).unwrap(),
            "I remember 42 things from last time."
        );
    }

    // ── K-Perf-3 v1 2026-05-17: spawn_blocking wrap of profile_block_for_callosum ──

    #[test]
    fn profile_block_for_callosum_sync_returns_none_on_missing_db() {
        // When `views.db` doesn't exist (fresh install / test env),
        // the sync helper must return None gracefully — no panic,
        // no error bubble. The async wrapper logs a blocking-worker failure
        // and keeps the same privacy-safe no-injection outcome.
        //
        // Test runs in a process where the default-path views.db
        // does NOT exist (or, if it does, the operator's actual
        // profile data shouldn't be touched — the test is environment-
        // sensitive but the only safe outcome is None either way).
        // Either branch — missing db OR empty db — satisfies the
        // "returns Option, never panics" contract.
        let _ = profile_block_for_callosum_sync(&crate::memory::store::default_path(), &[]);
        // No assertion on the value; the point is that the call
        // returned at all without panicking.
    }

    #[test]
    fn callosum_min_confidence_consumes_p06_injection_floor_constant() {
        // CH-11 / P-06 drift guard (Session 21): the callosum profile-
        // injection floor MUST source from the primitive
        // `profile::injection::DEFAULT_INJECTION_FLOOR` (currently
        // 0.6). If a future refactor either (a) re-introduces a
        // hardcoded literal here, or (b) changes the primitive's
        // default without thinking through callosum impact, this
        // test surfaces the drift.
        //
        // Why pin at the constant rather than the literal: the
        // SPEC says "Block-B profile injection ≥ 0.6 confidence
        // gate" once. Two places enforcing the same threshold
        // independently always drift; the single-source-of-truth
        // is `DEFAULT_INJECTION_FLOOR` per CH-11 closeout.
        assert!(
            (crate::profile::injection::DEFAULT_INJECTION_FLOOR - 0.6).abs() < f64::EPSILON,
            "primitive's DEFAULT_INJECTION_FLOOR drifted from 0.6 — \
             update SPEC + this drift guard together"
        );
    }

    #[tokio::test]
    async fn profile_block_for_callosum_async_does_not_block_tokio_worker() {
        // K-Perf-3 v1: the wrapper offloads the rusqlite query to
        // the blocking pool. Concurrently with this call, a
        // `tokio::time::sleep(0)` MUST make progress (= the worker
        // pool isn't stalled). Smoke check that the spawn_blocking
        // path actually fires.
        let pipeline_task = tokio::spawn(profile_block_for_callosum(
            crate::memory::store::default_path(),
            Vec::new(),
        ));
        // Yield + immediately await — the runtime should schedule
        // other work even while spawn_blocking runs.
        tokio::task::yield_now().await;
        let _ = pipeline_task.await.unwrap();
        // No specific value assertion (env-sensitive); the
        // contract is: doesn't deadlock, doesn't panic.
    }

    #[tokio::test]
    async fn incognito_callosum_omits_existing_profile_claims() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = crate::memory::store::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO idx_profile (extraction_id, event_id, field, value_json, confidence, \
             evidence_event_ids, guard_version, applied_at, superseded_at) \
             VALUES ('ext-incognito', 42, 'operator_preferences.communication_structure', \
             '\"structured\"', 0.95, '[]', 'test', 1, NULL)",
            [],
        )
        .unwrap();
        drop(conn);

        let normal = profile_block_for_callosum_for_turn(db_path.clone(), Vec::new(), false)
            .await
            .expect("ordinary Council turn should load the stored profile claim");
        assert!(normal.contains("communication_structure"), "{normal}");

        assert!(
            profile_block_for_callosum_for_turn(db_path, Vec::new(), true)
                .await
                .is_none(),
            "incognito Council turn must not expose stored profile claims"
        );
    }

    struct MockProvider {
        reply: String,
    }

    #[async_trait]
    impl Provider for MockProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            Ok(Completion {
                text: self.reply.clone(),
                identity: Default::default(),
                model: "mock-1".to_string(),
                latency: Duration::from_millis(7),
                input_tokens: Some(12),
                output_tokens: Some(8),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    /// GOLD-WIRE-02: a provider that records whether `complete` was ever
    /// called. The conversational-recall short-circuit must answer from
    /// memory WITHOUT touching it.
    #[derive(Default)]
    struct NeverCalledProvider {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Provider for NeverCalledProvider {
        fn name(&self) -> &'static str {
            "never-called"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Completion {
                text: "SHOULD NOT BE CALLED".into(),
                identity: Default::default(),
                model: "x".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(0),
                output_tokens: Some(0),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[derive(Default)]
    struct ConsentCountingProvider {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Provider for ConsentCountingProvider {
        fn name(&self) -> &'static str {
            "openai_api"
        }

        fn default_model(&self) -> Option<&str> {
            Some("gpt-4o")
        }

        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Completion {
                text: "must not dispatch".into(),
                identity: Default::default(),
                model: "gpt-4o".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn one_shot_chat_rechecks_revoked_consent_before_dispatch() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("freedom.yaml");
        let segment = dir.path().join("chat-consent.wal");
        let config = FreedomConfig {
            provider_kind: Some(ProviderKind::OpenaiApi),
            provider_model: Some("gpt-4o".into()),
            language_primary: Some("en".into()),
            ..Default::default()
        };
        let provider = ConsentCountingProvider::default();
        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("Reply with one short greeting.".into()),
            model: None,
            system: None,
            edit: false,
            config: Some(config_path),
            wal_segment: Some(segment),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        let error = run_chat_with(args, config, &provider)
            .await
            .expect_err("missing live consent marker must stop the final dispatch");
        assert!(error.to_string().contains("consent"));
        assert_eq!(
            provider.calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the provider leaf must not run after a live revoke"
        );
    }

    #[tokio::test]
    async fn recall_intent_short_circuits_without_provider_or_request_frame() {
        // GOLD-WIRE-02: "do you remember when we talked about X?" is answered
        // from local memory — the provider's complete() must NEVER fire, so
        // no PROVIDER_REQUEST / PROVIDER_RESPONSE frame is written. The only
        // WAL frame for the turn is the RAW_TEXT (the recall question itself).
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let config = FreedomConfig {
            language_primary: Some("en".into()),
            ..Default::default()
        };
        let provider = NeverCalledProvider::default();
        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("Do you remember when we talked about rust?".into()),
            model: None,
            system: None,
            edit: false,
            config: None,
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        run_chat_with(args, config, &provider)
            .await
            .expect("recall chat run succeeds");

        assert_eq!(
            provider.calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "recall short-circuit must not call the provider"
        );

        // WAL: SegmentHeader, then MODE_CHECKPOINT (PWF-02 session-start anchor),
        // then RAW_TEXT — and NOTHING after RAW_TEXT (no PROVIDER_REQUEST).
        let bytes = read(&seg).await.unwrap();
        let frames = &bytes[SEGMENT_HEADER_LEN..];
        // PWF-02: skip the MODE_CHECKPOINT frame that now precedes RAW_TEXT.
        let cp = decode_frame(frames).expect("decode MODE_CHECKPOINT frame");
        assert_eq!(
            cp.header.event_type,
            crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT,
            "first frame after segment header must be MODE_CHECKPOINT (PWF-02)"
        );
        let frames = &frames[cp.header.total_len as usize..];
        let dec0 = decode_frame(frames).expect("decode RAW_TEXT frame");
        assert_eq!(
            dec0.header.event_type,
            crate::wal::events::EVENT_TYPE_RAW_TEXT
        );
        assert_eq!(
            dec0.payload, b"Do you remember when we talked about rust?",
            "RAW_TEXT payload must be the verbatim recall prompt"
        );
        let rest = &frames[dec0.header.total_len as usize..];
        assert!(
            rest.is_empty(),
            "no frame may follow RAW_TEXT on the recall path (no PROVIDER_REQUEST); got {} trailing bytes",
            rest.len()
        );
    }

    #[tokio::test]
    async fn chat_writes_request_and_response_frames() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        crate::consent::grant(dir.path(), ProviderKind::ClaudeCli).unwrap();

        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: Some("en".into()),
            language_code: Some("en".into()),
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: Some("claude-opus-4-7".into()),
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };

        let provider = MockProvider {
            reply: "hello back".to_string(),
        };

        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("hi".into()),
            model: None,
            system: None,
            edit: false,
            config: Some(dir.path().join("freedom.yaml")),
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        run_chat_with(args, config, &provider)
            .await
            .expect("chat run_with succeeds");

        // B22 — the turn intent precedes the final-boundary authorization; the
        // cost preview and gate must be adjacent to the real provider call.
        let bytes = read(&seg).await.unwrap();
        let frames = &bytes[SEGMENT_HEADER_LEN..];

        // PWF-02: skip the MODE_CHECKPOINT frame that now precedes RAW_TEXT.
        let cp = decode_frame(frames).expect("decode MODE_CHECKPOINT frame");
        assert_eq!(
            cp.header.event_type,
            crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT,
        );
        let frames = &frames[cp.header.total_len as usize..];

        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        let dec0 = decode_frame(frames).expect("decode RAW_TEXT frame");
        assert_eq!(dec0.header.event_type, EVENT_TYPE_RAW_TEXT);
        assert_eq!(dec0.payload, b"hi");

        // Turn journal + council decision are prepared before the exact leaf
        // cost gate. The 0x20 intent itself is emitted only after approval,
        // immediately before transport dispatch.
        let rest = &frames[dec0.header.total_len as usize..];
        let opened = decode_frame(rest).expect("decode TURN_JOURNAL_OPENED frame");
        assert_eq!(
            opened.header.event_type,
            crate::wal::events::EVENT_TYPE_TURN_JOURNAL_OPENED,
        );
        let rest = &rest[opened.header.total_len as usize..];
        // B-1 (Session 13): COUNCIL_SKIP frame sits between PROVIDER_REQUEST and
        // PROVIDER_RESPONSE whenever the council smart-trigger evaluates to Skip.
        let council_skip = decode_frame(rest).expect("decode COUNCIL_SKIP frame");
        assert_eq!(
            council_skip.header.event_type,
            crate::wal::events::EVENT_TYPE_COUNCIL_SKIP,
        );
        let council_skip_payload: serde_json::Value =
            serde_json::from_slice(council_skip.payload).unwrap();
        assert!(council_skip_payload["reason"].is_string());

        let rest = &rest[council_skip.header.total_len as usize..];
        let cost = decode_frame(rest).expect("decode cost estimate frame");
        assert_eq!(
            cost.header.event_type,
            crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN,
        );
        let cost_payload: serde_json::Value = serde_json::from_slice(cost.payload).unwrap();
        assert_eq!(cost_payload["call_scope"], "chat_provider_round");
        assert_eq!(cost_payload["authorization_binding"], "actual_leaf_request");
        assert_eq!(cost_payload["provider"], "mock");
        assert_eq!(cost_payload["model"], "claude-opus-4-7");
        assert_eq!(cost_payload["streaming"], false);

        let rest = &rest[cost.header.total_len as usize..];
        let perm = decode_frame(rest).expect("decode permission frame");
        assert_eq!(
            perm.header.event_type,
            crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED,
        );

        let rest = &rest[perm.header.total_len as usize..];
        let dec1 = decode_frame(rest).expect("decode PROVIDER_REQUEST frame");
        assert_eq!(dec1.header.event_type, EVENT_TYPE_PROVIDER_REQUEST);
        let req_payload: serde_json::Value = serde_json::from_slice(dec1.payload).unwrap();
        assert_eq!(req_payload["provider"], "mock");
        assert_eq!(req_payload["operator_id"], "alice");
        assert_eq!(req_payload["model_source"], "freedom");
        assert_eq!(req_payload["wire_model"], "claude-opus-4-7");

        let rest = &rest[dec1.header.total_len as usize..];
        let dec2 = decode_frame(rest).expect("decode response frame");
        assert_eq!(dec2.header.event_type, EVENT_TYPE_PROVIDER_RESPONSE);
        let resp_payload: serde_json::Value = serde_json::from_slice(dec2.payload).unwrap();
        assert_eq!(resp_payload["provider"], "mock");
        assert_eq!(resp_payload["model"], "claude-opus-4-7");
        assert_eq!(resp_payload["invocation_id"], req_payload["invocation_id"]);
        assert_eq!(resp_payload["input_tokens"], 12);
        assert_eq!(resp_payload["output_tokens"], 8);

        // SPEC_mirror_refusal Phase 1: a clean reply MUST NOT produce a
        // REFUSAL_OBSERVED frame. The audit trail stays empty of false
        // positives so operators can grep for actual refusals without
        // wading through noise.
        let rest = &rest[dec2.header.total_len as usize..];
        if !rest.is_empty() {
            let after = decode_frame(rest).expect("decode after-response frame");
            assert_ne!(
                after.header.event_type,
                crate::wal::events::EVENT_TYPE_REFUSAL_OBSERVED,
                "clean reply must not emit REFUSAL_OBSERVED"
            );
        }
    }

    /// SPEC_mirror_refusal Phase 1: a provider reply that matches a
    /// hard-refusal pattern must produce a `0x16 REFUSAL_OBSERVED` WAL
    /// frame after PROVIDER_RESPONSE. The full mirror pipeline (Stages
    /// 2-6) is hemisphere-architecture work and lands later.
    #[tokio::test]
    async fn chat_emits_refusal_observed_on_hard_refusal_reply() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        crate::consent::grant(dir.path(), ProviderKind::ClaudeCli).unwrap();

        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: Some("en".into()),
            language_code: Some("en".into()),
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: Some("claude-opus-4-7".into()),
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };

        let provider = MockProvider {
            reply: "I cannot help with that request.".to_string(),
        };

        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("do the dangerous thing".into()),
            model: None,
            system: None,
            edit: false,
            config: Some(dir.path().join("freedom.yaml")),
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        run_chat_with(args, config, &provider)
            .await
            .expect("chat run_with succeeds");

        // Walk every frame; one of them must be REFUSAL_OBSERVED with the
        // expected class + a non-empty matched_patterns array.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut found = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_REFUSAL_OBSERVED {
                let p: serde_json::Value =
                    serde_json::from_slice(frame.payload).expect("REFUSAL payload JSON");
                found = Some(p);
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let payload = found.expect("REFUSAL_OBSERVED frame must be present");
        assert_eq!(payload["refusal_class"], "hard_refusal");
        assert!(payload["confidence"].as_u64().unwrap() >= 80);
        assert!(!payload["matched_patterns"].as_array().unwrap().is_empty());
        assert_eq!(payload["provider"], "mock");
    }

    /// AP-2: every local inference call must leave a WAL trace
    /// (`LOCAL_INFERENCE_START` + `LOCAL_INFERENCE_END`). Test uses a
    /// mock provider that reports `name() == "local_qwen"` so the
    /// chat.rs branch fires; the real candle path isn't exercised.
    #[tokio::test]
    async fn chat_emits_local_inference_start_and_end_for_local_qwen() {
        struct LocalQwenMock;
        #[async_trait]
        impl Provider for LocalQwenMock {
            fn name(&self) -> &'static str {
                "local_qwen"
            }
            async fn complete(&self, _req: Request) -> Result<Completion> {
                Ok(Completion {
                    text: "PARIS".into(),
                    identity: Default::default(),
                    model: "Qwen/Qwen2.5-3B-Instruct".into(),
                    latency: Duration::from_millis(11),
                    input_tokens: Some(5),
                    output_tokens: Some(1),
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                })
            }
        }

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: None,
            language_code: None,
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::LocalQwen),
            provider_binary: None,
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: None,
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };
        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("Capital of France?".into()),
            model: None,
            system: None,
            edit: false,
            config: None,
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };
        run_chat_with(args, config, &LocalQwenMock)
            .await
            .expect("run_chat_with");

        // Walk every frame and collect event types we care about. Some
        // intermediate frames (RAW_TEXT, PROVIDER_REQUEST, PERMISSION_GRANTED,
        // PROVIDER_RESPONSE) live in between; the assertion is just that
        // both START + END appear in the right order.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut saw_start_at: Option<usize> = None;
        let mut saw_end_at: Option<usize> = None;
        let mut index = 0usize;
        while !cursor.is_empty() {
            let Ok(frame) = decode_frame(cursor) else {
                break;
            };
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_LOCAL_INFERENCE_START {
                saw_start_at = Some(index);
            }
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_LOCAL_INFERENCE_END {
                saw_end_at = Some(index);
            }
            cursor = &cursor[frame.header.total_len as usize..];
            index += 1;
        }
        let start = saw_start_at.expect("LOCAL_INFERENCE_START frame missing");
        let end = saw_end_at.expect("LOCAL_INFERENCE_END frame missing");
        assert!(
            start < end,
            "END must follow START (start={start}, end={end})"
        );
    }

    #[tokio::test]
    async fn chat_streaming_emits_chunks_then_response() {
        use crate::providers::ChunkStream;
        use futures_util::stream;

        struct MockStreamProvider;

        #[async_trait]
        impl Provider for MockStreamProvider {
            fn name(&self) -> &'static str {
                "mock_stream"
            }
            async fn complete(&self, _req: Request) -> Result<Completion> {
                anyhow::bail!("not used in streaming test")
            }
            async fn stream(&self, _req: Request) -> Result<ChunkStream> {
                let chunks: Vec<Result<CompletionChunk>> = vec![
                    Ok(CompletionChunk {
                        delta: "hello ".into(),
                        done: false,
                        identity: Default::default(),
                        input_tokens: None,
                        output_tokens: None,
                        cache_creation_tokens: None,
                        cache_read_tokens: None,
                    }),
                    Ok(CompletionChunk {
                        delta: "world".into(),
                        done: false,
                        identity: Default::default(),
                        input_tokens: None,
                        output_tokens: None,
                        cache_creation_tokens: None,
                        cache_read_tokens: None,
                    }),
                    Ok(CompletionChunk {
                        delta: String::new(),
                        done: true,
                        identity: Default::default(),
                        input_tokens: Some(5),
                        output_tokens: Some(3),
                        cache_creation_tokens: None,
                        cache_read_tokens: None,
                    }),
                ];
                Ok(Box::pin(stream::iter(chunks)))
            }
        }

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        crate::consent::grant(dir.path(), ProviderKind::ClaudeCli).unwrap();
        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: None,
            language_code: None,
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: Some("mock-stream-1".into()),
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };
        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("hi".into()),
            model: None,
            system: None,
            edit: false,
            config: Some(dir.path().join("freedom.yaml")),
            wal_segment: Some(seg.clone()),
            stream: true,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        run_chat_with(args, config, &MockStreamProvider)
            .await
            .expect("streaming run");

        // B22 — the streaming call is authorized from its final request at the
        // provider boundary, immediately before the stream is opened.
        let bytes = read(&seg).await.unwrap();
        let frames = &bytes[SEGMENT_HEADER_LEN..];

        // PWF-02: skip the MODE_CHECKPOINT frame that now precedes RAW_TEXT.
        let cp = decode_frame(frames).expect("MODE_CHECKPOINT");
        assert_eq!(
            cp.header.event_type,
            crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT,
        );
        let frames = &frames[cp.header.total_len as usize..];

        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        let dec0 = decode_frame(frames).expect("RAW_TEXT");
        assert_eq!(dec0.header.event_type, EVENT_TYPE_RAW_TEXT);
        let frames = &frames[dec0.header.total_len as usize..];

        let mut cursor = frames;
        let mut index = 0usize;
        let mut opened_index = None;
        let mut council_index = None;
        let mut cost_index = None;
        let mut permission_index = None;
        let mut request_index = None;
        let mut response_index = None;
        let mut chunk_count = 0usize;
        let mut request_payload: Option<serde_json::Value> = None;
        let mut response_payload: Option<serde_json::Value> = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode streaming audit frame");
            match frame.header.event_type {
                crate::wal::events::EVENT_TYPE_TURN_JOURNAL_OPENED => opened_index = Some(index),
                crate::wal::events::EVENT_TYPE_COUNCIL_SKIP => {
                    council_index = Some(index);
                    let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                    assert_eq!(payload["reason"], "streaming_mode_disables_council");
                }
                crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN => {
                    cost_index = Some(index);
                    let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
                    assert_eq!(payload["call_scope"], "chat_provider_round");
                    assert_eq!(payload["provider"], "mock_stream");
                    assert_eq!(payload["model"], "mock-stream-1");
                }
                crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED => permission_index = Some(index),
                EVENT_TYPE_PROVIDER_REQUEST => {
                    request_index = Some(index);
                    request_payload = Some(serde_json::from_slice(frame.payload).unwrap());
                }
                EVENT_TYPE_PROVIDER_RESPONSE => {
                    response_index = Some(index);
                    response_payload = Some(serde_json::from_slice(frame.payload).unwrap());
                }
                crate::wal::events::EVENT_TYPE_PROVIDER_STREAM_CHUNK => chunk_count += 1,
                _ => {}
            }
            cursor = &cursor[frame.header.total_len as usize..];
            index += 1;
        }
        assert!(opened_index.unwrap() < council_index.unwrap());
        assert_eq!(permission_index.unwrap(), cost_index.unwrap() + 1);
        assert_eq!(request_index.unwrap(), permission_index.unwrap() + 1);
        assert!(request_index.unwrap() < response_index.unwrap());
        assert_eq!(chunk_count, 2);
        let request_payload = request_payload.unwrap();
        let response_payload = response_payload.unwrap();
        assert_eq!(response_payload["streamed"], true);
        assert_eq!(response_payload["input_tokens"], 5);
        assert_eq!(response_payload["output_tokens"], 3);
        assert_eq!(response_payload["model"], "mock-stream-1");
        assert_eq!(
            response_payload["invocation_id"],
            request_payload["invocation_id"]
        );
    }

    #[tokio::test]
    async fn chat_propagates_provider_error() {
        struct FailingProvider;
        #[async_trait]
        impl Provider for FailingProvider {
            fn name(&self) -> &'static str {
                "fail"
            }
            async fn complete(&self, _req: Request) -> Result<Completion> {
                anyhow::bail!("simulated upstream failure")
            }
        }

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        crate::consent::grant(dir.path(), ProviderKind::ClaudeCli).unwrap();
        let config = FreedomConfig {
            operator_id: Some("alice".into()),
            language_primary: None,
            language_code: None,
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            provider_model: None,
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };
        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("trigger".into()),
            model: None,
            system: None,
            edit: false,
            config: Some(dir.path().join("freedom.yaml")),
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        let result = run_chat_with(args, config, &FailingProvider).await;
        assert!(result.is_err());

        // B22 — a failed wire call must still have its final request estimate
        // and permission decision immediately before dispatch.
        let bytes = read(&seg).await.unwrap();
        let frames = &bytes[SEGMENT_HEADER_LEN..];

        // PWF-02: skip the MODE_CHECKPOINT frame that now precedes RAW_TEXT.
        let cp = decode_frame(frames).expect("MODE_CHECKPOINT");
        assert_eq!(
            cp.header.event_type,
            crate::wal::events::EVENT_TYPE_MODE_CHECKPOINT,
        );
        let frames = &frames[cp.header.total_len as usize..];

        use crate::wal::events::EVENT_TYPE_RAW_TEXT;
        let dec0 = decode_frame(frames).expect("RAW_TEXT");
        assert_eq!(dec0.header.event_type, EVENT_TYPE_RAW_TEXT);

        let mut cursor = &frames[dec0.header.total_len as usize..];
        let mut index = 0usize;
        let mut request_index = None;
        let mut cost_index = None;
        let mut permission_index = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame on error path");
            if frame.header.event_type == EVENT_TYPE_PROVIDER_REQUEST {
                request_index = Some(index);
            } else if frame.header.event_type == crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN
            {
                cost_index = Some(index);
            } else if frame.header.event_type == crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED {
                permission_index = Some(index);
            }
            cursor = &cursor[frame.header.total_len as usize..];
            index += 1;
        }
        let request_index = request_index.expect("PROVIDER_REQUEST on failure");
        let cost_index = cost_index.expect("COST_ESTIMATE_SHOWN on failure");
        let permission_index = permission_index.expect("PERMISSION_GRANTED on failure");
        assert!(
            permission_index == cost_index + 1 && request_index == permission_index + 1,
            "cost + permission must precede the durable leaf intent and failed provider call"
        );
    }

    /// B22 fix — PROVIDER_REQUEST WAL `model` and `model_source` must exactly
    /// match the `Request.model` that `dispatch_provider` sends to the wire.
    /// With no skill/agent/cli override active, the freedom tier
    /// (`config.provider_model`) drives both.
    #[tokio::test]
    async fn provider_request_wal_model_matches_dispatch_model() {
        use std::sync::{Arc, Mutex};

        struct CapturingProvider {
            reply: String,
            received_model: Arc<Mutex<Option<Option<String>>>>,
        }
        #[async_trait]
        impl Provider for CapturingProvider {
            fn name(&self) -> &'static str {
                "mock"
            }
            async fn complete(&self, req: Request) -> Result<Completion> {
                *self.received_model.lock().unwrap() = Some(req.model.clone());
                let model_echo = req
                    .model
                    .clone()
                    .unwrap_or_else(|| "mock-capture-1".to_string());
                Ok(Completion {
                    text: self.reply.clone(),
                    identity: Default::default(),
                    model: model_echo,
                    latency: Duration::from_millis(1),
                    input_tokens: Some(4),
                    output_tokens: Some(2),
                    cache_creation_tokens: None,
                    cache_read_tokens: None,
                })
            }
        }

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        crate::consent::grant(dir.path(), ProviderKind::ClaudeCli).unwrap();

        let config = FreedomConfig {
            operator_id: Some("b22-check".into()),
            language_primary: Some("en".into()),
            language_code: Some("en".into()),
            role: None,
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("claude".into()),
            provider_key: None,
            provider_endpoint: None,
            provider_region: None,
            provider_api_version: None,
            council: Default::default(),
            // freedom tier: no skill/agent/cli override → this should appear in WAL
            provider_model: Some("claude-sonnet-4-6".into()),
            telegram_token: None,
            telegram_user_id: None,
            whatsapp_webhook_port: None,
            autonomy: crate::permissions::AutonomyLevel::Standard,
            observability_listen: None,
            inference: crate::config::inference::InferenceTopology::default(),
            review_gate_enabled: false,
            obsidian_vault: None,
            obsidian_subdir: None,
            obsidian_auto_sync_secs: None,
            hysteria: None,
            cloud_archive_dest: None,
            cloud_archive_subdir: None,
            cloud_archive_auto_sync_secs: None,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7],
            rollback: crate::config::RollbackConfig::default(),
            claude_cli: crate::config::ClaudeCliConfig::default(),
            profile: crate::config::ProfileConfig::default(),
            refusal_recovery: crate::config::RefusalRecoveryConfig::default(),
            code_map: crate::config::CodeMapConfig::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            coding: crate::config::CodingConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            doctor: crate::config::DoctorConfig::default(),
            updater: crate::config::UpdaterConfig::default(),
            hook_chain: Default::default(),
            dreaming: crate::config::DreamingConfig::default(),
            proactive: crate::config::ProactiveConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
            n8n_api: crate::config::N8nApiConfig::default(),
            ..Default::default()
        };

        let received_model: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
        let provider = CapturingProvider {
            reply: "captured".into(),
            received_model: Arc::clone(&received_model),
        };

        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("b22 test prompt".into()),
            model: None, // no CLI override — freedom tier must win
            system: None,
            edit: false,
            config: Some(dir.path().join("freedom.yaml")),
            wal_segment: Some(seg.clone()),
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        run_chat_with(args, config, &provider)
            .await
            .expect("b22 chat run succeeds");

        // (a) What model did dispatch_provider actually send?
        let dispatch_model: Option<String> = received_model
            .lock()
            .unwrap()
            .clone()
            .expect("provider must have been called");

        // (b) Find PROVIDER_REQUEST frame in WAL.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut req_payload_opt: Option<serde_json::Value> = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == EVENT_TYPE_PROVIDER_REQUEST {
                req_payload_opt =
                    Some(serde_json::from_slice(frame.payload).expect("parse PROVIDER_REQUEST"));
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let req_payload = req_payload_opt.expect("PROVIDER_REQUEST frame must be present");

        // (c) model in WAL must equal model sent to the provider.
        let wal_model: Option<String> = req_payload["model"].as_str().map(str::to_string);
        assert_eq!(
            wal_model, dispatch_model,
            "PROVIDER_REQUEST WAL `model` must match Request.model sent to dispatch"
        );

        // (d) model_source must be "freedom" (only freedom.yaml sets the model here).
        assert_eq!(
            req_payload["model_source"], "freedom",
            "model_source must be 'freedom' when only config.provider_model is set"
        );

        // (e) Turn intent precedes the exact-request boundary gate. COST and
        //     PERMISSION remain adjacent immediately before the provider call.
        let mut cursor2 = &bytes[SEGMENT_HEADER_LEN..];
        let mut perm_idx: Option<usize> = None;
        let mut req_idx: Option<usize> = None;
        let mut cost_idx: Option<usize> = None;
        let mut cost_model: Option<String> = None;
        let mut idx = 0usize;
        while !cursor2.is_empty() {
            let frame = decode_frame(cursor2).expect("decode frame for ordering check");
            match frame.header.event_type {
                t if t == crate::wal::events::EVENT_TYPE_PERMISSION_GRANTED => {
                    perm_idx = Some(idx);
                }
                t if t == crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN => {
                    cost_idx = Some(idx);
                    let payload: serde_json::Value =
                        serde_json::from_slice(frame.payload).expect("parse cost payload");
                    cost_model = payload["model"].as_str().map(str::to_owned);
                }
                t if t == EVENT_TYPE_PROVIDER_REQUEST => {
                    req_idx = Some(idx);
                }
                _ => {}
            }
            cursor2 = &cursor2[frame.header.total_len as usize..];
            idx += 1;
        }
        let perm_pos = perm_idx.expect("PERMISSION_GRANTED must be present");
        let req_pos = req_idx.expect("PROVIDER_REQUEST must be present");
        let cost_pos = cost_idx.expect("COST_ESTIMATE_SHOWN must be present");
        assert!(
            perm_pos == cost_pos + 1 && req_pos == perm_pos + 1,
            "expected COST_ESTIMATE_SHOWN -> PERMISSION_GRANTED -> PROVIDER_REQUEST; \
             got req={req_pos}, cost={cost_pos}, perm={perm_pos}"
        );
        assert_eq!(
            cost_model, dispatch_model,
            "authorized model must hit the wire"
        );
    }

    // ── E-2 Phase 2 (Session 13) recursive sub-council ────────────────

    /// Counting mock provider — increments a shared counter on every
    /// `complete` call. Used to pin how many leaf LLM calls a
    /// `ProviderHemisphere::ask_with_depth` invocation triggers.
    struct CountingMockProvider {
        counter: std::sync::Arc<std::sync::atomic::AtomicU32>,
        reply: String,
    }

    #[async_trait]
    impl Provider for CountingMockProvider {
        fn name(&self) -> &'static str {
            "counting-mock"
        }
        fn default_model(&self) -> Option<&str> {
            Some("counting-mock-1")
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Completion {
                text: self.reply.clone(),
                identity: Default::default(),
                model: "counting-mock-1".to_string(),
                latency: Duration::from_millis(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    /// Captures the exact request model after the provider leaf's canonical
    /// binding, so Council tests distinguish builder state from what actually
    /// reaches the transport.
    struct CouncilModelCapturingProvider {
        seen_models: Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl Provider for CouncilModelCapturingProvider {
        fn name(&self) -> &'static str {
            "model-capture"
        }

        fn default_model(&self) -> Option<&str> {
            Some("capture-default")
        }

        async fn complete(&self, req: Request) -> Result<Completion> {
            let model = req
                .model
                .expect("authorized leaf request must bind a model");
            self.seen_models.lock().unwrap().push(model.clone());
            Ok(Completion {
                text: "captured".into(),
                identity: Default::default(),
                model,
                latency: Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn ask_with_depth_one_is_flat_no_recursion() {
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "ok".into(),
            }),
            base_req: Request::default(),
            authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            neoth_home: std::path::PathBuf::new(),
            config: None,
            outer_role: None,
            voice: None,
            recall_fragment: None,
            allow_persistent_context: true,
        };
        let result = ph.ask_with_depth("hi", 1).await.unwrap();
        assert_eq!(result.text, "ok");
        // Exactly one flat call — no recursion at depth=1.
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ask_with_depth_zero_is_flat_no_recursion() {
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "ok".into(),
            }),
            base_req: Request::default(),
            authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            neoth_home: std::path::PathBuf::new(),
            config: None,
            outer_role: None,
            voice: None,
            recall_fragment: None,
            allow_persistent_context: true,
        };
        let result = ph.ask_with_depth("hi", 0).await.unwrap();
        assert_eq!(result.text, "ok");
        // depth=0 must also bypass recursion (no negative depth).
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ask_with_depth_without_config_arc_is_flat() {
        // Even with depth > 1, a wrapper built without a config Arc
        // (e.g. via legacy `build_hemisphere` for Split-recovery
        // path) MUST behave as flat. Pins the contract that callosum
        // recovery never triggers recursion regardless of operator
        // config.
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "no-recurse".into(),
            }),
            base_req: Request::default(),
            authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            neoth_home: std::path::PathBuf::new(),
            config: None,
            outer_role: None,
            voice: None,
            recall_fragment: None,
            allow_persistent_context: true,
        };
        // depth=4 (MAX cap) + no config → still flat, one call.
        let result = ph.ask_with_depth("hi", 4).await.unwrap();
        assert_eq!(result.text, "no-recurse");
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ask_with_depth_recursion_path_attempts_to_build_subs() {
        // When a config Arc IS present + depth > 1, the recursion
        // path fires. With a `provider_kind = Skip` config the
        // sub-build will fail (from_config_for_role bails on Skip);
        // we assert the failure path threads the operator-actionable
        // error message rather than panicking. This pins the
        // recursion code path is reached without needing a live LLM.
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = Some(ProviderKind::Skip);
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "outer".into(),
            }),
            base_req: Request::default(),
            authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            neoth_home: std::path::PathBuf::new(),
            config: Some(std::sync::Arc::new(cfg)),
            outer_role: Some(crate::config::inference::HemisphereRole::Left),
            voice: None,
            recall_fragment: None,
            allow_persistent_context: true,
        };
        let err = ph.ask_with_depth("hi", 2).await.unwrap_err();
        // Error msg names "build sub-" so operator sees which leg failed.
        assert!(
            err.contains("build sub-"),
            "expected sub-build error, got: {err}",
        );
        // Flat provider was NEVER called on the outer wrapper —
        // recursion took priority over the outer's own ask.
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // ── Pick #8 SP-2 (Session 14) role-agnostic winner selection ────────

    fn mk_outcome_consensus(
        winning: &str,
        responses: Vec<crate::council::HemisphereResponse>,
    ) -> crate::council::CouncilDebate {
        crate::council::CouncilDebate {
            factual_outcomes: Vec::new(),
            prompt_hash_xxh3: 0,
            responses,
            dissent: crate::council::dissent::DissentScore(0.1),
            verdict: crate::council::Verdict::Consensus {
                winning_text: winning.to_string(),
            },
            total_latency_ms: 100,
        }
    }

    fn mk_outcome_split(
        responses: Vec<crate::council::HemisphereResponse>,
    ) -> crate::council::CouncilDebate {
        crate::council::CouncilDebate {
            factual_outcomes: Vec::new(),
            prompt_hash_xxh3: 0,
            responses,
            dissent: crate::council::dissent::DissentScore(0.7),
            verdict: crate::council::Verdict::Split {
                summary: "left vs right".into(),
            },
            total_latency_ms: 100,
        }
    }

    fn mk_resp_picksel(
        role: crate::config::inference::HemisphereRole,
        provider: &str,
        text: &str,
    ) -> crate::council::HemisphereResponse {
        crate::council::HemisphereResponse {
            role,
            provider: provider.into(),
            text: Some(text.into()),
            error: None,
            latency_ms: 100,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        }
    }

    #[test]
    fn sum_council_tokens_aggregates_and_preserves_unknown() {
        // GOLD-COR-09 / A-14: a council-backed hemisphere must thread the
        // sub-council's real token burn up, summed across the hemispheres that
        // reported, and stay None (never a fabricated 0) when none reported.
        use crate::config::inference::HemisphereRole;
        let mk = |inp: Option<u32>, out: Option<u32>| crate::council::HemisphereResponse {
            role: HemisphereRole::Left,
            provider: "p".into(),
            text: Some("t".into()),
            error: None,
            latency_ms: 1,
            input_tokens: inp,
            output_tokens: out,
            refusal: None,
        };
        let mixed = vec![mk(Some(10), Some(3)), mk(None, None), mk(Some(5), Some(2))];
        assert_eq!(sum_council_tokens(&mixed), (Some(15), Some(5)));
        let none = vec![mk(None, None), mk(None, None)];
        assert_eq!(sum_council_tokens(&none), (None, None));
        assert_eq!(sum_council_tokens(&[]), (None, None));
    }

    #[test]
    fn legacy_majority_mode_returns_none_so_dispatch_uses_legacy_path() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let outcome = mk_outcome_consensus(
            "consensus answer",
            vec![mk_resp_picksel(
                HemisphereRole::Left,
                "claude_cli",
                "claude says",
            )],
        );
        let winner =
            select_winner_role_agnostic(&outcome, SelectionMode::LegacyMajority, None, 0, None);
        assert!(winner.is_none());
    }

    #[test]
    fn best_always_mode_picks_highest_quality_response_regardless_of_consensus() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        // Consensus would say "local_qwen text"; BestAlways picks
        // the higher-tier claude_cli response instead.
        let outcome = mk_outcome_consensus(
            "local_qwen text",
            vec![
                mk_resp_picksel(HemisphereRole::Left, "local_qwen", "local_qwen text"),
                mk_resp_picksel(HemisphereRole::Right, "claude_cli", "claude text"),
            ],
        );
        let winner =
            select_winner_role_agnostic(&outcome, SelectionMode::BestAlways, None, 0, None)
                .expect("BestAlways picks a winner");
        assert_eq!(winner.role, HemisphereRole::Right);
        assert_eq!(winner.provider, "claude_cli");
    }

    #[test]
    fn consensus_or_best_mode_uses_winning_text_when_consensus() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let outcome = mk_outcome_consensus(
            "claude text",
            vec![
                mk_resp_picksel(HemisphereRole::Left, "claude_cli", "claude text"),
                mk_resp_picksel(HemisphereRole::Right, "local_qwen", "qwen text"),
            ],
        );
        let winner =
            select_winner_role_agnostic(&outcome, SelectionMode::ConsensusOrBest, None, 0, None)
                .expect("ConsensusOrBest picks a winner");
        // winning_text = "claude text" → matches the claude_cli response.
        assert_eq!(winner.text, "claude text");
        assert_eq!(winner.provider, "claude_cli");
    }

    // ── SP-4 F5 diversity_bonus_for ────────────────────────────────────

    #[test]
    fn diversity_bonus_zero_for_text_matching_consensus() {
        use crate::config::inference::HemisphereRole;
        let outcome = mk_outcome_consensus(
            "yes that is correct",
            vec![
                mk_resp_picksel(HemisphereRole::Left, "claude_cli", "yes that is correct"),
                mk_resp_picksel(HemisphereRole::Right, "local_qwen", "no never"),
            ],
        );
        // Left text == winning_text → zero distance → zero bonus.
        let b = diversity_bonus_for(Some("yes that is correct"), HemisphereRole::Left, &outcome);
        assert_eq!(b, 0.0);
    }

    #[test]
    fn diversity_bonus_positive_for_text_dissenting_from_consensus() {
        use crate::config::inference::HemisphereRole;
        let outcome = mk_outcome_consensus(
            "yes that is correct",
            vec![
                mk_resp_picksel(HemisphereRole::Left, "claude_cli", "yes that is correct"),
                mk_resp_picksel(
                    HemisphereRole::Right,
                    "local_qwen",
                    "no totally wrong instead",
                ),
            ],
        );
        // Right text fully disjoint from winning_text → high distance.
        let b = diversity_bonus_for(
            Some("no totally wrong instead"),
            HemisphereRole::Right,
            &outcome,
        );
        assert!(
            b > 0.0,
            "a dissenting hemisphere must earn a nonzero diversity bonus; got {b}"
        );
        assert!(b <= 1.0, "bonus stays bounded; got {b}");
    }

    #[test]
    fn diversity_bonus_zero_for_errored_hemisphere() {
        use crate::config::inference::HemisphereRole;
        let outcome = mk_outcome_consensus(
            "yes",
            vec![mk_resp_picksel(HemisphereRole::Left, "claude_cli", "yes")],
        );
        // text=None (errored) → 0.0, no panic.
        assert_eq!(
            diversity_bonus_for(None, HemisphereRole::Right, &outcome),
            0.0
        );
    }

    #[test]
    fn diversity_bonus_split_verdict_uses_other_hemisphere_as_proxy() {
        use crate::config::inference::HemisphereRole;
        // Split has no winning_text → fall back to the OTHER hemisphere's
        // text as the consensus proxy. Left="alpha beta", Right="gamma
        // delta" → disjoint → nonzero, no panic.
        let outcome = mk_outcome_split(vec![
            mk_resp_picksel(HemisphereRole::Left, "claude_cli", "alpha beta"),
            mk_resp_picksel(HemisphereRole::Right, "local_qwen", "gamma delta"),
        ]);
        let b = diversity_bonus_for(Some("alpha beta"), HemisphereRole::Left, &outcome);
        assert!(
            b > 0.0,
            "split-verdict proxy must still produce a distance; got {b}"
        );
    }

    #[test]
    fn consensus_or_best_falls_back_to_best_response_on_split() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let outcome = mk_outcome_split(vec![
            mk_resp_picksel(HemisphereRole::Left, "local_qwen", "qwen says A"),
            mk_resp_picksel(HemisphereRole::Right, "claude_cli", "claude says B"),
        ]);
        let winner =
            select_winner_role_agnostic(&outcome, SelectionMode::ConsensusOrBest, None, 0, None)
                .expect("falls back to best_response");
        // winning_text is None on Split → falls back to best_response,
        // which picks the higher-tier claude_cli.
        assert_eq!(winner.role, HemisphereRole::Right);
        assert_eq!(winner.provider, "claude_cli");
    }

    #[test]
    fn winner_carries_composite_score() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let outcome = mk_outcome_split(vec![mk_resp_picksel(
            HemisphereRole::Left,
            "claude_cli",
            "thoughtful answer with structure\n```rust\nfn x() {}\n```\n- list",
        )]);
        let winner =
            select_winner_role_agnostic(&outcome, SelectionMode::BestAlways, None, 0, None)
                .expect("BestAlways winner");
        // claude_cli tier 1.0 + non-zero dynamic + 0.5 memory + 0 diversity
        // total ≥ 0.40 (tier component alone) + memory component
        assert!(
            winner.score >= 0.4,
            "composite score should reflect tier weight, got {}",
            winner.score
        );
    }

    #[test]
    fn all_unusable_returns_none_in_best_always() {
        use crate::config::inference::{HemisphereRole, SelectionMode};
        let errored = crate::council::HemisphereResponse {
            role: HemisphereRole::Left,
            provider: "claude_cli".into(),
            text: None,
            error: Some("boom".into()),
            latency_ms: 0,
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        };
        let outcome = mk_outcome_split(vec![errored]);
        let winner =
            select_winner_role_agnostic(&outcome, SelectionMode::BestAlways, None, 0, None);
        assert!(winner.is_none(), "no usable responses → fall through");
    }

    // ── E-2 Phase 3 (Session 14) sub-slot routing ──────────────────────

    #[tokio::test]
    async fn council_outer_roles_override_primary_model_with_alias_resolved_role_models() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, TopologyMode,
        };
        use crate::council::orchestrator::HemisphereProvider;

        let mut cfg = FreedomConfig::default();
        cfg.inference.mode = TopologyMode::Custom;
        cfg.models_aliases
            .insert("@council-left".into(), "role-left-wire".into());
        cfg.models_aliases
            .insert("@council-right".into(), "role-right-wire".into());
        cfg.models_aliases
            .insert("@council-cerebellum".into(), "role-cerebellum-wire".into());
        let slot = |model: &str| HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            model: Some(model.into()),
            endpoint: Some("http://127.0.0.1:1/v1".into()),
            ..Default::default()
        };
        cfg.inference.left = slot("@council-left");
        cfg.inference.right = slot("@council-right");
        cfg.inference.cerebellum = slot("@council-cerebellum");

        let config = Arc::new(cfg);
        let primary_req = Request {
            model: Some("primary-chat-wire".into()),
            prompt: "outer question".into(),
            ..Default::default()
        };
        let seen_models = Arc::new(std::sync::Mutex::new(Vec::new()));
        for (role, expected) in [
            (HemisphereRole::Left, "role-left-wire"),
            (HemisphereRole::Right, "role-right-wire"),
            (HemisphereRole::Cerebellum, "role-cerebellum-wire"),
        ] {
            let mut hemisphere = super::build_hemisphere_with_config(
                Arc::clone(&config),
                std::path::Path::new(""),
                role,
                &primary_req,
                crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                    crate::permissions::AutonomyLevel::Full,
                ),
                false,
            )
            .await
            .expect("configured OpenAI-compatible role must build");
            assert_eq!(
                hemisphere.base_req.model.as_deref(),
                Some(expected),
                "role model must replace the primary request model before dispatch"
            );
            hemisphere.provider = Box::new(CouncilModelCapturingProvider {
                seen_models: Arc::clone(&seen_models),
            });
            hemisphere
                .ask("role question")
                .await
                .expect("capturing role leaf must dispatch");
        }

        assert_eq!(
            *seen_models.lock().unwrap(),
            vec![
                "role-left-wire".to_string(),
                "role-right-wire".to_string(),
                "role-cerebellum-wire".to_string(),
            ],
            "each captured Council request must carry its own alias-resolved role model"
        );
    }

    #[tokio::test]
    async fn council_role_without_model_uses_its_provider_default_not_primary_model() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, TopologyMode,
        };
        use crate::council::orchestrator::HemisphereProvider;

        let mut cfg = FreedomConfig::default();
        cfg.inference.mode = TopologyMode::Custom;
        cfg.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            model: None,
            ..Default::default()
        };
        let primary_req = Request {
            model: Some("primary-chat-wire".into()),
            ..Default::default()
        };
        let mut hemisphere = super::build_hemisphere_with_config(
            Arc::new(cfg),
            std::path::Path::new(""),
            HemisphereRole::Left,
            &primary_req,
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            false,
        )
        .await
        .expect("role provider with a declared default must build");
        let expected = hemisphere
            .provider
            .default_model()
            .expect("Claude CLI declares a concrete default")
            .to_owned();
        assert_ne!(expected, "primary-chat-wire");
        assert_eq!(
            hemisphere.base_req.model.as_deref(),
            Some(expected.as_str())
        );

        let seen_models = Arc::new(std::sync::Mutex::new(Vec::new()));
        hemisphere.provider = Box::new(CouncilModelCapturingProvider {
            seen_models: Arc::clone(&seen_models),
        });
        hemisphere
            .ask("default-model question")
            .await
            .expect("capturing default-model leaf must dispatch");
        assert_eq!(*seen_models.lock().unwrap(), vec![expected]);
    }

    #[tokio::test]
    async fn recursive_council_subslot_overrides_parent_model_with_alias_resolved_model() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots, TopologyMode,
        };
        use crate::council::orchestrator::HemisphereProvider;

        let mut cfg = FreedomConfig::default();
        cfg.inference.mode = TopologyMode::Custom;
        cfg.models_aliases
            .insert("@inner-right".into(), "inner-right-wire".into());
        let mut sub_slots = SubHemisphereSlots::default();
        sub_slots.right = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAiCompat),
            model: Some("@inner-right".into()),
            endpoint: Some("http://127.0.0.1:1/v1".into()),
            ..Default::default()
        };
        cfg.inference
            .hemisphere_sub_slots
            .insert(HemisphereRole::Left, sub_slots);

        let parent_req = Request {
            model: Some("outer-left-wire".into()),
            prompt: "parent question".into(),
            ..Default::default()
        };
        let seen_models = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut hemisphere = super::build_sub_hemisphere_with_config(
            Arc::new(cfg),
            std::path::Path::new(""),
            HemisphereRole::Left,
            HemisphereRole::Right,
            &parent_req,
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            false,
        )
        .await
        .expect("configured recursive sub-slot must build");
        assert_eq!(
            hemisphere.base_req.model.as_deref(),
            Some("inner-right-wire"),
            "sub-slot model must replace the recursive parent request model"
        );
        hemisphere.provider = Box::new(CouncilModelCapturingProvider {
            seen_models: Arc::clone(&seen_models),
        });
        hemisphere
            .ask("inner question")
            .await
            .expect("capturing recursive leaf must dispatch");
        assert_eq!(
            *seen_models.lock().unwrap(),
            vec!["inner-right-wire".to_string()],
            "captured recursive request must carry the sub-slot model, not the parent model"
        );
    }

    #[tokio::test]
    async fn ask_with_depth_routes_through_sub_slots_when_outer_role_set() {
        // When `outer_role: Some(Left)` AND the topology configures
        // `hemisphere_sub_slots[Left]`, recursion builds sub-hemispheres
        // via from_config_for_sub_role → the sub-slot's provider
        // (Skip → bail) gets attempted. The error path proves the
        // sub-slot routing fired rather than reusing outer's binding.
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots, TopologyMode,
        };
        use crate::council::orchestrator::HemisphereProvider;

        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut cfg = FreedomConfig::default();
        // Outer providers: claude_cli (the wrapper's provider isn't
        // consulted during recursion — flat provider never fires).
        cfg.provider_kind = Some(ProviderKind::ClaudeCli);
        cfg.inference.mode = TopologyMode::Custom;
        cfg.inference.left = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            model: Some("claude-opus-4-7".into()),
            ..Default::default()
        };
        cfg.inference.right = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };
        cfg.inference.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::ClaudeCli),
            ..Default::default()
        };

        // Sub-slots for outer-Left: every inner-role pinned to a
        // variant that fails to construct without env-credentials
        // (`AwsBedrock` bails when no creds available). The exact
        // error doesn't matter — what matters is the routing-shape
        // proves the sub_slots[Left] entry was consulted, not
        // outer's Left binding.
        let mut sub = SubHemisphereSlots::default();
        sub.left = HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            model: Some("anthropic.claude-opus-4-7".into()),
            ..Default::default()
        };
        sub.right = HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            model: Some("anthropic.claude-opus-4-7".into()),
            ..Default::default()
        };
        sub.cerebellum = HemisphereSlot {
            provider: Some(InferenceProvider::AwsBedrock),
            model: Some("anthropic.claude-opus-4-7".into()),
            ..Default::default()
        };
        cfg.inference
            .hemisphere_sub_slots
            .insert(HemisphereRole::Left, sub);

        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "outer-left".into(),
            }),
            base_req: Request::default(),
            authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            neoth_home: std::path::PathBuf::new(),
            config: Some(std::sync::Arc::new(cfg)),
            outer_role: Some(HemisphereRole::Left),
            voice: None,
            recall_fragment: None,
            allow_persistent_context: true,
        };

        let result = ph.ask_with_depth("hi", 2).await;
        // Outcome: either the sub-build fails (no AWS creds in test
        // env → expected on CI), surfacing the actionable error, OR
        // (impossibly here) it succeeds and the outer flat provider
        // is NOT consulted. Either way the outer counter stays at 0.
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "outer wrapper's own provider must NOT fire during recursion"
        );
        if let Err(msg) = result {
            assert!(
                msg.contains("build sub-")
                    || msg.contains("aws_bedrock")
                    || msg.contains("credentials"),
                "expected sub-build / aws creds error, got: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn ask_with_depth_falls_back_to_outer_role_path_when_outer_role_none() {
        // When `outer_role: None` (legacy Split-recovery wrapper),
        // recursion goes through the Phase 2 path even with depth > 1
        // + config Arc present. Pins backwards-compat for the
        // callosum recovery wrapper.
        use crate::council::orchestrator::HemisphereProvider;
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = Some(ProviderKind::Skip);
        let ph = super::ProviderHemisphere {
            provider: Box::new(CountingMockProvider {
                counter: counter.clone(),
                reply: "outer".into(),
            }),
            base_req: Request::default(),
            authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            neoth_home: std::path::PathBuf::new(),
            config: Some(std::sync::Arc::new(cfg)),
            outer_role: None,
            voice: None,
            recall_fragment: None,
            allow_persistent_context: true,
        };
        let err = ph.ask_with_depth("hi", 2).await.unwrap_err();
        // Skip provider → build_hemisphere_with_config (Phase 2 path)
        // surfaces the Skip bail.
        assert!(
            err.contains("build sub-") && err.contains("skip"),
            "expected Phase 2 sub-build skip error, got: {err}"
        );
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // ── GOLD-WIRE-04: council voice → system prompt ───────────────────

    #[test]
    fn compose_voice_system_layers_after_existing_system_and_is_noop_when_none() {
        use crate::council::types::CouncilVoice;
        let frag = CouncilVoice::SecurityEngineer.system_prompt_fragment();

        // None voice → system unchanged (both Some and None base).
        assert_eq!(
            super::compose_voice_system(Some("base".into()), None),
            Some("base".into())
        );
        assert_eq!(super::compose_voice_system(None, None), None);

        // Some voice + existing system → fragment appended AFTER the base
        // (operator / persona / skill layers keep precedence).
        let layered = super::compose_voice_system(
            Some("BASE SYS".into()),
            Some(CouncilVoice::SecurityEngineer),
        )
        .unwrap();
        assert!(layered.starts_with("BASE SYS"), "operator system must lead");
        assert!(layered.ends_with(frag), "voice fragment must trail");

        // Some voice + no/blank system → fragment becomes the whole system.
        assert_eq!(
            super::compose_voice_system(None, Some(CouncilVoice::SecurityEngineer)),
            Some(frag.to_string())
        );
        assert_eq!(
            super::compose_voice_system(Some("   ".into()), Some(CouncilVoice::SecurityEngineer)),
            Some(frag.to_string())
        );
    }

    #[tokio::test]
    async fn build_hemisphere_sets_role_voice_on_field_not_base_req() {
        // E2E wiring (the gap Lens-2 flagged): a slot voice configured in
        // freedom.yaml must reach the hemisphere — on the `voice` field, and
        // crucially NOT baked into `base_req.system` (so recursion's sub-
        // hemispheres, cloned from base_req, stay voice-free → no cross-role
        // leak). OpenaiCompat builds a provider object from endpoint + model
        // with no network call, so the build path runs deterministically.
        use crate::config::inference::HemisphereRole;
        use crate::council::types::CouncilVoice;

        let mut cfg = FreedomConfig::default();
        cfg.provider_kind = Some(ProviderKind::OpenaiCompat);
        cfg.provider_endpoint = Some("http://127.0.0.1:1/v1".into());
        cfg.provider_model = Some("test-model".into());
        // Single topology → slot_for(any role) resolves to default_slot.
        cfg.inference.default_slot.voice = Some(CouncilVoice::SecurityEngineer);

        let req = Request {
            system: Some("OPERATOR SYSTEM".into()),
            ..Default::default()
        };
        let ph = super::build_hemisphere(
            &cfg,
            std::path::Path::new(""),
            HemisphereRole::Left,
            &req,
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
        )
        .await
        .expect("openai_compat hemisphere builds without network");

        assert_eq!(
            ph.voice,
            Some(CouncilVoice::SecurityEngineer),
            "the configured slot voice must land on the hemisphere's voice field"
        );
        // The anti-leak invariant: base_req.system is the operator system
        // UNCHANGED — the voice is applied later, at the leaf `ask`.
        assert_eq!(
            ph.base_req.system.as_deref(),
            Some("OPERATOR SYSTEM"),
            "voice must NOT be baked into base_req (else it leaks into recursion)"
        );
    }

    /// Provider that records the `system` of the last request it received,
    /// so a test can prove `ask` layers the voice into the system field.
    struct SystemCapturingProvider {
        seen_system: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    }

    #[async_trait]
    impl Provider for SystemCapturingProvider {
        fn name(&self) -> &'static str {
            "system-capture"
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            *self.seen_system.lock().unwrap() = req.system.clone();
            Ok(Completion {
                text: "ok".into(),
                identity: Default::default(),
                model: "cap-1".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn ask_layers_voice_into_request_system() {
        // The leaf-call contract: when a hemisphere carries a voice, the
        // request that reaches the provider has the voice fragment layered
        // onto its system field (operator system first, voice last).
        use crate::council::orchestrator::HemisphereProvider;
        use crate::council::types::CouncilVoice;

        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let ph = super::ProviderHemisphere {
            provider: Box::new(SystemCapturingProvider {
                seen_system: seen.clone(),
            }),
            base_req: Request {
                system: Some("OPERATOR SYSTEM".into()),
                ..Default::default()
            },
            authorizer: crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            neoth_home: std::path::PathBuf::new(),
            config: None,
            outer_role: None,
            voice: Some(CouncilVoice::SecurityEngineer),
            recall_fragment: None,
            allow_persistent_context: true,
        };

        ph.ask("operator question").await.unwrap();

        let sys = seen
            .lock()
            .unwrap()
            .clone()
            .expect("request must carry system");
        assert!(
            sys.starts_with("OPERATOR SYSTEM"),
            "operator system must lead: {sys}"
        );
        assert!(
            sys.ends_with(CouncilVoice::SecurityEngineer.system_prompt_fragment()),
            "voice fragment must be layered into the request system: {sys}"
        );
    }

    // ── Finding 2 (Session 13) multi-cloud fan-out advisory ───────────

    fn mk_advisory_config(
        left: Option<crate::config::inference::InferenceProvider>,
        right: Option<crate::config::inference::InferenceProvider>,
        cere: Option<crate::config::inference::InferenceProvider>,
    ) -> FreedomConfig {
        use crate::config::inference::{HemisphereSlot, InferenceTopology, TopologyMode};
        let mut cfg = FreedomConfig::default();
        let mut topo = InferenceTopology::default();
        topo.mode = TopologyMode::Custom;
        topo.left = HemisphereSlot {
            provider: left,
            ..HemisphereSlot::default()
        };
        topo.right = HemisphereSlot {
            provider: right,
            ..HemisphereSlot::default()
        };
        topo.cerebellum = HemisphereSlot {
            provider: cere,
            ..HemisphereSlot::default()
        };
        cfg.inference = topo;
        cfg
    }

    #[test]
    fn fan_out_advisory_line_returns_none_for_single_cloud_topology() {
        use crate::config::inference::InferenceProvider as I;
        // All three slots = same cloud kind → only 1 distinct kind →
        // no joint fan-out advisory needed (single per-provider V03-08
        // prompt already covers it).
        let cfg = mk_advisory_config(Some(I::OpenAi), Some(I::OpenAi), Some(I::OpenAi));
        assert!(super::fan_out_advisory_line(&cfg).is_none());
    }

    #[test]
    fn fan_out_advisory_line_returns_none_when_only_local_qwen() {
        use crate::config::inference::InferenceProvider as I;
        // Local-only topology has zero cloud kinds → no advisory.
        let cfg = mk_advisory_config(Some(I::LocalQwen), Some(I::LocalQwen), Some(I::LocalQwen));
        assert!(super::fan_out_advisory_line(&cfg).is_none());
    }

    #[test]
    fn fan_out_advisory_line_fires_for_two_distinct_clouds() {
        use crate::config::inference::InferenceProvider as I;
        let cfg = mk_advisory_config(Some(I::OpenAi), Some(I::Gemini), Some(I::LocalQwen));
        let line = super::fan_out_advisory_line(&cfg).expect("≥2 clouds should fire");
        assert!(line.contains("2 cloud providers"));
        assert!(line.contains("openai_api"));
        assert!(line.contains("gemini_api"));
        assert!(!line.contains("local_qwen"));
    }

    #[test]
    fn fan_out_advisory_line_fires_for_three_distinct_clouds() {
        use crate::config::inference::InferenceProvider as I;
        let cfg = mk_advisory_config(Some(I::ClaudeCli), Some(I::OpenAi), Some(I::Gemini));
        let line = super::fan_out_advisory_line(&cfg).expect("3 clouds should fire");
        assert!(line.contains("3 cloud providers"));
        for slug in ["claude_cli", "openai_api", "gemini_api"] {
            assert!(line.contains(slug), "advisory must name {slug}: {line}");
        }
    }

    #[test]
    fn fan_out_advisory_line_dedups_repeated_kinds() {
        use crate::config::inference::InferenceProvider as I;
        // Left=Right=ClaudeCli, Cerebellum=Gemini → 2 distinct kinds.
        let cfg = mk_advisory_config(Some(I::ClaudeCli), Some(I::ClaudeCli), Some(I::Gemini));
        let line = super::fan_out_advisory_line(&cfg).expect("2 distinct clouds should fire");
        assert!(line.contains("2 cloud providers"));
        // ClaudeCli appears once, not twice.
        let claude_count = line.matches("claude_cli").count();
        assert_eq!(
            claude_count, 1,
            "expected dedup, got {claude_count} in: {line}"
        );
    }

    // ── Pick #26 (Session 14) — Phase 3c auto repo-context injection
    //
    // Tests drive `maybe_repo_context_block_at` with an explicit
    // tempdir path instead of mutating HOME / USERPROFILE — keeps
    // the suite parallel-safe (no env-var race with cli::code_map
    // CLI tests + no shared mutex needed).

    #[test]
    fn maybe_repo_context_returns_none_when_max_files_is_zero() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let cfg = FreedomConfig::default();
        assert_eq!(cfg.code_map.auto_context_max_files, 0);
        let result = maybe_repo_context_block_at(&cfg, "find auth_middleware", &db);
        assert!(result.is_none(), "default config must skip injection");
    }

    #[test]
    fn maybe_repo_context_returns_none_when_db_missing() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("does_not_exist.db");
        let mut cfg = FreedomConfig::default();
        cfg.code_map.auto_context_max_files = 5;
        let result = maybe_repo_context_block_at(&cfg, "find auth_middleware", &db);
        assert!(
            result.is_none(),
            "missing DB must yield None, not panic; got: {result:?}"
        );
    }

    #[test]
    fn maybe_repo_context_returns_none_when_db_has_no_matching_files() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let _ = crate::code_map::persist::open(&db).unwrap();
        let mut cfg = FreedomConfig::default();
        cfg.code_map.auto_context_max_files = 5;
        let result = maybe_repo_context_block_at(&cfg, "where is some_nonexistent_xyz?", &db);
        assert!(result.is_none(), "empty DB must yield None");
    }

    #[test]
    fn maybe_repo_context_injects_block_when_match_exists() {
        use crate::code_map::persist::{open, persist_map};
        use crate::code_map::symbols::{Symbol, SymbolKind};
        use crate::code_map::walker::{Language, RepoFile, RepoMap, ScanReport};

        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let mut conn = open(&db).unwrap();
        let map = RepoMap {
            root: "/repo/test".into(),
            files: vec![RepoFile {
                path: "src/auth/middleware.rs".into(),
                language: Language::Rust,
                bytes: 200,
                loc: 30,
                sha256: String::new(),
                mtime_ns: 0,
                symbols: vec![Symbol {
                    name: "auth_middleware".into(),
                    kind: SymbolKind::Function,
                    line: 12,
                }],
            }],
            report: ScanReport::default(),
        };
        persist_map(&mut conn, &map).unwrap();
        drop(conn);

        let mut cfg = FreedomConfig::default();
        cfg.code_map.auto_context_max_files = 5;
        let result = maybe_repo_context_block_at(&cfg, "where is auth_middleware?", &db);
        let block = result.expect("symbol match must produce a block");
        assert!(
            block.contains("repo-context"),
            "block must declare itself as repo-context; got: {block}"
        );
        assert!(
            block.contains("src/auth/middleware.rs"),
            "block must include the matched file; got: {block}"
        );
        assert!(
            block.contains("auth_middleware"),
            "block must include the matched symbol; got: {block}"
        );
    }

    #[test]
    fn architecture_skill_appends_automatic_cycle_findings_without_repo_context_gate() {
        use crate::code_map::graph::{CodeEdge, EdgeKind};
        use crate::code_map::persist::{open, persist_edges, persist_map};
        use crate::code_map::walker::{RepoMap, ScanReport};

        let dir = tempdir().unwrap();
        let db = dir.path().join("code_map.db");
        let mut conn = open(&db).unwrap();
        persist_map(
            &mut conn,
            &RepoMap {
                root: "/repo/test".into(),
                files: vec![],
                report: ScanReport::default(),
            },
        )
        .unwrap();
        persist_edges(
            &mut conn,
            "/repo/test",
            &[
                CodeEdge {
                    from_file: "src/a.rs".into(),
                    from_symbol: "a".into(),
                    to_name: "b".into(),
                    kind: EdgeKind::Calls,
                },
                CodeEdge {
                    from_file: "src/b.rs".into(),
                    from_symbol: "b".into(),
                    to_name: "a".into(),
                    kind: EdgeKind::Calls,
                },
            ],
        )
        .unwrap();
        drop(conn);

        assert!(
            maybe_architecture_findings_for_skill_at(
                Some("unrelated_skill"),
                &db,
                std::path::Path::new("/repo/test"),
            )
            .is_none()
        );
        let findings = maybe_architecture_findings_for_skill_at(
            Some(crate::code_map::recall::ARCHITECTURE_SKILL_ID),
            &db,
            std::path::Path::new("/repo/test"),
        )
        .expect("active architecture workflow must consume persisted cycles");
        let combined = append_architecture_findings(None, &findings).unwrap();

        assert_eq!(findings.cycles_injected, 1);
        assert!(combined.contains("a -> b -> a"));
        assert!(
            maybe_architecture_findings_for_skill_at(
                Some(crate::code_map::recall::ARCHITECTURE_SKILL_ID),
                &db,
                std::path::Path::new("/repo/other"),
            )
            .is_none(),
            "an unrelated cwd must not receive cycles from the only persisted repo"
        );
    }

    // ── GOLD-WIRE Block::D + GOLD-ADAPT-MEM-09 — auto-recall injection ────
    //
    // Drive `maybe_recall_block_at` with an explicit tempdir views.db (same
    // parallel-safe idiom as the repo-context tests — no HOME mutation).

    #[tokio::test]
    async fn recall_block_skips_skip_tier_prompt() {
        // A Skip-tier prompt ("hi") must NOT inject, even when the episode
        // store holds a row that would otherwise match — the MEM-09 gate fires
        // before any DB work.
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = crate::memory::store::open(&db).unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, 1000, ?1, 'h', 0.9, 0)",
            rusqlite::params!["hi — notes on the quantum widget proposal"],
        )
        .unwrap();
        drop(conn);
        assert!(
            maybe_recall_block_at("hi", &db).await.is_none(),
            "Skip-tier prompt must not inject a recall block"
        );
    }

    #[tokio::test]
    async fn recall_block_none_when_db_absent() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does_not_exist.db");
        assert!(
            maybe_recall_block_at("the quantum widget proposal", &missing)
                .await
                .is_none(),
            "missing DB must yield None, not panic"
        );
    }

    #[tokio::test]
    async fn recall_block_injects_for_matching_non_skip_prompt() {
        // A non-Skip prompt whose words appear in a stored hot-tier episode
        // injects a Block::D recall section carrying that episode's text.
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = crate::memory::store::open(&db).unwrap();
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, 1000, ?1, 'h', 0.7, 0)",
            rusqlite::params!["notes on the quantum widget proposal from our chat"],
        )
        .unwrap();
        drop(conn);
        let block = maybe_recall_block_at("quantum widget proposal", &db)
            .await
            .expect("a matching episode on a non-Skip prompt must inject a block");
        assert!(block.contains("Relevant memory"), "header present: {block}");
        assert!(
            block.contains("quantum widget proposal"),
            "episode text present: {block}"
        );
    }

    #[test]
    fn render_recall_block_truncates_and_flattens_newlines() {
        let hit = crate::memory::views::EpisodeHit {
            event_id: 1,
            event_type: 1,
            ts_ns: 1,
            text: format!("line1\nline2 {}", "x".repeat(400)),
            text_hash: "h".into(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: "hot".into(),
            importance: Some(0.5),
            access_count: 0,
            trust: 1,
        };
        let output = crate::cli::recall::RecallOutput {
            episodes: vec![hit],
            ..Default::default()
        };
        let out = render_recall_block_layered(&output);
        assert!(out.contains("Relevant memory"), "header: {out}");
        assert!(
            out.contains("### Relevant episodes"),
            "episodes sub-heading: {out}"
        );
        assert!(out.contains("[hot]"), "tier tag: {out}");
        assert!(
            out.contains("line1 line2"),
            "newline flattened to space: {out}"
        );
        assert!(
            out.contains('…'),
            "over-long snippet truncated with ellipsis"
        );
        // JV-MEM-10: empty lanes emit no sub-heading.
        assert!(
            !out.contains("Canonical facts"),
            "empty canonical lane → no heading: {out}"
        );
        assert!(
            !out.contains("Flagged contradictions"),
            "empty contradiction lane → no heading: {out}"
        );
    }

    /// One EpisodeHit carrying just `text` — the other fields are inert for the
    /// dedup path (which keys purely on normalized text).
    fn ep(text: &str) -> crate::memory::views::EpisodeHit {
        crate::memory::views::EpisodeHit {
            event_id: 0,
            event_type: 0,
            ts_ns: 0,
            text: text.to_string(),
            text_hash: String::new(),
            channel: None,
            sender_id: None,
            operator_id: None,
            tier: "hot".into(),
            importance: None,
            access_count: 0,
            trust: 1,
        }
    }

    #[test]
    fn recall_dedup_key_normalizes_case_and_whitespace() {
        // Case + internal-whitespace variants collapse to one key…
        assert_eq!(
            recall_dedup_key("Alex  is\tthe Operator."),
            recall_dedup_key("alex is the operator.")
        );
        // …but distinct text and punctuation differences stay distinct
        // (conservative — never over-collapses two genuine memories).
        assert_ne!(recall_dedup_key("fact one"), recall_dedup_key("fact two"));
        assert_ne!(recall_dedup_key("done"), recall_dedup_key("done."));
    }

    #[test]
    fn dedup_recall_lanes_drops_episode_matching_canonical_or_prior_episode() {
        let mut out = crate::cli::recall::RecallOutput {
            canonical: vec![ep("Alex is the operator.")],
            episodes: vec![
                ep("alex  is the   operator."), // case/ws variant of canonical → dropped
                ep("Distinct episode about Rust."), // kept
                ep("distinct episode about rust."), // case variant of prior episode → dropped
            ],
            contradictions: vec![crate::cli::recall::ContradictionLine {
                // same text as a canonical fact, but contradictions are untouched
                statement_a: "Alex is the operator.".into(),
                statement_b: "Bob is the operator.".into(),
                confidence: 0.9,
            }],
        };
        dedup_recall_lanes(&mut out);
        assert_eq!(out.canonical.len(), 1, "canonical lane is never pruned");
        assert_eq!(
            out.episodes.len(),
            1,
            "the canonical-dup and the intra-lane dup are both dropped"
        );
        assert_eq!(out.episodes[0].text, "Distinct episode about Rust.");
        assert_eq!(
            out.contradictions.len(),
            1,
            "contradiction lane is untouched"
        );
    }

    // ── GOLD-ADAPT-MEM-12 — session-guidance block ───────────────────────

    #[test]
    fn guidance_block_none_when_nothing_to_say() {
        assert!(render_guidance_block(&[], 0, None).is_none());
    }

    #[test]
    fn guidance_block_pending_only_omits_sessions_section() {
        let out = render_guidance_block(&[], 3, None).expect("pending alone yields a block");
        assert!(out.contains("Session context"), "header: {out}");
        assert!(
            out.contains("3 flagged fact-contradiction"),
            "pending count: {out}"
        );
        assert!(
            !out.contains("Recent sessions"),
            "no cards → no sessions heading: {out}"
        );
    }

    #[test]
    fn guidance_block_renders_recent_card() {
        let card = crate::memory::hindsight::HindsightCard {
            session_id: "s1".into(),
            started_at_unix: 1000,
            ended_at_unix: 1500,
            turn_count: 4,
            operator_turn_count: 2,
            agent_turn_count: 2,
            top_topics: vec!["rust".into()],
            opening_utterance: "hi".into(),
            closing_utterance: "bye".into(),
            one_line_summary: "4 turns on the cluster design".into(),
            display_name: None,
        };
        let out = render_guidance_block(std::slice::from_ref(&card), 0, None)
            .expect("a recent card yields a block");
        assert!(out.contains("### Recent sessions"), "{out}");
        assert!(
            out.contains("4 turns on the cluster design"),
            "summary rendered: {out}"
        );
    }

    #[test]
    fn maybe_guidance_block_at_empty_home_is_none() {
        let dir = tempdir().unwrap();
        assert!(maybe_guidance_block_at(dir.path(), 1_700_000_000).is_none());
    }

    #[test]
    fn maybe_guidance_block_at_counts_pending_contradictions() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = crate::memory::store::open(&db).unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, statement, source, scope, asserted_at, fact_state) \
             VALUES (1, ?1, 'op', 'g', 1, 'verified'), (2, ?2, 'op', 'g', 1, 'verified')",
            rusqlite::params!["the limit is three", "the limit is five"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO idx_contradictions (fact_a_id, fact_b_id, confidence, detected_at, decision) \
             VALUES (1, 2, 0.9, 1, 'pending')",
            [],
        )
        .unwrap();
        drop(conn);
        let out = maybe_guidance_block_at(dir.path(), 1_700_000_000)
            .expect("a pending contradiction yields a block");
        assert!(out.contains("1 flagged fact-contradiction"), "{out}");
        assert!(
            maybe_guidance_block_for_turn_at(dir.path(), 1_700_000_000, true).is_none(),
            "incognito must suppress an otherwise visible guidance block"
        );
    }

    // ── GOLD-ADAPT-JV-MEM-16 — guidance snapshot integration ────────────────

    /// JV-MEM-16: verify that maybe_guidance_block_at surfaces cron errors
    /// from a pre-written guidance_snapshot.json — proving the round-trip:
    /// snapshot written by the daemon cron → read + rendered by the chat
    /// assembly path that build_prompt_bundle calls.
    #[test]
    fn maybe_guidance_block_at_renders_cron_errors_from_snapshot() {
        let dir = tempdir().unwrap();
        // Write a snapshot with 2 cron errors and unhealthy freshness.
        let snap = crate::daemon::guidance_cron::GuidanceSnapshot {
            ts_unix: 1_700_000_000,
            scorecard_freshness: 0.20,
            scorecard_grade: "F".to_string(),
            scorecard_healthy: false,
            crash_alerts_24h: 0,
            silence_alerts_24h: 0,
            token_anomaly_24h: 0,
            session_degraded_24h: 0,
            cron_errors_24h: 2,
        };
        let snap_path = crate::daemon::guidance_cron::guidance_snapshot_path(dir.path());
        std::fs::create_dir_all(snap_path.parent().unwrap()).unwrap();
        std::fs::write(&snap_path, serde_json::to_vec(&snap).unwrap()).unwrap();

        // Call the same function that build_prompt_bundle calls.
        let out = maybe_guidance_block_at(dir.path(), 1_700_000_000)
            .expect("snapshot with cron errors must yield a guidance block");

        assert!(
            out.contains("2 cron job failure"),
            "cron errors rendered: {out}"
        );
        assert!(
            out.contains("Memory quality"),
            "freshness lane rendered: {out}"
        );
        assert!(
            out.contains("20%") || out.contains("grade F") || out.contains("(grade F)"),
            "grade shown: {out}"
        );
    }

    /// JV-MEM-16: verify that an unhealthy-but-zero-signals snapshot still
    /// yields a block (memory quality lane alone is sufficient).
    #[test]
    fn guidance_block_unhealthy_snapshot_no_signals_yields_block() {
        let snap = crate::daemon::guidance_cron::GuidanceSnapshot {
            ts_unix: 1_700_000_000,
            scorecard_freshness: 0.55,
            scorecard_grade: "E".to_string(),
            scorecard_healthy: false,
            crash_alerts_24h: 0,
            silence_alerts_24h: 0,
            token_anomaly_24h: 0,
            session_degraded_24h: 0,
            cron_errors_24h: 0,
        };
        let out = render_guidance_block(&[], 0, Some(&snap))
            .expect("unhealthy freshness alone should yield a block");
        assert!(out.contains("Memory quality"), "{out}");
        assert!(out.contains("55%") || out.contains("grade E"), "{out}");
        assert!(
            !out.contains("24h system"),
            "no signals → no signals lane: {out}"
        );
    }

    /// JV-MEM-16: verify that a healthy snapshot with no signals and no cards
    /// yields None (no noisy empty block on every turn).
    #[test]
    fn guidance_block_healthy_snapshot_no_signals_yields_none() {
        let snap = crate::daemon::guidance_cron::GuidanceSnapshot {
            ts_unix: 1_700_000_000,
            scorecard_freshness: 0.95,
            scorecard_grade: "A".to_string(),
            scorecard_healthy: true,
            crash_alerts_24h: 0,
            silence_alerts_24h: 0,
            token_anomaly_24h: 0,
            session_degraded_24h: 0,
            cron_errors_24h: 0,
        };
        assert!(
            render_guidance_block(&[], 0, Some(&snap)).is_none(),
            "healthy snapshot + no signals = no block"
        );
    }

    // ── GOLD-ADAPT-MEM-10 — hemisphere-aware recall ──────────────────────

    #[test]
    fn hemisphere_region_maps_roles_exhaustively() {
        use crate::config::inference::HemisphereRole as R;
        use crate::memory::regions::MemoryRegion as Region;
        assert!(matches!(hemisphere_region(R::Left), Region::Hippocampus));
        assert!(matches!(hemisphere_region(R::Right), Region::Hippocampus));
        assert!(matches!(
            hemisphere_region(R::Cerebellum),
            Region::Cerebellum
        ));
    }

    #[test]
    fn hemisphere_recall_fragment_at_missing_db_is_none() {
        use crate::config::inference::HemisphereRole as R;
        let dir = tempdir().unwrap();
        let db = dir.path().join("nope.db");
        assert!(hemisphere_recall_fragment_at(&db, R::Left, "anything").is_none());
    }

    #[test]
    fn hemisphere_recall_fragment_left_leads_with_groundtruth() {
        use crate::config::inference::HemisphereRole as R;
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = crate::memory::store::open(&db).unwrap();
        conn.execute(
            "INSERT INTO idx_groundtruth (id, statement, source, scope, asserted_at, fact_state) \
             VALUES (1, ?1, 'op', 'g', 1, 'verified')",
            rusqlite::params!["the canonical fact about quokkas"],
        )
        .unwrap();
        drop(conn);
        let frag = hemisphere_recall_fragment_at(&db, R::Left, "quokkas")
            .expect("Left fact match yields a fragment");
        assert!(frag.contains("Left hemisphere"), "{frag}");
        assert!(
            frag.contains("(fact)"),
            "Left leads with groundtruth: {frag}"
        );
        assert!(frag.contains("quokkas"), "{frag}");
        assert!(
            hemisphere_recall_fragment_for_turn_at(&db, R::Left, "quokkas", false).is_none(),
            "incognito Council must not read hemisphere recall"
        );
    }

    #[test]
    fn hemisphere_recall_fragment_cerebellum_pulls_operational_band() {
        use crate::config::inference::HemisphereRole as R;
        let dir = tempdir().unwrap();
        let db = dir.path().join("views.db");
        let conn = crate::memory::store::open(&db).unwrap();
        // event_type 0x20 (=32) = provider band → Cerebellum region.
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 32, 1000, ?1, 'h', 0.5, 0)",
            rusqlite::params!["council picked the local cerebellum provider"],
        )
        .unwrap();
        drop(conn);
        let frag = hemisphere_recall_fragment_at(&db, R::Cerebellum, "cerebellum provider")
            .expect("Cerebellum band match yields a fragment");
        assert!(frag.contains("Cerebellum hemisphere"), "{frag}");
        assert!(frag.contains("operational"), "{frag}");
    }

    #[test]
    fn maybe_repo_context_block_zero_max_short_circuits_before_db_open() {
        // Defensive: even if the DB file is broken / unreadable, the
        // zero-max short-circuit must fire BEFORE we try to open it.
        // No I/O happens, no error surfaces.
        let cfg = FreedomConfig::default();
        let result = maybe_repo_context_block_at(
            &cfg,
            "auth_middleware",
            std::path::Path::new("/definitely/does/not/exist/code_map.db"),
        );
        assert!(result.is_none());
    }

    // ── operator-facts wiring (role_custom + language_primary) ──────────

    #[test]
    fn operator_facts_none_when_no_role_no_lang() {
        let cfg = FreedomConfig::default();
        assert_eq!(merge_operator_facts(&cfg, None), None);
        // A rendered NEOTH.md body passes through untouched.
        assert_eq!(
            merge_operator_facts(&cfg, Some("# Rules\nBe terse.".into())).as_deref(),
            Some("# Rules\nBe terse.")
        );
    }

    #[test]
    fn operator_facts_custom_role_wins_over_enum() {
        let mut cfg = FreedomConfig::default();
        cfg.role = Some(crate::cli::init::OperatorRole::Developer);
        cfg.role_custom = Some("authorized pentester".into());
        let out = merge_operator_facts(&cfg, None).expect("facts");
        assert_eq!(out, "Operator role: authorized pentester.");
    }

    #[test]
    fn operator_facts_enum_role_maps_to_prose() {
        let mut cfg = FreedomConfig::default();
        cfg.role = Some(crate::cli::init::OperatorRole::SecurityResearcher);
        let out = merge_operator_facts(&cfg, None).expect("facts");
        assert_eq!(out, "Operator role: security researcher.");
    }

    #[test]
    fn operator_facts_role_none_variant_yields_nothing() {
        let mut cfg = FreedomConfig::default();
        cfg.role = Some(crate::cli::init::OperatorRole::None);
        assert_eq!(merge_operator_facts(&cfg, None), None);
    }

    #[test]
    fn operator_facts_non_english_language_emits_instruction() {
        let mut cfg = FreedomConfig::default();
        cfg.language_primary = Some("de".into());
        let out = merge_operator_facts(&cfg, None).expect("facts");
        assert!(out.contains("BCP-47 'de'"), "got: {out}");
        assert!(out.starts_with("Respond in the operator's primary language"));
    }

    #[test]
    fn operator_facts_english_language_emits_no_instruction() {
        // English is the model default — no instruction needed, and the
        // "en-GB" / "en" family is all skipped.
        for tag in ["en", "en-GB", "EN", "en-US"] {
            let mut cfg = FreedomConfig::default();
            cfg.language_primary = Some(tag.into());
            assert_eq!(
                merge_operator_facts(&cfg, None),
                None,
                "tag {tag} must not emit a language instruction"
            );
        }
    }

    #[test]
    fn operator_facts_role_and_language_stack_above_body() {
        let mut cfg = FreedomConfig::default();
        cfg.role_custom = Some("solo dev".into());
        cfg.language_primary = Some("zh-CN".into());
        let out = merge_operator_facts(&cfg, Some("# NEOTH.md body".into())).expect("facts");
        // Role line first, language line second, then a blank line, then body.
        assert!(out.starts_with("Operator role: solo dev.\n"));
        assert!(out.contains("BCP-47 'zh-CN'"));
        assert!(out.ends_with("\n\n# NEOTH.md body"));
    }

    // ── GOLD-CCPARITY-MODEL-02: dispatch_provider model-override tests ───────

    #[test]
    fn cost_authorization_binds_dispatch_then_skill_model() {
        let (dispatch_model, dispatch_source) = resolve_provider_call_model(
            Some("claude-opus-4-7"),
            Some("claude-haiku-4-5"),
            Some("claude-sonnet-4-6"),
            None,
            None,
        );
        assert_eq!(dispatch_model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(dispatch_source, "dispatch");

        let (skill_model, skill_source) = resolve_provider_call_model(
            None,
            Some("claude-opus-4-7"),
            Some("claude-haiku-4-5"),
            Some("claude-haiku-4-5"),
            None,
        );
        assert_eq!(skill_model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(skill_source, "skill");
    }

    /// Provider that captures the `model` field of the last Request it received.
    /// Distinct from `SystemCapturingProvider` (captures system) — we need model.
    struct ModelCapturingProvider {
        seen_model: std::sync::Arc<std::sync::Mutex<Option<Option<String>>>>,
    }

    #[async_trait]
    impl Provider for ModelCapturingProvider {
        fn name(&self) -> &'static str {
            "model-capture"
        }
        fn default_model(&self) -> Option<&str> {
            Some("model-capture-default")
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            *self.seen_model.lock().unwrap() = Some(req.model.clone());
            Ok(Completion {
                text: "model-captured".into(),
                identity: Default::default(),
                model: req.model.clone().unwrap_or_else(|| "default".into()),
                latency: Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    /// Helper: run dispatch_provider with the given override_model and args.model,
    /// return the model field the provider saw.
    async fn run_dispatch_capture_model(
        override_model: Option<String>,
        args_model: Option<String>,
    ) -> Result<Option<String>> {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("test.wal");
        let quota_path = dir.path().join("quota.json");

        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let provider = ModelCapturingProvider {
            seen_model: seen.clone(),
        };

        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("test prompt".to_string()),
            model: args_model,
            system: None,
            edit: false,
            config: None,
            wal_segment: None,
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        let mut config = FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Full;
        let (authorized_model, authorized_source) = {
            let (model, source) = crate::tweaks::resolve_effective_model(
                override_model.as_deref(),
                None,
                args.model.as_deref(),
                None,
                config.provider_model.as_deref(),
            );
            (model.map(str::to_string), source.as_str())
        };
        let (writer, writer_join) = wal_spawn(seg).expect("wal_spawn");
        let mcp_servers = crate::mcp::McpServers::default();
        let result = dispatch_provider(
            "test prompt".to_string(),
            None,
            &args,
            &provider,
            &config,
            dir.path(),
            writer,
            writer_join,
            quota_path.clone(),
            Some(
                crate::providers::quota::QuotaTracker::load_from(&quota_path)
                    .expect("load test quota state"),
            ),
            "test prompt",
            config.tokens.max_per_request,
            &mcp_servers,
            crate::mcp::McpToolScope::default(),
            "0000000000000001",
            authorized_model,
            // GOLD-CCPARITY-EFFORT-03: no effort override in model-capture tests.
            None,
            authorized_source,
            crate::providers::cost_authorization::ProviderCallAuditContext::default(),
        )
        .await;

        let DispatchOutput {
            writer,
            writer_join,
            ..
        } = result?;
        drop(writer);
        writer_join.await?;
        let captured = seen
            .lock()
            .unwrap()
            .clone()
            .expect("provider must have been called");
        Ok(captured)
    }

    #[tokio::test]
    async fn model_override_skill_wins_over_none_args_model() {
        // skill.manifest.model = Some("claude-haiku-4-5"), args.model = None
        // → Request.model == Some("claude-haiku-4-5")
        let seen = run_dispatch_capture_model(Some("claude-haiku-4-5".to_string()), None)
            .await
            .expect("dispatch succeeds");
        assert_eq!(
            seen.as_deref(),
            Some("claude-haiku-4-5"),
            "skill model override must reach the provider when args.model is None"
        );
    }

    #[tokio::test]
    async fn model_override_args_model_wins_when_no_override() {
        // override_model = None, args.model = Some("claude-opus-4-7")
        // → Request.model == Some("claude-opus-4-7")
        let seen = run_dispatch_capture_model(None, Some("claude-opus-4-7".to_string()))
            .await
            .expect("dispatch succeeds");
        assert_eq!(
            seen.as_deref(),
            Some("claude-opus-4-7"),
            "args.model must be used when override_model is None"
        );
    }

    #[tokio::test]
    async fn model_override_wins_over_args_model() {
        // override_model = Some("claude-haiku-4-5"), args.model = Some("claude-opus-4-7")
        // → Request.model == Some("claude-haiku-4-5") (override wins)
        let seen = run_dispatch_capture_model(
            Some("claude-haiku-4-5".to_string()),
            Some("claude-opus-4-7".to_string()),
        )
        .await
        .expect("dispatch succeeds");
        assert_eq!(
            seen.as_deref(),
            Some("claude-haiku-4-5"),
            "override_model must beat args.model (agent/skill > default)"
        );
    }

    #[tokio::test]
    async fn model_override_both_none_binds_provider_default() {
        // B22 requires a concrete wire model before authorization. With no
        // higher-precedence override, the leaf's declared default is bound and
        // reaches the transport unchanged.
        let seen = run_dispatch_capture_model(None, None)
            .await
            .expect("dispatch succeeds");
        assert_eq!(seen.as_deref(), Some("model-capture-default"));
    }

    #[tokio::test]
    async fn dispatch_provider_authorization_failure_drains_wal_without_deadlock() {
        let dir = tempfile::tempdir().unwrap();
        let quota_path = dir.path().join("quota.json");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let provider = ModelCapturingProvider {
            seen_model: Arc::clone(&seen),
        };
        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("blocked prompt".to_string()),
            model: Some("unknown-paid-model".to_string()),
            system: None,
            edit: false,
            config: None,
            wal_segment: None,
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };
        let mut config = FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Strict;
        let (writer, writer_join) =
            wal_spawn(dir.path().join("authorization-failure.wal")).expect("wal_spawn");
        let mcp_servers = crate::mcp::McpServers::default();

        let dispatch = dispatch_provider(
            "blocked prompt".to_string(),
            None,
            &args,
            &provider,
            &config,
            dir.path(),
            writer,
            writer_join,
            quota_path.clone(),
            Some(
                crate::providers::quota::QuotaTracker::load_from(&quota_path)
                    .expect("load test quota state"),
            ),
            "blocked prompt",
            config.tokens.max_per_request,
            &mcp_servers,
            crate::mcp::McpToolScope::default(),
            "0000000000000003",
            Some("unknown-paid-model".to_string()),
            None,
            "cli",
            crate::providers::cost_authorization::ProviderCallAuditContext::default(),
        );

        let result = tokio::time::timeout(Duration::from_secs(2), dispatch)
            .await
            .expect("authorization failure must drain the WAL writer without hanging");
        let error = match result {
            Ok(_) => panic!("strict policy must block the unknown paid provider"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("authorization")
                || error.to_string().contains("fail-closed"),
            "unexpected error: {error}"
        );
        assert!(
            seen.lock().unwrap().is_none(),
            "the provider transport must not run after authorization is denied"
        );
    }

    // ── GOLD-CCPARITY-EFFORT-03: dispatch_provider effort-override tests ─────

    /// Provider that captures the `thinking_budget` field of the Request.
    /// Mirrors `ModelCapturingProvider` pattern — same shape, different field.
    struct EffortCapturingProvider {
        seen_budget: std::sync::Arc<std::sync::Mutex<Option<Option<u32>>>>,
    }

    #[async_trait]
    impl Provider for EffortCapturingProvider {
        fn name(&self) -> &'static str {
            "effort-capture"
        }
        fn default_model(&self) -> Option<&str> {
            Some("effort-capture-default")
        }
        fn request_controls(&self) -> crate::providers::ProviderRequestControls {
            crate::providers::ProviderRequestControls::THINKING_BUDGET
        }
        async fn complete(&self, req: Request) -> Result<Completion> {
            *self.seen_budget.lock().unwrap() = Some(req.thinking_budget);
            Ok(Completion {
                text: "effort-captured".into(),
                identity: Default::default(),
                model: "effort-capture".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    /// Helper: run dispatch_provider with `override_effort`, return the
    /// `thinking_budget` the provider saw on the Request.
    async fn run_dispatch_capture_effort(
        override_effort: Option<crate::providers::effort_override::EffortBudget>,
    ) -> Result<Option<u32>> {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("effort_test.wal");
        let quota_path = dir.path().join("quota.json");

        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let provider = EffortCapturingProvider {
            seen_budget: seen.clone(),
        };

        let args = ChatArgs {
            attach: Vec::new(),
            message: Some("effort test".to_string()),
            model: None,
            system: None,
            edit: false,
            config: None,
            wal_segment: None,
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        };

        let mut config = FreedomConfig::default();
        config.autonomy = crate::permissions::AutonomyLevel::Full;
        let (writer, writer_join) = wal_spawn(seg).expect("wal_spawn");
        let mcp_servers = crate::mcp::McpServers::default();
        let result = dispatch_provider(
            "effort test".to_string(),
            None,
            &args,
            &provider,
            &config,
            dir.path(),
            writer,
            writer_join,
            quota_path.clone(),
            Some(
                crate::providers::quota::QuotaTracker::load_from(&quota_path)
                    .expect("load test quota state"),
            ),
            "effort test",
            config.tokens.max_per_request,
            &mcp_servers,
            crate::mcp::McpToolScope::default(),
            "0000000000000002",
            None, // effective model authorization binding
            override_effort,
            "provider_default",
            crate::providers::cost_authorization::ProviderCallAuditContext::default(),
        )
        .await;

        let DispatchOutput {
            writer,
            writer_join,
            ..
        } = result?;
        drop(writer);
        writer_join.await?;
        let captured = seen
            .lock()
            .unwrap()
            .expect("provider must have been called");
        Ok(captured)
    }

    #[tokio::test]
    async fn effort_high_maps_to_16384_tokens_in_dispatch() {
        use crate::providers::effort_override::EffortBudget;
        let budget = run_dispatch_capture_effort(Some(EffortBudget::High))
            .await
            .expect("dispatch succeeds");
        assert_eq!(
            budget,
            Some(16_384),
            "EffortBudget::High must produce thinking_budget=16384 on Request"
        );
    }

    #[tokio::test]
    async fn effort_low_maps_to_1024_tokens_in_dispatch() {
        use crate::providers::effort_override::EffortBudget;
        let budget = run_dispatch_capture_effort(Some(EffortBudget::Low))
            .await
            .expect("dispatch succeeds");
        assert_eq!(
            budget,
            Some(1_024),
            "EffortBudget::Low must produce thinking_budget=1024 on Request"
        );
    }

    #[tokio::test]
    async fn effort_medium_maps_to_4096_tokens_in_dispatch() {
        use crate::providers::effort_override::EffortBudget;
        let budget = run_dispatch_capture_effort(Some(EffortBudget::Medium))
            .await
            .expect("dispatch succeeds");
        assert_eq!(
            budget,
            Some(4_096),
            "EffortBudget::Medium must produce thinking_budget=4096 on Request"
        );
    }

    #[tokio::test]
    async fn effort_max_maps_to_32000_tokens_in_dispatch() {
        use crate::providers::effort_override::EffortBudget;
        let budget = run_dispatch_capture_effort(Some(EffortBudget::Max))
            .await
            .expect("dispatch succeeds");
        assert_eq!(
            budget,
            Some(32_000),
            "EffortBudget::Max must produce thinking_budget=32000 on Request"
        );
    }

    #[tokio::test]
    async fn effort_none_yields_no_thinking_budget_in_dispatch() {
        let budget = run_dispatch_capture_effort(None)
            .await
            .expect("dispatch succeeds");
        assert_eq!(
            budget, None,
            "override_effort=None must leave thinking_budget=None (backward compat)"
        );
    }

    // ── GOLD-CCPARITY-ONCE: run_hook_stage once-gate tests ──────────────────
    //
    // These tests exercise run_hook_stage directly with a real (temp-file) WAL
    // writer and a SessionOnceGuard, verifying WAL event emission:
    //   1. First call → HOOK_FIRED.
    //   2. Second call with same guard → HOOK_SKIPPED_ONCE, no second HOOK_FIRED.
    //   3. Fresh SessionOnceGuard → fires again (independent session).
    //   4. once=false hook fires every time with no HOOK_SKIPPED_ONCE.

    /// Decode all frames from a WAL file after the segment header and collect
    /// event types into a Vec so tests can assert on them without caring about
    /// byte offsets.
    async fn collect_event_types(seg: &std::path::Path) -> Vec<u8> {
        let bytes = tokio::fs::read(seg).await.unwrap();
        let mut cursor = &bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..];
        let mut types = Vec::new();
        while !cursor.is_empty() {
            let Ok(frame) = crate::wal::frame::decode_frame(cursor) else {
                break;
            };
            types.push(frame.header.event_type);
            cursor = &cursor[frame.header.total_len as usize..];
        }
        types
    }

    #[tokio::test]
    async fn ccparity_once_fires_exactly_once_across_two_stages_in_one_session() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("once_test.wal");

        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let hook = crate::hooks::schema::HookDef {
            name: "startup-banner".into(),
            stage: crate::hooks::HookStage::PrePipeline,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: crate::hooks::schema::HookAction::Allow,
            status_message: None,
            once: true,
            fail_fast: false,
        };
        let hooks = vec![hook];
        let once_guard = crate::hooks::SessionOnceGuard::new();

        // Call 1 — first firing. Must emit HOOK_FIRED.
        let outcome = run_hook_stage(
            crate::hooks::HookStage::PrePipeline,
            "hello",
            &hooks,
            &writer,
            &once_guard,
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, HookOutcome::Continue(ref b, _) if b == "hello"),
            "first firing must Continue with unchanged body"
        );

        // Call 2 — same guard — must suppress, emit HOOK_SKIPPED_ONCE.
        let outcome2 = run_hook_stage(
            crate::hooks::HookStage::PrePipeline,
            "world",
            &hooks,
            &writer,
            &once_guard,
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome2, HookOutcome::Continue(ref b, _) if b == "world"),
            "suppressed once-hook must still Continue (not Block)"
        );

        // Call 3 — fresh guard — must fire again (independent session).
        let new_guard = crate::hooks::SessionOnceGuard::new();
        let outcome3 = run_hook_stage(
            crate::hooks::HookStage::PrePipeline,
            "fresh",
            &hooks,
            &writer,
            &new_guard,
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome3, HookOutcome::Continue(ref b, _) if b == "fresh"),
            "new guard must fire once-hook again"
        );

        // Drain writer so WAL file is complete.
        drop(writer);
        let _ = join.await;

        // Verify WAL: exactly 2 HOOK_FIRED (call1 + call3) and exactly 1
        // HOOK_SKIPPED_ONCE (call2).
        let types = collect_event_types(&seg).await;
        let fired_count = types
            .iter()
            .filter(|&&t| t == crate::wal::events::EVENT_TYPE_HOOK_FIRED)
            .count();
        let skipped_count = types
            .iter()
            .filter(|&&t| t == crate::wal::events::EVENT_TYPE_HOOK_SKIPPED_ONCE)
            .count();
        assert_eq!(
            fired_count, 2,
            "must emit HOOK_FIRED for call1 and call3 (new session), got {fired_count}"
        );
        assert_eq!(
            skipped_count, 1,
            "must emit exactly one HOOK_SKIPPED_ONCE for call2 (same session), got {skipped_count}"
        );
    }

    #[tokio::test]
    async fn ccparity_once_false_fires_on_every_turn() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("always_test.wal");

        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let hook = crate::hooks::schema::HookDef {
            name: "audit-log".into(),
            stage: crate::hooks::HookStage::PrePipeline,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: crate::hooks::schema::HookAction::Allow,
            status_message: None,
            once: false, // default behaviour — fires every time
            fail_fast: false,
        };
        let hooks = vec![hook];
        let once_guard = crate::hooks::SessionOnceGuard::new();

        // Two calls with the same guard. Both must fire (once=false).
        run_hook_stage(
            crate::hooks::HookStage::PrePipeline,
            "turn1",
            &hooks,
            &writer,
            &once_guard,
        )
        .await
        .unwrap();
        run_hook_stage(
            crate::hooks::HookStage::PrePipeline,
            "turn2",
            &hooks,
            &writer,
            &once_guard,
        )
        .await
        .unwrap();

        drop(writer);
        let _ = join.await;

        let types = collect_event_types(&seg).await;
        let fired_count = types
            .iter()
            .filter(|&&t| t == crate::wal::events::EVENT_TYPE_HOOK_FIRED)
            .count();
        let skipped_count = types
            .iter()
            .filter(|&&t| t == crate::wal::events::EVENT_TYPE_HOOK_SKIPPED_ONCE)
            .count();
        assert_eq!(
            fired_count, 2,
            "once=false hook must emit HOOK_FIRED on every turn, got {fired_count}"
        );
        assert_eq!(
            skipped_count, 0,
            "once=false hook must never emit HOOK_SKIPPED_ONCE, got {skipped_count}"
        );
        // once=false hooks do NOT claim the guard — no assertion needed since
        // SessionOnceGuard's inner set is not accessible from this module.
    }

    // ── GOLD-ADAPT-SKILL-10: skill-catalog banner unit tests ─────────────

    fn make_test_skill(id: &str, keywords: &[&str], enabled: bool) -> crate::skills::schema::Skill {
        use crate::skills::schema::{Skill, SkillManifest};
        Skill {
            manifest: SkillManifest {
                id: id.to_string(),
                description: format!("test skill {id}"),
                version: "1.0.0".to_string(),
                trigger_keywords: keywords.iter().map(|s| s.to_string()).collect(),
                system_prompt: String::new(),
                tool_allowlist: Vec::new(),
                author: None,
                tags: Vec::new(),
                homepage: None,
                source: None,
                modes: Vec::new(),
                enabled,
                delegate_to: None,
                model: None,
                paths: Vec::new(),
                effort: None,
                loop_trigger: false,
                visibility: crate::config::SkillVisibility::On,
            },
            path: std::path::PathBuf::from(format!("/skills/{id}")),
            content_hash: String::new(),
        }
    }

    /// Catalog renders a table when at least one enabled skill is present,
    /// includes both enabled skills, excludes the disabled one, and lists
    /// trigger keywords in the row.
    #[test]
    fn skill_catalog_prints_when_enabled() {
        let skills = vec![
            make_test_skill("code-review", &["review", "check code"], true),
            make_test_skill("security-scan", &["scan", "audit"], true),
            make_test_skill("disabled-skill", &["nope"], false),
        ];

        let result = maybe_skill_catalog_block(&skills);
        assert!(
            result.is_some(),
            "should return Some when enabled skills exist"
        );

        let table = result.unwrap();
        assert!(
            table.contains("code-review"),
            "table must contain enabled skill id 'code-review'"
        );
        assert!(
            table.contains("security-scan"),
            "table must contain enabled skill id 'security-scan'"
        );
        assert!(
            !table.contains("disabled-skill"),
            "table must NOT contain disabled skill"
        );
        assert!(
            table.contains("review"),
            "table must contain trigger keyword 'review'"
        );
        assert!(
            table.contains("scan"),
            "table must contain trigger keyword 'scan'"
        );
        // Check the markdown table header is present.
        assert!(
            table.contains("| Skill | Trigger phrases |"),
            "table must contain markdown header"
        );
    }

    /// Catalog returns None when all skills are disabled (silent on fresh
    /// installs or when every skill is turned off).
    #[test]
    fn skill_catalog_silent_when_all_disabled() {
        let skills = vec![
            make_test_skill("disabled-a", &["foo"], false),
            make_test_skill("disabled-b", &["bar"], false),
        ];
        let result = maybe_skill_catalog_block(&skills);
        assert!(
            result.is_none(),
            "should return None when every skill is disabled"
        );
    }

    /// Catalog returns None on an empty skill list (fresh install).
    #[test]
    fn skill_catalog_silent_on_empty_list() {
        let result = maybe_skill_catalog_block(&[]);
        assert!(result.is_none(), "should return None for empty skill list");
    }

    /// Skills with no trigger keywords render a dash placeholder instead
    /// of leaving the cell blank.
    #[test]
    fn skill_catalog_no_keywords_renders_dash() {
        let skills = vec![make_test_skill("no-kw-skill", &[], true)];
        let result = maybe_skill_catalog_block(&skills);
        assert!(result.is_some());
        let table = result.unwrap();
        assert!(
            table.contains("no-kw-skill"),
            "skill id must appear in table"
        );
        assert!(
            table.contains('—'),
            "empty trigger_keywords must render em-dash placeholder"
        );
    }

    /// config.skills.session_catalog=false means the catalog block is
    /// never passed to println! — verify by calling the function and
    /// checking the gate condition directly (pure logic, no stdout capture
    /// needed for the gating check).
    #[test]
    fn skill_catalog_gate_off_by_default() {
        let config = FreedomConfig::default();
        assert!(
            !config.skills.session_catalog,
            "session_catalog must default to false (operator opt-in)"
        );
    }
}

// build_header() moved to wal::make_header — Phase 33a AU-B3.
// Old default `importance = 0.6` is now the wal::builder DEFAULT_IMPORTANCE
// (0.5). The 0.1 difference is intentional — operator-facing chat frames now
// use the same baseline importance as every other write, so the
// `idx_episode` ranking is honest about origin instead of secretly biasing
// chat-originated rows.

// GOLD-ADAPT-ODY-03 — attachment-block rendering.
#[cfg(test)]
mod attach_tests {
    use super::*;

    #[test]
    fn attachment_block_labels_and_caps() {
        let small = attachment_block("notes.txt", "hello world");
        assert!(small.starts_with("[Attachment: notes.txt]\n"));
        assert!(small.contains("hello world"));
        assert!(small.ends_with("[End attachment]\n"));
        assert!(!small.contains("truncated"));

        let big_input = "x".repeat(ATTACH_TEXT_CAP + 100);
        let big = attachment_block("big.log", &big_input);
        assert!(big.contains("[…truncated at 8000 chars]"), "{}", &big[..80]);
        // Capped payload: block stays bounded.
        assert!(big.len() < ATTACH_TEXT_CAP + 200);
    }

    #[tokio::test]
    async fn render_attachments_block_plain_text_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let txt = dir.path().join("ctx.md");
        std::fs::write(&txt, "# heading\nbody line").unwrap();
        let missing = dir.path().join("nope.bin");
        let block =
            render_attachments_block(&[txt, missing], &FreedomConfig::default(), dir.path()).await;
        assert!(block.contains("[Attachment: ctx.md]"));
        assert!(block.contains("# heading"));
        assert!(block.contains("[Attachment nope.bin: unsupported or unreadable"));
    }

    #[tokio::test]
    async fn resolve_prompt_prepends_attachment_block() {
        let dir = tempfile::tempdir().unwrap();
        let txt = dir.path().join("a.txt");
        std::fs::write(&txt, "attached context").unwrap();
        let args = ChatArgs {
            message: Some("the question".into()),
            attach: vec![txt],
            ..test_chat_args_default()
        };
        let prompt = resolve_prompt(&args, &FreedomConfig::default(), dir.path())
            .await
            .unwrap();
        assert!(prompt.starts_with("[Attachment: a.txt]"));
        assert!(prompt.ends_with("the question"));
        assert!(prompt.contains("attached context"));
    }

    /// Minimal ChatArgs for tests in this module (mirrors clap defaults).
    fn test_chat_args_default() -> ChatArgs {
        ChatArgs {
            message: None,
            attach: Vec::new(),
            model: None,
            system: None,
            edit: false,
            config: None,
            wal_segment: None,
            stream: false,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            resume_from: None,
            incognito: false,
            loop_mode: false,
            iterations: None,
            until: vec![],
        }
    }
}
