//! Wizard provider step (GOLD-ARCH-05): step5 provider selection + key
//! entry + CLI-installer offers. Split out of `cli/init.rs`.

use anyhow::{Context, Result};
use tracing::debug;

// `probe_local_bridge_sync` lives in `providers::local_probe` so the
// telemetry-guard lint (Phase 33c BS-6) keeps the daemon's `cli/` tree
// clean of any HTTP-client construction. Loopback-only probes still
// belong in `providers/` architecturally — the wizard is just one caller.
use crate::providers::local_probe::probe_local_bridge_sync;

#[cfg(feature = "wizard")]
use super::npm_path_hint;
use super::{
    InitArgs, ProviderKind, WizardState, WizardStep, catalog_recommended_for_provider_kind,
    prompt_provider_key, which_binary,
};

pub(crate) async fn step5_provider(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    debug!("wizard step 5: provider");

    // Detect the three first-class CLIs and offer to install any that are
    // missing. Memory note: [[neoth-cli-installers]] — operator never
    // opens npm or curl manually. Google's Antigravity CLI (`agy`)
    // replaces the retired gemini-cli per 2026-05-19 transition; legacy
    // `gemini` binaries still on PATH surface as a doctor warning.
    let mut claude_path = which_binary("claude");
    let mut codex_path = which_binary("codex");
    let mut antigravity_path = which_binary("agy");
    let legacy_gemini_path = which_binary("gemini");

    if interactive {
        println!("\n[5/9] LLM Provider — detected CLIs:");
        println!(
            "  claude: {}",
            claude_path.as_deref().unwrap_or("NOT FOUND")
        );
        println!("  codex:  {}", codex_path.as_deref().unwrap_or("NOT FOUND"));
        println!(
            "  agy:    {}",
            antigravity_path.as_deref().unwrap_or("NOT FOUND")
        );
        if let Some(legacy) = legacy_gemini_path.as_deref() {
            println!(
                "  ! legacy `gemini` ({legacy}) detected. Google retires gemini-cli \
                 API on 2026-06-18 — install `agy` to migrate."
            );
        }

        if claude_path.is_none() || codex_path.is_none() || antigravity_path.is_none() {
            offer_cli_installs(&mut claude_path, &mut codex_path, &mut antigravity_path).await?;
        }
    }

    let default_kind = if claude_path.is_some() {
        ProviderKind::ClaudeCli
    } else if codex_path.is_some() {
        ProviderKind::OpenaiApi
    } else {
        ProviderKind::Skip
    };

    let kind = if let Some(k) = args.provider {
        k
    } else if !interactive {
        // Pick #34 (Session 14, operator-flow audit-fix Flow#1): in
        // non-interactive mode (CI / cloud-init / scripted install)
        // a `Skip` default means no CLI was detected AND the operator
        // didn't pass `--provider`. The wizard would happily write a
        // Skip config; `neoth chat` then fails cryptically on
        // provider construction with no actionable signal. Surface
        // the gap loudly here — operator chose CI-mode + omitted a
        // mandatory choice, so we error with a remedy instead of
        // silently shipping a broken install.
        if matches!(default_kind, ProviderKind::Skip) {
            anyhow::bail!(
                "neoth init: non-interactive mode + no `--provider <kind>` + no claude/codex/agy \
                 binary detected on PATH. The wizard would silently configure provider=`skip` and \
                 `neoth chat` would fail. Pick one:\n  \
                   --provider claude_cli   (install claude CLI first)\n  \
                   --provider openai_api   (provide --provider-key sk-...)\n  \
                   --provider gemini_api   (provide --provider-key ...)\n  \
                   --provider local_qwen   (no key needed, ~3 GB local model)\n  \
                   --provider openai_compat --provider-endpoint <URL>   (OpenRouter / vLLM / etc.)"
            );
        }
        default_kind
    } else {
        #[cfg(feature = "wizard")]
        {
            const CHOICES: &[(ProviderKind, &str)] = &[
                (ProviderKind::ClaudeCli, "claude_cli (Claude CLI binary)"),
                (ProviderKind::OpenaiApi, "openai_api (api.openai.com)"),
                (
                    ProviderKind::AnthropicApi,
                    "anthropic_api (api.anthropic.com — Claude via API key) — ⚠ BILLED PER-TOKEN; \
                     pick claude_cli for OAuth/subscription (no metering)",
                ),
                (ProviderKind::GeminiApi, "gemini_api (Google Gemini REST)"),
                (
                    ProviderKind::Cohere,
                    "cohere_api (api.cohere.com — Cohere v2 Chat, ⚠ BILLED per-token)",
                ),
                (
                    ProviderKind::OpenaiCompat,
                    "openai_compat (OpenRouter / Together / Groq / LM Studio / vLLM / Ollama / custom)",
                ),
                (
                    ProviderKind::LocalQwen,
                    "local_qwen — Qwen2/Qwen3 dense on your hardware (~3 GB cached, CPU + GPU). No GPU? Pick openai_compat + OpenRouter instead.",
                ),
                (ProviderKind::Skip, "skip (configure later)"),
            ];
            let labels: Vec<&str> = CHOICES.iter().map(|(_, l)| *l).collect();
            let default_idx = CHOICES
                .iter()
                .position(|(k, _)| *k == default_kind)
                .unwrap_or(0);
            let idx = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("[5/9] LLM provider kind")
                .items(&labels)
                .default(default_idx)
                .interact()
                .context("provider selection")?;
            CHOICES[idx].0
        }
        #[cfg(not(feature = "wizard"))]
        {
            default_kind
        }
    };

    state.provider_kind = Some(kind);

    match kind {
        ProviderKind::LocalQwen => {
            // No endpoint / key — model + tokenizer come from Hugging Face.
            // `provider_model` here is the HF repo identifier; default in the
            // adapter applies if unset.
            state.provider_model = args.provider_model.clone();
            if interactive {
                println!(
                    "  local_qwen runs Qwen2/Qwen3 dense models locally via candle. \
                     First-run downloads ~3 GB of weights into ~/.neoth/models/ \
                     and may take a few minutes; later runs reuse the cache. \
                     CPU-only by default — pick CUDA/Metal in step 5b if you \
                     have a GPU. `neoth chat --temperature 0.7 --top-p 0.9` \
                     enables nucleus sampling; the default is greedy/argmax."
                );
            }
        }
        ProviderKind::LocalOuro => {
            // Ouro O-3: same hf-hub flow as LocalQwen. Default checkpoint
            // (when provider_model is None) is `ByteDance/Ouro-1.4B-Thinking`
            // — operator overrides with `--provider-model
            // ByteDance/Ouro-2.6B-Thinking` for the larger variant.
            state.provider_model = args.provider_model.clone();
            if interactive {
                println!(
                    "  local_ouro runs ByteDance Ouro LoopLM thinking-models \
                     locally via candle. First-run downloads ~3 GB of weights \
                     into ~/.neoth/models/. Looped-transformer architecture \
                     applies 24 layers 4× per token (~4× compute vs Qwen) but \
                     emits explicit reasoning prose in the -Thinking variants. \
                     Default checkpoint: ByteDance/Ouro-1.4B-Thinking. \
                     Apache-2.0; CPU-only by default — pick CUDA/Metal in step \
                     5b if you have a GPU."
                );
            }
        }
        ProviderKind::ClaudeCli => {
            let bin = args
                .provider_binary
                .clone()
                .or(claude_path)
                .unwrap_or_else(|| "claude".to_string());
            state.provider_binary = Some(bin);
            // MV-01c — catalog-first default so a newly-discovered Claude
            // model (Opus 4.8 / 4.9, Sonnet 4.8, codenames) becomes the
            // wizard default WITHOUT a code patch. Mirrors the OpenAI/Gemini
            // arm below; `ClaudeCli` maps to the `anthropic_api` catalog
            // key. Falls back to the bundled baseline when no fresh
            // anthropic_api entry exists (fresh install, pre-`catalog
            // refresh`).
            // GOLD-WIRE-03: the bundled fallback comes from the same SSOT as
            // `providers::from_config` (`model_roles::default_table`), so the
            // wizard + the runtime can't drift.
            let resolved_default =
                catalog_recommended_for_provider_kind(kind).unwrap_or_else(|| {
                    crate::providers::default_model(
                        "claude_cli",
                        crate::providers::model_roles::ModelRole::Flagship,
                        "claude-opus-4-7",
                    )
                });
            state.provider_model = Some(args.provider_model.clone().unwrap_or(resolved_default));
        }
        ProviderKind::OpenaiApi
        | ProviderKind::AnthropicApi
        | ProviderKind::GeminiApi
        | ProviderKind::Cohere
        | ProviderKind::OpenaiCompat => {
            // Cost guard (operator directive 2026-05-31): anthropic_api BILLS
            // per-token; claude_cli via tmux is the OAuth/subscription path
            // with NO metering. Make the distinction loud so a noob doesn't
            // accidentally bill themselves by picking the API over the CLI.
            if interactive && kind == ProviderKind::AnthropicApi {
                println!(
                    "  ⚠ anthropic_api BILLS PER-TOKEN via the Anthropic API. If you have a \
                     Claude subscription (Claude Pro/Max or Claude Code OAuth), go back and \
                     pick `claude_cli` instead — it routes through the `claude` CLI (tmux) \
                     with NO per-token metering. Only use anthropic_api if you specifically \
                     want API-key billing (e.g. no subscription, just an API key)."
                );
            }
            if interactive && kind == ProviderKind::Cohere {
                println!(
                    "  ⚠ cohere_api BILLS PER-TOKEN via the Cohere API (no subscription \
                     path). For a free local option pick `local_qwen`; for a Claude \
                     subscription pick `claude_cli`."
                );
            }
            // Endpoint resolution: for OpenaiCompat we prompt explicitly because
            // there is no upstream default. For OpenaiApi we default to api.openai.com.
            // For GeminiApi the endpoint lives in code (URL has model in path), no field needed.
            if matches!(kind, ProviderKind::OpenaiApi | ProviderKind::OpenaiCompat) {
                let mut default_endpoint = match kind {
                    ProviderKind::OpenaiApi => "https://api.openai.com/v1".to_string(),
                    _ => String::new(),
                };
                // For OpenaiCompat: auto-probe the local Claude bridge so the
                // operator does not have to type the URL when it is the common
                // path on this machine. Probe runs at wizard time only.
                if kind == ProviderKind::OpenaiCompat && default_endpoint.is_empty() {
                    if let Some(probed) = probe_local_bridge_sync() {
                        default_endpoint = probed;
                    }
                }
                let endpoint = if let Some(e) = args.provider_endpoint.clone() {
                    e
                } else if !interactive {
                    default_endpoint
                } else {
                    #[cfg(feature = "wizard")]
                    {
                        dialoguer::Input::<String>::with_theme(
                            &dialoguer::theme::ColorfulTheme::default(),
                        )
                        .with_prompt(format!(
                            "[5/9] {} endpoint (full URL incl. /v1)",
                            match kind {
                                ProviderKind::OpenaiApi => "OpenAI API",
                                _ => "OpenAI-compat (local bridge / vLLM / LM Studio)",
                            }
                        ))
                        .default(default_endpoint)
                        .interact_text()
                        .context("endpoint input")?
                    }
                    #[cfg(not(feature = "wizard"))]
                    {
                        default_endpoint
                    }
                };
                state.provider_endpoint = Some(endpoint);
            }

            // Key resolution: OpenaiCompat may accept empty (unauthenticated local server)
            // or a local bridge token (NOT an Anthropic key).
            let key = prompt_provider_key(args, interactive, kind)?;
            if let Some(k) = key {
                state.provider_key = Some(crate::secret::SecretString::from(k));
            }

            // Default model per provider. K-Models-Discovery (Session 14)
            // consults the cached catalog at `~/.neoth/models_catalog.json`
            // when present; falls back to the bundled hardcoded baseline
            // when the catalog is empty / stale / has no entry for the
            // chosen provider.
            // GOLD-WIRE-03: bundled fallbacks come from the same SSOT as
            // `providers::from_config` (`model_roles::default_table`) so the
            // wizard's freedom.yaml write can't drift from the runtime default.
            // anthropic_api uses BALANCED (sonnet) to match from_config's
            // metered-API cost choice. `openai_compat` requires an operator
            // model anyway (no table row) so it keeps its literal placeholder.
            use crate::providers::model_roles::ModelRole;
            let bundled_default = match kind {
                ProviderKind::OpenaiApi => {
                    crate::providers::default_model("openai_api", ModelRole::Flagship, "gpt-5.5")
                }
                ProviderKind::AnthropicApi => crate::providers::default_model(
                    "anthropic_api",
                    ModelRole::Balanced,
                    "claude-sonnet-4-6",
                ),
                ProviderKind::GeminiApi => crate::providers::default_model(
                    "gemini_api",
                    ModelRole::Flagship,
                    "gemini-3.1-pro-preview",
                ),
                ProviderKind::Cohere => crate::providers::default_model(
                    "cohere_api",
                    ModelRole::Flagship,
                    "command-a-plus-05-2026",
                ),
                ProviderKind::OpenaiCompat => "opus-4.7".to_string(),
                _ => String::new(),
            };
            let resolved_default =
                catalog_recommended_for_provider_kind(kind).unwrap_or(bundled_default);
            state.provider_model = Some(args.provider_model.clone().unwrap_or(resolved_default));
        }
        ProviderKind::AwsBedrock => {
            // C-3 (Session 13) Phase 1 — scaffold variant. Operator
            // sees it in the wizard select but the actual SigV4
            // adapter lands in Phase 2. Region + IAM credential
            // chain config schema also Phase 2.
            if interactive {
                println!(
                    "  aws_bedrock is C-3 Phase 1 scaffold — the variant is selectable \
                     for forward-compat but the SigV4 adapter ships in Phase 2. \
                     Use `openai_compat` against a Bedrock-on-OpenAI proxy in the interim."
                );
            }
        }
        ProviderKind::AzureOpenAi => {
            // C-4 (Session 13) Phase 1 — scaffold variant. Operator
            // sees it in the wizard select; actual adapter ships in
            // Phase 2 with the `api-version` + deployment-name-as-
            // model schema.
            if interactive {
                println!(
                    "  azure_openai is C-4 Phase 1 scaffold — the variant is selectable \
                     for forward-compat but the adapter (api-version query param + \
                     deployment-name-as-model schema) ships in Phase 2."
                );
            }
        }
        ProviderKind::Skip => {
            if interactive {
                println!("  Skipped. Configure later: `neoth provider add`");
            }
        }
    }

    state.steps_completed.push(WizardStep::Provider as u8);
    Ok(())
}

/// Offer to install the three CLIs that are missing on PATH. Dispatches
/// on each CLI's [`InstallStrategy`] — npm-strategy CLIs need npm
/// reachable, shell-script-strategy CLIs (Antigravity) only need
/// `sh`/PowerShell which we can rely on. Updates the passed-in path
/// Options in place so the wizard can re-probe after install. Quiet
/// no-op when all three are already present.
#[cfg(feature = "wizard")]
pub(crate) async fn offer_cli_installs(
    claude: &mut Option<String>,
    codex: &mut Option<String>,
    antigravity: &mut Option<String>,
) -> Result<()> {
    use crate::installers::{
        ALL, ANTIGRAVITY as INST_ANTIGRAVITY, CLAUDE as INST_CLAUDE, CODEX as INST_CODEX, CliKind,
        InstallStrategy,
    };

    // npm probe is per-strategy now — only required when at least one
    // missing CLI ships via npm.
    let npm_v = crate::installers::npm_version().await;
    let needs_npm = ALL.iter().any(|k| {
        matches!(k.install, InstallStrategy::Npm { .. })
            && match k.binary {
                "claude" => claude.is_none(),
                "codex" => codex.is_none(),
                _ => false,
            }
    });
    if needs_npm && npm_v.is_none() {
        println!();
        println!("  ! npm not found on PATH. To auto-install npm-managed CLIs, install Node.js:");
        println!("    https://nodejs.org/  (the LTS installer ships npm)");
        println!("  Shell-script CLIs (Antigravity) can still install — continuing.");
    } else if let Some(v) = npm_v.as_ref() {
        println!("\n  npm {v} detected — auto-install available for npm-managed CLIs.");
    }

    for kind in ALL {
        let current = match kind.binary {
            "claude" => claude.clone(),
            "codex" => codex.clone(),
            "agy" => antigravity.clone(),
            _ => None,
        };
        if current.is_some() {
            continue;
        }
        // Skip npm-strategy CLIs when npm is missing — the message
        // above already told the operator how to recover.
        if matches!(kind.install, InstallStrategy::Npm { .. }) && npm_v.is_none() {
            continue;
        }
        let source_hint = match kind.install {
            InstallStrategy::Npm { package } => format!("npm: {package}"),
            InstallStrategy::ShellScript { unix_url, .. } => format!("shell: {unix_url}"),
        };
        let install_it =
            dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(format!("Install {} ({source_hint})?", kind.display))
                .default(true)
                .interact()
                .context("install confirm prompt")?;
        if !install_it {
            continue;
        }
        if let Err(e) = crate::installers::install_kind(*kind).await {
            println!("  ✗ install of {} failed: {e}", kind.display);
            continue;
        }
        // Re-probe and trigger login if the binary now appears on PATH.
        let resolved = which_binary(kind.binary);
        if resolved.is_some() {
            println!("  ✓ {} installed", kind.display);
            // Update the caller's path slot for the picker downstream.
            match kind.binary {
                "claude" => *claude = resolved.clone(),
                "codex" => *codex = resolved.clone(),
                "agy" => *antigravity = resolved.clone(),
                _ => {}
            }
            let login_it =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(format!(
                        "Run `{} {}` for OAuth login now?",
                        kind.binary,
                        kind.login_args.unwrap_or(&[]).join(" ")
                    ))
                    .default(true)
                    .interact()
                    .context("login confirm prompt")?;
            if login_it {
                if let Err(e) = crate::installers::login_kind(*kind).await {
                    println!(
                        "  ! {} login error: {e} (you can re-run later)",
                        kind.display
                    );
                }
            }
        } else {
            let hint = match kind.install {
                InstallStrategy::Npm { .. } => npm_path_hint(kind.binary),
                InstallStrategy::ShellScript { .. } => {
                    "Open a new shell or check the installer's reported install path.".to_string()
                }
            };
            println!(
                "  ! {} installed but `{}` is still not on PATH. {hint}",
                kind.display, kind.binary
            );
        }
        // Silence unused-import on cfg with no other use of these.
        let _ = (INST_CLAUDE, INST_CODEX, INST_ANTIGRAVITY);
        let _: CliKind = *kind;
    }
    Ok(())
}

/// No-op fallback when the `wizard` feature is off. Wizard-less builds skip
/// interactive install offers entirely.
#[cfg(not(feature = "wizard"))]
pub(crate) async fn offer_cli_installs(
    _claude: &mut Option<String>,
    _codex: &mut Option<String>,
    _antigravity: &mut Option<String>,
) -> Result<()> {
    Ok(())
}
