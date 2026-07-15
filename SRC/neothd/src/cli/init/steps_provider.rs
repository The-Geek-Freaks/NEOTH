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
    ping_provider_key, prompt_provider_key, which_binary,
};

fn cli_install_threshold(
    security_policy: &crate::config::SecurityPolicy,
) -> crate::security::osv_check::SeverityLevel {
    security_policy.dep_vuln_threshold
}

pub(crate) async fn step5_provider(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
    security_policy: &crate::config::SecurityPolicy,
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
            offer_cli_installs(
                &mut claude_path,
                &mut codex_path,
                &mut antigravity_path,
                security_policy,
            )
            .await?;
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
                   --provider copilot_api  (provide --provider-key <github_pat>)\n  \
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
                    ProviderKind::AwsBedrock,
                    "aws_bedrock (native SigV4 + AWS credential chain; billed by AWS)",
                ),
                (
                    ProviderKind::AzureOpenAi,
                    "azure_openai (native Azure deployment endpoint; billed by Azure)",
                ),
                (
                    ProviderKind::LocalQwen,
                    "local_qwen — Qwen2/Qwen3 dense on your hardware (~3 GB cached, CPU + GPU). No GPU? Pick openai_compat + OpenRouter instead.",
                ),
                (
                    ProviderKind::LocalOllama,
                    "local_ollama — native Ollama /api/chat NDJSON (point at a running `ollama serve`, no API key). More direct than openai_compat for Ollama.",
                ),
                (
                    ProviderKind::GitHubCopilot,
                    "copilot_api (GitHub Copilot — OAuth PAT; variable billing, cost-gated as unbounded)",
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
                if kind == ProviderKind::OpenaiCompat
                    && default_endpoint.is_empty()
                    && let Some(probed) = probe_local_bridge_sync()
                {
                    default_endpoint = probed;
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
            if let Some(ref k) = key {
                // ZF-03 — live ping with the entered key (non-fatal).
                ping_provider_key(k, kind, state.provider_endpoint.as_deref()).await;
                state.provider_key = Some(crate::secret::SecretString::from(k.clone()));
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
            let default_region = args
                .provider_region
                .clone()
                .or_else(|| std::env::var("AWS_REGION").ok())
                .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
                .unwrap_or_else(|| "us-east-1".to_string());
            let region = if args.provider_region.is_some() || !interactive {
                default_region
            } else {
                #[cfg(feature = "wizard")]
                {
                    dialoguer::Input::<String>::with_theme(
                        &dialoguer::theme::ColorfulTheme::default(),
                    )
                    .with_prompt("[5/9] AWS Bedrock region")
                    .default(default_region)
                    .interact_text()
                    .context("AWS Bedrock region input")?
                }
                #[cfg(not(feature = "wizard"))]
                {
                    default_region
                }
            };
            if region.trim().is_empty() {
                anyhow::bail!("aws_bedrock requires a non-empty --provider-region");
            }
            let default_model = catalog_recommended_for_provider_kind(kind).unwrap_or_else(|| {
                crate::providers::default_model(
                    "aws_bedrock",
                    crate::providers::model_roles::ModelRole::Flagship,
                    "anthropic.claude-opus-4-7-v1:0",
                )
            });
            let model = if let Some(model) = args.provider_model.clone() {
                model
            } else if !interactive {
                default_model
            } else {
                #[cfg(feature = "wizard")]
                {
                    dialoguer::Input::<String>::with_theme(
                        &dialoguer::theme::ColorfulTheme::default(),
                    )
                    .with_prompt("[5/9] AWS Bedrock model id")
                    .default(default_model)
                    .interact_text()
                    .context("AWS Bedrock model input")?
                }
                #[cfg(not(feature = "wizard"))]
                {
                    default_model
                }
            };
            if model.trim().is_empty() {
                anyhow::bail!("aws_bedrock requires a non-empty --provider-model");
            }
            state.provider_region = Some(region);
            state.provider_model = Some(model);
            if interactive {
                println!(
                    "  aws_bedrock uses the native Converse API with SigV4. Credentials \
                     resolve from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (plus optional \
                     AWS_SESSION_TOKEN) or the [default] profile in ~/.aws/credentials. \
                     Calls are billed by AWS and cross the normal NEOTH cost/consent gate."
                );
            }
        }
        ProviderKind::AzureOpenAi => {
            let endpoint = if let Some(endpoint) = args.provider_endpoint.clone() {
                endpoint
            } else if !interactive {
                anyhow::bail!(
                    "azure_openai requires --provider-endpoint \
                     https://<resource>.openai.azure.com in non-interactive mode"
                );
            } else {
                #[cfg(feature = "wizard")]
                {
                    dialoguer::Input::<String>::with_theme(
                        &dialoguer::theme::ColorfulTheme::default(),
                    )
                    .with_prompt("[5/9] Azure OpenAI resource endpoint")
                    .interact_text()
                    .context("Azure OpenAI endpoint input")?
                }
                #[cfg(not(feature = "wizard"))]
                {
                    String::new()
                }
            };
            if endpoint.trim().is_empty() {
                anyhow::bail!("azure_openai requires a non-empty --provider-endpoint");
            }
            let deployment = if let Some(model) = args.provider_model.clone() {
                model
            } else if !interactive {
                anyhow::bail!(
                    "azure_openai requires --provider-model <deployment-name> in non-interactive mode"
                );
            } else {
                #[cfg(feature = "wizard")]
                {
                    dialoguer::Input::<String>::with_theme(
                        &dialoguer::theme::ColorfulTheme::default(),
                    )
                    .with_prompt("[5/9] Azure OpenAI deployment name")
                    .interact_text()
                    .context("Azure OpenAI deployment input")?
                }
                #[cfg(not(feature = "wizard"))]
                {
                    String::new()
                }
            };
            if deployment.trim().is_empty() {
                anyhow::bail!("azure_openai requires a non-empty deployment name");
            }
            let default_api_version = args
                .provider_api_version
                .clone()
                .unwrap_or_else(|| "2024-10-21".to_string());
            let api_version = if args.provider_api_version.is_some() || !interactive {
                default_api_version
            } else {
                #[cfg(feature = "wizard")]
                {
                    dialoguer::Input::<String>::with_theme(
                        &dialoguer::theme::ColorfulTheme::default(),
                    )
                    .with_prompt("[5/9] Azure OpenAI API version")
                    .default(default_api_version)
                    .interact_text()
                    .context("Azure OpenAI API-version input")?
                }
                #[cfg(not(feature = "wizard"))]
                {
                    default_api_version
                }
            };
            let key = prompt_provider_key(args, interactive, kind)?.ok_or_else(|| {
                anyhow::anyhow!("azure_openai requires --provider-key (or NEOTH_PROVIDER_KEY)")
            })?;
            state.provider_key = Some(crate::secret::SecretString::from(key));
            state.provider_endpoint = Some(endpoint);
            state.provider_model = Some(deployment);
            state.provider_api_version = Some(api_version);
            if interactive {
                println!(
                    "  azure_openai is configured through the native deployment endpoint \
                     (`api-key` header + api-version query). Calls are billed by Azure \
                     and cross the normal NEOTH cost/consent gate."
                );
            }
        }
        ProviderKind::GitHubCopilot => {
            // GOLD-ADAPT-ODY-15 — Copilot OAuth provider.
            // No endpoint prompt needed (defaults to api.githubcopilot.com).
            // Collect the GitHub PAT (provider_key) that the session-token
            // endpoint will authenticate with.
            if interactive {
                println!(
                    "  copilot_api billing varies by plan, model, allowance and overage state; \
                     NEOTH therefore confirms it as an unbounded paid call unless Full autonomy is active. \
                     Requires a GitHub PAT with `copilot` scope (Settings → Developer settings → \
                     Personal access tokens → Fine-grained; scope: Copilot Editor Context). \
                     Your PAT is stored locally in credentials.yaml (mlock + zeroize)."
                );
            }
            let key = prompt_provider_key(args, interactive, kind)?;
            if let Some(ref k) = key {
                // ZF-03 — live ping (non-fatal).
                ping_provider_key(k, kind, state.provider_endpoint.as_deref()).await;
                state.provider_key = Some(crate::secret::SecretString::from(k.clone()));
            }
            use crate::providers::model_roles::ModelRole;
            let bundled_default =
                crate::providers::default_model("copilot_api", ModelRole::Flagship, "gpt-4o");
            state.provider_model = Some(args.provider_model.clone().unwrap_or(bundled_default));
        }
        ProviderKind::RecursiveMas => {
            // GOLD-ADAPT-RMAS-03 — no endpoint / key / model repo. The
            // sidecar is an operator-installed checkout configured via
            // freedom.yaml::recursive_mas; the wizard only points there.
            state.provider_model = None;
            if interactive {
                println!(
                    "  recursive_mas is an EXPERIMENTAL local sidecar (latent \
                     recursion for council deliberation). It needs: a GPU with \
                     enough VRAM, an operator-installed RecursiveMAS checkout, \
                     and `recursive_mas.enabled: true` + `sidecar_repo` in \
                     freedom.yaml. The binary must be built with the \
                     `recursive-mas` feature. NEOTH never downloads the \
                     upstream code or weights."
                );
            }
        }
        ProviderKind::Skip => {
            if interactive {
                println!(
                    "  Skipped. Configure later with `neoth init` or `neoth hemispheres set`."
                );
            }
        }
        ProviderKind::LocalOllama => {
            // Native Ollama /api/chat (NDJSON) — no API key; the operator points
            // at a running `ollama serve` and names a pulled model. Endpoint +
            // model come from config; the adapter defaults (localhost:11434 +
            // a baked default model) apply when left unset.
            state.provider_endpoint = args.provider_endpoint.clone();
            state.provider_model = args.provider_model.clone();
            if interactive {
                println!(
                    "  local_ollama talks to a running Ollama daemon over its native \
                     /api/chat NDJSON streaming API (not the OpenAI-compat shim). No \
                     API key. Default endpoint http://localhost:11434 — override with \
                     `--provider-endpoint`; set `--provider-model` (e.g. llama3.2) to \
                     a model you have `ollama pull`-ed."
                );
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
    security_policy: &crate::config::SecurityPolicy,
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
        if let Err(e) =
            crate::installers::install_kind(*kind, cli_install_threshold(security_policy)).await
        {
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
            if login_it && let Err(e) = crate::installers::login_kind(*kind).await {
                println!(
                    "  ! {} login error: {e} (you can re-run later)",
                    kind.display
                );
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
    _security_policy: &crate::config::SecurityPolicy,
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::cli_install_threshold;

    #[test]
    fn wizard_installs_honour_operator_severity_policy() {
        let policy = crate::config::SecurityPolicy {
            dep_vuln_threshold: crate::security::osv_check::SeverityLevel::Critical,
            ..Default::default()
        };
        assert_eq!(
            cli_install_threshold(&policy),
            crate::security::osv_check::SeverityLevel::Critical
        );
    }
}
