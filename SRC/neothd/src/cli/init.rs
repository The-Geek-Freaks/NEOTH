//! `neoth init` -- interactive onboarding wizard.
//!
//! Normative reference: PLAN/SPEC_onboarding.md
//!
//! All 7 wizard steps are implemented. Interactive prompts (dialoguer) require
//! the `wizard` Cargo feature (enabled by default). Non-interactive operation
//! works without `wizard` and is driven entirely by CLI flags + env vars.

use std::io::IsTerminal;

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// LLM provider kind. Typed enum (replaces stringly-typed v0.1 alpha).
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[clap(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// claude CLI binary (OAuth via `claude` command).
    ClaudeCli,
    /// OpenAI REST API (api.openai.com or compatible).
    OpenaiApi,
    /// Google Gemini REST API.
    GeminiApi,
    /// OpenAI-compatible endpoint at custom URL (LM Studio, vLLM, etc.).
    OpenaiCompat,
    /// Local Qwen3 inference. ~3 GB disk + first-load model download.
    /// Runs entirely on operator hardware — used for profile extraction
    /// (sensitive operator history never reaches a cloud vendor).
    LocalQwen,
    /// Local Ouro thinking-models inference (ByteDance LoopLM,
    /// `ByteDance/Ouro-1.4B-Thinking` default). ~3 GB disk + first-load
    /// download via hf-hub. Looped-transformer reasoning runs entirely
    /// on operator hardware — Apache-2.0, novel architecture, ~4× compute
    /// per token vs Qwen but explicit reasoning prose in the -Thinking
    /// variants.
    LocalOuro,
    /// AWS Bedrock Runtime (C-3 Session 13). Stub variant: Phase 1
    /// ships the surface + consent gate; Phase 2 ships the SigV4 adapter.
    AwsBedrock,
    /// Azure OpenAI Service (C-4 Session 13). Stub variant: Phase 1
    /// ships the surface + consent gate; Phase 2 ships the api-version
    /// + deployment-as-model adapter.
    AzureOpenAi,
    /// No provider yet; configure later via `neoth provider add`.
    Skip,
}

/// Operator role. Free-form string fallback covered by `Custom(String)` is
/// intentionally not modelled to preserve enum exhaustiveness; the CLI accepts
/// the listed values plus any [a-z0-9_-] custom string mapped via `try_from`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[clap(rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum OperatorRole {
    Developer,
    SecurityResearcher,
    Founder,
    DataScientist,
    Writer,
    None,
}

/// Arguments for `neoth init`.
#[derive(Args, Debug, Clone, Default)]
pub struct InitArgs {
    /// Run without interactive prompts. All values via flags.
    /// On a TTY, `neoth init` defaults to interactive; pass this to force
    /// non-interactive mode (e.g. inside CI or cloud-init).
    #[arg(long = "non-interactive")]
    pub non_interactive: bool,

    /// Accept license without prompt. Required with --non-interactive.
    #[arg(long)]
    pub accept_license: bool,

    /// Operator identity (2-32 chars, [a-zA-Z0-9_-]).
    #[arg(long, value_name = "ID")]
    pub operator_id: Option<String>,

    /// Primary language as BCP-47 code.
    #[arg(long, value_name = "BCP47", default_value = "en")]
    pub language: String,

    /// Code language as BCP-47 code (default: same as --language).
    #[arg(long, value_name = "BCP47")]
    pub code_language: Option<String>,

    /// Operator role. Listed values only; custom labels must be set via
    /// `neoth profile set --role <label>` after init.
    #[arg(long, value_name = "ROLE")]
    pub role: Option<OperatorRole>,

    /// LLM provider kind.
    #[arg(long, value_name = "KIND")]
    pub provider: Option<ProviderKind>,

    /// Path to CLI binary (for claude_cli).
    #[arg(long, value_name = "PATH")]
    pub provider_binary: Option<String>,

    /// API key. Prefer env NEOTH_PROVIDER_KEY.
    #[arg(long, value_name = "KEY", env = "NEOTH_PROVIDER_KEY")]
    pub provider_key: Option<String>,

    /// Custom API endpoint (for openai_compat).
    #[arg(long, value_name = "URL")]
    pub provider_endpoint: Option<String>,

    /// Override default model.
    #[arg(long, value_name = "MODEL")]
    pub provider_model: Option<String>,

    /// Telegram bot token. Prefer env NEOTH_TELEGRAM_TOKEN.
    #[arg(long, value_name = "TOKEN", env = "NEOTH_TELEGRAM_TOKEN")]
    pub telegram_token: Option<String>,

    /// Restrict Telegram bot to a single user ID.
    #[arg(long, value_name = "USER_ID")]
    pub telegram_user_id: Option<u64>,

    /// Autonomy level non-interactive override (Phase 28b R-23).
    /// `strict | standard | elevated | full | custom`. Defaults to
    /// `standard` when the wizard runs without a TTY.
    #[arg(long, value_name = "LEVEL")]
    pub autonomy: Option<String>,

    /// Inference topology non-interactive override (D14b).
    /// `single | triplet | custom`. Defaults to `single` when the
    /// wizard runs without a TTY.
    #[arg(long, value_name = "MODE")]
    pub inference_mode: Option<String>,

    /// Accelerator override (D14b).
    /// `cuda | metal | openvino | cpu`. Defaults to the auto-detected
    /// best fit; this flag bypasses detection.
    #[arg(long, value_name = "ACCEL")]
    pub accelerator_override: Option<String>,

    /// Embedding-provider non-interactive override (D14b).
    /// `local_qwen | openai_api | anthropic_api | gemini_api`.
    #[arg(long, value_name = "PROVIDER")]
    pub embedding_provider: Option<String>,

    /// E-2 Phase 4 (Session 14 Pick #23) — operator-pinned council
    /// recursion depth. `0`/`1` = flat (default). `2` = 3×3 = 9 leaf
    /// calls per user message. `3` = 27 leaf calls. `4` = 81 leaf
    /// calls (the `MAX_HEMISPHERE_COUNCIL_DEPTH` cap). Values above
    /// 4 clamp silently. Operators raising this above 1 in non-
    /// interactive mode get a one-line stderr warning instead of the
    /// interactive confirm screen — there's no terminal to draw it on.
    #[arg(long, value_name = "N")]
    pub council_depth: Option<u8>,

    /// E-21 step 7c non-interactive override (D-102 deferred follow-up).
    /// Pre-activate a discovered WASM plugin by id without the
    /// interactive multiselect — repeat the flag for each id to
    /// activate. Unknown ids are warned but don't fail the wizard.
    /// CI / cloud-init operators use this to flip plugins to Active
    /// during scripted bring-up; everyone else uses the interactive
    /// step or `neoth plugin enable <id>` afterwards.
    #[arg(long = "enable-plugin", value_name = "ID", num_args = 0..)]
    pub enable_plugin: Vec<String>,

    /// Re-run full wizard even if already initialized.
    #[arg(long)]
    pub force: bool,

    /// Print what would be written, write nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// Output final config as JSON to stdout.
    #[arg(long)]
    pub output_json: bool,
}

/// In-memory state accumulated across all 7 wizard steps.
/// Written to disk atomically after step 7.
///
/// Typed enums for `role` and `provider_kind` (Rust Architect review): prevents
/// silent drift when a new provider arm is added without updating match coverage.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WizardState {
    pub operator_id: Option<String>,
    pub language_primary: Option<String>,
    pub language_code: Option<String>,
    pub role: Option<OperatorRole>,
    /// Free-form custom role label when `role == None` is too narrow.
    /// Validated against `[a-z0-9_-]{1,32}` at construction time.
    pub role_custom: Option<String>,
    pub provider_kind: Option<ProviderKind>,
    pub provider_binary: Option<String>,
    pub provider_key: Option<crate::secret::SecretString>,
    pub provider_endpoint: Option<String>,
    pub provider_model: Option<String>,
    pub telegram_token: Option<crate::secret::SecretString>,
    pub telegram_user_id: Option<u64>,
    /// Autonomy level chosen at onboarding — Phase 28b R-23. Defaults to
    /// `Standard` so an aborted wizard still writes a sane freedom.yaml.
    #[serde(default)]
    pub autonomy: crate::permissions::AutonomyLevel,
    /// Per-hemisphere LLM topology + accelerator + embedding provider.
    /// Defaults to `single` mode that mirrors the legacy `provider_kind`
    /// path, so an aborted wizard still writes a sane freedom.yaml.
    #[serde(default)]
    pub inference: crate::config::inference::InferenceTopology,
    /// V03-09 Phase 2a (2026-05-21): operator-facing self-update
    /// policy. `enabled: false` (default) keeps the daemon silent.
    /// step7b_auto_update toggles this based on the operator's
    /// answer. Lives in freedom.yaml under `auto_update:` so the
    /// reload + read paths see the same shape as the rest of the
    /// FreedomConfig surface.
    #[serde(default)]
    pub auto_update: crate::config::AutoUpdateConfig,
    /// D-102 wizard step 7c (Session 21, 2026-05-23): per-plugin
    /// activation state populated by `step7c_wasm_plugin_activation`.
    /// Empty by default; the step writes
    /// `activations[<id>] = Active|Disabled` based on the operator's
    /// MultiSelect picks. Maps 1:1 to FreedomConfig.plugins so the
    /// YAML round-trip lands the same shape at daemon boot.
    #[serde(default)]
    pub plugins: crate::config::PluginsConfig,
    /// K-3.5 (Session 21, 2026-05-23) — Keet pairing seed phrase.
    /// Stripped from freedom.yaml by `write_config` + persisted to
    /// credentials.yaml::keet_seed_phrase. Wrapped in `SecretString`
    /// for mlock+zeroize parity with provider keys.
    #[serde(skip)]
    pub keet_seed_phrase: Option<crate::secret::SecretString>,
    /// K-3.5 (Session 21, 2026-05-23) — bearer token generated by
    /// the wizard for the Pears HTTP bridge. Stripped from
    /// freedom.yaml + persisted to credentials.yaml::pears_bearer_token.
    #[serde(skip)]
    pub pears_bearer_token: Option<crate::secret::SecretString>,
    pub steps_completed: Vec<u8>,
}

/// Effective interactivity: TTY on stdin AND --non-interactive not set.
/// On Windows, `IsTerminal` correctly handles ConHost/Terminal/MinTTY.
fn is_interactive(args: &InitArgs) -> bool {
    !args.non_interactive && std::io::stdin().is_terminal()
}

/// Main entry point for `neoth init`.
pub async fn run_init(args: InitArgs) -> Result<()> {
    let interactive = is_interactive(&args);
    info!(interactive, force = args.force, "neoth init starting");

    let neoth_dir = dirs_home().join(".neoth");
    let marker = neoth_dir.join(".initialized");

    if marker.exists() && !args.force {
        info!("Already initialized. Showing reconfigure menu.");
        return run_reconfigure_menu(&args);
    }

    // Non-interactive (pipe / CI / --non-interactive flag) requires explicit license accept.
    if !interactive && !args.accept_license {
        anyhow::bail!(
            "--accept-license is required when running non-interactively \
             (no TTY detected or --non-interactive set)"
        );
    }

    let mut state = WizardState::default();
    step1_license(&args, interactive, &mut state)?;
    step2_operator_id(&args, interactive, &mut state)?;
    step3_language(&args, interactive, &mut state)?;
    step4_role(&args, interactive, &mut state)?;
    step5_provider(&args, interactive, &mut state).await?;
    step5b_inference_topology(&args, interactive, &mut state)?;
    step6_channel(&args, interactive, &mut state).await?;
    step6b_keet_pairing(&args, interactive, &mut state).await?;
    step7_autonomy(&args, interactive, &mut state)?;
    step7b_auto_update(&args, interactive, &mut state)?;
    step7c_wasm_plugin_activation(&args, interactive, &neoth_dir, &mut state)?;
    step8_summary(&args, &mut state)?;

    if args.dry_run {
        println!("[dry-run] No files written.");
    } else {
        write_config(&neoth_dir, &state).await?;
        write_initialized_marker(&neoth_dir, &state)?;
        println!("Configuration written to ~/.neoth/");
        // Phase 28c R-24 GT-4: optional Q&A ground-truth seed. Runs only on
        // a TTY; non-interactive flow points operator at `neoth groundtruth
        // ask` instead. Skippable in interactive mode too.
        if interactive {
            maybe_run_groundtruth_qa(&state)?;
        } else {
            println!(
                "Run `neoth groundtruth ask` to seed ground-truth facts \
                 (or skip and add later via `neoth groundtruth add ...`)."
            );
        }
    }
    Ok(())
}

/// Step 9 (post-write) — optional ground-truth Q&A. Always interactive.
///
/// Operator gets one confirm prompt. If they decline, the daemon is fully
/// usable; ground truth can be added later. Failures here log and continue
/// so a bad question bank doesn't block the freshly-written config.
fn maybe_run_groundtruth_qa(state: &WizardState) -> Result<()> {
    #[cfg(feature = "wizard")]
    {
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Seed ground-truth facts now? (~5 min Q&A — can skip / run later)")
            .default(true)
            .interact()
            .context("groundtruth Q&A opt-in")?;
        if !want {
            println!(
                "  Skipped. Re-run any time: `neoth groundtruth ask` or \
                 `neoth groundtruth add \"...\"`."
            );
            return Ok(());
        }

        let bank = match crate::cli::groundtruth_wizard::load_bank() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "ground-truth Q&A skipped: bank load failed");
                return Ok(());
            }
        };
        let lang = state.language_primary.as_deref().unwrap_or("en");
        let answers = match crate::cli::groundtruth_wizard::run_qa(&bank, lang) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(error = %e, "ground-truth Q&A aborted");
                return Ok(());
            }
        };
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        let db = crate::memory::store::default_path();
        match crate::cli::groundtruth_wizard::persist_answers(&db, &bank, &answers, lang, now_ns) {
            Ok(n) => println!("  {n} ground-truth row(s) stored."),
            Err(e) => tracing::warn!(error = %e, "ground-truth persist failed"),
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        let _ = state;
        println!(
            "(no TTY wizard available; run `neoth groundtruth ask` from a terminal to seed facts)"
        );
    }
    Ok(())
}

fn step1_license(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    info!("wizard step 1: license");

    println!("\n=================================================================");
    println!(
        "  Neoth v{} -- Personal AI Agent",
        env!("CARGO_PKG_VERSION")
    );
    println!("  neoth knows.");
    println!("=================================================================\n");
    println!("License: MIT OR Apache-2.0");
    println!("Telemetry: ZERO. Neoth never phones home.\n");

    if !interactive {
        if args.accept_license {
            state.steps_completed.push(1);
            return Ok(());
        }
        anyhow::bail!("--accept-license required in non-interactive mode");
    }

    #[cfg(feature = "wizard")]
    {
        let accept = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[1/7] Do you accept the license?")
            .default(false)
            .interact()
            .context("license confirmation prompt")?;
        if !accept {
            // Spec: deliberate refusal is exit 0, not failure.
            println!("Aborted. Re-run `neoth init` when ready.");
            std::process::exit(0);
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        if !args.accept_license {
            anyhow::bail!(
                "[1/7] Interactive license prompt requires the `wizard` feature. \
                 Re-run with --accept-license or rebuild with `--features wizard`."
            );
        }
    }

    state.steps_completed.push(1);
    Ok(())
}

fn step2_operator_id(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    info!("wizard step 2: operator_id");
    let default_id = get_os_username();

    let id = if let Some(ref id) = args.operator_id {
        validate_operator_id(id)?;
        id.clone()
    } else if !interactive {
        // Non-interactive without --operator-id: take OS username, fall back
        // to "operator" if it contains chars our validator rejects (Unicode,
        // spaces, etc. — common on Windows).
        if validate_operator_id(&default_id).is_ok() {
            default_id
        } else {
            "operator".to_string()
        }
    } else {
        #[cfg(feature = "wizard")]
        {
            loop {
                let input: String =
                    dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                        .with_prompt("[2/7] Operator identity (2-32 chars, [a-zA-Z0-9_-])")
                        .default(default_id.clone())
                        .interact_text()
                        .context("operator-id input")?;
                match validate_operator_id(&input) {
                    Ok(()) => break input,
                    Err(e) => {
                        eprintln!("  ✗ {e}");
                        continue;
                    }
                }
            }
        }
        #[cfg(not(feature = "wizard"))]
        {
            default_id
        }
    };
    state.operator_id = Some(id);
    state.steps_completed.push(2);
    Ok(())
}

fn step3_language(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    info!("wizard step 3: language");
    validate_bcp47(&args.language)?;
    let default_code = args
        .code_language
        .clone()
        .unwrap_or_else(|| args.language.clone());

    let (primary, code) = if !interactive {
        validate_bcp47(&default_code)?;
        (args.language.clone(), default_code)
    } else {
        #[cfg(feature = "wizard")]
        {
            let primary: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("[3/7] Primary language (BCP-47, e.g. en, de, zh-CN)")
                    .default(args.language.clone())
                    .validate_with(|input: &String| {
                        validate_bcp47(input).map_err(|e| e.to_string())
                    })
                    .interact_text()
                    .context("language input")?;
            let code: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("[3/7] Code-comment language (BCP-47)")
                    .default(primary.clone())
                    .validate_with(|input: &String| {
                        validate_bcp47(input).map_err(|e| e.to_string())
                    })
                    .interact_text()
                    .context("code-language input")?;
            (primary, code)
        }
        #[cfg(not(feature = "wizard"))]
        {
            validate_bcp47(&default_code)?;
            (args.language.clone(), default_code)
        }
    };

    state.language_primary = Some(primary);
    state.language_code = Some(code);
    state.steps_completed.push(3);
    Ok(())
}

fn step4_role(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    info!("wizard step 4: role");
    let role = if let Some(r) = args.role {
        r
    } else if !interactive {
        OperatorRole::None
    } else {
        #[cfg(feature = "wizard")]
        {
            const CHOICES: &[(OperatorRole, &str)] = &[
                (OperatorRole::Developer, "developer"),
                (OperatorRole::SecurityResearcher, "security-researcher"),
                (OperatorRole::Founder, "founder"),
                (OperatorRole::DataScientist, "data-scientist"),
                (OperatorRole::Writer, "writer"),
                (OperatorRole::None, "none (skip role inference)"),
            ];
            let labels: Vec<&str> = CHOICES.iter().map(|(_, l)| *l).collect();
            let idx = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("[4/7] Operator role (shapes profile inference defaults)")
                .items(&labels)
                .default(0)
                .interact()
                .context("role selection")?;
            CHOICES[idx].0
        }
        #[cfg(not(feature = "wizard"))]
        {
            OperatorRole::None
        }
    };
    state.role = Some(role);
    state.steps_completed.push(4);
    Ok(())
}

async fn step5_provider(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    info!("wizard step 5: provider");

    // Detect the three first-class CLIs and offer to install any that are
    // missing. Memory note: [[neoth-cli-installers]] — operator never opens
    // npm manually.
    let mut claude_path = which_binary("claude");
    let mut codex_path = which_binary("codex");
    let mut gemini_path = which_binary("gemini");

    if interactive {
        println!("\n[5/7] LLM Provider — detected CLIs:");
        println!(
            "  claude: {}",
            claude_path.as_deref().unwrap_or("NOT FOUND")
        );
        println!("  codex:  {}", codex_path.as_deref().unwrap_or("NOT FOUND"));
        println!(
            "  gemini: {}",
            gemini_path.as_deref().unwrap_or("NOT FOUND")
        );

        if claude_path.is_none() || codex_path.is_none() || gemini_path.is_none() {
            offer_cli_installs(&mut claude_path, &mut codex_path, &mut gemini_path).await?;
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
                "neoth init: non-interactive mode + no `--provider <kind>` + no claude/codex/gemini \
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
                (ProviderKind::GeminiApi, "gemini_api (Google Gemini REST)"),
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
                .with_prompt("[5/7] LLM provider kind")
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
            state.provider_model = Some(
                args.provider_model
                    .clone()
                    .unwrap_or_else(|| "claude-opus-4-7".to_string()),
            );
        }
        ProviderKind::OpenaiApi | ProviderKind::GeminiApi | ProviderKind::OpenaiCompat => {
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
                            "[5/7] {} endpoint (full URL incl. /v1)",
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
            let bundled_default = match kind {
                ProviderKind::OpenaiApi => "gpt-5.5",
                ProviderKind::GeminiApi => "gemini-3.1-pro-preview",
                ProviderKind::OpenaiCompat => "opus-4.7",
                _ => "",
            };
            let resolved_default = catalog_recommended_for_provider_kind(kind)
                .unwrap_or_else(|| bundled_default.to_string());
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

    state.steps_completed.push(5);
    Ok(())
}

/// Resolve a provider API key from (in order): --provider-key, env, interactive
/// password prompt. Returns None if user skips.
fn prompt_provider_key(
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
                .with_prompt(format!("[5/7] {label}"))
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

/// Step 5b — inference topology (D14b).
///
/// Operator picks:
///   1. **Mode** — single (one provider for all), triplet (same provider
///      on all three hemispheres but separate keys/models), or custom
///      (per-hemisphere provider).
///   2. **Accelerator** — auto-detected default, override allowed.
///   3. **Embedding provider** — local Qwen (uses the chosen accelerator)
///      or a cloud LLM with embedding endpoint.
///
/// Persists into `state.inference`. Non-interactive uses the
/// `--inference-mode` / `--accelerator-override` / `--embedding-provider`
/// flags and falls back to safe defaults (single mode, auto accelerator,
/// no embedding provider).
fn step5b_inference_topology(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::config::inference::{HemisphereSlot, InferenceProvider, TopologyMode};
    use crate::daemon::accelerator;

    info!("wizard step 5b: inference topology");

    // Auto-detect runs in both interactive and non-interactive paths so we
    // log what we found. Cheap (<500ms total) — see daemon::accelerator.
    let probe = accelerator::probe();
    info!(
        picked = probe.picked.as_str(),
        cuda = probe.cuda,
        metal = probe.metal,
        openvino = probe.openvino,
        "accelerator probe complete"
    );

    // Mirror the operator's step-5 provider choice into default_slot so the
    // common single-mode case round-trips without re-asking the operator.
    state.inference.default_slot = HemisphereSlot {
        provider: state.provider_kind.map(provider_kind_to_inference),
        model: state.provider_model.clone(),
        key: state.provider_key.clone(),
        endpoint: state.provider_endpoint.clone(),
        region: None,
        api_version: None,
    };

    // Non-interactive: honour CLI overrides, otherwise stay in single mode.
    if !interactive {
        let mode = parse_topology_mode_arg(args.inference_mode.as_deref())?;
        state.inference.mode = mode;
        if let Some(o) = args.accelerator_override.as_deref() {
            accelerator::Accelerator::from_str(o).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --accelerator-override '{o}'. Expected: cuda | metal | openvino | cpu"
                )
            })?;
            state.inference.accelerator_override = Some(o.to_string());
        }
        if let Some(e) = args.embedding_provider.as_deref() {
            let parsed = InferenceProvider::from_str(e).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --embedding-provider '{e}'. Expected: local_qwen | openai_api | anthropic_api | gemini_api"
                )
            })?;
            state.inference.embedding_provider = Some(parsed);
        }
        // E-2 Phase 4 (Session 14 Pick #23) — non-interactive depth
        // override. Clamp + stderr warning instead of the interactive
        // confirm screen (no TTY to draw it on).
        if let Some(raw) = args.council_depth {
            let (depth, clamped) =
                crate::config::inference::HemisphereCouncilDepth::new_clamped(raw);
            state.inference.hemisphere_council_depth = depth;
            if depth.get() > 1 {
                eprintln!(
                    "[neoth init] {}",
                    render_council_depth_cost_warning(depth.get()),
                );
            }
            if clamped {
                eprintln!(
                    "[neoth init] --council-depth={} exceeds MAX_HEMISPHERE_COUNCIL_DEPTH={}; clamped",
                    raw,
                    crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
                );
            }
        }
        state.steps_completed.push(56); // marker for step 5b (kept separate)
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        // ─── 1. Topology mode ──────────────────────────────────────────
        // Finding 6 (Session 13) — Topology preset table with a new
        // `local-only` privacy-positive option that hard-binds all
        // three hemispheres to LocalQwen on operator hardware. Default
        // moves to `local-only` when an accelerator (CUDA / Metal /
        // OpenVino) is detected; on CPU-only systems the default stays
        // at `single` because CPU Qwen is too slow for daily-use Council
        // mode.
        let gpu_detected = probe.picked != accelerator::Accelerator::Cpu;
        let local_only_hint = if gpu_detected {
            "all 3 hemispheres = LocalQwen on operator hardware (RECOMMENDED — zero cloud exposure)"
        } else {
            "all 3 hemispheres = LocalQwen (CPU — slower; prefer `single` without a GPU)"
        };
        let single_hint = if gpu_detected {
            "one provider for everything (cloud or local)"
        } else {
            "one provider for everything (recommended)"
        };
        // Topology preset table. `local-only` is a virtual preset — the
        // wizard expands it to Triplet mode + LocalQwen slots below so
        // freedom.yaml round-trips through the existing TopologyMode
        // enum without a new wire-format variant.
        let modes: [(TopologyMode, &str, String); 4] = [
            (TopologyMode::Single, "single", single_hint.to_string()),
            (
                TopologyMode::Triplet,
                "triplet",
                "same provider on all 3 hemispheres, separate keys/models allowed".to_string(),
            ),
            (
                TopologyMode::Custom,
                "custom",
                "fully custom — different provider per hemisphere".to_string(),
            ),
            (
                // local-only expands to Triplet mode at apply time.
                TopologyMode::Triplet,
                "local-only",
                local_only_hint.to_string(),
            ),
        ];
        let labels: Vec<String> = modes
            .iter()
            .map(|(_, n, hint)| format!("{n:<10}  {hint}"))
            .collect();
        let default_idx = topology_default_idx_for_probe(&probe);
        let pick = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[5b/8] Hemisphere LLM topology")
            .items(&labels)
            .default(default_idx)
            .interact()
            .context("topology mode select")?;
        state.inference.mode = modes[pick].0;
        let is_local_only_preset = matches!(modes[pick].1, "local-only");
        println!("  [5b/8] mode: {}", modes[pick].1);
        // Apply the local-only preset BEFORE the per-hemisphere loop —
        // the loop's gate on `Triplet|Custom` would otherwise overwrite
        // these with the per-role prompts.
        if is_local_only_preset {
            apply_local_only_preset(&mut state.inference);
            println!("  [5b/8] hemispheres (local-only preset):");
            println!("      left        provider=local_qwen  model=(adapter default)");
            println!("      right       provider=local_qwen  model=(adapter default)");
            println!("      cerebellum  provider=local_qwen  model=(adapter default)");
        }

        // ─── 2. Accelerator (only matters when local_qwen is in play) ──
        let accel_options = [
            accelerator::Accelerator::Cpu,
            accelerator::Accelerator::Cuda,
            accelerator::Accelerator::Metal,
            accelerator::Accelerator::OpenVino,
        ];
        // Build a "(detected: X)" hint so the operator sees what auto-detect
        // picked and which alternatives compile.
        let accel_labels: Vec<String> = accel_options
            .iter()
            .map(|a| {
                let marker = if *a == probe.picked {
                    " (detected)"
                } else {
                    ""
                };
                format!("{:<9}{marker}  {}", a.as_str(), a.description())
            })
            .collect();
        let default_idx = accel_options
            .iter()
            .position(|a| *a == probe.picked)
            .unwrap_or(0);
        let accel_pick = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("    accelerator (used by local_qwen forward pass)")
            .items(&accel_labels)
            .default(default_idx)
            .interact()
            .context("accelerator select")?;
        let chosen_accel = accel_options[accel_pick];
        // Only record an override when the operator picked something OTHER
        // than the detected default — auto-detection is preferred so portable
        // freedom.yaml files survive moving between hosts.
        state.inference.accelerator_override = if chosen_accel == probe.picked {
            None
        } else {
            Some(chosen_accel.as_str().to_string())
        };
        println!("  [5b/8] accelerator: {}", chosen_accel.as_str());

        // ─── 3. Per-hemisphere providers (only Triplet + Custom) ───────
        // SPEC_hemisphere_provider_selection.md §3: surface a recommended
        // provider per role (claude_cli/gemini/local_qwen) without
        // enforcing it. Custom mode additionally asks for a per-role
        // model so left=opus-4-7 + right=gemini-3.1-pro + cerebellum=Qwen3
        // can coexist without further CLI edits.
        if !is_local_only_preset
            && matches!(
                state.inference.mode,
                TopologyMode::Triplet | TopologyMode::Custom
            )
        {
            let is_custom = matches!(state.inference.mode, TopologyMode::Custom);
            for role in ["left", "right", "cerebellum"] {
                let recommended = recommended_provider_for_role(role);
                let chosen = prompt_inference_provider(
                    &format!(
                        "    {role} hemisphere provider (recommended: {})",
                        recommended.as_str()
                    ),
                    Some(recommended),
                )?;
                // In Triplet mode model/key/endpoint inherit from default so
                // the operator isn't asked 3× for the same value. In Custom
                // mode prompt for the model — the most common reason to
                // pick per-role providers in the first place.
                let model = if is_custom {
                    prompt_hemisphere_model(role, chosen, &state.inference.default_slot.model)?
                } else {
                    state.inference.default_slot.model.clone()
                };
                let slot = HemisphereSlot {
                    provider: Some(chosen),
                    model,
                    key: state.inference.default_slot.key.clone(),
                    endpoint: state.inference.default_slot.endpoint.clone(),
                    region: state.inference.default_slot.region.clone(),
                    api_version: state.inference.default_slot.api_version.clone(),
                };
                match role {
                    "left" => state.inference.left = slot,
                    "right" => state.inference.right = slot,
                    "cerebellum" => state.inference.cerebellum = slot,
                    _ => {}
                }
            }
            // Render summary so the operator confirms what they just
            // bound. Matches `neoth hemispheres show` table format.
            println!("  [5b/8] hemispheres:");
            for (label, slot) in [
                ("left      ", &state.inference.left),
                ("right     ", &state.inference.right),
                ("cerebellum", &state.inference.cerebellum),
            ] {
                let prov = slot
                    .provider
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| "(default)".into());
                let model = slot.model.as_deref().unwrap_or("(default)");
                println!("      {label}  provider={prov}  model={model}");
            }
        }

        // ─── 4. Embedding provider (independent of chat) ───────────────
        let want_emb = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(
                "    configure an embedding provider (used by skill router + ctx-mode re-rank)?",
            )
            .default(false)
            .interact()
            .context("embedding-yes/no confirm")?;
        if want_emb {
            let emb = prompt_inference_provider(
                "    embedding provider",
                Some(InferenceProvider::LocalQwen),
            )?;
            state.inference.embedding_provider = Some(emb);
            println!("  [5b/8] embeddings via {}", emb.as_str());
        }

        // ─── E-2 Phase 4 (Session 14 Pick #23) — Council recursion depth
        //     + one-screen cost warning. Wizard never asked about this
        //     before; operators only saw depth>1 if they hand-edited
        //     freedom.yaml, which silently produced 3^depth leaf calls
        //     per message. Now they pick it explicitly with the math
        //     spelled out + a confirm that defaults to "no".
        let depth_choice = if let Some(raw) = args.council_depth {
            // Operator passed --council-depth on the CLI even though
            // we're in the interactive path. Honour it without re-asking.
            let (d, _) = crate::config::inference::HemisphereCouncilDepth::new_clamped(raw);
            d.get()
        } else {
            let raw: u8 = dialoguer::Input::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
            .with_prompt(
                "[5b/8] Council recursion depth (1=flat default, 2..=4 enables fractal sub-councils)",
            )
            .default(1u8)
            .validate_with(|v: &u8| {
                if *v <= crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH {
                    Ok(())
                } else {
                    Err(format!(
                        "must be 0..={}",
                        crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
                    ))
                }
            })
            .interact_text()
            .context("council depth input")?;
            raw
        };
        let depth_choice = if depth_choice > 1 {
            // One-screen cost warning + confirm — default no, so a
            // distracted Enter-spammer doesn't accidentally opt in to
            // 81 leaf calls per message.
            println!("{}", render_council_depth_cost_warning(depth_choice));
            let proceed =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(format!(
                        "[5b/8] Proceed with hemisphere_council_depth={depth_choice}?"
                    ))
                    .default(false)
                    .interact()
                    .context("council depth confirm")?;
            if proceed {
                depth_choice
            } else {
                println!("  [5b/8] reverted to depth=1 (flat council)");
                1
            }
        } else {
            depth_choice
        };
        let (clamped_depth, was_clamped) =
            crate::config::inference::HemisphereCouncilDepth::new_clamped(depth_choice);
        state.inference.hemisphere_council_depth = clamped_depth;
        if was_clamped {
            println!(
                "  [5b/8] depth clamped to MAX_HEMISPHERE_COUNCIL_DEPTH={}",
                crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
            );
        }
        println!("  [5b/8] hemisphere_council_depth: {}", clamped_depth.get(),);
    }
    #[cfg(not(feature = "wizard"))]
    {
        // No dialoguer build → leave defaults from non-interactive path.
    }

    state.steps_completed.push(56);
    Ok(())
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
fn prompt_inference_provider(
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
fn prompt_inference_provider(
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
    };
    topology.mode = TopologyMode::Triplet;
    topology.default_slot = local_slot.clone();
    topology.left = local_slot.clone();
    topology.right = local_slot.clone();
    topology.cerebellum = local_slot;
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

fn recommended_provider_for_role(role: &str) -> crate::config::inference::InferenceProvider {
    use crate::config::inference::InferenceProvider as I;
    match role {
        "left" => I::ClaudeCli,       // analytic / structured reasoning
        "right" => I::Gemini,         // creative / freeform
        "cerebellum" => I::LocalQwen, // fast pattern matching / routing
        _ => I::ClaudeCli,
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
fn default_model_for(
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

/// Map a wizard `ProviderKind` to the catalog key used by
/// `crate::models::catalog`. Some kinds have no catalog source today
/// (LocalQwen, AzureOpenAi, Skip) and return `None` → wizard falls
/// back to bundled defaults.
fn catalog_key_for_provider_kind(kind: ProviderKind) -> Option<&'static str> {
    Some(match kind {
        ProviderKind::ClaudeCli => "anthropic_api",
        ProviderKind::OpenaiApi => "openai_api",
        ProviderKind::OpenaiCompat => "openai_compat",
        ProviderKind::GeminiApi => "gemini_api",
        ProviderKind::AwsBedrock => "aws_bedrock",
        ProviderKind::LocalQwen
        | ProviderKind::LocalOuro
        | ProviderKind::AzureOpenAi
        | ProviderKind::Skip => return None,
    })
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

    let key = catalog_key_for_provider_kind(kind)?;
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
fn catalog_key_for_provider(
    provider: crate::config::inference::InferenceProvider,
) -> Option<&'static str> {
    use crate::config::inference::InferenceProvider as I;
    Some(match provider {
        I::ClaudeCli | I::AnthropicApi => "anthropic_api",
        I::OpenAi => "openai_api",
        I::OpenAiCompat => "openai_compat",
        I::Gemini => "gemini_api",
        I::AwsBedrock => "aws_bedrock",
        // Local Qwen + AzureOpenAi don't have a model-catalog source
        // today — fall through to bundled defaults.
        I::LocalQwen | I::LocalOuro | I::AzureOpenAi => return None,
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
fn prompt_hemisphere_model(
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
fn catalog_model_ids_for_provider(
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
fn prompt_hemisphere_model(
    _role: &str,
    _provider: crate::config::inference::InferenceProvider,
    inherited_default: &Option<String>,
) -> Result<Option<String>> {
    Ok(inherited_default.clone())
}

/// Parse the `--inference-mode` flag. None → Single.
fn parse_topology_mode_arg(arg: Option<&str>) -> Result<crate::config::inference::TopologyMode> {
    use crate::config::inference::TopologyMode;
    match arg {
        None => Ok(TopologyMode::Single),
        Some(s) => TopologyMode::from_str(s).ok_or_else(|| {
            anyhow::anyhow!("invalid --inference-mode '{s}'. Expected: single | triplet | custom")
        }),
    }
}

/// Translate the legacy `ProviderKind` step-5 choice into the typed
/// `InferenceProvider`.
fn provider_kind_to_inference(
    kind: crate::cli::init::ProviderKind,
) -> crate::config::inference::InferenceProvider {
    use crate::cli::init::ProviderKind;
    use crate::config::inference::InferenceProvider as I;
    match kind {
        ProviderKind::ClaudeCli => I::ClaudeCli,
        ProviderKind::OpenaiApi => I::OpenAi,
        ProviderKind::OpenaiCompat => I::OpenAiCompat,
        ProviderKind::GeminiApi => I::Gemini,
        ProviderKind::LocalQwen => I::LocalQwen,
        ProviderKind::LocalOuro => I::LocalOuro,
        ProviderKind::AwsBedrock => I::AwsBedrock,
        ProviderKind::AzureOpenAi => I::AzureOpenAi,
        ProviderKind::Skip => I::ClaudeCli, // unreachable in practice
    }
}

async fn step6_channel(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    info!("wizard step 6: channel");

    // Resolve token from args or interactive prompt.
    let token = if let Some(t) = args.telegram_token.clone() {
        Some(t)
    } else if !interactive {
        None
    } else {
        #[cfg(feature = "wizard")]
        {
            let set_up =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("[6/7] Set up a Telegram bot now? (optional, can add later)")
                    .default(false)
                    .interact()
                    .context("telegram channel prompt")?;
            if !set_up {
                None
            } else {
                let t: String =
                    dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
                        .with_prompt("Telegram bot token (from @BotFather)")
                        .interact()
                        .context("telegram token input")?;
                Some(t)
            }
        }
        #[cfg(not(feature = "wizard"))]
        {
            None
        }
    };

    if let Some(t) = token {
        validate_telegram_token(&t)?;
        state.telegram_token = Some(crate::secret::SecretString::from(t.as_str()));
        state.telegram_user_id = args.telegram_user_id;
    } else if interactive {
        println!("  [6/7] Telegram skipped. Add later: `neoth channel add telegram`");
    }

    state.steps_completed.push(6);
    Ok(())
}

/// K-3.5 (Session 21, 2026-05-23) — interactive Keet pairing prompt.
///
/// Runs AFTER step6_channel (Telegram) so an operator who set both
/// Telegram + Keet has both configured. Skipped silently in non-
/// interactive mode + when `pear` is not on PATH (the operator-facing
/// install command surfaces so they know what to install if they want
/// the K-2b outbound path).
///
/// Flow:
///   1. Probe `pear --version` via `installers::pears::check_pears`.
///   2. If missing → print install command + skip the rest of the step
///      (don't bail — Telegram already covers the operator's channel).
///   3. Ask "Set up Keet pairing now?"  default No.
///   4. If yes → prompt for 24-word seed (Password input — pasted seed
///      shouldn't end up in scrollback).
///   5. Call `channels::keet_pairing::prepare_pairing(seed, port)`.
///      Validation failure → print error + offer to re-try; capped
///      at 3 attempts so an operator who pasted the wrong thing 3x
///      doesn't get stuck.
///   6. Render the pairing-anchor hex + freedom.yaml snippet + the
///      PAIRING_INSTRUCTIONS list. Bearer token value is NOT printed
///      (Debug-redacted in the module); it lands in credentials.yaml.
///   7. Stash seed + bearer in WizardState so `write_config` persists
///      both into credentials.yaml on the next step.
async fn step6b_keet_pairing(
    _args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    info!("wizard step 6b: keet pairing");

    if !interactive {
        // CI / cloud-init operators configure Keet by editing
        // ~/.neoth/credentials.yaml directly + running `neoth serve`.
        // No prompt available, no flag yet — K-3.5 deferred non-
        // interactive surface.
        state.steps_completed.push(60); // 6b marker
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        let pear_present = crate::installers::pears::check_pears().await.is_some();
        if !pear_present {
            // Operator can still skip Keet entirely (Telegram is
            // already wired in step 6). Surface the install path so
            // they know how to come back to this.
            println!();
            println!("[6b/8] Keet pairing skipped — `pear` runtime not on PATH.");
            let path = crate::installers::pears::recommend_install_path(false);
            let cmd = crate::installers::pears::install_command(path);
            if !cmd.is_empty() {
                println!("       To enable Keet later, install Pears + re-run `neoth init`:");
                println!("       $ {}", cmd.join(" "));
            }
            state.steps_completed.push(60);
            return Ok(());
        }

        let set_up = dialoguer::Confirm::with_theme(
            &dialoguer::theme::ColorfulTheme::default(),
        )
        .with_prompt("[6b/8] `pear` runtime detected. Pair Keet now? (optional)")
        .default(false)
        .interact()
        .context("keet pairing confirm")?;
        if !set_up {
            state.steps_completed.push(60);
            return Ok(());
        }

        const MAX_ATTEMPTS: usize = 3;
        for attempt in 1..=MAX_ATTEMPTS {
            let seed: String = dialoguer::Password::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
            .with_prompt(
                "  Paste the 24-word Keet seed phrase your phone showed (single-spaced, lowercase)",
            )
            .interact()
            .context("keet seed input")?;

            match crate::channels::keet_pairing::prepare_pairing(
                &seed,
                crate::channels::pears_bridge::DEFAULT_BRIDGE_PORT,
            ) {
                Ok(info) => {
                    println!();
                    println!("  ✔ Pairing prepared.");
                    println!("    Anchor (compare with phone): {}", info.pairing_anchor);
                    println!();
                    println!("    Operator steps:");
                    for line in crate::channels::keet_pairing::PAIRING_INSTRUCTIONS {
                        println!("      {line}");
                    }
                    println!();
                    println!("    freedom.yaml snippet (auto-written; shown for reference):");
                    for line in info.freedom_yaml_snippet.lines() {
                        println!("      {line}");
                    }
                    state.keet_seed_phrase =
                        Some(crate::secret::SecretString::from(seed.trim().to_string()));
                    state.pears_bearer_token = Some(crate::secret::SecretString::from(
                        info.bearer_token.expose().to_string(),
                    ));
                    break;
                }
                Err(e) => {
                    println!("  ✗ {e}");
                    if attempt == MAX_ATTEMPTS {
                        println!(
                            "  Maximum attempts reached. Skipping Keet pairing — re-run `neoth init` later."
                        );
                        break;
                    }
                    println!("  Re-paste the phrase (attempt {}/{}).", attempt + 1, MAX_ATTEMPTS);
                }
            }
        }
    }

    state.steps_completed.push(60);
    Ok(())
}

/// Step 7 — operator picks an autonomy level (Phase 28b R-23).
///
/// Five choices map to `permissions::AutonomyLevel`. Each one-line
/// consequence preview describes the *first* surprise the operator would
/// hit at that level so the choice stays concrete.
///
/// Non-interactive: honours `--autonomy <level>`. Falls back to `Standard`
/// if absent — least-surprise default per spec.
fn step7_autonomy(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    use crate::permissions::AutonomyLevel;

    info!("wizard step 7: autonomy");

    // Non-interactive path: --autonomy flag wins, otherwise default.
    if !interactive {
        let level = match args.autonomy.as_deref() {
            Some(s) => AutonomyLevel::from_str(s).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --autonomy '{s}'. Expected: strict | standard | elevated | full | custom"
                )
            })?,
            None => AutonomyLevel::Standard,
        };
        state.autonomy = level;
        state.steps_completed.push(7);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        let options = [
            (
                "strict",
                AutonomyLevel::Strict,
                "every write/exec/send asks before running",
            ),
            (
                "standard",
                AutonomyLevel::Standard,
                "writes inside ~/.neoth/ allowed; shell exec confirms; paid calls > €0.50 confirm",
            ),
            (
                "elevated",
                AutonomyLevel::Elevated,
                "writes everywhere allowed; shell inside ~/.neoth/scripts/ runs; paid calls > €5 confirm",
            ),
            (
                "full",
                AutonomyLevel::Full,
                "trusts the operator. Only policy.yaml dangerous_targets prompt",
            ),
            (
                "custom",
                AutonomyLevel::Custom,
                "fine-grained matrix (today behaves like standard until override file lands)",
            ),
        ];
        let labels: Vec<String> = options
            .iter()
            .map(|(name, _, hint)| format!("{name:<8}  {hint}"))
            .collect();

        let default_idx = options
            .iter()
            .position(|(_, l, _)| *l == AutonomyLevel::Standard)
            .unwrap_or(1);
        let choice = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[7/8] How autonomous should NEOTH be?")
            .items(&labels)
            .default(default_idx)
            .interact()
            .context("autonomy select")?;

        let picked = options[choice].1;
        if picked == AutonomyLevel::Full {
            // Spec calls for a hardware-2FA prompt the first time `full` is
            // enabled. Phase 28b ships a confirm step; the real 2FA hook
            // lands when `policy.yaml::dangerous_targets` is wired (Phase 33c).
            let confirmed =
                dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(
                        "  ⚠  `full` lets NEOTH run shell commands without asking. Continue?",
                    )
                    .default(false)
                    .interact()
                    .context("full-level confirm")?;
            if !confirmed {
                println!("  [7/8] Falling back to `standard`.");
                state.autonomy = AutonomyLevel::Standard;
            } else {
                state.autonomy = AutonomyLevel::Full;
            }
        } else {
            state.autonomy = picked;
        }
        println!("  [7/8] autonomy: {}", state.autonomy.as_str());
    }
    #[cfg(not(feature = "wizard"))]
    {
        state.autonomy = AutonomyLevel::Standard;
    }

    state.steps_completed.push(7);
    Ok(())
}

/// V03-09 Phase 2a wizard step. Two questions, both default to
/// the conservative answer so a hammered-Enter operator leaves
/// the daemon in the safest mode (no background HTTP traffic to
/// GitHub, no auto-apply).
///
/// Non-interactive runs leave the default `AutoUpdateConfig`
/// (enabled=false, auto_apply=false). Operators in CI / cold-
/// start scripts who want different values edit freedom.yaml
/// directly OR add `--auto-update` / `--auto-update-apply`
/// flags later (not yet wired — would land alongside other
/// non-interactive wizard knobs).
fn step7b_auto_update(_args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    info!("wizard step 7b: auto-update");

    if !interactive {
        // Default = enabled:false, auto_apply:false. Already set
        // by WizardState::default(); just record the step.
        state.steps_completed.push(70); // 7-and-a-half style marker
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        let check = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(
                "[7b/8] Allow NEOTH to check GitHub for newer releases? (no background traffic until you say yes)",
            )
            .default(false)
            .interact()
            .context("auto-update check confirm")?;

        if check {
            state.auto_update.enabled = true;
            let apply = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(
                    "  Also auto-apply updates (download + replace the daemon binary)? Recommend NO — most operators want check-only nag.",
                )
                .default(false)
                .interact()
                .context("auto-update apply confirm")?;
            state.auto_update.auto_apply = apply;
            println!(
                "  [7b/8] auto_update: enabled={} auto_apply={} channel={}",
                state.auto_update.enabled, state.auto_update.auto_apply, state.auto_update.channel,
            );
        } else {
            // Explicit "no" — make sure both flags are false even
            // if a prior wizard run had flipped them on.
            state.auto_update.enabled = false;
            state.auto_update.auto_apply = false;
            println!("  [7b/8] auto_update: disabled");
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        // Slim build: leave defaults.
    }

    state.steps_completed.push(70);
    Ok(())
}

/// D-102 wizard step 7c (Session 21, 2026-05-23) — bulk-enable
/// multiselect for discovered WASM plugins.
///
/// Per the 6/6 senior-dev panel verdict on D-102 (default-inactive),
/// the daemon NEVER auto-instantiates a discovered `.wasm` plugin.
/// This step is where the operator picks which ones to opt into during
/// onboarding — the alternative is running `neoth plugin enable <id>`
/// once per plugin after first boot, which is the friction the agent
/// panel called out as the noob-UX gap.
///
/// Behaviour:
///   - Scans `<neoth_dir>/plugins/` via `wasm_plugin::discovery::discover`.
///   - Zero discovered → silent no-op (the common first-run state).
///   - Non-interactive → leaves activations empty (every plugin stays
///     Pending; operator must enable via `neoth plugin enable <id>`
///     after install).
///   - Interactive → MultiSelect with one row per discovered plugin.
///     Picked → `Active`; unpicked → `Disabled` (NOT `Pending`, because
///     the operator HAS reviewed it during the wizard).
///
/// Activations land on `state.plugins.wasm.activations`; `write_config`
/// serialises the whole `plugins:` block into freedom.yaml so the next
/// daemon boot's `bootstrap_plugin_invoker` reads the operator's
/// decisions directly.
fn step7c_wasm_plugin_activation(
    args: &InitArgs,
    interactive: bool,
    neoth_dir: &std::path::Path,
    state: &mut WizardState,
) -> Result<()> {
    info!("wizard step 7c: wasm plugin activation");

    let plugins_root = neoth_dir.join("plugins");
    let report = crate::wasm_plugin::discovery::discover(&plugins_root);
    if report.loaded.is_empty() {
        // Common first-run case: no plugins discovered. Skip silently
        // so the wizard transcript stays tight. Operator passing
        // --enable-plugin without any plugins on disk gets a warn
        // so the typo'd id is at least surfaced.
        if !args.enable_plugin.is_empty() {
            warn!(
                ids = ?args.enable_plugin,
                "--enable-plugin given but no plugins discovered under {}",
                plugins_root.display()
            );
        }
        state.steps_completed.push(71); // 7c marker (7-and-three-quarters)
        return Ok(());
    }

    if !interactive {
        // Non-interactive runs honour --enable-plugin <id> (repeatable).
        // Unknown ids surface a warn so CI operators see the typo but
        // the wizard doesn't bail — partial activation is better than
        // a failed init.
        let known: std::collections::HashSet<&str> = report
            .loaded
            .iter()
            .map(|p| p.manifest.id.as_str())
            .collect();
        let mut activated: Vec<String> = Vec::new();
        let disabled: Vec<String> = Vec::new();
        for id in &args.enable_plugin {
            if known.contains(id.as_str()) {
                state.plugins.wasm.activations.insert(
                    id.clone(),
                    crate::wasm_plugin::discovery::PluginActivation::Active,
                );
                activated.push(id.clone());
            } else {
                let discovered: Vec<&str> = known.iter().copied().collect();
                warn!(
                    id = %id,
                    discovered = ?discovered,
                    "--enable-plugin id not found among discovered plugins; ignored"
                );
            }
        }
        // Any plugin not explicitly enabled stays PENDING (no entry =
        // default). We do NOT auto-Disabled them — that matches the
        // operator's mental model: `--enable-plugin X` is positive,
        // silence is "decide later" not "actively refused".
        let ids: Vec<&str> = report
            .loaded
            .iter()
            .map(|p| p.manifest.id.as_str())
            .collect();
        info!(
            count = report.loaded.len(),
            ids = ?ids,
            activated = ?activated,
            disabled = ?disabled,
            "wasm plugins discovered; non-interactive activation applied"
        );
        state.steps_completed.push(71);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        println!(
            "[7c/8] {} WASM plugin(s) discovered under ~/.neoth/plugins/.",
            report.loaded.len()
        );
        println!("       Default is PENDING (skipped at daemon boot until you opt in).");
        println!("       Pick the ones you want active. Unpicked = Disabled.");

        let labels: Vec<String> = report
            .loaded
            .iter()
            .map(|p| {
                format!(
                    "{}  ({})",
                    p.manifest.id,
                    p.manifest.name,
                )
            })
            .collect();

        let picked = dialoguer::MultiSelect::with_theme(
            &dialoguer::theme::ColorfulTheme::default(),
        )
        .with_prompt("[7c/8] Activate plugins (space to toggle, Enter to confirm)")
        .items(&labels)
        .interact()
        .context("wasm plugin multiselect")?;

        let picked_set: std::collections::HashSet<usize> = picked.into_iter().collect();
        let mut active_count = 0usize;
        let mut disabled_count = 0usize;
        for (idx, plugin) in report.loaded.iter().enumerate() {
            let state_val = if picked_set.contains(&idx) {
                active_count += 1;
                crate::wasm_plugin::discovery::PluginActivation::Active
            } else {
                disabled_count += 1;
                crate::wasm_plugin::discovery::PluginActivation::Disabled
            };
            state
                .plugins
                .wasm
                .activations
                .insert(plugin.manifest.id.clone(), state_val);
        }
        println!(
            "  [7c/8] {} plugin(s) Active, {} Disabled.",
            active_count, disabled_count,
        );
    }
    #[cfg(not(feature = "wizard"))]
    {
        // Slim build (no dialoguer): default Pending for every
        // discovered id — same as non-interactive.
    }

    state.steps_completed.push(71);
    Ok(())
}

fn step8_summary(args: &InitArgs, state: &mut WizardState) -> Result<()> {
    info!("wizard step 8: summary");
    // Step 7 (autonomy) already pushed `7`; pushing again here corrupted
    // `.initialized.steps_completed` so a partial-resume couldn't tell
    // whether step 7 had actually run. Step 8 is its own marker.
    state.steps_completed.push(8);
    let role_display = match state.role {
        Some(OperatorRole::Developer) => "developer",
        Some(OperatorRole::SecurityResearcher) => "security-researcher",
        Some(OperatorRole::Founder) => "founder",
        Some(OperatorRole::DataScientist) => "data-scientist",
        Some(OperatorRole::Writer) => "writer",
        Some(OperatorRole::None) | None => "none",
    };
    let provider_display = match state.provider_kind {
        Some(ProviderKind::ClaudeCli) => "claude_cli",
        Some(ProviderKind::OpenaiApi) => "openai_api",
        Some(ProviderKind::GeminiApi) => "gemini_api",
        Some(ProviderKind::OpenaiCompat) => "openai_compat",
        Some(ProviderKind::LocalQwen) => "local_qwen",
        Some(ProviderKind::LocalOuro) => "local_ouro",
        Some(ProviderKind::AwsBedrock) => "aws_bedrock",
        Some(ProviderKind::AzureOpenAi) => "azure_openai",
        Some(ProviderKind::Skip) | None => "(none)",
    };
    println!("\n[8/8] Setup Complete\n");
    println!(
        "  Operator:  {}",
        state.operator_id.as_deref().unwrap_or("(not set)")
    );
    println!(
        "  Language:  {} / code: {}",
        state.language_primary.as_deref().unwrap_or("en"),
        state.language_code.as_deref().unwrap_or("en")
    );
    println!("  Role:      {role_display}");
    println!("  Provider:  {provider_display}");
    println!(
        "  Channel:   {}",
        if state.telegram_token.is_some() {
            "Telegram"
        } else {
            "none"
        }
    );
    // Pick #34 (Session 14, operator-flow audit-fix Flow#1): surface
    // the consent-gate requirement BEFORE the operator runs `neoth
    // chat` and hits the consent-prompt cold. The gate exists for
    // every cloud provider (V03-08 + A-2 hard rule) — operators who
    // never read the docs reach `chat` first, see a consent-failure
    // error with no context, and don't know which command unblocks
    // them. The hint here connects wizard → consent → chat in one
    // operator-visible breath.
    let cloud_provider = matches!(
        state.provider_kind,
        Some(
            ProviderKind::ClaudeCli
                | ProviderKind::OpenaiApi
                | ProviderKind::GeminiApi
                | ProviderKind::OpenaiCompat
                | ProviderKind::AwsBedrock
                | ProviderKind::AzureOpenAi
        )
    );
    if cloud_provider {
        println!(
            "\n  Consent gate (V03-08): `neoth chat` will prompt you to grant cloud-egress consent\n  \
             for `{provider_display}` on first run. Pre-grant with:\n  \
             `neoth consent grant {provider_display}`"
        );
    }
    if !args.dry_run {
        println!("\nNext: neoth chat  |  neothd  |  neoth profile show");
    }
    println!("\nneoth knows. Good luck.");
    Ok(())
}

fn run_reconfigure_menu(_args: &InitArgs) -> Result<()> {
    println!("Neoth is already initialized.");
    println!();
    println!("To reconfigure individual sections, use:");
    println!("  neoth provider add        # change LLM provider");
    println!("  neoth channel add <kind>  # add a chat channel");
    println!("  neoth profile show        # inspect operator profile");
    println!();
    println!("To re-run the full wizard from scratch, pass --force.");
    Ok(())
}

// ── Atomic, mode-0600 file write helpers ──────────────────────────────────────
//
// SECURITY P0 (from Security Engineer review, OPEN_DECISIONS.md D-003):
// freedom.yaml and .initialized MUST be created with mode 0600 on `OpenOptions`
// BEFORE `open()` — never chmod-after-create (TOCTOU race). Pattern below uses
// `create_new(true)` + `.mode(0o600)` for unix; Windows inherits parent DACL
// (see wal/writer.rs::open_segment for the parallel Windows TODO).

/// `.initialized` marker payload (F-22).
///
/// Written once at the end of `neoth init`. Backward-compatible reads
/// rely on `#[serde(default)]` so an older marker (without `neoth_version`,
/// `init_time_iso8601`, `provider_kind`, `channels`) still parses.
///
/// What each field is for:
///   - `wizard_version` — schema version of THIS struct. Bump when a
///     field becomes required so `read_marker` can flag stale markers.
///   - `neoth_version` — the daemon binary version that wrote it.
///     `neoth doctor` uses this to detect "marker says v0.1, binary is
///     v0.2 — operator might want to re-run wizard for new steps".
///   - `operator_id` — pinned identity. Mismatched ops on the
///     `freedom.yaml` carry the operator_id; the marker pins it for
///     boot-time cross-check (BS-9 isolation builds on this).
///   - `init_time_unix` — original epoch seconds (kept for old code).
///   - `init_time_iso8601` — same instant, human-readable.
///   - `steps_completed` — wizard step numbers that ran successfully.
///   - `provider_kind` — which LLM the wizard configured. `neoth doctor`
///     surfaces this so the operator can confirm at-a-glance.
///   - `channels` — sorted, stable list of channel ids configured at
///     onboarding (`["telegram"]`, `["telegram", "keet"]`, etc).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitializedMarker {
    wizard_version: u8,
    #[serde(default)]
    neoth_version: String,
    operator_id: String,
    steps_completed: Vec<u8>,
    init_time_unix: u64,
    #[serde(default)]
    init_time_iso8601: String,
    #[serde(default)]
    provider_kind: Option<ProviderKind>,
    #[serde(default)]
    channels: Vec<String>,
}

fn ensure_dir_secure(dir: &std::path::Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create_dir_all {}", dir.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    Ok(())
}

/// Open a file for exclusive create with mode 0600 (unix).
/// Windows: parent DACL inherited; warning emitted at daemon startup.
fn open_for_create_secure(path: &std::path::Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("open_for_create {}", path.display()))
}

/// Atomic write: `target.tmp` → fsync → rename → parent dir fsync (unix).
/// On `--force` paths, the caller is responsible for removing existing `target`
/// before invoking (we accept a target that already exists by removing it).
fn write_atomically(target: &std::path::Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let tmp = target.with_extension("tmp");
    if tmp.exists() {
        std::fs::remove_file(&tmp).ok();
    }

    {
        let mut f = open_for_create_secure(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }

    if target.exists() {
        std::fs::remove_file(target).with_context(|| {
            format!("remove existing target {} before rename", target.display())
        })?;
    }
    std::fs::rename(&tmp, target)
        .with_context(|| format!("rename {} -> {}", tmp.display(), target.display()))?;

    // Durable rename on unix: fsync the parent directory.
    // Windows: rename is durable via NTFS metadata journal; no portable
    // equivalent of dir-fsync, so we skip.
    #[cfg(unix)]
    {
        if let Some(parent) = target.parent() {
            if parent.exists() {
                let dir = std::fs::File::open(parent)?;
                dir.sync_all().ok();
            }
        }
    }

    // Windows: restrict DACL to current user. Logs warning on failure, never
    // fails the write (degrades to "file inherits parent DACL").
    #[cfg(windows)]
    {
        let _ = crate::wal::win_acl::restrict_to_owner(target);
    }

    Ok(())
}

/// A3-tail: emit a `ConfigWrite` PRE_MUTATION_SNAPSHOT for the prior
/// freedom.yaml bytes before the reconfigure-flow rewrite. Honours the
/// operator's existing RollbackConfig when freedom.yaml is parseable;
/// falls back to defaults if the prior file is corrupt (still snapshot
/// it — corrupt bytes are exactly what an operator might want to roll
/// forward FROM during recovery).
async fn snapshot_existing_config(freedom_yaml: &std::path::Path) -> Result<()> {
    let prior_bytes = std::fs::read(freedom_yaml)
        .with_context(|| format!("read prior {} for snapshot", freedom_yaml.display()))?;
    let rollback_policy = match crate::config::FreedomConfig::load_from_path(freedom_yaml) {
        Ok(cfg) => cfg.rollback,
        Err(_) => crate::config::RollbackConfig::default(),
    };
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let wal_dir = crate::config::FreedomConfig::default_wal_dir();
    std::fs::create_dir_all(&wal_dir).context("create WAL dir for init snapshot")?;
    let segment = wal_dir.join(format!("init-snapshot-{now_unix}.wal"));
    let (writer, join) = crate::wal::writer::spawn(segment).context("spawn WAL snapshot writer")?;
    let _ = crate::wal::snapshot::emit_if_policy_allows(
        &writer,
        &rollback_policy,
        crate::wal::snapshot::MutationKind::ConfigWrite,
        freedom_yaml.display().to_string(),
        &prior_bytes,
        now_unix,
        Some("init wizard rewriting existing freedom.yaml".to_string()),
    )
    .await
    .context("emit pre-mutation snapshot for init rewrite")?;
    drop(writer);
    let _ = join.await;
    Ok(())
}

async fn write_config(neoth_dir: &std::path::Path, state: &WizardState) -> Result<()> {
    ensure_dir_secure(neoth_dir)?;
    ensure_dir_secure(&neoth_dir.join("credentials"))?;

    // Phase 33+ secret split (Codex audit #7): serialise freedom.yaml
    // WITHOUT the secret fields, write the secrets to credentials.yaml
    // alongside. Loading merges both back together — see
    // `FreedomConfig::load_from_path`.
    let mut public_state = state.clone();
    let provider_key = public_state.provider_key.take();
    let telegram_token = public_state.telegram_token.take();
    // K-3.5 (Session 21): keet seed + pears bearer never touch freedom.yaml.
    let keet_seed_phrase = public_state.keet_seed_phrase.take();
    let pears_bearer_token = public_state.pears_bearer_token.take();

    let freedom_yaml = neoth_dir.join("freedom.yaml");
    let serialized = serde_yaml::to_string(&public_state)
        .context("serialize WizardState as YAML for freedom.yaml")?;

    // A3-tail mutation-site wiring: when freedom.yaml ALREADY exists
    // (reconfigure flow, not first-run), capture its prior bytes
    // before overwriting so `neoth rollback list --kind config_write`
    // surfaces this rewrite. First-run wizard has no prior bytes →
    // skip (would produce a useless empty-restore snapshot).
    if freedom_yaml.exists() {
        if let Err(e) = snapshot_existing_config(&freedom_yaml).await {
            tracing::warn!(
                error = %e,
                path = %freedom_yaml.display(),
                "could not capture pre-overwrite snapshot for freedom.yaml — proceeding without rollback coverage for this write"
            );
        }
    }

    write_atomically(&freedom_yaml, serialized.as_bytes())?;
    info!(path = %freedom_yaml.display(), "freedom.yaml written (mode 0600 on unix)");

    let creds = crate::config::credentials::Credentials {
        provider_key,
        telegram_token,
        keet_seed_phrase,
        pears_bearer_token,
        ..Default::default()
    };
    let cred_path = neoth_dir.join("credentials.yaml");
    creds.write(&cred_path).context("write credentials.yaml")?;
    if creds.has_any() {
        info!(path = %cred_path.display(), "credentials.yaml written (mode 0600 on unix)");
    }
    Ok(())
}

fn write_initialized_marker(neoth_dir: &std::path::Path, state: &WizardState) -> Result<()> {
    let now_system = std::time::SystemTime::now();
    let now = now_system
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let marker = InitializedMarker {
        wizard_version: 2, // F-22: bumped to 2 after extending the schema
        neoth_version: env!("CARGO_PKG_VERSION").to_string(),
        operator_id: state.operator_id.clone().unwrap_or_default(),
        steps_completed: state.steps_completed.clone(),
        init_time_unix: now,
        init_time_iso8601: format_iso8601(now),
        provider_kind: state.provider_kind,
        channels: configured_channels(state),
    };

    let path = neoth_dir.join(".initialized");
    let json =
        serde_json::to_string_pretty(&marker).context("serialize InitializedMarker as JSON")?;
    write_atomically(&path, json.as_bytes())?;
    info!(path = %path.display(), "init marker written (mode 0600 on unix)");
    Ok(())
}

/// Format a UTC epoch-seconds value as ISO-8601 / RFC 3339 with `Z`
/// suffix. Naive month-day arithmetic so we don't pull a date crate
/// just for this — the marker is human-info only, not parsed back.
fn format_iso8601(unix_secs: u64) -> String {
    // chrono is already in the dependency tree (used by profile pipeline);
    // reuse it for accuracy + leap-year handling.
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| format!("{unix_secs}-epoch"))
}

/// Sorted, stable list of channel ids the wizard configured. Operators
/// reading the marker via `neoth doctor` see exactly which inbound
/// surfaces are live without parsing freedom.yaml. Extend this when a
/// future channel (keet, whatsapp, slack) lands.
fn configured_channels(state: &WizardState) -> Vec<String> {
    let mut out = Vec::new();
    if state.telegram_token.is_some() {
        out.push("telegram".to_string());
    }
    out.sort();
    out
}

// ── Validation helpers ────────────────────────────────────────────────────────

const RESERVED_IDS: &[&str] = &["neoth", "root", "system", "admin", "daemon", "nobody"];

/// Validate operator-id: 2-32 ASCII chars, [a-zA-Z0-9_-], not reserved.
///
/// ASCII only is intentional. Operator IDs appear in WAL audit events,
/// filesystem paths, and tracing fields — Unicode here would cause
/// downstream issues (NTFS codepage clashes, log-parser breakage).
pub fn validate_operator_id(id: &str) -> Result<()> {
    if id.len() < 2 || id.len() > 32 {
        anyhow::bail!("operator-id must be 2-32 chars (got {})", id.len());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!("operator-id may only contain [a-zA-Z0-9_-]: {id}");
    }
    if RESERVED_IDS.contains(&id) {
        anyhow::bail!("operator-id '{}' is reserved", id);
    }
    Ok(())
}

/// Validate BCP-47 language code (simplified pattern check).
pub fn validate_bcp47(code: &str) -> Result<()> {
    if code.len() < 2 || code.split('-').any(|p| p.is_empty() || p.len() > 8) {
        anyhow::bail!("invalid BCP-47 language code: {code}");
    }
    Ok(())
}

/// Validate role: listed key or custom [a-z0-9_-] 1-32 chars.
pub fn validate_role(role: &str) -> Result<()> {
    const KNOWN: &[&str] = &[
        "developer",
        "security-researcher",
        "founder",
        "data-scientist",
        "writer",
        "none",
    ];
    if KNOWN.contains(&role) {
        return Ok(());
    }
    if role.len() > 32
        || !role
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!(
            "invalid role '{}'. Must be known or [a-z0-9_-] max 32 chars",
            role
        );
    }
    Ok(())
}

/// Validate Telegram bot token: {8-12 digits}:{35 alphanum/dash/underscore}.
pub fn validate_telegram_token(token: &str) -> Result<()> {
    let parts: Vec<&str> = token.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid Telegram token (expected <digits>:<hash>)");
    }
    let (id_part, hash_part) = (parts[0], parts[1]);
    if !id_part.chars().all(|c| c.is_ascii_digit()) || id_part.len() < 8 || id_part.len() > 12 {
        anyhow::bail!("invalid Telegram token: numeric ID must be 8-12 digits");
    }
    if hash_part.len() != 35
        || !hash_part
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!("invalid Telegram token: hash must be 35 alphanumeric chars");
    }
    Ok(())
}

// ── OS utilities ──────────────────────────────────────────────────────────────

fn get_os_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

// `probe_local_bridge_sync` moved to `providers::local_probe` so the
// telemetry-guard lint (Phase 33c BS-6) keeps the daemon's `cli/` tree
// clean of any HTTP-client construction. Loopback-only probes still
// belong in `providers/` architecturally — the wizard is just one caller.
use crate::providers::local_probe::probe_local_bridge_sync;

/// Offer to npm-install the three CLIs that are missing on PATH. Updates the
/// passed-in path Options in place so the wizard can re-probe after install.
/// Quiet no-op when all three are already present.
#[cfg(feature = "wizard")]
async fn offer_cli_installs(
    claude: &mut Option<String>,
    codex: &mut Option<String>,
    gemini: &mut Option<String>,
) -> Result<()> {
    use crate::installers::{
        ALL, CLAUDE as INST_CLAUDE, CODEX as INST_CODEX, CliKind, GEMINI as INST_GEMINI,
    };

    // npm reachable?
    let npm = crate::installers::npm_version().await;
    let Some(npm_v) = npm else {
        println!();
        println!("  ! npm not found on PATH. To auto-install CLIs, install Node.js first:");
        println!("    https://nodejs.org/  (the LTS installer ships npm)");
        println!("  Skipping CLI auto-install for this run.");
        return Ok(());
    };
    println!("\n  npm {npm_v} detected — auto-install available for missing CLIs.");

    for kind in ALL {
        let current = match kind.binary {
            "claude" => claude.clone(),
            "codex" => codex.clone(),
            "gemini" => gemini.clone(),
            _ => None,
        };
        if current.is_some() {
            continue;
        }
        let install_it =
            dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(format!("Install {} ({})?", kind.display, kind.npm_package))
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
                "gemini" => *gemini = resolved.clone(),
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
            println!(
                "  ! {} installed but `{}` is still not on PATH. \
                 Open a new shell or check your npm prefix.",
                kind.display, kind.binary
            );
        }
        // Silence unused-CliKind import on cfg with no other use.
        let _ = (INST_CLAUDE, INST_CODEX, INST_GEMINI);
        let _: CliKind = *kind;
    }
    Ok(())
}

/// No-op fallback when the `wizard` feature is off. Wizard-less builds skip
/// interactive install offers entirely.
#[cfg(not(feature = "wizard"))]
async fn offer_cli_installs(
    _claude: &mut Option<String>,
    _codex: &mut Option<String>,
    _gemini: &mut Option<String>,
) -> Result<()> {
    Ok(())
}

fn which_binary(name: &str) -> Option<String> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    let sep = if cfg!(windows) { ';' } else { ':' };
    // On Windows npm installs CLI shims as `<name>`, `<name>.cmd`, `<name>.ps1`.
    // CreateProcessW can only invoke .cmd/.bat/.exe directly — the bare
    // `<name>` script needs a shell. Prefer .cmd > .exe > .bat > bare.
    let extensions: &[&str] = if cfg!(windows) {
        &[".cmd", ".exe", ".bat", ""]
    } else {
        &[""]
    };
    for dir in path_var.split(sep) {
        for ext in extensions {
            let mut candidate = std::path::PathBuf::from(dir).join(name);
            if !ext.is_empty() {
                // PathBuf::set_extension would strip a trailing dot in name; use string append.
                candidate =
                    std::path::PathBuf::from(format!("{}{ext}", candidate.to_string_lossy()));
            }
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_id_valid() {
        assert!(validate_operator_id("alex").is_ok());
        assert!(validate_operator_id("my-dev_1").is_ok());
    }

    #[test]
    fn operator_id_reserved() {
        assert!(validate_operator_id("root").is_err());
        assert!(validate_operator_id("neoth").is_err());
    }

    #[test]
    fn operator_id_length() {
        assert!(validate_operator_id("a").is_err());
        assert!(validate_operator_id(&"a".repeat(33)).is_err());
    }

    #[test]
    fn operator_id_charset() {
        assert!(validate_operator_id("has space").is_err());
        assert!(validate_operator_id("has@sym").is_err());
    }

    /// NOOB-UX-4 drift guard — every interactive wizard prompt
    /// (`dialoguer::Confirm/Select/Input`) MUST have an operator-
    /// readable `(recommended)` / `recommended` marker explaining
    /// the default choice. The full editorial pass needs real
    /// fresh-OS install testing, but this test pins the coverage
    /// ratio so a future refactor that drops a marker surfaces.
    /// Failure mode: a wizard prompt without a `(recommended)`
    /// tag forces a non-developer operator to guess.
    #[test]
    fn noob_ux_4_wizard_prompts_keep_recommended_markers() {
        let src = include_str!("init.rs");
        let prompt_count = src.matches("dialoguer::Confirm").count()
            + src.matches("dialoguer::Select").count()
            + src.matches("dialoguer::Input").count();
        let recommended_count = src.matches("recommended").count();
        assert!(
            prompt_count >= 1,
            "wizard prompt count went to zero — surface check"
        );
        assert!(
            recommended_count >= prompt_count,
            "NOOB-UX-4 drift: {} wizard prompts, {} 'recommended' markers — \
             every interactive prompt needs at least one recommended-default \
             hint for non-developer operators",
            prompt_count,
            recommended_count
        );
    }

    #[test]
    fn recommended_provider_matches_spec_table() {
        use crate::config::inference::InferenceProvider as I;
        // SPEC_hemisphere_provider_selection.md §2 table — pinned so a
        // future refactor of the recommendation logic doesn't silently
        // drift away from the documented operator-facing defaults.
        assert_eq!(recommended_provider_for_role("left"), I::ClaudeCli);
        assert_eq!(recommended_provider_for_role("right"), I::Gemini);
        assert_eq!(recommended_provider_for_role("cerebellum"), I::LocalQwen);
    }

    // ── Finding 6 (Session 13) wizard local-only preset ─────────────

    #[test]
    fn apply_local_only_preset_binds_every_slot_to_local_qwen() {
        use crate::config::inference::{InferenceProvider, InferenceTopology, TopologyMode};
        let mut topo = InferenceTopology::default();
        apply_local_only_preset(&mut topo);
        assert_eq!(topo.mode, TopologyMode::Triplet);
        assert_eq!(
            topo.default_slot.provider,
            Some(InferenceProvider::LocalQwen)
        );
        assert_eq!(topo.left.provider, Some(InferenceProvider::LocalQwen));
        assert_eq!(topo.right.provider, Some(InferenceProvider::LocalQwen));
        assert_eq!(topo.cerebellum.provider, Some(InferenceProvider::LocalQwen));
    }

    #[test]
    fn apply_local_only_preset_clears_keys_and_endpoints() {
        // Pre-fill the topology with cloud secrets, then assert the preset
        // wipes them — local-only must not retain stale cloud credentials
        // that confuse later wizard reconfigure passes.
        use crate::config::inference::{HemisphereSlot, InferenceProvider, InferenceTopology};
        let dirty = HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            model: Some("gpt-4o".into()),
            key: Some(crate::secret::SecretString::from("sk-test")),
            endpoint: Some("https://api.openai.com/v1".into()),
            region: None,
            api_version: None,
        };
        let mut topo = InferenceTopology {
            left: dirty.clone(),
            right: dirty.clone(),
            cerebellum: dirty.clone(),
            default_slot: dirty,
            ..InferenceTopology::default()
        };
        apply_local_only_preset(&mut topo);
        for slot in [
            &topo.left,
            &topo.right,
            &topo.cerebellum,
            &topo.default_slot,
        ] {
            assert_eq!(slot.provider, Some(InferenceProvider::LocalQwen));
            assert!(slot.model.is_none(), "model should be cleared");
            assert!(slot.key.is_none(), "key should be cleared");
            assert!(slot.endpoint.is_none(), "endpoint should be cleared");
        }
    }

    #[test]
    fn topology_default_idx_picks_local_only_when_gpu_detected() {
        use crate::daemon::accelerator::{Accelerator, Probe};
        for picked in [Accelerator::Cuda, Accelerator::Metal, Accelerator::OpenVino] {
            let probe = Probe {
                picked,
                cuda: matches!(picked, Accelerator::Cuda),
                metal: matches!(picked, Accelerator::Metal),
                openvino: matches!(picked, Accelerator::OpenVino),
            };
            assert_eq!(
                topology_default_idx_for_probe(&probe),
                3,
                "GPU-detected probe must default to local-only (idx 3), got otherwise for {picked:?}",
            );
        }
    }

    #[test]
    fn topology_default_idx_picks_single_when_cpu_only() {
        use crate::daemon::accelerator::{Accelerator, Probe};
        let probe = Probe {
            picked: Accelerator::Cpu,
            cuda: false,
            metal: false,
            openvino: false,
        };
        assert_eq!(topology_default_idx_for_probe(&probe), 0);
    }

    #[test]
    fn recommended_provider_unknown_role_falls_back_safely() {
        use crate::config::inference::InferenceProvider as I;
        // Defensive default — never crash if a renamed role is passed.
        assert_eq!(recommended_provider_for_role("hippocampus"), I::ClaudeCli);
        assert_eq!(recommended_provider_for_role(""), I::ClaudeCli);
    }

    #[test]
    fn default_model_for_known_pairs() {
        use crate::config::inference::InferenceProvider as I;
        assert_eq!(
            default_model_for("left", I::ClaudeCli),
            Some("claude-opus-4-7")
        );
        assert_eq!(
            default_model_for("right", I::Gemini),
            Some("gemini-3.1-pro-preview")
        );
        assert_eq!(
            default_model_for("cerebellum", I::LocalQwen),
            Some("Qwen/Qwen2.5-3B-Instruct"),
        );
    }

    #[test]
    fn default_model_for_unknown_role_provider_pair_returns_none() {
        use crate::config::inference::InferenceProvider as I;
        // Pick #11 Phase A (Session 14): the Hermes/OpenClaw stub
        // test was removed alongside the variants. This replacement
        // pins the broader "unknown role+provider pair → fall back
        // to free-text input" contract that the wizard depends on.
        assert_eq!(default_model_for("hippocampus", I::ClaudeCli), None);
        assert_eq!(default_model_for("left", I::LocalQwen), None);
        assert_eq!(default_model_for("cerebellum", I::Gemini), None);
    }

    // ── K-Models-Wizard-Integration (Session 14 Pick #4) ─────────────────

    #[test]
    fn catalog_key_for_provider_kind_maps_all_real_providers() {
        assert_eq!(
            catalog_key_for_provider_kind(ProviderKind::ClaudeCli),
            Some("anthropic_api")
        );
        assert_eq!(
            catalog_key_for_provider_kind(ProviderKind::OpenaiApi),
            Some("openai_api")
        );
        assert_eq!(
            catalog_key_for_provider_kind(ProviderKind::GeminiApi),
            Some("gemini_api")
        );
        assert_eq!(
            catalog_key_for_provider_kind(ProviderKind::AwsBedrock),
            Some("aws_bedrock")
        );
        assert_eq!(
            catalog_key_for_provider_kind(ProviderKind::OpenaiCompat),
            Some("openai_compat")
        );
    }

    #[test]
    fn catalog_key_for_provider_kind_returns_none_for_kinds_without_catalog_source() {
        // No remote list-models endpoint for these — wizard falls back
        // to bundled defaults.
        assert_eq!(catalog_key_for_provider_kind(ProviderKind::LocalQwen), None);
        assert_eq!(
            catalog_key_for_provider_kind(ProviderKind::AzureOpenAi),
            None
        );
        assert_eq!(catalog_key_for_provider_kind(ProviderKind::Skip), None);
    }

    #[test]
    fn catalog_recommended_returns_none_when_catalog_missing() {
        // Pointing at a non-existent catalog path → load returns empty
        // catalog → no provider entry → None. Confirms the wizard
        // bundled-fallback path fires on a fresh install.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never_existed.json");
        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::ClaudeCli);
        assert_eq!(result, None);
    }

    #[test]
    fn catalog_recommended_returns_id_when_catalog_has_provider_entry() {
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![
                ModelEntry::new("claude-opus-4-7"),
                ModelEntry::new("claude-sonnet-4-6"),
            ],
        );
        catalog.save().unwrap();

        // ClaudeCli → anthropic_api → recommended = first non-deprecated = opus-4-7
        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::ClaudeCli);
        assert_eq!(result, Some("claude-opus-4-7".to_string()));
    }

    #[test]
    fn catalog_recommended_skips_deprecated_first_entry() {
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "openai_api",
            SourceOrigin::Api,
            vec![
                ModelEntry::new("gpt-4o").marked_deprecated(),
                ModelEntry::new("gpt-5.4"),
                ModelEntry::new("gpt-5.5"),
            ],
        );
        catalog.save().unwrap();

        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::OpenaiApi);
        assert_eq!(result, Some("gpt-5.4".to_string()));
    }

    #[test]
    fn catalog_recommended_returns_none_for_kinds_without_source() {
        // Even when catalog file exists, LocalQwen has no source entry
        // because catalog_key_for_provider_kind returns None.
        use crate::models::catalog::{ModelEntry, ModelsCatalog, SourceOrigin};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.json");
        let mut catalog = ModelsCatalog::default().with_path(path.clone());
        catalog.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![ModelEntry::new("claude-opus-4-7")],
        );
        catalog.save().unwrap();

        let result = catalog_recommended_for_provider_kind_at(&path, ProviderKind::LocalQwen);
        assert_eq!(result, None);
    }

    #[test]
    fn default_model_for_unknown_pair_returns_none() {
        use crate::config::inference::InferenceProvider as I;
        // Pairs the SPEC doesn't pin (e.g. ClaudeCli for cerebellum)
        // return None so the wizard inherits the operator's step-5 model.
        assert_eq!(default_model_for("cerebellum", I::ClaudeCli), None);
        assert_eq!(default_model_for("right", I::OpenAi), None);
    }

    #[test]
    fn bcp47_valid() {
        assert!(validate_bcp47("en").is_ok());
        assert!(validate_bcp47("zh-CN").is_ok());
        assert!(validate_bcp47("pt-BR").is_ok());
    }

    #[test]
    fn bcp47_invalid() {
        assert!(validate_bcp47("").is_err());
        assert!(validate_bcp47("x").is_err());
    }

    #[test]
    fn role_valid() {
        assert!(validate_role("developer").is_ok());
        assert!(validate_role("security-researcher").is_ok());
        assert!(validate_role("custom-role").is_ok());
    }

    #[test]
    fn role_invalid() {
        assert!(validate_role("has space").is_err());
        assert!(validate_role(&"a".repeat(33)).is_err());
    }

    #[test]
    fn telegram_token_valid() {
        let token = format!("12345678:{}", "A".repeat(35));
        assert!(validate_telegram_token(&token).is_ok());
    }

    #[test]
    fn telegram_token_invalid() {
        assert!(validate_telegram_token("notvalid").is_err());
        assert!(validate_telegram_token("123:short").is_err());
    }

    // ── write_config + write_initialized_marker (O-1 acceptance) ───────────────

    fn fixture_state() -> WizardState {
        WizardState {
            operator_id: Some("alice".to_string()),
            language_primary: Some("en".to_string()),
            language_code: Some("en".to_string()),
            role: Some(OperatorRole::Developer),
            role_custom: None,
            provider_kind: Some(ProviderKind::ClaudeCli),
            provider_binary: Some("/usr/local/bin/claude".to_string()),
            provider_key: None,
            provider_endpoint: None,
            provider_model: Some("claude-opus-4-7".to_string()),
            telegram_token: Some(crate::secret::SecretString::from(
                "12345678:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )),
            telegram_user_id: Some(987654321),
            autonomy: crate::permissions::AutonomyLevel::Standard,
            inference: crate::config::inference::InferenceTopology::default(),
            auto_update: crate::config::AutoUpdateConfig::default(),
            plugins: crate::config::PluginsConfig::default(),
            keet_seed_phrase: None,
            pears_bearer_token: None,
            steps_completed: vec![1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    #[tokio::test]
    async fn write_config_creates_freedom_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let state = fixture_state();

        write_config(&neoth_dir, &state)
            .await
            .expect("write_config");

        let yaml = neoth_dir.join("freedom.yaml");
        assert!(
            yaml.exists(),
            "freedom.yaml should exist after write_config"
        );

        let body = std::fs::read_to_string(&yaml).unwrap();
        assert!(body.contains("operator_id: alice"));
        assert!(body.contains("provider_kind: claude_cli"));
        assert!(body.contains("role: developer"));
        // Phase 33+ split: secrets are NOT in freedom.yaml. They live in
        // the sibling credentials.yaml — verify the negative + check the
        // sibling file contains the token.
        assert!(
            !body.contains("12345678:AAAAAAAAA"),
            "telegram_token must NOT be embedded in freedom.yaml after the split",
        );
        let creds_body =
            std::fs::read_to_string(neoth_dir.join("credentials.yaml")).expect("credentials.yaml");
        assert!(
            creds_body.contains("12345678:AAAAAAAAA"),
            "telegram_token must be in credentials.yaml",
        );
        // V03-09 Phase 2a — freedom.yaml MUST carry the auto_update
        // block so operators see the field exists + can edit it
        // without a docs roundtrip.
        assert!(
            body.contains("auto_update:"),
            "freedom.yaml must serialize auto_update block: {body}"
        );
        assert!(
            body.contains("enabled: false"),
            "auto_update default must serialize enabled: false"
        );
    }

    #[tokio::test]
    async fn step7b_non_interactive_leaves_default_auto_update() {
        // The step writes the default AutoUpdateConfig when
        // interactive == false. Pin the contract so a future
        // refactor that flips the default doesn't silently
        // enable background HTTP traffic.
        let mut state = fixture_state();
        state.auto_update = crate::config::AutoUpdateConfig {
            // Pretend a prior wizard run had enabled it; the
            // non-interactive re-run MUST NOT clobber that.
            enabled: true,
            auto_apply: true,
            ..crate::config::AutoUpdateConfig::default()
        };

        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        step7b_auto_update(&args, false, &mut state).unwrap();

        // Non-interactive run preserves whatever the prior state
        // had — does NOT prompt, does NOT reset.
        assert!(state.auto_update.enabled);
        assert!(state.auto_update.auto_apply);
        // Step marker recorded.
        assert!(state.steps_completed.contains(&70));
    }

    #[tokio::test]
    async fn write_config_uses_atomic_temp_then_rename() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        write_config(&neoth_dir, &fixture_state())
            .await
            .expect("write_config");

        // After successful write, the .tmp sibling must be gone (rename consumed it).
        let tmp = neoth_dir.join("freedom.tmp");
        assert!(!tmp.exists(), "intermediate .tmp must be renamed away");
    }

    #[tokio::test]
    async fn write_config_overwrites_existing_on_force_path() {
        // Simulate a --force re-run: write twice with different states.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");

        let mut s1 = fixture_state();
        s1.operator_id = Some("first".to_string());
        write_config(&neoth_dir, &s1).await.expect("first write");

        let mut s2 = fixture_state();
        s2.operator_id = Some("second".to_string());
        write_config(&neoth_dir, &s2)
            .await
            .expect("second write replaces first");

        let yaml = neoth_dir.join("freedom.yaml");
        let body = std::fs::read_to_string(&yaml).unwrap();
        assert!(body.contains("operator_id: second"));
        assert!(!body.contains("operator_id: first"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_config_sets_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        write_config(&neoth_dir, &fixture_state())
            .await
            .expect("write_config");

        let yaml = neoth_dir.join("freedom.yaml");
        let mode = std::fs::metadata(&yaml).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "freedom.yaml must be 0600 on unix");

        let dir_mode = std::fs::metadata(&neoth_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "~/.neoth/ must be 0700 on unix");
    }

    #[test]
    fn write_initialized_marker_writes_json() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let state = fixture_state();

        write_initialized_marker(&neoth_dir, &state).expect("marker write");

        let path = neoth_dir.join(".initialized");
        assert!(path.exists());

        let body = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        // F-22: wizard_version bumped to 2 after schema extension.
        assert_eq!(parsed["wizard_version"], 2);
        assert_eq!(parsed["operator_id"], "alice");
        // 8 steps after Phase 28b inserted the autonomy step.
        assert_eq!(parsed["steps_completed"].as_array().unwrap().len(), 8);
        assert!(parsed["init_time_unix"].as_u64().unwrap() > 0);
        // F-22: new fields all populated.
        assert!(
            !parsed["neoth_version"].as_str().unwrap().is_empty(),
            "neoth_version must reflect the daemon binary version"
        );
        let iso = parsed["init_time_iso8601"].as_str().unwrap();
        assert!(
            iso.ends_with('Z') && iso.contains('T'),
            "iso8601 must be RFC 3339 UTC: {iso}"
        );
        // fixture_state sets provider_kind = ClaudeCli — should round-trip.
        assert_eq!(parsed["provider_kind"], "claude_cli");
        // fixture_state sets telegram_token, so channels lists telegram.
        let channels = parsed["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0], "telegram");
    }

    #[test]
    fn write_initialized_marker_records_telegram_channel() {
        // F-22: when the wizard configured Telegram, the marker should
        // list it under `channels`. Mirrors what `neoth doctor` will
        // surface to the operator.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let mut state = fixture_state();
        state.telegram_token = Some(crate::secret::SecretString::from("dummy-token"));

        write_initialized_marker(&neoth_dir, &state).expect("marker write");

        let body = std::fs::read_to_string(neoth_dir.join(".initialized")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let channels = parsed["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0], "telegram");
    }

    #[test]
    fn format_iso8601_rfc3339_round_trips_known_epoch() {
        // Bounds check: zero epoch maps to 1970.
        assert_eq!(format_iso8601(0), "1970-01-01T00:00:00Z");
        // RFC 3339 round-trip via chrono: write → parse → compare.
        let s = format_iso8601(1_700_000_000);
        let parsed = chrono::DateTime::parse_from_rfc3339(&s).expect("RFC3339 parse");
        assert_eq!(parsed.timestamp(), 1_700_000_000);
        // Format invariant — every output ends with Z + carries a T separator.
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
    }

    #[test]
    fn configured_channels_lists_telegram_when_token_set() {
        let mut s = fixture_state();
        s.telegram_token = None;
        assert!(configured_channels(&s).is_empty());
        s.telegram_token = Some(crate::secret::SecretString::from("t"));
        assert_eq!(configured_channels(&s), vec!["telegram".to_string()]);
    }

    #[test]
    fn initialized_marker_deserialises_old_v1_format() {
        // F-22 invariant: a `.initialized` file written by the previous
        // wizard (without neoth_version / iso8601 / provider_kind /
        // channels) must still parse — `#[serde(default)]` makes the
        // new fields optional. Future code paths (status, doctor)
        // depend on being able to read old markers without operator
        // intervention.
        let old_marker_json = r#"{
            "wizard_version": 1,
            "operator_id": "legacy_op",
            "steps_completed": [1, 2, 3, 4, 5, 6, 7],
            "init_time_unix": 1700000000
        }"#;
        let parsed: InitializedMarker = serde_json::from_str(old_marker_json).unwrap();
        assert_eq!(parsed.wizard_version, 1);
        assert_eq!(parsed.operator_id, "legacy_op");
        assert!(parsed.neoth_version.is_empty(), "missing field defaults");
        assert!(parsed.init_time_iso8601.is_empty());
        assert!(parsed.provider_kind.is_none());
        assert!(parsed.channels.is_empty());
    }

    #[tokio::test]
    async fn freedom_yaml_roundtrip_via_serde() {
        // Phase 33+ split: freedom.yaml carries the public fields, secrets
        // live in credentials.yaml. Verify the WizardState round-trips by
        // reading BOTH files (the daemon's `FreedomConfig::load_from_path`
        // does the same merge automatically).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let original = fixture_state();
        write_config(&neoth_dir, &original).await.expect("write");

        let body = std::fs::read_to_string(neoth_dir.join("freedom.yaml")).unwrap();
        let restored: WizardState = serde_yaml::from_str(&body).expect("deserialize");

        assert_eq!(restored.operator_id, original.operator_id);
        assert_eq!(restored.role, original.role);
        assert_eq!(restored.provider_kind, original.provider_kind);
        assert_eq!(restored.steps_completed, original.steps_completed);
        // Secrets MUST be absent from freedom.yaml.
        assert!(
            restored.telegram_token.is_none(),
            "telegram_token must NOT live in freedom.yaml after the split",
        );
        assert!(
            restored.provider_key.is_none(),
            "provider_key must NOT live in freedom.yaml after the split",
        );
        // But they DO live in the sibling credentials.yaml.
        let cred_path = neoth_dir.join("credentials.yaml");
        assert!(cred_path.exists(), "credentials.yaml must be created");
        let creds = crate::config::credentials::Credentials::load_or_default(&cred_path).unwrap();
        let restored_token = creds.telegram_token.unwrap();
        assert_eq!(
            restored_token.expose(),
            "12345678:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert!(format!("{restored_token:?}").contains("REDACTED"));
    }

    // ── Pick #23 (Session 14) — E-2 Phase 4 council-depth cost warning

    #[test]
    fn depth_warning_at_depth_1_is_not_invoked_in_production_but_still_pure_fn() {
        // The wizard never calls render_council_depth_cost_warning
        // when depth <= 1 — but the fn must stay pure-fn + total so a
        // future refactor that DOES call it with 0/1 still produces a
        // sensible string instead of panicking. At depth=1 the leaf
        // count is 3^1 = 3 (the three outer hemispheres, no recursion).
        let s = render_council_depth_cost_warning(1);
        assert!(s.contains("depth=1"));
        assert!(
            s.contains("3 leaf"),
            "depth=1 should report 3 leaf calls; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_2_shows_9_leaf_calls() {
        let s = render_council_depth_cost_warning(2);
        assert!(s.contains("depth=2"));
        assert!(s.contains("9 leaf"), "want 9 leaf calls; got: {s}");
        // Default cap is 15 — 9 ≤ 15, so the "fits within" branch
        // should fire.
        assert!(
            s.contains("fits within"),
            "depth-2 cost note must mention cap-fit; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_3_shows_27_leaf_calls_and_exceeds_cap() {
        let s = render_council_depth_cost_warning(3);
        assert!(s.contains("depth=3"));
        assert!(s.contains("27 leaf"), "want 27 leaf calls; got: {s}");
        // 27 > 15 default cap → must mention budget-exhausted.
        assert!(
            s.contains("exceeds"),
            "depth-3 cost note must mention exceeding cap; got: {s}"
        );
        assert!(
            s.contains("budget-exhausted"),
            "depth-3 must surface the Pick #19 BudgetToken interaction; got: {s}"
        );
    }

    #[test]
    fn depth_warning_at_4_shows_81_leaf_calls() {
        let s = render_council_depth_cost_warning(4);
        assert!(s.contains("depth=4"));
        assert!(s.contains("81 leaf"), "want 81 leaf calls; got: {s}");
    }

    #[test]
    fn depth_warning_clamps_above_max_to_max_leaf_count() {
        // Defensive: even if a caller bypasses the type system and
        // passes depth=255, the render fn must not over-compute.
        let s = render_council_depth_cost_warning(255);
        // Worst-case render still bounded to MAX_HEMISPHERE_COUNCIL_DEPTH
        // power = 3^4 = 81.
        assert!(
            s.contains("81 leaf"),
            "render must clamp internally to MAX depth; got: {s}"
        );
    }

    #[test]
    fn depth_warning_mentions_remedies_in_freedom_yaml() {
        // Operator-facing strings must point at the lever they can pull.
        let s = render_council_depth_cost_warning(3);
        assert!(s.contains("freedom.yaml"), "operator needs the remedy file");
        assert!(
            s.contains("max_calls_per_user_message"),
            "must name the actual config key"
        );
    }

    #[test]
    fn depth_warning_lists_recommended_defaults() {
        let s = render_council_depth_cost_warning(2);
        assert!(s.contains("depth=1"));
        assert!(s.contains("depth=2"));
        // The "depth=3+" hint should still be in the table even when
        // the operator picked depth=2 — they should see the next-step
        // implications too.
        assert!(s.contains("depth=3+"));
    }

    // ── D-102 wizard step 7c — bulk plugin activation tests ─────────

    #[test]
    fn step7c_missing_plugins_dir_silent_noop_records_marker() {
        // Common first-run state: ~/.neoth/plugins/ doesn't exist yet.
        // Step must not panic + must record its marker so a wizard
        // resume can tell the step ran.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth-empty");
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(
            state.plugins.wasm.activations.is_empty(),
            "no plugins discovered → no activations recorded"
        );
        assert!(state.steps_completed.contains(&71));
    }

    #[test]
    fn step7c_empty_plugins_dir_silent_noop() {
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        std::fs::create_dir_all(neoth_dir.join("plugins")).unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(state.plugins.wasm.activations.is_empty());
        assert!(state.steps_completed.contains(&71));
    }

    #[test]
    fn step7c_non_interactive_with_discovered_plugins_leaves_activations_empty() {
        // Per panel verdict on D-102 + non-interactive contract:
        // automatically opting plugins in without operator review
        // would defeat the default-inactive guarantee. Activations
        // must stay empty (= every id falls through to default
        // Pending at boot).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let plugins_root = neoth_dir.join("plugins").join("indexer_v1");
        std::fs::create_dir_all(&plugins_root).unwrap();
        std::fs::write(
            plugins_root.join("plugin.toml"),
            "id = \"indexer_v1\"\nname = \"Indexer\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        // Minimal valid WASM module bytes (wasm magic + version).
        std::fs::write(plugins_root.join("plugin.wasm"), [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(
            state.plugins.wasm.activations.is_empty(),
            "non-interactive run MUST NOT auto-activate; got {:?}",
            state.plugins.wasm.activations,
        );
        assert!(state.steps_completed.contains(&71));
    }

    #[test]
    fn step7c_non_interactive_with_enable_plugin_flag_activates_named_ids() {
        // E-21 non-interactive follow-up: `--enable-plugin indexer_v1`
        // during scripted bring-up MUST land indexer_v1 = Active in
        // freedom.yaml without prompting. Other discovered plugins
        // stay Pending (no entry = default at boot).
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        for id in ["indexer_v1", "recall_rerank"] {
            let pd = neoth_dir.join("plugins").join(id);
            std::fs::create_dir_all(&pd).unwrap();
            std::fs::write(
                pd.join("plugin.toml"),
                format!("id = \"{id}\"\nname = \"x\"\nversion = \"0.1.0\"\n"),
            )
            .unwrap();
            std::fs::write(pd.join("plugin.wasm"), [
                0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
            ])
            .unwrap();
        }
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            enable_plugin: vec!["indexer_v1".to_string()],
            ..Default::default()
        };
        let mut state = fixture_state();
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert_eq!(
            state
                .plugins
                .wasm
                .activations
                .get("indexer_v1")
                .copied(),
            Some(crate::wasm_plugin::discovery::PluginActivation::Active),
            "indexer_v1 must be Active after --enable-plugin",
        );
        // recall_rerank stays absent from the map → default Pending
        // at daemon boot.
        assert!(
            !state.plugins.wasm.activations.contains_key("recall_rerank"),
            "unspecified plugins must stay PENDING (no map entry); got {:?}",
            state.plugins.wasm.activations,
        );
    }

    #[test]
    fn step7c_non_interactive_unknown_enable_plugin_id_is_warn_not_fail() {
        // Typo on the operator's CLI line MUST NOT fail the wizard.
        // Per the non-interactive contract: partial activation is
        // better than a failed init.
        let dir = tempfile::tempdir().unwrap();
        let neoth_dir = dir.path().join(".neoth");
        let pd = neoth_dir.join("plugins").join("indexer_v1");
        std::fs::create_dir_all(&pd).unwrap();
        std::fs::write(
            pd.join("plugin.toml"),
            "id = \"indexer_v1\"\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(pd.join("plugin.wasm"), [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            enable_plugin: vec!["typoed_id".to_string(), "indexer_v1".to_string()],
            ..Default::default()
        };
        let mut state = fixture_state();
        // Should not panic / not bail; typoed_id is ignored, the valid
        // id still activates.
        step7c_wasm_plugin_activation(&args, false, &neoth_dir, &mut state).unwrap();
        assert!(state.plugins.wasm.activations.contains_key("indexer_v1"));
        assert!(!state.plugins.wasm.activations.contains_key("typoed_id"));
    }

    #[tokio::test]
    async fn step6b_non_interactive_silent_noop_records_marker() {
        // K-3.5 contract: non-interactive runs skip the prompt
        // entirely (no flag yet). The step must record its marker
        // for resume tracking.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        step6b_keet_pairing(&args, false, &mut state).await.unwrap();
        assert!(state.keet_seed_phrase.is_none());
        assert!(state.pears_bearer_token.is_none());
        assert!(state.steps_completed.contains(&60));
    }

    #[test]
    fn keet_credentials_round_trip_through_credentials_yaml() {
        // K-3.5 wire-format pin: WizardState.keet_seed_phrase +
        // pears_bearer_token MUST land in credentials.yaml, NOT
        // freedom.yaml. The Credentials struct now carries both
        // fields — verify they round-trip the YAML cleanly.
        let cred = crate::config::credentials::Credentials {
            keet_seed_phrase: Some(crate::secret::SecretString::from("alpha bravo charlie")),
            pears_bearer_token: Some(crate::secret::SecretString::from("deadbeef".repeat(8))),
            ..Default::default()
        };
        assert!(cred.has_any());
        let yaml = serde_yaml::to_string(&cred).expect("serialize");
        assert!(yaml.contains("keet_seed_phrase:"));
        assert!(yaml.contains("pears_bearer_token:"));
        let back: crate::config::credentials::Credentials =
            serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(
            back.keet_seed_phrase.as_ref().map(|s| s.expose().to_string()),
            Some("alpha bravo charlie".to_string()),
        );
        assert_eq!(
            back.pears_bearer_token.as_ref().map(|s| s.expose().len()),
            Some(64),
        );
    }

    #[test]
    fn wizard_state_keet_fields_excluded_from_freedom_yaml() {
        // K-3.5 split contract: state.keet_seed_phrase +
        // state.pears_bearer_token are #[serde(skip)] so they NEVER
        // surface in freedom.yaml. The serde wire pin: emitting a
        // WizardState carrying both fields produces YAML that does
        // NOT mention either key.
        let mut state = fixture_state();
        state.keet_seed_phrase = Some(crate::secret::SecretString::from("not_in_freedom_yaml"));
        state.pears_bearer_token =
            Some(crate::secret::SecretString::from("token_not_in_freedom_yaml"));
        let yaml = serde_yaml::to_string(&state).expect("serialize");
        assert!(
            !yaml.contains("keet_seed_phrase"),
            "keet_seed_phrase MUST be #[serde(skip)] — yaml: {yaml}"
        );
        assert!(
            !yaml.contains("pears_bearer_token"),
            "pears_bearer_token MUST be #[serde(skip)] — yaml: {yaml}"
        );
        assert!(!yaml.contains("not_in_freedom_yaml"));
        assert!(!yaml.contains("token_not_in_freedom_yaml"));
    }

    #[test]
    fn wizard_state_plugins_field_round_trips_through_yaml() {
        // D-102 wire-format pin: WizardState.plugins serialises into
        // the same `plugins:\n  wasm:\n    activations:\n      <id>: active`
        // shape FreedomConfig deserialises from. A drift here would
        // mean the operator's wizard picks don't reach the daemon.
        let mut state = fixture_state();
        state.plugins.wasm.activations.insert(
            "indexer_v1".to_string(),
            crate::wasm_plugin::discovery::PluginActivation::Active,
        );
        state.plugins.wasm.activations.insert(
            "recall_rerank".to_string(),
            crate::wasm_plugin::discovery::PluginActivation::Disabled,
        );
        let yaml = serde_yaml::to_string(&state).expect("serialize");
        assert!(yaml.contains("plugins:"));
        assert!(yaml.contains("wasm:"));
        assert!(yaml.contains("activations:"));
        assert!(yaml.contains("indexer_v1: active"));
        assert!(yaml.contains("recall_rerank: disabled"));
    }
}
