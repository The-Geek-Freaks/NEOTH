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
use tracing::{debug, info, warn};

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

    /// Skip the GUI/CLI mode-selection prompt and hand off to the GUI
    /// surface. The CLI wizard prints launch instructions for
    /// `neothd-gui` and exits — the GUI binary owns its own
    /// onboarding flow with the same freedom.yaml backing.
    #[arg(long)]
    pub gui: bool,

    /// Skip the GUI/CLI mode-selection prompt and stay in the
    /// terminal wizard. Useful for scripted bring-up that pipes
    /// answers in OR for power users who never want the GUI option
    /// surfaced. Mutually exclusive with `--gui`.
    #[arg(long, conflicts_with = "gui")]
    pub cli: bool,

    /// Accept license without prompt. Required with --non-interactive.
    #[arg(long)]
    pub accept_license: bool,

    /// NOOB-UX (Session 26) — operator's experience level override.
    /// `beginner | intermediate | advanced`. Skips the step1c prompt
    /// when set. Drives whether tech-deep wizard prompts surface or
    /// silently default. Non-interactive runs default to `beginner`.
    #[arg(long = "experience-level", value_name = "LEVEL")]
    pub experience_level_override: Option<String>,

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

    /// NOOB-UX-6 (Workstream B) — pre-download the LocalQwen model weights
    /// inside the wizard. Without this flag the wizard surfaces the
    /// `huggingface-cli download …` command and lets the operator run it
    /// later; with it the wizard offers to spawn the download synchronously
    /// (interactive confirms once more before spawning; non-interactive
    /// records the opt-in + surfaces the command to run).
    #[arg(long = "download-qwen-weights")]
    pub download_qwen_weights: bool,

    /// O-1 (Workstream B) — opt into the Obsidian-install wizard step. With
    /// no flag the wizard skips Obsidian in non-interactive mode; with the
    /// flag the wizard renders the OS-specific install command + records the
    /// opt-in. Interactive mode prompts independently of this flag.
    #[arg(long = "install-obsidian")]
    pub install_obsidian: bool,

    /// O-2 (Workstream B) — bootstrap a fresh NEOTH-Vault under the operator's
    /// `~/Documents/NEOTH-Vault/`. Writes the curated `.obsidian/` config +
    /// templates from `installers::obsidian_vault::bootstrap_files`. Non-
    /// interactive: skipped without this flag; with it, the vault is created
    /// at the default path. Interactive: prompted with operator-pickable path.
    #[arg(long = "bootstrap-vault")]
    pub bootstrap_vault: bool,

    /// N-1 (Workstream B) — opt into the n8n install wizard step. Non-
    /// interactive: skipped unless this flag is set. Interactive: prompts
    /// + auto-picks Docker over npm when both are available.
    #[arg(long = "install-n8n")]
    pub install_n8n: bool,

    /// E-16 (Workstream B) — Jarvis seed migration. Path to the operator's
    /// `HIPPOCAMPUS_CORE.md` (or the directory holding the 12 Jarvis stores).
    /// When set, the wizard records the import intent + surfaces the
    /// `neoth-migrate dry-run` / `apply --confirm` runbook against the path.
    /// Heavyweight migrations stay operator-triggered — the wizard never
    /// auto-applies. Non-interactive only honours the flag; interactive
    /// prompts for the path independently.
    #[arg(long = "import-jarvis", value_name = "PATH")]
    pub import_jarvis: Option<std::path::PathBuf>,

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
    /// NOOB-UX (Session 26): operator-declared experience level.
    /// Drives whether tech-deep wizard prompts (accelerator manual
    /// pick, embedding provider, council recursion depth, etc.)
    /// appear or get silently defaulted. `Beginner` is the safest
    /// first-run default — operators who know they want the deep
    /// flow pick `Advanced` at step 1c.
    #[serde(default)]
    pub experience_level: crate::wizard::recommend::ExperienceLevel,
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
    /// NOOB-UX-6 (Workstream B, Session 22) — operator opted into
    /// the Qwen-weights pre-download step. Recorded for the audit
    /// trail + wal NOOB_UX events; no behaviour beyond the wizard step.
    #[serde(default)]
    pub download_qwen_weights: bool,
    /// O-1 (Workstream B, Session 22) — operator opted into the
    /// Obsidian install wizard step. The actual install is operator-
    /// run; this field records the intent.
    #[serde(default)]
    pub install_obsidian: bool,
    /// O-2 (Workstream B, Session 22) — operator opted into the
    /// NEOTH-Vault bootstrap. When `true`, `step6d` materialised the
    /// curated `.obsidian/` config + templates at the recorded path.
    #[serde(default)]
    pub bootstrap_vault: bool,
    /// O-2 (Workstream B, Session 22) — vault path picked by the
    /// operator (default `~/Documents/NEOTH-Vault/`). `None` when
    /// `bootstrap_vault == false`. Persisted so the materialiser
    /// (O-4) finds the same vault on next boot.
    #[serde(default)]
    pub vault_path: Option<std::path::PathBuf>,
    /// N-1 (Workstream B, Session 22) — operator opted into n8n.
    /// Captures the strategy + port; the install command itself is
    /// operator-run.
    #[serde(default)]
    pub install_n8n: bool,
    /// E-16 (Workstream B, Session 22) — Jarvis seed migration
    /// source path. When `Some`, the wizard recorded the operator's
    /// intent to run `neoth-migrate` against this path. `None` for
    /// fresh-host operators with no Jarvis history.
    #[serde(default)]
    pub import_jarvis: Option<std::path::PathBuf>,
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
    debug!(interactive, force = args.force, "neoth init starting");

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

    // R-04 (Session 24) — restore in-flight wizard state from
    // ~/.neoth/wizard_checkpoint.json when the operator confirms
    // resume. Secrets are never persisted (the checkpoint module
    // strips them); operator re-enters provider_key + telegram_token
    // on resume. Decline → clear the file + start fresh.
    maybe_resume_from_checkpoint(&neoth_dir, interactive, &mut state)?;

    // Step 0 — operator picks GUI or CLI mode before anything else.
    // Per the HARD RULE `neoth_gui_first_screen_and_settings_parity`:
    // NEOTH targets non-developer operators ("noobs") who land on a
    // mode-selection screen, not a tracing-style logspew. If the
    // operator picks GUI here we exit the CLI wizard cleanly with a
    // pointer to `neothd-gui` — the wizard runs in either surface
    // with parity guarantees on settings.
    if step0_mode_selection(&args, interactive)?.exit_for_gui() {
        return Ok(());
    }
    step1_license(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step1b_detect_environment(&args, interactive, &neoth_dir).await;
    step1c_experience_level(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step2_operator_id(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step3_language(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step4_role(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5_provider(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5b_inference_topology(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5c_qwen_weights(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step5d_profile_approval_gate(interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6_channel(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6b_keet_pairing(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6c_obsidian_install(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6d_obsidian_vault_bootstrap(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6e_n8n_install(&args, interactive, &mut state).await?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6f_import_jarvis(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step6g_credential_import(&args, interactive, &neoth_dir).await;
    step6h_install_recommended(&args, interactive, &neoth_dir);
    step7_autonomy(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step7b_auto_update(&args, interactive, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step7c_wasm_plugin_activation(&args, interactive, &neoth_dir, &mut state)?;
    save_checkpoint_best_effort(&neoth_dir, &state);
    step8_summary(&args, &mut state)?;

    if args.dry_run {
        println!("[dry-run] No files written.");
    } else {
        write_config(&neoth_dir, &state).await?;
        write_initialized_marker(&neoth_dir, &state)?;
        // R-04: wizard reached the `.initialized` marker — the
        // checkpoint is no longer needed. Clear it so the next
        // `neoth init` (e.g. via --force or reconfigure) starts
        // from scratch instead of offering resume.
        if let Err(e) = crate::cli::wizard_checkpoint::clear_checkpoint(&neoth_dir) {
            tracing::warn!(error = %e, "post-init checkpoint clear failed (cosmetic)");
        }
        println!("Configuration written to ~/.neoth/");
        // R-05 (Session 24) — offer to auto-start the daemon + greet
        // with the first-tour message. Runs on TTY only; CI / pipe
        // skip so the wizard remains scriptable.
        if interactive {
            if let Err(e) = step9_offer_start_daemon(&neoth_dir) {
                tracing::warn!(error = %e, "auto-start daemon offer failed (cosmetic)");
            }
        }
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

/// R-04 (Session 24) — best-effort checkpoint write between wizard
/// steps. Failures here log a `warn!` and continue: the wizard keeps
/// running with the in-memory state, and the operator can still finish
/// in one sitting if the crash never actually arrives. The checkpoint
/// only earns its keep when there IS a crash; making save failures
/// fatal would let a transient disk issue (full /tmp, AV scanner lock)
/// kill an otherwise-healthy wizard run.
fn save_checkpoint_best_effort(neoth_dir: &std::path::Path, state: &WizardState) {
    if let Err(e) = crate::cli::wizard_checkpoint::save_checkpoint(neoth_dir, state) {
        tracing::warn!(
            error = %e,
            "wizard checkpoint save failed; in-memory state intact, resume after crash will lose this step",
        );
    }
}

/// R-04 (Session 24) — entry-point resume gate. Called once before
/// step1. When a checkpoint file exists AND the operator is on a TTY,
/// prompts `Resume from your previous wizard? (last updated …) [Y/n]`.
/// On confirm: hydrates `state` from the file. On decline: clears the
/// file so the next boot starts clean. Non-interactive (CI / pipe /
/// `--non-interactive`) auto-resumes silently — a crashed CI run that
/// re-runs `neoth init --non-interactive` should pick up where it
/// left off without needing operator input.
fn maybe_resume_from_checkpoint(
    neoth_dir: &std::path::Path,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    let checkpoint = match crate::cli::wizard_checkpoint::load_checkpoint(neoth_dir) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(()),
        Err(e) => {
            // Corrupt checkpoint shouldn't block a fresh wizard run.
            // Log + delete it so the next boot doesn't keep tripping.
            tracing::warn!(
                error = %e,
                "wizard checkpoint unreadable, ignoring + clearing",
            );
            let _ = crate::cli::wizard_checkpoint::clear_checkpoint(neoth_dir);
            return Ok(());
        }
    };

    let resume = if interactive {
        #[cfg(feature = "wizard")]
        {
            let age_hint = format_checkpoint_age(checkpoint.checkpoint_written_at_unix);
            let prompt = format!(
                "Found an incomplete wizard run ({age_hint}). \
                 Resume with your previous answers? (secrets must be re-entered)",
            );
            dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt(prompt)
                .default(true)
                .interact()
                .context("wizard resume confirm")?
        }
        #[cfg(not(feature = "wizard"))]
        {
            // No dialoguer available → fall through to the
            // non-interactive default (auto-resume).
            true
        }
    } else {
        // CI / pipe: silently auto-resume so a re-run of `neoth init
        // --non-interactive` after a transient crash picks up the
        // saved progress without needing TTY input.
        true
    };

    if resume {
        info!(
            steps_completed = ?checkpoint.steps_completed,
            "wizard resumed from checkpoint",
        );
        checkpoint.apply_to(state);
    } else {
        info!("operator declined wizard resume; clearing checkpoint");
        let _ = crate::cli::wizard_checkpoint::clear_checkpoint(neoth_dir);
    }
    Ok(())
}

/// Human-readable age hint for the resume prompt. Operator-facing only;
/// not parsed back. Returns e.g. `"last updated 2 hours ago"` or
/// `"timestamp unavailable"` if the wall clock looks bogus.
fn format_checkpoint_age(ts_unix: i64) -> String {
    if ts_unix <= 0 {
        return "timestamp unavailable".into();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let delta = now.saturating_sub(ts_unix);
    let phrase = match delta {
        d if d < 60 => "less than a minute ago".to_string(),
        d if d < 3_600 => format!("{} minutes ago", d / 60),
        d if d < 86_400 => format!("{} hours ago", d / 3_600),
        d => format!("{} days ago", d / 86_400),
    };
    format!("last updated {phrase}")
}

/// Marker filename written under `~/.neoth/` to flag the very first
/// chat session post-wizard. `neoth chat` reads + deletes it on its
/// next run and prepends the first-tour greeting. Single-use; once
/// the chat session consumes it the operator is past onboarding.
pub const FIRST_TOUR_MARKER: &str = "first_tour_pending";

/// Body printed for the very first interactive `neoth chat` after the
/// wizard finishes. Lives next to the marker constant so the chat
/// path imports both from a single source of truth.
pub const FIRST_TOUR_MESSAGE: &str = "Hi, I'm running. Want a quick tour? \
                                      Type `neoth chat \"give me a tour\"` \
                                      or `neoth recall --help` to start exploring.";

/// R-05 (Session 24) — final wizard step (interactive only). Offers
/// `Start NEOTH now? [Y/n]`. On Yes:
///   1. Spawns `neoth serve` as a detached background process so the
///      operator's terminal returns immediately + the daemon survives
///      the wizard process exit.
///   2. Drops the [`FIRST_TOUR_MARKER`] file so the next interactive
///      `neoth chat` session prepends the "Hi, I'm running. Want a
///      quick tour?" greeting.
///   3. Prints a confirmation line with the spawned PID + suggested
///      first command.
///
/// On No: prints a hint pointing at `neoth serve` and the same first-
/// tour suggestion. The marker is still written so a later
/// operator-initiated `neoth serve` + `neoth chat` lands in the same
/// onboarding-aware path.
fn step9_offer_start_daemon(neoth_dir: &std::path::Path) -> Result<()> {
    #[cfg(feature = "wizard")]
    {
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Start NEOTH now?")
            .default(true)
            .interact()
            .context("auto-start daemon confirm")?;

        // Always drop the first-tour marker — operator might start
        // the daemon later by hand, and the next chat session should
        // still feel like the first.
        if let Err(e) = write_first_tour_marker(neoth_dir) {
            tracing::warn!(error = %e, "first-tour marker write failed (cosmetic)");
        }

        if want {
            match spawn_daemon_detached() {
                Ok(pid) => println!(
                    "✓ NEOTH daemon started (pid {pid}). \
                     Try: `neoth chat \"give me a tour\"`",
                ),
                Err(e) => {
                    tracing::warn!(error = %e, "auto-start spawn failed");
                    println!(
                        "Couldn't auto-start the daemon ({e}). \
                         Run `neoth serve` from a new terminal, then \
                         `neoth chat \"give me a tour\"`."
                    );
                }
            }
        } else {
            println!(
                "Start NEOTH any time with `neoth serve`. \
                 First-chat suggestion: `neoth chat \"give me a tour\"`."
            );
        }
        Ok(())
    }
    #[cfg(not(feature = "wizard"))]
    {
        // No dialoguer build → leave the marker so the operator's
        // first chat session still gets the tour, and tell them how
        // to start the daemon.
        let _ = write_first_tour_marker(neoth_dir);
        println!(
            "Start NEOTH with `neoth serve` (run in a separate terminal). \
             First-chat suggestion: `neoth chat \"give me a tour\"`."
        );
        Ok(())
    }
}

/// Spawn the current binary with the `serve` subcommand as a detached
/// background process. Returns the child PID on success.
///
/// Detach semantics:
///   - **Unix**: `Stdio::null()` on stdin/stdout/stderr so the daemon
///     keeps running after the wizard's shell exits. The kernel inherits
///     orphaned processes by init/launchd, so an explicit `setsid` isn't
///     required for the wizard's "I just want it running" UX.
///   - **Windows**: `Stdio::null()` plus `CREATE_NEW_PROCESS_GROUP`
///     (via the `windows` crate's process flags) detaches the child
///     from the console so closing the wizard terminal doesn't SIGTERM
///     the daemon.
///
/// The path comes from `std::env::current_exe()` so a `cargo run
/// --bin neoth` invocation reuses the same binary instead of relying
/// on a `PATH` lookup that might miss a freshly-built dev binary.
fn spawn_daemon_detached() -> Result<u32> {
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().context("locate current neoth binary for daemon spawn")?;

    let mut cmd = Command::new(&exe);
    cmd.arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP = 0x00000200; DETACHED_PROCESS = 0x00000008.
        // The combination keeps the child alive after the wizard shell
        // closes + decouples it from Ctrl+C in the parent console.
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("spawn `{} serve`", exe.display()))?;
    Ok(child.id())
}

/// Drop the [`FIRST_TOUR_MARKER`] file. Idempotent — overwrites if
/// present (operator re-ran the wizard with `--force`, both runs
/// should land in the same onboarding-aware first-chat path).
fn write_first_tour_marker(neoth_dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(neoth_dir).with_context(|| {
        format!(
            "create neoth dir for first-tour marker: {}",
            neoth_dir.display(),
        )
    })?;
    let path = neoth_dir.join(FIRST_TOUR_MARKER);
    std::fs::write(&path, FIRST_TOUR_MESSAGE.as_bytes())
        .with_context(|| format!("write first-tour marker: {}", path.display()))?;
    Ok(())
}

/// Read + delete the first-tour marker. Returns `Some(message)` once
/// and `None` thereafter — used by the chat path to render the
/// greeting at most once per wizard run.
pub fn consume_first_tour_marker(neoth_dir: &std::path::Path) -> Option<String> {
    let path = neoth_dir.join(FIRST_TOUR_MARKER);
    let body = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    Some(body)
}

/// Outcome of the GUI/CLI mode-selection step. Callers branch on
/// [`Self::exit_for_gui`] to short-circuit the rest of the CLI
/// wizard when the operator picked the graphical surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WizardModeChoice {
    /// Stay in the terminal wizard. Default for non-interactive runs
    /// + advanced operators who prefer typing.
    Cli,
    /// Operator wants the GUI surface. Wizard prints how to launch
    /// `neothd-gui` and returns — the GUI binary owns its own
    /// onboarding flow with the same backing FreedomConfig.
    Gui,
}

impl WizardModeChoice {
    pub fn exit_for_gui(self) -> bool {
        matches!(self, Self::Gui)
    }
}

/// Step 0 — pick GUI vs CLI surface as the very first thing the
/// operator sees. Closes the HARD RULE
/// `neoth_gui_first_screen_and_settings_parity` violation flagged
/// in Session 26's UX review: a fresh `neoth init` run on a TTY
/// landed straight in a license prompt with tracing INFO lines
/// interleaved, which fails the "Alex's mom on Win11" sanity test.
///
/// Non-interactive runs (CI / scripted bring-up / `--non-interactive`)
/// always pick CLI silently — there's no operator to ask, and the
/// scripted flow IS the API surface they want. Operators who want
/// to script the GUI install pass `--gui` to skip the prompt.
fn step0_mode_selection(args: &InitArgs, interactive: bool) -> Result<WizardModeChoice> {
    debug!("wizard step 0: mode selection");
    if args.gui {
        print_gui_handoff_banner();
        return Ok(WizardModeChoice::Gui);
    }
    if args.cli {
        // Operator explicitly opted out of the mode picker.
        return Ok(WizardModeChoice::Cli);
    }
    if !interactive {
        return Ok(WizardModeChoice::Cli);
    }

    println!();
    println!("=================================================================");
    println!("  Welcome to Neoth.");
    println!("=================================================================");
    println!();
    println!("  How would you like to set up Neoth?");
    println!();
    println!("    [GUI]  Graphical wizard — clickable cards, no terminal");
    println!("           prompts. Recommended for first-time setup.");
    println!();
    println!("    [CLI]  Terminal wizard — keyboard-only, scriptable.");
    println!("           Recommended for developers, SSH sessions, and");
    println!("           anything you want to automate later.");
    println!();

    #[cfg(feature = "wizard")]
    {
        let options = ["GUI (recommended)", "CLI (terminal wizard)"];
        let picked = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Pick your setup surface")
            .items(&options)
            .default(0)
            .interact()
            .context("mode-selection prompt")?;
        match picked {
            0 => {
                print_gui_handoff_banner();
                Ok(WizardModeChoice::Gui)
            }
            _ => Ok(WizardModeChoice::Cli),
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        // No `dialoguer` available → silent CLI fallback. Operators
        // who want GUI on a wizard-less build pass `--gui` explicitly.
        let _ = args;
        Ok(WizardModeChoice::Cli)
    }
}

/// Render the operator-facing handoff message when the GUI surface
/// is picked. Kept separate so non-interactive `--gui` runs and the
/// interactive Select both print identical instructions.
fn print_gui_handoff_banner() {
    println!();
    println!("=================================================================");
    println!("  Launch the GUI wizard:");
    println!();
    println!("    neothd-gui");
    println!();
    println!("  The graphical wizard uses the same freedom.yaml + WAL backing");
    println!("  store as the CLI, so anything you configure there is visible");
    println!("  to `neoth chat` + `neoth serve` afterwards. To come back to");
    println!("  this terminal wizard at any point, run:");
    println!();
    println!("    neoth init --cli");
    println!("=================================================================");
    println!();
}

fn step1_license(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 1: license");

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
            .with_prompt("[1/9] Do you accept the license?")
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
                "[1/9] Interactive license prompt requires the `wizard` feature. \
                 Re-run with --accept-license or rebuild with `--features wizard`."
            );
        }
    }

    state.steps_completed.push(1);
    Ok(())
}

/// W-04 (Session 25) — wizard environment-detect step. Runs the
/// installer probes in parallel via `tokio::join!`, hands the
/// results to [`crate::wizard::detect_step::run_detect_step`] which
/// handles the 24h cache + atomic save, and prints a one-line
/// summary so the operator sees what the wizard found.
///
/// Non-interactive runs skip the probe pass entirely — probes do
/// subprocess + filesystem work that adds 2-15s of wall time, and
/// CI / scripted bring-up paths shouldn't pay that cost (the cache
/// hit on the next interactive run will fill the snapshot).
///
/// Failures are best-effort: a probe that fails returns None for
/// that field; a cache save IO error logs warn but doesn't abort
/// the wizard. The whole step is observability + planning input
/// for downstream steps — losing it never makes the wizard
/// non-functional.
async fn step1b_detect_environment(
    args: &InitArgs,
    interactive: bool,
    neoth_dir: &std::path::Path,
) {
    debug!("wizard step 1b: detect environment (W-04)");
    if !interactive {
        debug!("skipping environment detection in non-interactive mode");
        return;
    }
    if args.non_interactive {
        return;
    }
    println!("\n[1b/9] Detecting installed tools...");
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (docker, compose_v2, compose_v1, node_npm, ffmpeg) = tokio::join!(
        crate::installers::n8n::check_docker_available(),
        crate::installers::paperless::check_docker_compose_available(),
        crate::installers::paperless::check_docker_compose_legacy_available(),
        crate::installers::node::check_node_and_npm(),
        crate::installers::ffmpeg::check_ffmpeg_available(),
    );
    let (node_version, npm_version) = match node_npm {
        Some((n, m)) => (Some(n), Some(m)),
        None => (None, None),
    };
    let inputs = crate::wizard::detect_step::DetectStepInputs {
        docker_version: docker,
        docker_compose_version: compose_v2,
        docker_compose_legacy_version: compose_v1,
        npm_version,
        node_version,
        git_version: None, // No `installers::git` probe today; follow-up.
        ffmpeg_version: ffmpeg,
        gpu: None, // GPU probe needs subprocess + parser orchestration
        // (out of scope for the W-04 wiring; cached on
        // first daemon boot).
        disk_free_bytes: None,
    };
    match crate::wizard::detect_step::run_detect_step(neoth_dir, now_unix, &inputs) {
        Ok(outcome) => {
            let summary = outcome.report.render_summary();
            for line in summary.lines() {
                println!("  {line}");
            }
            if outcome.probed_now {
                println!("  (snapshot saved; daemon will read it on next boot)");
                // W-04 follow-up (Session 26): drop a 0xD5 sidecar so
                // the daemon's ingester emits the DETECT_COMPLETE
                // audit frame. The wizard has no WAL writer of its
                // own — at-least-once via sidecar matches the
                // installer_ran + credentials_import path.
                if let Some(payload) = outcome.frame_payload.as_ref() {
                    if let Err(e) = write_detect_complete_sidecar(neoth_dir, now_unix, payload) {
                        warn!(error = %e, "detect_complete sidecar write failed (non-fatal)");
                    }
                }
            } else {
                println!("  (using cached snapshot from earlier today)");
            }
        }
        Err(e) => {
            warn!(error = %e, "wizard detect step save failed (non-fatal)");
            println!("  (detection inconclusive — wizard continues without it)");
        }
    }
}

/// W-04 follow-up (Session 26): write the
/// [`DetectCompletePayload`](crate::wal::payloads_w08::DetectCompletePayload)
/// to a sidecar file under `~/.neoth/`. The daemon's
/// `detect_complete_sidecar` ingester picks it up on next tick,
/// emits the `0xD5 DETECT_COMPLETE` WAL frame, then deletes the
/// sidecar. Atomic via `.tmp` + rename, Windows-safe.
fn write_detect_complete_sidecar(
    neoth_dir: &std::path::Path,
    ts_unix: u64,
    payload: &crate::wal::payloads_w08::DetectCompletePayload,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(neoth_dir)?;
    // Zero-padded timestamp so lexicographic == chronological order
    // when the ingester walks the home dir.
    let final_path = neoth_dir.join(format!("detect_complete_{ts_unix:020}.json"));
    let tmp_path = final_path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(payload).map_err(std::io::Error::other)?;
    std::fs::write(&tmp_path, &body)?;
    if final_path.exists() {
        let _ = std::fs::remove_file(&final_path);
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// NOOB-UX (Session 26) step 1c — operator picks an experience
/// level so later steps know how much tech detail to surface.
///
/// Beginner is the default + safest pick: every tech-deep prompt
/// in later steps (accelerator manual pick, embedding provider,
/// council recursion depth, …) silently uses the detected /
/// recommended value. Intermediate surfaces those prompts with
/// reasonable defaults pre-selected. Advanced surfaces everything
/// with no pre-selection.
///
/// Non-interactive runs default to Beginner (CI / scripted bring-
/// up benefits from minimal surface). Operators who want a
/// specific level in non-interactive mode can pass
/// `--experience-level <beginner|intermediate|advanced>` (added
/// alongside this step).
fn step1c_experience_level(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::wizard::recommend::ExperienceLevel;
    debug!("wizard step 1c: experience level");

    if let Some(ref raw) = args.experience_level_override {
        let lvl = match raw.to_ascii_lowercase().as_str() {
            "beginner" => ExperienceLevel::Beginner,
            "intermediate" => ExperienceLevel::Intermediate,
            "advanced" => ExperienceLevel::Advanced,
            other => anyhow::bail!(
                "invalid --experience-level '{other}'. Expected: beginner | intermediate | advanced"
            ),
        };
        state.experience_level = lvl;
        return Ok(());
    }
    if !interactive {
        // Safest non-interactive default: hand-holding flow.
        state.experience_level = ExperienceLevel::Beginner;
        return Ok(());
    }

    println!("\n[1c/9] How comfortable are you with terminals + config files?\n");
    println!("    [B]eginner       Auto-pick every default for you. Hide tech toggles.");
    println!("    [I]ntermediate   Show toggles with reasonable defaults pre-selected.");
    println!("    [A]dvanced       Surface every advanced setting. No defaults applied.");
    println!();

    #[cfg(feature = "wizard")]
    {
        let options = [
            "Beginner (recommended for first-time setup)",
            "Intermediate (terminal-comfortable)",
            "Advanced (power user)",
        ];
        let picked = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[1c/9] Pick your experience level")
            .items(&options)
            .default(0)
            .interact()
            .context("experience-level prompt")?;
        state.experience_level = match picked {
            0 => ExperienceLevel::Beginner,
            1 => ExperienceLevel::Intermediate,
            _ => ExperienceLevel::Advanced,
        };
    }
    #[cfg(not(feature = "wizard"))]
    {
        state.experience_level = ExperienceLevel::Beginner;
    }

    println!(
        "  [1c/9] experience: {} — tech-deep prompts will {}.",
        state.experience_level.as_str(),
        match state.experience_level {
            ExperienceLevel::Beginner => "be silently defaulted",
            ExperienceLevel::Intermediate => "appear with pre-selected defaults",
            ExperienceLevel::Advanced => "appear without defaults",
        }
    );
    Ok(())
}

fn step2_operator_id(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 2: operator_id");
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
                        .with_prompt("[2/9] Operator identity (2-32 chars, [a-zA-Z0-9_-])")
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
    debug!("wizard step 3: language");
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
                    .with_prompt("[3/9] Primary language (BCP-47, e.g. en, de, zh-CN)")
                    .default(args.language.clone())
                    .validate_with(|input: &String| {
                        validate_bcp47(input).map_err(|e| e.to_string())
                    })
                    .interact_text()
                    .context("language input")?;
            let code: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("[3/9] Code-comment language (BCP-47)")
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
    debug!("wizard step 4: role");
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
                .with_prompt("[4/9] Operator role (shapes profile inference defaults)")
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

    debug!("wizard step 5b: inference topology");

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
            .with_prompt("[5b/9] Hemisphere LLM topology")
            .items(&labels)
            .default(default_idx)
            .interact()
            .context("topology mode select")?;
        state.inference.mode = modes[pick].0;
        let is_local_only_preset = matches!(modes[pick].1, "local-only");
        println!("  [5b/9] mode: {}", modes[pick].1);
        // Apply the local-only preset BEFORE the per-hemisphere loop —
        // the loop's gate on `Triplet|Custom` would otherwise overwrite
        // these with the per-role prompts.
        if is_local_only_preset {
            apply_local_only_preset(&mut state.inference);
            println!("  [5b/9] hemispheres (local-only preset):");
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
        // NOOB-UX gate: Beginner-level operators don't see the
        // manual accelerator pick — auto-detection is almost always
        // right, and surfacing the choice scares non-developers
        // (see Session 26 UX review for the screenshot Alex flagged).
        // Intermediate + Advanced still get the prompt with the
        // detected pick pre-selected as default.
        let chosen_accel = if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "  [5b/9] accelerator: {} (auto-detected, hidden in beginner mode)",
                probe.picked.as_str()
            );
            probe.picked
        } else {
            let accel_pick =
                dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("    accelerator (used by local_qwen forward pass)")
                    .items(&accel_labels)
                    .default(default_idx)
                    .interact()
                    .context("accelerator select")?;
            accel_options[accel_pick]
        };
        // Only record an override when the operator picked something OTHER
        // than the detected default — auto-detection is preferred so portable
        // freedom.yaml files survive moving between hosts.
        state.inference.accelerator_override = if chosen_accel == probe.picked {
            None
        } else {
            Some(chosen_accel.as_str().to_string())
        };
        // Beginner-mode already printed the "auto-detected" line above;
        // re-print only for Intermediate/Advanced who actually picked.
        if !matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!("  [5b/9] accelerator: {}", chosen_accel.as_str());
        }

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
            println!("  [5b/9] hemispheres:");
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
        // NOOB-UX gate: Beginner skips. Embedding provider is an
        // optional speed-up for the skill router + ctx-mode re-rank;
        // operators who don't know what either of those is get a
        // sensible no-op default.
        if !matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            let want_emb = dialoguer::Confirm::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
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
                println!("  [5b/9] embeddings via {}", emb.as_str());
            }
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
        } else if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            // NOOB-UX gate: Beginner gets the safe flat default
            // silently. Depth>1 is a 3^N cost multiplier — surfacing
            // it to non-developers risks accidental 81-leaf-call
            // councils that burn provider quota.
            1u8
        } else {
            let raw: u8 = dialoguer::Input::with_theme(
                &dialoguer::theme::ColorfulTheme::default(),
            )
            .with_prompt(
                "[5b/9] Council recursion depth (1=flat default, 2..=4 enables fractal sub-councils)",
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
                        "[5b/9] Proceed with hemisphere_council_depth={depth_choice}?"
                    ))
                    .default(false)
                    .interact()
                    .context("council depth confirm")?;
            if proceed {
                depth_choice
            } else {
                println!("  [5b/9] reverted to depth=1 (flat council)");
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
                "  [5b/9] depth clamped to MAX_HEMISPHERE_COUNCIL_DEPTH={}",
                crate::config::inference::MAX_HEMISPHERE_COUNCIL_DEPTH,
            );
        }
        println!("  [5b/9] hemisphere_council_depth: {}", clamped_depth.get(),);
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

/// Step 5c — NOOB-UX-6 (Workstream B): Qwen weights pre-download.
///
/// Only meaningful when the operator's inference topology pulls in
/// `LocalQwen` somewhere (default_slot or any hemisphere or the
/// embedding provider). The probe is sync + ~1ms (file_exists); when
/// weights are already cached the step is a no-op log line.
///
/// Non-interactive: honours `--download-qwen-weights`. With the flag
/// the step records the intent + surfaces the `huggingface-cli` line
/// the operator runs. Without the flag the step is a silent no-op
/// for hosts that don't touch LocalQwen.
async fn step5c_qwen_weights(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::installers::qwen_weights;

    debug!("wizard step 5c: qwen weights");

    if !inference_uses_local_qwen(&state.inference, &state.provider_kind) {
        // Operator picked cloud-only — no LocalQwen path = nothing to
        // pre-download. Mark step run + return.
        state.steps_completed.push(58);
        return Ok(());
    }

    let cached = qwen_weights::check_weights_cached(qwen_weights::DEFAULT_QWEN_MODEL_ID);

    if !interactive {
        let opted_in = args.download_qwen_weights;
        let action = qwen_weights::recommend_action(cached, opted_in);
        match action {
            qwen_weights::WeightsAction::AlreadyCached => {
                info!(
                    model = qwen_weights::DEFAULT_QWEN_MODEL_ID,
                    "qwen weights cached"
                );
            }
            qwen_weights::WeightsAction::DownloadNeeded => {
                state.download_qwen_weights = true;
                let cmd =
                    qwen_weights::weights_download_command(qwen_weights::DEFAULT_QWEN_MODEL_ID);
                info!(
                    cmd = %cmd.join(" "),
                    gb = qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
                    "operator opted into Qwen weights pre-download"
                );
            }
            qwen_weights::WeightsAction::OperatorSkipped => {
                warn!(
                    model = qwen_weights::DEFAULT_QWEN_MODEL_ID,
                    "LocalQwen configured but weights not cached + operator did not pass --download-qwen-weights; \
                     first chat will lazy-download"
                );
            }
        }
        state.steps_completed.push(58);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        if cached {
            println!("[5c/9] Qwen weights already cached (~/.cache/huggingface/hub/). Skipping.");
            state.steps_completed.push(58);
            return Ok(());
        }
        // NOOB-UX gate: Beginner skips the pre-download prompt. The
        // jargon ("Pre-download", "lazy-download", `huggingface-cli`)
        // scares non-developers and the safe default (lazy-fetch on
        // first chat with operator-visible progress) is already the
        // right answer for the "Alex's mom" cliff. Intermediate and
        // Advanced still see the prompt + the download recipe.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "[5c/9] Qwen weights will download automatically on your first chat (~{} GB, progress shown).",
                qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
            );
            state.steps_completed.push(58);
            return Ok(());
        }
        println!(
            "[5c/9] LocalQwen is wired but the {} weights aren't cached yet (~{} GB download).",
            qwen_weights::DEFAULT_QWEN_MODEL_ID,
            qwen_weights::DEFAULT_QWEN_DOWNLOAD_GB,
        );
        let opt_in = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Pre-download the Qwen weights now? (skip = lazy-download on first chat)")
            .default(false)
            .interact()
            .context("qwen weights opt-in")?;
        if !opt_in {
            println!(
                "  Skipped — weights will lazy-download on first chat (operator-visible progress)."
            );
            state.steps_completed.push(58);
            return Ok(());
        }
        state.download_qwen_weights = true;
        let cmd = qwen_weights::weights_download_command(qwen_weights::DEFAULT_QWEN_MODEL_ID);
        println!();
        println!("  To download the weights, run:");
        println!("      $ {}", cmd.join(" "));
        println!(
            "  (`huggingface-cli` ships with the `huggingface_hub` pip package; \
             `pip install -U huggingface_hub` if missing.)"
        );
    }

    state.steps_completed.push(58);
    Ok(())
}

/// True when the configured inference topology touches LocalQwen
/// anywhere — default slot, a hemisphere override, or the embedding
/// provider. Sole call site is `step5c_qwen_weights`'s skip-check.
fn inference_uses_local_qwen(
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

/// ADV-03 item 4 Phase 7 (Session 24): operator-awareness step for
/// the profile-claim approval gate. The actual persistence happens
/// via serde default on `ProfileConfig::require_approval` (true on
/// fresh installs + missing-field migrations) AND via the
/// `neoth profile migrate-require-approval [--disable]` CLI — this
/// step exists so fresh-install operators KNOW the gate is on
/// before their first chat triggers a profile extraction.
///
/// Non-interactive: silent no-op (the marker still records the step
/// completed for the audit trail).
///
/// Interactive: print a 3-line summary + the disable command, then
/// continue. No prompt — operator can opt out later via
/// `neoth profile migrate-require-approval --disable` if they
/// genuinely want auto-apply.
fn step5d_profile_approval_gate(interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 5d: profile approval gate awareness");
    if interactive {
        println!();
        // NOOB-UX gate: Beginner gets a 1-line plain-English summary.
        // The 6-line technical version ("prompt-injection attacks",
        // "multi-turn slow-poison chains", "daemon mode no tty",
        // `neoth profile pending`) is jargon dense — Intermediate +
        // Advanced still see it so they know the disable command.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!(
                "[5d/9] NEOTH will ask before saving facts about you (e.g. 'you live in Berlin')."
            );
        } else {
            println!("[5d/9] Profile-claim approval gate is ON by default.");
            println!(
                "  When NEOTH extracts a profile claim ('you live in Berlin', \
                 'your editor is vim'),"
            );
            println!(
                "  it asks you to confirm before writing — protects against \
                 prompt-injection attacks"
            );
            println!("  via channel inbound + multi-turn slow-poison chains.");
            println!(
                "  Daemon mode (no tty) parks pending claims in \
                 `neoth profile pending` for review."
            );
            println!("  Opt out anytime with: `neoth profile migrate-require-approval --disable`");
        }
    }
    state.steps_completed.push(60); // 5d marker (between 5c=58 and 6=61).
    Ok(())
}

async fn step6_channel(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 6: channel");

    // K-4b (Session 21): probe `pear` once so the prompt copy reflects
    // whether Keet is reachable as the preferred primary. The probe is
    // cheap (single subprocess spawn with 5s timeout) and only runs in
    // interactive mode where the prompt actually surfaces.
    let pear_present = if interactive {
        crate::installers::pears::check_pears().await.is_some()
    } else {
        false
    };

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
                    .with_prompt(k4b_telegram_prompt_text(pear_present))
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
        println!("  [6/9] Telegram skipped. Add later: `neoth channel add telegram`");
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
    debug!("wizard step 6b: keet pairing");

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
            println!("[6b/9] Keet pairing skipped — `pear` runtime not on PATH.");
            let path = crate::installers::pears::recommend_install_path(false);
            let cmd = crate::installers::pears::install_command(path);
            if !cmd.is_empty() {
                println!("       To enable Keet later, install Pears + re-run `neoth init`:");
                println!("       $ {}", cmd.join(" "));
            }
            state.steps_completed.push(60);
            return Ok(());
        }

        let set_up = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[6b/9] `pear` runtime detected. Pair Keet now? (optional)")
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
                    println!(
                        "  Re-paste the phrase (attempt {}/{}).",
                        attempt + 1,
                        MAX_ATTEMPTS
                    );
                }
            }
        }
    }

    state.steps_completed.push(60);
    Ok(())
}

/// Step 6c — O-1 (Workstream B): Obsidian install.
///
/// Surfaces the OS-appropriate `winget` / `brew` / AppImage URL.
/// Never auto-spawns the installer — operators paste the command
/// (per "operator GO per command" rule). The wizard records the
/// opt-in so subsequent boots know whether to nudge the vault step.
async fn step6c_obsidian_install(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::installers::obsidian;

    debug!("wizard step 6c: obsidian install");

    let already = obsidian::detect_obsidian_install();
    if already {
        info!("obsidian already installed; skipping install step");
        state.install_obsidian = true;
        state.steps_completed.push(61);
        return Ok(());
    }

    if !interactive {
        if !args.install_obsidian {
            state.steps_completed.push(61);
            return Ok(());
        }
        state.install_obsidian = true;
        let path = obsidian::recommend_install_path(false);
        let cmd = obsidian::install_command(path);
        info!(
            path = path.as_str(),
            cmd = %cmd.join(" "),
            "operator opted into obsidian install"
        );
        state.steps_completed.push(61);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        println!("[6c/9] Obsidian (vault archive — see step 6d) is not installed.");
        let install = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Install Obsidian now? (recommended for the NEOTH-Vault archive)")
            .default(true)
            .interact()
            .context("obsidian install confirm")?;
        if !install {
            state.steps_completed.push(61);
            return Ok(());
        }
        state.install_obsidian = true;
        let path = obsidian::recommend_install_path(false);
        let cmd = obsidian::install_command(path);
        println!();
        if cmd.is_empty() {
            println!("  Obsidian appears to be installed via a non-standard path. Skipping.");
        } else {
            println!("  Suggested install command for this platform:");
            println!("      $ {}", cmd.join(" "));
            println!("  Run it in a separate shell; the wizard does not auto-spawn installers.");
        }
    }

    state.steps_completed.push(61);
    Ok(())
}

/// Step 6d — O-2 (Workstream B): NEOTH-Vault bootstrap.
///
/// When the operator opts in, the wizard creates the vault directory
/// + writes the curated `.obsidian/` config + templates from
/// `installers::obsidian_vault::bootstrap_files`. Idempotent — files
/// that already exist are left alone (operator's edits win).
fn step6d_obsidian_vault_bootstrap(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    step6d_obsidian_vault_bootstrap_with_home(args, interactive, state, None)
}

/// Session 24 env-mutation refactor: explicit `home_override` lets
/// tests pass a tempdir instead of mutating the global HOME /
/// USERPROFILE env vars. Production call site passes `None` and
/// reads the env as before.
fn step6d_obsidian_vault_bootstrap_with_home(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
    home_override: Option<&std::path::Path>,
) -> Result<()> {
    use crate::installers::obsidian_vault;

    debug!("wizard step 6d: obsidian vault bootstrap");

    let resolve_vault = || -> Option<std::path::PathBuf> {
        match home_override {
            Some(h) => Some(obsidian_vault::default_vault_path_at(h)),
            None => obsidian_vault::default_vault_path(),
        }
    };

    let mut bootstrap = false;
    let mut vault_path: Option<std::path::PathBuf> = None;

    if !interactive {
        if !args.bootstrap_vault {
            state.steps_completed.push(62);
            return Ok(());
        }
        bootstrap = true;
        vault_path = resolve_vault();
    } else {
        #[cfg(feature = "wizard")]
        {
            let default_path = resolve_vault();
            let default_label = default_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<HOME unset>".to_string());
            println!();
            println!("[6d/9] Bootstrap a NEOTH-Vault at: {default_label}");
            let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("Create the vault now? (skip if you already have one)")
                .default(true)
                .interact()
                .context("vault bootstrap confirm")?;
            if want {
                bootstrap = true;
                vault_path = default_path;
            }
        }
    }

    if !bootstrap {
        state.steps_completed.push(62);
        return Ok(());
    }

    let Some(path) = vault_path else {
        warn!("vault bootstrap requested but no default path resolvable (HOME unset); skipping");
        state.steps_completed.push(62);
        return Ok(());
    };

    std::fs::create_dir_all(&path)
        .with_context(|| format!("create vault root at {}", path.display()))?;
    let mut wrote = 0usize;
    let mut skipped = 0usize;
    for file in obsidian_vault::bootstrap_files() {
        let target = path.join(file.relative_path);
        if target.exists() {
            skipped += 1;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create vault subdir {}", parent.display()))?;
        }
        std::fs::write(&target, file.content)
            .with_context(|| format!("write vault file {}", target.display()))?;
        wrote += 1;
    }
    info!(
        vault = %path.display(),
        wrote,
        skipped,
        "neoth vault bootstrapped"
    );

    state.bootstrap_vault = true;
    state.vault_path = Some(path);
    state.steps_completed.push(62);
    Ok(())
}

/// Step 6e — N-1 (Workstream B): n8n install opt-in.
///
/// Probes Docker + npm asynchronously, picks the recommended path
/// via `InstallStrategy::recommend`. The actual install command is
/// surfaced — never auto-spawned — so the operator runs it with full
/// visibility.
async fn step6e_n8n_install(
    args: &InitArgs,
    interactive: bool,
    state: &mut WizardState,
) -> Result<()> {
    use crate::installers::n8n;

    debug!("wizard step 6e: n8n install");

    if !interactive {
        if !args.install_n8n {
            state.steps_completed.push(63);
            return Ok(());
        }
        state.install_n8n = true;
        let docker = n8n::check_docker_available().await.is_some();
        let npm = n8n::check_npm_available().await.is_some();
        match n8n::InstallStrategy::recommend(docker, npm) {
            Some(strategy) => {
                let cmd = strategy.install_command(n8n::DEFAULT_N8N_PORT);
                info!(
                    strategy = strategy.as_str(),
                    cmd = %cmd.join(" "),
                    "operator opted into n8n install"
                );
            }
            None => {
                warn!(
                    "n8n install opted in but neither docker nor npm available; install one first"
                );
            }
        }
        state.steps_completed.push(63);
        return Ok(());
    }

    #[cfg(feature = "wizard")]
    {
        println!();
        // NOOB-UX gate: Beginner skips the n8n prompt entirely.
        // n8n is an optional workflow engine — non-developers don't
        // know what "workflow engine" means and the safe default is
        // "don't install" (matches `Recommendation::skip_optional_installers`
        // from wizard/recommend.rs). Intermediate + Advanced still
        // get the prompt.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            println!("[6e/9] Skipped optional workflow-engine install (n8n).");
            state.steps_completed.push(63);
            return Ok(());
        }
        let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("[6e/9] Install n8n (workflow engine, optional)?")
            .default(false)
            .interact()
            .context("n8n install confirm")?;
        if !want {
            state.steps_completed.push(63);
            return Ok(());
        }
        state.install_n8n = true;
        let docker = n8n::check_docker_available().await.is_some();
        let npm = n8n::check_npm_available().await.is_some();
        match n8n::InstallStrategy::recommend(docker, npm) {
            Some(strategy) => {
                let cmd = strategy.install_command(n8n::DEFAULT_N8N_PORT);
                println!();
                println!("  {}", strategy.description());
                println!("      $ {}", cmd.join(" "));
                println!(
                    "  Then open http://127.0.0.1:{} to finish n8n's first-run setup.",
                    n8n::DEFAULT_N8N_PORT
                );
            }
            None => {
                println!();
                println!(
                    "  Neither Docker nor npm is on PATH. Install one first, then re-run \
                     `neoth init --force` to get the n8n step."
                );
            }
        }
    }

    state.steps_completed.push(63);
    Ok(())
}

/// Step 6f — E-16 (Workstream B): Jarvis seed migration record.
///
/// The actual migration is the separate `neoth-migrate` binary; the
/// wizard records the operator's intent + surfaces the runbook so a
/// later `neoth-migrate apply --confirm` knows where to look. Never
/// auto-applies — migrating 12 stores is heavyweight + irreversible
/// once the WAL frames land.
fn step6f_import_jarvis(args: &InitArgs, interactive: bool, state: &mut WizardState) -> Result<()> {
    debug!("wizard step 6f: jarvis import intent");

    let path = if !interactive {
        args.import_jarvis.clone()
    } else {
        #[cfg(feature = "wizard")]
        {
            let want = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("[6f/9] Migrate an existing Jarvis HIPPOCAMPUS_CORE.md into NEOTH?")
                .default(false)
                .interact()
                .context("jarvis import confirm")?;
            if !want {
                state.steps_completed.push(64);
                return Ok(());
            }
            let raw: String =
                dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(
                        "  Path to HIPPOCAMPUS_CORE.md (or directory with 12 Jarvis stores)",
                    )
                    .allow_empty(true)
                    .interact_text()
                    .context("jarvis path input")?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(trimmed))
            }
        }
        #[cfg(not(feature = "wizard"))]
        {
            None
        }
    };

    let Some(path) = path else {
        state.steps_completed.push(64);
        return Ok(());
    };

    if !path.exists() {
        warn!(
            path = %path.display(),
            "jarvis import path does not exist; recording intent but operator must \
             repoint with `neoth-migrate dry-run --source <path>` before applying"
        );
    }

    state.import_jarvis = Some(path.clone());

    if interactive {
        #[cfg(feature = "wizard")]
        {
            println!();
            println!("  Intent recorded. Run the migration when ready:");
            println!("      $ neoth-migrate dry-run");
            println!("      $ neoth-migrate apply --confirm");
            println!(
                "  The wizard never auto-applies — migration writes WAL frames you can't undo."
            );
        }
    } else {
        info!(
            path = %path.display(),
            "jarvis import intent recorded; operator runs `neoth-migrate apply --confirm` manually"
        );
    }

    state.steps_completed.push(64);
    Ok(())
}

/// C-05 (Session 25) — wizard step 6g: credential import.
///
/// Iterates the available [`crate::credentials::CredentialImporter`]
/// impls (Chrome / Firefox + optional Bitwarden JSON export) +
/// hands the operator-visible outcomes to `run_wizard_step`,
/// which delegates redaction to the SC-17 typed gate
/// (`security::credential_redact::redact_credential_import`).
///
/// What this step writes to disk:
///   - Operator-visible summary printed inline.
///   - `~/.neoth/credentials_import_<ts>.json` sidecar file
///     containing the [`RedactedCredentialImportPayload`]. The
///     daemon's next boot picks up the sidecar, emits the
///     `0xD6 CREDENTIAL_IMPORT` WAL frame, then deletes the
///     sidecar — same at-least-once semantics the cluster audit
///     ingester uses.
///
/// What this step does NOT do: it never writes the secrets
/// themselves to disk. The SC-17 typed wrapper makes leaking
/// secret material via the WAL emit path unrepresentable. Future
/// secret-store integration (C-06) is the path operators will
/// use to actually consume the imported credentials.
///
/// Non-interactive runs skip the step entirely — credential
/// import requires explicit operator intent.
async fn step6g_credential_import(args: &InitArgs, interactive: bool, neoth_dir: &std::path::Path) {
    debug!("wizard step 6g: credential import (C-05)");
    if !interactive || args.non_interactive {
        debug!("skipping credential import in non-interactive mode");
        return;
    }
    println!("\n[6g/9] Credential import (optional).");
    println!("Bitwarden JSON / Chrome / Firefox sources detected on this host can");
    println!("be discovered + their structure recorded in a redacted audit frame.");
    println!("**No secret material is ever written to disk by this step.**");
    println!();

    #[cfg(feature = "wizard")]
    let opted_in = {
        match dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Run credential discovery now?")
            .default(false)
            .interact()
        {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "credential-import opt-in prompt failed; skipping step");
                return;
            }
        }
    };
    #[cfg(not(feature = "wizard"))]
    let opted_in = false;

    if !opted_in {
        println!("Skipped — operator declined.");
        return;
    }

    // Optional Bitwarden export path — empty input = no Bitwarden source.
    #[cfg(feature = "wizard")]
    let bitwarden_path: Option<std::path::PathBuf> = {
        match dialoguer::Input::<String>::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Bitwarden JSON export path (blank to skip)")
            .allow_empty(true)
            .interact_text()
        {
            Ok(s) if s.trim().is_empty() => None,
            Ok(s) => Some(std::path::PathBuf::from(s.trim())),
            Err(e) => {
                warn!(error = %e, "bitwarden path prompt failed; skipping bitwarden source");
                None
            }
        }
    };
    #[cfg(not(feature = "wizard"))]
    let bitwarden_path: Option<std::path::PathBuf> = None;

    let ts_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let importers =
        crate::credentials::wizard_step::build_wizard_importer_list(bitwarden_path.as_deref());
    let result =
        crate::credentials::wizard_step::run_wizard_step(importers, "primary", ts_unix).await;

    if result.summaries.is_empty() {
        println!("No credential sources were available on this host.");
        return;
    }

    println!("\nDiscovered credential sources:");
    for s in &result.summaries {
        if s.ok {
            println!(
                "  • {} — {} entries, {} warnings",
                s.importer_name, s.entry_count, s.warning_count,
            );
        } else {
            println!("  • {} — FAILED: {}", s.importer_name, s.error_summary);
        }
    }
    println!(
        "\nSC-17 redactor pass: services_redacted = {} (entry_count = {})",
        result.redacted_payload.services_redacted, result.redacted_payload.entry_count,
    );

    // Sidecar drop — daemon picks up + emits 0xD6 WAL frame on next
    // boot. Atomic `.tmp` + rename, Windows-safe.
    if let Err(e) = write_credential_import_sidecar(neoth_dir, ts_unix, &result.redacted_payload) {
        warn!(error = %e, "credential import sidecar write failed (non-fatal)");
    } else {
        println!("Saved redacted import record (operator-private).");
    }
}

/// Write the SC-17-redacted credential-import payload to a sidecar
/// file under `~/.neoth/`. Pure-fn over the home dir + payload so
/// tests can exercise the disk shape without the wizard prompts.
fn write_credential_import_sidecar(
    neoth_dir: &std::path::Path,
    ts_unix: i64,
    payload: &crate::security::credential_redact::RedactedCredentialImportPayload,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(neoth_dir)?;
    let final_path = neoth_dir.join(format!("credentials_import_{ts_unix}.json"));
    let tmp_path = final_path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(payload).map_err(std::io::Error::other)?;
    std::fs::write(&tmp_path, &body)?;
    if final_path.exists() {
        let _ = std::fs::remove_file(&final_path);
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// W-05 (Session 25) — wizard step 6h: install-command preview.
///
/// Reads the detect cache produced by `step1b_detect_environment`
/// (W-04), identifies operator-visible missing dev tools (docker,
/// node) and renders the per-OS install argv via
/// `wizard::install_step::FallbackChain::for_host()` +
/// `dry_run_install_commands`. The operator copies + runs the
/// commands manually — the wizard NEVER executes privileged
/// installs on the operator's behalf. This keeps the wizard's
/// surface "informational" and matches AGENTER's hard rule about
/// not invoking package managers without explicit go.
///
/// Non-interactive runs skip entirely. Operators who want to
/// audit the chain without prompts use
/// `neoth wizard install --dry-run` (CLI surface in W-05b).
fn step6h_install_recommended(args: &InitArgs, interactive: bool, neoth_dir: &std::path::Path) {
    debug!("wizard step 6h: install-command preview (W-05)");
    if !interactive || args.non_interactive {
        debug!("skipping install-command preview in non-interactive mode");
        return;
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let Some(report) = crate::installers::detect::load_cache(neoth_dir, now_unix) else {
        debug!("no detect cache; W-05 step has nothing to recommend");
        return;
    };

    // Identify the missing tools operators most commonly need
    // (docker for n8n + paperless; node for n8n; ffmpeg for media
    // ingest). Each entry: (canonical pkg_id, friendly name,
    // currently-detected-version Option).
    let candidates: Vec<(&str, &str, &Option<String>)> = vec![
        ("Docker.Docker", "Docker", &report.docker_version),
        ("OpenJS.NodeJS.LTS", "Node.js", &report.node_version),
        ("Gyan.FFmpeg", "ffmpeg", &report.ffmpeg_version),
    ];
    let missing: Vec<(&str, &str)> = candidates
        .iter()
        .filter(|(_, _, v)| v.is_none())
        .map(|(pkg, name, _)| (*pkg, *name))
        .collect();
    if missing.is_empty() {
        debug!("W-05: detect cache reports every recommended tool is already present");
        return;
    }

    println!("\n[6h/9] Install-command preview (W-05).");
    println!("These tools were NOT detected by step 1b. Copy + run the commands");
    println!("for the package manager you prefer. NEOTH never runs them for you.");
    println!();

    #[cfg(feature = "wizard")]
    let opted_in = {
        match dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Show install commands?")
            .default(true)
            .interact()
        {
            Ok(b) => b,
            Err(_) => return,
        }
    };
    #[cfg(not(feature = "wizard"))]
    let opted_in = true;

    if !opted_in {
        println!("Skipped — operator declined.");
        return;
    }

    let chain = crate::wizard::install_step::FallbackChain::for_host();
    if chain.is_empty() {
        println!("(No package-manager chain known for this host — install manually.)");
        return;
    }
    for (pkg_id, friendly) in &missing {
        println!("• {friendly} ({pkg_id})");
        let cmds = crate::wizard::install_step::dry_run_install_commands(&chain, pkg_id);
        for (kind, argv) in cmds {
            println!("    [{}] {}", kind.as_str(), argv.join(" "));
        }
        println!();
    }
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

    debug!("wizard step 7: autonomy");

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
        // NOOB-UX gate: Beginner silently takes `Standard` — the
        // 5-option matrix ("paid calls > €0.50", "policy.yaml
        // dangerous_targets", "fine-grained matrix") is dense
        // jargon and Standard is the safe default the panel
        // already recommends. Intermediate + Advanced see the
        // full picker.
        if matches!(
            state.experience_level,
            crate::wizard::recommend::ExperienceLevel::Beginner
        ) {
            state.autonomy = AutonomyLevel::Standard;
            println!(
                "  [7/9] autonomy: {} (safe default — change anytime in settings)",
                state.autonomy.as_str(),
            );
            state.steps_completed.push(7);
            return Ok(());
        }
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
            .with_prompt("[7/9] How autonomous should NEOTH be?")
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
                println!("  [7/9] Falling back to `standard`.");
                state.autonomy = AutonomyLevel::Standard;
            } else {
                state.autonomy = AutonomyLevel::Full;
            }
        } else {
            state.autonomy = picked;
        }
        println!("  [7/9] autonomy: {}", state.autonomy.as_str());
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
    debug!("wizard step 7b: auto-update");

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
                "[7b/9] Allow NEOTH to check GitHub for newer releases? (no background traffic until you say yes)",
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
                "  [7b/9] auto_update: enabled={} auto_apply={} channel={}",
                state.auto_update.enabled, state.auto_update.auto_apply, state.auto_update.channel,
            );
        } else {
            // Explicit "no" — make sure both flags are false even
            // if a prior wizard run had flipped them on.
            state.auto_update.enabled = false;
            state.auto_update.auto_apply = false;
            println!("  [7b/9] auto_update: disabled");
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
    debug!("wizard step 7c: wasm plugin activation");

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
            "[7c/9] {} WASM plugin(s) discovered under ~/.neoth/plugins/.",
            report.loaded.len()
        );
        println!("       Default is PENDING (skipped at daemon boot until you opt in).");
        println!("       Pick the ones you want active. Unpicked = Disabled.");

        let labels: Vec<String> = report
            .loaded
            .iter()
            .map(|p| format!("{}  ({})", p.manifest.id, p.manifest.name,))
            .collect();

        let picked =
            dialoguer::MultiSelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
                .with_prompt("[7c/9] Activate plugins (space to toggle, Enter to confirm)")
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
            "  [7c/9] {} plugin(s) Active, {} Disabled.",
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
    debug!("wizard step 8: summary");
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
    println!("\n[9/9] Setup Complete\n");
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
    // K-4 (Session 21, 2026-05-23): primary/secondary channel display.
    // Keet wins if paired (operator-private + e2e by default); Telegram
    // is the fallback. Both paired → "Keet (primary) / Telegram
    // (secondary)" — encodes the recommended-default flip the agent
    // panel called for in K-4.
    let channels = configured_channels(state);
    let channel_line = match channels.as_slice() {
        [] => "none".to_string(),
        [one] => match one.as_str() {
            "keet" => "Keet".to_string(),
            "telegram" => "Telegram".to_string(),
            other => other.to_string(),
        },
        [primary, secondary] => {
            fn pretty(s: &str) -> &str {
                match s {
                    "keet" => "Keet",
                    "telegram" => "Telegram",
                    other => other,
                }
            }
            format!(
                "{} (primary) / {} (secondary)",
                pretty(primary),
                pretty(secondary)
            )
        }
        many => many.join(", "),
    };
    println!("  Channel:   {channel_line}");
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
    // K-4 (Session 21, 2026-05-23): primary-channel ordering. Once
    // Keet pairing succeeded, surface Keet FIRST in the configured
    // list — `.initialized` marker + post-init wizard summary both
    // read this as "first entry = primary". Telegram still listed
    // but becomes the fallback channel. This is the minimal-first
    // K-4 verdict: change the recommended-primary signal without
    // restructuring step6_channel's dispatch (full default flip
    // gated on cluster live-test against `pear`).
    let mut out = Vec::new();
    if state.keet_seed_phrase.is_some() {
        out.push("keet".to_string());
    }
    if state.telegram_token.is_some() {
        out.push("telegram".to_string());
    }
    // No .sort() — K-4 ordering is intentional. The Vec is the
    // primary-first list operators see in `neoth status` output.
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

/// Offer to install the three CLIs that are missing on PATH. Dispatches
/// on each CLI's [`InstallStrategy`] — npm-strategy CLIs need npm
/// reachable, shell-script-strategy CLIs (Antigravity) only need
/// `sh`/PowerShell which we can rely on. Updates the passed-in path
/// Options in place so the wizard can re-probe after install. Quiet
/// no-op when all three are already present.
#[cfg(feature = "wizard")]
async fn offer_cli_installs(
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
                InstallStrategy::Npm { .. } => "Open a new shell or check your npm prefix.",
                InstallStrategy::ShellScript { .. } => {
                    "Open a new shell or check the installer's reported install path."
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
async fn offer_cli_installs(
    _claude: &mut Option<String>,
    _codex: &mut Option<String>,
    _antigravity: &mut Option<String>,
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

    // ── R-04 (Session 24) wizard resume gate ──────────────────────────

    #[test]
    fn maybe_resume_no_checkpoint_leaves_state_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("noop ok");
        assert!(state.operator_id.is_none());
        assert!(state.steps_completed.is_empty());
    }

    #[test]
    fn maybe_resume_non_interactive_auto_hydrates_from_checkpoint() {
        // CI / pipe path: auto-resume without prompting. The checkpoint
        // payload is the source of truth for non-secret fields.
        let dir = tempfile::tempdir().unwrap();
        let mut saved = WizardState::default();
        saved.operator_id = Some("alex".into());
        saved.language_code = Some("de".into());
        saved.steps_completed = vec![1, 2, 3, 4];
        saved.bootstrap_vault = true;
        crate::cli::wizard_checkpoint::save_checkpoint(dir.path(), &saved).expect("save");

        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("auto-resume");
        assert_eq!(state.operator_id.as_deref(), Some("alex"));
        assert_eq!(state.language_code.as_deref(), Some("de"));
        assert_eq!(state.steps_completed, vec![1, 2, 3, 4]);
        assert!(state.bootstrap_vault);
        // Checkpoint file must still exist after auto-resume — it gets
        // cleared at the very end of run_init or by an operator decline.
        assert!(
            crate::cli::wizard_checkpoint::checkpoint_path(dir.path()).exists(),
            "non-interactive auto-resume keeps the file in place for the next save",
        );
    }

    #[test]
    fn maybe_resume_with_corrupt_file_clears_it_and_proceeds() {
        // Garbage JSON in the checkpoint must NOT brick the wizard.
        // Operator sees a fresh wizard + the bad file goes away.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            crate::cli::wizard_checkpoint::checkpoint_path(dir.path()),
            b"<<<not real json>>>",
        )
        .unwrap();

        let mut state = WizardState::default();
        maybe_resume_from_checkpoint(dir.path(), false, &mut state).expect("survives corruption");
        assert!(state.operator_id.is_none());
        assert!(
            !crate::cli::wizard_checkpoint::checkpoint_path(dir.path()).exists(),
            "corrupt checkpoint must be cleared",
        );
    }

    #[test]
    fn format_checkpoint_age_handles_zero_and_negative() {
        // Defensive: an operator who hand-edits the file to ts=0 or
        // pre-epoch shouldn't crash the resume prompt.
        assert_eq!(format_checkpoint_age(0), "timestamp unavailable");
        assert_eq!(format_checkpoint_age(-1), "timestamp unavailable");
    }

    // ── R-05 (Session 24) auto-start + first-tour marker ─────────────

    #[test]
    fn write_first_tour_marker_creates_file_with_canonical_body() {
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("write marker");
        let path = dir.path().join(super::FIRST_TOUR_MARKER);
        assert!(path.exists(), "marker file must exist after write");
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, super::FIRST_TOUR_MESSAGE);
    }

    #[test]
    fn consume_first_tour_marker_returns_some_then_none() {
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("write");
        let first = super::consume_first_tour_marker(dir.path());
        assert!(first.is_some());
        assert_eq!(first.as_deref(), Some(super::FIRST_TOUR_MESSAGE));

        // Second call: marker consumed → None.
        let second = super::consume_first_tour_marker(dir.path());
        assert!(
            second.is_none(),
            "marker is single-use; second consume must return None",
        );
        assert!(
            !dir.path().join(super::FIRST_TOUR_MARKER).exists(),
            "consume must delete the file",
        );
    }

    #[test]
    fn consume_first_tour_marker_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let out = super::consume_first_tour_marker(dir.path());
        assert!(
            out.is_none(),
            "fresh-install state (no wizard ran yet) → None, not Err",
        );
    }

    #[test]
    fn write_first_tour_marker_is_idempotent_on_rewrite() {
        // Operator re-runs `neoth init --force` → second write must
        // succeed + leave the file at the canonical message. Catches
        // a future regression that switches to "fail if exists" mode.
        let dir = tempfile::tempdir().unwrap();
        super::write_first_tour_marker(dir.path()).expect("first");
        // Tamper with the file as if a partial write happened.
        std::fs::write(dir.path().join(super::FIRST_TOUR_MARKER), b"stale-content").unwrap();
        super::write_first_tour_marker(dir.path()).expect("second");
        let body = std::fs::read_to_string(dir.path().join(super::FIRST_TOUR_MARKER)).unwrap();
        assert_eq!(body, super::FIRST_TOUR_MESSAGE);
    }

    #[test]
    fn first_tour_message_is_actionable_one_liner() {
        // Drift guard: the greeting must mention a runnable command so
        // a first-time operator has a clear next step. If a future
        // refactor reduces it to "Hello." this fails.
        assert!(
            super::FIRST_TOUR_MESSAGE.contains("neoth chat")
                || super::FIRST_TOUR_MESSAGE.contains("neoth recall"),
            "greeting must reference a runnable command: {}",
            super::FIRST_TOUR_MESSAGE,
        );
    }

    #[test]
    fn format_checkpoint_age_picks_human_units() {
        // The exact phrasing isn't a contract, but the unit boundary
        // selection is — a 2-hour-old checkpoint should not say
        // "7200 seconds ago" to an operator.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(format_checkpoint_age(now - 30).contains("minute"));
        assert!(format_checkpoint_age(now - 600).contains("minutes ago"));
        assert!(format_checkpoint_age(now - 7_200).contains("hours ago"));
        assert!(format_checkpoint_age(now - 172_800).contains("days ago"));
    }

    /// Process-level lock for tests that mutate the global `HOME` /
    /// `USERPROFILE` env vars. `std::env::set_var` is process-global,
    /// so two parallel tests in this lib that both set HOME race —
    /// one sees the other's tempdir and asserts wrong, surfacing as
    /// the intermittent failure of e.g. step6d_non_interactive_*.
    /// Every test that calls `set_var("HOME"/"USERPROFILE", ...)`
    /// MUST take this lock at function entry; release on drop
    /// happens after the restore-prev block.
    static HOME_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Wrapper that hides the `PoisonError` recovery boilerplate —
    /// a previously-panicking test poisoned the mutex but the data
    /// inside is `()`, so reuse it unconditionally.
    fn lock_home_env() -> std::sync::MutexGuard<'static, ()> {
        HOME_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

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
            experience_level: crate::wizard::recommend::ExperienceLevel::Beginner,
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
            download_qwen_weights: false,
            install_obsidian: false,
            bootstrap_vault: false,
            vault_path: None,
            install_n8n: false,
            import_jarvis: None,
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
        std::fs::write(
            plugins_root.join("plugin.wasm"),
            [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        )
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
            std::fs::write(
                pd.join("plugin.wasm"),
                [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            )
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
            state.plugins.wasm.activations.get("indexer_v1").copied(),
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
        std::fs::write(
            pd.join("plugin.wasm"),
            [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        )
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
            back.keet_seed_phrase
                .as_ref()
                .map(|s| s.expose().to_string()),
            Some("alpha bravo charlie".to_string()),
        );
        assert_eq!(
            back.pears_bearer_token.as_ref().map(|s| s.expose().len()),
            Some(64),
        );
    }

    // ── K-4b telegram-prompt text tests (Session 21) ────────────────

    #[test]
    fn k4b_prompt_demotes_telegram_when_pear_present() {
        // K-4b: when `pear` is on PATH, Keet is the preferred primary.
        // The Telegram prompt must reframe Telegram as a FALLBACK so
        // operators don't accidentally pick it as primary out of habit.
        let s = k4b_telegram_prompt_text(true);
        assert!(s.contains("FALLBACK"), "msg: {s}");
        assert!(s.contains("Keet"), "msg: {s}");
        assert!(s.contains("preferred primary"), "msg: {s}");
        assert!(s.contains("default: no"), "msg: {s}");
    }

    #[test]
    fn k4b_prompt_neutral_when_pear_missing() {
        // Backward-compat pin: operators without `pear` see the
        // original neutral Telegram prompt — Keet is unreachable so
        // there's nothing to demote Telegram against.
        let s = k4b_telegram_prompt_text(false);
        assert!(!s.contains("FALLBACK"));
        assert!(!s.contains("Keet"));
        assert!(s.contains("Telegram"));
        assert!(s.contains("optional"));
    }

    #[test]
    fn k4b_prompt_keeps_step_label_consistent_across_modes() {
        // Both variants must carry the same `[6/9]` step label so the
        // wizard transcript stays parseable — operators (or automated
        // probes) grepping for "[6/9]" find it regardless of the pear
        // detection outcome.
        assert!(k4b_telegram_prompt_text(true).contains("[6/9]"));
        assert!(k4b_telegram_prompt_text(false).contains("[6/9]"));
    }

    // ── K-4 channel-ordering tests (Session 21) ─────────────────────

    #[test]
    fn k4_configured_channels_lists_keet_first_when_both_paired() {
        // K-4 contract pin: when operator paired BOTH Keet + Telegram
        // during the wizard, Keet appears FIRST in the configured list.
        // First entry = primary; downstream (status display, .initialized
        // marker, post-init summary) reads this ordering.
        let mut s = fixture_state();
        // fixture_state sets Telegram already; add Keet.
        s.keet_seed_phrase = Some(crate::secret::SecretString::from(
            "alpha bravo charlie delta echo foxtrot golf hotel india juliet \
             kilo lima mike november oscar papa quebec romeo sierra tango \
             uniform victor whiskey xray",
        ));
        let chans = configured_channels(&s);
        assert_eq!(chans, vec!["keet".to_string(), "telegram".to_string()]);
    }

    #[test]
    fn k4_configured_channels_keet_only_when_no_telegram() {
        let mut s = fixture_state();
        s.telegram_token = None;
        s.keet_seed_phrase = Some(crate::secret::SecretString::from("seed".to_string()));
        let chans = configured_channels(&s);
        assert_eq!(chans, vec!["keet".to_string()]);
    }

    #[test]
    fn k4_configured_channels_telegram_only_when_no_keet() {
        // Backward-compat pin: a wizard run that skipped Keet pairing
        // still lists Telegram as the configured channel — K-4 must
        // not regress the pre-Keet operators.
        let s = fixture_state(); // has Telegram, no Keet
        let chans = configured_channels(&s);
        assert_eq!(chans, vec!["telegram".to_string()]);
    }

    #[test]
    fn k4_configured_channels_empty_when_neither_paired() {
        let mut s = fixture_state();
        s.telegram_token = None;
        s.keet_seed_phrase = None;
        assert!(configured_channels(&s).is_empty());
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
        state.pears_bearer_token = Some(crate::secret::SecretString::from(
            "token_not_in_freedom_yaml",
        ));
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

    // ── Workstream B (Session 22) — 5 wizard step regressions ─────────────

    fn args_with_flag(set: impl FnOnce(&mut InitArgs)) -> InitArgs {
        let mut a = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        set(&mut a);
        a
    }

    #[tokio::test]
    async fn step5c_non_interactive_no_op_when_provider_not_local_qwen() {
        // Cloud-only operator — no LocalQwen path. Step must skip
        // silently without recording opt-in.
        let mut state = fixture_state();
        state.provider_kind = Some(ProviderKind::ClaudeCli);
        let args = args_with_flag(|a| a.download_qwen_weights = true);
        step5c_qwen_weights(&args, false, &mut state).await.unwrap();
        assert!(!state.download_qwen_weights);
        assert!(state.steps_completed.contains(&58));
    }

    // The std::Mutex env-lock is intentional here: tests in this module
    // mutate process-global $HOME / $USERPROFILE so they MUST serialise
    // against each other. An async-aware Mutex would defeat the purpose
    // (tokio's mutex doesn't poison on panic, so a panicking test could
    // leave the env corrupted for the next test). The await inside the
    // critical section is bounded (`step5c_qwen_weights` does no
    // operator-blocking IO under #[non_interactive=false]).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn step5c_non_interactive_records_when_flag_set_and_local_qwen() {
        let _env_lock = lock_home_env();
        // LocalQwen-using operator + --download-qwen-weights → opt-in
        // recorded. The probe lives under a synthetic HOME so the
        // "weights missing" branch is exercised.
        let temp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("USERPROFILE", temp.path());
        }

        let mut state = fixture_state();
        state.provider_kind = Some(ProviderKind::LocalQwen);
        let args = args_with_flag(|a| a.download_qwen_weights = true);
        step5c_qwen_weights(&args, false, &mut state).await.unwrap();
        assert!(state.download_qwen_weights);
        assert!(state.steps_completed.contains(&58));

        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_userprofile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }
    }

    #[tokio::test]
    async fn step6c_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {}); // no install_obsidian
        step6c_obsidian_install(&args, false, &mut state)
            .await
            .unwrap();
        // Whether install_obsidian was set depends on whether the host
        // happens to have Obsidian already installed (sets it true).
        // The flag-absent path either records "already present" or
        // does nothing — the marker MUST land either way.
        assert!(state.steps_completed.contains(&61));
    }

    #[tokio::test]
    async fn step6c_non_interactive_records_when_flag_set() {
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.install_obsidian = true);
        step6c_obsidian_install(&args, false, &mut state)
            .await
            .unwrap();
        assert!(state.install_obsidian);
        assert!(state.steps_completed.contains(&61));
    }

    #[test]
    fn step6d_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6d_obsidian_vault_bootstrap(&args, false, &mut state).unwrap();
        assert!(!state.bootstrap_vault);
        assert!(state.vault_path.is_none());
        assert!(state.steps_completed.contains(&62));
    }

    #[test]
    fn step6d_non_interactive_bootstraps_vault_when_flag_set() {
        // Session 24 env-mutation refactor: use the explicit
        // `home_override` parameter instead of mutating the global
        // HOME / USERPROFILE env vars. No lock needed; tempdir
        // is fully isolated per test.
        let temp = tempfile::tempdir().unwrap();
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.bootstrap_vault = true);
        step6d_obsidian_vault_bootstrap_with_home(&args, false, &mut state, Some(temp.path()))
            .unwrap();

        assert!(state.bootstrap_vault);
        let path = state.vault_path.as_ref().expect("vault_path recorded");
        assert!(path.exists());
        assert!(path.join("README.md").exists());
        assert!(path.join(".obsidian").join("app.json").exists());
        assert!(state.steps_completed.contains(&62));
    }

    #[test]
    fn step6d_idempotent_skips_files_that_already_exist() {
        // Session 24 env-mutation refactor: explicit home_override.
        // Operator re-runs init with --force: existing vault files
        // must NOT be clobbered (operator edits win).
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("Documents").join("NEOTH-Vault");
        std::fs::create_dir_all(&vault).unwrap();
        let sentinel = "OPERATOR EDIT — DO NOT OVERWRITE\n";
        std::fs::write(vault.join("README.md"), sentinel).unwrap();

        let mut state = fixture_state();
        let args = args_with_flag(|a| a.bootstrap_vault = true);
        step6d_obsidian_vault_bootstrap_with_home(&args, false, &mut state, Some(temp.path()))
            .unwrap();

        let body = std::fs::read_to_string(vault.join("README.md")).unwrap();
        assert_eq!(body, sentinel, "operator-edited README must be preserved");
    }

    #[tokio::test]
    async fn step6e_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6e_n8n_install(&args, false, &mut state).await.unwrap();
        assert!(!state.install_n8n);
        assert!(state.steps_completed.contains(&63));
    }

    #[tokio::test]
    async fn step6e_non_interactive_records_when_flag_set() {
        let mut state = fixture_state();
        let args = args_with_flag(|a| a.install_n8n = true);
        step6e_n8n_install(&args, false, &mut state).await.unwrap();
        assert!(state.install_n8n);
        assert!(state.steps_completed.contains(&63));
    }

    #[test]
    fn step6f_non_interactive_no_op_when_flag_absent() {
        let mut state = fixture_state();
        let args = args_with_flag(|_| {});
        step6f_import_jarvis(&args, false, &mut state).unwrap();
        assert!(state.import_jarvis.is_none());
        assert!(state.steps_completed.contains(&64));
    }

    #[test]
    fn step6f_non_interactive_records_path_when_flag_set() {
        let temp = tempfile::tempdir().unwrap();
        let jarvis = temp.path().join("HIPPOCAMPUS_CORE.md");
        std::fs::write(&jarvis, "synthetic jarvis seed").unwrap();

        let mut state = fixture_state();
        let args = args_with_flag(|a| a.import_jarvis = Some(jarvis.clone()));
        step6f_import_jarvis(&args, false, &mut state).unwrap();
        assert_eq!(state.import_jarvis.as_ref(), Some(&jarvis));
        assert!(state.steps_completed.contains(&64));
    }

    #[test]
    fn inference_uses_local_qwen_detects_default_slot() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};
        let mut topology = crate::config::inference::InferenceTopology::default();
        topology.default_slot = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };
        assert!(inference_uses_local_qwen(&topology, &None));
    }

    #[test]
    fn inference_uses_local_qwen_detects_hemisphere_override() {
        use crate::config::inference::{HemisphereSlot, InferenceProvider};
        let mut topology = crate::config::inference::InferenceTopology::default();
        topology.left = HemisphereSlot {
            provider: Some(InferenceProvider::LocalQwen),
            ..Default::default()
        };
        assert!(inference_uses_local_qwen(&topology, &None));
    }

    #[test]
    fn inference_uses_local_qwen_false_for_cloud_only_topology() {
        let topology = crate::config::inference::InferenceTopology::default();
        assert!(!inference_uses_local_qwen(
            &topology,
            &Some(ProviderKind::ClaudeCli)
        ));
    }

    // ── C-05 (Session 25) credential-import sidecar ────────────────────

    #[test]
    fn credential_import_sidecar_writes_redacted_payload_only() {
        // SC-17 invariant: the sidecar carries the redacted projection,
        // never the secrets. Test pins this contract for the wizard
        // step's disk shape.
        use crate::security::credential_redact::{ImportSource, RedactedCredentialImportPayload};
        let home = tempfile::tempdir().unwrap();
        let payload = RedactedCredentialImportPayload {
            source: ImportSource::Bitwarden,
            entry_count: 3,
            distinct_tags_sorted: vec!["banking".into(), "work".into()],
            services_hash: "deadbeefcafebabe".into(),
            target_vault_id: "primary".into(),
            ts_unix: 1_700_000_000,
            services_redacted: true,
        };
        let path = write_credential_import_sidecar(home.path(), 1_700_000_000, &payload).unwrap();
        assert!(path.exists());
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("credentials_import_1700000000.json"),
        );
        let body = std::fs::read_to_string(&path).unwrap();
        // SC-17 keys present; no secret-bearing keys leaked.
        assert!(body.contains("\"services_redacted\""));
        assert!(body.contains("\"entry_count\""));
        assert!(body.contains("\"services_hash\""));
        assert!(!body.contains("password"));
        assert!(!body.contains("secret"));
    }

    #[test]
    fn credential_import_sidecar_overwrites_existing_atomically() {
        // Re-running the wizard at the same ts_unix should overwrite,
        // not leave a `.tmp` companion + not error out on
        // Windows-style rename-over-existing.
        use crate::security::credential_redact::{ImportSource, RedactedCredentialImportPayload};
        let home = tempfile::tempdir().unwrap();
        let payload = RedactedCredentialImportPayload {
            source: ImportSource::Bitwarden,
            entry_count: 0,
            distinct_tags_sorted: Vec::new(),
            services_hash: "0000000000000000".into(),
            target_vault_id: "primary".into(),
            ts_unix: 100,
            services_redacted: true,
        };
        let first = write_credential_import_sidecar(home.path(), 100, &payload).unwrap();
        let second = write_credential_import_sidecar(home.path(), 100, &payload).unwrap();
        assert_eq!(first, second);
        // No `.tmp` companion leaked.
        let tmp = home.path().join("credentials_import_100.json.tmp");
        assert!(!tmp.exists());
    }

    // ── Session 27: NOOB-UX experience-level gates for step5c/5d/6e/7 ──
    //
    // Pattern matches step5b (Session 26): Beginner short-circuits
    // dialoguer prompts and takes safe defaults silently. The tests
    // exercise the early-return branch — if it regresses, step6e_n8n /
    // step7_autonomy would block on stdin instead of completing, which
    // surfaces as the test hanging the suite. Better to fail fast.

    #[test]
    fn step5d_beginner_records_marker() {
        // Beginner sees the 1-line plain-English summary; the marker
        // still lands so the audit chain has the same shape across
        // experience levels.
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        step5d_profile_approval_gate(true, &mut state).expect("step5d Beginner");
        assert!(
            state.steps_completed.contains(&60),
            "step5d marker (60) must be recorded irrespective of experience level",
        );
    }

    #[test]
    fn step5d_intermediate_records_marker() {
        // Intermediate operators still get the 6-line technical
        // version; assert the marker still records so future drift
        // (e.g. early-return-without-marker) is caught.
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Intermediate;
        step5d_profile_approval_gate(true, &mut state).expect("step5d Intermediate");
        assert!(state.steps_completed.contains(&60));
    }

    #[tokio::test]
    async fn step6e_beginner_skips_n8n_silently() {
        // Beginner gate MUST short-circuit before dialoguer. If this
        // regresses, the test hangs on stdin — fail-fast is the goal.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        // Interactive=true would normally prompt; the Beginner gate
        // hits FIRST and short-circuits the dialoguer call.
        step6e_n8n_install(&args, true, &mut state)
            .await
            .expect("step6e Beginner");
        assert!(
            !state.install_n8n,
            "Beginner default is don't-install n8n — operator opts in via settings later",
        );
        assert!(state.steps_completed.contains(&63));
    }

    #[test]
    fn step7_beginner_takes_standard_silently() {
        // Beginner skips the 5-option autonomy matrix and lands on
        // Standard. The 5-option matrix uses jargon (paid-call
        // thresholds, policy.yaml::dangerous_targets) that scares
        // non-developers.
        let args = InitArgs {
            non_interactive: true,
            accept_license: true,
            ..Default::default()
        };
        let mut state = fixture_state();
        state.experience_level = crate::wizard::recommend::ExperienceLevel::Beginner;
        state.autonomy = crate::permissions::AutonomyLevel::Strict; // start non-default
        step7_autonomy(&args, true, &mut state).expect("step7 Beginner");
        assert_eq!(
            state.autonomy,
            crate::permissions::AutonomyLevel::Standard,
            "Beginner gate must land on Standard regardless of prior state",
        );
        assert!(state.steps_completed.contains(&7));
    }
}
