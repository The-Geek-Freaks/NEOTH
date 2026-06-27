//! Pure data types for the `neoth init` wizard (GOLD-ARCH-05).
//!
//! No I/O, no dialoguer: provider/role/mode enums, CLI args, checkpoint step
//! markers and the cross-step `WizardState`. Split out of `cli/init.rs`.

use clap::{Args, ValueEnum};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

/// LLM provider kind. Typed enum (replaces stringly-typed v0.1 alpha).
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[clap(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// claude CLI binary (OAuth via `claude` command).
    ClaudeCli,
    /// OpenAI REST API (api.openai.com or compatible).
    OpenaiApi,
    /// Native Anthropic Messages API (PF-02) — key-based
    /// `api.anthropic.com/v1/messages`, distinct from `ClaudeCli` (which
    /// drives the `claude` CLI binary). For operators who want Anthropic
    /// access via an API key without installing the CLI.
    AnthropicApi,
    /// Google Gemini REST API.
    GeminiApi,
    /// PF-02 — native Cohere v2 Chat API (`api.cohere.com/v2`, key-based,
    /// BILLED per-token; no subscription path).
    Cohere,
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
    ///
    /// COR-13: the variant is spelled `AzureOpenAi` (two Pascal words
    /// `Open` + `Ai`), so the default `rename_all = "snake_case"` would
    /// emit `azure_open_ai` — diverging from the canonical `azure_openai`
    /// used by `consent::slug`, the cost price table, `InferenceProvider`,
    /// and the `learn_provider` error message. Pin both the serde wire
    /// form and the clap value to `azure_openai`; accept the legacy
    /// `azure_open_ai` as an alias so any older config still loads.
    #[serde(rename = "azure_openai", alias = "azure_open_ai")]
    #[value(name = "azure_openai", alias = "azure_open_ai")]
    AzureOpenAi,
    /// GOLD-ADAPT-ODY-15 — GitHub Copilot via OAuth PAT + short-lived session
    /// token. Zero per-token cost for GitHub Copilot subscribers (flat
    /// subscription). Uses the OpenAI-compatible `api.githubcopilot.com`
    /// endpoint authenticated via `api.github.com/copilot_internal/v2/token`.
    ///
    /// COR-Copilot: `rename_all = "snake_case"` would emit `git_hub_copilot`
    /// — not the canonical `copilot_api` slug. Pin both the serde wire form
    /// and the clap value to `copilot_api`; accept `github_copilot` as a
    /// human-friendly alias so operators who type the long form still work.
    #[serde(rename = "copilot_api", alias = "github_copilot")]
    #[value(name = "copilot_api", alias = "github_copilot")]
    GitHubCopilot,
    /// No provider yet; configure later via `neoth provider add`.
    Skip,
}

impl ProviderKind {
    /// Canonical machine slug — identical to the serde/clap wire form for
    /// every variant (`#[serde(rename_all = "snake_case")]` plus the
    /// `AzureOpenAi` override). Use this for display, logs, and any place
    /// that needs the persisted provider id. `Skip => "skip"`.
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::ClaudeCli => "claude_cli",
            ProviderKind::OpenaiApi => "openai_api",
            ProviderKind::AnthropicApi => "anthropic_api",
            ProviderKind::GeminiApi => "gemini_api",
            ProviderKind::Cohere => "cohere",
            ProviderKind::OpenaiCompat => "openai_compat",
            ProviderKind::LocalQwen => "local_qwen",
            ProviderKind::LocalOuro => "local_ouro",
            ProviderKind::AwsBedrock => "aws_bedrock",
            ProviderKind::AzureOpenAi => "azure_openai",
            ProviderKind::GitHubCopilot => "copilot_api",
            ProviderKind::Skip => "skip",
        }
    }

    /// Provider-id string for the status / cost-estimation surface
    /// (`cost::predict` price-table key, `consent::kind_from_slug` lookup,
    /// job/serve provider field). Differs from [`Self::as_str`] in two
    /// spots: `Cohere => "cohere_api"` (the metered price-table + consent
    /// slug key) and `Skip => "none"` — the single canonical token that
    /// replaced the old three-way drift (`"unconfigured"` in jobs,
    /// `"unknown"` in serve, `"(none)"` in the wizard summary). All three
    /// fed `cost::predict` (returns the unknown-estimate for any
    /// unrecognised key) or a tracing field, and `kind_from_slug("none")`
    /// is `None` just like the old values — so cloud-gating is unchanged.
    pub fn as_provider_id(self) -> &'static str {
        match self {
            ProviderKind::Cohere => "cohere_api",
            ProviderKind::Skip => "none",
            other => other.as_str(),
        }
    }

    /// Models-catalog provider key (`crate::models::catalog`). `None` for
    /// kinds with no model-discovery source today (Cohere, LocalQwen,
    /// LocalOuro, AzureOpenAi, Skip) → caller falls back to bundled
    /// defaults. `ClaudeCli` + `AnthropicApi` share the `anthropic_api`
    /// catalog source.
    pub fn catalog_key(self) -> Option<&'static str> {
        Some(match self {
            ProviderKind::ClaudeCli => "anthropic_api",
            ProviderKind::AnthropicApi => "anthropic_api",
            ProviderKind::OpenaiApi => "openai_api",
            ProviderKind::OpenaiCompat => "openai_compat",
            ProviderKind::GeminiApi => "gemini_api",
            ProviderKind::AwsBedrock => "aws_bedrock",
            ProviderKind::LocalQwen
            | ProviderKind::LocalOuro
            | ProviderKind::AzureOpenAi
            | ProviderKind::Cohere
            | ProviderKind::GitHubCopilot
            | ProviderKind::Skip => return None,
        })
    }

    /// Translate the wizard step-5 choice into the typed
    /// [`crate::config::inference::InferenceProvider`]. `Skip` maps to
    /// `ClaudeCli` (unreachable in practice — a Skip config never reaches
    /// inference dispatch).
    pub fn to_inference(self) -> crate::config::inference::InferenceProvider {
        use crate::config::inference::InferenceProvider as I;
        match self {
            ProviderKind::ClaudeCli => I::ClaudeCli,
            ProviderKind::OpenaiApi => I::OpenAi,
            ProviderKind::AnthropicApi => I::AnthropicApi,
            ProviderKind::OpenaiCompat => I::OpenAiCompat,
            ProviderKind::GeminiApi => I::Gemini,
            ProviderKind::Cohere => I::Cohere,
            ProviderKind::LocalQwen => I::LocalQwen,
            ProviderKind::LocalOuro => I::LocalOuro,
            ProviderKind::AwsBedrock => I::AwsBedrock,
            ProviderKind::AzureOpenAi => I::AzureOpenAi,
            ProviderKind::GitHubCopilot => I::GitHubCopilot,
            ProviderKind::Skip => I::ClaudeCli, // unreachable in practice
        }
    }
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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

    /// GOLD-FEAT-01b — one-click zero-friction onboarding. Applies the
    /// maximally-permissive preset (Full autonomy + single-provider
    /// inference + every bundled skill active), overriding the per-step
    /// autonomy/topology picks. Opt-in; interactive runs are also offered
    /// it as a y/n confirm.
    #[arg(long)]
    pub zero_friction: bool,

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

    /// E-16 (Workstream B) — prior-AI memory import. Path to an
    /// `import-manifest.yaml` declaring your prior-AI memory stores (see
    /// the `neoth-migrate` examples). When set, the wizard records the
    /// import intent + surfaces the `neoth-migrate dry-run` /
    /// `apply --confirm` runbook against the manifest. Heavyweight
    /// migrations stay operator-triggered — the wizard never
    /// auto-applies. Non-interactive only honours the flag; interactive
    /// prompts for the path independently.
    #[arg(long = "import-memory", value_name = "PATH")]
    pub import_memory: Option<std::path::PathBuf>,

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

/// GOLD-COR-07 / A-26: single source of truth for the `WizardState::
/// steps_completed` checkpoint markers. Previously every step pushed a bare
/// magic number, and step 5d + step 6b BOTH pushed `60` — a silent collision
/// that made the resume/checkpoint record ambiguous (a half-finished run
/// couldn't tell whether 5d or 6b had completed). Naming every marker here +
/// the `wizard_step_all_covered` test makes a future duplicate a test failure
/// instead of a latent bug. Values are identity tags, not an ordering — the Vec
/// preserves push order — so the only invariant is uniqueness.
/// GOLD-ARCH-20: typed wizard step marker, replacing the old magic-`u8`
/// `step_markers` consts. `#[repr(u8)]` + explicit discriminants pin the
/// on-disk values (`steps_completed` stays a `Vec<u8>` at every persistence
/// boundary, so old `.initialized` / `wizard_checkpoint.json` files keep
/// deserializing unchanged). `num_enum` gives `TryFrom<u8>` / `Into<u8>`
/// for free — same pattern as `wal::types`. Values are identity tags, not
/// an ordering; the only invariant is discriminant uniqueness (a duplicate
/// is a `repr(u8)` compile error, plus `wizard_step_all_covered` guards
/// `ALL` coverage).
#[repr(u8)]
#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WizardStep {
    License = 1,
    /// GOLD-HON-10: new-vs-migration onboarding mode (step 1d), asked
    /// before the identity step so a migrating operator sees the import
    /// path up front.
    OnboardingMode = 14,
    OperatorId = 2,
    Language = 3,
    Role = 4,
    Provider = 5,
    Channel = 6,
    Autonomy = 7,
    Summary = 8,
    Topology = 56,
    QwenWeights = 58,
    ProfileGate = 60,
    Obsidian = 61,
    ObsidianVault = 62,
    N8n = 63,
    ImportMemory = 64,
    /// GOLD-COR-07: distinct from `ProfileGate` (was both `60`).
    KeetPairing = 65,
    AutoUpdate = 70,
    WasmPlugins = 71,
    Supervisor = 72,
    /// GOLD-ADAPT-TUDU-01 — wizard offer for the optional tududi self-hosted
    /// task manager MCP rail. Registers `server.js` path + API token, writes
    /// `tududi_api_token` to `credentials.yaml` and the hardened entry to
    /// `mcp_servers.yaml`. Non-interactive: skips (no unattended install).
    TududiOffer = 73,
    /// GOLD-ADAPT-SYS-01 — wizard offer for the optional mobile-mcp iOS/Android
    /// device control rail (`@mobilenext/mobile-mcp`). Launched via npx; no
    /// secret token. Writes the hardened entry (Elevated autonomy gate,
    /// telemetry OFF, 24 local-device tools) to `mcp_servers.yaml`.
    /// Non-interactive: skips (device prerequisites require operator setup).
    MobileMcpOffer = 74,
}

impl WizardStep {
    /// Every variant, for the coverage guard. Adding a step MUST add it
    /// here — `wizard_step_all_covered` trips on the count otherwise.
    pub const ALL: &'static [WizardStep] = &[
        Self::License,
        Self::OnboardingMode,
        Self::OperatorId,
        Self::Language,
        Self::Role,
        Self::Provider,
        Self::Channel,
        Self::Autonomy,
        Self::Summary,
        Self::Topology,
        Self::QwenWeights,
        Self::ProfileGate,
        Self::KeetPairing,
        Self::Obsidian,
        Self::ObsidianVault,
        Self::N8n,
        Self::ImportMemory,
        Self::AutoUpdate,
        Self::WasmPlugins,
        Self::Supervisor,
        Self::TududiOffer,
        Self::MobileMcpOffer,
    ];
}

/// GOLD-HON-10 — high-level onboarding intent, captured up front (step 1d,
/// before the identity step) so a migrating operator knows from the start
/// that NEOTH can import a prior assistant's memory. The detailed manifest
/// is still collected later in step 6f; this enum is the early signpost,
/// not the importer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingMode {
    /// Fresh install — start with an empty memory.
    #[default]
    New,
    /// Migrating from a prior AI assistant — surface the import path.
    Migration,
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
    /// GOLD-HON-10 (step 1d): fresh install vs migrating from a prior
    /// assistant. Defaults to `New`; non-interactive runs infer
    /// `Migration` from `--import-memory`.
    #[serde(default)]
    pub onboarding_mode: OnboardingMode,
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
    /// MV-01b prereq #3 (Session 28c): process-supervisor install state.
    /// `step7d_supervisor` sets it when the operator opts into a
    /// background auto-restart service. Serializes under `supervisor:` so
    /// the daemon's `config.supervisor.enabled` read sees the same shape.
    #[serde(default)]
    pub supervisor: crate::config::SupervisorConfig,
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
    /// E-16 (Workstream B, Session 22) — prior-AI memory import
    /// manifest path. When `Some`, the wizard recorded the operator's
    /// intent to run `neoth-migrate` against this manifest. `None` for
    /// fresh-host operators with no prior AI memory history.
    #[serde(default)]
    pub import_memory: Option<std::path::PathBuf>,
    /// SC-09 (step 3b) — whether the wizard offered the operator the optional
    /// plaintext HMAC-key backup (so an aborted/resumed wizard doesn't re-ask).
    #[serde(default)]
    pub hmac_backup_offered: bool,
    /// GOLD-ADAPT-OH-03 — persisted by `write_config` when at least one channel
    /// was configured during the wizard. `FreedomConfig` reads this field back;
    /// `neoth serve` bails at boot when `false` AND the credential probe also
    /// finds no channel. `#[serde(default)]` keeps old freedom.yaml round-trips
    /// clean (missing field → false → secondary probe applied at daemon boot).
    #[serde(default)]
    pub onboarding_complete: bool,
    /// GOLD-ADAPT-OH-11 — mirrored from FreedomConfig; reset to `false` by
    /// `write_config` so every fresh wizard run re-arms the first-chat hint.
    /// `#[serde(default)]` keeps old WizardState round-trips clean (missing
    /// field → false → overwritten to false by write_config anyway).
    #[serde(default)]
    pub chat_onboarding_completed: bool,
    /// GOLD-ADAPT-ODY-24 — set by `step6k_companion_pairing_offer` when the
    /// operator opts into the companion LAN pairing server. Serialises into
    /// `freedom.yaml::companion.enabled` via the `write_config` path (the
    /// WizardState YAML shape mirrors FreedomConfig — companion block is
    /// included via `#[serde(default)]` on both sides).
    #[serde(default)]
    pub companion: crate::config::CompanionConfig,
    pub steps_completed: Vec<u8>,
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
