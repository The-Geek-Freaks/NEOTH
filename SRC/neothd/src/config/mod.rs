pub mod inference;
pub mod reload;

// FreedomConfig — runtime view of ~/.neoth/freedom.yaml.
//
// Written by the `neoth init` wizard (see cli/init.rs). Read by `neoth serve`
// at daemon startup. Shape stays aligned with `WizardState`'s on-disk fields
// (operator_id, role, provider_*, telegram_*) — `steps_completed` is wizard
// state and ignored here.
//
// Loading enforces:
//   - File exists at ~/.neoth/freedom.yaml. If missing, the error tells the
//     operator to run `neoth init`.
//   - Permissions on unix: warn (not fail) if not 0600. The init wizard sets
//     it correctly; manual edits may not.
//   - YAML parses with serde_yaml. Unknown fields are tolerated for forward
//     compat (operator may have written extras NEOTH does not yet consume).
//
// ## Secrets-on-disk model (be honest about it)
//
// `freedom.yaml` DOES contain credentials in plaintext: `provider_key`
// (LLM API key) and `telegram_token`. These are `SecretString` typed —
// which means:
//   - **In RAM:** mlock'd against swap (Linux), zeroize on drop.
//   - **On disk:** plain text inside the YAML. NEOTH relies on OS-level
//     file permission (mode 0600 / Windows DACL grant:r owner) for at-rest
//     protection. There is no NEOTH-side encryption of `freedom.yaml`.
//
// Operators who need at-rest crypto should use FDE (BitLocker / LUKS / FileVault).
// A future Phase 33+ pass moves the secret fields into a separate
// `~/.neoth/credentials.yaml` for clearer audit + optional OS-keyring
// integration. The split is non-breaking — the wizard already writes a
// single file; the split just adds a second one alongside.
//
// The boot-time `cli/serve.rs` permission check warns if the file is
// readable by anyone other than the operator.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub mod credentials;

use crate::cli::init::{OperatorRole, ProviderKind};
use crate::secret::SecretString;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FreedomConfig {
    #[serde(default)]
    pub operator_id: Option<String>,
    #[serde(default)]
    pub language_primary: Option<String>,
    #[serde(default)]
    pub language_code: Option<String>,
    #[serde(default)]
    pub role: Option<OperatorRole>,
    #[serde(default)]
    pub role_custom: Option<String>,
    #[serde(default)]
    pub provider_kind: Option<ProviderKind>,
    #[serde(default)]
    pub provider_binary: Option<String>,
    #[serde(default)]
    pub provider_key: Option<SecretString>,
    #[serde(default)]
    pub provider_endpoint: Option<String>,
    #[serde(default)]
    pub provider_model: Option<String>,
    /// C-3 Phase 2 (Session 14) — AWS region for the `aws_bedrock`
    /// provider in single-mode dispatch. Examples: `us-east-1`,
    /// `eu-central-1`. Ignored by every non-AWS provider. When set
    /// at top level, it acts as the fallback region for any
    /// `HemisphereSlot` that didn't pin its own `region:` field.
    /// Default `None` → adapter falls back to `"us-east-1"`.
    #[serde(default)]
    pub provider_region: Option<String>,
    /// C-4 Phase 2 (Session 14) — Azure OpenAI `api-version` query
    /// parameter. Examples: `2024-10-21` (GA, default),
    /// `2025-04-01-preview` (preview). Ignored by every non-Azure
    /// provider. Per-slot override lives on
    /// `HemisphereSlot.api_version`.
    #[serde(default)]
    pub provider_api_version: Option<String>,
    #[serde(default)]
    pub telegram_token: Option<SecretString>,
    #[serde(default)]
    pub telegram_user_id: Option<u64>,
    /// Operator-chosen autonomy level — Phase 28b R-23.
    /// Defaults to `Standard` (least surprise: writes inside ~/.neoth/ are
    /// allowed, every shell exec confirms). Old freedom.yaml files without
    /// the field round-trip cleanly via `#[serde(default)]`.
    #[serde(default)]
    pub autonomy: crate::permissions::AutonomyLevel,
    /// Optional `host:port` for the local `/healthz` + `/metrics` listener.
    /// Defaults to `None` (listener disabled). Example: `127.0.0.1:43117`.
    /// Phase 33c BS-1.
    #[serde(default)]
    pub observability_listen: Option<String>,
    /// Per-hemisphere LLM topology (D14b extension): operator may want one
    /// provider for all three hemispheres (single), the same provider on
    /// all three slots (triplet), or fully custom per-slot configuration.
    /// Auto-detected accelerator + embedding provider also live here.
    /// Defaults to `single` mode that mirrors the legacy provider_kind path.
    #[serde(default)]
    pub inference: crate::config::inference::InferenceTopology,
    /// Pick #8 SP-2 (Session 14) — council winner-selection +
    /// cost-cap config. Defaults preserve v0.1 / Session-14-prior
    /// behaviour exactly: `selection_mode = LegacyMajority` skips
    /// every new code path. Operator opts in via
    /// `council.selection_mode: consensus_or_best` (and friends).
    #[serde(default)]
    pub council: crate::config::inference::CouncilConfig,
    /// Two-stage sub-agent review gate (obra/superpowers Item #2 port).
    /// When `true`, every `/agent <name> ...` dispatch chains two extra
    /// provider calls (spec compliance + code quality) and emits a WAL
    /// `0x84 SUBAGENT_REVIEW_STAGE` frame per stage. Costs 3× the spend
    /// of an un-reviewed call. Off by default. Operator flips it on
    /// per-deployment via `neoth init --force` or by editing freedom.yaml.
    #[serde(default)]
    pub review_gate_enabled: bool,
    /// R-5 Obsidian vault auto-sync: when set, the daemon mirrors
    /// `~/.neoth/archive/sessions/<day>/<file>.md` into the operator's
    /// vault on a schedule. `None` = task off (operator still runs
    /// `neoth obsidian sync` manually).
    #[serde(default)]
    pub obsidian_vault: Option<String>,
    /// Subdirectory inside the vault to write into. Defaults to `"NEOTH"`.
    #[serde(default)]
    pub obsidian_subdir: Option<String>,
    /// Auto-sync interval in seconds. `None` = use the module default
    /// (1 hour). Field unused when `obsidian_vault` is None.
    #[serde(default)]
    pub obsidian_auto_sync_secs: Option<u64>,
    /// R-3 Hysteria transport — encrypted egress for provider HTTP
    /// traffic. When `Some`, `neothd serve` spawns the Hysteria
    /// subprocess at startup, probes the local SOCKS5 port, and sets
    /// the `NEOTH_HTTP_PROXY` env var so every `providers::http_client`
    /// build automatically routes through it. Operator-supplied server +
    /// auth lives here; binary lookup falls back to `$PATH` or
    /// `~/.neoth/bin/hysteria` per the transport module's search order.
    #[serde(default)]
    pub hysteria: Option<crate::transport::hysteria::HysteriaConfig>,
    /// R-8 Cloud archive destination — local folder that the operator's
    /// cloud client (Dropbox / GDrive / OneDrive / iCloud / SMB / NAS
    /// mount, …) already syncs upstream. Daemon mirrors
    /// `~/.neoth/archive/sessions/` into this folder on a schedule.
    /// `None` = task off. Mirrors the obsidian sync pattern; cloud
    /// auth + transport are owned by the cloud vendor's desktop
    /// client, NEOTH stays out of it.
    #[serde(default)]
    pub cloud_archive_dest: Option<String>,
    /// Subdirectory inside `cloud_archive_dest`. Defaults to `"NEOTH"`.
    #[serde(default)]
    pub cloud_archive_subdir: Option<String>,
    /// Auto-mirror interval in seconds. `None` = 1 hour default.
    #[serde(default)]
    pub cloud_archive_auto_sync_secs: Option<u64>,
    /// Wizard step tracking — kept around for round-trip but not used at runtime.
    #[serde(default)]
    pub steps_completed: Vec<u8>,
    /// B-Rollback (CDX-02) snapshot emission policy. Decides which
    /// effect-adapter mutation sites emit `PRE_MUTATION_SNAPSHOT`
    /// (0xF2) frames so `neoth rollback apply` can restore later.
    /// Operator-flagged per Konsens decision #4 (A3 2026-05-16).
    #[serde(default)]
    pub rollback: RollbackConfig,
    /// B-6 Item 2: per-provider knobs for the Claude CLI adapter.
    /// Backend selection (auto / tmux / subprocess) + the tmux warm
    /// session tuning lives here. Round-trips through serde with
    /// `#[serde(default)]` so freedom.yaml files written before this
    /// field landed keep parsing.
    #[serde(default)]
    pub claude_cli: ClaudeCliConfig,
    /// 2026-05-17 Session 2: per-operator profile-learning policy.
    /// Controls whether the post-reply profile pipeline (K-Wire-1)
    /// fires after every `neoth chat`. Default **off** — the pipeline
    /// runs an extra LLM extract call per chat which costs operator
    /// tokens on cloud providers (OpenAI / Anthropic / OpenRouter / …).
    /// Operators who explicitly want passive operator-profile learning
    /// flip `learn_enabled: true`; operators who want NEOTH to be a
    /// pure pass-through chat tool leave it false.
    #[serde(default)]
    pub profile: ProfileConfig,
    /// R-04 2026-05-17: LOWKEY refusal-recovery policy. When the
    /// Schicht-0 detector flags a refusal, NEOTH classifies the
    /// cause + picks a reframing + retries once (R-05). Default ON
    /// because reframings are pure-function + the worst case is one
    /// extra paid LLM call on confirmed refusals (rare). Operators
    /// who want the original refusal visible flip `enabled: false`.
    #[serde(default)]
    pub refusal_recovery: RefusalRecoveryConfig,
    /// K-Repo-Map Phase 3c (Session 14 Pick #26) — automatic repo-
    /// context injection. When `auto_context_max_files > 0`, every
    /// `neoth chat` invocation queries the persisted code map via
    /// `relevant_files_for_prompt` and stitches a `<repo-context>`
    /// block into the system prompt. Default `0` = disabled so the
    /// rollout doesn't change baseline behaviour. Operators opt in
    /// by editing `freedom.yaml::code_map.auto_context_max_files: 5`
    /// (or similar).
    #[serde(default)]
    pub code_map: CodeMapConfig,
    /// V03-09 Phase 2a (2026-05-21): daemon self-update policy.
    /// `enabled: false` keeps the daemon silent (no check, no nag,
    /// no download). `enabled: true && auto_apply: false` =
    /// background check + nag in `neoth doctor` output (Phase 1
    /// behaviour today). `auto_apply: true` lets Phase 2b
    /// download + verify + extract + atomic-replace once that
    /// landing arrives. Operators on a forked build override
    /// `repo` to point at their own release feed.
    #[serde(default)]
    pub auto_update: AutoUpdateConfig,
    /// Pick #6 Phase 4 (2026-05-21): coding-workflow runtime knobs.
    /// Today the only field is `test_cmd` — the operator's per-
    /// repo test command (e.g. `"cargo check --quiet"` / `"pytest
    /// -x"`). When set + `neoth code --apply` is active, the
    /// dispatcher runs the command inside each task worktree
    /// after a successful patch apply; non-zero exit triggers
    /// the retryable-failure path.
    #[serde(default)]
    pub coding: CodingConfig,
    /// NOOB-UX-3 (Session 19, 2026-05-21): operator-facing
    /// plugin runtime gates. Pairs with the cargo build-time
    /// `wasm-plugin-host` feature per the
    /// `neoth-features-default-on-runtime-toggle` rule —
    /// release builds compile the feature ON, this field
    /// lets operators flip it OFF without recompiling.
    #[serde(default)]
    pub plugins: PluginsConfig,
}

/// NOOB-UX-3 plugin runtime gates.
///
/// `wasm.enabled` — master switch for the WASM plugin host.
/// `false` makes the daemon skip plugin discovery + skip the
/// `bootstrap_plugin_invoker` call so hook-engine `Plugin`
/// actions degrade to Allow (same as a slim daemon build).
/// Default is `true` because the wizard-shipped release
/// already compiled the feature on; operators who want a
/// quieter daemon flip it to `false`.
///
/// Future: per-plugin allowlist (`plugins.wasm.allow = ["hello",
/// "morning-news"]`) — restricts which plugin IDs the
/// discovery sweep accepts.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PluginsConfig {
    #[serde(default)]
    pub wasm: WasmPluginsConfig,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            wasm: WasmPluginsConfig::default(),
        }
    }
}

/// WASM plugin host runtime gate. Field-level struct (not a
/// bare `Option<bool>` on PluginsConfig) so a future field
/// addition (`allow: Vec<String>`, `memory_limit_mib: u32`)
/// extends the nested map without re-shuffling the schema.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WasmPluginsConfig {
    /// Master runtime switch. Pair-with the build-time
    /// `wasm-plugin-host` cargo feature: when the feature is
    /// compiled out, this field has no effect (the daemon
    /// has no plugin host to disable). When compiled in,
    /// `false` here makes the daemon skip plugin discovery +
    /// invoker bootstrap.
    #[serde(default = "default_wasm_plugins_enabled")]
    pub enabled: bool,
}

fn default_wasm_plugins_enabled() -> bool {
    // Default ON to honour the neoth-features-default-on
    // hard rule for shipped release binaries. Operators on a
    // slim build (no wasm-plugin-host feature) see no effect
    // either way.
    true
}

impl Default for WasmPluginsConfig {
    fn default() -> Self {
        Self {
            enabled: default_wasm_plugins_enabled(),
        }
    }
}

/// Pick #6 Phase 4 coding-workflow config block.
///
/// `test_cmd: None` (default) preserves Phase-3 behaviour — the
/// dispatcher applies the patch but never spawns a test command.
/// Operators flip it on by editing `freedom.yaml::coding.test_cmd`
/// or via the wizard (lands as a follow-up step).
///
/// `test_timeout_secs` caps a single test-command invocation so a
/// hung test can't block the dispatcher indefinitely. 5 minutes
/// is plenty for `cargo check` on a normal-sized repo + matches
/// the default DispatchBudget per-task share.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CodingConfig {
    #[serde(default)]
    pub test_cmd: Option<String>,
    #[serde(default = "default_test_timeout_secs")]
    pub test_timeout_secs: u64,
}

fn default_test_timeout_secs() -> u64 {
    5 * 60
}

impl Default for CodingConfig {
    fn default() -> Self {
        Self {
            test_cmd: None,
            test_timeout_secs: default_test_timeout_secs(),
        }
    }
}

/// V03-09 Phase 2a — operator-facing self-update knobs.
///
/// Field semantics:
///   - `enabled` — master switch. Default `false` so a stock
///     contributor build (or a daemon running behind a
///     restricted-egress firewall) never reaches out to GitHub
///     for releases. Operators flip to `true` during onboarding.
///   - `auto_apply` — Phase 2b consumes this. `true` = download
///     + verify SHA-256 + extract + atomic-replace + emit
///     "restart required" hint. `false` (default) = check-only,
///     surface the new version + URL in `neoth doctor` and let
///     the operator install manually.
///   - `channel` — release channel. Today only `"stable"` is
///     wired; `"rc"` + `"nightly"` are reserved for future
///     cargo-dist matrix variants.
///   - `check_interval_secs` — how often the background check
///     fires. Defaults to 24h (86400s). `0` disables the
///     periodic task even when `enabled: true` (operator runs
///     `neoth update --self` on demand).
///   - `repo` — owner/repo slug. Default
///     `"The-Geek-Freaks/NEOTH"`. Forks override.
///   - `target_triple` — operator override for the cargo-dist
///     target triple used during asset lookup. `None` (default)
///     means the daemon detects via
///     [`updater::self_update::host_target_triple`]; set
///     explicitly when running an unusual host
///     (e.g. `x86_64-unknown-linux-musl` against a glibc-built
///     release).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AutoUpdateConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub auto_apply: bool,
    #[serde(default = "default_update_channel")]
    pub channel: String,
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,
    #[serde(default = "default_update_repo")]
    pub repo: String,
    #[serde(default)]
    pub target_triple: Option<String>,
}

fn default_update_channel() -> String {
    "stable".to_string()
}

fn default_check_interval_secs() -> u64 {
    24 * 60 * 60
}

fn default_update_repo() -> String {
    "The-Geek-Freaks/NEOTH".to_string()
}

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_apply: false,
            channel: default_update_channel(),
            check_interval_secs: default_check_interval_secs(),
            repo: default_update_repo(),
            target_triple: None,
        }
    }
}

/// K-Repo-Map Phase 3c (Session 14 Pick #26) — code-map injection
/// policy. Lives on `FreedomConfig::code_map`. Independent from
/// `CouncilConfig::max_calls_per_user_message` because code-map
/// reads are local SQLite — no LLM cost — and need their own knob.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CodeMapConfig {
    /// Max files to surface in the auto-injected `<repo-context>`
    /// block. `0` (default) disables auto-injection. Recommended
    /// production value: 3-5 — large enough to surface the obvious
    /// hits, small enough to keep the system prompt tight.
    #[serde(default)]
    pub auto_context_max_files: u32,
}

/// R-04 2026-05-17: LOWKEY refusal-recovery policy. Operators tune
/// per-reframing opt-out via `disabled_reframings` (e.g. keep the
/// `operator_authority` LOWKEY-prepend off if the deployment is
/// for a third-party who isn't an authorised pentester).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RefusalRecoveryConfig {
    /// Master switch — `true` (default) runs `try_recover` once per
    /// detected refusal. `false` keeps the original refusal text in
    /// the response chain (downstream SESSION_ARCHIVE + profile
    /// pipeline see the refusal verbatim).
    #[serde(default = "default_refusal_recovery_enabled")]
    pub enabled: bool,
    /// Reframing IDs that should NEVER fire. Matched against
    /// `Reframing::id()` (snake_case). Defaults to empty —
    /// operator must opt-out per-reframing. Disabling
    /// `operator_authority` falls back to `narrow_scope` for
    /// SafetyPolicy refusals.
    #[serde(default)]
    pub disabled_reframings: Vec<String>,
    /// R-01 2026-05-17: maximum reframings to try per refusal.
    /// Default 2 per SPEC §4. Set to 1 for single-attempt (matches
    /// original R-05 behaviour); set to 6 to walk the entire
    /// applicable catalogue. After this budget is exhausted the
    /// orchestrator emits `0x1A REFUSAL_PERSISTENT` and surfaces
    /// the last failure to the caller.
    #[serde(default = "default_refusal_recovery_max_attempts")]
    pub max_attempts: u32,
}

impl Default for RefusalRecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: default_refusal_recovery_enabled(),
            disabled_reframings: Vec::new(),
            max_attempts: default_refusal_recovery_max_attempts(),
        }
    }
}

fn default_refusal_recovery_enabled() -> bool {
    true
}

fn default_refusal_recovery_max_attempts() -> u32 {
    2
}

/// 2026-05-17 Session 2: profile-learning policy. Defaults to off so
/// operators using paid cloud providers don't get a surprise 2× token
/// bill from the post-reply extract LLM call. Flip `learn_enabled:
/// true` in freedom.yaml (or override per-call via env var
/// `NEOTH_PROFILE_LEARN_DISABLE=0`) to opt in.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProfileConfig {
    /// When `true`, the chat handler runs `profile::run_pipeline` after
    /// each reply so operator-profile claims grow passively. Costs one
    /// extra LLM call per chat (the Stage-3 extract). Default `false`.
    #[serde(default = "default_profile_learn_enabled")]
    pub learn_enabled: bool,
    /// Hard upper bound (seconds) on how long the post-reply profile
    /// pipeline is allowed to block the CLI before bailing. Default
    /// 15s. A hung provider or oversized window cannot keep the CLI
    /// from returning past this cap; the pipeline run is abandoned
    /// (logged at warn) and the operator gets their shell prompt back.
    #[serde(default = "default_profile_timeout_secs")]
    pub timeout_secs: u64,
    /// L-06 (2026-05-22 Session 20): preferred provider name for the
    /// profile-extract LLM call. `None` → uses the operator's default
    /// provider from `provider_kind`. Operators on paid cloud providers
    /// (claude_cli / openai_api / gemini_api) typically set this to
    /// `local_qwen` so the post-reply extract stays free + offline.
    /// Defaults to `Some("local_qwen")` — the cheap-by-default stance.
    #[serde(default = "default_profile_learn_provider")]
    pub learn_provider: Option<String>,
    /// L-07 (2026-05-22 Session 20): when the configured
    /// `learn_provider` is unavailable (local_qwen weights missing,
    /// model download failed, hardware unsupported), fall back to the
    /// operator's main `provider_kind` IF this flag is true. Default
    /// `false` — operators on local-qwen-only profile-learn explicitly
    /// opt in to "spend cloud tokens when local doesn't work today".
    #[serde(default = "default_profile_allow_cloud_fallback")]
    pub allow_cloud_fallback: bool,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            learn_enabled: default_profile_learn_enabled(),
            timeout_secs: default_profile_timeout_secs(),
            learn_provider: default_profile_learn_provider(),
            allow_cloud_fallback: default_profile_allow_cloud_fallback(),
        }
    }
}

fn default_profile_learn_enabled() -> bool {
    false
}

fn default_profile_timeout_secs() -> u64 {
    15
}

/// L-06: profile-extract should use the cheapest available path by
/// default — local_qwen avoids surprise paid-cloud tokens.
fn default_profile_learn_provider() -> Option<String> {
    Some("local_qwen".to_string())
}

/// L-07: fail-closed by default. Operators who explicitly want cloud
/// fallback for profile-learning flip this to `true`.
fn default_profile_allow_cloud_fallback() -> bool {
    false
}

/// B-6 Item 2: Claude CLI adapter configuration.
///
/// Mapped onto `claude_cli.backend` + `claude_cli.tmux.*` in
/// freedom.yaml. Empty block (or missing field) inherits all defaults.
///
/// Example:
/// ```yaml
/// claude_cli:
///   backend: auto              # auto | tmux | subprocess
///   tmux:
///     session_scope: singleton # singleton | per_conversation (v0.2+)
///     compaction_rotate_after: 10
///     idle_ttl_secs: 1800      # session sweeper TTL
///     idle_timeout_secs: 120   # per-request idle window
///     hard_timeout_secs: 300   # per-request absolute cap
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ClaudeCliConfig {
    /// Backend selection. `auto` (default) probes tmux availability +
    /// picks the best option; `tmux` forces warm-session mode (the
    /// only path that works reliably for Alex's stack — see memory
    /// `neoth-claude-cli-tmux-mandatory.md`); `subprocess` forces the
    /// cold-start `claude --print` path (broken on Alex's host but
    /// kept as a Windows-without-WSL escape hatch).
    #[serde(default)]
    pub backend: ClaudeCliBackendCfg,
    /// Tmux backend tuning. Ignored when `backend == subprocess`.
    #[serde(default)]
    pub tmux: ClaudeCliTmuxConfig,
}

/// Serde-facing backend tag. Separate from
/// [`crate::providers::claude_cli::ClaudeBackend`] so the config layer
/// does not depend on the providers module's internals.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeCliBackendCfg {
    #[default]
    Auto,
    Tmux,
    Subprocess,
}

impl ClaudeCliBackendCfg {
    /// Lower the config-layer enum into the providers-layer enum the
    /// adapter constructor accepts. Pure mapping; keeps `config` free
    /// of `providers::` imports.
    pub fn to_provider(self) -> crate::providers::claude_cli::ClaudeBackend {
        match self {
            Self::Auto => crate::providers::claude_cli::ClaudeBackend::Auto,
            Self::Tmux => crate::providers::claude_cli::ClaudeBackend::Tmux,
            Self::Subprocess => crate::providers::claude_cli::ClaudeBackend::Subprocess,
        }
    }
}

/// Tmux warm-session tuning. Defaults match bridge.py + claude_tmux's
/// pinned constants. Each field is optional in the YAML; missing fields
/// inherit the constants below.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaudeCliTmuxConfig {
    /// Session scope. `Singleton` (default) = one warm session per
    /// adapter (the v0.1 TmuxSlot wiring). `PerConversation` is the
    /// Agent-4 architecture that pools sessions keyed by
    /// conversation-id; deferred until the chat dispatch threads a
    /// `conversation_id` through `Request`. Set today + NEOTH warns
    /// at boot + falls back to singleton.
    #[serde(default)]
    pub session_scope: TmuxSessionScope,
    /// How many "Memory was condensed" responses trigger a fresh
    /// session. Bridge.py default = 10. Lower = more rotations
    /// (cleaner state, higher cold-start cost); higher = more drift.
    #[serde(default = "default_compaction_rotate_after")]
    pub compaction_rotate_after: u32,
    /// Session sweeper TTL — `cli/tmux_sweeper` kills warm sessions
    /// idle longer than this. Bridge.py default = 1800 (30 min).
    /// Honored by the sweeper task; tmux_session itself is
    /// indifferent.
    #[serde(default = "default_idle_ttl_secs")]
    pub idle_ttl_secs: u64,
    /// Per-request idle-window cap. No pane change for this many
    /// seconds = response complete. Bridge.py + claude_tmux default
    /// = 120. v0.1: declared here but not yet read by claude_tmux
    /// (that uses the const). Wired in Item 3 when the retry
    /// classifier consumes the per-call timer budget.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Per-request absolute cap. claude_tmux returns
    /// `HardTimeoutNoOutput` past this. Bridge.py default = 300.
    /// v0.1: declared, not yet wired (see `idle_timeout_secs`).
    #[serde(default = "default_hard_timeout_secs")]
    pub hard_timeout_secs: u64,
}

impl Default for ClaudeCliTmuxConfig {
    fn default() -> Self {
        Self {
            session_scope: TmuxSessionScope::default(),
            compaction_rotate_after: default_compaction_rotate_after(),
            idle_ttl_secs: default_idle_ttl_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
            hard_timeout_secs: default_hard_timeout_secs(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TmuxSessionScope {
    #[default]
    Singleton,
    /// Reserved for the Agent-4 conversation-keyed pool. Logged +
    /// downgraded to `Singleton` at startup for v0.1.
    PerConversation,
}

fn default_compaction_rotate_after() -> u32 {
    10
}

fn default_idle_ttl_secs() -> u64 {
    1800
}

fn default_idle_timeout_secs() -> u64 {
    120
}

fn default_hard_timeout_secs() -> u64 {
    300
}

/// B-Rollback snapshot policy. Defaults to capturing config writes +
/// outbound channel sends — the two mutation classes operators most
/// often regret. SQL mutations + MCP tool invocations + free-form
/// file writes are opt-in because their payload sizes are unbounded.
///
/// Per Konsens decision #4: WAL growth at the default ≈ 42 MB/year
/// for a typical operator; safe within the 5 GiB quota ceiling.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackConfig {
    /// Mutation kinds (snake_case) NEOTH should emit snapshots for.
    /// Empty list = rollback fully off (no automatic snapshots emitted).
    #[serde(default = "default_rollback_kinds")]
    pub capture_kinds: Vec<String>,
    /// Per-frame ceiling on `before_state` bytes. Snapshots whose
    /// captured state exceeds this cap are skipped + logged at WARN
    /// — prevents a single 10 MB file write from producing a
    /// runaway WAL frame.
    #[serde(default = "default_rollback_max_bytes")]
    pub max_snapshot_bytes: usize,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            capture_kinds: default_rollback_kinds(),
            max_snapshot_bytes: default_rollback_max_bytes(),
        }
    }
}

fn default_rollback_kinds() -> Vec<String> {
    vec!["config_write".to_string(), "channel_send".to_string()]
}

fn default_rollback_max_bytes() -> usize {
    65_536
}

impl RollbackConfig {
    /// True when the given mutation kind is in the capture allowlist.
    /// Case-insensitive match against the snake_case wire name.
    pub fn should_capture(&self, kind: &str) -> bool {
        let needle = kind.to_ascii_lowercase();
        self.capture_kinds
            .iter()
            .any(|k| k.eq_ignore_ascii_case(&needle))
    }
}

impl FreedomConfig {
    /// `~/.neoth/freedom.yaml` resolved against HOME (unix) or USERPROFILE (Windows).
    pub fn default_path() -> PathBuf {
        neoth_home().join("freedom.yaml")
    }

    /// `~/.neoth/wal/` resolved against HOME / USERPROFILE.
    pub fn default_wal_dir() -> PathBuf {
        neoth_home().join("wal")
    }

    /// `~/.neoth/` itself — used by callers that need siblings of the wal dir
    /// (audit logs, credentials, models, …).
    pub fn default_neoth_home() -> PathBuf {
        neoth_home()
    }

    /// Path to the optional cron jobs file (`~/.neoth/jobs.yaml`).
    ///
    /// Returns `Some` regardless of whether the file exists — callers should
    /// check `exists()`. `None` is reserved for future per-operator overrides
    /// (e.g. `jobs_path:` field in `freedom.yaml`); none exist yet.
    pub fn jobs_file_path(&self) -> Option<PathBuf> {
        Some(neoth_home().join("jobs.yaml"))
    }

    pub fn load_from_default_path() -> Result<Self> {
        Self::load_from_path(&Self::default_path())
    }

    /// Write the public (secret-free) portion of this config to the
    /// default `freedom.yaml` path with mode 0600 (unix) + atomic
    /// rename. SecretString fields are stripped before serialisation
    /// — secret-split (Codex audit #7) requires API keys / tokens to
    /// live in `credentials.yaml`, not `freedom.yaml`.
    ///
    /// Used by `neoth hemispheres set` and similar CLI commands that
    /// mutate freedom.yaml after onboarding. Per-hemisphere API keys
    /// must be set by editing `~/.neoth/credentials.yaml` manually for
    /// v0.1; a future `neoth credentials set` CLI will close that gap.
    pub fn save_public_to_default_path(&self) -> Result<()> {
        let mut public = self.clone();
        // Strip every secret field so freedom.yaml stays free of
        // plaintext API keys. Operators who want per-slot keys edit
        // credentials.yaml directly.
        public.provider_key = None;
        public.telegram_token = None;
        public.inference.left.key = None;
        public.inference.right.key = None;
        public.inference.cerebellum.key = None;
        public.inference.default_slot.key = None;

        let body = serde_yaml::to_string(&public)
            .context("serialize FreedomConfig as YAML for freedom.yaml")?;
        let path = Self::default_path();
        let tmp = path.with_extension("yaml.tmp");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent {}", parent.display()))?;
        }
        credentials::write_mode_0600(&tmp, body.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        #[cfg(windows)]
        {
            let _ = crate::wal::win_acl::restrict_to_owner(&path);
        }
        Ok(())
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            anyhow::bail!(
                "freedom.yaml not found at {}. Run `neoth init` first to generate it.",
                path.display()
            );
        }

        #[cfg(unix)]
        warn_if_world_readable(path);

        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read freedom.yaml at {}", path.display()))?;
        let mut config: FreedomConfig = serde_yaml::from_str(&body)
            .with_context(|| format!("parse YAML at {}", path.display()))?;

        // Merge `~/.neoth/credentials.yaml` if present. credentials.yaml
        // is the dedicated home for plaintext secrets — the values there
        // win over anything embedded in `freedom.yaml` because the
        // operator-editable surface is the dedicated file. Legacy
        // installs that still keep secrets inline keep working.
        let cred_path = match path.parent() {
            Some(parent) => parent.join("credentials.yaml"),
            None => credentials::default_path(),
        };
        #[cfg(unix)]
        warn_if_world_readable(&cred_path);
        let creds = credentials::Credentials::load_or_default(&cred_path)
            .with_context(|| format!("load credentials at {}", cred_path.display()))?;
        if let Some(k) = creds.provider_key {
            config.provider_key = Some(k);
        }
        if let Some(t) = creds.telegram_token {
            config.telegram_token = Some(t);
        }
        Ok(config)
    }
}

fn neoth_home() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".neoth")
}

#[cfg(unix)]
fn warn_if_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode),
                "freedom.yaml is more permissive than 0600. \
                 Run `chmod 0600 {}` to lock it down.",
                path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_yaml(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("freedom.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn load_minimal_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nrole: developer\nprovider_kind: claude_cli\nsteps_completed: [1,2,3,4,5,6,7]\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.operator_id.as_deref(), Some("alice"));
        assert_eq!(cfg.role, Some(OperatorRole::Developer));
        assert_eq!(cfg.provider_kind, Some(ProviderKind::ClaudeCli));
    }

    #[test]
    fn load_missing_file_says_to_run_init() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.yaml");
        let err = FreedomConfig::load_from_path(&path).unwrap_err();
        assert!(err.to_string().contains("neoth init"));
    }

    #[test]
    fn load_tolerates_unknown_fields() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nfuture_field: 42\nanother_unknown: foo\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.operator_id.as_deref(), Some("alice"));
    }

    #[test]
    fn load_rejects_malformed_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: [unterminated\n");
        let err = FreedomConfig::load_from_path(&path).unwrap_err();
        assert!(err.to_string().contains("parse YAML"));
    }

    /// V02-08 acceptance: the shipped `freedom.yaml.example` must
    /// parse cleanly through `FreedomConfig::load_from_path`. Catches
    /// the failure mode where someone adds a new field to the struct
    /// + the wizard, but forgets to update the example.
    #[test]
    fn freedom_yaml_example_parses_cleanly() {
        // The example file lives at SRC/freedom.yaml.example —
        // walking up from CARGO_MANIFEST_DIR (neothd crate root).
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let example_path = manifest_dir.parent().unwrap().join("freedom.yaml.example");
        if !example_path.exists() {
            // The workspace shape may vary across local checkouts; skip
            // gracefully rather than break developer flow when the
            // example file is moved.
            eprintln!(
                "skipping: freedom.yaml.example not at {}",
                example_path.display()
            );
            return;
        }
        let cfg = FreedomConfig::load_from_path(&example_path)
            .expect("freedom.yaml.example must parse via FreedomConfig::load_from_path");
        // Spot-check the documented defaults landed.
        assert_eq!(cfg.operator_id.as_deref(), Some("alex"));
        assert_eq!(cfg.role, Some(OperatorRole::Developer));
        assert_eq!(cfg.provider_kind, Some(ProviderKind::ClaudeCli));
        assert!(
            cfg.rollback
                .capture_kinds
                .contains(&"config_write".to_string())
        );
        assert!(
            cfg.rollback
                .capture_kinds
                .contains(&"channel_send".to_string())
        );
        assert_eq!(cfg.rollback.max_snapshot_bytes, 65_536);
    }

    #[test]
    fn rollback_default_captures_config_and_channel_send() {
        // A3: pin the Konsens-decision defaults so a refactor that
        // drifts them fails loudly rather than silently changing
        // operator behaviour.
        let cfg = RollbackConfig::default();
        assert!(cfg.should_capture("config_write"));
        assert!(cfg.should_capture("channel_send"));
        // NOT captured by default: file_write, mcp_tool_invoke,
        // sql_mutation. Operators opt in per kind.
        assert!(!cfg.should_capture("file_write"));
        assert!(!cfg.should_capture("mcp_tool_invoke"));
        assert!(!cfg.should_capture("sql_mutation"));
        // 64 KB per-frame cap matches Konsens recommendation.
        assert_eq!(cfg.max_snapshot_bytes, 65_536);
    }

    #[test]
    fn rollback_should_capture_is_case_insensitive_on_snake_case() {
        // Match is case-insensitive but snake_case-only — we do NOT
        // normalise CamelCase → snake_case (that would invite typo
        // tolerance the operator can't audit).
        let cfg = RollbackConfig::default();
        assert!(cfg.should_capture("CONFIG_WRITE"));
        assert!(cfg.should_capture("Config_Write"));
        assert!(cfg.should_capture("config_write"));
        assert!(!cfg.should_capture("config_wrte")); // typo → no match
        // Operator must use snake_case to match — `ConfigWrite`
        // (camelCase) intentionally does not match.
        assert!(!cfg.should_capture("ConfigWrite"));
    }

    #[test]
    fn rollback_empty_capture_kinds_means_disabled() {
        // Operator who wants rollback fully off can ship an empty list.
        let cfg = RollbackConfig {
            capture_kinds: vec![],
            max_snapshot_bytes: 65_536,
        };
        assert!(!cfg.should_capture("config_write"));
        assert!(!cfg.should_capture("channel_send"));
    }

    #[test]
    fn claude_cli_config_default_is_auto_backend_with_bridge_py_tuning() {
        // Drift guard: the no-config-block fallback must match the
        // operator-tested bridge.py constants so freedom.yaml files
        // that don't mention `claude_cli:` behave like they did
        // before B-6 landed.
        let cfg = ClaudeCliConfig::default();
        assert_eq!(cfg.backend, ClaudeCliBackendCfg::Auto);
        assert_eq!(cfg.tmux.session_scope, TmuxSessionScope::Singleton);
        assert_eq!(cfg.tmux.compaction_rotate_after, 10);
        assert_eq!(cfg.tmux.idle_ttl_secs, 1800);
        assert_eq!(cfg.tmux.idle_timeout_secs, 120);
        assert_eq!(cfg.tmux.hard_timeout_secs, 300);
    }

    #[test]
    fn claude_cli_backend_cfg_lowers_to_provider_enum() {
        // The config-layer enum must round-trip into the providers
        // adapter's enum without losing variants — otherwise the
        // wizard's selection wouldn't reach the adapter.
        use crate::providers::claude_cli::ClaudeBackend as P;
        assert_eq!(ClaudeCliBackendCfg::Auto.to_provider(), P::Auto);
        assert_eq!(ClaudeCliBackendCfg::Tmux.to_provider(), P::Tmux);
        assert_eq!(ClaudeCliBackendCfg::Subprocess.to_provider(), P::Subprocess);
    }

    #[test]
    fn refusal_recovery_default_is_enabled_with_no_disabled_reframings() {
        // R-04 2026-05-17: default ON so refusals get auto-retried via
        // pure-function reframings. Operators who want raw refusals
        // visible (debugging / forensic) flip enabled=false. Drift
        // guard so a future refactor flipping the default fails
        // loudly rather than silently changing recovery behaviour.
        let cfg = RefusalRecoveryConfig::default();
        assert!(cfg.enabled, "default must be opt-in (auto-recovery on)");
        assert!(cfg.disabled_reframings.is_empty());
    }

    #[test]
    fn refusal_recovery_block_round_trips_through_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             refusal_recovery:\n  \
               enabled: false\n  \
               disabled_reframings:\n    \
                 - operator_authority\n    \
                 - historical_framing\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.refusal_recovery.enabled);
        assert_eq!(cfg.refusal_recovery.disabled_reframings.len(), 2);
        assert!(
            cfg.refusal_recovery
                .disabled_reframings
                .contains(&"operator_authority".to_string())
        );
    }

    #[test]
    fn refusal_recovery_block_missing_inherits_enabled_default() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.refusal_recovery.enabled);
        assert!(cfg.refusal_recovery.disabled_reframings.is_empty());
    }

    #[test]
    fn profile_config_default_is_opt_out_with_15s_timeout() {
        // 2026-05-17 Session 2: default OFF so paid-cloud operators
        // don't get a surprise 2× token bill from the post-reply
        // extract LLM call. Drift guard so a future refactor flipping
        // the default fails loudly.
        let cfg = ProfileConfig::default();
        assert!(!cfg.learn_enabled, "default must be opt-out");
        assert_eq!(cfg.timeout_secs, 15);
        // L-06 (2026-05-22): cheap-by-default learn provider so
        // turning learning ON doesn't suddenly cost cloud tokens.
        assert_eq!(cfg.learn_provider.as_deref(), Some("local_qwen"));
        // L-07: fail-closed by default. Operators explicitly opt in
        // to "spend cloud tokens when local fails".
        assert!(!cfg.allow_cloud_fallback);
    }

    #[test]
    fn l_06_l_07_profile_block_round_trips_new_fields() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               learn_enabled: true\n  \
               learn_provider: openai_api\n  \
               allow_cloud_fallback: true\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.profile.learn_enabled);
        assert_eq!(
            cfg.profile.learn_provider.as_deref(),
            Some("openai_api")
        );
        assert!(cfg.profile.allow_cloud_fallback);
    }

    #[test]
    fn l_06_explicit_null_learn_provider_disables_pin() {
        // Operator who wants the profile-extract to follow the main
        // provider_kind sets learn_provider: null. Verify the
        // round-trip preserves None instead of falling back to the
        // default `Some("local_qwen")`.
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               learn_provider: null\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.profile.learn_provider.is_none());
    }

    #[test]
    fn profile_block_missing_inherits_opt_out_default() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.profile.learn_enabled);
        assert_eq!(cfg.profile.timeout_secs, 15);
    }

    #[test]
    fn profile_block_round_trips_through_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             profile:\n  \
               learn_enabled: true\n  \
               timeout_secs: 30\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.profile.learn_enabled);
        assert_eq!(cfg.profile.timeout_secs, 30);
    }

    #[test]
    fn profile_partial_block_fills_unspecified_fields_with_defaults() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nprofile:\n  learn_enabled: true\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.profile.learn_enabled);
        // Missing timeout_secs falls back to default.
        assert_eq!(cfg.profile.timeout_secs, 15);
    }

    #[test]
    fn claude_cli_block_round_trips_through_yaml_when_present() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             claude_cli:\n  \
               backend: tmux\n  \
               tmux:\n    \
                 session_scope: per_conversation\n    \
                 compaction_rotate_after: 5\n    \
                 idle_ttl_secs: 600\n    \
                 idle_timeout_secs: 90\n    \
                 hard_timeout_secs: 240\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.claude_cli.backend, ClaudeCliBackendCfg::Tmux);
        assert_eq!(
            cfg.claude_cli.tmux.session_scope,
            TmuxSessionScope::PerConversation
        );
        assert_eq!(cfg.claude_cli.tmux.compaction_rotate_after, 5);
        assert_eq!(cfg.claude_cli.tmux.idle_ttl_secs, 600);
        assert_eq!(cfg.claude_cli.tmux.idle_timeout_secs, 90);
        assert_eq!(cfg.claude_cli.tmux.hard_timeout_secs, 240);
    }

    #[test]
    fn claude_cli_block_missing_inherits_defaults() {
        // Backward compat: freedom.yaml files written before B-6
        // landed have no `claude_cli:` block; serde must populate
        // the defaults transparently.
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.claude_cli.backend, ClaudeCliBackendCfg::Auto);
        assert_eq!(cfg.claude_cli.tmux.compaction_rotate_after, 10);
    }

    #[test]
    fn claude_cli_partial_block_fills_unspecified_fields_with_defaults() {
        // Operator overrides one knob (compaction cap) but leaves the
        // rest implicit. Missing fields must inherit defaults rather
        // than throwing.
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\n\
             claude_cli:\n  \
               tmux:\n    \
                 compaction_rotate_after: 3\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.claude_cli.backend, ClaudeCliBackendCfg::Auto);
        assert_eq!(cfg.claude_cli.tmux.compaction_rotate_after, 3);
        // Other tmux fields still default.
        assert_eq!(cfg.claude_cli.tmux.idle_timeout_secs, 120);
        assert_eq!(cfg.claude_cli.tmux.hard_timeout_secs, 300);
    }

    #[test]
    fn claude_cli_backend_serializes_snake_case() {
        // Operators read what they wrote — the on-disk form must
        // be canonical snake_case, not `Auto` / `Tmux` (which would
        // confuse anyone editing by hand).
        let cfg = ClaudeCliConfig {
            backend: ClaudeCliBackendCfg::Tmux,
            tmux: ClaudeCliTmuxConfig::default(),
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        assert!(
            yaml.contains("backend: tmux"),
            "expected snake_case `tmux`, got: {yaml}"
        );
        assert!(
            yaml.contains("session_scope: singleton"),
            "expected snake_case scope, got: {yaml}"
        );
    }

    // ── V03-09 Phase 2a — AutoUpdateConfig ─────────────────────────

    #[test]
    fn auto_update_config_defaults_are_check_only_disabled() {
        // Master switch is OFF; auto_apply is OFF. Stock build does
        // nothing on the update front until the operator opts in.
        let cfg = AutoUpdateConfig::default();
        assert!(!cfg.enabled, "auto-update master switch must default OFF");
        assert!(!cfg.auto_apply, "auto_apply must default OFF (check-only)");
        assert_eq!(cfg.channel, "stable");
        assert_eq!(cfg.check_interval_secs, 24 * 60 * 60);
        assert_eq!(cfg.repo, "The-Geek-Freaks/NEOTH");
        assert!(cfg.target_triple.is_none());
    }

    #[test]
    fn auto_update_config_inherits_default_when_yaml_omits_block() {
        // Backward compat with freedom.yaml written before this
        // field existed: load must succeed + populate the default.
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.auto_update, AutoUpdateConfig::default());
    }

    #[test]
    fn auto_update_config_partial_block_fills_defaults() {
        // Operator only writes `enabled: true` — channel, repo,
        // interval, etc. must inherit defaults so a future field
        // addition doesn't break existing configs.
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nauto_update:\n  enabled: true\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.auto_update.enabled);
        assert!(!cfg.auto_update.auto_apply);
        assert_eq!(cfg.auto_update.channel, "stable");
        assert_eq!(cfg.auto_update.repo, "The-Geek-Freaks/NEOTH");
    }

    #[test]
    fn auto_update_config_full_block_round_trips() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nauto_update:\n  enabled: true\n  auto_apply: true\n  channel: rc\n  check_interval_secs: 3600\n  repo: example/fork\n  target_triple: x86_64-unknown-linux-musl\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.auto_update.enabled);
        assert!(cfg.auto_update.auto_apply);
        assert_eq!(cfg.auto_update.channel, "rc");
        assert_eq!(cfg.auto_update.check_interval_secs, 3_600);
        assert_eq!(cfg.auto_update.repo, "example/fork");
        assert_eq!(
            cfg.auto_update.target_triple.as_deref(),
            Some("x86_64-unknown-linux-musl")
        );
    }

    #[test]
    fn auto_update_config_serializes_to_yaml_with_snake_case_fields() {
        // Wire form pin: operator-facing keys are snake_case so the
        // wizard + docs match.
        let cfg = FreedomConfig {
            operator_id: Some("alice".to_string()),
            auto_update: AutoUpdateConfig {
                enabled: true,
                auto_apply: true,
                channel: "stable".to_string(),
                check_interval_secs: 7_200,
                repo: "The-Geek-Freaks/NEOTH".to_string(),
                target_triple: None,
            },
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        assert!(yaml.contains("auto_update:"));
        assert!(yaml.contains("auto_apply: true"));
        assert!(yaml.contains("check_interval_secs: 7200"));
        assert!(yaml.contains("channel: stable"));
    }

    // ── NOOB-UX-3 PluginsConfig runtime gate ────────────────────────

    #[test]
    fn plugins_wasm_enabled_defaults_to_true() {
        // Honours the neoth-features-default-on hard rule —
        // operators on a shipped release expect the feature to
        // be live unless they explicitly disabled it.
        let cfg = PluginsConfig::default();
        assert!(cfg.wasm.enabled);
    }

    #[test]
    fn plugins_block_inherits_default_when_yaml_omits_it() {
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.plugins.wasm.enabled, "absent block → default ON");
    }

    #[test]
    fn plugins_wasm_disabled_via_yaml_round_trips() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nplugins:\n  wasm:\n    enabled: false\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.plugins.wasm.enabled, "operator override took effect");
    }

    #[test]
    fn plugins_block_serialises_with_snake_case_fields() {
        // Wire form pin — the wizard + docs use these exact keys.
        let cfg = FreedomConfig {
            operator_id: Some("alice".to_string()),
            plugins: PluginsConfig {
                wasm: WasmPluginsConfig { enabled: false },
            },
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        assert!(yaml.contains("plugins:"));
        assert!(yaml.contains("wasm:"));
        assert!(yaml.contains("enabled: false"));
    }

    #[test]
    fn rollback_round_trips_through_yaml() {
        // Backward compat: freedom.yaml without a `rollback:` block
        // inherits the default config.
        let dir = tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.rollback.should_capture("config_write"));
        // And with an explicit block, operator can shrink or extend.
        let path2 = write_yaml(
            dir.path(),
            "operator_id: alice\nrollback:\n  capture_kinds: [sql_mutation, file_write]\n  max_snapshot_bytes: 32768\n",
        );
        let cfg2 = FreedomConfig::load_from_path(&path2).unwrap();
        assert!(cfg2.rollback.should_capture("sql_mutation"));
        assert!(cfg2.rollback.should_capture("file_write"));
        assert!(!cfg2.rollback.should_capture("config_write"));
        assert_eq!(cfg2.rollback.max_snapshot_bytes, 32_768);
    }
}
