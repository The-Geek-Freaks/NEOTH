pub mod automation;
pub mod features;
pub mod inference;
mod instance_paths;
pub mod memory;
pub mod ops;
pub mod policy;
pub mod provider;
pub mod reload;
pub mod rollback;
pub mod tools;
pub mod wal;

pub(crate) use instance_paths::InstancePaths;

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
// ## Secrets-on-disk model (D003-KEYCHAIN-01)
//
// Secrets live in `~/.neoth/credentials.yaml` (split from freedom.yaml in
// the Codex audit pass). `SecretString` values are mlock'd in RAM and
// zeroize'd on drop; the YAML file is mode 0600 / Windows DACL-restricted.
//
// **OS keychain backend (opt-in):** set `secrets_backend: keychain` in
// freedom.yaml (or run `neoth credential migrate --to keychain`) to move
// `SecretString` fields into the OS credential store (Windows Credential
// Manager; macOS Keychain / Linux Secret Service in follow-on commits).
// The YAML values then act as an emergency fallback — a non-null YAML
// value always wins over the keychain entry so operators can recover
// without the OS store.
//
// Operators who need at-rest crypto should also enable FDE (BitLocker /
// LUKS / FileVault) — the keychain does not replace full-disk encryption.
//
// The boot-time `cli/serve.rs` permission check warns if the file is
// readable by anyone other than the operator.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub mod credentials;
// D003-KEYCHAIN-01 — OS keychain backend, migration helpers, SecretStore trait.
pub mod keychain;

// Serialises same-process freedom.yaml read-modify-write cycles. The sibling
// OS lock below covers separate CLI/daemon processes; both tiers are needed
// because advisory file-lock reentrancy differs across platforms.
static FREEDOM_UPDATE_LOCK: Mutex<()> = Mutex::new(());

fn lock_freedom_update() -> MutexGuard<'static, ()> {
    FREEDOM_UPDATE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
// GOLD-ADAPT-DOC-01 (2026-06-23) — Python pip-gate helpers (ppt_master → python-pptx).
pub mod installer;
pub mod preset_builtins;
pub mod presets;

use crate::cli::init::{OperatorRole, ProviderKind};
use crate::secret::SecretString;

pub use crate::analytics::babel::BabelConfig;
pub use automation::{
    AutoSkillExtractConfig, BgMonitorConfig, CheckinCronConfig, CompanionConfig,
    ConsolidationSweepConfig, DEFAULT_CHECKIN_CRON_INTERVAL_SECS,
    DEFAULT_CONSOLIDATION_SWEEP_INTERVAL_SECS, DEFAULT_DRIFT_ALERT_INTERVAL_SECS,
    DEFAULT_GUIDANCE_CRON_INTERVAL_SECS, DEFAULT_INACTIVITY_GAP_SECS,
    DEFAULT_MONITOR_INTERVAL_SECS, DEFAULT_OAI_SERVE_PORT, DEFAULT_PATTERN_CRON_INTERVAL_SECS,
    DEFAULT_PROFILE_ADAPT_INTERVAL_SECS, DEFAULT_RECALL_LATENCY_INTERVAL_SECS,
    DEFAULT_REGRESSION_INTERVAL_SECS, DEFAULT_RESOURCE_WATCH_INTERVAL_SECS,
    DEFAULT_SESSION_HEALTH_INTERVAL_SECS, DEFAULT_SKILL_CURATOR_INTERVAL_SECS,
    DEFAULT_SYNTHESIS_CRON_INTERVAL_SECS, DEFAULT_TOKEN_ANOMALY_INTERVAL_SECS,
    DEFAULT_WATCHDOG_WINDOW_SECS, DriftAlertConfig, EmailIngestCronConfig, GuidanceCronConfig,
    KanbanSseConfig, MonitorConfig, N8nApiConfig, OaiServeConfig, PatternCronConfig,
    ProactiveConfig, ProfileAdaptConfig, RecallLatencyConfig, RecursiveMasConfig,
    RegressionAnchorConfig, ResourceWatchConfig, SelfActivationConfig, SelfWikiConfig,
    SessionHealthConfig, SkillCuratorConfig, SynthesisCronConfig, TokenAnomalyConfig,
    WatchdogConfig,
};
pub use features::{
    ArxivIngestConfig, ArxivSkillScanConfig, CalendarConfig, ChannelLearnScope,
    ChannelWeightsConfig, DEFAULT_ECOLOGY_SCHEDULER_INTERVAL_SECS,
    DEFAULT_LIVE_EDIT_MIN_INTERVAL_MS, DEFAULT_LIVE_MAX_EDITS_PER_MESSAGE, DreamingConfig,
    EcologyConfig, EmailConfig, FallbackConfig, GoalConfig, HintsConfig, HookChainConfig,
    LiveDeliveryConfig, LoopConfig, MediaConfig, OmiConfig, OmiIngestMode, TransferConfig,
};
pub use memory::{MemoryConfig, VectorBackend, VectorIndexConfig};
pub use ops::{
    AutoUpdateConfig, CodeMapConfig, CodingConfig, DoctorConfig, PluginsConfig, ProfileConfig,
    RefusalRecoveryConfig, ReleaseChannel, SupervisorConfig, SupervisorKind, TaskEngineConfig,
    UpdaterConfig, WasmPluginsConfig,
};
pub use policy::{
    CompactionConfig, CompressionConfig, DangerousPolicy, EgressMode, EgressPolicy, FeedEntry,
    FeedsConfig, SecurityPolicy, SkillVisibility, SkillsConfig, TokensConfig,
};
pub use provider::{ClaudeCliBackendCfg, ClaudeCliConfig, ClaudeCliTmuxConfig, TmuxSessionScope};
pub use rollback::RollbackConfig;
pub use tools::{ClipboardConfig, OsToolsConfig, ToolsConfig};
pub use wal::{WalCompression, WalConfig, load_wal_config, load_wal_config_strict};

/// GOLD-ADAPT-JV-MODE-01 — identity-locked persona modes.
///
/// Unlike `ProfilePreset` (which controls tone/verbosity per turn),
/// `PersonaMode` carries a hard identity-anchor invariant: once set, the
/// chosen persona CANNOT be changed by incoming channel messages, skills, or
/// user prompts. The lock is enforced at two layers:
///
/// 1. Ingress sanitizer: persona-override attempt patterns quarantine the
///    message before it reaches the pipeline.
/// 2. Enrichment: the identity-anchor text is pinned at position 1 in the
///    layered system prompt (after moral_core, before operator_context) so no
///    downstream layer can displace it.
///
/// Stored in `freedom.yaml::persona_mode` as the snake_case variant name.
/// `None` = no identity lock (default; all channels open).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaMode {
    /// Identity-locked loyal-buddy: mirrors operator register, proactive
    /// ("ausführen+berichten nicht fragen"), direct/no-filler, loyal-first.
    /// Rejects persona-change requests at the ingress layer.
    LoyalBuddy,
}

/// D003-KEYCHAIN-01 — controls where `SecretString` fields are loaded from at
/// daemon startup.
///
/// | Value      | Behaviour                                                    |
/// |------------|--------------------------------------------------------------|
/// | `file`     | (default) load secrets exclusively from `credentials.yaml`. |
/// | `keychain` | supplement YAML with OS credential store; YAML value wins.  |
///
/// Switch at runtime: set `secrets_backend: keychain` in freedom.yaml (or
/// run `neoth credential migrate --to keychain` to auto-populate the store
/// and blank the YAML values). Revert with `--to file`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretsBackend {
    /// Secrets come exclusively from `credentials.yaml` (default).
    #[default]
    File,
    /// Secrets come from the OS credential store, with `credentials.yaml`
    /// values as an emergency override (YAML wins over keychain if non-null).
    Keychain,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FreedomConfig {
    /// D003-KEYCHAIN-01 — secrets backend selection. Default `file`;
    /// set to `keychain` after running `neoth credential migrate --to keychain`.
    #[serde(default)]
    pub secrets_backend: SecretsBackend,
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
    /// GOLD-ADAPT-JV-MISC-01 — operator-defined model alias map.
    ///
    /// Declared in `freedom.yaml` as:
    /// ```yaml
    /// models_aliases:
    ///   fast: gpt-5.5
    ///   smart: gpt-4o
    ///   local: qwen3-8b-q8
    /// ```
    ///
    /// Resolved by [`FreedomConfig::resolve_model_alias`] at the config layer
    /// (plain first-match `HashMap` lookup — no catalog access). **Warning:**
    /// if an alias key equals a real model id the alias WILL redirect it; the
    /// config-layer resolver has no catalog visibility to detect the collision.
    /// Use distinct alias names (prefix with `@`, e.g. `@fast`) to avoid
    /// accidental shadowing. Unknown key → passes through verbatim (the
    /// provider sees it as-is and surfaces an error if it is not a valid id).
    /// Alias→alias chains resolve ONE level only; the intermediate name goes to
    /// the provider verbatim.
    #[serde(default)]
    pub models_aliases: crate::models::catalog::ModelAliasMap,
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
    /// Local bind port for the WhatsApp / Meta webhook listener. Defaults
    /// to `None` (listener uses 8443). The listener always binds to
    /// `127.0.0.1` — TLS terminates at the operator's reverse proxy.
    #[serde(default)]
    pub whatsapp_webhook_port: Option<u16>,
    /// Operator-chosen autonomy level — Phase 28b R-23.
    /// Defaults to `Standard` (least surprise: writes inside ~/.neoth/ are
    /// allowed, every shell exec confirms). Old freedom.yaml files without
    /// the field round-trip cleanly via `#[serde(default)]`.
    #[serde(default)]
    pub autonomy: crate::permissions::AutonomyLevel,
    /// Per-action overrides used only when `autonomy: custom` is active.
    /// Missing entries inherit the `Standard` decision exactly; explicit
    /// overrides remain bounded by the irreducible `Full` safety floor.
    #[serde(default)]
    pub custom_autonomy: crate::permissions::CustomAutonomyConfig,
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
    /// Round-3 v0.4 ARCH-07 — LOWKEY skill versioning + eval-session
    /// suppression toggle. Wizard pre-populates with defaults; operators
    /// edit freedom.yaml::skills.disabled_for_eval_sessions = true when
    /// running eval baselines that must not be biased by active skills.
    #[serde(default)]
    pub skills: SkillsConfig,
    /// GOLD-FEAT-07 — moral-core injection kill-switch (`moral_core.enabled`,
    /// default true). When false, `compact_for_injection` returns None so the
    /// operator's authored moral core is NOT injected (without deleting the dir).
    #[serde(default)]
    pub moral_core: crate::config::policy::MoralCoreConfig,
    /// GOLD-ADAPT-JV-MODE-01 — identity-locked persona mode.
    /// `None` = no lock (default). `Some(PersonaMode::LoyalBuddy)` activates
    /// the loyal-buddy persona: identity-anchor injected at position 1 in the
    /// system-prompt stack; ingress sanitizer quarantines persona-override
    /// attempts before they reach the pipeline.
    ///
    /// Set via `freedom.yaml::persona_mode = "loyal_buddy"` or
    /// `neoth profile persona apply loyal-buddy`.
    #[serde(default)]
    pub persona_mode: Option<PersonaMode>,
    /// GOLD-ADOPT-26 — RSS / Atom / JSON-Feed poller. Off by default; an
    /// operator opts in with `feeds.enabled = true` + `feeds.entries`.
    #[serde(default)]
    pub feeds: FeedsConfig,
    /// GOLD-ADOPT-23 P0 — tool-call risk policy gate. GR-080: the two inspectors
    /// have DIFFERENT defaults — the dangerous-command inspector DENIES a Critical
    /// finding by default (`dangerous_commands = deny`), but the egress inspector
    /// is WARN-ONLY by default (`egress.mode = allow`, non-breaking); the operator
    /// opts into `confirm_unknown` / `deny_unknown`. So "deny/confirm" is the
    /// dangerous-command default + the egress OPT-IN, NOT the egress default.
    #[serde(default)]
    pub security: SecurityPolicy,
    /// Round-3 v0.4 ARCH-04 — operator-tunable token cap for the
    /// prompt-bundle pre-flight check. Default 100_000 covers Opus 4.7
    /// + Sonnet 4.6 + Gemini 3 with response headroom; operators on
    /// tighter-context models (Gemini Flash 32k, local Qwen3-4B 8k)
    /// lower this to match.
    #[serde(default)]
    pub tokens: TokensConfig,
    /// GOLD-ADOPT-19 — auto context-compaction for the agentic tool-loop.
    #[serde(default)]
    pub compaction: CompactionConfig,
    /// WS-HR — headroom-style token compression of long tool-result blocks.
    /// Off by default (`enabled = false`) → every block passes through
    /// byte-identical. Distinct from `compaction`: compaction summarises the
    /// WHOLE accumulated prompt with an LLM call; compression shrinks an
    /// INDIVIDUAL block losslessly via CCR with no extra model call.
    #[serde(default)]
    pub compression: CompressionConfig,
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
    /// OH-14 — periodic self-wiki rebuild interval in seconds.
    /// `None` = use the module default (24 hours).
    /// Field unused when `obsidian_vault` is None.
    #[serde(default)]
    pub obsidian_wiki_rebuild_secs: Option<u64>,
    /// OH-14 — path to the source design-doc directory (PLAN/) fed into
    /// the wiki rebuild cron. `None` = check env `NEOTH_PLAN_DIR`; skip
    /// the cron when neither is set. Relative paths are resolved from the
    /// process working directory (repo root under normal daemon invocation).
    #[serde(default)]
    pub obsidian_wiki_source_dir: Option<String>,
    /// GOLD-ADAPT-JV-IMP-05 — enable the Obsidian vault bidirectional reader+writer
    /// cron. Gate: `obsidian_vault` must also be set. Default `false` (opt-in).
    /// When enabled, the cron reads managed notes (source: openclaw-* / neoth-*)
    /// into `idx_groundtruth` and writes operator-attested facts back to the vault
    /// as `NEOTH-Facts/<scope>/<id>.md` notes.
    #[serde(default)]
    pub obsidian_vault_reader_enabled: bool,
    /// GOLD-ADAPT-JV-IMP-05 — cron interval override in seconds.
    /// `None` = use the module default (6 hours).
    /// Field unused when `obsidian_vault_reader_enabled = false`.
    #[serde(default)]
    pub obsidian_vault_reader_secs: Option<u64>,
    /// GOLD-ADAPT-VAULT-PRELOAD-01 — optional curated vault-template directory
    /// copied by `neoth obsidian preload --template`. The importer reads the
    /// template's `preload_manifest.yaml` and keeps raw/restricted corpora out
    /// of normal recall unless explicitly promoted there.
    /// NOTE: L6-PRELOAD-AUTORUN-01 shipped — also consumed at serve startup by
    /// `serve_tasks::spawn_obsidian_preload` (one-shot, idempotent via hash state).
    #[serde(default)]
    pub obsidian_preload_template_dir: Option<String>,
    /// Vault subdirectory for copied preload notes. `None` = the manifest
    /// default, normally `"NEOTH-Preload"`.
    #[serde(default)]
    pub obsidian_preload_subdir: Option<String>,
    /// Additional curated knowledge roots NEOTH can preload/index. Each root
    /// should carry its own manifest or be explicitly operator-reviewed.
    /// NOTE: L6-PRELOAD-AUTORUN-01 shipped — consumed at serve startup by
    /// `serve_tasks::spawn_obsidian_preload`; roots without a manifest are skipped.
    #[serde(default)]
    pub knowledge_preload_dirs: Vec<String>,
    /// GOLD-ADAPT-GRAPH-05 — source directory for the self-map cron.
    /// `graphify update` is run against this directory to produce the
    /// structural graph of the daemon source tree.
    /// `None` = check env `NEOTH_SRC_DIR`; skip when absent.
    #[serde(default)]
    pub self_map_source_dir: Option<String>,
    /// GOLD-ADAPT-GRAPH-05 — self-map rebuild interval in seconds.
    /// `None` = use the module default (24h).
    #[serde(default)]
    pub self_map_interval_secs: Option<u64>,
    /// GOLD-ADAPT-GRAPH-05 — vault subdir for self-map output.
    /// `None` = `"NEOTH-Self"`.
    #[serde(default)]
    pub self_map_subdir: Option<String>,
    /// GOLD-ADAPT-GRAPH-07 — opt-in community naming via the configured provider.
    /// When `true`, each self-map tick runs `python -m graphifyy label .` after
    /// `update`, routing the LLM call through the operator's configured provider
    /// (AnthropicApi / OpenaiApi / OpenaiCompat / ClaudeCli). Local candle
    /// providers (LocalQwen / LocalOuro) expose no HTTP endpoint and are skipped
    /// with a warn. Default `false` — the step costs real API tokens or a
    /// `claude` subprocess call.
    #[serde(default)]
    pub self_map_label_enabled: bool,
    /// GOLD-ADAPT-GRAPH-07 — model to pass to `graphify label`. `None` = let
    /// graphify pick its default (claude-opus-4-5 or gpt-4o depending on backend).
    #[serde(default)]
    pub self_map_label_model: Option<String>,
    /// R-3 Hysteria transport — encrypted egress for provider HTTP
    /// traffic. When `Some`, `neothd serve` spawns the Hysteria
    /// subprocess at startup, probes the local SOCKS5 port, and sets
    /// the `NEOTH_HTTP_PROXY` env var so every `providers::http_client`
    /// build automatically routes through it. Operator-supplied server +
    /// auth lives here; binary lookup falls back to `$PATH` or
    /// `~/.neoth/bin/hysteria` per the transport module's search order.
    #[serde(default)]
    pub hysteria: Option<crate::transport::hysteria::HysteriaConfig>,
    /// TERMIX-01 — SSH local-forward tunnels the daemon establishes at
    /// startup (e.g. to reach a provider / DB behind a bastion). Each
    /// entry binds `127.0.0.1:<local_port>` and forwards through the SSH
    /// endpoint (jump-chain aware, host-key TOFU). Empty = off. Runtime
    /// requires the `ssh-tunnel` build feature; a slim build parses +
    /// preserves this block and warns that tunnels are not compiled in.
    #[serde(default)]
    pub ssh_tunnels: Vec<crate::transport::ssh_config::SshTunnelConfig>,
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
    /// Daemon self-update policy. `enabled: false` keeps both background
    /// check and staging silent. Check-only mode probes the configured release
    /// ring; `auto_apply: true` additionally permits verified stage-and-notify
    /// at Elevated/Full autonomy. The running binary is replaced only by the
    /// operator-initiated `neoth update --self --apply` path.
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
    /// GOLD-TASK-01 — general-task pipeline knobs.
    /// Master gate: `task_engine.decompose_non_coding` (default `false`).
    /// When `false`, zero behaviour change to the channel pipeline.
    /// When `true`, high-confidence non-coding prompts (reminders,
    /// scheduling, research, delegation) from channels are routed into
    /// the kanban decomposer and land in `Backlog` status. Dispatch
    /// stays operator-driven (`neoth code --run-pending`). Requires
    /// `autonomy >= Standard`.
    #[serde(default)]
    pub task_engine: TaskEngineConfig,
    /// NOOB-UX-3 (Session 19, 2026-05-21): operator-facing
    /// plugin runtime gates. Pairs with the cargo build-time
    /// `wasm-plugin-host` feature per the
    /// `neoth-features-default-on-runtime-toggle` rule —
    /// release builds compile the feature ON, this field
    /// lets operators flip it OFF without recompiling.
    #[serde(default)]
    pub plugins: PluginsConfig,
    /// EL-01 follow-up (Session 26): operator-tunable interval for the
    /// daemon's doctor cron loop. Default mirrors the hardcoded
    /// `DEFAULT_CRON_INTERVAL_SECS = 3600` (1h tick). Operators who
    /// want the doctor to run more aggressively or want to silence
    /// the tick entirely flip this without recompiling.
    #[serde(default)]
    pub doctor: DoctorConfig,
    /// U-04 follow-up (Session 26): operator-tunable interval for the
    /// three updater cron lanes (neoth_self, cli_version, skill_plugin).
    /// Default mirrors the hardcoded `DEFAULT_UPDATER_INTERVAL_SECS =
    /// 6h tick`. All three lanes share the interval today; per-lane
    /// override lands when an operator asks for it.
    #[serde(default)]
    pub updater: UpdaterConfig,
    /// MV-01b prereq #3 — process-supervisor install state. When the
    /// wizard installs a supervisor (systemd user unit / launchd agent /
    /// Windows Task Scheduler) the daemon can self-restart so unattended
    /// self-update actually activates the new binary. Off by default;
    /// the wizard's supervisor step writes it. `enabled = false` means
    /// self-update degrades to stage-and-notify (no auto-restart).
    #[serde(default)]
    pub supervisor: SupervisorConfig,
    /// AR-03 (Session 24) — per-stage hook chain composition. Keyed
    /// by stage name (`"pre_pipeline"` / `"pre_provider_call"` / etc).
    /// Today carries one field, `fail_fast`, that flips the
    /// dispatcher's regex-compile-error behaviour from skip-and-warn
    /// to Block-the-stage. Operator-defined per-stage policy lives
    /// here so a future `priority_floor` / `max_chain_depth` field
    /// lands in the same shape without another schema bump.
    ///
    /// Empty by default — every stage keeps the pre-AR-03 lenient
    /// behaviour (regex errors skip the hook + continue) unless the
    /// operator opts that stage into `fail_fast = true`.
    #[serde(default)]
    pub hook_chain: std::collections::HashMap<String, HookChainConfig>,
    /// R-02 Phase 4c (Session 22): nightly dreaming pipeline gate.
    /// Off by default — operator opts in via `dreaming.enabled: true`.
    /// When on, `cli::dreaming_task::spawn` runs on
    /// `interval_secs` (default 24h) over a window of `window_secs`
    /// (default 24h) capped at `max_events` (default 500). When an
    /// `inference.embedding_provider` is also wired, the task uses
    /// `compose_dreams_with_embeddings` for cosine-clustered themes;
    /// otherwise it falls back to deterministic compose_dream
    /// (matches L-07 `allow_cloud_fallback: false` safe-default).
    #[serde(default)]
    pub dreaming: DreamingConfig,

    /// A3-01 — `neoth transfer export` hard size caps. A memory export can grow
    /// large; these bound an accidental runaway (event count + plaintext bytes
    /// before encryption + final bundle bytes). Defaults: 1000 / 8 MiB / 16 MiB.
    #[serde(default)]
    pub transfer: TransferConfig,

    /// EM-01b / PL-05b — inbound email knobs. The LLM threat tie-breaker is
    /// off by default (it spends an LLM call per borderline email — see
    /// `EmailConfig::llm_tiebreak`).
    #[serde(default)]
    pub email: EmailConfig,

    /// CH-13 / F4-01 — Ecology self-adaptation layer. The auto-scheduler is off
    /// by default; the read-only `neoth ecology correlation` scan works
    /// regardless (it's a diagnostic report).
    #[serde(default)]
    pub ecology: EcologyConfig,

    /// GM-01 — agentic tool-use turn budget. `max_turns` is the operator-tunable
    /// hard ceiling on MCP dispatch-loop iterations (was a hardcoded 5).
    #[serde(default)]
    pub goal: GoalConfig,

    /// GOLD-LOOP-01 — multi-round autonomous loop engine. Disabled by default;
    /// opt in via `loop_config.enabled: true` in freedom.yaml. When enabled
    /// the loop engine wraps `run_mcp_dispatch_loop` with outer rounds,
    /// stop-condition verification, and optional self-reflect refine passes.
    #[serde(default)]
    pub loop_config: LoopConfig,

    /// GOLD-ADOPT-18 — subdirectory-hint auto-injection toggle (default ON).
    #[serde(default)]
    pub hints: HintsConfig,

    /// OMI-MULTIMODAL-01 — Developer API conversation import plus local native
    /// PCM/media ingest. Off by default. Legacy mode remains local-only; a
    /// public Developer API endpoint needs the explicit cloud-egress opt-in.
    #[serde(default)]
    pub omi: OmiConfig,

    /// MM-01b/02b/03b — cloud media (STT / TTS / vision / video frames). ALL
    /// default OFF: audio, images, and video are more sensitive than text
    /// prompts, so sending them to a cloud provider is an explicit opt-in. Each
    /// flag is surfaced as its own safe-mode rail ("this media leaves your
    /// device").
    #[serde(default)]
    pub media: MediaConfig,

    /// EM-02b — CalDAV calendar writes (`neoth calendar add`). A power surface
    /// (external network mutation): a kill switch the operator can flip without
    /// touching credentials. Default ON (the surface ships usable), but it is
    /// ALSO gated by the autonomy/consent `ExternalTaskWrite` path + audited
    /// (`0xCA CALENDAR_WRITE`). Surfaced as the `calendar_writes` safe-mode rail.
    #[serde(default)]
    pub calendar: CalendarConfig,

    /// SPEC-11 — outbound live-delivery (send-then-edit) rate limiting. Bounds
    /// how often NEOTH edits a streaming message so it can't trip Slack/Telegram/
    /// Discord edit rate limits. Surfaced as the `live_delivery_edits` rail.
    #[serde(default)]
    pub live_delivery: LiveDeliveryConfig,

    /// KF-05 — channel-acceptance Hebbian learning scope. Bounds WHOSE replies
    /// move the recall-ranking weights so a non-operator can't poison them.
    /// Default `operator_only`. Surfaced as the `channel_weight_learning` rail.
    #[serde(default)]
    pub channel_weights: ChannelWeightsConfig,

    /// EL-02 — arXiv topic-feed periodic ingest. Off by default; opt in
    /// via `arxiv.enabled: true` + a non-empty `arxiv.topics` list. When
    /// active, the daemon runs each topic query on a cadence (default 6h),
    /// optionally LLM-summarises each abstract, and lands the result in
    /// the ctx knowledge store keyed `arxiv:<id>`.
    #[serde(default)]
    pub arxiv: ArxivIngestConfig,

    /// GOLD-ADAPT-MEM-16 — ArXiv skill-learning cron. Off by default. When
    /// `arxiv_skill_scan.enabled: true` and a provider is wired, the daemon
    /// scans `topics` (default cs.AI/cs.LG) on a 6h cadence, extracts 1-3
    /// actionable takeaways per paper via LLM, and writes each to
    /// `idx_groundtruth` (`source = "arxiv-skill-scan"`, `scope =
    /// "arxiv-learning"`). Facts surface into recall/council automatically.
    #[serde(default)]
    pub arxiv_skill_scan: ArxivSkillScanConfig,

    /// C-16 (Session 21) — operator opt-in for proactive channel
    /// messaging. When `enabled = true`, the daemon's cron + the
    /// future `send_proactive()` impl (C-11) MAY post outbound
    /// messages on their own (briefings, follow-ups). Default
    /// `false` per the AGENTER hard rule "no destructive auto-
    /// action without operator GO per command".
    #[serde(default)]
    pub proactive: ProactiveConfig,
    /// HO-09 / V1x-03 — profile baseline drift alerting. When
    /// `enabled = true`, a drift-report whose ratio exceeds `threshold`
    /// is surfaced as an alert (CLI today; daemon cron is a follow-on).
    /// Default OFF.
    #[serde(default)]
    pub drift_alert: DriftAlertConfig,
    /// GOLD-ADAPT-JV-PRO-02 — token-anomaly security tripwire cron. Default OFF.
    #[serde(default)]
    pub token_anomaly: TokenAnomalyConfig,
    /// GOLD-ADAPT-VIEW-05 — session-health / outcome cron. Default OFF.
    #[serde(default)]
    pub session_health: SessionHealthConfig,
    /// GOLD-ADAPT-ODY-20 — auto-skill extraction from MCP-loop agent runs.
    /// After a turn with ≥ `min_tool_calls` tool-calls, a single provider call
    /// distils a `{title,steps,tags,confidence}` block; extractions above
    /// `confidence_threshold` that are computer-executable are staged in the
    /// proactive review queue (`~/.neoth/proposals/`). Default OFF (opt-in).
    #[serde(default)]
    pub auto_skill_extract: AutoSkillExtractConfig,

    /// GOLD-ADAPT-ODY-21 — outbound webhook manager cron. Tail-reads new WAL
    /// frames of types `0x9A` (session.created), `0x21` (chat.completed),
    /// `0x01`/`0x32` (chat.message) and fans them out to registered HTTPS
    /// endpoints as HMAC-SHA256-signed POSTs. Emits `0x08`/`0x09`/`0x0A`
    /// audit frames. Default OFF — opt-in via `webhook_manager.enabled: true`.
    #[serde(default)]
    pub webhook_manager: crate::config::automation::WebhookManagerConfig,
    /// ADV-14 — longitudinal recall-regression anchor cron. When `enabled`,
    /// the daemon weekly re-asks the anchor queries, re-embeds the answers,
    /// and emits `0x3F REGRESSION_ALERT` for any whose cosine to the cutover
    /// anchor vector drops below `threshold`. Default OFF.
    #[serde(default)]
    pub regression_anchor: RegressionAnchorConfig,
    /// MONITOR-03 / RECALL-METER-01 — recall-p95 latency alert cron. When
    /// `enabled`, the daemon reads the recent `idx_recall_latency` window (one
    /// sample per `neoth recall`) and emits `0x4B RECALL_LATENCY_ALERT` when
    /// the p95 exceeds `p95_threshold_ms`. Default OFF.
    #[serde(default)]
    pub recall_latency: RecallLatencyConfig,
    /// SL-03 — ResourcePressureWatcher cron. When `enabled`, the daemon
    /// polls live GPU VRAM + emits `0x47 RESOURCE_PRESSURE_ALERT` on a
    /// breach of `vram_threshold_pct`. Default OFF; a no-op on non-GPU /
    /// non-NVIDIA hosts.
    #[serde(default)]
    pub resource_watch: ResourceWatchConfig,
    /// GOLD-ADAPT-RMAS-01 — optional RecursiveMAS latent-recursion sidecar
    /// for council deliberation. Default OFF; runtime-gated on VRAM +
    /// operator-installed checkout (`providers::recursive_mas`), provider
    /// adapter compile-gated behind the `recursive-mas` Cargo feature.
    #[serde(default)]
    pub recursive_mas: RecursiveMasConfig,
    /// GOLD-FEAT-03b — self-wiki background rebuild cron. When `enabled`,
    /// periodically re-renders the in-binary capability map (+ the PLAN/
    /// design corpus on dev checkouts) into the operator's Obsidian
    /// vault and refreshes the ground-truth pointers. Default ON (local-only;
    /// signed release baseline + update-safe operator overlays).
    #[serde(default)]
    pub self_wiki: SelfWikiConfig,
    /// HO-07 — neoth-monitor alerting sidecar cron. When `enabled`, the
    /// daemon polls WAL integrity, crash.log, and channel activity and
    /// emits `0x48 WAL_CRC_ALERT` / `0x49 CRASH_LOG_ALERT` /
    /// `0x4A CHANNEL_SILENCE_ALERT` on anomalies. Default OFF (opt-in).
    #[serde(default)]
    pub monitor: MonitorConfig,
    /// GOLD-FEAT-09 — daemon watchdog / auto-recovery cron. When `enabled`,
    /// the daemon probes supervised local services (n8n / Ollama) every
    /// `interval_secs` and restarts a service that has been down for
    /// `consecutive_failures_before_restart` ticks (only at `Elevated`+
    /// autonomy), emitting `0x5F WATCHDOG_RESTART`. Default OFF (opt-in).
    #[serde(default)]
    pub watchdog: WatchdogConfig,
    /// SPEC-05 — passive user-adaptation engine. When `enabled = true`,
    /// a daemon cron (`daemon::profile_adapt_cron`) re-aggregates the
    /// behavioural snapshot from the WAL every `interval_secs`, runs the
    /// 5 passive estimators + `propose_adjustments`, and queues any new
    /// self-dev PROPOSALS (operator reviews via `neoth self-dev review`;
    /// nothing is auto-applied). Default OFF — opt-in to proactive
    /// adaptation, matching the `drift_alert` precedent.
    #[serde(default)]
    pub profile_adapt: ProfileAdaptConfig,
    /// G-01 (first slice) — passive inactivity-nudge cron. Default OFF
    /// (opt-in; a proactive ping is intrusive). When enabled, the daemon
    /// enqueues one "still there?" nudge after `inactivity_gap_secs` of
    /// quiet (deduped per UTC day).
    #[serde(default)]
    pub pattern_cron: PatternCronConfig,
    /// GOLD-ADAPT-ODY-07 — background-job detach monitor. Scans
    /// `~/.neoth/bgjobs/` every `bg_monitor.interval_secs` for completed
    /// detached subprocess jobs and fires auto-continue callbacks. Always-on
    /// infrastructure: default `interval_secs = 5`. Set `interval_secs: 0`
    /// to disable entirely (no task spawns, no global registry).
    #[serde(default)]
    pub bg_monitor: BgMonitorConfig,
    /// GOLD-ADAPT-JV-MEM-16 — guidance-block snapshot refresh cron.
    /// When `enabled`, the daemon periodically writes
    /// `~/.neoth/guidance_snapshot.json` with freshness + 24h-signal counts
    /// so `build_prompt_bundle` can inject richer session context. Default OFF.
    #[serde(default)]
    pub guidance_cron: GuidanceCronConfig,
    /// NN-MEM-02 — weekly 5-dimensional synthesis pattern-recognition cron.
    /// When `enabled`, performs a weekly pass over `idx_episode`,
    /// `idx_groundtruth`, and `idx_contradictions`, producing a structured
    /// synthesis note written as a `idx_groundtruth` row and optionally to
    /// `~/.neoth/synthesis/YYYY-WW.md`. Default OFF (WAL-free, opt-in).
    #[serde(default)]
    pub synthesis_cron: SynthesisCronConfig,
    /// GOLD-FEAT-11 — LLM-generated check-in cron. When `enabled`, detects
    /// inactivity gaps in `views.db` and enqueues an LLM-generated check-in
    /// nudge once per UTC day. Default OFF (provider call per tick, opt-in).
    #[serde(default)]
    pub checkin_cron: CheckinCronConfig,
    /// GOLD-ADAPT-JV-PAPERLESS-01 — email→Paperless ingest cron. When `enabled`,
    /// polls IMAP on `interval_secs` cadence, runs the content scanner,
    /// quarantines HIGH findings, and uploads clean documents to Paperless-NGX
    /// + writes Obsidian notes. Default OFF. Credentials in `credentials.yaml`.
    #[serde(default)]
    pub email_ingest_cron: EmailIngestCronConfig,
    /// GOLD-FEAT-11 — skill-curator cron. When `enabled`, auto-promotes mature
    /// (`>= min_age_days`) operator-accepted skill proposals from
    /// `~/.neoth/proposals/` to `~/.neoth/skills/`. Default OFF.
    #[serde(default)]
    pub skill_curator: SkillCuratorConfig,
    /// JV-SELF-02 — AMEM4Rec consolidation sweep. When `enabled`, a
    /// background cron (default 6h) clusters hot-tier embeddings by cosine
    /// similarity ≥ `cosine_threshold`, boosts member importance (cap
    /// `importance_boost_cap`), and merges mature clusters into
    /// `idx_groundtruth`. Emits WAL `0x9D`/`0x9E`. Default OFF.
    #[serde(default)]
    pub consolidation_sweep: ConsolidationSweepConfig,
    /// GOLD-ADAPT-JV-SELF-03 — auto-builder signal collector. When `enabled`,
    /// a daily cron scans episode topics, ground-truth lessons, and the
    /// SkillOpt ledger to classify improvement signals (`PatchSkill`,
    /// `PromptEdit`, `ConfigChange`, `Escalate`) and writes them atomically
    /// to `~/.neoth/self_improvement_signals.json` for HERMES-06. Emits WAL
    /// `0xBE`/`0xBF`. Default OFF.
    #[serde(default)]
    pub self_improvement_collector: crate::config::automation::SelfImprovementCollectorConfig,
    /// NN-MEM-06 — daily contradiction auto-resolution cron. When `enabled`,
    /// auto-resolves the `idx_contradictions` backlog: temporal-supersede
    /// (newer fact wins) · semantic-equiv (Jaccard>=0.90 merge) · human-review
    /// queue for genuine conflicts. Default OFF.
    #[serde(default)]
    pub contradiction_resolve:
        crate::daemon::contradiction_resolve_cron::ContradictionResolveCronConfig,
    /// SPEC-03b — per-provider HTTP-429 fallback chain. Empty (default) =
    /// no fallback, pre-SPEC-03b behaviour preserved exactly.
    #[serde(default)]
    pub fallback: FallbackConfig,
    /// E-18 Workstream N (Session 22) — operator opt-in for
    /// anonymous version-check telemetry. Default OFF
    /// (`enabled: false`, `endpoint: None`). When on, the daemon
    /// POSTs `{neoth_version, os, arch, anonymous_id}` once per
    /// boot to `endpoint` or [`crate::telemetry::DEFAULT_TELEMETRY_ENDPOINT`].
    /// CLI surface: `neoth telemetry on/off/preview/send-now/status`.
    #[serde(default)]
    pub telemetry: crate::telemetry::TelemetryConfig,

    /// N-3 Workstream D (Session 23) — operator opt-in for the
    /// localhost HTTP API n8n workflows talk to. Default OFF: every
    /// bootstrap workflow (`daily_summary`, `morning_brief`,
    /// `weekly_stats`) ships INACTIVE so a fresh install never serves
    /// HTTP without explicit operator opt-in. Bind is loopback-only;
    /// bearer token is a 43-char base64url-NOPAD secret stored at
    /// `~/.neoth/n8n_api_token` mode-0600.
    #[serde(default)]
    pub n8n_api: N8nApiConfig,
    /// GOLD-ADAPT-HERMES-08 — SSE endpoint for live kanban events.
    /// Streams `idx_kanban_task_event` rows + real-time broadcast to
    /// browser/GUI/n8n EventSource clients. Off by default; operator
    /// opts in via `kanban_sse.enabled: true` + optional `port` override.
    #[serde(default)]
    pub kanban_sse: KanbanSseConfig,
    /// GOLD-ADAPT-AWE-PROV-01 — OpenRouter-compat `/v1/models` serve adapter.
    /// Binds `127.0.0.1:9746` (loopback only). Lets Cline, Continue, OpenCode,
    /// Goose and any other OpenRouter-aware coding assistant discover NEOTH's
    /// models catalog without bespoke per-client config. Default OFF (`enabled:
    /// false`). `/v1/models` is unauthenticated (read-only; loopback is the
    /// security boundary). Port defaults to 9746.
    #[serde(default)]
    pub oai_serve: OaiServeConfig,
    /// GOLD-ADAPT-ODY-24 — Companion LAN pairing server. A phone scans a QR
    /// code (displayed at `neoth init` step 6k or via `neoth companion qr`)
    /// and mints a chat-scoped bearer token via `POST /api/v1/companion/pair`.
    /// Loopback-only; default OFF (`enabled: false`). Port defaults to 9745.
    #[serde(default)]
    pub companion: CompanionConfig,
    /// GOLD-ADAPT-ODY-26 — session auto-sort cron. When `enabled`, a daily
    /// background cron prunes throwaway [`HindsightCard`]s and calls an LLM
    /// to group remaining sessions into topic folders (persisted as
    /// `"folder:<name>"` entries in `top_topics`). Default OFF (LLM call per
    /// tick, opt-in). `dry_run: true` simulates without writing.
    ///
    /// [`HindsightCard`]: crate::memory::hindsight::HindsightCard
    #[serde(default)]
    pub session_sort_cron: crate::config::automation::SessionSortCronConfig,
    /// PC-01 — OS-tool surface (file/folder access). Default DENY-ALL: an
    /// empty `tools.os.allowed_paths` means NEOTH can read no operator file.
    /// Operators at `elevated`/`full` autonomy opt in by listing absolute
    /// path prefixes. NO registry / system-paths / process-kill — those are
    /// not representable. Every gated read/deny lands in the WAL
    /// (`0xA8`/`0xA9`).
    #[serde(default)]
    pub tools: ToolsConfig,
    /// SL-00 — fully typed cluster identity, transport, peer seeds, mDNS and
    /// announce policy. `name` is the PUBLIC rendezvous label that derives the
    /// Hyperswarm DHT topic + the mDNS service name (it is NOT a secret — the
    /// DHT topic is public; the shared `cluster_passphrase` in credentials.yaml
    /// is what authenticates). Empty `name` = no cluster identity = every
    /// transport stays inert (fail-closed).
    #[serde(default)]
    pub cluster: ClusterConfig,
    /// GOLD-FEAT-06 — local/peer resource snapshot cadence and dashboard
    /// freshness policy. Always parsed even in builds without the optional
    /// cluster transport so one freedom.yaml remains portable across builds.
    #[serde(default)]
    pub swarm: SwarmConfig,
    /// AUDIT-RPC-01 — loopback audit-RPC listener. When the daemon owns the
    /// single WAL writer, one-shot CLIs (`neoth os launch`, `fs`, `lease`, …)
    /// can't write their own audit frames; with this enabled they forward an
    /// authenticated audit intent to the running daemon over `127.0.0.1:<auto>`
    /// (bearer-token + loopback-only + a compile-time event-type allowlist), so
    /// every gated action stays audited even while `neoth serve` is up.
    /// Default OFF at the struct level (source builds stay opt-in); the wizard
    /// turns it on so noob operators get audited one-shots automatically.
    #[serde(default)]
    pub audit_rpc: AuditRpcConfig,
    /// GOLD-WIRE-07 — memory backend tuning. Today: the similarity-recall
    /// vector-index backend (`brute_force` default | `hnsw`). Default keeps the
    /// pre-WIRE-07 O(N) scan so existing installs see zero behaviour change.
    #[serde(default)]
    pub memory: MemoryConfig,

    /// GOLD-ADAPT-ODY-17 — deep-research engine iteration budget. Caps how many
    /// search→read→synthesize rounds are allowed per `/research` invocation.
    /// Default `None` → engine uses its compiled-in ceiling (5 rounds).
    /// Operators on paid search APIs lower this to control per-query cost.
    #[serde(default)]
    pub deep_research: DeepResearchConfig,

    /// GOLD-ADAPT-OH-03 — set to `true` by `write_config` when at least one
    /// channel/integration was configured during onboarding. `neoth serve` bails
    /// at boot if `false` and the secondary credential probe also finds nothing.
    /// Idempotent: re-running `neoth init --force` with a channel re-sets it `true`.
    /// Old freedom.yaml files (missing field) default to `false`; the secondary
    /// probe in `check_onboarding_complete` passes them through when credentials.yaml
    /// already has a channel configured.
    #[serde(default)]
    pub onboarding_complete: bool,

    /// GOLD-ADAPT-OH-11 — set to `false` by `write_config` at wizard completion;
    /// flipped to `true` by `cli/chat.rs::run_post_reply_pipelines` after the
    /// operator's first successful chat turn. Gates a one-time first-chat hint in
    /// the CLI ("Run `neoth doctor` to check status…").
    /// Old freedom.yaml files (missing field) default to `true` via
    /// `#[serde(default = "default_true")]` so existing operators are NOT shown
    /// the hint retroactively — only fresh wizard runs see it.
    #[serde(default = "default_true")]
    pub chat_onboarding_completed: bool,

    /// GOLD-ADAPT-ODY-28 — IANA timezone name for user-local TZ context injection.
    /// When set, every provider turn prepends a concise time-context block to the
    /// user message so the LLM can anchor scheduling references correctly.
    /// Env override: `NEOTH_TZ` takes priority over this field.
    /// Example: `"Europe/Berlin"`, `"America/New_York"`. `None` = no inject (default).
    ///
    /// The block is placed in the USER-role message (not system prompt) so the
    /// prefix-cached system block is never polluted. The user turn already busts
    /// prefix cache on every message, so per-turn time content adds no cache cost.
    #[serde(default)]
    pub user_tz: Option<String>,

    /// GOLD-ADAPT-LOWKEY-08 — Dynamic-persona MDS tone modifier.
    /// When `enabled`, classifies input intensity per-turn and augments the
    /// active `persona_override` with a matching tone directive (e.g.
    /// "keep answer short, skip preamble" for a High-intensity turn).
    /// Default OFF (`enabled: false`) — an explicit opt-in so operators who
    /// didn't configure a `tweaks.toml::persona_override` don't get surprise
    /// tone changes. Following `mif_enabled` / `self_score_enabled` precedent.
    #[serde(default)]
    pub tone_modifier: ToneModifierConfig,

    /// GOLD-ADOPT-17 — mid-turn schema-driven elicitation gate.
    /// When `enabled` (default `true`), the MCP dispatch loop intercepts
    /// tool results that carry an `elicitation_request` key and presents
    /// the operator with a structured CLI form before continuing. Operators
    /// who want fully non-interactive operation (CI pipelines, scripted
    /// chat) flip `enabled: false`. Only active on the TTY path (`neoth
    /// chat`); the channel / serve-pipeline path always behaves as disabled
    /// regardless of this field.
    #[serde(default)]
    pub elicitation: ElicitationConfig,

    /// GOLD-DELTA-01 — Babel-Index observer configuration (`babel:` block).
    /// The observer is default-ON and strictly local; `babel.federate`
    /// (default OFF) is the only egress switch and is additionally
    /// consent-gated at runtime (AutonomyLevel >= Elevated). See
    /// `analytics/babel/config.rs`.
    #[serde(default)]
    pub babel: BabelConfig,

    /// GOLD-ADAPT-JV-MODE-02 — sovereign-buddy operating mode flag.
    ///
    /// Set ONLY via `neoth autonomy sovereign --enable` (typed-phrase consent
    /// ceremony, TTY-only, no GUI bypass). Cleared by `neoth autonomy gated` or
    /// `neoth autonomy sovereign --disable` (no ceremony required for disable).
    ///
    /// **This flag alone changes nothing.** Gates throughout the codebase MUST
    /// call [`FreedomConfig::sovereign_active`] which returns `true` ONLY when
    /// BOTH this field is `true` AND `autonomy == AutonomyLevel::Full`. A
    /// sovereign_buddy flag on a non-Full autonomy level is an inert noop.
    ///
    /// WAL audit: activation is recorded via the three-frame sequence
    /// `0xA2 LEVEL_ELEVATED + 0xDD SUDOMODE_PRESET_APPLIED + 0xD0 CONFIG_RELOADED`
    /// (with `changed_fields` including `"sovereign_buddy"`). No new WAL event
    /// code is used — the byte space is exhausted (255/256 codes assigned).
    #[serde(default)]
    pub sovereign_buddy: bool,

    /// GOLD-ADAPT-JV-MODE-04 — self-activation configuration.
    ///
    /// Governs whether NEOTH may toggle its own skills or register new cron
    /// jobs under sovereign mode. All subfields default to OFF; the operator
    /// must explicitly populate `skill_allowlist` and set `enabled: true`
    /// before any self-toggle is accepted.
    ///
    /// See [`SelfActivationConfig`] for the full field docs and safety
    /// invariants. The gate chain is:
    ///   1. `self_activation.enabled` must be `true` (else immediate Deny).
    ///   2. `skills.disabled` must NOT contain the target skill id (else Err
    ///      before the permissions gate — operator veto is unconditional).
    ///   3. Permissions gate: `Action::SelfSkillToggle` / `Action::SelfCronRegister`
    ///      must Allow or Confirm (see `permissions::evaluate`).
    ///   4. For skill toggles: `skill_allowlist` must contain the id, else Confirm.
    ///   5. For cron: `--confirm-cron` flag required every time.
    #[serde(default)]
    pub self_activation: crate::config::automation::SelfActivationConfig,
}

/// GOLD-ADAPT-OH-11 — serde default returning `true` so that existing
/// `freedom.yaml` files that predate this field treat chat as already
/// introduced (no retroactive hint spam for long-running operators).
fn default_true() -> bool {
    true
}

/// GOLD-ADOPT-17 — runtime gate for schema-driven mid-turn elicitation.
///
/// Lives in `freedom.yaml::elicitation`. Example operator opt-out:
/// ```yaml
/// elicitation:
///   enabled: false
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ElicitationConfig {
    /// Master kill-switch. Default `true` — opt-out for non-interactive
    /// environments (CI, scripted pipelines).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for ElicitationConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// GOLD-ADAPT-LOWKEY-08 — kill-switch + threshold for the MDS tone modifier.
///
/// Lives in `freedom.yaml::tone_modifier`. Example operator opt-in:
/// ```yaml
/// tone_modifier:
///   enabled: true
///   min_intensity: medium   # or high / urgent
/// ```
///
/// `min_intensity` is the lowest `InputIntensity` band that triggers
/// augmentation. Default `Medium` means Low prompts are always a no-op
/// and every working prompt gets the direct-tone hint. Operators who
/// want the modifier only on urgent prompts set `min_intensity: urgent`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ToneModifierConfig {
    /// Master kill-switch. Default `false` — operator must opt in.
    pub enabled: bool,
    /// Minimum intensity that triggers tone augmentation. Default `Medium`.
    pub min_intensity: crate::council::mds_tone::InputIntensity,
}

impl Default for ToneModifierConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_intensity: crate::council::mds_tone::InputIntensity::Medium,
        }
    }
}

/// AUDIT-RPC-01 — audit-RPC listener config. Default: disabled (the daemon
/// binds no audit-RPC port unless this is flipped on).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct AuditRpcConfig {
    /// Bind the loopback audit-RPC listener. No port field — the daemon always
    /// binds `127.0.0.1:0` (OS-assigned) and advertises the chosen port in the
    /// `~/.neoth/audit_rpc.port` sidecar so one-shot CLIs can find it.
    pub enabled: bool,

    /// Compliance fail-closed switch. When `true` AND a daemon owns the WAL, a
    /// one-shot permission action (OS file read/write, app launch, autonomy
    /// change) is REFUSED if the daemon's audit-RPC listener is unreachable —
    /// so the action never happens without an audit record. Default `false`
    /// (best-effort: the action proceeds and the frame is dropped if the
    /// listener is down). Pairs with `enabled`: turning this on without the
    /// listener enabled would refuse every one-shot while a daemon is live.
    pub required_for_oneshot_permission_events: bool,
}

/// Default TCP port shared by cluster mDNS announces and Tailscale probes.
pub const DEFAULT_CLUSTER_LISTEN_PORT: u16 = 49_737;

/// Wire carrier for authenticated cluster gossip and WAL sync.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClusterTransport {
    /// peeroxide Hyperswarm (the shipped default).
    #[default]
    Peeroxide,
    /// iroh QUIC (requires the `cluster-iroh` build feature).
    Iroh,
}

/// mDNS discovery switch. Default-on discovery is still privacy-gated by
/// [`ClusterAnnouncePolicy`], whose default trusted-SSID set is empty.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ClusterMdnsConfig {
    pub enabled: bool,
}

impl Default for ClusterMdnsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Operator-controlled LAN announcement policy.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ClusterAnnouncePolicy {
    /// Permit mDNS announcement on any reachable network. Default false.
    pub announce_on_untrusted_wifi: bool,
    /// Case-sensitive SSIDs on which mDNS announcement is permitted.
    pub trusted_ssids: Vec<String>,
}

/// SL-00 cluster identity and transport config. Default: inert cluster,
/// peeroxide selected, no peers, and privacy-gated mDNS discovery.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ClusterConfig {
    /// Public cluster rendezvous name — derives the DHT topic + mDNS service.
    /// `None`/empty = this node has no cluster identity (transport inert).
    pub name: Option<String>,
    /// SL-00(1b) transport master-switch. **Default `false`.** Even with a
    /// full identity configured, the Hyperswarm DHT transport stays inert
    /// until the operator explicitly flips this on. The daemon NEVER
    /// announces on the public DHT while this is `false` — the safety gate
    /// against an accidental cluster join on a fresh install.
    pub enabled: bool,
    /// Authenticated gossip/WAL-sync carrier.
    pub transport: ClusterTransport,
    /// iroh endpoint ids used to bootstrap the first outbound contacts.
    pub peers: Vec<String>,
    /// LAN discovery switch (announcement remains subject to `policy`).
    pub mdns: ClusterMdnsConfig,
    /// LAN privacy policy used by daemon, CLI and doctor alike.
    pub policy: ClusterAnnouncePolicy,
    /// Shared mDNS/Tailscale probe port. Zero is invalid.
    pub listen_port: u16,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            name: None,
            enabled: false,
            transport: ClusterTransport::Peeroxide,
            peers: Vec::new(),
            mdns: ClusterMdnsConfig::default(),
            policy: ClusterAnnouncePolicy::default(),
            listen_port: DEFAULT_CLUSTER_LISTEN_PORT,
        }
    }
}

impl ClusterConfig {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.listen_port == 0 {
            return Err("listen_port must be greater than zero".to_string());
        }
        if self.peers.iter().any(|peer| peer.trim().is_empty()) {
            return Err("peers must not contain empty endpoint ids".to_string());
        }
        if self.enabled
            && self
                .name
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .is_none()
        {
            return Err("name is required when cluster.enabled is true".to_string());
        }
        if self.enabled && !cfg!(feature = "cluster") {
            return Err(
                "cluster.enabled is true, but this binary was built without the `cluster` feature"
                    .to_string(),
            );
        }
        if self.enabled
            && self.transport == ClusterTransport::Iroh
            && !cfg!(feature = "cluster-iroh")
        {
            return Err(
                "cluster.transport is `iroh`, but this binary was built without the `cluster-iroh` feature"
                    .to_string(),
            );
        }
        #[cfg(feature = "cluster-iroh")]
        if self.transport == ClusterTransport::Iroh {
            for peer in &self.peers {
                peer.trim().parse::<iroh::EndpointId>().map_err(|error| {
                    format!("invalid iroh endpoint id `{peer}` in cluster.peers: {error}")
                })?;
            }
        }
        Ok(())
    }
}

/// GOLD-FEAT-06 resource-snapshot and swarm-dashboard policy.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct SwarmConfig {
    /// Emit local resource snapshots when the cluster feature is compiled in.
    pub enabled: bool,
    /// Seconds between local CPU/RAM/VRAM samples.
    pub interval_secs: u64,
    /// Seconds after which a dashboard snapshot is stale.
    pub stale_after_secs: i64,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            stale_after_secs: 300,
        }
    }
}

impl SwarmConfig {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.interval_secs == 0 {
            return Err("interval_secs must be greater than zero".to_string());
        }
        if self.stale_after_secs <= 0 {
            return Err("stale_after_secs must be greater than zero".to_string());
        }
        Ok(())
    }

    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs)
    }
}

/// GOLD-ADAPT-ODY-17 — operator-tunable iteration budget for the deep-research engine.
/// All fields are `Option<T>` so an absent `deep_research:` block in freedom.yaml
/// round-trips without error; `None` fields use the engine's compiled-in defaults.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct DeepResearchConfig {
    /// Maximum search→read→synthesize rounds per `/research` call.
    /// Default: 5. Operators on paid search APIs lower this to bound cost.
    pub max_rounds: Option<u8>,
    /// How many search results to request per query (1–20).
    /// Default: 5.
    pub results_per_query: Option<usize>,
    /// How many search-hit pages to fetch and goal-extract per round.
    /// Default: 3. Higher values raise quality at the cost of LLM calls.
    pub pages_per_round: Option<usize>,
}

#[cfg(test)]
mod inline_tests;

impl FreedomConfig {
    /// Immutable point-in-time autonomy policy for one permission decision.
    ///
    /// Reload-aware callers must obtain a fresh snapshot from their active
    /// [`crate::config::reload::ReloadController`] at each side-effect leaf.
    pub fn autonomy_policy(&self) -> crate::permissions::AutonomyPolicySnapshot {
        crate::permissions::AutonomyPolicySnapshot::new(self.autonomy, &self.custom_autonomy)
    }

    /// AR-03 — look up the configured policy for `stage` and return
    /// the `fail_fast` flag. Returns `false` for any stage the
    /// operator hasn't pinned (= legacy lenient behaviour).
    pub fn fail_fast_for_stage(&self, stage: crate::hooks::stages::HookStage) -> bool {
        self.hook_chain
            .get(stage.as_str())
            .map(|cfg| cfg.fail_fast)
            .unwrap_or(false)
    }

    /// GOLD-ADAPT-JV-MODE-02 — single chokepoint for sovereign-buddy mode.
    ///
    /// Returns `true` ONLY when BOTH conditions hold:
    /// 1. `self.sovereign_buddy == true` (operator ran the ceremony), AND
    /// 2. `self.autonomy == AutonomyLevel::Full` (Full autonomy is active).
    ///
    /// This is the ONLY place in the codebase that should read `sovereign_buddy`
    /// directly. Every gate that conditions behaviour on sovereign mode calls
    /// this accessor instead of reading the flag raw, so the dual-requirement
    /// is enforced in exactly one place. JV-MODE-04 (self-activation) and any
    /// other downstream consumer MUST use this method.
    /// GOLD-ADAPT-JV-MISC (model-alias map) — resolve an operator alias to
    /// its real model id via a plain first-match `HashMap` lookup.
    ///
    /// **Contract:** the map has no catalog access. If an alias key equals a
    /// real model id the alias WILL redirect it — choose distinct alias names
    /// (e.g. prefix with `@`) to avoid accidental shadowing. Alias→alias chains
    /// resolve ONE level; the intermediate is sent to the provider verbatim.
    /// Unknown keys pass through unchanged (provider surfaces the error).
    #[inline]
    pub fn resolve_model_alias<'a>(&'a self, id: &'a str) -> &'a str {
        self.models_aliases
            .get(id)
            .map(String::as_str)
            .unwrap_or(id)
    }

    pub fn sovereign_active(&self) -> bool {
        self.sovereign_buddy && matches!(self.autonomy, crate::permissions::AutonomyLevel::Full)
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

    /// Session 24 env-mutation refactor (Option C): build the
    /// `~/.neoth/` path against an explicit `base` directory instead
    /// of reading `HOME` / `USERPROFILE` from the process-global env.
    /// Tests that previously mutated the env can now pass a tempdir
    /// directly — no `std::env::set_var`, no cross-test race.
    pub fn default_neoth_home_at(base: &Path) -> PathBuf {
        neoth_home_from(base)
    }

    /// Same idea for the WAL directory specifically. Mirrors
    /// [`default_wal_dir`] but accepts an explicit `base` so test
    /// callers don't have to call `default_neoth_home_at(base).join("wal")`
    /// themselves.
    pub fn default_wal_dir_at(base: &Path) -> PathBuf {
        neoth_home_from(base).join("wal")
    }

    /// Path to the optional cron jobs file (`~/.neoth/jobs.yaml`).
    ///
    /// Returns `Some` regardless of whether the file exists — callers should
    /// check `exists()`. `None` is reserved for future per-operator overrides
    /// (e.g. `jobs_path:` field in `freedom.yaml`); none exist yet.
    pub fn jobs_file_path(&self) -> Option<PathBuf> {
        self.jobs_file_path_at(&Self::default_neoth_home())
    }

    /// Instance-bound counterpart to [`Self::jobs_file_path`].
    pub fn jobs_file_path_at(&self, home: &Path) -> Option<PathBuf> {
        Some(home.join("jobs.yaml"))
    }

    pub fn load_from_default_path() -> Result<Self> {
        Self::load_from_path(&Self::default_path())
    }

    /// Load the default config when present, or use the safe compiled defaults
    /// only when the path is genuinely absent. Unlike `unwrap_or_default()`,
    /// this preserves read, parse, validation, and credential-backend errors
    /// from an existing operator config.
    pub fn load_from_default_path_or_default() -> Result<Self> {
        Self::load_from_path_or_default(&Self::default_path())
    }

    /// Path-injectable counterpart to [`Self::load_from_default_path_or_default`].
    /// The `try_exists` error is significant: an unreadable path must not be
    /// mistaken for first-run absence and silently relax policy to defaults.
    pub fn load_from_path_or_default(path: &Path) -> Result<Self> {
        match path
            .try_exists()
            .with_context(|| format!("check freedom.yaml path {}", path.display()))?
        {
            true => Self::load_from_path(path),
            false => Ok(Self::default()),
        }
    }

    /// Write the public (secret-free) portion of this config to the
    /// default `freedom.yaml` path with mode 0600 (unix) + atomic
    /// rename. SecretString fields are stripped before serialisation
    /// — secret-split (Codex audit #7) requires API keys / tokens to
    /// live in `credentials.yaml`, not `freedom.yaml`.
    ///
    /// Used by CLI paths that already hold a complete config value. New
    /// read-modify-write callers should prefer [`Self::update_at`]; provider
    /// keys are persisted separately through `Credentials::update_at`.
    pub fn save_public_to_default_path(&self) -> Result<()> {
        let path = Self::default_path();
        let _process_guard = lock_freedom_update();
        let _file_guard = crate::util::locked_file::lock_file_blocking(
            &path.with_extension("lock"),
            "freedom config",
        )?;
        self.write_public_to_path(&path)
    }

    /// Concurrency-safe read-modify-write for `freedom.yaml`.
    ///
    /// The config is reloaded only after both the process-local mutex and the
    /// sibling OS lock are held. A malformed existing file therefore returns
    /// an error before `mutation` runs and before any bytes are replaced. The
    /// resulting public config is secret-stripped and atomically renamed.
    pub fn update_at<T>(path: &Path, mutation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let _process_guard = lock_freedom_update();
        let _file_guard = crate::util::locked_file::lock_file_blocking(
            &path.with_extension("lock"),
            "freedom config",
        )?;
        let mut config = Self::load_from_path(path)?;
        let value = mutation(&mut config)?;
        config.write_public_to_path(path)?;
        Ok(value)
    }

    /// Secret-free YAML rendering used by operator-facing config inspection.
    pub(crate) fn public_yaml(&self) -> Result<String> {
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

        public
            .companion
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid companion config: {error}"))?;
        public
            .swarm
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid swarm config: {error}"))?;
        public
            .cluster
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid cluster config: {error}"))?;
        serde_yaml::to_string(&public).context("serialize FreedomConfig as YAML for freedom.yaml")
    }

    fn write_public_to_path(&self, path: &Path) -> Result<()> {
        let body = self.public_yaml()?;
        crate::util::atomic_write::atomic_write_private(path, body.as_bytes())
            .with_context(|| format!("atomically write {}", path.display()))?;
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
        config
            .companion
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid companion config: {error}"))?;
        config
            .swarm
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid swarm config: {error}"))?;
        config
            .cluster
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid cluster config: {error}"))?;

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
        let creds = credentials::Credentials::load_effective(&cred_path, config.secrets_backend)
            .with_context(|| format!("load credentials at {}", cred_path.display()))?;

        if let Some(k) = creds.provider_key {
            config.provider_key = Some(k);
        }
        if let Some(t) = creds.telegram_token {
            config.telegram_token = Some(t);
        }
        // GR-041: per-slot inference keys. `save_public_to_default_path` strips
        // `inference.{left,right,cerebellum,default_slot}.key` from freedom.yaml
        // and the doc tells operators to set them in credentials.yaml — but the
        // Credentials struct had no field for them, so a per-slot key was
        // silently DROPPED on the next save (and unconfigurable via the
        // documented file). Merge them back here, matching provider_key's
        // "credentials.yaml wins" posture.
        if let Some(k) = creds.inference_left_key {
            config.inference.left.key = Some(k);
        }
        if let Some(k) = creds.inference_right_key {
            config.inference.right.key = Some(k);
        }
        if let Some(k) = creds.inference_cerebellum_key {
            config.inference.cerebellum.key = Some(k);
        }
        if let Some(k) = creds.inference_default_slot_key {
            config.inference.default_slot.key = Some(k);
        }
        Ok(config)
    }
}

fn neoth_home() -> PathBuf {
    // `NEOTH_HOME` overrides everything — used by CI, integration tests,
    // and operators who keep `~/.neoth` on a non-default mount. The
    // override IS the home dir (no `.neoth` suffix appended). HOME /
    // USERPROFILE fallback keeps the long-standing default.
    if let Ok(explicit) = std::env::var("NEOTH_HOME")
        && !explicit.is_empty()
    {
        return PathBuf::from(explicit);
    }
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    neoth_home_from(&home)
}

/// Session 24: build the `~/.neoth/` path against an explicit `base`.
/// Pure function — no env reads, no allocation beyond the final join.
/// Used by [`FreedomConfig::default_neoth_home_at`] and the test
/// helpers in `cli/*` that previously had to mutate HOME.
pub fn neoth_home_from(base: &Path) -> PathBuf {
    base.join(".neoth")
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
