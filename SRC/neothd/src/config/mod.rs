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
pub mod presets;

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

    /// GOLD-ADOPT-18 — subdirectory-hint auto-injection toggle (default ON).
    #[serde(default)]
    pub hints: HintsConfig,

    /// OM-01 — local OMI transcript ingest. Off by default; the daemon REFUSES
    /// to start (SC-14) if enabled with a non-local endpoint.
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
    /// HO-07 — neoth-monitor alerting sidecar cron. When `enabled`, the
    /// daemon polls WAL integrity, crash.log, and channel activity and
    /// emits `0x48 WAL_CRC_ALERT` / `0x49 CRASH_LOG_ALERT` /
    /// `0x4A CHANNEL_SILENCE_ALERT` on anomalies. Default OFF (opt-in).
    #[serde(default)]
    pub monitor: MonitorConfig,
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
    /// PC-01 — OS-tool surface (file/folder access). Default DENY-ALL: an
    /// empty `tools.os.allowed_paths` means NEOTH can read no operator file.
    /// Operators at `elevated`/`full` autonomy opt in by listing absolute
    /// path prefixes. NO registry / system-paths / process-kill — those are
    /// not representable. Every gated read/deny lands in the WAL
    /// (`0xA8`/`0xA9`).
    #[serde(default)]
    pub tools: ToolsConfig,
    /// SL-00 — cluster identity. `name` is the PUBLIC rendezvous label that
    /// derives the Hyperswarm DHT topic + the mDNS service name (it is NOT a
    /// secret — the DHT topic is public; the shared `cluster_passphrase` in
    /// credentials.yaml is what authenticates). Empty `name` = no cluster
    /// identity = the transport stays inert (fail-closed). The existing
    /// untyped `cluster.mdns.enabled` / `cluster.listen_port` are read
    /// separately by `cluster::policy`; serde ignores them here.
    #[serde(default)]
    pub cluster: ClusterConfig,
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
}

/// GOLD-WIRE-07 — memory subsystem tuning. One field today
/// (`vector_index`); a natural home for future retention / decay knobs.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct MemoryConfig {
    pub vector_index: VectorIndexConfig,
    /// GOLD-ADOPT-21 — when `true`, NEOTH generates an LLM title for each
    /// completed `neoth chat` session (via the cheap `inference.utility_provider`)
    /// and stores it as the card's `display_name`, which the next-session banner
    /// then prefers over the deterministic summary. Default `false`: it costs one
    /// extra (fast-model) call + a little latency at chat exit, so it's opt-in.
    #[serde(default)]
    pub name_sessions: bool,
    /// GR-039 — gate for the GOLD-WIRE-02 conversational-recall short-circuit
    /// in `neoth chat`. `true` (default, the shipped behaviour): recall-looking
    /// prompts ("do you remember when…") are answered straight from the local
    /// episode store without an LLM call. `false`: such prompts go to the
    /// provider like any other turn.
    #[serde(default = "default_recall_shortcut")]
    pub recall_shortcut: bool,
}

// Manual impl (not derived): `recall_shortcut` must default `true` on BOTH
// deserialization paths — a missing field inside an existing `memory:` block
// (field-level serde default) AND a missing `memory:` block entirely (struct
// `#[serde(default)]` → `Default::default()`). A derived Default would make
// the second path silently disable the shipped behaviour.
impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            vector_index: VectorIndexConfig::default(),
            name_sessions: false,
            recall_shortcut: true,
        }
    }
}

fn default_recall_shortcut() -> bool {
    true
}

/// GOLD-WIRE-07 — similarity-recall vector-index backend selector.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct VectorIndexConfig {
    /// `brute_force` (default) is the always-available O(N) cosine scan over
    /// `idx_embedding`. `hnsw` activates the in-process HNSW index for
    /// `neoth recall --similar-to*`: the CLI cold-loads `<neoth_home>/
    /// embeddings.hnsw` per query, falling back to brute-force when the
    /// snapshot is absent/empty/unreadable OR the corpus is still under the
    /// brute-force ceiling (~50k) where the scan is faster than a cold load.
    /// The snapshot is NOT built automatically — run `neoth memory
    /// --rebuild-index` before HNSW recall returns results. `neoth doctor`
    /// flags a missing/stale snapshot when `hnsw` is selected.
    #[serde(default)]
    pub backend: VectorBackend,
}

/// GOLD-WIRE-07 — operator-visible vector-index backend. Serialises as
/// lowercase snake_case (`brute_force` / `hnsw`).
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VectorBackend {
    /// O(N) cosine scan over `idx_embedding`. Always available. Default.
    #[default]
    BruteForce,
    /// In-process approximate nearest-neighbour via `hnsw_rs`. Opt-in; needs
    /// a built `embeddings.hnsw` snapshot to be useful (else falls back).
    Hnsw,
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

/// SL-00 cluster-identity config. Default: no name (no cluster).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
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
}

/// PC-01 OS-tool surface config. Default-safe: every sub-surface is
/// deny-all until the operator explicitly opts in.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ToolsConfig {
    pub os: OsToolsConfig,
}

/// PC-01 OS file-access config. `allowed_paths` is the operator's allowlist
/// of absolute path PREFIXES the daemon may read under; empty = deny-all
/// (the default). A read is permitted only when the canonical target path
/// is under one of these (canonical) prefixes — see `os_tools::allowlist`.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct OsToolsConfig {
    /// Allowlisted absolute path prefixes. Empty = deny-all (default).
    /// Example: `["/home/alice/workspace", "/tmp/neoth-scratch"]`.
    pub allowed_paths: Vec<std::path::PathBuf>,
    /// Max bytes a single `OsFileRead` may return. Default 1 MiB — a guard
    /// against pulling a multi-GB file into memory / a provider prompt.
    pub max_read_bytes: usize,
    /// PC-01 (write slice): allowlisted absolute path prefixes the daemon may
    /// WRITE under. SEPARATE from `allowed_paths` ON PURPOSE — a readable path
    /// is NOT automatically writable. Empty = deny-all (the default). A write is
    /// permitted only when the target's canonical PARENT dir is under one of
    /// these (canonical) prefixes — see `os_tools::allowlist::resolve_write_target`.
    pub allowed_write_paths: Vec<std::path::PathBuf>,
    /// Max bytes a single `OsFileWrite` may write. Default 1 MiB — bounds how
    /// much a gated write (or a delegated one) can put on the operator's disk.
    pub max_write_bytes: usize,
    /// PC-01 (app-launch slice): allowlisted absolute EXECUTABLE paths the
    /// daemon may launch. SEPARATE from the file allowlists ON PURPOSE — a
    /// readable/writable path is NOT runnable. Empty = deny-all (the default).
    /// Matched by EXACT canonical path (not a directory prefix): an entry
    /// `/usr/bin/firefox` authorises launching exactly that binary, never the
    /// rest of `/usr/bin`. See `os_tools::allowlist::resolve_exec_program`.
    ///
    /// TOCTOU note: prefer binaries in non-world-writable directories
    /// (`/usr/bin`, `~/bin`). On Unix the resolver REFUSES to launch from a
    /// world-writable dir (e.g. `/tmp`), where another local user could swap
    /// the binary between resolution and exec; entries in user-private dirs are
    /// safe, system dirs are safest.
    pub allowed_exec_paths: Vec<std::path::PathBuf>,
    /// PC-01 (clipboard slice): OS clipboard read/write policy. Default = fully
    /// OFF. Compiled unconditionally (pure data, no `arboard` dependency); the
    /// `os-clipboard` cargo feature only gates the backend + the gate functions
    /// that consume this config.
    #[serde(default)]
    pub clipboard: ClipboardConfig,
}

impl Default for OsToolsConfig {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            max_read_bytes: 1024 * 1024,
            allowed_write_paths: Vec::new(),
            max_write_bytes: 1024 * 1024,
            allowed_exec_paths: Vec::new(),
            clipboard: ClipboardConfig::default(),
        }
    }
}

/// PC-01 (clipboard slice) — OS clipboard policy. Default is the MOST
/// RESTRICTIVE posture: every toggle OFF, so a fresh install (or any
/// `freedom.yaml` missing the `tools.os.clipboard` key) can neither read nor
/// write the operator's clipboard. The operator opts in PER DIRECTION
/// (`read_enabled` / `write_enabled` are SEPARATE ON PURPOSE — mirroring the
/// `allowed_paths` vs `allowed_write_paths` split: reading is not writing).
///
/// Security rationale: the OS clipboard is an UNSCOPED ambient secret store
/// (read can capture a just-copied password) and a passive injection sink
/// (write enables pastejacking). Both directions are also autonomy-gated and
/// WAL-audited downstream; these flags are the upstream master switches.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ClipboardConfig {
    /// Master switch. `false` (default) ⇒ neither read nor write is possible.
    pub enabled: bool,
    /// Allow `OsClipboardRead`. `false` (default) ⇒ reads denied even if
    /// `enabled`.
    pub read_enabled: bool,
    /// Allow `OsClipboardWrite`. `false` (default) ⇒ writes denied even if
    /// `enabled`.
    pub write_enabled: bool,
    /// Max bytes a clipboard READ may surface (default 4 KiB) — caps how much
    /// ambient content a single read can pull.
    pub max_clipboard_read_bytes: usize,
    /// Max bytes a clipboard WRITE may place (default 4 KiB).
    pub max_clipboard_write_bytes: usize,
    /// Permit newline/CR characters in a WRITE. `false` (default) ⇒ the gate
    /// STRUCTURALLY rejects newline-bearing content (the terminal auto-execute
    /// precondition of a pastejacking attack). Set `true` only for deliberate
    /// multi-line clipboard use; the gate then logs a warning per write.
    pub allow_newlines_in_write: bool,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            read_enabled: false,
            write_enabled: false,
            max_clipboard_read_bytes: 4096,
            max_clipboard_write_bytes: 4096,
            allow_newlines_in_write: false,
        }
    }
}

/// Workstream F (CT-10/E-20/V1x-06) — WAL compression policy.
///
/// Written by the wizard / operator into `freedom.yaml`. Consumed at segment
/// finalize time by the writer task. Default `compression = "none"` keeps
/// v0.1.x behaviour unchanged; flip to `"zstd_3"` in v0.2.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalConfig {
    /// Compression algorithm for newly-sealed segments.
    ///
    /// `"none"`   — v1 segments, no compression (v0.1.x default).
    /// `"zstd_3"` — v2 segments, zstd level-3 on the sealed frame body.
    ///
    /// Existing segments replay correctly regardless — the reader auto-detects
    /// header version and decompresses when the COMPRESSED flag is set.
    pub compression: WalCompression,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            compression: WalCompression::None,
        }
    }
}

/// Compression algorithm for WAL segments.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalCompression {
    /// No compression — v1 wire format (default for v0.1.x).
    #[default]
    None,
    /// zstd level-3 — v2 wire format with SEGMENT_FLAG_COMPRESSED.
    /// YAML key: `zstd_3` (explicit rename — snake_case would give `zstd3`).
    #[serde(rename = "zstd_3")]
    Zstd3,
}

/// Load the `wal:` sub-key from a `freedom.yaml` file.
///
/// Reads only the `wal:` stanza — does NOT parse the full `FreedomConfig`.
/// Returns `WalConfig::default()` (no compression) on any error so existing
/// operator setups with no `wal:` key keep working without changes.
pub fn load_wal_config(freedom_yaml_path: &Path) -> WalConfig {
    load_wal_config_strict(freedom_yaml_path).unwrap_or_default()
}

/// Like `load_wal_config` but surfaces parse errors.
pub fn load_wal_config_strict(freedom_yaml_path: &Path) -> Result<WalConfig> {
    let text = std::fs::read_to_string(freedom_yaml_path)
        .with_context(|| format!("read {}", freedom_yaml_path.display()))?;
    let value: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("parse {}", freedom_yaml_path.display()))?;
    match value.get("wal").cloned() {
        None | Some(serde_yaml::Value::Null) => Ok(WalConfig::default()),
        Some(wal_val) => {
            serde_yaml::from_value(wal_val).with_context(|| "parse freedom.yaml wal: stanza")
        }
    }
}

#[cfg(test)]
mod wal_config_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_wal_config_is_none_compression() {
        assert_eq!(WalConfig::default().compression, WalCompression::None);
    }

    #[test]
    fn tools_os_defaults_to_deny_all() {
        // PC-01: a fresh config (or a freedom.yaml with no `tools:` block)
        // must read as deny-all — empty allowed_paths, 1 MiB read cap.
        let cfg = ToolsConfig::default();
        assert!(
            cfg.os.allowed_paths.is_empty(),
            "default OS allowlist must be empty (deny-all)"
        );
        assert_eq!(cfg.os.max_read_bytes, 1024 * 1024);
        // Round-trips through YAML with the field absent.
        let parsed: FreedomConfig =
            serde_yaml::from_str("operator_id: alice\n").expect("parse minimal freedom.yaml");
        assert!(parsed.tools.os.allowed_paths.is_empty());
    }

    #[test]
    fn omi_config_defaults_off_and_local() {
        // OM-01 — default OFF, local endpoint, 30s/0.75 knobs; serde round-trips.
        let d = OmiConfig::default();
        assert!(!d.enabled);
        assert_eq!(d.endpoint, crate::installers::omi::DEFAULT_OMI_ENDPOINT);
        assert_eq!(d.poll_interval_secs, 30);
        assert!((d.confidence_threshold - 0.75).abs() < 1e-6);
        let absent: FreedomConfig = serde_yaml::from_str("operator_id: a\n").expect("parse");
        assert!(!absent.omi.enabled);
        let set: FreedomConfig = serde_yaml::from_str(
            "operator_id: a\nomi:\n  enabled: true\n  endpoint: http://127.0.0.1:9999\n",
        )
        .expect("parse");
        assert!(set.omi.enabled);
        assert_eq!(set.omi.endpoint, "http://127.0.0.1:9999");
    }

    #[test]
    fn goal_config_max_turns_defaults_to_five() {
        // GM-01 — default 5 (the prior hardcoded dispatch-loop cap; no behaviour
        // change). An absent `goal:` block + a partial one both read 5.
        assert_eq!(GoalConfig::default().max_turns, 5);
        let absent: FreedomConfig = serde_yaml::from_str("operator_id: a\n").expect("parse");
        assert_eq!(absent.goal.max_turns, 5);
        let set: FreedomConfig =
            serde_yaml::from_str("operator_id: a\ngoal:\n  max_turns: 12\n").expect("parse");
        assert_eq!(set.goal.max_turns, 12);
    }

    #[test]
    fn email_config_tiebreak_serde_defaults_are_safe() {
        // PL-05b — both flags off by default (cost-safe + security-conservative).
        let d = EmailConfig::default();
        assert!(!d.llm_tiebreak);
        assert!(!d.llm_tiebreak_allow_downgrade);

        // Absent `email:` block ⇒ both false.
        let absent: FreedomConfig =
            serde_yaml::from_str("operator_id: alice\n").expect("parse minimal");
        assert!(!absent.email.llm_tiebreak);
        assert!(!absent.email.llm_tiebreak_allow_downgrade);

        // Partial block (opt into the tie-breaker, OMIT the dangerous downgrade)
        // ⇒ the downgrade must stay false (the most important regression guard).
        let partial: FreedomConfig =
            serde_yaml::from_str("operator_id: a\nemail:\n  llm_tiebreak: true\n")
                .expect("parse partial email block");
        assert!(partial.email.llm_tiebreak);
        assert!(
            !partial.email.llm_tiebreak_allow_downgrade,
            "omitted downgrade flag must default false, never silently true"
        );

        // Full explicit opt-in ⇒ both true (the opt-in path isn't suppressed).
        let full: FreedomConfig = serde_yaml::from_str(
            "operator_id: a\nemail:\n  llm_tiebreak: true\n  llm_tiebreak_allow_downgrade: true\n",
        )
        .expect("parse full email block");
        assert!(full.email.llm_tiebreak);
        assert!(full.email.llm_tiebreak_allow_downgrade);
    }

    #[test]
    fn load_wal_config_zstd3_from_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "wal:\n  compression: zstd_3\n").unwrap();
        let cfg = load_wal_config(&path);
        assert_eq!(cfg.compression, WalCompression::Zstd3);
    }

    #[test]
    fn load_wal_config_none_explicit_from_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "wal:\n  compression: none\n").unwrap();
        let cfg = load_wal_config(&path);
        assert_eq!(cfg.compression, WalCompression::None);
    }

    #[test]
    fn load_wal_config_missing_key_defaults_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "operator_id: test\n").unwrap();
        let cfg = load_wal_config(&path);
        assert_eq!(cfg.compression, WalCompression::None);
    }

    #[test]
    fn load_wal_config_missing_file_defaults_none() {
        let dir = tempdir().unwrap();
        let cfg = load_wal_config(&dir.path().join("nonexistent.yaml"));
        assert_eq!(cfg.compression, WalCompression::None);
    }
}

/// N-3 Workstream D (Session 23) — `freedom.yaml::n8n_api` shape.
///
/// Default OFF: a fresh install must explicitly flip `enabled: true`
/// + run `neoth n8n token` to bring the localhost HTTP API up. Port
/// pinned to [`crate::n8n_api::DEFAULT_N8N_API_PORT`] (9744) so the
/// bootstrap workflow JSONs at `assets/n8n_workflows/*.json` find
/// the daemon without operator-side surgery.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct N8nApiConfig {
    /// Master switch. Default `false` — the hyper task never spawns
    /// until the operator opts in.
    pub enabled: bool,
    /// Loopback port the hyper server binds. Defaults to
    /// `crate::n8n_api::DEFAULT_N8N_API_PORT` (9744). Override only
    /// when 9744 collides with another local service.
    pub port: u16,
    /// Override the bearer-token file location. `None` resolves to
    /// `~/.neoth/n8n_api_token` (mode-0600 / DACL-restricted).
    pub token_path: Option<std::path::PathBuf>,
}

impl Default for N8nApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: crate::n8n_api::DEFAULT_N8N_API_PORT,
            token_path: None,
        }
    }
}

/// C-16 (Session 21) — proactive messaging opt-in. Pure config
/// shape; the runtime gate consults `proactive.enabled` before
/// firing any unsolicited outbound. Default OFF.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProactiveConfig {
    /// Master switch. `false` = daemon never posts unsolicited
    /// messages (briefings stay opt-in-per-call via the cron yaml).
    /// `true` = cron + `send_proactive()` MAY post on their own.
    pub enabled: bool,
}

/// HO-09 / V1x-03 — profile baseline drift alerting. `neoth profile drift
/// report` flags drift over `threshold`; when `enabled`, the daemon
/// drift-alert cron (HO-09b, `daemon::drift_alert_cron`) emits a
/// `0xBA PROFILE_DRIFT_ALERT` WAL frame on the same threshold every
/// `interval_secs`. Default OFF so the common path is unaffected.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct DriftAlertConfig {
    /// Master switch for drift alerting. Default `false`.
    pub enabled: bool,
    /// Drift ratio above which the profile is "drifted". A report
    /// at-or-below this is informational; strictly above is flagged.
    /// The ratio ranges `0.0..=2.0` (0.0 = identical; 1.0 = full
    /// one-sided replacement; 2.0 = fully disjoint sets — see
    /// `baseline_diff::DriftReport::drift_ratio`). Default `0.25`
    /// (a quarter of the baseline churned).
    pub threshold: f64,
    /// Daemon drift-alert cron tick interval, seconds. Default 6h
    /// (drift changes slowly — claims accrete over days). Clamped to a
    /// 60s floor by [`Self::interval_duration`] so a misconfigured `0`
    /// can't tight-loop.
    pub interval_secs: u64,
}

/// 6 hours — the drift-alert cron default cadence.
pub const DEFAULT_DRIFT_ALERT_INTERVAL_SECS: u64 = 6 * 3600;

impl Default for DriftAlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 0.25,
            interval_secs: DEFAULT_DRIFT_ALERT_INTERVAL_SECS,
        }
    }
}

impl DriftAlertConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    /// Mirrors `DoctorCronConfig::interval_duration`.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// ADV-14 default tick interval: weekly (recall regressions are detected
/// against a cutover anchor; a weekly re-check is plenty + keeps the provider
/// + embed cost negligible).
pub const DEFAULT_REGRESSION_INTERVAL_SECS: u64 = 7 * 24 * 3600;

/// ADV-14 — longitudinal recall-regression anchor cron config. When `enabled`,
/// the daemon weekly re-asks each anchor query, embeds the fresh answer, and
/// emits `0x3F REGRESSION_ALERT` when `cosine(current, anchor) < threshold` —
/// durable evidence that the model's answer to a known query has drifted after
/// a model/config change. Default OFF (opt-in; needs a configured embed
/// provider + a captured anchor file under `~/.neoth/eval/`).
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RegressionAnchorConfig {
    /// Master switch. Default `false`.
    pub enabled: bool,
    /// Cosine floor. An anchor whose fresh answer scores STRICTLY BELOW this
    /// against its cutover vector is flagged. Range `0.0..=1.0`. Default `0.70`.
    pub threshold: f32,
    /// Tick interval, seconds. Default weekly. Clamped to a 60s floor by
    /// [`Self::interval_duration`] so a misconfigured `0` can't tight-loop.
    pub interval_secs: u64,
}

impl Default for RegressionAnchorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 0.70,
            interval_secs: DEFAULT_REGRESSION_INTERVAL_SECS,
        }
    }
}

impl RegressionAnchorConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum (mirrors
    /// `DriftAlertConfig::interval_duration`) so `interval_secs: 0` can't
    /// tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// MONITOR-03 default tick interval: 6h (recall p95 changes slowly; the
/// runbook checks it a few times a day).
pub const DEFAULT_RECALL_LATENCY_INTERVAL_SECS: u64 = 6 * 3600;

/// MONITOR-03 / RECALL-METER-01 — recall-p95 latency alert cron config. When
/// `enabled`, the daemon reads the recent `idx_recall_latency` window and
/// emits `0x4B RECALL_LATENCY_ALERT` when p95 exceeds `p95_threshold_ms`
/// (and at least `min_samples` samples exist — a 2-query window isn't a
/// meaningful p95). Default OFF.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RecallLatencyConfig {
    /// Master switch. Default `false`.
    pub enabled: bool,
    /// p95 ceiling in milliseconds. A window whose p95 STRICTLY exceeds this is
    /// flagged. Default `750.0` (local FTS5 recall is normally single-digit ms;
    /// 750ms p95 signals a cold cache / disk pressure / index regression).
    pub p95_threshold_ms: f64,
    /// Don't alert until at least this many samples exist in the window — a
    /// handful of queries don't make a trustworthy p95. Default `20`.
    pub min_samples: usize,
    /// How many of the most-recent samples to compute p95 over. Default `200`.
    pub window: usize,
    /// Tick interval, seconds. Default 6h. Clamped to a 60s floor.
    pub interval_secs: u64,
}

impl Default for RecallLatencyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            p95_threshold_ms: 750.0,
            min_samples: 20,
            window: 200,
            interval_secs: DEFAULT_RECALL_LATENCY_INTERVAL_SECS,
        }
    }
}

impl RecallLatencyConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum so
    /// `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// SL-03 — ResourcePressureWatcher cron config. When `enabled`, the
/// daemon polls live GPU VRAM every `interval_secs` and emits a
/// `0x47 RESOURCE_PRESSURE_ALERT` when usage `>= vram_threshold_pct`.
/// Default OFF (opt-in). No-op on non-GPU / non-NVIDIA hosts.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ResourceWatchConfig {
    /// Master switch. `false` (default) = the cron never spawns.
    pub enabled: bool,
    /// Poll interval in seconds. Default 30. Clamped to a 10s floor by
    /// [`Self::interval_duration`] so a misconfigured `0` can't tight-loop.
    pub interval_secs: u64,
    /// VRAM-usage percent at-or-above which an advisory frame is emitted.
    /// Default 90.
    pub vram_threshold_pct: u8,
}

/// 30 seconds — the resource-watch cron default cadence.
pub const DEFAULT_RESOURCE_WATCH_INTERVAL_SECS: u64 = 30;

impl Default for ResourceWatchConfig {
    fn default() -> Self {
        // Off by default — opt-in gate per the noob-wizard rule.
        Self {
            enabled: false,
            interval_secs: DEFAULT_RESOURCE_WATCH_INTERVAL_SECS,
            vram_threshold_pct: 90,
        }
    }
}

impl ResourceWatchConfig {
    /// Poll interval as a `Duration`, clamped to a 10s floor so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(10))
    }
}

/// HO-07 — neoth-monitor alerting cron config. When `enabled`, the daemon
/// scans the WAL + crash log every `interval_secs` and emits advisory
/// frames when anomalies are detected:
///   - `0x48 WAL_CRC_ALERT` when RECOVERY_TRUNCATED / COMPACTION_AUTH_FAILED
///     frames appear in the `wal_crc_window_secs` look-back
///   - `0x49 CRASH_LOG_ALERT` when new content arrives in `crash.log`
///   - `0x4A CHANNEL_SILENCE_ALERT` when no CHANNEL_INGRESS/EGRESS frames
///     appear for `channel_silence_secs` during the active UTC window
///
/// Default OFF. No-op when the WAL dir is empty / crash.log absent.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct MonitorConfig {
    /// Master switch. `false` (default) = the cron never spawns.
    pub enabled: bool,
    /// Poll interval in seconds. Default 300 (5 min). Clamped to 30s floor.
    pub interval_secs: u64,
    /// Look-back window for WAL CRC anomaly counting, seconds. Default 3600 (1h).
    pub wal_crc_window_secs: u64,
    /// Channel silence threshold in seconds. Default 1800 (30 min).
    pub channel_silence_secs: u64,
    /// UTC hour (0-23) when the active channel-watch window OPENS.
    /// Default 7 (07:00 UTC ≈ 08:00 CET / 09:00 CEST).
    pub channel_silence_active_utc_start: u8,
    /// UTC hour (0-23) when the active channel-watch window CLOSES.
    /// Default 21 (21:00 UTC ≈ 22:00 CET / 23:00 CEST).
    pub channel_silence_active_utc_end: u8,
    /// MONITOR-04 — minimum seconds between repeated alerts of the SAME kind.
    /// The monitor re-checks state every tick; without this it re-emits
    /// `0x48`/`0x4A` on every tick the bad state persists (CRC frames linger in
    /// the look-back window; channel silence is level- not edge-triggered).
    /// Default 3600 (1h): emit-once-per-hour-per-kind. `0` disables dedup.
    /// (Crash alerts are already edge-triggered via the crash.log byte offset,
    /// so dedup is moot for them.)
    pub min_repeat_alert_secs: u64,
}

/// 5 minutes — the monitor cron default cadence.
pub const DEFAULT_MONITOR_INTERVAL_SECS: u64 = 300;

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_MONITOR_INTERVAL_SECS,
            wal_crc_window_secs: 3600,
            channel_silence_secs: 1800,
            channel_silence_active_utc_start: 7,
            channel_silence_active_utc_end: 21,
            min_repeat_alert_secs: 3600,
        }
    }
}

impl MonitorConfig {
    /// Poll interval as a `Duration`, clamped to a 30s floor.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(30))
    }
}

/// SPEC-05 — passive user-adaptation cron config. When `enabled`, the
/// daemon re-aggregates the behavioural snapshot + generates self-dev
/// proposals every `interval_secs`. Default OFF (opt-in), matching the
/// `drift_alert` precedent — the proposals are non-destructive (pending
/// operator review) but the aggregation scans the WAL, so it stays
/// opt-in until the operator wants proactive adaptation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ProfileAdaptConfig {
    /// Master switch for the passive-adaptation cron. Default `false`.
    pub enabled: bool,
    /// Cron tick interval, seconds. Default 24h — behavioural patterns
    /// shift over days, so daily re-aggregation is ample. Clamped to a
    /// 60s floor by [`Self::interval_duration`].
    pub interval_secs: u64,
}

// NOTE: the cron computes proposals *against* the operator's chosen
// behavioural preset, but that choice is NOT stored here — it lives in the
// single canonical active-preset marker (`cli::profile::{record,load}_active_preset`,
// set by `neoth profile preset set` / the GUI selector). The cron reads it
// live each tick via `load_active_preset`, so there is exactly one source of
// truth for "the operator's behavioural preset".

/// 24 hours — the passive-adaptation cron default cadence.
pub const DEFAULT_PROFILE_ADAPT_INTERVAL_SECS: u64 = 24 * 3600;

impl Default for ProfileAdaptConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_PROFILE_ADAPT_INTERVAL_SECS,
        }
    }
}

impl ProfileAdaptConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum so an
    /// operator-supplied `interval_secs: 0` can't tight-loop the cron.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// G-01 — passive behaviour-pattern cron config. When `enabled`, the
/// daemon's `pattern_cron` runs every `interval_secs` and fires up to
/// four independent detectors, each enqueueing at most ONE proactive
/// nudge per UTC day (deduped):
///   - **inactivity-gap**: silence longer than `inactivity_gap_secs`.
///   - **query-repeat**: the same message asked `query_repeat_min_count`+
///     times within `query_repeat_window_secs` (candidate for a saved
///     note/shortcut/skill).
///   - **topic-burst**: a topic whose recent mention-rate spikes by
///     `topic_burst_factor`× over its baseline (focus shift).
///   - **time-of-day-shift**: the operator's peak active hour moved by
///     `tod_shift_min_hours`+ hours.
/// Master `enabled` is OFF by default — a proactive ping is intrusive,
/// so the whole engine stays opt-in (matching `drift_alert`/
/// `profile_adapt`). Once opted in, each detector has its own toggle so
/// an operator can keep, say, inactivity + query-repeat but silence the
/// topic-burst nudges.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct PatternCronConfig {
    /// Master switch for the whole pattern engine. Default `false`.
    pub enabled: bool,
    /// Cron tick interval, seconds. Default 24h.
    pub interval_secs: u64,
    /// Quiet-gap threshold, seconds, beyond which an inactivity nudge
    /// fires. Default 3 days — long enough that a normal weekend pause
    /// stays silent.
    pub inactivity_gap_secs: u64,

    // --- query-repeat detector ---
    /// Enable the query-repeat detector. Default `true` (within the
    /// opt-in engine).
    pub query_repeat_enabled: bool,
    /// Look-back window for repeated-message detection, seconds.
    /// Default 7 days.
    pub query_repeat_window_secs: u64,
    /// How many byte-identical messages within the window trigger a
    /// nudge. Default 3.
    pub query_repeat_min_count: u32,

    // --- topic-burst detector ---
    /// Enable the topic-burst detector. Default `true`.
    pub topic_burst_enabled: bool,
    /// Recent window for burst detection, seconds. Default 2 days.
    pub topic_burst_recent_secs: u64,
    /// Total baseline window, seconds. The baseline period the recent
    /// rate is compared against is `baseline_secs - recent_secs`.
    /// Default 14 days.
    pub topic_burst_baseline_secs: u64,
    /// Absolute floor: a topic must appear at least this many times in
    /// the recent window before it can burst (drops one-off noise).
    /// Default 4.
    pub topic_burst_min_count: u32,
    /// Burst factor: recent mention-rate must exceed this multiple of
    /// the baseline rate. Default 3.0. (A brand-new topic with zero
    /// baseline always passes once over the min-count floor.)
    pub topic_burst_factor: f64,

    // --- time-of-day-shift detector ---
    /// Enable the time-of-day-shift detector. Default `true`.
    pub tod_shift_enabled: bool,
    /// Recent window for the peak-hour histogram, seconds. Default
    /// 7 days.
    pub tod_shift_recent_secs: u64,
    /// Baseline window for the peak-hour histogram, seconds. The
    /// compared baseline period is `baseline_secs - recent_secs`.
    /// Default 30 days.
    pub tod_shift_baseline_secs: u64,
    /// Minimum circular distance (hours) between the recent and baseline
    /// peak active hour before a shift nudge fires. Default 4.
    pub tod_shift_min_hours: u32,
    /// Minimum episodes required in EACH window before the histogram is
    /// trusted (sparse data gives a noisy peak). Default 10.
    pub tod_shift_min_episodes: u32,

    /// Max nudges the pattern engine enqueues in a SINGLE tick across all
    /// detectors. Highest-priority detectors win the slots. Default 1 so
    /// the engine takes at most a third of the shared 3/day ProactiveQueue
    /// budget per tick, leaving room for the reflection + g02 producers.
    /// Clamped to a 1 floor downstream (0 would silence the engine).
    pub max_nudges_per_tick: u32,
}

/// 24 hours — the pattern cron default cadence.
pub const DEFAULT_PATTERN_CRON_INTERVAL_SECS: u64 = 24 * 3600;
/// 3 days — the default inactivity gap before a nudge.
pub const DEFAULT_INACTIVITY_GAP_SECS: u64 = 3 * 24 * 3600;

impl Default for PatternCronConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_PATTERN_CRON_INTERVAL_SECS,
            inactivity_gap_secs: DEFAULT_INACTIVITY_GAP_SECS,
            query_repeat_enabled: true,
            query_repeat_window_secs: 7 * 24 * 3600,
            query_repeat_min_count: 3,
            topic_burst_enabled: true,
            topic_burst_recent_secs: 2 * 24 * 3600,
            topic_burst_baseline_secs: 14 * 24 * 3600,
            topic_burst_min_count: 4,
            topic_burst_factor: 3.0,
            tod_shift_enabled: true,
            tod_shift_recent_secs: 7 * 24 * 3600,
            tod_shift_baseline_secs: 30 * 24 * 3600,
            tod_shift_min_hours: 4,
            tod_shift_min_episodes: 10,
            max_nudges_per_tick: 1,
        }
    }
}

impl PatternCronConfig {
    /// Tick interval as a `Duration`, clamped to a 60s minimum.
    pub fn interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.interval_secs.max(60))
    }
}

/// SPEC-03b — per-provider HTTP-429 fallback chain (4-lens gremium design,
/// 2026-05-30). When the primary provider returns `QuotaError` (429), the
/// chat dispatch transparently tries each chain entry in order. Two guards
/// the gremium flagged as mandatory: (1) each fallback hop must pass the
/// SAME cloud-egress consent gate as the primary — a 429 must never
/// silently exfiltrate to a provider the operator never approved; (2)
/// fallback fires ONLY on 429 (not breaker-open/timeout — mixing signals
/// contaminates the breaker). Entries already in QuotaTracker backoff are
/// skipped. Empty `chain` (default) = no fallback, no behaviour change.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FallbackConfig {
    /// Ordered fallback providers, each a `HemisphereSlot`
    /// (provider/model/key/endpoint/region/api_version). Tried in order
    /// after the primary 429s; the primary is NOT repeated here.
    #[serde(default)]
    pub chain: Vec<crate::config::inference::HemisphereSlot>,
    /// Hard cap on fallback hops (cycle + retry-storm guard). Default 2.
    #[serde(default = "default_fallback_max_hops")]
    pub max_hops: u8,
}

fn default_fallback_max_hops() -> u8 {
    2
}

/// A3-01 — `neoth transfer` size caps (default-applied; an absent block uses
/// the documented defaults).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TransferConfig {
    /// Max `idx_episode` rows an export may bundle. Default 1000.
    pub max_events: usize,
    /// Max plaintext JSON bytes BEFORE encryption. Default 8 MiB.
    pub max_plaintext_bytes: usize,
    /// Max sealed-bundle JSON bytes on disk. Default 16 MiB. Also the cap a
    /// received bundle may be before `verify`/`import` reads it.
    pub max_bundle_bytes: usize,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            max_events: 1000,
            max_plaintext_bytes: 8 * 1024 * 1024,
            max_bundle_bytes: 16 * 1024 * 1024,
        }
    }
}

/// R-02 Phase 4c — nightly dreaming task gates.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct DreamingConfig {
    /// Master switch. `false` = task never spawns (zero CPU /
    /// memory / log noise). `true` = spawn the interval task at
    /// daemon boot.
    pub enabled: bool,
    /// Interval between dreaming passes in seconds. `None` =
    /// 86_400 (24h, matches the SPEC nightly 03:00 cron pattern).
    /// Operators wanting hourly batches set 3600.
    pub interval_secs: Option<u64>,
    /// Time window read from `idx_episode` per pass in seconds.
    /// `None` = 86_400 (one day's events per tick).
    pub window_secs: Option<u64>,
    /// Cap on events processed per pass. `None` = 500. Bounds
    /// operator-LLM cost on high-traffic days (~50ms/embed × 500 =
    /// ~25s compute per pass).
    pub max_events: Option<usize>,
    /// KF-04 — when `true`, each composed dream is run through the
    /// skill-forge: a candidate skill YAML is synthesised + staged as an
    /// OB-03 proposal for operator review (`neoth proactive review`).
    /// Off by default — opt-in (NEOTH never adds a skill unprompted; the
    /// operator adopts it via `neoth proactive accept`).
    pub forge_skills: bool,
    /// SPEC-12 Phase 4b — when `true`, each embedding-clustered dream's
    /// theme label is summarised by the configured CHAT provider (turns
    /// `cluster-3-seed-918` into a real motif like "auth refactor +
    /// deploy"). Off by default because it spends one extra LLM call per
    /// cluster per pass: on a metered cloud provider an opted-in nightly
    /// dreaming run would otherwise silently bill — so the operator opts
    /// in explicitly (cost-safe default, matching the `claude_cli is the
    /// cost-free path` rule). When `false`, OR when no chat provider is
    /// configured, OR when a summarisation call fails, the deterministic
    /// `cluster-N-seed-id` label is used (no behaviour change). Has no
    /// effect without an embedding provider (the deterministic path has
    /// no clusters to label).
    pub summarize_themes: bool,
    /// SPEC-12 cross-theme merging — when `true`, after per-cluster dreams are
    /// composed, clusters whose centroid embeddings have cosine ≥
    /// [`crate::daemon::dreaming::DREAMING_CROSS_THEME_THRESHOLD`] are merged
    /// into a single combined meta-theme. Off by default. PURE deterministic
    /// centroid math — no LLM, no extra cost. Has no effect without an embedding
    /// provider (the deterministic path has no centroids to compare) or with a
    /// single cluster.
    pub merge_cross_themes: bool,
}

impl Default for DreamingConfig {
    fn default() -> Self {
        // Off by default — opt-in gate per the noob-wizard rule.
        Self {
            enabled: false,
            interval_secs: None,
            window_secs: None,
            max_events: None,
            forge_skills: false,
            summarize_themes: false,
            merge_cross_themes: false,
        }
    }
}

/// EM-01b / PL-05b — inbound email knobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EmailConfig {
    /// PL-05b — when `true`, an email that the deterministic PL-05 rule engine
    /// lands in the borderline `ReviewQueue` band (score 50-79) gets a SECOND
    /// opinion from the configured CHAT provider: the redacted body is
    /// classified benign / spam / phishing / malware, which can PROMOTE it to
    /// Quarantine (always safe — more restrictive) or, only with
    /// `llm_tiebreak_allow_downgrade`, demote it to Deliver.
    ///
    /// Off by default because it spends one LLM call PER borderline email: on
    /// a metered cloud provider an opted-in inbox poll would otherwise silently
    /// bill — so the operator opts in explicitly (cost-safe default, matching
    /// the `claude_cli is the cost-free path` rule). A provider error, or no
    /// configured provider, leaves the deterministic `ReviewQueue` verdict
    /// unchanged (fail-safe — the email is still held for the operator).
    pub llm_tiebreak: bool,
    /// PL-05b — gate the one DANGEROUS direction. When `false` (default), the
    /// tie-breaker may only CONFIRM `ReviewQueue` or PROMOTE to Quarantine; a
    /// `benign` verdict keeps the email in `ReviewQueue` (the operator still
    /// decides). When `true`, a high-confidence benign verdict DEMOTES the
    /// email to `Deliver` (the agent may auto-act) — opt-in because it lets an
    /// LLM false-negative override the deterministic rules.
    pub llm_tiebreak_allow_downgrade: bool,
    /// P1a — operator-configured trusted sender domains (e.g. `acme.com`,
    /// `bank.example`). A sender whose envelope-From domain matches (exactly or
    /// as a subdomain) is FLAGGED trusted in the triage output + audit. This is
    /// a VISIBILITY signal only — a trusted sender's mail is STILL fully
    /// sanitized + threat-scored (trust never bypasses the security pipeline;
    /// "trusted but still sanitized"). Default empty.
    #[serde(default)]
    pub trusted_domains: Vec<String>,
    /// P1a — turn the trusted-sender ENFORCEMENT policy ON (default off, opt-in).
    /// When on, the PRIMARY behaviour is spoof defence: a `trusted_domains` match
    /// whose mail carries a FAILING SPF/DKIM/DMARC verdict is escalated to
    /// quarantine (the allowlist alone is spoofable — failing auth on a "trusted"
    /// domain is the attack tell). Only ever MORE restrictive. Visibility-only
    /// annotation still runs regardless of this flag.
    #[serde(default)]
    pub trusted_sender_policy: bool,
    /// P1a — gate the one RELAXING direction (default off, double-opt-in like
    /// `llm_tiebreak_allow_downgrade`). When on AND `trusted_sender_policy` is on,
    /// a VERIFIED-trust sender (allowlist + auth pass) whose mail is a borderline
    /// `ReviewQueue` — with no LLM tie-break already applied — is delivered. Never
    /// downgrades a quarantine; opt-in because it lets trust override a
    /// deterministic borderline hold.
    #[serde(default)]
    pub trusted_sender_allow_relax: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        // Both off + no trusted domains — opt-in per the cost-safe +
        // security-conservative defaults.
        Self {
            llm_tiebreak: false,
            llm_tiebreak_allow_downgrade: false,
            trusted_domains: Vec::new(),
            trusted_sender_policy: false,
            trusted_sender_allow_relax: false,
        }
    }
}

/// F4-01 Phase 1 — default Ecology auto-scheduler cadence: 6h.
pub const DEFAULT_ECOLOGY_SCHEDULER_INTERVAL_SECS: u64 = 6 * 3600;

/// CH-13 / F4-01 — Ecology self-adaptation layer knobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EcologyConfig {
    /// Master switch for the 6h auto-scheduler (F4-01 Phase 1). Off by default
    /// per the AGENTER hard rule (matches `proactive.enabled` / `dreaming.enabled`).
    /// Does NOT gate the read-only `neoth ecology correlation` scan. When ON, the
    /// scheduler only ever STAGES `neoth self-dev` proposals (never auto-applies)
    /// + emits `0x4C ECOLOGY_SCHEDULER_FIRED` — the DESIGN_CH13 P2 review-gate.
    pub enabled: bool,
    /// F4-01 — minimum consecutive same-winner streak the correlation scan
    /// reports as a low-dissent signal. Default 5. Doubles as the scheduler's
    /// fire-threshold (a streak ≥ this triggers a self-dev proposal pass).
    pub correlation_min_streak: usize,
    /// F4-01 Phase 1 — auto-scheduler tick interval in seconds. Default 6h.
    /// Clamped to a 60s floor by [`EcologyConfig::scheduler_interval_duration`].
    pub scheduler_interval_secs: u64,
}

impl Default for EcologyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            correlation_min_streak: 5,
            scheduler_interval_secs: DEFAULT_ECOLOGY_SCHEDULER_INTERVAL_SECS,
        }
    }
}

impl EcologyConfig {
    /// Scheduler tick interval as a [`std::time::Duration`], clamped to a 60s
    /// floor so a misconfigured `0` can't spin the cron loop hot.
    pub fn scheduler_interval_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.scheduler_interval_secs.max(60))
    }
}

/// GM-01 — agentic tool-use turn budget knobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct GoalConfig {
    /// Hard ceiling on MCP autoroute dispatch-loop iterations (each iteration is
    /// one provider call + a round of tool calls). Bounds a model that keeps
    /// emitting tool-call fences from burning budget. Default 5 (the prior
    /// hardcoded `dispatch_loop::DEFAULT_MAX_ITERATIONS`); raise it for deeper
    /// tool chains, lower it for a tighter leash.
    pub max_turns: u32,
    /// GOLD-ADOPT-22 — a one-shot GOAL. When set, the dispatch loop injects ONE
    /// invisible "before finishing, check this goal is met" nudge the first time
    /// the model would stop, then lets the next clean exit end the loop. `None`
    /// (default) = no goal nudge.
    #[serde(default)]
    pub goal: Option<String>,
    /// GOLD-ADOPT-22 — a relentless GRIND objective. When set, EVERY clean exit
    /// injects a "keep working, not done yet" nudge until `max_turns` is hit, so
    /// the model can't stop early. `None` (default) = no grind. Clear it when the
    /// objective is done — a persistent grind burns budget every turn.
    #[serde(default)]
    pub grind: Option<String>,
}

impl Default for GoalConfig {
    fn default() -> Self {
        // 5 = the prior hardcoded dispatch-loop cap (no behaviour change).
        Self {
            max_turns: 5,
            goal: None,
            grind: None,
        }
    }
}

/// GOLD-ADOPT-18 — subdirectory-hint injection knobs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct HintsConfig {
    /// Auto-inject a subdirectory's `.neothhints` / `AGENTS.md` into the agent's
    /// context the first time it enters that dir via a tool-call path arg.
    /// Default ON (per the features-default-on hard rule); the hint FILES are
    /// the real opt-in, but this flag is the global kill switch operators can
    /// flip in `freedom.yaml` without recompiling.
    pub enabled: bool,
}

impl Default for HintsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// OM-01 — local OMI transcript-ingest knobs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct OmiConfig {
    /// Off by default — opt-in. When `true` the daemon polls `endpoint` and the
    /// SC-14 startup gate REFUSES a non-local `endpoint` (e.g. `api.omi.me`).
    pub enabled: bool,
    /// The LOCAL OMI backend base URL. Default `http://127.0.0.1:8002`.
    pub endpoint: String,
    /// Poll interval (seconds). Default 30; floored at 5.
    pub poll_interval_secs: u64,
    /// A transcript item at/above this score is promoted to ground-truth +
    /// audited (`0x9C`). Default 0.75.
    pub confidence_threshold: f32,
}

impl Default for OmiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: crate::installers::omi::DEFAULT_OMI_ENDPOINT.to_string(),
            poll_interval_secs: 30,
            confidence_threshold: 0.75,
        }
    }
}

/// MM-01b/02b/03b — cloud media opt-ins. ALL default OFF (`false`). Each flag,
/// when `true`, means the operator has accepted that THIS media type leaves the
/// device for a cloud provider. Audio/image/video are more sensitive than text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct MediaConfig {
    /// Cloud speech-to-text (OpenAI Whisper / Azure Speech). On = your AUDIO
    /// leaves the device to be transcribed. Local candle STT needs no flag.
    pub cloud_stt_enabled: bool,
    /// Cloud text-to-speech (Azure / ElevenLabs). On = your TEXT leaves the
    /// device to be synthesised into audio.
    pub cloud_tts_enabled: bool,
    /// Cloud vision (Anthropic / OpenAI / Gemini). On = your IMAGES/frames leave
    /// the device for a multimodal model.
    pub cloud_vision_enabled: bool,
    /// Upload decoded VIDEO FRAMES to a cloud vision provider. Distinct from
    /// `cloud_vision_enabled` (a single still vs a sampled sequence of frames):
    /// a video upload exposes far more, so it is its own opt-in.
    pub video_frame_upload_enabled: bool,
    /// P0 "proof-hardline": when true, a cloud STT/TTS/Vision/Video operation
    /// that CANNOT be audited (no WAL sink available) is REFUSED rather than run
    /// best-effort. Default `false` — the normal posture audits best-effort; flip
    /// on when every cloud-media call must be provable or not happen at all.
    ///
    /// COVERAGE NOTE: this flag is enforced by the audited wrappers
    /// (`media::stt_provider::transcribe_and_audit`,
    /// `media::tts_cloud::synth_and_audit`,
    /// `media::video_dispatch::dispatch_video_analysis`). Until the channel
    /// pipeline routes cloud media THROUGH those wrappers, the protection only
    /// applies where they are called. The `tests/no_unaudited_media_calls.rs`
    /// source guard prevents a new caller from bypassing them; wiring them onto
    /// the production hot path is the remaining step before this flag is a
    /// whole-product guarantee.
    pub required_audit_for_cloud_media: bool,
}

/// EM-02b — CalDAV calendar-write knobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CalendarConfig {
    /// Master kill switch for `neoth calendar add`. Default `true` — the
    /// surface ships usable (writes are still gated by the autonomy/consent
    /// `ExternalTaskWrite` path + audited `0xCA CALENDAR_WRITE`). Flip to
    /// `false` to make calendar writes refuse fail-closed regardless of grant.
    pub writes_enabled: bool,
}

impl Default for CalendarConfig {
    fn default() -> Self {
        Self {
            writes_enabled: true,
        }
    }
}

/// SPEC-11 — default minimum interval (ms) between in-place edits to one live
/// message. 800ms is comfortably under Telegram's ~1 edit/sec soft limit.
pub const DEFAULT_LIVE_EDIT_MIN_INTERVAL_MS: u64 = 800;
/// SPEC-11 — default cap on edits per live message before further intermediate
/// edits are dropped (the final edit still lands — see `final_edit_always_allowed`).
pub const DEFAULT_LIVE_MAX_EDITS_PER_MESSAGE: u32 = 50;

/// SPEC-11 — outbound live-delivery (send-then-edit) rate-limit knobs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LiveDeliveryConfig {
    /// Master switch for in-place edits. Default `true`. When `false`,
    /// `LiveDelivery` only ever SENDS (never edits) — the safest posture for a
    /// channel that rate-limits edits aggressively.
    pub edits_enabled: bool,
    /// Minimum ms between consecutive edits to the same message. An edit that
    /// arrives sooner is COALESCED (dropped) unless it is the final edit.
    pub min_edit_interval_ms: u64,
    /// Hard cap on edits per message. Beyond it, intermediate edits are dropped.
    pub max_edits_per_message: u32,
    /// The final edit (the completed reply) ALWAYS lands, even past the
    /// interval/count limits — so the operator never sees a truncated draft.
    pub final_edit_always_allowed: bool,
}

impl Default for LiveDeliveryConfig {
    fn default() -> Self {
        Self {
            edits_enabled: true,
            min_edit_interval_ms: DEFAULT_LIVE_EDIT_MIN_INTERVAL_MS,
            max_edits_per_message: DEFAULT_LIVE_MAX_EDITS_PER_MESSAGE,
            final_edit_always_allowed: true,
        }
    }
}

/// KF-05 — whose replies are allowed to move the channel-acceptance weights.
/// Default [`ChannelLearnScope::OperatorOnly`] so a non-operator on a shared
/// channel can't poison the recall-ranking context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelLearnScope {
    /// Only the operator's own `human_uuid` (the C-13 cross-channel identity)
    /// moves the weights. The safe default.
    #[default]
    OperatorOnly,
    /// The operator + any allowlisted sender moves the weights at full strength.
    Allowlisted,
    /// Everyone moves the weights, but a non-operator/non-allowlisted sender
    /// only at a tiny fraction (poisoning-resistant but still adaptive).
    AllTiny,
}

/// KF-05 — channel-acceptance learning-scope knobs.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ChannelWeightsConfig {
    /// Whose successful replies move the Hebbian weights.
    pub learn_scope: ChannelLearnScope,
    /// The operator's own cross-channel `human_uuid` (C-13). When set, the scope
    /// gate can strictly distinguish the operator from everyone else. When
    /// `None` (default fresh install) the gate treats every sender as the
    /// operator — a solo install has only the operator, and refusing to learn
    /// would make KF-05 inert — so pin this to lock down a shared/open channel.
    pub operator_human_uuid: Option<String>,
    /// Additional `human_uuid`s trusted to move the weights under the
    /// `allowlisted` / `all_tiny` scopes (the operator is always trusted).
    pub allowlisted_human_uuids: Vec<String>,
}

/// EL-02 — arXiv topic-feed ingest task knobs.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ArxivIngestConfig {
    /// Master switch. `false` = task never spawns. `true` AND a
    /// non-empty `topics` list = spawn the interval task at boot.
    pub enabled: bool,
    /// Tick interval in seconds. `None` = 21_600 (6h — well clear of
    /// arXiv's politeness window for an anonymous client).
    pub interval_secs: Option<u64>,
    /// Operator-curated topic queries in arXiv query syntax:
    /// `cat:cs.CL`, `all:rag`, `ti:diffusion AND cat:cs.CV`, …
    pub topics: Vec<String>,
    /// Max results fetched per topic per tick. `None` = 10. The
    /// underlying `arxiv::search` clamps to the API cap of 50.
    pub max_per_topic: Option<usize>,
    /// `source_category` bucket label for the ctx index rows. `None`
    /// = `"arxiv"`.
    pub source_category: Option<String>,
}

impl Default for ArxivIngestConfig {
    fn default() -> Self {
        // Off by default — opt-in gate per the noob-wizard rule.
        Self {
            enabled: false,
            interval_secs: None,
            topics: Vec::new(),
            max_per_topic: None,
            source_category: None,
        }
    }
}

/// NOOB-UX-3 plugin runtime gates.
///
/// `wasm.enabled` — master switch for the WASM plugin host.
/// `false` makes the daemon skip plugin discovery + skip the
/// `bootstrap_plugin_invoker` call so hook-engine `Plugin`
/// actions degrade to Allow (same as a slim daemon build).
/// Default is `true` because the wizard-shipped release
/// AR-03 (Session 24) — per-stage hook chain policy. Operators
/// drop one entry per stage they want stricter behaviour on.
///
/// Example freedom.yaml:
///
/// ```yaml
/// hook_chain:
///   pre_provider_call:
///     fail_fast: true
///   post_provider_call:
///     fail_fast: false
/// ```
///
/// Today only `fail_fast` is honoured. Future fields (`max_chain_depth`,
/// `priority_floor`, `timeout_ms`) land here without another schema
/// touch — the map shape absorbs additions cleanly.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HookChainConfig {
    /// When `true`, the dispatcher escalates a hook regex-compile
    /// failure at this stage from skip-and-warn to
    /// `StageOutcome::Block`. Default `false` preserves the pre-AR-03
    /// lenient behaviour. Use `true` for stages where a misconfigured
    /// safety hook should stop the turn rather than silently fall back
    /// to allow.
    #[serde(default)]
    pub fail_fast: bool,
}

impl FreedomConfig {
    /// AR-03 — look up the configured policy for `stage` and return
    /// the `fail_fast` flag. Returns `false` for any stage the
    /// operator hasn't pinned (= legacy lenient behaviour).
    pub fn fail_fast_for_stage(&self, stage: crate::hooks::stages::HookStage) -> bool {
        self.hook_chain
            .get(stage.as_str())
            .map(|cfg| cfg.fail_fast)
            .unwrap_or(false)
    }
}

/// already compiled the feature on; operators who want a
/// quieter daemon flip it to `false`.
///
/// Future: per-plugin allowlist (`plugins.wasm.allow = ["hello",
/// "morning-news"]`) — restricts which plugin IDs the
/// discovery sweep accepts.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PluginsConfig {
    #[serde(default)]
    pub wasm: WasmPluginsConfig,
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
    /// D-102 (Session 21, 2026-05-23, 6/6 agent panel) — per-plugin
    /// operator activation. Keyed by manifest id. Newly discovered
    /// ids default to [`PluginActivation::Pending`] and are NOT
    /// instantiated until the operator runs `neoth plugin enable
    /// <id>` (or accepts them via the first-run wizard multiselect).
    ///
    /// Why default-inactive: wasmtime sandbox is strong but the
    /// hostcall surface (channel send, fs, WAL) is the attack
    /// vector — auto-instantiating an unknown `.wasm` bypasses the
    /// consent gate every other auto-discovery path in NEOTH
    /// (channels, providers, skills) already respects. Matches the
    /// conservative defaults n8n + Obsidian already use.
    #[serde(default)]
    pub activations:
        std::collections::BTreeMap<String, crate::wasm_plugin::discovery::PluginActivation>,
    /// SC-03 — operator-pinned `plugin.wasm` SHA-256 hashes, keyed by
    /// manifest id (lowercase hex). Before instantiating a plugin the
    /// daemon recomputes the hash and refuses to run it on a mismatch
    /// (tamper / supply-chain swap). Empty by default → no gate; the
    /// operator pins the hashes they trust (surfaced by `neoth plugin
    /// list`). Opt-in-secure: existing unsigned plugins keep loading
    /// until the operator pins them.
    #[serde(default)]
    pub pinned_hashes: std::collections::BTreeMap<String, String>,
    /// SC-03 — when true, a plugin with NO pinned hash is refused
    /// instead of loaded ("deny anything I haven't explicitly
    /// trusted"). Default `false` for back-compat.
    #[serde(default)]
    pub require_all_pinned: bool,
    /// SC-03 — operator's trusted plugin-author minisign PUBLIC key
    /// (base64 of the key line, as `minisign -G` / `rsign generate`
    /// prints it). When set, the daemon verifies each plugin's
    /// `plugin.wasm.minisig` companion against it before instantiation —
    /// proving WHO signed the binary (authenticity), complementing the
    /// hash pin (which only proves the bytes didn't change). `None`
    /// (default) → no signature checking. Sign a plugin with
    /// `minisign -Sm plugin.wasm`.
    #[serde(default)]
    pub author_pubkey: Option<String>,
    /// SC-03 — when true AND `author_pubkey` is set, a plugin with no
    /// valid signature companion is refused ("deny anything not signed
    /// by my trusted author"). Default `false`: a missing signature is
    /// allowed (soft gate) but a PRESENT-but-invalid signature is ALWAYS
    /// refused regardless of this flag.
    #[serde(default)]
    pub require_signature: bool,
    /// SC-03 — revoked plugin ids, refused outright regardless of hash
    /// pin or signature (a known-bad-plugin kill switch). Default empty.
    #[serde(default)]
    pub revoked_ids: Vec<String>,
}

fn default_wasm_plugins_enabled() -> bool {
    // Default ON to honour the neoth-features-default-on
    // hard rule for shipped release binaries. Operators on a
    // slim build (no wasm-plugin-host feature) see no effect
    // either way.
    //
    // NOTE: D-102 (Session 21) — `enabled: true` only governs whether
    // the HOST is live. Each individual plugin still requires the
    // operator to flip its `activations[id]` to `Active` before it
    // runs. Default-on host + default-inactive plugins is the
    // intentional combination: zero-friction for operators who never
    // install any plugins; explicit consent for those who do.
    true
}

impl Default for WasmPluginsConfig {
    fn default() -> Self {
        Self {
            enabled: default_wasm_plugins_enabled(),
            activations: std::collections::BTreeMap::new(),
            pinned_hashes: std::collections::BTreeMap::new(),
            require_all_pinned: false,
            author_pubkey: None,
            require_signature: false,
            revoked_ids: Vec::new(),
        }
    }
}

/// EL-01 follow-up (Session 26): operator-tunable doctor cron knobs.
/// Mirrors the daemon-side `DoctorCronConfig` shape but lives here so
/// `freedom.yaml::doctor.interval_secs` deserialises without the
/// config layer pulling in the daemon crate (circular).
///
/// Default mirrors `daemon::doctor_cron::DEFAULT_CRON_INTERVAL_SECS`
/// (1h tick). Operator-facing fields only — pluggable notification
/// sink stays out of the schema until an operator asks for it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DoctorConfig {
    /// Master runtime switch. `false` disables the doctor cron loop
    /// entirely without recompiling, per the
    /// `neoth-features-default-on-runtime-toggle` rule.
    #[serde(default = "default_doctor_enabled")]
    pub enabled: bool,
    /// Tick interval in seconds. Clamped to a 60s floor downstream so
    /// an accidental `0` doesn't tight-loop the daemon.
    #[serde(default = "default_doctor_interval_secs")]
    pub interval_secs: u64,
}

fn default_doctor_enabled() -> bool {
    true
}

fn default_doctor_interval_secs() -> u64 {
    3600
}

impl Default for DoctorConfig {
    fn default() -> Self {
        Self {
            enabled: default_doctor_enabled(),
            interval_secs: default_doctor_interval_secs(),
        }
    }
}

/// U-04 follow-up (Session 26): operator-tunable updater cron knobs.
/// Mirrors the daemon-side `UpdaterCronConfig` shape; same circular-
/// dep reason for living in the config crate.
///
/// Default mirrors `daemon::updater_cron::DEFAULT_UPDATER_INTERVAL_SECS`
/// (6h tick). All three updater lanes (neoth_self, cli_version,
/// skill_plugin) share the interval today — per-lane override lands
/// when an operator asks for it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdaterConfig {
    #[serde(default = "default_updater_enabled")]
    pub enabled: bool,
    #[serde(default = "default_updater_interval_secs")]
    pub interval_secs: u64,
    /// HF-01: when `false`, `neoth model pull` REFUSES HuggingFace model
    /// downloads (air-gapped / bandwidth-controlled / consent-gated
    /// deployments). Default `true` so the common path is unaffected.
    /// The download path reads this before any network fetch + emits the
    /// `0xD7/0xD8 MODEL_DOWNLOAD_*` audit frames around a permitted pull.
    #[serde(default = "default_allow_huggingface_downloads")]
    pub allow_huggingface_downloads: bool,
    /// SC-10 — per-model download policy overriding the global
    /// `allow_huggingface_downloads` flag for specific model ids. An
    /// entry `"<repo_or_model_id>": false` blocks ONLY that model even
    /// when the global flag is `true` (and vice-versa: `true` permits a
    /// single model on an otherwise air-gapped install). Absent entry ⇒
    /// the global flag applies. Default empty (global flag governs all).
    #[serde(default)]
    pub model_download_policy: std::collections::HashMap<String, bool>,
}

impl UpdaterConfig {
    /// SC-10 — whether a HuggingFace download is permitted. A per-model
    /// entry in `model_download_policy` takes precedence over the global
    /// `allow_huggingface_downloads`; absent ⇒ the global flag.
    ///
    /// A model has TWO identifiers an operator might key the policy by:
    /// the short CLI name (`whisper` — what you pass to `neoth model pull`)
    /// and the full HuggingFace repo string (`openai/whisper-large-v3-turbo`
    /// — what the download code uses internally). The repo BASENAME
    /// (`whisper-large-v3-turbo`) is neither, so a naive last-segment split
    /// would miss. Both identifiers are checked explicitly; an explicit
    /// entry under EITHER governs (a `false` under either blocks).
    pub fn model_download_allowed(&self, model_id: &str, name: Option<&str>) -> bool {
        for key in [Some(model_id), name].into_iter().flatten() {
            if let Some(&explicit) = self.model_download_policy.get(key) {
                return explicit;
            }
        }
        self.allow_huggingface_downloads
    }

    /// SC-10 — gate a model download, returning an actionable error when
    /// blocked. Keeps the policy-map logic inside `UpdaterConfig` so the
    /// CLI call site never reaches back into the internal `HashMap` to
    /// reconstruct which gate fired. Pass both the full repo `model_id`
    /// and the short CLI `name` so a policy entry keyed by either matches.
    /// `Ok(())` ⇒ permitted.
    pub fn check_model_download(&self, model_id: &str, name: Option<&str>) -> Result<(), String> {
        if self.model_download_allowed(model_id, name) {
            return Ok(());
        }
        // Blocked. Distinguish a per-model policy entry (under either
        // identifier) from the global flag for a precise error message.
        let per_model = self.model_download_policy.contains_key(model_id)
            || name
                .map(|n| self.model_download_policy.contains_key(n))
                .unwrap_or(false);
        if per_model {
            Err(format!(
                "model download blocked: freedom.yaml::updater.model_download_policy for \
                 `{model_id}` = false (per-model policy). Set it to true (or remove it) to \
                 permit this model."
            ))
        } else {
            Err(format!(
                "model download blocked: freedom.yaml::updater.allow_huggingface_downloads = \
                 false. Set it to true (or add updater.model_download_policy with `{model_id}` = \
                 true) to permit HuggingFace fetches."
            ))
        }
    }
}

fn default_updater_enabled() -> bool {
    true
}

fn default_updater_interval_secs() -> u64 {
    6 * 3600
}

fn default_allow_huggingface_downloads() -> bool {
    true
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            enabled: default_updater_enabled(),
            interval_secs: default_updater_interval_secs(),
            allow_huggingface_downloads: default_allow_huggingface_downloads(),
            model_download_policy: std::collections::HashMap::new(),
        }
    }
}

/// MV-01b prereq #3 — which OS-native process supervisor keeps `neoth
/// serve` running + restarts it (so unattended self-update can activate
/// the new binary). Wizard step writes the resolved kind; `None` =
/// no supervisor installed (self-update degrades to stage-and-notify).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorKind {
    /// systemd user unit (`~/.config/systemd/user/neoth.service` +
    /// `loginctl enable-linger`). No root.
    SystemdUser,
    /// launchd LaunchAgent (`~/Library/LaunchAgents/io.neoth.daemon.plist`).
    LaunchdAgent,
    /// Windows Task Scheduler `onlogon` task pointing at the built-in
    /// `neoth supervisor-loop` restart wrapper. No admin.
    WindowsTask,
    /// No supervisor installed.
    #[default]
    None,
}

impl SupervisorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SupervisorKind::SystemdUser => "systemd_user",
            SupervisorKind::LaunchdAgent => "launchd_agent",
            SupervisorKind::WindowsTask => "windows_task",
            SupervisorKind::None => "none",
        }
    }
}

/// MV-01b prereq #3 — operator supervisor state. Off by default per the
/// noob-wizard opt-in rule. `enabled = false` → no auto-restart, so
/// self-update stages the new binary + notifies but never relaunches.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct SupervisorConfig {
    pub enabled: bool,
    pub kind: SupervisorKind,
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
    /// ADV-03 item 4 (Session 24): when `true` (default for fresh
    /// installs) AND `learn_enabled` is also true, the extracted
    /// `ProfileDelta` flows through a Stage-5b approval gate before
    /// `apply_delta` writes it to `idx_profile`. tty-attached
    /// callers see a `dialoguer::Confirm`; daemon-mode callers park
    /// the delta in `idx_profile_pending` + emit
    /// `EVENT_TYPE_PROFILE_DELTA_PENDING` (0xB5) for the operator to
    /// resolve via `neoth profile approve <id>` / `decline <id>`.
    ///
    /// `AutonomyLevel::Strict` always confirms regardless of this
    /// flag; `Full` skips the gate unconditionally; `Standard` and
    /// `Elevated` respect the flag.
    ///
    /// Existing operators on freedom.yaml without this field inherit
    /// `true` via the serde default — opt-out is the explicit
    /// operator action.
    #[serde(default = "default_profile_require_approval")]
    pub require_approval: bool,
    /// ADV-05 (Session 28): PII categories that MUST NOT be injected
    /// into the Block-B prompt context, even if `idx_profile` holds
    /// active high-confidence claims for them. Today disabling a
    /// category in extraction stops NEW claims from landing, but
    /// historical rows continue to leak into Block-B for the
    /// row's full TTL (~276 days). This gate lets the operator
    /// say "stop using anything you know about my location" + have
    /// the effect take hold on the NEXT chat turn, not 9 months
    /// from now.
    ///
    /// Values are top-level category names (`identity` / `health` /
    /// `location` / `relationships` / etc.); they match the segment
    /// returned by `crate::profile::extension_registry::TypedExtensionRegistry::category_of`.
    /// Empty default → backwards-compatible with existing freedom.yaml
    /// files (no fields skipped).
    ///
    /// To wipe the underlying rows (not just hide them from
    /// injection) the operator runs `neoth memory --forget <topic>`
    /// or `neoth profile redact`; this flag is the soft / reversible
    /// counterpart.
    #[serde(default)]
    pub pii_categories_disabled: Vec<String>,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            learn_enabled: default_profile_learn_enabled(),
            timeout_secs: default_profile_timeout_secs(),
            learn_provider: default_profile_learn_provider(),
            allow_cloud_fallback: default_profile_allow_cloud_fallback(),
            require_approval: default_profile_require_approval(),
            pii_categories_disabled: Vec::new(),
        }
    }
}

fn default_profile_learn_enabled() -> bool {
    false
}

fn default_profile_timeout_secs() -> u64 {
    15
}

/// ADV-03 item 4: fresh installs default to `require_approval = true`.
/// Operators on existing freedom.yaml without this field also inherit
/// `true` via serde — opt-out is the explicit operator action (set
/// `profile.require_approval: false`).
fn default_profile_require_approval() -> bool {
    true
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
    /// only path that works reliably for tmux-based setups — see memory
    /// `neoth-claude-cli-tmux-mandatory.md`); `subprocess` forces the
    /// cold-start `claude --print` path (broken on some hosts but
    /// kept as a Windows-without-WSL escape hatch).
    #[serde(default)]
    pub backend: ClaudeCliBackendCfg,
    /// Tmux backend tuning. Ignored when `backend == subprocess`.
    #[serde(default)]
    pub tmux: ClaudeCliTmuxConfig,
    /// Env-var prefixes to strip from the spawned `claude` subprocess's
    /// environment, so the operator's OTHER agent-stack secrets never
    /// reach the model. Default empty — declare your own if you run NEOTH
    /// alongside another agent framework that exports prefixed env vars
    /// (e.g. `["MYGATEWAY_", "MYAGENT_"]`). NEOTH always strips its own
    /// `NEOTH_*` (except `NEOTH_LOG`), CI markers, `CLAUDECODE_*` and TMUX
    /// vars regardless of this list.
    #[serde(default)]
    pub scrub_env_prefixes: Vec<String>,
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
    /// = 120. Read by `providers::mod::build_provider` and threaded into
    /// `ClaudeCliAdapter::new_with_backend_and_timeouts` (Pick #35).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Per-request absolute cap. claude_tmux returns
    /// `HardTimeoutNoOutput` past this. Bridge.py default = 300.
    /// Read alongside `idle_timeout_secs` at `providers/mod.rs`
    /// build-time (Pick #35).
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
    // `NEOTH_HOME` overrides everything — used by CI, integration tests,
    // and operators who keep `~/.neoth` on a non-default mount. The
    // override IS the home dir (no `.neoth` suffix appended). HOME /
    // USERPROFILE fallback keeps the long-standing default.
    if let Ok(explicit) = std::env::var("NEOTH_HOME") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
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

// ─── Round-3 v0.4 ARCH-07 / ARCH-04 sub-configs ────────────────────────────

/// Round-3 v0.4 ARCH-07 — LOWKEY skill versioning + eval-session
/// suppression operator-config.
///
/// `disabled_for_eval_sessions`: when `true` AND the daemon is
/// running in an eval session (env `NEOTH_EVAL_SESSION=1` or
/// `freedom.yaml::eval_session_active = true`), all skill injection
/// into the prompt bundle is suppressed + emits
/// `EVENT_TYPE_SKILL_INJECT_SKIPPED` (WAL `0x29`) per skipped skill.
/// Operators running benchmark suites use this to ensure the eval
/// baseline isn't biased by behavioural skills.
///
/// `eval_session_active`: marker flag operators flip when starting
/// an eval run. Persists across daemon restarts so a long eval
/// suite doesn't accidentally reset.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillsConfig {
    /// Suppress skill injection during eval sessions.
    /// Default false — operators opt in for eval runs.
    #[serde(default)]
    pub disabled_for_eval_sessions: bool,
    /// Whether the daemon is currently in an eval session. Operators
    /// flip on before starting a benchmark suite + flip off after.
    /// Also honoured via env `NEOTH_EVAL_SESSION=1` for one-shot
    /// CLI eval invocations.
    #[serde(default)]
    pub eval_session_active: bool,
    /// ARCH-07 (Session 28) — pinned content_hash per skill_id. When
    /// a skill is loaded, the loader's computed `content_hash` is
    /// compared against the operator's pinned hash; mismatch drops
    /// the skill from injection + emits one
    /// `EVENT_TYPE_SKILL_INJECT_SKIPPED` (0x29) with
    /// `reason = hash_mismatch` + both expected + actual hashes in
    /// the payload. Operator's defence against "someone or something
    /// silently edited my skill's system_prompt".
    ///
    /// Format in freedom.yaml:
    /// ```yaml
    /// skills:
    ///   pinned_hashes:
    ///     code-reviewer: "abc123…"
    ///     security-reviewer: "def456…"
    /// ```
    /// Empty map = no integrity check (default behaviour — opt-in).
    /// Skills NOT in the map are not gated (operator pins what they
    /// care about; bundled skills can drift across NEOTH releases
    /// without pinning every one).
    #[serde(default)]
    pub pinned_hashes: std::collections::HashMap<String, String>,
    /// PF-01 (Session 30) — when `true`, the chat router runs Stage-2
    /// embedding cosine re-rank on EVERY turn (not only on a keyword
    /// Stage-1 miss), and a Stage-2 hit (cosine ≥ `EMBEDDING_THRESHOLD`)
    /// takes precedence over the keyword match. This makes the skill
    /// library route by SEMANTICS by default rather than only when a
    /// literal keyword is present — so a request whose wording misses
    /// the keyword, or hits the wrong skill's keyword, still lands on
    /// the semantically-closest skill.
    ///
    /// Cost note: Stage-2 only runs at all when the operator has
    /// configured `inference.embedding_provider` (off by default), so a
    /// default install pays NOTHING here. For operators who DID opt into
    /// an embedding provider, this adds N+1 embed calls per turn (1
    /// message + 1 per enabled skill) on turns that previously short-
    /// circuited on a keyword hit — acceptable because configuring an
    /// embedding provider is itself the opt-in to that cost, and the
    /// per-skill embeds are cached within `route_stage2_embedding`'s
    /// invocation. Set `false` to restore the keyword-miss-only fallback.
    #[serde(default = "default_skills_always_embed_route")]
    pub always_embed_route: bool,
    /// GOLD-HON-11 (B-16) — operator blocklist of skill ids to disable,
    /// applied at load time. The security-research registers
    /// (`lowkey_base`, `raskal`, `archon`) ship bundled + ENABLED by
    /// default; an operator who does not want them turns them off here
    /// rather than editing the shipped `skill.yaml` (which an upgrade
    /// overwrites). Case-insensitive id match; unknown ids are ignored.
    ///
    /// ```yaml
    /// skills:
    ///   disabled:
    ///     - raskal
    ///     - archon
    /// ```
    /// Empty (default) = every bundled skill stays enabled.
    #[serde(default)]
    pub disabled: Vec<String>,
    /// GOLD-ADOPT-14 — operator allowlist of skill ids to force-ON, applied at
    /// load time. The complement of [`disabled`]: it turns ON a skill that ships
    /// `enabled: false` (e.g. the 68 imported `pm-*` product-management skills,
    /// which ship DISABLED so a non-PM operator's routing stays clean). Set via
    /// `neoth skill enable <id>`.
    ///
    /// ```yaml
    /// skills:
    ///   enabled:
    ///     - pm-create-prd
    ///     - pm-swot-analysis
    /// ```
    /// **`disabled` always wins** over `enabled` (a force-OFF can never be
    /// silently re-enabled — preserves the GOLD-HON-11 security-register
    /// guarantee). Case-insensitive id match; unknown ids ignored. Empty
    /// (default) = no force-ON overrides; ships-disabled skills stay disabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enabled: Vec<String>,
    /// Full-auto operating mode — when `true`, the loader force-enables EVERY
    /// bundled skill (including the 68 `pm-*` skills that ship `enabled: false`)
    /// so NEOTH proactively routes the entire library. The `disabled` blocklist
    /// still wins over this (an operator force-OFF — e.g. the RASKAL offensive
    /// register — is never silently re-enabled). Flipped together with
    /// `autonomy: full` by `neoth autonomy full-auto` / `neoth sudomode`; cleared
    /// by `neoth autonomy gated`.
    ///
    /// Routing-safety pairing: when this is `true` the chat + channel routers
    /// raise their confidence floor to [`crate::skills::router::FULL_AUTO_MIN_WEIGHT`]
    /// so a lone generic single-word trigger (now live across 98 skills) cannot
    /// false-activate a turn. Default `false` = gated mode = curated skill set.
    #[serde(default)]
    pub enable_all_bundled: bool,
}

fn default_skills_always_embed_route() -> bool {
    true
}

impl Default for SkillsConfig {
    fn default() -> Self {
        Self {
            disabled_for_eval_sessions: false,
            eval_session_active: false,
            pinned_hashes: std::collections::HashMap::new(),
            always_embed_route: default_skills_always_embed_route(),
            disabled: Vec::new(),
            enabled: Vec::new(),
            enable_all_bundled: false,
        }
    }
}

/// GOLD-ADOPT-26 — RSS / Atom / JSON-Feed poller config. Off by default; a
/// fresh install does zero network for feeds until the operator opts in.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct FeedsConfig {
    /// Master switch. `false` (default) → the poller never spawns.
    #[serde(default)]
    pub enabled: bool,
    /// Poll cadence in seconds. `None` → the task default (1 hour).
    #[serde(default)]
    pub interval_secs: Option<u64>,
    /// The feeds to poll. Empty (default) → nothing to do.
    #[serde(default)]
    pub entries: Vec<FeedEntry>,
}

/// One configured feed: a short label + the feed URL + an optional per-feed
/// entry cap. The label namespaces the ctx store keys (`rss:<label>:<hash>`).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct FeedEntry {
    /// Short operator-chosen label, e.g. `hn`, `rust_blog`.
    pub label: String,
    /// The feed URL (RSS / Atom / JSON Feed). SSRF-validated before each GET.
    pub url: String,
    /// Max entries ingested per tick for this feed. `None` → the task default.
    #[serde(default)]
    pub max_entries: Option<usize>,
}

/// GOLD-ADOPT-23 P0 — what the MCP tool-loop risk gate does when an LLM-issued
/// tool call carries a destructive shell pattern or an outbound egress target.
/// Surfacing (a tracing warn) ALWAYS happens; this controls whether the call is
/// additionally blocked.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct SecurityPolicy {
    /// Policy for a Critical-severity dangerous-command finding (rm -rf /, dd
    /// of=/dev, fork bomb, shutdown/reboot, …). Default `deny` — the LLM should
    /// never autonomously run a host-destroying command; the operator widens to
    /// `confirm`/`allow` to lift the block.
    #[serde(default)]
    pub dangerous_commands: DangerousPolicy,
    /// Outbound-egress policy (data leaving the host via a tool's shell args).
    #[serde(default)]
    pub egress: EgressPolicy,
    /// GOLD-ADOPT-23 P1 — when `true`, a HIGH-severity dangerous finding
    /// (`git push --force`, `curl … | sh`, …) also requires confirmation rather
    /// than warn-only. Default `false` (warn-only) to avoid false-positive
    /// friction; operators working against precious repos opt in.
    #[serde(default)]
    pub confirm_high: bool,
    /// GOLD-ADOPT-22 SmartApprove — the global MASTER switch. When `true`, a
    /// tool call the autonomy gate would `Confirm` MAY be AUTO-APPROVED if the
    /// tool's server-DECLARED EFFECT metadata (`readOnlyHint`, never its name)
    /// marks it read-only (and not destructive). Default `false` — a
    /// confirm-bypass is opt-in. GR-018: this master switch alone is NOT
    /// sufficient — the specific server must ALSO set `smart_approve: true` in
    /// its `McpServerConfig`, so enabling it for one trusted server never
    /// bypasses confirmation for the rest. Never lifts a `Deny`; every
    /// auto-approval is audited (`RISK_GATE_ALLOWED_BY_READONLY_CACHE`).
    #[serde(default)]
    pub smart_approve: bool,
}

/// Action for a Critical dangerous-command finding.
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DangerousPolicy {
    /// Block the call (default). The reason names the matched rule.
    #[default]
    Deny,
    /// Block + tell the LLM the operator must confirm it.
    Confirm,
    /// Don't block — warn only (the pre-P0 behaviour).
    Warn,
}

/// Outbound-egress gate policy.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct EgressPolicy {
    /// How to treat a destination domain NOT in [`EgressPolicy::allowlist`].
    #[serde(default)]
    pub mode: EgressMode,
    /// Known-good domains that always pass (exact or suffix match, e.g.
    /// `github.com` matches `api.github.com`).
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// What the egress gate does about an UNKNOWN (non-allowlisted) destination.
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// Allow any destination — warn only (default; non-breaking).
    #[default]
    Allow,
    /// Block an unknown destination + tell the LLM the operator must confirm.
    ConfirmUnknown,
    /// Block an unknown destination outright.
    DenyUnknown,
}

impl SkillsConfig {
    /// True iff skills should be suppressed for this turn (config flag
    /// AND eval mode active OR env var). Pure-fn so the skill router
    /// can short-circuit without re-reading env.
    pub fn should_suppress_for_eval(&self) -> bool {
        let env_active = std::env::var("NEOTH_EVAL_SESSION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        self.disabled_for_eval_sessions && (self.eval_session_active || env_active)
    }
}

/// Round-3 v0.4 ARCH-04 — operator-tunable token cap for the
/// prompt-bundle pre-flight check.
///
/// `max_per_request`: total token cap across all blocks (A+B+C+D+E)
/// before degradation fires. Default 100_000 covers Opus 4.7 (200k
/// context) + Sonnet 4.6 (200k) + Gemini 3 (1M) with significant
/// response headroom. Operators on smaller-context models lower this
/// to match. The hardcoded `cli::chat::DEFAULT_PROMPT_TOKEN_CAP` falls
/// back to this value when callers don't pass an override.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokensConfig {
    /// Total token cap per provider request before
    /// `tokens::budget::enforce_budget` degradation policy fires.
    #[serde(default = "TokensConfig::default_max_per_request")]
    pub max_per_request: u32,
}

impl Default for TokensConfig {
    fn default() -> Self {
        Self {
            max_per_request: Self::default_max_per_request(),
        }
    }
}

impl TokensConfig {
    pub fn default_max_per_request() -> u32 {
        100_000
    }
}

/// GOLD-ADOPT-19 — auto context-compaction for the agentic tool-dispatch loop.
/// When the loop's accumulated prompt crosses `threshold_fraction` of
/// `tokens.max_per_request`, an LLM summarization pass replaces the older
/// history with a dense `[CONTEXT SUMMARY]`. Default-on but high-threshold, so
/// it only fires on genuinely long tool chains.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CompactionConfig {
    /// Master switch. `false` → the loop never compacts (no extra LLM calls).
    #[serde(default = "CompactionConfig::default_enabled")]
    pub enabled: bool,
    /// Compaction fires when the prompt's estimated tokens reach this fraction
    /// of `tokens.max_per_request`. Clamped to (0.0, 1.0]; a bad value disables
    /// compaction (fail-safe). NOTE: `max_per_request` is NEOTH's pre-flight
    /// cap, NOT the model's real context window (the catalog stores no
    /// per-model window). Operators on a large-context model should raise
    /// `tokens.max_per_request` to match so compaction doesn't fire early.
    #[serde(default = "CompactionConfig::default_threshold_fraction")]
    pub threshold_fraction: f32,
    /// Opt-in: also compact after every tool-pair once a lower threshold is
    /// crossed (more aggressive, more LLM calls). Default off.
    #[serde(default)]
    pub progressive: bool,
}

impl CompactionConfig {
    pub fn default_enabled() -> bool {
        true
    }
    pub fn default_threshold_fraction() -> f32 {
        0.8
    }
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            threshold_fraction: Self::default_threshold_fraction(),
            progressive: false,
        }
    }
}

#[cfg(test)]
mod sub_config_tests {
    use super::*;

    #[test]
    fn skills_config_default_eval_disabled() {
        let cfg = SkillsConfig::default();
        assert!(!cfg.disabled_for_eval_sessions);
        assert!(!cfg.eval_session_active);
        assert!(!cfg.should_suppress_for_eval());
    }

    #[test]
    fn skills_config_always_embed_route_defaults_true_consistently() {
        // PF-01: `::default()` AND a freedom.yaml that OMITS the field
        // must agree (both true) — a divergence would make code-built
        // configs route differently from loaded ones.
        assert!(SkillsConfig::default().always_embed_route);
        let from_empty: SkillsConfig =
            serde_yaml::from_str("{}").expect("empty skills block deserialises");
        assert!(
            from_empty.always_embed_route,
            "omitted always_embed_route must default true to match ::default()"
        );
        // And an explicit false round-trips.
        let off: SkillsConfig =
            serde_yaml::from_str("always_embed_route: false\n").expect("explicit false");
        assert!(!off.always_embed_route);
    }

    #[test]
    fn skills_config_suppress_requires_both_flags() {
        // Mutates the process-global NEOTH_EVAL_SESSION — take the
        // crate env lock so it can't race the sibling test below (or
        // any other env test) under the multi-threaded runner.
        let _env = crate::test_env::lock();
        let mut cfg = SkillsConfig::default();
        cfg.disabled_for_eval_sessions = true;
        // Without eval_session_active OR env → still false.
        unsafe { std::env::remove_var("NEOTH_EVAL_SESSION") };
        assert!(!cfg.should_suppress_for_eval());
        cfg.eval_session_active = true;
        assert!(cfg.should_suppress_for_eval());
    }

    #[test]
    fn skills_config_suppress_honours_env_var() {
        let _env = crate::test_env::lock();
        let mut cfg = SkillsConfig::default();
        cfg.disabled_for_eval_sessions = true;
        cfg.eval_session_active = false;
        unsafe { std::env::set_var("NEOTH_EVAL_SESSION", "1") };
        assert!(cfg.should_suppress_for_eval());
        unsafe { std::env::remove_var("NEOTH_EVAL_SESSION") };
    }

    #[test]
    fn tokens_config_default_is_100k() {
        assert_eq!(TokensConfig::default().max_per_request, 100_000);
        assert_eq!(TokensConfig::default_max_per_request(), 100_000);
    }

    #[test]
    fn tokens_config_serde_round_trip_with_default() {
        let json = r#"{}"#;
        let cfg: TokensConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.max_per_request, 100_000);
    }

    #[test]
    fn tokens_config_serde_round_trip_with_override() {
        let json = r#"{"max_per_request": 8192}"#;
        let cfg: TokensConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.max_per_request, 8192);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    // ── GOLD-WIRE-07: memory.vector_index.backend ─────────────────────────

    /// GR-039: `recall_shortcut` must default `true` on BOTH paths — the
    /// derived-struct path (missing `memory:` block → Default::default())
    /// and the field-level serde path (present block, absent field).
    #[test]
    fn memory_recall_shortcut_defaults_true_on_both_paths() {
        assert!(MemoryConfig::default().recall_shortcut);
        let cfg: MemoryConfig = serde_yaml::from_str("name_sessions: false").unwrap();
        assert!(cfg.recall_shortcut, "field-level serde default must be true");
        let cfg: MemoryConfig = serde_yaml::from_str("recall_shortcut: false").unwrap();
        assert!(!cfg.recall_shortcut, "explicit false must stick");
    }

    #[test]
    fn memory_config_defaults_to_brute_force() {
        assert_eq!(
            MemoryConfig::default().vector_index.backend,
            VectorBackend::BruteForce,
            "default must keep the pre-WIRE-07 brute-force path"
        );
        assert_eq!(
            FreedomConfig::default().memory.vector_index.backend,
            VectorBackend::BruteForce
        );
    }

    #[test]
    fn vector_backend_serialises_snake_case_and_roundtrips() {
        let hnsw = serde_yaml::to_string(&VectorBackend::Hnsw).unwrap();
        assert!(hnsw.contains("hnsw"), "got: {hnsw}");
        let bf = serde_yaml::to_string(&VectorBackend::BruteForce).unwrap();
        assert!(bf.contains("brute_force"), "got: {bf}");
        let back: VectorBackend = serde_yaml::from_str(&hnsw).unwrap();
        assert_eq!(back, VectorBackend::Hnsw);
    }

    #[test]
    fn memory_config_parses_hnsw_from_freedom_yaml() {
        let dir = tempdir().unwrap();
        let path = write_yaml(
            dir.path(),
            "operator_id: alice\nmemory:\n  vector_index:\n    backend: hnsw\n",
        );
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(cfg.memory.vector_index.backend, VectorBackend::Hnsw);
    }

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
        assert_eq!(cfg.operator_id.as_deref(), Some("demo-user"));
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
        assert_eq!(cfg.profile.learn_provider.as_deref(), Some("openai_api"));
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
            scrub_env_prefixes: Vec::new(),
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
                wasm: WasmPluginsConfig {
                    enabled: false,
                    activations: std::collections::BTreeMap::new(),
                    pinned_hashes: std::collections::BTreeMap::new(),
                    require_all_pinned: false,
                    ..Default::default()
                },
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

    // ── R-02 Phase 4c — DreamingConfig serde wiring ──────────────────

    #[test]
    fn dreaming_config_default_is_off() {
        let cfg = DreamingConfig::default();
        assert!(!cfg.enabled, "Phase 4c task is OFF by default");
        assert!(cfg.interval_secs.is_none());
        assert!(cfg.window_secs.is_none());
        assert!(cfg.max_events.is_none());
        assert!(!cfg.summarize_themes);
        assert!(!cfg.merge_cross_themes, "SPEC-12 cross-theme merge is opt-in");
    }

    #[test]
    fn dreaming_merge_cross_themes_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "dreaming:\n  merge_cross_themes: true\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.dreaming.merge_cross_themes);
    }

    #[test]
    fn dreaming_section_absent_loads_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.dreaming.enabled);
        assert!(cfg.dreaming.interval_secs.is_none());
    }

    #[test]
    fn dreaming_enabled_with_custom_interval_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\n\
                    dreaming:\n  \
                    enabled: true\n  \
                    interval_secs: 3600\n  \
                    window_secs: 86400\n  \
                    max_events: 100\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.dreaming.enabled);
        assert_eq!(cfg.dreaming.interval_secs, Some(3600));
        assert_eq!(cfg.dreaming.window_secs, Some(86_400));
        assert_eq!(cfg.dreaming.max_events, Some(100));
    }

    #[test]
    fn dreaming_partial_block_inherits_defaults() {
        let dir = tempfile::tempdir().unwrap();
        // Operator sets only `enabled: true` — rest fall through to
        // None which means downstream uses the task's DEFAULT_*.
        let yaml = "dreaming:\n  enabled: true\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.dreaming.enabled);
        assert!(cfg.dreaming.interval_secs.is_none());
        assert!(cfg.dreaming.window_secs.is_none());
        assert!(cfg.dreaming.max_events.is_none());
    }

    // ── C-16 proactive: enabled (Session 21) ────────────────────

    #[test]
    fn proactive_config_default_is_off() {
        // AGENTER hard rule drift guard — "no destructive auto-
        // action without operator GO per command". A future
        // refactor flipping the default to true would surface here.
        let cfg = ProactiveConfig::default();
        assert!(!cfg.enabled);
    }

    #[test]
    fn proactive_section_absent_loads_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(!cfg.proactive.enabled);
    }

    #[test]
    fn proactive_enabled_true_round_trips_via_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\nproactive:\n  enabled: true\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.proactive.enabled);
    }

    // ── SC-10 per-model download policy ───────────────────────────────
    #[test]
    fn sc10_model_download_allowed_falls_back_to_global_flag() {
        let mut u = UpdaterConfig::default();
        assert!(u.model_download_policy.is_empty());
        // Global true (default) ⇒ any model allowed.
        assert!(u.model_download_allowed("clip", None));
        // Global false ⇒ any model blocked when no per-model entry.
        u.allow_huggingface_downloads = false;
        assert!(!u.model_download_allowed("clip", None));
    }

    #[test]
    fn sc10_per_model_entry_overrides_global_both_directions() {
        let mut u = UpdaterConfig::default();
        // Block one model on an otherwise-open install.
        u.allow_huggingface_downloads = true;
        u.model_download_policy.insert("whisper".into(), false);
        assert!(!u.model_download_allowed("whisper", None));
        assert!(u.model_download_allowed("clip", None)); // unlisted ⇒ global true
        // Permit one model on an otherwise air-gapped install.
        u.allow_huggingface_downloads = false;
        u.model_download_policy.clear();
        u.model_download_policy.insert("clip".into(), true);
        assert!(u.model_download_allowed("clip", None));
        assert!(!u.model_download_allowed("whisper", None)); // unlisted ⇒ global false
    }

    #[test]
    fn sc10_model_download_policy_round_trips_via_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\nupdater:\n  model_download_policy:\n    whisper: false\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert_eq!(
            cfg.updater.model_download_policy.get("whisper"),
            Some(&false)
        );
        assert!(!cfg.updater.model_download_allowed("whisper", None));
        // The actual run_pull call site passes the FULL repo string + the
        // short name — a `whisper: false` policy entry MUST still block it
        // (the high-sev gate-bypass regression guard).
        assert!(
            !cfg.updater
                .model_download_allowed("openai/whisper-large-v3-turbo", Some("whisper"))
        );
        assert!(
            cfg.updater
                .check_model_download("openai/whisper-large-v3-turbo", Some("whisper"))
                .is_err()
        );
    }

    #[test]
    fn sc10_short_name_policy_blocks_full_repo_string() {
        // The call site passes (full_repo, Some(short_name)); the operator
        // writes the short name. Either identifier must match the policy.
        let mut u = UpdaterConfig::default();
        u.allow_huggingface_downloads = true; // global open
        u.model_download_policy.insert("whisper".into(), false);
        assert!(!u.model_download_allowed("openai/whisper-large-v3-turbo", Some("whisper")));
        // Different model, name not in policy ⇒ global true.
        assert!(u.model_download_allowed("openai/clip-vit-base-patch32", Some("clip")));
        // check_model_download surfaces the per-model error, not the global.
        let err = u
            .check_model_download("openai/whisper-large-v3-turbo", Some("whisper"))
            .unwrap_err();
        assert!(err.contains("per-model policy"), "got: {err}");
    }

    // ── AR-03 (Session 24) hook_chain per-stage policy ────────────────

    #[test]
    fn ar_03_hook_chain_section_absent_returns_lenient_default() {
        // No section in freedom.yaml → every stage is lenient
        // (fail_fast=false). Back-compat with every existing install.
        let dir = tempfile::tempdir().unwrap();
        let path = write_yaml(dir.path(), "operator_id: alice\n");
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(cfg.hook_chain.is_empty());
        for stage in [
            crate::hooks::stages::HookStage::PreProviderCall,
            crate::hooks::stages::HookStage::PreChannelIngress,
            crate::hooks::stages::HookStage::PostProviderCall,
        ] {
            assert!(
                !cfg.fail_fast_for_stage(stage),
                "default for {} must be lenient",
                stage.as_str(),
            );
        }
    }

    #[test]
    fn ar_03_hook_chain_fail_fast_round_trips_via_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = "operator_id: alice\n\
                    hook_chain:\n  \
                      pre_provider_call:\n    \
                        fail_fast: true\n  \
                      post_provider_call:\n    \
                        fail_fast: false\n";
        let path = write_yaml(dir.path(), yaml);
        let cfg = FreedomConfig::load_from_path(&path).unwrap();
        assert!(
            cfg.fail_fast_for_stage(crate::hooks::stages::HookStage::PreProviderCall),
            "pre_provider_call opted into fail_fast",
        );
        assert!(
            !cfg.fail_fast_for_stage(crate::hooks::stages::HookStage::PostProviderCall),
            "post_provider_call explicitly opted out",
        );
        // Stage not mentioned in yaml → default lenient.
        assert!(
            !cfg.fail_fast_for_stage(crate::hooks::stages::HookStage::PreChannelIngress),
            "absent stage → lenient default",
        );
    }
}
