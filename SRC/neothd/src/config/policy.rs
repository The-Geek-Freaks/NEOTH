//! Skills, security policy, token, and compression configuration.

use serde::{Deserialize, Serialize};

/// GOLD-CCPARITY-SKILLVIS-01 — per-skill routing visibility.
///
/// Controls whether a skill participates in automatic keyword/embedding routing
/// or is only reachable via an explicit `/skill-id` slash invocation.
///
/// Set in the skill's own `skill.yaml` as a default, or overridden per-skill
/// in `freedom.yaml::skills.visibility_overrides` (operator wins over manifest).
///
/// ```yaml
/// # skill.yaml example (per-skill default)
/// visibility: name_only
///
/// # freedom.yaml example (operator override)
/// skills:
///   visibility_overrides:
///     raskal: off
///     pm-create-prd: user_invocable_only
/// ```
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillVisibility {
    /// Auto-routed and slash-invocable (default).
    /// The skill participates in both Stage-1 keyword scan and Stage-2
    /// embedding re-rank on every turn — existing behaviour.
    #[default]
    On,
    /// Name appears in skill listings but the skill is never auto-routed.
    /// Resolves only when the operator explicitly types `/skill-id`.
    /// Use for powerful skills that should not activate on keyword accidents.
    NameOnly,
    /// Same routing behaviour as `NameOnly` — not auto-routed; explicit slash
    /// invocation only. Semantic distinction: intended for skills the operator
    /// added and wants to trigger manually rather than by the keyword router.
    /// Appears in listings identically to `NameOnly`.
    UserInvocableOnly,
    /// Skill is completely inactive — never loads into the routing pool.
    /// Equivalent to `disabled` but set from the operator's `freedom.yaml`
    /// without editing the skill's own `skill.yaml` (which an upgrade would
    /// overwrite). Applied at load time in `skills::loader::load_all`.
    Off,
}

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

    /// GOLD-ADAPT-SPEAKR-01 — operator-overridable 5-layer prompt for the
    /// warm-tier / meeting summarization path. Empty by default → the
    /// hardcoded summarizer prompt is used; any set layer overrides it
    /// (see [`crate::memory::summarize_prompt::SummarizePromptLayers`]).
    #[serde(default)]
    pub meeting_summary: MeetingSummaryConfig,

    /// GOLD-CCPARITY-SKILLVIS-01 — per-skill visibility overrides.
    /// Operator sets this in `freedom.yaml` to restrict routing of specific
    /// skills without editing `skill.yaml` (which an upgrade would overwrite).
    /// Keys are skill ids (case-insensitive match); values are the effective
    /// `SkillVisibility`. Skills NOT in the map use their manifest's `visibility`
    /// field (default `on` — backward-compatible).
    ///
    /// `Off` overrides are applied at load time in `skills::loader::load_all`
    /// (same effect as the `disabled` blocklist). `NameOnly` and
    /// `UserInvocableOnly` are stored into the manifest and applied as a
    /// routing-time pre-filter in `build_prompt_bundle` / the channel path.
    ///
    /// ```yaml
    /// skills:
    ///   visibility_overrides:
    ///     raskal: off
    ///     pm-create-prd: user_invocable_only
    /// ```
    #[serde(default)]
    pub visibility_overrides: std::collections::HashMap<String, SkillVisibility>,

    /// GOLD-ADAPT-SKILL-10 — emit a compact skill-catalog table at the
    /// session-start banner (stdout only, NOT injected into the system
    /// prompt). When `true`, `run_chat_with` prints a markdown table of
    /// every enabled skill and its trigger keywords immediately after the
    /// UX-05 unlock-moment block, giving the operator at-a-glance
    /// discoverability of `/skill-id` commands without any provider tokens.
    ///
    /// Default `false` — opt-in. Operators running many skills or using
    /// NEOTH non-interactively leave this off so the banner stays quiet.
    ///
    /// ```yaml
    /// skills:
    ///   session_catalog: true
    /// ```
    #[serde(default)]
    pub session_catalog: bool,

    /// GOLD-ADAPT-KB-03 — when `true` (default) the nightly dreaming pass also
    /// runs a distill scan over `~/.neoth/trajectories/` and logs repeated
    /// tool-call sequences via tracing. Applies only when `dreaming.enabled`
    /// is true (the scan is piggybacked on that task). Set `false` to opt out.
    ///
    /// ```yaml
    /// skills:
    ///   auto_distill: false
    /// ```
    #[serde(default = "default_skills_auto_distill")]
    pub auto_distill: bool,
}

/// GOLD-ADAPT-SPEAKR-01 — config mirror of the 5 summarize prompt layers.
/// Kept as a plain `Eq` config struct (so `SkillsConfig: Eq` holds) and
/// mapped to [`crate::memory::summarize_prompt::SummarizePromptLayers`] at the
/// summarize call site. All layers default to `None` → the hardcoded prompt.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MeetingSummaryConfig {
    /// Highest-priority context layer → provider `system` prompt.
    #[serde(default)]
    pub admin: Option<String>,
    /// User-supplied instruction override → provider `user` prompt.
    #[serde(default)]
    pub user: Option<String>,
    /// Folder/context-scoped layer → `system` side.
    #[serde(default)]
    pub folder: Option<String>,
    /// Tag-scoped layer → `user` side.
    #[serde(default)]
    pub tag: Option<String>,
    /// Lowest-priority append layer → `user` side.
    #[serde(default)]
    pub append: Option<String>,
    /// Concatenate all set layers instead of short-circuiting at the first.
    #[serde(default)]
    pub append_mode: bool,
}

/// GOLD-FEAT-07 — moral-core injection config. The LOWKEY moral core (operator-
/// authored value directives) is injected at enrichment position 0 on every
/// chat + channel turn. `enabled` is the operator kill-switch: default `true`
/// (injection ON, backward-compatible); set `false` to disable injection
/// without deleting the moral-core directory.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MoralCoreConfig {
    #[serde(default = "default_moral_core_enabled")]
    pub enabled: bool,
}

fn default_moral_core_enabled() -> bool {
    true
}

impl Default for MoralCoreConfig {
    fn default() -> Self {
        Self {
            enabled: default_moral_core_enabled(),
        }
    }
}

fn default_skills_always_embed_route() -> bool {
    true
}

fn default_skills_auto_distill() -> bool {
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
            meeting_summary: MeetingSummaryConfig::default(),
            visibility_overrides: std::collections::HashMap::new(),
            session_catalog: false,
            auto_distill: default_skills_auto_distill(),
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
    /// GOLD-ADAPT-SNYK-01 — minimum OSV advisory severity that blocks a CLI
    /// install performed through NEOTH's npm installer. Advisories at-or-above
    /// this level abort the install; below it the call proceeds with a `warn!`.
    /// Default `High` — blocks both High and Critical. Set `Critical` for the
    /// narrower policy that blocks only Critical findings, or `None` for
    /// warn-only.
    #[serde(default)]
    pub dep_vuln_threshold: crate::security::osv_check::SeverityLevel,
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
// f32 field (history_compaction_threshold) means Eq is not derivable.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TokensConfig {
    /// Total token cap per provider request before
    /// `tokens::budget::enforce_budget` degradation policy fires.
    #[serde(default = "TokensConfig::default_max_per_request")]
    pub max_per_request: u32,
    /// GOLD-PROG-09 (OP-01) — when true, `neoth edit` emits the compact
    /// content-hash "hashline" diff by default (without the explicit
    /// `--hashline` flag). Off by default.
    #[serde(default)]
    pub hashline_edits: bool,
    /// GOLD-PROG-10 (OP-03) — when true, `neoth edit --apply` runs the
    /// just-written file through the configured LSP server and prints
    /// diagnostics to stderr inline. Off by default (best-effort: a
    /// missing or slow server never fails the edit itself).
    #[serde(default)]
    pub lsp_diagnostics_enabled: bool,
    /// LSP server command to launch when `lsp_diagnostics_enabled` is true.
    /// Defaults to `"rust-analyzer"` for `.rs` files when absent or `None`.
    /// Examples: `"rust-analyzer"`, `"pylsp"`, `"typescript-language-server --stdio"`.
    #[serde(default)]
    pub lsp_server_cmd: Option<String>,
    /// GOLD-ADAPT-HARNESS-03 — enable message-history compaction middleware.
    /// When true, `CompactingProvider` wraps the fallback chain and
    /// squashes old prompt history when `history_compaction_threshold`
    /// fraction of `max_per_request` is exceeded.
    #[serde(default)]
    pub history_compaction_enabled: bool,
    /// Fraction of `max_per_request` at which compaction fires.
    /// Default 0.85 — fire when prompt + system exceed 85% of the cap (ODY-06).
    #[serde(default = "TokensConfig::default_history_compaction_threshold")]
    pub history_compaction_threshold: f32,
    /// Characters of the most-recent prompt to preserve verbatim
    /// (the "live zone"). Everything before this suffix is summarised.
    /// Default 4000 chars ≈ 1000 tokens.
    #[serde(default = "TokensConfig::default_history_keep_recent_chars")]
    pub history_keep_recent_chars: usize,
}

impl Default for TokensConfig {
    fn default() -> Self {
        Self {
            max_per_request: Self::default_max_per_request(),
            hashline_edits: false,
            lsp_diagnostics_enabled: false,
            lsp_server_cmd: None,
            history_compaction_enabled: false,
            history_compaction_threshold: Self::default_history_compaction_threshold(),
            history_keep_recent_chars: Self::default_history_keep_recent_chars(),
        }
    }
}

impl TokensConfig {
    pub fn default_max_per_request() -> u32 {
        100_000
    }
    /// GOLD-ADAPT-ODY-06 — raised from 0.80 to 0.85 per spec ("85% fill").
    pub fn default_history_compaction_threshold() -> f32 {
        0.85
    }
    pub fn default_history_keep_recent_chars() -> usize {
        4_000
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

/// WS-HR — `freedom.yaml::compression`. Per-block token compression of long
/// tool outputs (headroom port). Off by default — an operator opts in with
/// `compression.enabled = true`. The three orchestrator thresholds are exposed
/// for tuning but default to headroom's conservative stock values.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CompressionConfig {
    /// Master switch. `false` → no block is ever compressed (passthrough).
    #[serde(default)]
    pub enabled: bool,
    /// Blocks smaller than this many bytes are left untouched (compression
    /// overhead + a CCR marker isn't worth it on small outputs).
    #[serde(default = "CompressionConfig::default_min_block_bytes")]
    pub min_block_bytes: usize,
    /// The most-recent N turns are never compressed — the live zone. Protects
    /// correctness on the active turn and keeps provider prompt-cache hits.
    #[serde(default = "CompressionConfig::default_live_zone_turns")]
    pub live_zone_turns: usize,
    /// After reformat, `output/input ≤ this` ⇒ reformat sufficient, skip
    /// offloads unless bloat demands them.
    #[serde(default = "CompressionConfig::default_reformat_target_ratio")]
    pub reformat_target_ratio: f64,
    /// Bloat score ≥ this ⇒ run the offload regardless of reformat outcome.
    #[serde(default = "CompressionConfig::default_bloat_threshold")]
    pub bloat_threshold: f32,
    /// After reformat, `output/input > this` ⇒ run offloads even below the
    /// bloat threshold (the "reformat barely helped" fallback).
    #[serde(default = "CompressionConfig::default_offload_fallback_ratio")]
    pub offload_fallback_ratio: f64,
}

impl CompressionConfig {
    pub fn default_min_block_bytes() -> usize {
        2048
    }
    pub fn default_live_zone_turns() -> usize {
        3
    }
    pub fn default_reformat_target_ratio() -> f64 {
        0.5
    }
    pub fn default_bloat_threshold() -> f32 {
        0.5
    }
    pub fn default_offload_fallback_ratio() -> f64 {
        0.85
    }

    /// Runtime gating view consumed by `CompressionPipeline::compress_block`.
    pub fn gate(&self) -> crate::context::compress::Gate {
        crate::context::compress::Gate {
            enabled: self.enabled,
            min_block_bytes: self.min_block_bytes,
            live_zone_turns: self.live_zone_turns,
        }
    }

    /// Orchestrator acceptance thresholds consumed by the pipeline builder.
    pub fn thresholds(&self) -> crate::context::compress::Thresholds {
        crate::context::compress::Thresholds {
            reformat_target_ratio: self.reformat_target_ratio,
            bloat_threshold: self.bloat_threshold,
            offload_fallback_ratio: self.offload_fallback_ratio,
        }
    }
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_block_bytes: Self::default_min_block_bytes(),
            live_zone_turns: Self::default_live_zone_turns(),
            reformat_target_ratio: Self::default_reformat_target_ratio(),
            bloat_threshold: Self::default_bloat_threshold(),
            offload_fallback_ratio: Self::default_offload_fallback_ratio(),
        }
    }
}
