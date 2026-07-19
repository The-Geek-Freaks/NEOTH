//! Feature, channel, and operator-facing integration configuration.

use serde::{Deserialize, Serialize};

/// SPEC-03b — per-provider HTTP-429 fallback chain (4-lens gremium design,
/// 2026-05-30). When the primary provider returns `QuotaError` (429), the
/// chat dispatch transparently tries each chain entry in order. Two guards
/// the gremium flagged as mandatory: (1) each fallback hop must pass the
/// SAME cloud-egress consent gate as the primary — a 429 must never
/// silently exfiltrate to a provider the operator never approved; (2)
/// fallback fires ONLY on 429 (not breaker-open/timeout — mixing signals
/// contaminates the breaker). Entries already in QuotaTracker backoff are
/// skipped. Empty `chain` (default) = no fallback, no behaviour change.
#[derive(Clone, Debug, Deserialize, Serialize)]
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

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            chain: Vec::new(),
            max_hops: default_fallback_max_hops(),
        }
    }
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
    /// HERMES-04 — enable independent LLM judge verification on goal clean-exit.
    /// When `true` AND a `goal` is set, the dispatch loop fires an extra provider
    /// call to verify the goal is met before allowing an early exit. Default
    /// `false` (opt-in) to prevent unexpected extra provider calls for operators
    /// who have not explicitly configured a judge.
    #[serde(default)]
    pub judge_enabled: bool,
}

impl Default for GoalConfig {
    fn default() -> Self {
        // 5 = the prior hardcoded dispatch-loop cap (no behaviour change).
        Self {
            max_turns: 5,
            goal: None,
            grind: None,
            judge_enabled: false,
        }
    }
}

/// GOLD-LOOP-01 — multi-round autonomous loop engine knobs.
///
/// The loop engine wraps the existing MCP dispatch loop, running up to
/// `max_rounds` outer iterations and evaluating structural stop criteria via
/// `council::stop_verifier::StopConditionVerifier` after each round. All
/// fields default to the safe/off state so the engine is opt-in at the
/// operator level via `freedom.yaml::loop_config`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LoopConfig {
    /// Master switch. `false` (default) = engine disabled, every path falls
    /// through to the existing single `run_mcp_dispatch_loop` call.
    pub enabled: bool,
    /// Hard ceiling on outer loop rounds. Each round is one full
    /// `run_mcp_dispatch_loop` call (which itself may iterate up to
    /// `goal.max_turns` inner iterations). Default 3.
    pub max_rounds: u32,
    /// When `true` AND a council debate returns a dissent score above the
    /// strong-dissent threshold (0.6), the loop engine is auto-invoked with
    /// `max_rounds = 1` to try to produce a more-converged answer. Default
    /// `false` — the council path is already expensive and this adds an extra
    /// dispatch round; opt in explicitly.
    pub auto_invoke_on_dissent: bool,
    /// When `true` and the loop is at `L2+` autonomy, each round where the
    /// self-reflect quality score is below threshold gets a refine pass via
    /// `council::self_reflect::refine`. Default `false` (opt-in: adds an
    /// extra provider call per round).
    pub refine_enabled: bool,
    /// Optional cumulative TOOL-CALL cap across all rounds. When `Some(n)` and the
    /// accumulated tool calls (successful + failed) exceed `n`, the loop exits with
    /// `StopReason::BudgetExceeded` instead of starting another round. This is a
    /// tool-call budget, NOT an LLM-token budget (the dispatch loop doesn't surface
    /// per-round token usage) — named honestly so the operator isn't misled.
    /// `None` (default) = no budget gate. `serde(alias)` keeps older
    /// `token_budget:` freedom.yaml keys working.
    #[serde(alias = "token_budget")]
    pub tool_call_budget: Option<u64>,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_rounds: 3,
            auto_invoke_on_dissent: false,
            refine_enabled: false,
            tool_call_budget: None,
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

/// OMI-MULTIMODAL-01 — which OMI ingestion surfaces are active.
///
/// `developer_api` is the supported conversation import. Operators who still
/// run the old local `/v1/memories` endpoint select `legacy_memories`
/// explicitly. Native ingest is NEOTH's local authenticated PCM/media webhook;
/// it is not an emulation of OMI's private `/v4/listen` backend socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmiIngestMode {
    /// Import conversations from `/v1/dev/user/conversations` with an
    /// `omi_dev_*` bearer key.
    DeveloperApi,
    /// Accept NEOTH's authenticated local PCM/media ingest protocol.
    NativeIngest,
    /// Run Developer API import and native ingest together.
    Both,
    /// Compatibility for the old unauthenticated local `/v1/memories` poller.
    /// This mode trusts the configured local backend and private network; it is
    /// intentionally forbidden for public endpoints.
    LegacyMemories,
}

impl Default for OmiIngestMode {
    fn default() -> Self {
        Self::DeveloperApi
    }
}

impl OmiIngestMode {
    /// True when the self-hosted OMI backend must be polled.
    pub const fn polls(self) -> bool {
        matches!(self, Self::DeveloperApi | Self::Both | Self::LegacyMemories)
    }

    /// True when NEOTH must accept authenticated native PCM/media ingestion.
    pub const fn listens(self) -> bool {
        matches!(self, Self::NativeIngest | Self::Both)
    }
}

/// OMI-MULTIMODAL-01 — local OMI conversation and media-ingest knobs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct OmiConfig {
    /// Off by default — opt-in. SC-14 refuses non-local poll endpoints and
    /// public/unspecified native-listener addresses.
    pub enabled: bool,
    /// Select polling, native live ingestion, both, or the old `/v1/memories`
    /// compatibility endpoint. Defaults to `developer_api`.
    pub mode: OmiIngestMode,
    /// OMI backend/API base URL. Default `http://127.0.0.1:8002` remains local.
    pub endpoint: String,
    /// Permit Developer API mode to call a public HTTPS endpoint. Separate
    /// external-network opt-in; never relaxes the legacy local-only rule.
    pub allow_cloud_api: bool,
    /// Poll interval (seconds). Default 30; floored at 5.
    pub poll_interval_secs: u64,
    /// A transcript item at/above this score is promoted to ground-truth +
    /// audited (`extended/omi_lifecycle_audit`). Default 0.75.
    pub confidence_threshold: f32,
    /// Native OMI listener socket. Private/LAN addresses are allowed so a
    /// physical OMI device can reach NEOTH; wildcard and public binds are not.
    pub listen_addr: String,
    /// How far the first conversation poll may look back. Default one day.
    pub initial_lookback_secs: u64,
    /// Hard cap on conversations fetched and processed per poll.
    pub max_conversations_per_poll: usize,
    /// Persist raw transcript text locally. Default false; aligned metadata and
    /// derived summaries remain available without retaining verbatim speech.
    pub retain_transcripts: bool,
    /// Accept and process audio from OMI. Separate opt-in from text ingestion.
    pub audio_enabled: bool,
    /// Accept and process still images from OMI.
    pub visual_enabled: bool,
    /// Accept and process video/call media from OMI.
    pub video_enabled: bool,
    /// Promote OMI action items into the local task system.
    pub create_actions: bool,
    /// Seed corroborated OMI statements into ground truth.
    pub seed_groundtruth: bool,
    /// Produce bounded conversation summaries.
    pub summary_enabled: bool,
    /// Permit summaries to use a configured cloud model. Default false.
    pub allow_cloud_summary: bool,
    /// Retention window for OMI-derived records and retained transcripts.
    pub retention_days: u64,
    /// Per-stream audio byte cap, enforced before buffering/decoding.
    pub max_audio_bytes_per_stream: u64,
    /// Per-image byte cap, enforced before base64 decode/reassembly.
    pub max_image_bytes: u64,
    /// Maximum concurrent native OMI connections.
    pub max_connections: usize,
    /// Maximum simultaneously active native calls. Terminal calls are evicted
    /// from memory and served idempotently from their bounded journals.
    pub max_active_calls: usize,
    /// Close native streams that make no progress for this many seconds.
    pub idle_timeout_secs: u64,
    /// Optional exact OMI UID allowlist. Empty means any authenticated/local UID.
    pub allowed_uids: Vec<String>,
}

impl Default for OmiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: OmiIngestMode::default(),
            endpoint: crate::installers::omi::DEFAULT_OMI_ENDPOINT.to_string(),
            allow_cloud_api: false,
            poll_interval_secs: 30,
            confidence_threshold: 0.75,
            listen_addr: "127.0.0.1:8003".to_string(),
            initial_lookback_secs: 86_400,
            max_conversations_per_poll: 100,
            retain_transcripts: false,
            audio_enabled: false,
            visual_enabled: false,
            video_enabled: false,
            create_actions: true,
            seed_groundtruth: true,
            summary_enabled: true,
            allow_cloud_summary: false,
            retention_days: 30,
            max_audio_bytes_per_stream: 64 * 1024 * 1024,
            max_image_bytes: 16 * 1024 * 1024,
            max_connections: 4,
            max_active_calls: 64,
            idle_timeout_secs: 120,
            allowed_uids: Vec::new(),
        }
    }
}

impl OmiConfig {
    /// Parse the native listener once and return an operator-facing error.
    pub fn listen_socket_addr(&self) -> Result<std::net::SocketAddr, String> {
        self.listen_addr.parse().map_err(|_| {
            format!(
                "omi.listen_addr {:?} must be an IP socket address (for example 127.0.0.1:8003)",
                self.listen_addr
            )
        })
    }

    /// Validate OMI's security and memory/DoS bounds before starting workers.
    ///
    /// Memory/connection bounds are validated even while their feature toggle
    /// is off. Endpoint policy follows the selected pull mode; native-only
    /// ingest does not require an otherwise-unused backend URL.
    pub fn validate(&self) -> Result<(), String> {
        const MAX_POLL_INTERVAL_SECS: u64 = 86_400;
        const MAX_INITIAL_LOOKBACK_SECS: u64 = 366 * 86_400;
        const MAX_CONVERSATIONS_PER_POLL: usize = 1_000;
        const MAX_RETENTION_DAYS: u64 = 3_650;
        const MAX_AUDIO_BYTES: u64 = 512 * 1024 * 1024;
        const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
        const MAX_CONNECTIONS: usize = 64;
        const MAX_ACTIVE_CALLS: usize = 4_096;
        const MAX_IDLE_TIMEOUT_SECS: u64 = 3_600;
        const MAX_ALLOWED_UIDS: usize = 256;
        const MAX_UID_BYTES: usize = 256;

        match self.mode {
            OmiIngestMode::LegacyMemories => {
                crate::installers::omi::is_local_endpoint(&self.endpoint)?;
            }
            OmiIngestMode::DeveloperApi | OmiIngestMode::Both => {
                crate::installers::omi::validate_developer_api_endpoint(
                    &self.endpoint,
                    self.allow_cloud_api,
                )?;
            }
            OmiIngestMode::NativeIngest => {}
        }

        if self.allow_cloud_api
            && !matches!(self.mode, OmiIngestMode::DeveloperApi | OmiIngestMode::Both)
        {
            return Err("omi.allow_cloud_api requires developer_api or both mode".to_string());
        }
        if self.allow_cloud_summary && (!self.summary_enabled || !self.mode.listens()) {
            return Err(
                "omi.allow_cloud_summary requires summary_enabled and native_ingest/both mode"
                    .to_string(),
            );
        }
        if self.video_enabled && !self.visual_enabled {
            return Err("omi.video_enabled requires omi.visual_enabled".to_string());
        }
        if !self.mode.listens()
            && (self.audio_enabled
                || self.visual_enabled
                || self.video_enabled
                || !self.allowed_uids.is_empty())
        {
            return Err(
                "OMI media controls and allowed_uids require native_ingest or both mode"
                    .to_string(),
            );
        }

        let listen_addr = self.listen_socket_addr()?;
        if listen_addr.port() == 0 {
            return Err("omi.listen_addr port must be non-zero".to_string());
        }
        crate::installers::omi::is_local_endpoint(&format!("http://{listen_addr}"))
            .map_err(|reason| format!("unsafe omi.listen_addr: {reason}"))?;

        if !(1..=MAX_POLL_INTERVAL_SECS).contains(&self.poll_interval_secs) {
            return Err(format!(
                "omi.poll_interval_secs must be between 1 and {MAX_POLL_INTERVAL_SECS}"
            ));
        }
        if !self.confidence_threshold.is_finite()
            || !(f32::EPSILON..=1.0).contains(&self.confidence_threshold)
        {
            return Err("omi.confidence_threshold must be finite and in (0, 1]".to_string());
        }
        if !(1..=MAX_INITIAL_LOOKBACK_SECS).contains(&self.initial_lookback_secs) {
            return Err(format!(
                "omi.initial_lookback_secs must be between 1 and {MAX_INITIAL_LOOKBACK_SECS}"
            ));
        }
        if !(1..=MAX_CONVERSATIONS_PER_POLL).contains(&self.max_conversations_per_poll) {
            return Err(format!(
                "omi.max_conversations_per_poll must be between 1 and {MAX_CONVERSATIONS_PER_POLL}"
            ));
        }
        if !(1..=MAX_RETENTION_DAYS).contains(&self.retention_days) {
            return Err(format!(
                "omi.retention_days must be between 1 and {MAX_RETENTION_DAYS}"
            ));
        }
        if !(1..=MAX_AUDIO_BYTES).contains(&self.max_audio_bytes_per_stream) {
            return Err(format!(
                "omi.max_audio_bytes_per_stream must be between 1 and {MAX_AUDIO_BYTES}"
            ));
        }
        if !(1..=MAX_IMAGE_BYTES).contains(&self.max_image_bytes) {
            return Err(format!(
                "omi.max_image_bytes must be between 1 and {MAX_IMAGE_BYTES}"
            ));
        }
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections) {
            return Err(format!(
                "omi.max_connections must be between 1 and {MAX_CONNECTIONS}"
            ));
        }
        if !(1..=MAX_ACTIVE_CALLS).contains(&self.max_active_calls) {
            return Err(format!(
                "omi.max_active_calls must be between 1 and {MAX_ACTIVE_CALLS}"
            ));
        }
        if !(1..=MAX_IDLE_TIMEOUT_SECS).contains(&self.idle_timeout_secs) {
            return Err(format!(
                "omi.idle_timeout_secs must be between 1 and {MAX_IDLE_TIMEOUT_SECS}"
            ));
        }
        if self.allowed_uids.len() > MAX_ALLOWED_UIDS {
            return Err(format!(
                "omi.allowed_uids may contain at most {MAX_ALLOWED_UIDS} entries"
            ));
        }
        if self
            .allowed_uids
            .iter()
            .any(|uid| uid.trim().is_empty() || uid.trim() != uid || uid.len() > MAX_UID_BYTES)
        {
            return Err(format!(
                "each omi.allowed_uids entry must be trimmed and contain 1..={MAX_UID_BYTES} bytes"
            ));
        }
        let mut unique_uids = std::collections::HashSet::with_capacity(self.allowed_uids.len());
        if self
            .allowed_uids
            .iter()
            .any(|uid| !unique_uids.insert(uid.as_str()))
        {
            return Err("omi.allowed_uids entries must be unique".to_string());
        }

        Ok(())
    }

    /// Validate the cross-file OMI authentication contract without exposing
    /// either secret. Disabled OMI remains credential-free; every enabled
    /// network surface fails closed when its dedicated bearer is absent.
    pub fn validate_with_credentials(
        &self,
        credentials: &crate::config::credentials::Credentials,
    ) -> Result<(), String> {
        self.validate()?;
        if !self.enabled {
            return Ok(());
        }
        if matches!(self.mode, OmiIngestMode::DeveloperApi | OmiIngestMode::Both) {
            let key = credentials.omi_developer_api_key.as_ref().ok_or_else(|| {
                "enabled OMI Developer API ingestion requires omi_developer_api_key in credentials"
                    .to_string()
            })?;
            let exposed = key.expose();
            if !exposed.starts_with("omi_dev_")
                || exposed.len() == "omi_dev_".len()
                || exposed.trim() != exposed
            {
                return Err(
                    "omi_developer_api_key must be trimmed and use the non-empty omi_dev_* format"
                        .to_string(),
                );
            }
        }
        if self.mode.listens() {
            let token = credentials.omi_ingest_token.as_ref().ok_or_else(|| {
                "enabled native OMI ingestion requires omi_ingest_token in credentials".to_string()
            })?;
            if token.expose().len() < 32 || token.expose().trim() != token.expose() {
                return Err(
                    "omi_ingest_token must be trimmed and contain at least 32 bytes".to_string(),
                );
            }
        }
        // LegacyMemories intentionally has no credential gate: the historical
        // local protocol has no auth. Its reduced trust boundary is compensated
        // by the strict local/private endpoint validator above.
        Ok(())
    }
}

/// MM-01b/02b/03b — cloud media opt-ins. ALL default OFF (`false`). Each flag,
/// when `true`, means the operator has accepted that THIS media type leaves the
/// device for a cloud provider. Audio/image/video are more sensitive than text.
// `Copy` dropped in B20: MediaConfig now embeds `stt: MediaSttConfig` which owns
// String fields (provider model/language/region), so the struct can no longer be
// bit-copied. It is passed by reference or `.clone()`d everywhere already.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// This flag is enforced by the audited wrappers
    /// (`media::stt_provider::transcribe_and_audit`,
    /// `media::tts_cloud::synth_and_audit`,
    /// `media::video_dispatch::dispatch_video_analysis`). The inbound audio
    /// pipeline passes the daemon WAL writer into the canonical STT dispatcher;
    /// the source guard prevents new direct cloud-media callers from bypassing
    /// the audited boundaries.
    pub required_audit_for_cloud_media: bool,
    /// SPEAKR-02b — when true, the STT dispatch labels speakers by matching each
    /// utterance's voice embedding against the persisted profile store
    /// (`media::speaker_profile`). Default `false`. The canonical STT path feeds
    /// raw PCM/WAV through ECAPA, x-vector, or the log-mel fallback before
    /// matching profiles.
    pub auto_speaker_labels: bool,
    /// GOLD-ADAPT-HANDY-05 — idle unload window for the local candle Whisper engine.
    ///
    /// When `Some(n)`, the shared `WhisperEngine` drops its `LoadedWhisper`
    /// (freeing VRAM / RAM) after `n` seconds of inactivity; the next
    /// transcription request reloads the model from the cached safetensors
    /// (~1-5 s). `None` or `Some(0)` = keep loaded forever after first use.
    ///
    /// Default `Some(120)` (2 minutes). Applied by the canonical
    /// `WhisperRsLocal` provider factory.
    #[serde(default = "default_whisper_idle_unload_secs")]
    pub whisper_idle_unload_secs: Option<u64>,
    /// GOLD-ADAPT-AWE-DOC-01 — enable the Docling subprocess extractor in
    /// `neoth ingest`. When `true`, `DoclingExtractor` is tried first for
    /// PDF, Document, and Image assets (before the pure-Rust extractors),
    /// invoking `docling --output-format json <file>` in a headless subprocess.
    /// Default `false` — the pure-Rust path (PdfExtractor / DocumentExtractor)
    /// is used unless the operator has installed Docling AND opted in here.
    /// If Docling is opted-in but the binary is not on PATH, the extractor
    /// returns `Unsupported` and the pipeline falls through to the Rust backends
    /// (graceful degradation).
    #[serde(default)]
    pub docling_enabled: bool,
    /// GOLD-ADAPT-HANDY-02 — enable `media::vad::SmoothedVad` as a pre-STT
    /// energy gate in the dictation capture path.
    ///
    /// When `true`, caller-supplied PCM frames are passed through `SmoothedVad`
    /// before being forwarded to the STT provider. Silence
    /// frames (VAD says `VadDecision::Silence`) are dropped, saving STT calls
    /// for quiet stretches between utterances.
    ///
    /// Default `false` — gate is bypassed; all captured audio reaches STT.
    /// Flip to `true` in `freedom.yaml` under `media.vad_enabled`.
    ///
    /// The shipped backend is the deterministic energy/smoothing/hangover
    /// implementation; no feature flag advertises an unavailable neural model.
    #[serde(default)]
    pub vad_enabled: bool,
    /// GOLD-ADOPT-25 — opt-in dictation input mode.
    ///
    /// When `true`, `neoth dictate <file>` decodes the operator-selected audio,
    /// gates it through the VAD (if `vad_enabled`), and routes the utterance
    /// through `media.stt` (local by default; cloud only when separately and
    /// explicitly enabled). Chat and daemon media attachments use the same
    /// dispatcher but do not depend on this file-dictation consent flag.
    ///
    /// Default `false` — file dictation is opt-in because transcription handles
    /// sensitive audio. Live microphone capture is not implemented.
    ///
    /// Configure in `freedom.yaml` under `media.dictation_enabled`.
    #[serde(default)]
    pub dictation_enabled: bool,

    /// B20 STT-DISPATCHER-HOTPATH — per-call STT configuration.
    ///
    /// Defaults to local candle Whisper; no cloud unless explicitly configured.
    /// Missing `media.stt` key in `freedom.yaml` deserializes cleanly to the
    /// local-candle default (no cloud, no egress).
    #[serde(default)]
    pub stt: crate::media::stt_dispatch::MediaSttConfig,
    /// Canonical text-to-speech provider, fallback, local asset, voice, locale,
    /// and request-limit contract. Defaults to offline `system_native`.
    #[serde(default)]
    pub tts: crate::media::tts_dispatch::TtsDispatcherConfig,
}

fn default_whisper_idle_unload_secs() -> Option<u64> {
    Some(120)
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            cloud_stt_enabled: false,
            cloud_tts_enabled: false,
            cloud_vision_enabled: false,
            video_frame_upload_enabled: false,
            required_audit_for_cloud_media: false,
            auto_speaker_labels: false,
            // HANDY-05 — default 2-minute idle unload; matches serde default.
            whisper_idle_unload_secs: default_whisper_idle_unload_secs(),
            docling_enabled: false,
            // GOLD-ADAPT-HANDY-02 — VAD gate: off by default; operator opt-in.
            vad_enabled: false,
            // GOLD-ADOPT-25 — dictation: off by default; mic capture is opt-in.
            dictation_enabled: false,
            // B20 — default to local candle Whisper; no cloud egress.
            stt: crate::media::stt_dispatch::MediaSttConfig::default(),
            // TTS Gold — default is guaranteed offline; cloud choices remain
            // separately gated by `cloud_tts_enabled`.
            tts: crate::media::tts_dispatch::TtsDispatcherConfig::default(),
        }
    }
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

/// GOLD-ADAPT-MEM-16 — ArXiv skill-learning cron config.
///
/// Scans `topics` on a cadence (default 6h), extracts 1-3 actionable
/// takeaways per paper via the shared LLM provider, and writes each
/// takeaway to `idx_groundtruth` as `source = "arxiv-skill-scan"` /
/// `scope = "arxiv-learning"` / `FactState::Candidate`. Facts surface
/// into recall/council via the existing `groundtruth::surface_for_recall`
/// path. Requires a wired provider — no provider → task not spawned.
/// WAL-free (groundtruth insert is the durable record).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ArxivSkillScanConfig {
    /// Master switch. Default `false` — opt in via freedom.yaml.
    pub enabled: bool,
    /// arXiv query strings to scan. Default: `["cat:cs.AI", "cat:cs.LG"]`.
    pub topics: Vec<String>,
    /// Tick interval in seconds. `None` = 21_600 (6h).
    pub interval_secs: Option<u64>,
    /// Max results fetched per topic per tick. `None` = 10.
    pub max_per_topic: Option<usize>,
}

impl Default for ArxivSkillScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            topics: vec!["cat:cs.AI".to_string(), "cat:cs.LG".to_string()],
            interval_secs: None,
            max_per_topic: None,
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
