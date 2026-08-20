//! Sub-agent TOML schema — Phase 30 R-18 SA-1.
//!
//! ## QM-5 NEXUS handoff schema (2026-05-22)
//!
//! In addition to the static `SubAgent` config shape, this module now
//! also ships [`SubAgentRequest`] + [`SubAgentResult`] — the runtime
//! payload that flows between Cerebellum → Left/Right hemispheres and
//! between successive sub-agents in a coding-workflow chain. Adopted
//! verbatim from the NEXUS handoff pattern documented in
//! `PLAN/QUELLEN_ADOPT_agency_2026-05-21.md` §4: every transfer carries
//! `from / to / phase / task_id / priority / context / success_criteria /
//! deliverable / evidence_required`. Returns carry `verdict` (typed via
//! [`crate::council::qa_verdict::QaVerdict`] from QM-6) + `evidence` +
//! `next_agent` so the dispatcher loop has structured pass/fail/blocked
//! semantics instead of free-form prose.
//!
//! ```toml
//! # ~/.neoth/agents/code-reviewer.toml
//! name        = "code-reviewer"
//! description = "Review code for bugs, style, and security"
//! model       = "claude-opus-4-7"           # optional — falls back to default
//! system      = """
//! You are a senior software engineer. Review the supplied code for:
//! ...
//! """
//! tools       = ["recall", "ctx_search"]    # tool allowlist
//! enabled     = true
//! ```
//!
//! Tools listed in `tools` must match the names the daemon's tool registry
//! exposes. Unknown tool names log + skip at dispatch time, they don't
//! fail validation — operator-typo recovery without daemon restart.

use serde::{Deserialize, Serialize};

use crate::council::qa_verdict::QaVerdict;

/// GOLD-ADAPT-OH-13 — per-agent context-layer omission flags.
///
/// Each flag controls whether the corresponding enrichment layer is OMITTED
/// when the agent fires (true = omit, false = keep). Defaults mirror OH's
/// intent: everything except the moral core is omitted by default (the agent
/// supplies its own system prompt and doesn't need the operator's profile /
/// recall / MCP catalogue), but the moral-core safety layer stays injected
/// so agents can't silently drop the operator's position-0 directives.
///
/// Operators override these in their agent TOML:
/// ```toml
/// omit_moral_core = true        # opts the agent out of the moral-core layer
/// omit_operator_context = false # keeps the operator context for this agent
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentOmitFlags {
    /// Omit the `operator_context` enrichment layer (identity + memory context).
    pub operator_context: bool,
    /// Omit the `mcp_catalogue` enrichment layer.
    pub mcp_catalogue: bool,
    /// Omit the `moral_core` enrichment layer (position-0 directives).
    /// Defaults to `false` — moral core stays injected for safety.
    pub moral_core: bool,
    /// Omit the `preset_addendum` enrichment layer (profile preset delta).
    pub preset: bool,
    /// Omit the recall block (Block::D memory episodes).
    pub recall: bool,
    /// Omit the `repo_context_block` enrichment layer.
    pub repo_context: bool,
}

/// One sub-agent definition. Either operator-defined (TOML) or built-in
/// (returned by [`super::builtins::built_in_agents`]).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SubAgent {
    /// Stable identifier. Used by `/agent <name>` dispatch + `delegate_to`
    /// in skill manifests. Override resolution: same-name operator entry
    /// wins over a built-in.
    pub name: String,
    /// One-line description shown by `/agent list`.
    pub description: String,
    /// Model preference for this sub-agent. `None` → daemon falls back to
    /// `freedom.yaml::provider_model`.
    #[serde(default)]
    pub model: Option<String>,
    /// System prompt replaces the operator's per-turn system block when
    /// the sub-agent activates. Multi-line. No `{args}` substitution
    /// (sub-agents see the user message as the prompt body, not via the
    /// system prompt).
    pub system: String,
    /// Names of host tools this sub-agent is allowed to call. Empty list
    /// or `None` means "no tools" (provider-only). Phase 30 wires this
    /// into the tool dispatcher when host tools land.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Names of host tools this sub-agent is explicitly FORBIDDEN from
    /// calling, even if the server-level `allow_tools` list permits them.
    /// Takes priority over `tools` allow-list — if a tool appears in both,
    /// the denylist wins. Operators use this to harden a sub-agent's blast
    /// radius without rewriting the server-level gate.
    ///
    /// ```toml
    /// disallowedTools = ["shell_exec", "file_write"]
    /// ```
    #[serde(default, rename = "disallowedTools")]
    pub disallowed_tools: Vec<String>,
    /// Disable an override without deleting the file.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    // ── GOLD-ADAPT-OH-13: per-agent context-layer omission flags ────────────
    /// Omit the `operator_context` enrichment layer for this agent.
    /// Default: true (agents get their own system; operator context excluded).
    #[serde(default = "default_true")]
    pub omit_operator_context: bool,
    /// Omit the `mcp_catalogue` enrichment layer for this agent.
    /// Default: true.
    #[serde(default = "default_true")]
    pub omit_mcp_catalogue: bool,
    /// Omit the `moral_core` enrichment layer for this agent.
    /// Default: false — moral core stays injected for safety by default.
    #[serde(default)]
    pub omit_moral_core: bool,
    /// Omit the `preset_addendum` enrichment layer for this agent.
    /// Default: true.
    #[serde(default = "default_true")]
    pub omit_preset: bool,
    /// Omit the recall block (Block::D memory episodes) for this agent.
    /// Default: true.
    #[serde(default = "default_true")]
    pub omit_recall: bool,
    /// Omit the `repo_context_block` enrichment layer for this agent.
    /// Default: true.
    #[serde(default = "default_true")]
    pub omit_repo_context: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

impl SubAgent {
    /// True if this agent is allowed to call `tool_name`.
    pub fn allows_tool(&self, tool_name: &str) -> bool {
        self.tools.iter().any(|t| t == tool_name)
    }

    /// True if this agent's denylist forbids `tool_name`.
    /// The denylist WINS over the allow-list: a tool in both is denied.
    pub fn denies_tool(&self, tool_name: &str) -> bool {
        self.disallowed_tools.iter().any(|t| t == tool_name)
    }

    /// GOLD-ADAPT-OH-13 — convert this agent's `omit_*` TOML fields into
    /// the typed [`AgentOmitFlags`] struct used by the enrichment rebuild.
    pub fn to_omit_flags(&self) -> AgentOmitFlags {
        AgentOmitFlags {
            operator_context: self.omit_operator_context,
            mcp_catalogue: self.omit_mcp_catalogue,
            moral_core: self.omit_moral_core,
            preset: self.omit_preset,
            recall: self.omit_recall,
            repo_context: self.omit_repo_context,
        }
    }
}

// ─── QM-5 NEXUS handoff types ───────────────────────────────────────────────

/// Handoff priority. NEXUS spec uses Low/Normal/High/Critical; ports
/// verbatim so operators familiar with the NEXUS taxonomy don't have
/// to relearn it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffPriority {
    Low,
    Normal,
    High,
    Critical,
}

impl Default for HandoffPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// One-shot work item flowing FROM one agent TO another. Replaces the
/// pre-QM-5 implicit handoff (just task text + WAL frame) with a
/// structured contract.
///
/// Wire serialised as JSON for two reasons:
///   1. WAL frames live in `0x7X` event band (coding workflow) and
///      already carry JSON payloads.
///   2. The `neoth code show <task>` operator surface renders the
///      request structure for grep-friendly diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAgentRequest {
    /// Sender agent id — `"cerebellum"`, `"left"`, `"right"`, or any
    /// operator-defined sub-agent name from [`SubAgent::name`].
    pub from: String,
    /// Recipient agent id.
    pub to: String,
    /// Workflow phase — `"plan"` / `"implementation"` / `"verify"` /
    /// `"merge"`. Operator-readable; the dispatcher doesn't enforce a
    /// fixed enum so future phases don't need a schema bump.
    pub phase: String,
    /// Stable task identifier — typically `idx_kanban_*.task_id`.
    pub task_id: String,
    /// Urgency — drives dispatcher scheduling (`Critical` preempts
    /// in-flight Low/Normal work; default `Normal`).
    #[serde(default)]
    pub priority: HandoffPriority,
    /// Free-form context for the recipient — current state, relevant
    /// files, dependencies. NEXUS calls this `current_state`.
    pub context: String,
    /// What the recipient must produce — patch, test plan, verdict,
    /// summary. NEXUS calls this `deliverable`.
    pub deliverable: String,
    /// Acceptance criteria the deliverable must satisfy. Recipient's
    /// QA verdict (`SubAgentResult::verdict`) checks these. Empty
    /// list means "no formal criteria" — recipient applies its own
    /// judgment.
    #[serde(default)]
    pub success_criteria: Vec<String>,
    /// What evidence the recipient must include in its response.
    /// `cargo test` output, `file:line` citations, etc. Drives the
    /// EvidenceCollector sub-agent's verification pass.
    #[serde(default)]
    pub evidence_required: Vec<String>,
    /// Wall-clock seconds when the handoff was created. Used for
    /// stale-handoff detection (a 24h-old Critical request that
    /// hasn't been picked up flags an operator alert).
    pub ts_unix: i64,
}

/// Content-free audit evidence for one real provider invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAgentProviderCall {
    /// `primary` or `qa`.
    pub stage: String,
    /// One-based candidate attempt.
    pub attempt: u8,
    /// Authoritative B22-stamped leaf provider.
    pub provider: String,
    /// Exact model identifier sent on the provider wire.
    pub wire_model: String,
    #[serde(default)]
    pub input_tokens: Option<u32>,
    #[serde(default)]
    pub output_tokens: Option<u32>,
    /// Behavior-neutral NCT-01 measurement of the already-dispatched request
    /// and completion. Absent on legacy records and on callers which do not
    /// collect this bounded sub-agent baseline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_baseline: Option<SubAgentPromptBaseline>,
}

/// Content-free shape of one sub-agent provider request.
///
/// These are byte counts of known construction segments, not a reconstruction
/// from a rendered prompt. Local token values are deliberately conservative
/// upper bounds (`bytes`, because a UTF-8 token cannot consume fewer than one
/// byte); provider-native usage, when reported, lives beside this shape in
/// [`SubAgentPromptBaseline`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAgentPromptShape {
    pub prompt_bytes: u64,
    pub system_bytes: u64,
    pub context_bytes: u64,
    pub candidate_bytes: u64,
    pub qa_failure_bytes: u64,
    /// Bytes carried again from an earlier current-path stage. This is a
    /// duplication measure, not a content fingerprint.
    pub repeated_segment_bytes: u64,
    pub prompt_tokens_upper_bound: u64,
    pub system_tokens_upper_bound: u64,
    pub context_tokens_upper_bound: u64,
    pub candidate_tokens_upper_bound: u64,
    pub qa_failure_tokens_upper_bound: u64,
    pub total_request_tokens_upper_bound: u64,
}

/// Behavior-neutral NCT-01 measurement attached to one existing provider
/// call. It deliberately contains no prompt, candidate, verdict, request ID,
/// hash, route, or content-derived identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAgentPromptBaseline {
    pub shape: SubAgentPromptShape,
    /// Provider-native usage is optional: `None` means it was not reported,
    /// while `Some(0)` is a real reported zero.
    #[serde(default)]
    pub input_tokens: Option<u32>,
    #[serde(default)]
    pub output_tokens: Option<u32>,
    #[serde(default)]
    pub cache_creation_tokens: Option<u32>,
    #[serde(default)]
    pub cache_read_tokens: Option<u32>,
    /// Wall-clock request-to-last-token duration reported by `Completion`.
    pub completion_latency_ms: u64,
}

/// Fixed on-disk schema for the content-free NCT-01 baseline corpus.
///
/// This corpus is an evaluation artifact only. It is intentionally separate
/// from provider requests, routing receipts, WAL identity, and private run
/// records so collecting a baseline cannot change a dispatch decision.
pub const NCT_BASELINE_CORPUS_SCHEMA_V2: &str = "neoth.nct-baseline-corpus.v2";
pub const NCT_BASELINE_TRAIN_FIXTURE_PATH: &str =
    "tests/fixtures/nct_baseline/nct_baseline_train_v2.json";
pub const NCT_BASELINE_HOLDOUT_FIXTURE_PATH: &str =
    "tests/fixtures/nct_baseline/nct_baseline_holdout_v2.json";
pub const NCT_BASELINE_MEMBERSHIP_VERSION: &str = "neoth.nct-baseline-membership.v1";
pub const NCT_BASELINE_MEMBERSHIP_SHA256: &str =
    "e60dabbe0f227c22eee803da19d2de5547c2cf8a6fbe78c24293813a4e93778d";
pub const NCT_BASELINE_CANONICAL_CORPUS_VERSION: &str = "neoth.nct-baseline-canonical-json.v1";
pub const NCT_BASELINE_TRAIN_CORPUS_SHA256: &str =
    "0ddae3251624b615ff3099d4f68743c734953bd4610ee2d782440fd71496c0ef";
pub const NCT_BASELINE_HOLDOUT_CORPUS_SHA256: &str =
    "a311b0989da51e4c7193db6af8d24278d31540355f0d5215129b3c41740fa311";
pub const NCT_BASELINE_CONTENT_FREE_POLICY_V1: &str = "content_free_v1";
pub const NCT_BASELINE_MAX_FIXTURE_BYTES: usize = 256 * 1024;
pub const NCT_BASELINE_TRAIN_CASE_IDS: [&str; 4] = [
    "nct-train-direct-pass",
    "nct-train-nexus-pass",
    "nct-train-council-pass",
    "nct-train-retry-fail",
];
pub const NCT_BASELINE_HOLDOUT_CASE_IDS: [&str; 4] = [
    "nct-holdout-fallback-blocked",
    "nct-holdout-streaming-pass",
    "nct-holdout-sub-agent-pass",
    "nct-holdout-cluster-worker-fail",
];

const NCT_BASELINE_MEMBERSHIP_MANIFEST: &str = concat!(
    "neoth.nct-baseline-membership.v1\n",
    "train:nct-train-direct-pass\n",
    "train:nct-train-nexus-pass\n",
    "train:nct-train-council-pass\n",
    "train:nct-train-retry-fail\n",
    "holdout:nct-holdout-fallback-blocked\n",
    "holdout:nct-holdout-streaming-pass\n",
    "holdout:nct-holdout-sub-agent-pass\n",
    "holdout:nct-holdout-cluster-worker-fail",
);

const NCT_FORBIDDEN_RAW_FRAGMENTS: &[&[u8]] = &[
    b"NCT_RAW_",
    b"sk-",
    b"ghp_",
    b"xoxb-",
    b"xapp-",
    b"AKIA",
    b"Bearer ",
    b"-----BEGIN",
];

const NCT_FORBIDDEN_JSON_FIELDS: &[&str] = &[
    "prompt",
    "system",
    "context",
    "candidate",
    "qa_failures",
    "raw_prompt",
    "raw_system",
    "raw_context",
    "raw_candidate",
    "operator_data",
    "operator_task",
    "secret",
    "api_key",
    "provider_error",
    "request_id",
    "content_hash",
    "remote_payload",
];

/// Closed current-path label used by the NCT-01 corpus.
///
/// It is deliberately a route family rather than a provider, model, task,
/// user, request, or content-derived identifier. The `nexus` row contains
/// the existing NEXUS primary/QA envelope; it does not introduce a new
/// dispatch path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NctRouteIdentity {
    Direct,
    Nexus,
    Council,
    Retry,
    Fallback,
    Streaming,
    SubAgent,
    ClusterWorker,
}

impl NctRouteIdentity {
    pub const ALL: [Self; 8] = [
        Self::Direct,
        Self::Nexus,
        Self::Council,
        Self::Retry,
        Self::Fallback,
        Self::Streaming,
        Self::SubAgent,
        Self::ClusterWorker,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Nexus => "nexus",
            Self::Council => "council",
            Self::Retry => "retry",
            Self::Fallback => "fallback",
            Self::Streaming => "streaming",
            Self::SubAgent => "sub_agent",
            Self::ClusterWorker => "cluster_worker",
        }
    }
}

/// Mutually exclusive fixture partitions. A holdout case must never become a
/// train case under the same corpus version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NctFixtureSplit {
    Train,
    Holdout,
}

/// Closed fixture identity. Arbitrary, overlong, path-like, or cross-split
/// corpus identifiers cannot deserialize into this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NctCorpusId {
    #[serde(rename = "nct-baseline-train-v2")]
    TrainV2,
    #[serde(rename = "nct-baseline-holdout-v2")]
    HoldoutV2,
}

impl NctCorpusId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrainV2 => "nct-baseline-train-v2",
            Self::HoldoutV2 => "nct-baseline-holdout-v2",
        }
    }

    pub const fn split(self) -> NctFixtureSplit {
        match self {
            Self::TrainV2 => NctFixtureSplit::Train,
            Self::HoldoutV2 => NctFixtureSplit::Holdout,
        }
    }
}

/// Closed declaration that the corpus carries measurements only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NctRawContentPolicy {
    #[serde(rename = "content_free_v1")]
    ContentFreeV1,
}

impl NctRawContentPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContentFreeV1 => NCT_BASELINE_CONTENT_FREE_POLICY_V1,
        }
    }
}

/// Content-free terminal-quality classification for a frozen baseline case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NctQualityOutcome {
    Pass,
    Fail,
    Blocked,
}

/// Closed reason class for a baseline failure. No provider error, prompt,
/// secret, operator text, or remote payload is retained here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NctFailureClass {
    Provider,
    Qa,
    Policy,
    Timeout,
    Transport,
}

/// NCT-fixture-specific prompt shape. It mirrors the established
/// [`SubAgentPromptShape`] measurements but is strict at every nested JSON
/// boundary, so an unknown raw-content field cannot be silently discarded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NctPromptShape {
    prompt_bytes: u64,
    system_bytes: u64,
    context_bytes: u64,
    candidate_bytes: u64,
    qa_failure_bytes: u64,
    repeated_segment_bytes: u64,
    prompt_tokens_upper_bound: u64,
    system_tokens_upper_bound: u64,
    context_tokens_upper_bound: u64,
    candidate_tokens_upper_bound: u64,
    qa_failure_tokens_upper_bound: u64,
    total_request_tokens_upper_bound: u64,
}

impl NctPromptShape {
    pub const fn prompt_bytes(&self) -> u64 {
        self.prompt_bytes
    }

    pub const fn system_bytes(&self) -> u64 {
        self.system_bytes
    }

    pub const fn context_bytes(&self) -> u64 {
        self.context_bytes
    }

    pub const fn candidate_bytes(&self) -> u64 {
        self.candidate_bytes
    }

    pub const fn qa_failure_bytes(&self) -> u64 {
        self.qa_failure_bytes
    }

    pub const fn repeated_segment_bytes(&self) -> u64 {
        self.repeated_segment_bytes
    }

    pub const fn prompt_tokens_upper_bound(&self) -> u64 {
        self.prompt_tokens_upper_bound
    }

    pub const fn system_tokens_upper_bound(&self) -> u64 {
        self.system_tokens_upper_bound
    }

    pub const fn context_tokens_upper_bound(&self) -> u64 {
        self.context_tokens_upper_bound
    }

    pub const fn candidate_tokens_upper_bound(&self) -> u64 {
        self.candidate_tokens_upper_bound
    }

    pub const fn qa_failure_tokens_upper_bound(&self) -> u64 {
        self.qa_failure_tokens_upper_bound
    }

    pub const fn total_request_tokens_upper_bound(&self) -> u64 {
        self.total_request_tokens_upper_bound
    }
}

impl From<&SubAgentPromptShape> for NctPromptShape {
    fn from(shape: &SubAgentPromptShape) -> Self {
        Self {
            prompt_bytes: shape.prompt_bytes,
            system_bytes: shape.system_bytes,
            context_bytes: shape.context_bytes,
            candidate_bytes: shape.candidate_bytes,
            qa_failure_bytes: shape.qa_failure_bytes,
            repeated_segment_bytes: shape.repeated_segment_bytes,
            prompt_tokens_upper_bound: shape.prompt_tokens_upper_bound,
            system_tokens_upper_bound: shape.system_tokens_upper_bound,
            context_tokens_upper_bound: shape.context_tokens_upper_bound,
            candidate_tokens_upper_bound: shape.candidate_tokens_upper_bound,
            qa_failure_tokens_upper_bound: shape.qa_failure_tokens_upper_bound,
            total_request_tokens_upper_bound: shape.total_request_tokens_upper_bound,
        }
    }
}

/// Strict NCT fixture measurement using the same absence-versus-reported-zero
/// usage semantics as [`SubAgentPromptBaseline`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NctPromptBaseline {
    shape: NctPromptShape,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    cache_creation_tokens: Option<u32>,
    cache_read_tokens: Option<u32>,
    completion_latency_ms: u64,
}

impl NctPromptBaseline {
    pub const fn shape(&self) -> &NctPromptShape {
        &self.shape
    }

    pub const fn input_tokens(&self) -> Option<u32> {
        self.input_tokens
    }

    pub const fn output_tokens(&self) -> Option<u32> {
        self.output_tokens
    }

    pub const fn cache_creation_tokens(&self) -> Option<u32> {
        self.cache_creation_tokens
    }

    pub const fn cache_read_tokens(&self) -> Option<u32> {
        self.cache_read_tokens
    }

    pub const fn completion_latency_ms(&self) -> u64 {
        self.completion_latency_ms
    }
}

impl From<&SubAgentPromptBaseline> for NctPromptBaseline {
    fn from(baseline: &SubAgentPromptBaseline) -> Self {
        Self {
            shape: NctPromptShape::from(&baseline.shape),
            input_tokens: baseline.input_tokens,
            output_tokens: baseline.output_tokens,
            cache_creation_tokens: baseline.cache_creation_tokens,
            cache_read_tokens: baseline.cache_read_tokens,
            completion_latency_ms: baseline.completion_latency_ms,
        }
    }
}

/// Bounded result metadata paired with one NCT baseline measurement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NctBaselineOutcome {
    /// Aggregate billed cost in micro-units from the frozen fixture, never a
    /// provider receipt or account identifier.
    total_cost_microunits: u64,
    /// Existing current-path correction attempts consumed by the case.
    repair_attempts: u8,
    quality: NctQualityOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<NctFailureClass>,
}

impl NctBaselineOutcome {
    pub const fn total_cost_microunits(&self) -> u64 {
        self.total_cost_microunits
    }

    pub const fn repair_attempts(&self) -> u8 {
        self.repair_attempts
    }

    pub const fn quality(&self) -> NctQualityOutcome {
        self.quality
    }

    pub const fn failure(&self) -> Option<NctFailureClass> {
        self.failure
    }
}

/// One frozen, content-free current-path observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NctBaselineCase {
    /// Synthetic fixture-only label. It is not a task, request, subject,
    /// provider, model, hash, or operator identifier.
    case_id: String,
    route: NctRouteIdentity,
    /// Reuses the sub-agent baseline's numeric semantics through an
    /// NCT-specific, deny-unknown-fields representation.
    prompt_baseline: NctPromptBaseline,
    outcome: NctBaselineOutcome,
}

impl NctBaselineCase {
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    pub const fn route(&self) -> NctRouteIdentity {
        self.route
    }

    pub const fn prompt_baseline(&self) -> &NctPromptBaseline {
        &self.prompt_baseline
    }

    pub const fn outcome(&self) -> &NctBaselineOutcome {
        &self.outcome
    }
}

/// A strict single-split NCT-01 corpus fixture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NctBaselineCorpus {
    schema: String,
    corpus_id: NctCorpusId,
    split: NctFixtureSplit,
    raw_content_policy: NctRawContentPolicy,
    cases: Vec<NctBaselineCase>,
}

impl NctBaselineCorpus {
    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub const fn corpus_id(&self) -> NctCorpusId {
        self.corpus_id
    }

    pub const fn split(&self) -> NctFixtureSplit {
        self.split
    }

    pub const fn raw_content_policy(&self) -> NctRawContentPolicy {
        self.raw_content_policy
    }

    pub fn cases(&self) -> &[NctBaselineCase] {
        &self.cases
    }
}

/// Private wire-only types keep `Deserialize` behind
/// [`parse_nct_baseline_fixture`]. Every nested object is strict so no field
/// can disappear between the lossless `Value` review and the validated,
/// opaque public corpus.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NctPromptShapeWire {
    prompt_bytes: u64,
    system_bytes: u64,
    context_bytes: u64,
    candidate_bytes: u64,
    qa_failure_bytes: u64,
    repeated_segment_bytes: u64,
    prompt_tokens_upper_bound: u64,
    system_tokens_upper_bound: u64,
    context_tokens_upper_bound: u64,
    candidate_tokens_upper_bound: u64,
    qa_failure_tokens_upper_bound: u64,
    total_request_tokens_upper_bound: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NctPromptBaselineWire {
    shape: NctPromptShapeWire,
    #[serde(default)]
    input_tokens: Option<u32>,
    #[serde(default)]
    output_tokens: Option<u32>,
    #[serde(default)]
    cache_creation_tokens: Option<u32>,
    #[serde(default)]
    cache_read_tokens: Option<u32>,
    completion_latency_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NctBaselineOutcomeWire {
    total_cost_microunits: u64,
    repair_attempts: u8,
    quality: NctQualityOutcome,
    #[serde(default)]
    failure: Option<NctFailureClass>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NctBaselineCaseWire {
    case_id: String,
    route: NctRouteIdentity,
    prompt_baseline: NctPromptBaselineWire,
    outcome: NctBaselineOutcomeWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NctBaselineCorpusWire {
    schema: String,
    corpus_id: NctCorpusId,
    split: NctFixtureSplit,
    raw_content_policy: NctRawContentPolicy,
    cases: Vec<NctBaselineCaseWire>,
}

impl From<NctPromptShapeWire> for NctPromptShape {
    fn from(shape: NctPromptShapeWire) -> Self {
        Self {
            prompt_bytes: shape.prompt_bytes,
            system_bytes: shape.system_bytes,
            context_bytes: shape.context_bytes,
            candidate_bytes: shape.candidate_bytes,
            qa_failure_bytes: shape.qa_failure_bytes,
            repeated_segment_bytes: shape.repeated_segment_bytes,
            prompt_tokens_upper_bound: shape.prompt_tokens_upper_bound,
            system_tokens_upper_bound: shape.system_tokens_upper_bound,
            context_tokens_upper_bound: shape.context_tokens_upper_bound,
            candidate_tokens_upper_bound: shape.candidate_tokens_upper_bound,
            qa_failure_tokens_upper_bound: shape.qa_failure_tokens_upper_bound,
            total_request_tokens_upper_bound: shape.total_request_tokens_upper_bound,
        }
    }
}

impl From<NctPromptBaselineWire> for NctPromptBaseline {
    fn from(baseline: NctPromptBaselineWire) -> Self {
        Self {
            shape: baseline.shape.into(),
            input_tokens: baseline.input_tokens,
            output_tokens: baseline.output_tokens,
            cache_creation_tokens: baseline.cache_creation_tokens,
            cache_read_tokens: baseline.cache_read_tokens,
            completion_latency_ms: baseline.completion_latency_ms,
        }
    }
}

impl From<NctBaselineOutcomeWire> for NctBaselineOutcome {
    fn from(outcome: NctBaselineOutcomeWire) -> Self {
        Self {
            total_cost_microunits: outcome.total_cost_microunits,
            repair_attempts: outcome.repair_attempts,
            quality: outcome.quality,
            failure: outcome.failure,
        }
    }
}

impl From<NctBaselineCaseWire> for NctBaselineCase {
    fn from(case: NctBaselineCaseWire) -> Self {
        Self {
            case_id: case.case_id,
            route: case.route,
            prompt_baseline: case.prompt_baseline.into(),
            outcome: case.outcome.into(),
        }
    }
}

impl From<NctBaselineCorpusWire> for NctBaselineCorpus {
    fn from(corpus: NctBaselineCorpusWire) -> Self {
        Self {
            schema: corpus.schema,
            corpus_id: corpus.corpus_id,
            split: corpus.split,
            raw_content_policy: corpus.raw_content_policy,
            cases: corpus.cases.into_iter().map(Into::into).collect(),
        }
    }
}

/// Stable, deterministic summary of the two required corpus partitions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NctBaselineCoverageReport {
    pub schema: String,
    pub membership_version: String,
    pub membership_sha256: String,
    pub canonical_corpus_version: String,
    pub train_corpus_sha256: String,
    pub holdout_corpus_sha256: String,
    pub train_fixture_path: String,
    pub holdout_fixture_path: String,
    pub train_case_count: u32,
    pub holdout_case_count: u32,
    /// Sorted route labels and counts; a map is used instead of encounter
    /// order so the report is reproducible across fixture ordering changes.
    pub route_case_counts: std::collections::BTreeMap<String, u32>,
}

struct NctNoDuplicateValueSeed;

impl<'de> serde::de::DeserializeSeed<'de> for NctNoDuplicateValueSeed {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NctNoDuplicateValueVisitor)
    }
}

struct NctNoDuplicateValueVisitor;

impl<'de> serde::de::Visitor<'de> for NctNoDuplicateValueVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("non-finite number in NCT fixture"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde::de::DeserializeSeed::deserialize(NctNoDuplicateValueSeed, deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element_seed(NctNoDuplicateValueSeed)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(
                    "duplicate JSON object key in NCT fixture",
                ));
            }
            let value = object.next_value_seed(NctNoDuplicateValueSeed)?;
            values.insert(key, value);
        }
        Ok(serde_json::Value::Object(values))
    }
}

fn parse_nct_json_value(raw: &[u8]) -> Result<serde_json::Value, String> {
    use serde::de::DeserializeSeed as _;

    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = NctNoDuplicateValueSeed
        .deserialize(&mut deserializer)
        .map_err(|error| {
            if error
                .to_string()
                .contains("duplicate JSON object key in NCT fixture")
            {
                "invalid NCT fixture JSON: duplicate object key".to_string()
            } else {
                format!("invalid NCT fixture JSON: {error}")
            }
        })?;
    deserializer
        .end()
        .map_err(|error| format!("invalid NCT fixture JSON: {error}"))?;
    Ok(value)
}

/// Inspect raw bytes and the lossless JSON value before strict typed
/// deserialization. Sensitive fragments and forbidden content-bearing field
/// names are rejected without echoing their values into an error.
pub fn parse_nct_baseline_fixture(raw: &[u8]) -> Result<NctBaselineCorpus, String> {
    if raw.len() > NCT_BASELINE_MAX_FIXTURE_BYTES {
        return Err("NCT fixture exceeds the byte limit".to_string());
    }
    reject_nct_raw_fragments(raw)?;
    let value = parse_nct_json_value(raw)?;
    validate_nct_fixture_value(&value)?;
    verify_nct_membership_pin()?;
    let wire: NctBaselineCorpusWire = serde_json::from_value(value).map_err(|error| {
        let error = error.to_string();
        if error.contains("unknown field") {
            "invalid NCT fixture schema: unknown field".to_string()
        } else if error.contains("unknown variant") {
            "invalid NCT fixture schema: value is outside a closed set".to_string()
        } else {
            "invalid NCT fixture schema".to_string()
        }
    })?;
    let corpus: NctBaselineCorpus = wire.into();
    validate_nct_corpus(&corpus, corpus.corpus_id.split())?;
    verify_nct_corpus_pin(&corpus)?;
    Ok(corpus)
}

/// Validate the two disjoint fixture partitions and return a stable coverage
/// report. This function is intentionally pure: it neither opens files nor
/// calls providers, changes routing, or records anything.
pub fn nct_baseline_coverage_report(
    train: &NctBaselineCorpus,
    holdout: &NctBaselineCorpus,
) -> Result<NctBaselineCoverageReport, String> {
    verify_nct_membership_pin()?;
    validate_nct_corpus(train, NctFixtureSplit::Train)?;
    validate_nct_corpus(holdout, NctFixtureSplit::Holdout)?;
    verify_nct_corpus_pin(train)?;
    verify_nct_corpus_pin(holdout)?;
    if train.corpus_id == holdout.corpus_id {
        return Err("NCT train and holdout corpus ids must differ".to_string());
    }

    let mut case_ids = std::collections::BTreeSet::new();
    let mut route_case_counts = std::collections::BTreeMap::new();
    for corpus in [train, holdout] {
        for case in &corpus.cases {
            if !case_ids.insert(case.case_id.as_str()) {
                return Err("NCT case id appears in both splits".to_string());
            }
            *route_case_counts
                .entry(case.route.as_str().to_string())
                .or_insert(0) += 1;
        }
    }
    for route in NctRouteIdentity::ALL {
        if !route_case_counts.contains_key(route.as_str()) {
            return Err(format!(
                "NCT corpus does not cover route: {}",
                route.as_str()
            ));
        }
    }

    Ok(NctBaselineCoverageReport {
        schema: NCT_BASELINE_CORPUS_SCHEMA_V2.to_string(),
        membership_version: NCT_BASELINE_MEMBERSHIP_VERSION.to_string(),
        membership_sha256: NCT_BASELINE_MEMBERSHIP_SHA256.to_string(),
        canonical_corpus_version: NCT_BASELINE_CANONICAL_CORPUS_VERSION.to_string(),
        train_corpus_sha256: NCT_BASELINE_TRAIN_CORPUS_SHA256.to_string(),
        holdout_corpus_sha256: NCT_BASELINE_HOLDOUT_CORPUS_SHA256.to_string(),
        train_fixture_path: NCT_BASELINE_TRAIN_FIXTURE_PATH.to_string(),
        holdout_fixture_path: NCT_BASELINE_HOLDOUT_FIXTURE_PATH.to_string(),
        train_case_count: train.cases.len().try_into().unwrap_or(u32::MAX),
        holdout_case_count: holdout.cases.len().try_into().unwrap_or(u32::MAX),
        route_case_counts,
    })
}

fn validate_nct_corpus(
    corpus: &NctBaselineCorpus,
    expected_split: NctFixtureSplit,
) -> Result<(), String> {
    if corpus.schema != NCT_BASELINE_CORPUS_SCHEMA_V2 {
        return Err("unsupported NCT corpus schema".to_string());
    }
    if corpus.split != expected_split {
        return Err(format!(
            "NCT fixture split mismatch: expected {:?}, got {:?}",
            expected_split, corpus.split
        ));
    }
    if corpus.corpus_id.split() != expected_split {
        return Err(format!(
            "NCT corpus id {} belongs to the wrong split",
            corpus.corpus_id.as_str()
        ));
    }
    if corpus.raw_content_policy != NctRawContentPolicy::ContentFreeV1 {
        return Err("NCT corpus content policy is not the reviewed closed policy".to_string());
    }
    if corpus.cases.is_empty() {
        return Err("NCT corpus must contain at least one case".to_string());
    }
    let (expected_id, expected_prefix, expected_cases): (NctCorpusId, &str, &[&str]) =
        match expected_split {
            NctFixtureSplit::Train => (
                NctCorpusId::TrainV2,
                "nct-train-",
                &NCT_BASELINE_TRAIN_CASE_IDS,
            ),
            NctFixtureSplit::Holdout => (
                NctCorpusId::HoldoutV2,
                "nct-holdout-",
                &NCT_BASELINE_HOLDOUT_CASE_IDS,
            ),
        };
    if corpus.corpus_id != expected_id {
        return Err(format!(
            "NCT corpus id does not match its frozen split: {}",
            corpus.corpus_id.as_str()
        ));
    }
    for (case_index, case) in corpus.cases.iter().enumerate() {
        if case.case_id.is_empty()
            || case.case_id.len() > 80
            || !case
                .case_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(format!(
                "invalid synthetic NCT case id at index {case_index}"
            ));
        }
        if !case.case_id.starts_with(expected_prefix) {
            return Err(format!(
                "NCT case id has the wrong split prefix at index {case_index}"
            ));
        }
        validate_nct_prompt_baseline(case_index, &case.prompt_baseline)?;
        if case.outcome.repair_attempts > 1 {
            return Err(format!(
                "NCT case at index {case_index} exceeds the current one-correction bound"
            ));
        }
        match (case.outcome.quality, case.outcome.failure) {
            (NctQualityOutcome::Pass, None)
            | (NctQualityOutcome::Fail, Some(_))
            | (NctQualityOutcome::Blocked, Some(_)) => {}
            (NctQualityOutcome::Pass, Some(_)) => {
                return Err(format!(
                    "passing NCT case at index {case_index} has failure metadata"
                ));
            }
            (NctQualityOutcome::Fail | NctQualityOutcome::Blocked, None) => {
                return Err(format!(
                    "failed NCT case at index {case_index} lacks failure metadata"
                ));
            }
        }
    }
    let actual_cases = corpus
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<Vec<_>>();
    if actual_cases.as_slice() != expected_cases {
        return Err(format!(
            "NCT {} membership differs from the reviewed manifest",
            corpus.corpus_id.as_str()
        ));
    }
    Ok(())
}

fn validate_nct_prompt_baseline(
    case_index: usize,
    baseline: &NctPromptBaseline,
) -> Result<(), String> {
    let shape = &baseline.shape;
    let exact_upper_bounds = shape.prompt_tokens_upper_bound == shape.prompt_bytes
        && shape.system_tokens_upper_bound == shape.system_bytes
        && shape.context_tokens_upper_bound == shape.context_bytes
        && shape.candidate_tokens_upper_bound == shape.candidate_bytes
        && shape.qa_failure_tokens_upper_bound == shape.qa_failure_bytes
        && shape.total_request_tokens_upper_bound
            == shape.prompt_bytes.saturating_add(shape.system_bytes);
    if !exact_upper_bounds {
        return Err(format!(
            "NCT prompt-shape upper bounds drifted at case index {case_index}"
        ));
    }
    let repeatable_bytes = shape
        .context_bytes
        .saturating_add(shape.candidate_bytes)
        .saturating_add(shape.qa_failure_bytes);
    if shape.repeated_segment_bytes > repeatable_bytes {
        return Err(format!(
            "NCT repeated-context bytes exceed known segments at case index {case_index}"
        ));
    }
    Ok(())
}

fn reject_nct_raw_fragments(raw: &[u8]) -> Result<(), String> {
    if NCT_FORBIDDEN_RAW_FRAGMENTS.iter().any(|fragment| {
        raw.windows(fragment.len())
            .any(|window| window == *fragment)
    }) {
        return Err("NCT fixture contains a forbidden raw-content fragment".to_string());
    }
    Ok(())
}

fn validate_nct_fixture_value(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Object(fields) => {
            for (field, child) in fields {
                if NCT_FORBIDDEN_JSON_FIELDS.contains(&field.as_str()) {
                    return Err(format!(
                        "NCT fixture contains forbidden content-bearing field: {field}"
                    ));
                }
                validate_nct_fixture_value(child)?;
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                validate_nct_fixture_value(child)?;
            }
        }
        serde_json::Value::String(text) => reject_nct_raw_fragments(text.as_bytes())?,
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn verify_nct_corpus_pin(corpus: &NctBaselineCorpus) -> Result<(), String> {
    let canonical = serde_json::to_vec(corpus)
        .map_err(|_| "failed to canonicalize the NCT corpus".to_string())?;
    let expected = match corpus.corpus_id {
        NctCorpusId::TrainV2 => NCT_BASELINE_TRAIN_CORPUS_SHA256,
        NctCorpusId::HoldoutV2 => NCT_BASELINE_HOLDOUT_CORPUS_SHA256,
    };
    if nct_sha256_hex(&canonical) != expected {
        return Err("NCT canonical corpus digest drifted".to_string());
    }
    Ok(())
}

fn verify_nct_membership_pin() -> Result<(), String> {
    let digest = nct_sha256_hex(NCT_BASELINE_MEMBERSHIP_MANIFEST.as_bytes());
    if digest != NCT_BASELINE_MEMBERSHIP_SHA256 {
        return Err("NCT reviewed membership manifest digest drifted".to_string());
    }
    Ok(())
}

fn nct_sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;

    hex::encode(sha2::Sha256::digest(bytes))
}

/// Response from a sub-agent back to its caller (typically Cerebellum)
/// or forward to the next sub-agent in the chain. The verdict field
/// carries the structured PASS/FAIL/BLOCKED outcome from QM-6
/// (`QaVerdict`) so the dispatcher's retry path has typed routing
/// instead of free-form text parsing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubAgentResult {
    /// The sub-agent that produced this result.
    pub from: String,
    /// Intended recipient — usually `"cerebellum"`, sometimes a peer.
    pub to: String,
    /// Mirrors the originating `SubAgentRequest::task_id` so the
    /// dispatcher can correlate handoffs across the chain.
    pub task_id: String,
    /// Structured pass/fail/blocked. Pass → merge, Fail → retry path
    /// consumes the failure items, Blocked → escalate to operator.
    pub verdict: QaVerdict,
    /// Free-form evidence the sub-agent collected — `cargo test`
    /// excerpts, screenshots, log lines, citations. Operators see
    /// this in `neoth code show <task>`.
    #[serde(default)]
    pub evidence: Vec<String>,
    /// Full operator-requested result. Stored only in the private run record;
    /// WAL receives hashes and typed verdict metadata, never this content.
    #[serde(default)]
    pub output: String,
    /// Exact leaf identity for every primary/QA provider call.
    #[serde(default)]
    pub provider_calls: Vec<SubAgentProviderCall>,
    /// Candidate attempts consumed (1 normally; hard-capped at 2).
    #[serde(default)]
    pub attempts: u8,
    /// Optional pointer to the next sub-agent in the chain. `Some`
    /// for Dev → QA handoffs; `None` for terminal results that close
    /// the kanban row.
    #[serde(default)]
    pub next_agent: Option<String>,
    /// Wall-clock seconds when the result was emitted.
    pub ts_unix: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_agent() {
        let toml_src = r#"
            name = "planner"
            description = "Plan complex changes"
            system = "You are a planner."
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert_eq!(a.name, "planner");
        assert!(a.enabled);
        assert!(a.model.is_none());
        assert!(a.tools.is_empty());
    }

    #[test]
    fn parses_full_agent_with_tools() {
        let toml_src = r#"
            name = "reviewer"
            description = "Review"
            model = "claude-opus-4-7"
            system = "Be thorough."
            tools = ["recall", "ctx_search", "groundtruth_list"]
            enabled = true
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert_eq!(a.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(a.tools.len(), 3);
        assert!(a.allows_tool("recall"));
        assert!(!a.allows_tool("nope"));
    }

    #[test]
    fn disabled_round_trips() {
        let toml_src = r#"
            name = "off"
            description = "Disabled"
            system = "noop"
            enabled = false
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert!(!a.enabled);
    }

    #[test]
    fn empty_tools_means_no_tools() {
        let a = SubAgent {
            name: "n".into(),
            description: "d".into(),
            model: None,
            system: "s".into(),
            tools: vec![],
            disallowed_tools: vec![],
            enabled: true,
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        };
        assert!(!a.allows_tool("anything"));
    }

    #[test]
    fn denies_tool_returns_true_for_listed_tool() {
        let a = SubAgent {
            name: "n".into(),
            description: "d".into(),
            model: None,
            system: "s".into(),
            tools: vec!["safe_tool".into(), "dangerous_tool".into()],
            disallowed_tools: vec!["dangerous_tool".into()],
            enabled: true,
            omit_operator_context: true,
            omit_mcp_catalogue: true,
            omit_moral_core: false,
            omit_preset: true,
            omit_recall: true,
            omit_repo_context: true,
        };
        assert!(
            a.denies_tool("dangerous_tool"),
            "listed tool must be denied"
        );
        assert!(
            !a.denies_tool("safe_tool"),
            "non-listed tool must not be denied"
        );
    }

    #[test]
    fn disallowed_tools_parsed_from_toml() {
        let toml_src = r#"
            name = "hardened"
            description = "Hardened agent"
            system = "Be careful."
            tools = ["shell_exec", "file_read", "file_write"]
            disallowedTools = ["shell_exec", "file_write"]
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert_eq!(a.disallowed_tools, vec!["shell_exec", "file_write"]);
        assert!(a.denies_tool("shell_exec"));
        assert!(a.denies_tool("file_write"));
        assert!(!a.denies_tool("file_read"));
    }

    #[test]
    fn disallowed_tools_defaults_empty_when_absent() {
        let toml_src = r#"
            name = "plain"
            description = "No denylist"
            system = "Normal agent."
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert!(a.disallowed_tools.is_empty());
        assert!(!a.denies_tool("anything"));
    }

    // ── GOLD-ADAPT-OH-13: omit_ flag tests ─────────────────────────────

    #[test]
    fn omit_flags_default_to_true_for_all_but_moral_core() {
        // A minimal TOML with no omit_ fields must produce omit=true for all
        // context layers EXCEPT moral_core, which defaults to false.
        let toml_src = r#"
            name = "planner2"
            description = "Plan"
            system = "Be a planner."
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        assert!(
            a.omit_operator_context,
            "omit_operator_context must default true"
        );
        assert!(a.omit_mcp_catalogue, "omit_mcp_catalogue must default true");
        assert!(a.omit_preset, "omit_preset must default true");
        assert!(a.omit_recall, "omit_recall must default true");
        assert!(a.omit_repo_context, "omit_repo_context must default true");
        assert!(
            !a.omit_moral_core,
            "omit_moral_core must default false (safety layer stays in)"
        );
    }

    #[test]
    fn omit_moral_core_can_be_set_true_in_toml() {
        let toml_src = r#"
            name = "bare-agent"
            description = "No moral core"
            system = "raw system"
            omit_moral_core = true
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        let flags = a.to_omit_flags();
        assert!(
            flags.moral_core,
            "to_omit_flags must propagate omit_moral_core=true"
        );
    }

    #[test]
    fn omit_operator_context_false_in_toml() {
        let toml_src = r#"
            name = "context-agent"
            description = "Wants operator context"
            system = "use context"
            omit_operator_context = false
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        let flags = a.to_omit_flags();
        assert!(!flags.operator_context);
        assert!(!flags.moral_core, "moral_core still false by default");
    }

    #[test]
    fn to_omit_flags_round_trips_all_fields() {
        let toml_src = r#"
            name = "full-omit"
            description = "Everything omitted"
            system = "agent"
            omit_operator_context = true
            omit_mcp_catalogue = true
            omit_moral_core = true
            omit_preset = true
            omit_recall = true
            omit_repo_context = true
        "#;
        let a: SubAgent = toml::from_str(toml_src).unwrap();
        let flags = a.to_omit_flags();
        assert!(flags.operator_context);
        assert!(flags.mcp_catalogue);
        assert!(flags.moral_core);
        assert!(flags.preset);
        assert!(flags.recall);
        assert!(flags.repo_context);
    }

    // ── QM-5 NEXUS handoff tests ────────────────────────────────────────

    #[test]
    fn nexus_request_round_trips_through_json() {
        let r = SubAgentRequest {
            from: "cerebellum".into(),
            to: "right".into(),
            phase: "implementation".into(),
            task_id: "T-42".into(),
            priority: HandoffPriority::High,
            context: "refactor the WAL writer to use io_uring".into(),
            deliverable: "diff against main + cargo test green".into(),
            success_criteria: vec![
                "no clippy warnings".into(),
                "writer_recovers_torn_tail still passes".into(),
            ],
            evidence_required: vec!["paste cargo test output".into()],
            ts_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"priority\":\"high\""));
        let back: SubAgentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn nexus_result_with_pass_verdict_round_trips() {
        let res = SubAgentResult {
            from: "right".into(),
            to: "cerebellum".into(),
            task_id: "T-42".into(),
            verdict: QaVerdict::pass_with_evidence(vec!["1450 tests pass".into()]),
            evidence: vec!["cargo test output: 1450 / 0".into()],
            output: "implementation result".into(),
            provider_calls: vec![],
            attempts: 1,
            next_agent: Some("evidence_collector".into()),
            ts_unix: 1_700_000_500,
        };
        let json = serde_json::to_string(&res).unwrap();
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"kind\":\"pass\""));
        let back: SubAgentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(res, back);
        assert!(back.verdict.is_pass());
    }

    #[test]
    fn nexus_result_with_fail_verdict_round_trips() {
        use crate::council::qa_verdict::FailureItem;
        let res = SubAgentResult {
            from: "left".into(),
            to: "cerebellum".into(),
            task_id: "T-99".into(),
            verdict: QaVerdict::fail(vec![FailureItem {
                kind: "test_failure".into(),
                message: "ArithmeticError in line 88".into(),
                citation: Some("src/math.rs:88".into()),
            }]),
            evidence: vec!["cargo test failed".into()],
            output: "candidate result".into(),
            provider_calls: vec![],
            attempts: 1,
            next_agent: None,
            ts_unix: 1_700_001_000,
        };
        let json = serde_json::to_string(&res).unwrap();
        assert!(json.contains("\"kind\":\"fail\""));
        let back: SubAgentResult = serde_json::from_str(&json).unwrap();
        assert_eq!(res, back);
        assert!(back.verdict.is_retriable());
    }

    #[test]
    fn handoff_priority_round_trips_serde() {
        for p in [
            HandoffPriority::Low,
            HandoffPriority::Normal,
            HandoffPriority::High,
            HandoffPriority::Critical,
        ] {
            let s = serde_json::to_string(&p).unwrap();
            let back: HandoffPriority = serde_json::from_str(&s).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn handoff_priority_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&HandoffPriority::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(
            serde_json::to_string(&HandoffPriority::Normal).unwrap(),
            "\"normal\""
        );
    }

    #[test]
    fn nexus_request_defaults_keep_optional_lists_empty() {
        let minimal = r#"{
            "from": "ce",
            "to": "left",
            "phase": "plan",
            "task_id": "T-1",
            "priority": "normal",
            "context": "x",
            "deliverable": "y",
            "ts_unix": 1
        }"#;
        let r: SubAgentRequest = serde_json::from_str(minimal).unwrap();
        assert!(r.success_criteria.is_empty());
        assert!(r.evidence_required.is_empty());
    }

    #[test]
    fn provider_call_baseline_is_backward_compatible_and_omits_none() {
        let legacy = r#"{
            "stage":"primary",
            "attempt":1,
            "provider":"openai_api",
            "wire_model":"wire-model-v1",
            "input_tokens":null,
            "output_tokens":null
        }"#;
        let call: SubAgentProviderCall = serde_json::from_str(legacy).unwrap();
        assert_eq!(call.prompt_baseline, None);
        let encoded = serde_json::to_value(&call).unwrap();
        assert!(encoded.get("prompt_baseline").is_none());
    }
}
