//! Operational, plugin, updater, supervisor, and profile configuration.

use std::path::PathBuf;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

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
    /// ids default to `PluginActivation::Pending` and are NOT
    /// instantiated until the operator runs `neoth plugin enable
    /// <id>` (or accepts them via the first-run wizard multiselect).
    /// Active records bind the approved permission, canonical manifest
    /// digest, and WASM digest; legacy scalar `active` entries deserialize
    /// safely but require explicit re-consent before they may run.
    ///
    /// Why default-inactive: wasmtime sandbox is strong but the
    /// hostcall surface (channel send, fs, WAL) is the attack
    /// vector — auto-instantiating an unknown `.wasm` bypasses the
    /// consent gate every other auto-discovery path in NEOTH
    /// (channels, providers, skills) already respects. Matches the
    /// conservative defaults n8n + Obsidian already use.
    #[serde(default)]
    pub activations:
        std::collections::BTreeMap<String, crate::wasm_plugin::discovery::PluginActivationRecord>,
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
    // operator to persist an approval-bound Active record before it
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

/// U-04 follow-up: canonical operator input for the reload-owned updater
/// supervisor. The daemon deliberately has no second snapshot/config type.
///
/// The default remains the historical six-hour tick. `enabled` is the global
/// recurring-lane master switch. CLI and Skill/Plugin probes use
/// `interval_secs`; the neoth-self probe uses the more specific
/// `auto_update.check_interval_secs` so checks and staging stay aligned.
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
    /// GOLD-ADAPT-GRILL-04 — Socratic brainstorm pre-flight ahead of
    /// `neoth code` decomposition. Pure heuristic (zero LLM cost);
    /// interactive refinement only on a TTY, warn-and-proceed otherwise.
    /// Default ON (features-default-on rule); this is the kill-switch.
    #[serde(default = "default_coding_gate")]
    pub brainstorm_gate: bool,
    /// GOLD-ADAPT-GRILL-02 — adversarial plan review after decomposition
    /// (`coding::plan_review::review_plan`, ≤5 Cerebellum rounds). A review
    /// deadlock warns + lists unresolved critiques but never blocks —
    /// operator sovereignty. Kill-switch for cost-sensitive setups.
    #[serde(default = "default_coding_gate")]
    pub plan_review: bool,
    /// GOLD-FEAT-05 — five-layer fail-closed gate stack for self-source edits.
    /// Default: kill-switch `enabled = false` (all requests refused until the
    /// operator explicitly opts in via `freedom.yaml::coding.self_edit.enabled`).
    #[serde(default)]
    pub self_edit: SelfEditConfig,
}

fn default_test_timeout_secs() -> u64 {
    5 * 60
}

fn default_coding_gate() -> bool {
    true
}

fn default_self_edit_max_lines() -> usize {
    200
}

fn default_self_edit_require_green() -> bool {
    true
}

fn default_self_edit_apply_cooldown() -> u64 {
    300
}

impl Default for CodingConfig {
    fn default() -> Self {
        Self {
            test_cmd: None,
            test_timeout_secs: default_test_timeout_secs(),
            brainstorm_gate: default_coding_gate(),
            plan_review: default_coding_gate(),
            self_edit: SelfEditConfig::default(),
        }
    }
}

/// GOLD-FEAT-05 / GUI-DES-SELFDEV-APPLY-01 — self-source-edit safety config.
///
/// Lives at `freedom.yaml::coding.self_edit`.
///
/// **Default: enabled = true** with minimal module allowlist (src/cli +
/// src/coding). Real gating is the full five-layer stack + Elevated/Full
/// autonomy requirement + explicit `--yes` ack + WAL write.  The kill-switch
/// (`enabled: false`) fully stops all self-edits regardless of other settings.
///
/// Gate stack summary (all five must pass in order):
/// 1. `enabled` kill-switch (Layer 1).
/// 2. `allowed_modules` allowlist + hard-deny paths (Layer 2).
/// 3. Autonomy permission gate — `Action::SelfSourceEdit` (Layer 3).
/// 4. Worktree isolation — apply in a temp `git worktree` (Layer 4).
/// 5. Green-test gate — `cargo check` must pass in the worktree (Layer 5).
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct SelfEditConfig {
    /// Layer-1 kill-switch.  **Default `true`** — real safety comes from the
    /// five-layer gate + autonomy requirement + WAL audit.  Set `false` to
    /// refuse ALL self-edit requests regardless of other settings.
    #[serde(default = "default_self_edit_enabled")]
    pub enabled: bool,
    /// Positive allowlist of path prefixes (relative to source root) that a
    /// diff MAY touch. An empty list means DENY-ALL.
    ///
    /// Default: `["src/cli", "src/coding"]` — the primary self-improvement
    /// surface as ratified by the architecture panel.
    #[serde(default = "default_self_edit_allowed_modules")]
    pub allowed_modules: Vec<String>,
    /// Source-root override. `None` = auto-detect from binary path (walk up to
    /// the workspace `Cargo.toml`).
    #[serde(default)]
    pub source_root: Option<std::path::PathBuf>,
    /// Hard cap on total changed lines (additions `+` + removals `-` in the
    /// diff, excluding header lines). Enforced by Layer 2. Default 200.
    #[serde(default = "default_self_edit_max_lines")]
    pub max_lines_changed: usize,
    /// Require the isolated worktree `cargo check` to pass before applying to
    /// the live tree. Default `true`. Setting `false` skips Layer 5 for dry-run
    /// previews only; every live apply fails closed without a green test.
    #[serde(default = "default_self_edit_require_green")]
    pub require_green_tests: bool,
    /// Minimum seconds between two successive live applies (anti-loop guard).
    /// Enforced inside the central self-source gate for every caller.
    /// Default 300 (5 minutes).
    #[serde(default = "default_self_edit_apply_cooldown")]
    pub apply_cooldown_secs: u64,
}

fn default_self_edit_enabled() -> bool {
    true
}

fn default_self_edit_allowed_modules() -> Vec<String> {
    vec!["src/cli".into(), "src/coding".into()]
}

impl Default for SelfEditConfig {
    fn default() -> Self {
        Self {
            enabled: default_self_edit_enabled(),
            allowed_modules: default_self_edit_allowed_modules(),
            source_root: None,
            max_lines_changed: default_self_edit_max_lines(),
            require_green_tests: default_self_edit_require_green(),
            apply_cooldown_secs: default_self_edit_apply_cooldown(),
        }
    }
}

/// GOLD-TASK-01 — general-task pipeline knobs.
///
/// Controls whether the channel inbound pipeline routes non-coding
/// prompts (reminders, scheduling, research, delegation) into the
/// kanban decomposer instead of falling through to chat completion.
///
/// **Safety default: `decompose_non_coding = false`** — this flag
/// makes REMOTE channel text create executable task sessions. Operators
/// must opt in explicitly. When `false`, the channel pipeline behaves
/// exactly as before (zero behaviour change).
///
/// Gates enforced by the routing branch (all must pass):
/// 1. `task_engine.decompose_non_coding = true` (this field, default OFF).
/// 2. `autonomy >= Standard` (Strict blocks all unattended task creation).
/// 3. High-confidence general-task intent detected AND no coding intent
///    (mutual-exclusion with the coding auto-dispatch path).
/// 4. Tasks land in `Backlog` status — never auto-dispatched from the
///    channel path. Operator drives execution via `neoth code --run-pending`.
///
/// ### WAL audit trail note
///
/// The WAL byte space is exhausted (255/256 slots used; `0x00` is the
/// reserved null sentinel). No new WAL event code is allocated.
/// Audit trail is: the `idx_kanban_session` row itself (`insert_session`),
/// a `tracing::info!` log line, and the kanban SSE `FeedEntry` broadcast
/// that the babel cron emits for every new session event.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TaskEngineConfig {
    /// Master gate: when `false` (default), the channel pipeline does NOT
    /// route non-coding prompts into the kanban decomposer. Set to `true`
    /// to enable GOLD-TASK-01 general-task routing.
    pub decompose_non_coding: bool,
}

impl Default for TaskEngineConfig {
    fn default() -> Self {
        Self {
            decompose_non_coding: false,
        }
    }
}

/// Operator-facing self-update policy.
///
/// Field semantics:
///   - `enabled` — arms recurring self-update checks when the global updater
///     is enabled and the check interval is nonzero. Default `false` creates
///     no self-update lane; manual update commands remain available.
///   - `auto_apply` — additionally permits an Elevated/Full daemon to
///     authenticate and stage a release through the bounded owned helper.
///     Signed recovery admission and acknowledged leaf receipts bind each
///     pass. Staging never swaps the running binary; the operator completes
///     that step with `neoth update --self --apply`.
///   - `channel` — release channel. `stable` selects final releases only;
///     `rc` also accepts release candidates; `nightly` accepts final, RC, and
///     nightly-tagged SemVer releases. Alpha/beta tags belong to no ring.
///     The selected channel is shared by recurring intent and operator-
///     initiated checks/apply.
///   - `check_interval_secs` — how often the background check
///     fires. Defaults to 24h (86400s). `0` disables the
///     periodic task even when `enabled: true` (operator runs
///     `neoth update --self` on demand).
///   - `repo` — validated GitHub owner/repo slug. Default
///     `"The-Geek-Freaks/NEOTH"`. Forks override. The exact source is stored
///     with staged artifacts so a later repo switch cannot reuse old bytes.
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
    pub channel: ReleaseChannel,
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,
    #[serde(
        default = "default_update_repo",
        deserialize_with = "deserialize_update_repo"
    )]
    pub repo: String,
    #[serde(default, deserialize_with = "deserialize_update_target_triple")]
    pub target_triple: Option<String>,
}

/// Ordered self-update release rings. Each wider ring includes the narrower
/// ones so an RC/nightly operator still receives a final release when it wins
/// SemVer precedence.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseChannel {
    #[default]
    Stable,
    Rc,
    Nightly,
}

impl ReleaseChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Rc => "rc",
            Self::Nightly => "nightly",
        }
    }
}

impl std::fmt::Display for ReleaseChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn default_update_channel() -> ReleaseChannel {
    ReleaseChannel::Stable
}

fn deserialize_update_target_triple<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let target = raw.trim();
    if !crate::updater::self_update::release_target_is_supported(target) {
        return Err(D::Error::custom(format!(
            "unsupported auto_update.target_triple {target:?}; expected one of {}",
            crate::updater::self_update::SUPPORTED_RELEASE_TARGETS.join(", ")
        )));
    }
    Ok(Some(target.to_string()))
}

fn default_check_interval_secs() -> u64 {
    24 * 60 * 60
}

fn default_update_repo() -> String {
    "The-Geek-Freaks/NEOTH".to_string()
}

fn deserialize_update_repo<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    let repo = raw.trim();
    if !crate::updater::self_update::owner_repo_is_valid(repo) {
        return Err(D::Error::custom(format!(
            "invalid auto_update.repo {repo:?}; expected a GitHub owner/repo slug"
        )));
    }
    Ok(repo.to_string())
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
const MAX_CONFIGURED_MCP_PATH_READ_SELECTORS: usize = 32;
const MAX_CONFIGURED_MCP_PATH_READ_IDENTIFIER_BYTES: usize = 128;
const MAX_CONFIGURED_MCP_PATH_READ_TOTAL_BYTES: usize = 4_096;

/// The only externally-configured code-map sidecar projection in this slice.
///
/// This is selection data, not authority: `McpServerConfig` preflight,
/// allowlists, request binding, and cancellation remain responsible for whether
/// a call may happen. `path_field` is deliberately fixed to `path`; retaining
/// it in the persisted form makes an attempted future schema projection reject
/// instead of being silently accepted. Unknown selector keys are rejected so a
/// typo cannot silently default to the fixed `path` contract.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredMcpPathRead {
    pub server_id: String,
    pub tool: String,
    #[serde(default)]
    pub kind: ConfiguredMcpPathReadKind,
    #[serde(default = "default_configured_mcp_path_read_path_field")]
    pub path_field: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum ConfiguredMcpPathReadKind {
    #[default]
    #[serde(rename = "ReadPath", alias = "read_path")]
    ReadPath,
}

fn default_configured_mcp_path_read_path_field() -> String {
    "path".to_owned()
}

impl ConfiguredMcpPathRead {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.server_id.is_empty()
                && self.server_id.len() <= MAX_CONFIGURED_MCP_PATH_READ_IDENTIFIER_BYTES,
            "code_map.enrichment_selectors server_id must contain 1..={} UTF-8 bytes",
            MAX_CONFIGURED_MCP_PATH_READ_IDENTIFIER_BYTES,
        );
        anyhow::ensure!(
            !self.tool.is_empty()
                && self.tool.len() <= MAX_CONFIGURED_MCP_PATH_READ_IDENTIFIER_BYTES,
            "code_map.enrichment_selectors tool must contain 1..={} UTF-8 bytes",
            MAX_CONFIGURED_MCP_PATH_READ_IDENTIFIER_BYTES,
        );
        anyhow::ensure!(
            matches!(self.kind, ConfiguredMcpPathReadKind::ReadPath),
            "code_map.enrichment_selectors kind must be ReadPath",
        );
        anyhow::ensure!(
            self.path_field == "path",
            "code_map.enrichment_selectors path_field must be exactly `path`",
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CodeMapConfig {
    /// Opt-in bounded sidecar for the exact generated `codegraph_outline`
    /// route and operator-selected configured providers. It never enables a
    /// server, tool, or generic filesystem capability.
    #[serde(default)]
    pub outline_enrichment: bool,
    /// Exact configured-provider local-path projections eligible for the
    /// opt-in sidecar. The empty default selects no configured-provider call,
    /// even while `outline_enrichment` is true; it does not disable W53's
    /// existing generated built-in outline route.
    #[serde(default)]
    pub enrichment_selectors: Vec<ConfiguredMcpPathRead>,
    #[serde(default)]
    pub impact_policy: CodeMapImpactPolicy,
    /// Max files to surface in the auto-injected `<repo-context>`
    /// block. `0` (default) disables auto-injection. Recommended
    /// production value: 3-5 — large enough to surface the obvious
    /// hits, small enough to keep the system prompt tight.
    #[serde(
        default = "default_auto_context_max_files",
        deserialize_with = "deserialize_auto_context_max_files"
    )]
    pub auto_context_max_files: u32,
    /// Maximum code-map files recalled for one `neoth code` invocation.
    /// This is independent from `auto_context_max_files`: the latter controls
    /// continuous chat/channel injection and remains disabled at zero.
    #[serde(
        default = "default_coding_recall_max_files",
        deserialize_with = "deserialize_coding_recall_max_files"
    )]
    pub coding_recall_max_files: u32,
    /// Maximum depth-one caller entries included for each recalled symbol during
    /// a one-shot coding invocation. `0` disables this enrichment only.
    #[serde(
        default = "default_coding_callers_per_symbol",
        deserialize_with = "deserialize_coding_callers_per_symbol"
    )]
    pub coding_callers_per_symbol: u32,
    /// Heuristic budget for a generic repo-map summary in a one-shot coding
    /// invocation. It is not a provider billing limit or the full combined
    /// coding-context cap.
    #[serde(
        default = "default_coding_summary_token_budget",
        deserialize_with = "deserialize_coding_summary_token_budget"
    )]
    pub coding_summary_token_budget: u32,
    /// Traversal ceiling for explicit codegraph callers/callees requests.
    /// It is distinct from `coding_callers_per_symbol`, which counts direct
    /// caller rows in `neoth code` and is never a BFS depth.
    #[serde(
        default = "default_requested_context_max_bfs_depth",
        deserialize_with = "deserialize_requested_context_max_bfs_depth"
    )]
    pub requested_context_max_bfs_depth: u8,
    /// Default-off daemon ownership for explicitly selected repository roots.
    /// It is separate from both automatic chat context and one-shot coding
    /// recall limits.
    #[serde(default)]
    pub lifecycle: CodeMapLifecycleConfig,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CodeMapImpactPolicy {
    #[serde(
        default = "default_impact_policy_max_depth",
        deserialize_with = "deserialize_impact_policy_max_depth"
    )]
    pub max_depth: u32,
    #[serde(
        default = "default_impact_policy_max_nodes",
        deserialize_with = "deserialize_impact_policy_max_nodes"
    )]
    pub max_nodes: u32,
    #[serde(default, deserialize_with = "deserialize_impact_policy_allow_stale")]
    pub allow_stale: bool,
}

/// Immutable, data-only limits for an explicit code-map request.  This is
/// deliberately derived from the existing validated coding settings: automatic
/// Chat/Channel context remains governed by `auto_context_max_files` and is
/// never enabled by this view.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct RequestedContextPolicy {
    pub recall_max_files: u32,
    /// A count of direct caller rows per matched symbol, never traversal depth.
    pub callers_per_symbol: u32,
    pub summary_token_budget: u32,
    pub max_bfs_depth: u8,
}

impl RequestedContextPolicy {
    pub const MAX_RENDERED_BYTES: usize = 64 * 1024;

    pub fn max_rendered_bytes(self) -> usize {
        (self.summary_token_budget as usize)
            .saturating_mul(4)
            .min(Self::MAX_RENDERED_BYTES)
    }
}

impl Default for CodeMapImpactPolicy {
    fn default() -> Self {
        Self {
            max_depth: default_impact_policy_max_depth(),
            max_nodes: default_impact_policy_max_nodes(),
            allow_stale: false,
        }
    }
}

impl CodeMapImpactPolicy {
    /// Convert the already validated operator policy into the bounded impact
    /// request options consumed by production code-map clients.
    pub fn impact_options(&self) -> crate::code_map::ImpactOptions {
        crate::code_map::ImpactOptions {
            max_depth: self.max_depth as usize,
            max_nodes: self.max_nodes as usize,
            allow_stale: self.allow_stale,
            ..Default::default()
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=crate::code_map::impact::MAX_IMPACT_DEPTH as u32).contains(&self.max_depth),
            "code_map.impact_policy.max_depth must be between 1 and {}",
            crate::code_map::impact::MAX_IMPACT_DEPTH
        );
        anyhow::ensure!(
            (1..=crate::code_map::impact::MAX_IMPACT_NODES as u32).contains(&self.max_nodes),
            "code_map.impact_policy.max_nodes must be between 1 and {}",
            crate::code_map::impact::MAX_IMPACT_NODES
        );
        anyhow::ensure!(
            !self.allow_stale,
            "code_map.impact_policy.allow_stale must remain false"
        );
        Ok(())
    }
}

/// Bounded daemon lifecycle controls for native code-map refreshes.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CodeMapLifecycleConfig {
    /// The daemon never infers a managed repository from its service CWD.
    #[serde(default)]
    pub enabled: bool,
    /// Operator-selected absolute repository roots. Canonical physical identity
    /// is verified during config validation before any watcher is started.
    #[serde(default, deserialize_with = "deserialize_code_map_managed_roots")]
    pub managed_roots: Vec<PathBuf>,
    /// Coalesce filesystem invalidations for this bounded interval before a
    /// lifecycle refresh. Watcher events are dirty signals, never freshness
    /// proof.
    #[serde(
        default = "default_code_map_debounce_millis",
        deserialize_with = "deserialize_code_map_debounce_millis"
    )]
    pub debounce_millis: u64,
    /// Strong freshness reconciliation cadence, used to discover missed watcher
    /// events. It does not derive a freshness claim from watcher quietness.
    #[serde(
        default = "default_code_map_reconciliation_interval_secs",
        deserialize_with = "deserialize_code_map_reconciliation_interval_secs"
    )]
    pub reconciliation_interval_secs: u64,
}

impl CodeMapLifecycleConfig {
    pub const MAX_MANAGED_ROOTS: usize = 8;
    pub const MIN_DEBOUNCE_MILLIS: u64 = 50;
    pub const MAX_DEBOUNCE_MILLIS: u64 = 60_000;
    pub const MIN_RECONCILIATION_INTERVAL_SECS: u64 = 30;
    pub const MAX_RECONCILIATION_INTERVAL_SECS: u64 = 3_600;

    /// Resolve the configured roots to canonical physical identities. A
    /// managed root cannot alias, duplicate, contain, or be contained by a
    /// second managed root, because that would produce overlapping recursive
    /// watchers and ambiguous refresh authority.
    pub fn canonical_managed_roots(
        &self,
    ) -> anyhow::Result<Vec<crate::code_map::CanonicalRepoRoot>> {
        self.validate_shape()?;
        let roots: Vec<_> = self
            .managed_roots
            .iter()
            .map(|root| crate::code_map::CanonicalRepoRoot::discover(root))
            .collect::<anyhow::Result<_>>()?;
        Self::validate_root_conflicts(&roots)?;
        Ok(roots)
    }

    fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.managed_roots.len() <= Self::MAX_MANAGED_ROOTS,
            "code_map.lifecycle.managed_roots supports at most {} roots",
            Self::MAX_MANAGED_ROOTS
        );
        anyhow::ensure!(
            !self.enabled || !self.managed_roots.is_empty(),
            "code_map.lifecycle.managed_roots must contain at least one root when enabled"
        );
        anyhow::ensure!(
            self.managed_roots.iter().all(|root| root.is_absolute()),
            "code_map.lifecycle.managed_roots entries must be absolute paths"
        );
        anyhow::ensure!(
            (Self::MIN_DEBOUNCE_MILLIS..=Self::MAX_DEBOUNCE_MILLIS).contains(&self.debounce_millis),
            "code_map.lifecycle.debounce_millis must be between {} and {}",
            Self::MIN_DEBOUNCE_MILLIS,
            Self::MAX_DEBOUNCE_MILLIS
        );
        anyhow::ensure!(
            (Self::MIN_RECONCILIATION_INTERVAL_SECS..=Self::MAX_RECONCILIATION_INTERVAL_SECS)
                .contains(&self.reconciliation_interval_secs),
            "code_map.lifecycle.reconciliation_interval_secs must be between {} and {}",
            Self::MIN_RECONCILIATION_INTERVAL_SECS,
            Self::MAX_RECONCILIATION_INTERVAL_SECS
        );
        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_shape()?;
        // Exact duplicate spellings are always structurally invalid, even if
        // the directory was moved or deleted while the daemon was stopped.
        for (index, root) in self.managed_roots.iter().enumerate() {
            anyhow::ensure!(
                !self
                    .managed_roots
                    .iter()
                    .skip(index + 1)
                    .any(|other| other == root),
                "code_map.lifecycle.managed_roots contains the same root twice: {}",
                root.display()
            );
        }
        // Config loading must preserve a formerly valid root that is currently
        // absent, so Doctor/GUI can expose and remove it. Physical aliases and
        // overlap remain rejected for every root that is available now; the
        // strict `canonical_managed_roots` path remains the runtime gate.
        let available = self
            .managed_roots
            .iter()
            .filter_map(|root| crate::code_map::CanonicalRepoRoot::discover(root).ok())
            .collect::<Vec<_>>();
        Self::validate_root_conflicts(&available)
    }

    fn validate_root_conflicts(roots: &[crate::code_map::CanonicalRepoRoot]) -> anyhow::Result<()> {
        for (index, root) in roots.iter().enumerate() {
            for other in roots.iter().skip(index + 1) {
                anyhow::ensure!(
                    root != other,
                    "code_map.lifecycle.managed_roots contains the same physical root twice: {}",
                    root.display()
                );
                anyhow::ensure!(
                    !root.path().starts_with(other.path())
                        && !other.path().starts_with(root.path()),
                    "code_map.lifecycle.managed_roots must not overlap: {} and {}",
                    root.display(),
                    other.display()
                );
            }
        }
        Ok(())
    }
}

impl Default for CodeMapLifecycleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            managed_roots: Vec::new(),
            debounce_millis: default_code_map_debounce_millis(),
            reconciliation_interval_secs: default_code_map_reconciliation_interval_secs(),
        }
    }
}

fn default_auto_context_max_files() -> u32 {
    0
}

fn default_impact_policy_max_depth() -> u32 {
    crate::code_map::impact::DEFAULT_MAX_DEPTH as u32
}
fn default_impact_policy_max_nodes() -> u32 {
    crate::code_map::impact::DEFAULT_MAX_NODES as u32
}
fn deserialize_impact_policy_max_depth<'de, D>(d: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_code_map_u32_in_range(
        d,
        "code_map.impact_policy.max_depth",
        1,
        crate::code_map::impact::MAX_IMPACT_DEPTH as u32,
    )
}
fn deserialize_impact_policy_max_nodes<'de, D>(d: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_code_map_u32_in_range(
        d,
        "code_map.impact_policy.max_nodes",
        1,
        crate::code_map::impact::MAX_IMPACT_NODES as u32,
    )
}
fn deserialize_impact_policy_allow_stale<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    if bool::deserialize(d)? {
        Err(D::Error::custom(
            "code_map.impact_policy.allow_stale must remain false",
        ))
    } else {
        Ok(false)
    }
}

fn default_coding_recall_max_files() -> u32 {
    8
}

fn default_coding_callers_per_symbol() -> u32 {
    3
}

fn default_coding_summary_token_budget() -> u32 {
    2_048
}

fn default_requested_context_max_bfs_depth() -> u8 {
    20
}

fn default_code_map_debounce_millis() -> u64 {
    500
}

fn default_code_map_reconciliation_interval_secs() -> u64 {
    300
}

fn deserialize_code_map_u32_in_range<'de, D>(
    deserializer: D,
    field: &str,
    minimum: u32,
    maximum: u32,
) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u32::deserialize(deserializer)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(D::Error::custom(format!(
            "{field} must be between {minimum} and {maximum}"
        )));
    }
    Ok(value)
}

fn deserialize_code_map_u64_in_range<'de, D>(
    deserializer: D,
    field: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(D::Error::custom(format!(
            "{field} must be between {minimum} and {maximum}"
        )));
    }
    Ok(value)
}

fn deserialize_auto_context_max_files<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_code_map_u32_in_range(deserializer, "auto_context_max_files", 0, 200)
}

fn deserialize_coding_recall_max_files<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_code_map_u32_in_range(deserializer, "coding_recall_max_files", 1, 50)
}

fn deserialize_coding_callers_per_symbol<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_code_map_u32_in_range(deserializer, "coding_callers_per_symbol", 0, 20)
}

fn deserialize_coding_summary_token_budget<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_code_map_u32_in_range(deserializer, "coding_summary_token_budget", 128, 12_000)
}

fn deserialize_requested_context_max_bfs_depth<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u8::deserialize(deserializer)?;
    if !(1..=20).contains(&value) {
        return Err(D::Error::custom(
            "requested_context_max_bfs_depth must be between 1 and 20",
        ));
    }
    Ok(value)
}

fn deserialize_code_map_managed_roots<'de, D>(deserializer: D) -> Result<Vec<PathBuf>, D::Error>
where
    D: Deserializer<'de>,
{
    let roots = Vec::<PathBuf>::deserialize(deserializer)?;
    if roots.len() > CodeMapLifecycleConfig::MAX_MANAGED_ROOTS {
        return Err(D::Error::custom(format!(
            "code_map.lifecycle.managed_roots supports at most {} roots",
            CodeMapLifecycleConfig::MAX_MANAGED_ROOTS
        )));
    }
    if roots.iter().any(|root| !root.is_absolute()) {
        return Err(D::Error::custom(
            "code_map.lifecycle.managed_roots entries must be absolute paths",
        ));
    }
    Ok(roots)
}

fn deserialize_code_map_debounce_millis<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_code_map_u64_in_range(
        deserializer,
        "code_map.lifecycle.debounce_millis",
        CodeMapLifecycleConfig::MIN_DEBOUNCE_MILLIS,
        CodeMapLifecycleConfig::MAX_DEBOUNCE_MILLIS,
    )
}

fn deserialize_code_map_reconciliation_interval_secs<'de, D>(
    deserializer: D,
) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_code_map_u64_in_range(
        deserializer,
        "code_map.lifecycle.reconciliation_interval_secs",
        CodeMapLifecycleConfig::MIN_RECONCILIATION_INTERVAL_SECS,
        CodeMapLifecycleConfig::MAX_RECONCILIATION_INTERVAL_SECS,
    )
}

impl Default for CodeMapConfig {
    fn default() -> Self {
        Self {
            outline_enrichment: false,
            enrichment_selectors: Vec::new(),
            impact_policy: CodeMapImpactPolicy::default(),
            auto_context_max_files: default_auto_context_max_files(),
            coding_recall_max_files: default_coding_recall_max_files(),
            coding_callers_per_symbol: default_coding_callers_per_symbol(),
            coding_summary_token_budget: default_coding_summary_token_budget(),
            requested_context_max_bfs_depth: default_requested_context_max_bfs_depth(),
            lifecycle: CodeMapLifecycleConfig::default(),
        }
    }
}

impl CodeMapConfig {
    pub fn requested_context_policy(&self) -> anyhow::Result<RequestedContextPolicy> {
        self.validate()?;
        Ok(RequestedContextPolicy {
            recall_max_files: self.coding_recall_max_files,
            callers_per_symbol: self.coding_callers_per_symbol,
            summary_token_budget: self.coding_summary_token_budget,
            max_bfs_depth: self.requested_context_max_bfs_depth,
        })
    }

    /// Reject invalid programmatically-built values that bypassed the
    /// YAML field deserializers. Call this before a caller performs IO.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.enrichment_selectors.len() <= MAX_CONFIGURED_MCP_PATH_READ_SELECTORS,
            "code_map.enrichment_selectors supports at most {} entries",
            MAX_CONFIGURED_MCP_PATH_READ_SELECTORS,
        );
        let mut selector_bytes = 0usize;
        for (index, selector) in self.enrichment_selectors.iter().enumerate() {
            selector.validate()?;
            selector_bytes = selector_bytes
                .saturating_add(selector.server_id.len())
                .saturating_add(selector.tool.len())
                .saturating_add(selector.path_field.len());
            anyhow::ensure!(
                self.enrichment_selectors[..index]
                    .iter()
                    .all(|previous| previous.server_id != selector.server_id
                        || previous.tool != selector.tool),
                "code_map.enrichment_selectors contains duplicate ({}, {})",
                selector.server_id,
                selector.tool,
            );
        }
        anyhow::ensure!(
            selector_bytes <= MAX_CONFIGURED_MCP_PATH_READ_TOTAL_BYTES,
            "code_map.enrichment_selectors exceeds {} total UTF-8 bytes",
            MAX_CONFIGURED_MCP_PATH_READ_TOTAL_BYTES,
        );
        if self.auto_context_max_files > 200 {
            anyhow::bail!("auto_context_max_files must be between 0 and 200");
        }
        if !(1..=50).contains(&self.coding_recall_max_files) {
            anyhow::bail!("coding_recall_max_files must be between 1 and 50");
        }
        if self.coding_callers_per_symbol > 20 {
            anyhow::bail!("coding_callers_per_symbol must be between 0 and 20");
        }
        if !(128..=12_000).contains(&self.coding_summary_token_budget) {
            anyhow::bail!("coding_summary_token_budget must be between 128 and 12000");
        }
        if !(1..=20).contains(&self.requested_context_max_bfs_depth) {
            anyhow::bail!("requested_context_max_bfs_depth must be between 1 and 20");
        }
        self.impact_policy.validate()?;
        self.lifecycle.validate()?;
        Ok(())
    }
}

/// R-04 2026-05-17: refusal-recovery policy. Operators can disable
/// NEOTH's one truthful `operator_authority` context retry. The retry
/// never invents ownership, professional credentials, or authorization
/// that was not established by the authenticated request context.
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
    /// operator must opt out explicitly. Disabling `operator_authority`
    /// disables the truthful same-leaf context retry; NEOTH does not
    /// substitute a fictional academic, historical, or narrower purpose.
    #[serde(default)]
    pub disabled_reframings: Vec<String>,
    /// Maximum truthful context retries per refusal. The catalogue
    /// currently exposes one context-preserving retry, so values above
    /// one do not create synthetic alternate purposes. After the effective
    /// budget is exhausted the orchestrator emits
    /// `0x1A REFUSAL_PERSISTENT` and surfaces the last failure.
    #[serde(default = "default_refusal_recovery_max_attempts")]
    pub max_attempts: u32,
    /// GOLD-FEAT-08 Tier-3 — enable the local-abliterated fallback. Default
    /// `false` (opt-in). When `true`, a `SafetyPolicy` or `Privacy` over-refusal that
    /// survives the LOWKEY reframing pipeline is re-attempted via the
    /// operator's OWN local model (`abliterated_model`) — not by deceiving the
    /// cloud, but by routing to operator-owned hardware. WAL records
    /// `0x26 REFUSAL_ABLITERATED_USED` / `0x27 REFUSAL_ABLITERATED_FAILED`.
    #[serde(default = "default_abliterated_fallback_enabled")]
    pub abliterated_fallback_enabled: bool,
    /// GOLD-FEAT-08 — HF repo id of the operator's local abliterated model used
    /// for the Tier-3 fallback. `None` disables the fallback even when
    /// `abliterated_fallback_enabled` is `true` (no model = nothing to route to).
    #[serde(default)]
    pub abliterated_model: Option<String>,
    /// Legacy compatibility flag. Cloud jailbreak harnesses are no longer
    /// dispatched: provider-native refusal signals receive at most one truthful
    /// context retry, followed only by separately authorized provider/local
    /// fallbacks. `true` is accepted but ignored with a visible warning.
    #[serde(default = "default_jailbreak_retry_enabled")]
    pub jailbreak_retry_enabled: bool,
    /// Legacy compatibility value for old configs; ignored by production
    /// dispatch together with `jailbreak_retry_enabled`.
    #[serde(default = "default_jailbreak_max_retries")]
    pub jailbreak_max_retries: usize,
    /// GOLD-ADAPT-ODY-08 — enable SOTA teacher escalation when the local model
    /// fails or produces a low-confidence reply. Default `false` (opt-in, cloud
    /// egress). When `true`, the local response is typed as `ModelOutput`
    /// (ODY-18 anti-injection) and sent to `inference.teacher_provider` (default:
    /// flagship cloud) for correction. Only fires when the ORIGINAL provider was a
    /// local model (`is_local_provider` check). WAL records
    /// `0x85 TEACHER_ESCALATION_ATTEMPTED` / `0x86 TEACHER_ESCALATION_COMPLETE`.
    /// The permanent hard-block floor (`hard_blocked`) still suppresses this tier.
    #[serde(default = "default_teacher_escalation_enabled")]
    pub teacher_escalation_enabled: bool,
    /// GOLD-ADAPT-ODY-08 — optional explicit teacher model override string passed
    /// to the teacher provider (e.g. `claude-opus-4-5`). `None` = use the
    /// provider's default flagship. Only consulted when `teacher_escalation_enabled`
    /// is `true`. Stored separately from `inference.teacher_provider` so an operator
    /// can pick e.g. `claude_cli` as the teacher channel but override the exact
    /// model for that call.
    #[serde(default)]
    pub teacher_model_override: Option<String>,
}

impl Default for RefusalRecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: default_refusal_recovery_enabled(),
            disabled_reframings: Vec::new(),
            max_attempts: default_refusal_recovery_max_attempts(),
            abliterated_fallback_enabled: default_abliterated_fallback_enabled(),
            abliterated_model: None,
            jailbreak_retry_enabled: default_jailbreak_retry_enabled(),
            jailbreak_max_retries: default_jailbreak_max_retries(),
            teacher_escalation_enabled: default_teacher_escalation_enabled(),
            teacher_model_override: None,
        }
    }
}

fn default_refusal_recovery_enabled() -> bool {
    true
}

fn default_abliterated_fallback_enabled() -> bool {
    false
}

fn default_jailbreak_retry_enabled() -> bool {
    false
}

fn default_teacher_escalation_enabled() -> bool {
    false
}

fn default_jailbreak_max_retries() -> usize {
    crate::security::jailbreak_retry::DEFAULT_MAX_RETRIES
}

fn default_refusal_recovery_max_attempts() -> u32 {
    1
}

/// 2026-05-17 Session 2: profile-learning policy. Defaults to off so
/// operators using paid cloud providers don't get a surprise 2× token
/// bill from the post-reply extract LLM call. Flip `learn_enabled:
/// true` in freedom.yaml (or override per-call via env var
/// `NEOTH_PROFILE_LEARN_DISABLE=0`) to opt in.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProfileConfig {
    /// Default-on, deterministic, local communication adaptation. This is
    /// deliberately separate from `learn_enabled`: it never invokes an LLM,
    /// never stores raw chat text, and never infers medical diagnoses.
    #[serde(default)]
    pub communication: CommunicationProfileConfig,
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
    /// PROFILE-LOCAL-EXTRACT-01: character budget for the segment-content
    /// portion of the extractor LLM prompt. Segments are trimmed to the
    /// most-recent N chars so local models with small context windows
    /// (e.g. Qwen3-4B-INT4 ≈ 4 K tokens after system-prompt overhead)
    /// don't OOM or silently truncate. 32 000 chars ≈ 8 K tokens at
    /// 4 chars/token — fits every supported local backend; operators on
    /// 4 K-context builds should lower this to ~12 000.
    ///
    /// Serde default = 32 000. Existing freedom.yaml files without this
    /// field inherit the default, which is large enough that typical
    /// 2-turn windows (≤ 5 K chars) see no behavioral change.
    #[serde(default = "default_profile_extract_window_chars")]
    pub extract_window_chars: usize,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            communication: CommunicationProfileConfig::default(),
            learn_enabled: default_profile_learn_enabled(),
            timeout_secs: default_profile_timeout_secs(),
            learn_provider: default_profile_learn_provider(),
            allow_cloud_fallback: default_profile_allow_cloud_fallback(),
            require_approval: default_profile_require_approval(),
            pii_categories_disabled: Vec::new(),
            extract_window_chars: default_profile_extract_window_chars(),
        }
    }
}

/// Controls what the communication-profile compiler may disclose to the
/// provider. The safe default exports only concrete presentation
/// accommodations; it never exports a health or neurodivergence label.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommunicationPromptExport {
    /// Do not inject the communication profile into provider prompts.
    None,
    /// Export only locally compiled presentation instructions.
    #[default]
    AccommodationsOnly,
    /// Export an explicitly operator-declared label plus accommodations.
    /// Passive estimators can never create such a declaration.
    LabelAndAccommodations,
}

/// Deterministic local communication-profile policy.
///
/// This engine is default-on because it is bounded local computation, not the
/// paid Stage-3 fact extractor controlled by [`ProfileConfig::learn_enabled`].
/// It learns presentation and clarification preferences only. Authentication,
/// cost, tool permission and safety decisions are outside its authority.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CommunicationProfileConfig {
    /// Master switch. Disabled and incognito turns perform zero reads/writes.
    pub enabled: bool,
    /// Automatically apply estimates that pass the evidence thresholds.
    pub auto_apply_low_risk: bool,
    /// Minimum retained observations before a passive estimate is effective.
    pub min_observations: u32,
    /// Minimum distinct authenticated sessions before passive application.
    pub min_distinct_sessions: u32,
    /// Minimum winning-weight share for passive application.
    pub min_confidence: f32,
    /// Half-life for low-weight passive observations.
    pub passive_half_life_days: u32,
    /// Half-life for explicit response-feedback controls.
    pub feedback_half_life_days: u32,
    /// Half-life for explicit corrections in natural language.
    pub correction_half_life_days: u32,
    /// Full/Sovereign can promote a stable low-risk accommodation only after
    /// this many observations. The communication core additionally enforces a
    /// fixed presentation-only allowlist; no config threshold can make pace,
    /// clarification, correction style, autonomy or task/channel evidence
    /// durable without an explicit operator pin.
    pub full_auto_min_observations: u32,
    /// Distinct-session floor for durable Full/Sovereign promotion.
    pub full_auto_min_distinct_sessions: u32,
    /// Confidence floor for durable Full/Sovereign promotion.
    pub full_auto_min_confidence: f32,
    /// Bounded evidence retained per subject and dimension.
    pub max_evidence_per_dimension: usize,
    /// Provider disclosure policy.
    pub prompt_export: CommunicationPromptExport,
    /// Profile synchronization is private/local unless explicitly enabled by
    /// a future signed, subject-bound cluster contract.
    pub cluster_sync: bool,
}

impl Default for CommunicationProfileConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_apply_low_risk: true,
            min_observations: 5,
            min_distinct_sessions: 3,
            min_confidence: 0.75,
            passive_half_life_days: 30,
            feedback_half_life_days: 90,
            correction_half_life_days: 180,
            full_auto_min_observations: 10,
            full_auto_min_distinct_sessions: 5,
            full_auto_min_confidence: 0.85,
            max_evidence_per_dimension: 32,
            prompt_export: CommunicationPromptExport::AccommodationsOnly,
            cluster_sync: false,
        }
    }
}

impl CommunicationProfileConfig {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.min_observations == 0 {
            return Err("min_observations must be greater than zero".to_string());
        }
        if self.min_distinct_sessions == 0 {
            return Err("min_distinct_sessions must be greater than zero".to_string());
        }
        if self.min_distinct_sessions > self.min_observations {
            return Err("min_distinct_sessions must be <= min_observations".to_string());
        }
        if !self.min_confidence.is_finite() || !(0.5..=1.0).contains(&self.min_confidence) {
            return Err("min_confidence must be within 0.5..=1.0".to_string());
        }
        if self.passive_half_life_days == 0
            || self.feedback_half_life_days == 0
            || self.correction_half_life_days == 0
        {
            return Err("communication half-life values must be greater than zero".to_string());
        }
        if self.full_auto_min_observations < self.min_observations {
            return Err("full_auto_min_observations must be >= min_observations".to_string());
        }
        if self.full_auto_min_distinct_sessions < self.min_distinct_sessions {
            return Err(
                "full_auto_min_distinct_sessions must be >= min_distinct_sessions".to_string(),
            );
        }
        if self.full_auto_min_distinct_sessions > self.full_auto_min_observations {
            return Err(
                "full_auto_min_distinct_sessions must be <= full_auto_min_observations".to_string(),
            );
        }
        if !self.full_auto_min_confidence.is_finite()
            || self.full_auto_min_confidence < self.min_confidence
            || self.full_auto_min_confidence > 1.0
        {
            return Err("full_auto_min_confidence must be within min_confidence..=1.0".to_string());
        }
        if !(8..=256).contains(&self.max_evidence_per_dimension) {
            return Err("max_evidence_per_dimension must be within 8..=256".to_string());
        }
        if u64::try_from(self.max_evidence_per_dimension).unwrap_or(u64::MAX)
            < u64::from(self.full_auto_min_observations)
        {
            return Err(
                "max_evidence_per_dimension must be >= full_auto_min_observations".to_string(),
            );
        }
        if self.cluster_sync {
            return Err(
                "cluster_sync is not available until the signed subject-bound sync contract is enabled; leave it false"
                    .to_string(),
            );
        }
        Ok(())
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

/// PROFILE-LOCAL-EXTRACT-01: 32 000 chars ≈ 8 K tokens at 4 chars/token.
/// Large enough that typical 2-turn windows (≤ 5 K chars) are never
/// trimmed with the default config; small enough that quantized local
/// models with 8 K context (Qwen3-8B-INT4, Mistral-7B-INT4, etc.) fit
/// without OOM. Operators on 4 K-context builds should set
/// `profile.extract_window_chars: 12000` in freedom.yaml.
fn default_profile_extract_window_chars() -> usize {
    32_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impact_policy_converts_validated_bounds_without_widening() {
        let default_policy = CodeMapImpactPolicy::default();
        let default_options = default_policy.impact_options();
        assert_eq!(default_options.max_depth, default_policy.max_depth as usize);
        assert_eq!(default_options.max_nodes, default_policy.max_nodes as usize);
        assert!(!default_options.allow_stale);

        let maximum_policy = CodeMapImpactPolicy {
            max_depth: crate::code_map::impact::MAX_IMPACT_DEPTH as u32,
            max_nodes: crate::code_map::impact::MAX_IMPACT_NODES as u32,
            allow_stale: false,
        };
        maximum_policy.validate().unwrap();
        let maximum_options = maximum_policy.impact_options();
        assert_eq!(
            maximum_options.max_depth,
            crate::code_map::impact::MAX_IMPACT_DEPTH
        );
        assert_eq!(
            maximum_options.max_nodes,
            crate::code_map::impact::MAX_IMPACT_NODES
        );
        assert!(!maximum_options.allow_stale);
    }

    #[test]
    fn impact_policy_invalid_values_reject_before_dispatch_conversion() {
        for policy in [
            CodeMapImpactPolicy {
                max_depth: 0,
                ..CodeMapImpactPolicy::default()
            },
            CodeMapImpactPolicy {
                max_nodes: 0,
                ..CodeMapImpactPolicy::default()
            },
            CodeMapImpactPolicy {
                allow_stale: true,
                ..CodeMapImpactPolicy::default()
            },
        ] {
            assert!(policy.validate().is_err());
        }
    }
}
