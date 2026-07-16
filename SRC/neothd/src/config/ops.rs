//! Operational, plugin, updater, supervisor, and profile configuration.

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

/// U-04 follow-up (Session 26): operator-tunable updater cron knobs.
/// Mirrors the daemon-side `UpdaterCronConfig` shape; same circular-
/// dep reason for living in the config crate.
///
/// Default mirrors `daemon::updater_cron::DEFAULT_UPDATER_INTERVAL_SECS`
/// (6h tick). `enabled` is the global background-probe switch. CLI and skill
/// probes use `interval_secs`; the neoth-self probe uses the more specific
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
///   - `enabled` — master switch. Default `false` so a stock
///     contributor build (or a daemon running behind a
///     restricted-egress firewall) never reaches out to GitHub
///     for releases. Operators flip to `true` during onboarding.
///   - `auto_apply` — `true` allows an Elevated/Full daemon to download,
///     authenticate, and stage a release. The daemon never swaps the running
///     binary; the operator completes that step with
///     `neoth update --self --apply`. `false` (default) is check-only.
///   - `channel` — release channel. `stable` selects final releases only;
///     `rc` also accepts release candidates; `nightly` accepts final, RC, and
///     nightly-tagged SemVer releases. Alpha/beta tags belong to no ring.
///     The selected channel is shared by checks, unattended staging, and
///     operator-initiated apply.
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
    /// GOLD-FEAT-08 Tier-3 — enable the local-abliterated fallback. Default
    /// `false` (opt-in). When `true`, a `SafetyPolicy` over-refusal that
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
    /// GOLD-FEAT-08b — enable the jailbreak-harness retry layer that runs BEFORE
    /// the local-abliterated fallback. Default `false` (opt-in). When `true`, a
    /// `SafetyPolicy` over-refusal that survives the LOWKEY reframing pipeline is
    /// retried against the SAME cloud provider up to `jailbreak_max_retries`
    /// times, each wrapping the request in a distinct seed harness
    /// (`security::jailbreak_retry`). First non-refusal wins; all-refused falls
    /// through to FEAT-08. The CSAM/bioweapon hard-block floor still applies
    /// first. WAL records `0x25 PROVIDER_FALLBACK_ATTEMPTED` (kind=jailbreak).
    #[serde(default = "default_jailbreak_retry_enabled")]
    pub jailbreak_retry_enabled: bool,
    /// GOLD-FEAT-08b — number of jailbreak harnesses to try before falling
    /// through to FEAT-08. Default 4; capped at the seed-catalog length.
    #[serde(default = "default_jailbreak_max_retries")]
    pub jailbreak_max_retries: usize,
    /// GOLD-ADAPT-ODY-08 — enable SOTA teacher escalation when the local model
    /// fails or produces a low-confidence reply. Default `false` (opt-in, cloud
    /// egress). When `true`, the local response is fenced via `wrap_untrusted`
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
    2
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
    /// this many observations.
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
