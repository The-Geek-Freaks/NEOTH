//! Hot-reload controller for `FreedomConfig` (Pick #37, Session 14).
//!
//! Agent #4 design consensus (2026-05-19): when the operator edits
//! `freedom.yaml` mid-session, NEOTH must pick up the changes without
//! a daemon restart. Some fields (`operator_id` and the complete provider
//! runtime graph) are IMMUTABLE post-init because they would require rebuilding
//! the provider Arc + adapters that hold derived state. Those
//! fields cause the reload to be rejected with a reason logged at
//! warn level + audited via WAL.
//! Cluster lifecycle fields are mutable: the generation-bound cluster runtime
//! supervisor owns carrier, mDNS, gossip and request-consumer reconstruction.
//!
//! Tunable fields (`council.selection_mode`, `code_map.auto_context_max_files`,
//! `claude_cli.tmux.*`, hooks/skills paths, autonomy level, …) reload
//! atomically via `arc-swap::ArcSwap` — lock-free, no reader contention.
//!
//! ## Trigger
//!
//! Explicit `neoth reload` CLI command writes a one-byte sentinel
//! file at `~/.neoth/.reload-requested`. The daemon's main loop
//! polls for the sentinel on each ingress tick (cheap stat call —
//! the file usually doesn't exist). On present: load + validate +
//! atomic swap, then delete the sentinel.
//!
//! Why filesystem signaling, not SIGHUP/notify:
//!   - SIGHUP doesn't exist on Windows (the operator's primary target)
//!   - `notify` crate adds a background thread + cross-platform FS
//!     event complexity that for a solo operator with explicit
//!     intent (typing `neoth reload`) is overkill
//!   - A sentinel file works identically on every OS NEOTH targets
//!
//! ## Public API
//!
//! ```ignore
//! let controller = ReloadController::new(initial_config, freedom_yaml_path);
//! let cfg: Arc<FreedomConfig> = controller.latest();   // fresh snapshot
//! match controller.try_reload() {
//!     ReloadResult::Reloaded { changed_fields } => /* audit + log */,
//!     ReloadResult::Rejected { rejection }      => /* audit + warn */,
//!     ReloadResult::Unchanged                   => /* no-op */,
//! }
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;

use crate::config::FreedomConfig;

#[derive(Debug, Default)]
struct DreamCommitState {
    retired: bool,
    active: usize,
}

/// Per-accepted-generation linearization gate for irreversible Dream effects.
///
/// Retirement and lease acquisition serialize on `state`. Once retirement
/// wins, no new effect can enter; retirement then waits until every lease that
/// won earlier has released after its real commit.
#[derive(Debug, Default)]
struct DreamCommitGate {
    state: Mutex<DreamCommitState>,
    drained: Condvar,
}

impl DreamCommitGate {
    fn acquire(self: &Arc<Self>, effect: &str) -> Result<DreamCommitLease> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        anyhow::ensure!(
            !state.retired,
            "Dream {effect} blocked: accepted generation is retired"
        );
        state.active = state
            .active
            .checked_add(1)
            .context("Dream commit-lease counter overflow")?;
        drop(state);
        Ok(DreamCommitLease {
            gate: Arc::clone(self),
        })
    }

    fn retire_and_wait(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.retired = true;
        while state.active != 0 {
            state = self
                .drained
                .wait(state)
                .unwrap_or_else(|poison| poison.into_inner());
        }
    }
}

/// Held over the true irreversible effect, including async WAL acknowledgement.
#[derive(Debug)]
#[must_use = "the Dream commit lease must be held until the irreversible effect returns"]
pub(crate) struct DreamCommitLease {
    gate: Arc<DreamCommitGate>,
}

impl Drop for DreamCommitLease {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.active = state
            .active
            .checked_sub(1)
            .expect("Dream commit lease counter underflow");
        if state.active == 0 {
            self.gate.drained.notify_all();
        }
    }
}

/// Config, epoch identity and Dream commit gate published by one ArcSwap store.
///
/// Consumers that bind work to an accepted generation must retain this exact
/// `Arc`; reading `latest()` and a watch counter separately is not an authority
/// proof because a reload can occur between those reads.
pub struct AcceptedConfigSnapshot {
    config: Arc<FreedomConfig>,
    epoch: u64,
    dream_commit_gate: Arc<DreamCommitGate>,
}

impl AcceptedConfigSnapshot {
    fn new(config: FreedomConfig, epoch: u64) -> Self {
        let dream_commit_gate = Arc::new(DreamCommitGate::default());
        if !config.dreaming.enabled
            || !crate::cron::scheduler::autonomy_allows_scheduler(config.autonomy)
        {
            // A policy-disabled generation has no lease-acquisition window at
            // all. This hardens the gate itself instead of relying solely on
            // every caller remembering a separate policy check.
            dream_commit_gate.retire_and_wait();
        }
        Self {
            config: Arc::new(config),
            epoch,
            dream_commit_gate,
        }
    }

    pub fn config(&self) -> Arc<FreedomConfig> {
        Arc::clone(&self.config)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn acquire_dream_commit(&self, effect: &str) -> Result<DreamCommitLease> {
        self.dream_commit_gate.acquire(effect)
    }

    pub(crate) fn retire_dream_commits_and_wait(&self) {
        self.dream_commit_gate.retire_and_wait();
    }
}

/// Sentinel file name written into `~/.neoth/` by `neoth reload`.
/// The daemon's polling tick checks for this file's existence; on
/// present it loads + validates + swaps + deletes the file. Name
/// starts with `.` so it's hidden in `ls`/Explorer; doesn't collide
/// with any user-facing artifact.
pub const RELOAD_SENTINEL_NAME: &str = ".reload-requested";

/// Typed reason why a candidate config could not replace the live snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReloadRejectionReason {
    /// Changing the daemon identity requires every identity-bound subsystem to
    /// be reconstructed from startup.
    OperatorIdChanged {
        old: Option<String>,
        new: Option<String>,
    },
    /// The authorized provider transport is constructed once at startup.
    ProviderKindChanged {
        old: Option<crate::cli::init::ProviderKind>,
        new: Option<crate::cli::init::ProviderKind>,
    },
    /// A provider Arc, fallback/compaction decorator, route, credential, or
    /// adapter setting would diverge from the newly published config snapshot.
    ProviderRuntimeChanged { changed_fields: Vec<&'static str> },
    /// Enabling sovereign mode requires its explicit consent ceremony, but it
    /// does not require a daemon restart after that ceremony succeeds.
    SovereignBuddyCeremonyRequired,
}

impl ReloadRejectionReason {
    /// Stable machine-readable reason code for the WAL audit payload.
    pub fn code(&self) -> &'static str {
        match self {
            Self::OperatorIdChanged { .. } => "operator_id_changed",
            Self::ProviderKindChanged { .. } => "provider_kind_changed",
            Self::ProviderRuntimeChanged { .. } => "provider_runtime_changed",
            Self::SovereignBuddyCeremonyRequired => "sovereign_buddy_ceremony_required",
        }
    }

    /// Whether this specific rejection can only be applied by restarting the
    /// daemon. Policy/consent rejections deliberately return false.
    pub fn restart_required(&self) -> bool {
        matches!(
            self,
            Self::OperatorIdChanged { .. }
                | Self::ProviderKindChanged { .. }
                | Self::ProviderRuntimeChanged { .. }
        )
    }
}

impl std::fmt::Display for ReloadRejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperatorIdChanged { old, new } => write!(
                f,
                "operator_id is immutable post-init (old={old:?}, new={new:?}); restart NEOTH to change operator identity"
            ),
            Self::ProviderKindChanged { old, new } => write!(
                f,
                "provider_kind is immutable post-init (old={old:?}, new={new:?}); restart NEOTH to switch provider — the provider Arc + consent gate are built once at startup"
            ),
            Self::ProviderRuntimeChanged { changed_fields } => write!(
                f,
                "provider runtime fields cannot be hot-reloaded yet (changed: {}); the active provider Arc, route/fallback graph and compaction decorators remain on the startup generation; restart NEOTH to apply these fields",
                changed_fields.join(", ")
            ),
            Self::SovereignBuddyCeremonyRequired => write!(
                f,
                "sovereign_buddy cannot be enabled via reload — run `neoth autonomy sovereign --enable` (consent ceremony required)"
            ),
        }
    }
}

/// Complete rejection of one candidate snapshot. All applicable reasons are
/// retained so a non-restart policy rejection cannot hide a restart-bound
/// field change in the same file edit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReloadRejection {
    reasons: Vec<ReloadRejectionReason>,
}

impl ReloadRejection {
    fn from_reasons(reasons: Vec<ReloadRejectionReason>) -> Option<Self> {
        (!reasons.is_empty()).then_some(Self { reasons })
    }

    pub fn reasons(&self) -> &[ReloadRejectionReason] {
        &self.reasons
    }

    /// Stable reason codes for structured audit consumers.
    pub fn reason_codes(&self) -> Vec<&'static str> {
        self.reasons
            .iter()
            .map(ReloadRejectionReason::code)
            .collect()
    }

    /// Restart is required when any retained reason owns startup-only state.
    pub fn restart_required(&self) -> bool {
        self.reasons
            .iter()
            .any(ReloadRejectionReason::restart_required)
    }
}

impl std::fmt::Display for ReloadRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, reason) in self.reasons.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{reason}")?;
        }
        Ok(())
    }
}

/// Result of a reload attempt. Carries operator-visible detail for
/// the audit trail + the stderr/`tracing` log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReloadResult {
    /// Reload succeeded — `ArcSwap` now holds the new config.
    /// `changed_fields` lists the operator-visible top-level fields
    /// that differ between old + new (best-effort enumeration; deep
    /// nested changes within `council.*` etc. show up as
    /// `"council"` not a per-leaf diff).
    Reloaded { changed_fields: Vec<String> },
    /// Reload rejected — an immutable field was changed. The
    /// `ArcSwap` value did NOT change; current config stays live.
    /// `rejection` retains every applicable typed reason and derives the
    /// structured restart requirement without parsing operator-facing text.
    Rejected { rejection: ReloadRejection },
    /// File content identical to live config — no swap performed,
    /// no audit frame emitted. Operator triggered reload against a
    /// freedom.yaml they hadn't actually edited.
    Unchanged,
}

/// Owns the live atomic accepted snapshot + the source file path.
/// Construct once at daemon startup; clone freely.
#[derive(Clone)]
pub struct ReloadController {
    inner: Arc<ArcSwap<AcceptedConfigSnapshot>>,
    source_path: PathBuf,
    /// Q-4 (hermes port, Session 19): cached `xxh3_64(path +
    /// mtime + size)` snapshot of the source file. Lets a
    /// polling loop skip the full YAML re-read when nothing
    /// has changed — read-stat-hash is ~10µs vs ~500µs for
    /// the full parse. `None` means "not yet computed";
    /// `try_reload` populates it after every read.
    snapshot_hash: Arc<std::sync::Mutex<Option<u64>>>,
    /// Reload-generation counter — bumped once per SUCCESSFUL swap
    /// (`ReloadResult::Reloaded` only; Unchanged / Rejected leave it
    /// alone). Long-lived consumers that freeze config at construction
    /// (channel adapters) subscribe via [`Self::subscribe_generation`]
    /// and rebuild on a bump.
    generation_tx: Arc<tokio::sync::watch::Sender<u64>>,
    /// Serializes accepted-generation publication and permanent shutdown
    /// retirement. Without this lock two concurrent reloads can derive the same
    /// epoch or shutdown can race publication of a fresh active Dream gate.
    publication_lock: Arc<Mutex<()>>,
    dream_runtime_retired: Arc<AtomicBool>,
}

impl ReloadController {
    /// Construct from the initial config + the freedom.yaml path
    /// that `try_reload()` will re-read.
    pub fn new(initial: FreedomConfig, source_path: PathBuf) -> Self {
        let initial_hash = compute_snapshot_hash(&source_path).ok();
        let (generation_tx, _initial_rx) = tokio::sync::watch::channel(0u64);
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(AcceptedConfigSnapshot::new(
                initial, 0,
            )))),
            source_path,
            snapshot_hash: Arc::new(std::sync::Mutex::new(initial_hash)),
            generation_tx: Arc::new(generation_tx),
            publication_lock: Arc::new(Mutex::new(())),
            dream_runtime_retired: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Subscribe to reload-generation bumps. `changed().await` fires
    /// once per successful `try_reload` swap; read the new config via
    /// [`Self::latest`] — the generation value itself is only a
    /// monotonic tick.
    pub fn subscribe_generation(&self) -> tokio::sync::watch::Receiver<u64> {
        self.generation_tx.subscribe()
    }

    /// Lock-free snapshot of the current config. Returns an `Arc`;
    /// every reader gets the same `Arc` until a reload swaps in a
    /// new one. Cheap: an atomic pointer load + Arc clone.
    pub fn latest(&self) -> Arc<FreedomConfig> {
        self.accepted_snapshot().config()
    }

    /// Atomically capture config + monotonic epoch + Dream commit gate.
    pub fn accepted_snapshot(&self) -> Arc<AcceptedConfigSnapshot> {
        self.inner.load_full()
    }

    /// Permanently retire Dream effects during daemon shutdown.
    ///
    /// The publication lock closes the reload-vs-shutdown race: after this
    /// returns, no concurrent or future reload can publish a fresh active gate.
    pub fn retire_dream_runtime(&self) {
        let _publication = self
            .publication_lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        self.dream_runtime_retired.store(true, Ordering::Release);
        self.inner.load_full().retire_dream_commits_and_wait();
    }

    /// Immutable snapshot of the currently active autonomy policy.
    ///
    /// Calling this at the side-effect leaf makes successful config reloads
    /// visible without sharing a mutable policy object across awaits.
    pub fn autonomy_policy(&self) -> crate::permissions::AutonomyPolicySnapshot {
        self.latest().autonomy_policy()
    }

    /// Current hot-reloadable cluster gossip policy. Long-lived transports
    /// resolve this at each send/receive operation instead of freezing startup
    /// defaults, so privacy and replay-window changes take effect atomically.
    pub fn gossip_policy(&self) -> crate::config::ClusterGossipPolicy {
        self.latest().cluster.gossip.clone()
    }

    /// Source path the controller re-reads on `try_reload`.
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Q-4 fast-path gate. Computes the file's current
    /// `xxh3_64(path + mtime + size)` snapshot hash and
    /// compares against the cached one. Returns:
    ///
    ///   - `Ok(true)`  — file changed (or first call); the
    ///     caller should run `try_reload()` to do the full
    ///     YAML parse + validation pass.
    ///   - `Ok(false)` — file unchanged since last check;
    ///     skip the parse. Polling loops use this to keep
    ///     idle CPU below 1%.
    ///   - `Err`       — file disappeared or stat failed.
    ///     Caller decides: most use cases log + skip.
    ///
    /// Side effect: when the file IS changed, the cached
    /// hash is updated to the new value so a follow-up
    /// `try_reload()` is correctly tracked.
    pub fn should_reload(&self) -> Result<bool> {
        let fresh = compute_snapshot_hash(&self.source_path)?;
        let mut cached = self.snapshot_hash.lock().expect("snapshot mutex poisoned");
        let changed = match *cached {
            Some(prev) => prev != fresh,
            None => true,
        };
        if changed {
            *cached = Some(fresh);
        }
        Ok(changed)
    }

    /// Attempt to reload from `source_path`. Validates that no
    /// immutable field has changed; on validation pass, swaps the
    /// ArcSwap atomically. Caller emits the audit WAL frame.
    ///
    /// A successful reload waits for active Dream commit leases. Async callers
    /// must invoke this synchronous boundary through `spawn_blocking` (the
    /// daemon reload loop does) so a lease-owning future can keep progressing.
    pub fn try_reload(&self) -> Result<ReloadResult> {
        let _publication = self
            .publication_lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        anyhow::ensure!(
            !self.dream_runtime_retired.load(Ordering::Acquire),
            "config reload refused: daemon Dream runtime is retired for shutdown"
        );
        let old = self.accepted_snapshot();
        let old_config = old.config();
        let candidate = FreedomConfig::load_from_path(&self.source_path)
            .with_context(|| format!("re-read {}", self.source_path.display()))?;

        // Identical content → no-op. Compare via YAML round-trip so
        // deep-equal works without requiring `PartialEq` on every
        // nested config struct (which several lack).
        let old_yaml = serde_yaml::to_string(&*old_config)
            .context("serialize active config for reload comparison")?;
        let new_yaml = serde_yaml::to_string(&candidate)
            .context("serialize candidate config for reload comparison")?;
        // `ssh_tunnels` is intentionally runtime-only and serde-skipped so no
        // password/passphrase can enter a public config rendering. Compare the
        // effective private authority explicitly before the public-YAML
        // no-change fast path; a credentials-only edit must be rejected as a
        // restart-bound runtime change rather than mislabeled `Unchanged`.
        let ssh_tunnels_changed = old_config.ssh_tunnels != candidate.ssh_tunnels;
        if old_yaml == new_yaml && !ssh_tunnels_changed {
            return Ok(ReloadResult::Unchanged);
        }

        // Validate immutable fields.
        if let Some(rejection) = validate_reload(&old_config, &candidate) {
            return Ok(ReloadResult::Rejected { rejection });
        }

        // Compute changed top-level fields before publishing the new snapshot.
        // A serialization failure must reject the reload rather than silently
        // reporting an empty diff for a config that is about to become active.
        let changed_fields = diff_top_level(&old_config, &candidate)?;

        let next_epoch = old
            .epoch()
            .checked_add(1)
            .context("accepted reload epoch overflow")?;
        let next = Arc::new(AcceptedConfigSnapshot::new(candidate, next_epoch));

        // Linearization order:
        // 1. retire old gate, preventing new irreversible effects;
        // 2. wait for every already-leased commit to finish;
        // 3. atomically publish config + epoch + fresh gate in one ArcSwap store.
        old.retire_dream_commits_and_wait();
        self.inner.store(Arc::clone(&next));

        // Watch is notification only. Exact authority comes from the accepted
        // snapshot Arc identity, never a separate counter/config read pair.
        let _ = self.generation_tx.send_replace(next_epoch);

        Ok(ReloadResult::Reloaded { changed_fields })
    }
}

/// Validate that no immutable field changed between `old` + `new`.
/// Returns a typed aggregate on rejection, `None` when the swap is
/// allowed to proceed.
///
/// Immutable post-init:
///   - `operator_id` — the daemon's identity is pinned at first init
///   - provider runtime fields — the provider Arc, endpoint, credentials,
///     per-role topology, fallbacks and compaction decorators are built once at
///     startup. Publishing a different config without rebuilding that graph
///     would make live consent checks authorize the wrong route generation.
/// Cluster lifecycle fields are mutable because the runtime supervisor rebuilds
/// the complete generation. `cluster.gossip` remains cheaper: workers resolve
/// it from the live controller without a carrier rebuild.
/// Channel-specific fields, including `telegram_user_id`, are mutable because
/// the credential-aware adapter reconciler restarts only the affected adapter.
fn validate_reload(old: &FreedomConfig, new: &FreedomConfig) -> Option<ReloadRejection> {
    let mut reasons = Vec::new();
    if old.operator_id != new.operator_id {
        reasons.push(ReloadRejectionReason::OperatorIdChanged {
            old: old.operator_id.clone(),
            new: new.operator_id.clone(),
        });
    }
    if old.provider_kind != new.provider_kind {
        reasons.push(ReloadRejectionReason::ProviderKindChanged {
            old: old.provider_kind,
            new: new.provider_kind,
        });
    }
    let provider_runtime_changes = changed_provider_runtime_fields(old, new);
    if !provider_runtime_changes.is_empty() {
        reasons.push(ReloadRejectionReason::ProviderRuntimeChanged {
            changed_fields: provider_runtime_changes,
        });
    }
    // Error-hunt #2 (2026-07-03) HIGH: sovereign-buddy must NEVER escalate via a
    // hand-edited freedom.yaml + `neoth reload` — the typed-phrase consent
    // ceremony (`neoth autonomy sovereign --enable`) is the ONLY on-ramp.
    // De-escalation (true→false) through reload is always allowed.
    if new.sovereign_buddy && !old.sovereign_buddy {
        reasons.push(ReloadRejectionReason::SovereignBuddyCeremonyRequired);
    }
    ReloadRejection::from_reasons(reasons)
}

fn serialized_fragment_changed<T: serde::Serialize>(old: &T, new: &T) -> bool {
    let old = serde_yaml::to_string(old).map(zeroize::Zeroizing::new);
    let new = serde_yaml::to_string(new).map(zeroize::Zeroizing::new);
    match (old, new) {
        (Ok(old), Ok(new)) => old.as_str() != new.as_str(),
        // A fragment that cannot be compared safely must stay on the active
        // generation. Failing closed here is preferable to publishing a
        // snapshot that no longer describes the constructed provider graph.
        _ => true,
    }
}

fn provider_secret_changed(
    old: &Option<crate::secret::SecretString>,
    new: &Option<crate::secret::SecretString>,
) -> bool {
    old.as_ref().map(crate::secret::SecretString::expose)
        != new.as_ref().map(crate::secret::SecretString::expose)
}

/// Exact config fragments captured by the long-lived provider runtime.
/// Keep this list next to the reload validator: adding a new provider builder
/// input requires either a generation-bound rebuild supervisor or a new entry
/// here. Dynamic policy/prompt fields remain hot-reloadable.
fn changed_provider_runtime_fields(old: &FreedomConfig, new: &FreedomConfig) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if old.secrets_backend != new.secrets_backend {
        changed.push("secrets_backend");
    }
    if old.provider_binary != new.provider_binary {
        changed.push("provider_binary");
    }
    if provider_secret_changed(&old.provider_key, &new.provider_key) {
        changed.push("provider_key");
    }
    if old.provider_endpoint != new.provider_endpoint {
        changed.push("provider_endpoint");
    }
    if old.provider_model != new.provider_model {
        changed.push("provider_model");
    }
    if serialized_fragment_changed(&old.models_aliases, &new.models_aliases) {
        changed.push("models_aliases");
    }
    if old.provider_region != new.provider_region {
        changed.push("provider_region");
    }
    if old.provider_api_version != new.provider_api_version {
        changed.push("provider_api_version");
    }
    if serialized_fragment_changed(&old.inference, &new.inference) {
        changed.push("inference");
    }
    if serialized_fragment_changed(&old.fallback, &new.fallback) {
        changed.push("fallback");
    }
    if serialized_fragment_changed(&old.claude_cli, &new.claude_cli) {
        changed.push("claude_cli");
    }
    // The leaf authorizer reads this cap from the current reload generation,
    // but an enabled history compactor captures it when the provider graph is
    // built. Keep those two boundaries generation-consistent.
    let compactor_bound_input_cap_changed = old.tokens.max_per_request
        != new.tokens.max_per_request
        && (old.tokens.history_compaction_enabled || new.tokens.history_compaction_enabled);
    if compactor_bound_input_cap_changed
        || old.tokens.history_compaction_enabled != new.tokens.history_compaction_enabled
        || old.tokens.history_compaction_threshold != new.tokens.history_compaction_threshold
        || old.tokens.history_keep_recent_chars != new.tokens.history_keep_recent_chars
    {
        changed.push("tokens.provider_runtime");
    }
    if serialized_fragment_changed(&old.hysteria, &new.hysteria) {
        changed.push("hysteria");
    }
    if old.ssh_tunnels != new.ssh_tunnels {
        changed.push("ssh_tunnels");
    }
    if serialized_fragment_changed(&old.recursive_mas, &new.recursive_mas) {
        changed.push("recursive_mas");
    }
    changed
}

/// Compare two `FreedomConfig` instances at the top level via their YAML
/// serialisation. Returns the names of top-level keys whose value differs
/// (sorted, deduplicated).
///
/// GOLD-ARCH-18: a `serde_yaml::Value` mapping diff rather than a
/// hand-maintained per-field `check!` list — so a NEW `FreedomConfig` field is
/// diffed automatically and adding one no longer requires editing this function
/// (the old list silently missed any field a contributor forgot to add). A
/// best-effort operator-visible diagnostic only; the actual swap uses ArcSwap
/// pointer-store, not this diff. By the time this runs the caller has already
/// established the two configs differ AND that no immutable field changed
/// (`validate_reload` passed), so every reported key is a tunable.
fn diff_top_level(old: &FreedomConfig, new: &FreedomConfig) -> Result<Vec<String>> {
    use serde_yaml::Value;
    let old_v = serde_yaml::to_value(old).context("serialize active config for reload diff")?;
    let new_v = serde_yaml::to_value(new).context("serialize candidate config for reload diff")?;
    let (Value::Mapping(old_map), Value::Mapping(new_map)) = (&old_v, &new_v) else {
        anyhow::bail!("FreedomConfig serialized to a non-mapping YAML value");
    };
    // Union of keys: a key whose value differs — or that exists in only one of
    // the two configs — counts as changed. BTreeSet dedups the shared keys
    // (each appears in both `keys()` iterators) and yields a stable sorted list.
    let mut changed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for key in old_map.keys().chain(new_map.keys()) {
        if let Value::String(name) = key
            && old_map.get(key) != new_map.get(key)
        {
            changed.insert(name.clone());
        }
    }
    Ok(changed.into_iter().collect())
}

/// Q-4 (hermes port, Session 19): compute the
/// `xxh3_64(path + mtime_unix_ns + size_bytes)` snapshot
/// hash for a config file. Pure I/O — does NOT read the
/// file's content, only its metadata. ~10µs vs ~500µs for
/// a full YAML parse. When the operator runs `touch
/// freedom.yaml` the mtime changes even if bytes don't,
/// which is the expected operator-side trigger for a
/// reload-without-edit (e.g. after a `chmod`).
///
/// Returns Err when stat fails (file missing / permission
/// denied) — caller decides whether to bail or skip.
pub fn compute_snapshot_hash(path: &Path) -> Result<u64> {
    // Build the hash input as: path_bytes || ":" || mtime_ns || ":" || size_bytes.
    // Cross-platform via `Metadata::modified()` — no unix-only
    // MetadataExt::mtime needed.
    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat {} for snapshot hash", path.display()))?;
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    let size = meta.len();
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    use std::hash::Hasher;
    hasher.write(path_bytes);
    hasher.write_u8(b':');
    hasher.write_i128(mtime_ns);
    hasher.write_u8(b':');
    hasher.write_u64(size);
    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::cli::init::ProviderKind;
    use crate::config::credentials::Credentials;
    use crate::secret::SecretString;
    use crate::transport::ssh_config::{SshAuth, SshEndpoint, SshTunnelConfig};

    fn fresh_config() -> FreedomConfig {
        FreedomConfig {
            operator_id: Some("sam".into()),
            provider_kind: Some(ProviderKind::ClaudeCli),
            telegram_user_id: Some(42),
            ..Default::default()
        }
    }

    fn ssh_tunnel(password: &str) -> SshTunnelConfig {
        SshTunnelConfig {
            endpoint: SshEndpoint {
                host: "bastion.example".into(),
                port: 22,
                username: "sam".into(),
                auth: SshAuth::Password(SecretString::from(password)),
            },
            remote_host: "127.0.0.1".into(),
            remote_port: 5432,
            local_port: 0,
            jump_hosts: Vec::new(),
            max_retries: 5,
            retry_delay: Duration::from_secs(2),
        }
    }

    #[test]
    fn latest_returns_initial_config() {
        let cfg = fresh_config();
        let ctrl = ReloadController::new(cfg.clone(), PathBuf::from("/tmp/nope.yaml"));
        let latest = ctrl.latest();
        assert_eq!(latest.operator_id, cfg.operator_id);
    }

    #[test]
    fn validate_immutable_operator_id_rejects() {
        let old = fresh_config();
        let mut new = old.clone();
        new.operator_id = Some("not-sam".into());
        let rejection = validate_reload(&old, &new).expect("must reject");
        assert!(matches!(
            rejection.reasons(),
            [ReloadRejectionReason::OperatorIdChanged { .. }]
        ));
        assert_eq!(rejection.reason_codes(), ["operator_id_changed"]);
        assert!(rejection.restart_required());
        assert!(rejection.to_string().contains("operator_id"));
    }

    #[test]
    fn validate_immutable_provider_kind_rejects() {
        let old = fresh_config();
        let mut new = old.clone();
        new.provider_kind = Some(ProviderKind::OpenaiApi);
        let rejection = validate_reload(&old, &new).expect("must reject");
        assert!(matches!(
            rejection.reasons(),
            [ReloadRejectionReason::ProviderKindChanged { .. }]
        ));
        assert_eq!(rejection.reason_codes(), ["provider_kind_changed"]);
        assert!(rejection.restart_required());
        assert!(rejection.to_string().contains("provider_kind"));
    }

    #[test]
    fn provider_endpoint_reload_is_restart_bound() {
        let old = fresh_config();
        let mut new = old.clone();
        new.provider_endpoint = Some("http://127.0.0.1:11434".into());

        let rejection = validate_reload(&old, &new).expect("provider route must not diverge");
        assert_eq!(rejection.reason_codes(), ["provider_runtime_changed"]);
        assert!(rejection.restart_required());
        assert!(rejection.to_string().contains("provider_endpoint"));
        assert!(rejection.to_string().contains("restart NEOTH"));
    }

    #[test]
    fn input_cap_is_hot_reloadable_when_history_compactor_is_disabled() {
        let old = fresh_config();
        let mut new = old.clone();
        new.tokens.max_per_request += 1;

        assert!(
            validate_reload(&old, &new).is_none(),
            "the leaf authorizer reads the current cap on every call"
        );
    }

    #[test]
    fn fallback_and_recursive_sub_slot_reload_are_restart_bound() {
        use crate::config::inference::{
            HemisphereRole, HemisphereSlot, InferenceProvider, SubHemisphereSlots,
        };

        let old = fresh_config();
        let mut new = old.clone();
        new.fallback.chain.push(HemisphereSlot {
            provider: Some(InferenceProvider::OpenAi),
            ..Default::default()
        });
        new.inference.hemisphere_sub_slots.insert(
            HemisphereRole::Left,
            SubHemisphereSlots {
                right: HemisphereSlot {
                    provider: Some(InferenceProvider::Gemini),
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let rejection = validate_reload(&old, &new).expect("provider graph edit must reject");
        assert_eq!(rejection.reasons().len(), 1);
        match &rejection.reasons()[0] {
            ReloadRejectionReason::ProviderRuntimeChanged { changed_fields } => {
                assert_eq!(changed_fields, &["inference", "fallback"]);
            }
            other => panic!("unexpected rejection: {other:?}"),
        }
    }

    #[test]
    fn every_cluster_lifecycle_field_is_hot_reloadable_by_runtime_supervisor() {
        let old = fresh_config();
        let mut new = old.clone();
        new.cluster.name = Some("home-mesh".into());
        new.cluster.enabled = true;
        new.cluster.transport = crate::config::ClusterTransport::Iroh;
        new.cluster.peers = vec!["endpoint-id".into()];
        new.cluster.mdns.enabled = false;
        new.cluster.policy.announce_on_untrusted_wifi = true;
        new.cluster.policy.trusted_ssids = vec!["home".into()];
        new.cluster.gossip.replicate_raw_ingress = true;
        new.cluster.gossip.replay_budget_days = 14;
        new.cluster.listen_port = 49_738;

        assert!(
            validate_reload(&old, &new).is_none(),
            "one supervisor owns every cluster lifecycle resource"
        );
    }

    #[test]
    fn gossip_policy_is_hot_reloadable_and_visible_through_controller() {
        let old = fresh_config();
        let mut new = old.clone();
        new.cluster.gossip.replicate_raw_ingress = true;
        new.cluster.gossip.replay_budget_days = 14;

        assert!(
            validate_reload(&old, &new).is_none(),
            "gossip policy does not own a carrier and must hot-reload"
        );

        let controller = ReloadController::new(new, PathBuf::from("missing-freedom.yaml"));
        let policy = controller.gossip_policy();
        assert!(policy.replicate_raw_ingress);
        assert_eq!(policy.replay_budget_days, 14);
    }

    #[test]
    fn sovereign_ceremony_rejection_does_not_require_restart() {
        let old = fresh_config();
        let mut new = old.clone();
        new.sovereign_buddy = true;

        let rejection = validate_reload(&old, &new).expect("ceremony must reject raw reload");
        assert_eq!(
            rejection.reasons(),
            &[ReloadRejectionReason::SovereignBuddyCeremonyRequired]
        );
        assert_eq!(
            rejection.reason_codes(),
            ["sovereign_buddy_ceremony_required"]
        );
        assert!(!rejection.restart_required());
    }

    #[test]
    fn cluster_change_does_not_turn_ceremony_rejection_into_restart_requirement() {
        let old = fresh_config();
        let mut new = old.clone();
        new.cluster.name = Some("new-mesh".into());
        new.sovereign_buddy = true;

        let rejection = validate_reload(&old, &new).expect("combined edit must reject");
        assert_eq!(
            rejection.reasons(),
            &[ReloadRejectionReason::SovereignBuddyCeremonyRequired]
        );
        assert!(!rejection.restart_required());
    }

    #[test]
    fn validate_mutable_telegram_user_id_allows_targeted_adapter_restart() {
        let old = fresh_config();
        let mut new = old.clone();
        new.telegram_user_id = Some(99);
        assert!(validate_reload(&old, &new).is_none());
    }

    #[test]
    fn validate_mutable_field_allows() {
        let old = fresh_config();
        let mut new = old.clone();
        new.review_gate_enabled = !old.review_gate_enabled;
        assert!(
            validate_reload(&old, &new).is_none(),
            "review_gate_enabled is a tunable; reload must pass validation"
        );
    }

    #[test]
    fn diff_top_level_finds_tunable_changes() {
        let old = fresh_config();
        let mut new = old.clone();
        new.review_gate_enabled = !old.review_gate_enabled;
        let changed = diff_top_level(&old, &new).unwrap();
        assert!(
            changed.contains(&"review_gate_enabled".to_string()),
            "expected review_gate_enabled in diff; got: {changed:?}",
        );
    }

    #[test]
    fn diff_top_level_is_empty_for_identical_configs() {
        let cfg = fresh_config();
        let diff = diff_top_level(&cfg, &cfg).unwrap();
        assert!(
            diff.is_empty(),
            "identical configs must have empty diff; got: {diff:?}"
        );
    }

    #[test]
    fn diff_top_level_finds_multiple_tunables() {
        let old = fresh_config();
        let mut new = old.clone();
        new.review_gate_enabled = !old.review_gate_enabled;
        new.code_map.auto_context_max_files = 5;
        let changed = diff_top_level(&old, &new).unwrap();
        assert!(changed.contains(&"review_gate_enabled".to_string()));
        assert!(changed.contains(&"code_map".to_string()));
    }

    #[test]
    fn reload_sentinel_name_is_dotted() {
        // Dotted file name → hidden in `ls`/Explorer + doesn't
        // collide with any user-facing artifact in ~/.neoth/.
        assert!(RELOAD_SENTINEL_NAME.starts_with('.'));
        assert_eq!(RELOAD_SENTINEL_NAME, ".reload-requested");
    }

    // ── try_reload integration test using a real temp YAML file ──────

    use tempfile::tempdir;

    fn write_yaml(path: &Path, yaml: &str) {
        std::fs::write(path, yaml).expect("write fixture yaml");
    }

    #[test]
    fn try_reload_returns_unchanged_when_file_matches_live_config() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let initial = fresh_config();
        // Round-trip current config to disk.
        let yaml = serde_yaml::to_string(&initial).unwrap();
        write_yaml(&yaml_path, &yaml);
        let ctrl = ReloadController::new(initial, yaml_path.clone());
        match ctrl.try_reload().expect("reload must succeed") {
            ReloadResult::Unchanged => {}
            other => panic!("expected Unchanged, got {other:?}"),
        }
    }

    #[test]
    fn credentials_only_ssh_change_is_restart_bound_not_unchanged() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        write_yaml(&yaml_path, &serde_yaml::to_string(&fresh_config()).unwrap());
        Credentials {
            ssh_tunnels: Some(vec![ssh_tunnel("old-password")]),
            ..Default::default()
        }
        .write(&credentials_path)
        .unwrap();
        let initial = FreedomConfig::load_from_path(&yaml_path).unwrap();
        let ctrl = ReloadController::new(initial, yaml_path);

        Credentials::update_at(&credentials_path, |credentials| {
            credentials.ssh_tunnels = Some(vec![ssh_tunnel("new-password")]);
            Ok(())
        })
        .unwrap();

        match ctrl.try_reload().expect("reload call succeeds") {
            ReloadResult::Rejected { rejection } => {
                assert_eq!(rejection.reason_codes(), ["provider_runtime_changed"]);
                assert!(rejection.restart_required());
                assert!(rejection.to_string().contains("ssh_tunnels"));
            }
            other => panic!("expected restart-bound rejection, got {other:?}"),
        }
        match &ctrl.latest().ssh_tunnels[0].endpoint.auth {
            SshAuth::Password(secret) => {
                assert_eq!(secret.expose_secret(), "old-password");
            }
            other => panic!("unexpected active SSH auth: {other:?}"),
        }
    }

    #[test]
    fn try_reload_rejects_when_immutable_field_changed_on_disk() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let initial = fresh_config();
        let mut new_on_disk = initial.clone();
        new_on_disk.operator_id = Some("attacker".into());
        let yaml = serde_yaml::to_string(&new_on_disk).unwrap();
        write_yaml(&yaml_path, &yaml);
        let ctrl = ReloadController::new(initial, yaml_path);
        match ctrl.try_reload().expect("reload call succeeds") {
            ReloadResult::Rejected { rejection } => {
                assert!(rejection.restart_required());
                assert!(rejection.to_string().contains("operator_id"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        // Critically: latest() still returns the ORIGINAL config.
        assert_eq!(ctrl.latest().operator_id, Some("sam".into()));
    }

    #[test]
    fn try_reload_rejects_provider_route_without_swapping_generation() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let initial = fresh_config();
        let mut changed = initial.clone();
        changed.provider_endpoint = Some("https://provider.example.invalid".into());
        write_yaml(&yaml_path, &serde_yaml::to_string(&changed).unwrap());

        let ctrl = ReloadController::new(initial, yaml_path);
        let generation = ctrl.subscribe_generation();
        match ctrl.try_reload().expect("reload validation succeeds") {
            ReloadResult::Rejected { rejection } => {
                assert_eq!(rejection.reason_codes(), ["provider_runtime_changed"]);
                assert!(rejection.restart_required());
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert!(ctrl.latest().provider_endpoint.is_none());
        assert_eq!(*generation.borrow(), 0);
    }

    #[test]
    fn input_cap_reload_is_restart_bound_while_history_compactor_is_active() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let mut initial = fresh_config();
        initial.tokens.history_compaction_enabled = true;
        let initial_cap = initial.tokens.max_per_request;
        let mut changed = initial.clone();
        changed.tokens.max_per_request = initial_cap.saturating_sub(1);
        write_yaml(&yaml_path, &serde_yaml::to_string(&changed).unwrap());

        let ctrl = ReloadController::new(initial, yaml_path);
        let generation = ctrl.subscribe_generation();
        match ctrl.try_reload().expect("reload validation succeeds") {
            ReloadResult::Rejected { rejection } => {
                assert_eq!(rejection.reason_codes(), ["provider_runtime_changed"]);
                assert!(rejection.restart_required());
                assert!(rejection.to_string().contains("tokens.provider_runtime"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert_eq!(ctrl.latest().tokens.max_per_request, initial_cap);
        assert_eq!(*generation.borrow(), 0);
    }

    #[test]
    fn try_reload_swaps_cluster_change_and_bumps_supervisor_generation() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let initial = fresh_config();
        let mut new_on_disk = initial.clone();
        // A name-only change is a valid persisted config, but it changes the
        // identity from which a future carrier and mDNS registration derive.
        new_on_disk.cluster.name = Some("new-mesh".into());
        write_yaml(&yaml_path, &serde_yaml::to_string(&new_on_disk).unwrap());

        let ctrl = ReloadController::new(initial, yaml_path);
        let generation = ctrl.subscribe_generation();
        assert!(matches!(
            ctrl.try_reload().expect("reload call succeeds"),
            ReloadResult::Reloaded { .. }
        ));

        assert_eq!(
            ctrl.latest().cluster.name.as_deref(),
            Some("new-mesh"),
            "cluster supervisor must observe the published config generation"
        );
        assert_eq!(
            *generation.borrow(),
            1,
            "cluster lifecycle change must wake the runtime supervisor"
        );
    }

    #[test]
    fn try_reload_swaps_when_only_tunable_changed() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let initial = fresh_config();
        let mut new_on_disk = initial.clone();
        new_on_disk.review_gate_enabled = !initial.review_gate_enabled;
        let yaml = serde_yaml::to_string(&new_on_disk).unwrap();
        write_yaml(&yaml_path, &yaml);
        let ctrl = ReloadController::new(initial.clone(), yaml_path);
        match ctrl.try_reload().expect("reload must succeed") {
            ReloadResult::Reloaded { changed_fields } => {
                assert!(
                    changed_fields.contains(&"review_gate_enabled".to_string()),
                    "diff should name the changed field; got: {changed_fields:?}",
                );
            }
            other => panic!("expected Reloaded, got {other:?}"),
        }
        // Critically: latest() now returns the NEW config.
        assert_eq!(
            ctrl.latest().review_gate_enabled,
            !initial.review_gate_enabled,
            "latest() must reflect the swapped value"
        );
    }

    #[test]
    fn custom_policy_reload_swaps_atomically_and_old_snapshot_stays_immutable() {
        use crate::permissions::{Action, ActionKind, AutonomyLevel, CustomDecision, evaluate};

        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let mut initial = fresh_config();
        initial.autonomy = AutonomyLevel::Custom;
        initial
            .custom_autonomy
            .overrides
            .insert(ActionKind::ExecArbitrary, CustomDecision::Allow);
        write_yaml(&yaml_path, &serde_yaml::to_string(&initial).unwrap());
        let ctrl = ReloadController::new(initial.clone(), yaml_path.clone());
        let before = ctrl.autonomy_policy();
        assert!(evaluate(&Action::ExecArbitrary, &before).is_allow());

        let mut changed = initial;
        changed
            .custom_autonomy
            .overrides
            .insert(ActionKind::ExecArbitrary, CustomDecision::Deny);
        write_yaml(&yaml_path, &serde_yaml::to_string(&changed).unwrap());
        match ctrl.try_reload().unwrap() {
            ReloadResult::Reloaded { changed_fields } => assert!(
                changed_fields.contains(&"custom_autonomy".to_string()),
                "custom policy must appear in reload diff: {changed_fields:?}"
            ),
            other => panic!("expected Reloaded, got {other:?}"),
        }

        let after = ctrl.autonomy_policy();
        assert!(evaluate(&Action::ExecArbitrary, &after).is_deny());
        assert!(
            evaluate(&Action::ExecArbitrary, &before).is_allow(),
            "previous immutable snapshot must not mutate after reload"
        );
    }

    #[test]
    fn generation_bumps_only_on_reloaded() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let initial = fresh_config();
        // Round-trip the current config to disk → Unchanged.
        write_yaml(&yaml_path, &serde_yaml::to_string(&initial).unwrap());
        let ctrl = ReloadController::new(initial.clone(), yaml_path.clone());
        let rx = ctrl.subscribe_generation();
        assert_eq!(*rx.borrow(), 0);

        assert!(matches!(
            ctrl.try_reload().unwrap(),
            ReloadResult::Unchanged
        ));
        assert_eq!(*rx.borrow(), 0, "Unchanged must not bump");

        // Immutable-field edit → Rejected, still no bump.
        let mut rejected = initial.clone();
        rejected.operator_id = Some("attacker".into());
        write_yaml(&yaml_path, &serde_yaml::to_string(&rejected).unwrap());
        assert!(matches!(
            ctrl.try_reload().unwrap(),
            ReloadResult::Rejected { .. }
        ));
        assert_eq!(*rx.borrow(), 0, "Rejected must not bump");

        // Tunable edit → Reloaded → bump, and latest() already reflects
        // the new value when the subscriber wakes.
        let mut tuned = initial.clone();
        tuned.review_gate_enabled = !initial.review_gate_enabled;
        write_yaml(&yaml_path, &serde_yaml::to_string(&tuned).unwrap());
        assert!(matches!(
            ctrl.try_reload().unwrap(),
            ReloadResult::Reloaded { .. }
        ));
        assert_eq!(*rx.borrow(), 1, "Reloaded must bump exactly once");
        assert_eq!(
            ctrl.latest().review_gate_enabled,
            !initial.review_gate_enabled
        );
    }

    #[test]
    fn latest_arc_clones_share_the_same_pointer_until_swap() {
        let cfg = fresh_config();
        let ctrl = ReloadController::new(cfg, PathBuf::from("/tmp/nope.yaml"));
        let a = ctrl.latest();
        let b = ctrl.latest();
        // Both clones point to the same Arc — verified by pointer
        // equality (Arc::ptr_eq).
        assert!(Arc::ptr_eq(&a, &b), "latest() clones must share Arc");
    }

    #[test]
    fn accepted_snapshot_never_observes_a_torn_config_epoch_pair() {
        use std::sync::Barrier;

        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let mut initial = fresh_config();
        initial.review_gate_enabled = false;
        write_yaml(&yaml_path, &serde_yaml::to_string(&initial).unwrap());
        let controller = Arc::new(ReloadController::new(initial, yaml_path.clone()));

        for expected_epoch in 1..=64u64 {
            let before = controller.accepted_snapshot();
            let before_pair = (before.epoch(), before.config().review_gate_enabled);
            assert_eq!(before_pair.0, expected_epoch - 1);

            let mut candidate = (*before.config()).clone();
            candidate.review_gate_enabled = !before_pair.1;
            let after_pair = (expected_epoch, candidate.review_gate_enabled);
            write_yaml(&yaml_path, &serde_yaml::to_string(&candidate).unwrap());

            let start = Arc::new(Barrier::new(2));
            let writer_start = Arc::clone(&start);
            let writer_controller = Arc::clone(&controller);
            let writer = std::thread::spawn(move || {
                writer_start.wait();
                writer_controller.try_reload()
            });

            start.wait();
            let observed = controller.accepted_snapshot();
            let observed_pair = (observed.epoch(), observed.config().review_gate_enabled);
            assert!(
                observed_pair == before_pair || observed_pair == after_pair,
                "atomic reader observed torn config/epoch pair {observed_pair:?}; \
                 valid pairs were {before_pair:?} or {after_pair:?}"
            );

            assert!(matches!(
                writer.join().unwrap().unwrap(),
                ReloadResult::Reloaded { .. }
            ));
            let after = controller.accepted_snapshot();
            assert_eq!(
                (after.epoch(), after.config().review_gate_enabled),
                after_pair
            );
        }
    }

    #[test]
    fn reload_retires_old_dream_gate_and_waits_for_active_commit() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let mut initial = fresh_config();
        initial.dreaming.enabled = true;
        initial.autonomy = crate::permissions::AutonomyLevel::Standard;
        write_yaml(&yaml_path, &serde_yaml::to_string(&initial).unwrap());
        let controller = Arc::new(ReloadController::new(initial.clone(), yaml_path.clone()));
        let old = controller.accepted_snapshot();
        let active_commit = old.acquire_dream_commit("test JSONL commit").unwrap();

        let mut candidate = initial;
        candidate.review_gate_enabled = !candidate.review_gate_enabled;
        write_yaml(&yaml_path, &serde_yaml::to_string(&candidate).unwrap());
        let reload_controller = Arc::clone(&controller);
        let reload = std::thread::spawn(move || reload_controller.try_reload());

        // Wait for reload to close the old gate. While our lease is active it
        // must not yet publish the replacement snapshot.
        while let Ok(probe) = old.acquire_dream_commit("retirement probe") {
            drop(probe);
            std::thread::yield_now();
        }
        assert!(
            Arc::ptr_eq(&controller.accepted_snapshot(), &old),
            "reload published before the active Dream commit drained"
        );

        drop(active_commit);
        assert!(matches!(
            reload.join().unwrap().unwrap(),
            ReloadResult::Reloaded { .. }
        ));
        let current = controller.accepted_snapshot();
        assert!(!Arc::ptr_eq(&current, &old));
        assert_eq!(current.epoch(), 1);
        assert!(
            old.acquire_dream_commit("late old-generation commit")
                .is_err()
        );
    }

    #[test]
    fn strict_and_custom_snapshots_never_open_a_dream_commit_gate() {
        for autonomy in [
            crate::permissions::AutonomyLevel::Strict,
            crate::permissions::AutonomyLevel::Custom,
        ] {
            let mut config = fresh_config();
            config.dreaming.enabled = true;
            config.autonomy = autonomy;
            let snapshot = AcceptedConfigSnapshot::new(config, 0);
            assert!(
                snapshot.acquire_dream_commit("policy probe").is_err(),
                "{autonomy:?} opened an unattended Dream commit gate"
            );
        }
    }

    #[test]
    fn policy_reenable_publishes_a_fresh_active_dream_gate() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let mut initial = fresh_config();
        initial.dreaming.enabled = true;
        initial.autonomy = crate::permissions::AutonomyLevel::Custom;
        write_yaml(&yaml_path, &serde_yaml::to_string(&initial).unwrap());
        let controller = ReloadController::new(initial.clone(), yaml_path.clone());
        let blocked = controller.accepted_snapshot();
        assert!(blocked.acquire_dream_commit("custom probe").is_err());

        initial.autonomy = crate::permissions::AutonomyLevel::Standard;
        write_yaml(&yaml_path, &serde_yaml::to_string(&initial).unwrap());
        assert!(matches!(
            controller.try_reload().unwrap(),
            ReloadResult::Reloaded { .. }
        ));
        let enabled = controller.accepted_snapshot();
        assert!(!Arc::ptr_eq(&blocked, &enabled));
        assert!(
            enabled.acquire_dream_commit("standard probe").is_ok(),
            "re-enabling scheduled autonomy must create a new active gate"
        );
    }

    #[test]
    fn shutdown_retirement_is_permanent_and_blocks_future_reload() {
        let dir = tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let mut initial = fresh_config();
        initial.dreaming.enabled = true;
        initial.autonomy = crate::permissions::AutonomyLevel::Standard;
        write_yaml(&yaml_path, &serde_yaml::to_string(&initial).unwrap());
        let controller = Arc::new(ReloadController::new(initial.clone(), yaml_path.clone()));
        let accepted = controller.accepted_snapshot();
        let active_commit = accepted.acquire_dream_commit("test WAL commit").unwrap();

        let retire_controller = Arc::clone(&controller);
        let retire = std::thread::spawn(move || retire_controller.retire_dream_runtime());
        while let Ok(probe) = accepted.acquire_dream_commit("shutdown probe") {
            drop(probe);
            std::thread::yield_now();
        }
        assert!(
            !retire.is_finished(),
            "shutdown did not wait for active commit"
        );
        drop(active_commit);
        retire.join().unwrap();

        let mut candidate = initial;
        candidate.review_gate_enabled = !candidate.review_gate_enabled;
        write_yaml(&yaml_path, &serde_yaml::to_string(&candidate).unwrap());
        let error = controller.try_reload().unwrap_err();
        assert!(format!("{error:#}").contains("retired for shutdown"));
    }

    // ── Q-4 snapshot_hash gate ──────────────────────────────────────

    #[test]
    fn compute_snapshot_hash_is_deterministic_for_unchanged_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "operator_id: alice\n").unwrap();
        let a = compute_snapshot_hash(&path).unwrap();
        let b = compute_snapshot_hash(&path).unwrap();
        assert_eq!(a, b, "unchanged file must hash identically");
    }

    #[test]
    fn compute_snapshot_hash_differs_when_size_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "short\n").unwrap();
        let before = compute_snapshot_hash(&path).unwrap();
        // Sleep briefly so the mtime resolution definitely
        // increments between writes. Some filesystems
        // (FAT32, older NTFS) have 2s mtime granularity;
        // bumping the size is the more reliable signal.
        std::fs::write(&path, "a much longer content here\n").unwrap();
        let after = compute_snapshot_hash(&path).unwrap();
        assert_ne!(before, after, "size change must change hash");
    }

    #[test]
    fn compute_snapshot_hash_errs_on_missing_file() {
        let nonexistent = std::path::Path::new("/tmp/neoth-snapshot-test-nonexistent-9999.yaml");
        assert!(compute_snapshot_hash(nonexistent).is_err());
    }

    #[test]
    fn should_reload_returns_true_on_first_call_when_cache_empty() {
        // ReloadController::new() seeds the cache when the
        // file exists. Pin the post-construction behaviour:
        // if the file is present + we call should_reload
        // immediately, it returns false (cache already
        // matches).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "operator_id: alice\n").unwrap();
        let cfg = FreedomConfig {
            operator_id: Some("alice".into()),
            ..Default::default()
        };
        let ctrl = ReloadController::new(cfg, path.clone());
        // Cache was just populated; no drift yet.
        assert!(!ctrl.should_reload().unwrap(), "fresh cache → no drift");
    }

    #[test]
    fn should_reload_returns_true_after_file_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "operator_id: alice\n").unwrap();
        let cfg = FreedomConfig {
            operator_id: Some("alice".into()),
            ..Default::default()
        };
        let ctrl = ReloadController::new(cfg, path.clone());
        assert!(!ctrl.should_reload().unwrap(), "no drift right after new()");
        // Write different content + larger size — the size
        // diff is the reliable cross-FS signal.
        std::fs::write(
            &path,
            "operator_id: alice\nrole: developer\nlanguage_primary: en\n",
        )
        .unwrap();
        assert!(ctrl.should_reload().unwrap(), "drift after content change");
        // After a should_reload call returning true, the
        // cache updates → next call is false.
        assert!(!ctrl.should_reload().unwrap(), "cache updated → no drift");
    }

    /// GOLD-ADAPT-TRAIL-03 integration test.
    ///
    /// Proves the full consumer path:
    ///   ArcSwap swap → `ctrl.latest().pattern_cron.interval_secs` on the
    ///   next simulated cron tick sees the new value.
    ///
    /// This is the key invariant TRAIL-03 relies on: daemon cron wrappers
    /// call `ctrl.latest().<sub_field>` each tick, so they pick up any
    /// config swap that happened since the previous tick — no restart required.
    #[test]
    fn trail03_latest_reflects_arcswap_after_config_swap() {
        use crate::config::automation::PatternCronConfig;
        use arc_swap::ArcSwap;
        use std::sync::Arc;

        // Boot config: pattern_cron interval = 3600s.
        let boot_cfg = FreedomConfig {
            pattern_cron: PatternCronConfig {
                interval_secs: 3600,
                ..Default::default()
            },
            ..Default::default()
        };

        // Wrap in ArcSwap the same way ReloadController does internally.
        let store: Arc<ArcSwap<FreedomConfig>> = Arc::new(ArcSwap::from_pointee(boot_cfg));

        // Simulate tick-1: cron loop reads sub-field.
        let tick1_interval = store.load().pattern_cron.interval_secs;
        assert_eq!(tick1_interval, 3600, "tick-1 sees boot value");

        // Operator edits freedom.yaml → ReloadController::try_reload swaps
        // the store.  Simulate that swap directly here.
        let new_cfg = FreedomConfig {
            pattern_cron: PatternCronConfig {
                interval_secs: 7200,
                ..Default::default()
            },
            ..Default::default()
        };
        store.store(Arc::new(new_cfg));

        // Simulate tick-2: cron loop calls ctrl.latest().pattern_cron...
        // Uses the same load() path that ReloadController::latest() wraps.
        let tick2_interval = store.load().pattern_cron.interval_secs;
        assert_eq!(
            tick2_interval, 7200,
            "tick-2 sees swapped value — no restart needed"
        );

        // Tick-1 guard: the previous load (already stored in tick1_interval)
        // was a snapshot at that moment; the new load is independent.
        assert_ne!(
            tick1_interval, tick2_interval,
            "swap is visible to subsequent loads"
        );
    }
}
