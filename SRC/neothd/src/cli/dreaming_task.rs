//! Background dreaming task — R-02 Phase 4c.
//!
//! Wraps the existing [`crate::daemon::dreaming`] composer in a calendar
//! scheduler so the daemon attempts one batch at the configured local daily
//! boundary. When an `EmbedProvider` is wired into the
//! daemon (`freedom.yaml::inference.embedding_provider`) the task
//! uses [`crate::daemon::dreaming::compose_dreams_with_embeddings`]
//! for cosine-clustered themes; otherwise it falls back to the
//! deterministic [`crate::daemon::dreaming::compose_dream`] path so
//! operators without local inference still get a daily dream record.
//!
//! Off by default — opt in via `freedom.yaml::dream.cron_enabled: true`.
//! Boundaries are claimed durably before effects; boot never catches up an
//! already-passed boundary.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, LocalResult, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use rusqlite::Connection;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::daemon::dreaming::{
    DREAMING_CLUSTER_THRESHOLD, EventRef, append_dream, compose_dream,
    compose_dreams_with_embeddings,
};
use crate::providers::cost_authorization::AuthorizedProvider;
use crate::providers::embed::EmbedProvider;
use crate::wal::writer::WalWriterHandle;

const DREAM_CRON_POLL: Duration = Duration::from_secs(30);

/// Cooperative cancellation shared with the Cron fleet owner.
///
/// Dream uses blocking leaves (JSONL/Obsidian/proposal persistence). Aborting
/// only the async wrapper would detach an already-started `spawn_blocking`
/// child. The fleet therefore signals this token and joins the real Dream task;
/// every blocking commit re-checks the same token immediately before mutation.
#[derive(Debug, Default)]
pub(crate) struct DreamCancellation {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl DreamCancellation {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            // `notify_one` stores a permit when the scheduler has not entered
            // its select yet, avoiding a lost wake between the atomic check and
            // `notified().await`.
            self.notify.notify_one();
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

/// Irreversible effect classes owned by the Dream runtime.
///
/// Keeping these typed makes the call sites and the adversarial retirement
/// test share one exhaustive vocabulary instead of relying on unrelated log
/// strings.
#[derive(Clone, Copy, Debug)]
enum DreamCommitEffect {
    RuntimeSetup,
    StateClaim,
    ProviderDispatch,
    JsonlAppend,
    ObsidianSync,
    ProposalQueue,
    SelfImproveProposal,
    WalAppend,
}

impl DreamCommitEffect {
    #[cfg(test)]
    const ALL: [Self; 8] = [
        Self::RuntimeSetup,
        Self::StateClaim,
        Self::ProviderDispatch,
        Self::JsonlAppend,
        Self::ObsidianSync,
        Self::ProposalQueue,
        Self::SelfImproveProposal,
        Self::WalAppend,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::RuntimeSetup => "runtime setup",
            Self::StateClaim => "state claim",
            Self::ProviderDispatch => "provider dispatch",
            Self::JsonlAppend => "Dream JSONL append",
            Self::ObsidianSync => "Obsidian sync",
            Self::ProposalQueue => "proposal/queue commit",
            Self::SelfImproveProposal => "self-improve proposal staging",
            Self::WalAppend => "DREAM_COMPOSED WAL append",
        }
    }
}

/// Authorization rail for one atomically accepted Dream Cron snapshot.
///
/// The retained snapshot is the config, epoch identity and commit gate that
/// were published by one ArcSwap store. A leaf first proves Arc identity, then
/// acquires the generation's gate. Reload/stop retirement serializes against
/// acquisition and waits for already-leased commits to finish.
#[derive(Clone)]
pub(crate) struct DreamEffectRail {
    reload_controller: Arc<crate::config::reload::ReloadController>,
    accepted: Arc<crate::config::reload::AcceptedConfigSnapshot>,
    cancellation: Arc<DreamCancellation>,
}

impl DreamEffectRail {
    pub(crate) fn new(
        reload_controller: Arc<crate::config::reload::ReloadController>,
        accepted: Arc<crate::config::reload::AcceptedConfigSnapshot>,
        cancellation: Arc<DreamCancellation>,
    ) -> Self {
        Self {
            reload_controller,
            accepted,
            cancellation,
        }
    }

    pub(crate) fn ensure_current(&self, effect: &str) -> Result<()> {
        anyhow::ensure!(
            !self.cancellation.is_cancelled(),
            "Dream {effect} blocked: task cancellation is active"
        );
        let current = self.reload_controller.accepted_snapshot();
        anyhow::ensure!(
            Arc::ptr_eq(&current, &self.accepted),
            "Dream {effect} blocked: accepted generation {} was superseded by {}",
            self.accepted.epoch(),
            current.epoch()
        );
        let config = current.config();
        anyhow::ensure!(
            config.dreaming.enabled
                && crate::cron::scheduler::autonomy_allows_scheduler(config.autonomy),
            "Dream {effect} blocked: current policy disables unattended Dream work"
        );
        Ok(())
    }

    fn acquire_commit_lease(
        &self,
        effect: DreamCommitEffect,
    ) -> Result<crate::config::reload::DreamCommitLease> {
        self.ensure_current(effect.label())?;
        // Retirement and acquisition serialize inside the accepted snapshot's
        // gate. If reload/stop wins after ensure_current, this fails closed; if
        // acquisition wins, retirement waits until the true commit returns.
        self.accepted.acquire_dream_commit(effect.label())
    }

    pub(crate) fn acquire_runtime_setup_lease(
        &self,
    ) -> Result<crate::config::reload::DreamCommitLease> {
        self.acquire_commit_lease(DreamCommitEffect::RuntimeSetup)
    }

    pub(crate) fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub(crate) fn retire_generation_and_wait(&self) {
        self.accepted.retire_dream_commits_and_wait();
    }

    pub(crate) fn retire_runtime_and_wait(&self) {
        self.reload_controller.retire_dream_runtime();
    }
}

/// Default window: last 24h. The composer reads `idx_episode` rows
/// whose `ts_ns` falls inside `now - window`. Aligns with the daily
/// calendar boundary so each pass processes one fresh day.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum events to embed per dreaming pass. Above this the task
/// truncates with a warn — protects operator-LLM cost on
/// high-traffic days (a 5k-event day at ~50ms/embed = 4min compute).
/// Tunable via `dreaming.max_events_per_pass`.
pub const DEFAULT_MAX_EVENTS: usize = 500;

#[derive(Clone, Debug)]
struct DreamObsidianTarget {
    vault: String,
    subdir: String,
}

/// Effect-bearing inputs pinned to one accepted `freedom.yaml` generation.
///
/// Cron reload validates a new `FreedomConfig` before constructing this value.
/// The pass, vault sync, forge and self-improve leaves consume only this
/// snapshot; none of them reread a possibly rejected on-disk rewrite.
#[derive(Clone, Debug)]
pub struct DreamPassConfig {
    window: Duration,
    max_events: usize,
    merge_cross_themes: bool,
    forge_skills: bool,
    autonomy: crate::permissions::AutonomyLevel,
    auto_distill: bool,
    obsidian_target: Option<DreamObsidianTarget>,
}

impl DreamPassConfig {
    pub fn from_config(
        config: &crate::config::FreedomConfig,
        window_override: Option<Duration>,
        max_events_override: Option<usize>,
    ) -> Result<Self> {
        let mut validated = config.dreaming.clone();
        if let Some(window) = window_override {
            validated.window_secs = Some(window.as_secs());
        }
        if let Some(max_events) = max_events_override {
            validated.max_events = Some(max_events);
        }
        validated
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid Dream pass config: {error}"))?;
        let obsidian_target = resolve_obsidian_target(
            config.obsidian_vault.clone(),
            config.obsidian_subdir.clone(),
        )
        .map(|(vault, subdir)| DreamObsidianTarget { vault, subdir });
        Ok(Self {
            window: window_override
                .or_else(|| config.dreaming.window_secs.map(Duration::from_secs))
                .unwrap_or(DEFAULT_WINDOW),
            max_events: max_events_override
                .or(config.dreaming.max_events)
                .unwrap_or(DEFAULT_MAX_EVENTS),
            merge_cross_themes: config.dreaming.merge_cross_themes,
            forge_skills: config.dreaming.forge_skills,
            autonomy: config.autonomy,
            auto_distill: config.skills.auto_distill,
            obsidian_target,
        })
    }
}

#[derive(Clone, Debug)]
pub struct DreamSchedule {
    at: chrono::NaiveTime,
    timezone: Tz,
}

impl DreamSchedule {
    pub fn from_config(config: &crate::config::FreedomConfig) -> Result<Self> {
        let at = config
            .dreaming
            .cron_time()
            .map_err(|error| anyhow::anyhow!("invalid dream.cron_at: {error}"))?;
        let timezone_name = config
            .dreaming
            .timezone
            .as_deref()
            .or(config.user_tz.as_deref())
            .unwrap_or("Etc/UTC");
        let timezone = timezone_name
            .parse::<Tz>()
            .with_context(|| format!("invalid Dream cron IANA timezone `{timezone_name}`"))?;
        Ok(Self { at, timezone })
    }

    fn boundary_for(&self, now: DateTime<Utc>) -> Result<(String, DateTime<Utc>)> {
        let local_date = now.with_timezone(&self.timezone).date_naive();
        let due = resolve_local_boundary(self.timezone, local_date, self.at)?;
        Ok((local_date.format("%Y-%m-%d").to_string(), due))
    }
}

/// Deterministic DST policy: the earlier UTC instant wins an ambiguous fold;
/// a nonexistent wall time advances minute-by-minute to the first valid instant
/// (bounded to the normal three-hour transition envelope).
fn resolve_local_boundary(
    timezone: Tz,
    date: NaiveDate,
    at: chrono::NaiveTime,
) -> Result<DateTime<Utc>> {
    let local = NaiveDateTime::new(date, at);
    for minute in 0..=180 {
        let candidate = local
            .checked_add_signed(chrono::Duration::minutes(minute))
            .context("Dream cron local boundary overflow")?;
        match timezone.from_local_datetime(&candidate) {
            LocalResult::Single(value) => return Ok(value.with_timezone(&Utc)),
            LocalResult::Ambiguous(first, second) => {
                return Ok(std::cmp::min(first, second).with_timezone(&Utc));
            }
            LocalResult::None => {}
        }
    }
    anyhow::bail!(
        "Dream cron local boundary {date} {at} in {timezone} has no valid instant within 180 minutes"
    )
}

/// Spawn the dreaming task. The fleet owner signals `effect_rail` cancellation
/// and joins this exact handle on reload/shutdown.
///
/// `schedule` is an accepted-generation calendar schedule; `pass_config`
/// carries the matching effect policy and resource bounds.
/// `embed_provider = None` → deterministic theme labels only
/// (composer still runs, dreams still land). `chat_provider = Some`
/// (SPEC-12 Phase 4b) → LLM-summarised cluster theme labels; `None`
/// keeps the deterministic `cluster-N-seed-id` labels. `writer = Some`
/// → the daemon owns the WAL writer and each non-empty pass emits a
/// `0xF4 DREAM_COMPOSED` audit frame (`None` for one-shot callers that
/// audit separately, e.g. `neoth dream now`).
pub(crate) fn spawn(
    home: PathBuf,
    embed_provider: Option<std::sync::Arc<dyn EmbedProvider>>,
    chat_provider: Option<std::sync::Arc<AuthorizedProvider>>,
    schedule: DreamSchedule,
    pass_config: DreamPassConfig,
    writer: Option<WalWriterHandle>,
    effect_rail: Arc<DreamEffectRail>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        run(
            home,
            embed_provider,
            chat_provider,
            schedule,
            pass_config,
            writer,
            effect_rail,
        )
        .await
    })
}

async fn run(
    home: PathBuf,
    embed_provider: Option<std::sync::Arc<dyn EmbedProvider>>,
    chat_provider: Option<std::sync::Arc<AuthorizedProvider>>,
    schedule: DreamSchedule,
    pass_config: DreamPassConfig,
    writer: Option<WalWriterHandle>,
    effect_rail: Arc<DreamEffectRail>,
) -> Result<()> {
    effect_rail.ensure_current("scheduler start")?;
    let mut generation = effect_rail.reload_controller.subscribe_generation();
    let now = crate::time::utc_now();
    let (boot_date, boot_due) = schedule.boundary_for(now)?;
    let mut pending_boot_skip = None;
    if now >= boot_due {
        let _lease = effect_rail.acquire_commit_lease(DreamCommitEffect::StateClaim)?;
        let persist = crate::cron::state::RuntimeState::modify(&home, |state| {
            state.skip_dream_boundary_on_start(&boot_date);
            Ok(())
        });
        match persist {
            Ok(()) => info!(
                local_date = %boot_date,
                "Dream cron startup found an already-passed boundary; catch-up skipped"
            ),
            Err(error) => {
                warn!(
                    error = %error,
                    local_date = %boot_date,
                    "Dream no-boot-catch-up boundary is not durable yet; effects remain blocked"
                );
                pending_boot_skip = Some(boot_date);
            }
        }
    }
    info!(
        cron_at = %schedule.at.format("%H:%M"),
        timezone = %schedule.timezone,
        window_secs = pass_config.window.as_secs(),
        max_events = pass_config.max_events,
        embed_enabled = embed_provider.is_some(),
        summarize_themes = chat_provider.is_some(),
        "dreaming task started"
    );
    let mut ticker = tokio::time::interval(DREAM_CRON_POLL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = effect_rail.cancellation.cancelled() => return Ok(()),
            _ = generation.changed() => return Ok(()),
            _ = ticker.tick() => {}
        }
        let now = crate::time::utc_now();
        let (local_date, due) = match schedule.boundary_for(now) {
            Ok(boundary) => boundary,
            Err(error) => {
                warn!(error = %error, "Dream calendar boundary resolution failed; retrying");
                continue;
            }
        };
        if let Some(mut skipped_date) = pending_boot_skip.take() {
            if now >= due && local_date > skipped_date {
                skipped_date = local_date.clone();
            }
            let _lease = effect_rail.acquire_commit_lease(DreamCommitEffect::StateClaim)?;
            match crate::cron::state::RuntimeState::modify(&home, |state| {
                state.skip_dream_boundary_on_start(&skipped_date);
                Ok(())
            }) {
                Ok(()) => info!(
                    local_date = %skipped_date,
                    "Dream no-boot-catch-up boundary became durable; scheduler resumed"
                ),
                Err(error) => {
                    warn!(
                        error = %error,
                        local_date = %skipped_date,
                        "Dream no-boot-catch-up persistence still unavailable; effects remain blocked"
                    );
                    pending_boot_skip = Some(skipped_date);
                }
            }
            continue;
        }
        if now < due {
            continue;
        }
        let _lease = effect_rail.acquire_commit_lease(DreamCommitEffect::StateClaim)?;
        let claimed = match crate::cron::state::RuntimeState::modify(&home, |state| {
            Ok(state.claim_dream_boundary(&local_date))
        }) {
            Ok(claimed) => claimed,
            Err(error) => {
                warn!(
                    error = %error,
                    local_date = %local_date,
                    "Dream boundary claim is not durable; effects blocked until the next poll"
                );
                continue;
            }
        };
        drop(_lease);
        if !claimed {
            continue;
        }
        effect_rail.ensure_current("scheduled pass dispatch")?;
        let pass = run_one_pass_for_day(
            &home,
            embed_provider.as_deref(),
            chat_provider.as_deref(),
            &pass_config,
            writer.as_ref(),
            &local_date,
            Some(effect_rail.as_ref()),
        );
        tokio::pin!(pass);
        let pass_result = tokio::select! {
            result = &mut pass => result,
            _ = effect_rail.cancellation.cancelled() => return Ok(()),
            _ = generation.changed() => return Ok(()),
        };
        match pass_result {
            Ok(report) => {
                if report.dreams_written > 0 {
                    info!(
                        events = report.events_considered,
                        dreams = report.dreams_written,
                        path = %report.path.display(),
                        "dreaming task wrote dream batch",
                    );
                    // OBSIDIAN-DREAMING-01 — push the just-composed day into the
                    // operator's vault so the Dreams folder stays fresh without a
                    // manual sync. Gate: a configured `obsidian_vault` IS the
                    // operator's vault opt-in. Dreams land only as bounded
                    // markdown under `<vault>/<subdir>/Dreams/` — they never
                    // re-enter recall/groundtruth, so no preload poisoning.
                    // The dream batch is already durable, so a vault failure
                    // cannot roll it back; surface it explicitly and retry on
                    // the next scheduled pass instead of silently treating policy/config
                    // corruption as "no vault configured".
                    if let Err(error) = sync_day_to_obsidian(
                        &home,
                        &report,
                        pass_config.obsidian_target.as_ref(),
                        Some(effect_rail.as_ref()),
                    )
                    .await
                    {
                        warn!(
                            error = %error,
                            "dream→Obsidian sync failed (dreams still persisted locally)"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    local_date = %local_date,
                    "dreaming pass failed after its durable boundary claim; not retrying automatically"
                );
            }
        }
        // Slice C — nightly auto self-improve. In full-auto mode (or when the
        // operator explicitly enabled `auto`) stage a SkillOpt proposal so
        // improvements accrue without a manual `neoth self-improve run`. NEVER
        // auto-accepts: the review-then-adopt gate still requires an explicit
        // `accept`. Daemon-cron only — `neoth dream now` calls run_one_pass
        // directly and never triggers this. Best-effort: any miss logs + skips.
        self_improve_auto_pass(&home, pass_config.autonomy, effect_rail.as_ref()).await;
        // GOLD-ADAPT-KB-03 — Slice D: nightly distill scan (skills.auto_distill).
        // Reads trajectory JSONL under `~/trajectories/` and logs repeated
        // tool-call sequences via tracing. Daemon-cron only. Best-effort.
        if pass_config.auto_distill {
            effect_rail.ensure_current("automatic distill scan")?;
            distill_auto_pass(&home).await;
        }
    }
}

/// GOLD-ADAPT-KB-03 — nightly background distill scan. Runs the same n-gram
/// scan as `neoth distill` but emits via `tracing::info` (no stdout) so it is
/// safe in the daemon loop. Best-effort: returns silently on any miss.
async fn distill_auto_pass(home: &std::path::Path) {
    let traj_dir = home.join("trajectories");
    let records = crate::cli::distill::read_trajectories(&traj_dir);
    if records.is_empty() {
        return;
    }
    let patterns = crate::cli::distill::find_repeated_sequences(&records, 3, 2);
    if patterns.is_empty() {
        return;
    }
    tracing::info!(
        pattern_count = patterns.len(),
        top_sequence = %patterns[0].sequence.join(" -> "),
        top_occurrences = patterns[0].occurrences,
        "distill: repeated tool-call sequences found -- consider `neoth distill`",
    );
}

#[cfg(test)]
mod distill_auto_pass_tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn distill_auto_pass_is_noop_on_missing_trajectories_dir() {
        // No trajectories dir under the temp home → must return without panic.
        let dir = TempDir::new().unwrap();
        distill_auto_pass(dir.path()).await;
    }
}

/// Resolve the vault opt-in: a non-blank `obsidian_vault` gates the sync;
/// `obsidian_subdir` falls back to the default. Returns `None` when no vault
/// is configured (the operator has not opted into a vault) OR when the subdir
/// fails the path-traversal guard.
fn resolve_obsidian_target(
    vault: Option<String>,
    subdir: Option<String>,
) -> Option<(String, String)> {
    let vault = vault.filter(|v| !v.trim().is_empty())?;
    let subdir = subdir
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "NEOTH-sessions".to_string());
    // P2 guard: reuse the same validate_subdir() used by the normal Obsidian sync
    // path (cli::obsidian). Rejects `..` traversal, absolute paths, null bytes,
    // colons, backslashes, and multi-component values. Fail-closed: never write
    // outside the vault — log the bad value and return None (no panic, no sync).
    if let Err(e) = crate::cli::obsidian::validate_subdir(std::path::Path::new(&subdir)) {
        warn!(
            subdir = %subdir,
            error = %e,
            "dreaming: obsidian_subdir rejected by path-traversal guard; skipping vault sync"
        );
        return None;
    }
    Some((vault, subdir))
}

/// OBSIDIAN-DREAMING-01 — push the day a dream batch just landed in into the
/// operator's Obsidian vault. No-op when no `obsidian_vault` is configured.
/// The day is taken from the pass report's JSONL filename stem so the exact
/// composed day is synced (never a midnight-rollover mismatch). Runs the
/// blocking file write off the async runtime. The target belongs to the same
/// accepted config generation as the pass; rejected disk rewrites cannot
/// redirect this effect.
async fn sync_day_to_obsidian(
    home: &Path,
    report: &PassReport,
    target: Option<&DreamObsidianTarget>,
    effect_rail: Option<&DreamEffectRail>,
) -> Result<()> {
    let Some(target) = target else {
        return Ok(()); // vault not configured → operator has not opted into a vault
    };
    let vault = target.vault.clone();
    let subdir = target.subdir.clone();
    let Some(day) = report
        .path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_string)
    else {
        return Ok(());
    };
    let home = home.to_path_buf();
    let effect_rail = effect_rail.cloned();
    let outcome = tokio::task::spawn_blocking(move || {
        let _lease = effect_rail
            .as_ref()
            .map(|rail| rail.acquire_commit_lease(DreamCommitEffect::ObsidianSync))
            .transpose()?;
        crate::daemon::dreaming::sync_dreams_to_obsidian(
            &home,
            std::path::Path::new(&vault),
            &subdir,
            &day,
        )
        .map_err(anyhow::Error::from)
    })
    .await??;
    if outcome.written {
        info!(
            day = %outcome.day,
            dreams = outcome.dream_count,
            path = %outcome.target_path.display(),
            "dreaming task synced day to Obsidian vault",
        );
    }
    Ok(())
}

/// Nightly auto self-improve pass (Slice C). Gated by the EFFECTIVE
/// self-improve switch (full-auto implies on, an explicit operator choice
/// wins) AND SkillOpt being installed. Stages one proposal for the default
/// persona's `skill.md`; the operator still must `neoth self-improve accept`
/// it. Runs the (blocking, possibly slow) engine off the async runtime.
async fn self_improve_auto_pass(
    home: &Path,
    autonomy: crate::permissions::AutonomyLevel,
    effect_rail: &DreamEffectRail,
) {
    let home = home.to_path_buf();
    let effect_rail = effect_rail.clone();
    match tokio::task::spawn_blocking(move || {
        self_improve_auto_pass_blocking(&home, autonomy, &effect_rail)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(error = %format!("{e:#}"), "self-improve auto-pass failed closed"),
        Err(e) => warn!(error = %e, "self-improve auto-pass task join failed"),
    }
}

/// Upper bound on the baseline `skill.md` read. The previous ambient
/// `read_to_string` was unbounded; the capability-bound read caps it so a
/// pathological installed file can never OOM the dreaming tick.
const MAX_BASELINE_SKILL_BYTES: usize = 16 * 1024 * 1024;

/// GOLD-R3-11 — read the installed baseline skill body through the
/// capability-bound store instead of an ambient `read_to_string`.
///
/// Opens the skills root as a bound directory and takes the cross-process skill
/// mutation lock so the read cannot observe a torn mid-replacement generation,
/// then reads `<persona>/skill.md` through handle-relative, no-follow,
/// size-bounded primitives. An absent skills root, persona directory, or
/// `skill.md` all yield an empty baseline (the same "no baseline yet" contract
/// as the previous NotFound arm); any other error propagates. The lock guard is
/// released when this function returns, before the SkillOpt run.
fn read_installed_baseline(skills_dir: &Path, persona: &str) -> Result<String> {
    let Some(root) = crate::skills::store::open_bound_directory(skills_dir, false, "skills root")?
    else {
        return Ok(String::new());
    };
    let _guard = crate::skills::installer::lock_skill_mutations(&root)
        .context("lock skill store for a consistent baseline read")?;
    let persona_path = root.display_path.join(persona);
    let persona_dir = match crate::skills::store::open_real_child_dir(
        &root.dir,
        OsStr::new(persona),
        &persona_path,
    ) {
        Ok(dir) => dir,
        Err(error) if baseline_error_is_not_found(&error) => return Ok(String::new()),
        Err(error) => return Err(error),
    };
    let skill_md_path = persona_path.join("skill.md");
    match crate::skills::store::read_regular_file_bounded(
        &persona_dir,
        OsStr::new("skill.md"),
        &skill_md_path,
        MAX_BASELINE_SKILL_BYTES,
    ) {
        // GOLD-R3-11: a generation-bound ground-truth baseline must fail VISIBLY
        // on corruption rather than silently pass replacement characters through
        // `from_utf8_lossy`. Invalid UTF-8 propagates as an error into the
        // best-effort dreaming tick, which logs and skips the pass — "broken
        // visible" instead of "broken repaired". The error carries only the path,
        // never the raw bytes.
        Ok(bytes) => String::from_utf8(bytes).with_context(|| {
            format!(
                "installed baseline {} is not valid UTF-8",
                skill_md_path.display()
            )
        }),
        Err(error) if baseline_error_is_not_found(&error) => Ok(String::new()),
        Err(error) => Err(error),
    }
}

/// Downcast an anyhow chain to an io `NotFound` (mirrors `skills::loader`).
fn baseline_error_is_not_found(error: &anyhow::Error) -> bool {
    error
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
}

fn self_improve_auto_pass_blocking(
    home: &Path,
    autonomy: crate::permissions::AutonomyLevel,
    effect_rail: &DreamEffectRail,
) -> Result<()> {
    use crate::self_improve as si;
    effect_rail.ensure_current("self-improve scan")?;
    // B19: fail-closed — corrupt config stops this tick rather than defaulting
    // to auto-on and re-enabling a deliberately-disabled master switch.
    let cfg = match si::SelfImproveConfig::load_strict(home) {
        Ok(opt) => si::effective_from_option(opt, autonomy),
        Err(e) => return Err(e).context("self-improve auto-pass: config is corrupt"),
    };
    if !cfg.auto || !si::is_installed() {
        return Ok(()); // not in auto mode, or engine absent → nothing to do
    }
    let persona = "default";
    // Don't pile up: if a proposal for this persona is already awaiting review,
    // skip this tick (and skip spawning the engine entirely).
    if si::load_proposals(home)?
        .iter()
        .any(|p| p.skill == persona && p.status == si::ProposalStatus::Pending)
    {
        return Ok(());
    }
    let skills_dir = crate::skills::installer::default_skills_dir();
    let skill_path = skills_dir.join(persona).join("skill.md");
    // GOLD-R3-11: read the installed baseline THROUGH the capability-bound store
    // under the skill mutation lock, not with an ambient `read_to_string` that
    // follows symlinks, ignores the store lock and reads unbounded bytes.
    let before = read_installed_baseline(&skills_dir, persona)
        .with_context(|| format!("read baseline skill {}", skill_path.display()))?;
    // F13 — bounded run: a hung/runaway SkillOpt python process must not block
    // the dreaming tick (best-effort "any miss logs + skips" contract).
    let (after, quality, parsed_spec) = match si::run_skillopt_capped(persona, si::SKILLOPT_TIMEOUT)
    {
        Ok(o) => si::parse_proposal_output(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => return Err(e).context("self-improve auto-pass: SkillOpt run failed/timed out"),
    };
    if after.trim().is_empty() || after == before {
        return Ok(()); // engine proposed nothing new → don't stage a no-op
    }
    // The SkillOpt process can run for minutes. Acquire immediately before the
    // durable mutation and retain the lease through stage_proposal's return.
    let _lease = effect_rail.acquire_commit_lease(DreamCommitEffect::SelfImproveProposal)?;
    let now = crate::time::now_unix_i64();
    let id = format!("p{now}");
    let staged_id = si::stage_proposal(
        home,
        si::Proposal {
            id: id.clone(),
            skill: persona.to_string(),
            skill_path: skill_path.display().to_string(),
            before,
            after,
            summary: format!("nightly SkillOpt proposal for {persona}"),
            status: si::ProposalStatus::Pending,
            at_unix: now,
            backup: None,
            score_before: quality.score_before,
            score_after: quality.score_after,
            heldout_eval_summary: quality.heldout_eval_summary,
            why_this_improves: quality.why_this_improves,
            risk_notes: quality.risk_notes,
            spec: parsed_spec, // IMPR-01: carry parsed spec; drift_sha added inside stage_proposal
        },
    )?;
    info!(proposal = %staged_id, "self-improve auto-pass staged a proposal for review");
    Ok(())
}

/// One pass result — operator-visible counters + the file path the
/// dreams landed in. Returned from [`run_one_pass`] so the operator
/// `neoth dream now` CLI surface (future) can render the same shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassReport {
    /// Number of `idx_episode` rows considered in the window.
    pub events_considered: usize,
    /// Number of Dream records appended to the pass calendar day's JSONL.
    pub dreams_written: usize,
    /// JSONL file that received the appends (`~/.neoth/dreams/YYYY-MM-DD.jsonl`).
    pub path: PathBuf,
    /// Path that was taken: `embedding` (compose_dreams_with_embeddings)
    /// or `deterministic` (single compose_dream).
    pub path_taken: DreamingPath,
}

impl PassReport {
    /// `YYYY-MM-DD` derived from the JSONL path stem (e.g.
    /// `~/.neoth/dreams/2026-06-03.jsonl` → `2026-06-03`). Empty when the
    /// path has no stem. Used by the `0xF4 DREAM_COMPOSED` audit payload +
    /// the operator render — single source so the daemon + CLI agree.
    pub(crate) fn day_label(&self) -> String {
        self.path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string()
    }
}

/// Build the `0xF4 DREAM_COMPOSED` audit payload from a pass report.
/// Shared by the daemon cron emit ([`run_one_pass`] when a writer is
/// passed) and the one-shot `neoth dream now` CLI emit so the two paths
/// never drift in payload shape (only the emit MECHANISM + provenance
/// flag differ: daemon = `writer.append` + SYNTHETIC; CLI = one-shot
/// writer, operator-triggered).
pub(crate) fn dream_composed_payload(report: &PassReport, ts_unix: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "day": report.day_label(),
        "dreams": report.dreams_written,
        "events_considered": report.events_considered,
        "path_taken": format!("{:?}", report.path_taken),
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

/// Daemon-side `0xF4 DREAM_COMPOSED` emit. Best-effort + SYNTHETIC (this
/// is a daemon-derived frame, matching the regression / recall-latency
/// cron convention). A WAL append failure logs + never fails the pass.
async fn emit_dream_composed_daemon(writer: &WalWriterHandle, report: &PassReport) {
    let ts_unix = crate::time::now_unix_secs();
    let payload = dream_composed_payload(report, ts_unix);
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_DREAM_COMPOSED, &payload)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "dreaming: DREAM_COMPOSED frame append failed (audit gap)");
    }
}

/// Which composer ran. Surfaces in the operator log so a sudden
/// flip from `embedding` → `deterministic` (e.g. local_qwen weights
/// went missing) is visible without grepping for "embed failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamingPath {
    Embedding,
    Deterministic,
}

/// Run one dreaming pass. Pure orchestrator — gathers events,
/// dispatches to embedding or deterministic compose, appends to
/// JSONL. Returns a [`PassReport`] for operator surface use.
///
/// `embed_provider = None` OR provider fails → deterministic
/// fallback (matches the L-07 `allow_cloud_fallback: false` safe-
/// default pattern: never silently spend cloud tokens, never crash
/// the dreaming pipeline either).
pub async fn run_one_pass(
    home: &Path,
    embed_provider: Option<&dyn EmbedProvider>,
    chat_provider: Option<&AuthorizedProvider>,
    pass_config: &DreamPassConfig,
    writer: Option<&WalWriterHandle>,
) -> Result<PassReport> {
    let day = today_utc_date();
    run_one_pass_for_day(
        home,
        embed_provider,
        chat_provider,
        pass_config,
        writer,
        &day,
        None,
    )
    .await
}

/// Scheduled-pass implementation bound to the exact claimed calendar date.
///
/// The public one-shot wrapper above intentionally supplies UTC today. Cron
/// supplies its claimed local date, so JSONL paths, Dream bodies, Obsidian sync
/// and DREAM_COMPOSED all share one date even at UTC+14/-10 boundaries.
async fn run_one_pass_for_day(
    home: &Path,
    embed_provider: Option<&dyn EmbedProvider>,
    chat_provider: Option<&AuthorizedProvider>,
    pass_config: &DreamPassConfig,
    writer: Option<&WalWriterHandle>,
    day: &str,
    effect_rail: Option<&DreamEffectRail>,
) -> Result<PassReport> {
    let events = gather_window_events(home, pass_config.window, pass_config.max_events)?;
    let path = crate::daemon::dreaming::jsonl_file_for_day(home, day);

    if events.is_empty() {
        return Ok(PassReport {
            events_considered: 0,
            dreams_written: 0,
            path,
            path_taken: DreamingPath::Deterministic,
        });
    }

    let (dreams, path_taken) = if let Some(provider) = embed_provider {
        let _lease = effect_rail
            .map(|rail| rail.acquire_commit_lease(DreamCommitEffect::ProviderDispatch))
            .transpose()?;
        match compose_dreams_with_embeddings(
            day,
            &events,
            provider,
            chat_provider,
            DREAMING_CLUSTER_THRESHOLD,
            pass_config.merge_cross_themes,
        )
        .await
        {
            Ok(d) => (d, DreamingPath::Embedding),
            Err(e) => {
                warn!(error = %e, "embedding compose failed; falling back to deterministic theme");
                (
                    vec![compose_dream(day, "daily-deterministic", &events)],
                    DreamingPath::Deterministic,
                )
            }
        }
    } else {
        (
            vec![compose_dream(day, "daily-deterministic", &events)],
            DreamingPath::Deterministic,
        )
    };

    let mut written = 0;
    for dream in &dreams {
        let _lease = effect_rail
            .map(|rail| rail.acquire_commit_lease(DreamCommitEffect::JsonlAppend))
            .transpose()?;
        match append_dream(home, dream) {
            Ok(_) => written += 1,
            Err(e) => {
                warn!(error = %e, "append_dream failed; skipping this dream entry");
            }
        }
    }
    // KF-04 — idle-time skill forge: gated, best-effort. Synthesise a
    // candidate skill from each composed dream + stage it for operator
    // review (OB-03 queue). NEOTH never writes the skill; the operator
    // adopts it via `neoth proactive accept`. A forge/queue miss never
    // fails the pass — the dreams are already persisted above.
    if pass_config.forge_skills {
        forge_and_stage_dreams(home, &dreams, effect_rail)?;
    }

    let report = PassReport {
        events_considered: events.len(),
        dreams_written: written,
        path,
        path_taken,
    };

    // SPEC-12 daemon-side audit: when the daemon owns the WAL writer and
    // this pass actually wrote dreams, emit a `0xF4 DREAM_COMPOSED` frame so
    // the nightly cron is auditable just like `neoth dream now`. One-shot
    // callers pass `writer = None` and audit via their own path.
    if report.dreams_written > 0
        && let Some(w) = writer
    {
        let _lease = effect_rail
            .map(|rail| rail.acquire_commit_lease(DreamCommitEffect::WalAppend))
            .transpose()?;
        emit_dream_composed_daemon(w, &report).await;
    }

    Ok(report)
}

/// KF-04 — forge a candidate skill from each dream + stage it as an
/// OB-03 proposal for operator review. Best-effort: a queue-IO error or
/// an un-forgeable dream is logged + skipped, never fails the dreaming
/// pass. Dedup is handled by `stage_and_enqueue` (same dream → same
/// proposal id → enqueued at most once).
///
/// Uses `ProactiveQueue::modify` (locked load→mutate→save) so this site
/// cannot race the delivery tick's reconcile and accidentally resurrect
/// delivered items via a blind bare-load/save cycle — the same pattern
/// required by the G02-QUEUE-01 sweep.
fn forge_and_stage_dreams(
    home: &Path,
    dreams: &[crate::daemon::dreaming::Dream],
    effect_rail: Option<&DreamEffectRail>,
) -> Result<()> {
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::stage_and_enqueue;
    let queue_path = home.join("proactive_queue.json");

    // Build proposals outside the lock (pure CPU, no I/O) so the lock
    // window stays tight.
    let proposals: Vec<_> = dreams
        .iter()
        .filter_map(crate::daemon::skill_forge::build_skill_proposal_from_dream)
        .collect();

    if proposals.is_empty() {
        return Ok(());
    }

    let _lease = effect_rail
        .map(|rail| rail.acquire_commit_lease(DreamCommitEffect::ProposalQueue))
        .transpose()?;
    let modify_result = ProactiveQueue::modify(&queue_path, |queue| {
        let mut staged = 0usize;
        for proposal in proposals {
            match stage_and_enqueue(home, proposal, queue) {
                Ok((_, true)) => staged += 1,
                Ok((_, false)) => {} // already queued (dedup)
                Err(e) => warn!(error = %e, "skill-forge: stage failed"),
            }
        }
        // Persist only when at least one new proposal was staged.
        let dirty = staged > 0;
        (dirty, staged)
    });

    match modify_result {
        Ok(staged) if staged > 0 => {
            tracing::info!(staged, "skill-forge: staged candidate skill(s) for review");
        }
        Ok(_) => {} // nothing new staged (all dedup)
        Err(e) => warn!(error = %e, "skill-forge: queue load/save failed"),
    }
    Ok(())
}

/// Load `idx_episode` rows whose `ts_ns` is within `window` of
/// `now`. Truncates at `max_events` (oldest-first selection so the
/// dream covers the start of the window — operators inspecting the
/// dream get a coherent narrative, not a random subset). Missing
/// `views.db` → empty Vec (fresh-install daemon hasn't indexed
/// anything yet).
fn gather_window_events(home: &Path, window: Duration, max_events: usize) -> Result<Vec<EventRef>> {
    let db_path = home.join("views.db");
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open(&db_path)?;
    let now_ns: i64 = (crate::time::now_unix_ns_u128()) as i64;
    let window_ns = window.as_nanos() as i64;
    let cutoff_ns = now_ns - window_ns;
    let mut stmt = conn.prepare(
        "SELECT event_id, ts_ns, text FROM idx_episode \
         WHERE ts_ns >= ?1 ORDER BY ts_ns ASC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![cutoff_ns, max_events as i64], |row| {
        let id: i64 = row.get(0)?;
        let ts_ns: i64 = row.get(1)?;
        let text: String = row.get(2)?;
        Ok((id, ts_ns, text))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (id, ts_ns, text) = r?;
        out.push(EventRef {
            id,
            ts_unix: ts_ns / 1_000_000_000,
            preview: text,
        });
    }
    Ok(out)
}

/// Return today's UTC date (`YYYY-MM-DD`). Same Howard-Hinnant
/// civil-from-days conversion used elsewhere in the codebase.
fn today_utc_date() -> String {
    let ts_unix = crate::time::now_unix_i64();
    let days = ts_unix.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;
    use tempfile::tempdir;

    #[test]
    fn dream_schedule_resolves_dst_gap_and_fold_deterministically() {
        let berlin: Tz = "Europe/Berlin".parse().unwrap();
        let at = chrono::NaiveTime::from_hms_opt(2, 30, 0).unwrap();

        let gap = resolve_local_boundary(berlin, NaiveDate::from_ymd_opt(2026, 3, 29).unwrap(), at)
            .unwrap();
        assert_eq!(gap.to_rfc3339(), "2026-03-29T01:00:00+00:00");

        let fold =
            resolve_local_boundary(berlin, NaiveDate::from_ymd_opt(2026, 10, 25).unwrap(), at)
                .unwrap();
        assert_eq!(
            fold.to_rfc3339(),
            "2026-10-25T00:30:00+00:00",
            "ambiguous folds use the earlier UTC instant"
        );
    }

    #[test]
    fn dream_schedule_uses_user_timezone_only_when_dream_timezone_is_absent() {
        let mut config = crate::config::FreedomConfig::default();
        config.user_tz = Some("America/New_York".to_string());
        assert_eq!(
            DreamSchedule::from_config(&config).unwrap().timezone,
            "America/New_York".parse::<Tz>().unwrap()
        );
        config.dreaming.timezone = Some("Europe/Berlin".to_string());
        assert_eq!(
            DreamSchedule::from_config(&config).unwrap().timezone,
            "Europe/Berlin".parse::<Tz>().unwrap()
        );
    }

    #[test]
    fn dream_schedule_keeps_utc_plus_14_and_minus_10_calendar_dates_distinct() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 9, 30, 0).single().unwrap();
        let at = chrono::NaiveTime::from_hms_opt(3, 0, 0).unwrap();
        let plus_14 = DreamSchedule {
            at,
            timezone: "Pacific/Kiritimati".parse().unwrap(),
        };
        let minus_10 = DreamSchedule {
            at,
            timezone: "Pacific/Honolulu".parse().unwrap(),
        };

        assert_eq!(plus_14.boundary_for(now).unwrap().0, "2026-01-01");
        assert_eq!(
            minus_10.boundary_for(now).unwrap().0,
            "2025-12-31",
            "the scheduler must claim the operator's local date, not UTC today"
        );

        let after_dateline = Utc
            .with_ymd_and_hms(2026, 1, 1, 10, 30, 0)
            .single()
            .unwrap();
        assert_eq!(
            plus_14.boundary_for(after_dateline).unwrap().0,
            "2026-01-02"
        );
        assert_eq!(
            minus_10.boundary_for(after_dateline).unwrap().0,
            "2026-01-01"
        );
    }

    #[test]
    fn effect_rail_rejects_cancelled_and_superseded_generations() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("freedom.yaml");
        let mut config = crate::config::FreedomConfig::default();
        config.dreaming.enabled = true;
        config.autonomy = crate::permissions::AutonomyLevel::Standard;
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config.clone(),
            config_path.clone(),
        ));

        let cancellation = DreamCancellation::new();
        let rail = DreamEffectRail::new(
            Arc::clone(&controller),
            controller.accepted_snapshot(),
            Arc::clone(&cancellation),
        );
        rail.ensure_current("test commit").unwrap();

        let mut replacement = config;
        replacement.review_gate_enabled = !replacement.review_gate_enabled;
        std::fs::write(&config_path, serde_yaml::to_string(&replacement).unwrap()).unwrap();
        assert!(matches!(
            controller.try_reload().unwrap(),
            crate::config::reload::ReloadResult::Reloaded { .. }
        ));
        assert!(
            format!("{:#}", rail.ensure_current("test commit").unwrap_err()).contains("superseded")
        );

        let cancelled_rail = DreamEffectRail::new(
            Arc::clone(&controller),
            controller.accepted_snapshot(),
            Arc::clone(&cancellation),
        );
        cancellation.cancel();
        assert!(
            format!(
                "{:#}",
                cancelled_rail.ensure_current("test commit").unwrap_err()
            )
            .contains("cancellation")
        );
    }

    #[test]
    fn every_irreversible_effect_is_linearized_against_retirement() {
        use std::sync::mpsc;

        for effect in DreamCommitEffect::ALL {
            let dir = tempdir().unwrap();
            let config_path = dir.path().join("freedom.yaml");
            let mut config = crate::config::FreedomConfig::default();
            config.dreaming.enabled = true;
            config.autonomy = crate::permissions::AutonomyLevel::Standard;
            std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
            let controller = Arc::new(crate::config::reload::ReloadController::new(
                config,
                config_path,
            ));
            let rail = Arc::new(DreamEffectRail::new(
                Arc::clone(&controller),
                controller.accepted_snapshot(),
                DreamCancellation::new(),
            ));

            let (lease_acquired_tx, lease_acquired_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let worker_rail = Arc::clone(&rail);
            let worker = std::thread::spawn(move || {
                let lease = worker_rail
                    .acquire_commit_lease(effect)
                    .expect("effect lease must enter before retirement");
                lease_acquired_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                drop(lease);
            });
            lease_acquired_rx.recv().unwrap();

            let (retire_started_tx, retire_started_rx) = mpsc::channel();
            let (retired_tx, retired_rx) = mpsc::channel();
            let retire_rail = Arc::clone(&rail);
            let retire = std::thread::spawn(move || {
                retire_started_tx.send(()).unwrap();
                retire_rail.retire_generation_and_wait();
                retired_tx.send(()).unwrap();
            });
            retire_started_rx.recv().unwrap();

            // Wait until the retirement thread has actually closed the gate.
            // This avoids a timing-based assertion that could pass merely
            // because the retirement thread had not been scheduled yet.
            while let Ok(probe) = rail.acquire_commit_lease(effect) {
                drop(probe);
                std::thread::yield_now();
            }
            assert!(
                matches!(retired_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
                "{} retirement returned while its true commit was active",
                effect.label()
            );
            release_tx.send(()).unwrap();
            retired_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("retirement did not drain after commit release");
            worker.join().unwrap();
            retire.join().unwrap();

            let error = rail.acquire_commit_lease(effect).unwrap_err();
            assert!(
                format!("{error:#}").contains("retired"),
                "{} accepted a new lease after retirement: {error:#}",
                effect.label()
            );
        }
    }

    #[test]
    fn read_installed_baseline_reads_through_capability_bound_store() {
        let dir = tempdir().unwrap();
        let skills = dir.path().join("skills");
        std::fs::create_dir_all(skills.join("default")).unwrap();
        std::fs::write(skills.join("default").join("skill.md"), b"BASELINE BODY").unwrap();
        assert_eq!(
            read_installed_baseline(&skills, "default").unwrap(),
            "BASELINE BODY"
        );
    }

    #[test]
    fn read_installed_baseline_rejects_invalid_utf8() {
        // GOLD-R3-11: a corrupt (non-UTF-8) baseline must escalate visibly, not
        // be silently repaired with replacement characters.
        let dir = tempdir().unwrap();
        let skills = dir.path().join("skills");
        std::fs::create_dir_all(skills.join("default")).unwrap();
        std::fs::write(skills.join("default").join("skill.md"), [0xff, 0xfe, 0x00]).unwrap();
        let err = read_installed_baseline(&skills, "default").unwrap_err();
        assert!(
            format!("{err:#}").contains("not valid UTF-8"),
            "expected a visible UTF-8 escalation, got: {err:#}"
        );
    }

    #[test]
    fn read_installed_baseline_absent_paths_yield_empty() {
        let dir = tempdir().unwrap();
        let skills = dir.path().join("skills");
        // 1) skills root absent entirely.
        assert_eq!(read_installed_baseline(&skills, "default").unwrap(), "");
        // 2) skills root present, persona directory absent.
        std::fs::create_dir_all(&skills).unwrap();
        assert_eq!(read_installed_baseline(&skills, "default").unwrap(), "");
        // 3) persona directory present, skill.md absent.
        std::fs::create_dir_all(skills.join("default")).unwrap();
        assert_eq!(read_installed_baseline(&skills, "default").unwrap(), "");
    }

    fn seed_views_db(home: &Path, rows: &[(i64, i64, &str)]) {
        let db = Connection::open(home.join("views.db")).unwrap();
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS idx_episode ( \
                event_id INTEGER PRIMARY KEY, \
                ts_ns INTEGER NOT NULL, \
                text TEXT NOT NULL, \
                text_hash BLOB, \
                importance REAL DEFAULT 1.0)",
        )
        .unwrap();
        let mut stmt = db
            .prepare("INSERT INTO idx_episode (event_id, ts_ns, text) VALUES (?1, ?2, ?3)")
            .unwrap();
        for (id, ts_ns, text) in rows {
            stmt.execute(rusqlite::params![id, ts_ns, text]).unwrap();
        }
    }

    fn now_ns() -> i64 {
        crate::time::now_unix_ns_i64()
    }

    fn test_pass_config(window: Duration, max_events: usize) -> DreamPassConfig {
        DreamPassConfig::from_config(
            &crate::config::FreedomConfig::default(),
            Some(window),
            Some(max_events),
        )
        .unwrap()
    }

    struct AlwaysWeatherEmbed;

    #[async_trait::async_trait]
    impl EmbedProvider for AlwaysWeatherEmbed {
        fn name(&self) -> &'static str {
            "always_weather"
        }
        fn default_dim(&self) -> usize {
            4
        }
        async fn embed(
            &self,
            _req: crate::providers::embed::EmbedRequest,
        ) -> Result<crate::providers::embed::EmbedResponse> {
            // All texts land in slot 0 → cosine = 1.0 between any
            // pair → single cluster.
            let mut v = vec![0.0f32; 4];
            v[0] = 1.0;
            Ok(crate::providers::embed::EmbedResponse {
                vector: v,
                model: "always_weather".into(),
                latency: Duration::from_micros(1),
            })
        }
    }

    struct FailingEmbed;

    #[async_trait::async_trait]
    impl EmbedProvider for FailingEmbed {
        fn name(&self) -> &'static str {
            "failing"
        }
        fn default_dim(&self) -> usize {
            4
        }
        async fn embed(
            &self,
            _req: crate::providers::embed::EmbedRequest,
        ) -> Result<crate::providers::embed::EmbedResponse> {
            anyhow::bail!("provider down")
        }
    }

    #[tokio::test]
    async fn one_pass_returns_empty_report_for_missing_views_db() {
        let dir = tempdir().unwrap();
        let report = run_one_pass(
            dir.path(),
            None,
            None,
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.events_considered, 0);
        assert_eq!(report.dreams_written, 0);
        assert_eq!(report.path_taken, DreamingPath::Deterministic);
    }

    #[tokio::test]
    async fn one_pass_writes_deterministic_dream_when_no_provider() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[
                (1, n - 3600 * 1_000_000_000, "first event"),
                (2, n - 1800 * 1_000_000_000, "second event"),
            ],
        );
        let report = run_one_pass(
            dir.path(),
            None,
            None,
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.events_considered, 2);
        assert_eq!(report.dreams_written, 1);
        assert_eq!(report.path_taken, DreamingPath::Deterministic);
        assert!(report.path.exists());
    }

    #[tokio::test]
    async fn scheduled_pass_binds_jsonl_dream_and_audit_day_to_claimed_local_date() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[(1, n - 60 * 1_000_000_000, "dateline-bound event")],
        );
        let claimed_local_date = "2042-12-31";
        let report = run_one_pass_for_day(
            dir.path(),
            None,
            None,
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            None,
            claimed_local_date,
            None,
        )
        .await
        .unwrap();

        assert_eq!(report.day_label(), claimed_local_date);
        assert_eq!(
            report.path.file_name().and_then(|name| name.to_str()),
            Some("2042-12-31.jsonl")
        );
        let jsonl = std::fs::read_to_string(&report.path).unwrap();
        assert!(
            jsonl.contains("\"day\":\"2042-12-31\""),
            "the persisted Dream body must use the claimed local date: {jsonl}"
        );
        let payload: serde_json::Value =
            serde_json::from_slice(&dream_composed_payload(&report, 7)).unwrap();
        assert_eq!(payload["day"], claimed_local_date);
    }

    #[tokio::test]
    async fn one_pass_uses_embedding_path_when_provider_available() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[
                (1, n - 3600 * 1_000_000_000, "first event"),
                (2, n - 1800 * 1_000_000_000, "second event"),
                (3, n - 900 * 1_000_000_000, "third event"),
            ],
        );
        let provider = AlwaysWeatherEmbed;
        let report = run_one_pass(
            dir.path(),
            Some(&provider),
            None,
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.events_considered, 3);
        // AlwaysWeather collapses everything to one cluster → 1 dream.
        assert_eq!(report.dreams_written, 1);
        assert_eq!(report.path_taken, DreamingPath::Embedding);
    }

    #[tokio::test]
    async fn one_pass_falls_back_to_deterministic_when_embed_fails() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(dir.path(), &[(1, n - 3600 * 1_000_000_000, "first event")]);
        let provider = FailingEmbed;
        let report = run_one_pass(
            dir.path(),
            Some(&provider),
            None,
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.events_considered, 1);
        assert_eq!(report.dreams_written, 1);
        assert_eq!(
            report.path_taken,
            DreamingPath::Deterministic,
            "provider error must trigger deterministic fallback, never crash"
        );
    }

    #[tokio::test]
    async fn one_pass_respects_max_events_truncation() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        let rows: Vec<_> = (1i64..=10)
            .map(|i| (i, n - i * 1_000_000_000, "event"))
            .collect();
        let rows_ref: Vec<_> = rows.iter().map(|(a, b, c)| (*a, *b, *c)).collect();
        seed_views_db(dir.path(), &rows_ref);
        let report = run_one_pass(
            dir.path(),
            None,
            None,
            &test_pass_config(DEFAULT_WINDOW, 3),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.events_considered, 3, "truncate at max_events=3");
    }

    #[tokio::test]
    async fn one_pass_ignores_events_outside_window() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        // One event inside the 1-hour test window, one outside.
        seed_views_db(
            dir.path(),
            &[
                (1, n - 60 * 1_000_000_000, "inside"), // 60s ago
                (2, n - 3600 * 1_000_000_000 * 24, "outside"),
            ], // 24h ago
        );
        let report = run_one_pass(
            dir.path(),
            None,
            None,
            &test_pass_config(Duration::from_secs(1800), DEFAULT_MAX_EVENTS),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            report.events_considered, 1,
            "window excludes the 24h-ago row"
        );
    }

    #[test]
    fn resolve_obsidian_target_gates_on_vault_and_defaults_subdir() {
        // No vault → None (operator has not opted in).
        assert!(resolve_obsidian_target(None, None).is_none());
        assert!(resolve_obsidian_target(Some("   ".into()), None).is_none());
        // Vault set, no subdir → default subdir.
        assert_eq!(
            resolve_obsidian_target(Some("/vault".into()), None),
            Some(("/vault".into(), "NEOTH-sessions".into()))
        );
        // Vault + blank subdir → default; explicit subdir honoured.
        assert_eq!(
            resolve_obsidian_target(Some("/vault".into()), Some("  ".into())),
            Some(("/vault".into(), "NEOTH-sessions".into()))
        );
        assert_eq!(
            resolve_obsidian_target(Some("/vault".into()), Some("Dreams-Custom".into())),
            Some(("/vault".into(), "Dreams-Custom".into()))
        );
    }

    #[test]
    fn resolve_obsidian_target_rejects_traversal_subdirs() {
        // Traversal inputs must be rejected fail-closed (no write outside vault).
        for bad in &["../../escape", "..", "/abs/path"] {
            assert!(
                resolve_obsidian_target(Some("/vault".into()), Some((*bad).into())).is_none(),
                "expected None for bad subdir {bad:?}"
            );
        }
        // Clean single-component names are still accepted.
        assert!(
            resolve_obsidian_target(Some("/vault".into()), Some("NEOTH-sessions".into())).is_some()
        );
        assert!(
            resolve_obsidian_target(Some("/vault".into()), Some("Dreams-Custom".into())).is_some()
        );
    }

    #[tokio::test]
    async fn today_utc_date_renders_yyyy_mm_dd() {
        let s = today_utc_date();
        assert_eq!(s.len(), 10);
        assert_eq!(s.chars().nth(4), Some('-'));
        assert_eq!(s.chars().nth(7), Some('-'));
        // First 4 chars parse as year.
        let _: u32 = s[..4].parse().unwrap();
    }

    #[tokio::test]
    async fn task_aborts_cleanly() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("freedom.yaml");
        let mut config = crate::config::FreedomConfig::default();
        config.dreaming.enabled = true;
        config.autonomy = crate::permissions::AutonomyLevel::Standard;
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config,
            config_path,
        ));
        let effect_rail = Arc::new(DreamEffectRail::new(
            Arc::clone(&controller),
            controller.accepted_snapshot(),
            DreamCancellation::new(),
        ));
        let task = spawn(
            dir.path().to_path_buf(),
            None,
            None,
            DreamSchedule::from_config(&crate::config::FreedomConfig::default()).unwrap(),
            DreamPassConfig {
                auto_distill: true,
                ..test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS)
            },
            None,
            effect_rail,
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        task.abort();
        let _ = task.await;
    }

    #[test]
    fn constants_pinned() {
        assert_eq!(DREAM_CRON_POLL.as_secs(), 30);
        assert_eq!(DEFAULT_WINDOW.as_secs(), 86_400);
        assert_eq!(DEFAULT_MAX_EVENTS, 500);
    }

    // ── SPEC-12 daemon-side 0xF4 DREAM_COMPOSED emit + chat-label wiring ──────

    /// Count `0xF4 DREAM_COMPOSED` frames in a sealed WAL segment.
    fn count_dream_composed_frames(seg: &Path) -> usize {
        let Ok(bytes) = std::fs::read(seg) else {
            return 0;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            return 0;
        };
        let mut cursor = hdr.header_len();
        let mut count = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_DREAM_COMPOSED {
                count += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        count
    }

    /// Chat provider returning a fixed reply — exercises the run_one_pass
    /// chat-label wiring end-to-end.
    struct FixedLabelChat;
    #[async_trait::async_trait]
    impl Provider for FixedLabelChat {
        fn name(&self) -> &'static str {
            "fixed_label_chat"
        }
        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                text: "weekend trip planning".into(),
                identity: Default::default(),
                model: "fixed_label_chat".into(),
                latency: Duration::from_micros(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn run_one_pass_emits_dream_composed_when_writer_present() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[(1, n - 1800 * 1_000_000_000, "an event in the window")],
        );
        let seg_dir = tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let report = run_one_pass(
            dir.path(),
            None,
            None,
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            Some(&writer),
        )
        .await
        .unwrap();
        assert_eq!(report.dreams_written, 1);

        drop(writer);
        join.await.ok();
        assert_eq!(
            count_dream_composed_frames(&seg),
            1,
            "a writer-backed pass that wrote dreams must emit exactly one 0xF4",
        );
    }

    #[tokio::test]
    async fn run_one_pass_no_frame_when_writer_none() {
        // The CLI one-shot path passes writer = None (it audits separately).
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(dir.path(), &[(1, n - 1800 * 1_000_000_000, "event")]);
        let seg_dir = tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let report = run_one_pass(
            dir.path(),
            None,
            None,
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.dreams_written, 1);

        drop(writer);
        join.await.ok();
        assert_eq!(
            count_dream_composed_frames(&seg),
            0,
            "writer = None must not emit a frame on this segment",
        );
    }

    #[tokio::test]
    async fn run_one_pass_no_frame_when_no_dreams() {
        // Empty window (no views.db) → 0 dreams → no audit frame even with a writer.
        let dir = tempdir().unwrap();
        let seg_dir = tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let report = run_one_pass(
            dir.path(),
            None,
            None,
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            Some(&writer),
        )
        .await
        .unwrap();
        assert_eq!(report.dreams_written, 0);

        drop(writer);
        join.await.ok();
        assert_eq!(count_dream_composed_frames(&seg), 0);
    }

    #[tokio::test]
    async fn run_one_pass_threads_chat_label_into_dreams() {
        // embed groups everything into one cluster; the chat provider labels it.
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[
                (1, n - 1800 * 1_000_000_000, "first"),
                (2, n - 900 * 1_000_000_000, "second"),
            ],
        );
        let embed = AlwaysWeatherEmbed;
        let chat = AuthorizedProvider::from_box(
            Box::new(FixedLabelChat),
            crate::providers::cost_authorization::ProviderCallAuthorizer::test_only(
                crate::permissions::AutonomyLevel::Full,
            ),
            Some("fixed_label_chat".to_string()),
            "dreaming.task.test",
        );
        let report = run_one_pass(
            dir.path(),
            Some(&embed),
            Some(&chat),
            &test_pass_config(DEFAULT_WINDOW, DEFAULT_MAX_EVENTS),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.path_taken, DreamingPath::Embedding);

        let day = report.day_label();
        let dreams = crate::daemon::dreaming::load_dreams_for_day(dir.path(), &day);
        assert_eq!(dreams.len(), 1);
        assert_eq!(
            dreams[0].theme_label, "weekend trip planning",
            "the LLM label must replace the deterministic cluster-N-seed-id",
        );
    }

    #[test]
    fn dream_composed_payload_has_stable_shape() {
        let report = PassReport {
            events_considered: 5,
            dreams_written: 2,
            path: PathBuf::from("/home/op/.neoth/dreams/2026-06-03.jsonl"),
            path_taken: DreamingPath::Embedding,
        };
        let bytes = dream_composed_payload(&report, 1_700_000_000);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["day"], "2026-06-03");
        assert_eq!(v["dreams"], 2);
        assert_eq!(v["events_considered"], 5);
        assert_eq!(v["path_taken"], "Embedding");
        assert_eq!(v["ts_unix"], 1_700_000_000_u64);
    }
}
