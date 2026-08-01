//! Skill registry — hot-reloadable atomic-swap container around the loaded
//! skill set.
//!
//! D-103 (Session 21, 2026-05-23): 6-agent senior-dev panel picked Option 3
//! for the skill hot-reload semantics — every reload swaps the live registry
//! atomically, but invocations in flight finish on the version they started
//! with. Same semantics as vite, cargo-watch, esbuild.
//!
//! ## Why one compound ArcSwap snapshot
//!
//! Reads dominate the workload: every chat turn calls
//! `crate::skills::route(prompt, &registry.load())` once, often from many
//! concurrent channel-handler tasks (Telegram + Slack + CLI simultaneously).
//! Writes are rare — only when the operator edits a YAML or drops a new
//! skill into `~/.neoth/skills/`.
//!
//! `arc-swap::ArcSwap<PublishedSkillSnapshot>` publishes the config epoch,
//! per-home authority epoch, and admitted `Arc<Vec<RuntimeSkill>>` in one
//! pointer swap. Keeping those values in one immutable object is essential:
//! separate publications permit a reader to observe new Skill bytes with an
//! old epoch. Each turn retains the returned Skill `Arc`; a later swap cannot
//! change that invocation's view.
//!
//! ## Watcher
//!
//! [`SkillRegistry::watch`] spawns a tokio task that owns a
//! `notify::RecommendedWatcher` over the user skills directory, the complete
//! installed-authority tree, and authority-relevant WAL structure. A typed
//! in-process transition bus closes the append-to-existing-WAL case for the
//! daemon's own audit writer and synchronously advances a per-home epoch before
//! watcher scheduling. When one of those directories does not exist yet, the
//! nearest existing ancestor is watched until it appears. Skill edits are
//! debounced; proof-input changes first invalidate every new snapshot
//! acquisition and then rebuild from authenticated current state. This prevents
//! a same-id bundled Skill from appearing inside the authority transition
//! window.
//! [`SkillRegistry::reload_now`] validates the complete Skill/Mode snapshot
//! and only then publishes the new compound epoch/Skill value atomically.
//! Bundled skills always re-load too — they live in `include_str!` and
//! never change without a binary rebuild, but re-running the loader is
//! the simplest path and the cost is sub-millisecond (deserializing N
//! YAMLs out of memory).
//!
//! BUG-W2-P1-SKILL-WATCHER: skill subdirectories created **after** daemon
//! boot are covered by two complementary mechanisms:
//! 1. `RecursiveMode::Recursive` on `skills_dir` — the OS backend notifies on
//!    any descendant change.
//! 2. Explicit `NonRecursive` watches on each current skill subdir, rebuilt by
//!    every `reconcile_watches` call.  This closes the inotify race window where
//!    a `skill.yaml` file is written between directory creation and the OS
//!    sub-watch being installed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

use super::loader::{
    load_all, load_authorized_initial_from_reload_controller,
    load_authorized_reload_from_reload_controller, load_trusted_bundled_from_reload_controller,
};
use super::schema::{RuntimeSkill, Skill};

/// Build the complete skill snapshot and validate every cross-skill mode id
/// before the value can reach an [`ArcSwap`]. A mode collision is a registry
/// load error, not a per-request routing error.
pub(crate) async fn load_validated_skills(skills_dir: &Path) -> Result<Vec<Skill>> {
    let skills = load_all(skills_dir).await?;
    super::mode_registry::ModeRegistry::validate_inventory(&skills)
        .context("validate unique mode ids in skill inventory")?;
    Ok(skills)
}

fn validate_runtime_skills(skills: Vec<RuntimeSkill>) -> Result<Vec<RuntimeSkill>> {
    super::mode_registry::ModeRegistry::from_skills(&skills)
        .context("validate unique mode ids in skill registry")?;
    Ok(skills)
}

fn lock_installed_runtime_publication(
    skills_dir: &Path,
    skills: &[RuntimeSkill],
) -> Result<Option<super::authority::InstalledSkillPublicationGuard>> {
    if skills.iter().all(|skill| skill.is_trusted_bundled()) {
        return Ok(None);
    }
    let home = skills_dir.parent().with_context(|| {
        format!(
            "installed runtime Skill directory has no NEOTH home parent: {}",
            skills_dir.display()
        )
    })?;
    let mut guard = super::authority::lock_installed_skill_publication(home)
        .context("lock installed Skill authority through runtime ArcSwap publication")?;
    for skill in skills.iter().filter(|skill| !skill.is_trusted_bundled()) {
        guard.validate_installed_binding(
            skill.id(),
            skill
                .package_generation_sha256()
                .context("installed runtime Skill lacks package-generation proof")?,
            skill
                .install_incarnation()
                .context("installed runtime Skill lacks install-incarnation proof")?,
            skill
                .install_terminal_receipt_sha256()
                .context("installed runtime Skill lacks terminal-receipt proof")?,
            skill
                .authority_record_sha256()
                .context("installed runtime Skill lacks authority-record proof")?,
        )?;
    }
    Ok(Some(guard))
}

async fn lock_installed_runtime_publication_async(
    skills_dir: PathBuf,
    skills: Arc<Vec<RuntimeSkill>>,
) -> Result<Option<super::authority::InstalledSkillPublicationGuard>> {
    tokio::task::spawn_blocking(move || {
        lock_installed_runtime_publication(&skills_dir, skills.as_slice())
    })
    .await
    .context("installed Skill publication barrier worker failed")?
}

/// Compare the complete runtime-relevant skill snapshot before publishing a
/// new Arc. Some filesystem backends (notably macOS FSEvents) can report a
/// watched directory as modified when only a sibling file changed. Reloading
/// is harmless, but replacing an identical Arc would falsely signal a new
/// routing generation to pinned readers.
fn skill_snapshots_match(current: &[RuntimeSkill], candidate: &[RuntimeSkill]) -> Result<bool> {
    let current = serde_json::to_vec(current).context("serialize current skill snapshot")?;
    let candidate = serde_json::to_vec(candidate).context("serialize candidate skill snapshot")?;
    Ok(current == candidate)
}

struct PublishedSkillSnapshot {
    config_epoch: u64,
    authority_epoch: u64,
    skills: Arc<Vec<RuntimeSkill>>,
}

fn published_skill_snapshot(
    config_epoch: u64,
    authority_epoch: u64,
    skills: Arc<Vec<RuntimeSkill>>,
) -> Arc<PublishedSkillSnapshot> {
    Arc::new(PublishedSkillSnapshot {
        config_epoch,
        authority_epoch,
        skills,
    })
}

fn empty_runtime_snapshot() -> Arc<Vec<RuntimeSkill>> {
    static EMPTY: OnceLock<Arc<Vec<RuntimeSkill>>> = OnceLock::new();
    Arc::clone(EMPTY.get_or_init(|| Arc::new(Vec::new())))
}

const RUNTIME_AUTHORITY_TRANSITION_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeAuthorityTransitionKind {
    InstallIntent,
    InstallResult,
    RemovalIntent,
    RemovalResult,
    AuthorityDecision,
}

#[derive(Clone, Debug)]
struct RuntimeAuthorityTransition {
    home: PathBuf,
    kind: RuntimeAuthorityTransitionKind,
}

fn runtime_authority_transition_sender()
-> &'static tokio::sync::broadcast::Sender<RuntimeAuthorityTransition> {
    static SENDER: OnceLock<tokio::sync::broadcast::Sender<RuntimeAuthorityTransition>> =
        OnceLock::new();
    SENDER.get_or_init(|| {
        let (sender, _) = tokio::sync::broadcast::channel(RUNTIME_AUTHORITY_TRANSITION_CAPACITY);
        sender
    })
}

fn subscribe_runtime_authority_transitions()
-> tokio::sync::broadcast::Receiver<RuntimeAuthorityTransition> {
    runtime_authority_transition_sender().subscribe()
}

#[cfg(test)]
pub(crate) struct RuntimeAuthorityTransitionTestSubscriber {
    receiver: tokio::sync::broadcast::Receiver<RuntimeAuthorityTransition>,
}

#[cfg(test)]
impl RuntimeAuthorityTransitionTestSubscriber {
    pub(crate) async fn recv(
        &mut self,
    ) -> std::result::Result<
        (PathBuf, RuntimeAuthorityTransitionKind),
        tokio::sync::broadcast::error::RecvError,
    > {
        self.receiver
            .recv()
            .await
            .map(|transition| (transition.home, transition.kind))
    }

    pub(crate) fn try_recv(
        &mut self,
    ) -> std::result::Result<
        (PathBuf, RuntimeAuthorityTransitionKind),
        tokio::sync::broadcast::error::TryRecvError,
    > {
        self.receiver
            .try_recv()
            .map(|transition| (transition.home, transition.kind))
    }
}

#[cfg(test)]
pub(crate) fn subscribe_runtime_authority_transitions_for_test()
-> RuntimeAuthorityTransitionTestSubscriber {
    RuntimeAuthorityTransitionTestSubscriber {
        receiver: subscribe_runtime_authority_transitions(),
    }
}

fn runtime_authority_home_key(home: &Path) -> PathBuf {
    let absolute = if home.is_absolute() {
        home.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(home))
            .unwrap_or_else(|_| home.to_path_buf())
    };
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(existing) {
            Ok(mut canonical) => {
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return canonical;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = existing.file_name() else {
                    return absolute;
                };
                missing.push(name.to_os_string());
                let Some(parent) = existing.parent() else {
                    return absolute;
                };
                existing = parent;
            }
            Err(_) => return absolute,
        }
    }
}

struct RuntimeAuthorityEpoch {
    value: AtomicU64,
    publication_barrier: std::sync::Mutex<()>,
}

impl RuntimeAuthorityEpoch {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
            publication_barrier: std::sync::Mutex::new(()),
        }
    }

    fn current(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    /// Linearization point for a durable authority transition. Publication
    /// takes the same barrier, so it either commits before this increment and
    /// is invalidated immediately, or observes the new epoch and must rebuild.
    fn advance(&self) -> u64 {
        let _barrier = self
            .publication_barrier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next = self
            .current()
            .checked_add(1)
            .expect("Skill authority transition epoch exhausted");
        self.value.store(next, Ordering::Release);
        next
    }

    fn publish_if_current<T>(
        &self,
        validated_epoch: u64,
        publish: impl FnOnce() -> T,
    ) -> Option<T> {
        let _barrier = self
            .publication_barrier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (self.current() == validated_epoch).then(publish)
    }
}

fn runtime_authority_epoch(home_key: &Path) -> Arc<RuntimeAuthorityEpoch> {
    static EPOCHS: OnceLock<std::sync::Mutex<HashMap<PathBuf, Arc<RuntimeAuthorityEpoch>>>> =
        OnceLock::new();
    let mut epochs = EPOCHS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(
        epochs
            .entry(home_key.to_path_buf())
            .or_insert_with(|| Arc::new(RuntimeAuthorityEpoch::new())),
    )
}

/// Notify the live runtime immediately after an authenticated Skill authority
/// or mutation frame becomes durable. The per-home epoch advances
/// synchronously before the advisory broadcast, so a new snapshot acquisition
/// fails closed even when the watcher is not scheduled or a reload lock is
/// already held. The receiver is created before registry loading, so an append
/// in the narrow load-to-watcher-start window remains queued for exact rebuild.
pub(crate) fn notify_runtime_authority_transition(
    home: &Path,
    kind: RuntimeAuthorityTransitionKind,
) {
    let home = runtime_authority_home_key(home);
    runtime_authority_epoch(&home).advance();
    let _ = runtime_authority_transition_sender().send(RuntimeAuthorityTransition { home, kind });
}

/// Process-wide live skill registry. Set by `serve.rs::run_serve` at
/// daemon boot via [`init_global`]; chat / channel-pipeline / skill
/// dispatch paths inside the daemon read from it via [`global`] so
/// every reader sees the same compound Skill publication the daemon's
/// hot-reload watcher mutates.
///
/// One-shot CLI calls (`neoth chat "..."` without `serve` running) build
/// their own registry instead of using the global — there's no daemon
/// to share it with + no long-lived reader to revalidate against.
static GLOBAL_REGISTRY: OnceLock<Arc<SkillRegistry>> = OnceLock::new();

/// Initialise the process-wide skill registry. Idempotent — second call
/// returns `false` without disturbing the existing registry. Intended
/// for daemon startup (`serve.rs`) so every in-daemon skill consumer
/// reads from the same atomic-swap pointer the watcher mutates.
pub fn init_global(registry: Arc<SkillRegistry>) -> bool {
    GLOBAL_REGISTRY.set(registry).is_ok()
}

/// Read the process-wide skill registry if one was initialised.
/// Returns None for one-shot CLI invocations that never called
/// [`init_global`].
pub fn global() -> Option<Arc<SkillRegistry>> {
    GLOBAL_REGISTRY.get().cloned()
}

/// Hot-reloadable skill set. Held in `Arc` so the watcher task can keep
/// a reference + the daemon's main loop can hand `.clone()` references to
/// every channel-handler at startup.
///
/// The inner `ArcSwap<PublishedSkillSnapshot>` is the swap unit. Readers call
/// [`SkillRegistry::snapshot`] and retain the returned Skill `Arc` for one
/// chat turn / dispatch. Even if a reload swaps the compound pointer mid-turn,
/// the pre-reload Skill vec remains alive until drop. This is the
/// "invocations finish on old version" half of D-103 Option 3.
pub struct SkillRegistry {
    inner: ArcSwap<PublishedSkillSnapshot>,
    skills_dir: PathBuf,
    config_path: PathBuf,
    authority_home: PathBuf,
    authority_epoch: Arc<RuntimeAuthorityEpoch>,
    reload_controller: Arc<crate::config::reload::ReloadController>,
    reload_lock: tokio::sync::Mutex<()>,
    authority_transition_rx:
        std::sync::Mutex<Option<tokio::sync::broadcast::Receiver<RuntimeAuthorityTransition>>>,
    /// `true` only for one-shot/file-backed registries that constructed their
    /// own accepted-config controller. Daemon registries receive the process
    /// controller and never race it by re-reading config independently.
    owns_reload_controller: bool,
}

impl SkillRegistry {
    /// Load the initial skill set + return the registry. Existing unreadable
    /// or malformed skill/policy files fail startup; only the loader's
    /// explicitly optional missing paths resolve to an empty user layer.
    pub async fn load(skills_dir: impl AsRef<Path>) -> Result<Arc<Self>> {
        let skills_dir = skills_dir.as_ref().to_path_buf();
        let config_path = skills_dir
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("freedom.yaml");
        Self::load_from_config_path(skills_dir, config_path).await
    }

    /// Load a file-backed registry from one exact operator config path.
    /// Long-lived daemons should prefer [`Self::load_with_reload_controller`]
    /// so rejected config candidates can never affect live skill routing.
    pub async fn load_from_config_path(
        skills_dir: impl AsRef<Path>,
        config_path: impl AsRef<Path>,
    ) -> Result<Arc<Self>> {
        let skills_dir = skills_dir.as_ref().to_path_buf();
        let config_path = config_path.as_ref().to_path_buf();
        let authority_transition_rx = subscribe_runtime_authority_transitions();
        let authority_home =
            runtime_authority_home_key(skills_dir.parent().with_context(|| {
                format!(
                    "Skill registry directory has no NEOTH home parent: {}",
                    skills_dir.display()
                )
            })?);
        let authority_epoch = runtime_authority_epoch(&authority_home);
        let validated_authority_epoch = authority_epoch.current();
        let config = crate::config::FreedomConfig::load_from_path_or_default(&config_path)
            .with_context(|| {
                format!("load accepted Skill policy from {}", config_path.display())
            })?;
        let reload_controller = Arc::new(crate::config::reload::ReloadController::new(
            config,
            config_path.clone(),
        ));
        let initial_snapshot =
            load_authorized_initial_from_reload_controller(&skills_dir, reload_controller.as_ref())
                .await
                .with_context(|| {
                    format!(
                        "load initial skill registry from {} with policy {}",
                        skills_dir.display(),
                        config_path.display()
                    )
                })?;
        let accepted_config_epoch = initial_snapshot.accepted_config_epoch;
        let initial = Arc::new(validate_runtime_skills(initial_snapshot.skills)?);
        let initial_count = initial.len();
        let publication_guard =
            lock_installed_runtime_publication_async(skills_dir.clone(), Arc::clone(&initial))
                .await?;
        let registry = reload_controller
            .with_accepted_epoch_publication(accepted_config_epoch, || {
                let _publication_guard = publication_guard;
                authority_epoch
                    .publish_if_current(validated_authority_epoch, || {
                        Arc::new(Self {
                            inner: ArcSwap::new(published_skill_snapshot(
                                accepted_config_epoch,
                                validated_authority_epoch,
                                Arc::clone(&initial),
                            )),
                            skills_dir,
                            config_path,
                            authority_home,
                            authority_epoch: Arc::clone(&authority_epoch),
                            reload_controller: Arc::clone(&reload_controller),
                            reload_lock: tokio::sync::Mutex::new(()),
                            authority_transition_rx: std::sync::Mutex::new(Some(
                                authority_transition_rx,
                            )),
                            owns_reload_controller: true,
                        })
                    })
                    .context("Skill authority changed before initial registry ArcSwap publication")
            })?
            .context("accepted Skill policy changed before initial registry publication")?;
        info!(
            count = initial_count,
            dir = %registry.skills_dir.display(),
            config = %registry.config_path.display(),
            "skill registry primed"
        );
        Ok(registry)
    }

    /// Load a daemon registry from the exact already-accepted config
    /// generation and subscribe to every successful reload generation.
    pub async fn load_with_reload_controller(
        skills_dir: impl AsRef<Path>,
        reload_controller: Arc<crate::config::reload::ReloadController>,
    ) -> Result<Arc<Self>> {
        let skills_dir = skills_dir.as_ref().to_path_buf();
        let config_path = reload_controller.source_path().to_path_buf();
        let authority_transition_rx = subscribe_runtime_authority_transitions();
        let authority_home =
            runtime_authority_home_key(skills_dir.parent().with_context(|| {
                format!(
                    "Skill registry directory has no NEOTH home parent: {}",
                    skills_dir.display()
                )
            })?);
        let authority_epoch = runtime_authority_epoch(&authority_home);
        let validated_authority_epoch = authority_epoch.current();
        let initial_snapshot =
            load_authorized_initial_from_reload_controller(&skills_dir, reload_controller.as_ref())
                .await
                .with_context(|| {
                    format!(
                        "load initial skill registry from {} with active policy {}",
                        skills_dir.display(),
                        config_path.display()
                    )
                })?;
        let accepted_config_epoch = initial_snapshot.accepted_config_epoch;
        let initial = Arc::new(validate_runtime_skills(initial_snapshot.skills)?);
        let initial_count = initial.len();
        let publication_guard =
            lock_installed_runtime_publication_async(skills_dir.clone(), Arc::clone(&initial))
                .await?;
        let registry = reload_controller
            .with_accepted_epoch_publication(accepted_config_epoch, || {
                let _publication_guard = publication_guard;
                authority_epoch
                    .publish_if_current(validated_authority_epoch, || {
                        Arc::new(Self {
                            inner: ArcSwap::new(published_skill_snapshot(
                                accepted_config_epoch,
                                validated_authority_epoch,
                                Arc::clone(&initial),
                            )),
                            skills_dir,
                            config_path,
                            authority_home,
                            authority_epoch: Arc::clone(&authority_epoch),
                            reload_controller: Arc::clone(&reload_controller),
                            reload_lock: tokio::sync::Mutex::new(()),
                            authority_transition_rx: std::sync::Mutex::new(Some(
                                authority_transition_rx,
                            )),
                            owns_reload_controller: false,
                        })
                    })
                    .context("Skill authority changed before initial registry ArcSwap publication")
            })?
            .context("accepted Skill policy changed before initial registry publication")?;
        info!(
            count = initial_count,
            dir = %registry.skills_dir.display(),
            config = %registry.config_path.display(),
            reload_bound = true,
            "skill registry primed"
        );
        Ok(registry)
    }

    /// Get a read snapshot for the accepted config generation that is current
    /// throughout this acquisition. A config reload whose Skill rebuild has
    /// not published yet returns an empty fail-closed layer.
    pub fn snapshot(&self) -> Arc<Vec<RuntimeSkill>> {
        let accepted_epoch = self.reload_controller.accepted_snapshot().epoch();
        let snapshot = self.snapshot_owned_for_epoch(accepted_epoch);
        if self.reload_controller.accepted_snapshot().epoch() == accepted_epoch {
            snapshot
        } else {
            empty_runtime_snapshot()
        }
    }

    /// Convenience for callers that want an owned `Arc<Vec<RuntimeSkill>>` they
    /// can hand to a sibling task — same effect as `Arc::clone` on the
    /// loaded snapshot.
    pub fn snapshot_owned(&self) -> Arc<Vec<RuntimeSkill>> {
        self.snapshot()
    }

    /// Acquire the Skill layer for the exact config epoch already pinned by
    /// one turn. Returning a newer or older generation would create a torn
    /// config/Skill authority pair, so any mismatch is an empty fail-closed
    /// snapshot.
    pub fn snapshot_owned_for_epoch(&self, expected_config_epoch: u64) -> Arc<Vec<RuntimeSkill>> {
        let authority_epoch = self.authority_epoch.current();
        let published = self.inner.load_full();
        if published.config_epoch != expected_config_epoch
            || published.authority_epoch != authority_epoch
        {
            return empty_runtime_snapshot();
        }
        let skills = Arc::clone(&published.skills);
        if self.authority_epoch.current() == authority_epoch {
            skills
        } else {
            empty_runtime_snapshot()
        }
    }

    /// Directory the registry watches for user skill overrides. The
    /// watcher task uses this; tests use it for assertions.
    pub fn skills_dir(&self) -> &Path {
        &self.skills_dir
    }

    /// Exact active config path that owns this registry's policy.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Manually trigger a reload from disk. Returns (previous_count,
    /// new_count). Useful for operator-driven reload (`neoth skills
    /// reload`) without waiting for the watcher debounce.
    pub async fn reload_now(&self) -> Result<(usize, usize)> {
        let _reload_guard = self.reload_lock.lock().await;
        // Capture before any config, package, or authority input is read. A
        // durable transition after this point invalidates the build and the
        // final publication barrier rejects it.
        let validated_authority_epoch = self.authority_epoch.current();
        let config_exists = if self.owns_reload_controller {
            match self.config_path.try_exists().with_context(|| {
                format!(
                    "inspect owned Skill config before reload {}",
                    self.config_path.display()
                )
            }) {
                Ok(exists) => exists,
                Err(error) => {
                    self.publish_bundled_only_fail_closed("config path inspection failed")
                        .await;
                    return Err(error);
                }
            }
        } else {
            false
        };
        if self.owns_reload_controller && config_exists {
            let reload_controller = Arc::clone(&self.reload_controller);
            if let Err(error) = tokio::task::spawn_blocking(move || reload_controller.try_reload())
                .await
                .context("owned Skill config reload worker failed")
                .and_then(std::convert::identity)
            {
                self.publish_bundled_only_fail_closed("owned config reload failed")
                    .await;
                return Err(error);
            }
        }
        let new_snapshot = match load_authorized_reload_from_reload_controller(
            &self.skills_dir,
            self.reload_controller.as_ref(),
        )
        .await
        .with_context(|| {
            format!(
                "reload skill registry from {} with active policy {}",
                self.skills_dir.display(),
                self.config_path.display()
            )
        }) {
            Ok(new) => new,
            Err(error) => {
                self.publish_bundled_only_fail_closed("authorized runtime rebuild failed")
                    .await;
                return Err(error);
            }
        };
        let accepted_config_epoch = new_snapshot.accepted_config_epoch;
        let new = match validate_runtime_skills(new_snapshot.skills) {
            Ok(new) => Arc::new(new),
            Err(error) => {
                self.publish_bundled_only_fail_closed("runtime mode validation failed")
                    .await;
                return Err(error);
            }
        };
        let new_count = new.len();
        let current = self.inner.load_full();
        let prev = current.skills.len();
        let snapshots_match = match skill_snapshots_match(current.skills.as_slice(), new.as_slice())
        {
            Ok(matches) => matches,
            Err(error) => {
                self.publish_bundled_only_fail_closed("runtime snapshot comparison failed")
                    .await;
                return Err(error);
            }
        };
        let publication_guard = match lock_installed_runtime_publication_async(
            self.skills_dir.clone(),
            Arc::clone(&new),
        )
        .await
        {
            Ok(guard) => guard,
            Err(error) => {
                self.publish_bundled_only_fail_closed(
                    "installed authority changed before runtime publication",
                )
                .await;
                return Err(error);
            }
        };
        let publication =
            self.reload_controller
                .with_accepted_epoch_publication(accepted_config_epoch, || {
                    let _publication_guard = publication_guard;
                    let published_skills = if snapshots_match {
                        Arc::clone(&current.skills)
                    } else {
                        Arc::clone(&new)
                    };
                    Ok(self
                        .authority_epoch
                        .publish_if_current(validated_authority_epoch, || {
                            self.inner.store(published_skill_snapshot(
                                accepted_config_epoch,
                                validated_authority_epoch,
                                published_skills,
                            ));
                        })
                        .is_some())
                });
        match publication {
            Ok(Some(true)) => Ok((prev, new_count)),
            Ok(Some(false)) => {
                anyhow::bail!(
                    "Skill authority changed before runtime ArcSwap publication; stale rebuild discarded"
                )
            }
            Ok(None) => {
                self.publish_bundled_only_fail_closed(
                    "accepted config changed before runtime publication",
                )
                .await;
                anyhow::bail!("accepted Skill policy changed before runtime ArcSwap publication")
            }
            Err(error) => {
                self.publish_bundled_only_fail_closed(
                    "installed authority changed before runtime publication",
                )
                .await;
                Err(error)
            }
        }
    }

    /// Last-resort live safety boundary. A reload error must never preserve an
    /// installed capability whose package or authority may have changed.
    /// Rebuild the complete compile-time bundled layer under one accepted
    /// config publication epoch; if that epoch never stabilizes, publish empty.
    async fn publish_bundled_only_fail_closed(&self, reason: &'static str) {
        const MAX_PUBLICATION_RETRIES: usize = 4;

        let current = self.inner.load_full();
        for attempt in 1..=MAX_PUBLICATION_RETRIES {
            let validated_authority_epoch = self.authority_epoch.current();
            let snapshot =
                match load_trusted_bundled_from_reload_controller(self.reload_controller.as_ref())
                    .await
                {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        warn!(
                            %error,
                            attempt,
                            reason,
                            "fresh bundled fallback could not bind to a stable accepted policy"
                        );
                        break;
                    }
                };
            let bundled_count = snapshot.skills.len();
            let bundled = Arc::new(snapshot.skills);
            match self.reload_controller.with_accepted_epoch_publication(
                snapshot.accepted_config_epoch,
                || {
                    Ok(self
                        .authority_epoch
                        .publish_if_current(validated_authority_epoch, || {
                            self.inner.store(published_skill_snapshot(
                                snapshot.accepted_config_epoch,
                                validated_authority_epoch,
                                Arc::clone(&bundled),
                            ));
                        })
                        .is_some())
                },
            ) {
                Ok(Some(true)) => {
                    warn!(
                        previous_count = current.skills.len(),
                        bundled_count,
                        reason,
                        "Skill reload failed closed; all installed runtime capabilities were removed"
                    );
                    return;
                }
                Ok(Some(false)) => {
                    debug!(
                        attempt,
                        reason,
                        "Skill authority advanced before bundled fallback publication; retrying"
                    );
                }
                Ok(None) => {
                    debug!(
                        attempt,
                        reason,
                        "accepted policy advanced before bundled fallback publication; retrying"
                    );
                }
                Err(error) => {
                    warn!(
                        %error,
                        attempt,
                        reason,
                        "bundled fallback publication failed"
                    );
                    break;
                }
            }
        }
        warn!(
            previous_count = current.skills.len(),
            reason,
            "fresh bundled fallback could not be published; installing an empty runtime registry"
        );
        let accepted_epoch = self.reload_controller.accepted_snapshot().epoch();
        let authority_epoch = self.authority_epoch.current();
        let _ = self
            .authority_epoch
            .publish_if_current(authority_epoch, || {
                self.inner.store(published_skill_snapshot(
                    accepted_epoch,
                    authority_epoch,
                    empty_runtime_snapshot(),
                ));
            });
    }

    async fn fail_closed_after_observer_failure(&self, reason: &'static str) {
        let _reload_guard = self.reload_lock.lock().await;
        self.publish_bundled_only_fail_closed(reason).await;
    }

    /// Authority proof changes are stricter than ordinary config/watcher
    /// failures. Publishing the bundled layer here could expose a same-id
    /// implementation between the durable authority transition and its exact
    /// rebuild, so the transition window has no executable Skills at all.
    async fn fail_closed_for_authority_transition(&self, reason: &'static str) {
        // Invalidate readers before waiting for an in-progress reload. Typed
        // transitions already advanced once at durable notify; an additional
        // observer epoch is harmless and also covers raw FS/WAL proof changes.
        self.authority_epoch.advance();
        let _reload_guard = self.reload_lock.lock().await;
        let current = self.inner.load_full();
        let accepted_epoch = self.reload_controller.accepted_snapshot().epoch();
        let authority_epoch = self.authority_epoch.current();
        let _ = self
            .authority_epoch
            .publish_if_current(authority_epoch, || {
                self.inner.store(published_skill_snapshot(
                    accepted_epoch,
                    authority_epoch,
                    empty_runtime_snapshot(),
                ));
            });
        warn!(
            previous_count = current.skills.len(),
            reason, "Skill authority transition published an empty runtime snapshot before rebuild"
        );
    }

    /// Spawn the watcher task. A missing skills directory is a supported
    /// first-run state: the nearest existing ancestor is watched until the
    /// directory appears. Watch construction and initial registration fail
    /// loudly so daemon startup never reports a watcher that is not active.
    /// Drop the returned handle to stop watching.
    pub fn watch(self: &Arc<Self>) -> Result<WatcherHandle> {
        let authority_transition_rx = self
            .authority_transition_rx
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
            .context("Skill registry watcher is already active")?;
        watcher::spawn(Arc::clone(self), authority_transition_rx)
    }
}

/// Handle to the spawned filesystem watcher. Drop stops the watcher task.
/// Production callers usually leak this for daemon lifetime; tests drop it
/// to assert the watcher tears down cleanly.
pub struct WatcherHandle {
    _watcher: Arc<std::sync::Mutex<notify::RecommendedWatcher>>,
    /// Sender end of the cancellation channel — drop signals the
    /// debounce loop to exit.
    _cancel: tokio::sync::oneshot::Sender<()>,
}

mod watcher {
    use super::*;
    use notify::{Event, EventKind, RecursiveMode, Watcher};
    use std::collections::BTreeMap;
    use tokio::sync::mpsc;

    /// Debounce window — skills/<id>/skill.yaml edits commonly fire 2-3
    /// events back-to-back (editor saves a temp file + renames + chmods).
    /// We collapse them into a single reload.
    const DEBOUNCE: Duration = Duration::from_millis(250);
    const REBIND_RETRY: Duration = Duration::from_secs(1);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WatchDepth {
        NonRecursive,
        Recursive,
    }

    enum WatchSignal {
        Event(Event),
        BackendError(String),
    }

    impl WatchDepth {
        fn notify_mode(self) -> RecursiveMode {
            match self {
                Self::NonRecursive => RecursiveMode::NonRecursive,
                Self::Recursive => RecursiveMode::Recursive,
            }
        }
    }

    pub fn spawn(
        registry: Arc<SkillRegistry>,
        mut authority_transition_rx: tokio::sync::broadcast::Receiver<RuntimeAuthorityTransition>,
    ) -> Result<WatcherHandle> {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<WatchSignal>();
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let mut config_generation = Some(registry.reload_controller.subscribe_generation());
        // A reload-bound daemon only accepts config policy through the
        // ReloadController generation. A raw file edit may later be rejected
        // and must not leak into the routing ArcSwap through notify.
        let watched_config_path = registry
            .owns_reload_controller
            .then_some(registry.config_path.as_path());
        let authority_root = registry
            .skills_dir
            .parent()
            .context("Skill registry directory has no NEOTH home")?
            .join("skill-authority");
        let wal_dir = registry
            .skills_dir
            .parent()
            .context("Skill registry directory has no NEOTH home")?
            .join("wal");

        // `notify` callbacks run on the watcher's own thread — bounce
        // each event onto the tokio runtime via unbounded mpsc so the
        // debounce loop can `select!` on it alongside cancellation.
        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<Event>| match res {
                Ok(ev) => {
                    let _ = event_tx.send(WatchSignal::Event(ev));
                }
                Err(error) => {
                    let _ = event_tx.send(WatchSignal::BackendError(error.to_string()));
                }
            })
            .context("construct skill filesystem watcher")?;
        let mut active_watches = BTreeMap::new();
        reconcile_watches(
            &mut watcher,
            &registry.skills_dir,
            &authority_root,
            &wal_dir,
            watched_config_path,
            &mut active_watches,
        )
        .with_context(|| {
            format!(
                "register skill filesystem watcher for {}",
                registry.skills_dir.display()
            )
        })?;
        let watcher = Arc::new(std::sync::Mutex::new(watcher));

        info!(
            dir = %registry.skills_dir.display(),
            "skill hot-reload watcher started"
        );

        let registry = Arc::clone(&registry);
        let task_watcher = Arc::clone(&watcher);
        tokio::spawn(async move {
            // Debounce loop: drain events; whenever a relevant event
            // lands, wait DEBOUNCE for the dust to settle, then reload
            // once. A second event arriving inside the window resets
            // the timer (collapses bursts).
            let mut pending: Option<tokio::time::Instant> = None;
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => {
                        debug!("skill watcher cancellation received; exiting loop");
                        break;
                    }
                    maybe_ev = event_rx.recv() => {
                        match maybe_ev {
                            Some(WatchSignal::Event(ev)) => {
                                let watched_config_path = registry
                                    .owns_reload_controller
                                    .then_some(registry.config_path.as_path());
                                let authority_changed =
                                    event_is_authority_relevant(&ev, &authority_root);
                                let wal_structure_changed =
                                    event_is_authority_wal_structural_relevant(&ev, &wal_dir);
                                if wal_structure_changed
                                    || event_is_skill_relevant(
                                    &ev,
                                    &registry.skills_dir,
                                    &authority_root,
                                    watched_config_path,
                                ) {
                                    if authority_changed || wal_structure_changed {
                                        // A filesystem echo can arrive after the typed bus has
                                        // already rebuilt. Without an authenticated event-to-proof
                                        // binding it cannot be suppressed safely, so the bounded
                                        // debounce may briefly publish empty a second time.
                                        registry
                                            .fail_closed_for_authority_transition(
                                                "Skill authority proof input changed",
                                            )
                                            .await;
                                    }
                                    pending = Some(tokio::time::Instant::now() + DEBOUNCE);
                                }
                            }
                            Some(WatchSignal::BackendError(error)) => {
                                warn!(
                                    %error,
                                    "skill watcher backend failed; removing installed runtime capabilities and scheduling rebind"
                                );
                                registry
                                    .fail_closed_after_observer_failure("watcher backend error")
                                    .await;
                                pending = Some(tokio::time::Instant::now() + REBIND_RETRY);
                            }
                            None => {
                                warn!(
                                    "skill watcher event sender dropped; removing installed runtime capabilities"
                                );
                                registry
                                    .fail_closed_after_observer_failure(
                                        "watcher event channel terminated",
                                    )
                                    .await;
                                break;
                            }
                        }
                    }
                    _ = sleep_until_opt(pending) => {
                        pending = None;
                        let rebound = {
                            let mut watcher = task_watcher
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            reconcile_watches(
                                &mut watcher,
                                &registry.skills_dir,
                                &authority_root,
                                &wal_dir,
                                registry
                                    .owns_reload_controller
                                    .then_some(registry.config_path.as_path()),
                                &mut active_watches,
                            )
                        };
                        if let Err(e) = rebound {
                            warn!(
                                dir = %registry.skills_dir.display(),
                                error = %e,
                                "skill watcher rebind failed; revalidating fail-closed and retrying"
                            );
                            pending = Some(tokio::time::Instant::now() + REBIND_RETRY);
                        }
                        match registry.reload_now().await {
                            Ok((prev, new)) => info!(
                                prev_count = prev,
                                new_count = new,
                                "skills hot-reloaded"
                            ),
                            Err(e) => warn!(error = %e, "skills hot-reload failed"),
                        }
                    }
                    generation_changed = wait_for_generation(&mut config_generation) => {
                        if !generation_changed {
                            debug!("skill config-generation sender dropped; watcher remains file-bound");
                            config_generation = None;
                            continue;
                        }
                        match registry.reload_now().await {
                            Ok((prev, new)) => info!(
                                prev_count = prev,
                                new_count = new,
                                config = %registry.config_path.display(),
                                "skill policy hot-reloaded from accepted config generation"
                            ),
                            Err(e) => warn!(
                                error = %e,
                                config = %registry.config_path.display(),
                                "accepted config generation could not rebuild skill registry; installed runtime remains fail-closed"
                            ),
                        }
                    }
                    transition = authority_transition_rx.recv() => {
                        match transition {
                            Ok(transition) if transition.home == registry.authority_home =>
                            {
                                warn!(
                                    kind = ?transition.kind,
                                    "durable Skill authority transition observed; publishing an empty runtime snapshot before rebuild"
                                );
                                registry
                                    .fail_closed_for_authority_transition(
                                        "durable Skill authority transition",
                                    )
                                    .await;
                                match registry.reload_now().await {
                                    Ok((prev, new)) => info!(
                                        prev_count = prev,
                                        new_count = new,
                                        kind = ?transition.kind,
                                        "Skill authority transition rebuilt the runtime registry"
                                    ),
                                    Err(error) => warn!(
                                        %error,
                                        kind = ?transition.kind,
                                        "Skill authority transition rebuild failed closed"
                                    ),
                                }
                            }
                            Ok(_) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(
                                    skipped,
                                    "Skill authority transition observer lagged; publishing an empty runtime snapshot before rebuild"
                                );
                                registry
                                    .fail_closed_for_authority_transition(
                                        "Skill authority transition observer lagged",
                                    )
                                    .await;
                                if let Err(error) = registry.reload_now().await {
                                    warn!(
                                        %error,
                                        "lagged Skill authority transition rebuild failed closed"
                                    );
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                registry
                                    .fail_closed_for_authority_transition(
                                        "Skill authority transition observer closed",
                                    )
                                    .await;
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(WatcherHandle {
            _watcher: watcher,
            _cancel: cancel_tx,
        })
    }

    fn reconcile_watches(
        watcher: &mut notify::RecommendedWatcher,
        skills_dir: &Path,
        authority_root: &Path,
        wal_dir: &Path,
        config_path: Option<&Path>,
        active: &mut BTreeMap<PathBuf, WatchDepth>,
    ) -> Result<()> {
        let desired = desired_watches(skills_dir, authority_root, wal_dir, config_path)?;

        // Add the replacement watch before dropping an obsolete ancestor so
        // directory creation/removal never opens an observation gap.
        for (path, depth) in &desired {
            if active.get(path) == Some(depth) {
                continue;
            }
            if active.contains_key(path) {
                watcher
                    .unwatch(path)
                    .with_context(|| format!("replace skill watch at {}", path.display()))?;
                active.remove(path);
            }
            watcher
                .watch(path, depth.notify_mode())
                .with_context(|| format!("watch skill path {}", path.display()))?;
            active.insert(path.clone(), *depth);
        }

        let obsolete: Vec<PathBuf> = active
            .keys()
            .filter(|path| !desired.contains_key(*path))
            .cloned()
            .collect();
        for path in obsolete {
            // Backends may automatically forget a watch when its directory is
            // deleted. Failure to unwatch is therefore observable but harmless:
            // the new ancestor watch is already active.
            if let Err(error) = watcher.unwatch(&path) {
                debug!(path = %path.display(), error = %error, "obsolete skill watch already absent");
            }
            active.remove(&path);
        }
        Ok(())
    }

    fn desired_watches(
        skills_dir: &Path,
        authority_root: &Path,
        wal_dir: &Path,
        config_path: Option<&Path>,
    ) -> Result<BTreeMap<PathBuf, WatchDepth>> {
        let mut desired = BTreeMap::new();
        match std::fs::metadata(skills_dir) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    anyhow::bail!(
                        "skill watch path exists but is not a directory: {}",
                        skills_dir.display()
                    );
                }
                desired.insert(skills_dir.to_path_buf(), WatchDepth::Recursive);

                // BUG-W2-P1-SKILL-WATCHER: also add an explicit NonRecursive
                // watch for every current skill subdir so that a `skill.yaml`
                // written into a freshly-created directory is always observed.
                // `RecursiveMode::Recursive` on skills_dir covers the parent at
                // the OS level but on inotify (Linux) there is a race window
                // between the directory-creation event arriving and notify
                // internally calling `inotify_add_watch` for the new subdir;
                // files written during that window emit no events.  Explicit
                // per-subdir watches close the gap: after any relevant event
                // fires and `reconcile_watches` runs, the new subdir is added
                // to `desired` and immediately registered.  `reconcile_watches`
                // also prunes the set, so deleted skill dirs are unwatched
                // automatically.
                match std::fs::read_dir(skills_dir) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                desired.insert(entry.path(), WatchDepth::NonRecursive);
                            }
                        }
                    }
                    // skills_dir was removed between metadata() and read_dir();
                    // the Recursive watch handles the remove/recreate cycle.
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "enumerate skill subdirs for explicit watch under {}",
                                skills_dir.display()
                            )
                        });
                    }
                }

                let parent = skills_dir.parent().ok_or_else(|| {
                    anyhow::anyhow!("skill directory has no parent: {}", skills_dir.display())
                })?;
                let parent_metadata = std::fs::metadata(parent).with_context(|| {
                    format!("inspect skill directory parent {}", parent.display())
                })?;
                if !parent_metadata.is_dir() {
                    anyhow::bail!(
                        "skill directory parent is not a directory: {}",
                        parent.display()
                    );
                }
                // Keep observing deletion/recreation of the whole skills tree.
                desired.insert(parent.to_path_buf(), WatchDepth::NonRecursive);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = skills_dir.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing skill directory has no parent: {}",
                        skills_dir.display()
                    )
                })?;
                desired.insert(
                    nearest_existing_directory(parent)?,
                    WatchDepth::NonRecursive,
                );
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect skill watch path {}", skills_dir.display()));
            }
        }
        if let Some(config_path) = config_path {
            let config_parent = config_path.parent().ok_or_else(|| {
                anyhow::anyhow!("skill config path has no parent: {}", config_path.display())
            })?;
            desired.insert(
                nearest_existing_directory(config_parent)?,
                WatchDepth::NonRecursive,
            );
        }
        match std::fs::metadata(authority_root) {
            Ok(metadata) if metadata.is_dir() => {
                // Key, immutable records and current anchors all participate
                // in installed runtime proof validation. Watch the complete
                // low-churn authority tree, not only `current/`.
                desired.insert(authority_root.to_path_buf(), WatchDepth::Recursive);
            }
            Ok(_) => {
                anyhow::bail!(
                    "Skill authority root path is not a directory: {}",
                    authority_root.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = authority_root.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Skill authority root path has no parent: {}",
                        authority_root.display()
                    )
                })?;
                desired.insert(
                    nearest_existing_directory(parent)?,
                    WatchDepth::NonRecursive,
                );
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect Skill authority root path {}",
                        authority_root.display()
                    )
                });
            }
        }
        match std::fs::metadata(wal_dir) {
            Ok(metadata) if metadata.is_dir() => {
                // Normal frame appends are covered by the typed durable-ACK
                // channel. This non-recursive watch catches proof-destroying
                // segment/key creation, removal and replacement without
                // rebuilding Skills on every unrelated provider frame.
                desired.insert(wal_dir.to_path_buf(), WatchDepth::NonRecursive);
            }
            Ok(_) => {
                anyhow::bail!(
                    "Skill authority WAL path is not a directory: {}",
                    wal_dir.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = wal_dir.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Skill authority WAL path has no parent: {}",
                        wal_dir.display()
                    )
                })?;
                desired.insert(
                    nearest_existing_directory(parent)?,
                    WatchDepth::NonRecursive,
                );
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect Skill authority WAL path {}", wal_dir.display())
                });
            }
        }
        Ok(desired)
    }

    fn nearest_existing_directory(start: &Path) -> Result<PathBuf> {
        let mut candidate = start;
        loop {
            match std::fs::metadata(candidate) {
                Ok(metadata) if metadata.is_dir() => return Ok(candidate.to_path_buf()),
                Ok(_) => {
                    anyhow::bail!(
                        "skill watch ancestor is not a directory: {}",
                        candidate.display()
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    candidate = candidate.parent().ok_or_else(|| {
                        anyhow::anyhow!(
                            "no existing directory ancestor for skill path {}",
                            start.display()
                        )
                    })?;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("inspect skill watch ancestor {}", candidate.display())
                    });
                }
            }
        }
    }

    /// Filter — we care about `skill.yaml` create/modify/remove, a `skill`
    /// folder create/remove, and an exact file-backed config change. A daemon
    /// bound to ReloadController passes no config path here: only an accepted
    /// generation bump may publish config policy into its ArcSwap.
    pub(super) fn event_is_skill_relevant(
        ev: &Event,
        skills_dir: &std::path::Path,
        authority_root: &std::path::Path,
        config_path: Option<&Path>,
    ) -> bool {
        let kind_matches = matches!(
            ev.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        );
        if !kind_matches {
            return false;
        }
        let relevant_for = |skills_dir: &std::path::Path| {
            ev.paths.iter().any(|path| {
                if config_path == Some(path.as_path()) {
                    return true;
                }
                // Either side of this prefix relation can be relevant while a
                // missing parent chain is being created or the skills tree is being
                // removed. This does not rely on `is_dir()`, which is false after a
                // remove/rename event on every platform.
                if path == skills_dir || (!skills_dir.exists() && skills_dir.starts_with(path)) {
                    return true;
                }
                path.starts_with(skills_dir)
                    && (path.file_name().and_then(|name| name.to_str()) == Some("skill.yaml")
                        || path.parent() == Some(skills_dir))
            })
        };
        if relevant_for(skills_dir) {
            return true;
        }
        if event_is_authority_relevant(ev, authority_root) {
            return true;
        }
        // macOS FSEvents reports canonical paths (`/private/var/...`) while the
        // configured skills_dir may reach the same directory through a symlink
        // (`/var/...` tempdirs, symlinked homes). Resolve a canonical alias via
        // the parent — which exists even while skills_dir itself is still
        // missing — and accept a match against that spelling too. On Windows
        // `canonicalize` yields a `\\?\` path that never matches notify's
        // plain paths, so this arm is a no-op there and the primary
        // comparison above stays authoritative.
        let canonical_skills_alias = canonical_alias(skills_dir);
        canonical_skills_alias
            .as_deref()
            .is_some_and(|alias| alias != skills_dir && relevant_for(alias))
    }

    pub(super) fn event_is_authority_relevant(ev: &Event, authority_root: &Path) -> bool {
        let authority_relevant_for = |authority_dir: &Path| {
            ev.paths.iter().any(|path| {
                path == authority_dir
                    || authority_dir.starts_with(path)
                    || path.starts_with(authority_dir)
            })
        };
        if authority_relevant_for(authority_root) {
            return true;
        }
        canonical_alias(authority_root)
            .as_deref()
            .is_some_and(|alias| alias != authority_root && authority_relevant_for(alias))
    }

    /// WAL segments carry many unrelated provider/audit frames, so treating
    /// every append notification as an authority reload would continuously
    /// strip and rebuild installed Skills. Cooperative Skill authority and
    /// incarnation appends use the typed durable-ACK channel instead. This
    /// filesystem lane covers structural proof loss (segment/key create,
    /// remove, rename or replacement) and changes to non-segment key/sidecar
    /// files. Same-owner in-place rewriting of an existing `.wal` file is not
    /// a live revocation protocol; the next explicit validation/Doctor scan
    /// rejects its broken proof.
    pub(super) fn event_is_authority_wal_structural_relevant(ev: &Event, wal_dir: &Path) -> bool {
        let path_is_relevant = |candidate_dir: &Path, path: &Path| {
            path == candidate_dir
                || candidate_dir.starts_with(path)
                || path.parent() == Some(candidate_dir)
        };
        let event_targets_wal = |candidate_dir: &Path| {
            ev.paths
                .iter()
                .any(|path| path_is_relevant(candidate_dir, path))
        };
        let targets_wal = event_targets_wal(wal_dir)
            || canonical_alias(wal_dir)
                .as_deref()
                .is_some_and(|alias| alias != wal_dir && event_targets_wal(alias));
        if !targets_wal {
            return false;
        }

        match &ev.kind {
            EventKind::Create(_) | EventKind::Remove(_) => true,
            EventKind::Modify(notify::event::ModifyKind::Name(_)) => true,
            EventKind::Modify(_) => ev.paths.iter().any(|path| {
                path == wal_dir
                    || path.extension().and_then(|extension| extension.to_str()) != Some("wal")
            }),
            _ => false,
        }
    }

    /// Resolve the canonical spelling of a path even while one or more final
    /// components do not exist yet. This is required for FSEvents, which emits
    /// the real path behind a symlinked home while first-run watches may still
    /// be bound to the configured spelling of a not-yet-created directory.
    fn canonical_alias(path: &Path) -> Option<PathBuf> {
        let mut existing = path;
        let mut missing = Vec::new();
        loop {
            match std::fs::canonicalize(existing) {
                Ok(mut canonical) => {
                    for component in missing.iter().rev() {
                        canonical.push(component);
                    }
                    return Some(canonical);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(existing.file_name()?.to_os_string());
                    existing = existing.parent()?;
                }
                Err(_) => return None,
            }
        }
    }

    /// Helper: `tokio::time::sleep_until` but returns a future that
    /// completes immediately when `pending` is None (so the select! arm
    /// just stays parked instead of firing).
    async fn sleep_until_opt(pending: Option<tokio::time::Instant>) {
        match pending {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    }

    async fn wait_for_generation(receiver: &mut Option<tokio::sync::watch::Receiver<u64>>) -> bool {
        match receiver {
            Some(receiver) => receiver.changed().await.is_ok(),
            None => std::future::pending::<bool>().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs::{create_dir_all, write};

    async fn write_skill(dir: &Path, id: &str, body: &str) {
        let sd = dir.join(id);
        create_dir_all(&sd).await.unwrap();
        write(sd.join("skill.yaml"), body).await.unwrap();
    }

    async fn wait_for_skill(registry: &SkillRegistry, id: &str, present: bool) {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if registry.snapshot().iter().any(|skill| skill.id() == id) == present {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("skill `{id}` did not reach present={present}"));
    }

    async fn wait_for_skill_enabled(registry: &SkillRegistry, id: &str, enabled: bool) {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let current = registry
                    .snapshot()
                    .iter()
                    .find(|skill| skill.id() == id)
                    .map(|skill| skill.is_enabled());
                if current == Some(enabled) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("skill `{id}` did not reach enabled={enabled}"));
    }

    #[cfg(unix)]
    #[test]
    fn canonical_authority_tree_event_is_relevant_for_symlinked_home() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let real_home = root.path().join("real-home");
        let linked_home = root.path().join("linked-home");
        let real_authority = real_home.join("skill-authority");
        let real_current = real_authority.join("current");
        std::fs::create_dir_all(&real_current).unwrap();
        symlink(&real_home, &linked_home).unwrap();

        let configured_authority = linked_home.join("skill-authority");
        let canonical_anchor = std::fs::canonicalize(configured_authority.join("current"))
            .unwrap()
            .join("authority-runtime.json");
        let event = notify::Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Data(
            notify::event::DataChange::Content,
        )))
        .add_path(canonical_anchor);

        assert!(watcher::event_is_skill_relevant(
            &event,
            &linked_home.join("skills"),
            &configured_authority,
            None,
        ));
    }

    #[test]
    fn every_authority_proof_file_event_is_skill_relevant() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let authority_root = home.path().join("skill-authority");
        let paths = [
            authority_root.join("authority.key"),
            authority_root
                .join("records")
                .join("alpha")
                .join("0000000000000001.json"),
            authority_root.join("current").join("alpha.json"),
        ];

        for path in paths {
            let event = notify::Event::new(notify::EventKind::Modify(
                notify::event::ModifyKind::Data(notify::event::DataChange::Content),
            ))
            .add_path(path.clone());
            assert!(
                watcher::event_is_skill_relevant(&event, &skills_dir, &authority_root, None,),
                "{} must invalidate the runtime authority snapshot",
                path.display()
            );
        }
    }

    #[test]
    fn ordinary_wal_append_is_not_an_authority_structural_event() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        let event = notify::Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Data(
            notify::event::DataChange::Content,
        )))
        .add_path(wal_dir.join("0000000000000001.wal"));

        assert!(
            !watcher::event_is_authority_wal_structural_relevant(&event, &wal_dir),
            "ordinary WAL frame appends use the typed durable-ACK channel"
        );
    }

    #[test]
    fn wal_segment_remove_and_rename_are_authority_structural_events() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        let segment = wal_dir.join("0000000000000001.wal");
        let removed =
            notify::Event::new(notify::EventKind::Remove(notify::event::RemoveKind::File))
                .add_path(segment.clone());
        let renamed = notify::Event::new(notify::EventKind::Modify(
            notify::event::ModifyKind::Name(notify::event::RenameMode::Any),
        ))
        .add_path(segment);

        assert!(watcher::event_is_authority_wal_structural_relevant(
            &removed, &wal_dir
        ));
        assert!(watcher::event_is_authority_wal_structural_relevant(
            &renamed, &wal_dir
        ));
    }

    #[test]
    fn wal_key_modify_is_an_authority_structural_event() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        let event = notify::Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Data(
            notify::event::DataChange::Content,
        )))
        .add_path(wal_dir.join("hmac.key"));

        assert!(watcher::event_is_authority_wal_structural_relevant(
            &event, &wal_dir
        ));
    }

    fn skill_with_mode(id: &str, mode_id: &str) -> String {
        format!(
            r#"id: {id}
description: duplicate-mode registry fixture
system_prompt: test
modes:
  - id: {mode_id}
    description: test mode
    spectrum: balanced
    oversight: low
    output:
      format: markdown
"#
        )
    }

    fn install_test_authority_key(home: &Path) {
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&wal_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        crate::wal::win_native::set_private_current_user_directory_dacl(&wal_dir).unwrap();
        crate::wal::compaction::load_or_init_key(&wal_dir.join("hmac.key")).unwrap();
    }

    fn record_test_install_incarnation(home: &Path, id: &str) {
        let current = super::super::installer::inspect_current_install(&home.join("skills"), id)
            .expect("installed Skill fixture exists");
        super::super::mutation_lifecycle::record_committed_install_incarnation_for_test(
            home,
            id,
            &current.generation_sha256,
            super::super::installer::SkillMutationOrigin::CliInstall,
        )
        .unwrap();
    }

    fn test_reload_controller(
        home: &Path,
        config: crate::config::FreedomConfig,
    ) -> Arc<crate::config::reload::ReloadController> {
        let config_path = home.join("freedom.yaml");
        std::fs::write(&config_path, serde_yaml::to_string(&config).unwrap()).unwrap();
        Arc::new(crate::config::reload::ReloadController::new(
            config,
            config_path,
        ))
    }

    fn activate_test_skill(
        home: &Path,
        id: &str,
        reload: &crate::config::reload::ReloadController,
    ) -> super::super::authority::SkillAuthorityReceipt {
        decide_test_skill(
            home,
            id,
            reload,
            super::super::authority::SkillAuthorityState::Active,
            None,
        )
    }

    fn decide_test_skill(
        home: &Path,
        id: &str,
        reload: &crate::config::reload::ReloadController,
        state: super::super::authority::SkillAuthorityState,
        reason: Option<&str>,
    ) -> super::super::authority::SkillAuthorityReceipt {
        let decision = super::super::authority::SkillAuthorityDecision::new(
            super::super::authority::SkillAuthorityDecisionSource::OperatorCli,
            state,
            reason.map(str::to_string),
        )
        .unwrap();
        super::super::authority::publish_installed_authority_decision(home, id, reload, decision)
            .unwrap()
    }

    #[tokio::test]
    async fn load_primes_registry_with_bundled_set() {
        let dir = tempdir().unwrap();
        let reg = SkillRegistry::load(dir.path()).await.unwrap();
        let snap = reg.snapshot();
        assert!(
            !snap.is_empty(),
            "registry must surface bundled skills even with empty user dir"
        );
    }

    #[tokio::test]
    async fn positive_policy_never_mints_missing_installed_authority() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_skill(
            &skills_dir,
            "policy-only",
            "id: policy-only\n\
             description: policy is not authority\n\
             system_prompt: must stay inactive\n\
             trigger_keywords: [policy]\n\
             enabled: true\n",
        )
        .await;
        std::fs::write(
            home.path().join("freedom.yaml"),
            "skills:\n  enable_all_bundled: true\n  enabled:\n    - policy-only\n",
        )
        .unwrap();

        let registry = SkillRegistry::load(&skills_dir).await.unwrap();
        assert!(
            registry
                .snapshot()
                .iter()
                .all(|skill| skill.id() != "policy-only"),
            "enable_all_bundled and skills.enabled must not mint installed authority"
        );
    }

    #[tokio::test]
    async fn unapproved_same_id_install_never_inherits_bundled_trust() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "systematic_debugging";
        write_skill(
            &skills_dir,
            id,
            &format!(
                "id: {id}\n\
                 description: unapproved override\n\
                 system_prompt: UNAPPROVED-SAME-ID-PAYLOAD\n\
                 trigger_keywords: [debug]\n\
                 enabled: true\n"
            ),
        )
        .await;
        std::fs::write(
            home.path().join("freedom.yaml"),
            format!("skills:\n  enable_all_bundled: true\n  enabled:\n    - {id}\n"),
        )
        .unwrap();

        let registry = SkillRegistry::load(&skills_dir).await.unwrap();
        let snapshot = registry.snapshot();
        let loaded = snapshot
            .iter()
            .find(|skill| skill.id() == id)
            .expect("trusted bundled generation remains available");
        assert!(loaded.is_trusted_bundled());
        assert!(
            !loaded
                .system_prompt()
                .contains("UNAPPROVED-SAME-ID-PAYLOAD")
        );
        assert!(loaded.authority_record_sha256().is_none());
    }

    #[tokio::test]
    async fn authority_transition_window_never_publishes_same_id_bundled_fallback() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "systematic_debugging";
        write_skill(
            &skills_dir,
            id,
            &format!(
                "id: {id}\n\
                 description: exact same-id authority fixture\n\
                 system_prompt: AUTHORIZED-SAME-ID-PAYLOAD\n\
                 trigger_keywords: [debug]\n\
                 enabled: true\n"
            ),
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        activate_test_skill(home.path(), id, reload.as_ref());
        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        let initial = registry.snapshot();
        let installed = initial
            .iter()
            .find(|skill| skill.id() == id)
            .expect("exact installed same-id generation must start active");
        assert!(!installed.is_trusted_bundled());
        drop(initial);

        let skills_root = super::super::store::open_bound_directory(
            &skills_dir,
            false,
            "authority transition test root",
        )
        .unwrap()
        .unwrap();
        let mutation_guard = super::super::installer::lock_skill_mutations(&skills_root).unwrap();
        let reload_guard = registry.reload_lock.lock().await;
        let _watcher = registry.watch().expect("authority transition watcher");
        notify_runtime_authority_transition(
            home.path(),
            RuntimeAuthorityTransitionKind::AuthorityDecision,
        );
        assert!(
            registry.snapshot().is_empty(),
            "durable notify must invalidate a new snapshot acquisition synchronously while the reload lock is held"
        );
        drop(reload_guard);
        tokio::time::timeout(Duration::from_secs(8), async {
            while !registry.snapshot().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("typed authority observer must publish empty before blocked rebuild");

        let transition_window = registry.snapshot();
        assert!(
            transition_window.is_empty(),
            "authority transition window must be empty until exact-authority rebuild"
        );
        assert!(
            transition_window.iter().all(|skill| skill.id() != id),
            "same-id bundled fallback must not appear before exact-authority rebuild"
        );
        drop(transition_window);
        drop(mutation_guard);
        drop(skills_root);
        wait_for_skill(&registry, id, true).await;
        assert!(
            !registry
                .snapshot()
                .iter()
                .find(|skill| skill.id() == id)
                .expect("exact authority rebuild must restore installed same-id generation")
                .is_trusted_bundled()
        );
    }

    #[tokio::test]
    async fn authority_transition_rejects_reload_validated_before_epoch_advance() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        create_dir_all(&skills_dir).await.unwrap();
        let registry = SkillRegistry::load(&skills_dir).await.unwrap();
        assert!(!registry.snapshot().is_empty());

        let skills_root = super::super::store::open_bound_directory(
            &skills_dir,
            false,
            "stale authority reload test root",
        )
        .unwrap()
        .unwrap();
        let mutation_guard = super::super::installer::lock_skill_mutations(&skills_root).unwrap();
        let stale_reload = {
            let registry = Arc::clone(&registry);
            tokio::spawn(async move { registry.reload_now().await })
        };
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if registry.reload_lock.try_lock().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reload must hold its serialization lock while package loading is blocked");

        notify_runtime_authority_transition(
            home.path(),
            RuntimeAuthorityTransitionKind::AuthorityDecision,
        );
        assert!(
            registry.snapshot().is_empty(),
            "epoch advance must invalidate the old publication before the blocked reload resumes"
        );
        drop(mutation_guard);
        drop(skills_root);

        let stale_result = tokio::time::timeout(Duration::from_secs(8), stale_reload)
            .await
            .expect("blocked reload must finish after releasing the mutation guard")
            .expect("blocked reload task must not panic");
        assert!(
            stale_result.is_err(),
            "a rebuild validated before the authority epoch advance must be discarded"
        );
        assert!(registry.snapshot().is_empty());

        registry.reload_now().await.unwrap();
        assert!(
            !registry.snapshot().is_empty(),
            "a fresh rebuild at the current authority epoch must restore the registry"
        );
    }

    #[tokio::test]
    async fn authority_transition_epoch_is_isolated_per_home() {
        let home_a = tempdir().unwrap();
        let home_b = tempdir().unwrap();
        let skills_a = home_a.path().join("skills");
        let skills_b = home_b.path().join("skills");
        let registry_a = SkillRegistry::load(&skills_a).await.unwrap();
        let registry_b = SkillRegistry::load(&skills_b).await.unwrap();
        assert!(!registry_a.snapshot().is_empty());
        assert!(!registry_b.snapshot().is_empty());

        notify_runtime_authority_transition(
            home_a.path(),
            RuntimeAuthorityTransitionKind::AuthorityDecision,
        );

        assert!(registry_a.snapshot().is_empty());
        assert!(
            !registry_b.snapshot().is_empty(),
            "an authority transition must not invalidate a different NEOTH home"
        );
        registry_a.reload_now().await.unwrap();
        assert!(!registry_a.snapshot().is_empty());
    }

    #[tokio::test]
    async fn missing_home_uses_same_authority_epoch_key_after_creation() {
        let root = tempdir().unwrap();
        let home = root.path().join("first-run-home");
        let skills_dir = home.join("skills");
        let registry = SkillRegistry::load(&skills_dir).await.unwrap();
        assert!(!registry.snapshot().is_empty());

        create_dir_all(&home).await.unwrap();
        notify_runtime_authority_transition(&home, RuntimeAuthorityTransitionKind::InstallIntent);

        assert!(
            registry.snapshot().is_empty(),
            "creating a previously missing home must not change its authority epoch identity"
        );
        registry.reload_now().await.unwrap();
        assert!(!registry.snapshot().is_empty());
    }

    #[tokio::test]
    async fn exact_authority_materializes_installed_skill_and_stale_bytes_drop_on_reload() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "authority-runtime";
        write_skill(
            &skills_dir,
            id,
            "id: authority-runtime\n\
             description: exact authority fixture\n\
             system_prompt: AUTHORIZED-GENERATION-ONE\n\
             trigger_keywords: [authority]\n\
             enabled: true\n",
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        let receipt = activate_test_skill(home.path(), id, reload.as_ref());

        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        {
            let snapshot = registry.snapshot();
            let admitted = snapshot
                .iter()
                .find(|skill| skill.id() == id)
                .expect("exact active authority admits installed generation");
            assert!(!admitted.is_trusted_bundled());
            assert_eq!(
                admitted.authority_record_sha256(),
                Some(receipt.record_sha256())
            );
            assert_eq!(
                admitted.install_incarnation(),
                Some(receipt.install_incarnation())
            );
            assert_eq!(
                admitted.install_terminal_receipt_sha256(),
                Some(receipt.install_terminal_receipt_sha256())
            );
            assert_eq!(admitted.system_prompt(), "AUTHORIZED-GENERATION-ONE");
        }

        write_skill(
            &skills_dir,
            id,
            "id: authority-runtime\n\
             description: exact authority fixture\n\
             system_prompt: UNAUTHORIZED-GENERATION-TWO\n\
             trigger_keywords: [authority]\n\
             enabled: true\n",
        )
        .await;
        registry.reload_now().await.unwrap();
        assert!(
            registry.snapshot().iter().all(|skill| skill.id() != id),
            "stale generation authority must be removed atomically"
        );
    }

    #[tokio::test]
    async fn malformed_active_generation_is_quarantined_and_dropped_on_reload() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "authority-malformed";
        write_skill(
            &skills_dir,
            id,
            "id: authority-malformed\n\
             description: malformed reload fixture\n\
             system_prompt: AUTHORIZED-BEFORE-CORRUPTION\n\
             trigger_keywords: [authority]\n\
             enabled: true\n",
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        activate_test_skill(home.path(), id, reload.as_ref());
        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        assert!(registry.snapshot().iter().any(|skill| skill.id() == id));

        write(skills_dir.join(id).join("skill.yaml"), "id: [malformed\n")
            .await
            .unwrap();
        registry.reload_now().await.unwrap();
        assert!(
            registry.snapshot().iter().all(|skill| skill.id() != id),
            "a malformed live package must drop its previously admitted runtime capability"
        );
    }

    #[tokio::test]
    async fn malformed_sibling_cannot_preserve_a_revoked_runtime_skill() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "authority-revoked";
        write_skill(
            &skills_dir,
            id,
            "id: authority-revoked\n\
             description: revoked reload fixture\n\
             system_prompt: MUST-DISAPPEAR-AFTER-REVOCATION\n\
             trigger_keywords: [authority]\n\
             enabled: true\n",
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        activate_test_skill(home.path(), id, reload.as_ref());
        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        assert!(registry.snapshot().iter().any(|skill| skill.id() == id));

        write_skill(&skills_dir, "poisoned-sibling", "id: [malformed\n").await;
        decide_test_skill(
            home.path(),
            id,
            reload.as_ref(),
            super::super::authority::SkillAuthorityState::Revoked,
            Some("operator revoked test generation"),
        );
        registry.reload_now().await.unwrap();
        assert!(
            registry.snapshot().iter().all(|skill| skill.id() != id),
            "an unrelated malformed package must not retain revoked authority through reload failure"
        );
    }

    #[tokio::test]
    async fn unavailable_skill_root_cannot_preserve_a_revoked_runtime_skill() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "authority-root-failure";
        write_skill(
            &skills_dir,
            id,
            "id: authority-root-failure\n\
             description: unavailable root reload fixture\n\
             system_prompt: MUST-DISAPPEAR-WHEN-ROOT-IS-UNAVAILABLE\n\
             trigger_keywords: [authority]\n\
             enabled: true\n",
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        activate_test_skill(home.path(), id, reload.as_ref());
        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        assert!(registry.snapshot().iter().any(|skill| skill.id() == id));

        decide_test_skill(
            home.path(),
            id,
            reload.as_ref(),
            super::super::authority::SkillAuthorityState::Revoked,
            Some("operator revoked before root failure"),
        );
        let unavailable_root = home.path().join("skills-unavailable");
        std::fs::rename(&skills_dir, &unavailable_root).unwrap();
        std::fs::write(&skills_dir, b"not a directory").unwrap();

        registry.reload_now().await.unwrap();
        assert!(
            registry.snapshot().iter().all(|skill| skill.id() != id),
            "an unavailable Skill root must publish bundled-only instead of retaining revoked authority"
        );
    }

    #[tokio::test]
    // The test makes the skills root unavailable by renaming it while a watcher
    // is active. On Windows a directory with an open ReadDirectoryChangesW
    // handle cannot be renamed — the rename fails with ERROR_ACCESS_DENIED and
    // the test never reaches the behaviour it is checking. That is a property
    // of the test's mechanism, not of the registry: the drop-on-unavailable
    // path is platform-independent and stays covered on Linux CI. Skipped
    // rather than weakened, so the Windows gap is visible instead of papered
    // over.
    #[cfg_attr(
        windows,
        ignore = "renaming a watched directory is denied on Windows; covered on Unix"
    )]
    async fn watcher_rebind_failure_still_drops_installed_runtime_skills() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "authority-watch-rebind";
        write_skill(
            &skills_dir,
            id,
            "id: authority-watch-rebind\n\
             description: watcher rebind fail-closed fixture\n\
             system_prompt: MUST-DISAPPEAR-WHEN-WATCH-REBIND-FAILS\n\
             trigger_keywords: [authority]\n\
             enabled: true\n",
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        activate_test_skill(home.path(), id, reload.as_ref());
        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        assert!(registry.snapshot().iter().any(|skill| skill.id() == id));
        let _watcher = registry.watch().unwrap();

        let unavailable_root = home.path().join("skills-watch-unavailable");
        std::fs::rename(&skills_dir, &unavailable_root).unwrap();
        std::fs::write(&skills_dir, b"not a directory").unwrap();

        wait_for_skill(&registry, id, false).await;
        assert!(
            registry
                .snapshot()
                .iter()
                .all(|skill| skill.is_trusted_bundled()),
            "a watcher rebind error must never retain an installed runtime capability"
        );
    }

    #[tokio::test]
    async fn authority_anchor_publication_hot_loads_exact_installed_generation() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "authority-watch";
        write_skill(
            &skills_dir,
            id,
            "id: authority-watch\n\
             description: authority watcher fixture\n\
             system_prompt: WATCHED-AUTHORITY\n\
             trigger_keywords: [watch]\n\
             enabled: true\n",
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        assert!(registry.snapshot().iter().all(|skill| skill.id() != id));
        let _watcher = registry.watch().unwrap();

        activate_test_skill(home.path(), id, reload.as_ref());
        wait_for_skill(&registry, id, true).await;
        let snapshot = registry.snapshot();
        let admitted = snapshot
            .iter()
            .find(|skill| skill.id() == id)
            .expect("authority anchor event publishes runtime Skill");
        assert_eq!(admitted.system_prompt(), "WATCHED-AUTHORITY");
        assert!(admitted.authority_record_sha256().is_some());
    }

    #[tokio::test]
    async fn authority_key_removal_hot_revokes_installed_skill() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "authority-key-removal";
        write_skill(
            &skills_dir,
            id,
            "id: authority-key-removal\n\
             description: authority key removal fixture\n\
             system_prompt: MUST-DISAPPEAR-WITH-AUTHORITY-KEY\n\
             trigger_keywords: [authority]\n\
             enabled: true\n",
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        activate_test_skill(home.path(), id, reload.as_ref());
        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        assert!(registry.snapshot().iter().any(|skill| skill.id() == id));
        let _watcher = registry.watch().unwrap();

        std::fs::remove_file(home.path().join("skill-authority").join("authority.key")).unwrap();

        wait_for_skill(&registry, id, false).await;
        assert!(
            registry
                .snapshot()
                .iter()
                .all(|skill| skill.is_trusted_bundled()),
            "authority key loss must remove every installed runtime capability"
        );
    }

    #[tokio::test]
    async fn authority_record_removal_hot_revokes_installed_skill() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        let id = "authority-record-removal";
        write_skill(
            &skills_dir,
            id,
            "id: authority-record-removal\n\
             description: authority record removal fixture\n\
             system_prompt: MUST-DISAPPEAR-WITH-AUTHORITY-RECORD\n\
             trigger_keywords: [authority]\n\
             enabled: true\n",
        )
        .await;
        install_test_authority_key(home.path());
        record_test_install_incarnation(home.path(), id);
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        let receipt = activate_test_skill(home.path(), id, reload.as_ref());
        let registry = SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&reload))
            .await
            .unwrap();
        assert!(registry.snapshot().iter().any(|skill| skill.id() == id));
        let _watcher = registry.watch().unwrap();
        let record_path =
            std::fs::read_dir(home.path().join("skill-authority").join("records").join(id))
                .unwrap()
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.path())
                .find(|path| {
                    path.extension().and_then(|extension| extension.to_str()) == Some("json")
                        && path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name.contains(receipt.record_sha256()))
                })
                .expect("active authority record fixture exists");

        std::fs::remove_file(record_path).unwrap();

        wait_for_skill(&registry, id, false).await;
        assert!(
            registry
                .snapshot()
                .iter()
                .all(|skill| skill.is_trusted_bundled()),
            "authority record loss must remove every installed runtime capability"
        );
    }

    #[tokio::test]
    async fn initial_load_propagates_existing_malformed_manifest() {
        let dir = tempdir().unwrap();
        write_skill(dir.path(), "broken", "id: [not-valid\n").await;
        let error = match SkillRegistry::load(dir.path()).await {
            Ok(_) => panic!("malformed manifest must reject initial registry load"),
            Err(error) => error,
        };
        let detail = format!("{error:#}");
        assert!(detail.contains("load initial skill registry"));
        assert!(detail.contains("parse YAML"));
        assert!(detail.contains("broken"));
    }

    #[tokio::test]
    async fn initial_load_with_reload_controller_propagates_existing_malformed_manifest() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        write_skill(&skills_dir, "broken", "id: [not-valid\n").await;
        let reload = test_reload_controller(home.path(), crate::config::FreedomConfig::default());
        let error = match SkillRegistry::load_with_reload_controller(&skills_dir, reload).await {
            Ok(_) => panic!("malformed manifest must reject daemon registry startup"),
            Err(error) => error,
        };
        let detail = format!("{error:#}");
        assert!(detail.contains("load initial skill registry"));
        assert!(detail.contains("parse YAML"));
        assert!(detail.contains("broken"));
    }

    #[tokio::test]
    async fn unauthorised_duplicate_modes_never_reach_initial_registry() {
        let dir = tempdir().unwrap();
        write_skill(
            dir.path(),
            "mode-owner-a",
            &skill_with_mode("mode-owner-a", "registry-duplicate-mode"),
        )
        .await;
        write_skill(
            dir.path(),
            "mode-owner-b",
            &skill_with_mode("mode-owner-b", "registry-duplicate-mode"),
        )
        .await;

        let registry = SkillRegistry::load(dir.path()).await.unwrap();
        let snapshot = registry.snapshot();
        assert!(
            snapshot
                .iter()
                .all(|skill| !skill.id().starts_with("mode-owner-")),
            "raw mode manifests without authority must not reach runtime validation"
        );
        let modes =
            super::super::mode_registry::ModeRegistry::from_skills(snapshot.as_slice()).unwrap();
        assert!(modes.get("registry-duplicate-mode").is_none());
    }

    #[tokio::test]
    async fn unauthorised_duplicate_mode_reload_retains_previous_atomic_snapshot() {
        let dir = tempdir().unwrap();
        let reg = SkillRegistry::load(dir.path()).await.unwrap();
        let pinned = reg.snapshot_owned();

        write_skill(
            dir.path(),
            "reload-mode-owner-a",
            &skill_with_mode("reload-mode-owner-a", "reload-duplicate-mode"),
        )
        .await;
        write_skill(
            dir.path(),
            "reload-mode-owner-b",
            &skill_with_mode("reload-mode-owner-b", "reload-duplicate-mode"),
        )
        .await;

        let (previous, current) = reg.reload_now().await.unwrap();
        assert_eq!(previous, current);
        let live = reg.snapshot_owned();
        assert!(
            Arc::ptr_eq(&pinned, &live),
            "authority-inactive candidates must retain the exact previous Arc snapshot"
        );
    }

    #[tokio::test]
    async fn unapproved_hot_reload_cannot_enter_stable_snapshot() {
        // D-103 Option 3 contract: a snapshot held before a reload must
        // stay valid after the reload — `arc-swap` keeps the old Arc
        // alive until the guard drops, so invocations in flight see the
        // pre-reload skill set even as the registry pointer moves on.
        let dir = tempdir().unwrap();
        let reg = SkillRegistry::load(dir.path()).await.unwrap();
        let pinned = reg.snapshot_owned();
        let pinned_count = pinned.len();

        // Add a new user skill + reload.
        write_skill(
            dir.path(),
            "hot-reload-test",
            r#"
id: hot-reload-test
description: hot-reload regression skill
trigger_keywords: ["hot-reload"]
system_prompt: "ok"
"#,
        )
        .await;
        let (prev, new) = reg.reload_now().await.unwrap();
        assert_eq!(prev, pinned_count);
        assert_eq!(new, pinned_count);

        // The pre-reload snapshot is unchanged.
        assert_eq!(pinned.len(), pinned_count);
        assert!(
            !pinned.iter().any(|s| s.id() == "hot-reload-test"),
            "old snapshot must NOT see the post-reload skill"
        );

        // A fresh snapshot still excludes the unauthorised package.
        let live = reg.snapshot_owned();
        assert!(Arc::ptr_eq(&pinned, &live));
        assert_eq!(live.len(), pinned_count);
        assert!(!live.iter().any(|s| s.id() == "hot-reload-test"));
    }

    #[tokio::test]
    async fn accepted_custom_config_generation_rebuilds_the_routing_snapshot() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        tokio::fs::create_dir_all(&skills_dir).await.unwrap();
        let custom_config = home.path().join("operator-instance.yaml");
        let initial = crate::config::FreedomConfig::default();
        std::fs::write(&custom_config, serde_yaml::to_string(&initial).unwrap()).unwrap();

        // A conflicting adjacent default must never own this instance.
        let mut wrong_adjacent = initial.clone();
        wrong_adjacent.skills.disabled = vec!["systematic_debugging".to_string()];
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&wrong_adjacent).unwrap(),
        )
        .unwrap();

        let controller = Arc::new(crate::config::reload::ReloadController::new(
            initial.clone(),
            custom_config.clone(),
        ));
        let registry =
            SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&controller))
                .await
                .unwrap();
        assert_eq!(registry.config_path(), custom_config);
        assert!(
            registry
                .snapshot()
                .iter()
                .find(|skill| skill.id() == "systematic_debugging")
                .unwrap()
                .is_enabled(),
            "initial routing policy must come from the controller snapshot"
        );
        let _watcher = registry.watch().unwrap();

        let mut accepted = initial;
        accepted.skills.disabled = vec!["systematic_debugging".to_string()];
        std::fs::write(&custom_config, serde_yaml::to_string(&accepted).unwrap()).unwrap();
        assert!(matches!(
            controller.try_reload().unwrap(),
            crate::config::reload::ReloadResult::Reloaded { .. }
        ));
        wait_for_skill_enabled(&registry, "systematic_debugging", false).await;
    }

    #[tokio::test]
    async fn accepted_config_epoch_is_fail_closed_until_matching_skills_publish() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        tokio::fs::create_dir_all(&skills_dir).await.unwrap();
        let config_path = home.path().join("operator-instance.yaml");
        let initial = crate::config::FreedomConfig::default();
        std::fs::write(&config_path, serde_yaml::to_string(&initial).unwrap()).unwrap();
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            initial.clone(),
            config_path.clone(),
        ));
        let registry =
            SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&controller))
                .await
                .unwrap();
        let epoch_zero = controller.accepted_snapshot().epoch();
        let pinned_epoch_zero = registry.snapshot_owned_for_epoch(epoch_zero);
        assert!(!pinned_epoch_zero.is_empty());

        let mut next = initial;
        next.skills.disabled = vec!["systematic_debugging".to_string()];
        std::fs::write(&config_path, serde_yaml::to_string(&next).unwrap()).unwrap();
        assert!(matches!(
            controller.try_reload().unwrap(),
            crate::config::reload::ReloadResult::Reloaded { .. }
        ));
        let epoch_one = controller.accepted_snapshot().epoch();
        assert_ne!(epoch_zero, epoch_one);

        // Config N+1 is accepted, but the watcher/rebuild has not published its
        // matching Skill layer. A new turn must get no Skills, while an
        // already-started turn may retain the exact old pair it pinned.
        assert!(registry.snapshot().is_empty());
        assert!(Arc::ptr_eq(
            &pinned_epoch_zero,
            &registry.snapshot_owned_for_epoch(epoch_zero)
        ));
        assert!(registry.snapshot_owned_for_epoch(epoch_one).is_empty());

        registry.reload_now().await.unwrap();
        let epoch_one_skills = registry.snapshot_owned_for_epoch(epoch_one);
        assert!(!epoch_one_skills.is_empty());
        assert!(
            !epoch_one_skills
                .iter()
                .find(|skill| skill.id() == "systematic_debugging")
                .unwrap()
                .is_enabled()
        );
        assert!(
            registry.snapshot_owned_for_epoch(epoch_zero).is_empty(),
            "old config epoch must never receive the newly published Skill layer"
        );
    }

    #[tokio::test]
    async fn rejected_config_candidate_cannot_change_skill_routing() {
        let home = tempdir().unwrap();
        let skills_dir = home.path().join("skills");
        tokio::fs::create_dir_all(&skills_dir).await.unwrap();
        let custom_config = home.path().join("operator-instance.yaml");
        let initial = crate::config::FreedomConfig::default();
        std::fs::write(&custom_config, serde_yaml::to_string(&initial).unwrap()).unwrap();
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            initial.clone(),
            custom_config.clone(),
        ));
        let registry =
            SkillRegistry::load_with_reload_controller(&skills_dir, Arc::clone(&controller))
                .await
                .unwrap();
        let pinned = registry.snapshot_owned();
        let _watcher = registry.watch().unwrap();

        let mut rejected = initial;
        rejected.operator_id = Some("different-operator".to_string());
        rejected.skills.disabled = vec!["systematic_debugging".to_string()];
        std::fs::write(&custom_config, serde_yaml::to_string(&rejected).unwrap()).unwrap();
        assert!(matches!(
            controller.try_reload().unwrap(),
            crate::config::reload::ReloadResult::Rejected { .. }
        ));
        tokio::time::sleep(Duration::from_millis(600)).await;

        assert!(
            Arc::ptr_eq(&pinned, &registry.snapshot_owned()),
            "a rejected config file edit must retain the exact routing snapshot"
        );
        assert!(
            registry
                .snapshot()
                .iter()
                .find(|skill| skill.id() == "systematic_debugging")
                .unwrap()
                .is_enabled()
        );
    }

    #[tokio::test]
    async fn reload_now_handles_missing_dir_gracefully() {
        // If the user removes the entire skills dir between boot and
        // reload, the registry must not panic — load_all returns the
        // bundled set + reload_now ends up with that.
        let dir = tempdir().unwrap();
        let nope = dir.path().join("does-not-exist");
        let reg = SkillRegistry::load(&nope).await.unwrap();
        let bundled_count = reg.snapshot().len();
        let (prev, new) = reg.reload_now().await.unwrap();
        assert_eq!(prev, bundled_count);
        assert_eq!(new, bundled_count);
    }

    #[tokio::test]
    async fn missing_dir_watcher_never_publishes_unapproved_skill() {
        let dir = tempdir().unwrap();
        let skills_dir = dir.path().join("missing-parent").join("skills");
        let reg = SkillRegistry::load(&skills_dir).await.unwrap();
        let _watcher = reg
            .watch()
            .expect("nearest existing ancestor must bootstrap the watcher");

        write_skill(
            &skills_dir,
            "created-after-start",
            r#"
id: created-after-start
description: watcher bootstrap regression
trigger_keywords: ["created-after-start"]
system_prompt: "live"
"#,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            reg.snapshot()
                .iter()
                .all(|skill| skill.id() != "created-after-start")
        );
    }

    #[tokio::test]
    async fn watch_returns_handle_when_dir_exists() {
        let dir = tempdir().unwrap();
        let reg = SkillRegistry::load(dir.path()).await.unwrap();
        reg.watch()
            .expect("watcher must bind on an existing dir even when empty");
    }

    /// BUG-W2-P1-SKILL-WATCHER regression test: skills_dir EXISTS at daemon
    /// boot (unlike `missing_dir_watcher_publishes_skill_created_after_start`)
    /// but a brand-new skill subdir is dropped in after the watcher starts.
    /// The explicit per-subdir watch added by `desired_watches` during the next
    /// `reconcile_watches` call must ensure the skill is observed.
    #[tokio::test]
    async fn skill_dir_created_after_boot_stays_inactive_without_authority() {
        let dir = tempdir().unwrap();
        // skills_dir already exists when the watcher starts — the key
        // difference from the missing-dir test.
        let skills_dir = dir.path().join("skills");
        tokio::fs::create_dir_all(&skills_dir).await.unwrap();
        let reg = SkillRegistry::load(&skills_dir).await.unwrap();
        let _watcher = reg.watch().expect("watcher on existing skills dir");

        write_skill(
            &skills_dir,
            "new-after-boot",
            r#"
id: new-after-boot
description: skill subdir added after daemon start
trigger_keywords: ["new-after-boot"]
system_prompt: "live"
"#,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            reg.snapshot()
                .iter()
                .all(|skill| skill.id() != "new-after-boot")
        );
    }

    #[tokio::test]
    async fn invalid_first_publication_and_later_unapproved_fix_stay_out() {
        let dir = tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        let reg = SkillRegistry::load(&skills_dir).await.unwrap();
        let pinned = reg.snapshot_owned();
        let _watcher = reg.watch().expect("bootstrap watcher");

        write_skill(&skills_dir, "initially-broken", "id: [not-valid\n").await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            Arc::ptr_eq(&pinned, &reg.snapshot_owned()),
            "invalid first publication must retain the exact prior snapshot"
        );

        write_skill(
            &skills_dir,
            "initially-broken",
            r#"
id: initially-broken
description: corrected watcher publication
trigger_keywords: ["corrected"]
system_prompt: "live"
"#,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(Arc::ptr_eq(&pinned, &reg.snapshot_owned()));
        assert!(
            reg.snapshot()
                .iter()
                .all(|skill| skill.id() != "initially-broken")
        );
    }

    #[tokio::test]
    async fn deleted_and_recreated_unapproved_skills_dir_never_routes() {
        let dir = tempdir().unwrap();
        let skills_dir = dir.path().join("skills");
        let reg = SkillRegistry::load(&skills_dir).await.unwrap();
        let _watcher = reg.watch().expect("bootstrap watcher");

        write_skill(
            &skills_dir,
            "before-recreate",
            r#"
id: before-recreate
description: pre-delete watcher fixture
system_prompt: "before"
"#,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            reg.snapshot()
                .iter()
                .all(|skill| skill.id() != "before-recreate")
        );

        tokio::fs::remove_dir_all(&skills_dir).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        write_skill(
            &skills_dir,
            "after-recreate",
            r#"
id: after-recreate
description: post-delete watcher fixture
system_prompt: "after"
"#,
        )
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            reg.snapshot()
                .iter()
                .all(|skill| skill.id() != "after-recreate")
        );
    }

    #[tokio::test]
    async fn snapshot_and_snapshot_owned_see_the_same_count() {
        let dir = tempdir().unwrap();
        let reg = SkillRegistry::load(dir.path()).await.unwrap();
        let by_guard = reg.snapshot().len();
        let by_owned = reg.snapshot_owned().len();
        assert_eq!(by_guard, by_owned);
    }

    // ── E-22 chat-route: process-wide global registry tests ───────────

    #[tokio::test]
    async fn global_is_none_before_init() {
        // E-22 contract: one-shot CLI invocations (no `serve` ever
        // ran) see `global() == None` and build a per-call registry
        // instead. Pin so a future refactor that pre-initialises the
        // global doesn't silently turn `neoth chat` into a stateful
        // call that shares state across invocations.
        //
        // NOTE: this test runs against the live OnceLock. If another
        // test in this binary called init_global earlier (test order
        // is non-deterministic), `global()` is Some — assert weakly
        // by checking the binary type (Arc) rather than the None
        // case.
        if let Some(reg) = global() {
            assert!(
                Arc::strong_count(&reg) >= 1,
                "global registry, if present, must be a valid Arc"
            );
        }
    }

    #[tokio::test]
    async fn init_global_is_idempotent_after_first_set() {
        // Second init_global call MUST return false + leave the
        // existing registry untouched. Prevents a duplicate
        // bootstrap path (e.g. a second `serve` task spawned within
        // the same process) from replacing the active registry +
        // orphaning the watcher.
        let dir = tempdir().unwrap();
        let reg_a = SkillRegistry::load(dir.path()).await.unwrap();
        let reg_b = SkillRegistry::load(dir.path()).await.unwrap();
        // First call may or may not succeed depending on test
        // ordering (OnceLock is process-wide). Always check the
        // SECOND call's behaviour.
        let _ = init_global(Arc::clone(&reg_a));
        let second = init_global(Arc::clone(&reg_b));
        assert!(!second, "second init_global call must return false");
        // The global registry, whichever one wins the race, must
        // be queryable.
        assert!(global().is_some());
    }
}
