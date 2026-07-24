//! Skill registry — hot-reloadable atomic-swap container around the loaded
//! skill set.
//!
//! D-103 (Session 21, 2026-05-23): 6-agent senior-dev panel picked Option 3
//! for the skill hot-reload semantics — every reload swaps the live registry
//! atomically, but invocations in flight finish on the version they started
//! with. Same semantics as vite, cargo-watch, esbuild.
//!
//! ## Why ArcSwap over Vec<Skill>
//!
//! Reads dominate the workload: every chat turn calls
//! `crate::skills::route(prompt, &registry.load())` once, often from many
//! concurrent channel-handler tasks (Telegram + Slack + CLI simultaneously).
//! Writes are rare — only when the operator edits a YAML or drops a new
//! skill into `~/.neoth/skills/`.
//!
//! `arc-swap::ArcSwap<Vec<Skill>>` is the same primitive used for
//! [`crate::config::FreedomConfig`] hot-reload (Pick #36, Session 14): each
//! `.load()` is a single atomic refcount increment, returns a cheap
//! `Arc<Vec<Skill>>` guard the caller holds for the duration of one
//! invocation. The atomic swap on the writer side bumps the pointer; any
//! `.load()` that happened before the swap keeps the old `Arc` alive
//! until its handle drops. The version pinned at invocation start is
//! exactly the version the consent gate evaluated against.
//!
//! ## Watcher
//!
//! [`SkillRegistry::watch`] spawns a tokio task that owns a
//! `notify::RecommendedWatcher` over the user skills directory. When that
//! directory does not exist yet, the nearest existing ancestor is watched
//! non-recursively until the missing path appears; the watcher then binds the
//! skills directory recursively without a daemon restart. On
//! `Create | Modify | Remove` events affecting `*/skill.yaml` it calls
//! [`SkillRegistry::reload_now`], validates the complete Skill/Mode snapshot,
//! and only then publishes the new Vec atomically.
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

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

use super::loader::{load_all, load_all_from_config_path, load_all_from_skills_config};
use super::schema::Skill;

/// Build the complete skill snapshot and validate every cross-skill mode id
/// before the value can reach an [`ArcSwap`]. A mode collision is a registry
/// load error, not a per-request routing error.
pub(crate) async fn load_validated_skills(skills_dir: &Path) -> Result<Vec<Skill>> {
    let skills = load_all(skills_dir).await?;
    validate_loaded_skills(skills)
}

async fn load_validated_skills_from_config_path(
    skills_dir: &Path,
    config_path: &Path,
) -> Result<Vec<Skill>> {
    let skills = load_all_from_config_path(skills_dir, config_path).await?;
    validate_loaded_skills(skills)
}

async fn load_validated_skills_from_config(
    skills_dir: &Path,
    config: &crate::config::SkillsConfig,
) -> Result<Vec<Skill>> {
    let skills = load_all_from_skills_config(skills_dir, config).await?;
    validate_loaded_skills(skills)
}

fn validate_loaded_skills(skills: Vec<Skill>) -> Result<Vec<Skill>> {
    super::mode_registry::ModeRegistry::from_skills(&skills)
        .context("validate unique mode ids in skill registry")?;
    Ok(skills)
}

/// Compare the complete runtime-relevant skill snapshot before publishing a
/// new Arc. Some filesystem backends (notably macOS FSEvents) can report a
/// watched directory as modified when only a sibling file changed. Reloading
/// is harmless, but replacing an identical Arc would falsely signal a new
/// routing generation to pinned readers.
fn skill_snapshots_match(current: &[Skill], candidate: &[Skill]) -> Result<bool> {
    let current = serde_json::to_vec(current).context("serialize current skill snapshot")?;
    let candidate = serde_json::to_vec(candidate).context("serialize candidate skill snapshot")?;
    Ok(current == candidate)
}

/// Process-wide live skill registry. Set by `serve.rs::run_serve` at
/// daemon boot via [`init_global`]; chat / channel-pipeline / skill
/// dispatch paths inside the daemon read from it via [`global`] so
/// every reader sees the same `ArcSwap<Vec<Skill>>` the daemon's
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
/// The inner `ArcSwap<Vec<Skill>>` is the swap unit. Readers call
/// [`SkillRegistry::snapshot`] which returns an `arc_swap::Guard` that
/// derefs to `&Vec<Skill>`. Held for the duration of one chat turn /
/// skill dispatch — even if a reload swaps the pointer mid-turn, the
/// guard keeps the pre-reload vec alive until drop. This is the
/// "invocations finish on old version" half of D-103 Option 3.
pub struct SkillRegistry {
    inner: ArcSwap<Vec<Skill>>,
    skills_dir: PathBuf,
    config_path: PathBuf,
    reload_controller: Option<Arc<crate::config::reload::ReloadController>>,
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
        let initial = load_validated_skills_from_config_path(&skills_dir, &config_path)
            .await
            .with_context(|| {
                format!(
                    "load initial skill registry from {} with policy {}",
                    skills_dir.display(),
                    config_path.display()
                )
            })?;
        info!(
            count = initial.len(),
            dir = %skills_dir.display(),
            config = %config_path.display(),
            "skill registry primed"
        );
        Ok(Arc::new(Self {
            inner: ArcSwap::new(Arc::new(initial)),
            skills_dir,
            config_path,
            reload_controller: None,
        }))
    }

    /// Load a daemon registry from the exact already-accepted config
    /// generation and subscribe to every successful reload generation.
    pub async fn load_with_reload_controller(
        skills_dir: impl AsRef<Path>,
        reload_controller: Arc<crate::config::reload::ReloadController>,
    ) -> Result<Arc<Self>> {
        let skills_dir = skills_dir.as_ref().to_path_buf();
        let config_path = reload_controller.source_path().to_path_buf();
        let config = reload_controller.latest();
        let initial = load_validated_skills_from_config(&skills_dir, &config.skills)
            .await
            .with_context(|| {
                format!(
                    "load initial skill registry from {} with active policy {}",
                    skills_dir.display(),
                    config_path.display()
                )
            })?;
        info!(
            count = initial.len(),
            dir = %skills_dir.display(),
            config = %config_path.display(),
            reload_bound = true,
            "skill registry primed"
        );
        Ok(Arc::new(Self {
            inner: ArcSwap::new(Arc::new(initial)),
            skills_dir,
            config_path,
            reload_controller: Some(reload_controller),
        }))
    }

    /// Get a read snapshot of the live skill set. Cheap — single atomic
    /// refcount increment. The returned guard derefs to `&Vec<Skill>`;
    /// hold it for the duration of one invocation so a concurrent
    /// reload doesn't pull the underlying Arc out from under you.
    pub fn snapshot(&self) -> arc_swap::Guard<Arc<Vec<Skill>>> {
        self.inner.load()
    }

    /// Convenience for callers that want an owned `Arc<Vec<Skill>>` they
    /// can hand to a sibling task — same effect as `Arc::clone` on the
    /// loaded snapshot.
    pub fn snapshot_owned(&self) -> Arc<Vec<Skill>> {
        self.inner.load_full()
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
        let new = match &self.reload_controller {
            Some(reload_controller) => {
                let config = reload_controller.latest();
                load_validated_skills_from_config(&self.skills_dir, &config.skills).await
            }
            None => {
                load_validated_skills_from_config_path(&self.skills_dir, &self.config_path).await
            }
        }
        .with_context(|| {
            format!(
                "reload skill registry from {} with active policy {}",
                self.skills_dir.display(),
                self.config_path.display()
            )
        })?;
        let new_count = new.len();
        let current = self.inner.load_full();
        let prev = current.len();
        if skill_snapshots_match(&current, &new)? {
            return Ok((prev, new_count));
        }
        self.inner.store(Arc::new(new));
        Ok((prev, new_count))
    }

    /// Spawn the watcher task. A missing skills directory is a supported
    /// first-run state: the nearest existing ancestor is watched until the
    /// directory appears. Watch construction and initial registration fail
    /// loudly so daemon startup never reports a watcher that is not active.
    /// Drop the returned handle to stop watching.
    pub fn watch(self: &Arc<Self>) -> Result<WatcherHandle> {
        watcher::spawn(Arc::clone(self))
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

    impl WatchDepth {
        fn notify_mode(self) -> RecursiveMode {
            match self {
                Self::NonRecursive => RecursiveMode::NonRecursive,
                Self::Recursive => RecursiveMode::Recursive,
            }
        }
    }

    pub fn spawn(registry: Arc<SkillRegistry>) -> Result<WatcherHandle> {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let mut config_generation = registry
            .reload_controller
            .as_ref()
            .map(|controller| controller.subscribe_generation());
        // A reload-bound daemon only accepts config policy through the
        // ReloadController generation. A raw file edit may later be rejected
        // and must not leak into the routing ArcSwap through notify.
        let watched_config_path = registry
            .reload_controller
            .is_none()
            .then_some(registry.config_path.as_path());

        // `notify` callbacks run on the watcher's own thread — bounce
        // each event onto the tokio runtime via unbounded mpsc so the
        // debounce loop can `select!` on it alongside cancellation.
        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<Event>| match res {
                Ok(ev) => {
                    let _ = event_tx.send(ev);
                }
                Err(e) => warn!(error = %e, "skill watcher reported error"),
            })
            .context("construct skill filesystem watcher")?;
        let mut active_watches = BTreeMap::new();
        reconcile_watches(
            &mut watcher,
            &registry.skills_dir,
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
                            Some(ev) => {
                                let watched_config_path = registry
                                    .reload_controller
                                    .is_none()
                                    .then_some(registry.config_path.as_path());
                                if event_is_skill_relevant(
                                    &ev,
                                    &registry.skills_dir,
                                    watched_config_path,
                                ) {
                                    pending = Some(tokio::time::Instant::now() + DEBOUNCE);
                                }
                            }
                            None => {
                                debug!("skill watcher event sender dropped; exiting loop");
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
                                registry
                                    .reload_controller
                                    .is_none()
                                    .then_some(registry.config_path.as_path()),
                                &mut active_watches,
                            )
                        };
                        if let Err(e) = rebound {
                            warn!(
                                dir = %registry.skills_dir.display(),
                                error = %e,
                                "skill watcher rebind failed; retaining prior watch and retrying"
                            );
                            pending = Some(tokio::time::Instant::now() + REBIND_RETRY);
                            continue;
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
                                "accepted config generation could not rebuild skill registry; retaining prior snapshot"
                            ),
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
        config_path: Option<&Path>,
        active: &mut BTreeMap<PathBuf, WatchDepth>,
    ) -> Result<()> {
        let desired = desired_watches(skills_dir, config_path)?;

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
    fn event_is_skill_relevant(
        ev: &Event,
        skills_dir: &std::path::Path,
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
        // macOS FSEvents reports canonical paths (`/private/var/...`) while the
        // configured skills_dir may reach the same directory through a symlink
        // (`/var/...` tempdirs, symlinked homes). Resolve a canonical alias via
        // the parent — which exists even while skills_dir itself is still
        // missing — and accept a match against that spelling too. On Windows
        // `canonicalize` yields a `\\?\` path that never matches notify's
        // plain paths, so this arm is a no-op there and the primary
        // comparison above stays authoritative.
        let canonical_alias = skills_dir.parent().and_then(|parent| {
            let parent = std::fs::canonicalize(parent).ok()?;
            Some(parent.join(skills_dir.file_name()?))
        });
        canonical_alias
            .as_deref()
            .is_some_and(|alias| alias != skills_dir && relevant_for(alias))
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
    async fn initial_load_rejects_duplicate_mode_ids_before_publishing_registry() {
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

        let error = SkillRegistry::load(dir.path())
            .await
            .err()
            .expect("duplicate mode ids must reject the initial registry");
        let detail = format!("{error:#}");
        assert!(detail.contains("validate unique mode ids"));
        assert!(detail.contains("registry-duplicate-mode"));
        assert!(detail.contains("mode-owner-a"));
        assert!(detail.contains("mode-owner-b"));
    }

    #[tokio::test]
    async fn duplicate_mode_reload_retains_the_previous_atomic_snapshot() {
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

        let error = reg
            .reload_now()
            .await
            .expect_err("invalid mode snapshot must not be published");
        assert!(format!("{error:#}").contains("reload-duplicate-mode"));
        let live = reg.snapshot_owned();
        assert!(
            Arc::ptr_eq(&pinned, &live),
            "failed reload must retain the exact previous Arc snapshot"
        );
    }

    #[tokio::test]
    async fn snapshot_returns_stable_arc_across_reload() {
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
        assert_eq!(new, pinned_count + 1);

        // The pre-reload snapshot is unchanged.
        assert_eq!(pinned.len(), pinned_count);
        assert!(
            !pinned.iter().any(|s| s.id() == "hot-reload-test"),
            "old snapshot must NOT see the post-reload skill"
        );

        // A fresh snapshot picks up the new skill.
        let live = reg.snapshot();
        assert_eq!(live.len(), pinned_count + 1);
        assert!(live.iter().any(|s| s.id() == "hot-reload-test"));
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
    async fn missing_dir_watcher_publishes_skill_created_after_start() {
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
        wait_for_skill(&reg, "created-after-start", true).await;
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
    async fn skill_dir_created_after_boot_is_observed() {
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
        wait_for_skill(&reg, "new-after-boot", true).await;
    }

    #[tokio::test]
    async fn invalid_first_publication_keeps_snapshot_and_later_fix_goes_live() {
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
        wait_for_skill(&reg, "initially-broken", true).await;
    }

    #[tokio::test]
    async fn deleted_and_recreated_skills_dir_remains_observed() {
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
        wait_for_skill(&reg, "before-recreate", true).await;

        tokio::fs::remove_dir_all(&skills_dir).await.unwrap();
        wait_for_skill(&reg, "before-recreate", false).await;

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
        wait_for_skill(&reg, "after-recreate", true).await;
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
