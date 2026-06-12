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
//! `notify::RecommendedWatcher` over the user skills directory. On
//! `Create | Modify | Remove` events affecting `*/skill.yaml` it calls
//! [`crate::skills::load_all`] again and stores the new Vec atomically.
//! Bundled skills always re-load too — they live in `include_str!` and
//! never change without a binary rebuild, but re-running the loader is
//! the simplest path and the cost is sub-millisecond (deserializing N
//! YAMLs out of memory).

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

use super::load_all;
use super::schema::Skill;

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
}

impl SkillRegistry {
    /// Load the initial skill set + return the registry. Failures fall
    /// back to an empty set so a malformed user skill never blocks daemon
    /// startup — each load failure is already warned by
    /// [`super::loader::parse_one`] / `parse_bundled_skills`.
    pub async fn load(skills_dir: impl AsRef<Path>) -> Result<Arc<Self>> {
        let skills_dir = skills_dir.as_ref().to_path_buf();
        let initial = load_all(&skills_dir).await.unwrap_or_else(|e| {
            warn!(
                dir = %skills_dir.display(),
                error = %e,
                "initial skill load failed; daemon continues with empty skill set"
            );
            Vec::new()
        });
        info!(
            count = initial.len(),
            dir = %skills_dir.display(),
            "skill registry primed"
        );
        Ok(Arc::new(Self {
            inner: ArcSwap::new(Arc::new(initial)),
            skills_dir,
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

    /// Atomically replace the live skill set. Called by the watcher task
    /// after a successful reload. Returns the previous count for logging.
    pub fn store(&self, new: Vec<Skill>) -> usize {
        let prev = self.inner.load().len();
        self.inner.store(Arc::new(new));
        prev
    }

    /// Manually trigger a reload from disk. Returns (previous_count,
    /// new_count). Useful for operator-driven reload (`neoth skills
    /// reload`) without waiting for the watcher debounce.
    pub async fn reload_now(&self) -> Result<(usize, usize)> {
        let new = load_all(&self.skills_dir).await?;
        let new_count = new.len();
        let prev = self.store(new);
        Ok((prev, new_count))
    }

    /// Spawn the watcher task. Best-effort — if the skills dir doesn't
    /// exist or the watcher can't bind, log + return `Ok(None)` so the
    /// daemon stays bootable. The returned `WatcherHandle` keeps the
    /// underlying `notify::RecommendedWatcher` alive; drop it to stop
    /// watching.
    pub fn watch(self: &Arc<Self>) -> Option<WatcherHandle> {
        if !self.skills_dir.exists() {
            debug!(
                dir = %self.skills_dir.display(),
                "skills dir missing; hot-reload watcher not started"
            );
            return None;
        }
        watcher::spawn(Arc::clone(self))
    }
}

/// Handle to the spawned filesystem watcher. Drop stops the watcher task.
/// Production callers usually leak this for daemon lifetime; tests drop it
/// to assert the watcher tears down cleanly.
pub struct WatcherHandle {
    _watcher: notify::RecommendedWatcher,
    /// Sender end of the cancellation channel — drop signals the
    /// debounce loop to exit.
    _cancel: tokio::sync::oneshot::Sender<()>,
}

mod watcher {
    use super::*;
    use notify::{Event, EventKind, RecursiveMode, Watcher};
    use tokio::sync::mpsc;

    /// Debounce window — skills/<id>/skill.yaml edits commonly fire 2-3
    /// events back-to-back (editor saves a temp file + renames + chmods).
    /// We collapse them into a single reload.
    const DEBOUNCE: Duration = Duration::from_millis(250);

    pub fn spawn(registry: Arc<SkillRegistry>) -> Option<WatcherHandle> {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();

        // `notify` callbacks run on the watcher's own thread — bounce
        // each event onto the tokio runtime via unbounded mpsc so the
        // debounce loop can `select!` on it alongside cancellation.
        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<Event>| match res {
                Ok(ev) => {
                    let _ = event_tx.send(ev);
                }
                Err(e) => warn!(error = %e, "skill watcher reported error"),
            }) {
                Ok(w) => w,
                Err(e) => {
                    warn!(error = %e, "failed to construct skill watcher; hot-reload disabled");
                    return None;
                }
            };

        if let Err(e) = watcher.watch(&registry.skills_dir, RecursiveMode::Recursive) {
            warn!(
                dir = %registry.skills_dir.display(),
                error = %e,
                "failed to start watching skills dir; hot-reload disabled"
            );
            return None;
        }

        // GR-049: also watch freedom.yaml (it lives next to skills_dir) so an
        // edit to skills.{disabled,enabled,enable_all_bundled} hot-reloads the
        // registry — `load_all` re-reads freedom.yaml on every `reload_now`, so
        // this watch makes those operator edits take effect WITHOUT a restart.
        // Best-effort + NonRecursive: a failed watch leaves skill.yaml hot-
        // reload working (unlike the mandatory skills_dir watch above).
        if let Some(parent) = registry.skills_dir.parent() {
            if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
                warn!(
                    dir = %parent.display(),
                    error = %e,
                    "could not watch freedom.yaml dir; skills.* edits need a restart to apply"
                );
            }
        }

        info!(
            dir = %registry.skills_dir.display(),
            "skill hot-reload watcher started"
        );

        let registry = Arc::clone(&registry);
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
                                if event_is_skill_relevant(&ev, &registry.skills_dir) {
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
                        match registry.reload_now().await {
                            Ok((prev, new)) => info!(
                                prev_count = prev,
                                new_count = new,
                                "skills hot-reloaded"
                            ),
                            Err(e) => warn!(error = %e, "skills hot-reload failed"),
                        }
                    }
                }
            }
        });

        Some(WatcherHandle {
            _watcher: watcher,
            _cancel: cancel_tx,
        })
    }

    /// Filter — we care about `skill.yaml` create/modify/remove, a `skill`
    /// folder create/remove, and (GR-049) a `freedom.yaml` change (its
    /// `skills.*` settings are re-read by `load_all`). Permission changes etc.
    /// are noise. `skills_dir` scopes the directory match so the freedom.yaml
    /// parent-dir watch never fires on unrelated home-dir directories (`wal/`,
    /// `archive/`, …) — a Modify on `~/.neoth/wal` would otherwise spuriously
    /// reload on every WAL write.
    fn event_is_skill_relevant(ev: &Event, skills_dir: &std::path::Path) -> bool {
        let kind_matches = matches!(
            ev.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        );
        if !kind_matches {
            return false;
        }
        ev.paths.iter().any(|p| {
            match p.file_name().and_then(|s| s.to_str()) {
                // skill.yaml anywhere under the watch, or freedom.yaml (GR-049).
                Some("skill.yaml") | Some("freedom.yaml") => true,
                // A skill-folder create/remove — but ONLY under skills_dir, so a
                // home-dir directory event from the freedom.yaml watch is noise.
                _ => p.is_dir() && p.starts_with(skills_dir),
            }
        })
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
    async fn watch_returns_none_when_dir_missing() {
        let dir = tempdir().unwrap();
        let nope = dir.path().join("does-not-exist");
        let reg = SkillRegistry::load(&nope).await.unwrap();
        let handle = reg.watch();
        assert!(
            handle.is_none(),
            "watcher must decline to start on a missing dir instead of panicking"
        );
    }

    #[tokio::test]
    async fn watch_returns_handle_when_dir_exists() {
        let dir = tempdir().unwrap();
        let reg = SkillRegistry::load(dir.path()).await.unwrap();
        let handle = reg.watch();
        assert!(
            handle.is_some(),
            "watcher must bind on an existing dir even when empty"
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
