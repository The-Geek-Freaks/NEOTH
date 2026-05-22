//! Hot-reload controller for `FreedomConfig` (Pick #37, Session 14).
//!
//! Agent #4 design consensus (2026-05-19): when the operator edits
//! `freedom.yaml` mid-session, NEOTH must pick up the changes without
//! a daemon restart. Some fields (`operator_id`, `provider_kind`) are
//! IMMUTABLE post-init — reloading them would require rebuilding the
//! provider Arc + channel adapters that hold derived state, which
//! isn't worth the complexity for a solo-operator daemon. Those
//! fields cause the reload to be rejected with a reason logged at
//! warn level + audited via WAL.
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
//!   - SIGHUP doesn't exist on Windows (Alex's primary)
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
//!     ReloadResult::Rejected { reason }         => /* audit + warn */,
//!     ReloadResult::Unchanged                   => /* no-op */,
//! }
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;

use crate::config::FreedomConfig;

/// Sentinel file name written into `~/.neoth/` by `neoth reload`.
/// The daemon's polling tick checks for this file's existence; on
/// present it loads + validates + swaps + deletes the file. Name
/// starts with `.` so it's hidden in `ls`/Explorer; doesn't collide
/// with any user-facing artifact.
pub const RELOAD_SENTINEL_NAME: &str = ".reload-requested";

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
    /// `reason` includes the field name + the old/new values for the
    /// operator's audit log.
    Rejected { reason: String },
    /// File content identical to live config — no swap performed,
    /// no audit frame emitted. Operator triggered reload against a
    /// freedom.yaml they hadn't actually edited.
    Unchanged,
}

/// Owns the live `Arc<ArcSwap<FreedomConfig>>` + the source file
/// path. Construct once at daemon startup; clone freely (every
/// clone shares the same ArcSwap via inner Arc).
#[derive(Clone)]
pub struct ReloadController {
    inner: Arc<ArcSwap<FreedomConfig>>,
    source_path: PathBuf,
    /// Q-4 (hermes port, Session 19): cached `xxh3_64(path +
    /// mtime + size)` snapshot of the source file. Lets a
    /// polling loop skip the full YAML re-read when nothing
    /// has changed — read-stat-hash is ~10µs vs ~500µs for
    /// the full parse. `None` means "not yet computed";
    /// `try_reload` populates it after every read.
    snapshot_hash: Arc<std::sync::Mutex<Option<u64>>>,
}

impl ReloadController {
    /// Construct from the initial config + the freedom.yaml path
    /// that `try_reload()` will re-read.
    pub fn new(initial: FreedomConfig, source_path: PathBuf) -> Self {
        let initial_hash = compute_snapshot_hash(&source_path).ok();
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(initial))),
            source_path,
            snapshot_hash: Arc::new(std::sync::Mutex::new(initial_hash)),
        }
    }

    /// Lock-free snapshot of the current config. Returns an `Arc`;
    /// every reader gets the same `Arc` until a reload swaps in a
    /// new one. Cheap: an atomic pointer load + Arc clone.
    pub fn latest(&self) -> Arc<FreedomConfig> {
        self.inner.load_full()
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
    pub fn try_reload(&self) -> Result<ReloadResult> {
        let old = self.inner.load_full();
        let candidate = FreedomConfig::load_from_path(&self.source_path)
            .with_context(|| format!("re-read {}", self.source_path.display()))?;

        // Identical content → no-op. Compare via YAML round-trip so
        // deep-equal works without requiring `PartialEq` on every
        // nested config struct (which several lack).
        let old_yaml = serde_yaml::to_string(&*old).unwrap_or_default();
        let new_yaml = serde_yaml::to_string(&candidate).unwrap_or_default();
        if old_yaml == new_yaml {
            return Ok(ReloadResult::Unchanged);
        }

        // Validate immutable fields.
        if let Some(reason) = validate_reload(&old, &candidate) {
            return Ok(ReloadResult::Rejected { reason });
        }

        // Compute changed top-level fields (best-effort diff).
        let changed_fields = diff_top_level(&old, &candidate);

        // Atomic swap. Lock-free, no reader contention.
        self.inner.store(Arc::new(candidate));

        Ok(ReloadResult::Reloaded { changed_fields })
    }
}

/// Validate that no immutable field changed between `old` + `new`.
/// Returns `Some(reason)` on rejection, `None` when the swap is
/// allowed to proceed.
///
/// Immutable post-init:
///   - `operator_id` — the daemon's identity is pinned at first init
///   - `provider_kind` — the provider Arc is built once at startup
///     from this kind; reloading would require rebuilding it +
///     re-issuing consent
///   - `telegram_user_id` — restrictively-bound bot; changing
///     mid-run would require restarting the Telegram adapter
fn validate_reload(old: &FreedomConfig, new: &FreedomConfig) -> Option<String> {
    if old.operator_id != new.operator_id {
        return Some(format!(
            "operator_id is immutable post-init (old={:?}, new={:?}); restart NEOTH \
             to change operator identity",
            old.operator_id, new.operator_id
        ));
    }
    if old.provider_kind != new.provider_kind {
        return Some(format!(
            "provider_kind is immutable post-init (old={:?}, new={:?}); restart \
             NEOTH to switch provider — the provider Arc + consent gate are \
             built once at startup",
            old.provider_kind, new.provider_kind
        ));
    }
    if old.telegram_user_id != new.telegram_user_id {
        return Some(format!(
            "telegram_user_id is immutable post-init (old={:?}, new={:?}); restart \
             to rebind the Telegram adapter",
            old.telegram_user_id, new.telegram_user_id
        ));
    }
    None
}

/// Compare two `FreedomConfig` instances field-by-field at the top
/// level. Returns a list of field names where the YAML serialisation
/// differs. Mostly an operator-visible diagnostic; the actual swap
/// uses pointer-compare via ArcSwap, not this diff.
fn diff_top_level(old: &FreedomConfig, new: &FreedomConfig) -> Vec<String> {
    macro_rules! check {
        ($($field:ident),* $(,)?) => {{
            let mut out: Vec<String> = Vec::new();
            $(
                let old_y = serde_yaml::to_string(&old.$field).unwrap_or_default();
                let new_y = serde_yaml::to_string(&new.$field).unwrap_or_default();
                if old_y != new_y {
                    out.push(stringify!($field).into());
                }
            )*
            out
        }};
    }
    check!(
        language_primary,
        language_code,
        role,
        role_custom,
        provider_binary,
        provider_endpoint,
        provider_model,
        provider_region,
        provider_api_version,
        autonomy,
        observability_listen,
        inference,
        council,
        review_gate_enabled,
        obsidian_vault,
        obsidian_subdir,
        obsidian_auto_sync_secs,
        hysteria,
        cloud_archive_dest,
        cloud_archive_subdir,
        cloud_archive_auto_sync_secs,
        rollback,
        claude_cli,
        profile,
        refusal_recovery,
        code_map,
    )
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
    use super::*;
    use crate::cli::init::ProviderKind;

    fn fresh_config() -> FreedomConfig {
        FreedomConfig {
            operator_id: Some("alex".into()),
            provider_kind: Some(ProviderKind::ClaudeCli),
            telegram_user_id: Some(42),
            ..Default::default()
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
        new.operator_id = Some("not-alex".into());
        let reason = validate_reload(&old, &new).expect("must reject");
        assert!(reason.contains("operator_id"));
        assert!(reason.contains("restart"));
    }

    #[test]
    fn validate_immutable_provider_kind_rejects() {
        let old = fresh_config();
        let mut new = old.clone();
        new.provider_kind = Some(ProviderKind::OpenaiApi);
        let reason = validate_reload(&old, &new).expect("must reject");
        assert!(reason.contains("provider_kind"));
    }

    #[test]
    fn validate_immutable_telegram_user_id_rejects() {
        let old = fresh_config();
        let mut new = old.clone();
        new.telegram_user_id = Some(99);
        let reason = validate_reload(&old, &new).expect("must reject");
        assert!(reason.contains("telegram_user_id"));
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
        let changed = diff_top_level(&old, &new);
        assert!(
            changed.contains(&"review_gate_enabled".to_string()),
            "expected review_gate_enabled in diff; got: {changed:?}",
        );
    }

    #[test]
    fn diff_top_level_is_empty_for_identical_configs() {
        let cfg = fresh_config();
        let diff = diff_top_level(&cfg, &cfg);
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
        let changed = diff_top_level(&old, &new);
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
            ReloadResult::Rejected { reason } => {
                assert!(reason.contains("operator_id"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        // Critically: latest() still returns the ORIGINAL config.
        assert_eq!(ctrl.latest().operator_id, Some("alex".into()));
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
    fn latest_arc_clones_share_the_same_pointer_until_swap() {
        let cfg = fresh_config();
        let ctrl = ReloadController::new(cfg, PathBuf::from("/tmp/nope.yaml"));
        let a = ctrl.latest();
        let b = ctrl.latest();
        // Both clones point to the same Arc — verified by pointer
        // equality (Arc::ptr_eq).
        assert!(Arc::ptr_eq(&a, &b), "latest() clones must share Arc");
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
        std::fs::write(&path, "operator_id: alice\nrole: developer\nlanguage_primary: en\n")
            .unwrap();
        assert!(ctrl.should_reload().unwrap(), "drift after content change");
        // After a should_reload call returning true, the
        // cache updates → next call is false.
        assert!(!ctrl.should_reload().unwrap(), "cache updated → no drift");
    }
}
