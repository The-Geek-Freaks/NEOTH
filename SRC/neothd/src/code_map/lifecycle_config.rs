//! Typed persistence facade for daemon-managed code-map lifecycle settings.
//!
//! This module intentionally owns only the desired configuration and reload
//! request. It never infers that the daemon accepted or activated a setting:
//! [`CodeMapLifecycleConfigApplyReceipt::active_observed`] comes solely from
//! the lock-proven runtime status snapshot.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::code_map::lifecycle_watcher::{
    CodeMapLifecycleRuntimeStatus, read_active_code_map_lifecycle_status,
};
use crate::config::{CodeMapLifecycleConfig, FreedomConfig};

/// Result of persisting one complete lifecycle configuration request.
///
/// `reload_requested` means the durable reload sentinel was written. It does
/// not mean a daemon observed, accepted, or activated the stored settings.
/// Those facts can only be reported by `active_observed`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CodeMapLifecycleConfigApplyReceipt {
    pub instance_home: PathBuf,
    pub config_path: PathBuf,
    pub persisted_config: CodeMapLifecycleConfig,
    pub canonical_managed_roots: Vec<PathBuf>,
    /// Every persisted root is represented even when its path is currently
    /// unavailable. `canonical_path = None` is a runtime availability fact,
    /// not an invalidation of the saved desired configuration.
    pub managed_root_observations: Vec<CodeMapLifecycleManagedRootObservation>,
    pub reload_requested: bool,
    pub reload_diagnostic: Option<String>,
    pub active_observed: Option<CodeMapLifecycleRuntimeStatus>,
    pub active_observation_diagnostic: Option<String>,
}

/// Physical availability observed while producing a config receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CodeMapLifecycleManagedRootObservation {
    pub persisted_path: PathBuf,
    pub canonical_path: Option<PathBuf>,
    pub availability_diagnostic: Option<String>,
}

/// Transactional edit for a lifecycle configuration already persisted by an
/// operator or another GUI surface. Every omitted scalar and every root not
/// explicitly added or removed is retained from the current source generation.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CodeMapLifecycleConfigPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debounce_millis: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add_managed_roots: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_managed_roots: Vec<PathBuf>,
    /// Disable only when the transaction's merged root set is empty. This is
    /// safe for a stale GUI "remove final root" action because a concurrently
    /// added root keeps the currently enabled state intact.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_if_no_managed_roots: bool,
}

impl CodeMapLifecycleConfigPatch {
    /// Empty patches are read-only config/runtime observations and do not write
    /// either freedom.yaml or a reload sentinel.
    pub fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.debounce_millis.is_none()
            && self.reconciliation_interval_secs.is_none()
            && self.add_managed_roots.is_empty()
            && self.remove_managed_roots.is_empty()
            && !self.disable_if_no_managed_roots
    }

    fn validate_shape(&self) -> Result<()> {
        let bound = CodeMapLifecycleConfig::MAX_MANAGED_ROOTS;
        anyhow::ensure!(
            self.add_managed_roots.len() <= bound,
            "code_map.lifecycle patch accepts at most {bound} added roots"
        );
        anyhow::ensure!(
            self.remove_managed_roots.len() <= bound,
            "code_map.lifecycle patch accepts at most {bound} removed roots"
        );
        anyhow::ensure!(
            self.add_managed_roots.iter().all(|path| path.is_absolute()),
            "code_map.lifecycle patch added roots must be absolute"
        );
        anyhow::ensure!(
            self.remove_managed_roots
                .iter()
                .all(|path| path.is_absolute()),
            "code_map.lifecycle patch removed roots must be absolute"
        );
        if let Some(value) = self.debounce_millis {
            anyhow::ensure!(
                (CodeMapLifecycleConfig::MIN_DEBOUNCE_MILLIS
                    ..=CodeMapLifecycleConfig::MAX_DEBOUNCE_MILLIS)
                    .contains(&value),
                "code_map.lifecycle.debounce_millis must be between {} and {}",
                CodeMapLifecycleConfig::MIN_DEBOUNCE_MILLIS,
                CodeMapLifecycleConfig::MAX_DEBOUNCE_MILLIS,
            );
        }
        if let Some(value) = self.reconciliation_interval_secs {
            anyhow::ensure!(
                (CodeMapLifecycleConfig::MIN_RECONCILIATION_INTERVAL_SECS
                    ..=CodeMapLifecycleConfig::MAX_RECONCILIATION_INTERVAL_SECS)
                    .contains(&value),
                "code_map.lifecycle.reconciliation_interval_secs must be between {} and {}",
                CodeMapLifecycleConfig::MIN_RECONCILIATION_INTERVAL_SECS,
                CodeMapLifecycleConfig::MAX_RECONCILIATION_INTERVAL_SECS,
            );
        }
        Ok(())
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Persist a complete lifecycle configuration for the standard
/// `<instance-home>/freedom.yaml` instance path and request its established
/// daemon reload sentinel.
///
/// Validation, physical-root canonicalization, and overlap rejection happen
/// before the config mutation begins. A reload-sentinel failure after a
/// successful durable update is returned as truthful receipt data rather than
/// being hidden by a rollback claim that did not occur.
pub fn apply_code_map_lifecycle_config(
    instance_home: &Path,
    requested: CodeMapLifecycleConfig,
) -> Result<CodeMapLifecycleConfigApplyReceipt> {
    apply_code_map_lifecycle_config_with_reload(instance_home, requested, |home| {
        crate::cli::reload::request_reload_at(home).map(|_| ())
    })
}

/// Apply a merge patch to the current persisted lifecycle configuration under
/// the same `FreedomConfig::update_at` transaction that writes it. This avoids
/// GUI load/edit/save races where a full replacement would erase roots or
/// timing values accepted by a concurrent operator action.
pub fn apply_code_map_lifecycle_config_patch(
    instance_home: &Path,
    patch: CodeMapLifecycleConfigPatch,
) -> Result<CodeMapLifecycleConfigApplyReceipt> {
    apply_code_map_lifecycle_config_patch_with_reload(instance_home, patch, |home| {
        crate::cli::reload::request_reload_at(home).map(|_| ())
    })
}

fn apply_code_map_lifecycle_config_with_reload<R>(
    instance_home: &Path,
    requested: CodeMapLifecycleConfig,
    request_reload: R,
) -> Result<CodeMapLifecycleConfigApplyReceipt>
where
    R: FnOnce(&Path) -> Result<()>,
{
    // This is intentionally before `FreedomConfig::update_at`: invalid
    // operator input has no opportunity to rewrite even a losslessly merged
    // freedom.yaml generation.
    let canonical_managed_roots = requested
        .canonical_managed_roots()?
        .into_iter()
        .map(|root| root.path().to_path_buf())
        .collect::<Vec<_>>();
    let mut canonical_requested = requested;
    canonical_requested.managed_roots = canonical_managed_roots.clone();
    canonical_requested.validate()?;

    let config_path = instance_home.join("freedom.yaml");
    let persisted_requested = canonical_requested.clone();
    FreedomConfig::update_at(&config_path, move |config| {
        config.code_map.lifecycle = persisted_requested;
        config
            .code_map
            .validate()
            .context("validate updated code_map lifecycle")
    })?;

    let (reload_requested, reload_diagnostic) = match request_reload(instance_home) {
        Ok(()) => (true, None),
        Err(error) => (false, Some(format!("{error:#}"))),
    };
    lifecycle_config_readback_receipt(
        instance_home,
        config_path,
        reload_requested,
        reload_diagnostic,
    )
}

fn apply_code_map_lifecycle_config_patch_with_reload<R>(
    instance_home: &Path,
    patch: CodeMapLifecycleConfigPatch,
    request_reload: R,
) -> Result<CodeMapLifecycleConfigApplyReceipt>
where
    R: FnOnce(&Path) -> Result<()>,
{
    patch.validate_shape()?;
    let config_path = instance_home.join("freedom.yaml");
    if patch.is_empty() {
        return lifecycle_config_readback_receipt(instance_home, config_path, false, None);
    }

    FreedomConfig::update_at(&config_path, move |config| {
        let merged = merge_lifecycle_patch(&config.code_map.lifecycle, &patch)?;
        config.code_map.lifecycle = merged;
        config
            .code_map
            .validate()
            .context("validate patched code_map lifecycle")
    })?;

    let (reload_requested, reload_diagnostic) = match request_reload(instance_home) {
        Ok(()) => (true, None),
        Err(error) => (false, Some(format!("{error:#}"))),
    };
    lifecycle_config_readback_receipt(
        instance_home,
        config_path,
        reload_requested,
        reload_diagnostic,
    )
}

fn merge_lifecycle_patch(
    current: &CodeMapLifecycleConfig,
    patch: &CodeMapLifecycleConfigPatch,
) -> Result<CodeMapLifecycleConfig> {
    // Resolve available physical identities while the coherent freedom.yaml
    // transaction is held. Missing historical roots remain as their exact
    // stored spelling so an operator can still remove them after a move or
    // deletion. Existing aliases continue to remove by physical identity.
    let remove_available = patch
        .remove_managed_roots
        .iter()
        .filter_map(|path| crate::code_map::root_identity::CanonicalRepoRoot::discover(path).ok())
        .collect::<Vec<_>>();
    let mut roots = Vec::with_capacity(current.managed_roots.len() + patch.add_managed_roots.len());
    for stored in &current.managed_roots {
        if patch
            .remove_managed_roots
            .iter()
            .any(|remove| remove == stored)
        {
            continue;
        }
        let available = crate::code_map::root_identity::CanonicalRepoRoot::discover(stored).ok();
        if available.as_ref().is_some_and(|root| {
            remove_available
                .iter()
                .any(|remove| remove.identity() == root.identity())
        }) {
            continue;
        }
        roots.push(
            available
                .as_ref()
                .map(|root| root.path().to_path_buf())
                .unwrap_or_else(|| stored.clone()),
        );
    }

    for path in &patch.add_managed_roots {
        let added = crate::code_map::root_identity::CanonicalRepoRoot::discover(path)?;
        let duplicate = roots.iter().any(|current| {
            current == added.path()
                || crate::code_map::root_identity::CanonicalRepoRoot::discover(current)
                    .ok()
                    .is_some_and(|current| current.identity() == added.identity())
        });
        if !duplicate {
            anyhow::ensure!(
                !roots.iter().any(|current| {
                    crate::code_map::root_identity::CanonicalRepoRoot::discover(current).is_err()
                        && (added.path().starts_with(current) || current.starts_with(added.path()))
                }),
                "code_map.lifecycle.managed_roots must not overlap an unavailable persisted root"
            );
            roots.push(added.path().to_path_buf());
        }
    }

    let mut merged = current.clone();
    if let Some(enabled) = patch.enabled {
        merged.enabled = enabled;
    }
    if let Some(debounce_millis) = patch.debounce_millis {
        merged.debounce_millis = debounce_millis;
    }
    if let Some(reconciliation_interval_secs) = patch.reconciliation_interval_secs {
        merged.reconciliation_interval_secs = reconciliation_interval_secs;
    }
    merged.managed_roots = roots;
    if patch.disable_if_no_managed_roots && merged.managed_roots.is_empty() {
        merged.enabled = false;
    }
    merged.validate()?;
    Ok(merged)
}

fn lifecycle_config_readback_receipt(
    instance_home: &Path,
    config_path: PathBuf,
    reload_requested: bool,
    reload_diagnostic: Option<String>,
) -> Result<CodeMapLifecycleConfigApplyReceipt> {
    let persisted = FreedomConfig::load_from_path(&config_path)
        .with_context(|| {
            format!(
                "read back persisted lifecycle config at {}",
                config_path.display()
            )
        })?
        .code_map
        .lifecycle;
    let managed_root_observations = persisted
        .managed_roots
        .iter()
        .map(|persisted_path| {
            match crate::code_map::root_identity::CanonicalRepoRoot::discover(persisted_path) {
                Ok(root) => CodeMapLifecycleManagedRootObservation {
                    persisted_path: persisted_path.clone(),
                    canonical_path: Some(root.path().to_path_buf()),
                    availability_diagnostic: None,
                },
                Err(error) => CodeMapLifecycleManagedRootObservation {
                    persisted_path: persisted_path.clone(),
                    canonical_path: None,
                    availability_diagnostic: Some(format!("{error:#}")),
                },
            }
        })
        .collect::<Vec<_>>();
    let persisted_canonical_managed_roots = managed_root_observations
        .iter()
        .filter_map(|observation| observation.canonical_path.clone())
        .collect();
    let (active_observed, active_observation_diagnostic) =
        match read_active_code_map_lifecycle_status(instance_home) {
            Ok(status) => (status, None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };

    Ok(CodeMapLifecycleConfigApplyReceipt {
        instance_home: instance_home.to_path_buf(),
        config_path,
        persisted_config: persisted,
        canonical_managed_roots: persisted_canonical_managed_roots,
        managed_root_observations,
        reload_requested,
        reload_diagnostic,
        active_observed,
        active_observation_diagnostic,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn write_default_config(home: &Path) -> PathBuf {
        fs::create_dir_all(home).unwrap();
        let path = home.join("freedom.yaml");
        fs::write(
            &path,
            serde_yaml::to_string(&FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        path
    }

    fn enabled(root: PathBuf) -> CodeMapLifecycleConfig {
        CodeMapLifecycleConfig {
            enabled: true,
            managed_roots: vec![root],
            ..CodeMapLifecycleConfig::default()
        }
    }

    #[test]
    fn invalid_request_has_no_config_file_effect() {
        let home = tempfile::tempdir().unwrap();
        let path = write_default_config(home.path());
        let before = fs::read(&path).unwrap();
        let invalid = CodeMapLifecycleConfig {
            enabled: true,
            ..CodeMapLifecycleConfig::default()
        };

        assert!(
            apply_code_map_lifecycle_config_with_reload(home.path(), invalid, |_| Ok(())).is_err()
        );
        assert_eq!(fs::read(path).unwrap(), before);
        assert!(
            !home
                .path()
                .join(crate::config::reload::RELOAD_SENTINEL_NAME)
                .exists()
        );
    }

    #[test]
    fn aliases_persist_as_one_canonical_root_and_overlaps_are_rejected() {
        let home = tempfile::tempdir().unwrap();
        write_default_config(home.path());
        let root = home.path().join("repo");
        fs::create_dir_all(root.join("nested")).unwrap();
        let alias = root.join(".");

        let receipt =
            apply_code_map_lifecycle_config_with_reload(home.path(), enabled(alias), |_| Ok(()))
                .unwrap();
        assert_eq!(
            receipt.canonical_managed_roots,
            vec![fs::canonicalize(&root).unwrap()]
        );
        assert_eq!(
            receipt.persisted_config.managed_roots,
            receipt.canonical_managed_roots
        );

        let before = fs::read(home.path().join("freedom.yaml")).unwrap();
        let overlap = CodeMapLifecycleConfig {
            enabled: true,
            managed_roots: vec![root.clone(), root.join("nested")],
            ..CodeMapLifecycleConfig::default()
        };
        assert!(
            apply_code_map_lifecycle_config_with_reload(home.path(), overlap, |_| Ok(())).is_err()
        );
        assert_eq!(fs::read(home.path().join("freedom.yaml")).unwrap(), before);
    }

    #[test]
    fn successful_write_is_read_back_and_requests_reload_without_claiming_active_runtime() {
        let home = tempfile::tempdir().unwrap();
        write_default_config(home.path());
        let root = home.path().join("repo");
        fs::create_dir_all(&root).unwrap();

        let receipt = apply_code_map_lifecycle_config(home.path(), enabled(root)).unwrap();
        assert!(receipt.reload_requested);
        assert!(receipt.reload_diagnostic.is_none());
        assert!(receipt.active_observed.is_none());
        let read_back = FreedomConfig::load_from_path(&home.path().join("freedom.yaml"))
            .unwrap()
            .code_map
            .lifecycle;
        assert_eq!(read_back.enabled, receipt.persisted_config.enabled);
        assert_eq!(
            read_back.managed_roots,
            receipt.persisted_config.managed_roots
        );
        assert_eq!(
            read_back.debounce_millis,
            receipt.persisted_config.debounce_millis
        );
        assert_eq!(
            read_back.reconciliation_interval_secs,
            receipt.persisted_config.reconciliation_interval_secs
        );
        assert!(
            home.path()
                .join(crate::config::reload::RELOAD_SENTINEL_NAME)
                .exists()
        );
    }

    #[test]
    fn reload_request_failure_reports_persisted_partial_state() {
        let home = tempfile::tempdir().unwrap();
        write_default_config(home.path());
        let root = home.path().join("repo");
        fs::create_dir_all(&root).unwrap();

        let receipt =
            apply_code_map_lifecycle_config_with_reload(home.path(), enabled(root), |_| {
                anyhow::bail!("synthetic reload-sentinel failure")
            })
            .unwrap();
        assert!(!receipt.reload_requested);
        assert!(
            receipt
                .reload_diagnostic
                .as_deref()
                .is_some_and(|diagnostic| diagnostic.contains("synthetic reload-sentinel failure"))
        );
        assert!(receipt.persisted_config.enabled);
        assert!(
            FreedomConfig::load_from_path(&receipt.config_path)
                .unwrap()
                .code_map
                .lifecycle
                .enabled
        );
    }

    #[test]
    fn sequential_patches_preserve_unrelated_roots_and_timings() {
        let home = tempfile::tempdir().unwrap();
        write_default_config(home.path());
        let root_a = home.path().join("repo-a");
        let root_b = home.path().join("repo-b");
        let root_c = home.path().join("repo-c");
        fs::create_dir_all(&root_a).unwrap();
        fs::create_dir_all(&root_b).unwrap();
        fs::create_dir_all(&root_c).unwrap();

        let initial = CodeMapLifecycleConfig {
            enabled: true,
            managed_roots: vec![root_a.clone(), root_c.clone()],
            debounce_millis: 700,
            reconciliation_interval_secs: 600,
        };
        apply_code_map_lifecycle_config_with_reload(home.path(), initial, |_| Ok(())).unwrap();

        let after_add = apply_code_map_lifecycle_config_patch_with_reload(
            home.path(),
            CodeMapLifecycleConfigPatch {
                add_managed_roots: vec![root_b.clone()],
                ..CodeMapLifecycleConfigPatch::default()
            },
            |_| Ok(()),
        )
        .unwrap();
        assert!(after_add.persisted_config.enabled);
        assert_eq!(after_add.persisted_config.debounce_millis, 700);
        assert_eq!(after_add.persisted_config.reconciliation_interval_secs, 600);
        assert_eq!(after_add.canonical_managed_roots.len(), 3);

        let after_remove_and_timing = apply_code_map_lifecycle_config_patch_with_reload(
            home.path(),
            CodeMapLifecycleConfigPatch {
                debounce_millis: Some(900),
                remove_managed_roots: vec![root_b.join(".")],
                ..CodeMapLifecycleConfigPatch::default()
            },
            |_| Ok(()),
        )
        .unwrap();
        assert!(after_remove_and_timing.persisted_config.enabled);
        assert_eq!(
            after_remove_and_timing.persisted_config.debounce_millis,
            900
        );
        assert_eq!(
            after_remove_and_timing
                .persisted_config
                .reconciliation_interval_secs,
            600
        );
        assert_eq!(after_remove_and_timing.canonical_managed_roots.len(), 2);
        assert!(
            after_remove_and_timing
                .canonical_managed_roots
                .contains(&fs::canonicalize(root_a).unwrap())
        );
        assert!(
            after_remove_and_timing
                .canonical_managed_roots
                .contains(&fs::canonicalize(root_c).unwrap())
        );
    }

    #[test]
    fn invalid_patch_has_no_durable_effect() {
        let home = tempfile::tempdir().unwrap();
        let path = write_default_config(home.path());
        let before = fs::read(&path).unwrap();
        let invalid = CodeMapLifecycleConfigPatch {
            debounce_millis: Some(CodeMapLifecycleConfig::MIN_DEBOUNCE_MILLIS - 1),
            ..CodeMapLifecycleConfigPatch::default()
        };

        assert!(
            apply_code_map_lifecycle_config_patch_with_reload(home.path(), invalid, |_| Ok(()))
                .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), before);
        assert!(
            !home
                .path()
                .join(crate::config::reload::RELOAD_SENTINEL_NAME)
                .exists()
        );
    }

    #[test]
    fn deleted_persisted_root_loads_and_can_be_removed_by_exact_stored_path() {
        let home = tempfile::tempdir().unwrap();
        write_default_config(home.path());
        let root = home.path().join("moved-or-deleted-repo");
        fs::create_dir_all(&root).unwrap();
        let initial =
            apply_code_map_lifecycle_config_with_reload(home.path(), enabled(root.clone()), |_| {
                Ok(())
            })
            .unwrap();
        let stored_path = initial.persisted_config.managed_roots[0].clone();
        fs::remove_dir_all(&root).unwrap();

        let loaded = FreedomConfig::load_from_path(&initial.config_path)
            .expect("a missing lifecycle root must not make saved config unreadable");
        assert_eq!(
            loaded.code_map.lifecycle.managed_roots,
            vec![stored_path.clone()]
        );

        let receipt = apply_code_map_lifecycle_config_patch_with_reload(
            home.path(),
            CodeMapLifecycleConfigPatch {
                remove_managed_roots: vec![stored_path],
                disable_if_no_managed_roots: true,
                ..CodeMapLifecycleConfigPatch::default()
            },
            |_| Ok(()),
        )
        .expect("exact stored missing root must remain removable");
        assert!(receipt.persisted_config.managed_roots.is_empty());
        assert!(receipt.managed_root_observations.is_empty());
    }

    #[test]
    fn conditional_disable_preserves_enabled_when_a_root_was_added_before_remove() {
        let home = tempfile::tempdir().unwrap();
        write_default_config(home.path());
        let first = home.path().join("first");
        let concurrent = home.path().join("concurrent-add");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&concurrent).unwrap();
        apply_code_map_lifecycle_config_with_reload(home.path(), enabled(first.clone()), |_| Ok(()))
            .unwrap();

        // A second GUI action commits an add before the stale first form
        // removes what it thought was the final root.
        apply_code_map_lifecycle_config_patch_with_reload(
            home.path(),
            CodeMapLifecycleConfigPatch {
                add_managed_roots: vec![concurrent.clone()],
                ..CodeMapLifecycleConfigPatch::default()
            },
            |_| Ok(()),
        )
        .unwrap();
        let receipt = apply_code_map_lifecycle_config_patch_with_reload(
            home.path(),
            CodeMapLifecycleConfigPatch {
                remove_managed_roots: vec![first],
                disable_if_no_managed_roots: true,
                ..CodeMapLifecycleConfigPatch::default()
            },
            |_| Ok(()),
        )
        .unwrap();
        assert!(receipt.persisted_config.enabled);
        assert_eq!(receipt.canonical_managed_roots, vec![fs::canonicalize(concurrent).unwrap()]);
    }

    #[test]
    fn empty_patch_is_readback_only_without_reload_request() {
        let home = tempfile::tempdir().unwrap();
        write_default_config(home.path());
        let receipt = apply_code_map_lifecycle_config_patch_with_reload(
            home.path(),
            CodeMapLifecycleConfigPatch::default(),
            |_| anyhow::bail!("must not request reload for an empty patch"),
        )
        .unwrap();
        assert!(!receipt.reload_requested);
        assert!(receipt.reload_diagnostic.is_none());
        assert!(
            !home
                .path()
                .join(crate::config::reload::RELOAD_SENTINEL_NAME)
                .exists()
        );
    }
}
