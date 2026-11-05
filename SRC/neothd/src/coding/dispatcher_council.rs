//! Action-bound Council admission for patches to the configured NEOTH crate.
//! No live-tree apply: the dispatcher still owns its isolated worktree path.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::code_map::CanonicalRepoRoot;
use crate::coding::self_source_gate::{
    self, BaseShaSnapshot, SelfEditLock, council_review,
};
use crate::config::FreedomConfig;
use crate::permissions::{Action, ConfirmStrategy, Gate, PermissionAuditSink};
use crate::wal::writer::WalWriterHandle;

#[derive(Clone)]
pub(super) struct Context {
    config: Arc<FreedomConfig>,
    home: PathBuf,
    #[cfg(test)]
    leaf: Option<Arc<dyn council_review::ReviewLeaf>>,
}

impl Context {
    #[cfg(test)]
    pub(super) fn with_leaf(mut self, leaf: Arc<dyn council_review::ReviewLeaf>) -> Self {
        self.leaf = Some(leaf);
        self
    }
    pub(super) fn new(config: &FreedomConfig, home: &Path) -> Self {
        Self { config: Arc::new(config.clone()), home: home.to_owned(), #[cfg(test)] leaf: None }
    }
}

/// Moves with admission into the blocking effect. Drop releases the same
/// source exclusion used by the central SelfSourceEdit gate.
pub(super) struct Admission {
    target: CanonicalRepoRoot,
    source_repo: CanonicalRepoRoot,
    source_crate: CanonicalRepoRoot,
    base: BaseShaSnapshot,
    action_binding: String,
    reviewed: Option<council_review::ReviewedEdit>,
    _lock: SelfEditLock,
}

fn action_binding(
    original: &str,
    source_repo: &CanonicalRepoRoot,
    source_crate: &CanonicalRepoRoot,
    base: &BaseShaSnapshot,
    cfg: &FreedomConfig,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        original, source_repo.identity().as_str(), source_crate.identity().as_str(),
        base, &cfg.coding.self_edit,
    )).map_err(|_| "dispatcher self-edit binding failed")?;
    Ok(crate::wal::events::effect_digest(b"dispatcher-self-edit-council-v1", &bytes))
}

impl Admission {
    pub(super) fn commit(&self) -> &str { &self.base.head_sha }

    pub(super) fn permission_binding(&self, original: &str) -> Result<String, String> {
        let resolution = self.reviewed.as_ref().map(|r| r.binding()).transpose()?;
        let bytes = serde_json::to_vec(&(original, &self.action_binding, resolution))
            .map_err(|_| "dispatcher reviewed permission binding failed")?;
        Ok(crate::wal::events::effect_digest(b"dispatcher-reviewed-permission-v1", &bytes))
    }

    pub(super) fn validate(&self, context: &Context, target: &CanonicalRepoRoot, original: &str) -> Result<(), String> {
        if target != &self.target
            || CanonicalRepoRoot::discover(self.source_repo.path()).map_err(|_| "source repository unavailable")? != self.source_repo
            || CanonicalRepoRoot::discover(self.source_crate.path()).map_err(|_| "source crate unavailable")? != self.source_crate
            || action_binding(original, &self.source_repo, &self.source_crate, &self.base, &context.config)? != self.action_binding
        {
            return Err("dispatcher self-edit source or policy changed after review".into());
        }
        self_source_gate::verify_base_snapshot(target.path(), &self.base)?;
        if let Some(reviewed) = &self.reviewed {
            reviewed.validate(&self.action_binding, &context.config.coding.self_edit.council_review)?;
        }
        Ok(())
    }

    pub(super) fn verify_worktree(&self, worktree: &Path) -> Result<(), String> {
        let actual = self_source_gate::capture_base_snapshot(worktree)?;
        if actual.head_sha != self.base.head_sha {
            return Err("reviewed worktree did not start at the exact admitted commit".into());
        }
        Ok(())
    }
}

pub(super) async fn admit(
    context: &Context,
    target: &CanonicalRepoRoot,
    patch: &str,
    original_binding: &str,
    writer: &WalWriterHandle,
    confirmation: super::ApplyConfirmation,
) -> Result<Option<Admission>, String> {
    #[cfg(test)]
    if let Some(leaf) = context.leaf.as_deref() {
        return admit_with_leaf(context, target, patch, original_binding, writer, confirmation, leaf).await;
    }
    admit_with_leaf(context, target, patch, original_binding, writer, confirmation, &council_review::NativeLeaf).await
}

async fn admit_with_leaf(
    context: &Context,
    target: &CanonicalRepoRoot,
    patch: &str,
    original_binding: &str,
    writer: &WalWriterHandle,
    confirmation: super::ApplyConfirmation,
    leaf: &dyn council_review::ReviewLeaf,
) -> Result<Option<Admission>, String> {
    let cfg = context.config.as_ref();
    if !cfg.coding.self_edit.council_review.enabled { return Ok(None); }
    council_review::required(&cfg.coding.self_edit.council_review, &[], 0)?;
    // A downloaded binary needs its operator-configured source root. Failure
    // is never interpreted as proof that a request targets an unrelated repo.
    let roots = crate::coding::self_source::neoth_source_root(&cfg.coding.self_edit.source_root)
        .map_err(|_| "enabled self-edit Council requires an available configured NEOTH source root")?;
    let source_repo = CanonicalRepoRoot::discover(&roots.git_root).map_err(|_| "source repository identity unavailable")?;
    let source_crate = CanonicalRepoRoot::discover(&roots.crate_dir).map_err(|_| "source crate identity unavailable")?;
    if !source_crate.path().starts_with(target.path()) && !target.path().starts_with(source_crate.path()) {
        return Ok(None);
    }
    // Git interprets a new worktree's patch relative to its actual top level.
    // Refuse subdirectory aliases instead of silently changing that base.
    let output = std::process::Command::new("git").arg("-C").arg(target.path())
        .args(["rev-parse", "--show-toplevel"]).output().map_err(|_| "dispatcher Git root lookup failed")?;
    if !output.status.success() { return Err("dispatcher Git root lookup failed".into()); }
    let top = std::str::from_utf8(&output.stdout).map_err(|_| "non-UTF8 Git root")?.trim();
    if CanonicalRepoRoot::discover(Path::new(top)).map_err(|_| "Git root identity unavailable")? != *target {
        return Err("reviewed dispatcher requires the actual repository top level".into());
    }
    let paths = source_paths(target.path(), source_crate.path(), patch)?;
    if paths.is_empty() { return Ok(None); }
    let changed = crate::coding::self_source::diff_line_count(patch);
    self_source_gate::layer1_kill_switch(&cfg.coding.self_edit)?;
    self_source_gate::layer2_allowlist(&cfg.coding.self_edit, &paths, changed)?;
    self_source_gate::layer3_permission(&cfg.autonomy_policy(), &paths, confirmation != super::ApplyConfirmation::Unattended)?;
    let lock = SelfEditLock::acquire(&roots.git_root)?;
    let base = self_source_gate::capture_base_snapshot(target.path())?;
    let action_binding = action_binding(original_binding, &source_repo, &source_crate, &base, cfg)?;
    let reviewed = if council_review::required(&cfg.coding.self_edit.council_review, &paths, changed)? {
        let mut reviewed = council_review::review(cfg, &context.home, patch, &action_binding, writer, leaf).await?;
        if !reviewed.dissent().is_empty() {
            if confirmation != super::ApplyConfirmation::LocalCliFlag {
                return Err("Council dissent needs a fresh local operator override; existing patch approval is insufficient".into());
            }
            let binding = reviewed.confirmation_binding()?;
            eprintln!("Council objects to this NEOTH patch. Review binding: {binding}");
            for summary in reviewed.dissent() { eprintln!("{summary}"); }
            Gate::for_policy(cfg.autonomy_policy()).with_confirm(ConfirmStrategy::Tty)
                .check_with_audit_sink(
                    &Action::SelfSourceEdit { target_paths: paths.clone() },
                    PermissionAuditSink::Writer(writer), true, Some(&binding),
                ).await.map_err(|_| "fresh dispatcher Council override refused")?;
            reviewed.acknowledge_override()?;
        }
        reviewed.validate(&action_binding, &cfg.coding.self_edit.council_review)?;
        reviewed.persist(writer).await?;
        Some(reviewed)
    } else { None };
    let admission = Admission { target: target.clone(), source_repo, source_crate, base, action_binding, reviewed, _lock: lock };
    admission.validate(context, target, original_binding)?;
    Ok(Some(admission))
}

/// Use the existing strict Git-diff grammar; both sides of moves/deletions
/// participate. Reject ambiguous/binary records and filesystem aliases rather
/// than guessing whether they could touch the configured source tree.
pub(super) fn source_paths(repo: &Path, source_crate: &Path, patch: &str) -> Result<Vec<String>, String> {
    let crate_relative = source_crate.strip_prefix(repo).map_err(|_| "source crate is not beneath the admitted Git root")?;
    let prefix: Vec<_> = crate_relative.components().map(|p| p.as_os_str().to_string_lossy().to_ascii_lowercase()).collect();
    let files = crate::code_map::diff::parse_unified_diff(patch).map_err(|_| "ambiguous self-edit diff; strict Git headers required")?;
    let mut paths = std::collections::BTreeSet::new();
    for file in files {
        if file.change == crate::code_map::diff::DiffChange::Binary {
            return Err("binary self-edit diff cannot be reviewed as complete source".into());
        }
        for path in [file.old_path, file.new_path].into_iter().flatten() {
            let mut current = repo.to_path_buf();
            for component in path.split('/') {
                current.push(component);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        let alias = metadata.file_type().is_symlink();
                        #[cfg(windows)]
                        let alias = {
                            use std::os::windows::fs::MetadataExt;
                            alias || metadata.file_attributes() & 0x400 != 0
                        };
                        if alias { return Err("self-edit diff traverses a filesystem alias".into()); }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err("self-edit path identity unavailable".into()),
                }
            }
            let parts: Vec<_> = path.split('/').collect();
            if parts.len() > prefix.len() && parts.iter().zip(&prefix).all(|(actual, expected)| actual.eq_ignore_ascii_case(expected)) {
                paths.insert(parts[prefix.len()..].join("/"));
            }
        }
    }
    Ok(paths.into_iter().collect())
}
