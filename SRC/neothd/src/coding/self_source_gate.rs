//! GOLD-FEAT-05 — five-layer fail-closed gate stack for self-source edits.
//!
//! Every gate runs IN ORDER. Any failure returns [`GateError`] without
//! touching the live source tree; the partially-evaluated gate results
//! form the WAL audit payload so a reviewer can see exactly which gate
//! blocked a refused edit.
//!
//! ## Gate order
//!
//! | Layer | Name            | What it checks                                         |
//! |-------|-----------------|--------------------------------------------------------|
//! | 1     | Kill-switch     | `freedom.yaml::coding.self_edit.enabled`               |
//! | 2     | Allowlist       | path prefix allowlist + hard-deny list                 |
//! | 3     | Permission      | `Action::SelfSourceEdit` — Strict/Standard → Deny      |
//! | 4     | Worktree        | apply diff in isolated `git worktree` (never live tree) |
//! | 5     | Green-test      | `cargo check` GREEN in the worktree                    |
//!
//! ## WAL audit
//!
//! - `EXTENDED/SelfEditProposed` (0x01) emitted when a request enters
//!   evaluation (before any gate runs).
//! - `EXTENDED/SelfEditApplied` (0x02) emitted ONLY when all 5 gates pass
//!   AND `--dry-run` is false.
//! - Refused edits emit PROPOSED then nothing; the gap is the audit trail.
//!
//! ## Hard-deny list
//!
//! Paths under these prefixes are ALWAYS refused regardless of the allowlist:
//!
//! ```text
//! src/wal/
//! src/crypto
//! src/config/          (credentials AND the FreedomConfig / autonomy loader)
//! src/permissions/     (the permission evaluator — no self-weakening the gate)
//! src/coding/self_source_gate.rs   (this file — gates may not self-modify)
//! src/coding/self_source.rs        (companion engine)
//! src/cli/self_edit.rs             (CLI orchestrator — could hardcode the ack)
//! src/coding/worktree.rs           (layer 4+5 enforcement infrastructure)
//! src/coding/mod.rs
//! ```
//!
//! Additionally the following are denied by pattern:
//! - `freedom.yaml` (the config that holds the kill-switch)
//! - `.github/` (CI / release pipelines)
//! - `build.rs`, `Cargo.toml`, `Cargo.lock`, `.cargo/` (layer 5's `cargo
//!   check` EXECUTES build scripts and proc macros — these paths are
//!   build-time code execution on the host)
//! - Any path matching `*secret*`, `*credential*`, `*token*`, `*password*`,
//!   `*private_key*`, `*.pem`, `*.key` (secrets patterns)
//!
//! ## Reentrancy
//!
//! A cross-process lock (one self-edit per source root at a time) refuses
//! nested self-edits — nothing spawned by layer 5's build can start another
//! self-edit while one is in flight.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::coding::self_source::{
    SourceRoots, diff_line_count, diff_paths, diff_sha256, neoth_source_root,
};
use crate::coding::worktree::{
    PatchApplyOutcome, apply_patch_in_worktree, cleanup_worktree, create_task_worktree,
    run_cargo_check_json,
};
use crate::coding::types::KanbanTaskId;
use crate::config::FreedomConfig;
use crate::config::ops::SelfEditConfig;
use crate::permissions::{self, Action, AutonomyLevel, Decision};
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::types::EventFlags;
use crate::wal::writer::WalWriterHandle;

// ── Hard-deny path prefixes (always refused, regardless of allowlist) ─────────

/// Paths under these prefixes can NEVER be edited via self-edit, even when
/// the allowlist contains a matching prefix. Applied in [`layer2_allowlist`].
static HARD_DENY_PREFIXES: &[&str] = &[
    "src/wal/",
    "src/crypto",
    // The whole config tree: it holds credentials AND the FreedomConfig loader
    // that decides the autonomy level + the self-edit kill-switch. A self-edit
    // that could rewrite the loader (or SelfEditConfig defaults) would neuter
    // its own gate. Covers the narrower src/config/credentials too.
    "src/config/",
    // The permission evaluator itself — a self-edit that flips
    // `evaluate(SelfSourceEdit)` from Confirm to Allow (or weakens any other
    // action) is a privilege escalation that survives restart.
    "src/permissions/",
    // The gate's own source — self-edit may never rewrite the gate.
    "src/coding/self_source_gate.rs",
    "src/coding/self_source.rs",
    // The CLI orchestrator: editable via a `src/cli` allowlist entry, it could
    // hardcode operator_acked=true / skip the WAL requirement — same class of
    // gate-weakening as editing the gate itself.
    "src/cli/self_edit.rs",
    // Layer 4+5 enforcement infrastructure: a rewritten
    // `apply_patch_in_worktree` / `run_cargo_check_json` that always returns
    // success hollows both layers after the next rebuild.
    "src/coding/worktree.rs",
    "src/coding/mod.rs",
];

/// Exact filenames / path fragments that are hard-denied regardless of
/// directory: build-time code execution, config, CI pipelines, secrets.
///
/// Matched via case-insensitive `contains` — deliberately over-broad
/// (e.g. `rebuild.rs` also trips `build.rs`): the deny side may false-positive,
/// never false-negative.
static HARD_DENY_FRAGMENTS: &[&str] = &[
    "freedom.yaml",
    ".github/",
    // `cargo check` (layer 5) COMPILES the worktree: build scripts and proc
    // macros EXECUTE during it. A diff adding/altering any of these gets
    // arbitrary code execution on the host before the live apply is decided.
    "build.rs",
    "cargo.toml",
    "cargo.lock",
    ".cargo/",
];

/// Lowercase substrings that match secret-pattern filenames.
static SECRET_PATTERNS: &[&str] = &[
    "secret",
    "credential",
    "token",
    "password",
    "private_key",
    ".pem",
    ".key",
];

// ── Gate result types ─────────────────────────────────────────────────────────

/// Per-gate outcome captured in the WAL audit payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LayerOutcome {
    Pass,
    Fail(String),
    Skipped,
}

/// Audit record emitted for every self-edit request (proposed + optionally
/// applied). Stored as JSON in the WAL payload — NEVER contains secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfEditAudit {
    pub target_paths: Vec<String>,
    pub diff_hash: String,
    pub layer1_kill_switch: LayerOutcome,
    pub layer2_allowlist: LayerOutcome,
    pub layer3_permission: LayerOutcome,
    pub layer4_worktree: LayerOutcome,
    pub layer5_green_test: LayerOutcome,
    pub ts_unix: i64,
    pub dry_run: bool,
}

/// Error returned when any gate refuses the edit.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("Layer 1 (kill-switch): {0}")]
    KillSwitch(String),
    #[error("Layer 2 (allowlist): {0}")]
    Allowlist(String),
    #[error("Layer 3 (permission): {0}")]
    Permission(String),
    #[error("Layer 4 (worktree): {0}")]
    Worktree(String),
    #[error("Layer 5 (green-test): {0}")]
    GreenTest(String),
    #[error("audit / WAL error: {0}")]
    Audit(#[from] anyhow::Error),
}

/// Final outcome returned to the caller on success.
#[derive(Debug)]
pub struct SelfEditOutcome {
    /// Paths the diff touched.
    pub target_paths: Vec<String>,
    /// SHA-256 of the diff bytes.
    pub diff_hash: String,
    /// When `true`, no file was written to the live tree.
    pub dry_run: bool,
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Run all five gates for a self-source edit request.
///
/// Parameters:
/// - `diff_text`: the unified-diff text to evaluate. Every downstream step
///   (worktree apply, live apply, hash) uses THESE bytes — the gate never
///   re-reads a diff file from disk, so there is no validate-then-swap window.
/// - `cfg`: loaded `FreedomConfig` (used for autonomy level + `coding.self_edit`).
/// - `dry_run`: when `true`, all five gates still run but the diff is NOT
///   applied to the live tree and no `SelfEditApplied` WAL frame is emitted.
/// - `wal`: optional handle to the WAL writer for audit emission. When `None`,
///   a warning is logged and the gates proceed (WAL is audit, not security).
pub async fn run_gate_stack(
    diff_text: &str,
    cfg: &FreedomConfig,
    dry_run: bool,
    operator_acked: bool,
    wal: Option<&WalWriterHandle>,
) -> Result<SelfEditOutcome, GateError> {
    let self_edit_cfg = &cfg.coding.self_edit;
    let diff_bytes = diff_text.as_bytes();
    let diff_hash = diff_sha256(diff_bytes);
    let ts = crate::time::now_unix_i64();

    // Parse paths first (needed for audit payload before any gate runs).
    let target_paths = diff_paths(diff_text)
        .map_err(|e| GateError::Allowlist(format!("diff parse failed: {e}")))?;

    // Build a partial audit record (layers filled in as gates run).
    let mut audit = SelfEditAudit {
        target_paths: target_paths.clone(),
        diff_hash: diff_hash.clone(),
        layer1_kill_switch: LayerOutcome::Skipped,
        layer2_allowlist: LayerOutcome::Skipped,
        layer3_permission: LayerOutcome::Skipped,
        layer4_worktree: LayerOutcome::Skipped,
        layer5_green_test: LayerOutcome::Skipped,
        ts_unix: ts,
        dry_run,
    };

    // Emit PROPOSED frame BEFORE any gate runs (audit trail of all attempts).
    emit_wal(wal, ExtendedSubtype::SelfEditProposed, &audit).await;

    // ── Layer 1: kill-switch ──────────────────────────────────────────────────
    match layer1_kill_switch(self_edit_cfg) {
        Ok(()) => {
            audit.layer1_kill_switch = LayerOutcome::Pass;
        }
        Err(reason) => {
            audit.layer1_kill_switch = LayerOutcome::Fail(reason.clone());
            info!(reason, "self_edit gate: layer1 kill-switch refused");
            return Err(GateError::KillSwitch(reason));
        }
    }

    // ── Layer 2: allowlist + hard-deny + line-cap ─────────────────────────────
    match layer2_allowlist(self_edit_cfg, &target_paths, diff_line_count(diff_text)) {
        Ok(()) => {
            audit.layer2_allowlist = LayerOutcome::Pass;
        }
        Err(reason) => {
            audit.layer2_allowlist = LayerOutcome::Fail(reason.clone());
            info!(reason, "self_edit gate: layer2 allowlist refused");
            return Err(GateError::Allowlist(reason));
        }
    }

    // ── Layer 3: autonomy permission gate ─────────────────────────────────────
    // dry_run implies acked: it never applies, so previewing needs no ack.
    match layer3_permission(cfg.autonomy, &target_paths, operator_acked || dry_run) {
        Ok(()) => {
            audit.layer3_permission = LayerOutcome::Pass;
        }
        Err(reason) => {
            audit.layer3_permission = LayerOutcome::Fail(reason.clone());
            info!(reason, "self_edit gate: layer3 permission refused");
            return Err(GateError::Permission(reason));
        }
    }

    // ── Layer 4: worktree isolation ───────────────────────────────────────────
    let roots = neoth_source_root(&self_edit_cfg.source_root)
        .map_err(|e| {
            let reason = format!("source root detection failed: {e}");
            audit.layer4_worktree = LayerOutcome::Fail(reason.clone());
            GateError::Worktree(reason)
        })?;

    // Reentrancy guard: a self-edit may never trigger further self-edits.
    // Layer 5 executes `cargo check` (build scripts run!) — if anything in
    // that process tree invokes `neoth self-edit` again, the lock refuses it.
    // File-based so it holds across processes; Drop releases it. Keyed on the
    // git root (one self-edit at a time per repo).
    let _reentrancy_lock = SelfEditLock::acquire(&roots.git_root).map_err(|reason| {
        audit.layer4_worktree = LayerOutcome::Fail(reason.clone());
        GateError::Worktree(reason)
    })?;

    // Use a pseudo-task-id derived from the diff hash (low bits) to get a
    // unique worktree path without requiring a real kanban task.
    let pseudo_id = pseudo_task_id(&diff_hash);
    let worktree = {
        // git subprocess spawns block; keep them off the async executor.
        let r = roots.clone();
        let dt = diff_text.to_string();
        tokio::task::spawn_blocking(move || layer4_worktree(&r, &dt, pseudo_id))
            .await
            .map_err(|e| GateError::Worktree(format!("worktree task panicked: {e}")))?
            .map_err(|reason| {
                audit.layer4_worktree = LayerOutcome::Fail(reason.clone());
                GateError::Worktree(reason)
            })?
    };
    // RAII: from here the worktree is cleaned up on EVERY exit — error return,
    // panic unwind, and async cancellation (future dropped mid-await) alike.
    // Cleanup is a `git worktree remove` run from the git root.
    let _worktree_guard = WorktreeGuard::new(roots.git_root.clone(), worktree.clone());

    audit.layer4_worktree = LayerOutcome::Pass;

    // ── Layer 5: green-test gate (cargo check) ────────────────────────────────
    if self_edit_cfg.require_green_tests {
        // cargo check runs in the WORKSPACE dir inside the worktree so the whole
        // workspace resolves (NEOTH's workspace is a subdir of the git root).
        let wt = worktree.join(roots.workspace_rel());
        let outcome = tokio::task::spawn_blocking(move || layer5_green_test(&wt))
            .await
            .map_err(|e| GateError::GreenTest(format!("green-test task panicked: {e}")))?;
        match outcome {
            Ok(()) => {
                audit.layer5_green_test = LayerOutcome::Pass;
            }
            Err(reason) => {
                audit.layer5_green_test = LayerOutcome::Fail(reason.clone());
                info!(reason, "self_edit gate: layer5 green-test refused");
                return Err(GateError::GreenTest(reason));
            }
        }
    } else {
        audit.layer5_green_test = LayerOutcome::Skipped;
        if !dry_run {
            warn!(
                "self_edit: require_green_tests=false — layer 5 SKIPPED for a \
                 LIVE apply (development setting; re-enable for production)"
            );
        }
    }

    // ── All gates passed — apply to live tree (unless --dry-run) ─────────────
    if !dry_run {
        // Apply the SAME in-memory bytes the gates validated (piped via stdin),
        // NOT a re-read of the on-disk file — closes the TOCTOU where the diff
        // file could be swapped between validation and the live apply. Runs in
        // the crate dir so `src/…` diff paths resolve.
        let cd = roots.crate_dir.clone();
        let dt = diff_text.to_string();
        let applied = tokio::task::spawn_blocking(move || apply_to_live_tree(&cd, &dt))
            .await
            .map_err(|e| GateError::Worktree(format!("live-apply task panicked: {e}")))?;
        if let Err(e) = applied {
            return Err(GateError::Worktree(format!("live-tree apply failed: {e}")));
        }

        // Update audit timestamp to reflect the actual apply moment.
        audit.ts_unix = crate::time::now_unix_i64();
        emit_wal(wal, ExtendedSubtype::SelfEditApplied, &audit).await;
        info!(
            paths = ?target_paths,
            diff_hash,
            "self_edit gate: all 5 gates passed — diff applied to live tree"
        );
    } else {
        info!(
            paths = ?target_paths,
            diff_hash,
            "self_edit gate: all 5 gates passed (dry-run — NOT applied to live tree)"
        );
    }

    Ok(SelfEditOutcome {
        target_paths,
        diff_hash,
        dry_run,
    })
}

// ── RAII guards ───────────────────────────────────────────────────────────────

/// Removes the worktree on drop — covers error returns, panics, and async
/// cancellation in one place instead of per-exit-path cleanup calls.
/// `git worktree remove` is a short blocking call; acceptable in Drop.
struct WorktreeGuard {
    source_root: PathBuf,
    path: PathBuf,
}

impl WorktreeGuard {
    fn new(source_root: PathBuf, path: PathBuf) -> Self {
        Self { source_root, path }
    }
}

impl Drop for WorktreeGuard {
    fn drop(&mut self) {
        if let Err(e) = cleanup_worktree(&self.source_root, &self.path, true) {
            warn!(
                error = %e,
                path = %self.path.display(),
                "self_edit: worktree cleanup failed — run `git worktree prune` manually"
            );
        }
    }
}

/// Cross-process reentrancy guard: one self-edit at a time per source root.
///
/// Lock file lives in the OS temp dir keyed by the source-root hash; `Drop`
/// releases it. A crash leaves a stale file, so acquisition steals locks
/// older than [`Self::STALE_AFTER`].
#[derive(Debug)]
struct SelfEditLock {
    path: PathBuf,
}

impl SelfEditLock {
    const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(30 * 60);

    fn acquire(source_root: &Path) -> Result<Self, String> {
        let key = diff_sha256(source_root.to_string_lossy().as_bytes());
        let path = std::env::temp_dir().join(format!("neoth_self_edit_{}.lock", &key[..16]));
        match Self::try_create(&path) {
            Ok(lock) => Ok(lock),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_none_or(|age| age > Self::STALE_AFTER);
                if stale {
                    let _ = std::fs::remove_file(&path);
                    Self::try_create(&path)
                        .map_err(|e| format!("self-edit lock re-acquire failed: {e}"))
                } else {
                    Err(
                        "another self-edit is already in progress for this source root \
                         (reentrancy guard) — a self-edit may not trigger further self-edits"
                            .into(),
                    )
                }
            }
            Err(e) => Err(format!("self-edit lock create failed: {e}")),
        }
    }

    fn try_create(path: &Path) -> std::io::Result<Self> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map(|_| Self {
                path: path.to_path_buf(),
            })
    }
}

impl Drop for SelfEditLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ── Layer implementations ─────────────────────────────────────────────────────

/// Layer 1: check the kill-switch.
fn layer1_kill_switch(cfg: &SelfEditConfig) -> Result<(), String> {
    if cfg.enabled {
        Ok(())
    } else {
        Err(
            "self-source edit is disabled (freedom.yaml::coding.self_edit.enabled = false); \
             set enabled: true to opt in"
                .into(),
        )
    }
}

/// Layer 2: verify every touched path is in the allowlist and NOT in the
/// hard-deny list.
///
/// Checks in order:
/// 1. Hard-deny prefixes (always refused, even if allowlist matches).
/// 2. Hard-deny fragments (filename patterns).
/// 3. Secret-pattern filenames (case-insensitive).
/// 4. Line-count cap (`max_lines_changed`).
/// 5. Positive allowlist (at least one `allowed_modules` prefix must match).
fn layer2_allowlist(
    cfg: &SelfEditConfig,
    paths: &[String],
    changed_lines: usize,
) -> Result<(), String> {
    // Hard-deny + secret checks run against a LOWERCASED path. NEOTH's primary
    // platform is Windows, whose filesystem is case-insensitive, so
    // `src/WAL/mod.rs` resolves to the same file as `src/wal/mod.rs`. The
    // live-tree sink (`git apply`) does not normalise case, so a case-SENSITIVE
    // deny is a real bypass. Paths are already validated as clean relative
    // forward-slash paths by `diff_paths` (no `..`, absolute, drive, or
    // backslash), so lowercasing is the only remaining normalisation needed.
    for path in paths {
        let path_norm = path.to_lowercase();
        // 2a — hard-deny prefixes
        for deny in HARD_DENY_PREFIXES {
            let deny_l = deny.to_lowercase();
            if path_norm.starts_with(&deny_l) || path_norm == deny_l.trim_end_matches('/') {
                return Err(format!(
                    "path '{path}' is under hard-deny prefix '{deny}' — \
                     self-edit may never touch this path"
                ));
            }
        }
        // 2b — hard-deny fragments
        for fragment in HARD_DENY_FRAGMENTS {
            if path_norm.contains(&fragment.to_lowercase()) {
                return Err(format!(
                    "path '{path}' contains hard-deny fragment '{fragment}'"
                ));
            }
        }
        // 2c — secret patterns (SECRET_PATTERNS are already lowercase)
        for pattern in SECRET_PATTERNS {
            if path_norm.contains(pattern) {
                return Err(format!(
                    "path '{path}' matches secret pattern '{pattern}' — \
                     self-edit may never touch secrets or credentials"
                ));
            }
        }
    }

    // 2d — line-count cap. Enforced INSIDE the gate (not only in the CLI) so
    // every caller of run_gate_stack is covered — defense-in-depth, never
    // caller-dependent.
    if changed_lines > cfg.max_lines_changed {
        return Err(format!(
            "diff changes {changed_lines} line(s), exceeding max_lines_changed \
             ({}) — split the edit into smaller diffs",
            cfg.max_lines_changed
        ));
    }

    // 2e — positive allowlist
    if cfg.allowed_modules.is_empty() {
        return Err(
            "self_edit.allowed_modules is empty — no paths are permitted; \
             add at least one prefix (e.g. 'src/cli', 'src/coding') to freedom.yaml"
                .into(),
        );
    }
    for path in paths {
        // Segment-aware prefix match: `src/cli` must NOT match `src/clitrap`.
        // A path is covered only if it equals the prefix or sits under it as a
        // directory (`<prefix>/…`). Trailing slashes in the config are
        // tolerated. An explicit "." opts into the whole tree; "" and "/" are
        // REFUSED (too easy to write intending whole-tree and silently get an
        // allow-all — spell it "." if that is really wanted).
        let allowed = cfg.allowed_modules.iter().any(|prefix| {
            let p = prefix.as_str().trim_end_matches('/');
            if p.is_empty() {
                return false;
            }
            if p == "." {
                return true;
            }
            path.starts_with(p)
                && (path.len() == p.len() || path.as_bytes().get(p.len()) == Some(&b'/'))
        });
        if !allowed {
            return Err(format!(
                "path '{path}' is not covered by any allowed_modules prefix \
                 (configured: {:?})",
                cfg.allowed_modules
            ));
        }
    }
    Ok(())
}

/// Layer 3: evaluate the permission gate for `Action::SelfSourceEdit`.
///
/// Strict and Standard → `Deny` (returns `Err`).
/// Elevated and Full → `Confirm`. Policy (mirrors `SelfBinaryReplace`): a
/// self-source edit is NEVER auto-applied — the operator must acknowledge each
/// one. `Confirm` is therefore a PASS **only** when `operator_acked` is true.
///
/// `operator_acked` is threaded down from the CLI, which sets it after an
/// explicit `--yes` acknowledgement (or when `--dry-run` means nothing is
/// applied). Enforcing the ack in the gate — not just in the CLI — makes the
/// contract impossible for a future caller to forget: a bare `run_gate_stack`
/// call with `operator_acked = false` REFUSES a Confirm decision instead of
/// silently applying it.
fn layer3_permission(
    autonomy: AutonomyLevel,
    target_paths: &[String],
    operator_acked: bool,
) -> Result<(), String> {
    let action = Action::SelfSourceEdit {
        target_paths: target_paths.to_vec(),
    };
    match permissions::evaluate(&action, autonomy) {
        Decision::Allow => Ok(()),
        Decision::Confirm(reason) => {
            if operator_acked {
                Ok(())
            } else {
                Err(format!(
                    "{reason} — pass --yes to acknowledge (a self-source edit is \
                     never auto-applied, even at Full autonomy)"
                ))
            }
        }
        Decision::Deny(reason) => Err(reason),
    }
}

/// Layer 4: apply the diff in an isolated `git worktree`.
///
/// Creates a new worktree as a sibling of the source root using the existing
/// `coding::worktree` infrastructure, stages the VALIDATED in-memory diff
/// bytes as a file INSIDE that fresh worktree, and applies it there. The
/// caller's original diff file on disk is never re-read — a post-validation
/// swap of that file cannot reach the worktree (or, later, the live tree).
///
/// Returns the worktree path on success (caller owns cleanup via guard).
fn layer4_worktree(
    roots: &SourceRoots,
    diff_text: &str,
    task_id: KanbanTaskId,
) -> Result<PathBuf, String> {
    // The worktree is a fresh checkout of the WHOLE git repo (NEOTH's crate is
    // a subdir of it). Returned path is the worktree root — cleanup runs from
    // the git root against it.
    let worktree = create_task_worktree(&roots.git_root, task_id)
        .map_err(|e| format!("failed to create worktree: {e}"))?;

    // Apply at the crate dir INSIDE the worktree so `src/…` diff paths resolve
    // (matching the crate-relative hard-deny / allowlist). The patch file lives
    // at the worktree root, outside the crate's `src/`.
    let crate_in_wt = worktree.join(roots.crate_rel());
    let patch_file = worktree.join(".neoth_self_edit.patch");
    if let Err(e) = std::fs::write(&patch_file, diff_text.as_bytes()) {
        let _ = cleanup_worktree(&roots.git_root, &worktree, true);
        return Err(format!("failed to stage patch in worktree: {e}"));
    }

    let outcome = apply_patch_in_worktree(&crate_in_wt, &patch_file);
    // Drop the staged patch so layer 5's cargo check sees only the applied diff.
    let _ = std::fs::remove_file(&patch_file);

    match outcome {
        Ok(PatchApplyOutcome::Applied { .. }) => Ok(worktree),
        Ok(PatchApplyOutcome::Rejected { stderr }) => {
            let _ = cleanup_worktree(&roots.git_root, &worktree, true);
            Err(format!("patch rejected by git apply: {stderr}"))
        }
        Err(e) => {
            let _ = cleanup_worktree(&roots.git_root, &worktree, true);
            Err(format!("worktree patch error: {e}"))
        }
    }
}

/// Layer 5: run `cargo check` in the worktree and require a zero exit.
fn layer5_green_test(worktree: &Path) -> Result<(), String> {
    use std::time::Duration;

    // 5-minute timeout matches the default `test_timeout_secs`.
    let timeout = Duration::from_secs(5 * 60);

    // ponytail: cargo check only — no test run (spec says "cargo check", not
    // "cargo test"). Adding `cargo test` here would BSOD the box (see memory).
    let check_run = run_cargo_check_json(worktree, "cargo check", timeout)
        .map_err(|e| format!("cargo check invocation failed: {e}"))?;

    if check_run.passed {
        Ok(())
    } else {
        let errors: Vec<_> = check_run
            .diagnostics
            .iter()
            .filter(|d| d.level == "error")
            .take(5)
            .map(|d| d.message.as_str())
            .collect();
        Err(format!(
            "cargo check failed with {} error(s): {}",
            check_run.diagnostics.iter().filter(|d| d.level == "error").count(),
            errors.join("; ")
        ))
    }
}

/// Apply the diff to the live source tree using `git apply`, feeding the
/// validated in-memory bytes via stdin (`git apply --index -`).
///
/// Piping the bytes — rather than passing the on-disk path — guarantees the
/// live tree receives exactly what the five gates validated, eliminating the
/// TOCTOU window where the diff file could be replaced between validation and
/// apply. The WAL `diff_hash` (computed from the same bytes) therefore always
/// matches what was actually written.
fn apply_to_live_tree(source_root: &Path, diff_text: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = std::process::Command::new("git")
        .args(["apply", "--index", "-"])
        .current_dir(source_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("git apply failed to launch: {e}"))?;

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("git apply stdin unavailable"))?
        .write_all(diff_text.as_bytes())
        .map_err(|e| anyhow::anyhow!("write diff to git apply stdin: {e}"))?;

    let output = child
        .wait_with_output()
        .map_err(|e| anyhow::anyhow!("git apply wait failed: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git apply --index failed: {stderr}")
    }
}

// ── WAL emit helper ───────────────────────────────────────────────────────────

/// Emit a `EXTENDED/<subtype>` WAL frame. Best-effort: logs a warning on
/// failure but does NOT propagate the error (WAL is audit trail, not security).
async fn emit_wal(
    wal: Option<&WalWriterHandle>,
    subtype: ExtendedSubtype,
    audit: &SelfEditAudit,
) {
    let Some(writer) = wal else {
        warn!(
            subtype = subtype.name(),
            "self_edit: no WAL writer available — audit frame skipped"
        );
        return;
    };

    let payload = match serde_json::to_vec(audit) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "self_edit: failed to serialize audit payload; WAL frame skipped");
            return;
        }
    };

    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(subtype as u8)
        .flags(EventFlags::empty())
        .build();

    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "self_edit: WAL append failed");
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

/// Derive a pseudo `KanbanTaskId` from the first 8 hex chars of the diff hash.
///
/// This gives each self-edit attempt a unique worktree path without requiring
/// a real kanban task in the store.
fn pseudo_task_id(diff_hash: &str) -> KanbanTaskId {
    // Parse the first 8 hex chars of the SHA-256 as a u64 (always valid hex).
    let hex8 = &diff_hash[..8.min(diff_hash.len())];
    let raw = u64::from_str_radix(hex8, 16).unwrap_or(0xDEAD_BEEF);
    // Set the high bit to avoid collisions with real kanban task IDs (which
    // start from 1 and grow linearly).
    // Cast via as i64: bit pattern preserved, high bit set → negative i64
    // (avoids collisions with real task IDs which are small positive values).
    KanbanTaskId((raw | (1u64 << 63)) as i64)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ops::SelfEditConfig;
    use crate::permissions::AutonomyLevel;

    fn cfg_enabled(modules: &[&str]) -> SelfEditConfig {
        SelfEditConfig {
            enabled: true,
            allowed_modules: modules.iter().map(|s| s.to_string()).collect(),
            ..SelfEditConfig::default()
        }
    }

    fn cfg_disabled() -> SelfEditConfig {
        SelfEditConfig {
            enabled: false,
            ..SelfEditConfig::default()
        }
    }

    // ── Layer 1 ──────────────────────────────────────────────────────────────

    #[test]
    fn layer1_passes_when_enabled() {
        let cfg = cfg_enabled(&["src/cli"]);
        assert!(layer1_kill_switch(&cfg).is_ok());
    }

    #[test]
    fn layer1_fails_when_disabled() {
        let cfg = cfg_disabled();
        let err = layer1_kill_switch(&cfg).unwrap_err();
        assert!(err.contains("enabled = false"), "got: {err}");
    }

    // ── Layer 2 ──────────────────────────────────────────────────────────────

    #[test]
    fn layer2_passes_allowed_path() {
        // NOTE: src/cli/self_edit.rs is deliberately NOT usable here — the
        // orchestrator is hard-denied (gate-weakening class).
        let cfg = cfg_enabled(&["src/cli"]);
        let paths = vec!["src/cli/chat.rs".to_string()];
        assert!(layer2_allowlist(&cfg, &paths, 0).is_ok());
    }

    #[test]
    fn layer2_rejects_wal_path() {
        let cfg = cfg_enabled(&["src/wal"]);
        let paths = vec!["src/wal/writer.rs".to_string()];
        let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
        assert!(
            err.contains("hard-deny prefix"),
            "expected hard-deny error, got: {err}"
        );
    }

    #[test]
    fn layer2_rejects_gate_file_itself() {
        let cfg = cfg_enabled(&["src/coding"]);
        let paths = vec!["src/coding/self_source_gate.rs".to_string()];
        let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
        assert!(err.contains("hard-deny prefix"), "got: {err}");
    }

    #[test]
    fn layer2_rejects_freedom_yaml() {
        let cfg = cfg_enabled(&["src/cli", "."]);
        let paths = vec!["freedom.yaml".to_string()];
        let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
        assert!(err.contains("freedom.yaml"), "got: {err}");
    }

    #[test]
    fn layer2_rejects_secret_pattern() {
        let cfg = cfg_enabled(&["src/cli"]);
        let paths = vec!["src/cli/secret_token.rs".to_string()];
        let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
        assert!(err.contains("secret pattern"), "got: {err}");
    }

    #[test]
    fn layer2_rejects_path_not_in_allowlist() {
        let cfg = cfg_enabled(&["src/cli"]);
        let paths = vec!["src/memory/store.rs".to_string()];
        let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
        assert!(err.contains("not covered"), "got: {err}");
    }

    #[test]
    fn layer2_rejects_empty_allowlist() {
        let cfg = cfg_enabled(&[]);
        let paths = vec!["src/cli/foo.rs".to_string()];
        let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
        assert!(err.contains("allowed_modules is empty"), "got: {err}");
    }

    #[test]
    fn layer2_rejects_wal_path_case_insensitive() {
        // Windows FS is case-insensitive: src/WAL/ IS src/wal/. The deny must
        // catch it even though the raw string doesn't match `src/wal/`.
        let cfg = cfg_enabled(&["src/coding"]);
        for p in ["src/WAL/writer.rs", "SRC/wal/writer.rs", "src/Wal/writer.rs"] {
            let paths = vec![p.to_string()];
            let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
            assert!(err.contains("hard-deny prefix"), "path {p} not denied: {err}");
        }
    }

    #[test]
    fn layer2_rejects_freedom_yaml_case_insensitive() {
        let cfg = cfg_enabled(&["."]);
        let paths = vec!["Freedom.YAML".to_string()];
        let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
        assert!(err.contains("hard-deny fragment"), "got: {err}");
    }

    #[test]
    fn layer2_rejects_over_cap_diff() {
        // Cap is enforced IN the gate now, not only in the CLI.
        let cfg = cfg_enabled(&["src/cli"]);
        let paths = vec!["src/cli/foo.rs".to_string()];
        let over = cfg.max_lines_changed + 1;
        let err = layer2_allowlist(&cfg, &paths, over).unwrap_err();
        assert!(err.contains("max_lines_changed"), "got: {err}");
    }

    #[test]
    fn layer2_allows_at_exact_cap() {
        let cfg = cfg_enabled(&["src/cli"]);
        let paths = vec!["src/cli/foo.rs".to_string()];
        assert!(layer2_allowlist(&cfg, &paths, cfg.max_lines_changed).is_ok());
    }

    #[test]
    fn layer2_rejects_permissions_and_config_paths() {
        // The permission evaluator and config loader are as security-critical as
        // the WAL — self-edit may never touch them (gate-backdoor prevention).
        let cfg = cfg_enabled(&["src/permissions", "src/config"]);
        for p in ["src/permissions/mod.rs", "src/config/ops.rs", "src/config/mod.rs"] {
            let paths = vec![p.to_string()];
            let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
            assert!(err.contains("hard-deny prefix"), "path {p} not denied: {err}");
        }
    }

    #[test]
    fn layer2_allowlist_is_segment_aware() {
        // `src/cli` must NOT authorize a sibling dir `src/clitrap`.
        let cfg = cfg_enabled(&["src/cli"]);
        let bad = vec!["src/clitrap/evil.rs".to_string()];
        let err = layer2_allowlist(&cfg, &bad, 0).unwrap_err();
        assert!(err.contains("not covered"), "src/clitrap wrongly allowed: {err}");
        // The real dir under the prefix is still allowed.
        let ok = vec!["src/cli/foo.rs".to_string()];
        assert!(layer2_allowlist(&cfg, &ok, 0).is_ok());
    }

    // ── Layer 3 ──────────────────────────────────────────────────────────────

    #[test]
    fn layer3_denies_strict() {
        let paths = vec!["src/cli/foo.rs".to_string()];
        // Denied regardless of the ack flag.
        let err = layer3_permission(AutonomyLevel::Strict, &paths, true).unwrap_err();
        assert!(err.contains("strict"), "got: {err}");
    }

    #[test]
    fn layer3_denies_standard() {
        let paths = vec!["src/cli/foo.rs".to_string()];
        let err = layer3_permission(AutonomyLevel::Standard, &paths, true).unwrap_err();
        assert!(err.contains("standard"), "got: {err}");
    }

    #[test]
    fn layer3_elevated_passes_only_with_ack() {
        let paths = vec!["src/cli/foo.rs".to_string()];
        // Without the operator ack, Confirm is a REFUSAL — not a silent pass.
        let err = layer3_permission(AutonomyLevel::Elevated, &paths, false).unwrap_err();
        assert!(err.contains("--yes"), "expected ack-required error, got: {err}");
        assert!(layer3_permission(AutonomyLevel::Elevated, &paths, true).is_ok());
    }

    #[test]
    fn layer3_full_passes_only_with_ack() {
        let paths = vec!["src/cli/foo.rs".to_string()];
        // Policy: NEVER auto-apply, even at Full.
        assert!(layer3_permission(AutonomyLevel::Full, &paths, false).is_err());
        assert!(layer3_permission(AutonomyLevel::Full, &paths, true).is_ok());
    }

    #[test]
    fn layer2_rejects_build_time_execution_paths() {
        // Layer 5's `cargo check` EXECUTES build scripts / proc macros — any
        // path that shapes the build is host code execution and hard-denied.
        let cfg = cfg_enabled(&["src/cli", "."]);
        for p in [
            "src/cli/build.rs",
            "build.rs",
            "Cargo.toml",
            "neothd/Cargo.toml",
            "Cargo.lock",
            ".cargo/config.toml",
        ] {
            let err = layer2_allowlist(&cfg, &[p.to_string()], 1).unwrap_err();
            assert!(err.contains("hard-deny"), "path {p} not denied: {err}");
        }
    }

    #[test]
    fn layer2_rejects_gate_orchestrator_and_worktree_infra() {
        // Editing the CLI orchestrator or the layer-4/5 infrastructure is the
        // same class of gate-weakening as editing the gate itself.
        let cfg = cfg_enabled(&["src/cli", "src/coding"]);
        for p in [
            "src/cli/self_edit.rs",
            "src/coding/worktree.rs",
            "src/coding/mod.rs",
        ] {
            let err = layer2_allowlist(&cfg, &[p.to_string()], 1).unwrap_err();
            assert!(err.contains("hard-deny"), "path {p} not denied: {err}");
        }
    }

    #[test]
    fn layer2_empty_or_slash_prefix_is_not_allow_all() {
        // "" / "/" used to short-circuit the allowlist to allow-everything
        // (operator-precedence bug) — both must now cover NOTHING.
        for prefix in ["", "/"] {
            let cfg = cfg_enabled(&[prefix]);
            let err = layer2_allowlist(&cfg, &["src/tools/foo.rs".to_string()], 1).unwrap_err();
            assert!(err.contains("not covered"), "prefix {prefix:?} acted as allow-all: {err}");
        }
    }

    #[test]
    fn layer2_dot_prefix_means_whole_tree() {
        let cfg = cfg_enabled(&["."]);
        assert!(layer2_allowlist(&cfg, &["src/tools/foo.rs".to_string()], 1).is_ok());
    }

    // ── Reentrancy lock ──────────────────────────────────────────────────────

    #[test]
    fn self_edit_lock_blocks_reentry_until_released() {
        let root = std::env::temp_dir().join(format!(
            "neoth_self_edit_lock_test_{}",
            std::process::id()
        ));
        let first = SelfEditLock::acquire(&root).expect("first acquire");
        let second = SelfEditLock::acquire(&root);
        assert!(second.is_err(), "reentry must be refused while lock held");
        assert!(second.unwrap_err().contains("already in progress"));
        drop(first);
        // Drop released the lock file — a fresh acquire succeeds.
        let third = SelfEditLock::acquire(&root).expect("re-acquire after release");
        drop(third);
    }

    // ── End-to-end acceptance (spec: dummy.rs comment addition passes) ──────

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn init_fixture_repo(dir: &Path) {
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?} failed in fixture repo");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "neoth-test@example.com"]);
        git(&["config", "user.name", "neoth-test"]);
        // SourceRoots model: the crate dir must have BOTH `[package]` (so
        // `validate_crate_dir` accepts it) and a `src/` dir. `[workspace]` in the
        // same manifest makes git_root == crate_dir == workspace_dir for this
        // flat single-crate fixture.
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"self-edit-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/cli")).unwrap();
        std::fs::write(dir.join("src/cli/dummy.rs"), "fn dummy() {}\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "init"]);
    }

    #[tokio::test]
    async fn dummy_comment_addition_passes_all_gates_and_applies() {
        if !git_available() {
            eprintln!("git not on PATH — skipping e2e gate test");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        init_fixture_repo(tmp.path());

        let diff = "--- a/src/cli/dummy.rs\n\
                    +++ b/src/cli/dummy.rs\n\
                    @@ -1 +1,2 @@\n \
                    fn dummy() {}\n\
                    +// self-edit acceptance comment\n";

        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Elevated;
        cfg.coding.self_edit.enabled = true;
        cfg.coding.self_edit.allowed_modules = vec!["src/cli".to_string()];
        // The fixture repo has no compilable crate — layer 5's cargo plumbing
        // is covered by worktree.rs's run_cargo_check_json tests; skip it here.
        cfg.coding.self_edit.require_green_tests = false;
        cfg.coding.self_edit.source_root = Some(tmp.path().to_path_buf());

        let outcome = run_gate_stack(diff, &cfg, false, true, None)
            .await
            .expect("dummy.rs comment addition must pass all gates");
        assert_eq!(outcome.target_paths, vec!["src/cli/dummy.rs".to_string()]);
        assert!(!outcome.dry_run);

        let body = std::fs::read_to_string(tmp.path().join("src/cli/dummy.rs")).unwrap();
        assert!(
            body.contains("self-edit acceptance comment"),
            "live tree must contain the applied edit, got: {body}"
        );

        // The RAII guard must have removed the gate's worktree — only the
        // main tree remains in `git worktree list`.
        let list = std::process::Command::new("git")
            .arg("-C")
            .arg(tmp.path())
            .args(["worktree", "list", "--porcelain"])
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&list.stdout);
        assert_eq!(
            listing.matches("worktree ").count(),
            1,
            "gate worktree leaked: {listing}"
        );
    }

    // ── Pseudo task ID ───────────────────────────────────────────────────────

    #[test]
    fn pseudo_task_id_high_bit_set() {
        let id = pseudo_task_id("abcdef01234567890000000000000000000000000000000000000000deadbeef");
        assert!((id.0 as u64) & (1u64 << 63) != 0, "high bit must be set: {:x}", id.0);
    }

    #[test]
    fn pseudo_task_id_deterministic() {
        let hash = "aabbccdd00000000000000000000000000000000000000000000000000000000";
        assert_eq!(pseudo_task_id(hash).0, pseudo_task_id(hash).0);
    }
}
