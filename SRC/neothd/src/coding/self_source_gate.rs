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
//! Live applies additionally pass a caller-independent anti-loop cooldown
//! after the cross-process reentrancy lock is acquired.
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

use crate::cli::self_dev::SourceEditPreApplyPlan;
use crate::coding::self_source::{
    SourceRoots, diff_line_count, diff_paths, diff_sha256, neoth_source_root,
};
use crate::coding::types::KanbanTaskId;
use crate::coding::worktree::{
    PatchApplyOutcome, apply_patch_in_worktree, cleanup_worktree, create_task_worktree,
    run_cargo_check_json,
};
use crate::config::FreedomConfig;
use crate::config::ops::SelfEditConfig;
use crate::permissions::{self, Action, Decision};
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

impl Default for LayerOutcome {
    fn default() -> Self {
        Self::Skipped
    }
}

/// HEAD commit SHA and index tree SHA captured immediately after the
/// reentrancy lock is acquired and before the worktree is created.
///
/// Re-verified right before the live apply: if HEAD has moved (another commit
/// landed) or the index tree has changed (files were staged) between snapshot
/// and apply, the edit is refused — the gates evaluated a state that no longer
/// matches what `git apply --index` would land on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseShaSnapshot {
    /// Output of `git rev-parse HEAD` at capture time.
    pub head_sha: String,
    /// Output of `git write-tree` (current index tree) at capture time.
    pub index_tree: String,
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
    /// Outcome of the live-apply anti-loop cooldown. `Skipped` for dry-runs
    /// and WAL records written before this field existed.
    #[serde(default)]
    pub layer_apply_cooldown: LayerOutcome,
    pub ts_unix: i64,
    pub dry_run: bool,
    /// Snapshot captured after lock acquisition; `None` when capture failed
    /// (gate refuses before worktree creation). Present in every WAL record
    /// written after the base-SHA drift fix was introduced.
    #[serde(default)]
    pub base_snapshot: Option<BaseShaSnapshot>,
    /// Outcome of the pre-apply state-drift check (HEAD + index tree
    /// unchanged since snapshot). `Skipped` for dry-runs and for WAL records
    /// written before this field existed (backward-compatible default).
    #[serde(default)]
    pub layer_state_drift: LayerOutcome,
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
    #[error("apply cooldown: {0}")]
    Cooldown(String),
    /// HEAD or staged index moved between worktree-test and live-apply.
    /// The diff was NOT applied. The operator must re-submit against HEAD.
    #[error("state drift (pre-apply): {0}")]
    StateDrift(String),
    /// The live tree WAS mutated but the REQUIRED `SelfEditApplied` audit frame
    /// could not be written — an inconsistent state the operator must reconcile.
    /// Never reported as clean success.
    #[error("INCONSISTENT: edit applied to the live tree but the required audit frame failed: {0}")]
    AuditFailedAfterApply(String),
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
/// - `dry_run`: when `true`, every enabled gate still runs but the diff is NOT
///   applied to the live tree and no `SelfEditApplied` WAL frame is emitted.
///   A disabled green-test gate is allowed only in this preview mode.
/// - `wal`: optional handle to the WAL writer for audit emission. When `None`,
///   a warning is logged and the gates proceed (WAL is audit, not security).
/// - `source_edit_pre_apply_plan`: only proposal-bound callers populate this;
///   Git's Layer-4b plan and a final no-follow base-image snapshot must both
///   match before live mutation.
pub(crate) async fn run_gate_stack(
    diff_text: &str,
    cfg: &FreedomConfig,
    dry_run: bool,
    operator_acked: bool,
    wal: Option<&WalWriterHandle>,
    source_edit_pre_apply_plan: Option<&SourceEditPreApplyPlan>,
) -> Result<SelfEditOutcome, GateError> {
    let self_edit_cfg = &cfg.coding.self_edit;
    let diff_bytes = diff_text.as_bytes();
    let diff_hash = diff_sha256(diff_bytes);
    let ts = crate::time::now_unix_i64();
    let autonomy_policy = cfg.autonomy_policy();

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
        layer_apply_cooldown: LayerOutcome::Skipped,
        ts_unix: ts,
        dry_run,
        base_snapshot: None,
        layer_state_drift: LayerOutcome::Skipped,
    };

    // Emit PROPOSED frame BEFORE any gate runs (audit trail of all attempts).
    // Best-effort: a proposal-audit miss must not block the gate evaluation.
    let _ = emit_wal(wal, ExtendedSubtype::SelfEditProposed, &audit).await;

    // A gate refusal emits a REFUSED frame carrying the full per-layer status
    // (which layer blocked + why) so the WAL shows the real block reason, not an
    // unresolved `proposed` frame. Best-effort (a refusal-audit miss never
    // changes the refusal outcome).
    macro_rules! refuse {
        ($audit:expr, $err:expr) => {{
            let _ = emit_wal(wal, ExtendedSubtype::SelfEditRefused, &$audit).await;
            return Err($err);
        }};
    }

    // ── Layer 1: kill-switch ──────────────────────────────────────────────────
    match layer1_kill_switch(self_edit_cfg) {
        Ok(()) => {
            audit.layer1_kill_switch = LayerOutcome::Pass;
        }
        Err(reason) => {
            audit.layer1_kill_switch = LayerOutcome::Fail(reason.clone());
            info!(reason, "self_edit gate: layer1 kill-switch refused");
            refuse!(audit, GateError::KillSwitch(reason));
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
            refuse!(audit, GateError::Allowlist(reason));
        }
    }

    // ── Layer 3: autonomy permission gate ─────────────────────────────────────
    // dry_run implies acked: it never applies, so previewing needs no ack.
    match layer3_permission(&autonomy_policy, &target_paths, operator_acked || dry_run) {
        Ok(()) => {
            audit.layer3_permission = LayerOutcome::Pass;
        }
        Err(reason) => {
            audit.layer3_permission = LayerOutcome::Fail(reason.clone());
            info!(reason, "self_edit gate: layer3 permission refused");
            refuse!(audit, GateError::Permission(reason));
        }
    }

    // ── Layer 4: worktree isolation ───────────────────────────────────────────
    let roots = match neoth_source_root(&self_edit_cfg.source_root) {
        Ok(r) => r,
        Err(e) => {
            let reason = format!("source root detection failed: {e}");
            audit.layer4_worktree = LayerOutcome::Fail(reason.clone());
            refuse!(audit, GateError::Worktree(reason));
        }
    };

    // Reentrancy guard: a self-edit may never trigger further self-edits.
    // Layer 5 executes `cargo check` (build scripts run!) — if anything in
    // that process tree invokes `neoth self-edit` again, the lock refuses it.
    // File-based so it holds across processes; Drop releases it. Keyed on the
    // git root (one self-edit at a time per repo).
    let _reentrancy_lock = match SelfEditLock::acquire(&roots.git_root) {
        Ok(l) => l,
        Err(reason) => {
            audit.layer4_worktree = LayerOutcome::Fail(reason.clone());
            refuse!(audit, GateError::Worktree(reason));
        }
    };

    // Caller-independent anti-loop guard. It lives under the same cross-process
    // lock as the apply itself so two concurrent callers cannot both observe an
    // expired sentinel and race through. Dry-runs never read or write it.
    if !dry_run {
        let cooldown_path = self_edit_cooldown_path();
        match check_apply_cooldown_at(
            &cooldown_path,
            self_edit_cfg.apply_cooldown_secs,
            crate::time::now_unix_i64(),
        ) {
            Ok(()) => audit.layer_apply_cooldown = LayerOutcome::Pass,
            Err(reason) => {
                audit.layer_apply_cooldown = LayerOutcome::Fail(reason.clone());
                info!(reason, "self_edit gate: apply cooldown refused");
                refuse!(audit, GateError::Cooldown(reason));
            }
        }
    }

    // ── Base-SHA snapshot (M1 drift guard) ───────────────────────────────────
    // Capture HEAD + index tree right after the reentrancy lock so we have a
    // reference point for the state the gates are about to test. Re-verified
    // immediately before the live apply (see below). Runs in spawn_blocking
    // because it shells out to git.
    let base_snapshot = {
        let r = roots.clone();
        match tokio::task::spawn_blocking(move || capture_base_snapshot(&r.git_root)).await {
            Ok(Ok(snap)) => snap,
            Ok(Err(reason)) => {
                audit.layer_state_drift = LayerOutcome::Fail(reason.clone());
                refuse!(audit, GateError::StateDrift(reason));
            }
            Err(e) => {
                let reason = format!("base snapshot task panicked: {e}");
                audit.layer_state_drift = LayerOutcome::Fail(reason.clone());
                refuse!(audit, GateError::StateDrift(reason));
            }
        }
    };
    audit.base_snapshot = Some(base_snapshot.clone());

    // Use a pseudo-task-id derived from the diff hash (low bits) to get a
    // unique worktree path without requiring a real kanban task.
    let pseudo_id = pseudo_task_id(&diff_hash);
    // git subprocess spawns block; keep them off the async executor.
    let worktree = {
        let r = roots.clone();
        let dt = diff_text.to_string();
        match tokio::task::spawn_blocking(move || layer4_worktree(&r, &dt, pseudo_id)).await {
            Ok(Ok(wt)) => wt,
            Ok(Err(reason)) => {
                audit.layer4_worktree = LayerOutcome::Fail(reason.clone());
                refuse!(audit, GateError::Worktree(reason));
            }
            Err(e) => {
                let reason = format!("worktree task panicked: {e}");
                audit.layer4_worktree = LayerOutcome::Fail(reason.clone());
                refuse!(audit, GateError::Worktree(reason));
            }
        }
    };
    // RAII: from here the worktree is cleaned up on EVERY exit — error return,
    // panic unwind, and async cancellation (future dropped mid-await) alike.
    // Cleanup is a `git worktree remove` run from the git root.
    let _worktree_guard = WorktreeGuard::new(roots.git_root.clone(), worktree.clone());

    // ── Layer 4b: git-truth path differential ─────────────────────────────────
    // Re-validate against GIT's actual changed paths + modes, not the vendored
    // `---/+++` parser (renames/binary/mode/symlink/second-file smuggling).
    let real_paths = {
        let r = roots.clone();
        let wt = worktree.clone();
        let cfg2 = self_edit_cfg.clone();
        let cl = diff_line_count(diff_text);
        match tokio::task::spawn_blocking(move || verify_git_truth(&r, &wt, &cfg2, cl)).await {
            Ok(Ok(paths)) => paths,
            Ok(Err(reason)) => {
                audit.layer2_allowlist = LayerOutcome::Fail(reason.clone());
                info!(
                    reason,
                    "self_edit gate: layer4b git-truth differential refused"
                );
                refuse!(audit, GateError::Allowlist(reason));
            }
            Err(e) => {
                let reason = format!("git-truth task panicked: {e}");
                audit.layer4_worktree = LayerOutcome::Fail(reason.clone());
                refuse!(audit, GateError::Worktree(reason));
            }
        }
    };
    // Record git's authoritative path set in the audit (may differ from / be a
    // superset of the parser's `target_paths`).
    audit.target_paths = real_paths.clone();
    audit.layer4_worktree = LayerOutcome::Pass;

    // A SourceEdit proposal binds a finite authoritative path set. Git—not the
    // lightweight unified-diff parser—is the final authority after worktree
    // application, so reject additions, removals, renames and mode-smuggled
    // paths HERE, before Layer 5 or the live `git apply` sink can run.
    if let Some(plan) = source_edit_pre_apply_plan
        && !exact_authoritative_path_set(plan.target_paths(), &real_paths)
    {
        let reason = format!(
            "proposal-bound source edit path mismatch: reviewed {:?}, git resolved {:?}",
            plan.target_paths(),
            real_paths
        );
        audit.layer2_allowlist = LayerOutcome::Fail(reason.clone());
        let _ = emit_wal(wal, ExtendedSubtype::SelfEditRefused, &audit).await;
        return Err(GateError::Allowlist(reason));
    }

    // ── Layer 3b: autonomy permission re-check on git-truth paths ─────────────
    // The Layer-3 check above ran on the vendored-parser `target_paths`. Layer-4b
    // already re-ran the ALLOWLIST on git's authoritative `real_paths`, but the
    // autonomy-TIER permission gate was not — so a diff crafted to hide a
    // permission-elevating path from the `---/+++` parser (while git still sees
    // it) could clear Layer 3 with the wrong path set. Re-run it on `real_paths`.
    match layer3_permission(&autonomy_policy, &real_paths, operator_acked || dry_run) {
        Ok(()) => {
            audit.layer3_permission = LayerOutcome::Pass;
        }
        Err(reason) => {
            audit.layer3_permission = LayerOutcome::Fail(reason.clone());
            info!(
                reason,
                "self_edit gate: layer3 permission refused (git-truth re-check)"
            );
            refuse!(audit, GateError::Permission(reason));
        }
    }

    // ── Layer 5: green-test gate (cargo check) ────────────────────────────────
    if self_edit_cfg.require_green_tests {
        // cargo check runs in the WORKSPACE dir inside the worktree so the whole
        // workspace resolves (NEOTH's workspace is a subdir of the git root).
        let wt = worktree.join(roots.workspace_rel());
        let outcome = match tokio::task::spawn_blocking(move || layer5_green_test(&wt)).await {
            Ok(o) => o,
            Err(e) => {
                let reason = format!("green-test task panicked: {e}");
                audit.layer5_green_test = LayerOutcome::Fail(reason.clone());
                refuse!(audit, GateError::GreenTest(reason));
            }
        };
        match outcome {
            Ok(()) => {
                audit.layer5_green_test = LayerOutcome::Pass;
            }
            Err(reason) => {
                audit.layer5_green_test = LayerOutcome::Fail(reason.clone());
                info!(reason, "self_edit gate: layer5 green-test refused");
                refuse!(audit, GateError::GreenTest(reason));
            }
        }
    } else if dry_run {
        audit.layer5_green_test = LayerOutcome::Skipped;
    } else {
        let reason = "require_green_tests=false is allowed only for dry-run previews; \
                      live self-source apply requires Layer 5 cargo check"
            .to_string();
        audit.layer5_green_test = LayerOutcome::Fail(reason.clone());
        warn!(
            reason,
            "self_edit gate: live apply without green tests refused"
        );
        refuse!(audit, GateError::GreenTest(reason));
    }

    // ── All gates passed — apply to live tree (unless --dry-run) ─────────────
    if !dry_run {
        // A live apply REQUIRES a WAL writer — enforced HERE, inside the gate,
        // so no caller (CLI, daemon, GUI, future IPC) can mutate the source
        // tree without a forensic record. Dry-runs stay WAL-optional; refusal
        // paths above stay testable with `wal: None`.
        if wal.is_none() {
            return Err(GateError::Audit(anyhow::anyhow!(
                "live apply requires a WAL writer — refusing to mutate the \
                 source tree without an audit trail (use dry_run to preview)"
            )));
        }
        // ── M1 drift check: verify HEAD + index unchanged since snapshot ────
        // Between worktree-creation and this point another process could have
        // committed (HEAD moves) or staged files (index tree changes). Neither
        // makes `git apply --index` error on non-conflicting diffs, so without
        // this check the patch would silently land on a different overall state
        // than the one the 5 gates evaluated. Any drift → refuse, emit
        // SelfEditRefused via the existing 0x05 opcode (no new WAL opcode).
        {
            let r = roots.clone();
            let snap = base_snapshot.clone();
            match tokio::task::spawn_blocking(move || verify_base_snapshot(&r.git_root, &snap))
                .await
            {
                Ok(Ok(())) => {
                    audit.layer_state_drift = LayerOutcome::Pass;
                }
                Ok(Err(reason)) => {
                    audit.layer_state_drift = LayerOutcome::Fail(reason.clone());
                    warn!(
                        reason,
                        "self_edit: state drift detected before live apply — refusing"
                    );
                    let _ = emit_wal(wal, ExtendedSubtype::SelfEditRefused, &audit).await;
                    return Err(GateError::StateDrift(reason));
                }
                Err(e) => {
                    let reason = format!("drift check task panicked: {e}");
                    audit.layer_state_drift = LayerOutcome::Fail(reason.clone());
                    let _ = emit_wal(wal, ExtendedSubtype::SelfEditRefused, &audit).await;
                    return Err(GateError::StateDrift(reason));
                }
            }
        }

        // Final proposal-bound live-sink invariant, deliberately after the
        // generic Git HEAD/index proof and immediately before `git apply`.
        // The bounded no-follow snapshot must still equal the transaction's
        // authenticated base images; no parser-only or stale source state can
        // cross the mutation boundary.
        if let Some(plan) = source_edit_pre_apply_plan {
            let plan_matches = if !plan.binds_source_root(&roots.crate_dir) {
                Ok(false)
            } else {
                plan.exact_base_images_still_match().await
            };
            match plan_matches {
                Ok(true) => {}
                Ok(false) => {
                    let reason = "proposal-bound source edit base images changed before live apply"
                        .to_owned();
                    audit.layer_state_drift = LayerOutcome::Fail(reason.clone());
                    let _ = emit_wal(wal, ExtendedSubtype::SelfEditRefused, &audit).await;
                    return Err(GateError::StateDrift(reason));
                }
                Err(error) => {
                    let reason = format!(
                        "proposal-bound source edit base-image proof unavailable before live apply: {error:#}"
                    );
                    audit.layer_state_drift = LayerOutcome::Fail(reason.clone());
                    let _ = emit_wal(wal, ExtendedSubtype::SelfEditRefused, &audit).await;
                    return Err(GateError::StateDrift(reason));
                }
            }
        }

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

        // Update audit timestamp to reflect the actual apply moment. The
        // SelfEditApplied frame is a REQUIRED audit: the entry guard above
        // guarantees a writer is present for every live apply, so any write
        // failure here is an inconsistent state (tree mutated, no forensic
        // record) and must surface as AuditFailedAfterApply — never as clean
        // success.
        audit.ts_unix = crate::time::now_unix_i64();
        if let Err(e) = emit_wal(wal, ExtendedSubtype::SelfEditApplied, &audit).await {
            return Err(GateError::AuditFailedAfterApply(e));
        }
        if self_edit_cfg.apply_cooldown_secs > 0 {
            let path = self_edit_cooldown_path();
            if let Err(error) = record_apply_cooldown_at(&path, audit.ts_unix) {
                warn!(
                    error,
                    path = %path.display(),
                    "self_edit: cannot record apply cooldown sentinel"
                );
            }
        }
        info!(
            paths = ?real_paths,
            diff_hash,
            "self_edit gate: all gates passed — diff applied to live tree"
        );
    } else {
        info!(
            paths = ?real_paths,
            diff_hash,
            "self_edit gate: all 5 gates passed (dry-run — NOT applied to live tree)"
        );
    }

    // Return git's authoritative path set, not the vendored-parser `target_paths`
    // — callers (and the JSON/table output) must see the same files the WAL audit
    // recorded (`audit.target_paths = real_paths`), never the pre-verification set.
    Ok(SelfEditOutcome {
        target_paths: real_paths,
        diff_hash,
        dry_run,
    })
}

/// Path equality is set equality with no duplicate tolerance. Both inputs are
/// expected to be validated clean relative paths; sorting only gives the
/// comparison a stable order while preserving the exact member requirement.
fn exact_authoritative_path_set(expected: &[String], actual: &[String]) -> bool {
    if expected.is_empty() || expected.len() != actual.len() {
        return false;
    }
    let mut expected = expected.to_vec();
    let mut actual = actual.to_vec();
    expected.sort();
    actual.sort();
    expected == actual
}

/// Canonical anti-loop sentinel (`~/.neoth/self_edit/last_apply`).
fn self_edit_cooldown_path() -> PathBuf {
    FreedomConfig::default_neoth_home()
        .join("self_edit")
        .join("last_apply")
}

/// Refuse when `path` records a successful live apply inside the configured
/// interval. Missing files mean no previous apply; unreadable or malformed
/// sentinels fail closed so corruption cannot silently disable the guard.
fn check_apply_cooldown_at(
    path: &Path,
    cooldown_secs: u64,
    now_unix: i64,
) -> std::result::Result<(), String> {
    if cooldown_secs == 0 {
        return Ok(());
    }
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "read cooldown sentinel {}: {error}",
                path.display()
            ));
        }
    };
    let last_apply = content
        .trim()
        .parse::<i64>()
        .map_err(|error| format!("invalid cooldown sentinel {}: {error}", path.display()))?;
    if last_apply < 0 {
        return Err(format!(
            "invalid cooldown sentinel {}: timestamp must be non-negative",
            path.display()
        ));
    }
    let elapsed = now_unix.saturating_sub(last_apply).max(0) as u64;
    if elapsed < cooldown_secs {
        let remaining = cooldown_secs - elapsed;
        return Err(format!(
            "self-edit apply on cooldown — {remaining}s remaining (cooldown: \
             {cooldown_secs}s). Adjust \
             freedom.yaml::coding.self_edit.apply_cooldown_secs to change this limit."
        ));
    }
    Ok(())
}

fn record_apply_cooldown_at(path: &Path, now_unix: i64) -> std::result::Result<(), String> {
    crate::util::atomic_write::atomic_write_private(path, now_unix.to_string().as_bytes())
        .map_err(|error| format!("atomic write cooldown sentinel {}: {error}", path.display()))
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
fn layer3_permission<P: permissions::PolicyArgument>(
    policy: P,
    target_paths: &[String],
    operator_acked: bool,
) -> Result<(), String> {
    let action = Action::SelfSourceEdit {
        target_paths: target_paths.to_vec(),
    };
    match permissions::evaluate(&action, policy) {
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
            check_run
                .diagnostics
                .iter()
                .filter(|d| d.level == "error")
                .count(),
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

// ── Layer 4b: git-truth path differential guard ───────────────────────────────

/// After the patch is applied in the worktree, ask GIT ITSELF for the exact set
/// of changed paths + modes and re-validate them — instead of trusting the
/// vendored `--- a/ +++ b/` parser (`diff_paths`), which cannot see renames,
/// copies, binary hunks, mode changes, symlink/submodule creations, or a second
/// file smuggled into a combined patch. Without this, the hard-deny list is only
/// as strong as the incomplete pre-parser: a patch could modify an allowed text
/// file via `---/+++` (the only path in `target_paths`) AND rewrite a protected
/// file via a rename/binary hunk that git happily applies.
///
/// Policy (v1, deliberately strict — fail-closed):
/// - reject symlink (`120000`), submodule/gitlink (`160000`) creations,
/// - reject file-mode changes (e.g. chmod +x on a script),
/// - reject rename/copy/type-change statuses (`R`/`C`/`T`),
/// - reject binary hunks,
/// - reject any changed path that escapes the crate dir,
/// - re-run the full Layer-2 deny/allowlist against every real changed path.
fn verify_git_truth(
    roots: &SourceRoots,
    worktree: &Path,
    cfg: &SelfEditConfig,
    changed_lines: usize,
) -> Result<Vec<String>, String> {
    let run_git = |args: &[&str]| -> Result<std::process::Output, String> {
        std::process::Command::new("git")
            .arg("-C")
            .arg(worktree)
            .args(args)
            .output()
            .map_err(|e| format!("git {args:?} failed to launch: {e}"))
    };

    // Stage every applied change so a single `diff --cached` sees the full set
    // (incl. new files) with mode + status classification.
    let add = run_git(&["add", "-A"])?;
    if !add.status.success() {
        return Err(format!(
            "git add -A in worktree failed: {}",
            String::from_utf8_lossy(&add.stderr).trim()
        ));
    }

    // `--raw -z`: one record per change = `:<oldmode> <newmode> <sha1> <sha2> <status>\0<path>\0`.
    // `--no-renames` expands a rename into DELETE(old)+ADD(new) so BOTH paths are
    // seen (a rename INTO a protected path can't hide behind rename detection).
    let raw = run_git(&["diff", "--cached", "--no-renames", "--raw", "-z"])?;
    if !raw.status.success() {
        return Err(format!(
            "git diff --raw in worktree failed: {}",
            String::from_utf8_lossy(&raw.stderr).trim()
        ));
    }
    let raw_str = String::from_utf8_lossy(&raw.stdout);
    let fields: Vec<&str> = raw_str.split('\0').filter(|s| !s.is_empty()).collect();

    // Binary detection via numstat: a binary change renders as `-\t-\t<path>`.
    let numstat = run_git(&["diff", "--cached", "--numstat", "-z"])?;
    let numstat_str = String::from_utf8_lossy(&numstat.stdout);
    let binary_paths: std::collections::BTreeSet<&str> = numstat_str
        .split('\0')
        .filter(|s| !s.is_empty())
        .filter_map(|rec| rec.strip_prefix("-\t-\t"))
        .collect();

    let crate_rel = roots.crate_rel();
    let crate_prefix = {
        let p = crate_rel.to_string_lossy().replace('\\', "/");
        if p == "." {
            String::new()
        } else {
            format!("{}/", p.trim_end_matches('/'))
        }
    };

    let mut real_paths: Vec<String> = Vec::new();
    // Records come in (meta, path) pairs.
    let mut i = 0;
    while i + 1 < fields.len() {
        let meta = fields[i];
        let repo_path = fields[i + 1];
        i += 2;

        // meta = ":100644 100755 sha1 sha2 M"
        let parts: Vec<&str> = meta.trim_start_matches(':').split(' ').collect();
        if parts.len() < 5 {
            return Err(format!("unparseable git raw record '{meta}'"));
        }
        let old_mode = parts[0];
        let new_mode = parts[1];
        let status = parts[4];

        if new_mode == "120000" {
            return Err(format!("symlink change to '{repo_path}' is refused"));
        }
        if new_mode == "160000" || old_mode == "160000" {
            return Err(format!(
                "submodule/gitlink change to '{repo_path}' is refused"
            ));
        }
        if old_mode != "000000" && new_mode != "000000" && old_mode != new_mode {
            return Err(format!(
                "file-mode change ({old_mode}->{new_mode}) on '{repo_path}' is refused"
            ));
        }
        if matches!(status, "R" | "C" | "T") || status.starts_with('R') || status.starts_with('C') {
            return Err(format!(
                "rename/copy/type-change ('{status}') on '{repo_path}' is refused"
            ));
        }
        if binary_paths.contains(repo_path) {
            return Err(format!("binary change to '{repo_path}' is refused"));
        }

        // Map the repo-root-relative path back to a crate-relative path. A path
        // that does not live under the crate dir has escaped the self-edit
        // surface entirely — refuse.
        let crate_path = if crate_prefix.is_empty() {
            repo_path.to_string()
        } else if let Some(stripped) = repo_path.strip_prefix(&crate_prefix) {
            stripped.to_string()
        } else {
            return Err(format!(
                "changed path '{repo_path}' is outside the crate dir '{crate_prefix}' — refused"
            ));
        };
        real_paths.push(crate_path);
    }

    if real_paths.is_empty() {
        return Err("git reports no changes after apply — refusing (nothing to audit)".into());
    }

    // The authoritative re-check: git's REAL paths through the full Layer-2 gate.
    layer2_allowlist(cfg, &real_paths, changed_lines)?;
    Ok(real_paths)
}

// ── Base-SHA snapshot helpers ─────────────────────────────────────────────────

/// Capture the current HEAD commit SHA and index tree SHA from `git_root`.
///
/// Both values are used by [`verify_base_snapshot`] right before the live
/// apply to detect any concurrent mutation of the repo state.
fn capture_base_snapshot(git_root: &Path) -> Result<BaseShaSnapshot, String> {
    let run_git = |args: &[&str]| -> Result<String, String> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(git_root)
            .args(args)
            .output()
            .map_err(|e| format!("git {args:?} failed to launch: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    let head_sha = run_git(&["rev-parse", "HEAD"])?;
    // `git write-tree` serialises the current index as a tree object and
    // prints its SHA. Idempotent and side-effect-free (the tree object may
    // already exist; GC reclaims unreferenced objects later). Captures staged
    // changes that have not yet been committed.
    let index_tree = run_git(&["write-tree"])?;
    Ok(BaseShaSnapshot {
        head_sha,
        index_tree,
    })
}

/// Re-check that `git_root`'s HEAD and index tree match the captured snapshot.
///
/// Returns `Err` with a human-readable message if either has changed, so the
/// caller can emit `SelfEditRefused` and return `GateError::StateDrift` before
/// the live apply runs. The error message names the old/new values (first 12
/// chars) so the operator understands what happened without needing to grep
/// the WAL.
fn verify_base_snapshot(git_root: &Path, base: &BaseShaSnapshot) -> Result<(), String> {
    let run_git = |args: &[&str]| -> Result<String, String> {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(git_root)
            .args(args)
            .output()
            .map_err(|e| format!("git {args:?} failed to launch: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    fn abbrev(sha: &str) -> &str {
        &sha[..12.min(sha.len())]
    }

    let current_head = run_git(&["rev-parse", "HEAD"])?;
    if current_head != base.head_sha {
        return Err(format!(
            "HEAD moved between worktree test and live apply \
             (was {}, now {}) — another commit landed while the gates ran; \
             re-submit the diff against the current HEAD",
            abbrev(&base.head_sha),
            abbrev(&current_head),
        ));
    }

    let current_tree = run_git(&["write-tree"])?;
    if current_tree != base.index_tree {
        return Err(format!(
            "staged index changed between worktree test and live apply \
             (tree was {}, now {}) — the index was modified concurrently; \
             re-submit to avoid applying to a different state than what was tested",
            abbrev(&base.index_tree),
            abbrev(&current_tree),
        ));
    }

    Ok(())
}

// ── WAL emit helper ───────────────────────────────────────────────────────────

/// Emit a `EXTENDED/<subtype>` WAL frame. Returns `Err` on a genuine write
/// failure (serialize / closed writer / append) so callers that REQUIRE the
/// audit (the post-apply `SelfEditApplied` frame) can surface an inconsistent
/// state instead of reporting clean success. Refusal/proposal frames call this
/// best-effort (they ignore the `Err`).
async fn emit_wal(
    wal: Option<&WalWriterHandle>,
    subtype: ExtendedSubtype,
    audit: &SelfEditAudit,
) -> Result<(), String> {
    let Some(writer) = wal else {
        warn!(
            subtype = subtype.name(),
            "self_edit: no WAL writer available — audit frame skipped"
        );
        return Err("no WAL writer available".into());
    };

    let payload = serde_json::to_vec(audit).map_err(|e| {
        warn!(error = %e, "self_edit: failed to serialize audit payload; WAL frame skipped");
        format!("serialize audit payload: {e}")
    })?;

    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(subtype as u8)
        .flags(EventFlags::empty())
        .build();

    writer
        .append(header, payload)
        .await
        .map(|_| ())
        .map_err(|e| {
            warn!(error = %e, "self_edit: WAL append failed");
            format!("WAL append: {e}")
        })
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
        for p in [
            "src/WAL/writer.rs",
            "SRC/wal/writer.rs",
            "src/Wal/writer.rs",
        ] {
            let paths = vec![p.to_string()];
            let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
            assert!(
                err.contains("hard-deny prefix"),
                "path {p} not denied: {err}"
            );
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
        for p in [
            "src/permissions/mod.rs",
            "src/config/ops.rs",
            "src/config/mod.rs",
        ] {
            let paths = vec![p.to_string()];
            let err = layer2_allowlist(&cfg, &paths, 0).unwrap_err();
            assert!(
                err.contains("hard-deny prefix"),
                "path {p} not denied: {err}"
            );
        }
    }

    #[test]
    fn layer2_allowlist_is_segment_aware() {
        // `src/cli` must NOT authorize a sibling dir `src/clitrap`.
        let cfg = cfg_enabled(&["src/cli"]);
        let bad = vec!["src/clitrap/evil.rs".to_string()];
        let err = layer2_allowlist(&cfg, &bad, 0).unwrap_err();
        assert!(
            err.contains("not covered"),
            "src/clitrap wrongly allowed: {err}"
        );
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
        assert!(
            err.contains("--yes"),
            "expected ack-required error, got: {err}"
        );
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
            assert!(
                err.contains("not covered"),
                "prefix {prefix:?} acted as allow-all: {err}"
            );
        }
    }

    #[test]
    fn layer2_dot_prefix_means_whole_tree() {
        let cfg = cfg_enabled(&["."]);
        assert!(layer2_allowlist(&cfg, &["src/tools/foo.rs".to_string()], 1).is_ok());
    }

    #[test]
    fn proposal_bound_authoritative_path_plan_requires_exact_set_equality() {
        let reviewed = vec!["src/cli/a.rs".to_string(), "src/cli/b.rs".to_string()];
        assert!(exact_authoritative_path_set(
            &reviewed,
            &["src/cli/b.rs".to_string(), "src/cli/a.rs".to_string()],
        ));
        assert!(!exact_authoritative_path_set(
            &reviewed,
            &[
                "src/cli/a.rs".to_string(),
                "src/cli/b.rs".to_string(),
                "src/cli/hidden.rs".to_string(),
            ],
        ));
        assert!(!exact_authoritative_path_set(
            &reviewed,
            &["src/cli/a.rs".to_string(), "src/cli/a.rs".to_string()],
        ));
    }

    // ── Reentrancy lock ──────────────────────────────────────────────────────

    #[test]
    fn self_edit_lock_blocks_reentry_until_released() {
        let root =
            std::env::temp_dir().join(format!("neoth_self_edit_lock_test_{}", std::process::id()));
        let first = SelfEditLock::acquire(&root).expect("first acquire");
        let second = SelfEditLock::acquire(&root);
        assert!(second.is_err(), "reentry must be refused while lock held");
        assert!(second.unwrap_err().contains("already in progress"));
        drop(first);
        // Drop released the lock file — a fresh acquire succeeds.
        let third = SelfEditLock::acquire(&root).expect("re-acquire after release");
        drop(third);
    }

    #[test]
    fn apply_cooldown_is_fail_closed_and_recorded_atomically() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sentinel = tmp.path().join("nested").join("last_apply");

        assert!(check_apply_cooldown_at(&sentinel, 300, 1_000).is_ok());
        record_apply_cooldown_at(&sentinel, 900).expect("record sentinel");
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "900");

        let fresh = check_apply_cooldown_at(&sentinel, 300, 1_000).unwrap_err();
        assert!(
            fresh.contains("200s remaining"),
            "unexpected error: {fresh}"
        );
        assert!(check_apply_cooldown_at(&sentinel, 300, 1_200).is_ok());

        std::fs::write(&sentinel, "not-a-timestamp").unwrap();
        let corrupt = check_apply_cooldown_at(&sentinel, 300, 1_200).unwrap_err();
        assert!(corrupt.contains("invalid cooldown sentinel"));
        assert!(
            check_apply_cooldown_at(&sentinel, 0, 1_200).is_ok(),
            "zero explicitly disables the guard even when the sentinel is corrupt"
        );
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
        std::fs::write(dir.join("src/lib.rs"), "// compilable fixture target\n").unwrap();
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
        cfg.coding.self_edit.require_green_tests = true;
        cfg.coding.self_edit.apply_cooldown_secs = 0;
        cfg.coding.self_edit.source_root = Some(tmp.path().to_path_buf());

        // Live applies require a WAL writer (gate-enforced) — spawn one into
        // the fixture tempdir so the applied-frame audit has somewhere to go.
        let wal_seg = tmp.path().join("wal").join("self_edit_audit.wal");
        std::fs::create_dir_all(wal_seg.parent().unwrap()).unwrap();
        let (wal_handle, wal_join) =
            crate::wal::writer::spawn(wal_seg).expect("fixture WAL writer");

        let outcome = run_gate_stack(diff, &cfg, false, true, Some(&wal_handle), None)
            .await
            .expect("dummy.rs comment addition must pass all gates");
        drop(wal_handle);
        let _ = wal_join.await;
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

    #[tokio::test]
    async fn disabled_green_test_is_preview_only_and_live_apply_fails_closed() {
        if !git_available() {
            eprintln!("git not on PATH — skipping green-test policy test");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        init_fixture_repo(tmp.path());

        let diff = "--- a/src/cli/dummy.rs\n\
                    +++ b/src/cli/dummy.rs\n\
                    @@ -1 +1,2 @@\n \
                    fn dummy() {}\n\
                    +// untested apply attempt\n";
        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Elevated;
        cfg.coding.self_edit.enabled = true;
        cfg.coding.self_edit.allowed_modules = vec!["src/cli".to_string()];
        cfg.coding.self_edit.require_green_tests = false;
        cfg.coding.self_edit.apply_cooldown_secs = 0;
        cfg.coding.self_edit.source_root = Some(tmp.path().to_path_buf());

        let preview = run_gate_stack(diff, &cfg, true, false, None, None)
            .await
            .expect("dry-run may explicitly skip Layer 5");
        assert!(preview.dry_run);

        let err = run_gate_stack(diff, &cfg, false, true, None, None)
            .await
            .expect_err("live apply must not bypass Layer 5");
        assert!(
            matches!(err, GateError::GreenTest(_)),
            "expected GreenTest refusal, got: {err:?}"
        );
        let body = std::fs::read_to_string(tmp.path().join("src/cli/dummy.rs")).unwrap();
        assert!(
            !body.contains("untested apply attempt"),
            "live tree must remain unchanged after a Layer 5 refusal: {body}"
        );
    }

    /// Pins the gate-internal WAL invariant: a live apply with `wal: None`
    /// must be REFUSED before the tree is touched, no matter how careful the
    /// caller is elsewhere. Guards against any future GUI/IPC/daemon caller
    /// (or refactor) re-opening the unaudited-apply path.
    #[tokio::test]
    async fn live_apply_without_wal_writer_is_refused_before_mutation() {
        if !git_available() {
            eprintln!("git not on PATH — skipping WAL-required gate test");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        init_fixture_repo(tmp.path());

        let diff = "--- a/src/cli/dummy.rs\n\
                    +++ b/src/cli/dummy.rs\n\
                    @@ -1 +1,2 @@\n \
                    fn dummy() {}\n\
                    +// unaudited apply attempt\n";

        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Elevated;
        cfg.coding.self_edit.enabled = true;
        cfg.coding.self_edit.allowed_modules = vec!["src/cli".to_string()];
        cfg.coding.self_edit.require_green_tests = true;
        cfg.coding.self_edit.apply_cooldown_secs = 0;
        cfg.coding.self_edit.source_root = Some(tmp.path().to_path_buf());

        let err = run_gate_stack(diff, &cfg, false, true, None, None)
            .await
            .expect_err("live apply without a WAL writer must be refused");
        assert!(
            matches!(err, GateError::Audit(_)),
            "expected Audit refusal, got: {err:?}"
        );
        let body = std::fs::read_to_string(tmp.path().join("src/cli/dummy.rs")).unwrap();
        assert!(
            !body.contains("unaudited apply attempt"),
            "live tree must NOT be mutated on a WAL-less apply, got: {body}"
        );
    }

    #[tokio::test]
    async fn git_truth_refuses_rename_into_protected_path_the_parser_cannot_see() {
        // #1 git-parser-differential: a PURE RENAME patch has no `--- a/ +++ b/`
        // hunk lines, so the vendored `diff_paths` parser extracts ZERO paths and
        // Layer 2 passes vacuously. git still performs the rename. Layer 4b asks
        // git for the REAL changed paths and re-runs Layer 2 → the new path under
        // `src/wal/` (hard-denied) is caught. Without 4b this edit would apply.
        if !git_available() {
            eprintln!("git not on PATH — skipping git-truth differential test");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        init_fixture_repo(tmp.path());

        // 100% rename of the allowed dummy.rs INTO the hard-denied src/wal/ tree.
        let diff = "diff --git a/src/cli/dummy.rs b/src/wal/evil.rs\n\
                    similarity index 100%\n\
                    rename from src/cli/dummy.rs\n\
                    rename to src/wal/evil.rs\n";

        let mut cfg = FreedomConfig::default();
        cfg.autonomy = AutonomyLevel::Elevated;
        cfg.coding.self_edit.enabled = true;
        cfg.coding.self_edit.allowed_modules = vec!["src/cli".to_string()];
        cfg.coding.self_edit.require_green_tests = false;
        cfg.coding.self_edit.apply_cooldown_secs = 0;
        cfg.coding.self_edit.source_root = Some(tmp.path().to_path_buf());

        let err = run_gate_stack(diff, &cfg, false, true, None, None)
            .await
            .expect_err("rename into src/wal/ must be refused by the git-truth guard");
        // Refused at the allowlist layer on git's REAL path set.
        assert!(
            matches!(err, GateError::Allowlist(_)),
            "expected Allowlist refusal, got: {err:?}"
        );
        // The protected file must NOT exist in the live tree.
        assert!(
            !tmp.path().join("src/wal/evil.rs").exists(),
            "the rename must have been refused before touching the live tree"
        );
    }

    // ── Base-SHA snapshot / M1 drift guard ──────────────────────────────────

    #[test]
    fn capture_base_snapshot_returns_valid_shas() {
        if !git_available() {
            eprintln!("git not on PATH — skipping base-snapshot capture test");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        init_fixture_repo(tmp.path());

        let snap = capture_base_snapshot(tmp.path()).expect("capture must succeed");
        // SHA-1 OIDs are 40 hex chars; SHA-256 repos produce 64. Either is fine.
        assert!(
            snap.head_sha.len() >= 40,
            "head_sha too short: {:?}",
            snap.head_sha
        );
        assert!(
            snap.index_tree.len() >= 40,
            "index_tree too short: {:?}",
            snap.index_tree
        );
        assert!(
            snap.head_sha.chars().all(|c| c.is_ascii_hexdigit()),
            "head_sha contains non-hex chars: {:?}",
            snap.head_sha
        );
        assert!(
            snap.index_tree.chars().all(|c| c.is_ascii_hexdigit()),
            "index_tree contains non-hex chars: {:?}",
            snap.index_tree
        );
    }

    #[test]
    fn drift_check_passes_when_repo_unchanged() {
        if !git_available() {
            eprintln!("git not on PATH — skipping drift no-change test");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        init_fixture_repo(tmp.path());

        let snap = capture_base_snapshot(tmp.path()).expect("capture");
        verify_base_snapshot(tmp.path(), &snap).expect("unchanged repo must pass drift check");
    }

    #[test]
    fn drift_check_refused_when_head_moves() {
        if !git_available() {
            eprintln!("git not on PATH — skipping head-drift test");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        init_fixture_repo(tmp.path());

        let snap = capture_base_snapshot(tmp.path()).expect("capture");

        // Advance HEAD with a new commit while the "gates are running".
        let new_file = tmp.path().join("src/cli/added.rs");
        std::fs::write(&new_file, "fn added() {}\n").unwrap();
        let git = |args: &[&str]| -> bool {
            std::process::Command::new("git")
                .arg("-C")
                .arg(tmp.path())
                .args(args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        assert!(git(&["add", "src/cli/added.rs"]), "git add failed");
        assert!(
            git(&["commit", "-q", "-m", "concurrent commit"]),
            "commit failed"
        );

        let err = verify_base_snapshot(tmp.path(), &snap)
            .expect_err("HEAD drift must be detected and refused");
        assert!(
            err.contains("HEAD moved"),
            "expected 'HEAD moved' in error, got: {err}"
        );
    }

    #[test]
    fn drift_check_refused_when_index_changes() {
        if !git_available() {
            eprintln!("git not on PATH — skipping index-drift test");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        init_fixture_repo(tmp.path());

        let snap = capture_base_snapshot(tmp.path()).expect("capture");

        // Stage a file (no commit) — index tree diverges from HEAD tree.
        let staged = tmp.path().join("src/cli/staged.rs");
        std::fs::write(&staged, "fn staged() {}\n").unwrap();
        let git_ok = std::process::Command::new("git")
            .arg("-C")
            .arg(tmp.path())
            .args(["add", "src/cli/staged.rs"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(git_ok, "git add for index-drift setup failed");

        let err = verify_base_snapshot(tmp.path(), &snap)
            .expect_err("index drift must be detected and refused");
        assert!(
            err.contains("staged index changed"),
            "expected 'staged index changed' in error, got: {err}"
        );
    }

    // ── Pseudo task ID ───────────────────────────────────────────────────────

    #[test]
    fn pseudo_task_id_high_bit_set() {
        let id = pseudo_task_id("abcdef01234567890000000000000000000000000000000000000000deadbeef");
        assert!(
            (id.0 as u64) & (1u64 << 63) != 0,
            "high bit must be set: {:x}",
            id.0
        );
    }

    #[test]
    fn pseudo_task_id_deterministic() {
        let hash = "aabbccdd00000000000000000000000000000000000000000000000000000000";
        assert_eq!(pseudo_task_id(hash).0, pseudo_task_id(hash).0);
    }
}
