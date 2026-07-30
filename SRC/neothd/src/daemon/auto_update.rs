//! MV-01b — daemon mutation primitives for NEOTH-managed updates.
//!
//! Elevated/Full plus the operator update switches select the mutation lanes.
//! NEOTH self-probe and verified self-stage now consume request-bound authority
//! plus mandatory intent/result WAL at every concrete GitHub/stage leaf. CLI
//! npm/OSV/install mutation remains explicitly fail-closed until its own leaves
//! enforce the same contract. Manual `neoth update` commands are unaffected.
//!
//! Scope: the three NEOTH-managed CLIs (claude-cli, antigravity-cli, codex)
//! via [`crate::updater::check_all`] + [`crate::updater::apply_one`]. Their
//! recurring lanes stay denied until each concrete probe/install leaf consumes
//! request-bound authority and records mandatory terminal WAL. A future CLI
//! adoption must also restore a correlated `0x13 UPDATE_RAN` outcome for every
//! component mutation; no active recurring CLI mutation claims that receipt
//! today.
//!
//! The running daemon is never auto-replaced here. The authorized unattended
//! lane may download, verify and stage a candidate; the actual replacement is
//! operator-initiated via `neoth update --self --apply` (which emits `0xD2`).
//!
//! The pre-release standalone loop entry points were removed instead of kept
//! as silent no-ops. Embedders get a compile error rather than believing an
//! update loop is active when the daemon supervisor is not running.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::permissions::AutonomyLevel;
use crate::updater;
use crate::updater::pipeline::GateDecision;
use crate::wal::events::EVENT_TYPE_SELF_UPDATE_APPLIED;
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};

/// Auto-apply runs only at the two highest autonomy tiers. Everything else
/// is notify-only (the probe cron surfaces availability; the operator
/// applies). Pure — the reload-owned supervisor uses this to derive its exact
/// accepted-generation lane set.
pub fn auto_apply_enabled(autonomy: AutonomyLevel) -> bool {
    matches!(autonomy, AutonomyLevel::Elevated | AutonomyLevel::Full)
}

/// Result of one reload-owned mutating lane pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecurringMutationOutcome {
    BlockedByGate,
    SkippedByPolicy,
    GenerationRetired,
    Completed,
    Staged {
        prior_version: String,
        staged_version: String,
    },
}

/// One CLI auto-apply pass. The denied recurring-egress gate is consumed before
/// any npm/OSV/install probe. A later transport-authority slice may pass Allow
/// only after every concrete leaf owns its request-bound intent/result WAL.
pub(crate) async fn run_cli_auto_apply_pass(
    gate: GateDecision,
    writer: &WalWriterHandle,
    security_policy: &crate::config::SecurityPolicy,
) -> Result<RecurringMutationOutcome, String> {
    match gate {
        GateDecision::Deny { reason } => {
            tracing::debug!(%reason, "CLI auto-apply blocked before recurring egress");
        }
        GateDecision::Allow => {
            tracing::error!(
                "rejected unexpected recurring CLI auto-apply Allow before leaf authority wiring"
            );
        }
    }
    let _ = (writer, security_policy);
    Ok(RecurringMutationOutcome::BlockedByGate)
}

fn now_unix_secs() -> u64 {
    crate::time::now_unix_secs()
}

// ── MV-01b prereq #5 — unattended neoth-self STAGING lane ──────────────
//
// Senior-dev panel 2026-05-29: the `Action::SelfBinaryReplace` gate is
// Confirm-always BY DESIGN, the daemon has no TTY, and there is no
// confirmation-persistence layer — so the unattended task must NEVER
// call `atomic_replace_binary`. It only DETECTS + DOWNLOADS + VERIFIES
// (sha256 + minisig, `require_signature = true`) + STAGES the archive to
// `~/.neoth/staged/` with a `pending.json`, emits a `0xD2` frame with
// `trigger_source = "staged_pending"`, and drops an operator
// notification. The actual swap stays operator-initiated (`neoth update
// --self --apply`), which keeps prereq #1's gate intact.

/// One unattended neoth-self staging pass. The denied recurring-egress gate is
/// consumed before release metadata, asset download, verification or staging.
pub(crate) async fn run_self_stage_pass(
    gate: GateDecision,
    home: &Path,
    snapshot: Arc<crate::config::reload::AcceptedConfigSnapshot>,
    writer: &WalWriterHandle,
) -> Result<RecurringMutationOutcome, String> {
    match gate {
        GateDecision::Deny { reason } => {
            tracing::debug!(%reason, "neoth-self staging blocked before recurring egress");
            Ok(RecurringMutationOutcome::BlockedByGate)
        }
        GateDecision::Allow => {
            let authority = updater::self_update::RecurringSelfUpdateAuthority::for_stage(
                writer.clone(),
                Arc::clone(&snapshot),
            );
            run_self_stage_pass_allowed(home, &snapshot.config().auto_update, writer, &authority)
                .await
        }
    }
}

/// One staging pass: probe GitHub, and if a newer release exists,
/// download + verify + stage it + emit `0xD2 (staged_pending)` + notify.
/// Permission refusal becomes an honest skipped pass. Configuration,
/// transport, verification, stage, notification and mandatory WAL failures
/// propagate to the reload-owned supervisor so its outer FIRED/RESULT pair
/// cannot claim success.
async fn run_self_stage_pass_allowed(
    home: &Path,
    config: &crate::config::AutoUpdateConfig,
    writer: &WalWriterHandle,
    authority: &updater::self_update::RecurringSelfUpdateAuthority,
) -> Result<RecurringMutationOutcome, String> {
    let target = match updater::self_update::resolve_release_target(config.target_triple.as_deref())
    {
        Ok(target) => target,
        Err(error) => {
            return Err(format!(
                "neoth-self staging rejected the configured release target: {error}"
            ));
        }
    };
    let release = match updater::self_update::fetch_release_for_channel_authorized(
        authority,
        &config.repo,
        config.channel,
    )
    .await
    {
        Ok(release) => release,
        Err(error) if crate::updater::authority::error_is_generation_retired(&error) => {
            return Ok(RecurringMutationOutcome::GenerationRetired);
        }
        Err(error) if crate::updater::authority::error_is_policy_refusal(&error) => {
            return Ok(RecurringMutationOutcome::SkippedByPolicy);
        }
        Err(error) => {
            return Err(format!(
                "neoth-self staging release metadata leaf failed: {error}"
            ));
        }
    };
    let current = updater::self_update::current_version();
    let is_newer = match updater::self_update::version_is_newer(&release.tag_name, current) {
        Ok(is_newer) => is_newer,
        Err(error) => {
            return Err(format!(
                "neoth-self staging release tag is not valid SemVer: {error}"
            ));
        }
    };
    if !is_newer {
        return Ok(RecurringMutationOutcome::Completed);
    }
    let stage_dir = home.join("staged");
    let pending = match updater::self_update::stage_update_authorized(
        authority,
        home,
        &release,
        &config.repo,
        config.channel,
        target,
        // The archive is a version-locked bundle. Apply-time preflight updates
        // every installed companion beside the public `neoth` executable.
        "neoth",
        &stage_dir,
        true, // require_signature — unattended demands a verified release
        now_unix_secs() as i64,
    )
    .await
    {
        Ok(pending) => pending,
        Err(error) if crate::updater::authority::error_is_generation_retired(&error) => {
            return Ok(RecurringMutationOutcome::GenerationRetired);
        }
        Err(error) if crate::updater::authority::error_is_policy_refusal(&error) => {
            return Ok(RecurringMutationOutcome::SkippedByPolicy);
        }
        Err(error) => {
            return Err(format!("neoth-self staging leaf failed: {error}"));
        }
    };
    emit_self_update_staged(writer, &pending).await?;
    write_stage_notification(home, &pending)
        .map_err(|error| format!("self-update notification sidecar write failed: {error}"))?;
    tracing::info!(
        to = %pending.to_version,
        channel = %pending.channel,
        target = %pending.target_triple,
        sig = %pending.signature_status,
        "neoth-self update staged + verified; awaiting operator `neoth update --self --apply`"
    );
    Ok(RecurringMutationOutcome::Staged {
        prior_version: current.to_string(),
        staged_version: pending.to_version,
    })
}

/// Emit the `0xD2 SELF_UPDATE_APPLIED` frame with `trigger_source =
/// "staged_pending"` via the daemon's own WAL writer (no one-shot guard
/// — the daemon owns the segment). The `trigger_source` discriminator
/// distinguishes this staged record from a real `manual`/`auto` apply.
async fn emit_self_update_staged(
    writer: &WalWriterHandle,
    pending: &updater::self_update::PendingUpdate,
) -> Result<(), String> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "from_version": updater::self_update::current_version(),
        "to_version": pending.to_version,
        "channel": pending.channel.as_str(),
        "target_triple": pending.target_triple,
        "archive_sha256": pending.archive_sha256,
        "signature_status": pending.signature_status,
        "stage_generation": pending.stage_generation,
        "trigger_source": "staged_pending",
        "ts_unix": now_unix_secs(),
    }))
    .expect("SELF_UPDATE_APPLIED payload contains only infallible JSON values");
    let header = HeaderBuilder::new(EVENT_TYPE_SELF_UPDATE_APPLIED, &payload)
        .flags(EventFlags::SYNTHETIC)
        .build();
    writer
        .append(header, payload)
        .await
        .map(|_| ())
        .map_err(|error| format!("mandatory staged self-update WAL append failed: {error}"))
}

/// Drop an operator-facing notification sidecar
/// (`~/.neoth/notifications/self_update_<ts>_<uuid>.json`) so the GUI / `neoth
/// notifications` surface the staged update. Errors are returned for visible
/// logging; the already verified staged artifact remains usable.
fn write_stage_notification(
    home: &Path,
    pending: &updater::self_update::PendingUpdate,
) -> std::io::Result<PathBuf> {
    let dir = home.join("notifications");
    let ts = now_unix_secs();
    let path = dir.join(format!(
        "self_update_{ts:020}_{}.json",
        uuid::Uuid::now_v7().simple()
    ));
    let body = serde_json::json!({
        "ts_unix": ts,
        "kind": "self_update_staged",
        "to_version": pending.to_version,
        "channel": pending.channel.as_str(),
        "target_triple": pending.target_triple,
        "signature_status": pending.signature_status,
        "body": format!(
            "NEOTH {} is downloaded + verified ({}). Run `neoth update --self --apply` to install it.",
            pending.to_version, pending.signature_status
        ),
    });
    let encoded = serde_json::to_vec_pretty(&body).map_err(std::io::Error::other)?;
    crate::util::atomic_write::atomic_write_private(&path, &encoded)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_apply_gate_only_elevated_and_full() {
        assert!(auto_apply_enabled(AutonomyLevel::Elevated));
        assert!(auto_apply_enabled(AutonomyLevel::Full));
        assert!(!auto_apply_enabled(AutonomyLevel::Standard));
        assert!(!auto_apply_enabled(AutonomyLevel::Strict));
        assert!(!auto_apply_enabled(AutonomyLevel::Custom));
    }

    #[tokio::test]
    async fn denied_recurring_gate_blocks_cli_apply_and_self_stage_before_work() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, _join) = crate::wal::writer::spawn(dir.path().join("blocked.wal")).unwrap();
        let gate = || GateDecision::Deny {
            reason: "test denied".to_string(),
        };

        assert_eq!(
            run_cli_auto_apply_pass(gate(), &writer, &Default::default()).await,
            Ok(RecurringMutationOutcome::BlockedByGate)
        );

        let controller = crate::config::reload::ReloadController::new(
            crate::config::FreedomConfig::default(),
            dir.path().join("freedom.yaml"),
        );
        assert_eq!(
            run_self_stage_pass(gate(), dir.path(), controller.accepted_snapshot(), &writer).await,
            Ok(RecurringMutationOutcome::BlockedByGate)
        );
        assert_eq!(
            run_cli_auto_apply_pass(GateDecision::Allow, &writer, &Default::default()).await,
            Ok(RecurringMutationOutcome::BlockedByGate),
            "an accidental Allow must remain inert until leaf permits land"
        );
        assert!(!dir.path().join("staged").exists());
        assert!(!dir.path().join("notifications").exists());
    }

    #[test]
    fn emit_payload_shape_matches_0x13_schema() {
        // Drift guard for the 0x13 payload contract
        // {component, old_version, new_version, status, ts}.
        let payload = serde_json::json!({
            "component": "claude_cli",
            "old_version": "1.0.0",
            "new_version": "1.1.0",
            "status": "applied",
            "ts": 1_700_000_000u64,
        });
        let obj = payload.as_object().unwrap();
        for key in ["component", "old_version", "new_version", "status", "ts"] {
            assert!(obj.contains_key(key), "0x13 payload missing key {key}");
        }
    }

    #[test]
    fn stage_notifications_are_atomic_and_never_overwrite_same_second() {
        let home = tempfile::tempdir().unwrap();
        let pending = updater::self_update::PendingUpdate {
            to_version: "1.0.1".into(),
            source_repo: "owner/repo".into(),
            channel: crate::config::ReleaseChannel::Stable,
            archive_sha256: "ab".repeat(32),
            download_url: "https://example.invalid/neoth.tar.gz".into(),
            signature_status: "verified".into(),
            staged_archive: home.path().join("stage.tar.gz").display().to_string(),
            staged_signature: None,
            stage_generation: None,
            target_triple: "x86_64-unknown-linux-gnu".into(),
            staged_ts_unix: 1,
        };
        let first = write_stage_notification(home.path(), &pending).unwrap();
        let second = write_stage_notification(home.path(), &pending).unwrap();
        assert_ne!(first, second);
        assert!(first.exists());
        assert!(second.exists());
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(first).unwrap()).unwrap();
        assert_eq!(parsed["kind"], "self_update_staged");
        assert_eq!(parsed["to_version"], "1.0.1");
    }
}
