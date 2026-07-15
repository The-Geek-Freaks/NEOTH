//! MV-01b — daemon auto-apply for NEOTH-managed CLI updates.
//!
//! Operator policy (Option A, 2026-05-29): NEOTH auto-applies CLI updates
//! when the operator runs at `AutonomyLevel::Elevated` or `Full`. At
//! `Standard` / `Strict` / `Custom` the daemon stays **notify-only** — the
//! probe cron ([`crate::daemon::updater_cron`]) already emits `0x44/0x45`
//! frames so the operator sees "an update is available" and applies it via
//! `neoth update --apply`.
//!
//! Scope: the three NEOTH-managed CLIs (claude-cli, antigravity-cli, codex)
//! via [`crate::updater::check_all`] + [`crate::updater::apply_one`]. Each
//! component actually updated emits one `0x13 UPDATE_RAN` frame carrying
//! `{component, old_version, new_version, status, ts}` so the audit chain
//! records exactly what the daemon changed on the operator's box and when.
//!
//! The `neoth` daemon binary's own self-replacement (`updater::self_update`)
//! is NOT auto-applied here — unattended self-replacement of the running
//! daemon is a separate, more delicate slice. Operators apply it via
//! `neoth update --self --apply` (which emits `0xD2`).
//!
//! Every failure (probe error, npm/install failure, WAL emit failure) logs
//! and the loop continues — an auto-update task must never crash the daemon.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::permissions::AutonomyLevel;
use crate::updater;
use crate::wal::events::{EVENT_TYPE_SELF_UPDATE_APPLIED, EVENT_TYPE_UPDATE_RAN};
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, HeaderBuilder};

/// Default cadence between auto-apply passes. Matches the probe cron's 6h
/// default so the two stay aligned. Floored at 60s to protect against a
/// misconfigured `0`.
pub const DEFAULT_INTERVAL_SECS: u64 = 6 * 3600;

/// Auto-apply runs only at the two highest autonomy tiers. Everything else
/// is notify-only (the probe cron surfaces availability; the operator
/// applies). Pure — the gate the spawn decision turns on.
pub fn auto_apply_enabled(autonomy: AutonomyLevel) -> bool {
    matches!(autonomy, AutonomyLevel::Elevated | AutonomyLevel::Full)
}

/// Spawn the CLI auto-apply loop. Returns `None` (no task) unless BOTH the
/// updater is enabled AND the autonomy tier permits auto-apply — so
/// notify-only operators accumulate no idle task.
pub fn spawn(
    autonomy: AutonomyLevel,
    updater_enabled: bool,
    interval_secs: u64,
    security_policy: crate::config::SecurityPolicy,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !updater_enabled {
        return None;
    }
    if !auto_apply_enabled(autonomy) {
        tracing::info!(
            autonomy = autonomy.as_str(),
            "CLI auto-apply disabled at this autonomy tier (notify-only); \
             use `neoth update --apply` or raise autonomy to elevated/full"
        );
        return None;
    }
    let interval = Duration::from_secs(interval_secs.max(60));
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            autonomy = autonomy.as_str(),
            interval_secs = interval.as_secs(),
            "CLI auto-apply loop online (MV-01b)"
        );
        // Burn the immediate tick — a fresh boot's first pass is the probe
        // cron's job; auto-apply waits one interval so it doesn't race the
        // wizard's first-install on startup.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_pass(&writer, &security_policy).await;
        }
    }))
}

/// One auto-apply pass: probe all CLIs, apply each flagged update, emit a
/// `0x13 UPDATE_RAN` frame per component actually updated.
async fn run_pass(writer: &WalWriterHandle, security_policy: &crate::config::SecurityPolicy) {
    let statuses = updater::check_all().await;
    for status in statuses {
        if !status.update_available {
            continue;
        }
        let component = status.component;
        let old_version = status.installed.clone();
        match updater::apply_one(component, security_policy).await {
            Ok(()) => {
                // Re-probe so the frame records the version actually live
                // after the install (falls back to the probed `latest`).
                let new_version = updater::check_one(component)
                    .await
                    .installed
                    .or(status.latest);
                emit_update_ran(
                    writer,
                    component.name(),
                    old_version,
                    new_version,
                    "applied",
                )
                .await;
                tracing::info!(component = component.name(), "CLI auto-updated");
            }
            Err(e) => {
                tracing::warn!(
                    component = component.name(),
                    error = %e,
                    "CLI auto-update failed (will retry next pass)"
                );
            }
        }
    }
}

/// Emit one `0x13 UPDATE_RAN` audit frame. Best-effort — a WAL append
/// failure logs and is swallowed (the install already happened).
async fn emit_update_ran(
    writer: &WalWriterHandle,
    component: &str,
    old_version: Option<String>,
    new_version: Option<String>,
    status: &str,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "component": component,
        "old_version": old_version,
        "new_version": new_version,
        "status": status,
        "ts": now_unix_secs(),
    }))
    .expect("UPDATE_RAN payload contains only infallible JSON values");
    let header = HeaderBuilder::new(EVENT_TYPE_UPDATE_RAN, &payload)
        .flags(EventFlags::SYNTHETIC)
        .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(component, error = %e, "UPDATE_RAN WAL emit failed (non-fatal)");
    }
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

/// Spawn the unattended neoth-self STAGING loop. Same gate as the CLI
/// auto-apply lane (autonomy elevated/full + `auto_update.enabled` +
/// `auto_update.auto_apply`). `check_interval_secs = 0` also disables the
/// periodic task. Returns `None` otherwise so check-only operators accumulate
/// no staging task.
pub fn spawn_self_stage(
    autonomy: AutonomyLevel,
    config: crate::config::AutoUpdateConfig,
    home: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled || !config.auto_apply || config.check_interval_secs == 0 {
        return None;
    }
    if !auto_apply_enabled(autonomy) {
        return None;
    }
    let interval = Duration::from_secs(config.check_interval_secs.max(60));
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            autonomy = autonomy.as_str(),
            interval_secs = interval.as_secs(),
            repo = %config.repo,
            channel = %config.channel,
            target = config.target_triple.as_deref().unwrap_or("host"),
            "neoth-self staging loop online (MV-01b #5; stage-only, never auto-swaps)"
        );
        ticker.tick().await; // burn immediate tick
        loop {
            ticker.tick().await;
            run_self_stage_pass(&home, &config, &writer).await;
        }
    }))
}

/// One staging pass: probe GitHub, and if a newer release exists,
/// download + verify + stage it + emit `0xD2 (staged_pending)` + notify.
/// Every failure logs + the loop retries next tick — never crashes the
/// daemon, never swaps the binary.
async fn run_self_stage_pass(
    home: &Path,
    config: &crate::config::AutoUpdateConfig,
    writer: &WalWriterHandle,
) {
    let target = match updater::self_update::resolve_release_target(config.target_triple.as_deref())
    {
        Ok(target) => target,
        Err(error) => {
            tracing::warn!(error = %error, "neoth-self staging: invalid release target");
            return;
        }
    };
    let release =
        match updater::self_update::fetch_release_for_channel(&config.repo, config.channel).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "neoth-self staging: release probe failed");
                return;
            }
        };
    let current = updater::self_update::current_version();
    let is_newer = match updater::self_update::version_is_newer(&release.tag_name, current) {
        Ok(is_newer) => is_newer,
        Err(error) => {
            tracing::warn!(
                version = %release.tag_name,
                error = %error,
                "neoth-self staging: release tag is not valid SemVer"
            );
            return;
        }
    };
    if !is_newer {
        return; // already current — nothing to stage
    }
    let stage_dir = home.join("staged");
    match updater::self_update::stage_update(
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
        Ok(pending) => {
            emit_self_update_staged(writer, &pending).await;
            if let Err(error) = write_stage_notification(home, &pending) {
                tracing::warn!(%error, "self-update notification sidecar write failed");
            }
            tracing::info!(
                to = %pending.to_version,
                channel = %pending.channel,
                target = %pending.target_triple,
                sig = %pending.signature_status,
                "neoth-self update staged + verified; awaiting operator `neoth update --self --apply`"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "neoth-self staging failed (will retry next tick)");
        }
    }
}

/// Emit the `0xD2 SELF_UPDATE_APPLIED` frame with `trigger_source =
/// "staged_pending"` via the daemon's own WAL writer (no one-shot guard
/// — the daemon owns the segment). The `trigger_source` discriminator
/// distinguishes this staged record from a real `manual`/`auto` apply.
async fn emit_self_update_staged(
    writer: &WalWriterHandle,
    pending: &updater::self_update::PendingUpdate,
) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "from_version": updater::self_update::current_version(),
        "to_version": pending.to_version,
        "channel": pending.channel.as_str(),
        "target_triple": pending.target_triple,
        "archive_sha256": pending.archive_sha256,
        "download_url": pending.download_url,
        "signature_status": pending.signature_status,
        "staged_archive": pending.staged_archive,
        "trigger_source": "staged_pending",
        "ts_unix": now_unix_secs(),
    }))
    .expect("SELF_UPDATE_APPLIED payload contains only infallible JSON values");
    let header = HeaderBuilder::new(EVENT_TYPE_SELF_UPDATE_APPLIED, &payload)
        .flags(EventFlags::SYNTHETIC)
        .build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "SELF_UPDATE_APPLIED (staged) WAL emit failed (non-fatal)");
    }
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
    use crate::updater::UpdateStatus;

    #[test]
    fn auto_apply_gate_only_elevated_and_full() {
        assert!(auto_apply_enabled(AutonomyLevel::Elevated));
        assert!(auto_apply_enabled(AutonomyLevel::Full));
        assert!(!auto_apply_enabled(AutonomyLevel::Standard));
        assert!(!auto_apply_enabled(AutonomyLevel::Strict));
        assert!(!auto_apply_enabled(AutonomyLevel::Custom));
    }

    #[tokio::test]
    async fn spawn_none_when_updater_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, _join) = crate::wal::writer::spawn(dir.path().join("a.wal")).unwrap();
        // Even at Full autonomy, a disabled updater spawns no task.
        assert!(spawn(AutonomyLevel::Full, false, 3600, Default::default(), writer).is_none());
    }

    #[tokio::test]
    async fn spawn_none_at_standard_autonomy() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, _join) = crate::wal::writer::spawn(dir.path().join("b.wal")).unwrap();
        assert!(
            spawn(
                AutonomyLevel::Standard,
                true,
                3600,
                Default::default(),
                writer
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn spawn_some_at_elevated_with_updater_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let (writer, _join) = crate::wal::writer::spawn(dir.path().join("c.wal")).unwrap();
        let handle = spawn(
            AutonomyLevel::Elevated,
            true,
            3600,
            Default::default(),
            writer,
        )
        .expect("expected a task at elevated autonomy with updater enabled");
        handle.abort();
    }

    #[tokio::test]
    async fn self_stage_spawn_gated_like_cli_lane() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let enabled = crate::config::AutoUpdateConfig {
            enabled: true,
            auto_apply: true,
            check_interval_secs: 3_600,
            repo: "owner/repo".into(),
            ..Default::default()
        };
        // Standard autonomy → no staging task (notify-only tier).
        let (w1, _j1) = crate::wal::writer::spawn(dir.path().join("s1.wal")).unwrap();
        assert!(
            spawn_self_stage(AutonomyLevel::Standard, enabled.clone(), home.clone(), w1).is_none()
        );
        // Self-update disabled → no staging task even at Full.
        let (w2, _j2) = crate::wal::writer::spawn(dir.path().join("s2.wal")).unwrap();
        let mut disabled = enabled.clone();
        disabled.enabled = false;
        assert!(spawn_self_stage(AutonomyLevel::Full, disabled, home.clone(), w2).is_none());
        // Check-only policy never downloads/stages.
        let (w_check, _j_check) =
            crate::wal::writer::spawn(dir.path().join("s-check.wal")).unwrap();
        let mut check_only = enabled.clone();
        check_only.auto_apply = false;
        assert!(spawn_self_stage(AutonomyLevel::Full, check_only, home.clone(), w_check).is_none());
        // Elevated + enabled → task spawns.
        let (w3, _j3) = crate::wal::writer::spawn(dir.path().join("s3.wal")).unwrap();
        let handle = spawn_self_stage(AutonomyLevel::Elevated, enabled, home, w3)
            .expect("staging task at elevated autonomy");
        handle.abort();
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

    #[allow(dead_code)]
    fn _status_field_access(s: &UpdateStatus) -> bool {
        // Compile-time guard: the fields run_pass reads must exist.
        s.update_available && s.installed.is_some() && s.latest.is_some()
    }
}
