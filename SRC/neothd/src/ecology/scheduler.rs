//! F4-01 Phase 1 — Ecology auto-scheduler cron.
//!
//! The Ecology layer (CH-13) decides **WHEN** NEOTH adapts itself; P-04 decides
//! **WHAT** to propose. This module is the WHEN: a 6h cron that scans the WAL
//! for a low-dissent council regime — one provider winning a sustained streak,
//! via [`crate::ecology::correlation_detector`] — and, when it detects one,
//! runs the P-04 self-dev proposal generator and STAGES the resulting proposals
//! for `neoth self-dev review`.
//!
//! ## P2 HARD CONSTRAINT (DESIGN_CH13)
//!
//! The Ecology fitness layer must NEVER silently rewrite policy
//! ("Council-Fitness darf nicht heimlich Council-Policy umschreiben"). This
//! scheduler therefore only ever PROPOSES: it calls the same
//! [`crate::cli::self_dev::propose_and_store`] staging path the passive
//! profile-adapt cron uses (status `Pending`, operator-reviewable via
//! `neoth self-dev review` / `accept <id>` / `decline <id>`, idempotent by
//! stable proposal id), and every fire emits a `0x4C ECOLOGY_SCHEDULER_FIRED`
//! audit frame. Nothing is auto-applied. Both halves of the constraint hold:
//! **review-gated** (proposals await an explicit `neoth self-dev accept`) AND
//! **WAL-audited** (the 0x4C frame records every fire).
//!
//! ## Design (mirrors [`crate::daemon::profile_adapt_cron`])
//!
//! A pure-ish [`run_ecology_tick_once`] (testable against a tempdir + in-memory
//! WAL) + a [`spawn_ecology_cron_loop`] that returns `None` when
//! `ecology.enabled == false` (the default) so opt-out operators carry no idle
//! tokio task. The correlation scan that GATES the tick is read-only and
//! LLM-free — the whole Ecology layer is deterministic.

use std::path::{Path, PathBuf};

use crate::config::EcologyConfig;
use crate::ecology::correlation_detector::{detect_winner_streaks, scan_winner_records};
use crate::wal::writer::WalWriterHandle;

/// Preset the scheduler computes adaptation proposals against. Matches the
/// `neoth self-dev propose` CLI default + the profile-adapt cron basis — there
/// is no persisted behavioural `ProfilePreset` in `freedom.yaml` today, so the
/// recommended `Lowkey` default is the basis. See
/// [`crate::daemon::profile_adapt_cron`] for the full rationale.
const SCHEDULER_BASIS_PRESET: &str = "lowkey";

/// One Ecology auto-scheduler pass:
///   1. Scan the WAL for outer-council winner records + detect same-provider
///      streaks ≥ `min_streak` (the low-dissent fitness signal). Read-only.
///   2. If NO streak signal fired → idle tick: return `Ok(false)`, emit nothing
///      (keeps `ECOLOGY_SCHEDULER_FIRED` meaning "the scheduler acted").
///   3. Otherwise re-aggregate the behavioural snapshot + run the P-04 self-dev
///      proposal generator via the shared [`crate::cli::self_dev::propose_and_store`]
///      STAGING path (review-gated — proposals are `Pending`, never applied).
///   4. Emit `0x4C ECOLOGY_SCHEDULER_FIRED` with
///      `{streak_signals_count, proposals_queued, ts_unix}` — the P2 audit
///      trail.
///
/// Returns `Ok(true)` when ≥1 NEW proposal was queued this tick. Errors are
/// `String` so the loop can log + continue (one bad tick never kills the cron).
pub async fn run_ecology_tick_once(
    home: &Path,
    wal_dir: &Path,
    writer: &WalWriterHandle,
    min_streak: usize,
    now_unix: i64,
) -> Result<bool, String> {
    // ── 1+2: read-only fitness scan (the WHEN gate) ────────────────────────
    let records = scan_winner_records(wal_dir);
    let signals = detect_winner_streaks(&records, min_streak);
    if signals.is_empty() {
        // No low-dissent regime → the scheduler does NOT act. No proposals, no
        // audit frame (an idle tick is not a "fire").
        return Ok(false);
    }
    let streak_signals_count = signals.len();

    // ── 3: STAGE proposals (the WHAT, via the review-gated P-04 path) ──────
    // Best-effort snapshot refresh; a fresh install with no behavioural data
    // still counts as a fire (signal detected) but queues 0 proposals.
    let proposals_queued = match stage_self_dev_proposals(home, wal_dir, writer).await {
        Ok(n) => n,
        Err(e) => {
            // Record the fire with 0 proposals + surface the error to the loop.
            // Emitting first preserves the audit trail even on a staging error.
            emit_scheduler_fired(writer, streak_signals_count, 0, now_unix).await?;
            return Err(e);
        }
    };

    // ── 4: P2 audit frame — proves the scheduler only PROPOSED ─────────────
    emit_scheduler_fired(writer, streak_signals_count, proposals_queued, now_unix).await?;
    Ok(proposals_queued > 0)
}

/// Re-aggregate the behavioural snapshot + queue any NEW self-dev proposals via
/// the shared staging path. Returns the count newly queued (0 on a fresh
/// install with no snapshot, or when the operator already matches the basis
/// preset within thresholds). Never auto-applies.
async fn stage_self_dev_proposals(
    home: &Path,
    wal_dir: &Path,
    writer: &WalWriterHandle,
) -> Result<usize, String> {
    crate::cron::runner::aggregate_profile_snapshot(home, wal_dir)
        .await
        .map_err(|e| format!("aggregate snapshot: {e}"))?;
    let Some(profile) = crate::profile::snapshot::load_snapshot(home) else {
        return Ok(0);
    };
    crate::cli::self_dev::propose_and_store(home, &profile, SCHEDULER_BASIS_PRESET, Some(writer))
        .await
        .map_err(|e| format!("propose + store: {e}"))
}

/// Emit the `0x4C ECOLOGY_SCHEDULER_FIRED` audit frame. Batchable (synthetic) —
/// the WAL chain still seals it, but it does not force an fsync.
async fn emit_scheduler_fired(
    writer: &WalWriterHandle,
    streak_signals_count: usize,
    proposals_queued: usize,
    now_unix: i64,
) -> Result<(), String> {
    let payload = serde_json::to_vec(&serde_json::json!({
        "streak_signals_count": streak_signals_count,
        "proposals_queued": proposals_queued,
        "ts_unix": now_unix,
    }))
    .map_err(|e| format!("serialize ecology-scheduler payload: {e}"))?;
    let header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_ECOLOGY_SCHEDULER_FIRED,
        &payload,
    )
    .flags(crate::wal::EventFlags::SYNTHETIC)
    .build();
    writer
        .append(header, payload)
        .await
        .map(|_seq| ())
        .map_err(|e| format!("wal append: {e}"))
}

/// Spawn the Ecology auto-scheduler cron loop. Returns the `JoinHandle` so the
/// daemon tracks it; `None` when `config.enabled == false` (the default) so
/// opt-out operators carry no idle tokio task. Interval comes from
/// `config.scheduler_interval_secs`, clamped to a 60s floor.
pub fn spawn_ecology_cron_loop(
    home: PathBuf,
    wal_dir: PathBuf,
    config: EcologyConfig,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("ecology scheduler disabled in config (ecology.enabled = false)");
        return None;
    }
    let interval = config.scheduler_interval_duration();
    let min_streak = config.correlation_min_streak;
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            min_streak,
            "ecology scheduler cron loop online (F4-01 — proposals are review-gated)",
        );
        loop {
            ticker.tick().await;
            let now_unix = crate::time::now_unix_i64();
            match run_ecology_tick_once(&home, &wal_dir, &writer, min_streak, now_unix).await {
                Ok(true) => tracing::info!(
                    "ecology scheduler: low-dissent regime → queued new self-dev proposal(s) — \
                     review via `neoth self-dev review`",
                ),
                Ok(false) => {
                    tracing::debug!(
                        "ecology scheduler: no fire (no streak signal / no new proposals)"
                    )
                }
                Err(e) => tracing::error!(error = %e, "ecology scheduler tick failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::events::EVENT_TYPE_COUNCIL_WINNER_SELECTED;

    fn enabled_config() -> EcologyConfig {
        EcologyConfig {
            enabled: true,
            correlation_min_streak: 3,
            scheduler_interval_secs: crate::config::DEFAULT_ECOLOGY_SCHEDULER_INTERVAL_SECS,
        }
    }

    /// Count frames of `event_type` in a single sealed WAL segment — mirrors
    /// `recall_latency_cron::tests::count_alert_frames`. Used to assert the
    /// `0x4C` audit frame actually hit disk.
    fn count_frames(seg: &std::path::Path, event_type: u8) -> usize {
        let Ok(bytes) = std::fs::read(seg) else {
            return 0;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            return 0;
        };
        let mut cursor = hdr.header_len();
        let mut count = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == event_type {
                count += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        count
    }

    /// Seed `n` consecutive outer-council winner frames for `provider` into the
    /// open WAL writer so the correlation scan sees a streak.
    async fn seed_winner_streak(writer: &WalWriterHandle, provider: &str, n: usize) {
        for i in 0..n {
            let payload = serde_json::to_vec(&serde_json::json!({
                "provider": provider,
                "role": "left",
                "score": 0.9,
                "depth": 0,
                "ts_unix": 1_000 + i as i64,
            }))
            .unwrap();
            let header =
                crate::wal::HeaderBuilder::new(EVENT_TYPE_COUNCIL_WINNER_SELECTED, &payload)
                    .build();
            writer.append(header, payload).await.unwrap();
        }
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("ec.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = EcologyConfig {
            enabled: false,
            ..enabled_config()
        };
        let handle = spawn_ecology_cron_loop(
            home.path().to_path_buf(),
            wal_dir.path().to_path_buf(),
            cfg,
            writer,
        );
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn spawn_returns_some_when_enabled() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("ec.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let handle = spawn_ecology_cron_loop(
            home.path().to_path_buf(),
            wal_dir.path().to_path_buf(),
            enabled_config(),
            writer,
        )
        .expect("expected join handle when enabled");
        handle.abort();
    }

    #[tokio::test]
    async fn tick_no_wal_returns_ok_false() {
        // Fresh install: empty WAL dir → no winner records → no streak signal →
        // the scheduler does not fire.
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("ec-000001.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let fired = run_ecology_tick_once(home.path(), wal_dir.path(), &writer, 3, 5_000)
            .await
            .expect("tick on empty wal must not error");
        assert!(!fired, "empty WAL → no signal → no fire");
    }

    #[tokio::test]
    async fn tick_below_streak_threshold_does_not_fire() {
        // 2 consecutive wins but threshold is 3 → no signal → no fire, no
        // proposals, no audit frame.
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("ec-000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        seed_winner_streak(&writer, "claude_cli", 2).await;
        let fired = run_ecology_tick_once(home.path(), wal_dir.path(), &writer, 3, 5_000)
            .await
            .expect("tick must not error");
        assert!(!fired, "streak of 2 below threshold 3 → no fire");
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn tick_above_threshold_fires_and_emits_audit_frame() {
        // 4 consecutive wins ≥ threshold 3 → the scheduler fires + emits the
        // 0x4C audit frame even though a fresh install has no behavioural
        // snapshot (0 proposals queued). The FIRE + AUDIT are the P2 guarantee;
        // the 0-proposal outcome is fine.
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("ec-000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        seed_winner_streak(&writer, "claude_cli", 4).await;
        let fired = run_ecology_tick_once(home.path(), wal_dir.path(), &writer, 3, 7_000)
            .await
            .expect("tick must not error");
        // No behavioural snapshot on a fresh install → 0 proposals → Ok(false),
        // but the audit frame WAS emitted (proven below).
        assert!(!fired, "no behavioural snapshot → 0 proposals → Ok(false)");
        drop(writer);
        let _ = join.await;

        // The 0x4C ECOLOGY_SCHEDULER_FIRED frame must be on disk — the P2
        // audit trail proving the scheduler ran (and only proposed).
        let fired_frames =
            count_frames(&seg, crate::wal::events::EVENT_TYPE_ECOLOGY_SCHEDULER_FIRED);
        assert_eq!(
            fired_frames, 1,
            "a streak ≥ threshold must emit exactly one 0x4C ECOLOGY_SCHEDULER_FIRED audit frame",
        );
    }

    #[test]
    fn config_serde_default_disabled() {
        let cfg = EcologyConfig::default();
        assert!(!cfg.enabled, "F4-01 scheduler must be opt-in (default OFF)");
        assert_eq!(
            cfg.scheduler_interval_secs,
            crate::config::DEFAULT_ECOLOGY_SCHEDULER_INTERVAL_SECS,
        );
        assert_eq!(cfg.scheduler_interval_duration().as_secs(), 6 * 3600);
    }

    #[test]
    fn scheduler_interval_clamped_to_60s_floor() {
        let cfg = EcologyConfig {
            scheduler_interval_secs: 0,
            ..EcologyConfig::default()
        };
        assert_eq!(
            cfg.scheduler_interval_duration().as_secs(),
            60,
            "a misconfigured 0 must clamp to the 60s floor (no hot-spin)",
        );
    }
}
