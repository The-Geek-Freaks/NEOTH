//! SPEC-05 — passive user-adaptation daemon cron.
//!
//! The 5 passive estimators (`profile::estimators`), the snapshot
//! aggregator (`cron::runner::aggregate_profile_snapshot`), the
//! proposal generator (`profile::self_dev::propose_adjustments`), the
//! proposal store + `0x1C SELF_DEV_PROPOSED` WAL emit
//! (`cli::self_dev::propose_and_store`), and the `neoth self-dev
//! review/accept/decline` CLI all shipped previously. This module is the
//! missing wiring: the daemon cron that, every `interval_secs`,
//! re-aggregates the behavioural snapshot from the WAL and queues any new
//! adaptation proposals for operator review.
//!
//! ## Design (mirrors [`super::drift_alert_cron`])
//!
//! A pure-ish [`run_profile_adapt_tick`] (testable against a tempdir) +
//! a [`spawn_profile_adapt_cron_loop`] that returns `None` when
//! `profile_adapt.enabled == false` — the default — so opt-out operators
//! carry no idle tokio task.
//!
//! Nothing is auto-APPLIED: the cron only generates PROPOSALS (status
//! `Pending`), which the operator reviews via `neoth self-dev review` and
//! accepts/declines explicitly. The proposal ids are stable, so re-running
//! the tick is idempotent (`propose_and_store` dedups against the store) —
//! the operator never sees the same suggestion twice unless they decline
//! it and the underlying pattern re-emerges.
//!
//! Preset basis: the cron computes proposals *against* the operator's
//! chosen behavioural `ProfilePreset` — read LIVE each tick from the single
//! canonical active-preset marker (`cli::profile::load_active_preset`, set
//! by `neoth profile preset set` / the GUI selector). A drift away from THAT
//! preset is what queues a proposal, so an operator who picks `Formal` gets
//! adaptation toward Formal, not the hardcoded `Lowkey`. Falls back to
//! `Lowkey` — the documented recommended baseline, matching the
//! `neoth self-dev propose` CLI default — when no preset has been chosen.
//! (This behavioural preset is orthogonal to the `neoth preset`
//! provider-bundle store.)

use std::path::PathBuf;

use crate::config::ProfileAdaptConfig;
use crate::profile::presets::ProfilePreset;
use crate::wal::writer::WalWriterHandle;

/// G-03: window the feedback consumer aggregates over each tick. 7 days — long
/// enough that a sustained-pushback episode (not a one-off bad turn) drives a
/// proposal, short enough that resolved pushback stops re-surfacing.
const FEEDBACK_WINDOW_SECS: i64 = 7 * 24 * 3600;

/// One passive-adaptation cron pass:
///   1. Re-aggregate the behavioural snapshot from the WAL window
///      (`aggregate_profile_snapshot` persists it under `home`).
///   2. Load the persisted snapshot.
///   3. Run `propose_adjustments` + queue any NEW proposals (emitting
///      `0x1C SELF_DEV_PROPOSED` per new one via the daemon `writer`).
///
/// Returns the number of NEW proposals queued this tick (`0` when the
/// snapshot is empty/fresh or the operator already matches the basis
/// preset within thresholds). Errors are returned as `String` so the loop
/// can log + continue (one bad tick never kills the cron).
pub async fn run_profile_adapt_tick(
    home: &std::path::Path,
    wal_dir: &std::path::Path,
    writer: &WalWriterHandle,
    basis_preset: ProfilePreset,
) -> Result<usize, String> {
    crate::cron::runner::aggregate_profile_snapshot(home, wal_dir)
        .await
        .map_err(|e| format!("aggregate snapshot: {e}"))?;

    // G-03 consumer: aggregate recent OPERATOR_FEEDBACK (0xBB) and, on
    // SUSTAINED pushback, queue ONE operator-reviewable self-dev proposal. This
    // runs even when there is no behavioural snapshot yet — feedback is its own
    // signal. Best-effort: a feedback-path error never blocks the snapshot path.
    let feedback_added = run_feedback_consumer(home, wal_dir, writer).await;

    let Some(profile) = crate::profile::snapshot::load_snapshot(home) else {
        // Fresh install / empty WAL → no behavioural snapshot to adapt from,
        // but a feedback proposal may still have been queued above.
        return Ok(feedback_added);
    };

    let snapshot_added = crate::cli::self_dev::propose_and_store(
        home,
        &profile,
        basis_preset.as_str(),
        Some(writer),
    )
    .await
    .map_err(|e| format!("propose + store: {e}"))?;
    Ok(feedback_added + snapshot_added)
}

/// G-03 consumer half: read the recent feedback window + queue a sustained
/// -pushback proposal. Returns the number of NEW proposals queued (0 below
/// `High` pressure or when already queued). Errors are swallowed to a debug log
/// — the feedback path must never break the snapshot adaptation path.
async fn run_feedback_consumer(
    home: &std::path::Path,
    wal_dir: &std::path::Path,
    writer: &WalWriterHandle,
) -> usize {
    let now = crate::time::now_unix_i64();
    let summary =
        crate::feedback::consume::aggregate_recent_feedback(wal_dir, FEEDBACK_WINDOW_SECS, now);
    let Some(proposal) = crate::feedback::consume::propose_from_feedback(&summary) else {
        return 0;
    };
    match crate::cli::self_dev::store_proposals(home, std::slice::from_ref(&proposal), Some(writer))
        .await
    {
        Ok(n) => {
            if n > 0 {
                tracing::info!(
                    corrections = summary.corrections,
                    "profile-adapt cron: queued a sustained-pushback self-dev proposal (G-03)"
                );
            }
            n
        }
        Err(e) => {
            tracing::debug!(error = %e, "profile-adapt cron: feedback proposal store failed");
            0
        }
    }
}

/// The behavioural preset the next tick computes proposals *against* — the
/// operator's live choice from the single canonical active-preset marker
/// (`neoth profile preset set` / GUI selector), or [`ProfilePreset::Lowkey`]
/// (the recommended baseline) when none has been chosen.
fn current_basis(home: &std::path::Path) -> ProfilePreset {
    crate::cli::profile::load_active_preset(home).unwrap_or(ProfilePreset::Lowkey)
}

/// Spawn the passive-adaptation cron loop. Returns the `JoinHandle` so the
/// daemon tracks it alongside the other background tasks; `None` when
/// `config.enabled == false` (the default) so opt-out operators carry no
/// idle tokio task. Interval comes from `config.interval_secs`, clamped to
/// a 60s floor by `ProfileAdaptConfig::interval_duration`.
pub fn spawn_profile_adapt_cron_loop(
    config: ProfileAdaptConfig,
    home: PathBuf,
    wal_dir: PathBuf,
    writer: WalWriterHandle,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!("profile-adapt cron disabled in config (profile_adapt.enabled = false)");
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            "profile-adapt cron loop online (SPEC-05)",
        );
        loop {
            ticker.tick().await;
            // Read the operator's CURRENT behavioural preset each tick (single
            // source of truth: the active-preset marker), so a mid-run
            // `neoth profile preset set` is honoured on the next daily tick.
            match run_profile_adapt_tick(&home, &wal_dir, &writer, current_basis(&home)).await {
                Ok(0) => tracing::debug!("profile-adapt cron: no new proposals this tick"),
                Ok(n) => tracing::info!(
                    new_proposals = n,
                    "profile-adapt cron: queued new self-dev proposal(s) — review via \
                     `neoth self-dev review`",
                ),
                Err(e) => tracing::error!(error = %e, "profile-adapt tick failed"),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> ProfileAdaptConfig {
        ProfileAdaptConfig {
            enabled: true,
            ..ProfileAdaptConfig::default()
        }
    }

    #[tokio::test]
    async fn spawn_returns_none_when_disabled() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("pa.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let cfg = ProfileAdaptConfig {
            enabled: false,
            ..ProfileAdaptConfig::default()
        };
        let handle = spawn_profile_adapt_cron_loop(
            cfg,
            home.path().to_path_buf(),
            wal_dir.path().to_path_buf(),
            writer,
        );
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn spawn_returns_some_when_enabled() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("pa.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let handle = spawn_profile_adapt_cron_loop(
            enabled_config(),
            home.path().to_path_buf(),
            wal_dir.path().to_path_buf(),
            writer,
        )
        .expect("expected join handle when enabled");
        handle.abort(); // immediate cancel; ticker has not fired
    }

    #[tokio::test]
    async fn tick_on_empty_wal_runs_clean_and_proposes_nothing() {
        // No behavioural data in the (empty) WAL dir → aggregate persists
        // an empty snapshot → the tick completes without error and queues
        // no proposals. Proves the aggregate→snapshot→propose wiring holds
        // end-to-end on a fresh install.
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("pa.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg).unwrap();
        let n = run_profile_adapt_tick(home.path(), wal_dir.path(), &writer, ProfilePreset::Lowkey)
            .await
            .expect("tick on empty wal must not error");
        assert_eq!(n, 0, "empty WAL → no behavioural data → no proposals");
    }

    #[tokio::test]
    async fn sustained_pushback_queues_a_feedback_proposal() {
        // G-03 consumer end-to-end: writing >= HIGH_AT operator-feedback (0xBB)
        // frames into the WAL ⇒ the tick's feedback consumer queues ONE
        // operator-reviewable self-dev proposal (deduped on re-run).
        let home = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("fb-000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg).unwrap();
        let now = crate::time::now_unix_i64();
        for i in 0..(crate::feedback::consume::HIGH_AT + 1) {
            let payload = serde_json::to_vec(&serde_json::json!({
                "sentiment_score": -0.8,
                "matched_patterns": ["wrong_answer"],
                "prompt_hash": i,
                "ts_unix": now - 10,
            }))
            .unwrap();
            let header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_OPERATOR_FEEDBACK,
                &payload,
            )
            .build();
            writer.append(header, payload).await.unwrap();
        }

        // First tick queues the feedback proposal.
        let n1 =
            run_profile_adapt_tick(home.path(), wal_dir.path(), &writer, ProfilePreset::Lowkey)
                .await
                .expect("tick must not error");
        assert!(
            n1 >= 1,
            "high pushback must queue a self-dev proposal, got {n1}"
        );

        // Second tick is idempotent — the proposal is deduped by stable id.
        let n2 =
            run_profile_adapt_tick(home.path(), wal_dir.path(), &writer, ProfilePreset::Lowkey)
                .await
                .expect("tick must not error");
        assert_eq!(
            n2, 0,
            "the feedback proposal must not re-queue on the next tick"
        );

        drop(writer);
        let _ = join.await;
    }

    #[test]
    fn default_interval_is_24h() {
        assert_eq!(ProfileAdaptConfig::default().interval_secs, 24 * 3600);
        assert_eq!(
            crate::config::DEFAULT_PROFILE_ADAPT_INTERVAL_SECS,
            24 * 3600
        );
    }

    #[test]
    fn current_basis_defaults_lowkey_then_follows_operator_choice() {
        // The cron basis is the operator's live active-preset choice. Unset →
        // Lowkey (recommended baseline). After `neoth profile preset set formal`
        // the very next tick computes adaptation AGAINST Formal — proving the
        // hardcoded-Lowkey basis is gone and the operator's pick is honoured.
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            current_basis(home.path()),
            ProfilePreset::Lowkey,
            "no active preset chosen → Lowkey default"
        );
        crate::cli::profile::record_active_preset(home.path(), ProfilePreset::Formal).unwrap();
        assert_eq!(
            current_basis(home.path()),
            ProfilePreset::Formal,
            "after the operator picks Formal, the cron basis follows live"
        );
    }

    #[test]
    fn disabled_is_the_default() {
        assert!(
            !ProfileAdaptConfig::default().enabled,
            "SPEC-05 cron must be opt-in (default OFF), matching drift_alert"
        );
    }
}
