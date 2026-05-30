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
//! Preset basis: there is no persisted behavioural `ProfilePreset` in
//! `freedom.yaml` today (the `neoth preset` system is the orthogonal
//! provider-bundle store), so proposals are computed against the `Lowkey`
//! preset — the documented recommended default — exactly as the
//! `neoth self-dev propose` CLI defaults (`--current-preset lowkey`).

use std::path::PathBuf;

use crate::config::ProfileAdaptConfig;
use crate::wal::writer::WalWriterHandle;

/// Preset the cron computes adaptation proposals against. Matches the
/// `neoth self-dev propose` CLI default; see the module doc for why.
const CRON_BASIS_PRESET: &str = "lowkey";

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
) -> Result<usize, String> {
    crate::cron::runner::aggregate_profile_snapshot(home, wal_dir)
        .await
        .map_err(|e| format!("aggregate snapshot: {e}"))?;

    let Some(profile) = crate::profile::snapshot::load_snapshot(home) else {
        // Fresh install / empty WAL → no behavioural data to adapt from.
        return Ok(0);
    };

    crate::cli::self_dev::propose_and_store(home, &profile, CRON_BASIS_PRESET, Some(writer))
        .await
        .map_err(|e| format!("propose + store: {e}"))
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
            match run_profile_adapt_tick(&home, &wal_dir, &writer).await {
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
            interval_secs: crate::config::DEFAULT_PROFILE_ADAPT_INTERVAL_SECS,
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
            interval_secs: crate::config::DEFAULT_PROFILE_ADAPT_INTERVAL_SECS,
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
        let n = run_profile_adapt_tick(home.path(), wal_dir.path(), &writer)
            .await
            .expect("tick on empty wal must not error");
        assert_eq!(n, 0, "empty WAL → no behavioural data → no proposals");
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
    fn disabled_is_the_default() {
        assert!(
            !ProfileAdaptConfig::default().enabled,
            "SPEC-05 cron must be opt-in (default OFF), matching drift_alert"
        );
    }
}
