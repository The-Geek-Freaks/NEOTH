//! NN-MEM-06 — daily contradiction auto-resolution cron.
//!
//! Calls [`crate::memory::contradiction::auto_resolve_batch`] on a daily
//! schedule (operator-tunable via `freedom.yaml::contradiction_resolve.interval_secs`).
//! Resolves the accumulating `pending` ledger backlog without operator effort:
//!
//! - **Temporal-supersede** — same entity + newer timestamp → older fact flagged
//!   `Superseded`, ledger decision `'superseded'`.
//! - **Semantic-equiv** — full-statement Jaccard ≥ 0.90 → older fact merged away,
//!   ledger decision `'merged'`.
//! - **Human-review** — genuine conflicts that match neither rule → decision
//!   `'human_review'` so `neoth groundtruth contradictions --list` can surface them.
//!
//! ## Design notes
//!
//! - Mirrors the `run_X_tick` + `spawn_X_cron_loop` pattern used by
//!   [`super::drift_alert_cron`] and [`super::doctor_cron`]: one pure testable
//!   function + one spawn wrapper.
//! - Opt-in (disabled by default). Operators enable by adding:
//!   ```yaml
//!   contradiction_resolve:
//!     enabled: true
//!   ```
//!   to `freedom.yaml`. The interval defaults to 24 h.
//! - No WAL event is written (the `0x9D` slot reserved in `contradiction.rs`'s
//!   module doc is for a future HOT-lane PR). Resolution details are logged via
//!   `tracing`.

use std::path::PathBuf;
use std::time::Duration;

use crate::memory::contradiction::{AutoResolveSummary, auto_resolve_batch};
use crate::memory::store;

/// Default run interval: once per day. Operators may lower this to hourly
/// (3600) on busy fact corpora, or raise it to 7 days (604800) for light
/// installations.
pub const DEFAULT_INTERVAL_SECS: u64 = 86_400; // 24 h

/// Configuration for the contradiction-resolve cron (maps to
/// `freedom.yaml::contradiction_resolve`).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ContradictionResolveCronConfig {
    /// Master switch. When `false`, the cron loop is not spawned.
    pub enabled: bool,
    /// How often to run, in seconds. Clamped to a 60s floor.
    pub interval_secs: u64,
}

impl Default for ContradictionResolveCronConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: DEFAULT_INTERVAL_SECS,
        }
    }
}

impl ContradictionResolveCronConfig {
    /// The effective interval duration — clamped to 60s so `interval_secs: 0`
    /// can never tight-loop.
    pub fn interval_duration(&self) -> Duration {
        Duration::from_secs(self.interval_secs.max(60))
    }
}

/// One contradiction-resolve cron tick. Opens `db_path`, loads all pending
/// ledger rows, and runs [`auto_resolve_batch`] without an embed provider
/// (deterministic Jaccard paths; no model required for the daily sweep).
///
/// The connection is opened and the entire batch resolved in a
/// `spawn_blocking` context so the `!Send` [`rusqlite::Connection`] never
/// crosses an async await boundary.
///
/// Returns `Ok(summary)` — callers log counts and continue.
pub async fn run_contradiction_resolve_tick(db_path: &std::path::Path) -> Result<AutoResolveSummary, String> {
    let path = db_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let conn = store::open(&path).map_err(|e| format!("open db: {e}"))?;
        let now_ns = crate::time::now_unix_ns_i64();
        // Run the async batch in a one-shot runtime — spawn_blocking provides
        // its own thread but no async executor, so we build a minimal local
        // one to drive the future. The batch is CPU/SQLite-bound; no real
        // async I/O occurs on the None-embed path.
        tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|e| format!("build rt: {e}"))?
            .block_on(auto_resolve_batch(&conn, now_ns, None))
            .map_err(|e| format!("auto_resolve_batch: {e}"))
    })
    .await
    .map_err(|e| format!("spawn_blocking join: {e}"))?
}

/// Spawn the contradiction-resolve cron loop as a background tokio task.
/// Returns `None` when `config.enabled == false` — opt-out operators carry
/// no idle task.
///
/// `db_path` is the path to `views.db` (the file that holds
/// `idx_contradictions` and `idx_groundtruth`).
pub fn spawn_contradiction_resolve_cron_loop(
    config: ContradictionResolveCronConfig,
    db_path: PathBuf,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        tracing::info!(
            "contradiction-resolve cron disabled \
             (contradiction_resolve.enabled = false)"
        );
        return None;
    }
    let interval = config.interval_duration();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            "contradiction-resolve cron loop online (NN-MEM-06)",
        );
        loop {
            ticker.tick().await;
            match run_contradiction_resolve_tick(&db_path).await {
                Ok(summary) => tracing::info!(
                    superseded = summary.superseded,
                    merged = summary.merged,
                    human_queue = summary.human_queue,
                    "contradiction-resolve cron tick complete",
                ),
                Err(e) => tracing::error!(
                    error = %e,
                    "contradiction-resolve cron tick failed",
                ),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::groundtruth::{self, Source};
    use crate::memory::contradiction::{
        DECISION_HUMAN_REVIEW, list_contradictions,
    };

    #[tokio::test]
    async fn cron_tick_supersedes_older_of_two_same_entity_facts() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = store::open(&db_path).unwrap();

        // Insert two same-entity facts with different timestamps.
        groundtruth::insert(&conn, "nas is at 192.168.1.20", &Source::OperatorRuntime, "global", 1).unwrap();
        groundtruth::insert(&conn, "nas is at 10.0.0.5", &Source::OperatorRuntime, "global", 500).unwrap();
        drop(conn); // release so the tick can reopen

        let summary = run_contradiction_resolve_tick(&db_path).await.unwrap();
        assert_eq!(summary.superseded, 1, "one pair resolved as temporal-supersede");

        let conn2 = store::open(&db_path).unwrap();
        // The older fact (ts=1) must be Superseded.
        let st: String = conn2.query_row(
            "SELECT fact_state FROM idx_groundtruth WHERE statement = 'nas is at 192.168.1.20'",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(st, "superseded");
        // No pending rows remain.
        assert!(list_contradictions(&conn2, false).unwrap().is_empty());
    }

    #[tokio::test]
    async fn cron_tick_sends_equal_timestamp_conflict_to_human_review() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = store::open(&db_path).unwrap();

        // Same timestamp → no temporal rule; different values → no semantic-equiv.
        groundtruth::insert(&conn, "nas is at 192.168.1.20", &Source::OperatorRuntime, "global", 77).unwrap();
        groundtruth::insert(&conn, "nas is at 10.0.0.5", &Source::OperatorRuntime, "global", 77).unwrap();
        drop(conn);

        let summary = run_contradiction_resolve_tick(&db_path).await.unwrap();
        assert_eq!(summary.human_queue, 1, "equal-ts → human-review queue");

        let conn2 = store::open(&db_path).unwrap();
        let all = list_contradictions(&conn2, true).unwrap();
        assert!(!all.is_empty());
        assert_eq!(all[0].decision, DECISION_HUMAN_REVIEW);
    }

    #[tokio::test]
    async fn cron_tick_noop_on_empty_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        // Open once to create the schema.
        drop(store::open(&db_path).unwrap());

        let summary = run_contradiction_resolve_tick(&db_path).await.unwrap();
        assert_eq!(summary, AutoResolveSummary::default());
    }

    #[test]
    fn config_defaults() {
        let cfg = ContradictionResolveCronConfig::default();
        assert!(!cfg.enabled, "off by default");
        assert_eq!(cfg.interval_secs, DEFAULT_INTERVAL_SECS);
        assert_eq!(cfg.interval_duration(), Duration::from_secs(DEFAULT_INTERVAL_SECS));
    }

    #[test]
    fn interval_floor_clamps_zero() {
        let cfg = ContradictionResolveCronConfig {
            enabled: true,
            interval_secs: 0,
        };
        assert_eq!(cfg.interval_duration(), Duration::from_secs(60));
    }

    #[test]
    fn spawn_returns_none_when_disabled() {
        let cfg = ContradictionResolveCronConfig { enabled: false, interval_secs: 86_400 };
        let handle = spawn_contradiction_resolve_cron_loop(cfg, "/nonexistent".into());
        assert!(handle.is_none(), "disabled config must return None");
    }
}
