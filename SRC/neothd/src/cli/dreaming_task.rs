//! Background dreaming task — R-02 Phase 4c.
//!
//! Wraps the existing [`crate::daemon::dreaming`] composer in a tokio
//! interval task so the daemon writes one batch of dreams per cadence
//! tick (default: daily). When an `EmbedProvider` is wired into the
//! daemon (`freedom.yaml::inference.embedding_provider`) the task
//! uses [`crate::daemon::dreaming::compose_dreams_with_embeddings`]
//! for cosine-clustered themes; otherwise it falls back to the
//! deterministic [`crate::daemon::dreaming::compose_dream`] path so
//! operators without local inference still get a daily dream record.
//!
//! Off by default — opt in via `freedom.yaml::dreaming.enabled: true`.
//! The interval is operator-tunable (`dreaming.interval_secs`). Errors
//! log + retry next tick; never crash the daemon.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use rusqlite::Connection;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::daemon::dreaming::{
    append_dream, compose_dream, compose_dreams_with_embeddings, EventRef,
    DREAMING_CLUSTER_THRESHOLD,
};
use crate::providers::embed::EmbedProvider;

/// Default cadence: every 24h. Matches the "nightly dreaming" UX the
/// R-02 SPEC describes (cron 03:00). On a long-running daemon a 24h
/// interval lands one batch per day; operators who want more
/// frequent passes flip `dreaming.interval_secs: 3600` for hourly.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default window: last 24h. The composer reads `idx_episode` rows
/// whose `ts_ns` falls inside `now - window`. Aligns with the daily
/// interval so each tick processes one fresh day.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum events to embed per dreaming pass. Above this the task
/// truncates with a warn — protects operator-LLM cost on
/// high-traffic days (a 5k-event day at ~50ms/embed = 4min compute).
/// Tunable via `dreaming.max_events_per_pass`.
pub const DEFAULT_MAX_EVENTS: usize = 500;

/// Spawn the dreaming task. Returns the `JoinHandle` so the caller
/// can `.abort()` on shutdown.
///
/// `interval = None` → [`DEFAULT_INTERVAL`]. `window = None` →
/// [`DEFAULT_WINDOW`]. `max_events = None` → [`DEFAULT_MAX_EVENTS`].
/// `embed_provider = None` → deterministic theme labels only
/// (composer still runs, dreams still land).
pub fn spawn(
    home: PathBuf,
    embed_provider: Option<std::sync::Arc<dyn EmbedProvider>>,
    interval: Option<Duration>,
    window: Option<Duration>,
    max_events: Option<usize>,
) -> JoinHandle<Result<()>> {
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    let window = window.unwrap_or(DEFAULT_WINDOW);
    let max_events = max_events.unwrap_or(DEFAULT_MAX_EVENTS);
    tokio::spawn(async move { run(home, embed_provider, interval, window, max_events).await })
}

async fn run(
    home: PathBuf,
    embed_provider: Option<std::sync::Arc<dyn EmbedProvider>>,
    interval: Duration,
    window: Duration,
    max_events: usize,
) -> Result<()> {
    info!(
        interval_secs = interval.as_secs(),
        window_secs = window.as_secs(),
        max_events,
        embed_enabled = embed_provider.is_some(),
        "dreaming task started"
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — fresh boot has no new events to
    // process yet (the prior daemon's last tick already covered
    // the window).
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match run_one_pass(&home, embed_provider.as_deref(), window, max_events).await {
            Ok(report) => {
                if report.dreams_written > 0 {
                    info!(
                        events = report.events_considered,
                        dreams = report.dreams_written,
                        path = %report.path.display(),
                        "dreaming task wrote dream batch",
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "dreaming pass failed (will retry next tick)");
            }
        }
    }
}

/// One pass result — operator-visible counters + the file path the
/// dreams landed in. Returned from [`run_one_pass`] so the operator
/// `neoth dream now` CLI surface (future) can render the same shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassReport {
    /// Number of `idx_episode` rows considered in the window.
    pub events_considered: usize,
    /// Number of Dream records appended to today's JSONL.
    pub dreams_written: usize,
    /// JSONL file that received the appends (`~/.neoth/dreams/YYYY-MM-DD.jsonl`).
    pub path: PathBuf,
    /// Path that was taken: `embedding` (compose_dreams_with_embeddings)
    /// or `deterministic` (single compose_dream).
    pub path_taken: DreamingPath,
}

/// Which composer ran. Surfaces in the operator log so a sudden
/// flip from `embedding` → `deterministic` (e.g. local_qwen weights
/// went missing) is visible without grepping for "embed failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamingPath {
    Embedding,
    Deterministic,
}

/// Run one dreaming pass. Pure orchestrator — gathers events,
/// dispatches to embedding or deterministic compose, appends to
/// JSONL. Returns a [`PassReport`] for operator surface use.
///
/// `embed_provider = None` OR provider fails → deterministic
/// fallback (matches the L-07 `allow_cloud_fallback: false` safe-
/// default pattern: never silently spend cloud tokens, never crash
/// the dreaming pipeline either).
pub async fn run_one_pass(
    home: &Path,
    embed_provider: Option<&dyn EmbedProvider>,
    window: Duration,
    max_events: usize,
) -> Result<PassReport> {
    let events = gather_window_events(home, window, max_events)?;
    let day = today_utc_date();
    let path = crate::daemon::dreaming::jsonl_file_for_day(home, &day);

    if events.is_empty() {
        return Ok(PassReport {
            events_considered: 0,
            dreams_written: 0,
            path,
            path_taken: DreamingPath::Deterministic,
        });
    }

    let (dreams, path_taken) = if let Some(provider) = embed_provider {
        match compose_dreams_with_embeddings(
            &day,
            &events,
            provider,
            DREAMING_CLUSTER_THRESHOLD,
        )
        .await
        {
            Ok(d) => (d, DreamingPath::Embedding),
            Err(e) => {
                warn!(error = %e, "embedding compose failed; falling back to deterministic theme");
                (
                    vec![compose_dream(&day, "daily-deterministic", &events)],
                    DreamingPath::Deterministic,
                )
            }
        }
    } else {
        (
            vec![compose_dream(&day, "daily-deterministic", &events)],
            DreamingPath::Deterministic,
        )
    };

    let mut written = 0;
    for dream in &dreams {
        match append_dream(home, dream) {
            Ok(_) => written += 1,
            Err(e) => {
                warn!(error = %e, "append_dream failed; skipping this dream entry");
            }
        }
    }
    Ok(PassReport {
        events_considered: events.len(),
        dreams_written: written,
        path,
        path_taken,
    })
}

/// Load `idx_episode` rows whose `ts_ns` is within `window` of
/// `now`. Truncates at `max_events` (oldest-first selection so the
/// dream covers the start of the window — operators inspecting the
/// dream get a coherent narrative, not a random subset). Missing
/// `views.db` → empty Vec (fresh-install daemon hasn't indexed
/// anything yet).
fn gather_window_events(
    home: &Path,
    window: Duration,
    max_events: usize,
) -> Result<Vec<EventRef>> {
    let db_path = home.join("views.db");
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open(&db_path)?;
    let now_ns: i64 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)) as i64;
    let window_ns = window.as_nanos() as i64;
    let cutoff_ns = now_ns - window_ns;
    let mut stmt = conn.prepare(
        "SELECT event_id, ts_ns, text FROM idx_episode \
         WHERE ts_ns >= ?1 ORDER BY ts_ns ASC LIMIT ?2",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![cutoff_ns, max_events as i64],
        |row| {
            let id: i64 = row.get(0)?;
            let ts_ns: i64 = row.get(1)?;
            let text: String = row.get(2)?;
            Ok((id, ts_ns, text))
        },
    )?;
    let mut out = Vec::new();
    for r in rows {
        let (id, ts_ns, text) = r?;
        out.push(EventRef {
            id,
            ts_unix: ts_ns / 1_000_000_000,
            preview: text,
        });
    }
    Ok(out)
}

/// Return today's UTC date (`YYYY-MM-DD`). Same Howard-Hinnant
/// civil-from-days conversion used elsewhere in the codebase.
fn today_utc_date() -> String {
    let ts_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = ts_unix.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn seed_views_db(home: &Path, rows: &[(i64, i64, &str)]) {
        let db = Connection::open(home.join("views.db")).unwrap();
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS idx_episode ( \
                event_id INTEGER PRIMARY KEY, \
                ts_ns INTEGER NOT NULL, \
                text TEXT NOT NULL, \
                text_hash BLOB, \
                importance REAL DEFAULT 1.0)",
        )
        .unwrap();
        let mut stmt = db
            .prepare("INSERT INTO idx_episode (event_id, ts_ns, text) VALUES (?1, ?2, ?3)")
            .unwrap();
        for (id, ts_ns, text) in rows {
            stmt.execute(rusqlite::params![id, ts_ns, text]).unwrap();
        }
    }

    fn now_ns() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    }

    struct AlwaysWeatherEmbed;

    #[async_trait::async_trait]
    impl EmbedProvider for AlwaysWeatherEmbed {
        fn name(&self) -> &'static str {
            "always_weather"
        }
        fn default_dim(&self) -> usize {
            4
        }
        async fn embed(
            &self,
            _req: crate::providers::embed::EmbedRequest,
        ) -> Result<crate::providers::embed::EmbedResponse> {
            // All texts land in slot 0 → cosine = 1.0 between any
            // pair → single cluster.
            let mut v = vec![0.0f32; 4];
            v[0] = 1.0;
            Ok(crate::providers::embed::EmbedResponse {
                vector: v,
                model: "always_weather".into(),
                latency: Duration::from_micros(1),
            })
        }
    }

    struct FailingEmbed;

    #[async_trait::async_trait]
    impl EmbedProvider for FailingEmbed {
        fn name(&self) -> &'static str {
            "failing"
        }
        fn default_dim(&self) -> usize {
            4
        }
        async fn embed(
            &self,
            _req: crate::providers::embed::EmbedRequest,
        ) -> Result<crate::providers::embed::EmbedResponse> {
            anyhow::bail!("provider down")
        }
    }

    #[tokio::test]
    async fn one_pass_returns_empty_report_for_missing_views_db() {
        let dir = tempdir().unwrap();
        let report = run_one_pass(dir.path(), None, DEFAULT_WINDOW, DEFAULT_MAX_EVENTS)
            .await
            .unwrap();
        assert_eq!(report.events_considered, 0);
        assert_eq!(report.dreams_written, 0);
        assert_eq!(report.path_taken, DreamingPath::Deterministic);
    }

    #[tokio::test]
    async fn one_pass_writes_deterministic_dream_when_no_provider() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[(1, n - 3600 * 1_000_000_000, "first event"),
              (2, n - 1800 * 1_000_000_000, "second event")],
        );
        let report = run_one_pass(dir.path(), None, DEFAULT_WINDOW, DEFAULT_MAX_EVENTS)
            .await
            .unwrap();
        assert_eq!(report.events_considered, 2);
        assert_eq!(report.dreams_written, 1);
        assert_eq!(report.path_taken, DreamingPath::Deterministic);
        assert!(report.path.exists());
    }

    #[tokio::test]
    async fn one_pass_uses_embedding_path_when_provider_available() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[(1, n - 3600 * 1_000_000_000, "first event"),
              (2, n - 1800 * 1_000_000_000, "second event"),
              (3, n - 900 * 1_000_000_000, "third event")],
        );
        let provider = AlwaysWeatherEmbed;
        let report =
            run_one_pass(dir.path(), Some(&provider), DEFAULT_WINDOW, DEFAULT_MAX_EVENTS)
                .await
                .unwrap();
        assert_eq!(report.events_considered, 3);
        // AlwaysWeather collapses everything to one cluster → 1 dream.
        assert_eq!(report.dreams_written, 1);
        assert_eq!(report.path_taken, DreamingPath::Embedding);
    }

    #[tokio::test]
    async fn one_pass_falls_back_to_deterministic_when_embed_fails() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[(1, n - 3600 * 1_000_000_000, "first event")],
        );
        let provider = FailingEmbed;
        let report =
            run_one_pass(dir.path(), Some(&provider), DEFAULT_WINDOW, DEFAULT_MAX_EVENTS)
                .await
                .unwrap();
        assert_eq!(report.events_considered, 1);
        assert_eq!(report.dreams_written, 1);
        assert_eq!(
            report.path_taken,
            DreamingPath::Deterministic,
            "provider error must trigger deterministic fallback, never crash"
        );
    }

    #[tokio::test]
    async fn one_pass_respects_max_events_truncation() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        let rows: Vec<_> = (1i64..=10)
            .map(|i| (i, n - i * 1_000_000_000, "event"))
            .collect();
        let rows_ref: Vec<_> = rows.iter().map(|(a, b, c)| (*a, *b, *c)).collect();
        seed_views_db(dir.path(), &rows_ref);
        let report = run_one_pass(dir.path(), None, DEFAULT_WINDOW, 3).await.unwrap();
        assert_eq!(report.events_considered, 3, "truncate at max_events=3");
    }

    #[tokio::test]
    async fn one_pass_ignores_events_outside_window() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        // One event inside the 1-hour test window, one outside.
        seed_views_db(
            dir.path(),
            &[(1, n - 60 * 1_000_000_000, "inside"),     // 60s ago
              (2, n - 3600 * 1_000_000_000 * 24, "outside")], // 24h ago
        );
        let report =
            run_one_pass(dir.path(), None, Duration::from_secs(1800), DEFAULT_MAX_EVENTS)
                .await
                .unwrap();
        assert_eq!(report.events_considered, 1, "window excludes the 24h-ago row");
    }

    #[tokio::test]
    async fn today_utc_date_renders_yyyy_mm_dd() {
        let s = today_utc_date();
        assert_eq!(s.len(), 10);
        assert_eq!(s.chars().nth(4), Some('-'));
        assert_eq!(s.chars().nth(7), Some('-'));
        // First 4 chars parse as year.
        let _: u32 = s[..4].parse().unwrap();
    }

    #[tokio::test]
    async fn task_aborts_cleanly() {
        let dir = tempdir().unwrap();
        let task = spawn(
            dir.path().to_path_buf(),
            None,
            Some(Duration::from_millis(50)),
            None,
            None,
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        task.abort();
        let _ = task.await;
    }

    #[test]
    fn constants_pinned() {
        assert_eq!(DEFAULT_INTERVAL.as_secs(), 86_400);
        assert_eq!(DEFAULT_WINDOW.as_secs(), 86_400);
        assert_eq!(DEFAULT_MAX_EVENTS, 500);
    }
}
