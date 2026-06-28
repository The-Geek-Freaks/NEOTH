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
    DREAMING_CLUSTER_THRESHOLD, EventRef, append_dream, compose_dream,
    compose_dreams_with_embeddings,
};
use crate::providers::Provider;
use crate::providers::embed::EmbedProvider;
use crate::wal::writer::WalWriterHandle;

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
/// (composer still runs, dreams still land). `chat_provider = Some`
/// (SPEC-12 Phase 4b) → LLM-summarised cluster theme labels; `None`
/// keeps the deterministic `cluster-N-seed-id` labels. `writer = Some`
/// → the daemon owns the WAL writer and each non-empty pass emits a
/// `0xF4 DREAM_COMPOSED` audit frame (`None` for one-shot callers that
/// audit separately, e.g. `neoth dream now`).
pub fn spawn(
    home: PathBuf,
    embed_provider: Option<std::sync::Arc<dyn EmbedProvider>>,
    chat_provider: Option<std::sync::Arc<dyn Provider>>,
    interval: Option<Duration>,
    window: Option<Duration>,
    max_events: Option<usize>,
    writer: Option<WalWriterHandle>,
) -> JoinHandle<Result<()>> {
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    let window = window.unwrap_or(DEFAULT_WINDOW);
    let max_events = max_events.unwrap_or(DEFAULT_MAX_EVENTS);
    tokio::spawn(async move {
        run(
            home,
            embed_provider,
            chat_provider,
            interval,
            window,
            max_events,
            writer,
        )
        .await
    })
}

async fn run(
    home: PathBuf,
    embed_provider: Option<std::sync::Arc<dyn EmbedProvider>>,
    chat_provider: Option<std::sync::Arc<dyn Provider>>,
    interval: Duration,
    window: Duration,
    max_events: usize,
    writer: Option<WalWriterHandle>,
) -> Result<()> {
    info!(
        interval_secs = interval.as_secs(),
        window_secs = window.as_secs(),
        max_events,
        embed_enabled = embed_provider.is_some(),
        summarize_themes = chat_provider.is_some(),
        "dreaming task started"
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — fresh boot has no new events to
    // process yet (the prior daemon's last tick already covered
    // the window).
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match run_one_pass(
            &home,
            embed_provider.as_deref(),
            chat_provider.as_deref(),
            window,
            max_events,
            writer.as_ref(),
        )
        .await
        {
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
        // Slice C — nightly auto self-improve. In full-auto mode (or when the
        // operator explicitly enabled `auto`) stage a SkillOpt proposal so
        // improvements accrue without a manual `neoth self-improve run`. NEVER
        // auto-accepts: the review-then-adopt gate still requires an explicit
        // `accept`. Daemon-cron only — `neoth dream now` calls run_one_pass
        // directly and never triggers this. Best-effort: any miss logs + skips.
        self_improve_auto_pass(&home).await;
    }
}

/// Nightly auto self-improve pass (Slice C). Gated by the EFFECTIVE
/// self-improve switch (full-auto implies on, an explicit operator choice
/// wins) AND SkillOpt being installed. Stages one proposal for the default
/// persona's `skill.md`; the operator still must `neoth self-improve accept`
/// it. Runs the (blocking, possibly slow) engine off the async runtime.
async fn self_improve_auto_pass(home: &Path) {
    let home = home.to_path_buf();
    if let Err(e) =
        tokio::task::spawn_blocking(move || self_improve_auto_pass_blocking(&home)).await
    {
        warn!(error = %e, "self-improve auto-pass task join failed");
    }
}

fn self_improve_auto_pass_blocking(home: &Path) {
    use crate::self_improve as si;
    let autonomy = crate::config::FreedomConfig::load_from_default_path()
        .map(|c| c.autonomy)
        .unwrap_or_default();
    let cfg = si::SelfImproveConfig::load(home).effective(autonomy);
    if !cfg.auto || !si::is_installed() {
        return; // not in auto mode, or engine absent → nothing to do
    }
    let persona = "default";
    // Don't pile up: if a proposal for this persona is already awaiting review,
    // skip this tick (and skip spawning the engine entirely).
    if si::load_proposals(home)
        .iter()
        .any(|p| p.skill == persona && p.status == si::ProposalStatus::Pending)
    {
        return;
    }
    let skill_path = crate::skills::installer::default_skills_dir()
        .join(persona)
        .join("skill.md");
    let before = std::fs::read_to_string(&skill_path).unwrap_or_default();
    // F13 — bounded run: a hung/runaway SkillOpt python process must not block
    // the dreaming tick (best-effort "any miss logs + skips" contract).
    let (after, quality, parsed_spec) =
        match si::run_skillopt_capped(persona, si::SKILLOPT_TIMEOUT) {
            Ok(o) => si::parse_proposal_output(&String::from_utf8_lossy(&o.stdout)),
            Err(e) => {
                warn!(error = %e, "self-improve auto-pass: SkillOpt run failed/timed out");
                return;
            }
        };
    if after.trim().is_empty() || after == before {
        return; // engine proposed nothing new → don't stage a no-op
    }
    let now = crate::time::now_unix_i64();
    let id = format!("p{now}");
    match si::stage_proposal(
        home,
        si::Proposal {
            id: id.clone(),
            skill: persona.to_string(),
            skill_path: skill_path.display().to_string(),
            before,
            after,
            summary: format!("nightly SkillOpt proposal for {persona}"),
            status: si::ProposalStatus::Pending,
            at_unix: now,
            backup: None,
            score_before: quality.score_before,
            score_after: quality.score_after,
            heldout_eval_summary: quality.heldout_eval_summary,
            why_this_improves: quality.why_this_improves,
            risk_notes: quality.risk_notes,
            spec: parsed_spec, // IMPR-01: carry parsed spec; drift_sha added inside stage_proposal
        },
    ) {
        Ok(_) => info!(proposal = %id, "self-improve auto-pass staged a proposal for review"),
        Err(e) => warn!(error = %e, "self-improve auto-pass: stage_proposal failed"),
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

impl PassReport {
    /// `YYYY-MM-DD` derived from the JSONL path stem (e.g.
    /// `~/.neoth/dreams/2026-06-03.jsonl` → `2026-06-03`). Empty when the
    /// path has no stem. Used by the `0xF4 DREAM_COMPOSED` audit payload +
    /// the operator render — single source so the daemon + CLI agree.
    pub(crate) fn day_label(&self) -> String {
        self.path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string()
    }
}

/// Build the `0xF4 DREAM_COMPOSED` audit payload from a pass report.
/// Shared by the daemon cron emit ([`run_one_pass`] when a writer is
/// passed) and the one-shot `neoth dream now` CLI emit so the two paths
/// never drift in payload shape (only the emit MECHANISM + provenance
/// flag differ: daemon = `writer.append` + SYNTHETIC; CLI = one-shot
/// writer, operator-triggered).
pub(crate) fn dream_composed_payload(report: &PassReport, ts_unix: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "day": report.day_label(),
        "dreams": report.dreams_written,
        "events_considered": report.events_considered,
        "path_taken": format!("{:?}", report.path_taken),
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

/// Daemon-side `0xF4 DREAM_COMPOSED` emit. Best-effort + SYNTHETIC (this
/// is a daemon-derived frame, matching the regression / recall-latency
/// cron convention). A WAL append failure logs + never fails the pass.
async fn emit_dream_composed_daemon(writer: &WalWriterHandle, report: &PassReport) {
    let ts_unix = crate::time::now_unix_secs();
    let payload = dream_composed_payload(report, ts_unix);
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_DREAM_COMPOSED, &payload)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
    if let Err(e) = writer.append(header, payload).await {
        warn!(error = %e, "dreaming: DREAM_COMPOSED frame append failed (audit gap)");
    }
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
    chat_provider: Option<&dyn Provider>,
    window: Duration,
    max_events: usize,
    writer: Option<&WalWriterHandle>,
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

    let merge_cross_themes = crate::config::FreedomConfig::load_from_default_path()
        .map(|c| c.dreaming.merge_cross_themes)
        .unwrap_or(false);
    let (dreams, path_taken) = if let Some(provider) = embed_provider {
        match compose_dreams_with_embeddings(
            &day,
            &events,
            provider,
            chat_provider,
            DREAMING_CLUSTER_THRESHOLD,
            merge_cross_themes,
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
    // KF-04 — idle-time skill forge: gated, best-effort. Synthesise a
    // candidate skill from each composed dream + stage it for operator
    // review (OB-03 queue). NEOTH never writes the skill; the operator
    // adopts it via `neoth proactive accept`. A forge/queue miss never
    // fails the pass — the dreams are already persisted above.
    let forge_enabled = crate::config::FreedomConfig::load_from_default_path()
        .map(|c| c.dreaming.forge_skills)
        .unwrap_or(false);
    if forge_enabled {
        forge_and_stage_dreams(home, &dreams);
    }

    let report = PassReport {
        events_considered: events.len(),
        dreams_written: written,
        path,
        path_taken,
    };

    // SPEC-12 daemon-side audit: when the daemon owns the WAL writer and
    // this pass actually wrote dreams, emit a `0xF4 DREAM_COMPOSED` frame so
    // the nightly cron is auditable just like `neoth dream now`. One-shot
    // callers pass `writer = None` and audit via their own path.
    if report.dreams_written > 0 {
        if let Some(w) = writer {
            emit_dream_composed_daemon(w, &report).await;
        }
    }

    Ok(report)
}

/// KF-04 — forge a candidate skill from each dream + stage it as an
/// OB-03 proposal for operator review. Best-effort: a queue-IO error or
/// an un-forgeable dream is logged + skipped, never fails the dreaming
/// pass. Dedup is handled by `stage_and_enqueue` (same dream → same
/// proposal id → enqueued at most once).
fn forge_and_stage_dreams(home: &Path, dreams: &[crate::daemon::dreaming::Dream]) {
    use crate::proactive::ProactiveQueue;
    use crate::proactive::action_staging::stage_and_enqueue;
    let queue_path = home.join("proactive_queue.json");
    let mut queue = ProactiveQueue::load_from(&queue_path).unwrap_or_default();
    let mut staged = 0usize;
    for dream in dreams {
        if let Some(proposal) = crate::daemon::skill_forge::build_skill_proposal_from_dream(dream) {
            match stage_and_enqueue(home, proposal, &mut queue) {
                Ok((_, true)) => staged += 1,
                Ok((_, false)) => {} // already queued (dedup)
                Err(e) => warn!(error = %e, "skill-forge: stage failed"),
            }
        }
    }
    if staged > 0 {
        match queue.save_to(&queue_path) {
            Ok(()) => {
                tracing::info!(staged, "skill-forge: staged candidate skill(s) for review")
            }
            Err(e) => warn!(error = %e, "skill-forge: queue save failed"),
        }
    }
}

/// Load `idx_episode` rows whose `ts_ns` is within `window` of
/// `now`. Truncates at `max_events` (oldest-first selection so the
/// dream covers the start of the window — operators inspecting the
/// dream get a coherent narrative, not a random subset). Missing
/// `views.db` → empty Vec (fresh-install daemon hasn't indexed
/// anything yet).
fn gather_window_events(home: &Path, window: Duration, max_events: usize) -> Result<Vec<EventRef>> {
    let db_path = home.join("views.db");
    if !db_path.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open(&db_path)?;
    let now_ns: i64 = (crate::time::now_unix_ns_u128()) as i64;
    let window_ns = window.as_nanos() as i64;
    let cutoff_ns = now_ns - window_ns;
    let mut stmt = conn.prepare(
        "SELECT event_id, ts_ns, text FROM idx_episode \
         WHERE ts_ns >= ?1 ORDER BY ts_ns ASC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![cutoff_ns, max_events as i64], |row| {
        let id: i64 = row.get(0)?;
        let ts_ns: i64 = row.get(1)?;
        let text: String = row.get(2)?;
        Ok((id, ts_ns, text))
    })?;
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
    let ts_unix = crate::time::now_unix_i64();
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
        crate::time::now_unix_ns_i64()
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
        let report = run_one_pass(
            dir.path(),
            None,
            None,
            DEFAULT_WINDOW,
            DEFAULT_MAX_EVENTS,
            None,
        )
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
            &[
                (1, n - 3600 * 1_000_000_000, "first event"),
                (2, n - 1800 * 1_000_000_000, "second event"),
            ],
        );
        let report = run_one_pass(
            dir.path(),
            None,
            None,
            DEFAULT_WINDOW,
            DEFAULT_MAX_EVENTS,
            None,
        )
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
            &[
                (1, n - 3600 * 1_000_000_000, "first event"),
                (2, n - 1800 * 1_000_000_000, "second event"),
                (3, n - 900 * 1_000_000_000, "third event"),
            ],
        );
        let provider = AlwaysWeatherEmbed;
        let report = run_one_pass(
            dir.path(),
            Some(&provider),
            None,
            DEFAULT_WINDOW,
            DEFAULT_MAX_EVENTS,
            None,
        )
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
        seed_views_db(dir.path(), &[(1, n - 3600 * 1_000_000_000, "first event")]);
        let provider = FailingEmbed;
        let report = run_one_pass(
            dir.path(),
            Some(&provider),
            None,
            DEFAULT_WINDOW,
            DEFAULT_MAX_EVENTS,
            None,
        )
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
        let report = run_one_pass(dir.path(), None, None, DEFAULT_WINDOW, 3, None)
            .await
            .unwrap();
        assert_eq!(report.events_considered, 3, "truncate at max_events=3");
    }

    #[tokio::test]
    async fn one_pass_ignores_events_outside_window() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        // One event inside the 1-hour test window, one outside.
        seed_views_db(
            dir.path(),
            &[
                (1, n - 60 * 1_000_000_000, "inside"), // 60s ago
                (2, n - 3600 * 1_000_000_000 * 24, "outside"),
            ], // 24h ago
        );
        let report = run_one_pass(
            dir.path(),
            None,
            None,
            Duration::from_secs(1800),
            DEFAULT_MAX_EVENTS,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            report.events_considered, 1,
            "window excludes the 24h-ago row"
        );
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
            None,
            Some(Duration::from_millis(50)),
            None,
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

    // ── SPEC-12 daemon-side 0xF4 DREAM_COMPOSED emit + chat-label wiring ──────

    /// Count `0xF4 DREAM_COMPOSED` frames in a sealed WAL segment.
    fn count_dream_composed_frames(seg: &Path) -> usize {
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
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_DREAM_COMPOSED {
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

    /// Chat provider returning a fixed reply — exercises the run_one_pass
    /// chat-label wiring end-to-end.
    struct FixedLabelChat;
    #[async_trait::async_trait]
    impl Provider for FixedLabelChat {
        fn name(&self) -> &'static str {
            "fixed_label_chat"
        }
        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                text: "weekend trip planning".into(),
                model: "fixed_label_chat".into(),
                latency: Duration::from_micros(1),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn run_one_pass_emits_dream_composed_when_writer_present() {
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[(1, n - 1800 * 1_000_000_000, "an event in the window")],
        );
        let seg_dir = tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let report = run_one_pass(
            dir.path(),
            None,
            None,
            DEFAULT_WINDOW,
            DEFAULT_MAX_EVENTS,
            Some(&writer),
        )
        .await
        .unwrap();
        assert_eq!(report.dreams_written, 1);

        drop(writer);
        join.await.ok();
        assert_eq!(
            count_dream_composed_frames(&seg),
            1,
            "a writer-backed pass that wrote dreams must emit exactly one 0xF4",
        );
    }

    #[tokio::test]
    async fn run_one_pass_no_frame_when_writer_none() {
        // The CLI one-shot path passes writer = None (it audits separately).
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(dir.path(), &[(1, n - 1800 * 1_000_000_000, "event")]);
        let seg_dir = tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let report = run_one_pass(
            dir.path(),
            None,
            None,
            DEFAULT_WINDOW,
            DEFAULT_MAX_EVENTS,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.dreams_written, 1);

        drop(writer);
        join.await.ok();
        assert_eq!(
            count_dream_composed_frames(&seg),
            0,
            "writer = None must not emit a frame on this segment",
        );
    }

    #[tokio::test]
    async fn run_one_pass_no_frame_when_no_dreams() {
        // Empty window (no views.db) → 0 dreams → no audit frame even with a writer.
        let dir = tempdir().unwrap();
        let seg_dir = tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        let report = run_one_pass(
            dir.path(),
            None,
            None,
            DEFAULT_WINDOW,
            DEFAULT_MAX_EVENTS,
            Some(&writer),
        )
        .await
        .unwrap();
        assert_eq!(report.dreams_written, 0);

        drop(writer);
        join.await.ok();
        assert_eq!(count_dream_composed_frames(&seg), 0);
    }

    #[tokio::test]
    async fn run_one_pass_threads_chat_label_into_dreams() {
        // embed groups everything into one cluster; the chat provider labels it.
        let dir = tempdir().unwrap();
        let n = now_ns();
        seed_views_db(
            dir.path(),
            &[
                (1, n - 1800 * 1_000_000_000, "first"),
                (2, n - 900 * 1_000_000_000, "second"),
            ],
        );
        let embed = AlwaysWeatherEmbed;
        let report = run_one_pass(
            dir.path(),
            Some(&embed),
            Some(&FixedLabelChat),
            DEFAULT_WINDOW,
            DEFAULT_MAX_EVENTS,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.path_taken, DreamingPath::Embedding);

        let day = report.day_label();
        let dreams = crate::daemon::dreaming::load_dreams_for_day(dir.path(), &day);
        assert_eq!(dreams.len(), 1);
        assert_eq!(
            dreams[0].theme_label, "weekend trip planning",
            "the LLM label must replace the deterministic cluster-N-seed-id",
        );
    }

    #[test]
    fn dream_composed_payload_has_stable_shape() {
        let report = PassReport {
            events_considered: 5,
            dreams_written: 2,
            path: PathBuf::from("/home/op/.neoth/dreams/2026-06-03.jsonl"),
            path_taken: DreamingPath::Embedding,
        };
        let bytes = dream_composed_payload(&report, 1_700_000_000);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["day"], "2026-06-03");
        assert_eq!(v["dreams"], 2);
        assert_eq!(v["events_considered"], 5);
        assert_eq!(v["path_taken"], "Embedding");
        assert_eq!(v["ts_unix"], 1_700_000_000_u64);
    }
}
