//! GOLD-ADAPT-MEM-16 — ArXiv skill-learning cron.
//!
//! Scans cs.AI/cs.LG (operator-configurable `arxiv_skill_scan.topics`) on a
//! cadence (default 6h), extracts 1-3 actionable takeaways per paper via the
//! shared LLM provider, and writes each takeaway to `idx_groundtruth` as
//! `source = "arxiv-skill-scan"` / `scope = "arxiv-learning"` /
//! `FactState::Candidate`. Facts surface into recall/council via the existing
//! `groundtruth::surface_for_recall` path — no new recall wiring needed.
//!
//! ## Design
//!
//! - **WAL-free**: groundtruth insert is the durable audit record (per
//!   MEM-15 precedent — all WAL bands 0x00..=0xFF are assigned/reserved).
//! - **spawn_blocking for DB writes**: rusqlite `Connection` is `!Send`;
//!   a new connection is opened INSIDE `spawn_blocking` (never passed across
//!   an `.await` boundary), matching the `daemon::synthesis_cron` pattern.
//! - **Provider required**: unlike EL-02 `arxiv_ingest_task` (which falls
//!   back to raw abstracts), this cron requires a provider for extraction.
//!   No provider → `spawn_arxiv_skill_scan` returns `None` and warns.
//! - **Fail-soft**: topic fetch failure → skip topic. Paper extraction
//!   failure → skip paper. DB write failure → log + skip. Never crashes.
//! - **Dedup via corroboration**: `groundtruth::insert` merges repeated
//!   identical `(statement, scope)` rows — second tick bumps `confirmed_count`
//!   and lifts the Candidate toward Verified automatically.
//! - **Disabled by default**: `arxiv_skill_scan.enabled: false`. Opt in via
//!   freedom.yaml.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::memory::{groundtruth, groundtruth::Source, store};
use crate::providers::{Provider, Request};
use crate::tools::arxiv::{self, ARXIV_API_URL};

/// Default cadence: 6h. Same as the EL-02 arxiv_ingest_task.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Default max papers fetched per topic per tick.
pub const DEFAULT_MAX_PER_TOPIC: usize = 10;

/// One scan pass result — counters for tracing + tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Number of topics queried this pass.
    pub topics_queried: usize,
    /// Total papers fetched across all topics.
    pub papers_scanned: usize,
    /// Groundtruth facts successfully inserted (or corroborated).
    pub facts_inserted: usize,
    /// Papers skipped due to extraction or DB failure.
    pub papers_skipped: usize,
}

/// Spawn the arxiv skill-scan cron. Returns the `JoinHandle` for abort-on-shutdown.
///
/// `interval = None` → [`DEFAULT_INTERVAL`]. `max_per_topic = None` →
/// [`DEFAULT_MAX_PER_TOPIC`].
pub fn spawn(
    home: PathBuf,
    topics: Vec<String>,
    provider: Arc<dyn Provider>,
    interval: Option<Duration>,
    max_per_topic: Option<usize>,
) -> JoinHandle<Result<()>> {
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    let max_per_topic = max_per_topic.unwrap_or(DEFAULT_MAX_PER_TOPIC);
    tokio::spawn(async move { run(home, topics, provider, interval, max_per_topic).await })
}

async fn run(
    home: PathBuf,
    topics: Vec<String>,
    provider: Arc<dyn Provider>,
    interval: Duration,
    max_per_topic: usize,
) -> Result<()> {
    info!(
        topics = topics.len(),
        interval_secs = interval.as_secs(),
        max_per_topic,
        "arxiv skill-scan cron started"
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — a fresh boot has nothing new to scan beyond
    // what the prior run already ingested.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match run_one_scan_pass(ARXIV_API_URL, &home, &topics, provider.as_ref(), max_per_topic)
            .await
        {
            Ok(r) if r.facts_inserted > 0 || r.papers_skipped > 0 => {
                info!(
                    topics = r.topics_queried,
                    papers = r.papers_scanned,
                    facts = r.facts_inserted,
                    skipped = r.papers_skipped,
                    "arxiv skill-scan pass complete"
                );
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "arxiv skill-scan pass failed (will retry next tick)"),
        }
    }
}

/// Run one scan pass. `endpoint` is a test seam (wiremock replaces the real
/// arXiv URL in tests; production passes [`ARXIV_API_URL`]).
///
/// Fail-soft: topic fetch failure → skip topic; paper extraction failure →
/// skip paper; DB write failure → log + skip. Never returns `Err` for
/// per-item failures — only for a catastrophic pass-level failure.
pub async fn run_one_scan_pass(
    endpoint: &str,
    home: &Path,
    topics: &[String],
    provider: &dyn Provider,
    max_per_topic: usize,
) -> Result<ScanReport> {
    let db_path = home.join("views.db");
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    let mut papers_scanned = 0usize;
    let mut facts_inserted = 0usize;
    let mut papers_skipped = 0usize;

    for topic in topics {
        let papers = match arxiv::search_against(endpoint, topic, max_per_topic).await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, topic, "arxiv skill-scan topic fetch failed; skipping topic");
                continue;
            }
        };

        for paper in &papers {
            papers_scanned += 1;
            let learnings =
                match extract_learnings(provider, &paper.title, &paper.abstract_text).await {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(
                            error = %e,
                            title = %paper.title,
                            "extract_learnings failed; skipping paper"
                        );
                        papers_skipped += 1;
                        continue;
                    }
                };

            // DB write: open a NEW connection INSIDE spawn_blocking.
            // rusqlite Connection is !Send — never pass it across an .await.
            // MEM-16 arxiv-provenance: capture paper metadata so each fact is
            // content-addressed and auditable (arxiv_id, pdf_url, published, categories/topic).
            let paper_title = paper.title.clone();
            let paper_id = paper.id.clone();
            let paper_pdf_url = paper.pdf_url.clone();
            let paper_published = paper.published.clone();
            let paper_categories = paper.categories.clone();
            let db = db_path.clone();
            let rows: Vec<String> = learnings;
            let inserted = tokio::task::spawn_blocking(move || -> usize {
                let conn = match store::open(&db) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "arxiv skill-scan: failed to open views.db; skipping paper");
                        return 0;
                    }
                };
                let topic_tag = paper_categories.first().map(|s| s.as_str()).unwrap_or("unknown");
                let mut n = 0usize;
                for fact in rows {
                    // Enrich statement with paper provenance so recall surfaces context.
                    let statement = format!(
                        "[arxiv:{paper_id}] {paper_title} ({paper_published}, {topic_tag}, {paper_pdf_url}): {fact}"
                    );
                    match groundtruth::insert(&conn, &statement, &Source::ArxivScan, "arxiv-learning", now_ns) {
                        Ok(_) => n += 1,
                        Err(e) => {
                            warn!(error = %e, "arxiv skill-scan: groundtruth::insert failed; skipping fact");
                        }
                    }
                }
                n
            })
            .await
            .unwrap_or(0);

            facts_inserted += inserted;
        }
    }

    Ok(ScanReport {
        topics_queried: topics.len(),
        papers_scanned,
        facts_inserted,
        papers_skipped,
    })
}

/// Extract 1-3 actionable takeaways from a paper abstract via the LLM provider.
///
/// Returns up to 3 non-empty lines from the completion. Returns `Err` if the
/// provider errors or returns no usable lines (caller skips the paper).
async fn extract_learnings(
    provider: &dyn Provider,
    title: &str,
    abstract_text: &str,
) -> Result<Vec<String>> {
    let prompt = format!(
        "List 1-3 concise actionable takeaways from this AI/ML paper for a software developer. \
         One per line, no preamble, no numbering.\n\n\
         Title: {title}\n\nAbstract:\n{abstract_text}\n\nTakeaways:"
    );
    let completion = provider
        .complete(Request {
            prompt,
            ..Default::default()
        })
        .await?;
    let facts: Vec<String> = completion
        .text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .take(3)
        .collect();
    if facts.is_empty() {
        anyhow::bail!("provider returned no takeaways for paper: {title}");
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::groundtruth::{FactState, Source};
    use crate::providers::Completion;
    use async_trait::async_trait;
    use tempfile::tempdir;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Minimal cs.AI Atom feed with one paper.
    const ONE_CS_AI_PAPER: &str = r#"<feed>
<entry>
<id>http://arxiv.org/abs/2506.0001v1</id>
<title>Attention Is All You Need Revisited</title>
<summary>We revisit the transformer architecture and show that attention mechanisms outperform RNNs on sequence tasks with far less data.</summary>
<published>2026-06-01T00:00:00Z</published>
<author><name>Alice Smith</name></author>
<category term="cs.AI" />
</entry>
</feed>"#;

    async fn mock_arxiv_server(atom: &str, status: u16) -> MockServer {
        let srv = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(if status == 200 {
                ResponseTemplate::new(200).set_body_raw(atom.to_string(), "application/atom+xml")
            } else {
                ResponseTemplate::new(status).set_body_string("error")
            })
            .mount(&srv)
            .await;
        srv
    }

    // Provider that returns fixed takeaways.
    struct FixedProvider(String);

    #[async_trait]
    impl Provider for FixedProvider {
        async fn complete(&self, _req: Request) -> Result<Completion> {
            Ok(Completion {
                text: self.0.clone(),
                model: "fixed-test".to_string(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
            })
        }
        fn name(&self) -> &'static str {
            "fixed-test"
        }
    }

    // Provider that always errors.
    struct FailProvider;

    #[async_trait]
    impl Provider for FailProvider {
        async fn complete(&self, _req: Request) -> Result<Completion> {
            anyhow::bail!("test provider always fails")
        }
        fn name(&self) -> &'static str {
            "fail-test"
        }
    }

    fn count_groundtruth_rows(home: &Path, scope: &str, source: &str) -> usize {
        let conn = store::open(&home.join("views.db")).expect("open views.db");
        conn.query_row(
            "SELECT COUNT(*) FROM idx_groundtruth WHERE scope = ?1 AND source_weight LIKE ?2 AND revoked_at IS NULL",
            rusqlite::params![scope, format!("%{source}%")],
            |r| r.get::<_, usize>(0),
        )
        .unwrap_or(0)
    }

    #[tokio::test]
    async fn skill_scan_inserts_groundtruth_rows_for_cs_ai_paper() {
        let dir = tempdir().unwrap();
        // Init the DB (views.db) by opening it — store::open creates tables.
        let _conn = store::open(&dir.path().join("views.db")).unwrap();

        let srv = mock_arxiv_server(ONE_CS_AI_PAPER, 200).await;
        let provider = FixedProvider(
            "Use attention mechanisms for sequence tasks.\nPrefer transformers over RNNs."
                .to_string(),
        );
        let topics = vec!["cat:cs.AI".to_string()];
        let report = run_one_scan_pass(&srv.uri(), dir.path(), &topics, &provider, 10)
            .await
            .unwrap();

        assert_eq!(report.topics_queried, 1);
        assert_eq!(report.papers_scanned, 1);
        assert_eq!(report.papers_skipped, 0);
        assert!(report.facts_inserted >= 1, "expected at least 1 fact inserted");

        let rows = count_groundtruth_rows(dir.path(), "arxiv-learning", "arxiv-skill-scan");
        assert!(rows >= 1, "expected groundtruth rows in arxiv-learning scope");
    }

    #[tokio::test]
    async fn skill_scan_skips_paper_when_provider_fails() {
        let dir = tempdir().unwrap();
        let _conn = store::open(&dir.path().join("views.db")).unwrap();

        let srv = mock_arxiv_server(ONE_CS_AI_PAPER, 200).await;
        let provider = FailProvider;
        let topics = vec!["cat:cs.AI".to_string()];
        let report = run_one_scan_pass(&srv.uri(), dir.path(), &topics, &provider, 10)
            .await
            .unwrap();

        assert_eq!(report.papers_scanned, 1);
        assert_eq!(report.papers_skipped, 1);
        assert_eq!(report.facts_inserted, 0);

        let rows = count_groundtruth_rows(dir.path(), "arxiv-learning", "arxiv-skill-scan");
        assert_eq!(rows, 0, "no rows should be written when provider fails");
    }

    #[tokio::test]
    async fn skill_scan_empty_topics_returns_zero() {
        let dir = tempdir().unwrap();
        let _conn = store::open(&dir.path().join("views.db")).unwrap();

        let provider = FixedProvider("anything".to_string());
        let report = run_one_scan_pass("http://unused", dir.path(), &[], &provider, 10)
            .await
            .unwrap();

        assert_eq!(report.topics_queried, 0);
        assert_eq!(report.papers_scanned, 0);
        assert_eq!(report.facts_inserted, 0);
        assert_eq!(report.papers_skipped, 0);
    }

    #[test]
    fn arxiv_scan_source_has_correct_string() {
        assert_eq!(Source::ArxivScan.as_str(), "arxiv-skill-scan");
        assert!(!Source::ArxivScan.is_operator_attested());
        assert_eq!(Source::ArxivScan.initial_fact_state(), FactState::Candidate);
    }

    #[tokio::test]
    async fn skill_scan_skips_topic_on_non_200() {
        let dir = tempdir().unwrap();
        let _conn = store::open(&dir.path().join("views.db")).unwrap();

        let srv = mock_arxiv_server("", 503).await;
        let provider = FixedProvider("takeaway".to_string());
        let topics = vec!["cat:cs.LG".to_string()];
        let report = run_one_scan_pass(&srv.uri(), dir.path(), &topics, &provider, 10)
            .await
            .unwrap();

        assert_eq!(report.papers_scanned, 0, "503 → topic skipped, no papers");
        assert_eq!(report.facts_inserted, 0);
    }
}
