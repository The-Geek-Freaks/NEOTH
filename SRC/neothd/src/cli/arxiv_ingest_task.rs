//! Background arXiv topic-feed ingest task — EL-02.
//!
//! Wraps the existing [`crate::tools::arxiv`] search tool in a tokio
//! interval task. Each tick, for every operator-curated topic in
//! `freedom.yaml::arxiv.topics`, the task runs the arXiv query, optionally
//! LLM-summarises each abstract, and lands the result in the ctx
//! knowledge store keyed `arxiv:<id>`. Operators then `neoth recall`
//! / `neoth ctx` over the ingested papers like any other indexed doc.
//!
//! Off by default — opt in via `freedom.yaml::arxiv.enabled: true` plus a
//! non-empty `arxiv.topics` list. The interval is operator-tunable
//! (`arxiv.interval_secs`, default 6h). A topic fetch failure logs +
//! skips that topic; a pass failure logs + retries next tick — never
//! crashes the daemon. Summarisation falls back to the raw abstract when
//! no provider is wired or the provider errors (the same L-07 safe-
//! default the dreaming task uses).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::memory::{ctx, store};
use crate::providers::{Provider, Request};
use crate::tools::arxiv::{self, ARXIV_API_URL};

/// Default cadence: every 6h. Anonymous arXiv clients should stay well
/// clear of the API's politeness window; 6h × a handful of topics is
/// negligible load.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Default results fetched per topic per tick. The underlying
/// `arxiv::search` clamps to the API cap of 50.
pub const DEFAULT_MAX_PER_TOPIC: usize = 10;

/// One ingest pass result — operator-visible counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassReport {
    /// Topics queried this pass (the configured list length).
    pub topics_queried: usize,
    /// Papers successfully written to the ctx index.
    pub papers_indexed: usize,
    /// Papers that failed to index (logged + counted, never fatal).
    pub papers_skipped: usize,
}

/// Spawn the ingest task. Returns the `JoinHandle` so the caller can
/// `.abort()` on shutdown.
///
/// `interval = None` → [`DEFAULT_INTERVAL`]. `max_per_topic = None` →
/// [`DEFAULT_MAX_PER_TOPIC`]. `provider = None` → raw abstracts are
/// indexed without summarisation. `source_category = None` → `"arxiv"`.
pub fn spawn(
    home: PathBuf,
    topics: Vec<String>,
    provider: Option<Arc<dyn Provider>>,
    interval: Option<Duration>,
    max_per_topic: Option<usize>,
    source_category: Option<String>,
) -> JoinHandle<Result<()>> {
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    let max_per_topic = max_per_topic.unwrap_or(DEFAULT_MAX_PER_TOPIC);
    let source_category = source_category.unwrap_or_else(|| "arxiv".to_string());
    tokio::spawn(async move {
        run(
            home,
            topics,
            provider,
            interval,
            max_per_topic,
            source_category,
        )
        .await
    })
}

async fn run(
    home: PathBuf,
    topics: Vec<String>,
    provider: Option<Arc<dyn Provider>>,
    interval: Duration,
    max_per_topic: usize,
    source_category: String,
) -> Result<()> {
    info!(
        interval_secs = interval.as_secs(),
        topics = topics.len(),
        max_per_topic,
        provider_enabled = provider.is_some(),
        "arxiv ingest task started"
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — a fresh boot has nothing new to fetch
    // beyond what the prior daemon run already ingested.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match run_one_pass_against(
            ARXIV_API_URL,
            &home,
            &topics,
            provider.as_deref(),
            max_per_topic,
            &source_category,
        )
        .await
        {
            Ok(report) => {
                if report.papers_indexed > 0 || report.papers_skipped > 0 {
                    info!(
                        topics = report.topics_queried,
                        indexed = report.papers_indexed,
                        skipped = report.papers_skipped,
                        "arxiv ingest pass landed papers",
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "arxiv ingest pass failed (will retry next tick)");
            }
        }
    }
}

/// Run one ingest pass. Test seam: `endpoint` lets wiremock tests pass a
/// mock server URI in place of the real arXiv host.
///
/// A topic whose fetch fails is logged + skipped (the other topics still
/// run). A paper whose index write fails is logged + counted in
/// `papers_skipped`. Summarisation failure folds to the raw abstract.
pub async fn run_one_pass_against(
    endpoint: &str,
    home: &Path,
    topics: &[String],
    provider: Option<&dyn Provider>,
    max_per_topic: usize,
    source_category: &str,
) -> Result<PassReport> {
    let db_path = home.join("views.db");
    let mut conn = store::open(&db_path)?;
    let mut indexed = 0usize;
    let mut skipped = 0usize;

    for topic in topics {
        let papers = match arxiv::search_against(endpoint, topic, max_per_topic).await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, topic, "arxiv topic fetch failed; skipping topic");
                continue;
            }
        };
        for paper in papers {
            let summary = match provider {
                Some(p) => summarise_abstract(p, &paper.title, &paper.abstract_text)
                    .await
                    .unwrap_or_else(|_| paper.abstract_text.clone()),
                None => paper.abstract_text.clone(),
            };
            let content = format!(
                "# {}\n\nAuthors: {}\nPublished: {}\nCategories: {}\nPDF: {}\n\n{}",
                paper.title,
                paper.authors.join(", "),
                paper.published,
                paper.categories.join(", "),
                paper.pdf_url,
                summary,
            );
            let req = ctx::IndexRequest {
                label: format!("arxiv:{}", paper.id),
                content,
                file_path: Some(paper.pdf_url.clone()),
                content_type: "prose".to_string(),
                source_category: Some(source_category.to_string()),
                event_id: None,
            };
            match ctx::index_document(&mut conn, &req) {
                Ok(_) => indexed += 1,
                Err(e) => {
                    warn!(error = %e, label = %req.label, "index_document failed; skipping paper");
                    skipped += 1;
                }
            }
        }
    }

    Ok(PassReport {
        topics_queried: topics.len(),
        papers_indexed: indexed,
        papers_skipped: skipped,
    })
}

/// LLM-summarise a single abstract for the knowledge base. Errors
/// propagate so the caller can fall back to the raw abstract.
async fn summarise_abstract(
    provider: &dyn Provider,
    title: &str,
    abstract_text: &str,
) -> Result<String> {
    let prompt = format!(
        "Summarise this arXiv abstract in 2-3 sentences for a software \
         developer's knowledge base. Be factual, no preamble.\n\n\
         Title: {title}\n\nAbstract:\n{abstract_text}\n\nSummary:"
    );
    let completion = provider
        .complete(Request {
            prompt,
            ..Default::default()
        })
        .await?;
    let text = completion.text.trim().to_string();
    if text.is_empty() {
        anyhow::bail!("provider returned an empty summary");
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Completion;
    use async_trait::async_trait;
    use std::time::Duration as StdDuration;
    use tempfile::tempdir;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ONE_PAPER_ATOM: &str = r#"<feed>
<entry>
<id>http://arxiv.org/abs/2024.0042v1</id>
<title>Async Rust in Practice</title>
<summary>A practical guide to async runtimes and their trade-offs.</summary>
<published>2024-04-15T00:00:00Z</published>
<author><name>Carol</name></author>
<category term="cs.PL" />
</entry>
</feed>"#;

    async fn mock_arxiv(atom: &str, status: u16) -> MockServer {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(if status == 200 {
                ResponseTemplate::new(200).set_body_raw(atom.to_string(), "application/atom+xml")
            } else {
                ResponseTemplate::new(status).set_body_string("error")
            })
            .mount(&mock)
            .await;
        mock
    }

    fn label_exists(home: &Path, label: &str) -> bool {
        let conn = store::open(&home.join("views.db")).expect("open views.db");
        conn.query_row(
            "SELECT COUNT(*) FROM sources WHERE label = ?1",
            [label],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false)
    }

    /// Count indexed chunks whose body matches a LIKE pattern. The ctx
    /// store chunks `content` into the `chunks` FTS table, so a paper's
    /// summary/abstract lands in a chunk body.
    fn count_chunks_like(home: &Path, pattern: &str) -> i64 {
        let conn = store::open(&home.join("views.db")).expect("open views.db");
        conn.query_row(
            "SELECT COUNT(*) FROM chunks WHERE content LIKE ?1",
            [pattern],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
    }

    /// A provider that always returns a fixed summary.
    struct FixedSummaryProvider(&'static str);
    #[async_trait]
    impl Provider for FixedSummaryProvider {
        fn name(&self) -> &'static str {
            "fixed-summary-mock"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            Ok(Completion {
                text: self.0.to_string(),
                model: "mock".to_string(),
                latency: StdDuration::from_millis(0),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    /// A provider that always errors — exercises the raw-abstract fallback.
    struct FailingProvider;
    #[async_trait]
    impl Provider for FailingProvider {
        fn name(&self) -> &'static str {
            "failing-mock"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            anyhow::bail!("provider unavailable")
        }
    }

    #[tokio::test]
    async fn empty_topics_returns_zero_no_network() {
        let dir = tempdir().unwrap();
        let report =
            run_one_pass_against("http://unused.invalid", dir.path(), &[], None, 10, "arxiv")
                .await
                .expect("pass ok");
        assert_eq!(report.topics_queried, 0);
        assert_eq!(report.papers_indexed, 0);
        assert_eq!(report.papers_skipped, 0);
    }

    #[tokio::test]
    async fn indexes_single_paper_without_provider() {
        let dir = tempdir().unwrap();
        let mock = mock_arxiv(ONE_PAPER_ATOM, 200).await;
        let report = run_one_pass_against(
            &mock.uri(),
            dir.path(),
            &["all:async rust".to_string()],
            None,
            10,
            "arxiv",
        )
        .await
        .expect("pass ok");
        assert_eq!(report.topics_queried, 1);
        assert_eq!(report.papers_indexed, 1);
        assert!(label_exists(
            dir.path(),
            "arxiv:http://arxiv.org/abs/2024.0042v1"
        ));
    }

    #[tokio::test]
    async fn uses_provider_summary_when_available() {
        let dir = tempdir().unwrap();
        let mock = mock_arxiv(ONE_PAPER_ATOM, 200).await;
        let provider = FixedSummaryProvider("LLM-CONDENSED-SUMMARY.");
        run_one_pass_against(
            &mock.uri(),
            dir.path(),
            &["all:x".to_string()],
            Some(&provider),
            10,
            "arxiv",
        )
        .await
        .expect("pass ok");
        assert!(
            count_chunks_like(dir.path(), "%LLM-CONDENSED-SUMMARY.%") >= 1,
            "indexed content must carry the provider summary"
        );
    }

    #[tokio::test]
    async fn falls_back_to_raw_abstract_when_provider_fails() {
        let dir = tempdir().unwrap();
        let mock = mock_arxiv(ONE_PAPER_ATOM, 200).await;
        let provider = FailingProvider;
        run_one_pass_against(
            &mock.uri(),
            dir.path(),
            &["all:x".to_string()],
            Some(&provider),
            10,
            "arxiv",
        )
        .await
        .expect("pass ok");
        assert!(
            count_chunks_like(dir.path(), "%practical guide to async runtimes%") >= 1,
            "fallback must index the raw abstract"
        );
    }

    #[tokio::test]
    async fn non_2xx_arxiv_skips_topic_no_panic() {
        let dir = tempdir().unwrap();
        let mock = mock_arxiv("", 503).await;
        let report = run_one_pass_against(
            &mock.uri(),
            dir.path(),
            &["all:x".to_string()],
            None,
            10,
            "arxiv",
        )
        .await
        .expect("pass is fail-soft");
        assert_eq!(report.topics_queried, 1);
        assert_eq!(report.papers_indexed, 0);
    }

    #[tokio::test]
    async fn reindex_same_paper_indexes_once_per_pass() {
        let dir = tempdir().unwrap();
        let mock = mock_arxiv(ONE_PAPER_ATOM, 200).await;
        let topics = vec!["all:x".to_string()];
        let first = run_one_pass_against(&mock.uri(), dir.path(), &topics, None, 10, "arxiv")
            .await
            .unwrap();
        let second = run_one_pass_against(&mock.uri(), dir.path(), &topics, None, 10, "arxiv")
            .await
            .unwrap();
        assert_eq!(first.papers_indexed, 1);
        assert_eq!(second.papers_indexed, 1);
    }

    #[test]
    fn config_default_is_off_and_empty() {
        let c = crate::config::ArxivIngestConfig::default();
        assert!(!c.enabled);
        assert!(c.topics.is_empty());
        assert!(c.interval_secs.is_none());
        assert!(c.max_per_topic.is_none());
    }

    #[test]
    fn config_round_trips_via_yaml() {
        let yaml = r#"
enabled: true
interval_secs: 3600
topics:
  - "cat:cs.CL"
  - "all:rag"
max_per_topic: 5
source_category: "research"
"#;
        let c: crate::config::ArxivIngestConfig = serde_yaml::from_str(yaml).expect("parse");
        assert!(c.enabled);
        assert_eq!(c.interval_secs, Some(3600));
        assert_eq!(
            c.topics,
            vec!["cat:cs.CL".to_string(), "all:rag".to_string()]
        );
        assert_eq!(c.max_per_topic, Some(5));
        assert_eq!(c.source_category.as_deref(), Some("research"));
    }
}
