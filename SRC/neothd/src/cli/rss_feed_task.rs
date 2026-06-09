//! GOLD-ADOPT-26 — RSS / Atom / JSON-Feed poller cron.
//!
//! When `freedom.yaml::feeds.enabled = true` AND `feeds.entries` is non-empty,
//! this task polls each configured feed URL on a cadence (default 1h), parses
//! new entries via `feed-rs`, and lands each entry in the ctx knowledge store
//! keyed `rss:<label>:<entry_id_hash>`. The poller:
//!
//!   - Validates each feed URL via `tools::web_fetch::validate_url` (SSRF
//!     guard) before every HTTP GET. A URL that fails validation is logged +
//!     skipped; the other feeds still run.
//!   - Parses the body with `feed_rs::parser::parse` (pure-Rust; handles
//!     RSS 0.9x/1.0/2.0, Atom 0.3/1.0, JSON Feed 1.x — any format `feed-rs`
//!     supports). A parse failure logs + skips that feed.
//!   - Caps per-feed entries at `max_entries` (default 20) so a high-volume
//!     feed can't flood the ctx store in one tick.
//!   - Emits `0x4E RSS_FEED_ITEM_INDEXED` per successful ctx write (metadata
//!     only — title + id are hashed, never stored verbatim in the WAL frame).
//!   - Emits `0x4F RSS_FEED_PASS_COMPLETE` once per full sweep.
//!   - Off by default. Zero cost / zero network for a fresh install.
//!
//! **Cron pattern**: mirrors `cli/arxiv_ingest_task.rs` (burns the first tick
//! so a fresh boot doesn't fetch immediately, then runs on the interval). A
//! pass failure logs + retries next tick — never crashes the daemon.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::FeedEntry;
use crate::memory::{ctx, store};
use crate::wal::events::{EVENT_TYPE_RSS_FEED_ITEM_INDEXED, EVENT_TYPE_RSS_FEED_PASS_COMPLETE};
use crate::wal::writer::WalWriterHandle;
use crate::wal::HeaderBuilder;

/// Default cadence: every 1 hour. Well-mannered for most public feeds.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Default max entries ingested per feed per tick. Cap prevents a firehose
/// feed from flooding the ctx store on the first poll.
pub const DEFAULT_MAX_ENTRIES: usize = 20;

/// One pass result — counters surfaced in `0x4F RSS_FEED_PASS_COMPLETE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RssFeedPassReport {
    /// Number of feed entries checked (feed list length × entries fetched).
    pub feeds_checked: usize,
    /// Entries successfully written to the ctx knowledge store.
    pub entries_indexed: usize,
    /// Entries that failed to parse or index (logged + counted, never fatal).
    pub entries_skipped: usize,
}

/// Spawn the RSS feed poller. Returns the `JoinHandle` so `serve.rs` can
/// `.abort()` on shutdown.
///
/// `interval = None` → [`DEFAULT_INTERVAL`].
pub fn spawn(
    home: PathBuf,
    entries: Vec<FeedEntry>,
    interval: Option<Duration>,
    writer: WalWriterHandle,
) -> JoinHandle<Result<()>> {
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    tokio::spawn(async move { run(home, entries, interval, writer).await })
}

async fn run(
    home: PathBuf,
    entries: Vec<FeedEntry>,
    interval: Duration,
    writer: WalWriterHandle,
) -> Result<()> {
    info!(
        interval_secs = interval.as_secs(),
        feeds = entries.len(),
        "rss feed poller started"
    );
    let client = crate::providers::http_client::build_client()
        .context("rss_feed_task: build reqwest client")?;
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — a fresh boot has nothing new to fetch
    // beyond what the prior daemon run already ingested.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match run_one_pass_against(&home, &entries, &writer, &client).await {
            Ok(report) => {
                emit_pass_complete(&writer, &report);
                if report.entries_indexed > 0 || report.entries_skipped > 0 {
                    info!(
                        feeds = report.feeds_checked,
                        indexed = report.entries_indexed,
                        skipped = report.entries_skipped,
                        "rss feed pass complete"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "rss feed pass failed (will retry next tick)");
            }
        }
    }
}

/// Run one ingest pass. Test seam: `http` is injected so tests can pass a
/// client pre-configured to point at a wiremock server.
pub async fn run_one_pass_against(
    home: &Path,
    entries: &[FeedEntry],
    writer: &WalWriterHandle,
    http: &reqwest::Client,
) -> Result<RssFeedPassReport> {
    let db_path = home.join("views.db");
    let mut conn = store::open(&db_path).context("rss_feed_task: open views.db")?;
    let mut indexed = 0usize;
    let mut skipped = 0usize;

    for entry in entries {
        // SSRF guard: validate the operator-supplied feed URL before the GET.
        if let Err(e) = crate::tools::web_fetch::validate_url(&entry.url).await {
            warn!(url = %entry.url, label = %entry.label, error = %e,
                  "rss feed: URL failed SSRF validation — skipping feed");
            skipped += 1;
            continue;
        }

        let body = match http.get(&entry.url).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(url = %entry.url, label = %entry.label,
                          status = %resp.status(), "rss feed: non-2xx — skipping");
                    skipped += 1;
                    continue;
                }
                match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(error = %e, label = %entry.label, "rss feed: read body failed");
                        skipped += 1;
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, label = %entry.label, "rss feed: GET failed");
                skipped += 1;
                continue;
            }
        };

        let feed = match feed_rs::parser::parse(body.as_ref()) {
            Ok(f) => f,
            Err(e) => {
                warn!(error = %e, label = %entry.label, url = %entry.url,
                      "rss feed: parse failed — skipping feed");
                skipped += 1;
                continue;
            }
        };

        let max = entry.max_entries.unwrap_or(DEFAULT_MAX_ENTRIES);
        for item in feed.entries.iter().take(max) {
            // Stable per-entry key (becomes the `rss:<label>:<hash>` ctx label,
            // which is the dedup key — index_document REPLACES by label).
            // Preference: feed GUID → first link href → a CONTENT hash. The last
            // fallback is load-bearing: a feed whose entries carry NEITHER a
            // guid NOR a link would otherwise all hash `""` → collapse onto one
            // label → every entry but the last is silently lost each pass.
            let entry_id_fallback;
            let entry_id: &str = if !item.id.is_empty() {
                item.id.as_str()
            } else if let Some(href) = item
                .links
                .first()
                .map(|l| l.href.as_str())
                .filter(|h| !h.is_empty())
            {
                href
            } else {
                let t = item.title.as_ref().map(|t| t.content.as_str()).unwrap_or("");
                let p = item.published.map(|d| d.to_rfc3339()).unwrap_or_default();
                let s = item.summary.as_ref().map(|s| s.content.as_str()).unwrap_or("");
                // `\u{1f}` (unit separator) keeps the three fields unambiguous.
                entry_id_fallback = format!("content:{t}\u{1f}{p}\u{1f}{s}");
                entry_id_fallback.as_str()
            };
            let title = item
                .title
                .as_ref()
                .map(|t| t.content.as_str())
                .unwrap_or("(no title)");
            let summary = item
                .summary
                .as_ref()
                .map(|s| s.content.as_str())
                .unwrap_or("")
                .to_string();
            let content_text = item
                .content
                .as_ref()
                .and_then(|c| c.body.as_deref())
                .unwrap_or("");

            let text = if !content_text.is_empty() {
                content_text.to_string()
            } else {
                summary.clone()
            };

            let entry_id_hash =
                format!("{:016x}", xxhash_rust::xxh3::xxh3_64(entry_id.as_bytes()));
            let ctx_key = format!("rss:{}:{}", entry.label, entry_id_hash);

            let link = item
                .links
                .first()
                .map(|l| l.href.as_str())
                .unwrap_or(&entry.url);

            let published = item
                .published
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();

            let content = format!(
                "# {title}\n\nSource: {}\nPublished: {}\nLink: {}\n\n{}",
                entry.label, published, link, text,
            );

            let req = ctx::IndexRequest {
                label: ctx_key.clone(),
                content,
                file_path: Some(link.to_string()),
                content_type: "prose".to_string(),
                source_category: Some(format!("rss:{}", entry.label)),
                event_id: None,
            };
            match ctx::index_document(&mut conn, &req) {
                Ok(_) => {
                    emit_item_indexed(writer, &entry.label, &entry_id_hash, title, &ctx_key);
                    indexed += 1;
                }
                Err(e) => {
                    warn!(error = %e, ctx_key, "rss feed: index_document failed");
                    skipped += 1;
                }
            }
        }
    }

    Ok(RssFeedPassReport {
        feeds_checked: entries.len(),
        entries_indexed: indexed,
        entries_skipped: skipped,
    })
}

/// Emit `0x4E RSS_FEED_ITEM_INDEXED`. Best-effort — errors are logged but
/// never propagate; the ctx write already succeeded.
fn emit_item_indexed(
    writer: &WalWriterHandle,
    feed_label: &str,
    entry_id_hash: &str,
    title: &str,
    ctx_key: &str,
) {
    let title_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(title.as_bytes()));
    let payload = serde_json::to_vec(&serde_json::json!({
        "feed_label": feed_label,
        "entry_id_hash": entry_id_hash,
        "title_hash": title_hash,
        "ctx_key": ctx_key,
        "ts_unix": now_unix(),
    }))
    .unwrap_or_default();
    let header = HeaderBuilder::new(EVENT_TYPE_RSS_FEED_ITEM_INDEXED, &payload).build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "rss feed: 0x4E append failed (audit gap)");
    }
}

/// Emit `0x4F RSS_FEED_PASS_COMPLETE`. Best-effort.
fn emit_pass_complete(writer: &WalWriterHandle, report: &RssFeedPassReport) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "feeds_checked": report.feeds_checked,
        "entries_indexed": report.entries_indexed,
        "entries_skipped": report.entries_skipped,
        "ts_unix": now_unix(),
    }))
    .unwrap_or_default();
    let header = HeaderBuilder::new(EVENT_TYPE_RSS_FEED_PASS_COMPLETE, &payload).build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "rss feed: 0x4F append failed (audit gap)");
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FeedEntry;
    use tempfile::tempdir;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Minimal RSS 2.0 feed with one item.
    const RSS2_ONE_ITEM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <link>https://example.com</link>
    <description>Unit test feed</description>
    <item>
      <title>First Post</title>
      <link>https://example.com/1</link>
      <guid>https://example.com/1</guid>
      <description>Hello from RSS</description>
      <pubDate>Mon, 01 Jan 2024 00:00:00 +0000</pubDate>
    </item>
  </channel>
</rss>"#;

    // Minimal Atom 1.0 feed with one entry.
    const ATOM_ONE_ENTRY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Test</title>
  <id>https://example.com/atom</id>
  <updated>2024-01-01T00:00:00Z</updated>
  <entry>
    <id>https://example.com/atom/1</id>
    <title>Atom Entry</title>
    <link href="https://example.com/atom/1"/>
    <summary>Hello from Atom</summary>
    <updated>2024-01-01T00:00:00Z</updated>
  </entry>
</feed>"#;

    async fn mock_feed(xml: &str, status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(if status == 200 {
                ResponseTemplate::new(200)
                    .set_body_string(xml)
                    .insert_header("content-type", "application/rss+xml; charset=utf-8")
            } else {
                ResponseTemplate::new(status).set_body_string("error")
            })
            .mount(&server)
            .await;
        server
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

    fn make_wal(home: &Path) -> (WalWriterHandle, tokio::task::JoinHandle<()>) {
        crate::wal::writer::spawn(home.join("000001.wal")).unwrap()
    }

    #[tokio::test]
    async fn empty_feed_list_no_network() {
        let dir = tempdir().unwrap();
        let (writer, join) = make_wal(dir.path());
        let client = reqwest::Client::new();
        let report = run_one_pass_against(dir.path(), &[], &writer, &client)
            .await
            .expect("pass ok");
        assert_eq!(report.feeds_checked, 0);
        assert_eq!(report.entries_indexed, 0);
        assert_eq!(report.entries_skipped, 0);
        drop(writer);
        join.await.ok();
    }

    #[tokio::test]
    async fn indexes_rss2_entry() {
        let _loopback = crate::tools::web_fetch::test_overrides::LoopbackGuard::enable();
        let dir = tempdir().unwrap();
        let server = mock_feed(RSS2_ONE_ITEM, 200).await;
        let (writer, join) = make_wal(dir.path());
        let client = reqwest::Client::new();
        let entries = vec![FeedEntry {
            label: "test_rss".to_string(),
            url: server.uri(),
            max_entries: None,
        }];
        let report = run_one_pass_against(dir.path(), &entries, &writer, &client)
            .await
            .expect("pass ok");
        assert_eq!(report.feeds_checked, 1);
        assert_eq!(report.entries_indexed, 1);
        assert_eq!(report.entries_skipped, 0);
        // Verify ctx row key is present
        let entry_id = "https://example.com/1";
        let entry_id_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(entry_id.as_bytes()));
        let ctx_key = format!("rss:test_rss:{entry_id_hash}");
        assert!(label_exists(dir.path(), &ctx_key), "ctx row must exist: {ctx_key}");
        drop(writer);
        join.await.ok();
    }

    #[tokio::test]
    async fn indexes_atom_entry() {
        let _loopback = crate::tools::web_fetch::test_overrides::LoopbackGuard::enable();
        let dir = tempdir().unwrap();
        let server = mock_feed(ATOM_ONE_ENTRY, 200).await;
        let (writer, join) = make_wal(dir.path());
        let client = reqwest::Client::new();
        let entries = vec![FeedEntry {
            label: "test_atom".to_string(),
            url: server.uri(),
            max_entries: None,
        }];
        let report = run_one_pass_against(dir.path(), &entries, &writer, &client)
            .await
            .expect("pass ok");
        assert_eq!(report.entries_indexed, 1);
        drop(writer);
        join.await.ok();
    }

    #[tokio::test]
    async fn non_2xx_feed_skips_no_panic() {
        let _loopback = crate::tools::web_fetch::test_overrides::LoopbackGuard::enable();
        let dir = tempdir().unwrap();
        let server = mock_feed("", 503).await;
        let (writer, join) = make_wal(dir.path());
        let client = reqwest::Client::new();
        let entries = vec![FeedEntry {
            label: "bad_feed".to_string(),
            url: server.uri(),
            max_entries: None,
        }];
        let report = run_one_pass_against(dir.path(), &entries, &writer, &client)
            .await
            .expect("pass is fail-soft");
        assert_eq!(report.feeds_checked, 1);
        assert_eq!(report.entries_indexed, 0);
        assert_eq!(report.entries_skipped, 1);
        drop(writer);
        join.await.ok();
    }

    #[tokio::test]
    async fn duplicate_entry_on_second_pass_upserts() {
        let _loopback = crate::tools::web_fetch::test_overrides::LoopbackGuard::enable();
        let dir = tempdir().unwrap();
        let server = mock_feed(RSS2_ONE_ITEM, 200).await;
        let (writer, join) = make_wal(dir.path());
        let client = reqwest::Client::new();
        let entries = vec![FeedEntry {
            label: "dup_test".to_string(),
            url: server.uri(),
            max_entries: None,
        }];
        let first = run_one_pass_against(dir.path(), &entries, &writer, &client)
            .await
            .unwrap();
        let second = run_one_pass_against(dir.path(), &entries, &writer, &client)
            .await
            .unwrap();
        // Both passes complete; upsert semantics mean no error on re-index.
        assert_eq!(first.entries_indexed, 1);
        assert_eq!(second.entries_indexed, 1);
        // Still only one source row (upsert, not insert).
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sources WHERE label LIKE 'rss:dup_test:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "upsert must not duplicate source rows");
        drop(writer);
        join.await.ok();
    }

    #[tokio::test]
    async fn entries_without_guid_or_link_do_not_collide() {
        let _loopback = crate::tools::web_fetch::test_overrides::LoopbackGuard::enable();
        // Two RSS items with NO <guid> and NO <link> — only title/description.
        // Pre-fix both hashed `""` → one colliding ctx label → silent data loss.
        // Post-fix each gets a distinct content-derived key → both indexed.
        let feed = r#"<?xml version="1.0"?><rss version="2.0"><channel>
            <title>No-ID Feed</title><link>https://example.com</link>
            <description>items without guid or link</description>
            <item><title>Alpha post</title><description>body alpha</description></item>
            <item><title>Beta post</title><description>body beta</description></item>
            </channel></rss>"#;
        let dir = tempdir().unwrap();
        let server = mock_feed(feed, 200).await;
        let (writer, join) = make_wal(dir.path());
        let client = reqwest::Client::new();
        let entries = vec![FeedEntry {
            label: "noid".to_string(),
            url: server.uri(),
            max_entries: None,
        }];
        let report = run_one_pass_against(dir.path(), &entries, &writer, &client)
            .await
            .unwrap();
        assert_eq!(report.entries_indexed, 2, "both id-less entries must index distinctly");
        let conn = store::open(&dir.path().join("views.db")).unwrap();
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sources WHERE label LIKE 'rss:noid:%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2, "distinct content → distinct labels, no collision");
        drop(writer);
        join.await.ok();
    }

    #[tokio::test]
    async fn max_entries_caps_indexing() {
        let _loopback = crate::tools::web_fetch::test_overrides::LoopbackGuard::enable();
        // Build a feed with 5 items.
        let items: String = (1..=5)
            .map(|i| {
                format!(
                    "<item><title>Post {i}</title><guid>https://example.com/{i}</guid>\
                     <description>body {i}</description></item>"
                )
            })
            .collect();
        let feed = format!(
            r#"<?xml version="1.0"?><rss version="2.0"><channel>
            <title>Big Feed</title><link>https://example.com</link>
            <description>many items</description>
            {items}
            </channel></rss>"#
        );
        let dir = tempdir().unwrap();
        let server = mock_feed(&feed, 200).await;
        let (writer, join) = make_wal(dir.path());
        let client = reqwest::Client::new();
        let entries = vec![FeedEntry {
            label: "capped".to_string(),
            url: server.uri(),
            max_entries: Some(2), // only want 2
        }];
        let report = run_one_pass_against(dir.path(), &entries, &writer, &client)
            .await
            .unwrap();
        assert_eq!(report.entries_indexed, 2, "max_entries cap must be respected");
        drop(writer);
        join.await.ok();
    }

    #[test]
    fn config_default_is_off_and_empty() {
        let c = crate::config::FeedsConfig::default();
        assert!(!c.enabled);
        assert!(c.entries.is_empty());
        assert!(c.interval_secs.is_none());
    }

    #[test]
    fn config_round_trips_via_yaml() {
        let yaml = r#"
enabled: true
interval_secs: 1800
entries:
  - label: hn
    url: https://news.ycombinator.com/rss
  - label: rust_blog
    url: https://blog.rust-lang.org/feed.xml
    max_entries: 5
"#;
        let c: crate::config::FeedsConfig = serde_yaml::from_str(yaml).expect("parse");
        assert!(c.enabled);
        assert_eq!(c.interval_secs, Some(1800));
        assert_eq!(c.entries.len(), 2);
        assert_eq!(c.entries[0].label, "hn");
        assert_eq!(c.entries[1].max_entries, Some(5));
    }

    #[tokio::test]
    async fn wal_0x4e_emitted_on_index() {
        let _loopback = crate::tools::web_fetch::test_overrides::LoopbackGuard::enable();
        let dir = tempdir().unwrap();
        let server = mock_feed(RSS2_ONE_ITEM, 200).await;
        let wal_path = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::writer::spawn(wal_path.clone()).unwrap();
        let client = reqwest::Client::new();
        let entries = vec![FeedEntry {
            label: "wal_test".to_string(),
            url: server.uri(),
            max_entries: None,
        }];
        run_one_pass_against(dir.path(), &entries, &writer, &client)
            .await
            .unwrap();
        drop(writer);
        join.await.ok();

        // Scan the WAL segment for a 0x4E frame.
        let bytes = std::fs::read(&wal_path).unwrap();
        let mut cur = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut found_item = false;
        while cur < bytes.len() {
            let Ok(f) = crate::wal::frame::decode_frame(&bytes[cur..]) else {
                break;
            };
            if f.header.event_type == EVENT_TYPE_RSS_FEED_ITEM_INDEXED {
                found_item = true;
                let p: serde_json::Value = serde_json::from_slice(f.payload).unwrap();
                assert_eq!(p["feed_label"], "wal_test");
                // Raw title must NOT be in the WAL frame — only the hash.
                assert!(!p.to_string().contains("First Post"), "raw title must not be in WAL");
            }
            let t = f.header.total_len as usize;
            if t == 0 {
                break;
            }
            cur += t;
        }
        assert!(found_item, "a 0x4E RSS_FEED_ITEM_INDEXED frame must be present");
    }

    // Compile-time pin: both RSS codes live in the `0x40..=0x4F` cron band and
    // are distinct. A future edit that moves them out of band fails the build.
    const _: () = {
        assert!(EVENT_TYPE_RSS_FEED_ITEM_INDEXED >= 0x40 && EVENT_TYPE_RSS_FEED_ITEM_INDEXED <= 0x4F);
        assert!(EVENT_TYPE_RSS_FEED_PASS_COMPLETE >= 0x40 && EVENT_TYPE_RSS_FEED_PASS_COMPLETE <= 0x4F);
        assert!(EVENT_TYPE_RSS_FEED_ITEM_INDEXED != EVENT_TYPE_RSS_FEED_PASS_COMPLETE);
    };
}
