//! `web_search` — A-20. Provider-agnostic web search.
//!
//! Operator picks one of `brave` / `tavily` / `googlecse` via
//! `freedom.yaml::web_search_provider`. The API key for that provider
//! lives in `credentials.yaml::web_search_key`. NEOTH's
//! `providers::http_client` carries the request, so Hysteria proxy is
//! honoured if configured.
//!
//! Returns a uniform `SearchHit` shape regardless of provider so
//! downstream skills don't have to branch per backend.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::providers::http_client;
use crate::secret::SecretString;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SearchHit {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

#[derive(Clone, Copy, Debug)]
pub enum Provider {
    Brave,
    Tavily,
    /// GOLD-ADAPT-ODY-19 — self-hosted SearXNG meta-search. Free, no API key;
    /// the instance URL comes from `NEOTH_SEARXNG_URL` (default
    /// `http://127.0.0.1:8888`). Removes the paid-API requirement for search.
    SearXng,
}

impl Provider {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "brave" => Some(Provider::Brave),
            "tavily" => Some(Provider::Tavily),
            "searxng" => Some(Provider::SearXng),
            _ => None,
        }
    }

    /// Stable lower-snake label — used as part of the `search_cache` key.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Brave => "brave",
            Provider::Tavily => "tavily",
            Provider::SearXng => "searxng",
        }
    }

    /// Whether this provider needs an API key. SearXNG is keyless (self-hosted).
    pub fn needs_api_key(self) -> bool {
        !matches!(self, Provider::SearXng)
    }
}

/// Run a web search through the configured provider. Returns up to
/// `count` hits (provider may return fewer).
pub async fn search(
    provider: Provider,
    api_key: &SecretString,
    query: &str,
    count: usize,
) -> Result<Vec<SearchHit>> {
    if query.trim().is_empty() {
        anyhow::bail!("web_search: empty query");
    }
    let count = count.clamp(1, 20);
    match provider {
        Provider::Brave => brave_search(api_key, query, count).await,
        Provider::Tavily => tavily_search(api_key, query, count).await,
        Provider::SearXng => searxng_search(query, count).await,
    }
}

/// GOLD-ADAPT-ODY-29 — [`search`] with a disk-backed LRU result cache in
/// front. A repeated `{provider, query, count}` inside the cache TTL is served
/// from `~/.neoth/cache/search/` instead of re-billing the provider. Set
/// `NEOTH_SEARCH_CACHE_DISABLED` (any value) to force a live call + skip the
/// cache entirely. The `count` is clamped the same way [`search`] clamps it, so
/// the cache key matches the request that would actually be issued.
pub async fn search_cached(
    provider: Provider,
    api_key: &SecretString,
    query: &str,
    count: usize,
) -> Result<Vec<SearchHit>> {
    // GOLD-ADAPT-ODY-30 — record every invocation (cache_hit / success / fail)
    // unless analytics are disabled. Best-effort: never breaks a search.
    let analytics_on = std::env::var_os("NEOTH_SEARCH_ANALYTICS_DISABLED").is_none();
    let record = |outcome: crate::tools::search_analytics::Outcome| {
        if analytics_on {
            use crate::tools::search_analytics::SearchAnalytics;
            SearchAnalytics::record_to(&SearchAnalytics::default_path(), query, outcome);
        }
    };
    use crate::tools::search_analytics::Outcome;

    if std::env::var_os("NEOTH_SEARCH_CACHE_DISABLED").is_some() {
        let result = search(provider, api_key, query, count).await;
        record(if result.is_ok() {
            Outcome::Success
        } else {
            Outcome::Fail
        });
        return result;
    }

    let key_count = count.clamp(1, 20);
    let cache = crate::tools::search_cache::SearchCache::at_default();
    let now = crate::tools::search_cache::now_unix_secs();
    if let Some(hits) = cache.get(provider.as_str(), query, key_count, now) {
        tracing::debug!(provider = provider.as_str(), "web_search cache hit");
        record(Outcome::CacheHit);
        return Ok(hits);
    }
    match search(provider, api_key, query, count).await {
        Ok(hits) => {
            record(Outcome::Success);
            if let Err(e) = cache.put(provider.as_str(), query, key_count, &hits, now) {
                tracing::warn!(error = %e, "web_search cache write failed (non-fatal)");
            }
            Ok(hits)
        }
        Err(e) => {
            record(Outcome::Fail);
            Err(e)
        }
    }
}

/// Production Brave Search API endpoint. Lifted to a const so the
/// CDX-04 wiremock tests can override it via `brave_search_against`.
pub const BRAVE_API_URL: &str = "https://api.search.brave.com/res/v1/web/search";

async fn brave_search(api_key: &SecretString, query: &str, count: usize) -> Result<Vec<SearchHit>> {
    brave_search_against(BRAVE_API_URL, api_key, query, count).await
}

/// Internal test seam — production `brave_search` calls this with the
/// real endpoint; wiremock tests pass a mock server's URI.
async fn brave_search_against(
    endpoint: &str,
    api_key: &SecretString,
    query: &str,
    count: usize,
) -> Result<Vec<SearchHit>> {
    let client = http_client::build_client()?;
    let resp = client
        .get(endpoint)
        .header("Accept", "application/json")
        .header("X-Subscription-Token", api_key.expose())
        .query(&[("q", query), ("count", &count.to_string())])
        .send()
        .await
        .context("brave search request")?;
    if !resp.status().is_success() {
        anyhow::bail!("brave search returned {}", resp.status());
    }
    let body: BraveBody = resp.json().await.context("brave search decode")?;
    Ok(body
        .web
        .map(|w| {
            w.results
                .into_iter()
                .map(|r| SearchHit {
                    title: r.title,
                    url: r.url,
                    snippet: r.description.unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default())
}

pub const TAVILY_API_URL: &str = "https://api.tavily.com/search";

async fn tavily_search(
    api_key: &SecretString,
    query: &str,
    count: usize,
) -> Result<Vec<SearchHit>> {
    tavily_search_against(TAVILY_API_URL, api_key, query, count).await
}

async fn tavily_search_against(
    endpoint: &str,
    api_key: &SecretString,
    query: &str,
    count: usize,
) -> Result<Vec<SearchHit>> {
    // Pick #33 (Session 14, security audit-fix Security#3): Tavily's
    // API accepts the key in the JSON body OR as `Authorization: Bearer
    // <key>`. The body form leaves the key in every middleware that
    // captures the request payload (tracing instrumentation, debug
    // logs, intermediate caches). The header form is the standard
    // surface for credentials and keeps the body free of secret.
    let client = http_client::build_client()?;
    let resp = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", api_key.expose()))
        .json(&serde_json::json!({
            "query": query,
            "max_results": count,
            "search_depth": "basic",
        }))
        .send()
        .await
        .context("tavily search request")?;
    if !resp.status().is_success() {
        anyhow::bail!("tavily search returned {}", resp.status());
    }
    let body: TavilyBody = resp.json().await.context("tavily search decode")?;
    Ok(body
        .results
        .into_iter()
        .map(|r| SearchHit {
            title: r.title,
            url: r.url,
            snippet: r.content,
        })
        .collect())
}

/// Default SearXNG instance when `NEOTH_SEARXNG_URL` is unset — the loopback
/// port the docker-compose'd SearXNG binds by convention.
pub const SEARXNG_DEFAULT_URL: &str = "http://127.0.0.1:8888";

async fn searxng_search(query: &str, count: usize) -> Result<Vec<SearchHit>> {
    let base = std::env::var("NEOTH_SEARXNG_URL")
        .unwrap_or_else(|_| SEARXNG_DEFAULT_URL.to_string());
    searxng_search_against(base.trim_end_matches('/'), query, count).await
}

/// Internal test seam — production `searxng_search` calls this with the
/// configured instance; wiremock tests pass a mock server's URI. SearXNG's
/// JSON API: `GET {base}/search?q=…&format=json` → `{ results: [{title, url,
/// content}] }`. No API key (self-hosted). Results are truncated to `count`.
async fn searxng_search_against(
    base: &str,
    query: &str,
    count: usize,
) -> Result<Vec<SearchHit>> {
    let client = http_client::build_client()?;
    let endpoint = format!("{base}/search");
    let resp = client
        .get(&endpoint)
        .header("Accept", "application/json")
        .query(&[("q", query), ("format", "json")])
        .send()
        .await
        .context("searxng search request")?;
    if !resp.status().is_success() {
        anyhow::bail!("searxng search returned {}", resp.status());
    }
    let body: SearxngBody = resp.json().await.context("searxng search decode")?;
    Ok(body
        .results
        .into_iter()
        .take(count)
        .map(|r| SearchHit {
            title: r.title,
            url: r.url,
            snippet: r.content.unwrap_or_default(),
        })
        .collect())
}

#[derive(Deserialize)]
struct SearxngBody {
    #[serde(default)]
    results: Vec<SearxngResult>,
}

#[derive(Deserialize)]
struct SearxngResult {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    /// SearXNG calls the snippet `content`; some engines omit it.
    content: Option<String>,
}

#[derive(Deserialize)]
struct BraveBody {
    web: Option<BraveWeb>,
}

#[derive(Deserialize)]
struct BraveWeb {
    results: Vec<BraveResult>,
}

#[derive(Deserialize)]
struct BraveResult {
    title: String,
    url: String,
    description: Option<String>,
}

#[derive(Deserialize)]
struct TavilyBody {
    results: Vec<TavilyResult>,
}

#[derive(Deserialize)]
struct TavilyResult {
    title: String,
    url: String,
    content: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parses_known_names() {
        assert!(matches!(Provider::from_str("brave"), Some(Provider::Brave)));
        assert!(matches!(
            Provider::from_str("tavily"),
            Some(Provider::Tavily)
        ));
        assert!(matches!(
            Provider::from_str("searxng"),
            Some(Provider::SearXng)
        ));
        assert!(Provider::from_str("unknown").is_none());
    }

    #[test]
    fn searxng_is_keyless_others_need_a_key() {
        assert!(!Provider::SearXng.needs_api_key());
        assert!(Provider::Brave.needs_api_key());
        assert!(Provider::Tavily.needs_api_key());
        assert_eq!(Provider::SearXng.as_str(), "searxng");
    }

    #[tokio::test]
    async fn searxng_decodes_real_response_shape() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .and(query_param("q", "rust async"))
            .and(query_param("format", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    {"title": "Async Book", "url": "https://rust-lang.github.io/async-book/", "content": "Asynchronous Rust."},
                    {"title": "Tokio", "url": "https://tokio.rs/", "content": null},
                    {"title": "Third", "url": "https://example.org/3", "content": "third"}
                ]
            })))
            .mount(&mock)
            .await;
        // count=2 → only the first two results survive the truncation.
        let hits = searxng_search_against(&mock.uri(), "rust async", 2)
            .await
            .unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].title, "Async Book");
        assert_eq!(hits[0].snippet, "Asynchronous Rust.");
        assert_eq!(hits[1].snippet, "", "null content → empty snippet");
    }

    #[tokio::test]
    async fn searxng_propagates_non_2xx_as_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&mock)
            .await;
        let r = searxng_search_against(&mock.uri(), "q", 5).await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("502"));
    }

    #[tokio::test]
    async fn search_rejects_empty_query() {
        let r = search(Provider::Brave, &SecretString::from("dummy"), "", 10).await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("empty"));
    }

    // ── CDX-04: wiremock HTTP round-trip coverage ─────────────────────────

    #[tokio::test]
    async fn brave_decodes_real_response_shape() {
        use wiremock::matchers::{header, method, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("x-subscription-token", "brave-key-123"))
            .and(query_param("q", "rust borrow checker"))
            .and(query_param("count", "5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "web": {
                    "results": [
                        {
                            "title": "The Rust Reference",
                            "url": "https://doc.rust-lang.org/reference/",
                            "description": "Detailed reference on Rust semantics."
                        },
                        {
                            "title": "Borrow Checker Deep Dive",
                            "url": "https://example.org/borrow",
                            "description": null
                        }
                    ]
                }
            })))
            .mount(&mock)
            .await;
        let hits = brave_search_against(
            &mock.uri(),
            &SecretString::from("brave-key-123"),
            "rust borrow checker",
            5,
        )
        .await
        .expect("brave decode");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].title, "The Rust Reference");
        assert_eq!(hits[0].url, "https://doc.rust-lang.org/reference/");
        assert!(hits[0].snippet.contains("semantics"));
        assert_eq!(hits[1].title, "Borrow Checker Deep Dive");
        assert!(hits[1].snippet.is_empty());
    }

    #[tokio::test]
    async fn brave_handles_empty_web_block() {
        // Some queries return `web: null` — the decoder must not panic
        // and just yields an empty Vec.
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "web": null
            })))
            .mount(&mock)
            .await;
        let hits = brave_search_against(&mock.uri(), &SecretString::from("k"), "x", 1)
            .await
            .unwrap();
        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn brave_propagates_non_2xx_as_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
            .mount(&mock)
            .await;
        let err = brave_search_against(&mock.uri(), &SecretString::from("k"), "x", 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("429"));
    }

    #[tokio::test]
    async fn tavily_decodes_real_response_shape() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    {
                        "title": "Tokio Tutorial",
                        "url": "https://tokio.rs/tokio/tutorial",
                        "content": "Async runtime intro."
                    }
                ]
            })))
            .mount(&mock)
            .await;
        let hits = tavily_search_against(
            &mock.uri(),
            &SecretString::from("tavily-key"),
            "tokio tutorial",
            3,
        )
        .await
        .expect("tavily decode");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "Tokio Tutorial");
        assert!(hits[0].snippet.contains("Async runtime"));
    }

    #[tokio::test]
    async fn tavily_propagates_non_2xx_as_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&mock)
            .await;
        let err = tavily_search_against(&mock.uri(), &SecretString::from("k"), "x", 3)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("401"));
    }

    #[test]
    fn provider_url_constants_pinned() {
        // Drift guard — production code targets these exact URLs.
        assert_eq!(
            BRAVE_API_URL,
            "https://api.search.brave.com/res/v1/web/search"
        );
        assert_eq!(TAVILY_API_URL, "https://api.tavily.com/search");
    }
}
