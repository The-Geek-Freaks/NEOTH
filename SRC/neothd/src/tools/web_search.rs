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

#[derive(Clone, Debug, serde::Serialize)]
pub struct SearchHit {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

#[derive(Clone, Debug)]
pub enum Provider {
    Brave,
    Tavily,
}

impl Provider {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "brave" => Some(Provider::Brave),
            "tavily" => Some(Provider::Tavily),
            _ => None,
        }
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
        assert!(Provider::from_str("unknown").is_none());
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
