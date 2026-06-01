//! ArXiv search + retrieval (A-24).
//!
//! Public XML API at `http://export.arxiv.org/api/query` — no API
//! key, no rate-limit surprise. Operator queries by keyword + gets
//! back a structured `Vec<ArxivPaper>` with title, authors, abstract,
//! pdf url. Downstream skills can `neoth fetch <pdf_url>` + run the
//! existing `media::pdf` extractor to land the paper text in recall.
//!
//! Included for research-workflow value — high value, low build cost.

use anyhow::{Context, Result};

use crate::providers::http_client;

#[derive(Clone, Debug, serde::Serialize)]
pub struct ArxivPaper {
    pub id: String,
    pub title: String,
    pub authors: Vec<String>,
    pub abstract_text: String,
    pub pdf_url: String,
    pub published: String,
    pub categories: Vec<String>,
}

/// Production ArXiv Atom endpoint. Lifted to a const so the CDX-04
/// wiremock tests can override it via `search_against`.
pub const ARXIV_API_URL: &str = "http://export.arxiv.org/api/query";

/// Query the ArXiv API + return up to `max_results` matches. Most
/// recent first. ArXiv's search query syntax: `all:keyword`,
/// `ti:title`, `au:author`, `cat:cs.CL`, `AND` / `OR` / `ANDNOT`.
pub async fn search(query: &str, max_results: usize) -> Result<Vec<ArxivPaper>> {
    search_against(ARXIV_API_URL, query, max_results).await
}

/// Internal test seam — production `search` calls this with the real
/// ArXiv endpoint; wiremock tests pass a mock server's URI. `pub(crate)`
/// so the EL-02 ingest task (`cli::arxiv_ingest_task`) can drive it
/// against a mock endpoint in its own wiremock tests.
pub(crate) async fn search_against(
    endpoint: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<ArxivPaper>> {
    if query.trim().is_empty() {
        anyhow::bail!("arxiv: empty query");
    }
    let max = max_results.clamp(1, 50);
    let url = format!(
        "{endpoint}?search_query={}&start=0&max_results={}&sortBy=submittedDate&sortOrder=descending",
        urlencode(query),
        max
    );
    let client = http_client::build_client()?;
    let resp = client
        .get(&url)
        .header("User-Agent", "NEOTH-arxiv/0.1")
        .send()
        .await
        .context("arxiv API request")?;
    if !resp.status().is_success() {
        anyhow::bail!("arxiv API returned {}", resp.status());
    }
    let body = resp.text().await.context("arxiv body read")?;
    parse_atom(&body)
}

/// Minimal Atom XML parser scoped to ArXiv's response shape. We pull
/// out `<entry>` blocks then regex-extract the fields we care about.
/// No XML lib dep — the response is well-formed enough that a
/// targeted scan is reliable for v0.1.x. Operators who hit a parse
/// edge case can opt into a future `quick-xml`-based path (Phase 2).
fn parse_atom(xml: &str) -> Result<Vec<ArxivPaper>> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<entry>") {
        rest = &rest[start + "<entry>".len()..];
        let Some(end) = rest.find("</entry>") else {
            break;
        };
        let block = &rest[..end];
        rest = &rest[end + "</entry>".len()..];
        let id = inner(block, "<id>", "</id>").unwrap_or_default();
        let title = inner(block, "<title>", "</title>")
            .unwrap_or_default()
            .trim()
            .replace('\n', " ");
        let abstract_text = inner(block, "<summary>", "</summary>")
            .unwrap_or_default()
            .trim()
            .to_string();
        let published = inner(block, "<published>", "</published>").unwrap_or_default();
        let authors = inner_all(block, "<name>", "</name>");
        let categories = inner_all_attr(block, "<category", "term=\"", "\"");
        let pdf_url = id
            .replace("abs", "pdf")
            .strip_suffix("v1")
            .map(|s| format!("{s}.pdf"))
            .unwrap_or_else(|| format!("{id}.pdf"));
        out.push(ArxivPaper {
            id,
            title,
            authors,
            abstract_text,
            pdf_url,
            published,
            categories,
        });
    }
    Ok(out)
}

fn inner(haystack: &str, open: &str, close: &str) -> Option<String> {
    let s = haystack.find(open)? + open.len();
    let e = haystack[s..].find(close)?;
    Some(haystack[s..s + e].to_string())
}

fn inner_all(haystack: &str, open: &str, close: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = haystack;
    while let Some(s) = rest.find(open) {
        let from = s + open.len();
        let Some(e) = rest[from..].find(close) else {
            break;
        };
        out.push(rest[from..from + e].trim().to_string());
        rest = &rest[from + e..];
    }
    out
}

fn inner_all_attr(
    haystack: &str,
    tag_prefix: &str,
    attr_open: &str,
    attr_close: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = haystack;
    while let Some(s) = rest.find(tag_prefix) {
        rest = &rest[s + tag_prefix.len()..];
        let Some(attr_s) = rest.find(attr_open) else {
            break;
        };
        let from = attr_s + attr_open.len();
        let Some(e) = rest[from..].find(attr_close) else {
            break;
        };
        out.push(rest[from..from + e].to_string());
        rest = &rest[from + e..];
    }
    out
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_basics() {
        assert_eq!(urlencode("foo bar"), "foo+bar");
        assert_eq!(urlencode("cat:cs.CL"), "cat%3Acs.CL");
        assert_eq!(urlencode("abc-123_xyz.test"), "abc-123_xyz.test");
    }

    #[test]
    fn parse_atom_extracts_entry() {
        let xml = r#"<feed>
<entry>
<id>http://arxiv.org/abs/2024.0001v1</id>
<title>A Test Paper Title</title>
<summary>The abstract goes here.</summary>
<published>2024-01-01T00:00:00Z</published>
<author><name>Alice</name></author>
<author><name>Bob</name></author>
<category term="cs.CL" />
<category term="cs.AI" />
</entry>
</feed>"#;
        let papers = parse_atom(xml).expect("parse ok");
        assert_eq!(papers.len(), 1);
        let p = &papers[0];
        assert_eq!(p.title, "A Test Paper Title");
        assert_eq!(p.abstract_text, "The abstract goes here.");
        assert_eq!(p.authors, vec!["Alice".to_string(), "Bob".to_string()]);
        assert_eq!(p.categories, vec!["cs.CL".to_string(), "cs.AI".to_string()]);
        assert!(p.pdf_url.contains("2024.0001"));
        assert!(p.pdf_url.ends_with(".pdf"));
    }

    #[test]
    fn parse_atom_empty_feed_returns_empty() {
        let xml = r#"<feed></feed>"#;
        let papers = parse_atom(xml).expect("parse ok");
        assert!(papers.is_empty());
    }

    #[tokio::test]
    async fn search_rejects_empty_query() {
        let err = search("", 10).await.unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    // ── CDX-04: wiremock HTTP round-trip coverage ─────────────────────────

    #[tokio::test]
    async fn search_decodes_real_atom_feed_via_http() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        let atom = r#"<feed>
<entry>
<id>http://arxiv.org/abs/2024.0042v1</id>
<title>Async Rust in Practice</title>
<summary>A practical guide to async runtimes.</summary>
<published>2024-04-15T00:00:00Z</published>
<author><name>Carol</name></author>
<category term="cs.PL" />
</entry>
</feed>"#;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(atom.to_string(), "application/atom+xml"),
            )
            .mount(&mock)
            .await;
        let papers = search_against(&mock.uri(), "all:async rust", 3)
            .await
            .expect("arxiv decode");
        assert_eq!(papers.len(), 1);
        assert_eq!(papers[0].title, "Async Rust in Practice");
        assert_eq!(papers[0].authors, vec!["Carol".to_string()]);
        assert!(papers[0].pdf_url.contains("2024.0042"));
    }

    #[tokio::test]
    async fn search_propagates_non_2xx_as_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503).set_body_string("service unavailable"))
            .mount(&mock)
            .await;
        let err = search_against(&mock.uri(), "x", 1).await.unwrap_err();
        assert!(err.to_string().contains("503"));
    }

    #[tokio::test]
    async fn search_clamps_max_results_to_50() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        // We pass 200; the request URL is inspected via wiremock's
        // request log after the call to assert clamp behaviour.
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw("<feed></feed>", "application/atom+xml"),
            )
            .mount(&mock)
            .await;
        let papers = search_against(&mock.uri(), "x", 200).await.unwrap();
        assert!(papers.is_empty());
        let received = mock.received_requests().await.expect("requests captured");
        assert_eq!(received.len(), 1);
        let url = received[0].url.as_str();
        assert!(
            url.contains("max_results=50"),
            "clamp must hit cap of 50, got URL: {url}"
        );
    }

    #[test]
    fn arxiv_url_constant_pinned() {
        assert_eq!(ARXIV_API_URL, "http://export.arxiv.org/api/query");
    }
}
