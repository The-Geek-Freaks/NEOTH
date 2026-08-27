//! ArXiv search + retrieval (A-24).
//!
//! Public XML API at `https://export.arxiv.org/api/query` — no API
//! key, no rate-limit surprise. Operator queries by keyword + gets
//! back a structured `Vec<ArxivPaper>` with title, authors, abstract,
//! pdf url. Downstream skills can `neoth fetch <pdf_url>` + run the
//! existing `media::pdf` extractor to land the paper text in recall.
//!
//! Included for research-workflow value — high value, low build cost.

use anyhow::{Context, Result};

use crate::providers::http_client;
use crate::tools::external_http::{
    ExternalHttpAuthorizer, ExternalHttpRequest, ExternalHttpSurface,
};

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
pub const ARXIV_API_URL: &str = "https://export.arxiv.org/api/query";

/// Hard limit for the raw ArXiv response before UTF-8 or Atom parsing.
/// Fifty ordinary Atom entries fit comfortably below this while preventing an
/// upstream response from forcing an unbounded allocation in either caller.
const MAX_ARXIV_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ARXIV_RESULTS: usize = 50;

/// Query the ArXiv API + return up to `max_results` matches. Most
/// recent first. ArXiv's search query syntax: `all:keyword`,
/// `ti:title`, `au:author`, `cat:cs.CL`, `AND` / `OR` / `ANDNOT`.
pub async fn search(query: &str, max_results: usize) -> Result<Vec<ArxivPaper>> {
    let config = crate::config::FreedomConfig::load_from_default_path_or_default()?;
    let http = ExternalHttpAuthorizer::interactive(config.autonomy_policy())?;
    search_against_authorized(ARXIV_API_URL, query, max_results, &http).await
}

/// Internal test seam — production `search` calls this with the real
/// ArXiv endpoint; wiremock tests pass a mock server's URI. `pub(crate)`
/// so the EL-02 ingest task (`cli::arxiv_ingest_task`) can drive it
/// against a mock endpoint in its own wiremock tests.
#[cfg(test)]
pub(crate) async fn search_against(
    endpoint: &str,
    query: &str,
    max_results: usize,
) -> Result<Vec<ArxivPaper>> {
    let http = ExternalHttpAuthorizer::test_allow();
    search_against_authorized(endpoint, query, max_results, &http).await
}

pub(crate) async fn search_against_authorized(
    endpoint: &str,
    query: &str,
    max_results: usize,
    http: &ExternalHttpAuthorizer,
) -> Result<Vec<ArxivPaper>> {
    if query.trim().is_empty() {
        anyhow::bail!("arxiv: empty query");
    }
    let max = max_results.clamp(1, MAX_ARXIV_RESULTS);
    let url = format!(
        "{endpoint}?search_query={}&start=0&max_results={}&sortBy=submittedDate&sortOrder=descending",
        urlencode(query),
        max
    );
    let request = ExternalHttpRequest::get(&url, ExternalHttpSurface::Arxiv);
    let permitted_request = request.clone();
    http.execute(request, move |permit| async move {
        permit.require(&permitted_request)?;
        let client = http_client::build_client_no_redirect()?;
        let mut resp = client
            .get(url)
            .header("User-Agent", "NEOTH-arxiv/0.1")
            .send()
            .await
            .context("arxiv API request")?;
        if !resp.status().is_success() {
            anyhow::bail!("arxiv API returned {}", resp.status());
        }
        preflight_response_content_length(resp.content_length())?;
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.context("arxiv response read")? {
            append_response_chunk(&mut body, &chunk)?;
        }
        let body = std::str::from_utf8(&body)
            .map_err(|_| anyhow::anyhow!("arxiv response is not valid UTF-8"))?;
        parse_atom(body, max)
    })
    .await
}

/// A Content-Length preflight avoids reading a declared oversized response, but
/// cannot be the enforcement mechanism because chunked responses may omit or
/// lie about that header. [`append_response_chunk`] is the authoritative cap.
fn preflight_response_content_length(content_length: Option<u64>) -> Result<()> {
    if content_length.is_some_and(|length| length > MAX_ARXIV_RESPONSE_BYTES as u64) {
        anyhow::bail!("arxiv response exceeds configured size limit");
    }
    Ok(())
}

/// Append one raw HTTP chunk without exceeding the response memory boundary.
/// The checked addition protects the boundary even if an adversarial stream
/// presents a pathological sequence of chunks.
fn append_response_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    let total = body
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| anyhow::anyhow!("arxiv response exceeds configured size limit"))?;
    if total > MAX_ARXIV_RESPONSE_BYTES {
        anyhow::bail!("arxiv response exceeds configured size limit");
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Minimal Atom XML parser scoped to ArXiv's response shape. We pull
/// out `<entry>` blocks then regex-extract the fields we care about.
/// No XML lib dep — the response is well-formed enough that a
/// targeted scan is reliable for v0.1.x. Operators who hit a parse
/// edge case can opt into a future `quick-xml`-based path (Phase 2).
fn parse_atom(xml: &str, max_entries: usize) -> Result<Vec<ArxivPaper>> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<entry>") {
        if out.len() >= max_entries {
            anyhow::bail!("arxiv response exceeds requested entry limit");
        }
        rest = &rest[start + "<entry>".len()..];
        let end = rest
            .find("</entry>")
            .ok_or_else(|| anyhow::anyhow!("arxiv response contains an unterminated entry"))?;
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
        let papers = parse_atom(xml, MAX_ARXIV_RESULTS).expect("parse ok");
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
        let papers = parse_atom(xml, MAX_ARXIV_RESULTS).expect("parse ok");
        assert!(papers.is_empty());
    }

    #[test]
    fn response_body_rejects_oversized_declared_length_before_reading() {
        let err = preflight_response_content_length(Some(MAX_ARXIV_RESPONSE_BYTES as u64 + 1))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "arxiv response exceeds configured size limit"
        );
    }

    #[test]
    fn response_body_rejects_oversized_chunked_stream_without_length() {
        preflight_response_content_length(None).expect("missing length is allowed");
        let mut body = Vec::new();
        append_response_chunk(&mut body, &vec![b'x'; MAX_ARXIV_RESPONSE_BYTES - 1])
            .expect("under-limit chunk accepted");
        let err = append_response_chunk(&mut body, b"xx").unwrap_err();
        assert_eq!(
            err.to_string(),
            "arxiv response exceeds configured size limit"
        );
        assert_eq!(body.len(), MAX_ARXIV_RESPONSE_BYTES - 1);
    }

    #[test]
    fn response_body_accepts_exact_byte_cap() {
        let mut body = Vec::new();
        append_response_chunk(&mut body, &vec![b'x'; MAX_ARXIV_RESPONSE_BYTES])
            .expect("exact cap accepted");
        assert_eq!(body.len(), MAX_ARXIV_RESPONSE_BYTES);
    }

    #[test]
    fn parse_atom_rejects_entries_over_requested_limit() {
        let xml = concat!(
            "<feed><entry><id>one</id></entry>",
            "<entry><id>two</id></entry></feed>"
        );
        let err = parse_atom(xml, 1).unwrap_err();
        assert_eq!(
            err.to_string(),
            "arxiv response exceeds requested entry limit"
        );
    }

    #[test]
    fn parse_atom_rejects_feed_with_unterminated_later_entry() {
        let xml = concat!(
            "<feed><entry><id>one</id></entry>",
            "<entry><id>truncated</id></feed>"
        );
        let err = parse_atom(xml, MAX_ARXIV_RESULTS).unwrap_err();
        assert_eq!(
            err.to_string(),
            "arxiv response contains an unterminated entry"
        );
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
    async fn search_does_not_follow_redirects() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "http://169.254.169.254/latest/meta-data"),
            )
            .mount(&mock)
            .await;
        let err = search_against(&mock.uri(), "x", 1).await.unwrap_err();
        assert!(err.to_string().contains("302"));
        assert_eq!(mock.received_requests().await.unwrap().len(), 1);
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
        assert_eq!(ARXIV_API_URL, "https://export.arxiv.org/api/query");
    }
}
