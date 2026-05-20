//! `web_fetch` — A-21. HTTP GET + HTML→clean-text extraction.
//!
//! Operator workflow: `neoth fetch <url>` returns the page body as
//! Markdown-friendly text. The agent's RAG path consumes this via the
//! skill router; channels consume it via `/fetch <url>` slash command
//! (Phase 2). The HTTP client reuses `providers::http_client` so the
//! Hysteria proxy is honoured for free.
//!
//! Self-contained: no JavaScript execution (operator's "real browser"
//! path is Playwright MCP, Phase 2). The text extractor is hand-rolled
//! to avoid adding a heavy HTML-to-MD dep — the contract is "operator
//! gets readable text, not byte-perfect Markdown". Tables, headers,
//! and links survive; layout / colour / scripts do not.

use anyhow::{Context, Result};

use crate::providers::http_client;

/// Hard ceiling on response body. Matches the WAL payload cap so a
/// 50 MiB HTML response can't crash the daemon when an agent pipes it
/// to recall. Operators who genuinely want huge bodies stream via
/// Playwright + chunking (Phase 2).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Hard ceiling on extracted text. After the stripper runs, anything
/// above this gets truncated with a `…[truncated]` marker. Keeps
/// downstream prompt costs bounded.
pub const MAX_EXTRACTED_BYTES: usize = 200_000;

#[derive(Clone, Debug, serde::Serialize)]
pub struct FetchResult {
    pub url: String,
    pub status: u16,
    pub content_type: String,
    pub bytes: usize,
    pub text: String,
    pub truncated: bool,
}

/// Fetch the URL + return clean-text body. HTML pages run through the
/// stripper; text/* responses pass through verbatim (within the
/// `MAX_EXTRACTED_BYTES` ceiling); other content types return their
/// raw bytes count + empty text + a status flag.
pub async fn fetch(url: &str) -> Result<FetchResult> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        anyhow::bail!("web_fetch: only http(s) URLs accepted, got: {url}");
    }
    let client = http_client::build_client().context("build reqwest client")?;
    let resp = client
        .get(url)
        .header("User-Agent", "NEOTH-fetch/0.1 (+self-hosted)")
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = resp
        .bytes()
        .await
        .with_context(|| format!("read body of {url}"))?;
    let bytes = body.len();
    if bytes > MAX_RESPONSE_BYTES {
        anyhow::bail!(
            "web_fetch: response {bytes} bytes exceeds ceiling {}",
            MAX_RESPONSE_BYTES
        );
    }
    let raw = String::from_utf8_lossy(&body).into_owned();
    let (text, truncated) = if content_type.starts_with("text/html") {
        let stripped = strip_html(&raw);
        truncate(&stripped, MAX_EXTRACTED_BYTES)
    } else if content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
    {
        truncate(&raw, MAX_EXTRACTED_BYTES)
    } else {
        (String::new(), false)
    };
    Ok(FetchResult {
        url: url.to_string(),
        status,
        content_type,
        bytes,
        text,
        truncated,
    })
}

fn truncate(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    // Truncate at char boundary near `max`.
    let mut end = max;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push_str("\n\n…[truncated]");
    (out, true)
}

/// Strip HTML markup, preserving paragraph structure + links + headers.
/// Hand-rolled to avoid a heavy dep; the contract is "readable text
/// for LLM context", not "byte-perfect Markdown conversion". Operators
/// who need rich conversion install Pandoc + the markdown converter
/// skill (Phase 3+).
fn strip_html(html: &str) -> String {
    // 1. Drop script/style blocks entirely — their content is
    // never user-visible text.
    let mut s = drop_block(html, "script");
    s = drop_block(&s, "style");
    s = drop_block(&s, "noscript");
    s = drop_block(&s, "iframe");

    // 2. Replace block-level tags with newline markers BEFORE we
    // strip remaining tags. Order matters — we hit headings first so
    // the link rewriter sees the cleaner shape.
    s = replace_block_open_close(&s, "h1", "\n\n# ", "\n\n");
    s = replace_block_open_close(&s, "h2", "\n\n## ", "\n\n");
    s = replace_block_open_close(&s, "h3", "\n\n### ", "\n\n");
    s = replace_block_open_close(&s, "h4", "\n\n#### ", "\n\n");
    s = replace_block_open_close(&s, "h5", "\n\n##### ", "\n\n");
    s = replace_block_open_close(&s, "h6", "\n\n###### ", "\n\n");
    s = replace_block_open_close(&s, "p", "\n\n", "\n\n");
    s = replace_block_open_close(&s, "li", "\n- ", "");
    s = replace_block_open_close(&s, "br", "\n", "");
    s = replace_block_open_close(&s, "tr", "\n", "");
    s = replace_block_open_close(&s, "td", " | ", "");
    s = replace_block_open_close(&s, "th", " | ", "");

    // 3. Rewrite anchor tags as Markdown links. This catches the
    // common case <a href="URL">TEXT</a>; messy HTML with attributes
    // out of order or quotes mixed still gets stripped to plain
    // TEXT by the catch-all stripper below.
    s = rewrite_anchors(&s);

    // 4. Strip every remaining tag.
    s = strip_remaining_tags(&s);

    // 5. Decode the small subset of entities operators actually see.
    s = s
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ");

    // 6. Collapse runaway whitespace.
    collapse_whitespace(&s)
}

fn drop_block(input: &str, tag: &str) -> String {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(open_at) = find_ci(rest, &open) {
        out.push_str(&rest[..open_at]);
        let after = &rest[open_at..];
        if let Some(close_at) = find_ci(after, &close) {
            rest = &after[close_at + close.len()..];
        } else {
            // No matching close — drop the rest entirely.
            return out;
        }
    }
    out.push_str(rest);
    out
}

fn replace_block_open_close(input: &str, tag: &str, open_sub: &str, close_sub: &str) -> String {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let self_closing = format!("<{tag}/>");
    let mut out = String::with_capacity(input.len() + 32);
    let mut rest = input;
    loop {
        let next_open = find_ci(rest, &open);
        let next_self = find_ci(rest, &self_closing);
        let next = match (next_open, next_self) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };
        match next {
            Some(i) => {
                out.push_str(&rest[..i]);
                out.push_str(open_sub);
                // Skip to the close of THIS open tag (find the next `>`).
                if let Some(gt) = rest[i..].find('>') {
                    rest = &rest[i + gt + 1..];
                } else {
                    return out;
                }
            }
            None => {
                // Now strip remaining closes.
                out.push_str(rest);
                break;
            }
        }
    }
    out = out.replace(&close, close_sub);
    out
}

fn rewrite_anchors(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(open_at) = find_ci(rest, "<a ") {
        out.push_str(&rest[..open_at]);
        let after = &rest[open_at..];
        let Some(gt) = after.find('>') else {
            out.push_str(after);
            return out;
        };
        let tag = &after[..gt];
        let href = extract_attr(tag, "href").unwrap_or_default();
        let body_start = gt + 1;
        let Some(close_at) = find_ci(&after[body_start..], "</a>") else {
            out.push_str(after);
            return out;
        };
        let body = &after[body_start..body_start + close_at];
        if href.is_empty() {
            out.push_str(body);
        } else {
            out.push_str(&format!("[{body}]({href})"));
        }
        rest = &after[body_start + close_at + 4..]; // 4 = "</a>"
    }
    out.push_str(rest);
    out
}

fn extract_attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let i = find_ci(tag, &needle)?;
    let after = &tag[i + needle.len()..];
    let bytes = after.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let (quote, content) = match bytes[0] {
        b'"' => ('"', &after[1..]),
        b'\'' => ('\'', &after[1..]),
        _ => return after.split_whitespace().next().map(|s| s.to_string()),
    };
    let end = content.find(quote)?;
    Some(content[..end].to_string())
}

fn strip_remaining_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for c in input.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_blank = false;
    let mut prev_space = false;
    for line in input.lines() {
        let trimmed = line.trim_end();
        // Collapse internal runs of spaces to single space.
        let mut compact = String::with_capacity(trimmed.len());
        for c in trimmed.chars() {
            if c.is_whitespace() {
                if !prev_space {
                    compact.push(' ');
                }
                prev_space = true;
            } else {
                compact.push(c);
                prev_space = false;
            }
        }
        prev_space = false;
        let trimmed = compact.trim();
        if trimmed.is_empty() {
            if !last_blank && !out.is_empty() {
                out.push('\n');
            }
            last_blank = true;
        } else {
            out.push_str(trimmed);
            out.push('\n');
            last_blank = false;
        }
    }
    out.trim().to_string()
}

fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    haystack.to_lowercase().find(&needle.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_html_drops_script_blocks_entirely() {
        let html = "<p>visible</p><script>alert('hack')</script><p>also visible</p>";
        let s = strip_html(html);
        assert!(s.contains("visible"));
        assert!(s.contains("also visible"));
        assert!(!s.contains("alert"));
        assert!(!s.contains("hack"));
    }

    #[test]
    fn strip_html_converts_headings_to_markdown() {
        let html = "<h1>Title</h1><h2>Subtitle</h2><p>Body</p>";
        let s = strip_html(html);
        assert!(s.contains("# Title"));
        assert!(s.contains("## Subtitle"));
        assert!(s.contains("Body"));
    }

    #[test]
    fn strip_html_rewrites_anchors_as_markdown_links() {
        let html = r#"<p>Visit <a href="https://example.com">our site</a> today.</p>"#;
        let s = strip_html(html);
        assert!(s.contains("[our site](https://example.com)"));
    }

    #[test]
    fn strip_html_decodes_common_entities() {
        let html = "<p>A &amp; B &lt; C &gt; D &quot;quoted&quot; &nbsp; space</p>";
        let s = strip_html(html);
        assert!(s.contains("A & B < C > D \"quoted\""));
    }

    #[test]
    fn strip_html_converts_list_items_to_dashes() {
        let html = "<ul><li>one</li><li>two</li><li>three</li></ul>";
        let s = strip_html(html);
        assert!(s.contains("- one"));
        assert!(s.contains("- two"));
        assert!(s.contains("- three"));
    }

    #[test]
    fn truncate_preserves_short_input_verbatim() {
        let (s, t) = truncate("hello", 100);
        assert_eq!(s, "hello");
        assert!(!t);
    }

    #[test]
    fn truncate_long_input_with_marker() {
        let (s, t) = truncate(&"a".repeat(500), 200);
        assert!(t);
        assert!(s.ends_with("…[truncated]"));
        // Length includes the marker; underlying content ≤ 200 chars.
        assert!(s.len() < 250);
    }

    #[test]
    fn extract_attr_handles_double_quotes() {
        let tag = "<a href=\"https://example.com\" class=\"link\"";
        assert_eq!(
            extract_attr(tag, "href"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn extract_attr_handles_single_quotes() {
        let tag = "<a href='https://example.com'";
        assert_eq!(
            extract_attr(tag, "href"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn collapse_whitespace_compresses_runs() {
        // Multiple blank lines collapse to a single paragraph break
        // (one blank line = two `\n`s between non-empty content).
        // Runs of internal spaces collapse to a single space.
        let input = "hello    world\n\n\n\nfoo";
        let s = collapse_whitespace(input);
        assert_eq!(s, "hello world\n\nfoo");
    }

    #[tokio::test]
    async fn fetch_rejects_non_http_schemes() {
        let err = fetch("file:///etc/passwd").await.unwrap_err();
        assert!(err.to_string().contains("http(s) URLs"));
        let err = fetch("javascript:alert(1)").await.unwrap_err();
        assert!(err.to_string().contains("http(s) URLs"));
    }

    // ── CDX-04: wiremock HTTP round-trip coverage ─────────────────────────

    #[tokio::test]
    async fn fetch_html_decodes_via_real_http() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/article"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(
                        "<html><head><title>x</title></head><body>\
                         <h1>Title</h1><p>Body paragraph with <a href=\"https://link\">a link</a>.</p>\
                         </body></html>",
                        "text/html; charset=utf-8",
                    ),
            )
            .mount(&mock)
            .await;
        let url = format!("{}/article", mock.uri());
        let r = fetch(&url).await.expect("fetch should succeed");
        assert_eq!(r.status, 200);
        assert!(
            r.content_type.starts_with("text/html"),
            "content_type was `{}`",
            r.content_type
        );
        assert!(r.text.contains("# Title"));
        assert!(r.text.contains("Body paragraph"));
        assert!(r.text.contains("[a link](https://link)"));
        assert!(!r.truncated);
    }

    #[tokio::test]
    async fn fetch_passes_plaintext_through_verbatim() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/raw.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw("hello\nplain world", "text/plain; charset=utf-8"),
            )
            .mount(&mock)
            .await;
        let url = format!("{}/raw.txt", mock.uri());
        let r = fetch(&url).await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.text, "hello\nplain world");
    }

    #[tokio::test]
    async fn fetch_propagates_non_2xx_status() {
        // Status is captured but body still parsed — operator sees what
        // the server actually returned, including 404 pages.
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(404).set_body_raw("<h1>Not Found</h1>", "text/html"),
            )
            .mount(&mock)
            .await;
        let r = fetch(&mock.uri()).await.unwrap();
        assert_eq!(r.status, 404);
        assert!(r.text.contains("Not Found"));
    }

    #[tokio::test]
    async fn fetch_returns_empty_text_for_binary_content_type() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(vec![0u8, 1, 2, 3, 4], "application/octet-stream"),
            )
            .mount(&mock)
            .await;
        let r = fetch(&mock.uri()).await.unwrap();
        assert_eq!(r.bytes, 5);
        assert!(r.text.is_empty());
        assert_eq!(r.content_type, "application/octet-stream");
    }

    #[tokio::test]
    async fn fetch_includes_user_agent_header() {
        // Drift guard — if the User-Agent string ever changes by
        // accident, the regression shows up here. Our fetcher
        // identifies itself as `NEOTH-fetch/0.1 (+self-hosted)`.
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("user-agent", "NEOTH-fetch/0.1 (+self-hosted)"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("ok", "text/plain"))
            .mount(&mock)
            .await;
        let r = fetch(&mock.uri()).await.expect("expected_header match");
        assert_eq!(r.status, 200);
        assert_eq!(r.text, "ok");
    }
}
