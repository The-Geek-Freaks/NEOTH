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
//!
//! ## Goal-based extraction (GOLD-ADAPT-ODY-23)
//!
//! `fetch_with_goal(url, goal, provider)` fetches the page then runs a
//! focused LLM extraction pass that returns `{ rational, evidence[], summary }`
//! scoped to the caller's goal. Pairs with `tools/deep_research.rs` (ODY-17)
//! where every page in a research plan is goal-extracted before synthesis.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use tokio::net::lookup_host;

use crate::providers::http_client;
use crate::providers::{Completion, Provider, Request};
use crate::tools::external_http::{
    ExternalHttpAuthorizer, ExternalHttpRequest, ExternalHttpSurface,
};
use crate::tools::web_doc_cache;

/// Cloud metadata hostnames that resolve to link-local 169.254.x.x in
/// practice but are sometimes resolvable to public IPs in misconfigured
/// DNS — block them by name as defence-in-depth.
const BLOCKED_METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.azure.internal",
    "169.254.169.254",
    "metadata",
];

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

/// GOLD-ADOPT-04 — a fetch that ALSO exposes the raw HTML body, so the
/// [`crate::tools::web_extract`] CSS layer can run selectors on the real markup
/// (the `meta.text` field is already stripped/extracted, useless for CSS). The
/// raw HTML is populated only for `text/html` / `application/xhtml+xml`
/// content-types (empty otherwise). Inherits the SSRF guard + no-redirect
/// client from the shared path.
#[derive(Clone, Debug)]
pub struct RawFetchResult {
    /// The raw HTML body (empty for non-HTML content-types).
    pub raw_html: String,
    /// The same metadata + stripped text a plain `fetch()` returns.
    pub meta: FetchResult,
}

/// Fetch the URL + return clean-text body. HTML pages run through the
/// stripper; text/* responses pass through verbatim (within the
/// `MAX_EXTRACTED_BYTES` ceiling); other content types return their
/// raw bytes count + empty text + a status flag.
pub async fn fetch(url: &str) -> Result<FetchResult> {
    let http = interactive_http()?;
    fetch_authorized(url, &http).await
}

pub async fn fetch_authorized(url: &str, http: &ExternalHttpAuthorizer) -> Result<FetchResult> {
    fetch_inner(url, http).await.map(|(_, meta)| meta)
}

/// GOLD-ADOPT-04 — like [`fetch`] but also surfaces the raw HTML body for the
/// CSS-extract layer.
pub async fn fetch_raw(url: &str) -> Result<RawFetchResult> {
    let http = interactive_http()?;
    fetch_raw_authorized(url, &http).await
}

pub async fn fetch_raw_authorized(
    url: &str,
    http: &ExternalHttpAuthorizer,
) -> Result<RawFetchResult> {
    let (raw, meta) = fetch_inner(url, http).await?;
    let raw_html =
        if meta.content_type.starts_with("text/html") || meta.content_type.contains("xhtml") {
            raw
        } else {
            String::new()
        };
    Ok(RawFetchResult { raw_html, meta })
}

/// GOLD-ADAPT-ODY-23 — result of a goal-focused extraction pass over a fetched
/// page. The LLM is asked to read the page text and answer three structured
/// questions relative to the caller's `goal`:
///
/// * `rational`  — why this page is (or is not) relevant to the goal.
/// * `evidence`  — direct verbatim or close-paraphrase quotes that support
///                 the goal; empty when the page contains no relevant evidence.
/// * `summary`   — a concise paragraph synthesising what the page contributes
///                 toward the goal.
///
/// The struct derives `serde::Deserialize` so the LLM JSON response is parsed
/// directly into it. All three fields are `String`/`Vec<String>` — no
/// structured sub-types that would require a schema change.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct GoalExtraction {
    /// Why the page is (or is not) relevant to the goal.
    pub rational: String,
    /// Direct evidence quotes / paraphrases supporting the goal (may be empty).
    pub evidence: Vec<String>,
    /// Concise synthesis of what the page contributes toward the goal.
    pub summary: String,
}

/// System prompt prefix for the goal-extraction LLM pass. Kept short to save
/// tokens; the caller appends the goal and the page text.
const GOAL_EXTRACT_SYSTEM: &str = "You are a precise research assistant. \
Extract structured goal-relevant information from a web page. \
Respond ONLY with a JSON object — no markdown fences, no extra keys. \
The JSON must have exactly three fields: \
\"rational\" (string: why the page is or is not relevant to the goal), \
\"evidence\" (array of strings: direct quotes or close paraphrases from the page that support the goal; empty array if none), \
\"summary\" (string: one-paragraph synthesis of what the page contributes to the goal). \
If the page is not relevant, set rational to explain why, evidence to [], and summary to an empty string.";

/// Extracts goal-focused structured content from a fetched URL.
///
/// Workflow:
/// 1. Fetches `url` via the normal [`fetch`] path (SSRF-guarded, cached).
/// 2. Sends the extracted page text + the caller's `goal` to `provider` in a
///    structured extraction prompt.
/// 3. Parses the provider's JSON response into [`GoalExtraction`].
///
/// `provider` is caller-supplied so this function is fully testable with a
/// mock provider — no config loading, no daemon dependency.
///
/// # Errors
/// Propagates fetch errors and provider errors. Returns `Err` when the
/// provider response is not valid JSON matching the [`GoalExtraction`] schema.
pub async fn fetch_with_goal(
    url: &str,
    goal: &str,
    provider: &dyn Provider,
) -> Result<GoalExtraction> {
    let http = interactive_http()?;
    fetch_with_goal_authorized(url, goal, provider, &http).await
}

pub async fn fetch_with_goal_authorized(
    url: &str,
    goal: &str,
    provider: &dyn Provider,
    http: &ExternalHttpAuthorizer,
) -> Result<GoalExtraction> {
    let fetched = fetch_authorized(url, http).await?;
    extract_goal_from_text(&fetched.text, url, goal, provider).await
}

fn interactive_http() -> Result<ExternalHttpAuthorizer> {
    let config = crate::config::FreedomConfig::load_from_default_path_or_default()?;
    ExternalHttpAuthorizer::interactive(config.autonomy_policy())
}

/// Inner extraction helper — separated so the test suite can call it directly
/// with fixture text without making a network request.
pub(crate) async fn extract_goal_from_text(
    page_text: &str,
    page_url: &str,
    goal: &str,
    provider: &dyn Provider,
) -> Result<GoalExtraction> {
    // Bound the page text fed to the LLM. Uses a conservative 8 000-char
    // ceiling: the goal + JSON envelope cost tokens too, and most extraction
    // goals are satisfiable from the opening sections of a page.
    const MAX_PAGE_CHARS_FOR_GOAL: usize = 8_000;
    let page_snippet = if page_text.len() > MAX_PAGE_CHARS_FOR_GOAL {
        &page_text[..MAX_PAGE_CHARS_FOR_GOAL]
    } else {
        page_text
    };

    let prompt = format!(
        "GOAL: {goal}\n\nSOURCE URL: {page_url}\n\nPAGE TEXT:\n{page_snippet}\n\n\
         Extract the goal-relevant information from the page above as a JSON object \
         with fields rational, evidence, summary."
    );

    let req = Request {
        prompt,
        system: Some(GOAL_EXTRACT_SYSTEM.to_string()),
        ..Request::default()
    };

    let completion: Completion = provider
        .complete(req)
        .await
        .context("goal extractor: LLM call failed")?;

    // Strip optional markdown code fences the LLM might emit despite the
    // instruction — "```json\n...\n```" or "```\n...\n```".
    let raw = completion.text.trim();
    let stripped = raw
        .strip_prefix("```json")
        .or_else(|| raw.strip_prefix("```"))
        .map(|s| s.trim_start())
        .and_then(|s| s.strip_suffix("```"))
        .map(|s| s.trim_end())
        .unwrap_or(raw);

    serde_json::from_str::<GoalExtraction>(stripped).with_context(|| {
        format!(
            "goal extractor: provider returned non-JSON response: {}",
            &stripped[..stripped.len().min(200)]
        )
    })
}

/// Shared fetch core — returns the raw body string AND the extracted
/// [`FetchResult`]. Both [`fetch`] and [`fetch_raw`] go through here so the
/// SSRF guard + no-redirect client + byte ceiling live in ONE place.
async fn fetch_inner(url: &str, http: &ExternalHttpAuthorizer) -> Result<(String, FetchResult)> {
    let request = ExternalHttpRequest::get(url, ExternalHttpSurface::Fetch);
    let permitted_request = request.clone();
    http.execute(request, move |permit| async move {
        permit.require(&permitted_request)?;
        // SX-01: SSRF guard — strict URL parsing + scheme filtering + DNS
        // pre-resolution to block private/loopback/link-local/cloud-metadata
        // targets BEFORE the HTTP client opens a socket.
        let parsed = validate_url(url).await?;
        // Use the no-redirect variant so an attacker cannot 302 us into a
        // private network after `validate_url` cleared the initial host.
        // Operators who need redirects see the 3xx status + Location header
        // and call `fetch` again (each call re-validates).
        let client =
            http_client::build_client_no_redirect().context("build web_fetch reqwest client")?;

        // GOLD-ADAPT-SKILL-03 — conditional-GET doc cache: if we hold a prior copy,
        // revalidate it with the origin (If-None-Match / If-Modified-Since). The
        // SSRF guard above + the no-redirect client still gate this request; the
        // cache only adds validator headers and a 304-serve branch, and is inert
        // until `web_doc_cache::init` has opted the process in.
        let cache_dir = web_doc_cache::dir();
        let cached = cache_dir
            .as_deref()
            .and_then(|d| web_doc_cache::lookup(d, url));

        let mut req = client
            .get(parsed.as_str())
            .header("User-Agent", "NEOTH-fetch/0.1 (+self-hosted)");
        if let Some(c) = &cached {
            if let Some(etag) = &c.etag {
                req = req.header(reqwest::header::IF_NONE_MATCH, etag.as_str());
            }
            if let Some(lm) = &c.last_modified {
                req = req.header(reqwest::header::IF_MODIFIED_SINCE, lm.as_str());
            }
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        let status = resp.status().as_u16();

        // 304 Not Modified — the origin confirms our cached copy is current. Serve
        // it (re-deriving the stripped text so the result is byte-identical to a
        // fresh fetch of the same body).
        if status == 304 {
            if let Some(c) = cached {
                let (text, truncated) = derive_text(&c.raw, &c.content_type);
                let bytes = c.raw.len();
                return Ok((
                    c.raw,
                    FetchResult {
                        url: url.to_string(),
                        status: c.status,
                        content_type: c.content_type,
                        bytes,
                        text,
                        truncated,
                    },
                ));
            }
            // 304 without a cached body (protocol violation, or the entry was
            // evicted mid-flight) — nothing to serve. Fail loudly, never silently.
            anyhow::bail!("web_fetch: {url} returned 304 with no cached body to serve");
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        // Capture cache validators BEFORE the body consumes `resp`.
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let last_modified = resp
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
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
        let (text, truncated) = derive_text(&raw, &content_type);

        // Cache only a successful, revalidatable, bounded body. A response with no
        // ETag/Last-Modified cannot be conditionally revalidated, so caching it
        // would risk serving stale content — skip it.
        if let Some(dir) = &cache_dir {
            // doc-cache review LOW-1: only a full 200 OK is cacheable — a 206
            // Partial Content (or other 2xx) would cache an incomplete body.
            // LOW-2: never cache a response whose URL carries a credential param.
            if status == 200
                && (etag.is_some() || last_modified.is_some())
                && raw.len() <= web_doc_cache::MAX_CACHEABLE_BYTES
                && !web_doc_cache::url_has_credential_params(url)
            {
                let stored_unix = crate::time::now_unix_i64();
                web_doc_cache::store(
                    dir,
                    &web_doc_cache::CachedDoc {
                        url: url.to_string(),
                        etag,
                        last_modified,
                        content_type: content_type.clone(),
                        status,
                        raw: raw.clone(),
                        stored_unix,
                    },
                );
            }
        }

        Ok((
            raw,
            FetchResult {
                url: url.to_string(),
                status,
                content_type,
                bytes,
                text,
                truncated,
            },
        ))
    })
    .await
}

/// Strip + truncate a raw body into displayed text by content type. Shared by
/// the live fetch and the 304-cache-hit path so both produce identical text.
fn derive_text(raw: &str, content_type: &str) -> (String, bool) {
    if content_type.starts_with("text/html") {
        let stripped = strip_html(raw);
        truncate(&stripped, MAX_EXTRACTED_BYTES)
    } else if content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
    {
        truncate(raw, MAX_EXTRACTED_BYTES)
    } else {
        (String::new(), false)
    }
}

/// SX-01: parse + validate URL. Rejects non-http(s) schemes, hostnames
/// matching known cloud-metadata names, and any host that resolves to a
/// private / loopback / link-local / unique-local-v6 / multicast IP. On
/// rejection emits a `tracing::warn!` so the audit trail surfaces the
/// blocked target.
///
/// Returns the parsed `url::Url` so callers can reuse the canonical form
/// without re-parsing. Note: this is best-effort defence at *call time* —
/// the underlying reqwest client may re-resolve at connect time
/// (classic TOCTOU). Mitigated by `redirect(Policy::none())` in
/// `http_client::build_client_no_redirect` so an attacker cannot 302 us into a
/// private network after the check.
pub(crate) async fn validate_url(url_str: &str) -> Result<url::Url> {
    let parsed =
        url::Url::parse(url_str).with_context(|| format!("web_fetch: invalid URL: {url_str}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            tracing::warn!(
                scheme = other,
                url = url_str,
                "web_fetch: rejected non-http(s) scheme"
            );
            anyhow::bail!("web_fetch: only http(s) URLs accepted, got scheme `{other}`: {url_str}");
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("web_fetch: URL has no host: {url_str}"))?;

    let host_lower = host.to_ascii_lowercase();
    if BLOCKED_METADATA_HOSTS.iter().any(|h| host_lower == *h) {
        tracing::warn!(
            host = %host,
            url = url_str,
            "web_fetch: rejected cloud metadata hostname"
        );
        anyhow::bail!("web_fetch: refused metadata host `{host}`: {url_str}");
    }

    let port = parsed.port_or_known_default().ok_or_else(|| {
        anyhow::anyhow!("web_fetch: URL missing port and no default for scheme: {url_str}")
    })?;

    let mut saw_any = false;
    for addr in lookup_host(format!("{host}:{port}"))
        .await
        .with_context(|| format!("web_fetch: DNS lookup failed for {host}"))?
    {
        saw_any = true;
        if is_private_ip(addr.ip()) {
            // Test-only escape hatch: wiremock binds to 127.0.0.1, so the
            // existing round-trip tests cannot run against a production
            // SSRF guard. A per-test `LoopbackGuard` (below in #[cfg(test)])
            // flips a thread-local that lets `is_loopback()` traffic pass.
            // Production builds never compile this branch — the
            // `#[cfg(test)]` keeps it out of the release binary entirely.
            #[cfg(test)]
            if test_overrides::loopback_allowed() && addr.ip().is_loopback() {
                continue;
            }
            tracing::warn!(
                host = %host,
                ip = %addr.ip(),
                url = url_str,
                "web_fetch: rejected private/loopback/link-local IP"
            );
            anyhow::bail!(
                "web_fetch: refused private address {} for host `{host}`: {url_str}",
                addr.ip()
            );
        }
    }

    if !saw_any {
        anyhow::bail!("web_fetch: DNS resolved zero addresses for {host}: {url_str}");
    }

    Ok(parsed)
}

/// True if `ip` is in any address class NEOTH must never connect to from
/// an external-fetch tool. Union of: loopback, RFC-1918 private,
/// link-local (covers AWS/GCP/Azure 169.254.169.254 metadata),
/// IPv6 unique-local (RFC-4193 fc00::/7), IPv6 link-local (fe80::/10),
/// unspecified, broadcast, documentation ranges, and multicast.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || is_shared_v4(v4)
                || is_benchmarking_v4(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local_v6(v6)
                || is_link_local_v6(v6)
                || is_ipv4_mapped_private(v6)
        }
    }
}

/// RFC-6598 shared address space `100.64.0.0/10` — carrier-grade NAT.
fn is_shared_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// RFC-2544 benchmarking range `198.18.0.0/15`.
fn is_benchmarking_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// RFC-4193 IPv6 unique-local `fc00::/7`.
fn is_unique_local_v6(ip: Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xfe) == 0xfc
}

/// IPv6 link-local `fe80::/10`.
fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

/// IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) — re-check the embedded
/// v4 octets against the private-IP rules, otherwise an attacker can
/// bypass via `::ffff:127.0.0.1`.
fn is_ipv4_mapped_private(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        is_private_ip(IpAddr::V4(v4))
    } else {
        false
    }
}

#[cfg(test)]
pub(crate) mod test_overrides {
    //! Thread-local SSRF overrides used by the test suite only. Never
    //! compiled into release binaries — production `validate_url` ALWAYS
    //! rejects loopback targets. `pub(crate)` so other modules' wiremock
    //! tests (e.g. `cli::rss_feed_task`, which calls `validate_url` before
    //! every feed GET) can enable the loopback hatch too.
    use std::cell::Cell;
    thread_local! {
        static ALLOW_LOOPBACK: Cell<bool> = const { Cell::new(false) };
    }
    pub(super) fn loopback_allowed() -> bool {
        ALLOW_LOOPBACK.with(|c| c.get())
    }
    /// RAII guard: enables loopback for the current test's tokio
    /// runtime thread, restores deny on drop. `#[tokio::test]` defaults
    /// to current-thread flavour, so the thread-local survives across
    /// awaits inside one test without leaking into parallel tests.
    pub(crate) struct LoopbackGuard;
    impl LoopbackGuard {
        pub(crate) fn enable() -> Self {
            ALLOW_LOOPBACK.with(|c| c.set(true));
            Self
        }
    }
    impl Drop for LoopbackGuard {
        fn drop(&mut self) {
            ALLOW_LOOPBACK.with(|c| c.set(false));
        }
    }
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

/// Case-insensitive ASCII substring search returning the byte offset of
/// the first match in `haystack`.
///
/// COR-28: the previous impl did `haystack.to_lowercase().find(...)`, which
/// allocated a full lowercased copy of the haystack on *every* call. Inside
/// the tag-rewrite loops (`drop_block`, `replace_block_open_close`,
/// `rewrite_anchors`, `extract_attr`) that ran once per tag occurrence over
/// the whole body — quadratic allocation + wall time on a multi-MiB page.
/// This version compares bytes with `to_ascii_lowercase` in a single pass
/// and allocates nothing. Every needle in this file is a pure-ASCII HTML
/// tag/attribute name, so the ASCII fold is correct and complete. Unlike the
/// old version it returns the offset into the *original* haystack (the old
/// one returned an offset into the lowercased copy, identical for ASCII).
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.len() > h.len() {
        return None;
    }
    (0..=(h.len() - n.len())).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    #[test]
    fn find_ci_is_case_insensitive_single_pass() {
        // COR-28: parity with the old to_lowercase().find() behaviour
        // for ASCII content, plus the empty/overflow edge cases.
        assert_eq!(find_ci("Hello World", "world"), Some(6));
        assert_eq!(find_ci("<SCRIPT>", "<script"), Some(0));
        assert_eq!(find_ci("abc", "xyz"), None);
        assert_eq!(find_ci("", ""), Some(0));
        assert_eq!(find_ci("anything", ""), Some(0));
        assert_eq!(find_ci("x", "xx"), None);
        // Offset is into the original haystack (matters once a caller
        // slices haystack with the returned index).
        assert_eq!(find_ci("aXbYc", "by"), Some(2));
        // At scale: a many-tag body must still find / reject correctly
        // without the old per-call full-body allocation.
        let big = "<p>".repeat(100_000);
        assert!(find_ci(&big, "<P>").is_some());
        assert!(find_ci(&big, "<script>").is_none());
    }

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

    // ── SX-01: SSRF guard rejection corpus ────────────────────────────────
    //
    // Coverage matrix per A5 CRIT-01 finding. Each `fetch` call MUST fail
    // before any HTTP socket is opened (validate_url runs first).

    #[tokio::test]
    async fn ssrf_rejects_gopher_scheme() {
        let err = fetch("gopher://example.com/").await.unwrap_err();
        assert!(err.to_string().contains("http(s) URLs"));
    }

    #[tokio::test]
    async fn ssrf_rejects_dict_scheme() {
        let err = fetch("dict://example.com/").await.unwrap_err();
        assert!(err.to_string().contains("http(s) URLs"));
    }

    #[tokio::test]
    async fn ssrf_rejects_ftp_scheme() {
        let err = fetch("ftp://example.com/").await.unwrap_err();
        assert!(err.to_string().contains("http(s) URLs"));
    }

    #[tokio::test]
    async fn ssrf_rejects_ipv4_loopback_literal() {
        let err = fetch("http://127.0.0.1/api/health").await.unwrap_err();
        assert!(
            err.to_string().contains("private address"),
            "expected private-address rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn ssrf_rejects_ipv4_loopback_alt_octet() {
        // `127.0.0.0/8` is fully loopback — not just 127.0.0.1.
        let err = fetch("http://127.42.0.99/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_rfc1918_10_8() {
        let err = fetch("http://10.0.0.1/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_rfc1918_192_168() {
        let err = fetch("http://192.168.1.1/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_rfc1918_172_16_through_172_31() {
        let err = fetch("http://172.20.0.5/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_link_local_aws_metadata() {
        // 169.254.169.254 is the AWS/GCP/Azure instance-metadata IP. Goes
        // through the hostname blocklist before DNS even runs.
        let err = fetch("http://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("metadata host")
                || err.to_string().contains("private address"),
            "expected metadata or private-address rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn ssrf_rejects_link_local_other_169_254() {
        let err = fetch("http://169.254.42.42/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_gcp_metadata_hostname() {
        let err = fetch("http://metadata.google.internal/").await.unwrap_err();
        assert!(err.to_string().contains("metadata host"));
    }

    #[tokio::test]
    async fn ssrf_rejects_azure_metadata_hostname() {
        let err = fetch("http://metadata.azure.internal/").await.unwrap_err();
        assert!(err.to_string().contains("metadata host"));
    }

    #[tokio::test]
    async fn ssrf_rejects_ipv6_loopback() {
        let err = fetch("http://[::1]/api").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_ipv6_unique_local() {
        let err = fetch("http://[fc00::1]/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_ipv6_link_local() {
        let err = fetch("http://[fe80::1]/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_ipv4_mapped_ipv6_loopback() {
        // Classic IPv4-mapped bypass: `::ffff:127.0.0.1` looks like an
        // IPv6 address but the embedded v4 octets are loopback. Our
        // `is_ipv4_mapped_private` check unwraps + re-validates.
        let err = fetch("http://[::ffff:127.0.0.1]/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_zero_v4() {
        let err = fetch("http://0.0.0.0/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_broadcast_v4() {
        let err = fetch("http://255.255.255.255/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_cgnat_shared_v4() {
        // RFC-6598 100.64.0.0/10 — common in carrier networks.
        let err = fetch("http://100.64.0.1/").await.unwrap_err();
        assert!(err.to_string().contains("private address"));
    }

    #[tokio::test]
    async fn ssrf_rejects_malformed_url() {
        // Junk strings should never reach the HTTP client. `url::Url::parse`
        // catches missing scheme; the wrapper context surfaces "invalid URL".
        let err = fetch("not a url at all").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid URL") || msg.contains("only http(s) URLs"),
            "expected URL rejection, got: {msg}"
        );
    }

    #[test]
    fn is_private_ip_catches_classic_ssrf_targets() {
        // Pure-function smoke matrix — runs without DNS / sockets so the
        // is_private_ip primitive is provably correct independently of
        // the async `fetch` wiring.
        use std::net::Ipv4Addr;
        use std::net::Ipv6Addr;
        let blocked = [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
        ];
        for ip in blocked {
            assert!(is_private_ip(ip), "expected {ip} to be blocked");
        }

        let allowed = [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4)), // github.com
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap()), // google DNS
        ];
        for ip in allowed {
            assert!(!is_private_ip(ip), "expected {ip} to be allowed");
        }
    }

    // ── CDX-04: wiremock HTTP round-trip coverage ─────────────────────────

    #[tokio::test]
    async fn fetch_html_decodes_via_real_http() {
        let _g = test_overrides::LoopbackGuard::enable();
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
        let _g = test_overrides::LoopbackGuard::enable();
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
        let _g = test_overrides::LoopbackGuard::enable();
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
        let _g = test_overrides::LoopbackGuard::enable();
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
        let _g = test_overrides::LoopbackGuard::enable();
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

    // ── GOLD-ADAPT-ODY-23: goal-based extraction tests ────────────────────

    /// A mock provider that always returns a fixed JSON string, simulating the
    /// LLM extraction pass without any network or API key dependency.
    struct FixedJsonProvider(String);

    #[async_trait::async_trait]
    impl Provider for FixedJsonProvider {
        fn name(&self) -> &'static str {
            "goal-extract-mock"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            Ok(Completion {
                text: self.0.clone(),
                identity: Default::default(),
                model: "mock".to_string(),
                latency: StdDuration::from_millis(0),
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    /// A mock provider that always fails — proves `fetch_with_goal` surfaces
    /// provider errors as `Err` instead of silently swallowing them.
    struct FailingGoalProvider;

    #[async_trait::async_trait]
    impl Provider for FailingGoalProvider {
        fn name(&self) -> &'static str {
            "goal-extract-fail-mock"
        }
        async fn complete(&self, _req: Request) -> anyhow::Result<Completion> {
            anyhow::bail!("simulated provider unavailable")
        }
    }

    /// Happy path: fixture HTML page + goal → structured `GoalExtraction`.
    /// The mock provider returns a hard-coded JSON object; we verify all three
    /// fields are parsed correctly and that `evidence` is a vec not a scalar.
    #[tokio::test]
    async fn goal_extraction_parses_structured_json_from_mock_provider() {
        let page_html = "<h1>Rust Memory Safety</h1>\
            <p>Rust prevents data races at compile time via its ownership model. \
            Buffer overflows are eliminated by bounds checking. \
            The borrow checker enforces exclusive mutable access.</p>";
        let page_text = strip_html(page_html);

        let json = r#"{
            "rational": "The page directly addresses memory safety mechanisms in Rust.",
            "evidence": [
                "Rust prevents data races at compile time via its ownership model.",
                "Buffer overflows are eliminated by bounds checking."
            ],
            "summary": "Rust achieves memory safety through ownership, borrow checking, and bounds checks."
        }"#;

        let provider = FixedJsonProvider(json.to_string());
        let goal = "How does Rust achieve memory safety?";

        let result =
            extract_goal_from_text(&page_text, "https://example.com/rust", goal, &provider)
                .await
                .expect("extraction should succeed");

        assert!(
            result.rational.contains("memory safety"),
            "rational should mention the goal topic; got: {}",
            result.rational
        );
        assert_eq!(
            result.evidence.len(),
            2,
            "expected 2 evidence items; got: {:?}",
            result.evidence
        );
        assert!(
            result.evidence[0].contains("data races"),
            "first evidence item should reference data races"
        );
        assert!(
            result.summary.contains("Rust"),
            "summary should mention Rust; got: {}",
            result.summary
        );
    }

    /// When the page has no relevant content, the LLM returns empty evidence
    /// and an explanatory rational. We verify the zero-evidence path parses.
    #[tokio::test]
    async fn goal_extraction_handles_no_relevant_evidence() {
        let json = r#"{
            "rational": "The page is about cooking recipes and is unrelated to the goal.",
            "evidence": [],
            "summary": ""
        }"#;
        let provider = FixedJsonProvider(json.to_string());

        let result = extract_goal_from_text(
            "This page is about pasta carbonara and tiramisu.",
            "https://example.com/recipes",
            "What are the latest breakthroughs in quantum computing?",
            &provider,
        )
        .await
        .expect("extraction should succeed even with empty evidence");

        assert!(
            result.evidence.is_empty(),
            "evidence should be empty for an off-topic page"
        );
        assert!(result.rational.contains("cooking") || result.rational.contains("unrelated"));
        assert!(result.summary.is_empty());
    }

    /// The LLM sometimes wraps its JSON in a ```json ... ``` code fence even
    /// when instructed not to. Verify the fence-stripping logic handles it.
    #[tokio::test]
    async fn goal_extraction_strips_markdown_code_fences() {
        let json_with_fence = "```json\n{\
            \"rational\": \"relevant\",\
            \"evidence\": [\"item one\"],\
            \"summary\": \"A summary.\"\
        }\n```";
        let provider = FixedJsonProvider(json_with_fence.to_string());

        let result = extract_goal_from_text(
            "some page text",
            "https://example.com/fenced",
            "test goal",
            &provider,
        )
        .await
        .expect("fence-wrapped JSON should still parse");

        assert_eq!(result.rational, "relevant");
        assert_eq!(result.evidence, vec!["item one"]);
        assert_eq!(result.summary, "A summary.");
    }

    /// Fence variant without `json` language tag (bare ``` ... ```).
    #[tokio::test]
    async fn goal_extraction_strips_bare_code_fences() {
        let json_with_bare_fence = "```\n{\
            \"rational\": \"bare fence test\",\
            \"evidence\": [],\
            \"summary\": \"bare\"\
        }\n```";
        let provider = FixedJsonProvider(json_with_bare_fence.to_string());

        let result = extract_goal_from_text(
            "page content",
            "https://example.com/bare",
            "any goal",
            &provider,
        )
        .await
        .expect("bare-fence JSON should still parse");

        assert_eq!(result.rational, "bare fence test");
        assert!(result.evidence.is_empty());
    }

    /// Provider failure propagates as `Err` rather than silently producing a
    /// default or panicking. The caller decides how to handle provider outages.
    #[tokio::test]
    async fn goal_extraction_propagates_provider_error() {
        let provider = FailingGoalProvider;
        let err = extract_goal_from_text(
            "any page",
            "https://example.com/fail",
            "any goal",
            &provider,
        )
        .await
        .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("LLM call failed") || msg.contains("provider unavailable"),
            "error message should identify the provider failure; got: {msg}"
        );
    }

    /// Malformed JSON from the provider returns `Err` with a context message
    /// that includes the truncated raw response — helps operators debug prompt
    /// regressions without reading logs.
    #[tokio::test]
    async fn goal_extraction_returns_err_on_malformed_json() {
        let provider = FixedJsonProvider("not valid json {{{".to_string());
        let err = extract_goal_from_text("page", "https://example.com/bad-json", "goal", &provider)
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("non-JSON response"),
            "error should mention non-JSON response; got: {msg}"
        );
    }

    /// No-goal path: plain `fetch` (without a goal) returns unchanged text —
    /// the extraction layer is strictly additive and does not mutate the base
    /// `FetchResult`. Verified here with a wiremock round-trip.
    #[tokio::test]
    async fn plain_fetch_without_goal_returns_unchanged_passthrough() {
        let _g = test_overrides::LoopbackGuard::enable();
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/page"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw("<p>Rust ownership rules.</p>", "text/html; charset=utf-8"),
            )
            .mount(&mock)
            .await;

        let url = format!("{}/page", mock.uri());
        // Plain fetch — no goal, no provider, no extraction pass.
        let r = fetch(&url).await.expect("plain fetch should succeed");
        assert_eq!(r.status, 200);
        assert!(
            r.text.contains("Rust ownership rules"),
            "plain fetch text should contain the page content unchanged; got: {}",
            r.text
        );
    }
}
