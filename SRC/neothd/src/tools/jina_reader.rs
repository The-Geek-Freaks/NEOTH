//! GOLD-ADOPT-26 — zero-config web-to-Markdown via Jina Reader.
//!
//! `https://r.jina.ai/<url>` converts any web page to clean Markdown without
//! requiring an API key. NEOTH's live caller is `neoth fetch <url>`
//! ([`crate::cli::fetch`]) — when an operator asks the CLI to fetch a URL and
//! the `--jina` path is taken, we prepend the Jina Reader prefix and GET the
//! result. (GR-066/096: the previous doc named `neoth ingest <url>`, which has
//! no jina wiring — `cli::fetch` is the real and only caller.)
//!
//! The caller is responsible for SSRF guard (validate_url from
//! `tools::web_fetch`) BEFORE calling into this module — Jina always dials
//! `r.jina.ai`, which is a fixed public proxy, so the SSRF risk is limited
//! to the proxy bouncing back a transformed version of whatever the operator
//! supplied. GR-017/095: we STREAM the response and abort the moment the
//! running total crosses [`JINA_MAX_BYTES`] (plus a fast-path reject on an
//! honest oversized `Content-Length`), so we never buffer more than one chunk
//! past the ceiling — a giant page genuinely can't OOM the daemon (the old
//! code buffered the WHOLE body via `resp.bytes()` before checking the size).
//!
//! **Network path**: this module dials `r.jina.ai` (a fixed public proxy)
//! through `providers::http_client::build_client_no_redirect` — the audited,
//! allowlisted, no-redirect construction site (GR-065) — so it needs no
//! `no_outbound_network` allowlist entry of its own (it never constructs a
//! `reqwest::Client` directly).

use anyhow::{Context, Result};

use crate::providers::http_client;
use crate::tools::external_http::{
    ExternalHttpAuthorizer, ExternalHttpRequest, ExternalHttpSurface,
};

/// Jina Reader base URL. Append the target URL directly.
pub const JINA_READER_BASE: &str = "https://r.jina.ai/";

/// Hard ceiling on the raw bytes read from the Jina proxy response.
/// A page transformed to Markdown is typically far smaller than 500 KiB;
/// anything larger is likely a crawl error or an unusually large document.
pub const JINA_MAX_BYTES: usize = 500_000;

/// User-Agent sent to Jina Reader. Identifies NEOTH without leaking any
/// operator-specific information.
const JINA_UA: &str = "NEOTH-ingest/0.1 (+self-hosted; https://r.jina.ai)";

/// Fetch `url` via the Jina Reader proxy and return the Markdown text.
///
/// The caller MUST have already run `tools::web_fetch::validate_url(url)` (or
/// equivalent SSRF guard) on the original URL before this call. This function
/// prepends [`JINA_READER_BASE`] and sends a plain GET — it does NOT re-validate
/// the proxy URL (r.jina.ai is a fixed known host).
///
/// Returns `Err` on non-2xx HTTP status, body exceeding [`JINA_MAX_BYTES`], or
/// any network/parse error. The returned `String` is UTF-8 Markdown text.
pub async fn fetch_via_jina(url: &str) -> Result<String> {
    let config = crate::config::FreedomConfig::load_from_default_path_or_default()?;
    let http = ExternalHttpAuthorizer::interactive(config.autonomy_policy())?;
    fetch_via_jina_at_authorized(JINA_READER_BASE, url, &http).await
}

/// GR-067/151 — testable core of [`fetch_via_jina`]. `base` is the proxy
/// prefix: production passes [`JINA_READER_BASE`]; the unit tests point it at a
/// local wiremock server so the REAL status-check + streaming byte-ceiling +
/// no-redirect path is exercised end-to-end (the old tests only mirrored this
/// function's body against a direct client, leaving the function itself
/// untested).
#[cfg(test)]
async fn fetch_via_jina_at(base: &str, url: &str) -> Result<String> {
    let http = ExternalHttpAuthorizer::test_allow();
    fetch_via_jina_at_authorized(base, url, &http).await
}

async fn fetch_via_jina_at_authorized(
    base: &str,
    url: &str,
    http: &ExternalHttpAuthorizer,
) -> Result<String> {
    let jina_url = format!("{base}{url}");
    let request = ExternalHttpRequest::get(&jina_url, ExternalHttpSurface::JinaReader);
    let permitted_request = request.clone();
    http.execute(request, move |permit| async move {
        permit.require(&permitted_request)?;
        // GR-065 — no-redirect client (the SX-01 norm web_fetch follows): r.jina.ai
        // (a third-party proxy) must not be able to 30x-bounce the fetch to an
        // arbitrary host the SSRF guard never saw.
        let client =
            http_client::build_client_no_redirect().context("jina_reader: build reqwest client")?;
        let mut resp = client
            .get(&jina_url)
            .header("User-Agent", JINA_UA)
            .header("Accept", "text/plain")
            // X-Return-Format: markdown is the documented Jina hint that prefers
            // a clean Markdown rendering over the default plain-text strip.
            .header("X-Return-Format", "markdown")
            .send()
            .await
            .with_context(|| format!("jina_reader: GET {jina_url}"))?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!(
                "jina_reader: Jina Reader returned HTTP {} for {url}",
                status.as_u16()
            );
        }

        // GR-017/095 — fast-path: refuse before reading a single body byte when the
        // server honestly advertises an oversized payload.
        if let Some(len) = resp.content_length()
            && len > JINA_MAX_BYTES as u64
        {
            anyhow::bail!(
                "jina_reader: Content-Length {len} exceeds ceiling {JINA_MAX_BYTES} for {url}"
            );
        }

        // GR-017/095 — stream the body chunk-by-chunk and abort the instant the
        // running total crosses the ceiling, so a giant (or Content-Length-lying)
        // page can never buffer more than one chunk past JINA_MAX_BYTES into RAM.
        let mut body: Vec<u8> = Vec::with_capacity(8 * 1024);
        while let Some(chunk) = resp
            .chunk()
            .await
            .with_context(|| format!("jina_reader: read body for {url}"))?
        {
            if body.len() + chunk.len() > JINA_MAX_BYTES {
                anyhow::bail!(
                    "jina_reader: response body exceeds ceiling {JINA_MAX_BYTES} for {url}"
                );
            }
            body.extend_from_slice(&chunk);
        }

        let text = String::from_utf8_lossy(&body).into_owned();
        Ok(text)
    })
    .await
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper: a wiremock server that serves `body` with `status` on any GET,
    /// plus the `base` URL (with trailing slash) to feed `fetch_via_jina_at`.
    async fn mock_jina(body: &str, status: u16) -> (MockServer, String) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string(body)
                    .insert_header("content-type", "text/plain; charset=utf-8"),
            )
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri());
        (server, base)
    }

    #[test]
    fn jina_url_is_constructed_correctly() {
        let target = "https://example.com/page";
        let expected = format!("{JINA_READER_BASE}{target}");
        assert_eq!(expected, "https://r.jina.ai/https://example.com/page");
    }

    #[tokio::test]
    async fn returns_markdown_body_on_200() {
        // GR-067/151 — exercises the REAL fetch_via_jina_at end-to-end against a
        // mock proxy (not a hand-mirrored client call).
        let (_server, base) = mock_jina("# Hello\n\nThis is Markdown.", 200).await;
        let text = fetch_via_jina_at(&base, "target").await.unwrap();
        assert!(text.contains("Hello"));
        assert!(text.contains("Markdown"));
    }

    #[tokio::test]
    async fn non_200_triggers_error() {
        let (_server, base) = mock_jina("error", 503).await;
        let err = fetch_via_jina_at(&base, "target").await.unwrap_err();
        assert!(
            format!("{err}").contains("503"),
            "a 503 must bail with the status in the message: {err}"
        );
    }

    #[tokio::test]
    async fn jina_client_does_not_follow_redirects() {
        // GR-065: a 302 from r.jina.ai must NOT be chased to an internal target.
        // The no-redirect client surfaces the 302 → fetch_via_jina_at bails
        // (302 is not a success status) instead of fetching 169.254.169.254.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "http://169.254.169.254/"),
            )
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri());
        let err = fetch_via_jina_at(&base, "target").await.unwrap_err();
        assert!(
            format!("{err}").contains("302"),
            "the redirect must surface as a 302 error, not be followed: {err}"
        );
    }

    #[test]
    fn max_bytes_constant_is_sane() {
        // 500 KiB is a reasonable ceiling for a Markdown-rendered page.
        assert_eq!(JINA_MAX_BYTES, 500_000);
    }

    #[test]
    fn jina_reader_base_ends_with_slash() {
        assert!(
            JINA_READER_BASE.ends_with('/'),
            "JINA_READER_BASE must end with / so URL concatenation is correct"
        );
    }

    #[tokio::test]
    async fn sends_correct_accept_and_format_headers() {
        // GR-067/151 — the real fetch must send the documented headers; the mock
        // ONLY answers when they match, so a green result proves they were sent.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("Accept", "text/plain"))
            .and(header("X-Return-Format", "markdown"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .insert_header("content-type", "text/plain"),
            )
            .mount(&server)
            .await;
        let base = format!("{}/", server.uri());
        assert_eq!(fetch_via_jina_at(&base, "target").await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_by_streaming_ceiling() {
        // GR-017/095 — a body over the ceiling must bail (the fix: the old code
        // buffered the whole body via resp.bytes() THEN checked; now we refuse
        // on Content-Length / mid-stream). Proves the OOM-safety claim is real.
        let big = "x".repeat(JINA_MAX_BYTES + 100);
        let (_server, base) = mock_jina(&big, 200).await;
        let err = fetch_via_jina_at(&base, "target").await.unwrap_err();
        assert!(
            format!("{err}").contains("ceiling"),
            "an oversized body must be rejected against the ceiling: {err}"
        );
    }

    #[tokio::test]
    async fn body_exactly_at_ceiling_is_accepted() {
        // GR-017/095 boundary — exactly JINA_MAX_BYTES is NOT over the ceiling,
        // so the streaming reader accepts it (real call, replaces the old
        // tautological byte_ceiling_boundary self-check).
        let at_limit = "x".repeat(JINA_MAX_BYTES);
        let (_server, base) = mock_jina(&at_limit, 200).await;
        let text = fetch_via_jina_at(&base, "target").await.unwrap();
        assert_eq!(text.len(), JINA_MAX_BYTES);
    }
}
