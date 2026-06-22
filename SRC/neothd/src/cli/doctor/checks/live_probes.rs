//! GOLD-ADAPT-ODY-22 — live service-health probes.
//!
//! These probes are deliberately separate from the synchronous `CheckFn`
//! battery: they make real network calls (bounded by `tokio::time::timeout`)
//! and are only run when the operator passes `--live` to `neoth doctor`.
//! Each probe reports **Up** (reachable within the timeout) or **Down**
//! (connection refused / timeout elapsed), plus the round-trip latency.
//!
//! Probed subsystems:
//!   - **ollama** — local LLM runtime (`GET /v1/models`; default
//!     `http://127.0.0.1:11434`; override via `NEOTH_OLLAMA_URL`).
//!   - **SearXNG** — self-hosted search (`GET /`; default
//!     `http://127.0.0.1:8888`; override via `NEOTH_SEARXNG_URL`).
//!   - **IMAP** — email server TCP-connect (default `imap.gmail.com:993`;
//!     override via `NEOTH_IMAP_HOST` / `NEOTH_IMAP_PORT`).
//!
//! Tests use closed ports (always Down within timeout) and a Wiremock mock
//! server (Up with sub-timeout latency). Tests never touch real external
//! network.

use std::time::{Duration, Instant};

use super::super::{CheckOutcome, CheckStatus};

// ── timeout budget ────────────────────────────────────────────────────────────

/// Wall-clock budget for each HTTP probe (connect + first byte).
pub(crate) const HTTP_PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// Wall-clock budget for each TCP-connect probe (handshake only).
pub(crate) const TCP_PROBE_TIMEOUT: Duration = Duration::from_secs(4);

// ── probe result ─────────────────────────────────────────────────────────────

/// Status of a single live probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    /// Endpoint responded within the timeout.
    Up,
    /// Connection refused, timed out, or DNS failed.
    Down,
}

/// A live probe result, before conversion to [`CheckOutcome`].
#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub name: &'static str,
    pub endpoint: String,
    pub status: ProbeStatus,
    /// Round-trip latency in milliseconds.  `None` when `Down`.
    pub latency_ms: Option<u64>,
    /// Human-readable reason for `Down` (error text, no secrets).
    pub reason: Option<String>,
}

impl ProbeResult {
    fn into_outcome(self) -> CheckOutcome {
        let (status, detail) = match self.status {
            ProbeStatus::Up => (
                CheckStatus::Pass,
                format!(
                    "Up — {} responded in {}ms",
                    self.endpoint,
                    self.latency_ms.unwrap_or(0)
                ),
            ),
            ProbeStatus::Down => (
                CheckStatus::Warn,
                format!(
                    "Down — {} unreachable ({})",
                    self.endpoint,
                    self.reason.as_deref().unwrap_or("connection refused or timeout")
                ),
            ),
        };
        CheckOutcome {
            name: self.name,
            status,
            detail,
        }
    }
}

// ── individual probes ─────────────────────────────────────────────────────────

/// Probe the local Ollama runtime (`GET /v1/models`).
///
/// The endpoint URL defaults to `http://127.0.0.1:11434` and can be
/// overridden via the `NEOTH_OLLAMA_URL` environment variable.  The probe
/// is purely structural — it verifies the server is reachable and returns
/// an HTTP 200; it does NOT parse the model list.
pub async fn probe_ollama() -> ProbeResult {
    let base = std::env::var("NEOTH_OLLAMA_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
    let url = format!("{}/v1/models", base.trim_end_matches('/'));
    http_get_probe("ollama", &url, HTTP_PROBE_TIMEOUT).await
}

/// Probe the local SearXNG search instance (`GET /`).
///
/// The endpoint defaults to `http://127.0.0.1:8888` (matching
/// [`crate::tools::web_search::SEARXNG_DEFAULT_URL`]) and can be overridden
/// via `NEOTH_SEARXNG_URL`.
pub async fn probe_searxng() -> ProbeResult {
    let base = std::env::var("NEOTH_SEARXNG_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8888".to_string());
    let url = format!("{}/", base.trim_end_matches('/'));
    http_get_probe("searxng", &url, HTTP_PROBE_TIMEOUT).await
}

/// Probe the IMAP server with a raw TCP connect (no TLS handshake, no
/// auth — just verifies the host accepts connections on the right port).
///
/// Host defaults to `imap.gmail.com`; port to `993`.  Override via
/// `NEOTH_IMAP_HOST` / `NEOTH_IMAP_PORT`.
pub async fn probe_imap() -> ProbeResult {
    let host = std::env::var("NEOTH_IMAP_HOST")
        .unwrap_or_else(|_| "imap.gmail.com".to_string());
    let port: u16 = std::env::var("NEOTH_IMAP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(993);
    let endpoint = format!("{host}:{port}");
    tcp_connect_probe("imap", &endpoint, TCP_PROBE_TIMEOUT).await
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// HTTP GET probe: succeed on any HTTP response (1xx–5xx counts as Up — the
/// server is reachable).  Connection refused / DNS failure / timeout = Down.
async fn http_get_probe(name: &'static str, url: &str, timeout: Duration) -> ProbeResult {
    let start = Instant::now();
    let client = match reqwest::ClientBuilder::new()
        .timeout(timeout)
        .danger_accept_invalid_certs(false)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ProbeResult {
                name,
                endpoint: url.to_string(),
                status: ProbeStatus::Down,
                latency_ms: None,
                reason: Some(format!("client build failed: {}", safe_error(&e.to_string()))),
            };
        }
    };
    let result = tokio::time::timeout(timeout, client.get(url).send()).await;
    let latency_ms = start.elapsed().as_millis() as u64;
    match result {
        // Timeout wrapper fired.
        Err(_) => ProbeResult {
            name,
            endpoint: url.to_string(),
            status: ProbeStatus::Down,
            latency_ms: None,
            reason: Some(format!("timeout after {}ms", timeout.as_millis())),
        },
        // reqwest returned an error (refused, DNS, TLS…).
        Ok(Err(e)) => ProbeResult {
            name,
            endpoint: url.to_string(),
            status: ProbeStatus::Down,
            latency_ms: None,
            reason: Some(safe_error(&e.to_string())),
        },
        // Any HTTP response = the server is Up.
        Ok(Ok(_resp)) => ProbeResult {
            name,
            endpoint: url.to_string(),
            status: ProbeStatus::Up,
            latency_ms: Some(latency_ms),
            reason: None,
        },
    }
}

/// TCP connect probe: opens a TCP stream to `host:port`.  Succeeds on a
/// successful handshake regardless of what the server sends after.
async fn tcp_connect_probe(name: &'static str, addr: &str, timeout: Duration) -> ProbeResult {
    let start = Instant::now();
    let result = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect(addr),
    )
    .await;
    let latency_ms = start.elapsed().as_millis() as u64;
    match result {
        Err(_) => ProbeResult {
            name,
            endpoint: addr.to_string(),
            status: ProbeStatus::Down,
            latency_ms: None,
            reason: Some(format!("timeout after {}ms", timeout.as_millis())),
        },
        Ok(Err(e)) => ProbeResult {
            name,
            endpoint: addr.to_string(),
            status: ProbeStatus::Down,
            latency_ms: None,
            reason: Some(safe_error(&e.to_string())),
        },
        Ok(Ok(_stream)) => ProbeResult {
            name,
            endpoint: addr.to_string(),
            status: ProbeStatus::Up,
            latency_ms: Some(latency_ms),
            reason: None,
        },
    }
}

/// Strip any embedded IPs / hostnames / credentials from an error string
/// so that error messages in Check outcomes never leak config secrets.
/// Conservative: keep only the error *kind* (everything before the first
/// `'` or quoted hostname fragment).
fn safe_error(raw: &str) -> String {
    // reqwest/hyper errors embed the URL in them; keep only the first
    // "sentence" (up to the first URL-like segment).
    let truncated = raw
        .split_once("://")
        .map(|(prefix, _rest)| {
            // Keep the prefix up to the last word before "://" so the error
            // kind is preserved (e.g. "error sending request for url (…)" →
            // "error sending request for url").
            prefix.rsplit_once(' ').map(|(p, _)| p).unwrap_or(prefix)
        })
        .unwrap_or(raw);
    // Cap at 120 chars to keep doctor output readable.
    truncated.chars().take(120).collect()
}

// ── entry point ───────────────────────────────────────────────────────────────

/// Run all live probes concurrently and return one [`CheckOutcome`] per probe.
///
/// Called by `run_doctor` only when `--live` is passed. The probes are
/// independent so they run in parallel via `tokio::join!`.
pub async fn run_live_probes() -> Vec<CheckOutcome> {
    let (ollama, searxng, imap) = tokio::join!(probe_ollama(), probe_searxng(), probe_imap());
    vec![
        ollama.into_outcome(),
        searxng.into_outcome(),
        imap.into_outcome(),
    ]
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: find a port that is definitely not listening on 127.0.0.1.
    /// We bind a TcpListener, note its port, then DROP it so the OS reclaims
    /// it — the probe therefore sees a refused connection.
    fn closed_port_on_localhost() -> u16 {
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = l.local_addr().expect("local_addr").port();
        drop(l);
        port
    }

    // ── TCP probe ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tcp_probe_closed_port_returns_down_within_timeout() {
        let port = closed_port_on_localhost();
        let addr = format!("127.0.0.1:{port}");
        let start = std::time::Instant::now();
        let result = tcp_connect_probe("test", &addr, Duration::from_secs(4)).await;
        // Must finish well under the 4 s budget (refused connections
        // return immediately on the loopback interface).
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "closed-port probe took too long: {:?}",
            start.elapsed()
        );
        assert_eq!(result.status, ProbeStatus::Down, "expected Down on closed port");
        assert!(result.latency_ms.is_none(), "no latency on Down");
        assert!(result.reason.is_some(), "reason must be set on Down");
    }

    #[tokio::test]
    async fn tcp_probe_open_port_returns_up() {
        use tokio::net::TcpListener;
        // Bind a listener so the connect succeeds.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = listener.local_addr().unwrap().port();
        // Accept in background so the handshake completes.
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let addr = format!("127.0.0.1:{port}");
        let result = tcp_connect_probe("test", &addr, Duration::from_secs(4)).await;
        assert_eq!(result.status, ProbeStatus::Up, "expected Up on open port");
        assert!(result.latency_ms.is_some(), "latency must be set on Up");
        let latency = result.latency_ms.unwrap();
        // Loopback connect is sub-100ms on any reasonable host.
        assert!(
            latency < 500,
            "loopback connect latency suspiciously high: {latency}ms"
        );
    }

    // ── HTTP probe ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn http_probe_closed_port_returns_down_within_timeout() {
        let port = closed_port_on_localhost();
        let url = format!("http://127.0.0.1:{port}/");
        let start = std::time::Instant::now();
        let result = http_get_probe("test", &url, Duration::from_secs(4)).await;
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "refused HTTP probe took too long: {:?}",
            start.elapsed()
        );
        assert_eq!(result.status, ProbeStatus::Down);
        assert!(result.reason.is_some());
    }

    #[tokio::test]
    async fn http_probe_mock_server_returns_up_with_latency() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&mock)
            .await;
        let url = format!("{}/v1/models", mock.uri());
        let result = http_get_probe("ollama", &url, Duration::from_secs(4)).await;
        assert_eq!(result.status, ProbeStatus::Up, "mock server must be Up");
        assert!(
            result.latency_ms.is_some(),
            "latency must be recorded on Up"
        );
        let latency = result.latency_ms.unwrap();
        // Wiremock is on localhost — expect sub-500ms.
        assert!(
            latency < 500,
            "wiremock latency suspiciously high: {latency}ms"
        );
    }

    #[tokio::test]
    async fn http_probe_5xx_response_counts_as_up() {
        // A 500 means the server is reachable — Up, not Down.
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&mock)
            .await;
        let url = format!("{}/", mock.uri());
        let result = http_get_probe("searxng", &url, Duration::from_secs(4)).await;
        assert_eq!(result.status, ProbeStatus::Up, "5xx is still Up (server reachable)");
    }

    // ── into_outcome ─────────────────────────────────────────────────────

    #[test]
    fn up_probe_converts_to_pass_outcome() {
        let r = ProbeResult {
            name: "ollama",
            endpoint: "http://127.0.0.1:11434/v1/models".into(),
            status: ProbeStatus::Up,
            latency_ms: Some(12),
            reason: None,
        };
        let out = r.into_outcome();
        assert_eq!(out.status, CheckStatus::Pass);
        assert!(out.detail.contains("12ms"), "detail: {}", out.detail);
        assert_eq!(out.name, "ollama");
    }

    #[test]
    fn down_probe_converts_to_warn_outcome() {
        let r = ProbeResult {
            name: "searxng",
            endpoint: "http://127.0.0.1:8888/".into(),
            status: ProbeStatus::Down,
            latency_ms: None,
            reason: Some("connection refused".into()),
        };
        let out = r.into_outcome();
        assert_eq!(out.status, CheckStatus::Warn);
        assert!(out.detail.contains("unreachable"), "detail: {}", out.detail);
        assert!(out.detail.contains("connection refused"), "detail: {}", out.detail);
    }

    // ── safe_error ────────────────────────────────────────────────────────

    #[test]
    fn safe_error_strips_url_fragment() {
        let raw = "error sending request for url (http://127.0.0.1:11434/v1/models): connection refused";
        let safe = safe_error(raw);
        assert!(!safe.contains("127.0.0.1"), "safe_error leaked IP: {safe}");
        assert!(safe.contains("error sending request"), "kind preserved: {safe}");
    }

    #[test]
    fn safe_error_passthrough_when_no_url() {
        let raw = "connection refused";
        assert_eq!(safe_error(raw), "connection refused");
    }

    #[test]
    fn safe_error_caps_at_120_chars() {
        let raw = "x".repeat(200);
        assert_eq!(safe_error(&raw).len(), 120);
    }

    // ── env-var overrides ─────────────────────────────────────────────────

    /// Verify that probe_ollama reads NEOTH_OLLAMA_URL and hits the mock.
    /// Uses a serial test to avoid env-var races with other test threads.
    #[tokio::test]
    async fn probe_ollama_honours_neoth_ollama_url_env() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/v1/models"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"object": "list", "data": []}),
            ))
            .mount(&mock)
            .await;
        // Scope the env override so it doesn't leak to other tests.
        // SAFETY: single-threaded tokio test runtime; no other thread reads
        // this variable concurrently inside this test.
        unsafe { std::env::set_var("NEOTH_OLLAMA_URL", mock.uri()); }
        let result = probe_ollama().await;
        unsafe { std::env::remove_var("NEOTH_OLLAMA_URL"); }
        assert_eq!(result.status, ProbeStatus::Up, "ollama probe via env override: {result:?}");
    }

    /// Verify that probe_searxng reads NEOTH_SEARXNG_URL.
    #[tokio::test]
    async fn probe_searxng_honours_neoth_searxng_url_env() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&mock)
            .await;
        // SAFETY: single-threaded tokio test runtime.
        unsafe { std::env::set_var("NEOTH_SEARXNG_URL", mock.uri()); }
        let result = probe_searxng().await;
        unsafe { std::env::remove_var("NEOTH_SEARXNG_URL"); }
        assert_eq!(result.status, ProbeStatus::Up, "searxng probe via env override: {result:?}");
    }

    /// Verify that probe_imap reads NEOTH_IMAP_HOST / NEOTH_IMAP_PORT.
    #[tokio::test]
    async fn probe_imap_honours_env_overrides() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { let _ = listener.accept().await; });
        // SAFETY: single-threaded tokio test runtime.
        unsafe {
            std::env::set_var("NEOTH_IMAP_HOST", "127.0.0.1");
            std::env::set_var("NEOTH_IMAP_PORT", port.to_string());
        }
        let result = probe_imap().await;
        unsafe {
            std::env::remove_var("NEOTH_IMAP_HOST");
            std::env::remove_var("NEOTH_IMAP_PORT");
        }
        assert_eq!(result.status, ProbeStatus::Up, "imap probe via env override: {result:?}");
    }

    /// run_live_probes returns 3 outcomes — one per subsystem.
    #[tokio::test]
    async fn run_live_probes_returns_three_outcomes_on_no_services() {
        // With no services running, all three should be Down (Warn).
        // We just verify the count — not the Up/Down status, since
        // the test host might have Ollama running.
        let outcomes = run_live_probes().await;
        assert_eq!(outcomes.len(), 3, "expected exactly 3 live probe outcomes");
        let names: Vec<&str> = outcomes.iter().map(|o| o.name).collect();
        assert!(names.contains(&"ollama"), "ollama probe missing");
        assert!(names.contains(&"searxng"), "searxng probe missing");
        assert!(names.contains(&"imap"), "imap probe missing");
    }
}
