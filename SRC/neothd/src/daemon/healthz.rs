//! Local HTTP listener for `/healthz` + `/metrics` — Phase 33c BS-1 follow-up.
//!
//! Binds to `127.0.0.1:<port>` (localhost-only by design, per the self-
//! contained rule — no public endpoint, no firewall coordination needed).
//! The operator points monitoring stacks or `curl` at it directly.
//!
//! The HTTP parser here is intentionally minimal — read the request line,
//! pick a route, drain the rest, write a fixed response. No headers
//! interpretation beyond Content-Length on outbound. No keep-alive. One
//! request per connection. This avoids pulling in `hyper` + `tower` for a
//! 4-route diagnostic surface.
//!
//! ## Routes
//!
//! | Method | Path        | Body                                          |
//! |--------|-------------|-----------------------------------------------|
//! | `GET`  | `/`         | `NEOTH <ver> — see /healthz or /metrics\n`    |
//! | `GET`  | `/healthz`  | JSON snapshot via `observability::snapshot`   |
//! | `GET`  | `/metrics`  | Prometheus text via `Snapshot::render_prometheus` |
//! | any    | other       | 404 `not found`                               |

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::FreedomConfig;
use crate::daemon::observability;
use crate::providers::meter::Meter;
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Configuration captured at spawn-time. `home` is the resolved `~/.neoth/`
/// directory the snapshot reader sweeps. `config` is cloned so the listener
/// task has no shared lock on the parent's `FreedomConfig`.
#[derive(Clone)]
pub struct HealthzConfig {
    pub home: PathBuf,
    pub config: Option<Arc<FreedomConfig>>,
    /// Live rolling-window provider Meter. When present, `/healthz` and
    /// `/metrics` enrich the snapshot with `MeterStats`. None during
    /// `neoth status` CLI runs or in tests without the daemon meter wired.
    #[doc(alias = "provider_meter")]
    pub meter: Option<Meter>,
}

/// Spawn the listener as a tokio task. Returns the `JoinHandle` so the
/// caller can `.abort()` on shutdown. The accept loop has no graceful-stop
/// signal — the listener socket is closed when the task is dropped, and
/// any in-flight per-connection task finishes on its own.
pub fn spawn(addr: SocketAddr, cfg: HealthzConfig) -> JoinHandle<Result<()>> {
    tokio::spawn(async move { serve(addr, cfg).await })
}

/// Run the listener inline. Useful when the caller already owns a task
/// (tests, single-binary smoke tools). Returns only on bind error — the
/// accept loop runs forever until the task is aborted.
pub async fn serve(addr: SocketAddr, cfg: HealthzConfig) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind healthz listener on {addr}"))?;
    tracing::info!(addr = %listener.local_addr()?, "healthz listener up");
    run_accept_loop(listener, cfg).await
}

/// Bind the listener but expose the OS-assigned port to the caller before
/// returning the future. Used in tests so we don't race against port reuse.
pub async fn bind_and_serve(
    addr: SocketAddr,
    cfg: HealthzConfig,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind healthz listener on {addr}"))?;
    let local = listener.local_addr()?;
    let task = tokio::spawn(async move { run_accept_loop(listener, cfg).await });
    Ok((local, task))
}

async fn run_accept_loop(listener: TcpListener, cfg: HealthzConfig) -> Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    let _ = handle_one(stream, &cfg).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "healthz accept failed");
            }
        }
    }
}

const MAX_REQUEST_BYTES: usize = 8 * 1024;

async fn handle_one(mut stream: TcpStream, cfg: &HealthzConfig) -> Result<()> {
    let mut buf = [0u8; MAX_REQUEST_BYTES];
    let mut total = 0usize;

    // Read up to MAX_REQUEST_BYTES or until we see `\r\n\r\n`. Browser-style
    // requests fit easily; longer ones get truncated, which is fine since we
    // ignore everything past the request line anyway.
    loop {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            break;
        }
        total += n;
        if total >= MAX_REQUEST_BYTES {
            break;
        }
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let request_line = parse_request_line(&buf[..total]);
    let response = render_route(request_line, cfg);
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await.ok();
    Ok(())
}

/// Extracted from the raw request — `(method, path)`. Empty values on parse
/// failure (we'll 400 those).
fn parse_request_line(bytes: &[u8]) -> (String, String) {
    let nl = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    let line = String::from_utf8_lossy(&bytes[..nl]);
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    (method, path)
}

fn render_route((method, path): (String, String), cfg: &HealthzConfig) -> String {
    if method.is_empty() || path.is_empty() {
        return http_response(400, "text/plain", "bad request\n");
    }
    if method != "GET" {
        return http_response(405, "text/plain", "method not allowed\n");
    }
    // Strip query string before matching — `/healthz?from=loki` still maps.
    let path_only = path.split('?').next().unwrap_or(&path);

    match path_only {
        "/" => http_response(
            200,
            "text/plain",
            &format!(
                "NEOTH {} — see /healthz or /metrics\n",
                env!("CARGO_PKG_VERSION"),
            ),
        ),
        "/healthz" => match build_snapshot(cfg) {
            Ok(snap) => http_response(200, "application/json", &snap.render_json()),
            Err(e) => http_response(500, "text/plain", &format!("snapshot error: {e}\n")),
        },
        "/metrics" => match build_snapshot(cfg) {
            Ok(snap) => http_response(200, "text/plain; version=0.0.4", &snap.render_prometheus()),
            Err(e) => http_response(500, "text/plain", &format!("snapshot error: {e}\n")),
        },
        // R-03 (Session 24) — operator-poll tps snapshot. Single-shot
        // JSON; future GUI/SSE clients poll on whatever cadence they
        // need (1Hz during streaming / 10Hz idle per the spec, but
        // the cadence is client-driven so this endpoint stays a
        // simple GET). Returns `{output_tps, input_tps, p50_ms,
        // p95_ms, sample_count, header_line}` — `header_line` is
        // the operator-readable one-liner that the chat UI can drop
        // verbatim into its status bar.
        "/metrics/tps" => render_tps_json(cfg),
        _ => http_response(404, "text/plain", "not found\n"),
    }
}

/// R-03 — minimal JSON snapshot of the rolling-window TPS metrics.
/// Returns `{}` (empty object) when no meter is wired so the GUI
/// renders an inert status bar instead of erroring out.
fn render_tps_json(cfg: &HealthzConfig) -> String {
    let Some(meter) = cfg.meter.as_ref() else {
        return http_response(200, "application/json", "{}\n");
    };
    let snap = meter.snapshot();
    let header = snap
        .chat_header_line()
        .unwrap_or_else(|| "[meter] (no samples)".into());
    let body = serde_json::json!({
        "output_tps": snap.output_tps,
        "input_tps": snap.input_tps,
        "p50_ms": snap.p50_latency_ms,
        "p95_ms": snap.p95_latency_ms,
        "sample_count": snap.sample_count,
        "header_line": header,
    });
    http_response(200, "application/json", &format!("{body}\n"))
}

/// Pick the right snapshot builder based on whether the operator wired
/// a live Meter into the listener. When `meter` is `None` (CLI status
/// path), we emit the bare snapshot; when `Some` (daemon path), we enrich
/// it with the rolling-window provider stats.
fn build_snapshot(cfg: &HealthzConfig) -> anyhow::Result<observability::Snapshot> {
    match cfg.meter.as_ref() {
        Some(meter) => observability::snapshot_with_meter(&cfg.home, cfg.config.as_deref(), meter),
        None => observability::snapshot(&cfg.home, cfg.config.as_deref()),
    }
}

fn http_response(status: u16, content_type: &str, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    )
}

// This file is allowlisted in `tests/no_outbound_network.rs` because
// production code only uses `TcpStream` via `listener.accept()` (inbound),
// and the test client below connects to a local listener spawned by the
// same test — never to the real network.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;

    async fn raw_get(addr: SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    fn cfg_for(dir: &tempfile::TempDir) -> HealthzConfig {
        HealthzConfig {
            home: dir.path().to_path_buf(),
            config: None,
            meter: None,
        }
    }

    #[tokio::test]
    async fn root_returns_help_text() {
        let dir = tempdir().unwrap();
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg_for(&dir),
        )
        .await
        .unwrap();
        let body = raw_get(addr, "/").await;
        assert!(body.contains("HTTP/1.1 200 OK"));
        assert!(body.contains("NEOTH"));
        task.abort();
    }

    #[tokio::test]
    async fn healthz_returns_json_snapshot() {
        let dir = tempdir().unwrap();
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg_for(&dir),
        )
        .await
        .unwrap();
        let body = raw_get(addr, "/healthz").await;
        assert!(body.contains("HTTP/1.1 200 OK"));
        assert!(body.contains("application/json"));
        assert!(body.contains("\"daemon_version\""));
        task.abort();
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_format() {
        let dir = tempdir().unwrap();
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg_for(&dir),
        )
        .await
        .unwrap();
        let body = raw_get(addr, "/metrics").await;
        assert!(body.contains("HTTP/1.1 200 OK"));
        assert!(body.contains("neoth_wal_segments"));
        assert!(body.contains("# TYPE neoth_wal_segments gauge"));
        task.abort();
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let dir = tempdir().unwrap();
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg_for(&dir),
        )
        .await
        .unwrap();
        let body = raw_get(addr, "/nope").await;
        assert!(body.contains("HTTP/1.1 404 Not Found"));
        task.abort();
    }

    #[tokio::test]
    async fn query_string_does_not_break_route_match() {
        let dir = tempdir().unwrap();
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg_for(&dir),
        )
        .await
        .unwrap();
        let body = raw_get(addr, "/metrics?from=loki&job=neoth").await;
        assert!(body.contains("HTTP/1.1 200 OK"));
        assert!(body.contains("neoth_wal_segments"));
        task.abort();
    }

    #[tokio::test]
    async fn post_is_rejected_with_405() {
        let dir = tempdir().unwrap();
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg_for(&dir),
        )
        .await
        .unwrap();
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"POST /healthz HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.contains("HTTP/1.1 405"));
        task.abort();
    }

    #[test]
    fn parse_request_line_picks_method_and_path() {
        let req = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n";
        let (method, path) = parse_request_line(req);
        assert_eq!(method, "GET");
        assert_eq!(path, "/healthz");
    }

    #[test]
    fn parse_request_line_handles_empty_input() {
        let (method, path) = parse_request_line(b"");
        assert_eq!(method, "");
        assert_eq!(path, "");
    }

    #[test]
    fn http_response_includes_content_length() {
        let r = http_response(200, "text/plain", "hello\n");
        assert!(r.contains("HTTP/1.1 200 OK"));
        assert!(r.contains("Content-Length: 6"));
        assert!(r.contains("\r\n\r\nhello\n"));
    }

    #[test]
    fn render_route_root_returns_help() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let cfg = HealthzConfig {
            home: dir.path().to_path_buf(),
            config: None,
            meter: None,
        };
        let r = render_route(("GET".into(), "/".into()), &cfg);
        assert!(r.contains("HTTP/1.1 200 OK"));
        assert!(r.contains("NEOTH"));
    }

    #[test]
    fn render_route_unknown_returns_404() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let cfg = HealthzConfig {
            home: dir.path().to_path_buf(),
            config: None,
            meter: None,
        };
        let r = render_route(("GET".into(), "/nope".into()), &cfg);
        assert!(r.contains("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn build_snapshot_with_meter_includes_provider_stats() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let meter = crate::providers::meter::Meter::with_default_window();
        meter.record(40, 20, std::time::Duration::from_millis(120));
        let cfg = HealthzConfig {
            home: dir.path().to_path_buf(),
            config: None,
            meter: Some(meter),
        };
        let snap = build_snapshot(&cfg).expect("build_snapshot");
        let stats = snap.provider_meter.expect("meter stats present");
        assert_eq!(stats.sample_count, 1);
        assert!(stats.p50_latency_ms > 0.0);
    }

    #[test]
    fn build_snapshot_without_meter_omits_provider_stats() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let cfg = HealthzConfig {
            home: dir.path().to_path_buf(),
            config: None,
            meter: None,
        };
        let snap = build_snapshot(&cfg).expect("build_snapshot");
        assert!(snap.provider_meter.is_none());
    }

    #[test]
    fn render_route_post_rejected_405() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let cfg = HealthzConfig {
            home: dir.path().to_path_buf(),
            config: None,
            meter: None,
        };
        let r = render_route(("POST".into(), "/healthz".into()), &cfg);
        assert!(r.contains("HTTP/1.1 405"));
    }

    // ── R-03 (Session 24) /metrics/tps JSON endpoint ──────────────────

    #[tokio::test]
    async fn r_03_metrics_tps_returns_empty_object_when_no_meter_wired() {
        let dir = tempdir().unwrap();
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg_for(&dir),
        )
        .await
        .unwrap();
        let body = raw_get(addr, "/metrics/tps").await;
        assert!(body.contains("HTTP/1.1 200 OK"));
        assert!(body.contains("application/json"));
        // GUI client renders an inert status bar instead of crashing.
        assert!(body.contains("{}"), "no-meter response must be empty JSON: {body}");
        task.abort();
    }

    #[tokio::test]
    async fn r_03_metrics_tps_returns_snapshot_fields_when_meter_wired() {
        let dir = tempdir().unwrap();
        let meter = crate::providers::meter::Meter::with_default_window();
        meter.record(120, 600, std::time::Duration::from_millis(800));

        let cfg = HealthzConfig {
            home: dir.path().to_path_buf(),
            config: None,
            meter: Some(meter),
        };
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg,
        )
        .await
        .unwrap();
        let body = raw_get(addr, "/metrics/tps").await;
        assert!(body.contains("HTTP/1.1 200 OK"));
        assert!(body.contains("application/json"));
        // All 6 fields must appear so a GUI consumer doesn't have to
        // probe for which version of the daemon it's talking to.
        for field in [
            "\"output_tps\"",
            "\"input_tps\"",
            "\"p50_ms\"",
            "\"p95_ms\"",
            "\"sample_count\"",
            "\"header_line\"",
        ] {
            assert!(body.contains(field), "field {field} missing from body: {body}");
        }
        // header_line must carry the operator-readable format the GUI
        // can drop verbatim — sanity that the formatter wiring didn't
        // get bypassed.
        assert!(body.contains("[meter]"), "header_line must contain the [meter] prefix");
        task.abort();
    }

    #[tokio::test]
    async fn r_03_metrics_tps_unknown_path_still_404() {
        let dir = tempdir().unwrap();
        let (addr, task) = bind_and_serve(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            cfg_for(&dir),
        )
        .await
        .unwrap();
        // Sibling path that doesn't match must still 404.
        let body = raw_get(addr, "/metrics/nope").await;
        assert!(body.contains("HTTP/1.1 404"), "got: {body}");
        task.abort();
    }
}
