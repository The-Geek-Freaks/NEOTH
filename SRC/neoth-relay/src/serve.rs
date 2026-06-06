//! Minimal HTTP-line-framed serve loop.
//!
//! v0.1 ships a hand-rolled `tokio::net::TcpListener` accepting:
//!   - `POST /register` — JSON body = `RelayRegistration`, response =
//!     JSON `RegistrationOutcome`
//!   - `POST /unregister?cluster=<hex>&peer=<hex>` — response = JSON
//!     `{ "removed": bool }`
//!   - `GET  /status` — JSON `{ "total_peers", "buckets" }`
//!
//! Real axum integration + auth + TLS via Hysteria socket plumbing
//! lands in multi-week follow-ups. This scaffold is deliberately
//! minimal so the relay binary ships + operators can sanity-check
//! the wire protocol against `neothd`'s outbound register call
//! before the production wire arrives.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

use crate::relay::{PeerRoster, RegistrationOutcome, RelayRegistration};

/// Max concurrent connection handlers. Each handler holds a 64 KB read
/// buffer; without a cap an attacker could open unbounded sockets and
/// exhaust daemon memory (GOLD-SEC-17). A permit is acquired BEFORE the
/// handler task is spawned, so the buffer is only allocated once a slot
/// is free.
const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

pub async fn serve(
    addr: SocketAddr,
    roster: Arc<Mutex<PeerRoster>>,
    expected_token: Option<Arc<String>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    info!(bind = %addr, auth = expected_token.is_some(), "neoth-relay listening");
    loop {
        let (mut socket, peer_addr) = listener.accept().await.context("TcpListener::accept")?;
        // Bound concurrency BEFORE spawning so handler buffers stay capped.
        // `acquire_owned` only errors if the semaphore is closed, which we
        // never do — skip the connection defensively if it ever happens.
        let permit = match Arc::clone(&limiter).acquire_owned().await {
            Ok(p) => p,
            Err(_) => continue,
        };
        let roster = Arc::clone(&roster);
        let token = expected_token.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when this task completes
            let token_ref = token.as_deref().map(String::as_str);
            if let Err(e) = handle_one(&mut socket, peer_addr, roster, token_ref).await {
                warn!(peer = %peer_addr, error = %e, "connection handler errored");
            }
        });
    }
}

async fn handle_one(
    socket: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
    roster: Arc<Mutex<PeerRoster>>,
    expected_token: Option<&str>,
) -> Result<()> {
    // Read up to 64 KB. Hyperswarm announce/register payloads are
    // tiny — anything larger is hostile + dropped.
    const MAX_REQUEST_BYTES: usize = 64 * 1024;
    // Slowloris guard (GOLD-SEC-17): a client that opens a socket and
    // then stalls would otherwise hold its concurrency permit forever.
    // Cap the time we wait for the request bytes.
    const READ_TIMEOUT: Duration = Duration::from_secs(10);
    let mut buf = vec![0u8; MAX_REQUEST_BYTES];
    let n = match tokio::time::timeout(READ_TIMEOUT, socket.read(&mut buf)).await {
        Ok(read) => read.context("read request")?,
        Err(_) => {
            warn!(peer = %peer_addr, "request read timed out — dropping connection");
            return Ok(());
        }
    };
    if n == 0 {
        return Ok(());
    }
    buf.truncate(n);
    let text = String::from_utf8_lossy(&buf);
    let response = route(&text, &roster, expected_token).await;
    socket
        .write_all(response.as_bytes())
        .await
        .context("write response")?;
    socket.shutdown().await.ok();
    info!(peer = %peer_addr, bytes = n, "handled connection");
    Ok(())
}

/// A public (non-loopback) bind MUST carry an auth token, otherwise the
/// relay would expose the cluster peer roster to unauthenticated writes
/// and deletes. Returns `true` when the bind would be unsafe — callers
/// must refuse to start in that case (GOLD-SEC-01).
pub fn public_bind_requires_token(addr: &SocketAddr, has_token: bool) -> bool {
    !addr.ip().is_loopback() && !has_token
}

/// Extract the token from an `Authorization: Bearer <token>` header
/// (header name compared case-insensitively). Returns the trimmed token
/// or `None` when the header is absent/empty.
fn extract_bearer(request_text: &str) -> Option<&str> {
    request_text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("authorization") {
            return None;
        }
        let value = value.trim();
        let token = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))?
            .trim();
        if token.is_empty() { None } else { Some(token) }
    })
}

/// Constant-time byte comparison. A length mismatch returns early (the
/// token's length is not a useful secret); equal-length inputs are
/// compared without early-exit to avoid a timing side channel.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parse the request line + dispatch. Returns a complete HTTP/1.1
/// response (status line + headers + body). Pure-string + Mutex —
/// trivially testable without a real socket.
///
/// When `expected_token` is `Some`, EVERY endpoint requires a matching
/// `Authorization: Bearer <token>` header; the check runs before any
/// dispatch so unauthenticated callers can neither mutate the roster nor
/// probe which paths exist (GOLD-SEC-01).
pub async fn route(
    request_text: &str,
    roster: &Arc<Mutex<PeerRoster>>,
    expected_token: Option<&str>,
) -> String {
    if let Some(expected) = expected_token {
        let authorized = extract_bearer(request_text)
            .map(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !authorized {
            return http_response(
                401,
                "application/json",
                &serde_json::json!({ "error": "unauthorized" }).to_string(),
            );
        }
    }
    let request_line = request_text.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path_and_query = parts.next().unwrap_or("");
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };
    let body = request_text.split("\r\n\r\n").nth(1).unwrap_or("");

    match (method, path) {
        ("POST", "/register") => handle_register(body, roster).await,
        ("POST", "/unregister") => handle_unregister(query, roster).await,
        ("GET", "/status") => handle_status(roster).await,
        _ => http_response(
            404,
            "application/json",
            &serde_json::json!({
                "error": "not_found",
                "method": method,
                "path": path,
            })
            .to_string(),
        ),
    }
}

async fn handle_register(body: &str, roster: &Arc<Mutex<PeerRoster>>) -> String {
    let reg: RelayRegistration = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return http_response(
                400,
                "application/json",
                &serde_json::json!({
                    "error": "bad_body",
                    "detail": e.to_string(),
                })
                .to_string(),
            );
        }
    };
    let mut r = roster.lock().await;
    let outcome = r.register(reg);
    let (status, body) = match &outcome {
        RegistrationOutcome::Registered => (200, serde_json::json!({ "outcome": "registered" })),
        RegistrationOutcome::Refreshed => (200, serde_json::json!({ "outcome": "refreshed" })),
        RegistrationOutcome::RejectedAtCap { cap } => (
            429,
            serde_json::json!({ "outcome": "rejected_at_cap", "cap": cap }),
        ),
        RegistrationOutcome::Malformed { reason } => (
            400,
            serde_json::json!({ "outcome": "malformed", "reason": reason }),
        ),
    };
    http_response(status, "application/json", &body.to_string())
}

async fn handle_unregister(query: &str, roster: &Arc<Mutex<PeerRoster>>) -> String {
    let mut cluster = "";
    let mut peer = "";
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        if k == "cluster" {
            cluster = v;
        } else if k == "peer" {
            peer = v;
        }
    }
    if cluster.is_empty() || peer.is_empty() {
        return http_response(
            400,
            "application/json",
            &serde_json::json!({
                "error": "missing_query",
                "expected": "cluster=<hex>&peer=<hex>",
            })
            .to_string(),
        );
    }
    let removed = roster.lock().await.unregister(cluster, peer);
    http_response(
        200,
        "application/json",
        &serde_json::json!({ "removed": removed }).to_string(),
    )
}

async fn handle_status(roster: &Arc<Mutex<PeerRoster>>) -> String {
    let r = roster.lock().await;
    http_response(
        200,
        "application/json",
        &serde_json::json!({
            "total_peers": r.total_peers(),
            "buckets": r.buckets.len(),
            "max_peers_per_key": r.max_peers_per_key,
        })
        .to_string(),
    )
}

pub fn http_response(status: u16, content_type: &str, body: &str) -> String {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    fn fixture_register_body(cluster: &str, peer: &str) -> String {
        let reg = RelayRegistration {
            cluster_key_hex: cluster.into(),
            peer_pub_key_hex: peer.into(),
            instance_label: "demo-laptop".into(),
            listen_port: 4242,
            registered_at_unix: 1,
        };
        serde_json::to_string(&reg).unwrap()
    }

    fn fixture_request(method: &str, path: &str, body: &str) -> String {
        format!(
            "{method} {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn fresh_roster() -> Arc<Mutex<PeerRoster>> {
        Arc::new(Mutex::new(PeerRoster::new(5)))
    }

    #[tokio::test]
    async fn register_then_status_round_trip() {
        let roster = fresh_roster();
        let body = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        let req = fixture_request("POST", "/register", &body);
        let resp = route(&req, &roster, None).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"outcome\":\"registered\""));

        let status_req = fixture_request("GET", "/status", "");
        let status_resp = route(&status_req, &roster, None).await;
        assert!(status_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(status_resp.contains("\"total_peers\":1"));
    }

    #[tokio::test]
    async fn register_then_unregister() {
        let roster = fresh_roster();
        let body = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        let _ = route(&fixture_request("POST", "/register", &body), &roster, None).await;
        let unreg_path = format!("/unregister?cluster={}&peer={}", hex64(0xaa), hex64(0x01));
        let resp = route(&fixture_request("POST", &unreg_path, ""), &roster, None).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"removed\":true"));
    }

    #[tokio::test]
    async fn unregister_returns_false_when_absent() {
        let roster = fresh_roster();
        let path = format!("/unregister?cluster={}&peer={}", hex64(0xaa), hex64(0x01));
        let resp = route(&fixture_request("POST", &path, ""), &roster, None).await;
        assert!(resp.contains("\"removed\":false"));
    }

    #[tokio::test]
    async fn unregister_rejects_missing_query() {
        let roster = fresh_roster();
        let resp = route(&fixture_request("POST", "/unregister", ""), &roster, None).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(resp.contains("missing_query"));
    }

    #[tokio::test]
    async fn register_malformed_body_returns_400() {
        let roster = fresh_roster();
        let resp = route(&fixture_request("POST", "/register", "not json"), &roster, None).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(resp.contains("bad_body"));
    }

    #[tokio::test]
    async fn register_at_cap_returns_429() {
        let roster = Arc::new(Mutex::new(PeerRoster::new(1)));
        let body1 = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        let body2 = fixture_register_body(&hex64(0xaa), &hex64(0x02));
        let _ = route(&fixture_request("POST", "/register", &body1), &roster, None).await;
        let resp = route(&fixture_request("POST", "/register", &body2), &roster, None).await;
        assert!(resp.starts_with("HTTP/1.1 429 Too Many Requests"));
        assert!(resp.contains("rejected_at_cap"));
        assert!(resp.contains("\"cap\":1"));
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let roster = fresh_roster();
        let resp = route(&fixture_request("GET", "/nope", ""), &roster, None).await;
        assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn malformed_registration_via_http_returns_400() {
        let roster = fresh_roster();
        // Valid JSON but invalid hex length (cluster_key_hex).
        let reg = RelayRegistration {
            cluster_key_hex: "ZZ".into(),
            peer_pub_key_hex: hex64(0x01),
            instance_label: "x".into(),
            listen_port: 1,
            registered_at_unix: 1,
        };
        let body = serde_json::to_string(&reg).unwrap();
        let resp = route(&fixture_request("POST", "/register", &body), &roster, None).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(resp.contains("malformed"));
    }

    #[test]
    fn http_response_pins_content_length_header() {
        let body = "{\"k\":\"v\"}";
        let resp = http_response(200, "application/json", body);
        assert!(resp.contains(&format!("Content-Length: {}", body.len())));
        assert!(resp.contains("Connection: close"));
    }

    fn fixture_request_auth(method: &str, path: &str, body: &str, auth: Option<&str>) -> String {
        let auth_line = match auth {
            Some(tok) => format!("Authorization: Bearer {tok}\r\n"),
            None => String::new(),
        };
        format!(
            "{method} {path} HTTP/1.1\r\n{auth_line}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn route_with_token_rejects_missing_auth() {
        let roster = fresh_roster();
        let body = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        let req = fixture_request_auth("POST", "/register", &body, None);
        let resp = route(&req, &roster, Some("s3cr3t")).await;
        assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(resp.contains("unauthorized"));
        // Roster must NOT have been mutated by an unauthenticated call.
        let status = route(&fixture_request_auth("GET", "/status", "", Some("s3cr3t")), &roster, Some("s3cr3t")).await;
        assert!(status.contains("\"total_peers\":0"));
    }

    #[tokio::test]
    async fn route_with_token_accepts_correct_bearer() {
        let roster = fresh_roster();
        let body = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        let req = fixture_request_auth("POST", "/register", &body, Some("s3cr3t"));
        let resp = route(&req, &roster, Some("s3cr3t")).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"outcome\":\"registered\""));
    }

    #[tokio::test]
    async fn route_with_token_rejects_wrong_bearer() {
        let roster = fresh_roster();
        let body = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        let req = fixture_request_auth("POST", "/register", &body, Some("wrong"));
        let resp = route(&req, &roster, Some("s3cr3t")).await;
        assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[tokio::test]
    async fn route_with_token_auth_gates_unknown_path_before_404() {
        let roster = fresh_roster();
        // Unauthenticated probe of an unknown path must 401 (not 404),
        // so callers cannot enumerate which paths exist.
        let resp = route(&fixture_request_auth("GET", "/secret-admin", "", None), &roster, Some("s3cr3t")).await;
        assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[tokio::test]
    async fn route_without_token_skips_auth() {
        let roster = fresh_roster();
        let body = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        // No expected token configured (loopback dev mode) — request with
        // no auth header still succeeds.
        let resp = route(&fixture_request("POST", "/register", &body), &roster, None).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn extract_bearer_is_case_insensitive_and_trims() {
        let req = "GET /status HTTP/1.1\r\nauthorization:   Bearer  tok123 \r\n\r\n";
        assert_eq!(extract_bearer(req), Some("tok123"));
        let req2 = "GET /status HTTP/1.1\r\nAUTHORIZATION: bearer abc\r\n\r\n";
        assert_eq!(extract_bearer(req2), Some("abc"));
        let none = "GET /status HTTP/1.1\r\n\r\n";
        assert_eq!(extract_bearer(none), None);
        let empty = "GET /status HTTP/1.1\r\nAuthorization: Bearer \r\n\r\n";
        assert_eq!(extract_bearer(empty), None);
    }

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        assert!(constant_time_eq(b"hunter2", b"hunter2"));
        assert!(!constant_time_eq(b"hunter2", b"hunter3"));
        assert!(!constant_time_eq(b"short", b"longer-token"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn public_bind_requires_token_only_for_non_loopback() {
        use std::net::SocketAddr;
        let loopback: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let public: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        // Loopback never requires a token.
        assert!(!public_bind_requires_token(&loopback, false));
        assert!(!public_bind_requires_token(&loopback, true));
        // Public bind without a token is unsafe; with a token it is fine.
        assert!(public_bind_requires_token(&public, false));
        assert!(!public_bind_requires_token(&public, true));
    }
}
