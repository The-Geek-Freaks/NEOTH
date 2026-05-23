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

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::relay::{PeerRoster, RegistrationOutcome, RelayRegistration};

pub async fn serve(addr: SocketAddr, roster: Arc<Mutex<PeerRoster>>) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    info!(bind = %addr, "neoth-relay listening");
    loop {
        let (mut socket, peer_addr) = listener.accept().await.context("TcpListener::accept")?;
        let roster = Arc::clone(&roster);
        tokio::spawn(async move {
            if let Err(e) = handle_one(&mut socket, peer_addr, roster).await {
                warn!(peer = %peer_addr, error = %e, "connection handler errored");
            }
        });
    }
}

async fn handle_one(
    socket: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
    roster: Arc<Mutex<PeerRoster>>,
) -> Result<()> {
    // Read up to 64 KB. Hyperswarm announce/register payloads are
    // tiny — anything larger is hostile + dropped.
    const MAX_REQUEST_BYTES: usize = 64 * 1024;
    let mut buf = vec![0u8; MAX_REQUEST_BYTES];
    let n = socket.read(&mut buf).await.context("read request")?;
    if n == 0 {
        return Ok(());
    }
    buf.truncate(n);
    let text = String::from_utf8_lossy(&buf);
    let response = route(&text, &roster).await;
    socket
        .write_all(response.as_bytes())
        .await
        .context("write response")?;
    socket.shutdown().await.ok();
    info!(peer = %peer_addr, bytes = n, "handled connection");
    Ok(())
}

/// Parse the request line + dispatch. Returns a complete HTTP/1.1
/// response (status line + headers + body). Pure-string + Mutex —
/// trivially testable without a real socket.
pub async fn route(request_text: &str, roster: &Arc<Mutex<PeerRoster>>) -> String {
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
            instance_label: "alex-laptop".into(),
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
        let resp = route(&req, &roster).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"outcome\":\"registered\""));

        let status_req = fixture_request("GET", "/status", "");
        let status_resp = route(&status_req, &roster).await;
        assert!(status_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(status_resp.contains("\"total_peers\":1"));
    }

    #[tokio::test]
    async fn register_then_unregister() {
        let roster = fresh_roster();
        let body = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        let _ = route(&fixture_request("POST", "/register", &body), &roster).await;
        let unreg_path = format!("/unregister?cluster={}&peer={}", hex64(0xaa), hex64(0x01));
        let resp = route(&fixture_request("POST", &unreg_path, ""), &roster).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"removed\":true"));
    }

    #[tokio::test]
    async fn unregister_returns_false_when_absent() {
        let roster = fresh_roster();
        let path = format!("/unregister?cluster={}&peer={}", hex64(0xaa), hex64(0x01));
        let resp = route(&fixture_request("POST", &path, ""), &roster).await;
        assert!(resp.contains("\"removed\":false"));
    }

    #[tokio::test]
    async fn unregister_rejects_missing_query() {
        let roster = fresh_roster();
        let resp = route(&fixture_request("POST", "/unregister", ""), &roster).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(resp.contains("missing_query"));
    }

    #[tokio::test]
    async fn register_malformed_body_returns_400() {
        let roster = fresh_roster();
        let resp = route(&fixture_request("POST", "/register", "not json"), &roster).await;
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(resp.contains("bad_body"));
    }

    #[tokio::test]
    async fn register_at_cap_returns_429() {
        let roster = Arc::new(Mutex::new(PeerRoster::new(1)));
        let body1 = fixture_register_body(&hex64(0xaa), &hex64(0x01));
        let body2 = fixture_register_body(&hex64(0xaa), &hex64(0x02));
        let _ = route(&fixture_request("POST", "/register", &body1), &roster).await;
        let resp = route(&fixture_request("POST", "/register", &body2), &roster).await;
        assert!(resp.starts_with("HTTP/1.1 429 Too Many Requests"));
        assert!(resp.contains("rejected_at_cap"));
        assert!(resp.contains("\"cap\":1"));
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let roster = fresh_roster();
        let resp = route(&fixture_request("GET", "/nope", ""), &roster).await;
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
        let resp = route(&fixture_request("POST", "/register", &body), &roster).await;
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
}
