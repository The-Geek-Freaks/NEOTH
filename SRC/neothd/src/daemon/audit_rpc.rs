//! AUDIT-RPC-01 — loopback audit-RPC listener + client.
//!
//! ## Why this exists
//! The daemon owns the SINGLE WAL writer (the single-writer invariant). So when
//! `neoth serve` is running, a one-shot CLI (`neoth os launch`, `fs read/write`,
//! `lease …`) cannot open a second writer to record its own gated action — it
//! passes `writer: None` and the action runs gated but UN-audited. This module
//! closes that gap: the one-shot CLI forwards an *audit intent* to the running
//! daemon over a loopback socket, and the daemon (which owns the writer)
//! appends the frame on its behalf.
//!
//! ## Security model — anti-audit-poisoning
//! The audit chain is NEOTH's verifiable-loyalty wedge, so a forged frame is a
//! real threat. Defenses, all fail-closed:
//!   1. **Loopback-only.** The listener binds `127.0.0.1:0`; every connection's
//!      peer is re-checked `is_loopback()` at accept time (403 otherwise).
//!   2. **Per-boot bearer token.** 32 bytes from the OS CSPRNG, base64url, freshly
//!      minted on every daemon start (a token captured before a restart is dead
//!      after it), written `0600` on unix / DPAPI-wrapped+DACL on Windows via the
//!      same `write_key_securely` path as the WAL HMAC key. Only a SAME-UID
//!      process can read it. Checked constant-time; 5-strike cooldown on failure.
//!   3. **Compile-time event-type allowlist.** Only the nine one-shot-emittable
//!      permission-band codes (`0xA5..=0xAD`) are acceptable over IPC; anything
//!      else (daemon-lifecycle, cluster, quota, …) is refused 422. The allowlist
//!      is a `const` — not operator-tunable, since an operator who could widen it
//!      could already forge frames directly.
//!   4. **Body cap** 4096 bytes (audit payloads are small structured JSON).
//!
//! ## Residual (documented, accepted)
//! A process running as the SAME OS user can read the token file and submit
//! frames — but a same-uid process is already inside NEOTH's trust boundary (it
//! could read the WAL HMAC key, or simply BE `neoth`). The token closes the
//! cross-uid forgery vector, which is the real boundary. Same precedent as the
//! WAL HMAC key (`wal/compaction.rs`).
//!
//! Gated behind `freedom.yaml::audit_rpc.enabled` (default OFF). The listener is
//! spawned from `cli/serve.rs` and aborted on shutdown; the sidecar is removed
//! by [`SidecarGuard`] on drop.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::n8n_api::auth::AuthCooldown;
use crate::n8n_api::{constant_time_token_eq, extract_bearer_token};
use crate::wal::events::{EVENT_TYPE_AUDIT_RPC_ACCEPT, EVENT_TYPE_AUDIT_RPC_REJECT};
use crate::wal::writer::WalWriterHandle;

/// The ONLY event types a one-shot CLI may forward over the audit-RPC channel —
/// the permission-band codes that are lost today when the daemon owns the
/// writer: autonomy-level changes (`neoth autonomy set`), lease
/// grant/expire/revoke, and OS file read/write + app-launch (with their denial
/// variants). A compile-time `const`, deliberately NOT a config toggle:
/// widening it is a code change that goes through review, never a runtime flag
/// an attacker (or a careless operator) could flip.
pub const ALLOWED_CLIENT_EVENT_TYPES: &[u8] = &[
    0xA2, // LEVEL_ELEVATED   — `neoth autonomy set` raised the level
    0xA3, // LEVEL_DEROGATED  — `neoth autonomy set` lowered the level
    0xA5, // LEASE_GRANTED
    0xA6, // LEASE_EXPIRED
    0xA7, // LEASE_REVOKED
    0xA8, // OS_FILE_READ
    0xA9, // OS_FILE_DENIED
    0xAA, // OS_FILE_WRITE
    0xAB, // OS_FILE_WRITE_DENIED
    0xAC, // OS_APP_LAUNCH
    0xAD, // OS_APP_LAUNCH_DENIED
];

/// Max inbound request size (headers + body). Audit payloads are small.
const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// Max body size accepted (tighter than the request cap).
const MAX_BODY_BYTES: usize = 4096;
/// Per-connection wall-clock budget. A client that opens a connection and then
/// stalls (slowloris) is dropped after this — bounds resource pinning.
const CONNECTION_TIMEOUT_SECS: u64 = 5;
/// Cap on concurrent in-flight connections. A local process can't exhaust the
/// daemon's FD table / task pool by holding connections open — excess
/// connections are dropped immediately (the one-shot falls back to its
/// un-audited path, fail-open on availability).
const MAX_CONCURRENT_CONNS: usize = 32;

/// `true` iff `event_type` may be forwarded by a one-shot CLI.
pub fn is_allowed_client_event(event_type: u8) -> bool {
    ALLOWED_CLIENT_EVENT_TYPES.contains(&event_type)
}

// ── Token (per-boot bearer secret) ───────────────────────────────────────────

/// `~/.neoth/audit_rpc_token`.
pub fn rpc_token_path(home: &Path) -> PathBuf {
    home.join("audit_rpc_token")
}

/// Mint a FRESH per-boot token (32 bytes CSPRNG → base64url-NOPAD, 43 chars) and
/// persist it securely (`0600` unix / DPAPI+DACL windows). Per-boot on purpose:
/// a token captured before a daemon restart is useless after it. Fail-closed if
/// the OS RNG is unavailable (a predictable token defeats the whole gate).
pub fn init_rpc_token(home: &Path) -> Result<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .context("OS RNG unavailable — refusing to mint a weak audit-RPC token")?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    std::fs::create_dir_all(home)
        .with_context(|| format!("create neoth home {}", home.display()))?;
    let path = rpc_token_path(home);
    crate::wal::compaction::write_key_securely(&path, token.as_bytes())
        .with_context(|| format!("write audit-RPC token {}", path.display()))?;
    Ok(token)
}

/// Read the token a daemon minted (DPAPI-unwrapped on Windows). Used by the
/// one-shot CLI client to prove same-uid legitimacy.
pub fn read_rpc_token(home: &Path) -> Result<String> {
    let path = rpc_token_path(home);
    let body =
        std::fs::read(&path).with_context(|| format!("read audit-RPC token {}", path.display()))?;
    let raw = crate::wal::compaction::maybe_unwrap_dpapi(&body, &path)?;
    Ok(String::from_utf8(raw)
        .context("audit-RPC token is not valid UTF-8")?
        .trim()
        .to_string())
}

// ── Sidecar (port advertisement) ─────────────────────────────────────────────

/// `~/.neoth/audit_rpc.port`.
pub fn sidecar_path(home: &Path) -> PathBuf {
    home.join("audit_rpc.port")
}

/// Write the sidecar advertising the bound port + the daemon PID + a short
/// token hint (first 8 chars only — NEVER the full token; the client reads that
/// from the token file). The PID lets the client reject a STALE sidecar from a
/// crashed daemon whose port may have been recycled (sending the token to that
/// recycled-port process would disclose it). Best-effort secure perms via the
/// shared key-writer.
pub fn write_sidecar(home: &Path, port: u16, pid: u32, token: &str) -> Result<()> {
    std::fs::create_dir_all(home)
        .with_context(|| format!("create neoth home {}", home.display()))?;
    let hint: String = token.chars().take(8).collect();
    let body =
        serde_json::to_vec(&serde_json::json!({ "port": port, "pid": pid, "token_hint": hint }))
            .context("serialize audit-RPC sidecar")?;
    let path = sidecar_path(home);
    crate::wal::compaction::write_key_securely(&path, &body)
        .with_context(|| format!("write audit-RPC sidecar {}", path.display()))?;
    Ok(())
}

/// Read the advertised `(port, pid)`. Returns an error if the sidecar is
/// absent/garbled (the caller then falls back to the un-audited path —
/// fail-open on AVAILABILITY but never on integrity).
pub fn read_sidecar(home: &Path) -> Result<(u16, u32)> {
    let path = sidecar_path(home);
    let body =
        std::fs::read(&path).with_context(|| format!("read audit-RPC sidecar {}", path.display()))?;
    let raw = crate::wal::compaction::maybe_unwrap_dpapi(&body, &path)?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).context("parse audit-RPC sidecar JSON")?;
    let port = v
        .get("port")
        .and_then(|p| p.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
        .context("audit-RPC sidecar has no valid port")?;
    let pid = v
        .get("pid")
        .and_then(|p| p.as_u64())
        .and_then(|p| u32::try_from(p).ok())
        .context("audit-RPC sidecar has no valid pid")?;
    Ok((port, pid))
}

/// Remove the sidecar (best-effort). Called on daemon shutdown.
pub fn remove_sidecar(home: &Path) {
    let _ = std::fs::remove_file(sidecar_path(home));
    let _ = std::fs::remove_file(rpc_token_path(home));
}

/// RAII guard that removes the sidecar + token on drop (daemon shutdown).
pub struct SidecarGuard {
    home: PathBuf,
}

impl SidecarGuard {
    pub fn new(home: PathBuf) -> Self {
        Self { home }
    }
}

impl Drop for SidecarGuard {
    fn drop(&mut self) {
        remove_sidecar(&self.home);
    }
}

// ── Listener ─────────────────────────────────────────────────────────────────

/// Spawn-time state for the audit-RPC listener.
#[derive(Clone)]
pub struct AuditRpcState {
    pub token: String,
    pub writer: WalWriterHandle,
    pub cooldown: Arc<AuthCooldown>,
}

/// Bind `127.0.0.1:0`, return the OS-assigned address + the accept-loop handle.
/// Mirrors [`crate::daemon::healthz::bind_and_serve`].
pub async fn bind_and_serve(state: AuditRpcState) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let addr: SocketAddr = (std::net::Ipv4Addr::LOCALHOST, 0).into();
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind audit-RPC listener on {addr}"))?;
    let local = listener.local_addr()?;
    let task = tokio::spawn(async move { run_accept_loop(listener, state).await });
    Ok((local, task))
}

async fn run_accept_loop(listener: TcpListener, state: AuditRpcState) -> Result<()> {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNS));
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Drop the connection immediately if we're at the concurrency
                // cap — never queue (queuing is what a slowloris flood wants).
                let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
                    tracing::warn!("audit-RPC at connection cap; dropping connection");
                    continue;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit; // released when this task ends
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(CONNECTION_TIMEOUT_SECS),
                        handle_one(stream, peer, &state),
                    )
                    .await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "audit-RPC accept failed");
            }
        }
    }
}

/// Parsed request: method, path, bearer token, body bytes.
struct Parsed {
    method: String,
    path: String,
    bearer: Option<String>,
    body: Vec<u8>,
}

/// Read + parse a single HTTP request (request line + headers + Content-Length
/// body), capped. Returns `None` on a malformed/oversized request.
async fn read_request(stream: &mut TcpStream) -> Option<Parsed> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut header_end: Option<usize> = None;
    // Read until headers complete or cap hit.
    while buf.len() < MAX_REQUEST_BYTES {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
    }
    let header_end = header_end?;
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut rl = request_line.split_whitespace();
    let method = rl.next().unwrap_or("").to_string();
    let path = rl.next().unwrap_or("").to_string();

    let mut bearer = None;
    let mut content_length = 0usize;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization:") {
            // Value is everything after the first colon (case-preserving).
            let val = line.split_once(':').map(|(_, v)| v).unwrap_or("").trim();
            bearer = extract_bearer_token(val).map(|t| t.to_string());
        } else if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse::<usize>().unwrap_or(0);
        }
    }
    if content_length > MAX_BODY_BYTES {
        return None;
    }
    // Body bytes already buffered after the header terminator.
    let mut body: Vec<u8> = buf[header_end..].to_vec();
    while body.len() < content_length && body.len() < MAX_BODY_BYTES {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Some(Parsed {
        method,
        path,
        bearer,
        body,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn handle_one(mut stream: TcpStream, peer: SocketAddr, state: &AuditRpcState) -> Result<()> {
    // Layer 1 — loopback peer guard (defense-in-depth vs a future bind regression).
    if !peer.ip().is_loopback() {
        let _ = stream
            .write_all(http_response(403, "non-loopback peer rejected").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    let source = peer.ip().to_string();

    let Some(req) = read_request(&mut stream).await else {
        let _ = stream
            .write_all(http_response(400, "malformed or oversized request").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    };

    // Only POST /audit.
    if req.method != "POST" || req.path.split('?').next().unwrap_or("") != "/audit" {
        let _ = stream
            .write_all(http_response(404, "not found").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    // Layer 2 — bearer auth (cooldown → constant-time compare). Auth failures
    // are NOT WAL-recorded (avoids a forged-frame paradox + WAL spam).
    let now = std::time::Instant::now();
    if state.cooldown.is_locked(&source, now) {
        let _ = stream
            .write_all(http_response(429, "auth cooldown active").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    let ok = req
        .bearer
        .as_deref()
        .is_some_and(|t| constant_time_token_eq(t, &state.token));
    if !ok {
        state.cooldown.record_failure(&source, now);
        let _ = stream
            .write_all(http_response(401, "unauthorized").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    state.cooldown.record_success(&source);

    // Body: {"event_type": u8, "payload_b64": "<base64-standard>"}.
    let parsed: Result<(u8, Vec<u8>), &str> = (|| {
        let v: serde_json::Value = serde_json::from_slice(&req.body).map_err(|_| "bad json")?;
        let event_type = v
            .get("event_type")
            .and_then(|e| e.as_u64())
            .and_then(|e| u8::try_from(e).ok())
            .ok_or("missing event_type")?;
        let payload_b64 = v
            .get("payload_b64")
            .and_then(|p| p.as_str())
            .ok_or("missing payload_b64")?;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .map_err(|_| "bad payload base64")?;
        Ok((event_type, payload))
    })();

    let (event_type, payload) = match parsed {
        Ok(x) => x,
        Err(reason) => {
            emit_reject(state, reason).await;
            let _ = stream
                .write_all(http_response(400, reason).as_bytes())
                .await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    // Layer 3 — compile-time event-type allowlist (anti-poisoning gate).
    if !is_allowed_client_event(event_type) {
        emit_reject(state, "event_type_not_allowed").await;
        let _ = stream
            .write_all(http_response(422, "event_type_not_allowed").as_bytes())
            .await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    // Forward the frame into the daemon's single writer.
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    match state.writer.append(header, payload).await {
        Ok(offset) => {
            emit_accept(state, event_type).await;
            let body = format!("{{\"ok\":true,\"offset\":{offset}}}");
            let _ = stream
                .write_all(http_response_json(200, &body).as_bytes())
                .await;
        }
        Err(e) => {
            let _ = stream
                .write_all(http_response(500, &format!("append failed: {e}")).as_bytes())
                .await;
        }
    }
    let _ = stream.shutdown().await;
    Ok(())
}

async fn emit_accept(state: &AuditRpcState, forwarded_event_type: u8) {
    let payload = serde_json::to_vec(&serde_json::json!({
        "forwarded_event_type": forwarded_event_type,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_AUDIT_RPC_ACCEPT, &payload).build();
    let _ = state.writer.append(header, payload).await;
}

async fn emit_reject(state: &AuditRpcState, reason: &str) {
    let payload = serde_json::to_vec(&serde_json::json!({ "reason": reason }))
        .unwrap_or_else(|_| b"{}".to_vec());
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_AUDIT_RPC_REJECT, &payload).build();
    let _ = state.writer.append(header, payload).await;
}

fn http_response(status: u16, msg: &str) -> String {
    http_response_json(status, &format!("{{\"error\":{:?}}}", msg))
}

fn http_response_json(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    )
}

// ── Client (one-shot CLI side) ───────────────────────────────────────────────
//
// This file is allowlisted in `tests/no_outbound_network.rs`: the client below
// uses `TcpStream::connect` ONLY to the daemon's own loopback audit-RPC port
// (read from the same-uid sidecar), never to a remote host — it is local
// same-host IPC, not network egress.

#[derive(Debug, thiserror::Error)]
pub enum AuditRpcClientError {
    #[error("audit-RPC unavailable: {0}")]
    Unavailable(String),
    #[error("audit-RPC daemon refused the frame: HTTP {0}")]
    Refused(u16),
}

/// Forward an audit intent to the running daemon. `payload` is the exact frame
/// payload the one-shot would have written itself. Returns `Ok(())` once the
/// daemon confirms the append (HTTP 200). On ANY availability failure (no
/// sidecar / no token / connect refused) returns `Unavailable` so the caller can
/// fall back to its existing un-audited path — the action itself is already
/// gated; this only governs whether the audit frame lands.
/// Cheap reachability proxy for the daemon's audit-RPC listener: the sidecar
/// is present AND the daemon that wrote it is still alive. The daemon writes
/// the sidecar only AFTER binding the listener and removes it on shutdown, so
/// sidecar-present + pid-alive ≈ listener-up. Used by the fail-closed
/// pre-flight; a real connect would be more thorough but heavier.
pub fn is_reachable(home: &Path) -> bool {
    matches!(read_sidecar(home), Ok((_, pid)) if crate::daemon::pidfile::pid_is_alive(pid))
}

/// AUDIT-RPC-01 #1 — fail-closed pre-flight for one-shot PERMISSION actions.
///
/// When `required` (`audit_rpc.required_for_oneshot_permission_events`) is set
/// AND a daemon is live (it owns the WAL writer, so the one-shot can't audit
/// locally) AND the daemon's audit-RPC listener is NOT reachable, returns an
/// error so the caller REFUSES the action — a permission action must never run
/// without an audit record under a compliance/proof posture. No-op when the
/// flag is off, no daemon is live (the one-shot writes its own frame), or the
/// listener is reachable.
pub fn enforce_required_audit(required: bool, daemon_live: bool, home: &Path) -> Result<()> {
    if required && daemon_live && !is_reachable(home) {
        anyhow::bail!(
            "audit_rpc.required_for_oneshot_permission_events is set, a daemon owns the WAL, but \
             its audit-RPC listener is unreachable — refusing this permission action so it isn't \
             performed un-audited. Enable `audit_rpc` + restart the daemon, stop the daemon, or \
             clear the required flag."
        );
    }
    Ok(())
}

pub async fn try_post_audit_frame(
    home: &Path,
    event_type: u8,
    payload: &[u8],
) -> std::result::Result<(), AuditRpcClientError> {
    let (port, pid) = read_sidecar(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    // Anti-token-disclosure: a crashed daemon may have left a stale sidecar
    // whose port the OS recycled to an UNRELATED process — sending the bearer
    // token there would leak it. Only proceed if the daemon that wrote the
    // sidecar is still alive.
    if !crate::daemon::pidfile::pid_is_alive(pid) {
        return Err(AuditRpcClientError::Unavailable(format!(
            "stale audit-RPC sidecar (daemon pid {pid} not alive)"
        )));
    }
    let token = read_rpc_token(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let body = format!(
        "{{\"event_type\":{event_type},\"payload_b64\":{:?}}}",
        payload_b64
    );
    let addr: SocketAddr = (std::net::Ipv4Addr::LOCALHOST, port).into();
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| AuditRpcClientError::Unavailable(format!("connect {addr}: {e}")))?;
    let req = format!(
        "POST /audit HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| AuditRpcClientError::Unavailable(format!("write: {e}")))?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .await
        .map_err(|e| AuditRpcClientError::Unavailable(format!("read: {e}")))?;
    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status == 200 {
        Ok(())
    } else {
        Err(AuditRpcClientError::Refused(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn raw_post(addr: SocketAddr, token: Option<&str>, body: &str) -> u16 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "POST /audit HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        resp.split_whitespace()
            .nth(1)
            .and_then(|x| x.parse().ok())
            .unwrap_or(0)
    }

    #[test]
    fn allowlist_contains_exactly_the_oneshot_codes() {
        assert_eq!(ALLOWED_CLIENT_EVENT_TYPES.len(), 11);
        // Autonomy-level changes (`neoth autonomy set`) + the lease/OS one-shots.
        for c in [0xA2u8, 0xA3] {
            assert!(is_allowed_client_event(c), "{c:#x} (autonomy) must be allowed");
        }
        for c in 0xA5u8..=0xADu8 {
            assert!(is_allowed_client_event(c), "{c:#x} must be allowed");
        }
        // Daemon-lifecycle / cluster / quota codes are NOT forwardable — and the
        // autonomy codes must NOT bleed into the neighbouring 0xA0/0xA1/0xA4.
        for c in [0x10u8, 0x15, 0xA0, 0xA1, 0xA4, 0xAE, 0xAF, 0xE0, 0xF0] {
            assert!(!is_allowed_client_event(c), "{c:#x} must be refused");
        }
    }

    #[test]
    fn is_reachable_is_false_without_a_sidecar() {
        let dir = tempdir().unwrap();
        assert!(!is_reachable(dir.path()), "no sidecar ⇒ not reachable");
    }

    #[test]
    fn enforce_required_audit_only_bails_when_required_live_and_unreachable() {
        let dir = tempdir().unwrap(); // no sidecar ⇒ unreachable
        // Flag off ⇒ always Ok (best-effort posture).
        assert!(enforce_required_audit(false, true, dir.path()).is_ok());
        // No daemon ⇒ Ok (the one-shot writes its own frame locally).
        assert!(enforce_required_audit(true, false, dir.path()).is_ok());
        // Required + daemon live + listener unreachable ⇒ fail-closed.
        assert!(enforce_required_audit(true, true, dir.path()).is_err());
    }

    #[test]
    fn token_round_trips_through_secure_write() {
        let dir = tempdir().unwrap();
        let t = init_rpc_token(dir.path()).unwrap();
        assert_eq!(t.len(), 43);
        assert_eq!(read_rpc_token(dir.path()).unwrap(), t);
    }

    #[test]
    fn sidecar_round_trips_port_without_full_token() {
        let dir = tempdir().unwrap();
        write_sidecar(dir.path(), 54321, std::process::id(), "supersecrettoken").unwrap();
        assert_eq!(read_sidecar(dir.path()).unwrap().0, 54321);
        // The full token must NEVER be in the sidecar — only an 8-char hint.
        let raw = std::fs::read(sidecar_path(dir.path())).unwrap();
        let body = crate::wal::compaction::maybe_unwrap_dpapi(&raw, &sidecar_path(dir.path())).unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("supersec"));
        assert!(!s.contains("supersecrettoken"));
    }

    #[test]
    fn sidecar_guard_removes_on_drop() {
        let dir = tempdir().unwrap();
        let t = init_rpc_token(dir.path()).unwrap();
        write_sidecar(dir.path(), 1, std::process::id(), &t).unwrap();
        {
            let _g = SidecarGuard::new(dir.path().to_path_buf());
            assert!(sidecar_path(dir.path()).exists());
        }
        assert!(!sidecar_path(dir.path()).exists());
        assert!(!rpc_token_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn valid_token_appends_allowed_frame_and_emits_accept() {
        use crate::wal::events::EVENT_TYPE_OS_APP_LAUNCH;
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, wal_join) = crate::wal::spawn(seg.clone()).unwrap();
        let state = AuditRpcState {
            token: "tok-valid".into(),
            writer: writer.clone(),
            cooldown: Arc::new(AuthCooldown::new()),
        };
        let (addr, task) = bind_and_serve(state).await.unwrap();

        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(br#"{"program":"/bin/x"}"#);
        let body = format!("{{\"event_type\":{},\"payload_b64\":{:?}}}", EVENT_TYPE_OS_APP_LAUNCH, payload_b64);
        let status = raw_post(addr, Some("tok-valid"), &body).await;
        assert_eq!(status, 200);

        task.abort();
        drop(writer);
        wal_join.await.ok();

        // The forwarded 0xAC frame AND the 0xAE accept frame both landed.
        let bytes = tokio::fs::read(&seg).await.unwrap();
        let mut types = Vec::new();
        let mut cur = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        while cur < bytes.len() {
            let Ok(f) = crate::wal::frame::decode_frame(&bytes[cur..]) else {
                break;
            };
            types.push(f.header.event_type);
            cur = cur.saturating_add(f.header.total_len as usize);
        }
        assert!(types.contains(&EVENT_TYPE_OS_APP_LAUNCH), "forwarded frame landed");
        assert!(types.contains(&EVENT_TYPE_AUDIT_RPC_ACCEPT), "accept marker landed");
    }

    #[tokio::test]
    async fn wrong_token_is_401_and_writes_no_frame() {
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, wal_join) = crate::wal::spawn(seg.clone()).unwrap();
        let state = AuditRpcState {
            token: "tok-valid".into(),
            writer: writer.clone(),
            cooldown: Arc::new(AuthCooldown::new()),
        };
        let (addr, task) = bind_and_serve(state).await.unwrap();
        let body = r#"{"event_type":168,"payload_b64":"e30="}"#;
        let status = raw_post(addr, Some("tok-WRONG"), body).await;
        assert_eq!(status, 401);
        // missing token too
        assert_eq!(raw_post(addr, None, body).await, 401);
        task.abort();
        drop(writer);
        wal_join.await.ok();
        // No frame written (auth failures are not audited).
        let bytes = tokio::fs::read(&seg).await.unwrap();
        assert!(crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..]).is_err());
    }

    #[tokio::test]
    async fn blocked_event_type_is_422_and_emits_reject() {
        use crate::wal::events::EVENT_TYPE_AUDIT_RPC_REJECT;
        let segdir = tempdir().unwrap();
        let seg = segdir.path().join("000001.wal");
        let (writer, wal_join) = crate::wal::spawn(seg.clone()).unwrap();
        let state = AuditRpcState {
            token: "tok".into(),
            writer: writer.clone(),
            cooldown: Arc::new(AuthCooldown::new()),
        };
        let (addr, task) = bind_and_serve(state).await.unwrap();
        // 0x10 (daemon lifecycle) is NOT forwardable.
        let body = r#"{"event_type":16,"payload_b64":"e30="}"#;
        let status = raw_post(addr, Some("tok"), body).await;
        assert_eq!(status, 422);
        task.abort();
        drop(writer);
        wal_join.await.ok();
        let bytes = tokio::fs::read(&seg).await.unwrap();
        let f = crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_AUDIT_RPC_REJECT);
    }

    #[tokio::test]
    async fn client_round_trips_against_a_live_listener() {
        use crate::wal::events::EVENT_TYPE_OS_FILE_READ;
        let home = tempdir().unwrap();
        let seg_dir = tempdir().unwrap();
        let seg = seg_dir.path().join("000001.wal");
        let token = init_rpc_token(home.path()).unwrap();
        let (writer, wal_join) = crate::wal::spawn(seg.clone()).unwrap();
        let state = AuditRpcState {
            token: token.clone(),
            writer: writer.clone(),
            cooldown: Arc::new(AuthCooldown::new()),
        };
        let (addr, task) = bind_and_serve(state).await.unwrap();
        // The test process is alive, so the client's pid-liveness check passes.
        write_sidecar(home.path(), addr.port(), std::process::id(), &token).unwrap();

        // The CLIENT path: read sidecar+token, connect, POST.
        try_post_audit_frame(home.path(), EVENT_TYPE_OS_FILE_READ, br#"{"path":"/etc/hosts","bytes":42}"#)
            .await
            .expect("client round-trip must succeed end-to-end");

        task.abort();
        drop(writer);
        wal_join.await.ok();
        let bytes = tokio::fs::read(&seg).await.unwrap();
        let f = crate::wal::frame::decode_frame(&bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..]).unwrap();
        assert_eq!(f.header.event_type, EVENT_TYPE_OS_FILE_READ);
    }

    #[tokio::test]
    async fn client_unavailable_when_no_sidecar() {
        let home = tempdir().unwrap();
        let r = try_post_audit_frame(home.path(), 0xA8, b"{}").await;
        assert!(matches!(r, Err(AuditRpcClientError::Unavailable(_))));
    }

    #[tokio::test]
    async fn client_rejects_stale_sidecar_with_dead_pid() {
        // A sidecar left by a crashed daemon (dead pid) must NOT be trusted —
        // the recycled port could belong to an unrelated process, and sending
        // the bearer token there would disclose it.
        let home = tempdir().unwrap();
        init_rpc_token(home.path()).unwrap();
        // 999_999_999 is above any OS pid_max (and stays positive as an i32
        // pid_t, so the unix `kill(pid,0)` check can't alias to the -1
        // "whole process group" sentinel) — reliably a dead pid on all OSes.
        write_sidecar(home.path(), 5000, 999_999_999, "tok").unwrap();
        let r = try_post_audit_frame(home.path(), 0xA8, b"{}").await;
        assert!(
            matches!(r, Err(AuditRpcClientError::Unavailable(ref m)) if m.contains("stale")),
            "a dead-pid sidecar must be refused as stale, got {r:?}"
        );
    }
}
