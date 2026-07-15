//! AUDIT-RPC-01 — the one-shot CLI client side.
//!
//! This file is allowlisted in `tests/no_outbound_network.rs`: the client below
//! uses `TcpStream::connect` ONLY to the daemon's own loopback audit-RPC port
//! (read from the same-uid sidecar), never to a remote host — it is local
//! same-host IPC, not network egress.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::Result;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::sidecar::read_sidecar;
use super::token::read_rpc_token;

#[derive(Debug, thiserror::Error)]
pub enum AuditRpcClientError {
    #[error("audit-RPC unavailable: {0}")]
    Unavailable(String),
    #[error("audit-RPC daemon refused the frame: HTTP {0}")]
    Refused(u16),
}

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

/// Forward an audit intent to the running daemon. `payload` is the exact frame
/// payload the one-shot would have written itself. Returns `Ok(())` once the
/// daemon confirms the append (HTTP 200). On ANY availability failure (no
/// sidecar / no token / connect refused) returns `Unavailable` so the caller can
/// fall back to its existing un-audited path — the action itself is already
/// gated; this only governs whether the audit frame lands.
pub async fn try_post_audit_frame(
    home: &Path,
    event_type: u8,
    payload: &[u8],
) -> std::result::Result<(), AuditRpcClientError> {
    try_post_audit_frame_with_subtype(home, event_type, 0, payload).await
}

/// Subtype-aware audit forwarder. Existing callers keep using
/// [`try_post_audit_frame`] (subtype zero); EXTENDED events must use this
/// function with `(event_type=0x00, event_subtype!=0)`. The server validates
/// the exact pair against its compile-time allowlist.
pub async fn try_post_audit_frame_with_subtype(
    home: &Path,
    event_type: u8,
    event_subtype: u8,
    payload: &[u8],
) -> std::result::Result<(), AuditRpcClientError> {
    let (port, pid) =
        read_sidecar(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    // Anti-token-disclosure: a crashed daemon may have left a stale sidecar
    // whose port the OS recycled to an UNRELATED process — sending the bearer
    // token there would leak it. Only proceed if the daemon that wrote the
    // sidecar is still alive.
    if !crate::daemon::pidfile::pid_is_alive(pid) {
        return Err(AuditRpcClientError::Unavailable(format!(
            "stale audit-RPC sidecar (daemon pid {pid} not alive)"
        )));
    }
    let token =
        read_rpc_token(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
    let body = format!(
        "{{\"event_type\":{event_type},\"event_subtype\":{event_subtype},\"payload_b64\":{:?}}}",
        payload_b64,
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

/// Shared same-uid loopback POST to the daemon's audit-RPC listener (same
/// sidecar + bearer-token auth + staleness guard as [`try_post_audit_frame`]).
/// Returns `(status, full_response)`. Used by the D34 FULL-AUTO token verbs.
async fn post_rpc(
    home: &Path,
    path: &str,
    body: &str,
) -> std::result::Result<(u16, String), AuditRpcClientError> {
    let (port, pid) =
        read_sidecar(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    if !crate::daemon::pidfile::pid_is_alive(pid) {
        return Err(AuditRpcClientError::Unavailable(format!(
            "stale audit-RPC sidecar (daemon pid {pid} not alive)"
        )));
    }
    let token =
        read_rpc_token(home).map_err(|e| AuditRpcClientError::Unavailable(e.to_string()))?;
    let addr: SocketAddr = (std::net::Ipv4Addr::LOCALHOST, port).into();
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| AuditRpcClientError::Unavailable(format!("connect {addr}: {e}")))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
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
    Ok((status, resp))
}

/// GR-RESID-D34 — ask the running daemon to mint a single-use, short-TTL
/// FULL-AUTO token. The GUI calls this AFTER its two-step confirm dialog passes,
/// then spawns `neoth autonomy full-auto --gui-confirmed --gui-token <t>`.
/// Returns the token, or `None` if the daemon is unreachable / refuses / the
/// response carries no token.
pub async fn mint_fullauto_token(home: &Path) -> Option<String> {
    let (status, resp) = post_rpc(home, "/fullauto-token/mint", "{}").await.ok()?;
    if status != 200 {
        return None;
    }
    // The JSON body follows the blank header/body separator.
    let body = resp.rsplit("\r\n\r\n").next().unwrap_or("");
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("token")?
        .as_str()
        .map(str::to_string)
}

/// GR-RESID-D34 — validate + CONSUME a FULL-AUTO token at the daemon (the CLI
/// calls this when `--gui-token` is present). `true` iff the daemon confirmed it
/// (HTTP 200, single-use). Any failure (unreachable / expired / wrong / already
/// consumed) → `false`, and the FULL-AUTO bypass is then denied.
pub async fn consume_fullauto_token(home: &Path, token: &str) -> bool {
    let body = format!("{{\"token\":{:?}}}", token);
    matches!(
        post_rpc(home, "/fullauto-token/consume", &body).await,
        Ok((200, _))
    )
}
