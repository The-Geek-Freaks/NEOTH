//! AUDIT-RPC-01 — the port-advertisement sidecar (`~/.neoth/audit_rpc.port`).
//!
//! The daemon binds `127.0.0.1:0` (OS-assigned) and advertises the bound port +
//! its PID + a short token hint here so a one-shot CLI can find the listener.
//! The PID lets the client reject a STALE sidecar from a crashed daemon whose
//! port the OS may have recycled (sending the token there would disclose it).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::token::rpc_token_path;

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
pub fn write_sidecar(
    home: &Path,
    port: u16,
    pid: u32,
    token: &str,
    endpoint_nonce: &str,
) -> Result<()> {
    if endpoint_nonce.len() != 32
        || !endpoint_nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("audit-RPC endpoint nonce must be 32 lowercase hex characters");
    }
    std::fs::create_dir_all(home)
        .with_context(|| format!("create neoth home {}", home.display()))?;
    let hint: String = token.chars().take(8).collect();
    let body = serde_json::to_vec(&serde_json::json!({
        "port": port,
        "pid": pid,
        "endpoint_nonce": endpoint_nonce,
        "token_hint": hint
    }))
    .context("serialize audit-RPC sidecar")?;
    let path = sidecar_path(home);
    crate::wal::compaction::write_key_securely(&path, &body)
        .with_context(|| format!("write audit-RPC sidecar {}", path.display()))?;
    Ok(())
}

/// Read the advertised `(port, pid, endpoint_nonce)`. Returns an error if the sidecar is
/// absent/garbled (the caller then falls back to the un-audited path —
/// fail-open on AVAILABILITY but never on integrity).
pub fn read_sidecar(home: &Path) -> Result<(u16, u32, String)> {
    let path = sidecar_path(home);
    let body = std::fs::read(&path)
        .with_context(|| format!("read audit-RPC sidecar {}", path.display()))?;
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
    let endpoint_nonce = v
        .get("endpoint_nonce")
        .and_then(|value| value.as_str())
        .filter(|value| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .context("audit-RPC sidecar has no valid endpoint nonce")?;
    Ok((port, pid, endpoint_nonce.to_string()))
}

/// Remove the sidecar (best-effort). Called on daemon shutdown.
pub fn remove_sidecar(home: &Path) {
    let _ = std::fs::remove_file(sidecar_path(home));
    let _ = std::fs::remove_file(rpc_token_path(home));
}

/// RAII guard that removes the sidecar + token on drop (daemon shutdown).
pub struct SidecarGuard {
    home: PathBuf,
    listener_abort: Option<tokio::task::AbortHandle>,
}

impl SidecarGuard {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            listener_abort: None,
        }
    }

    /// Bind discovery cleanup to the listener lifetime. This is used by the
    /// daemon startup path so any later `?` return aborts the already-published
    /// endpoint instead of detaching an undiscoverable task that still owns a
    /// WAL sender.
    pub(crate) fn with_listener(home: PathBuf, listener_abort: tokio::task::AbortHandle) -> Self {
        Self {
            home,
            listener_abort: Some(listener_abort),
        }
    }
}

impl Drop for SidecarGuard {
    fn drop(&mut self) {
        if let Some(abort) = self.listener_abort.take() {
            abort.abort();
        }
        remove_sidecar(&self.home);
    }
}
