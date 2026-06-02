//! AUDIT-RPC-01 — the per-boot bearer token.
//!
//! 32 bytes from the OS CSPRNG, base64url, freshly minted on every daemon start
//! (a token captured before a restart is dead after it), written `0600` on unix
//! / DPAPI-wrapped+DACL on Windows via the same `write_key_securely` path as the
//! WAL HMAC key — only a SAME-UID process can read it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;

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
