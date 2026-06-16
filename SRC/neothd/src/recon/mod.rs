//! Operator recon — gated shims over ProjectDiscovery's single-binary recon
//! CLIs for authorized engagements.
//!
//! NEOTH integrates two lightweight, single-binary Go tools by SHELLING OUT
//! (self-contained rule: no embedded scanner, no DB stack) — the same pattern as
//! `gh` ([`crate::tools::github`]) and the cua MCP driver:
//!
//! - [`uncover`] — `projectdiscovery/uncover`: discover exposed hosts via search
//!   engines (Shodan / Censys / FOFA / …). Passive (queries third-party APIs).
//! - [`tlsx`] — `projectdiscovery/tlsx`: TLS/cert intelligence grabber (SAN, CN,
//!   issuer, JARM, cipher, expiry). Active (connects to the target host:port).
//!
//! `ivre/ivre` was evaluated and DELIBERATELY NOT embedded: it's a full
//! self-hosted recon *platform* (Nmap/Masscan/Zeek ingestion + MongoDB/Postgres
//! + a web UI) — wiring it in-binary would break NEOTH's self-contained rule.
//! It belongs as an OPTIONAL external source (query an operator's existing ivre
//! instance) — tracked, not built here.
//!
//! Both tools are GATED (refused under Strict autonomy — NEOTH does nothing
//! external there) and every invocation is WAL-audited via `0xF6 RECON_RUN`
//! (forwarded to the live daemon over audit-RPC, else a one-shot frame — the
//! same audit level as the MCP/computer-use tool band; the raw query/targets
//! are hashed, never logged). Args are passed as an explicit argv (never a shell
//! line) and validated so an operator/LLM-supplied value can't smuggle a CLI flag.

pub mod tlsx;
pub mod uncover;

use anyhow::Result;
use std::path::PathBuf;

/// Locate a recon binary on `$PATH` (with the Windows `.exe` suffix). `None`
/// when it isn't installed — callers turn that into an install hint.
pub fn locate(bin: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    };
    std::env::var_os("PATH")?
        .to_str()
        .map(|s| s.to_string())?
        .split(if cfg!(windows) { ';' } else { ':' })
        .map(|dir| std::path::Path::new(dir).join(&exe))
        .find(|p| p.exists())
}

/// Reject an operator/LLM-supplied token that would be parsed as a CLI FLAG by
/// the downstream tool (argv-level flag injection), plus shell metacharacters as
/// belt-and-suspenders. Args are passed as an explicit argv so this is the only
/// realistic injection surface.
pub fn validate_arg(kind: &str, v: &str) -> Result<()> {
    let t = v.trim();
    if t.is_empty() {
        anyhow::bail!("recon: empty {kind}");
    }
    if t.starts_with('-') {
        anyhow::bail!("recon: {kind} {v:?} may not start with '-' (flag injection)");
    }
    if t.len() > 512 {
        anyhow::bail!("recon: {kind} too long ({} chars, max 512)", t.len());
    }
    if t.chars().any(|c| matches!(c, '\0' | '\n' | '\r')) {
        anyhow::bail!("recon: {kind} contains a control character");
    }
    Ok(())
}

/// Tracing breadcrumb for a recon invocation (live operator log). The durable
/// audit anchor is the `0xF6 RECON_RUN` WAL frame emitted by `cli::recon`
/// (daemon-forwarded over audit-RPC, else one-shot) — same level as the MCP
/// tool band. This is the human-readable complement, not the audit of record.
pub fn audit(tool: &str, summary: &str, results: usize) {
    tracing::info!(tool, summary, results, "recon: tool invoked");
}
