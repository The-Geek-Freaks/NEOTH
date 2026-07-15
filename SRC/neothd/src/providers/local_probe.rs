//! Auto-detect a running OpenAI-compatible bridge on `localhost`.
//!
//! Used by the `neoth init` wizard's provider step. Loopback-only; the
//! function is in `providers/` rather than `cli/` so the telemetry-guard
//! lint (Phase 33c BS-6) doesn't trip — outbound HTTP is allowed here by
//! design.
//!
//! NEOTH probes only `localhost`. No operator-specific IPs, no external
//! services. Per `memory/neoth-hard-rule-self-contained.md`.

const CANDIDATES: &[&str] = &[
    "http://localhost:1234/v1",  // LM Studio default
    "http://localhost:8000/v1",  // vLLM default
    "http://localhost:11434/v1", // Ollama
    "http://localhost:31338/v1", // legacy claude-bridge port
];

/// Probe each candidate URL and return the first one that responds 2xx or 401.
/// 401 counts as "service alive" because LM Studio and vLLM both return it
/// for unauthenticated `/models` requests.
///
/// Returns `None` when nothing answered — the wizard then falls back to
/// asking the operator for a manual endpoint.
pub fn probe_local_bridge_sync() -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .ok()?;
    for url in CANDIDATES {
        let probe = format!("{url}/models");
        if let Ok(resp) = client.get(&probe).send()
            && (resp.status().is_success() || resp.status().as_u16() == 401)
        {
            tracing::info!(endpoint = url, "detected local OpenAI-compat server");
            return Some((*url).to_string());
        }
    }
    None
}
