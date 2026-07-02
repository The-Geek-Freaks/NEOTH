//! Anonymisation transforms applied BEFORE federation.
//!
//! All transforms are applied to a mutable `FederatedWindow` value BEFORE
//! it leaves the instance.  No raw IDs, repo URIs, or exact model strings
//! ever reach the submission endpoint.
//!
//! ## Rules (from review brief HIGH/data-protocol — privacy spec)
//!
//! 1. `run_id`, `session_id`, `agent_id`, `task_id` → HMAC-SHA256(local_salt,
//!    original_id) truncated to 16 hex chars.
//! 2. `repo` → `{owner}/{repo}` slug only (strip scheme and host path after
//!    the second slash).
//! 3. `model` → `{provider}/{family}` ("anthropic/claude-3", not the full
//!    version string).  A version suffix MUST NOT appear in federated records.
//! 4. Windows shorter than 60 seconds MUST NOT be submitted (re-identification
//!    via timing).
//! 5. Only pre-approved metrics keys are allowed in the `metrics` object.
//!
//! ## Contributor ID
//!
//! Derived once per installation:
//! `SHA-256(local_secret_salt || repo_slug)` → 64-char hex.
//! Stored in `FreedomConfig::babel.contributor_id` after first derivation.
//! Never changes between submissions from the same instance so results are
//! pseudonymous but consistent (enables per-instance random effects in the
//! mixed-effects model).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::channels::keet_crypto::hmac_sha256;

/// Approved keys in the `metrics` pass-through map.
/// Any key NOT in this set is silently dropped before federation.
pub static APPROVED_METRICS_KEYS: &[&str] = &[
    "tokens_in_total",
    "tokens_out_total",
    "tool_calls_total",
    "fallback_attempts_total",
    "retry_events_total",
    "agent_dispatches_total",
    "context_used_ratio_max",
    "latency_ms_p99",
];

/// Minimum window duration that may be submitted to the federation pool.
pub const MIN_WINDOW_SECS: u64 = 60;

/// Pseudonymous contributor ID: SHA-256(local_salt || repo_slug) → 64-char hex.
/// Stable across submissions from the same installation.
pub fn derive_contributor_id(local_salt: &[u8], repo_slug: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(local_salt);
    h.update(b"\0");
    h.update(repo_slug.as_bytes());
    hex::encode(h.finalize())
}

/// Pseudonymise a field value: HMAC-SHA256(local_salt, original_id), truncated
/// to 16 hex chars.  The truncation to 64-bit output is sufficient for
/// de-duplication within the dataset and too short to reverse the HMAC.
pub fn pseudonymise_id(local_salt: &[u8], original_id: &str) -> String {
    let mut out = [0u8; 32];
    hmac_sha256(local_salt, original_id.as_bytes(), &mut out);
    hex::encode(&out[..8]) // 16 hex chars = 8 bytes
}

/// Normalise a full repo URI to `owner/repo` slug.
/// `https://github.com/The-Geek-Freaks/NEOTH` → `The-Geek-Freaks/NEOTH`.
/// `git@github.com:The-Geek-Freaks/NEOTH.git` → `The-Geek-Freaks/NEOTH.git`.
/// Falls back to the full string if the pattern is not recognisable.
pub fn normalise_repo_slug(repo_uri: &str) -> String {
    // Strip common scheme prefixes first.
    let stripped = repo_uri
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git@");
    // For `host:owner/repo` (git@ format): prefer ':' as the host delimiter.
    // For `host/owner/repo` (https format): prefer first '/' as the host delimiter.
    let after_host = if let Some(colon_pos) = stripped.find(':') {
        // Check there is no '/' before the colon (which would mean it's already owner/repo).
        let slash_before_colon = stripped[..colon_pos].contains('/');
        if !slash_before_colon {
            &stripped[colon_pos + 1..]
        } else {
            // https-style: find the first '/' then skip one more component
            stripped.find('/').map(|i| &stripped[i + 1..]).unwrap_or(stripped)
        }
    } else {
        // No colon — https-style: skip host (first slash-delimited component)
        stripped.find('/').map(|i| &stripped[i + 1..]).unwrap_or(stripped)
    };
    // Take at most two path components (owner/repo).
    let parts: Vec<&str> = after_host.splitn(3, '/').take(2).collect();
    if parts.len() == 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        after_host.to_string()
    }
}

/// Coarsen a model string to `{provider}/{family}`.
/// "claude-3-5-sonnet-20241022" with provider "anthropic" → "anthropic/claude-3".
/// Any version suffix is stripped.
pub fn coarsen_model(provider: &str, model_id: &str) -> String {
    // Derive family: take the first two dash-separated tokens.
    let family: String = model_id
        .split('-')
        .take(2)
        .collect::<Vec<_>>()
        .join("-");
    format!("{}/{}", provider, family)
}

/// Filter a metrics map to only approved keys.
pub fn filter_metrics(
    raw: &std::collections::HashMap<String, serde_json::Value>,
) -> std::collections::HashMap<String, serde_json::Value> {
    let approved: HashSet<&str> = APPROVED_METRICS_KEYS.iter().copied().collect();
    raw.iter()
        .filter(|(k, _)| approved.contains(k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Deployment context for stratification metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentContext {
    SingleUser,
    MultiUser,
    Ci,
    Benchmark,
}

/// Hardware tier for stratification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardwareTier {
    Laptop,
    Workstation,
    Server,
    CloudSmall,
    CloudLarge,
}

/// Submission metadata added to each federated window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmissionMetadata {
    /// Pseudonymous stable contributor id (64-char hex SHA-256).
    pub contributor_id: String,
    pub deployment_context: DeploymentContext,
    pub hardware_tier: HardwareTier,
    /// Provider+family of the primary model (coarsened).
    pub primary_model_family: String,
    /// Integer bucket for average tasks per day on this instance.
    pub avg_tasks_per_day_bucket: u32,
    /// Schema version of the submission protocol.
    pub protocol_version: &'static str,
    /// Runtime class for cross-runtime pooling.
    pub runtime_class: &'static str,
}

impl SubmissionMetadata {
    pub const PROTOCOL_VERSION: &'static str = "neoth-federation/0.1.0";
    pub const RUNTIME_CLASS: &'static str = "llm-agent-orchestrator";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_repo_slug_strips_github_https() {
        assert_eq!(
            normalise_repo_slug("https://github.com/The-Geek-Freaks/NEOTH"),
            "The-Geek-Freaks/NEOTH"
        );
    }

    #[test]
    fn normalise_repo_slug_strips_git_at() {
        // git@ format: "git@github.com:The-Geek-Freaks/NEOTH.git"
        // After trim_start "git@" → "github.com:The-Geek-Freaks/NEOTH.git"
        // find ':' → after = "The-Geek-Freaks/NEOTH.git"
        // splitn(3, '/').take(2) → ["The-Geek-Freaks", "NEOTH.git"]
        let slug = normalise_repo_slug("git@github.com:The-Geek-Freaks/NEOTH.git");
        assert_eq!(slug, "The-Geek-Freaks/NEOTH.git");
    }

    #[test]
    fn coarsen_model_strips_version_suffix() {
        // split('-').take(2): "claude-3-5-sonnet-20241022" → ["claude", "3"] → "claude-3"
        assert_eq!(
            coarsen_model("anthropic", "claude-3-5-sonnet-20241022"),
            "anthropic/claude-3"
        );
        // split('-').take(2): "claude-sonnet-4-6" → ["claude", "sonnet"] → "claude-sonnet"
        assert_eq!(
            coarsen_model("anthropic", "claude-sonnet-4-6"),
            "anthropic/claude-sonnet"
        );
    }

    #[test]
    fn pseudonymise_id_is_16_hex_chars() {
        let salt = b"test-salt";
        let id = pseudonymise_id(salt, "session-abc-123");
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pseudonymise_id_is_deterministic() {
        let salt = b"test-salt";
        assert_eq!(
            pseudonymise_id(salt, "same-id"),
            pseudonymise_id(salt, "same-id")
        );
    }

    #[test]
    fn pseudonymise_id_differs_for_different_inputs() {
        let salt = b"test-salt";
        assert_ne!(
            pseudonymise_id(salt, "id-a"),
            pseudonymise_id(salt, "id-b")
        );
    }

    #[test]
    fn filter_metrics_drops_unapproved_keys() {
        let raw: std::collections::HashMap<String, serde_json::Value> = [
            ("tokens_in_total".to_string(), serde_json::Value::Number(42.into())),
            ("raw_prompt_text".to_string(), serde_json::Value::String("secret".into())),
        ].into();
        let filtered = filter_metrics(&raw);
        assert!(filtered.contains_key("tokens_in_total"));
        assert!(!filtered.contains_key("raw_prompt_text"));
    }

    #[test]
    fn contributor_id_is_64_hex_chars() {
        let id = derive_contributor_id(b"my-secret-salt", "The-Geek-Freaks/NEOTH");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
