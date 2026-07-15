//! GOLD-ADAPT-AWE-PROV-01 — OpenRouter-compat `/v1/models` serve adapter.
//!
//! Exposes a loopback-only hyper 1.x HTTP server on port 9746 (next after the
//! companion server at 9745) that returns the NEOTH models catalog in
//! OpenRouter wire format so Cline, Continue, OpenCode, Goose and other
//! OpenRouter-aware clients can discover available models without any
//! per-client configuration.
//!
//! ## Endpoints
//!
//! | Method | Path          | Auth | Notes |
//! |--------|---------------|------|-------|
//! | GET    | `/v1/models`  | None | OpenRouter/OpenAI wire shape |
//!
//! ## Auth policy
//!
//! `/v1/models` is intentionally unauthenticated — matching Ollama's
//! convention for read-only model discovery. The defence is the bind address
//! (`127.0.0.1` only); a non-loopback peer is rejected at the TCP accept
//! level. If a future `/v1/chat/completions` endpoint is added it will reuse
//! the n8n_api bearer token; `/v1/models` will remain open so discovery works
//! without credential bootstrapping.
//!
//! ## Catalog freshness
//!
//! The catalog is populated by `models::refresh_task` (a daily cron already
//! wired into `run_serve`). On first boot the catalog file may not exist yet;
//! `ModelsCatalog::load_from` returns an empty catalog in that case, and the
//! response is `{"object":"list","data":[]}` — valid OpenRouter wire shape.
//!
//! ## Port
//!
//! Default 9746 ([`crate::config::automation::DEFAULT_OAI_SERVE_PORT`]).
//! Operator can override via `freedom.yaml::oai_serve.port`.

pub mod handlers;
pub mod server;

use serde::{Deserialize, Serialize};

/// One model entry in the OpenRouter / OpenAI `/v1/models` wire format.
///
/// OpenRouter's extended shape includes `context_length` and `pricing`.
/// NEOTH's catalog does not currently carry either value, so the fields are
/// omitted instead of publishing fabricated zero/null metadata. They remain
/// optional on the wire for forwards-compatible catalog enrichment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OaiModelEntry {
    /// Model identifier — forwarded verbatim from `ModelEntry::id`.
    /// Examples: `"claude-opus-4-7"`, `"gpt-4o"`.
    pub id: String,
    /// Always `"model"` — required by the OpenRouter wire format.
    pub object: String,
    /// Provider name from the NEOTH catalog (e.g. `"anthropic_api"`).
    pub owned_by: String,
    /// Context window token count when the catalog source supplied one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_length: Option<u32>,
    /// Pricing object when the catalog source supplied one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pricing: Option<serde_json::Value>,
}

/// The top-level OpenRouter `/v1/models` response envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OaiModelsResponse {
    /// Always `"list"`.
    pub object: String,
    /// Model entries, one per (provider, model) pair.
    pub data: Vec<OaiModelEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oai_model_entry_serialises_object_field() {
        let entry = OaiModelEntry {
            id: "claude-opus-4-7".to_string(),
            object: "model".to_string(),
            owned_by: "anthropic_api".to_string(),
            context_length: None,
            pricing: None,
        };
        let v: serde_json::Value = serde_json::to_value(&entry).unwrap();
        assert_eq!(v["object"], "model");
        assert_eq!(v["id"], "claude-opus-4-7");
        assert_eq!(v["owned_by"], "anthropic_api");
        assert!(v.get("context_length").is_none());
        assert!(v.get("pricing").is_none());
    }

    #[test]
    fn oai_models_response_serialises_list_envelope() {
        let resp = OaiModelsResponse {
            object: "list".to_string(),
            data: vec![OaiModelEntry {
                id: "test-model".to_string(),
                object: "model".to_string(),
                owned_by: "test_provider".to_string(),
                context_length: None,
                pricing: None,
            }],
        };
        let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["object"], "list");
        let data = v["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["id"], "test-model");
    }

    #[test]
    fn empty_response_is_valid_wire_shape() {
        let resp = OaiModelsResponse {
            object: "list".to_string(),
            data: vec![],
        };
        let v: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["object"], "list");
        assert_eq!(v["data"].as_array().unwrap().len(), 0);
    }
}
