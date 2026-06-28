//! GOLD-ADAPT-AWE-PROV-01 — oai_serve request handlers.
//!
//! Pure-fn dispatch: `route` maps `(method, path)` to a handler result.
//! No I/O happens here except the `spawn_blocking` catalog read inside
//! `models_handler` — the tokio runtime is never blocked on the catalog
//! file read (up to a few hundred KiB).

use std::path::Path;

use super::{OaiModelEntry, OaiModelsResponse};

/// Handler return shape — mirrors the n8n_api pattern so the server layer
/// can render HTTP responses uniformly without knowing about hyper types.
#[derive(Debug)]
pub enum HandlerOutcome {
    /// Success: JSON body to send as HTTP 200.
    Ok { body: Vec<u8> },
    /// Error: HTTP status code + plain-text message.
    Err { status: u16, message: String },
}

impl HandlerOutcome {
    fn ok(body: Vec<u8>) -> Self {
        Self::Ok { body }
    }
    fn not_found(path: &str) -> Self {
        Self::Err {
            status: 404,
            message: format!("oai_serve: unknown endpoint `{path}`"),
        }
    }
    fn method_not_allowed(method: &str, path: &str) -> Self {
        Self::Err {
            status: 405,
            message: format!("oai_serve: method `{method}` not allowed for `{path}`"),
        }
    }
    fn internal(msg: impl Into<String>) -> Self {
        Self::Err {
            status: 500,
            message: msg.into(),
        }
    }
}

/// Dispatch a request to the right handler. The server layer has already
/// enforced the loopback peer guard; no auth needed on the read-only path.
///
/// `catalog_path` — absolute path to the `models_catalog.json` file under
/// `~/.neoth/`. Passed in so the server and tests can inject any location.
pub async fn route(method: &str, path: &str, catalog_path: &Path) -> HandlerOutcome {
    match path {
        "/v1/models" => match method {
            "GET" | "HEAD" => models_handler(catalog_path).await,
            other => HandlerOutcome::method_not_allowed(other, path),
        },
        _ => HandlerOutcome::not_found(path),
    }
}

/// `GET /v1/models` — read the NEOTH models catalog from disk and return it
/// in OpenRouter wire format.
///
/// The catalog file is read synchronously inside `spawn_blocking` so the
/// async runtime is never blocked. A missing or malformed catalog returns
/// `{"object":"list","data":[]}` — valid OpenRouter shape; Cline/Continue
/// show an empty model list until the daily refresh populates the catalog.
async fn models_handler(catalog_path: &Path) -> HandlerOutcome {
    let path_owned = catalog_path.to_path_buf();

    // Offload the synchronous file read to the blocking pool — the catalog
    // is up to a few hundred KiB and `std::fs::read` must not block the
    // async executor.
    let catalog = tokio::task::spawn_blocking(move || {
        crate::models::catalog::ModelsCatalog::load_from(&path_owned)
    })
    .await;

    let catalog = match catalog {
        Ok(c) => c,
        Err(join_err) => {
            tracing::error!(
                error = %join_err,
                "oai_serve: spawn_blocking panicked reading models catalog"
            );
            return HandlerOutcome::internal(
                "catalog read panicked — check logs",
            );
        }
    };

    // Flatten (provider_name, ModelEntry) pairs into OaiModelEntry vec.
    // Ordering: iterate providers in BTreeMap insertion order (alphabetical)
    // then within each provider preserve the Vec<ModelEntry> order which
    // the provider source chose (priority / recency).
    let mut entries: Vec<OaiModelEntry> = Vec::new();
    for (provider_name, provider_catalog) in &catalog.providers {
        for model_entry in &provider_catalog.models {
            entries.push(OaiModelEntry {
                id: model_entry.id.clone(),
                object: "model".to_string(),
                owned_by: provider_name.clone(),
                // context_length: stub 0 — ModelEntry has no token-window field yet.
                // A follow-up schema extension to ModelEntry will populate this.
                context_length: 0,
                // pricing: null — same stub rationale.
                pricing: None,
            });
        }
    }

    let response = OaiModelsResponse {
        object: "list".to_string(),
        data: entries,
    };

    match serde_json::to_vec(&response) {
        Ok(bytes) => HandlerOutcome::ok(bytes),
        Err(e) => {
            tracing::error!(error = %e, "oai_serve: models response serialisation failed");
            HandlerOutcome::internal("response serialisation failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Helper — write a synthetic catalog to a temp path, then run the handler
    /// and assert the OpenRouter wire shape comes back.
    #[tokio::test]
    async fn models_handler_returns_openrouter_shape_for_one_provider() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog_path = tmp.path().join("models_catalog.json");

        let catalog_json = serde_json::json!({
            "version": 1,
            "providers": {
                "anthropic_api": {
                    "fetched_at_unix": 9_999_999_999u64,
                    "source": "api",
                    "models": [{"id": "claude-opus-4-7", "display_name": "Claude Opus 4.7"}]
                }
            }
        });
        std::fs::write(&catalog_path, serde_json::to_vec(&catalog_json).unwrap()).unwrap();

        let outcome = route("GET", "/v1/models", &catalog_path).await;
        match outcome {
            HandlerOutcome::Ok { body } => {
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(v["object"], "list");
                let data = v["data"].as_array().unwrap();
                assert!(
                    data.iter().any(|m| m["id"] == "claude-opus-4-7"),
                    "expected claude-opus-4-7 in /v1/models response"
                );
                assert_eq!(data[0]["object"], "model");
                assert_eq!(data[0]["owned_by"], "anthropic_api");
            }
            HandlerOutcome::Err { status, message } => {
                panic!("expected Ok, got Err {status}: {message}");
            }
        }
    }

    #[tokio::test]
    async fn models_handler_returns_empty_list_on_missing_catalog() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog_path = tmp.path().join("nonexistent.json");

        let outcome = route("GET", "/v1/models", &catalog_path).await;
        match outcome {
            HandlerOutcome::Ok { body } => {
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(v["object"], "list");
                assert_eq!(v["data"].as_array().unwrap().len(), 0);
            }
            HandlerOutcome::Err { status, message } => {
                panic!("expected Ok empty list, got Err {status}: {message}");
            }
        }
    }

    #[tokio::test]
    async fn route_returns_404_for_unknown_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog_path = tmp.path().join("models_catalog.json");
        let outcome = route("GET", "/unknown", &catalog_path).await;
        match outcome {
            HandlerOutcome::Err { status, .. } => assert_eq!(status, 404),
            HandlerOutcome::Ok { .. } => panic!("expected 404"),
        }
    }

    #[tokio::test]
    async fn route_returns_405_for_post_to_models() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog_path = tmp.path().join("models_catalog.json");
        let outcome = route("POST", "/v1/models", &catalog_path).await;
        match outcome {
            HandlerOutcome::Err { status, .. } => assert_eq!(status, 405),
            HandlerOutcome::Ok { .. } => panic!("expected 405"),
        }
    }

    #[tokio::test]
    async fn models_handler_flattens_multiple_providers() {
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog_path = tmp.path().join("models_catalog.json");

        let catalog_json = serde_json::json!({
            "version": 1,
            "providers": {
                "anthropic_api": {
                    "fetched_at_unix": 1u64,
                    "models": [{"id": "claude-opus-4-7"}]
                },
                "openai": {
                    "fetched_at_unix": 1u64,
                    "models": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}]
                }
            }
        });
        std::fs::write(&catalog_path, serde_json::to_vec(&catalog_json).unwrap()).unwrap();

        let outcome = route("GET", "/v1/models", &catalog_path).await;
        match outcome {
            HandlerOutcome::Ok { body } => {
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let data = v["data"].as_array().unwrap();
                // BTreeMap order: anthropic_api < openai; within each, Vec order.
                assert_eq!(data.len(), 3);
                assert_eq!(data[0]["id"], "claude-opus-4-7");
                assert_eq!(data[0]["owned_by"], "anthropic_api");
                assert_eq!(data[1]["id"], "gpt-4o");
                assert_eq!(data[1]["owned_by"], "openai");
                assert_eq!(data[2]["id"], "gpt-4o-mini");
            }
            HandlerOutcome::Err { status, message } => {
                panic!("expected Ok, got Err {status}: {message}");
            }
        }
    }
}
