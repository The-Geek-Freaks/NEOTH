//! GOLD-ADAPT-AWE-PROV-01 — oai_serve hyper 1.x server task.
//!
//! Mirrors the pattern of `n8n_api/server.rs` exactly:
//! - Binds `127.0.0.1:<port>` (loopback ONLY — no `0.0.0.0`).
//! - Enforces a loopback peer guard at `accept()` as a second defence layer.
//! - Hands each connection to `hyper::server::conn::http1::Builder`.
//! - Respects a `tokio::sync::Notify` for graceful shutdown.
//!
//! The `/v1/models` endpoint is unauthenticated (read-only model discovery,
//! matching Ollama convention). The loopback bind is the security boundary.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::config::FreedomConfig;

use super::handlers::{HandlerOutcome, route};

/// Spawn the oai_serve hyper task.
///
/// Returns `None` when `config.oai_serve.enabled = false` (the default).
/// On a bind failure logs at `error!` and returns `None` — the daemon
/// continues without the serve adapter rather than aborting boot.
///
/// `home` is the NEOTH home directory. The catalog path is derived through
/// [`crate::models::catalog::ModelsCatalog::default_path`], the same SSOT used
/// by the refresh task and CLI. In production this is
/// `FreedomConfig::default_neoth_home()`; tests inject a tempdir.
pub fn spawn_server(
    config: Arc<FreedomConfig>,
    home: PathBuf,
    shutdown: Arc<Notify>,
) -> Option<JoinHandle<()>> {
    if !config.oai_serve.enabled {
        tracing::debug!("freedom.yaml::oai_serve.enabled = false; skipping oai_serve spawn");
        return None;
    }
    let port = config.oai_serve.port;
    let catalog_path = crate::models::catalog::ModelsCatalog::default_path(&home);

    Some(tokio::spawn(async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    port = port,
                    error = %e,
                    "oai_serve hyper bind failed; /v1/models will not be available this session"
                );
                return;
            }
        };
        tracing::info!(
            port = port,
            "oai_serve listening on 127.0.0.1 — GET /v1/models (OpenRouter-compat)"
        );

        loop {
            let accept = tokio::select! {
                biased;
                _ = shutdown.notified() => {
                    tracing::info!("oai_serve shutdown signal received; draining");
                    break;
                }
                res = listener.accept() => res,
            };

            let (stream, peer) = match accept {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "oai_serve accept failed");
                    continue;
                }
            };

            // Defence in depth: reject non-loopback peers even though the
            // bind address is already 127.0.0.1. A future misconfigured bind
            // must still get caught here.
            if !peer.ip().is_loopback() {
                tracing::warn!(
                    peer = %peer,
                    "oai_serve non-loopback peer rejected at accept"
                );
                continue;
            }

            let catalog_path_for_conn = catalog_path.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let cat = catalog_path_for_conn.clone();
                    async move { Ok::<_, Infallible>(handle_request(req, &cat).await) }
                });
                if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                    tracing::debug!(error = %e, "oai_serve connection error");
                }
            });
        }
    }))
}

/// Per-request handler: dispatch to the route table and render the HTTP
/// response. No auth — `/v1/models` is intentionally open (read-only
/// discovery; loopback is the security boundary).
async fn handle_request(
    req: Request<Incoming>,
    catalog_path: &std::path::Path,
) -> Response<Full<Bytes>> {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    let outcome = route(&method, &path, catalog_path).await;

    match outcome {
        HandlerOutcome::Ok { body } => Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| fallback_500()),
        HandlerOutcome::Err { status, message } => {
            let body = serde_json::to_vec(&serde_json::json!({
                "error": message
            }))
            .unwrap_or_default();
            Response::builder()
                .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap_or_else(|_| fallback_500())
        }
    }
}

fn fallback_500() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(Bytes::from_static(
            br#"{"error":"response build failed"}"#,
        )))
        .expect("static error body always builds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Notify;

    fn find_free_port() -> u16 {
        // Bind port 0 → OS assigns a free port → read it back.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    /// Round-trip integration test: spawn the real server, issue a GET
    /// /v1/models via reqwest, assert the OpenRouter wire shape.
    #[tokio::test]
    async fn oai_serve_models_returns_openrouter_wire_shape() {
        // 1. Write a synthetic catalog to a tempdir.
        let tmp = tempfile::TempDir::new().unwrap();
        let catalog_path = tmp.path().join("models_catalog.json");
        let catalog = serde_json::json!({
            "version": 1,
            "providers": {
                "anthropic_api": {
                    "fetched_at_unix": 9_999_999_999u64,
                    "source": "api",
                    "models": [{"id": "claude-opus-4-7", "display_name": "Claude Opus 4.7"}]
                }
            }
        });
        std::fs::write(&catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();

        // 2. Build a minimal FreedomConfig with oai_serve enabled on a free port.
        let port = find_free_port();
        let mut config = FreedomConfig::default();
        config.oai_serve.enabled = true;
        config.oai_serve.port = port;

        // 3. Spawn the server.
        let shutdown = Arc::new(Notify::new());
        let handle = spawn_server(
            Arc::new(config),
            tmp.path().to_path_buf(),
            Arc::clone(&shutdown),
        )
        .expect("oai_serve.enabled=true must return Some(handle)");

        // 4. Give the task time to bind.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        // 5. GET /v1/models.
        let resp = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/v1/models"))
            .send()
            .await
            .expect("GET /v1/models should succeed");

        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();

        // OpenRouter wire shape requirements.
        assert_eq!(body["object"], "list", "top-level object must be 'list'");
        let data = body["data"].as_array().unwrap();
        assert!(
            data.iter().any(|m| m["id"] == "claude-opus-4-7"),
            "catalog entry must appear in /v1/models response; got: {data:?}"
        );
        assert_eq!(
            data[0]["object"], "model",
            "each entry must have object='model'"
        );
        assert_eq!(data[0]["owned_by"], "anthropic_api");

        // 6. Shut down cleanly.
        shutdown.notify_waiters();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn oai_serve_disabled_returns_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut config = FreedomConfig::default();
        config.oai_serve.enabled = false;
        let shutdown = Arc::new(Notify::new());
        let handle = spawn_server(Arc::new(config), tmp.path().to_path_buf(), shutdown);
        assert!(handle.is_none(), "disabled oai_serve must return None");
    }

    #[tokio::test]
    async fn oai_serve_404_for_unknown_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let port = find_free_port();
        let mut config = FreedomConfig::default();
        config.oai_serve.enabled = true;
        config.oai_serve.port = port;
        let shutdown = Arc::new(Notify::new());
        let handle = spawn_server(
            Arc::new(config),
            tmp.path().to_path_buf(),
            Arc::clone(&shutdown),
        )
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let resp = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/v1/unknown"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404);

        shutdown.notify_waiters();
        let _ = handle.await;
    }
}
