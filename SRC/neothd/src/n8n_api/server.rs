//! Hyper 1.x server task for the localhost API.
//!
//! Binds `127.0.0.1:<port>` (loopback ONLY — no `0.0.0.0`), accepts
//! TCP, hands each connection to a service that:
//!
//! 1. Enforces the loopback peer guard (defence in depth — bind is
//!    already 127.0.0.1, but a future regression that flips the
//!    bind address must still get caught here).
//! 2. Extracts the bearer token + checks the 5-strike cooldown.
//! 3. Writes the [`super::EVENT_TYPE_N8N_REQUEST`] (0x39) WAL frame
//!    before any handler-side work — operator sees every attempt.
//! 4. Reads the body with a 256 KiB cap.
//! 5. Dispatches into [`super::handlers::route`].
//! 6. Renders the [`super::ApiOkResponse`] / [`super::ApiErrorResponse`]
//!    envelope as the HTTP body.
//!
//! Cancellation: the task respects a `tokio_util::sync::CancellationToken`
//! handed in by `cli::serve::run_serve` so daemon shutdown drains the
//! socket cleanly.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Notify;

use super::auth::AuthCooldown;
use super::handlers::route;
use super::{
    ApiErrorCode, ApiErrorResponse, ApiOkResponse, REQUEST_BODY_LIMIT_BYTES,
    build_n8n_request_payload, constant_time_token_eq, extract_bearer_token, new_request_id,
};
use crate::config::FreedomConfig;
use crate::wal::writer::WalWriterHandle;

/// Shared state passed into every handler. Cheap to clone — the
/// fields are all `Arc` / handles.
pub struct ApiState {
    pub writer: WalWriterHandle,
    pub config: Arc<FreedomConfig>,
    pub home: PathBuf,
    pub token: String,
    pub cooldown: Arc<AuthCooldown>,
    pub boot_instant: Instant,
}

/// Parsed shape a handler receives. The server layer has already
/// dealt with auth + audit + body buffering by the time this lands.
#[derive(Clone, Debug)]
pub struct ApiRequestCtx {
    pub method: String,
    pub path: String,
    pub request_id: String,
    pub source_ip: String,
    pub body: Vec<u8>,
}

/// Handler return shape. The server layer maps this into an HTTP
/// response — handlers don't see `hyper::Response` directly.
#[derive(Debug)]
pub enum HandlerOutcome {
    Ok {
        body: serde_json::Value,
    },
    Err {
        code: ApiErrorCode,
        message: String,
        hint: String,
    },
}

impl HandlerOutcome {
    pub fn ok_json(body: serde_json::Value) -> Self {
        Self::Ok { body }
    }
    pub fn error(code: ApiErrorCode, message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::Err {
            code,
            message: message.into(),
            hint: hint.into(),
        }
    }

    pub fn error_code(&self) -> Option<ApiErrorCode> {
        match self {
            Self::Ok { .. } => None,
            Self::Err { code, .. } => Some(*code),
        }
    }

    fn into_http_response(self, request_id: &str) -> Response<Full<Bytes>> {
        match self {
            Self::Ok { body } => {
                let env = ApiOkResponse::new(body, request_id);
                let bytes = serde_json::to_vec(&env).unwrap_or_default();
                build_http_response(StatusCode::OK, bytes)
            }
            Self::Err {
                code,
                message,
                hint,
            } => {
                let env = ApiErrorResponse::new(code, message, hint, request_id);
                let status = StatusCode::from_u16(code.http_status())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                build_http_response(status, env.to_bytes())
            }
        }
    }
}

fn build_http_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from_static(
                    br#"{"ok":false,"error":{"code":"UpstreamError","message":"response build failed","hint":""}}"#,
                )))
                .expect("static error body always builds")
        })
}

/// Spawn the hyper server task. Returns a JoinHandle the caller can
/// abort/await for graceful shutdown.
pub fn spawn_server(state: Arc<ApiState>, shutdown: Arc<Notify>) -> tokio::task::JoinHandle<()> {
    let port = state.config.n8n_api.port;
    tokio::spawn(async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    port = port,
                    error = %e,
                    "n8n_api hyper bind failed; HTTP API will not be available this session"
                );
                return;
            }
        };
        tracing::info!(port = port, "n8n_api hyper task listening on 127.0.0.1");
        loop {
            let accept = tokio::select! {
                biased;
                _ = shutdown.notified() => {
                    tracing::info!("n8n_api shutdown signal received; draining");
                    break;
                }
                res = listener.accept() => res,
            };
            let (stream, peer) = match accept {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "n8n_api accept failed");
                    continue;
                }
            };
            if !peer.ip().is_loopback() {
                tracing::warn!(peer = %peer, "n8n_api non-loopback peer rejected at accept");
                continue;
            }
            let state_for_conn = Arc::clone(&state);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let state = Arc::clone(&state_for_conn);
                    let peer_str = peer.ip().to_string();
                    async move { Ok::<_, Infallible>(serve(req, state, peer_str).await) }
                });
                if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                    tracing::debug!(error = %e, "n8n_api connection error");
                }
            });
        }
    })
}

/// Per-request top-level: auth, audit, dispatch.
async fn serve(
    req: Request<Incoming>,
    state: Arc<ApiState>,
    peer_ip: String,
) -> Response<Full<Bytes>> {
    let request_id = new_request_id();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let now = Instant::now();
    let ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Write the 0x39 audit frame BEFORE any auth/business logic so
    // every attempt is durable — even refused ones.
    let audit_payload = build_n8n_request_payload(&path, &peer_ip, &request_id, ts_unix);
    let audit_header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_N8N_REQUEST, &audit_payload)
            .build();
    let writer_for_audit = state.writer.clone();
    if let Err(e) = writer_for_audit.append(audit_header, audit_payload).await {
        tracing::warn!(error = %e, request_id = %request_id, "n8n_api N8N_REQUEST audit WAL append failed");
    }

    // Auth: cooldown lockout first, then token check.
    if state.cooldown.is_locked(&peer_ip, now) {
        let outcome = HandlerOutcome::error(
            ApiErrorCode::Unauthorized,
            "auth cooldown active",
            "wait 60 seconds; ensure your bearer token matches ~/.neoth/n8n_api_token",
        );
        return outcome.into_http_response(&request_id);
    }
    match extract_bearer_token(&auth_header) {
        Some(token) if constant_time_token_eq(token, &state.token) => {
            state.cooldown.record_success(&peer_ip);
        }
        _ => {
            let tripped = state.cooldown.record_failure(&peer_ip, now);
            tracing::warn!(
                peer = %peer_ip,
                path = %path,
                tripped = tripped,
                "n8n_api auth refused"
            );
            let hint = if tripped {
                "5 failures hit — cooldown engaged for 60s. Verify ~/.neoth/n8n_api_token."
            } else {
                "set Authorization: Bearer <token> using ~/.neoth/n8n_api_token"
            };
            let outcome = HandlerOutcome::error(
                ApiErrorCode::Unauthorized,
                "bearer token missing or invalid",
                hint,
            );
            return outcome.into_http_response(&request_id);
        }
    }

    // Buffer body with the 256 KiB cap.
    let body = match read_body_capped(req).await {
        Ok(b) => b,
        Err(outcome) => return outcome.into_http_response(&request_id),
    };

    let ctx = ApiRequestCtx {
        method: method.as_str().to_string(),
        path,
        request_id: request_id.clone(),
        source_ip: peer_ip,
        body,
    };
    let outcome = route(ctx, Arc::clone(&state)).await;
    outcome.into_http_response(&request_id)
}

async fn read_body_capped(req: Request<Incoming>) -> Result<Vec<u8>, HandlerOutcome> {
    let collected = req.into_body().collect().await.map_err(|e| {
        HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            format!("body read failed: {e}"),
            "retry with a smaller payload or check network",
        )
    })?;
    let bytes = collected.to_bytes();
    if bytes.len() > REQUEST_BODY_LIMIT_BYTES {
        return Err(HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            format!(
                "request body {} bytes exceeds cap {}",
                bytes.len(),
                REQUEST_BODY_LIMIT_BYTES
            ),
            "shrink the payload — the workflow JSON likely embeds a huge field",
        ));
    }
    Ok(bytes.to_vec())
}

/// Load or freshly mint the bearer token. The token lives at
/// `<home>/n8n_api_token` (mode-0600 on Unix, DACL on Windows via
/// the WAL helper). Missing file → 32 bytes from `getrandom`,
/// base64url-NOPAD encoded → 43 chars. Subsequent boots reuse the
/// stored token so n8n workflows don't need re-rotation per restart.
pub fn load_or_init_token(home: &std::path::Path) -> std::io::Result<String> {
    let path = home.join("n8n_api_token");
    if path.exists() {
        // SC-08: read raw bytes + DPAPI-unwrap on Windows (legacy
        // plaintext files pass through + upgrade to wrapped on the next
        // mint). Unix is plaintext mode-0600 as before.
        let bytes = std::fs::read(&path)?;
        #[cfg(windows)]
        let token = {
            let raw = if crate::wal::dpapi::is_wrapped(&bytes) {
                crate::wal::dpapi::unprotect(&bytes)
                    .map_err(|e| std::io::Error::other(format!("DPAPI unwrap n8n_api_token: {e}")))?
            } else {
                bytes
            };
            String::from_utf8(raw)
                .map_err(|e| std::io::Error::other(format!("n8n_api_token UTF-8: {e}")))?
                .trim()
                .to_string()
        };
        #[cfg(not(windows))]
        let token = String::from_utf8(bytes)
            .map_err(|e| std::io::Error::other(format!("n8n_api_token UTF-8: {e}")))?
            .trim()
            .to_string();
        if token.len() == super::N8N_API_TOKEN_CHAR_LEN {
            return Ok(token);
        }
        tracing::warn!(
            path = %path.display(),
            "n8n_api_token wrong length; minting fresh token"
        );
    }
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .map_err(|e| std::io::Error::other(format!("getrandom failed: {e}")))?;
    use base64::Engine;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    std::fs::create_dir_all(home)?;
    // SC-08: on Windows DPAPI-wrap the token (so a stolen file is useless
    // outside the operator's account) + restrict the DACL; on Unix write
    // plaintext mode-0600. Mirrors the WAL HMAC-key handling.
    #[cfg(windows)]
    {
        let payload = match crate::wal::dpapi::protect(token.as_bytes()) {
            Ok(wrapped) => wrapped,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "DPAPI wrap unavailable; writing n8n_api_token plaintext with DACL fallback"
                );
                token.as_bytes().to_vec()
            }
        };
        std::fs::write(&path, &payload)?;
        if let Err(e) = crate::wal::win_acl::restrict_to_owner(&path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "n8n_api_token DACL restriction failed; token file inherits parent DACL"
            );
        }
    }
    #[cfg(not(windows))]
    {
        std::fs::write(&path, &token)?;
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_outcome_ok_serialises_to_envelope() {
        let outcome = HandlerOutcome::ok_json(serde_json::json!({"x": 1}));
        let resp = outcome.into_http_response("req-1");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn handler_outcome_err_maps_status() {
        let outcome = HandlerOutcome::error(ApiErrorCode::PermissionDenied, "no", "fix it");
        let resp = outcome.into_http_response("req-2");
        assert_eq!(resp.status(), 403);
    }

    #[test]
    fn handler_outcome_error_code_introspect() {
        let ok = HandlerOutcome::ok_json(serde_json::json!({}));
        assert!(ok.error_code().is_none());
        let err = HandlerOutcome::error(ApiErrorCode::NotFound, "x", "y");
        assert_eq!(err.error_code(), Some(ApiErrorCode::NotFound));
    }

    #[tokio::test]
    async fn load_or_init_mints_fresh_token_in_temp_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let token = load_or_init_token(dir.path()).unwrap();
        assert_eq!(token.len(), super::super::N8N_API_TOKEN_CHAR_LEN);
        // Re-load returns the same token (idempotent).
        let token2 = load_or_init_token(dir.path()).unwrap();
        assert_eq!(token, token2);
    }
}
