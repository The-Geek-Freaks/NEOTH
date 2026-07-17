//! Hyper 1.x server task for the localhost API.
//!
//! Binds `127.0.0.1:<port>` (loopback ONLY — no `0.0.0.0`), accepts
//! TCP, hands each connection to a service that:
//!
//! 1. Enforces the loopback peer guard (defence in depth — bind is
//!    already 127.0.0.1, but a future regression that flips the
//!    bind address must still get caught here).
//! 2. Extracts the bearer token + checks the 5-strike cooldown.
//! 3. Auth: accepts the static operator master token (full access) OR a
//!    scope-gated API token from `~/.neoth/api_tokens.json`. Scope-gated
//!    tokens are checked via PBKDF2-HMAC-SHA256 + constant-time compare
//!    (see `security::api_tokens`). Each endpoint requires a specific scope.
//! 4. Writes the [`super::EVENT_TYPE_N8N_REQUEST`] (0x39) WAL frame
//!    before any handler-side work — operator sees every attempt.
//! 5. Reads the body with a 256 KiB cap.
//! 6. Dispatches into [`super::handlers::route`].
//! 7. Renders the [`super::ApiOkResponse`] / [`super::ApiErrorResponse`]
//!    envelope as the HTTP body.
//!
//! Cancellation: the task respects the shared [`Notify`] handed in by
//! `cli::serve::run_serve`; shutdown then aborts and awaits all owned
//! connection tasks before the server returns.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
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
use crate::security::api_tokens;
use crate::security::api_tokens::VerifyResult;
use crate::wal::writer::WalWriterHandle;

/// Map a (method, path) pair to the required API-token scope string.
/// The static operator master token (`state.token`) is always accepted
/// for any path and bypasses scope checks. Scope-gated tokens must carry
/// the scope returned here. Returns `None` for unknown paths (handled
/// downstream as 404).
fn required_scope_for(method: &str, path: &str) -> Option<&'static str> {
    match (method, path) {
        ("GET", "/api/health") => Some(api_tokens::SCOPE_API_HEALTH),
        ("POST", "/api/recall") => Some(api_tokens::SCOPE_RECALL_READ),
        ("GET", "/api/stats") => Some(api_tokens::SCOPE_STATS_READ),
        ("POST", "/api/memory/save") => Some(api_tokens::SCOPE_MEMORY_WRITE),
        ("POST", "/api/provider/call") => Some(api_tokens::SCOPE_PROVIDER_CALL),
        ("POST", "/api/channel/send") => Some(api_tokens::SCOPE_CHANNEL_SEND),
        // Unknown path — pass through, route() will 404.
        // Security review: fail CLOSED — an unmapped path must never be
        // reachable with the narrowest scope. New routes must be added here.
        _ => None,
    }
}

/// Shared state passed into every handler. Cheap to clone — the
/// fields are all `Arc` / handles.
pub struct ApiState {
    pub writer: WalWriterHandle,
    pub config: Arc<FreedomConfig>,
    pub reload_controller: Arc<crate::config::reload::ReloadController>,
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
                let bytes = serde_json::to_vec(&env)
                    .expect("ApiOkResponse contains only JSON-serializable values");
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

/// Spawn the hyper server task. The caller signals `shutdown`, then awaits the
/// returned handle so every connection releases its state before WAL drain.
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
        run_server(listener, state, shutdown).await;
    })
}

async fn run_server(listener: TcpListener, state: Arc<ApiState>, shutdown: Arc<Notify>) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accept = tokio::select! {
            biased;
            _ = shutdown.notified() => {
                tracing::info!("n8n_api shutdown signal received; stopping connections");
                break;
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "n8n_api connection task failed");
                }
                continue;
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
        connections.spawn(async move {
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

    connections.shutdown().await;
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
    let ts_unix = crate::time::now_unix_i64();

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

    // Two-path auth:
    // Path A — the static operator master token (full access, backward compat).
    // Path B — a scope-gated token from api_tokens.json (GOLD-ADAPT-ODY-31).
    let candidate = match extract_bearer_token(&auth_header) {
        Some(t) => t,
        None => {
            let tripped = state.cooldown.record_failure(&peer_ip, now);
            tracing::warn!(peer = %peer_ip, path = %path, tripped, "n8n_api auth refused: no bearer");
            let hint = if tripped {
                "5 failures hit — cooldown engaged for 60s. Verify your bearer token."
            } else {
                "set Authorization: Bearer <token>"
            };
            return HandlerOutcome::error(ApiErrorCode::Unauthorized, "bearer token missing", hint)
                .into_http_response(&request_id);
        }
    };

    if constant_time_token_eq(candidate, &state.token) {
        // Path A: master token — full access, no scope check needed.
        state.cooldown.record_success(&peer_ip);
    } else {
        // Path B: try scope-gated tokens. An unmapped path fails CLOSED for
        // scoped tokens — only the master token (Path A) reaches route()'s
        // 404 for unknown paths (security review 2026-07-03).
        let Some(required_scope) = required_scope_for(method.as_str(), &path) else {
            let tripped = state.cooldown.record_failure(&peer_ip, now);
            tracing::warn!(peer = %peer_ip, path = %path, tripped,
                "n8n_api: scoped token on unmapped path — denied fail-closed");
            return HandlerOutcome::error(
                ApiErrorCode::Unauthorized,
                "endpoint not available to scoped tokens",
                "use the master token or add the route's scope mapping",
            )
            .into_http_response(&request_id);
        };
        // PBKDF2 + locked file I/O are blocking work. Keep them off the Tokio
        // worker and perform verification + last_used persistence as one
        // cross-process transaction so a stale request cannot resurrect a
        // concurrently revoked token.
        let token_home = state.home.clone();
        let token_candidate = candidate.to_owned();
        let auth_result = match tokio::task::spawn_blocking(move || {
            api_tokens::verify_token_for_scope_persisted(
                &token_home,
                &token_candidate,
                required_scope,
            )
        })
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                // Infrastructure failure — the token file is unreadable. This is NOT
                // an auth failure: the client's token may be perfectly valid but the
                // store is temporarily unavailable. Do NOT call cooldown.record_failure
                // (that would penalise the client for a server-side fault).
                tracing::warn!(error = %e, path = %path, "n8n_api: api_tokens store unreadable — returning 503");
                return HandlerOutcome::error(
                    ApiErrorCode::StoreUnavailable,
                    "token store temporarily unavailable",
                    "check disk permissions on ~/.neoth/ and retry",
                )
                .into_http_response(&request_id);
            }
            Err(e) => {
                tracing::error!(error = %e, path = %path, "n8n_api: token verification worker failed");
                return HandlerOutcome::error(
                    ApiErrorCode::StoreUnavailable,
                    "token verification temporarily unavailable",
                    "retry the request; inspect daemon logs if the failure persists",
                )
                .into_http_response(&request_id);
            }
        };

        match auth_result {
            VerifyResult::Ok { token_id } => {
                tracing::debug!(token_id = %token_id, path = %path, "n8n_api scope-gated token accepted");
                state.cooldown.record_success(&peer_ip);
            }
            VerifyResult::InsufficientScope { token_id, required } => {
                tracing::warn!(
                    token_id = %token_id,
                    path = %path,
                    required_scope = %required,
                    "n8n_api scope-gated token lacks required scope"
                );
                let tripped = state.cooldown.record_failure(&peer_ip, now);
                let hint = if tripped {
                    "5 failures hit — cooldown active. Token does not grant the required scope."
                } else {
                    "token does not grant the scope required for this endpoint"
                };
                return HandlerOutcome::error(
                    ApiErrorCode::PermissionDenied,
                    format!("insufficient scope — need {required}"),
                    hint,
                )
                .into_http_response(&request_id);
            }
            VerifyResult::Denied => {
                let tripped = state.cooldown.record_failure(&peer_ip, now);
                tracing::warn!(
                    peer = %peer_ip,
                    path = %path,
                    tripped,
                    "n8n_api auth refused"
                );
                let hint = if tripped {
                    "5 failures hit — cooldown engaged for 60s. Verify ~/.neoth/n8n_api_token."
                } else {
                    "set Authorization: Bearer <token> using ~/.neoth/n8n_api_token"
                };
                return HandlerOutcome::error(
                    ApiErrorCode::Unauthorized,
                    "bearer token missing or invalid",
                    hint,
                )
                .into_http_response(&request_id);
            }
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
    // Security fix (NEOTH-AUDIT-HTTP-BODY-LIMITS-01): wrap the Incoming body with
    // `Limited` BEFORE `.collect()` so the allocator never grows past
    // REQUEST_BODY_LIMIT_BYTES. The previous pattern called `.collect()` first and
    // only checked the length afterwards — a single oversized POST would fully
    // allocate in memory before being rejected. `Limited` from `http_body_util`
    // stops reading at the byte cap and returns an error before any further
    // allocation. Mirrors the established pattern in `channels/webhook_listener.rs`.
    let limited = Limited::new(req.into_body(), REQUEST_BODY_LIMIT_BYTES);
    let bytes = match limited.collect().await {
        Ok(c) => c.to_bytes(),
        Err(error) => return Err(body_read_error(error.as_ref())),
    };
    Ok(bytes.to_vec())
}

fn body_read_error(error: &(dyn std::error::Error + Send + Sync + 'static)) -> HandlerOutcome {
    if error.downcast_ref::<LengthLimitError>().is_some() {
        HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            format!("request body exceeds cap {REQUEST_BODY_LIMIT_BYTES} bytes"),
            "shrink the payload — the workflow JSON likely embeds a huge field",
        )
    } else {
        HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            format!("request body read failed: {error}"),
            "retry the request; if it repeats, inspect the client or connection",
        )
    }
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
                crate::wal::dpapi::unprotect(&bytes).map_err(|e| {
                    std::io::Error::other(format!("DPAPI unwrap n8n_api_token: {e}"))
                })?
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

    #[tokio::test]
    async fn shutdown_aborts_idle_connection_before_wal_drain() {
        use tokio::io::AsyncWriteExt;

        let home = tempfile::tempdir().unwrap();
        let (writer, wal_join) =
            crate::wal::writer::spawn(home.path().join("n8n-shutdown.wal")).unwrap();
        let config = FreedomConfig::default();
        let state = Arc::new(ApiState {
            writer: writer.clone(),
            config: Arc::new(config.clone()),
            reload_controller: Arc::new(crate::config::reload::ReloadController::new(
                config,
                home.path().join("freedom.yaml"),
            )),
            home: home.path().to_path_buf(),
            token: "test-token".to_string(),
            cooldown: Arc::new(AuthCooldown::new()),
            boot_instant: Instant::now(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let shutdown = Arc::new(Notify::new());
        let server = tokio::spawn(run_server(
            listener,
            Arc::clone(&state),
            Arc::clone(&shutdown),
        ));

        let mut idle = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        idle.write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while Arc::strong_count(&state) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("n8n server never accepted the idle connection");

        shutdown.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(3), server)
            .await
            .expect("n8n server did not stop")
            .expect("n8n server task panicked");
        drop(state);
        drop(writer);
        tokio::time::timeout(std::time::Duration::from_secs(3), wal_join)
            .await
            .expect("idle n8n connection retained ApiState's WAL sender")
            .expect("WAL writer task panicked");

        drop(idle);
    }

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

    // ── FIX-2: StoreUnavailable maps to 503 ─────────────────────────────────

    #[test]
    fn store_unavailable_maps_to_503() {
        let outcome = HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            "token store temporarily unavailable",
            "check disk permissions on ~/.neoth/ and retry",
        );
        let resp = outcome.into_http_response("req-503");
        assert_eq!(resp.status(), 503);
    }

    // ── FIX-6: required_scope_for contract ───────────────────────────────────

    #[test]
    fn required_scope_for_all_mapped_routes_return_some() {
        // Every explicitly-mapped (method, path) must return a scope string —
        // this pins the fail-closed contract: add a route here when adding it
        // to required_scope_for.
        let cases = [
            ("GET", "/api/health"),
            ("POST", "/api/recall"),
            ("GET", "/api/stats"),
            ("POST", "/api/memory/save"),
            ("POST", "/api/provider/call"),
            ("POST", "/api/channel/send"),
        ];
        for (method, path) in cases {
            let scope = required_scope_for(method, path);
            assert!(
                scope.is_some(),
                "({method}, {path}) must return Some(scope) — add it to required_scope_for"
            );
        }
    }

    #[test]
    fn required_scope_for_unmapped_path_returns_none() {
        // Unknown paths must return None so the caller can fail CLOSED.
        // This pins the contract: scoped tokens are denied on unknown routes,
        // not silently granted.
        assert_eq!(required_scope_for("GET", "/api/unknown"), None);
        assert_eq!(required_scope_for("POST", "/api/unknown"), None);
        assert_eq!(required_scope_for("DELETE", "/api/health"), None);
        assert_eq!(required_scope_for("GET", "/"), None);
    }

    // ── NEOTH-AUDIT-HTTP-BODY-LIMITS-01: Limited body cap ───────────────────────
    //
    // Verify that `http_body_util::Limited` — the same wrapper used by
    // `read_body_capped` — rejects bodies exceeding the cap BEFORE the
    // allocator grows past that limit, and passes bodies at/under the cap.

    #[tokio::test]
    async fn limited_rejects_body_one_byte_over_cap() {
        use http_body_util::{BodyExt, Full, Limited};
        use hyper::body::Bytes;
        let oversized = Full::new(Bytes::from(vec![0u8; REQUEST_BODY_LIMIT_BYTES + 1]));
        let limited = Limited::new(oversized, REQUEST_BODY_LIMIT_BYTES);
        let error = limited.collect().await.unwrap_err();
        let outcome = body_read_error(error.as_ref());
        match outcome {
            HandlerOutcome::Err { message, .. } => assert_eq!(
                message,
                format!("request body exceeds cap {REQUEST_BODY_LIMIT_BYTES} bytes")
            ),
            HandlerOutcome::Ok { .. } => panic!("oversized body must be rejected"),
        }
    }

    #[test]
    fn body_transport_error_is_not_reported_as_size_violation() {
        let error = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset");
        let outcome = body_read_error(&error);
        match outcome {
            HandlerOutcome::Err { message, .. } => {
                assert!(message.contains("request body read failed"));
                assert!(message.contains("peer reset"));
                assert!(!message.contains("exceeds cap"));
            }
            HandlerOutcome::Ok { .. } => panic!("body transport error must be rejected"),
        }
    }

    #[tokio::test]
    async fn limited_passes_body_at_exact_cap() {
        use http_body_util::{BodyExt, Full, Limited};
        use hyper::body::Bytes;
        let at_cap = Full::new(Bytes::from(vec![0u8; REQUEST_BODY_LIMIT_BYTES]));
        let limited = Limited::new(at_cap, REQUEST_BODY_LIMIT_BYTES);
        assert!(
            limited.collect().await.is_ok(),
            "Limited must allow a body at exactly the {REQUEST_BODY_LIMIT_BYTES} byte cap"
        );
    }
}
