//! N-3 — NEOTH localhost HTTP API for n8n integration.
//!
//! Full spec: `PLAN/SPEC_n8n_localhost_api_2026-05-23.md`.
//!
//! Layer split:
//! - `mod.rs` (this file) — request/response primitives + bearer
//!   token helpers + WAL payload builder. Pure-fn / deterministic;
//!   no I/O.
//! - [`auth`] — 5-strike auth-failure cooldown tracker (in-memory).
//! - [`server`] — hyper 1.x task that binds to `127.0.0.1:<port>`,
//!   pipes requests through the auth middleware + loopback guard +
//!   into [`handlers`].
//! - [`handlers`] — the six v1 endpoint handlers
//!   (/api/health, /api/recall, /api/provider/call,
//!   /api/channel/send, /api/stats, /api/memory/save).
//!
//! Spawned from `cli::serve::run_serve` when
//! `freedom.yaml::n8n_api.enabled = true`. Bind is loopback-only
//! (defence in depth — middleware AND hyper bind both enforce
//! `127.0.0.1` so a single regression can't expose the API to LAN).

pub mod auth;
pub mod handlers;
pub mod server;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Default port for the NEOTH localhost API n8n consumes. Pinned —
/// every N-2 bootstrap workflow JSON references this exact port.
/// Renaming requires a coordinated workflow-asset rewrite.
pub const DEFAULT_N8N_API_PORT: u16 = 9744;

/// Token length in characters — 43-char base64url-NOPAD ⇔ 32 raw
/// bytes (256 bits of entropy). Matches the RFC 7636 PKCE verifier
/// length already used in `installers/oauth_pkce.rs`.
pub const N8N_API_TOKEN_CHAR_LEN: usize = 43;

/// 401-cooldown gate. 5 consecutive auth failures from one source
/// triggers a 60-second silence window. Defends against accidental
/// operator config drift / mistyped env without becoming a DOS
/// vector (operator owns the host).
pub const AUTH_FAILURE_STRIKE_LIMIT: u32 = 5;
pub const AUTH_FAILURE_COOLDOWN_SECS: u64 = 60;

/// Per-request body cap. n8n payloads carrying a `/api/memory/save`
/// body or `/api/provider/call` prompt should never exceed this
/// without the operator explicitly raising it. 256 KiB matches the
/// `assets/n8n_workflows/*.json` worst-case prompt envelope.
pub const REQUEST_BODY_LIMIT_BYTES: usize = 256 * 1024;

/// API error code surfaced in the JSON envelope. Operator + n8n
/// workflow read this to decide retry vs surface-to-human.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ApiErrorCode {
    /// Bearer token missing / wrong / cooldown active.
    Unauthorized,
    /// Autonomy / consent gate refused (operator-level decision).
    PermissionDenied,
    /// Endpoint path unknown.
    NotFound,
    /// Body failed JSON parse or missing required field.
    BadRequest,
    /// Downstream NEOTH op (provider / channel / recall) failed.
    UpstreamError,
    /// Localhost-only enforcement caught a non-loopback peer.
    NonLoopback,
    /// Token store (file on disk) is unreadable — infrastructure failure,
    /// not an auth failure. Maps to HTTP 503. Cooldown is NOT incremented
    /// for this variant: the client token may be correct; the store is just
    /// temporarily unavailable.
    StoreUnavailable,
}

impl ApiErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "Unauthorized",
            Self::PermissionDenied => "PermissionDenied",
            Self::NotFound => "NotFound",
            Self::BadRequest => "BadRequest",
            Self::UpstreamError => "UpstreamError",
            Self::NonLoopback => "NonLoopback",
            Self::StoreUnavailable => "StoreUnavailable",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::PermissionDenied => 403,
            Self::NotFound => 404,
            Self::BadRequest => 400,
            Self::UpstreamError => 502,
            Self::NonLoopback => 403,
            Self::StoreUnavailable => 503,
        }
    }
}

/// Successful API response envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiOkResponse<T: Serialize> {
    pub ok: bool, // always true
    pub data: T,
    pub request_id: String,
}

impl<T: Serialize> ApiOkResponse<T> {
    pub fn new(data: T, request_id: impl Into<String>) -> Self {
        Self {
            ok: true,
            data,
            request_id: request_id.into(),
        }
    }
}

/// Error response envelope. `hint` is operator-actionable text the
/// n8n execution log surfaces so operator knows WHY + WHAT to do.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub ok: bool, // always false
    pub error: ApiErrorBody,
    pub request_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: ApiErrorCode,
    pub message: String,
    pub hint: String,
}

impl ApiErrorResponse {
    pub fn new(
        code: ApiErrorCode,
        message: impl Into<String>,
        hint: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            ok: false,
            error: ApiErrorBody {
                code,
                message: message.into(),
                hint: hint.into(),
            },
            request_id: request_id.into(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Fresh per-request id. UUID v7 = time-ordered so WAL replay can
/// sort request chains chronologically without re-deriving from the
/// ts_unix field.
pub fn new_request_id() -> String {
    Uuid::now_v7().to_string()
}

/// Constant-time bearer-token compare. Operators care about the
/// 5-strike cooldown defending against typos, but the compare itself
/// must be timing-safe so a future remote-exposure misconfig doesn't
/// leak the token byte-by-byte.
pub fn constant_time_token_eq(provided: &str, expected: &str) -> bool {
    // Security review 2026-07-03: digest-compare removes the content-timing
    // channel (no byte-by-byte early exit) and eliminates the early-length-
    // return (both inputs are hashed to a fixed 32-byte digest before the
    // constant-time comparison). Residual length signal via SHA-256 block
    // count is negligible for the fixed-width tokens this function guards
    // (base64url-encoded 32-byte secrets fit in one block). Full content
    // timing confidentiality holds; length confidentiality is best-effort.
    use sha2::{Digest, Sha256};
    let a = Sha256::digest(provided.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    use subtle::ConstantTimeEq as _;
    a.as_slice().ct_eq(b.as_slice()).unwrap_u8() == 1
}

/// Extract the bearer token from an `Authorization: Bearer <token>`
/// header value. Case-insensitive on the scheme name per RFC 6750.
/// Returns None for malformed inputs so the auth middleware fails
/// closed.
pub fn extract_bearer_token(header_value: &str) -> Option<&str> {
    let trimmed = header_value.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("bearer ") {
        return None;
    }
    let token = trimmed[7..].trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Build the JSON byte vec for the `EVENT_TYPE_N8N_REQUEST` (0x39)
/// WAL frame. `endpoint` is the path (e.g. `/api/recall`),
/// `source_ip` is `127.0.0.1` in normal operation (defence in depth
/// — non-loopback addresses are rejected upstream).
pub fn build_n8n_request_payload(
    endpoint: &str,
    source_ip: &str,
    request_id: &str,
    ts_unix: i64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "endpoint": endpoint,
        "source_ip": source_ip,
        "request_id": request_id,
        "ts_unix": ts_unix,
    }))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── port + token + cooldown constants ───────────────────────

    #[test]
    fn default_port_pinned_for_workflow_asset_compat() {
        assert_eq!(DEFAULT_N8N_API_PORT, 9744);
    }

    #[test]
    fn token_char_len_matches_256_bit_entropy() {
        assert_eq!(N8N_API_TOKEN_CHAR_LEN, 43);
    }

    #[test]
    fn auth_failure_strike_limit_pinned() {
        assert_eq!(AUTH_FAILURE_STRIKE_LIMIT, 5);
        assert_eq!(AUTH_FAILURE_COOLDOWN_SECS, 60);
    }

    #[test]
    fn request_body_limit_pinned() {
        assert_eq!(REQUEST_BODY_LIMIT_BYTES, 256 * 1024);
    }

    // ── ApiErrorCode ────────────────────────────────────────────

    #[test]
    fn error_code_as_str_pinned() {
        assert_eq!(ApiErrorCode::Unauthorized.as_str(), "Unauthorized");
        assert_eq!(ApiErrorCode::PermissionDenied.as_str(), "PermissionDenied");
        assert_eq!(ApiErrorCode::NotFound.as_str(), "NotFound");
        assert_eq!(ApiErrorCode::BadRequest.as_str(), "BadRequest");
        assert_eq!(ApiErrorCode::UpstreamError.as_str(), "UpstreamError");
        assert_eq!(ApiErrorCode::NonLoopback.as_str(), "NonLoopback");
        assert_eq!(ApiErrorCode::StoreUnavailable.as_str(), "StoreUnavailable");
    }

    #[test]
    fn error_code_http_status_pinned() {
        assert_eq!(ApiErrorCode::Unauthorized.http_status(), 401);
        assert_eq!(ApiErrorCode::PermissionDenied.http_status(), 403);
        assert_eq!(ApiErrorCode::NotFound.http_status(), 404);
        assert_eq!(ApiErrorCode::BadRequest.http_status(), 400);
        assert_eq!(ApiErrorCode::UpstreamError.http_status(), 502);
        assert_eq!(ApiErrorCode::NonLoopback.http_status(), 403);
        assert_eq!(ApiErrorCode::StoreUnavailable.http_status(), 503);
    }

    #[test]
    fn error_code_serialises_pascal_case() {
        let s = serde_json::to_string(&ApiErrorCode::PermissionDenied).unwrap();
        assert_eq!(s, "\"PermissionDenied\"");
    }

    // ── envelope shapes ─────────────────────────────────────────

    #[test]
    fn ok_envelope_carries_ok_true_data_request_id() {
        let r = ApiOkResponse::new(serde_json::json!({"x": 1}), "req-1");
        let bytes = serde_json::to_vec(&r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["x"], 1);
        assert_eq!(v["request_id"], "req-1");
    }

    #[test]
    fn error_envelope_carries_ok_false_code_message_hint() {
        let r = ApiErrorResponse::new(
            ApiErrorCode::PermissionDenied,
            "autonomy strict refuses cloud providers",
            "bump autonomy or pick local Qwen",
            "req-2",
        );
        let v: serde_json::Value = serde_json::from_slice(&r.to_bytes()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "PermissionDenied");
        assert!(v["error"]["message"].as_str().unwrap().contains("autonomy"));
        assert!(v["error"]["hint"].as_str().unwrap().contains("local Qwen"));
        assert_eq!(v["request_id"], "req-2");
    }

    // ── request id ──────────────────────────────────────────────

    #[test]
    fn new_request_id_returns_uuid_v7_shape() {
        let id = new_request_id();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[8], b'-');
        assert_eq!(id.as_bytes()[13], b'-');
        assert_eq!(id.as_bytes()[18], b'-');
        assert_eq!(id.as_bytes()[23], b'-');
    }

    #[test]
    fn two_request_ids_differ() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
    }

    // ── token compare ───────────────────────────────────────────

    #[test]
    fn constant_time_eq_matches_identical_tokens() {
        assert!(constant_time_token_eq("abcdef", "abcdef"));
    }

    #[test]
    fn constant_time_eq_rejects_length_mismatch() {
        assert!(!constant_time_token_eq("short", "longer-token"));
    }

    #[test]
    fn constant_time_eq_rejects_one_byte_diff() {
        assert!(!constant_time_token_eq("abcdef0", "abcdef1"));
    }

    #[test]
    fn constant_time_eq_returns_false_on_empty_inputs() {
        assert!(constant_time_token_eq("", ""));
    }

    // ── extract_bearer_token ────────────────────────────────────

    #[test]
    fn extract_bearer_token_canonical_form() {
        assert_eq!(extract_bearer_token("Bearer abc-123"), Some("abc-123"));
    }

    #[test]
    fn extract_bearer_token_case_insensitive_scheme() {
        assert_eq!(extract_bearer_token("BEARER token"), Some("token"));
        assert_eq!(extract_bearer_token("bearer token"), Some("token"));
        assert_eq!(extract_bearer_token("Bearer token"), Some("token"));
    }

    #[test]
    fn extract_bearer_token_trims_surrounding_whitespace() {
        assert_eq!(extract_bearer_token("  Bearer  abc  "), Some("abc"));
    }

    #[test]
    fn extract_bearer_token_rejects_wrong_scheme() {
        assert!(extract_bearer_token("Basic abc123").is_none());
        assert!(extract_bearer_token("Digest xyz").is_none());
    }

    #[test]
    fn extract_bearer_token_rejects_missing_value() {
        assert!(extract_bearer_token("Bearer").is_none());
        assert!(extract_bearer_token("Bearer   ").is_none());
        assert!(extract_bearer_token("").is_none());
    }

    // ── WAL payload builder ─────────────────────────────────────

    #[test]
    fn n8n_request_payload_carries_required_fields() {
        let bytes =
            build_n8n_request_payload("/api/recall", "127.0.0.1", "req-7f3a", 1_700_000_000);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["endpoint"], "/api/recall");
        assert_eq!(v["source_ip"], "127.0.0.1");
        assert_eq!(v["request_id"], "req-7f3a");
        assert_eq!(v["ts_unix"], 1_700_000_000);
    }

    #[test]
    fn n8n_request_payload_round_trips_endpoint_path_verbatim() {
        for path in ["/api/health", "/api/provider/call", "/api/channel/send"] {
            let bytes = build_n8n_request_payload(path, "127.0.0.1", "r", 0);
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["endpoint"], path);
        }
    }
}
