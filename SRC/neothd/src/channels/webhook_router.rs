//! Transport-agnostic webhook router (A7 follow-on).
//!
//! The verify primitives in `webhook_verify.rs` are pure-crypto +
//! pure-string-parsing. This module sits one layer up: it takes a
//! framework-neutral request shape (method + path + headers + body
//! + querystring), runs it through the right verify path for the
//!   platform, and returns a framework-neutral response shape
//!   (status + body).
//!
//! Why no hyper / axum dependency: keeping the router transport-free
//! means we can swap the HTTP server (hyper 1.x today, axum tomorrow,
//! reverse-proxy bridge on a constrained operator's box) without
//! rewriting the security-critical wiring. The HTTP binding becomes
//! ~30 lines of glue per framework — call `route_meta_webhook` or
//! `route_slack_webhook` and translate the [`WebhookResponse`] to
//! whatever the framework expects.
//!
//! Pipeline for the Meta WhatsApp Cloud API webhook:
//!   1. `GET /webhook?hub.mode=subscribe&hub.verify_token=X&hub.challenge=Y`
//!      → `meta_challenge_response` decides 200/403/400.
//!   2. `POST /webhook` with body + `X-Hub-Signature-256` header
//!      → `verify_meta_signature` enforces HMAC, then
//!        `whatsapp_webhook::decode_payload` produces `InboundMessage`s.
//!   3. Caller fans the messages out to its pipeline handler. Always
//!      respond 200 so Meta stops re-delivering, even on a
//!      `NoMessages` outcome (a status update isn't a content event).
//!
//! Slack Events API:
//!   1. `POST /slack/events` with body + `X-Slack-Signature` +
//!      `X-Slack-Request-Timestamp` → `verify_slack_signature`.
//!   2. Three event-envelope flavours: `url_verification` (handshake),
//!      `event_callback` (real event), `app_rate_limited` (advisory).
//!      The router responds to `url_verification` inline; the other
//!      two return 200 + empty body and the caller decodes.

use std::collections::HashMap;

use super::webhook_verify::{
    MetaChallengeOutcome, SlackVerifyError, meta_challenge_response, verify_meta_signature,
    verify_slack_signature,
};

/// HTTP request as seen by the router. Caller normalises into this
/// shape — header lookup is case-insensitive (RFC 7230 §3.2).
#[derive(Debug, Clone)]
pub struct WebhookRequest {
    pub method: HttpMethod,
    /// Path component (`/webhook`, `/slack/events`, ...). Used by the
    /// caller's router; this module doesn't dispatch on it.
    pub path: String,
    /// Raw query-string (without leading `?`). Empty when absent.
    pub query: String,
    /// Lowercase-keyed header map — caller is responsible for the
    /// case-fold (most HTTP frameworks expose case-insensitive lookups
    /// but the router stays simple).
    pub headers_lc: HashMap<String, String>,
    /// Raw body bytes. May be empty.
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Other,
}

/// Response the caller should serialize onto the wire. `status` is the
/// HTTP status code; `body` is the response body (may be empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookResponse {
    pub status: u16,
    pub body: String,
}

impl WebhookResponse {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
        }
    }
    pub fn forbidden(reason: impl Into<String>) -> Self {
        Self {
            status: 403,
            body: reason.into(),
        }
    }
    pub fn bad_request(reason: impl Into<String>) -> Self {
        Self {
            status: 400,
            body: reason.into(),
        }
    }
    pub fn method_not_allowed() -> Self {
        Self {
            status: 405,
            body: "method not allowed".into(),
        }
    }
}

/// Route a Meta WhatsApp Cloud API webhook request to the right
/// verify/decode path. Returns the HTTP response the caller should
/// serialise + a parallel `RouteOutcome` describing what (if anything)
/// reached the pipeline.
///
/// `app_secret` is the Meta App Secret used to compute
/// `X-Hub-Signature-256`. `operator_verify_token` is the value the
/// operator pinned in the Meta console for the GET handshake.
///
/// Errors are NEVER leaked into the response body verbatim — only
/// short canonical reasons (`"signature mismatch"`, `"bad mode"`).
/// Detailed reasons go into [`RouteOutcome`] for operator-facing
/// logging.
pub fn route_meta_webhook(
    req: &WebhookRequest,
    app_secret: &[u8],
    operator_verify_token: &str,
) -> (WebhookResponse, MetaRouteOutcome) {
    match req.method {
        HttpMethod::Get => match meta_challenge_response(&req.query, operator_verify_token) {
            MetaChallengeOutcome::Echo(nonce) => (
                WebhookResponse::ok(nonce.clone()),
                MetaRouteOutcome::HandshakeAccepted { nonce },
            ),
            MetaChallengeOutcome::TokenMismatch => (
                WebhookResponse::forbidden("forbidden"),
                MetaRouteOutcome::HandshakeRejected {
                    reason: "verify_token mismatch".to_string(),
                },
            ),
            MetaChallengeOutcome::BadRequest { reason } => (
                WebhookResponse::bad_request("bad request"),
                MetaRouteOutcome::HandshakeRejected { reason },
            ),
        },
        HttpMethod::Post => {
            let sig = req
                .headers_lc
                .get("x-hub-signature-256")
                .map(String::as_str)
                .unwrap_or("");
            if sig.is_empty() {
                return (
                    WebhookResponse::forbidden("forbidden"),
                    MetaRouteOutcome::SignatureMissing,
                );
            }
            if !verify_meta_signature(&req.body, sig, app_secret) {
                return (
                    WebhookResponse::forbidden("forbidden"),
                    MetaRouteOutcome::SignatureMismatch,
                );
            }
            // Verified — defer to the caller's payload decoder. We
            // always respond 200 so Meta doesn't re-deliver; the
            // caller's pipeline handler is responsible for content
            // dispatch.
            let raw = match std::str::from_utf8(&req.body) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    return (
                        WebhookResponse::bad_request("body is not utf-8"),
                        MetaRouteOutcome::BodyNotUtf8,
                    );
                }
            };
            (
                WebhookResponse::ok(""),
                MetaRouteOutcome::Verified { raw_body: raw },
            )
        }
        HttpMethod::Other => (
            WebhookResponse::method_not_allowed(),
            MetaRouteOutcome::UnsupportedMethod,
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaRouteOutcome {
    /// GET handshake accepted — `nonce` was echoed in the response.
    HandshakeAccepted { nonce: String },
    /// GET handshake rejected (token mismatch / missing param / bad mode).
    HandshakeRejected { reason: String },
    /// POST body passed signature verification. `raw_body` is the
    /// verified UTF-8 string the caller should feed into
    /// `whatsapp_webhook::decode_payload`.
    Verified { raw_body: String },
    /// POST arrived without the `X-Hub-Signature-256` header — Meta
    /// always sends it on real callbacks, so its absence is treated
    /// like a signature mismatch.
    SignatureMissing,
    /// `X-Hub-Signature-256` didn't match HMAC-SHA256(secret, body).
    SignatureMismatch,
    /// POST body wasn't valid UTF-8 — Meta sends JSON, so this is
    /// always a misconfiguration or attack.
    BodyNotUtf8,
    /// PUT/DELETE/etc. — webhook path responds only to GET and POST.
    UnsupportedMethod,
}

/// Route a Slack Events API webhook. Slack puts everything (handshake
/// + real events + advisories) over POST, distinguished by the body's
///   `type` field. The router enforces signature + timestamp, then
///   returns the verified body to the caller for envelope routing.
///
/// `signing_secret` is the operator's Slack signing secret.
/// `now_unix` should be `std::time::SystemTime::now()` in seconds —
/// taken as a parameter so tests can pin the clock.
pub fn route_slack_webhook(
    req: &WebhookRequest,
    signing_secret: &[u8],
    now_unix: i64,
) -> (WebhookResponse, SlackRouteOutcome) {
    if req.method != HttpMethod::Post {
        return (
            WebhookResponse::method_not_allowed(),
            SlackRouteOutcome::UnsupportedMethod,
        );
    }
    let ts = match req.headers_lc.get("x-slack-request-timestamp") {
        Some(t) => t.as_str(),
        None => {
            return (
                WebhookResponse::forbidden("forbidden"),
                SlackRouteOutcome::HeaderMissing {
                    name: "x-slack-request-timestamp",
                },
            );
        }
    };
    let sig = match req.headers_lc.get("x-slack-signature") {
        Some(s) => s.as_str(),
        None => {
            return (
                WebhookResponse::forbidden("forbidden"),
                SlackRouteOutcome::HeaderMissing {
                    name: "x-slack-signature",
                },
            );
        }
    };
    if let Err(e) = verify_slack_signature(&req.body, ts, sig, signing_secret, now_unix) {
        return (
            WebhookResponse::forbidden("forbidden"),
            SlackRouteOutcome::Rejected { error: e },
        );
    }
    let raw = match std::str::from_utf8(&req.body) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return (
                WebhookResponse::bad_request("body is not utf-8"),
                SlackRouteOutcome::BodyNotUtf8,
            );
        }
    };
    // Slack's url_verification handshake is body-encoded: the operator
    // must echo back the `challenge` field. Identify the envelope
    // shape via a cheap substring check before triggering a full JSON
    // parse — keeps the hot path tight for normal events.
    if raw.contains("\"url_verification\"")
        && let Ok(envelope) = serde_json::from_str::<SlackUrlVerification>(&raw)
        && envelope.envelope_type == "url_verification"
        && !envelope.challenge.is_empty()
    {
        return (
            WebhookResponse::ok(envelope.challenge.clone()),
            SlackRouteOutcome::UrlVerification {
                challenge: envelope.challenge,
            },
        );
    }
    (
        WebhookResponse::ok(""),
        SlackRouteOutcome::Verified { raw_body: raw },
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackRouteOutcome {
    /// Verified body decoded to a `url_verification` envelope — the
    /// router echoed the `challenge` field. No further work.
    UrlVerification { challenge: String },
    /// Signature + timestamp verified. Caller decodes `raw_body` to
    /// the event envelope (event_callback / app_rate_limited / ...).
    Verified { raw_body: String },
    /// One of the required headers was absent.
    HeaderMissing { name: &'static str },
    /// Signature failed verification (taxonomy in [`SlackVerifyError`]).
    Rejected { error: SlackVerifyError },
    /// Body wasn't valid UTF-8 — Slack sends JSON.
    BodyNotUtf8,
    /// Not POST.
    UnsupportedMethod,
}

#[derive(Debug, serde::Deserialize)]
struct SlackUrlVerification {
    #[serde(rename = "type")]
    envelope_type: String,
    #[serde(default)]
    challenge: String,
}

#[cfg(test)]
mod tests {
    use super::super::webhook_verify::{sign_meta, sign_slack};
    use super::*;

    fn meta_get_req(query: &str) -> WebhookRequest {
        WebhookRequest {
            method: HttpMethod::Get,
            path: "/webhook".into(),
            query: query.into(),
            headers_lc: HashMap::new(),
            body: Vec::new(),
        }
    }

    fn meta_post_req(body: &[u8], sig: &str) -> WebhookRequest {
        let mut headers = HashMap::new();
        headers.insert("x-hub-signature-256".into(), sig.to_string());
        WebhookRequest {
            method: HttpMethod::Post,
            path: "/webhook".into(),
            query: String::new(),
            headers_lc: headers,
            body: body.to_vec(),
        }
    }

    // ── Meta GET handshake ─────────────────────────────────────────────

    #[test]
    fn meta_get_happy_path_echoes_challenge() {
        let req =
            meta_get_req("hub.mode=subscribe&hub.verify_token=secret&hub.challenge=NONCE-XYZ");
        let (resp, outcome) = route_meta_webhook(&req, b"app-secret", "secret");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "NONCE-XYZ");
        assert_eq!(
            outcome,
            MetaRouteOutcome::HandshakeAccepted {
                nonce: "NONCE-XYZ".into()
            }
        );
    }

    #[test]
    fn meta_get_token_mismatch_is_403() {
        let req = meta_get_req("hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=x");
        let (resp, outcome) = route_meta_webhook(&req, b"app-secret", "right");
        assert_eq!(resp.status, 403);
        match outcome {
            MetaRouteOutcome::HandshakeRejected { reason } => {
                assert!(reason.contains("verify_token"));
            }
            other => panic!("expected HandshakeRejected, got {other:?}"),
        }
    }

    #[test]
    fn meta_get_bad_mode_is_400() {
        let req = meta_get_req("hub.mode=unsubscribe&hub.verify_token=t&hub.challenge=x");
        let (resp, _) = route_meta_webhook(&req, b"x", "t");
        assert_eq!(resp.status, 400);
    }

    // ── Meta POST verification ─────────────────────────────────────────

    #[test]
    fn meta_post_happy_path_returns_verified_body() {
        let body = br#"{"object":"whatsapp_business_account","entry":[]}"#;
        let sig = sign_meta(body, b"app-secret");
        let req = meta_post_req(body, &sig);
        let (resp, outcome) = route_meta_webhook(&req, b"app-secret", "v");
        assert_eq!(resp.status, 200);
        match outcome {
            MetaRouteOutcome::Verified { raw_body } => {
                assert!(raw_body.contains("whatsapp_business_account"));
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn meta_post_missing_signature_header_is_forbidden() {
        let req = WebhookRequest {
            method: HttpMethod::Post,
            path: "/webhook".into(),
            query: String::new(),
            headers_lc: HashMap::new(),
            body: b"{}".to_vec(),
        };
        let (resp, outcome) = route_meta_webhook(&req, b"k", "v");
        assert_eq!(resp.status, 403);
        assert_eq!(outcome, MetaRouteOutcome::SignatureMissing);
    }

    #[test]
    fn meta_post_signature_mismatch_is_forbidden() {
        let body = b"original";
        let sig = sign_meta(body, b"right");
        let req = meta_post_req(body, &sig);
        let (resp, outcome) = route_meta_webhook(&req, b"wrong", "v");
        assert_eq!(resp.status, 403);
        assert_eq!(outcome, MetaRouteOutcome::SignatureMismatch);
    }

    #[test]
    fn meta_post_body_not_utf8_is_400() {
        let body = vec![0xff, 0xfe, 0x00, 0x80];
        let sig = sign_meta(&body, b"k");
        let req = meta_post_req(&body, &sig);
        let (resp, outcome) = route_meta_webhook(&req, b"k", "v");
        assert_eq!(resp.status, 400);
        assert_eq!(outcome, MetaRouteOutcome::BodyNotUtf8);
    }

    #[test]
    fn meta_other_method_returns_405() {
        let req = WebhookRequest {
            method: HttpMethod::Other,
            path: "/webhook".into(),
            query: String::new(),
            headers_lc: HashMap::new(),
            body: vec![],
        };
        let (resp, outcome) = route_meta_webhook(&req, b"k", "v");
        assert_eq!(resp.status, 405);
        assert_eq!(outcome, MetaRouteOutcome::UnsupportedMethod);
    }

    // ── Slack POST verification ────────────────────────────────────────

    fn slack_post_req(body: &[u8], ts: &str, sig: &str) -> WebhookRequest {
        let mut headers = HashMap::new();
        headers.insert("x-slack-signature".into(), sig.to_string());
        headers.insert("x-slack-request-timestamp".into(), ts.to_string());
        WebhookRequest {
            method: HttpMethod::Post,
            path: "/slack/events".into(),
            query: String::new(),
            headers_lc: headers,
            body: body.to_vec(),
        }
    }

    #[test]
    fn slack_url_verification_echoes_challenge() {
        let body = br#"{"type":"url_verification","challenge":"slack-nonce-1"}"#;
        let ts = "1700000000";
        let sig = sign_slack(body, ts, b"sig-secret");
        let req = slack_post_req(body, ts, &sig);
        let (resp, outcome) = route_slack_webhook(&req, b"sig-secret", 1_700_000_000);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "slack-nonce-1");
        assert_eq!(
            outcome,
            SlackRouteOutcome::UrlVerification {
                challenge: "slack-nonce-1".into()
            }
        );
    }

    #[test]
    fn slack_event_callback_returns_verified_body() {
        let body = br#"{"type":"event_callback","event":{"type":"message"}}"#;
        let ts = "1700000000";
        let sig = sign_slack(body, ts, b"k");
        let req = slack_post_req(body, ts, &sig);
        let (resp, outcome) = route_slack_webhook(&req, b"k", 1_700_000_000);
        assert_eq!(resp.status, 200);
        match outcome {
            SlackRouteOutcome::Verified { raw_body } => {
                assert!(raw_body.contains("event_callback"));
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn slack_signature_mismatch_is_forbidden() {
        let body = b"x";
        let ts = "1700000000";
        let sig = sign_slack(body, ts, b"right");
        let req = slack_post_req(body, ts, &sig);
        let (resp, outcome) = route_slack_webhook(&req, b"wrong", 1_700_000_000);
        assert_eq!(resp.status, 403);
        assert!(matches!(outcome, SlackRouteOutcome::Rejected { .. }));
    }

    #[test]
    fn slack_missing_signature_header_is_forbidden() {
        let req = WebhookRequest {
            method: HttpMethod::Post,
            path: "/slack/events".into(),
            query: String::new(),
            headers_lc: {
                let mut h = HashMap::new();
                h.insert("x-slack-request-timestamp".into(), "1700000000".into());
                h
            },
            body: b"{}".to_vec(),
        };
        let (resp, outcome) = route_slack_webhook(&req, b"k", 1_700_000_000);
        assert_eq!(resp.status, 403);
        assert_eq!(
            outcome,
            SlackRouteOutcome::HeaderMissing {
                name: "x-slack-signature"
            }
        );
    }

    #[test]
    fn slack_missing_timestamp_header_is_forbidden() {
        let req = WebhookRequest {
            method: HttpMethod::Post,
            path: "/slack/events".into(),
            query: String::new(),
            headers_lc: HashMap::new(),
            body: b"{}".to_vec(),
        };
        let (resp, outcome) = route_slack_webhook(&req, b"k", 1_700_000_000);
        assert_eq!(resp.status, 403);
        assert_eq!(
            outcome,
            SlackRouteOutcome::HeaderMissing {
                name: "x-slack-request-timestamp"
            }
        );
    }

    #[test]
    fn slack_get_is_method_not_allowed() {
        let req = WebhookRequest {
            method: HttpMethod::Get,
            path: "/slack/events".into(),
            query: String::new(),
            headers_lc: HashMap::new(),
            body: vec![],
        };
        let (resp, outcome) = route_slack_webhook(&req, b"k", 1_700_000_000);
        assert_eq!(resp.status, 405);
        assert_eq!(outcome, SlackRouteOutcome::UnsupportedMethod);
    }

    #[test]
    fn slack_skew_outside_window_rejected() {
        let body = b"x";
        let ts = "1700000000";
        let sig = sign_slack(body, ts, b"k");
        let req = slack_post_req(body, ts, &sig);
        // 600s into the future — well outside the ±300s window.
        let (resp, outcome) = route_slack_webhook(&req, b"k", 1_700_000_000 + 600);
        assert_eq!(resp.status, 403);
        match outcome {
            SlackRouteOutcome::Rejected {
                error: SlackVerifyError::TimestampOutOfWindow { skew_secs },
            } => {
                assert_eq!(skew_secs, 600);
            }
            other => panic!("expected TimestampOutOfWindow rejection, got {other:?}"),
        }
    }

    // ── Response helpers ───────────────────────────────────────────────

    #[test]
    fn response_helpers_set_expected_codes() {
        assert_eq!(WebhookResponse::ok("x").status, 200);
        assert_eq!(WebhookResponse::forbidden("nope").status, 403);
        assert_eq!(WebhookResponse::bad_request("nope").status, 400);
        assert_eq!(WebhookResponse::method_not_allowed().status, 405);
    }
}
