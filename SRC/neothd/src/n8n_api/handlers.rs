//! Six v1 endpoint handlers for the localhost API.
//!
//! Every handler:
//! 1. Receives the parsed [`ApiRequestCtx`] from
//!    [`super::server::dispatch`] (already passed auth + loopback +
//!    method gating).
//! 2. Returns a [`HandlerOutcome`] carrying the response shape +
//!    status code. The server layer wraps the data in the
//!    [`super::ApiOkResponse`] / [`super::ApiErrorResponse`]
//!    envelope and pipes the JSON to the hyper connection.
//!
//! Handlers themselves are pure-ish: they only touch the shared
//! `ApiState` (WAL writer + config snapshot + memory store path).
//! Side effects (WAL audit frame, memory insert) flow through that
//! state — no global statics, no per-handler I/O bootstrapping.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::server::{ApiRequestCtx, ApiState, HandlerOutcome};
use super::{ApiErrorCode, REQUEST_BODY_LIMIT_BYTES};

/// `/api/health` response payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub version: &'static str,
    pub uptime_secs: u64,
    pub status: &'static str,
}

/// `/api/recall` request body — `query` is the operator-facing
/// search string, `limit` caps results (default 10, hard cap 100).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecallRequest {
    pub query: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `/api/recall` response payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecallResponse {
    pub hits: Vec<JsonValue>,
    pub total: usize,
}

/// `/api/stats` payload — high-level counts the n8n weekly_stats
/// workflow renders into a markdown digest.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatsResponse {
    pub events_total: u64,
    pub provider_requests: u64,
    pub channel_inbound: u64,
    pub channel_outbound: u64,
}

/// `/api/memory/save` body — operator-typed note that gets WAL'd
/// as `EVENT_TYPE_MEMORY_NOTE`. The `kind` is one of the operator-
/// taxonomy strings (`fact`, `decision`, `preference`, …).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemorySaveRequest {
    pub kind: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `/api/memory/save` response — echoes the persisted record id so
/// the workflow can correlate the write with later recall.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemorySaveResponse {
    pub stored: bool,
    pub bytes: usize,
}

/// `/api/provider/call` body. The shared helper composes the
/// system prompt; n8n callers can override via `system`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderCallRequest {
    pub prompt: String,
    #[serde(default)]
    pub system: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}

/// `/api/provider/call` response — sliced down to the operator-
/// useful subset (no per-token deltas; the n8n surface is a single
/// JSON round-trip).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderCallResponse {
    pub completion: String,
    pub model: Option<String>,
}

/// `/api/channel/send` body. `channel` is the channel-id slug
/// (`telegram`, `keet`, …); `recipient` is the channel-native
/// addressee.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSendRequest {
    pub channel: String,
    pub recipient: String,
    pub text: String,
}

/// `/api/channel/send` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSendResponse {
    pub queued: bool,
}

/// Validate body size before any JSON parse touches the bytes.
pub fn enforce_body_limit(bytes: &[u8]) -> Result<(), HandlerOutcome> {
    if bytes.len() > REQUEST_BODY_LIMIT_BYTES {
        return Err(HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            format!(
                "request body {} bytes exceeds cap {}",
                bytes.len(),
                REQUEST_BODY_LIMIT_BYTES
            ),
            "shrink the prompt or raise n8n_api.body_limit_bytes",
        ));
    }
    Ok(())
}

/// Parse JSON body into the expected request shape.
pub fn parse_body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, HandlerOutcome> {
    enforce_body_limit(bytes)?;
    serde_json::from_slice(bytes).map_err(|e| {
        HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            format!("body parse failed: {e}"),
            "check the workflow JSON matches the documented shape",
        )
    })
}

// ── /api/health ─────────────────────────────────────────────────

pub fn health(_ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let uptime = state.boot_instant.elapsed().as_secs();
    let body = HealthResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: uptime,
        status: "ok",
    };
    HandlerOutcome::ok_json(serde_json::to_value(&body).unwrap_or(JsonValue::Null))
}

// ── /api/recall ─────────────────────────────────────────────────

pub fn recall(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let req: RecallRequest = match parse_body(&ctx.body) {
        Ok(r) => r,
        Err(outcome) => return outcome,
    };
    let limit = req.limit.unwrap_or(10).min(100);
    let views_path = state.home.join("views.db");
    match crate::memory::store::open(&views_path) {
        Ok(conn) => match crate::memory::ctx::search(&conn, &req.query, limit) {
            Ok(hits) => {
                let total = hits.len();
                let json_hits: Vec<JsonValue> = hits
                    .into_iter()
                    .filter_map(|h| serde_json::to_value(&h).ok())
                    .collect();
                HandlerOutcome::ok_json(
                    serde_json::to_value(RecallResponse {
                        hits: json_hits,
                        total,
                    })
                    .unwrap_or(JsonValue::Null),
                )
            }
            Err(e) => HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("recall search failed: {e}"),
                "check views.db integrity or run `neoth recall` from the CLI",
            ),
        },
        Err(e) => HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("views.db open failed: {e}"),
            "run `neoth serve` once to materialise views.db",
        ),
    }
}

// ── /api/stats ──────────────────────────────────────────────────

pub fn stats(_ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let views_path = state.home.join("views.db");
    match crate::memory::store::open(&views_path) {
        Ok(conn) => {
            let counts = read_stat_counts(&conn).unwrap_or_default();
            HandlerOutcome::ok_json(serde_json::to_value(counts).unwrap_or(JsonValue::Null))
        }
        Err(e) => HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("views.db open failed: {e}"),
            "run `neoth serve` once to materialise views.db",
        ),
    }
}

fn read_stat_counts(conn: &rusqlite::Connection) -> Result<StatsResponse, rusqlite::Error> {
    let count = |sql: &str| -> Result<u64, rusqlite::Error> {
        conn.query_row(sql, [], |row| row.get::<_, i64>(0))
            .map(|n| n.max(0) as u64)
            .or_else(|e| {
                // A missing table just means the view hasn't been
                // materialised yet; surface 0 rather than 500.
                if matches!(e, rusqlite::Error::SqliteFailure(_, Some(ref msg)) if msg.contains("no such table"))
                {
                    Ok(0)
                } else {
                    Err(e)
                }
            })
    };
    Ok(StatsResponse {
        events_total: count("SELECT COUNT(*) FROM idx_events")?,
        provider_requests: count("SELECT COUNT(*) FROM idx_events WHERE event_type = 33")?,
        channel_inbound: count("SELECT COUNT(*) FROM idx_events WHERE event_type = 50")?,
        channel_outbound: count("SELECT COUNT(*) FROM idx_events WHERE event_type = 51")?,
    })
}

// ── /api/memory/save ────────────────────────────────────────────

pub async fn memory_save(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let req: MemorySaveRequest = match parse_body(&ctx.body) {
        Ok(r) => r,
        Err(outcome) => return outcome,
    };
    if req.body.trim().is_empty() {
        return HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            "memory save body is empty",
            "supply a non-empty `body` string",
        );
    }
    let payload = match serde_json::to_vec(&serde_json::json!({
        "kind": req.kind,
        "body": req.body,
        "tags": req.tags,
        "source": "n8n_api",
        "request_id": ctx.request_id.clone(),
    })) {
        Ok(p) => p,
        Err(e) => {
            return HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("serialise MEMORY_NOTE payload failed: {e}"),
                "retry with a smaller body",
            );
        }
    };
    let bytes = payload.len();
    // RAW_TEXT (0x01) is the operator-recallable durable channel —
    // a dedicated EVENT_TYPE_MEMORY_NOTE would need its own bucket
    // in the recall search; n8n-driven saves piggyback on the same
    // tier the CLI's `neoth memory save` ends up writing.
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_RAW_TEXT, &payload).build();
    // Session 24 #4 fix: await the WAL append so the API only
    // returns `stored: true` AFTER the writer task acknowledges.
    // Pre-fix this was fire-and-forget — the handler returned 200
    // before the frame was durable, so a writer task that died
    // (queue full, fsync error, daemon shutdown mid-call) silently
    // dropped the audit record while n8n thought the save succeeded.
    // Now: WAL backpressure / closed-writer / fsync errors surface
    // as 5xx so the n8n workflow author can retry on the same idem-
    // potency key instead of corrupting the audit trail.
    match state.writer.append(header, payload).await {
        Ok(_) => HandlerOutcome::ok_json(
            serde_json::to_value(MemorySaveResponse {
                stored: true,
                bytes,
            })
            .unwrap_or(JsonValue::Null),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "n8n_api memory_save WAL append failed");
            HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("memory_save WAL append failed: {e}"),
                "retry — the WAL writer may be briefly backpressured or shutting down",
            )
        }
    }
}

// ── /api/provider/call ──────────────────────────────────────────

/// H1 (2026-06-12) — cloud-egress consent gate for the n8n `provider_call`
/// surface. Returns `Some(refusal)` if the call must be refused, `None` if it
/// may proceed. Mirrors the chat path: at autonomy=Strict cloud is refused
/// outright (the loudest privacy signal); at every OTHER autonomy level the
/// specific cloud provider must carry a recorded operator consent marker
/// (`consent::is_granted`). Previously only Strict was gated, so an n8n workflow
/// could drive un-consented cloud egress at the daemon-default Standard
/// autonomy. Pure (no I/O beyond the consent-marker read) so it is unit-tested
/// without constructing a full `ApiState`.
fn cloud_egress_gate(
    autonomy: crate::permissions::AutonomyLevel,
    provider_kind: Option<crate::cli::init::ProviderKind>,
    home: &std::path::Path,
) -> Option<HandlerOutcome> {
    // Only cloud providers are gated; a local/none provider proceeds.
    let kind = provider_kind.filter(|k| crate::consent::is_cloud(*k))?;
    if matches!(autonomy, crate::permissions::AutonomyLevel::Strict) {
        return Some(HandlerOutcome::error(
            ApiErrorCode::PermissionDenied,
            "n8n provider_call refused under autonomy=strict for cloud providers — \
             confirm via the chat surface or lower autonomy to standard/elevated/full",
            "use /api/channel/send for the gated path OR lower autonomy",
        ));
    }
    if !crate::consent::is_granted(home, kind) {
        return Some(HandlerOutcome::error(
            ApiErrorCode::PermissionDenied,
            format!(
                "n8n provider_call: cloud provider `{}` has no recorded operator consent — \
                 run `neoth consent grant {}` first",
                crate::consent::slug(kind),
                crate::consent::slug(kind)
            ),
            "run `neoth consent grant <provider>` to record outbound-LLM consent",
        ));
    }
    None
}

pub async fn provider_call(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let req: ProviderCallRequest = match parse_body(&ctx.body) {
        Ok(r) => r,
        Err(outcome) => return outcome,
    };
    if req.prompt.trim().is_empty() {
        return HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            "provider_call prompt is empty",
            "supply a non-empty `prompt` field",
        );
    }
    // Build a fresh provider from the daemon's config snapshot.
    // The n8n localhost surface intentionally bypasses the
    // sub-agent / slash / hook chain — workflow authors who need
    // those features should call /api/channel/send + let the
    // channel pipeline run the full stack.
    //
    // Session 24 fix #5: even on the bare-metal surface we now
    // (a) honour autonomy=Strict by refusing cloud provider calls
    //     without explicit operator confirmation; n8n workflows
    //     cannot bypass the operator's loudest privacy signal,
    // (b) emit PROVIDER_REQUEST (0x20) BEFORE the call + a
    //     PROVIDER_RESPONSE (0x21) on success / PROVIDER_ERROR
    //     (0x22) on failure so `neoth wal show --type provider_request`
    //     surfaces every n8n-initiated provider call alongside
    //     the chat-initiated ones — single audit truth.
    // (c) the circuit-breaker wrap happens INSIDE
    //     `provider.complete()` (GR-04) — automatic.
    let provider_kind = state.config.provider_kind;
    // GR-003 + H1 (2026-06-12): cloud egress on the n8n surface goes through
    // `cloud_egress_gate` — at autonomy=Strict cloud is refused outright (the
    // loudest privacy signal), and at EVERY other autonomy level the specific
    // cloud provider must carry a recorded operator consent marker (parity with
    // the chat path's `consent::ensure_all_still_granted`). Previously only the
    // Strict case was gated, so an n8n workflow could drive un-consented cloud
    // LLM calls at the daemon-default Standard autonomy. `consent::is_cloud`
    // (inside the gate) is the compile-enforced EXHAUSTIVE classifier (GR-003).
    if let Some(refusal) = cloud_egress_gate(state.config.autonomy, provider_kind, &state.home) {
        tracing::warn!(
            provider_kind = ?provider_kind,
            request_id = %ctx.request_id,
            "n8n_api provider_call refused by the cloud-egress consent gate"
        );
        return refusal;
    }
    let provider = match crate::providers::from_config(state.config.as_ref()).await {
        Ok(p) => p,
        Err(e) => {
            return HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("provider init failed: {e}"),
                "verify freedom.yaml provider_kind + credentials",
            );
        }
    };
    let request = crate::providers::Request {
        prompt: req.prompt.clone(),
        system: req.system.clone(),
        model: req.model.clone(),
        ..Default::default()
    };
    // Emit PROVIDER_REQUEST (0x20) BEFORE the call so a crash mid-
    // call still leaves the audit trail with the operator-typed
    // prompt in `before_state`. The redactor in the WAL snapshot
    // path strips secret patterns automatically.
    let req_payload = serde_json::to_vec(&serde_json::json!({
        "source": "n8n_api",
        "request_id": ctx.request_id,
        "provider_kind": provider_kind.map(|k| k.as_str()).unwrap_or("none"),
        "model": req.model,
        "prompt_bytes": req.prompt.len(),
        "system_bytes": req.system.as_deref().map(|s| s.len()).unwrap_or(0),
    }))
    .unwrap_or_default();
    let req_header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
        &req_payload,
    )
    .build();
    if let Err(e) = state.writer.append(req_header, req_payload).await {
        tracing::warn!(error = %e, request_id = %ctx.request_id, "n8n_api provider_request WAL append failed");
    }

    match provider.complete(request).await {
        Ok(comp) => {
            let resp_payload = serde_json::to_vec(&serde_json::json!({
                "source": "n8n_api",
                "request_id": ctx.request_id,
                "model": comp.model,
                "completion_bytes": comp.text.len(),
                "latency_ms": comp.latency.as_millis() as u64,
                "input_tokens": comp.input_tokens,
                "output_tokens": comp.output_tokens,
            }))
            .unwrap_or_default();
            let resp_header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
                &resp_payload,
            )
            .build();
            if let Err(e) = state.writer.append(resp_header, resp_payload).await {
                tracing::warn!(error = %e, request_id = %ctx.request_id, "n8n_api provider_response WAL append failed");
            }
            HandlerOutcome::ok_json(
                serde_json::to_value(ProviderCallResponse {
                    completion: comp.text,
                    model: req.model,
                })
                .unwrap_or(JsonValue::Null),
            )
        }
        Err(e) => {
            let err_payload = serde_json::to_vec(&serde_json::json!({
                "source": "n8n_api",
                "request_id": ctx.request_id,
                "provider_kind": provider_kind.map(|k| k.as_str()).unwrap_or("none"),
                "model": req.model,
                "error": e.to_string(),
            }))
            .unwrap_or_default();
            let err_header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
                &err_payload,
            )
            .build();
            if let Err(append_err) = state.writer.append(err_header, err_payload).await {
                tracing::warn!(error = %append_err, request_id = %ctx.request_id, "n8n_api provider_error WAL append failed");
            }
            HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("provider call failed: {e}"),
                "check provider quota / credentials / cooldown",
            )
        }
    }
}

// ── /api/channel/send ───────────────────────────────────────────

pub async fn channel_send(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let req: ChannelSendRequest = match parse_body(&ctx.body) {
        Ok(r) => r,
        Err(outcome) => return outcome,
    };
    if req.text.trim().is_empty() {
        return HandlerOutcome::error(
            ApiErrorCode::BadRequest,
            "channel_send text is empty",
            "supply a non-empty `text` field",
        );
    }
    // Emit a CHANNEL_EGRESS WAL frame so the audit trail records
    // the outbound the same way the in-process channel adapter
    // would. The actual adapter dispatch lives in
    // `cli::serve::ChannelOutboundBroker` (separate workstream);
    // n8n callers see the queue acknowledgement here and the
    // adapter task drains the WAL into the wire.
    let payload = match serde_json::to_vec(&serde_json::json!({
        "channel": req.channel,
        "recipient_id": req.recipient,
        "text_bytes": req.text.len(),
        "source": "n8n_api",
        "request_id": ctx.request_id.clone(),
    })) {
        Ok(p) => p,
        Err(e) => {
            return HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("serialise CHANNEL_EGRESS payload failed: {e}"),
                "retry with a shorter `text` field",
            );
        }
    };
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_CHANNEL_EGRESS, &payload)
            .build();
    // Session 24 #4 fix: await the WAL append so the API only
    // returns `queued: true` AFTER the writer task acknowledges.
    // Pre-fix the handler returned 200 before the frame was durable
    // — n8n got an OK for a payload that may have silently dropped.
    match state.writer.append(header, payload).await {
        Ok(_) => HandlerOutcome::ok_json(
            serde_json::to_value(ChannelSendResponse { queued: true }).unwrap_or(JsonValue::Null),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "n8n_api channel_send WAL append failed");
            HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("channel_send WAL append failed: {e}"),
                "retry — the WAL writer may be briefly backpressured or shutting down",
            )
        }
    }
}

/// Wire — the dispatcher in `server::dispatch` matches the path +
/// method and forwards here.
pub async fn route(ctx: ApiRequestCtx, state: Arc<ApiState>) -> HandlerOutcome {
    match (ctx.method.as_str(), ctx.path.as_str()) {
        ("GET", "/api/health") => health(&ctx, &state),
        ("POST", "/api/recall") => recall(&ctx, &state),
        ("GET", "/api/stats") => stats(&ctx, &state),
        ("POST", "/api/memory/save") => memory_save(&ctx, &state).await,
        ("POST", "/api/provider/call") => provider_call(&ctx, &state).await,
        ("POST", "/api/channel/send") => channel_send(&ctx, &state).await,
        (method, path) if path.starts_with("/api/") => HandlerOutcome::error(
            ApiErrorCode::NotFound,
            format!("no route for {method} {path}"),
            "see PLAN/SPEC_n8n_localhost_api_2026-05-23.md for the v1 endpoint list",
        ),
        (method, path) => HandlerOutcome::error(
            ApiErrorCode::NotFound,
            format!("only /api/* routes are exposed; got {method} {path}"),
            "n8n must POST/GET /api/<endpoint>",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_body_rejects_oversize_payload() {
        let big = vec![b'a'; REQUEST_BODY_LIMIT_BYTES + 1];
        let err = parse_body::<RecallRequest>(&big).err().unwrap();
        let code = err.error_code().unwrap();
        assert_eq!(code, ApiErrorCode::BadRequest);
    }

    #[test]
    fn parse_body_rejects_malformed_json() {
        let bytes = b"{this is not json";
        let err = parse_body::<RecallRequest>(bytes).err().unwrap();
        assert_eq!(err.error_code().unwrap(), ApiErrorCode::BadRequest);
    }

    #[test]
    fn parse_body_accepts_minimal_recall() {
        let bytes = br#"{"query": "test"}"#;
        let r: RecallRequest = parse_body(bytes).unwrap();
        assert_eq!(r.query, "test");
        assert_eq!(r.limit, None);
    }

    #[test]
    fn parse_body_accepts_memory_save_with_tags() {
        let bytes = br#"{"kind": "fact", "body": "foo", "tags": ["x", "y"]}"#;
        let r: MemorySaveRequest = parse_body(bytes).unwrap();
        assert_eq!(r.kind, "fact");
        assert_eq!(r.tags.len(), 2);
    }

    #[test]
    fn recall_request_defaults_limit_to_none() {
        let r: RecallRequest = serde_json::from_str(r#"{"query": "x"}"#).unwrap();
        assert_eq!(r.limit, None);
    }

    // ── H1 (2026-06-12): cloud-egress consent gate ──────────────────
    use crate::cli::init::ProviderKind;
    use crate::permissions::AutonomyLevel;

    #[test]
    fn cloud_egress_gate_blocks_cloud_without_consent_at_standard() {
        // The core H1 regression: at the daemon-default Standard autonomy a
        // cloud provider with NO recorded consent marker must be REFUSED — the
        // pre-fix gate only fired at Strict, letting un-consented cloud egress
        // through on the n8n surface.
        let home = tempfile::tempdir().expect("tempdir");
        let out = cloud_egress_gate(AutonomyLevel::Standard, Some(ProviderKind::OpenaiApi), home.path());
        let out = out.expect("must refuse cloud without consent at Standard");
        assert_eq!(out.error_code(), Some(ApiErrorCode::PermissionDenied));
    }

    #[test]
    fn cloud_egress_gate_allows_cloud_with_recorded_consent() {
        // Once the operator has granted consent for the provider, the n8n call
        // proceeds (None == no refusal) at a non-Strict autonomy.
        let home = tempfile::tempdir().expect("tempdir");
        crate::consent::grant(home.path(), ProviderKind::OpenaiApi).expect("record consent");
        let out = cloud_egress_gate(AutonomyLevel::Standard, Some(ProviderKind::OpenaiApi), home.path());
        assert!(out.is_none(), "a consented cloud provider must pass the gate");
    }

    #[test]
    fn cloud_egress_gate_refuses_all_cloud_at_strict_even_with_consent() {
        // Strict is the loudest privacy signal: cloud is refused outright,
        // regardless of any recorded consent (parity with the prior behavior).
        let home = tempfile::tempdir().expect("tempdir");
        crate::consent::grant(home.path(), ProviderKind::OpenaiApi).expect("record consent");
        let out = cloud_egress_gate(AutonomyLevel::Strict, Some(ProviderKind::OpenaiApi), home.path());
        let out = out.expect("Strict must refuse cloud even with consent");
        assert_eq!(out.error_code(), Some(ApiErrorCode::PermissionDenied));
    }

    #[test]
    fn cloud_egress_gate_ignores_local_and_absent_providers() {
        // A local provider (no cloud egress) and an absent provider_kind are
        // never gated — at any autonomy level.
        let home = tempfile::tempdir().expect("tempdir");
        assert!(
            cloud_egress_gate(AutonomyLevel::Standard, Some(ProviderKind::LocalQwen), home.path())
                .is_none(),
            "a local provider is not cloud egress"
        );
        assert!(
            cloud_egress_gate(AutonomyLevel::Full, None, home.path()).is_none(),
            "no provider configured → no cloud gate"
        );
    }
}
