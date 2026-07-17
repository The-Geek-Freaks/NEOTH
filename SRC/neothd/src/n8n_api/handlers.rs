//! Six v1 endpoint handlers for the localhost API.
//!
//! Every handler:
//! 1. Receives the parsed [`ApiRequestCtx`] from [`super::server::serve`]
//!    (already passed auth + loopback). Path/method routing happens in
//!    [`route`] (a wrong method falls through to `NotFound`).
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

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::server::{ApiRequestCtx, ApiState, HandlerOutcome};
use super::{ApiErrorCode, REQUEST_BODY_LIMIT_BYTES};
use crate::providers::Provider;

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

/// `/api/provider/call` body. The handler composes the explicit `system`
/// layer with the authenticated operator's communication profile before the
/// concrete provider request is authorized. Callers cannot choose a profile
/// subject and automation prompts are never learned as behavioral evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderCallRequest {
    pub prompt: String,
    #[serde(default)]
    pub system: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    /// Skip every communication-profile read for this request. Defaults false
    /// so existing workflows keep their prior request shape and behavior.
    #[serde(default)]
    pub incognito: bool,
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
/// (`telegram`, `slack`, …); `recipient` is the channel-native
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
    HandlerOutcome::ok_json(
        serde_json::to_value(&body).expect("HealthResponse contains only JSON-safe fields"),
    )
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
                let json_hits: Vec<JsonValue> = match hits
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                {
                    Ok(hits) => hits,
                    Err(error) => {
                        return HandlerOutcome::error(
                            ApiErrorCode::UpstreamError,
                            format!("recall result serialization failed: {error}"),
                            "inspect the matching recall row for invalid stored data",
                        );
                    }
                };
                HandlerOutcome::ok_json(
                    serde_json::to_value(RecallResponse {
                        hits: json_hits,
                        total,
                    })
                    .expect("RecallResponse contains only JSON values and integers"),
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
        Ok(conn) => match read_stat_counts(&conn) {
            Ok(counts) => HandlerOutcome::ok_json(
                serde_json::to_value(counts)
                    .expect("StatsResponse contains only fixed-width integer fields"),
            ),
            Err(error) => HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("stats query failed: {error}"),
                "check views.db integrity or run `neoth doctor`",
            ),
        },
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
        provider_requests: count("SELECT COUNT(*) FROM idx_events WHERE event_type = 32")?,
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
            .expect("MemorySaveResponse contains only JSON-safe fields"),
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

/// The n8n server authenticates either the operator master token or an
/// operator-issued `provider:call` scoped token before this handler runs. The
/// request schema deliberately has no subject field, so workflow JSON cannot
/// select another person's communication profile.
const PROVIDER_CALL_COMMUNICATION_SUBJECT: &str = "operator";

fn build_provider_request(
    home: &std::path::Path,
    config: &crate::config::FreedomConfig,
    req: &ProviderCallRequest,
    effective_model: Option<String>,
) -> anyhow::Result<crate::providers::Request> {
    // Read-only by design: automation prompts may be machine-generated and
    // therefore must never become behavioral evidence. `compile_prompt`
    // returns before opening state when `incognito` is true.
    let communication_profile = crate::profile::communication::compile_prompt(
        home,
        PROVIDER_CALL_COMMUNICATION_SUBJECT,
        &config.profile.communication,
        None,
        req.incognito,
    )
    .context("compile communication profile for n8n provider call")?;

    let enriched = crate::pipeline::build_enriched_request(crate::pipeline::EnrichmentInputs {
        prompt: &req.prompt,
        operator_context: None,
        preset_addendum: None,
        explicit_system: req.system.as_deref(),
        repo_context_block: None,
        skill_system_prompt: None,
        used_skill_id: None,
        mcp_catalogue: None,
        persona_override: None,
        moral_core: None,
        identity_anchor: None,
        identity_locked: false,
        current_goal: None,
        communication_profile: communication_profile.as_ref().map(|compiled| {
            crate::pipeline::CommunicationProfilePrompt::presentation_only(compiled.as_str())
        }),
    });

    Ok(crate::providers::Request {
        prompt: enriched.prompt,
        system: enriched.system,
        model: effective_model,
        ..Default::default()
    })
}

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
    provider_endpoint: Option<&str>,
    home: &std::path::Path,
) -> Option<HandlerOutcome> {
    let kind = provider_kind?;
    let route = crate::consent::ConsentRoute::new(kind, provider_endpoint);
    // In-process/loopback providers proceed. Remote Ollama is egress despite
    // the historical LocalOllama enum name and therefore stays in this gate.
    if !crate::consent::route_requires_consent(kind, provider_endpoint) {
        return None;
    }
    if matches!(autonomy, crate::permissions::AutonomyLevel::Strict) {
        return Some(HandlerOutcome::error(
            ApiErrorCode::PermissionDenied,
            "n8n provider_call refused under autonomy=strict for cloud providers — \
             confirm via the chat surface or lower autonomy to standard/elevated/full",
            "use /api/channel/send for the gated path OR lower autonomy",
        ));
    }
    if !crate::consent::is_route_granted(home, &route) {
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
    // (a) honour the current built-in or Custom autonomy policy at
    //     the actual provider leaf; n8n workflows cannot bypass it,
    // (b) use the mandatory leaf lifecycle boundary, which persists
    //     PROVIDER_REQUEST (0x20) before dispatch and exactly one
    //     PROVIDER_RESPONSE (0x21) or PROVIDER_ERROR (0x22), so
    //     `neoth wal show --type provider_request` surfaces every
    //     n8n-initiated call alongside chat — one audit truth.
    // (c) the circuit-breaker wrap happens INSIDE
    //     `provider.complete()` (GR-04) — automatic.
    let live_config = state.reload_controller.latest();
    let provider_kind = live_config.provider_kind;
    // GR-003 + H1 (2026-06-12): cloud egress on the n8n surface goes through
    // `cloud_egress_gate` — at autonomy=Strict cloud is refused outright (the
    // loudest privacy signal), and at EVERY other autonomy level the specific
    // cloud provider must carry a recorded operator consent marker (parity with
    // the chat path's `consent::ensure_all_still_granted`). Previously only the
    // Strict case was gated, so an n8n workflow could drive un-consented cloud
    // LLM calls at the daemon-default Standard autonomy. `consent::is_cloud`
    // (inside the gate) is the compile-enforced EXHAUSTIVE classifier (GR-003).
    if let Some(refusal) = cloud_egress_gate(
        live_config.autonomy,
        provider_kind,
        live_config.provider_endpoint.as_deref(),
        &state.home,
    ) {
        tracing::warn!(
            provider_kind = ?provider_kind,
            request_id = %ctx.request_id,
            "n8n_api provider_call refused by the cloud-egress consent gate"
        );
        return refusal;
    }
    let provider = match crate::providers::from_config_at(live_config.as_ref(), &state.home).await {
        Ok(p) => p,
        Err(e) => {
            return HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("provider init failed: {e}"),
                "verify freedom.yaml provider_kind + credentials",
            );
        }
    };
    // B22 parity (n8n bare-metal surface): no dispatch/skill/CLI/tweaks tiers
    // exist here, so the effective model folds request > freedom
    // (provider_model) > provider default. Resolve BEFORE building the
    // request AND the WAL frame so the logged model always equals the wire
    // model — even when the workflow omits `model` and the provider's
    // configured default takes over.
    let model_source = if req.model.is_some() {
        "request"
    } else if live_config.provider_model.is_some() {
        "freedom"
    } else {
        "provider_default"
    };
    let requested_model = req
        .model
        .as_deref()
        .or(live_config.provider_model.as_deref());
    let effective_model = match crate::providers::resolve_configured_request_model_for_wire(
        live_config.as_ref(),
        provider.as_ref(),
        requested_model,
    ) {
        Ok(model) => Some(model),
        Err(error) => {
            return HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("provider model resolution failed: {error:#}"),
                "set a valid request model or provider_model in freedom.yaml",
            );
        }
    };
    // Compose every provider-bound system layer BEFORE constructing the
    // AuthorizedProvider. Its request binding therefore covers the final
    // communication-enriched system prompt, not the caller's partial input.
    let request = match build_provider_request(
        &state.home,
        live_config.as_ref(),
        &req,
        effective_model.clone(),
    ) {
        Ok(request) => request,
        Err(error) => {
            return HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("provider_call prompt composition failed: {error:#}"),
                "inspect `neoth profile communication status`; use `incognito: true` only when this workflow must not read profile state",
            );
        }
    };
    let provider = crate::providers::cost_authorization::AuthorizedProvider::from_box(
        provider,
        crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed_reload(
            Arc::clone(&state.reload_controller),
            Some(state.writer.clone()),
            state.home.clone(),
        )
        .with_audit_context(
            crate::providers::cost_authorization::ProviderCallAuditContext {
                source: Some("n8n_api"),
                call_type: Some("n8n_provider_call"),
                request_id: Some(ctx.request_id.clone()),
                operator_id: live_config.operator_id.clone(),
                model_source: Some(model_source),
                incognito: req.incognito,
                configured_provider_kind: Some(
                    provider_kind
                        .map(|kind| kind.as_str())
                        .unwrap_or("none")
                        .to_owned(),
                ),
                ..Default::default()
            },
        ),
        effective_model,
        "n8n.provider_call",
    );
    match provider.complete(request).await {
        Ok(comp) => {
            let model = comp.identity.wire_model.clone();
            HandlerOutcome::ok_json(
                serde_json::to_value(ProviderCallResponse {
                    completion: comp.text,
                    model: Some(model),
                })
                .expect("ProviderCallResponse contains only JSON-safe fields"),
            )
        }
        Err(e) => HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("provider call failed: {e}"),
            "check provider quota / credentials / cooldown",
        ),
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
            serde_json::to_value(ChannelSendResponse { queued: true })
                .expect("ChannelSendResponse contains only JSON-safe fields"),
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

/// Wire — `server::serve` (per-request) calls this; `route` matches the path +
/// method and forwards to the right handler (wrong method → `NotFound`).
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

    fn pin_preference(
        home: &std::path::Path,
        subject_id: &str,
        session_id: &str,
        event_byte: u8,
        value: crate::profile::communication::PreferenceValue,
    ) {
        crate::profile::communication::set_explicit_preference(
            home,
            &crate::config::CommunicationProfileConfig::default(),
            subject_id,
            session_id,
            value,
            [event_byte; 32],
            1_700_000_000 + i64::from(event_byte),
            crate::profile::communication::CommunicationScope::Global,
            false,
        )
        .expect("pin communication preference");
    }

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

    #[test]
    fn provider_request_injects_operator_profile_before_explicit_system() {
        let home = tempfile::tempdir().expect("tempdir");
        let config = crate::config::FreedomConfig::default();
        pin_preference(
            home.path(),
            PROVIDER_CALL_COMMUNICATION_SUBJECT,
            "operator-session",
            1,
            crate::profile::communication::PreferenceValue::Directness(
                crate::profile::communication::DirectnessPreference::Direct,
            ),
        );
        let req = ProviderCallRequest {
            prompt: "automation task".into(),
            system: Some("CALLER_SYSTEM_LAYER".into()),
            model: None,
            incognito: false,
        };

        let request = build_provider_request(home.path(), &config, &req, Some("wire-model".into()))
            .expect("compose provider request");
        let system = request.system.expect("communication + explicit system");
        let communication_pos = system.find("Be direct.").expect("compiled accommodation");
        let explicit_pos = system
            .find("CALLER_SYSTEM_LAYER")
            .expect("explicit caller system");
        assert!(communication_pos < explicit_pos);
        assert_eq!(request.prompt, "automation task");
        assert_eq!(request.model.as_deref(), Some("wire-model"));
    }

    #[test]
    fn provider_request_incognito_defaults_false_and_skips_malformed_state() {
        let home = tempfile::tempdir().expect("tempdir");
        let state_path = crate::profile::communication::state_path(home.path());
        std::fs::create_dir_all(state_path.parent().expect("profile parent"))
            .expect("create profile parent");
        std::fs::write(&state_path, b"not valid communication state")
            .expect("write malformed sentinel");
        let config = crate::config::FreedomConfig::default();

        let legacy: ProviderCallRequest =
            serde_json::from_str(r#"{"prompt":"legacy"}"#).expect("legacy request parses");
        assert!(
            !legacy.incognito,
            "omitted flag must remain backward-compatible"
        );
        assert!(
            build_provider_request(home.path(), &config, &legacy, None).is_err(),
            "non-incognito must not silently drop corrupt configured state"
        );

        let incognito: ProviderCallRequest = serde_json::from_str(
            r#"{"prompt":"private automation","system":"EXPLICIT_ONLY","incognito":true}"#,
        )
        .expect("incognito request parses");
        let request = build_provider_request(home.path(), &config, &incognito, None)
            .expect("incognito skips communication-state read");
        assert_eq!(request.system.as_deref(), Some("EXPLICIT_ONLY"));
        assert_eq!(
            std::fs::read(&state_path).expect("read malformed sentinel"),
            b"not valid communication state"
        );
    }

    #[test]
    fn provider_request_subject_is_fixed_and_caller_override_is_ignored() {
        let home = tempfile::tempdir().expect("tempdir");
        let config = crate::config::FreedomConfig::default();
        pin_preference(
            home.path(),
            PROVIDER_CALL_COMMUNICATION_SUBJECT,
            "operator-session",
            2,
            crate::profile::communication::PreferenceValue::Structure(
                crate::profile::communication::StructurePreference::Bullets,
            ),
        );
        pin_preference(
            home.path(),
            "attacker",
            "attacker-session",
            3,
            crate::profile::communication::PreferenceValue::Directness(
                crate::profile::communication::DirectnessPreference::Gentle,
            ),
        );

        // Unknown fields remain ignored for backward-compatible JSON parsing,
        // but there is no subject field in ProviderCallRequest and the helper
        // always compiles the authenticated operator subject above.
        let req: ProviderCallRequest =
            serde_json::from_str(r#"{"prompt":"task","subject":"attacker","incognito":false}"#)
                .expect("request with unrelated legacy field parses");
        let request = build_provider_request(home.path(), &config, &req, None)
            .expect("compose fixed-subject request");
        let system = request.system.expect("operator accommodation");
        assert!(system.contains("Use short bullet lists for parallel points."));
        assert!(!system.contains("Use a calm, gentle tone"));
    }

    #[test]
    fn provider_request_exports_no_profile_metadata_and_records_no_automation_evidence() {
        let home = tempfile::tempdir().expect("tempdir");
        let config = crate::config::FreedomConfig::default();
        let private_session_marker = "RAW_PROFILE_METADATA_MUST_NOT_LEAK";
        pin_preference(
            home.path(),
            PROVIDER_CALL_COMMUNICATION_SUBJECT,
            private_session_marker,
            4,
            crate::profile::communication::PreferenceValue::Clarification(
                crate::profile::communication::ClarificationPreference::AskOneQuestion,
            ),
        );
        let state_path = crate::profile::communication::state_path(home.path());
        let before = std::fs::read(&state_path).expect("read state before request composition");
        let req = ProviderCallRequest {
            prompt: "machine-generated automation prompt".into(),
            system: None,
            model: None,
            incognito: false,
        };

        let request = build_provider_request(home.path(), &config, &req, None)
            .expect("compose provider request");
        let system = request.system.expect("compiled accommodation");
        assert!(system.contains("ask at most one concise question"));
        for forbidden in [
            private_session_marker,
            "event_hash",
            "subject_id",
            "session_id",
            "reason_code",
        ] {
            assert!(
                !system.contains(forbidden),
                "profile metadata leaked: {forbidden}"
            );
        }
        assert_eq!(
            std::fs::read(&state_path).expect("read state after request composition"),
            before,
            "automation provider calls must never record behavioral evidence"
        );
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
        let out = cloud_egress_gate(
            AutonomyLevel::Standard,
            Some(ProviderKind::OpenaiApi),
            None,
            home.path(),
        );
        let out = out.expect("must refuse cloud without consent at Standard");
        assert_eq!(out.error_code(), Some(ApiErrorCode::PermissionDenied));
    }

    #[test]
    fn cloud_egress_gate_allows_cloud_with_recorded_consent() {
        // Once the operator has granted consent for the provider, the n8n call
        // proceeds (None == no refusal) at a non-Strict autonomy.
        let home = tempfile::tempdir().expect("tempdir");
        crate::consent::grant(home.path(), ProviderKind::OpenaiApi).expect("record consent");
        let out = cloud_egress_gate(
            AutonomyLevel::Standard,
            Some(ProviderKind::OpenaiApi),
            None,
            home.path(),
        );
        assert!(
            out.is_none(),
            "a consented cloud provider must pass the gate"
        );
    }

    #[test]
    fn cloud_egress_gate_refuses_all_cloud_at_strict_even_with_consent() {
        // Strict is the loudest privacy signal: cloud is refused outright,
        // regardless of any recorded consent (parity with the prior behavior).
        let home = tempfile::tempdir().expect("tempdir");
        crate::consent::grant(home.path(), ProviderKind::OpenaiApi).expect("record consent");
        let out = cloud_egress_gate(
            AutonomyLevel::Strict,
            Some(ProviderKind::OpenaiApi),
            None,
            home.path(),
        );
        let out = out.expect("Strict must refuse cloud even with consent");
        assert_eq!(out.error_code(), Some(ApiErrorCode::PermissionDenied));
    }

    #[test]
    fn cloud_egress_gate_ignores_local_and_absent_providers() {
        // A local provider (no cloud egress) and an absent provider_kind are
        // never gated — at any autonomy level.
        let home = tempfile::tempdir().expect("tempdir");
        assert!(
            cloud_egress_gate(
                AutonomyLevel::Standard,
                Some(ProviderKind::LocalQwen),
                None,
                home.path()
            )
            .is_none(),
            "a local provider is not cloud egress"
        );
        assert!(
            cloud_egress_gate(AutonomyLevel::Full, None, None, home.path()).is_none(),
            "no provider configured → no cloud gate"
        );
    }

    #[test]
    fn cloud_egress_gate_treats_remote_ollama_as_consent_managed() {
        let home = tempfile::tempdir().expect("tempdir");
        let remote = "http://192.168.1.25:11434";
        assert!(
            cloud_egress_gate(
                AutonomyLevel::Standard,
                Some(ProviderKind::LocalOllama),
                Some(remote),
                home.path(),
            )
            .is_some(),
            "remote Ollama must not inherit the loopback consent bypass"
        );
        crate::consent::grant(home.path(), ProviderKind::LocalOllama).unwrap();
        assert!(
            cloud_egress_gate(
                AutonomyLevel::Standard,
                Some(ProviderKind::LocalOllama),
                Some(remote),
                home.path(),
            )
            .is_none()
        );
        assert!(
            cloud_egress_gate(
                AutonomyLevel::Standard,
                Some(ProviderKind::LocalOllama),
                Some("http://[::1]:11434"),
                tempfile::tempdir().unwrap().path(),
            )
            .is_none(),
            "loopback Ollama remains zero-friction"
        );
    }
}
