//! Ten v1 endpoint handlers for the localhost API.
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

#[cfg(test)]
#[derive(Clone)]
struct N8nTestProviderHandle(Arc<dyn crate::providers::Provider>);

#[cfg(test)]
#[async_trait::async_trait]
impl crate::providers::Provider for N8nTestProviderHandle {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn request_controls(&self) -> crate::providers::ProviderRequestControls {
        self.0.request_controls()
    }

    fn default_model(&self) -> Option<&str> {
        self.0.default_model()
    }

    fn consent_route(&self) -> Option<crate::consent::ConsentRoute> {
        self.0.consent_route()
    }

    fn resolve_model_for_wire(&self, requested_model: &str) -> String {
        self.0.resolve_model_for_wire(requested_model)
    }

    fn output_token_ceiling(&self, request: &crate::providers::Request) -> Option<u32> {
        self.0.output_token_ceiling(request)
    }

    async fn complete(
        &self,
        request: crate::providers::Request,
    ) -> anyhow::Result<crate::providers::Completion> {
        self.0.complete(request).await
    }
}

#[cfg(test)]
type N8nTestDependencies = std::collections::BTreeMap<
    std::path::PathBuf,
    (
        Arc<dyn crate::providers::Provider>,
        Arc<crate::skills::registry::SkillRegistry>,
    ),
>;

#[cfg(test)]
type N8nTestDependencyStore = std::sync::Mutex<N8nTestDependencies>;

#[cfg(test)]
fn n8n_test_dependencies() -> &'static N8nTestDependencyStore {
    static DEPENDENCIES: std::sync::OnceLock<N8nTestDependencyStore> = std::sync::OnceLock::new();
    DEPENDENCIES.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
fn install_n8n_test_dependencies(
    home: &std::path::Path,
    provider: Arc<dyn crate::providers::Provider>,
    registry: Arc<crate::skills::registry::SkillRegistry>,
) {
    n8n_test_dependencies()
        .lock()
        .expect("n8n test dependency mutex")
        .insert(home.to_path_buf(), (provider, registry));
}

#[cfg(test)]
fn remove_n8n_test_dependencies(home: &std::path::Path) {
    n8n_test_dependencies()
        .lock()
        .expect("n8n test dependency mutex")
        .remove(home);
}

async fn n8n_provider_from_config(
    config: &crate::config::FreedomConfig,
    home: &std::path::Path,
) -> anyhow::Result<Box<dyn crate::providers::Provider>> {
    #[cfg(test)]
    if let Some((provider, _)) = n8n_test_dependencies()
        .lock()
        .expect("n8n test dependency mutex")
        .get(home)
        .cloned()
    {
        return Ok(Box::new(N8nTestProviderHandle(provider)));
    }
    crate::providers::from_config_at(config, home).await
}

fn n8n_provider_call_skill_registry(
    _home: &std::path::Path,
) -> Option<Arc<crate::skills::registry::SkillRegistry>> {
    #[cfg(test)]
    if let Some((_, registry)) = n8n_test_dependencies()
        .lock()
        .expect("n8n test dependency mutex")
        .get(_home)
        .cloned()
    {
        return Some(registry);
    }
    crate::skills::registry::global()
}

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

/// API memory-drift request body. limit caps returned rows; omitted defaults to
/// 20 and the API never accepts more than 100.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryDriftRequest {
    #[serde(default)]
    pub limit: Option<usize>,
}

mod calendar_agenda;
mod calendar_route;
mod dream_obsidian_sync;
mod email_threat;
mod paperless_consult;
mod paperless_findings;
mod pending_drafts;
mod pending_proposals;
mod permission_audit;
mod reflection_weekly_obsidian_sync;

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
    /// Optional caller ceiling carried to the concrete provider request. The
    /// common provider boundary rejects zero, values above its portable cap,
    /// and leaves which cannot prove the exact wire enforcement before any
    /// provider transport begins.
    #[serde(default)]
    pub max_output_tokens: Option<u32>,
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
    /// The caller-provided value from the exact request admitted by the
    /// provider boundary. Omitted for legacy requests that supplied no cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_max_output_tokens: Option<u32>,
    /// The concrete leaf's proven wire ceiling for that same request. This is
    /// an adapter/authorization fact, not a claim about remote consumption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_output_token_ceiling: Option<u32>,
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

// ── /api/memory/drift ───────────────────────────────────────────

/// Read a drift report from an existing views database without creating,
/// migrating, or modifying it. Drift output includes memory text, so callers
/// must hold the same recall-read capability as recall.
fn read_memory_drift(
    views_path: &std::path::Path,
    limit: usize,
) -> Result<crate::memory::drift::DriftReport, HandlerOutcome> {
    if !views_path.is_file() {
        return Err(HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            format!(
                "memory drift store is unavailable: {}",
                views_path.display()
            ),
            "run neoth serve once to materialise views.db; this read-only endpoint will not create it",
        ));
    }
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = rusqlite::Connection::open_with_flags(views_path, flags).map_err(|error| {
        HandlerOutcome::error(
            ApiErrorCode::StoreUnavailable,
            format!("memory drift store open failed: {error}"),
            "check views.db availability and permissions; this endpoint never creates or migrates it",
        )
    })?;
    crate::memory::drift::drift_report(&conn, limit).map_err(|error| {
        HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("memory drift query failed: {error}"),
            "check views.db integrity and the idx_episode projection",
        )
    })
}

/// Return operator-triageable drift rows and exact bucket counts from the
/// existing memory projection. No WAL append, database creation, migration,
/// provider call, or egress occurs.
pub fn memory_drift(ctx: &ApiRequestCtx, state: &ApiState) -> HandlerOutcome {
    let req: MemoryDriftRequest = match parse_body(&ctx.body) {
        Ok(request) => request,
        Err(outcome) => return outcome,
    };
    let limit = req.limit.unwrap_or(20).min(100);
    let report = match read_memory_drift(&state.home.join("views.db"), limit) {
        Ok(report) => report,
        Err(outcome) => return outcome,
    };
    match serde_json::to_value(report) {
        Ok(report) => HandlerOutcome::ok_json(report),
        Err(error) => HandlerOutcome::error(
            ApiErrorCode::UpstreamError,
            format!("memory drift response serialisation failed: {error}"),
            "retry after checking the stored drift rows",
        ),
    }
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
    skill_registry_context: Option<&crate::pipeline::RenderedUntrustedContext>,
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
        // A provider:call token authenticates the workflow, not the provenance
        // of each machine-generated prompt. Do not relabel arbitrary workflow
        // input as an explicit human operator command.
        operator_sovereignty: None,
        operator_context: None,
        preset_addendum: None,
        explicit_system: req.system.as_deref(),
        repo_context_block: None,
        attachment_contexts: None,
        skill_system_prompt: None,
        skill_registry_context,
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

    // Apply typed budget enforcement (parity with the CLI finalize path):
    // wrap the enriched system (A) + prompt (E), enforce the live cap derived
    // from the resolved model and operator config, and fail-close if protected
    // content cannot fit.
    let cap = crate::tokens::budget::effective_cap(
        "",
        effective_model.as_deref().unwrap_or("provider_default"),
        config.tokens.max_per_request,
    );
    let budget =
        crate::tokens::budget::finalize_daemon_request(enriched.prompt, enriched.system, cap)
            .map_err(|e| anyhow::anyhow!("n8n provider_call over token cap: {e}"))?;

    Ok(crate::providers::Request {
        prompt: budget.prompt,
        system: budget.system,
        model: effective_model,
        max_output_tokens: req.max_output_tokens,
        ..Default::default()
    })
}

/// Check caller-owned provider controls before the authorization boundary can
/// begin a transport. `complete` repeats this common validation immediately
/// before authorizing its exact request; the early check makes malformed or
/// unsupported n8n input an ordinary handler refusal and lets the response
/// retain only a proven, request-bound ceiling.
fn n8n_output_ceiling_preflight(
    provider: &dyn crate::providers::Provider,
    request: &crate::providers::Request,
) -> anyhow::Result<Option<u32>> {
    provider.validate_request_controls(request)?;
    let effective = provider.output_token_ceiling(request);
    match (request.max_output_tokens, effective) {
        (Some(requested), Some(ceiling)) if ceiling > 0 && ceiling <= requested => Ok(effective),
        (Some(requested), Some(0)) => anyhow::bail!(
            "provider `{}` returned a zero output-token ceiling for requested max_output_tokens={requested}",
            provider.name()
        ),
        (Some(requested), Some(ceiling)) => anyhow::bail!(
            "provider `{}` cannot prove requested max_output_tokens={requested}: effective wire ceiling is {ceiling}",
            provider.name()
        ),
        (Some(requested), None) => anyhow::bail!(
            "provider `{}` cannot prove wire enforcement for requested max_output_tokens={requested}",
            provider.name()
        ),
        (None, effective) => Ok(effective),
    }
}

/// Resolve the one prompt-visible Skill registry for an n8n provider call.
///
/// n8n is a bare-metal provider surface, so it deliberately has no selected
/// Skill body, tool catalogue, or routing result. It does receive the same
/// bounded, typed Block D session registry as other daemon entry points. The
/// caller pins the accepted config epoch first; a missing, foreign-home, or
/// stale daemon registry is an error, never an empty inventory.
fn n8n_session_skill_registry_context(
    home: &std::path::Path,
    config: &crate::config::FreedomConfig,
    reload_controller: &Arc<crate::config::reload::ReloadController>,
    accepted_config_epoch: u64,
    registry: Option<Arc<crate::skills::registry::SkillRegistry>>,
) -> anyhow::Result<crate::pipeline::RenderedUntrustedContext> {
    let expected_skills_dir = home.join("skills");
    let registry = registry.context("n8n provider_call requires the daemon SkillRegistry")?;
    anyhow::ensure!(
        registry.skills_dir() == expected_skills_dir.as_path(),
        "n8n provider_call daemon SkillRegistry belongs to a different home"
    );
    anyhow::ensure!(
        registry.uses_reload_controller(reload_controller),
        "n8n provider_call daemon SkillRegistry is bound to a different accepted config controller"
    );
    let snapshot = registry
        .authority_bound_snapshot_for_epoch(accepted_config_epoch)
        .context("acquire authority-bound n8n Skill snapshot")?;

    let mut blocked_skill_ids = std::collections::BTreeSet::<String>::new();
    if !config.skills.pinned_hashes.is_empty() {
        let verdicts = crate::skills::versioning::check_pinned_hashes(
            snapshot
                .skills()
                .iter()
                .map(|skill| (skill.id(), skill.content_hash.as_str())),
            &config.skills.pinned_hashes,
        );
        for (skill, verdict) in snapshot.skills().iter().zip(verdicts) {
            if verdict.verdict == crate::skills::versioning::PinnedHashOutcome::Mismatch {
                blocked_skill_ids.insert(skill.id().to_owned());
            }
        }
    }
    let eval_suppress = config.skills.should_suppress_for_eval();
    crate::skills::resolver::SkillRouteResolver::new(snapshot)
        .retaining(|skill| !eval_suppress && !blocked_skill_ids.contains(skill.id()))
        .session_registry_context(&[])
        .context("render n8n session-start Skill registry context")
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
    // Retain one accepted config+epoch snapshot for the entire request. The
    // registry below must be bound to this same epoch before any provider is
    // constructed, so n8n cannot combine a newer config with old authority.
    let accepted_config = state.reload_controller.accepted_snapshot();
    let accepted_config_epoch = accepted_config.epoch();
    let live_config = accepted_config.config();
    let skill_registry_context = match n8n_session_skill_registry_context(
        &state.home,
        live_config.as_ref(),
        &state.reload_controller,
        accepted_config_epoch,
        n8n_provider_call_skill_registry(&state.home),
    ) {
        Ok(context) => context,
        Err(error) => {
            return HandlerOutcome::error(
                ApiErrorCode::UpstreamError,
                format!("n8n provider_call Skill registry unavailable: {error:#}"),
                "start the daemon with its accepted skills directory and retry after the registry is current",
            );
        }
    };
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
    let provider = match n8n_provider_from_config(live_config.as_ref(), &state.home).await {
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
        Some(&skill_registry_context),
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
    // Validate the exact final request before `complete` can authorize or
    // dispatch it. The same common Provider implementation repeats this at
    // its mandatory boundary, which keeps cost and WAL bindings anchored to
    // this unchanged `request`, not to n8n-side response metadata.
    let requested_max_output_tokens = request.max_output_tokens;
    let proven_output_token_ceiling = match n8n_output_ceiling_preflight(&provider, &request) {
        Ok(ceiling) => ceiling,
        Err(error) => {
            return HandlerOutcome::error(
                ApiErrorCode::BadRequest,
                format!("provider_call output ceiling refused: {error:#}"),
                "use max_output_tokens within the provider's supported bounded range",
            );
        }
    };
    // A legacy caller did not ask the n8n status surface for a ceiling. Keep
    // its response shape unchanged while preserving the leaf-proven default
    // ceiling inside the existing AuthorizedProvider cost/WAL boundary.
    let effective_output_token_ceiling = requested_max_output_tokens.and(proven_output_token_ceiling);
    match provider.complete(request).await {
        Ok(comp) => {
            let model = comp.identity.wire_model.clone();
            HandlerOutcome::ok_json(
                serde_json::to_value(ProviderCallResponse {
                    completion: comp.text,
                    model: Some(model),
                    requested_max_output_tokens,
                    effective_output_token_ceiling,
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
        ("POST", "/api/memory/drift") => memory_drift(&ctx, &state),
        ("POST", "/api/proactive/proposals/pending") => pending_proposals::handle(&ctx, &state),
        ("POST", "/api/email/drafts/pending") => pending_drafts::handle(&ctx, &state),
        ("POST", "/api/permissions/audit") => permission_audit::handle(&ctx, &state).await,
        ("POST", "/api/calendar/agenda") => calendar_route::handle(&ctx, &state).await,
        ("POST", "/api/dreams/obsidian/sync") => dream_obsidian_sync::handle(&ctx, &state).await,
        ("POST", "/api/reflections/weekly/obsidian/sync") => {
            reflection_weekly_obsidian_sync::handle(&ctx, &state).await
        }
        ("POST", "/api/email/threat/scan") => email_threat::handle(&ctx, &state),
        ("POST", "/api/paperless/consult") => paperless_consult::handle(&ctx, &state).await,
        ("POST", "/api/paperless/findings/recent") => {
            paperless_findings::handle(&ctx, &state).await
        }
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct N8nCeilingProbe {
        controls: crate::providers::ProviderRequestControls,
        ceiling: Option<u32>,
        calls: AtomicUsize,
        requests: std::sync::Mutex<Vec<crate::providers::Request>>,
    }

    #[async_trait::async_trait]
    impl crate::providers::Provider for N8nCeilingProbe {
        fn name(&self) -> &'static str {
            "local_ollama"
        }

        fn request_controls(&self) -> crate::providers::ProviderRequestControls {
            self.controls
        }

        fn output_token_ceiling(&self, _request: &crate::providers::Request) -> Option<u32> {
            self.ceiling
        }

        fn default_model(&self) -> Option<&str> {
            Some("n8n-ceiling-probe")
        }

        async fn complete(
            &self,
            request: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests
                .lock()
                .expect("n8n ceiling probe requests")
                .push(request.clone());
            Ok(crate::providers::Completion {
                text: "bounded n8n completion".to_owned(),
                model: request
                    .model
                    .unwrap_or_else(|| "n8n-ceiling-probe".to_owned()),
                latency: Duration::ZERO,
                ..Default::default()
            })
        }
    }

    async fn n8n_test_registry(
        home: &std::path::Path,
        config: crate::config::FreedomConfig,
    ) -> (
        Arc<crate::config::reload::ReloadController>,
        Arc<crate::skills::registry::SkillRegistry>,
    ) {
        let config_path = home.join("freedom.yaml");
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            config,
            config_path,
        ));
        let registry = crate::skills::registry::SkillRegistry::load_with_reload_controller(
            home.join("skills"),
            Arc::clone(&controller),
        )
        .await
        .expect("load n8n test SkillRegistry");
        (controller, registry)
    }

    async fn n8n_ceiling_handler_state(
        home: &std::path::Path,
        provider: Arc<dyn crate::providers::Provider>,
    ) -> (
        ApiState,
        crate::wal::writer::WalWriterHandle,
        tokio::task::JoinHandle<()>,
    ) {
        let mut config = crate::config::FreedomConfig::default();
        config.provider_kind = Some(crate::cli::init::ProviderKind::LocalOllama);
        config.provider_model = Some("n8n-ceiling-probe".to_owned());
        let (controller, registry) = n8n_test_registry(home, config.clone()).await;
        install_n8n_test_dependencies(home, provider, registry);
        let (writer, writer_join) =
            crate::wal::writer::spawn(home.join("n8n-ceiling-handler.wal")).expect("start WAL");
        let state = ApiState {
            writer: writer.clone(),
            config: Arc::new(config),
            reload_controller: controller,
            home: home.to_path_buf(),
            token: "n8n-ceiling-test-token".to_owned(),
            cooldown: Arc::new(crate::n8n_api::auth::AuthCooldown::new()),
            boot_instant: std::time::Instant::now(),
        };
        (state, writer, writer_join)
    }

    fn n8n_ceiling_provider_call_ctx(body: &[u8]) -> ApiRequestCtx {
        ApiRequestCtx {
            caller: super::super::server::ApiCaller::MasterToken,
            method: "POST".to_owned(),
            path: "/api/provider/call".to_owned(),
            request_id: "n8n-ceiling-handler-test".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            body: body.to_vec(),
        }
    }

    fn wal_payloads(segment: &std::path::Path, event_type: u8) -> Vec<serde_json::Value> {
        let bytes = std::fs::read(segment).expect("read provider WAL");
        let header =
            crate::wal::segment_header::parse_segment_header(&bytes).expect("parse WAL header");
        let mut cursor = header.header_len();
        let mut payloads = Vec::new();
        while cursor < bytes.len() {
            let frame =
                crate::wal::frame::decode_frame(&bytes[cursor..]).expect("decode WAL frame");
            if frame.header.event_type == event_type {
                payloads.push(
                    serde_json::from_slice::<serde_json::Value>(frame.payload)
                        .expect("provider request JSON"),
                );
            }
            cursor += frame.header.total_len as usize;
        }
        payloads
    }

    fn provider_request_wal_payloads(segment: &std::path::Path) -> Vec<serde_json::Value> {
        wal_payloads(segment, crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST)
    }

    fn cost_estimate_wal_payloads(segment: &std::path::Path) -> Vec<serde_json::Value> {
        wal_payloads(segment, crate::wal::events::EVENT_TYPE_COST_ESTIMATE_SHOWN)
    }

    fn pin_preference(
        home: &std::path::Path,
        subject_id: &str,
        session_id: &str,
        event_byte: u8,
        value: crate::profile::communication::PreferenceValue,
    ) {
        crate::profile::communication::set_test_scoped_preference(
            home,
            &crate::config::CommunicationProfileConfig::default(),
            subject_id,
            session_id,
            value,
            [event_byte; 32],
            1_700_000_000 + i64::from(event_byte),
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
    fn memory_drift_request_defaults_limit_to_none_and_rejects_wrong_type() {
        let request: MemoryDriftRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(request.limit, None);
        assert!(parse_body::<MemoryDriftRequest>(br#"{"limit":"20"}"#).is_err());
    }

    #[test]
    fn memory_drift_reads_seeded_rows_with_limit_and_exact_counts() {
        let home = tempfile::tempdir().unwrap();
        let views_path = home.path().join("views.db");
        let conn = crate::memory::store::open(&views_path).unwrap();
        for (event_id, importance) in [(1_i64, 0.12_f64), (2, 0.18), (3, 0.25), (4, 0.60)] {
            conn.execute(
                "INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                 VALUES (?1, 1, ?2, ?3, ?4, ?5, ?2)",
                rusqlite::params![
                    event_id,
                    event_id,
                    format!("drift-{event_id}"),
                    format!("hash-{event_id}"),
                    importance
                ],
            )
            .unwrap();
        }
        drop(conn);

        let report = read_memory_drift(&views_path, 2).unwrap();
        assert_eq!(report.drifting.len(), 2);
        assert_eq!(report.imminent_count, 2);
        assert_eq!(report.at_risk_count, 1);
        assert_eq!(report.stable_count, 1);
        assert_eq!(report.drifting[0].event_id, 1);
        assert_eq!(report.drifting[1].event_id, 2);
    }

    #[test]
    fn memory_drift_missing_store_is_structured_and_does_not_create_database() {
        let home = tempfile::tempdir().unwrap();
        let views_path = home.path().join("views.db");
        let outcome = read_memory_drift(&views_path, 20).unwrap_err();
        assert_eq!(outcome.error_code(), Some(ApiErrorCode::StoreUnavailable));
        assert!(!views_path.exists());
    }

    fn memory_drift_test_state(
        home: &std::path::Path,
        writer: crate::wal::writer::WalWriterHandle,
    ) -> ApiState {
        let config = crate::config::FreedomConfig::default();
        ApiState {
            writer,
            config: Arc::new(config.clone()),
            reload_controller: Arc::new(crate::config::reload::ReloadController::new(
                config,
                home.join("freedom.yaml"),
            )),
            home: home.to_path_buf(),
            token: "test-token".to_owned(),
            cooldown: Arc::new(crate::n8n_api::auth::AuthCooldown::new()),
            boot_instant: std::time::Instant::now(),
        }
    }

    fn memory_drift_ctx(body: &[u8]) -> ApiRequestCtx {
        ApiRequestCtx {
            caller: super::super::server::ApiCaller::MasterToken,
            method: "POST".to_owned(),
            path: "/api/memory/drift".to_owned(),
            request_id: "memory-drift-test".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            body: body.to_vec(),
        }
    }

    #[tokio::test]
    async fn memory_drift_handler_default_cap_and_zero_keep_exact_counts() {
        let home = tempfile::tempdir().unwrap();
        let views_path = home.path().join("views.db");
        let conn = crate::memory::store::open(&views_path).unwrap();
        for event_id in 1_i64..=101 {
            conn.execute(
                "INSERT INTO idx_episode \
                 (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
                 VALUES (?1, 1, ?2, ?3, ?4, 0.15, ?2)",
                rusqlite::params![
                    event_id,
                    event_id,
                    format!("drift-{event_id}"),
                    format!("hash-{event_id}")
                ],
            )
            .unwrap();
        }
        drop(conn);
        let (writer, writer_join) =
            crate::wal::writer::spawn(home.path().join("memory-drift-test.wal")).unwrap();
        let state = memory_drift_test_state(home.path(), writer.clone());

        let default = memory_drift(&memory_drift_ctx(b"{}"), &state);
        let capped = memory_drift(&memory_drift_ctx(br#"{"limit":999}"#), &state);
        let zero = memory_drift(&memory_drift_ctx(br#"{"limit":0}"#), &state);
        for (outcome, expected_rows) in [(default, 20_usize), (capped, 100), (zero, 0)] {
            match outcome {
                HandlerOutcome::Ok { body } => {
                    assert_eq!(body["drifting"].as_array().unwrap().len(), expected_rows);
                    assert_eq!(body["imminent_count"], 101);
                    assert_eq!(body["at_risk_count"], 0);
                    assert_eq!(body["stable_count"], 0);
                }
                HandlerOutcome::Err { message, .. } => panic!("unexpected drift error: {message}"),
            }
        }

        drop(state);
        drop(writer);
        writer_join.await.unwrap();
    }

    #[tokio::test]
    async fn memory_drift_route_success_envelopes_report_and_rejects_wrong_limit_type() {
        let home = tempfile::tempdir().unwrap();
        let views_path = home.path().join("views.db");
        let conn = crate::memory::store::open(&views_path).unwrap();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, 1, 'triage', 'hash-1', 0.15, 1)",
            [],
        )
        .unwrap();
        drop(conn);
        let (writer, writer_join) =
            crate::wal::writer::spawn(home.path().join("memory-drift-route.wal")).unwrap();
        let state = Arc::new(memory_drift_test_state(home.path(), writer.clone()));

        let outcome = route(memory_drift_ctx(br#"{"limit":1}"#), Arc::clone(&state)).await;
        match outcome {
            HandlerOutcome::Ok { body } => {
                let envelope = crate::n8n_api::ApiOkResponse::new(body, "route-request");
                let value = serde_json::to_value(envelope).unwrap();
                assert_eq!(value["ok"], true);
                assert_eq!(value["data"]["drifting"].as_array().unwrap().len(), 1);
                assert_eq!(value["data"]["imminent_count"], 1);
            }
            HandlerOutcome::Err { message, .. } => panic!("route failed: {message}"),
        }
        let invalid = memory_drift(&memory_drift_ctx(br#"{"limit":"1"}"#), &state);
        assert_eq!(invalid.error_code(), Some(ApiErrorCode::BadRequest));

        drop(state);
        drop(writer);
        writer_join.await.unwrap();
    }

    #[tokio::test]
    async fn memory_drift_handler_missing_store_is_structured_without_creation() {
        let home = tempfile::tempdir().unwrap();
        let views_path = home.path().join("views.db");
        let (writer, writer_join) =
            crate::wal::writer::spawn(home.path().join("memory-drift-missing.wal")).unwrap();
        let state = memory_drift_test_state(home.path(), writer.clone());

        let outcome = memory_drift(&memory_drift_ctx(b"{}"), &state);
        assert_eq!(outcome.error_code(), Some(ApiErrorCode::StoreUnavailable));
        assert!(!views_path.exists());

        drop(state);
        drop(writer);
        writer_join.await.unwrap();
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
            max_output_tokens: None,
            incognito: false,
        };

        let request =
            build_provider_request(home.path(), &config, &req, Some("wire-model".into()), None)
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
            build_provider_request(home.path(), &config, &legacy, None, None).is_err(),
            "non-incognito must not silently drop corrupt configured state"
        );

        let incognito: ProviderCallRequest = serde_json::from_str(
            r#"{"prompt":"private automation","system":"EXPLICIT_ONLY","incognito":true}"#,
        )
        .expect("incognito request parses");
        let request = build_provider_request(home.path(), &config, &incognito, None, None)
            .expect("incognito skips communication-state read");
        assert_eq!(request.system.as_deref(), Some("EXPLICIT_ONLY"));
        assert_eq!(
            std::fs::read(&state_path).expect("read malformed sentinel"),
            b"not valid communication state"
        );
    }

    #[test]
    fn provider_call_output_ceiling_json_reaches_exact_final_request_and_response() {
        let home = tempfile::tempdir().expect("tempdir");
        let config = crate::config::FreedomConfig::default();
        let request: ProviderCallRequest = parse_body(
            br#"{"prompt":"bounded automation","incognito":true,"max_output_tokens":321}"#,
        )
        .expect("bounded n8n JSON parses");
        let final_request = build_provider_request(home.path(), &config, &request, None, None)
            .expect("build exact provider request");
        assert_eq!(final_request.max_output_tokens, Some(321));

        let effective = n8n_output_ceiling_preflight(
            &N8nCeilingProbe {
                controls: crate::providers::ProviderRequestControls::OUTPUT_TOKEN_LIMIT,
                ceiling: Some(320),
                calls: AtomicUsize::new(0),
                requests: std::sync::Mutex::new(Vec::new()),
            },
            &final_request,
        )
        .expect("bounded leaf proves its stricter wire ceiling");
        let response = serde_json::to_value(ProviderCallResponse {
            completion: "bounded".to_owned(),
            model: Some("wire-model".to_owned()),
            requested_max_output_tokens: final_request.max_output_tokens,
            effective_output_token_ceiling: effective,
        })
        .expect("response is JSON");
        assert_eq!(response["requested_max_output_tokens"], 321);
        assert_eq!(response["effective_output_token_ceiling"], 320);
    }

    #[test]
    fn provider_call_output_ceiling_legacy_absence_preserves_request_and_response_shape() {
        let request: ProviderCallRequest =
            parse_body(br#"{"prompt":"legacy"}"#).expect("legacy n8n JSON parses");
        assert_eq!(request.max_output_tokens, None);
        let response = serde_json::to_value(ProviderCallResponse {
            completion: "legacy".to_owned(),
            model: None,
            requested_max_output_tokens: None,
            effective_output_token_ceiling: None,
        })
        .expect("legacy response is JSON");
        assert!(response.get("requested_max_output_tokens").is_none());
        assert!(response.get("effective_output_token_ceiling").is_none());
    }

    #[test]
    fn provider_call_output_ceiling_invalid_or_unproven_is_refused_before_complete() {
        let controls = crate::providers::ProviderRequestControls::OUTPUT_TOKEN_LIMIT;
        for invalid in [
            Some(0),
            Some(crate::providers::MAX_REQUEST_OUTPUT_TOKENS + 1),
        ] {
            let request = crate::providers::Request {
                max_output_tokens: invalid,
                ..Default::default()
            };
            assert!(
                n8n_output_ceiling_preflight(
                    &N8nCeilingProbe {
                        controls,
                        ceiling: Some(64),
                        calls: AtomicUsize::new(0),
                        requests: std::sync::Mutex::new(Vec::new()),
                    },
                    &request,
                )
                .is_err(),
                "invalid cap {invalid:?} must fail before provider complete"
            );
        }
        let requested = crate::providers::Request {
            max_output_tokens: Some(64),
            ..Default::default()
        };
        assert!(
            n8n_output_ceiling_preflight(
                &N8nCeilingProbe {
                    controls: crate::providers::ProviderRequestControls::NONE,
                    ceiling: None,
                    calls: AtomicUsize::new(0),
                    requests: std::sync::Mutex::new(Vec::new()),
                },
                &requested,
            )
            .is_err(),
            "a leaf without the output-capability cannot receive the request"
        );
        assert!(
            n8n_output_ceiling_preflight(
                &N8nCeilingProbe {
                    controls,
                    ceiling: None,
                    calls: AtomicUsize::new(0),
                    requests: std::sync::Mutex::new(Vec::new()),
                },
                &requested,
            )
            .is_err(),
            "a nominally-capable leaf must still prove an exact wire ceiling"
        );
    }

    #[tokio::test]
    async fn provider_call_output_ceiling_handler_returns_exact_request_response_and_wal_binding() {
        let home = tempfile::tempdir().expect("temporary n8n home");
        let inner = Arc::new(N8nCeilingProbe {
            controls: crate::providers::ProviderRequestControls::OUTPUT_TOKEN_LIMIT,
            ceiling: Some(320),
            calls: AtomicUsize::new(0),
            requests: std::sync::Mutex::new(Vec::new()),
        });
        let (state, writer, writer_join) = n8n_ceiling_handler_state(
            home.path(),
            Arc::clone(&inner) as Arc<dyn crate::providers::Provider>,
        )
        .await;
        let outcome = provider_call(
            &n8n_ceiling_provider_call_ctx(
                br#"{"prompt":"bounded automation","incognito":true,"max_output_tokens":321}"#,
            ),
            &state,
        )
        .await;
        match outcome {
            HandlerOutcome::Ok { body } => {
                assert_eq!(body["requested_max_output_tokens"], 321);
                assert_eq!(body["effective_output_token_ceiling"], 320);
            }
            HandlerOutcome::Err { message, .. } => panic!("unexpected handler refusal: {message}"),
        }
        let legacy = provider_call(
            &n8n_ceiling_provider_call_ctx(br#"{"prompt":"legacy automation","incognito":true}"#),
            &state,
        )
        .await;
        match legacy {
            HandlerOutcome::Ok { body } => {
                assert!(body.get("requested_max_output_tokens").is_none());
                assert!(body.get("effective_output_token_ceiling").is_none());
            }
            HandlerOutcome::Err { message, .. } => panic!("unexpected legacy refusal: {message}"),
        }
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        let requests = inner.requests.lock().expect("recorded request");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].max_output_tokens, Some(321));
        assert_eq!(requests[1].max_output_tokens, None);
        drop(requests);
        let segment = home.path().join("n8n-ceiling-handler.wal");
        remove_n8n_test_dependencies(home.path());
        drop(state);
        drop(writer);
        writer_join.await.expect("WAL writer drains");
        let payloads = provider_request_wal_payloads(&segment);
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0]["requested_max_output_tokens"], 321);
        assert!(payloads[1]["requested_max_output_tokens"].is_null());
        let estimates = cost_estimate_wal_payloads(&segment);
        assert_eq!(estimates.len(), 2);
        assert_eq!(estimates[0]["requested_max_output_tokens"], 321);
        assert_eq!(estimates[0]["output_token_ceiling"], 320);
        let request_binding = payloads[0]["request_binding_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
            .expect("provider request carries a nonempty binding");
        let estimate_binding = estimates[0]["request_binding_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
            .expect("cost estimate carries a nonempty binding");
        assert_eq!(request_binding.len(), 64);
        assert!(request_binding.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(request_binding, estimate_binding);
    }

    #[tokio::test]
    async fn provider_call_output_ceiling_handler_refuses_invalid_or_unproven_before_leaf_or_wal() {
        for (controls, ceiling, body) in [
            (
                crate::providers::ProviderRequestControls::OUTPUT_TOKEN_LIMIT,
                Some(64),
                br#"{"prompt":"zero","incognito":true,"max_output_tokens":0}"#.as_slice(),
            ),
            (
                crate::providers::ProviderRequestControls::OUTPUT_TOKEN_LIMIT,
                Some(64),
                br#"{"prompt":"over","incognito":true,"max_output_tokens":131073}"#.as_slice(),
            ),
            (
                crate::providers::ProviderRequestControls::NONE,
                None,
                br#"{"prompt":"unsupported","incognito":true,"max_output_tokens":64}"#.as_slice(),
            ),
            (
                crate::providers::ProviderRequestControls::OUTPUT_TOKEN_LIMIT,
                None,
                br#"{"prompt":"unproven","incognito":true,"max_output_tokens":64}"#.as_slice(),
            ),
        ] {
            let home = tempfile::tempdir().expect("temporary n8n home");
            let inner = Arc::new(N8nCeilingProbe {
                controls,
                ceiling,
                calls: AtomicUsize::new(0),
                requests: std::sync::Mutex::new(Vec::new()),
            });
            let (state, writer, writer_join) = n8n_ceiling_handler_state(
                home.path(),
                Arc::clone(&inner) as Arc<dyn crate::providers::Provider>,
            )
            .await;
            let outcome = provider_call(&n8n_ceiling_provider_call_ctx(body), &state).await;
            assert_eq!(outcome.error_code(), Some(ApiErrorCode::BadRequest));
            assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
            assert!(inner.requests.lock().expect("recorded request").is_empty());
            let segment = home.path().join("n8n-ceiling-handler.wal");
            remove_n8n_test_dependencies(home.path());
            drop(state);
            drop(writer);
            writer_join.await.expect("WAL writer drains");
            assert!(
                provider_request_wal_payloads(&segment).is_empty(),
                "refused n8n ceiling must not start a provider lifecycle WAL record"
            );
        }
    }

    #[tokio::test]
    async fn provider_call_output_ceiling_reuses_authorized_cost_wal_request_binding() {
        let home = tempfile::tempdir().expect("temporary n8n home");
        let segment = home.path().join("n8n-output-ceiling.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).expect("start WAL writer");
        let inner = Arc::new(N8nCeilingProbe {
            controls: crate::providers::ProviderRequestControls::OUTPUT_TOKEN_LIMIT,
            ceiling: Some(320),
            calls: AtomicUsize::new(0),
            requests: std::sync::Mutex::new(Vec::new()),
        });
        let authorizer = crate::providers::cost_authorization::ProviderCallAuthorizer::fail_closed(
            crate::permissions::AutonomyLevel::Full,
            Some(writer.clone()),
            crate::config::TokensConfig::default_max_per_request(),
        );
        let provider = crate::providers::cost_authorization::AuthorizedProvider::from_arc(
            Arc::clone(&inner) as Arc<dyn crate::providers::Provider>,
            authorizer,
            Some("n8n-ceiling-probe".to_owned()),
            "n8n.provider_call",
        );
        let exact_request = crate::providers::Request {
            prompt: "bounded n8n request".to_owned(),
            max_output_tokens: Some(321),
            ..Default::default()
        };
        assert_eq!(
            n8n_output_ceiling_preflight(&provider, &exact_request).expect("preflight"),
            Some(320)
        );
        provider
            .complete(exact_request)
            .await
            .expect("authorized capped provider call");
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        drop(provider);
        drop(writer);
        join.await.expect("WAL writer drains");

        let requests = provider_request_wal_payloads(&segment);
        assert_eq!(requests.len(), 1);
        let request_payload = &requests[0];
        assert_eq!(request_payload["requested_max_output_tokens"], 321);
        let estimates = cost_estimate_wal_payloads(&segment);
        assert_eq!(estimates.len(), 1);
        assert_eq!(estimates[0]["requested_max_output_tokens"], 321);
        assert_eq!(estimates[0]["output_token_ceiling"], 320);
        let request_binding = request_payload["request_binding_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
            .expect("provider request carries a nonempty binding");
        let estimate_binding = estimates[0]["request_binding_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
            .expect("cost estimate carries a nonempty binding");
        assert_eq!(request_binding.len(), 64);
        assert!(request_binding.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(request_binding, estimate_binding);
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
        let request = build_provider_request(home.path(), &config, &req, None, None)
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
            max_output_tokens: None,
            incognito: false,
        };

        let request = build_provider_request(home.path(), &config, &req, None, None)
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

    #[tokio::test]
    async fn n8n_provider_request_includes_exactly_one_guarded_registry_without_route_leaks() {
        let home = tempfile::tempdir().expect("tempdir");
        let config = crate::config::FreedomConfig::default();
        let (controller, registry) = n8n_test_registry(home.path(), config.clone()).await;
        let context = n8n_session_skill_registry_context(
            home.path(),
            &config,
            &controller,
            controller.accepted_snapshot().epoch(),
            Some(registry),
        )
        .expect("render admitted n8n registry");
        let request = build_provider_request(
            home.path(),
            &config,
            &ProviderCallRequest {
                prompt: "automation task".into(),
                system: None,
                model: None,
                max_output_tokens: None,
                incognito: true,
            },
            Some("wire-model".into()),
            Some(&context),
        )
        .expect("compose n8n provider request");
        let system = request.system.expect("typed Block D registry system layer");
        assert_eq!(system.matches(context.as_str()).count(), 1);
        assert!(context.as_str().contains("UNTRUSTED data"));
        assert!(context.payload().contains("\"skills\""));
        assert!(!context.payload().contains("\"system_prompt\""));
        assert!(!context.payload().contains("\"used_skill_id\""));
    }

    #[tokio::test]
    async fn n8n_registry_excludes_eval_and_pinned_hash_mismatch_skills() {
        let home = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::FreedomConfig::default();
        config.skills.disabled_for_eval_sessions = true;
        config.skills.eval_session_active = true;
        let (controller, registry) = n8n_test_registry(home.path(), config.clone()).await;
        let eval_context = n8n_session_skill_registry_context(
            home.path(),
            &config,
            &controller,
            controller.accepted_snapshot().epoch(),
            Some(Arc::clone(&registry)),
        )
        .expect("eval registry remains a valid empty typed envelope");
        assert!(eval_context.payload().contains("\"skills\":[]"));

        let mut pinned_config = crate::config::FreedomConfig::default();
        let (baseline_controller, baseline_registry) =
            n8n_test_registry(home.path(), pinned_config.clone()).await;
        let baseline_context = n8n_session_skill_registry_context(
            home.path(),
            &pinned_config,
            &baseline_controller,
            baseline_controller.accepted_snapshot().epoch(),
            Some(baseline_registry),
        )
        .expect("unpinned baseline registry");
        let baseline: serde_json::Value =
            serde_json::from_str(baseline_context.payload()).expect("registry payload JSON");
        let pinned_skill = baseline["skills"]
            .as_array()
            .and_then(|skills| skills.first())
            .and_then(|skill| skill["id"].as_str())
            .expect("pin fixture needs an advertised Skill")
            .to_owned();
        pinned_config
            .skills
            .pinned_hashes
            .insert(pinned_skill.clone(), "deliberately-wrong-hash".into());
        let (pinned_controller, pinned_registry) =
            n8n_test_registry(home.path(), pinned_config.clone()).await;
        let pinned_context = n8n_session_skill_registry_context(
            home.path(),
            &pinned_config,
            &pinned_controller,
            pinned_controller.accepted_snapshot().epoch(),
            Some(pinned_registry),
        )
        .expect("pinned registry renders after excluding mismatch");
        let pinned: serde_json::Value =
            serde_json::from_str(pinned_context.payload()).expect("pinned registry payload JSON");
        assert!(
            pinned["skills"]
                .as_array()
                .expect("complete pinned Skill inventory")
                .iter()
                .all(|skill| skill["id"].as_str() != Some(pinned_skill.as_str())),
            "a pinned-hash mismatch must not be advertised to n8n"
        );
    }

    #[tokio::test]
    async fn n8n_registry_refuses_absent_foreign_or_stale_daemon_registry() {
        let home = tempfile::tempdir().expect("tempdir");
        let config = crate::config::FreedomConfig::default();
        let (controller, registry) = n8n_test_registry(home.path(), config.clone()).await;
        let epoch = controller.accepted_snapshot().epoch();
        assert!(
            n8n_session_skill_registry_context(home.path(), &config, &controller, epoch, None,)
                .is_err()
        );
        let foreign_home = tempfile::tempdir().expect("foreign tempdir");
        assert!(
            n8n_session_skill_registry_context(
                foreign_home.path(),
                &config,
                &controller,
                epoch,
                Some(Arc::clone(&registry)),
            )
            .is_err()
        );
        let same_path_controller = Arc::new(crate::config::reload::ReloadController::new(
            config.clone(),
            home.path().join("freedom.yaml"),
        ));
        assert!(
            n8n_session_skill_registry_context(
                home.path(),
                &config,
                &same_path_controller,
                epoch,
                Some(Arc::clone(&registry)),
            )
            .is_err()
        );
        let different_path_controller = Arc::new(crate::config::reload::ReloadController::new(
            config.clone(),
            home.path().join("other-freedom.yaml"),
        ));
        assert!(
            n8n_session_skill_registry_context(
                home.path(),
                &config,
                &different_path_controller,
                epoch,
                Some(Arc::clone(&registry)),
            )
            .is_err()
        );
        assert!(
            n8n_session_skill_registry_context(
                home.path(),
                &config,
                &controller,
                epoch.saturating_add(1),
                Some(registry),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn n8n_provider_request_retains_registry_a_after_later_accepted_b() {
        let home = tempfile::tempdir().expect("tempdir");
        let config_a = crate::config::FreedomConfig::default();
        let (controller, registry) = n8n_test_registry(home.path(), config_a.clone()).await;
        let registry_a = n8n_session_skill_registry_context(
            home.path(),
            &config_a,
            &controller,
            controller.accepted_snapshot().epoch(),
            Some(Arc::clone(&registry)),
        )
        .expect("render registry A");

        let mut config_b = config_a.clone();
        config_b.skills.disabled_for_eval_sessions = true;
        config_b.skills.eval_session_active = true;
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config_b).expect("serialize config B"),
        )
        .expect("write config B");
        controller.try_reload().expect("accept config B");
        registry.reload_now().await.expect("publish registry B");
        let registry_b = n8n_session_skill_registry_context(
            home.path(),
            &config_b,
            &controller,
            controller.accepted_snapshot().epoch(),
            Some(registry),
        )
        .expect("render registry B");
        assert!(registry_b.payload().contains("\"skills\":[]"));

        let request_a = build_provider_request(
            home.path(),
            &config_a,
            &ProviderCallRequest {
                prompt: "automation task".into(),
                system: None,
                model: None,
                max_output_tokens: None,
                incognito: true,
            },
            None,
            Some(&registry_a),
        )
        .expect("compose retained A request");
        let system_a = request_a.system.expect("retained A registry");
        assert!(system_a.contains(registry_a.as_str()));
        assert!(!system_a.contains(registry_b.as_str()));
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
        crate::consent::grant_route(
            home.path(),
            &crate::consent::ConsentRoute::new(ProviderKind::LocalOllama, Some(remote)),
        )
        .unwrap();
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
