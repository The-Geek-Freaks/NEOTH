//! Authenticated loopback browser access to the existing daemon chat runtime.
//! Same-user audit RPC mints single-use handoffs. Companion tokens cannot enter
//! this surface. Turn capabilities remain server-side, within their session.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::daemon::gui_chat_protocol as gui;
use crate::channels::registry::ChannelAccountId;
use base64::Engine as _;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const HANDOFF_TTL_SECS: u64 = 120;
const SESSION_TTL_SECS: u64 = 3600;
const BODY_LIMIT: usize = 16 * 1024;
const COOKIE_NAME: &str = "neoth_webchat";
const MAX_HANDOFFS: usize = 128;
const MAX_SESSIONS: usize = 128;
const MAX_REQUESTS: usize = 64;
const TRANSCRIPT_LIMIT: usize = 200;

#[derive(Clone)]
pub(crate) struct WebChatState {
    port: u16,
    home: Arc<PathBuf>,
    boot_id: Arc<String>,
    runtime: Arc<dyn gui::GuiChatRuntime>,
    handoffs: Arc<Mutex<HashMap<String, Handoff>>>,
    sessions: Arc<Mutex<HashMap<String, Arc<BrowserSession>>>>,
    listener_ready: Arc<AtomicBool>,
}
struct Handoff {
    session_id: String,
    expires_at: u64,
}
struct BrowserSession {
    session_id: String,
    surface_account_id: ChannelAccountId,
    expires_at: u64,
    requests: Mutex<HashMap<uuid::Uuid, Arc<Mutex<BrowserRequest>>>>,
    capacity: Arc<Semaphore>,
}
struct BrowserRequest {
    _slot: OwnedSemaphorePermit,
    preflight: gui::GuiChatPreflightResponse,
    decision: Option<(
        gui::GuiChatConsentDecision,
        gui::GuiChatConsentDecisionResponse,
    )>,
    started: Option<gui::GuiChatStartResponse>,
    terminal: bool,
    incognito: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WebChatRuntimeReadiness {
    ListenerNotReady,
    Ready,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebChatRuntimeStatus {
    pub(crate) state: WebChatRuntimeReadiness,
    pub(crate) endpoint: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebChatHandoffResponse {
    pub(crate) handoff: String,
    pub(crate) url: String,
    pub(crate) session_id: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRequest {
    handoff: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightInput {
    message: String,
    model: Option<String>,
    skill_id: Option<String>,
    incognito: bool,
    reasoning_display: bool,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestInput {
    request_id: uuid::Uuid,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideInput {
    request_id: uuid::Uuid,
    decision: gui::GuiChatConsentDecision,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachInput {
    request_id: uuid::Uuid,
    after_sequence: u64,
}

struct GatewayError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}
type GatewayResult<T> = Result<T, GatewayError>;
impl GatewayError {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }
    fn unavailable(message: &'static str) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
    }
    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Open a new WebChat session.",
        )
    }
    fn conflict(message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }
}
impl From<gui::GuiChatProtocolError> for GatewayError {
    fn from(error: gui::GuiChatProtocolError) -> Self {
        use gui::GuiChatErrorCode as Code;
        let code = match error {
            gui::GuiChatProtocolError::Invalid(_) => Code::InvalidRequest,
            gui::GuiChatProtocolError::Runtime(response) => response.code,
        };
        let (status, code, message) = match code {
            Code::ReplayGap => (
                StatusCode::CONFLICT,
                "replay_gap",
                "Response history is no longer available for replay.",
            ),
            Code::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "This request conflicts with existing turn state.",
            ),
            Code::Busy => (
                StatusCode::CONFLICT,
                "busy",
                "The chat runtime is busy. Retry this request.",
            ),
            Code::BootChanged => (
                StatusCode::CONFLICT,
                "boot_changed",
                "The daemon restarted. Open a new session.",
            ),
            Code::ConsentRequired => (
                StatusCode::FORBIDDEN,
                "consent_required",
                "This request needs a new consent decision.",
            ),
            Code::InvalidRequest | Code::AttachmentRejected => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The chat request is invalid.",
            ),
            Code::Unauthorized | Code::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "This session cannot access the requested turn.",
            ),
            Code::CancelIndeterminate => (
                StatusCode::CONFLICT,
                "cancel_indeterminate",
                "Cancellation is not confirmed. Reconnect to check the turn.",
            ),
            Code::Unavailable | Code::Internal => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "The chat runtime is unavailable.",
            ),
        };
        Self::new(status, code, message)
    }
}
impl WebChatState {
    pub(crate) fn new(
        port: u16,
        home: PathBuf,
        boot_id: String,
        runtime: Arc<dyn gui::GuiChatRuntime>,
    ) -> Self {
        Self {
            port,
            home: Arc::new(home),
            boot_id: Arc::new(boot_id),
            runtime,
            handoffs: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            listener_ready: Arc::new(AtomicBool::new(false)),
        }
    }
    pub(crate) fn set_listener_ready(&self, ready: bool) {
        self.listener_ready.store(ready, Ordering::Release);
    }

    /// Secret-free snapshot of actual listener authority; never mints a handoff.
    pub(crate) fn runtime_status(&self) -> WebChatRuntimeStatus {
        if self.listener_ready.load(Ordering::Acquire) {
            WebChatRuntimeStatus {
                state: WebChatRuntimeReadiness::Ready,
                endpoint: Some(format!("http://127.0.0.1:{}/webchat", self.port)),
            }
        } else {
            WebChatRuntimeStatus {
                state: WebChatRuntimeReadiness::ListenerNotReady,
                endpoint: None,
            }
        }
    }
    pub(crate) async fn mint_handoff(&self) -> Result<WebChatHandoffResponse, &'static str> {
        if !self.listener_ready.load(Ordering::Acquire) {
            return Err("webchat listener is not ready");
        }
        let handoff = random_opaque()?;
        let now = crate::time::now_unix_secs();
        let mut handoffs = self.handoffs.lock().await;
        handoffs.retain(|_, entry| entry.expires_at > now);
        if handoffs.len() >= MAX_HANDOFFS {
            return Err("webchat handoff capacity reached");
        }
        let session_id = uuid::Uuid::now_v7().to_string();
        handoffs.insert(
            digest_key(&handoff),
            Handoff {
                session_id: session_id.clone(),
                expires_at: now.saturating_add(HANDOFF_TTL_SECS),
            },
        );
        Ok(WebChatHandoffResponse {
            url: format!("http://127.0.0.1:{}/webchat#handoff={handoff}", self.port),
            handoff,
            session_id,
        })
    }
    pub(crate) async fn mint_resume_handoff(
        &self,
        session_id: &str,
    ) -> Result<WebChatHandoffResponse, &'static str> {
        if !self.listener_ready.load(Ordering::Acquire) {
            return Err("webchat listener is not ready");
        }
        let Ok(parsed) = uuid::Uuid::parse_str(session_id) else {
            return Err("webchat session id is invalid");
        };
        if parsed.get_version_num() != 7 || parsed.to_string() != session_id {
            return Err("webchat session id is invalid");
        }
        let home = Arc::clone(&self.home);
        let session_id = session_id.to_owned();
        let provenance_session_id = session_id.clone();
        let proven = tokio::task::spawn_blocking(move || {
            crate::daemon::gui_chat_runtime::has_webchat_default_session_provenance(
                &home,
                &provenance_session_id,
            )
        })
        .await
        .map_err(|_| "webchat provenance unavailable")?;
        if !proven {
            return Err("webchat session cannot be resumed");
        }
        self.mint_handoff_for_session(session_id).await
    }
    async fn mint_handoff_for_session(
        &self,
        session_id: String,
    ) -> Result<WebChatHandoffResponse, &'static str> {
        let handoff = random_opaque()?;
        let now = crate::time::now_unix_secs();
        let mut handoffs = self.handoffs.lock().await;
        handoffs.retain(|_, entry| entry.expires_at > now);
        if handoffs.len() >= MAX_HANDOFFS {
            return Err("webchat handoff capacity reached");
        }
        handoffs.insert(digest_key(&handoff), Handoff { session_id: session_id.clone(), expires_at: now.saturating_add(HANDOFF_TTL_SECS) });
        Ok(WebChatHandoffResponse { url: format!("http://127.0.0.1:{}/webchat#handoff={handoff}", self.port), handoff, session_id })
    }
    async fn consume_handoff(&self, handoff: &str) -> Option<String> {
        if !valid_opaque(handoff) {
            return None;
        }
        let entry = self.handoffs.lock().await.remove(&digest_key(handoff))?;
        (entry.expires_at > crate::time::now_unix_secs()).then_some(entry.session_id)
    }
    async fn session_for(&self, req: &Request<Incoming>) -> GatewayResult<Arc<BrowserSession>> {
        let raw = cookie(req, COOKIE_NAME).ok_or_else(GatewayError::unauthorized)?;
        let now = crate::time::now_unix_secs();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, entry| entry.expires_at > now);
        sessions
            .get(&digest_key(raw))
            .cloned()
            .ok_or_else(GatewayError::unauthorized)
    }
    async fn establish_session(&self, session_id: String) -> Result<String, &'static str> {
        let value = random_opaque()?;
        let now = crate::time::now_unix_secs();
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, entry| entry.expires_at > now);
        if sessions.len() >= MAX_SESSIONS {
            return Err("webchat session capacity reached");
        }
        sessions.insert(
            digest_key(&value),
            Arc::new(BrowserSession {
                session_id,
                surface_account_id: ChannelAccountId::default_account(),
                expires_at: now.saturating_add(SESSION_TTL_SECS),
                requests: Mutex::new(HashMap::new()),
                capacity: Arc::new(Semaphore::new(MAX_REQUESTS)),
            }),
        );
        Ok(value)
    }
}
impl BrowserSession {
    fn require_live(&self) -> GatewayResult<()> {
        if self.expires_at <= crate::time::now_unix_secs() {
            return Err(GatewayError::unauthorized());
        }
        Ok(())
    }
    async fn request(&self, id: uuid::Uuid) -> GatewayResult<Arc<Mutex<BrowserRequest>>> {
        self.require_live()?;
        self.requests.lock().await.get(&id).cloned().ok_or_else(|| {
            GatewayError::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "This session does not own that request.",
            )
        })
    }
}
pub(crate) async fn handle(
    req: Request<Incoming>,
    state: Arc<WebChatState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut response = match route(req, state).await {
        Ok(response) => response,
        Err(error) => json(
            error.status,
            &serde_json::json!({"code":error.code,"message":error.message}),
        ),
    };
    let headers = response.headers_mut();
    for (name, value) in [
        (hyper::header::CACHE_CONTROL, "no-store"),
        (hyper::header::REFERRER_POLICY, "no-referrer"),
        (hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (hyper::header::X_FRAME_OPTIONS, "DENY"),
        (
            hyper::header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        ),
    ] {
        headers.insert(name, hyper::header::HeaderValue::from_static(value));
    }
    Ok(response)
}
async fn route(
    req: Request<Incoming>,
    state: Arc<WebChatState>,
) -> GatewayResult<Response<Full<Bytes>>> {
    if !host_ok(&req, state.port) {
        return Err(GatewayError::new(
            StatusCode::FORBIDDEN,
            "invalid_host",
            "Invalid local host.",
        ));
    }
    if !state.listener_ready.load(Ordering::Acquire) {
        return Err(GatewayError::unavailable(
            "The WebChat listener is stopping.",
        ));
    }
    let path = req.uri().path().to_owned();
    if req.method() == Method::GET && path == "/webchat" {
        return Ok(html());
    }
    if req.headers().contains_key(hyper::header::ORIGIN) && !origin_ok(&req, state.port) {
        return Err(GatewayError::new(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "Invalid local origin.",
        ));
    }
    if req.method() == Method::GET {
        let session = state.session_for(&req).await?;
        return match path.as_str() {
            "/api/v1/webchat/session" => {
                let requests: Vec<_> = session
                    .requests
                    .lock()
                    .await
                    .iter()
                    .map(|(id, entry)| (*id, Arc::clone(entry)))
                    .collect();
                let mut active = None;
                for (id, entry) in requests {
                    let (started, stored_terminal, incognito) = {
                        let stored = entry.lock().await;
                        (stored.started.clone(), stored.terminal, stored.incognito)
                    };
                    let Some(started) = started else { continue };
                    if stored_terminal {
                        continue;
                    }
                    // `start` deliberately withholds a usable origin capability.
                    // Derive a fresh server-side attach capability from the stored
                    // same-session grant; it is never exposed by this status route.
                    let exchange = state
                        .runtime
                        .exchange_attach(gui::GuiChatAttachExchangeRequest {
                            schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                            expected_boot_id: state.boot_id.to_string(),
                            turn_id: started.turn_id.clone(),
                            session_id: session.session_id.clone(),
                            desired_surface: gui::GuiChatSurface::WebChat,
                            grant: started.same_session_attach_grant.grant,
                        })
                        .await?;
                    let runtime_status = state
                        .runtime
                        .status(gui::GuiChatStatusRequest {
                            schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                            expected_boot_id: state.boot_id.to_string(),
                            turn_id: started.turn_id.clone(),
                            session_id: session.session_id.clone(),
                            attach_capability: exchange.attach_capability,
                        })
                        .await?;
                    if runtime_status.terminal.is_some() && !incognito {
                        entry.lock().await.terminal = true;
                        continue;
                    }
                    if active.is_none_or(|current| id > current) {
                        active = Some(id);
                    }
                }
                Ok(json(
                    StatusCode::OK,
                    &serde_json::json!({"authenticated":true,"active_request_id":active}),
                ))
            }
            "/api/v1/webchat/transcript" => {
                let home = Arc::clone(&state.home);
                let session_id = session.session_id.clone();
                let rows = tokio::task::spawn_blocking(move || {
                    crate::memory::transcript_store::read_session_turns_bounded_at(
                        &home.join("views.db"),
                        &session_id,
                        TRANSCRIPT_LIMIT + 1,
                    )
                })
                .await
                .map_err(|_| GatewayError::unavailable("Transcript read failed."))?
                .map_err(|_| GatewayError::unavailable("Saved transcript is unavailable."))?;
                let truncated = rows.len() > TRANSCRIPT_LIMIT;
                let skip = rows.len().saturating_sub(TRANSCRIPT_LIMIT);
                let turns: Vec<_> = rows
                    .into_iter()
                    .skip(skip)
                    .map(|row| serde_json::json!({"role":row.role,"text":row.text}))
                    .collect();
                Ok(json(
                    StatusCode::OK,
                    &serde_json::json!({"turns":turns,"truncated":truncated}),
                ))
            }
            _ => Err(GatewayError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "Unknown WebChat route.",
            )),
        };
    }
    if req.method() != Method::POST {
        return Err(GatewayError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Unsupported request method.",
        ));
    }
    if !origin_ok(&req, state.port) {
        return Err(GatewayError::new(
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "Invalid local origin.",
        ));
    }
    if path == "/api/v1/webchat/bootstrap" {
        let input: BootstrapRequest = json_body(req).await?;
        let session_id = state
            .consume_handoff(&input.handoff)
            .await
            .ok_or_else(GatewayError::unauthorized)?;
        let value = state
            .establish_session(session_id)
            .await
            .map_err(GatewayError::unavailable)?;
        let mut response = json(StatusCode::OK, &serde_json::json!({"ok":true}));
        response.headers_mut().insert(hyper::header::SET_COOKIE, hyper::header::HeaderValue::from_str(
            &format!("{COOKIE_NAME}={value}; SameSite=Strict; HttpOnly; Path=/api/v1/webchat; Max-Age={SESSION_TTL_SECS}")
        ).map_err(|_| GatewayError::unavailable("Session cookie could not be issued."))?);
        return Ok(response);
    }
    let session = state.session_for(&req).await?;
    match path.as_str() {
        "/api/v1/webchat/preflight" => {
            let input: PreflightInput = json_body(req).await?;
            let slot = Arc::clone(&session.capacity)
                .try_acquire_owned()
                .map_err(|_| {
                    GatewayError::new(
                        StatusCode::TOO_MANY_REQUESTS,
                        "capacity",
                        "Open a new session to create more requests.",
                    )
                })?;
            let request_id = uuid::Uuid::now_v7();
            let request = gui::GuiChatPreflightRequest {
                schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                expected_boot_id: state.boot_id.to_string(),
                request_id: gui::GuiChatRequestId(request_id),
                session_id: session.session_id.clone(),
                origin_surface: gui::GuiChatSurface::WebChat,
                surface_account_id: Some(session.surface_account_id.clone()),
                message: input.message,
                model: input.model,
                skill_id: input.skill_id,
                incognito: input.incognito,
                reasoning_display: input.reasoning_display,
                attachments: Vec::new(),
            };
            gui::validate_preflight_request(&request)?;
            session.require_live()?;
            let preflight = state.runtime.preflight(request).await?;
            let consent = preflight.consent.clone();
            session.requests.lock().await.insert(
                request_id,
                Arc::new(Mutex::new(BrowserRequest {
                    _slot: slot,
                    preflight,
                    decision: None,
                    started: None,
                    terminal: false,
                    incognito: input.incognito,
                })),
            );
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({"request_id":request_id,"consent":consent}),
            ))
        }
        "/api/v1/webchat/decide" => {
            let input: DecideInput = json_body(req).await?;
            if input.decision == gui::GuiChatConsentDecision::AllowAlways {
                return Err(GatewayError::conflict(
                    "This surface supports Allow once or Deny.",
                ));
            }
            let entry = session.request(input.request_id).await?;
            // Serialize this request's transitions, never the global maps.
            let mut stored = entry.lock().await;
            session.require_live()?;
            if let Some((prior, decision)) = &stored.decision {
                if *prior != input.decision {
                    return Err(GatewayError::conflict(
                        "This consent request was already decided.",
                    ));
                }
                return Ok(decision_response(decision));
            }
            let preflight = &stored.preflight;
            let proof = match (&preflight.consent, input.decision) {
                (_, gui::GuiChatConsentDecision::Deny) => None,
                (gui::GuiChatConsentPreflightState::Ready, _) => {
                    let home = Arc::clone(&state.home);
                    let digest = preflight.preflight_descriptor_digest.0.clone();
                    let challenge = preflight.consent_challenge.0.clone();
                    let session_id = session.session_id.clone();
                    let proof = tokio::task::spawn_blocking(move || {
                        crate::cli::consent_challenge::mint_ready_request_bound_gui_chat_consent(
                            &home,
                            &digest,
                            &challenge,
                            &session_id,
                            crate::time::now_unix_secs(),
                        )
                    })
                    .await
                    .map_err(|_| GatewayError::unavailable("Consent verification failed."))?
                    .map_err(|_| {
                        GatewayError::conflict("Consent changed; prepare a new request.")
                    })?;
                    Some(gui::GuiChatConsentProof(proof.to_string()))
                }
                (gui::GuiChatConsentPreflightState::ConfirmationRequired { .. }, _) => {
                    let proof =
                        crate::cli::consent_challenge::decide_request_bound_gui_chat_consent(
                            &state.home,
                            &preflight.consent_challenge.0,
                            &preflight.preflight_descriptor_digest.0,
                            &session.session_id,
                            crate::cli::consent_challenge::ChatConsentDecision::AllowOnce,
                        )
                        .await
                        .map_err(|_| {
                            GatewayError::conflict("Consent changed; prepare a new request.")
                        })?
                        .ok_or_else(|| GatewayError::conflict("Consent was not granted."))?;
                    Some(gui::GuiChatConsentProof(proof.to_string()))
                }
            };
            let decision = state
                .runtime
                .decide(gui::GuiChatConsentDecisionRequest {
                    schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                    expected_boot_id: state.boot_id.to_string(),
                    preflight_id: preflight.preflight_id.clone(),
                    preflight_descriptor_digest: preflight.preflight_descriptor_digest.clone(),
                    consent_challenge: preflight.consent_challenge.clone(),
                    decision: input.decision,
                    consent_proof: proof,
                })
                .await?;
            let response = decision_response(&decision);
            stored.decision = Some((input.decision, decision));
            Ok(response)
        }
        "/api/v1/webchat/start" => {
            let input: RequestInput = json_body(req).await?;
            let entry = session.request(input.request_id).await?;
            let mut stored = entry.lock().await;
            session.require_live()?;
            if stored.started.is_none() {
                let Some((
                    _,
                    gui::GuiChatConsentDecisionResponse::Approved {
                        turn_intent_digest,
                        start_capability,
                        attachment_tickets,
                        ..
                    },
                )) = &stored.decision
                else {
                    return Err(GatewayError::conflict(
                        "This request has not been approved.",
                    ));
                };
                let started = state
                    .runtime
                    .start(gui::GuiChatStartRequest {
                        schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                        expected_boot_id: state.boot_id.to_string(),
                        request_id: gui::GuiChatRequestId(input.request_id),
                        session_id: session.session_id.clone(),
                        origin_surface: gui::GuiChatSurface::WebChat,
                        turn_intent_digest: turn_intent_digest.clone(),
                        start_capability: start_capability.clone(),
                        attachment_tickets: attachment_tickets.clone(),
                    })
                    .await?;
                stored.started = Some(started);
            }
            // Start retries retain the same request ID. Replay starts at zero,
            // including frames produced before the HTTP start response.
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({"request_id":input.request_id,"initial_sequence":0}),
            ))
        }
        "/api/v1/webchat/attach" => {
            let input: AttachInput = json_body(req).await?;
            let entry = session.request(input.request_id).await?;
            let started = entry
                .lock()
                .await
                .started
                .clone()
                .ok_or_else(|| GatewayError::conflict("The turn has not started."))?;
            session.require_live()?;
            let exchange = state
                .runtime
                .exchange_attach(gui::GuiChatAttachExchangeRequest {
                    schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                    expected_boot_id: state.boot_id.to_string(),
                    turn_id: started.turn_id.clone(),
                    session_id: session.session_id.clone(),
                    desired_surface: gui::GuiChatSurface::WebChat,
                    grant: started.same_session_attach_grant.grant,
                })
                .await?;
            let frames = state
                .runtime
                .replay(gui::GuiChatAttachRequest {
                    schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                    expected_boot_id: state.boot_id.to_string(),
                    turn_id: started.turn_id,
                    session_id: session.session_id.clone(),
                    surface: gui::GuiChatSurface::WebChat,
                    subscription_generation: exchange.subscription_generation,
                    attach_capability: exchange.attach_capability,
                    after_sequence: input.after_sequence,
                })
                .await?;
            if frames
                .iter()
                .any(|frame| matches!(&frame.payload, gui::GuiChatFramePayload::Terminal { .. }))
            {
                entry.lock().await.terminal = true;
            }
            let frames: Vec<_> = frames
                .into_iter()
                .map(|frame| serde_json::json!({"sequence":frame.sequence,"payload":frame.payload}))
                .collect();
            Ok(json(StatusCode::OK, &serde_json::json!({"frames":frames})))
        }
        "/api/v1/webchat/cancel" => {
            let input: RequestInput = json_body(req).await?;
            let entry = session.request(input.request_id).await?;
            let started = entry
                .lock()
                .await
                .started
                .clone()
                .ok_or_else(|| GatewayError::conflict("The turn has not started."))?;
            session.require_live()?;
            let result = state
                .runtime
                .cancel(gui::GuiChatCancelRequest {
                    schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                    expected_boot_id: state.boot_id.to_string(),
                    turn_id: started.turn_id,
                    session_id: session.session_id.clone(),
                    cancel_capability: started.cancel_capability,
                })
                .await?;
            Ok(json(StatusCode::OK, &result))
        }
        _ => Err(GatewayError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "Unknown WebChat route.",
        )),
    }
}
fn decision_response(decision: &gui::GuiChatConsentDecisionResponse) -> Response<Full<Bytes>> {
    let approved = matches!(
        decision,
        gui::GuiChatConsentDecisionResponse::Approved { .. }
    );
    json(
        StatusCode::OK,
        &serde_json::json!({"outcome":if approved { "approved" } else { "denied" }}),
    )
}
async fn json_body<T: serde::de::DeserializeOwned>(req: Request<Incoming>) -> GatewayResult<T> {
    if req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        != Some("application/json")
    {
        return Err(GatewayError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content_type",
            "A JSON request body is required.",
        ));
    }
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        Limited::new(req.into_body(), BODY_LIMIT).collect(),
    )
    .await
    .map_err(|_| {
        GatewayError::new(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "The request body timed out.",
        )
    })?
    .map_err(|_| {
        GatewayError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_limit",
            "The request body is too large or incomplete.",
        )
    })?
    .to_bytes();
    serde_json::from_slice(&bytes).map_err(|_| {
        GatewayError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid WebChat request.",
        )
    })
}
fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(value) => Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(value)))
            .expect("static response headers"),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(
                br#"{"code":"encode_failure","message":"Response unavailable."}"#,
            )))
            .expect("static response headers"),
    }
}
fn host_ok(req: &Request<Incoming>, port: u16) -> bool {
    req.headers().get_all(hyper::header::HOST).iter().count() == 1
        && req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|host| {
                host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
            })
}
fn origin_ok(req: &Request<Incoming>, port: u16) -> bool {
    host_ok(req, port)
        && req.headers().get_all(hyper::header::ORIGIN).iter().count() == 1
        && req
            .headers()
            .get(hyper::header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|origin| {
                req.headers()
                    .get(hyper::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|host| origin == format!("http://{host}"))
            })
}
fn cookie<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    let mut found = None;
    for header in req.headers().get_all(hyper::header::COOKIE) {
        for part in header.to_str().ok()?.split(';').map(str::trim) {
            if let Some((key, value)) = part.split_once('=')
                && key == name
            {
                if found.is_some() || !valid_opaque(value) {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}
fn valid_opaque(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn digest_key(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn random_opaque() -> Result<String, &'static str> {
    let mut raw = [0_u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| "OS entropy is unavailable")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}
fn html() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Full::new(Bytes::from_static(include_bytes!(
            "../../assets/webchat/index.html"
        ))))
        .expect("static response headers")
}
#[cfg(test)]
mod tests;
