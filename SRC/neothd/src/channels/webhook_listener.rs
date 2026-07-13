//! Hyper 1.x adapter for the transport-neutral `webhook_router`.
//!
//! Binds a minimal HTTP/1.1 server on `127.0.0.1:PORT`, translates
//! each incoming `hyper::Request` into the router's
//! [`WebhookRequest`] shape, dispatches via `route_meta_webhook` or
//! `route_slack_webhook`, and serialises the resulting
//! [`WebhookResponse`] back onto the wire.
//!
//! Why 127.0.0.1 only: NEOTH is operator-local. The expectation is
//! that a TLS-terminating reverse proxy (Caddy / nginx / Cloudflare
//! tunnel) sits in front and forwards verified plaintext requests to
//! this listener. Binding to 0.0.0.0 would expose the signature-verify
//! path to the public internet — fine in principle but a sharper
//! footgun than is warranted at v0.1.
//!
//! Why HTTP/1.1 only: the Meta WhatsApp Cloud + Slack Events APIs
//! both speak HTTP/1.1. No HTTP/2 multiplexing benefit on a
//! single-operator webhook (one event at a time). Smaller attack
//! surface than enabling HTTP/2.
//!
//! Per-connection lifetime is short — accept, parse, route, respond,
//! drop. The body is bounded at [`MAX_BODY_BYTES`] = 1 MiB to keep a
//! pathological POST from consuming RAM. Operators expecting larger
//! media uploads should raise it in their fork (Meta's webhook docs
//! cap inbound at 256 KiB so 1 MiB is generous).
//!
//! Pipeline contract:
//!   - GET / POST /webhook → `route_meta_webhook` → on `Verified`
//!     the body is fed into `whatsapp_webhook::decode_payload` and
//!     the resulting `InboundMessage`s passed to the operator's
//!     handler.
//!   - POST /slack/events → `route_slack_webhook` → on `Verified`
//!     the raw body is handed to the operator's handler (envelope
//!     decode is Slack-event-specific and lives downstream).
//!   - Any other path → 404.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming as IncomingBody};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Method, Request as HyperRequest, Response as HyperResponse, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use super::line_api::{DecodedLineWebhook, decode_line_payload};
use super::webhook_router::{
    HttpMethod, LineRouteOutcome, MetaRouteOutcome, SlackRouteOutcome, WebhookRequest,
    WebhookResponse, route_line_webhook, route_meta_webhook, route_slack_webhook,
};
use super::webhook_verify::SlackVerifyError;
use super::whatsapp_webhook::{DecodedWebhook, decode_payload};
use super::{ChannelKind, InboundMessage, PipelineHandler};

/// 1 MiB cap on inbound request bodies. Meta + Slack webhooks fit
/// well under this; larger uploads should go through a media endpoint.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// R2-P1-1 default concurrency ceiling (2026-05-22 Session 20).
/// A localhost-bound listener behind a reverse proxy doesn't need
/// thousands of concurrent connections — the proxy fans out long-
/// running calls. 64 lets bursty webhook delivery (Meta retries N
/// messages at once during reconnects) succeed without unbounded
/// `tokio::spawn` growth that the R2 reviewer flagged.
pub const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// R2-P1-1 shutdown drain budget. When the operator signals shutdown,
/// the listener stops accepting + waits up to this duration for in-
/// flight connections to finish their final response. After the cap
/// the remaining connections drop; the operator's reverse proxy
/// retries via its own client logic.
pub const SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// P0 — governance inputs for the outbound channel send. The daemon evaluates
/// the channel-send permission ONCE (at config build) + threads its WAL writer
/// so every WhatsApp webhook reply is gated + audited via
/// [`crate::channels::send_gate`]. `Default` is the writerless, permissive
/// posture used by tests / non-sending listeners.
pub struct SendGovernance {
    /// Daemon WAL writer for the `CHANNEL_EGRESS` / `PERMISSION_DENIED` audit.
    /// `None` ⇒ no audit is written (and a `required_audit` send fails closed).
    pub wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    /// Pre-evaluated `Action::ChannelSend` decision under the active autonomy.
    pub decision: crate::permissions::Decision,
    /// When true, a send that cannot be audited is REFUSED (fail-closed).
    pub required_audit: bool,
    /// When true, skip the real API call — emit a dry-run audit only.
    pub dry_run: bool,
}

impl Default for SendGovernance {
    fn default() -> Self {
        Self {
            wal_writer: None,
            decision: crate::permissions::Decision::Allow,
            required_audit: false,
            dry_run: false,
        }
    }
}

/// Operator-configurable settings the listener needs to do its job.
/// Cloned once into the `Arc` the per-connection service shares.
pub struct WebhookListenerConfig {
    /// Meta App Secret used to compute `X-Hub-Signature-256`.
    pub meta_app_secret: Vec<u8>,
    /// Operator's pinned `hub.verify_token` for the Meta GET handshake.
    pub meta_verify_token: String,
    /// Slack signing secret used to verify `X-Slack-Signature`.
    pub slack_signing_secret: Vec<u8>,
    /// Pipeline handler the operator's daemon passes — invoked once
    /// per `InboundMessage` decoded from a verified Meta POST. When
    /// the handler returns `Ok(Some(outbound))` AND
    /// `whatsapp_send_creds` is set below, the listener forwards the
    /// reply via `whatsapp_api::send_text_message` (GR-01 Pick B).
    /// When `whatsapp_send_creds` is `None` the listener logs-and-
    /// drops outbound replies (pre-GR-01 behaviour) — this path is
    /// reserved for non-WhatsApp listeners that mount the same
    /// handler shape.
    pub pipeline: PipelineHandler,
    /// GR-01 Pick B: WhatsApp Graph API credentials (access token +
    /// phone-number-id). When `Some`, `dispatch_messages` routes
    /// pipeline-produced replies back through `whatsapp_api::
    /// send_text_message` instead of logging+dropping them. Closes
    /// the documented gap where inbound-LIVE webhooks would call
    /// the pipeline but silently drop the reply.
    pub whatsapp_send_creds: Option<WhatsAppSendCreds>,
    /// P0 — channel-send governance (gate decision + audit writer + fail-closed
    /// flags). `Default` = writerless permissive (tests / non-sending listeners).
    pub send_governance: SendGovernance,
    /// R2-P1-1 concurrency cap. `None` → `DEFAULT_MAX_CONCURRENT_CONNECTIONS`.
    /// Operators behind a reverse proxy can raise this if their proxy
    /// fans out many concurrent webhook calls; localhost-only deploys
    /// rarely need to touch it.
    pub max_concurrent_connections: Option<usize>,
    /// COR-34: shared JoinSet that tracks the detached, DISPATCH_GATE-bounded
    /// Meta fan-out tasks (`handle_meta`). When `Some`, each dispatch is spawned
    /// INTO this set instead of fire-and-forget, so the daemon's shutdown path
    /// can drain in-flight pipeline turns (and their WAL writes) deterministically
    /// before dropping the WAL writer — replacing the accidental, possibly-hanging
    /// drain that relied on the dispatch task holding a `WalWriterHandle` clone.
    /// `None` (tests / non-Meta listeners) keeps the legacy fire-and-forget spawn.
    pub dispatch_join: Option<Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>>,
    /// GR-010: bounded seen-set for inbound wamids. When `Some`,
    /// `dispatch_messages` skips messages whose `message_id` was already
    /// processed, so a Meta reconnect-storm re-delivery never triggers a
    /// duplicate pipeline run (and duplicate outbound reply). `None` disables
    /// dedup (tests + non-WhatsApp listeners that never set `message_id`).
    pub inbound_dedup: Option<Arc<tokio::sync::Mutex<InboundDedup>>>,
    /// GOLD-FEAT-10 — LINE webhook config. When `Some`, the listener serves
    /// `POST /line/webhook`: verify the `X-Line-Signature`, decode events, and
    /// route pipeline replies back through the LINE push API (gated + audited
    /// via `send_governance`, deduped via `inbound_dedup` on the stable
    /// `webhookEventId`). `None` ⇒ the `/line/webhook` path 404s (non-LINE
    /// listeners).
    pub line: Option<LineConfig>,
}

/// GOLD-FEAT-10 — LINE credentials the webhook listener needs: the channel
/// secret (verify the inbound `X-Line-Signature`) + the long-lived channel
/// access token (push outbound replies).
pub struct LineConfig {
    /// Channel secret bytes — verifies `X-Line-Signature` (base64 HMAC-SHA256
    /// over the raw body).
    pub channel_secret: Vec<u8>,
    /// Long-lived channel access token (Bearer) for the push send API.
    pub access_token: crate::secret::SecretString,
    /// Push API base-URL override. `None` = production
    /// (`line_api::LINE_API_BASE`); tests point it at a mock server so the send
    /// path's gate contracts are machine-verified.
    pub base_url: Option<String>,
}

/// Bounded FIFO dedup ring for inbound WhatsApp message IDs (wamids). Capacity
/// covers the longest plausible Meta reconnect burst; older entries evict FIFO
/// so the set never grows unbounded (GR-010).
pub struct InboundDedup {
    ring: std::collections::VecDeque<String>,
    cap: usize,
}

impl InboundDedup {
    pub fn new(cap: usize) -> Self {
        Self {
            ring: std::collections::VecDeque::with_capacity(cap.min(4096)),
            cap: cap.max(1),
        }
    }

    /// `true` if `id` was already seen (duplicate); otherwise inserts it and
    /// returns `false`.
    pub fn check_and_insert(&mut self, id: &str) -> bool {
        if self.ring.iter().any(|s| s == id) {
            return true;
        }
        if self.ring.len() >= self.cap {
            self.ring.pop_front();
        }
        self.ring.push_back(id.to_owned());
        false
    }
}

/// GR-01 Pick B: WhatsApp credentials needed by the webhook listener
/// to send pipeline replies back out via the Meta Graph API.
pub struct WhatsAppSendCreds {
    pub access_token: crate::secret::SecretString,
    pub phone_number_id: String,
    /// Graph API base-URL override. `None` = production
    /// (`whatsapp_api::GRAPH_API_BASE`); tests point it at a wiremock server so
    /// the send path's "skips API on Deny/DryRun" contract is machine-verified.
    pub base_url: Option<String>,
}

/// Bind to `addr` and run the listener until the cancellation
/// `shutdown` future resolves. Returns the bound port (useful for
/// tests that pass `addr: 127.0.0.1:0`) on success, or an error if
/// the bind / accept loop fails.
///
/// The shutdown future is polled on every accept iteration — once it
/// resolves the listener stops accepting + the function returns. The
/// caller is responsible for draining in-flight connections (this
/// minimal listener drops them on shutdown; if the operator needs
/// graceful drain they should run this behind their own task with
/// `tokio::select!` against in-flight tracking).
pub async fn serve(
    addr: SocketAddr,
    config: WebhookListenerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<u16> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind webhook listener to {addr}"))?;
    let local = listener.local_addr().context("read local addr")?;
    let concurrency = config
        .max_concurrent_connections
        .unwrap_or(DEFAULT_MAX_CONCURRENT_CONNECTIONS)
        .max(1);
    info!(
        addr = %local,
        max_concurrent = concurrency,
        "webhook listener bound — 127.0.0.1 only, terminate TLS at your reverse proxy"
    );
    let config = Arc::new(config);
    // R2-P1-1: semaphore caps concurrent connections + in-flight
    // AtomicUsize counter feeds the `/metrics` doctor surface (the
    // operator's runtime visibility into how close the listener is
    // to the cap).
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let join_set: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>> =
        Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));

    let mut shutdown = Box::pin(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("webhook listener received shutdown — draining in-flight connections");
                // R2-P1-1 bounded drain: wait up to SHUTDOWN_DRAIN_TIMEOUT
                // for tasks to finish their final response. Anything
                // still in flight after that is dropped — operator's
                // reverse proxy retries via its own client.
                let drain = async {
                    let mut js = join_set.lock().await;
                    while js.join_next().await.is_some() {}
                };
                if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, drain).await.is_err() {
                    warn!(
                        timeout_ms = SHUTDOWN_DRAIN_TIMEOUT.as_millis() as u64,
                        in_flight = in_flight.load(std::sync::atomic::Ordering::Relaxed),
                        "webhook drain timed out — abandoning remaining connections"
                    );
                }
                return Ok(local.port());
            }
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(p) => p,
                    Err(e) => {
                        error!(error = %e, "webhook listener accept failed");
                        continue;
                    }
                };
                // R2-P1-1: try_acquire — when the semaphore is at
                // capacity, return 429 immediately + drop the
                // connection. Unbounded `tokio::spawn` (pre-fix) was
                // the path that let a webhook fanout storm pin the
                // daemon's task pool.
                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(
                            peer = %peer,
                            cap = concurrency,
                            "webhook concurrency cap reached — responding 429 + dropping"
                        );
                        let io = TokioIo::new(stream);
                        let svc = ConcurrencyExceededService;
                        // Spawn the rejection write OUTSIDE the semaphore
                        // so it can't itself wedge the pool. Best-effort:
                        // the 429 may not flush on slow clients; the
                        // operator's reverse proxy treats either path
                        // (429 received OR connection reset) as backpressure.
                        tokio::spawn(async move {
                            let _ = http1::Builder::new().serve_connection(io, svc).await;
                        });
                        continue;
                    }
                };
                in_flight.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let io = TokioIo::new(stream);
                let svc = WebhookService { config: Arc::clone(&config) };
                let in_flight_for_task = Arc::clone(&in_flight);
                {
                    let mut js = join_set.lock().await;
                    js.spawn(async move {
                        let _permit_guard = permit; // hold for the connection's lifetime
                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, svc)
                            .await
                        {
                            debug!(error = %e, peer = %peer, "connection ended");
                        }
                        in_flight_for_task.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    });
                }
            }
        }
    }
}

/// R2-P1-1 service that returns `429 Too Many Requests` immediately +
/// closes. Used when the listener's concurrency cap is at capacity so
/// the client (operator's reverse proxy / direct Meta retry path)
/// learns to back off instead of seeing a connection reset.
#[derive(Clone)]
struct ConcurrencyExceededService;

impl Service<HyperRequest<IncomingBody>> for ConcurrencyExceededService {
    type Response = HyperResponse<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn call(&self, _req: HyperRequest<IncomingBody>) -> Self::Future {
        Box::pin(async move {
            Ok(plain_response(
                StatusCode::TOO_MANY_REQUESTS,
                "webhook listener at concurrency cap; retry after backoff",
            ))
        })
    }
}

#[derive(Clone)]
struct WebhookService {
    config: Arc<WebhookListenerConfig>,
}

impl Service<HyperRequest<IncomingBody>> for WebhookService {
    type Response = HyperResponse<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn call(&self, req: HyperRequest<IncomingBody>) -> Self::Future {
        let cfg = Arc::clone(&self.config);
        Box::pin(async move {
            let response = match handle_request(cfg, req).await {
                Ok(r) => r,
                Err(HandleError::BodyTooLarge { cap }) => {
                    // R2-P1-1: distinct 413 instead of generic 500 so
                    // the operator's reverse proxy + the upstream
                    // webhook sender both see "payload too large" as
                    // a structured signal instead of "broken server".
                    warn!(
                        cap_bytes = cap,
                        "webhook body exceeded MAX_BODY_BYTES — responding 413"
                    );
                    plain_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "request body exceeds webhook body cap (1 MiB)",
                    )
                }
                Err(HandleError::Other(e)) => {
                    error!(error = %e, "webhook listener handler error");
                    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                }
            };
            Ok(response)
        })
    }
}

/// R2-P1-1 structured error so the service layer can map "body too
/// large" to 413 instead of bucketing every translate failure as 500.
/// Other handler errors stay generic — operator reads the trace log
/// for the actual cause.
enum HandleError {
    BodyTooLarge { cap: usize },
    Other(anyhow::Error),
}

impl From<anyhow::Error> for HandleError {
    fn from(e: anyhow::Error) -> Self {
        HandleError::Other(e)
    }
}

async fn handle_request(
    cfg: Arc<WebhookListenerConfig>,
    req: HyperRequest<IncomingBody>,
) -> std::result::Result<HyperResponse<Full<Bytes>>, HandleError> {
    let path = req.uri().path().to_string();
    let webhook_req = translate(req).await?;
    match path.as_str() {
        // GOLD-COR-08: handle_meta takes the Arc by value so it can clone it
        // into the detached, bounded dispatch task.
        "/webhook" => handle_meta(cfg, webhook_req)
            .await
            .map_err(HandleError::Other),
        "/slack/events" => handle_slack(&cfg, webhook_req)
            .await
            .map_err(HandleError::Other),
        // GOLD-FEAT-10: LINE pushes its event batch here. handle_line takes the
        // Arc by value so it can clone it into the detached dispatch task.
        "/line/webhook" => handle_line(cfg, webhook_req)
            .await
            .map_err(HandleError::Other),
        _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found")),
    }
}

/// GOLD-COR-08 / A-12: upper bound on concurrently-EXECUTING webhook pipeline
/// dispatches. Now that `handle_meta` ACKs Meta with 200 BEFORE running the LLM
/// pipeline (so a slow turn can't trip Meta's retry → duplicate processing),
/// the dispatch runs in a detached task and no longer holds the connection
/// semaphore permit.
///
/// GR-012 — accuracy: this gate bounds how many dispatches RUN at once
/// (`acquire().await` is inside the spawned task), NOT how many tasks are
/// spawned. Under a fan-out storm, tasks are still spawned and queue on the
/// permit; each is lightweight (a future awaiting a permit) and Meta
/// rate-limits inbound, so the spawned-but-waiting set stays small in practice.
/// Acquiring BEFORE the spawn (to bound the spawn COUNT) is deliberately NOT
/// done: the 200 is already returned below regardless, so dropping an
/// over-the-cap webhook would silently LOSE it (Meta does not redeliver an
/// ACKed message). Queue-on-gate is the lesser evil. Generous default — far
/// above any real inbound rate, well below resource exhaustion. (Graceful
/// shutdown-drain of these detached tasks is tracked by GOLD-COR-34.)
const DISPATCH_CONCURRENCY: usize = 64;
static DISPATCH_GATE: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(DISPATCH_CONCURRENCY);

async fn handle_meta(
    cfg: Arc<WebhookListenerConfig>,
    req: WebhookRequest,
) -> Result<HyperResponse<Full<Bytes>>> {
    let (resp, outcome) = route_meta_webhook(&req, &cfg.meta_app_secret, &cfg.meta_verify_token);
    match outcome {
        MetaRouteOutcome::HandshakeAccepted { .. } => {
            info!("Meta handshake accepted");
        }
        MetaRouteOutcome::HandshakeRejected { ref reason } => {
            warn!(reason = %reason, "Meta handshake rejected");
        }
        MetaRouteOutcome::SignatureMissing | MetaRouteOutcome::SignatureMismatch => {
            warn!("Meta POST signature failed verification");
        }
        MetaRouteOutcome::BodyNotUtf8 => {
            warn!("Meta POST body not utf-8");
        }
        MetaRouteOutcome::UnsupportedMethod => {
            debug!("Meta endpoint received non-GET/POST");
        }
        MetaRouteOutcome::Verified { ref raw_body } => {
            // Verified — decode + fan out via the operator's
            // pipeline handler. We DON'T await replies here; the
            // pipeline owns its own outbound path.
            match decode_payload(raw_body) {
                DecodedWebhook::Messages(msgs) => {
                    // GOLD-COR-08 / A-12: do NOT await the pipeline here — that
                    // would delay the 200 until the LLM turn finished, and Meta
                    // retries a webhook it didn't see ACKed in time, re-running
                    // the whole pipeline + double-sending the reply. Hand the
                    // fan-out to a detached, DISPATCH_GATE-bounded task and let
                    // `resp` (200) return immediately below.
                    //
                    // GR-012b: spool the verified body to disk BEFORE the detached
                    // dispatch. A crash between the 200 ACK and the dispatch's
                    // first WAL write would otherwise LOSE the message (Meta won't
                    // redeliver an ACKed webhook). The dispatch deletes the spool
                    // file on completion; a survivor is re-dispatched on next boot.
                    let spool_key = msgs
                        .first()
                        .and_then(|m| m.message_id.clone())
                        .unwrap_or_else(|| {
                            format!("{:016x}", xxhash_rust::xxh3::xxh3_64(raw_body.as_bytes()))
                        });
                    let spool_path = spool_inbound_body(&spool_key, raw_body, "meta");
                    let cfg2 = Arc::clone(&cfg);
                    let dispatch = async move {
                        match DISPATCH_GATE.acquire().await {
                            Ok(_permit) => dispatch_messages(&cfg2, msgs).await,
                            Err(_) => {
                                warn!("webhook dispatch gate closed — dropping fan-out")
                            }
                        }
                        // GR-012b — processed (or gate-dropped): the message is no
                        // longer at risk → delete its spool entry.
                        if let Some(p) = spool_path {
                            let _ = std::fs::remove_file(&p);
                        }
                    };
                    // COR-34: when the daemon wired a shared JoinSet, track the
                    // dispatch task in it so shutdown can drain in-flight pipeline
                    // turns (+ their WAL frames) deterministically. Otherwise keep
                    // the legacy detached spawn.
                    match cfg.dispatch_join.as_ref() {
                        Some(join) => {
                            let mut js = join.lock().await;
                            js.spawn(dispatch);
                            // GOLD-COR-34 — reap COMPLETED fan-out tasks now (the
                            // non-blocking try_join_next under the lock we already
                            // hold). Without this the shared JoinSet only shed
                            // entries at shutdown, so finished handles accumulated
                            // unbounded over the daemon's lifetime — one per Meta
                            // webhook fan-out. This bounds it to the in-flight set.
                            while js.try_join_next().is_some() {}
                        }
                        None => {
                            tokio::spawn(dispatch);
                        }
                    }
                }
                DecodedWebhook::NoMessages { reason } => {
                    debug!(reason = %reason, "Meta payload had no processable messages");
                }
                DecodedWebhook::ParseError { reason } => {
                    warn!(reason = %reason, "Meta payload parse error after verify");
                }
            }
        }
    }
    Ok(webhook_to_hyper(resp))
}

async fn handle_slack(
    cfg: &WebhookListenerConfig,
    req: WebhookRequest,
) -> Result<HyperResponse<Full<Bytes>>> {
    let now = crate::time::now_unix_i64();
    let (resp, outcome) = route_slack_webhook(&req, &cfg.slack_signing_secret, now);
    match outcome {
        SlackRouteOutcome::UrlVerification { .. } => {
            info!("Slack url_verification handshake completed");
        }
        SlackRouteOutcome::Verified { raw_body: _ } => {
            // Slack envelope decode is event-specific (event_callback,
            // app_rate_limited, …) and lives in the Slack adapter.
            // The listener returns 200 here; the adapter consumes
            // the raw body via its own integration in a follow-up.
            debug!("Slack event verified — envelope decode owned by adapter");
        }
        SlackRouteOutcome::HeaderMissing { name } => {
            warn!(name = name, "Slack request missing required header");
        }
        SlackRouteOutcome::Rejected { ref error } => {
            warn!(error = %error, "Slack signature verification failed");
            // Avoid `unused` lint when SlackVerifyError gains variants.
            let _: &SlackVerifyError = error;
        }
        SlackRouteOutcome::BodyNotUtf8 => warn!("Slack POST body not utf-8"),
        SlackRouteOutcome::UnsupportedMethod => debug!("Slack endpoint received non-POST"),
    }
    Ok(webhook_to_hyper(resp))
}

/// GOLD-FEAT-10 — LINE webhook handler. Verifies the `X-Line-Signature`, decodes
/// the event batch, and — exactly like `handle_meta` — ACKs 200 immediately and
/// runs the pipeline fan-out in a detached, `DISPATCH_GATE`-bounded task so a
/// slow LLM turn can't trip LINE's webhook timeout (which would make LINE
/// re-deliver and double-process). A listener with no `line` config 404s the
/// path.
async fn handle_line(
    cfg: Arc<WebhookListenerConfig>,
    req: WebhookRequest,
) -> Result<HyperResponse<Full<Bytes>>> {
    let Some(line) = cfg.line.as_ref() else {
        return Ok(plain_response(StatusCode::NOT_FOUND, "not found"));
    };
    let (resp, outcome) = route_line_webhook(&req, &line.channel_secret);
    match outcome {
        LineRouteOutcome::SignatureMissing | LineRouteOutcome::SignatureMismatch => {
            warn!("LINE POST signature failed verification");
        }
        LineRouteOutcome::BodyNotUtf8 => {
            warn!("LINE POST body not utf-8");
        }
        LineRouteOutcome::UnsupportedMethod => {
            debug!("LINE endpoint received non-POST");
        }
        LineRouteOutcome::Verified { ref raw_body } => match decode_line_payload(raw_body) {
            DecodedLineWebhook::Messages(msgs) => {
                // GR-012b — spool the verified LINE body before the detached
                // dispatch (same crash-loss window as Meta); deleted on
                // completion, re-dispatched on next boot via the "line" decoder.
                let spool_key = msgs
                    .first()
                    .and_then(|m| m.message_id.clone())
                    .unwrap_or_else(|| {
                        format!("{:016x}", xxhash_rust::xxh3::xxh3_64(raw_body.as_bytes()))
                    });
                let spool_path = spool_inbound_body(&spool_key, raw_body, "line");
                let cfg2 = Arc::clone(&cfg);
                let dispatch = async move {
                    match DISPATCH_GATE.acquire().await {
                        Ok(_permit) => dispatch_line_messages(&cfg2, msgs).await,
                        Err(_) => {
                            warn!("webhook dispatch gate closed — dropping LINE fan-out")
                        }
                    }
                    if let Some(p) = spool_path {
                        let _ = std::fs::remove_file(&p);
                    }
                };
                match cfg.dispatch_join.as_ref() {
                    Some(join) => {
                        let mut js = join.lock().await;
                        js.spawn(dispatch);
                        while js.try_join_next().is_some() {}
                    }
                    None => {
                        tokio::spawn(dispatch);
                    }
                }
            }
            DecodedLineWebhook::NoMessages { reason } => {
                debug!(reason = %reason, "LINE payload had no actionable messages");
            }
            DecodedLineWebhook::ParseError { reason } => {
                warn!(reason = %reason, "LINE payload parse error after verify");
            }
        },
    }
    Ok(webhook_to_hyper(resp))
}

/// GOLD-ARCH-12: append a channel-send audit frame + log on write failure.
/// Centralises the `make_header` + `append` + failure-log shape that every
/// send-gate verdict arm in [`dispatch_messages`] repeated. `critical = true`
/// logs at `error!` (a broken audit chain for an action that ALREADY happened —
/// e.g. a delivered send); `false` logs at `warn!`. The per-verdict payload is
/// built by the caller; this owns only the emit + error handling.
async fn append_audit(
    w: &crate::wal::writer::WalWriterHandle,
    event_type: u8,
    payload: Vec<u8>,
    critical: bool,
    fail_msg: &str,
) {
    let h = crate::wal::make_header(event_type, &payload);
    if let Err(e) = w.append(h, payload).await {
        if critical {
            error!(error = %e, "{fail_msg}");
        } else {
            warn!(error = %e, "{fail_msg}");
        }
    }
}

/// GR-012b — durable inbound spool dir (`~/.neoth/inbound_spool/`). A Meta
/// webhook is ACKed 200 immediately + dispatched in a DETACHED task, so a crash
/// between the ACK and the dispatch's first WAL write would LOSE the message
/// (Meta won't redeliver an ACKed webhook). Each verified body is spooled here
/// BEFORE the detached dispatch, deleted on successful completion, and any
/// survivor is re-dispatched on the next daemon start ([`drain_inbound_spool`]).
fn inbound_spool_dir() -> std::path::PathBuf {
    inbound_spool_dir_at(&crate::config::FreedomConfig::default_neoth_home())
}

fn inbound_spool_dir_at(home: &std::path::Path) -> std::path::PathBuf {
    home.join("inbound_spool")
}

/// Spool the verified webhook body BEFORE its detached dispatch. `key` is the
/// message id (wamid) when available — idempotent across Meta retries — else a
/// content hash. Returns the spool path so the dispatch can delete it on
/// success. Best-effort: a spool error logs + returns `None` (the dispatch still
/// runs; durability is simply off for that one message).
fn spool_inbound_body(key: &str, raw_body: &str, decoder: &str) -> Option<std::path::PathBuf> {
    let dir = inbound_spool_dir();
    spool_inbound_body_at(&dir, key, raw_body, decoder)
}

fn spool_inbound_body_at(
    dir: &std::path::Path,
    key: &str,
    raw_body: &str,
    decoder: &str,
) -> Option<std::path::PathBuf> {
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!(error = %e, "inbound spool: mkdir failed (durability off for this message)");
        return None;
    }
    // Prefix the on-disk name with the decoder so two providers can't collide on
    // the same id-derived key.
    let safe: String = format!("{decoder}-{key}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(96)
        .collect();
    let safe = if safe.is_empty() {
        "msg".to_string()
    } else {
        safe
    };
    let path = dir.join(format!("{safe}.json"));
    let body = serde_json::json!({
        "raw_body": raw_body,
        "decoder": decoder,
        "ts_unix": crate::time::now_unix_i64(),
    })
    .to_string();
    match crate::util::atomic_write::atomic_write(&path, body.as_bytes()) {
        Ok(()) => Some(path),
        Err(e) => {
            warn!(error = %e, "inbound spool: write failed (durability off for this message)");
            None
        }
    }
}

/// GR-012b — drain leftover spooled inbound webhooks on daemon startup. Each
/// survivor is a webhook that Meta saw ACKed but whose dispatch did not provably
/// complete before a crash. Re-decode + re-dispatch + delete (the in-memory
/// GR-010 dedup ring is empty after a restart, so this is recovery, not a
/// duplicate). Best-effort throughout — a bad spool file is dropped, never fatal.
pub(crate) async fn drain_inbound_spool(cfg: &WebhookListenerConfig) {
    let dir = inbound_spool_dir();
    drain_inbound_spool_at(cfg, &dir).await;
}

async fn drain_inbound_spool_at(cfg: &WebhookListenerConfig, dir: &std::path::Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(error = %e, "inbound spool: read_dir failed on startup drain");
            return;
        }
    };
    let mut drained = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        let parsed = serde_json::from_str::<serde_json::Value>(&body).ok();
        let raw = parsed.as_ref().and_then(|v| {
            v.get("raw_body")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        });
        // Decoder tag picks the re-decode path; default "meta" (back-compat with
        // any pre-tag spool file).
        let decoder = parsed
            .as_ref()
            .and_then(|v| v.get("decoder").and_then(|x| x.as_str()))
            .unwrap_or("meta")
            .to_string();
        match raw {
            Some(raw) => {
                match decoder.as_str() {
                    "line" => {
                        if let DecodedLineWebhook::Messages(msgs) = decode_line_payload(&raw) {
                            dispatch_line_messages(cfg, msgs).await;
                            drained += 1;
                        }
                    }
                    _ => {
                        if let DecodedWebhook::Messages(msgs) = decode_payload(&raw) {
                            dispatch_messages(cfg, msgs).await;
                            drained += 1;
                        }
                    }
                }
                let _ = std::fs::remove_file(&path);
            }
            // Corrupt / unexpected shape → drop it so it can't wedge every boot.
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    if drained > 0 {
        info!(
            count = drained,
            "inbound spool: re-dispatched survivors on startup"
        );
    }
}

async fn dispatch_messages(cfg: &WebhookListenerConfig, msgs: Vec<InboundMessage>) {
    for msg in msgs {
        // GR-010: skip duplicate wamids — a Meta reconnect-storm re-delivers the
        // same message_id, and without this every re-delivery would re-run the
        // whole pipeline (and re-send the reply when send creds are wired).
        if let (Some(dedup), Some(mid)) = (cfg.inbound_dedup.as_ref(), msg.message_id.as_deref()) {
            if dedup.lock().await.check_and_insert(mid) {
                debug!(
                    message_id = mid,
                    "webhook: duplicate wamid — skipping re-delivery"
                );
                continue;
            }
        }
        let chat_id = msg.chat_id.clone();
        match (cfg.pipeline)(msg).await {
            Ok(Some(outbound)) => {
                // PII guard: the recipient id is a phone number for WhatsApp.
                // Hash it once for the tracing lines below — the WAL helpers
                // hash internally, but tracing is a parallel persistent sink
                // (journald / OTLP / log files) not covered by that hash.
                let recipient_hash = format!(
                    "{:016x}",
                    xxhash_rust::xxh3::xxh3_64(outbound.recipient_id.as_bytes())
                );
                // GR-01 Pick B: route pipeline-produced replies back
                // through the WhatsApp Graph API when the listener
                // was wired with send credentials. Pre-GR-01 this
                // arm logged-and-dropped (the operator-pipeline was
                // supposed to own send), which silently broke the
                // inbound→reply loop in webhook mode.
                if let Some(creds) = cfg.whatsapp_send_creds.as_ref() {
                    // P0 — every WhatsApp webhook reply is a real external
                    // mutation: gate it (a Deny blocks + audits), honour
                    // required-audit fail-closed + dry-run, and audit every send
                    // metadata-only (recipient + body HASHED — never the phone
                    // number / text in the clear).
                    use crate::channels::send_gate::{self, ChannelSendVerdict};
                    let gov = &cfg.send_governance;
                    let now = crate::time::now_unix_secs();
                    let verdict = send_gate::decide_channel_send(
                        &gov.decision,
                        gov.dry_run,
                        // `is_some()` would pass a Some-but-crashed writer; probe
                        // liveness so required_audit fails closed on a dead sink.
                        gov.wal_writer.as_ref().is_some_and(|w| w.is_alive()),
                        gov.required_audit,
                    );
                    match verdict {
                        ChannelSendVerdict::Denied(reason) => {
                            if let Some(w) = gov.wal_writer.as_ref() {
                                let p = send_gate::channel_send_denied_payload(
                                    "whatsapp",
                                    &outbound.recipient_id,
                                    &reason,
                                    now,
                                );
                                append_audit(
                                    w,
                                    crate::wal::events::EVENT_TYPE_CHANNEL_SEND_DENIED,
                                    p,
                                    false,
                                    "WAL write failed for channel-send denial audit frame",
                                )
                                .await;
                            }
                            warn!(
                                recipient_hash = %recipient_hash,
                                reason = %reason,
                                "P0: WhatsApp send DENIED by channel-send gate",
                            );
                        }
                        ChannelSendVerdict::RefusedNoAudit => {
                            warn!(
                                recipient_hash = %recipient_hash,
                                "P0: WhatsApp send REFUSED — required-audit on but no writable audit sink (fail-closed)",
                            );
                        }
                        ChannelSendVerdict::DryRun => {
                            if let Some(w) = gov.wal_writer.as_ref() {
                                let p = send_gate::channel_egress_payload(
                                    "whatsapp",
                                    &outbound.recipient_id,
                                    &outbound.text,
                                    None,
                                    true,
                                    false,
                                    now,
                                );
                                append_audit(
                                    w,
                                    crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                                    p,
                                    false,
                                    "WAL write failed for dry-run channel-send audit frame",
                                )
                                .await;
                            }
                            debug!(
                                recipient_hash = %recipient_hash,
                                "P0: WhatsApp send DRY-RUN (audited, not sent)",
                            );
                        }
                        ChannelSendVerdict::Send => {
                            let send = crate::channels::whatsapp_api::send_text_message_at(
                                creds
                                    .base_url
                                    .as_deref()
                                    .unwrap_or(crate::channels::whatsapp_api::GRAPH_API_BASE),
                                &creds.access_token,
                                &creds.phone_number_id,
                                &outbound.recipient_id,
                                &outbound.text,
                            )
                            .await;
                            match send {
                                Ok(r) if r.ok => {
                                    // Mandatory audit frame. The Graph API send at
                                    // the top of this arm already happened and
                                    // cannot be undone, so a WAL-write failure here
                                    // means the audit chain is broken for a REAL
                                    // egress — surface it at ERROR, never silently.
                                    if let Some(w) = gov.wal_writer.as_ref() {
                                        let p = send_gate::channel_egress_payload(
                                            "whatsapp",
                                            &outbound.recipient_id,
                                            &outbound.text,
                                            r.message_id.as_deref(),
                                            false,
                                            // confirm_degraded: records a Strict
                                            // Confirm that reached send (dead path
                                            // under the standard pipeline gate).
                                            matches!(
                                                gov.decision,
                                                crate::permissions::Decision::Confirm(_)
                                            ),
                                            now,
                                        );
                                        append_audit(
                                            w,
                                            crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                                            p,
                                            true,
                                            "required-audit WAL write failed AFTER send — audit chain broken for a delivered channel-send",
                                        )
                                        .await;
                                    }
                                    debug!(
                                        recipient_hash = %recipient_hash,
                                        wamid = ?r.message_id,
                                        "GR-01 Pick B: webhook reply delivered via Graph API",
                                    );
                                }
                                Ok(r) => {
                                    // Audit the FAILED attempt too — a Meta API
                                    // rejection must leave a durable trace, not
                                    // an indistinguishable WAL gap.
                                    if let Some(w) = gov.wal_writer.as_ref() {
                                        let p = send_gate::channel_egress_failed_payload(
                                            "whatsapp",
                                            &outbound.recipient_id,
                                            "meta_api_error",
                                            now,
                                        );
                                        append_audit(
                                            w,
                                            crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                                            p,
                                            false,
                                            "WAL write failed for Meta-API-error channel-send audit frame",
                                        )
                                        .await;
                                    }
                                    warn!(
                                        recipient_hash = %recipient_hash,
                                        error = ?r.error,
                                        "GR-01 Pick B: webhook reply failed (Meta API error)",
                                    );
                                }
                                Err(e) => {
                                    // Transport failure: same durable-trace rule.
                                    if let Some(w) = gov.wal_writer.as_ref() {
                                        let p = send_gate::channel_egress_failed_payload(
                                            "whatsapp",
                                            &outbound.recipient_id,
                                            "transport_error",
                                            now,
                                        );
                                        append_audit(
                                            w,
                                            crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                                            p,
                                            false,
                                            "WAL write failed for transport-error channel-send audit frame",
                                        )
                                        .await;
                                    }
                                    warn!(
                                        recipient_hash = %recipient_hash,
                                        error = %e,
                                        "GR-01 Pick B: webhook reply failed (transport)",
                                    );
                                }
                            }
                        }
                    }
                } else {
                    debug!(
                        recipient_hash = %recipient_hash,
                        "pipeline produced outbound but listener has no send creds — dropping (configure whatsapp_send_creds to wire send)"
                    );
                }
            }
            Ok(None) => {
                debug!(chat_id = %chat_id, "pipeline returned no outbound");
            }
            Err(e) => {
                warn!(error = %e, chat_id = %chat_id, "pipeline handler errored");
            }
        }
    }
    let _ = ChannelKind::WhatsAppBusiness; // silence unused-import lint until adapter wires here
}

/// GOLD-FEAT-10 — LINE fan-out: for each decoded inbound message run the
/// pipeline, then route any reply back through the LINE push API. Mirrors
/// `dispatch_messages` (the WhatsApp path): the SAME `send_gate` governance
/// gates + audits every reply (Deny → audit + skip; required-audit fail-closed;
/// dry-run audits without sending), the recipient + body are HASHED in every
/// WAL frame, and `inbound_dedup` skips a redelivered `webhookEventId` before it
/// re-runs the pipeline.
async fn dispatch_line_messages(cfg: &WebhookListenerConfig, msgs: Vec<InboundMessage>) {
    let Some(line) = cfg.line.as_ref() else {
        return; // handle_line guards Some; keep the fan-out total for safety
    };
    let base_url = line
        .base_url
        .as_deref()
        .unwrap_or(crate::channels::line_api::LINE_API_BASE);
    // One shared HTTP client for the whole batch's push sends.
    let http = match crate::providers::http_client::build_client() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "LINE dispatch: could not build HTTP client — dropping batch");
            return;
        }
    };
    for msg in msgs {
        // LINE re-delivers the SAME webhookEventId (carried as message_id); skip
        // a duplicate before it re-runs the pipeline (+ re-sends the reply).
        if let (Some(dedup), Some(mid)) = (cfg.inbound_dedup.as_ref(), msg.message_id.as_deref()) {
            if dedup.lock().await.check_and_insert(mid) {
                debug!(
                    message_id = mid,
                    "LINE webhook: duplicate event — skipping redelivery"
                );
                continue;
            }
        }
        let chat_id = msg.chat_id.clone();
        match (cfg.pipeline)(msg).await {
            Ok(Some(outbound)) => {
                use crate::channels::send_gate::{self, ChannelSendVerdict};
                // LINE recipient ids (userId/groupId/roomId) are PII — hash for
                // the tracing sink (the WAL helpers hash internally).
                let recipient_hash = format!(
                    "{:016x}",
                    xxhash_rust::xxh3::xxh3_64(outbound.recipient_id.as_bytes())
                );
                let gov = &cfg.send_governance;
                let now = crate::time::now_unix_secs();
                let verdict = send_gate::decide_channel_send(
                    &gov.decision,
                    gov.dry_run,
                    gov.wal_writer.as_ref().is_some_and(|w| w.is_alive()),
                    gov.required_audit,
                );
                match verdict {
                    ChannelSendVerdict::Denied(reason) => {
                        if let Some(w) = gov.wal_writer.as_ref() {
                            let p = send_gate::channel_send_denied_payload(
                                "line",
                                &outbound.recipient_id,
                                &reason,
                                now,
                            );
                            append_audit(
                                w,
                                crate::wal::events::EVENT_TYPE_CHANNEL_SEND_DENIED,
                                p,
                                false,
                                "WAL write failed for LINE channel-send denial audit frame",
                            )
                            .await;
                        }
                        warn!(
                            recipient_hash = %recipient_hash,
                            reason = %reason,
                            "P0: LINE send DENIED by channel-send gate",
                        );
                    }
                    ChannelSendVerdict::RefusedNoAudit => {
                        warn!(
                            recipient_hash = %recipient_hash,
                            "P0: LINE send REFUSED — required-audit on but no writable audit sink (fail-closed)",
                        );
                    }
                    ChannelSendVerdict::DryRun => {
                        if let Some(w) = gov.wal_writer.as_ref() {
                            let p = send_gate::channel_egress_payload(
                                "line",
                                &outbound.recipient_id,
                                &outbound.text,
                                None,
                                true,
                                false,
                                now,
                            );
                            append_audit(
                                w,
                                crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                                p,
                                false,
                                "WAL write failed for LINE dry-run channel-send audit frame",
                            )
                            .await;
                        }
                        debug!(
                            recipient_hash = %recipient_hash,
                            "P0: LINE send DRY-RUN (audited, not sent)",
                        );
                    }
                    ChannelSendVerdict::Send => {
                        let send = crate::channels::line_api::send_line_push(
                            &http,
                            base_url,
                            &line.access_token,
                            &outbound.recipient_id,
                            &outbound.text,
                        )
                        .await;
                        match send {
                            Ok(id) => {
                                if let Some(w) = gov.wal_writer.as_ref() {
                                    let p = send_gate::channel_egress_payload(
                                        "line",
                                        &outbound.recipient_id,
                                        &outbound.text,
                                        Some(&id.0),
                                        false,
                                        matches!(
                                            gov.decision,
                                            crate::permissions::Decision::Confirm(_)
                                        ),
                                        now,
                                    );
                                    append_audit(
                                        w,
                                        crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                                        p,
                                        true,
                                        "required-audit WAL write failed AFTER send — audit chain broken for a delivered LINE channel-send",
                                    )
                                    .await;
                                }
                                debug!(
                                    recipient_hash = %recipient_hash,
                                    message_id = %id.0,
                                    "GOLD-FEAT-10: LINE webhook reply delivered via push API",
                                );
                            }
                            Err(e) => {
                                // Distinguish the failure class in the audit
                                // frame (mirrors the WhatsApp meta_api/transport
                                // split) so the operator can tell a bad token /
                                // rate-limit from a TCP failure in the WAL alone.
                                let error_kind = match &e {
                                    crate::channels::ChannelError::Auth(_) => "line_auth_error",
                                    crate::channels::ChannelError::RateLimited { .. } => {
                                        "line_rate_limited"
                                    }
                                    _ => "line_transport_error",
                                };
                                if let Some(w) = gov.wal_writer.as_ref() {
                                    let p = send_gate::channel_egress_failed_payload(
                                        "line",
                                        &outbound.recipient_id,
                                        error_kind,
                                        now,
                                    );
                                    append_audit(
                                        w,
                                        crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                                        p,
                                        false,
                                        "WAL write failed for LINE push-error channel-send audit frame",
                                    )
                                    .await;
                                }
                                warn!(
                                    recipient_hash = %recipient_hash,
                                    error = %e,
                                    "GOLD-FEAT-10: LINE webhook reply failed (push API)",
                                );
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                debug!(chat_id = %chat_id, "LINE pipeline returned no outbound");
            }
            Err(e) => {
                warn!(error = %e, chat_id = %chat_id, "LINE pipeline handler errored");
            }
        }
    }
}

async fn translate(
    req: HyperRequest<IncomingBody>,
) -> std::result::Result<WebhookRequest, HandleError> {
    let method = match *req.method() {
        Method::GET => HttpMethod::Get,
        Method::POST => HttpMethod::Post,
        _ => HttpMethod::Other,
    };
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let mut headers_lc = std::collections::HashMap::new();
    for (k, v) in req.headers() {
        if let Ok(value) = v.to_str() {
            headers_lc.insert(k.as_str().to_ascii_lowercase(), value.to_string());
        }
    }
    // Security fix (Agent 2 audit 2026-05-16): bound the body BEFORE
    // it lands in memory. The previous `into_body().collect()` path
    // buffered the whole HTTP body first and only enforced the cap
    // afterwards — a single `Content-Length: 10737418240` POST would
    // OOM the daemon before the post-read check fired. `Limited` from
    // `http_body_util` stops reading at the byte cap and returns the
    // size-limit error before the allocator grows further. The
    // listener binds 127.0.0.1 only so the attack surface is local,
    // but the daemon co-resides with WAL writer / LLM pipeline /
    // channel loops, so any OOM kill takes the whole process down.
    let limited = Limited::new(req.into_body(), MAX_BODY_BYTES);
    let bytes = match limited.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            // R2-P1-1: bubble as a structured BodyTooLarge so the
            // service layer renders 413 instead of generic 500. The
            // upstream error chain from `Limited` reliably indicates
            // size-limit overrun for this codepath since the only
            // wrapper around the body is the MAX_BODY_BYTES cap.
            return Err(HandleError::BodyTooLarge {
                cap: MAX_BODY_BYTES,
            });
        }
    };
    Ok(WebhookRequest {
        method,
        path,
        query,
        headers_lc,
        body: bytes.to_vec(),
    })
}

fn webhook_to_hyper(resp: WebhookResponse) -> HyperResponse<Full<Bytes>> {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    HyperResponse::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(resp.body)))
        .unwrap_or_else(|_| plain_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))
}

fn plain_response(status: StatusCode, body: &str) -> HyperResponse<Full<Bytes>> {
    HyperResponse::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("static response always valid")
}

#[cfg(test)]
mod tests {
    use super::super::webhook_verify::{sign_meta, sign_slack};
    use super::*;

    #[test]
    fn inbound_dedup_skips_dups_passes_new_and_evicts_at_cap() {
        let mut d = InboundDedup::new(2);
        // New wamid → not seen; repeat → seen.
        assert!(!d.check_and_insert("wamid.A"));
        assert!(d.check_and_insert("wamid.A"));
        // A second distinct id is new.
        assert!(!d.check_and_insert("wamid.B"));
        // Cap is 2 → inserting a third evicts the oldest ("wamid.A"), so it is
        // no longer considered seen and re-inserts as new.
        assert!(!d.check_and_insert("wamid.C"));
        assert!(!d.check_and_insert("wamid.A"));
    }

    fn fake_pipeline() -> PipelineHandler {
        Box::new(|_msg| {
            Box::pin(
                async move { anyhow::Result::<Option<crate::channels::OutboundMessage>>::Ok(None) },
            )
        })
    }

    /// GR-01 Pick B regression helper: pipeline that always emits an
    /// outbound reply addressed to "+4900000". Used by the
    /// `dispatch_messages_*` tests below.
    fn pipeline_with_outbound() -> PipelineHandler {
        Box::new(|_msg| {
            Box::pin(async move {
                anyhow::Result::<Option<crate::channels::OutboundMessage>>::Ok(Some(
                    crate::channels::OutboundMessage {
                        recipient_id: "+4900000".into(),
                        text: "auto-reply".into(),
                    },
                ))
            })
        })
    }

    fn inbound_fixture() -> InboundMessage {
        InboundMessage {
            channel: ChannelKind::WhatsAppBusiness,
            chat_id: "+4912345".into(),
            thread_id: None,
            sender_id: "+4912345".into(),
            sender_display: None,
            text: Some("hi".into()),
            media: None,
            reply_to: None,
            message_id: None,
            edit_unix: None,
            mention_kind: None,
            channel_ts_unix: 1_700_000_000,
            raw_ts_ms: None,
            human_uuid: None,
        }
    }

    #[tokio::test]
    async fn dispatch_drops_outbound_when_no_send_creds_present() {
        // GR-01 backward-compat: a listener without whatsapp_send_creds
        // (non-WhatsApp consumer) MUST log+drop pipeline replies, not
        // panic. Pre-GR-01 behaviour preserved.
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: pipeline_with_outbound(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        // No panic, no network call — completes cleanly.
        dispatch_messages(&cfg, vec![inbound_fixture()]).await;
    }

    /// Build a config with send creds + the given governance (the Deny/DryRun
    /// verdicts below never touch the network, so the fake token is safe).
    fn gated_cfg(gov: SendGovernance, base_url: Option<String>) -> WebhookListenerConfig {
        WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: pipeline_with_outbound(),
            whatsapp_send_creds: Some(WhatsAppSendCreds {
                access_token: crate::secret::SecretString::from("fake-token"),
                phone_number_id: "123".to_string(),
                base_url,
            }),
            send_governance: gov,
            max_concurrent_connections: None,
            dispatch_join: None,
        }
    }

    /// Decode the first WAL frame → (event_type, owned payload bytes).
    fn read_first_frame(seg: &std::path::Path) -> (u8, Vec<u8>) {
        let bytes = std::fs::read(seg).unwrap();
        let f = crate::wal::frame::decode_frame(
            &bytes[crate::wal::segment_header::SEGMENT_HEADER_LEN..],
        )
        .unwrap();
        (f.header.event_type, f.payload.to_vec())
    }

    #[tokio::test]
    async fn p0_denied_send_skips_api_and_audits_permission_denied() {
        // A Deny verdict must NOT call the Graph API and MUST emit a 0xA1
        // PERMISSION_DENIED frame with the recipient HASHED. base_url points at a
        // wiremock server with NO mounted route, so any stray send is recorded —
        // we machine-assert the server saw ZERO requests (the "skips API" half).
        use wiremock::MockServer;
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let cfg = gated_cfg(
            SendGovernance {
                wal_writer: Some(writer.clone()),
                decision: crate::permissions::Decision::Deny("test-deny".into()),
                required_audit: false,
                dry_run: false,
            },
            Some(server.uri()),
        );
        dispatch_messages(&cfg, vec![inbound_fixture()]).await;
        // Drop cfg FIRST — it holds a writer clone inside send_governance; the
        // writer task only finishes (so `join` returns) once every handle is
        // gone. (Production never joins: the daemon owns the writer for life.)
        drop(cfg);
        drop(writer);
        let _ = join.await;
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "Deny verdict must not hit the WhatsApp Graph API"
        );
        let (event_type, payload) = read_first_frame(&seg);
        assert_eq!(
            event_type,
            crate::wal::events::EVENT_TYPE_CHANNEL_SEND_DENIED
        );
        let text = String::from_utf8_lossy(&payload);
        assert!(!text.contains("+4900000"), "recipient phone leaked: {text}");
        assert!(
            text.contains("channel_send"),
            "denial payload tags the action"
        );
    }

    #[tokio::test]
    async fn p0_dry_run_audits_egress_without_sending() {
        // dry_run + Allow → emit a 0x33 CHANNEL_EGRESS (dry_run:true), no API.
        // Machine-verified: the wiremock server receives ZERO requests.
        use wiremock::MockServer;
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let cfg = gated_cfg(
            SendGovernance {
                wal_writer: Some(writer.clone()),
                decision: crate::permissions::Decision::Allow,
                required_audit: false,
                dry_run: true,
            },
            Some(server.uri()),
        );
        dispatch_messages(&cfg, vec![inbound_fixture()]).await;
        drop(cfg);
        drop(writer);
        let _ = join.await;
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "dry-run must not hit the WhatsApp Graph API"
        );
        let (event_type, payload) = read_first_frame(&seg);
        assert_eq!(event_type, crate::wal::events::EVENT_TYPE_CHANNEL_SEND);
        let text = String::from_utf8_lossy(&payload);
        // Metadata-only: hashed recipient + body, dry-run flag set.
        assert!(!text.contains("+4900000"), "recipient leaked: {text}");
        assert!(!text.contains("auto-reply"), "message body leaked: {text}");
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["dry_run"], true);
        assert_eq!(v["channel"], "whatsapp");
    }

    #[tokio::test]
    async fn p0_send_hits_api_once_and_audits_delivered_egress() {
        // WA-SEAM-01: Allow + not-dry-run → exactly ONE POST to the Graph API
        // (machine-verified via wiremock) AND a 0x33 CHANNEL_EGRESS frame
        // attesting the delivered reply (recipient + body HASHED, real wamid).
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/123/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"contacts":[{"wa_id":"49000"}],"messages":[{"id":"wamid.OK"}]}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let cfg = gated_cfg(
            SendGovernance {
                wal_writer: Some(writer.clone()),
                decision: crate::permissions::Decision::Allow,
                required_audit: false,
                dry_run: false,
            },
            Some(server.uri()),
        );
        dispatch_messages(&cfg, vec![inbound_fixture()]).await;
        drop(cfg);
        drop(writer);
        let _ = join.await;
        // Exactly one Graph API POST landed (also enforced by `.expect(1)`).
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs.len(),
            1,
            "Allow+send must hit the Graph API exactly once"
        );
        let (event_type, payload) = read_first_frame(&seg);
        assert_eq!(event_type, crate::wal::events::EVENT_TYPE_CHANNEL_SEND);
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["dry_run"], false);
        assert_eq!(v["channel"], "whatsapp");
        assert_eq!(v["provider_message_id"], "wamid.OK");
        let text = String::from_utf8_lossy(&payload);
        assert!(!text.contains("+4900000"), "recipient leaked: {text}");
    }

    // ── GOLD-FEAT-10 LINE dispatch governance (L-01) ───────────────────────

    /// LINE analogue of `gated_cfg`: a listener wired with `line` send config +
    /// the given governance. The Deny/Allow verdicts drive the push path.
    fn gated_line_cfg(gov: SendGovernance, base_url: Option<String>) -> WebhookListenerConfig {
        WebhookListenerConfig {
            inbound_dedup: None,
            line: Some(LineConfig {
                channel_secret: b"line-secret".to_vec(),
                access_token: crate::secret::SecretString::from("fake-line-token"),
                base_url,
            }),
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: pipeline_with_outbound(),
            whatsapp_send_creds: None,
            send_governance: gov,
            max_concurrent_connections: None,
            dispatch_join: None,
        }
    }

    #[tokio::test]
    async fn line_denied_send_skips_push_api_and_audits_permission_denied() {
        // A Deny verdict must NOT call the LINE push API and MUST emit a
        // CHANNEL_SEND_DENIED frame with the recipient HASHED. base_url points
        // at a wiremock server with NO mounted route — we machine-assert it saw
        // ZERO requests (the "skips API" half).
        use wiremock::MockServer;
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let cfg = gated_line_cfg(
            SendGovernance {
                wal_writer: Some(writer.clone()),
                decision: crate::permissions::Decision::Deny("test-deny".into()),
                required_audit: false,
                dry_run: false,
            },
            Some(server.uri()),
        );
        dispatch_line_messages(&cfg, vec![inbound_fixture()]).await;
        drop(cfg);
        drop(writer);
        let _ = join.await;
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "Deny verdict must not hit the LINE push API"
        );
        let (event_type, payload) = read_first_frame(&seg);
        assert_eq!(
            event_type,
            crate::wal::events::EVENT_TYPE_CHANNEL_SEND_DENIED
        );
        let text = String::from_utf8_lossy(&payload);
        assert!(!text.contains("+4900000"), "recipient leaked: {text}");
        assert!(
            text.contains("channel_send"),
            "denial payload tags the action"
        );
    }

    #[tokio::test]
    async fn line_send_hits_push_api_once_and_audits_without_leaking_pii() {
        // Allow + not-dry-run → exactly ONE POST to /v2/bot/message/push
        // (machine-verified via wiremock) AND a CHANNEL_SEND frame attesting the
        // delivered reply with the recipient + body HASHED (never cleartext).
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v2/bot/message/push"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"sentMessages":[{"id":"line-msg-1"}]}"#),
            )
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let cfg = gated_line_cfg(
            SendGovernance {
                wal_writer: Some(writer.clone()),
                decision: crate::permissions::Decision::Allow,
                required_audit: false,
                dry_run: false,
            },
            Some(server.uri()),
        );
        dispatch_line_messages(&cfg, vec![inbound_fixture()]).await;
        drop(cfg);
        drop(writer);
        let _ = join.await;
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs.len(),
            1,
            "Allow+send must hit the LINE push API exactly once"
        );
        let (event_type, payload) = read_first_frame(&seg);
        assert_eq!(event_type, crate::wal::events::EVENT_TYPE_CHANNEL_SEND);
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["channel"], "line");
        assert_eq!(v["provider_message_id"], "line-msg-1");
        let text = String::from_utf8_lossy(&payload);
        assert!(!text.contains("+4900000"), "recipient leaked: {text}");
        assert!(!text.contains("auto-reply"), "message body leaked: {text}");
    }

    async fn http_get(host: &str, path: &str) -> (u16, String) {
        let url = format!("http://{host}{path}");
        let resp = reqwest::get(&url).await.expect("get");
        let status = resp.status().as_u16();
        let body = resp.text().await.expect("body");
        (status, body)
    }

    async fn http_post(
        host: &str,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> (u16, String) {
        let url = format!("http://{host}{path}");
        let mut builder = reqwest::Client::new().post(&url).body(body.to_vec());
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = builder.send().await.expect("post");
        let status = resp.status().as_u16();
        let body = resp.text().await.expect("body");
        (status, body)
    }

    #[tokio::test]
    async fn server_handles_meta_get_handshake_end_to_end() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"appsecret".to_vec(),
            meta_verify_token: "verify123".to_string(),
            slack_signing_secret: b"slack-sig".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = tokio::spawn(async move {
            let _ = serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });
        // Give the server a beat to bind.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let host = format!("{}", addr);
        let (status, body) = http_get(
            &host,
            "/webhook?hub.mode=subscribe&hub.verify_token=verify123&hub.challenge=NONCE-1",
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, "NONCE-1");

        let (status, _) = http_get(
            &host,
            "/webhook?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=x",
        )
        .await;
        assert_eq!(status, 403);

        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    #[tokio::test]
    async fn server_handles_meta_post_signature_path() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"appsecret".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            let _ = serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let host = format!("{}", addr);

        let body = br#"{"object":"whatsapp_business_account","entry":[]}"#;
        let sig = sign_meta(body, b"appsecret");
        let (status, _) =
            http_post(&host, "/webhook", body, &[("x-hub-signature-256", &sig)]).await;
        assert_eq!(status, 200);

        // Tampered signature → 403.
        let (status, _) = http_post(
            &host,
            "/webhook",
            body,
            &[("x-hub-signature-256", "sha256=00")],
        )
        .await;
        assert_eq!(status, 403);

        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    #[tokio::test]
    async fn meta_post_acks_200_before_pipeline_runs() {
        // GOLD-COR-08 / A-12: the 200 must come back BEFORE the LLM pipeline
        // finishes, or Meta retries the webhook (re-running the pipeline +
        // double-sending the reply). Proof without timing flakiness: the
        // pipeline blocks on a 0-permit semaphore. If dispatch were still
        // synchronous (pre-fix), `handle_meta` would await it and the 200 would
        // NEVER be sent — `http_post` would hang. A prompt 200 proves the
        // dispatch is detached; releasing the permit afterwards proves it is
        // fire-and-FORGET, not fire-and-drop (the turn still runs to completion).
        use std::sync::atomic::{AtomicBool, Ordering};
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let completed = Arc::new(AtomicBool::new(false));
        let release_h = Arc::clone(&release);
        let completed_h = Arc::clone(&completed);
        let pipeline: PipelineHandler = Box::new(move |_inbound| {
            let release_h = Arc::clone(&release_h);
            let completed_h = Arc::clone(&completed_h);
            Box::pin(async move {
                // Block until the test releases us — simulates a slow LLM turn.
                let _ = release_h.acquire().await;
                completed_h.store(true, Ordering::SeqCst);
                Ok(None)
            })
        });

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"appsecret".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline,
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            let _ = serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let host = format!("{}", addr);

        // A real WhatsApp text message → decode_payload yields Messages → the
        // pipeline is invoked (and blocks on the semaphore).
        let body = br#"{"object":"whatsapp_business_account","entry":[{"id":"W","changes":[{"field":"messages","value":{"metadata":{"phone_number_id":"PN","display_phone_number":"+49"},"contacts":[{"profile":{"name":"S"},"wa_id":"49"}],"messages":[{"from":"49","id":"wamid.X","timestamp":"1700000000","type":"text","text":{"body":"hi"}}]}}]}]}"#;
        let sig = sign_meta(body, b"appsecret");
        let (status, _) =
            http_post(&host, "/webhook", body, &[("x-hub-signature-256", &sig)]).await;
        assert_eq!(
            status, 200,
            "Meta POST must 200 even while the pipeline blocks"
        );
        assert!(
            !completed.load(Ordering::SeqCst),
            "pipeline must still be blocked when the 200 returns (fire-and-forget)"
        );

        // Release the blocked turn; the detached dispatch must run to completion.
        release.add_permits(1);
        for _ in 0..50 {
            if completed.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            completed.load(Ordering::SeqCst),
            "detached dispatch must still run to completion (not dropped)"
        );

        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    #[tokio::test]
    async fn gr012b_spooled_body_drains_and_redispatches_on_startup() {
        // GR-012b: a verified webhook body spooled before a (simulated) crash
        // must be re-dispatched by the startup drain, then its spool file deleted;
        // a corrupt spool entry is dropped (never wedges the boot).
        let home = tempfile::tempdir().unwrap();
        let spool_dir = inbound_spool_dir_at(home.path());

        let raw = r#"{"object":"whatsapp_business_account","entry":[{"id":"W","changes":[{"field":"messages","value":{"metadata":{"phone_number_id":"PN","display_phone_number":"+49"},"contacts":[{"profile":{"name":"S"},"wa_id":"49"}],"messages":[{"from":"49","id":"wamid.DRAIN","timestamp":"1700000000","type":"text","text":{"body":"hi"}}]}}]}]}"#;
        let path =
            spool_inbound_body_at(&spool_dir, "wamid.DRAIN", raw, "meta").expect("spool write");
        assert!(path.exists(), "spool file must exist before drain");

        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let pipeline: PipelineHandler = Box::new(move |_inbound| {
            let c = Arc::clone(&c);
            Box::pin(async move {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(None)
            })
        });
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"x".to_vec(),
            meta_verify_token: "v".into(),
            slack_signing_secret: b"s".to_vec(),
            pipeline,
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };

        drain_inbound_spool_at(&cfg, &spool_dir).await;
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "drain must re-dispatch the spooled survivor"
        );
        assert!(!path.exists(), "drained spool file must be deleted");

        // A corrupt spool entry is dropped (not re-run, not a boot-wedge).
        let bad = spool_dir.join("corrupt.json");
        std::fs::write(&bad, b"not json").unwrap();
        drain_inbound_spool_at(&cfg, &spool_dir).await;
        assert!(!bad.exists(), "corrupt spool file must be dropped");
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "corrupt entry must NOT trigger a dispatch"
        );
    }

    #[tokio::test]
    async fn cor34_dispatch_join_tracks_fanout_and_drain_completes_wal_write() {
        // COR-34: when a shared dispatch_join is wired, handle_meta must spawn the
        // detached Meta fan-out INTO that JoinSet (not fire-and-forget), so the
        // daemon's shutdown can drain in-flight pipeline turns + their WAL writes
        // before dropping the writer. Proof: post a WhatsApp message whose
        // pipeline writes a unique marker frame; after the listener stops, drain
        // the JoinSet — it must yield >=1 joined task (the dispatch was tracked,
        // not detached) and the marker frame must be durable in the WAL.
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();

        let writer_for_pipeline = writer.clone();
        let pipeline: PipelineHandler = Box::new(move |_inbound| {
            let w = writer_for_pipeline.clone();
            Box::pin(async move {
                let payload = b"cor34-drain-marker".to_vec();
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_RAW_TEXT,
                    &payload,
                )
                .build();
                let _ = w.append(header, payload).await;
                Ok(None)
            })
        });

        let dispatch_join: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>> =
            Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"appsecret".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline,
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: Some(Arc::clone(&dispatch_join)),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            let _ = serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let host = format!("{}", addr);

        let body = br#"{"object":"whatsapp_business_account","entry":[{"id":"W","changes":[{"field":"messages","value":{"metadata":{"phone_number_id":"PN","display_phone_number":"+49"},"contacts":[{"profile":{"name":"S"},"wa_id":"49"}],"messages":[{"from":"49","id":"wamid.X","timestamp":"1700000000","type":"text","text":{"body":"hi"}}]}}]}]}"#;
        let sig = sign_meta(body, b"appsecret");
        let (status, _) =
            http_post(&host, "/webhook", body, &[("x-hub-signature-256", &sig)]).await;
        assert_eq!(status, 200);

        // Stop the listener (no more accepts). The dispatch task lives in the
        // shared JoinSet, independent of the (now-finished) listener task.
        let _ = shutdown_tx.send(());
        let _ = server.await;

        // Drain the shared JoinSet exactly as serve.rs's shutdown does. It must
        // yield at least one task — proving handle_meta routed the fan-out into
        // the provided JoinSet rather than detaching it.
        let mut joined = 0usize;
        {
            let mut js = dispatch_join.lock().await;
            while js.join_next().await.is_some() {
                joined += 1;
            }
        }
        assert!(
            joined >= 1,
            "COR-34: the Meta fan-out must be spawned into the shared dispatch_join (joined={joined})"
        );

        drop(writer);
        let _ = join.await;
        let bytes = std::fs::read(&seg).unwrap();
        assert!(
            bytes
                .windows(b"cor34-drain-marker".len())
                .any(|w| w == b"cor34-drain-marker"),
            "COR-34: the in-flight dispatch's WAL frame must survive the drain"
        );
    }

    #[tokio::test]
    async fn server_handles_slack_url_verification() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"slackkey".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            let _ = serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let host = format!("{}", addr);

        let body = br#"{"type":"url_verification","challenge":"slack-nonce-7"}"#;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let sig = sign_slack(body, &ts, b"slackkey");
        let (status, resp_body) = http_post(
            &host,
            "/slack/events",
            body,
            &[
                ("x-slack-signature", &sig),
                ("x-slack-request-timestamp", &ts),
            ],
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(resp_body, "slack-nonce-7");

        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            let _ = serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let host = format!("{}", addr);
        let (status, body) = http_get(&host, "/nope").await;
        assert_eq!(status, 404);
        assert!(body.contains("not found"));
        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    #[tokio::test]
    async fn body_over_cap_is_rejected_without_buffering_whole_payload() {
        // Security regression test (Agent 2 audit 2026-05-16): the
        // listener must STOP reading after MAX_BODY_BYTES, not collect
        // the full body first. We submit `MAX_BODY_BYTES + 1` bytes
        // and assert the listener rejects without OOM. The exact
        // response code is implementation detail (hyper returns 500
        // when the handler errors); what matters is the daemon
        // didn't allocate the full payload first.
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            let _ = serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        // Submit body slightly over the cap. The smallest possible
        // over-cap exercises the Limited<> rejection path without
        // contending with parallel webhook tests for scheduler time.
        let host = format!("{}", addr);
        let big = vec![b'A'; MAX_BODY_BYTES + 64];
        let url = format!("http://{host}/webhook");
        let resp = reqwest::Client::new()
            .post(&url)
            .body(big)
            .send()
            .await
            .expect("post");
        // R2-P1-1: post-fix the cap rejection surfaces as a STRUCTURED
        // 413 Payload Too Large, not generic 500. Operators / reverse
        // proxies / upstream webhook senders can now distinguish "body
        // too large, fix your sender" from "server broken, retry later".
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::PAYLOAD_TOO_LARGE,
            "R2-P1-1: over-cap body must yield 413, got {}",
            resp.status()
        );
        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    // ── R2-P1-1 concurrency cap + bounded drain ─────────────────────────

    #[tokio::test]
    async fn r2_p1_1_concurrency_cap_returns_429_when_over_capacity() {
        // Cap at 1 so the second concurrent request is guaranteed to
        // exceed it. The first request hits a delay (we use Meta
        // signature verification path which takes a tiny but bounded
        // amount of time on every request) so the test can race the
        // second request against it.
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: Some(1),
            dispatch_join: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            let _ = serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let host = format!("{}", addr);

        // Fire many requests in parallel; at least one must hit the
        // 429 cap. We can't deterministically time it perfectly under
        // tokio's scheduler, so we look across 8 parallel requests
        // for ANY 429 response. The reverse case (no 429 anywhere
        // across 8 concurrent requests against a cap of 1) would
        // mean the semaphore isn't enforcing.
        let url =
            format!("http://{host}/webhook?hub.mode=subscribe&hub.verify_token=v&hub.challenge=x");
        let mut handles = Vec::new();
        for _ in 0..8 {
            let u = url.clone();
            handles.push(tokio::spawn(async move {
                reqwest::Client::new()
                    .get(&u)
                    .send()
                    .await
                    .map(|r| r.status())
            }));
        }
        let mut saw_429 = false;
        for h in handles {
            if let Ok(Ok(status)) = h.await {
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    saw_429 = true;
                    break;
                }
            }
        }
        assert!(
            saw_429,
            "R2-P1-1: with cap=1, at least one of 8 parallel requests must see 429"
        );
        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    #[tokio::test]
    async fn r2_p1_1_default_concurrency_cap_is_64() {
        assert_eq!(DEFAULT_MAX_CONCURRENT_CONNECTIONS, 64);
    }

    #[tokio::test]
    async fn r2_p1_1_shutdown_drain_timeout_is_five_seconds() {
        // Pin the timeout so a future refactor that drops it to zero
        // (== shutdown abandons every in-flight connection immediately)
        // surfaces as a test failure. R2-P1-1 done-criterion: "Shutdown
        // wartet bounded auf aktive Requests".
        assert_eq!(SHUTDOWN_DRAIN_TIMEOUT, std::time::Duration::from_secs(5));
    }

    #[tokio::test]
    async fn shutdown_signal_stops_accept_loop() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let server = tokio::spawn(async move {
            serve(addr, cfg, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve should exit cleanly on shutdown")
        });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        let _ = shutdown_tx.send(());
        let port = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("server did not exit within 2s")
            .expect("task panicked");
        assert_eq!(port, addr.port());
    }
}
