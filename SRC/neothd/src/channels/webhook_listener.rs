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
use futures_util::StreamExt as _;
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

/// Hard cap on directory entries inspected during one recovery batch.
/// Every `ReadDir` item counts, including non-JSON junk and unreadable entries,
/// so an attacker-filled spool cannot monopolise the async runtime. Recovery
/// starts only after the listener has bound, yields between batches, and keeps
/// the same directory cursor until every entry in the pass was inspected.
const MAX_SPOOL_DRAIN_FILES: usize = 1024;
const MAX_CONCURRENT_SPOOL_DRAINS: usize = 8;
const MAX_SPOOL_ENTRY_BYTES: u64 = (MAX_BODY_BYTES as u64) * 8;
const WEBHOOK_OUTBOX_VERSION: u8 = 1;
const MAX_OUTBOX_ENTRY_BYTES: u64 = 512 * 1024;
const WEBHOOK_RETRY_BASE_SECS: u64 = 5;
const WEBHOOK_RETRY_MAX_SECS: u64 = 15 * 60;
/// Complete/quarantined source-key receipts suppress provider redelivery across daemon
/// restarts without retaining the reply body indefinitely. The cap and TTL keep
/// the private outbox bounded; after either window expires a very late provider
/// redelivery is deliberately treated as a new delivery.
const MAX_TERMINAL_OUTBOX_RECEIPTS_PER_CHANNEL: usize = 4096;
const TERMINAL_OUTBOX_RECEIPT_RETENTION: std::time::Duration =
    std::time::Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OutboxChannel {
    Meta,
    Line,
}

impl OutboxChannel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Meta => "whatsapp",
            Self::Line => "line",
        }
    }

    fn decoder(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Line => "line",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OutboxState {
    PendingSend,
    WaitingForConfiguration {
        reason: String,
    },
    DeliveredPendingAudit {
        provider_message_id: Option<String>,
        confirm_degraded: bool,
    },
    /// The provider conclusively rejected this payload. It remains a distinct,
    /// operator-visible receipt (rather than masquerading as `Complete`) and
    /// suppresses both transport and pipeline replay for the retention window.
    Quarantined {
        reason: String,
        quarantined_at: u64,
    },
    Complete,
}

/// Private durable hand-off between a completed pipeline turn and the provider
/// transport. Tokens are deliberately absent: recovery resolves credentials
/// from the live config. Recipient/body are required to retry and therefore
/// live only in a current-user-only file, never in logs or WAL payloads.
/// Meta/LINE push APIs do not expose a caller idempotency key here, so an
/// ambiguous connection loss after provider acceptance is explicitly
/// at-least-once for transport delivery. A scrubbed, bounded completion receipt
/// suppresses model/tools replay for the same durable source key across restarts
/// for the retention window above; this is not an unbounded exactly-once claim.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookOutboxRecord {
    version: u8,
    channel: OutboxChannel,
    source_key: String,
    recipient_id: String,
    body: String,
    body_sha256: String,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    audit_attempts: u32,
    /// Transport and required-audit retries are deliberately independent: a
    /// delivered message must never be sent again while only its audit is due.
    #[serde(default)]
    transport_next_attempt_at: Option<u64>,
    #[serde(default)]
    audit_next_attempt_at: Option<u64>,
    #[serde(default)]
    last_failure: Option<String>,
    state: OutboxState,
    inbound_spool_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryOutcome {
    Sent,
    Denied,
    DryRun,
    AlreadyComplete,
    RefusedNoAudit,
    MissingCredentials,
    BackoffWait,
    Quarantined,
    TransportRetry,
    AuditRetry,
    PersistenceRetry,
}

#[derive(Debug)]
enum TransportDisposition {
    Delivered(Option<String>),
    Retry {
        reason: &'static str,
        retry_after_secs: Option<u64>,
    },
    Permanent {
        reason: &'static str,
    },
    ConfigurationWait {
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageLifecycle {
    /// The pipeline did not complete, so only the inbound spool can retry it.
    RetryPipeline,
    /// The turn completed and is either terminal or durably owned by outbox.
    Adopted(DeliveryOutcome),
}

/// P0 — governance inputs for the outbound channel send. The daemon resolves
/// the active policy at each send leaf + threads its WAL writer
/// so every WhatsApp webhook reply is gated + audited via
/// [`crate::channels::send_gate`]. `Default` is the writerless, permissive
/// posture used by tests / non-sending listeners.
pub struct SendGovernance {
    /// Daemon WAL writer for the `CHANNEL_EGRESS` / `PERMISSION_DENIED` audit.
    /// `None` ⇒ no audit is written (and a `required_audit` send fails closed).
    pub wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    /// Pre-evaluated `Action::ChannelSend` decision under the active autonomy.
    /// Used only by tests/non-daemon callers without a reload controller.
    pub decision: crate::permissions::Decision,
    /// Live daemon policy source. When present it supersedes `decision` and a
    /// fresh immutable snapshot is evaluated for every outbound reply.
    pub reload_controller: Option<std::sync::Arc<crate::config::reload::ReloadController>>,
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
            reload_controller: None,
            required_audit: false,
            dry_run: false,
        }
    }
}

impl SendGovernance {
    fn current_decision(&self) -> crate::permissions::Decision {
        let Some(controller) = &self.reload_controller else {
            return self.decision.clone();
        };
        let policy = controller.autonomy_policy();
        crate::permissions::evaluate(&crate::permissions::Action::ChannelSend, &policy)
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
    /// Exact sender identity authorized for the active inbound webhook adapter.
    /// WhatsApp stores canonical international digits; LINE stores an immutable
    /// `U…` member id. Empty is deliberately deny-all for tests/handshakes and
    /// prevents a future composition bug from creating open inbound.
    pub inbound_allowed_sender: String,
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
    seen: std::collections::HashSet<String>,
    in_flight: std::collections::HashSet<String>,
    cap: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DedupReservation {
    New,
    CommittedDuplicate,
    InFlight,
}

impl InboundDedup {
    pub fn new(cap: usize) -> Self {
        let cap = cap.clamp(1, 4096);
        Self {
            ring: std::collections::VecDeque::with_capacity(cap),
            seen: std::collections::HashSet::with_capacity(cap),
            in_flight: std::collections::HashSet::with_capacity(cap.min(64)),
            cap,
        }
    }

    /// Reserve a message while its pipeline result is not durable yet. A
    /// concurrent redelivery sees the reservation as a duplicate; a retryable
    /// failure rolls it back instead of poisoning the committed seen-set.
    fn reserve(&mut self, id: &str) -> DedupReservation {
        if self.seen.contains(id) {
            return DedupReservation::CommittedDuplicate;
        }
        if self.in_flight.contains(id) {
            return DedupReservation::InFlight;
        }
        self.in_flight.insert(id.to_owned());
        DedupReservation::New
    }

    fn commit(&mut self, id: &str) {
        self.in_flight.remove(id);
        if self.seen.contains(id) {
            return;
        }
        if self.ring.len() >= self.cap
            && let Some(evicted) = self.ring.pop_front()
        {
            self.seen.remove(&evicted);
        }
        let id = id.to_owned();
        self.seen.insert(id.clone());
        self.ring.push_back(id);
    }

    fn rollback(&mut self, id: &str) {
        self.in_flight.remove(id);
    }

    /// `true` if `id` was already seen (duplicate); otherwise inserts it and
    /// returns `false`.
    pub fn check_and_insert(&mut self, id: &str) -> bool {
        match self.reserve(id) {
            DedupReservation::New => {
                self.commit(id);
                false
            }
            DedupReservation::CommittedDuplicate | DedupReservation::InFlight => true,
        }
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
    serve_inner(addr, config, shutdown, false).await
}

/// Production listener entry point. Binding/acceptance comes first; durable
/// crash survivors are then replayed concurrently in bounded batches so a
/// large or junk-filled spool cannot delay readiness.
pub(crate) async fn serve_with_spool_recovery(
    addr: SocketAddr,
    config: WebhookListenerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<u16> {
    serve_inner(addr, config, shutdown, true).await
}

async fn serve_inner(
    addr: SocketAddr,
    config: WebhookListenerConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
    recover_spool: bool,
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
    let mut spool_recovery = recover_spool.then(|| {
        let recovery_config = Arc::clone(&config);
        tokio::spawn(async move {
            let channel = if recovery_config.line.is_some() {
                OutboxChannel::Line
            } else {
                OutboxChannel::Meta
            };
            // Inbound recovery also adopts any matching existing outbox record.
            // Run it first so one daemon start never attempts the same pending
            // send twice back-to-back (once from each directory scan).
            drain_inbound_spool(&recovery_config).await;
            let mut retry = tokio::time::interval(std::time::Duration::from_secs(30));
            retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            retry.tick().await;
            loop {
                retry.tick().await;
                // A pipeline failure intentionally leaves only the inbound
                // spool behind. Retry it during normal uptime as well as at
                // startup; otherwise the survivor would wait for a restart.
                drain_inbound_spool(&recovery_config).await;
                let outbox_dir = webhook_outbox_dir_at(&active_neoth_home(&recovery_config));
                drain_webhook_outbox_at(&recovery_config, &outbox_dir, channel).await;
            }
        })
    });
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
                if let Some(task) = spool_recovery.take() {
                    // Cancellation leaves the current survivor on disk; the
                    // next daemon start resumes it. Never hold shutdown open
                    // on an LLM-backed recovery dispatch.
                    task.abort();
                    let _ = task.await;
                }
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
                    let spool_path = match spool_inbound_body(&cfg, &spool_key, raw_body, "meta") {
                        Ok(path) => path,
                        Err(error) => {
                            error!(error = %error, "inbound spool unavailable; refusing Meta ACK so provider retries");
                            return Ok(plain_response(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "durable inbound queue unavailable; retry",
                            ));
                        }
                    };
                    let cfg2 = Arc::clone(&cfg);
                    let dispatch = async move {
                        match DISPATCH_GATE.acquire().await {
                            Ok(_permit) => {
                                let outbox_dir = outbox_dir_for_spool(
                                    spool_path
                                        .parent()
                                        .unwrap_or_else(|| std::path::Path::new(".")),
                                );
                                let _ = dispatch_messages_durable(
                                    &cfg2,
                                    msgs,
                                    OutboxChannel::Meta,
                                    &outbox_dir,
                                    Some(&spool_path),
                                )
                                .await;
                            }
                            Err(_) => {
                                warn!("webhook dispatch gate closed — retaining durable fan-out")
                            }
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
                let spool_path = match spool_inbound_body(&cfg, &spool_key, raw_body, "line") {
                    Ok(path) => path,
                    Err(error) => {
                        error!(error = %error, "inbound spool unavailable; refusing LINE ACK so provider retries");
                        return Ok(plain_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "durable inbound queue unavailable; retry",
                        ));
                    }
                };
                let cfg2 = Arc::clone(&cfg);
                let dispatch = async move {
                    match DISPATCH_GATE.acquire().await {
                        Ok(_permit) => {
                            let outbox_dir = outbox_dir_for_spool(
                                spool_path
                                    .parent()
                                    .unwrap_or_else(|| std::path::Path::new(".")),
                            );
                            let _ = dispatch_messages_durable(
                                &cfg2,
                                msgs,
                                OutboxChannel::Line,
                                &outbox_dir,
                                Some(&spool_path),
                            )
                            .await;
                        }
                        Err(_) => {
                            warn!("webhook dispatch gate closed — retaining durable LINE fan-out")
                        }
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
) -> bool {
    let h = crate::wal::make_header(event_type, &payload);
    if let Err(e) = w.append(h, payload).await {
        if critical {
            error!(error = %e, "{fail_msg}");
        } else {
            warn!(error = %e, "{fail_msg}");
        }
        false
    } else {
        true
    }
}

fn active_neoth_home(cfg: &WebhookListenerConfig) -> std::path::PathBuf {
    cfg.send_governance
        .reload_controller
        .as_ref()
        .and_then(|controller| controller.source_path().parent())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(crate::config::FreedomConfig::default_neoth_home)
}

fn webhook_outbox_dir_at(home: &std::path::Path) -> std::path::PathBuf {
    home.join("webhook_outbox")
}

fn outbox_dir_for_spool(spool_dir: &std::path::Path) -> std::path::PathBuf {
    spool_dir
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("webhook_outbox")
}

fn prepare_private_state_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_directory_dacl(dir)?;
        crate::wal::win_native::verify_private_directory_dacl(dir)?;
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn terminal_outbox_state(state: &OutboxState) -> bool {
    matches!(
        state,
        OutboxState::Complete | OutboxState::Quarantined { .. }
    )
}

fn retry_is_due(next_attempt_at: Option<u64>, now: u64) -> bool {
    next_attempt_at.is_none_or(|due| due <= now)
}

/// Exponential retry with deterministic, source-bound jitter. Determinism
/// keeps restart behaviour stable; the source hash still distributes a burst
/// across the full 0..25% jitter window. Provider hints are lower bounds but
/// are capped with the local maximum so a malicious response cannot park work
/// forever.
fn retry_delay_secs(
    record: &WebhookOutboxRecord,
    attempts: u32,
    provider_hint: Option<u64>,
) -> u64 {
    let shift = attempts.saturating_sub(1).min(16);
    let exponential = WEBHOOK_RETRY_BASE_SECS
        .saturating_mul(1u64 << shift)
        .min(WEBHOOK_RETRY_MAX_SECS);
    let jitter_window = (exponential / 4).max(1);
    let seed = u64::from_str_radix(&record.source_key[..16], 16).unwrap_or_default()
        ^ u64::from(attempts).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let jitter = seed % (jitter_window + 1);
    exponential
        .saturating_add(jitter)
        .max(
            provider_hint
                .unwrap_or_default()
                .min(WEBHOOK_RETRY_MAX_SECS),
        )
        .min(WEBHOOK_RETRY_MAX_SECS)
}

fn meta_disposition(
    result: anyhow::Result<crate::channels::whatsapp_api::SendMessageResult>,
) -> TransportDisposition {
    match result {
        Ok(response) if response.ok => TransportDisposition::Delivered(response.message_id),
        Ok(response) => match response.http_status {
            Some(429) => TransportDisposition::Retry {
                reason: "meta_rate_limited",
                retry_after_secs: response.retry_after_secs,
            },
            Some(401 | 403) => TransportDisposition::Permanent {
                reason: "meta_auth_rejected",
            },
            Some(400..=499) => TransportDisposition::Permanent {
                reason: "meta_request_rejected",
            },
            Some(500..=599) => TransportDisposition::Retry {
                reason: "meta_server_error",
                retry_after_secs: None,
            },
            Some(_) => TransportDisposition::Retry {
                reason: "meta_api_transient",
                retry_after_secs: None,
            },
            // Pure-parser and pre-metadata callers have no transport status.
            // Keep the old body-derived behaviour only for that compatibility
            // surface; real HTTP calls are classified exclusively above.
            None => {
                let error = response.error.unwrap_or_default().to_ascii_lowercase();
                if error.contains("rate limit")
                    || error.contains("too many request")
                    || error.contains("throttl")
                {
                    TransportDisposition::Retry {
                        reason: "meta_rate_limited",
                        retry_after_secs: None,
                    }
                } else if error.contains("oauthexception")
                    || error.contains("access token")
                    || error.contains("invalid oauth")
                    || error.contains("token has expired")
                {
                    TransportDisposition::Permanent {
                        reason: "meta_auth_rejected",
                    }
                } else if error.contains("invalid parameter")
                    || error.contains("unsupported post")
                    || error.contains("message too long")
                    || error.contains("recipient is not")
                {
                    TransportDisposition::Permanent {
                        reason: "meta_request_rejected",
                    }
                } else {
                    TransportDisposition::Retry {
                        reason: "meta_api_transient",
                        retry_after_secs: None,
                    }
                }
            }
        },
        Err(error) => {
            if error.downcast_ref::<reqwest::Error>().is_some() {
                TransportDisposition::Retry {
                    reason: "meta_transport_error",
                    retry_after_secs: None,
                }
            } else {
                TransportDisposition::ConfigurationWait {
                    reason: "meta_configuration_invalid",
                }
            }
        }
    }
}

fn line_disposition(
    result: std::result::Result<crate::channels::MessageId, crate::channels::ChannelError>,
) -> TransportDisposition {
    match result {
        Ok(message_id) => TransportDisposition::Delivered(Some(message_id.0)),
        Err(crate::channels::ChannelError::RateLimited { retry_after_secs }) => {
            TransportDisposition::Retry {
                reason: "line_rate_limited",
                retry_after_secs: Some(retry_after_secs),
            }
        }
        Err(crate::channels::ChannelError::Auth(_)) => TransportDisposition::Permanent {
            reason: "line_auth_rejected",
        },
        Err(crate::channels::ChannelError::NotSupported { .. }) => {
            TransportDisposition::Permanent {
                reason: "line_send_unsupported",
            }
        }
        Err(crate::channels::ChannelError::Transport(error)) => {
            let status = error
                .split_ascii_whitespace()
                .find_map(|part| part.parse::<u16>().ok());
            if error.contains("exceeds the")
                || status.is_some_and(|status| (400..500).contains(&status))
            {
                TransportDisposition::Permanent {
                    reason: "line_request_rejected",
                }
            } else {
                TransportDisposition::Retry {
                    reason: "line_transport_error",
                    retry_after_secs: None,
                }
            }
        }
    }
}

fn source_key(channel: OutboxChannel, message: &InboundMessage) -> String {
    let identity = if let Some(message_id) = message.message_id.as_deref() {
        format!("{}\0id\0{message_id}", channel.decoder())
    } else {
        // Hash-only fallback: no sender/chat/text is written to the file name.
        format!(
            "{}\0fallback\0{}\0{}\0{}\0{}",
            channel.decoder(),
            message.sender_id,
            message.chat_id,
            message.raw_ts_ms.unwrap_or_default(),
            message.text.as_deref().unwrap_or_default()
        )
    };
    sha256_hex(identity.as_bytes())
}

fn outbox_path(
    dir: &std::path::Path,
    channel: OutboxChannel,
    source_key: &str,
) -> std::path::PathBuf {
    dir.join(format!("{}-{source_key}.json", channel.decoder()))
}

fn validate_outbox_record(record: &WebhookOutboxRecord) -> Result<()> {
    if record.version != WEBHOOK_OUTBOX_VERSION
        || record.source_key.len() != 64
        || !record
            .source_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || record.body_sha256 != sha256_hex(record.body.as_bytes())
        || record.recipient_id.len() > 4096
        || record.body.len() > MAX_OUTBOX_ENTRY_BYTES as usize
        || record
            .last_failure
            .as_ref()
            .is_some_and(|reason| reason.len() > 128)
    {
        anyhow::bail!("invalid webhook outbox record");
    }
    if let Some(name) = record.inbound_spool_name.as_deref()
        && (name.is_empty()
            || std::path::Path::new(name)
                .file_name()
                .and_then(|v| v.to_str())
                != Some(name))
    {
        anyhow::bail!("invalid webhook outbox inbound spool name");
    }
    Ok(())
}

fn encode_outbox_record(record: &WebhookOutboxRecord) -> Result<Vec<u8>> {
    validate_outbox_record(record)?;
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() as u64 > MAX_OUTBOX_ENTRY_BYTES {
        anyhow::bail!("webhook outbox record exceeds the hard size cap");
    }
    Ok(bytes)
}

fn load_outbox_record(path: &std::path::Path) -> Result<WebhookOutboxRecord> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if metadata.len() > MAX_OUTBOX_ENTRY_BYTES {
        anyhow::bail!("oversized webhook outbox record");
    }
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let record: WebhookOutboxRecord =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    validate_outbox_record(&record)?;
    Ok(record)
}

fn persist_outbox_record(path: &std::path::Path, record: &WebhookOutboxRecord) -> Result<()> {
    let bytes = encode_outbox_record(record)?;
    crate::util::atomic_write::atomic_write_private(path, &bytes)
        .with_context(|| format!("persist webhook outbox record at {}", path.display()))
}

fn stage_outbox_record(
    dir: &std::path::Path,
    record: &WebhookOutboxRecord,
) -> Result<(std::path::PathBuf, WebhookOutboxRecord)> {
    prepare_private_state_dir(dir).context("prepare private webhook outbox")?;
    let path = outbox_path(dir, record.channel, &record.source_key);
    let bytes = encode_outbox_record(record)?;
    match crate::util::atomic_write::write_private_create_new(&path, &bytes) {
        Ok(()) => Ok((path, record.clone())),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = load_outbox_record(&path)?;
            if existing.channel != record.channel || existing.source_key != record.source_key {
                anyhow::bail!("webhook outbox identity collision");
            }
            Ok((path, existing))
        }
        Err(error) => {
            Err(error).with_context(|| format!("stage webhook outbox record at {}", path.display()))
        }
    }
}

fn inbound_spool_name(path: Option<&std::path::Path>) -> Option<String> {
    path.and_then(std::path::Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_owned)
}

fn matching_inbound_spool_exists(
    record: &WebhookOutboxRecord,
    outbox_dir: &std::path::Path,
) -> bool {
    let Some(name) = record.inbound_spool_name.as_deref() else {
        return false;
    };
    outbox_dir
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("inbound_spool")
        .join(name)
        .is_file()
}

async fn audit_delivered(
    cfg: &WebhookListenerConfig,
    record: &WebhookOutboxRecord,
    provider_message_id: Option<&str>,
    confirm_degraded: bool,
) -> bool {
    let Some(writer) = cfg.send_governance.wal_writer.as_ref() else {
        return !cfg.send_governance.required_audit;
    };
    let payload = crate::channels::send_gate::channel_egress_payload(
        record.channel.as_str(),
        &record.recipient_id,
        &record.body,
        provider_message_id,
        false,
        confirm_degraded,
        crate::time::now_unix_secs(),
    );
    append_audit(
        writer,
        crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
        payload,
        true,
        "required-audit WAL write failed after webhook send; durable outbox will retry audit only",
    )
    .await
}

fn complete_outbox(
    path: &std::path::Path,
    record: &mut WebhookOutboxRecord,
    outcome: DeliveryOutcome,
) -> DeliveryOutcome {
    record.state = OutboxState::Complete;
    record.transport_next_attempt_at = None;
    record.audit_next_attempt_at = None;
    record.last_failure = None;
    match persist_outbox_record(path, record) {
        Ok(()) => outcome,
        Err(error) => {
            warn!(error = %error, "webhook outbox: could not persist terminal state");
            DeliveryOutcome::PersistenceRetry
        }
    }
}

fn scrub_terminal_outbox_receipt(
    path: &std::path::Path,
    record: &mut WebhookOutboxRecord,
) -> Result<()> {
    if !terminal_outbox_state(&record.state)
        || (record.recipient_id.is_empty()
            && record.body.is_empty()
            && record.inbound_spool_name.is_none()
            && record.attempts == 0
            && record.audit_attempts == 0)
    {
        return Ok(());
    }
    record.recipient_id.clear();
    record.body.clear();
    record.body_sha256 = sha256_hex(b"");
    record.attempts = 0;
    record.audit_attempts = 0;
    record.transport_next_attempt_at = None;
    record.audit_next_attempt_at = None;
    record.inbound_spool_name = None;
    persist_outbox_record(path, record).context("scrub terminal webhook outbox receipt")
}

fn remove_terminal_outbox_receipt(path: &std::path::Path, reason: &'static str) {
    if let Err(error) = crate::util::atomic_write::durable_remove_file(path) {
        warn!(
            error = %error,
            path = %path.display(),
            reason,
            "webhook outbox: terminal receipt prune failed"
        );
    }
}

async fn finish_delivered_outbox(
    cfg: &WebhookListenerConfig,
    path: &std::path::Path,
    record: &mut WebhookOutboxRecord,
    provider_message_id: Option<String>,
    confirm_degraded: bool,
) -> DeliveryOutcome {
    let now = crate::time::now_unix_secs();
    if !retry_is_due(record.audit_next_attempt_at, now) {
        return DeliveryOutcome::BackoffWait;
    }
    record.audit_attempts = record.audit_attempts.saturating_add(1);
    if let Err(error) = persist_outbox_record(path, record) {
        warn!(error = %error, "webhook outbox: refusing audit before durable attempt state");
        return DeliveryOutcome::PersistenceRetry;
    }
    if !audit_delivered(
        cfg,
        record,
        provider_message_id.as_deref(),
        confirm_degraded,
    )
    .await
    {
        let delay = retry_delay_secs(record, record.audit_attempts, None);
        record.audit_next_attempt_at = Some(now.saturating_add(delay));
        record.last_failure = Some("required_audit_unavailable".to_owned());
        if let Err(error) = persist_outbox_record(path, record) {
            warn!(error = %error, "webhook outbox: could not persist audit retry schedule");
            return DeliveryOutcome::PersistenceRetry;
        }
        return DeliveryOutcome::AuditRetry;
    }
    record.audit_next_attempt_at = None;
    record.last_failure = None;
    complete_outbox(path, record, DeliveryOutcome::Sent)
}

async fn deliver_outbox_record(
    cfg: &WebhookListenerConfig,
    path: &std::path::Path,
    record: &mut WebhookOutboxRecord,
) -> DeliveryOutcome {
    match record.state.clone() {
        OutboxState::Complete => return DeliveryOutcome::AlreadyComplete,
        OutboxState::Quarantined { .. } => return DeliveryOutcome::Quarantined,
        OutboxState::DeliveredPendingAudit {
            provider_message_id,
            confirm_degraded,
        } => {
            return finish_delivered_outbox(
                cfg,
                path,
                record,
                provider_message_id,
                confirm_degraded,
            )
            .await;
        }
        OutboxState::WaitingForConfiguration { .. } => {
            let configured = match record.channel {
                OutboxChannel::Meta => cfg.whatsapp_send_creds.is_some(),
                OutboxChannel::Line => cfg.line.is_some(),
            };
            if !configured {
                return DeliveryOutcome::MissingCredentials;
            }
            record.state = OutboxState::PendingSend;
            record.transport_next_attempt_at = None;
            record.last_failure = None;
            if let Err(error) = persist_outbox_record(path, record) {
                warn!(error = %error, "webhook outbox: could not leave configuration-wait state");
                return DeliveryOutcome::PersistenceRetry;
            }
        }
        OutboxState::PendingSend => {}
    }

    let now = crate::time::now_unix_secs();
    if !retry_is_due(record.transport_next_attempt_at, now) {
        return DeliveryOutcome::BackoffWait;
    }

    use crate::channels::send_gate::{self, ChannelSendVerdict};
    let governance = &cfg.send_governance;
    let decision = governance.current_decision();
    let verdict = send_gate::decide_channel_send(
        &decision,
        governance.dry_run,
        governance
            .wal_writer
            .as_ref()
            .is_some_and(|writer| writer.is_alive()),
        governance.required_audit,
    );

    match verdict {
        ChannelSendVerdict::Denied(reason) => {
            if let Some(writer) = governance.wal_writer.as_ref() {
                let payload = send_gate::channel_send_denied_payload(
                    record.channel.as_str(),
                    &record.recipient_id,
                    &reason,
                    now,
                );
                let _ = append_audit(
                    writer,
                    crate::wal::events::EVENT_TYPE_CHANNEL_SEND_DENIED,
                    payload,
                    false,
                    "WAL write failed for webhook channel-send denial audit frame",
                )
                .await;
            }
            complete_outbox(path, record, DeliveryOutcome::Denied)
        }
        ChannelSendVerdict::RefusedNoAudit => DeliveryOutcome::RefusedNoAudit,
        ChannelSendVerdict::DryRun => {
            if let Some(writer) = governance.wal_writer.as_ref() {
                let payload = send_gate::channel_egress_payload(
                    record.channel.as_str(),
                    &record.recipient_id,
                    &record.body,
                    None,
                    true,
                    false,
                    now,
                );
                let _ = append_audit(
                    writer,
                    crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                    payload,
                    false,
                    "WAL write failed for dry-run webhook channel-send audit frame",
                )
                .await;
            }
            complete_outbox(path, record, DeliveryOutcome::DryRun)
        }
        ChannelSendVerdict::Send => {
            let missing_reason = match record.channel {
                OutboxChannel::Meta if cfg.whatsapp_send_creds.is_none() => {
                    Some("whatsapp_credentials_missing")
                }
                OutboxChannel::Line if cfg.line.is_none() => Some("line_credentials_missing"),
                _ => None,
            };
            if let Some(reason) = missing_reason {
                record.state = OutboxState::WaitingForConfiguration {
                    reason: reason.to_owned(),
                };
                record.transport_next_attempt_at = None;
                record.last_failure = Some(reason.to_owned());
                if let Err(error) = persist_outbox_record(path, record) {
                    warn!(error = %error, "webhook outbox: could not persist configuration-wait state");
                    return DeliveryOutcome::PersistenceRetry;
                }
                info!(
                    channel = record.channel.as_str(),
                    source_hash = %record.source_key,
                    reason,
                    "webhook outbox waiting for channel configuration"
                );
                return DeliveryOutcome::MissingCredentials;
            }

            record.attempts = record.attempts.saturating_add(1);
            record.transport_next_attempt_at = None;
            if let Err(error) = persist_outbox_record(path, record) {
                warn!(error = %error, "webhook outbox: refusing send before durable attempt state");
                return DeliveryOutcome::PersistenceRetry;
            }

            // GOLD-LF-P1-01a — durable intent BEFORE the message leaves. This
            // sits after the attempt-state persist so a retry cannot lose the
            // attempt, and before the transport so no send can outrun its own
            // audit trail. No writer configured = auditing off, not a failure.
            let egress_intent = match governance.wal_writer.as_ref() {
                Some(writer) => {
                    match send_gate::emit_egress_intent(
                        writer,
                        record.channel.as_str(),
                        &record.recipient_id,
                        &record.body,
                        now,
                    )
                    .await
                    {
                        Some(id) => Some(id),
                        None => {
                            warn!(
                                channel = record.channel.as_str(),
                                "webhook outbox: refusing send, pre-egress audit intent \
                                 could not be recorded"
                            );
                            return DeliveryOutcome::PersistenceRetry;
                        }
                    }
                }
                None => None,
            };

            let disposition = match record.channel {
                OutboxChannel::Meta => {
                    let credentials = cfg
                        .whatsapp_send_creds
                        .as_ref()
                        .expect("credentials checked above");
                    meta_disposition(
                        crate::channels::whatsapp_api::send_text_message_at(
                            credentials
                                .base_url
                                .as_deref()
                                .unwrap_or(crate::channels::whatsapp_api::GRAPH_API_BASE),
                            &credentials.access_token,
                            &credentials.phone_number_id,
                            &record.recipient_id,
                            &record.body,
                        )
                        .await,
                    )
                }
                OutboxChannel::Line => {
                    let line = cfg.line.as_ref().expect("credentials checked above");
                    match crate::providers::http_client::build_client() {
                        Ok(client) => line_disposition(
                            crate::channels::line_api::send_line_push(
                                &client,
                                line.base_url
                                    .as_deref()
                                    .unwrap_or(crate::channels::line_api::LINE_API_BASE),
                                &line.access_token,
                                &record.recipient_id,
                                &record.body,
                            )
                            .await,
                        ),
                        Err(_) => TransportDisposition::Retry {
                            reason: "line_http_client_unavailable",
                            retry_after_secs: None,
                        },
                    }
                }
            };

            // GOLD-LF-P1-01a — pair the intent to what the transport actually
            // did, before any state bookkeeping can fail and hide it.
            if let (Some(writer), Some(intent_id)) =
                (governance.wal_writer.as_ref(), egress_intent.as_ref())
            {
                let (outcome, provider_message_id) = match &disposition {
                    TransportDisposition::Delivered(id) => ("delivered", id.as_deref()),
                    TransportDisposition::Retry { .. } => ("retry", None),
                    _ => ("failed", None),
                };
                send_gate::emit_egress_result(
                    writer,
                    intent_id,
                    outcome,
                    provider_message_id,
                    now,
                )
                .await;
            }

            match disposition {
                TransportDisposition::Delivered(provider_message_id) => {
                    let confirm_degraded =
                        matches!(decision, crate::permissions::Decision::Confirm(_));
                    record.state = OutboxState::DeliveredPendingAudit {
                        provider_message_id: provider_message_id.clone(),
                        confirm_degraded,
                    };
                    record.transport_next_attempt_at = None;
                    record.last_failure = None;
                    if let Err(error) = persist_outbox_record(path, record) {
                        error!(error = %error, "webhook outbox: delivered response could not be persisted");
                        return DeliveryOutcome::PersistenceRetry;
                    }
                    finish_delivered_outbox(
                        cfg,
                        path,
                        record,
                        provider_message_id,
                        confirm_degraded,
                    )
                    .await
                }
                TransportDisposition::Retry {
                    reason,
                    retry_after_secs,
                } => {
                    let delay = retry_delay_secs(record, record.attempts, retry_after_secs);
                    record.transport_next_attempt_at = Some(now.saturating_add(delay));
                    record.last_failure = Some(reason.to_owned());
                    if let Err(error) = persist_outbox_record(path, record) {
                        warn!(error = %error, "webhook outbox: could not persist transport retry schedule");
                        return DeliveryOutcome::PersistenceRetry;
                    }
                    if let Some(writer) = governance.wal_writer.as_ref() {
                        let payload = send_gate::channel_egress_failed_payload(
                            record.channel.as_str(),
                            &record.recipient_id,
                            reason,
                            now,
                        );
                        let _ = append_audit(
                            writer,
                            crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                            payload,
                            false,
                            "WAL write failed for webhook transport-error audit frame",
                        )
                        .await;
                    }
                    DeliveryOutcome::TransportRetry
                }
                TransportDisposition::Permanent { reason } => {
                    record.state = OutboxState::Quarantined {
                        reason: reason.to_owned(),
                        quarantined_at: now,
                    };
                    record.transport_next_attempt_at = None;
                    record.last_failure = Some(reason.to_owned());
                    if let Err(error) = persist_outbox_record(path, record) {
                        warn!(error = %error, "webhook outbox: could not persist quarantine state");
                        return DeliveryOutcome::PersistenceRetry;
                    }
                    if let Some(writer) = governance.wal_writer.as_ref() {
                        let payload = send_gate::channel_egress_failed_payload(
                            record.channel.as_str(),
                            &record.recipient_id,
                            reason,
                            now,
                        );
                        let _ = append_audit(
                            writer,
                            crate::wal::events::EVENT_TYPE_CHANNEL_SEND,
                            payload,
                            false,
                            "WAL write failed for quarantined webhook send audit frame",
                        )
                        .await;
                    }
                    warn!(
                        channel = record.channel.as_str(),
                        source_hash = %record.source_key,
                        reason,
                        "webhook outbox send quarantined after permanent provider rejection"
                    );
                    DeliveryOutcome::Quarantined
                }
                TransportDisposition::ConfigurationWait { reason } => {
                    record.state = OutboxState::WaitingForConfiguration {
                        reason: reason.to_owned(),
                    };
                    record.transport_next_attempt_at = None;
                    record.last_failure = Some(reason.to_owned());
                    if let Err(error) = persist_outbox_record(path, record) {
                        warn!(error = %error, "webhook outbox: could not persist configuration-wait state");
                        return DeliveryOutcome::PersistenceRetry;
                    }
                    warn!(
                        channel = record.channel.as_str(),
                        source_hash = %record.source_key,
                        reason,
                        "webhook outbox paused for corrected channel configuration"
                    );
                    DeliveryOutcome::MissingCredentials
                }
            }
        }
    }
}

/// GR-012b — durable inbound spool dir (`~/.neoth/inbound_spool/`). A Meta
/// webhook is ACKed 200 immediately + dispatched in a DETACHED task, so a crash
/// between the ACK and the dispatch's first WAL write would LOSE the message
/// (Meta won't redeliver an ACKed webhook). Each verified body is spooled here
/// BEFORE the detached dispatch, deleted on successful completion, and any
/// survivor is re-dispatched by the live recovery pump and on the next daemon
/// start ([`drain_inbound_spool`]).
fn inbound_spool_dir_at(home: &std::path::Path) -> std::path::PathBuf {
    home.join("inbound_spool")
}

/// Spool the verified webhook body BEFORE its detached dispatch. `key` is the
/// message id (wamid) when available — idempotent across Meta retries — else a
/// content hash. Returns the spool path so the dispatch can delete it on
/// success. Persistence failure is returned to the request handler so verified
/// provider traffic is answered 503 and can be redelivered; dispatch never runs
/// without first establishing this durable ownership boundary.
fn spool_inbound_body(
    cfg: &WebhookListenerConfig,
    key: &str,
    raw_body: &str,
    decoder: &str,
) -> Result<std::path::PathBuf> {
    let dir = inbound_spool_dir_at(&active_neoth_home(cfg));
    spool_inbound_body_at(&dir, key, raw_body, decoder)
}

fn spool_inbound_body_at(
    dir: &std::path::Path,
    key: &str,
    raw_body: &str,
    decoder: &str,
) -> Result<std::path::PathBuf> {
    prepare_private_state_dir(dir).context("prepare private inbound webhook spool")?;
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
    let body = serde_json::json!({
        "raw_body": raw_body,
        "decoder": decoder,
        "ts_unix": crate::time::now_unix_i64(),
    })
    .to_string();
    // The sanitized/truncated key is only an operator hint. The suffix binds
    // the full unsanitized id, so `+`, `/`, `=` and long common prefixes cannot
    // collide. create_new makes a duplicate retry idempotent without replacing
    // the first durable body.
    let key_hash = xxhash_rust::xxh3::xxh3_64(key.as_bytes());
    let path = dir.join(format!("{safe}-{key_hash:016x}.json"));
    match crate::util::atomic_write::write_private_create_new(&path, body.as_bytes()) {
        Ok(()) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            debug!(path = %path.display(), "inbound spool: duplicate id already durable");
            Ok(path)
        }
        Err(error) => Err(error)
            .with_context(|| format!("persist inbound webhook spool at {}", path.display())),
    }
}

/// GR-012b — drain leftover spooled inbound webhooks after the daemon listener
/// is bound. Each
/// survivor is a webhook that Meta saw ACKed but whose dispatch did not provably
/// complete before a crash. Re-decode + re-dispatch + delete (the in-memory
/// GR-010 dedup ring is empty after a restart, so this is recovery, not a
/// duplicate). Best-effort throughout — a bad spool file is dropped, never fatal.
pub(crate) async fn drain_inbound_spool(cfg: &WebhookListenerConfig) {
    let dir = inbound_spool_dir_at(&active_neoth_home(cfg));
    drain_inbound_spool_at(cfg, &dir).await;
}

async fn drain_inbound_spool_at(cfg: &WebhookListenerConfig, dir: &std::path::Path) {
    // WhatsApp and LINE listeners share the spool directory but own distinct
    // policies/pipelines. Each startup drains only its own decoder so a LINE
    // survivor can never run through WhatsApp's sender policy (or vice versa).
    let expected_decoder = if cfg.line.is_some() { "line" } else { "meta" };
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            warn!(error = %error, "inbound spool: read_dir failed during recovery");
            return;
        }
    };
    let mut drained_total = 0usize;
    loop {
        let mut paths = Vec::with_capacity(MAX_SPOOL_DRAIN_FILES);
        let mut inspected = 0usize;
        let mut exhausted = false;
        while inspected < MAX_SPOOL_DRAIN_FILES {
            match entries.next_entry().await {
                Ok(Some(entry)) => {
                    inspected += 1;
                    let path = entry.path();
                    if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                        paths.push(path);
                    }
                }
                Ok(None) => {
                    exhausted = true;
                    break;
                }
                Err(error) => {
                    warn!(error = %error, "inbound spool: directory iteration failed during recovery");
                    return;
                }
            }
        }

        let mut drains = futures_util::stream::iter(paths.into_iter().map(|path| async move {
            match DISPATCH_GATE.acquire().await {
                Ok(_permit) => drain_one_spool_entry(cfg, path, expected_decoder).await,
                Err(_) => false,
            }
        }))
        .buffer_unordered(MAX_CONCURRENT_SPOOL_DRAINS);
        while let Some(was_drained) = drains.next().await {
            drained_total += usize::from(was_drained);
        }
        if exhausted {
            break;
        }
        debug!(
            inspected,
            cap = MAX_SPOOL_DRAIN_FILES,
            "inbound spool: recovery batch complete; yielding before continuation"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    if drained_total > 0 {
        info!(
            count = drained_total,
            "inbound spool: re-dispatched durable survivors"
        );
    }
}

#[cfg(test)]
struct SpoolCandidates {
    paths: Vec<std::path::PathBuf>,
    inspected: usize,
    inspection_cap_reached: bool,
}

#[cfg(test)]
fn select_spool_candidates(
    entries: impl IntoIterator<Item = std::io::Result<std::path::PathBuf>>,
) -> SpoolCandidates {
    let mut paths = Vec::with_capacity(MAX_SPOOL_DRAIN_FILES);
    let mut inspected = 0usize;
    for entry in entries.into_iter().take(MAX_SPOOL_DRAIN_FILES) {
        inspected += 1;
        let Ok(path) = entry else {
            continue;
        };
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    SpoolCandidates {
        paths,
        inspected,
        // Conservatively report a reached cap at exactly the limit. Detecting
        // whether another entry exists would itself exceed the hard scan bound.
        inspection_cap_reached: inspected == MAX_SPOOL_DRAIN_FILES,
    }
}

async fn finish_dedup_reservation(
    cfg: &WebhookListenerConfig,
    message_id: Option<&str>,
    commit: bool,
) {
    let (Some(dedup), Some(message_id)) = (cfg.inbound_dedup.as_ref(), message_id) else {
        return;
    };
    let mut dedup = dedup.lock().await;
    if commit {
        dedup.commit(message_id);
    } else {
        dedup.rollback(message_id);
    }
}

async fn dispatch_messages_durable(
    cfg: &WebhookListenerConfig,
    messages: Vec<InboundMessage>,
    channel: OutboxChannel,
    outbox_dir: &std::path::Path,
    inbound_path: Option<&std::path::Path>,
) -> bool {
    let mut all_adopted = true;
    let mut owned_records = Vec::new();

    for message in messages {
        if crate::channels::sender_blocked_by_allowlist(
            Some(cfg.inbound_allowed_sender.trim()),
            &message.sender_id,
            cfg.send_governance.wal_writer.as_ref(),
            channel.as_str(),
        )
        .await
        {
            continue;
        }
        let dedup_id = message.message_id.clone();
        if let (Some(dedup), Some(message_id)) = (cfg.inbound_dedup.as_ref(), dedup_id.as_deref()) {
            match dedup.lock().await.reserve(message_id) {
                DedupReservation::New => {}
                DedupReservation::CommittedDuplicate => continue,
                DedupReservation::InFlight => {
                    all_adopted = false;
                    continue;
                }
            }
        }

        let key = source_key(channel, &message);
        let candidate = outbox_path(outbox_dir, channel, &key);
        let existing = if candidate.is_file() {
            match load_outbox_record(&candidate) {
                Ok(record) if record.channel == channel && record.source_key == key => Some(record),
                Ok(_) | Err(_) => {
                    warn!(source_hash = %key, "webhook outbox: invalid existing record; retaining inbound spool");
                    all_adopted = false;
                    finish_dedup_reservation(cfg, dedup_id.as_deref(), false).await;
                    continue;
                }
            }
        } else {
            None
        };

        let (path, mut record) = if let Some(record) = existing {
            (candidate, record)
        } else {
            let pipeline_result = match (cfg.pipeline)(message).await {
                Ok(outbound) => outbound,
                Err(error) => {
                    warn!(
                        error = %error,
                        source_hash = %key,
                        outcome = ?MessageLifecycle::RetryPipeline,
                        "webhook pipeline failed; retaining inbound spool"
                    );
                    all_adopted = false;
                    finish_dedup_reservation(cfg, dedup_id.as_deref(), false).await;
                    continue;
                }
            };
            let (recipient_id, body, state) = match pipeline_result {
                Some(outbound) => (
                    outbound.recipient_id,
                    outbound.text,
                    OutboxState::PendingSend,
                ),
                None => (String::new(), String::new(), OutboxState::Complete),
            };
            let record = WebhookOutboxRecord {
                version: WEBHOOK_OUTBOX_VERSION,
                channel,
                source_key: key.clone(),
                body_sha256: sha256_hex(body.as_bytes()),
                recipient_id,
                body,
                attempts: 0,
                audit_attempts: 0,
                transport_next_attempt_at: None,
                audit_next_attempt_at: None,
                last_failure: None,
                state,
                inbound_spool_name: inbound_spool_name(inbound_path),
            };
            match stage_outbox_record(outbox_dir, &record) {
                Ok(staged) => staged,
                Err(error) => {
                    warn!(error = %error, source_hash = %key, "webhook pipeline result could not be handed to durable outbox");
                    all_adopted = false;
                    finish_dedup_reservation(cfg, dedup_id.as_deref(), false).await;
                    continue;
                }
            }
        };

        let lifecycle = if matches!(record.state, OutboxState::Complete) {
            MessageLifecycle::Adopted(DeliveryOutcome::AlreadyComplete)
        } else {
            MessageLifecycle::Adopted(deliver_outbox_record(cfg, &path, &mut record).await)
        };
        debug!(
            channel = channel.as_str(),
            source_hash = %key,
            outcome = ?lifecycle,
            "webhook durable delivery lifecycle"
        );
        finish_dedup_reservation(cfg, dedup_id.as_deref(), true).await;
        owned_records.push(path);
    }

    if !all_adopted {
        return false;
    }

    if let Some(path) = inbound_path
        && let Err(error) = crate::util::atomic_write::durable_remove_file(path)
    {
        warn!(error = %error, "webhook inbound spool: terminal hand-off could not be committed");
        return false;
    }

    // Keep scrubbed completion receipts after the inbound deletion. They bind a
    // provider source key across process restarts and suppress pipeline replay;
    // the recovery pump prunes them by a documented TTL + count bound.
    for path in owned_records {
        if let Ok(mut record) = load_outbox_record(&path)
            && let Err(error) = scrub_terminal_outbox_receipt(&path, &mut record)
        {
            warn!(error = %error, path = %path.display(), "webhook outbox: terminal receipt scrub failed; recovery will retry");
        }
    }
    true
}

async fn drain_webhook_outbox_at(
    cfg: &WebhookListenerConfig,
    dir: &std::path::Path,
    expected_channel: OutboxChannel,
) {
    use std::cmp::Reverse;

    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            warn!(error = %error, "webhook outbox: recovery scan failed");
            return;
        }
    };
    let mut inspected_in_batch = 0usize;
    let now = std::time::SystemTime::now();
    let mut terminal_receipts =
        std::collections::BinaryHeap::<Reverse<(std::time::SystemTime, std::path::PathBuf)>>::new();
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(error) => {
                warn!(error = %error, "webhook outbox: recovery iteration failed");
                break;
            }
        };
        inspected_in_batch += 1;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let mut record = match load_outbox_record(&path) {
            Ok(record) => record,
            Err(error) => {
                warn!(error = %error, "webhook outbox: invalid recovery record retained fail-closed");
                continue;
            }
        };
        if record.channel != expected_channel {
            continue;
        }
        if !terminal_outbox_state(&record.state) {
            let outcome = deliver_outbox_record(cfg, &path, &mut record).await;
            debug!(
                channel = expected_channel.as_str(),
                source_hash = %record.source_key,
                outcome = ?outcome,
                "webhook outbox recovery attempt"
            );
        }
        if terminal_outbox_state(&record.state) && !matching_inbound_spool_exists(&record, dir) {
            if let Err(error) = scrub_terminal_outbox_receipt(&path, &mut record) {
                warn!(error = %error, path = %path.display(), "webhook outbox: terminal receipt scrub failed");
                continue;
            }
            let modified = std::fs::metadata(&path)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let expired = now
                .duration_since(modified)
                .is_ok_and(|age| age > TERMINAL_OUTBOX_RECEIPT_RETENTION);
            if expired {
                remove_terminal_outbox_receipt(&path, "retention_expired");
            } else {
                let candidate = (modified, path.clone());
                if terminal_receipts.len() < MAX_TERMINAL_OUTBOX_RECEIPTS_PER_CHANNEL {
                    terminal_receipts.push(Reverse(candidate));
                } else {
                    let replaces_oldest = terminal_receipts
                        .peek()
                        .is_some_and(|Reverse(oldest)| &candidate > oldest);
                    if replaces_oldest {
                        if let Some(Reverse((_, oldest_path))) = terminal_receipts.pop() {
                            remove_terminal_outbox_receipt(&oldest_path, "retention_count_cap");
                        }
                        terminal_receipts.push(Reverse(candidate));
                    } else {
                        remove_terminal_outbox_receipt(&path, "retention_count_cap");
                    }
                }
            }
        }
        if inspected_in_batch >= MAX_SPOOL_DRAIN_FILES {
            inspected_in_batch = 0;
            tokio::task::yield_now().await;
        }
    }
}

async fn drain_one_spool_entry(
    cfg: &WebhookListenerConfig,
    path: std::path::PathBuf,
    expected_decoder: &'static str,
) -> bool {
    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    if metadata.len() > MAX_SPOOL_ENTRY_BYTES {
        warn!(path = %path.display(), bytes = metadata.len(), "inbound spool: oversized entry dropped");
        let _ = tokio::fs::remove_file(&path).await;
        return false;
    }
    let body = match tokio::fs::read_to_string(&path).await {
        Ok(body) => body,
        Err(_) => {
            let _ = tokio::fs::remove_file(&path).await;
            return false;
        }
    };
    let Some(parsed) = serde_json::from_str::<serde_json::Value>(&body).ok() else {
        let _ = tokio::fs::remove_file(&path).await;
        return false;
    };
    // Missing decoder means a pre-tag Meta spool. Unknown tags are corrupt and
    // removed instead of being silently dispatched through the Meta policy.
    let decoder = parsed
        .get("decoder")
        .and_then(|value| value.as_str())
        .unwrap_or("meta");
    if !matches!(decoder, "meta" | "line") {
        let _ = tokio::fs::remove_file(&path).await;
        return false;
    }
    if decoder != expected_decoder {
        return false;
    }
    let Some(raw) = parsed.get("raw_body").and_then(|value| value.as_str()) else {
        let _ = tokio::fs::remove_file(&path).await;
        return false;
    };

    let spool_dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let outbox_dir = outbox_dir_for_spool(spool_dir);
    match decoder {
        "line" => match decode_line_payload(raw) {
            DecodedLineWebhook::Messages(messages) => {
                dispatch_messages_durable(
                    cfg,
                    messages,
                    OutboxChannel::Line,
                    &outbox_dir,
                    Some(&path),
                )
                .await
            }
            _ => {
                let _ = crate::util::atomic_write::durable_remove_file(&path);
                false
            }
        },
        "meta" => match decode_payload(raw) {
            DecodedWebhook::Messages(messages) => {
                dispatch_messages_durable(
                    cfg,
                    messages,
                    OutboxChannel::Meta,
                    &outbox_dir,
                    Some(&path),
                )
                .await
            }
            _ => {
                let _ = crate::util::atomic_write::durable_remove_file(&path);
                false
            }
        },
        _ => unreachable!("decoder validated above"),
    }
}

#[cfg_attr(not(test), allow(dead_code))] // retained: exercised by unit tests; prod caller removed in Wave-3 refactor
async fn dispatch_messages(cfg: &WebhookListenerConfig, msgs: Vec<InboundMessage>) {
    for msg in msgs {
        if crate::channels::sender_blocked_by_allowlist(
            Some(cfg.inbound_allowed_sender.trim()),
            &msg.sender_id,
            cfg.send_governance.wal_writer.as_ref(),
            "whatsapp",
        )
        .await
        {
            continue;
        }
        // GR-010: skip duplicate wamids — a Meta reconnect-storm re-delivers the
        // same message_id, and without this every re-delivery would re-run the
        // whole pipeline (and re-send the reply when send creds are wired).
        if let (Some(dedup), Some(mid)) = (cfg.inbound_dedup.as_ref(), msg.message_id.as_deref())
            && dedup.lock().await.check_and_insert(mid)
        {
            debug!(
                message_id = mid,
                "webhook: duplicate wamid — skipping re-delivery"
            );
            continue;
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
                    let decision = gov.current_decision();
                    let now = crate::time::now_unix_secs();
                    let verdict = send_gate::decide_channel_send(
                        &decision,
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
#[cfg_attr(not(test), allow(dead_code))] // retained: exercised by unit tests; prod caller removed in Wave-3 refactor
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
        if crate::channels::sender_blocked_by_allowlist(
            Some(cfg.inbound_allowed_sender.trim()),
            &msg.sender_id,
            cfg.send_governance.wal_writer.as_ref(),
            "line",
        )
        .await
        {
            continue;
        }
        // LINE re-delivers the SAME webhookEventId (carried as message_id); skip
        // a duplicate before it re-runs the pipeline (+ re-sends the reply).
        if let (Some(dedup), Some(mid)) = (cfg.inbound_dedup.as_ref(), msg.message_id.as_deref())
            && dedup.lock().await.check_and_insert(mid)
        {
            debug!(
                message_id = mid,
                "LINE webhook: duplicate event — skipping redelivery"
            );
            continue;
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
                let decision = gov.current_decision();
                let now = crate::time::now_unix_secs();
                let verdict = send_gate::decide_channel_send(
                    &decision,
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

    #[test]
    fn inbound_dedup_reservation_rolls_back_retryable_work() {
        let mut dedup = InboundDedup::new(4);
        assert_eq!(dedup.reserve("wamid.retry"), DedupReservation::New);
        assert_eq!(dedup.reserve("wamid.retry"), DedupReservation::InFlight);
        dedup.rollback("wamid.retry");
        assert_eq!(dedup.reserve("wamid.retry"), DedupReservation::New);
        dedup.commit("wamid.retry");
        assert_eq!(
            dedup.reserve("wamid.retry"),
            DedupReservation::CommittedDuplicate
        );
    }

    #[test]
    fn inbound_spool_names_are_unique_and_never_overwrite() {
        let home = tempfile::tempdir().unwrap();
        let dir = inbound_spool_dir_at(home.path());
        let shared_prefix = "x".repeat(200);
        let first_key = format!("{shared_prefix}+A");
        let second_key = format!("{shared_prefix}/A");
        let first = spool_inbound_body_at(&dir, &first_key, "first", "meta").unwrap();
        let second = spool_inbound_body_at(&dir, &second_key, "second", "meta").unwrap();
        assert_ne!(first, second, "truncated key prefixes must not collide");
        assert!(first.exists() && second.exists());
        assert!(std::fs::read_to_string(&first).unwrap().contains("first"));
        assert!(std::fs::read_to_string(second).unwrap().contains("second"));

        let duplicate = spool_inbound_body_at(&dir, &first_key, "replacement", "meta").unwrap();
        assert_eq!(duplicate, first);
        let durable = std::fs::read_to_string(first).unwrap();
        assert!(durable.contains("first"));
        assert!(
            !durable.contains("replacement"),
            "duplicate must not overwrite"
        );
    }

    #[test]
    fn inbound_spool_persist_failure_is_not_best_effort() {
        let home = tempfile::tempdir().unwrap();
        let blocker = home.path().join("not-a-directory");
        std::fs::write(&blocker, b"x").unwrap();
        let result = spool_inbound_body_at(&blocker.join("spool"), "wamid.fail", "{}", "meta");
        assert!(
            result.is_err(),
            "the HTTP handler maps this durability failure to 503"
        );
    }

    #[test]
    fn startup_spool_drain_limits_are_pinned() {
        assert_eq!(MAX_SPOOL_DRAIN_FILES, 1024);
        assert_eq!(MAX_CONCURRENT_SPOOL_DRAINS, 8);
        assert!(MAX_SPOOL_ENTRY_BYTES >= MAX_BODY_BYTES as u64);
    }

    #[test]
    fn startup_spool_scan_counts_junk_and_leaves_entries_behind_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let survivor = dir.path().join("valid-behind-junk.json");
        std::fs::write(&survivor, b"durable survivor").unwrap();

        let ordered_entries = (0..MAX_SPOOL_DRAIN_FILES)
            .map(|index| Ok(dir.path().join(format!("junk-{index}.tmp"))))
            .chain(std::iter::once(Ok(survivor.clone())));
        let candidates = select_spool_candidates(ordered_entries);

        assert_eq!(candidates.inspected, MAX_SPOOL_DRAIN_FILES);
        assert!(candidates.inspection_cap_reached);
        assert!(
            candidates.paths.is_empty(),
            "junk must count against the scan cap"
        );
        assert!(
            survivor.exists(),
            "a valid entry behind the hard cap must remain durable for a later pass"
        );
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

    fn counting_listener_cfg(
        allowed_sender: &str,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        send_governance: SendGovernance,
    ) -> WebhookListenerConfig {
        let pipeline: PipelineHandler = Box::new(move |_inbound| {
            let calls = std::sync::Arc::clone(&calls);
            Box::pin(async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(None)
            })
        });
        WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline,
            inbound_allowed_sender: allowed_sender.to_string(),
            whatsapp_send_creds: None,
            send_governance,
            max_concurrent_connections: None,
            dispatch_join: None,
        }
    }

    #[tokio::test]
    async fn whatsapp_sender_gate_blocks_mismatch_audits_and_passes_exact_match() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cfg = counting_listener_cfg(
            "491709999999",
            std::sync::Arc::clone(&calls),
            SendGovernance {
                wal_writer: Some(writer.clone()),
                ..Default::default()
            },
        );
        dispatch_messages(&cfg, vec![inbound_fixture()]).await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(cfg);
        drop(writer);
        let _ = join.await;
        assert_eq!(
            read_first_frame(&seg).0,
            crate::wal::events::EVENT_TYPE_CHANNEL_GATE_REJECTED
        );

        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cfg = counting_listener_cfg(
            "+4912345",
            std::sync::Arc::clone(&calls),
            SendGovernance::default(),
        );
        dispatch_messages(&cfg, vec![inbound_fixture()]).await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn line_sender_gate_blocks_mismatch_audits_and_passes_exact_match() {
        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = crate::wal::spawn(seg.clone()).unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut cfg = counting_listener_cfg(
            "Uother",
            std::sync::Arc::clone(&calls),
            SendGovernance {
                wal_writer: Some(writer.clone()),
                ..Default::default()
            },
        );
        cfg.line = Some(LineConfig {
            channel_secret: b"line-secret".to_vec(),
            access_token: crate::secret::SecretString::from("line-token"),
            base_url: None,
        });
        dispatch_line_messages(&cfg, vec![inbound_fixture()]).await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(cfg);
        drop(writer);
        let _ = join.await;
        assert_eq!(
            read_first_frame(&seg).0,
            crate::wal::events::EVENT_TYPE_CHANNEL_GATE_REJECTED
        );

        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut cfg = counting_listener_cfg(
            "+4912345",
            std::sync::Arc::clone(&calls),
            SendGovernance::default(),
        );
        cfg.line = Some(LineConfig {
            channel_secret: b"line-secret".to_vec(),
            access_token: crate::secret::SecretString::from("line-token"),
            base_url: None,
        });
        dispatch_line_messages(&cfg, vec![inbound_fixture()]).await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
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
            inbound_allowed_sender: "+4912345".to_string(),
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
            inbound_allowed_sender: "+4912345".to_string(),
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

    /// Keep listener integration tests out of the operator's real ~/.neoth.
    /// Production always wires a reload controller rooted at the active home;
    /// server-level tests must model that boundary as well so durable receipt
    /// ids cannot collide across tests or repeated runs.
    fn isolated_test_governance(home: &std::path::Path) -> SendGovernance {
        SendGovernance {
            reload_controller: Some(Arc::new(crate::config::reload::ReloadController::new(
                crate::config::FreedomConfig::default(),
                home.join("freedom.yaml"),
            ))),
            ..Default::default()
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
                reload_controller: None,
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
                reload_controller: None,
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
                reload_controller: None,
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
            inbound_allowed_sender: "+4912345".to_string(),
            whatsapp_send_creds: None,
            send_governance: gov,
            max_concurrent_connections: None,
            dispatch_join: None,
        }
    }

    fn pending_outbox_fixture(channel: OutboxChannel, identity: &str) -> WebhookOutboxRecord {
        let body = "durable reply".to_owned();
        WebhookOutboxRecord {
            version: WEBHOOK_OUTBOX_VERSION,
            channel,
            source_key: sha256_hex(identity.as_bytes()),
            recipient_id: match channel {
                OutboxChannel::Meta => "+4900000".to_owned(),
                OutboxChannel::Line => "Urecipient".to_owned(),
            },
            body_sha256: sha256_hex(body.as_bytes()),
            body,
            attempts: 0,
            audit_attempts: 0,
            transport_next_attempt_at: None,
            audit_next_attempt_at: None,
            last_failure: None,
            state: OutboxState::PendingSend,
            inbound_spool_name: None,
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
                reload_controller: None,
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
                reload_controller: None,
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
            inbound_allowed_sender: String::new(),
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
        let host = format!("{addr}");
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
            inbound_allowed_sender: String::new(),
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
        let host = format!("{addr}");

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

        let home = tempfile::tempdir().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"appsecret".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline,
            inbound_allowed_sender: "49".to_string(),
            whatsapp_send_creds: None,
            send_governance: isolated_test_governance(home.path()),
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
        let host = format!("{addr}");

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
            inbound_allowed_sender: "49".to_string(),
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
    async fn pipeline_error_retains_inbound_spool_for_recovery() {
        let home = tempfile::tempdir().unwrap();
        let spool_dir = inbound_spool_dir_at(home.path());
        let raw = r#"{"object":"whatsapp_business_account","entry":[{"id":"W","changes":[{"field":"messages","value":{"metadata":{"phone_number_id":"PN","display_phone_number":"+49"},"contacts":[{"profile":{"name":"S"},"wa_id":"49"}],"messages":[{"from":"49","id":"wamid.PIPELINE-ERR","timestamp":"1700000000","type":"text","text":{"body":"hi"}}]}}]}]}"#;
        let path = spool_inbound_body_at(&spool_dir, "wamid.PIPELINE-ERR", raw, "meta").unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_pipeline = Arc::clone(&calls);
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: Vec::new(),
            meta_verify_token: String::new(),
            slack_signing_secret: Vec::new(),
            pipeline: Box::new(move |_| {
                let calls = Arc::clone(&calls_for_pipeline);
                Box::pin(async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    anyhow::bail!("retryable pipeline failure")
                })
            }),
            inbound_allowed_sender: "49".into(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };

        drain_inbound_spool_at(&cfg, &spool_dir).await;

        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            path.exists(),
            "retryable pipeline failure must retain inbound"
        );
        assert!(!webhook_outbox_dir_at(home.path()).exists());
    }

    #[tokio::test]
    async fn failed_send_retries_from_outbox_without_rerunning_pipeline() {
        use wiremock::matchers::{method, path as request_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let failing = MockServer::start().await;
        Mock::given(method("POST"))
            .and(request_path("/123/messages"))
            .respond_with(ResponseTemplate::new(500).set_body_string(
                r#"{"error":{"message":"temporary","type":"ApiException","code":2}}"#,
            ))
            .expect(1)
            .mount(&failing)
            .await;
        let home = tempfile::tempdir().unwrap();
        let spool_dir = inbound_spool_dir_at(home.path());
        let outbox_dir = webhook_outbox_dir_at(home.path());
        let raw = r#"{"object":"whatsapp_business_account","entry":[{"id":"W","changes":[{"field":"messages","value":{"metadata":{"phone_number_id":"PN","display_phone_number":"+49"},"contacts":[{"profile":{"name":"S"},"wa_id":"49"}],"messages":[{"from":"49","id":"wamid.OUTBOX","timestamp":"1700000000","type":"text","text":{"body":"hi"}}]}}]}]}"#;
        let inbound = spool_inbound_body_at(&spool_dir, "wamid.OUTBOX", raw, "meta").unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_pipeline = Arc::clone(&calls);
        let pipeline: PipelineHandler = Box::new(move |_| {
            let calls = Arc::clone(&calls_for_pipeline);
            Box::pin(async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Some(crate::channels::OutboundMessage {
                    recipient_id: "+4900000".into(),
                    text: "durable reply".into(),
                }))
            })
        });
        let first_cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: Vec::new(),
            meta_verify_token: String::new(),
            slack_signing_secret: Vec::new(),
            pipeline,
            inbound_allowed_sender: "49".into(),
            whatsapp_send_creds: Some(WhatsAppSendCreds {
                access_token: crate::secret::SecretString::from("token"),
                phone_number_id: "123".into(),
                base_url: Some(failing.uri()),
            }),
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        drain_inbound_spool_at(&first_cfg, &spool_dir).await;
        assert!(
            !inbound.exists(),
            "durable outbox owns the completed pipeline turn"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(std::fs::read_dir(&outbox_dir).unwrap().count(), 1);

        // A restart must honor the persisted due time. Force it due without a
        // wall-clock sleep so this regression remains fast and deterministic.
        let pending_path = std::fs::read_dir(&outbox_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut pending = load_outbox_record(&pending_path).unwrap();
        assert_eq!(pending.attempts, 1);
        assert!(pending.transport_next_attempt_at.is_some());
        assert_eq!(pending.last_failure.as_deref(), Some("meta_server_error"));
        pending.transport_next_attempt_at = Some(0);
        persist_outbox_record(&pending_path, &pending).unwrap();

        let succeeding = MockServer::start().await;
        Mock::given(method("POST"))
            .and(request_path("/123/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"contacts":[{"wa_id":"49000"}],"messages":[{"id":"wamid.RETRY-OK"}]}"#,
            ))
            .expect(1)
            .mount(&succeeding)
            .await;
        let second_cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: Vec::new(),
            meta_verify_token: String::new(),
            slack_signing_secret: Vec::new(),
            pipeline: Box::new(|_| Box::pin(async { anyhow::bail!("pipeline must not rerun") })),
            inbound_allowed_sender: "49".into(),
            whatsapp_send_creds: Some(WhatsAppSendCreds {
                access_token: crate::secret::SecretString::from("token"),
                phone_number_id: "123".into(),
                base_url: Some(succeeding.uri()),
            }),
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };
        drain_webhook_outbox_at(&second_cfg, &outbox_dir, OutboxChannel::Meta).await;

        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(std::fs::read_dir(&outbox_dir).unwrap().count(), 1);
        let receipt_path = std::fs::read_dir(&outbox_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let receipt = load_outbox_record(&receipt_path).unwrap();
        assert!(matches!(receipt.state, OutboxState::Complete));
        assert!(receipt.recipient_id.is_empty());
        assert!(receipt.body.is_empty());
        assert!(receipt.inbound_spool_name.is_none());

        // Simulate provider redelivery after restart. The durable source-key
        // receipt must consume the new inbound spool without rerunning either
        // the model/tools pipeline or the provider transport.
        let duplicate = spool_inbound_body_at(&spool_dir, "wamid.OUTBOX", raw, "meta").unwrap();
        drain_inbound_spool_at(&second_cfg, &spool_dir).await;
        assert!(!duplicate.exists());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(succeeding.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn meta_auth_rejection_is_quarantined_not_completed_or_retried() {
        use wiremock::matchers::{method, path as request_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(request_path("/123/messages"))
            .respond_with(ResponseTemplate::new(401).set_body_string(
                r#"{"error":{"message":"temporary-looking text","type":"ApiException","code":2}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let home = tempfile::tempdir().unwrap();
        let outbox = webhook_outbox_dir_at(home.path());
        let record = pending_outbox_fixture(OutboxChannel::Meta, "meta-auth-permanent");
        let (path, mut record) = stage_outbox_record(&outbox, &record).unwrap();
        let cfg = gated_cfg(SendGovernance::default(), Some(server.uri()));

        assert_eq!(
            deliver_outbox_record(&cfg, &path, &mut record).await,
            DeliveryOutcome::Quarantined
        );
        let persisted = load_outbox_record(&path).unwrap();
        assert!(matches!(
            persisted.state,
            OutboxState::Quarantined {
                ref reason,
                quarantined_at: _
            } if reason == "meta_auth_rejected"
        ));
        assert!(!matches!(persisted.state, OutboxState::Complete));
        assert_eq!(persisted.attempts, 1);
        assert_eq!(persisted.transport_next_attempt_at, None);

        let mut restarted = load_outbox_record(&path).unwrap();
        assert_eq!(
            deliver_outbox_record(&cfg, &path, &mut restarted).await,
            DeliveryOutcome::Quarantined
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn meta_rate_limit_persists_retry_after_across_restart() {
        use wiremock::matchers::{method, path as request_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(request_path("/123/messages"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "120")
                    .set_body_string(
                        r#"{"error":{"message":"generic","type":"ApiException","code":4}}"#,
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        let home = tempfile::tempdir().unwrap();
        let outbox = webhook_outbox_dir_at(home.path());
        let record = pending_outbox_fixture(OutboxChannel::Meta, "meta-rate-limited");
        let (path, mut record) = stage_outbox_record(&outbox, &record).unwrap();
        let cfg = gated_cfg(SendGovernance::default(), Some(server.uri()));
        let before = crate::time::now_unix_secs();

        assert_eq!(
            deliver_outbox_record(&cfg, &path, &mut record).await,
            DeliveryOutcome::TransportRetry
        );
        let mut restarted = load_outbox_record(&path).unwrap();
        let due = restarted.transport_next_attempt_at.unwrap();
        assert!(due >= before + 120);
        assert!(due <= crate::time::now_unix_secs() + WEBHOOK_RETRY_MAX_SECS);
        assert_eq!(restarted.last_failure.as_deref(), Some("meta_rate_limited"));
        assert_eq!(
            deliver_outbox_record(&cfg, &path, &mut restarted).await,
            DeliveryOutcome::BackoffWait
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn line_rate_limit_persists_capped_retry_after_across_restart() {
        use wiremock::matchers::{method, path as request_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(request_path("/v2/bot/message/push"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "120"))
            .expect(1)
            .mount(&server)
            .await;
        let home = tempfile::tempdir().unwrap();
        let outbox = webhook_outbox_dir_at(home.path());
        let record = pending_outbox_fixture(OutboxChannel::Line, "line-rate-limited");
        let (path, mut record) = stage_outbox_record(&outbox, &record).unwrap();
        let cfg = gated_line_cfg(SendGovernance::default(), Some(server.uri()));
        let before = crate::time::now_unix_secs();

        assert_eq!(
            deliver_outbox_record(&cfg, &path, &mut record).await,
            DeliveryOutcome::TransportRetry
        );
        let mut restarted = load_outbox_record(&path).unwrap();
        let due = restarted.transport_next_attempt_at.unwrap();
        assert!(due >= before + 120);
        assert!(due <= crate::time::now_unix_secs() + WEBHOOK_RETRY_MAX_SECS);
        assert_eq!(restarted.attempts, 1);
        assert_eq!(restarted.last_failure.as_deref(), Some("line_rate_limited"));
        assert_eq!(
            deliver_outbox_record(&cfg, &path, &mut restarted).await,
            DeliveryOutcome::BackoffWait
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn missing_credentials_waits_without_attempt_or_audit_spam() {
        let home = tempfile::tempdir().unwrap();
        let outbox = webhook_outbox_dir_at(home.path());
        let record = pending_outbox_fixture(OutboxChannel::Meta, "meta-config-wait");
        let (path, mut record) = stage_outbox_record(&outbox, &record).unwrap();
        let mut cfg = gated_cfg(SendGovernance::default(), None);
        cfg.whatsapp_send_creds = None;

        assert_eq!(
            deliver_outbox_record(&cfg, &path, &mut record).await,
            DeliveryOutcome::MissingCredentials
        );
        let mut restarted = load_outbox_record(&path).unwrap();
        assert!(matches!(
            restarted.state,
            OutboxState::WaitingForConfiguration { .. }
        ));
        assert_eq!(restarted.attempts, 0);
        assert_eq!(restarted.audit_attempts, 0);
        assert_eq!(restarted.transport_next_attempt_at, None);
        assert_eq!(
            deliver_outbox_record(&cfg, &path, &mut restarted).await,
            DeliveryOutcome::MissingCredentials
        );
        let persisted = load_outbox_record(&path).unwrap();
        assert_eq!(persisted.attempts, 0);
        assert_eq!(persisted.audit_attempts, 0);
    }

    #[test]
    fn outbox_v1_without_retry_metadata_remains_readable() {
        let record = pending_outbox_fixture(OutboxChannel::Meta, "legacy-v1-outbox");
        let mut value = serde_json::to_value(record).unwrap();
        let object = value.as_object_mut().unwrap();
        for field in [
            "audit_attempts",
            "transport_next_attempt_at",
            "audit_next_attempt_at",
            "last_failure",
        ] {
            object.remove(field);
        }
        let decoded: WebhookOutboxRecord = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.attempts, 0);
        assert_eq!(decoded.audit_attempts, 0);
        assert_eq!(decoded.transport_next_attempt_at, None);
        assert_eq!(decoded.audit_next_attempt_at, None);
        assert_eq!(decoded.last_failure, None);
    }

    #[tokio::test]
    async fn terminal_deny_cleans_inbound_and_retains_scrubbed_receipt() {
        use wiremock::MockServer;
        let server = MockServer::start().await;
        let home = tempfile::tempdir().unwrap();
        let spool_dir = inbound_spool_dir_at(home.path());
        let raw = r#"{"object":"whatsapp_business_account","entry":[{"id":"W","changes":[{"field":"messages","value":{"metadata":{"phone_number_id":"PN","display_phone_number":"+49"},"contacts":[{"profile":{"name":"S"},"wa_id":"49"}],"messages":[{"from":"49","id":"wamid.DENY","timestamp":"1700000000","type":"text","text":{"body":"hi"}}]}}]}]}"#;
        let inbound = spool_inbound_body_at(&spool_dir, "wamid.DENY", raw, "meta").unwrap();
        let mut cfg = gated_cfg(
            SendGovernance {
                decision: crate::permissions::Decision::Deny("operator policy".into()),
                ..Default::default()
            },
            Some(server.uri()),
        );
        cfg.inbound_allowed_sender = "49".into();

        assert!(drain_one_spool_entry(&cfg, inbound.clone(), "meta").await);
        assert!(!inbound.exists());
        let outbox = webhook_outbox_dir_at(home.path());
        assert_eq!(std::fs::read_dir(&outbox).unwrap().count(), 1);
        let receipt_path = std::fs::read_dir(&outbox)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let receipt = load_outbox_record(&receipt_path).unwrap();
        assert!(matches!(receipt.state, OutboxState::Complete));
        assert!(receipt.recipient_id.is_empty());
        assert!(receipt.body.is_empty());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn outbox_recovery_drains_multiple_line_records() {
        use wiremock::matchers::{method, path as request_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(request_path("/v2/bot/message/push"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"sentMessages":[{"id":"line-recovered"}]}"#),
            )
            .expect(2)
            .mount(&server)
            .await;
        let home = tempfile::tempdir().unwrap();
        let outbox_dir = webhook_outbox_dir_at(home.path());
        for index in 0..2 {
            let body = format!("reply {index}");
            let record = WebhookOutboxRecord {
                version: WEBHOOK_OUTBOX_VERSION,
                channel: OutboxChannel::Line,
                source_key: sha256_hex(format!("line-{index}").as_bytes()),
                recipient_id: "Urecipient".into(),
                body_sha256: sha256_hex(body.as_bytes()),
                body,
                attempts: 0,
                audit_attempts: 0,
                transport_next_attempt_at: None,
                audit_next_attempt_at: None,
                last_failure: None,
                state: OutboxState::PendingSend,
                inbound_spool_name: None,
            };
            stage_outbox_record(&outbox_dir, &record).unwrap();
        }
        let cfg = gated_line_cfg(SendGovernance::default(), Some(server.uri()));

        drain_webhook_outbox_at(&cfg, &outbox_dir, OutboxChannel::Line).await;

        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        assert_eq!(std::fs::read_dir(outbox_dir).unwrap().count(), 2);
    }

    #[tokio::test]
    async fn spool_recovery_continues_past_the_first_bounded_batch() {
        let home = tempfile::tempdir().unwrap();
        let spool_dir = inbound_spool_dir_at(home.path());
        for index in 0..=MAX_SPOOL_DRAIN_FILES {
            let message_id = format!("wamid.BATCH.{index:05}");
            let raw = format!(
                r#"{{"object":"whatsapp_business_account","entry":[{{"id":"W","changes":[{{"field":"messages","value":{{"metadata":{{"phone_number_id":"PN","display_phone_number":"+49"}},"contacts":[{{"profile":{{"name":"S"}},"wa_id":"49"}}],"messages":[{{"from":"49","id":"{message_id}","timestamp":"1700000000","type":"text","text":{{"body":"hi"}}}}]}}}}]}}]}}"#
            );
            spool_inbound_body_at(&spool_dir, &message_id, &raw, "meta").unwrap();
        }

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
            inbound_allowed_sender: "49".to_string(),
            whatsapp_send_creds: None,
            send_governance: SendGovernance::default(),
            max_concurrent_connections: None,
            dispatch_join: None,
        };

        drain_inbound_spool_at(&cfg, &spool_dir).await;
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            MAX_SPOOL_DRAIN_FILES + 1,
            "every survivor must be replayed even when recovery needs multiple batches"
        );
        assert_eq!(std::fs::read_dir(&spool_dir).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn spool_recovery_never_crosses_meta_and_line_policy_boundaries() {
        let home = tempfile::tempdir().unwrap();
        let spool_dir = inbound_spool_dir_at(home.path());
        let raw = r#"{"destination":"Ubot","events":[{"type":"message","mode":"active","timestamp":1625665242211,"source":{"type":"user","userId":"Ualice"},"replyToken":"rt","webhookEventId":"01FZ","deliveryContext":{"isRedelivery":false},"message":{"id":"m1","type":"text","text":"hello"}}]}"#;
        let path = spool_inbound_body_at(&spool_dir, "01FZ", raw, "line").unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let meta_cfg = counting_listener_cfg(
            "Ualice",
            std::sync::Arc::clone(&calls),
            SendGovernance::default(),
        );
        drain_inbound_spool_at(&meta_cfg, &spool_dir).await;
        assert!(
            path.exists(),
            "Meta startup must leave LINE survivors alone"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        let mut line_cfg = counting_listener_cfg(
            "Ualice",
            std::sync::Arc::clone(&calls),
            SendGovernance::default(),
        );
        line_cfg.line = Some(LineConfig {
            channel_secret: b"line-secret".to_vec(),
            access_token: crate::secret::SecretString::from("line-token"),
            base_url: None,
        });
        drain_inbound_spool_at(&line_cfg, &spool_dir).await;
        assert!(!path.exists(), "LINE startup must consume its own survivor");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
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

        let home = tempfile::tempdir().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            inbound_dedup: None,
            line: None,
            meta_app_secret: b"appsecret".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline,
            inbound_allowed_sender: "49".to_string(),
            whatsapp_send_creds: None,
            send_governance: isolated_test_governance(home.path()),
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
        let host = format!("{addr}");

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
            inbound_allowed_sender: String::new(),
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
        let host = format!("{addr}");

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
            inbound_allowed_sender: String::new(),
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
        let host = format!("{addr}");
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
            inbound_allowed_sender: String::new(),
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
        let host = format!("{addr}");
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
            inbound_allowed_sender: String::new(),
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
        let host = format!("{addr}");

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
            if let Ok(Ok(status)) = h.await
                && status == reqwest::StatusCode::TOO_MANY_REQUESTS
            {
                saw_429 = true;
                break;
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
            inbound_allowed_sender: String::new(),
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
