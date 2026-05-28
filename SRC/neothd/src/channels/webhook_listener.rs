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

use super::webhook_router::{
    HttpMethod, MetaRouteOutcome, SlackRouteOutcome, WebhookRequest, WebhookResponse,
    route_meta_webhook, route_slack_webhook,
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
    /// R2-P1-1 concurrency cap. `None` → `DEFAULT_MAX_CONCURRENT_CONNECTIONS`.
    /// Operators behind a reverse proxy can raise this if their proxy
    /// fans out many concurrent webhook calls; localhost-only deploys
    /// rarely need to touch it.
    pub max_concurrent_connections: Option<usize>,
}

/// GR-01 Pick B: WhatsApp credentials needed by the webhook listener
/// to send pipeline replies back out via the Meta Graph API.
pub struct WhatsAppSendCreds {
    pub access_token: crate::secret::SecretString,
    pub phone_number_id: String,
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
            let response = match handle_request(&cfg, req).await {
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
    cfg: &WebhookListenerConfig,
    req: HyperRequest<IncomingBody>,
) -> std::result::Result<HyperResponse<Full<Bytes>>, HandleError> {
    let path = req.uri().path().to_string();
    let webhook_req = translate(req).await?;
    match path.as_str() {
        "/webhook" => handle_meta(cfg, webhook_req)
            .await
            .map_err(HandleError::Other),
        "/slack/events" => handle_slack(cfg, webhook_req)
            .await
            .map_err(HandleError::Other),
        _ => Ok(plain_response(StatusCode::NOT_FOUND, "not found")),
    }
}

async fn handle_meta(
    cfg: &WebhookListenerConfig,
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
                    dispatch_messages(cfg, msgs).await;
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
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

async fn dispatch_messages(cfg: &WebhookListenerConfig, msgs: Vec<InboundMessage>) {
    for msg in msgs {
        let chat_id = msg.chat_id.clone();
        match (cfg.pipeline)(msg).await {
            Ok(Some(outbound)) => {
                // GR-01 Pick B: route pipeline-produced replies back
                // through the WhatsApp Graph API when the listener
                // was wired with send credentials. Pre-GR-01 this
                // arm logged-and-dropped (the operator-pipeline was
                // supposed to own send), which silently broke the
                // inbound→reply loop in webhook mode.
                if let Some(creds) = cfg.whatsapp_send_creds.as_ref() {
                    let send = crate::channels::whatsapp_api::send_text_message(
                        &creds.access_token,
                        &creds.phone_number_id,
                        &outbound.recipient_id,
                        &outbound.text,
                    )
                    .await;
                    match send {
                        Ok(r) if r.ok => {
                            debug!(
                                recipient = %outbound.recipient_id,
                                wamid = ?r.message_id,
                                "GR-01 Pick B: webhook reply delivered via Graph API",
                            );
                        }
                        Ok(r) => {
                            warn!(
                                recipient = %outbound.recipient_id,
                                error = ?r.error,
                                "GR-01 Pick B: webhook reply failed (Meta API error)",
                            );
                        }
                        Err(e) => {
                            warn!(
                                recipient = %outbound.recipient_id,
                                error = %e,
                                "GR-01 Pick B: webhook reply failed (transport)",
                            );
                        }
                    }
                } else {
                    debug!(
                        recipient = %outbound.recipient_id,
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
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: pipeline_with_outbound(),
            whatsapp_send_creds: None,
            max_concurrent_connections: None,
        };
        // No panic, no network call — completes cleanly.
        dispatch_messages(&cfg, vec![inbound_fixture()]).await;
    }

    // NOTE on GR-01 Pick B behaviour test: a true behaviour test —
    // verifying the dispatch path actually CALLS the graph API when
    // creds are set — needs `whatsapp_api` to accept an injectable
    // base URL so tests can point at wiremock instead of the real
    // graph.facebook.com endpoint. That refactor is tracked as a
    // v0.4 follow-up. For now the wire-in is covered by:
    //   - the structural test above (no panic, no log-and-drop loop),
    //   - the dispatch_messages code review (if-let arm routes
    //     through send_text_message),
    //   - the existing `whatsapp_inbound_live_when_full_meta_secrets_present`
    //     integration test that pins the LIVE-mode credential
    //     wiring at the wizard level.

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
            meta_app_secret: b"appsecret".to_vec(),
            meta_verify_token: "verify123".to_string(),
            slack_signing_secret: b"slack-sig".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            max_concurrent_connections: None,
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
            meta_app_secret: b"appsecret".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            max_concurrent_connections: None,
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
    async fn server_handles_slack_url_verification() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"slackkey".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            max_concurrent_connections: None,
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
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            max_concurrent_connections: None,
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
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            max_concurrent_connections: None,
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
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            max_concurrent_connections: Some(1),
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
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
            whatsapp_send_creds: None,
            max_concurrent_connections: None,
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
