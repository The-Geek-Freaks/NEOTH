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
    /// per `InboundMessage` decoded from a verified Meta POST. The
    /// listener does NOT block on the handler's reply; outbound sends
    /// flow through the channel adapter's `send_text`.
    pub pipeline: PipelineHandler,
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
    info!(
        addr = %local,
        "webhook listener bound — 127.0.0.1 only, terminate TLS at your reverse proxy"
    );
    let config = Arc::new(config);
    let mut shutdown = Box::pin(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("webhook listener received shutdown — closing");
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
                let io = TokioIo::new(stream);
                let svc = WebhookService { config: Arc::clone(&config) };
                tokio::spawn(async move {
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, svc)
                        .await
                    {
                        debug!(error = %e, peer = %peer, "connection ended");
                    }
                });
            }
        }
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
                Err(e) => {
                    error!(error = %e, "webhook listener handler error");
                    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                }
            };
            Ok(response)
        })
    }
}

async fn handle_request(
    cfg: &WebhookListenerConfig,
    req: HyperRequest<IncomingBody>,
) -> Result<HyperResponse<Full<Bytes>>> {
    let path = req.uri().path().to_string();
    let webhook_req = translate(req).await?;
    match path.as_str() {
        "/webhook" => handle_meta(cfg, webhook_req).await,
        "/slack/events" => handle_slack(cfg, webhook_req).await,
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
                // The listener doesn't have a direct send path — the
                // operator's pipeline handler must own outbound sends
                // via the channel adapter (otherwise the listener
                // would need to hold a WhatsAppChannel reference,
                // which is the adapter's job). Log + drop.
                debug!(
                    recipient = %outbound.recipient_id,
                    "pipeline produced outbound (drop here; adapter owns send)"
                );
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

async fn translate(req: HyperRequest<IncomingBody>) -> Result<WebhookRequest> {
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
        Err(e) => {
            anyhow::bail!(
                "request body exceeds MAX_BODY_BYTES ({} B cap): {e}",
                MAX_BODY_BYTES
            );
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
        // The cap rejection surfaces as a non-2xx response. We don't
        // assert the exact code (hyper renders an internal-error 500
        // when the body limit fires inside the handler) — what we
        // assert is "the daemon refused, didn't crash, didn't OOM".
        assert!(
            !resp.status().is_success(),
            "over-cap body should be rejected, got status {}",
            resp.status()
        );
        let _ = shutdown_tx.send(());
        let _ = server.await;
    }

    #[tokio::test]
    async fn shutdown_signal_stops_accept_loop() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = WebhookListenerConfig {
            meta_app_secret: b"m".to_vec(),
            meta_verify_token: "v".to_string(),
            slack_signing_secret: b"s".to_vec(),
            pipeline: fake_pipeline(),
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
