//! GOLD-ADAPT-HERMES-08 — Kanban SSE (Server-Sent Events) endpoint.
//!
//! Binds `127.0.0.1:9432` (default, configurable via
//! `freedom.yaml::kanban_sse.port`) when `kanban_sse.enabled = true`.
//! Responds to `GET /kanban/events` with a `text/event-stream` that:
//!
//! 1. Streams the full `idx_kanban_task_event` history as an initial
//!    `event: snapshot` batch — one `data:{json}\n\n` frame per row.
//! 2. Tails live [`FeedEntry`] frames from the shared broadcast channel.
//!
//! Auth: bearer-token pattern identical to n8n_api (constant-time compare
//! against `~/.neoth/n8n_api_token`); 401 otherwise.
//! Loopback-only: bind is 127.0.0.1 and the accept loop rejects non-loopback
//! peers as defence-in-depth.
//!
//! Cancellation: the accept loop exits when `shutdown.notified()`.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::Stream;
use http_body_util::{Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{Notify, broadcast, mpsc};

use crate::coding::feed::FeedEntry;
use crate::config::FreedomConfig;

// ── Body type ──────────────────────────────────────────────────────────────

/// Response body for both SSE streams and small error/404 responses.
pub enum SseBody {
    Full(Full<Bytes>),
    #[allow(clippy::type_complexity)]
    Stream(StreamBody<Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, Infallible>> + Send>>>),
}

impl hyper::body::Body for SseBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            SseBody::Full(inner) => Pin::new(inner).poll_frame(cx),
            SseBody::Stream(inner) => Pin::new(inner).poll_frame(cx),
        }
    }
}

fn plain_response(status: StatusCode, msg: &'static str) -> Response<SseBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(SseBody::Full(Full::new(Bytes::from_static(msg.as_bytes()))))
        .expect("static response always builds")
}

// ── Shared state ───────────────────────────────────────────────────────────

/// Shared state injected into every SSE handler connection.
pub struct SseState {
    pub config: Arc<FreedomConfig>,
    /// Broadcast channel: live [`FeedEntry`] frames from store mutations.
    /// Each SSE connection subscribes a new Receiver for fan-out.
    pub tx: Arc<broadcast::Sender<FeedEntry>>,
    /// NEOTH home directory — used to open `views.db` for the snapshot.
    pub home: PathBuf,
    /// Bearer token loaded from `~/.neoth/n8n_api_token`.
    pub token: String,
}

// ── Server ─────────────────────────────────────────────────────────────────

/// Spawn the SSE server task.
pub fn spawn_server(
    state: Arc<SseState>,
    shutdown: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    let port = state.config.kanban_sse.port;
    tokio::spawn(async move {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    port = port,
                    error = %e,
                    "kanban_sse bind failed; SSE endpoint not available this session"
                );
                return;
            }
        };
        tracing::info!(port = port, "kanban_sse listening on 127.0.0.1");
        loop {
            let accept = tokio::select! {
                biased;
                _ = shutdown.notified() => {
                    tracing::info!("kanban_sse shutdown signal; draining");
                    break;
                }
                res = listener.accept() => res,
            };
            let (stream, peer) = match accept {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "kanban_sse accept error");
                    continue;
                }
            };
            if !peer.ip().is_loopback() {
                tracing::warn!(peer = %peer, "kanban_sse rejected non-loopback peer");
                continue;
            }
            let state_for_conn = Arc::clone(&state);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let s = Arc::clone(&state_for_conn);
                    async move { Ok::<_, Infallible>(handle(req, s).await) }
                });
                if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                    tracing::debug!(error = %e, "kanban_sse connection closed");
                }
            });
        }
    })
}

// ── Request handler ────────────────────────────────────────────────────────

async fn handle(req: Request<Incoming>, state: Arc<SseState>) -> Response<SseBody> {
    let auth = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let provided = crate::n8n_api::extract_bearer_token(auth).unwrap_or("");
    if !crate::n8n_api::constant_time_token_eq(provided, &state.token) {
        return plain_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    match req.uri().path() {
        "/kanban/events" => sse_stream(state).await,
        _ => plain_response(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn sse_stream(state: Arc<SseState>) -> Response<SseBody> {
    // Subscribe before reading snapshot so we never miss a concurrent event.
    let mut rx = state.tx.subscribe();
    let home = state.home.clone();

    // Phase 1 — initial snapshot from views.db (blocking rusqlite in
    // spawn_blocking so the async reactor is not blocked).
    let snapshot_frames: Vec<Bytes> = tokio::task::spawn_blocking(move || {
        let db_path = home.join("views.db");
        let conn = match rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %db_path.display(),
                    error = %e,
                    "kanban_sse: views.db unavailable; snapshot empty"
                );
                return vec![];
            }
        };
        match crate::coding::store::list_all_task_events(&conn) {
            Ok(events) => events
                .into_iter()
                .filter_map(|ev| {
                    serde_json::to_string(&ev)
                        .ok()
                        .map(|json| Bytes::from(format!("event: snapshot\ndata:{json}\n\n")))
                })
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "kanban_sse: list_all_task_events failed");
                vec![]
            }
        }
    })
    .await
    .unwrap_or_default();

    // Phase 2 — bridge the broadcast::Receiver to an mpsc so we can
    // drive it from a spawned task feeding an mpsc::Receiver<Bytes>.
    // Using mpsc avoids the `tokio-stream/sync` feature requirement.
    let (line_tx, line_rx) = mpsc::channel::<Bytes>(128);

    // Forwarder task: drain broadcast::Receiver into the mpsc sender.
    // When the client disconnects, line_tx.send() fails → task exits.
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    let json = match serde_json::to_string(&entry) {
                        Ok(j) => j,
                        Err(_) => continue,
                    };
                    let line = Bytes::from(format!("data:{json}\n\n"));
                    if line_tx.send(line).await.is_err() {
                        break; // client disconnected
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Some frames were missed; continue — clients reconnect for
                    // consistency if they care (SSE reconnect is idiomatic).
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Build a unified async stream from snapshot_frames + live line_rx.
    let snapshot_stream = futures_util::stream::iter(
        snapshot_frames
            .into_iter()
            .map(|b| Ok::<Frame<Bytes>, Infallible>(Frame::data(b))),
    );

    let live_stream = futures_util::stream::unfold(line_rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|b| (Ok::<Frame<Bytes>, Infallible>(Frame::data(b)), rx))
    });

    let combined: Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, Infallible>> + Send>> =
        Box::pin(futures_util::StreamExt::chain(snapshot_stream, live_stream));

    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/event-stream")
        .header(hyper::header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(SseBody::Stream(StreamBody::new(combined)))
        .unwrap_or_else(|_| plain_response(StatusCode::INTERNAL_SERVER_ERROR, "build failed"))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use tokio::sync::broadcast;
    use tokio::time::timeout;

    fn make_state(
        home: std::path::PathBuf,
        tx: Arc<broadcast::Sender<FeedEntry>>,
    ) -> Arc<SseState> {
        use crate::config::FreedomConfig;
        let mut cfg = FreedomConfig::default();
        cfg.kanban_sse.enabled = true;
        cfg.kanban_sse.port = 0;
        Arc::new(SseState {
            config: Arc::new(cfg),
            tx,
            home,
            token: "test-token".to_string(),
        })
    }

    #[test]
    fn auth_helper_rejects_wrong_token() {
        assert!(!crate::n8n_api::constant_time_token_eq("wrong", "test-token"));
        assert!(!crate::n8n_api::constant_time_token_eq("", "test-token"));
        assert!(crate::n8n_api::constant_time_token_eq(
            "test-token",
            "test-token"
        ));
    }

    #[test]
    fn extract_bearer_strips_prefix() {
        assert_eq!(
            crate::n8n_api::extract_bearer_token("Bearer test-token"),
            Some("test-token")
        );
        assert_eq!(crate::n8n_api::extract_bearer_token(""), None);
    }

    /// Missing views.db → spawn_blocking open in read-only fails gracefully.
    #[tokio::test]
    async fn snapshot_missing_db_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let db_path = home.join("views.db");
            rusqlite::Connection::open_with_flags(
                &db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .ok()
        })
        .await
        .unwrap();
        assert!(
            result.is_none(),
            "missing db should fail to open in read-only mode"
        );
    }

    /// insert_task_event writes to DB and fires broadcast.
    #[tokio::test]
    async fn insert_task_event_db_and_broadcast() {
        use crate::coding::store;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        store::ensure_schema(&conn).unwrap();

        let sid = store::insert_session(&conn, 1000, "test", "hash", "ch", None).unwrap();
        let tid = store::insert_task(&conn, sid, 1001, "t1", None, "code", None).unwrap();

        let (tx, mut rx) = broadcast::channel::<FeedEntry>(16);
        let payload = r#"{"task_id":1,"new_status":"in_progress"}"#;
        store::insert_task_event(&conn, tid.raw(), 0x73, payload, 2000, Some(&tx)).unwrap();

        let events = store::list_task_events(&conn, tid.raw()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, 0x73);
        assert_eq!(events[0].payload_json, payload);

        let entry = timeout(Duration::from_millis(200), async { rx.recv().await })
            .await
            .expect("broadcast timed out")
            .expect("recv");
        assert_eq!(entry.event_type, 0x73);
    }

    /// Dep add + remove round-trip with broadcast events.
    #[tokio::test]
    async fn task_dep_add_remove_roundtrip() {
        use crate::coding::store;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        store::ensure_schema(&conn).unwrap();

        let sid = store::insert_session(&conn, 1000, "test", "hash", "ch", None).unwrap();
        let t1 = store::insert_task(&conn, sid, 1001, "task1", None, "code", None).unwrap();
        let t2 = store::insert_task(&conn, sid, 1002, "task2", None, "code", None).unwrap();

        let (tx, mut rx) = broadcast::channel::<FeedEntry>(32);

        store::insert_task_dep(&conn, t2.raw(), t1.raw(), 3000, Some(&tx)).unwrap();
        let deps = store::list_deps_for_task(&conn, t2.raw()).unwrap();
        assert_eq!(deps, vec![t1.raw()]);

        let added = timeout(Duration::from_millis(200), async { rx.recv().await })
            .await
            .expect("add broadcast timeout")
            .expect("recv");
        assert_eq!(added.event_type, 0x78, "should be DEP_ADDED");

        store::remove_task_dep(&conn, t2.raw(), t1.raw(), 4000, Some(&tx)).unwrap();
        let deps_after = store::list_deps_for_task(&conn, t2.raw()).unwrap();
        assert!(deps_after.is_empty());

        let removed = timeout(Duration::from_millis(200), async { rx.recv().await })
            .await
            .expect("remove broadcast timeout")
            .expect("recv");
        assert_eq!(removed.event_type, 0x79, "should be DEP_REMOVED");
    }

    /// list_all_task_events returns rows from multiple tasks in ts order.
    #[tokio::test]
    async fn list_all_task_events_spans_tasks() {
        use crate::coding::store;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        store::ensure_schema(&conn).unwrap();

        let sid = store::insert_session(&conn, 1000, "test", "hash", "ch", None).unwrap();
        let t1 = store::insert_task(&conn, sid, 1001, "task1", None, "code", None).unwrap();
        let t2 = store::insert_task(&conn, sid, 1002, "task2", None, "code", None).unwrap();

        store::insert_task_event(&conn, t1.raw(), 0x73, r#"{"a":1}"#, 1000, None).unwrap();
        store::insert_task_event(&conn, t2.raw(), 0x74, r#"{"b":2}"#, 2000, None).unwrap();

        let all = store::list_all_task_events(&conn).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].task_id, t1.raw());
        assert_eq!(all[1].task_id, t2.raw());
    }

    /// End-to-end: spawn SSE server, connect, verify 401 on wrong token.
    #[tokio::test]
    async fn sse_server_rejects_bad_token() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = broadcast::channel::<FeedEntry>(4);
        let shutdown = Arc::new(Notify::new());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut cfg = crate::config::FreedomConfig::default();
        cfg.kanban_sse.port = port;
        cfg.kanban_sse.enabled = true;
        let state = Arc::new(SseState {
            config: Arc::new(cfg),
            tx: Arc::new(tx),
            home: dir.path().to_path_buf(),
            token: "secret".to_string(),
        });

        let shutdown2 = Arc::clone(&shutdown);
        let state2 = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let accept = tokio::select! {
                    biased;
                    _ = shutdown2.notified() => break,
                    r = listener.accept() => r,
                };
                let (stream, peer) = match accept {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if !peer.ip().is_loopback() { continue; }
                let s = Arc::clone(&state2);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let s2 = Arc::clone(&s);
                        async move { Ok::<_, Infallible>(handle(req, s2).await) }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{port}/kanban/events"))
            .header("Authorization", "Bearer wrong-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

        shutdown.notify_waiters();
    }

    /// End-to-end: correct token + valid events → 200 + SSE frames received.
    #[tokio::test]
    async fn sse_server_streams_broadcast_entry() {
        use crate::coding::store;

        let dir = tempfile::tempdir().unwrap();
        // Seed views.db with one event so the snapshot is non-empty.
        {
            let db_path = dir.path().join("views.db");
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            store::ensure_schema(&conn).unwrap();
            let sid = store::insert_session(&conn, 1000, "test", "hash", "ch", None).unwrap();
            let tid = store::insert_task(&conn, sid, 1001, "t1", None, "code", None).unwrap();
            store::insert_task_event(&conn, tid.raw(), 0x73, r#"{"x":1}"#, 1000, None).unwrap();
        }

        let (tx, _) = broadcast::channel::<FeedEntry>(16);
        let tx_arc = Arc::new(tx);
        let shutdown = Arc::new(Notify::new());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut cfg = crate::config::FreedomConfig::default();
        cfg.kanban_sse.port = port;
        cfg.kanban_sse.enabled = true;
        let state = Arc::new(SseState {
            config: Arc::new(cfg),
            tx: Arc::clone(&tx_arc),
            home: dir.path().to_path_buf(),
            token: "secret".to_string(),
        });

        let shutdown2 = Arc::clone(&shutdown);
        let state2 = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let accept = tokio::select! {
                    biased;
                    _ = shutdown2.notified() => break,
                    r = listener.accept() => r,
                };
                let (stream, peer) = match accept {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if !peer.ip().is_loopback() { continue; }
                let s = Arc::clone(&state2);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let s2 = Arc::clone(&s);
                        async move { Ok::<_, Infallible>(handle(req, s2).await) }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let client = reqwest::Client::new();
        let mut response = client
            .get(format!("http://127.0.0.1:{port}/kanban/events"))
            .header("Authorization", "Bearer secret")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        // Read the snapshot chunk (at least the one seeded event).
        let first_chunk = timeout(Duration::from_millis(500), response.chunk())
            .await
            .expect("snapshot chunk timeout")
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&first_chunk);
        assert!(
            text.contains("event: snapshot"),
            "expected snapshot frame, got: {text:?}"
        );

        shutdown.notify_waiters();
    }
}
