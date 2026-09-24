use super::*;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex as StdMutex};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Notify;

#[derive(Default)]
struct RecordingRuntime {
    calls: StdMutex<Vec<String>>,
}

impl RecordingRuntime {
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("recording runtime mutex poisoned")
            .clone()
    }

    fn record(&self, value: impl Into<String>) {
        self.calls
            .lock()
            .expect("recording runtime mutex poisoned")
            .push(value.into());
    }

    fn preflight_response() -> gui::GuiChatPreflightResponse {
        gui::GuiChatPreflightResponse {
            schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: "w690-boot".into(),
            preflight_id: gui::GuiChatOpaqueCapability("preflight-capability".into()),
            preflight_descriptor_digest: gui::GuiChatDigest("a".repeat(64)),
            consent_challenge: gui::GuiChatOpaqueCapability("server-only-challenge".into()),
            attachment_manifest: Vec::new(),
            consent: gui::GuiChatConsentPreflightState::Ready,
        }
    }
}

#[async_trait::async_trait]
impl gui::GuiChatRuntime for RecordingRuntime {
    async fn preflight(
        &self,
        request: gui::GuiChatPreflightRequest,
    ) -> gui::GuiChatResult<gui::GuiChatPreflightResponse> {
        self.record(format!(
            "preflight:{}:{}",
            request.session_id, request.message
        ));
        Ok(Self::preflight_response())
    }

    async fn decide(
        &self,
        request: gui::GuiChatConsentDecisionRequest,
    ) -> gui::GuiChatResult<gui::GuiChatConsentDecisionResponse> {
        self.record(format!("decide:{:?}", request.decision));
        Ok(match request.decision {
            gui::GuiChatConsentDecision::AllowOnce => {
                gui::GuiChatConsentDecisionResponse::Approved {
                    schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                    expected_boot_id: "w690-boot".into(),
                    turn_intent_digest: gui::GuiChatDigest("b".repeat(64)),
                    start_capability: gui::GuiChatOpaqueCapability("start-capability".into()),
                    attachment_tickets: Vec::new(),
                }
            }
            _ => gui::GuiChatConsentDecisionResponse::Denied {
                schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
                expected_boot_id: "w690-boot".into(),
            },
        })
    }

    async fn start(
        &self,
        request: gui::GuiChatStartRequest,
    ) -> gui::GuiChatResult<gui::GuiChatStartResponse> {
        self.record(format!("start:{}", request.session_id));
        let turn_id = gui::GuiChatTurnId(uuid::Uuid::now_v7());
        Ok(gui::GuiChatStartResponse {
            schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: "w690-boot".into(),
            turn_id: turn_id.clone(),
            turn_intent_digest: request.turn_intent_digest,
            origin_attach_capability: gui::GuiChatOpaqueCapability("origin-attach".into()),
            cancel_capability: gui::GuiChatOpaqueCapability("cancel-capability".into()),
            same_session_attach_grant: gui::GuiChatSameSessionAttachGrant {
                grant: gui::GuiChatOpaqueCapability("same-session-grant".into()),
                turn_id,
                session_id: request.session_id,
                allowed_surfaces: vec![gui::GuiChatSurface::WebChat],
            },
            initial_sequence: 7,
        })
    }

    async fn exchange_attach(
        &self,
        request: gui::GuiChatAttachExchangeRequest,
    ) -> gui::GuiChatResult<gui::GuiChatAttachExchangeResponse> {
        self.record(format!("exchange_attach:{}", request.session_id));
        Ok(gui::GuiChatAttachExchangeResponse {
            schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
            expected_boot_id: "w690-boot".into(),
            turn_id: request.turn_id,
            session_id: request.session_id,
            surface: gui::GuiChatSurface::WebChat,
            subscription_generation: 1,
            attach_capability: gui::GuiChatOpaqueCapability("attach-capability".into()),
            initial_sequence: 7,
        })
    }

    async fn attach(
        &self,
        _: crate::daemon::audit_rpc::AuditStream,
        _: gui::GuiChatAttachRequest,
    ) -> gui::GuiChatResult<()> {
        panic!("WebChat uses bounded replay, never a live AuditStream attach")
    }

    async fn replay(
        &self,
        request: gui::GuiChatAttachRequest,
    ) -> gui::GuiChatResult<Vec<gui::GuiChatStreamFrame>> {
        self.record(format!(
            "replay:{}:{}",
            request.session_id, request.after_sequence
        ));
        Ok(Vec::new())
    }

    async fn cancel(
        &self,
        request: gui::GuiChatCancelRequest,
    ) -> gui::GuiChatResult<gui::GuiChatCancelResponse> {
        self.record(format!("cancel:{}", request.session_id));
        Ok(gui::GuiChatCancelResponse {
            schema_version: gui::GUI_CHAT_V1_SCHEMA_VERSION,
            outcome: gui::GuiChatCancelOutcome::Accepted,
        })
    }

    async fn status(
        &self,
        _: gui::GuiChatStatusRequest,
    ) -> gui::GuiChatResult<gui::GuiChatStatusResponse> {
        panic!("unused by WebChat")
    }
    async fn active(
        &self,
        _: gui::GuiChatActiveRequest,
    ) -> gui::GuiChatResult<gui::GuiChatActiveResponse> {
        panic!("unused by WebChat")
    }
    async fn close_and_drain(&self) {}
}

async fn spawn_webchat(
    runtime: Arc<RecordingRuntime>,
) -> (
    String,
    Arc<WebChatState>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
    tempfile::TempDir,
) {
    let home = tempfile::tempdir().expect("test home");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("listener address").port();
    let state = Arc::new(WebChatState::new(
        port,
        home.path().to_path_buf(),
        "w690-boot".into(),
        runtime,
    ));
    state.set_listener_ready(true);
    let shutdown = Arc::new(Notify::new());
    let server_state = Arc::clone(&state);
    let server_shutdown = Arc::clone(&shutdown);
    let server = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = server_shutdown.notified() => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted.expect("test listener accept");
                    let state = Arc::clone(&server_state);
                    tokio::spawn(async move {
                        let service = service_fn(move |request| handle(request, Arc::clone(&state)));
                        let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
                    });
                }
            }
        }
    });
    (
        format!("http://127.0.0.1:{port}"),
        state,
        shutdown,
        server,
        home,
    )
}

async fn stop(shutdown: Arc<Notify>, server: tokio::task::JoinHandle<()>) {
    shutdown.notify_waiters();
    server.await.expect("test WebChat server task panicked");
}

async fn bootstrap(client: &reqwest::Client, base: &str, state: &WebChatState) -> String {
    let handoff = state.mint_handoff().await.expect("mint handoff").handoff;
    let response = client
        .post(format!("{base}/api/v1/webchat/bootstrap"))
        .header("Origin", base)
        .json(&serde_json::json!({"handoff":handoff}))
        .send()
        .await
        .expect("bootstrap HTTP");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("bootstrap cookie")
        .to_str()
        .expect("cookie utf8")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned()
}

async fn post(
    client: &reqwest::Client,
    base: &str,
    cookie: &str,
    path: &str,
    body: serde_json::Value,
) -> reqwest::Response {
    client
        .post(format!("{base}{path}"))
        .header("Origin", base)
        .header("Cookie", cookie)
        .json(&body)
        .send()
        .await
        .expect("WebChat HTTP")
}

async fn session_id_for_test(state: &WebChatState, cookie: &str) -> String {
    let value = cookie
        .strip_prefix("neoth_webchat=")
        .expect("WebChat cookie name");
    state
        .sessions
        .lock()
        .await
        .get(&digest_key(value))
        .expect("server session")
        .session_id
        .clone()
}

fn error_code(value: &serde_json::Value) -> &str {
    value["code"]
        .as_str()
        .expect("gateway errors are JSON code/message objects")
}

fn prepare_ready_consent_home(home: &std::path::Path) {
    let config = crate::config::FreedomConfig {
        provider_kind: Some(crate::cli::init::ProviderKind::ClaudeCli),
        provider_binary: Some("claude".into()),
        ..Default::default()
    };
    std::fs::write(
        home.join("freedom.yaml"),
        serde_yaml::to_string(&config).expect("serialize config"),
    )
    .expect("write config");
    crate::consent::prepare_grant_routes(
        home,
        &[crate::consent::ConsentRoute::new(
            crate::cli::init::ProviderKind::ClaudeCli,
            None,
        )],
    )
    .expect("prepare fixture consent")
    .commit()
    .expect("commit fixture consent");
}

async fn start_owned_request(client: &reqwest::Client, base: &str, cookie: &str) -> uuid::Uuid {
    let preflight = post(
        client,
        base,
        cookie,
        "/api/v1/webchat/preflight",
        serde_json::json!({"message":"W690 test", "incognito":false, "reasoning_display":false}),
    )
    .await;
    assert_eq!(preflight.status(), reqwest::StatusCode::OK);
    let request_id = preflight
        .json::<serde_json::Value>()
        .await
        .expect("preflight json")["request_id"]
        .as_str()
        .expect("request id")
        .parse()
        .expect("UUIDv7 request id");
    let decision = post(
        client,
        base,
        cookie,
        "/api/v1/webchat/decide",
        serde_json::json!({"request_id":request_id, "decision":"allow_once"}),
    )
    .await;
    assert_eq!(decision.status(), reqwest::StatusCode::OK);
    let start = post(
        client,
        base,
        cookie,
        "/api/v1/webchat/start",
        serde_json::json!({"request_id":request_id}),
    )
    .await;
    assert_eq!(start.status(), reqwest::StatusCode::OK);
    request_id
}

#[tokio::test]
async fn handoff_is_one_shot_and_expired_handoffs_never_reach_runtime() {
    let runtime = Arc::new(RecordingRuntime::default());
    let (base, state, shutdown, server, _home) = spawn_webchat(Arc::clone(&runtime)).await;
    let client = reqwest::Client::new();
    let handoff = state.mint_handoff().await.expect("mint handoff").handoff;
    let first = client
        .post(format!("{base}/api/v1/webchat/bootstrap"))
        .header("Origin", &base)
        .json(&serde_json::json!({"handoff":handoff}))
        .send()
        .await
        .expect("first bootstrap");
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let replay = client
        .post(format!("{base}/api/v1/webchat/bootstrap"))
        .header("Origin", &base)
        .json(&serde_json::json!({"handoff":handoff}))
        .send()
        .await
        .expect("replayed bootstrap");
    assert_eq!(replay.status(), reqwest::StatusCode::UNAUTHORIZED);
    let expired_handoff = state
        .mint_handoff()
        .await
        .expect("mint valid expiry fixture")
        .handoff;
    state
        .handoffs
        .lock()
        .await
        .get_mut(&digest_key(&expired_handoff))
        .expect("stored valid handoff")
        .expires_at = 1;
    let expired = client
        .post(format!("{base}/api/v1/webchat/bootstrap"))
        .header("Origin", &base)
        .json(&serde_json::json!({"handoff":expired_handoff}))
        .send()
        .await
        .expect("expired bootstrap");
    assert_eq!(expired.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        error_code(&expired.json().await.expect("expired handoff error json")),
        "unauthorized"
    );
    assert!(
        runtime.calls().is_empty(),
        "bootstrap authority must not invoke the runtime"
    );
    stop(shutdown, server).await;
}

#[tokio::test]
async fn companion_tokens_and_expired_or_unknown_cookies_are_rejected_before_runtime() {
    let runtime = Arc::new(RecordingRuntime::default());
    let (base, state, shutdown, server, _home) = spawn_webchat(Arc::clone(&runtime)).await;
    let client = reqwest::Client::new();
    let companion_token = client.post(format!("{base}/api/v1/webchat/preflight")).header("Origin", &base).bearer_auth("companion-pairing-token").json(&serde_json::json!({"message":"must not run", "incognito":false, "reasoning_display":false})).send().await.expect("token request");
    assert_eq!(companion_token.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        error_code(
            &companion_token
                .json()
                .await
                .expect("companion token error json")
        ),
        "unauthorized"
    );
    let cookie = bootstrap(&client, &base, &state).await;
    let value = cookie.strip_prefix("neoth_webchat=").expect("cookie name");
    let mut sessions = state.sessions.lock().await;
    let entry = sessions
        .get_mut(&digest_key(value))
        .expect("stored session");
    Arc::get_mut(entry)
        .expect("session has no outstanding clones")
        .expires_at = 1;
    drop(sessions);
    let expired_cookie = client.post(format!("{base}/api/v1/webchat/preflight")).header("Origin", &base).header("Cookie", &cookie).json(&serde_json::json!({"message":"must not run", "incognito":false, "reasoning_display":false})).send().await.expect("expired cookie request");
    assert_eq!(expired_cookie.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        error_code(
            &expired_cookie
                .json()
                .await
                .expect("expired cookie error json")
        ),
        "unauthorized"
    );
    assert!(
        runtime.calls().is_empty(),
        "authentication failures must precede runtime admission"
    );
    stop(shutdown, server).await;
}

#[tokio::test]
async fn transcript_is_session_scoped_and_bounded_through_the_real_database() {
    let runtime = Arc::new(RecordingRuntime::default());
    let (base, state, shutdown, server, home) = spawn_webchat(Arc::clone(&runtime)).await;
    let client = reqwest::Client::new();
    let cookie_a = bootstrap(&client, &base, &state).await;
    let cookie_b = bootstrap(&client, &base, &state).await;
    let session_a = session_id_for_test(&state, &cookie_a).await;
    let session_b = session_id_for_test(&state, &cookie_b).await;
    let db = home.path().join("views.db");
    let conn = crate::memory::store::open(&db).expect("open real views database");
    for sequence in 0..205 {
        crate::memory::transcript_store::insert_turn(
            &conn,
            &session_a,
            "operator",
            sequence,
            &format!("a-{sequence}"),
        )
        .expect("insert session-a row");
    }
    crate::memory::transcript_store::insert_turn(&conn, &session_b, "operator", 999, "private-b")
        .expect("insert session-b row");
    drop(conn);
    let a = client
        .get(format!("{base}/api/v1/webchat/transcript"))
        .header("Cookie", &cookie_a)
        .send()
        .await
        .expect("transcript A");
    assert_eq!(a.status(), reqwest::StatusCode::OK);
    let a = a
        .json::<serde_json::Value>()
        .await
        .expect("transcript A json");
    assert_eq!(
        a["turns"].as_array().expect("turns array").len(),
        TRANSCRIPT_LIMIT
    );
    assert_eq!(a["turns"][0]["text"], "a-5");
    assert!(a["truncated"].as_bool().expect("truncated"));
    let b = client
        .get(format!("{base}/api/v1/webchat/transcript"))
        .header("Cookie", &cookie_b)
        .send()
        .await
        .expect("transcript B");
    assert_eq!(b.status(), reqwest::StatusCode::OK);
    let b = b
        .json::<serde_json::Value>()
        .await
        .expect("transcript B json");
    assert_eq!(b["turns"].as_array().expect("turns array").len(), 1);
    assert_eq!(b["turns"][0]["text"], "private-b");
    crate::memory::transcript_store::insert_turn(
        &crate::memory::store::open(&db).expect("reopen real views database"),
        &session_b,
        "operator",
        1_000,
        &"x".repeat(65_537),
    )
    .expect("insert oversized visible row");
    let oversized = client
        .get(format!("{base}/api/v1/webchat/transcript"))
        .header("Cookie", &cookie_b)
        .send()
        .await
        .expect("oversized transcript");
    assert_eq!(oversized.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        error_code(
            &oversized
                .json()
                .await
                .expect("oversized transcript error json")
        ),
        "unavailable"
    );
    std::fs::write(&db, b"W696 deliberately corrupt transcript fixture")
        .expect("corrupt temporary views database");
    let corrupt = client
        .get(format!("{base}/api/v1/webchat/transcript"))
        .header("Cookie", &cookie_a)
        .send()
        .await
        .expect("corrupt transcript");
    assert_eq!(corrupt.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        error_code(&corrupt.json().await.expect("corrupt transcript error json")),
        "unavailable"
    );
    assert!(
        runtime.calls().is_empty(),
        "transcript storage failures must not invoke the chat runtime"
    );
    stop(shutdown, server).await;
}

#[tokio::test]
async fn same_session_maps_preflight_decision_start_and_idempotent_start_to_runtime() {
    let runtime = Arc::new(RecordingRuntime::default());
    let (base, state, shutdown, server, home) = spawn_webchat(Arc::clone(&runtime)).await;
    prepare_ready_consent_home(home.path());
    let client = reqwest::Client::new();
    let cookie = bootstrap(&client, &base, &state).await;
    let request_id = start_owned_request(&client, &base, &cookie).await;
    let repeated_decision = post(
        &client,
        &base,
        &cookie,
        "/api/v1/webchat/decide",
        serde_json::json!({"request_id":request_id, "decision":"allow_once"}),
    )
    .await;
    assert_eq!(repeated_decision.status(), reqwest::StatusCode::OK);
    let conflicting_decision = post(
        &client,
        &base,
        &cookie,
        "/api/v1/webchat/decide",
        serde_json::json!({"request_id":request_id, "decision":"deny"}),
    )
    .await;
    assert_eq!(conflicting_decision.status(), reqwest::StatusCode::CONFLICT);
    assert_eq!(
        error_code(
            &conflicting_decision
                .json()
                .await
                .expect("decision conflict error json")
        ),
        "conflict"
    );
    let retry = post(
        &client,
        &base,
        &cookie,
        "/api/v1/webchat/start",
        serde_json::json!({"request_id":request_id}),
    )
    .await;
    assert_eq!(retry.status(), reqwest::StatusCode::OK);
    let session = client
        .get(format!("{base}/api/v1/webchat/session"))
        .header("Cookie", &cookie)
        .send()
        .await
        .expect("session re-entry");
    assert_eq!(session.status(), reqwest::StatusCode::OK);
    let session = session
        .json::<serde_json::Value>()
        .await
        .expect("session json");
    assert_eq!(
        session["active_request_id"]
            .as_str()
            .expect("active request id"),
        request_id.to_string()
    );
    let calls = runtime.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.starts_with("preflight:"))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.starts_with("decide:"))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.starts_with("start:"))
            .count(),
        1,
        "retry must replay stored start, not re-run runtime start"
    );
    stop(shutdown, server).await;
}

#[tokio::test]
async fn cross_session_request_ids_refuse_start_attach_and_cancel_before_runtime_side_effects() {
    let runtime = Arc::new(RecordingRuntime::default());
    let (base, state, shutdown, server, home) = spawn_webchat(Arc::clone(&runtime)).await;
    prepare_ready_consent_home(home.path());
    let client = reqwest::Client::new();
    let owner = bootstrap(&client, &base, &state).await;
    let intruder = bootstrap(&client, &base, &state).await;
    let request_id = start_owned_request(&client, &base, &owner).await;
    let before = runtime.calls();
    for (path, body) in [
        (
            "/api/v1/webchat/start",
            serde_json::json!({"request_id":request_id}),
        ),
        (
            "/api/v1/webchat/attach",
            serde_json::json!({"request_id":request_id,"after_sequence":0}),
        ),
        (
            "/api/v1/webchat/cancel",
            serde_json::json!({"request_id":request_id}),
        ),
    ] {
        let response = post(&client, &base, &intruder, path, body).await;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "{path} must reject a foreign request id"
        );
        assert_eq!(
            error_code(&response.json().await.expect("foreign request error json")),
            "forbidden"
        );
    }
    assert_eq!(
        runtime.calls(),
        before,
        "foreign requests must fail before attach/start/cancel runtime calls"
    );
    stop(shutdown, server).await;
}

#[tokio::test]
async fn own_cancel_reaches_runtime_and_host_origin_and_body_rejections_have_no_effects() {
    let runtime = Arc::new(RecordingRuntime::default());
    let (base, state, shutdown, server, home) = spawn_webchat(Arc::clone(&runtime)).await;
    prepare_ready_consent_home(home.path());
    let client = reqwest::Client::new();
    let cookie = bootstrap(&client, &base, &state).await;
    let request_id = start_owned_request(&client, &base, &cookie).await;
    let cancelled = post(
        &client,
        &base,
        &cookie,
        "/api/v1/webchat/cancel",
        serde_json::json!({"request_id":request_id}),
    )
    .await;
    assert_eq!(cancelled.status(), reqwest::StatusCode::OK);
    assert!(
        runtime
            .calls()
            .iter()
            .any(|call| call.starts_with("cancel:")),
        "owner cancellation must reach runtime"
    );
    let before = runtime.calls();
    let wrong_host = client
        .post(format!("{base}/api/v1/webchat/preflight"))
        .header("Host", "evil.example")
        .header("Origin", &base)
        .header("Cookie", &cookie)
        .json(
            &serde_json::json!({"message":"ignored", "incognito":false, "reasoning_display":false}),
        )
        .send()
        .await
        .expect("wrong host request");
    assert_eq!(wrong_host.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        error_code(&wrong_host.json().await.expect("invalid host error json")),
        "invalid_host"
    );
    let wrong_origin = client
        .post(format!("{base}/api/v1/webchat/preflight"))
        .header("Origin", "http://evil.example")
        .header("Cookie", &cookie)
        .json(
            &serde_json::json!({"message":"ignored", "incognito":false, "reasoning_display":false}),
        )
        .send()
        .await
        .expect("wrong origin request");
    assert_eq!(wrong_origin.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        error_code(
            &wrong_origin
                .json()
                .await
                .expect("invalid origin error json")
        ),
        "invalid_origin"
    );
    let oversized = client
        .post(format!("{base}/api/v1/webchat/preflight"))
        .header("Origin", &base)
        .header("Cookie", &cookie)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"message":"{}","incognito":false,"reasoning_display":false}}"#,
            "x".repeat(BODY_LIMIT)
        ))
        .send()
        .await
        .expect("oversized request");
    assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        error_code(&oversized.json().await.expect("oversize error json")),
        "body_limit"
    );
    assert_eq!(
        runtime.calls(),
        before,
        "HTTP envelope rejections must precede runtime effects"
    );
    stop(shutdown, server).await;
}
