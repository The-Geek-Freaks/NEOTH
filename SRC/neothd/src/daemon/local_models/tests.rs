use std::sync::Arc;
use std::time::Duration;

use super::loopback_fixture::{FixtureModel, FixtureState, LoopbackOllamaFixture};
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as TokioMutex, Notify};

struct Harness {
    _home: tempfile::TempDir,
    controller: LocalModelController,
    fixture: LoopbackOllamaFixture,
}

impl Harness {
    async fn stop(self) {
        self.controller.shutdown().await;
        self.fixture.shutdown().await;
    }
}

struct ProbeRaceFixture {
    endpoint: String,
    chat_entered: Arc<Notify>,
    release_chat: Arc<Notify>,
    requests: Arc<TokioMutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

struct TerminalReconciliationFixture {
    endpoint: String,
    reconciliation_chat_entered: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl TerminalReconciliationFixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("terminal-reconciliation listener");
        let endpoint = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("terminal-reconciliation listener address")
        );
        let reconciliation_chat_entered = Arc::new(Notify::new());
        let task_entered = Arc::clone(&reconciliation_chat_entered);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let _ = serve_terminal_reconciliation(stream, Arc::clone(&task_entered)).await;
            }
        });
        Self {
            endpoint,
            reconciliation_chat_entered,
            task,
        }
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

impl ProbeRaceFixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe-race listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("probe-race listener address")
        );
        let chat_entered = Arc::new(Notify::new());
        let release_chat = Arc::new(Notify::new());
        let requests = Arc::new(TokioMutex::new(Vec::new()));
        let task_chat_entered = Arc::clone(&chat_entered);
        let task_release_chat = Arc::clone(&release_chat);
        let task_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let _ = serve_probe_race(
                    stream,
                    Arc::clone(&task_chat_entered),
                    Arc::clone(&task_release_chat),
                    Arc::clone(&task_requests),
                )
                .await;
            }
        });
        Self {
            endpoint,
            chat_entered,
            release_chat,
            requests,
            task,
        }
    }

    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn serve_probe_race(
    mut stream: TcpStream,
    chat_entered: Arc<Notify>,
    release_chat: Arc<Notify>,
    requests: Arc<TokioMutex<Vec<String>>>,
) -> std::io::Result<()> {
    let mut bytes = vec![0_u8; 16 * 1024];
    let read = stream.read(&mut bytes).await?;
    let request = String::from_utf8_lossy(&bytes[..read]).to_string();
    requests.lock().await.push(request.clone());
    let path = request
        .split_once(' ')
        .and_then(|(_, tail)| tail.split_whitespace().next())
        .unwrap_or_default();
    let body = match (request.starts_with("GET "), path) {
        (true, "/api/tags") => serde_json::json!({
            "models": [{
                "name": "tiny:latest",
                "model": "tiny:latest",
                "digest": "sha256:exact",
                "size": 42
            }]
        })
        .to_string(),
        (true, "/api/ps") => serde_json::json!({
            "models": [{
                "name": "tiny:latest",
                "model": "tiny:latest",
                "digest": "sha256:exact",
                "size": 42
            }]
        })
        .to_string(),
        (false, "/api/chat") => {
            chat_entered.notify_one();
            release_chat.notified().await;
            serde_json::json!({"model": "tiny:latest", "done": true}).to_string()
        }
        _ => r#"{"error":"missing"}"#.to_owned(),
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(body.as_bytes()).await
}

async fn serve_terminal_reconciliation(
    mut stream: TcpStream,
    reconciliation_chat_entered: Arc<Notify>,
) -> std::io::Result<()> {
    let mut bytes = vec![0_u8; 16 * 1024];
    let read = stream.read(&mut bytes).await?;
    let request = String::from_utf8_lossy(&bytes[..read]);
    let path = request
        .split_once(' ')
        .and_then(|(_, tail)| tail.split_whitespace().next())
        .unwrap_or_default();
    let body = match (request.starts_with("GET "), path) {
        (true, "/api/tags") => serde_json::json!({
            "models": [{
                "name": "tiny:latest",
                "model": "tiny:latest",
                "digest": "sha256:exact",
                "size": 42
            }]
        })
        .to_string(),
        (true, "/api/ps") => serde_json::json!({"models": []}).to_string(),
        (false, "/api/pull") => "{\"status\":\"success\"}\n".to_owned(),
        (false, "/api/chat") => {
            reconciliation_chat_entered.notify_one();
            std::future::pending::<String>().await
        }
        _ => r#"{"error":"missing"}"#.to_owned(),
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(body.as_bytes()).await
}

fn installed_model(selector: &str, digest: &str, loaded: bool) -> FixtureModel {
    FixtureModel {
        selector: selector.to_owned(),
        digest: digest.to_owned(),
        size: 42,
        loaded,
    }
}

async fn harness(state: FixtureState, configured_model: Option<&str>) -> Harness {
    let fixture = LoopbackOllamaFixture::start(state).await;
    let home = tempfile::tempdir().expect("test home");
    let controller = LocalModelController::new(
        home.path().to_path_buf(),
        LocalModelEndpoint {
            base_url: fixture.endpoint.clone(),
            configured_model: configured_model.map(str::to_owned),
        },
    )
    .expect("loopback controller");
    Harness {
        _home: home,
        controller,
        fixture,
    }
}

async fn terminal_snapshot(controller: &LocalModelController) -> LocalModelsSnapshot {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = controller.status().await;
            if snapshot.active_operation.is_none() && snapshot.last_terminal_operation.is_some() {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("operation did not reach a terminal receipt")
}

async fn wait_for_pull(fixture: &LoopbackOllamaFixture) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if fixture.state.lock().await.pulls_started > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixture did not observe the pull request");
}

fn row<'a>(snapshot: &'a LocalModelsSnapshot, model: &str) -> &'a LocalModelRow {
    snapshot
        .models
        .iter()
        .find(|row| row.model == model)
        .expect("target model row")
}

#[tokio::test]
async fn ready_requires_exact_chat_then_fresh_matching_ps_digest() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", true),
    );
    let harness = harness(state, Some("tiny:latest")).await;

    let snapshot = harness.controller.refresh().await;
    assert!(matches!(
        &row(&snapshot, "tiny:latest").readiness,
        LocalModelReadiness::Ready { .. }
    ));
    assert_eq!(
        row(&snapshot, "tiny:latest")
            .loaded
            .as_ref()
            .map(|loaded| loaded.digest.as_str()),
        Some("sha256:exact")
    );

    let requests = harness.fixture.state.lock().await.requests.clone();
    let chat = requests
        .iter()
        .position(|request| request.starts_with("POST /api/chat "))
        .expect("model-specific chat probe");
    assert!(requests[chat].contains(r#""model":"tiny:latest""#));
    assert!(
        requests[chat + 1..]
            .iter()
            .any(|request| request.starts_with("GET /api/ps ")),
        "a fresh /api/ps must follow the successful chat probe"
    );
    harness.stop().await;
}

#[tokio::test]
async fn fresh_chat_ps_proof_assigns_loaded_use_for_an_initially_unloaded_model() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    state.script.chat_marks_requested_loaded = true;
    let harness = harness(state, Some("tiny:latest")).await;

    let snapshot = harness.controller.refresh().await;
    assert!(matches!(
        &row(&snapshot, "tiny:latest").readiness,
        LocalModelReadiness::Ready { .. }
    ));
    let loaded = row(&snapshot, "tiny:latest")
        .loaded
        .as_ref()
        .expect("fresh /api/ps loaded row");
    assert_eq!(loaded.model, "tiny:latest");
    assert_eq!(loaded.name.as_deref(), Some("tiny:latest"));
    assert_eq!(loaded.digest, "sha256:exact");
    harness.stop().await;
}

#[tokio::test]
async fn restart_does_not_revive_a_previous_ready_observation() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", true),
    );
    let harness = harness(state, Some("tiny:latest")).await;
    assert!(matches!(
        &row(&harness.controller.refresh().await, "tiny:latest").readiness,
        LocalModelReadiness::Ready { .. }
    ));

    let restarted = LocalModelController::new(
        harness._home.path().to_path_buf(),
        LocalModelEndpoint {
            base_url: harness.fixture.endpoint.clone(),
            configured_model: Some("tiny:latest".to_owned()),
        },
    )
    .expect("restart controller");
    let snapshot = restarted.status().await;
    assert!(matches!(
        snapshot.endpoint,
        LocalEndpointStatus::Unavailable { .. }
    ));
    assert!(matches!(
        &row(&snapshot, "tiny:latest").readiness,
        LocalModelReadiness::Unavailable
    ));
    assert!(row(&snapshot, "tiny:latest").loaded.is_none());
    harness.stop().await;
}

#[tokio::test]
async fn mutation_admission_is_rejected_while_a_real_probe_is_in_flight() {
    let fixture = ProbeRaceFixture::start().await;
    let home = tempfile::tempdir().expect("probe-race home");
    let controller = LocalModelController::new(
        home.path().to_path_buf(),
        LocalModelEndpoint {
            base_url: fixture.endpoint.clone(),
            configured_model: Some("tiny:latest".to_owned()),
        },
    )
    .expect("probe-race controller");
    let refresh_controller = controller.clone();
    let refresh = tokio::spawn(async move { refresh_controller.refresh().await });
    tokio::time::timeout(Duration::from_secs(2), fixture.chat_entered.notified())
        .await
        .expect("probe did not reach /api/chat");

    let admission = controller
        .start(LocalModelAction::Update {
            model: "tiny:latest".to_owned(),
        })
        .await;
    assert!(!admission.ok);
    assert!(matches!(
        admission.error.as_ref().map(|error| &error.code),
        Some(LocalModelErrorCode::Conflict)
    ));
    assert!(admission.snapshot.active_operation.is_none());
    assert!(matches!(
        &row(&admission.snapshot, "tiny:latest").readiness,
        LocalModelReadiness::Probing
    ));
    assert!(
        fixture
            .requests
            .lock()
            .await
            .iter()
            .all(|request| !request.starts_with("POST /api/pull "))
    );

    fixture.release_chat.notify_one();
    let snapshot = tokio::time::timeout(Duration::from_secs(2), refresh)
        .await
        .expect("probe refresh did not finish")
        .expect("probe refresh task panicked");
    assert!(matches!(
        &row(&snapshot, "tiny:latest").readiness,
        LocalModelReadiness::Ready { .. }
    ));
    controller.shutdown().await;
    fixture.stop().await;
}

#[tokio::test]
async fn critical_admission_persistence_failure_sends_no_mutation_request() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    let harness = harness(state, None).await;
    harness.controller.fail_next_critical_persist_for_test();

    let ack = harness
        .controller
        .start(LocalModelAction::Pull {
            model: "tiny:latest".to_owned(),
        })
        .await;
    assert!(!ack.ok);
    assert!(ack.operation_id.is_none());
    assert!(ack.snapshot.active_operation.is_none());
    assert!(harness.fixture.state.lock().await.requests.is_empty());
    harness.stop().await;
}

#[tokio::test]
async fn terminal_persistence_failure_after_send_keeps_intent_blocks_actions_and_never_replays() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    state.script.hold_pull_open = true;
    let harness = harness(state, None).await;
    let admitted = harness
        .controller
        .start(LocalModelAction::Pull {
            model: "tiny:latest".to_owned(),
        })
        .await;
    let operation_id = admitted
        .operation_id
        .clone()
        .expect("durably admitted operation id");
    wait_for_pull(&harness.fixture).await;
    harness.controller.fail_next_critical_persist_for_test();

    let cancelled = harness.controller.cancel(&operation_id).await;
    assert!(!cancelled.ok);
    assert!(matches!(
        cancelled.error.as_ref().map(|error| &error.code),
        Some(LocalModelErrorCode::Persistence)
    ));
    assert_eq!(
        cancelled
            .snapshot
            .active_operation
            .as_ref()
            .map(|active| active.operation_id.as_str()),
        Some(operation_id.as_str()),
        "terminal persistence failure keeps the unresolved durable intent visible"
    );

    let blocked_mutation = harness
        .controller
        .start(LocalModelAction::Pull {
            model: "other:latest".to_owned(),
        })
        .await;
    assert!(!blocked_mutation.ok);
    assert!(matches!(
        blocked_mutation.error.as_ref().map(|error| &error.code),
        Some(LocalModelErrorCode::Persistence)
    ));
    let blocked_retry = harness
        .controller
        .start(LocalModelAction::Retry {
            terminal_operation_id: operation_id,
        })
        .await;
    assert!(!blocked_retry.ok);
    assert_eq!(harness.fixture.state.lock().await.pulls_started, 1);

    let restarted = LocalModelController::new(
        harness._home.path().to_path_buf(),
        LocalModelEndpoint {
            base_url: harness.fixture.endpoint.clone(),
            configured_model: None,
        },
    )
    .expect("restart after unresolved intent");
    let restarted_snapshot = restarted.status().await;
    assert!(restarted_snapshot.active_operation.is_none());
    assert!(matches!(
        restarted_snapshot
            .last_terminal_operation
            .as_ref()
            .expect("restart uncertainty receipt")
            .outcome,
        LocalModelTerminalOutcome::InterruptedUnknown
    ));
    assert_eq!(harness.fixture.state.lock().await.pulls_started, 1);
    harness.fixture.shutdown().await;
}

#[tokio::test]
async fn concurrent_cancel_and_shutdown_reap_one_blocked_pull_with_one_uncertain_receipt() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    state.script.hold_pull_open = true;
    let harness = harness(state, None).await;
    let started = harness
        .controller
        .start(LocalModelAction::Pull {
            model: "tiny:latest".to_owned(),
        })
        .await;
    let operation_id = started.operation_id.expect("active pull id");
    wait_for_pull(&harness.fixture).await;

    let cancel_controller = harness.controller.clone();
    let shutdown_controller = harness.controller.clone();
    let cancel_id = operation_id.clone();
    let cancel = tokio::spawn(async move { cancel_controller.cancel(&cancel_id).await });
    let shutdown = tokio::spawn(async move { shutdown_controller.shutdown().await });
    let (cancelled, shutdown_result) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(cancel, shutdown)
    })
    .await
    .expect("concurrent cancel and shutdown did not drain");
    let _ = cancelled.expect("cancel task panicked");
    shutdown_result.expect("shutdown task panicked");

    let snapshot = harness.controller.status().await;
    assert!(snapshot.active_operation.is_none());
    assert!(matches!(
        snapshot
            .last_terminal_operation
            .as_ref()
            .expect("single terminal receipt")
            .outcome,
        LocalModelTerminalOutcome::InterruptedUnknown
    ));
    let state = harness.controller.inner.state.lock().await;
    assert!(
        state.active.is_none(),
        "the joined pull handle must not remain detached"
    );
    assert_eq!(
        state.receipts.len(),
        1,
        "exactly one terminal receipt is retained"
    );
    assert!(matches!(
        &state.receipts[0].outcome,
        LocalModelTerminalOutcome::InterruptedUnknown
    ));
    drop(state);
    assert_eq!(harness.fixture.state.lock().await.pulls_started, 1);
    harness.stop().await;
}

#[tokio::test]
async fn failed_or_mismatched_probe_never_marks_model_ready() {
    for (chat_succeeds, chat_returns_requested_model, ps_digest_matches, response_mismatch) in [
        (false, true, true, false),
        (true, false, true, true),
        (true, true, false, false),
    ] {
        let mut state = FixtureState::default();
        state.models.insert(
            "tiny:latest".to_owned(),
            installed_model("tiny:latest", "sha256:exact", true),
        );
        state.script.chat_succeeds = chat_succeeds;
        state.script.chat_returns_requested_model = chat_returns_requested_model;
        state.script.ps_digest_matches = ps_digest_matches;
        let harness = harness(state, Some("tiny:latest")).await;

        let snapshot = harness.controller.refresh().await;
        assert!(matches!(
            &row(&snapshot, "tiny:latest").readiness,
            LocalModelReadiness::ReachableButUnready { .. }
        ));
        if response_mismatch {
            assert!(matches!(
                &row(&snapshot, "tiny:latest").readiness,
                LocalModelReadiness::ReachableButUnready {
                    reason: LocalModelUnreadyReason::ResponseModelMismatch
                }
            ));
        } else {
            assert!(matches!(
                &row(&snapshot, "tiny:latest").readiness,
                LocalModelReadiness::ReachableButUnready {
                    reason: LocalModelUnreadyReason::ProbeFailed
                }
            ));
        }
        harness.stop().await;
    }
}

#[tokio::test]
async fn inventory_uses_tag_name_when_ollama_omits_model() {
    let mut state = FixtureState::default();
    state.models.insert(
        "fallback:latest".to_owned(),
        installed_model("fallback:latest", "sha256:fallback", false),
    );
    state.omit_tag_model = true;
    let harness = harness(state, None).await;

    let snapshot = harness.controller.refresh().await;
    assert_eq!(row(&snapshot, "fallback:latest").model, "fallback:latest");
    harness.stop().await;
}

#[tokio::test]
async fn pull_requires_terminal_success_and_fresh_target_inventory() {
    let mut missing_target = FixtureState::default();
    missing_target.script.pull_frames = vec![r#"{"status":"success"}"#.to_owned()];
    let missing_target_harness = harness(missing_target, None).await;
    let ack = missing_target_harness
        .controller
        .start(LocalModelAction::Pull {
            model: "missing:latest".to_owned(),
        })
        .await;
    assert!(ack.ok);
    let snapshot = terminal_snapshot(&missing_target_harness.controller).await;
    assert!(matches!(
        snapshot.last_terminal_operation.expect("receipt").outcome,
        LocalModelTerminalOutcome::InterruptedUnknown
    ));
    assert_eq!(
        missing_target_harness
            .fixture
            .state
            .lock()
            .await
            .pulls_started,
        1
    );
    missing_target_harness.stop().await;

    let mut eof = FixtureState::default();
    eof.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    eof.script.pull_frames = vec![r#"{"status":"pulling","completed":1,"total":2}"#.to_owned()];
    let eof_harness = harness(eof, None).await;
    let ack = eof_harness
        .controller
        .start(LocalModelAction::Pull {
            model: "tiny:latest".to_owned(),
        })
        .await;
    assert!(ack.ok);
    let snapshot = terminal_snapshot(&eof_harness.controller).await;
    let receipt = snapshot.last_terminal_operation.expect("receipt");
    assert!(matches!(
        receipt.outcome,
        LocalModelTerminalOutcome::InterruptedUnknown
    ));
    assert!(
        !eof_harness
            .controller
            .start(LocalModelAction::Retry {
                terminal_operation_id: receipt.operation_id,
            })
            .await
            .ok
    );
    eof_harness.stop().await;
}

#[tokio::test]
async fn completed_operation_handle_is_reaped_before_a_refresh_observation() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    let harness = harness(state, None).await;
    assert!(
        harness
            .controller
            .start(LocalModelAction::Pull {
                model: "tiny:latest".to_owned(),
            })
            .await
            .ok
    );
    let terminal = terminal_snapshot(&harness.controller).await;
    assert!(matches!(
        terminal
            .last_terminal_operation
            .expect("completed receipt")
            .outcome,
        LocalModelTerminalOutcome::Completed
    ));

    let refreshed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = harness.controller.refresh().await;
            if matches!(snapshot.endpoint, LocalEndpointStatus::Reachable { .. }) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("completed task was not reaped before refresh");
    assert!(refreshed.active_operation.is_none());
    assert!(matches!(
        refreshed
            .last_terminal_operation
            .as_ref()
            .expect("completed receipt retained through refresh")
            .outcome,
        LocalModelTerminalOutcome::Completed
    ));
    harness.stop().await;
}

#[tokio::test]
async fn shutdown_aborts_blocked_terminal_reconciliation_without_rewriting_completed_receipt() {
    let fixture = TerminalReconciliationFixture::start().await;
    let home = tempfile::tempdir().expect("terminal-reconciliation home");
    let controller = LocalModelController::new(
        home.path().to_path_buf(),
        LocalModelEndpoint {
            base_url: fixture.endpoint.clone(),
            configured_model: None,
        },
    )
    .expect("terminal-reconciliation controller");
    assert!(
        controller
            .start(LocalModelAction::Pull {
                model: "tiny:latest".to_owned(),
            })
            .await
            .ok
    );
    tokio::time::timeout(
        Duration::from_secs(2),
        fixture.reconciliation_chat_entered.notified(),
    )
    .await
    .expect("terminal reconciliation did not reach its blocked chat probe");
    let before_shutdown = controller.status().await;
    assert!(before_shutdown.active_operation.is_none());
    assert!(matches!(
        before_shutdown
            .last_terminal_operation
            .as_ref()
            .expect("durable completed receipt")
            .outcome,
        LocalModelTerminalOutcome::Completed
    ));

    controller.shutdown().await;
    let after_shutdown = controller.status().await;
    assert!(after_shutdown.active_operation.is_none());
    assert!(matches!(
        after_shutdown
            .last_terminal_operation
            .as_ref()
            .expect("completed receipt survives shutdown")
            .outcome,
        LocalModelTerminalOutcome::Completed
    ));
    fixture.stop().await;
}

#[tokio::test]
async fn cancel_requires_the_exact_active_id_and_retains_uncertainty() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    state.script.hold_pull_open = true;
    let harness = harness(state, None).await;
    let started = harness
        .controller
        .start(LocalModelAction::Pull {
            model: "tiny:latest".to_owned(),
        })
        .await;
    let operation_id = started.operation_id.clone().expect("active operation id");
    wait_for_pull(&harness.fixture).await;

    let wrong = harness.controller.cancel("another-operation").await;
    assert!(!wrong.ok);
    assert_eq!(wrong.operation_id.as_deref(), Some(operation_id.as_str()));
    assert_eq!(
        harness
            .controller
            .status()
            .await
            .active_operation
            .as_ref()
            .map(|active| active.operation_id.as_str()),
        Some(operation_id.as_str())
    );

    let cancelled = harness.controller.cancel(&operation_id).await;
    assert!(cancelled.ok);
    assert!(matches!(
        cancelled
            .snapshot
            .last_terminal_operation
            .as_ref()
            .expect("uncertain receipt")
            .outcome,
        LocalModelTerminalOutcome::InterruptedUnknown
    ));
    assert!(matches!(
        &row(&cancelled.snapshot, "tiny:latest").readiness,
        LocalModelReadiness::InterruptedUnknown { operation_id: persisted } if persisted == &operation_id
    ));
    let refreshed = harness.controller.refresh().await;
    assert!(matches!(
        refreshed
            .last_terminal_operation
            .as_ref()
            .expect("retained uncertainty")
            .outcome,
        LocalModelTerminalOutcome::InterruptedUnknown
    ));
    let restarted = LocalModelController::new(
        harness._home.path().to_path_buf(),
        LocalModelEndpoint {
            base_url: harness.fixture.endpoint.clone(),
            configured_model: None,
        },
    )
    .expect("restart controller");
    assert!(matches!(
        restarted
            .status()
            .await
            .last_terminal_operation
            .as_ref()
            .expect("restart receipt")
            .outcome,
        LocalModelTerminalOutcome::InterruptedUnknown
    ));
    assert!(matches!(
        &row(&restarted.status().await, "tiny:latest").readiness,
        LocalModelReadiness::InterruptedUnknown { operation_id: persisted } if persisted == &operation_id
    ));
    let retry = harness
        .controller
        .start(LocalModelAction::Retry {
            terminal_operation_id: operation_id,
        })
        .await;
    assert!(
        !retry.ok,
        "an uncertain post-send outcome must not be retried"
    );
    assert_eq!(harness.fixture.state.lock().await.pulls_started, 1);
    harness.stop().await;
}

#[tokio::test]
async fn prune_refuses_absent_or_loaded_targets_and_proves_exact_fresh_absence() {
    let absent = harness(FixtureState::default(), None).await;
    assert!(
        absent
            .controller
            .start(LocalModelAction::Prune {
                model: "missing:latest".to_owned(),
            })
            .await
            .ok
    );
    let snapshot = terminal_snapshot(&absent.controller).await;
    assert!(matches!(
        snapshot.last_terminal_operation.expect("receipt").outcome,
        LocalModelTerminalOutcome::Failed
    ));
    assert!(absent.fixture.state.lock().await.deletes.is_empty());
    absent.stop().await;

    let mut loaded = FixtureState::default();
    loaded.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", true),
    );
    let loaded = harness(loaded, None).await;
    assert!(
        loaded
            .controller
            .start(LocalModelAction::Prune {
                model: "tiny:latest".to_owned(),
            })
            .await
            .ok
    );
    let snapshot = terminal_snapshot(&loaded.controller).await;
    assert!(matches!(
        snapshot.last_terminal_operation.expect("receipt").outcome,
        LocalModelTerminalOutcome::Failed
    ));
    assert!(loaded.fixture.state.lock().await.deletes.is_empty());
    loaded.stop().await;

    let mut removable = FixtureState::default();
    removable.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    let removable = harness(removable, None).await;
    let ack = removable
        .controller
        .start(LocalModelAction::Prune {
            model: "tiny:latest".to_owned(),
        })
        .await;
    assert!(ack.ok);
    let snapshot = terminal_snapshot(&removable.controller).await;
    assert!(matches!(
        snapshot.last_terminal_operation.expect("receipt").outcome,
        LocalModelTerminalOutcome::Completed
    ));
    assert!(snapshot.models.iter().all(|row| row.model != "tiny:latest"));
    assert_eq!(
        removable.fixture.state.lock().await.deletes,
        vec!["tiny:latest".to_owned()]
    );
    removable.stop().await;
}

#[tokio::test]
async fn retry_requires_an_exact_retained_failed_action_and_never_runs_implicitly() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", false),
    );
    state.script.pull_frames = vec![r#"{"error":"scripted remote rejection"}"#.to_owned()];
    let harness = harness(state, None).await;
    assert!(
        harness
            .controller
            .start(LocalModelAction::Pull {
                model: "tiny:latest".to_owned(),
            })
            .await
            .ok
    );
    let failed = terminal_snapshot(&harness.controller).await;
    assert!(matches!(
        failed
            .last_terminal_operation
            .as_ref()
            .expect("failed receipt")
            .outcome,
        LocalModelTerminalOutcome::Failed
    ));
    let failed_id = failed
        .last_terminal_operation
        .as_ref()
        .expect("failed receipt")
        .operation_id
        .clone();
    assert_eq!(harness.fixture.state.lock().await.pulls_started, 1);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        harness.fixture.state.lock().await.pulls_started,
        1,
        "failed operations are never retried automatically"
    );

    let unknown = harness
        .controller
        .start(LocalModelAction::Retry {
            terminal_operation_id: "not-retained".to_owned(),
        })
        .await;
    assert!(!unknown.ok);
    let retry = harness
        .controller
        .start(LocalModelAction::Retry {
            terminal_operation_id: failed_id,
        })
        .await;
    assert!(retry.ok);
    assert_eq!(retry.action, LocalModelActionKind::Pull);
    let _ = terminal_snapshot(&harness.controller).await;
    let fixture = harness.fixture.state.lock().await;
    assert_eq!(fixture.pulls_started, 2);
    assert!(
        fixture
            .requests
            .iter()
            .filter(|request| request.starts_with("POST /api/pull "))
            .all(|request| request.contains(r#""name":"tiny:latest""#))
    );
    drop(fixture);
    harness.stop().await;
}

#[tokio::test]
async fn refresh_cannot_restore_stale_ready_while_a_mutation_is_active() {
    let mut state = FixtureState::default();
    state.models.insert(
        "tiny:latest".to_owned(),
        installed_model("tiny:latest", "sha256:exact", true),
    );
    state.script.hold_pull_open = true;
    let harness = harness(state, Some("tiny:latest")).await;
    assert!(matches!(
        &row(&harness.controller.refresh().await, "tiny:latest").readiness,
        LocalModelReadiness::Ready { .. }
    ));

    let ack = harness
        .controller
        .start(LocalModelAction::Update {
            model: "tiny:latest".to_owned(),
        })
        .await;
    let operation_id = ack.operation_id.expect("active update id");
    wait_for_pull(&harness.fixture).await;
    let snapshot = harness.controller.refresh().await;
    assert!(matches!(
        &row(&snapshot, "tiny:latest").readiness,
        LocalModelReadiness::Updating { operation_id: active, .. } if active == &operation_id
    ));
    let _ = harness.controller.cancel(&operation_id).await;
    harness.stop().await;
}

#[tokio::test]
async fn bounded_http_response_is_rejected_before_inventory_is_accepted() {
    let mut state = FixtureState::default();
    state.oversized_response = true;
    let harness = harness(state, None).await;

    let snapshot = harness.controller.refresh().await;
    assert!(matches!(
        snapshot.endpoint,
        LocalEndpointStatus::Unavailable { .. }
    ));
    assert!(snapshot.models.is_empty());
    harness.stop().await;
}

#[test]
fn nested_action_payload_rejects_unknown_fields() {
    let payload = r#"{"kind":"pull","model":"tiny:latest","unexpected":{"replace_model":"other"}}"#;
    assert!(serde_json::from_str::<LocalModelAction>(payload).is_err());
}
